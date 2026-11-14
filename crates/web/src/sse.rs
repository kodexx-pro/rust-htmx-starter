use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use askama::Template;
use axum::{
    extract::State,
    http::{HeaderName, HeaderValue, header},
    response::{
        IntoResponse,
        sse::{Event, KeepAlive, Sse},
    },
};
use futures_util::stream::{self, Stream};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, postgres::PgListener};
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::{
    AppState,
    auth::AuthenticatedSession,
    error::FlashAlertTemplate,
    i18n::{Locale, Translations},
};

const CHANNEL_CAPACITY: usize = 128;
const REALTIME_CHANNEL: &str = "app_realtime_events";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RealtimeEvent {
    EmailVerified { user_id: Uuid },
    SessionRevoked { session_id: String },
    UserSessionsRevoked { user_id: Uuid },
}

#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<RealtimeEvent>,
    db: Option<PgPool>,
    pg_notify_ready: Arc<AtomicBool>,
}

impl EventBus {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(CHANNEL_CAPACITY);
        Self {
            tx,
            db: None,
            pg_notify_ready: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Inicia um único `PgListener` dedicado para propagar eventos SSE entre múltiplas réplicas
    /// via PostgreSQL `LISTEN/NOTIFY` sem reter conexões do `PgPool` por cliente SSE.
    pub async fn with_pg_listener(db: PgPool) -> Self {
        let (tx, _) = broadcast::channel(CHANNEL_CAPACITY);
        let pg_notify_ready = Arc::new(AtomicBool::new(false));

        let initial_listener = match connect_listener(&db).await {
            Ok(listener) => {
                pg_notify_ready.store(true, Ordering::Release);
                tracing::info!(channel = REALTIME_CHANNEL, "SSE PgListener conectado");
                Some(listener)
            }
            Err(err) => {
                tracing::warn!(
                    error = ?err,
                    "Falha inicial ao conectar SSE PgListener; usando broadcast local até reconectar"
                );
                None
            }
        };

        tokio::spawn(run_pg_listener_loop(
            db.clone(),
            tx.clone(),
            Arc::clone(&pg_notify_ready),
            initial_listener,
        ));

        Self {
            tx,
            db: Some(db),
            pg_notify_ready,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<RealtimeEvent> {
        self.tx.subscribe()
    }

    pub fn is_pg_listener_ready(&self) -> bool {
        self.pg_notify_ready.load(Ordering::Acquire)
    }

    fn publish(&self, event: RealtimeEvent) {
        if let Some(db) = &self.db
            && self.pg_notify_ready.load(Ordering::Acquire)
        {
            let db = db.clone();
            let tx = self.tx.clone();
            tokio::spawn(async move {
                let Ok(payload) = serde_json::to_string(&event) else {
                    let _ = tx.send(event);
                    return;
                };
                if let Err(err) = sqlx::query("SELECT pg_notify($1, $2)")
                    .bind(REALTIME_CHANNEL)
                    .bind(&payload)
                    .execute(&db)
                    .await
                {
                    tracing::warn!(error = ?err, "Falha ao enviar pg_notify; usando fallback local");
                    let _ = tx.send(event);
                }
            });
            return;
        }
        let _ = self.tx.send(event);
    }

    pub fn notify_email_verified(&self, user_id: Uuid) {
        self.publish(RealtimeEvent::EmailVerified { user_id });
    }

    pub fn notify_session_revoked(&self, session_id: impl Into<String>) {
        self.publish(RealtimeEvent::SessionRevoked {
            session_id: session_id.into(),
        });
    }

    pub fn notify_user_sessions_revoked(&self, user_id: Uuid) {
        self.publish(RealtimeEvent::UserSessionsRevoked { user_id });
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

async fn connect_listener(db: &PgPool) -> Result<PgListener, sqlx::Error> {
    let mut listener = PgListener::connect_with(db).await?;
    listener.listen(REALTIME_CHANNEL).await?;
    Ok(listener)
}

async fn run_pg_listener_loop(
    db: PgPool,
    tx: broadcast::Sender<RealtimeEvent>,
    ready: Arc<AtomicBool>,
    mut active_listener: Option<PgListener>,
) {
    loop {
        let listener = match active_listener.take() {
            Some(l) => l,
            None => match connect_listener(&db).await {
                Ok(l) => {
                    ready.store(true, Ordering::Release);
                    tracing::info!(channel = REALTIME_CHANNEL, "SSE PgListener reconectado");
                    l
                }
                Err(err) => {
                    ready.store(false, Ordering::Release);
                    tracing::warn!(error = ?err, "Erro ao reconectar SSE PgListener");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
            },
        };

        let mut listener = listener;
        loop {
            match listener.recv().await {
                Ok(notification) => {
                    match serde_json::from_str::<RealtimeEvent>(notification.payload()) {
                        Ok(event) => {
                            let _ = tx.send(event);
                        }
                        Err(err) => {
                            tracing::warn!(error = ?err, "Payload inválido recebido em pg_notify SSE");
                        }
                    }
                }
                Err(err) => {
                    ready.store(false, Ordering::Release);
                    tracing::warn!(error = ?err, "Conexão SSE PgListener interrompida; reconectando");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    break;
                }
            }
        }
    }
}

#[derive(Template)]
#[template(path = "partials/verification_badge.html")]
struct VerificationBadgeTemplate {
    email_verified: bool,
    t: &'static Translations,
}

#[derive(Serialize)]
struct EmailVerifiedPayload {
    badge_html: String,
    toast_html: String,
}

enum RenderedEvent {
    Continue(Event),
    Close(Event),
}

fn render_event_for_session(
    event: &RealtimeEvent,
    user_id: Uuid,
    session_id: &str,
    locale: Locale,
) -> Option<RenderedEvent> {
    let t = locale.translations();
    match event {
        RealtimeEvent::EmailVerified { user_id: target } if *target == user_id => {
            let badge_html = VerificationBadgeTemplate {
                email_verified: true,
                t,
            }
            .render()
            .ok()?;
            let toast_html = FlashAlertTemplate {
                kind: "alert-success",
                message: t.verified_success.to_string(),
            }
            .render()
            .ok()?;
            let payload = serde_json::to_string(&EmailVerifiedPayload {
                badge_html,
                toast_html,
            })
            .ok()?;
            Some(RenderedEvent::Continue(
                Event::default().event("email-verified").data(payload),
            ))
        }
        RealtimeEvent::SessionRevoked { session_id: target } if target == session_id => Some(
            RenderedEvent::Close(Event::default().event("session-revoked").data("/login")),
        ),
        RealtimeEvent::UserSessionsRevoked { user_id: target } if *target == user_id => Some(
            RenderedEvent::Close(Event::default().event("session-revoked").data("/login")),
        ),
        _ => None,
    }
}

fn build_user_stream(
    rx: broadcast::Receiver<RealtimeEvent>,
    user_id: Uuid,
    session_id: String,
    locale: Locale,
) -> impl Stream<Item = Result<Event, Infallible>> {
    stream::unfold((rx, false), move |(mut rx, closed)| {
        let session_id = session_id.clone();
        async move {
            if closed {
                return None;
            }
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        match render_event_for_session(&event, user_id, &session_id, locale) {
                            Some(RenderedEvent::Continue(sse_event)) => {
                                return Some((Ok(sse_event), (rx, false)));
                            }
                            Some(RenderedEvent::Close(sse_event)) => {
                                return Some((Ok(sse_event), (rx, true)));
                            }
                            None => continue,
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        }
    })
}

pub async fn events_stream(
    session: AuthenticatedSession,
    locale: Locale,
    State(state): State<AppState>,
) -> impl IntoResponse {
    let rx = state.events.subscribe();
    let stream = build_user_stream(rx, session.user.id, session.session_id, locale);

    let sse = Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keep-alive"),
    );

    (
        [
            (
                HeaderName::from_static("x-accel-buffering"),
                HeaderValue::from_static("no"),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-cache")),
        ],
        sse,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;

    #[test]
    fn renders_email_verified_only_for_target_user_and_locale() {
        let user_id = Uuid::new_v4();
        let other_id = Uuid::new_v4();
        let event = RealtimeEvent::EmailVerified { user_id };

        assert!(render_event_for_session(&event, other_id, "s1", Locale::Pt).is_none());

        let RenderedEvent::Continue(_) =
            render_event_for_session(&event, user_id, "s1", Locale::Es)
                .expect("should render event for target user")
        else {
            panic!("expected continue event");
        };

        let badge = VerificationBadgeTemplate {
            email_verified: true,
            t: Locale::Es.translations(),
        }
        .render()
        .unwrap();
        assert!(badge.contains("verification-badge"));
        assert!(badge.contains(Locale::Es.translations().verified_label));
    }

    #[tokio::test]
    async fn stream_filters_events_and_closes_on_session_revocation() {
        let bus = EventBus::new();
        let user_id = Uuid::new_v4();
        let other_user = Uuid::new_v4();

        let stream = build_user_stream(bus.subscribe(), user_id, "sess-1".into(), Locale::Pt);
        tokio::pin!(stream);

        bus.notify_email_verified(other_user);
        bus.notify_session_revoked("sess-other");
        bus.notify_email_verified(user_id);
        bus.notify_session_revoked("sess-1");

        let first = stream.next().await.expect("first event").unwrap();
        let first_debug = format!("{first:?}");
        assert!(first_debug.contains("email-verified"));
        assert!(first_debug.contains("E-mail verificado"));

        let second = stream.next().await.expect("second event").unwrap();
        let second_debug = format!("{second:?}");
        assert!(second_debug.contains("session-revoked"));

        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn stream_survives_lagged_broadcast_channel() {
        let bus = EventBus::new();
        let user_id = Uuid::new_v4();
        let other_user = Uuid::new_v4();

        let stream = build_user_stream(bus.subscribe(), user_id, "sess-1".into(), Locale::Pt);
        tokio::pin!(stream);

        for _ in 0..(CHANNEL_CAPACITY + 10) {
            bus.notify_email_verified(other_user);
        }
        bus.notify_email_verified(user_id);

        let item = stream
            .next()
            .await
            .expect("should recover after lag")
            .unwrap();
        assert!(format!("{item:?}").contains("email-verified"));
    }

    #[sqlx::test(migrations = "./migrations")]
    #[ignore = "requires PostgreSQL and DATABASE_URL with permission to create test databases"]
    async fn pg_listener_fans_out_events_across_replicas(pool: PgPool) -> anyhow::Result<()> {
        let replica_a = EventBus::with_pg_listener(pool.clone()).await;
        let replica_b = EventBus::with_pg_listener(pool).await;
        assert!(replica_a.is_pg_listener_ready());
        assert!(replica_b.is_pg_listener_ready());

        let mut rx_b = replica_b.subscribe();
        let user_id = Uuid::new_v4();

        replica_a.notify_email_verified(user_id);

        let received = tokio::time::timeout(Duration::from_secs(3), rx_b.recv())
            .await
            .expect("replica B should receive event via LISTEN/NOTIFY in time")?;
        assert_eq!(received, RealtimeEvent::EmailVerified { user_id });

        Ok(())
    }
}
