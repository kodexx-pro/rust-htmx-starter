use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::{Cookie, SameSite, SignedCookieJar};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use sqlx::PgPool;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use crate::{
    AppState, auth::try_resolve_session_user, i18n::Locale, orgs::resolve_active_organization_id,
    telemetry::AppMetrics,
};

pub const VISITOR_COOKIE: &str = "vid";
const CHANNEL_CAPACITY: usize = 4096;
const MAX_BATCH_INSERT: usize = 100;
const MAX_PAYLOAD_BYTES: usize = 65_536;
const MAX_EVENTS_PER_REQUEST: usize = 50;
const FLUSH_INTERVAL: Duration = Duration::from_millis(500);

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct NewAnalyticsEvent {
    pub event_type: String,
    pub event_name: String,
    pub visitor_id: Uuid,
    pub user_id: Option<Uuid>,
    pub organization_id: Option<Uuid>,
    pub request_id: Option<String>,
    pub path: String,
    pub referrer: Option<String>,
    pub page_title: Option<String>,
    pub element_tag: Option<String>,
    pub element_label: Option<String>,
    pub element_target: Option<String>,
    pub click_x_pct: Option<i16>,
    pub click_y_pct: Option<i16>,
    pub duration_ms: Option<i32>,
    pub locale: Option<String>,
    pub timezone: Option<String>,
    pub country_code: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub device_type: Option<String>,
    pub viewport: Option<String>,
    pub ip_hash: Option<String>,
    pub properties: serde_json::Value,
}

enum AnalyticsCommand {
    Event(Box<NewAnalyticsEvent>),
    Flush(oneshot::Sender<()>),
}

#[derive(Clone)]
pub struct AnalyticsCollector {
    sender: mpsc::Sender<AnalyticsCommand>,
    pending_count: Arc<AtomicUsize>,
    metrics: Arc<AppMetrics>,
}

impl AnalyticsCollector {
    pub fn new(db: PgPool, metrics: Arc<AppMetrics>) -> Self {
        let (sender, receiver) = mpsc::channel(CHANNEL_CAPACITY);
        let pending_count = Arc::new(AtomicUsize::new(0));
        let worker_pending = Arc::clone(&pending_count);
        let worker_metrics = Arc::clone(&metrics);

        tokio::spawn(run_flush_worker(
            db,
            receiver,
            worker_pending,
            worker_metrics,
        ));

        Self {
            sender,
            pending_count,
            metrics,
        }
    }

    pub fn pending_approx(&self) -> usize {
        self.pending_count.load(Ordering::Relaxed)
    }

    pub fn record(&self, event: NewAnalyticsEvent) {
        self.metrics
            .record_analytics_received(&event.event_type, event.duration_ms);

        tracing::info!(
            target: "web::analytics",
            event_type = %event.event_type,
            event_name = %event.event_name,
            path = %event.path,
            visitor_id = %event.visitor_id,
            user_id = ?event.user_id,
            organization_id = ?event.organization_id,
            duration_ms = ?event.duration_ms,
            element_target = ?event.element_target,
            country = ?event.country_code,
            timezone = ?event.timezone,
            request_id = ?event.request_id,
            "Evento de uso registrado"
        );

        match self
            .sender
            .try_send(AnalyticsCommand::Event(Box::new(event)))
        {
            Ok(()) => {
                self.pending_count.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                self.metrics.record_analytics_dropped(1);
                tracing::warn!("Fila de analytics cheia; evento descartado");
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn track_server_event(
        &self,
        headers: &HeaderMap,
        secret_key: &[u8],
        locale: Locale,
        visitor_id: Option<Uuid>,
        user_id: Option<Uuid>,
        organization_id: Option<Uuid>,
        event_name: &str,
        path: &str,
        properties: serde_json::Value,
    ) {
        let visitor_id = visitor_id.unwrap_or_else(Uuid::new_v4);
        let geo = extract_geo_context(headers);
        let device_type = headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(classify_device);
        let ip_hash = extract_client_ip(headers).map(|ip| hash_ip(&ip, secret_key));
        let request_id = headers
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(|s| truncate_str(s, 64));

        self.record(NewAnalyticsEvent {
            event_type: "custom".to_string(),
            event_name: truncate_str(event_name, 80),
            visitor_id,
            user_id,
            organization_id,
            request_id,
            path: normalize_path(path),
            referrer: None,
            page_title: None,
            element_tag: None,
            element_label: None,
            element_target: None,
            click_x_pct: None,
            click_y_pct: None,
            duration_ms: None,
            locale: Some(locale.code().to_string()),
            timezone: None,
            country_code: geo.country_code,
            region: geo.region,
            city: geo.city,
            device_type: Some(device_type.unwrap_or("unknown").to_string()),
            viewport: None,
            ip_hash,
            properties,
        });
    }

    pub async fn flush(&self) {
        let (tx, rx) = oneshot::channel();
        if self.sender.send(AnalyticsCommand::Flush(tx)).await.is_ok() {
            let _ = rx.await;
        }
    }
}

async fn run_flush_worker(
    db: PgPool,
    mut receiver: mpsc::Receiver<AnalyticsCommand>,
    pending_count: Arc<AtomicUsize>,
    metrics: Arc<AppMetrics>,
) {
    let mut buffer = Vec::with_capacity(MAX_BATCH_INSERT);
    let mut flush_waiters: Vec<oneshot::Sender<()>> = Vec::new();

    loop {
        let cmd = if buffer.is_empty() {
            receiver.recv().await
        } else {
            match tokio::time::timeout(FLUSH_INTERVAL, receiver.recv()).await {
                Ok(item) => item,
                Err(_) => {
                    flush_buffer(&db, &mut buffer, &pending_count, &metrics).await;
                    for waiter in flush_waiters.drain(..) {
                        let _ = waiter.send(());
                    }
                    continue;
                }
            }
        };

        match cmd {
            Some(AnalyticsCommand::Event(ev)) => {
                buffer.push(*ev);
                while buffer.len() < MAX_BATCH_INSERT {
                    match receiver.try_recv() {
                        Ok(AnalyticsCommand::Event(next_ev)) => buffer.push(*next_ev),
                        Ok(AnalyticsCommand::Flush(tx)) => flush_waiters.push(tx),
                        Err(_) => break,
                    }
                }
                if buffer.len() >= MAX_BATCH_INSERT || !flush_waiters.is_empty() {
                    flush_buffer(&db, &mut buffer, &pending_count, &metrics).await;
                    for waiter in flush_waiters.drain(..) {
                        let _ = waiter.send(());
                    }
                }
            }
            Some(AnalyticsCommand::Flush(tx)) => {
                flush_waiters.push(tx);
                while let Ok(next) = receiver.try_recv() {
                    match next {
                        AnalyticsCommand::Event(ev) => buffer.push(*ev),
                        AnalyticsCommand::Flush(more_tx) => flush_waiters.push(more_tx),
                    }
                }
                if !buffer.is_empty() {
                    flush_buffer(&db, &mut buffer, &pending_count, &metrics).await;
                }
                for waiter in flush_waiters.drain(..) {
                    let _ = waiter.send(());
                }
            }
            None => {
                if !buffer.is_empty() {
                    flush_buffer(&db, &mut buffer, &pending_count, &metrics).await;
                }
                for waiter in flush_waiters.drain(..) {
                    let _ = waiter.send(());
                }
                break;
            }
        }
    }
}

async fn flush_buffer(
    db: &PgPool,
    buffer: &mut Vec<NewAnalyticsEvent>,
    pending_count: &AtomicUsize,
    metrics: &AppMetrics,
) {
    if buffer.is_empty() {
        return;
    }

    let batch = std::mem::take(buffer);
    let count = batch.len();
    pending_count.fetch_sub(
        count.min(pending_count.load(Ordering::Relaxed)),
        Ordering::Relaxed,
    );

    if let Err(err) = insert_batch(db, &batch).await {
        metrics.record_analytics_dropped(count as u64);
        tracing::error!(error = ?err, batch_size = count, "Falha ao persistir lote de analytics");
    } else {
        metrics.record_analytics_persisted(count as u64);
    }
}

async fn insert_batch(db: &PgPool, batch: &[NewAnalyticsEvent]) -> anyhow::Result<()> {
    let len = batch.len();
    let mut event_types = Vec::with_capacity(len);
    let mut event_names = Vec::with_capacity(len);
    let mut visitor_ids = Vec::with_capacity(len);
    let mut user_ids = Vec::with_capacity(len);
    let mut organization_ids = Vec::with_capacity(len);
    let mut request_ids = Vec::with_capacity(len);
    let mut paths = Vec::with_capacity(len);
    let mut referrers = Vec::with_capacity(len);
    let mut page_titles = Vec::with_capacity(len);
    let mut element_tags = Vec::with_capacity(len);
    let mut element_labels = Vec::with_capacity(len);
    let mut element_targets = Vec::with_capacity(len);
    let mut click_x_pcts = Vec::with_capacity(len);
    let mut click_y_pcts = Vec::with_capacity(len);
    let mut duration_mss = Vec::with_capacity(len);
    let mut locales = Vec::with_capacity(len);
    let mut timezones = Vec::with_capacity(len);
    let mut country_codes = Vec::with_capacity(len);
    let mut regions = Vec::with_capacity(len);
    let mut cities = Vec::with_capacity(len);
    let mut device_types = Vec::with_capacity(len);
    let mut viewports = Vec::with_capacity(len);
    let mut ip_hashes = Vec::with_capacity(len);
    let mut properties_json = Vec::with_capacity(len);

    for ev in batch {
        event_types.push(ev.event_type.clone());
        event_names.push(ev.event_name.clone());
        visitor_ids.push(ev.visitor_id);
        user_ids.push(ev.user_id);
        organization_ids.push(ev.organization_id);
        request_ids.push(ev.request_id.clone());
        paths.push(ev.path.clone());
        referrers.push(ev.referrer.clone());
        page_titles.push(ev.page_title.clone());
        element_tags.push(ev.element_tag.clone());
        element_labels.push(ev.element_label.clone());
        element_targets.push(ev.element_target.clone());
        click_x_pcts.push(ev.click_x_pct);
        click_y_pcts.push(ev.click_y_pct);
        duration_mss.push(ev.duration_ms);
        locales.push(ev.locale.clone());
        timezones.push(ev.timezone.clone());
        country_codes.push(ev.country_code.clone());
        regions.push(ev.region.clone());
        cities.push(ev.city.clone());
        device_types.push(ev.device_type.clone());
        viewports.push(ev.viewport.clone());
        ip_hashes.push(ev.ip_hash.clone());
        properties_json.push(ev.properties.to_string());
    }

    sqlx::query(
        r#"
        INSERT INTO analytics_events (
            event_type,
            event_name,
            visitor_id,
            user_id,
            organization_id,
            request_id,
            path,
            referrer,
            page_title,
            element_tag,
            element_label,
            element_target,
            click_x_pct,
            click_y_pct,
            duration_ms,
            locale,
            timezone,
            country_code,
            region,
            city,
            device_type,
            viewport,
            ip_hash,
            properties
        )
        SELECT
            t.event_type,
            t.event_name,
            t.visitor_id,
            t.user_id,
            t.organization_id,
            t.request_id,
            t.path,
            t.referrer,
            t.page_title,
            t.element_tag,
            t.element_label,
            t.element_target,
            t.click_x_pct,
            t.click_y_pct,
            t.duration_ms,
            t.locale,
            t.timezone,
            t.country_code,
            t.region,
            t.city,
            t.device_type,
            t.viewport,
            t.ip_hash,
            t.properties::jsonb
        FROM UNNEST(
            $1::text[],
            $2::text[],
            $3::uuid[],
            $4::uuid[],
            $5::uuid[],
            $6::text[],
            $7::text[],
            $8::text[],
            $9::text[],
            $10::text[],
            $11::text[],
            $12::text[],
            $13::int2[],
            $14::int2[],
            $15::int4[],
            $16::text[],
            $17::text[],
            $18::text[],
            $19::text[],
            $20::text[],
            $21::text[],
            $22::text[],
            $23::text[],
            $24::text[]
        ) AS t(
            event_type,
            event_name,
            visitor_id,
            user_id,
            organization_id,
            request_id,
            path,
            referrer,
            page_title,
            element_tag,
            element_label,
            element_target,
            click_x_pct,
            click_y_pct,
            duration_ms,
            locale,
            timezone,
            country_code,
            region,
            city,
            device_type,
            viewport,
            ip_hash,
            properties
        )
        "#,
    )
    .bind(&event_types)
    .bind(&event_names)
    .bind(&visitor_ids)
    .bind(&user_ids)
    .bind(&organization_ids)
    .bind(&request_ids)
    .bind(&paths)
    .bind(&referrers)
    .bind(&page_titles)
    .bind(&element_tags)
    .bind(&element_labels)
    .bind(&element_targets)
    .bind(&click_x_pcts)
    .bind(&click_y_pcts)
    .bind(&duration_mss)
    .bind(&locales)
    .bind(&timezones)
    .bind(&country_codes)
    .bind(&regions)
    .bind(&cities)
    .bind(&device_types)
    .bind(&viewports)
    .bind(&ip_hashes)
    .bind(&properties_json)
    .execute(db)
    .await?;

    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct CollectBatchPayload {
    #[serde(default)]
    pub events: Vec<ClientAnalyticsEvent>,
    pub timezone: Option<String>,
    pub browser_locale: Option<String>,
    pub viewport: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ClientAnalyticsEvent {
    pub event_type: String,
    pub event_name: Option<String>,
    pub path: Option<String>,
    pub referrer: Option<String>,
    pub page_title: Option<String>,
    pub element_tag: Option<String>,
    pub element_label: Option<String>,
    pub element_target: Option<String>,
    pub click_x_pct: Option<i16>,
    pub click_y_pct: Option<i16>,
    pub duration_ms: Option<i32>,
    pub properties: Option<serde_json::Value>,
}

pub async fn collect_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: SignedCookieJar,
    body: Bytes,
) -> Response {
    if body.is_empty() || body.len() > MAX_PAYLOAD_BYTES {
        return StatusCode::BAD_REQUEST.into_response();
    }

    let Ok(payload) = serde_json::from_slice::<CollectBatchPayload>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };

    if payload.events.is_empty() {
        return StatusCode::NO_CONTENT.into_response();
    }

    let user = try_resolve_session_user(&headers, &state).await;
    let user_id = user.as_ref().map(|u| u.id);
    let organization_id = if let Some(uid) = user_id {
        resolve_active_organization_id(&state.db, &state.cache, &jar, uid).await
    } else {
        None
    };

    let (visitor_id, jar_to_set) = match jar
        .get(VISITOR_COOKIE)
        .and_then(|c| Uuid::parse_str(c.value()).ok())
    {
        Some(existing) => (existing, None),
        None => {
            let fresh = Uuid::new_v4();
            let cookie = Cookie::parse(format!(
                "{VISITOR_COOKIE}={fresh}; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax"
            ))
            .unwrap_or_else(|_| {
                Cookie::build((VISITOR_COOKIE, fresh.to_string()))
                    .path("/")
                    .http_only(true)
                    .same_site(SameSite::Lax)
                    .build()
            });
            (fresh, Some(jar.add(cookie)))
        }
    };

    let geo = extract_geo_context(&headers);
    let device_type = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|ua| classify_device(ua).to_string());
    let ip_hash = extract_client_ip(&headers).map(|ip| hash_ip(&ip, state.cookie_key.master()));
    let request_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| truncate_str(s, 64));

    let timezone = payload
        .timezone
        .as_deref()
        .map(|s| truncate_str(s, 64))
        .filter(|s| !s.is_empty());
    let locale = payload
        .browser_locale
        .as_deref()
        .map(|s| truncate_str(s, 24))
        .filter(|s| !s.is_empty());
    let viewport = payload
        .viewport
        .as_deref()
        .map(|s| truncate_str(s, 32))
        .filter(|s| !s.is_empty());

    for raw in payload.events.into_iter().take(MAX_EVENTS_PER_REQUEST) {
        let Some(event_type) = normalize_event_type(&raw.event_type) else {
            continue;
        };
        let event_name = raw
            .event_name
            .as_deref()
            .map(|s| truncate_str(s, 80))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| event_type.to_string());
        let path = normalize_path(raw.path.as_deref().unwrap_or("/"));

        let click_x_pct = raw.click_x_pct.map(|v| v.clamp(0, 100));
        let click_y_pct = raw.click_y_pct.map(|v| v.clamp(0, 100));
        let duration_ms = raw
            .duration_ms
            .filter(|&v| v >= 0)
            .map(|v| v.min(86_400_000));

        let properties = match raw.properties {
            Some(serde_json::Value::Object(map)) => serde_json::Value::Object(map),
            _ => serde_json::json!({}),
        };

        state.analytics.record(NewAnalyticsEvent {
            event_type: event_type.to_string(),
            event_name,
            visitor_id,
            user_id,
            organization_id,
            request_id: request_id.clone(),
            path,
            referrer: clean_opt(raw.referrer.as_deref(), 512),
            page_title: clean_opt(raw.page_title.as_deref(), 160),
            element_tag: clean_opt(raw.element_tag.as_deref(), 32),
            element_label: clean_opt(raw.element_label.as_deref(), 120),
            element_target: clean_opt(raw.element_target.as_deref(), 200),
            click_x_pct,
            click_y_pct,
            duration_ms,
            locale: locale.clone(),
            timezone: timezone.clone(),
            country_code: geo.country_code.clone(),
            region: geo.region.clone(),
            city: geo.city.clone(),
            device_type: device_type.clone(),
            viewport: viewport.clone(),
            ip_hash: ip_hash.clone(),
            properties,
        });
    }

    match jar_to_set {
        Some(updated_jar) => (StatusCode::ACCEPTED, updated_jar).into_response(),
        None => StatusCode::ACCEPTED.into_response(),
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct GeoContext {
    pub country_code: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
}

pub fn extract_geo_context(headers: &HeaderMap) -> GeoContext {
    let country_code = first_header(
        headers,
        &[
            "cf-ipcountry",
            "x-vercel-ip-country",
            "cloudfront-viewer-country",
            "fly-country",
            "x-country-code",
        ],
    )
    .map(|v| v.to_ascii_uppercase())
    .filter(|v| v.len() == 2 && v != "XX" && v != "T1");

    let region = first_header(
        headers,
        &[
            "x-vercel-ip-country-region",
            "cloudfront-viewer-country-region",
            "x-region",
        ],
    )
    .map(|v| decode_header_text(&v, 64));

    let city = first_header(
        headers,
        &[
            "x-vercel-ip-city",
            "cloudfront-viewer-city",
            "fly-city",
            "x-city",
        ],
    )
    .map(|v| decode_header_text(&v, 100));

    GeoContext {
        country_code,
        region,
        city,
    }
}

pub fn classify_device(user_agent: &str) -> &'static str {
    let ua = user_agent.to_ascii_lowercase();
    if ua.contains("bot")
        || ua.contains("spider")
        || ua.contains("crawl")
        || ua.contains("headless")
    {
        "bot"
    } else if ua.contains("ipad") || ua.contains("tablet") {
        "tablet"
    } else if ua.contains("mobi") || ua.contains("android") || ua.contains("iphone") {
        "mobile"
    } else {
        "desktop"
    }
}

pub fn extract_client_ip(headers: &HeaderMap) -> Option<String> {
    if let Some(ip) = first_header(headers, &["cf-connecting-ip", "x-real-ip"]) {
        return Some(truncate_str(&ip, 64));
    }
    first_header(headers, &["x-forwarded-for"]).and_then(|raw| {
        raw.split(',')
            .map(str::trim)
            .find(|s| !s.is_empty())
            .map(|ip| truncate_str(ip, 64))
    })
}

pub fn hash_ip(ip: &str, secret_key: &[u8]) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret_key).expect("HMAC aceita chaves de qualquer tamanho");
    mac.update(ip.as_bytes());
    let digest = mac.finalize().into_bytes();
    hex::encode(&digest[..8])
}

fn first_header(headers: &HeaderMap, names: &[&str]) -> Option<String> {
    for name in names {
        if let Some(val) = headers
            .get(*name)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return Some(val.to_string());
        }
    }
    None
}

fn decode_header_text(raw: &str, max_chars: usize) -> String {
    let replaced = raw.replace("%20", " ").replace('+', " ");
    truncate_str(replaced.trim(), max_chars)
}

fn normalize_event_type(raw: &str) -> Option<&'static str> {
    match raw.trim() {
        "page_view" => Some("page_view"),
        "click" => Some("click"),
        "page_leave" => Some("page_leave"),
        "custom" => Some("custom"),
        _ => None,
    }
}

fn normalize_path(raw: &str) -> String {
    let trimmed = raw.trim();
    let without_query = trimmed.split(['?', '#']).next().unwrap_or("/");
    if without_query.is_empty() {
        "/".to_string()
    } else if without_query.starts_with('/') {
        truncate_str(without_query, 256)
    } else {
        format!("/{}", truncate_str(without_query, 255))
    }
}

fn clean_opt(raw: Option<&str>, max_chars: usize) -> Option<String> {
    raw.map(|s| truncate_str(s.trim(), max_chars))
        .filter(|s| !s.is_empty())
}

fn truncate_str(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    #[test]
    fn extracts_geo_device_and_pseudonymous_ip_hash() {
        let mut headers = HeaderMap::new();
        headers.insert("cf-ipcountry", HeaderValue::from_static("br"));
        headers.insert("x-vercel-ip-country-region", HeaderValue::from_static("SP"));
        headers.insert("x-vercel-ip-city", HeaderValue::from_static("Sao%20Paulo"));
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("203.0.113.42, 10.0.0.1"),
        );
        headers.insert(
            "user-agent",
            HeaderValue::from_static(
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148",
            ),
        );

        let geo = extract_geo_context(&headers);
        assert_eq!(geo.country_code.as_deref(), Some("BR"));
        assert_eq!(geo.region.as_deref(), Some("SP"));
        assert_eq!(geo.city.as_deref(), Some("Sao Paulo"));

        let ip = extract_client_ip(&headers).unwrap();
        assert_eq!(ip, "203.0.113.42");
        let h1 = hash_ip(&ip, b"test-secret-key");
        let h2 = hash_ip(&ip, b"test-secret-key");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 16);
        assert_ne!(h1, ip);

        assert_eq!(
            classify_device(headers.get("user-agent").unwrap().to_str().unwrap()),
            "mobile"
        );
        assert_eq!(
            normalize_path("/reset-password?token=secret123"),
            "/reset-password"
        );
    }

    #[sqlx::test(migrations = "./migrations")]
    async fn collector_batches_flushes_and_updates_metrics(pool: PgPool) -> anyhow::Result<()> {
        let metrics = Arc::new(AppMetrics::new());
        let collector = AnalyticsCollector::new(pool.clone(), Arc::clone(&metrics));

        let visitor_id = Uuid::new_v4();
        collector.record(NewAnalyticsEvent {
            event_type: "page_view".to_string(),
            event_name: "page_view".to_string(),
            visitor_id,
            user_id: None,
            organization_id: None,
            request_id: Some("req-123".to_string()),
            path: "/dashboard".to_string(),
            referrer: Some("/login".to_string()),
            page_title: Some("Painel".to_string()),
            element_tag: None,
            element_label: None,
            element_target: None,
            click_x_pct: None,
            click_y_pct: None,
            duration_ms: None,
            locale: Some("pt-BR".to_string()),
            timezone: Some("America/Sao_Paulo".to_string()),
            country_code: Some("BR".to_string()),
            region: Some("SP".to_string()),
            city: Some("Sao Paulo".to_string()),
            device_type: Some("desktop".to_string()),
            viewport: Some("1440x900".to_string()),
            ip_hash: Some("0123456789abcdef".to_string()),
            properties: serde_json::json!({ "source": "test" }),
        });

        collector.record(NewAnalyticsEvent {
            event_type: "click".to_string(),
            event_name: "button_click".to_string(),
            visitor_id,
            user_id: None,
            organization_id: None,
            request_id: Some("req-124".to_string()),
            path: "/dashboard".to_string(),
            referrer: None,
            page_title: None,
            element_tag: Some("button".to_string()),
            element_label: Some("Criar organização".to_string()),
            element_target: Some("btn-create-org".to_string()),
            click_x_pct: Some(48),
            click_y_pct: Some(62),
            duration_ms: None,
            locale: Some("pt-BR".to_string()),
            timezone: Some("America/Sao_Paulo".to_string()),
            country_code: Some("BR".to_string()),
            region: Some("SP".to_string()),
            city: Some("Sao Paulo".to_string()),
            device_type: Some("desktop".to_string()),
            viewport: Some("1440x900".to_string()),
            ip_hash: Some("0123456789abcdef".to_string()),
            properties: serde_json::json!({}),
        });

        collector.record(NewAnalyticsEvent {
            event_type: "page_leave".to_string(),
            event_name: "time_on_page".to_string(),
            visitor_id,
            user_id: None,
            organization_id: None,
            request_id: Some("req-125".to_string()),
            path: "/dashboard".to_string(),
            referrer: None,
            page_title: None,
            element_tag: None,
            element_label: None,
            element_target: None,
            click_x_pct: None,
            click_y_pct: None,
            duration_ms: Some(12500),
            locale: Some("pt-BR".to_string()),
            timezone: Some("America/Sao_Paulo".to_string()),
            country_code: Some("BR".to_string()),
            region: Some("SP".to_string()),
            city: Some("Sao Paulo".to_string()),
            device_type: Some("desktop".to_string()),
            viewport: Some("1440x900".to_string()),
            ip_hash: Some("0123456789abcdef".to_string()),
            properties: serde_json::json!({}),
        });

        collector.flush().await;

        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM analytics_events WHERE visitor_id = $1")
                .bind(visitor_id)
                .fetch_one(&pool)
                .await?;
        assert_eq!(count, 3);

        let snap = metrics.snapshot();
        assert_eq!(snap.analytics_events_received, 3);
        assert_eq!(snap.analytics_events_persisted, 3);
        assert_eq!(snap.analytics_events_dropped, 0);

        Ok(())
    }
}
