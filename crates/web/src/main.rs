mod admin;
mod analytics;
mod auth;
mod billing;
mod cache;
mod cron;
mod error;
mod i18n;
mod jobs;
mod mailer;
mod oauth;
mod orgs;
mod security;
mod sse;
mod telemetry;

use anyhow::{Context, ensure};
use askama::Template;
use axum::{
    Router,
    extract::{FromRef, OriginalUri},
    http::header,
    response::IntoResponse,
    routing::{get, post},
};
use axum_extra::extract::cookie::Key;
use pgboss::Client as PgBossClient;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::net::SocketAddr;

use crate::analytics::AnalyticsCollector;
use crate::billing::StripeWebhookConfig;
use crate::cache::PgCache;
use crate::cron::PgCron;
use crate::oauth::GoogleOAuth;
use crate::security::RateLimitConfig;
use crate::sse::EventBus;
use crate::telemetry::TelemetryController;
use crate::{
    error::HtmlTemplate,
    i18n::{Locale, Translations},
    jobs::spawn_workers,
    mailer::ResendMailer,
};

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub boss: PgBossClient,
    pub cookie_key: Key,
    pub events: EventBus,
    pub cache: PgCache,
    pub cron: PgCron,
    pub telemetry: TelemetryController,
    pub analytics: AnalyticsCollector,
    pub admin_emails: Vec<String>,
    pub google: GoogleOAuth,
    pub stripe_webhook: Option<StripeWebhookConfig>,
    pub rate_limits: RateLimitConfig,
    pub app_url: String,
}

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.cookie_key.clone()
    }
}

#[derive(Template)]
#[template(path = "home.html")]
struct HomeTemplate {
    locale: Locale,
    t: &'static Translations,
    return_to: String,
}

async fn home(locale: Locale, OriginalUri(uri): OriginalUri) -> impl IntoResponse {
    HtmlTemplate(HomeTemplate {
        locale,
        t: locale.translations(),
        return_to: uri.to_string(),
    })
}

async fn htmx_asset() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "application/javascript")],
        include_str!("../assets/htmx.min.js"),
    )
}

async fn css_asset() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css")],
        include_str!("../assets/app.css"),
    )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let telemetry = telemetry::init_tracing()?;

    let database_url =
        std::env::var("DATABASE_URL").context("Variável DATABASE_URL não definida")?;
    let app_url = std::env::var("APP_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());
    let app_secret = std::env::var("APP_SECRET").context("Variável APP_SECRET não definida")?;
    let resend_api_key =
        std::env::var("RESEND_API_KEY").context("Variável RESEND_API_KEY não definida")?;
    let email_from = std::env::var("EMAIL_FROM")
        .unwrap_or_else(|_| "Sistema <onboarding@resend.dev>".to_string());

    ensure!(
        app_secret.len() >= 64,
        "APP_SECRET precisa ter no mínimo 64 caracteres para assinar cookies"
    );

    let db = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await
        .context("Falha ao conectar no PostgreSQL")?;

    sqlx::migrate!("./migrations")
        .run(&db)
        .await
        .context("Falha ao aplicar migrations")?;

    let boss = PgBossClient::with_pool(db.clone())
        .await
        .context("Falha ao inicializar cliente pgboss")?;
    boss.create_standard_queue(jobs::QUEUE_VERIFY_EMAIL).await?;
    boss.create_standard_queue(jobs::QUEUE_RESET_PASSWORD)
        .await?;
    boss.create_standard_queue(jobs::QUEUE_ORG_INVITE).await?;

    let mailer = ResendMailer::new(resend_api_key, email_from);
    spawn_workers(boss.clone(), mailer);
    let cache = PgCache::new(db.clone());
    let cron = PgCron::new(db.clone());
    let admin_emails = admin::parse_admin_emails();
    let promoted = admin::sync_configured_admins(&db, &cache, &admin_emails).await?;
    if promoted > 0 {
        tracing::info!(
            promoted,
            "Administradores configurados em ADMIN_EMAILS sincronizados"
        );
    }
    let google = GoogleOAuth::from_env(&app_url)?;
    let stripe_webhook = StripeWebhookConfig::from_env();
    let rate_limits = RateLimitConfig::from_env();
    let events = EventBus::with_pg_listener(db.clone()).await;
    let analytics = AnalyticsCollector::new(db.clone(), std::sync::Arc::clone(telemetry.metrics()));
    let analytics_shutdown = analytics.clone();

    let state = AppState {
        db,
        boss,
        cookie_key: Key::from(app_secret.as_bytes()),
        cache,
        events,
        cron,
        google,
        stripe_webhook,
        rate_limits,
        telemetry,
        analytics,
        admin_emails,
        app_url,
    };
    tracing::info!(
        app_url = %state.app_url,
        log_filter = %state.telemetry.current_filter(),
        log_format = state.telemetry.log_format(),
        "Servidor configurado"
    );

    let app = Router::new()
        .route("/", get(home))
        .route("/healthz", get(telemetry::healthz))
        .route("/metrics", get(telemetry::metrics_handler))
        .route("/analytics/collect", post(analytics::collect_events))
        // Painel administrativo do provedor do sistema
        .route("/admin", get(admin::admin_page))
        .route("/admin/settings", post(admin::update_settings))
        .route(
            "/admin/users/{id}/toggle-admin",
            post(admin::toggle_user_admin),
        )
        .route(
            "/admin/users/{id}/toggle-suspend",
            post(admin::toggle_user_suspend),
        )
        .route(
            "/admin/cache/purge-expired",
            post(admin::purge_expired_cache),
        )
        .route("/admin/cache/clear", post(admin::clear_non_session_cache))
        .route("/admin/cron/{job_id}/toggle", post(admin::toggle_cron_job))
        .route("/admin/jobs/retry-failed", post(admin::retry_failed_jobs))
        .route(
            "/admin/organizations/{id}/subscription",
            post(admin::update_organization_subscription),
        )
        // Webhooks externos
        .route("/webhooks/stripe", post(billing::stripe_webhook))
        // Área autenticada
        .route("/events", get(sse::events_stream))
        .route("/dashboard", get(auth::dashboard))
        .route(
            "/onboarding",
            get(orgs::onboarding_page).post(orgs::onboarding_submit),
        )
        .route(
            "/organizations",
            get(orgs::organizations_page).post(orgs::create_organization_from_dashboard),
        )
        .route("/organizations/switch", post(orgs::switch_organization))
        .route("/organizations/invites", post(orgs::create_invite))
        .route(
            "/organizations/invites/{id}/revoke",
            post(orgs::revoke_invite),
        )
        .route(
            "/organizations/members/{user_id}/role",
            post(orgs::update_member_role),
        )
        .route(
            "/organizations/members/{user_id}/remove",
            post(orgs::remove_member),
        )
        .route(
            "/invites/accept",
            get(orgs::accept_invite_page).post(orgs::accept_invite_submit),
        )
        .route("/language", post(i18n::set_language))
        .route("/resend-verification", post(auth::resend_verification))
        .route("/logout", post(auth::logout))
        // Fluxos públicos de autenticação
        .route("/login", get(auth::login_page).post(auth::login_submit))
        .route(
            "/register",
            get(auth::register_page).post(auth::register_submit),
        )
        .route("/auth/google", get(oauth::google_login))
        .route("/auth/google/callback", get(oauth::google_callback))
        .route("/verify-email", get(auth::verify_email))
        .route(
            "/forgot-password",
            get(auth::forgot_password_page).post(auth::forgot_password_submit),
        )
        .route(
            "/reset-password",
            get(auth::reset_password_page).post(auth::reset_password_submit),
        )
        // Assets estáticos embutidos no binário
        .route("/assets/htmx.min.js", get(htmx_asset))
        .route("/assets/app.css", get(css_asset))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            admin::maintenance_guard,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            security::rate_limit_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            security::csrf_middleware,
        ))
        .layer(axum::middleware::from_fn(i18n::localize))
        .layer(telemetry::propagate_request_id_layer())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            telemetry::http_metrics_middleware,
        ))
        .layer(telemetry::http_trace_layer())
        .layer(telemetry::set_request_id_layer())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    analytics_shutdown.flush().await;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
    tracing::info!("Sinal de encerramento recebido; finalizando servidor");
}
