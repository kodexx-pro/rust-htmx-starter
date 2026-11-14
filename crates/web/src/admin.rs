use std::time::Duration;

use anyhow::Context;
use askama::Template;
use axum::{
    Form,
    extract::{FromRequestParts, OriginalUri, Path, Query, Request, State},
    http::{StatusCode, request::Parts},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};
use domain::{DomainError, SubscriptionStatus, User};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::{
    AppState,
    auth::{AuthenticatedSession, invalidate_user_sessions_cache},
    billing::invalidate_org_subscription_cache,
    cache::PgCache,
    cron::{CronJob, CronJobRun},
    error::{AppError, FlashAlertTemplate, HtmlTemplate},
    i18n::{Locale, Translations},
};

const APP_SETTINGS_CACHE_KEY: &str = "app_settings";
const APP_SETTINGS_CACHE_TTL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Serialize, Deserialize, FromRow, PartialEq, Eq)]
pub struct AppSettings {
    pub registration_enabled: bool,
    pub maintenance_mode: bool,
    pub google_oauth_enabled: bool,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            registration_enabled: true,
            maintenance_mode: false,
            google_oauth_enabled: true,
        }
    }
}

pub fn parse_admin_emails() -> Vec<String> {
    std::env::var("ADMIN_EMAILS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

pub fn is_configured_admin_email(admin_emails: &[String], email: &str) -> bool {
    let normalized = email.trim().to_ascii_lowercase();
    admin_emails
        .iter()
        .any(|candidate| candidate == &normalized)
}

pub async fn sync_configured_admins(
    db: &PgPool,
    cache: &PgCache,
    admin_emails: &[String],
) -> anyhow::Result<u64> {
    if admin_emails.is_empty() {
        return Ok(0);
    }

    let updated_ids: Vec<Uuid> = sqlx::query_scalar(
        r#"
        UPDATE users
        SET is_platform_admin = TRUE
        WHERE LOWER(email) = ANY($1)
          AND is_platform_admin = FALSE
        RETURNING id
        "#,
    )
    .bind(admin_emails)
    .fetch_all(db)
    .await
    .context("Falha ao promover administradores configurados em ADMIN_EMAILS")?;

    let count = updated_ids.len() as u64;
    for user_id in updated_ids {
        invalidate_user_sessions_cache(db, cache, user_id).await;
    }
    Ok(count)
}

pub async fn load_app_settings(db: &PgPool, cache: &PgCache) -> anyhow::Result<AppSettings> {
    cache
        .get_or_set(
            APP_SETTINGS_CACHE_KEY,
            Some(APP_SETTINGS_CACHE_TTL),
            || async {
                let row = sqlx::query_as::<_, AppSettings>(
                    r#"
                SELECT registration_enabled, maintenance_mode, google_oauth_enabled
                FROM app_settings
                WHERE id = 1
                "#,
                )
                .fetch_optional(db)
                .await
                .context("Falha ao carregar configurações da plataforma")?;
                Ok(row.unwrap_or_default())
            },
        )
        .await
}

pub async fn record_audit_log(
    db: &PgPool,
    actor_user_id: Option<Uuid>,
    action: &str,
    target: Option<&str>,
    details: serde_json::Value,
) -> anyhow::Result<()> {
    sqlx::query(
        r#"
        INSERT INTO audit_logs (id, actor_user_id, action, target, details)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(Uuid::new_v4())
    .bind(actor_user_id)
    .bind(action)
    .bind(target)
    .bind(sqlx::types::Json(details))
    .execute(db)
    .await
    .context("Falha ao registrar audit log")?;
    Ok(())
}

pub struct PlatformAdmin(pub User);

impl FromRequestParts<AppState> for PlatformAdmin {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let session = AuthenticatedSession::from_request_parts(parts, state)
            .await
            .map_err(IntoResponse::into_response)?;

        if !session.user.is_platform_admin {
            return Err(AppError::Domain(DomainError::Forbidden).into_response());
        }

        Ok(Self(session.user))
    }
}

pub async fn maintenance_guard(
    State(state): State<AppState>,
    locale: Locale,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    let bypass = path == "/healthz"
        || path == "/metrics"
        || path == "/login"
        || path == "/logout"
        || path == "/language"
        || path.starts_with("/auth/google")
        || path.starts_with("/assets/")
        || path.starts_with("/webhooks/")
        || path.starts_with("/analytics/")
        || path.starts_with("/admin");
    if bypass {
        return next.run(request).await;
    }

    let settings = match load_app_settings(&state.db, &state.cache).await {
        Ok(s) => s,
        Err(err) => {
            tracing::error!(error = ?err, "Falha ao verificar modo de manutenção");
            return next.run(request).await;
        }
    };

    if !settings.maintenance_mode {
        return next.run(request).await;
    }

    let (mut parts, body) = request.into_parts();
    if let Ok(session) = AuthenticatedSession::from_request_parts(&mut parts, &state).await
        && session.user.is_platform_admin
    {
        return next.run(Request::from_parts(parts, body)).await;
    }

    let t = locale.translations();
    let html = FlashAlertTemplate {
        kind: "alert-warning",
        message: t.maintenance_active.to_string(),
    }
    .render()
    .unwrap_or_else(|_| t.maintenance_active.to_string());

    (StatusCode::SERVICE_UNAVAILABLE, axum::response::Html(html)).into_response()
}

#[derive(Debug, FromRow)]
pub struct SystemMetrics {
    pub total_users: i64,
    pub verified_users: i64,
    pub suspended_users: i64,
    pub admin_users: i64,
    pub total_orgs: i64,
    pub active_subscriptions: i64,
    pub cache_entries: i64,
}

#[derive(Debug, FromRow)]
pub struct AdminUserRow {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub email_verified: bool,
    pub is_platform_admin: bool,
    pub is_suspended: bool,
    pub org_count: i64,
    pub created_at: String,
}

#[derive(Debug, FromRow)]
pub struct AdminOrgRow {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub member_count: i64,
    pub sub_status: String,
    pub plan_name: Option<String>,
    pub stripe_customer_id: Option<String>,
    pub stripe_subscription_id: Option<String>,
    pub current_period_end: Option<String>,
    pub created_at: String,
}
#[derive(Debug, FromRow)]
pub struct QueueStatsRow {
    pub name: String,
    pub created: i64,
    pub retry: i64,
    pub active: i64,
    pub failed: i64,
    pub completed: i64,
}

#[derive(Debug, FromRow)]
pub struct AuditLogRow {
    pub action: String,
    pub target: Option<String>,
    pub actor_email: Option<String>,
    pub created_at: String,
}

#[derive(Debug, FromRow)]
pub struct AdminWebhookEventRow {
    pub stripe_event_id: String,
    pub event_type: String,
    pub org_slug: Option<String>,
    pub processing_status: String,
    pub error_message: Option<String>,
    pub received_at: String,
}

#[derive(Debug, FromRow)]
pub struct AnalyticsSummary {
    pub page_views_24h: i64,
    pub clicks_24h: i64,
    pub unique_visitors_24h: i64,
    pub identified_users_24h: i64,
    pub avg_duration_secs: i64,
}

#[derive(Debug, FromRow)]
pub struct AnalyticsTopPageRow {
    pub path: String,
    pub views: i64,
    pub avg_duration_secs: i64,
}

#[derive(Debug, FromRow)]
pub struct AnalyticsTopClickRow {
    pub element_target: String,
    pub element_label: Option<String>,
    pub clicks: i64,
}

#[derive(Debug, FromRow)]
pub struct AnalyticsLocationRow {
    pub location_label: String,
    pub events_count: i64,
}

#[derive(Debug, FromRow)]
pub struct AnalyticsRecentEventRow {
    pub occurred_at: String,
    pub event_type: String,
    pub event_name: String,
    pub path: String,
    pub actor_label: String,
    pub detail: String,
    pub location_device: String,
}

#[derive(Template)]
#[template(path = "admin.html")]
pub struct AdminTemplate {
    pub locale: Locale,
    pub t: &'static Translations,
    pub return_to: String,
    pub admin: User,
    pub search_query: String,
    pub flash_message: Option<&'static str>,
    pub settings: AppSettings,
    pub log_filter: String,
    pub log_format: &'static str,
    pub metrics: SystemMetrics,
    pub users: Vec<AdminUserRow>,
    pub organizations: Vec<AdminOrgRow>,
    pub queues: Vec<QueueStatsRow>,
    pub failed_jobs_total: i64,
    pub cron_enabled: bool,
    pub cron_jobs: Vec<CronJob>,
    pub cron_runs: Vec<CronJobRun>,
    pub analytics_summary: AnalyticsSummary,
    pub analytics_top_pages: Vec<AnalyticsTopPageRow>,
    pub analytics_top_clicks: Vec<AnalyticsTopClickRow>,
    pub analytics_locations: Vec<AnalyticsLocationRow>,
    pub analytics_recent: Vec<AnalyticsRecentEventRow>,
    pub analytics_queue_pending: usize,
    pub webhook_events: Vec<AdminWebhookEventRow>,
    pub audit_logs: Vec<AuditLogRow>,
}

#[derive(Deserialize)]
pub struct AdminQuery {
    pub q: Option<String>,
    pub saved: Option<String>,
}

pub async fn admin_page(
    PlatformAdmin(admin): PlatformAdmin,
    State(state): State<AppState>,
    locale: Locale,
    OriginalUri(uri): OriginalUri,
    Query(query): Query<AdminQuery>,
) -> Result<Response, AppError> {
    let t = locale.translations();
    let settings = load_app_settings(&state.db, &state.cache).await?;

    let metrics = sqlx::query_as::<_, SystemMetrics>(
        r#"
        SELECT
            (SELECT COUNT(*) FROM users) AS total_users,
            (SELECT COUNT(*) FROM users WHERE email_verified = TRUE) AS verified_users,
            (SELECT COUNT(*) FROM users WHERE suspended_at IS NOT NULL) AS suspended_users,
            (SELECT COUNT(*) FROM users WHERE is_platform_admin = TRUE) AS admin_users,
            (SELECT COUNT(*) FROM organizations) AS total_orgs,
            (SELECT COUNT(*) FROM organization_subscriptions WHERE status IN ('active', 'trialing')) AS active_subscriptions,
            (SELECT COUNT(*) FROM cache_entries) AS cache_entries
        "#,
    )
    .fetch_one(&state.db)
    .await
    .context("Falha ao carregar métricas do painel admin")?;

    let search_query = query.q.unwrap_or_default().trim().to_string();
    let like_pattern = format!("%{}%", search_query);

    let users = sqlx::query_as::<_, AdminUserRow>(
        r#"
        SELECT
            u.id,
            u.email,
            u.name,
            u.email_verified,
            u.is_platform_admin,
            (u.suspended_at IS NOT NULL) AS is_suspended,
            COUNT(om.organization_id) AS org_count,
            TO_CHAR(u.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI') AS created_at
        FROM users u
        LEFT JOIN organization_members om ON om.user_id = u.id
        WHERE ($1 = '' OR u.email ILIKE $2 OR u.name ILIKE $2)
        GROUP BY u.id
        ORDER BY u.created_at DESC
        LIMIT 50
        "#,
    )
    .bind(&search_query)
    .bind(&like_pattern)
    .fetch_all(&state.db)
    .await
    .context("Falha ao listar usuários no painel admin")?;

    let organizations = sqlx::query_as::<_, AdminOrgRow>(
        r#"
        SELECT
            o.id,
            o.name,
            o.slug,
            COUNT(om.user_id) AS member_count,
            COALESCE(s.status, 'inactive') AS sub_status,
            s.plan_name,
            s.stripe_customer_id,
            s.stripe_subscription_id,
            TO_CHAR(s.current_period_end AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS current_period_end,
            TO_CHAR(o.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI') AS created_at
        FROM organizations o
        LEFT JOIN organization_members om ON om.organization_id = o.id
        LEFT JOIN organization_subscriptions s ON s.organization_id = o.id
        GROUP BY o.id, s.status, s.plan_name, s.stripe_customer_id, s.stripe_subscription_id, s.current_period_end
        ORDER BY o.created_at DESC
        LIMIT 50
        "#,
    )
    .fetch_all(&state.db)
    .await
    .context("Falha ao listar organizações no painel admin")?;

    let queues = sqlx::query_as::<_, QueueStatsRow>(
        r#"
        SELECT
            q.name,
            COUNT(j.id) FILTER (WHERE j.state = 'created') AS created,
            COUNT(j.id) FILTER (WHERE j.state = 'retry') AS retry,
            COUNT(j.id) FILTER (WHERE j.state = 'active') AS active,
            COUNT(j.id) FILTER (WHERE j.state = 'failed') AS failed,
            COUNT(j.id) FILTER (WHERE j.state = 'completed') AS completed
        FROM pgboss.queue q
        LEFT JOIN pgboss.job j ON j.name = q.name
        GROUP BY q.name
        ORDER BY q.name ASC
        "#,
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let failed_jobs_total: i64 = queues.iter().map(|q| q.failed).sum();

    let cron_enabled = state.cron.is_enabled().await;
    let (cron_jobs, cron_runs) = if cron_enabled {
        (
            state.cron.list_jobs().await.unwrap_or_default(),
            state.cron.recent_runs(15).await.unwrap_or_default(),
        )
    } else {
        (Vec::new(), Vec::new())
    };

    let audit_logs = sqlx::query_as::<_, AuditLogRow>(
        r#"
        SELECT
            a.action,
            a.target,
            u.email AS actor_email,
            TO_CHAR(a.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS') AS created_at
        FROM audit_logs a
        LEFT JOIN users u ON u.id = a.actor_user_id
        ORDER BY a.created_at DESC
        LIMIT 20
        "#,
    )
    .fetch_all(&state.db)
    .await
    .context("Falha ao listar audit logs no painel admin")?;

    let webhook_events = sqlx::query_as::<_, AdminWebhookEventRow>(
        r#"
        SELECT
            e.stripe_event_id,
            e.event_type,
            o.slug AS org_slug,
            e.processing_status,
            e.error_message,
            TO_CHAR(e.received_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS') AS received_at
        FROM stripe_webhook_events e
        LEFT JOIN organizations o ON o.id = e.organization_id
        ORDER BY e.received_at DESC
        LIMIT 20
        "#,
    )
    .fetch_all(&state.db)
    .await
    .context("Falha ao listar eventos de webhook Stripe")?;

    let analytics_summary = sqlx::query_as::<_, AnalyticsSummary>(
        r#"
        SELECT
            COUNT(*) FILTER (WHERE event_type = 'page_view' AND occurred_at >= NOW() - INTERVAL '24 hours') AS page_views_24h,
            COUNT(*) FILTER (WHERE event_type = 'click' AND occurred_at >= NOW() - INTERVAL '24 hours') AS clicks_24h,
            COUNT(DISTINCT visitor_id) FILTER (WHERE occurred_at >= NOW() - INTERVAL '24 hours') AS unique_visitors_24h,
            COUNT(DISTINCT user_id) FILTER (WHERE user_id IS NOT NULL AND occurred_at >= NOW() - INTERVAL '24 hours') AS identified_users_24h,
            COALESCE(ROUND(AVG(duration_ms) FILTER (WHERE event_type = 'page_leave' AND duration_ms > 0 AND occurred_at >= NOW() - INTERVAL '24 hours') / 1000.0)::bigint, 0) AS avg_duration_secs
        FROM analytics_events
        "#,
    )
    .fetch_one(&state.db)
    .await
    .context("Falha ao carregar resumo de analytics")?;

    let analytics_top_pages = sqlx::query_as::<_, AnalyticsTopPageRow>(
        r#"
        SELECT
            path,
            COUNT(*) FILTER (WHERE event_type = 'page_view') AS views,
            COALESCE(ROUND(AVG(duration_ms) FILTER (WHERE event_type = 'page_leave' AND duration_ms > 0) / 1000.0)::bigint, 0) AS avg_duration_secs
        FROM analytics_events
        WHERE occurred_at >= NOW() - INTERVAL '7 days'
          AND event_type IN ('page_view', 'page_leave')
        GROUP BY path
        HAVING COUNT(*) FILTER (WHERE event_type = 'page_view') > 0
        ORDER BY views DESC, path ASC
        LIMIT 10
        "#,
    )
    .fetch_all(&state.db)
    .await
    .context("Falha ao carregar páginas mais acessadas")?;

    let analytics_top_clicks = sqlx::query_as::<_, AnalyticsTopClickRow>(
        r#"
        SELECT
            COALESCE(element_target, element_tag, 'unknown') AS element_target,
            MAX(element_label) AS element_label,
            COUNT(*) AS clicks
        FROM analytics_events
        WHERE occurred_at >= NOW() - INTERVAL '7 days'
          AND event_type = 'click'
        GROUP BY COALESCE(element_target, element_tag, 'unknown')
        ORDER BY clicks DESC
        LIMIT 10
        "#,
    )
    .fetch_all(&state.db)
    .await
    .context("Falha ao carregar cliques mais frequentes")?;

    let analytics_locations = sqlx::query_as::<_, AnalyticsLocationRow>(
        r#"
        SELECT
            COALESCE(
                NULLIF(CONCAT_WS(', ', city, region, country_code), ''),
                NULLIF(timezone, ''),
                'Desconhecido'
            ) AS location_label,
            COUNT(*) AS events_count
        FROM analytics_events
        WHERE occurred_at >= NOW() - INTERVAL '7 days'
        GROUP BY location_label
        ORDER BY events_count DESC
        LIMIT 10
        "#,
    )
    .fetch_all(&state.db)
    .await
    .context("Falha ao carregar localizações de analytics")?;

    let analytics_recent = sqlx::query_as::<_, AnalyticsRecentEventRow>(
        r#"
        SELECT
            TO_CHAR(e.occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS') AS occurred_at,
            e.event_type,
            e.event_name,
            e.path,
            COALESCE(u.email, 'anon:' || SUBSTRING(e.visitor_id::text, 1, 8)) AS actor_label,
            CASE
                WHEN e.event_type = 'click' THEN COALESCE(e.element_target, e.element_label, e.element_tag, '-')
                WHEN e.event_type = 'page_leave' THEN COALESCE(ROUND(e.duration_ms / 1000.0, 1)::text || 's', '-')
                ELSE COALESCE(e.element_target, e.page_title, e.event_name)
            END AS detail,
            COALESCE(
                NULLIF(CONCAT_WS(' · ', NULLIF(CONCAT_WS(', ', e.city, e.country_code), ''), e.timezone, e.device_type), ''),
                '-'
            ) AS location_device
        FROM analytics_events e
        LEFT JOIN users u ON u.id = e.user_id
        ORDER BY e.occurred_at DESC, e.id DESC
        LIMIT 25
        "#,
    )
    .fetch_all(&state.db)
    .await
    .context("Falha ao carregar eventos recentes de analytics")?;

    let flash_message = match query.saved.as_deref() {
        Some("settings") => Some(t.admin_saved_settings),
        Some("user") => Some(t.admin_saved_user),
        Some("cache") => Some(t.admin_saved_cache),
        Some("cron") => Some(t.admin_saved_cron),
        Some("jobs") => Some(t.admin_saved_jobs),
        Some("subscription") => Some(t.admin_saved_subscription),
        _ => None,
    };
    Ok(HtmlTemplate(AdminTemplate {
        locale,
        t,
        return_to: uri.to_string(),
        admin,
        search_query,
        flash_message,
        settings,
        log_filter: state.telemetry.current_filter(),
        log_format: state.telemetry.log_format(),
        metrics,
        users,
        organizations,
        queues,
        failed_jobs_total,
        cron_enabled,
        cron_jobs,
        cron_runs,
        analytics_summary,
        analytics_top_pages,
        analytics_top_clicks,
        analytics_locations,
        analytics_recent,
        analytics_queue_pending: state.analytics.pending_approx(),
        webhook_events,
        audit_logs,
    })
    .into_response())
}

#[derive(Deserialize)]
pub struct AdminSettingsForm {
    pub registration_enabled: Option<String>,
    pub maintenance_mode: Option<String>,
    pub google_oauth_enabled: Option<String>,
    pub log_filter: Option<String>,
}

pub async fn update_settings(
    PlatformAdmin(admin): PlatformAdmin,
    State(state): State<AppState>,
    Form(form): Form<AdminSettingsForm>,
) -> Result<Response, AppError> {
    let registration_enabled = form.registration_enabled.is_some();
    let maintenance_mode = form.maintenance_mode.is_some();
    let google_oauth_enabled = form.google_oauth_enabled.is_some();

    if let Some(raw_filter) = form
        .log_filter
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        && raw_filter != state.telemetry.current_filter()
    {
        state
            .telemetry
            .set_filter(raw_filter)
            .map_err(|_| DomainError::InvalidLogFilter)?;
    }

    sqlx::query(
        r#"
        INSERT INTO app_settings (id, registration_enabled, maintenance_mode, google_oauth_enabled, updated_at, updated_by)
        VALUES (1, $1, $2, $3, NOW(), $4)
        ON CONFLICT (id) DO UPDATE SET
            registration_enabled = EXCLUDED.registration_enabled,
            maintenance_mode = EXCLUDED.maintenance_mode,
            google_oauth_enabled = EXCLUDED.google_oauth_enabled,
            updated_at = NOW(),
            updated_by = EXCLUDED.updated_by
        "#,
    )
    .bind(registration_enabled)
    .bind(maintenance_mode)
    .bind(google_oauth_enabled)
    .bind(admin.id)
    .execute(&state.db)
    .await
    .context("Falha ao atualizar configurações da plataforma")?;

    let _ = state.cache.delete(APP_SETTINGS_CACHE_KEY).await;

    record_audit_log(
        &state.db,
        Some(admin.id),
        "settings.updated",
        Some("app_settings"),
        serde_json::json!({
            "registration_enabled": registration_enabled,
            "maintenance_mode": maintenance_mode,
            "google_oauth_enabled": google_oauth_enabled,
            "log_filter": state.telemetry.current_filter(),
        }),
    )
    .await?;

    tracing::info!(
        admin_id = %admin.id,
        registration_enabled,
        maintenance_mode,
        google_oauth_enabled,
        "Configurações da plataforma atualizadas via /admin"
    );

    Ok(Redirect::to("/admin?saved=settings").into_response())
}

pub async fn toggle_user_admin(
    PlatformAdmin(admin): PlatformAdmin,
    State(state): State<AppState>,
    Path(target_user_id): Path<Uuid>,
) -> Result<Response, AppError> {
    if target_user_id == admin.id {
        return Err(DomainError::Forbidden.into());
    }

    let new_state: Option<bool> = sqlx::query_scalar(
        r#"
        UPDATE users
        SET is_platform_admin = NOT is_platform_admin
        WHERE id = $1
        RETURNING is_platform_admin
        "#,
    )
    .bind(target_user_id)
    .fetch_optional(&state.db)
    .await
    .context("Falha ao alterar papel de administrador")?;

    if let Some(is_admin) = new_state {
        invalidate_user_sessions_cache(&state.db, &state.cache, target_user_id).await;
        record_audit_log(
            &state.db,
            Some(admin.id),
            if is_admin {
                "user.admin_granted"
            } else {
                "user.admin_revoked"
            },
            Some(&target_user_id.to_string()),
            serde_json::json!({ "is_platform_admin": is_admin }),
        )
        .await?;
    }

    Ok(Redirect::to("/admin?saved=user").into_response())
}

pub async fn toggle_user_suspend(
    PlatformAdmin(admin): PlatformAdmin,
    State(state): State<AppState>,
    Path(target_user_id): Path<Uuid>,
) -> Result<Response, AppError> {
    if target_user_id == admin.id {
        return Err(DomainError::Forbidden.into());
    }

    let is_suspended: Option<bool> = sqlx::query_scalar(
        r#"
        UPDATE users
        SET suspended_at = CASE WHEN suspended_at IS NULL THEN NOW() ELSE NULL END
        WHERE id = $1
        RETURNING (suspended_at IS NOT NULL)
        "#,
    )
    .bind(target_user_id)
    .fetch_optional(&state.db)
    .await
    .context("Falha ao suspender ou reativar usuário")?;

    if let Some(suspended) = is_suspended {
        if suspended {
            let revoked_sessions: Vec<String> =
                sqlx::query_scalar("DELETE FROM sessions WHERE user_id = $1 RETURNING id")
                    .bind(target_user_id)
                    .fetch_all(&state.db)
                    .await
                    .context("Falha ao encerrar sessões do usuário suspenso")?;
            for sid in revoked_sessions {
                let _ = state
                    .cache
                    .delete(&crate::auth::session_cache_key(&sid))
                    .await;
            }
            state.events.notify_user_sessions_revoked(target_user_id);
        }

        record_audit_log(
            &state.db,
            Some(admin.id),
            if suspended {
                "user.suspended"
            } else {
                "user.unsuspended"
            },
            Some(&target_user_id.to_string()),
            serde_json::json!({ "suspended": suspended }),
        )
        .await?;
    }

    Ok(Redirect::to("/admin?saved=user").into_response())
}

pub async fn purge_expired_cache(
    PlatformAdmin(admin): PlatformAdmin,
    State(state): State<AppState>,
) -> Result<Response, AppError> {
    let deleted = state.cache.purge_expired().await?;
    record_audit_log(
        &state.db,
        Some(admin.id),
        "cache.purged_expired",
        Some("cache_entries"),
        serde_json::json!({ "deleted": deleted }),
    )
    .await?;

    Ok(Redirect::to("/admin?saved=cache").into_response())
}

pub async fn clear_non_session_cache(
    PlatformAdmin(admin): PlatformAdmin,
    State(state): State<AppState>,
) -> Result<Response, AppError> {
    let result =
        sqlx::query("DELETE FROM cache_entries WHERE NOT starts_with(cache_key, 'session:')")
            .execute(&state.db)
            .await
            .context("Falha ao limpar cache não-sessão")?;

    record_audit_log(
        &state.db,
        Some(admin.id),
        "cache.cleared_non_sessions",
        Some("cache_entries"),
        serde_json::json!({ "deleted": result.rows_affected() }),
    )
    .await?;

    Ok(Redirect::to("/admin?saved=cache").into_response())
}

pub async fn toggle_cron_job(
    PlatformAdmin(admin): PlatformAdmin,
    State(state): State<AppState>,
    Path(job_id): Path<i64>,
) -> Result<Response, AppError> {
    let jobs = state.cron.list_jobs().await?;
    if let Some(job) = jobs.into_iter().find(|j| j.jobid == job_id) {
        let next_active = !job.active;
        state.cron.set_active(job_id, next_active).await?;
        record_audit_log(
            &state.db,
            Some(admin.id),
            "cron.toggled",
            job.jobname.as_deref(),
            serde_json::json!({ "jobid": job_id, "active": next_active }),
        )
        .await?;
    }

    Ok(Redirect::to("/admin?saved=cron").into_response())
}

pub async fn retry_failed_jobs(
    PlatformAdmin(admin): PlatformAdmin,
    State(state): State<AppState>,
) -> Result<Response, AppError> {
    let retried = sqlx::query(
        r#"
        UPDATE pgboss.job
        SET state = 'retry', retry_count = 0, start_after = NOW()
        WHERE state = 'failed'
        "#,
    )
    .execute(&state.db)
    .await
    .map(|r| r.rows_affected())
    .unwrap_or(0);

    record_audit_log(
        &state.db,
        Some(admin.id),
        "jobs.retried_failed",
        Some("pgboss.job"),
        serde_json::json!({ "retried": retried }),
    )
    .await?;

    Ok(Redirect::to("/admin?saved=jobs").into_response())
}

#[derive(Deserialize)]
pub struct AdminOrgSubscriptionForm {
    pub status: String,
    pub plan_name: Option<String>,
    pub stripe_customer_id: Option<String>,
    pub stripe_subscription_id: Option<String>,
}

fn clean_optional_field(raw: Option<String>) -> Option<String> {
    raw.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

pub async fn update_organization_subscription(
    PlatformAdmin(admin): PlatformAdmin,
    State(state): State<AppState>,
    Path(organization_id): Path<Uuid>,
    Form(form): Form<AdminOrgSubscriptionForm>,
) -> Result<Response, AppError> {
    let status = SubscriptionStatus::parse(&form.status).ok_or(DomainError::Forbidden)?;
    let plan_name = clean_optional_field(form.plan_name);
    let stripe_customer_id = clean_optional_field(form.stripe_customer_id);
    let stripe_subscription_id = clean_optional_field(form.stripe_subscription_id);

    sqlx::query(
        r#"
        INSERT INTO organization_subscriptions (
            organization_id,
            stripe_customer_id,
            stripe_subscription_id,
            status,
            plan_name,
            updated_at
        )
        VALUES ($1, $2, $3, $4, $5, NOW())
        ON CONFLICT (organization_id) DO UPDATE SET
            stripe_customer_id = EXCLUDED.stripe_customer_id,
            stripe_subscription_id = EXCLUDED.stripe_subscription_id,
            status = EXCLUDED.status,
            plan_name = EXCLUDED.plan_name,
            updated_at = NOW()
        "#,
    )
    .bind(organization_id)
    .bind(&stripe_customer_id)
    .bind(&stripe_subscription_id)
    .bind(status.as_str())
    .bind(&plan_name)
    .execute(&state.db)
    .await
    .context("Falha ao atualizar assinatura da organização")?;

    invalidate_org_subscription_cache(&state.cache, organization_id).await;

    record_audit_log(
        &state.db,
        Some(admin.id),
        "organization.subscription_updated",
        Some(&organization_id.to_string()),
        serde_json::json!({
            "status": status.as_str(),
            "plan_name": plan_name,
            "stripe_customer_id": stripe_customer_id,
            "stripe_subscription_id": stripe_subscription_id,
        }),
    )
    .await?;

    Ok(Redirect::to("/admin?saved=subscription").into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[sqlx::test(migrations = "./migrations")]
    async fn app_settings_persists_and_invalidates_cache_and_syncs_admins(
        pool: PgPool,
    ) -> anyhow::Result<()> {
        let cache = PgCache::new(pool.clone());
        let user_id = Uuid::new_v4();
        sqlx::query("INSERT INTO users (id, email, name) VALUES ($1, $2, $3)")
            .bind(user_id)
            .bind("provider@exemplo.com")
            .bind("Provedor")
            .execute(&pool)
            .await?;

        let promoted =
            sync_configured_admins(&pool, &cache, &["provider@exemplo.com".to_string()]).await?;
        assert_eq!(promoted, 1);

        let is_admin: bool =
            sqlx::query_scalar("SELECT is_platform_admin FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_one(&pool)
                .await?;
        assert!(is_admin);

        let defaults = load_app_settings(&pool, &cache).await?;
        assert_eq!(defaults, AppSettings::default());

        sqlx::query(
            "UPDATE app_settings SET registration_enabled = FALSE, maintenance_mode = TRUE WHERE id = 1",
        )
        .execute(&pool)
        .await?;
        cache.delete(APP_SETTINGS_CACHE_KEY).await?;

        let updated = load_app_settings(&pool, &cache).await?;
        assert!(!updated.registration_enabled);
        assert!(updated.maintenance_mode);
        assert!(updated.google_oauth_enabled);

        Ok(())
    }
}
