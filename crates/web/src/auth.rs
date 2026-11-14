use std::time::Duration;

use anyhow::Context;
use askama::Template;
use axum::{
    Form,
    extract::{FromRequestParts, OriginalUri, Query, State},
    http::{StatusCode, header, request::Parts},
    response::{Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::{Cookie, SameSite, SignedCookieJar};
use domain::{DomainError, Organization, User, normalize_email, validate_name, validate_password};
use password_auth::{generate_hash, verify_password};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use sqlx::{Executor, FromRow, PgPool, Postgres};

use crate::{
    AppState,
    admin::{is_configured_admin_email, load_app_settings},
    billing::OrganizationSubscription,
    cache::PgCache,
    error::{AppError, FlashAlertTemplate, HtmlTemplate},
    i18n::{Locale, Translations, safe_return_to},
    jobs::{
        QUEUE_RESET_PASSWORD, QUEUE_VERIFY_EMAIL, ResetPasswordPayload, VerifyEmailPayload,
        enqueue, enqueue_transactional,
    },
    orgs::{ACTIVE_ORG_COOKIE, OrgContext, post_auth_redirect_path, role_label},
};

pub const SESSION_COOKIE: &str = "sid";

const SESSION_CACHE_TTL: Duration = Duration::from_secs(300);

pub(crate) fn session_cache_key(session_id: &str) -> String {
    format!("session:{session_id}")
}

pub(crate) async fn invalidate_user_sessions_cache(db: &PgPool, cache: &PgCache, user_id: Uuid) {
    if let Ok(session_ids) =
        sqlx::query_scalar::<_, String>("SELECT id FROM sessions WHERE user_id = $1")
            .bind(user_id)
            .fetch_all(db)
            .await
    {
        for session_id in session_ids {
            let _ = cache.delete(&session_cache_key(&session_id)).await;
        }
    }
}
// 1. TEMPLATES DE AUTH E DASHBOARD
#[derive(Template)]
#[template(path = "login.html")]
pub struct LoginTemplate {
    pub locale: Locale,
    pub t: &'static Translations,
    pub return_to: String,
    pub info: Option<String>,
    pub error: Option<String>,
    pub next_url: Option<String>,
}

#[derive(Template)]
#[template(path = "register.html")]
pub struct RegisterTemplate {
    pub locale: Locale,
    pub t: &'static Translations,
    pub return_to: String,
    pub registration_enabled: bool,
    pub next_url: Option<String>,
}

#[derive(Template)]
#[template(path = "forgot_password.html")]
pub struct ForgotPasswordTemplate {
    pub locale: Locale,
    pub t: &'static Translations,
    pub return_to: String,
}

#[derive(Template)]
#[template(path = "reset_password.html")]
pub struct ResetPasswordTemplate {
    pub locale: Locale,
    pub t: &'static Translations,
    pub return_to: String,
    pub token: String,
}

#[derive(Template)]
#[template(path = "dashboard.html")]
pub struct DashboardTemplate {
    pub locale: Locale,
    pub t: &'static Translations,
    pub return_to: String,
    pub user: User,
    pub organization: Organization,
    pub all_organizations: Vec<Organization>,
    pub organization_role: &'static str,
    pub subscription: OrganizationSubscription,
    pub subscription_label: &'static str,
    pub subscription_badge_class: &'static str,
    pub verified_just_now: bool,
}

#[derive(Template)]
#[template(path = "partials/verification_banner.html")]
pub struct VerificationBannerTemplate {
    pub t: &'static Translations,
    pub user: User,
}

// 2. EXTRATOR DE USUÁRIO LOGADO (Valida assinatura HMAC do cookie via SignedCookieJar)
pub struct AuthenticatedSession {
    pub user: User,
    pub session_id: String,
}

pub struct CurrentUser(pub User);

pub struct AuthRedirect {
    is_htmx: bool,
    is_sse: bool,
}

impl IntoResponse for AuthRedirect {
    fn into_response(self) -> Response {
        if self.is_htmx {
            (StatusCode::UNAUTHORIZED, [("HX-Redirect", "/login")]).into_response()
        } else if self.is_sse {
            StatusCode::UNAUTHORIZED.into_response()
        } else {
            Redirect::to("/login").into_response()
        }
    }
}

#[derive(Serialize, Deserialize)]
struct CachedSessionUser {
    id: Uuid,
    email: String,
    name: String,
    email_verified: bool,
    #[serde(default)]
    is_platform_admin: bool,
}

impl From<CachedSessionUser> for User {
    fn from(value: CachedSessionUser) -> Self {
        Self {
            id: value.id,
            email: value.email,
            name: value.name,
            email_verified: value.email_verified,
            is_platform_admin: value.is_platform_admin,
        }
    }
}

#[derive(FromRow)]
struct UserRow {
    id: Uuid,
    email: String,
    name: String,
    email_verified: bool,
    is_platform_admin: bool,
    ttl_secs: i64,
}

impl FromRequestParts<AppState> for AuthenticatedSession {
    type Rejection = AuthRedirect;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let is_htmx = parts.headers.contains_key("hx-request");
        let is_sse = parts
            .headers
            .get(header::ACCEPT)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|accept| accept.contains("text/event-stream"));
        let jar = SignedCookieJar::from_headers(&parts.headers, state.cookie_key.clone());

        let Some(cookie) = jar.get(SESSION_COOKIE) else {
            return Err(AuthRedirect { is_htmx, is_sse });
        };

        let session_id = cookie.value().to_string();
        let cache_key = session_cache_key(&session_id);

        if let Ok(Some(cached)) = state.cache.get::<CachedSessionUser>(&cache_key).await {
            return Ok(Self {
                user: cached.into(),
                session_id,
            });
        }

        let row = sqlx::query_as::<_, UserRow>(
            r#"
            SELECT
                u.id,
                u.email,
                u.name,
                u.email_verified,
                u.is_platform_admin,
                LEAST($2::bigint, GREATEST(0, FLOOR(EXTRACT(EPOCH FROM (s.expires_at - NOW())))::bigint)) AS ttl_secs
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.id = $1 AND s.expires_at > NOW() AND u.suspended_at IS NULL
            "#,
        )
        .bind(&session_id)
        .bind(SESSION_CACHE_TTL.as_secs() as i64)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

        match row {
            Some(u) => {
                if u.ttl_secs > 0 {
                    let cached = CachedSessionUser {
                        id: u.id,
                        email: u.email.clone(),
                        name: u.name.clone(),
                        email_verified: u.email_verified,
                        is_platform_admin: u.is_platform_admin,
                    };
                    let _ = state
                        .cache
                        .set(
                            &cache_key,
                            &cached,
                            Some(Duration::from_secs(u.ttl_secs as u64)),
                        )
                        .await;
                }
                Ok(Self {
                    user: User {
                        id: u.id,
                        email: u.email,
                        name: u.name,
                        email_verified: u.email_verified,
                        is_platform_admin: u.is_platform_admin,
                    },
                    session_id,
                })
            }
            None => Err(AuthRedirect { is_htmx, is_sse }),
        }
    }
}

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = AuthRedirect;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        AuthenticatedSession::from_request_parts(parts, state)
            .await
            .map(|session| Self(session.user))
    }
}

pub(crate) async fn try_resolve_session_user(
    headers: &header::HeaderMap,
    state: &AppState,
) -> Option<User> {
    let jar = SignedCookieJar::from_headers(headers, state.cookie_key.clone());
    let cookie = jar.get(SESSION_COOKIE)?;
    let session_id = cookie.value().to_string();
    let cache_key = session_cache_key(&session_id);

    if let Ok(Some(cached)) = state.cache.get::<CachedSessionUser>(&cache_key).await {
        return Some(cached.into());
    }

    let row = sqlx::query_as::<_, UserRow>(
        r#"
        SELECT
            u.id,
            u.email,
            u.name,
            u.email_verified,
            u.is_platform_admin,
            LEAST($2::bigint, GREATEST(0, FLOOR(EXTRACT(EPOCH FROM (s.expires_at - NOW())))::bigint)) AS ttl_secs
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.id = $1 AND s.expires_at > NOW() AND u.suspended_at IS NULL
        "#,
    )
    .bind(&session_id)
    .bind(SESSION_CACHE_TTL.as_secs() as i64)
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten()?;

    if row.ttl_secs > 0 {
        let cached = CachedSessionUser {
            id: row.id,
            email: row.email.clone(),
            name: row.name.clone(),
            email_verified: row.email_verified,
            is_platform_admin: row.is_platform_admin,
        };
        let _ = state
            .cache
            .set(
                &cache_key,
                &cached,
                Some(Duration::from_secs(row.ttl_secs as u64)),
            )
            .await;
    }

    Some(User {
        id: row.id,
        email: row.email,
        name: row.name,
        email_verified: row.email_verified,
        is_platform_admin: row.is_platform_admin,
    })
}

// Helpers internos de sessão e token
pub(crate) async fn create_session_cookie<'e, E>(
    executor: E,
    jar: SignedCookieJar,
    user_id: Uuid,
) -> anyhow::Result<SignedCookieJar>
where
    E: Executor<'e, Database = Postgres>,
{
    let session_id = Uuid::new_v4().to_string();
    sqlx::query(
        r#"
        INSERT INTO sessions (id, user_id, expires_at)
        VALUES ($1, $2, NOW() + INTERVAL '14 days')
        "#,
    )
    .bind(&session_id)
    .bind(user_id)
    .execute(executor)
    .await
    .context("Falha ao criar sessão")?;

    let cookie = Cookie::build((SESSION_COOKIE, session_id))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .build();

    Ok(jar.add(cookie))
}

async fn create_auth_token<'e, E>(
    executor: E,
    user_id: Uuid,
    purpose: &str,
    hours: i32,
) -> anyhow::Result<String>
where
    E: Executor<'e, Database = Postgres>,
{
    let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    sqlx::query(
        r#"
        INSERT INTO auth_tokens (token, user_id, purpose, expires_at)
        VALUES ($1, $2, $3, NOW() + ($4 * INTERVAL '1 hour'))
        "#,
    )
    .bind(&token)
    .bind(user_id)
    .bind(purpose)
    .bind(hours)
    .execute(executor)
    .await
    .context("Falha ao gerar token de autenticação")?;

    Ok(token)
}

// 3. HANDLERS DE PÁGINAS E AÇÕES
pub fn sanitize_next_path(raw: Option<&str>) -> Option<String> {
    let val = raw?.trim();
    if val.is_empty() {
        return None;
    }
    let safe = safe_return_to(val);
    if safe == "/login" && val != "/login" {
        return None;
    }
    if safe == "/login" || safe == "/register" {
        return None;
    }
    Some(safe.to_string())
}

#[derive(Deserialize)]
pub struct LoginQuery {
    pub reset: Option<String>,
    pub error: Option<String>,
    pub next: Option<String>,
}

pub async fn login_page(
    locale: Locale,
    OriginalUri(uri): OriginalUri,
    Query(q): Query<LoginQuery>,
) -> impl IntoResponse {
    let t = locale.translations();
    let info = q.reset.map(|_| t.password_reset_success.to_string());
    let error = q.error.as_deref().and_then(|code| match code {
        "google_unavailable" => Some(t.google_not_configured.to_string()),
        "google_cancelled" => Some(t.google_cancelled.to_string()),
        "google_failed" => Some(t.google_auth_failed.to_string()),
        "google_unverified_email" => Some(t.google_unverified_email.to_string()),
        "account_suspended" => Some(t.account_suspended.to_string()),
        _ => None,
    });
    HtmlTemplate(LoginTemplate {
        locale,
        t,
        return_to: uri.to_string(),
        info,
        error,
        next_url: sanitize_next_path(q.next.as_deref()),
    })
}

#[derive(Deserialize)]
pub struct LoginForm {
    pub email: String,
    pub password: String,
    pub next: Option<String>,
}

pub async fn login_submit(
    State(state): State<AppState>,
    headers: header::HeaderMap,
    locale: Locale,
    jar: SignedCookieJar,
    Form(form): Form<LoginForm>,
) -> Result<Response, AppError> {
    let email = normalize_email(&form.email).map_err(|_| DomainError::InvalidCredentials)?;

    #[derive(FromRow)]
    struct AuthRow {
        id: Uuid,
        password_hash: Option<String>,
        is_suspended: bool,
    }

    let user = sqlx::query_as::<_, AuthRow>(
        "SELECT id, password_hash, (suspended_at IS NOT NULL) AS is_suspended FROM users WHERE email = $1",
    )
    .bind(&email)
    .fetch_optional(&state.db)
    .await
    .context("Falha ao consultar usuário no login")?;

    let valid_user = user.filter(|u| {
        u.password_hash
            .as_deref()
            .is_some_and(|hash| verify_password(&form.password, hash).is_ok())
    });
    let Some(user) = valid_user else {
        return Err(DomainError::InvalidCredentials.into());
    };
    if user.is_suspended {
        return Err(DomainError::AccountSuspended.into());
    }
    let jar = create_session_cookie(&state.db, jar, user.id).await?;
    let next_path = match sanitize_next_path(form.next.as_deref()) {
        Some(custom) => custom,
        None => post_auth_redirect_path(&state.db, &state.cache, user.id)
            .await?
            .to_string(),
    };
    let visitor_id = jar
        .get(crate::analytics::VISITOR_COOKIE)
        .and_then(|c| Uuid::parse_str(c.value()).ok());
    state.analytics.track_server_event(
        &headers,
        state.cookie_key.master(),
        locale,
        visitor_id,
        Some(user.id),
        None,
        "auth.logged_in",
        "/login",
        serde_json::json!({ "method": "password" }),
    );
    Ok((jar, [("HX-Redirect", next_path)]).into_response())
}

#[derive(Deserialize)]
pub struct RegisterQuery {
    pub next: Option<String>,
}

pub async fn register_page(
    State(state): State<AppState>,
    locale: Locale,
    OriginalUri(uri): OriginalUri,
    Query(q): Query<RegisterQuery>,
) -> impl IntoResponse {
    let registration_enabled = load_app_settings(&state.db, &state.cache)
        .await
        .map(|s| s.registration_enabled)
        .unwrap_or(true);
    HtmlTemplate(RegisterTemplate {
        locale,
        t: locale.translations(),
        return_to: uri.to_string(),
        registration_enabled,
        next_url: sanitize_next_path(q.next.as_deref()),
    })
}

#[derive(Deserialize)]
pub struct RegisterForm {
    pub name: String,
    pub email: String,
    pub password: String,
    pub next: Option<String>,
}

pub async fn register_submit(
    State(state): State<AppState>,
    headers: header::HeaderMap,
    jar: SignedCookieJar,
    locale: Locale,
    Form(form): Form<RegisterForm>,
) -> Result<Response, AppError> {
    let settings = load_app_settings(&state.db, &state.cache).await?;
    if !settings.registration_enabled {
        return Err(DomainError::RegistrationDisabled.into());
    }

    let name = validate_name(&form.name)?;
    let email = normalize_email(&form.email)?;
    validate_password(&form.password)?;

    let mut tx = state.db.begin().await.context("Falha ao abrir transação")?;

    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
        .bind(&email)
        .fetch_one(&mut *tx)
        .await
        .context("Falha ao verificar e-mail existente")?;

    if exists {
        return Err(DomainError::EmailAlreadyInUse.into());
    }

    let user_id = Uuid::new_v4();
    let password_hash = generate_hash(&form.password);
    let is_platform_admin = is_configured_admin_email(&state.admin_emails, &email);

    sqlx::query(
        "INSERT INTO users (id, email, name, password_hash, is_platform_admin) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(user_id)
    .bind(&email)
    .bind(&name)
    .bind(&password_hash)
    .bind(is_platform_admin)
    .execute(&mut *tx)
    .await
    .context("Falha ao inserir novo usuário")?;
    let token = create_auth_token(&mut *tx, user_id, "verify_email", 24).await?;
    let jar = create_session_cookie(&mut *tx, jar, user_id).await?;
    let verify_url = format!(
        "{}/verify-email?token={token}&locale={}",
        state.app_url,
        locale.code()
    );
    enqueue_transactional(
        &mut tx,
        QUEUE_VERIFY_EMAIL,
        &VerifyEmailPayload {
            to: email,
            name,
            verify_url,
            locale,
        },
    )
    .await?;
    tx.commit().await.context("Falha ao confirmar cadastro")?;

    let visitor_id = jar
        .get(crate::analytics::VISITOR_COOKIE)
        .and_then(|c| Uuid::parse_str(c.value()).ok());
    state.analytics.track_server_event(
        &headers,
        state.cookie_key.master(),
        locale,
        visitor_id,
        Some(user_id),
        None,
        "auth.registered",
        "/register",
        serde_json::json!({ "method": "password" }),
    );

    let next_path =
        sanitize_next_path(form.next.as_deref()).unwrap_or_else(|| "/onboarding".to_string());
    Ok((jar, [("HX-Redirect", next_path)]).into_response())
}

#[derive(Deserialize)]
pub struct TokenQuery {
    pub token: String,
}

pub async fn verify_email(
    State(state): State<AppState>,
    locale: Locale,
    OriginalUri(uri): OriginalUri,
    Query(q): Query<TokenQuery>,
) -> Result<Response, AppError> {
    let mut tx = state.db.begin().await.context("Falha ao abrir transação")?;

    let user_id: Option<Uuid> = sqlx::query_scalar(
        r#"
        UPDATE auth_tokens
        SET used_at = NOW()
        WHERE token = $1
          AND purpose = 'verify_email'
          AND used_at IS NULL
          AND expires_at > NOW()
        RETURNING user_id
        "#,
    )
    .bind(&q.token)
    .fetch_optional(&mut *tx)
    .await
    .context("Falha ao validar token de verificação")?;

    let Some(user_id) = user_id else {
        return Ok(HtmlTemplate(LoginTemplate {
            locale,
            t: locale.translations(),
            return_to: uri.to_string(),
            info: None,
            error: Some(locale.translations().invalid_token.to_string()),
            next_url: None,
        })
        .into_response());
    };

    sqlx::query("UPDATE users SET email_verified = TRUE WHERE id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .context("Falha ao marcar e-mail como verificado")?;

    tx.commit()
        .await
        .context("Falha ao confirmar verificação de e-mail")?;
    invalidate_user_sessions_cache(&state.db, &state.cache, user_id).await;
    state.events.notify_email_verified(user_id);
    let next_path = post_auth_redirect_path(&state.db, &state.cache, user_id)
        .await
        .unwrap_or("/dashboard");
    Ok(Redirect::to(&format!("{next_path}?verified=1")).into_response())
}

pub async fn resend_verification(
    CurrentUser(user): CurrentUser,
    locale: Locale,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    if !user.email_verified {
        let token = create_auth_token(&state.db, user.id, "verify_email", 24).await?;
        let verify_url = format!(
            "{}/verify-email?token={token}&locale={}",
            state.app_url,
            locale.code()
        );

        enqueue(
            &state.boss,
            QUEUE_VERIFY_EMAIL,
            &VerifyEmailPayload {
                to: user.email.clone(),
                name: user.name.clone(),
                verify_url,
                locale,
            },
        )
        .await?;
    }

    let banner = VerificationBannerTemplate {
        user,
        t: locale.translations(),
    }
    .render()
    .map_err(anyhow::Error::from)?;
    let toast = FlashAlertTemplate {
        kind: "alert-success",
        message: locale.translations().verification_resent.to_string(),
    }
    .render()
    .map_err(anyhow::Error::from)?;

    Ok(Html(format!(
        r#"{banner}<div id="toast-container" hx-swap-oob="innerHTML">{toast}</div>"#
    )))
}

pub async fn forgot_password_page(
    locale: Locale,
    OriginalUri(uri): OriginalUri,
) -> impl IntoResponse {
    HtmlTemplate(ForgotPasswordTemplate {
        locale,
        t: locale.translations(),
        return_to: uri.to_string(),
    })
}

#[derive(Deserialize)]
pub struct ForgotPasswordForm {
    pub email: String,
}

pub async fn forgot_password_submit(
    State(state): State<AppState>,
    locale: Locale,
    Form(form): Form<ForgotPasswordForm>,
) -> Result<impl IntoResponse, AppError> {
    if let Ok(email) = normalize_email(&form.email) {
        let user_id: Option<Uuid> = sqlx::query_scalar("SELECT id FROM users WHERE email = $1")
            .bind(&email)
            .fetch_optional(&state.db)
            .await
            .context("Falha ao buscar usuário para recuperação de senha")?;

        if let Some(user_id) = user_id {
            let token = create_auth_token(&state.db, user_id, "reset_password", 1).await?;
            let reset_url = format!(
                "{}/reset-password?token={token}&locale={}",
                state.app_url,
                locale.code()
            );

            enqueue(
                &state.boss,
                QUEUE_RESET_PASSWORD,
                &ResetPasswordPayload {
                    to: email,
                    reset_url,
                    locale,
                },
            )
            .await?;
        }
    }

    // Resposta neutra evita enumeração de e-mails cadastrados
    Ok(HtmlTemplate(FlashAlertTemplate {
        kind: "alert-success",
        message: locale.translations().recovery_neutral.to_string(),
    }))
}

pub async fn reset_password_page(
    locale: Locale,
    OriginalUri(uri): OriginalUri,
    Query(q): Query<TokenQuery>,
) -> impl IntoResponse {
    HtmlTemplate(ResetPasswordTemplate {
        locale,
        t: locale.translations(),
        return_to: uri.to_string(),
        token: q.token,
    })
}

#[derive(Deserialize)]
pub struct ResetPasswordForm {
    pub token: String,
    pub password: String,
}

pub async fn reset_password_submit(
    State(state): State<AppState>,
    Form(form): Form<ResetPasswordForm>,
) -> Result<Response, AppError> {
    validate_password(&form.password)?;

    let mut tx = state.db.begin().await.context("Falha ao abrir transação")?;

    let user_id: Option<Uuid> = sqlx::query_scalar(
        r#"
        UPDATE auth_tokens
        SET used_at = NOW()
        WHERE token = $1
          AND purpose = 'reset_password'
          AND used_at IS NULL
          AND expires_at > NOW()
        RETURNING user_id
        "#,
    )
    .bind(&form.token)
    .fetch_optional(&mut *tx)
    .await
    .context("Falha ao validar token de redefinição")?;

    let Some(user_id) = user_id else {
        return Err(DomainError::InvalidOrExpiredToken.into());
    };

    let new_hash = generate_hash(&form.password);
    sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
        .bind(&new_hash)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .context("Falha ao atualizar senha")?;

    // Encerra todas as sessões ativas do usuário por segurança
    let revoked_sessions: Vec<String> =
        sqlx::query_scalar("DELETE FROM sessions WHERE user_id = $1 RETURNING id")
            .bind(user_id)
            .fetch_all(&mut *tx)
            .await
            .context("Falha ao encerrar sessões")?;

    tx.commit()
        .await
        .context("Falha ao confirmar redefinição de senha")?;
    for session_id in revoked_sessions {
        let _ = state.cache.delete(&session_cache_key(&session_id)).await;
    }
    state.events.notify_user_sessions_revoked(user_id);
    Ok(([("HX-Redirect", "/login?reset=1")]).into_response())
}

pub async fn logout(
    State(state): State<AppState>,
    jar: SignedCookieJar,
) -> Result<impl IntoResponse, AppError> {
    if let Some(cookie) = jar.get(SESSION_COOKIE) {
        sqlx::query("DELETE FROM sessions WHERE id = $1")
            .bind(cookie.value())
            .execute(&state.db)
            .await
            .context("Falha ao remover sessão")?;
        let _ = state.cache.delete(&session_cache_key(cookie.value())).await;
        state
            .events
            .notify_session_revoked(cookie.value().to_string());
    }

    let jar = jar
        .remove(Cookie::from(SESSION_COOKIE))
        .remove(Cookie::from(ACTIVE_ORG_COOKIE));
    Ok((jar, [("HX-Redirect", "/login")]))
}

#[derive(Deserialize)]
pub struct DashboardQuery {
    pub verified: Option<String>,
}

pub async fn dashboard(
    ctx: OrgContext,
    locale: Locale,
    OriginalUri(uri): OriginalUri,
    Query(q): Query<DashboardQuery>,
) -> Result<Response, AppError> {
    let t = locale.translations();
    let organization_role = role_label(ctx.organization.role, t);
    let (subscription_label, subscription_badge_class) = match ctx.subscription.parsed_status() {
        domain::SubscriptionStatus::Active => (t.sub_status_active, "badge-success"),
        domain::SubscriptionStatus::Trialing => (t.sub_status_trialing, "badge-info"),
        domain::SubscriptionStatus::PastDue | domain::SubscriptionStatus::Unpaid => {
            (t.sub_status_past_due, "badge-warning")
        }
        domain::SubscriptionStatus::Canceled
        | domain::SubscriptionStatus::Paused
        | domain::SubscriptionStatus::Incomplete
        | domain::SubscriptionStatus::IncompleteExpired => (t.sub_status_canceled, "badge-error"),
        domain::SubscriptionStatus::Inactive => (t.sub_status_inactive, "badge-ghost"),
    };

    Ok(HtmlTemplate(DashboardTemplate {
        locale,
        t,
        return_to: uri.to_string(),
        user: ctx.user,
        organization: ctx.organization,
        all_organizations: ctx.all_organizations,
        organization_role,
        subscription: ctx.subscription,
        subscription_label,
        subscription_badge_class,
        verified_just_now: q.verified.is_some(),
    })
    .into_response())
}
