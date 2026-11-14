use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::{Cookie, SameSite, SignedCookieJar};
use domain::normalize_email;
use openidconnect::{
    AccessTokenHash, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
    reqwest as oidc_reqwest,
};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::{
    AppState,
    admin::{is_configured_admin_email, load_app_settings},
    analytics::VISITOR_COOKIE,
    auth::{create_session_cookie, invalidate_user_sessions_cache},
    cache::PgCache,
    i18n::Locale,
    orgs::post_auth_redirect_path,
    sse::EventBus,
};

const GOOGLE_ISSUER_URL: &str = "https://accounts.google.com";
const OAUTH_FLOW_COOKIE: &str = "oauth_google";
const GOOGLE_PROVIDER: &str = "google";
const GOOGLE_METADATA_CACHE_KEY: &str = "oidc:google:metadata";
const GOOGLE_METADATA_TTL: Duration = Duration::from_secs(3600);

#[derive(Clone)]
struct GoogleOAuthConfig {
    client_id: ClientId,
    client_secret: ClientSecret,
    redirect_url: RedirectUrl,
}

#[derive(Clone)]
pub struct GoogleOAuth {
    config: Option<GoogleOAuthConfig>,
    http_client: oidc_reqwest::Client,
}

impl GoogleOAuth {
    pub fn from_env(app_url: &str) -> anyhow::Result<Self> {
        let client_id = std::env::var("GOOGLE_CLIENT_ID")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        let client_secret = std::env::var("GOOGLE_CLIENT_SECRET")
            .ok()
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());

        let config = match (client_id, client_secret) {
            (Some(id), Some(secret)) => {
                let redirect_uri =
                    format!("{}/auth/google/callback", app_url.trim_end_matches('/'));
                let redirect_url = RedirectUrl::new(redirect_uri)
                    .context("URL de redirecionamento do Google OAuth inválida")?;
                Some(GoogleOAuthConfig {
                    client_id: ClientId::new(id),
                    client_secret: ClientSecret::new(secret),
                    redirect_url,
                })
            }
            _ => None,
        };

        let http_client = oidc_reqwest::ClientBuilder::new()
            .redirect(oidc_reqwest::redirect::Policy::none())
            .build()
            .context("Falha ao criar cliente HTTP do Google OIDC")?;

        Ok(Self {
            config,
            http_client,
        })
    }

    pub fn is_configured(&self) -> bool {
        self.config.is_some()
    }

    async fn metadata(&self, cache: &PgCache) -> anyhow::Result<CoreProviderMetadata> {
        cache
            .get_or_set(
                GOOGLE_METADATA_CACHE_KEY,
                Some(GOOGLE_METADATA_TTL),
                || async {
                    let issuer = IssuerUrl::new(GOOGLE_ISSUER_URL.to_string())?;
                    CoreProviderMetadata::discover_async(issuer, &self.http_client)
                        .await
                        .context("Falha ao descobrir metadados OpenID Connect do Google")
                },
            )
            .await
    }
}

#[derive(Serialize, Deserialize)]
struct PendingOAuthFlow {
    state: String,
    nonce: String,
    pkce_verifier: String,
    expires_at: u64,
    #[serde(default)]
    next: Option<String>,
}

#[derive(Deserialize)]
pub struct GoogleLoginQuery {
    pub next: Option<String>,
}

pub async fn google_login(
    State(state): State<AppState>,
    jar: SignedCookieJar,
    Query(query): Query<GoogleLoginQuery>,
) -> Response {
    let settings = load_app_settings(&state.db, &state.cache)
        .await
        .unwrap_or_default();
    let Some(config) = (if settings.google_oauth_enabled {
        state.google.config.as_ref()
    } else {
        None
    }) else {
        return Redirect::to("/login?error=google_unavailable").into_response();
    };

    let metadata = match state.google.metadata(&state.cache).await {
        Ok(m) => m,
        Err(_) => return Redirect::to("/login?error=google_failed").into_response(),
    };

    let client = CoreClient::from_provider_metadata(
        metadata,
        config.client_id.clone(),
        Some(config.client_secret.clone()),
    )
    .set_redirect_uri(config.redirect_url.clone());

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, csrf_token, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let Ok(payload) = serde_json::to_string(&PendingOAuthFlow {
        state: csrf_token.secret().clone(),
        nonce: nonce.secret().clone(),
        pkce_verifier: pkce_verifier.secret().clone(),
        expires_at: now_secs + 600,
        next: crate::auth::sanitize_next_path(query.next.as_deref()),
    }) else {
        return Redirect::to("/login?error=google_failed").into_response();
    };

    let cookie = Cookie::build((OAUTH_FLOW_COOKIE, payload))
        .path("/auth/google")
        .http_only(true)
        .same_site(SameSite::Lax)
        .build();
    (jar.add(cookie), Redirect::to(auth_url.as_str())).into_response()
}

#[derive(Deserialize)]
pub struct GoogleCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

fn clear_oauth_cookie(jar: SignedCookieJar) -> SignedCookieJar {
    jar.remove(
        Cookie::build(OAUTH_FLOW_COOKIE)
            .path("/auth/google")
            .build(),
    )
}

pub async fn google_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    locale: Locale,
    jar: SignedCookieJar,
    Query(query): Query<GoogleCallbackQuery>,
) -> Response {
    let flow_cookie = jar.get(OAUTH_FLOW_COOKIE).map(|c| c.value().to_string());
    let jar = clear_oauth_cookie(jar);
    if let Some(err) = query.error {
        let code = if err == "access_denied" {
            "google_cancelled"
        } else {
            "google_failed"
        };
        return (jar, Redirect::to(&format!("/login?error={code}"))).into_response();
    }

    let Some(config) = &state.google.config else {
        return (jar, Redirect::to("/login?error=google_unavailable")).into_response();
    };

    let (Some(code), Some(returned_state), Some(flow_json)) =
        (query.code, query.state, flow_cookie)
    else {
        return (jar, Redirect::to("/login?error=google_failed")).into_response();
    };

    let Ok(pending) = serde_json::from_str::<PendingOAuthFlow>(&flow_json) else {
        return (jar, Redirect::to("/login?error=google_failed")).into_response();
    };

    if CsrfToken::new(returned_state) != CsrfToken::new(pending.state) {
        return (jar, Redirect::to("/login?error=google_failed")).into_response();
    }
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now_secs > pending.expires_at {
        return (jar, Redirect::to("/login?error=google_failed")).into_response();
    }

    let metadata = match state.google.metadata(&state.cache).await {
        Ok(m) => m,
        Err(_) => return (jar, Redirect::to("/login?error=google_failed")).into_response(),
    };

    let client = CoreClient::from_provider_metadata(
        metadata,
        config.client_id.clone(),
        Some(config.client_secret.clone()),
    )
    .set_redirect_uri(config.redirect_url.clone());

    let Ok(token_request) = client.exchange_code(AuthorizationCode::new(code)) else {
        return (jar, Redirect::to("/login?error=google_failed")).into_response();
    };

    let Ok(token_response) = token_request
        .set_pkce_verifier(PkceCodeVerifier::new(pending.pkce_verifier))
        .request_async(&state.google.http_client)
        .await
    else {
        return (jar, Redirect::to("/login?error=google_failed")).into_response();
    };

    let Some(id_token) = token_response.id_token() else {
        return (jar, Redirect::to("/login?error=google_failed")).into_response();
    };

    let id_token_verifier = client.id_token_verifier();
    let expected_nonce = Nonce::new(pending.nonce);
    let Ok(claims) = id_token.claims(&id_token_verifier, &expected_nonce) else {
        return (jar, Redirect::to("/login?error=google_failed")).into_response();
    };

    if let Some(expected_access_token_hash) = claims.access_token_hash() {
        let verified_hash = (|| -> anyhow::Result<bool> {
            let actual_hash = AccessTokenHash::from_token(
                token_response.access_token(),
                id_token.signing_alg()?,
                id_token.signing_key(&id_token_verifier)?,
            )?;
            Ok(actual_hash == *expected_access_token_hash)
        })();
        if !verified_hash.unwrap_or(false) {
            return (jar, Redirect::to("/login?error=google_failed")).into_response();
        }
    }

    if claims.email_verified() != Some(true) {
        return (jar, Redirect::to("/login?error=google_unverified_email")).into_response();
    }

    let Some(raw_email) = claims.email().map(|e| e.as_str()) else {
        return (jar, Redirect::to("/login?error=google_failed")).into_response();
    };

    let display_name = claims
        .name()
        .and_then(|localized| localized.get(None))
        .map(|name| name.as_str().trim().to_string())
        .filter(|name| name.chars().count() >= 2)
        .unwrap_or_else(|| fallback_name_from_email(raw_email));

    let identity = GoogleIdentity {
        subject: claims.subject().as_str().to_string(),
        email: raw_email.to_string(),
        name: display_name,
    };

    let user_id = match upsert_google_user(
        &state.db,
        &state.cache,
        &state.events,
        &state.admin_emails,
        &identity,
    )
    .await
    {
        Ok(id) => id,
        Err(err) if err.to_string().contains("account_suspended") => {
            return (jar, Redirect::to("/login?error=account_suspended")).into_response();
        }
        Err(_) => return (jar, Redirect::to("/login?error=google_failed")).into_response(),
    };

    let Ok(jar) = create_session_cookie(&state.db, jar.clone(), user_id).await else {
        return (jar, Redirect::to("/login?error=google_failed")).into_response();
    };

    let next_path = match pending.next {
        Some(custom) => custom,
        None => post_auth_redirect_path(&state.db, &state.cache, user_id)
            .await
            .unwrap_or("/onboarding")
            .to_string(),
    };
    let visitor_id = jar
        .get(VISITOR_COOKIE)
        .and_then(|c| Uuid::parse_str(c.value()).ok());
    state.analytics.track_server_event(
        &headers,
        state.cookie_key.master(),
        locale,
        visitor_id,
        Some(user_id),
        None,
        "auth.logged_in",
        "/auth/google/callback",
        serde_json::json!({ "method": "google_oidc" }),
    );
    (jar, Redirect::to(&next_path)).into_response()
}

fn fallback_name_from_email(email: &str) -> String {
    let local = email.split('@').next().unwrap_or("").trim();
    if local.chars().count() >= 2 {
        local.to_string()
    } else {
        "Usuário Google".to_string()
    }
}

#[derive(Debug, Clone)]
pub struct GoogleIdentity {
    pub subject: String,
    pub email: String,
    pub name: String,
}

#[derive(FromRow)]
struct ExistingUserRow {
    id: Uuid,
    email_verified: bool,
    is_suspended: bool,
}

pub async fn upsert_google_user(
    db: &PgPool,
    cache: &PgCache,
    events: &EventBus,
    admin_emails: &[String],
    identity: &GoogleIdentity,
) -> anyhow::Result<Uuid> {
    let email = normalize_email(&identity.email)?;
    let mut tx = db.begin().await.context("Falha ao abrir transação OAuth")?;

    let linked_user: Option<ExistingUserRow> = sqlx::query_as(
        r#"
        SELECT u.id, u.email_verified, (u.suspended_at IS NOT NULL) AS is_suspended
        FROM oauth_accounts oa
        JOIN users u ON u.id = oa.user_id
        WHERE oa.provider = $1 AND oa.provider_user_id = $2
        "#,
    )
    .bind(GOOGLE_PROVIDER)
    .bind(&identity.subject)
    .fetch_optional(&mut *tx)
    .await
    .context("Falha ao consultar conta Google vinculada")?;

    let (user_id, became_verified) = if let Some(user) = linked_user {
        anyhow::ensure!(!user.is_suspended, "account_suspended");
        let mut verified_now = false;
        if !user.email_verified {
            sqlx::query("UPDATE users SET email_verified = TRUE WHERE id = $1")
                .bind(user.id)
                .execute(&mut *tx)
                .await
                .context("Falha ao atualizar verificação do usuário Google")?;
            verified_now = true;
        }
        (user.id, verified_now)
    } else {
        let existing_by_email: Option<ExistingUserRow> = sqlx::query_as(
            "SELECT id, email_verified, (suspended_at IS NOT NULL) AS is_suspended FROM users WHERE email = $1",
        )
        .bind(&email)
        .fetch_optional(&mut *tx)
        .await
        .context("Falha ao buscar usuário existente por e-mail")?;

        let (user_id, verified_now) = if let Some(existing) = existing_by_email {
            anyhow::ensure!(!existing.is_suspended, "account_suspended");
            let mut verified_now = false;
            if !existing.email_verified {
                sqlx::query("UPDATE users SET email_verified = TRUE WHERE id = $1")
                    .bind(existing.id)
                    .execute(&mut *tx)
                    .await
                    .context("Falha ao marcar e-mail como verificado via Google")?;
                verified_now = true;
            }
            (existing.id, verified_now)
        } else {
            let user_id = Uuid::new_v4();
            let is_platform_admin = is_configured_admin_email(admin_emails, &email);
            sqlx::query(
                r#"
                INSERT INTO users (id, email, name, password_hash, email_verified, is_platform_admin)
                VALUES ($1, $2, $3, NULL, TRUE, $4)
                "#,
            )
            .bind(user_id)
            .bind(&email)
            .bind(&identity.name)
            .bind(is_platform_admin)
            .execute(&mut *tx)
            .await
            .context("Falha ao criar usuário via Google")?;
            (user_id, false)
        };

        sqlx::query(
            r#"
            INSERT INTO oauth_accounts (provider, provider_user_id, user_id)
            VALUES ($1, $2, $3)
            ON CONFLICT (provider, provider_user_id) DO NOTHING
            "#,
        )
        .bind(GOOGLE_PROVIDER)
        .bind(&identity.subject)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .context("Falha ao vincular conta Google")?;

        (user_id, verified_now)
    };

    tx.commit()
        .await
        .context("Falha ao confirmar autenticação Google")?;

    if became_verified {
        invalidate_user_sessions_cache(db, cache, user_id).await;
        events.notify_email_verified(user_id);
    }

    Ok(user_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_name_handles_short_or_valid_emails() {
        assert_eq!(fallback_name_from_email("ana.silva@gmail.com"), "ana.silva");
        assert_eq!(fallback_name_from_email("a@gmail.com"), "Usuário Google");
    }

    #[test]
    fn google_oauth_from_env_is_optional() {
        // Without GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET set, initialization succeeds as unconfigured.
        let oauth = GoogleOAuth::from_env("http://localhost:3000").unwrap();
        let expected = std::env::var("GOOGLE_CLIENT_ID")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .is_some()
            && std::env::var("GOOGLE_CLIENT_SECRET")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .is_some();
        assert_eq!(oauth.is_configured(), expected);
    }
}
