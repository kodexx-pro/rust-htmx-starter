use std::{net::SocketAddr, time::Duration};

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use domain::DomainError;

use crate::{
    AppState,
    analytics::{extract_client_ip, hash_ip},
    error::AppError,
};

#[derive(Clone, Copy, Debug)]
pub struct RateLimitConfig {
    pub auth_max: i64,
    pub register_max: i64,
    pub analytics_max: i64,
    pub window_secs: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            auth_max: 10,
            register_max: 5,
            analytics_max: 120,
            window_secs: 60,
        }
    }
}

impl RateLimitConfig {
    pub fn from_env() -> Self {
        let parse = |key: &str, default: i64| -> i64 {
            std::env::var(key)
                .ok()
                .and_then(|v| v.trim().parse::<i64>().ok())
                .filter(|&v| v > 0)
                .unwrap_or(default)
        };
        let window_secs = std::env::var("RATE_LIMIT_WINDOW_SECS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(60);
        Self {
            auth_max: parse("RATE_LIMIT_AUTH_MAX", 10),
            register_max: parse("RATE_LIMIT_REGISTER_MAX", 5),
            analytics_max: parse("RATE_LIMIT_ANALYTICS_MAX", 120),
            window_secs,
        }
    }

    pub fn rule_for(self, method: &Method, path: &str) -> Option<(&'static str, i64)> {
        if *method != Method::POST {
            return None;
        }
        match path {
            "/login" => Some(("auth_login", self.auth_max)),
            "/register" => Some(("auth_register", self.register_max)),
            "/forgot-password" => Some(("auth_forgot", self.register_max)),
            "/resend-verification" => Some(("auth_resend", self.register_max)),
            "/reset-password" => Some(("auth_reset", self.auth_max)),
            "/organizations/invites" => Some(("org_invite", self.auth_max * 2)),
            "/analytics/collect" => Some(("analytics", self.analytics_max)),
            _ => None,
        }
    }
}

fn client_ip_identifier(
    headers: &HeaderMap,
    connect_info: Option<SocketAddr>,
    secret: &[u8],
) -> String {
    if let Some(ip) = extract_client_ip(headers) {
        return hash_ip(&ip, secret);
    }
    if let Some(addr) = connect_info {
        return hash_ip(&addr.ip().to_string(), secret);
    }
    "unknown".to_string()
}

pub async fn rate_limit_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();
    let Some((bucket, max_requests)) = state.rate_limits.rule_for(request.method(), &path) else {
        return next.run(request).await;
    };

    let connect_info = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0);
    let ip_key = client_ip_identifier(request.headers(), connect_info, state.cookie_key.master());
    let cache_key = format!("rl:{bucket}:{ip_key}");
    let window = Duration::from_secs(state.rate_limits.window_secs);

    match state.cache.incr_with_ttl(&cache_key, window).await {
        Ok(count) if count > max_requests => {
            tracing::warn!(
                bucket,
                path = %path,
                count,
                max_requests,
                "Rate limit excedido"
            );
            if path == "/analytics/collect" {
                let mut res = StatusCode::TOO_MANY_REQUESTS.into_response();
                if let Ok(val) = HeaderValue::from_str(&state.rate_limits.window_secs.to_string()) {
                    res.headers_mut().insert(header::RETRY_AFTER, val);
                }
                return res;
            }
            let mut res = AppError::Domain(DomainError::RateLimitExceeded).into_response();
            if let Ok(val) = HeaderValue::from_str(&state.rate_limits.window_secs.to_string()) {
                res.headers_mut().insert(header::RETRY_AFTER, val);
            }
            res
        }
        Ok(_) => next.run(request).await,
        Err(err) => {
            tracing::error!(error = ?err, bucket, "Falha ao consultar rate limiter no PgCache");
            next.run(request).await
        }
    }
}

fn is_unsafe_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

fn normalize_origin_authority(uri: &Uri) -> Option<(Option<&str>, String)> {
    let authority = uri.authority()?.as_str().to_ascii_lowercase();
    Some((uri.scheme_str(), authority))
}

fn origin_matches_request(origin_raw: &str, headers: &HeaderMap, app_url: &str) -> bool {
    let Ok(origin_uri) = origin_raw.trim().parse::<Uri>() else {
        return false;
    };
    let Some((origin_scheme, origin_auth)) = normalize_origin_authority(&origin_uri) else {
        return false;
    };

    if let Ok(app_uri) = app_url.trim().parse::<Uri>()
        && let Some((app_scheme, app_auth)) = normalize_origin_authority(&app_uri)
        && origin_auth == app_auth
        && (origin_scheme.is_none() || app_scheme.is_none() || origin_scheme == app_scheme)
    {
        return true;
    }

    if let Some(host) = headers.get(header::HOST).and_then(|v| v.to_str().ok())
        && origin_auth == host.trim().to_ascii_lowercase()
    {
        return true;
    }

    false
}

pub fn validate_csrf_headers(headers: &HeaderMap, app_url: &str) -> bool {
    if let Some(sec_fetch_site) = headers
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_ascii_lowercase())
        && sec_fetch_site != "same-origin"
        && sec_fetch_site != "none"
    {
        return false;
    }

    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        return origin_matches_request(origin, headers, app_url);
    }

    if let Some(referer) = headers.get(header::REFERER).and_then(|v| v.to_str().ok()) {
        return origin_matches_request(referer, headers, app_url);
    }

    true
}

pub async fn csrf_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if !is_unsafe_method(request.method()) || path.starts_with("/webhooks/") {
        return next.run(request).await;
    }

    if !validate_csrf_headers(request.headers(), &state.app_url) {
        tracing::warn!(path = %path, "Requisição bloqueada pela proteção CSRF");
        if path == "/analytics/collect" {
            return StatusCode::FORBIDDEN.into_response();
        }
        return AppError::Domain(DomainError::CsrfValidationFailed).into_response();
    }

    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, routing::post};
    use tower::ServiceExt;

    #[test]
    fn csrf_checks_fetch_metadata_origin_and_referer() {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, HeaderValue::from_static("localhost:3000"));
        assert!(validate_csrf_headers(&h, "http://localhost:3000"));

        h.insert("sec-fetch-site", HeaderValue::from_static("cross-site"));
        assert!(!validate_csrf_headers(&h, "http://localhost:3000"));

        h.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
        h.insert(
            header::ORIGIN,
            HeaderValue::from_static("http://localhost:3000"),
        );
        assert!(validate_csrf_headers(&h, "http://localhost:3000"));

        h.insert(
            header::ORIGIN,
            HeaderValue::from_static("https://evil.example"),
        );
        assert!(!validate_csrf_headers(&h, "http://localhost:3000"));

        h.remove(header::ORIGIN);
        h.insert(
            header::REFERER,
            HeaderValue::from_static("https://app.minhaempresa.com/login"),
        );
        assert!(validate_csrf_headers(&h, "https://app.minhaempresa.com"));

        h.insert(
            header::REFERER,
            HeaderValue::from_static("https://evil.example/phish"),
        );
        assert!(!validate_csrf_headers(&h, "https://app.minhaempresa.com"));
    }

    #[sqlx::test(migrations = "./migrations")]
    #[ignore = "requires PostgreSQL and DATABASE_URL with permission to create test databases"]
    async fn rate_limit_and_csrf_middlewares_enforce_limits_and_exemptions(
        pool: sqlx::PgPool,
    ) -> anyhow::Result<()> {
        let boss = pgboss::Client::with_pool(pool.clone()).await?;
        let cache = crate::cache::PgCache::new(pool.clone());
        let cron = crate::cron::PgCron::new(pool.clone());
        let telemetry = crate::telemetry::TelemetryController::for_test();
        let analytics = crate::analytics::AnalyticsCollector::new(
            pool.clone(),
            std::sync::Arc::clone(telemetry.metrics()),
        );
        let state = AppState {
            db: pool,
            boss,
            cookie_key: axum_extra::extract::cookie::Key::from(&[7u8; 64]),
            events: crate::sse::EventBus::new(),
            cache,
            cron,
            telemetry,
            analytics,
            admin_emails: vec![],
            google: crate::oauth::GoogleOAuth::from_env("http://localhost:3000")?,
            stripe_webhook: None,
            rate_limits: RateLimitConfig {
                auth_max: 2,
                register_max: 2,
                analytics_max: 2,
                window_secs: 60,
            },
            app_url: "http://localhost:3000".to_string(),
        };

        let app = Router::new()
            .route("/login", post(|| async { StatusCode::OK }))
            .route("/webhooks/stripe", post(|| async { StatusCode::OK }))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                rate_limit_middleware,
            ))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                csrf_middleware,
            ))
            .with_state(state);

        // 1. CSRF bloqueia POST cross-site em /login
        let csrf_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login")
                    .header("origin", "https://evil.example")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(csrf_res.status(), StatusCode::FORBIDDEN);

        // 2. Webhook Stripe é isento de CSRF
        let webhook_res = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/webhooks/stripe")
                    .header("origin", "https://stripe.com")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(webhook_res.status(), StatusCode::OK);

        // 3. Rate limit permite 2 tentativas e bloqueia a 3a com 429 + Retry-After
        for _ in 0..2 {
            let ok = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/login")
                        .header("origin", "http://localhost:3000")
                        .header("x-forwarded-for", "198.51.100.42")
                        .body(Body::empty())?,
                )
                .await?;
            assert_eq!(ok.status(), StatusCode::OK);
        }

        let limited = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/login")
                    .header("origin", "http://localhost:3000")
                    .header("x-forwarded-for", "198.51.100.42")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(limited.headers().get(header::RETRY_AFTER).unwrap(), "60");

        Ok(())
    }
}
