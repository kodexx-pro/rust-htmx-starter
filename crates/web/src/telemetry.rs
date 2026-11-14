use std::{
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::Context;
use axum::{
    Json,
    extract::{Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use subtle::ConstantTimeEq;
use tower_http::{
    classify::{ServerErrorsAsFailures, SharedClassifier},
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::{DefaultOnResponse, TraceLayer},
};
use tracing::Level;
use tracing_subscriber::{
    EnvFilter, Registry, fmt, layer::SubscriberExt, reload, util::SubscriberInitExt,
};

use crate::AppState;

const DEFAULT_LOG_FILTER: &str = "web=info,tower_http=info,sqlx=warn";

type ReloadHandle = reload::Handle<EnvFilter, Registry>;

#[derive(Debug, Serialize, Clone, Copy)]
pub struct MetricsSnapshot {
    pub uptime_secs: u64,
    pub http_requests_total: u64,
    pub analytics_events_received: u64,
    pub analytics_events_persisted: u64,
    pub analytics_events_dropped: u64,
}

pub struct AppMetrics {
    started_at: Instant,
    http_requests_total: AtomicU64,
    http_requests_2xx: AtomicU64,
    http_requests_3xx: AtomicU64,
    http_requests_4xx: AtomicU64,
    http_requests_5xx: AtomicU64,
    http_request_duration_ms_sum: AtomicU64,
    http_request_duration_ms_count: AtomicU64,
    analytics_events_received: AtomicU64,
    analytics_events_page_view: AtomicU64,
    analytics_events_click: AtomicU64,
    analytics_events_page_leave: AtomicU64,
    analytics_events_custom: AtomicU64,
    analytics_events_persisted: AtomicU64,
    analytics_events_dropped: AtomicU64,
    analytics_engagement_ms_sum: AtomicU64,
    analytics_engagement_ms_count: AtomicU64,
}

impl Default for AppMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl AppMetrics {
    pub fn new() -> Self {
        Self {
            started_at: Instant::now(),
            http_requests_total: AtomicU64::new(0),
            http_requests_2xx: AtomicU64::new(0),
            http_requests_3xx: AtomicU64::new(0),
            http_requests_4xx: AtomicU64::new(0),
            http_requests_5xx: AtomicU64::new(0),
            http_request_duration_ms_sum: AtomicU64::new(0),
            http_request_duration_ms_count: AtomicU64::new(0),
            analytics_events_received: AtomicU64::new(0),
            analytics_events_page_view: AtomicU64::new(0),
            analytics_events_click: AtomicU64::new(0),
            analytics_events_page_leave: AtomicU64::new(0),
            analytics_events_custom: AtomicU64::new(0),
            analytics_events_persisted: AtomicU64::new(0),
            analytics_events_dropped: AtomicU64::new(0),
            analytics_engagement_ms_sum: AtomicU64::new(0),
            analytics_engagement_ms_count: AtomicU64::new(0),
        }
    }

    pub fn record_http_request(&self, status: StatusCode, duration: Duration) {
        self.http_requests_total.fetch_add(1, Ordering::Relaxed);
        let code = status.as_u16();
        if (200..300).contains(&code) {
            self.http_requests_2xx.fetch_add(1, Ordering::Relaxed);
        } else if (300..400).contains(&code) {
            self.http_requests_3xx.fetch_add(1, Ordering::Relaxed);
        } else if (400..500).contains(&code) {
            self.http_requests_4xx.fetch_add(1, Ordering::Relaxed);
        } else if code >= 500 {
            self.http_requests_5xx.fetch_add(1, Ordering::Relaxed);
        }
        let ms = duration.as_millis().min(u128::from(u64::MAX)) as u64;
        self.http_request_duration_ms_sum
            .fetch_add(ms, Ordering::Relaxed);
        self.http_request_duration_ms_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_analytics_received(&self, event_type: &str, duration_ms: Option<i32>) {
        self.analytics_events_received
            .fetch_add(1, Ordering::Relaxed);
        match event_type {
            "page_view" => {
                self.analytics_events_page_view
                    .fetch_add(1, Ordering::Relaxed);
            }
            "click" => {
                self.analytics_events_click.fetch_add(1, Ordering::Relaxed);
            }
            "page_leave" => {
                self.analytics_events_page_leave
                    .fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.analytics_events_custom.fetch_add(1, Ordering::Relaxed);
            }
        }
        if let Some(ms) = duration_ms
            && ms > 0
        {
            self.analytics_engagement_ms_sum
                .fetch_add(ms as u64, Ordering::Relaxed);
            self.analytics_engagement_ms_count
                .fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_analytics_persisted(&self, count: u64) {
        self.analytics_events_persisted
            .fetch_add(count, Ordering::Relaxed);
    }

    pub fn record_analytics_dropped(&self, count: u64) {
        self.analytics_events_dropped
            .fetch_add(count, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            uptime_secs: self.started_at.elapsed().as_secs(),
            http_requests_total: self.http_requests_total.load(Ordering::Relaxed),
            analytics_events_received: self.analytics_events_received.load(Ordering::Relaxed),
            analytics_events_persisted: self.analytics_events_persisted.load(Ordering::Relaxed),
            analytics_events_dropped: self.analytics_events_dropped.load(Ordering::Relaxed),
        }
    }

    pub fn render_prometheus(&self, analytics_queue_pending: usize) -> String {
        let uptime = self.started_at.elapsed().as_secs();
        let req_total = self.http_requests_total.load(Ordering::Relaxed);
        let req_2xx = self.http_requests_2xx.load(Ordering::Relaxed);
        let req_3xx = self.http_requests_3xx.load(Ordering::Relaxed);
        let req_4xx = self.http_requests_4xx.load(Ordering::Relaxed);
        let req_5xx = self.http_requests_5xx.load(Ordering::Relaxed);
        let req_ms_sum = self.http_request_duration_ms_sum.load(Ordering::Relaxed);
        let req_ms_count = self.http_request_duration_ms_count.load(Ordering::Relaxed);

        let ev_received = self.analytics_events_received.load(Ordering::Relaxed);
        let ev_page_view = self.analytics_events_page_view.load(Ordering::Relaxed);
        let ev_click = self.analytics_events_click.load(Ordering::Relaxed);
        let ev_page_leave = self.analytics_events_page_leave.load(Ordering::Relaxed);
        let ev_custom = self.analytics_events_custom.load(Ordering::Relaxed);
        let ev_persisted = self.analytics_events_persisted.load(Ordering::Relaxed);
        let ev_dropped = self.analytics_events_dropped.load(Ordering::Relaxed);
        let eng_ms_sum = self.analytics_engagement_ms_sum.load(Ordering::Relaxed);
        let eng_ms_count = self.analytics_engagement_ms_count.load(Ordering::Relaxed);

        format!(
            "# HELP app_uptime_seconds Process uptime in seconds\n\
# TYPE app_uptime_seconds gauge\n\
app_uptime_seconds {uptime}\n\
# HELP http_requests_total Total HTTP requests handled\n\
# TYPE http_requests_total counter\n\
http_requests_total {req_total}\n\
# HELP http_requests_by_status_total HTTP requests partitioned by status class\n\
# TYPE http_requests_by_status_total counter\n\
http_requests_by_status_total{{class=\"2xx\"}} {req_2xx}\n\
http_requests_by_status_total{{class=\"3xx\"}} {req_3xx}\n\
http_requests_by_status_total{{class=\"4xx\"}} {req_4xx}\n\
http_requests_by_status_total{{class=\"5xx\"}} {req_5xx}\n\
# HELP http_request_duration_ms_sum Cumulative HTTP request duration in milliseconds\n\
# TYPE http_request_duration_ms_sum counter\n\
http_request_duration_ms_sum {req_ms_sum}\n\
# HELP http_request_duration_ms_count Count of timed HTTP requests\n\
# TYPE http_request_duration_ms_count counter\n\
http_request_duration_ms_count {req_ms_count}\n\
# HELP analytics_events_received_total Usage events received by the app\n\
# TYPE analytics_events_received_total counter\n\
analytics_events_received_total {ev_received}\n\
# HELP analytics_events_by_type_total Usage events received by event type\n\
# TYPE analytics_events_by_type_total counter\n\
analytics_events_by_type_total{{type=\"page_view\"}} {ev_page_view}\n\
analytics_events_by_type_total{{type=\"click\"}} {ev_click}\n\
analytics_events_by_type_total{{type=\"page_leave\"}} {ev_page_leave}\n\
analytics_events_by_type_total{{type=\"custom\"}} {ev_custom}\n\
# HELP analytics_events_persisted_total Usage events flushed to PostgreSQL\n\
# TYPE analytics_events_persisted_total counter\n\
analytics_events_persisted_total {ev_persisted}\n\
# HELP analytics_events_dropped_total Usage events dropped due to queue saturation\n\
# TYPE analytics_events_dropped_total counter\n\
analytics_events_dropped_total {ev_dropped}\n\
# HELP analytics_queue_pending Approximate queued usage events waiting to flush\n\
# TYPE analytics_queue_pending gauge\n\
analytics_queue_pending {analytics_queue_pending}\n\
# HELP analytics_engagement_ms_sum Cumulative active page engagement time in milliseconds\n\
# TYPE analytics_engagement_ms_sum counter\n\
analytics_engagement_ms_sum {eng_ms_sum}\n\
# HELP analytics_engagement_ms_count Number of engagement duration samples\n\
# TYPE analytics_engagement_ms_count counter\n\
analytics_engagement_ms_count {eng_ms_count}\n"
        )
    }
}

#[derive(Clone)]
pub struct TelemetryController {
    reload_handle: ReloadHandle,
    current_filter: Arc<RwLock<String>>,
    log_format: &'static str,
    metrics: Arc<AppMetrics>,
    metrics_token: Option<String>,
}

impl TelemetryController {
    pub fn current_filter(&self) -> String {
        self.current_filter
            .read()
            .map(|guard| guard.clone())
            .unwrap_or_else(|_| DEFAULT_LOG_FILTER.to_string())
    }

    pub fn log_format(&self) -> &'static str {
        self.log_format
    }

    pub fn metrics(&self) -> &Arc<AppMetrics> {
        &self.metrics
    }

    pub fn set_filter(&self, raw_filter: &str) -> anyhow::Result<String> {
        let trimmed = raw_filter.trim();
        anyhow::ensure!(!trimmed.is_empty(), "Filtro de log não pode ser vazio");
        let parsed = EnvFilter::try_new(trimmed)
            .with_context(|| format!("Filtro de log inválido: '{trimmed}'"))?;
        self.reload_handle
            .reload(parsed)
            .context("Falha ao aplicar novo filtro de tracing em tempo de execução")?;
        if let Ok(mut guard) = self.current_filter.write() {
            *guard = trimmed.to_string();
        }
        tracing::info!(
            log_filter = trimmed,
            "Filtro de tracing atualizado em tempo real"
        );
        Ok(trimmed.to_string())
    }

    pub fn is_metrics_authorized(&self, headers: &HeaderMap) -> bool {
        let Some(expected) = self.metrics_token.as_deref() else {
            return true;
        };
        let Some(provided) = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
        else {
            return false;
        };
        provided.as_bytes().ct_eq(expected.as_bytes()).into()
    }

    #[cfg(test)]
    pub fn for_test() -> Self {
        let (_, reload_handle) = reload::Layer::new(EnvFilter::new(DEFAULT_LOG_FILTER));
        Self {
            reload_handle,
            current_filter: Arc::new(RwLock::new(DEFAULT_LOG_FILTER.to_string())),
            log_format: "compact",
            metrics: Arc::new(AppMetrics::new()),
            metrics_token: None,
        }
    }
}

pub fn init_tracing() -> anyhow::Result<TelemetryController> {
    let initial_filter = std::env::var("RUST_LOG")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_LOG_FILTER.to_string());

    let env_filter =
        EnvFilter::try_new(&initial_filter).unwrap_or_else(|_| EnvFilter::new(DEFAULT_LOG_FILTER));
    let (filter_layer, reload_handle) = reload::Layer::new(env_filter);

    let use_json = std::env::var("LOG_FORMAT")
        .ok()
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("json"));

    let log_format = if use_json {
        Registry::default()
            .with(filter_layer)
            .with(fmt::layer().json().with_current_span(true))
            .try_init()
            .context("Falha ao inicializar tracing JSON")?;
        "json"
    } else {
        Registry::default()
            .with(filter_layer)
            .with(fmt::layer().compact())
            .try_init()
            .context("Falha ao inicializar tracing")?;
        "compact"
    };

    let metrics_token = std::env::var("METRICS_TOKEN")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty());

    Ok(TelemetryController {
        reload_handle,
        current_filter: Arc::new(RwLock::new(initial_filter)),
        log_format,
        metrics: Arc::new(AppMetrics::new()),
        metrics_token,
    })
}

pub fn set_request_id_layer() -> SetRequestIdLayer<MakeRequestUuid> {
    SetRequestIdLayer::x_request_id(MakeRequestUuid)
}

pub fn propagate_request_id_layer() -> PropagateRequestIdLayer {
    PropagateRequestIdLayer::x_request_id()
}

pub fn http_trace_layer() -> TraceLayer<
    SharedClassifier<ServerErrorsAsFailures>,
    impl Fn(&axum::http::Request<axum::body::Body>) -> tracing::Span + Clone,
> {
    TraceLayer::new_for_http()
        .make_span_with(|request: &axum::http::Request<axum::body::Body>| {
            let request_id = request
                .headers()
                .get("x-request-id")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("-");
            tracing::info_span!(
                "http_request",
                method = %request.method(),
                uri = %request.uri().path(),
                request_id = %request_id,
            )
        })
        .on_response(DefaultOnResponse::new().level(Level::INFO))
}

pub async fn http_metrics_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let started = Instant::now();
    let response = next.run(request).await;
    state
        .telemetry
        .metrics()
        .record_http_request(response.status(), started.elapsed());
    response
}

pub async fn metrics_handler(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if !state.telemetry.is_metrics_authorized(&headers) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let body = state
        .telemetry
        .metrics()
        .render_prometheus(state.analytics.pending_approx());
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    database: &'static str,
    pg_cron: bool,
    log_filter: String,
    log_format: &'static str,
    metrics: MetricsSnapshot,
}

pub async fn healthz(State(state): State<AppState>) -> impl IntoResponse {
    let db_ok = sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.db)
        .await
        .is_ok();
    let pg_cron = if db_ok {
        state.cron.is_enabled().await
    } else {
        false
    };

    let status = if db_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status,
        Json(HealthResponse {
            status: if db_ok { "ok" } else { "degraded" },
            database: if db_ok { "ok" } else { "error" },
            pg_cron,
            log_filter: state.telemetry.current_filter(),
            log_format: state.telemetry.log_format(),
            metrics: state.telemetry.metrics().snapshot(),
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_records_http_and_analytics_and_renders_prometheus() {
        let metrics = AppMetrics::new();
        metrics.record_http_request(StatusCode::OK, Duration::from_millis(25));
        metrics.record_http_request(StatusCode::NOT_FOUND, Duration::from_millis(5));
        metrics.record_analytics_received("page_view", None);
        metrics.record_analytics_received("click", None);
        metrics.record_analytics_received("page_leave", Some(4200));
        metrics.record_analytics_persisted(3);

        let snap = metrics.snapshot();
        assert_eq!(snap.http_requests_total, 2);
        assert_eq!(snap.analytics_events_received, 3);
        assert_eq!(snap.analytics_events_persisted, 3);

        let prom = metrics.render_prometheus(7);
        assert!(prom.contains("http_requests_total 2"));
        assert!(prom.contains("http_requests_by_status_total{class=\"2xx\"} 1"));
        assert!(prom.contains("http_requests_by_status_total{class=\"4xx\"} 1"));
        assert!(prom.contains("analytics_events_by_type_total{type=\"click\"} 1"));
        assert!(prom.contains("analytics_engagement_ms_sum 4200"));
        assert!(prom.contains("analytics_queue_pending 7"));
    }
}
