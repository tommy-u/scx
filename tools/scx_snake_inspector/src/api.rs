// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{mpsc, Arc};
use std::time::Duration;

use axum::extract::Request;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use tokio_stream::wrappers::WatchStream;
use tokio_stream::StreamExt;

use crate::collector::{CollectorCommand, FineTimingCallback, FineTimingControlResponse};
use crate::dashboard::Dashboard;
use crate::policies::PolicyActivation;
use crate::scope::{resolve_scope, ScopeRequest};

pub const CSRF_HEADER: &str = "x-snake-token";
const INDEX_HTML: &str = include_str!("web/index.html");
const APP_JS: &str = include_str!("web/app.js");
const HEATMAP_JS: &str = include_str!("web/heatmap.js");
const INSPECTION_JS: &str = include_str!("web/inspection.js");
const STYLE_CSS: &str = include_str!("web/style.css");

#[derive(Clone)]
pub struct ApiContext {
    dashboard: Dashboard,
    commands: mpsc::Sender<CollectorCommand>,
    token: Arc<str>,
    cgroup_root: Arc<PathBuf>,
    initial_window_ms: u64,
}

impl ApiContext {
    pub fn new(
        dashboard: Dashboard,
        commands: mpsc::Sender<CollectorCommand>,
        token: impl Into<Arc<str>>,
        cgroup_root: PathBuf,
    ) -> Self {
        Self {
            dashboard,
            commands,
            token: token.into(),
            cgroup_root: Arc::new(cgroup_root),
            initial_window_ms: 10_000,
        }
    }

    pub fn with_initial_window_ms(mut self, initial_window_ms: u64) -> Self {
        self.initial_window_ms = initial_window_ms;
        self
    }
}

pub fn router(context: ApiContext) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/assets/app.js", get(app_script))
        .route("/assets/heatmap.js", get(heatmap_script))
        .route("/assets/inspection.js", get(inspection_script))
        .route("/assets/style.css", get(stylesheet))
        .route("/api/topology", get(topology))
        .route("/api/snapshot", get(snapshot))
        .route("/api/inspection", get(inspection))
        .route("/api/callback-timing", get(callback_timing))
        .route("/api/fine-timing", get(fine_timing).post(set_fine_timing))
        .route("/api/policies", get(policies))
        .route("/api/policies/activate", post(activate_policy))
        .route("/api/events", get(events))
        .route("/api/scope", post(set_scope))
        .layer(middleware::from_fn(require_loopback_host))
        .with_state(context)
}

async fn require_loopback_host(request: Request, next: Next) -> Response {
    let allowed = request
        .headers()
        .get(header::HOST)
        .and_then(|host| host.to_str().ok())
        .is_some_and(is_loopback_host);
    if !allowed {
        return StatusCode::MISDIRECTED_REQUEST.into_response();
    }
    next.run(request).await
}

fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(address) = host.parse::<SocketAddr>() {
        return address.ip().is_loopback();
    }
    if let Ok(address) = host.parse::<IpAddr>() {
        return address.is_loopback();
    }
    if let Some((name, port)) = host.rsplit_once(':') {
        return name.eq_ignore_ascii_case("localhost") && port.parse::<u16>().is_ok();
    }
    host.strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .and_then(|host| host.parse::<IpAddr>().ok())
        .is_some_and(|address| address.is_loopback())
}

async fn index(State(context): State<ApiContext>) -> Html<String> {
    Html(
        INDEX_HTML
            .replace("__SESSION_TOKEN__", &context.token)
            .replace(
                "__INITIAL_WINDOW_MS__",
                &context.initial_window_ms.to_string(),
            )
            .replace(
                "__MAX_WINDOW_MS__",
                &context.dashboard.max_window_ms().to_string(),
            ),
    )
}

async fn app_script() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        APP_JS,
    )
}

async fn heatmap_script() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        HEATMAP_JS,
    )
}

async fn inspection_script() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
        INSPECTION_JS,
    )
}

async fn stylesheet() -> impl IntoResponse {
    (
        [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
        STYLE_CSS,
    )
}

#[derive(Deserialize)]
struct SnapshotQuery {
    window_ms: u64,
}

async fn topology(State(context): State<ApiContext>) -> impl IntoResponse {
    Json((*context.dashboard.topology()).clone())
}

async fn snapshot(
    State(context): State<ApiContext>,
    Query(query): Query<SnapshotQuery>,
) -> Result<impl IntoResponse, ApiError> {
    context
        .dashboard
        .snapshot(query.window_ms)
        .map(Json)
        .map_err(|error| ApiError::bad_request(error.to_string()))
}

async fn inspection(State(context): State<ApiContext>) -> impl IntoResponse {
    Json(context.dashboard.inspection())
}

#[derive(Deserialize)]
struct CallbackTimingQuery {
    scope: String,
    window_ms: Option<u64>,
}

async fn callback_timing(
    State(context): State<ApiContext>,
    Query(query): Query<CallbackTimingQuery>,
) -> Result<impl IntoResponse, ApiError> {
    match query.scope.as_str() {
        "window" => {
            let window_ms = query
                .window_ms
                .ok_or_else(|| ApiError::bad_request("window scope requires window_ms"))?;
            context
                .dashboard
                .callback_timing_window(window_ms)
                .map(Json)
                .map_err(|error| ApiError::bad_request(error.to_string()))
        }
        "lifetime" if query.window_ms.is_none() => {
            Ok(Json(context.dashboard.callback_timing_lifetime()))
        }
        "lifetime" => Err(ApiError::bad_request(
            "lifetime scope does not accept window_ms",
        )),
        _ => Err(ApiError::bad_request(
            "callback timing scope must be window or lifetime",
        )),
    }
}

async fn fine_timing(State(context): State<ApiContext>) -> impl IntoResponse {
    Json(context.dashboard.fine_timing())
}

#[derive(Deserialize)]
struct FineTimingRequest {
    callback: FineTimingCallback,
    enabled: bool,
}

async fn set_fine_timing(
    State(context): State<ApiContext>,
    headers: HeaderMap,
    Json(request): Json<FineTimingRequest>,
) -> Result<Json<FineTimingControlResponse>, ApiError> {
    require_session_token(&headers, &context.token)?;
    let (response_tx, response_rx) = std::sync::mpsc::sync_channel(1);
    context
        .commands
        .send(CollectorCommand::SetFineTiming {
            callback: request.callback,
            enabled: request.enabled,
            response: response_tx,
        })
        .map_err(|_| ApiError::unavailable("collector is not running"))?;
    let response =
        tokio::task::spawn_blocking(move || response_rx.recv_timeout(Duration::from_secs(5)))
            .await
            .map_err(|_| ApiError::unavailable("fine timing worker failed"))?
            .map_err(|_| ApiError::unavailable("fine timing update timed out"))?
            .map_err(ApiError::bad_request)?;
    Ok(Json(response))
}

async fn policies(State(context): State<ApiContext>) -> impl IntoResponse {
    Json(context.dashboard.policy_catalog())
}

#[derive(Deserialize)]
struct ActivatePolicyRequest {
    policy_id: String,
}

async fn activate_policy(
    State(context): State<ApiContext>,
    headers: HeaderMap,
    Json(request): Json<ActivatePolicyRequest>,
) -> Result<Json<PolicyActivation>, ApiError> {
    require_session_token(&headers, &context.token)?;
    let (response_tx, response_rx) = std::sync::mpsc::sync_channel(1);
    context
        .commands
        .send(CollectorCommand::ActivatePolicy {
            policy_id: request.policy_id,
            response: response_tx,
        })
        .map_err(|_| ApiError::unavailable("collector is not running"))?;
    let response =
        tokio::task::spawn_blocking(move || response_rx.recv_timeout(Duration::from_secs(20)))
            .await
            .map_err(|_| ApiError::unavailable("policy activation worker failed"))?
            .map_err(|_| ApiError::unavailable("policy activation timed out"))?
            .map_err(ApiError::bad_request)?;
    Ok(Json(response))
}

async fn events(
    State(context): State<ApiContext>,
    Query(query): Query<SnapshotQuery>,
) -> Result<impl IntoResponse, ApiError> {
    context
        .dashboard
        .snapshot(query.window_ms)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;

    let receiver = context.dashboard.subscribe();
    let dashboard = context.dashboard.clone();
    let window_ms = query.window_ms;
    let stream = WatchStream::new(receiver).map(move |_| {
        let event = match dashboard.snapshot(window_ms) {
            Ok(snapshot) => match serde_json::to_string(&snapshot) {
                Ok(snapshot) => Event::default().event("snapshot").data(snapshot),
                Err(error) => Event::default()
                    .event("error")
                    .data(serde_json::json!({ "error": error.to_string() }).to_string()),
            },
            Err(error) => Event::default()
                .event("error")
                .data(serde_json::json!({ "error": error.to_string() }).to_string()),
        };
        Ok::<_, std::convert::Infallible>(event)
    });

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keepalive"),
    ))
}

async fn set_scope(
    State(context): State<ApiContext>,
    headers: HeaderMap,
    Json(request): Json<ScopeRequest>,
) -> Result<StatusCode, ApiError> {
    require_session_token(&headers, &context.token)?;

    let scope = resolve_scope(request, &context.cgroup_root)
        .map_err(|error| ApiError::bad_request(error.to_string()))?;
    context
        .commands
        .send(CollectorCommand::SetScope(scope))
        .map_err(|_| ApiError::unavailable("collector is not running"))?;
    Ok(StatusCode::ACCEPTED)
}

fn require_session_token(headers: &HeaderMap, token: &str) -> Result<(), ApiError> {
    let supplied = headers
        .get(CSRF_HEADER)
        .and_then(|value| value.to_str().ok());
    if supplied != Some(token) {
        return Err(ApiError::unauthorized("missing or invalid session token"));
    }
    Ok(())
}

struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.into(),
        }
    }

    fn unavailable(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({ "error": self.message })),
        )
            .into_response()
    }
}
