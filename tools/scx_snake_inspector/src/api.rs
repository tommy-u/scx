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
use serde::{Deserialize, Serialize};
use tokio_stream::wrappers::WatchStream;
use tokio_stream::StreamExt;

use crate::collector::{
    CallbackTimingRateResponse, CollectorCommand, FineTimingCallback, FineTimingControlResponse,
};
use crate::dashboard::Dashboard;
use crate::launcher::{LaunchOptions, LaunchRequest, SnakeLauncher};
use crate::policies::PolicyActivation;
use crate::scope::{resolve_scope, ScopeRequest};
use crate::workload::{WorkloadCellResponse, WorkloadTarget};

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
    launcher: Option<SnakeLauncher>,
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
            launcher: None,
        }
    }

    pub fn with_initial_window_ms(mut self, initial_window_ms: u64) -> Self {
        self.initial_window_ms = initial_window_ms;
        self
    }

    pub fn with_launcher(mut self, launcher: SnakeLauncher) -> Self {
        self.launcher = Some(launcher);
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
        .route(
            "/api/callback-timing",
            get(callback_timing).post(set_callback_timing_sample_rate),
        )
        .route("/api/fine-timing", get(fine_timing).post(set_fine_timing))
        .route("/api/policies", get(policies))
        .route("/api/policies/activate", post(activate_policy))
        .route("/api/scheduler/control", get(scheduler_control))
        .route("/api/scheduler/start", post(start_scheduler))
        .route("/api/scheduler/stop", post(stop_scheduler))
        .route("/api/events", get(events))
        .route("/api/scope", post(set_scope))
        .route("/api/cells/assignment", post(set_workload_cell))
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

#[derive(Deserialize)]
struct CallbackTimingRateRequest {
    sample_rate: u32,
}

async fn set_callback_timing_sample_rate(
    State(context): State<ApiContext>,
    headers: HeaderMap,
    Json(request): Json<CallbackTimingRateRequest>,
) -> Result<Json<CallbackTimingRateResponse>, ApiError> {
    require_session_token(&headers, &context.token)?;
    let (response_tx, response_rx) = std::sync::mpsc::sync_channel(1);
    context
        .commands
        .send(CollectorCommand::SetCallbackTimingSampleRate {
            sample_rate: request.sample_rate,
            response: response_tx,
        })
        .map_err(|_| ApiError::unavailable("collector is not running"))?;
    let response =
        tokio::task::spawn_blocking(move || response_rx.recv_timeout(Duration::from_secs(5)))
            .await
            .map_err(|_| ApiError::unavailable("callback timing worker failed"))?
            .map_err(|_| ApiError::unavailable("callback timing update timed out"))?
            .map_err(ApiError::bad_request)?;
    Ok(Json(response))
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

#[derive(Clone, Debug, Serialize)]
struct SchedulerPolicyControl {
    id: String,
    name: String,
    change_mode: &'static str,
    reload_reasons: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct SchedulerSettingControl {
    name: &'static str,
    value: serde_json::Value,
    change_mode: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct SchedulerControl {
    managed: bool,
    active: bool,
    policy_id: Option<String>,
    last_exit: Option<String>,
    launch: LaunchOptions,
    policies: Vec<SchedulerPolicyControl>,
    settings: Vec<SchedulerSettingControl>,
}

async fn scheduler_control(
    State(context): State<ApiContext>,
) -> Result<Json<SchedulerControl>, ApiError> {
    scheduler_control_response(&context).map(Json)
}

async fn start_scheduler(
    State(context): State<ApiContext>,
    headers: HeaderMap,
    Json(request): Json<LaunchRequest>,
) -> Result<Json<SchedulerControl>, ApiError> {
    require_session_token(&headers, &context.token)?;
    let launcher = context
        .launcher
        .clone()
        .ok_or_else(|| ApiError::unavailable("managed scheduler launching is unavailable"))?;
    tokio::task::spawn_blocking(move || launcher.start(request))
        .await
        .map_err(|_| ApiError::unavailable("scheduler launcher worker failed"))?
        .map_err(|error| ApiError::bad_request(format!("{error:#}")))?;
    scheduler_control_response(&context).map(Json)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyRequest {}

async fn stop_scheduler(
    State(context): State<ApiContext>,
    headers: HeaderMap,
    Json(_request): Json<EmptyRequest>,
) -> Result<Json<SchedulerControl>, ApiError> {
    require_session_token(&headers, &context.token)?;
    let launcher = context
        .launcher
        .clone()
        .ok_or_else(|| ApiError::unavailable("managed scheduler launching is unavailable"))?;
    tokio::task::spawn_blocking(move || launcher.stop())
        .await
        .map_err(|_| ApiError::unavailable("scheduler launcher worker failed"))?
        .map_err(|error| ApiError::bad_request(format!("{error:#}")))?;
    scheduler_control_response(&context).map(Json)
}

fn scheduler_control_response(context: &ApiContext) -> Result<SchedulerControl, ApiError> {
    let launcher = context
        .launcher
        .as_ref()
        .ok_or_else(|| ApiError::unavailable("managed scheduler launching is unavailable"))?;
    let status = launcher
        .status()
        .map_err(|error| ApiError::unavailable(format!("reading scheduler status: {error:#}")))?;
    let inspection = context.dashboard.inspection();
    let catalog = context.dashboard.policy_catalog();
    let active_source = inspection.snapshot.as_ref().and_then(active_policy_source);
    let policy_id = status.policy_id.clone().or_else(|| {
        let source = active_source?;
        catalog
            .catalog
            .as_ref()?
            .policies
            .iter()
            .find_map(|policy| (policy.source.trim() == source.trim()).then(|| policy.id.clone()))
    });

    let mut launch = status.launch.unwrap_or_default();
    if !status.managed && status.active && launch.fairness.is_none() {
        launch.fairness = inspection
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.get("fairness"))
            .and_then(|fairness| fairness.get("mode_name"))
            .and_then(serde_json::Value::as_str)
            .and_then(|mode| serde_json::from_value(serde_json::Value::String(mode.into())).ok());
    }
    if !status.managed && status.active && launch.callback_timing_sample_rate.is_none() {
        launch.callback_timing_sample_rate = inspection
            .snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.get("callback_timing_sample_rate"))
            .and_then(serde_json::Value::as_u64)
            .and_then(|rate| u32::try_from(rate).ok());
    }

    let dynamic = catalog
        .catalog
        .as_ref()
        .map(|catalog| {
            catalog
                .policies
                .iter()
                .map(|policy| policy.id.as_str())
                .collect::<std::collections::BTreeSet<_>>()
        })
        .unwrap_or_default();
    let reload = catalog
        .catalog
        .as_ref()
        .map(|catalog| {
            catalog
                .invalid
                .iter()
                .map(|policy| (policy.id.as_str(), policy.error.as_str()))
                .collect::<std::collections::BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    let policies = launcher
        .policies()
        .map_err(|error| ApiError::unavailable(format!("reading policy library: {error:#}")))?
        .into_iter()
        .map(|policy| {
            if status.active && dynamic.contains(policy.id.as_str()) {
                SchedulerPolicyControl {
                    id: policy.id,
                    name: policy.name,
                    change_mode: "dynamic",
                    reload_reasons: Vec::new(),
                }
            } else {
                let reason = reload
                    .get(policy.id.as_str())
                    .map(|reason| (*reason).to_owned())
                    .or_else(|| catalog.error.clone())
                    .unwrap_or_else(|| {
                        if status.active {
                            "Policy compatibility has not been validated yet.".into()
                        } else {
                            "Starting this policy requires launching Snake.".into()
                        }
                    });
                SchedulerPolicyControl {
                    id: policy.id,
                    name: policy.name,
                    change_mode: "reload",
                    reload_reasons: vec![reason],
                }
            }
        })
        .collect();

    let settings = vec![
        SchedulerSettingControl {
            name: "fairness",
            value: serde_json::to_value(launch.fairness)
                .map_err(|error| ApiError::unavailable(error.to_string()))?,
            change_mode: "reload",
        },
        SchedulerSettingControl {
            name: "callback_timing_sample_rate",
            value: serde_json::to_value(launch.callback_timing_sample_rate)
                .map_err(|error| ApiError::unavailable(error.to_string()))?,
            change_mode: "dynamic",
        },
        SchedulerSettingControl {
            name: "exit_dump_len",
            value: serde_json::to_value(launch.exit_dump_len)
                .map_err(|error| ApiError::unavailable(error.to_string()))?,
            change_mode: "reload",
        },
        SchedulerSettingControl {
            name: "verbose",
            value: serde_json::Value::Bool(launch.verbose),
            change_mode: "reload",
        },
    ];

    Ok(SchedulerControl {
        managed: status.managed,
        active: status.active,
        policy_id,
        last_exit: status.last_exit,
        launch,
        policies,
        settings,
    })
}

fn active_policy_source(snapshot: &serde_json::Value) -> Option<&str> {
    let active_slot = snapshot.get("active_slot")?.as_u64()?;
    snapshot
        .get("slots")?
        .as_array()?
        .iter()
        .find(|slot| slot.get("slot").and_then(serde_json::Value::as_u64) == Some(active_slot))?
        .get("policy")?
        .get("source")?
        .as_str()
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

#[derive(Deserialize)]
struct WorkloadCellRequest {
    target: WorkloadTarget,
    cell_id: Option<u32>,
}

async fn set_workload_cell(
    State(context): State<ApiContext>,
    headers: HeaderMap,
    Json(request): Json<WorkloadCellRequest>,
) -> Result<Json<WorkloadCellResponse>, ApiError> {
    require_session_token(&headers, &context.token)?;
    let (response_tx, response_rx) = std::sync::mpsc::sync_channel(1);
    context
        .commands
        .send(CollectorCommand::SetWorkloadCell {
            target: request.target,
            cell_id: request.cell_id,
            response: response_tx,
        })
        .map_err(|_| ApiError::unavailable("collector is not running"))?;
    let response =
        tokio::task::spawn_blocking(move || response_rx.recv_timeout(Duration::from_secs(20)))
            .await
            .map_err(|_| ApiError::unavailable("workload assignment worker failed"))?
            .map_err(|_| ApiError::unavailable("workload assignment timed out"))?
            .map_err(ApiError::bad_request)?;
    Ok(Json(response))
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
