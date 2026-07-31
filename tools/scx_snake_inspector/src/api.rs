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
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tokio_stream::wrappers::WatchStream;

use crate::collector::{
    CallbackTimingRateResponse, CollectorCommand, FineTimingCallback, FineTimingControlResponse,
    QueueTimingControlResponse, StatsResetResponse,
};
use crate::dashboard::{Dashboard, RuntimeContextView};
use crate::host_context::{ChartMetric, HostContextService};
use crate::launcher::{LaunchFairness, LaunchOptions, LaunchRequest, SnakeLauncher};
use crate::policies::PolicyActivation;
use crate::scope::{resolve_scope, ScopeRequest};
use crate::testing::{TestRun, TestingController};
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
    host_context: Option<HostContextService>,
    testing: Option<TestingController>,
    lifecycle: Arc<tokio::sync::Mutex<()>>,
    shutdown: Option<tokio::sync::watch::Receiver<bool>>,
    allowed_hosts: Arc<Vec<String>>,
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
            host_context: None,
            testing: None,
            lifecycle: Arc::new(tokio::sync::Mutex::new(())),
            shutdown: None,
            allowed_hosts: Arc::new(Vec::new()),
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

    pub fn with_host_context(mut self, host_context: HostContextService) -> Self {
        self.host_context = Some(host_context);
        self
    }

    pub fn with_testing(mut self, testing: TestingController) -> Self {
        self.testing = Some(testing);
        self
    }

    pub fn with_shutdown(mut self, shutdown: tokio::sync::watch::Receiver<bool>) -> Self {
        self.shutdown = Some(shutdown);
        self
    }

    pub fn with_allowed_host(mut self, host: impl Into<String>) -> Self {
        Arc::make_mut(&mut self.allowed_hosts).push(host.into());
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
        .route("/api/host-context", get(host_context))
        .route("/api/host-charts/cpu-pressure.png", get(cpu_pressure_chart))
        .route(
            "/api/host-charts/scheduler-delay.png",
            get(scheduler_delay_chart),
        )
        .route(
            "/api/host-charts/cpu-pressure/open",
            post(open_cpu_pressure_chart),
        )
        .route(
            "/api/host-charts/scheduler-delay/open",
            post(open_scheduler_delay_chart),
        )
        .route("/api/snapshot", get(snapshot))
        .route("/api/inspection", get(inspection))
        .route(
            "/api/callback-timing",
            get(callback_timing).post(set_callback_timing_sample_rate),
        )
        .route("/api/fine-timing", get(fine_timing).post(set_fine_timing))
        .route(
            "/api/queue-timing",
            get(queue_timing).post(set_queue_timing),
        )
        .route("/api/policies", get(policies))
        .route("/api/policies/activate", post(activate_policy))
        .route("/api/scheduler/control", get(scheduler_control))
        .route("/api/scheduler/start", post(start_scheduler))
        .route("/api/scheduler/restart", post(restart_scheduler))
        .route("/api/scheduler/stop", post(stop_scheduler))
        .route("/api/testing/matrix", get(testing_matrix))
        .route("/api/testing/run", post(start_testing))
        .route("/api/testing/stop", post(stop_testing))
        .route("/api/stats/reset", post(reset_stats))
        .route("/api/events", get(events))
        .route("/api/scope", post(set_scope))
        .route("/api/cells/assignment", post(set_workload_cell))
        .layer(middleware::from_fn_with_state(
            context.clone(),
            require_allowed_host,
        ))
        .with_state(context)
}

async fn testing_matrix(State(context): State<ApiContext>) -> Result<Json<TestRun>, ApiError> {
    let testing = context
        .testing
        .as_ref()
        .ok_or_else(|| ApiError::unavailable("VM testing is not configured"))?;
    let catalog = context.dashboard.policy_catalog();
    testing
        .snapshot_available(catalog.catalog.as_ref())
        .map(Json)
        .map_err(|error| ApiError::unavailable(format!("reading testing matrix: {error:#}")))
}

async fn start_testing(
    State(context): State<ApiContext>,
    headers: HeaderMap,
    Json(_request): Json<EmptyRequest>,
) -> Result<Json<TestRun>, ApiError> {
    require_session_token(&headers, &context.token)?;
    let _lifecycle = context.lifecycle.lock().await;
    if context.launcher.is_some() {
        let scheduler = scheduler_control_response(&context)?;
        if scheduler.managed || scheduler.active {
            return Err(ApiError::conflict(
                "testing requires Snake and sched_ext to be stopped",
            ));
        }
    }
    let testing = context
        .testing
        .as_ref()
        .ok_or_else(|| ApiError::unavailable("VM testing is not configured"))?;
    let catalog = context.dashboard.policy_catalog();
    testing
        .start_available(catalog.catalog.as_ref())
        .map(Json)
        .map_err(|error| ApiError::bad_request(format!("starting testing matrix: {error:#}")))
}

async fn stop_testing(
    State(context): State<ApiContext>,
    headers: HeaderMap,
    Json(_request): Json<EmptyRequest>,
) -> Result<Json<TestRun>, ApiError> {
    require_session_token(&headers, &context.token)?;
    let _lifecycle = context.lifecycle.lock().await;
    context
        .testing
        .as_ref()
        .ok_or_else(|| ApiError::unavailable("VM testing is not configured"))?
        .stop()
        .map(Json)
        .map_err(|error| ApiError::bad_request(format!("stopping testing matrix: {error:#}")))
}

async fn require_allowed_host(
    State(context): State<ApiContext>,
    request: Request,
    next: Next,
) -> Response {
    let allowed = request
        .headers()
        .get(header::HOST)
        .and_then(|host| host.to_str().ok())
        .is_some_and(|host| is_allowed_host(host, &context.allowed_hosts));
    if !allowed {
        eprintln!(
            "rejected Host header: {}",
            request
                .headers()
                .get(header::HOST)
                .and_then(|host| host.to_str().ok())
                .unwrap_or("<missing or invalid>"),
        );
        return StatusCode::MISDIRECTED_REQUEST.into_response();
    }
    next.run(request).await
}

fn is_allowed_host(host: &str, allowed_hosts: &[String]) -> bool {
    if is_loopback_host(host) {
        return true;
    }
    let name = host
        .rsplit_once(':')
        .filter(|(_, port)| port.parse::<u16>().is_ok())
        .map_or(host, |(name, _)| name);
    allowed_hosts
        .iter()
        .any(|allowed| name.eq_ignore_ascii_case(allowed))
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

#[derive(Deserialize)]
struct ChartImageQuery {
    revision: Option<u64>,
}

async fn topology(State(context): State<ApiContext>) -> impl IntoResponse {
    Json((*context.dashboard.topology()).clone())
}

async fn host_context(State(context): State<ApiContext>) -> Result<impl IntoResponse, ApiError> {
    context
        .host_context
        .as_ref()
        .map(|host_context| Json(host_context.snapshot()))
        .ok_or_else(|| ApiError::unavailable("host context is unavailable"))
}

async fn cpu_pressure_chart(
    State(context): State<ApiContext>,
    Query(query): Query<ChartImageQuery>,
) -> Result<Response, ApiError> {
    host_chart(context, ChartMetric::CpuPressure, query.revision)
}

async fn scheduler_delay_chart(
    State(context): State<ApiContext>,
    Query(query): Query<ChartImageQuery>,
) -> Result<Response, ApiError> {
    host_chart(context, ChartMetric::SchedulerDelay, query.revision)
}

fn host_chart(
    context: ApiContext,
    metric: ChartMetric,
    requested_revision: Option<u64>,
) -> Result<Response, ApiError> {
    let (revision, bytes) = context
        .host_context
        .as_ref()
        .and_then(|host_context| host_context.chart_payload(metric))
        .ok_or_else(|| ApiError::unavailable("ODS chart is unavailable"))?;
    let cache_control = if requested_revision == Some(revision) {
        "private, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    Ok((
        [
            (header::CONTENT_TYPE, "image/png"),
            (header::CACHE_CONTROL, cache_control),
        ],
        bytes,
    )
        .into_response())
}

#[derive(Serialize)]
struct OpenHostChartResponse {
    url: String,
}

async fn open_cpu_pressure_chart(
    State(context): State<ApiContext>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    open_host_chart(context, headers, ChartMetric::CpuPressure).await
}

async fn open_scheduler_delay_chart(
    State(context): State<ApiContext>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    open_host_chart(context, headers, ChartMetric::SchedulerDelay).await
}

async fn open_host_chart(
    context: ApiContext,
    headers: HeaderMap,
    metric: ChartMetric,
) -> Result<Json<OpenHostChartResponse>, ApiError> {
    require_session_token(&headers, &context.token)?;
    let url = context
        .host_context
        .as_ref()
        .ok_or_else(|| ApiError::unavailable("host context is unavailable"))?
        .fresh_chart_url(metric)
        .await
        .map_err(ApiError::unavailable)?;
    Ok(Json(OpenHostChartResponse { url }))
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

async fn queue_timing(
    State(context): State<ApiContext>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    require_session_token(&headers, &context.token)?;
    Ok(Json(context.dashboard.queue_timing()))
}

#[derive(Deserialize)]
struct QueueTimingRequest {
    enabled: bool,
}

async fn set_queue_timing(
    State(context): State<ApiContext>,
    headers: HeaderMap,
    Json(request): Json<QueueTimingRequest>,
) -> Result<Json<QueueTimingControlResponse>, ApiError> {
    require_session_token(&headers, &context.token)?;
    let (response_tx, response_rx) = std::sync::mpsc::sync_channel(1);
    context
        .commands
        .send(CollectorCommand::SetQueueTiming {
            enabled: request.enabled,
            response: response_tx,
        })
        .map_err(|_| ApiError::unavailable("collector is not running"))?;
    let response =
        tokio::task::spawn_blocking(move || response_rx.recv_timeout(Duration::from_secs(5)))
            .await
            .map_err(|_| ApiError::unavailable("queue timing worker failed"))?
            .map_err(|_| ApiError::unavailable("queue timing update timed out"))?
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
    apply_mode: PolicyApplyMode,
    reasons: Vec<PolicyReason>,
    supported_fairness: Vec<LaunchFairness>,
    // Compatibility fields for older inspector clients.
    change_mode: &'static str,
    reload_reasons: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PolicyApplyMode {
    Live,
    Restart,
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum PolicyReasonCode {
    DsqTopology,
    TaskMembership,
    EnqueueTargets,
    DispatchSources,
    ValidationFailed,
    NotValidated,
    SchedulerStopped,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct PolicyReason {
    code: PolicyReasonCode,
    label: &'static str,
    detail: String,
}

#[derive(Clone, Debug, Serialize)]
struct SchedulerSettingControl {
    name: &'static str,
    value: serde_json::Value,
    effective: serde_json::Value,
    default_value: serde_json::Value,
    launch_override: serde_json::Value,
    runtime_observed: bool,
    change_mode: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct SchedulerControl {
    context: RuntimeContextView,
    managed: bool,
    controllable: bool,
    control_error: Option<String>,
    active: bool,
    scheduler_name: Option<String>,
    pid: Option<u32>,
    uptime_ms: Option<u64>,
    current_command: Option<Vec<String>>,
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
    let _lifecycle = context.lifecycle.lock().await;
    require_testing_idle(&context)?;
    let control = scheduler_control_response(&context)?;
    validate_lifecycle_policy(&control, &request, "started")?;
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

async fn restart_scheduler(
    State(context): State<ApiContext>,
    headers: HeaderMap,
    Json(request): Json<LaunchRequest>,
) -> Result<Json<SchedulerControl>, ApiError> {
    require_session_token(&headers, &context.token)?;
    let _lifecycle = context.lifecycle.lock().await;
    require_testing_idle(&context)?;
    let control = scheduler_control_response(&context)?;
    validate_lifecycle_policy(&control, &request, "restarted")?;
    let launcher = context
        .launcher
        .clone()
        .ok_or_else(|| ApiError::unavailable("managed scheduler launching is unavailable"))?;
    tokio::task::spawn_blocking(move || launcher.restart(request))
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
    let _lifecycle = context.lifecycle.lock().await;
    require_testing_idle(&context)?;
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

async fn reset_stats(
    State(context): State<ApiContext>,
    headers: HeaderMap,
) -> Result<Json<StatsResetResponse>, ApiError> {
    require_session_token(&headers, &context.token)?;
    let (response_tx, response_rx) = std::sync::mpsc::sync_channel(1);
    context
        .commands
        .send(CollectorCommand::ResetStats {
            response: response_tx,
        })
        .map_err(|_| ApiError::unavailable("collector is not running"))?;
    let response =
        tokio::task::spawn_blocking(move || response_rx.recv_timeout(Duration::from_secs(15)))
            .await
            .map_err(|_| ApiError::unavailable("stats reset worker failed"))?
            .map_err(|_| ApiError::unavailable("stats reset timed out"))?
            .map_err(ApiError::bad_request)?;
    Ok(Json(response))
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
        let mut matches = catalog
            .catalog
            .as_ref()?
            .policies
            .iter()
            .filter(|policy| policy.source.trim() == source.trim());
        let policy_id = matches.next()?.id.clone();
        matches.next().is_none().then_some(policy_id)
    });

    let launch_known = status.launch.is_some();
    let launch = status.launch.unwrap_or_default();
    let observed_fairness = inspection
        .snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.pointer("/fairness/mode_name"))
        .and_then(serde_json::Value::as_str)
        .and_then(|mode| serde_json::from_value(serde_json::Value::String(mode.into())).ok());
    let observed_sample_rate = inspection
        .snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.get("callback_timing_sample_rate"))
        .and_then(serde_json::Value::as_u64)
        .and_then(|rate| u32::try_from(rate).ok());
    let effective_fairness = observed_fairness.or_else(|| {
        (status.active && launch_known).then_some(launch.fairness.unwrap_or(LaunchFairness::Fifo))
    });
    let effective_sample_rate = observed_sample_rate.or_else(|| {
        (status.active && launch_known).then_some(launch.callback_timing_sample_rate.unwrap_or(64))
    });
    let effective_exit_dump_len =
        (status.active && launch_known).then_some(launch.exit_dump_len.unwrap_or_default());
    let effective_verbose = (status.active && launch_known).then_some(launch.verbose);

    let valid = catalog
        .catalog
        .as_ref()
        .map(|catalog| {
            catalog
                .policies
                .iter()
                .map(|policy| (policy.id.as_str(), policy))
                .collect::<std::collections::BTreeMap<_, _>>()
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
            let validated = valid.get(policy.id.as_str()).copied();
            let validation_error = reload
                .get(policy.id.as_str())
                .map(|reason| (*reason).to_owned());
            let source_uses_queues = validated
                .map(|candidate| candidate.source.as_str())
                .or_else(|| {
                    catalog.catalog.as_ref().and_then(|catalog| {
                        catalog
                            .invalid
                            .iter()
                            .find(|candidate| candidate.id == policy.id)
                            .map(|candidate| candidate.source.as_str())
                    })
                })
                .or(Some(policy.source.as_str()))
                .is_some_and(policy_source_uses_queues);
            let supported_fairness = if validated.is_some_and(|candidate| candidate.queue_policy)
                || source_uses_queues
            {
                vec![LaunchFairness::Vtime]
            } else {
                vec![
                    LaunchFairness::Fifo,
                    LaunchFairness::Vtime,
                    LaunchFairness::Eevdf,
                ]
            };
            let (apply_mode, reasons) = if status.active && validated.is_some() {
                (PolicyApplyMode::Live, Vec::new())
            } else if let Some(error) = validation_error {
                let mode = if status.active && !policy_requires_restart(&error) {
                    PolicyApplyMode::Invalid
                } else {
                    PolicyApplyMode::Restart
                };
                (mode, vec![policy_reason_from_error(error)])
            } else if status.active {
                let detail = catalog
                    .error
                    .clone()
                    .unwrap_or_else(|| "Policy compatibility has not been validated yet.".into());
                (
                    PolicyApplyMode::Invalid,
                    vec![PolicyReason {
                        code: PolicyReasonCode::NotValidated,
                        label: "Compatibility not validated",
                        detail,
                    }],
                )
            } else {
                (
                    PolicyApplyMode::Restart,
                    vec![PolicyReason {
                        code: PolicyReasonCode::SchedulerStopped,
                        label: "Snake is stopped",
                        detail: "Starting this policy requires a new Snake attachment.".into(),
                    }],
                )
            };
            let change_mode = match apply_mode {
                PolicyApplyMode::Live => "dynamic",
                PolicyApplyMode::Restart => "reload",
                PolicyApplyMode::Invalid => "invalid",
            };
            SchedulerPolicyControl {
                id: policy.id,
                name: policy.name,
                apply_mode,
                reload_reasons: reasons.iter().map(|reason| reason.detail.clone()).collect(),
                reasons,
                supported_fairness,
                change_mode,
            }
        })
        .collect();

    let effective_fairness_value = serde_json::to_value(effective_fairness)
        .map_err(|error| ApiError::unavailable(error.to_string()))?;
    let fairness_override_value = serde_json::to_value(launch.fairness)
        .map_err(|error| ApiError::unavailable(error.to_string()))?;
    let effective_sample_rate_value = serde_json::to_value(effective_sample_rate)
        .map_err(|error| ApiError::unavailable(error.to_string()))?;
    let sample_rate_override_value = serde_json::to_value(launch.callback_timing_sample_rate)
        .map_err(|error| ApiError::unavailable(error.to_string()))?;
    let effective_exit_dump_value = serde_json::to_value(effective_exit_dump_len)
        .map_err(|error| ApiError::unavailable(error.to_string()))?;
    let exit_dump_override_value = serde_json::to_value(launch.exit_dump_len)
        .map_err(|error| ApiError::unavailable(error.to_string()))?;
    let effective_verbose_value = serde_json::to_value(effective_verbose)
        .map_err(|error| ApiError::unavailable(error.to_string()))?;
    let verbose_override_value = if launch.verbose {
        serde_json::Value::Bool(true)
    } else {
        serde_json::Value::Null
    };
    let settings = vec![
        SchedulerSettingControl {
            name: "fairness",
            value: effective_fairness_value.clone(),
            effective: effective_fairness_value,
            default_value: serde_json::to_value(LaunchFairness::Fifo)
                .map_err(|error| ApiError::unavailable(error.to_string()))?,
            launch_override: fairness_override_value,
            runtime_observed: observed_fairness.is_some(),
            change_mode: "reload",
        },
        SchedulerSettingControl {
            name: "callback_timing_sample_rate",
            value: effective_sample_rate_value.clone(),
            effective: effective_sample_rate_value,
            default_value: serde_json::Value::from(64),
            launch_override: sample_rate_override_value,
            runtime_observed: observed_sample_rate.is_some(),
            change_mode: "dynamic",
        },
        SchedulerSettingControl {
            name: "exit_dump_len",
            value: effective_exit_dump_value.clone(),
            effective: effective_exit_dump_value,
            default_value: serde_json::Value::from(0),
            launch_override: exit_dump_override_value,
            runtime_observed: false,
            change_mode: "reload",
        },
        SchedulerSettingControl {
            name: "verbose",
            value: effective_verbose_value.clone(),
            effective: effective_verbose_value,
            default_value: serde_json::Value::Bool(false),
            launch_override: verbose_override_value,
            runtime_observed: false,
            change_mode: "reload",
        },
        SchedulerSettingControl {
            name: "stats_reset",
            value: serde_json::Value::String("On demand".into()),
            effective: serde_json::Value::String("On demand".into()),
            default_value: serde_json::Value::Null,
            launch_override: serde_json::Value::Null,
            runtime_observed: false,
            change_mode: "dynamic",
        },
    ];

    Ok(SchedulerControl {
        context: context.dashboard.runtime_context(),
        managed: status.managed,
        controllable: status.controllable,
        control_error: status.control_error,
        active: status.active,
        scheduler_name: status.scheduler_name,
        pid: status.pid,
        uptime_ms: status.uptime_ms,
        current_command: status.current_command,
        policy_id,
        last_exit: status.last_exit,
        launch,
        policies,
        settings,
    })
}

fn policy_requires_restart(error: &str) -> bool {
    error.contains("restart Snake to apply it")
        || error.contains("cannot remove active queue enqueue target")
        || error.contains("cannot remove active queue dispatch source")
}

fn policy_source_uses_queues(source: &str) -> bool {
    source.lines().any(|line| {
        let line = line.split('#').next().unwrap_or_default().trim();
        let Some(table) = line
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
        else {
            return false;
        };
        let table = table
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>();
        table == "queues" || table.starts_with("queues.")
    })
}

fn policy_reason_from_error(detail: String) -> PolicyReason {
    let lower = detail.to_ascii_lowercase();
    let (code, label) = if lower.contains("queue topology") {
        (PolicyReasonCode::DsqTopology, "DSQ topology changes")
    } else if lower.contains("task membership") {
        (PolicyReasonCode::TaskMembership, "Task membership changes")
    } else if lower.contains("enqueue target") {
        (
            PolicyReasonCode::EnqueueTargets,
            "Queue enqueue targets change",
        )
    } else if lower.contains("dispatch source") {
        (
            PolicyReasonCode::DispatchSources,
            "Queue dispatch sources change",
        )
    } else {
        (
            PolicyReasonCode::ValidationFailed,
            "Policy validation failed",
        )
    };
    PolicyReason {
        code,
        label,
        detail,
    }
}

fn validate_lifecycle_policy(
    control: &SchedulerControl,
    request: &LaunchRequest,
    action: &str,
) -> Result<(), ApiError> {
    let policy = control
        .policies
        .iter()
        .find(|policy| policy.id == request.policy_id)
        .ok_or_else(|| ApiError::bad_request("selected policy is not available"))?;
    if policy.apply_mode == PolicyApplyMode::Invalid {
        let reason = policy
            .reload_reasons
            .first()
            .map(String::as_str)
            .unwrap_or("policy validation failed");
        return Err(ApiError::bad_request(format!(
            "selected policy is invalid and cannot be {action}: {reason}"
        )));
    }
    let fairness = request.fairness.unwrap_or(LaunchFairness::Fifo);
    if !policy.supported_fairness.contains(&fairness) {
        let supported = policy
            .supported_fairness
            .iter()
            .map(|mode| format!("{mode:?}").to_ascii_uppercase())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(ApiError::bad_request(format!(
            "selected policy cannot be {action} with {fairness:?} fairness; choose {supported}"
        )));
    }
    Ok(())
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
    let mut shutdown = context.shutdown.clone();
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
    let stream = stream.take_until(async move {
        let Some(shutdown) = shutdown.as_mut() else {
            std::future::pending::<()>().await;
            return;
        };
        while !*shutdown.borrow() {
            if shutdown.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
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

fn require_testing_idle(context: &ApiContext) -> Result<(), ApiError> {
    if context
        .testing
        .as_ref()
        .is_some_and(|testing| testing.is_running())
    {
        return Err(ApiError::conflict(
            "scheduler lifecycle is locked while the testing matrix is running",
        ));
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

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
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
