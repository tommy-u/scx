// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::sync::{mpsc, Arc, RwLock};
use std::time::{Duration, Instant};

use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, Redirect};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_http::compression::CompressionLayer;

use crate::collector::{CollectorCommand, ResetRequest, Snapshot};
use crate::explore_model::ExploreSnapshot;
use crate::host_context::HostContextView;
use crate::lifecycle::{unix_ms, CollectorStatus, SharedObserverContext};
use crate::migration_history::{MigrationHistory, MigrationWindowView};
use crate::replay::{
    ReplayHistory, ReplayQuery, ReplayTimeline, ReplayView, ReplayViewQuery, REPLAY_RETENTION_MS,
};
use crate::replay_migrations::ReplayMigrationHistory;
use crate::scheduler_config::SchedulerConfigSnapshot;
use crate::stats::StatsSnapshot;
use crate::stats_history::{StatsHistory, StatsHistoryQuery, StatsHistoryView};
use crate::system_stats::SystemStatsSnapshot;

const CALLBACKS_HTML: &str = include_str!("web/callbacks.html");
const SCHEDULING_HTML: &str = include_str!("web/scheduling.html");
const INSPECTOR_HTML: &str = include_str!("web/inspector.html");
const CONFIG_HTML: &str = include_str!("web/config.html");
const STATS_HTML: &str = include_str!("web/stats.html");
const SYSTEM_HTML: &str = include_str!("web/system.html");
const GUIDE_HTML: &str = include_str!("web/guide.html");
const AI_GUIDE: &str = include_str!("web/ai-guide.md");
const SECTIONS_JS: &str = include_str!("web/sections.js");
const CALLBACKS_JS: &str = include_str!("web/callbacks.js");
const SCHEDULING_JS: &str = include_str!("web/scheduling.js");
const INSPECTOR_JS: &str = include_str!("web/inspector.js");
const POLLING_JS: &str = include_str!("web/polling.js");
const CHARTS_JS: &str = include_str!("web/charts.js");
const CONFIG_JS: &str = include_str!("web/config.js");
const FEEDBACK_JS: &str = include_str!("web/feedback.js");
const HEATMAP_JS: &str = include_str!("web/heatmap.js");
const RESET_JS: &str = include_str!("web/reset.js");
const STATS_JS: &str = include_str!("web/stats.js");
const TOPOLOGY_STRIP_JS: &str = include_str!("web/topology_strip.js");
const SYSTEM_JS: &str = include_str!("web/system.js");
const MEMORY_CHARTS_JS: &str = include_str!("web/memory_charts.js");
const EXPLORE_JS: &str = include_str!("web/explore.js");
const EXPLORE_CSS: &str = include_str!("web/explore.css");
const THEME_JS: &str = include_str!("web/theme.js");
const TIMELINE_JS: &str = include_str!("web/timeline.js");
const STYLE_CSS: &str = include_str!("web/style.css");
const WEB_CACHE_CONTROL: &str = "no-store";
const NAVIGATION_PLACEHOLDER: &str = "<!-- workspace-navigation -->";
/// Sidebar workspaces, in display order. Pages are grouped by the question
/// they answer rather than by the collector that produced their data.
const NAVIGATION: [(&str, &[(&str, &str)]); 2] = [
    (
        "Observe",
        &[
            ("/scheduling", "Scheduling"),
            ("/", "Cells"),
            ("/callbacks", "Callbacks"),
            ("/system", "System"),
            ("/config", "Configuration"),
        ],
    ),
    (
        "Reference",
        &[("/inspector", "Inspector"), ("/guide", "AI guide")],
    ),
];

#[derive(Serialize)]
struct ReplayTimelineResponse {
    #[serde(flatten)]
    timeline: ReplayTimeline,
    window_ms: u64,
    default_window_ms: u64,
    max_window_ms: u64,
}

#[derive(Clone)]
pub struct ApiContext {
    counters: Arc<RwLock<Snapshot>>,
    stats: Arc<RwLock<StatsSnapshot>>,
    stats_history: Arc<RwLock<StatsHistory>>,
    system: Arc<RwLock<SystemStatsSnapshot>>,
    host_context: HostContextView,
    migrations: Arc<RwLock<MigrationHistory>>,
    migration_window_ms: u64,
    commands: mpsc::SyncSender<CollectorCommand>,
    observer: SharedObserverContext,
    scheduler_config: Arc<RwLock<SchedulerConfigSnapshot>>,
    replay: Arc<RwLock<ReplayHistory>>,
    replay_migrations: Arc<RwLock<ReplayMigrationHistory>>,
    explore: Arc<RwLock<ExploreSnapshot>>,
}

impl ApiContext {
    pub fn new(
        counters: Arc<RwLock<Snapshot>>,
        stats: Arc<RwLock<StatsSnapshot>>,
        system: Arc<RwLock<SystemStatsSnapshot>>,
        host_context: HostContextView,
        migrations: Arc<RwLock<MigrationHistory>>,
        migration_window_ms: u64,
        commands: mpsc::SyncSender<CollectorCommand>,
        observer: SharedObserverContext,
    ) -> Self {
        let max_window_ms = migrations
            .read()
            .expect("migration history lock poisoned")
            .view(migration_window_ms)
            .map(|view| view.max_window_ms)
            .unwrap_or_else(|_| migration_window_ms.max(1_000));
        let replay_migrations =
            ReplayMigrationHistory::new(REPLAY_RETENTION_MS, max_window_ms, &host_context.topology);
        Self {
            counters,
            stats,
            stats_history: Arc::new(RwLock::new(StatsHistory::new())),
            system,
            host_context,
            migrations,
            migration_window_ms,
            commands,
            observer,
            scheduler_config: Arc::new(RwLock::new(SchedulerConfigSnapshot::default())),
            replay: Arc::new(RwLock::new(ReplayHistory::new())),
            replay_migrations: Arc::new(RwLock::new(replay_migrations)),
            explore: Arc::new(RwLock::new(ExploreSnapshot::default())),
        }
    }

    pub fn with_scheduler_config(mut self, scheduler_config: SchedulerConfigSnapshot) -> Self {
        self.scheduler_config = Arc::new(RwLock::new(scheduler_config));
        self
    }
    pub fn with_scheduler_config_state(
        mut self,
        scheduler_config: Arc<RwLock<SchedulerConfigSnapshot>>,
    ) -> Self {
        self.scheduler_config = scheduler_config;
        self
    }

    pub fn with_stats_history(mut self, history: Arc<RwLock<StatsHistory>>) -> Self {
        self.stats_history = history;
        self
    }

    pub fn with_explore_state(mut self, explore: Arc<RwLock<ExploreSnapshot>>) -> Self {
        self.explore = explore;
        self
    }

    pub fn with_replay_state(
        mut self,
        history: Arc<RwLock<ReplayHistory>>,
        migrations: Arc<RwLock<ReplayMigrationHistory>>,
    ) -> Self {
        self.replay = history;
        self.replay_migrations = migrations;
        self
    }
}

pub fn router(context: ApiContext) -> Router {
    Router::new()
        .route("/", get(cells_page))
        .route("/stats", get(cells_page))
        .route("/scheduling", get(scheduling_page))
        .route("/callbacks", get(callbacks_page))
        .route("/system", get(system_page))
        .route("/config", get(config_page))
        .route("/inspector", get(inspector_page))
        .route("/guide", get(guide_page))
        // Former pages whose sections moved; bookmarks keep working.
        .route(
            "/explore",
            get(|| async { Redirect::temporary("/scheduling") }),
        )
        .route(
            "/appendix",
            get(|| async { Redirect::temporary("/inspector") }),
        )
        .route("/ai-guide", get(ai_guide))
        .route("/assets/sections.js", get(sections_script))
        .route("/assets/callbacks.js", get(callbacks_script))
        .route("/assets/scheduling.js", get(scheduling_script))
        .route("/assets/inspector.js", get(inspector_script))
        .route("/assets/charts.js", get(charts_script))
        .route("/assets/polling.js", get(polling_script))
        .route("/assets/config.js", get(config_script))
        .route("/assets/feedback.js", get(feedback_script))
        .route("/assets/heatmap.js", get(heatmap_script))
        .route("/assets/reset.js", get(reset_script))
        .route("/assets/stats.js", get(stats_script))
        .route("/assets/topology_strip.js", get(topology_strip_script))
        .route("/assets/system.js", get(system_script))
        .route("/assets/memory_charts.js", get(memory_charts_script))
        .route("/assets/explore.js", get(explore_script))
        .route("/assets/explore.css", get(explore_stylesheet))
        .route("/assets/theme.js", get(theme_script))
        .route("/assets/timeline.js", get(timeline_script))
        .route("/assets/style.css", get(stylesheet))
        .route("/api/counters", get(counters))
        .route("/api/config", get(config_snapshot))
        .route("/api/migrations", get(migration_snapshot))
        .route("/api/reset", post(reset_inspector))
        .route("/api/host-context", get(host_context))
        .route("/api/stats", get(stats_snapshot))
        .route("/api/stats/history", get(stats_history_snapshot))
        .route("/api/system", get(system_snapshot))
        .route("/api/explore", get(explore_snapshot))
        .route("/api/timeline", get(replay_timeline))
        .route("/api/timeline/view", get(replay_view))
        .with_state(context)
        .layer(CompressionLayer::new())
}

fn navigation(active: &str) -> String {
    let mut html = String::new();
    for (index, (group, links)) in NAVIGATION.iter().enumerate() {
        let class = if index == 0 {
            "navigation-group-label"
        } else {
            "navigation-group-label navigation-group-label-secondary"
        };
        html.push_str(&format!(
            "\n          <span class=\"{class}\">{group}</span>"
        ));
        for (href, label) in links.iter() {
            let current = if *href == active {
                " class=\"active\" aria-current=\"page\""
            } else {
                ""
            };
            html.push_str(&format!(
                "\n          <a{current} href=\"{href}\">{label}</a>"
            ));
        }
    }
    html.push_str("\n        ");
    html
}

fn page(html: &str, active: &str) -> (HeaderMap, Html<String>) {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(WEB_CACHE_CONTROL),
    );
    let body = html.replacen(NAVIGATION_PLACEHOLDER, &navigation(active), 1);
    (headers, Html(body))
}

async fn cells_page() -> (HeaderMap, Html<String>) {
    page(STATS_HTML, "/")
}

async fn scheduling_page() -> (HeaderMap, Html<String>) {
    page(SCHEDULING_HTML, "/scheduling")
}

async fn callbacks_page() -> (HeaderMap, Html<String>) {
    page(CALLBACKS_HTML, "/callbacks")
}

async fn system_page() -> (HeaderMap, Html<String>) {
    page(SYSTEM_HTML, "/system")
}

async fn config_page() -> (HeaderMap, Html<String>) {
    page(CONFIG_HTML, "/config")
}

async fn inspector_page() -> (HeaderMap, Html<String>) {
    page(INSPECTOR_HTML, "/inspector")
}

async fn guide_page() -> (HeaderMap, Html<String>) {
    let mut escaped = String::with_capacity(AI_GUIDE.len());
    for character in AI_GUIDE.chars() {
        escaped.push_str(match character {
            '&' => "&amp;",
            '<' => "&lt;",
            '>' => "&gt;",
            '"' => "&quot;",
            '\'' => "&#39;",
            _ => {
                escaped.push(character);
                continue;
            }
        });
    }
    page(
        &GUIDE_HTML.replace("{{AI_GUIDE_CONTENT}}", &escaped),
        "/guide",
    )
}

async fn ai_guide() -> (HeaderMap, &'static str) {
    content("text/plain; charset=utf-8", AI_GUIDE)
}

async fn sections_script() -> (HeaderMap, &'static str) {
    content("application/javascript; charset=utf-8", SECTIONS_JS)
}

async fn callbacks_script() -> (HeaderMap, &'static str) {
    content("application/javascript; charset=utf-8", CALLBACKS_JS)
}

async fn scheduling_script() -> (HeaderMap, &'static str) {
    content("application/javascript; charset=utf-8", SCHEDULING_JS)
}

async fn inspector_script() -> (HeaderMap, &'static str) {
    content("application/javascript; charset=utf-8", INSPECTOR_JS)
}

async fn polling_script() -> (HeaderMap, &'static str) {
    content("application/javascript; charset=utf-8", POLLING_JS)
}

async fn charts_script() -> (HeaderMap, &'static str) {
    content("application/javascript; charset=utf-8", CHARTS_JS)
}

async fn config_script() -> (HeaderMap, &'static str) {
    content("application/javascript; charset=utf-8", CONFIG_JS)
}

async fn feedback_script() -> (HeaderMap, &'static str) {
    content("application/javascript; charset=utf-8", FEEDBACK_JS)
}

async fn heatmap_script() -> (HeaderMap, &'static str) {
    content("application/javascript; charset=utf-8", HEATMAP_JS)
}

async fn reset_script() -> (HeaderMap, &'static str) {
    content("application/javascript; charset=utf-8", RESET_JS)
}

async fn stats_script() -> (HeaderMap, &'static str) {
    content("application/javascript; charset=utf-8", STATS_JS)
}

async fn topology_strip_script() -> (HeaderMap, &'static str) {
    content("application/javascript; charset=utf-8", TOPOLOGY_STRIP_JS)
}

async fn system_script() -> (HeaderMap, &'static str) {
    content("application/javascript; charset=utf-8", SYSTEM_JS)
}

async fn memory_charts_script() -> (HeaderMap, &'static str) {
    content("application/javascript; charset=utf-8", MEMORY_CHARTS_JS)
}

async fn explore_script() -> (HeaderMap, &'static str) {
    content("application/javascript; charset=utf-8", EXPLORE_JS)
}

async fn explore_stylesheet() -> (HeaderMap, &'static str) {
    content("text/css; charset=utf-8", EXPLORE_CSS)
}

async fn theme_script() -> (HeaderMap, &'static str) {
    content("application/javascript; charset=utf-8", THEME_JS)
}

async fn timeline_script() -> (HeaderMap, &'static str) {
    content("application/javascript; charset=utf-8", TIMELINE_JS)
}

async fn stylesheet() -> (HeaderMap, &'static str) {
    content("text/css; charset=utf-8", STYLE_CSS)
}

fn content(content_type: &'static str, body: &'static str) -> (HeaderMap, &'static str) {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(WEB_CACHE_CONTROL),
    );
    (headers, body)
}

#[derive(Deserialize)]
struct CountersQuery {
    include_migrations: Option<bool>,
}

async fn counters(
    State(context): State<ApiContext>,
    Query(query): Query<CountersQuery>,
) -> Json<Snapshot> {
    let stored = context.counters.read().expect("snapshot lock poisoned");
    let snapshot = if query.include_migrations == Some(false) {
        stored.compact_clone_without_migrations()
    } else {
        stored.clone()
    };
    Json(snapshot)
}

async fn config_snapshot(State(context): State<ApiContext>) -> Json<SchedulerConfigSnapshot> {
    Json(
        context
            .scheduler_config
            .read()
            .expect("scheduler config lock poisoned")
            .clone(),
    )
}

#[derive(Deserialize)]
struct MigrationQuery {
    window_ms: Option<u64>,
}

async fn migration_snapshot(
    State(context): State<ApiContext>,
    Query(query): Query<MigrationQuery>,
) -> Result<Json<MigrationWindowView>, (StatusCode, Json<serde_json::Value>)> {
    let window_ms = query.window_ms.unwrap_or(context.migration_window_ms);
    context
        .migrations
        .read()
        .expect("migration history lock poisoned")
        .view(window_ms)
        .map(Json)
        .map_err(|error| {
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": error.to_string() })),
            )
        })
}

async fn reset_inspector(
    State(context): State<ApiContext>,
) -> (StatusCode, Json<serde_json::Value>) {
    let epoch = {
        let observer = context
            .observer
            .read()
            .expect("observer context lock poisoned");
        if observer.status != CollectorStatus::Active {
            return reset_error(StatusCode::CONFLICT, "Mitosis observer is not active");
        }
        observer.epoch
    };
    let timeout = Duration::from_secs(15);
    let (reply, receipt) = tokio::sync::oneshot::channel();
    let request = ResetRequest {
        expected_epoch: epoch,
        deadline: Instant::now() + timeout,
        reply,
    };
    if let Err(error) = context.commands.try_send(CollectorCommand::Reset(request)) {
        return reset_error(
            StatusCode::SERVICE_UNAVAILABLE,
            &format!("collector command unavailable: {error}"),
        );
    }
    match tokio::time::timeout(timeout, receipt).await {
        Ok(Ok(Ok(receipt))) => {
            context
                .replay
                .write()
                .expect("replay history lock poisoned")
                .clear();
            context
                .replay_migrations
                .write()
                .expect("replay migration lock poisoned")
                .clear();
            (
                StatusCode::OK,
                Json(json!({
                    "epoch": receipt.epoch,
                    "sample_seq": receipt.sample_seq,
                    "reset_at_unix_ms": receipt.reset_at_unix_ms,
                    "scope": "inspector",
                    "preserved": ["scheduler stats socket", "kernel counters"]
                })),
            )
        }
        Ok(Ok(Err(error))) => reset_error(StatusCode::SERVICE_UNAVAILABLE, &error),
        Ok(Err(_)) => reset_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "collector stopped before acknowledging reset",
        ),
        Err(_) => reset_error(StatusCode::GATEWAY_TIMEOUT, "inspector reset timed out"),
    }
}

fn reset_error(status: StatusCode, error: &str) -> (StatusCode, Json<serde_json::Value>) {
    (
        status,
        Json(json!({ "scope": "inspector", "error": error })),
    )
}

async fn host_context(State(context): State<ApiContext>) -> Json<HostContextView> {
    Json(context.host_context)
}

async fn stats_snapshot(State(context): State<ApiContext>) -> Json<StatsSnapshot> {
    Json(
        context
            .stats
            .read()
            .expect("stats snapshot lock poisoned")
            .clone(),
    )
}

async fn stats_history_snapshot(
    State(context): State<ApiContext>,
    Query(query): Query<StatsHistoryQuery>,
) -> Result<Json<StatsHistoryView>, (StatusCode, Json<serde_json::Value>)> {
    let current = context
        .observer
        .read()
        .expect("observer context lock poisoned");
    let mut history = context
        .stats_history
        .write()
        .expect("stats history lock poisoned");
    history
        .view(&current, &query, unix_ms())
        .map(Json)
        .map_err(|error| (StatusCode::BAD_REQUEST, Json(json!({"error": error}))))
}

async fn explore_snapshot(State(context): State<ApiContext>) -> Json<ExploreSnapshot> {
    let mut snapshot = context
        .explore
        .read()
        .expect("Explore snapshot lock poisoned")
        .clone();
    let current = context
        .observer
        .read()
        .expect("observer context lock poisoned")
        .clone();
    snapshot.mask_incompatible_probes(&current);
    Json(snapshot)
}

async fn system_snapshot(State(context): State<ApiContext>) -> Json<SystemStatsSnapshot> {
    Json(
        context
            .system
            .read()
            .expect("system snapshot lock poisoned")
            .clone(),
    )
}

fn replay_error(
    context: &ApiContext,
    error: impl ToString,
) -> (StatusCode, Json<serde_json::Value>) {
    let (oldest_at_unix_ms, latest_at_unix_ms) = context
        .replay
        .read()
        .expect("replay history lock poisoned")
        .bounds();
    let max_window_ms = context
        .replay_migrations
        .read()
        .expect("replay migration lock poisoned")
        .max_window_ms();
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "error": error.to_string(),
            "oldest_at_unix_ms": oldest_at_unix_ms,
            "latest_at_unix_ms": latest_at_unix_ms,
            "now_unix_ms": unix_ms(),
            "default_window_ms": context.migration_window_ms,
            "max_window_ms": max_window_ms,
        })),
    )
}

async fn replay_timeline(
    State(context): State<ApiContext>,
    Query(query): Query<ReplayQuery>,
) -> Result<Json<ReplayTimelineResponse>, (StatusCode, Json<serde_json::Value>)> {
    let window_ms = query.window_ms.unwrap_or(context.migration_window_ms);
    let validation = context
        .replay_migrations
        .read()
        .expect("replay migration lock poisoned")
        .locality_at(0, 0, window_ms);
    validation.map_err(|error| replay_error(&context, error))?;
    let response = context
        .replay
        .write()
        .expect("replay history lock poisoned")
        .timeline(&query, unix_ms());
    let mut response = response.map_err(|error| replay_error(&context, error))?;
    let migrations = context
        .replay_migrations
        .read()
        .expect("replay migration lock poisoned");
    for frame in &mut response.frames {
        let percentages = if frame.source_available.get("counters") == Some(&true) {
            let meta = &frame.source_meta["counters"];
            migrations
                .locality_at(
                    meta.captured_at_unix_ms.unwrap_or(frame.at_unix_ms),
                    meta.epoch,
                    window_ms,
                )
                .unwrap_or([None; 4])
        } else {
            [None; 4]
        };
        for (name, percentage) in ["same_core", "same_llc", "cross_llc", "cross_numa"]
            .into_iter()
            .zip(percentages)
        {
            frame
                .signals
                .insert(format!("migration.{name}"), percentage);
        }
    }
    Ok(Json(ReplayTimelineResponse {
        timeline: response,
        window_ms,
        default_window_ms: context.migration_window_ms,
        max_window_ms: migrations.max_window_ms(),
    }))
}

async fn replay_view(
    State(context): State<ApiContext>,
    Query(query): Query<ReplayViewQuery>,
) -> Result<Json<ReplayView>, (StatusCode, Json<serde_json::Value>)> {
    let window_ms = query.window_ms.unwrap_or(context.migration_window_ms);
    let validation = context
        .replay_migrations
        .read()
        .expect("replay migration lock poisoned")
        .locality_at(0, 0, window_ms);
    validation.map_err(|error| replay_error(&context, error))?;
    let selected = context
        .replay
        .write()
        .expect("replay history lock poisoned")
        .select_view(query.at_unix_ms, unix_ms());
    let selected = selected.map_err(|error| replay_error(&context, error))?;
    // Inflation and JSON parsing operate on an owned payload after the replay
    // guard has been dropped, so readers do not block frame publication.
    let mut response = selected
        .decode()
        .map_err(|error| replay_error(&context, error))?;
    if let Some(error) = response.source_errors.get("counters") {
        response
            .source_errors
            .insert("migrations".into(), error.clone());
    } else {
        let meta = &response.sources["counters"]["meta"];
        let epoch = meta["epoch"].as_u64().unwrap_or(response.collector.epoch);
        let counter_captured_at = meta["captured_at_unix_ms"].as_u64();
        let migrations = context
            .replay_migrations
            .read()
            .expect("replay migration lock poisoned")
            // The heatmap represents the window ending at the selected
            // replay frame; its counter source may have an older capture.
            .view_at(response.at_unix_ms, epoch, window_ms);
        // Drop the migration guard before an error response reads its limits.
        let mut migrations = migrations.map_err(|error| replay_error(&context, error))?;
        // If the frame contains a newer counter capture, a missing retained
        // interval up to that known endpoint must remain incomplete. This does
        // not change the frame cutoff or exclude newer valid historical bins.
        if migrations.migration_quality == "complete"
            && counter_captured_at.is_some_and(|captured| {
                migrations
                    .meta
                    .captured_at_unix_ms
                    .is_none_or(|retained| captured > retained)
            })
        {
            migrations.migration_quality = "incomplete";
        }
        response.migrations = Some(migrations);
        if response
            .migrations
            .as_ref()
            .is_some_and(|view| view.migration_quality == "unavailable")
        {
            response.source_errors.insert(
                "migrations".into(),
                "No retained migration interval at this time".into(),
            );
        }
    }
    Ok(Json(response))
}
