// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::sync::{Arc, RwLock};

use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::Html;
use axum::routing::get;
use axum::{Json, Router};

use crate::collector::Snapshot;
use crate::host_context::HostContextView;
use crate::stats::StatsSnapshot;

const INDEX_HTML: &str = include_str!("web/index.html");
const STATS_HTML: &str = include_str!("web/stats.html");
const APP_JS: &str = include_str!("web/app.js");
const STATS_JS: &str = include_str!("web/stats.js");
const STYLE_CSS: &str = include_str!("web/style.css");
const WEB_CACHE_CONTROL: &str = "no-store";

#[derive(Clone)]
pub struct ApiContext {
    counters: Arc<RwLock<Snapshot>>,
    stats: Arc<RwLock<StatsSnapshot>>,
    host_context: HostContextView,
}

impl ApiContext {
    pub fn new(
        counters: Arc<RwLock<Snapshot>>,
        stats: Arc<RwLock<StatsSnapshot>>,
        host_context: HostContextView,
    ) -> Self {
        Self {
            counters,
            stats,
            host_context,
        }
    }
}

pub fn router(context: ApiContext) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/stats", get(stats_page))
        .route("/assets/app.js", get(app_script))
        .route("/assets/stats.js", get(stats_script))
        .route("/assets/style.css", get(stylesheet))
        .route("/api/counters", get(counters))
        .route("/api/host-context", get(host_context))
        .route("/api/stats", get(stats_snapshot))
        .with_state(context)
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn stats_page() -> Html<&'static str> {
    Html(STATS_HTML)
}

async fn app_script() -> (HeaderMap, &'static str) {
    content("application/javascript; charset=utf-8", APP_JS)
}

async fn stats_script() -> (HeaderMap, &'static str) {
    content("application/javascript; charset=utf-8", STATS_JS)
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

async fn counters(State(context): State<ApiContext>) -> Json<Snapshot> {
    Json(
        context
            .counters
            .read()
            .expect("snapshot lock poisoned")
            .clone(),
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
