// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::BTreeMap;
use std::sync::mpsc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use scx_snake_heatmap::api::{router, ApiContext, CSRF_HEADER};
use scx_snake_heatmap::collector::CollectorCommand;
use scx_snake_heatmap::dashboard::Dashboard;
use scx_snake_heatmap::model::CpuPair;
use scx_snake_heatmap::scope::TaskScope;
use scx_snake_heatmap::topology::{CpuInfo, TopologyView};
use serde_json::{json, Value};
use tower::ServiceExt;

fn dashboard() -> Dashboard {
    let topology = TopologyView::from_cpus(vec![
        CpuInfo {
            cpu: 0,
            node: 0,
            package: 0,
            llc: 0,
            core: 0,
        },
        CpuInfo {
            cpu: 1,
            node: 0,
            package: 0,
            llc: 0,
            core: 1,
        },
    ])
    .unwrap();
    Dashboard::new(topology, 5_000)
}

#[tokio::test]
async fn snapshot_endpoint_returns_the_requested_rolling_window() {
    let dashboard = dashboard();
    let pair = CpuPair::new(0, 1);
    dashboard.ingest(0, &BTreeMap::new());
    dashboard.ingest(250, &BTreeMap::from([(pair, 4)]));
    dashboard.reset_cpu_usage(0);
    dashboard.ingest_cpu_usage(250, &BTreeMap::from([(0, 125_000_000), (1, 250_000_000)]));
    dashboard.set_scheduler("snake", true, 11);
    let (tx, _rx) = mpsc::channel();
    let root = tempfile::tempdir().unwrap();
    let app = router(ApiContext::new(
        dashboard,
        tx,
        "secret",
        root.path().to_path_buf(),
    ));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/snapshot?window_ms=1000")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["scheduler"]["name"], "snake");
    assert_eq!(json["scheduler"]["active"], true);
    assert_eq!(json["window_ms"], 1000);
    assert_eq!(json["observed_ms"], 250);
    assert_eq!(json["total"], 4);
    assert_eq!(json["cells"], json!([{"from": 0, "to": 1, "count": 4}]));
    assert_eq!(json["cpu_usage_observed_ms"], 250);
    assert_eq!(
        json["cpu_usage"],
        json!([
            {"cpu": 0, "runtime_ns": 125_000_000, "utilization_pct": 50.0},
            {"cpu": 1, "runtime_ns": 250_000_000, "utilization_pct": 100.0},
        ])
    );
    assert_eq!(json["cpu_usage_scope"], "all_snake_tasks");
}

#[tokio::test]
async fn snapshot_endpoint_rejects_a_window_beyond_retention() {
    let (tx, _rx) = mpsc::channel();
    let root = tempfile::tempdir().unwrap();
    let app = router(ApiContext::new(
        dashboard(),
        tx,
        "secret",
        root.path().to_path_buf(),
    ));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/snapshot?window_ms=5001")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn snapshot_endpoint_exposes_collector_health() {
    let dashboard = dashboard();
    dashboard.set_collector_health(Some("BPF attach denied".into()), 2, 3);
    dashboard.set_cpu_usage_error(Some("Snake stats unavailable".into()));
    let (tx, _rx) = mpsc::channel();
    let root = tempfile::tempdir().unwrap();
    let app = router(ApiContext::new(
        dashboard,
        tx,
        "secret",
        root.path().to_path_buf(),
    ));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/snapshot?window_ms=1000")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["collector_error"], "BPF attach denied");
    assert_eq!(json["pair_map_failures"], 2);
    assert_eq!(json["task_storage_failures"], 3);
    assert_eq!(json["cpu_usage_error"], "Snake stats unavailable");
}

#[tokio::test]
async fn scope_endpoint_requires_token_and_sends_validated_command() {
    let (tx, rx) = mpsc::channel();
    let root = tempfile::tempdir().unwrap();
    let context = ApiContext::new(dashboard(), tx, "secret", root.path().to_path_buf());
    let body = serde_json::to_vec(&json!({"kind": "tgids", "tgids": [21, 8, 21]})).unwrap();

    let unauthorized = router(context.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/scope")
                .header("host", "127.0.0.1")
                .header("content-type", "application/json")
                .body(Body::from(body.clone()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let accepted = router(context)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/scope")
                .header("host", "127.0.0.1")
                .header("content-type", "application/json")
                .header(CSRF_HEADER, "secret")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::ACCEPTED);
    assert_eq!(
        rx.try_recv().unwrap(),
        CollectorCommand::SetScope(TaskScope::Tgids(vec![8, 21]))
    );
}

#[tokio::test]
async fn event_stream_emits_an_immediate_snapshot() {
    let dashboard = dashboard();
    dashboard.ingest(0, &BTreeMap::new());
    dashboard.ingest(250, &BTreeMap::from([(CpuPair::new(1, 0), 2)]));
    let (tx, _rx) = mpsc::channel();
    let root = tempfile::tempdir().unwrap();
    let app = router(ApiContext::new(
        dashboard,
        tx,
        "secret",
        root.path().to_path_buf(),
    ));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/events?window_ms=1000")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["content-type"], "text/event-stream");

    let mut body = response.into_body();
    let frame = tokio::time::timeout(std::time::Duration::from_secs(1), body.frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let data = frame.into_data().unwrap();
    let event = std::str::from_utf8(&data).unwrap();
    assert!(event.contains("\"total\":2"), "unexpected event: {event}");
}

#[tokio::test]
async fn root_page_embeds_session_configuration_and_local_assets() {
    let (tx, _rx) = mpsc::channel();
    let root = tempfile::tempdir().unwrap();
    let context = ApiContext::new(dashboard(), tx, "secret", root.path().to_path_buf())
        .with_initial_window_ms(2_000);
    let app = router(context);

    let page = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    assert_eq!(page.headers()["content-type"], "text/html; charset=utf-8");
    let page = page.into_body().collect().await.unwrap().to_bytes();
    let page = std::str::from_utf8(&page).unwrap();
    assert!(page.contains("name=\"snake-session-token\" content=\"secret\""));
    assert!(page.contains("data-initial-window-ms=\"2000\""));
    assert!(page.contains("data-max-window-ms=\"5000\""));
    assert!(page.contains("/assets/app.js"));
    assert!(!page.contains("https://"));
    for control in [
        "id=\"liveStatus\"",
        "id=\"windowSelect\"",
        "id=\"orderTopology\"",
        "id=\"scaleLog\"",
        "id=\"scopeMode\"",
        "id=\"totalMigrations\"",
        "id=\"heatmapCanvas\"",
    ] {
        assert!(page.contains(control), "missing page control {control}");
    }
    assert!(page.contains("id=\"zoomControl\" type=\"range\" min=\"0.25\" max=\"3\" step=\"0.25\""));

    let script = app
        .oneshot(
            Request::builder()
                .uri("/assets/app.js")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(script.status(), StatusCode::OK);
    assert_eq!(
        script.headers()["content-type"],
        "text/javascript; charset=utf-8"
    );
}

#[tokio::test]
async fn router_rejects_non_loopback_host_headers() {
    let (tx, _rx) = mpsc::channel();
    let root = tempfile::tempdir().unwrap();
    let app = router(ApiContext::new(
        dashboard(),
        tx,
        "secret",
        root.path().to_path_buf(),
    ));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header("host", "attacker.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::MISDIRECTED_REQUEST);
}
