// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::BTreeMap;
use std::sync::mpsc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use scx_snake_inspector::api::{router, ApiContext, CSRF_HEADER};
use scx_snake_inspector::collector::CollectorCommand;
use scx_snake_inspector::dashboard::Dashboard;
use scx_snake_inspector::model::CpuPair;
use scx_snake_inspector::policies::{PolicyCatalog, PolicyChoice};
use scx_snake_inspector::scope::TaskScope;
use scx_snake_inspector::topology::{CpuInfo, TopologyView};
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

fn callback_timing_snapshot(
    generation: u64,
    dispatch_total_ns: u64,
    dispatch_samples: u64,
) -> Value {
    let mut callbacks = serde_json::Map::new();
    for name in [
        "select_cpu",
        "enqueue",
        "dispatch",
        "runnable",
        "running",
        "stopping",
        "quiescent",
    ] {
        let mut buckets = vec![0_u64; 64];
        let total_ns = if name == "dispatch" {
            buckets[5] = dispatch_samples;
            dispatch_total_ns
        } else {
            0
        };
        callbacks.insert(
            name.into(),
            json!({"total_ns": total_ns, "buckets": buckets}),
        );
    }
    json!({
        "schema_version": 1,
        "active_slot": 0,
        "callback_timing_sample_rate": 64,
        "slots": [{
            "slot": 0,
            "state": "active",
            "generation": generation,
            "metrics": {"callback_timing": callbacks}
        }],
        "cells": [],
        "task_mappings": []
    })
}

fn fine_timing_snapshot() -> Value {
    let mut snapshot = callback_timing_snapshot(7, 0, 0);
    let mut dispatch_buckets = vec![0_u64; 32];
    let empty_buckets = vec![0_u64; 32];
    dispatch_buckets[5] = 100;
    snapshot["fine_timing"] = json!({
        "sample_rate": 64,
        "captures": [
            {
                "callback": "select_cpu",
                "state": "inactive",
                "session_id": null,
                "policy_generation": null,
                "started_at_ms": null,
                "stopped_at_ms": null,
                "stages": {}
            },
            {
                "callback": "enqueue",
                "state": "collecting",
                "session_id": 10,
                "policy_generation": 7,
                "started_at_ms": 1000,
                "stopped_at_ms": null,
                "stages": {
                    "normal_dsq_insert": {"total_ns": 0, "buckets": empty_buckets}
                }
            },
            {
                "callback": "dispatch",
                "state": "historical",
                "session_id": 9,
                "policy_generation": 7,
                "started_at_ms": 500,
                "stopped_at_ms": 900,
                "stages": {
                    "remote_normal_scan": {"total_ns": 6300, "buckets": dispatch_buckets}
                }
            }
        ]
    });
    snapshot
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
async fn inspection_endpoint_returns_the_latest_scheduler_read_model() {
    let dashboard = dashboard();
    dashboard.set_inspection(
        Some(json!({
            "schema_version": 1,
            "active_slot": 1,
            "slots": [
                {"slot": 0, "state": "inactive"},
                {"slot": 1, "state": "active"}
            ],
            "cells": [{"id": 7, "cpus": [0, 1], "task_count": 1}],
            "task_mappings": [{"tid": 4812, "cell_id": 7}]
        })),
        None,
    );
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
                .uri("/api/inspection")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["sequence"], 1);
    assert_eq!(json["error"], Value::Null);
    assert_eq!(json["snapshot"]["active_slot"], 1);
    assert_eq!(json["snapshot"]["cells"][0]["id"], 7);
    assert_eq!(json["snapshot"]["task_mappings"][0]["tid"], 4812);
}

#[tokio::test]
async fn callback_timing_endpoint_returns_window_and_lifetime_percentiles() {
    let dashboard = dashboard();
    dashboard.set_scheduler("snake", true, 4);
    dashboard.set_inspection_at(0, Some(callback_timing_snapshot(7, 0, 0)), None);
    dashboard.set_inspection_at(1_000, Some(callback_timing_snapshot(7, 6_300, 100)), None);
    let (tx, _rx) = mpsc::channel();
    let root = tempfile::tempdir().unwrap();
    let context = ApiContext::new(dashboard, tx, "secret", root.path().to_path_buf());

    let response = router(context.clone())
        .oneshot(
            Request::builder()
                .uri("/api/callback-timing?scope=window&window_ms=2000")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    let dispatch = json["callbacks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["callback"] == "dispatch")
        .unwrap();

    assert_eq!(json["status"], "ready");
    assert_eq!(json["scope"], "window");
    assert_eq!(json["window_ms"], 2_000);
    assert_eq!(json["observed_ms"], 1_000);
    assert_eq!(json["generation"], 7);
    assert_eq!(json["sample_rate"], 64);
    assert_eq!(json["callbacks"].as_array().unwrap().len(), 7);
    assert_eq!(dispatch["samples"], 100);
    assert_eq!(dispatch["mean_ns"], 63);
    assert_eq!(dispatch["p50_ns"], 63);
    assert_eq!(dispatch["p95_ns"], 63);
    assert_eq!(dispatch["p99_ns"], 63);

    let lifetime = router(context)
        .oneshot(
            Request::builder()
                .uri("/api/callback-timing?scope=lifetime")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(lifetime.status(), StatusCode::OK);
    let body = lifetime.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["scope"], "lifetime");
    assert_eq!(json["window_ms"], Value::Null);
    assert_eq!(json["observed_ms"], Value::Null);
}

#[tokio::test]
async fn fine_timing_endpoint_summarizes_stages_and_controls_callbacks_independently() {
    use scx_snake_inspector::collector::{FineTimingCallback, FineTimingControlResponse};

    let dashboard = dashboard();
    dashboard.set_inspection(Some(fine_timing_snapshot()), None);
    let (tx, rx) = mpsc::channel();
    let root = tempfile::tempdir().unwrap();
    let context = ApiContext::new(dashboard, tx, "secret", root.path().to_path_buf());

    let response = router(context.clone())
        .oneshot(
            Request::builder()
                .uri("/api/fine-timing")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();
    let dispatch = body["captures"]
        .as_array()
        .unwrap()
        .iter()
        .find(|capture| capture["callback"] == "dispatch")
        .unwrap();
    assert_eq!(body["status"], "ready");
    assert_eq!(dispatch["state"], "historical");
    assert_eq!(dispatch["stages"][0]["stage"], "remote_normal_scan");
    assert_eq!(dispatch["stages"][0]["samples"], 100);
    assert_eq!(dispatch["stages"][0]["mean_ns"], 63);

    let responder = std::thread::spawn(move || {
        let CollectorCommand::SetFineTiming {
            callback,
            enabled,
            response,
        } = rx.recv().unwrap()
        else {
            panic!("expected fine timing command");
        };
        assert_eq!(callback, FineTimingCallback::SelectCpu);
        assert!(enabled);
        response
            .send(Ok(FineTimingControlResponse {
                callback,
                enabled,
                session_id: Some(11),
            }))
            .unwrap();
    });
    let response = router(context)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/fine-timing")
                .header("host", "127.0.0.1")
                .header("content-type", "application/json")
                .header(CSRF_HEADER, "secret")
                .body(Body::from(r#"{"callback":"select_cpu","enabled":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["callback"], "select_cpu");
    assert_eq!(body["enabled"], true);
    assert_eq!(body["session_id"], 11);
    responder.join().unwrap();
}

#[tokio::test]
async fn workload_assignment_requires_token_and_sends_typed_target() {
    use scx_snake_inspector::workload::{WorkloadCellResponse, WorkloadTarget};

    let (tx, rx) = mpsc::channel();
    let root = tempfile::tempdir().unwrap();
    let context = ApiContext::new(dashboard(), tx, "secret", root.path().to_path_buf());
    let body = r#"{"target":{"kind":"tgid","tgid":42},"cell_id":2}"#;

    let unauthorized = router(context.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/cells/assignment")
                .header("host", "127.0.0.1")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let responder = std::thread::spawn(move || {
        let CollectorCommand::SetWorkloadCell {
            target,
            cell_id,
            response,
        } = rx.recv().unwrap()
        else {
            panic!("expected workload cell command");
        };
        assert_eq!(target, WorkloadTarget::Tgid { tgid: 42 });
        assert_eq!(cell_id, Some(2));
        response
            .send(Ok(WorkloadCellResponse {
                target: "TGID 42".into(),
                cell_id: Some(2),
                matched: 3,
                updated: 2,
                transient: vec![44],
                rehome_requested: 2,
            }))
            .unwrap();
    });
    let accepted = router(context)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/cells/assignment")
                .header("host", "127.0.0.1")
                .header("content-type", "application/json")
                .header(CSRF_HEADER, "secret")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);
    let response: Value =
        serde_json::from_slice(&accepted.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(response["target"], "TGID 42");
    assert_eq!(response["updated"], 2);
    assert_eq!(response["transient"], json!([44]));
    responder.join().unwrap();
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
async fn policy_catalog_is_readable_and_activation_requires_the_session_token() {
    let dashboard = dashboard();
    dashboard.set_policy_catalog(
        Some(PolicyCatalog {
            policies: vec![PolicyChoice {
                id: "random-idle.toml".into(),
                name: "random idle".into(),
                source: "[[rung]]\noperation = \"pick_random_idle\"\nscope = \"task_allowed\"\n"
                    .into(),
                rung_count: 1,
                mask_table_count: 0,
                cell_count: 0,
                summary: "1 rung, 0 mask tables, 0 cells".into(),
            }],
            invalid: Vec::new(),
        }),
        None,
    );
    let (tx, rx) = mpsc::channel();
    let root = tempfile::tempdir().unwrap();
    let context = ApiContext::new(dashboard, tx, "secret", root.path().to_path_buf());

    let catalog = router(context.clone())
        .oneshot(
            Request::builder()
                .uri("/api/policies")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(catalog.status(), StatusCode::OK);
    let body = catalog.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["catalog"]["policies"][0]["id"], "random-idle.toml");

    let request_body = Body::from(r#"{"policy_id":"random-idle.toml"}"#);
    let unauthorized = router(context.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/policies/activate")
                .header("host", "127.0.0.1")
                .header("content-type", "application/json")
                .body(request_body)
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let responder = std::thread::spawn(move || {
        let command = rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("activation command should arrive");
        let CollectorCommand::ActivatePolicy {
            policy_id,
            response,
        } = command
        else {
            panic!("expected policy activation command");
        };
        assert_eq!(policy_id, "random-idle.toml");
        response
            .send(Ok(scx_snake_inspector::policies::PolicyActivation {
                generation: 9,
                rung_count: 1,
                mask_table_count: 0,
                summary: "1 rung, 0 mask tables".into(),
            }))
            .unwrap();
    });
    let accepted = router(context)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/policies/activate")
                .header("host", "127.0.0.1")
                .header("content-type", "application/json")
                .header(CSRF_HEADER, "secret")
                .body(Body::from(r#"{"policy_id":"random-idle.toml"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);
    let body = accepted.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["generation"], 9);
    responder.join().unwrap();
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
        "id=\"primaryNav\"",
        "href=\"#/activity\"",
        "href=\"#/policy\"",
        "href=\"#/cells\"",
        "id=\"activityView\"",
        "id=\"policyView\"",
        "id=\"policyLibrary\"",
        "id=\"policyDialog\"",
        "id=\"cellsView\"",
        "id=\"workloadTargetKind\"",
        "id=\"workloadTargetValue\"",
        "id=\"workloadCellId\"",
        "id=\"assignWorkloadCell\"",
        "id=\"clearWorkloadCell\"",
        "id=\"referencePopover\"",
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
