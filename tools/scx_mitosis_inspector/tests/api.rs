use std::sync::{Arc, RwLock};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use scx_mitosis_inspector::api::{router, ApiContext};
use scx_mitosis_inspector::collector::Snapshot;
use scx_mitosis_inspector::host_context::{HostContextView, HostIdentityView};
use scx_mitosis_inspector::stats::StatsSnapshot;
use scx_mitosis_inspector::{CallbackCounter, CallbackTimingRow};
use serde_json::json;
use tower::ServiceExt;

fn snapshot() -> Snapshot {
    Snapshot {
        scheduler: "scx_mitosis",
        target_program_ids: [11, 12, 13, 14, 15],
        uptime_seconds: 9,
        counters: vec![CallbackCounter {
            name: "select_cpu",
            count: 42,
            rate_per_second: 7.0,
        }],
        callback_timing_sample_rate: 1024,
        callback_timings: vec![CallbackTimingRow {
            callback: "select_cpu",
            samples: 18,
            mean_ns: Some(211),
            p50_ns: Some(127),
            p95_ns: None,
            p99_ns: None,
        }],
    }
}

fn stats_snapshot() -> StatsSnapshot {
    StatsSnapshot {
        metrics: Some(json!({
            "num_cells": 1,
            "local_q_pct": 71.0,
            "cpu_q_pct": 12.0,
            "cell_q_pct": 9.0,
            "borrowed_pct": 8.0,
            "affn_violations_pct": 0.5,
            "steal_pct": 2.0,
            "drain_cnt": 3,
            "slice_shrink": 14,
            "slice_shrink_max": 4,
            "slice_shrink_proportional": 8,
            "slice_shrink_min": 2,
            "share_of_decisions_pct": 100.0,
            "total_decisions": 1234,
            "util_pct": 63.5,
            "demand_borrow_pct": 4.5,
            "lent_pct": 1.5,
            "rebalance_count": 2,
            "enforced_holdout": 0,
            "cells": {
                "0": {
                    "num_cpus": 16,
                    "local_q_pct": 71.0,
                    "cpu_q_pct": 12.0,
                    "cell_q_pct": 9.0,
                    "borrowed_pct": 8.0,
                    "affn_violations_pct": 0.5,
                    "steal_pct": 2.0,
                    "drain_cnt": 3,
                    "slice_shrink": 14,
                    "slice_shrink_max": 4,
                    "slice_shrink_proportional": 8,
                    "slice_shrink_min": 2,
                    "share_of_decisions_pct": 100.0,
                    "total_decisions": 1234,
                    "util_pct": 63.5,
                    "demand_borrow_pct": 4.5,
                    "lent_pct": 1.5,
                    "smoothed_util_pct": 61.0
                }
            }
        })),
        error: None,
    }
}

fn app() -> axum::Router {
    router(ApiContext::new(
        Arc::new(RwLock::new(snapshot())),
        Arc::new(RwLock::new(stats_snapshot())),
        HostContextView {
            identity: HostIdentityView {
                hostname: "mitosis-vm".into(),
                kernel_release: "6.12.0-scx".into(),
                cpu_count: 16,
            },
        },
    ))
}

#[tokio::test]
async fn counters_endpoint_returns_the_current_snapshot() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/api/counters")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["scheduler"], "scx_mitosis");
    assert_eq!(value["counters"][0]["count"], 42);
    assert_eq!(value["counters"][0]["rate_per_second"], 7.0);
    assert_eq!(value["callback_timing_sample_rate"], 1024);
    assert_eq!(value["callback_timings"][0]["samples"], 18);
    assert_eq!(value["callback_timings"][0]["mean_ns"], 211);
}

#[tokio::test]
async fn index_is_the_one_page_inspector() {
    let response = app()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(html.contains("Mitosis inspector"));
    assert!(html.contains("class=\"workspace-sidebar\""));
    assert!(html.contains("aria-current=\"page\" href=\"/\">Callbacks"));
    assert!(html.contains("id=\"hostname\""));
    assert!(html.contains("id=\"kernelRelease\""));
    assert!(html.contains("id=\"cpuCount\""));
    assert!(html.contains("id=\"callbackTimingSampleRate\""));
    assert!(html.contains("id=\"callbackTimingRows\""));
    assert!(html.contains("/assets/app.js"));
}

#[tokio::test]
async fn host_context_endpoint_returns_target_environment() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/api/host-context")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["identity"]["hostname"], "mitosis-vm");
    assert_eq!(value["identity"]["kernel_release"], "6.12.0-scx");
    assert_eq!(value["identity"]["cpu_count"], 16);
}

#[tokio::test]
async fn stats_endpoint_returns_every_scheduler_stat() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/api/stats")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["metrics"]["slice_shrink"], 14);
    assert_eq!(value["metrics"]["cells"]["0"]["smoothed_util_pct"], 61.0);
    assert!(value["error"].is_null());
}

#[tokio::test]
async fn stats_is_a_distinct_second_page() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/stats")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(html.contains("Mitosis stats"));
    assert!(html.contains("class=\"workspace-sidebar\""));
    assert!(html.contains("aria-current=\"page\" href=\"/stats\">Stats"));
    assert!(html.contains("/assets/stats.js"));
}
