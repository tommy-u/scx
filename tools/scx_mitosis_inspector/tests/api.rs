use std::sync::{Arc, RwLock};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use scx_mitosis_inspector::api::{router, ApiContext};
use scx_mitosis_inspector::collector::Snapshot;
use scx_mitosis_inspector::host_context::{HostContextView, HostIdentityView};
use scx_mitosis_inspector::stats::StatsSnapshot;
use scx_mitosis_inspector::system_stats::SystemStatsCollector;
use scx_mitosis_inspector::topology::{CpuInfo, TopologyView};
use scx_mitosis_inspector::{
    CallbackCounter, CallbackTimingRow, CpuRuntimeRow, MigrationRow, TimingMetricRow,
};
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
        event_timing_sample_rate: 64,
        callback_timings: vec![CallbackTimingRow {
            callback: "select_cpu",
            samples: 18,
            mean_ns: Some(211),
            p50_ns: Some(127),
            p95_ns: None,
            p99_ns: None,
        }],
        scheduler_timings: vec![TimingMetricRow {
            metric: "wakeup_to_running",
            samples: 25,
            mean_ns: Some(12_400),
            p50_ns: Some(8_191),
            p95_ns: Some(32_767),
            p99_ns: None,
        }],
        migrations: vec![MigrationRow {
            from_cpu: 2,
            to_cpu: 7,
            count: 19,
        }],
        cpu_runtime: vec![CpuRuntimeRow {
            cpu: 0,
            runtime_ns: 1234,
            utilization_pct: 72.5,
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
        Arc::new(RwLock::new(SystemStatsCollector::new().collect())),
        HostContextView {
            identity: HostIdentityView {
                hostname: "mitosis-vm".into(),
                kernel_release: "6.12.0-scx".into(),
                cpu_count: 16,
            },
            topology: TopologyView::from_cpus(vec![CpuInfo {
                cpu: 0,
                node: 0,
                package: 0,
                llc: 0,
                core: 0,
            }])
            .unwrap(),
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
    assert_eq!(value["event_timing_sample_rate"], 64);
    assert_eq!(value["callback_timings"][0]["samples"], 18);
    assert_eq!(value["callback_timings"][0]["mean_ns"], 211);
    assert_eq!(value["scheduler_timings"][0]["metric"], "wakeup_to_running");
    assert_eq!(value["scheduler_timings"][0]["samples"], 25);
    assert_eq!(value["migrations"][0]["from_cpu"], 2);
    assert_eq!(value["migrations"][0]["to_cpu"], 7);
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
    assert!(html.contains("id=\"schedulerTimingRows\""));
    assert!(html.contains("id=\"eventTimingSampleRate\""));
    assert!(html.contains("id=\"migrationRows\""));
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
    assert_eq!(value["topology"]["cpus"][0]["llc"], 0);
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
async fn scheduler_stats_is_a_distinct_third_page() {
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
    assert!(html.contains("Scheduler stats"));
    assert!(html.contains("class=\"workspace-sidebar\""));
    assert!(html.contains("aria-current=\"page\" href=\"/stats\">Scheduler"));
    assert!(html.contains("/assets/stats.js"));
}

#[tokio::test]
async fn system_is_a_distinct_page() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/system")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(html.contains("System stats"));
    assert!(html.contains("aria-current=\"page\" href=\"/system\">System"));
    assert!(html.contains("/assets/system.js"));
}
