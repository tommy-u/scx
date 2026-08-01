use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use scx_mitosis_inspector::api::{router, ApiContext};
use scx_mitosis_inspector::bpf_program_stats::BpfProgramStatsRow;
use scx_mitosis_inspector::collector::Snapshot;
use scx_mitosis_inspector::host_context::{HostContextView, HostIdentityView};
use scx_mitosis_inspector::migration_history::MigrationHistory;
use scx_mitosis_inspector::stats::StatsSnapshot;
use scx_mitosis_inspector::system_stats::SystemStatsCollector;
use scx_mitosis_inspector::topology::{CpuInfo, TopologyView};
use scx_mitosis_inspector::{
    CallbackCounter, CallbackTimingRow, CpuRuntimeRow, MigrationRow, ProbeManifestRow,
    TimingMetricRow,
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
            buckets: vec![0; 64],
            mean_ns: Some(211),
            p50_ns: Some(127),
            p95_ns: None,
            p99_ns: None,
        }],
        scheduler_timings: vec![TimingMetricRow {
            metric: "wakeup_to_running",
            samples: 25,
            buckets: vec![0; 64],
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
        cpu_capacity_loss: Vec::new(),
        bpf_program_stats: vec![BpfProgramStatsRow {
            id: 11,
            name: "mitosis_select_".into(),
            run_count: 42,
            run_time_ns: 8_400,
            average_runtime_ns: Some(200),
            recursion_misses: 0,
            verified_insns: Some(100),
        }],
        inspector_bpf_program_stats: Vec::new(),
        inspector_bpf_cpu_equivalent_pct: None,
        inspector_bpf_host_capacity_pct: None,
        dsq_metrics: Default::default(),
        scheduler_events: Vec::new(),
        softirqs: Vec::new(),
        block_io: Default::default(),
        interrupt_cpu: Vec::new(),
        hardirqs: Default::default(),
        probe_manifest: vec![ProbeManifestRow {
            group: "Callback latency",
            status: "active",
            mode: "Sampled 1/1024".into(),
            scope: "Mitosis callbacks",
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
    let mut migration_history = MigrationHistory::new(5_000);
    migration_history.ingest(0, &[]);
    migration_history.ingest(
        250,
        &[MigrationRow {
            from_cpu: 2,
            to_cpu: 7,
            count: 3,
        }],
    );
    migration_history.ingest(
        500,
        &[MigrationRow {
            from_cpu: 2,
            to_cpu: 7,
            count: 5,
        }],
    );
    migration_history.ingest(
        600,
        &[MigrationRow {
            from_cpu: 2,
            to_cpu: 7,
            count: 5,
        }],
    );
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
        Arc::new(RwLock::new(migration_history)),
        1_000,
        Arc::new(AtomicBool::new(false)),
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
    assert_eq!(value["dsq_metrics"]["available"], false);
    assert_eq!(value["probe_manifest"][0]["status"], "active");
    assert_eq!(value["probe_manifest"][0]["mode"], "Sampled 1/1024");
}

#[tokio::test]
async fn migration_endpoint_returns_the_selected_rolling_window() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/api/migrations?window_ms=300")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["window_ms"], 300);
    assert_eq!(value["max_window_ms"], 5_000);
    assert_eq!(value["total"], 2);
    assert_eq!(value["rows"][0]["from_cpu"], 2);
    assert_eq!(value["rows"][0]["to_cpu"], 7);
}

#[tokio::test]
async fn reset_endpoint_accepts_a_new_inspector_epoch() {
    let response = app()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/reset")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["scope"], "inspector");
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
    assert!(html.contains("id=\"sectionNavigation\""));
    assert!(html.contains("href=\"#probe-manifest\""));
    assert!(html.contains("href=\"#migration-locality\""));
    assert!(html.contains("id=\"downloadSnapshot\""));
    assert!(html.contains("id=\"resetAllStats\""));
    assert!(html.contains("id=\"resetStatsStatus\""));
    assert!(html.contains("id=\"hostname\""));
    assert!(html.contains("id=\"kernelRelease\""));
    assert!(html.contains("id=\"cpuCount\""));
    let summary = html
        .split("<section class=\"summary\"")
        .nth(1)
        .and_then(|section| section.split("</section>").next())
        .unwrap();
    assert!(summary.contains("id=\"overallCpuUtilization\""));
    assert!(html.contains("id=\"callbackTimingSampleRate\""));
    assert!(html.contains("id=\"callbackTimingRows\""));
    assert!(html.contains("id=\"schedulerTimingRows\""));
    assert!(html.contains("id=\"eventTimingSampleRate\""));
    assert!(html.contains("id=\"migrationWindow\""));
    assert!(html.contains("id=\"migrationWindowCoverage\""));
    assert!(html.contains("id=\"migrationRows\""));
    assert!(html.contains("id=\"dsqMetricRows\""));
    assert!(html.contains("id=\"schedulerEventRows\""));
    assert!(html.contains("id=\"softirqRows\""));
    assert!(html.contains("id=\"blockIoRows\""));
    assert!(html.contains("id=\"hardirqRows\""));
    assert!(html.contains("id=\"probeManifestRows\""));
    assert!(html.contains("id=\"inspectorBpfProgramRows\""));
    for id in [
        "live-history",
        "cpuHistoryChart",
        "callbackRateHistoryChart",
        "latencyHistoryChart",
        "dsqDepthHistoryChart",
        "callbackCostChart",
        "callbackLatencyChart",
        "schedulerLatencyChart",
        "softirqLatencyChart",
        "hardirqLatencyChart",
        "blockIoLatencyChart",
        "dsqResidenceChart",
        "overheadHistoryChart",
        "migrationLocalityChart",
    ] {
        assert!(html.contains(&format!("id=\"{id}\"")), "missing {id}");
    }
    assert!(html.contains("/assets/charts.js"));
    assert!(html.contains("/assets/feedback.js"));
    assert!(html.contains("/assets/reset.js"));
    assert!(html.contains("/assets/app.js"));
    assert!(
        html.find("id=\"migration-locality\"").unwrap()
            < html.find("id=\"probe-manifest\"").unwrap()
    );
}

#[tokio::test]
async fn shared_chart_library_is_served() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/assets/charts.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let javascript = std::str::from_utf8(&body).unwrap();
    assert!(javascript.contains("MitosisCharts"));
}

#[tokio::test]
async fn heatmap_styles_show_the_complete_vertical_canvas() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/assets/style.css")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let css = std::str::from_utf8(&body).unwrap();
    let heatmap = css
        .split(".heatmap-viewport {")
        .nth(1)
        .and_then(|rules| rules.split('}').next())
        .unwrap();
    assert!(heatmap.contains("overflow-x: auto"));
    assert!(heatmap.contains("overflow-y: visible"));
    assert!(!heatmap.contains("max-height"));
}

#[tokio::test]
async fn shared_feedback_library_is_served() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/assets/feedback.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let javascript = std::str::from_utf8(&body).unwrap();
    assert!(javascript.contains("data-feedback-toggle"));
}

#[tokio::test]
async fn shared_reset_library_is_served() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/assets/reset.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let javascript = std::str::from_utf8(&body).unwrap();
    assert!(javascript.contains("mitosis:stats-reset"));
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
    assert!(html.contains("data-feedback-key=\"Scheduler:Summary\""));
    assert!(html.contains("data-feedback-key=\"Scheduler:Cell-history\""));
    assert!(html.contains("id=\"resetAllStats\""));
    assert!(html.contains("/assets/feedback.js"));
    assert!(html.contains("/assets/reset.js"));
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
    assert!(html.contains("data-feedback-key=\"System:Summary\""));
    assert!(html.contains("data-feedback-key=\"System:Resource-history\""));
    assert!(html.contains("id=\"resetAllStats\""));
    assert!(html.contains("/assets/feedback.js"));
    assert!(html.contains("/assets/reset.js"));
    assert!(html.contains("/assets/system.js"));
}
