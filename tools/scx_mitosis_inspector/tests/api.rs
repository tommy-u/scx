use std::io::Read;
use std::sync::{mpsc, Arc, RwLock};

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use flate2::read::GzDecoder;
use http_body_util::BodyExt;
use scx_mitosis_inspector::api::{router, ApiContext};
use scx_mitosis_inspector::bpf_program_stats::BpfProgramStatsRow;
use scx_mitosis_inspector::collector::{CollectorCommand, ResetReceipt, Snapshot};
use scx_mitosis_inspector::host_context::{HostContextView, HostIdentityView};
use scx_mitosis_inspector::lifecycle::{unix_ms, CollectorStatus, ObserverContext, SampleMeta};
use scx_mitosis_inspector::migration_history::MigrationHistory;
use scx_mitosis_inspector::replay::{ReplayHistory, ReplaySources, REPLAY_RETENTION_MS};
use scx_mitosis_inspector::replay_migrations::ReplayMigrationHistory;
use scx_mitosis_inspector::scheduler_config::SchedulerConfigSnapshot;
use scx_mitosis_inspector::stats::StatsSnapshot;
use scx_mitosis_inspector::stats_history::{StatsHistory, STATS_HISTORY_RETENTION_MS};
use scx_mitosis_inspector::system_stats::SystemStatsCollector;
use scx_mitosis_inspector::topology::{CpuInfo, TopologyView};
use scx_mitosis_inspector::{
    CallbackCounter, CallbackTimingRow, CpuRuntimeRow, MigrationRow, ProbeManifestRow,
    TimingMetricRow,
};
use serde_json::json;
use tower::ServiceExt;

#[tokio::test]
async fn system_memory_chart_asset_is_served_without_stale_browser_caching() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/assets/memory_charts.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(std::str::from_utf8(&body)
        .unwrap()
        .contains("MitosisTimeline"));
}

#[tokio::test]
async fn system_memory_charts_have_total_and_per_llc_panels() {
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
    for id in [
        "memoryBandwidthTotalHistory",
        "memoryBandwidthLlcHistory",
        "memoryCacheAccessTotalHistory",
        "memoryCacheAccessLlcHistory",
        "memoryCacheMissTotalHistory",
        "memoryCacheMissLlcHistory",
        "memoryCacheMissPercentTotalHistory",
        "memoryCacheMissPercentLlcHistory",
    ] {
        assert!(html.contains(&format!("id=\"{id}\"")), "missing {id}");
    }
    assert!(html.contains("/assets/memory_charts.js"));
}

#[tokio::test]
async fn timeline_endpoint_is_available_even_before_the_first_retained_sample() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/api/timeline")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["retention_ms"], 1_800_000);
    assert_eq!(value["frames"], json!([]));
    assert_eq!(value["oldest_at_unix_ms"], serde_json::Value::Null);
    assert_eq!(value["latest_at_unix_ms"], serde_json::Value::Null);
}

#[tokio::test]
async fn timeline_window_limits_are_discoverable_before_any_retained_frames() {
    let (status, value) = replay_json(app(), "/api/timeline").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["frames"], json!([]));
    assert_eq!(value["window_ms"], 1_000);
    assert_eq!(value["default_window_ms"], 1_000);
    assert_eq!(value["max_window_ms"], 5_000);
}

#[tokio::test]
async fn timeline_window_request_uses_selected_window_and_keeps_configured_limits() {
    let (status, value) = replay_json(app(), "/api/timeline?window_ms=4000").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["window_ms"], 4_000);
    assert_eq!(value["default_window_ms"], 1_000);
    assert_eq!(value["max_window_ms"], 5_000);
}

#[tokio::test]
async fn timeline_window_error_advertises_valid_fallback_without_any_retained_frames() {
    let (status, value) = replay_json(app(), "/api/timeline?window_ms=300000").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(value["error"]
        .as_str()
        .is_some_and(|error| !error.is_empty()));
    assert_eq!(value["oldest_at_unix_ms"], serde_json::Value::Null);
    assert_eq!(value["latest_at_unix_ms"], serde_json::Value::Null);
    assert_eq!(value["default_window_ms"], 1_000);
    assert_eq!(value["max_window_ms"], 5_000);
}

#[tokio::test]
async fn timeline_window_discovery_preserves_legacy_positive_subsecond_cli_windows() {
    let (commands, _receiver) = mpsc::sync_channel(1);
    let app = router(ApiContext::new(
        Arc::new(RwLock::new(snapshot())),
        Arc::new(RwLock::new(stats_snapshot())),
        Arc::new(RwLock::new(SystemStatsCollector::new().collect())),
        HostContextView {
            identity: HostIdentityView {
                hostname: "subsecond-replay".into(),
                kernel_release: "6.12.0-scx".into(),
                cpu_count: 1,
            },
            topology: TopologyView::from_cpus(vec![CpuInfo {
                cpu: 0,
                node: 0,
                package: 0,
                llc: 0,
                core: 0,
                core_topology_available: true,
            }])
            .unwrap(),
        },
        Arc::new(RwLock::new(MigrationHistory::new(1_000))),
        500,
        commands,
        Arc::new(RwLock::new(active_observer())),
    ));
    let (status, value) = replay_json(app, "/api/timeline").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["window_ms"], 500);
    assert_eq!(value["default_window_ms"], 500);
    assert_eq!(value["max_window_ms"], 1_000);
}

type ReplayApiFixture = (
    axum::Router,
    Arc<RwLock<ReplayHistory>>,
    Arc<RwLock<ReplayMigrationHistory>>,
    mpsc::Receiver<CollectorCommand>,
    [u64; 3],
);

fn replay_api_fixture() -> ReplayApiFixture {
    let now = unix_ms();
    let times = [now - 3_000, now - 2_000, now - 1_000];
    let topology = TopologyView::from_cpus(
        [2, 7]
            .into_iter()
            .map(|cpu| CpuInfo {
                cpu,
                node: 0,
                package: 0,
                llc: 0,
                core: 0,
                core_topology_available: true,
            })
            .collect(),
    )
    .unwrap();
    let mut replay = ReplayHistory::new();
    let mut migrations = ReplayMigrationHistory::new(REPLAY_RETENTION_MS, 5_000, &topology);
    let mut current = active_observer();
    let mut latest_counters = snapshot();
    let mut latest_stats = stats_snapshot();
    let mut latest_system = SystemStatsCollector::new().collect();
    for (index, at) in times.into_iter().enumerate() {
        let epoch = if index < 2 { 1 } else { 2 };
        let seq = if index < 2 { index as u64 + 1 } else { 1 };
        current.epoch = epoch;
        current.scheduler_enable_seq = Some(7 + epoch);
        let meta = SampleMeta {
            epoch,
            sample_seq: seq,
            captured_at_unix_ms: Some(at),
            last_success_at_unix_ms: Some(at),
            error: None,
        };
        latest_counters.meta = meta.clone();
        latest_counters.collector = current.clone();
        latest_counters.counters[0].count = [42, 84, 11][index];
        latest_counters.migrations[0].count = [19, 29, 1_001][index];
        latest_stats.meta = meta.clone();
        latest_stats.collector = current.clone();
        latest_stats.metrics.as_mut().unwrap()["rebalance_count"] = json!(seq);
        latest_system.meta = meta;
        latest_system.collector = current.clone();
        latest_system.captured_at_unix_ms = at;
        migrations.ingest(at, &latest_counters);
        replay
            .record(
                at,
                &current,
                ReplaySources {
                    counters: latest_counters.compact_clone_without_migrations(),
                    stats: latest_stats.clone(),
                    system: latest_system.clone(),
                    config: SchedulerConfigSnapshot::default(),
                },
            )
            .unwrap();
    }
    let replay = Arc::new(RwLock::new(replay));
    let migrations = Arc::new(RwLock::new(migrations));
    let (commands, receiver) = mpsc::sync_channel(4);
    let context = ApiContext::new(
        Arc::new(RwLock::new(latest_counters)),
        Arc::new(RwLock::new(latest_stats)),
        Arc::new(RwLock::new(latest_system)),
        HostContextView {
            identity: HostIdentityView {
                hostname: "replay-vm".into(),
                kernel_release: "6.12.0-scx".into(),
                cpu_count: 2,
            },
            topology,
        },
        Arc::new(RwLock::new(MigrationHistory::new(5_000))),
        1_000,
        commands,
        Arc::new(RwLock::new(current)),
    )
    .with_replay_state(replay.clone(), migrations.clone());
    (router(context), replay, migrations, receiver, times)
}

async fn replay_json(app: axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let response = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn timeline_light_frames_preserve_source_clocks_and_epochs_without_full_snapshots() {
    let (app, _history, _migrations, _commands, times) = replay_api_fixture();
    let (status, timeline) = replay_json(app.clone(), "/api/timeline?window_ms=1000").await;
    assert_eq!(status, StatusCode::OK);
    let frames = timeline["frames"].as_array().unwrap();
    assert_eq!(frames.len(), 3);
    assert_eq!(
        frames[0]["source_meta"]["counters"]["captured_at_unix_ms"],
        times[0]
    );
    assert_eq!(frames[0]["source_available"]["stats"], true);
    assert_eq!(frames[0]["epochs"]["counters"], 1);
    assert_eq!(frames[2]["epochs"]["counters"], 2);
    assert!(frames.iter().all(|frame| frame.get("sources").is_none()));
    assert_eq!(frames[1]["signals"]["migration.same_core"], 100.0);
    assert_eq!(frames[1]["signals"]["migration.cross_numa"], 0.0);
    assert_eq!(timeline["oldest_at_unix_ms"], times[0]);
    assert_eq!(timeline["latest_at_unix_ms"], times[2]);
    let instance = timeline["instance_id"].as_str().unwrap();
    let (_, update) = replay_json(
        app.clone(),
        &format!("/api/timeline?instance_id={instance}&after_seq=2&window_ms=1000"),
    )
    .await;
    assert_eq!(update["reset"], false);
    assert_eq!(update["frames"].as_array().unwrap().len(), 1);
    assert_eq!(update["frames"][0]["seq"], 3);
    let (_, replaced) = replay_json(app, "/api/timeline?instance_id=old-process&after_seq=2").await;
    assert_eq!(replaced["reset"], true);
    assert_eq!(replaced["frames"].as_array().unwrap().len(), 3);
}

#[tokio::test]
async fn timeline_view_floors_time_and_returns_historical_histograms_owners_and_migration_window() {
    let (app, _history, _migrations, _commands, times) = replay_api_fixture();
    let (status, view) = replay_json(
        app.clone(),
        &format!(
            "/api/timeline/view?at_unix_ms={}&window_ms=1000",
            times[0] + 999
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(view["at_unix_ms"], times[0]);
    assert_eq!(view["collector"]["epoch"], 1);
    assert_eq!(view["sources"]["counters"]["counters"][0]["count"], 42);
    assert_eq!(
        view["sources"]["counters"]["scheduler_timings"][0]["buckets"]
            .as_array()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(view["sources"]["stats"]["cpu_cells"], json!({"0": 0}));
    assert_eq!(view["sources"]["counters"]["migrations"], json!([]));
    let (_, migrated) = replay_json(
        app.clone(),
        &format!("/api/timeline/view?at_unix_ms={}&window_ms=1000", times[1]),
    )
    .await;
    assert_eq!(migrated["migrations"]["total"], 10);
    assert_eq!(migrated["migrations"]["observed_ms"], 1_000);
    let (_, latest) = replay_json(app, "/api/timeline/view").await;
    assert_eq!(latest["at_unix_ms"], times[2]);
    assert_eq!(latest["collector"]["epoch"], 2);
    assert_eq!(latest["sources"]["counters"]["counters"][0]["count"], 11);
}

#[tokio::test]
async fn timeline_heatmap_window_ends_at_selected_frame_even_when_counter_capture_is_older() {
    let (app, history, _migrations, _commands, times) = replay_api_fixture();
    let mut context = active_observer();
    context.scheduler_enable_seq = Some(8);
    let mut counters = snapshot();
    counters.meta = SampleMeta {
        epoch: 1,
        sample_seq: 2,
        captured_at_unix_ms: Some(times[1]),
        last_success_at_unix_ms: Some(times[1]),
        error: None,
    };
    counters.collector = context.clone();
    let mut stats = stats_snapshot();
    stats.meta = counters.meta.clone();
    stats.collector = context.clone();
    let mut system = SystemStatsCollector::new().collect();
    system.meta = counters.meta.clone();
    system.collector = context.clone();
    system.captured_at_unix_ms = times[1];
    {
        let mut retained = history.write().unwrap();
        retained.clear();
        retained
            .record(
                times[2],
                &context,
                ReplaySources {
                    counters: counters.compact_clone_without_migrations(),
                    stats,
                    system,
                    config: SchedulerConfigSnapshot::default(),
                },
            )
            .unwrap();
    }
    // The retained epoch-1 delta ends exactly at the selected window's
    // beginning. The later epoch-2 sample must not contribute either.
    let (status, view) = replay_json(
        app.clone(),
        &format!("/api/timeline/view?at_unix_ms={}&window_ms=1000", times[2]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(view["at_unix_ms"], times[2]);
    assert_eq!(view["migrations"]["total"], 0);
    assert_eq!(view["migrations"]["observed_ms"], 0);
    assert_eq!(view["migrations"]["migration_quality"], "unavailable");
    assert_eq!(view["migrations"]["meta"]["epoch"], 1);
    assert_eq!(view["migrations"]["meta"]["captured_at_unix_ms"], times[1]);
    // The locality graph's point still belongs to the original counter
    // measurement, where that same delta was inside its one-second window.
    let (_, timeline) = replay_json(app, "/api/timeline?window_ms=1000").await;
    assert_eq!(
        timeline["frames"][0]["source_meta"]["counters"]["captured_at_unix_ms"],
        times[1]
    );
    assert_eq!(
        timeline["frames"][0]["signals"]["migration.same_core"],
        100.0
    );
}

#[tokio::test]
async fn timeline_heatmap_reports_complete_measured_coverage_with_an_older_counter_capture() {
    let (app, history, _migrations, _commands, times) = replay_api_fixture();
    let mut context = active_observer();
    context.scheduler_enable_seq = Some(8);
    let mut counters = snapshot();
    counters.meta = SampleMeta {
        epoch: 1,
        sample_seq: 2,
        captured_at_unix_ms: Some(times[1]),
        last_success_at_unix_ms: Some(times[1]),
        error: None,
    };
    counters.collector = context.clone();
    let mut stats = stats_snapshot();
    stats.meta = counters.meta.clone();
    stats.collector = context.clone();
    let mut system = SystemStatsCollector::new().collect();
    system.meta = counters.meta.clone();
    system.collector = context.clone();
    system.captured_at_unix_ms = times[1];
    let frame_at = times[1] + 190;
    {
        let mut retained = history.write().unwrap();
        retained.clear();
        retained
            .record(
                frame_at,
                &context,
                ReplaySources {
                    counters: counters.compact_clone_without_migrations(),
                    stats,
                    system,
                    config: SchedulerConfigSnapshot::default(),
                },
            )
            .unwrap();
    }

    let (status, view) = replay_json(
        app,
        &format!("/api/timeline/view?at_unix_ms={frame_at}&window_ms=1000"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(view["at_unix_ms"], frame_at);
    assert_eq!(view["migrations"]["meta"]["captured_at_unix_ms"], times[1]);
    assert_eq!(view["migrations"]["window_ms"], 1_000);
    assert_eq!(view["migrations"]["observed_ms"], 810);
    assert_eq!(view["migrations"]["total"], 10);
    assert_eq!(view["migrations"]["migration_quality"], "complete");
}

#[tokio::test]
async fn timeline_heatmap_keeps_a_known_missing_counter_interval_incomplete() {
    let (app, history, _migrations, _commands, times) = replay_api_fixture();
    let mut context = active_observer();
    context.scheduler_enable_seq = Some(8);
    let captured_at = times[1] + 500;
    let frame_at = times[1] + 700;
    let mut counters = snapshot();
    counters.collector = context.clone();
    counters.meta = SampleMeta {
        epoch: 1,
        sample_seq: 3,
        captured_at_unix_ms: Some(captured_at),
        last_success_at_unix_ms: Some(captured_at),
        error: None,
    };
    {
        let mut retained = history.write().unwrap();
        retained.clear();
        // A counter capture was retained in the frame, but its migration
        // interval was not ingested. An older bin cannot fill that known gap.
        retained
            .record(
                frame_at,
                &context,
                ReplaySources {
                    counters: counters.compact_clone_without_migrations(),
                    stats: StatsSnapshot::default(),
                    system: SystemStatsCollector::new().collect(),
                    config: SchedulerConfigSnapshot::default(),
                },
            )
            .unwrap();
    }

    let (status, view) = replay_json(
        app,
        &format!("/api/timeline/view?at_unix_ms={frame_at}&window_ms=1000"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        view["sources"]["counters"]["meta"]["captured_at_unix_ms"],
        captured_at
    );
    assert_eq!(view["migrations"]["meta"]["captured_at_unix_ms"], times[1]);
    assert_eq!(view["migrations"]["observed_ms"], 300);
    assert_eq!(view["migrations"]["total"], 10);
    assert_eq!(view["migrations"]["migration_quality"], "incomplete");
}

#[tokio::test]
async fn timeline_errors_include_available_bounds_for_expired_time_or_invalid_cursor_and_window() {
    let (app, _history, _migrations, _commands, times) = replay_api_fixture();
    for uri in [
        format!("/api/timeline/view?at_unix_ms={}", times[0] - 1),
        "/api/timeline?instance_id=partial-cursor".into(),
        "/api/timeline?after_seq=1".into(),
        "/api/timeline?window_ms=0".into(),
        "/api/timeline?window_ms=5001".into(),
        "/api/timeline/view?window_ms=5001".into(),
    ] {
        let (status, error) = replay_json(app.clone(), &uri).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
        assert!(
            error["error"]
                .as_str()
                .is_some_and(|error| !error.is_empty()),
            "{uri}"
        );
        assert_eq!(error["oldest_at_unix_ms"], times[0], "{uri}");
        assert_eq!(error["latest_at_unix_ms"], times[2], "{uri}");
    }
}

#[tokio::test]
async fn successful_explicit_reset_clears_replay_but_failed_reset_preserves_it() {
    let (app, history, migrations, receiver, times) = replay_api_fixture();
    std::thread::spawn(move || {
        for reply in [
            Err("reset failed".into()),
            Ok(ResetReceipt {
                epoch: 3,
                sample_seq: 1,
                reset_at_unix_ms: unix_ms(),
            }),
        ] {
            if let Ok(CollectorCommand::Reset(request)) = receiver.recv() {
                request.reply.send(reply).unwrap();
            }
        }
    });
    let post = || {
        Request::builder()
            .method("POST")
            .uri("/api/reset")
            .body(Body::empty())
            .unwrap()
    };
    let failed = app.clone().oneshot(post()).await.unwrap();
    assert_eq!(failed.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(history.write().unwrap().view(None, unix_ms()).is_ok());
    assert_eq!(
        migrations
            .read()
            .unwrap()
            .view_at(times[1], 1, 1_000)
            .unwrap()
            .total,
        10
    );
    let success = app.clone().oneshot(post()).await.unwrap();
    assert_eq!(success.status(), StatusCode::OK);
    let (_, timeline) = replay_json(app.clone(), "/api/timeline").await;
    assert_eq!(timeline["frames"], json!([]));
    assert_eq!(timeline["oldest_at_unix_ms"], serde_json::Value::Null);
    assert_eq!(
        migrations
            .read()
            .unwrap()
            .view_at(times[1], 1, 1_000)
            .unwrap()
            .migration_quality,
        "unavailable"
    );
    assert_eq!(
        replay_json(app, "/api/timeline/view").await.0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn browser_guide_has_shared_timeline_and_raw_ai_guide_remains_machine_readable() {
    let (app, _history, _migrations, _commands, _times) = replay_api_fixture();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/guide")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&bytes).unwrap();
    assert!(html.contains("id=\"timelineRange\""));
    assert!(html.contains("/assets/timeline.js"));
    assert!(!html.contains("{{AI_GUIDE_CONTENT}}"));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/ai-guide")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let raw = std::str::from_utf8(&bytes).unwrap();
    assert!(!raw.contains("<!doctype html>"));
    assert!(raw.contains("/api/stats"));
}

fn snapshot() -> Snapshot {
    Snapshot {
        meta: SampleMeta {
            epoch: 1,
            sample_seq: 7,
            captured_at_unix_ms: Some(100),
            last_success_at_unix_ms: Some(100),
            error: None,
        },
        collector: active_observer(),
        migration_map_capacity: 256,
        migration_map_failures: 0,
        migration_quality: "complete",
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
        meta: SampleMeta {
            epoch: 1,
            sample_seq: 3,
            captured_at_unix_ms: Some(100),
            last_success_at_unix_ms: Some(100),
            error: None,
        },
        collector: active_observer(),
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
        cpu_cells: Some(std::collections::BTreeMap::from([(0, 0)])),
        cpu_cells_error: None,
    }
}

fn active_observer() -> ObserverContext {
    ObserverContext {
        epoch: 1,
        status: CollectorStatus::Active,
        scheduler_enable_seq: Some(7),
        scheduler_name: Some("mitosis_1.1.3_x86_64_unknown_linux_gnu".into()),
        error: None,
    }
}

#[tokio::test]
async fn stats_include_observed_cpu_ownership_separately_from_scheduler_metrics() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/api/stats")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["cpu_cells"], json!({"0": 0}));
    assert_eq!(value["cpu_cells_error"], serde_json::Value::Null);
    assert_eq!(value["metrics"]["cells"]["0"]["num_cpus"], 16);
}

fn app() -> axum::Router {
    let (app, commands) = app_with_commands(active_observer());
    std::thread::spawn(move || {
        if let Ok(CollectorCommand::Reset(request)) = commands.recv() {
            request
                .reply
                .send(Ok(ResetReceipt {
                    epoch: 2,
                    sample_seq: 1,
                    reset_at_unix_ms: 200,
                }))
                .unwrap();
        }
    });
    app
}

fn app_with_commands(
    observer: ObserverContext,
) -> (axum::Router, mpsc::Receiver<CollectorCommand>) {
    app_with_capacity(observer, 1)
}

fn app_with_capacity(
    observer: ObserverContext,
    capacity: usize,
) -> (axum::Router, mpsc::Receiver<CollectorCommand>) {
    app_with_capacity_and_counters(observer, capacity, Arc::new(RwLock::new(snapshot())))
}

fn app_with_capacity_and_counters(
    observer: ObserverContext,
    capacity: usize,
    counters: Arc<RwLock<Snapshot>>,
) -> (axum::Router, mpsc::Receiver<CollectorCommand>) {
    let (commands, commands_rx) = mpsc::sync_channel(capacity);
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
    let app = router(ApiContext::new(
        counters,
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
                core_topology_available: true,
            }])
            .unwrap(),
        },
        Arc::new(RwLock::new(migration_history)),
        1_000,
        commands,
        Arc::new(RwLock::new(observer)),
    ));
    (app, commands_rx)
}

#[tokio::test]
async fn compact_counters_omit_only_response_migrations_and_preserve_the_default() {
    let stored = Arc::new(RwLock::new(snapshot()));
    let expected = serde_json::to_value(&*stored.read().unwrap()).unwrap();
    let (router, _commands) = app_with_capacity_and_counters(active_observer(), 1, stored.clone());
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/counters?include_migrations=false")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let compact: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let mut expected_compact = expected.clone();
    expected_compact["migrations"] = json!([]);
    assert_eq!(compact, expected_compact);
    assert_eq!(
        serde_json::to_value(&*stored.read().unwrap()).unwrap(),
        expected
    );

    for uri in ["/api/counters", "/api/counters?include_migrations=true"] {
        let response = router
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value, expected);
    }
}

#[tokio::test]
async fn json_apis_negotiate_gzip_without_changing_their_decoded_body() {
    let (router, _commands) = app_with_commands(active_observer());
    for uri in [
        "/api/counters",
        "/api/migrations?window_ms=300",
        "/api/stats",
        "/api/system",
    ] {
        let plain = router
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(plain.status(), StatusCode::OK);
        assert!(plain.headers().get(header::CONTENT_ENCODING).is_none());
        let plain = plain.into_body().collect().await.unwrap().to_bytes();
        let expected: serde_json::Value = serde_json::from_slice(&plain).unwrap();

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header(header::ACCEPT_ENCODING, "gzip")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_ENCODING).unwrap(),
            "gzip",
            "{uri}"
        );
        assert!(response
            .headers()
            .get_all(header::VARY)
            .iter()
            .any(|value| value
                .to_str()
                .unwrap()
                .to_ascii_lowercase()
                .contains("accept-encoding")));
        let compressed = response.into_body().collect().await.unwrap().to_bytes();
        let mut decoded = Vec::new();
        GzDecoder::new(compressed.as_ref())
            .read_to_end(&mut decoded)
            .unwrap();
        let actual: serde_json::Value = serde_json::from_slice(&decoded).unwrap();
        assert_eq!(actual, expected, "{uri}");
    }
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
    assert!(
        value["meta"]["sample_seq"].is_u64(),
        "snapshot must identify its collected sample"
    );
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
async fn reset_endpoint_acknowledges_a_completed_inspector_epoch() {
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

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["scope"], "inspector");
    assert!(
        value["epoch"].is_u64(),
        "reset acknowledgement must identify its completed epoch"
    );
    assert!(value["sample_seq"].is_u64());
}

async fn page_html(path: &str) -> String {
    let response = app()
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK, "{path}");
    let body = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(body.to_vec()).unwrap()
}

fn assert_ids(html: &str, page: &str, ids: &[&str]) {
    for id in ids {
        assert!(
            html.contains(&format!("id=\"{id}\"")),
            "{page} is missing {id}"
        );
    }
}

fn assert_section_order(html: &str, page: &str, ids: &[&str]) {
    let positions: Vec<usize> = ids
        .iter()
        .map(|id| {
            html.find(&format!("id=\"{id}\""))
                .unwrap_or_else(|| panic!("{page} is missing section {id}"))
        })
        .collect();
    assert!(
        positions.windows(2).all(|pair| pair[0] < pair[1]),
        "{page} sections are out of order: {ids:?}"
    );
}

#[tokio::test]
async fn callbacks_page_covers_only_callback_cost() {
    let html = page_html("/callbacks").await;
    assert!(html.contains("<h2>Callbacks</h2>"));
    assert!(html.contains("class=\"workspace-sidebar\""));
    assert!(html.contains("aria-current=\"page\" href=\"/callbacks\">Callbacks"));
    assert!(html.contains("id=\"sectionNavigation\""));
    assert_ids(
        &html,
        "/callbacks",
        &[
            "resetAllStats",
            "resetStatsStatus",
            "callbackTimingSampleRate",
            "callbackTimingRows",
        ],
    );
    assert_section_order(
        &html,
        "/callbacks",
        &[
            "counterGrid",
            "callback-rate",
            "callback-latency",
            "callback-cost",
            "bpf-runtime",
        ],
    );
    assert_ids(
        &html,
        "/callbacks",
        &[
            "live-history",
            "callbackRateHistoryChart",
            "callbackLatencyChart",
            "callbackCostChart",
            "bpfProgramRows",
        ],
    );
    let callback_rate = html.split("id=\"callback-rate\"").nth(1).unwrap();
    let callback_rate = callback_rate.split("</section>").next().unwrap();
    assert!(
        callback_rate.contains("id=\"live-history\""),
        "the legacy history bookmark must target the callback-rate section"
    );
    assert!(html.contains("href=\"#callback-rate\""));
    // Sections that answer other questions live on the page for that question.
    for id in [
        "schedulerTimingRows",
        "migrationRows",
        "dsqMetricRows",
        "schedulerEventRows",
        "softirqRows",
        "blockIoRows",
        "probeManifestRows",
        "downloadSnapshot",
    ] {
        assert!(
            !html.contains(&format!("id=\"{id}\"")),
            "{id} belongs on another page"
        );
    }
    for script in [
        "charts.js",
        "sections.js",
        "feedback.js",
        "reset.js",
        "callbacks.js",
    ] {
        assert!(
            html.contains(&format!("/assets/{script}")),
            "missing {script}"
        );
    }
    assert!(!html.contains("/assets/heatmap.js"));
}

#[tokio::test]
async fn scheduling_page_groups_latency_queues_migration_and_sched_ext() {
    let html = page_html("/scheduling").await;
    assert!(html.contains("<h2>Scheduling</h2>"));
    assert!(html.contains("aria-current=\"page\" href=\"/scheduling\">Scheduling"));
    assert_section_order(
        &html,
        "/scheduling",
        &[
            "migration-locality",
            "scheduler-latency",
            "exploreTasks",
            "exploreWakers",
            "dsq-performance",
            "exploreDsqs",
            "scheduler-activity",
            "sched-ext",
            "exploreScxEvents",
        ],
    );
    assert_ids(
        &html,
        "/scheduling",
        &[
            "eventTimingSampleRate",
            "schedulerTimingRows",
            "schedulerLatencyChart",
            "latencyHistoryChart",
            "dsqMetricRows",
            "dsqResidenceChart",
            "dsqDepthHistoryChart",
            "migrationWindow",
            "migrationWindowCoverage",
            "migrationRows",
            "migrationLocalityChart",
            "schedulerEventRows",
            "schedExtRows",
        ],
    );
    for asset in [
        "/assets/heatmap.js",
        "/assets/sections.js",
        "/assets/scheduling.js",
        "/assets/explore.js",
        "/assets/explore.css",
    ] {
        assert!(html.contains(asset), "missing {asset}");
    }
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
async fn dark_mode_controls_and_theme_script_are_shared() {
    for path in [
        "/",
        "/stats",
        "/scheduling",
        "/callbacks",
        "/system",
        "/config",
        "/inspector",
        "/guide",
    ] {
        let response = app()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            html.contains("data-theme-toggle"),
            "missing theme toggle on {path}"
        );
        assert!(
            html.contains("role=\"switch\""),
            "theme control is not a switch on {path}"
        );
        assert!(
            html.contains("/assets/theme.js"),
            "missing theme script on {path}"
        );
        assert!(
            html.find("/assets/theme.js").unwrap() < html.find("/assets/style.css").unwrap(),
            "theme must initialize before the stylesheet on {path}",
        );
    }

    let response = app()
        .oneshot(
            Request::builder()
                .uri("/assets/theme.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let javascript = std::str::from_utf8(&body).unwrap();
    assert!(javascript.contains("prefers-color-scheme: dark"));
    assert!(javascript.contains("localStorage"));
    assert!(javascript.contains("mitosis-theme-change"));
}

#[tokio::test]
async fn scheduler_configuration_is_a_distinct_read_only_page() {
    let page = app()
        .oneshot(
            Request::builder()
                .uri("/config")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    let body = page.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(html.contains("aria-current=\"page\" href=\"/config\""));
    assert!(html.contains("id=\"configurationRows\""));
    assert!(html.contains("id=\"configurationSearch\""));
    assert!(html.contains("name=\"configurationState\""));
    assert!(html.contains("/assets/config.js"));
    assert!(!html.contains("type=\"submit\""));

    let api = app()
        .oneshot(
            Request::builder()
                .uri("/api/config")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(api.status(), StatusCode::OK);
    let body = api.into_body().collect().await.unwrap().to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(value.get("available").is_some());
    assert!(value.get("options").is_some());

    let script = app()
        .oneshot(
            Request::builder()
                .uri("/assets/config.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(script.status(), StatusCode::OK);
}

#[tokio::test]
async fn inspector_page_reports_collection_health_and_cost() {
    let html = page_html("/inspector").await;
    assert!(html.contains("<h2>Inspector</h2>"));
    assert!(html.contains("aria-current=\"page\" href=\"/inspector\">Inspector"));
    assert!(html.contains(">Reference</span>"));
    assert!(html.contains("data-theme-toggle"));
    assert_ids(
        &html,
        "/inspector",
        &[
            "downloadSnapshot",
            "hostname",
            "kernelRelease",
            "cpuCount",
            "resetAllStats",
        ],
    );
    let summary = html
        .split("<section class=\"summary\"")
        .nth(1)
        .and_then(|section| section.split("</section>").next())
        .unwrap();
    assert!(summary.contains("id=\"systemCpuUtilization\""));
    assert!(summary.contains("id=\"mitosisCpuUtilization\""));
    assert_section_order(
        &html,
        "/inspector",
        &["sources", "probe-manifest", "inspector-overhead"],
    );
    assert_ids(
        &html,
        "/inspector",
        &[
            "sourceRows",
            "probeManifestRows",
            "overheadHistoryChart",
            "inspectorBpfProgramRows",
        ],
    );
    assert!(html.contains("/assets/inspector.js"));
    assert!(!html.contains("/assets/heatmap.js"));
}

#[tokio::test]
async fn retired_pages_redirect_to_their_new_homes() {
    for (path, target) in [("/explore", "/scheduling"), ("/appendix", "/inspector")] {
        let response = app()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT, "{path}");
        assert_eq!(response.headers()[header::LOCATION], target, "{path}");
    }
    for path in [
        "/mockups/cpuset-alternatives",
        "/mockups/hyperthreads",
        "/assets/app.js",
    ] {
        let response = app()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
    }
}

#[tokio::test]
async fn inspector_script_renders_system_and_mitosis_utilization() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/assets/inspector.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let javascript = std::str::from_utf8(&body).unwrap();
    assert!(javascript.contains("systemCpuUtilization"));
    assert!(javascript.contains("mitosisCpuUtilization"));
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
async fn mobile_workspace_navigation_keeps_reference_links_visible() {
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
    let mobile = css.split("@media (max-width: 720px) {").nth(1).unwrap();
    let navigation = mobile
        .split(".workspace-navigation {")
        .nth(1)
        .and_then(|rules| rules.split('}').next())
        .unwrap();
    assert!(navigation.contains("flex-wrap: wrap"));
    assert!(navigation.contains("overflow-x: visible"));
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
    assert_eq!(
        value["topology"]["cpus"][0]["core_topology_available"],
        true
    );
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
async fn stats_history_endpoint_returns_server_retention_and_collector_metadata() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/api/stats/history")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["retention_ms"], 1_800_000);
    assert!(value["instance_id"]
        .as_str()
        .is_some_and(|id| !id.is_empty()));
    assert_eq!(value["meta"]["epoch"], 1);
    assert_eq!(value["collector"]["status"], "active");
    assert_eq!(value["reset"], true);
    assert!(value["samples"].is_array());
}

#[tokio::test]
async fn cells_is_the_landing_page_with_a_stats_alias() {
    let response = app()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let html = std::str::from_utf8(&body).unwrap();
    assert!(html.contains("<h2>Cells</h2>"));
    assert!(html.contains("class=\"workspace-sidebar\""));
    assert!(html.contains("aria-current=\"page\" href=\"/\">Cells"));
    assert!(html.contains("data-feedback-key=\"Cells:Summary\""));
    assert!(html.contains("data-feedback-key=\"Cells:Cell-history\""));
    assert!(html.contains("id=\"resetAllStats\""));
    assert!(html.contains("/assets/feedback.js"));
    assert!(html.contains("/assets/reset.js"));
    assert!(html.contains("/assets/stats.js"));

    let alias = app()
        .oneshot(
            Request::builder()
                .uri("/stats")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(alias.status(), StatusCode::OK);
    assert_eq!(alias.into_body().collect().await.unwrap().to_bytes(), body);
}

#[tokio::test]
async fn workspace_navigation_is_shared_by_every_page() {
    let links = [
        ("/scheduling", "Scheduling"),
        ("/", "Cells"),
        ("/callbacks", "Callbacks"),
        ("/system", "System"),
        ("/config", "Configuration"),
        ("/inspector", "Inspector"),
        ("/guide", "AI guide"),
    ];
    for (path, active) in [
        ("/", "/"),
        ("/stats", "/"),
        ("/scheduling", "/scheduling"),
        ("/callbacks", "/callbacks"),
        ("/system", "/system"),
        ("/config", "/config"),
        ("/inspector", "/inspector"),
        ("/guide", "/guide"),
    ] {
        let response = app()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(
            response.headers()[header::CACHE_CONTROL],
            "no-store",
            "{path}"
        );
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(!html.contains("<!-- workspace-navigation -->"), "{path}");
        let navigation = html
            .split("aria-label=\"Inspector workspaces\">")
            .nth(1)
            .and_then(|rest| rest.split("</nav>").next())
            .unwrap();
        let mut position = 0;
        for (href, label) in links {
            let current = if href == active {
                " class=\"active\" aria-current=\"page\""
            } else {
                ""
            };
            let link = format!("<a{current} href=\"{href}\">{label}</a>");
            let found = navigation[position..]
                .find(&link)
                .unwrap_or_else(|| panic!("{path}: {link} is missing or out of order"));
            position += found + link.len();
        }
        assert_eq!(navigation.matches("aria-current").count(), 1, "{path}");
        let reference = navigation.find(">Reference</span>").unwrap();
        assert!(
            navigation.find(">Observe</span>").unwrap() < navigation.find(">Cells</a>").unwrap()
        );
        assert!(navigation.find(">Configuration</a>").unwrap() < reference);
        assert!(reference < navigation.find(">Inspector</a>").unwrap());
        assert!(!navigation.contains("/explore") && !navigation.contains("/appendix"));
    }
}

#[tokio::test]
async fn system_page_groups_host_interference() {
    let html = page_html("/system").await;
    assert!(html.contains("<h2>System</h2>"));
    assert!(html.contains("aria-current=\"page\" href=\"/system\">System"));
    assert!(html.contains("data-feedback-key=\"System:Summary\""));
    assert!(html.contains("data-feedback-key=\"System:CPU\""));
    assert_section_order(
        &html,
        "/system",
        &[
            "system-cpu",
            "interrupts",
            "softirq-activity",
            "hardirq-activity",
            "exploreIpis",
            "block-io",
            "memory",
            "systemMemoryHistory",
            "explorePerf",
            "exploreBandwidth",
            "exploreIdle",
            "exploreHardware",
            "pressure",
            "network",
        ],
    );
    assert_ids(
        &html,
        "/system",
        &[
            "resetAllStats",
            "cpuHistoryChart",
            "frequencyHistory",
            "irqHistory",
            "softirqRows",
            "hardirqRows",
            "blockIoRows",
            "blockRateHistory",
            "blockThroughputHistory",
            "pressureRows",
            "networkRows",
        ],
    );
    // Scheduler health moved to Scheduling; resource history split by subsystem.
    assert!(!html.contains("id=\"schedExtRows\""));
    assert!(!html.contains("id=\"resourceHistory\""));
    for asset in [
        "/assets/feedback.js",
        "/assets/reset.js",
        "/assets/sections.js",
        "/assets/system.js",
        "/assets/memory_charts.js",
        "/assets/explore.js",
        "/assets/explore.css",
    ] {
        assert!(html.contains(asset), "missing {asset}");
    }
}

fn reset_request() -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/api/reset")
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn reset_waits_for_the_collector_and_reports_its_failure() {
    let (app, commands) = app_with_commands(active_observer());
    let response = tokio::spawn(app.oneshot(reset_request()));
    let command = tokio::task::spawn_blocking(move || commands.recv().unwrap())
        .await
        .unwrap();
    assert!(
        !response.is_finished(),
        "reset acknowledged before the observer completed it"
    );
    let CollectorCommand::Reset(request) = command else {
        panic!("expected reset")
    };
    assert_eq!(request.expected_epoch, 1);
    request
        .reply
        .send(Err("reattachment failed".into()))
        .unwrap();
    let response = response.await.unwrap().unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"], "reattachment failed");
    assert!(value.get("epoch").is_none());
}

#[tokio::test]
async fn reset_rejects_an_unavailable_observer_without_enqueuing_work() {
    let (app, commands) = app_with_commands(ObserverContext::default());
    assert_eq!(
        app.oneshot(reset_request()).await.unwrap().status(),
        StatusCode::CONFLICT
    );
    assert!(!matches!(commands.try_recv(), Ok(_)));
}

#[tokio::test]
async fn reset_reports_a_stopped_collector_without_success() {
    let (app, commands) = app_with_commands(active_observer());
    drop(commands);
    assert_eq!(
        app.oneshot(reset_request()).await.unwrap().status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[tokio::test]
async fn polling_asset_is_served_as_uncached_javascript() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/assets/polling.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(
        response.headers()["content-type"],
        "application/javascript; charset=utf-8"
    );
}

#[tokio::test]
async fn reset_reports_a_full_command_queue_and_preserves_the_snapshot() {
    let (app, commands) = app_with_capacity(active_observer(), 0);
    let response = app.clone().oneshot(reset_request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(commands.try_recv().is_err());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/counters")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["meta"]["epoch"], 1);
    assert_eq!(value["counters"][0]["count"], 42);
}

fn history_sample(seq: u64, at_ms: u64) -> StatsSnapshot {
    let mut snapshot = stats_snapshot();
    snapshot.meta.sample_seq = seq;
    snapshot.meta.captured_at_unix_ms = Some(at_ms);
    snapshot.meta.last_success_at_unix_ms = Some(at_ms);
    snapshot.metrics.as_mut().unwrap()["cells"]["0"]["num_cpus"] = json!(16 + seq);
    snapshot
}

fn retained_stats_history() -> Arc<RwLock<StatsHistory>> {
    let mut history = StatsHistory::new();
    let now_ms = unix_ms();
    for seq in 1..=3 {
        let at_ms = now_ms - (3 - seq) * 1_000;
        history.record(&history_sample(seq, at_ms), at_ms);
    }
    Arc::new(RwLock::new(history))
}

fn app_with_stats_history(
    history: Arc<RwLock<StatsHistory>>,
    observer: Arc<RwLock<ObserverContext>>,
) -> axum::Router {
    let (commands, _receiver) = mpsc::sync_channel(1);
    router(
        ApiContext::new(
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
                    core_topology_available: true,
                }])
                .unwrap(),
            },
            Arc::new(RwLock::new(MigrationHistory::new(5_000))),
            1_000,
            commands,
            observer,
        )
        .with_stats_history(history),
    )
}

async fn history_response(app: axum::Router, uri: &str) -> serde_json::Value {
    let response = app
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
async fn stats_history_api_backfills_compact_original_samples_in_collection_order() {
    let app = app_with_stats_history(
        retained_stats_history(),
        Arc::new(RwLock::new(active_observer())),
    );
    let value = history_response(app.clone(), "/api/stats/history").await;
    assert_eq!(value.as_object().unwrap().len(), 6);
    assert_eq!(value["retention_ms"], 1_800_000);
    assert_eq!(value["reset"], true);
    assert_eq!(value["meta"]["sample_seq"], 3);
    let samples = value["samples"].as_array().unwrap();
    assert_eq!(samples.len(), 3);
    for (index, sample) in samples.iter().enumerate() {
        assert_eq!(sample.as_object().unwrap().len(), 2);
        assert_eq!(sample["meta"]["epoch"], 1);
        assert_eq!(sample["meta"]["sample_seq"], index as u64 + 1);
        assert!(sample["meta"]["error"].is_null());
        assert_eq!(
            sample["cells"]["0"],
            json!({
                "num_cpus": 17 + index,
                "util_pct": 63.5,
                "smoothed_util_pct": 61.0
            })
        );
        if index > 0 {
            assert!(
                sample["meta"]["captured_at_unix_ms"].as_u64().unwrap()
                    > samples[index - 1]["meta"]["captured_at_unix_ms"]
                        .as_u64()
                        .unwrap()
            );
        }
    }
    let latest = history_response(app, "/api/stats").await;
    assert!(latest.get("samples").is_none());
    assert_eq!(latest["metrics"]["slice_shrink"], 14);
}

#[tokio::test]
async fn stats_history_api_cursor_fetches_missed_samples_and_can_return_no_new_samples() {
    let app = app_with_stats_history(
        retained_stats_history(),
        Arc::new(RwLock::new(active_observer())),
    );
    let full = history_response(app.clone(), "/api/stats/history").await;
    let instance_id = full["instance_id"].as_str().unwrap();
    let after_one = history_response(
        app.clone(),
        &format!("/api/stats/history?instance_id={instance_id}&epoch=1&after_seq=1"),
    )
    .await;
    assert_eq!(after_one["reset"], false);
    assert_eq!(after_one["samples"].as_array().unwrap().len(), 2);
    assert_eq!(after_one["samples"][0]["meta"]["sample_seq"], 2);
    assert_eq!(after_one["samples"][1]["meta"]["sample_seq"], 3);
    let caught_up = history_response(
        app,
        &format!("/api/stats/history?instance_id={instance_id}&epoch=1&after_seq=3"),
    )
    .await;
    assert_eq!(caught_up["reset"], false);
    assert_eq!(caught_up["samples"], json!([]));
    assert_eq!(caught_up["meta"], full["meta"]);
}

#[tokio::test]
async fn stats_history_api_resets_instance_epoch_and_future_cursors() {
    let app = app_with_stats_history(
        retained_stats_history(),
        Arc::new(RwLock::new(active_observer())),
    );
    let full = history_response(app.clone(), "/api/stats/history").await;
    let instance_id = full["instance_id"].as_str().unwrap();
    for uri in [
        "/api/stats/history?instance_id=old-inspector&epoch=1&after_seq=3".into(),
        format!("/api/stats/history?instance_id={instance_id}&epoch=2&after_seq=3"),
        format!("/api/stats/history?instance_id={instance_id}&epoch=1&after_seq=10"),
    ] {
        let reset = history_response(app.clone(), &uri).await;
        assert_eq!(reset["reset"], true);
        assert_eq!(reset["samples"], full["samples"]);
    }
}

#[tokio::test]
async fn stats_history_api_rejects_incomplete_empty_and_non_numeric_cursors() {
    let app = app_with_stats_history(
        retained_stats_history(),
        Arc::new(RwLock::new(active_observer())),
    );
    for uri in [
        "/api/stats/history?after_seq=1",
        "/api/stats/history?instance_id=current&epoch=1",
        "/api/stats/history?instance_id=&epoch=1&after_seq=1",
        "/api/stats/history?instance_id=current&epoch=invalid&after_seq=1",
        "/api/stats/history?instance_id=current&epoch=1&after_seq=-1",
    ] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
    }
}

#[tokio::test]
async fn stats_history_api_observes_a_reset_before_new_epoch_stats_are_published() {
    let observer = Arc::new(RwLock::new(active_observer()));
    let app = app_with_stats_history(retained_stats_history(), observer.clone());
    let previous = history_response(app.clone(), "/api/stats/history").await;
    {
        let mut observer = observer.write().unwrap();
        observer.epoch = 2;
        observer.status = CollectorStatus::Resetting;
    }
    let value = history_response(
        app,
        &format!(
            "/api/stats/history?instance_id={}&epoch=1&after_seq=3",
            previous["instance_id"].as_str().unwrap()
        ),
    )
    .await;
    assert_eq!(value["meta"]["epoch"], 2);
    assert_eq!(value["meta"]["sample_seq"], 0);
    assert!(value["meta"]["captured_at_unix_ms"].is_null());
    assert_eq!(value["collector"]["status"], "resetting");
    assert_eq!(value["reset"], true);
    assert_eq!(value["samples"], json!([]));
}

#[tokio::test]
async fn stats_history_api_exposes_read_failures_while_preserving_successful_samples() {
    let history = retained_stats_history();
    let app = app_with_stats_history(history.clone(), Arc::new(RwLock::new(active_observer())));
    let previous = history_response(app.clone(), "/api/stats/history").await;
    let at_ms = previous["meta"]["captured_at_unix_ms"].as_u64().unwrap();
    let mut failure = history_sample(3, at_ms);
    failure.error = Some("socket closed".into());
    failure.meta.error = failure.error.clone();
    history.write().unwrap().record(&failure, unix_ms());
    let value = history_response(app, "/api/stats/history").await;
    assert_eq!(value["meta"]["error"], "socket closed");
    assert_eq!(value["meta"]["sample_seq"], 3);
    assert_eq!(value["meta"]["captured_at_unix_ms"], at_ms);
    assert_eq!(value["samples"], previous["samples"]);
}

#[tokio::test]
async fn stats_history_api_expires_by_request_time_without_faking_fresh_publication_metadata() {
    let mut history = StatsHistory::new();
    let old_at_ms = unix_ms() - STATS_HISTORY_RETENTION_MS - 1;
    history.record(&history_sample(1, old_at_ms), old_at_ms);
    let app = app_with_stats_history(
        Arc::new(RwLock::new(history)),
        Arc::new(RwLock::new(active_observer())),
    );
    let value = history_response(app, "/api/stats/history").await;
    assert_eq!(value["samples"], json!([]));
    assert_eq!(value["meta"]["sample_seq"], 1);
    assert_eq!(value["meta"]["captured_at_unix_ms"], old_at_ms);
    assert_eq!(value["meta"]["last_success_at_unix_ms"], old_at_ms);
}
