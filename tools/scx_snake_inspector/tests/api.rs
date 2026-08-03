// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use scx_snake_inspector::api::{router, ApiContext, CSRF_HEADER};
use scx_snake_inspector::collector::CollectorCommand;
use scx_snake_inspector::dashboard::{
    CellStatsStatus, Dashboard, FineTimingStatus, QueueTimingStatus,
};
use scx_snake_inspector::host_context::{
    ChartMetric, CommandFuture, CommandInvocation, CommandOutput as HostCommandOutput,
    CommandRunner, HostContextService,
};
use scx_snake_inspector::launcher::SnakeLauncher;
use scx_snake_inspector::model::{CellMetricCounters, CpuPair, HostCpuTimeCounters};
use scx_snake_inspector::policies::{InvalidPolicy, PolicyCatalog, PolicyChoice};
use scx_snake_inspector::scope::TaskScope;
use scx_snake_inspector::testing::{MatrixConfig, TestingController};
use scx_snake_inspector::topology::{CpuInfo, TopologyView};
use serde_json::{json, Value};
use tower::ServiceExt;

fn launcher_fixture() -> (tempfile::TempDir, SnakeLauncher) {
    launcher_fixture_with_script("#!/bin/sh\ntrap 'exit 0' INT TERM\nwhile :; do sleep 1; done\n")
}

fn launcher_fixture_with_script(script: &str) -> (tempfile::TempDir, SnakeLauncher) {
    let root = tempfile::tempdir().unwrap();
    let binary = root.path().join("scx_snake");
    fs::write(&binary, script).unwrap();
    let mut permissions = fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&binary, permissions).unwrap();
    let policies = root.path().join("policies");
    fs::create_dir(&policies).unwrap();
    fs::write(
        policies.join("basic.toml"),
        "[[rung]]\noperation = \"claim_idle\"\nscope = \"previous_cpu\"\n",
    )
    .unwrap();
    let ops = root.path().join("ops");
    fs::write(&ops, "\n").unwrap();
    let launcher = SnakeLauncher::with_ops_path(&binary, &policies, &ops).unwrap();
    (root, launcher)
}

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
    snapshot["fairness"] = json!({"mode_name": "fifo"});
    let mut dispatch_buckets = vec![0_u64; 32];
    let mut dsq_buckets = vec![0_u64; 32];
    let empty_buckets = vec![0_u64; 32];
    dispatch_buckets[5] = 100;
    dsq_buckets[17] = 100;
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
                    "normal_dsq_insert": {"total_ns": 0, "buckets": empty_buckets.clone()}
                }
            },
            {
                "callback": "dispatch",
                "state": "historical",
                "session_id": 9,
                "policy_generation": 7,
                "sample_rate": 32,
                "started_at_ms": 500,
                "stopped_at_ms": 900,
                "stages": {
                    "remote_normal_scan": {"total_ns": 6300, "buckets": dispatch_buckets}
                },
                "dsq_operations": [{
                    "dsq_id": 13835058055282163719_u64,
                    "operation": "insert",
                    "outcome": "success",
                    "timing": {"total_ns": 13107200, "buckets": dsq_buckets}
                }],
                "dsq_transfers": [{
                    "source_dsq_id": 805306368,
                    "target_dsq_id": 13835058055282163719_u64,
                    "samples": 100
                }]
            },
            {
                "callback": "runnable",
                "state": "inactive",
                "session_id": null,
                "policy_generation": null,
                "started_at_ms": null,
                "stopped_at_ms": null,
                "stages": {
                    "runnable_state": {"total_ns": 0, "buckets": empty_buckets.clone()}
                }
            },
            {
                "callback": "running",
                "state": "inactive",
                "session_id": null,
                "policy_generation": null,
                "started_at_ms": null,
                "stopped_at_ms": null,
                "stages": {
                    "run_state": {"total_ns": 0, "buckets": empty_buckets.clone()}
                }
            },
            {
                "callback": "stopping",
                "state": "inactive",
                "session_id": null,
                "policy_generation": null,
                "started_at_ms": null,
                "stopped_at_ms": null,
                "stages": {
                    "runtime_stat": {"total_ns": 0, "buckets": empty_buckets.clone()}
                }
            },
            {
                "callback": "quiescent",
                "state": "inactive",
                "session_id": null,
                "policy_generation": null,
                "started_at_ms": null,
                "stopped_at_ms": null,
                "stages": {
                    "fairness_state": {"total_ns": 0, "buckets": empty_buckets}
                }
            }
        ]
    });
    snapshot
}

fn queue_topology_snapshot(generation: u64) -> Value {
    let mut snapshot = callback_timing_snapshot(generation, 0, 0);
    snapshot["queue_topology"] = json!({
        "cells": [{
            "external_id": 3,
            "index": 1,
            "slot_epoch": 4,
            "primary_cpus": [0, 1]
        }]
    });
    snapshot["topology_lifecycle"] = json!({"current_generation": generation});
    snapshot
}

fn queue_timing_snapshot() -> Value {
    let mut snapshot = queue_topology_snapshot(7);
    let mut residence = vec![0_u64; 64];
    residence[5] = 100;
    let mut depth = vec![0_u64; 256];
    depth[3] = 50;
    depth[9] = 50;
    snapshot["queue_timing"] = json!({
        "sample_rate": 64,
        "state": "collecting",
        "session_id": 11,
        "policy_generation": 7,
        "started_at_ms": 1000,
        "stopped_at_ms": null,
        "started_samples": 120,
        "completed_samples": 100,
        "dropped_samples": 2,
        "dsqs": [{
            "dsq_id": 8192,
            "cell_index": 1,
            "queue_class": "normal",
            "residence": {"total_ns": 6300, "buckets": residence},
            "depth": {"samples": 100, "latest": 4, "max": 9, "buckets": depth}
        }]
    });
    snapshot
}

fn cell_metrics(runtime_ns: u64) -> CellMetricCounters {
    let active = runtime_ns > 0;
    CellMetricCounters {
        id: 3,
        index: 1,
        slot_epoch: Some(4),
        primary_cpu_count: Some(2),
        utilization_pct: active.then_some(50.0),
        ewma_utilization_pct: active.then_some(42.0),
        borrowed_pct: active.then_some(25.0),
        lent_pct: active.then_some(10.0),
        runtime_ns,
        runtime_ns_by_cpu: None,
        primary_runtime_ns: runtime_ns * 3 / 4,
        borrowed_runtime_ns: runtime_ns / 4,
        lent_runtime_ns: runtime_ns / 4,
        foreign_affinity_runtime_ns: Some(runtime_ns / 8),
        normal_enqueues: if active { 80 } else { 0 },
        affinity_enqueues: if active { 20 } else { 0 },
        normal_dispatches: if active { 50 } else { 0 },
        affinity_dispatches: if active { 50 } else { 0 },
        clock_transitions: if active { 10 } else { 0 },
    }
}

#[test]
fn utilization_reconciles_cell_service_with_host_cpu_capacity() {
    let dashboard = dashboard();
    dashboard.set_scheduler("snake", true, 11);
    dashboard.set_inspection_at(0, Some(queue_topology_snapshot(7)), None);
    dashboard.reset_top_metrics(0);
    dashboard.ingest_top_metrics(
        0,
        7,
        &BTreeMap::from([(0, 0), (1, 0)]),
        Some(&BTreeMap::from([(3, cell_metrics(0))])),
    );
    let mut cell = cell_metrics(450_000_000);
    cell.runtime_ns_by_cpu = Some(BTreeMap::from([(0, 450_000_000)]));
    dashboard.ingest_top_metrics(
        1_000,
        7,
        &BTreeMap::from([(0, 500_000_000), (1, 100_000_000)]),
        Some(&BTreeMap::from([(3, cell)])),
    );
    dashboard.ingest_host_cpu_times(
        0,
        100,
        &BTreeMap::from([
            (0, HostCpuTimeCounters::default()),
            (1, HostCpuTimeCounters::default()),
        ]),
    );
    dashboard.ingest_host_cpu_times(
        1_000,
        100,
        &BTreeMap::from([
            (
                0,
                HostCpuTimeCounters {
                    task_ticks: 60,
                    irq_ticks: 2,
                    softirq_ticks: 3,
                    idle_ticks: 34,
                    iowait_ticks: 1,
                    steal_ticks: 0,
                },
            ),
            (
                1,
                HostCpuTimeCounters {
                    task_ticks: 20,
                    irq_ticks: 1,
                    softirq_ticks: 1,
                    idle_ticks: 78,
                    iowait_ticks: 0,
                    steal_ticks: 0,
                },
            ),
        ]),
    );

    let snapshot = dashboard.snapshot(1_000).unwrap();
    assert!(snapshot.server_time_ms > 0);

    assert_eq!(
        snapshot.cell_stats.cells[0].runtime_ns_by_cpu,
        Some(BTreeMap::from([(0, 450_000_000)]))
    );
    assert_eq!(snapshot.host_cpu_usage_observed_ms, 1_000);
    assert_eq!(snapshot.host_cpu_usage.len(), 2);
    let cpu0 = &snapshot.host_cpu_usage[0];
    assert_eq!(cpu0.total_ns, 1_000_000_000);
    assert_eq!(cpu0.task_ns, 600_000_000);
    assert_eq!(cpu0.snake_ns, 500_000_000);
    assert_eq!(cpu0.cell_ns, Some(450_000_000));
    assert_eq!(cpu0.other_task_ns, 100_000_000);
    assert_eq!(cpu0.hardirq_ns, 20_000_000);
    assert_eq!(cpu0.softirq_ns, 30_000_000);
    assert_eq!(cpu0.unattributed_snake_ns, Some(50_000_000));
    assert_eq!(cpu0.source_overage_ns, 0);
}

#[test]
fn host_cpu_sampling_failure_rebaselines_before_reporting_recovery() {
    let dashboard = dashboard();
    dashboard.ingest_host_cpu_times(
        0,
        100,
        &BTreeMap::from([(0, HostCpuTimeCounters::default())]),
    );
    dashboard.ingest_host_cpu_times(
        1_000,
        100,
        &BTreeMap::from([(
            0,
            HostCpuTimeCounters {
                task_ticks: 20,
                idle_ticks: 80,
                ..Default::default()
            },
        )]),
    );
    dashboard.set_host_cpu_usage_error(Some("/proc/stat unavailable".into()));
    dashboard.ingest_host_cpu_times(
        10_000,
        100,
        &BTreeMap::from([(
            0,
            HostCpuTimeCounters {
                task_ticks: 200,
                idle_ticks: 800,
                ..Default::default()
            },
        )]),
    );
    dashboard.set_host_cpu_usage_error(None);

    let recovery = dashboard.snapshot(1_000).unwrap();
    assert_eq!(recovery.host_cpu_usage_observed_ms, 0);
    assert!(recovery.host_cpu_usage.is_empty());

    dashboard.ingest_host_cpu_times(
        11_000,
        100,
        &BTreeMap::from([(
            0,
            HostCpuTimeCounters {
                task_ticks: 230,
                idle_ticks: 870,
                ..Default::default()
            },
        )]),
    );
    let stable = dashboard.snapshot(1_000).unwrap();
    assert_eq!(stable.host_cpu_usage[0].total_ns, 1_000_000_000);
}

#[test]
fn runtime_context_tracks_scheduler_attachment_and_policy_generation() {
    let dashboard = dashboard();
    dashboard.ingest(1_000, &BTreeMap::new());
    dashboard.set_scheduler("snake", true, 24);
    let mut inspection = fine_timing_snapshot();
    inspection["active_slot"] = json!(0);
    inspection["fairness"] = json!({"mode_name": "vtime"});
    dashboard.set_inspection_at(1_000, Some(inspection), None);

    let snapshot = dashboard.snapshot(1_000).unwrap();
    assert_eq!(snapshot.context.scheduler_attach_seq, 24);
    assert!(snapshot.context.scheduler_active);
    assert_eq!(snapshot.context.policy_generation, Some(7));
    assert_eq!(snapshot.context.active_slot, Some(0));
    assert_eq!(snapshot.context.fairness.as_deref(), Some("vtime"));
    assert_eq!(snapshot.context.callback_sample_rate, Some(64));
    assert_eq!(snapshot.context.observed_at_ms, Some(1_000));

    assert_eq!(dashboard.inspection().context, snapshot.context);
    assert_eq!(
        dashboard.callback_timing_lifetime().context,
        snapshot.context
    );
    assert_eq!(dashboard.fine_timing().context, snapshot.context);
}

#[test]
fn dashboard_stats_reset_rebases_all_histories_without_changing_scope() {
    let dashboard = dashboard();
    let pair = CpuPair::new(0, 1);
    dashboard.set_scope(TaskScope::Tgids(vec![42]));
    dashboard.ingest(0, &BTreeMap::new());
    dashboard.ingest(500, &BTreeMap::from([(pair, 9)]));
    dashboard.set_scheduler("snake", true, 4);

    let mut inspection = fine_timing_snapshot();
    inspection["queue_topology"] = queue_topology_snapshot(7)["queue_topology"].clone();
    let mut buckets = vec![0_u64; 64];
    buckets[5] = 100;
    inspection["slots"][0]["metrics"]["callback_timing"]["dispatch"] =
        json!({"total_ns": 6300, "buckets": buckets});
    dashboard.set_inspection_at(500, Some(inspection), None);
    dashboard.ingest_top_metrics(
        0,
        7,
        &BTreeMap::from([(0, 0)]),
        Some(&BTreeMap::from([(3, cell_metrics(0))])),
    );
    dashboard.ingest_top_metrics(
        500,
        7,
        &BTreeMap::from([(0, 250_000_000)]),
        Some(&BTreeMap::from([(3, cell_metrics(250_000_000))])),
    );
    assert_eq!(
        dashboard
            .callback_timing_lifetime()
            .callbacks
            .iter()
            .find(|row| row.callback == "dispatch")
            .unwrap()
            .samples,
        100
    );
    assert_eq!(dashboard.fine_timing().status, FineTimingStatus::Ready);

    dashboard.reset_statistics(750, &BTreeMap::from([(pair, 9)]));

    let snapshot = dashboard.snapshot(1_000).unwrap();
    assert_eq!(snapshot.scope, TaskScope::Tgids(vec![42]));
    assert_eq!(snapshot.total, 0);
    assert_eq!(snapshot.observed_ms, 0);
    assert!(snapshot.cpu_usage.is_empty());
    assert_eq!(snapshot.cpu_usage_observed_ms, 0);
    assert_eq!(snapshot.cell_stats.source_policy_generation, None);
    assert_eq!(snapshot.cell_stats.source_topology_generation, None);
    assert!(snapshot.cell_stats.cells.is_empty());
    assert!(dashboard.callback_timing_lifetime().callbacks.is_empty());
    assert_eq!(
        dashboard.fine_timing().status,
        FineTimingStatus::Unavailable
    );
    assert!(dashboard.inspection().snapshot.is_none());
}

#[test]
fn cell_stats_derive_window_metrics_from_top_deltas_and_queue_topology() {
    let dashboard = dashboard();
    dashboard.set_scheduler("snake", true, 4);
    dashboard.set_inspection_at(0, Some(queue_topology_snapshot(7)), None);
    dashboard.ingest_top_metrics(
        0,
        7,
        &BTreeMap::from([(0, 0), (1, 0)]),
        Some(&BTreeMap::from([(3, cell_metrics(0))])),
    );
    let empty = serde_json::to_value(dashboard.snapshot(1_000).unwrap()).unwrap();
    let empty = &empty["cell_stats"]["cells"][0];
    for field in [
        "service_cores",
        "service_share_pct",
        "primary_pct",
        "borrowed_pct",
        "owned_utilization_pct",
        "enqueue_rate_per_second",
        "dispatch_rate_per_second",
        "affinity_enqueue_share_pct",
        "affinity_dispatch_share_pct",
        "transition_rate_per_second",
        "transitions_per_1k_dispatches",
    ] {
        assert_eq!(empty[field], Value::Null, "{field}");
    }
    dashboard.ingest_top_metrics(
        1_000,
        7,
        &BTreeMap::from([(0, 500_000_000), (1, 500_000_000)]),
        Some(&BTreeMap::from([(3, cell_metrics(1_000_000_000))])),
    );

    let snapshot = serde_json::to_value(dashboard.snapshot(1_000).unwrap()).unwrap();
    let stats = &snapshot["cell_stats"];
    let cell = &stats["cells"][0];
    assert_eq!(stats["status"], "ready");
    assert_eq!(stats["scope"], "all_snake_tasks");
    assert_eq!(stats["source_policy_generation"], 7);
    assert_eq!(stats["source_topology_generation"], 7);
    assert_eq!(stats["window_ms"], 1_000);
    assert_eq!(stats["observed_ms"], 1_000);
    assert_eq!(cell["id"], 3);
    assert_eq!(cell["index"], 1);
    assert_eq!(cell["slot_epoch"], 4);
    assert_eq!(cell["primary_cpu_count"], 2);
    assert_eq!(cell["utilization_pct"], 50.0);
    assert_eq!(cell["ewma_utilization_pct"], 42.0);
    assert_eq!(cell["lent_pct"], 10.0);
    assert_eq!(cell["runtime_ns"], 1_000_000_000_u64);
    assert_eq!(cell["foreign_affinity_runtime_ns"], 125_000_000_u64);
    assert_eq!(cell["service_cores"], 1.0);
    assert_eq!(cell["service_share_pct"], 100.0);
    assert_eq!(cell["primary_pct"], 75.0);
    assert_eq!(cell["borrowed_pct"], 25.0);
    assert_eq!(cell["owned_utilization_pct"], 50.0);
    assert_eq!(cell["enqueue_rate_per_second"], 100.0);
    assert_eq!(cell["dispatch_rate_per_second"], 100.0);
    assert_eq!(cell["affinity_enqueue_share_pct"], 20.0);
    assert_eq!(cell["affinity_dispatch_share_pct"], 50.0);
    assert_eq!(cell["transition_rate_per_second"], 10.0);
    assert_eq!(cell["transitions_per_1k_dispatches"], 100.0);
}

#[test]
fn cell_stats_distinguish_policy_mode_support_and_generation_sync() {
    let dashboard = dashboard();
    dashboard.set_scheduler("snake", true, 4);
    let mut placement = callback_timing_snapshot(7, 0, 0);
    placement["queue_topology"] = Value::Null;
    dashboard.set_inspection_at(0, Some(placement), None);
    dashboard.ingest_top_metrics(0, 7, &BTreeMap::from([(0, 0)]), None);
    assert_eq!(
        dashboard.snapshot(1_000).unwrap().cell_stats.status,
        CellStatsStatus::NotApplicable
    );
    dashboard.set_cpu_usage_error(Some("top stream unavailable".into()));
    assert_eq!(
        dashboard.snapshot(1_000).unwrap().cell_stats.status,
        CellStatsStatus::NotApplicable
    );
    dashboard.set_cpu_usage_error(None);

    dashboard.set_inspection_at(0, Some(queue_topology_snapshot(7)), None);
    assert_eq!(
        dashboard.snapshot(1_000).unwrap().cell_stats.status,
        CellStatsStatus::Unsupported
    );

    dashboard.ingest_top_metrics(
        250,
        8,
        &BTreeMap::from([(0, 0)]),
        Some(&BTreeMap::from([(3, cell_metrics(0))])),
    );
    assert_eq!(
        dashboard.snapshot(1_000).unwrap().cell_stats.status,
        CellStatsStatus::Synchronizing
    );
}

#[test]
fn cell_stats_are_not_applicable_to_llc_queue_sharding() {
    let dashboard = dashboard();
    dashboard.set_scheduler("snake", true, 4);
    let mut llc_queues = callback_timing_snapshot(7, 0, 0);
    llc_queues["queue_topology"] = json!({"layout": "llc", "cells": []});
    dashboard.set_inspection_at(0, Some(llc_queues), None);
    dashboard.ingest_top_metrics(100, 7, &BTreeMap::from([(0, 0)]), Some(&BTreeMap::new()));

    assert_eq!(
        dashboard.snapshot(1_000).unwrap().cell_stats.status,
        CellStatsStatus::NotApplicable
    );
}

#[tokio::test]
async fn stats_reset_requires_token_and_sends_collector_command() {
    use scx_snake_inspector::collector::StatsResetResponse;

    let (tx, rx) = mpsc::channel();
    let root = tempfile::tempdir().unwrap();
    let context = ApiContext::new(dashboard(), tx, "secret", root.path().to_path_buf());

    let unauthorized = router(context.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/stats/reset")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let responder = std::thread::spawn(move || {
        let CollectorCommand::ResetStats { response } = rx.recv().unwrap() else {
            panic!("expected stats reset command");
        };
        response
            .send(Ok(StatsResetResponse {
                generation: 7,
                active_slot: 1,
                reset_at_ms: 123_456,
                fine_timing_stopped: true,
                queue_timing_stopped: true,
            }))
            .unwrap();
    });
    let accepted = router(context)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/stats/reset")
                .header("host", "127.0.0.1")
                .header(CSRF_HEADER, "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);
    let response: Value =
        serde_json::from_slice(&accepted.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(response["generation"], 7);
    assert_eq!(response["active_slot"], 1);
    assert_eq!(response["reset_at_ms"], 123_456);
    assert_eq!(response["fine_timing_stopped"], true);
    assert_eq!(response["queue_timing_stopped"], true);
    responder.join().unwrap();
}

#[tokio::test]
async fn scheduler_control_lists_policies_while_stopped_and_manages_an_owned_child() {
    let (root, launcher) = launcher_fixture();
    fs::write(
        root.path().join("policies/queue.toml"),
        "[queues]\nlayout = \"llc\"\n",
    )
    .unwrap();
    let (tx, _rx) = mpsc::channel();
    let cgroup_root = tempfile::tempdir().unwrap();
    let context = ApiContext::new(dashboard(), tx, "secret", cgroup_root.path().to_path_buf())
        .with_launcher(launcher);

    let response = router(context.clone())
        .oneshot(
            Request::builder()
                .uri("/api/scheduler/control")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["managed"], false);
    assert_eq!(body["controllable"], false);
    assert_eq!(body["control_error"], Value::Null);
    assert_eq!(body["active"], false);
    assert_eq!(body["policy_id"], Value::Null);
    assert_eq!(body["launch"]["fairness"], Value::Null);
    assert_eq!(body["launch"]["callback_timing_sample_rate"], Value::Null);
    assert_eq!(body["launch"]["exit_dump_len"], Value::Null);
    assert_eq!(body["launch"]["verbose"], false);
    assert_eq!(body["launch"]["preserved_args"], json!([]));
    assert_eq!(body["policies"][0]["id"], "basic.toml");
    assert_eq!(body["policies"][0]["change_mode"], "reload");
    let queue = body["policies"]
        .as_array()
        .unwrap()
        .iter()
        .find(|policy| policy["id"] == "queue.toml")
        .unwrap();
    assert_eq!(queue["supported_fairness"], json!(["vtime"]));
    assert_eq!(body["settings"][0]["name"], "fairness");
    assert_eq!(body["settings"][0]["default_value"], "fifo");
    assert_eq!(body["settings"][1]["default_value"], 64);
    assert_eq!(body["settings"][2]["default_value"], 0);
    assert_eq!(body["settings"][3]["default_value"], false);

    let request_body = Body::from(
        r#"{"policy_id":"basic.toml","fairness":"vtime","callback_timing_sample_rate":128,"exit_dump_len":4096,"verbose":true}"#,
    );
    let unauthorized = router(context.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/scheduler/start")
                .header("host", "127.0.0.1")
                .header("content-type", "application/json")
                .body(request_body)
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let started = router(context.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/scheduler/start")
                .header("host", "127.0.0.1")
                .header("content-type", "application/json")
                .header(CSRF_HEADER, "secret")
                .body(Body::from(
                    r#"{"policy_id":"basic.toml","fairness":"vtime","callback_timing_sample_rate":128,"exit_dump_len":4096,"verbose":true}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(started.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&started.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["managed"], true);
    assert_eq!(body["controllable"], true);
    assert_eq!(body["policy_id"], "basic.toml");
    assert!(body["uptime_ms"].as_u64().is_some());
    let current_command = body["current_command"]
        .as_array()
        .expect("managed command must expose argv");
    assert!(current_command[0]
        .as_str()
        .is_some_and(|argument| argument.ends_with("scx_snake")));
    assert_eq!(current_command[1], "--policy");
    assert_eq!(current_command[3], "--fairness");
    assert_eq!(current_command[4], "vtime");
    assert_eq!(current_command.last().unwrap(), "--verbose");
    assert_eq!(body["launch"]["fairness"], "vtime");
    assert_eq!(body["launch"]["callback_timing_sample_rate"], 128);
    assert_eq!(body["launch"]["exit_dump_len"], 4096);
    assert_eq!(body["launch"]["verbose"], true);

    let restarted = router(context.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/scheduler/restart")
                .header("host", "127.0.0.1")
                .header("content-type", "application/json")
                .header(CSRF_HEADER, "secret")
                .body(Body::from(
                    r#"{"policy_id":"basic.toml","fairness":"fifo","verbose":false}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(restarted.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&restarted.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["managed"], true);
    assert_eq!(body["controllable"], true);
    assert_eq!(body["launch"]["fairness"], "fifo");

    let stopped = router(context)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/scheduler/stop")
                .header("host", "127.0.0.1")
                .header("content-type", "application/json")
                .header(CSRF_HEADER, "secret")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stopped.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&stopped.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["managed"], false);
}

#[tokio::test]
async fn scheduler_start_rejects_raw_or_unknown_arguments() {
    let (_root, launcher) = launcher_fixture();
    let (tx, _rx) = mpsc::channel();
    let cgroup_root = tempfile::tempdir().unwrap();
    let context = ApiContext::new(dashboard(), tx, "secret", cgroup_root.path().to_path_buf())
        .with_launcher(launcher);

    let response = router(context.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/scheduler/start")
                .header("host", "127.0.0.1")
                .header("content-type", "application/json")
                .header(CSRF_HEADER, "secret")
                .body(Body::from(
                    r#"{"policy_id":"basic.toml","verbose":false,"args":["--fairness","eevdf"]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn scheduler_control_preserves_omitted_launch_flags() {
    let (_root, launcher) = launcher_fixture();
    let dashboard = dashboard();
    dashboard.set_inspection(
        Some(json!({
            "active_slot": 0,
            "callback_timing_sample_rate": 64,
            "fairness": {"mode_name": "fifo"},
            "slots": [{"slot": 0, "policy": {"source": "basic"}}]
        })),
        None,
    );
    let (tx, _rx) = mpsc::channel();
    let cgroup_root = tempfile::tempdir().unwrap();
    let context = ApiContext::new(dashboard, tx, "secret", cgroup_root.path().to_path_buf())
        .with_launcher(launcher);

    let response = router(context)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/scheduler/start")
                .header("host", "127.0.0.1")
                .header("content-type", "application/json")
                .header(CSRF_HEADER, "secret")
                .body(Body::from(r#"{"policy_id":"basic.toml","verbose":false}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();

    assert_eq!(body["launch"]["fairness"], Value::Null);
    assert_eq!(body["launch"]["callback_timing_sample_rate"], Value::Null);
    let settings = body["settings"].as_array().unwrap();
    let fairness = settings
        .iter()
        .find(|setting| setting["name"] == "fairness")
        .unwrap();
    assert_eq!(fairness["effective"], "fifo");
    assert_eq!(fairness["default_value"], "fifo");
    assert_eq!(fairness["launch_override"], Value::Null);
    assert_eq!(fairness["runtime_observed"], true);
    let sampling = settings
        .iter()
        .find(|setting| setting["name"] == "callback_timing_sample_rate")
        .unwrap();
    assert_eq!(sampling["effective"], 64);
    assert_eq!(sampling["default_value"], 64);
    assert_eq!(sampling["launch_override"], Value::Null);
    assert_eq!(sampling["runtime_observed"], true);
}

#[tokio::test]
async fn scheduler_control_uses_external_argv_without_inventing_launch_flags() {
    let root = tempfile::tempdir().unwrap();
    let binary = root.path().join("scx_snake");
    fs::write(
        &binary,
        "#!/bin/sh\ntrap 'exit 0' INT TERM\nwhile :; do sleep 0.05; done\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&binary).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&binary, permissions).unwrap();
    let policies = root.path().join("policies");
    fs::create_dir(&policies).unwrap();
    let policy = policies.join("basic.toml");
    fs::write(&policy, "basic").unwrap();
    let ops = root.path().join("ops");
    fs::write(&ops, "snake_test\n").unwrap();
    let proc_root = root.path().join("proc");
    fs::create_dir(&proc_root).unwrap();
    let mut child = Command::new(&binary)
        .args(["--policy", policy.to_str().unwrap(), "--stats", "1"])
        .spawn()
        .unwrap();
    let process = proc_root.join(child.id().to_string());
    fs::create_dir(&process).unwrap();
    let cmdline = format!(
        "{}\0--policy\0{}\0--stats\01\0",
        binary.display(),
        policy.display()
    );
    fs::write(process.join("cmdline"), cmdline.as_bytes()).unwrap();
    std::os::unix::fs::symlink(&binary, process.join("exe")).unwrap();
    let launcher = SnakeLauncher::with_paths(&binary, &policies, &ops, &proc_root).unwrap();
    let dashboard = dashboard();
    dashboard.set_scheduler("snake_test", true, 24);
    dashboard.set_inspection(
        Some(json!({
            "active_slot": 0,
            "callback_timing_sample_rate": 64,
            "fairness": {"mode_name": "vtime"},
            "slots": [{"slot": 0, "generation": 7, "policy": {"source": "basic"}}]
        })),
        None,
    );
    let (tx, _rx) = mpsc::channel();
    let cgroup_root = tempfile::tempdir().unwrap();
    let context = ApiContext::new(dashboard, tx, "secret", cgroup_root.path().to_path_buf())
        .with_launcher(launcher);

    let response = router(context.clone())
        .oneshot(
            Request::builder()
                .uri("/api/scheduler/control")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["controllable"], true);
    assert_eq!(body["pid"], child.id());
    assert_eq!(
        body["current_command"],
        json!([
            binary.to_string_lossy(),
            "--policy",
            policy.to_string_lossy(),
            "--stats",
            "1"
        ])
    );
    assert_eq!(body["launch"]["callback_timing_sample_rate"], Value::Null);
    assert_eq!(body["launch"]["preserved_args"], json!(["--stats", "1"]));
    assert_eq!(body["context"]["scheduler_attach_seq"], 24);
    assert_eq!(body["context"]["policy_generation"], 7);
    assert_eq!(body["context"]["fairness"], "vtime");

    child.kill().unwrap();
    child.wait().unwrap();
}

#[tokio::test]
async fn scheduler_control_distinguishes_dynamic_restart_and_invalid_policies() {
    let (root, launcher) = launcher_fixture();
    for name in [
        "cell.toml",
        "broken.toml",
        "enqueue.toml",
        "dispatch.toml",
        "legacy-queue.toml",
        "managed.toml",
    ] {
        fs::write(root.path().join("policies").join(name), "candidate").unwrap();
    }
    fs::write(root.path().join("ops"), "snake_test\n").unwrap();
    let dashboard = dashboard();
    dashboard.set_policy_catalog(
        Some(PolicyCatalog {
            policies: vec![
                PolicyChoice {
                    id: "basic.toml".into(),
                    name: "basic".into(),
                    source: "basic".into(),
                    rung_count: 1,
                    mask_table_count: 0,
                    cell_count: 0,
                    queue_policy: false,
                    summary: "dynamic".into(),
                },
                PolicyChoice {
                    id: "legacy-queue.toml".into(),
                    name: "legacy queue".into(),
                    source: "[ queues ] # old Snake response".into(),
                    rung_count: 1,
                    mask_table_count: 0,
                    cell_count: 1,
                    queue_policy: false,
                    summary: "legacy queue response".into(),
                },
            ],
            invalid: vec![
                InvalidPolicy {
                    id: "cell.toml".into(),
                    name: "cell".into(),
                    source: "[queues]".into(),
                    error: "candidate changes attachment-time queue topology; restart Snake to apply it"
                        .into(),
                },
                InvalidPolicy {
                    id: "broken.toml".into(),
                    name: "broken".into(),
                    source: "candidate".into(),
                    error: "compiling candidate policy: missing rung".into(),
                },
                InvalidPolicy {
                    id: "enqueue.toml".into(),
                    name: "enqueue".into(),
                    source: "[queues]".into(),
                    error: "cannot remove active queue enqueue target `cell` during live replacement"
                        .into(),
                },
                InvalidPolicy {
                    id: "dispatch.toml".into(),
                    name: "dispatch".into(),
                    source: "[queues]".into(),
                    error: "cannot remove active queue dispatch source `affinity` during live replacement"
                        .into(),
                },
                InvalidPolicy {
                    id: "managed.toml".into(),
                    name: "managed".into(),
                    source: "[managed_cells]".into(),
                    error: "Invalid argument (os error 22): \"managed cells are attachment-time configuration; restart Snake to apply a policy update\""
                        .into(),
                },
            ],
        }),
        None,
    );
    let (tx, _rx) = mpsc::channel();
    let cgroup_root = tempfile::tempdir().unwrap();
    let context = ApiContext::new(dashboard, tx, "secret", cgroup_root.path().to_path_buf())
        .with_launcher(launcher);

    let response = router(context.clone())
        .oneshot(
            Request::builder()
                .uri("/api/scheduler/control")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let modes = body["policies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|policy| {
            (
                policy["id"].as_str().unwrap(),
                policy["change_mode"].as_str().unwrap(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(modes["basic.toml"], "dynamic");
    assert_eq!(modes["cell.toml"], "reload");
    assert_eq!(modes["broken.toml"], "invalid");
    assert_eq!(modes["enqueue.toml"], "reload");
    assert_eq!(modes["dispatch.toml"], "reload");
    assert_eq!(modes["managed.toml"], "reload");
    let policy = |id| {
        body["policies"]
            .as_array()
            .unwrap()
            .iter()
            .find(|policy| policy["id"] == id)
            .unwrap()
    };
    assert_eq!(policy("basic.toml")["apply_mode"], "live");
    assert_eq!(
        policy("basic.toml")["supported_fairness"],
        json!(["fifo", "vtime", "eevdf"])
    );
    assert_eq!(policy("cell.toml")["apply_mode"], "restart");
    assert_eq!(policy("cell.toml")["reasons"][0]["code"], "dsq_topology");
    assert_eq!(policy("broken.toml")["apply_mode"], "invalid");
    assert_eq!(
        policy("broken.toml")["reasons"][0]["code"],
        "validation_failed"
    );
    assert_eq!(
        policy("legacy-queue.toml")["supported_fairness"],
        json!(["vtime"])
    );
    assert_eq!(
        policy("enqueue.toml")["reasons"][0]["code"],
        "enqueue_targets"
    );
    assert_eq!(
        policy("dispatch.toml")["reasons"][0]["code"],
        "dispatch_sources"
    );
    assert_eq!(policy("managed.toml")["apply_mode"], "restart");

    let rejected = router(context.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/scheduler/restart")
                .header("host", "127.0.0.1")
                .header("content-type", "application/json")
                .header(CSRF_HEADER, "secret")
                .body(Body::from(r#"{"policy_id":"broken.toml","verbose":false}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
    let body: Value =
        serde_json::from_slice(&rejected.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(body["error"].as_str().unwrap().contains("invalid"));

    fs::write(root.path().join("ops"), "\n").unwrap();
    let response = router(context)
        .oneshot(
            Request::builder()
                .uri("/api/scheduler/control")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert!(body["policies"]
        .as_array()
        .unwrap()
        .iter()
        .all(|policy| policy["change_mode"] == "reload"));
}

#[tokio::test]
async fn scheduler_restart_rejects_unsupported_fairness_without_stopping_snake() {
    let (root, launcher) = launcher_fixture();
    fs::write(root.path().join("policies/queue.toml"), "[queues]\n").unwrap();
    let dashboard = dashboard();
    dashboard.set_policy_catalog(
        Some(PolicyCatalog {
            policies: vec![
                PolicyChoice {
                    id: "basic.toml".into(),
                    name: "basic".into(),
                    source: "basic".into(),
                    rung_count: 1,
                    mask_table_count: 0,
                    cell_count: 0,
                    queue_policy: false,
                    summary: "placement".into(),
                },
                PolicyChoice {
                    id: "queue.toml".into(),
                    name: "queue".into(),
                    source: "[queues]".into(),
                    rung_count: 1,
                    mask_table_count: 0,
                    cell_count: 1,
                    queue_policy: true,
                    summary: "queue topology".into(),
                },
            ],
            invalid: Vec::new(),
        }),
        None,
    );
    let (tx, _rx) = mpsc::channel();
    let cgroup_root = tempfile::tempdir().unwrap();
    let context = ApiContext::new(dashboard, tx, "secret", cgroup_root.path().to_path_buf())
        .with_launcher(launcher);

    let rejected_start = router(context.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/scheduler/start")
                .header("host", "127.0.0.1")
                .header("content-type", "application/json")
                .header(CSRF_HEADER, "secret")
                .body(Body::from(r#"{"policy_id":"queue.toml","verbose":false}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected_start.status(), StatusCode::BAD_REQUEST);

    let started = router(context.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/scheduler/start")
                .header("host", "127.0.0.1")
                .header("content-type", "application/json")
                .header(CSRF_HEADER, "secret")
                .body(Body::from(r#"{"policy_id":"basic.toml","verbose":false}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(started.status(), StatusCode::OK);
    let started: Value =
        serde_json::from_slice(&started.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let original_pid = started["pid"].as_u64().unwrap();

    let rejected = router(context.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/scheduler/restart")
                .header("host", "127.0.0.1")
                .header("content-type", "application/json")
                .header(CSRF_HEADER, "secret")
                .body(Body::from(
                    r#"{"policy_id":"queue.toml","fairness":"fifo","verbose":false}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);

    let current = router(context)
        .oneshot(
            Request::builder()
                .uri("/api/scheduler/control")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let current: Value =
        serde_json::from_slice(&current.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(current["managed"], true);
    assert_eq!(current["pid"], original_pid);
}

#[tokio::test]
async fn scheduler_control_reports_the_last_managed_exit() {
    let (_root, launcher) = launcher_fixture_with_script(
        "#!/bin/sh\necho 'queues require --fairness vtime' >&2\nexit 7\n",
    );
    let (tx, _rx) = mpsc::channel();
    let cgroup_root = tempfile::tempdir().unwrap();
    let context = ApiContext::new(dashboard(), tx, "secret", cgroup_root.path().to_path_buf())
        .with_launcher(launcher);

    let started = router(context.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/scheduler/start")
                .header("host", "127.0.0.1")
                .header("content-type", "application/json")
                .header(CSRF_HEADER, "secret")
                .body(Body::from(r#"{"policy_id":"basic.toml","verbose":false}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(started.status(), StatusCode::OK);

    let mut body = Value::Null;
    for _ in 0..50 {
        let response = router(context.clone())
            .oneshot(
                Request::builder()
                    .uri("/api/scheduler/control")
                    .header("host", "127.0.0.1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        body = serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
        if body["managed"] == false {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    assert_eq!(body["managed"], false);
    assert_eq!(
        body["last_exit"],
        "exit code 7: queues require --fairness vtime"
    );
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
async fn callback_timing_rate_update_requires_token_and_uses_runtime_control() {
    use scx_snake_inspector::collector::CallbackTimingRateResponse;

    let (tx, rx) = mpsc::channel();
    let root = tempfile::tempdir().unwrap();
    let context = ApiContext::new(dashboard(), tx, "secret", root.path().to_path_buf());
    let body = r#"{"sample_rate":128}"#;

    let unauthorized = router(context.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/callback-timing")
                .header("host", "127.0.0.1")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let responder = std::thread::spawn(move || {
        let CollectorCommand::SetCallbackTimingSampleRate {
            sample_rate,
            response,
        } = rx.recv().unwrap()
        else {
            panic!("expected callback timing rate command");
        };
        assert_eq!(sample_rate, 128);
        response
            .send(Ok(CallbackTimingRateResponse {
                sample_rate,
                fine_timing_stopped: true,
                queue_timing_stopped: true,
            }))
            .unwrap();
    });
    let accepted = router(context)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/callback-timing")
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
    assert_eq!(response["sample_rate"], 128);
    assert_eq!(response["fine_timing_stopped"], true);
    assert_eq!(response["queue_timing_stopped"], true);
    responder.join().unwrap();
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
    let enqueue = body["captures"]
        .as_array()
        .unwrap()
        .iter()
        .find(|capture| capture["callback"] == "enqueue")
        .unwrap();
    let select_cpu = body["captures"]
        .as_array()
        .unwrap()
        .iter()
        .find(|capture| capture["callback"] == "select_cpu")
        .unwrap();
    assert_eq!(body["status"], "ready");
    assert_eq!(select_cpu["available"], true);
    assert_eq!(select_cpu["unavailable_reason"], Value::Null);
    assert_eq!(enqueue["available"], true);
    assert_eq!(enqueue["unavailable_reason"], Value::Null);
    assert_eq!(dispatch["available"], true);
    assert_eq!(dispatch["unavailable_reason"], Value::Null);
    assert_eq!(dispatch["state"], "historical");
    assert_eq!(dispatch["sample_rate"], 32);
    assert_eq!(dispatch["observed_ms"], 400);
    assert_eq!(dispatch["stages"][0]["stage"], "remote_normal_scan");
    assert_eq!(dispatch["stages"][0]["samples"], 100);
    assert_eq!(dispatch["stages"][0]["mean_ns"], 63);
    assert_eq!(
        dispatch["dsq_operations"][0]["dsq_id"],
        "13835058055282163719"
    );
    assert_eq!(dispatch["dsq_operations"][0]["operation"], "insert");
    assert_eq!(dispatch["dsq_operations"][0]["outcome"], "success");
    assert_eq!(dispatch["dsq_operations"][0]["samples"], 100);
    assert_eq!(dispatch["dsq_operations"][0]["p99_ns"], 262143);
    assert_eq!(dispatch["dsq_transfers"][0]["source_dsq_id"], "805306368");
    assert_eq!(
        dispatch["dsq_transfers"][0]["target_dsq_id"],
        "13835058055282163719"
    );
    assert_eq!(dispatch["dsq_transfers"][0]["samples"], 100);

    let responder = std::thread::spawn(move || {
        let CollectorCommand::SetFineTiming {
            callback,
            enabled,
            response,
        } = rx.recv().unwrap()
        else {
            panic!("expected fine timing command");
        };
        assert_eq!(callback, FineTimingCallback::Stopping);
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
                .body(Body::from(r#"{"callback":"stopping","enabled":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["callback"], "stopping");
    assert_eq!(body["enabled"], true);
    assert_eq!(body["session_id"], 11);
    responder.join().unwrap();
}

#[tokio::test]
async fn queue_timing_endpoint_summarizes_capture_and_controls_it_with_a_token() {
    use scx_snake_inspector::collector::QueueTimingControlResponse;

    let dashboard = dashboard();
    dashboard.set_scheduler("snake", true, 4);
    dashboard.set_inspection_at(1_000, Some(queue_timing_snapshot()), None);
    let (tx, rx) = mpsc::channel();
    let root = tempfile::tempdir().unwrap();
    let context = ApiContext::new(dashboard, tx, "secret", root.path().to_path_buf());

    let unauthorized = router(context.clone())
        .oneshot(
            Request::builder()
                .uri("/api/queue-timing")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let response = router(context.clone())
        .oneshot(
            Request::builder()
                .uri("/api/queue-timing")
                .header("host", "127.0.0.1")
                .header(CSRF_HEADER, "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let dsq = &body["dsqs"][0];
    assert_eq!(body["status"], "ready");
    assert_eq!(body["sample_rate"], 64);
    assert_eq!(body["state"], "collecting");
    assert_eq!(body["session_id"], 11);
    assert_eq!(body["started_samples"], 120);
    assert_eq!(body["completed_samples"], 100);
    assert_eq!(body["dropped_samples"], 2);
    assert_eq!(dsq["dsq_id"], "8192");
    assert_eq!(dsq["cell_index"], 1);
    assert_eq!(dsq["queue_class"], "normal");
    assert_eq!(dsq["residence"]["samples"], 100);
    assert_eq!(dsq["residence"]["mean_ns"], 63);
    assert_eq!(dsq["residence"]["p50_ns"], 63);
    assert_eq!(dsq["residence"]["p95_ns"], 63);
    assert_eq!(dsq["residence"]["p99_ns"], 63);
    assert_eq!(dsq["depth"]["samples"], 100);
    assert_eq!(dsq["depth"]["latest"], 4);
    assert_eq!(dsq["depth"]["p95"], 9);
    assert_eq!(dsq["depth"]["max"], 9);

    let unauthorized = router(context.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/queue-timing")
                .header("host", "127.0.0.1")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"enabled":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let responder = std::thread::spawn(move || {
        let CollectorCommand::SetQueueTiming { enabled, response } = rx.recv().unwrap() else {
            panic!("expected queue timing command");
        };
        assert!(enabled);
        response
            .send(Ok(QueueTimingControlResponse {
                enabled,
                session_id: Some(12),
            }))
            .unwrap();
    });
    let accepted = router(context)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/queue-timing")
                .header("host", "127.0.0.1")
                .header("content-type", "application/json")
                .header(CSRF_HEADER, "secret")
                .body(Body::from(r#"{"enabled":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&accepted.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body, json!({"enabled": true, "session_id": 12}));
    responder.join().unwrap();
}

#[test]
fn queue_timing_availability_and_validation_are_explicit() {
    let dashboard = dashboard();
    assert_eq!(
        dashboard.queue_timing().status,
        QueueTimingStatus::Unavailable
    );

    dashboard.set_scheduler("snake", true, 4);
    let mut no_topology = queue_timing_snapshot();
    no_topology["queue_topology"] = Value::Null;
    dashboard.set_inspection(Some(no_topology), None);
    assert_eq!(dashboard.queue_timing().status, QueueTimingStatus::Ready);

    dashboard.set_inspection(Some(queue_topology_snapshot(7)), None);
    assert_eq!(
        dashboard.queue_timing().status,
        QueueTimingStatus::Unsupported
    );

    let mut disabled = queue_timing_snapshot();
    disabled["queue_timing"]["sample_rate"] = json!(0);
    dashboard.set_inspection(Some(disabled), None);
    assert_eq!(dashboard.queue_timing().status, QueueTimingStatus::Disabled);

    let mut malformed = queue_timing_snapshot();
    malformed["queue_timing"]["dsqs"][0]["queue_class"] = json!("global");
    dashboard.set_inspection(Some(malformed), None);
    let invalid = dashboard.queue_timing();
    assert_eq!(invalid.status, QueueTimingStatus::Unavailable);
    assert!(invalid.error.unwrap().contains("queue class"));

    let mut fairness = queue_timing_snapshot();
    fairness["queue_timing"]["dsqs"][0]["queue_class"] = json!("fairness");
    dashboard.set_inspection(Some(fairness), None);
    assert_eq!(dashboard.queue_timing().status, QueueTimingStatus::Ready);

    let mut malformed = queue_timing_snapshot();
    malformed["queue_timing"]["dsqs"][0]["residence"]["buckets"] = json!(vec![0_u64; 63]);
    dashboard.set_inspection(Some(malformed), None);
    let invalid = dashboard.queue_timing();
    assert_eq!(invalid.status, QueueTimingStatus::Unavailable);
    assert!(invalid.error.unwrap().contains("64 buckets"));

    let mut sparse = queue_timing_snapshot();
    let mut residence = vec![0_u64; 64];
    residence[3] = 19;
    let mut depth = vec![0_u64; 256];
    depth[2] = 19;
    sparse["queue_timing"]["completed_samples"] = json!(19);
    sparse["queue_timing"]["dsqs"][0]["residence"] = json!({"total_ns": 190, "buckets": residence});
    sparse["queue_timing"]["dsqs"][0]["depth"] =
        json!({"samples": 19, "latest": 2, "max": 2, "buckets": depth});
    dashboard.set_inspection(Some(sparse), None);
    let sparse = serde_json::to_value(dashboard.queue_timing()).unwrap();
    assert_eq!(sparse["dsqs"][0]["residence"]["p95_ns"], Value::Null);
    assert_eq!(sparse["dsqs"][0]["residence"]["p99_ns"], Value::Null);
    assert_eq!(sparse["dsqs"][0]["depth"]["p95"], Value::Null);
}

#[test]
fn fine_timing_availability_tracks_callback_sampling() {
    let dashboard = dashboard();
    let mut snapshot = fine_timing_snapshot();
    snapshot["queue_topology"] = json!({});
    dashboard.set_inspection(Some(snapshot.clone()), None);

    let view = serde_json::to_value(dashboard.fine_timing()).unwrap();
    assert!(view["captures"]
        .as_array()
        .unwrap()
        .iter()
        .all(|capture| capture["available"] == true));

    snapshot["queue_topology"] = Value::Null;
    dashboard.set_inspection(Some(snapshot.clone()), None);
    let view = serde_json::to_value(dashboard.fine_timing()).unwrap();
    assert!(view["captures"]
        .as_array()
        .unwrap()
        .iter()
        .all(|capture| capture["available"] == true));

    snapshot["fine_timing"]["sample_rate"] = json!(0);
    dashboard.set_inspection(Some(snapshot), None);
    let view = serde_json::to_value(dashboard.fine_timing()).unwrap();
    assert!(view["captures"].as_array().unwrap().iter().all(|capture| {
        capture["available"] == false
            && capture["unavailable_reason"]
                == "Enable callback sampling to collect fine-grained timestamps."
    }));
}

#[test]
fn fine_timing_accepts_legacy_three_callback_payloads() {
    let dashboard = dashboard();
    let mut snapshot = fine_timing_snapshot();
    snapshot["fine_timing"]["captures"]
        .as_array_mut()
        .unwrap()
        .truncate(3);

    dashboard.set_inspection(Some(snapshot), None);

    let view = dashboard.fine_timing();
    assert_eq!(view.status, FineTimingStatus::Ready);
    assert_eq!(view.captures.len(), 3);
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
                queue_policy: false,
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
async fn testing_matrix_endpoint_groups_compatible_policies_by_fairness() {
    let dashboard = dashboard();
    dashboard.set_policy_catalog(
        Some(PolicyCatalog {
            policies: vec![
                PolicyChoice {
                    id: "basic.toml".into(),
                    name: "basic".into(),
                    source: String::new(),
                    rung_count: 1,
                    mask_table_count: 0,
                    cell_count: 0,
                    queue_policy: false,
                    summary: String::new(),
                },
                PolicyChoice {
                    id: "cell-queues.toml".into(),
                    name: "cell queues".into(),
                    source: "[queues]\n".into(),
                    rung_count: 1,
                    mask_table_count: 0,
                    cell_count: 2,
                    queue_policy: true,
                    summary: String::new(),
                },
            ],
            invalid: Vec::new(),
        }),
        None,
    );
    let (tx, _rx) = mpsc::channel();
    let root = tempfile::tempdir().unwrap();
    let context = ApiContext::new(dashboard, tx, "secret", root.path().to_path_buf())
        .with_testing(TestingController::new(MatrixConfig::new(60, 0, 8).unwrap()));

    let response = router(context.clone())
        .oneshot(
            Request::builder()
                .uri("/api/testing/matrix")
                .header("host", "127.0.0.1:8788")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["status"], "idle");
    assert_eq!(body["matrix"]["duration_secs"], 60);
    assert_eq!(body["matrix"]["shard_count"], 8);
    assert_eq!(body["matrix"]["total_cases"], 16);
    assert_eq!(body["matrix"]["groups"][0]["fairness"], "fifo");
    assert_eq!(
        body["matrix"]["groups"][0]["rows"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(body["matrix"]["groups"][1]["fairness"], "vtime");
    assert_eq!(
        body["matrix"]["groups"][1]["rows"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    let response = router(context)
        .oneshot(
            Request::builder()
                .uri("/api/testing/campaigns")
                .header("host", "127.0.0.1:8788")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["runs"].as_array().unwrap().len(), 1);
    assert_eq!(body["runs"][0]["matrix"]["total_cases"], 16);
}

#[tokio::test]
async fn testing_run_and_stop_require_the_session_token() {
    let dashboard = dashboard();
    dashboard.set_policy_catalog(
        Some(PolicyCatalog {
            policies: vec![PolicyChoice {
                id: "basic.toml".into(),
                name: "basic".into(),
                source: String::new(),
                rung_count: 1,
                mask_table_count: 0,
                cell_count: 0,
                queue_policy: false,
                summary: String::new(),
            }],
            invalid: Vec::new(),
        }),
        None,
    );
    let (tx, _rx) = mpsc::channel();
    let root = tempfile::tempdir().unwrap();
    let context = ApiContext::new(dashboard, tx, "secret", root.path().to_path_buf())
        .with_testing(TestingController::new(MatrixConfig::new(60, 0, 1).unwrap()));

    let unauthorized = router(context.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/testing/run")
                .header("host", "127.0.0.1:8788")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let started = router(context.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/testing/run")
                .header("host", "127.0.0.1:8788")
                .header("content-type", "application/json")
                .header(CSRF_HEADER, "secret")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(started.status(), StatusCode::OK);
    let body = started.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["status"], "running");

    let stopped = router(context)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/testing/stop")
                .header("host", "127.0.0.1:8788")
                .header("content-type", "application/json")
                .header(CSRF_HEADER, "secret")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stopped.status(), StatusCode::OK);
    let body = stopped.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["status"], "stopped");
}

#[tokio::test]
async fn active_testing_run_locks_manual_scheduler_lifecycle() {
    let (root, launcher) = launcher_fixture();
    let dashboard = dashboard();
    let catalog = PolicyCatalog {
        policies: vec![PolicyChoice {
            id: "basic.toml".into(),
            name: "basic".into(),
            source: String::new(),
            rung_count: 1,
            mask_table_count: 0,
            cell_count: 0,
            queue_policy: false,
            summary: String::new(),
        }],
        invalid: Vec::new(),
    };
    dashboard.set_policy_catalog(Some(catalog.clone()), None);
    let testing = TestingController::new(MatrixConfig::new(60, 0, 1).unwrap());
    testing.start(&catalog).unwrap();
    let (tx, _rx) = mpsc::channel();
    let context = ApiContext::new(dashboard, tx, "secret", root.path().to_path_buf())
        .with_launcher(launcher)
        .with_testing(testing);

    for endpoint in [
        "/api/scheduler/start",
        "/api/scheduler/restart",
        "/api/scheduler/stop",
    ] {
        let body = if endpoint.ends_with("stop") {
            "{}"
        } else {
            r#"{"policy_id":"basic.toml","fairness":"fifo","verbose":false}"#
        };
        let response = router(context.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(endpoint)
                    .header("host", "127.0.0.1:8788")
                    .header("content-type", "application/json")
                    .header(CSRF_HEADER, "secret")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT, "{endpoint}");
    }
}

#[tokio::test]
async fn managed_scheduler_locks_testing_start_before_sched_ext_attach() {
    let (root, launcher) = launcher_fixture();
    let dashboard = dashboard();
    dashboard.set_policy_catalog(
        Some(PolicyCatalog {
            policies: vec![PolicyChoice {
                id: "basic.toml".into(),
                name: "basic".into(),
                source: String::new(),
                rung_count: 1,
                mask_table_count: 0,
                cell_count: 0,
                queue_policy: false,
                summary: String::new(),
            }],
            invalid: Vec::new(),
        }),
        None,
    );
    let testing = TestingController::new(MatrixConfig::new(60, 0, 1).unwrap());
    let (tx, _rx) = mpsc::channel();
    let context = ApiContext::new(dashboard, tx, "secret", root.path().to_path_buf())
        .with_launcher(launcher)
        .with_testing(testing);

    let scheduler = router(context.clone())
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/scheduler/start")
                .header("host", "127.0.0.1:8788")
                .header("content-type", "application/json")
                .header(CSRF_HEADER, "secret")
                .body(Body::from(
                    r#"{"policy_id":"basic.toml","fairness":"fifo","verbose":false}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(scheduler.status(), StatusCode::OK);

    let testing = router(context)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/testing/run")
                .header("host", "127.0.0.1:8788")
                .header("content-type", "application/json")
                .header(CSRF_HEADER, "secret")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(testing.status(), StatusCode::CONFLICT);
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
async fn event_stream_closes_when_server_shutdown_starts() {
    let dashboard = dashboard();
    dashboard.ingest(0, &BTreeMap::new());
    let (tx, _rx) = mpsc::channel();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let root = tempfile::tempdir().unwrap();
    let app = router(
        ApiContext::new(dashboard, tx, "secret", root.path().to_path_buf())
            .with_shutdown(shutdown_rx),
    );

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
    let mut body = response.into_body();
    assert!(body.frame().await.unwrap().unwrap().is_data());

    shutdown_tx.send(true).unwrap();
    let end = tokio::time::timeout(Duration::from_secs(1), body.frame())
        .await
        .unwrap();
    assert!(end.is_none());
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
    assert!(page.contains("/assets/theme.js"));
    assert!(!page.contains("https://"));
    for control in [
        "id=\"liveStatus\"",
        "id=\"primaryNav\"",
        "href=\"#/overview\"",
        "href=\"#/observe/placement\"",
        "href=\"#/observe/callbacks\"",
        "href=\"#/configure\"",
        "href=\"#/inspect/policy-slots\"",
        "href=\"#/inspect/queue-topology\"",
        "href=\"#/inspect/cells\"",
        "id=\"overviewView\"",
        "id=\"activityView\"",
        "id=\"policyView\"",
        "id=\"queueTopologyView\"",
        "id=\"policyLibrary\"",
        "id=\"policyDialog\"",
        "id=\"feedbackDrawer\"",
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
        "id=\"callbackSampleRateControl\"",
        "id=\"applyCallbackSampleRate\"",
    ] {
        assert!(page.contains(control), "missing page control {control}");
    }
    assert!(page.contains("id=\"zoomControl\" type=\"range\" min=\"0.25\" max=\"3\" step=\"0.25\""));

    let script = app
        .clone()
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

    let theme = app
        .oneshot(
            Request::builder()
                .uri("/assets/theme.js")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(theme.status(), StatusCode::OK);
    assert_eq!(
        theme.headers()["content-type"],
        "text/javascript; charset=utf-8"
    );
}

#[tokio::test]
async fn web_shell_disables_browser_caching() {
    let (tx, _rx) = mpsc::channel();
    let root = tempfile::tempdir().unwrap();
    let app = router(ApiContext::new(
        dashboard(),
        tx,
        "secret",
        root.path().to_path_buf(),
    ));

    for uri in [
        "/",
        "/assets/app.js",
        "/assets/heatmap.js",
        "/assets/inspection.js",
        "/assets/theme.js",
        "/assets/style.css",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("host", "127.0.0.1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "unexpected status for {uri}"
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-store",
            "unexpected cache policy for {uri}"
        );
    }
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

#[tokio::test]
async fn router_accepts_only_the_configured_secure_web_app_host() {
    let (tx, _rx) = mpsc::channel();
    let root = tempfile::tempdir().unwrap();
    let context = ApiContext::new(dashboard(), tx, "secret", root.path().to_path_buf())
        .with_allowed_host("devbig008.atn3.fbinfra.net")
        .with_allowed_host("devbig008.atn3.facebook.com")
        .with_allowed_host("www.edge.x2p.facebook.net");
    let app = router(context);

    let accepted = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header("host", "devbig008.atn3.fbinfra.net:44102")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);

    let translated = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header("host", "devbig008.atn3.facebook.com:44102")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(translated.status(), StatusCode::OK);

    let bridged = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/")
                .header("host", "www.edge.x2p.facebook.net")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bridged.status(), StatusCode::OK);

    let rejected = app
        .oneshot(
            Request::builder()
                .uri("/")
                .header("host", "other.atn3.fbinfra.net:44102")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(rejected.status(), StatusCode::MISDIRECTED_REQUEST);
}

#[derive(Default)]
struct HostApiRunner {
    calls: Mutex<Vec<CommandInvocation>>,
}

impl CommandRunner for HostApiRunner {
    fn run<'a>(&'a self, invocation: CommandInvocation, _timeout: Duration) -> CommandFuture<'a> {
        self.calls.lock().unwrap().push(invocation.clone());
        Box::pin(async move {
            let joined = invocation.args.join(" ");
            if joined.contains("tupperware.host") {
                Ok(HostCommandOutput::text(
                    r#"[{"job_handle":"tsp_atn/team/service","task_id":"3"}]"#,
                ))
            } else if joined.contains("allotments_table") {
                Ok(HostCommandOutput::text("[]"))
            } else if joined.contains("host_fqdn") {
                Ok(HostCommandOutput::text(
                    r#"[{"datacenter_name":"atn3","host_fqdn":"devbig008.atn3.facebook.com","id":"332060305","logical_server_subtype":"T2_TRN","machine_pool":"devbig","region":"atn","reservation_entitlement_id":"-","resource_materialization_id":"","stackable":"false"}]"#,
                ))
            } else if joined.contains("--image") {
                let path = invocation
                    .args
                    .iter()
                    .position(|arg| arg == "--image")
                    .and_then(|index| invocation.args.get(index + 1))
                    .ok_or_else(|| "missing chart path".to_owned())?;
                fs::write(path, b"\x89PNG\r\n\x1a\npng-data").map_err(|error| error.to_string())?;
                Ok(HostCommandOutput::text(""))
            } else if joined.contains("--fburlonly") {
                Ok(HostCommandOutput::text("https://fburl.com/ods/fresh\n"))
            } else {
                Err(format!("unexpected command: {joined}"))
            }
        })
    }
}

#[tokio::test]
async fn host_context_routes_expose_metadata_charts_and_fresh_ods_links() {
    let runner = Arc::new(HostApiRunner::default());
    let host_context =
        HostContextService::with_runner("devbig008.atn3.facebook.com", 316, None, runner);
    host_context.refresh_metadata(1_000).await;
    host_context
        .refresh_chart(ChartMetric::CpuPressure, 1_100)
        .await;
    let (tx, _rx) = mpsc::channel();
    let root = tempfile::tempdir().unwrap();
    let app = router(
        ApiContext::new(dashboard(), tx, "secret", root.path().to_path_buf())
            .with_host_context(host_context),
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/host-context")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["identity"]["machine_pool"], "devbig");
    assert_eq!(body["tupperware"]["data"][0]["task_id"], "3");
    assert_eq!(body["charts"][0]["state"], "ready");

    let image = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/host-charts/cpu-pressure.png?revision=1100")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(image.status(), StatusCode::OK);
    assert_eq!(image.headers()["content-type"], "image/png");
    assert_eq!(
        image.headers()["cache-control"],
        "private, max-age=31536000, immutable"
    );
    assert_eq!(
        image.into_body().collect().await.unwrap().to_bytes(),
        b"\x89PNG\r\n\x1a\npng-data".as_slice()
    );

    let get_open = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/host-charts/scheduler-delay/open")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get_open.status(), StatusCode::METHOD_NOT_ALLOWED);

    let unauthorized_open = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/host-charts/scheduler-delay/open")
                .header("host", "127.0.0.1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized_open.status(), StatusCode::UNAUTHORIZED);

    let open = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/host-charts/scheduler-delay/open")
                .header("host", "127.0.0.1")
                .header(CSRF_HEADER, "secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(open.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&open.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["url"], "https://fburl.com/ods/fresh");
}
