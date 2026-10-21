//! Controlled browser fixture for exercising the actual router and replay store.
//! Run manually; no BPF attachment, scheduler, or production listener is changed.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, RwLock};
use std::time::Duration;

use axum::routing::get;
use scx_mitosis_inspector::api::{router, ApiContext};
use scx_mitosis_inspector::collector::{CollectorConfig, Snapshot};
use scx_mitosis_inspector::host_context::{HostContextView, HostIdentityView};
use scx_mitosis_inspector::lifecycle::{unix_ms, CollectorStatus, ObserverContext, SampleMeta};
use scx_mitosis_inspector::migration_history::MigrationHistory;
use scx_mitosis_inspector::replay::{ReplayHistory, ReplaySources, REPLAY_RETENTION_MS};
use scx_mitosis_inspector::replay_migrations::ReplayMigrationHistory;
use scx_mitosis_inspector::scheduler_config::{
    OptionStatus, SchedulerConfigSnapshot, SchedulerOptionView,
};
use scx_mitosis_inspector::stats::StatsSnapshot;
use scx_mitosis_inspector::system_stats::{
    CpuFrequency, FrequencyStats, MetricSource, SchedExtStats, SystemStatsCollector,
    SystemStatsSnapshot,
};
use scx_mitosis_inspector::topology::{CpuInfo, LlcGroup, TopologyView};
use scx_mitosis_inspector::{
    build_callback_timing_rows, CallbackCounter, CallbackTimingCounters, CpuCapacityLossRow,
    CpuRuntimeRow, InterruptCpuRow, MigrationRow, TimingMetricRow, CALLBACK_NAMES,
};
use serde_json::json;

fn observer(index: u64) -> ObserverContext {
    let epoch = if index <= 900 { 1 } else { 2 };
    ObserverContext {
        epoch,
        status: CollectorStatus::Active,
        scheduler_enable_seq: Some(epoch),
        scheduler_name: Some(format!("mitosis_fixture_{epoch}")),
        error: None,
    }
}

fn sources(index: u64, at: u64, template: &SystemStatsSnapshot) -> ReplaySources {
    let context = observer(index);
    let seq = if context.epoch == 1 {
        index
    } else {
        index - 900
    };
    let meta = SampleMeta {
        epoch: context.epoch,
        sample_seq: seq,
        captured_at_unix_ms: Some(at),
        last_success_at_unix_ms: Some(at),
        error: None,
    };
    let mut counters = Snapshot::empty(CollectorConfig {
        callback_timing_sample_rate: 1024,
        event_timing_sample_rate: 64,
        enable_dsq: true,
        enable_scheduler_events: true,
        enable_irqs: true,
        enable_block_io: true,
    });
    counters.meta = meta.clone();
    counters.collector = context.clone();
    counters.target_program_ids = [11, 12, 13, 14, 15];
    counters.uptime_seconds = seq;
    counters.migration_map_capacity = 256;
    counters.migration_quality = "complete";
    counters.counters = CALLBACK_NAMES
        .into_iter()
        .map(|name| CallbackCounter {
            name,
            count: seq * 100,
            rate_per_second: 100.0 + context.epoch as f64,
        })
        .collect();
    let mut timing = CallbackTimingCounters::default();
    timing.buckets[12] = seq * 10;
    timing.buckets[16] = seq;
    timing.total_ns = seq * 11 * 6000;
    counters.callback_timings = build_callback_timing_rows(&vec![timing.clone(); 5]);
    counters.scheduler_timings = vec![TimingMetricRow {
        metric: "wakeup_to_running",
        samples: seq * 11,
        buckets: timing.buckets.clone(),
        mean_ns: Some(6000),
        p50_ns: Some(8191),
        p95_ns: Some(131071),
        p99_ns: Some(131071),
    }];
    counters.cpu_runtime = (0..16)
        .map(|cpu| CpuRuntimeRow {
            cpu,
            runtime_ns: seq * 100_000,
            utilization_pct: 40.0 + context.epoch as f64,
        })
        .collect();
    counters.interrupt_cpu = (0..16)
        .map(|cpu| InterruptCpuRow {
            cpu,
            hardirq_utilization_pct: 1.0,
            softirq_utilization_pct: 1.0,
            total_utilization_pct: 2.0,
        })
        .collect();
    counters.cpu_capacity_loss = (0..16)
        .map(|cpu| CpuCapacityLossRow {
            cpu,
            rt_stop_utilization_pct: 1.0,
            deadline_utilization_pct: 0.0,
            steal_utilization_pct: 0.0,
            total_utilization_pct: 1.0,
        })
        .collect();
    counters.dsq_metrics.available = true;
    counters.dsq_metrics.depth_average = Some(context.epoch as f64);
    counters.dsq_metrics.depth_latest_max = context.epoch * 2;
    counters.dsq_metrics.residence_buckets = timing.buckets.clone();
    counters.dsq_metrics.residence_samples = seq * 11;
    counters.block_io.available = true;
    counters.block_io.completion_rate_per_second = 10.0 * context.epoch as f64;
    counters.block_io.completed_bytes_per_second = 1_048_576.0 * context.epoch as f64;
    counters.block_io.latency_buckets = timing.buckets.clone();
    counters.block_io.latency_samples = seq * 11;
    counters.migrations = vec![
        MigrationRow {
            from_cpu: 0,
            to_cpu: 1,
            count: seq * 10,
        },
        MigrationRow {
            from_cpu: 0,
            to_cpu: 4,
            count: seq * 5,
        },
    ];

    let mut stats = StatsSnapshot::default();
    stats.meta = meta.clone();
    stats.collector = context.clone();
    stats.error = None;
    let cpus = if context.epoch == 1 { 8 } else { 10 };
    stats.metrics = Some(json!({ "num_cells": 2, "rebalance_count": index,
    "util_pct": 50.0, "cells": {
        "0": {"num_cpus": cpus, "util_pct": 50.0, "smoothed_util_pct": 50.0,
              "demand_borrow_pct": 0.0, "lent_pct": 0.0},
        "1": {"num_cpus": 16 - cpus, "util_pct": 30.0, "smoothed_util_pct": 30.0,
              "demand_borrow_pct": 0.0, "lent_pct": 0.0}
    }}));
    stats.cpu_cells = Some(
        (0..16)
            .map(|cpu| (cpu, if cpu < cpus { 0 } else { 1 }))
            .collect(),
    );
    stats.cpu_cells_error = None;

    let mut system = template.clone();
    system.meta = meta;
    system.collector = context.clone();
    system.captured_at_unix_ms = at;
    system.interval_ms = Some(1000);
    if let Some(cpu) = &mut system.cpu.value {
        cpu.busy_pct = Some(20.0 * context.epoch as f64);
    }
    for metric in [
        &mut system.pressure.cpu,
        &mut system.pressure.memory,
        &mut system.pressure.io,
    ] {
        if let Some(value) = &mut metric.value {
            if let Some(some) = &mut value.some {
                some.avg10 = context.epoch as f64;
            }
        }
    }
    if let Some(network) = &mut system.network.value {
        for interface in &mut network.interfaces {
            interface.rx_bytes_per_second = Some(1000.0 * context.epoch as f64);
            interface.tx_bytes_per_second = Some(500.0 * context.epoch as f64);
        }
    }
    system.frequencies = MetricSource {
        available: true,
        error: None,
        value: Some(FrequencyStats {
            average_khz: Some(2_000_000 + context.epoch * 100_000),
            minimum_khz: Some(2_000_000),
            maximum_khz: Some(2_200_000),
            available_cpus: 16,
            unavailable_cpus: 0,
            cpus: (0..16)
                .map(|cpu| CpuFrequency {
                    cpu,
                    current_khz: Some(2_100_000),
                    error: None,
                })
                .collect(),
        }),
    };
    system.sched_ext = MetricSource {
        available: true,
        error: None,
        value: Some(SchedExtStats {
            state: "enabled".into(),
            enable_seq: context.epoch,
            hotplug_seq: 0,
            nr_rejected: 0,
            switch_all: true,
        }),
    };
    let config = SchedulerConfigSnapshot {
        available: true,
        error: None,
        pid: Some(1000 + context.epoch as u32),
        executable: Some("/fixture/scx_mitosis".into()),
        version: Some(format!("fixture-epoch-{}", context.epoch)),
        command_line: vec!["/fixture/scx_mitosis".into()],
        options: vec![SchedulerOptionView {
            name: "--cell0-min-cpus".into(),
            value_name: None,
            current_value: cpus.to_string(),
            status: OptionStatus::Explicit,
            default: Some("2".into()),
            possible_values: vec![],
            description: "Fixture allocation".into(),
            group: "placement".into(),
        }],
    };
    ReplaySources {
        counters,
        stats,
        system,
        config,
    }
}

#[tokio::test]
#[ignore = "manual controlled browser fixture"]
async fn serve_timeline_browser_fixture() {
    let window_ms = std::env::var("MITOSIS_TIMELINE_FIXTURE_WINDOW_MS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(10_000);
    let max_window_ms = std::env::var("MITOSIS_TIMELINE_FIXTURE_MAX_WINDOW_MS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(300_000);
    let cpus = (0..16)
        .map(|cpu| CpuInfo {
            cpu,
            node: 0,
            package: 0,
            core: cpu % 8,
            llc: cpu % 8 / 4,
            core_topology_available: true,
        })
        .collect::<Vec<_>>();
    let topology = TopologyView {
        cpu_count: 16,
        numeric_order: (0..16).collect(),
        topology_order: (0..8).flat_map(|cpu| [cpu, cpu + 8]).collect(),
        llc_groups: (0..2)
            .map(|llc| LlcGroup {
                llc,
                node: 0,
                cpus: cpus
                    .iter()
                    .filter(|cpu| cpu.llc == llc)
                    .map(|cpu| cpu.cpu)
                    .collect(),
            })
            .collect(),
        cpus,
    };
    let host = HostContextView {
        identity: HostIdentityView {
            hostname: "controlled-timeline-fixture".into(),
            kernel_release: "browser-test".into(),
            cpu_count: 16,
        },
        topology: topology.clone(),
    };
    let history = Arc::new(RwLock::new(ReplayHistory::new()));
    let migrations = Arc::new(RwLock::new(ReplayMigrationHistory::new(
        REPLAY_RETENTION_MS,
        max_window_ms,
        &topology,
    )));
    let mut system_collector = SystemStatsCollector::new();
    system_collector.collect();
    std::thread::sleep(Duration::from_millis(15));
    let template = system_collector.collect();
    let start = unix_ms() - 1_800_000;
    for index in 1..=1800 {
        let at = start + (index - 1) * 1000;
        let sample = sources(index, at, &template);
        migrations.write().unwrap().ingest(at, &sample.counters);
        history
            .write()
            .unwrap()
            .record(at, &observer(index), sample)
            .unwrap();
    }
    let latest = sources(1800, start + 1_799_000, &template);
    let counters = Arc::new(RwLock::new(latest.counters));
    let stats = Arc::new(RwLock::new(latest.stats));
    let system = Arc::new(RwLock::new(latest.system));
    let context = Arc::new(RwLock::new(observer(1800)));
    let (commands, _commands_rx) = mpsc::sync_channel(8);
    let app = router(
        ApiContext::new(
            counters,
            stats,
            system,
            host,
            Arc::new(RwLock::new(MigrationHistory::new(max_window_ms))),
            window_ms,
            commands,
            context,
        )
        .with_scheduler_config(latest.config)
        .with_replay_state(history.clone(), migrations.clone()),
    )
    .route(
        "/test/wait",
        get(|| async {
            tokio::time::sleep(Duration::from_millis(2200)).await;
            "ready"
        }),
    );
    let stop = Arc::new(AtomicBool::new(false));
    let record_stop = stop.clone();
    let record_history = history.clone();
    let record_migrations = migrations.clone();
    let recorder = std::thread::spawn(move || {
        let mut index = 1801;
        while !record_stop.load(Ordering::Relaxed) {
            let at = unix_ms();
            let sample = sources(index, at, &template);
            record_migrations
                .write()
                .unwrap()
                .ingest(at, &sample.counters);
            record_history
                .write()
                .unwrap()
                .record(at, &observer(index), sample)
                .unwrap();
            index += 1;
            std::thread::sleep(Duration::from_secs(1));
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    std::fs::write(manifest.join("target/timeline-browser-url.txt"), &url).unwrap();
    std::fs::write(
        manifest.join("target/timeline-browser-start.txt"),
        start.to_string(),
    )
    .unwrap();
    println!("TIMELINE_FIXTURE_URL={url}");
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .unwrap();
    stop.store(true, Ordering::Relaxed);
    recorder.join().unwrap();
}
