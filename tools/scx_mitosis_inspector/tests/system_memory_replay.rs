// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-2.0-only

use scx_mitosis_inspector::collector::{CollectorConfig, Snapshot};
use scx_mitosis_inspector::explore_model::{ExploreGroup, ExploreSnapshot};
use scx_mitosis_inspector::lifecycle::{CollectorStatus, ObserverContext, SampleMeta};
use scx_mitosis_inspector::replay::{ReplayFrame, ReplayHistory, ReplayQuery, ReplaySources};
use scx_mitosis_inspector::scheduler_config::SchedulerConfigSnapshot;
use scx_mitosis_inspector::stats::StatsSnapshot;
use scx_mitosis_inspector::system_stats::SystemStatsCollector;
use serde_json::{json, Value};

fn observer(epoch: u64) -> ObserverContext {
    ObserverContext {
        epoch,
        status: CollectorStatus::Active,
        scheduler_enable_seq: Some(epoch),
        scheduler_name: Some("mitosis".into()),
        error: None,
    }
}

fn meta(epoch: u64, sample_seq: u64, captured: u64) -> SampleMeta {
    SampleMeta {
        epoch,
        sample_seq,
        captured_at_unix_ms: Some(captured),
        last_success_at_unix_ms: Some(captured),
        error: None,
    }
}

fn sources(epoch: u64, seq: u64, at: u64) -> ReplaySources {
    let mut counters = Snapshot::empty(CollectorConfig {
        callback_timing_sample_rate: 1024,
        event_timing_sample_rate: 64,
        enable_dsq: true,
        enable_scheduler_events: true,
        enable_irqs: true,
        enable_block_io: true,
    });
    counters.meta = meta(epoch, seq, at);
    counters.collector = observer(epoch);
    let stats = StatsSnapshot {
        meta: meta(epoch, seq, at),
        collector: observer(epoch),
        metrics: Some(json!({"cells": {}})),
        error: None,
        cpu_cells: None,
        cpu_cells_error: None,
    };
    let mut system = SystemStatsCollector::new().collect();
    system.meta = meta(epoch, seq, at);
    system.collector = observer(epoch);
    system.captured_at_unix_ms = at;
    ReplaySources {
        counters,
        stats,
        system,
        config: SchedulerConfigSnapshot::default(),
    }
}

fn bandwidth_row(llc: u32, total: Option<f64>, local: Option<f64>) -> Value {
    json!({
        "domain_id": llc + 1,
        "llc": llc,
        "node": 0,
        "package": 0,
        "cpus": [llc * 2, llc * 2 + 1],
        "topology_available": true,
        "mbm_local_bytes": 8_000_000_000_u64,
        "mbm_total_bytes": 16_000_000_000_u64,
        "mbm_local_bps": local,
        "mbm_total_bps": total,
        "llc_occupancy_bytes": 1_048_576,
        "local_status": if local.is_some() { "measured" } else { "unsupported" },
        "total_status": if total.is_some() { "measured" } else { "reset" },
        "occupancy_status": "measured",
        "error": if total.is_none() { Some("mbm_total_bytes: counter reset; waiting for a fresh interval") } else { None },
    })
}

fn cache_summary(references: Option<f64>, misses: Option<f64>, miss_pct: Option<f64>) -> Value {
    json!({
        "cpu_count": 2,
        "available_cpus": 2,
        "unavailable_cpus": 0,
        "sampled_cpus": 2,
        "partial": references.is_none() || misses.is_none(),
        "metric_cpu_counts": {
            "cycles": 2, "instructions": 2,
            "cache_references": if references.is_some() { 2 } else { 0 },
            "cache_misses": if misses.is_some() { 2 } else { 0 },
            "stalled_frontend_cycles": 2, "stalled_backend_cycles": 2,
        },
        "cycles_per_second": 2_000_000_000.0,
        "instructions_per_second": 4_000_000_000.0,
        "cache_references_per_second": references,
        "cache_misses_per_second": misses,
        "stalled_frontend_cycles_per_second": 0.0,
        "stalled_backend_cycles_per_second": 0.0,
        "ipc": 2.0,
        "ipc_sampled_cpus": 2,
        "cache_miss_pct": miss_pct,
        "cache_sampled_cpus": if miss_pct.is_some() { 2 } else { 0 },
        "minimum_pmu_coverage_pct": 50.0,
        "maximum_pmu_coverage_pct": 100.0,
    })
}

fn cache_llc(
    llc: u32,
    references: Option<f64>,
    misses: Option<f64>,
    miss_pct: Option<f64>,
) -> Value {
    let mut summary = cache_summary(references, misses, miss_pct);
    summary["llc_id"] = json!(llc);
    summary
}

fn cache_cpu(cpu: u32, llc: u32, references: f64, misses: f64, miss_pct: f64) -> Value {
    let mut row = json!({
        "cpu": cpu, "llc_id": llc, "available": true, "partial": false,
        "error": "", "interval_ms": 1_000.0, "ipc": 2.0,
        "cache_miss_pct": miss_pct, "metrics": {},
    });
    for (key, rate) in [
        ("cycles", 1_000_000_000.0),
        ("instructions", 2_000_000_000.0),
        ("cache_references", references),
        ("cache_misses", misses),
        ("stalled_frontend_cycles", 0.0),
        ("stalled_backend_cycles", 0.0),
    ] {
        row[format!("{key}_per_second")] = json!(rate);
        row["metrics"][key] = json!({
            "available": true, "error": null,
            "raw_total": rate as u64 + 1_000, "raw_delta": rate as u64,
            "scaled_delta": rate, "per_second": rate,
            "time_enabled_ns": 10_000_000_000_u64,
            "time_running_ns": 10_000_000_000_u64,
            "enabled_delta_ns": 1_000_000_000,
            "running_delta_ns": 1_000_000_000,
            "coverage_pct": 100.0, "interval_ms": 1_000.0, "baseline": false,
        });
    }
    row
}

fn memory_snapshot() -> ExploreSnapshot {
    let mut bandwidth = ExploreGroup::available(
        "resctrl root and control groups · hardware L3 domains",
        json!({
            "source": "resctrl", "monitor": "all_control_groups",
            "domain_count": 2, "mapped_domain_count": 2,
            "features": ["mbm_local_bytes", "mbm_total_bytes", "llc_occupancy"],
            "mbm_local_bps": 3_000_000_000.0,
            "mbm_total_bps": 4_000_000_000.0,
            "llc_occupancy_bytes": 2_097_152,
            "scope_note": "Hardware L3 domains; no scheduler cell attribution.",
        }),
        vec![
            bandwidth_row(11, Some(3_000_000_000.0), Some(2_500_000_000.0)),
            bandwidth_row(0, Some(1_000_000_000.0), Some(500_000_000.0)),
        ],
    );
    bandwidth.meta = meta(7, 9, 1_400);
    let mut perf_summary = cache_summary(Some(1_000_000_000.0), Some(130_000_000.0), Some(13.0));
    perf_summary["cpu_count"] = json!(4);
    perf_summary["available_cpus"] = json!(4);
    perf_summary["sampled_cpus"] = json!(4);
    for count in perf_summary["metric_cpu_counts"]
        .as_object_mut()
        .unwrap()
        .values_mut()
    {
        *count = json!(4);
    }
    perf_summary["ipc_sampled_cpus"] = json!(4);
    perf_summary["cache_sampled_cpus"] = json!(4);
    perf_summary["cycles_per_second"] = json!(4_000_000_000.0);
    perf_summary["instructions_per_second"] = json!(8_000_000_000.0);
    perf_summary["interval_ms"] = json!(1_000.0);
    perf_summary["open_descriptors"] = json!(24);
    perf_summary["descriptor_budget"] = json!(24);
    perf_summary["llc_unknown_cpus"] = json!(0);
    perf_summary["llcs"] = json!([
        cache_llc(11, Some(900_000_000.0), Some(90_000_000.0), Some(10.0)),
        cache_llc(0, Some(100_000_000.0), Some(40_000_000.0), Some(40.0)),
    ]);
    perf_summary["note"] =
        json!("Counting only; cache miss percentage uses concurrent counter pairs.");
    let mut perf = ExploreGroup::available(
        "Whole CPU: all tasks, kernel and hypervisor; generic hardware events",
        perf_summary,
        vec![
            cache_cpu(0, 0, 50_000_000.0, 20_000_000.0, 40.0),
            cache_cpu(1, 0, 50_000_000.0, 20_000_000.0, 40.0),
            cache_cpu(22, 11, 450_000_000.0, 45_000_000.0, 10.0),
            cache_cpu(23, 11, 450_000_000.0, 45_000_000.0, 10.0),
        ],
    );
    perf.meta = meta(8, 4, 1_200);
    let mut result = ExploreSnapshot {
        meta: meta(3, 1, 1_500),
        collector: observer(3),
        ..ExploreSnapshot::default()
    };
    result.groups.insert("bandwidth".into(), bandwidth);
    result.groups.insert("perf".into(), perf);
    result
}

fn record(history: &mut ReplayHistory, epoch: u64, seq: u64, at: u64, explore: ExploreSnapshot) {
    assert!(history
        .record_with_explore(at, &observer(epoch), sources(epoch, seq, at), Some(explore))
        .unwrap());
}

fn frames(history: &mut ReplayHistory, now: u64) -> Vec<ReplayFrame> {
    history
        .timeline(&ReplayQuery::default(), now)
        .unwrap()
        .frames
}

fn signal(frame: &ReplayFrame, key: &str, expected: Option<f64>) {
    assert_eq!(frame.signals.get(key), Some(&expected), "{key}");
}

#[test]
fn compact_history_projects_sparse_llcs_with_raw_units_and_weighted_totals() {
    let mut history = ReplayHistory::new();
    record(&mut history, 3, 1, 2_000, memory_snapshot());
    let captured = frames(&mut history, 2_000);
    let frame = &captured[0];
    for (key, expected) in [
        ("explore.bandwidth.mbm_total_bps", 4_000_000_000.0),
        ("explore.bandwidth.mbm_local_bps", 3_000_000_000.0),
        ("explore.bandwidth.llc.0.mbm_total_bps", 1_000_000_000.0),
        ("explore.bandwidth.llc.0.mbm_local_bps", 500_000_000.0),
        ("explore.bandwidth.llc.11.mbm_total_bps", 3_000_000_000.0),
        ("explore.bandwidth.llc.11.mbm_local_bps", 2_500_000_000.0),
        ("explore.perf.cache_references_per_second", 1_000_000_000.0),
        ("explore.perf.cache_misses_per_second", 130_000_000.0),
        ("explore.perf.cache_miss_pct", 13.0),
        (
            "explore.perf.llc.0.cache_references_per_second",
            100_000_000.0,
        ),
        ("explore.perf.llc.0.cache_misses_per_second", 40_000_000.0),
        ("explore.perf.llc.0.cache_miss_pct", 40.0),
        (
            "explore.perf.llc.11.cache_references_per_second",
            900_000_000.0,
        ),
        ("explore.perf.llc.11.cache_misses_per_second", 90_000_000.0),
        ("explore.perf.llc.11.cache_miss_pct", 10.0),
    ] {
        signal(frame, key, Some(expected));
    }
    assert!(!frame
        .signals
        .contains_key("explore.perf.llc.1.cache_miss_pct"));
    assert!(!frame
        .signals
        .contains_key("explore.bandwidth.llc.1.mbm_total_bps"));
}

#[test]
fn partial_samples_keep_missing_values_and_real_zero_and_preserve_paired_percentages() {
    let mut explore = memory_snapshot();
    let bandwidth = explore.groups.get_mut("bandwidth").unwrap();
    bandwidth.partial = true;
    bandwidth.error = Some("One L3 domain has an unsupported local counter".into());
    bandwidth.summary["mbm_total_bps"] = Value::Null;
    bandwidth.summary["mbm_local_bps"] = Value::Null;
    bandwidth.rows = vec![
        bandwidth_row(0, Some(0.0), None),
        bandwidth_row(11, None, Some(500_000_000.0)),
        bandwidth_row(13, Some(-1.0), Some(0.0)),
        bandwidth_row(17, Some(0.0), Some(0.0)),
        bandwidth_row(19, Some(0.0), Some(0.0)),
    ];
    bandwidth.rows[2]["local_status"] = json!("unsupported");
    bandwidth.rows[3]["total_status"] = json!("reset");
    bandwidth.rows[3]["mbm_local_bps"] = json!("0");
    bandwidth.rows[4]["topology_available"] = json!(false);
    let perf = explore.groups.get_mut("perf").unwrap();
    perf.partial = true;
    perf.summary["partial"] = json!(true);
    perf.summary["cache_references_per_second"] = json!(1_000.0);
    perf.summary["cache_misses_per_second"] = json!(40.0);
    // Only one CPU has a concurrent pair: 40 misses / 100 accesses = 40%.
    // The other 900 accesses are valid for the access rate but unpaired.
    perf.summary["cache_miss_pct"] = json!(40.0);
    perf.summary["cache_sampled_cpus"] = json!(1);
    perf.summary["metric_cpu_counts"]["cache_misses"] = json!(1);
    perf.summary["llcs"] = json!([
        cache_llc(0, Some(1_000.0), Some(40.0), Some(40.0)),
        cache_llc(11, Some(0.0), Some(0.0), None),
        cache_llc(13, None, None, None),
        cache_llc(17, Some(-10.0), Some(-1.0), Some(-10.0)),
        cache_llc(19, None, None, None),
    ]);
    perf.summary["llcs"][0]["partial"] = json!(true);
    perf.summary["llcs"][0]["cache_sampled_cpus"] = json!(1);
    perf.summary["llcs"][4]
        .as_object_mut()
        .unwrap()
        .remove("cache_references_per_second");
    let mut history = ReplayHistory::new();
    record(&mut history, 3, 1, 2_000, explore);
    let captured = frames(&mut history, 2_000);
    let frame = &captured[0];
    assert!(frame.source_available["explore.bandwidth"]);
    assert!(frame.source_available["explore.perf"]);
    for key in [
        "explore.bandwidth.mbm_total_bps",
        "explore.bandwidth.mbm_local_bps",
        "explore.bandwidth.llc.0.mbm_local_bps",
        "explore.bandwidth.llc.11.mbm_total_bps",
        "explore.bandwidth.llc.13.mbm_total_bps",
        "explore.bandwidth.llc.13.mbm_local_bps",
        "explore.bandwidth.llc.17.mbm_total_bps",
        "explore.bandwidth.llc.17.mbm_local_bps",
        "explore.bandwidth.llc.19.mbm_total_bps",
        "explore.bandwidth.llc.19.mbm_local_bps",
        "explore.perf.llc.11.cache_miss_pct",
        "explore.perf.llc.13.cache_references_per_second",
        "explore.perf.llc.13.cache_misses_per_second",
        "explore.perf.llc.13.cache_miss_pct",
        "explore.perf.llc.17.cache_references_per_second",
        "explore.perf.llc.17.cache_misses_per_second",
        "explore.perf.llc.17.cache_miss_pct",
        "explore.perf.llc.19.cache_references_per_second",
    ] {
        signal(frame, key, None);
    }
    signal(frame, "explore.bandwidth.llc.0.mbm_total_bps", Some(0.0));
    signal(
        frame,
        "explore.bandwidth.llc.11.mbm_local_bps",
        Some(500_000_000.0),
    );
    signal(
        frame,
        "explore.perf.llc.11.cache_references_per_second",
        Some(0.0),
    );
    signal(
        frame,
        "explore.perf.llc.11.cache_misses_per_second",
        Some(0.0),
    );
    signal(frame, "explore.perf.cache_miss_pct", Some(40.0));
    signal(frame, "explore.perf.llc.0.cache_miss_pct", Some(40.0));
}

#[test]
fn invalid_numeric_memory_summaries_are_missing_without_replacing_valid_zero() {
    let mut explore = memory_snapshot();
    let bandwidth = explore.groups.get_mut("bandwidth").unwrap();
    bandwidth.summary["mbm_total_bps"] = json!(-1.0);
    bandwidth.summary["mbm_local_bps"] = json!(0.0);
    let perf = explore.groups.get_mut("perf").unwrap();
    perf.summary["cache_references_per_second"] = json!(-1.0);
    perf.summary["cache_misses_per_second"] = json!(-10.0);
    perf.summary["cache_miss_pct"] = json!(-10.0);
    let mut history = ReplayHistory::new();
    record(&mut history, 3, 1, 2_000, explore);
    let captured = frames(&mut history, 2_000);
    let frame = &captured[0];
    for key in [
        "explore.bandwidth.mbm_total_bps",
        "explore.perf.cache_references_per_second",
        "explore.perf.cache_misses_per_second",
        "explore.perf.cache_miss_pct",
    ] {
        signal(frame, key, None);
    }
    signal(frame, "explore.bandwidth.mbm_local_bps", Some(0.0));
}

#[test]
fn invalid_group_metadata_masks_partial_sources_and_clears_full_historical_values() {
    for condition in [
        "future",
        "missing_capture",
        "no_success",
        "failed",
        "unavailable",
    ] {
        let mut explore = memory_snapshot();
        for name in ["bandwidth", "perf"] {
            let group = explore.groups.get_mut(name).unwrap();
            group.partial = true;
            match condition {
                "future" => group.meta.captured_at_unix_ms = Some(3_000),
                "missing_capture" => group.meta.captured_at_unix_ms = None,
                "no_success" => group.meta.sample_seq = 0,
                "failed" => group.meta.error = Some("read failed".into()),
                "unavailable" => {
                    group.available = false;
                    group.error = Some("source unavailable".into());
                }
                _ => unreachable!(),
            }
        }
        let mut history = ReplayHistory::new();
        record(&mut history, 3, 1, 2_000, explore);
        let captured = frames(&mut history, 2_000);
        let frame = &captured[0];
        for name in ["bandwidth", "perf"] {
            assert!(
                !frame.source_available[&format!("explore.{name}")],
                "{condition}: {name}"
            );
        }
        for key in [
            "explore.bandwidth.mbm_total_bps",
            "explore.bandwidth.llc.0.mbm_total_bps",
            "explore.bandwidth.llc.11.mbm_local_bps",
            "explore.perf.cache_miss_pct",
            "explore.perf.llc.0.cache_references_per_second",
            "explore.perf.llc.11.cache_misses_per_second",
            "explore.perf.llc.11.cache_miss_pct",
        ] {
            signal(frame, key, None);
        }
        let view = history.view(None, 2_000).unwrap();
        for name in ["bandwidth", "perf"] {
            assert!(view.source_errors.contains_key(&format!("explore.{name}")));
            assert_eq!(view.sources["explore"]["groups"][name]["available"], false);
            assert_eq!(
                view.sources["explore"]["groups"][name]["summary"],
                json!({})
            );
            assert_eq!(view.sources["explore"]["groups"][name]["rows"], json!([]));
        }
    }
}

#[test]
fn duplicate_and_unknown_llc_ids_do_not_choose_arbitrary_or_indexed_values() {
    let mut explore = memory_snapshot();
    let bandwidth = explore.groups.get_mut("bandwidth").unwrap();
    bandwidth
        .rows
        .push(bandwidth_row(0, Some(99.0), Some(99.0)));
    for invalid in [
        Value::Null,
        json!(-1),
        json!(1.5),
        json!("1"),
        json!(4_294_967_296_u64),
    ] {
        let mut row = bandwidth_row(1, Some(99.0), Some(99.0));
        row["llc"] = invalid;
        bandwidth.rows.push(row);
    }
    let perf = explore.groups.get_mut("perf").unwrap();
    let llcs = perf.summary["llcs"].as_array_mut().unwrap();
    llcs.push(cache_llc(0, Some(99.0), Some(99.0), Some(99.0)));
    for invalid in [
        Value::Null,
        json!(-1),
        json!(1.5),
        json!("1"),
        json!(4_294_967_296_u64),
    ] {
        let mut row = cache_llc(1, Some(99.0), Some(99.0), Some(99.0));
        row["llc_id"] = invalid;
        llcs.push(row);
    }
    let mut history = ReplayHistory::new();
    record(&mut history, 3, 1, 2_000, explore);
    let captured = frames(&mut history, 2_000);
    let frame = &captured[0];
    for key in [
        "explore.bandwidth.llc.0.mbm_total_bps",
        "explore.bandwidth.llc.0.mbm_local_bps",
        "explore.perf.llc.0.cache_references_per_second",
        "explore.perf.llc.0.cache_misses_per_second",
        "explore.perf.llc.0.cache_miss_pct",
    ] {
        signal(frame, key, None);
    }
    signal(
        frame,
        "explore.bandwidth.llc.11.mbm_total_bps",
        Some(3_000_000_000.0),
    );
    signal(frame, "explore.perf.llc.11.cache_miss_pct", Some(10.0));
    for key in frame.signals.keys().filter(|key| key.contains(".llc.")) {
        assert!(
            key.contains(".llc.0.") || key.contains(".llc.11."),
            "unexpected key: {key}"
        );
    }
}

#[test]
fn full_u32_llc_ids_keep_measured_zero_rates_and_zero_percentages() {
    let mut explore = memory_snapshot();
    let bandwidth = explore.groups.get_mut("bandwidth").unwrap();
    bandwidth.summary["domain_count"] = json!(1);
    bandwidth.summary["mapped_domain_count"] = json!(1);
    bandwidth.summary["mbm_total_bps"] = json!(0.0);
    bandwidth.summary["mbm_local_bps"] = json!(0.0);
    let mut row = bandwidth_row(0, Some(0.0), Some(0.0));
    row["llc"] = json!(u32::MAX);
    bandwidth.rows = vec![row];
    let perf = explore.groups.get_mut("perf").unwrap();
    let mut summary = cache_summary(Some(250.0), Some(0.0), Some(0.0));
    summary["llcs"] = json!([cache_llc(u32::MAX, Some(250.0), Some(0.0), Some(0.0))]);
    summary["interval_ms"] = json!(1_000.0);
    summary["open_descriptors"] = json!(12);
    summary["descriptor_budget"] = json!(12);
    summary["llc_unknown_cpus"] = json!(0);
    perf.summary = summary;
    perf.rows = vec![
        cache_cpu(0, u32::MAX, 125.0, 0.0, 0.0),
        cache_cpu(1, u32::MAX, 125.0, 0.0, 0.0),
    ];
    let mut history = ReplayHistory::new();
    record(&mut history, 3, 1, 2_000, explore);
    let captured = frames(&mut history, 2_000);
    let frame = &captured[0];
    for key in [
        "explore.bandwidth.mbm_total_bps",
        "explore.bandwidth.mbm_local_bps",
        "explore.bandwidth.llc.4294967295.mbm_total_bps",
        "explore.bandwidth.llc.4294967295.mbm_local_bps",
        "explore.perf.cache_misses_per_second",
        "explore.perf.cache_miss_pct",
        "explore.perf.llc.4294967295.cache_misses_per_second",
        "explore.perf.llc.4294967295.cache_miss_pct",
    ] {
        signal(frame, key, Some(0.0));
    }
    signal(
        frame,
        "explore.perf.llc.4294967295.cache_references_per_second",
        Some(250.0),
    );
    assert!(!frame
        .signals
        .contains_key("explore.perf.llc.0.cache_miss_pct"));
}

#[test]
fn independent_memory_sources_keep_valid_cached_values_during_failure_and_recovery() {
    let mut history = ReplayHistory::new();
    let mut failed = memory_snapshot();
    failed.groups.get_mut("bandwidth").unwrap().meta.error = Some("resctrl read failed".into());
    record(&mut history, 3, 1, 2_000, failed.clone());
    record(&mut history, 3, 2, 3_000, failed);
    let mut recovered = memory_snapshot();
    recovered.groups.get_mut("bandwidth").unwrap().meta = meta(7, 10, 3_900);
    record(&mut history, 3, 3, 4_000, recovered.clone());
    recovered.groups.get_mut("perf").unwrap().meta = meta(8, 5, 5_500);
    record(&mut history, 3, 4, 5_000, recovered);
    let captured = frames(&mut history, 5_000);
    for frame in &captured[..2] {
        assert!(!frame.source_available["explore.bandwidth"]);
        assert!(frame.source_available["explore.perf"]);
        signal(frame, "explore.bandwidth.llc.0.mbm_total_bps", None);
        signal(frame, "explore.perf.llc.0.cache_miss_pct", Some(40.0));
        assert_eq!(
            frame.source_meta["explore.bandwidth"].captured_at_unix_ms,
            Some(1_400)
        );
        assert_eq!(frame.source_meta["explore.perf"], meta(8, 4, 1_200));
    }
    assert!(captured[2].source_available["explore.bandwidth"]);
    assert!(captured[2].source_available["explore.perf"]);
    assert_eq!(
        captured[2].source_meta["explore.bandwidth"],
        meta(7, 10, 3_900)
    );
    signal(
        &captured[2],
        "explore.bandwidth.llc.0.mbm_total_bps",
        Some(1_000_000_000.0),
    );
    assert!(captured[3].source_available["explore.bandwidth"]);
    assert!(!captured[3].source_available["explore.perf"]);
    signal(
        &captured[3],
        "explore.bandwidth.llc.0.mbm_total_bps",
        Some(1_000_000_000.0),
    );
    signal(&captured[3], "explore.perf.llc.0.cache_miss_pct", None);
    let failed_view = history.view(Some(3_500), 5_000).unwrap();
    assert_eq!(
        failed_view.sources["explore"]["groups"]["bandwidth"]["rows"],
        json!([])
    );
    assert_eq!(
        failed_view.sources["explore"]["groups"]["perf"]["summary"]["cache_miss_pct"],
        13.0
    );
    let recovered_view = history.view(Some(4_500), 5_000).unwrap();
    assert_eq!(
        recovered_view.sources["explore"]["groups"]["bandwidth"]["rows"][1]["mbm_total_bps"],
        1_000_000_000.0
    );
}

#[test]
fn cached_llc_values_keep_group_metadata_and_epochs_across_full_rewind() {
    let mut history = ReplayHistory::new();
    record(&mut history, 3, 1, 2_000, memory_snapshot());
    record(&mut history, 3, 2, 3_000, memory_snapshot());
    let mut next = memory_snapshot();
    next.meta = meta(4, 1, 3_950);
    next.collector = observer(4);
    next.groups.get_mut("bandwidth").unwrap().meta = meta(9, 1, 3_900);
    next.groups.get_mut("bandwidth").unwrap().rows[1]["mbm_total_bps"] = json!(2_000_000_000.0);
    next.groups.get_mut("perf").unwrap().meta = meta(10, 1, 3_800);
    next.groups.get_mut("perf").unwrap().summary["llcs"][1]["cache_miss_pct"] = json!(20.0);
    record(&mut history, 4, 1, 4_000, next);
    let captured = frames(&mut history, 4_000);
    assert_eq!(
        captured.iter().map(|frame| frame.seq).collect::<Vec<_>>(),
        [1, 2, 3]
    );
    for frame in &captured[..2] {
        assert_eq!(frame.source_meta["explore.bandwidth"], meta(7, 9, 1_400));
        assert_eq!(frame.source_meta["explore.perf"], meta(8, 4, 1_200));
        assert_eq!(frame.epochs["explore.bandwidth"], 7);
        assert_eq!(frame.epochs["explore.perf"], 8);
        signal(
            frame,
            "explore.bandwidth.llc.0.mbm_total_bps",
            Some(1_000_000_000.0),
        );
        signal(frame, "explore.perf.llc.0.cache_miss_pct", Some(40.0));
        assert!(!frame.source_meta.keys().any(|key| key.contains(".llc.")));
    }
    assert_eq!(
        captured[2].source_meta["explore.bandwidth"],
        meta(9, 1, 3_900)
    );
    assert_eq!(captured[2].source_meta["explore.perf"], meta(10, 1, 3_800));
    signal(
        &captured[2],
        "explore.bandwidth.llc.0.mbm_total_bps",
        Some(2_000_000_000.0),
    );
    signal(
        &captured[2],
        "explore.perf.llc.0.cache_miss_pct",
        Some(20.0),
    );
    let view = history.view(Some(3_500), 4_000).unwrap();
    assert_eq!(view.at_unix_ms, 3_000);
    assert_eq!(view.collector.epoch, 3);
    assert_eq!(
        view.sources["explore"]["groups"]["bandwidth"]["meta"]["sample_seq"],
        9
    );
    assert_eq!(
        view.sources["explore"]["groups"]["bandwidth"]["meta"]["captured_at_unix_ms"],
        1_400
    );
    assert_eq!(
        view.sources["explore"]["groups"]["bandwidth"]["rows"][1]["llc"],
        0
    );
    assert_eq!(
        view.sources["explore"]["groups"]["bandwidth"]["rows"][1]["mbm_total_bps"],
        1_000_000_000.0
    );
    assert_eq!(
        view.sources["explore"]["groups"]["perf"]["summary"]["llcs"][1]["cache_miss_pct"],
        40.0
    );
}
