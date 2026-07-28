// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::BTreeMap;

use scx_snake_inspector::model::{
    summarize_callback_timing, CallbackTimingCounters, CallbackTimingHistory,
    CallbackTimingSnapshot, CpuPair, CpuUsageHistory, RollingHistory,
};

fn counters(entries: &[(CpuPair, u64)]) -> BTreeMap<CpuPair, u64> {
    entries.iter().copied().collect()
}

fn timing(total_ns: u64, buckets: &[(usize, u64)]) -> CallbackTimingCounters {
    let mut counts = vec![0; 64];
    for &(bucket, count) in buckets {
        counts[bucket] = count;
    }
    CallbackTimingCounters {
        total_ns,
        buckets: counts,
    }
}

fn timing_snapshot(
    enable_seq: u64,
    generation: u64,
    dispatch: CallbackTimingCounters,
) -> CallbackTimingSnapshot {
    CallbackTimingSnapshot {
        enable_seq,
        generation,
        sample_rate: 64,
        callbacks: BTreeMap::from([("dispatch".into(), dispatch)]),
    }
}

#[test]
fn callback_timing_history_exposes_window_deltas_and_lifetime_totals() {
    let mut history = CallbackTimingHistory::new(5_000);
    history.ingest(0, timing_snapshot(4, 7, timing(100, &[(3, 10)])));
    history.ingest(1_000, timing_snapshot(4, 7, timing(180, &[(3, 14)])));

    let window = history.window(1_000, 2_000).unwrap().unwrap();
    assert_eq!(window.observed_ms, 1_000);
    assert_eq!(window.callbacks["dispatch"], timing(80, &[(3, 4)]));

    let lifetime = history.lifetime().unwrap();
    assert_eq!(lifetime.generation, 7);
    assert_eq!(lifetime.callbacks["dispatch"], timing(180, &[(3, 14)]));
}

#[test]
fn callback_timing_history_resets_on_scheduler_or_policy_generation_change() {
    let mut history = CallbackTimingHistory::new(5_000);
    history.ingest(0, timing_snapshot(4, 7, timing(100, &[(3, 10)])));
    history.ingest(1_000, timing_snapshot(4, 7, timing(180, &[(3, 14)])));
    history.ingest(2_000, timing_snapshot(4, 8, timing(30, &[(2, 3)])));

    let window = history.window(2_000, 5_000).unwrap().unwrap();
    assert_eq!(window.observed_ms, 0);
    assert_eq!(window.callbacks["dispatch"], timing(0, &[]));
    assert_eq!(
        history.lifetime().unwrap().callbacks["dispatch"],
        timing(30, &[(2, 3)])
    );

    history.ingest(3_000, timing_snapshot(5, 8, timing(7, &[(1, 1)])));
    assert_eq!(
        history.window(3_000, 5_000).unwrap().unwrap().observed_ms,
        0
    );
}

#[test]
fn callback_timing_summary_uses_log_bucket_upper_bounds_and_sample_thresholds() {
    let summary = summarize_callback_timing(&timing(2_000, &[(3, 50), (5, 50)]));

    assert_eq!(summary.samples, 100);
    assert_eq!(summary.mean_ns, Some(20));
    assert_eq!(summary.p50_ns, Some(15));
    assert_eq!(summary.p95_ns, Some(63));
    assert_eq!(summary.p99_ns, Some(63));

    let sparse = summarize_callback_timing(&timing(990, &[(4, 99)]));
    assert_eq!(sparse.p50_ns, Some(31));
    assert_eq!(sparse.p95_ns, Some(31));
    assert_eq!(sparse.p99_ns, None);
}

#[test]
fn rolling_view_contains_only_deltas_inside_the_window() {
    let pair = CpuPair::new(2, 7);
    let mut history = RollingHistory::new(5_000);

    history.ingest(0, &BTreeMap::new());
    history.ingest(250, &counters(&[(pair, 3)]));
    history.ingest(500, &counters(&[(pair, 5)]));

    let full = history.view(500, 500).unwrap();
    assert_eq!(full.total, 5);
    assert_eq!(full.cells, counters(&[(pair, 5)]));
    assert_eq!(full.observed_ms, 500);

    let recent = history.view(600, 300).unwrap();
    assert_eq!(recent.total, 2);
    assert_eq!(recent.cells, counters(&[(pair, 2)]));
    assert_eq!(recent.observed_ms, 300);
}

#[test]
fn a_decreased_counter_is_treated_as_a_new_counter_epoch() {
    let pair = CpuPair::new(1, 3);
    let mut history = RollingHistory::new(5_000);

    history.ingest(0, &counters(&[(pair, 10)]));
    history.ingest(250, &counters(&[(pair, 2)]));

    let view = history.view(250, 500).unwrap();
    assert_eq!(view.total, 2);
    assert_eq!(view.cells, counters(&[(pair, 2)]));
}

#[test]
fn reset_discards_old_scope_and_uses_the_new_baseline() {
    let pair = CpuPair::new(4, 9);
    let mut history = RollingHistory::new(5_000);

    history.ingest(0, &BTreeMap::new());
    history.ingest(250, &counters(&[(pair, 8)]));
    history.reset(300, &counters(&[(pair, 8)]));
    history.ingest(550, &counters(&[(pair, 11)]));

    let view = history.view(550, 1_000).unwrap();
    assert_eq!(view.total, 3);
    assert_eq!(view.cells, counters(&[(pair, 3)]));
    assert_eq!(view.observed_ms, 250);
}

#[test]
fn invalid_windows_are_rejected() {
    let history = RollingHistory::new(5_000);

    assert!(history.view(0, 0).is_err());
    assert!(history.view(0, 5_001).is_err());
}

#[test]
fn cpu_usage_view_sums_runtime_deltas_inside_the_window() {
    let mut history = CpuUsageHistory::new(5_000);
    history.reset(0);
    history.ingest(250, &BTreeMap::from([(0, 100_000_000), (1, 200_000_000)]));
    history.ingest(500, &BTreeMap::from([(0, 50_000_000), (1, 25_000_000)]));

    let full = history.view(500, 500).unwrap();
    assert_eq!(
        full.runtime_ns,
        BTreeMap::from([(0, 150_000_000), (1, 225_000_000)])
    );
    assert_eq!(full.observed_ms, 500);

    let recent = history.view(600, 300).unwrap();
    assert_eq!(
        recent.runtime_ns,
        BTreeMap::from([(0, 50_000_000), (1, 25_000_000)])
    );
    assert_eq!(recent.observed_ms, 300);
}

#[test]
fn cpu_usage_reset_discards_runtime_from_the_previous_scheduler_epoch() {
    let mut history = CpuUsageHistory::new(5_000);
    history.reset(0);
    history.ingest(250, &BTreeMap::from([(0, 200_000_000)]));
    history.reset(300);
    history.ingest(550, &BTreeMap::from([(0, 75_000_000)]));

    let view = history.view(550, 1_000).unwrap();
    assert_eq!(view.runtime_ns, BTreeMap::from([(0, 75_000_000)]));
    assert_eq!(view.observed_ms, 250);
}
