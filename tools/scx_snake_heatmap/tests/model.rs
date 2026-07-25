// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::BTreeMap;

use scx_snake_heatmap::model::{CpuPair, RollingHistory};

fn counters(entries: &[(CpuPair, u64)]) -> BTreeMap<CpuPair, u64> {
    entries.iter().copied().collect()
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
