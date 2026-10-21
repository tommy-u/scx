pub use scx_mitosis_inspector::{collector, lifecycle, migration_history, topology, MigrationRow};

#[path = "../src/replay_migrations.rs"]
mod replay_migrations;

use collector::{CollectorConfig, Snapshot};
use lifecycle::{CollectorStatus, ObserverContext, SampleMeta};
use replay_migrations::ReplayMigrationHistory;
use topology::{CpuInfo, TopologyView};

fn topology() -> TopologyView {
    TopologyView::from_cpus(vec![
        CpuInfo {
            cpu: 0,
            node: 0,
            package: 0,
            llc: 0,
            core: 0,
            core_topology_available: true,
        },
        CpuInfo {
            cpu: 1,
            node: 0,
            package: 0,
            llc: 0,
            core: 0,
            core_topology_available: true,
        },
        CpuInfo {
            cpu: 2,
            node: 0,
            package: 0,
            llc: 0,
            core: 1,
            core_topology_available: true,
        },
        CpuInfo {
            cpu: 3,
            node: 0,
            package: 0,
            llc: 1,
            core: 2,
            core_topology_available: true,
        },
        CpuInfo {
            cpu: 4,
            node: 1,
            package: 1,
            llc: 2,
            core: 0,
            core_topology_available: true,
        },
    ])
    .unwrap()
}

fn sample(at: u64, epoch: u64, seq: u64, pairs: &[(u32, u32, u64)]) -> Snapshot {
    let mut snapshot = Snapshot::empty(CollectorConfig {
        callback_timing_sample_rate: 1,
        event_timing_sample_rate: 1,
        enable_dsq: true,
        enable_scheduler_events: true,
        enable_irqs: true,
        enable_block_io: true,
    });
    snapshot.meta = SampleMeta {
        epoch,
        sample_seq: seq,
        captured_at_unix_ms: Some(at),
        last_success_at_unix_ms: Some(at),
        error: None,
    };
    snapshot.collector = ObserverContext {
        epoch,
        status: CollectorStatus::Active,
        scheduler_enable_seq: Some(epoch),
        scheduler_name: Some("mitosis".into()),
        error: None,
    };
    snapshot.migration_map_capacity = 25600;
    snapshot.migration_quality = "complete";
    snapshot.migrations = pairs
        .iter()
        .map(|&(from_cpu, to_cpu, count)| MigrationRow {
            from_cpu,
            to_cpu,
            count,
        })
        .collect();
    snapshot
}

#[test]
fn past_window_excludes_future_bins_and_uses_metadata_from_that_time() {
    let mut history = ReplayMigrationHistory::new(30 * 60_000, 5 * 60_000, &topology());
    history.ingest(10_000, &sample(10_000, 1, 1, &[(0, 2, 100)]));
    let selected = sample(11_000, 1, 2, &[(0, 2, 130)]);
    history.ingest(11_000, &selected);
    history.ingest(12_000, &sample(12_000, 1, 3, &[(0, 2, 900)]));

    let view = history.view_at(11_000, 1, 1_000).unwrap();
    assert_eq!(view.total, 30);
    assert_eq!(
        view.rows,
        vec![MigrationRow {
            from_cpu: 0,
            to_cpu: 2,
            count: 30
        }]
    );
    assert_eq!(view.meta, selected.meta);
    assert_eq!(view.collector, selected.collector);
    assert_eq!(view.observed_ms, 1_000);
    assert_eq!(view.rate_per_second, 30.0);
    assert_eq!(view.migration_quality, "complete");
}

#[test]
fn historical_epochs_remain_available_without_mixing_new_scheduler_counts() {
    let mut history = ReplayMigrationHistory::new(30 * 60_000, 5_000, &topology());
    history.ingest(10_000, &sample(10_000, 1, 1, &[(0, 2, 100)]));
    history.ingest(11_000, &sample(11_000, 1, 2, &[(0, 2, 110)]));
    history.ingest(12_000, &sample(12_000, 2, 1, &[(0, 2, 8_000)]));
    history.ingest(13_000, &sample(13_000, 2, 2, &[(0, 2, 8_005)]));

    assert_eq!(history.view_at(11_000, 1, 1_000).unwrap().total, 10);
    let restarted = history.view_at(13_000, 2, 3_000).unwrap();
    assert_eq!(restarted.total, 5);
    assert_eq!(restarted.observed_ms, 1_000);
    assert_eq!(restarted.migration_quality, "incomplete");
    let before_start = history.view_at(11_000, 2, 1_000).unwrap();
    assert_eq!(before_start.migration_quality, "unavailable");
    assert_eq!(before_start.meta.captured_at_unix_ms, None);
}

#[test]
fn custom_window_includes_only_bins_ending_inside_that_window() {
    let mut history = ReplayMigrationHistory::new(30 * 60_000, 5_000, &topology());
    for (seq, count) in [(1, 100), (2, 110), (3, 130)] {
        let at = 9_000 + seq * 1_000;
        history.ingest(at, &sample(at, 1, seq, &[(0, 2, count)]));
    }
    assert_eq!(history.view_at(12_000, 1, 1_000).unwrap().total, 20);
    assert_eq!(history.view_at(12_000, 1, 2_000).unwrap().total, 30);
    assert_eq!(
        history.view_at(12_000, 1, 2_000).unwrap().observed_ms,
        2_000
    );
    assert_eq!(
        history.view_at(12_000, 1, 3_000).unwrap().observed_ms,
        2_000
    );
}

#[test]
fn missing_collection_is_unavailable_and_recovery_does_not_bridge_the_gap() {
    let mut history = ReplayMigrationHistory::new(30 * 60_000, 5_000, &topology());
    history.ingest(10_000, &sample(10_000, 1, 1, &[(0, 2, 100)]));
    history.ingest(11_000, &sample(11_000, 1, 2, &[(0, 2, 110)]));
    let mut failed = sample(12_000, 1, 3, &[]);
    failed.meta.error = Some("migration map read failed".into());
    failed.meta.captured_at_unix_ms = None;
    failed.meta.last_success_at_unix_ms = Some(11_000);
    failed.collector.status = CollectorStatus::Error;
    failed.collector.error = failed.meta.error.clone();
    failed.migration_quality = "unavailable";
    failed.migration_map_capacity = 0;
    history.ingest(12_000, &failed);

    let unavailable = history.view_at(12_000, 1, 3_000).unwrap();
    assert_eq!(unavailable.migration_quality, "unavailable");
    assert_eq!(unavailable.meta, failed.meta);
    assert_eq!(history.locality_at(12_000, 1, 3_000).unwrap(), [None; 4]);

    history.ingest(13_000, &sample(13_000, 1, 4, &[(0, 2, 900)]));
    history.ingest(14_000, &sample(14_000, 1, 5, &[(0, 2, 905)]));
    let recovered = history.view_at(14_000, 1, 5_000).unwrap();
    assert_eq!(recovered.total, 15);
    assert_eq!(recovered.observed_ms, 2_000);
    assert_eq!(recovered.migration_quality, "incomplete");
}

#[test]
fn known_empty_interval_is_a_real_zero_but_first_sample_has_no_delta() {
    let mut history = ReplayMigrationHistory::new(30 * 60_000, 5_000, &topology());
    history.ingest(10_000, &sample(10_000, 1, 1, &[]));
    let initial = history.view_at(10_000, 1, 1_000).unwrap();
    assert_eq!(initial.total, 0);
    assert_eq!(initial.observed_ms, 0);
    assert_eq!(initial.migration_quality, "unavailable");
    history.ingest(11_000, &sample(11_000, 1, 2, &[]));
    let known = history.view_at(11_000, 1, 1_000).unwrap();
    assert_eq!(known.total, 0);
    assert_eq!(known.observed_ms, 1_000);
    assert_eq!(known.migration_quality, "complete");
    assert_eq!(
        history.locality_at(11_000, 1, 1_000).unwrap(),
        [Some(0.0); 4]
    );
}

#[test]
fn counter_rollback_sets_a_new_baseline_without_fabricated_migrations() {
    let mut history = ReplayMigrationHistory::new(30 * 60_000, 5_000, &topology());
    history.ingest(10_000, &sample(10_000, 1, 1, &[(0, 2, 100)]));
    history.ingest(11_000, &sample(11_000, 1, 2, &[(0, 2, 110)]));
    history.ingest(12_000, &sample(12_000, 1, 3, &[(0, 2, 3)]));
    let rollback = history.view_at(12_000, 1, 3_000).unwrap();
    assert_eq!(rollback.total, 10);
    assert_eq!(rollback.observed_ms, 1_000);
    assert_eq!(rollback.migration_quality, "incomplete");
    history.ingest(13_000, &sample(13_000, 1, 4, &[(0, 2, 5)]));
    assert_eq!(history.view_at(13_000, 1, 1_000).unwrap().total, 2);
}

#[test]
fn disappearing_map_entries_do_not_make_reappearing_lifetime_counts_into_deltas() {
    let mut history = ReplayMigrationHistory::new(30 * 60_000, 5_000, &topology());
    history.ingest(10_000, &sample(10_000, 1, 1, &[(0, 2, 100)]));
    history.ingest(11_000, &sample(11_000, 1, 2, &[]));
    history.ingest(12_000, &sample(12_000, 1, 3, &[(0, 2, 5_000)]));
    assert_eq!(history.view_at(12_000, 1, 3_000).unwrap().total, 0);
    history.ingest(13_000, &sample(13_000, 1, 4, &[(0, 2, 5_005)]));
    assert_eq!(history.view_at(13_000, 1, 1_000).unwrap().total, 5);
}

#[test]
fn duplicate_replay_reads_do_not_create_new_counter_intervals() {
    let mut history = ReplayMigrationHistory::new(30 * 60_000, 5_000, &topology());
    history.ingest(10_000, &sample(10_000, 1, 1, &[(0, 2, 100)]));
    let snapshot = sample(11_000, 1, 2, &[(0, 2, 130)]);
    history.ingest(11_005, &snapshot);
    history.ingest(12_005, &snapshot);
    let view = history.view_at(12_000, 1, 2_000).unwrap();
    assert_eq!(view.total, 30);
    assert_eq!(view.meta.captured_at_unix_ms, Some(11_000));
    assert_eq!(view.observed_ms, 1_000);
}

#[test]
fn complete_capture_coverage_keeps_the_frame_cutoff_without_inventing_the_uncaptured_tail() {
    let mut history = ReplayMigrationHistory::new(30 * 60_000, 10_000, &topology());
    for seq in 1..=11 {
        let at = 9_000 + seq * 1_000;
        history.ingest(at, &sample(at, 1, seq, &[(0, 2, 100 + seq)]));
    }

    // The frame follows its original counter capture by 190 ms. All measured
    // intervals from the frame's 10-second cutoff to that capture are retained.
    let view = history.view_at(20_190, 1, 10_000).unwrap();
    assert_eq!(view.meta.captured_at_unix_ms, Some(20_000));
    assert_eq!(view.window_ms, 10_000);
    assert_eq!(view.observed_ms, 9_810);
    assert_eq!(view.total, 10);
    assert_eq!(view.migration_quality, "complete");

    // A sample ending exactly at the historical cutoff remains excluded.
    let cutoff = history.view_at(21_000, 1, 1_000).unwrap();
    assert_eq!(cutoff.total, 0);
    assert_eq!(cutoff.observed_ms, 0);
    assert_eq!(cutoff.migration_quality, "unavailable");
}

#[test]
fn capture_aligned_quality_preserves_missing_intervals_and_map_loss() {
    let mut history = ReplayMigrationHistory::new(30 * 60_000, 10_000, &topology());
    history.ingest(10_000, &sample(10_000, 1, 1, &[]));
    history.ingest(11_000, &sample(11_000, 1, 2, &[(0, 2, 10)]));
    history.ingest(15_000, &sample(15_000, 1, 3, &[(0, 2, 5_000)]));
    history.ingest(16_000, &sample(16_000, 1, 4, &[(0, 2, 5_005)]));
    let gap = history.view_at(16_190, 1, 5_000).unwrap();
    assert_eq!(gap.total, 5);
    assert_eq!(gap.observed_ms, 1_000);
    assert_eq!(gap.migration_quality, "incomplete");

    let mut lost = sample(17_000, 1, 5, &[(0, 2, 5_010)]);
    lost.migration_map_failures = 1;
    lost.migration_quality = "incomplete";
    history.ingest(17_000, &lost);
    let loss = history.view_at(17_190, 1, 1_000).unwrap();
    assert_eq!(loss.observed_ms, 810);
    assert_eq!(loss.migration_map_failures, 1);
    assert_eq!(loss.migration_quality, "incomplete");
}

#[test]
fn stale_capture_does_not_hide_a_trailing_collection_gap() {
    let mut history = ReplayMigrationHistory::new(30 * 60_000, 10_000, &topology());
    for seq in 1..=11 {
        let at = 9_000 + seq * 1_000;
        history.ingest(at, &sample(at, 1, seq, &[(0, 2, 100 + seq)]));
    }

    // A four-second tail exceeds the existing trustworthy collection interval.
    // Known older intervals remain queryable, but that delay is a real gap.
    let view = history.view_at(24_000, 1, 10_000).unwrap();
    assert_eq!(view.meta.captured_at_unix_ms, Some(20_000));
    assert_eq!(view.observed_ms, 6_000);
    assert_eq!(view.total, 6);
    assert_eq!(view.migration_quality, "incomplete");
}

#[test]
fn long_gaps_do_not_claim_unobserved_counter_coverage() {
    let mut history = ReplayMigrationHistory::new(30 * 60_000, 10_000, &topology());
    history.ingest(10_000, &sample(10_000, 1, 1, &[(0, 2, 100)]));
    history.ingest(11_000, &sample(11_000, 1, 2, &[(0, 2, 110)]));
    history.ingest(20_000, &sample(20_000, 1, 3, &[(0, 2, 1_100)]));
    let gap = history.view_at(20_000, 1, 10_000).unwrap();
    assert_eq!(gap.total, 10);
    assert_eq!(gap.observed_ms, 1_000);
    assert_eq!(gap.migration_quality, "incomplete");
    history.ingest(21_000, &sample(21_000, 1, 4, &[(0, 2, 1_105)]));
    assert_eq!(history.view_at(21_000, 1, 1_000).unwrap().total, 5);
}

#[test]
fn time_retention_keeps_preceding_window_but_reports_evicted_coverage() {
    let mut history = ReplayMigrationHistory::new(3_000, 2_000, &topology());
    for seq in 1..=8 {
        let at = 9_000 + seq * 1_000;
        history.ingest(at, &sample(at, 1, seq, &[(0, 2, 100 + seq)]));
    }
    assert_eq!(history.oldest_at_unix_ms(), Some(12_000));
    let full = history.view_at(17_000, 1, 2_000).unwrap();
    assert_eq!(full.total, 2);
    assert_eq!(full.observed_ms, 2_000);
    assert_eq!(full.migration_quality, "complete");
    let clipped = history.view_at(13_000, 1, 2_000).unwrap();
    assert_eq!(clipped.total, 1);
    assert_eq!(clipped.observed_ms, 1_000);
    assert_eq!(clipped.migration_quality, "incomplete");
    assert_eq!(
        history.view_at(11_000, 1, 1_000).unwrap().migration_quality,
        "unavailable"
    );
    assert!(history.retained_bytes() > 0);
}

#[test]
fn locality_uses_four_exclusive_physical_categories_and_excludes_future() {
    let mut history = ReplayMigrationHistory::new(30 * 60_000, 5_000, &topology());
    history.ingest(10_000, &sample(10_000, 1, 1, &[]));
    history.ingest(
        11_000,
        &sample(
            11_000,
            1,
            2,
            &[(0, 1, 20), (0, 2, 30), (0, 3, 10), (0, 4, 40)],
        ),
    );
    history.ingest(
        12_000,
        &sample(
            12_000,
            1,
            3,
            &[(0, 1, 20), (0, 2, 10_030), (0, 3, 10), (0, 4, 40)],
        ),
    );
    assert_eq!(
        history.locality_at(11_000, 1, 1_000).unwrap(),
        [Some(20.0), Some(30.0), Some(10.0), Some(40.0)]
    );
}

#[test]
fn unavailable_physical_core_topology_does_not_publish_fake_locality_percentages() {
    let mut cpus = topology().cpus;
    cpus[1].core_topology_available = false;
    let incomplete_topology = TopologyView::from_cpus(cpus).unwrap();
    let mut history = ReplayMigrationHistory::new(30 * 60_000, 5_000, &incomplete_topology);
    history.ingest(10_000, &sample(10_000, 1, 1, &[]));
    history.ingest(11_000, &sample(11_000, 1, 2, &[(0, 1, 5)]));
    assert_eq!(history.locality_at(11_000, 1, 1_000).unwrap(), [None; 4]);
    assert_eq!(history.view_at(11_000, 1, 1_000).unwrap().total, 5);
}

#[test]
fn cpu_ids_missing_from_topology_make_locality_unknown() {
    let mut history = ReplayMigrationHistory::new(30 * 60_000, 5_000, &topology());
    history.ingest(10_000, &sample(10_000, 1, 1, &[]));
    history.ingest(11_000, &sample(11_000, 1, 2, &[(0, 99, 5)]));
    assert_eq!(history.view_at(11_000, 1, 1_000).unwrap().total, 5);
    assert_eq!(history.locality_at(11_000, 1, 1_000).unwrap(), [None; 4]);
}

#[test]
fn map_capacity_and_loss_flags_are_taken_from_the_selected_sample() {
    let mut history = ReplayMigrationHistory::new(30 * 60_000, 5_000, &topology());
    history.ingest(10_000, &sample(10_000, 1, 1, &[]));
    history.ingest(11_000, &sample(11_000, 1, 2, &[(0, 2, 5)]));
    let mut lost = sample(12_000, 1, 3, &[(0, 2, 10)]);
    lost.migration_map_failures = 3;
    lost.migration_quality = "incomplete";
    history.ingest(12_000, &lost);
    let before = history.view_at(11_000, 1, 1_000).unwrap();
    assert_eq!(before.migration_map_capacity, 25600);
    assert_eq!(before.migration_map_failures, 0);
    assert_eq!(before.migration_quality, "complete");
    let after = history.view_at(12_000, 1, 1_000).unwrap();
    assert_eq!(after.migration_map_capacity, 25600);
    assert_eq!(after.migration_map_failures, 3);
    assert_eq!(after.migration_quality, "incomplete");
}

#[test]
fn validates_positive_and_maximum_window_for_both_views() {
    let history = ReplayMigrationHistory::new(30 * 60_000, 5_000, &topology());
    assert!(matches!(
        history.view_at(10_000, 1, 0),
        Err(replay_migrations::WindowError::Zero)
    ));
    for window_ms in [1, 500, 999] {
        assert!(history.view_at(10_000, 1, window_ms).is_ok());
        assert!(history.locality_at(10_000, 1, window_ms).is_ok());
    }
    assert!(matches!(
        history.view_at(10_000, 1, 5_001),
        Err(replay_migrations::WindowError::BeyondRetention {
            max_window_ms: 5_000
        })
    ));
    assert!(history.locality_at(10_000, 1, 0).is_err());
    assert!(history.locality_at(10_000, 1, 5_001).is_err());
}

#[test]
fn configured_subsecond_window_replays_data_with_a_one_second_maximum() {
    let mut history = ReplayMigrationHistory::new(30 * 60_000, 1_000, &topology());
    history.ingest(10_000, &sample(10_000, 1, 1, &[(0, 2, 100)]));
    history.ingest(10_500, &sample(10_500, 1, 2, &[(0, 2, 105)]));
    history.ingest(11_000, &sample(11_000, 1, 3, &[(0, 2, 999)]));
    let view = history.view_at(10_500, 1, 500).unwrap();
    assert_eq!(view.total, 5);
    assert_eq!(view.observed_ms, 500);
    assert_eq!(view.window_ms, 500);
    assert_eq!(view.max_window_ms, 1_000);
    assert_eq!(view.migration_quality, "complete");
    assert_eq!(
        history.locality_at(10_500, 1, 500).unwrap(),
        [Some(0.0), Some(100.0), Some(0.0), Some(0.0)]
    );
    assert!(matches!(
        history.view_at(10_500, 1, 0),
        Err(replay_migrations::WindowError::Zero)
    ));
    assert!(matches!(
        history.view_at(10_500, 1, 1_001),
        Err(replay_migrations::WindowError::BeyondRetention {
            max_window_ms: 1_000
        })
    ));
}

#[test]
fn exposes_configured_maximum_even_before_collection_and_after_clear() {
    let mut history = ReplayMigrationHistory::new(30 * 60_000, 1_000, &topology());
    assert_eq!(history.max_window_ms(), 1_000);
    history.ingest(10_000, &sample(10_000, 1, 1, &[]));
    history.clear();
    assert_eq!(history.max_window_ms(), 1_000);
}

#[test]
fn explicit_clear_erases_retained_intervals_and_starts_a_fresh_baseline() {
    let mut history = ReplayMigrationHistory::new(30 * 60_000, 5_000, &topology());
    history.ingest(10_000, &sample(10_000, 1, 1, &[]));
    history.ingest(11_000, &sample(11_000, 1, 2, &[(0, 2, 10)]));
    history.clear();
    assert_eq!(history.oldest_at_unix_ms(), None);
    assert_eq!(
        history.view_at(11_000, 1, 1_000).unwrap().migration_quality,
        "unavailable"
    );
    history.ingest(12_000, &sample(12_000, 2, 1, &[(0, 2, 9_000)]));
    history.ingest(13_000, &sample(13_000, 2, 2, &[(0, 2, 9_005)]));
    assert_eq!(history.view_at(13_000, 2, 1_000).unwrap().total, 5);
    assert_eq!(
        history.locality_at(13_000, 2, 1_000).unwrap(),
        [Some(0.0), Some(100.0), Some(0.0), Some(0.0)]
    );
}
