use scx_mitosis_inspector::migration_history::{MigrationHistory, WindowError};
use scx_mitosis_inspector::MigrationRow;

fn rows(values: &[(u32, u32, u64)]) -> Vec<MigrationRow> {
    values
        .iter()
        .map(|&(from_cpu, to_cpu, count)| MigrationRow {
            from_cpu,
            to_cpu,
            count,
        })
        .collect()
}

#[test]
fn rolling_view_contains_only_deltas_inside_the_window() {
    let mut history = MigrationHistory::new(5_000);
    history.ingest(0, &[]);
    history.ingest(250, &rows(&[(2, 7, 3)]));
    history.ingest(500, &rows(&[(2, 7, 5)]));

    let full = history.view(500).unwrap();
    assert_eq!(full.total, 5);
    assert_eq!(full.rows, rows(&[(2, 7, 5)]));
    assert_eq!(full.observed_ms, 500);

    history.ingest(600, &rows(&[(2, 7, 5)]));
    let recent = history.view(300).unwrap();
    assert_eq!(recent.total, 2);
    assert_eq!(recent.rows, rows(&[(2, 7, 2)]));
    assert_eq!(recent.observed_ms, 300);
}

#[test]
fn counter_reset_starts_a_new_epoch() {
    let mut history = MigrationHistory::new(5_000);
    history.ingest(0, &rows(&[(1, 3, 10)]));
    history.ingest(250, &rows(&[(1, 3, 2)]));

    assert_eq!(history.view(500).unwrap().rows, rows(&[(1, 3, 2)]));

    history.reset();
    assert_eq!(history.view(500).unwrap().total, 0);
    assert_eq!(history.view(500).unwrap().observed_ms, 0);
}

#[test]
fn retention_and_invalid_windows_are_enforced() {
    let mut history = MigrationHistory::new(1_000);
    history.ingest(0, &[]);
    history.ingest(500, &rows(&[(0, 1, 2)]));
    history.ingest(1_500, &rows(&[(0, 1, 5)]));

    assert_eq!(history.view(1_000).unwrap().rows, rows(&[(0, 1, 3)]));
    assert_eq!(history.view(0), Err(WindowError::Zero));
    assert_eq!(
        history.view(1_001),
        Err(WindowError::BeyondRetention {
            max_window_ms: 1_000
        })
    );
}
