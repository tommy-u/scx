#[path = "../src/explore_probe_math.rs"]
mod math;

use math::{counter_interval, cpu_equivalents, event_sampled, Histogram, TaskIdentity};

#[test]
fn rates_require_a_baseline_and_real_elapsed_time() {
    assert!(counter_interval(3, None, Some(1_000_000_000)).is_none());
    assert!(counter_interval(3, Some(2), Some(0)).is_none());
    assert!(counter_interval(3, Some(2), None).is_none());
    let delta = counter_interval(11, Some(5), Some(2_000_000_000)).unwrap();
    assert_eq!(delta.count, 6);
    assert_eq!(delta.per_second, 3.0);
}

#[test]
fn decreasing_counters_are_a_new_baseline_not_an_underflow() {
    assert!(counter_interval(1, Some(u64::MAX), Some(1_000_000_000)).is_none());
    assert!(cpu_equivalents(1, Some(1_000_000), Some(1_000_000)).is_none());
}

#[test]
fn one_cpu_equivalent_uses_nanoseconds_of_cpu_over_wall_time() {
    assert_eq!(
        cpu_equivalents(1_500_000_000, Some(1_000_000_000), Some(1_000_000_000)),
        Some(0.5)
    );
}

#[test]
fn percentile_is_a_bucket_bound_limited_by_the_observed_maximum() {
    let mut histogram = Histogram::default();
    histogram.buckets[10] = 4;
    histogram.buckets[20] = 1;
    histogram.total_ns = 1_604_000;
    histogram.max_ns = 1_600_000;
    assert_eq!(histogram.samples(), 5);
    assert_eq!(histogram.quantile_us(50.0), Some(2.047));
    assert_eq!(histogram.quantile_us(99.0), Some(1600.0));
    assert_eq!(histogram.mean_us(), Some(320.8));
}

#[test]
fn an_empty_histogram_means_no_observation_not_zero_latency() {
    let histogram = Histogram::default();
    assert_eq!(histogram.quantile_us(95.0), None);
    assert_eq!(histogram.mean_us(), None);
}

#[test]
fn histogram_interval_preserves_only_new_observations() {
    let mut baseline = Histogram::default();
    baseline.buckets[9] = 100;
    baseline.total_ns = 50_000;
    let mut current = baseline.clone();
    current.buckets[20] = 2;
    current.total_ns += 3_000_000;
    current.max_ns = 1_500_000;
    let interval = current.delta(&baseline).unwrap();
    assert_eq!(interval.samples(), 2);
    assert_eq!(interval.mean_us(), Some(1500.0));
    assert!(baseline.delta(&current).is_none());
}

#[test]
fn reused_pid_is_a_different_task_even_with_the_same_comm() {
    let old = TaskIdentity {
        pid: 42,
        start_time_ns: 1000,
    };
    let new = TaskIdentity {
        pid: 42,
        start_time_ns: 2000,
    };
    assert_ne!(old, new);
    let mut baseline = std::collections::BTreeMap::new();
    baseline.insert(old, 1_000_000);
    assert!(baseline.get(&new).is_none());
}

#[test]
fn sampling_accepts_only_nonzero_powers_of_two() {
    assert!(!event_sampled(0, 0));
    assert!(!event_sampled(0, 3));
    for random in 0..64 {
        assert!(event_sampled(random, 1));
        assert_eq!(event_sampled(random, 16), random % 16 == 0);
    }
}

#[test]
fn merge_does_not_overflow_counts_or_totals() {
    let mut left = Histogram::default();
    left.buckets[0] = u64::MAX;
    left.total_ns = u64::MAX;
    let mut right = Histogram::default();
    right.buckets[0] = 1;
    right.total_ns = 1;
    right.max_ns = 8;
    left.merge(&right);
    assert_eq!(left.samples(), u64::MAX);
    assert_eq!(left.total_ns, u64::MAX);
    assert_eq!(left.max_ns, 8);
}

#[test]
fn proc_stat_identity_parser_handles_spaces_and_parentheses_in_comm() {
    let stat = format!(
        "42 (odd ) worker ( name) S {} 91234 0 0",
        vec!["0"; 18].join(" ")
    );
    assert_eq!(math::proc_start_ticks(&stat), Some(91234));
    assert_eq!(math::proc_start_ticks("42 (truncated) S 0"), None);
}

#[test]
fn proc_birth_time_matches_only_the_same_kernel_task_identity() {
    let identity = TaskIdentity {
        pid: 42,
        start_time_ns: 1_239_999_999,
    };
    assert!(math::proc_identity_matches(identity, 123, 100));
    assert!(!math::proc_identity_matches(identity, 124, 100));
    assert!(!math::proc_identity_matches(identity, 123, 0));
}

#[test]
fn schedstat_cpu_runtime_uses_first_column_and_rejects_bad_data() {
    assert_eq!(math::schedstat_runtime_ns("1234567 456 9\n"), Some(1234567));
    assert_eq!(math::schedstat_runtime_ns("x 456 9"), None);
    assert_eq!(math::schedstat_runtime_ns("1234567"), None);
    assert_eq!(math::schedstat_runtime_ns("0 0 0"), Some(0));
}

#[test]
fn readmitted_entry_is_a_new_baseline_even_if_its_counter_is_already_larger() {
    assert!(math::same_admission(42, 42));
    assert!(!math::same_admission(84, 42));
    assert!(!math::same_admission(0, 0));
}

#[test]
fn inconsistent_maximum_cannot_clip_a_larger_histogram_bucket() {
    let mut histogram = Histogram::default();
    histogram.buckets[20] = 2;
    histogram.max_ns = 1000;
    assert_eq!(histogram.quantile_us(95.0), Some(2097.151));
    assert_eq!(histogram.exact_max_us(), None);
}

#[test]
fn a_failed_max_update_forbids_clipping_even_in_the_same_bucket() {
    let mut histogram = Histogram::default();
    histogram.buckets[10] = 2;
    histogram.max_ns = 1200;
    histogram.max_update_failures = 1;
    assert_eq!(histogram.quantile_us(95.0), Some(2.047));
    assert_eq!(histogram.exact_max_us(), None);
}

#[test]
fn merged_and_interval_histograms_preserve_unknown_maximum_quality() {
    let mut left = Histogram::default();
    let mut right = Histogram::default();
    right.buckets[10] = 1;
    right.max_ns = 1200;
    right.max_update_failures = 1;
    left.merge(&right);
    assert_eq!(left.max_update_failures, 1);
    assert_eq!(left.exact_max_us(), None);
    let mut current = left.clone();
    current.buckets[0] += 1;
    let delta = current.delta(&left).unwrap();
    assert_eq!(delta.exact_max_us(), None);
}

#[test]
fn bounded_display_selection_keeps_hottest_rows_and_stable_ties() {
    let rows = (0u32..300).map(|id| (id, id / 2)).collect::<Vec<_>>();
    let rows = math::select_top_rows(rows, 128, |left, right| {
        right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0))
    });
    assert_eq!(rows.len(), 128);
    assert_eq!(rows[0], (298, 149));
    assert_eq!(rows[1], (299, 149));
    assert_eq!(rows[127], (173, 86));
}

#[test]
fn bounded_display_selection_can_return_no_rows_without_changing_counters() {
    let rows = vec![1, 2, 3];
    assert!(math::select_top_rows(rows, 0, |left, right| right.cmp(left)).is_empty());
}
