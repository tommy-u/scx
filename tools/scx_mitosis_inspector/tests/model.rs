use std::time::Duration;

use scx_mitosis_inspector::{
    build_callback_timing_rows, build_counters, build_cpu_capacity_loss_rows,
    build_cpu_runtime_rows, build_scheduler_event_rows, build_timing_metric_row,
    parse_callback_timing_sample_rate, program_name_matches, project_cpu_runtime,
    summarize_callback_timing, BlockIoMetricsView, CallbackCounter, CallbackTimingCounters,
    DsqMetricsView, HardirqRow, SoftirqRow,
};

fn timing(total_ns: u64, buckets: &[(usize, u64)]) -> CallbackTimingCounters {
    let mut timing = CallbackTimingCounters {
        total_ns,
        buckets: vec![0; 64],
    };
    for &(bucket, count) in buckets {
        timing.buckets[bucket] = count;
    }
    timing
}

#[test]
fn callback_counters_include_totals_and_interval_rates() {
    let counters = build_counters(
        [100, 80, 60, 40, 20],
        [90, 60, 30, 20, 10],
        Duration::from_millis(500),
    );

    assert_eq!(
        counters,
        vec![
            CallbackCounter {
                name: "select_cpu",
                count: 100,
                rate_per_second: 20.0,
            },
            CallbackCounter {
                name: "enqueue",
                count: 80,
                rate_per_second: 40.0,
            },
            CallbackCounter {
                name: "dispatch",
                count: 60,
                rate_per_second: 60.0,
            },
            CallbackCounter {
                name: "running",
                count: 40,
                rate_per_second: 40.0,
            },
            CallbackCounter {
                name: "stopping",
                count: 20,
                rate_per_second: 20.0,
            },
        ]
    );
}

#[test]
fn callback_counter_delta_saturates_after_collector_reset() {
    let counters = build_counters([3, 0, 0, 0, 0], [10, 0, 0, 0, 0], Duration::from_secs(1));

    assert_eq!(counters[0].rate_per_second, 0.0);
}

#[test]
fn target_names_match_the_kernel_bpf_name_limit() {
    assert!(program_name_matches(
        "mitosis_select_",
        "mitosis_select_cpu"
    ));
    assert!(program_name_matches("mitosis_dispatc", "mitosis_dispatch"));
    assert!(!program_name_matches(
        "snake_select_cp",
        "mitosis_select_cpu"
    ));
}

#[test]
fn callback_timing_reports_sampled_mean_and_percentiles() {
    let summary = summarize_callback_timing(&timing(2_000, &[(3, 50), (5, 50)]));

    assert_eq!(summary.samples, 100);
    assert_eq!(summary.mean_ns, Some(20));
    assert_eq!(summary.p50_ns, Some(15));
    assert_eq!(summary.p95_ns, Some(63));
    assert_eq!(summary.p99_ns, Some(63));
}

#[test]
fn timing_rows_preserve_histogram_buckets_for_visualization() {
    let timing = timing(2_000, &[(3, 50), (5, 50)]);

    let callback = build_callback_timing_rows(std::slice::from_ref(&timing));
    let scheduler = build_timing_metric_row("wakeup_to_running", &timing);

    assert_eq!(callback[0].buckets[3], 50);
    assert_eq!(callback[0].buckets[5], 50);
    assert_eq!(scheduler.buckets, timing.buckets);
}

#[test]
fn observer_views_expose_their_latency_histograms() {
    let buckets = vec![1, 2, 3];
    let softirq = SoftirqRow {
        vector: 1,
        name: "TIMER",
        count: 3,
        rate_per_second: 1.0,
        samples: 3,
        timing_buckets: buckets.clone(),
        mean_ns: Some(2),
        p50_ns: Some(1),
        p95_ns: None,
        p99_ns: None,
    };
    let hardirq = HardirqRow {
        irq: 4,
        name: Some("timer".into()),
        count: 3,
        rate_per_second: 1.0,
        samples: 3,
        timing_buckets: buckets.clone(),
        mean_ns: Some(2),
        p50_ns: Some(1),
        p95_ns: None,
        p99_ns: None,
    };
    let block = BlockIoMetricsView {
        latency_buckets: buckets.clone(),
        ..Default::default()
    };
    let dsq = DsqMetricsView {
        residence_buckets: buckets.clone(),
        ..Default::default()
    };

    assert_eq!(softirq.timing_buckets, buckets);
    assert_eq!(hardirq.timing_buckets, buckets);
    assert_eq!(block.latency_buckets, buckets);
    assert_eq!(dsq.residence_buckets, buckets);
}

#[test]
fn callback_timing_sample_rate_is_zero_or_a_bounded_power_of_two() {
    for rate in ["0", "1", "64", "1024", "4096"] {
        assert_eq!(
            parse_callback_timing_sample_rate(rate).unwrap().to_string(),
            rate
        );
    }
    assert!(parse_callback_timing_sample_rate("3").is_err());
    assert!(parse_callback_timing_sample_rate("8192").is_err());
}

#[test]
fn cpu_runtime_uses_the_observation_interval() {
    let rows = build_cpu_runtime_rows(&[1_000_000_000], &[0], Duration::from_secs(1));

    assert_eq!(rows[0].utilization_pct, 100.0);
}

#[test]
fn cpu_runtime_includes_the_open_running_interval() {
    assert_eq!(project_cpu_runtime(40, 100, true, 160), 100);
    assert_eq!(project_cpu_runtime(40, 100, false, 160), 40);
}

#[test]
fn cpu_capacity_loss_combines_non_ext_classes_and_hypervisor_steal() {
    let rows = build_cpu_capacity_loss_rows(
        &[250_000_000],
        &[0],
        &[100_000_000],
        &[0],
        &[5.0],
        Duration::from_secs(1),
    );

    assert_eq!(rows[0].rt_stop_utilization_pct, 25.0);
    assert_eq!(rows[0].deadline_utilization_pct, 10.0);
    assert_eq!(rows[0].steal_utilization_pct, 5.0);
    assert_eq!(rows[0].total_utilization_pct, 40.0);
}

#[test]
fn scheduler_event_rows_include_interval_rates() {
    let rows = build_scheduler_event_rows(
        [20, 8, 0, 0, 0, 0, 0, 0, 0],
        [10, 4, 0, 0, 0, 0, 0, 0, 0],
        Duration::from_secs(2),
    );

    assert_eq!(rows[0].metric, "context_switches");
    assert_eq!(rows[0].rate_per_second, 5.0);
    assert_eq!(rows[1].rate_per_second, 2.0);
}
