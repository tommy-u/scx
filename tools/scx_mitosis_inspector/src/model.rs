// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::time::Duration;

use serde::Serialize;

pub const CALLBACK_TIMING_BUCKETS: usize = 64;
pub const CALLBACK_NAMES: [&str; 5] = ["select_cpu", "enqueue", "dispatch", "running", "stopping"];
pub const SCHEDULER_EVENT_NAMES: [&str; 9] = [
    "context_switches",
    "preemptions",
    "blocked_switches",
    "voluntary_switches",
    "wakeups",
    "new_task_wakeups",
    "task_forks",
    "task_execs",
    "task_exits",
];
pub const SOFTIRQ_NAMES: [&str; 10] = [
    "HI", "TIMER", "NET_TX", "NET_RX", "BLOCK", "IRQ_POLL", "TASKLET", "SCHED", "HRTIMER", "RCU",
];

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CallbackCounter {
    pub name: &'static str,
    pub count: u64,
    pub rate_per_second: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SchedulerEventRow {
    pub metric: &'static str,
    pub count: u64,
    pub rate_per_second: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SoftirqRow {
    pub vector: u32,
    pub name: &'static str,
    pub count: u64,
    pub rate_per_second: f64,
    pub samples: u64,
    pub timing_buckets: Vec<u64>,
    pub mean_ns: Option<u64>,
    pub p50_ns: Option<u64>,
    pub p95_ns: Option<u64>,
    pub p99_ns: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct BlockIoMetricsView {
    pub available: bool,
    pub issue_events: u64,
    pub issue_rate_per_second: f64,
    pub completion_events: u64,
    pub completion_rate_per_second: f64,
    pub completed_requests: u64,
    pub error_events: u64,
    pub issued_bytes: u64,
    pub completed_bytes: u64,
    pub completed_bytes_per_second: f64,
    pub unmatched_completions: u64,
    pub tracking_failures: u64,
    pub latency_samples: u64,
    pub latency_buckets: Vec<u64>,
    pub latency_mean_ns: Option<u64>,
    pub latency_p50_ns: Option<u64>,
    pub latency_p95_ns: Option<u64>,
    pub latency_p99_ns: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct InterruptCpuRow {
    pub cpu: u32,
    pub hardirq_utilization_pct: f64,
    pub softirq_utilization_pct: f64,
    pub total_utilization_pct: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct HardirqRow {
    pub irq: u32,
    pub name: Option<String>,
    pub count: u64,
    pub rate_per_second: f64,
    pub samples: u64,
    pub timing_buckets: Vec<u64>,
    pub mean_ns: Option<u64>,
    pub p50_ns: Option<u64>,
    pub p95_ns: Option<u64>,
    pub p99_ns: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct HardirqMetricsView {
    pub available: bool,
    pub metrics_map_full: u64,
    pub starts_map_full: u64,
    pub unmatched_exits: u64,
    pub rows: Vec<HardirqRow>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ProbeManifestRow {
    pub group: &'static str,
    pub status: &'static str,
    pub mode: String,
    pub scope: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallbackTimingCounters {
    pub total_ns: u64,
    pub buckets: Vec<u64>,
}

impl Default for CallbackTimingCounters {
    fn default() -> Self {
        Self {
            total_ns: 0,
            buckets: vec![0; CALLBACK_TIMING_BUCKETS],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct CallbackTimingSummary {
    pub samples: u64,
    pub mean_ns: Option<u64>,
    pub p50_ns: Option<u64>,
    pub p95_ns: Option<u64>,
    pub p99_ns: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CallbackTimingRow {
    pub callback: &'static str,
    pub samples: u64,
    pub buckets: Vec<u64>,
    pub mean_ns: Option<u64>,
    pub p50_ns: Option<u64>,
    pub p95_ns: Option<u64>,
    pub p99_ns: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TimingMetricRow {
    pub metric: &'static str,
    pub samples: u64,
    pub buckets: Vec<u64>,
    pub mean_ns: Option<u64>,
    pub p50_ns: Option<u64>,
    pub p95_ns: Option<u64>,
    pub p99_ns: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct MigrationRow {
    pub from_cpu: u32,
    pub to_cpu: u32,
    pub count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct CpuRuntimeRow {
    pub cpu: u32,
    pub runtime_ns: u64,
    pub utilization_pct: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct CpuCapacityLossRow {
    pub cpu: u32,
    pub rt_stop_utilization_pct: f64,
    pub deadline_utilization_pct: f64,
    pub steal_utilization_pct: f64,
    pub total_utilization_pct: f64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct DsqMetricsView {
    pub available: bool,
    pub insert_count: u64,
    pub move_count: u64,
    pub residence_samples: u64,
    pub residence_buckets: Vec<u64>,
    pub residence_mean_ns: Option<u64>,
    pub residence_p50_ns: Option<u64>,
    pub residence_p95_ns: Option<u64>,
    pub residence_p99_ns: Option<u64>,
    pub depth_samples: u64,
    pub depth_average: Option<f64>,
    pub depth_latest_max: u64,
    pub depth_max: u64,
}

pub fn project_cpu_runtime(
    busy_ns: u64,
    last_switch_ns: u64,
    current_busy: bool,
    now_ns: u64,
) -> u64 {
    if current_busy {
        busy_ns.saturating_add(now_ns.saturating_sub(last_switch_ns))
    } else {
        busy_ns
    }
}

pub fn build_cpu_runtime_rows(
    current: &[u64],
    previous: &[u64],
    elapsed: Duration,
) -> Vec<CpuRuntimeRow> {
    let elapsed_ns = elapsed.as_nanos() as f64;
    current
        .iter()
        .zip(previous)
        .enumerate()
        .map(|(cpu, (&runtime_ns, &previous_ns))| {
            let delta = runtime_ns.saturating_sub(previous_ns);
            CpuRuntimeRow {
                cpu: cpu as u32,
                runtime_ns,
                utilization_pct: if elapsed_ns > 0.0 {
                    (delta as f64 / elapsed_ns * 100.0).clamp(0.0, 100.0)
                } else {
                    0.0
                },
            }
        })
        .collect()
}

pub fn build_cpu_capacity_loss_rows(
    current_rt_stop: &[u64],
    previous_rt_stop: &[u64],
    current_deadline: &[u64],
    previous_deadline: &[u64],
    steal_utilization_pct: &[f64],
    elapsed: Duration,
) -> Vec<CpuCapacityLossRow> {
    let cpu_count = current_rt_stop
        .len()
        .max(current_deadline.len())
        .max(steal_utilization_pct.len());
    let elapsed_ns = elapsed.as_nanos() as f64;
    let runtime_pct = |current: &[u64], previous: &[u64], cpu: usize| {
        if elapsed_ns == 0.0 {
            return 0.0;
        }
        let delta = current
            .get(cpu)
            .copied()
            .unwrap_or_default()
            .saturating_sub(previous.get(cpu).copied().unwrap_or_default());
        (delta as f64 / elapsed_ns * 100.0).clamp(0.0, 100.0)
    };

    (0..cpu_count)
        .map(|cpu| {
            let rt_stop = runtime_pct(current_rt_stop, previous_rt_stop, cpu);
            let deadline = runtime_pct(current_deadline, previous_deadline, cpu);
            let steal = steal_utilization_pct
                .get(cpu)
                .copied()
                .unwrap_or_default()
                .clamp(0.0, 100.0);
            CpuCapacityLossRow {
                cpu: cpu as u32,
                rt_stop_utilization_pct: rt_stop,
                deadline_utilization_pct: deadline,
                steal_utilization_pct: steal,
                total_utilization_pct: (rt_stop + deadline + steal).clamp(0.0, 100.0),
            }
        })
        .collect()
}

pub fn build_counters(
    current: [u64; 5],
    previous: [u64; 5],
    elapsed: Duration,
) -> Vec<CallbackCounter> {
    let seconds = elapsed.as_secs_f64();
    CALLBACK_NAMES
        .into_iter()
        .enumerate()
        .map(|(index, name)| CallbackCounter {
            name,
            count: current[index],
            rate_per_second: if seconds > 0.0 {
                current[index].saturating_sub(previous[index]) as f64 / seconds
            } else {
                0.0
            },
        })
        .collect()
}

pub fn build_scheduler_event_rows(
    current: [u64; 9],
    previous: [u64; 9],
    elapsed: Duration,
) -> Vec<SchedulerEventRow> {
    let seconds = elapsed.as_secs_f64();
    SCHEDULER_EVENT_NAMES
        .into_iter()
        .enumerate()
        .map(|(index, metric)| SchedulerEventRow {
            metric,
            count: current[index],
            rate_per_second: if seconds > 0.0 {
                current[index].saturating_sub(previous[index]) as f64 / seconds
            } else {
                0.0
            },
        })
        .collect()
}

pub fn build_callback_timing_rows(timings: &[CallbackTimingCounters]) -> Vec<CallbackTimingRow> {
    CALLBACK_NAMES
        .into_iter()
        .zip(timings)
        .map(|(callback, timing)| {
            let summary = summarize_callback_timing(timing);
            CallbackTimingRow {
                callback,
                samples: summary.samples,
                buckets: timing.buckets.clone(),
                mean_ns: summary.mean_ns,
                p50_ns: summary.p50_ns,
                p95_ns: summary.p95_ns,
                p99_ns: summary.p99_ns,
            }
        })
        .collect()
}

pub fn summarize_callback_timing(timing: &CallbackTimingCounters) -> CallbackTimingSummary {
    let samples = timing
        .buckets
        .iter()
        .fold(0_u64, |total, count| total.saturating_add(*count));
    CallbackTimingSummary {
        samples,
        mean_ns: (samples > 0).then(|| timing.total_ns / samples),
        p50_ns: percentile_upper_bound(&timing.buckets, samples, 50, 1),
        p95_ns: percentile_upper_bound(&timing.buckets, samples, 95, 20),
        p99_ns: percentile_upper_bound(&timing.buckets, samples, 99, 100),
    }
}

pub fn build_timing_metric_row(
    metric: &'static str,
    timing: &CallbackTimingCounters,
) -> TimingMetricRow {
    let summary = summarize_callback_timing(timing);
    TimingMetricRow {
        metric,
        samples: summary.samples,
        buckets: timing.buckets.clone(),
        mean_ns: summary.mean_ns,
        p50_ns: summary.p50_ns,
        p95_ns: summary.p95_ns,
        p99_ns: summary.p99_ns,
    }
}

fn percentile_upper_bound(
    buckets: &[u64],
    samples: u64,
    percentile: u64,
    minimum_samples: u64,
) -> Option<u64> {
    if samples < minimum_samples {
        return None;
    }
    let rank = ((u128::from(samples) * u128::from(percentile)) + 99) / 100;
    let mut cumulative = 0_u128;
    for (bucket, count) in buckets.iter().enumerate() {
        cumulative += u128::from(*count);
        if cumulative >= rank {
            return Some(if bucket >= 63 {
                u64::MAX
            } else {
                (1_u64 << (bucket + 1)) - 1
            });
        }
    }
    None
}

pub fn parse_callback_timing_sample_rate(value: &str) -> Result<u32, String> {
    let rate = value
        .parse::<u32>()
        .map_err(|error| format!("invalid callback timing sample rate `{value}`: {error}"))?;
    if rate == 0 || (rate.is_power_of_two() && rate <= 4096) {
        return Ok(rate);
    }
    Err("callback timing sample rate must be zero or a power of two through 4096".into())
}
