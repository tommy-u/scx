// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::time::Duration;

use serde::Serialize;

pub const CALLBACK_TIMING_BUCKETS: usize = 64;
pub const CALLBACK_NAMES: [&str; 5] = ["select_cpu", "enqueue", "dispatch", "running", "stopping"];

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CallbackCounter {
    pub name: &'static str,
    pub count: u64,
    pub rate_per_second: f64,
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
    pub mean_ns: Option<u64>,
    pub p50_ns: Option<u64>,
    pub p95_ns: Option<u64>,
    pub p99_ns: Option<u64>,
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

pub fn build_callback_timing_rows(timings: &[CallbackTimingCounters]) -> Vec<CallbackTimingRow> {
    CALLBACK_NAMES
        .into_iter()
        .zip(timings)
        .map(|(callback, timing)| {
            let summary = summarize_callback_timing(timing);
            CallbackTimingRow {
                callback,
                samples: summary.samples,
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
