#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct TaskIdentity {
    pub pid: u32,
    pub start_time_ns: u64,
}

#[derive(Clone, Debug)]
pub struct Histogram {
    pub buckets: [u64; 64],
    pub total_ns: u64,
    pub max_ns: u64,
    pub max_update_failures: u64,
    pub max_known: bool,
}

impl Default for Histogram {
    fn default() -> Self {
        Self {
            buckets: [0; 64],
            total_ns: 0,
            max_ns: 0,
            max_update_failures: 0,
            max_known: true,
        }
    }
}

impl Histogram {
    pub fn exact_max_us(&self) -> Option<f64> {
        if !self.max_known || self.max_update_failures != 0 {
            return None;
        }
        let highest = self.buckets.iter().rposition(|count| *count != 0)?;
        let lower = if highest == 0 { 0 } else { 1u64 << highest };
        (self.max_ns >= lower).then(|| self.max_ns as f64 / 1000.0)
    }
    pub fn samples(&self) -> u64 {
        self.buckets
            .iter()
            .fold(0u64, |total, count| total.saturating_add(*count))
    }

    pub fn mean_us(&self) -> Option<f64> {
        let samples = self.samples();
        (samples != 0).then(|| self.total_ns as f64 / samples as f64 / 1000.0)
    }

    /// Quantiles are upper bounds of logarithmic nanosecond buckets, not exact samples.
    pub fn quantile_us(&self, percentile: f64) -> Option<f64> {
        let samples = self.samples();
        if samples == 0 || !percentile.is_finite() || !(0.0..=100.0).contains(&percentile) {
            return None;
        }
        let rank = (samples as f64 * percentile / 100.0).ceil().max(1.0) as u64;
        let mut observed = 0u64;
        for (index, count) in self.buckets.iter().enumerate() {
            observed = observed.saturating_add(*count);
            if observed >= rank {
                let upper = if index == 63 {
                    u64::MAX
                } else {
                    (1u64 << (index + 1)) - 1
                };
                // A measured maximum is more precise than the last occupied bucket's bound.
                let upper = if self.exact_max_us().is_none() {
                    upper
                } else {
                    upper.min(self.max_ns)
                };
                return Some(upper as f64 / 1000.0);
            }
        }
        None
    }

    pub fn delta(&self, previous: &Self) -> Option<Self> {
        let mut result = Self::default();
        result.total_ns = self.total_ns.checked_sub(previous.total_ns)?;
        for index in 0..64 {
            result.buckets[index] = self.buckets[index].checked_sub(previous.buckets[index])?;
        }
        // The lifetime maximum cannot establish the maximum of this interval.
        // Leave it unknown and use the bucket upper bound for interval quantiles.
        result.max_ns = 0;
        result.max_known = false;
        Some(result)
    }

    pub fn merge(&mut self, other: &Self) {
        for index in 0..64 {
            self.buckets[index] = self.buckets[index].saturating_add(other.buckets[index]);
        }
        self.total_ns = self.total_ns.saturating_add(other.total_ns);
        self.max_ns = self.max_ns.max(other.max_ns);
        self.max_update_failures = self
            .max_update_failures
            .saturating_add(other.max_update_failures);
        self.max_known &= other.max_known;
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CounterInterval {
    pub count: u64,
    pub per_second: f64,
}

pub fn counter_interval(
    current: u64,
    previous: Option<u64>,
    elapsed_ns: Option<u64>,
) -> Option<CounterInterval> {
    let elapsed = elapsed_ns.filter(|elapsed| *elapsed != 0)?;
    let count = current.checked_sub(previous?)?;
    Some(CounterInterval {
        count,
        per_second: count as f64 * 1_000_000_000.0 / elapsed as f64,
    })
}

pub fn cpu_equivalents(
    current: u64,
    previous: Option<u64>,
    elapsed_ns: Option<u64>,
) -> Option<f64> {
    let elapsed = elapsed_ns.filter(|elapsed| *elapsed != 0)?;
    let cpu_ns = current.checked_sub(previous?)?;
    Some(cpu_ns as f64 / elapsed as f64)
}

pub fn event_sampled(random: u32, rate: u32) -> bool {
    rate.is_power_of_two() && random & (rate - 1) == 0
}

pub fn proc_start_ticks(value: &str) -> Option<u64> {
    // Field2 (comm) may contain spaces and parentheses; subsequent fields do not.
    let tail = value.rsplit_once(')')?.1;
    tail.split_whitespace().nth(19)?.parse().ok()
}

pub fn proc_identity_matches(identity: TaskIdentity, start_ticks: u64, hertz: u64) -> bool {
    hertz > 0
        && identity.start_time_ns > 0
        && (identity.start_time_ns as u128 * hertz as u128 / 1_000_000_000) == start_ticks as u128
}

pub fn schedstat_runtime_ns(value: &str) -> Option<u64> {
    let fields = value.split_whitespace().collect::<Vec<_>>();
    if fields.len() != 3 || fields.iter().any(|value| value.parse::<u64>().is_err()) {
        return None;
    }
    fields[0].parse().ok()
}

pub fn same_admission(current_started_ns: u64, previous_started_ns: u64) -> bool {
    current_started_ns != 0 && current_started_ns == previous_started_ns
}

pub fn select_top_rows<T, F: FnMut(&T, &T) -> std::cmp::Ordering>(
    mut rows: Vec<T>,
    limit: usize,
    mut compare: F,
) -> Vec<T> {
    if limit == 0 {
        return Vec::new();
    }
    if rows.len() > limit {
        rows.select_nth_unstable_by(limit, &mut compare);
        rows.truncate(limit);
    }
    rows.sort_by(compare);
    rows
}
// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-2.0-only
