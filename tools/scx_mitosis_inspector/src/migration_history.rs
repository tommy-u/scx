// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::time::Duration;

use serde::Serialize;

use crate::lifecycle::{ObserverContext, SampleMeta};
use crate::MigrationRow;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CpuPair {
    from_cpu: u32,
    to_cpu: u32,
}

#[derive(Debug)]
struct DeltaBin {
    at_ms: u64,
    counts: BTreeMap<CpuPair, u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct MigrationWindowView {
    pub meta: SampleMeta,
    pub collector: ObserverContext,
    pub migration_map_capacity: u32,
    pub migration_map_failures: u64,
    pub migration_quality: &'static str,
    pub window_ms: u64,
    pub max_window_ms: u64,
    pub observed_ms: u64,
    pub total: u64,
    pub rate_per_second: f64,
    pub rows: Vec<MigrationRow>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowError {
    Zero,
    BeyondRetention { max_window_ms: u64 },
}

impl fmt::Display for WindowError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero => write!(formatter, "window must be greater than zero"),
            Self::BeyondRetention { max_window_ms } => {
                write!(formatter, "window exceeds retained {max_window_ms} ms")
            }
        }
    }
}

impl std::error::Error for WindowError {}

#[derive(Debug)]
pub struct MigrationHistory {
    meta: SampleMeta,
    collector: ObserverContext,
    migration_map_capacity: u32,
    migration_map_failures: u64,
    max_window_ms: u64,
    started_at_ms: Option<u64>,
    latest_at_ms: u64,
    last_counts: BTreeMap<CpuPair, u64>,
    bins: VecDeque<DeltaBin>,
}

impl MigrationHistory {
    pub fn new(max_window_ms: u64) -> Self {
        assert!(max_window_ms > 0, "maximum window must be non-zero");
        Self {
            meta: SampleMeta::default(),
            collector: ObserverContext::default(),
            migration_map_capacity: 0,
            migration_map_failures: 0,
            max_window_ms,
            started_at_ms: None,
            latest_at_ms: 0,
            last_counts: BTreeMap::new(),
            bins: VecDeque::new(),
        }
    }

    pub fn set_context(
        &mut self,
        meta: SampleMeta,
        collector: ObserverContext,
        capacity: u32,
        failures: u64,
    ) {
        if self.meta.epoch != meta.epoch {
            self.reset();
        }
        self.meta = meta;
        self.collector = collector;
        self.migration_map_capacity = capacity;
        self.migration_map_failures = failures;
    }

    pub fn ingest(&mut self, at_ms: u64, rows: &[MigrationRow]) {
        let counts = rows
            .iter()
            .map(|row| {
                (
                    CpuPair {
                        from_cpu: row.from_cpu,
                        to_cpu: row.to_cpu,
                    },
                    row.count,
                )
            })
            .collect::<BTreeMap<_, _>>();
        self.latest_at_ms = at_ms;
        if self.started_at_ms.is_none() {
            self.started_at_ms = Some(at_ms);
            self.last_counts = counts;
            return;
        }

        let mut deltas = BTreeMap::new();
        for (&pair, &current) in &counts {
            let delta = match self.last_counts.get(&pair) {
                Some(previous) if current >= *previous => current - previous,
                Some(_) | None => current,
            };
            if delta > 0 {
                deltas.insert(pair, delta);
            }
        }
        self.last_counts = counts;
        if !deltas.is_empty() {
            self.bins.push_back(DeltaBin {
                at_ms,
                counts: deltas,
            });
        }
        self.expire(at_ms.saturating_sub(self.max_window_ms));
    }

    pub fn reset(&mut self) {
        self.started_at_ms = None;
        self.latest_at_ms = 0;
        self.last_counts.clear();
        self.bins.clear();
    }

    pub fn view(&self, window_ms: u64) -> Result<MigrationWindowView, WindowError> {
        if window_ms == 0 {
            return Err(WindowError::Zero);
        }
        if window_ms > self.max_window_ms {
            return Err(WindowError::BeyondRetention {
                max_window_ms: self.max_window_ms,
            });
        }

        let cutoff_ms = self.latest_at_ms.saturating_sub(window_ms);
        let mut counts = BTreeMap::<CpuPair, u64>::new();
        for bin in self.bins.iter().filter(|bin| bin.at_ms > cutoff_ms) {
            for (&pair, &count) in &bin.counts {
                let total = counts.entry(pair).or_default();
                *total = total.saturating_add(count);
            }
        }
        let total = counts.values().copied().fold(0_u64, u64::saturating_add);
        let observed_ms = self
            .started_at_ms
            .map(|started| self.latest_at_ms.saturating_sub(started).min(window_ms))
            .unwrap_or_default();
        let rows = counts
            .into_iter()
            .map(|(pair, count)| MigrationRow {
                from_cpu: pair.from_cpu,
                to_cpu: pair.to_cpu,
                count,
            })
            .collect();

        Ok(MigrationWindowView {
            meta: self.meta.clone(),
            collector: self.collector.clone(),
            migration_map_capacity: self.migration_map_capacity,
            migration_map_failures: self.migration_map_failures,
            migration_quality: if self.migration_map_capacity == 0 {
                "unavailable"
            } else if self.migration_map_failures > 0 {
                "incomplete"
            } else {
                "complete"
            },
            window_ms,
            max_window_ms: self.max_window_ms,
            observed_ms,
            total,
            rate_per_second: if observed_ms > 0 {
                total as f64 * 1_000.0 / observed_ms as f64
            } else {
                0.0
            },
            rows,
        })
    }

    fn expire(&mut self, cutoff_ms: u64) {
        while self.bins.front().is_some_and(|bin| bin.at_ms <= cutoff_ms) {
            self.bins.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::CollectorStatus;

    fn context(epoch: u64, seq: u64) -> (SampleMeta, ObserverContext) {
        (
            SampleMeta {
                epoch,
                sample_seq: seq,
                captured_at_unix_ms: Some(1000 + seq),
                last_success_at_unix_ms: Some(1000 + seq),
                error: None,
            },
            ObserverContext {
                epoch,
                status: CollectorStatus::Active,
                scheduler_enable_seq: Some(epoch),
                scheduler_name: Some("mitosis".into()),
                error: None,
            },
        )
    }

    #[test]
    fn epoch_change_discards_old_bins_and_sets_a_new_baseline() {
        let mut history = MigrationHistory::new(5000);
        let (meta, collector) = context(1, 1);
        history.set_context(meta, collector, 4096, 0);
        history.ingest(0, &[]);
        history.ingest(
            1000,
            &[MigrationRow {
                from_cpu: 1,
                to_cpu: 2,
                count: 5,
            }],
        );
        assert_eq!(history.view(5000).unwrap().total, 5);
        let (meta, collector) = context(2, 1);
        history.set_context(meta.clone(), collector.clone(), 4096, 0);
        history.ingest(
            0,
            &[MigrationRow {
                from_cpu: 1,
                to_cpu: 2,
                count: 3,
            }],
        );
        let view = history.view(5000).unwrap();
        assert_eq!(view.total, 0);
        assert_eq!(view.observed_ms, 0);
        assert_eq!(view.meta, meta);
        assert_eq!(view.collector, collector);
    }

    #[test]
    fn same_epoch_updates_metadata_and_quality_without_erasing_history() {
        let mut history = MigrationHistory::new(5000);
        let (meta, collector) = context(1, 1);
        history.set_context(meta, collector, 25600, 0);
        history.ingest(0, &[]);
        history.ingest(
            1000,
            &[MigrationRow {
                from_cpu: 0,
                to_cpu: 1,
                count: 9,
            }],
        );
        let (meta, collector) = context(1, 2);
        history.set_context(meta.clone(), collector, 25600, 4);
        let view = history.view(5000).unwrap();
        assert_eq!(view.total, 9);
        assert_eq!(view.meta, meta);
        assert_eq!(view.migration_map_capacity, 25600);
        assert_eq!(view.migration_map_failures, 4);
        assert_eq!(view.migration_quality, "incomplete");
    }

    #[test]
    fn retains_more_than_4096_distinct_pairs_in_a_window() {
        let mut history = MigrationHistory::new(5000);
        let (meta, collector) = context(1, 1);
        history.set_context(meta, collector, 25600, 0);
        history.ingest(0, &[]);
        let rows: Vec<_> = (0..5000)
            .map(|index| MigrationRow {
                from_cpu: index / 159,
                to_cpu: (index % 159 + index / 159 + 1) % 160,
                count: 1,
            })
            .collect();
        history.ingest(1000, &rows);
        let view = history.view(5000).unwrap();
        assert_eq!(view.rows.len(), 5000);
        assert_eq!(view.total, 5000);
        assert_eq!(view.migration_quality, "complete");
    }
}

pub fn parse_duration(value: &str) -> Result<Duration, String> {
    let value = value.trim();
    let (number, multiplier) = if let Some(number) = value.strip_suffix("ms") {
        (number, 1_u64)
    } else if let Some(number) = value.strip_suffix('s') {
        (number, 1_000)
    } else if let Some(number) = value.strip_suffix('m') {
        (number, 60_000)
    } else if let Some(number) = value.strip_suffix('h') {
        (number, 3_600_000)
    } else {
        (value, 1_000)
    };
    let number = number
        .parse::<u64>()
        .map_err(|_| format!("invalid duration: {value}"))?;
    let milliseconds = number
        .checked_mul(multiplier)
        .ok_or_else(|| format!("duration is too large: {value}"))?;
    if milliseconds == 0 {
        return Err("duration must be greater than zero".into());
    }
    Ok(Duration::from_millis(milliseconds))
}
