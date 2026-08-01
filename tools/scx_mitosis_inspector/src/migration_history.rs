// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::time::Duration;

use serde::Serialize;

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
            max_window_ms,
            started_at_ms: None,
            latest_at_ms: 0,
            last_counts: BTreeMap::new(),
            bins: VecDeque::new(),
        }
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
