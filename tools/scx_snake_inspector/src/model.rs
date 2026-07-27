// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::{BTreeMap, VecDeque};
use std::error::Error;
use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct CpuPair {
    pub from: u32,
    pub to: u32,
}

impl CpuPair {
    pub const fn new(from: u32, to: u32) -> Self {
        Self { from, to }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowView {
    pub cells: BTreeMap<CpuPair, u64>,
    pub total: u64,
    pub observed_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CpuUsageWindow {
    pub runtime_ns: BTreeMap<u32, u64>,
    pub observed_ms: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowError {
    Empty,
    TooLong { requested_ms: u64, max_ms: u64 },
}

impl Display for WindowError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "window must be greater than zero"),
            Self::TooLong {
                requested_ms,
                max_ms,
            } => write!(
                f,
                "window of {requested_ms}ms exceeds maximum of {max_ms}ms"
            ),
        }
    }
}

impl Error for WindowError {}

#[derive(Debug)]
struct DeltaBin {
    at_ms: u64,
    counts: BTreeMap<CpuPair, u64>,
}

#[derive(Debug)]
struct CpuUsageBin {
    at_ms: u64,
    runtime_ns: BTreeMap<u32, u64>,
}

#[derive(Debug)]
pub struct CpuUsageHistory {
    max_window_ms: u64,
    started_at_ms: Option<u64>,
    bins: VecDeque<CpuUsageBin>,
}

impl CpuUsageHistory {
    pub fn new(max_window_ms: u64) -> Self {
        assert!(max_window_ms > 0, "maximum window must be non-zero");
        Self {
            max_window_ms,
            started_at_ms: None,
            bins: VecDeque::new(),
        }
    }

    pub fn ingest(&mut self, at_ms: u64, runtime_ns: &BTreeMap<u32, u64>) {
        if self.started_at_ms.is_none() {
            self.reset(at_ms);
        }
        let runtime_ns = runtime_ns
            .iter()
            .filter_map(|(&cpu, &runtime_ns)| (runtime_ns > 0).then_some((cpu, runtime_ns)))
            .collect::<BTreeMap<_, _>>();
        if !runtime_ns.is_empty() {
            self.bins.push_back(CpuUsageBin { at_ms, runtime_ns });
        }
        self.expire(at_ms.saturating_sub(self.max_window_ms));
    }

    pub fn reset(&mut self, at_ms: u64) {
        self.started_at_ms = Some(at_ms);
        self.bins.clear();
    }

    pub fn view(&self, now_ms: u64, window_ms: u64) -> Result<CpuUsageWindow, WindowError> {
        validate_window(window_ms, self.max_window_ms)?;
        let cutoff_ms = now_ms.saturating_sub(window_ms);
        let mut runtime_ns = BTreeMap::<u32, u64>::new();
        for bin in self.bins.iter().filter(|bin| bin.at_ms > cutoff_ms) {
            for (&cpu, &delta_ns) in &bin.runtime_ns {
                let total = runtime_ns.entry(cpu).or_default();
                *total = total.saturating_add(delta_ns);
            }
        }
        let observed_ms = self
            .started_at_ms
            .map(|started| now_ms.saturating_sub(started).min(window_ms))
            .unwrap_or(0);
        Ok(CpuUsageWindow {
            runtime_ns,
            observed_ms,
        })
    }

    fn expire(&mut self, cutoff_ms: u64) {
        while self.bins.front().is_some_and(|bin| bin.at_ms <= cutoff_ms) {
            self.bins.pop_front();
        }
    }
}

#[derive(Debug)]
pub struct RollingHistory {
    max_window_ms: u64,
    started_at_ms: Option<u64>,
    last_counts: BTreeMap<CpuPair, u64>,
    bins: VecDeque<DeltaBin>,
}

impl RollingHistory {
    pub fn new(max_window_ms: u64) -> Self {
        assert!(max_window_ms > 0, "maximum window must be non-zero");
        Self {
            max_window_ms,
            started_at_ms: None,
            last_counts: BTreeMap::new(),
            bins: VecDeque::new(),
        }
    }

    pub fn ingest(&mut self, at_ms: u64, counts: &BTreeMap<CpuPair, u64>) {
        if self.started_at_ms.is_none() {
            self.reset(at_ms, counts);
            return;
        }

        let mut deltas = BTreeMap::new();
        for (&pair, &current) in counts {
            let delta = match self.last_counts.get(&pair) {
                Some(previous) if current >= *previous => current - previous,
                Some(_) | None => current,
            };
            if delta > 0 {
                deltas.insert(pair, delta);
            }
        }

        self.last_counts.clone_from(counts);
        if !deltas.is_empty() {
            self.bins.push_back(DeltaBin {
                at_ms,
                counts: deltas,
            });
        }
        self.expire(at_ms.saturating_sub(self.max_window_ms));
    }

    pub fn reset(&mut self, at_ms: u64, counts: &BTreeMap<CpuPair, u64>) {
        self.started_at_ms = Some(at_ms);
        self.last_counts.clone_from(counts);
        self.bins.clear();
    }

    pub fn view(&self, now_ms: u64, window_ms: u64) -> Result<WindowView, WindowError> {
        validate_window(window_ms, self.max_window_ms)?;

        let cutoff_ms = now_ms.saturating_sub(window_ms);
        let mut cells = BTreeMap::<CpuPair, u64>::new();
        for bin in self.bins.iter().filter(|bin| bin.at_ms > cutoff_ms) {
            for (&pair, &count) in &bin.counts {
                let total = cells.entry(pair).or_default();
                *total = total.saturating_add(count);
            }
        }
        let total = cells.values().copied().fold(0_u64, u64::saturating_add);
        let observed_ms = self
            .started_at_ms
            .map(|started| now_ms.saturating_sub(started).min(window_ms))
            .unwrap_or(0);

        Ok(WindowView {
            cells,
            total,
            observed_ms,
        })
    }

    fn expire(&mut self, cutoff_ms: u64) {
        while self.bins.front().is_some_and(|bin| bin.at_ms <= cutoff_ms) {
            self.bins.pop_front();
        }
    }
}

fn validate_window(window_ms: u64, max_window_ms: u64) -> Result<(), WindowError> {
    if window_ms == 0 {
        return Err(WindowError::Empty);
    }
    if window_ms > max_window_ms {
        return Err(WindowError::TooLong {
            requested_ms: window_ms,
            max_ms: max_window_ms,
        });
    }
    Ok(())
}
