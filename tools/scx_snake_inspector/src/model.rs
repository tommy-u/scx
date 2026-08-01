// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::{BTreeMap, VecDeque};
use std::error::Error;
use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};

pub const CALLBACK_TIMING_BUCKETS: usize = 64;
const MAX_ACCOUNTING_SAMPLE_GAP_MS: u64 = 1_000;
pub const CALLBACK_NAMES: [&str; 7] = [
    "select_cpu",
    "enqueue",
    "dispatch",
    "runnable",
    "running",
    "stopping",
    "quiescent",
];

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

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct CellMetricCounters {
    pub id: u32,
    pub index: u32,
    pub runtime_ns: u64,
    #[serde(default)]
    pub runtime_ns_by_cpu: Option<BTreeMap<u32, u64>>,
    pub primary_runtime_ns: u64,
    pub borrowed_runtime_ns: u64,
    pub lent_runtime_ns: u64,
    pub normal_enqueues: u64,
    pub affinity_enqueues: u64,
    pub normal_dispatches: u64,
    pub affinity_dispatches: u64,
    pub clock_transitions: u64,
}

impl CellMetricCounters {
    fn zero_like(&self) -> Self {
        Self {
            id: self.id,
            index: self.index,
            runtime_ns_by_cpu: self.runtime_ns_by_cpu.as_ref().map(|_| BTreeMap::new()),
            ..Self::default()
        }
    }

    fn add_assign(&mut self, other: &Self) {
        self.runtime_ns = self.runtime_ns.saturating_add(other.runtime_ns);
        if let Some(other_cpus) = &other.runtime_ns_by_cpu {
            let cpus = self.runtime_ns_by_cpu.get_or_insert_default();
            for (&cpu, &runtime_ns) in other_cpus {
                let total = cpus.entry(cpu).or_default();
                *total = total.saturating_add(runtime_ns);
            }
        }
        self.primary_runtime_ns = self
            .primary_runtime_ns
            .saturating_add(other.primary_runtime_ns);
        self.borrowed_runtime_ns = self
            .borrowed_runtime_ns
            .saturating_add(other.borrowed_runtime_ns);
        self.lent_runtime_ns = self.lent_runtime_ns.saturating_add(other.lent_runtime_ns);
        self.normal_enqueues = self.normal_enqueues.saturating_add(other.normal_enqueues);
        self.affinity_enqueues = self
            .affinity_enqueues
            .saturating_add(other.affinity_enqueues);
        self.normal_dispatches = self
            .normal_dispatches
            .saturating_add(other.normal_dispatches);
        self.affinity_dispatches = self
            .affinity_dispatches
            .saturating_add(other.affinity_dispatches);
        self.clock_transitions = self
            .clock_transitions
            .saturating_add(other.clock_transitions);
    }

    fn is_empty(&self) -> bool {
        self.runtime_ns == 0
            && self
                .runtime_ns_by_cpu
                .as_ref()
                .is_none_or(|cpus| cpus.values().all(|runtime_ns| *runtime_ns == 0))
            && self.primary_runtime_ns == 0
            && self.borrowed_runtime_ns == 0
            && self.lent_runtime_ns == 0
            && self.normal_enqueues == 0
            && self.affinity_enqueues == 0
            && self.normal_dispatches == 0
            && self.affinity_dispatches == 0
            && self.clock_transitions == 0
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HostCpuTimeCounters {
    pub task_ticks: u64,
    pub irq_ticks: u64,
    pub softirq_ticks: u64,
    pub idle_ticks: u64,
    pub iowait_ticks: u64,
    pub steal_ticks: u64,
}

impl HostCpuTimeCounters {
    fn delta(self, previous: Self) -> Option<Self> {
        if self.task_ticks < previous.task_ticks
            || self.irq_ticks < previous.irq_ticks
            || self.softirq_ticks < previous.softirq_ticks
            || self.idle_ticks < previous.idle_ticks
            || self.steal_ticks < previous.steal_ticks
        {
            return None;
        }
        Some(Self {
            task_ticks: self.task_ticks - previous.task_ticks,
            irq_ticks: self.irq_ticks - previous.irq_ticks,
            softirq_ticks: self.softirq_ticks - previous.softirq_ticks,
            idle_ticks: self.idle_ticks - previous.idle_ticks,
            iowait_ticks: self.iowait_ticks.saturating_sub(previous.iowait_ticks),
            steal_ticks: self.steal_ticks - previous.steal_ticks,
        })
    }

    fn add_assign(&mut self, other: Self) {
        self.task_ticks = self.task_ticks.saturating_add(other.task_ticks);
        self.irq_ticks = self.irq_ticks.saturating_add(other.irq_ticks);
        self.softirq_ticks = self.softirq_ticks.saturating_add(other.softirq_ticks);
        self.idle_ticks = self.idle_ticks.saturating_add(other.idle_ticks);
        self.iowait_ticks = self.iowait_ticks.saturating_add(other.iowait_ticks);
        self.steal_ticks = self.steal_ticks.saturating_add(other.steal_ticks);
    }

    fn is_empty(self) -> bool {
        self == Self::default()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostCpuTimeWindow {
    pub cpus: BTreeMap<u32, HostCpuTimeCounters>,
    pub observed_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellMetricWindow {
    pub scheduler_attach_seq: u64,
    pub policy_generation: u64,
    pub observed_ms: u64,
    pub cells: BTreeMap<u32, CellMetricCounters>,
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
struct HostCpuTimeBin {
    at_ms: u64,
    cpus: BTreeMap<u32, HostCpuTimeCounters>,
}

#[derive(Debug)]
struct CellMetricBin {
    at_ms: u64,
    cells: BTreeMap<u32, CellMetricCounters>,
}

#[derive(Debug)]
pub struct CellMetricHistory {
    max_window_ms: u64,
    started_at_ms: Option<u64>,
    scheduler_attach_seq: Option<u64>,
    policy_generation: Option<u64>,
    last_sample_at_ms: Option<u64>,
    latest_cells: BTreeMap<u32, CellMetricCounters>,
    bins: VecDeque<CellMetricBin>,
}

impl CellMetricHistory {
    pub fn new(max_window_ms: u64) -> Self {
        assert!(max_window_ms > 0, "maximum window must be non-zero");
        Self {
            max_window_ms,
            started_at_ms: None,
            scheduler_attach_seq: None,
            policy_generation: None,
            last_sample_at_ms: None,
            latest_cells: BTreeMap::new(),
            bins: VecDeque::new(),
        }
    }

    pub fn ingest(
        &mut self,
        at_ms: u64,
        scheduler_attach_seq: u64,
        policy_generation: u64,
        cells: &BTreeMap<u32, CellMetricCounters>,
    ) {
        let initialized = self.scheduler_attach_seq.is_some();
        if !initialized
            || self.scheduler_attach_seq != Some(scheduler_attach_seq)
            || self.policy_generation != Some(policy_generation)
        {
            self.reset_epoch(at_ms, scheduler_attach_seq, policy_generation, cells);
            if initialized {
                return;
            }
        }

        if self
            .last_sample_at_ms
            .is_some_and(|previous| at_ms.saturating_sub(previous) > MAX_ACCOUNTING_SAMPLE_GAP_MS)
        {
            self.reset_epoch(at_ms, scheduler_attach_seq, policy_generation, cells);
            return;
        }
        self.last_sample_at_ms = Some(at_ms);

        self.latest_cells = cells
            .iter()
            .map(|(&id, counters)| (id, counters.zero_like()))
            .collect();
        let deltas = cells
            .iter()
            .filter(|(_, counters)| !counters.is_empty())
            .map(|(&id, counters)| (id, counters.clone()))
            .collect::<BTreeMap<_, _>>();
        if !deltas.is_empty() {
            self.bins.push_back(CellMetricBin {
                at_ms,
                cells: deltas,
            });
        }
        self.expire(at_ms.saturating_sub(self.max_window_ms));
    }

    pub fn clear(&mut self) {
        self.started_at_ms = None;
        self.scheduler_attach_seq = None;
        self.policy_generation = None;
        self.last_sample_at_ms = None;
        self.latest_cells.clear();
        self.bins.clear();
    }

    pub fn view(
        &self,
        now_ms: u64,
        window_ms: u64,
    ) -> Result<Option<CellMetricWindow>, WindowError> {
        validate_window(window_ms, self.max_window_ms)?;
        let (Some(scheduler_attach_seq), Some(policy_generation)) =
            (self.scheduler_attach_seq, self.policy_generation)
        else {
            return Ok(None);
        };
        let cutoff_ms = now_ms.saturating_sub(window_ms);
        let mut cells = self.latest_cells.clone();
        for bin in self.bins.iter().filter(|bin| bin.at_ms > cutoff_ms) {
            for (&id, delta) in &bin.cells {
                cells
                    .entry(id)
                    .or_insert_with(|| delta.zero_like())
                    .add_assign(delta);
            }
        }
        let observed_ms = self
            .started_at_ms
            .map(|started| now_ms.saturating_sub(started).min(window_ms))
            .unwrap_or(0);
        Ok(Some(CellMetricWindow {
            scheduler_attach_seq,
            policy_generation,
            observed_ms,
            cells,
        }))
    }

    fn reset_epoch(
        &mut self,
        at_ms: u64,
        scheduler_attach_seq: u64,
        policy_generation: u64,
        cells: &BTreeMap<u32, CellMetricCounters>,
    ) {
        self.started_at_ms = Some(at_ms);
        self.scheduler_attach_seq = Some(scheduler_attach_seq);
        self.policy_generation = Some(policy_generation);
        self.last_sample_at_ms = Some(at_ms);
        self.latest_cells = cells
            .iter()
            .map(|(&id, counters)| (id, counters.zero_like()))
            .collect();
        self.bins.clear();
    }

    fn expire(&mut self, cutoff_ms: u64) {
        while self.bins.front().is_some_and(|bin| bin.at_ms <= cutoff_ms) {
            self.bins.pop_front();
        }
    }
}

#[derive(Debug)]
pub struct CpuUsageHistory {
    max_window_ms: u64,
    started_at_ms: Option<u64>,
    last_sample_at_ms: Option<u64>,
    bins: VecDeque<CpuUsageBin>,
}

#[derive(Debug)]
pub struct HostCpuTimeHistory {
    max_window_ms: u64,
    started_at_ms: Option<u64>,
    last_sample_at_ms: Option<u64>,
    latest: BTreeMap<u32, HostCpuTimeCounters>,
    bins: VecDeque<HostCpuTimeBin>,
}

impl HostCpuTimeHistory {
    pub fn new(max_window_ms: u64) -> Self {
        assert!(max_window_ms > 0, "maximum window must be non-zero");
        Self {
            max_window_ms,
            started_at_ms: None,
            last_sample_at_ms: None,
            latest: BTreeMap::new(),
            bins: VecDeque::new(),
        }
    }

    pub fn ingest(&mut self, at_ms: u64, current: &BTreeMap<u32, HostCpuTimeCounters>) {
        if self.started_at_ms.is_none() {
            self.started_at_ms = Some(at_ms);
            self.last_sample_at_ms = Some(at_ms);
            self.latest.clone_from(current);
            return;
        }
        if self
            .last_sample_at_ms
            .is_some_and(|previous| at_ms.saturating_sub(previous) > MAX_ACCOUNTING_SAMPLE_GAP_MS)
        {
            self.started_at_ms = Some(at_ms);
            self.last_sample_at_ms = Some(at_ms);
            self.latest.clone_from(current);
            self.bins.clear();
            return;
        }

        let cpus = current
            .iter()
            .filter_map(|(&cpu, &counters)| {
                let delta = counters.delta(*self.latest.get(&cpu)?)?;
                (!delta.is_empty()).then_some((cpu, delta))
            })
            .collect::<BTreeMap<_, _>>();
        if !cpus.is_empty() {
            self.bins.push_back(HostCpuTimeBin { at_ms, cpus });
        }
        self.latest.clone_from(current);
        self.last_sample_at_ms = Some(at_ms);
        self.expire(at_ms.saturating_sub(self.max_window_ms));
    }

    pub fn clear(&mut self) {
        self.started_at_ms = None;
        self.last_sample_at_ms = None;
        self.latest.clear();
        self.bins.clear();
    }

    pub fn view(&self, now_ms: u64, window_ms: u64) -> Result<HostCpuTimeWindow, WindowError> {
        validate_window(window_ms, self.max_window_ms)?;
        let cutoff_ms = now_ms.saturating_sub(window_ms);
        let mut cpus = BTreeMap::<u32, HostCpuTimeCounters>::new();
        for bin in self.bins.iter().filter(|bin| bin.at_ms > cutoff_ms) {
            for (&cpu, &delta) in &bin.cpus {
                cpus.entry(cpu).or_default().add_assign(delta);
            }
        }
        let observed_ms = self
            .started_at_ms
            .map(|started| now_ms.saturating_sub(started).min(window_ms))
            .unwrap_or(0);
        Ok(HostCpuTimeWindow { cpus, observed_ms })
    }

    fn expire(&mut self, cutoff_ms: u64) {
        while self.bins.front().is_some_and(|bin| bin.at_ms <= cutoff_ms) {
            self.bins.pop_front();
        }
    }
}

impl CpuUsageHistory {
    pub fn new(max_window_ms: u64) -> Self {
        assert!(max_window_ms > 0, "maximum window must be non-zero");
        Self {
            max_window_ms,
            started_at_ms: None,
            last_sample_at_ms: None,
            bins: VecDeque::new(),
        }
    }

    pub fn ingest(&mut self, at_ms: u64, runtime_ns: &BTreeMap<u32, u64>) {
        if self.started_at_ms.is_none() {
            self.reset(at_ms);
        }
        if self
            .last_sample_at_ms
            .is_some_and(|previous| at_ms.saturating_sub(previous) > MAX_ACCOUNTING_SAMPLE_GAP_MS)
        {
            self.reset(at_ms);
            return;
        }
        self.last_sample_at_ms = Some(at_ms);
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
        self.last_sample_at_ms = Some(at_ms);
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CallbackTimingCounters {
    pub total_ns: u64,
    pub buckets: Vec<u64>,
}

impl CallbackTimingCounters {
    fn zero_like(&self) -> Self {
        Self {
            total_ns: 0,
            buckets: vec![0; self.buckets.len()],
        }
    }

    fn checked_delta(&self, previous: &Self) -> Option<Self> {
        if self.buckets.len() != previous.buckets.len() {
            return None;
        }
        Some(Self {
            total_ns: self.total_ns.checked_sub(previous.total_ns)?,
            buckets: self
                .buckets
                .iter()
                .zip(&previous.buckets)
                .map(|(current, previous)| current.checked_sub(*previous))
                .collect::<Option<Vec<_>>>()?,
        })
    }

    fn add_assign(&mut self, other: &Self) {
        self.total_ns = self.total_ns.saturating_add(other.total_ns);
        for (total, delta) in self.buckets.iter_mut().zip(&other.buckets) {
            *total = total.saturating_add(*delta);
        }
    }

    fn is_empty(&self) -> bool {
        self.total_ns == 0 && self.buckets.iter().all(|count| *count == 0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallbackTimingSnapshot {
    pub enable_seq: u64,
    pub generation: u64,
    pub sample_rate: u32,
    pub callbacks: BTreeMap<String, CallbackTimingCounters>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallbackTimingWindow {
    pub generation: u64,
    pub sample_rate: u32,
    pub observed_ms: u64,
    pub callbacks: BTreeMap<String, CallbackTimingCounters>,
}

#[derive(Debug)]
struct CallbackTimingBin {
    at_ms: u64,
    callbacks: BTreeMap<String, CallbackTimingCounters>,
}

#[derive(Debug)]
pub struct CallbackTimingHistory {
    max_window_ms: u64,
    started_at_ms: Option<u64>,
    latest: Option<CallbackTimingSnapshot>,
    bins: VecDeque<CallbackTimingBin>,
}

impl CallbackTimingHistory {
    pub fn new(max_window_ms: u64) -> Self {
        assert!(max_window_ms > 0, "maximum window must be non-zero");
        Self {
            max_window_ms,
            started_at_ms: None,
            latest: None,
            bins: VecDeque::new(),
        }
    }

    pub fn ingest(&mut self, at_ms: u64, snapshot: CallbackTimingSnapshot) {
        let Some(previous) = self.latest.as_ref() else {
            self.reset(at_ms, snapshot);
            return;
        };
        if previous.enable_seq != snapshot.enable_seq
            || previous.generation != snapshot.generation
            || previous.sample_rate != snapshot.sample_rate
        {
            self.reset(at_ms, snapshot);
            return;
        }
        let Some(callbacks) = callback_timing_delta(&snapshot.callbacks, &previous.callbacks)
        else {
            self.reset(at_ms, snapshot);
            return;
        };

        if callbacks.values().any(|timing| !timing.is_empty()) {
            self.bins.push_back(CallbackTimingBin { at_ms, callbacks });
        }
        self.latest = Some(snapshot);
        self.expire(at_ms.saturating_sub(self.max_window_ms));
    }

    pub fn reset(&mut self, at_ms: u64, snapshot: CallbackTimingSnapshot) {
        self.started_at_ms = Some(at_ms);
        self.latest = Some(snapshot);
        self.bins.clear();
    }

    pub fn clear(&mut self) {
        self.started_at_ms = None;
        self.latest = None;
        self.bins.clear();
    }

    pub fn lifetime(&self) -> Option<&CallbackTimingSnapshot> {
        self.latest.as_ref()
    }

    pub fn window(
        &self,
        now_ms: u64,
        window_ms: u64,
    ) -> Result<Option<CallbackTimingWindow>, WindowError> {
        validate_window(window_ms, self.max_window_ms)?;
        let Some(latest) = &self.latest else {
            return Ok(None);
        };
        let cutoff_ms = now_ms.saturating_sub(window_ms);
        let mut callbacks = latest
            .callbacks
            .iter()
            .map(|(name, timing)| (name.clone(), timing.zero_like()))
            .collect::<BTreeMap<_, _>>();
        for bin in self.bins.iter().filter(|bin| bin.at_ms > cutoff_ms) {
            for (name, delta) in &bin.callbacks {
                if let Some(total) = callbacks.get_mut(name) {
                    total.add_assign(delta);
                }
            }
        }
        let observed_ms = self
            .started_at_ms
            .map(|started| now_ms.saturating_sub(started).min(window_ms))
            .unwrap_or(0);
        Ok(Some(CallbackTimingWindow {
            generation: latest.generation,
            sample_rate: latest.sample_rate,
            observed_ms,
            callbacks,
        }))
    }

    fn expire(&mut self, cutoff_ms: u64) {
        while self.bins.front().is_some_and(|bin| bin.at_ms <= cutoff_ms) {
            self.bins.pop_front();
        }
    }
}

fn callback_timing_delta(
    current: &BTreeMap<String, CallbackTimingCounters>,
    previous: &BTreeMap<String, CallbackTimingCounters>,
) -> Option<BTreeMap<String, CallbackTimingCounters>> {
    if current.len() != previous.len() || current.keys().ne(previous.keys()) {
        return None;
    }
    current
        .iter()
        .map(|(name, timing)| Some((name.clone(), timing.checked_delta(previous.get(name)?)?)))
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct CallbackTimingSummary {
    pub samples: u64,
    pub mean_ns: Option<u64>,
    pub p50_ns: Option<u64>,
    pub p95_ns: Option<u64>,
    pub p99_ns: Option<u64>,
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
