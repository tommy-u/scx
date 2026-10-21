// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-2.0-only

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::mem::size_of;

use crate::collector::Snapshot;
use crate::lifecycle::{CollectorStatus, ObserverContext, SampleMeta};
use crate::migration_history::MigrationWindowView;
use crate::topology::{CpuInfo, TopologyView};
use crate::MigrationRow;

const MAX_COLLECTION_INTERVAL_MS: u64 = 3_000;
const MAX_RETAINED_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WindowError {
    Zero,
    BeyondRetention { max_window_ms: u64 },
}

impl fmt::Display for WindowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero => write!(f, "window must be greater than zero"),
            Self::BeyondRetention { max_window_ms } => {
                write!(f, "window exceeds retained {max_window_ms} ms")
            }
        }
    }
}

impl std::error::Error for WindowError {}

#[derive(Debug)]
struct Baseline {
    epoch: u64,
    sample_seq: u64,
    at_unix_ms: u64,
    map_capacity: u32,
    map_failures: u64,
    counts: Vec<MigrationRow>,
}

#[derive(Debug)]
struct DeltaBin {
    at_unix_ms: u64,
    /// None means there was no trustworthy preceding counter baseline.
    start_unix_ms: Option<u64>,
    meta: SampleMeta,
    collector: ObserverContext,
    map_capacity: u32,
    map_failures: u64,
    source_available: bool,
    source_incomplete: bool,
    rows: Vec<MigrationRow>,
    /// same core, same LLC (other core), cross LLC (same NUMA), cross NUMA.
    locality_totals: [u64; 4],
    unknown_locality: u64,
}

impl DeltaBin {
    fn heap_bytes(&self) -> usize {
        self.rows.capacity() * size_of::<MigrationRow>()
            + string_capacity(&self.meta.error)
            + string_capacity(&self.collector.scheduler_name)
            + string_capacity(&self.collector.error)
    }
}

fn string_capacity(value: &Option<String>) -> usize {
    value.as_ref().map(String::capacity).unwrap_or_default()
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CpuPair(u32, u32);

fn pair(row: &MigrationRow) -> CpuPair {
    CpuPair(row.from_cpu, row.to_cpu)
}

enum Difference {
    Rows(Vec<MigrationRow>),
    RolledBack,
    MissingPair,
}

/// Cumulative map entries are never deleted during normal collection. A drop,
/// rollback, or map replacement is a new baseline, not a migration interval.
fn difference(previous: &[MigrationRow], current: &[MigrationRow]) -> Difference {
    let mut previous_index = 0;
    let mut rows = Vec::new();
    for row in current {
        let count = match previous.get(previous_index) {
            Some(old) if pair(old) < pair(row) => return Difference::MissingPair,
            Some(old) if pair(old) == pair(row) => {
                previous_index += 1;
                let Some(delta) = row.count.checked_sub(old.count) else {
                    return Difference::RolledBack;
                };
                delta
            }
            Some(_) | None => row.count,
        };
        if count > 0 {
            rows.push(MigrationRow {
                from_cpu: row.from_cpu,
                to_cpu: row.to_cpu,
                count,
            });
        }
    }
    if previous_index < previous.len() {
        Difference::MissingPair
    } else {
        Difference::Rows(rows)
    }
}

#[derive(Default)]
struct WindowSummary {
    observed_ms: u64,
    total: u64,
    locality_totals: [u64; 4],
    unknown_locality: u64,
    incomplete: bool,
}

/// Migration replay stores one delta interval per original counter capture.
/// Older observer epochs remain queryable. Only their differencing baseline is
/// replaced when a scheduler restarts. Retention includes an extra maximum
/// window so the earliest scrub position still has preceding interval data.
#[derive(Debug)]
pub struct ReplayMigrationHistory {
    retained_duration_ms: u64,
    max_window_ms: u64,
    max_bytes: usize,
    topology: Vec<CpuInfo>,
    baseline: Option<Baseline>,
    last_source: Option<(u64, u64, u64)>,
    bins: VecDeque<DeltaBin>,
    bin_heap_bytes: usize,
    latest_frame_at_unix_ms: u64,
}

impl ReplayMigrationHistory {
    pub fn new(retention_ms: u64, max_window_ms: u64, topology: &TopologyView) -> Self {
        assert!(retention_ms > 0, "replay retention must be non-zero");
        assert!(max_window_ms > 0, "maximum window must be non-zero");
        let mut cpus = topology.cpus.clone();
        cpus.sort_unstable_by_key(|cpu| cpu.cpu);
        Self {
            retained_duration_ms: retention_ms.saturating_add(max_window_ms),
            max_window_ms,
            max_bytes: MAX_RETAINED_BYTES,
            topology: cpus,
            baseline: None,
            last_source: None,
            bins: VecDeque::new(),
            bin_heap_bytes: 0,
            latest_frame_at_unix_ms: 0,
        }
    }

    pub fn ingest(&mut self, at_unix_ms: u64, snapshot: &Snapshot) {
        self.latest_frame_at_unix_ms = self.latest_frame_at_unix_ms.max(at_unix_ms);
        let source_available = snapshot.collector.status == CollectorStatus::Active
            && snapshot.collector.epoch == snapshot.meta.epoch
            && snapshot.collector.error.is_none()
            && snapshot.meta.error.is_none()
            && snapshot.meta.sample_seq > 0
            && snapshot.meta.captured_at_unix_ms.is_some()
            && snapshot.migration_map_capacity > 0
            && snapshot.migration_quality != "unavailable";
        let capture_at = if source_available {
            snapshot.meta.captured_at_unix_ms.unwrap()
        } else {
            // Waiting/error context has no capture timestamp. Keep its transition
            // time without rewriting the source's metadata or last-success time.
            at_unix_ms
        };
        let source_key = (snapshot.meta.epoch, snapshot.meta.sample_seq, capture_at);
        if source_available && self.last_source == Some(source_key) {
            self.enforce_retention();
            return;
        }
        if self
            .bins
            .back()
            .is_some_and(|last| capture_at < last.at_unix_ms)
        {
            self.enforce_retention();
            return;
        }

        let mut bin = DeltaBin {
            at_unix_ms: capture_at,
            start_unix_ms: None,
            meta: snapshot.meta.clone(),
            collector: snapshot.collector.clone(),
            map_capacity: snapshot.migration_map_capacity,
            map_failures: snapshot.migration_map_failures,
            source_available,
            source_incomplete: snapshot.migration_quality == "incomplete"
                || snapshot.migration_map_failures > 0,
            rows: Vec::new(),
            locality_totals: [0; 4],
            unknown_locality: 0,
        };
        if source_available {
            self.last_source = Some(source_key);
            let mut counts = snapshot.migrations.clone();
            counts.sort_unstable_by_key(pair);
            let mut keep_baseline = true;
            if let Some(previous) = self.baseline.as_ref().filter(|previous| {
                previous.epoch == snapshot.meta.epoch
                    && previous.sample_seq < snapshot.meta.sample_seq
                    && previous.at_unix_ms < capture_at
                    && capture_at - previous.at_unix_ms <= MAX_COLLECTION_INTERVAL_MS
                    && previous.map_capacity == snapshot.migration_map_capacity
                    && previous.map_failures <= snapshot.migration_map_failures
            }) {
                match difference(&previous.counts, &counts) {
                    Difference::Rows(rows) => {
                        bin.start_unix_ms = Some(previous.at_unix_ms);
                        bin.rows = rows;
                    }
                    Difference::RolledBack => {}
                    // A temporarily omitted pair can reappear with lifetime
                    // counts. Its next complete snapshot must become a baseline.
                    Difference::MissingPair => keep_baseline = false,
                }
            }
            for row in &bin.rows {
                if let Some(category) = self.locality_category(row) {
                    bin.locality_totals[category] =
                        bin.locality_totals[category].saturating_add(row.count);
                } else {
                    bin.unknown_locality = bin.unknown_locality.saturating_add(row.count);
                }
            }
            self.baseline = keep_baseline.then_some(Baseline {
                epoch: snapshot.meta.epoch,
                sample_seq: snapshot.meta.sample_seq,
                at_unix_ms: capture_at,
                map_capacity: snapshot.migration_map_capacity,
                map_failures: snapshot.migration_map_failures,
                counts,
            });
        } else {
            // A failed collection is unknown, including an apparently empty map.
            // Do not attribute cumulative changes across this gap to recovery.
            self.baseline = None;
        }
        self.bin_heap_bytes = self.bin_heap_bytes.saturating_add(bin.heap_bytes());
        self.bins.push_back(bin);
        self.enforce_retention();
    }

    /// Any positive duration is accepted, matching the original migration API
    /// and CLI. Subsecond windows do not increase collector sample resolution:
    /// complete migration intervals are selected by their capture endpoint.
    pub fn view_at(
        &self,
        at_unix_ms: u64,
        epoch: u64,
        window_ms: u64,
    ) -> Result<MigrationWindowView, WindowError> {
        self.validate_window(window_ms)?;
        let selected = self.selected_bin(at_unix_ms, epoch);
        let summary = self.window_summary(at_unix_ms, epoch, window_ms);
        let cutoff = at_unix_ms.saturating_sub(window_ms);
        let mut counts = BTreeMap::<CpuPair, u64>::new();
        for bin in self.window_bins(cutoff, at_unix_ms, epoch) {
            for row in &bin.rows {
                let count = counts.entry(pair(row)).or_default();
                *count = count.saturating_add(row.count);
            }
        }
        let rows = counts
            .into_iter()
            .map(|(CpuPair(from_cpu, to_cpu), count)| MigrationRow {
                from_cpu,
                to_cpu,
                count,
            })
            .collect();
        let (meta, collector, capacity, failures) = match selected {
            Some(bin) => (
                bin.meta.clone(),
                bin.collector.clone(),
                bin.map_capacity,
                bin.map_failures,
            ),
            None => (
                SampleMeta {
                    epoch,
                    error: Some("No retained migration sample at this time".into()),
                    ..SampleMeta::default()
                },
                ObserverContext {
                    epoch,
                    ..ObserverContext::default()
                },
                0,
                0,
            ),
        };
        Ok(MigrationWindowView {
            meta,
            collector,
            migration_map_capacity: capacity,
            migration_map_failures: failures,
            migration_quality: self.quality(selected, &summary, at_unix_ms, window_ms),
            window_ms,
            max_window_ms: self.max_window_ms,
            observed_ms: summary.observed_ms,
            total: summary.total,
            rate_per_second: if summary.observed_ms > 0 {
                summary.total as f64 * 1_000.0 / summary.observed_ms as f64
            } else {
                0.0
            },
            rows,
        })
    }

    /// Uses only four precomputed totals per bin. Building 30 minutes of chart
    /// points never repeatedly aggregates every CPU-to-CPU migration row.
    pub fn locality_at(
        &self,
        at_unix_ms: u64,
        epoch: u64,
        window_ms: u64,
    ) -> Result<[Option<f64>; 4], WindowError> {
        self.validate_window(window_ms)?;
        let summary = self.window_summary(at_unix_ms, epoch, window_ms);
        if self.quality(
            self.selected_bin(at_unix_ms, epoch),
            &summary,
            at_unix_ms,
            window_ms,
        ) == "unavailable"
            || summary.unknown_locality > 0
        {
            return Ok([None; 4]);
        }
        Ok(summary.locality_totals.map(|count| {
            Some(if summary.total > 0 {
                count as f64 * 100.0 / summary.total as f64
            } else {
                0.0
            })
        }))
    }

    /// Earliest preceding baseline still represented by the retained intervals.
    pub fn oldest_at_unix_ms(&self) -> Option<u64> {
        self.bins
            .front()
            .map(|bin| bin.start_unix_ms.unwrap_or(bin.at_unix_ms))
    }

    /// Configured query limit, including before the first captured sample.
    pub fn max_window_ms(&self) -> u64 {
        self.max_window_ms
    }

    /// Bound retained allocation, including the lifetime differencing baseline,
    /// topology, row capacities, metadata strings, and unused deque capacity.
    pub fn retained_bytes(&self) -> usize {
        size_of::<Self>()
            + self.topology.capacity() * size_of::<CpuInfo>()
            + self
                .baseline
                .as_ref()
                .map(|baseline| baseline.counts.capacity() * size_of::<MigrationRow>())
                .unwrap_or_default()
            + self.bins.capacity() * size_of::<DeltaBin>()
            + self.bin_heap_bytes
    }

    /// Explicit user reset clears history; observer epoch changes do not.
    pub fn clear(&mut self) {
        self.baseline = None;
        self.last_source = None;
        self.bins = VecDeque::new();
        self.bin_heap_bytes = 0;
        self.latest_frame_at_unix_ms = 0;
    }

    fn validate_window(&self, window_ms: u64) -> Result<(), WindowError> {
        if window_ms == 0 {
            Err(WindowError::Zero)
        } else if window_ms > self.max_window_ms {
            Err(WindowError::BeyondRetention {
                max_window_ms: self.max_window_ms,
            })
        } else {
            Ok(())
        }
    }

    fn selected_bin(&self, at_unix_ms: u64, epoch: u64) -> Option<&DeltaBin> {
        self.bins
            .iter()
            .rev()
            .find(|bin| bin.at_unix_ms <= at_unix_ms && bin.meta.epoch == epoch)
    }

    fn window_bins(
        &self,
        cutoff: u64,
        at_unix_ms: u64,
        epoch: u64,
    ) -> impl Iterator<Item = &DeltaBin> {
        self.bins.iter().filter(move |bin| {
            bin.at_unix_ms > cutoff && bin.at_unix_ms <= at_unix_ms && bin.meta.epoch == epoch
        })
    }

    fn window_summary(&self, at_unix_ms: u64, epoch: u64, window_ms: u64) -> WindowSummary {
        let cutoff = at_unix_ms.saturating_sub(window_ms);
        let mut summary = WindowSummary::default();
        for bin in self.window_bins(cutoff, at_unix_ms, epoch) {
            summary.incomplete |= bin.source_incomplete;
            if let Some(start) = bin.start_unix_ms {
                summary.observed_ms = summary
                    .observed_ms
                    .saturating_add(bin.at_unix_ms.saturating_sub(start.max(cutoff)));
            }
            for (index, count) in bin.locality_totals.iter().enumerate() {
                summary.locality_totals[index] =
                    summary.locality_totals[index].saturating_add(*count);
                summary.total = summary.total.saturating_add(*count);
            }
            summary.unknown_locality = summary
                .unknown_locality
                .saturating_add(bin.unknown_locality);
            summary.total = summary.total.saturating_add(bin.unknown_locality);
        }
        summary.observed_ms = summary.observed_ms.min(window_ms);
        summary
    }

    fn quality(
        &self,
        selected: Option<&DeltaBin>,
        summary: &WindowSummary,
        at_unix_ms: u64,
        window_ms: u64,
    ) -> &'static str {
        if !selected.is_some_and(|bin| bin.source_available) || summary.observed_ms == 0 {
            "unavailable"
        } else {
            // A frame can be captured just after its counter source. Preserve
            // the requested frame cutoff, but assess coverage only through the
            // original counter capture: its uncaptured tail is not data loss.
            // observed_ms still reports only the intervals actually retained.
            let cutoff = at_unix_ms.saturating_sub(window_ms);
            let captured_window_ms = selected
                .unwrap()
                .at_unix_ms
                .saturating_sub(cutoff)
                .min(window_ms);
            if at_unix_ms.saturating_sub(selected.unwrap().at_unix_ms) > MAX_COLLECTION_INTERVAL_MS
                || summary.observed_ms < captured_window_ms
                || summary.incomplete
            {
                "incomplete"
            } else {
                "complete"
            }
        }
    }

    fn locality_category(&self, row: &MigrationRow) -> Option<usize> {
        let from = self
            .topology
            .binary_search_by_key(&row.from_cpu, |cpu| cpu.cpu)
            .ok()
            .map(|index| self.topology[index])?;
        let to = self
            .topology
            .binary_search_by_key(&row.to_cpu, |cpu| cpu.cpu)
            .ok()
            .map(|index| self.topology[index])?;
        if !from.core_topology_available || !to.core_topology_available {
            return None;
        }
        Some(if from.package == to.package && from.core == to.core {
            0
        } else if from.package == to.package && from.llc == to.llc {
            1
        } else if from.node == to.node {
            2
        } else {
            3
        })
    }

    fn pop_front(&mut self) {
        if let Some(bin) = self.bins.pop_front() {
            self.bin_heap_bytes = self.bin_heap_bytes.saturating_sub(bin.heap_bytes());
        }
    }

    fn enforce_retention(&mut self) {
        let cutoff = self
            .latest_frame_at_unix_ms
            .saturating_sub(self.retained_duration_ms);
        while self
            .bins
            .front()
            .is_some_and(|bin| bin.at_unix_ms <= cutoff)
        {
            self.pop_front();
        }
        if self.retained_bytes() > self.max_bytes {
            self.bins.shrink_to_fit();
        }
        while self.retained_bytes() > self.max_bytes && !self.bins.is_empty() {
            self.pop_front();
            self.bins.shrink_to_fit();
        }
        if self.retained_bytes() > self.max_bytes {
            // An individual lifetime baseline can exceed a reduced budget. It
            // cannot be partially differenced without manufacturing counts.
            self.baseline = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::CollectorConfig;
    use crate::lifecycle::CollectorStatus;
    use crate::MigrationRow;

    #[test]
    fn byte_eviction_shortens_known_coverage_without_claiming_a_complete_window() {
        let topology = TopologyView::from_cpus(vec![]).unwrap();
        let mut history = ReplayMigrationHistory::new(30 * 60_000, 5_000, &topology);
        history.max_bytes = 1_500;
        let mut snapshot = Snapshot::empty(CollectorConfig {
            callback_timing_sample_rate: 1,
            event_timing_sample_rate: 1,
            enable_dsq: false,
            enable_scheduler_events: false,
            enable_irqs: false,
            enable_block_io: false,
        });
        snapshot.collector.status = CollectorStatus::Active;
        snapshot.collector.epoch = 1;
        snapshot.migration_map_capacity = 25_600;
        snapshot.migration_quality = "complete";
        for seq in 1..=20 {
            let at = 9_000 + seq * 1_000;
            snapshot.meta = SampleMeta {
                epoch: 1,
                sample_seq: seq,
                captured_at_unix_ms: Some(at),
                last_success_at_unix_ms: Some(at),
                error: None,
            };
            snapshot.migrations = vec![MigrationRow {
                from_cpu: 0,
                to_cpu: 1,
                count: 100 + seq,
            }];
            history.ingest(at, &snapshot);
        }
        assert!(history.retained_bytes() <= history.max_bytes);
        let view = history.view_at(29_000, 1, 5_000).unwrap();
        assert!(view.observed_ms > 0);
        assert!(view.observed_ms < 5_000);
        assert_eq!(view.migration_quality, "incomplete");
        assert_eq!(
            history.view_at(29_000, 1, 1_000).unwrap().observed_ms,
            1_000
        );
    }
}
