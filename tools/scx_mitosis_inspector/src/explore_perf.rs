// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-2.0-only

//! Counting-only Linux PMU collection. No sampling buffers or interrupts are
//! configured. Ratios use two-event groups so their numerators and denominators
//! run concurrently even when the PMU multiplexes the three groups.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{json, Value};

use crate::explore_model::ExploreGroup;
use crate::lifecycle::{unix_ms, SampleMeta};

const SCOPE: &str = "Whole CPU: all tasks, kernel and hypervisor; generic hardware events";
const MAX_INTERVAL: Duration = Duration::from_secs(5);
const FIRST_RETRY_SECONDS: u64 = 30;
const MAX_RETRY_SECONDS: u64 = 300;
const FD_RESERVE: usize = 128;

// UAPI values from linux/perf_event.h. Attribute version zero is 64 bytes,
// supported by every Linux kernel with perf_event_open.
const PERF_FLAG_FD_CLOEXEC: libc::c_ulong = 1 << 3;
const PERF_EVENT_IOC_ENABLE: libc::c_ulong = 0x2400;
const PERF_EVENT_IOC_RESET: libc::c_ulong = 0x2403;
const PERF_EVENT_IOC_ID: libc::c_ulong = 0x8008_2407;
const PERF_IOC_FLAG_GROUP: libc::c_ulong = 1;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
enum MetricKind {
    Cycles,
    Instructions,
    CacheReferences,
    CacheMisses,
    StalledFrontendCycles,
    StalledBackendCycles,
}

const METRIC_GROUPS: [[MetricKind; 2]; 3] = [
    [MetricKind::Cycles, MetricKind::Instructions],
    [MetricKind::CacheReferences, MetricKind::CacheMisses],
    [
        MetricKind::StalledFrontendCycles,
        MetricKind::StalledBackendCycles,
    ],
];
const METRICS: [MetricKind; 6] = [
    MetricKind::Cycles,
    MetricKind::Instructions,
    MetricKind::CacheReferences,
    MetricKind::CacheMisses,
    MetricKind::StalledFrontendCycles,
    MetricKind::StalledBackendCycles,
];

impl MetricKind {
    fn key(self) -> &'static str {
        match self {
            Self::Cycles => "cycles",
            Self::Instructions => "instructions",
            Self::CacheReferences => "cache_references",
            Self::CacheMisses => "cache_misses",
            Self::StalledFrontendCycles => "stalled_frontend_cycles",
            Self::StalledBackendCycles => "stalled_backend_cycles",
        }
    }

    fn config(self) -> u64 {
        match self {
            Self::Cycles => 0,
            Self::Instructions => 1,
            Self::CacheReferences => 2,
            Self::CacheMisses => 3,
            Self::StalledFrontendCycles => 7,
            Self::StalledBackendCycles => 8,
        }
    }
}

#[repr(C)]
#[derive(Debug, Default)]
struct PerfEventAttr {
    event_type: u32,
    size: u32,
    config: u64,
    sample_period: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events: u32,
    bp_type: u32,
    config1: u64,
}

impl PerfEventAttr {
    fn counting(kind: MetricKind) -> Self {
        Self {
            size: std::mem::size_of::<Self>() as u32,
            config: kind.config(),
            read_format: 15, // TOTAL_TIME_ENABLED | TOTAL_TIME_RUNNING | ID | GROUP
            flags: 1,        // disabled until the complete group is enabled
            ..Self::default()
        }
    }
}

#[derive(Debug)]
struct PerfEvent {
    fd: OwnedFd,
    kind: MetricKind,
    id: u64,
}

#[derive(Clone, Debug)]
struct GroupSample {
    time_enabled_ns: u64,
    time_running_ns: u64,
    values: BTreeMap<MetricKind, u64>,
}

#[derive(Debug)]
struct GroupBaseline {
    at: Instant,
    sample: GroupSample,
}

#[derive(Clone, Debug, Default, Serialize)]
struct MetricReading {
    available: bool,
    error: Option<String>,
    raw_total: Option<u64>,
    raw_delta: Option<u64>,
    scaled_delta: Option<f64>,
    per_second: Option<f64>,
    time_enabled_ns: Option<u64>,
    time_running_ns: Option<u64>,
    enabled_delta_ns: Option<u64>,
    running_delta_ns: Option<u64>,
    coverage_pct: Option<f64>,
    interval_ms: Option<f64>,
    baseline: bool,
}

impl MetricReading {
    fn unavailable(error: String) -> Self {
        Self {
            error: Some(error),
            ..Self::default()
        }
    }
}

fn interval_views(
    current: &GroupSample,
    previous: Option<&GroupBaseline>,
    now: Instant,
) -> BTreeMap<MetricKind, MetricReading> {
    current
        .values
        .iter()
        .map(|(&kind, &total)| {
            let mut view = MetricReading {
                available: true,
                raw_total: Some(total),
                time_enabled_ns: Some(current.time_enabled_ns),
                time_running_ns: Some(current.time_running_ns),
                baseline: true,
                ..Default::default()
            };
            let Some(previous) = previous else {
                return (kind, view);
            };
            let Some(elapsed) = now.checked_duration_since(previous.at) else {
                view.error = Some("PMU interval clock reset; collecting a new baseline".into());
                return (kind, view);
            };
            if elapsed.is_zero() || elapsed > MAX_INTERVAL {
                view.error = Some("PMU sampling gap; collecting a new baseline".into());
                return (kind, view);
            }
            let Some(&old_total) = previous.sample.values.get(&kind) else {
                return (kind, view);
            };
            let deltas = total
                .checked_sub(old_total)
                .zip(
                    current
                        .time_enabled_ns
                        .checked_sub(previous.sample.time_enabled_ns),
                )
                .zip(
                    current
                        .time_running_ns
                        .checked_sub(previous.sample.time_running_ns),
                );
            let Some(((raw_delta, enabled_delta), running_delta)) = deltas else {
                view.error = Some("PMU counter reset; collecting a new baseline".into());
                return (kind, view);
            };
            if running_delta > enabled_delta {
                view.error = Some("PMU interval running time exceeds enabled time".into());
                return (kind, view);
            }
            view.raw_delta = Some(raw_delta);
            view.enabled_delta_ns = Some(enabled_delta);
            view.running_delta_ns = Some(running_delta);
            view.interval_ms = Some(elapsed.as_secs_f64() * 1_000.0);
            view.baseline = false;
            view.coverage_pct =
                (enabled_delta > 0).then(|| running_delta as f64 * 100.0 / enabled_delta as f64);
            if enabled_delta == 0 || running_delta == 0 {
                view.error = Some("PMU event was not scheduled during this interval".into());
                return (kind, view);
            }
            let scaled = raw_delta as f64 * enabled_delta as f64 / running_delta as f64;
            view.scaled_delta = Some(scaled);
            view.per_second = Some(scaled / elapsed.as_secs_f64());
            (kind, view)
        })
        .collect()
}

fn parse_group_read(bytes: &[u8], ids: &[(MetricKind, u64)]) -> Result<GroupSample, String> {
    if bytes.len() < 24 || bytes.len() % 8 != 0 {
        return Err("Short or malformed PMU group read".into());
    }
    let words: Vec<u64> = bytes
        .chunks_exact(8)
        .map(|word| u64::from_ne_bytes(word.try_into().expect("eight-byte word")))
        .collect();
    if words[0] != ids.len() as u64 || words.len() != 3 + 2 * ids.len() {
        return Err("PMU group member count changed".into());
    }
    if words[2] > words[1] {
        return Err("PMU running time exceeds enabled time".into());
    }
    let mut values = BTreeMap::new();
    for pair in words[3..].chunks_exact(2) {
        let Some(&(kind, _)) = ids.iter().find(|(_, id)| *id == pair[1]) else {
            return Err("PMU group returned an unknown event ID".into());
        };
        if values.insert(kind, pair[0]).is_some() {
            return Err("PMU group returned a duplicate event ID".into());
        }
    }
    Ok(GroupSample {
        time_enabled_ns: words[1],
        time_running_ns: words[2],
        values,
    })
}

fn read_group(events: &[PerfEvent]) -> Result<GroupSample, String> {
    let Some(leader) = events.first() else {
        return Err("No supported PMU events in this group".into());
    };
    // Each group is at most two events: nr, time_enabled, time_running and
    // two (count, id) pairs. The kernel returns one complete group read.
    let mut buffer = [0_u8; 56];
    let size = loop {
        // SAFETY: buffer is writable for buffer.len(), and OwnedFd keeps the
        // descriptor alive throughout this read.
        let size = unsafe {
            libc::read(
                leader.fd.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
            )
        };
        if size >= 0 {
            break size as usize;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(format!("Reading PMU group: {error}"));
        }
    };
    if size == 0 {
        return Err("PMU group read returned no data (CPU offline or PMU unavailable)".into());
    }
    let ids: Vec<_> = events.iter().map(|event| (event.kind, event.id)).collect();
    parse_group_read(&buffer[..size], &ids)
}

fn open_event(cpu: u32, kind: MetricKind, group_fd: libc::c_int) -> Result<PerfEvent, String> {
    let cpu = libc::c_int::try_from(cpu)
        .map_err(|_| "CPU ID exceeds perf_event_open's signed integer range".to_string())?;
    let attr = PerfEventAttr::counting(kind);
    // SAFETY: the 64-byte version-zero attribute has the Linux UAPI layout.
    // pid=-1 selects every task on this CPU; no sampling or exclusions are set.
    let raw_fd = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            &attr as *const PerfEventAttr,
            -1 as libc::pid_t,
            cpu,
            group_fd,
            PERF_FLAG_FD_CLOEXEC,
        )
    };
    if raw_fd < 0 {
        let error = io::Error::last_os_error();
        return Err(format!("Opening {} on CPU {cpu}: {error}", kind.key()));
    }
    // SAFETY: the successful syscall returned a new descriptor owned here.
    // OwnedFd closes it on every following error path and on collector drop.
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd as libc::c_int) };
    let mut id = 0_u64;
    // SAFETY: the ioctl writes one u64 to id and fd is a live perf descriptor.
    if unsafe { libc::ioctl(fd.as_raw_fd(), PERF_EVENT_IOC_ID, &mut id as *mut u64) } < 0 {
        return Err(format!(
            "Reading {} event ID: {}",
            kind.key(),
            io::Error::last_os_error()
        ));
    }
    Ok(PerfEvent { fd, kind, id })
}

fn enable_group(events: &[PerfEvent]) -> Result<(), String> {
    let Some(leader) = events.first() else {
        return Ok(());
    };
    for request in [PERF_EVENT_IOC_RESET, PERF_EVENT_IOC_ENABLE] {
        // SAFETY: this is a perf descriptor and these ioctls take the GROUP
        // integer flag, not a userspace pointer. They affect only our events.
        if unsafe { libc::ioctl(leader.fd.as_raw_fd(), request, PERF_IOC_FLAG_GROUP) } < 0 {
            return Err(format!(
                "Enabling PMU group: {}",
                io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

#[derive(Debug)]
struct PerfGroup {
    kinds: [MetricKind; 2],
    events: Vec<PerfEvent>,
    errors: BTreeMap<MetricKind, String>,
    previous: Option<GroupBaseline>,
    next_attempt: Option<Instant>,
    retry_seconds: u64,
    initialized: bool,
}

impl PerfGroup {
    fn new(kinds: [MetricKind; 2]) -> Self {
        Self {
            kinds,
            events: Vec::new(),
            errors: BTreeMap::new(),
            previous: None,
            next_attempt: None,
            retry_seconds: FIRST_RETRY_SECONDS,
            initialized: false,
        }
    }

    fn schedule_retry(&mut self, now: Instant) {
        self.next_attempt = Some(now + Duration::from_secs(self.retry_seconds));
        self.retry_seconds = self.retry_seconds.saturating_mul(2).min(MAX_RETRY_SECONDS);
    }

    fn open(&mut self, cpu: u32, now: Instant, fd_budget: usize) {
        // Retrying a partial group replaces our descriptors and starts a new
        // baseline. This avoids combining a new member's lifetime with the old
        // group leader's time_enabled/time_running values.
        self.events.clear();
        self.previous = None;
        self.errors.clear();
        self.initialized = true;
        for kind in self.kinds {
            if self.events.len() >= fd_budget {
                self.errors.insert(kind, "PMU descriptor budget exhausted; keeping descriptors available for the inspector".into());
                continue;
            }
            let leader_fd = self
                .events
                .first()
                .map(|event| event.fd.as_raw_fd())
                .unwrap_or(-1);
            match open_event(cpu, kind, leader_fd) {
                Ok(event) => self.events.push(event),
                Err(error) => {
                    self.errors.insert(kind, error);
                }
            }
        }
        if let Err(error) = enable_group(&self.events) {
            self.events.clear();
            self.errors = self
                .kinds
                .into_iter()
                .map(|kind| (kind, error.clone()))
                .collect();
        }
        if self.events.len() == self.kinds.len() {
            self.next_attempt = None;
            self.retry_seconds = FIRST_RETRY_SECONDS;
        } else {
            self.schedule_retry(now);
        }
    }

    fn collect(
        &mut self,
        cpu: u32,
        now: Instant,
        fd_budget: usize,
    ) -> BTreeMap<MetricKind, MetricReading> {
        if !self.initialized || self.next_attempt.is_some_and(|at| now >= at) {
            self.open(cpu, now, fd_budget);
        }
        let mut readings: BTreeMap<_, _> = self
            .errors
            .iter()
            .map(|(&kind, error)| (kind, MetricReading::unavailable(error.clone())))
            .collect();
        if !self.events.is_empty() {
            match read_group(&self.events) {
                Ok(sample) => {
                    let at = Instant::now();
                    readings.extend(interval_views(&sample, self.previous.as_ref(), at));
                    self.previous = Some(GroupBaseline { at, sample });
                }
                Err(error) => {
                    self.events.clear();
                    self.previous = None;
                    self.errors = self
                        .kinds
                        .into_iter()
                        .map(|kind| (kind, error.clone()))
                        .collect();
                    readings = self
                        .errors
                        .iter()
                        .map(|(&kind, error)| (kind, MetricReading::unavailable(error.clone())))
                        .collect();
                    self.schedule_retry(now);
                }
            }
        }
        readings
    }
}

#[derive(Debug)]
struct CpuPerf {
    cpu: u32,
    groups: [PerfGroup; 3],
}

#[derive(Debug)]
struct CpuReading {
    cpu: u32,
    llc_id: Option<u32>,
    metrics: BTreeMap<MetricKind, MetricReading>,
}

fn rate(cpu: &CpuReading, kind: MetricKind) -> Option<f64> {
    cpu.metrics.get(&kind).and_then(|metric| metric.per_second)
}

fn paired_rates(
    cpu: &CpuReading,
    numerator: MetricKind,
    denominator: MetricKind,
) -> Option<(f64, f64)> {
    rate(cpu, numerator).zip(rate(cpu, denominator))
}

fn ratio(numerator: f64, denominator: f64) -> Option<f64> {
    (denominator > 0.0).then(|| numerator / denominator)
}

fn cpu_row(cpu: &CpuReading) -> Value {
    let mut row = json!({
        "cpu": cpu.cpu,
        "llc_id": cpu.llc_id,
        "available": cpu.metrics.values().any(|metric| metric.available),
        "partial": METRICS.iter().any(|kind| cpu.metrics.get(kind).is_none_or(|metric| !metric.available || metric.error.is_some())),
        "error": cpu.metrics.values().filter_map(|metric| metric.error.as_ref()).cloned().collect::<Vec<_>>().join("; "),
        "interval_ms": cpu.metrics.values().filter_map(|metric| metric.interval_ms).next(),
        "ipc": paired_rates(cpu, MetricKind::Instructions, MetricKind::Cycles).and_then(|(a, b)| ratio(a, b)),
        "cache_miss_pct": paired_rates(cpu, MetricKind::CacheMisses, MetricKind::CacheReferences).and_then(|(a, b)| ratio(a, b)).map(|value| value * 100.0),
        "metrics": cpu.metrics,
    });
    for kind in METRICS {
        row[format!("{}_per_second", kind.key())] = json!(rate(cpu, kind));
    }
    row
}

fn aggregate_cpu_rows(cpus: &[&CpuReading]) -> Value {
    let available = cpus
        .iter()
        .filter(|cpu| cpu.metrics.values().any(|metric| metric.available))
        .count();
    let sampled = cpus
        .iter()
        .filter(|cpu| {
            cpu.metrics
                .values()
                .any(|metric| metric.per_second.is_some())
        })
        .count();
    let partial = cpus.iter().any(|cpu| {
        METRICS.iter().any(|kind| {
            cpu.metrics
                .get(kind)
                .is_none_or(|metric| metric.per_second.is_none())
        })
    });
    let mut result = json!({
        "cpu_count": cpus.len(),
        "available_cpus": available,
        "unavailable_cpus": cpus.len().saturating_sub(available),
        "sampled_cpus": sampled,
        "partial": partial,
        "metric_cpu_counts": {},
    });
    for kind in METRICS {
        let values: Vec<f64> = cpus.iter().filter_map(|cpu| rate(cpu, kind)).collect();
        result[format!("{}_per_second", kind.key())] =
            json!((!values.is_empty()).then(|| values.iter().sum::<f64>()));
        result["metric_cpu_counts"][kind.key()] = json!(values.len());
    }
    for (key, numerator, denominator, multiplier) in [
        ("ipc", MetricKind::Instructions, MetricKind::Cycles, 1.0),
        (
            "cache_miss_pct",
            MetricKind::CacheMisses,
            MetricKind::CacheReferences,
            100.0,
        ),
    ] {
        let pairs: Vec<_> = cpus
            .iter()
            .filter_map(|cpu| paired_rates(cpu, numerator, denominator))
            .collect();
        result[key] = json!((!pairs.is_empty())
            .then(|| (
                pairs.iter().map(|pair| pair.0).sum::<f64>(),
                pairs.iter().map(|pair| pair.1).sum::<f64>()
            ))
            .and_then(|(a, b)| ratio(a, b))
            .map(|value| value * multiplier));
        result[format!(
            "{}_sampled_cpus",
            if key == "ipc" { "ipc" } else { "cache" }
        )] = json!(pairs.len());
    }
    let coverage: Vec<f64> = cpus
        .iter()
        .flat_map(|cpu| {
            cpu.metrics
                .values()
                .filter_map(|metric| metric.coverage_pct)
        })
        .collect();
    result["minimum_pmu_coverage_pct"] = json!(coverage.iter().copied().reduce(f64::min));
    result["maximum_pmu_coverage_pct"] = json!(coverage.iter().copied().reduce(f64::max));
    result
}

fn descriptor_budget(requested: usize) -> usize {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit fills the initialized rlimit; it changes no limits.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } < 0 {
        return requested;
    }
    let open_descriptors = std::fs::read_dir("/proc/self/fd")
        .map(|entries| entries.count())
        .unwrap_or(0);
    usize::try_from(limit.rlim_cur)
        .unwrap_or(usize::MAX)
        .saturating_sub(open_descriptors.saturating_add(FD_RESERVE))
        .min(requested)
}

/// Owns at most six counting descriptors for each provided CPU. No procfs,
/// sysfs, security policy, scheduler setting or service is modified.
#[derive(Debug)]
pub struct ExplorePerfCollector {
    cpus: Vec<CpuPerf>,
    llc_ids: BTreeMap<u32, u32>,
    event_fd_limit: usize,
    sample_seq: u64,
    last_success_at_unix_ms: Option<u64>,
    previous_collection: Option<Instant>,
}

impl ExplorePerfCollector {
    pub fn new(cpu_ids: Vec<u32>) -> Self {
        let ids: BTreeSet<u32> = cpu_ids.into_iter().collect();
        let event_fd_limit = descriptor_budget(ids.len().saturating_mul(METRICS.len()));
        Self {
            cpus: ids
                .into_iter()
                .map(|cpu| CpuPerf {
                    cpu,
                    groups: METRIC_GROUPS.map(PerfGroup::new),
                })
                .collect(),
            llc_ids: BTreeMap::new(),
            event_fd_limit,
            sample_seq: 0,
            last_success_at_unix_ms: None,
            previous_collection: None,
        }
    }

    pub fn with_llc_ids(mut self, llc_ids: BTreeMap<u32, u32>) -> Self {
        self.llc_ids = llc_ids;
        self
    }

    pub fn collect(&mut self) -> ExploreGroup {
        let now = Instant::now();
        let interval_ms = self
            .previous_collection
            .replace(now)
            .map(|at| now.duration_since(at).as_secs_f64() * 1_000.0);
        let mut open_fds: usize = self
            .cpus
            .iter()
            .flat_map(|cpu| &cpu.groups)
            .map(|group| group.events.len())
            .sum();
        let mut cpus = Vec::with_capacity(self.cpus.len());
        for cpu in &mut self.cpus {
            let mut metrics = BTreeMap::new();
            for group in &mut cpu.groups {
                let previous_fds = group.events.len();
                let budget = self
                    .event_fd_limit
                    .saturating_sub(open_fds.saturating_sub(previous_fds));
                metrics.extend(group.collect(cpu.cpu, now, budget));
                open_fds = open_fds
                    .saturating_sub(previous_fds)
                    .saturating_add(group.events.len());
            }
            cpus.push(CpuReading {
                cpu: cpu.cpu,
                llc_id: self.llc_ids.get(&cpu.cpu).copied(),
                metrics,
            });
        }
        let available = cpus
            .iter()
            .any(|cpu| cpu.metrics.values().any(|metric| metric.available));
        let error = (!available).then(|| {
            if cpus.is_empty() {
                "No CPUs available in host topology".to_string()
            } else {
                cpus.iter()
                    .flat_map(|cpu| cpu.metrics.values())
                    .filter_map(|metric| metric.error.clone())
                    .next()
                    .unwrap_or_else(|| "Hardware PMU counters are unavailable".into())
            }
        });
        let mut summary = aggregate_cpu_rows(&cpus.iter().collect::<Vec<_>>());
        summary["interval_ms"] = json!(interval_ms);
        summary["open_descriptors"] = json!(open_fds);
        summary["descriptor_budget"] = json!(self.event_fd_limit);
        summary["llc_unknown_cpus"] = json!(cpus.iter().filter(|cpu| cpu.llc_id.is_none()).count());
        let llcs: BTreeSet<u32> = cpus.iter().filter_map(|cpu| cpu.llc_id).collect();
        summary["llcs"] = json!(llcs
            .into_iter()
            .map(|llc_id| {
                let mut llc = aggregate_cpu_rows(
                    &cpus
                        .iter()
                        .filter(|cpu| cpu.llc_id == Some(llc_id))
                        .collect::<Vec<_>>(),
                );
                llc["llc_id"] = json!(llc_id);
                llc
            })
            .collect::<Vec<_>>());
        summary["note"] = json!("Counting only, without perf sampling interrupts. Interval counts are scaled by time_enabled/time_running; low PMU coverage increases estimation error. IPC and cache miss percentage use concurrently counted pairs and only CPUs with both rates. Generic cache and stalled-cycle definitions depend on the CPU PMU. Missing counters and unscheduled events are not zero. Unsupported sources retry after 30 seconds, backing off to 5 minutes. No rates are bridged across read gaps longer than 5 seconds.");
        let at = unix_ms();
        self.sample_seq = self.sample_seq.saturating_add(1);
        if available {
            self.last_success_at_unix_ms = Some(at);
        }
        let mut group = ExploreGroup::available(SCOPE, summary, cpus.iter().map(cpu_row).collect());
        group.available = available;
        group.partial = group.summary["partial"].as_bool().unwrap_or(false);
        group.error = error.clone();
        group.meta = SampleMeta {
            sample_seq: self.sample_seq,
            captured_at_unix_ms: Some(at),
            last_success_at_unix_ms: self.last_success_at_unix_ms,
            error,
            ..Default::default()
        };
        group
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::time::{Duration, Instant};

    fn measured(rate: f64, coverage: f64) -> MetricReading {
        MetricReading {
            available: true,
            per_second: Some(rate),
            coverage_pct: Some(coverage),
            ..Default::default()
        }
    }

    fn reading(enabled: u64, running: u64, counts: &[(MetricKind, u64)]) -> GroupSample {
        GroupSample {
            time_enabled_ns: enabled,
            time_running_ns: running,
            values: counts.iter().copied().collect(),
        }
    }

    fn encoded_read(enabled: u64, running: u64, values: &[(u64, u64)]) -> Vec<u8> {
        let mut words = vec![values.len() as u64, enabled, running];
        for (id, value) in values {
            words.extend([*value, *id]);
        }
        words.into_iter().flat_map(u64::to_ne_bytes).collect()
    }

    #[test]
    fn multiplexed_counts_use_interval_running_time() {
        let start = Instant::now();
        let previous = GroupBaseline {
            at: start,
            sample: reading(4_000_000_000, 3_000_000_000, &[(MetricKind::Cycles, 1_000)]),
        };
        let next = reading(5_000_000_000, 3_500_000_000, &[(MetricKind::Cycles, 1_100)]);
        let views = interval_views(&next, Some(&previous), start + Duration::from_secs(1));
        let cycles = &views[&MetricKind::Cycles];
        assert_eq!(cycles.raw_delta, Some(100));
        assert_eq!(cycles.scaled_delta, Some(200.0));
        assert_eq!(cycles.per_second, Some(200.0));
        assert_eq!(cycles.coverage_pct, Some(50.0));
        assert_eq!(cycles.enabled_delta_ns, Some(1_000_000_000));
        assert_eq!(cycles.running_delta_ns, Some(500_000_000));
    }

    #[test]
    fn initial_sample_preserves_totals_without_inventing_rates() {
        let sample = reading(
            1_000_000_000,
            800_000_000,
            &[(MetricKind::Instructions, 500)],
        );
        let views = interval_views(&sample, None, Instant::now());
        let value = &views[&MetricKind::Instructions];
        assert!(value.available);
        assert!(value.baseline);
        assert_eq!(value.raw_total, Some(500));
        assert_eq!(value.raw_delta, None);
        assert_eq!(value.scaled_delta, None);
        assert_eq!(value.per_second, None);
        assert_eq!(value.coverage_pct, None);
    }

    #[test]
    fn unscheduled_pmu_is_missing_even_when_count_does_not_change() {
        let start = Instant::now();
        let previous = GroupBaseline {
            at: start,
            sample: reading(1_000_000_000, 0, &[(MetricKind::Cycles, 0)]),
        };
        let sample = reading(2_000_000_000, 0, &[(MetricKind::Cycles, 0)]);
        let views = interval_views(&sample, Some(&previous), start + Duration::from_secs(1));
        let value = &views[&MetricKind::Cycles];
        assert_eq!(value.raw_delta, Some(0));
        assert_eq!(value.per_second, None);
        assert_eq!(value.scaled_delta, None);
        assert_eq!(value.coverage_pct, Some(0.0));
        assert!(value.error.as_deref().unwrap().contains("not scheduled"));
    }

    #[test]
    fn measured_zero_is_a_valid_rate() {
        let start = Instant::now();
        let previous = GroupBaseline {
            at: start,
            sample: reading(
                1_000_000_000,
                1_000_000_000,
                &[(MetricKind::CacheMisses, 20)],
            ),
        };
        let sample = reading(
            2_000_000_000,
            2_000_000_000,
            &[(MetricKind::CacheMisses, 20)],
        );
        let views = interval_views(&sample, Some(&previous), start + Duration::from_secs(1));
        let value = &views[&MetricKind::CacheMisses];
        assert_eq!(value.per_second, Some(0.0));
        assert_eq!(value.coverage_pct, Some(100.0));
        assert_eq!(value.error, None);
        assert!(!value.baseline);
    }

    #[test]
    fn counter_reset_does_not_make_a_wrapped_delta() {
        let start = Instant::now();
        let previous = GroupBaseline {
            at: start,
            sample: reading(1_000_000_000, 1_000_000_000, &[(MetricKind::Cycles, 1_000)]),
        };
        let sample = reading(2_000_000_000, 2_000_000_000, &[(MetricKind::Cycles, 2)]);
        let views = interval_views(&sample, Some(&previous), start + Duration::from_secs(1));
        let value = &views[&MetricKind::Cycles];
        assert!(value.baseline);
        assert_eq!(value.raw_delta, None);
        assert_eq!(value.per_second, None);
        assert!(value.error.as_deref().unwrap().contains("reset"));
    }

    #[test]
    fn reset_enabled_clock_discards_all_event_deltas() {
        let start = Instant::now();
        let previous = GroupBaseline {
            at: start,
            sample: reading(2_000_000_000, 2_000_000_000, &[(MetricKind::Cycles, 100)]),
        };
        let sample = reading(1_000_000_000, 1_000_000_000, &[(MetricKind::Cycles, 200)]);
        let views = interval_views(&sample, Some(&previous), start + Duration::from_secs(1));
        assert_eq!(views[&MetricKind::Cycles].per_second, None);
        assert!(views[&MetricKind::Cycles].baseline);
    }

    #[test]
    fn long_read_gap_restarts_baseline() {
        let start = Instant::now();
        let previous = GroupBaseline {
            at: start,
            sample: reading(1_000_000_000, 1_000_000_000, &[(MetricKind::Cycles, 100)]),
        };
        let sample = reading(
            31_000_000_000,
            31_000_000_000,
            &[(MetricKind::Cycles, 1_000)],
        );
        let views = interval_views(&sample, Some(&previous), start + Duration::from_secs(30));
        assert_eq!(views[&MetricKind::Cycles].per_second, None);
        assert!(views[&MetricKind::Cycles].baseline);
        assert!(views[&MetricKind::Cycles]
            .error
            .as_deref()
            .unwrap()
            .contains("gap"));
    }

    #[test]
    fn new_member_waits_for_its_own_baseline() {
        let start = Instant::now();
        let previous = GroupBaseline {
            at: start,
            sample: reading(1_000_000_000, 1_000_000_000, &[(MetricKind::Cycles, 100)]),
        };
        let sample = reading(
            2_000_000_000,
            2_000_000_000,
            &[(MetricKind::Cycles, 200), (MetricKind::Instructions, 80)],
        );
        let views = interval_views(&sample, Some(&previous), start + Duration::from_secs(1));
        assert_eq!(views[&MetricKind::Cycles].per_second, Some(100.0));
        assert_eq!(views[&MetricKind::Instructions].per_second, None);
        assert!(views[&MetricKind::Instructions].baseline);
    }

    #[test]
    fn group_read_matches_kernel_event_ids_in_any_order() {
        let bytes = encoded_read(1_000, 500, &[(12, 300), (11, 100)]);
        let ids = [(MetricKind::Cycles, 11), (MetricKind::Instructions, 12)];
        let parsed = parse_group_read(&bytes, &ids).unwrap();
        assert_eq!(parsed.values[&MetricKind::Cycles], 100);
        assert_eq!(parsed.values[&MetricKind::Instructions], 300);
        assert_eq!(parsed.time_enabled_ns, 1_000);
        assert_eq!(parsed.time_running_ns, 500);
    }

    #[test]
    fn group_read_rejects_duplicate_ids() {
        let bytes = encoded_read(1_000, 500, &[(11, 100), (11, 300)]);
        let ids = [(MetricKind::Cycles, 11), (MetricKind::Instructions, 12)];
        assert!(parse_group_read(&bytes, &ids).is_err());
    }

    #[test]
    fn group_read_rejects_unknown_ids() {
        let bytes = encoded_read(1_000, 500, &[(13, 100)]);
        let ids = [(MetricKind::Cycles, 11)];
        assert!(parse_group_read(&bytes, &ids).is_err());
    }

    #[test]
    fn group_read_rejects_truncated_payload() {
        let mut bytes = encoded_read(1_000, 500, &[(11, 100)]);
        bytes.pop();
        assert!(parse_group_read(&bytes, &[(MetricKind::Cycles, 11)]).is_err());
    }

    #[test]
    fn group_read_rejects_unexpected_member_count() {
        let bytes = encoded_read(1_000, 500, &[(11, 100)]);
        let ids = [(MetricKind::Cycles, 11), (MetricKind::Instructions, 12)];
        assert!(parse_group_read(&bytes, &ids).is_err());
    }

    #[test]
    fn group_read_rejects_impossible_running_time() {
        let bytes = encoded_read(500, 1_000, &[(11, 100)]);
        assert!(parse_group_read(&bytes, &[(MetricKind::Cycles, 11)]).is_err());
    }

    #[test]
    fn counting_attributes_use_stable_kernel_abi_without_sampling() {
        let attr = PerfEventAttr::counting(MetricKind::Instructions);
        assert_eq!(std::mem::size_of::<PerfEventAttr>(), 64);
        assert_eq!(attr.size, 64);
        assert_eq!(attr.event_type, 0);
        assert_eq!(attr.config, 1);
        assert_eq!(attr.sample_period, 0);
        assert_eq!(attr.sample_type, 0);
        assert_eq!(attr.wakeup_events, 0);
        assert_eq!(attr.flags, 1); // Only disabled. No user/kernel/hv/idle exclusions.
        assert_eq!(attr.read_format, 15); // time_enabled, time_running, id and group.
    }

    #[test]
    fn partial_cpu_keeps_supported_counters_and_missing_values() {
        let cpu = CpuReading {
            cpu: 7,
            llc_id: Some(2),
            metrics: [
                (MetricKind::Cycles, measured(100.0, 80.0)),
                (
                    MetricKind::Instructions,
                    MetricReading::unavailable("unsupported".into()),
                ),
            ]
            .into_iter()
            .collect(),
        };
        let row = cpu_row(&cpu);
        assert_eq!(row["available"], true);
        assert_eq!(row["partial"], true);
        assert_eq!(row["cycles_per_second"], 100.0);
        assert!(row["instructions_per_second"].is_null());
        assert!(row["ipc"].is_null());
        assert!(row["cache_misses_per_second"].is_null());
        assert_eq!(row["metrics"]["instructions"]["error"], "unsupported");
    }

    #[test]
    fn paired_ipc_and_cache_ratio_use_valid_denominators() {
        let cpu = CpuReading {
            cpu: 0,
            llc_id: Some(0),
            metrics: [
                (MetricKind::Cycles, measured(50.0, 100.0)),
                (MetricKind::Instructions, measured(100.0, 100.0)),
                (MetricKind::CacheReferences, measured(200.0, 100.0)),
                (MetricKind::CacheMisses, measured(20.0, 100.0)),
            ]
            .into_iter()
            .collect(),
        };
        let row = cpu_row(&cpu);
        assert_eq!(row["ipc"], 2.0);
        assert_eq!(row["cache_miss_pct"], 10.0);
        let zero = CpuReading {
            cpu: 1,
            llc_id: None,
            metrics: [
                (MetricKind::Cycles, measured(0.0, 100.0)),
                (MetricKind::Instructions, measured(0.0, 100.0)),
            ]
            .into_iter()
            .collect(),
        };
        assert!(cpu_row(&zero)["ipc"].is_null());
    }

    #[test]
    fn aggregate_rates_report_partial_coverage_without_counting_missing_cpus_as_zero() {
        let cpu0 = CpuReading {
            cpu: 0,
            llc_id: Some(1),
            metrics: [
                (MetricKind::Cycles, measured(10.0, 100.0)),
                (MetricKind::Instructions, measured(20.0, 100.0)),
            ]
            .into_iter()
            .collect(),
        };
        let cpu1 = CpuReading {
            cpu: 3,
            llc_id: Some(1),
            metrics: [
                (MetricKind::Cycles, measured(100.0, 20.0)),
                (
                    MetricKind::Instructions,
                    MetricReading::unavailable("unsupported".into()),
                ),
            ]
            .into_iter()
            .collect(),
        };
        let value = aggregate_cpu_rows(&[&cpu0, &cpu1]);
        assert_eq!(value["cpu_count"], 2);
        assert_eq!(value["instructions_per_second"], 20.0);
        assert_eq!(value["cycles_per_second"], 110.0);
        assert_eq!(value["ipc"], 2.0); // Only the jointly measured pair contributes.
        assert_eq!(value["ipc_sampled_cpus"], 1);
        assert_eq!(value["metric_cpu_counts"]["instructions"], 1);
        assert_eq!(value["metric_cpu_counts"]["cycles"], 2);
        assert_eq!(value["partial"], true);
        assert!(value["cache_misses_per_second"].is_null());
    }

    #[test]
    fn real_descriptor_read_and_drop_preserve_owned_resource_lifetime() {
        let mut fds = [-1; 2];
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        let read_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let write_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        let bytes = encoded_read(1_000, 500, &[(11, 100)]);
        assert_eq!(
            unsafe { libc::write(write_fd.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) },
            bytes.len() as isize
        );
        drop(write_fd);
        assert_ne!(
            unsafe { libc::fcntl(read_fd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        let event = PerfEvent {
            fd: read_fd,
            kind: MetricKind::Cycles,
            id: 11,
        };
        let sample = read_group(std::slice::from_ref(&event)).unwrap();
        assert_eq!(sample.values[&MetricKind::Cycles], 100);
        drop(event);

        // Verify closure through the owned pipe's EOF, rather than querying a
        // closed descriptor number that another parallel test could reuse.
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        let read_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let write_event = PerfEvent {
            fd: unsafe { OwnedFd::from_raw_fd(fds[1]) },
            kind: MetricKind::Cycles,
            id: 11,
        };
        drop(write_event);
        let mut byte = 0_u8;
        assert_eq!(
            unsafe { libc::read(read_fd.as_raw_fd(), (&mut byte as *mut u8).cast(), 1) },
            0
        );
    }

    #[test]
    fn empty_topology_is_explicitly_unavailable() {
        let mut collector = ExplorePerfCollector::new(Vec::new());
        let group = collector.collect();
        assert!(!group.available);
        assert!(group.error.as_deref().unwrap().contains("No CPUs"));
        assert!(group.rows.is_empty());
    }

    #[test]
    fn sparse_cpu_ids_are_not_used_as_array_lengths() {
        let mut collector = ExplorePerfCollector::new(vec![u32::MAX, u32::MAX]);
        let group = collector.collect();
        assert_eq!(group.rows.len(), 1);
        assert_eq!(group.summary["cpu_count"], 1);
        assert_eq!(group.rows[0]["cpu"], u32::MAX);
        assert_eq!(group.rows[0]["available"], false);
    }
}
