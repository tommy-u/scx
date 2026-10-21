// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

//! Lightweight host metrics collected without attaching BPF programs.
//!
//! Each kernel data source reports its own availability so a missing optional
//! procfs or sysfs file never prevents the inspector from serving a snapshot.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::lifecycle::{ObserverContext, SampleMeta, SharedObserverContext};

use serde::Serialize;

const PROC_STAT: &str = "/proc/stat";
const PROC_MEMINFO: &str = "/proc/meminfo";
const PROC_NET_DEV: &str = "/proc/net/dev";
const PROC_PRESSURE: &str = "/proc/pressure";
const SYS_CPU: &str = "/sys/devices/system/cpu";
const SYS_SCHED_EXT: &str = "/sys/kernel/sched_ext";

#[derive(Clone, Debug, Serialize)]
pub struct MetricSource<T> {
    pub available: bool,
    pub value: Option<T>,
    pub error: Option<String>,
}

impl<T> MetricSource<T> {
    fn from_result(result: Result<T, String>) -> Self {
        match result {
            Ok(value) => Self {
                available: true,
                value: Some(value),
                error: None,
            },
            Err(error) => Self {
                available: false,
                value: None,
                error: Some(error),
            },
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SystemStatsSnapshot {
    pub meta: SampleMeta,
    pub collector: ObserverContext,
    pub captured_at_unix_ms: u64,
    pub interval_ms: Option<u64>,
    pub cpu: MetricSource<CpuStats>,
    pub memory: MetricSource<MemoryStats>,
    pub pressure: PressureStats,
    pub network: MetricSource<NetworkStats>,
    pub frequencies: MetricSource<FrequencyStats>,
    pub sched_ext: MetricSource<SchedExtStats>,
}

/// Discard host reads that straddle an observer epoch transition.
pub fn publish_sample(
    state: &Arc<RwLock<SystemStatsSnapshot>>,
    observer: &SharedObserverContext,
    expected: &ObserverContext,
    mut sample: SystemStatsSnapshot,
) -> bool {
    let mut previous = state.write().expect("system snapshot lock poisoned");
    let current = observer.read().expect("observer context lock poisoned");
    if *current != *expected {
        return false;
    }
    sample.meta.sample_seq = if previous.meta.epoch == expected.epoch {
        previous.meta.sample_seq + 1
    } else {
        1
    };
    sample.meta.epoch = expected.epoch;
    sample.collector = expected.clone();
    *previous = sample;
    true
}

#[derive(Clone, Debug, Serialize)]
pub struct CpuStats {
    pub busy_pct: Option<f64>,
    pub user_pct: Option<f64>,
    pub system_pct: Option<f64>,
    pub iowait_pct: Option<f64>,
    pub steal_pct: Option<f64>,
    pub context_switches_total: u64,
    pub context_switches_per_second: Option<f64>,
    pub processes_created_total: u64,
    pub processes_created_per_second: Option<f64>,
    pub procs_running: u64,
    pub procs_blocked: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct MemoryStats {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
    pub buffers_bytes: u64,
    pub cached_bytes: u64,
    pub dirty_bytes: u64,
    pub swap_total_bytes: u64,
    pub swap_free_bytes: u64,
    pub swap_used_bytes: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct PressureStats {
    pub cpu: MetricSource<PsiStats>,
    pub memory: MetricSource<PsiStats>,
    pub io: MetricSource<PsiStats>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PsiStats {
    pub some: Option<PsiLine>,
    pub full: Option<PsiLine>,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct PsiLine {
    pub avg10: f64,
    pub avg60: f64,
    pub avg300: f64,
    pub total_us: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct NetworkStats {
    pub interfaces: Vec<NetworkInterfaceStats>,
}

#[derive(Clone, Debug, Serialize)]
pub struct NetworkInterfaceStats {
    pub interface: String,
    pub rx_bytes_total: u64,
    pub rx_bytes_per_second: Option<f64>,
    pub rx_packets_total: u64,
    pub rx_errors_total: u64,
    pub rx_dropped_total: u64,
    pub tx_bytes_total: u64,
    pub tx_bytes_per_second: Option<f64>,
    pub tx_packets_total: u64,
    pub tx_errors_total: u64,
    pub tx_dropped_total: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct FrequencyStats {
    pub average_khz: Option<u64>,
    pub minimum_khz: Option<u64>,
    pub maximum_khz: Option<u64>,
    pub available_cpus: usize,
    pub unavailable_cpus: usize,
    pub cpus: Vec<CpuFrequency>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CpuFrequency {
    pub cpu: u32,
    pub current_khz: Option<u64>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SchedExtStats {
    pub state: String,
    pub enable_seq: u64,
    pub hotplug_seq: u64,
    pub nr_rejected: u64,
    pub switch_all: bool,
}

#[derive(Debug, Default)]
pub struct SystemStatsCollector {
    sample_seq: u64,
    previous_collection: Option<Instant>,
    previous_cpu: Option<(Instant, RawProcStat)>,
    previous_network: Option<(Instant, BTreeMap<String, RawNetworkInterface>)>,
}

impl SystemStatsCollector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn collect(&mut self) -> SystemStatsSnapshot {
        let now = Instant::now();
        let interval_ms = self
            .previous_collection
            .replace(now)
            .map(|previous| duration_ms(now.duration_since(previous)));

        let cpu = self.collect_cpu(now);
        let network = self.collect_network(now);

        self.sample_seq += 1;
        let at_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(duration_ms)
            .unwrap_or(0);
        SystemStatsSnapshot {
            meta: SampleMeta {
                sample_seq: self.sample_seq,
                captured_at_unix_ms: Some(at_ms),
                last_success_at_unix_ms: Some(at_ms),
                ..Default::default()
            },
            collector: ObserverContext::default(),
            captured_at_unix_ms: at_ms,
            interval_ms,
            cpu,
            memory: MetricSource::from_result(read_and_parse(PROC_MEMINFO, parse_meminfo)),
            pressure: PressureStats {
                cpu: collect_psi("cpu"),
                memory: collect_psi("memory"),
                io: collect_psi("io"),
            },
            network,
            frequencies: MetricSource::from_result(collect_frequencies(Path::new(SYS_CPU))),
            sched_ext: MetricSource::from_result(collect_sched_ext(Path::new(SYS_SCHED_EXT))),
        }
    }

    fn collect_cpu(&mut self, now: Instant) -> MetricSource<CpuStats> {
        let current = match read_and_parse(PROC_STAT, parse_proc_stat) {
            Ok(current) => current,
            Err(error) => return MetricSource::from_result(Err(error)),
        };
        let (previous, elapsed) = self
            .previous_cpu
            .as_ref()
            .map(|(at, sample)| (Some(sample), Some(now.duration_since(*at).as_secs_f64())))
            .unwrap_or((None, None));
        let value = cpu_view(&current, previous, elapsed);
        self.previous_cpu = Some((now, current));
        MetricSource::from_result(Ok(value))
    }

    fn collect_network(&mut self, now: Instant) -> MetricSource<NetworkStats> {
        let current = match read_and_parse(PROC_NET_DEV, parse_net_dev) {
            Ok(current) => current,
            Err(error) => return MetricSource::from_result(Err(error)),
        };
        let (previous, elapsed) = self
            .previous_network
            .as_ref()
            .map(|(at, sample)| (Some(sample), Some(now.duration_since(*at).as_secs_f64())))
            .unwrap_or((None, None));
        let value = network_view(&current, previous, elapsed);
        self.previous_network = Some((now, current));
        MetricSource::from_result(Ok(value))
    }
}

#[derive(Clone, Debug)]
struct RawProcStat {
    user: u64,
    nice: u64,
    system: u64,
    idle: u64,
    iowait: u64,
    irq: u64,
    softirq: u64,
    steal: u64,
    context_switches: u64,
    processes_created: u64,
    procs_running: u64,
    procs_blocked: u64,
}

impl RawProcStat {
    fn total(&self) -> u64 {
        self.user
            .saturating_add(self.nice)
            .saturating_add(self.system)
            .saturating_add(self.idle)
            .saturating_add(self.iowait)
            .saturating_add(self.irq)
            .saturating_add(self.softirq)
            .saturating_add(self.steal)
    }

    fn busy(&self) -> u64 {
        self.total()
            .saturating_sub(self.idle)
            .saturating_sub(self.iowait)
    }
}

#[derive(Clone, Debug)]
struct RawNetworkInterface {
    rx_bytes: u64,
    rx_packets: u64,
    rx_errors: u64,
    rx_dropped: u64,
    tx_bytes: u64,
    tx_packets: u64,
    tx_errors: u64,
    tx_dropped: u64,
}

fn read_and_parse<T>(
    path: &str,
    parser: impl FnOnce(&str) -> Result<T, String>,
) -> Result<T, String> {
    let contents = fs::read_to_string(path).map_err(|error| format!("reading {path}: {error}"))?;
    parser(&contents).map_err(|error| format!("parsing {path}: {error}"))
}

fn parse_proc_stat(contents: &str) -> Result<RawProcStat, String> {
    let cpu_line = contents
        .lines()
        .find(|line| line.starts_with("cpu "))
        .ok_or_else(|| "aggregate cpu line is missing".to_owned())?;
    let fields = cpu_line
        .split_whitespace()
        .skip(1)
        .map(|value| {
            value
                .parse::<u64>()
                .map_err(|error| format!("invalid cpu counter `{value}`: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if fields.len() < 4 {
        return Err("aggregate cpu line has fewer than four counters".to_owned());
    }
    let field = |index: usize| fields.get(index).copied().unwrap_or(0);
    let named = |name: &str| -> Result<u64, String> {
        let value = contents
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name} ")))
            .ok_or_else(|| format!("{name} line is missing"))?;
        value
            .trim()
            .parse::<u64>()
            .map_err(|error| format!("invalid {name} counter `{value}`: {error}"))
    };

    Ok(RawProcStat {
        user: field(0),
        nice: field(1),
        system: field(2),
        idle: field(3),
        iowait: field(4),
        irq: field(5),
        softirq: field(6),
        steal: field(7),
        context_switches: named("ctxt")?,
        processes_created: named("processes")?,
        procs_running: named("procs_running")?,
        procs_blocked: named("procs_blocked")?,
    })
}

fn cpu_view(
    current: &RawProcStat,
    previous: Option<&RawProcStat>,
    elapsed_seconds: Option<f64>,
) -> CpuStats {
    // Every CPU component shares the denominator. A decrease in any component
    // (including the kernel's non-monotonic iowait counter) invalidates it.
    let total_delta = previous.and_then(|previous| {
        [
            (current.user, previous.user),
            (current.nice, previous.nice),
            (current.system, previous.system),
            (current.idle, previous.idle),
            (current.iowait, previous.iowait),
            (current.irq, previous.irq),
            (current.softirq, previous.softirq),
            (current.steal, previous.steal),
        ]
        .into_iter()
        .try_fold(0_u64, |total, (current, previous)| {
            total.checked_add(counter_delta(current, previous)?)
        })
    });
    let percentage = |current_value: u64, previous_value: u64| {
        total_delta
            .filter(|total| *total > 0)
            .zip(counter_delta(current_value, previous_value))
            .filter(|(total, delta)| delta <= total)
            .map(|(total, delta)| 100.0 * delta as f64 / total as f64)
    };
    let rate = |current_value: u64, previous_value: u64| {
        elapsed_seconds
            .filter(|seconds| seconds.is_finite() && *seconds > 0.0)
            .zip(counter_delta(current_value, previous_value))
            .map(|(seconds, delta)| delta as f64 / seconds)
    };

    CpuStats {
        busy_pct: previous.and_then(|previous| percentage(current.busy(), previous.busy())),
        user_pct: previous.and_then(|previous| {
            percentage(
                current.user.saturating_add(current.nice),
                previous.user.saturating_add(previous.nice),
            )
        }),
        system_pct: previous.and_then(|previous| {
            percentage(
                current
                    .system
                    .saturating_add(current.irq)
                    .saturating_add(current.softirq),
                previous
                    .system
                    .saturating_add(previous.irq)
                    .saturating_add(previous.softirq),
            )
        }),
        iowait_pct: previous.and_then(|previous| percentage(current.iowait, previous.iowait)),
        steal_pct: previous.and_then(|previous| percentage(current.steal, previous.steal)),
        context_switches_total: current.context_switches,
        context_switches_per_second: previous
            .and_then(|previous| rate(current.context_switches, previous.context_switches)),
        processes_created_total: current.processes_created,
        processes_created_per_second: previous
            .and_then(|previous| rate(current.processes_created, previous.processes_created)),
        procs_running: current.procs_running,
        procs_blocked: current.procs_blocked,
    }
}

fn parse_meminfo(contents: &str) -> Result<MemoryStats, String> {
    let values = contents
        .lines()
        .filter_map(|line| {
            let (name, rest) = line.split_once(':')?;
            let value = rest.split_whitespace().next()?.parse::<u64>().ok()?;
            Some((name, value.saturating_mul(1024)))
        })
        .collect::<BTreeMap<_, _>>();
    let get = |name: &str| {
        values
            .get(name)
            .copied()
            .ok_or_else(|| format!("{name} is missing"))
    };
    let total = get("MemTotal")?;
    let available = get("MemAvailable")?;
    let swap_total = get("SwapTotal")?;
    let swap_free = get("SwapFree")?;

    Ok(MemoryStats {
        total_bytes: total,
        available_bytes: available,
        used_bytes: total.saturating_sub(available),
        free_bytes: get("MemFree")?,
        buffers_bytes: get("Buffers")?,
        cached_bytes: get("Cached")?,
        dirty_bytes: get("Dirty")?,
        swap_total_bytes: swap_total,
        swap_free_bytes: swap_free,
        swap_used_bytes: swap_total.saturating_sub(swap_free),
    })
}

fn collect_psi(resource: &str) -> MetricSource<PsiStats> {
    let path = format!("{PROC_PRESSURE}/{resource}");
    MetricSource::from_result(read_and_parse(&path, parse_psi))
}

fn parse_psi(contents: &str) -> Result<PsiStats, String> {
    let mut some = None;
    let mut full = None;
    for line in contents.lines().filter(|line| !line.trim().is_empty()) {
        let mut fields = line.split_whitespace();
        let kind = fields
            .next()
            .ok_or_else(|| "empty pressure line".to_owned())?;
        let values = fields
            .filter_map(|field| field.split_once('='))
            .collect::<BTreeMap<_, _>>();
        let float = |name: &str| -> Result<f64, String> {
            values
                .get(name)
                .ok_or_else(|| format!("{kind} pressure {name} is missing"))?
                .parse::<f64>()
                .map_err(|error| format!("invalid {kind} pressure {name}: {error}"))
        };
        let integer = |name: &str| -> Result<u64, String> {
            values
                .get(name)
                .ok_or_else(|| format!("{kind} pressure {name} is missing"))?
                .parse::<u64>()
                .map_err(|error| format!("invalid {kind} pressure {name}: {error}"))
        };
        let parsed = PsiLine {
            avg10: float("avg10")?,
            avg60: float("avg60")?,
            avg300: float("avg300")?,
            total_us: integer("total")?,
        };
        match kind {
            "some" => some = Some(parsed),
            "full" => full = Some(parsed),
            _ => {}
        }
    }
    if some.is_none() && full.is_none() {
        return Err("no some or full pressure records found".to_owned());
    }
    Ok(PsiStats { some, full })
}

fn parse_net_dev(contents: &str) -> Result<BTreeMap<String, RawNetworkInterface>, String> {
    let mut interfaces = BTreeMap::new();
    for line in contents.lines().filter(|line| line.contains(':')) {
        let (name, counters) = line
            .split_once(':')
            .ok_or_else(|| "invalid network interface line".to_owned())?;
        let fields = counters
            .split_whitespace()
            .map(|value| {
                value
                    .parse::<u64>()
                    .map_err(|error| format!("invalid network counter `{value}`: {error}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if fields.len() < 16 {
            return Err(format!(
                "interface {} has fewer than 16 counters",
                name.trim()
            ));
        }
        interfaces.insert(
            name.trim().to_owned(),
            RawNetworkInterface {
                rx_bytes: fields[0],
                rx_packets: fields[1],
                rx_errors: fields[2],
                rx_dropped: fields[3],
                tx_bytes: fields[8],
                tx_packets: fields[9],
                tx_errors: fields[10],
                tx_dropped: fields[11],
            },
        );
    }
    if interfaces.is_empty() {
        return Err("no network interfaces found".to_owned());
    }
    Ok(interfaces)
}

fn network_view(
    current: &BTreeMap<String, RawNetworkInterface>,
    previous: Option<&BTreeMap<String, RawNetworkInterface>>,
    elapsed_seconds: Option<f64>,
) -> NetworkStats {
    let rate = |current: u64, previous: Option<u64>| {
        previous
            .zip(elapsed_seconds)
            .and_then(|(previous, seconds)| {
                counter_delta(current, previous)
                    .filter(|_| seconds.is_finite() && seconds > 0.0)
                    .map(|delta| delta as f64 / seconds)
            })
    };
    NetworkStats {
        interfaces: current
            .iter()
            .map(|(interface, stats)| {
                let previous = previous.and_then(|all| all.get(interface));
                NetworkInterfaceStats {
                    interface: interface.clone(),
                    rx_bytes_total: stats.rx_bytes,
                    rx_bytes_per_second: rate(stats.rx_bytes, previous.map(|stats| stats.rx_bytes)),
                    rx_packets_total: stats.rx_packets,
                    rx_errors_total: stats.rx_errors,
                    rx_dropped_total: stats.rx_dropped,
                    tx_bytes_total: stats.tx_bytes,
                    tx_bytes_per_second: rate(stats.tx_bytes, previous.map(|stats| stats.tx_bytes)),
                    tx_packets_total: stats.tx_packets,
                    tx_errors_total: stats.tx_errors,
                    tx_dropped_total: stats.tx_dropped,
                }
            })
            .collect(),
    }
}

fn collect_frequencies(cpu_root: &Path) -> Result<FrequencyStats, String> {
    let entries = fs::read_dir(cpu_root)
        .map_err(|error| format!("reading {}: {error}", cpu_root.display()))?;
    let mut cpu_paths = Vec::new();
    for entry in entries {
        let entry =
            entry.map_err(|error| format!("reading {} entry: {error}", cpu_root.display()))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(cpu) = name
            .strip_prefix("cpu")
            .and_then(|value| value.parse::<u32>().ok())
        {
            cpu_paths.push((cpu, entry.path()));
        }
    }
    cpu_paths.sort_unstable_by_key(|(cpu, _)| *cpu);
    if cpu_paths.is_empty() {
        return Err(format!(
            "no CPU directories found under {}",
            cpu_root.display()
        ));
    }

    let cpus = cpu_paths
        .into_iter()
        .map(|(cpu, path)| read_cpu_frequency(cpu, &path))
        .collect::<Vec<_>>();
    let frequencies = cpus
        .iter()
        .filter_map(|cpu| cpu.current_khz)
        .collect::<Vec<_>>();
    let sum = frequencies
        .iter()
        .fold(0_u128, |sum, frequency| sum + u128::from(*frequency));

    Ok(FrequencyStats {
        average_khz: (!frequencies.is_empty()).then(|| (sum / frequencies.len() as u128) as u64),
        minimum_khz: frequencies.iter().copied().min(),
        maximum_khz: frequencies.iter().copied().max(),
        available_cpus: frequencies.len(),
        unavailable_cpus: cpus.len().saturating_sub(frequencies.len()),
        cpus,
    })
}

fn read_cpu_frequency(cpu: u32, cpu_path: &Path) -> CpuFrequency {
    let candidates = ["scaling_cur_freq", "cpuinfo_cur_freq"];
    let mut errors = Vec::new();
    for file in candidates {
        let path = cpu_path.join("cpufreq").join(file);
        match read_frequency_file(&path) {
            Ok(current_khz) => {
                return CpuFrequency {
                    cpu,
                    current_khz: Some(current_khz),
                    error: None,
                };
            }
            Err(error) => errors.push(error),
        }
    }
    CpuFrequency {
        cpu,
        current_khz: None,
        error: Some(errors.join("; ")),
    }
}

fn read_frequency_file(path: &PathBuf) -> Result<u64, String> {
    let value = fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?;
    value
        .trim()
        .parse::<u64>()
        .map_err(|error| format!("{}: invalid frequency: {error}", path.display()))
}

fn collect_sched_ext(root: &Path) -> Result<SchedExtStats, String> {
    let read = |name: &str| -> Result<String, String> {
        let path = root.join(name);
        let value = fs::read_to_string(&path)
            .map_err(|error| format!("reading {}: {error}", path.display()))?;
        let value = value.trim();
        if value.is_empty() {
            return Err(format!("reading {}: value is empty", path.display()));
        }
        Ok(value.to_owned())
    };
    let integer = |name: &str| -> Result<u64, String> {
        let value = read(name)?;
        value
            .parse::<u64>()
            .map_err(|error| format!("parsing {}: {error}", root.join(name).display()))
    };
    let state = read("state")?;
    let enable_seq = integer("enable_seq")?;
    let hotplug_seq = integer("hotplug_seq")?;
    let nr_rejected = integer("nr_rejected")?;
    let switch_all = match integer("switch_all")? {
        0 => false,
        1 => true,
        value => {
            return Err(format!(
                "parsing {}: expected 0 or 1, got {value}",
                root.join("switch_all").display()
            ));
        }
    };

    Ok(SchedExtStats {
        state,
        enable_seq,
        hotplug_seq,
        nr_rejected,
        switch_all,
    })
}

fn counter_delta(current: u64, previous: u64) -> Option<u64> {
    current.checked_sub(previous)
}

fn duration_ms(duration: std::time::Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cpu_counters_and_calculates_a_delta() {
        let previous = parse_proc_stat(
            "cpu  100 0 20 80 0 2 3 1 0 0\nctxt 1000\nprocesses 50\nprocs_running 2\nprocs_blocked 1\n",
        )
        .unwrap();
        let current = parse_proc_stat(
            "cpu  130 0 30 130 0 4 5 1 0 0\nctxt 1120\nprocesses 56\nprocs_running 3\nprocs_blocked 0\n",
        )
        .unwrap();
        let view = cpu_view(&current, Some(&previous), Some(2.0));

        assert!((view.busy_pct.unwrap() - 46.808).abs() < 0.01);
        assert_eq!(view.context_switches_per_second, Some(60.0));
        assert_eq!(view.processes_created_per_second, Some(3.0));
        assert_eq!(view.procs_running, 3);
    }

    #[test]
    fn decreasing_iowait_invalidates_cpu_percentages_without_hiding_totals() {
        let previous = parse_proc_stat(
            "cpu 100 0 20 80 1000 0 0 0\nctxt 1000\nprocesses 50\nprocs_running 2\nprocs_blocked 1\n",
        )
        .unwrap();
        let current = parse_proc_stat(
            "cpu 101 0 20 82 999 0 0 0\nctxt 1010\nprocesses 51\nprocs_running 3\nprocs_blocked 0\n",
        )
        .unwrap();
        let view = cpu_view(&current, Some(&previous), Some(2.0));

        // A one-tick iowait decrease makes the old ratio 999 / 2 = 49,950%.
        assert_eq!(view.iowait_pct, None);
        assert_eq!(view.busy_pct, None);
        assert_eq!(view.user_pct, None);
        assert_eq!(view.system_pct, None);
        assert_eq!(view.steal_pct, None);
        assert_eq!(view.context_switches_total, 1010);
        assert_eq!(view.context_switches_per_second, Some(5.0));
        assert_eq!(view.processes_created_per_second, Some(0.5));
    }

    #[test]
    fn reset_cpu_counters_start_an_unknown_interval_and_recover_next_sample() {
        let previous = parse_proc_stat(
            "cpu 100 10 20 80 30 2 3 1\nctxt 1000\nprocesses 50\nprocs_running 2\nprocs_blocked 1\n",
        )
        .unwrap();
        let reset = parse_proc_stat(
            "cpu 10 0 2 8 0 0 0 0\nctxt 10\nprocesses 2\nprocs_running 1\nprocs_blocked 0\n",
        )
        .unwrap();
        let reset_view = cpu_view(&reset, Some(&previous), Some(2.0));
        assert_eq!(reset_view.busy_pct, None);
        assert_eq!(reset_view.context_switches_per_second, None);
        assert_eq!(reset_view.processes_created_per_second, None);
        assert_eq!(reset_view.context_switches_total, 10);
        assert_eq!(reset_view.processes_created_total, 2);

        let next = parse_proc_stat(
            "cpu 14 0 3 13 0 0 0 0\nctxt 20\nprocesses 3\nprocs_running 1\nprocs_blocked 0\n",
        )
        .unwrap();
        let recovered = cpu_view(&next, Some(&reset), Some(2.0));
        assert_eq!(recovered.busy_pct, Some(50.0));
        assert_eq!(recovered.user_pct, Some(40.0));
        assert_eq!(recovered.system_pct, Some(10.0));
        assert_eq!(recovered.context_switches_per_second, Some(5.0));
        assert_eq!(recovered.processes_created_per_second, Some(0.5));
    }

    #[test]
    fn reset_network_counter_has_unknown_rate_and_keeps_other_direction_valid() {
        let previous =
            parse_net_dev("eth0: 10000 100 0 0 0 0 0 0 20000 200 0 0 0 0 0 0\n").unwrap();
        let reset = parse_net_dev("eth0: 500 5 0 0 0 0 0 0 22000 220 0 0 0 0 0 0\n").unwrap();
        let view = network_view(&reset, Some(&previous), Some(2.0));
        let row = &view.interfaces[0];
        assert_eq!(row.rx_bytes_total, 500);
        assert_eq!(row.rx_bytes_per_second, None);
        assert_eq!(row.tx_bytes_per_second, Some(1000.0));

        let next = parse_net_dev("eth0: 1500 15 0 0 0 0 0 0 24000 240 0 0 0 0 0 0\n").unwrap();
        let next_view = network_view(&next, Some(&reset), Some(2.0));
        assert_eq!(next_view.interfaces[0].rx_bytes_per_second, Some(500.0));
        assert_eq!(next_view.interfaces[0].tx_bytes_per_second, Some(1000.0));
    }

    #[test]
    fn first_host_sample_establishes_baselines_and_keeps_cumulative_totals() {
        let cpu = parse_proc_stat(
            "cpu 100 0 20 80 1000 0 0 0\nctxt 1000\nprocesses 50\nprocs_running 2\nprocs_blocked 1\n",
        )
        .unwrap();
        let cpu = cpu_view(&cpu, None, None);
        assert_eq!(cpu.busy_pct, None);
        assert_eq!(cpu.iowait_pct, None);
        assert_eq!(cpu.context_switches_per_second, None);
        assert_eq!(cpu.processes_created_per_second, None);
        assert_eq!(cpu.context_switches_total, 1000);
        assert_eq!(cpu.processes_created_total, 50);

        let network = parse_net_dev("eth0: 10000 100 0 0 0 0 0 0 20000 200 0 0 0 0 0 0\n").unwrap();
        let network = network_view(&network, None, None);
        assert_eq!(network.interfaces[0].rx_bytes_per_second, None);
        assert_eq!(network.interfaces[0].tx_bytes_per_second, None);
        assert_eq!(network.interfaces[0].rx_bytes_total, 10000);
        assert_eq!(network.interfaces[0].tx_bytes_total, 20000);
    }

    #[test]
    fn parses_memory_pressure_and_network_rows() {
        let memory = parse_meminfo(
            "MemTotal: 1000 kB\nMemFree: 100 kB\nMemAvailable: 600 kB\nBuffers: 10 kB\nCached: 200 kB\nSwapTotal: 50 kB\nSwapFree: 20 kB\nDirty: 3 kB\n",
        )
        .unwrap();
        assert_eq!(memory.used_bytes, 400 * 1024);
        assert_eq!(memory.swap_used_bytes, 30 * 1024);

        let pressure = parse_psi(
            "some avg10=1.00 avg60=2.00 avg300=3.00 total=400\nfull avg10=0.10 avg60=0.20 avg300=0.30 total=40\n",
        )
        .unwrap();
        assert_eq!(pressure.some.unwrap().total_us, 400);
        assert_eq!(pressure.full.unwrap().avg60, 0.2);

        let network = parse_net_dev(
            "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n  eth0: 1000 10 1 2 0 0 0 0 2000 20 3 4 0 0 0 0\n",
        )
        .unwrap();
        assert_eq!(network["eth0"].rx_bytes, 1000);
        assert_eq!(network["eth0"].tx_dropped, 4);
    }

    #[test]
    fn every_source_reports_availability_without_failing_the_snapshot() {
        let snapshot = SystemStatsCollector::default().collect();
        assert!(snapshot.cpu.available || snapshot.cpu.error.is_some());
        assert!(snapshot.memory.available || snapshot.memory.error.is_some());
        assert!(snapshot.network.available || snapshot.network.error.is_some());
        assert!(snapshot.frequencies.available || snapshot.frequencies.error.is_some());
        assert!(snapshot.sched_ext.available || snapshot.sched_ext.error.is_some());
    }

    #[test]
    fn reads_sched_ext_lifecycle_health() {
        let root = std::env::temp_dir().join(format!(
            "scx-mitosis-inspector-sched-ext-{}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        for (name, value) in [
            ("state", "enabled\n"),
            ("enable_seq", "72\n"),
            ("hotplug_seq", "315\n"),
            ("nr_rejected", "2\n"),
            ("switch_all", "1\n"),
        ] {
            fs::write(root.join(name), value).unwrap();
        }

        let stats = collect_sched_ext(&root).unwrap();
        assert_eq!(stats.state, "enabled");
        assert_eq!(stats.enable_seq, 72);
        assert_eq!(stats.hotplug_seq, 315);
        assert_eq!(stats.nr_rejected, 2);
        assert!(stats.switch_all);

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn sched_ext_reports_missing_and_invalid_fields() {
        let root = std::env::temp_dir().join(format!(
            "scx-mitosis-inspector-sched-ext-errors-{}",
            std::process::id()
        ));
        fs::create_dir_all(&root).unwrap();
        assert!(collect_sched_ext(&root).unwrap_err().contains("state"));

        for (name, value) in [
            ("state", "disabled\n"),
            ("enable_seq", "1\n"),
            ("hotplug_seq", "2\n"),
            ("nr_rejected", "0\n"),
            ("switch_all", "sometimes\n"),
        ] {
            fs::write(root.join(name), value).unwrap();
        }
        assert!(collect_sched_ext(&root).unwrap_err().contains("switch_all"));

        fs::remove_dir_all(root).unwrap();
    }
}
