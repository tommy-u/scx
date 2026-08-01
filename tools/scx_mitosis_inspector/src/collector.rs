// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc::Sender, Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use libbpf_rs::query::ProgInfoIter;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{Link, MapCore, MapFlags, OpenObject, Program, ProgramType};
use serde::Serialize;

use crate::bpf_program_stats::{query_bpf_program_stats, BpfProgramStatsRow};
use crate::bpf_skel::{BpfSkel, BpfSkelBuilder};
use crate::probe_manifest::{build_probe_manifest, ProbeManifestInputs};
use crate::{
    build_callback_timing_rows, build_counters, build_cpu_runtime_rows, build_scheduler_event_rows,
    build_timing_metric_row, program_name_matches, project_cpu_runtime, summarize_callback_timing,
    BlockIoMetricsView, CallbackCounter, CallbackTimingCounters, CallbackTimingRow, CpuRuntimeRow,
    DsqMetricsView, HardirqMetricsView, HardirqRow, InterruptCpuRow, MigrationRow,
    ProbeManifestRow, SchedulerEventRow, SoftirqRow, TimingMetricRow, CALLBACK_NAMES,
    CALLBACK_TIMING_BUCKETS, SCHEDULER_EVENT_NAMES, SOFTIRQ_NAMES,
};

const TARGET_NAMES: [&str; 5] = [
    "mitosis_select_cpu",
    "mitosis_enqueue",
    "mitosis_dispatch",
    "mitosis_running",
    "mitosis_stopping",
];

#[derive(Clone, Copy, Debug)]
pub struct CollectorConfig {
    pub callback_timing_sample_rate: u32,
    pub event_timing_sample_rate: u32,
    pub enable_dsq: bool,
    pub enable_scheduler_events: bool,
    pub enable_irqs: bool,
    pub enable_block_io: bool,
}

struct TargetProgram {
    id: u32,
    fd: OwnedFd,
}

#[derive(Clone)]
struct SoftirqMetrics {
    count: u64,
    timing: CallbackTimingCounters,
}

#[derive(Clone)]
struct SoftirqMetricsSnapshot {
    rows: Vec<SoftirqMetrics>,
    cpu_elapsed_ns: Vec<u64>,
}

#[derive(Clone, Default)]
struct BlockIoMetrics {
    issue_events: u64,
    completion_events: u64,
    completed_requests: u64,
    error_events: u64,
    issued_bytes: u64,
    completed_bytes: u64,
    unmatched_completions: u64,
    tracking_failures: u64,
    latency: CallbackTimingCounters,
}

#[derive(Clone, Default)]
struct HardirqMetrics {
    rows: BTreeMap<u32, SoftirqMetrics>,
    cpu_elapsed_ns: Vec<u64>,
    metrics_map_full: u64,
    starts_map_full: u64,
    unmatched_exits: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Snapshot {
    pub scheduler: &'static str,
    pub target_program_ids: [u32; 5],
    pub uptime_seconds: u64,
    pub counters: Vec<CallbackCounter>,
    pub callback_timing_sample_rate: u32,
    pub event_timing_sample_rate: u32,
    pub callback_timings: Vec<CallbackTimingRow>,
    pub scheduler_timings: Vec<TimingMetricRow>,
    pub migrations: Vec<MigrationRow>,
    pub cpu_runtime: Vec<CpuRuntimeRow>,
    pub bpf_program_stats: Vec<BpfProgramStatsRow>,
    pub inspector_bpf_program_stats: Vec<BpfProgramStatsRow>,
    pub inspector_bpf_cpu_equivalent_pct: Option<f64>,
    pub inspector_bpf_host_capacity_pct: Option<f64>,
    pub dsq_metrics: DsqMetricsView,
    pub scheduler_events: Vec<SchedulerEventRow>,
    pub softirqs: Vec<SoftirqRow>,
    pub block_io: BlockIoMetricsView,
    pub interrupt_cpu: Vec<InterruptCpuRow>,
    pub hardirqs: HardirqMetricsView,
    pub probe_manifest: Vec<ProbeManifestRow>,
}

fn probe_manifest(
    config: CollectorConfig,
    dsq_available: bool,
    block_io_available: bool,
    hardirq_available: bool,
    runtime_accounting_enabled: bool,
) -> Vec<ProbeManifestRow> {
    build_probe_manifest(ProbeManifestInputs {
        callback_timing_sample_rate: config.callback_timing_sample_rate,
        event_timing_sample_rate: config.event_timing_sample_rate,
        dsq_enabled: config.enable_dsq,
        dsq_available,
        scheduler_events_enabled: config.enable_scheduler_events,
        irqs_enabled: config.enable_irqs,
        hardirq_available,
        block_io_enabled: config.enable_block_io,
        block_io_available,
        runtime_accounting_enabled,
    })
}

fn find_targets() -> Result<[TargetProgram; 5]> {
    let programs: Vec<_> = ProgInfoIter::default()
        .filter(|program| program.ty == ProgramType::StructOps)
        .collect();

    TARGET_NAMES
        .into_iter()
        .map(|expected| {
            let program = programs
                .iter()
                .filter(|program| {
                    program_name_matches(program.name.to_string_lossy().as_ref(), expected)
                })
                .max_by_key(|program| program.load_time)
                .with_context(|| format!("active callback program {expected} not found"))?;
            Ok(TargetProgram {
                id: program.id,
                fd: Program::fd_from_id(program.id)
                    .with_context(|| format!("opening BPF program {expected} ({})", program.id))?,
            })
        })
        .collect::<Result<Vec<_>>>()?
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected five callback targets"))
}

fn set_targets(
    open_skel: &mut crate::bpf_skel::OpenBpfSkel<'_>,
    targets: &[TargetProgram; 5],
) -> Result<()> {
    open_skel
        .progs
        .observe_select_cpu
        .set_attach_target(targets[0].fd.as_raw_fd(), Some(TARGET_NAMES[0].into()))?;
    open_skel
        .progs
        .observe_enqueue
        .set_attach_target(targets[1].fd.as_raw_fd(), Some(TARGET_NAMES[1].into()))?;
    open_skel
        .progs
        .observe_dispatch
        .set_attach_target(targets[2].fd.as_raw_fd(), Some(TARGET_NAMES[2].into()))?;
    open_skel
        .progs
        .observe_running
        .set_attach_target(targets[3].fd.as_raw_fd(), Some(TARGET_NAMES[3].into()))?;
    open_skel
        .progs
        .observe_stopping
        .set_attach_target(targets[4].fd.as_raw_fd(), Some(TARGET_NAMES[4].into()))?;
    open_skel
        .progs
        .observe_select_cpu_exit
        .set_attach_target(targets[0].fd.as_raw_fd(), Some(TARGET_NAMES[0].into()))?;
    open_skel
        .progs
        .observe_enqueue_exit
        .set_attach_target(targets[1].fd.as_raw_fd(), Some(TARGET_NAMES[1].into()))?;
    open_skel
        .progs
        .observe_dispatch_exit
        .set_attach_target(targets[2].fd.as_raw_fd(), Some(TARGET_NAMES[2].into()))?;
    open_skel
        .progs
        .observe_running_exit
        .set_attach_target(targets[3].fd.as_raw_fd(), Some(TARGET_NAMES[3].into()))?;
    open_skel
        .progs
        .observe_stopping_exit
        .set_attach_target(targets[4].fd.as_raw_fd(), Some(TARGET_NAMES[4].into()))?;
    Ok(())
}

fn attach_programs(
    skel: &BpfSkel<'_>,
    config: CollectorConfig,
    block_io_supported: bool,
    hardirq_supported: bool,
) -> Result<(Vec<Link>, bool, bool, bool)> {
    let mut links = vec![
        skel.progs.observe_select_cpu.attach_trace()?,
        skel.progs.observe_enqueue.attach_trace()?,
        skel.progs.observe_dispatch.attach_trace()?,
        skel.progs.observe_running.attach_trace()?,
        skel.progs.observe_stopping.attach_trace()?,
        skel.progs.on_sched_migrate_task.attach()?,
    ];
    if config.enable_scheduler_events {
        links.extend([
            skel.progs.scheduler_event_switch.attach()?,
            skel.progs.scheduler_event_wakeup.attach()?,
            skel.progs.scheduler_event_wakeup_new.attach()?,
            skel.progs.scheduler_event_fork.attach()?,
            skel.progs.scheduler_event_exec.attach()?,
            skel.progs.scheduler_event_exit.attach()?,
        ]);
    }
    if config.enable_irqs {
        links.extend([
            skel.progs.sirqo_entry.attach()?,
            skel.progs.sirqo_exit.attach()?,
        ]);
    }
    if config.callback_timing_sample_rate > 0 {
        links.extend([
            skel.progs.observe_select_cpu_exit.attach_trace()?,
            skel.progs.observe_enqueue_exit.attach_trace()?,
            skel.progs.observe_dispatch_exit.attach_trace()?,
            skel.progs.observe_running_exit.attach_trace()?,
            skel.progs.observe_stopping_exit.attach_trace()?,
        ]);
    }
    if config.event_timing_sample_rate > 0 {
        links.extend([
            skel.progs.on_sched_wakeup.attach()?,
            skel.progs.on_sched_wakeup_new.attach()?,
            skel.progs.on_sched_switch.attach()?,
        ]);
    }
    let dsq_available = config.enable_dsq && attach_dsq_programs(skel, &mut links);
    let block_io_available = block_io_supported && attach_block_io_programs(skel, &mut links);
    let hardirq_available = hardirq_supported && attach_hardirq_programs(skel, &mut links);
    Ok((links, dsq_available, block_io_available, hardirq_available))
}

fn tracepoint_available(group: &str, event: &str) -> bool {
    [
        "/sys/kernel/tracing/events",
        "/sys/kernel/debug/tracing/events",
    ]
    .into_iter()
    .any(|root| Path::new(root).join(group).join(event).exists())
}

fn configure_block_io_programs(
    open_skel: &mut crate::bpf_skel::OpenBpfSkel<'_>,
    enabled: bool,
) -> bool {
    let supported = enabled
        && tracepoint_available("block", "block_rq_issue")
        && tracepoint_available("block", "block_rq_complete");
    if !supported {
        open_skel.progs.block_io_observer_issue.set_autoload(false);
        open_skel
            .progs
            .block_io_observer_complete
            .set_autoload(false);
    }
    supported
}

fn attach_block_io_programs(skel: &BpfSkel<'_>, links: &mut Vec<Link>) -> bool {
    let issue = match skel.progs.block_io_observer_issue.attach() {
        Ok(link) => link,
        Err(error) => {
            eprintln!("block I/O observer could not attach issue tracepoint: {error}");
            return false;
        }
    };
    let complete = match skel.progs.block_io_observer_complete.attach() {
        Ok(link) => link,
        Err(error) => {
            eprintln!("block I/O observer could not attach completion tracepoint: {error}");
            return false;
        }
    };
    links.extend([issue, complete]);
    true
}

fn configure_hardirq_programs(
    open_skel: &mut crate::bpf_skel::OpenBpfSkel<'_>,
    enabled: bool,
) -> bool {
    let supported = enabled
        && tracepoint_available("irq", "irq_handler_entry")
        && tracepoint_available("irq", "irq_handler_exit");
    if !supported {
        open_skel.progs.hirqo_entry.set_autoload(false);
        open_skel.progs.hirqo_exit.set_autoload(false);
    }
    supported
}

fn attach_hardirq_programs(skel: &BpfSkel<'_>, links: &mut Vec<Link>) -> bool {
    let entry = match skel.progs.hirqo_entry.attach() {
        Ok(link) => link,
        Err(error) => {
            eprintln!("hard IRQ observer could not attach entry tracepoint: {error}");
            return false;
        }
    };
    let exit = match skel.progs.hirqo_exit.attach() {
        Ok(link) => link,
        Err(error) => {
            eprintln!("hard IRQ observer could not attach exit tracepoint: {error}");
            return false;
        }
    };
    links.extend([entry, exit]);
    true
}

fn kernel_symbols() -> HashSet<String> {
    fs::read_to_string("/proc/kallsyms")
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.split_whitespace().nth(2))
        .map(str::to_owned)
        .collect()
}

fn attach_dsq_programs(skel: &BpfSkel<'_>, links: &mut Vec<Link>) -> bool {
    let symbols = kernel_symbols();
    let mut attached = false;

    macro_rules! attach_if_present {
        ($symbol:literal, $program:ident) => {
            if symbols.contains($symbol) {
                match skel.progs.$program.attach() {
                    Ok(link) => {
                        links.push(link);
                        attached = true;
                    }
                    Err(error) => {
                        eprintln!("DSQ observer could not attach to {}: {error}", $symbol)
                    }
                }
            }
        };
    }

    let has_new_insert = symbols.contains("scx_bpf_dsq_insert")
        || symbols.contains("scx_bpf_dsq_insert_vtime")
        || symbols.contains("scx_bpf_dsq_insert___v2")
        || symbols.contains("__scx_bpf_dsq_insert_vtime");
    if has_new_insert {
        attach_if_present!("scx_bpf_dsq_insert", dsqo_insert);
        attach_if_present!("scx_bpf_dsq_insert___v2", dsqo_insert_v2);
        attach_if_present!("scx_bpf_dsq_insert_vtime", dsqo_insert_vtime);
        attach_if_present!("__scx_bpf_dsq_insert_vtime", dsqo_insert_vtime_args);
    } else {
        attach_if_present!("scx_bpf_dispatch", dsqo_dispatch);
        attach_if_present!("scx_bpf_dispatch_vtime", dsqo_dispatch_vtime);
    }

    if symbols.contains("scx_bpf_dsq_move_to_local") {
        attach_if_present!("scx_bpf_dsq_move_to_local", dsqo_move_local_ret);
    } else {
        attach_if_present!("scx_bpf_consume", dsqo_consume_ret);
    }
    if attached {
        match skel.progs.dsqo_sched_switch.attach() {
            Ok(link) => links.push(link),
            Err(error) => eprintln!("DSQ observer could not attach sched_switch: {error}"),
        }
    }
    attached
}

fn read_counts(skel: &BpfSkel<'_>) -> Result<[u64; 5]> {
    (0..CALLBACK_NAMES.len())
        .map(|index| {
            let key = (index as u32).to_ne_bytes();
            let values = skel
                .maps
                .callback_counts
                .lookup_percpu(&key, MapFlags::ANY)?
                .with_context(|| format!("callback map entry {} missing", CALLBACK_NAMES[index]))?;
            values.into_iter().try_fold(0_u64, |total, value| {
                let bytes: [u8; 8] = value
                    .get(..8)
                    .context("short per-CPU callback count")?
                    .try_into()
                    .expect("slice length checked");
                Ok(total.saturating_add(u64::from_ne_bytes(bytes)))
            })
        })
        .collect::<Result<Vec<_>>>()?
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected five callback counts"))
}

fn read_scheduler_events(skel: &BpfSkel<'_>) -> Result<[u64; 9]> {
    const U64_BYTES: usize = std::mem::size_of::<u64>();
    let key = 0_u32.to_ne_bytes();
    let values = skel
        .maps
        .scheduler_event_metrics
        .lookup_percpu(&key, MapFlags::ANY)?
        .context("scheduler event metrics entry missing")?;
    let mut totals = [0_u64; SCHEDULER_EVENT_NAMES.len()];
    for value in values {
        if value.len() < totals.len() * U64_BYTES {
            bail!("short scheduler event metrics value");
        }
        for (index, total) in totals.iter_mut().enumerate() {
            let start = index * U64_BYTES;
            *total = total.saturating_add(u64::from_ne_bytes(
                value[start..start + U64_BYTES].try_into()?,
            ));
        }
    }
    Ok(totals)
}

fn read_softirq_metrics(skel: &BpfSkel<'_>) -> Result<SoftirqMetricsSnapshot> {
    const U64_BYTES: usize = std::mem::size_of::<u64>();
    const FIELD_COUNT: usize = 2 + CALLBACK_TIMING_BUCKETS;

    let mut rows = Vec::with_capacity(SOFTIRQ_NAMES.len());
    let mut cpu_elapsed_ns = Vec::<u64>::new();
    for vector in 0..SOFTIRQ_NAMES.len() {
        let key = (vector as u32).to_ne_bytes();
        let values = skel
            .maps
            .softirq_observer_metrics
            .lookup_percpu(&key, MapFlags::ANY)?
            .with_context(|| format!("softirq metrics entry {} missing", SOFTIRQ_NAMES[vector]))?;
        let mut count = 0_u64;
        let mut timing = CallbackTimingCounters::default();
        for (cpu, value) in values.into_iter().enumerate() {
            if value.len() < FIELD_COUNT * U64_BYTES {
                bail!("short softirq metrics value for {}", SOFTIRQ_NAMES[vector]);
            }
            let field = |index: usize| -> Result<u64> {
                let start = index * U64_BYTES;
                Ok(u64::from_ne_bytes(
                    value[start..start + U64_BYTES].try_into()?,
                ))
            };
            count = count.saturating_add(field(0)?);
            let elapsed_ns = field(1)?;
            timing.total_ns = timing.total_ns.saturating_add(elapsed_ns);
            if cpu_elapsed_ns.len() <= cpu {
                cpu_elapsed_ns.resize(cpu + 1, 0);
            }
            cpu_elapsed_ns[cpu] = cpu_elapsed_ns[cpu].saturating_add(elapsed_ns);
            for bucket in 0..CALLBACK_TIMING_BUCKETS {
                timing.buckets[bucket] = timing.buckets[bucket].saturating_add(field(2 + bucket)?);
            }
        }
        rows.push(SoftirqMetrics { count, timing });
    }
    Ok(SoftirqMetricsSnapshot {
        rows,
        cpu_elapsed_ns,
    })
}

fn build_softirq_rows(
    current: &[SoftirqMetrics],
    previous: &[SoftirqMetrics],
    elapsed: Duration,
) -> Vec<SoftirqRow> {
    let seconds = elapsed.as_secs_f64();
    current
        .iter()
        .zip(previous)
        .enumerate()
        .map(|(vector, (current, previous))| {
            let summary = summarize_callback_timing(&current.timing);
            SoftirqRow {
                vector: vector as u32,
                name: SOFTIRQ_NAMES[vector],
                count: current.count,
                rate_per_second: if seconds > 0.0 {
                    current.count.saturating_sub(previous.count) as f64 / seconds
                } else {
                    0.0
                },
                samples: summary.samples,
                mean_ns: summary.mean_ns,
                p50_ns: summary.p50_ns,
                p95_ns: summary.p95_ns,
                p99_ns: summary.p99_ns,
            }
        })
        .collect()
}

fn read_block_io_metrics(skel: &BpfSkel<'_>, available: bool) -> Result<BlockIoMetrics> {
    const U64_BYTES: usize = std::mem::size_of::<u64>();
    const FIELD_COUNT: usize = 9 + CALLBACK_TIMING_BUCKETS;

    if !available {
        return Ok(BlockIoMetrics::default());
    }
    let key = 0_u32.to_ne_bytes();
    let values = skel
        .maps
        .block_io_observer_metrics
        .lookup_percpu(&key, MapFlags::ANY)?
        .context("block I/O metrics entry missing")?;
    let mut metrics = BlockIoMetrics::default();
    for value in values {
        if value.len() < FIELD_COUNT * U64_BYTES {
            bail!("short block I/O metrics value");
        }
        let field = |index: usize| -> Result<u64> {
            let start = index * U64_BYTES;
            Ok(u64::from_ne_bytes(
                value[start..start + U64_BYTES].try_into()?,
            ))
        };
        metrics.issue_events = metrics.issue_events.saturating_add(field(0)?);
        metrics.completion_events = metrics.completion_events.saturating_add(field(1)?);
        metrics.completed_requests = metrics.completed_requests.saturating_add(field(2)?);
        metrics.error_events = metrics.error_events.saturating_add(field(3)?);
        metrics.issued_bytes = metrics.issued_bytes.saturating_add(field(4)?);
        metrics.completed_bytes = metrics.completed_bytes.saturating_add(field(5)?);
        metrics.unmatched_completions = metrics.unmatched_completions.saturating_add(field(6)?);
        metrics.tracking_failures = metrics.tracking_failures.saturating_add(field(7)?);
        metrics.latency.total_ns = metrics.latency.total_ns.saturating_add(field(8)?);
        for bucket in 0..CALLBACK_TIMING_BUCKETS {
            metrics.latency.buckets[bucket] =
                metrics.latency.buckets[bucket].saturating_add(field(9 + bucket)?);
        }
    }
    Ok(metrics)
}

fn build_block_io_view(
    current: &BlockIoMetrics,
    previous: &BlockIoMetrics,
    elapsed: Duration,
    available: bool,
) -> BlockIoMetricsView {
    let seconds = elapsed.as_secs_f64();
    let rate = |current: u64, previous: u64| {
        if seconds > 0.0 {
            current.saturating_sub(previous) as f64 / seconds
        } else {
            0.0
        }
    };
    let latency = summarize_callback_timing(&current.latency);
    BlockIoMetricsView {
        available,
        issue_events: current.issue_events,
        issue_rate_per_second: rate(current.issue_events, previous.issue_events),
        completion_events: current.completion_events,
        completion_rate_per_second: rate(current.completion_events, previous.completion_events),
        completed_requests: current.completed_requests,
        error_events: current.error_events,
        issued_bytes: current.issued_bytes,
        completed_bytes: current.completed_bytes,
        completed_bytes_per_second: rate(current.completed_bytes, previous.completed_bytes),
        unmatched_completions: current.unmatched_completions,
        tracking_failures: current.tracking_failures,
        latency_samples: latency.samples,
        latency_mean_ns: latency.mean_ns,
        latency_p50_ns: latency.p50_ns,
        latency_p95_ns: latency.p95_ns,
        latency_p99_ns: latency.p99_ns,
    }
}

fn read_hardirq_metrics(skel: &BpfSkel<'_>, available: bool) -> Result<HardirqMetrics> {
    const U64_BYTES: usize = std::mem::size_of::<u64>();
    const FIELD_COUNT: usize = 2 + CALLBACK_TIMING_BUCKETS;

    if !available {
        return Ok(HardirqMetrics::default());
    }
    let mut result = HardirqMetrics::default();
    for key in skel.maps.hardirq_observer_metrics.keys() {
        if key.len() != 4 {
            bail!("invalid hard IRQ key size {}", key.len());
        }
        let irq = u32::from_ne_bytes(key[..4].try_into()?);
        let Some(values) = skel
            .maps
            .hardirq_observer_metrics
            .lookup_percpu(&key, MapFlags::ANY)?
        else {
            continue;
        };
        let mut metric = SoftirqMetrics {
            count: 0,
            timing: CallbackTimingCounters::default(),
        };
        for (cpu, value) in values.into_iter().enumerate() {
            if value.len() < FIELD_COUNT * U64_BYTES {
                bail!("short hard IRQ metrics value for IRQ {irq}");
            }
            let field = |index: usize| -> Result<u64> {
                let start = index * U64_BYTES;
                Ok(u64::from_ne_bytes(
                    value[start..start + U64_BYTES].try_into()?,
                ))
            };
            metric.count = metric.count.saturating_add(field(0)?);
            let elapsed_ns = field(1)?;
            metric.timing.total_ns = metric.timing.total_ns.saturating_add(elapsed_ns);
            if result.cpu_elapsed_ns.len() <= cpu {
                result.cpu_elapsed_ns.resize(cpu + 1, 0);
            }
            result.cpu_elapsed_ns[cpu] = result.cpu_elapsed_ns[cpu].saturating_add(elapsed_ns);
            for bucket in 0..CALLBACK_TIMING_BUCKETS {
                metric.timing.buckets[bucket] =
                    metric.timing.buckets[bucket].saturating_add(field(2 + bucket)?);
            }
        }
        result.rows.insert(irq, metric);
    }

    let key = 0_u32.to_ne_bytes();
    if let Some(values) = skel
        .maps
        .hardirq_observer_health
        .lookup_percpu(&key, MapFlags::ANY)?
    {
        for value in values {
            if value.len() < 3 * U64_BYTES {
                bail!("short hard IRQ health value");
            }
            result.metrics_map_full = result
                .metrics_map_full
                .saturating_add(u64::from_ne_bytes(value[..8].try_into()?));
            result.starts_map_full = result
                .starts_map_full
                .saturating_add(u64::from_ne_bytes(value[8..16].try_into()?));
            result.unmatched_exits = result
                .unmatched_exits
                .saturating_add(u64::from_ne_bytes(value[16..24].try_into()?));
        }
    }
    Ok(result)
}

fn parse_irq_names(interrupts: &str) -> BTreeMap<u32, String> {
    let mut lines = interrupts.lines();
    let cpu_count = lines
        .next()
        .map(|header| {
            header
                .split_whitespace()
                .filter(|column| {
                    column.strip_prefix("CPU").is_some_and(|suffix| {
                        !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit())
                    })
                })
                .count()
        })
        .unwrap_or(0);
    if cpu_count == 0 {
        return BTreeMap::new();
    }

    lines
        .filter_map(|line| {
            let (irq, fields) = line.split_once(':')?;
            let irq = irq.trim().parse::<u32>().ok()?;
            let fields = fields.split_whitespace().collect::<Vec<_>>();
            if fields.len() <= cpu_count
                || !fields[..cpu_count]
                    .iter()
                    .all(|count| count.bytes().all(|b| b.is_ascii_digit()))
            {
                return None;
            }
            let metadata = &fields[cpu_count..];
            let trigger = metadata.iter().position(|field| {
                let field = field.to_ascii_lowercase();
                field == "edge"
                    || field == "level"
                    || field.contains("-edge")
                    || field.contains("-level")
                    || field.contains("-fasteoi")
            })?;
            let name = metadata.get(trigger + 1..)?.join(" ");
            (!name.is_empty()).then_some((irq, name))
        })
        .collect()
}

fn read_irq_names() -> BTreeMap<u32, String> {
    fs::read_to_string("/proc/interrupts")
        .map(|contents| parse_irq_names(&contents))
        .unwrap_or_default()
}

fn build_hardirq_view(
    current: &HardirqMetrics,
    previous: &HardirqMetrics,
    elapsed: Duration,
    available: bool,
    irq_names: &BTreeMap<u32, String>,
) -> HardirqMetricsView {
    let seconds = elapsed.as_secs_f64();
    let mut rows = current
        .rows
        .iter()
        .map(|(&irq, metric)| {
            let summary = summarize_callback_timing(&metric.timing);
            let previous_count = previous.rows.get(&irq).map_or(0, |row| row.count);
            HardirqRow {
                irq,
                name: irq_names.get(&irq).cloned(),
                count: metric.count,
                rate_per_second: if seconds > 0.0 {
                    metric.count.saturating_sub(previous_count) as f64 / seconds
                } else {
                    0.0
                },
                samples: summary.samples,
                mean_ns: summary.mean_ns,
                p50_ns: summary.p50_ns,
                p95_ns: summary.p95_ns,
                p99_ns: summary.p99_ns,
            }
        })
        .collect::<Vec<_>>();
    rows.sort_unstable_by_key(|row| std::cmp::Reverse(row.count));
    HardirqMetricsView {
        available,
        metrics_map_full: current.metrics_map_full,
        starts_map_full: current.starts_map_full,
        unmatched_exits: current.unmatched_exits,
        rows,
    }
}

fn build_interrupt_cpu_rows(
    current_softirq: &SoftirqMetricsSnapshot,
    previous_softirq: &SoftirqMetricsSnapshot,
    current_hardirq: &HardirqMetrics,
    previous_hardirq: &HardirqMetrics,
    elapsed: Duration,
) -> Vec<InterruptCpuRow> {
    let cpu_count = current_softirq
        .cpu_elapsed_ns
        .len()
        .max(current_hardirq.cpu_elapsed_ns.len());
    let elapsed_ns = elapsed.as_nanos() as f64;
    (0..cpu_count)
        .map(|cpu| {
            let percentage = |current: &[u64], previous: &[u64]| {
                if elapsed_ns > 0.0 {
                    (current
                        .get(cpu)
                        .copied()
                        .unwrap_or(0)
                        .saturating_sub(previous.get(cpu).copied().unwrap_or(0))
                        as f64
                        / elapsed_ns
                        * 100.0)
                        .clamp(0.0, 100.0)
                } else {
                    0.0
                }
            };
            let hardirq = percentage(
                &current_hardirq.cpu_elapsed_ns,
                &previous_hardirq.cpu_elapsed_ns,
            );
            let softirq = percentage(
                &current_softirq.cpu_elapsed_ns,
                &previous_softirq.cpu_elapsed_ns,
            );
            InterruptCpuRow {
                cpu: cpu as u32,
                hardirq_utilization_pct: hardirq,
                softirq_utilization_pct: softirq,
                total_utilization_pct: (hardirq + softirq).clamp(0.0, 100.0),
            }
        })
        .collect()
}

fn read_callback_timings(skel: &BpfSkel<'_>) -> Result<Vec<CallbackTimingCounters>> {
    (0..CALLBACK_NAMES.len())
        .map(|index| {
            let key = (index as u32).to_ne_bytes();
            let values = skel
                .maps
                .callback_timings
                .lookup_percpu(&key, MapFlags::ANY)?
                .with_context(|| {
                    format!("callback timing entry {} missing", CALLBACK_NAMES[index])
                })?;
            aggregate_timing(values, CALLBACK_NAMES[index])
        })
        .collect()
}

fn read_wakeup_latency(skel: &BpfSkel<'_>) -> Result<CallbackTimingCounters> {
    let key = 0_u32.to_ne_bytes();
    let values = skel
        .maps
        .wakeup_latency
        .lookup_percpu(&key, MapFlags::ANY)?
        .context("wakeup latency entry missing")?;
    aggregate_timing(values, "wakeup_to_running")
}

fn read_cpu_slice_duration(skel: &BpfSkel<'_>) -> Result<CallbackTimingCounters> {
    let key = 0_u32.to_ne_bytes();
    let values = skel
        .maps
        .cpu_slice_duration
        .lookup_percpu(&key, MapFlags::ANY)?
        .context("CPU slice duration entry missing")?;
    aggregate_timing(values, "on_cpu_slice")
}

fn read_blocked_duration(skel: &BpfSkel<'_>) -> Result<CallbackTimingCounters> {
    let key = 0_u32.to_ne_bytes();
    let values = skel
        .maps
        .blocked_duration
        .lookup_percpu(&key, MapFlags::ANY)?
        .context("blocked duration entry missing")?;
    aggregate_timing(values, "blocked_off_cpu")
}

fn aggregate_timing(values: Vec<Vec<u8>>, name: &str) -> Result<CallbackTimingCounters> {
    const U64_BYTES: usize = std::mem::size_of::<u64>();
    const VALUE_BYTES: usize = (CALLBACK_TIMING_BUCKETS + 1) * U64_BYTES;

    values
        .into_iter()
        .try_fold(CallbackTimingCounters::default(), |mut total, value| {
            if value.len() < VALUE_BYTES {
                bail!("short timing value for {name}");
            }
            total.total_ns = total
                .total_ns
                .saturating_add(u64::from_ne_bytes(value[..U64_BYTES].try_into()?));
            for (bucket, bytes) in value[U64_BYTES..VALUE_BYTES]
                .chunks_exact(U64_BYTES)
                .enumerate()
            {
                total.buckets[bucket] =
                    total.buckets[bucket].saturating_add(u64::from_ne_bytes(bytes.try_into()?));
            }
            Ok(total)
        })
}

fn read_migrations(skel: &BpfSkel<'_>) -> Result<Vec<MigrationRow>> {
    let mut rows = Vec::new();
    for key in skel.maps.migration_counts.keys() {
        if key.len() != 8 {
            bail!("invalid migration key size {}", key.len());
        }
        let Some(value) = skel.maps.migration_counts.lookup(&key, MapFlags::ANY)? else {
            continue;
        };
        if value.len() < 8 {
            bail!("short migration counter value");
        }
        rows.push(MigrationRow {
            from_cpu: u32::from_ne_bytes(key[..4].try_into()?),
            to_cpu: u32::from_ne_bytes(key[4..8].try_into()?),
            count: u64::from_ne_bytes(value[..8].try_into()?),
        });
    }
    rows.sort_unstable_by_key(|row| std::cmp::Reverse(row.count));
    Ok(rows)
}

fn read_cpu_runtime(skel: &BpfSkel<'_>) -> Result<Vec<u64>> {
    let key = 0_u32.to_ne_bytes();
    let values = skel
        .maps
        .cpu_runtime
        .lookup_percpu(&key, MapFlags::ANY)?
        .context("CPU runtime entry missing")?;
    let now_ns = monotonic_time_ns()?;
    values
        .into_iter()
        .map(|value| {
            let last_switch_ns = u64::from_ne_bytes(
                value
                    .get(..8)
                    .context("short CPU runtime value")?
                    .try_into()?,
            );
            let busy_ns = u64::from_ne_bytes(
                value
                    .get(8..16)
                    .context("short CPU runtime value")?
                    .try_into()?,
            );
            let current_busy = u64::from_ne_bytes(
                value
                    .get(16..24)
                    .context("short CPU runtime value")?
                    .try_into()?,
            ) != 0;
            Ok(project_cpu_runtime(
                busy_ns,
                last_switch_ns,
                current_busy,
                now_ns,
            ))
        })
        .collect()
}

fn monotonic_time_ns() -> Result<u64> {
    let mut time = MaybeUninit::<libc::timespec>::uninit();
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, time.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("reading monotonic clock");
    }
    let time = unsafe { time.assume_init() };
    let seconds = u64::try_from(time.tv_sec).context("negative monotonic clock seconds")?;
    let nanoseconds =
        u64::try_from(time.tv_nsec).context("negative monotonic clock nanoseconds")?;
    Ok(seconds
        .saturating_mul(1_000_000_000)
        .saturating_add(nanoseconds))
}

fn read_dsq_metrics(skel: &BpfSkel<'_>, available: bool) -> Result<DsqMetricsView> {
    const FIELD_COUNT: usize = 3 + CALLBACK_TIMING_BUCKETS + 4;
    const U64_BYTES: usize = std::mem::size_of::<u64>();

    let key = 0_u32.to_ne_bytes();
    let values = skel
        .maps
        .dsq_observer_metrics
        .lookup_percpu(&key, MapFlags::ANY)?
        .context("DSQ metrics entry missing")?;
    let mut insert_count = 0_u64;
    let mut move_count = 0_u64;
    let mut residence = CallbackTimingCounters::default();
    let mut depth_samples = 0_u64;
    let mut depth_total = 0_u64;
    let mut depth_latest_max = 0_u64;
    let mut depth_max = 0_u64;

    for value in values {
        if value.len() < FIELD_COUNT * U64_BYTES {
            bail!("short DSQ metrics value");
        }
        let field = |index: usize| -> Result<u64> {
            let start = index * U64_BYTES;
            Ok(u64::from_ne_bytes(
                value[start..start + U64_BYTES].try_into()?,
            ))
        };
        insert_count = insert_count.saturating_add(field(0)?);
        move_count = move_count.saturating_add(field(1)?);
        residence.total_ns = residence.total_ns.saturating_add(field(2)?);
        for bucket in 0..CALLBACK_TIMING_BUCKETS {
            residence.buckets[bucket] =
                residence.buckets[bucket].saturating_add(field(3 + bucket)?);
        }
        depth_samples = depth_samples.saturating_add(field(67)?);
        depth_total = depth_total.saturating_add(field(68)?);
        depth_latest_max = depth_latest_max.max(field(69)?);
        depth_max = depth_max.max(field(70)?);
    }

    let summary = summarize_callback_timing(&residence);
    Ok(DsqMetricsView {
        available,
        insert_count,
        move_count,
        residence_samples: summary.samples,
        residence_mean_ns: summary.mean_ns,
        residence_p50_ns: summary.p50_ns,
        residence_p95_ns: summary.p95_ns,
        residence_p99_ns: summary.p99_ns,
        depth_samples,
        depth_average: (depth_samples > 0).then(|| depth_total as f64 / depth_samples as f64),
        depth_latest_max,
        depth_max,
    })
}

pub fn run(
    state: Arc<RwLock<Snapshot>>,
    shutdown: Arc<AtomicBool>,
    ready: Sender<Result<()>>,
    config: CollectorConfig,
) -> Result<()> {
    let targets = match find_targets() {
        Ok(targets) => targets,
        Err(error) => {
            let message = format!("{error:#}");
            let _ = ready.send(Err(anyhow::anyhow!(message.clone())));
            bail!(message);
        }
    };
    let target_program_ids = targets.each_ref().map(|target| target.id);
    let existing_program_ids = ProgInfoIter::default()
        .map(|program| program.id)
        .collect::<HashSet<_>>();

    let mut open_object = MaybeUninit::<OpenObject>::uninit();
    let mut open_skel = BpfSkelBuilder::default()
        .open(&mut open_object)
        .context("opening callback collector BPF object")?;
    set_targets(&mut open_skel, &targets).context("setting callback attach targets")?;
    let block_io_supported = configure_block_io_programs(&mut open_skel, config.enable_block_io);
    let hardirq_supported = configure_hardirq_programs(&mut open_skel, config.enable_irqs);
    let rodata = open_skel
        .maps
        .rodata_data
        .as_mut()
        .context("callback collector rodata is unavailable")?;
    rodata.callback_timing_sample_rate = config.callback_timing_sample_rate;
    rodata.event_timing_sample_rate = config.event_timing_sample_rate;
    let skel = open_skel
        .load()
        .context("loading callback collector BPF object")?;
    let inspector_program_ids = ProgInfoIter::default()
        .filter(|program| !existing_program_ids.contains(&program.id))
        .map(|program| program.id)
        .collect::<Vec<_>>();
    let (_links, dsq_available, block_io_available, hardirq_available) =
        attach_programs(&skel, config, block_io_supported, hardirq_supported)
            .context("attaching callback observer programs")?;

    let started = Instant::now();
    let mut previous = read_counts(&skel)?;
    let mut previous_scheduler_events = read_scheduler_events(&skel)?;
    let mut previous_softirqs = read_softirq_metrics(&skel)?;
    let mut previous_block_io = read_block_io_metrics(&skel, block_io_available)?;
    let mut previous_hardirqs = read_hardirq_metrics(&skel, hardirq_available)?;
    let irq_names = read_irq_names();
    let callback_timings = read_callback_timings(&skel)?;
    let wakeup_latency = read_wakeup_latency(&skel)?;
    let cpu_slice_duration = read_cpu_slice_duration(&skel)?;
    let blocked_duration = read_blocked_duration(&skel)?;
    let migrations = read_migrations(&skel)?;
    let mut previous_cpu_runtime = read_cpu_runtime(&skel)?;
    let bpf_program_stats = query_bpf_program_stats(&target_program_ids);
    let inspector_bpf_program_stats = query_bpf_program_stats(&inspector_program_ids);
    let inspector_stats_enabled = inspector_bpf_program_stats
        .iter()
        .any(|program| program.run_count > 0 || program.run_time_ns > 0);
    let mut previous_inspector_runtime_ns = inspector_bpf_program_stats
        .iter()
        .map(|program| program.run_time_ns)
        .sum::<u64>();
    let dsq_metrics = read_dsq_metrics(&skel, dsq_available)?;
    let mut previous_at = Instant::now();
    {
        let mut snapshot = state.write().expect("snapshot lock poisoned");
        *snapshot = Snapshot {
            scheduler: "scx_mitosis",
            target_program_ids,
            uptime_seconds: 0,
            counters: build_counters(previous, previous, Duration::ZERO),
            callback_timing_sample_rate: config.callback_timing_sample_rate,
            event_timing_sample_rate: config.event_timing_sample_rate,
            callback_timings: build_callback_timing_rows(&callback_timings),
            scheduler_timings: vec![
                build_timing_metric_row("wakeup_to_running", &wakeup_latency),
                build_timing_metric_row("on_cpu_slice", &cpu_slice_duration),
                build_timing_metric_row("blocked_off_cpu", &blocked_duration),
            ],
            migrations,
            cpu_runtime: build_cpu_runtime_rows(
                &previous_cpu_runtime,
                &previous_cpu_runtime,
                Duration::ZERO,
            ),
            bpf_program_stats,
            inspector_bpf_program_stats,
            inspector_bpf_cpu_equivalent_pct: None,
            inspector_bpf_host_capacity_pct: None,
            dsq_metrics,
            scheduler_events: build_scheduler_event_rows(
                previous_scheduler_events,
                previous_scheduler_events,
                Duration::ZERO,
            ),
            softirqs: build_softirq_rows(
                &previous_softirqs.rows,
                &previous_softirqs.rows,
                Duration::ZERO,
            ),
            block_io: build_block_io_view(
                &previous_block_io,
                &previous_block_io,
                Duration::ZERO,
                block_io_available,
            ),
            interrupt_cpu: build_interrupt_cpu_rows(
                &previous_softirqs,
                &previous_softirqs,
                &previous_hardirqs,
                &previous_hardirqs,
                Duration::ZERO,
            ),
            hardirqs: build_hardirq_view(
                &previous_hardirqs,
                &previous_hardirqs,
                Duration::ZERO,
                hardirq_available,
                &irq_names,
            ),
            probe_manifest: probe_manifest(
                config,
                dsq_available,
                block_io_available,
                hardirq_available,
                inspector_stats_enabled,
            ),
        };
    }
    ready
        .send(Ok(()))
        .context("reporting collector readiness")?;

    while !shutdown.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_secs(1));
        let now = Instant::now();
        let current = read_counts(&skel)?;
        let current_scheduler_events = read_scheduler_events(&skel)?;
        let current_softirqs = read_softirq_metrics(&skel)?;
        let current_block_io = read_block_io_metrics(&skel, block_io_available)?;
        let current_hardirqs = read_hardirq_metrics(&skel, hardirq_available)?;
        let callback_timings = read_callback_timings(&skel)?;
        let wakeup_latency = read_wakeup_latency(&skel)?;
        let cpu_slice_duration = read_cpu_slice_duration(&skel)?;
        let blocked_duration = read_blocked_duration(&skel)?;
        let migrations = read_migrations(&skel)?;
        let current_cpu_runtime = read_cpu_runtime(&skel)?;
        let bpf_program_stats = query_bpf_program_stats(&target_program_ids);
        let inspector_bpf_program_stats = query_bpf_program_stats(&inspector_program_ids);
        let dsq_metrics = read_dsq_metrics(&skel, dsq_available)?;
        let elapsed = now.duration_since(previous_at);
        let inspector_runtime_ns = inspector_bpf_program_stats
            .iter()
            .map(|program| program.run_time_ns)
            .sum::<u64>();
        let inspector_stats_enabled = inspector_bpf_program_stats
            .iter()
            .any(|program| program.run_count > 0 || program.run_time_ns > 0);
        let inspector_cpu_equivalent_pct = inspector_stats_enabled.then(|| {
            inspector_runtime_ns.saturating_sub(previous_inspector_runtime_ns) as f64
                / elapsed.as_nanos() as f64
                * 100.0
        });
        let counters = build_counters(current, previous, elapsed);
        previous = current;
        let mut snapshot = state.write().expect("snapshot lock poisoned");
        snapshot.uptime_seconds = started.elapsed().as_secs();
        snapshot.counters = counters;
        snapshot.callback_timings = build_callback_timing_rows(&callback_timings);
        snapshot.scheduler_timings = vec![
            build_timing_metric_row("wakeup_to_running", &wakeup_latency),
            build_timing_metric_row("on_cpu_slice", &cpu_slice_duration),
            build_timing_metric_row("blocked_off_cpu", &blocked_duration),
        ];
        snapshot.migrations = migrations;
        snapshot.cpu_runtime =
            build_cpu_runtime_rows(&current_cpu_runtime, &previous_cpu_runtime, elapsed);
        previous_cpu_runtime = current_cpu_runtime;
        snapshot.bpf_program_stats = bpf_program_stats;
        snapshot.inspector_bpf_program_stats = inspector_bpf_program_stats;
        snapshot.inspector_bpf_cpu_equivalent_pct = inspector_cpu_equivalent_pct;
        snapshot.inspector_bpf_host_capacity_pct = inspector_cpu_equivalent_pct
            .map(|percentage| percentage / previous_cpu_runtime.len().max(1) as f64);
        previous_inspector_runtime_ns = inspector_runtime_ns;
        snapshot.dsq_metrics = dsq_metrics;
        snapshot.scheduler_events = build_scheduler_event_rows(
            current_scheduler_events,
            previous_scheduler_events,
            elapsed,
        );
        previous_scheduler_events = current_scheduler_events;
        snapshot.softirqs =
            build_softirq_rows(&current_softirqs.rows, &previous_softirqs.rows, elapsed);
        snapshot.block_io = build_block_io_view(
            &current_block_io,
            &previous_block_io,
            elapsed,
            block_io_available,
        );
        previous_block_io = current_block_io;
        snapshot.interrupt_cpu = build_interrupt_cpu_rows(
            &current_softirqs,
            &previous_softirqs,
            &current_hardirqs,
            &previous_hardirqs,
            elapsed,
        );
        snapshot.hardirqs = build_hardirq_view(
            &current_hardirqs,
            &previous_hardirqs,
            elapsed,
            hardirq_available,
            &irq_names,
        );
        snapshot.probe_manifest = probe_manifest(
            config,
            dsq_available,
            block_io_available,
            hardirq_available,
            inspector_stats_enabled,
        );
        previous_softirqs = current_softirqs;
        previous_hardirqs = current_hardirqs;
        previous_at = now;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::parse_irq_names;

    #[test]
    fn parses_irq_action_names_after_per_cpu_counts() {
        let interrupts = r#"           CPU0       CPU1
  8:          1          2  IR-IO-APIC    8-edge      rtc0
 24:         10         20  IR-PCI-MSIX-0000:00:1f.4    0-edge      i2c_designware.0
 45:          3          4  GICv3  30 Level     arch_timer
NMI:          0          0   Non-maskable interrupts
"#;

        let names = parse_irq_names(interrupts);

        assert_eq!(names.get(&8).map(String::as_str), Some("rtc0"));
        assert_eq!(names.get(&24).map(String::as_str), Some("i2c_designware.0"));
        assert_eq!(names.get(&45).map(String::as_str), Some("arch_timer"));
        assert!(!names.contains_key(&0));
    }

    #[test]
    fn skips_malformed_and_unrecognized_irq_lines() {
        let interrupts = r#"           CPU0       CPU1
abc:          1          2  IR-IO-APIC  8-edge bogus
  9:          x          2  IR-IO-APIC  9-fasteoi malformed
 10:          1          2  vendor-format mystery-device
"#;

        assert!(parse_irq_names(interrupts).is_empty());
    }
}
