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
use std::sync::{
    mpsc::{Receiver, RecvTimeoutError},
    Arc, RwLock,
};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use libbpf_rs::query::ProgInfoIter;
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{Link, MapCore, MapFlags, OpenObject, Program, ProgramType};
use serde::Serialize;
use tokio::sync::oneshot;

use crate::bpf_program_stats::{query_bpf_program_stats, BpfProgramStatsRow};
use crate::bpf_skel::{BpfSkel, BpfSkelBuilder};
use crate::lifecycle::{
    read_scheduler_identity, unix_ms, CollectorStatus, ObserverContext, RetryBackoff, SampleMeta,
    SchedulerIdentity, SharedObserverContext,
};
use crate::migration_history::MigrationHistory;
use crate::probe_manifest::{build_probe_manifest, ProbeManifestInputs};
use crate::scheduler_config::SchedulerConfigSnapshot;
use crate::{
    build_callback_timing_rows, build_counters, build_cpu_capacity_loss_rows,
    build_cpu_runtime_rows, build_scheduler_event_rows, build_timing_metric_row,
    program_name_matches, project_cpu_runtime, summarize_callback_timing, BlockIoMetricsView,
    CallbackCounter, CallbackTimingCounters, CallbackTimingRow, CpuCapacityLossRow, CpuRuntimeRow,
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

pub enum CollectorCommand {
    Reset(ResetRequest),
    Shutdown,
}

pub struct ResetRequest {
    pub expected_epoch: u64,
    pub deadline: Instant,
    pub reply: oneshot::Sender<std::result::Result<ResetReceipt, String>>,
}

impl ResetRequest {
    fn check_deadline(&self, now: Instant) -> std::result::Result<(), String> {
        if self.reply.is_closed() {
            return Err("reset request cancelled".into());
        }
        if now >= self.deadline {
            return Err("reset request expired".into());
        }
        Ok(())
    }

    fn validate(&self, context: &ObserverContext, now: Instant) -> std::result::Result<(), String> {
        self.check_deadline(now)?;
        if self.expected_epoch != context.epoch {
            return Err("reset epoch changed; refresh before retrying".into());
        }
        if context.status != CollectorStatus::Active {
            return Err("inspector is not actively attached".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ResetReceipt {
    pub epoch: u64,
    pub sample_seq: u64,
    pub reset_at_unix_ms: u64,
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

#[derive(Clone, Default)]
struct SoftirqMetricsSnapshot {
    rows: Vec<SoftirqMetrics>,
    cpu_elapsed_ns: Vec<u64>,
}

#[derive(Clone, Default)]
struct CpuRuntimeSnapshot {
    busy_ns: Vec<u64>,
    rt_stop_ns: Vec<u64>,
    deadline_ns: Vec<u64>,
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
    pub meta: SampleMeta,
    pub collector: ObserverContext,
    pub migration_map_capacity: u32,
    pub migration_map_failures: u64,
    pub migration_quality: &'static str,
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
    pub cpu_capacity_loss: Vec<CpuCapacityLossRow>,
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

impl Snapshot {
    /// Clone replay/compact API fields without allocating the lifetime migration map.
    pub fn compact_clone_without_migrations(&self) -> Self {
        Self {
            meta: self.meta.clone(),
            collector: self.collector.clone(),
            migration_map_capacity: self.migration_map_capacity,
            migration_map_failures: self.migration_map_failures,
            migration_quality: self.migration_quality,
            scheduler: self.scheduler,
            target_program_ids: self.target_program_ids,
            uptime_seconds: self.uptime_seconds,
            counters: self.counters.clone(),
            callback_timing_sample_rate: self.callback_timing_sample_rate,
            event_timing_sample_rate: self.event_timing_sample_rate,
            callback_timings: self.callback_timings.clone(),
            scheduler_timings: self.scheduler_timings.clone(),
            migrations: Vec::new(),
            cpu_runtime: self.cpu_runtime.clone(),
            cpu_capacity_loss: self.cpu_capacity_loss.clone(),
            bpf_program_stats: self.bpf_program_stats.clone(),
            inspector_bpf_program_stats: self.inspector_bpf_program_stats.clone(),
            inspector_bpf_cpu_equivalent_pct: self.inspector_bpf_cpu_equivalent_pct,
            inspector_bpf_host_capacity_pct: self.inspector_bpf_host_capacity_pct,
            dsq_metrics: self.dsq_metrics.clone(),
            scheduler_events: self.scheduler_events.clone(),
            softirqs: self.softirqs.clone(),
            block_io: self.block_io.clone(),
            interrupt_cpu: self.interrupt_cpu.clone(),
            hardirqs: self.hardirqs.clone(),
            probe_manifest: self.probe_manifest.clone(),
        }
    }

    pub fn empty(config: CollectorConfig) -> Self {
        Self {
            meta: SampleMeta::default(),
            collector: ObserverContext::default(),
            migration_map_capacity: 0,
            migration_map_failures: 0,
            migration_quality: "unavailable",
            scheduler: "scx_mitosis",
            target_program_ids: [0; 5],
            uptime_seconds: 0,
            counters: Vec::new(),
            callback_timing_sample_rate: config.callback_timing_sample_rate,
            event_timing_sample_rate: config.event_timing_sample_rate,
            callback_timings: Vec::new(),
            scheduler_timings: Vec::new(),
            migrations: Vec::new(),
            cpu_runtime: Vec::new(),
            cpu_capacity_loss: Vec::new(),
            bpf_program_stats: Vec::new(),
            inspector_bpf_program_stats: Vec::new(),
            inspector_bpf_cpu_equivalent_pct: None,
            inspector_bpf_host_capacity_pct: None,
            dsq_metrics: DsqMetricsView::default(),
            scheduler_events: Vec::new(),
            softirqs: Vec::new(),
            block_io: BlockIoMetricsView::default(),
            interrupt_cpu: Vec::new(),
            hardirqs: HardirqMetricsView::default(),
            probe_manifest: Vec::new(),
        }
    }
}

fn migration_map_capacity(possible_cpus: usize) -> u32 {
    possible_cpus
        .saturating_mul(possible_cpus)
        .clamp(1, 1_048_576) as u32
}

fn publish_context(
    state: &Arc<RwLock<Snapshot>>,
    history: &Arc<RwLock<MigrationHistory>>,
    observer: &SharedObserverContext,
    context: ObserverContext,
    config: CollectorConfig,
) {
    // Every collector writer uses this order. API readers take one lock at a time.
    let mut snapshot = state.write().expect("snapshot lock poisoned");
    let mut history = history.write().expect("migration history lock poisoned");
    let mut observer = observer.write().expect("observer lock poisoned");
    let last_success = snapshot.meta.last_success_at_unix_ms;
    *snapshot = Snapshot::empty(config);
    snapshot.meta.epoch = context.epoch;
    snapshot.meta.last_success_at_unix_ms = last_success;
    snapshot.meta.error = context.error.clone();
    snapshot.collector = context.clone();
    history.set_context(snapshot.meta.clone(), context.clone(), 0, 0);
    *observer = context;
}

fn publish_sample(
    state: &Arc<RwLock<Snapshot>>,
    history: &Arc<RwLock<MigrationHistory>>,
    observer: &SharedObserverContext,
    snapshot: Snapshot,
    at_ms: u64,
) -> Result<()> {
    publish_sample_inner(state, history, observer, snapshot, at_ms, None)
}

fn publish_sample_inner(
    state: &Arc<RwLock<Snapshot>>,
    history: &Arc<RwLock<MigrationHistory>>,
    observer: &SharedObserverContext,
    snapshot: Snapshot,
    at_ms: u64,
    pending_reset: Option<&mut Option<PendingReset>>,
) -> Result<()> {
    let mut current = state.write().expect("snapshot lock poisoned");
    let mut history = history.write().expect("migration history lock poisoned");
    let mut observer = observer.write().expect("observer lock poisoned");
    if observer.epoch != snapshot.meta.epoch {
        bail!("collector epoch changed before publishing sample");
    }
    if let Some(Some(pending)) = pending_reset.as_ref() {
        // Check after taking the publication locks: a delayed lock acquisition
        // must never commit a reset whose HTTP deadline has already elapsed.
        pending
            .request
            .check_deadline(Instant::now())
            .map_err(anyhow::Error::msg)?;
        if pending.request.expected_epoch.checked_add(1) != Some(snapshot.meta.epoch)
            || context_identity(&snapshot.collector).as_ref() != Some(&pending.identity)
        {
            bail!("reset epoch or scheduler changed before publication");
        }
        if snapshot.meta.sample_seq == 0 || snapshot.collector.status != CollectorStatus::Active {
            bail!("reset baseline has no active sample");
        }
        snapshot
            .meta
            .captured_at_unix_ms
            .context("reset baseline has no capture time")?;
    }
    history.set_context(
        snapshot.meta.clone(),
        snapshot.collector.clone(),
        snapshot.migration_map_capacity,
        snapshot.migration_map_failures,
    );
    history.ingest(at_ms, &snapshot.migrations);
    *observer = snapshot.collector.clone();
    *current = snapshot;
    if let Some(pending_reset) = pending_reset {
        if let Some(pending) = pending_reset.take() {
            let _ = pending.request.reply.send(Ok(ResetReceipt {
                epoch: current.meta.epoch,
                sample_seq: current.meta.sample_seq,
                reset_at_unix_ms: current
                    .meta
                    .captured_at_unix_ms
                    .expect("validated reset capture time"),
            }));
        }
    }
    Ok(())
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
        skel.progs.on_sched_switch.attach()?,
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

fn configure_optional_probes(
    open_skel: &mut crate::bpf_skel::OpenBpfSkel<'_>,
    config: CollectorConfig,
) -> Result<(bool, bool)> {
    let block_io_supported = configure_block_io_programs(open_skel, config.enable_block_io);
    let hardirq_supported = configure_hardirq_programs(open_skel, config.enable_irqs);
    for mut program in open_skel.open_object_mut().progs_mut() {
        let name = program.name().to_string_lossy();
        let disabled = (!config.enable_dsq && name.starts_with("dsqo_"))
            || (!config.enable_scheduler_events && name.starts_with("scheduler_event_"))
            || (!config.enable_irqs && name.starts_with("sirqo_"))
            || (!hardirq_supported && name.starts_with("hirqo_"))
            || (!block_io_supported && name.starts_with("block_io_observer_"))
            || (config.callback_timing_sample_rate == 0
                && name.starts_with("observe_")
                && name.ends_with("_exit"))
            || (config.event_timing_sample_rate == 0
                && matches!(name.as_ref(), "on_sched_wakeup" | "on_sched_wakeup_new"));
        if disabled {
            program.set_autoload(false);
        }
    }
    for mut map in open_skel.open_object_mut().maps_mut() {
        let name = map.name().to_string_lossy();
        let disabled = (!config.enable_dsq && name.starts_with("dsq_"))
            || (!config.enable_scheduler_events && name.starts_with("scheduler_event_"))
            || (!config.enable_irqs && name.starts_with("softirq_"))
            || (!hardirq_supported && name.starts_with("hardirq_"))
            || (!block_io_supported && name.starts_with("block_io_"))
            || (config.callback_timing_sample_rate == 0 && name == "callback_timings");
        if disabled {
            map.set_autocreate(false)
                .with_context(|| format!("disabling optional map {:?}", map.name()))?;
        }
    }
    // Callback entries use timing_starts even at rate zero. The mandatory
    // sched_switch runtime probe also references the task timing maps.
    Ok((block_io_supported, hardirq_supported))
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

fn read_scheduler_events(skel: &BpfSkel<'_>, enabled: bool) -> Result<[u64; 9]> {
    if !enabled {
        return Ok([0; 9]);
    }
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

fn read_softirq_metrics(skel: &BpfSkel<'_>, enabled: bool) -> Result<SoftirqMetricsSnapshot> {
    if !enabled {
        return Ok(SoftirqMetricsSnapshot::default());
    }
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
                timing_buckets: current.timing.buckets.clone(),
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
        latency_buckets: current.latency.buckets.clone(),
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

#[derive(Clone, Copy, Debug, Default)]
struct RawPerCpuStat {
    total_ticks: u64,
    steal_ticks: u64,
}

fn parse_per_cpu_stat(contents: &str) -> std::result::Result<Vec<RawPerCpuStat>, String> {
    let mut cpus = Vec::new();
    for line in contents.lines() {
        let mut fields = line.split_whitespace();
        let Some(name) = fields.next() else {
            continue;
        };
        let Some(cpu) = name
            .strip_prefix("cpu")
            .filter(|suffix| !suffix.is_empty())
            .and_then(|suffix| suffix.parse::<usize>().ok())
        else {
            continue;
        };
        let counters = fields
            .take(8)
            .map(|value| {
                value
                    .parse::<u64>()
                    .map_err(|error| format!("invalid {name} counter `{value}`: {error}"))
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if counters.len() < 8 {
            return Err(format!("{name} has fewer than eight CPU counters"));
        }
        cpus.resize(cpus.len().max(cpu + 1), RawPerCpuStat::default());
        cpus[cpu] = RawPerCpuStat {
            total_ticks: counters.iter().copied().fold(0_u64, u64::saturating_add),
            steal_ticks: counters[7],
        };
    }
    (!cpus.is_empty())
        .then_some(cpus)
        .ok_or_else(|| "no per-CPU counters in /proc/stat".to_owned())
}

fn read_per_cpu_stat() -> std::result::Result<Vec<RawPerCpuStat>, String> {
    let contents =
        fs::read_to_string("/proc/stat").map_err(|error| format!("reading /proc/stat: {error}"))?;
    parse_per_cpu_stat(&contents)
}

fn build_steal_utilization(current: &[RawPerCpuStat], previous: &[RawPerCpuStat]) -> Vec<f64> {
    current
        .iter()
        .enumerate()
        .map(|(cpu, current)| {
            let previous = previous.get(cpu).copied().unwrap_or_default();
            let total = current.total_ticks.saturating_sub(previous.total_ticks);
            if total == 0 {
                0.0
            } else {
                (current.steal_ticks.saturating_sub(previous.steal_ticks) as f64 / total as f64
                    * 100.0)
                    .clamp(0.0, 100.0)
            }
        })
        .collect()
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
                timing_buckets: metric.timing.buckets.clone(),
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

fn read_callback_timings(skel: &BpfSkel<'_>, enabled: bool) -> Result<Vec<CallbackTimingCounters>> {
    if !enabled {
        return Ok(Vec::new());
    }
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

fn sum_percpu_u64(values: &[Vec<u8>]) -> Result<u64> {
    values.iter().try_fold(0_u64, |total, value| {
        if value.len() < 8 {
            bail!("short per-CPU migration failure counter");
        }
        Ok(total.saturating_add(u64::from_ne_bytes(value[..8].try_into()?)))
    })
}

fn read_migration_failures(skel: &BpfSkel<'_>) -> Result<u64> {
    let values = skel
        .maps
        .migration_failures
        .lookup_percpu(&0_u32.to_ne_bytes(), MapFlags::ANY)?
        .context("migration failure counter missing")?;
    sum_percpu_u64(&values)
}

fn read_cpu_runtime(skel: &BpfSkel<'_>) -> Result<CpuRuntimeSnapshot> {
    let key = 0_u32.to_ne_bytes();
    let values = skel
        .maps
        .cpu_runtime
        .lookup_percpu(&key, MapFlags::ANY)?
        .context("CPU runtime entry missing")?;
    let now_ns = monotonic_time_ns()?;
    values
        .into_iter()
        .try_fold(CpuRuntimeSnapshot::default(), |mut snapshot, value| {
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
            let rt_stop_ns = u64::from_ne_bytes(
                value
                    .get(24..32)
                    .context("short RT/stop runtime value")?
                    .try_into()?,
            );
            let deadline_ns = u64::from_ne_bytes(
                value
                    .get(32..40)
                    .context("short deadline runtime value")?
                    .try_into()?,
            );
            let current_class = u64::from_ne_bytes(
                value
                    .get(40..48)
                    .context("short current scheduling class value")?
                    .try_into()?,
            );
            snapshot.busy_ns.push(project_cpu_runtime(
                busy_ns,
                last_switch_ns,
                current_busy,
                now_ns,
            ));
            snapshot.rt_stop_ns.push(project_cpu_runtime(
                rt_stop_ns,
                last_switch_ns,
                current_class == 1,
                now_ns,
            ));
            snapshot.deadline_ns.push(project_cpu_runtime(
                deadline_ns,
                last_switch_ns,
                current_class == 2,
                now_ns,
            ));
            Ok(snapshot)
        })
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

    if !available {
        return Ok(DsqMetricsView {
            residence_buckets: vec![0; CALLBACK_TIMING_BUCKETS],
            ..DsqMetricsView::default()
        });
    }
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
        residence_buckets: residence.buckets,
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

enum SessionExit {
    IdentityChanged,
    Reset(ResetRequest),
    Shutdown,
}

struct PendingReset {
    request: ResetRequest,
    identity: SchedulerIdentity,
}

fn fail_reset(pending: &mut Option<PendingReset>, message: &str) {
    if let Some(pending) = pending.take() {
        let _ = pending.request.reply.send(Err(message.to_string()));
    }
}

fn context_identity(context: &ObserverContext) -> Option<SchedulerIdentity> {
    Some(SchedulerIdentity {
        name: context.scheduler_name.clone()?,
        enable_seq: context.scheduler_enable_seq?,
    })
}

fn set_identity(context: &mut ObserverContext, identity: Option<&SchedulerIdentity>) {
    context.scheduler_name = identity.map(|identity| identity.name.clone());
    context.scheduler_enable_seq = identity.map(|identity| identity.enable_seq);
}

fn advance_epoch(context: &mut ObserverContext) -> Result<()> {
    context.epoch = context
        .epoch
        .checked_add(1)
        .context("collector epoch exhausted")?;
    Ok(())
}

fn wait_inactive(
    commands: &Receiver<CollectorCommand>,
    shutdown: &AtomicBool,
    context: &ObserverContext,
    duration: Duration,
    expected: Option<&SchedulerIdentity>,
) -> bool {
    let deadline = Instant::now() + duration;
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return true;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        match commands.recv_timeout(remaining.min(Duration::from_secs(1))) {
            Ok(CollectorCommand::Shutdown) | Err(RecvTimeoutError::Disconnected) => return true,
            Ok(CollectorCommand::Reset(request)) => {
                let message = request
                    .validate(context, Instant::now())
                    .err()
                    .unwrap_or_else(|| "collector attachment is unavailable".into());
                let _ = request.reply.send(Err(message));
            }
            Err(RecvTimeoutError::Timeout) => {}
        }
        if let Ok(identity) = read_scheduler_identity() {
            if identity.as_ref() != expected {
                return false;
            }
        }
    }
}

pub fn run(
    state: Arc<RwLock<Snapshot>>,
    migration_history: Arc<RwLock<MigrationHistory>>,
    observer: SharedObserverContext,
    scheduler_config: Arc<RwLock<SchedulerConfigSnapshot>>,
    shutdown: Arc<AtomicBool>,
    commands: Receiver<CollectorCommand>,
    config: CollectorConfig,
) -> Result<()> {
    let mut context = observer.read().expect("observer lock poisoned").clone();
    let mut pending_reset = None;
    let mut backoff = RetryBackoff::default();

    while !shutdown.load(Ordering::Relaxed) {
        let identity = match read_scheduler_identity() {
            Ok(Some(identity)) => identity,
            Ok(None) => {
                fail_reset(&mut pending_reset, "scheduler changed while resetting");
                if context.status != CollectorStatus::Waiting
                    || context_identity(&context).is_some()
                {
                    advance_epoch(&mut context)?;
                    context.status = CollectorStatus::Waiting;
                    context.error = None;
                    set_identity(&mut context, None);
                    *scheduler_config
                        .write()
                        .expect("scheduler config lock poisoned") =
                        SchedulerConfigSnapshot::default();
                    publish_context(
                        &state,
                        &migration_history,
                        &observer,
                        context.clone(),
                        config,
                    );
                }
                backoff.reset();
                if wait_inactive(&commands, &shutdown, &context, Duration::from_secs(1), None) {
                    break;
                }
                continue;
            }
            Err(error) => {
                fail_reset(
                    &mut pending_reset,
                    &format!("scheduler identity read failed: {error:#}"),
                );
                if state
                    .read()
                    .expect("snapshot lock poisoned")
                    .meta
                    .captured_at_unix_ms
                    .is_some()
                {
                    advance_epoch(&mut context)?;
                }
                context.status = CollectorStatus::Error;
                context.error = Some(format!("scheduler identity read failed: {error:#}"));
                *scheduler_config
                    .write()
                    .expect("scheduler config lock poisoned") = SchedulerConfigSnapshot::default();
                publish_context(
                    &state,
                    &migration_history,
                    &observer,
                    context.clone(),
                    config,
                );
                if wait_inactive(
                    &commands,
                    &shutdown,
                    &context,
                    backoff.next_delay(),
                    context_identity(&context).as_ref(),
                ) {
                    break;
                }
                continue;
            }
        };
        if context_identity(&context).as_ref() != Some(&identity) {
            fail_reset(&mut pending_reset, "scheduler changed while resetting");
            advance_epoch(&mut context)?;
            set_identity(&mut context, Some(&identity));
            backoff.reset();
        }
        context.status = if pending_reset.is_some() {
            CollectorStatus::Resetting
        } else {
            CollectorStatus::Attaching
        };
        context.error = None;
        publish_context(
            &state,
            &migration_history,
            &observer,
            context.clone(),
            config,
        );

        // All skeletons, target FDs and links live on this stack. Returning drops
        // every probe/map before the next scheduler generation or reset is loaded.
        match run_attachment_session(
            &state,
            &migration_history,
            &observer,
            &scheduler_config,
            &shutdown,
            &commands,
            &identity,
            &context,
            &mut pending_reset,
            &mut backoff,
            config,
        ) {
            Ok(SessionExit::Shutdown) => break,
            Ok(SessionExit::IdentityChanged) => {
                fail_reset(&mut pending_reset, "scheduler changed while resetting");
                advance_epoch(&mut context)?;
                set_identity(&mut context, None);
                context.status = CollectorStatus::Waiting;
                context.error = None;
                *scheduler_config
                    .write()
                    .expect("scheduler config lock poisoned") = SchedulerConfigSnapshot::default();
                publish_context(
                    &state,
                    &migration_history,
                    &observer,
                    context.clone(),
                    config,
                );
                backoff.reset();
            }
            Ok(SessionExit::Reset(request)) => {
                // The session's links/maps were dropped before advertising reset.
                advance_epoch(&mut context)?;
                context.status = CollectorStatus::Resetting;
                context.error = None;
                *scheduler_config
                    .write()
                    .expect("scheduler config lock poisoned") = SchedulerConfigSnapshot::default();
                publish_context(
                    &state,
                    &migration_history,
                    &observer,
                    context.clone(),
                    config,
                );
                pending_reset = Some(PendingReset { request, identity });
                backoff.reset();
            }
            Err(error) => {
                let message = format!("collector attachment failed: {error:#}");
                fail_reset(&mut pending_reset, &message);
                if state
                    .read()
                    .expect("snapshot lock poisoned")
                    .meta
                    .captured_at_unix_ms
                    .is_some()
                {
                    advance_epoch(&mut context)?;
                }
                context.status = CollectorStatus::Error;
                context.error = Some(message.clone());
                *scheduler_config
                    .write()
                    .expect("scheduler config lock poisoned") = SchedulerConfigSnapshot::default();
                publish_context(
                    &state,
                    &migration_history,
                    &observer,
                    context.clone(),
                    config,
                );
                eprintln!("{message}");
                if wait_inactive(
                    &commands,
                    &shutdown,
                    &context,
                    backoff.next_delay(),
                    Some(&identity),
                ) {
                    break;
                }
            }
        }
    }
    fail_reset(&mut pending_reset, "inspector shutting down");
    while let Ok(command) = commands.try_recv() {
        if let CollectorCommand::Reset(request) = command {
            let _ = request.reply.send(Err("inspector shutting down".into()));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn run_attachment_session(
    state: &Arc<RwLock<Snapshot>>,
    migration_history: &Arc<RwLock<MigrationHistory>>,
    observer: &SharedObserverContext,
    scheduler_config: &Arc<RwLock<SchedulerConfigSnapshot>>,
    shutdown: &AtomicBool,
    commands: &Receiver<CollectorCommand>,
    identity: &SchedulerIdentity,
    context: &ObserverContext,
    pending_reset: &mut Option<PendingReset>,
    backoff: &mut RetryBackoff,
    config: CollectorConfig,
) -> Result<SessionExit> {
    if read_scheduler_identity()?.as_ref() != Some(identity) {
        return Ok(SessionExit::IdentityChanged);
    }
    if let Some(pending) = pending_reset {
        if pending.identity != *identity {
            bail!("scheduler changed while resetting");
        }
        pending
            .request
            .check_deadline(Instant::now())
            .map_err(anyhow::Error::msg)?;
    }
    let targets = find_targets()?;
    let target_program_ids = targets.each_ref().map(|target| target.id);
    let existing_program_ids = ProgInfoIter::default()
        .map(|program| program.id)
        .collect::<HashSet<_>>();

    let mut open_object = MaybeUninit::<OpenObject>::uninit();
    let mut open_skel = BpfSkelBuilder::default()
        .open(&mut open_object)
        .context("opening callback collector BPF object")?;
    set_targets(&mut open_skel, &targets).context("setting callback attach targets")?;
    let (block_io_supported, hardirq_supported) =
        configure_optional_probes(&mut open_skel, config)?;
    let rodata = open_skel
        .maps
        .rodata_data
        .as_mut()
        .context("callback collector rodata is unavailable")?;
    rodata.callback_timing_sample_rate = config.callback_timing_sample_rate;
    rodata.event_timing_sample_rate = config.event_timing_sample_rate;
    let map_capacity =
        migration_map_capacity(libbpf_rs::num_possible_cpus().context("counting possible CPUs")?);
    open_skel
        .maps
        .migration_counts
        .set_max_entries(map_capacity)
        .context("sizing migration map")?;
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

    if read_scheduler_identity()?.as_ref() != Some(identity) {
        return Ok(SessionExit::IdentityChanged);
    }
    if shutdown.load(Ordering::Relaxed) {
        return Ok(SessionExit::Shutdown);
    }
    let started = Instant::now();
    let mut previous = read_counts(&skel)?;
    let mut previous_scheduler_events =
        read_scheduler_events(&skel, config.enable_scheduler_events)?;
    let mut previous_softirqs = read_softirq_metrics(&skel, config.enable_irqs)?;
    let mut previous_block_io = read_block_io_metrics(&skel, block_io_available)?;
    let mut previous_hardirqs = read_hardirq_metrics(&skel, hardirq_available)?;
    let irq_names = read_irq_names();
    let callback_timings = read_callback_timings(&skel, config.callback_timing_sample_rate > 0)?;
    let wakeup_latency = read_wakeup_latency(&skel)?;
    let cpu_slice_duration = read_cpu_slice_duration(&skel)?;
    let blocked_duration = read_blocked_duration(&skel)?;
    let migrations = read_migrations(&skel)?;
    let migration_failures = read_migration_failures(&skel)?;
    let mut previous_cpu_runtime = read_cpu_runtime(&skel)?;
    let mut previous_cpu_stat = read_per_cpu_stat().unwrap_or_default();
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
    let discovered_config = crate::scheduler_config::discover();
    if read_scheduler_identity()?.as_ref() != Some(identity) {
        return Ok(SessionExit::IdentityChanged);
    }
    if shutdown.load(Ordering::Relaxed) {
        return Ok(SessionExit::Shutdown);
    }
    if let Some(pending) = pending_reset {
        pending
            .request
            .check_deadline(Instant::now())
            .map_err(anyhow::Error::msg)?;
    }
    let mut active_context = context.clone();
    active_context.status = CollectorStatus::Active;
    active_context.error = None;
    let captured_at = unix_ms();
    let mut sample_meta = SampleMeta {
        epoch: context.epoch,
        sample_seq: 1,
        captured_at_unix_ms: Some(captured_at),
        last_success_at_unix_ms: Some(captured_at),
        error: None,
    };
    let snapshot = Snapshot {
        meta: sample_meta.clone(),
        collector: active_context.clone(),
        migration_map_capacity: map_capacity,
        migration_map_failures: migration_failures,
        migration_quality: if migration_failures > 0 {
            "incomplete"
        } else {
            "complete"
        },
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
            &previous_cpu_runtime.busy_ns,
            &previous_cpu_runtime.busy_ns,
            Duration::ZERO,
        ),
        cpu_capacity_loss: build_cpu_capacity_loss_rows(
            &previous_cpu_runtime.rt_stop_ns,
            &previous_cpu_runtime.rt_stop_ns,
            &previous_cpu_runtime.deadline_ns,
            &previous_cpu_runtime.deadline_ns,
            &vec![0.0; previous_cpu_runtime.busy_ns.len()],
            Duration::ZERO,
        ),
        bpf_program_stats,
        inspector_bpf_program_stats,
        inspector_bpf_cpu_equivalent_pct: None,
        inspector_bpf_host_capacity_pct: None,
        dsq_metrics,
        scheduler_events: if config.enable_scheduler_events {
            build_scheduler_event_rows(
                previous_scheduler_events,
                previous_scheduler_events,
                Duration::ZERO,
            )
        } else {
            Vec::new()
        },
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
    *scheduler_config
        .write()
        .expect("scheduler config lock poisoned") = discovered_config;
    if read_scheduler_identity()?.as_ref() != Some(identity) {
        return Ok(SessionExit::IdentityChanged);
    }
    publish_sample_inner(
        state,
        migration_history,
        observer,
        snapshot,
        0,
        Some(pending_reset),
    )?;
    backoff.reset();

    while !shutdown.load(Ordering::Relaxed) {
        match commands.recv_timeout(Duration::from_secs(1)) {
            Ok(CollectorCommand::Shutdown) | Err(RecvTimeoutError::Disconnected) => {
                return Ok(SessionExit::Shutdown)
            }
            Ok(CollectorCommand::Reset(request)) => {
                if let Err(message) = request.validate(&active_context, Instant::now()) {
                    let _ = request.reply.send(Err(message));
                    continue;
                }
                if read_scheduler_identity()?.as_ref() != Some(identity) {
                    let _ = request
                        .reply
                        .send(Err("scheduler changed before reset".into()));
                    return Ok(SessionExit::IdentityChanged);
                }
                request
                    .check_deadline(Instant::now())
                    .map_err(anyhow::Error::msg)?;
                return Ok(SessionExit::Reset(request));
            }
            Err(RecvTimeoutError::Timeout) => {}
        }
        if shutdown.load(Ordering::Relaxed) {
            return Ok(SessionExit::Shutdown);
        }
        if read_scheduler_identity()?.as_ref() != Some(identity) {
            return Ok(SessionExit::IdentityChanged);
        }
        let now = Instant::now();
        let current = read_counts(&skel)?;
        let current_scheduler_events =
            read_scheduler_events(&skel, config.enable_scheduler_events)?;
        let current_softirqs = read_softirq_metrics(&skel, config.enable_irqs)?;
        let current_block_io = read_block_io_metrics(&skel, block_io_available)?;
        let current_hardirqs = read_hardirq_metrics(&skel, hardirq_available)?;
        let callback_timings =
            read_callback_timings(&skel, config.callback_timing_sample_rate > 0)?;
        let wakeup_latency = read_wakeup_latency(&skel)?;
        let cpu_slice_duration = read_cpu_slice_duration(&skel)?;
        let blocked_duration = read_blocked_duration(&skel)?;
        let migrations = read_migrations(&skel)?;
        let migration_failures = read_migration_failures(&skel)?;
        let current_cpu_runtime = read_cpu_runtime(&skel)?;
        let current_cpu_stat = read_per_cpu_stat().unwrap_or_else(|_| previous_cpu_stat.clone());
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
        let mut snapshot = state.read().expect("snapshot lock poisoned").clone();
        snapshot.uptime_seconds = started.elapsed().as_secs();
        snapshot.counters = counters;
        snapshot.callback_timings = build_callback_timing_rows(&callback_timings);
        snapshot.scheduler_timings = vec![
            build_timing_metric_row("wakeup_to_running", &wakeup_latency),
            build_timing_metric_row("on_cpu_slice", &cpu_slice_duration),
            build_timing_metric_row("blocked_off_cpu", &blocked_duration),
        ];
        snapshot.migrations = migrations;
        snapshot.cpu_runtime = build_cpu_runtime_rows(
            &current_cpu_runtime.busy_ns,
            &previous_cpu_runtime.busy_ns,
            elapsed,
        );
        let steal_utilization = if previous_cpu_stat.is_empty() {
            vec![0.0; current_cpu_stat.len()]
        } else {
            build_steal_utilization(&current_cpu_stat, &previous_cpu_stat)
        };
        snapshot.cpu_capacity_loss = build_cpu_capacity_loss_rows(
            &current_cpu_runtime.rt_stop_ns,
            &previous_cpu_runtime.rt_stop_ns,
            &current_cpu_runtime.deadline_ns,
            &previous_cpu_runtime.deadline_ns,
            &steal_utilization,
            elapsed,
        );
        previous_cpu_runtime = current_cpu_runtime;
        previous_cpu_stat = current_cpu_stat;
        snapshot.bpf_program_stats = bpf_program_stats;
        snapshot.inspector_bpf_program_stats = inspector_bpf_program_stats;
        snapshot.inspector_bpf_cpu_equivalent_pct = inspector_cpu_equivalent_pct;
        snapshot.inspector_bpf_host_capacity_pct = inspector_cpu_equivalent_pct
            .map(|percentage| percentage / previous_cpu_runtime.busy_ns.len().max(1) as f64);
        previous_inspector_runtime_ns = inspector_runtime_ns;
        snapshot.dsq_metrics = dsq_metrics;
        snapshot.scheduler_events = if config.enable_scheduler_events {
            build_scheduler_event_rows(current_scheduler_events, previous_scheduler_events, elapsed)
        } else {
            Vec::new()
        };
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
        if read_scheduler_identity()?.as_ref() != Some(identity) {
            return Ok(SessionExit::IdentityChanged);
        }
        if shutdown.load(Ordering::Relaxed) {
            return Ok(SessionExit::Shutdown);
        }
        let captured_at = unix_ms();
        sample_meta.sample_seq = sample_meta
            .sample_seq
            .checked_add(1)
            .context("collector sample sequence exhausted")?;
        sample_meta.captured_at_unix_ms = Some(captured_at);
        sample_meta.last_success_at_unix_ms = Some(captured_at);
        snapshot.meta = sample_meta.clone();
        snapshot.collector = active_context.clone();
        snapshot.migration_map_failures = migration_failures;
        snapshot.migration_quality = if migration_failures > 0 {
            "incomplete"
        } else {
            "complete"
        };
        publish_sample(
            state,
            migration_history,
            observer,
            snapshot,
            u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        )?;
        backoff.reset();
    }
    Ok(SessionExit::Shutdown)
}

#[cfg(test)]
mod tests {
    use super::{
        build_steal_utilization, migration_map_capacity, parse_irq_names, parse_per_cpu_stat,
    };

    #[test]
    fn replay_projection_preserves_all_counter_fields_without_allocating_migrations() {
        let mut snapshot = super::Snapshot::empty(super::CollectorConfig {
            callback_timing_sample_rate: 1024,
            event_timing_sample_rate: 64,
            enable_dsq: true,
            enable_scheduler_events: true,
            enable_irqs: true,
            enable_block_io: true,
        });
        snapshot.migrations.push(crate::MigrationRow {
            from_cpu: 1,
            to_cpu: 2,
            count: 99,
        });
        let projected = snapshot.compact_clone_without_migrations();
        let mut expected = serde_json::to_value(&snapshot).unwrap();
        expected["migrations"] = serde_json::json!([]);
        assert_eq!(serde_json::to_value(&projected).unwrap(), expected);
        assert_eq!(projected.migrations.capacity(), 0);
        assert_eq!(snapshot.migrations.len(), 1);
    }

    #[test]
    fn migration_map_retains_all_possible_pairs_until_the_memory_cap() {
        assert_eq!(migration_map_capacity(160), 25_600);
        assert_eq!(migration_map_capacity(1024), 1_048_576);
        assert_eq!(migration_map_capacity(4096), 1_048_576);
        assert_eq!(migration_map_capacity(usize::MAX), 1_048_576);
        assert_eq!(migration_map_capacity(1), 1);
        assert_eq!(migration_map_capacity(0), 1);
    }

    #[test]
    fn native_migration_observer_handles_origin_races_and_map_exhaustion() {
        let executable =
            std::env::temp_dir().join(format!("mitosis-migration-test-{}", std::process::id()));
        let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/migration_observer_test.c");
        let compilation = std::process::Command::new("cc")
            .args(["-std=c11", "-Wall", "-Wextra"])
            .arg(source)
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            compilation.status.success(),
            "{}",
            String::from_utf8_lossy(&compilation.stderr)
        );
        let result = std::process::Command::new(&executable).output().unwrap();
        let _ = std::fs::remove_file(executable);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }

    #[test]
    fn native_task_timing_excludes_idle_running_wakeups_and_preempted_blocking() {
        let executable =
            std::env::temp_dir().join(format!("mitosis-task-timing-test-{}", std::process::id()));
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let compilation = std::process::Command::new("cc")
            .args(["-std=gnu11", "-Wall", "-Wextra", "-Wno-unused-parameter"])
            .arg("-I")
            .arg(root.join("tests/native_bpf_stubs"))
            .arg(root.join("tests/task_timing_observer_test.c"))
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            compilation.status.success(),
            "{}",
            String::from_utf8_lossy(&compilation.stderr)
        );
        for case in [
            "idle",
            "wakeup",
            "preempt",
            "blocked",
            "switch_bins",
            "runtime",
            "buckets",
        ] {
            let result = std::process::Command::new(&executable)
                .arg(case)
                .output()
                .unwrap();
            assert!(
                result.status.success(),
                "{case}: {}",
                String::from_utf8_lossy(&result.stderr)
            );
        }
        let _ = std::fs::remove_file(executable);
    }

    #[test]
    #[ignore = "Manual native CoreCollector smoke requires BPF observation privileges and an already-running Mitosis scheduler"]
    fn native_disabled_optional_groups_collect_initial_and_poll() {
        use super::*;

        let identity = read_scheduler_identity()
            .unwrap()
            .expect("native smoke requires an already-running Mitosis scheduler");
        let config = CollectorConfig {
            callback_timing_sample_rate: 0,
            event_timing_sample_rate: 0,
            enable_dsq: false,
            enable_scheduler_events: false,
            enable_irqs: false,
            enable_block_io: false,
        };
        let context = ObserverContext {
            epoch: 1,
            status: CollectorStatus::Attaching,
            scheduler_enable_seq: Some(identity.enable_seq),
            scheduler_name: Some(identity.name.clone()),
            error: None,
        };
        let state = Arc::new(RwLock::new(Snapshot::empty(config)));
        let history = Arc::new(RwLock::new(MigrationHistory::new(10_000)));
        let observer = Arc::new(RwLock::new(context.clone()));
        let scheduler_config = Arc::new(RwLock::new(SchedulerConfigSnapshot::default()));
        let shutdown = Arc::new(AtomicBool::new(false));
        let (commands, receiver) = std::sync::mpsc::channel();
        let session_state = state.clone();
        let session_shutdown = shutdown.clone();
        let session_identity = identity.clone();
        let worker = std::thread::spawn(move || {
            run_attachment_session(
                &session_state,
                &history,
                &observer,
                &scheduler_config,
                &session_shutdown,
                &receiver,
                &session_identity,
                &context,
                &mut None,
                &mut RetryBackoff::default(),
                config,
            )
        });
        let deadline = Instant::now() + Duration::from_secs(8);
        let mut samples = Vec::new();
        while Instant::now() < deadline && !worker.is_finished() {
            let sample = state.read().unwrap().clone();
            if sample.meta.sample_seq
                > samples
                    .last()
                    .map_or(0, |previous: &Snapshot| previous.meta.sample_seq)
            {
                println!("native CoreCollector sample_seq={}", sample.meta.sample_seq);
                samples.push(sample);
            }
            if samples
                .last()
                .is_some_and(|sample| sample.meta.sample_seq >= 2)
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        // Teardown precedes assertions, including timeout/error assertions.
        let _ = commands.send(CollectorCommand::Shutdown);
        shutdown.store(true, Ordering::Relaxed);
        let result = worker.join().expect("native CoreCollector panicked");
        assert!(
            result.is_ok(),
            "native CoreCollector failed: {:?}",
            result.err()
        );
        assert_eq!(
            samples.first().map(|sample| sample.meta.sample_seq),
            Some(1)
        );
        assert!(samples
            .last()
            .is_some_and(|sample| sample.meta.sample_seq >= 2));
        assert_eq!(read_scheduler_identity().unwrap(), Some(identity));
        for sample in samples {
            assert_eq!(sample.collector.status, CollectorStatus::Active);
            assert_eq!(sample.counters.len(), 5);
            assert!(!sample.cpu_runtime.is_empty());
            assert!(!sample.dsq_metrics.available);
            assert_eq!(sample.dsq_metrics.insert_count, 0);
            assert_eq!(sample.dsq_metrics.move_count, 0);
            assert_eq!(sample.dsq_metrics.residence_samples, 0);
            assert_eq!(sample.dsq_metrics.residence_buckets, vec![0; 64]);
            assert!(sample.dsq_metrics.residence_mean_ns.is_none());
            assert!(sample.dsq_metrics.depth_average.is_none());
            assert!(sample.scheduler_events.is_empty());
            assert!(sample.callback_timings.is_empty());
            assert!(sample.softirqs.is_empty());
            assert!(sample.hardirqs.rows.is_empty());
            assert!(!sample.hardirqs.available);
            assert!(!sample.block_io.available);
        }
    }

    #[test]
    fn enabled_probe_configuration_keeps_the_core_counts_and_runtime_dependencies() {
        use super::*;

        let mut object = MaybeUninit::<OpenObject>::uninit();
        let mut skel = BpfSkelBuilder::default().open(&mut object).unwrap();
        let config = test_config();
        configure_optional_probes(&mut skel, config).unwrap();
        for program in skel.open_object().progs().filter(|program| {
            matches!(
                program.name().to_str(),
                Some(
                    "observe_select_cpu"
                        | "observe_enqueue"
                        | "observe_dispatch"
                        | "observe_running"
                        | "observe_stopping"
                        | "on_sched_switch"
                        | "on_sched_migrate_task"
                )
            )
        }) {
            assert!(program.autoload(), "{:?}", program.name());
        }
        for map in skel.open_object().maps().filter(|map| {
            matches!(
                map.name().to_str(),
                Some(
                    "callback_counts"
                        | "callback_timing_starts"
                        | "cpu_runtime"
                        | "migration_counts"
                        | "migration_failures"
                        | "task_observations"
                        | "wakeup_latency"
                        | "cpu_slice_duration"
                        | "blocked_duration"
                )
            )
        }) {
            assert!(map.autocreate(), "{:?}", map.name());
        }
    }

    fn inspect_probe_configuration(
        config: super::CollectorConfig,
        check: impl FnOnce(&crate::bpf_skel::OpenBpfSkel<'_>, bool, bool),
    ) {
        use super::*;

        let mut object = MaybeUninit::<OpenObject>::uninit();
        let mut skel = BpfSkelBuilder::default().open(&mut object).unwrap();
        let (block_io, hardirq) = configure_optional_probes(&mut skel, config).unwrap();
        check(&skel, block_io, hardirq);
    }

    fn assert_probe_group_flags(
        skel: &crate::bpf_skel::OpenBpfSkel<'_>,
        program_prefix: &str,
        map_prefix: &str,
        enabled: bool,
    ) {
        use libbpf_rs::skel::OpenSkel;

        let programs: Vec<_> = skel
            .open_object()
            .progs()
            .filter(|program| program.name().to_string_lossy().starts_with(program_prefix))
            .collect();
        assert!(!programs.is_empty(), "missing {program_prefix} programs");
        for program in programs {
            assert_eq!(program.autoload(), enabled, "{:?}", program.name());
        }
        let maps: Vec<_> = skel
            .open_object()
            .maps()
            .filter(|map| map.name().to_string_lossy().starts_with(map_prefix))
            .collect();
        assert!(!maps.is_empty(), "missing {map_prefix} maps");
        for map in maps {
            assert_eq!(map.autocreate(), enabled, "{:?}", map.name());
        }
    }

    #[test]
    fn disabled_dsq_probes_skip_program_load_and_map_creation() {
        let config = super::CollectorConfig {
            enable_dsq: false,
            ..test_config()
        };
        inspect_probe_configuration(config, |skel, _, _| {
            assert_probe_group_flags(skel, "dsqo_", "dsq_", false);
        });
    }

    #[test]
    fn disabled_scheduler_activity_skips_program_load_and_map_creation() {
        let config = super::CollectorConfig {
            enable_scheduler_events: false,
            ..test_config()
        };
        inspect_probe_configuration(config, |skel, _, _| {
            assert_probe_group_flags(skel, "scheduler_event_", "scheduler_event_", false);
        });
    }

    #[test]
    fn disabled_softirqs_skip_program_load_and_map_creation() {
        let config = super::CollectorConfig {
            enable_irqs: false,
            ..test_config()
        };
        inspect_probe_configuration(config, |skel, _, _| {
            assert_probe_group_flags(skel, "sirqo_", "softirq_", false);
        });
    }

    #[test]
    fn disabled_hardirqs_omit_the_per_cpu_histogram_maps() {
        let config = super::CollectorConfig {
            enable_irqs: false,
            ..test_config()
        };
        inspect_probe_configuration(config, |skel, _, supported| {
            assert!(!supported);
            assert_probe_group_flags(skel, "hirqo_", "hardirq_", false);
        });
    }

    #[test]
    fn disabled_block_io_omits_the_request_tracking_and_histogram_maps() {
        let config = super::CollectorConfig {
            enable_block_io: false,
            ..test_config()
        };
        inspect_probe_configuration(config, |skel, supported, _| {
            assert!(!supported);
            assert_probe_group_flags(skel, "block_io_observer_", "block_io_", false);
        });
    }

    #[test]
    fn disabled_callback_timing_omits_exits_and_keeps_counter_dependencies() {
        let config = super::CollectorConfig {
            callback_timing_sample_rate: 0,
            ..test_config()
        };
        inspect_probe_configuration(config, |skel, _, _| {
            assert!(!skel.progs.observe_select_cpu_exit.autoload());
            assert!(!skel.progs.observe_enqueue_exit.autoload());
            assert!(!skel.progs.observe_dispatch_exit.autoload());
            assert!(!skel.progs.observe_running_exit.autoload());
            assert!(!skel.progs.observe_stopping_exit.autoload());
            assert!(!skel.maps.callback_timings.autocreate());
            assert!(skel.progs.observe_enqueue.autoload());
            assert!(skel.maps.callback_counts.autocreate());
            assert!(skel.maps.callback_timing_starts.autocreate());
        });
    }

    #[test]
    fn disabled_event_timing_keeps_runtime_and_omits_wakeup_programs() {
        let config = super::CollectorConfig {
            event_timing_sample_rate: 0,
            ..test_config()
        };
        inspect_probe_configuration(config, |skel, _, _| {
            assert!(!skel.progs.on_sched_wakeup.autoload());
            assert!(!skel.progs.on_sched_wakeup_new.autoload());
            assert!(skel.progs.on_sched_switch.autoload());
            assert!(skel.maps.cpu_runtime.autocreate());
            assert!(skel.maps.task_observations.autocreate());
            assert!(skel.maps.cpu_slice_duration.autocreate());
        });
    }

    #[test]
    fn independent_probe_switches_preserve_all_loaded_map_dependencies() {
        for bits in 0..64 {
            let config = super::CollectorConfig {
                enable_dsq: bits & 1 != 0,
                enable_scheduler_events: bits & 2 != 0,
                enable_irqs: bits & 4 != 0,
                enable_block_io: bits & 8 != 0,
                callback_timing_sample_rate: u32::from(bits & 16 != 0),
                event_timing_sample_rate: u32::from(bits & 32 != 0),
            };
            inspect_probe_configuration(config, |skel, block_io, hardirq| {
                assert_probe_group_flags(skel, "dsqo_", "dsq_", config.enable_dsq);
                assert_probe_group_flags(
                    skel,
                    "scheduler_event_",
                    "scheduler_event_",
                    config.enable_scheduler_events,
                );
                assert_probe_group_flags(skel, "sirqo_", "softirq_", config.enable_irqs);
                assert_probe_group_flags(skel, "hirqo_", "hardirq_", hardirq);
                assert_probe_group_flags(skel, "block_io_observer_", "block_io_", block_io);
                assert_eq!(
                    skel.progs.observe_enqueue_exit.autoload(),
                    config.callback_timing_sample_rate > 0,
                );
                assert_eq!(
                    skel.maps.callback_timings.autocreate(),
                    config.callback_timing_sample_rate > 0,
                );
                assert_eq!(
                    skel.progs.on_sched_wakeup.autoload(),
                    config.event_timing_sample_rate > 0,
                );
                assert!(skel.progs.observe_enqueue.autoload());
                assert!(skel.progs.on_sched_switch.autoload());
                assert!(skel.maps.callback_counts.autocreate());
                assert!(skel.maps.callback_timing_starts.autocreate());
                assert!(skel.maps.cpu_runtime.autocreate());
                assert!(skel.maps.task_observations.autocreate());
                assert!(skel.maps.wakeup_latency.autocreate());
                assert!(skel.maps.cpu_slice_duration.autocreate());
                assert!(skel.maps.blocked_duration.autocreate());
            });
        }
    }

    fn test_config() -> super::CollectorConfig {
        super::CollectorConfig {
            callback_timing_sample_rate: 1,
            event_timing_sample_rate: 1,
            enable_dsq: true,
            enable_scheduler_events: true,
            enable_irqs: true,
            enable_block_io: true,
        }
    }

    #[test]
    fn reset_refuses_stale_expired_inactive_and_abandoned_requests() {
        use super::*;
        let now = Instant::now();
        let mut context = ObserverContext {
            epoch: 7,
            status: CollectorStatus::Active,
            ..ObserverContext::default()
        };
        let (reply, receiver) = oneshot::channel();
        let mut request = ResetRequest {
            expected_epoch: 6,
            deadline: now + Duration::from_secs(15),
            reply,
        };
        assert!(request
            .validate(&context, now)
            .unwrap_err()
            .contains("epoch"));
        request.expected_epoch = 7;
        assert!(request
            .validate(&context, now + Duration::from_secs(15))
            .unwrap_err()
            .contains("expired"));
        context.status = CollectorStatus::Waiting;
        assert!(request.validate(&context, now).is_err());
        context.status = CollectorStatus::Active;
        assert!(request.validate(&context, now).is_ok());
        drop(receiver);
        assert!(request
            .validate(&context, now)
            .unwrap_err()
            .contains("cancel"));
    }

    #[test]
    fn invalidation_clears_counters_and_history_together_and_keeps_last_success() {
        use super::*;
        use crate::migration_history::MigrationHistory;
        let config = test_config();
        let mut snapshot = Snapshot::empty(config);
        snapshot.meta.epoch = 1;
        snapshot.meta.sample_seq = 5;
        snapshot.meta.captured_at_unix_ms = Some(2000);
        snapshot.meta.last_success_at_unix_ms = Some(2000);
        snapshot.migrations = vec![MigrationRow {
            from_cpu: 0,
            to_cpu: 1,
            count: 9,
        }];
        let state = Arc::new(RwLock::new(snapshot));
        let history = Arc::new(RwLock::new(MigrationHistory::new(5000)));
        let observer = Arc::new(RwLock::new(ObserverContext::default()));
        let context = ObserverContext {
            epoch: 2,
            status: CollectorStatus::Error,
            error: Some("map read failed".into()),
            ..ObserverContext::default()
        };
        publish_context(&state, &history, &observer, context.clone(), config);
        let snapshot = state.read().unwrap();
        let view = history.read().unwrap().view(5000).unwrap();
        assert!(snapshot.migrations.is_empty());
        assert_eq!(snapshot.meta.epoch, 2);
        assert_eq!(snapshot.meta.sample_seq, 0);
        assert_eq!(snapshot.meta.captured_at_unix_ms, None);
        assert_eq!(snapshot.meta.last_success_at_unix_ms, Some(2000));
        assert_eq!(snapshot.meta.error.as_deref(), Some("map read failed"));
        assert_eq!(snapshot.meta, view.meta);
        assert_eq!(snapshot.collector, context);
        assert_eq!(*observer.read().unwrap(), context);
    }

    #[test]
    fn reset_receipt_requires_fresh_epoch_publication_and_expired_reset_cannot_commit() {
        use super::*;
        let config = test_config();
        let state = Arc::new(RwLock::new(Snapshot::empty(config)));
        let history = Arc::new(RwLock::new(MigrationHistory::new(5000)));
        let context = ObserverContext {
            epoch: 8,
            status: CollectorStatus::Resetting,
            scheduler_name: Some("mitosis".into()),
            scheduler_enable_seq: Some(5),
            error: None,
        };
        let observer = Arc::new(RwLock::new(context.clone()));
        let identity = SchedulerIdentity {
            name: "mitosis".into(),
            enable_seq: 5,
        };
        let (reply, mut receipt) = oneshot::channel();
        let mut pending = Some(PendingReset {
            identity: identity.clone(),
            request: ResetRequest {
                expected_epoch: 7,
                deadline: Instant::now() + Duration::from_secs(15),
                reply,
            },
        });
        let mut snapshot = Snapshot::empty(config);
        snapshot.collector = context;
        snapshot.collector.status = CollectorStatus::Active;
        snapshot.meta = SampleMeta {
            epoch: 8,
            sample_seq: 1,
            captured_at_unix_ms: Some(2000),
            last_success_at_unix_ms: Some(2000),
            error: None,
        };
        assert!(receipt.try_recv().is_err());
        publish_sample_inner(
            &state,
            &history,
            &observer,
            snapshot.clone(),
            0,
            Some(&mut pending),
        )
        .unwrap();
        let receipt = receipt.try_recv().unwrap().unwrap();
        assert_eq!(receipt.epoch, 8);
        assert_eq!(receipt.sample_seq, 1);
        assert_eq!(receipt.reset_at_unix_ms, 2000);
        assert_eq!(
            state.read().unwrap().meta,
            history.read().unwrap().view(5000).unwrap().meta
        );
        assert!(pending.is_none());

        let (reply, _receipt) = oneshot::channel();
        pending = Some(PendingReset {
            identity,
            request: ResetRequest {
                expected_epoch: 7,
                deadline: Instant::now(),
                reply,
            },
        });
        snapshot.meta.sample_seq = 2;
        assert!(
            publish_sample_inner(&state, &history, &observer, snapshot, 0, Some(&mut pending))
                .unwrap_err()
                .to_string()
                .contains("expired")
        );
        assert_eq!(state.read().unwrap().meta.sample_seq, 1);

        let (reply, _receipt) = oneshot::channel();
        pending = Some(PendingReset {
            identity: SchedulerIdentity {
                name: "mitosis".into(),
                enable_seq: 5,
            },
            request: ResetRequest {
                expected_epoch: 7,
                deadline: Instant::now() + Duration::from_secs(15),
                reply,
            },
        });
        let mut invalid = state.read().unwrap().clone();
        invalid.meta.sample_seq = 2;
        invalid.meta.captured_at_unix_ms = None;
        assert!(
            publish_sample_inner(&state, &history, &observer, invalid, 0, Some(&mut pending))
                .is_err()
        );
        assert_eq!(
            state.read().unwrap().meta.sample_seq,
            1,
            "invalid baseline must not partially publish"
        );
    }

    #[test]
    fn stale_epoch_sample_cannot_overwrite_new_session_or_history() {
        use super::*;
        let config = test_config();
        let state = Arc::new(RwLock::new(Snapshot::empty(config)));
        let history = Arc::new(RwLock::new(MigrationHistory::new(5000)));
        let observer = Arc::new(RwLock::new(ObserverContext {
            epoch: 2,
            ..ObserverContext::default()
        }));
        let mut stale = Snapshot::empty(config);
        stale.meta.epoch = 1;
        assert!(publish_sample(&state, &history, &observer, stale, 0).is_err());
        assert_eq!(state.read().unwrap().meta.epoch, 0);
        assert_eq!(history.read().unwrap().view(5000).unwrap().meta.epoch, 0);
        assert_eq!(observer.read().unwrap().epoch, 2);
    }

    #[test]
    fn failure_counters_aggregate_all_possible_cpus_and_validate_values() {
        let counters = [0_u64, 4, 9, 0, 2].map(|count| count.to_ne_bytes().to_vec());
        assert_eq!(super::sum_percpu_u64(&counters).unwrap(), 15);
        assert!(super::sum_percpu_u64(&[vec![0; 7]]).is_err());
        assert_eq!(
            super::sum_percpu_u64(&[
                u64::MAX.to_ne_bytes().to_vec(),
                1_u64.to_ne_bytes().to_vec()
            ])
            .unwrap(),
            u64::MAX
        );
    }

    #[test]
    fn shutdown_rejects_queued_resets_without_starting_an_attachment() {
        use super::*;
        let config = test_config();
        let (commands, receiver) = std::sync::mpsc::sync_channel(16);
        let (reply, mut receipt) = oneshot::channel();
        commands
            .send(CollectorCommand::Reset(ResetRequest {
                expected_epoch: 0,
                deadline: Instant::now() + Duration::from_secs(15),
                reply,
            }))
            .unwrap();
        run(
            Arc::new(RwLock::new(Snapshot::empty(config))),
            Arc::new(RwLock::new(MigrationHistory::new(5000))),
            Arc::new(RwLock::new(ObserverContext::default())),
            Arc::new(RwLock::new(SchedulerConfigSnapshot::default())),
            Arc::new(AtomicBool::new(true)),
            receiver,
            config,
        )
        .unwrap();
        assert!(receipt
            .try_recv()
            .unwrap()
            .unwrap_err()
            .contains("shutting down"));
    }

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

    #[test]
    fn parses_per_cpu_hypervisor_steal_utilization() {
        let previous = parse_per_cpu_stat(
            "cpu  0 0 0 0 0 0 0 0\ncpu0 10 0 10 70 0 0 0 10\ncpu1 20 0 10 70 0 0 0 0\n",
        )
        .unwrap();
        let current = parse_per_cpu_stat(
            "cpu  0 0 0 0 0 0 0 0\ncpu0 20 0 20 140 0 0 0 20\ncpu1 40 0 20 140 0 0 0 0\n",
        )
        .unwrap();

        assert_eq!(
            build_steal_utilization(&current, &previous),
            vec![10.0, 0.0]
        );
    }
}
