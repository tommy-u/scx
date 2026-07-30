// SPDX-License-Identifier: GPL-2.0-only

mod bpf_intf;
mod bpf_skel;
mod cell_allocation;
mod control;
mod fine_timing;
mod inspection;
mod mask_tables;
mod membership;
mod policy;
mod queue_timing;
mod queue_topology;
mod runtime_policy;
mod stats;
mod task_cells;

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::mem::{size_of, MaybeUninit};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use bpf_skel::*;
use clap::{Parser, ValueEnum};
use control::{SchedulerRequest, SchedulerResponse};
use crossbeam::channel::RecvTimeoutError;
use inspection::{InspectionView, Inspector, SlotPolicy};
use libbpf_rs::{MapCore as _, MapFlags, OpenObject, ProgramInput};
use log::{debug, info, warn};
use mask_tables::{dump_mask_tables, resolve_mask_tables, ResolvedMaskTable};
use membership::MembershipManager;
use policy::{
    CompiledPolicy, CompiledRung, InputSource, Opcode, QueueDispatchSource, QueueEnqueueTarget,
};
use queue_topology::{dump_queue_topology, resolve_host_queue_topology};
use runtime_policy::RuntimePolicy;
use scx_snake::fairness::FairnessMode;
use scx_stats::prelude::*;
use scx_utils::build_id;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::{
    scx_ops_attach, scx_ops_load, scx_ops_open, try_set_rlimit_infinity, uei_exited, uei_report,
    UserExitInfo,
};
use stats::{
    CallbackTimingMetrics, CellMetrics, CpuMetrics, Metrics, RungMetrics, RungTimingMetrics,
};
use task_cells::{ThreadCellAssignment, ThreadCellResponse};

const SCHEDULER_NAME: &str = "scx_snake";
const SLOT_QUIESCENCE_TIMEOUT: Duration = Duration::from_secs(5);
const SLOT_QUIESCENCE_POLL_INTERVAL: Duration = Duration::from_millis(10);
const TIMING_DRAIN_BATCH: usize = 4096;

fn unix_time_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
enum StatsFormat {
    #[default]
    Text,
    Json,
}

#[derive(Debug, Parser)]
#[command(name = SCHEDULER_NAME, version)]
struct Opts {
    /// Queue discipline used after idle-CPU placement misses; VTIME and EEVDF are experimental.
    #[arg(long, value_enum, default_value_t)]
    fairness: FairnessMode,

    /// Sample one in every N callback executions for timing; zero disables timing.
    #[arg(
        long,
        value_parser = parse_callback_timing_sample_rate,
        default_value_t = 64,
        value_name = "N",
        conflicts_with_all = ["update_policy", "dump_compiled_policy", "stats", "monitor", "help_stats", "set_thread_cell", "clear_thread_cell"]
    )]
    callback_timing_sample_rate: u32,

    /// TOML policy to compile and install before attaching the scheduler.
    #[arg(long, value_name = "PATH")]
    policy: Option<PathBuf>,

    /// Atomically replace the policy of the running scheduler.
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with_all = ["policy", "dump_compiled_policy", "stats", "monitor", "help_stats", "set_thread_cell", "clear_thread_cell"]
    )]
    update_policy: Option<PathBuf>,

    /// Assign a live thread to a policy-defined cell.
    #[arg(
        long,
        value_name = "TID:CELL",
        conflicts_with_all = ["policy", "update_policy", "dump_compiled_policy", "stats", "monitor", "help_stats", "clear_thread_cell"]
    )]
    set_thread_cell: Option<ThreadCellAssignment>,

    /// Remove a live thread's cell annotation.
    #[arg(
        long,
        value_name = "TID",
        value_parser = task_cells::parse_tid,
        conflicts_with_all = ["policy", "update_policy", "dump_compiled_policy", "stats", "monitor", "help_stats", "set_thread_cell"]
    )]
    clear_thread_cell: Option<i32>,

    /// Print the lowered mechanical ladder and exit without loading BPF.
    #[arg(long)]
    dump_compiled_policy: bool,

    /// Print in-process statistics at this interval in seconds.
    #[arg(long, value_parser = parse_positive_seconds, value_name = "SECONDS")]
    stats: Option<f64>,

    /// Statistics output format used by --stats and --monitor.
    #[arg(long, value_enum, default_value_t)]
    stats_format: StatsFormat,

    /// Monitor an already-running scheduler without loading BPF.
    #[arg(
        long,
        value_parser = parse_positive_seconds,
        value_name = "SECONDS",
        conflicts_with = "stats"
    )]
    monitor: Option<f64>,

    /// Show descriptions for all exported statistics.
    #[arg(long)]
    help_stats: bool,

    /// Exit debug dump buffer length. Zero selects the kernel default.
    #[arg(long, default_value_t = 0)]
    exit_dump_len: u32,

    /// Enable verbose userspace and libbpf logging.
    #[arg(short = 'v', long)]
    verbose: bool,

    #[command(flatten, next_help_heading = "Libbpf Options")]
    libbpf: LibbpfOpts,
}

#[derive(Debug, Eq, PartialEq)]
enum RunMode {
    HelpStats,
    Monitor(Duration),
    Update(PathBuf),
    SetThreadCell(ThreadCellAssignment),
    ClearThreadCell(i32),
    Dump(PathBuf),
    Launch(PathBuf),
}

fn parse_positive_seconds(value: &str) -> std::result::Result<f64, String> {
    let seconds = value
        .parse::<f64>()
        .map_err(|error| format!("invalid interval `{value}`: {error}"))?;
    if !seconds.is_finite() || seconds <= 0.0 {
        return Err("interval must be a positive finite number".into());
    }
    Ok(seconds)
}

fn parse_callback_timing_sample_rate(value: &str) -> std::result::Result<u32, String> {
    let rate = value
        .parse::<u32>()
        .map_err(|error| format!("invalid callback timing sample rate `{value}`: {error}"))?;
    validate_callback_timing_sample_rate(rate)?;
    Ok(rate)
}

fn validate_callback_timing_sample_rate(rate: u32) -> std::result::Result<(), String> {
    if rate == 0 || (rate.is_power_of_two() && rate <= 4096) {
        return Ok(());
    }
    Err("callback timing sample rate must be zero or a power of two through 4096".into())
}

fn resolve_mode(opts: &Opts) -> Result<RunMode> {
    let special_modes = usize::from(opts.help_stats)
        + usize::from(opts.monitor.is_some())
        + usize::from(opts.update_policy.is_some())
        + usize::from(opts.set_thread_cell.is_some())
        + usize::from(opts.clear_thread_cell.is_some())
        + usize::from(opts.dump_compiled_policy);
    if special_modes > 1 {
        bail!("control, monitoring, update, and dump modes are mutually exclusive");
    }
    if opts.fairness != FairnessMode::Fifo && special_modes != 0 {
        bail!("--fairness is only valid when launching the scheduler");
    }

    if opts.help_stats {
        return Ok(RunMode::HelpStats);
    }
    if let Some(seconds) = opts.monitor {
        return Ok(RunMode::Monitor(Duration::from_secs_f64(seconds)));
    }
    if let Some(path) = opts.update_policy.clone() {
        return Ok(RunMode::Update(path));
    }
    if let Some(assignment) = opts.set_thread_cell {
        return Ok(RunMode::SetThreadCell(assignment));
    }
    if let Some(tid) = opts.clear_thread_cell {
        return Ok(RunMode::ClearThreadCell(tid));
    }

    let policy = opts
        .policy
        .clone()
        .ok_or_else(|| anyhow!("--policy PATH is required when launching or dumping a policy"))?;
    if opts.dump_compiled_policy {
        Ok(RunMode::Dump(policy))
    } else {
        Ok(RunMode::Launch(policy))
    }
}

fn load_policy(path: &PathBuf) -> Result<(String, CompiledPolicy)> {
    let source =
        fs::read_to_string(path).with_context(|| format!("reading policy {}", path.display()))?;
    let compiled = policy::compile_policy(&source)
        .with_context(|| format!("compiling policy {}", path.display()))?;
    Ok((source, compiled))
}

fn encode_rung(rung: CompiledRung) -> bpf_intf::snake_rung {
    bpf_intf::snake_rung {
        opcode: rung.opcode as u32,
        input: rung.input as u32,
        flags: rung.flags,
        reserved: 0,
        data: rung.data,
    }
}

fn encode_ladder(
    policy: &CompiledPolicy,
    generation: u64,
) -> Result<bpf_intf::snake_compiled_ladder> {
    let mut rungs = std::array::from_fn(|_| bpf_intf::snake_rung {
        opcode: 0,
        input: 0,
        flags: 0,
        reserved: 0,
        data: 0,
    });
    for (destination, rung) in rungs.iter_mut().zip(&policy.rungs) {
        *destination = encode_rung(*rung);
    }

    let mut enqueue_rungs = std::array::from_fn(|_| bpf_intf::snake_queue_rung {
        opcode: 0,
        flags: 0,
    });
    let mut dispatch_rungs = std::array::from_fn(|_| bpf_intf::snake_queue_rung {
        opcode: 0,
        flags: 0,
    });
    let (nr_enqueue_rungs, nr_dispatch_rungs) = if let Some(queues) = &policy.queues {
        for (destination, target) in enqueue_rungs.iter_mut().zip(&queues.enqueue) {
            destination.opcode = match target {
                QueueEnqueueTarget::Cell => bpf_intf::snake_enqueue_opcode_SNAKE_ENQUEUE_OP_CELL,
                QueueEnqueueTarget::Affinity => {
                    bpf_intf::snake_enqueue_opcode_SNAKE_ENQUEUE_OP_AFFINITY
                }
            };
        }
        for (destination, source) in dispatch_rungs.iter_mut().zip(&queues.dispatch) {
            destination.opcode = match source {
                QueueDispatchSource::Cell => bpf_intf::snake_dispatch_opcode_SNAKE_DISPATCH_OP_CELL,
                QueueDispatchSource::Affinity => {
                    bpf_intf::snake_dispatch_opcode_SNAKE_DISPATCH_OP_AFFINITY
                }
                QueueDispatchSource::MinVtime => {
                    bpf_intf::snake_dispatch_opcode_SNAKE_DISPATCH_OP_MIN_VTIME
                }
            };
        }
        (
            queues
                .enqueue
                .len()
                .try_into()
                .context("enqueue rung count does not fit the BPF ABI")?,
            queues
                .dispatch
                .len()
                .try_into()
                .context("dispatch rung count does not fit the BPF ABI")?,
        )
    } else {
        (0, 0)
    };

    Ok(bpf_intf::snake_compiled_ladder {
        generation,
        policy_abi_version: bpf_intf::SNAKE_ABI_VERSION,
        nr_rungs: policy
            .rungs
            .len()
            .try_into()
            .context("policy rung count does not fit the BPF ABI")?,
        nr_mask_tables: policy
            .mask_tables
            .len()
            .try_into()
            .context("mask table count does not fit the BPF ABI")?,
        fallback_mode: policy.fallback as u32,
        rungs,
        nr_enqueue_rungs,
        nr_dispatch_rungs,
        enqueue_rungs,
        dispatch_rungs,
    })
}

fn bytes_of<T>(value: &T) -> &[u8] {
    // SAFETY: map updates copy exactly size_of::<T>() bytes before this borrow ends.
    unsafe { std::slice::from_raw_parts(value as *const T as *const u8, std::mem::size_of::<T>()) }
}

#[derive(Debug, Default)]
struct FineTimingAccumulator {
    sessions: [Option<u64>; 3],
    active: [bool; 3],
    metrics: BTreeMap<(u64, u32), CallbackTimingMetrics>,
    dsq_metrics: BTreeMap<(u64, u64, u32, u32), CallbackTimingMetrics>,
}

impl FineTimingAccumulator {
    fn reset(&mut self, callback: fine_timing::FineTimingCallback, session_id: u64) {
        if let Some(previous) = self.sessions[callback.index()].replace(session_id) {
            self.metrics.retain(|(session, _), _| *session != previous);
            self.dsq_metrics
                .retain(|(session, _, _, _), _| *session != previous);
        }
        self.active[callback.index()] = true;
        for stage in fine_timing::stages(callback) {
            self.metrics.insert(
                (session_id, stage.id),
                CallbackTimingMetrics {
                    total_ns: 0,
                    buckets: vec![0; bpf_intf::SNAKE_FINE_TIMING_BUCKETS as usize],
                },
            );
        }
    }

    fn record(&mut self, session_id: u64, stage: u32, elapsed_ns: u64) {
        let Some(callback_index) = self
            .sessions
            .iter()
            .position(|session| *session == Some(session_id))
        else {
            return;
        };
        if !self.active[callback_index] {
            return;
        }
        let Some(metrics) = self.metrics.get_mut(&(session_id, stage)) else {
            return;
        };
        record_timing_sample(metrics, elapsed_ns);
    }

    fn record_dsq_operation(
        &mut self,
        session_id: u64,
        source_dsq_id: u64,
        target_dsq_id: u64,
        operation: u32,
        outcome: u32,
        queue_class: u32,
        elapsed_ns: u64,
    ) {
        let Some(callback_index) = self
            .sessions
            .iter()
            .position(|session| *session == Some(session_id))
        else {
            return;
        };
        if !self.active[callback_index] || dsq_outcome_label(outcome).is_none() {
            return;
        }
        match operation {
            bpf_intf::snake_dsq_operation_SNAKE_DSQ_OP_INSERT => {
                self.record_dsq_metric(
                    session_id,
                    target_dsq_id,
                    bpf_intf::snake_dsq_operation_SNAKE_DSQ_OP_INSERT,
                    outcome,
                    elapsed_ns,
                );
            }
            bpf_intf::snake_dsq_operation_SNAKE_DSQ_OP_MOVE
            | bpf_intf::snake_dsq_operation_SNAKE_DSQ_OP_MOVE_TO_LOCAL => {
                self.record_dsq_metric(
                    session_id,
                    source_dsq_id,
                    bpf_intf::snake_dsq_operation_SNAKE_DSQ_OP_REMOVE,
                    outcome,
                    elapsed_ns,
                );
                if outcome == bpf_intf::snake_dsq_outcome_SNAKE_DSQ_OUTCOME_SUCCESS {
                    self.record_dsq_metric(
                        session_id,
                        target_dsq_id,
                        bpf_intf::snake_dsq_operation_SNAKE_DSQ_OP_INSERT,
                        outcome,
                        elapsed_ns,
                    );
                }
            }
            _ => return,
        }
        if operation == bpf_intf::snake_dsq_operation_SNAKE_DSQ_OP_MOVE_TO_LOCAL {
            self.record(
                session_id,
                bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_DISPATCH_MOVE_TO_LOCAL,
                elapsed_ns,
            );
            if let Some(stage) = dsq_move_stage(queue_class, outcome) {
                self.record(session_id, stage, elapsed_ns);
            }
        }
    }

    fn record_dsq_metric(
        &mut self,
        session_id: u64,
        dsq_id: u64,
        operation: u32,
        outcome: u32,
        elapsed_ns: u64,
    ) {
        let metrics = self
            .dsq_metrics
            .entry((session_id, dsq_id, operation, outcome))
            .or_insert_with(empty_fine_timing_metrics);
        record_timing_sample(metrics, elapsed_ns);
    }

    fn dsq_operations(&self, session_id: u64) -> Vec<inspection::DsqOperationTimingInspectionView> {
        self.dsq_metrics
            .iter()
            .filter_map(|(&(session, dsq_id, operation, outcome), timing)| {
                if session != session_id {
                    return None;
                }
                Some(inspection::DsqOperationTimingInspectionView {
                    dsq_id,
                    operation: dsq_operation_label(operation)?.to_owned(),
                    outcome: dsq_outcome_label(outcome)?.to_owned(),
                    timing: timing.clone(),
                })
            })
            .collect()
    }

    fn stop(&mut self, callback: fine_timing::FineTimingCallback) {
        self.active[callback.index()] = false;
    }

    fn clear(&mut self) {
        self.sessions = [None, None, None];
        self.active = [false; 3];
        self.metrics.clear();
        self.dsq_metrics.clear();
    }

    fn metrics(&self, session_id: u64, stage: u32) -> CallbackTimingMetrics {
        self.metrics
            .get(&(session_id, stage))
            .cloned()
            .unwrap_or_else(empty_fine_timing_metrics)
    }
}

fn empty_fine_timing_metrics() -> CallbackTimingMetrics {
    CallbackTimingMetrics {
        total_ns: 0,
        buckets: vec![0; bpf_intf::SNAKE_FINE_TIMING_BUCKETS as usize],
    }
}

fn record_timing_sample(metrics: &mut CallbackTimingMetrics, elapsed_ns: u64) {
    let bucket = if elapsed_ns > 1 {
        (u64::BITS - 1 - elapsed_ns.leading_zeros()) as usize
    } else {
        0
    }
    .min(metrics.buckets.len() - 1);
    metrics.total_ns = metrics.total_ns.saturating_add(elapsed_ns);
    metrics.buckets[bucket] = metrics.buckets[bucket].saturating_add(1);
}

fn dsq_operation_label(operation: u32) -> Option<&'static str> {
    match operation {
        bpf_intf::snake_dsq_operation_SNAKE_DSQ_OP_INSERT => Some("insert"),
        bpf_intf::snake_dsq_operation_SNAKE_DSQ_OP_REMOVE => Some("remove"),
        _ => None,
    }
}

fn dsq_outcome_label(outcome: u32) -> Option<&'static str> {
    match outcome {
        bpf_intf::snake_dsq_outcome_SNAKE_DSQ_OUTCOME_SUCCESS => Some("success"),
        bpf_intf::snake_dsq_outcome_SNAKE_DSQ_OUTCOME_MISS => Some("miss"),
        bpf_intf::snake_dsq_outcome_SNAKE_DSQ_OUTCOME_ERROR => Some("error"),
        _ => None,
    }
}

fn dsq_move_stage(queue_class: u32, outcome: u32) -> Option<u32> {
    match (queue_class, outcome) {
        (
            bpf_intf::SNAKE_QUEUE_CLASS_AFFINITY,
            bpf_intf::snake_dsq_outcome_SNAKE_DSQ_OUTCOME_SUCCESS,
        ) => {
            Some(bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_DISPATCH_MOVE_AFFINITY_SUCCESS)
        }
        (
            bpf_intf::SNAKE_QUEUE_CLASS_AFFINITY,
            bpf_intf::snake_dsq_outcome_SNAKE_DSQ_OUTCOME_MISS,
        ) => Some(bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_DISPATCH_MOVE_AFFINITY_MISS),
        (_, bpf_intf::snake_dsq_outcome_SNAKE_DSQ_OUTCOME_SUCCESS) => {
            Some(bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_DISPATCH_MOVE_NORMAL_SUCCESS)
        }
        (_, bpf_intf::snake_dsq_outcome_SNAKE_DSQ_OUTCOME_MISS) => {
            Some(bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_DISPATCH_MOVE_NORMAL_MISS)
        }
        _ => None,
    }
}

fn relay_fine_timing(data: &[u8], accumulator: &Mutex<FineTimingAccumulator>) -> i32 {
    if data.len() != size_of::<bpf_intf::snake_fine_timing_event>() {
        return 0;
    }
    let session_id = u64::from_ne_bytes(data[0..8].try_into().unwrap());
    let elapsed_ns = u64::from_ne_bytes(data[8..16].try_into().unwrap());
    let source_dsq_id = u64::from_ne_bytes(data[16..24].try_into().unwrap());
    let target_dsq_id = u64::from_ne_bytes(data[24..32].try_into().unwrap());
    let stage = u32::from_ne_bytes(data[32..36].try_into().unwrap());
    let operation = u32::from_ne_bytes(data[36..40].try_into().unwrap());
    let outcome = u32::from_ne_bytes(data[40..44].try_into().unwrap());
    let queue_class = u32::from_ne_bytes(data[44..48].try_into().unwrap());
    if let Ok(mut accumulator) = accumulator.lock() {
        if operation == bpf_intf::snake_dsq_operation_SNAKE_DSQ_OP_NONE {
            accumulator.record(session_id, stage, elapsed_ns);
        } else {
            accumulator.record_dsq_operation(
                session_id,
                source_dsq_id,
                target_dsq_id,
                operation,
                outcome,
                queue_class,
                elapsed_ns,
            );
        }
    }
    0
}

#[derive(Debug, Default)]
struct RungTimingAccumulator {
    metrics: BTreeMap<(u64, u32, u32), RungTimingMetrics>,
}

impl RungTimingAccumulator {
    fn record(&mut self, generation: u64, ladder: u32, rung: u32, elapsed_ns: u64) {
        if ladder >= bpf_intf::snake_rung_ladder_SNAKE_NR_RUNG_LADDERS
            || rung >= bpf_intf::SNAKE_MAX_RUNGS
        {
            return;
        }
        let metrics = self
            .metrics
            .entry((generation, ladder, rung))
            .or_insert_with(|| RungTimingMetrics {
                total_ns: 0,
                buckets: vec![0; bpf_intf::SNAKE_CALLBACK_TIMING_BUCKETS as usize],
            });
        let bucket = if elapsed_ns > 1 {
            (u64::BITS - 1 - elapsed_ns.leading_zeros()) as usize
        } else {
            0
        }
        .min(metrics.buckets.len() - 1);
        metrics.total_ns = metrics.total_ns.saturating_add(elapsed_ns);
        metrics.buckets[bucket] = metrics.buckets[bucket].saturating_add(1);
    }

    fn generation(&self, generation: u64) -> Result<BTreeMap<String, RungTimingMetrics>> {
        let mut result = BTreeMap::new();
        for ladder in 0..bpf_intf::snake_rung_ladder_SNAKE_NR_RUNG_LADDERS {
            for rung in 0..bpf_intf::SNAKE_MAX_RUNGS {
                result.insert(
                    rung_timing_key(ladder, rung)?,
                    self.metrics
                        .get(&(generation, ladder, rung))
                        .cloned()
                        .unwrap_or_else(|| RungTimingMetrics {
                            total_ns: 0,
                            buckets: vec![0; bpf_intf::SNAKE_CALLBACK_TIMING_BUCKETS as usize],
                        }),
                );
            }
        }
        Ok(result)
    }
}

fn relay_rung_timing(data: &[u8], accumulator: &Mutex<RungTimingAccumulator>) -> i32 {
    if data.len() != size_of::<bpf_intf::snake_rung_timing_event>() {
        return 0;
    }
    let generation = u64::from_ne_bytes(data[0..8].try_into().unwrap());
    let elapsed_ns = u64::from_ne_bytes(data[8..16].try_into().unwrap());
    let ladder = u32::from_ne_bytes(data[16..20].try_into().unwrap());
    let rung = u32::from_ne_bytes(data[20..24].try_into().unwrap());
    if let Ok(mut accumulator) = accumulator.lock() {
        accumulator.record(generation, ladder, rung, elapsed_ns);
    }
    0
}

fn relay_queue_timing(
    data: &[u8],
    accumulator: &Mutex<queue_timing::QueueTimingAccumulator>,
) -> i32 {
    if data.len() != size_of::<bpf_intf::snake_queue_timing_event>() {
        return 0;
    }
    let session_id = u64::from_ne_bytes(data[0..8].try_into().unwrap());
    let dsq_id = u64::from_ne_bytes(data[8..16].try_into().unwrap());
    let residence_ns = u64::from_ne_bytes(data[16..24].try_into().unwrap());
    let cell_index = u32::from_ne_bytes(data[24..28].try_into().unwrap());
    let raw_queue_class = u32::from_ne_bytes(data[28..32].try_into().unwrap());
    let depth_after_insert = u32::from_ne_bytes(data[32..36].try_into().unwrap());
    let depth_after_dispatch = u32::from_ne_bytes(data[36..40].try_into().unwrap());
    let Ok(queue_class) = queue_timing::QueueClass::try_from(raw_queue_class) else {
        return 0;
    };
    if let Ok(mut accumulator) = accumulator.lock() {
        accumulator.record(queue_timing::QueueTimingEvent {
            session_id,
            dsq_id,
            residence_ns,
            cell_index,
            queue_class,
            depth_after_insert,
            depth_after_dispatch,
        });
    }
    0
}

struct EncodedQueueTopology {
    header: bpf_intf::snake_queue_header,
    cell_lookup: Vec<u32>,
    cells: Vec<bpf_intf::snake_queue_cell>,
    normal_queues: Vec<bpf_intf::snake_normal_queue>,
    cpu_queues: Vec<bpf_intf::snake_cpu_queue>,
}

fn encode_queue_topology(topology: &queue_topology::QueueTopology) -> Result<EncodedQueueTopology> {
    let mut cell_lookup = vec![0_u32; policy::MAX_CELL_IDS as usize];
    let mut cells = (0..bpf_intf::SNAKE_MAX_QUEUE_CELLS)
        .map(|_| bpf_intf::snake_queue_cell {
            valid: 0,
            external_id: 0,
            cpu_weight: 0,
            clock_index: 0,
            first_normal_queue: 0,
            nr_normal_queues: 0,
            reserved: [0; 2],
            primary: bpf_intf::snake_mask_data {
                valid: 0,
                bits: [0; bpf_intf::SNAKE_MASK_BYTES as usize],
            },
            borrowable: bpf_intf::snake_mask_data {
                valid: 0,
                bits: [0; bpf_intf::SNAKE_MASK_BYTES as usize],
            },
        })
        .collect::<Vec<_>>();
    let mut normal_queues = (0..bpf_intf::SNAKE_MAX_NORMAL_QUEUES)
        .map(|_| bpf_intf::snake_normal_queue {
            valid: 0,
            cell_index: 0,
            clock_index: 0,
            llc_id: bpf_intf::SNAKE_QUEUE_LLC_NONE,
            consumer_cpu: 0,
            reserved: [0; 3],
        })
        .collect::<Vec<_>>();
    let mut cpu_queues = (0..bpf_intf::SNAKE_MAX_CPUS)
        .map(|_| bpf_intf::snake_cpu_queue {
            valid: 0,
            owner_cell_index: 0,
            llc_id: 0,
            normal_queue_index: 0,
        })
        .collect::<Vec<_>>();

    if topology.cells.len() > cells.len() {
        bail!("queue topology exceeds BPF cell capacity");
    }
    if topology.normal_queues.len() > normal_queues.len() {
        bail!("queue topology exceeds BPF normal queue capacity");
    }
    for cell in &topology.cells {
        let lookup = cell_lookup
            .get_mut(cell.external_id as usize)
            .with_context(|| format!("cell ID {} exceeds BPF lookup capacity", cell.external_id))?;
        *lookup = cell.index + 1;
        let destination = cells
            .get_mut(cell.index as usize)
            .with_context(|| format!("cell index {} exceeds BPF capacity", cell.index))?;
        *destination = bpf_intf::snake_queue_cell {
            valid: 1,
            external_id: cell.external_id,
            cpu_weight: cell.cpu_weight,
            clock_index: cell.index,
            first_normal_queue: cell.normal_queues.first().copied().unwrap_or(0),
            nr_normal_queues: cell.normal_queues.len().try_into()?,
            reserved: [0; 2],
            primary: mask_tables::serialize_entry(&cell.primary)?,
            borrowable: mask_tables::serialize_entry(&cell.borrowable)?,
        };
    }
    for queue in &topology.normal_queues {
        normal_queues[queue.index as usize] = bpf_intf::snake_normal_queue {
            valid: 1,
            cell_index: queue.cell_index,
            clock_index: queue.clock_index,
            llc_id: queue.llc_id.unwrap_or(bpf_intf::SNAKE_QUEUE_LLC_NONE),
            consumer_cpu: *queue
                .consumers
                .first()
                .context("normal queue has no consumer CPU")?,
            reserved: [0; 3],
        };
    }
    for (&cpu, queue) in &topology.cpu_queues {
        let destination = cpu_queues
            .get_mut(cpu as usize)
            .with_context(|| format!("CPU {cpu} exceeds BPF queue capacity"))?;
        *destination = bpf_intf::snake_cpu_queue {
            valid: 1,
            owner_cell_index: queue.owner_cell_index,
            llc_id: queue.llc_id,
            normal_queue_index: queue.normal_queue_index,
        };
    }
    let nr_cpus = topology.cpu_queues.len().try_into()?;
    let layout = match topology.layout {
        policy::QueueLayout::Cell => bpf_intf::SNAKE_QUEUE_LAYOUT_CELL,
        policy::QueueLayout::CellLlc => bpf_intf::SNAKE_QUEUE_LAYOUT_CELL_LLC,
    };
    Ok(EncodedQueueTopology {
        header: bpf_intf::snake_queue_header {
            layout,
            nr_cells: topology.cells.len().try_into()?,
            nr_normal_queues: topology.normal_queues.len().try_into()?,
            nr_cpus,
        },
        cell_lookup,
        cells,
        normal_queues,
        cpu_queues,
    })
}

fn install_queue_topology(
    skel: &mut BpfSkel<'_>,
    topology: Option<&queue_topology::QueueTopology>,
) -> Result<()> {
    let Some(topology) = topology else {
        return Ok(());
    };
    let encoded = encode_queue_topology(topology)?;
    for (key, value) in encoded.cell_lookup.iter().enumerate() {
        let key = u32::try_from(key)?;
        skel.maps
            .queue_cell_lookup
            .update(&key.to_ne_bytes(), &value.to_ne_bytes(), MapFlags::ANY)
            .with_context(|| format!("installing queue cell lookup {key}"))?;
    }
    for (key, value) in encoded.cells.iter().enumerate() {
        let key = u32::try_from(key)?;
        skel.maps
            .queue_cells
            .update(&key.to_ne_bytes(), bytes_of(value), MapFlags::ANY)
            .with_context(|| format!("installing queue cell {key}"))?;
    }
    for (key, value) in encoded.normal_queues.iter().enumerate() {
        let key = u32::try_from(key)?;
        skel.maps
            .normal_queues
            .update(&key.to_ne_bytes(), bytes_of(value), MapFlags::ANY)
            .with_context(|| format!("installing normal queue {key}"))?;
    }
    for (key, value) in encoded.cpu_queues.iter().enumerate() {
        let key = u32::try_from(key)?;
        skel.maps
            .cpu_queues
            .update(&key.to_ne_bytes(), bytes_of(value), MapFlags::ANY)
            .with_context(|| format!("installing CPU queue {key}"))?;
    }
    let key = 0_u32;
    skel.maps
        .queue_header
        .update(&key.to_ne_bytes(), bytes_of(&encoded.header), MapFlags::ANY)
        .context("publishing queue topology header")?;
    Ok(())
}

fn validate_queue_callback_replacement(
    active: &CompiledPolicy,
    candidate: &CompiledPolicy,
) -> Result<()> {
    let (Some(active), Some(candidate)) = (&active.queues, &candidate.queues) else {
        return Ok(());
    };
    for target in &active.enqueue {
        if !candidate.enqueue.contains(target) {
            bail!(
                "cannot remove active queue enqueue target `{}` during live replacement",
                target.as_str()
            );
        }
    }
    let dispatch_classes = |dispatch: &[QueueDispatchSource]| {
        let min_vtime = dispatch.contains(&QueueDispatchSource::MinVtime);
        (
            min_vtime || dispatch.contains(&QueueDispatchSource::Cell),
            min_vtime || dispatch.contains(&QueueDispatchSource::Affinity),
        )
    };
    let (active_cell, active_affinity) = dispatch_classes(&active.dispatch);
    let (candidate_cell, candidate_affinity) = dispatch_classes(&candidate.dispatch);
    for (active, candidate, source) in [
        (active_cell, candidate_cell, "cell"),
        (active_affinity, candidate_affinity, "affinity"),
    ] {
        if active && !candidate {
            bail!("cannot remove active queue dispatch source `{source}` during live replacement");
        }
    }
    Ok(())
}

fn install_mask_tables(
    skel: &mut BpfSkel<'_>,
    slot: u32,
    tables: &[ResolvedMaskTable],
) -> Result<()> {
    for table in tables {
        if table.id >= bpf_intf::SNAKE_MAX_MASK_TABLES {
            bail!("mask table {} exceeds the BPF table capacity", table.id);
        }
        for (&cpu, cpus) in &table.entries {
            if cpu >= bpf_intf::SNAKE_MAX_CPUS {
                bail!("CPU {cpu} exceeds the BPF table capacity");
            }
            let key = runtime_policy::mask_data_index(slot, table.id, cpu)?;
            let data = mask_tables::serialize_entry(cpus)?;
            skel.maps
                .mask_data
                .update(&key.to_ne_bytes(), bytes_of(&data), MapFlags::ANY)
                .with_context(|| format!("installing mask table {} key CPU {cpu}", table.id))?;
        }
    }
    Ok(())
}

fn clear_mask_table_data(skel: &mut BpfSkel<'_>, slot: u32, table_count: usize) -> Result<()> {
    if table_count > bpf_intf::SNAKE_MAX_MASK_TABLES as usize {
        bail!("mask table count {table_count} exceeds the BPF table capacity");
    }

    let empty = bpf_intf::snake_mask_data {
        valid: 0,
        bits: [0; bpf_intf::SNAKE_MASK_BYTES as usize],
    };
    for table_id in 0..table_count as u32 {
        for cpu in 0..bpf_intf::SNAKE_MAX_CPUS {
            let key = runtime_policy::mask_data_index(slot, table_id, cpu)?;
            skel.maps
                .mask_data
                .update(&key.to_ne_bytes(), bytes_of(&empty), MapFlags::ANY)
                .with_context(|| {
                    format!("clearing ladder slot {slot} mask table {table_id} key CPU {cpu}")
                })?;
        }
    }
    Ok(())
}

fn set_active_ladder(skel: &mut BpfSkel<'_>, slot: u32) -> Result<()> {
    let key = 0_u32;
    skel.maps
        .active_ladder
        .update(&key.to_ne_bytes(), &slot.to_ne_bytes(), MapFlags::ANY)
        .with_context(|| format!("publishing ladder slot {slot}"))
}

fn write_ladder_slot(
    skel: &mut BpfSkel<'_>,
    slot: u32,
    generation: u64,
    policy: &CompiledPolicy,
) -> Result<()> {
    let ladder = encode_ladder(policy, generation)?;
    skel.maps
        .compiled_ladders
        .update(&slot.to_ne_bytes(), bytes_of(&ladder), MapFlags::ANY)
        .with_context(|| format!("installing compiled ladder slot {slot}"))
}

fn prepare_ladder_slot(skel: &mut BpfSkel<'_>, slot: u32) -> Result<()> {
    skel.maps
        .bss_data
        .as_mut()
        .context("BPF bss map is not memory mapped")?
        .staging_ladder_slot = slot;
    let output = skel
        .progs
        .prepare_ladder
        .test_run(ProgramInput::default())
        .with_context(|| format!("preparing ladder slot {slot}"))?;
    if output.return_value != 0 {
        bail!(
            "preparing ladder slot {slot} failed: {}",
            output.return_value as i32
        );
    }
    Ok(())
}

fn wait_for_slot_quiescent(skel: &BpfSkel<'_>, slot: u32, timeout: Duration) -> Result<()> {
    if slot >= bpf_intf::SNAKE_LADDER_SLOTS {
        bail!("invalid ladder slot {slot}");
    }

    let deadline = Instant::now() + timeout;
    loop {
        let raw = skel
            .maps
            .ladder_readers
            .lookup_percpu(&slot.to_ne_bytes(), MapFlags::ANY)
            .with_context(|| format!("reading ladder slot {slot} reader counts"))?
            .ok_or_else(|| anyhow!("ladder reader map has no slot {slot}"))?;
        let readers = runtime_policy::nonzero_reader_counts(&raw)?;
        if readers.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("timed out waiting for ladder slot {slot} readers to drain: {readers:?}");
        }
        std::thread::sleep(SLOT_QUIESCENCE_POLL_INTERVAL);
    }
}

fn clear_slot_stats(skel: &mut BpfSkel<'_>, slot: u32) -> Result<()> {
    let nr_cpus = libbpf_rs::num_possible_cpus()?;
    let zeroes = vec![0_u64.to_ne_bytes().to_vec(); nr_cpus];
    for stat in 0..bpf_intf::snake_stat_SNAKE_NR_STATS {
        let key = runtime_policy::stat_index(slot, stat)?;
        skel.maps
            .stats
            .update_percpu(&key.to_ne_bytes(), &zeroes, MapFlags::ANY)
            .with_context(|| format!("clearing ladder slot {slot} statistic {stat}"))?;
    }
    for cell in 0..bpf_intf::SNAKE_MAX_QUEUE_CELLS {
        for stat in 0..bpf_intf::snake_cell_stat_SNAKE_NR_CELL_STATS {
            let key = runtime_policy::cell_stat_index(slot, cell, stat)?;
            skel.maps
                .cell_stats
                .update_percpu(&key.to_ne_bytes(), &zeroes, MapFlags::ANY)
                .with_context(|| {
                    format!("clearing ladder slot {slot} cell {cell} statistic {stat}")
                })?;
        }
    }
    let callback_zeroes = vec![vec![0; size_of::<bpf_intf::snake_callback_timing>()]; nr_cpus];
    for callback in 0..bpf_intf::snake_callback_SNAKE_NR_CALLBACKS {
        let key = runtime_policy::callback_timing_index(slot, callback)?;
        skel.maps
            .callback_timing
            .update_percpu(&key.to_ne_bytes(), &callback_zeroes, MapFlags::ANY)
            .with_context(|| format!("clearing ladder slot {slot} callback timing {callback}"))?;
    }
    Ok(())
}

struct BpfPolicyBackend<'skel, 'object> {
    skel: &'skel mut BpfSkel<'object>,
}

impl runtime_policy::PolicyBackend for BpfPolicyBackend<'_, '_> {
    fn wait_for_slot_quiescent(&mut self, slot: u32) -> Result<()> {
        wait_for_slot_quiescent(self.skel, slot, SLOT_QUIESCENCE_TIMEOUT)
    }

    fn write_ladder(&mut self, slot: u32, generation: u64, policy: &CompiledPolicy) -> Result<()> {
        write_ladder_slot(self.skel, slot, generation, policy)
    }

    fn write_mask_tables(&mut self, slot: u32, tables: &[ResolvedMaskTable]) -> Result<()> {
        clear_mask_table_data(self.skel, slot, tables.len())?;
        install_mask_tables(self.skel, slot, tables)
    }

    fn prepare_ladder(&mut self, slot: u32) -> Result<()> {
        prepare_ladder_slot(self.skel, slot)
    }

    fn clear_stats(&mut self, slot: u32) -> Result<()> {
        clear_slot_stats(self.skel, slot)
    }

    fn publish_ladder(&mut self, slot: u32) -> Result<()> {
        set_active_ladder(self.skel, slot)
    }
}

fn install_ladder_slot(
    skel: &mut BpfSkel<'_>,
    slot: u32,
    generation: u64,
    policy: &CompiledPolicy,
    tables: &[ResolvedMaskTable],
) -> Result<()> {
    write_ladder_slot(skel, slot, generation, policy)?;
    clear_mask_table_data(skel, slot, tables.len())?;
    install_mask_tables(skel, slot, tables)?;
    prepare_ladder_slot(skel, slot)
}

fn operation_label(rung: &CompiledRung) -> &'static str {
    if rung.flags & policy::RUNG_FLAG_PICK_RANDOM != 0 {
        return if rung.flags & policy::RUNG_FLAG_PICK_IDLE_CORE != 0 {
            "pick_random_idle_core"
        } else {
            "pick_random_idle"
        };
    }
    if rung.flags & policy::RUNG_FLAG_PICK_IDLE_CORE != 0 {
        return match rung.opcode {
            Opcode::PickRandomIdle => "pick_random_idle_core",
            _ => "pick_idle_core",
        };
    }

    match rung.opcode {
        Opcode::ClaimIdle => "claim_idle",
        Opcode::PickIdle | Opcode::PickIdleMaskTable | Opcode::PickIdleQueueMask => "pick_idle",
        Opcode::PickRandomIdle => "pick_random_idle",
        Opcode::KernelDefault => "kernel_default",
        Opcode::SyncWakeAffine => "sync_wake_affine",
    }
}

fn scope_label<'policy>(
    policy: &'policy CompiledPolicy,
    rung: &CompiledRung,
) -> Result<&'policy str> {
    match (rung.opcode, rung.input) {
        (Opcode::PickIdleMaskTable | Opcode::PickRandomIdle, InputSource::TaskCell) => {
            Ok("task_cell")
        }
        (Opcode::PickIdleMaskTable | Opcode::PickRandomIdle, InputSource::CpuPrev) => {
            let table_id = u32::try_from(rung.data).context("mask table ID does not fit u32")?;
            policy
                .mask_tables
                .iter()
                .find(|table| table.id == table_id)
                .map(|table| table.name.as_str())
                .with_context(|| format!("compiled rung references missing mask table {table_id}"))
        }
        (Opcode::PickIdleQueueMask, InputSource::QueueCell) => match rung.data {
            value if value == policy::QueueMaskKind::Primary as u64 => Ok("task_cell"),
            value if value == policy::QueueMaskKind::Borrowable as u64 => {
                Ok("task_cell_borrowable")
            }
            _ => bail!("queue-mask rung references unknown mask kind {}", rung.data),
        },
        (_, InputSource::CpuPrev) => Ok("previous_cpu"),
        (_, InputSource::MaskTaskAllowed) => Ok("task_allowed"),
        (_, InputSource::TaskCell) => bail!("operation cannot consume a task-cell input"),
        (_, InputSource::QueueCell) => bail!("operation cannot consume a queue-cell input"),
    }
}

fn decode_per_cpu_stat(raw: &[Vec<u8>]) -> Result<Vec<u64>> {
    raw.iter()
        .enumerate()
        .map(|(cpu, bytes)| {
            let bytes: [u8; size_of::<u64>()] = bytes.as_slice().try_into().with_context(|| {
                format!(
                    "CPU {cpu} statistic value has {} bytes, expected {}",
                    bytes.len(),
                    size_of::<u64>()
                )
            })?;
            Ok(u64::from_ne_bytes(bytes))
        })
        .collect()
}

fn decode_stat(raw: &[Vec<u8>], use_max: bool) -> Result<u64> {
    let values = decode_per_cpu_stat(raw)?;

    if use_max {
        Ok(values.into_iter().max().unwrap_or_default())
    } else {
        values.into_iter().try_fold(0_u64, |total, value| {
            total
                .checked_add(value)
                .ok_or_else(|| anyhow!("per-CPU statistic sum overflowed u64"))
        })
    }
}

fn aggregate_raw_stats(
    raw: &[Vec<Vec<u8>>],
    policy: &CompiledPolicy,
    generation: u64,
    fairness: FairnessMode,
) -> Result<Metrics> {
    let expected = bpf_intf::snake_stat_SNAKE_NR_STATS as usize;
    if raw.len() != expected {
        bail!(
            "statistics map returned {} entries, expected {expected}",
            raw.len()
        );
    }

    let mut values = Vec::with_capacity(raw.len());
    for (index, per_cpu) in raw.iter().enumerate() {
        values.push(
            decode_stat(
                per_cpu,
                index == bpf_intf::snake_stat_SNAKE_STAT_SELECT_LATENCY_MAX_NS as usize,
            )
            .with_context(|| format!("decoding statistic {index}"))?,
        );
    }

    let value = |index: u32| values[index as usize];
    let cpus = decode_per_cpu_stat(&raw[bpf_intf::snake_stat_SNAKE_STAT_RUNTIME_NS as usize])?
        .into_iter()
        .enumerate()
        .map(|(cpu, runtime_ns)| {
            let cpu = u32::try_from(cpu).context("CPU index does not fit u32")?;
            Ok((cpu, CpuMetrics { cpu, runtime_ns }))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let rungs = policy
        .rungs
        .iter()
        .enumerate()
        .map(|(index, rung)| -> Result<_> {
            let index_u32 = index as u32;
            Ok((
                index_u32,
                RungMetrics {
                    index: index_u32,
                    operation: operation_label(rung).into(),
                    scope: scope_label(policy, rung)?.into(),
                    attempts: value(bpf_intf::snake_stat_SNAKE_STAT_RUNG_ATTEMPT_BASE + index_u32),
                    hits: value(bpf_intf::snake_stat_SNAKE_STAT_RUNG_HIT_BASE + index_u32),
                    misses: value(bpf_intf::snake_stat_SNAKE_STAT_RUNG_MISS_BASE + index_u32),
                    errors: value(bpf_intf::snake_stat_SNAKE_STAT_RUNG_ERROR_BASE + index_u32),
                },
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;

    Ok(Metrics {
        policy_generation: generation,
        fairness_mode: fairness.as_str().into(),
        select_calls: value(bpf_intf::snake_stat_SNAKE_STAT_SELECT_CALLS),
        direct_dispatches: value(bpf_intf::snake_stat_SNAKE_STAT_DIRECT_DISPATCHES),
        ladder_exhaustions: value(bpf_intf::snake_stat_SNAKE_STAT_LADDER_EXHAUSTIONS),
        fallback_prev: value(bpf_intf::snake_stat_SNAKE_STAT_FALLBACK_PREV),
        fallback_any: value(bpf_intf::snake_stat_SNAKE_STAT_FALLBACK_ANY),
        invalid_errors: value(bpf_intf::snake_stat_SNAKE_STAT_INVALID_ERRORS),
        enqueues: value(bpf_intf::snake_stat_SNAKE_STAT_ENQUEUES),
        fifo_shared_enqueues: value(bpf_intf::snake_stat_SNAKE_STAT_FIFO_SHARED_ENQUEUES),
        fifo_shared_dispatches: value(bpf_intf::snake_stat_SNAKE_STAT_FIFO_SHARED_DISPATCHES),
        running: value(bpf_intf::snake_stat_SNAKE_STAT_RUNNING),
        membership_no_cell_runs: value(bpf_intf::snake_stat_SNAKE_STAT_MEMBERSHIP_NO_CELL_RUNS),
        membership_invalid_runs: value(bpf_intf::snake_stat_SNAKE_STAT_MEMBERSHIP_INVALID_RUNS),
        stopping: value(bpf_intf::snake_stat_SNAKE_STAT_STOPPING),
        quiescent: value(bpf_intf::snake_stat_SNAKE_STAT_QUIESCENT),
        select_latency_ns: value(bpf_intf::snake_stat_SNAKE_STAT_SELECT_LATENCY_NS),
        select_latency_max_ns: value(bpf_intf::snake_stat_SNAKE_STAT_SELECT_LATENCY_MAX_NS),
        cell_rehomes: value(bpf_intf::snake_stat_SNAKE_STAT_CELL_REHOMES),
        cell_rehome_misses: value(bpf_intf::snake_stat_SNAKE_STAT_CELL_REHOME_MISSES),
        queue_rehome_preemptions: value(bpf_intf::snake_stat_SNAKE_STAT_QUEUE_REHOME_PREEMPTIONS),
        queue_stale_rehome_runs: value(bpf_intf::snake_stat_SNAKE_STAT_QUEUE_STALE_REHOME_RUNS),
        queue_borrow_yields: value(bpf_intf::snake_stat_SNAKE_STAT_QUEUE_BORROW_YIELDS),
        vtime_enqueues: value(bpf_intf::snake_stat_SNAKE_STAT_VTIME_ENQUEUES),
        vtime_dispatches: value(bpf_intf::snake_stat_SNAKE_STAT_VTIME_DISPATCHES),
        vtime_cpu_enqueues: value(bpf_intf::snake_stat_SNAKE_STAT_VTIME_CPU_ENQUEUES),
        vtime_cpu_dispatches: value(bpf_intf::snake_stat_SNAKE_STAT_VTIME_CPU_DISPATCHES),
        vtime_strict_preempt_queues: value(
            bpf_intf::snake_stat_SNAKE_STAT_VTIME_STRICT_PREEMPT_QUEUES,
        ),
        vtime_direct_runtime_ns: value(bpf_intf::snake_stat_SNAKE_STAT_VTIME_DIRECT_RUNTIME_NS),
        vtime_queued_runtime_ns: value(bpf_intf::snake_stat_SNAKE_STAT_VTIME_QUEUED_RUNTIME_NS),
        vtime_credit_clamps: value(bpf_intf::snake_stat_SNAKE_STAT_VTIME_CREDIT_CLAMPS),
        vtime_accounting_errors: value(bpf_intf::snake_stat_SNAKE_STAT_VTIME_ACCOUNTING_ERRORS),
        vtime_equal_head_ties: value(bpf_intf::snake_stat_SNAKE_STAT_VTIME_EQUAL_HEAD_TIES),
        eevdf_eligible_enqueues: value(bpf_intf::snake_stat_SNAKE_STAT_EEVDF_ELIGIBLE_ENQUEUES),
        eevdf_future_enqueues: value(bpf_intf::snake_stat_SNAKE_STAT_EEVDF_FUTURE_ENQUEUES),
        eevdf_promotions: value(bpf_intf::snake_stat_SNAKE_STAT_EEVDF_PROMOTIONS),
        eevdf_forced_advances: value(bpf_intf::snake_stat_SNAKE_STAT_EEVDF_FORCED_ADVANCES),
        eevdf_dispatches: value(bpf_intf::snake_stat_SNAKE_STAT_EEVDF_DISPATCHES),
        eevdf_strict_preempt_queues: value(
            bpf_intf::snake_stat_SNAKE_STAT_EEVDF_STRICT_PREEMPT_QUEUES,
        ),
        eevdf_direct_runtime_ns: value(bpf_intf::snake_stat_SNAKE_STAT_EEVDF_DIRECT_RUNTIME_NS),
        eevdf_queued_runtime_ns: value(bpf_intf::snake_stat_SNAKE_STAT_EEVDF_QUEUED_RUNTIME_NS),
        eevdf_lag_clamps: value(bpf_intf::snake_stat_SNAKE_STAT_EEVDF_LAG_CLAMPS),
        eevdf_accounting_errors: value(bpf_intf::snake_stat_SNAKE_STAT_EEVDF_ACCOUNTING_ERRORS),
        cpus,
        cells: BTreeMap::new(),
        rungs,
        rung_timing: BTreeMap::new(),
        callback_timing: BTreeMap::new(),
    })
}

const CALLBACK_NAMES: [&str; bpf_intf::snake_callback_SNAKE_NR_CALLBACKS as usize] = [
    "select_cpu",
    "enqueue",
    "dispatch",
    "runnable",
    "running",
    "stopping",
    "quiescent",
];

fn aggregate_raw_callback_timing(
    raw: &[Vec<Vec<u8>>],
) -> Result<BTreeMap<String, CallbackTimingMetrics>> {
    if raw.len() != CALLBACK_NAMES.len() {
        bail!(
            "callback timing map returned {} entries, expected {}",
            raw.len(),
            CALLBACK_NAMES.len()
        );
    }
    let bucket_count = bpf_intf::SNAKE_CALLBACK_TIMING_BUCKETS as usize;
    let expected_size = size_of::<bpf_intf::snake_callback_timing>();

    CALLBACK_NAMES
        .iter()
        .zip(raw)
        .map(|(name, per_cpu)| {
            let mut metrics = CallbackTimingMetrics {
                total_ns: 0,
                buckets: vec![0; bucket_count],
            };
            for (cpu, bytes) in per_cpu.iter().enumerate() {
                if bytes.len() != expected_size {
                    bail!(
                        "CPU {cpu} callback timing value has {} bytes, expected {expected_size}",
                        bytes.len()
                    );
                }
                let value = |index: usize| -> Result<u64> {
                    let offset = index * size_of::<u64>();
                    Ok(u64::from_ne_bytes(
                        bytes[offset..offset + size_of::<u64>()]
                            .try_into()
                            .context("decoding callback timing value")?,
                    ))
                };
                metrics.total_ns = metrics
                    .total_ns
                    .checked_add(value(0)?)
                    .context("callback timing total overflowed u64")?;
                for (bucket, total) in metrics.buckets.iter_mut().enumerate() {
                    *total = total
                        .checked_add(value(1 + bucket)?)
                        .context("callback timing bucket overflowed u64")?;
                }
            }
            Ok(((*name).to_owned(), metrics))
        })
        .collect()
}

fn rung_timing_key(ladder: u32, rung: u32) -> Result<String> {
    let ladder = match ladder {
        bpf_intf::snake_rung_ladder_SNAKE_RUNG_LADDER_IDLE => "idle",
        bpf_intf::snake_rung_ladder_SNAKE_RUNG_LADDER_ENQUEUE => "enqueue",
        bpf_intf::snake_rung_ladder_SNAKE_RUNG_LADDER_DISPATCH => "dispatch",
        _ => bail!("unknown rung ladder {ladder}"),
    };
    Ok(format!("{ladder}:{rung}"))
}

fn aggregate_raw_cell_stats(
    raw: &[Vec<Vec<u8>>],
    topology: &queue_topology::QueueTopology,
) -> Result<BTreeMap<u32, CellMetrics>> {
    let nr_stats = bpf_intf::snake_cell_stat_SNAKE_NR_CELL_STATS as usize;
    let expected = topology.cells.len() * nr_stats;
    if raw.len() != expected {
        bail!(
            "cell statistics map returned {} entries, expected {expected}",
            raw.len()
        );
    }
    let value = |cell: usize, stat: u32| -> Result<u64> {
        decode_stat(&raw[cell * nr_stats + stat as usize], false)
    };
    topology
        .cells
        .iter()
        .enumerate()
        .map(|(dense, cell)| {
            Ok((
                cell.external_id,
                CellMetrics {
                    id: cell.external_id,
                    index: cell.index,
                    runtime_ns: value(dense, bpf_intf::snake_cell_stat_SNAKE_CELL_STAT_RUNTIME_NS)?,
                    primary_runtime_ns: value(
                        dense,
                        bpf_intf::snake_cell_stat_SNAKE_CELL_STAT_PRIMARY_RUNTIME_NS,
                    )?,
                    borrowed_runtime_ns: value(
                        dense,
                        bpf_intf::snake_cell_stat_SNAKE_CELL_STAT_BORROWED_RUNTIME_NS,
                    )?,
                    lent_runtime_ns: value(
                        dense,
                        bpf_intf::snake_cell_stat_SNAKE_CELL_STAT_LENT_RUNTIME_NS,
                    )?,
                    normal_enqueues: value(
                        dense,
                        bpf_intf::snake_cell_stat_SNAKE_CELL_STAT_NORMAL_ENQUEUES,
                    )?,
                    affinity_enqueues: value(
                        dense,
                        bpf_intf::snake_cell_stat_SNAKE_CELL_STAT_AFFINITY_ENQUEUES,
                    )?,
                    normal_dispatches: value(
                        dense,
                        bpf_intf::snake_cell_stat_SNAKE_CELL_STAT_NORMAL_DISPATCHES,
                    )?,
                    affinity_dispatches: value(
                        dense,
                        bpf_intf::snake_cell_stat_SNAKE_CELL_STAT_AFFINITY_DISPATCHES,
                    )?,
                    clock_transitions: value(
                        dense,
                        bpf_intf::snake_cell_stat_SNAKE_CELL_STAT_CLOCK_TRANSITIONS,
                    )?,
                },
            ))
        })
        .collect()
}

fn read_raw_stats(skel: &BpfSkel<'_>, slot: u32) -> Result<Vec<Vec<Vec<u8>>>> {
    (0..bpf_intf::snake_stat_SNAKE_NR_STATS)
        .map(|stat| {
            let index = runtime_policy::stat_index(slot, stat)?;
            skel.maps
                .stats
                .lookup_percpu(&index.to_ne_bytes(), libbpf_rs::MapFlags::ANY)
                .with_context(|| format!("looking up ladder slot {slot} statistic {stat}"))?
                .ok_or_else(|| anyhow!("statistics map has no entry {index}"))
        })
        .collect()
}

fn read_raw_callback_timing(skel: &BpfSkel<'_>, slot: u32) -> Result<Vec<Vec<Vec<u8>>>> {
    (0..bpf_intf::snake_callback_SNAKE_NR_CALLBACKS)
        .map(|callback| {
            let index = runtime_policy::callback_timing_index(slot, callback)?;
            skel.maps
                .callback_timing
                .lookup_percpu(&index.to_ne_bytes(), MapFlags::ANY)
                .with_context(|| {
                    format!("looking up ladder slot {slot} callback timing {callback}")
                })?
                .ok_or_else(|| anyhow!("callback timing map has no entry {index}"))
        })
        .collect()
}

fn read_raw_cell_stats(
    skel: &BpfSkel<'_>,
    slot: u32,
    nr_cells: usize,
) -> Result<Vec<Vec<Vec<u8>>>> {
    (0..nr_cells as u32)
        .flat_map(|cell| {
            (0..bpf_intf::snake_cell_stat_SNAKE_NR_CELL_STATS).map(move |stat| (cell, stat))
        })
        .map(|(cell, stat)| {
            let index = runtime_policy::cell_stat_index(slot, cell, stat)?;
            skel.maps
                .cell_stats
                .lookup_percpu(&index.to_ne_bytes(), MapFlags::ANY)
                .with_context(|| format!("looking up cell {cell} statistic {stat}"))?
                .ok_or_else(|| anyhow!("cell statistics map has no entry {index}"))
        })
        .collect()
}

struct Scheduler<'object, 'policy> {
    skel: BpfSkel<'object>,
    struct_ops: Option<libbpf_rs::Link>,
    timing_ring: libbpf_rs::RingBuffer<'static>,
    fine_timing_accumulator: Arc<Mutex<FineTimingAccumulator>>,
    rung_timing_accumulator: Arc<Mutex<RungTimingAccumulator>>,
    queue_timing_accumulator: Arc<Mutex<queue_timing::QueueTimingAccumulator>>,
    stats_server: StatsServer<SchedulerRequest, SchedulerResponse>,
    inspector: Inspector,
    runtime: &'policy mut RuntimePolicy,
    fairness: FairnessMode,
    queue_topology: Option<queue_topology::QueueTopology>,
    membership: Option<MembershipManager>,
    callback_timing_sample_rate: u32,
    fine_timing_state: fine_timing::FineTimingState,
    queue_timing_state: queue_timing::QueueTimingState,
    queue_timing_counters: queue_timing::QueueTimingCounters,
}

fn fine_timing_available(
    _callback: fine_timing::FineTimingCallback,
    _fairness: FairnessMode,
    _has_queue_topology: bool,
) -> bool {
    true
}

impl<'object, 'policy> Scheduler<'object, 'policy> {
    fn drain_timing_events(&self) -> Result<()> {
        loop {
            let consumed = self.timing_ring.consume_raw_n(TIMING_DRAIN_BATCH);
            if consumed < 0 {
                bail!("draining timing events failed with errno {}", -consumed);
            }
            if consumed < TIMING_DRAIN_BATCH as i32 {
                break;
            }
        }
        Ok(())
    }

    fn init(
        opts: &Opts,
        runtime: &'policy mut RuntimePolicy,
        mask_tables: &[ResolvedMaskTable],
        queue_topology: Option<&queue_topology::QueueTopology>,
        open_object: &'object mut MaybeUninit<OpenObject>,
    ) -> Result<Self> {
        try_set_rlimit_infinity();

        let mut builder = BpfSkelBuilder::default();
        builder.obj_builder.debug(opts.verbose);
        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(builder, open_object, snake_ops, open_opts)?;
        skel.maps
            .rodata_data
            .as_mut()
            .context("BPF read-only data is unavailable")?
            .fairness_mode = opts.fairness as u32;
        skel.maps
            .bss_data
            .as_mut()
            .context("BPF bss data is unavailable")?
            .callback_timing_sample_rate = opts.callback_timing_sample_rate;
        if queue_topology.is_some() {
            skel.struct_ops.snake_ops_mut().flags |= *scx_utils::compat::SCX_OPS_ENQ_LAST;
        }
        skel.struct_ops.snake_ops_mut().exit_dump_len = opts.exit_dump_len;
        let mut skel = scx_ops_load!(skel, snake_ops, uei)?;
        install_queue_topology(&mut skel, queue_topology)?;
        set_active_ladder(&mut skel, bpf_intf::SNAKE_LADDER_SLOT_INVALID)?;
        install_ladder_slot(
            &mut skel,
            0,
            runtime.generation,
            &runtime.compiled,
            mask_tables,
        )?;
        set_active_ladder(&mut skel, 0)?;
        runtime.active_slot = 0;
        let membership = if let Some(policy) = &runtime.compiled.membership {
            let mut manager =
                MembershipManager::new(policy).context("initializing userspace task membership")?;
            let report = manager
                .reconcile(&skel.maps.task_cells)
                .context("applying initial userspace task membership")?;
            info!(
                "classified {} of {} discovered threads before scheduler attach ({} transient)",
                report.updated, report.discovered, report.transient
            );
            Some(manager)
        } else {
            None
        };
        let struct_ops = Some(scx_ops_attach!(skel, snake_ops)?);
        let stats_server = StatsServer::new(stats::server_data()).launch()?;
        info!(
            "attached {SCHEDULER_NAME} policy generation {} with {} rungs ({:?} fairness)",
            runtime.generation,
            runtime.compiled.rungs.len(),
            opts.fairness,
        );
        let inspector = Inspector::new(
            SlotPolicy::new(
                runtime.active_slot,
                runtime.generation,
                runtime.source.clone(),
                runtime.compiled.clone(),
                mask_tables.to_vec(),
                unix_time_ms(),
            ),
            opts.fairness,
            queue_topology.cloned(),
        )
        .with_callback_timing_sample_rate(opts.callback_timing_sample_rate);
        let fine_timing_accumulator = Arc::new(Mutex::new(FineTimingAccumulator::default()));
        let relay_accumulator = Arc::clone(&fine_timing_accumulator);
        let rung_timing_accumulator = Arc::new(Mutex::new(RungTimingAccumulator::default()));
        let rung_relay_accumulator = Arc::clone(&rung_timing_accumulator);
        let queue_timing_accumulator =
            Arc::new(Mutex::new(queue_timing::QueueTimingAccumulator::default()));
        let queue_relay_accumulator = Arc::clone(&queue_timing_accumulator);
        let mut ring_builder = libbpf_rs::RingBufferBuilder::new();
        ring_builder
            .add(&skel.maps.fine_timing_events, move |data| {
                relay_fine_timing(data, &relay_accumulator)
            })
            .context("registering fine timing ring buffer")?;
        ring_builder
            .add(&skel.maps.rung_timing_events, move |data| {
                relay_rung_timing(data, &rung_relay_accumulator)
            })
            .context("registering rung timing ring buffer")?;
        ring_builder
            .add(&skel.maps.queue_timing_events, move |data| {
                relay_queue_timing(data, &queue_relay_accumulator)
            })
            .context("registering queue timing ring buffer")?;
        let timing_ring = ring_builder
            .build()
            .context("building timing ring buffers")?;

        Ok(Self {
            skel,
            struct_ops,
            timing_ring,
            fine_timing_accumulator,
            rung_timing_accumulator,
            queue_timing_accumulator,
            stats_server,
            inspector,
            runtime,
            fairness: opts.fairness,
            queue_topology: queue_topology.cloned(),
            membership,
            callback_timing_sample_rate: opts.callback_timing_sample_rate,
            fine_timing_state: fine_timing::FineTimingState::default(),
            queue_timing_state: queue_timing::QueueTimingState::default(),
            queue_timing_counters: queue_timing::QueueTimingCounters::default(),
        })
    }

    fn metrics(&self) -> Result<Metrics> {
        self.drain_timing_events()?;
        let mut metrics = aggregate_raw_stats(
            &read_raw_stats(&self.skel, self.runtime.active_slot)?,
            &self.runtime.compiled,
            self.runtime.generation,
            self.fairness,
        )?;
        if let Some(topology) = &self.queue_topology {
            metrics.cells = aggregate_raw_cell_stats(
                &read_raw_cell_stats(&self.skel, self.runtime.active_slot, topology.cells.len())?,
                topology,
            )?;
        }
        metrics.callback_timing = aggregate_raw_callback_timing(&read_raw_callback_timing(
            &self.skel,
            self.runtime.active_slot,
        )?)?;
        metrics.rung_timing = self
            .rung_timing_accumulator
            .lock()
            .map_err(|_| anyhow!("rung timing accumulator lock poisoned"))?
            .generation(self.runtime.generation)?;
        Ok(metrics)
    }

    fn replace_policy(&mut self, source: String) -> Result<runtime_policy::PolicyUpdateResponse> {
        self.stop_all_fine_timing()?;
        self.stop_queue_timing()?;
        let previous_slot = self.runtime.active_slot;
        let previous_generation = self.runtime.generation;
        let previous_policy = self.runtime.compiled.clone();
        let fallback_frozen_metrics = self.metrics()?;
        let mut activated_tables = None;
        let active_queue_topology = self.queue_topology.clone();
        let mut backend = BpfPolicyBackend {
            skel: &mut self.skel,
        };
        let response = runtime_policy::replace_policy(
            self.runtime,
            source,
            |policy| {
                let candidate = resolve_host_queue_topology(policy)
                    .context("resolving replacement policy queue topology")?;
                if candidate != active_queue_topology {
                    bail!(
                        "replacement changes the attachment-time queue topology; restart Snake to apply it"
                    );
                }
                if policy.membership != previous_policy.membership {
                    bail!(
                        "replacement changes attachment-time task membership; restart Snake to apply it"
                    );
                }
                validate_queue_callback_replacement(&previous_policy, policy)?;
                let tables = resolve_mask_tables(policy)?;
                activated_tables = Some(tables.clone());
                Ok(tables)
            },
            &mut backend,
        )?;
        drop(backend);
        let frozen_metrics =
            match wait_for_slot_quiescent(&self.skel, previous_slot, SLOT_QUIESCENCE_TIMEOUT)
                .and_then(|_| {
                    let mut metrics = aggregate_raw_stats(
                        &read_raw_stats(&self.skel, previous_slot)?,
                        &previous_policy,
                        previous_generation,
                        self.fairness,
                    )?;
                    if let Some(topology) = &self.queue_topology {
                        metrics.cells = aggregate_raw_cell_stats(
                            &read_raw_cell_stats(&self.skel, previous_slot, topology.cells.len())?,
                            topology,
                        )?;
                    }
                    metrics.callback_timing = aggregate_raw_callback_timing(
                        &read_raw_callback_timing(&self.skel, previous_slot)?,
                    )?;
                    self.drain_timing_events()?;
                    metrics.rung_timing = self
                        .rung_timing_accumulator
                        .lock()
                        .map_err(|_| anyhow!("rung timing accumulator lock poisoned"))?
                        .generation(previous_generation)?;
                    Ok(metrics)
                }) {
                Ok(metrics) => metrics,
                Err(error) => {
                    warn!(
                    "could not capture final metrics for inactive slot {previous_slot}: {error:#}"
                );
                    fallback_frozen_metrics
                }
            };
        let resolved_tables =
            activated_tables.context("activated policy has no resolved tables")?;
        let activated_at_ms = unix_time_ms();
        self.inspector.activate(
            SlotPolicy::new(
                self.runtime.active_slot,
                self.runtime.generation,
                self.runtime.source.clone(),
                self.runtime.compiled.clone(),
                resolved_tables,
                activated_at_ms,
            ),
            frozen_metrics,
            activated_at_ms,
        );
        info!(
            "activated policy generation {} ({})",
            response.generation, response.summary
        );
        Ok(response)
    }

    fn validate_policy(&self, source: &str) -> Result<runtime_policy::PolicyValidationResponse> {
        let policy = policy::compile_policy(source).context("compiling candidate policy")?;
        let candidate =
            resolve_host_queue_topology(&policy).context("resolving candidate queue topology")?;
        if candidate != self.queue_topology {
            bail!(
                "candidate changes the attachment-time queue topology; restart Snake to apply it"
            );
        }
        if policy.membership != self.runtime.compiled.membership {
            bail!("candidate changes attachment-time task membership; restart Snake to apply it");
        }
        validate_queue_callback_replacement(&self.runtime.compiled, &policy)?;
        resolve_mask_tables(&policy).context("resolving candidate policy mask tables")?;
        Ok(runtime_policy::PolicyValidationResponse::from_policy(
            &policy,
        ))
    }

    fn set_thread_cell(&mut self, assignment: ThreadCellAssignment) -> Result<ThreadCellResponse> {
        if !self
            .runtime
            .compiled
            .cells
            .contains_key(&assignment.cell_id)
            && !(assignment.cell_id == 0 && self.queue_topology.is_some())
        {
            bail!(
                "active policy generation {} does not define cell {}",
                self.runtime.generation,
                assignment.cell_id
            );
        }
        let rehome_requested = task_cells::set_thread_cell(&self.skel.maps.task_cells, assignment)?;
        self.inspector
            .set_assignment(assignment.tid, assignment.cell_id);
        Ok(ThreadCellResponse {
            tid: assignment.tid,
            cell_id: Some(assignment.cell_id),
            rehome_requested,
        })
    }

    fn clear_thread_cell(&mut self, tid: i32) -> Result<ThreadCellResponse> {
        task_cells::clear_thread_cell(&self.skel.maps.task_cells, tid)?;
        self.inspector.clear_assignment(tid);
        Ok(ThreadCellResponse {
            tid,
            cell_id: None,
            rehome_requested: self.queue_topology.is_some(),
        })
    }

    fn publish_fine_timing_state(&mut self, state: &fine_timing::FineTimingState) -> Result<()> {
        let key = 0_u32;
        let config = state.bpf_config();
        self.skel
            .maps
            .fine_timing_config
            .update(&key.to_ne_bytes(), bytes_of(&config), MapFlags::ANY)
            .context("updating fine timing configuration")?;
        self.skel
            .maps
            .bss_data
            .as_mut()
            .context("BPF bss map is not memory mapped")?
            .select_fine_timing_session_id =
            if state.is_enabled(fine_timing::FineTimingCallback::SelectCpu) {
                state
                    .session(fine_timing::FineTimingCallback::SelectCpu)
                    .map_or(0, |session| session.session_id)
            } else {
                0
            };
        Ok(())
    }

    fn set_fine_timing(
        &mut self,
        callback: fine_timing::FineTimingCallback,
        enabled: bool,
    ) -> Result<fine_timing::FineTimingControlResponse> {
        self.drain_timing_events()?;
        if enabled && self.callback_timing_sample_rate == 0 {
            bail!("fine timing requires callback timing sampling to be enabled");
        }
        if enabled && !fine_timing_available(callback, self.fairness, self.queue_topology.is_some())
        {
            bail!("enqueue and dispatch fine timing require queue topology mode");
        }
        if self.fine_timing_state.is_enabled(callback) == enabled {
            return Ok(fine_timing::FineTimingControlResponse {
                callback,
                enabled,
                session_id: self
                    .fine_timing_state
                    .session(callback)
                    .map(|session| session.session_id),
            });
        }

        let mut next = self.fine_timing_state.clone();
        if enabled {
            let session = next.start(callback, self.runtime.generation, unix_time_ms());
            self.fine_timing_accumulator
                .lock()
                .map_err(|_| anyhow!("fine timing accumulator lock poisoned"))?
                .reset(callback, session.session_id);
        } else {
            next.stop(callback, unix_time_ms());
        }
        self.publish_fine_timing_state(&next)?;
        if !enabled {
            self.fine_timing_accumulator
                .lock()
                .map_err(|_| anyhow!("fine timing accumulator lock poisoned"))?
                .stop(callback);
        }
        self.fine_timing_state = next;
        Ok(fine_timing::FineTimingControlResponse {
            callback,
            enabled,
            session_id: self
                .fine_timing_state
                .session(callback)
                .map(|session| session.session_id),
        })
    }

    fn set_callback_timing_sample_rate(
        &mut self,
        sample_rate: u32,
    ) -> Result<control::CallbackTimingRateResponse> {
        validate_callback_timing_sample_rate(sample_rate).map_err(anyhow::Error::msg)?;
        if sample_rate == self.callback_timing_sample_rate {
            return Ok(control::CallbackTimingRateResponse {
                sample_rate,
                fine_timing_stopped: false,
                queue_timing_stopped: false,
            });
        }
        let fine_timing_stopped = fine_timing::FineTimingCallback::ALL
            .into_iter()
            .any(|callback| self.fine_timing_state.is_enabled(callback));
        self.stop_all_fine_timing()?;
        let queue_timing_stopped = self.stop_queue_timing()?;
        self.skel
            .maps
            .bss_data
            .as_mut()
            .context("BPF bss map is not memory mapped")?
            .callback_timing_sample_rate = sample_rate;
        self.callback_timing_sample_rate = sample_rate;
        self.inspector.set_callback_timing_sample_rate(sample_rate);
        Ok(control::CallbackTimingRateResponse {
            sample_rate,
            fine_timing_stopped,
            queue_timing_stopped,
        })
    }

    fn reset_stats(&mut self) -> Result<control::StatsResetResponse> {
        self.drain_timing_events()?;
        let resolved_tables = self
            .inspector
            .active_resolved_tables()
            .context("active policy has no resolved mask tables")?
            .to_vec();
        let previous_fine_timing = self.fine_timing_state.clone();
        let mut cleared_fine_timing = previous_fine_timing.clone();
        let fine_timing_stopped = cleared_fine_timing.clear();
        let previous_queue_timing = self.queue_timing_state.clone();
        let queue_timing_stopped = previous_queue_timing.is_enabled();
        let accumulator = Arc::clone(&self.fine_timing_accumulator);
        let mut accumulator = accumulator
            .lock()
            .map_err(|_| anyhow!("fine timing accumulator lock poisoned"))?;
        self.publish_fine_timing_state(&cleared_fine_timing)?;
        self.publish_queue_timing_session(0)?;

        let mut backend = BpfPolicyBackend {
            skel: &mut self.skel,
        };
        let reset_result =
            runtime_policy::reset_stats(self.runtime, &resolved_tables, &mut backend);
        drop(backend);
        let active_slot = match reset_result {
            Ok(active_slot) => active_slot,
            Err(error) => {
                if let Err(restore_error) = self.publish_fine_timing_state(&previous_fine_timing) {
                    return Err(error).context(format!(
                        "restoring fine timing after reset failure also failed: {restore_error:#}"
                    ));
                }
                if queue_timing_stopped {
                    let session_id = previous_queue_timing
                        .capture()
                        .map_or(0, |capture| capture.session_id);
                    self.publish_queue_timing_session(session_id)?;
                }
                return Err(error);
            }
        };

        accumulator.clear();
        drop(accumulator);
        self.fine_timing_state = cleared_fine_timing;
        self.queue_timing_state.clear();
        self.queue_timing_accumulator
            .lock()
            .map_err(|_| anyhow!("queue timing accumulator lock poisoned"))?
            .clear();
        self.queue_timing_counters = queue_timing::QueueTimingCounters::default();
        self.reset_queue_timing_counters()?;

        let reset_at_ms = unix_time_ms();
        self.inspector.reset_stats(SlotPolicy::new(
            active_slot,
            self.runtime.generation,
            self.runtime.source.clone(),
            self.runtime.compiled.clone(),
            resolved_tables,
            reset_at_ms,
        ));
        Ok(control::StatsResetResponse {
            generation: self.runtime.generation,
            active_slot,
            reset_at_ms,
            fine_timing_stopped,
            queue_timing_stopped,
        })
    }

    fn stop_all_fine_timing(&mut self) -> Result<()> {
        if !fine_timing::FineTimingCallback::ALL
            .iter()
            .copied()
            .any(|callback| self.fine_timing_state.is_enabled(callback))
        {
            return Ok(());
        }
        self.drain_timing_events()?;
        let mut next = self.fine_timing_state.clone();
        let stopped_at_ms = unix_time_ms();
        for callback in fine_timing::FineTimingCallback::ALL {
            next.stop(callback, stopped_at_ms);
        }
        self.publish_fine_timing_state(&next)?;
        let mut accumulator = self
            .fine_timing_accumulator
            .lock()
            .map_err(|_| anyhow!("fine timing accumulator lock poisoned"))?;
        for callback in fine_timing::FineTimingCallback::ALL {
            accumulator.stop(callback);
        }
        drop(accumulator);
        self.fine_timing_state = next;
        Ok(())
    }

    fn fine_timing_inspection(&self) -> Result<inspection::FineTimingInspectionView> {
        self.drain_timing_events()?;
        let captures = fine_timing::FineTimingCallback::ALL
            .into_iter()
            .map(|callback| {
                let session = self.fine_timing_state.session(callback);
                let state = match session {
                    Some(session) if session.stopped_at_ms.is_none() => {
                        inspection::FineTimingCaptureState::Collecting
                    }
                    Some(_) => inspection::FineTimingCaptureState::Historical,
                    None => inspection::FineTimingCaptureState::Inactive,
                };
                let stages = match session {
                    Some(session) => {
                        let accumulator = self
                            .fine_timing_accumulator
                            .lock()
                            .map_err(|_| anyhow!("fine timing accumulator lock poisoned"))?;
                        fine_timing::stages(callback)
                            .iter()
                            .map(|stage| {
                                (
                                    stage.name.to_owned(),
                                    accumulator.metrics(session.session_id, stage.id),
                                )
                            })
                            .collect()
                    }
                    None => fine_timing::stages(callback)
                        .iter()
                        .map(|stage| {
                            (
                                stage.name.to_owned(),
                                CallbackTimingMetrics {
                                    total_ns: 0,
                                    buckets: vec![0; bpf_intf::SNAKE_FINE_TIMING_BUCKETS as usize],
                                },
                            )
                        })
                        .collect(),
                };
                Ok(inspection::FineTimingCaptureInspectionView {
                    callback: callback.as_str().to_owned(),
                    state,
                    session_id: session.map(|session| session.session_id),
                    policy_generation: session.map(|session| session.policy_generation),
                    started_at_ms: session.map(|session| session.started_at_ms),
                    stopped_at_ms: session.and_then(|session| session.stopped_at_ms),
                    stages,
                    dsq_operations: match session {
                        Some(session) => self
                            .fine_timing_accumulator
                            .lock()
                            .map_err(|_| anyhow!("fine timing accumulator lock poisoned"))?
                            .dsq_operations(session.session_id),
                        None => Vec::new(),
                    },
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(inspection::FineTimingInspectionView {
            sample_rate: self.callback_timing_sample_rate,
            captures,
        })
    }

    fn publish_queue_timing_session(&mut self, session_id: u64) -> Result<()> {
        self.skel
            .maps
            .bss_data
            .as_mut()
            .context("BPF bss map is not memory mapped")?
            .queue_timing_session_id = session_id;
        Ok(())
    }

    fn reset_queue_timing_counters(&mut self) -> Result<()> {
        let bss = self
            .skel
            .maps
            .bss_data
            .as_mut()
            .context("BPF bss map is not memory mapped")?;
        bss.queue_timing_counters.started_samples = 0;
        bss.queue_timing_counters.completed_samples = 0;
        bss.queue_timing_counters.dropped_samples = 0;
        Ok(())
    }

    fn read_queue_timing_counters(&self) -> Result<queue_timing::QueueTimingCounters> {
        let counters = &self
            .skel
            .maps
            .bss_data
            .as_ref()
            .context("BPF bss map is not memory mapped")?
            .queue_timing_counters;
        // BPF updates these counters concurrently with userspace inspection.
        let started_samples = unsafe { std::ptr::read_volatile(&counters.started_samples) };
        let completed_samples = unsafe { std::ptr::read_volatile(&counters.completed_samples) };
        let dropped_samples = unsafe { std::ptr::read_volatile(&counters.dropped_samples) };
        Ok(queue_timing::QueueTimingCounters {
            started_samples,
            completed_samples,
            dropped_samples,
        })
    }

    fn set_queue_timing(
        &mut self,
        enabled: bool,
    ) -> Result<queue_timing::QueueTimingControlResponse> {
        self.drain_timing_events()?;
        if enabled {
            queue_timing::validate_capture_start(self.callback_timing_sample_rate)
                .map_err(anyhow::Error::msg)?;
        }
        if self.queue_timing_state.is_enabled() == enabled {
            return Ok(queue_timing::QueueTimingControlResponse {
                enabled,
                session_id: self
                    .queue_timing_state
                    .capture()
                    .map(|capture| capture.session_id),
            });
        }

        if enabled {
            let mut next = self.queue_timing_state.clone();
            let capture = next.start(
                self.callback_timing_sample_rate,
                self.runtime.generation,
                unix_time_ms(),
            );
            self.publish_queue_timing_session(0)?;
            self.reset_queue_timing_counters()?;
            self.queue_timing_accumulator
                .lock()
                .map_err(|_| anyhow!("queue timing accumulator lock poisoned"))?
                .reset(capture.session_id);
            self.queue_timing_counters = queue_timing::QueueTimingCounters::default();
            self.publish_queue_timing_session(capture.session_id)?;
            self.queue_timing_state = next;
        } else {
            self.stop_queue_timing()?;
        }

        Ok(queue_timing::QueueTimingControlResponse {
            enabled,
            session_id: self
                .queue_timing_state
                .capture()
                .map(|capture| capture.session_id),
        })
    }

    fn stop_queue_timing(&mut self) -> Result<bool> {
        if !self.queue_timing_state.is_enabled() {
            return Ok(false);
        }
        self.publish_queue_timing_session(0)?;
        self.drain_timing_events()?;
        self.queue_timing_counters = self.read_queue_timing_counters()?;
        self.queue_timing_state.stop(unix_time_ms());
        self.queue_timing_accumulator
            .lock()
            .map_err(|_| anyhow!("queue timing accumulator lock poisoned"))?
            .stop();
        Ok(true)
    }

    fn queue_timing_inspection(&self) -> Result<queue_timing::QueueTimingInspectionView> {
        self.drain_timing_events()?;
        let counters = if self.queue_timing_state.is_enabled() {
            self.read_queue_timing_counters()?
        } else {
            self.queue_timing_counters
        };
        let accumulator = self
            .queue_timing_accumulator
            .lock()
            .map_err(|_| anyhow!("queue timing accumulator lock poisoned"))?;
        Ok(queue_timing::inspection_view(
            self.callback_timing_sample_rate,
            &self.queue_timing_state,
            counters,
            &accumulator,
        ))
    }

    fn exited(&self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn inspection(&mut self) -> Result<InspectionView> {
        let assignments = self.inspector.assignments().collect::<BTreeMap<_, _>>();
        let mut stale = Vec::new();
        let mut task_mappings = Vec::new();
        for (&tid, _) in &assignments {
            match task_cells::inspect_thread_cell(&self.skel.maps.task_cells, tid)? {
                Some(task) => task_mappings.push(inspection::TaskMappingInspectionView {
                    tid: task.tid,
                    tgid: task.tgid,
                    name: task.name,
                    state: task.state,
                    current_cpu: task.current_cpu,
                    cell_id: task.cell_id,
                    cell_defined: task.cell_id == 0
                        || self.runtime.compiled.cells.contains_key(&task.cell_id),
                    allowed_cpus: task.allowed_cpus,
                    cgroup: task.cgroup,
                    needs_rehome: task.needs_rehome,
                    source: "manual".into(),
                    membership: if task.cell_id == 0 { "no_cell" } else { "cell" }.into(),
                }),
                None => stale.push(tid),
            }
        }
        for tid in stale {
            self.inspector.clear_assignment(tid);
        }
        if let Some(manager) = &self.membership {
            for (tid, _) in manager.assignments() {
                if assignments.contains_key(&tid) {
                    continue;
                }
                let Some(task) = task_cells::inspect_thread_cell(&self.skel.maps.task_cells, tid)?
                else {
                    continue;
                };
                task_mappings.push(inspection::TaskMappingInspectionView {
                    tid: task.tid,
                    tgid: task.tgid,
                    name: task.name,
                    state: task.state,
                    current_cpu: task.current_cpu,
                    cell_id: task.cell_id,
                    cell_defined: task.cell_id == 0
                        || self.runtime.compiled.cells.contains_key(&task.cell_id),
                    allowed_cpus: task.allowed_cpus,
                    cgroup: task.cgroup,
                    needs_rehome: task.needs_rehome,
                    source: "managed".into(),
                    membership: "cell".into(),
                });
            }
        }
        let mut snapshot = self.inspector.snapshot(self.metrics()?, task_mappings);
        snapshot.fine_timing = self.fine_timing_inspection()?;
        snapshot.queue_timing = Some(self.queue_timing_inspection()?);
        Ok(snapshot)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (response_channel, request_channel) = self.stats_server.channels();
        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            let timeout = self
                .membership
                .as_ref()
                .map(MembershipManager::time_until_reconcile)
                .unwrap_or(Duration::from_secs(1))
                .min(Duration::from_secs(1));
            let timeout = if self.queue_timing_state.is_enabled()
                || fine_timing::FineTimingCallback::ALL
                    .into_iter()
                    .any(|callback| self.fine_timing_state.is_enabled(callback))
            {
                timeout.min(Duration::from_millis(50))
            } else {
                timeout
            };
            match request_channel.recv_timeout(timeout) {
                Ok(SchedulerRequest::Metrics) => {
                    response_channel.send(SchedulerResponse::Metrics(self.metrics()?))?
                }
                Ok(SchedulerRequest::Inspect) => {
                    response_channel.send(SchedulerResponse::Inspection(self.inspection()?))?
                }
                Ok(SchedulerRequest::ValidatePolicy { source }) => {
                    let response = self
                        .validate_policy(&source)
                        .map_err(|error| format!("{error:#}"));
                    response_channel.send(SchedulerResponse::PolicyValidation(response))?;
                }
                Ok(SchedulerRequest::ReplacePolicy { source }) => {
                    let response = self
                        .replace_policy(source)
                        .map_err(|error| format!("{error:#}"));
                    response_channel.send(SchedulerResponse::ReplacePolicy(response))?;
                }
                Ok(SchedulerRequest::SetThreadCell(assignment)) => {
                    let response = self
                        .set_thread_cell(assignment)
                        .map_err(|error| format!("{error:#}"));
                    response_channel.send(SchedulerResponse::ThreadCell(response))?;
                }
                Ok(SchedulerRequest::ClearThreadCell { tid }) => {
                    let response = self
                        .clear_thread_cell(tid)
                        .map_err(|error| format!("{error:#}"));
                    response_channel.send(SchedulerResponse::ThreadCell(response))?;
                }
                Ok(SchedulerRequest::SetFineTiming { callback, enabled }) => {
                    let response = self
                        .set_fine_timing(callback, enabled)
                        .map_err(|error| format!("{error:#}"));
                    response_channel.send(SchedulerResponse::FineTiming(response))?;
                }
                Ok(SchedulerRequest::SetQueueTiming { enabled }) => {
                    let response = self
                        .set_queue_timing(enabled)
                        .map_err(|error| format!("{error:#}"));
                    response_channel.send(SchedulerResponse::QueueTiming(response))?;
                }
                Ok(SchedulerRequest::SetCallbackTimingSampleRate { sample_rate }) => {
                    let response = self
                        .set_callback_timing_sample_rate(sample_rate)
                        .map_err(|error| format!("{error:#}"));
                    response_channel.send(SchedulerResponse::CallbackTimingSampleRate(response))?;
                }
                Ok(SchedulerRequest::ResetStats) => {
                    let response = self.reset_stats().map_err(|error| format!("{error:#}"));
                    response_channel.send(SchedulerResponse::StatsReset(response))?;
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    bail!("statistics server request channel disconnected")
                }
            }
            self.drain_timing_events()?;
            if let Some(manager) = &mut self.membership {
                match manager.reconcile_if_due(&self.skel.maps.task_cells) {
                    Ok(Some(report)) if report.updated != 0 || report.transient != 0 => debug!(
                        "membership reconciliation discovered {}, updated {}, transient {}",
                        report.discovered, report.updated, report.transient
                    ),
                    Ok(_) => {}
                    Err(error) => warn!("task membership reconciliation failed: {error:#}"),
                }
            }
        }

        self.stop_all_fine_timing()?;
        self.stop_queue_timing()?;
        let _ = self.struct_ops.take();
        uei_report!(&self.skel, uei)
    }
}

impl Drop for Scheduler<'_, '_> {
    fn drop(&mut self) {
        info!("unregistering {SCHEDULER_NAME}");
    }
}

fn monitor(interval: Duration, format: StatsFormat, shutdown: Arc<AtomicBool>) -> Result<()> {
    match format {
        StatsFormat::Text => stats::monitor(interval, shutdown),
        StatsFormat::Json => scx_utils::monitor_stats::<Metrics>(
            &[],
            interval,
            || shutdown.load(Ordering::Relaxed),
            move |metrics| {
                let mut stdout = std::io::stdout().lock();
                stdout.write_all(metrics.to_ndjson()?.as_bytes())?;
                stdout.flush()?;
                Ok(())
            },
        ),
    }
}

fn init_logging(verbose: bool) -> Result<()> {
    let level = if verbose {
        simplelog::LevelFilter::Debug
    } else {
        simplelog::LevelFilter::Info
    };
    let mut config = simplelog::ConfigBuilder::new();
    config
        .set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);
    simplelog::TermLogger::init(
        level,
        config.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;
    Ok(())
}

fn shutdown_flag() -> Result<Arc<AtomicBool>> {
    let shutdown = Arc::new(AtomicBool::new(false));
    let handler_flag = shutdown.clone();
    ctrlc::set_handler(move || handler_flag.store(true, Ordering::Relaxed))
        .context("installing signal handler")?;
    Ok(shutdown)
}

fn main() -> Result<()> {
    let opts = Opts::parse();
    let mode = resolve_mode(&opts)?;

    match mode {
        RunMode::HelpStats => {
            stats::server_data().describe_meta(&mut std::io::stdout(), None)?;
            return Ok(());
        }
        RunMode::Monitor(interval) => {
            init_logging(opts.verbose)?;
            return monitor(interval, opts.stats_format, shutdown_flag()?);
        }
        RunMode::Update(path) => {
            init_logging(opts.verbose)?;
            let response = control::update_policy_file(&path)?;
            println!(
                "activated policy generation {} ({})",
                response.generation, response.summary
            );
            return Ok(());
        }
        RunMode::SetThreadCell(assignment) => {
            init_logging(opts.verbose)?;
            println!("{}", control::set_running_thread_cell(assignment)?);
            return Ok(());
        }
        RunMode::ClearThreadCell(tid) => {
            init_logging(opts.verbose)?;
            println!("{}", control::clear_running_thread_cell(tid)?);
            return Ok(());
        }
        RunMode::Dump(path) => {
            let (_, policy) = load_policy(&path)?;
            let mask_tables = resolve_mask_tables(&policy)?;
            print!("{}{}", policy.dump(), dump_mask_tables(&mask_tables));
            if let Some(topology) = resolve_host_queue_topology(&policy)? {
                print!("{}", dump_queue_topology(&topology));
            }
            return Ok(());
        }
        RunMode::Launch(path) => {
            let (source, policy) = load_policy(&path)?;
            let mut runtime = RuntimePolicy::new(source, policy);
            init_logging(opts.verbose)?;
            info!(
                "{} {}",
                SCHEDULER_NAME,
                build_id::full_version(env!("CARGO_PKG_VERSION"))
            );

            let shutdown = shutdown_flag()?;
            if let Some(seconds) = opts.stats {
                let monitor_shutdown = shutdown.clone();
                let format = opts.stats_format;
                std::thread::spawn(move || {
                    if let Err(error) =
                        monitor(Duration::from_secs_f64(seconds), format, monitor_shutdown)
                    {
                        warn!("statistics monitor stopped: {error:#}");
                    } else {
                        debug!("statistics monitor stopped");
                    }
                });
            }

            let mut open_object = MaybeUninit::uninit();
            loop {
                let queue_topology = resolve_host_queue_topology(&runtime.compiled)?;
                if queue_topology.is_some() && opts.fairness != FairnessMode::Vtime {
                    bail!("[queues] policies require --fairness vtime");
                }
                let mask_tables = resolve_mask_tables(&runtime.compiled)?;
                let exit_info = {
                    let mut scheduler = Scheduler::init(
                        &opts,
                        &mut runtime,
                        &mask_tables,
                        queue_topology.as_ref(),
                        &mut open_object,
                    )?;
                    scheduler.run(shutdown.clone())?
                };
                if !exit_info.should_restart() {
                    break;
                }
                runtime.advance_for_restart()?;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::mem::{offset_of, size_of};
    use std::path::PathBuf;

    use clap::Parser;

    use super::*;
    use policy::{CompiledRung, InputSource, Opcode};

    fn policy_source() -> &'static str {
        r#"
[[rung]]
operation = "claim_idle"
scope = "previous_cpu"

[[rung]]
operation = "pick_idle"
scope = "task_allowed"
"#
    }

    fn raw_percpu_stats() -> Vec<Vec<Vec<u8>>> {
        (0..bpf_intf::snake_stat_SNAKE_NR_STATS)
            .map(|_| vec![0_u64.to_ne_bytes().to_vec(); 2])
            .collect()
    }

    #[test]
    fn callback_timing_sample_rate_accepts_disabled_and_bounded_powers_of_two() {
        for value in ["0", "1", "2", "64", "4096"] {
            assert_eq!(
                parse_callback_timing_sample_rate(value).unwrap(),
                value.parse::<u32>().unwrap()
            );
        }
        for value in ["3", "63", "4097", "8192", "not-a-number"] {
            assert!(parse_callback_timing_sample_rate(value).is_err(), "{value}");
        }
    }

    #[test]
    fn bpf_dsq_operations_stay_behind_the_shared_helpers() {
        const RAW_OPERATIONS: &[&str] = &[
            "scx_bpf_dsq_insert(",
            "scx_bpf_dsq_insert_vtime(",
            "scx_bpf_dsq_move(",
            "scx_bpf_dsq_move_vtime(",
            "scx_bpf_dsq_move_set_slice(",
            "scx_bpf_dsq_move_set_vtime(",
            "scx_bpf_dsq_move_to_local(",
            "scx_bpf_dsq_nr_queued(",
            "__COMPAT_scx_bpf_dsq_peek(",
            "scx_bpf_create_dsq(",
            "scx_bpf_destroy_dsq(",
        ];
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        for entry in fs::read_dir(&bpf_dir).expect("BPF source directory should exist") {
            let path = entry.expect("BPF source entry should be readable").path();
            if path.file_name().and_then(|name| name.to_str()) == Some("dsq.h")
                || !matches!(
                    path.extension().and_then(|ext| ext.to_str()),
                    Some("h" | "c")
                )
            {
                continue;
            }
            let source = fs::read_to_string(&path).expect("BPF source should be readable");
            for operation in RAW_OPERATIONS {
                assert!(
                    !source.contains(operation),
                    "{} bypasses dsq.h with {operation}",
                    path.display()
                );
            }
        }
        let shared = fs::read_to_string(bpf_dir.join("dsq.h"))
            .expect("shared DSQ helpers should be readable");
        assert!(shared.contains("fine_timing_record_dsq_operation"));
        assert!(shared.contains("static __noinline bool\ndsq_move_to_local"));
    }

    #[test]
    fn queue_timing_covers_fairness_and_direct_local_paths() {
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let fairness = fs::read_to_string(bpf_dir.join("fairness.h")).unwrap();
        let queue_fairness = fs::read_to_string(bpf_dir.join("queue_fairness.h")).unwrap();
        let main = fs::read_to_string(bpf_dir.join("main.bpf.c")).unwrap();
        let ladder = fs::read_to_string(bpf_dir.join("ladder.h")).unwrap();

        assert!(fairness.contains("static __noinline void\nqueue_timing_record_sample"));
        assert!(fairness.matches("queue_timing_record_insert(").count() >= 4);
        assert!(fairness.contains("queue_timing_complete(runtime);"));
        assert!(
            queue_fairness
                .matches("queue_timing_record_insert(")
                .count()
                >= 3
        );
        assert!(main.contains("queue_timing_record_insert("));
        assert!(ladder.contains("queue_timing_record_insert("));
        let rust =
            fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/main.rs"))
                .unwrap();
        assert!(rust.contains("snapshot.queue_timing = Some(self.queue_timing_inspection()?);"));
        assert!(
            !rust.contains("if self.queue_topology.is_some() {\n            snapshot.queue_timing")
        );
    }

    fn set_stat(raw: &mut [Vec<Vec<u8>>], index: u32, cpu_values: &[u64]) {
        raw[index as usize] = cpu_values
            .iter()
            .map(|value| value.to_ne_bytes().to_vec())
            .collect();
    }

    fn callback_timing_bytes(total_ns: u64, buckets: &[(usize, u64)]) -> Vec<u8> {
        let mut values = vec![0_u64; 1 + bpf_intf::SNAKE_CALLBACK_TIMING_BUCKETS as usize];
        values[0] = total_ns;
        for &(bucket, count) in buckets {
            values[1 + bucket] = count;
        }
        values.into_iter().flat_map(u64::to_ne_bytes).collect()
    }

    #[test]
    fn aggregates_percpu_callback_timing_by_stable_callback_name() {
        let empty = callback_timing_bytes(0, &[]);
        let mut raw = vec![
            vec![empty.clone(), empty.clone()];
            bpf_intf::snake_callback_SNAKE_NR_CALLBACKS as usize
        ];
        raw[bpf_intf::snake_callback_SNAKE_CALLBACK_SELECT_CPU as usize] = vec![
            callback_timing_bytes(100, &[(3, 2), (8, 1)]),
            callback_timing_bytes(250, &[(3, 5), (9, 4)]),
        ];

        let timing = aggregate_raw_callback_timing(&raw).expect("timing should aggregate");

        assert_eq!(timing.len(), 7);
        assert_eq!(timing["select_cpu"].total_ns, 350);
        assert_eq!(timing["select_cpu"].buckets[3], 7);
        assert_eq!(timing["select_cpu"].buckets[8], 1);
        assert_eq!(timing["select_cpu"].buckets[9], 4);
        assert_eq!(timing["enqueue"].buckets.iter().sum::<u64>(), 0);
        assert!(timing.contains_key("dispatch"));
        assert!(timing.contains_key("runnable"));
        assert!(timing.contains_key("running"));
        assert!(timing.contains_key("stopping"));
        assert!(timing.contains_key("quiescent"));
    }

    #[test]
    fn rung_timing_accumulator_separates_generations_ladders_and_indices() {
        let mut accumulator = RungTimingAccumulator::default();
        accumulator.record(7, bpf_intf::snake_rung_ladder_SNAKE_RUNG_LADDER_IDLE, 0, 8);
        accumulator.record(
            7,
            bpf_intf::snake_rung_ladder_SNAKE_RUNG_LADDER_IDLE,
            0,
            512,
        );
        accumulator.record(
            7,
            bpf_intf::snake_rung_ladder_SNAKE_RUNG_LADDER_DISPATCH,
            1,
            40,
        );
        accumulator.record(8, bpf_intf::snake_rung_ladder_SNAKE_RUNG_LADDER_IDLE, 0, 16);

        let timing = accumulator.generation(7).expect("timing should aggregate");
        assert_eq!(timing["idle:0"].total_ns, 520);
        assert_eq!(timing["idle:0"].buckets[3], 1);
        assert_eq!(timing["idle:0"].buckets[9], 1);
        assert_eq!(timing["dispatch:1"].total_ns, 40);
        assert_eq!(timing["dispatch:1"].buckets[5], 1);
        assert_eq!(accumulator.generation(8).unwrap()["idle:0"].total_ns, 16);
    }

    #[test]
    fn encodes_the_exact_c_rung_layout_and_zeros_reserved() {
        let encoded = encode_rung(CompiledRung {
            opcode: Opcode::PickIdle,
            input: InputSource::MaskTaskAllowed,
            flags: 0x1234,
            data: 0x0102_0304_0506_0708,
        });

        assert_eq!(size_of::<bpf_intf::snake_rung>(), 24);
        assert_eq!(offset_of!(bpf_intf::snake_rung, opcode), 0);
        assert_eq!(offset_of!(bpf_intf::snake_rung, input), 4);
        assert_eq!(offset_of!(bpf_intf::snake_rung, flags), 8);
        assert_eq!(offset_of!(bpf_intf::snake_rung, reserved), 12);
        assert_eq!(offset_of!(bpf_intf::snake_rung, data), 16);
        assert_eq!(encoded.opcode, 2);
        assert_eq!(encoded.input, 2);
        assert_eq!(encoded.flags, 0x1234);
        assert_eq!(encoded.reserved, 0);
        assert_eq!(encoded.data, 0x0102_0304_0506_0708);
    }

    #[test]
    fn encodes_complete_compiled_ladder() {
        let policy = policy::compile_policy(policy_source()).expect("policy should compile");
        let encoded = encode_ladder(&policy, 42).expect("ladder should encode");

        assert_eq!(bpf_intf::SNAKE_ABI_VERSION, 20);
        assert_eq!(size_of::<bpf_intf::snake_callback_timing>(), 520);
        assert_eq!(size_of::<bpf_intf::snake_fine_timing_config>(), 32);
        assert_eq!(size_of::<bpf_intf::snake_fine_timing_event>(), 48);
        assert_eq!(size_of::<bpf_intf::snake_queue_timing_counters>(), 24);
        assert_eq!(size_of::<bpf_intf::snake_queue_timing_event>(), 40);
        assert_eq!(size_of::<bpf_intf::snake_compiled_ladder>(), 352);
        assert_eq!(offset_of!(bpf_intf::snake_compiled_ladder, generation), 0);
        assert_eq!(
            offset_of!(bpf_intf::snake_compiled_ladder, policy_abi_version),
            8
        );
        assert_eq!(offset_of!(bpf_intf::snake_compiled_ladder, nr_rungs), 12);
        assert_eq!(
            offset_of!(bpf_intf::snake_compiled_ladder, nr_mask_tables),
            16
        );
        assert_eq!(
            offset_of!(bpf_intf::snake_compiled_ladder, fallback_mode),
            20
        );
        assert_eq!(offset_of!(bpf_intf::snake_compiled_ladder, rungs), 24);
        assert_eq!(
            offset_of!(bpf_intf::snake_compiled_ladder, nr_enqueue_rungs),
            216
        );
        assert_eq!(
            offset_of!(bpf_intf::snake_compiled_ladder, nr_dispatch_rungs),
            220
        );
        assert_eq!(
            offset_of!(bpf_intf::snake_compiled_ladder, enqueue_rungs),
            224
        );
        assert_eq!(
            offset_of!(bpf_intf::snake_compiled_ladder, dispatch_rungs),
            288
        );
        assert_eq!(encoded.generation, 42);
        assert_eq!(encoded.policy_abi_version, bpf_intf::SNAKE_ABI_VERSION);
        assert_eq!(encoded.nr_rungs, 2);
        assert_eq!(encoded.nr_mask_tables, 0);
        assert_eq!(
            encoded.fallback_mode,
            bpf_intf::snake_fallback_SNAKE_FALLBACK_PREVIOUS_CPU
        );
        assert_eq!(
            encoded.rungs[0].opcode,
            bpf_intf::snake_opcode_SNAKE_OP_CLAIM_IDLE
        );
        assert_eq!(
            encoded.rungs[1].opcode,
            bpf_intf::snake_opcode_SNAKE_OP_PICK_IDLE
        );
        assert_eq!(encoded.rungs[2].opcode, 0);
        assert_eq!(encoded.rungs[2].reserved, 0);
        assert_eq!(encoded.rungs[2].data, 0);
        assert_eq!(encoded.nr_enqueue_rungs, 0);
        assert_eq!(encoded.nr_dispatch_rungs, 0);
    }

    #[test]
    fn encodes_queue_callback_ladders_in_the_active_generation() {
        let policy = policy::compile_policy(
            r#"
[queues]
layout = "cell"

[[queues.enqueue]]
target = "cell"
[[queues.enqueue]]
target = "affinity"

[[queues.dispatch]]
source = "cell"
[[queues.dispatch]]
source = "affinity"

[[rung]]
operation = "pick_idle"
scope = "task_allowed"
"#,
        )
        .unwrap();
        let encoded = encode_ladder(&policy, 7).unwrap();

        assert_eq!(encoded.nr_enqueue_rungs, 2);
        assert_eq!(encoded.nr_dispatch_rungs, 2);
        assert_eq!(encoded.enqueue_rungs[0].opcode, 1);
        assert_eq!(encoded.enqueue_rungs[1].opcode, 2);
        assert_eq!(encoded.dispatch_rungs[0].opcode, 1);
        assert_eq!(encoded.dispatch_rungs[1].opcode, 2);
        assert!(encoded.enqueue_rungs.iter().all(|rung| rung.flags == 0));
        assert!(encoded.dispatch_rungs.iter().all(|rung| rung.flags == 0));

        let reversed = policy::compile_policy(
            r#"
[queues]
layout = "cell"
enqueue = [{ target = "cell" }, { target = "affinity" }]
dispatch = [{ source = "affinity" }, { source = "cell" }]

[[rung]]
operation = "pick_idle"
scope = "task_allowed"
"#,
        )
        .unwrap();
        let reversed = encode_ladder(&reversed, 8).unwrap();

        assert_eq!(reversed.dispatch_rungs[0].opcode, 2);
        assert_eq!(reversed.dispatch_rungs[1].opcode, 1);
    }

    #[test]
    fn encodes_min_vtime_dispatch_opcode() {
        let policy = policy::compile_policy(
            r#"
[queues]
layout = "cell"
enqueue = [{ target = "cell" }, { target = "affinity" }]
dispatch = [{ operation = "min_vtime" }]

[[rung]]
operation = "pick_idle"
scope = "task_allowed"
"#,
        )
        .unwrap();
        let encoded = encode_ladder(&policy, 7).unwrap();

        assert_eq!(encoded.nr_dispatch_rungs, 1);
        assert_eq!(encoded.dispatch_rungs[0].opcode, 3);
        assert_eq!(encoded.dispatch_rungs[0].flags, 0);
    }

    #[test]
    fn live_queue_callback_updates_may_add_but_not_remove_sources() {
        let compile_callbacks = |enqueue: &str, dispatch: &str| {
            policy::compile_policy(&format!(
                r#"
[queues]
layout = "cell"
enqueue = {enqueue}
dispatch = {dispatch}
[[rung]]
operation = "pick_idle"
scope = "task_allowed"
"#,
            ))
            .unwrap()
        };
        let affinity =
            compile_callbacks("[{ target = \"affinity\" }]", "[{ source = \"affinity\" }]");
        let full = compile_callbacks(
            "[{ target = \"cell\" }, { target = \"affinity\" }]",
            "[{ source = \"affinity\" }, { source = \"cell\" }]",
        );
        let reordered = compile_callbacks(
            "[{ target = \"cell\" }, { target = \"affinity\" }]",
            "[{ source = \"cell\" }, { source = \"affinity\" }]",
        );
        let min_vtime = compile_callbacks(
            "[{ target = \"cell\" }, { target = \"affinity\" }]",
            "[{ operation = \"min_vtime\" }]",
        );

        assert!(validate_queue_callback_replacement(&affinity, &full).is_ok());
        assert!(validate_queue_callback_replacement(&full, &reordered).is_ok());
        assert!(validate_queue_callback_replacement(&full, &min_vtime).is_ok());
        assert!(validate_queue_callback_replacement(&min_vtime, &reordered).is_ok());
        let error = validate_queue_callback_replacement(&full, &affinity)
            .unwrap_err()
            .to_string();
        assert!(error.contains("cannot remove active queue enqueue target `cell`"));
    }

    #[test]
    fn fairness_modes_match_the_bpf_abi() {
        assert_eq!(
            bpf_intf::snake_fairness_mode_SNAKE_FAIRNESS_FIFO,
            FairnessMode::Fifo as u32
        );
        assert_eq!(
            bpf_intf::snake_fairness_mode_SNAKE_FAIRNESS_EEVDF,
            FairnessMode::Eevdf as u32
        );
        assert_eq!(
            bpf_intf::snake_fairness_mode_SNAKE_FAIRNESS_VTIME,
            FairnessMode::Vtime as u32
        );
        assert_eq!(
            u64::from(bpf_intf::SNAKE_EEVDF_SLICE_NS),
            scx_snake::fairness::EEVDF_SLICE_NS
        );
        assert_eq!(
            u64::from(bpf_intf::SNAKE_VTIME_SLICE_NS),
            scx_snake::fairness::VTIME_SLICE_NS
        );
        assert_eq!(
            u64::from(bpf_intf::SNAKE_VTIME_MIN_SLICE_NS),
            scx_snake::fairness::VTIME_MIN_SLICE_NS
        );
        assert_eq!(bpf_intf::SNAKE_VTIME_GLOBAL_DSQ, 2);
        assert_eq!(bpf_intf::SNAKE_VTIME_CPU_DSQ_BASE, 3);
        assert!(
            bpf_intf::SNAKE_VTIME_CPU_DSQ_BASE + bpf_intf::SNAKE_MAX_CPUS
                > bpf_intf::SNAKE_VTIME_GLOBAL_DSQ
        );
    }

    #[test]
    fn queue_topology_encoding_matches_the_bpf_abi() {
        let policy = policy::compile_policy(
            r#"
[queues]
layout = "cell_llc"
[[cell]]
id = 7
cpus = "0-3"
[[rung]]
operation = "pick_idle"
scope = "task_cell"
"#,
        )
        .unwrap();
        let topology = queue_topology::resolve_queue_topology(
            &policy,
            &std::collections::BTreeSet::from([0, 1, 2, 3]),
            &BTreeMap::from([(0, 10), (1, 10), (2, 20), (3, 20)]),
        )
        .unwrap()
        .unwrap();
        let encoded = encode_queue_topology(&topology).unwrap();

        assert_eq!(encoded.header.layout, bpf_intf::SNAKE_QUEUE_LAYOUT_CELL_LLC);
        assert_eq!(encoded.header.nr_cells, 2);
        assert_eq!(encoded.header.nr_cpus, 4);
        assert_eq!(encoded.cell_lookup[0], 1);
        assert_eq!(encoded.cell_lookup[7], 2);
        for queue in encoded
            .normal_queues
            .iter()
            .take(encoded.header.nr_normal_queues as usize)
        {
            assert_eq!(queue.clock_index, queue.cell_index);
        }
        assert_eq!(
            u64::from(bpf_intf::SNAKE_AFFINITY_DSQ_BASE) & (3_u64 << 62),
            0
        );
        assert_eq!(
            u64::from(bpf_intf::SNAKE_NORMAL_DSQ_BASE) & (3_u64 << 62),
            0
        );
        assert!(bpf_intf::SNAKE_AFFINITY_DSQ_BASE > bpf_intf::SNAKE_VTIME_CPU_DSQ_BASE);
        assert!(bpf_intf::SNAKE_NORMAL_DSQ_BASE > bpf_intf::SNAKE_AFFINITY_DSQ_BASE);
    }

    #[test]
    fn queue_topology_encoding_accepts_sparse_online_cpu_ids() {
        let policy = policy::compile_policy(
            r#"
[queues]
layout = "cell"
[[cell]]
id = 7
cpus = "3"
[[rung]]
operation = "pick_idle"
scope = "task_cell"
"#,
        )
        .unwrap();
        let topology = queue_topology::resolve_queue_topology(
            &policy,
            &std::collections::BTreeSet::from([1, 3]),
            &BTreeMap::from([(1, 10), (3, 20)]),
        )
        .unwrap()
        .unwrap();
        let encoded = encode_queue_topology(&topology).unwrap();

        assert_eq!(encoded.header.nr_cpus, 2);
        assert_eq!(encoded.cpu_queues[0].valid, 0);
        assert_eq!(encoded.cpu_queues[1].valid, 1);
        assert_eq!(encoded.cpu_queues[2].valid, 0);
        assert_eq!(encoded.cpu_queues[3].valid, 1);
    }

    #[test]
    fn runtime_ladder_slots_have_disjoint_storage() {
        assert_eq!(runtime_policy::inactive_slot(0).unwrap(), 1);
        assert_eq!(runtime_policy::inactive_slot(1).unwrap(), 0);
        assert!(runtime_policy::inactive_slot(2).is_err());

        let slot_zero_mask = runtime_policy::mask_data_index(0, 3, 1023).unwrap();
        let slot_one_mask = runtime_policy::mask_data_index(1, 0, 0).unwrap();
        assert!(slot_zero_mask < slot_one_mask);
        assert_eq!(
            runtime_policy::stat_index(1, 0).unwrap(),
            bpf_intf::snake_stat_SNAKE_NR_STATS
        );
        assert_eq!(
            runtime_policy::callback_timing_index(1, 0).unwrap(),
            bpf_intf::snake_callback_SNAKE_NR_CALLBACKS
        );
        assert!(runtime_policy::callback_timing_index(
            0,
            bpf_intf::snake_callback_SNAKE_NR_CALLBACKS
        )
        .is_err());
        assert!(runtime_policy::mask_data_index(2, 0, 0).is_err());
        assert!(runtime_policy::mask_data_index(0, 4, 0).is_err());
        assert!(runtime_policy::mask_data_index(0, 0, 1024).is_err());
    }

    #[test]
    fn rust_mask_table_instruction_matches_the_bpf_abi() {
        let compiled = policy::compile_policy(
            r#"
[[rung]]
operation = "pick_idle"
scope = "previous_llc"
"#,
        )
        .expect("policy should compile");
        let encoded = encode_rung(compiled.rungs[0]);

        assert_eq!(
            encoded.opcode,
            bpf_intf::snake_opcode_SNAKE_OP_PICK_IDLE_MASK_TABLE
        );
        assert_eq!(
            encoded.input,
            bpf_intf::snake_input_source_SNAKE_INPUT_CPU_PREV
        );
        assert_eq!(encoded.flags, bpf_intf::SNAKE_RUNG_F_INTERSECT_TASK_ALLOWED);
        assert_eq!(encoded.data, 0);
        assert_eq!(
            policy::MAX_MASK_TABLES as u32,
            bpf_intf::SNAKE_MAX_MASK_TABLES
        );
    }

    #[test]
    fn rust_whole_core_instruction_matches_the_bpf_abi() {
        let compiled = policy::compile_policy(
            r#"
[[rung]]
operation = "pick_idle_core"
scope = "previous_llc"
"#,
        )
        .expect("policy should compile");
        let encoded = encode_rung(compiled.rungs[0]);

        assert_eq!(
            encoded.opcode,
            bpf_intf::snake_opcode_SNAKE_OP_PICK_IDLE_MASK_TABLE
        );
        assert_eq!(
            encoded.flags,
            bpf_intf::SNAKE_RUNG_F_INTERSECT_TASK_ALLOWED | bpf_intf::SNAKE_RUNG_F_PICK_IDLE_CORE
        );
    }

    #[test]
    fn rust_random_idle_policy_matches_the_bpf_abi() {
        let compiled = policy::compile_policy(
            r#"
fallback = "any_allowed"

[[rung]]
operation = "pick_random_idle"
scope = "task_allowed"
"#,
        )
        .expect("policy should compile");
        let encoded = encode_rung(compiled.rungs[0]);

        assert_eq!(
            encoded.opcode,
            bpf_intf::snake_opcode_SNAKE_OP_PICK_RANDOM_IDLE
        );
        assert_eq!(
            encoded.input,
            bpf_intf::snake_input_source_SNAKE_INPUT_MASK_TASK_ALLOWED
        );
        assert_eq!(encoded.flags, 0);
        assert_eq!(encoded.data, 0);
        assert_eq!(
            compiled.fallback as u32,
            bpf_intf::snake_fallback_SNAKE_FALLBACK_ANY_ALLOWED
        );
    }

    #[test]
    fn rust_random_llc_instruction_matches_the_bpf_abi() {
        let compiled = policy::compile_policy(
            r#"
[[rung]]
operation = "pick_random_idle"
scope = "previous_llc"
"#,
        )
        .expect("policy should compile");
        let encoded = encode_rung(compiled.rungs[0]);

        assert_eq!(
            encoded.opcode,
            bpf_intf::snake_opcode_SNAKE_OP_PICK_RANDOM_IDLE
        );
        assert_eq!(
            encoded.input,
            bpf_intf::snake_input_source_SNAKE_INPUT_CPU_PREV
        );
        assert_eq!(encoded.flags, bpf_intf::SNAKE_RUNG_F_INTERSECT_TASK_ALLOWED);
        assert_eq!(encoded.data, 0);
        assert_eq!(compiled.mask_tables.len(), 1);
    }

    #[test]
    fn rust_random_whole_core_instruction_matches_the_bpf_abi() {
        let compiled = policy::compile_policy(
            r#"
[[rung]]
operation = "pick_random_idle_core"
scope = "previous_llc"
"#,
        )
        .expect("policy should compile");
        let encoded = encode_rung(compiled.rungs[0]);

        assert_eq!(
            encoded.opcode,
            bpf_intf::snake_opcode_SNAKE_OP_PICK_RANDOM_IDLE
        );
        assert_eq!(
            encoded.flags,
            bpf_intf::SNAKE_RUNG_F_INTERSECT_TASK_ALLOWED | bpf_intf::SNAKE_RUNG_F_PICK_IDLE_CORE
        );
    }

    #[test]
    fn rust_kernel_default_instruction_matches_the_bpf_abi() {
        let compiled = policy::compile_policy(
            r#"
[[rung]]
operation = "kernel_default"
scope = "task_allowed"
"#,
        )
        .expect("policy should compile");
        let encoded = encode_rung(compiled.rungs[0]);

        assert_eq!(
            encoded.opcode,
            bpf_intf::snake_opcode_SNAKE_OP_KERNEL_DEFAULT
        );
        assert_eq!(
            encoded.input,
            bpf_intf::snake_input_source_SNAKE_INPUT_MASK_TASK_ALLOWED
        );
        assert_eq!(encoded.flags, 0);
        assert_eq!(encoded.data, 0);
    }

    #[test]
    fn rust_sync_wake_instruction_matches_the_bpf_abi() {
        let compiled = policy::compile_policy(
            r#"
[[rung]]
operation = "sync_wake_affine"
scope = "task_allowed"
"#,
        )
        .expect("policy should compile");
        let encoded = encode_rung(compiled.rungs[0]);

        assert_eq!(
            encoded.opcode,
            bpf_intf::snake_opcode_SNAKE_OP_SYNC_WAKE_AFFINE
        );
        assert_eq!(
            encoded.input,
            bpf_intf::snake_input_source_SNAKE_INPUT_MASK_TASK_ALLOWED
        );
        assert_eq!(encoded.flags, 0);
        assert_eq!(encoded.data, 1_u64 << 32);
        assert_eq!(compiled.mask_tables.len(), 2);
    }

    #[test]
    fn rust_task_cell_instruction_matches_the_bpf_abi() {
        let compiled = policy::compile_policy(
            r#"
[[cell]]
id = 7
cpus = "0-1"

[[rung]]
operation = "pick_idle"
scope = "task_cell"
"#,
        )
        .expect("cell policy should compile");
        let encoded = encode_rung(compiled.rungs[0]);

        assert_eq!(
            encoded.opcode,
            bpf_intf::snake_opcode_SNAKE_OP_PICK_IDLE_MASK_TABLE
        );
        assert_eq!(
            encoded.input,
            bpf_intf::snake_input_source_SNAKE_INPUT_TASK_CELL
        );
        assert_eq!(encoded.flags, bpf_intf::SNAKE_RUNG_F_INTERSECT_TASK_ALLOWED);
        assert_eq!(encoded.data, 0);
        assert_eq!(size_of::<bpf_intf::snake_task_cell>(), 16);
        assert_eq!(policy::MAX_CELL_IDS, bpf_intf::SNAKE_MAX_CPUS);
    }

    #[test]
    fn rust_borrowing_instruction_matches_the_bpf_abi() {
        let compiled = policy::compile_policy(
            r#"
[queues]
layout = "cell"
[[cell]]
id = 7
cpus = "0-3"
[[rung]]
operation = "pick_idle_core"
scope = "task_cell_borrowable"
"#,
        )
        .expect("borrowing policy should compile");
        let encoded = encode_rung(compiled.rungs[0]);

        assert_eq!(
            encoded.opcode,
            bpf_intf::snake_opcode_SNAKE_OP_PICK_IDLE_QUEUE_MASK
        );
        assert_eq!(
            encoded.input,
            bpf_intf::snake_input_source_SNAKE_INPUT_QUEUE_CELL
        );
        assert_eq!(encoded.flags, bpf_intf::SNAKE_RUNG_F_PICK_IDLE_CORE);
        assert_eq!(
            encoded.data,
            u64::from(bpf_intf::snake_queue_mask_kind_SNAKE_QUEUE_MASK_BORROWABLE)
        );
        assert!(compiled.mask_tables.is_empty());
    }

    #[test]
    fn requires_policy_for_launch_and_dump_but_not_monitor_or_help() {
        let launch =
            Opts::try_parse_from(["scx_snake"]).expect("argument parsing itself should succeed");
        assert!(resolve_mode(&launch)
            .expect_err("launch without a policy must fail")
            .to_string()
            .contains("--policy"));

        let dump = Opts::try_parse_from(["scx_snake", "--dump-compiled-policy"])
            .expect("argument parsing itself should succeed");
        assert!(resolve_mode(&dump)
            .expect_err("dump without a policy must fail")
            .to_string()
            .contains("--policy"));

        let monitor = Opts::try_parse_from(["scx_snake", "--monitor", "1"])
            .expect("monitor arguments should parse");
        assert!(matches!(resolve_mode(&monitor), Ok(RunMode::Monitor(_))));

        let help = Opts::try_parse_from(["scx_snake", "--help-stats"])
            .expect("stats help arguments should parse");
        assert!(matches!(resolve_mode(&help), Ok(RunMode::HelpStats)));

        let with_policy = Opts::try_parse_from([
            "scx_snake",
            "--policy",
            "/tmp/snake.toml",
            "--dump-compiled-policy",
        ])
        .expect("dump arguments should parse");
        assert!(matches!(
            resolve_mode(&with_policy),
            Ok(RunMode::Dump(path)) if path == PathBuf::from("/tmp/snake.toml")
        ));
    }

    #[test]
    fn rejects_contradictory_operational_modes() {
        let monitor_and_dump = Opts::try_parse_from([
            "scx_snake",
            "--monitor",
            "1",
            "--dump-compiled-policy",
            "--policy",
            "/tmp/snake.toml",
        ])
        .expect("individual arguments should parse");
        assert!(resolve_mode(&monitor_and_dump).is_err());

        let help_and_monitor =
            Opts::try_parse_from(["scx_snake", "--help-stats", "--monitor", "1"])
                .expect("individual arguments should parse");
        assert!(resolve_mode(&help_and_monitor).is_err());
    }

    #[test]
    fn rejects_eevdf_mode_for_non_launch_operations() {
        for args in [
            vec!["scx_snake", "--fairness", "eevdf", "--monitor", "1"],
            vec!["scx_snake", "--fairness", "eevdf", "--help-stats"],
            vec![
                "scx_snake",
                "--fairness",
                "eevdf",
                "--policy",
                "/tmp/snake.toml",
                "--dump-compiled-policy",
            ],
        ] {
            let opts = Opts::try_parse_from(args).expect("arguments should parse");
            assert!(resolve_mode(&opts)
                .expect_err("EEVDF must be selected only for launch")
                .to_string()
                .contains("only valid when launching"));
        }
    }

    #[test]
    fn update_policy_is_a_standalone_run_mode() {
        let update =
            Opts::try_parse_from(["scx_snake", "--update-policy", "/tmp/replacement.toml"])
                .expect("update arguments should parse");
        assert!(matches!(
            resolve_mode(&update),
            Ok(RunMode::Update(path)) if path == PathBuf::from("/tmp/replacement.toml")
        ));

        assert!(Opts::try_parse_from([
            "scx_snake",
            "--update-policy",
            "/tmp/replacement.toml",
            "--policy",
            "/tmp/initial.toml",
        ])
        .is_err());
        assert!(Opts::try_parse_from([
            "scx_snake",
            "--update-policy",
            "/tmp/replacement.toml",
            "--monitor",
            "1",
        ])
        .is_err());
    }

    #[test]
    fn thread_cell_updates_parse_as_standalone_control_modes() {
        let set = Opts::try_parse_from(["scx_snake", "--set-thread-cell", "4812:7"])
            .expect("set command should parse");
        assert!(matches!(
            resolve_mode(&set),
            Ok(RunMode::SetThreadCell(ThreadCellAssignment {
                tid: 4812,
                cell_id: 7
            }))
        ));

        let clear = Opts::try_parse_from(["scx_snake", "--clear-thread-cell", "4812"])
            .expect("clear command should parse");
        assert!(matches!(
            resolve_mode(&clear),
            Ok(RunMode::ClearThreadCell(4812))
        ));
    }

    #[test]
    fn aggregates_raw_percpu_stats_with_max_gauge_and_semantic_rung_labels() {
        let policy = policy::compile_policy(policy_source()).expect("policy should compile");
        let mut raw = raw_percpu_stats();
        set_stat(
            &mut raw,
            bpf_intf::snake_stat_SNAKE_STAT_SELECT_CALLS,
            &[7, 11],
        );
        set_stat(
            &mut raw,
            bpf_intf::snake_stat_SNAKE_STAT_SELECT_LATENCY_NS,
            &[100, 250],
        );
        set_stat(
            &mut raw,
            bpf_intf::snake_stat_SNAKE_STAT_SELECT_LATENCY_MAX_NS,
            &[900, 700],
        );
        set_stat(
            &mut raw,
            bpf_intf::snake_stat_SNAKE_STAT_RUNTIME_NS,
            &[25_000, 75_000],
        );
        set_stat(
            &mut raw,
            bpf_intf::snake_stat_SNAKE_STAT_VTIME_CPU_ENQUEUES,
            &[13, 17],
        );
        set_stat(
            &mut raw,
            bpf_intf::snake_stat_SNAKE_STAT_VTIME_CPU_DISPATCHES,
            &[11, 19],
        );
        set_stat(
            &mut raw,
            bpf_intf::snake_stat_SNAKE_STAT_MEMBERSHIP_NO_CELL_RUNS,
            &[7, 11],
        );
        set_stat(
            &mut raw,
            bpf_intf::snake_stat_SNAKE_STAT_MEMBERSHIP_INVALID_RUNS,
            &[0, 1],
        );
        set_stat(
            &mut raw,
            bpf_intf::snake_stat_SNAKE_STAT_RUNG_ATTEMPT_BASE,
            &[4, 6],
        );
        set_stat(
            &mut raw,
            bpf_intf::snake_stat_SNAKE_STAT_RUNG_HIT_BASE + 1,
            &[2, 3],
        );

        let metrics = aggregate_raw_stats(&raw, &policy, 42, FairnessMode::Eevdf)
            .expect("stats should aggregate");

        assert_eq!(metrics.policy_generation, 42);
        assert_eq!(metrics.select_calls, 18);
        assert_eq!(metrics.select_latency_ns, 350);
        assert_eq!(metrics.select_latency_max_ns, 900);
        assert_eq!(metrics.vtime_cpu_enqueues, 30);
        assert_eq!(metrics.vtime_cpu_dispatches, 30);
        assert_eq!(metrics.membership_no_cell_runs, 18);
        assert_eq!(metrics.membership_invalid_runs, 1);
        assert_eq!(metrics.cpus[&0].runtime_ns, 25_000);
        assert_eq!(metrics.cpus[&1].runtime_ns, 75_000);
        assert_eq!(metrics.rungs[&0].attempts, 10);
        assert_eq!(metrics.rungs[&0].operation, "claim_idle");
        assert_eq!(metrics.rungs[&0].scope, "previous_cpu");
        assert_eq!(metrics.rungs[&1].hits, 5);
        assert_eq!(metrics.rungs[&1].operation, "pick_idle");
        assert_eq!(metrics.rungs[&1].scope, "task_allowed");
    }

    #[test]
    fn labels_partition_and_parent_llc_placement_stats_separately() {
        let policy = policy::compile_policy(
            r#"
[[partition]]
name = "previous_llc_half"
provider = "split_llcs"
parts = 2

[[rung]]
operation = "pick_idle"
scope = "previous_llc_half"

[[rung]]
operation = "pick_idle"
scope = "previous_llc"
"#,
        )
        .expect("policy should compile");

        let metrics = aggregate_raw_stats(&raw_percpu_stats(), &policy, 1, FairnessMode::Fifo)
            .expect("stats should aggregate");

        assert_eq!(metrics.rungs[&0].scope, "previous_llc_half");
        assert_eq!(metrics.rungs[&1].scope, "previous_llc");
    }

    #[test]
    fn labels_whole_core_idle_stats_separately() {
        let policy = policy::compile_policy(
            r#"
[[rung]]
operation = "pick_idle_core"
scope = "previous_llc"
"#,
        )
        .expect("policy should compile");

        let metrics = aggregate_raw_stats(&raw_percpu_stats(), &policy, 1, FairnessMode::Fifo)
            .expect("stats should aggregate");

        assert_eq!(metrics.rungs[&0].operation, "pick_idle_core");
        assert_eq!(metrics.rungs[&0].scope, "previous_llc");
    }

    #[test]
    fn labels_previous_node_placement_stats() {
        let policy = policy::compile_policy(
            r#"
[[rung]]
operation = "pick_idle"
scope = "previous_node"
"#,
        )
        .expect("policy should compile");

        let metrics = aggregate_raw_stats(&raw_percpu_stats(), &policy, 1, FairnessMode::Fifo)
            .expect("stats should aggregate");

        assert_eq!(metrics.rungs[&0].operation, "pick_idle");
        assert_eq!(metrics.rungs[&0].scope, "previous_node");
    }

    #[test]
    fn labels_random_llc_placement_stats() {
        let policy = policy::compile_policy(
            r#"
[[rung]]
operation = "pick_random_idle"
scope = "previous_llc"
"#,
        )
        .expect("policy should compile");

        let metrics = aggregate_raw_stats(&raw_percpu_stats(), &policy, 1, FairnessMode::Fifo)
            .expect("stats should aggregate");

        assert_eq!(metrics.rungs[&0].operation, "pick_random_idle");
        assert_eq!(metrics.rungs[&0].scope, "previous_llc");
    }

    #[test]
    fn labels_random_whole_core_placement_stats() {
        let policy = policy::compile_policy(
            r#"
[[rung]]
operation = "pick_random_idle_core"
scope = "previous_llc"
"#,
        )
        .expect("policy should compile");

        let metrics = aggregate_raw_stats(&raw_percpu_stats(), &policy, 1, FairnessMode::Fifo)
            .expect("stats should aggregate");

        assert_eq!(metrics.rungs[&0].operation, "pick_random_idle_core");
        assert_eq!(metrics.rungs[&0].scope, "previous_llc");
    }

    #[test]
    fn labels_sync_wake_affine_stats() {
        let policy = policy::compile_policy(
            r#"
[[rung]]
operation = "sync_wake_affine"
scope = "task_allowed"
"#,
        )
        .expect("policy should compile");

        let metrics = aggregate_raw_stats(&raw_percpu_stats(), &policy, 1, FairnessMode::Fifo)
            .expect("stats should aggregate");

        assert_eq!(metrics.rungs[&0].operation, "sync_wake_affine");
        assert_eq!(metrics.rungs[&0].scope, "task_allowed");
    }

    #[test]
    fn fine_timing_sessions_are_independent_per_callback() {
        use crate::fine_timing::{FineTimingCallback, FineTimingState};

        let mut state = FineTimingState::default();
        let select = state.start(FineTimingCallback::SelectCpu, 7, 900);
        let enqueue = state.start(FineTimingCallback::Enqueue, 7, 1_000);
        let dispatch = state.start(FineTimingCallback::Dispatch, 7, 1_100);

        assert_ne!(select.session_id, enqueue.session_id);
        assert_ne!(enqueue.session_id, dispatch.session_id);
        assert!(state.is_enabled(FineTimingCallback::SelectCpu));
        assert!(state.is_enabled(FineTimingCallback::Enqueue));
        assert!(state.is_enabled(FineTimingCallback::Dispatch));

        state.stop(FineTimingCallback::Enqueue, 2_000);
        assert!(!state.is_enabled(FineTimingCallback::Enqueue));
        assert!(state.is_enabled(FineTimingCallback::Dispatch));
        assert_eq!(
            state
                .session(FineTimingCallback::Enqueue)
                .and_then(|session| session.stopped_at_ms),
            Some(2_000)
        );
        assert_eq!(
            state
                .session(FineTimingCallback::Dispatch)
                .and_then(|session| session.stopped_at_ms),
            None
        );
    }

    #[test]
    fn dsq_fine_timing_is_available_for_every_fairness_mode() {
        use crate::fine_timing::FineTimingCallback;

        assert!(fine_timing_available(
            FineTimingCallback::Dispatch,
            FairnessMode::Fifo,
            false,
        ));
        assert!(fine_timing_available(
            FineTimingCallback::Enqueue,
            FairnessMode::Fifo,
            false,
        ));
        assert!(fine_timing_available(
            FineTimingCallback::Dispatch,
            FairnessMode::Vtime,
            false,
        ));
        assert!(fine_timing_available(
            FineTimingCallback::Dispatch,
            FairnessMode::Vtime,
            true,
        ));
    }

    #[test]
    fn fine_timing_accumulator_filters_sessions_and_buckets_samples() {
        use crate::fine_timing::{stages, FineTimingCallback};

        let mut accumulator = FineTimingAccumulator::default();
        let stage = stages(FineTimingCallback::SelectCpu)[0].id;
        accumulator.reset(FineTimingCallback::SelectCpu, 7);
        accumulator.record(6, stage, 1_024);
        accumulator.record(7, stage, 1_024);
        accumulator.record(7, stage, 1_500);

        let metrics = accumulator.metrics(7, stage);
        assert_eq!(metrics.total_ns, 2_524);
        assert_eq!(metrics.buckets.iter().sum::<u64>(), 2);
        assert_eq!(metrics.buckets[10], 2);
        assert_eq!(accumulator.metrics(8, stage).buckets.iter().sum::<u64>(), 0);

        accumulator.stop(FineTimingCallback::SelectCpu);
        accumulator.record(7, stage, 2_000);
        assert_eq!(accumulator.metrics(7, stage), metrics);
    }

    #[test]
    fn fine_timing_accumulator_expands_moves_into_source_and_target_operations() {
        use crate::fine_timing::FineTimingCallback;

        let accumulator = Mutex::new(FineTimingAccumulator::default());
        accumulator
            .lock()
            .expect("accumulator should lock")
            .reset(FineTimingCallback::Dispatch, 17);
        let event = bpf_intf::snake_fine_timing_event {
            session_id: 17,
            elapsed_ns: 131_072,
            source_dsq_id: u64::from(bpf_intf::SNAKE_FIFO_DSQ),
            target_dsq_id: 13_835_058_055_282_163_719,
            stage: 0,
            operation: bpf_intf::snake_dsq_operation_SNAKE_DSQ_OP_MOVE_TO_LOCAL,
            outcome: bpf_intf::snake_dsq_outcome_SNAKE_DSQ_OUTCOME_SUCCESS,
            queue_class: bpf_intf::SNAKE_QUEUE_CLASS_NORMAL,
        };
        assert_eq!(relay_fine_timing(bytes_of(&event), &accumulator), 0);

        let operations = accumulator
            .lock()
            .expect("accumulator should lock")
            .dsq_operations(17);
        assert_eq!(operations.len(), 2);
        assert_eq!(operations[0].dsq_id, u64::from(bpf_intf::SNAKE_FIFO_DSQ));
        assert_eq!(operations[0].operation, "remove");
        assert_eq!(operations[0].outcome, "success");
        assert_eq!(operations[0].timing.total_ns, 131_072);
        assert_eq!(operations[0].timing.buckets.iter().sum::<u64>(), 1);
        assert_eq!(operations[1].dsq_id, 13_835_058_055_282_163_719);
        assert_eq!(operations[1].operation, "insert");
        assert_eq!(operations[1].outcome, "success");
        let helper = accumulator
            .lock()
            .expect("accumulator should lock")
            .metrics(
                17,
                bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_DISPATCH_MOVE_TO_LOCAL,
            );
        let success = accumulator
            .lock()
            .expect("accumulator should lock")
            .metrics(
                17,
                bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_DISPATCH_MOVE_NORMAL_SUCCESS,
            );
        assert_eq!(helper.buckets.iter().sum::<u64>(), 1);
        assert_eq!(success.buckets.iter().sum::<u64>(), 1);
    }

    #[test]
    fn fine_timing_accumulator_clear_discards_history_and_rejects_old_events() {
        use crate::fine_timing::{stages, FineTimingCallback};

        let mut accumulator = FineTimingAccumulator::default();
        let stage = stages(FineTimingCallback::SelectCpu)[0].id;
        accumulator.reset(FineTimingCallback::SelectCpu, 11);
        accumulator.record(11, stage, 900);

        accumulator.clear();
        accumulator.record(11, stage, 1_100);

        let metrics = accumulator.metrics(11, stage);
        assert_eq!(metrics.total_ns, 0);
        assert_eq!(metrics.buckets.iter().sum::<u64>(), 0);
    }

    #[test]
    fn queue_timing_relay_decodes_the_bpf_event_layout() {
        let accumulator = Mutex::new(queue_timing::QueueTimingAccumulator::default());
        accumulator
            .lock()
            .expect("accumulator lock should succeed")
            .reset(41);
        let event = bpf_intf::snake_queue_timing_event {
            session_id: 41,
            dsq_id: 0x2000_0007,
            residence_ns: 512,
            cell_index: 3,
            queue_class: bpf_intf::SNAKE_QUEUE_CLASS_AFFINITY,
            depth_after_insert: 12,
            depth_after_dispatch: 11,
        };

        assert_eq!(relay_queue_timing(bytes_of(&event), &accumulator), 0);

        let dsqs = accumulator
            .lock()
            .expect("accumulator lock should succeed")
            .dsqs(41);
        assert_eq!(dsqs.len(), 1);
        assert_eq!(dsqs[0].dsq_id, 0x2000_0007);
        assert_eq!(dsqs[0].cell_index, 3);
        assert_eq!(dsqs[0].queue_class, queue_timing::QueueClass::Affinity);
        assert_eq!(dsqs[0].residence.total_ns, 512);
        assert_eq!(dsqs[0].depth.samples, 2);
        assert_eq!(dsqs[0].depth.latest, 11);
        assert_eq!(dsqs[0].depth.max, 12);
    }

    #[test]
    fn fine_timing_stage_inventory_covers_enqueue_and_dispatch_hotspots() {
        use crate::fine_timing::{stages, FineTimingCallback};

        let select = stages(FineTimingCallback::SelectCpu);
        let enqueue = stages(FineTimingCallback::Enqueue);
        let dispatch = stages(FineTimingCallback::Dispatch);
        let names = |inventory: &[crate::fine_timing::FineTimingStage]| {
            inventory.iter().map(|stage| stage.name).collect::<Vec<_>>()
        };

        assert!(names(select).contains(&"acquire_ladder"));
        assert!(names(select).contains(&"policy_ladder"));
        assert!(names(select).contains(&"queue_target"));
        assert!(names(select).contains(&"direct_insert"));
        assert!(names(select).contains(&"strict_preempt"));
        assert!(names(select).contains(&"fallback"));
        assert!(names(select).contains(&"finish"));
        assert!(names(enqueue).contains(&"prepare_route_lookup"));
        assert!(names(enqueue).contains(&"prepare_task_storage"));
        assert!(names(enqueue).contains(&"prepare_cell_clock"));
        assert!(names(enqueue).contains(&"prepare_credit_clamp"));
        assert!(names(enqueue).contains(&"normal_dsq_insert"));
        assert!(names(enqueue).contains(&"affinity_dsq_insert"));
        assert!(names(enqueue).contains(&"affinity_path"));
        assert!(names(dispatch).contains(&"remote_scan_1_queue"));
        assert!(names(dispatch).contains(&"remote_scan_2_4_queues"));
        assert!(names(dispatch).contains(&"remote_scan_5_8_queues"));
        assert!(names(dispatch).contains(&"remote_scan_9_plus_queues"));
        assert!(names(dispatch).contains(&"move_to_local_helper"));
        assert!(names(dispatch).contains(&"move_to_local_normal_success"));
        assert!(names(dispatch).contains(&"move_to_local_normal_miss"));
        assert!(names(dispatch).contains(&"move_to_local_affinity_success"));
        assert!(names(dispatch).contains(&"move_to_local_affinity_miss"));
        assert!(select
            .iter()
            .all(|left| enqueue.iter().all(|right| left.id != right.id)));
        assert!(select
            .iter()
            .all(|left| dispatch.iter().all(|right| left.id != right.id)));
        assert!(enqueue
            .iter()
            .all(|left| dispatch.iter().all(|right| left.id != right.id)));
        assert_eq!(
            select.len() + enqueue.len() + dispatch.len(),
            bpf_intf::snake_fine_timing_stage_SNAKE_NR_FINE_TIMING_STAGES as usize
        );
    }
}
