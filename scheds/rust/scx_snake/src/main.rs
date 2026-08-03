// SPDX-License-Identifier: GPL-2.0-only

mod bpf_intf;
mod bpf_skel;
mod cell_allocation;
mod control;
mod demand;
mod fine_timing;
mod inspection;
mod managed_cells;
mod mask_tables;
mod membership;
mod policy;
mod policy_validation;
mod queue_timing;
mod queue_topology;
mod runtime_policy;
mod stats;
mod task_cells;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::mem::{size_of, MaybeUninit};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use bpf_skel::*;
use clap::{Parser, ValueEnum};
use control::{SchedulerRequest, SchedulerResponse};
use crossbeam::channel::RecvTimeoutError;
use inspection::{InspectionView, Inspector, SlotPolicy};
use libbpf_rs::{AsRawLibbpf as _, MapCore as _, MapFlags, OpenObject, ProgramInput};
use log::{debug, info, warn};
use mask_tables::{dump_mask_tables, resolve_mask_tables, ResolvedMaskTable};
use membership::{CellDirectory, MembershipManager};
use policy::{
    CompiledPolicy, CompiledRung, InputSource, Opcode, QueueDispatchAction, QueueDispatchOperation,
    QueueDispatchSource, QueueEnqueueAction, QueueEnqueueTarget,
};
use queue_topology::{
    dump_queue_topology, resolve_host_queue_topology, resolve_host_queue_topology_with_demands,
};
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
    CallbackTimingMetrics, CellMetrics, CpuMetrics, Metrics, QueueRungMetrics, RungMetrics,
    RungTimingMetrics,
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

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
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
        conflicts_with_all = ["update_policy", "dump_compiled_policy", "validate_policy", "stats", "monitor", "help_stats", "set_thread_cell", "clear_thread_cell"]
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

    /// Validate a policy and emit one machine-readable JSON report.
    #[arg(long, conflicts_with = "dump_compiled_policy")]
    validate_policy: bool,

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
    Validate(PathBuf),
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
        + usize::from(opts.dump_compiled_policy)
        + usize::from(opts.validate_policy);
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

    let policy = opts.policy.clone().ok_or_else(|| {
        anyhow!("--policy PATH is required when launching, dumping, or validating a policy")
    })?;
    if opts.dump_compiled_policy {
        Ok(RunMode::Dump(policy))
    } else if opts.validate_policy {
        Ok(RunMode::Validate(policy))
    } else {
        Ok(RunMode::Launch(policy))
    }
}

fn load_policy(path: &PathBuf) -> Result<(String, CompiledPolicy)> {
    let source =
        fs::read_to_string(path).with_context(|| format!("reading policy {}", path.display()))?;
    let mut compiled = policy::compile_policy(&source)
        .with_context(|| format!("compiling policy {}", path.display()))?;
    managed_cells::resolve_managed_cells(&mut compiled)
        .with_context(|| format!("resolving managed cells for policy {}", path.display()))?;
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
        input: 0,
        flags: 0,
        reserved: 0,
        data: 0,
    });
    let mut dispatch_rungs = std::array::from_fn(|_| bpf_intf::snake_queue_rung {
        opcode: 0,
        input: 0,
        flags: 0,
        reserved: 0,
        data: 0,
    });
    let (nr_enqueue_rungs, nr_dispatch_rungs) = if let Some(queues) = &policy.queues {
        for (destination, rung) in enqueue_rungs.iter_mut().zip(&queues.enqueue) {
            match (rung.action, rung.target) {
                (QueueEnqueueAction::TryDirect, QueueEnqueueTarget::Cell) => {
                    destination.opcode = bpf_intf::snake_enqueue_opcode_SNAKE_ENQUEUE_OP_TRY_DIRECT;
                    destination.input = bpf_intf::snake_queue_input_SNAKE_QUEUE_INPUT_CELL;
                }
                (QueueEnqueueAction::TryInsert, QueueEnqueueTarget::Cell) => {
                    destination.opcode = bpf_intf::snake_enqueue_opcode_SNAKE_ENQUEUE_OP_CELL;
                    destination.input = bpf_intf::snake_queue_input_SNAKE_QUEUE_INPUT_CELL;
                }
                (QueueEnqueueAction::Insert, QueueEnqueueTarget::Affinity) => {
                    destination.opcode = bpf_intf::snake_enqueue_opcode_SNAKE_ENQUEUE_OP_AFFINITY;
                }
                (QueueEnqueueAction::TryInsert, QueueEnqueueTarget::Local) => {
                    destination.opcode = bpf_intf::snake_enqueue_opcode_SNAKE_ENQUEUE_OP_TRY_INSERT;
                    destination.input = bpf_intf::snake_queue_input_SNAKE_QUEUE_INPUT_LOCAL;
                }
                (QueueEnqueueAction::Insert, QueueEnqueueTarget::Cpu) => {
                    destination.opcode = if queues.layout == policy::QueueLayout::Llc {
                        bpf_intf::snake_enqueue_opcode_SNAKE_ENQUEUE_OP_INSERT
                    } else {
                        bpf_intf::snake_enqueue_opcode_SNAKE_ENQUEUE_OP_INSERT_CPU
                    };
                    destination.input = bpf_intf::snake_queue_input_SNAKE_QUEUE_INPUT_CPU;
                }
                _ => bail!("unsupported compiled enqueue rung {}", rung.describe()),
            }
        }
        if queues.direct_dispatch {
            enqueue_rungs[0].flags = policy::QUEUE_RUNG_FLAG_DIRECT_DISPATCH;
        }
        for (destination, rung) in dispatch_rungs.iter_mut().zip(&queues.dispatch) {
            match (rung.action, rung.source, rung.operation) {
                (QueueDispatchAction::Consume, Some(QueueDispatchSource::Cell), None) => {
                    destination.opcode = bpf_intf::snake_dispatch_opcode_SNAKE_DISPATCH_OP_CELL;
                }
                (QueueDispatchAction::Consume, Some(QueueDispatchSource::Affinity), None) => {
                    destination.opcode = bpf_intf::snake_dispatch_opcode_SNAKE_DISPATCH_OP_AFFINITY;
                }
                (QueueDispatchAction::Consume, None, Some(QueueDispatchOperation::MinVtime))
                    if rung.fallback.is_empty() =>
                {
                    destination.opcode =
                        bpf_intf::snake_dispatch_opcode_SNAKE_DISPATCH_OP_MIN_VTIME;
                }
                (QueueDispatchAction::Peek, Some(source), None) => {
                    destination.opcode = bpf_intf::snake_dispatch_opcode_SNAKE_DISPATCH_OP_PEEK;
                    destination.input = match source {
                        QueueDispatchSource::Cpu => {
                            bpf_intf::snake_queue_input_SNAKE_QUEUE_INPUT_CPU
                        }
                        QueueDispatchSource::Local => {
                            bpf_intf::snake_queue_input_SNAKE_QUEUE_INPUT_LOCAL
                        }
                        QueueDispatchSource::Remote => {
                            bpf_intf::snake_queue_input_SNAKE_QUEUE_INPUT_REMOTE
                        }
                        QueueDispatchSource::Cell => {
                            bpf_intf::snake_queue_input_SNAKE_QUEUE_INPUT_CELL
                        }
                        _ => bail!("unsupported peek source {}", source.as_str()),
                    };
                }
                (QueueDispatchAction::Drain, Some(QueueDispatchSource::CellOrphan), None) => {
                    destination.opcode = bpf_intf::snake_dispatch_opcode_SNAKE_DISPATCH_OP_DRAIN;
                    destination.input = bpf_intf::snake_queue_input_SNAKE_QUEUE_INPUT_CELL_ORPHAN;
                }
                (QueueDispatchAction::Steal, Some(QueueDispatchSource::CellSibling), None) => {
                    destination.opcode = bpf_intf::snake_dispatch_opcode_SNAKE_DISPATCH_OP_STEAL;
                    destination.input = bpf_intf::snake_queue_input_SNAKE_QUEUE_INPUT_CELL_SIBLING;
                }
                (QueueDispatchAction::Consume, None, Some(QueueDispatchOperation::MinVtime)) => {
                    destination.opcode = bpf_intf::snake_dispatch_opcode_SNAKE_DISPATCH_OP_CONSUME;
                    destination.input = bpf_intf::snake_queue_input_SNAKE_QUEUE_INPUT_MIN_VTIME;
                    for (index, source) in rung.fallback.iter().enumerate() {
                        let encoded = match source {
                            QueueDispatchSource::Cpu => {
                                bpf_intf::snake_dispatch_fallback_SNAKE_DISPATCH_FALLBACK_CPU
                            }
                            QueueDispatchSource::Local => {
                                bpf_intf::snake_dispatch_fallback_SNAKE_DISPATCH_FALLBACK_LOCAL
                            }
                            QueueDispatchSource::Remote => {
                                bpf_intf::snake_dispatch_fallback_SNAKE_DISPATCH_FALLBACK_REMOTE
                            }
                            QueueDispatchSource::CellSibling => {
                                bpf_intf::snake_dispatch_fallback_SNAKE_DISPATCH_FALLBACK_CELL_SIBLING
                            }
                            _ => bail!("unsupported fallback source {}", source.as_str()),
                        };
                        destination.data |= u64::from(encoded)
                            << (index as u32 * bpf_intf::SNAKE_DISPATCH_FALLBACK_BITS);
                    }
                }
                _ => bail!("unsupported compiled dispatch rung {}", rung.describe()),
            }
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
    sessions:
        [Option<u64>; bpf_intf::snake_fine_timing_callback_SNAKE_NR_FINE_TIMING_CALLBACKS as usize],
    active: [bool; bpf_intf::snake_fine_timing_callback_SNAKE_NR_FINE_TIMING_CALLBACKS as usize],
    metrics: BTreeMap<(u64, u32), CallbackTimingMetrics>,
    dsq_metrics: BTreeMap<(u64, u64, u32, u32), CallbackTimingMetrics>,
    dsq_transfers: BTreeMap<(u64, u64, u64), u64>,
}

impl FineTimingAccumulator {
    fn reset(&mut self, callback: fine_timing::FineTimingCallback, session_id: u64) {
        if let Some(previous) = self.sessions[callback.index()].replace(session_id) {
            self.metrics.retain(|(session, _), _| *session != previous);
            self.dsq_metrics
                .retain(|(session, _, _, _), _| *session != previous);
            self.dsq_transfers
                .retain(|(session, _, _), _| *session != previous);
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
            bpf_intf::snake_dsq_operation_SNAKE_DSQ_OP_TRANSFER => {
                if outcome == bpf_intf::snake_dsq_outcome_SNAKE_DSQ_OUTCOME_SUCCESS {
                    self.record_dsq_transfer(session_id, source_dsq_id, target_dsq_id);
                }
            }
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
                    self.record_dsq_transfer(session_id, source_dsq_id, target_dsq_id);
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

    fn record_dsq_transfer(&mut self, session_id: u64, source_dsq_id: u64, target_dsq_id: u64) {
        *self
            .dsq_transfers
            .entry((session_id, source_dsq_id, target_dsq_id))
            .or_default() += 1;
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

    fn dsq_transfers(&self, session_id: u64) -> Vec<inspection::DsqTransferInspectionView> {
        self.dsq_transfers
            .iter()
            .filter_map(|(&(session, source_dsq_id, target_dsq_id), &samples)| {
                (session == session_id).then_some(inspection::DsqTransferInspectionView {
                    source_dsq_id,
                    target_dsq_id,
                    samples,
                })
            })
            .collect()
    }

    fn stop(&mut self, callback: fine_timing::FineTimingCallback) {
        self.active[callback.index()] = false;
    }

    fn clear(&mut self) {
        self.sessions =
            [None; bpf_intf::snake_fine_timing_callback_SNAKE_NR_FINE_TIMING_CALLBACKS as usize];
        self.active =
            [false; bpf_intf::snake_fine_timing_callback_SNAKE_NR_FINE_TIMING_CALLBACKS as usize];
        self.metrics.clear();
        self.dsq_metrics.clear();
        self.dsq_transfers.clear();
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
        let Some(limit) = rung_ladder_limit(ladder) else {
            return;
        };
        if rung >= limit {
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
            let limit =
                rung_ladder_limit(ladder).ok_or_else(|| anyhow!("unknown rung ladder {ladder}"))?;
            for rung in 0..limit {
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

fn rung_ladder_limit(ladder: u32) -> Option<u32> {
    match ladder {
        bpf_intf::snake_rung_ladder_SNAKE_RUNG_LADDER_IDLE => Some(bpf_intf::SNAKE_MAX_RUNGS),
        bpf_intf::snake_rung_ladder_SNAKE_RUNG_LADDER_ENQUEUE
        | bpf_intf::snake_rung_ladder_SNAKE_RUNG_LADDER_DISPATCH => {
            Some(bpf_intf::SNAKE_MAX_QUEUE_RUNGS)
        }
        _ => None,
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

fn queue_mode_for_topology(topology: Option<&queue_topology::QueueTopology>) -> u32 {
    match topology.map(|topology| topology.layout) {
        None => bpf_intf::SNAKE_QUEUE_MODE_NONE,
        Some(policy::QueueLayout::Cell | policy::QueueLayout::CellLlc) => {
            bpf_intf::SNAKE_QUEUE_MODE_CELL
        }
        Some(policy::QueueLayout::Llc) => bpf_intf::SNAKE_QUEUE_MODE_GLOBAL,
    }
}

fn encode_queue_topology(
    topology: &queue_topology::QueueTopology,
    generation: u64,
) -> Result<EncodedQueueTopology> {
    let nr_normal_dsqs = match topology.layout {
        policy::QueueLayout::Llc => u32::try_from(topology.normal_queues.len())?,
        policy::QueueLayout::Cell => bpf_intf::SNAKE_MAX_QUEUE_CELLS,
        policy::QueueLayout::CellLlc => {
            let first = topology
                .cells
                .first()
                .context("cell-LLC topology has no cells")?;
            let nr_llcs = u32::try_from(first.normal_queues.len())?;
            if nr_llcs == 0 || nr_llcs > bpf_intf::SNAKE_MAX_CELL_LLCS {
                bail!("cell-LLC topology has invalid LLC count {nr_llcs}");
            }
            if topology
                .cells
                .iter()
                .any(|cell| cell.normal_queues.len() != first.normal_queues.len())
            {
                bail!("cell-LLC topology does not have a complete cell/LLC queue matrix");
            }
            bpf_intf::SNAKE_MAX_QUEUE_CELLS
                .checked_mul(nr_llcs)
                .context("cell-LLC DSQ capacity overflow")?
        }
    };
    if nr_normal_dsqs > bpf_intf::SNAKE_MAX_NORMAL_QUEUES {
        bail!(
            "queue topology requires {nr_normal_dsqs} normal DSQs, maximum is {}",
            bpf_intf::SNAKE_MAX_NORMAL_QUEUES
        );
    }
    let mut cell_lookup = vec![0_u32; policy::MAX_CELL_IDS as usize];
    let mut cells = (0..bpf_intf::SNAKE_MAX_QUEUE_CELLS)
        .map(|_| bpf_intf::snake_queue_cell {
            valid: 0,
            external_id: 0,
            cpu_weight: 0,
            clock_index: 0,
            first_normal_queue: 0,
            nr_normal_queues: 0,
            slot_epoch: 0,
            reserved: 0,
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
            consumer_cpu: 0,
            reserved: [0; 4],
            consumers: bpf_intf::snake_mask_data {
                valid: 0,
                bits: [0; bpf_intf::SNAKE_MASK_BYTES as usize],
            },
        })
        .collect::<Vec<_>>();
    let mut cpu_queues = (0..bpf_intf::SNAKE_MAX_CPUS)
        .map(|_| bpf_intf::snake_cpu_queue {
            valid: 0,
            owner_cell_index: 0,
            normal_queue_index: 0,
            reserved: 0,
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
            slot_epoch: cell.slot_epoch,
            reserved: 0,
            primary: mask_tables::serialize_entry(&cell.primary)?,
            borrowable: mask_tables::serialize_entry(&cell.borrowable)?,
        };
    }
    for queue in &topology.normal_queues {
        normal_queues[queue.index as usize] = bpf_intf::snake_normal_queue {
            valid: 1,
            cell_index: queue.cell_index.unwrap_or(bpf_intf::SNAKE_QUEUE_CELL_NONE),
            clock_index: queue
                .cell_index
                .map_or(bpf_intf::SNAKE_QUEUE_CELL_NONE, |_| queue.clock_index),
            consumer_cpu: queue
                .consumers
                .first()
                .copied()
                .unwrap_or(bpf_intf::SNAKE_QUEUE_CPU_NONE),
            reserved: [0; 4],
            consumers: mask_tables::serialize_entry(&queue.consumers)?,
        };
    }
    for (&cpu, queue) in &topology.cpu_queues {
        let destination = cpu_queues
            .get_mut(cpu as usize)
            .with_context(|| format!("CPU {cpu} exceeds BPF queue capacity"))?;
        *destination = bpf_intf::snake_cpu_queue {
            valid: 1,
            owner_cell_index: queue
                .owner_cell_index
                .unwrap_or(bpf_intf::SNAKE_QUEUE_CELL_NONE),
            normal_queue_index: queue.normal_queue_index,
            reserved: 0,
        };
    }
    let nr_cpus = topology.cpu_queues.len().try_into()?;
    let mode = queue_mode_for_topology(Some(topology));
    Ok(EncodedQueueTopology {
        header: bpf_intf::snake_queue_header {
            mode,
            nr_cells: topology.cells.len().try_into()?,
            nr_normal_queues: topology.normal_queues.len().try_into()?,
            nr_normal_dsqs,
            nr_cpus,
            topology_generation: generation,
        },
        cell_lookup,
        cells,
        normal_queues,
        cpu_queues,
    })
}

fn install_queue_topology(
    skel: &mut BpfSkel<'_>,
    slot: u32,
    generation: u64,
    topology: Option<&queue_topology::QueueTopology>,
) -> Result<()> {
    if slot >= bpf_intf::SNAKE_LADDER_SLOTS {
        bail!("invalid queue topology slot {slot}");
    }
    let Some(topology) = topology else {
        return Ok(());
    };
    let encoded = encode_queue_topology(topology, generation)?;
    for (key, value) in encoded.cell_lookup.iter().enumerate() {
        let key = slot * bpf_intf::SNAKE_MAX_CPUS + u32::try_from(key)?;
        skel.maps
            .queue_cell_lookup
            .update(&key.to_ne_bytes(), &value.to_ne_bytes(), MapFlags::ANY)
            .with_context(|| format!("installing queue cell lookup {key}"))?;
    }
    for (key, value) in encoded.cells.iter().enumerate() {
        let key = slot * bpf_intf::SNAKE_MAX_QUEUE_CELLS + u32::try_from(key)?;
        skel.maps
            .queue_cells
            .update(&key.to_ne_bytes(), bytes_of(value), MapFlags::ANY)
            .with_context(|| format!("installing queue cell {key}"))?;
    }
    for (key, value) in encoded.normal_queues.iter().enumerate() {
        let key = slot * bpf_intf::SNAKE_MAX_NORMAL_QUEUES + u32::try_from(key)?;
        skel.maps
            .normal_queues
            .update(&key.to_ne_bytes(), bytes_of(value), MapFlags::ANY)
            .with_context(|| format!("installing normal queue {key}"))?;
    }
    for (key, value) in encoded.cpu_queues.iter().enumerate() {
        let key = slot * bpf_intf::SNAKE_MAX_CPUS + u32::try_from(key)?;
        skel.maps
            .cpu_queues
            .update(&key.to_ne_bytes(), bytes_of(value), MapFlags::ANY)
            .with_context(|| format!("installing CPU queue {key}"))?;
    }
    let key = slot;
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
    for rung in &active.enqueue {
        if !candidate.enqueue.contains(rung) {
            bail!(
                "cannot remove active queue enqueue target `{}` during live replacement",
                rung.target.as_str()
            );
        }
    }
    let dispatch_sources = |dispatch: &[policy::QueueDispatchRung]| {
        let mut sources = BTreeSet::new();
        for rung in dispatch {
            if let Some(source) = rung.source {
                sources.insert(source);
            }
            if rung.operation == Some(QueueDispatchOperation::MinVtime) {
                if rung.fallback.is_empty() {
                    sources.insert(QueueDispatchSource::Cell);
                    sources.insert(QueueDispatchSource::Affinity);
                } else {
                    sources.extend(rung.fallback.iter().copied());
                }
            }
        }
        sources
    };
    let active_sources = dispatch_sources(&active.dispatch);
    let candidate_sources = dispatch_sources(&candidate.dispatch);
    for source in active_sources {
        if !candidate_sources.contains(&source) {
            bail!(
                "cannot remove active queue dispatch source `{}` during live replacement",
                source.as_str()
            );
        }
    }
    Ok(())
}

fn uses_expanded_mitosis_select(policy: &CompiledPolicy) -> bool {
    policy.rungs.len() > policy::MAX_GENERIC_RUNGS
}

fn uses_enqueue_direct_retry(policy: &CompiledPolicy) -> bool {
    uses_expanded_mitosis_select(policy)
        && policy
            .queues
            .as_ref()
            .is_some_and(|queues| queues.direct_dispatch)
}

fn validate_select_cpu_variant_replacement(
    active: &CompiledPolicy,
    candidate: &CompiledPolicy,
) -> Result<()> {
    if uses_expanded_mitosis_select(active) != uses_expanded_mitosis_select(candidate) {
        bail!(
            "replacement changes the attachment-time select_cpu variant; restart Snake to apply it"
        );
    }
    Ok(())
}

fn validate_enqueue_variant_replacement(
    active: &CompiledPolicy,
    candidate: &CompiledPolicy,
) -> Result<()> {
    let active_variant = (uses_enqueue_direct_retry(active), active.queues.is_some());
    let candidate_variant = (
        uses_enqueue_direct_retry(candidate),
        candidate.queues.is_some(),
    );
    if active_variant != candidate_variant {
        bail!("replacement changes the attachment-time enqueue variant; restart Snake to apply it");
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

fn clear_mask_table_data(skel: &mut BpfSkel<'_>, slot: u32) -> Result<()> {
    let empty = bpf_intf::snake_mask_data {
        valid: 0,
        bits: [0; bpf_intf::SNAKE_MASK_BYTES as usize],
    };
    for table_id in 0..bpf_intf::SNAKE_MAX_MASK_TABLES {
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

fn set_queue_draining(skel: &mut BpfSkel<'_>, draining: bool) -> Result<()> {
    let draining_ptr = &mut skel
        .maps
        .bss_data
        .as_mut()
        .context("BPF bss map is not memory mapped")?
        .queue_draining as *mut u32;
    // The BPF enqueue gate orders two reads around its atomic inflight increment.
    unsafe { &*(draining_ptr.cast::<AtomicU32>()) }.store(u32::from(draining), Ordering::Release);
    Ok(())
}

fn set_queue_transition_cpus(
    skel: &mut BpfSkel<'_>,
    active: &queue_topology::QueueTopology,
    candidate: &queue_topology::QueueTopology,
) -> Result<()> {
    let changed = queue_topology::ownership_changed_cpus(active, candidate)?;
    let mask = mask_tables::serialize_entry(&changed)?;
    let destination = &mut skel
        .maps
        .bss_data
        .as_mut()
        .context("BPF bss map is not memory mapped")?
        .queue_transition_cpus;
    destination.valid = mask.valid;
    destination.bits.copy_from_slice(&mask.bits);
    Ok(())
}

fn queue_enqueues_inflight(skel: &BpfSkel<'_>) -> Result<bool> {
    let raw = skel
        .maps
        .queue_enqueue_inflight
        .lookup_percpu(&0_u32.to_ne_bytes(), MapFlags::ANY)
        .context("reading per-CPU queue enqueue interlock")?
        .context("queue enqueue interlock map has no entry")?;
    for (cpu, bytes) in raw.iter().enumerate() {
        let value = u32::from_ne_bytes(
            bytes
                .as_slice()
                .try_into()
                .with_context(|| format!("queue enqueue interlock CPU {cpu} has invalid width"))?,
        );
        if value != 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

fn wait_for_queue_enqueues_quiescent(skel: &BpfSkel<'_>, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while queue_enqueues_inflight(skel)? {
        if Instant::now() >= deadline {
            bail!("timed out waiting for custom queue enqueue callbacks to quiesce");
        }
        std::thread::sleep(SLOT_QUIESCENCE_POLL_INTERVAL);
    }
    Ok(())
}

fn affinity_queues_empty(skel: &mut BpfSkel<'_>) -> Result<bool> {
    let output = skel
        .progs
        .queue_affinity_drain_ready
        .test_run(ProgramInput::default())
        .context("checking affinity queues before CPU ownership transfer")?;
    match output.return_value as i32 {
        0 => Ok(true),
        result if result == -libc::EAGAIN => Ok(false),
        result => bail!("checking affinity queue drain failed: {result}"),
    }
}

fn wait_for_queue_drain(skel: &mut BpfSkel<'_>, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let mut result = -libc::EAGAIN;
        if !queue_enqueues_inflight(skel)? {
            let output = skel
                .progs
                .queue_drain_ready
                .test_run(ProgramInput::default())
                .context("checking queue topology drain")?;
            result = output.return_value as i32;
            if result == 0 && !queue_enqueues_inflight(skel)? {
                return Ok(());
            }
        }
        if result != -libc::EAGAIN {
            bail!("checking queue topology drain failed: {result}");
        }
        if Instant::now() >= deadline {
            bail!("timed out waiting for custom queue topology DSQs to drain");
        }
        std::thread::sleep(SLOT_QUIESCENCE_POLL_INTERVAL);
    }
}

fn refresh_queue_runtime(skel: &mut BpfSkel<'_>) -> Result<()> {
    let output = skel
        .progs
        .queue_refresh_runtime
        .test_run(ProgramInput::default())
        .context("refreshing normal queue runtime state")?;
    if output.return_value != 0 {
        bail!(
            "refreshing normal queue runtime state failed: {}",
            output.return_value as i32
        );
    }
    Ok(())
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
        let bss = skel
            .maps
            .bss_data
            .as_ref()
            .context("BPF bss map is not memory mapped")?;
        let ladder_stage = bss.staging_ladder_prepare_stage;
        let ladder_error = bss.staging_ladder_prepare_error;
        let topology_stage = bss.queue_topology_prepare_stage;
        let topology_error = bss.queue_topology_prepare_error;
        let topology_detail = bss.queue_topology_prepare_detail;
        bail!(
            "preparing ladder slot {slot} failed: {} (ladder stage {ladder_stage}, topology stage {topology_stage}, topology detail {topology_detail}; ladder error {ladder_error}, topology error {topology_error})",
            output.return_value as i32,
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

struct BpfPolicyBackend<'skel, 'object, 'topology> {
    skel: &'skel mut BpfSkel<'object>,
    queue_topology: Option<&'topology queue_topology::QueueTopology>,
    previous_slot: u32,
}

impl runtime_policy::PolicyBackend for BpfPolicyBackend<'_, '_, '_> {
    fn wait_for_slot_quiescent(&mut self, slot: u32) -> Result<()> {
        wait_for_slot_quiescent(self.skel, slot, SLOT_QUIESCENCE_TIMEOUT)
    }

    fn write_ladder(&mut self, slot: u32, generation: u64, policy: &CompiledPolicy) -> Result<()> {
        write_ladder_slot(self.skel, slot, generation, policy)
    }

    fn write_mask_tables(&mut self, slot: u32, tables: &[ResolvedMaskTable]) -> Result<()> {
        clear_mask_table_data(self.skel, slot)?;
        install_mask_tables(self.skel, slot, tables)
    }

    fn write_queue_topology(&mut self, slot: u32, generation: u64) -> Result<()> {
        install_queue_topology(self.skel, slot, generation, self.queue_topology)
    }

    fn prepare_ladder(&mut self, slot: u32) -> Result<()> {
        prepare_ladder_slot(self.skel, slot)
    }

    fn clear_stats(&mut self, slot: u32) -> Result<()> {
        clear_slot_stats(self.skel, slot)
    }

    fn publish_ladder(&mut self, slot: u32) -> Result<()> {
        set_active_ladder(self.skel, slot)?;
        if let Err(error) = refresh_queue_runtime(self.skel) {
            let rollback = set_active_ladder(self.skel, self.previous_slot)
                .and_then(|_| refresh_queue_runtime(self.skel));
            return match rollback {
                Ok(()) => Err(error).context("refreshing published queue runtime; rolled back"),
                Err(rollback_error) => Err(error).context(format!(
                    "refreshing published queue runtime failed and rollback failed: {rollback_error:#}"
                )),
            };
        }
        Ok(())
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
    clear_mask_table_data(skel, slot)?;
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
            Opcode::ClaimIdle => "claim_idle_core",
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
        Opcode::PickIdlePreferPrevious => "pick_idle_prefer_previous",
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
        (
            Opcode::ClaimIdle | Opcode::PickIdleQueueMask | Opcode::PickIdlePreferPrevious,
            InputSource::QueueCell,
        ) => match rung.data {
            value if value == policy::QueueMaskKind::Primary as u64 => Ok("task_cell"),
            value if value == policy::QueueMaskKind::Borrowable as u64 => {
                Ok("task_cell_borrowable")
            }
            value if value == policy::QueueMaskKind::LocalLlc as u64 => Ok("task_cell_llc"),
            _ => bail!("queue-mask rung references unknown mask kind {}", rung.data),
        },
        (
            Opcode::ClaimIdle | Opcode::PickIdleQueueMask | Opcode::PickIdlePreferPrevious,
            InputSource::TaskAllowedRestricted,
        ) => Ok("task_allowed_restricted"),
        (_, InputSource::CpuPrev) => Ok("previous_cpu"),
        (_, InputSource::MaskTaskAllowed) => Ok("task_allowed"),
        (_, InputSource::TaskCell) => bail!("operation cannot consume a task-cell input"),
        (_, InputSource::QueueCell) => bail!("operation cannot consume a queue-cell input"),
        (_, InputSource::TaskAllowedRestricted) => {
            bail!("operation cannot consume a restricted task-allowed input")
        }
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
    let enqueue_rungs = policy
        .queues
        .iter()
        .flat_map(|queues| queues.enqueue.iter())
        .enumerate()
        .map(|(index, rung)| {
            let index = index as u32;
            (
                index,
                QueueRungMetrics {
                    index,
                    operation: rung.describe(),
                    attempts: value(
                        bpf_intf::snake_stat_SNAKE_STAT_ENQUEUE_RUNG_ATTEMPT_BASE + index,
                    ),
                    hits: value(bpf_intf::snake_stat_SNAKE_STAT_ENQUEUE_RUNG_HIT_BASE + index),
                    misses: value(bpf_intf::snake_stat_SNAKE_STAT_ENQUEUE_RUNG_MISS_BASE + index),
                    errors: value(bpf_intf::snake_stat_SNAKE_STAT_ENQUEUE_RUNG_ERROR_BASE + index),
                    ..Default::default()
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let dispatch_rungs = policy
        .queues
        .iter()
        .flat_map(|queues| queues.dispatch.iter())
        .enumerate()
        .map(|(index, rung)| {
            let index = index as u32;
            (
                index,
                QueueRungMetrics {
                    index,
                    operation: rung.describe(),
                    attempts: value(
                        bpf_intf::snake_stat_SNAKE_STAT_DISPATCH_RUNG_ATTEMPT_BASE + index,
                    ),
                    hits: value(bpf_intf::snake_stat_SNAKE_STAT_DISPATCH_RUNG_HIT_BASE + index),
                    misses: value(bpf_intf::snake_stat_SNAKE_STAT_DISPATCH_RUNG_MISS_BASE + index),
                    errors: value(bpf_intf::snake_stat_SNAKE_STAT_DISPATCH_RUNG_ERROR_BASE + index),
                    selected: value(
                        bpf_intf::snake_stat_SNAKE_STAT_DISPATCH_RUNG_SELECTED_BASE + index,
                    ),
                    move_misses: value(
                        bpf_intf::snake_stat_SNAKE_STAT_DISPATCH_RUNG_MOVE_MISS_BASE + index,
                    ),
                    fallback_attempts: value(
                        bpf_intf::snake_stat_SNAKE_STAT_DISPATCH_RUNG_FALLBACK_ATTEMPT_BASE + index,
                    ),
                    fallback_hits: value(
                        bpf_intf::snake_stat_SNAKE_STAT_DISPATCH_RUNG_FALLBACK_HIT_BASE + index,
                    ),
                    fallback_misses: value(
                        bpf_intf::snake_stat_SNAKE_STAT_DISPATCH_RUNG_FALLBACK_MISS_BASE + index,
                    ),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();

    Ok(Metrics {
        policy_generation: generation,
        managed_rebalance_count: 0,
        managed_last_rebalance_at_ms: 0,
        fairness_mode: fairness.as_str().into(),
        select_calls: value(bpf_intf::snake_stat_SNAKE_STAT_SELECT_CALLS),
        dispatch_calls: value(bpf_intf::snake_stat_SNAKE_STAT_DISPATCH_CALLS),
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
        vtime_clock_cas_retries: value(bpf_intf::snake_stat_SNAKE_STAT_VTIME_CLOCK_CAS_RETRIES),
        vtime_clock_cas_exhaustions: value(
            bpf_intf::snake_stat_SNAKE_STAT_VTIME_CLOCK_CAS_EXHAUSTIONS,
        ),
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
        eevdf_run_lag_clamps: value(bpf_intf::snake_stat_SNAKE_STAT_EEVDF_RUN_LAG_CLAMPS),
        eevdf_accounting_errors: value(bpf_intf::snake_stat_SNAKE_STAT_EEVDF_ACCOUNTING_ERRORS),
        cpus,
        cells: BTreeMap::new(),
        rungs,
        enqueue_rungs,
        dispatch_rungs,
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
                    slot_epoch: cell.slot_epoch,
                    primary_cpu_count: u32::try_from(cell.primary.len())
                        .context("cell primary CPU count does not fit u32")?,
                    utilization_pct: 0.0,
                    ewma_utilization_pct: 0.0,
                    borrowed_pct: 0.0,
                    lent_pct: 0.0,
                    runtime_ns: value(dense, bpf_intf::snake_cell_stat_SNAKE_CELL_STAT_RUNTIME_NS)?,
                    runtime_ns_by_cpu: decode_per_cpu_stat(
                        &raw[dense * nr_stats
                            + bpf_intf::snake_cell_stat_SNAKE_CELL_STAT_RUNTIME_NS as usize],
                    )?
                    .into_iter()
                    .enumerate()
                    .filter_map(|(cpu, runtime_ns)| {
                        (runtime_ns > 0).then(|| {
                            u32::try_from(cpu)
                                .map(|cpu| (cpu, runtime_ns))
                                .context("CPU index does not fit u32")
                        })
                    })
                    .collect::<Result<_>>()?,
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
                    foreign_affinity_runtime_ns: value(
                        dense,
                        bpf_intf::snake_cell_stat_SNAKE_CELL_STAT_FOREIGN_AFFINITY_RUNTIME_NS,
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

fn read_cell_demand_snapshot(
    skel: &BpfSkel<'_>,
    generation: u64,
    slot: u32,
    topology: &queue_topology::QueueTopology,
) -> Result<demand::Snapshot> {
    let read = |dense: u32, stat: u32| -> Result<u64> {
        let index = runtime_policy::cell_stat_index(slot, dense, stat)?;
        let raw = skel
            .maps
            .cell_stats
            .lookup_percpu(&index.to_ne_bytes(), MapFlags::ANY)
            .with_context(|| format!("reading demand counter {stat} for cell index {dense}"))?
            .ok_or_else(|| anyhow!("cell demand counter has no entry {index}"))?;
        decode_stat(&raw, false)
    };
    let cells = topology
        .cells
        .iter()
        .map(|cell| {
            let identity = demand::CellIdentity {
                id: cell.external_id,
                slot_epoch: cell.slot_epoch,
            };
            let primary_ns = read(
                cell.index,
                bpf_intf::snake_cell_stat_SNAKE_CELL_STAT_PRIMARY_RUNTIME_NS,
            )?;
            let borrowed_ns = read(
                cell.index,
                bpf_intf::snake_cell_stat_SNAKE_CELL_STAT_BORROWED_RUNTIME_NS,
            )?;
            let lent_ns = read(
                cell.index,
                bpf_intf::snake_cell_stat_SNAKE_CELL_STAT_LENT_RUNTIME_NS,
            )?;
            // Runtime contains primary plus borrowed time, so read it last to
            // keep the borrowed percentage bounded under concurrent updates.
            let runtime_ns = read(
                cell.index,
                bpf_intf::snake_cell_stat_SNAKE_CELL_STAT_RUNTIME_NS,
            )?;
            let sample = demand::DemandSample {
                runtime_ns,
                primary_ns,
                borrowed_ns,
                lent_ns,
                primary_cpus: cell.primary.len(),
            };
            Ok((identity, sample))
        })
        .collect::<Result<_>>()?;
    Ok(demand::Snapshot {
        counter_bank: (generation, slot),
        sampled_at: Instant::now(),
        cells,
    })
}

struct TopologyTransitionAttempt {
    id: u64,
    reason: String,
    from_generation: u64,
    started_at_ms: u64,
    stages: Vec<inspection::TopologyTransitionStageInspectionView>,
    cell_changes: Vec<inspection::TopologyCellChangeInspectionView>,
}

impl TopologyTransitionAttempt {
    fn new(id: u64, from_generation: u64, started_at_ms: u64) -> Self {
        Self::new_with_reason(id, from_generation, started_at_ms, "managed_cells_changed")
    }

    fn new_with_reason(id: u64, from_generation: u64, started_at_ms: u64, reason: &str) -> Self {
        Self {
            id,
            reason: reason.into(),
            from_generation,
            started_at_ms,
            stages: Vec::new(),
            cell_changes: Vec::new(),
        }
    }

    fn push_stage(
        &mut self,
        stage: &str,
        status: inspection::TopologyTransitionStageStatus,
        duration: Duration,
        detail: Option<String>,
    ) {
        self.stages
            .push(inspection::TopologyTransitionStageInspectionView {
                stage: stage.into(),
                status,
                duration_ms: duration_ms(duration),
                detail,
            });
    }

    fn complete_stage(&mut self, stage: &str, duration: Duration) {
        self.push_stage(
            stage,
            inspection::TopologyTransitionStageStatus::Complete,
            duration,
            None,
        );
    }

    fn warn_stage(&mut self, stage: &str, duration: Duration, detail: String) {
        self.push_stage(
            stage,
            inspection::TopologyTransitionStageStatus::Warning,
            duration,
            Some(detail),
        );
    }

    fn fail_stage(&mut self, stage: &str, duration: Duration, detail: String) {
        self.push_stage(
            stage,
            inspection::TopologyTransitionStageStatus::Failed,
            duration,
            Some(detail),
        );
    }

    fn finish(
        self,
        outcome: inspection::TopologyTransitionOutcome,
        to_generation: Option<u64>,
        completed_at_ms: u64,
        duration: Duration,
        detail: Option<String>,
    ) -> inspection::TopologyTransitionInspectionView {
        inspection::TopologyTransitionInspectionView {
            id: self.id,
            reason: self.reason,
            outcome,
            from_generation: self.from_generation,
            to_generation,
            started_at_ms: self.started_at_ms,
            completed_at_ms,
            duration_ms: duration_ms(duration),
            stages: self.stages,
            cell_changes: self.cell_changes,
            detail,
        }
    }
}

fn topology_cell_names(policy: &CompiledPolicy) -> BTreeMap<u32, String> {
    policy
        .membership
        .as_ref()
        .into_iter()
        .flat_map(|membership| {
            membership
                .assignments
                .iter()
                .map(|(name, &cell_id)| (cell_id, name.clone()))
        })
        .collect()
}

fn policy_dispatches_orphan_queues(policy: &CompiledPolicy) -> bool {
    let Some(queues) = policy.queues.as_ref() else {
        return false;
    };
    queues.layout == policy::QueueLayout::CellLlc
        && queues.dispatch.len() == 5
        && queues.dispatch.first().is_some_and(|rung| {
            rung.action == QueueDispatchAction::Drain
                && rung.source == Some(QueueDispatchSource::CellOrphan)
        })
        && queues.dispatch.last().is_some_and(|rung| {
            rung.action == QueueDispatchAction::Steal
                && rung.source == Some(QueueDispatchSource::CellSibling)
        })
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
    managed_reconcile_interval: Option<Duration>,
    next_managed_reconcile: Option<Instant>,
    demand_tracker: Option<demand::DemandTracker>,
    demand_sample_interval: Option<Duration>,
    next_demand_sample: Option<Instant>,
    next_rebalance_allowed: Option<Instant>,
    managed_rebalance_count: u64,
    managed_last_rebalance_at_ms: u64,
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
        let expanded_mitosis = uses_expanded_mitosis_select(&runtime.compiled);
        let selected_select_cpu = if expanded_mitosis {
            skel.progs.snake_select_cpu.set_autoload(false);
            skel.progs.snake_select_cpu_expanded.set_autoload(true);
            skel.progs
                .snake_select_cpu_expanded
                .as_libbpf_object()
                .as_ptr()
        } else {
            skel.progs.snake_select_cpu.set_autoload(true);
            skel.progs.snake_select_cpu_expanded.set_autoload(false);
            skel.progs.snake_select_cpu.as_libbpf_object().as_ptr()
        };
        skel.struct_ops.snake_ops_mut().select_cpu = selected_select_cpu;
        let enqueue_direct_retry = uses_enqueue_direct_retry(&runtime.compiled);
        let selected_enqueue = if enqueue_direct_retry {
            skel.progs.snake_enqueue.set_autoload(false);
            skel.progs.snake_enqueue_expanded.set_autoload(true);
            skel.progs.snake_enqueue_no_direct.set_autoload(false);
            skel.progs
                .snake_enqueue_expanded
                .as_libbpf_object()
                .as_ptr()
        } else if runtime.compiled.queues.is_some() {
            skel.progs.snake_enqueue.set_autoload(false);
            skel.progs.snake_enqueue_expanded.set_autoload(false);
            skel.progs.snake_enqueue_no_direct.set_autoload(true);
            skel.progs
                .snake_enqueue_no_direct
                .as_libbpf_object()
                .as_ptr()
        } else {
            skel.progs.snake_enqueue.set_autoload(true);
            skel.progs.snake_enqueue_expanded.set_autoload(false);
            skel.progs.snake_enqueue_no_direct.set_autoload(false);
            skel.progs.snake_enqueue.as_libbpf_object().as_ptr()
        };
        skel.struct_ops.snake_ops_mut().enqueue = selected_enqueue;
        let rodata = skel
            .maps
            .rodata_data
            .as_mut()
            .context("BPF read-only data is unavailable")?;
        rodata.fairness_mode = opts.fairness as u32;
        rodata.queue_mode = queue_mode_for_topology(queue_topology);
        rodata.expanded_mitosis_select = u32::from(expanded_mitosis);
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
        install_queue_topology(&mut skel, 0, runtime.generation, queue_topology)?;
        set_active_ladder(&mut skel, bpf_intf::SNAKE_LADDER_SLOT_INVALID)?;
        install_ladder_slot(
            &mut skel,
            0,
            runtime.generation,
            &runtime.compiled,
            mask_tables,
        )?;
        set_active_ladder(&mut skel, 0)?;
        refresh_queue_runtime(&mut skel)?;
        runtime.active_slot = 0;
        let membership = if let Some(policy) = &runtime.compiled.membership {
            let mut manager = MembershipManager::new(policy, &runtime.compiled.cell_slot_epochs)
                .context("initializing userspace task membership")?;
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
        let managed_reconcile_interval = runtime
            .compiled
            .managed_cells
            .as_ref()
            .map(|managed| Duration::from_millis(managed.reconcile_ms));
        let next_managed_reconcile =
            managed_reconcile_interval.map(|interval| Instant::now() + interval);
        let resizing = runtime
            .compiled
            .managed_cells
            .as_ref()
            .and_then(|managed| managed.resizing.as_ref());
        let demand_tracker = resizing
            .map(|resizing| demand::DemandTracker::new(resizing.ewma_alpha()))
            .transpose()
            .context("initializing managed-cell demand tracker")?;
        let demand_sample_interval =
            resizing.map(|resizing| Duration::from_millis(resizing.sample_ms));
        let next_demand_sample = demand_sample_interval.map(|interval| Instant::now() + interval);
        let next_rebalance_allowed =
            resizing.map(|resizing| Instant::now() + Duration::from_millis(resizing.cooldown_ms));
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
            managed_reconcile_interval,
            next_managed_reconcile,
            demand_tracker,
            demand_sample_interval,
            next_demand_sample,
            next_rebalance_allowed,
            managed_rebalance_count: 0,
            managed_last_rebalance_at_ms: 0,
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
            if let Some(tracker) = self.demand_tracker.as_ref().filter(|tracker| {
                tracker.counter_bank() == Some((self.runtime.generation, self.runtime.active_slot))
            }) {
                for cell in &topology.cells {
                    let identity = demand::CellIdentity {
                        id: cell.external_id,
                        slot_epoch: cell.slot_epoch,
                    };
                    let Some(gauges) = tracker.gauge(identity) else {
                        continue;
                    };
                    let Some(cell_metrics) = metrics.cells.get_mut(&cell.external_id) else {
                        continue;
                    };
                    cell_metrics.utilization_pct = gauges.util_pct;
                    cell_metrics.ewma_utilization_pct = gauges.ewma_pct.unwrap_or(0.0);
                    cell_metrics.borrowed_pct = gauges.borrowed_pct;
                    cell_metrics.lent_pct = gauges.lent_pct;
                }
            }
        }
        metrics.managed_rebalance_count = self.managed_rebalance_count;
        metrics.managed_last_rebalance_at_ms = self.managed_last_rebalance_at_ms;
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
            queue_topology: active_queue_topology.as_ref(),
            previous_slot,
        };
        let response = runtime_policy::replace_policy(
            self.runtime,
            source,
            |policy| {
                if policy.managed_cells.is_some() || previous_policy.managed_cells.is_some() {
                    bail!(
                        "managed cells are attachment-time configuration; restart Snake to apply a policy update"
                    );
                }
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
                validate_select_cpu_variant_replacement(&previous_policy, policy)?;
                validate_enqueue_variant_replacement(&previous_policy, policy)?;
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
        if policy.managed_cells.is_some() || self.runtime.compiled.managed_cells.is_some() {
            bail!(
                "managed cells are attachment-time configuration; restart Snake to apply a policy update"
            );
        }
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
        validate_select_cpu_variant_replacement(&self.runtime.compiled, &policy)?;
        validate_enqueue_variant_replacement(&self.runtime.compiled, &policy)?;
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
            && !(assignment.cell_id == 0
                && self.queue_topology.as_ref().is_some_and(|topology| {
                    matches!(
                        topology.layout,
                        policy::QueueLayout::Cell | policy::QueueLayout::CellLlc
                    )
                }))
        {
            bail!(
                "active policy generation {} does not define cell {}",
                self.runtime.generation,
                assignment.cell_id
            );
        }
        let slot_epoch = self
            .runtime
            .compiled
            .cell_slot_epochs
            .get(&assignment.cell_id)
            .copied()
            .unwrap_or(0);
        let rehome_requested =
            task_cells::set_thread_cell(&self.skel.maps.task_cells, assignment, slot_epoch)?;
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
            rehome_requested: self.queue_topology.as_ref().is_some_and(|topology| {
                matches!(
                    topology.layout,
                    policy::QueueLayout::Cell | policy::QueueLayout::CellLlc
                )
            }),
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
        let bss = self
            .skel
            .maps
            .bss_data
            .as_mut()
            .context("BPF bss map is not memory mapped")?;
        bss.select_fine_timing_session_id =
            if state.is_enabled(fine_timing::FineTimingCallback::SelectCpu) {
                state
                    .session(fine_timing::FineTimingCallback::SelectCpu)
                    .map_or(0, |session| session.session_id)
            } else {
                0
            };
        bss.dispatch_fine_timing_session_id =
            if state.is_enabled(fine_timing::FineTimingCallback::Dispatch) {
                state
                    .session(fine_timing::FineTimingCallback::Dispatch)
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
            let session = next.start(
                callback,
                self.runtime.generation,
                self.callback_timing_sample_rate,
                unix_time_ms(),
            );
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
            queue_topology: self.queue_topology.as_ref(),
            previous_slot: self.runtime.active_slot,
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
        self.managed_rebalance_count = 0;
        self.managed_last_rebalance_at_ms = 0;
        if let Err(error) = self.rebase_managed_demand() {
            warn!("managed-cell demand rebase after stats reset failed: {error:#}");
        }
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
                    sample_rate: session.map(|session| session.sample_rate),
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
                    dsq_transfers: match session {
                        Some(session) => self
                            .fine_timing_accumulator
                            .lock()
                            .map_err(|_| anyhow!("fine timing accumulator lock poisoned"))?
                            .dsq_transfers(session.session_id),
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
                    cell_epoch: task.cell_epoch,
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
                    cell_epoch: task.cell_epoch,
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

    fn time_until_managed_reconcile(&self) -> Option<Duration> {
        self.next_managed_reconcile
            .map(|next| next.saturating_duration_since(Instant::now()))
    }

    fn time_until_demand_sample(&self) -> Option<Duration> {
        self.next_demand_sample
            .map(|next| next.saturating_duration_since(Instant::now()))
    }

    fn rebase_managed_demand(&mut self) -> Result<()> {
        let Some(topology) = self.queue_topology.as_ref() else {
            return Ok(());
        };
        if self.demand_tracker.is_none() {
            return Ok(());
        }
        let snapshot = read_cell_demand_snapshot(
            &self.skel,
            self.runtime.generation,
            self.runtime.active_slot,
            topology,
        )?;
        let sampled_at = snapshot.sampled_at;
        self.demand_tracker
            .as_mut()
            .expect("checked above")
            .step(snapshot)
            .context("rebasing managed-cell demand counters")?;
        if let Some(interval) = self.demand_sample_interval {
            self.next_demand_sample = Some(sampled_at + interval);
        }
        Ok(())
    }

    fn sample_managed_demand_if_due(&mut self) -> Result<()> {
        let Some(next) = self.next_demand_sample else {
            return Ok(());
        };
        let now = Instant::now();
        if now < next {
            return Ok(());
        }
        let interval = self
            .demand_sample_interval
            .context("managed demand sampling has no interval")?;
        self.next_demand_sample = Some(now + interval);
        let topology = self
            .queue_topology
            .as_ref()
            .context("managed demand sampling has no queue topology")?;
        let snapshot = match read_cell_demand_snapshot(
            &self.skel,
            self.runtime.generation,
            self.runtime.active_slot,
            topology,
        ) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                warn!("managed-cell demand sample unavailable; retrying: {error:#}");
                return Ok(());
            }
        };
        let tracker = self
            .demand_tracker
            .as_mut()
            .context("managed demand sampling has no tracker")?;
        if let Err(error) = tracker
            .step(snapshot)
            .context("updating managed-cell demand EWMA")
        {
            warn!("managed-cell demand sample rejected; retrying: {error:#}");
            return Ok(());
        }

        if self
            .next_rebalance_allowed
            .is_some_and(|allowed| now < allowed)
        {
            return Ok(());
        }
        let resizing = self
            .runtime
            .compiled
            .managed_cells
            .as_ref()
            .and_then(|managed| managed.resizing.as_ref())
            .context("managed demand policy disappeared")?;
        if !tracker
            .spread_at_least(resizing.threshold_pct())
            .context("checking managed-cell demand spread")?
        {
            return Ok(());
        }
        let weights = tracker.demand_weights();
        let cooldown = Duration::from_millis(resizing.cooldown_ms);
        let applied = self.activate_resized_managed_topology(&weights)?;
        self.next_rebalance_allowed = Some(Instant::now() + cooldown);
        if applied {
            self.managed_rebalance_count = self
                .managed_rebalance_count
                .checked_add(1)
                .context("managed rebalance counter overflow")?;
            self.managed_last_rebalance_at_ms = unix_time_ms();
        }
        Ok(())
    }

    fn reconcile_managed_cells_if_due(&mut self) -> Result<()> {
        let Some(next) = self.next_managed_reconcile else {
            return Ok(());
        };
        if Instant::now() < next {
            return Ok(());
        }
        let interval = self
            .managed_reconcile_interval
            .context("managed reconciliation has no interval")?;
        self.next_managed_reconcile = Some(Instant::now() + interval);

        let transition_started = Instant::now();
        let started_at_ms = unix_time_ms();
        let discovery_started = Instant::now();
        let mut candidate = self.runtime.compiled.clone();
        if let Err(error) = managed_cells::resolve_managed_cells(&mut candidate)
            .context("discovering live managed cells")
        {
            let mut transition = TopologyTransitionAttempt::new(
                self.inspector.next_topology_transition_id(),
                self.runtime.generation,
                started_at_ms,
            );
            let detail = format!("{error:#}");
            transition.fail_stage("discovery", discovery_started.elapsed(), detail.clone());
            self.inspector.record_topology_transition(transition.finish(
                inspection::TopologyTransitionOutcome::Rejected,
                None,
                unix_time_ms(),
                transition_started.elapsed(),
                Some(detail),
            ));
            warn!(
                "managed-cell discovery changed while scanning; preserving the active topology and retrying: {error:#}"
            );
            return Ok(());
        }
        if candidate == self.runtime.compiled {
            return Ok(());
        }
        let mut transition = TopologyTransitionAttempt::new(
            self.inspector.next_topology_transition_id(),
            self.runtime.generation,
            started_at_ms,
        );
        transition.complete_stage("discovery", discovery_started.elapsed());

        let resolution_started = Instant::now();
        let projected_weights = self.demand_tracker.as_ref().map(|tracker| {
            let identities = std::iter::once(demand::CellIdentity {
                id: 0,
                slot_epoch: 0,
            })
            .chain(candidate.cells.keys().map(|&id| demand::CellIdentity {
                id,
                slot_epoch: candidate.cell_slot_epochs.get(&id).copied().unwrap_or(0),
            }));
            tracker.projected_demand_weights(identities)
        });
        let topology =
            match resolve_host_queue_topology_with_demands(&candidate, projected_weights.as_ref())
                .context("resolving live managed cell topology")
            {
                Ok(Some(topology)) => topology,
                Ok(None) => {
                    let error = anyhow!("managed cells resolved without a queue topology");
                    let detail = format!("{error:#}");
                    transition.fail_stage(
                        "resolution",
                        resolution_started.elapsed(),
                        detail.clone(),
                    );
                    self.inspector.record_topology_transition(transition.finish(
                        inspection::TopologyTransitionOutcome::Rejected,
                        None,
                        unix_time_ms(),
                        transition_started.elapsed(),
                        Some(detail),
                    ));
                    return Err(error);
                }
                Err(error) => {
                    let detail = format!("{error:#}");
                    transition.fail_stage(
                        "resolution",
                        resolution_started.elapsed(),
                        detail.clone(),
                    );
                    self.inspector.record_topology_transition(transition.finish(
                        inspection::TopologyTransitionOutcome::Rejected,
                        None,
                        unix_time_ms(),
                        transition_started.elapsed(),
                        Some(detail),
                    ));
                    return Err(error);
                }
            };
        let active_topology = self
            .queue_topology
            .as_ref()
            .context("managed reconciliation has no active queue topology")?;
        if !queue_topology::same_host_queue_universe(active_topology, &topology) {
            let error = anyhow!(
                "host CPU/LLC topology changed during managed reconciliation; restart Snake"
            );
            let detail = format!("{error:#}");
            transition.fail_stage("resolution", resolution_started.elapsed(), detail.clone());
            self.inspector.record_topology_transition(transition.finish(
                inspection::TopologyTransitionOutcome::Rejected,
                None,
                unix_time_ms(),
                transition_started.elapsed(),
                Some(detail),
            ));
            return Err(error);
        }
        let tables = match resolve_mask_tables(&candidate)
            .context("resolving live managed cell mask tables")
        {
            Ok(tables) => tables,
            Err(error) => {
                let detail = format!("{error:#}");
                transition.fail_stage("resolution", resolution_started.elapsed(), detail.clone());
                self.inspector.record_topology_transition(transition.finish(
                    inspection::TopologyTransitionOutcome::Rejected,
                    None,
                    unix_time_ms(),
                    transition_started.elapsed(),
                    Some(detail),
                ));
                return Err(error);
            }
        };
        transition.complete_stage("resolution", resolution_started.elapsed());
        transition.cell_changes = inspection::topology_transition_changes(
            self.queue_topology.as_ref(),
            Some(&topology),
            &topology_cell_names(&self.runtime.compiled),
            &topology_cell_names(&candidate),
        );

        let previous_slot = self.runtime.active_slot;
        let frozen_metrics = self.metrics()?;
        let drain_started = Instant::now();
        if let Err(error) = set_queue_draining(&mut self.skel, true) {
            let detail = format!("{error:#}");
            transition.fail_stage("drain", drain_started.elapsed(), detail.clone());
            self.inspector.record_topology_transition(transition.finish(
                inspection::TopologyTransitionOutcome::Rejected,
                None,
                unix_time_ms(),
                transition_started.elapsed(),
                Some(detail),
            ));
            return Err(error);
        }
        if let Err(error) = wait_for_queue_drain(&mut self.skel, SLOT_QUIESCENCE_TIMEOUT) {
            let detail = format!("{error:#}");
            transition.fail_stage("drain", drain_started.elapsed(), detail.clone());
            self.inspector.record_topology_transition(transition.finish(
                inspection::TopologyTransitionOutcome::Deferred,
                None,
                unix_time_ms(),
                transition_started.elapsed(),
                Some(detail),
            ));
            set_queue_draining(&mut self.skel, false)?;
            warn!("managed cell topology activation deferred: {error:#}");
            return Ok(());
        }
        transition.complete_stage("drain", drain_started.elapsed());

        let publication_started = Instant::now();
        let source = self.runtime.source.clone();
        let activation = {
            let mut backend = BpfPolicyBackend {
                skel: &mut self.skel,
                queue_topology: Some(&topology),
                previous_slot,
            };
            runtime_policy::activate_compiled_policy(
                self.runtime,
                source,
                candidate,
                &tables,
                &mut backend,
            )
        };
        let response = match activation {
            Ok(response) => response,
            Err(error) => {
                let detail = format!("{error:#}");
                transition.fail_stage("publication", publication_started.elapsed(), detail.clone());
                self.inspector.record_topology_transition(transition.finish(
                    inspection::TopologyTransitionOutcome::Rejected,
                    None,
                    unix_time_ms(),
                    transition_started.elapsed(),
                    Some(detail),
                ));
                set_queue_draining(&mut self.skel, false)?;
                return Err(error);
            }
        };
        transition.complete_stage("publication", publication_started.elapsed());
        let quiescence_started = Instant::now();
        if let Err(error) =
            wait_for_slot_quiescent(&self.skel, previous_slot, SLOT_QUIESCENCE_TIMEOUT)
                .context("waiting for the retired managed topology bank")
        {
            let detail = format!("{error:#}");
            transition.fail_stage("quiescence", quiescence_started.elapsed(), detail.clone());
            self.inspector.record_topology_transition(transition.finish(
                inspection::TopologyTransitionOutcome::Applied,
                Some(response.generation),
                unix_time_ms(),
                transition_started.elapsed(),
                Some(detail),
            ));
            return Err(error);
        }
        transition.complete_stage("quiescence", quiescence_started.elapsed());
        set_queue_draining(&mut self.skel, false)?;
        self.queue_topology = Some(topology.clone());
        if let Err(error) = self.rebase_managed_demand() {
            warn!("managed-cell demand rebase after topology change failed: {error:#}");
        }

        let membership_started = Instant::now();
        let Some(membership_policy) = self.runtime.compiled.membership.as_ref() else {
            let error = anyhow!("managed topology has no membership policy");
            let detail = format!("{error:#}");
            transition.fail_stage("membership", membership_started.elapsed(), detail.clone());
            self.inspector.record_topology_transition(transition.finish(
                inspection::TopologyTransitionOutcome::Applied,
                Some(response.generation),
                unix_time_ms(),
                transition_started.elapsed(),
                Some(detail),
            ));
            return Err(error);
        };
        let directory =
            CellDirectory::from_policy(membership_policy, &self.runtime.compiled.cell_slot_epochs);
        let Some(manager) = self.membership.as_mut() else {
            let error = anyhow!("managed topology has no membership manager");
            let detail = format!("{error:#}");
            transition.fail_stage("membership", membership_started.elapsed(), detail.clone());
            self.inspector.record_topology_transition(transition.finish(
                inspection::TopologyTransitionOutcome::Applied,
                Some(response.generation),
                unix_time_ms(),
                transition_started.elapsed(),
                Some(detail),
            ));
            return Err(error);
        };
        manager.replace_directory(directory);
        match manager.reconcile(&self.skel.maps.task_cells) {
            Ok(report) => {
                transition.complete_stage("membership", membership_started.elapsed());
                debug!(
                    "managed topology membership discovered {}, updated {}, transient {}",
                    report.discovered, report.updated, report.transient
                );
            }
            Err(error) => {
                transition.warn_stage(
                    "membership",
                    membership_started.elapsed(),
                    format!("{error:#}"),
                );
                warn!("managed topology membership update failed: {error:#}");
            }
        }

        let activated_at_ms = unix_time_ms();
        self.inspector.set_queue_topology(Some(topology));
        self.inspector.activate(
            SlotPolicy::new(
                self.runtime.active_slot,
                self.runtime.generation,
                self.runtime.source.clone(),
                self.runtime.compiled.clone(),
                tables,
                activated_at_ms,
            ),
            frozen_metrics,
            activated_at_ms,
        );
        self.inspector.record_topology_transition(transition.finish(
            inspection::TopologyTransitionOutcome::Applied,
            Some(response.generation),
            unix_time_ms(),
            transition_started.elapsed(),
            None,
        ));
        info!(
            "activated managed cell topology generation {} with {} managed cells",
            response.generation,
            self.runtime.compiled.cells.len()
        );
        Ok(())
    }

    fn activate_resized_managed_topology(&mut self, weights: &BTreeMap<u32, f64>) -> Result<bool> {
        let transition_started = Instant::now();
        let started_at_ms = unix_time_ms();
        let mut transition = TopologyTransitionAttempt::new_with_reason(
            self.inspector.next_topology_transition_id(),
            self.runtime.generation,
            started_at_ms,
            "managed_cells_rebalanced",
        );
        let resolution_started = Instant::now();
        let resolution = (|| {
            let topology =
                resolve_host_queue_topology_with_demands(&self.runtime.compiled, Some(weights))?
                    .context("managed demand policy resolved without a queue topology")?;
            let tables = resolve_mask_tables(&self.runtime.compiled)
                .context("resolving managed rebalance mask tables")?;
            Ok::<_, anyhow::Error>((topology, tables))
        })();
        let (topology, tables) = match resolution {
            Ok(resolution) => resolution,
            Err(error) => {
                let detail = format!("{error:#}");
                transition.fail_stage("resolution", resolution_started.elapsed(), detail.clone());
                self.inspector.record_topology_transition(transition.finish(
                    inspection::TopologyTransitionOutcome::Rejected,
                    None,
                    unix_time_ms(),
                    transition_started.elapsed(),
                    Some(detail),
                ));
                return Err(error);
            }
        };
        if self.queue_topology.as_ref() == Some(&topology) {
            return Ok(false);
        }
        let active_topology = self
            .queue_topology
            .as_ref()
            .context("managed demand resize has no active queue topology")?;
        if !queue_topology::same_host_queue_universe(active_topology, &topology) {
            let error =
                anyhow!("host CPU/LLC topology changed during managed resizing; restart Snake");
            let detail = format!("{error:#}");
            transition.fail_stage("resolution", resolution_started.elapsed(), detail.clone());
            self.inspector.record_topology_transition(transition.finish(
                inspection::TopologyTransitionOutcome::Rejected,
                None,
                unix_time_ms(),
                transition_started.elapsed(),
                Some(detail),
            ));
            return Err(error);
        }
        let mut dispatch_managed = policy_dispatches_orphan_queues(&self.runtime.compiled)
            && queue_topology::preserves_resize_queue_identity(active_topology, &topology);
        transition.complete_stage("resolution", resolution_started.elapsed());
        transition.cell_changes = inspection::topology_transition_changes(
            self.queue_topology.as_ref(),
            Some(&topology),
            &topology_cell_names(&self.runtime.compiled),
            &topology_cell_names(&self.runtime.compiled),
        );
        let previous_slot = self.runtime.active_slot;
        let frozen_metrics = self.metrics()?;

        let drain_started = Instant::now();
        if let Err(error) = set_queue_transition_cpus(&mut self.skel, active_topology, &topology)
            .and_then(|_| set_queue_draining(&mut self.skel, true))
        {
            let detail = format!("{error:#}");
            transition.fail_stage("drain", drain_started.elapsed(), detail.clone());
            self.inspector.record_topology_transition(transition.finish(
                inspection::TopologyTransitionOutcome::Rejected,
                None,
                unix_time_ms(),
                transition_started.elapsed(),
                Some(detail),
            ));
            return Err(error);
        }
        let drain_result = (|| {
            if dispatch_managed {
                wait_for_queue_enqueues_quiescent(&self.skel, SLOT_QUIESCENCE_TIMEOUT)?;
                dispatch_managed = affinity_queues_empty(&mut self.skel)?;
            }
            if !dispatch_managed {
                wait_for_queue_drain(&mut self.skel, SLOT_QUIESCENCE_TIMEOUT)?;
            }
            Ok::<_, anyhow::Error>(())
        })();
        if let Err(error) = drain_result {
            let detail = format!("{error:#}");
            transition.fail_stage("drain", drain_started.elapsed(), detail.clone());
            self.inspector.record_topology_transition(transition.finish(
                inspection::TopologyTransitionOutcome::Deferred,
                None,
                unix_time_ms(),
                transition_started.elapsed(),
                Some(detail),
            ));
            set_queue_draining(&mut self.skel, false)?;
            warn!("managed demand resize deferred while draining: {error:#}");
            return Ok(false);
        }
        transition.complete_stage("drain", drain_started.elapsed());

        let publication_started = Instant::now();
        let candidate = self.runtime.compiled.clone();
        let source = self.runtime.source.clone();
        let activation = {
            let mut backend = BpfPolicyBackend {
                skel: &mut self.skel,
                queue_topology: Some(&topology),
                previous_slot,
            };
            runtime_policy::activate_compiled_policy(
                self.runtime,
                source,
                candidate,
                &tables,
                &mut backend,
            )
        };
        let response = match activation {
            Ok(response) => response,
            Err(error) => {
                let detail = format!("{error:#}");
                transition.fail_stage("publication", publication_started.elapsed(), detail.clone());
                self.inspector.record_topology_transition(transition.finish(
                    inspection::TopologyTransitionOutcome::Rejected,
                    None,
                    unix_time_ms(),
                    transition_started.elapsed(),
                    Some(detail),
                ));
                set_queue_draining(&mut self.skel, false)?;
                return Err(error);
            }
        };
        transition.complete_stage("publication", publication_started.elapsed());
        let quiescence_started = Instant::now();
        let quiescence =
            wait_for_slot_quiescent(&self.skel, previous_slot, SLOT_QUIESCENCE_TIMEOUT)
                .context("waiting for the retired managed rebalance bank")
                .and_then(|_| {
                    if dispatch_managed {
                        refresh_queue_runtime(&mut self.skel).context(
                            "refreshing queue runtime after retired managed callbacks quiesced",
                        )
                    } else {
                        Ok(())
                    }
                });
        if let Err(error) = quiescence {
            let detail = format!("{error:#}");
            transition.fail_stage("quiescence", quiescence_started.elapsed(), detail.clone());
            self.inspector.record_topology_transition(transition.finish(
                inspection::TopologyTransitionOutcome::Applied,
                Some(response.generation),
                unix_time_ms(),
                transition_started.elapsed(),
                Some(detail),
            ));
            set_queue_draining(&mut self.skel, false)?;
            return Err(error);
        }
        transition.complete_stage("quiescence", quiescence_started.elapsed());
        set_queue_draining(&mut self.skel, false)?;
        self.queue_topology = Some(topology.clone());
        if let Err(error) = self.rebase_managed_demand() {
            warn!("managed-cell demand rebase after resize failed: {error:#}");
        }

        let activated_at_ms = unix_time_ms();
        self.inspector.set_queue_topology(Some(topology));
        self.inspector.activate(
            SlotPolicy::new(
                self.runtime.active_slot,
                self.runtime.generation,
                self.runtime.source.clone(),
                self.runtime.compiled.clone(),
                tables,
                activated_at_ms,
            ),
            frozen_metrics,
            activated_at_ms,
        );
        self.inspector.record_topology_transition(transition.finish(
            inspection::TopologyTransitionOutcome::Applied,
            Some(response.generation),
            activated_at_ms,
            transition_started.elapsed(),
            None,
        ));
        info!(
            "activated managed-cell demand rebalance generation {}",
            response.generation
        );
        Ok(true)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (response_channel, request_channel) = self.stats_server.channels();
        let live_managed_cells = self.managed_reconcile_interval.is_some();
        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            let mut timeout = self
                .membership
                .as_ref()
                .map(MembershipManager::time_until_reconcile)
                .unwrap_or(Duration::from_secs(1))
                .min(Duration::from_secs(1));
            if let Some(managed_timeout) = self.time_until_managed_reconcile() {
                timeout = timeout.min(managed_timeout);
            }
            if let Some(demand_timeout) = self.time_until_demand_sample() {
                timeout = timeout.min(demand_timeout);
            }
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
            self.reconcile_managed_cells_if_due()?;
            if let Some(manager) = &mut self.membership {
                match manager.reconcile_if_due(&self.skel.maps.task_cells) {
                    Ok(Some(report)) if report.updated != 0 || report.transient != 0 => debug!(
                        "membership reconciliation discovered {}, updated {}, transient {}",
                        report.discovered, report.updated, report.transient
                    ),
                    Ok(_) => {}
                    Err(error) => {
                        if manager.identity_errors_are_fatal() && !live_managed_cells {
                            return Err(error).context(
                                "managed child identity changed; restart Snake to resolve managed cells",
                            );
                        }
                        if manager.identity_errors_are_fatal() {
                            self.next_managed_reconcile = Some(Instant::now());
                            warn!(
                                "managed child changed during membership reconciliation; retrying topology discovery: {error:#}"
                            );
                        } else {
                            warn!("task membership reconciliation failed: {error:#}");
                        }
                    }
                }
            }
            self.sample_managed_demand_if_due()?;
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
        RunMode::Validate(path) => {
            let report = policy_validation::validate_policy_file(&path);
            println!("{}", serde_json::to_string_pretty(&report)?);
            if !report.is_valid() {
                std::process::exit(2);
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
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::mem::{offset_of, size_of};
    use std::path::{Path, PathBuf};

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

    fn bpf_sources(bpf_dir: &Path) -> Vec<(PathBuf, String)> {
        let mut sources = fs::read_dir(bpf_dir)
            .expect("BPF source directory should exist")
            .map(|entry| entry.expect("BPF source entry should be readable").path())
            .filter(|path| {
                matches!(
                    path.extension().and_then(|extension| extension.to_str()),
                    Some("h" | "c")
                )
            })
            .map(|path| {
                let source = fs::read_to_string(&path).expect("BPF source should be readable");
                (path, source)
            })
            .collect::<Vec<_>>();
        sources.sort_by(|left, right| left.0.cmp(&right.0));
        sources
    }

    fn assert_acyclic_bpf_includes(
        name: &str,
        sources: &BTreeMap<String, &str>,
        visiting: &mut BTreeSet<String>,
        visited: &mut BTreeSet<String>,
    ) {
        if visited.contains(name) {
            return;
        }
        assert!(
            visiting.insert(name.to_owned()),
            "BPF local include cycle reaches {name}"
        );
        let source = sources
            .get(name)
            .unwrap_or_else(|| panic!("BPF source `{name}` should exist"));
        for include in source
            .lines()
            .filter_map(|line| line.trim().strip_prefix("#include \"")?.strip_suffix('"'))
        {
            assert_acyclic_bpf_includes(include, sources, visiting, visited);
        }
        visiting.remove(name);
        visited.insert(name.to_owned());
    }

    fn assert_text_order(source: &str, labels: &[&str]) {
        let mut offset = 0;
        for label in labels {
            let index = source[offset..]
                .find(label)
                .unwrap_or_else(|| panic!("missing ordered source marker `{label}`"));
            offset += index + label.len();
        }
    }

    #[test]
    fn bpf_is_one_translation_unit_and_all_headers_are_reachable() {
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let sources = bpf_sources(&bpf_dir);
        let translation_units = sources
            .iter()
            .filter(|(path, _)| path.extension().and_then(|value| value.to_str()) == Some("c"))
            .map(|(path, _)| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert_eq!(translation_units, ["main.bpf.c"]);

        let by_name = sources
            .iter()
            .map(|(path, source)| {
                (
                    path.file_name().unwrap().to_string_lossy().into_owned(),
                    source.as_str(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let mut pending = vec!["main.bpf.c".to_owned()];
        let mut reachable = BTreeSet::new();
        while let Some(name) = pending.pop() {
            if !reachable.insert(name.clone()) {
                continue;
            }
            let source = by_name
                .get(&name)
                .unwrap_or_else(|| panic!("included BPF source `{name}` should exist"));
            for include in source
                .lines()
                .filter_map(|line| line.trim().strip_prefix("#include \"")?.strip_suffix('"'))
            {
                assert!(
                    by_name.contains_key(include),
                    "{name} includes missing local header {include}"
                );
                pending.push(include.to_owned());
            }
        }
        let expected = by_name.keys().cloned().collect::<BTreeSet<_>>();
        assert_eq!(reachable, expected);

        for (name, source) in &by_name {
            if name != "main.bpf.c" {
                assert!(
                    !source.contains("#include \"main.h\""),
                    "only main.bpf.c may include the BPF umbrella; found in {name}"
                );
            }
        }
        let mut visiting = BTreeSet::new();
        let mut visited = BTreeSet::new();
        for name in by_name.keys() {
            assert_acyclic_bpf_includes(name, &by_name, &mut visiting, &mut visited);
        }
    }

    #[test]
    fn bpf_external_map_and_program_surface_is_stable() {
        const EXPECTED_MAP_DEFINITIONS: &[&str] = &[
            r#"struct {
                __uint(type, BPF_MAP_TYPE_ARRAY);
                __type(key, u32);
                __type(value, struct snake_compiled_ladder);
                __uint(max_entries, SNAKE_LADDER_SLOTS);
            } compiled_ladders SEC(".maps");"#,
            r#"struct {
                __uint(type, BPF_MAP_TYPE_ARRAY);
                __type(key, u32);
                __type(value, u32);
                __uint(max_entries, 1);
            } active_ladder SEC(".maps");"#,
            r#"struct {
                __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
                __type(key, u32);
                __type(value, u32);
                __uint(max_entries, SNAKE_LADDER_SLOTS);
            } ladder_readers SEC(".maps");"#,
            r#"struct {
                __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
                __type(key, u32);
                __type(value, u64);
                __uint(max_entries, SNAKE_LADDER_SLOTS * SNAKE_NR_STATS);
            } stats SEC(".maps");"#,
            r#"struct {
                __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
                __type(key, u32);
                __type(value, u64);
                __uint(max_entries, SNAKE_LADDER_SLOTS * SNAKE_MAX_QUEUE_CELLS *
                                            SNAKE_NR_CELL_STATS);
            } cell_stats SEC(".maps");"#,
            r#"struct {
                __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
                __type(key, u32);
                __type(value, struct snake_callback_timing);
                __uint(max_entries, SNAKE_LADDER_SLOTS * SNAKE_NR_CALLBACKS);
            } callback_timing SEC(".maps");"#,
            r#"struct {
                __uint(type, BPF_MAP_TYPE_ARRAY);
                __type(key, u32);
                __type(value, struct snake_fine_timing_config);
                __uint(max_entries, 1);
            } fine_timing_config SEC(".maps");"#,
            r#"struct {
                __uint(type, BPF_MAP_TYPE_RINGBUF);
                __uint(max_entries, 1024 * 1024);
            } fine_timing_events SEC(".maps");"#,
            r#"struct {
                __uint(type, BPF_MAP_TYPE_RINGBUF);
                __uint(max_entries, 1024 * 1024);
            } rung_timing_events SEC(".maps");"#,
            r#"struct {
                __uint(type, BPF_MAP_TYPE_RINGBUF);
                __uint(max_entries, 1024 * 1024);
            } queue_timing_events SEC(".maps");"#,
            r#"struct {
                __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
                __uint(map_flags, BPF_F_NO_PREALLOC);
                __type(key, int);
                __type(value, struct snake_task_runtime);
            } task_runtimes SEC(".maps");"#,
            r#"struct {
                __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
                __uint(map_flags, BPF_F_NO_PREALLOC);
                __type(key, int);
                __type(value, struct snake_task_cell);
            } task_cells SEC(".maps");"#,
            r#"struct {
                __uint(type, BPF_MAP_TYPE_ARRAY);
                __type(key, u32);
                __type(value, struct snake_queue_header);
                __uint(max_entries, SNAKE_LADDER_SLOTS);
            } queue_header SEC(".maps");"#,
            r#"struct {
                __uint(type, BPF_MAP_TYPE_ARRAY);
                __type(key, u32);
                __type(value, u32);
                __uint(max_entries, SNAKE_LADDER_SLOTS * SNAKE_MAX_CPUS);
            } queue_cell_lookup SEC(".maps");"#,
            r#"struct {
                __uint(type, BPF_MAP_TYPE_ARRAY);
                __type(key, u32);
                __type(value, struct snake_queue_cell);
                __uint(max_entries, SNAKE_LADDER_SLOTS * SNAKE_MAX_QUEUE_CELLS);
            } queue_cells SEC(".maps");"#,
            r#"struct {
                __uint(type, BPF_MAP_TYPE_ARRAY);
                __type(key, u32);
                __type(value, struct snake_normal_queue);
                __uint(max_entries, SNAKE_LADDER_SLOTS * SNAKE_MAX_NORMAL_QUEUES);
            } normal_queues SEC(".maps");"#,
            r#"struct {
                __uint(type, BPF_MAP_TYPE_ARRAY);
                __type(key, u32);
                __type(value, struct snake_cpu_queue);
                __uint(max_entries, SNAKE_LADDER_SLOTS * SNAKE_MAX_CPUS);
            } cpu_queues SEC(".maps");"#,
            r#"struct {
                __uint(type, BPF_MAP_TYPE_ARRAY);
                __type(key, u32);
                __type(value, struct snake_queue_cell_masks);
                __uint(max_entries, SNAKE_LADDER_SLOTS * SNAKE_MAX_QUEUE_CELLS);
            } queue_cell_masks SEC(".maps");"#,
            r#"struct {
                __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
                __type(key, u32);
                __type(value, struct snake_queue_cpu_state);
                __uint(max_entries, 1);
            } queue_cpu_states SEC(".maps");"#,
            r#"struct {
                __uint(type, BPF_MAP_TYPE_ARRAY);
                __type(key, u32);
                __type(value, struct snake_mask_data);
                __uint(max_entries, SNAKE_LADDER_SLOTS * SNAKE_MAX_MASK_TABLES * SNAKE_MAX_CPUS);
            } mask_data SEC(".maps");"#,
            r#"struct {
                __uint(type, BPF_MAP_TYPE_ARRAY);
                __type(key, u32);
                __type(value, struct snake_mask_slot);
                __uint(max_entries, SNAKE_LADDER_SLOTS * SNAKE_MAX_MASK_TABLES * SNAKE_MAX_CPUS);
            } mask_slots SEC(".maps");"#,
            r#"struct {
                __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
                __type(key, u32);
                __type(value, struct snake_mask_scratch);
                __uint(max_entries, 1);
            } mask_scratch SEC(".maps");"#,
            r#"struct {
                __uint(type, BPF_MAP_TYPE_ARRAY);
                __type(key, u32);
                __type(value, struct snake_vtime_domain);
                __uint(max_entries, 1);
            } vtime_domain SEC(".maps");"#,
            r#"struct {
                __uint(type, BPF_MAP_TYPE_ARRAY);
                __type(key, u32);
                __type(value, struct snake_eevdf_domain);
                __uint(max_entries, 1);
            } eevdf_domain SEC(".maps");"#,
            r#"struct {
                __uint(type, BPF_MAP_TYPE_ARRAY);
                __type(key, u32);
                __type(value, struct snake_vtime_domain);
                __uint(max_entries, SNAKE_MAX_QUEUE_CELLS);
            } cell_vtime_domains SEC(".maps");"#,
        ];
        const EXPECTED_MAPS: &[&str] = &[
            ".data.uei_dump",
            "active_ladder",
            "affinity_queue_runtime",
            "bpf_bpf.bss",
            "bpf_bpf.data",
            "bpf_bpf.kconfig",
            "bpf_bpf.rodata",
            "callback_timing",
            "cell_queue_runtime",
            "cell_stats",
            "cell_vtime_domains",
            "compiled_ladders",
            "cpu_queues",
            "eevdf_domain",
            "fine_timing_config",
            "fine_timing_events",
            "ladder_readers",
            "mask_data",
            "mask_scratch",
            "mask_slots",
            "normal_queue_masks",
            "normal_queue_runtime",
            "normal_queues",
            "queue_cell_lookup",
            "queue_cell_masks",
            "queue_cells",
            "queue_cpu_states",
            "queue_enqueue_inflight",
            "queue_header",
            "queue_timing_events",
            "rung_timing_events",
            "snake_ops",
            "stats",
            "task_cells",
            "task_runtimes",
            "vtime_domain",
        ];
        const EXPECTED_PROGRAMS: &[&str] = &[
            "prepare_ladder",
            "queue_affinity_drain_ready",
            "queue_drain_ready",
            "queue_refresh_runtime",
            "scx_lib_init_probe",
            "snake_dequeue",
            "snake_dispatch",
            "snake_enqueue",
            "snake_enqueue_expanded",
            "snake_enqueue_no_direct",
            "snake_exit",
            "snake_init",
            "snake_init_task",
            "snake_quiescent",
            "snake_runnable",
            "snake_running",
            "snake_select_cpu",
            "snake_select_cpu_expanded",
            "snake_set_weight",
            "snake_stopping",
        ];

        let skeleton = include_str!(concat!(env!("OUT_DIR"), "/bpf_skel.rs"));
        let mut maps = skeleton
            .lines()
            .filter_map(|line| {
                line.trim()
                    .strip_prefix(".map(\"")?
                    .split_once('"')
                    .map(|(name, _)| name)
            })
            .collect::<Vec<_>>();
        maps.sort_unstable();
        let mut programs = skeleton
            .lines()
            .filter_map(|line| {
                line.trim()
                    .strip_prefix(".prog(\"")?
                    .split_once('"')
                    .map(|(name, _)| name)
            })
            .collect::<Vec<_>>();
        programs.sort_unstable();

        assert_eq!(maps, EXPECTED_MAPS);
        assert_eq!(programs, EXPECTED_PROGRAMS);

        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let combined = bpf_sources(&bpf_dir)
            .into_iter()
            .map(|(_, source)| source)
            .collect::<Vec<_>>()
            .join("\n");
        let normalized = combined.split_whitespace().collect::<String>();
        for definition in EXPECTED_MAP_DEFINITIONS {
            let definition = definition.split_whitespace().collect::<String>();
            assert!(
                normalized.contains(&definition),
                "BPF map definition changed: {definition}"
            );
        }

        let main = fs::read_to_string(bpf_dir.join("main.bpf.c"))
            .expect("main BPF translation unit should be readable");
        let ops = main
            .split_once("SCX_OPS_DEFINE(")
            .and_then(|(_, rest)| rest.split_once(");"))
            .map(|(ops, _)| ops.split_whitespace().collect::<String>())
            .expect("snake_ops definition should exist");
        assert_eq!(
            ops,
            concat!(
                "snake_ops,",
                ".select_cpu=(void*)snake_select_cpu,",
                ".init_task=(void*)snake_init_task,",
                ".enqueue=(void*)snake_enqueue,",
                ".dequeue=(void*)snake_dequeue,",
                ".dispatch=(void*)snake_dispatch,",
                ".runnable=(void*)snake_runnable,",
                ".running=(void*)snake_running,",
                ".stopping=(void*)snake_stopping,",
                ".quiescent=(void*)snake_quiescent,",
                ".set_weight=(void*)snake_set_weight,",
                ".init=(void*)snake_init,",
                ".exit=(void*)snake_exit,",
                ".timeout_ms=5000,",
                ".name=\"snake\""
            )
        );
    }

    #[test]
    fn queue_topology_is_banked_with_the_pinned_ladder_slot() {
        let state = include_str!("bpf/queue_state.h");
        let bank = include_str!("bpf/policy_bank.h");
        let init = include_str!("bpf/queue_init.h");
        let main = include_str!("bpf/main.bpf.c");

        for capacity in [
            "SNAKE_LADDER_SLOTS * SNAKE_MAX_CPUS",
            "SNAKE_LADDER_SLOTS * SNAKE_MAX_QUEUE_CELLS",
            "SNAKE_LADDER_SLOTS * SNAKE_MAX_NORMAL_QUEUES",
        ] {
            assert!(
                state.contains(capacity),
                "missing banked capacity {capacity}"
            );
        }
        assert!(state.contains("queue_config(const struct snake_ladder_ctx *ctx)"));
        assert!(state.contains("queue_cell_mask_slot(ctx->slot, index, kind)"));
        assert!(state.contains("queue_slot_index(slot, SNAKE_MAX_QUEUE_CELLS"));
        assert!(state.contains("queue_slot_index(ctx->slot, SNAKE_MAX_NORMAL_QUEUES"));
        assert!(state.contains("queue_cpu_slot(ctx->slot, cpu)"));
        assert!(state.contains("queue_slot_index(slot, SNAKE_MAX_CPUS"));
        assert!(bank.contains("Pin one complete policy and topology slot"));
        assert!(init.contains("prepare_queue_topology(u32 slot)"));
        assert!(init.contains("i >= header->nr_normal_dsqs"));
        assert!(main.contains("prepare_queue_topology(slot)"));

        let validation = init
            .split_once("static __always_inline int validate_queue_topology(u32 bank)")
            .and_then(|(_, body)| {
                body.split_once("static __always_inline int create_queue_topology_dsqs")
            })
            .map(|(body, _)| body)
            .expect("queue topology validator should have one definition");
        assert!(validation.contains("cell = queue_cell_slot(bank, i);"));
        assert!(!validation.contains("bpf_map_lookup_elem(&queue_cells, &i)"));
    }

    #[test]
    fn live_topology_transition_stops_custom_inserts_until_old_readers_drain() {
        let source = include_str!("main.rs");
        let main = include_str!("bpf/main.bpf.c");
        let state = include_str!("bpf/queue_state.h");
        let enqueue = include_str!("bpf/queue_enqueue.h");
        let init = include_str!("bpf/queue_init.h");

        assert!(main.contains("queue_draining;"));
        assert!(!main.contains("u32\t\t\t\t   queue_enqueue_inflight;"));
        assert!(state.contains("} queue_enqueue_inflight SEC(\".maps\")"));
        assert!(state.contains("BPF_MAP_TYPE_PERCPU_ARRAY"));
        assert!(state.contains("queue_enqueue_inflight_gate("));
        let gate = state
            .split_once("queue_enqueue_inflight_gate(")
            .and_then(|(_, body)| body.split_once("queue_enqueue_inflight_exit("))
            .map(|(body, _)| body)
            .expect("queue enqueue gate should have one bounded body");
        assert_eq!(gate.matches("queue_transition_active()").count(), 2);
        assert_text_order(
            gate,
            &[
                "queue_transition_active()",
                "__sync_fetch_and_add(inflight, 1)",
                "queue_transition_active()",
            ],
        );
        assert!(main.contains("queue_enqueue_inflight_exit()"));
        let close = source
            .split_once("fn set_queue_draining(")
            .and_then(|(_, body)| body.split_once("fn queue_enqueues_inflight("))
            .map(|(body, _)| body)
            .expect("queue transition close should have one bounded helper");
        assert!(close.contains("AtomicU32"));
        assert!(close.contains("store(u32::from(draining), Ordering::Release)"));
        let inflight_reader = source
            .split_once("fn queue_enqueues_inflight(")
            .and_then(|(_, body)| body.split_once("fn wait_for_queue_drain("))
            .map(|(body, _)| body)
            .unwrap();
        assert!(inflight_reader.contains(".queue_enqueue_inflight"));
        assert!(inflight_reader.contains(".lookup_percpu"));
        assert!(main.contains("SEC(\"syscall\")\nint queue_drain_ready"));
        assert!(main.contains("if (queue_transition_active())"));
        assert!(main.contains("goto direct_dispatch;"));
        assert!(enqueue.contains("queue_transition_enqueue("));
        assert!(enqueue.contains("if (queue_transition_active())"));
        assert!(init.contains("header->nr_cpus"));
        assert!(main.contains("if (!queue_cpu_slot(active, i))"));
        assert!(main.contains("if (queued < 0)\n\t\t\treturn queued;"));
        assert!(main.contains("dsq_nr_queued(dsq_affinity(i))"));
        assert!(main.contains("dsq_nr_queued(dsq_normal(i))"));
        assert!(main.contains("READ_ONCE(runtime->nr_queued)"));
    }

    #[test]
    fn managed_resize_fences_affinity_queues_before_optimized_publication() {
        let source = include_str!("main.rs");
        let bpf = include_str!("bpf/main.bpf.c");
        let resize = source
            .split_once("fn activate_resized_managed_topology(")
            .and_then(|(_, body)| body.split_once("fn run(&mut self, shutdown:"))
            .map(|(body, _)| body)
            .expect("managed resize activation should be bounded");
        let affinity_check = bpf
            .split_once("queue_affinity_drain_ready_slot(")
            .and_then(|(_, body)| body.split_once("int queue_affinity_drain_ready(void *ctx)"))
            .map(|(body, _)| body)
            .expect("affinity drain checker should be bounded");
        let normalized_bpf = bpf.split_whitespace().collect::<String>();

        assert!(affinity_check.contains("dsq_nr_queued(dsq_affinity(i))"));
        assert!(affinity_check.contains("affinity_queue_runtime"));
        assert!(affinity_check.contains("READ_ONCE(affinity_runtime->nr_queued)"));
        assert!(affinity_check.contains("queue_mask_contains(&queue_transition_cpus, i)"));
        assert!(normalized_bpf.contains("structsnake_mask_dataqueue_transition_cpus;"));
        assert_text_order(
            resize,
            &[
                "set_queue_transition_cpus(",
                "set_queue_draining(&mut self.skel, true)",
                "wait_for_queue_enqueues_quiescent(",
                "affinity_queues_empty(",
                "if !dispatch_managed",
                "wait_for_queue_drain(&mut self.skel",
                "activate_compiled_policy(",
            ],
        );
        assert!(resize.contains("set_queue_draining(&mut self.skel, false)"));
    }

    #[test]
    fn queued_local_tasks_resolve_cell_identity_after_a_topology_bank_change() {
        let vtime = include_str!("bpf/queue_vtime.h");
        let resolver = vtime
            .split_once("queue_fairness_resolve_runtime_cell(")
            .and_then(|(_, body)| body.split_once("queue_fairness_prepare_task_for_cell("))
            .map(|(body, _)| body)
            .expect("queue fairness should resolve stored cell identity");

        assert!(resolver.contains("runtime->cell_external_id"));
        assert!(resolver.contains("runtime->cell_epoch"));
        assert!(resolver.contains("queue_cell_lookup"));
        assert!(resolver.contains("cell->slot_epoch"));
        assert!(resolver.contains("queue_task_cell_index(ctx, p)"));

        let runnable = vtime
            .split_once("queue_fairness_prepare_runnable(")
            .and_then(|(_, body)| body.split_once("queue_fairness_cancel_direct("))
            .map(|(body, _)| body)
            .expect("queue runnable preparation should be bounded");
        assert!(runnable.contains("cell_index = runtime->direct_cell_index"));
        assert!(runnable.contains("runtime->topology_generation !="));
        assert!(runnable.contains("queue_fairness_resolve_runtime_cell("));

        let running = vtime
            .split_once("queue_fairness_running(")
            .and_then(|(_, body)| body.split_once("queue_fairness_stopping("))
            .map(|(body, _)| body)
            .expect("queue running accounting should be bounded");
        assert!(running.contains("runtime->topology_generation !="));
        assert!(running.contains("queue_fairness_resolve_runtime_cell("));
        assert_text_order(
            running,
            &[
                "runtime->topology_generation !=",
                "runtime->direct_cell_valid",
                "queue_task_cell_index(ctx, p) != runtime->cell_index",
            ],
        );
        let direct_fast_path = running
            .split_once("} else if (runtime && runtime->direct_cell_valid) {")
            .and_then(|(_, body)| {
                body.split_once("} else if (runtime && runtime->cell_initialized")
            })
            .map(|(body, _)| body)
            .expect("same-generation direct path should be bounded");
        assert!(direct_fast_path.contains("runtime->direct_cell_index"));
        assert!(!direct_fast_path.contains("queue_fairness_resolve_runtime_cell("));

        let stopping = vtime
            .split_once("queue_fairness_stopping(")
            .map(|(_, body)| body)
            .expect("queue stopping accounting should exist");
        assert!(stopping.contains("runtime->topology_generation !="));
        assert!(!stopping.contains("queue_fairness_resolve_runtime_cell("));
        let stale_attribution = stopping
            .split_once("runtime->topology_generation !=")
            .map(|(_, body)| body)
            .expect("stopping should guard stale per-cell attribution");
        assert_text_order(
            stale_attribution,
            &["return 0", "cell_stat_add(ctx, runtime->run_cell_index"],
        );
    }

    #[test]
    fn managed_cell_reconciliation_activates_resources_before_membership() {
        let source = include_str!("main.rs");
        let reconcile = source
            .split_once("fn reconcile_managed_cells_if_due(")
            .map(|(_, body)| body)
            .expect("scheduler should reconcile managed resources at runtime");
        let stage = reconcile
            .find("activate_compiled_policy(")
            .expect("managed reconciliation should publish a compiled bank");
        let membership = reconcile
            .find("replace_directory")
            .expect("managed reconciliation should update task membership");

        assert!(stage < membership);
        assert!(reconcile.contains("set_queue_draining(&mut self.skel, true)"));
        assert!(reconcile.contains("wait_for_queue_drain(&mut self.skel"));
        assert!(reconcile.contains("wait_for_slot_quiescent(&self.skel, previous_slot"));
        assert!(reconcile.contains("set_queue_draining(&mut self.skel, false)"));
    }

    #[test]
    fn managed_cell_reconciliation_records_topology_lifecycle_stages() {
        let source = include_str!("main.rs");
        let reconcile = source
            .split_once("fn reconcile_managed_cells_if_due(")
            .and_then(|(_, body)| body.split_once("fn run(&mut self, shutdown:"))
            .map(|(body, _)| body)
            .expect("scheduler should reconcile managed resources at runtime");

        assert!(reconcile.contains("topology_transition_changes("));
        assert!(reconcile.contains("record_topology_transition("));
        for stage in [
            "discovery",
            "resolution",
            "drain",
            "publication",
            "quiescence",
            "membership",
        ] {
            assert!(
                reconcile.contains(&format!("complete_stage(\"{stage}\""))
                    || reconcile.contains(&format!("fail_stage(\"{stage}\""))
                    || reconcile.contains(&format!("warn_stage(\"{stage}\"")),
                "managed reconciliation does not record {stage}"
            );
        }
        for outcome in ["Applied", "Deferred", "Rejected"] {
            assert!(
                reconcile.contains(&format!("TopologyTransitionOutcome::{outcome}")),
                "managed reconciliation does not record {outcome} outcomes"
            );
        }
    }

    #[test]
    fn managed_runtime_discovery_errors_preserve_the_active_topology() {
        let source = include_str!("main.rs");
        let discovery_error = source
            .split_once("if let Err(error) = managed_cells::resolve_managed_cells")
            .and_then(|(_, body)| body.split_once("if candidate == self.runtime.compiled"))
            .map(|(body, _)| body)
            .expect("managed discovery error path should be bounded");

        assert!(discovery_error.contains("preserving the active topology and retrying"));
        assert!(discovery_error.contains("return Ok(())"));
        assert!(!discovery_error.contains("return Err(error)"));
    }

    #[test]
    fn managed_demand_rebases_reschedule_and_resize_attempts_throttle() {
        let source = include_str!("main.rs");
        let rebase = source
            .split_once("fn rebase_managed_demand(")
            .and_then(|(_, body)| body.split_once("fn sample_managed_demand_if_due("))
            .map(|(body, _)| body)
            .expect("managed demand rebase should be bounded");
        let sample = source
            .split_once("fn sample_managed_demand_if_due(")
            .and_then(|(_, body)| body.split_once("fn reconcile_managed_cells_if_due("))
            .map(|(body, _)| body)
            .expect("managed demand sampling should be bounded");

        let rebase_step = rebase.find(".step(snapshot)").expect("rebase should step");
        let reschedule = rebase
            .find("self.next_demand_sample = Some(sampled_at + interval)")
            .expect("successful rebase should reschedule sampling");
        assert!(rebase_step < reschedule);

        let attempt = sample
            .find("let applied = self.activate_resized_managed_topology(&weights)?")
            .expect("sampling should attempt a weighted resize");
        let cooldown = sample
            .find("self.next_rebalance_allowed = Some(Instant::now() + cooldown)")
            .expect("every completed resize attempt should arm cooldown");
        let applied = sample
            .find("if applied")
            .expect("applied resizes should update event counters");
        assert!(attempt < cooldown && cooldown < applied);
    }

    #[test]
    fn managed_resize_uses_dispatch_drain_only_when_queue_identity_supports_it() {
        let source = include_str!("main.rs");
        let lifecycle = source
            .split_once("fn reconcile_managed_cells_if_due(")
            .and_then(|(_, body)| body.split_once("fn activate_resized_managed_topology("))
            .map(|(body, _)| body)
            .expect("managed lifecycle activation should be present");
        let resize = source
            .split_once("fn activate_resized_managed_topology(")
            .and_then(|(_, body)| body.split_once("fn run(&mut self, shutdown:"))
            .map(|(body, _)| body)
            .expect("managed resize activation should be present");

        assert!(lifecycle.contains("set_queue_draining(&mut self.skel, true)"));
        assert!(lifecycle.contains("wait_for_queue_drain(&mut self.skel"));
        assert!(lifecycle.contains("same_host_queue_universe"));
        assert!(resize.contains("let mut dispatch_managed ="));
        assert!(resize.contains("policy_dispatches_orphan_queues"));
        assert!(resize.contains("preserves_resize_queue_identity"));
        assert!(resize.contains("same_host_queue_universe"));
        assert!(resize.contains("if !dispatch_managed"));
        assert!(resize.contains("set_queue_draining(&mut self.skel, true)"));
        assert!(resize.contains("wait_for_queue_drain(&mut self.skel"));
        assert!(resize.contains("BpfPolicyBackend"));
        assert!(source.contains("refreshing published queue runtime; rolled back"));
        let retired_quiescence = resize
            .find("wait_for_slot_quiescent(&self.skel, previous_slot")
            .expect("resize should wait for retired callbacks");
        let post_quiescence_refresh = resize[retired_quiescence..]
            .find("refresh_queue_runtime(&mut self.skel)")
            .expect("resize should refresh runtime after retired callbacks quiesce");
        assert!(post_quiescence_refresh > 0);

        let expanded = policy::compile_policy(include_str!("../examples/mitosis-sim.toml"))
            .expect("Mitosis policy should compile");
        assert!(policy_dispatches_orphan_queues(&expanded));

        let legacy = policy::compile_policy(
            r#"
[queues]
layout = "cell_llc"
enqueue = [{ target = "cell" }, { target = "affinity" }]
dispatch = [
  { action = "peek", source = "cell" },
  { action = "peek", source = "cpu" },
  { action = "consume", operation = "min_vtime", fallback = ["cpu", "cell_sibling"] },
]
[[rung]]
operation = "pick_idle"
scope = "task_cell"
"#,
        )
        .expect("legacy Mitosis policy should compile");
        assert!(!policy_dispatches_orphan_queues(&legacy));
    }

    #[test]
    fn topology_transition_attempt_preserves_stage_outcomes() {
        let mut attempt = TopologyTransitionAttempt::new(4, 10, 1_000);
        attempt.complete_stage("discovery", Duration::from_millis(2));
        attempt.warn_stage(
            "membership",
            Duration::from_millis(3),
            "one task disappeared".into(),
        );
        attempt.fail_stage(
            "drain",
            Duration::from_millis(5),
            "queues remained busy".into(),
        );
        let view = attempt.finish(
            inspection::TopologyTransitionOutcome::Deferred,
            None,
            1_012,
            Duration::from_millis(12),
            Some("queues remained busy".into()),
        );

        assert_eq!(view.id, 4);
        assert_eq!(view.from_generation, 10);
        assert_eq!(view.duration_ms, 12);
        assert_eq!(view.stages.len(), 3);
        assert_eq!(
            view.stages[0].status,
            inspection::TopologyTransitionStageStatus::Complete
        );
        assert_eq!(
            view.stages[1].status,
            inspection::TopologyTransitionStageStatus::Warning
        );
        assert_eq!(
            view.stages[2].status,
            inspection::TopologyTransitionStageStatus::Failed
        );
    }

    #[test]
    fn topology_transition_attempt_preserves_every_final_outcome() {
        for (index, outcome, to_generation) in [
            (1, inspection::TopologyTransitionOutcome::Applied, Some(11)),
            (2, inspection::TopologyTransitionOutcome::Deferred, None),
            (3, inspection::TopologyTransitionOutcome::Rejected, None),
        ] {
            let view = TopologyTransitionAttempt::new(index, 10, 1_000).finish(
                outcome,
                to_generation,
                1_005,
                Duration::from_millis(5),
                None,
            );
            assert_eq!(view.outcome, outcome);
            assert_eq!(view.to_generation, to_generation);
        }
    }

    #[test]
    fn managed_membership_identity_races_request_an_immediate_topology_retry() {
        let source = include_str!("main.rs");
        let run_loop = source
            .split_once("fn run(&mut self, shutdown: Arc<AtomicBool>)")
            .and_then(|(_, body)| body.split_once("impl Drop for Scheduler"))
            .map(|(body, _)| body)
            .expect("scheduler should have a run loop");

        assert!(run_loop.contains("let live_managed_cells ="));
        assert!(run_loop.contains("manager.identity_errors_are_fatal() && !live_managed_cells"));
        assert!(run_loop.contains("self.next_managed_reconcile = Some(Instant::now())"));
    }

    #[test]
    fn staged_topology_failures_report_the_exact_prepare_stage() {
        let main = include_str!("bpf/main.bpf.c");
        let init = include_str!("bpf/queue_init.h");
        let rust = include_str!("main.rs");

        assert!(main.contains("staging_ladder_prepare_stage"));
        assert!(main.contains("staging_ladder_prepare_error"));
        assert!(init.contains("queue_topology_prepare_stage"));
        assert!(init.contains("queue_topology_prepare_error"));
        assert!(init.contains("queue_topology_prepare_detail"));
        assert!(rust.contains("ladder stage {ladder_stage}, topology stage {topology_stage}"));
        assert!(rust.contains("topology detail {topology_detail}"));
    }

    #[test]
    fn task_runtime_flat_layout_is_stable() {
        const EXPECTED_DECLARATIONS: &[&str] = &[
            "struct bpf_cpumask __kptr *queue_cpumask",
            "u64 started_exec_runtime",
            "u64 service_budget",
            "u64 vruntime",
            "u64 affinity_vruntime",
            "u64 topology_generation",
            "u64 affinity_topology_generation",
            "u64 deadline",
            "u64 request_remaining_ns",
            "u64 queue_timing_session_id",
            "u64 queue_timing_dsq_id",
            "u64 queue_timing_enqueued_at_ns",
            "s64 sleep_lag",
            "u32 active_weight",
            "u32 pending_weight",
            "u32 cell_index",
            "u32 cell_external_id",
            "u32 cell_epoch",
            "u32 affinity_cell_index",
            "u32 affinity_cell_external_id",
            "u32 affinity_cell_epoch",
            "u32 run_cell_index",
            "u32 run_owner_cell_index",
            "u32 selected_cpu",
            "u32 direct_cell_index",
            "u32 queue_timing_cell_index",
            "u32 queue_timing_depth_after_insert",
            "u32 queue_timing_queue_class",
            "u32 queued_dsq_index",
            "u8 runtime_valid",
            "u8 initialized",
            "u8 runnable_accounted",
            "u8 has_sleep_lag",
            "u8 run_direct",
            "u8 cell_initialized",
            "u8 affinity_initialized",
            "u8 selected_cpu_valid",
            "u8 queue_class",
            "u8 run_queue_class",
            "u8 direct_cell_valid",
            "u8 queued_dsq_class",
            "u8 queued_dsq_accounted",
        ];

        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let combined = bpf_sources(&bpf_dir)
            .into_iter()
            .map(|(_, source)| source)
            .collect::<Vec<_>>()
            .join("\n");
        let body = combined
            .split_once("struct snake_task_runtime {")
            .and_then(|(_, rest)| rest.split_once("};"))
            .map(|(body, _)| body)
            .expect("snake_task_runtime should remain defined in BPF source");
        let declarations = body
            .lines()
            .filter_map(|line| {
                let declaration = line.trim().strip_suffix(';')?;
                Some(declaration.split_whitespace().collect::<Vec<_>>().join(" "))
            })
            .collect::<Vec<_>>();

        assert_eq!(declarations, EXPECTED_DECLARATIONS);

        type TaskRuntime = bpf_skel::types::snake_task_runtime;
        assert_eq!(size_of::<TaskRuntime>(), 184);
        assert_eq!(std::mem::align_of::<TaskRuntime>(), 8);
        assert_eq!(offset_of!(TaskRuntime, queue_cpumask), 0);
        assert_eq!(offset_of!(TaskRuntime, started_exec_runtime), 8);
        assert_eq!(offset_of!(TaskRuntime, service_budget), 16);
        assert_eq!(offset_of!(TaskRuntime, vruntime), 24);
        assert_eq!(offset_of!(TaskRuntime, affinity_vruntime), 32);
        assert_eq!(offset_of!(TaskRuntime, topology_generation), 40);
        assert_eq!(offset_of!(TaskRuntime, affinity_topology_generation), 48);
        assert_eq!(offset_of!(TaskRuntime, deadline), 56);
        assert_eq!(offset_of!(TaskRuntime, request_remaining_ns), 64);
        assert_eq!(offset_of!(TaskRuntime, queue_timing_session_id), 72);
        assert_eq!(offset_of!(TaskRuntime, queue_timing_dsq_id), 80);
        assert_eq!(offset_of!(TaskRuntime, queue_timing_enqueued_at_ns), 88);
        assert_eq!(offset_of!(TaskRuntime, sleep_lag), 96);
        assert_eq!(offset_of!(TaskRuntime, active_weight), 104);
        assert_eq!(offset_of!(TaskRuntime, pending_weight), 108);
        assert_eq!(offset_of!(TaskRuntime, cell_index), 112);
        assert_eq!(offset_of!(TaskRuntime, cell_external_id), 116);
        assert_eq!(offset_of!(TaskRuntime, cell_epoch), 120);
        assert_eq!(offset_of!(TaskRuntime, affinity_cell_index), 124);
        assert_eq!(offset_of!(TaskRuntime, affinity_cell_external_id), 128);
        assert_eq!(offset_of!(TaskRuntime, affinity_cell_epoch), 132);
        assert_eq!(offset_of!(TaskRuntime, run_cell_index), 136);
        assert_eq!(offset_of!(TaskRuntime, run_owner_cell_index), 140);
        assert_eq!(offset_of!(TaskRuntime, selected_cpu), 144);
        assert_eq!(offset_of!(TaskRuntime, direct_cell_index), 148);
        assert_eq!(offset_of!(TaskRuntime, queue_timing_cell_index), 152);
        assert_eq!(
            offset_of!(TaskRuntime, queue_timing_depth_after_insert),
            156
        );
        assert_eq!(offset_of!(TaskRuntime, queue_timing_queue_class), 160);
        assert_eq!(offset_of!(TaskRuntime, queued_dsq_index), 164);
        assert_eq!(offset_of!(TaskRuntime, runtime_valid), 168);
        assert_eq!(offset_of!(TaskRuntime, initialized), 169);
        assert_eq!(offset_of!(TaskRuntime, runnable_accounted), 170);
        assert_eq!(offset_of!(TaskRuntime, has_sleep_lag), 171);
        assert_eq!(offset_of!(TaskRuntime, run_direct), 172);
        assert_eq!(offset_of!(TaskRuntime, cell_initialized), 173);
        assert_eq!(offset_of!(TaskRuntime, affinity_initialized), 174);
        assert_eq!(offset_of!(TaskRuntime, selected_cpu_valid), 175);
        assert_eq!(offset_of!(TaskRuntime, queue_class), 176);
        assert_eq!(offset_of!(TaskRuntime, run_queue_class), 177);
        assert_eq!(offset_of!(TaskRuntime, direct_cell_valid), 178);
        assert_eq!(offset_of!(TaskRuntime, queued_dsq_class), 179);
        assert_eq!(offset_of!(TaskRuntime, queued_dsq_accounted), 180);
    }

    #[test]
    fn bpf_task_storage_access_is_centralized() {
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let sources = bpf_sources(&bpf_dir);
        let owners = sources
            .iter()
            .filter(|(_, source)| source.contains("bpf_task_storage_get("))
            .collect::<Vec<_>>();

        assert_eq!(owners.len(), 1, "task storage must have one raw owner");
        assert_eq!(owners[0].0.file_name().unwrap(), "task_state.h");
        let owner = &owners[0].1;
        assert_eq!(owner.matches("bpf_task_storage_get(").count(), 3);
        assert_eq!(owner.matches("BPF_MAP_TYPE_TASK_STORAGE").count(), 2);
        assert!(owner.contains("BPF_LOCAL_STORAGE_GET_F_CREATE"));
        assert!(owner.contains("} task_runtimes SEC(\".maps\");"));
        assert!(owner.contains("} task_cells SEC(\".maps\");"));
        for wrapper in [
            "task_state_lookup(",
            "task_state_get_or_create(",
            "task_annotation(",
            "task_state_init_queue_mask(",
            "task_route_record_selected_cpu(",
            "task_route_take_selected_cpu(",
            "task_route_clear_selected_cpu(",
        ] {
            assert!(
                owner.contains(wrapper),
                "task state owner is missing {wrapper}"
            );
        }

        for (path, source) in &sources {
            if path.file_name().unwrap() == "task_state.h" {
                continue;
            }
            assert!(
                !source.contains("task_runtimes") && !source.contains("task_cells"),
                "{} bypasses task-state ownership",
                path.display()
            );
            assert!(!source.contains("BPF_MAP_TYPE_TASK_STORAGE"));
            assert!(!source.contains("BPF_LOCAL_STORAGE_GET_F_CREATE"));
        }
    }

    #[test]
    fn vtime_initializes_task_state_before_wakeup_routing() {
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let mode = fs::read_to_string(bpf_dir.join("scheduler_mode.h")).unwrap();
        let state = fs::read_to_string(bpf_dir.join("task_state.h")).unwrap();
        let vtime = fs::read_to_string(bpf_dir.join("fairness_vtime.h")).unwrap();
        let queue_vtime = fs::read_to_string(bpf_dir.join("queue_vtime.h")).unwrap();

        assert!(state.contains("task_state_init(struct task_struct *p)"));
        assert_text_order(
            &mode,
            &[
                "scheduler_mode_init_task(",
                "queue_cell_mode_enabled()",
                "task_state_init_queue_mask(p)",
                "fairness_is_vtime()",
                "task_state_init(p)",
                "return 0;",
            ],
        );
        let prepare = vtime
            .split_once("fairness_vtime_prepare_task(")
            .and_then(|(_, body)| body.split_once("fairness_vtime_prepare_runnable("))
            .map(|(body, _)| body)
            .unwrap();
        assert!(prepare.contains("fairness_task(ctx, p, false)"));
        assert!(!prepare.contains("fairness_task(ctx, p, true)"));
        let queue_prepare = queue_vtime
            .split_once("queue_fairness_prepare_task_for_cell(")
            .and_then(|(_, body)| body.split_once("queue_fairness_prepare_task("))
            .map(|(body, _)| body)
            .unwrap();
        assert!(queue_prepare.contains("fairness_task(ctx, p, false)"));
        assert!(!queue_prepare.contains("fairness_task(ctx, p, true)"));
    }

    #[test]
    fn bpf_queue_state_and_initialization_have_distinct_owners() {
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let state = fs::read_to_string(bpf_dir.join("queue_state.h"))
            .expect("queue maps should have a dedicated owner");
        let init = fs::read_to_string(bpf_dir.join("queue_init.h"))
            .expect("queue initialization should have a dedicated owner");
        let runtime = fs::read_to_string(bpf_dir.join("queue.h")).unwrap();
        let umbrella = fs::read_to_string(bpf_dir.join("main.h")).unwrap();

        assert!(state.contains("#include \"bpf_common.h\""));
        for map in [
            "queue_header",
            "queue_cell_lookup",
            "queue_cells",
            "normal_queues",
            "cpu_queues",
            "queue_cell_masks",
            "queue_cpu_states",
        ] {
            assert!(
                state.contains(&format!("}} {map}")),
                "queue state owner is missing {map}"
            );
            let declaration = format!("}} {map}");
            assert!(!umbrella.contains(&declaration));
            assert!(!runtime.contains(&declaration));
        }
        for accessor in [
            "queue_config(",
            "queue_topology_enabled(",
            "queue_cell(",
            "queue_cpu(",
            "queue_cell_mask(",
        ] {
            assert!(
                state.contains(accessor),
                "queue state is missing {accessor}"
            );
        }
        assert!(runtime.contains("#include \"queue_state.h\""));
        assert!(init.contains("#include \"queue.h\""));
        assert!(init.contains("#include \"dsq.h\""));
        for initializer in [
            "queue_build_cpumask(",
            "queue_init_cell_masks(",
            "validate_queue_topology(",
            "create_queue_topology_dsqs(",
        ] {
            assert!(
                init.contains(initializer),
                "queue init is missing {initializer}"
            );
            assert!(!runtime.contains(initializer));
        }

        let main = fs::read_to_string(bpf_dir.join("main.bpf.c")).unwrap();
        let prepare = main
            .split_once("int prepare_ladder(void *ctx)")
            .unwrap()
            .1
            .split_once("BPF_STRUCT_OPS(snake_select_cpu")
            .unwrap()
            .0;
        assert_text_order(
            prepare,
            &[
                "active_ladder_slot()",
                "validate_compiled_ladder(ladder)",
                "scx_bpf_nr_cpu_ids()",
                "prepare_queue_topology(slot)",
                "queue_topology_enabled() && !fairness_is_vtime()",
                "prepare_mask_tables(slot, ladder)",
            ],
        );
        let attach = main
            .split_once("BPF_STRUCT_OPS_SLEEPABLE(snake_init)")
            .unwrap()
            .1
            .split_once("BPF_STRUCT_OPS(snake_exit")
            .unwrap()
            .0;
        assert_text_order(
            attach,
            &[
                "scx_bpf_nr_cpu_ids()",
                "init_mask_table_scratch()",
                "active_ladder_slot()",
                "validate_queue_topology(active)",
                "queue_topology_enabled() && !fairness_is_vtime()",
                "fairness_init()",
                "create_queue_topology_dsqs(active)",
                "acquire_active_ladder(&ladder_ctx)",
                "validate_compiled_ladder(ladder_ctx.ladder)",
            ],
        );
    }

    #[test]
    fn bpf_mask_runtime_and_initialization_have_distinct_owners() {
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let runtime = fs::read_to_string(bpf_dir.join("mask_table.h")).unwrap();
        let init = fs::read_to_string(bpf_dir.join("mask_table_init.h"))
            .expect("mask-table initialization should have a dedicated owner");
        let main = fs::read_to_string(bpf_dir.join("main.bpf.c")).unwrap();

        assert!(init.contains("#include \"mask_table.h\""));
        assert!(main.contains("#include \"mask_table_init.h\""));
        for initializer in [
            "init_mask_table_scratch(",
            "mask_data_test_cpu(",
            "build_mask_from_data(",
            "prepare_mask_tables(",
        ] {
            assert!(
                init.contains(initializer),
                "mask init is missing {initializer}"
            );
            assert!(!runtime.contains(initializer));
        }
        for runtime_symbol in [
            "mask_data SEC(\".maps\")",
            "mask_slots",
            "mask_scratch SEC(\".maps\")",
            "mask_table_scratch(",
            "mask_table_index(",
            "mask_table_has_key(",
            "mask_table_contains(",
            "mask_table_intersects(",
            "pick_idle_from_mask_table(",
            "pick_random_idle_from_mask_table(",
        ] {
            assert!(
                runtime.contains(runtime_symbol),
                "mask runtime is missing {runtime_symbol}"
            );
        }
    }

    #[test]
    fn bpf_fairness_common_owns_mode_and_task_adapter() {
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let common = fs::read_to_string(bpf_dir.join("fairness_common.h"))
            .expect("fairness mode and task access should have a common owner");
        let fairness = fs::read_to_string(bpf_dir.join("fairness.h")).unwrap();

        assert!(common.contains("#include \"stats.h\""));
        assert!(common.contains("#include \"task_state.h\""));
        for symbol in [
            "fairness_mode = SNAKE_FAIRNESS_FIFO",
            "fairness_is_eevdf(",
            "fairness_is_vtime(",
            "fairness_is_ordered(",
            "fairness_accounting_error(",
            "fairness_task(",
        ] {
            assert!(
                common.contains(symbol),
                "fairness common is missing {symbol}"
            );
        }
        assert!(fairness.contains("#include \"fairness_common.h\""));
        assert!(!fairness.contains("const volatile u32 fairness_mode"));
        assert!(!fairness.contains("fairness_task(struct snake_ladder_ctx"));
    }

    #[test]
    fn fairness_callback_facade_surface_is_stable() {
        const ENTRYPOINTS: &[&str] = &[
            "fairness_init(",
            "fairness_runnable(",
            "fairness_dispatch_slice(",
            "fairness_enqueue(",
            "fairness_dispatch(",
            "fairness_running(",
            "fairness_stopping(",
            "fairness_quiescent(",
            "fairness_set_weight(",
        ];

        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let combined = bpf_sources(&bpf_dir)
            .into_iter()
            .map(|(_, source)| source)
            .collect::<Vec<_>>()
            .join("\n");
        for entrypoint in ENTRYPOINTS {
            assert!(
                combined.contains(entrypoint),
                "fairness callback facade lost `{entrypoint}`"
            );
        }
    }

    #[test]
    fn eevdf_dispatch_has_a_verifier_boundary() {
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let eevdf = fs::read_to_string(bpf_dir.join("fairness_eevdf.h")).unwrap();
        let dsq = fs::read_to_string(bpf_dir.join("dsq.h")).unwrap();

        assert!(eevdf.contains("static __noinline int\nfairness_eevdf_dispatch("));
        assert!(dsq.contains("static __noinline bool\ndsq_move_vtime("));
    }

    #[test]
    fn vtime_keep_running_stays_inline_for_dispatch_stack() {
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let vtime = fs::read_to_string(bpf_dir.join("fairness_vtime.h")).unwrap();

        assert!(vtime.contains("static __always_inline bool\nfairness_vtime_keep_running("));
    }

    #[test]
    fn bpf_fairness_facade_vectors_to_separate_policy_modules() {
        const CALLBACKS: &[&str] = &[
            "runnable",
            "dispatch_slice",
            "enqueue",
            "dispatch",
            "running",
            "stopping",
            "quiescent",
            "set_weight",
            "init",
        ];
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let facade = fs::read_to_string(bpf_dir.join("fairness.h")).unwrap();
        let common = fs::read_to_string(bpf_dir.join("fairness_common.h")).unwrap();

        for policy in ["fifo", "vtime", "eevdf"] {
            let module = fs::read_to_string(bpf_dir.join(format!("fairness_{policy}.h")))
                .unwrap_or_else(|_| panic!("fairness policy module {policy} should exist"));
            assert!(facade.contains(&format!("#include \"fairness_{policy}.h\"")));
            for callback in CALLBACKS {
                let implementation = format!("fairness_{policy}_{callback}(");
                assert!(
                    module.contains(&implementation),
                    "{policy} module is missing {implementation}"
                );
                assert!(
                    facade.contains(&implementation),
                    "facade does not vector to {implementation}"
                );
            }
        }
        assert!(!facade.contains("SEC(\".maps\")"));
        assert!(!facade.contains("bpf_map_lookup_elem"));
        assert!(!facade.contains("bpf_spin_lock"));
        assert!(!facade.contains("bpf_for_each"));
        assert!(!facade.contains("(*"));
        assert_eq!(facade.matches("switch (fairness_mode)").count(), 9);
        for mode in [
            "SNAKE_FAIRNESS_FIFO",
            "SNAKE_FAIRNESS_VTIME",
            "SNAKE_FAIRNESS_EEVDF",
        ] {
            assert_eq!(facade.matches(&format!("case {mode}:")).count(), 9);
        }
        assert!(facade.contains("static __noinline u64 fairness_dispatch_slice("));

        for helper in [
            "fairness_task_weight(",
            "fairness_scale_inverse(",
            "fairness_runtime_begin(",
            "fairness_runtime_delta(",
        ] {
            assert!(
                common.contains(helper),
                "fairness common is missing {helper}"
            );
        }

        let vtime = fs::read_to_string(bpf_dir.join("fairness_vtime.h")).unwrap();
        let eevdf = fs::read_to_string(bpf_dir.join("fairness_eevdf.h")).unwrap();
        assert!(vtime.contains("vtime_domain"));
        assert!(!vtime.contains("cell_vtime_domains"));
        assert!(!vtime.contains("eevdf_domain SEC"));
        assert!(eevdf.contains("eevdf_domain"));
        assert!(!eevdf.contains("cell_vtime_domains"));
        assert_text_order(
            &vtime,
            &[
                "fairness_vtime_init(",
                "queue_topology_enabled()",
                "return 0",
                "dsq_create(dsq_vtime_global()",
            ],
        );
        let queue = fs::read_to_string(bpf_dir.join("queue_vtime.h")).unwrap();
        assert!(queue.contains("#include \"fairness.h\""));

        type VtimeDomain = bpf_skel::types::snake_vtime_domain;
        type EevdfDomain = bpf_skel::types::snake_eevdf_domain;
        assert_eq!(size_of::<VtimeDomain>(), 64);
        assert_eq!(offset_of!(VtimeDomain, lock), 0);
        assert_eq!(offset_of!(VtimeDomain, pad), 4);
        assert_eq!(offset_of!(VtimeDomain, vtime_now), 8);
        assert_eq!(size_of::<EevdfDomain>(), 24);
        assert_eq!(offset_of!(EevdfDomain, lock), 0);
        assert_eq!(offset_of!(EevdfDomain, pad), 4);
        assert_eq!(offset_of!(EevdfDomain, virtual_time), 8);
        assert_eq!(offset_of!(EevdfDomain, runnable_weight), 16);
    }

    #[test]
    fn bpf_queue_pipeline_has_explicit_owners_and_stable_facades() {
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let vtime = fs::read_to_string(bpf_dir.join("queue_vtime.h"))
            .expect("queue VTIME state should have a dedicated owner");
        let enqueue = fs::read_to_string(bpf_dir.join("queue_enqueue.h"))
            .expect("queue enqueue path should have a dedicated owner");
        let dispatch = fs::read_to_string(bpf_dir.join("queue_dispatch.h"))
            .expect("queue dispatch path should have a dedicated owner");
        let fairness = fs::read_to_string(bpf_dir.join("queue_fairness.h")).unwrap();
        let ladder = fs::read_to_string(bpf_dir.join("queue_ladder.h")).unwrap();

        for include in ["queue_vtime.h", "queue_enqueue.h", "queue_dispatch.h"] {
            assert!(fairness.contains(&format!("#include \"{include}\"")));
        }
        assert!(ladder.contains("#include \"queue_enqueue.h\""));
        assert!(ladder.contains("#include \"queue_dispatch.h\""));
        for implementation in [&vtime, &enqueue, &dispatch] {
            assert!(!implementation.contains("#include \"queue_fairness.h\""));
            assert!(!implementation.contains("#include \"queue_ladder.h\""));
        }

        for symbol in [
            "cell_vtime_domains",
            "queue_fairness_prepare_task_for_cell(",
            "queue_fairness_prepare_runnable(",
            "queue_fairness_prepare_affinity(",
            "queue_fairness_cancel_direct(",
            "queue_fairness_replenish(",
            "queue_fairness_running(",
            "queue_fairness_stopping(",
        ] {
            assert!(
                vtime.contains(symbol),
                "queue VTIME owner is missing {symbol}"
            );
        }
        for symbol in [
            "queue_fairness_direct_borrow(",
            "queue_fairness_enqueue_cell(",
            "queue_fairness_enqueue_affinity(",
            "queue_ladder_enqueue(",
        ] {
            assert!(
                enqueue.contains(symbol),
                "queue enqueue owner is missing {symbol}"
            );
        }
        for symbol in [
            "struct snake_queue_candidate",
            "queue_fairness_normal_candidate(",
            "queue_fairness_affinity_candidate(",
            "queue_fairness_dispatch_min(",
            "queue_fairness_dispatch_source(",
            "queue_ladder_dispatch(",
        ] {
            assert!(
                dispatch.contains(symbol),
                "queue dispatch owner is missing {symbol}"
            );
        }

        assert!(fairness.contains("static __always_inline s32\nqueue_pick_random_idle_cpu("));
        assert!(vtime.contains("static __noinline void queue_clear_rehome_if_cell("));
        assert!(vtime.contains("static __noinline void\nqueue_fairness_cancel_direct("));
        assert!(ladder.contains("validate_queue_ladders("));
        assert!(enqueue.contains("static __always_inline int\nqueue_ladder_enqueue("));
        assert!(dispatch.contains("static __always_inline int queue_ladder_dispatch("));

        let queue_api = [
            fairness.as_str(),
            vtime.as_str(),
            enqueue.as_str(),
            dispatch.as_str(),
        ]
        .join("\n");
        for entrypoint in [
            "queue_pick_task_cell_cpu(",
            "queue_fairness_select_cpu(",
            "queue_fairness_direct_borrow(",
            "queue_fairness_prepare_runnable(",
            "queue_fairness_cancel_direct(",
            "queue_fairness_running(",
            "queue_fairness_stopping(",
        ] {
            assert!(
                queue_api.contains(entrypoint),
                "queue API lost {entrypoint}"
            );
        }
        let ladder_api = [ladder.as_str(), enqueue.as_str(), dispatch.as_str()].join("\n");
        for entrypoint in [
            "validate_queue_ladders(",
            "queue_ladder_enqueue(",
            "queue_ladder_dispatch(",
        ] {
            assert!(
                ladder_api.contains(entrypoint),
                "queue ladder lost {entrypoint}"
            );
        }

        let sources = bpf_sources(&bpf_dir);
        let cell_map_owners = sources
            .iter()
            .filter(|(_, source)| source.contains("} cell_vtime_domains"))
            .collect::<Vec<_>>();
        assert_eq!(cell_map_owners.len(), 1);
        assert_eq!(cell_map_owners[0].0.file_name().unwrap(), "queue_vtime.h");
    }

    #[test]
    fn cell_vtime_clock_access_is_centralized_timed_and_lockless() {
        let vtime = include_str!("bpf/queue_vtime.h");
        let clock_wrappers = vtime
            .split_once("static __always_inline u64\nqueue_domain_now(")
            .and_then(|(_, body)| {
                body.split_once("static __always_inline u64 queue_translate_vruntime(")
            })
            .map(|(body, _)| body)
            .expect("cell clock wrappers should be contiguous");
        let normalized_clock_wrappers = clock_wrappers
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let running = vtime
            .split_once("static __always_inline int queue_fairness_running(")
            .and_then(|(_, body)| {
                body.split_once("static __always_inline int queue_fairness_stopping(")
            })
            .map(|(body, _)| body)
            .expect("queue running callback should have one definition");

        for wrapper in [
            "queue_domain_now(",
            "queue_domain_run_start(",
            "queue_domain_advance(",
        ] {
            assert!(
                vtime.contains(wrapper),
                "missing cell clock wrapper {wrapper}"
            );
        }
        for stage in [
            "SNAKE_FINE_TIMING_ENQUEUE_CELL_CLOCK_READ",
            "SNAKE_FINE_TIMING_SELECT_CELL_CLOCK_READ",
            "SNAKE_FINE_TIMING_RUNNABLE_CELL_CLOCK_READ",
            "SNAKE_FINE_TIMING_RUNNING_CELL_CLOCK_READ",
            "SNAKE_FINE_TIMING_RUNNING_CELL_CLOCK_RUN_START",
            "SNAKE_FINE_TIMING_RUNNING_AFFINITY_CLOCK_ADVANCE",
        ] {
            assert!(
                vtime.contains(stage),
                "cell clock wrapper is missing {stage}"
            );
        }
        assert!(running.contains("queue_domain_run_start("));
        assert!(running.contains("queue_domain_advance("));
        assert!(!running.contains("domain->vtime_now"));
        assert!(!running.contains("bpf_spin_lock"));

        assert!(clock_wrappers.contains("READ_ONCE(domain->vtime_now)"));
        assert!(clock_wrappers.contains("bpf_for(attempt, 0, SNAKE_VTIME_CAS_RETRIES)"));
        assert!(clock_wrappers.contains("__sync_val_compare_and_swap"));
        assert!(normalized_clock_wrappers.contains("observed = previous"));
        assert!(normalized_clock_wrappers.contains("desired = observed"));
        assert!(clock_wrappers.contains("fairness_vtime_run_start(vruntime, observed)"));
        assert!(clock_wrappers.contains("SNAKE_STAT_VTIME_CLOCK_CAS_RETRIES"));
        assert!(clock_wrappers.contains("SNAKE_STAT_VTIME_CLOCK_CAS_EXHAUSTIONS"));
        assert!(normalized_clock_wrappers.contains("ret = -EAGAIN"));
        assert!(running.contains("if (ret)"));
        assert!(!clock_wrappers.contains("bpf_spin_lock"));
    }

    #[test]
    fn mitosis_callback_ladders_preserve_the_kernel_control_flow() {
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let queue = fs::read_to_string(bpf_dir.join("queue.h")).unwrap();
        let enqueue = fs::read_to_string(bpf_dir.join("queue_enqueue.h")).unwrap();
        let dispatch = fs::read_to_string(bpf_dir.join("queue_dispatch.h")).unwrap();
        let ladder = fs::read_to_string(bpf_dir.join("queue_ladder.h")).unwrap();
        let scheduler = fs::read_to_string(bpf_dir.join("scheduler_mode.h")).unwrap();

        let restricted = queue
            .split_once("queue_task_cell_affinity_restricted(")
            .and_then(|(_, body)| body.split_once("queue_pick_primary_cpu("))
            .map(|(body, _)| body)
            .expect("cell affinity classifier should be shared by enqueue and placement");
        assert!(restricted.contains("SNAKE_QUEUE_MASK_PRIMARY"));
        assert!(restricted.contains("SNAKE_QUEUE_MASK_BORROWABLE"));
        assert_eq!(restricted.matches("bpf_cpumask_subset(").count(), 2);

        assert!(scheduler.contains("SNAKE_ENQUEUE_OP_TRY_DIRECT"));
        assert!(scheduler.contains("SNAKE_SELECT_F_AFFINITY"));
        assert!(enqueue.contains("queue_fairness_enqueue_cell("));
        assert!(enqueue.contains("queue_task_cell_affinity_restricted("));
        assert!(enqueue.contains("bpf_cpumask_any_distribute(p->cpus_ptr)"));
        assert!(enqueue.contains("dsq_nr_queued(dsq_affinity(target_cpu))"));
        assert!(enqueue.contains("SNAKE_ENQUEUE_OP_INSERT_CPU"));

        assert!(dispatch.contains("queue_mitosis_ladder_dispatch("));
        assert!(dispatch.contains("queue_mitosis_steal_sibling("));
        assert!(dispatch.contains("queue_dispatch_peek_local("));
        assert!(dispatch.contains("queue_dispatch_peek_cpu("));
        assert!(dispatch.contains("!time_before(cpu_candidate.vtime, cell_candidate.vtime)"));
        let arbitration = dispatch
            .split_once("queue_mitosis_ladder_dispatch(")
            .and_then(|(_, body)| body.split_once("struct snake_queue_dispatch_loop_ctx"))
            .map(|(body, _)| body)
            .expect("Mitosis dispatch should have a dedicated bounded path");
        let empty = arbitration
            .find("!cell_candidate.valid && !cpu_candidate.valid")
            .expect("sibling stealing should be guarded by two empty local candidates");
        let steal = arbitration
            .find("queue_mitosis_steal_sibling(")
            .expect("empty local candidates should trigger sibling stealing");
        assert!(empty < steal);
        assert!(arbitration.contains("if (winner == &cell_candidate && cpu_candidate.valid)"));
        assert!(arbitration.contains("queue_fairness_move(ctx, cpu_candidate.dsq"));

        assert!(ladder.contains("SNAKE_ENQUEUE_OP_TRY_DIRECT"));
        assert!(ladder.contains("SNAKE_ENQUEUE_OP_INSERT_CPU"));
        assert!(ladder.contains("SNAKE_DISPATCH_FALLBACK_CELL_SIBLING"));
    }

    #[test]
    fn expanded_mitosis_dispatch_orders_drain_arbitration_and_steal() {
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let dispatch = fs::read_to_string(bpf_dir.join("queue_dispatch.h")).unwrap();
        let ladder = fs::read_to_string(bpf_dir.join("queue_ladder.h")).unwrap();

        assert!(ladder.contains("ladder->nr_dispatch_rungs != 5"));
        assert!(ladder.contains("SNAKE_DISPATCH_OP_DRAIN"));
        assert!(ladder.contains("SNAKE_DISPATCH_OP_STEAL"));
        assert!(ladder.contains("queue_mitosis_expanded_dispatch_ladder("));
        assert!(ladder.contains("return enqueue_cell ? 0 : -EINVAL;"));

        let expanded = dispatch
            .split_once("queue_mitosis_expanded_dispatch(")
            .and_then(|(_, body)| body.split_once("struct snake_remote_scan_loop_ctx"))
            .map(|(body, _)| body)
            .expect("expanded Mitosis dispatch should have a dedicated bounded path");
        assert_text_order(
            expanded,
            &[
                "queue_mitosis_drain_orphan(",
                "queue_dispatch_peek_local(",
                "queue_dispatch_peek_cpu(",
            ],
        );
        let empty = expanded
            .find("!cell_candidate.valid && !cpu_candidate.valid")
            .expect("stealing should require two empty local candidates");
        let steal = expanded
            .find("queue_mitosis_steal_sibling(")
            .expect("empty local candidates should trigger sibling stealing");
        assert!(empty < steal);
        assert!(expanded.contains("queue_fairness_move("));
        assert!(expanded.contains("if (winner == &cell_candidate && cpu_candidate.valid)"));
    }

    #[test]
    fn orphan_drain_uses_unbanked_pending_state_and_enqueue_interlock() {
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let state = fs::read_to_string(bpf_dir.join("queue_state.h")).unwrap();
        let enqueue = fs::read_to_string(bpf_dir.join("queue_enqueue.h")).unwrap();
        let dispatch = fs::read_to_string(bpf_dir.join("queue_dispatch.h")).unwrap();
        let main = fs::read_to_string(bpf_dir.join("main.bpf.c")).unwrap();

        assert!(state.contains("struct snake_normal_queue_runtime"));
        assert!(state.contains("struct snake_cell_queue_runtime"));
        assert!(state.contains("} normal_queue_runtime SEC(\".maps\")"));
        assert!(state.contains("} cell_queue_runtime SEC(\".maps\")"));
        assert!(state.contains("sizeof(struct snake_normal_queue_runtime) == 64"));
        assert!(state.contains("sizeof(struct snake_cell_queue_runtime) == 64"));
        assert!(state.contains("__sync_fetch_and_add(&runtime->nr_queued, 1)"));
        assert!(state.contains("READ_ONCE(runtime->has_consumers)"));
        assert!(enqueue.contains("queue_custom_account_enqueue("));
        assert!(state.contains("queue_normal_account_dequeue("));
        assert!(dispatch.contains("READ_ONCE(cell_runtime->llcs_to_drain)"));
        let move_helper = dispatch
            .split_once("queue_fairness_move(")
            .and_then(|(_, body)| body.split_once("struct snake_queue_candidate"))
            .map(|(body, _)| body)
            .unwrap();
        assert!(!move_helper.contains("queue_normal_account_dequeue("));
        assert!(!move_helper.contains("scx_bpf_error("));
        assert!(main.contains("SEC(\"syscall\")\nint queue_refresh_runtime"));

        let drain = dispatch
            .split_once("queue_mitosis_drain_orphan(")
            .and_then(|(_, body)| body.split_once("queue_mitosis_expanded_dispatch("))
            .map(|(body, _)| body)
            .unwrap();
        assert_text_order(
            drain,
            &[
                "queue_cell_runtime(cpuq->owner_cell_index)",
                "READ_ONCE(cell_runtime->llcs_to_drain)",
                "if (!drain_mask)",
            ],
        );
        assert!(drain.contains("(local_offset + offset) % cell->nr_normal_queues"));
        assert!(drain.contains("cell->nr_normal_queues > SNAKE_MAX_CELL_LLCS"));
        let regained_consumers = drain
            .split_once("if (READ_ONCE(runtime->has_consumers))")
            .and_then(|(_, body)| body.split_once("pending ="))
            .map(|(body, _)| body)
            .unwrap();
        assert!(regained_consumers.contains("queue_normal_drain_disable"));
        let regained_recheck = drain
            .split_once("if (READ_ONCE(runtime->has_consumers))")
            .and_then(|(_, body)| body.split_once("continue;"))
            .map(|(body, _)| body)
            .unwrap();
        assert!(regained_recheck.contains("!READ_ONCE(runtime->has_consumers)"));
        assert!(regained_recheck.contains("queue_normal_drain_enable"));
        let stale_bank = drain
            .split_once("READ_ONCE(runtime->cell_index) != cpuq->owner_cell_index")
            .and_then(|(_, body)| body.split_once("READ_ONCE(runtime->has_consumers)"))
            .map(|(body, _)| body)
            .unwrap();
        assert!(stale_bank.contains("continue"));
        assert!(!stale_bank.contains("return -EINVAL"));

        let steal = dispatch
            .split_once("queue_mitosis_steal_sibling(")
            .and_then(|(_, body)| body.split_once("queue_mitosis_ladder_dispatch("))
            .map(|(body, _)| body)
            .unwrap();
        assert!(!steal.contains("READ_ONCE(runtime->draining)"));
    }

    #[test]
    fn orphan_drain_kicks_an_idle_cpu_from_the_current_cell() {
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let intf = fs::read_to_string(bpf_dir.join("intf.h")).unwrap();
        let state = fs::read_to_string(bpf_dir.join("queue_state.h")).unwrap();
        let dispatch = fs::read_to_string(bpf_dir.join("queue_dispatch.h")).unwrap();
        let main = fs::read_to_string(bpf_dir.join("main.bpf.c")).unwrap();

        let helper = state
            .split_once("queue_kick_idle_cell_cpu(")
            .and_then(|(_, body)| body.split_once("\n}"))
            .map(|(body, _)| body)
            .expect("orphan draining should have a bounded cell idle-kick helper");
        let helper = helper.split_whitespace().collect::<Vec<_>>().join(" ");
        assert_text_order(
            &helper,
            &[
                "queue_cell_mask_slot(slot, cell_index, SNAKE_QUEUE_MASK_PRIMARY)",
                "scx_bpf_pick_idle_cpu(primary, SCX_PICK_IDLE_CORE)",
                "if (cpu < 0)",
                "scx_bpf_pick_idle_cpu(primary, 0)",
                "scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE)",
            ],
        );
        assert!(!helper.contains("SNAKE_QUEUE_MASK_BORROWABLE"));

        let normalized_state = state.split_whitespace().collect::<Vec<_>>().join(" ");
        let normalized_main = main.split_whitespace().collect::<Vec<_>>().join(" ");
        let normalized_dispatch = dispatch.split_whitespace().collect::<Vec<_>>().join(" ");
        let drain = dispatch
            .split_once("queue_mitosis_drain_orphan(")
            .and_then(|(_, body)| body.split_once("queue_mitosis_expanded_dispatch("))
            .map(|(body, _)| body)
            .unwrap();
        assert!(normalized_state.contains("queue_kick_idle_cell_cpu(ctx->slot, cell_index)"));
        assert!(normalized_main.contains("queue_kick_idle_cell_cpu(active, queue->cell_index)"));
        let refresh_consumers = main
            .split_once("if (has_consumers) {")
            .and_then(|(_, body)| body.split_once("} else if"))
            .map(|(body, _)| body)
            .expect("consumer refresh should have a bounded branch");
        assert!(refresh_consumers.contains("READ_ONCE(runtime->nr_queued)"));
        assert!(refresh_consumers.contains("queue_kick_idle_cell_cpu("));
        assert!(normalized_dispatch
            .contains("queue_kick_idle_cell_cpu(ctx->slot, cpuq->owner_cell_index)"));
        assert_eq!(drain.matches("queue_kick_idle_cell_cpu(").count(), 3);

        let queue_cell = intf
            .split_once("struct snake_queue_cell {")
            .and_then(|(_, body)| body.split_once("};"))
            .map(|(body, _)| body)
            .unwrap();
        assert!(!queue_cell.contains("drain_cpu"));
        assert!(!state.contains("READ_ONCE(runtime->drain_cpu)"));
    }

    #[test]
    fn custom_queue_depth_follows_dequeue_custody() {
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let task_state = fs::read_to_string(bpf_dir.join("task_state.h")).unwrap();
        let state = fs::read_to_string(bpf_dir.join("queue_state.h")).unwrap();
        let enqueue = fs::read_to_string(bpf_dir.join("queue_enqueue.h")).unwrap();
        let dispatch = fs::read_to_string(bpf_dir.join("queue_dispatch.h")).unwrap();
        let main = fs::read_to_string(bpf_dir.join("main.bpf.c")).unwrap();

        for marker in [
            "queued_dsq_index",
            "queued_dsq_class",
            "queued_dsq_accounted",
        ] {
            assert!(
                task_state.contains(marker),
                "missing task custody marker {marker}"
            );
        }
        assert!(state.contains("struct snake_affinity_queue_runtime"));
        assert!(state.contains("} affinity_queue_runtime SEC(\".maps\")"));
        assert!(state.contains("queue_custom_account_enqueue("));
        assert!(state.contains("queue_custom_account_dequeue("));
        assert!(enqueue.matches("queue_custom_account_enqueue(").count() >= 2);

        let move_helper = dispatch
            .split_once("queue_fairness_move(")
            .and_then(|(_, body)| body.split_once("struct snake_queue_candidate"))
            .map(|(body, _)| body)
            .unwrap();
        assert!(!move_helper.contains("queue_normal_account_dispatch("));
        assert!(main.contains("BPF_STRUCT_OPS(snake_dequeue"));
        assert!(main.contains("queue_custom_account_dequeue("));
        assert!(main.contains(".dequeue = (void *)snake_dequeue"));
        assert!(main.contains("READ_ONCE(affinity_runtime->nr_queued)"));
    }

    #[test]
    fn global_sharded_queue_contract_is_topology_blind() {
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let intf = fs::read_to_string(bpf_dir.join("intf.h")).unwrap();
        let state = fs::read_to_string(bpf_dir.join("queue_state.h")).unwrap();
        let enqueue = fs::read_to_string(bpf_dir.join("queue_enqueue.h")).unwrap();
        let dispatch = fs::read_to_string(bpf_dir.join("queue_dispatch.h")).unwrap();
        let userspace =
            fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/main.rs"))
                .unwrap();

        for field in ["u32 input;", "u32 reserved;", "u64 data;"] {
            let queue_rung = intf
                .split_once("struct snake_queue_rung {")
                .unwrap()
                .1
                .split_once("};")
                .unwrap()
                .0;
            assert!(queue_rung.contains(field), "queue rung is missing {field}");
        }
        assert!(intf.contains("SNAKE_QUEUE_MODE_GLOBAL"));
        assert!(state.contains("const volatile u32 queue_mode = SNAKE_QUEUE_MODE_NONE;"));
        assert!(state.contains("return queue_mode != SNAKE_QUEUE_MODE_NONE;"));
        assert!(state.contains("return queue_mode == SNAKE_QUEUE_MODE_GLOBAL;"));
        assert!(state.contains("return queue_mode == SNAKE_QUEUE_MODE_CELL;"));
        assert!(userspace.contains("rodata.queue_mode = queue_mode_for_topology(queue_topology);"));
        assert_text_order(
            &userspace,
            &[
                "rodata.queue_mode = queue_mode_for_topology(queue_topology);",
                "scx_ops_load!(skel, snake_ops, uei)",
                "install_queue_topology(&mut skel, queue_topology)",
            ],
        );
        assert!(state.contains("next_remote_queue"));
        assert!(dispatch.contains("state->next_remote_queue  = cpuq->normal_queue_index + 1;"));
        assert!(enqueue.contains("queue_global_enqueue_local("));
        assert!(enqueue.contains("queue_global_enqueue_cpu("));
        assert!(dispatch.contains("queue_dispatch_peek_cpu("));
        assert!(dispatch.contains("queue_dispatch_peek_local("));
        assert!(dispatch.contains("queue_dispatch_peek_remote("));
        assert!(dispatch.contains("queue_dispatch_consume_min_vtime("));
        assert!(dispatch.contains("static __always_inline bool\nqueue_global_move("));
        let global_move = dispatch
            .split_once("queue_global_move(")
            .unwrap()
            .1
            .split_once("queue_global_replenish(")
            .unwrap()
            .0;
        assert!(global_move.contains("dsq_move_to_local_untimed(source)"));
        assert!(!global_move.contains("scx_bpf_dsq_move_to_local"));
        assert!(!global_move.contains("dsq_move_to_local(source, cpu, fine)"));
        assert!(!dispatch.contains("queue_global_dispatch_callback("));
        assert!(dispatch.contains("queue_global_dispatch_peek_rung(ctx, &loop_ctx, 0)"));
        assert!(dispatch.contains("queue_global_dispatch_peek_rung(ctx, &loop_ctx, 1)"));
        assert!(dispatch.contains("queue_global_dispatch_peek_rung(ctx, &loop_ctx, 2)"));
        assert!(dispatch.contains("queue_global_dispatch_consume_rung(ctx, &loop_ctx, 3)"));
        assert!(dispatch.contains("static __noinline s32 queue_global_dispatch_consume_rung("));
        assert!(dispatch.contains("static __noinline int queue_global_ladder_dispatch("));
        let candidate = dispatch
            .split_once("struct snake_queue_candidate {")
            .unwrap()
            .1
            .split_once("};")
            .unwrap()
            .0;
        assert!(!candidate.contains("source"));
        assert!(!candidate.contains("rung"));
        assert!(dispatch.contains(".rung = 0"));
        assert!(dispatch.contains(".rung = 1"));
        assert!(dispatch.contains(".rung = 2"));
        let global_context = dispatch
            .split_once("struct snake_global_dispatch_loop_ctx {")
            .unwrap()
            .1
            .split_once("};")
            .unwrap()
            .0;
        assert!(!global_context.contains("snake_ladder_ctx"));
        assert!(dispatch.contains(".callback_started_at = callback_started_at"));
        let global_peek = dispatch
            .split_once("queue_global_dispatch_peek_rung(")
            .unwrap()
            .1
            .split_once("queue_global_dispatch_consume_rung(")
            .unwrap()
            .0;
        assert!(global_peek.contains("if (index == 0)"));
        assert!(global_peek.contains("else if (index == 1)"));
        assert!(!global_peek.contains("else if (rung->input =="));
        let remote_peek = dispatch
            .split_once("queue_dispatch_peek_remote(")
            .unwrap()
            .1
            .split_once("queue_global_move(")
            .unwrap()
            .0;
        assert!(dispatch.contains("queue_dispatch_remote_scan_callback("));
        assert!(remote_peek.contains("bpf_loop(SNAKE_MAX_NORMAL_QUEUES,"));
        assert!(!remote_peek.contains("bpf_for(offset, 0, SNAKE_MAX_NORMAL_QUEUES)"));
        let remote_scan = dispatch
            .split_once("queue_dispatch_remote_scan_callback(")
            .unwrap()
            .1
            .split_once("queue_dispatch_peek_remote(")
            .unwrap()
            .0;
        assert!(remote_scan.contains("nr_queues > SNAKE_MAX_NORMAL_QUEUES"));
        assert!(remote_scan.contains("dsq_id_t dsq"));
        assert!(remote_scan.contains("index = (start + offset) % nr_queues"));
        assert!(remote_scan.contains("if (index >= SNAKE_MAX_NORMAL_QUEUES)"));
        assert!(!remote_scan.contains("index -= nr_queues"));
        assert!(!remote_scan.contains("return loop_ctx->candidate.valid ? 1 : 0"));
        assert!(dispatch.contains("bpf_cpumask_test_cpu"));
        assert!(dispatch.contains("bpf_rcu_read_lock"));
        assert!(dispatch.contains("bpf_task_from_pid"));
        assert!(dispatch.contains("bpf_task_release"));
        assert!(dispatch.contains("bpf_rcu_read_unlock"));
        assert!(dispatch.contains("SNAKE_DISPATCH_FALLBACK_CPU"));
        assert!(dispatch.contains("SNAKE_DISPATCH_FALLBACK_LOCAL"));
        assert!(dispatch.contains("SNAKE_DISPATCH_FALLBACK_REMOTE"));
        assert!(
            !dispatch.contains("candidate->dsq.raw == winner->dsq.raw"),
            "bounded fallback must retry a raced winner DSQ"
        );
        let consume = dispatch
            .split_once("queue_dispatch_consume_min_vtime(")
            .unwrap()
            .1
            .split_once("struct snake_global_dispatch_loop_ctx")
            .unwrap()
            .0;
        assert!(
            consume.contains("SNAKE_STAT_VTIME_EQUAL_HEAD_TIES"),
            "global min-VTIME arbitration must account exact head ties"
        );
        assert!(
            !consume.contains("bpf_for(offset, 0, 3)"),
            "fixed three-source arbitration must not use verifier iterators"
        );
        for source in ["cpu", "local", "remote"] {
            assert!(consume.contains(&format!("bool {source}_valid")));
            assert_eq!(
                consume
                    .matches(&format!("args->{source}_candidate->valid"))
                    .count(),
                1,
                "consume must normalize {source} candidate validity once"
            );
        }
        for helper in [
            "queue_dispatch_try_selected(",
            "queue_dispatch_try_fallbacks(",
            "queue_dispatch_fallback_callback(",
            "queue_dispatch_try_cpu_fallback(",
            "queue_dispatch_try_local_fallback(",
            "queue_dispatch_try_remote_fallback(",
        ] {
            assert!(dispatch.contains(helper), "missing {helper}");
        }
        assert!(
            !consume.contains("bpf_for(offset, 0, SNAKE_DISPATCH_FALLBACK_MAX)"),
            "the fixed three-source fallback must not multiply verifier iterator states"
        );
        assert!(dispatch.contains("bpf_loop(SNAKE_DISPATCH_FALLBACK_MAX,"));
        assert!(!dispatch.contains("queue_dispatch_selected_callback("));
        assert!(!dispatch.contains("bpf_loop(1, queue_dispatch_selected_callback,"));
        assert_eq!(
            dispatch.matches("queue_global_move(").count(),
            5,
            "selected dispatch and each fallback leaf must have one move path"
        );
        assert_eq!(dispatch.matches("candidate->rung >= 3").count(), 3);
        assert!(!dispatch.contains("queue_dispatch_callback_fine("));
        let move_callbacks = dispatch
            .split_once("static __noinline s32 queue_dispatch_try_selected")
            .unwrap()
            .1
            .split_once("static __noinline s32 queue_dispatch_consume_min_vtime")
            .unwrap()
            .0;
        assert!(!move_callbacks.contains("snake_fine_timing_ctx"));
        let selected = dispatch
            .split_once("static __noinline s32 queue_dispatch_try_selected(")
            .unwrap()
            .1
            .split_once("struct snake_global_fallback_candidate")
            .unwrap()
            .0;
        assert!(selected.contains("u32 class, rung;"));
        assert!(!selected.contains("candidate->rung"));
        let fallback_ctx = dispatch
            .split_once("struct snake_global_fallback_loop_ctx {")
            .unwrap()
            .1
            .split_once("};")
            .unwrap()
            .0;
        assert!(dispatch.contains("struct snake_global_fallback_candidate {"));
        assert!(!fallback_ctx.contains("struct snake_queue_candidate"));
        assert!(!dispatch.contains("candidate->class, loop_ctx->cpu, &loop_ctx->fine"));
        assert!(
            dispatch.matches("cpu >= SNAKE_MAX_CPUS").count() >= 7,
            "every callback boundary that consumes a CPU must restore the DSQ encoding bound"
        );
        for obsolete in [
            "queue_dispatch_try_fallback_slot0(",
            "queue_dispatch_try_fallback_slot1(",
            "queue_dispatch_try_fallback_slot2(",
        ] {
            assert!(
                !dispatch.contains(obsolete),
                "typed move fanout must not reappear through {obsolete}"
            );
        }

        let normal_queue = intf
            .split_once("struct snake_normal_queue {")
            .unwrap()
            .1
            .split_once("};")
            .unwrap()
            .0;
        assert!(normal_queue.contains("struct snake_mask_data consumers;"));
        assert!(!normal_queue.contains("llc_id"));
    }

    #[test]
    fn global_remote_scan_keeps_one_verifier_safe_candidate_state() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let dispatch = fs::read_to_string(root.join("src/bpf/queue_dispatch.h")).unwrap();
        let dsq = fs::read_to_string(root.join("src/bpf/dsq.h")).unwrap();
        let compat = fs::read_to_string(root.join("../../include/scx/compat.bpf.h")).unwrap();
        let remote_scan = dispatch
            .split_once("queue_dispatch_remote_scan_callback(")
            .unwrap()
            .1
            .split_once("queue_dispatch_peek_remote(")
            .unwrap()
            .0;

        assert_text_order(
            remote_scan,
            &[
                "dsq_nr_queued(dsq)",
                "if (!nr_queued)",
                "dsq_peek_vtime(dsq, &loop_ctx->candidate.vtime)",
                "bpf_task_from_pid(p->pid)",
            ],
        );
        assert_eq!(remote_scan.matches("dsq_peek_vtime(").count(), 1);
        assert!(!remote_scan.contains("dsq_vtime_head("));
        assert!(!remote_scan.contains("fast_move"));
        assert!(!dispatch.contains("SNAKE_QUEUE_CANDIDATE_MOVED"));
        assert!(dsq.contains("dsq_peek_vtime("));

        assert!(compat.contains("LINUX_KERNEL_VERSION >= KERNEL_VERSION(7, 1, 0)"));
        assert!(compat.contains("bpf_iter_scx_dsq_new(&it, dsq_id, 0)"));
        assert!(compat.contains("bpf_iter_scx_dsq_next(&it)"));
        assert!(compat.contains("bpf_iter_scx_dsq_destroy(&it)"));
    }

    #[test]
    fn queue_rungs_have_independent_outcome_and_move_miss_counter_ranges() {
        let intf =
            fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf/intf.h"))
                .unwrap();

        for counter in [
            "SNAKE_STAT_DISPATCH_CALLS",
            "SNAKE_STAT_ENQUEUE_RUNG_ATTEMPT_BASE",
            "SNAKE_STAT_ENQUEUE_RUNG_HIT_BASE",
            "SNAKE_STAT_ENQUEUE_RUNG_MISS_BASE",
            "SNAKE_STAT_ENQUEUE_RUNG_ERROR_BASE",
            "SNAKE_STAT_DISPATCH_RUNG_ATTEMPT_BASE",
            "SNAKE_STAT_DISPATCH_RUNG_HIT_BASE",
            "SNAKE_STAT_DISPATCH_RUNG_MISS_BASE",
            "SNAKE_STAT_DISPATCH_RUNG_ERROR_BASE",
            "SNAKE_STAT_DISPATCH_RUNG_SELECTED_BASE",
            "SNAKE_STAT_DISPATCH_RUNG_MOVE_MISS_BASE",
            "SNAKE_STAT_DISPATCH_RUNG_FALLBACK_ATTEMPT_BASE",
            "SNAKE_STAT_DISPATCH_RUNG_FALLBACK_HIT_BASE",
            "SNAKE_STAT_DISPATCH_RUNG_FALLBACK_MISS_BASE",
        ] {
            assert!(
                intf.contains(counter),
                "missing queue rung counter {counter}"
            );
        }
    }

    #[test]
    fn bpf_scheduler_mode_facade_routes_callback_families() {
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let mode = fs::read_to_string(bpf_dir.join("scheduler_mode.h"))
            .expect("scheduler callback routing should have one facade");
        let main = fs::read_to_string(bpf_dir.join("main.bpf.c")).unwrap();
        let normalized_mode = mode.split_whitespace().collect::<Vec<_>>().join(" ");

        assert!(main.contains("#include \"scheduler_mode.h\""));
        for symbol in [
            "static __noinline __maybe_unused int scheduler_mode_enqueue_generic(",
            "static __always_inline int scheduler_mode_enqueue_expanded(",
        ] {
            assert!(normalized_mode.contains(symbol));
        }
        assert!(normalized_mode.contains("static __always_inline void scheduler_mode_dispatch("));
        assert_text_order(
            &mode,
            &[
                "scheduler_mode_dispatch(",
                "queue_topology_enabled()",
                "queue_ladder_dispatch(",
                "fairness_dispatch(",
            ],
        );
        for (callback, queue, global) in [
            ("dispatch", "queue_ladder_dispatch(", "fairness_dispatch("),
            (
                "runnable",
                "queue_fairness_prepare_runnable(",
                "fairness_runnable(",
            ),
            ("running", "queue_fairness_running(", "fairness_running("),
            ("stopping", "queue_fairness_stopping(", "fairness_stopping("),
            (
                "quiescent",
                "queue_fairness_cancel_direct(",
                "fairness_quiescent(",
            ),
        ] {
            let symbol = format!("scheduler_mode_{callback}(");
            assert!(mode.contains(&symbol), "mode facade is missing {symbol}");
            let mode_body = mode
                .split_once(&symbol)
                .and_then(|(_, body)| body.split_once("\nstatic __always_inline"))
                .map(|(body, _)| body)
                .unwrap_or_else(|| panic!("{symbol} should have one bounded body"));
            assert!(mode_body.contains(queue), "{symbol} is missing {queue}");
            assert!(mode_body.contains(global), "{symbol} is missing {global}");

            let callback_body = main
                .split_once(&format!("BPF_STRUCT_OPS(snake_{callback}"))
                .and_then(|(_, body)| body.split_once("BPF_STRUCT_OPS(snake_"))
                .map(|(body, _)| body)
                .unwrap_or_else(|| panic!("snake_{callback} callback should be bounded"));
            assert!(callback_body.contains(&symbol));
            assert!(!callback_body.contains(queue));
            assert!(!callback_body.contains(global));
            let expected_releases = usize::from(callback != "dispatch");
            assert_eq!(
                callback_body.matches("release_timed_callback(").count(),
                expected_releases,
                "snake_{callback} has the wrong callback cleanup ownership"
            );
        }

        let generic_enqueue = mode
            .split_once("scheduler_mode_enqueue_generic(")
            .and_then(|(_, body)| body.split_once("\nstatic "))
            .map(|(body, _)| body)
            .expect("generic enqueue should have one bounded body");
        assert!(generic_enqueue.contains("queue_ladder_enqueue("));
        assert!(generic_enqueue.contains("fairness_enqueue("));
        let no_direct_enqueue = mode
            .split_once("scheduler_mode_enqueue_no_direct(")
            .and_then(|(_, body)| body.split_once("\nstatic "))
            .map(|(body, _)| body)
            .expect("queue-only enqueue should have one bounded body");
        assert!(no_direct_enqueue.contains("queue_ladder_enqueue("));
        assert!(!no_direct_enqueue.contains("fairness_enqueue("));
        let fairness_enqueue = mode
            .split_once("scheduler_mode_enqueue_fairness(")
            .and_then(|(_, body)| body.split_once("\nstatic "))
            .map(|(body, _)| body)
            .expect("fairness enqueue should have one bounded body");
        assert!(!fairness_enqueue.contains("queue_ladder_enqueue("));
        assert!(fairness_enqueue.contains("fairness_enqueue("));
        let expanded_fallback = mode
            .split_once("scheduler_mode_enqueue_expanded_fallback(")
            .and_then(|(_, body)| body.split_once("\nstatic "))
            .map(|(body, _)| body)
            .expect("expanded enqueue fallback should have one bounded body");
        assert!(mode.contains("static __noinline int scheduler_mode_enqueue_expanded_fallback("));
        assert!(expanded_fallback.contains("queue_ladder_enqueue("));
        let expanded_enqueue = mode
            .split_once("scheduler_mode_enqueue_expanded(")
            .and_then(|(_, body)| body.split_once("\nstatic "))
            .map(|(body, _)| body)
            .expect("expanded enqueue should have one bounded body");
        assert!(expanded_enqueue.contains("if (!queue_topology_enabled())"));
        assert!(mode.contains("static __always_inline int scheduler_mode_enqueue_expanded("));
        assert!(expanded_enqueue.contains("scheduler_mode_enqueue_expanded_fallback("));
        assert!(!expanded_enqueue.contains("queue_ladder_enqueue("));
        assert!(!expanded_enqueue.contains("fairness_enqueue("));

        let enqueue_impl = main
            .split_once("snake_enqueue_impl(")
            .and_then(|(_, body)| body.split_once("snake_enqueue_expanded_impl("))
            .map(|(body, _)| body)
            .expect("snake enqueue implementation should be bounded");
        assert!(enqueue_impl.contains("scheduler_mode_enqueue_fairness("));
        assert!(!enqueue_impl.contains("scheduler_mode_enqueue_expanded("));
        assert!(!enqueue_impl.contains("scheduler_mode_enqueue_no_direct("));
        assert!(!enqueue_impl.contains("queue_ladder_enqueue("));
        assert!(!enqueue_impl.contains("fairness_enqueue("));
        assert_eq!(enqueue_impl.matches("release_timed_callback(").count(), 1);

        let expanded_impl = main
            .split_once("snake_enqueue_expanded_impl(")
            .and_then(|(_, body)| {
                body.split_once("static __noinline void snake_enqueue_no_direct_impl(")
            })
            .map(|(body, _)| body)
            .expect("expanded enqueue implementation should be bounded");
        assert!(expanded_impl.contains("scheduler_mode_enqueue_expanded("));
        assert!(!expanded_impl.contains("scheduler_mode_enqueue_fairness("));
        assert_eq!(expanded_impl.matches("release_timed_callback(").count(), 1);

        let no_direct_impl = main
            .split_once("static __noinline void snake_enqueue_no_direct_impl(")
            .and_then(|(_, body)| body.split_once("void BPF_STRUCT_OPS(snake_enqueue"))
            .map(|(body, _)| body)
            .expect("no-direct enqueue implementation should be bounded");
        assert!(no_direct_impl.contains("scheduler_mode_enqueue_no_direct("));
        assert!(!no_direct_impl.contains("queue_try_direct_from_enqueue"));
        assert_eq!(no_direct_impl.matches("release_timed_callback(").count(), 1);

        for symbol in ["scheduler_mode_set_weight(", "scheduler_mode_init_task("] {
            assert!(mode.contains(symbol), "mode facade is missing {symbol}");
            assert!(main.contains(symbol), "main callback does not use {symbol}");
        }
        assert_text_order(
            &mode,
            &[
                "scheduler_mode_enqueue_generic(",
                "fairness_dispatch_slice(",
                "try_enqueue_task_cell(",
                "if (cell_enqueued < 0)",
                "if (cell_enqueued > 0)",
                "fairness_enqueue(",
            ],
        );
        assert_text_order(
            &mode,
            &[
                "scheduler_mode_running(",
                "stat_inc(ctx, SNAKE_STAT_RUNNING)",
                "queue_account_task_membership(",
                "queue_fairness_running(",
            ],
        );
        assert_text_order(
            &mode,
            &[
                "scheduler_mode_quiescent(",
                "stat_inc(ctx, SNAKE_STAT_QUIESCENT)",
                "queue_timing_cancel(",
                "queue_cell_mode_enabled()",
            ],
        );
        let stopping = main
            .split_once("BPF_STRUCT_OPS(snake_stopping")
            .and_then(|(_, body)| body.split_once("BPF_STRUCT_OPS(snake_quiescent"))
            .map(|(body, _)| body)
            .unwrap();
        assert_text_order(
            stopping,
            &[
                "scheduler_mode_stopping(",
                "if (ret)",
                "else",
                "stat_add(&ladder_ctx, SNAKE_STAT_RUNTIME_NS, runtime_ns)",
                "release_timed_callback(",
            ],
        );
        let select = main
            .split_once("static __noinline s32 snake_select_cpu_impl(")
            .and_then(|(_, body)| body.split_once("s32 BPF_STRUCT_OPS(snake_select_cpu,"))
            .map(|(body, _)| body)
            .unwrap();
        assert!(!select.contains("scheduler_mode_"));
        assert!(select.contains("queue_fairness_select_cpu("));
        assert_eq!(select.matches("release_timed_callback(").count(), 1);
        assert_eq!(select.matches("finish_select(&ladder_ctx").count(), 1);
        assert_text_order(
            select,
            &[
                "out_success:",
                "finish_select(&ladder_ctx",
                "out:",
                "release_timed_callback(",
                "return cpu;",
            ],
        );
        let post_acquire = select
            .split_once("stat_inc(&ladder_ctx, SNAKE_STAT_SELECT_CALLS)")
            .map(|(_, body)| body)
            .unwrap();
        assert_eq!(post_acquire.matches("return ").count(), 1);

        let enqueue = main
            .split_once("snake_enqueue_impl(")
            .and_then(|(_, body)| body.split_once("snake_enqueue_expanded_impl("))
            .map(|(body, _)| body)
            .unwrap();
        assert_text_order(
            enqueue,
            &[
                "scheduler_mode_enqueue_fairness(",
                "release_timed_callback(",
                "if (ret)",
                "snake fairness enqueue failed",
            ],
        );
        let dispatch = mode
            .split_once("scheduler_mode_dispatch(")
            .and_then(|(_, body)| body.split_once("scheduler_mode_runnable("))
            .map(|(body, _)| body)
            .unwrap();
        assert_eq!(dispatch.matches("release_timed_callback(").count(), 2);
        assert_text_order(
            dispatch,
            &[
                "queue_topology_enabled()",
                "queue_ladder_dispatch(",
                "scheduler_mode_dispatch_error(cpu, ret, true)",
                "SNAKE_FINE_TIMING_DISPATCH_FINISH",
                "release_timed_callback(",
                "return;",
                "fairness_dispatch(",
                "release_timed_callback(",
                "scheduler_mode_dispatch_error(cpu, ret, false)",
            ],
        );
    }

    #[test]
    fn select_policy_walk_has_a_bounded_verifier_interface() {
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let ladder = fs::read_to_string(bpf_dir.join("ladder.h")).unwrap();
        let main = fs::read_to_string(bpf_dir.join("main.bpf.c")).unwrap();
        let normalized_ladder = ladder.split_whitespace().collect::<Vec<_>>().join(" ");
        let walk_context = ladder
            .split_once("struct snake_ladder_walk_args {")
            .and_then(|(_, body)| body.split_once("};"))
            .map(|(body, _)| body)
            .expect("policy-walk context should have one definition");

        for field in [
            "s32 prev_cpu;",
            "u32 queue_cell_index;",
            "u64 wake_flags;",
            "u64 enqueue_flags;",
            "u64 select_flags;",
            "u64 callback_started_at;",
            "u64 scope_started_at;",
            "u32 local_llc_route_cpu;",
            "u32 local_llc_cell_index;",
        ] {
            assert!(
                normalized_ladder.contains(field),
                "policy-walk context is missing {field}"
            );
        }
        assert!(!walk_context.contains('*'));
        assert_eq!(walk_context.matches(';').count(), 9);
        assert!(normalized_ladder.contains(
            "static __noinline s32 walk_policy_rung(struct snake_ladder_ctx *ctx, struct task_struct *p, u32 i, struct snake_ladder_walk_args *walk_args)"
        ));
        assert!(normalized_ladder.contains(
            "static __noinline s32 walk_generic_policy_ladder(struct snake_ladder_ctx *ctx, struct task_struct *p, struct snake_ladder_walk_args *walk_args)"
        ));
        assert!(normalized_ladder.contains(
            "static __noinline s32 walk_expanded_mitosis_ladder(struct snake_ladder_ctx *ctx, struct task_struct *p, struct snake_ladder_walk_args *walk_args)"
        ));
        let generic_walk = ladder
            .split_once("walk_generic_policy_ladder(struct snake_ladder_ctx *ctx")
            .and_then(|(_, body)| body.split_once("struct snake_enqueue_ladder_loop_ctx"))
            .map(|(body, _)| body)
            .expect("generic policy walker should have one definition");
        let enqueue_walk = ladder
            .split_once("struct snake_enqueue_ladder_loop_ctx")
            .and_then(|(_, body)| body.split_once("walk_expanded_mitosis_ladder("))
            .map(|(body, _)| body)
            .expect("enqueue policy walker should have one definition");
        let atomic_walk = ladder
            .split_once("walk_expanded_mitosis_ladder(struct snake_ladder_ctx *ctx")
            .and_then(|(_, body)| body.split_once("#endif"))
            .map(|(body, _)| body)
            .expect("queue-atomic policy walker should have one definition");
        let normalized_generic = generic_walk
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let normalized_atomic = atomic_walk.split_whitespace().collect::<Vec<_>>().join(" ");
        for index in 0..policy::MAX_GENERIC_RUNGS {
            assert_eq!(
                normalized_generic
                    .matches(&format!("walk_policy_rung(ctx, p, {index}, walk_args)"))
                    .count(),
                1
            );
        }
        assert!(!generic_walk.contains("bpf_loop("));
        assert!(enqueue_walk.contains("bpf_loop(SNAKE_MAX_GENERIC_RUNGS,"));
        assert!(enqueue_walk.contains("walk_generic_enqueue_ladder_callback"));
        assert!(enqueue_walk.contains("execute_direct_enqueue_rung("));
        assert!(!enqueue_walk.contains("result = walk_policy_rung("));
        assert!(!atomic_walk.contains("bpf_loop("));
        for (base, kind) in [
            (0, "SNAKE_QUEUE_MASK_LOCAL_LLC"),
            (4, "SNAKE_QUEUE_MASK_PRIMARY"),
            (8, "SNAKE_QUEUE_MASK_BORROWABLE"),
        ] {
            assert!(normalized_atomic.contains(&format!("ctx, p, {base}, {kind}, walk_args)")));
        }
        assert!(normalized_atomic.contains("ctx, p, 12, walk_args)"));
        assert!(normalized_ladder.contains("expanded_mitosis_finish_stage("));
        assert!(
            normalized_ladder.contains("static __always_inline s32 expanded_mitosis_finish_stage(")
        );
        assert!(!atomic_walk.contains("ctx->ladder->rungs["));
        assert!(normalized_ladder.contains(
            "static __always_inline bool queue_atomic_rung_is_valid(const struct snake_rung *rung)"
        ));
        for obsolete in [
            "SNAKE_EXPANDED_MITOSIS_",
            "walk_expanded_mitosis_rung(",
            "expanded_mitosis_spec(",
            "snake_expanded_mitosis_loop_ctx",
            "walk_expanded_mitosis_callback(",
            "walk_policy_ladder(",
        ] {
            assert!(
                !ladder.contains(obsolete),
                "obsolete wide walker symbol remains: {obsolete}"
            );
        }
        let prepare_validation = main
            .split_once("validate_compiled_ladder(")
            .and_then(|(_, body)| body.split_once("SEC(\"syscall\")"))
            .map(|(body, _)| body)
            .expect("ladder prepare validator should have one definition");
        assert!(prepare_validation.contains("queue_atomic_rung_is_valid(&rung)"));
        assert!(prepare_validation.contains("expanded_mitosis_rung_matches(&rung, i)"));
        assert!(normalized_ladder
            .contains("queue_args.random = rung->flags & SNAKE_RUNG_F_PICK_RANDOM;"));

        let select = main
            .split_once("static __noinline s32 snake_select_cpu_impl")
            .and_then(|(_, body)| body.split_once("BPF_STRUCT_OPS(snake_select_cpu,"))
            .map(|(body, _)| body)
            .unwrap();
        let normalized_select = select.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(normalized_select.contains("struct snake_ladder_walk_args walk_args = {"));
        assert!(
            normalized_select.contains("walk_expanded_mitosis_ladder(&ladder_ctx, p, &walk_args)")
        );
        assert!(
            normalized_select.contains("walk_generic_policy_ladder(&ladder_ctx, p, &walk_args)")
        );
        assert!(normalized_select.contains("walk_args.enqueue_flags & SCX_ENQ_PREEMPT"));
        assert!(normalized_select.contains("walk_args.select_flags & SNAKE_SELECT_F_BORROWED"));
        assert!(normalized_select.contains("walk_args.queue_cell_index"));
    }

    #[test]
    fn transition_direct_dispatch_keeps_select_metadata_out_of_enqueue_flags() {
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let ladder = fs::read_to_string(bpf_dir.join("ladder.h")).unwrap();
        let main = fs::read_to_string(bpf_dir.join("main.bpf.c")).unwrap();
        let normalized_ladder = ladder.split_whitespace().collect::<Vec<_>>().join(" ");
        let normalized_main = main.split_whitespace().collect::<Vec<_>>().join(" ");

        assert!(normalized_ladder.contains("u64 enqueue_flags;"));
        assert!(normalized_ladder.contains("u64 select_flags;"));
        assert!(normalized_main.contains("walk_args.enqueue_flags"));
        assert!(normalized_main.contains("walk_args.select_flags"));
        assert!(normalized_main.contains(
            "ret = dsq_insert_local_on( p, cpu, fairness_dispatch_slice(&ladder_ctx, p, true), walk_args.enqueue_flags, &fine_timing);"
        ));
        assert!(!normalized_main
            .contains("fairness_dispatch_slice(&ladder_ctx, p, true), walk_args.select_flags"));
    }

    #[test]
    fn direct_dispatch_targets_the_selected_cpu_explicitly() {
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let dsq = fs::read_to_string(bpf_dir.join("dsq.h")).unwrap();
        let direct = dsq
            .split_once("dsq_insert_local_on(")
            .and_then(|(_, body)| body.split_once("dsq_insert_vtime("))
            .map(|(body, _)| body)
            .expect("direct dispatch should have a selected-CPU DSQ helper");

        assert!(direct.contains("scx_bpf_dsq_insert(p, target.raw"));
        assert!(!direct.contains("scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL,"));
    }

    #[test]
    fn expanded_mitosis_unavailable_scopes_report_and_time_counted_rungs() {
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let ladder = fs::read_to_string(bpf_dir.join("ladder.h")).unwrap();
        let unavailable = ladder
            .split_once("expanded_mitosis_unavailable_scope(")
            .and_then(|(_, body)| body.split_once("walk_expanded_mitosis_candidates("))
            .map(|(body, _)| body)
            .expect("expanded Mitosis unavailable-scope helper should have one definition");

        assert_eq!(
            unavailable
                .matches("expanded_mitosis_record_unavailable_stage(")
                .count(),
            4,
            "all four counted misses need a matching timing event"
        );
        assert!(unavailable.contains("scx_bpf_error("));
        assert_eq!(unavailable.matches("scx_bpf_error(").count(), 1);

        let normalized = ladder.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(normalized
            .contains("static __always_inline void expanded_mitosis_record_unavailable_stage("));
        assert!(normalized.contains(
            "walk_expanded_mitosis_candidates( struct snake_ladder_ctx *ctx, struct task_struct *p, u32 base, const struct cpumask *candidates, struct snake_ladder_walk_args *walk_args)"
        ));
        assert!(normalized.contains("started_at = walk_args->scope_started_at;"));
    }

    #[test]
    fn select_program_is_specialized_before_bpf_load() {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let bpf_main = fs::read_to_string(manifest.join("src/bpf/main.bpf.c")).unwrap();
        let scheduler_mode = fs::read_to_string(manifest.join("src/bpf/scheduler_mode.h")).unwrap();
        let userspace = fs::read_to_string(manifest.join("src/main.rs")).unwrap();
        let normalized_bpf = bpf_main.split_whitespace().collect::<Vec<_>>().join(" ");

        assert!(normalized_bpf.contains(
            "static __noinline s32 snake_select_cpu_impl(struct task_struct *p, s32 prev_cpu, u64 wake_flags, bool expanded_mitosis)"
        ));
        assert!(normalized_bpf.contains(
            "cpu = expanded_mitosis ? walk_expanded_mitosis_ladder(&ladder_ctx, p, &walk_args) : walk_generic_policy_ladder(&ladder_ctx, p, &walk_args);"
        ));
        assert!(bpf_main.contains("BPF_STRUCT_OPS(snake_select_cpu,"));
        assert!(bpf_main.contains("BPF_STRUCT_OPS(snake_select_cpu_expanded,"));
        assert!(bpf_main.contains("BPF_STRUCT_OPS(snake_enqueue_expanded,"));
        assert!(bpf_main.contains("BPF_STRUCT_OPS(snake_enqueue_no_direct,"));
        assert!(normalized_bpf.contains(
            "static __noinline void snake_enqueue_impl(struct task_struct *p, u64 enq_flags)"
        ));
        assert!(normalized_bpf.contains(
            "static __noinline void snake_enqueue_expanded_impl(struct task_struct *p, u64 enq_flags)"
        ));
        assert!(scheduler_mode.contains("scheduler_mode_enqueue_generic("));
        assert!(scheduler_mode.contains("scheduler_mode_enqueue_expanded("));
        assert!(scheduler_mode.contains("scheduler_mode_enqueue_no_direct("));
        assert!(scheduler_mode.contains("scheduler_mode_enqueue_fairness("));
        assert!(userspace.contains("snake_select_cpu_expanded.set_autoload(false)"));
        assert!(userspace.contains("snake_select_cpu.set_autoload(false)"));
        assert!(userspace.contains("snake_enqueue_expanded.set_autoload(false)"));
        assert!(userspace.contains("snake_enqueue.set_autoload(false)"));
        assert!(userspace.contains("snake_enqueue_no_direct.set_autoload(false)"));
        assert!(userspace.contains("snake_ops_mut().select_cpu = selected_select_cpu"));
        assert!(userspace.contains("snake_ops_mut().enqueue = selected_enqueue"));
        assert_text_order(
            &userspace,
            &[
                "snake_ops_mut().select_cpu = selected_select_cpu",
                "scx_ops_load!(skel, snake_ops, uei)",
            ],
        );
    }

    #[test]
    fn select_cpu_variant_is_attachment_time_configuration() {
        let generic = policy::compile_policy(policy_source()).unwrap();
        let expanded =
            policy::compile_policy(include_str!("../examples/mitosis-sim.toml")).unwrap();

        assert!(!uses_expanded_mitosis_select(&generic));
        assert!(uses_expanded_mitosis_select(&expanded));
        assert!(validate_select_cpu_variant_replacement(&generic, &generic).is_ok());
        assert!(validate_select_cpu_variant_replacement(&expanded, &expanded).is_ok());
        let error = validate_select_cpu_variant_replacement(&generic, &expanded)
            .unwrap_err()
            .to_string();
        assert!(error.contains("attachment-time select_cpu variant"));
        assert!(error.contains("restart Snake"));

        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let bpf_main = fs::read_to_string(manifest.join("src/bpf/main.bpf.c")).unwrap();
        let userspace = fs::read_to_string(manifest.join("src/main.rs")).unwrap();
        let normalized_bpf = bpf_main.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(normalized_bpf.contains(
            "if (!!expanded_mitosis_select != (ladder->nr_rungs > SNAKE_MAX_GENERIC_RUNGS)) return -EINVAL;"
        ));
        assert_text_order(
            &userspace,
            &[
                "rodata.expanded_mitosis_select = u32::from(uses_expanded_mitosis_select(&runtime.compiled));",
                "scx_ops_load!(skel, snake_ops, uei)",
            ],
        );
    }

    #[test]
    fn enqueue_direct_dispatch_variant_is_attachment_time_configuration() {
        let no_direct = policy::compile_policy(policy_source()).unwrap();
        let direct = policy::compile_policy(include_str!("../examples/mitosis-sim.toml")).unwrap();
        let generic_cell_direct_source = include_str!("../examples/cell-llc-queues.toml")
            .replacen("[queues]", "[queues]\ndirect_dispatch = true", 1)
            .replace("scope = \"task_allowed\"", "scope = \"task_cell\"");
        let generic_cell_direct = policy::compile_policy(&generic_cell_direct_source).unwrap();
        let llc_direct = policy::compile_policy(
            r#"
[queues]
layout = "llc"
direct_dispatch = true

[[rung]]
operation = "pick_idle"
scope = "task_allowed"
"#,
        )
        .unwrap();

        assert!(!uses_enqueue_direct_retry(&no_direct));
        assert!(uses_enqueue_direct_retry(&direct));
        assert!(!uses_enqueue_direct_retry(&generic_cell_direct));
        assert!(!uses_enqueue_direct_retry(&llc_direct));
        assert!(validate_enqueue_variant_replacement(&no_direct, &no_direct).is_ok());
        assert!(validate_enqueue_variant_replacement(&direct, &direct).is_ok());
        let error = validate_enqueue_variant_replacement(&no_direct, &direct)
            .unwrap_err()
            .to_string();
        assert!(error.contains("attachment-time enqueue variant"));
        assert!(error.contains("restart Snake"));

        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let userspace = fs::read_to_string(manifest.join("src/main.rs")).unwrap();
        assert_text_order(
            &userspace,
            &[
                "let enqueue_direct_retry = uses_enqueue_direct_retry(&runtime.compiled);",
                "scx_ops_load!(skel, snake_ops, uei)",
            ],
        );
    }

    #[test]
    fn task_cell_enqueue_walk_has_a_bounded_verifier_interface() {
        let ladder =
            fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf/ladder.h"))
                .unwrap();
        let normalized = ladder.split_whitespace().collect::<Vec<_>>().join(" ");
        let enqueue_walk = ladder
            .split_once("try_enqueue_task_cell(")
            .and_then(|(_, body)| body.split_once("walk_policy_rung("))
            .map(|(body, _)| body)
            .expect("task-cell enqueue walker should have one definition");

        assert!(normalized.contains(
            "bpf_loop(SNAKE_MAX_GENERIC_RUNGS, try_enqueue_task_cell_callback, &loop_ctx, 0)"
        ));
        assert!(normalized.contains(
            "if (i >= SNAKE_MAX_GENERIC_RUNGS || i >= loop_ctx->ladder_ctx.ladder->nr_rungs) return 1;"
        ));
        assert!(!enqueue_walk.contains("bpf_for(i, 0, SNAKE_MAX_RUNGS)"));
    }

    #[test]
    fn queue_enqueue_walk_has_a_bounded_verifier_interface() {
        let queue_enqueue = fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf/queue_enqueue.h"),
        )
        .unwrap();
        let normalized = queue_enqueue
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let enqueue_walk = queue_enqueue
            .split_once("queue_ladder_enqueue(")
            .and_then(|(_, body)| body.split_once("#endif"))
            .map(|(body, _)| body)
            .expect("queue enqueue walker should have one definition");

        assert!(normalized.contains(
            "bpf_loop(SNAKE_MAX_QUEUE_RUNGS, queue_cell_ladder_enqueue_callback, &loop_ctx, 0)"
        ));
        assert!(normalized.contains(
            "if (i >= SNAKE_MAX_QUEUE_RUNGS || i >= loop_ctx->ladder_ctx.ladder->nr_enqueue_rungs) return 1;"
        ));
        assert!(normalized.contains("static __noinline int queue_global_ladder_enqueue("));
        assert!(normalized.contains("static __noinline int queue_global_enqueue_local_ctx("));
        assert!(normalized.contains("static __noinline int queue_global_enqueue_cpu_ctx("));
        assert!(normalized.contains("queue_global_ladder_enqueue_rung(loop_ctx, 0)"));
        assert!(normalized.contains("queue_global_ladder_enqueue_rung(loop_ctx, 1)"));
        assert!(!enqueue_walk.contains("bpf_for(i, 0, SNAKE_MAX_QUEUE_RUNGS)"));
    }

    #[test]
    fn queue_allowed_cpu_scan_has_a_bounded_verifier_interface() {
        let queue =
            fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf/queue.h"))
                .unwrap();
        let normalized = queue.split_whitespace().collect::<Vec<_>>().join(" ");
        let allowed_scan = queue
            .split_once("queue_pick_allowed_cpu(")
            .and_then(|(_, body)| body.split_once("#endif"))
            .map(|(body, _)| body)
            .expect("queue allowed-CPU picker should have one definition");

        assert!(normalized
            .contains("bpf_loop(SNAKE_MAX_CPUS, queue_pick_allowed_cpu_callback, &loop_ctx, 0)"));
        assert!(
            normalized.contains("if (offset >= SNAKE_MAX_CPUS || offset >= nr_cpu_ids) return 1;")
        );
        assert!(!allowed_scan.contains("bpf_for(offset, 0, SNAKE_MAX_CPUS)"));
    }

    #[test]
    fn queue_dispatch_walk_has_a_bounded_verifier_interface() {
        let queue_dispatch = fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf/queue_dispatch.h"),
        )
        .unwrap();
        let normalized = queue_dispatch
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let dispatch_walk = queue_dispatch
            .split_once("queue_ladder_dispatch(")
            .and_then(|(_, body)| body.split_once("#endif"))
            .map(|(body, _)| body)
            .expect("queue dispatch walker should have one definition");

        assert!(normalized.contains(
            "bpf_loop(SNAKE_MAX_QUEUE_RUNGS, queue_ladder_dispatch_callback, &loop_ctx, 0)"
        ));
        assert!(normalized.contains(
            "if (step >= SNAKE_MAX_QUEUE_RUNGS || step >= loop_ctx->ladder_ctx.ladder->nr_dispatch_rungs) return 1;"
        ));
        assert!(!dispatch_walk.contains("bpf_for(step, 0, SNAKE_MAX_QUEUE_RUNGS)"));
    }

    #[test]
    fn fine_timing_context_stays_compact_for_loop_callbacks() {
        let timing =
            fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf/timing.h"))
                .unwrap();
        let context = timing
            .split_once("struct snake_fine_timing_ctx {")
            .and_then(|(_, body)| body.split_once("};"))
            .map(|(body, _)| body)
            .expect("fine-timing context should have one definition");
        let normalized = context.split_whitespace().collect::<Vec<_>>().join(" ");

        assert!(normalized.contains("u8 active;"));
        assert!(normalized.contains("u8 sampled;"));
        assert!(!normalized.contains("u32 active;"));
        assert!(!normalized.contains("u32 sampled;"));
    }

    #[test]
    fn dispatch_transfer_sampling_uses_ring_storage_instead_of_dispatch_stack() {
        let timing =
            fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf/timing.h"))
                .unwrap();
        let helper = timing
            .split_once("fine_timing_record_dispatch_transfer(")
            .and_then(|(_, body)| {
                body.split_once("static __always_inline void\nfine_timing_finish(")
            })
            .map(|(body, _)| body)
            .expect("dispatch transfer helper should have one definition");

        assert!(timing.contains("static __noinline void\nfine_timing_record_dispatch_transfer("));
        assert!(helper.contains("bpf_ringbuf_reserve(&fine_timing_events"));
        assert!(helper.contains("bpf_ringbuf_submit(event, 0)"));
        assert!(helper.contains("READ_ONCE(dispatch_fine_timing_session_id)"));
        assert!(!helper.contains("bpf_map_lookup_elem"));
        assert!(!helper.contains("struct snake_fine_timing_event event = {}"));
    }

    #[test]
    fn dispatch_transfer_sampling_unwinds_before_ringbuf_emission() {
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let dsq = fs::read_to_string(bpf_dir.join("dsq.h")).unwrap();
        let dispatch = fs::read_to_string(bpf_dir.join("queue_dispatch.h")).unwrap();
        let ladder = dispatch
            .split_once("static __noinline int queue_global_ladder_dispatch(")
            .and_then(|(_, body)| body.split_once("struct snake_queue_dispatch_loop_ctx"))
            .map(|(body, _)| body)
            .expect("global dispatch ladder should have one definition");

        assert!(!dsq.contains("fine_timing_record_dispatch_transfer("));
        assert_eq!(
            dispatch
                .matches("fine_timing_record_dispatch_transfer(")
                .count(),
            3
        );
        assert!(
            ladder.find("queue_global_dispatch_consume_rung(").unwrap()
                < ladder
                    .find("fine_timing_record_dispatch_transfer(")
                    .unwrap()
        );
    }

    #[test]
    fn queue_dispatch_keep_running_has_a_stack_boundary() {
        let queue_dispatch = fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf/queue_dispatch.h"),
        )
        .unwrap();
        let normalized = queue_dispatch
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");

        assert!(normalized.contains(
            "static __noinline s32 queue_fairness_keep_running(struct snake_ladder_ctx *ctx, struct snake_cpu_queue *cpuq, struct task_struct *prev, u32 class, u64 candidate_vtime)"
        ));
    }

    #[test]
    fn queue_dispatch_rehome_check_has_a_stack_boundary() {
        let queue_vtime = fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf/queue_vtime.h"),
        )
        .unwrap();
        let normalized = queue_vtime.split_whitespace().collect::<Vec<_>>().join(" ");

        assert!(normalized.contains(
            "static __noinline bool queue_fairness_rehome_pending( const struct snake_ladder_ctx *ctx, struct task_struct *p, struct snake_task_runtime *runtime)"
        ));
    }

    #[test]
    fn queue_dispatch_min_vtime_has_a_stack_boundary() {
        let queue_dispatch = fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf/queue_dispatch.h"),
        )
        .unwrap();
        let normalized = queue_dispatch
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");

        assert!(normalized.contains("static __noinline s32 queue_fairness_dispatch_min("));
        assert!(normalized.contains("const struct snake_queue_dispatch_min_args *args)"));
    }

    #[test]
    fn dispatch_error_formatting_has_a_stack_boundary() {
        let scheduler_mode = fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf/scheduler_mode.h"),
        )
        .unwrap();
        let normalized = scheduler_mode
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");

        assert!(normalized.contains(
            "static __noinline void scheduler_mode_dispatch_error(s32 cpu, s32 ret, bool queue)"
        ));
        assert_eq!(
            scheduler_mode
                .matches("scheduler_mode_dispatch_error(cpu, ret,")
                .count(),
            2
        );
    }

    #[test]
    fn fine_timing_recorders_bound_callback_indices() {
        let timing =
            fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf/timing.h"))
                .unwrap();

        assert!(
            timing
                .matches("callback >= SNAKE_NR_FINE_TIMING_CALLBACKS")
                .count()
                >= 2,
            "each fine-timing recorder must validate callback before indexing session_ids",
        );
        assert!(timing.matches("config->session_ids[callback]").count() >= 2);
    }

    #[test]
    fn task_cell_enqueue_errors_reach_the_root_reporter() {
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let scheduler = fs::read_to_string(bpf_dir.join("scheduler_mode.h")).unwrap();
        let ladder = fs::read_to_string(bpf_dir.join("ladder.h")).unwrap();
        let normalized_scheduler = scheduler.split_whitespace().collect::<Vec<_>>().join(" ");
        let task_cell_path = ladder
            .split_once("try_enqueue_task_cell_callback(")
            .and_then(|(_, body)| body.split_once("walk_policy_rung("))
            .map(|(body, _)| body)
            .expect("task-cell enqueue path should have one definition");

        assert!(normalized_scheduler.contains(
            "if (cell_enqueued < 0) return cell_enqueued; if (cell_enqueued > 0) return 0;"
        ));
        assert!(!task_cell_path.contains("scx_bpf_error"));
    }

    #[test]
    fn queue_loop_errors_defer_to_root_reporters() {
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        for file in ["queue_enqueue.h", "queue_dispatch.h"] {
            let source = fs::read_to_string(bpf_dir.join(file)).unwrap();
            let loop_error = source
                .split_once("if (nr_loops < 0) {")
                .and_then(|(_, body)| body.split_once('}'))
                .map(|(body, _)| body)
                .expect("queue loop should check bpf_loop errors");
            assert!(
                loop_error.contains("return nr_loops;")
                    || loop_error.contains("result = nr_loops;")
            );
            assert!(!loop_error.contains("scx_bpf_error"));
        }
    }

    fn raw_percpu_stats() -> Vec<Vec<Vec<u8>>> {
        (0..bpf_intf::snake_stat_SNAKE_NR_STATS)
            .map(|_| vec![0_u64.to_ne_bytes().to_vec(); 2])
            .collect()
    }

    fn raw_percpu_cell_stats(cell_count: usize, cpu_count: usize) -> Vec<Vec<Vec<u8>>> {
        (0..cell_count * bpf_intf::snake_cell_stat_SNAKE_NR_CELL_STATS as usize)
            .map(|_| vec![0_u64.to_ne_bytes().to_vec(); cpu_count])
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
        let sources = bpf_sources(&bpf_dir);
        let owners = sources
            .iter()
            .filter(|(_, source)| {
                RAW_OPERATIONS
                    .iter()
                    .any(|operation| source.contains(operation))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            owners.len(),
            1,
            "raw sched_ext DSQ operations must have exactly one source owner"
        );
        let shared = &owners[0].1;
        for operation in RAW_OPERATIONS {
            assert!(
                shared.contains(operation),
                "shared DSQ owner is missing {operation}"
            );
        }
        assert!(shared.contains("fine_timing_reserve_dsq_operation"));
        assert!(shared.contains("static __noinline bool\ndsq_move_to_local"));
    }

    #[test]
    fn dsq_fine_timing_reserves_events_without_a_stack_copy() {
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let dsq = fs::read_to_string(bpf_dir.join("dsq.h")).unwrap();
        let timing = fs::read_to_string(bpf_dir.join("timing.h")).unwrap();
        let recorder = timing
            .split_once("fine_timing_reserve_dsq_operation(")
            .unwrap()
            .1
            .split_once("/* Global dispatch stays untimed")
            .unwrap()
            .0;

        assert!(dsq.contains("event->session_id"));
        assert!(dsq.contains("fine->session_id"));
        assert!(!dsq.contains("struct snake_fine_timing_event event ="));
        assert!(recorder.contains("bpf_ringbuf_reserve("));
        assert!(dsq.contains("bpf_ringbuf_submit(event, 0)"));
    }

    #[test]
    fn vm_matrix_snapshots_inputs_and_scales_deadlines() {
        let tests = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
        let local = fs::read_to_string(tests.join("vm_matrix_local.sh")).unwrap();
        let shard = fs::read_to_string(tests.join("vm_matrix_shard.sh")).unwrap();

        assert!(local.contains("inputs_dir=${campaign_dir}/inputs"));
        assert!(local.contains("snapshot_snake=${inputs_dir}/scx_snake"));
        assert!(local.contains("snapshot_inspector=${inputs_dir}/scx_snake_inspector"));
        assert!(local.contains("snapshot_policies=${inputs_dir}/policies"));
        assert!(local.contains("chmod -R a-w \"${inputs_dir}\""));
        assert!(local.contains("max_cases_per_shard="));
        assert!(local.contains("case_budget_secs="));
        assert!(local.contains(".status == \"skipped\""));
        assert!(local.contains("testing_fairness=${SNAKE_TESTING_FAIRNESS:-}"));
        assert!(local.contains("testing_policy=${SNAKE_TESTING_POLICY:-}"));
        assert!(local.contains("shard_args+=(\"${testing_fairness}\" \"${testing_policy}\")"));
        assert!(local.contains("--testing-fairness"));
        assert!(local.contains("--testing-policy"));
        assert!(local.contains("guest_script=${campaign_dir}/shard-${shard}-guest.sh"));
        assert!(local.contains("--exec \"${guest_script}\""));
        assert!(local.contains("chmod 0555 \"${guest_script}\""));
        assert!(!local.contains("guest_command="));
        assert!(!local.contains("SNAKE_TESTING_VM_TIMEOUT_SECS:-2700"));

        assert!(shard.contains("policy_dir=${6:-"));
        assert!(shard.contains("testing_fairness=${7:-}"));
        assert!(shard.contains("testing_policy=${8:-}"));
        assert!(shard.contains("--testing-fairness"));
        assert!(shard.contains("--testing-policy"));
        assert!(shard.contains("assigned_cases=$(jq -er '.matrix.assigned_cases'"));
        assert!(shard.contains("duration_secs=$(jq -er '.matrix.duration_secs'"));
        assert!(shard.contains("case_budget_secs=$((duration_secs + 45))"));
        assert!(shard.contains(".status == \"skipped\""));
        assert!(shard.contains("passed + skipped == assigned"));
        assert!(!shard.contains("SECONDS + 2100"));
    }

    #[test]
    fn veristat_configs_cover_nondefault_fairness_and_queue_modes() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("veristat");
        let mut modes = BTreeSet::new();
        for entry in fs::read_dir(dir).expect("Snake veristat directory should exist") {
            let path = entry.expect("veristat entry should be readable").path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let document: serde_json::Value =
                serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
            let rodata = document[0]["formatted"]["value"][".rodata"]
                .as_array()
                .unwrap();
            let value = |name: &str| {
                rodata
                    .iter()
                    .find_map(|entry| entry.get(name).and_then(serde_json::Value::as_u64))
                    .unwrap()
            };
            modes.insert((value("fairness_mode"), value("queue_mode")));
        }
        assert_eq!(modes, BTreeSet::from([(2, 0), (3, 0), (3, 1), (3, 2)]));
    }

    #[test]
    fn bpf_dsq_head_peek_has_one_shared_implementation() {
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let sources = bpf_sources(&bpf_dir);
        let owners = sources
            .iter()
            .filter(|(_, source)| source.contains("scx.dsq_vtime"))
            .collect::<Vec<_>>();

        assert_eq!(owners.len(), 1, "DSQ vtime head reads must have one owner");
        assert_eq!(owners[0].0.file_name().unwrap(), "dsq.h");
        assert!(owners[0].1.contains("dsq_vtime_head("));
        let helper = owners[0]
            .1
            .split_once("dsq_peek_vtime(")
            .and_then(|(_, body)| body.split_once("dsq_create("))
            .map(|(body, _)| body)
            .unwrap();
        assert_text_order(
            helper,
            &[
                "dsq_peek(dsq)",
                "if (!p || !vtime)",
                "return NULL",
                "READ_ONCE(p->scx.dsq_vtime)",
                "return p",
                "dsq_nr_queued(dsq)",
                "return false",
                "dsq_peek_vtime(dsq, vtime)",
            ],
        );
        for (_, source) in &sources {
            assert!(!source.contains("fairness_vtime_head("));
            assert!(!source.contains("queue_fairness_head("));
        }
    }

    #[test]
    fn bpf_random_idle_reservoir_sampling_is_shared() {
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let shared = fs::read_to_string(bpf_dir.join("cpu_pick.h"))
            .expect("random idle CPU sampling should have a shared owner");
        let ladder = fs::read_to_string(bpf_dir.join("ladder.h")).unwrap();
        let queue = fs::read_to_string(bpf_dir.join("queue_fairness.h")).unwrap();
        let masks = fs::read_to_string(bpf_dir.join("mask_table.h")).unwrap();

        assert!(shared.contains("#include \"bpf_common.h\""));
        assert!(shared.contains("static __always_inline s32 cpu_pick_random_idle("));
        assert!(shared.contains("cpu_pick_random_idle("));
        assert!(shared.contains("bpf_for(cpu, 0, SNAKE_MAX_CPUS)"));
        assert!(shared.contains("bpf_cpumask_test_cpu(cpu, allowed)"));
        assert!(shared.contains("bpf_cpumask_test_cpu(cpu, idle)"));
        assert!(shared.contains("bpf_get_prandom_u32() % candidates"));
        assert!(shared.contains("scx_bpf_test_and_clear_cpu_idle(selected)"));
        assert_eq!(shared.matches("scx_bpf_put_idle_cpumask(idle)").count(), 2);
        assert!(ladder.contains("return cpu_pick_random_idle(p->cpus_ptr, whole_core);"));
        assert!(queue.contains("static __always_inline s32\nqueue_pick_random_idle_cpu("));
        assert!(queue.contains("return cpu_pick_random_idle(candidates, whole_core);"));
        let ladder_wrapper = ladder
            .split_once("pick_random_idle(")
            .and_then(|(_, body)| body.split_once("try_sync_wake_affine("))
            .map(|(body, _)| body)
            .unwrap();
        let queue_wrapper = queue
            .split_once("queue_pick_random_idle_cpu(")
            .and_then(|(_, body)| body.split_once("queue_pick_task_cell_cpu("))
            .map(|(body, _)| body)
            .unwrap();
        assert!(!ladder_wrapper.contains("bpf_for("));
        assert!(!queue_wrapper.contains("bpf_for("));
        let queue_cell_pick = queue
            .split_once("queue_pick_task_cell_cpu(")
            .and_then(|(_, body)| body.split_once("queue_fairness_select_cpu("))
            .map(|(body, _)| body)
            .unwrap();
        assert_text_order(
            queue_cell_pick,
            &[
                "bpf_cpumask_and(scratch, source, p->cpus_ptr)",
                "queue_pick_random_idle_cpu(",
                "(const struct cpumask *)scratch",
            ],
        );
        let mask_random = masks
            .split_once("pick_random_idle_from_mask_table(")
            .map(|(_, body)| body)
            .unwrap();
        assert!(mask_random.contains("(const struct cpumask *)table_mask"));
        assert!(mask_random.contains("p->cpus_ptr"));
        assert!(!mask_random.contains("cpu_pick_random_idle("));
    }

    #[test]
    fn bpf_dsq_identity_is_independent_from_dsq_operations() {
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let identity = fs::read_to_string(bpf_dir.join("dsq_id.h"))
            .expect("DSQ identity should have a dedicated header");
        let operations = fs::read_to_string(bpf_dir.join("dsq.h")).unwrap();

        assert!(identity.contains("#include \"bpf_common.h\""));
        assert!(identity.contains("typedef union"));
        for constructor in [
            "dsq_from_raw(",
            "dsq_invalid(",
            "dsq_eevdf_eligible(",
            "dsq_eevdf_future(",
            "dsq_vtime_global(",
            "dsq_vtime_cpu(",
            "dsq_affinity(",
            "dsq_normal(",
            "dsq_fifo(",
            "dsq_local(",
            "dsq_local_on(",
            "dsq_queue_class(",
        ] {
            assert!(
                identity.contains(constructor),
                "DSQ identity header is missing {constructor}"
            );
        }
        assert!(!identity.contains("scx_bpf_dsq_"));
        assert!(!identity.contains("fine_timing_"));
        assert!(operations.contains("#include \"dsq_id.h\""));
        assert!(operations.contains("#include \"timing.h\""));
        assert!(!operations.contains("typedef union"));
    }

    #[test]
    fn bpf_queue_timing_has_one_owner_and_preserves_state_machine() {
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let owner = fs::read_to_string(bpf_dir.join("queue_timing.h"))
            .expect("queue timing should have a dedicated owner");
        let main = fs::read_to_string(bpf_dir.join("main.bpf.c")).unwrap();

        assert!(owner.contains("#include \"fairness_common.h\""));
        assert!(owner.contains("#include \"dsq.h\""));
        for symbol in [
            "extern u64",
            "queue_timing_events",
            "queue_timing_record_sample(",
            "queue_timing_record_insert(",
            "queue_timing_cancel_runtime(",
            "queue_timing_cancel(",
            "queue_timing_complete(",
            "queue_timing_complete_pending(",
        ] {
            assert!(
                owner.contains(symbol),
                "queue timing owner is missing {symbol}"
            );
        }
        let normalized_main = main.split_whitespace().collect::<Vec<_>>().join(" ");
        assert_eq!(
            normalized_main
                .matches("u64 queue_timing_session_id;")
                .count(),
            1
        );
        assert_eq!(
            normalized_main
                .matches("struct snake_queue_timing_counters queue_timing_counters;")
                .count(),
            1
        );

        let sources = bpf_sources(&bpf_dir);
        for (path, source) in &sources {
            let name = path.file_name().unwrap().to_string_lossy();
            if name != "queue_timing.h" && name != "task_state.h" {
                assert!(
                    !source.contains("->queue_timing_"),
                    "{} bypasses queue-timing state transitions",
                    path.display()
                );
            }
        }
        let outside_owner = sources
            .iter()
            .filter(|(path, _)| path.file_name().unwrap() != "queue_timing.h")
            .map(|(_, source)| source.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            outside_owner
                .iter()
                .map(|source| source.matches("queue_timing_record_insert(").count())
                .sum::<usize>(),
            11
        );
        assert_eq!(
            outside_owner
                .iter()
                .map(|source| source.matches("queue_timing_complete_pending(").count())
                .sum::<usize>(),
            4
        );
        assert_eq!(
            outside_owner
                .iter()
                .map(|source| source.matches("queue_timing_cancel_runtime(").count())
                .sum::<usize>(),
            1
        );
        assert_eq!(
            outside_owner
                .iter()
                .map(|source| source.matches("queue_timing_cancel(").count())
                .sum::<usize>(),
            1
        );

        let record = owner
            .split_once("queue_timing_record_sample(")
            .and_then(|(_, body)| body.split_once("queue_timing_record_insert("))
            .map(|(body, _)| body)
            .unwrap();
        assert_text_order(
            record,
            &[
                "READ_ONCE(queue_timing_session_id) != session_id",
                "runtime->queue_timing_dsq_id",
                "runtime->queue_timing_enqueued_at_ns",
                "runtime->queue_timing_cell_index",
                "runtime->queue_timing_depth_after_insert",
                "runtime->queue_timing_queue_class",
                "runtime->queue_timing_session_id",
                "queue_timing_counters.started_samples",
            ],
        );
        let complete = owner
            .split_once("queue_timing_complete(struct")
            .and_then(|(_, body)| body.split_once("queue_timing_complete_pending("))
            .map(|(body, _)| body)
            .unwrap();
        assert_text_order(
            complete,
            &[
                "runtime->queue_timing_session_id = 0",
                "READ_ONCE(queue_timing_session_id)",
                "bpf_ringbuf_output(&queue_timing_events",
            ],
        );

        let rust =
            fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/main.rs"))
                .unwrap();
        assert!(rust.contains("snapshot.queue_timing = Some(self.queue_timing_inspection()?);"));
        assert!(
            !rust.contains("if self.queue_topology.is_some() {\n            snapshot.queue_timing")
        );
    }

    #[test]
    fn quiescence_cancels_an_unfinished_queue_timing_sample() {
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let main = fs::read_to_string(bpf_dir.join("main.bpf.c")).unwrap();
        let mode = fs::read_to_string(bpf_dir.join("scheduler_mode.h")).unwrap();
        let quiescent = main
            .split_once("void BPF_STRUCT_OPS(snake_quiescent")
            .and_then(|(_, rest)| rest.split_once("void BPF_STRUCT_OPS(snake_set_weight"))
            .map(|(body, _)| body)
            .expect("snake_quiescent should precede snake_set_weight");
        let mode_quiescent = mode
            .split_once("scheduler_mode_quiescent(")
            .and_then(|(_, rest)| rest.split_once("scheduler_mode_set_weight("))
            .map(|(body, _)| body)
            .expect("scheduler mode should own quiescent routing");

        assert!(quiescent
            .contains("scheduler_mode_quiescent(&ladder_ctx, p, deq_flags, &fine_timing);"));
        assert!(mode_quiescent.contains("queue_timing_cancel(ctx, p);"));
    }

    #[test]
    fn mask_preparation_releases_removed_table_slots() {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let mask_init = fs::read_to_string(manifest.join("src/bpf/mask_table_init.h")).unwrap();
        let prepare = mask_init
            .split_once("prepare_mask_tables(")
            .map(|(_, body)| body)
            .expect("prepare_mask_tables should have one initialization owner");
        assert!(prepare.contains("table_id >= ladder->nr_mask_tables"));
        assert!(prepare.contains("data->valid != 1"));
        let removed = prepare
            .split_once("table_id >= ladder->nr_mask_tables")
            .and_then(|(_, body)| body.split_once("continue;"))
            .map(|(body, _)| body)
            .expect("removed mask-table slots should be cleared before continuing");
        assert_text_order(
            removed,
            &[
                "bpf_kptr_xchg(&mask_slot->mask, NULL)",
                "if (stale)",
                "bpf_cpumask_release(stale)",
            ],
        );

        let rust = fs::read_to_string(manifest.join("src/main.rs")).unwrap();
        let clear = rust
            .split_once("fn clear_mask_table_data(")
            .and_then(|(_, rest)| rest.split_once("fn set_active_ladder("))
            .map(|(body, _)| body)
            .expect("clear_mask_table_data should precede set_active_ladder");
        assert!(clear.contains("for table_id in 0..bpf_intf::SNAKE_MAX_MASK_TABLES"));
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
    fn rung_timing_accumulator_uses_each_ladders_abi_limit() {
        let mut accumulator = RungTimingAccumulator::default();
        accumulator.record(
            7,
            bpf_intf::snake_rung_ladder_SNAKE_RUNG_LADDER_ENQUEUE,
            bpf_intf::SNAKE_MAX_QUEUE_RUNGS,
            40,
        );

        let timing = accumulator.generation(7).expect("timing should aggregate");

        assert_eq!(
            timing.len(),
            (bpf_intf::SNAKE_MAX_RUNGS + 2 * bpf_intf::SNAKE_MAX_QUEUE_RUNGS) as usize
        );
        assert!(!timing.contains_key(&format!("enqueue:{}", bpf_intf::SNAKE_MAX_QUEUE_RUNGS)));
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
        fn assert_field_type<T, F>(_field: fn(&T) -> &F) {}

        let policy = policy::compile_policy(policy_source()).expect("policy should compile");
        let encoded = encode_ladder(&policy, 42).expect("ladder should encode");

        assert_eq!(bpf_intf::SNAKE_ABI_VERSION, 30);
        assert_eq!(bpf_intf::SNAKE_MAX_RUNGS, 16);
        assert_eq!(bpf_intf::snake_stat_SNAKE_STAT_VTIME_CLOCK_CAS_RETRIES, 212);
        assert_eq!(
            bpf_intf::snake_stat_SNAKE_STAT_VTIME_CLOCK_CAS_EXHAUSTIONS,
            213
        );
        assert_eq!(bpf_intf::snake_stat_SNAKE_NR_STATS, 214);
        assert_eq!(size_of::<bpf_intf::snake_callback_timing>(), 520);
        assert_eq!(offset_of!(bpf_intf::snake_callback_timing, total_ns), 0);
        assert_eq!(offset_of!(bpf_intf::snake_callback_timing, buckets), 8);
        assert_field_type::<bpf_intf::snake_callback_timing, u64>(|value| &value.total_ns);
        assert_field_type::<
            bpf_intf::snake_callback_timing,
            [u64; bpf_intf::SNAKE_CALLBACK_TIMING_BUCKETS as usize],
        >(|value| &value.buckets);
        assert_eq!(size_of::<bpf_intf::snake_rung_timing_event>(), 24);
        assert_eq!(offset_of!(bpf_intf::snake_rung_timing_event, generation), 0);
        assert_eq!(offset_of!(bpf_intf::snake_rung_timing_event, elapsed_ns), 8);
        assert_eq!(offset_of!(bpf_intf::snake_rung_timing_event, ladder), 16);
        assert_eq!(offset_of!(bpf_intf::snake_rung_timing_event, rung), 20);
        assert_field_type::<bpf_intf::snake_rung_timing_event, u64>(|value| &value.generation);
        assert_field_type::<bpf_intf::snake_rung_timing_event, u64>(|value| &value.elapsed_ns);
        assert_field_type::<bpf_intf::snake_rung_timing_event, u32>(|value| &value.ladder);
        assert_field_type::<bpf_intf::snake_rung_timing_event, u32>(|value| &value.rung);
        assert_eq!(size_of::<bpf_intf::snake_fine_timing_config>(), 64);
        assert_eq!(
            offset_of!(bpf_intf::snake_fine_timing_config, session_ids),
            0
        );
        assert_eq!(
            offset_of!(bpf_intf::snake_fine_timing_config, enabled_mask),
            56
        );
        assert_eq!(offset_of!(bpf_intf::snake_fine_timing_config, reserved), 60);
        assert_field_type::<
            bpf_intf::snake_fine_timing_config,
            [u64; bpf_intf::snake_fine_timing_callback_SNAKE_NR_FINE_TIMING_CALLBACKS as usize],
        >(|value| &value.session_ids);
        assert_field_type::<bpf_intf::snake_fine_timing_config, u32>(|value| &value.enabled_mask);
        assert_field_type::<bpf_intf::snake_fine_timing_config, u32>(|value| &value.reserved);
        assert_eq!(size_of::<bpf_intf::snake_fine_timing_event>(), 48);
        assert_eq!(offset_of!(bpf_intf::snake_fine_timing_event, session_id), 0);
        assert_eq!(offset_of!(bpf_intf::snake_fine_timing_event, elapsed_ns), 8);
        assert_eq!(
            offset_of!(bpf_intf::snake_fine_timing_event, source_dsq_id),
            16
        );
        assert_eq!(
            offset_of!(bpf_intf::snake_fine_timing_event, target_dsq_id),
            24
        );
        assert_eq!(offset_of!(bpf_intf::snake_fine_timing_event, stage), 32);
        assert_eq!(offset_of!(bpf_intf::snake_fine_timing_event, operation), 36);
        assert_eq!(offset_of!(bpf_intf::snake_fine_timing_event, outcome), 40);
        assert_eq!(
            offset_of!(bpf_intf::snake_fine_timing_event, queue_class),
            44
        );
        assert_field_type::<bpf_intf::snake_fine_timing_event, u64>(|value| &value.session_id);
        assert_field_type::<bpf_intf::snake_fine_timing_event, u64>(|value| &value.elapsed_ns);
        assert_field_type::<bpf_intf::snake_fine_timing_event, u64>(|value| &value.source_dsq_id);
        assert_field_type::<bpf_intf::snake_fine_timing_event, u64>(|value| &value.target_dsq_id);
        assert_field_type::<bpf_intf::snake_fine_timing_event, u32>(|value| &value.stage);
        assert_field_type::<bpf_intf::snake_fine_timing_event, u32>(|value| &value.operation);
        assert_field_type::<bpf_intf::snake_fine_timing_event, u32>(|value| &value.outcome);
        assert_field_type::<bpf_intf::snake_fine_timing_event, u32>(|value| &value.queue_class);
        assert_eq!(size_of::<bpf_intf::snake_queue_timing_counters>(), 24);
        assert_eq!(
            offset_of!(bpf_intf::snake_queue_timing_counters, started_samples),
            0
        );
        assert_eq!(
            offset_of!(bpf_intf::snake_queue_timing_counters, completed_samples),
            8
        );
        assert_eq!(
            offset_of!(bpf_intf::snake_queue_timing_counters, dropped_samples),
            16
        );
        assert_field_type::<bpf_intf::snake_queue_timing_counters, u64>(|value| {
            &value.started_samples
        });
        assert_field_type::<bpf_intf::snake_queue_timing_counters, u64>(|value| {
            &value.completed_samples
        });
        assert_field_type::<bpf_intf::snake_queue_timing_counters, u64>(|value| {
            &value.dropped_samples
        });
        assert_eq!(size_of::<bpf_intf::snake_queue_timing_event>(), 40);
        assert_eq!(
            offset_of!(bpf_intf::snake_queue_timing_event, session_id),
            0
        );
        assert_eq!(offset_of!(bpf_intf::snake_queue_timing_event, dsq_id), 8);
        assert_eq!(
            offset_of!(bpf_intf::snake_queue_timing_event, residence_ns),
            16
        );
        assert_eq!(
            offset_of!(bpf_intf::snake_queue_timing_event, cell_index),
            24
        );
        assert_eq!(
            offset_of!(bpf_intf::snake_queue_timing_event, queue_class),
            28
        );
        assert_eq!(
            offset_of!(bpf_intf::snake_queue_timing_event, depth_after_insert),
            32
        );
        assert_eq!(
            offset_of!(bpf_intf::snake_queue_timing_event, depth_after_dispatch),
            36
        );
        assert_field_type::<bpf_intf::snake_queue_timing_event, u64>(|value| &value.session_id);
        assert_field_type::<bpf_intf::snake_queue_timing_event, u64>(|value| &value.dsq_id);
        assert_field_type::<bpf_intf::snake_queue_timing_event, u64>(|value| &value.residence_ns);
        assert_field_type::<bpf_intf::snake_queue_timing_event, u32>(|value| &value.cell_index);
        assert_field_type::<bpf_intf::snake_queue_timing_event, u32>(|value| &value.queue_class);
        assert_field_type::<bpf_intf::snake_queue_timing_event, u32>(|value| {
            &value.depth_after_insert
        });
        assert_field_type::<bpf_intf::snake_queue_timing_event, u32>(|value| {
            &value.depth_after_dispatch
        });
        assert_eq!(size_of::<bpf_intf::snake_compiled_ladder>(), 800);
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
            408
        );
        assert_eq!(
            offset_of!(bpf_intf::snake_compiled_ladder, nr_dispatch_rungs),
            412
        );
        assert_eq!(
            offset_of!(bpf_intf::snake_compiled_ladder, enqueue_rungs),
            416
        );
        assert_eq!(
            offset_of!(bpf_intf::snake_compiled_ladder, dispatch_rungs),
            608
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
    fn encodes_explicit_mitosis_callback_ladders() {
        let policy = policy::compile_policy(
            r#"
[queues]
layout = "cell_llc"
direct_dispatch = true
enqueue = [
  { action = "try_direct", target = "cell" },
  { action = "try_insert", target = "cell" },
  { action = "insert", target = "cpu" },
]
dispatch = [
  { action = "peek", source = "cell" },
  { action = "peek", source = "cpu" },
  { action = "consume", operation = "min_vtime", fallback = ["cpu", "cell_sibling"] },
]

[[cell]]
id = 7
cpus = "0-3"

[[rung]]
operation = "pick_idle_prefer_previous"
scope = "task_cell"
"#,
        )
        .unwrap();
        let encoded = encode_ladder(&policy, 9).unwrap();

        assert_eq!(bpf_intf::SNAKE_ABI_VERSION, 30);
        assert_eq!(encoded.nr_enqueue_rungs, 3);
        assert_eq!(encoded.enqueue_rungs[0].opcode, 5);
        assert_eq!(encoded.enqueue_rungs[0].input, 4);
        assert_eq!(
            encoded.enqueue_rungs[0].flags,
            policy::QUEUE_RUNG_FLAG_DIRECT_DISPATCH
        );
        assert_eq!(encoded.enqueue_rungs[1].opcode, 1);
        assert_eq!(encoded.enqueue_rungs[1].input, 4);
        assert_eq!(encoded.enqueue_rungs[2].opcode, 6);
        assert_eq!(encoded.enqueue_rungs[2].input, 1);
        assert_eq!(encoded.nr_dispatch_rungs, 3);
        assert_eq!(encoded.dispatch_rungs[0].opcode, 4);
        assert_eq!(encoded.dispatch_rungs[0].input, 4);
        assert_eq!(encoded.dispatch_rungs[1].opcode, 4);
        assert_eq!(encoded.dispatch_rungs[1].input, 1);
        assert_eq!(encoded.dispatch_rungs[2].opcode, 5);
        assert_eq!(encoded.dispatch_rungs[2].input, 5);
        assert_eq!(encoded.dispatch_rungs[2].data, 1 | (4 << 8));
    }

    #[test]
    fn encodes_explicit_mitosis_drain_dispatch_and_steal_ladders() {
        let policy = policy::compile_policy(
            r#"
[queues]
layout = "cell_llc"
direct_dispatch = true
enqueue = [
  { action = "try_direct", target = "cell" },
  { action = "try_insert", target = "cell" },
  { action = "insert", target = "cpu" },
]
dispatch = [
  { action = "drain", source = "cell_orphan" },
  { action = "peek", source = "cell" },
  { action = "peek", source = "cpu" },
  { action = "consume", operation = "min_vtime", fallback = ["cpu"] },
  { action = "steal", source = "cell_sibling" },
]

[[cell]]
id = 7
cpus = "0-3"

[[rung]]
operation = "pick_idle_prefer_previous"
scope = "task_cell"
"#,
        )
        .unwrap();
        let encoded = encode_ladder(&policy, 10).unwrap();

        assert_eq!(bpf_intf::SNAKE_ABI_VERSION, 30);
        assert_eq!(encoded.nr_dispatch_rungs, 5);
        assert_eq!(
            encoded
                .dispatch_rungs
                .iter()
                .take(5)
                .map(|rung| (rung.opcode, rung.input, rung.data))
                .collect::<Vec<_>>(),
            vec![(6, 6, 0), (4, 4, 0), (4, 1, 0), (5, 5, 1), (7, 7, 0),]
        );
    }

    #[test]
    fn encodes_global_llc_queue_rungs_and_fallback_order() {
        let policy = policy::compile_policy(
            r#"
[queues]
layout = "llc"

[[rung]]
operation = "pick_idle"
scope = "task_allowed"
"#,
        )
        .unwrap();
        let encoded = encode_ladder(&policy, 9).unwrap();

        assert_eq!(size_of::<bpf_intf::snake_queue_rung>(), 24);
        assert_eq!(encoded.nr_enqueue_rungs, 2);
        assert_eq!(encoded.enqueue_rungs[0].opcode, 3);
        assert_eq!(encoded.enqueue_rungs[0].input, 2);
        assert_eq!(encoded.enqueue_rungs[1].opcode, 4);
        assert_eq!(encoded.enqueue_rungs[1].input, 1);
        assert_eq!(encoded.nr_dispatch_rungs, 4);
        assert_eq!(
            encoded
                .dispatch_rungs
                .iter()
                .take(3)
                .map(|rung| (rung.opcode, rung.input))
                .collect::<Vec<_>>(),
            vec![(4, 1), (4, 2), (4, 3)]
        );
        assert_eq!(encoded.dispatch_rungs[3].opcode, 5);
        assert_eq!(encoded.dispatch_rungs[3].input, 5);
        assert_eq!(encoded.dispatch_rungs[3].data, 0x0003_0201);
        assert!(encoded.enqueue_rungs.iter().all(|rung| rung.reserved == 0));
        assert!(encoded.dispatch_rungs.iter().all(|rung| rung.reserved == 0));
    }

    #[test]
    fn encodes_and_executes_opt_in_llc_direct_dispatch() {
        let policy = policy::compile_policy(
            r#"
[queues]
layout = "llc"
direct_dispatch = true

[[rung]]
operation = "pick_idle"
scope = "task_allowed"
"#,
        )
        .expect("direct-dispatch LLC policy should compile");
        let encoded = encode_ladder(&policy, 10).unwrap();
        assert_eq!(encoded.enqueue_rungs[0].flags, 1);

        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let main = fs::read_to_string(bpf_dir.join("main.bpf.c")).unwrap();
        let queue_ladder = fs::read_to_string(bpf_dir.join("queue_ladder.h")).unwrap();
        let select = main
            .split_once("static __noinline s32 snake_select_cpu_impl(")
            .and_then(|(_, body)| body.split_once("s32 BPF_STRUCT_OPS(snake_select_cpu,"))
            .map(|(body, _)| body)
            .unwrap();

        assert!(queue_ladder.contains("queue_direct_dispatch_enabled("));
        assert_text_order(
            select,
            &[
                "queue_direct_dispatch_enabled(&ladder_ctx)",
                "queue_fairness_select_cpu(",
                "dsq_insert_local_on(",
            ],
        );
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
        let mut policy = policy::compile_policy(
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
        policy.cell_slot_epochs.insert(7, 42);
        let topology = queue_topology::resolve_queue_topology(
            &policy,
            &std::collections::BTreeSet::from([0, 1, 2, 3]),
            &BTreeMap::from([(0, 10), (1, 10), (2, 20), (3, 20)]),
        )
        .unwrap()
        .unwrap();
        let encoded = encode_queue_topology(&topology, 7).unwrap();

        assert_eq!(encoded.header.mode, bpf_intf::SNAKE_QUEUE_MODE_CELL);
        assert_eq!(encoded.header.nr_cells, 2);
        assert_eq!(encoded.header.nr_cpus, 4);
        assert_eq!(
            encoded.header.nr_normal_dsqs,
            bpf_intf::SNAKE_MAX_QUEUE_CELLS * 2
        );
        assert_eq!(encoded.cell_lookup[0], 1);
        assert_eq!(encoded.cell_lookup[7], 2);
        assert_eq!(encoded.cells[0].external_id, 0);
        assert_eq!(encoded.cells[0].slot_epoch, 0);
        assert_eq!(encoded.cells[1].external_id, 7);
        assert_eq!(encoded.cells[1].slot_epoch, 42);
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

        let one_cell_policy = policy::compile_policy(
            r#"
[queues]
layout = "cell_llc"
[[rung]]
operation = "pick_idle"
scope = "task_cell"
"#,
        )
        .unwrap();
        let one_cell_topology = queue_topology::resolve_queue_topology(
            &one_cell_policy,
            &std::collections::BTreeSet::from([0, 1, 2, 3]),
            &BTreeMap::from([(0, 10), (1, 10), (2, 20), (3, 20)]),
        )
        .unwrap()
        .unwrap();
        let one_cell_encoded = encode_queue_topology(&one_cell_topology, 8).unwrap();
        assert_eq!(
            one_cell_encoded.header.nr_normal_dsqs,
            encoded.header.nr_normal_dsqs
        );
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
        let encoded = encode_queue_topology(&topology, 7).unwrap();

        assert_eq!(encoded.header.nr_cpus, 2);
        assert_eq!(
            encoded.header.nr_normal_dsqs,
            bpf_intf::SNAKE_MAX_QUEUE_CELLS
        );
        assert_eq!(encoded.cpu_queues[0].valid, 0);
        assert_eq!(encoded.cpu_queues[1].valid, 1);
        assert_eq!(encoded.cpu_queues[2].valid, 0);
        assert_eq!(encoded.cpu_queues[3].valid, 1);
    }

    #[test]
    fn global_llc_topology_encoding_has_no_synthetic_cells() {
        let policy = policy::compile_policy(
            r#"
[queues]
layout = "llc"
[[rung]]
operation = "pick_idle"
scope = "task_allowed"
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
        let encoded = encode_queue_topology(&topology, 7).unwrap();

        assert_eq!(encoded.header.mode, bpf_intf::SNAKE_QUEUE_MODE_GLOBAL);
        assert_eq!(encoded.header.nr_cells, 0);
        assert_eq!(encoded.header.nr_normal_queues, 2);
        assert_eq!(encoded.header.nr_normal_dsqs, 2);
        assert!(encoded.cell_lookup.iter().all(|value| *value == 0));
        assert_eq!(encoded.normal_queues[0].cell_index, u32::MAX);
        assert_eq!(encoded.normal_queues[0].clock_index, u32::MAX);
        assert_eq!(encoded.normal_queues[0].consumers.valid, 1);
        assert_eq!(encoded.cpu_queues[0].owner_cell_index, u32::MAX);
        assert_eq!(encoded.cpu_queues[0].normal_queue_index, 0);
        assert_eq!(encoded.cpu_queues[2].normal_queue_index, 1);
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
    fn rust_previous_whole_core_claim_matches_the_bpf_abi() {
        let compiled = policy::compile_policy(
            r#"
[[rung]]
operation = "claim_idle_core"
scope = "previous_cpu"
"#,
        )
        .expect("policy should compile");
        let encoded = encode_rung(compiled.rungs[0]);

        assert_eq!(encoded.opcode, bpf_intf::snake_opcode_SNAKE_OP_CLAIM_IDLE);
        assert_eq!(
            encoded.input,
            bpf_intf::snake_input_source_SNAKE_INPUT_CPU_PREV
        );
        assert_eq!(encoded.flags, bpf_intf::SNAKE_RUNG_F_PICK_IDLE_CORE);
        assert_eq!(operation_label(&compiled.rungs[0]), "claim_idle_core");

        let ladder =
            fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf/ladder.h"))
                .unwrap();
        let claim = ladder
            .split_once("case SNAKE_OP_CLAIM_IDLE:")
            .and_then(|(_, body)| body.split_once("case SNAKE_OP_PICK_IDLE:"))
            .map(|(body, _)| body)
            .unwrap();
        assert_text_order(
            claim,
            &[
                "scx_bpf_get_idle_smtmask()",
                "bpf_cpumask_test_cpu(prev_cpu, idle)",
                "scx_bpf_put_idle_cpumask(idle)",
                "scx_bpf_test_and_clear_cpu_idle(prev_cpu)",
            ],
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
        assert_eq!(size_of::<bpf_intf::snake_task_cell>(), 24);
        assert_eq!(offset_of!(bpf_intf::snake_task_cell, cell_id), 0);
        assert_eq!(offset_of!(bpf_intf::snake_task_cell, cell_epoch), 4);
        assert_eq!(offset_of!(bpf_intf::snake_task_cell, managed_cell_id), 12);
        assert_eq!(
            offset_of!(bpf_intf::snake_task_cell, managed_cell_epoch),
            16
        );
        assert_eq!(policy::MAX_CELL_IDS, bpf_intf::SNAKE_MAX_CPUS);
    }

    #[test]
    fn queue_task_mapping_validates_the_annotated_slot_epoch() {
        let queue =
            fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf/queue.h"))
                .unwrap();
        let resolver = queue
            .split_once(
                "queue_task_cell(const struct snake_ladder_ctx *ctx, struct task_struct *p,",
            )
            .and_then(|(_, body)| body.split_once("queue_task_cell_index("))
            .map(|(body, _)| body)
            .expect("task-cell resolver should have one definition");

        assert!(resolver.contains("READ_ONCE(annotation->cell_epoch)"));
        assert!(resolver.contains("READ_ONCE(cell->slot_epoch)"));
    }

    #[test]
    fn task_cell_placement_and_rehome_clearing_validate_slot_epochs() {
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let ladder = fs::read_to_string(bpf_dir.join("ladder.h")).unwrap();
        let vtime = fs::read_to_string(bpf_dir.join("queue_vtime.h")).unwrap();
        let clear = vtime
            .split_once("queue_clear_rehome_if_cell(")
            .and_then(|(_, body)| body.split_once("queue_fairness_prepare_task_for_cell("))
            .map(|(body, _)| body)
            .expect("queue rehome clearer should have one definition");

        assert_eq!(ladder.matches("queue_task_cell_id(").count(), 2);
        assert!(clear.contains("READ_ONCE(annotation->cell_epoch)"));
        assert!(clear.contains("READ_ONCE(cell->slot_epoch)"));
    }

    #[test]
    fn queue_runtime_rebases_vtime_when_a_cell_slot_is_rebound() {
        let intf = include_str!("bpf/intf.h");
        let task_state = include_str!("bpf/task_state.h");
        let queue_vtime = include_str!("bpf/queue_vtime.h");

        assert!(intf.contains("u64 topology_generation;"));
        assert!(task_state.contains("topology_generation;"));
        assert!(task_state.contains("cell_external_id;"));
        assert!(task_state.contains("cell_epoch;"));
        assert!(queue_vtime.contains("runtime->cell_external_id != external_id"));
        assert!(queue_vtime.contains("runtime->cell_epoch != slot_epoch"));
        assert!(queue_vtime.contains("runtime->vruntime = new_now;"));
    }

    #[test]
    fn queue_runtime_accounts_foreign_affinity_to_the_cpu_owner() {
        let queue_vtime = include_str!("bpf/queue_vtime.h");
        let stopping = queue_vtime
            .split_once("static __always_inline int queue_fairness_stopping(")
            .and_then(|(_, body)| body.split_once("#endif"))
            .map(|(body, _)| body)
            .expect("queue stopping should have one definition");
        let foreign = stopping
            .split_once("if (runtime->run_cell_index == runtime->run_owner_cell_index)")
            .map(|(_, body)| body)
            .expect("foreign runtime accounting should be bounded");

        let affinity = foreign
            .split_once("runtime->run_queue_class == SNAKE_QUEUE_CLASS_AFFINITY")
            .map(|(_, body)| body)
            .expect("foreign affinity accounting should be conditional");
        assert!(affinity.contains("runtime->run_owner_cell_index"));
        assert!(affinity.contains("SNAKE_CELL_STAT_FOREIGN_AFFINITY_RUNTIME_NS"));
        assert_eq!(
            stopping
                .matches("SNAKE_CELL_STAT_FOREIGN_AFFINITY_RUNTIME_NS")
                .count(),
            1
        );
    }

    #[test]
    fn mitosis_preferred_idle_rung_uses_the_kernel_style_claim_order() {
        let intf = include_str!("bpf/intf.h");
        let cpu_pick = include_str!("bpf/cpu_pick.h");
        let ladder = include_str!("bpf/ladder.h");

        assert!(intf.contains("#define SNAKE_ABI_VERSION 30"));
        assert!(intf.contains("SNAKE_OP_PICK_IDLE_PREFER_PREVIOUS = 8"));
        assert!(intf.contains("SNAKE_INPUT_TASK_ALLOWED_RESTRICTED = 5"));
        assert!(intf.contains("SNAKE_QUEUE_MASK_LOCAL_LLC"));

        let helper = cpu_pick
            .split_once("cpu_pick_idle_prefer_previous(")
            .and_then(|(_, body)| body.split_once("#endif"))
            .map(|(body, _)| body)
            .expect("preferred idle helper should exist");
        let previous_core = helper
            .find("whole_core_idle && scx_bpf_test_and_clear_cpu_idle(prev_cpu)")
            .expect("previous whole-idle core should be first");
        let any_core = helper
            .find("scx_bpf_pick_idle_cpu(candidates, SCX_PICK_IDLE_CORE)")
            .expect("any whole-idle core should be second");
        let previous_thread = helper
            .rfind("scx_bpf_test_and_clear_cpu_idle(prev_cpu)")
            .expect("previous idle CPU should be third");
        let any_thread = helper
            .find("scx_bpf_pick_idle_cpu(candidates, 0)")
            .expect("any idle CPU should be last");
        assert!(previous_core < any_core);
        assert!(any_core < previous_thread);
        assert!(previous_thread < any_thread);

        assert!(ladder.contains("case SNAKE_OP_PICK_IDLE_PREFER_PREVIOUS:"));
        assert!(ladder.contains("SNAKE_QUEUE_MASK_LOCAL_LLC"));
        assert!(ladder.contains("SNAKE_INPUT_TASK_ALLOWED_RESTRICTED"));
    }

    #[test]
    fn cell_direct_dispatch_preserves_normal_borrowed_and_affinity_routes() {
        let main = include_str!("bpf/main.bpf.c");
        let queue_ladder = include_str!("bpf/queue_ladder.h");
        let enqueue = include_str!("bpf/queue_enqueue.h");
        let normalized_enqueue = enqueue.split_whitespace().collect::<Vec<_>>().join(" ");

        assert!(!queue_ladder.contains("!queue_global_mode_enabled()"));
        assert!(main.contains("SNAKE_SELECT_F_AFFINITY"));
        assert!(main.contains("queue_fairness_direct_primary("));
        assert!(main.contains("queue_fairness_direct_affinity("));
        assert!(enqueue.contains("queue_fairness_direct_primary("));
        assert!(enqueue.contains("queue_fairness_direct_borrow("));
        assert!(enqueue.contains("queue_fairness_direct_affinity("));
        assert!(enqueue.contains("SNAKE_QUEUE_CLASS_NORMAL"));
        assert!(enqueue.contains("SNAKE_QUEUE_MASK_PRIMARY"));
        assert!(enqueue.contains("SNAKE_QUEUE_MASK_BORROWABLE"));
        assert!(enqueue.contains("SNAKE_QUEUE_CLASS_AFFINITY"));
        for helper in [
            "queue_fairness_direct_primary",
            "queue_fairness_direct_borrow",
            "queue_fairness_direct_affinity",
        ] {
            assert!(normalized_enqueue.contains(&format!("static __noinline int {helper}(")));
        }
    }

    #[test]
    fn mitosis_cell_enqueue_retries_idle_placement_when_select_was_skipped() {
        let scheduler_mode = include_str!("bpf/scheduler_mode.h");
        let normalized_mode = scheduler_mode
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");

        assert!(normalized_mode
            .contains("static __always_inline int queue_try_direct_from_enqueue_impl("));
        assert!(normalized_mode
            .contains("static __noinline int queue_try_direct_from_enqueue_generic("));
        assert!(normalized_mode
            .contains("static __noinline int queue_try_direct_from_enqueue_expanded("));

        let retry = scheduler_mode
            .split_once("queue_try_direct_from_enqueue_impl(")
            .and_then(|(_, body)| body.split_once("queue_try_direct_from_enqueue_generic("))
            .map(|(body, _)| body)
            .expect("cell enqueue should have one direct-placement retry helper");
        assert!(retry.contains("__COMPAT_is_enq_cpu_selected(enq_flags)"));
        assert!(retry.contains("walk_expanded_mitosis_ladder(ctx, p, &walk_args)"));
        assert!(retry.contains("walk_generic_policy_ladder_from_enqueue("));
        assert!(retry.contains("queue_fairness_direct_primary("));
        assert!(retry.contains("queue_fairness_direct_borrow("));
        assert!(retry.contains("queue_fairness_direct_affinity("));
        assert!(retry.contains("scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE)"));
        let restriction_check = retry
            .find("queue_task_cell_affinity_restricted(")
            .expect("enqueue retry should classify restricted work before selecting a CPU");
        let expanded_walk = retry
            .find("walk_expanded_mitosis_ladder(ctx, p, &walk_args)")
            .expect("expanded enqueue retry should walk unrestricted placement");
        assert!(restriction_check < expanded_walk);

        let generic_enqueue = scheduler_mode
            .split_once("scheduler_mode_enqueue_generic(")
            .and_then(|(_, body)| body.split_once("scheduler_mode_enqueue_expanded("))
            .map(|(body, _)| body)
            .expect("generic scheduler mode enqueue should exist");
        assert!(generic_enqueue.contains("queue_try_direct_from_enqueue_generic("));
        let expanded_enqueue = scheduler_mode
            .split_once("scheduler_mode_enqueue_expanded(")
            .and_then(|(_, body)| body.split_once("scheduler_mode_dispatch("))
            .map(|(body, _)| body)
            .expect("expanded scheduler mode enqueue should exist");
        assert!(expanded_enqueue.contains("queue_try_direct_from_enqueue_expanded("));
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
        let policy =
            policy::compile_policy(&format!("[queues]\nlayout = \"llc\"\n{}", policy_source()))
                .expect("policy should compile");
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
        set_stat(
            &mut raw,
            bpf_intf::snake_stat_SNAKE_STAT_DISPATCH_CALLS,
            &[9, 11],
        );
        set_stat(
            &mut raw,
            bpf_intf::snake_stat_SNAKE_STAT_ENQUEUE_RUNG_ATTEMPT_BASE,
            &[4, 6],
        );
        set_stat(
            &mut raw,
            bpf_intf::snake_stat_SNAKE_STAT_ENQUEUE_RUNG_HIT_BASE,
            &[3, 5],
        );
        set_stat(
            &mut raw,
            bpf_intf::snake_stat_SNAKE_STAT_DISPATCH_RUNG_SELECTED_BASE + 1,
            &[2, 4],
        );
        set_stat(
            &mut raw,
            bpf_intf::snake_stat_SNAKE_STAT_DISPATCH_RUNG_MOVE_MISS_BASE + 3,
            &[1, 2],
        );
        set_stat(
            &mut raw,
            bpf_intf::snake_stat_SNAKE_STAT_DISPATCH_RUNG_FALLBACK_HIT_BASE + 2,
            &[5, 7],
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
        let serialized = serde_json::to_value(&metrics).unwrap();
        assert_eq!(serialized["dispatch_calls"], 20);
        assert_eq!(serialized["enqueue_rungs"]["0"]["attempts"], 10);
        assert_eq!(serialized["enqueue_rungs"]["0"]["hits"], 8);
        assert_eq!(serialized["dispatch_rungs"]["1"]["selected"], 6);
        assert_eq!(serialized["dispatch_rungs"]["3"]["move_misses"], 3);
        assert_eq!(serialized["dispatch_rungs"]["2"]["fallback_hits"], 12);
    }

    #[test]
    fn aggregates_cell_runtime_without_discarding_cpu_attribution() {
        let topology = queue_topology::QueueTopology {
            layout: policy::QueueLayout::Cell,
            nr_clock_domains: 1,
            cells: vec![queue_topology::QueueCell {
                index: 0,
                external_id: 7,
                slot_epoch: 9,
                cpu_weight: 100,
                primary: BTreeSet::from([0, 2]),
                borrowable: BTreeSet::new(),
                normal_queues: vec![],
            }],
            cell_index_by_id: BTreeMap::from([(7, 0)]),
            normal_queues: vec![],
            cpu_queues: BTreeMap::new(),
        };
        let mut raw = raw_percpu_cell_stats(1, 3);
        set_stat(
            &mut raw,
            bpf_intf::snake_cell_stat_SNAKE_CELL_STAT_RUNTIME_NS,
            &[2_500, 0, 7_500],
        );
        set_stat(
            &mut raw,
            bpf_intf::snake_cell_stat_SNAKE_CELL_STAT_FOREIGN_AFFINITY_RUNTIME_NS,
            &[0, 400, 0],
        );

        let cells = aggregate_raw_cell_stats(&raw, &topology).unwrap();

        assert_eq!(cells[&7].slot_epoch, 9);
        assert_eq!(cells[&7].runtime_ns, 10_000);
        assert_eq!(cells[&7].foreign_affinity_runtime_ns, 400);
        assert_eq!(
            cells[&7].runtime_ns_by_cpu,
            BTreeMap::from([(0, 2_500), (2, 7_500)])
        );
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
        let select = state.start(FineTimingCallback::SelectCpu, 7, 64, 900);
        let enqueue = state.start(FineTimingCallback::Enqueue, 7, 64, 1_000);
        let dispatch = state.start(FineTimingCallback::Dispatch, 7, 64, 1_100);

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
    fn fine_timing_accumulator_tracks_every_callback_session() {
        use crate::fine_timing::{stages, FineTimingCallback};

        let mut accumulator = FineTimingAccumulator::default();
        for callback in FineTimingCallback::ALL {
            let session_id = callback.index() as u64 + 1;
            accumulator.reset(callback, session_id);
            accumulator.record(session_id, stages(callback)[0].id, 512);
        }

        for callback in FineTimingCallback::ALL {
            let session_id = callback.index() as u64 + 1;
            assert_eq!(
                accumulator
                    .metrics(session_id, stages(callback)[0].id)
                    .buckets
                    .iter()
                    .sum::<u64>(),
                1
            );
        }
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
        let transfers = accumulator
            .lock()
            .expect("accumulator should lock")
            .dsq_transfers(17);
        assert_eq!(transfers.len(), 1);
        assert_eq!(
            transfers[0].source_dsq_id,
            u64::from(bpf_intf::SNAKE_FIFO_DSQ)
        );
        assert_eq!(transfers[0].target_dsq_id, 13_835_058_055_282_163_719);
        assert_eq!(transfers[0].samples, 1);
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
    fn fine_timing_accumulator_records_untimed_transfer_pairs_only() {
        use crate::fine_timing::FineTimingCallback;

        let accumulator = Mutex::new(FineTimingAccumulator::default());
        accumulator
            .lock()
            .expect("accumulator should lock")
            .reset(FineTimingCallback::Dispatch, 19);
        let event = bpf_intf::snake_fine_timing_event {
            session_id: 19,
            elapsed_ns: 0,
            source_dsq_id: u64::from(bpf_intf::SNAKE_FIFO_DSQ),
            target_dsq_id: 13_835_058_055_282_163_720,
            stage: 0,
            operation: bpf_intf::snake_dsq_operation_SNAKE_DSQ_OP_TRANSFER,
            outcome: bpf_intf::snake_dsq_outcome_SNAKE_DSQ_OUTCOME_SUCCESS,
            queue_class: bpf_intf::SNAKE_QUEUE_CLASS_NORMAL,
        };
        assert_eq!(relay_fine_timing(bytes_of(&event), &accumulator), 0);

        let accumulator = accumulator.lock().expect("accumulator should lock");
        assert!(accumulator.dsq_operations(19).is_empty());
        let transfers = accumulator.dsq_transfers(19);
        assert_eq!(transfers.len(), 1);
        assert_eq!(
            transfers[0].source_dsq_id,
            u64::from(bpf_intf::SNAKE_FIFO_DSQ)
        );
        assert_eq!(transfers[0].target_dsq_id, 13_835_058_055_282_163_720);
        assert_eq!(transfers[0].samples, 1);
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
        assert!(names(select).contains(&"cell_clock_read"));
        assert!(names(select).contains(&"finish"));
        assert!(names(enqueue).contains(&"prepare_route_lookup"));
        assert!(names(enqueue).contains(&"prepare_task_storage"));
        assert!(names(enqueue).contains(&"prepare_cell_clock"));
        assert!(names(enqueue).contains(&"prepare_credit_clamp"));
        assert!(names(enqueue).contains(&"cell_clock_read"));
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
        let remaining = [
            FineTimingCallback::Runnable,
            FineTimingCallback::Running,
            FineTimingCallback::Stopping,
            FineTimingCallback::Quiescent,
        ];
        assert_eq!(
            select.len()
                + enqueue.len()
                + dispatch.len()
                + remaining
                    .into_iter()
                    .map(|callback| stages(callback).len())
                    .sum::<usize>(),
            bpf_intf::snake_fine_timing_stage_SNAKE_NR_FINE_TIMING_STAGES as usize
        );
    }

    #[test]
    fn remaining_coarse_timed_callbacks_emit_fine_timing_stages() {
        let bpf_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/bpf");
        let callbacks = fs::read_to_string(bpf_dir.join("main.bpf.c")).unwrap();
        let modes = fs::read_to_string(bpf_dir.join("scheduler_mode.h")).unwrap();
        let instrumented = format!("{callbacks}\n{modes}");

        for callback in ["RUNNABLE", "RUNNING", "STOPPING", "QUIESCENT"] {
            assert!(callbacks.contains(&format!(
                "fine_timing_begin(SNAKE_FINE_TIMING_CALLBACK_{callback}"
            )));
            assert!(callbacks.contains(&format!("SNAKE_FINE_TIMING_{callback}_ACQUIRE_LADDER")));
            assert!(callbacks.contains(&format!("SNAKE_FINE_TIMING_{callback}_FINISH")));
        }
        for stage in [
            "SNAKE_FINE_TIMING_RUNNABLE_RUNNABLE_STATE",
            "SNAKE_FINE_TIMING_RUNNING_MEMBERSHIP_ACCOUNT",
            "SNAKE_FINE_TIMING_RUNNING_RUN_STATE",
            "SNAKE_FINE_TIMING_STOPPING_RUN_STATE",
            "SNAKE_FINE_TIMING_STOPPING_RUNTIME_STAT",
            "SNAKE_FINE_TIMING_QUIESCENT_QUEUE_TIMING_CANCEL",
            "SNAKE_FINE_TIMING_QUIESCENT_DIRECT_CANCEL",
            "SNAKE_FINE_TIMING_QUIESCENT_FAIRNESS_STATE",
        ] {
            assert!(instrumented.contains(stage), "missing timing stage {stage}");
        }
    }
}
