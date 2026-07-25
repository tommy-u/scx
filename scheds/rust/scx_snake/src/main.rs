// SPDX-License-Identifier: GPL-2.0-only

mod bpf_intf;
mod bpf_skel;
mod control;
mod mask_tables;
mod policy;
mod runtime_policy;
mod stats;

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::mem::{size_of, MaybeUninit};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use bpf_skel::*;
use clap::{Parser, ValueEnum};
use control::{SchedulerRequest, SchedulerResponse};
use crossbeam::channel::RecvTimeoutError;
use libbpf_rs::{MapCore as _, MapFlags, OpenObject, ProgramInput};
use log::{debug, info, warn};
use mask_tables::{dump_mask_tables, resolve_mask_tables, ResolvedMaskTable};
use policy::{CompiledPolicy, CompiledRung, InputSource, Opcode};
use runtime_policy::RuntimePolicy;
use scx_stats::prelude::*;
use scx_utils::build_id;
use scx_utils::libbpf_clap_opts::LibbpfOpts;
use scx_utils::{
    scx_ops_attach, scx_ops_load, scx_ops_open, try_set_rlimit_infinity, uei_exited, uei_report,
    UserExitInfo,
};
use stats::{Metrics, RungMetrics};

const SCHEDULER_NAME: &str = "scx_snake";
const SLOT_QUIESCENCE_TIMEOUT: Duration = Duration::from_secs(5);
const SLOT_QUIESCENCE_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
enum StatsFormat {
    #[default]
    Text,
    Json,
}

#[derive(Debug, Parser)]
#[command(name = SCHEDULER_NAME, version)]
struct Opts {
    /// TOML policy to compile and install before attaching the scheduler.
    #[arg(long, value_name = "PATH")]
    policy: Option<PathBuf>,

    /// Atomically replace the policy of the running scheduler.
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with_all = ["policy", "dump_compiled_policy", "stats", "monitor", "help_stats"]
    )]
    update_policy: Option<PathBuf>,

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

fn resolve_mode(opts: &Opts) -> Result<RunMode> {
    let special_modes = usize::from(opts.help_stats)
        + usize::from(opts.monitor.is_some())
        + usize::from(opts.update_policy.is_some())
        + usize::from(opts.dump_compiled_policy);
    if special_modes > 1 {
        bail!(
            "--help-stats, --monitor, --update-policy, and --dump-compiled-policy are mutually exclusive"
        );
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
    })
}

fn bytes_of<T>(value: &T) -> &[u8] {
    // SAFETY: map updates copy exactly size_of::<T>() bytes before this borrow ends.
    unsafe { std::slice::from_raw_parts(value as *const T as *const u8, std::mem::size_of::<T>()) }
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
    let zeroes = vec![0_u64.to_ne_bytes().to_vec(); libbpf_rs::num_possible_cpus()?];
    for stat in 0..bpf_intf::snake_stat_SNAKE_NR_STATS {
        let key = runtime_policy::stat_index(slot, stat)?;
        skel.maps
            .stats
            .update_percpu(&key.to_ne_bytes(), &zeroes, MapFlags::ANY)
            .with_context(|| format!("clearing ladder slot {slot} statistic {stat}"))?;
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
    if rung.flags & policy::RUNG_FLAG_PICK_IDLE_CORE != 0 {
        return "pick_idle_core";
    }

    match rung.opcode {
        Opcode::ClaimIdle => "claim_idle",
        Opcode::PickIdle | Opcode::PickIdleMaskTable => "pick_idle",
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
        (Opcode::PickIdleMaskTable, InputSource::CpuPrev) => {
            let table_id = u32::try_from(rung.data).context("mask table ID does not fit u32")?;
            policy
                .mask_tables
                .iter()
                .find(|table| table.id == table_id)
                .map(|table| table.name.as_str())
                .with_context(|| format!("compiled rung references missing mask table {table_id}"))
        }
        (_, InputSource::CpuPrev) => Ok("previous_cpu"),
        (_, InputSource::MaskTaskAllowed) => Ok("task_allowed"),
    }
}

fn decode_stat(raw: &[Vec<u8>], use_max: bool) -> Result<u64> {
    let values = raw
        .iter()
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
        .collect::<Result<Vec<_>>>()?;

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
        select_calls: value(bpf_intf::snake_stat_SNAKE_STAT_SELECT_CALLS),
        direct_dispatches: value(bpf_intf::snake_stat_SNAKE_STAT_DIRECT_DISPATCHES),
        ladder_exhaustions: value(bpf_intf::snake_stat_SNAKE_STAT_LADDER_EXHAUSTIONS),
        fallback_prev: value(bpf_intf::snake_stat_SNAKE_STAT_FALLBACK_PREV),
        fallback_any: value(bpf_intf::snake_stat_SNAKE_STAT_FALLBACK_ANY),
        invalid_errors: value(bpf_intf::snake_stat_SNAKE_STAT_INVALID_ERRORS),
        enqueues: value(bpf_intf::snake_stat_SNAKE_STAT_ENQUEUES),
        running: value(bpf_intf::snake_stat_SNAKE_STAT_RUNNING),
        stopping: value(bpf_intf::snake_stat_SNAKE_STAT_STOPPING),
        quiescent: value(bpf_intf::snake_stat_SNAKE_STAT_QUIESCENT),
        select_latency_ns: value(bpf_intf::snake_stat_SNAKE_STAT_SELECT_LATENCY_NS),
        select_latency_max_ns: value(bpf_intf::snake_stat_SNAKE_STAT_SELECT_LATENCY_MAX_NS),
        rungs,
    })
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

struct Scheduler<'object, 'policy> {
    skel: BpfSkel<'object>,
    struct_ops: Option<libbpf_rs::Link>,
    stats_server: StatsServer<SchedulerRequest, SchedulerResponse>,
    runtime: &'policy mut RuntimePolicy,
}

impl<'object, 'policy> Scheduler<'object, 'policy> {
    fn init(
        opts: &Opts,
        runtime: &'policy mut RuntimePolicy,
        mask_tables: &[ResolvedMaskTable],
        open_object: &'object mut MaybeUninit<OpenObject>,
    ) -> Result<Self> {
        try_set_rlimit_infinity();

        let mut builder = BpfSkelBuilder::default();
        builder.obj_builder.debug(opts.verbose);
        let open_opts = opts.libbpf.clone().into_bpf_open_opts();
        let mut skel = scx_ops_open!(builder, open_object, snake_ops, open_opts)?;
        skel.struct_ops.snake_ops_mut().exit_dump_len = opts.exit_dump_len;
        let mut skel = scx_ops_load!(skel, snake_ops, uei)?;
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
        let struct_ops = Some(scx_ops_attach!(skel, snake_ops)?);
        let stats_server = StatsServer::new(stats::server_data()).launch()?;
        info!(
            "attached {SCHEDULER_NAME} policy generation {} with {} rungs",
            runtime.generation,
            runtime.compiled.rungs.len()
        );

        Ok(Self {
            skel,
            struct_ops,
            stats_server,
            runtime,
        })
    }

    fn metrics(&self) -> Result<Metrics> {
        aggregate_raw_stats(
            &read_raw_stats(&self.skel, self.runtime.active_slot)?,
            &self.runtime.compiled,
            self.runtime.generation,
        )
    }

    fn replace_policy(&mut self, source: String) -> Result<runtime_policy::PolicyUpdateResponse> {
        let mut backend = BpfPolicyBackend {
            skel: &mut self.skel,
        };
        let response = runtime_policy::replace_policy(
            self.runtime,
            source,
            resolve_mask_tables,
            &mut backend,
        )?;
        info!(
            "activated policy generation {} ({})",
            response.generation, response.summary
        );
        Ok(response)
    }

    fn exited(&self) -> bool {
        uei_exited!(&self.skel, uei)
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let (response_channel, request_channel) = self.stats_server.channels();
        while !shutdown.load(Ordering::Relaxed) && !self.exited() {
            match request_channel.recv_timeout(Duration::from_secs(1)) {
                Ok(SchedulerRequest::Metrics) => {
                    response_channel.send(SchedulerResponse::Metrics(self.metrics()?))?
                }
                Ok(SchedulerRequest::ReplacePolicy { source }) => {
                    let response = self
                        .replace_policy(source)
                        .map_err(|error| format!("{error:#}"));
                    response_channel.send(SchedulerResponse::ReplacePolicy(response))?;
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    bail!("statistics server request channel disconnected")
                }
            }
        }

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
        RunMode::Dump(path) => {
            let (_, policy) = load_policy(&path)?;
            let mask_tables = resolve_mask_tables(&policy.mask_tables)?;
            print!("{}{}", policy.dump(), dump_mask_tables(&mask_tables));
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
                let mask_tables = resolve_mask_tables(&runtime.compiled.mask_tables)?;
                let exit_info = {
                    let mut scheduler =
                        Scheduler::init(&opts, &mut runtime, &mask_tables, &mut open_object)?;
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

    fn set_stat(raw: &mut [Vec<Vec<u8>>], index: u32, cpu_values: &[u64]) {
        raw[index as usize] = cpu_values
            .iter()
            .map(|value| value.to_ne_bytes().to_vec())
            .collect();
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

        assert_eq!(bpf_intf::SNAKE_ABI_VERSION, 7);
        assert_eq!(size_of::<bpf_intf::snake_compiled_ladder>(), 216);
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
            bpf_intf::snake_stat_SNAKE_STAT_RUNG_ATTEMPT_BASE,
            &[4, 6],
        );
        set_stat(
            &mut raw,
            bpf_intf::snake_stat_SNAKE_STAT_RUNG_HIT_BASE + 1,
            &[2, 3],
        );

        let metrics = aggregate_raw_stats(&raw, &policy, 42).expect("stats should aggregate");

        assert_eq!(metrics.policy_generation, 42);
        assert_eq!(metrics.select_calls, 18);
        assert_eq!(metrics.select_latency_ns, 350);
        assert_eq!(metrics.select_latency_max_ns, 900);
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

        let metrics =
            aggregate_raw_stats(&raw_percpu_stats(), &policy, 1).expect("stats should aggregate");

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

        let metrics =
            aggregate_raw_stats(&raw_percpu_stats(), &policy, 1).expect("stats should aggregate");

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

        let metrics =
            aggregate_raw_stats(&raw_percpu_stats(), &policy, 1).expect("stats should aggregate");

        assert_eq!(metrics.rungs[&0].operation, "pick_idle");
        assert_eq!(metrics.rungs[&0].scope, "previous_node");
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

        let metrics =
            aggregate_raw_stats(&raw_percpu_stats(), &policy, 1).expect("stats should aggregate");

        assert_eq!(metrics.rungs[&0].operation, "sync_wake_affine");
        assert_eq!(metrics.rungs[&0].scope, "task_allowed");
    }
}
