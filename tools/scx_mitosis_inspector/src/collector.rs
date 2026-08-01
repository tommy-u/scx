// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::HashSet;
use std::fs;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, OwnedFd};
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
use crate::{
    build_callback_timing_rows, build_counters, build_cpu_runtime_rows, build_scheduler_event_rows,
    build_timing_metric_row, program_name_matches, project_cpu_runtime, summarize_callback_timing,
    CallbackCounter, CallbackTimingCounters, CallbackTimingRow, CpuRuntimeRow, DsqMetricsView,
    MigrationRow, SchedulerEventRow, TimingMetricRow, CALLBACK_NAMES, CALLBACK_TIMING_BUCKETS,
    SCHEDULER_EVENT_NAMES,
};

const TARGET_NAMES: [&str; 5] = [
    "mitosis_select_cpu",
    "mitosis_enqueue",
    "mitosis_dispatch",
    "mitosis_running",
    "mitosis_stopping",
];

struct TargetProgram {
    id: u32,
    fd: OwnedFd,
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
    pub dsq_metrics: DsqMetricsView,
    pub scheduler_events: Vec<SchedulerEventRow>,
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
    callback_timing_sample_rate: u32,
    event_timing_sample_rate: u32,
) -> Result<(Vec<Link>, bool)> {
    let mut links = vec![
        skel.progs.observe_select_cpu.attach_trace()?,
        skel.progs.observe_enqueue.attach_trace()?,
        skel.progs.observe_dispatch.attach_trace()?,
        skel.progs.observe_running.attach_trace()?,
        skel.progs.observe_stopping.attach_trace()?,
        skel.progs.on_sched_migrate_task.attach()?,
        skel.progs.scheduler_event_switch.attach()?,
        skel.progs.scheduler_event_wakeup.attach()?,
        skel.progs.scheduler_event_wakeup_new.attach()?,
        skel.progs.scheduler_event_fork.attach()?,
        skel.progs.scheduler_event_exec.attach()?,
        skel.progs.scheduler_event_exit.attach()?,
    ];
    if callback_timing_sample_rate > 0 {
        links.extend([
            skel.progs.observe_select_cpu_exit.attach_trace()?,
            skel.progs.observe_enqueue_exit.attach_trace()?,
            skel.progs.observe_dispatch_exit.attach_trace()?,
            skel.progs.observe_running_exit.attach_trace()?,
            skel.progs.observe_stopping_exit.attach_trace()?,
        ]);
    }
    if event_timing_sample_rate > 0 {
        links.extend([
            skel.progs.on_sched_wakeup.attach()?,
            skel.progs.on_sched_wakeup_new.attach()?,
            skel.progs.on_sched_switch.attach()?,
        ]);
    }
    let dsq_available = attach_dsq_programs(skel, &mut links);
    Ok((links, dsq_available))
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
    callback_timing_sample_rate: u32,
    event_timing_sample_rate: u32,
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

    let mut open_object = MaybeUninit::<OpenObject>::uninit();
    let mut open_skel = BpfSkelBuilder::default()
        .open(&mut open_object)
        .context("opening callback collector BPF object")?;
    set_targets(&mut open_skel, &targets).context("setting callback attach targets")?;
    let rodata = open_skel
        .maps
        .rodata_data
        .as_mut()
        .context("callback collector rodata is unavailable")?;
    rodata.callback_timing_sample_rate = callback_timing_sample_rate;
    rodata.event_timing_sample_rate = event_timing_sample_rate;
    let skel = open_skel
        .load()
        .context("loading callback collector BPF object")?;
    let (_links, dsq_available) =
        attach_programs(&skel, callback_timing_sample_rate, event_timing_sample_rate)
            .context("attaching callback observer programs")?;

    let started = Instant::now();
    let mut previous = read_counts(&skel)?;
    let mut previous_scheduler_events = read_scheduler_events(&skel)?;
    let callback_timings = read_callback_timings(&skel)?;
    let wakeup_latency = read_wakeup_latency(&skel)?;
    let cpu_slice_duration = read_cpu_slice_duration(&skel)?;
    let blocked_duration = read_blocked_duration(&skel)?;
    let migrations = read_migrations(&skel)?;
    let mut previous_cpu_runtime = read_cpu_runtime(&skel)?;
    let bpf_program_stats = query_bpf_program_stats(&target_program_ids);
    let dsq_metrics = read_dsq_metrics(&skel, dsq_available)?;
    let mut previous_at = Instant::now();
    {
        let mut snapshot = state.write().expect("snapshot lock poisoned");
        *snapshot = Snapshot {
            scheduler: "scx_mitosis",
            target_program_ids,
            uptime_seconds: 0,
            counters: build_counters(previous, previous, Duration::ZERO),
            callback_timing_sample_rate,
            event_timing_sample_rate,
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
            dsq_metrics,
            scheduler_events: build_scheduler_event_rows(
                previous_scheduler_events,
                previous_scheduler_events,
                Duration::ZERO,
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
        let callback_timings = read_callback_timings(&skel)?;
        let wakeup_latency = read_wakeup_latency(&skel)?;
        let cpu_slice_duration = read_cpu_slice_duration(&skel)?;
        let blocked_duration = read_blocked_duration(&skel)?;
        let migrations = read_migrations(&skel)?;
        let current_cpu_runtime = read_cpu_runtime(&skel)?;
        let bpf_program_stats = query_bpf_program_stats(&target_program_ids);
        let dsq_metrics = read_dsq_metrics(&skel, dsq_available)?;
        let elapsed = now.duration_since(previous_at);
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
        snapshot.dsq_metrics = dsq_metrics;
        snapshot.scheduler_events = build_scheduler_event_rows(
            current_scheduler_events,
            previous_scheduler_events,
            elapsed,
        );
        previous_scheduler_events = current_scheduler_events;
        previous_at = now;
    }
    Ok(())
}
