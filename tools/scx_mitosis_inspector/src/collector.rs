// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

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

use crate::bpf_skel::{BpfSkel, BpfSkelBuilder};
use crate::{
    build_callback_timing_rows, build_counters, build_timing_metric_row, program_name_matches,
    CallbackCounter, CallbackTimingCounters, CallbackTimingRow, MigrationRow, TimingMetricRow,
    CALLBACK_NAMES, CALLBACK_TIMING_BUCKETS,
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
) -> Result<Vec<Link>> {
    let mut links = vec![
        skel.progs.observe_select_cpu.attach_trace()?,
        skel.progs.observe_enqueue.attach_trace()?,
        skel.progs.observe_dispatch.attach_trace()?,
        skel.progs.observe_running.attach_trace()?,
        skel.progs.observe_stopping.attach_trace()?,
        skel.progs.on_sched_migrate_task.attach()?,
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
    Ok(links)
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
    rows.truncate(32);
    Ok(rows)
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
    let _links = attach_programs(&skel, callback_timing_sample_rate, event_timing_sample_rate)
        .context("attaching callback observer programs")?;

    let started = Instant::now();
    let mut previous = read_counts(&skel)?;
    let callback_timings = read_callback_timings(&skel)?;
    let wakeup_latency = read_wakeup_latency(&skel)?;
    let cpu_slice_duration = read_cpu_slice_duration(&skel)?;
    let blocked_duration = read_blocked_duration(&skel)?;
    let migrations = read_migrations(&skel)?;
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
        };
    }
    ready
        .send(Ok(()))
        .context("reporting collector readiness")?;

    while !shutdown.load(Ordering::Relaxed) {
        thread::sleep(Duration::from_secs(1));
        let now = Instant::now();
        let current = read_counts(&skel)?;
        let callback_timings = read_callback_timings(&skel)?;
        let wakeup_latency = read_wakeup_latency(&skel)?;
        let cpu_slice_duration = read_cpu_slice_duration(&skel)?;
        let blocked_duration = read_blocked_duration(&skel)?;
        let migrations = read_migrations(&skel)?;
        let counters = build_counters(current, previous, now.duration_since(previous_at));
        previous = current;
        previous_at = now;
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
    }
    Ok(())
}
