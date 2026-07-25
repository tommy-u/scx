// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::BTreeMap;
use std::fs;
use std::mem::MaybeUninit;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags};

use crate::bpf_skel::BpfSkelBuilder;
use crate::dashboard::Dashboard;
use crate::scheduler::{GateChange, SchedulerGate};
use crate::scope::TaskScope;
use crate::{bpf_intf, model::CpuPair};

const DEFAULT_OPS_PATH: &str = "/sys/kernel/sched_ext/root/ops";
const DEFAULT_ENABLE_SEQ_PATH: &str = "/sys/kernel/sched_ext/enable_seq";
const DEFAULT_KALLSYMS_PATH: &str = "/proc/kallsyms";
const MAX_PAIR_MAP_ENTRIES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CollectorConfig {
    enabled: u32,
    scope_kind: u32,
    generation: u32,
    cgroup_id: u64,
}

impl CollectorConfig {
    pub fn new(enabled: bool, generation: u32, scope: &TaskScope) -> Self {
        let (scope_kind, cgroup_id) = match scope {
            TaskScope::All => (bpf_intf::task_scope_kind_TASK_SCOPE_ALL, 0),
            TaskScope::Tgids(_) => (bpf_intf::task_scope_kind_TASK_SCOPE_TGID, 0),
            TaskScope::Cgroup { cgroup_id, .. } => {
                (bpf_intf::task_scope_kind_TASK_SCOPE_CGROUP, *cgroup_id)
            }
        };
        Self {
            enabled: u32::from(enabled),
            scope_kind,
            generation,
            cgroup_id,
        }
    }

    pub fn to_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(24);
        bytes.extend_from_slice(&self.enabled.to_ne_bytes());
        bytes.extend_from_slice(&self.scope_kind.to_ne_bytes());
        bytes.extend_from_slice(&self.generation.to_ne_bytes());
        bytes.extend_from_slice(&0_u32.to_ne_bytes());
        bytes.extend_from_slice(&self.cgroup_id.to_ne_bytes());
        bytes
    }
}

pub fn decode_counter_entry(key: &[u8], value: &[u8]) -> anyhow::Result<(CpuPair, u64)> {
    if key.len() != 8 {
        anyhow::bail!("migration key has {} bytes, expected 8", key.len());
    }
    if value.len() != 8 {
        anyhow::bail!("migration count has {} bytes, expected 8", value.len());
    }

    let from = u32::from_ne_bytes(key[0..4].try_into().unwrap());
    let to = u32::from_ne_bytes(key[4..8].try_into().unwrap());
    let count = u64::from_ne_bytes(value.try_into().unwrap());
    Ok((CpuPair::new(from, to), count))
}

pub fn find_symbol_address(kallsyms: &str, symbol: &str) -> anyhow::Result<u64> {
    let address = kallsyms
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let address = fields.next()?;
            fields.next()?;
            let name = fields.next()?;
            (name == symbol).then_some(address)
        })
        .next()
        .ok_or_else(|| anyhow::anyhow!("symbol {symbol} not found in /proc/kallsyms"))?;
    let address = u64::from_str_radix(address, 16)
        .map_err(|error| anyhow::anyhow!("invalid address for {symbol}: {error}"))?;
    if address == 0 {
        anyhow::bail!("address for {symbol} is hidden; run with sufficient privileges");
    }
    Ok(address)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CollectorCommand {
    SetScope(TaskScope),
    Shutdown,
}

#[derive(Clone, Debug)]
pub struct CollectorOptions {
    pub poll_interval: Duration,
    pub ops_path: PathBuf,
    pub enable_seq_path: PathBuf,
    pub kallsyms_path: PathBuf,
}

impl Default for CollectorOptions {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_millis(250),
            ops_path: DEFAULT_OPS_PATH.into(),
            enable_seq_path: DEFAULT_ENABLE_SEQ_PATH.into(),
            kallsyms_path: DEFAULT_KALLSYMS_PATH.into(),
        }
    }
}

pub fn run_collector(
    dashboard: Dashboard,
    commands: Receiver<CollectorCommand>,
    options: CollectorOptions,
) -> Result<()> {
    let kallsyms = fs::read_to_string(&options.kallsyms_path).with_context(|| {
        format!(
            "failed to read kernel symbols from {}",
            options.kallsyms_path.display()
        )
    })?;
    let ext_sched_class_addr = find_symbol_address(&kallsyms, "ext_sched_class")?;

    let mut open_object = MaybeUninit::uninit();
    let builder = BpfSkelBuilder::default();
    let mut skel = builder.open(&mut open_object)?;
    skel.maps
        .rodata_data
        .as_mut()
        .context("BPF rodata is unavailable")?
        .ext_sched_class_addr = ext_sched_class_addr;

    let possible_cpus = libbpf_rs::num_possible_cpus()?;
    let max_pairs = possible_cpus
        .saturating_mul(possible_cpus)
        .clamp(64, MAX_PAIR_MAP_ENTRIES);
    skel.maps
        .migration_counts
        .set_max_entries(u32::try_from(max_pairs)?)?;

    let skel = skel.load().context(
        "failed to load migration BPF program; run as root or grant the required BPF capabilities",
    )?;
    let _link = skel
        .progs
        .on_sched_switch
        .attach()
        .context("failed to attach sched_switch BPF program")?;

    let started = Instant::now();
    let mut gate = SchedulerGate::new("snake");
    let mut scope = TaskScope::All;
    let mut generation = 1_u32;
    write_config(&skel.maps.collector_cfg, false, generation, &scope)?;
    let baseline = read_counts(&skel.maps.migration_counts)?;
    dashboard.reset(0, &baseline);
    dashboard.set_scope(scope.clone());

    let mut last_scheduler_name = String::new();
    let mut last_health = (0_u64, 0_u64);
    loop {
        match commands.recv_timeout(options.poll_interval) {
            Ok(CollectorCommand::SetScope(new_scope)) => {
                write_config(&skel.maps.collector_cfg, false, generation, &scope)?;
                replace_tgids(&skel.maps.tracked_tgids, &new_scope)?;
                scope = new_scope;
                generation = next_generation(generation);
                let now_ms = elapsed_ms(started);
                let baseline = read_counts(&skel.maps.migration_counts)?;
                dashboard.reset(now_ms, &baseline);
                dashboard.set_scope(scope.clone());
                write_config(
                    &skel.maps.collector_cfg,
                    gate.is_active(),
                    generation,
                    &scope,
                )?;
                continue;
            }
            Ok(CollectorCommand::Shutdown) => return Ok(()),
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
            Err(RecvTimeoutError::Timeout) => {}
        }

        let scheduler_name = read_trimmed(&options.ops_path).unwrap_or_default();
        let enable_seq = read_trimmed(&options.enable_seq_path)
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        let change = gate.observe(&scheduler_name, enable_seq);
        let now_ms = elapsed_ms(started);

        match change {
            GateChange::Started | GateChange::Restarted => {
                write_config(&skel.maps.collector_cfg, false, generation, &scope)?;
                generation = next_generation(generation);
                let baseline = read_counts(&skel.maps.migration_counts)?;
                dashboard.reset(now_ms, &baseline);
                write_config(&skel.maps.collector_cfg, true, generation, &scope)?;
            }
            GateChange::Stopped => {
                write_config(&skel.maps.collector_cfg, false, generation, &scope)?;
                let baseline = read_counts(&skel.maps.migration_counts)?;
                dashboard.reset(now_ms, &baseline);
            }
            GateChange::None => {}
        }

        if change != GateChange::None || scheduler_name != last_scheduler_name {
            dashboard.set_scheduler(&scheduler_name, gate.is_active(), enable_seq);
            last_scheduler_name.clone_from(&scheduler_name);
        }

        let health = read_health(&skel.maps.collector_stats)?;
        if health != last_health {
            dashboard.set_collector_health(None, health.0, health.1);
            last_health = health;
        }

        if gate.is_active() {
            let counts = read_counts(&skel.maps.migration_counts)?;
            dashboard.ingest(now_ms, &counts);
        }
    }
}

fn write_config(
    map: &impl MapCore,
    enabled: bool,
    generation: u32,
    scope: &TaskScope,
) -> Result<()> {
    let key = 0_u32.to_ne_bytes();
    let value = CollectorConfig::new(enabled, generation, scope).to_bytes();
    map.update(&key, &value, MapFlags::ANY)
        .context("failed to update BPF collector configuration")
}

fn replace_tgids(map: &impl MapCore, scope: &TaskScope) -> Result<()> {
    let existing = map.keys().collect::<Vec<_>>();
    for key in existing {
        map.delete(&key)?;
    }
    if let TaskScope::Tgids(tgids) = scope {
        for tgid in tgids {
            map.update(&tgid.to_ne_bytes(), &[1], MapFlags::NO_EXIST)?;
        }
    }
    Ok(())
}

fn read_counts(map: &impl MapCore) -> Result<BTreeMap<CpuPair, u64>> {
    let mut counts = BTreeMap::new();
    for key in map.keys() {
        if let Some(value) = map.lookup(&key, MapFlags::ANY)? {
            let (pair, count) = decode_counter_entry(&key, &value)?;
            counts.insert(pair, count);
        }
    }
    Ok(counts)
}

fn read_health(map: &impl MapCore) -> Result<(u64, u64)> {
    Ok((
        read_stat(
            map,
            bpf_intf::collector_stat_id_COLLECTOR_STAT_PAIR_MAP_FAILURE,
        )?,
        read_stat(
            map,
            bpf_intf::collector_stat_id_COLLECTOR_STAT_TASK_STORAGE_FAILURE,
        )?,
    ))
}

fn read_stat(map: &impl MapCore, stat: u32) -> Result<u64> {
    let value = map
        .lookup(&stat.to_ne_bytes(), MapFlags::ANY)?
        .context("collector stat is missing")?;
    if value.len() != 8 {
        anyhow::bail!("collector stat has {} bytes, expected 8", value.len());
    }
    Ok(u64::from_ne_bytes(value.try_into().unwrap()))
}

fn read_trimmed(path: &Path) -> Result<String> {
    Ok(fs::read_to_string(path)?.trim().to_owned())
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn next_generation(current: u32) -> u32 {
    current.wrapping_add(1).max(1)
}
