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
use scx_stats::StatsClient;
use serde::Deserialize;

use crate::bpf_skel::BpfSkelBuilder;
use crate::dashboard::Dashboard;
use crate::policies::{
    discover_policy_files, load_policy_source, validate_policy_files, PolicyActivation,
    PolicyCatalog, PolicyFile, PolicyValidation,
};
use crate::scheduler::{GateChange, SchedulerGate};
use crate::scope::TaskScope;
use crate::{bpf_intf, model::CpuPair};

const DEFAULT_OPS_PATH: &str = "/sys/kernel/sched_ext/root/ops";
const DEFAULT_ENABLE_SEQ_PATH: &str = "/sys/kernel/sched_ext/enable_seq";
const DEFAULT_KALLSYMS_PATH: &str = "/proc/kallsyms";
const DEFAULT_STATS_PATH: &str = "/var/run/scx/root/stats";
const MAX_PAIR_MAP_ENTRIES: usize = 1_048_576;
const STATS_TIMEOUT_MS: u64 = 1_000;
const INSPECTION_POLL_INTERVAL: Duration = Duration::from_secs(1);
const POLICY_SCAN_INTERVAL: Duration = Duration::from_secs(5);

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

#[derive(Debug, Deserialize)]
struct SnakeCpuMetrics {
    cpu: u32,
    runtime_ns: u64,
}

#[derive(Debug, Deserialize)]
struct SnakeMetrics {
    #[serde(default)]
    cpus: BTreeMap<u32, SnakeCpuMetrics>,
}

pub fn decode_cpu_runtime_stats(value: serde_json::Value) -> anyhow::Result<BTreeMap<u32, u64>> {
    let metrics: SnakeMetrics = serde_json::from_value(value)?;
    if metrics.cpus.is_empty() {
        anyhow::bail!("running Snake does not export per-CPU runtime");
    }
    metrics
        .cpus
        .into_iter()
        .map(|(cpu, metrics)| {
            if metrics.cpu != cpu {
                anyhow::bail!("Snake CPU metric key {cpu} contains CPU {}", metrics.cpu);
            }
            Ok((cpu, metrics.runtime_ns))
        })
        .collect()
}

pub fn decode_inspection_stats(value: serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let object = value
        .as_object()
        .context("Snake inspection payload is not an object")?;
    if object
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        != Some(1)
    {
        anyhow::bail!("Snake inspection schema is unsupported");
    }
    if !matches!(
        object
            .get("active_slot")
            .and_then(serde_json::Value::as_u64),
        Some(0 | 1)
    ) {
        anyhow::bail!("Snake inspection has an invalid active slot");
    }
    let slots = object
        .get("slots")
        .and_then(serde_json::Value::as_array)
        .context("Snake inspection has no slot list")?;
    if slots.len() != 2 {
        anyhow::bail!(
            "Snake inspection returned {} slots, expected 2",
            slots.len()
        );
    }
    for field in ["cells", "task_mappings"] {
        if !object.get(field).is_some_and(serde_json::Value::is_array) {
            anyhow::bail!("Snake inspection field {field} is not an array");
        }
    }
    Ok(value)
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

#[derive(Debug)]
pub enum CollectorCommand {
    SetScope(TaskScope),
    ActivatePolicy {
        policy_id: String,
        response: std::sync::mpsc::SyncSender<std::result::Result<PolicyActivation, String>>,
    },
    Shutdown,
}

impl PartialEq for CollectorCommand {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::SetScope(left), Self::SetScope(right)) => left == right,
            (
                Self::ActivatePolicy {
                    policy_id: left, ..
                },
                Self::ActivatePolicy {
                    policy_id: right, ..
                },
            ) => left == right,
            (Self::Shutdown, Self::Shutdown) => true,
            _ => false,
        }
    }
}

impl Eq for CollectorCommand {}

#[derive(Clone, Debug)]
pub struct CollectorOptions {
    pub poll_interval: Duration,
    pub ops_path: PathBuf,
    pub enable_seq_path: PathBuf,
    pub kallsyms_path: PathBuf,
    pub stats_path: PathBuf,
    pub policy_dir: PathBuf,
}

impl Default for CollectorOptions {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_millis(250),
            ops_path: DEFAULT_OPS_PATH.into(),
            enable_seq_path: DEFAULT_ENABLE_SEQ_PATH.into(),
            kallsyms_path: DEFAULT_KALLSYMS_PATH.into(),
            stats_path: DEFAULT_STATS_PATH.into(),
            policy_dir: "scheds/rust/scx_snake/examples".into(),
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
    let mut stats_client = None;
    let mut last_cpu_usage_error = None;
    let mut next_inspection_at = started;
    let mut next_policy_scan_at = started;
    let mut last_policy_files = None;
    loop {
        match commands.recv_timeout(options.poll_interval) {
            Ok(CollectorCommand::SetScope(new_scope)) => {
                write_config(&skel.maps.collector_cfg, false, generation, &scope)?;
                replace_tgids(&skel.maps.tracked_tgids, &new_scope)?;
                scope = new_scope;
                generation = next_generation(generation);
                let now_ms = elapsed_ms(started);
                let baseline = read_counts(&skel.maps.migration_counts)?;
                dashboard.reset_migrations(now_ms, &baseline);
                dashboard.set_scope(scope.clone());
                write_config(
                    &skel.maps.collector_cfg,
                    gate.is_active(),
                    generation,
                    &scope,
                )?;
                continue;
            }
            Ok(CollectorCommand::ActivatePolicy {
                policy_id,
                response,
            }) => {
                let result = activate_policy(
                    &mut stats_client,
                    &options.stats_path,
                    &options.policy_dir,
                    &policy_id,
                )
                .map_err(|error| format!("{error:#}"));
                let _ = response.send(result);
                next_inspection_at = Instant::now();
                next_policy_scan_at = Instant::now();
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
                stats_client = None;
                next_inspection_at = Instant::now();
                next_policy_scan_at = Instant::now();
                last_policy_files = None;
                dashboard.set_inspection(None, None);
                dashboard.set_policy_catalog(None, None);
                set_cpu_usage_error(&dashboard, &mut last_cpu_usage_error, None);
                write_config(&skel.maps.collector_cfg, true, generation, &scope)?;
            }
            GateChange::Stopped => {
                write_config(&skel.maps.collector_cfg, false, generation, &scope)?;
                let baseline = read_counts(&skel.maps.migration_counts)?;
                dashboard.reset(now_ms, &baseline);
                stats_client = None;
                last_policy_files = None;
                dashboard.set_inspection(None, None);
                dashboard.set_policy_catalog(None, None);
                set_cpu_usage_error(&dashboard, &mut last_cpu_usage_error, None);
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
            match read_cpu_runtime(&mut stats_client, &options.stats_path) {
                Ok((runtime_ns, connected)) => {
                    if connected {
                        dashboard.reset_cpu_usage(now_ms);
                    }
                    dashboard.ingest_cpu_usage(now_ms, &runtime_ns);
                    set_cpu_usage_error(&dashboard, &mut last_cpu_usage_error, None);
                }
                Err(error) => {
                    stats_client = None;
                    set_cpu_usage_error(
                        &dashboard,
                        &mut last_cpu_usage_error,
                        Some(format!("Snake utilization unavailable: {error:#}")),
                    );
                }
            }
            if Instant::now() >= next_inspection_at {
                match read_inspection(&mut stats_client, &options.stats_path) {
                    Ok(snapshot) => dashboard.set_inspection_at(now_ms, Some(snapshot), None),
                    Err(error) => dashboard.set_inspection_at(
                        now_ms,
                        None,
                        Some(format!("Snake inspection unavailable: {error:#}")),
                    ),
                }
                next_inspection_at = Instant::now() + INSPECTION_POLL_INTERVAL;
            }
            if Instant::now() >= next_policy_scan_at {
                match read_policy_catalog(
                    &mut stats_client,
                    &options.stats_path,
                    &options.policy_dir,
                    &mut last_policy_files,
                ) {
                    Ok(Some(catalog)) => dashboard.set_policy_catalog(Some(catalog), None),
                    Ok(None) => {}
                    Err(error) => dashboard.set_policy_catalog(
                        None,
                        Some(format!("Policy library unavailable: {error:#}")),
                    ),
                }
                next_policy_scan_at = Instant::now() + POLICY_SCAN_INTERVAL;
            }
        }
    }
}

fn read_policy_catalog(
    client: &mut Option<StatsClient>,
    stats_path: &Path,
    policy_dir: &Path,
    last_policy_files: &mut Option<Vec<PolicyFile>>,
) -> Result<Option<PolicyCatalog>> {
    let files = discover_policy_files(policy_dir)?;
    if last_policy_files.as_ref() == Some(&files) {
        return Ok(None);
    }
    let catalog = validate_policy_files(files.clone(), |source| {
        validate_policy(client, stats_path, source)
    });
    *last_policy_files = Some(files);
    Ok(Some(catalog))
}

fn validate_policy(
    client: &mut Option<StatsClient>,
    stats_path: &Path,
    source: &str,
) -> Result<PolicyValidation> {
    if client.is_none() {
        *client = Some(
            StatsClient::new()
                .set_path(stats_path)
                .connect(Some(STATS_TIMEOUT_MS))
                .with_context(|| format!("connecting to {}", stats_path.display()))?,
        );
    }
    client
        .as_mut()
        .context("Snake stats client is unavailable")?
        .request(
            "stats",
            vec![
                ("target".into(), "policy_validate".into()),
                ("source".into(), source.into()),
            ],
        )
}

fn activate_policy(
    client: &mut Option<StatsClient>,
    stats_path: &Path,
    policy_dir: &Path,
    policy_id: &str,
) -> Result<PolicyActivation> {
    let source = load_policy_source(policy_dir, policy_id)?;
    if client.is_none() {
        *client = Some(
            StatsClient::new()
                .set_path(stats_path)
                .connect(Some(STATS_TIMEOUT_MS))
                .with_context(|| format!("connecting to {}", stats_path.display()))?,
        );
    }
    client
        .as_mut()
        .context("Snake stats client is unavailable")?
        .request(
            "stats",
            vec![
                ("target".into(), "policy_update".into()),
                ("source".into(), source),
            ],
        )
}

fn read_inspection(
    client: &mut Option<StatsClient>,
    stats_path: &Path,
) -> Result<serde_json::Value> {
    if client.is_none() {
        *client = Some(
            StatsClient::new()
                .set_path(stats_path)
                .connect(Some(STATS_TIMEOUT_MS))
                .with_context(|| format!("connecting to {}", stats_path.display()))?,
        );
    }
    let payload = client
        .as_mut()
        .context("Snake stats client is unavailable")?
        .request::<serde_json::Value>("stats", vec![("target".into(), "inspect".into())])?;
    decode_inspection_stats(payload)
}

fn read_cpu_runtime(
    client: &mut Option<StatsClient>,
    stats_path: &Path,
) -> Result<(BTreeMap<u32, u64>, bool)> {
    let connected = client.is_none();
    if connected {
        *client = Some(
            StatsClient::new()
                .set_path(stats_path)
                .connect(Some(STATS_TIMEOUT_MS))
                .with_context(|| format!("connecting to {}", stats_path.display()))?,
        );
    }
    let payload = client
        .as_mut()
        .context("Snake stats client is unavailable")?
        .request::<serde_json::Value>("stats", Vec::new())?;
    Ok((decode_cpu_runtime_stats(payload)?, connected))
}

fn set_cpu_usage_error(
    dashboard: &Dashboard,
    previous: &mut Option<String>,
    error: Option<String>,
) {
    if *previous != error {
        dashboard.set_cpu_usage_error(error.clone());
        *previous = error;
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
