// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-2.0-only

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::mem::size_of;
use std::os::fd::AsRawFd;

use anyhow::{bail, Context, Result};
use libbpf_rs::{
    btf::{Btf, BtfType},
    Link, Map, MapCore, MapFlags, Object, ObjectBuilder, ProgramInput,
};
use serde_json::{json, Value};

use crate::explore_bpf_skel::EXPLORE_OBJECT;
use crate::explore_model::ExploreGroup;
use crate::lifecycle::unix_ms;
use crate::topology::TopologyView;

#[path = "explore_probe_io.rs"]
mod io;
#[path = "explore_probe_math.rs"]
mod math;
use math::{counter_interval, cpu_equivalents, Histogram, TaskIdentity};

const ROW_LIMIT: usize = 128;
const DSQ_LIMIT: usize = 256;
const DSQ_CAPACITY_MAX: usize = 16384;
const TASK_CAPACITY: usize = 4096;
const IPI_CAPACITY_MAX: usize = 1_048_576;
const CPU_CAPACITY: u32 = 4096;
const STALE_NS: u64 = 30_000_000_000;
const SCOPE: &str = "Whole host · observed scheduler events";
const SCX_NAMES: [&str; 5] = [
    "SCX_EV_SELECT_CPU_FALLBACK",
    "SCX_EV_DISPATCH_LOCAL_DSQ_OFFLINE",
    "SCX_EV_DISPATCH_KEEP_LAST",
    "SCX_EV_ENQ_SKIP_EXITING",
    "SCX_EV_ENQ_SKIP_MIGRATION_DISABLED",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FamilyKind {
    Dsqs,
    Tasks,
    Wakers,
    Scx,
    Ipis,
    Pressure,
}

impl FamilyKind {
    fn key(self) -> &'static str {
        match self {
            Self::Dsqs => "dsqs",
            Self::Tasks => "tasks",
            Self::Wakers => "wakers",
            Self::Scx => "scx_events",
            Self::Ipis => "ipis",
            Self::Pressure => "pressure",
        }
    }
    fn capacity(self, cpu_limit: u32) -> usize {
        match self {
            // Cover local-on and per-CPU custom queues, plus shared-queue headroom.
            Self::Dsqs => (cpu_limit as usize)
                .saturating_mul(2)
                .saturating_add(DSQ_LIMIT)
                .min(DSQ_CAPACITY_MAX),
            // Sparse CPU IDs can over-reserve pairs, but cannot cause under-coverage.
            Self::Ipis => (cpu_limit as usize)
                .saturating_mul(cpu_limit as usize)
                .clamp(1, IPI_CAPACITY_MAX),
            Self::Pressure => CPU_CAPACITY as usize,
            Self::Scx => 5,
            Self::Tasks | Self::Wakers => TASK_CAPACITY,
        }
    }
    fn row_limit(self) -> usize {
        match self {
            Self::Dsqs => DSQ_LIMIT,
            Self::Pressure => CPU_CAPACITY as usize,
            _ => ROW_LIMIT,
        }
    }
    fn sample_rate(self) -> u32 {
        match self {
            Self::Dsqs | Self::Wakers => 64,
            Self::Tasks => 16,
            _ => 1,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawHistogram {
    total_ns: u64,
    max_ns: u64,
    max_update_failures: u64,
    buckets: [u64; 64],
}
impl RawHistogram {
    fn histogram(&self) -> Histogram {
        Histogram {
            total_ns: self.total_ns,
            max_ns: self.max_ns,
            max_update_failures: self.max_update_failures,
            max_known: true,
            buckets: self.buckets,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RawTaskKey {
    start_time_ns: u64,
    pid: u32,
    pad: u32,
}
impl RawTaskKey {
    fn identity(self) -> TaskIdentity {
        TaskIdentity {
            pid: self.pid,
            start_time_ns: self.start_time_ns,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawDsq {
    insert_events: u64,
    move_events: u64,
    depth_samples: u64,
    depth_total: u64,
    depth_last: u64,
    depth_max: u64,
    last_seen_ns: u64,
    latency: RawHistogram,
    run: RawHistogram,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawTask {
    tgid: u32,
    cpu: u32,
    comm: [u8; 16],
    cgroup_id: u64,
    first_seen_ns: u64,
    last_seen_ns: u64,
    last_running_at_ns: u64,
    runtime_ns: u64,
    running_since_ns: u64,
    wakeups: u64,
    switches: u64,
    delay: RawHistogram,
    dsq_delay: RawHistogram,
}

#[repr(C)]
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct RawPairKey {
    waker: RawTaskKey,
    wakee: RawTaskKey,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawWaker {
    waker_tgid: u32,
    wakee_tgid: u32,
    waker_comm: [u8; 16],
    wakee_comm: [u8; 16],
    waker_cpu: u32,
    wakee_cpu: u32,
    first_seen_ns: u64,
    last_seen_ns: u64,
    wakeups: u64,
    same_cpu: u64,
    same_llc: u64,
    cross_llc: u64,
    cross_numa: u64,
    unknown_locality: u64,
    latency: RawHistogram,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct RawIpiKey {
    source_cpu: u32,
    target_cpu: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
struct RawPressure {
    pressure: u64,
    updated_at_ns: u64,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RawHealth {
    tracking_failures: u64,
    state_failures: u64,
    depth_failures: u64,
    ipi_send_cpu_events: u64,
    ipi_send_cpumask_events: u64,
    ipi_targets: u64,
    ipi_mask_read_failures: u64,
    ipi_mask_truncated: u64,
    waker_wakeups_seen: u64,
    waker_selected_wakeups: u64,
    waker_matched_samples: u64,
    waker_origins_seen: u64,
    waker_origins_selected: u64,
    waker_origins_missing: u64,
    waker_running_wakeups: u64,
    task_running_wakeups: u64,
    dsq_unverified_moves: u64,
    task_unverified_moves: u64,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct RawScx {
    supported_mask: u64,
    timestamp_ns: u64,
    counts: [u64; 5],
}

struct ProbeSupport {
    symbols: BTreeSet<String>,
    tracepoints: BTreeSet<String>,
    cpu_limit: u32,
}

impl ProbeSupport {
    fn discover(topology: &TopologyView) -> Self {
        let symbols = fs::read_to_string("/proc/kallsyms")
            .unwrap_or_default()
            .lines()
            .filter_map(|line| line.split_whitespace().nth(2).map(str::to_owned))
            .collect();
        let btf = Btf::from_vmlinux().ok();
        let tracepoints = [
            "sched_switch",
            "sched_wakeup",
            "sched_wakeup_new",
            "sched_waking",
            "sched_process_exit",
            "ipi_send_cpu",
            "ipi_send_cpumask",
            "hw_pressure_update",
        ]
        .into_iter()
        .filter(|name| {
            btf.as_ref().is_some_and(|btf| {
                btf.type_by_name::<BtfType>(&format!("btf_trace_{name}"))
                    .is_some()
            }) || [
                "/sys/kernel/tracing/events",
                "/sys/kernel/debug/tracing/events",
            ]
            .into_iter()
            .any(|base| {
                let category = if name.starts_with("sched_") {
                    "sched"
                } else if name.starts_with("ipi_") {
                    "ipi"
                } else {
                    "power"
                };
                std::path::Path::new(base)
                    .join(category)
                    .join(name)
                    .exists()
            })
        })
        .map(str::to_owned)
        .collect();
        let topology_limit = topology
            .cpus
            .iter()
            .map(|cpu| cpu.cpu)
            .max()
            .unwrap_or(0)
            .saturating_add(1);
        let cpu_limit = fs::read_to_string("/sys/devices/system/cpu/possible")
            .ok()
            .and_then(|value| cpu_list_limit(&value))
            .unwrap_or(topology_limit);
        Self {
            symbols,
            tracepoints,
            cpu_limit,
        }
    }

    fn insertion_programs(&self, prefix: &str) -> BTreeSet<String> {
        let mut result = BTreeSet::new();
        for variants in [
            vec![
                ("scx_bpf_dsq_insert___v2", "insert_v2"),
                ("scx_bpf_dsq_insert", "insert"),
                ("scx_bpf_dispatch", "dispatch"),
            ],
            vec![
                ("__scx_bpf_dsq_insert_vtime", "insert_args"),
                ("scx_bpf_dsq_insert_vtime", "insert_vtime"),
                ("scx_bpf_dispatch_vtime", "dispatch_vtime"),
            ],
            vec![
                ("scx_bpf_dsq_move", "move"),
                ("scx_bpf_dispatch_from_dsq", "dispatch_move"),
            ],
            vec![
                ("scx_bpf_dsq_move_vtime", "move_vtime"),
                ("scx_bpf_dispatch_vtime_from_dsq", "dispatch_move_vtime"),
            ],
        ] {
            if let Some((_, suffix)) = variants
                .into_iter()
                .find(|(symbol, _)| self.symbols.contains(*symbol))
            {
                result.insert(format!("{prefix}_{suffix}"));
            }
        }
        result
    }

    fn programs(&self, kind: FamilyKind) -> Result<BTreeSet<String>> {
        let mut result = BTreeSet::new();
        match kind {
            FamilyKind::Dsqs | FamilyKind::Tasks | FamilyKind::Wakers => {
                if !self.tracepoints.contains("sched_switch") {
                    bail!("Kernel tp_btf/sched_switch is unavailable");
                }
                let prefix = match kind {
                    FamilyKind::Dsqs => "ex_dsqs",
                    FamilyKind::Tasks => "ex_tasks",
                    _ => "ex_wakers",
                };
                result.insert(format!("{prefix}_switch"));
                if kind != FamilyKind::Wakers && self.tracepoints.contains("sched_process_exit") {
                    result.insert(format!("{prefix}_exit"));
                }
                if kind != FamilyKind::Dsqs {
                    for wakeup in ["sched_wakeup", "sched_wakeup_new"] {
                        if self.tracepoints.contains(wakeup) {
                            result.insert(format!(
                                "{prefix}_{}",
                                wakeup.strip_prefix("sched_").unwrap()
                            ));
                        }
                    }
                }
                if kind == FamilyKind::Wakers && !result.contains("ex_wakers_wakeup") {
                    bail!("Kernel tp_btf/sched_wakeup is unavailable");
                }
                if kind == FamilyKind::Wakers {
                    if !self.tracepoints.contains("sched_waking") {
                        bail!("Kernel tp_btf/sched_waking is required to identify original waking context");
                    }
                    result.insert("ex_wakers_waking".into());
                }
                if kind != FamilyKind::Wakers {
                    result.extend(self.insertion_programs(if kind == FamilyKind::Dsqs {
                        "ex_dsq"
                    } else {
                        "ex_task"
                    }));
                }
                if kind == FamilyKind::Dsqs
                    && !result.iter().any(|name| name.starts_with("ex_dsq_"))
                {
                    bail!(
                        "No supported sched_ext DSQ insertion symbols were found in /proc/kallsyms"
                    );
                }
            }
            FamilyKind::Ipis => {
                for name in ["ipi_send_cpu", "ipi_send_cpumask"] {
                    if self.tracepoints.contains(name) {
                        result.insert(format!("ex_{name}"));
                    }
                }
                if result.is_empty() {
                    bail!("Kernel IPI send tracepoints are unavailable");
                }
            }
            FamilyKind::Pressure => {
                if !self.tracepoints.contains("hw_pressure_update") {
                    bail!("Kernel tp_btf/hw_pressure_update is unavailable");
                }
                result.insert("ex_pressure_update".into());
            }
            FamilyKind::Scx => {
                result.insert("ex_collect_scx_events".into());
            }
        }
        Ok(result)
    }
}

struct ProbeFamily {
    kind: FamilyKind,
    object: Option<Object>,
    // Links must be dropped before the object whose programs they attach.
    links: Vec<Link>,
    error: Option<String>,
    attached_programs: BTreeSet<String>,
    attachment_errors: Vec<String>,
    attached_at_unix_ms: u64,
    previous_at_ns: Option<u64>,
    previous_health: Option<RawHealth>,
    previous_rows: BTreeMap<Vec<u8>, Vec<u8>>,
    previous_runtime: BTreeMap<TaskIdentity, (u64, u64)>,
    previous_scx: Option<RawScx>,
    previous_histograms: BTreeMap<&'static str, Histogram>,
    previous_ipis: HashMap<(u32, u32), u64>,
    cpu_limit: u32,
    next_retry_at: std::time::Instant,
    last_success_at_unix_ms: Option<u64>,
}

impl ProbeFamily {
    fn new(kind: FamilyKind, support: &ProbeSupport, topology: &TopologyView) -> Self {
        debug_assert!(math::event_sampled(0, kind.sample_rate()));
        let mut family = Self {
            kind,
            object: None,
            links: Vec::new(),
            error: None,
            attached_programs: BTreeSet::new(),
            attachment_errors: Vec::new(),
            attached_at_unix_ms: unix_ms(),
            previous_at_ns: None,
            previous_health: None,
            previous_rows: BTreeMap::new(),
            previous_runtime: BTreeMap::new(),
            previous_scx: None,
            previous_histograms: BTreeMap::new(),
            previous_ipis: HashMap::new(),
            cpu_limit: support.cpu_limit,
            next_retry_at: std::time::Instant::now() + std::time::Duration::from_secs(30),
            last_success_at_unix_ms: None,
        };
        if let Err(error) = family.attach(support, topology) {
            family.error = Some(format!("{error:#}"));
        }
        family
    }

    fn attach(&mut self, support: &ProbeSupport, topology: &TopologyView) -> Result<()> {
        self.cpu_limit = support.cpu_limit;
        let selected = support.programs(self.kind)?;
        let mut open = ObjectBuilder::default()
            .open_memory(EXPLORE_OBJECT)
            .context("opening independent Explore BPF object")?;
        for mut program in open.progs_mut() {
            let name = program.name().to_string_lossy();
            program.set_autoload(selected.contains(name.as_ref()));
        }
        for mut map in open.maps_mut() {
            let name = map.name().to_string_lossy().into_owned();
            let needed = match name.as_str() {
                "explore_dsqs"
                | "explore_dsq_zero"
                | "explore_dsq_states"
                | "explore_dsq_latency"
                | "explore_dsq_running" => self.kind == FamilyKind::Dsqs,
                "explore_tasks"
                | "explore_task_zero"
                | "explore_task_states"
                | "explore_task_delay" => self.kind == FamilyKind::Tasks,
                "explore_wakers"
                | "explore_waker_zero"
                | "explore_waker_states"
                | "explore_waker_latency"
                | "explore_topology" => self.kind == FamilyKind::Wakers,
                "explore_ipis" | "explore_config" => self.kind == FamilyKind::Ipis,
                "explore_pressure" => self.kind == FamilyKind::Pressure,
                _ => true,
            };
            if !needed {
                map.set_autocreate(false)
                    .context("disabling unrelated Explore map")?;
            } else if matches!(name.as_str(), "explore_dsqs" | "explore_ipis") {
                map.set_max_entries(self.kind.capacity(self.cpu_limit) as u32)
                    .with_context(|| format!("sizing {name} for possible CPU coverage"))?;
            }
        }
        let object = open
            .load()
            .context("loading independent optional BPF family")?;
        if self.kind == FamilyKind::Wakers {
            let map = object_map(&object, "explore_topology")?;
            for cpu in &topology.cpus {
                if cpu.cpu >= CPU_CAPACITY {
                    continue;
                }
                let mut value = Vec::with_capacity(16);
                for number in [cpu.llc, cpu.node, 1, 0] {
                    value.extend_from_slice(&number.to_ne_bytes());
                }
                map.update(&cpu.cpu.to_ne_bytes(), &value, MapFlags::ANY)
                    .context("configuring wakeup locality topology")?;
            }
        }
        if self.kind == FamilyKind::Ipis {
            let map = object_map(&object, "explore_config")?;
            let mut value = self.cpu_limit.min(CPU_CAPACITY).to_ne_bytes().to_vec();
            value.extend_from_slice(&0u32.to_ne_bytes());
            map.update(&0u32.to_ne_bytes(), &value, MapFlags::ANY)
                .context("configuring IPI cpumask coverage")?;
        }
        if self.kind == FamilyKind::Scx {
            self.attached_programs = selected;
            self.object = Some(object);
            return Ok(());
        }
        for program in object.progs_mut() {
            let name = program.name().to_string_lossy().into_owned();
            if !selected.contains(&name) {
                continue;
            }
            match program.attach() {
                Ok(link) => {
                    self.links.push(link);
                    self.attached_programs.insert(name);
                }
                Err(error) => self.attachment_errors.push(format!("{name}: {error}")),
            }
        }
        let required = match self.kind {
            FamilyKind::Dsqs => {
                self.attached_programs.contains("ex_dsqs_switch")
                    && self
                        .attached_programs
                        .iter()
                        .any(|name| name.starts_with("ex_dsq_"))
            }
            FamilyKind::Tasks => self.attached_programs.contains("ex_tasks_switch"),
            FamilyKind::Wakers => {
                self.attached_programs.contains("ex_wakers_switch")
                    && self.attached_programs.contains("ex_wakers_wakeup")
                    && self.attached_programs.contains("ex_wakers_waking")
            }
            FamilyKind::Ipis => !self.attached_programs.is_empty(),
            FamilyKind::Pressure => self.attached_programs.contains("ex_pressure_update"),
            FamilyKind::Scx => true,
        };
        if !required {
            self.links.clear();
            bail!(
                "Required {} observers could not attach: {}",
                self.kind.key(),
                self.attachment_errors.join("; ")
            );
        }
        self.attached_at_unix_ms = unix_ms();
        self.object = Some(object);
        Ok(())
    }

    fn clear_baseline(&mut self) {
        self.previous_at_ns = None;
        self.previous_health = None;
        self.previous_rows.clear();
        self.previous_runtime.clear();
        self.previous_scx = None;
        self.previous_histograms.clear();
        self.previous_ipis.clear();
    }

    fn retry_due(&self, now: std::time::Instant) -> bool {
        self.object.is_none() && now >= self.next_retry_at
    }

    fn retry(&mut self, support: &ProbeSupport, topology: &TopologyView) {
        self.next_retry_at = std::time::Instant::now() + std::time::Duration::from_secs(30);
        self.links.clear();
        self.attached_programs.clear();
        self.attachment_errors.clear();
        self.clear_baseline();
        self.error = self
            .attach(support, topology)
            .err()
            .map(|error| format!("{error:#}"));
    }

    fn collect(&mut self, topology: &TopologyView, seq: u64) -> ExploreGroup {
        let read_started = std::time::Instant::now();
        let mut group = match self.read(topology) {
            Ok(group) => group,
            Err(error) => {
                self.clear_baseline();
                ExploreGroup::unavailable(SCOPE, format!("{error:#}"))
            }
        };
        let captured_at = unix_ms();
        group.summary["collection_ms"] = json!(read_started.elapsed().as_secs_f64() * 1000.0);
        group.meta.sample_seq = seq;
        group.meta.captured_at_unix_ms = Some(captured_at);
        if group.available {
            self.last_success_at_unix_ms = Some(captured_at);
        }
        group.meta.last_success_at_unix_ms = self.last_success_at_unix_ms;
        group.meta.error = group.error.clone();
        group
    }

    fn read(&mut self, topology: &TopologyView) -> Result<ExploreGroup> {
        if self.object.is_none() {
            bail!(
                "{}",
                self.error
                    .as_deref()
                    .unwrap_or("Optional BPF family is not attached")
            );
        }
        let now_ns = monotonic_ns()?;
        let elapsed_ns = self
            .previous_at_ns
            .and_then(|previous| now_ns.checked_sub(previous))
            .filter(|elapsed| *elapsed > 0);
        let health = if self.kind == FamilyKind::Scx {
            RawHealth::default()
        } else {
            read_health(self.object.as_ref().unwrap())?
        };
        let mut summary = self.summary(elapsed_ns, health);
        let mut rows = match self.kind {
            FamilyKind::Dsqs => self.read_dsqs(elapsed_ns, &mut summary)?,
            FamilyKind::Tasks => self.read_tasks(now_ns, elapsed_ns, topology, &mut summary)?,
            FamilyKind::Wakers => self.read_wakers(now_ns, elapsed_ns, topology, &mut summary)?,
            FamilyKind::Ipis => self.read_ipis(elapsed_ns, topology, health, &mut summary)?,
            FamilyKind::Pressure => self.read_pressure(now_ns, topology, &mut summary)?,
            FamilyKind::Scx => self.read_scx(elapsed_ns, &mut summary)?,
        };
        self.update_aggregate_history(elapsed_ns, health, &mut summary)?;
        let tracked_count = summary["tracked_count"]
            .as_u64()
            .map(|count| count as usize)
            .unwrap_or(rows.len());
        summary["tracked_count"] = json!(tracked_count);
        summary["truncated_rows"] =
            json!(tracked_count.saturating_sub(rows.len().min(self.kind.row_limit())));
        let truncated = tracked_count > rows.len().min(self.kind.row_limit());
        rows.truncate(self.kind.row_limit());
        summary["returned_rows"] = json!(rows.len());
        let mut group = ExploreGroup::available(SCOPE, summary, rows);
        group.partial = truncated
            || health.tracking_failures > 0
            || health.state_failures > 0
            || health.depth_failures > 0
            || health.ipi_mask_read_failures > 0
            || !self.attachment_errors.is_empty()
            || (self.kind == FamilyKind::Ipis && self.cpu_limit > CPU_CAPACITY)
            || (self.kind == FamilyKind::Ipis
                && (!self.attached_programs.contains("ex_ipi_send_cpu")
                    || !self.attached_programs.contains("ex_ipi_send_cpumask")))
            || (self.kind == FamilyKind::Tasks
                && (group.summary["cpu_read_failures"].as_u64().unwrap_or(0) > 0
                    || group.summary["cpu_capped_threads"].as_u64().unwrap_or(0) > 0
                    || !self.attached_programs.contains("ex_tasks_wakeup")))
            || (self.kind == FamilyKind::Pressure
                && group.rows.len() < topology.cpu_count as usize)
            || (self.kind == FamilyKind::Scx && group.rows.len() < SCX_NAMES.len());
        group.partial |= matches!(self.kind, FamilyKind::Tasks | FamilyKind::Wakers);
        self.previous_health = Some(health);
        self.previous_at_ns = Some(now_ns);
        Ok(group)
    }

    fn summary(&self, elapsed_ns: Option<u64>, health: RawHealth) -> Value {
        let previous = self.previous_health;
        let failures = health
            .tracking_failures
            .saturating_add(health.state_failures);
        let previous_failures = previous.map(|health| {
            health
                .tracking_failures
                .saturating_add(health.state_failures)
        });
        let failure_interval = counter_interval(failures, previous_failures, elapsed_ns);
        json!({
            "attached_at_unix_ms": self.attached_at_unix_ms,
            "interval_ms": elapsed_ns.map(|ns| ns as f64 / 1_000_000.0),
            "interval_valid": elapsed_ns.is_some(),
            "sample_rate": self.kind.sample_rate(),
            "sample_probability": 1.0 / self.kind.sample_rate() as f64,
            "sample_policy": match self.kind {
                FamilyKind::Tasks => "stable cohort of task identities; continuous CPU time for retained threads",
                FamilyKind::Dsqs => "random selection at each final observed DSQ insertion or move",
                FamilyKind::Wakers => "random original waking contexts joined to successful wakeup and first run; already-on-CPU successes excluded",
                _ => "all observed tracepoint events; no sampling",
            },
            "counter_scope": if matches!(self.kind, FamilyKind::Tasks | FamilyKind::Wakers) { "since current bounded map admission" } else { "since attachment" },
            "histogram_scope": if matches!(self.kind, FamilyKind::Tasks | FamilyKind::Wakers) { "since current bounded map admission" } else { "since attachment" },
            "storage_policy": if matches!(self.kind, FamilyKind::Tasks | FamilyKind::Wakers) { "LRU4096 metrics/pending identities; completed states and inactive rows expire" } else { "bounded hash maps; failed admissions counted" },
            "counters_can_reset": matches!(self.kind, FamilyKind::Tasks | FamilyKind::Wakers),
            "storage_evictions_unknown": matches!(self.kind, FamilyKind::Tasks | FamilyKind::Wakers),
            "storage_evictions_total": Value::Null,
            "histograms_scaled": false,
            "row_limit": self.kind.row_limit(),
            "map_capacity": self.kind.capacity(self.cpu_limit),
            "tracking_failures_total": failures,
            "tracking_failures_interval": failure_interval.map(|interval| interval.count),
            "map_failures_total": health.tracking_failures,
            "state_failures_total": health.state_failures,
            "depth_read_failures_total": health.depth_failures,
            "already_running_wakeups_excluded_total": match self.kind { FamilyKind::Tasks => health.task_running_wakeups, FamilyKind::Wakers => health.waker_running_wakeups, _ => 0 },
            "unverified_move_attempts_total": match self.kind { FamilyKind::Tasks => health.task_unverified_moves, FamilyKind::Dsqs => health.dsq_unverified_moves, _ => 0 },
            "attached_programs": self.attached_programs,
            "attachment_errors": self.attachment_errors,
            "snapshots_atomic": false,
            "maxima_approximate_under_contention": matches!(self.kind, FamilyKind::Dsqs | FamilyKind::Wakers),
            "cpu_owner_attribution": "none",
        })
    }

    fn aggregate_delta(
        &mut self,
        name: &'static str,
        elapsed_ns: Option<u64>,
    ) -> Result<Option<Histogram>> {
        let current = read_aggregate_histogram(self.object.as_ref().unwrap(), name)?;
        let previous = self.previous_histograms.insert(name, current.clone());
        Ok(elapsed_ns.and_then(|_| previous.and_then(|previous| current.delta(&previous))))
    }

    fn update_aggregate_history(
        &mut self,
        elapsed_ns: Option<u64>,
        health: RawHealth,
        summary: &mut Value,
    ) -> Result<()> {
        match self.kind {
            FamilyKind::Dsqs => {
                let latency = self.aggregate_delta("explore_dsq_latency", elapsed_ns)?;
                let running = self.aggregate_delta("explore_dsq_running", elapsed_ns)?;
                summary["latency_mean_us"] = json!(latency.as_ref().and_then(Histogram::mean_us));
                summary["latency_p95_us"] = json!(latency
                    .as_ref()
                    .filter(|histogram| histogram.samples() >= 20)
                    .and_then(|histogram| histogram.quantile_us(95.0)));
                summary["running_mean_us"] = json!(running.as_ref().and_then(Histogram::mean_us));
                summary["interval_latency_samples"] =
                    json!(latency.as_ref().map(Histogram::samples));
            }
            FamilyKind::Tasks => {
                let delay = self.aggregate_delta("explore_task_delay", elapsed_ns)?;
                summary["delay_mean_us"] = json!(delay.as_ref().and_then(Histogram::mean_us));
                summary["interval_latency_samples"] = json!(delay.as_ref().map(Histogram::samples));
            }
            FamilyKind::Wakers => {
                let latency = self.aggregate_delta("explore_waker_latency", elapsed_ns)?;
                summary["latency_mean_us"] = json!(latency.as_ref().and_then(Histogram::mean_us));
                summary["interval_latency_samples"] =
                    json!(latency.as_ref().map(Histogram::samples));
                summary["wakeups_seen_total"] = json!(health.waker_wakeups_seen);
                summary["selected_wakeups_total"] = json!(health.waker_selected_wakeups);
                summary["origins_seen_total"] = json!(health.waker_origins_seen);
                summary["origins_selected_total"] = json!(health.waker_origins_selected);
                summary["successes_without_sampled_origin_total"] =
                    json!(health.waker_origins_missing);
                summary["origin_missing_note"] = json!("Includes intentionally unselected waking contexts and LRU origin-state eviction; not an exact dropped-event count");
                summary["completed_samples_total"] = json!(health.waker_matched_samples);
                summary["selected_without_completion_total"] = json!(health
                    .waker_selected_wakeups
                    .checked_sub(health.waker_matched_samples));
                summary["completion_note"] = json!("Joined successful wakeups without completion include still-runnable, exiting, and LRU-loss cases; this is not an exact loss counter");
                summary["per_second"] = json!(counter_interval(
                    health.waker_selected_wakeups,
                    self.previous_health
                        .map(|previous| previous.waker_selected_wakeups),
                    elapsed_ns
                )
                .map(|interval| interval.per_second));
                summary["observed_per_second"] = json!(counter_interval(
                    health.waker_wakeups_seen,
                    self.previous_health
                        .map(|previous| previous.waker_wakeups_seen),
                    elapsed_ns
                )
                .map(|interval| interval.per_second));
            }
            _ => return Ok(()),
        }
        summary["history_scope"] = json!("interval deltas of non-evicting per-CPU sampled aggregate histograms; independent of retained row admission");
        summary["quantile_sample_floor"] = json!({"p95":20,"p99":100});
        Ok(())
    }

    fn read_dsqs(&mut self, elapsed_ns: Option<u64>, summary: &mut Value) -> Result<Vec<Value>> {
        let entries = read_map(
            self.object.as_ref().unwrap(),
            "explore_dsqs",
            self.kind.capacity(self.cpu_limit),
        )?;
        summary["move_policy"] = json!("Iterator move calls are counted as attempts; destinations are not verified, so moved queue-residence cycles are excluded");
        let mut rows = Vec::with_capacity(entries.len());
        let mut latency = Histogram::default();
        let mut running = Histogram::default();
        let mut depth_samples = 0u64;
        let mut depth_total = 0u64;
        let mut insert_total = 0u64;
        let mut move_total = 0u64;
        for (key, bytes) in &entries {
            let dsq_id: u64 = decode(key)?;
            let raw: RawDsq = decode(bytes)?;
            let previous = self
                .previous_rows
                .get(key)
                .and_then(|value| decode::<RawDsq>(value).ok());
            insert_total = insert_total.saturating_add(raw.insert_events);
            move_total = move_total.saturating_add(raw.move_events);
            if elapsed_ns.is_some() {
                if let Some(previous) = previous {
                    if let Some(delta) =
                        raw.latency.histogram().delta(&previous.latency.histogram())
                    {
                        latency.merge(&delta);
                    }
                    if let Some(delta) = raw.run.histogram().delta(&previous.run.histogram()) {
                        running.merge(&delta);
                    }
                    if let (Some(samples), Some(total)) = (
                        raw.depth_samples.checked_sub(previous.depth_samples),
                        raw.depth_total.checked_sub(previous.depth_total),
                    ) {
                        depth_samples = depth_samples.saturating_add(samples);
                        depth_total = depth_total.saturating_add(total);
                    }
                }
            }
            let interval = counter_interval(
                raw.insert_events.saturating_add(raw.move_events),
                previous.map(|old| old.insert_events.saturating_add(old.move_events)),
                elapsed_ns,
            );
            rows.push(json!({
                "dsq_id": dsq_id.to_string(), "dsq_hex": format!("0x{dsq_id:016x}"),
                "insert_events": raw.insert_events, "move_events": raw.move_events,
                "interval_count": interval.map(|value| value.count), "per_second": interval.map(|value| value.per_second),
                "residence_samples": raw.latency.histogram().samples(),
                "latency": histogram_json(&raw.latency.histogram()),
                "depth": { "samples": raw.depth_samples,
                    "mean": (raw.depth_samples > 0).then(|| raw.depth_total as f64 / raw.depth_samples as f64),
                    "last": (raw.depth_samples > 0).then_some(raw.depth_last),
                    "max": (raw.depth_samples > 0).then_some(raw.depth_max),
                    "observed_at": "sampled transition to running; queue excludes the now-running task" },
                "run": histogram_json(&raw.run.histogram()),
                "latency_definition": "last direct insertion call to first running transition; unverified iterator-move cycles excluded",
            }));
        }
        rows.sort_by(|left, right| {
            right["residence_samples"]
                .as_u64()
                .cmp(&left["residence_samples"].as_u64())
                .then_with(|| left["dsq_id"].as_str().cmp(&right["dsq_id"].as_str()))
        });
        summary["total_insert_events"] = json!(insert_total);
        summary["total_move_events"] = json!(move_total);
        summary["latency_mean_us"] = json!(latency.mean_us());
        summary["latency_p95_us"] = json!(latency.quantile_us(95.0));
        summary["depth_mean"] =
            json!((depth_samples > 0).then(|| depth_total as f64 / depth_samples as f64));
        summary["running_mean_us"] = json!(running.mean_us());
        self.previous_rows = entries;
        Ok(rows)
    }

    fn read_tasks(
        &mut self,
        now_ns: u64,
        elapsed_ns: Option<u64>,
        topology: &TopologyView,
        summary: &mut Value,
    ) -> Result<Vec<Value>> {
        let entries = read_map(
            self.object.as_ref().unwrap(),
            "explore_tasks",
            TASK_CAPACITY,
        )?;
        let mut candidates = entries.into_iter().collect::<Vec<_>>();
        // Residency is only a priority hint for bounded procfs reads, never a CPU usage metric.
        candidates.sort_by(|(_, left), (_, right)| {
            let left = decode::<RawTask>(left).ok();
            let right = decode::<RawTask>(right).ok();
            right
                .map(|raw| (raw.running_since_ns != 0, raw.runtime_ns, raw.last_seen_ns))
                .cmp(&left.map(|raw| (raw.running_since_ns != 0, raw.runtime_ns, raw.last_seen_ns)))
        });
        let delay_available = self.attached_programs.contains("ex_tasks_wakeup");
        let dsq_available = self
            .attached_programs
            .iter()
            .any(|name| name.starts_with("ex_task_"));
        summary["delay_available"] = json!(delay_available);
        summary["dsq_delay_available"] = json!(dsq_available);
        summary["cgroup_identity"] = json!("cgroup v2 kernfs inode read from task membership at the latest observed event; path not resolved");
        summary["cpu_scope"] = json!("sum of validated kernel CPU runtime rates for up to 128 retained sampled thread identities; no extrapolation to all threads");
        summary["cpu_source"] = json!("/proc task schedstat CPU runtime; task birth identity validated before and after reading through a held procfs directory");
        summary["cpu_read_limit"] = json!(ROW_LIMIT);
        summary["counter_scope"] = json!("since this identity was admitted to bounded tracking");
        summary["histogram_scope"] = json!("since this identity was admitted to bounded tracking");
        summary["delay_definition"] =
            json!("successful wakeup to first observed run; already-on-CPU successes excluded");
        summary["dsq_delay_definition"] = json!(
            "last direct DSQ insertion to first run; unverified iterator-move cycles excluded"
        );
        let mut rows = Vec::new();
        let mut runtimes = BTreeMap::new();
        let mut current_rows = BTreeMap::new();
        let mut aggregate_delay = Histogram::default();
        let mut cpu_sum = 0.0;
        let mut cpu_observations = 0usize;
        let mut inconsistent_cpu_observations = 0usize;
        let mut cpu_reads = 0usize;
        let mut cpu_read_failures = 0usize;
        let mut cpu_capped_threads = 0usize;
        for (key, bytes) in candidates {
            let task: RawTaskKey = decode(&key)?;
            let raw: RawTask = decode(&bytes)?;
            if raw.running_since_ns == 0 && now_ns.saturating_sub(raw.last_seen_ns) > STALE_NS {
                object_map(self.object.as_ref().unwrap(), "explore_tasks")?
                    .delete(&key)
                    .ok();
                continue;
            }
            if cpu_reads >= ROW_LIMIT {
                cpu_capped_threads += 1;
                current_rows.insert(key, bytes);
                continue;
            }
            let cpu_read = if cpu_reads < ROW_LIMIT {
                cpu_reads += 1;
                match read_proc_cpu(task.identity()) {
                    Ok(value) => Ok(value),
                    Err(error) => {
                        cpu_read_failures += 1;
                        Err(format!("{error:#}"))
                    }
                }
            } else {
                cpu_capped_threads += 1;
                Err("CPU readings are limited to 128 retained sampled threads per interval".into())
            };
            let observed_ns = cpu_read
                .as_ref()
                .map(|(_, observed)| *observed)
                .unwrap_or(monotonic_ns()?);
            let runtime = cpu_read.as_ref().ok().map(|(runtime, _)| *runtime);
            let baseline = self.previous_runtime.get(&task.identity()).copied();
            let task_elapsed = baseline.and_then(|(_, at)| observed_ns.checked_sub(at));
            let usage = runtime.and_then(|runtime| {
                cpu_equivalents(runtime, baseline.map(|(runtime, _)| runtime), task_elapsed)
            });
            // A single identity cannot execute concurrently on multiple CPUs. Racing map fields
            // can violate this invariant; omit such a sample rather than clamping it to a fake value.
            let usage = match usage {
                Some(value) if value > 1.05 => {
                    inconsistent_cpu_observations += 1;
                    None
                }
                value => value,
            };
            if let Some(value) = usage {
                cpu_sum += value;
                cpu_observations += 1;
            }
            let previous = self
                .previous_rows
                .get(&key)
                .and_then(|value| decode::<RawTask>(value).ok())
                .filter(|previous| math::same_admission(raw.first_seen_ns, previous.first_seen_ns));
            if elapsed_ns.is_some() {
                if let Some(previous) = previous {
                    if let Some(delta) = raw.delay.histogram().delta(&previous.delay.histogram()) {
                        aggregate_delay.merge(&delta);
                    }
                }
            }
            let interval =
                counter_interval(raw.switches, previous.map(|old| old.switches), elapsed_ns);
            let cpu = (raw.last_running_at_ns != 0).then_some(raw.cpu);
            let (llc, node) = cpu.map_or((None, None), |cpu| cpu_location(topology, cpu));
            rows.push(json!({
                "pid": task.pid, "tgid": raw.tgid, "start_time_ns": task.start_time_ns.to_string(),
                "comm": comm(&raw.comm), "cpu": cpu, "llc": llc, "node": node,
                "cgroup_id": (raw.cgroup_id != 0).then(|| raw.cgroup_id.to_string()), "cgroup_observed_at_unix_ms": wall_time(raw.last_seen_ns, observed_ns, unix_ms()),
                "tracked_since_unix_ms": wall_time(raw.first_seen_ns, observed_ns, unix_ms()),
                "cpu_equivalents": usage, "runtime_ns": runtime, "runtime_scope": "since thread birth",
                "observed_residency_ns": raw.runtime_ns,
                "cpu_error": cpu_read.as_ref().err(),
                "cpu_identity_validation": "PID and kernel birth time rounded to clock ticks; held procfs directory",
                "delay": delay_available.then(|| histogram_json(&raw.delay.histogram())),
                "dsq_delay": dsq_available.then(|| histogram_json(&raw.dsq_delay.histogram())),
                "wakeups": delay_available.then_some(raw.wakeups), "switches": raw.switches,
                "interval_count": interval.map(|value| value.count), "per_second": interval.map(|value| value.per_second),
                "cpu_observed_at_unix_ms": cpu_read.as_ref().ok().map(|(_, at)| wall_time(*at, observed_ns, unix_ms())).flatten(),
                "last_running_at_unix_ms": wall_time(raw.last_running_at_ns, observed_ns, unix_ms()),
            }));
            if let Some(runtime) = runtime {
                runtimes.insert(task.identity(), (runtime, observed_ns));
            }
            current_rows.insert(key, bytes);
        }
        rows.sort_by(|left, right| {
            right["cpu_equivalents"]
                .as_f64()
                .unwrap_or(-1.0)
                .total_cmp(&left["cpu_equivalents"].as_f64().unwrap_or(-1.0))
                .then_with(|| {
                    right["delay"]["p95_us"]
                        .as_f64()
                        .unwrap_or(-1.0)
                        .total_cmp(&left["delay"]["p95_us"].as_f64().unwrap_or(-1.0))
                })
                .then_with(|| left["pid"].as_u64().cmp(&right["pid"].as_u64()))
        });
        summary["cpu_equivalents"] = json!((cpu_observations > 0).then_some(cpu_sum));
        summary["cpu_interval_thread_count"] = json!(cpu_observations);
        summary["inconsistent_cpu_samples"] = json!(inconsistent_cpu_observations);
        summary["cpu_read_failures"] = json!(cpu_read_failures);
        summary["cpu_capped_threads"] = json!(cpu_capped_threads);
        summary["tracked_count"] = json!(current_rows.len());
        summary["delay_mean_us"] = json!(aggregate_delay.mean_us());
        self.previous_runtime = runtimes;
        self.previous_rows = current_rows;
        Ok(rows)
    }

    fn read_wakers(
        &mut self,
        now_ns: u64,
        elapsed_ns: Option<u64>,
        topology: &TopologyView,
        summary: &mut Value,
    ) -> Result<Vec<Value>> {
        let mut entries = read_map(
            self.object.as_ref().unwrap(),
            "explore_wakers",
            TASK_CAPACITY,
        )?;
        let mut expired = Vec::new();
        let mut candidates = Vec::with_capacity(entries.len());
        let mut wakeups_total = 0u64;
        summary["waker_definition"] = json!("current task and CPU at original sched_waking context (fork parent for wakeup_new); interrupt origins can identify the interrupted task");
        summary["latency_definition"] = json!("joined successful wakeup to first run; original source preserved across deferred target activation; already-on-CPU successes excluded");
        summary["locality_definition"] = json!("exclusive categories: same CPU; different CPU same LLC; different LLC same NUMA node; different NUMA node; unknown");
        summary["locality_scope"] = json!("matched sampled wakeup-to-run cycles");
        summary["counter_scope"] = json!(
            "since current pair admission to bounded LRU tracking; row totals cover retained pairs"
        );
        summary["histogram_scope"] = json!("since current pair admission to bounded LRU tracking");
        summary["row_selection"] =
            json!("largest sampled wakeup increments; new admissions ranked by retained count");
        for (key, bytes) in &entries {
            let raw: RawWaker = decode(bytes)?;
            if now_ns.saturating_sub(raw.last_seen_ns) > STALE_NS
                && raw.wakeups == raw.latency.histogram().samples()
            {
                object_map(self.object.as_ref().unwrap(), "explore_wakers")?
                    .delete(key)
                    .ok();
                expired.push(key.clone());
                continue;
            }
            wakeups_total = wakeups_total.saturating_add(raw.wakeups);
            let previous = self
                .previous_rows
                .get(key)
                .and_then(|value| decode::<RawWaker>(value).ok())
                .filter(|previous| math::same_admission(raw.first_seen_ns, previous.first_seen_ns));
            let interval = counter_interval(
                raw.wakeups,
                previous.map(|previous| previous.wakeups),
                elapsed_ns,
            );
            candidates.push((key, raw, interval));
        }
        summary["tracked_count"] = json!(candidates.len());
        let candidates = math::select_top_rows(candidates, ROW_LIMIT, |left, right| {
            right
                .2
                .map(|interval| interval.count)
                .unwrap_or(right.1.wakeups)
                .cmp(
                    &left
                        .2
                        .map(|interval| interval.count)
                        .unwrap_or(left.1.wakeups),
                )
                .then_with(|| right.1.wakeups.cmp(&left.1.wakeups))
                .then_with(|| left.0.cmp(right.0))
        });
        let mut rows = Vec::with_capacity(candidates.len());
        let observed_ns = monotonic_ns()?;
        let observed_unix_ms = unix_ms();
        for (key, raw, interval) in candidates {
            let pair: RawPairKey = decode(key)?;
            let (waker_llc, waker_node) = cpu_location(topology, raw.waker_cpu);
            let wakee_cpu = (raw.latency.histogram().samples() > 0).then_some(raw.wakee_cpu);
            let (wakee_llc, wakee_node) =
                wakee_cpu.map_or((None, None), |cpu| cpu_location(topology, cpu));
            rows.push(json!({
                "waker_pid": pair.waker.pid, "waker_tgid": raw.waker_tgid,
                "waker_start_time_ns": pair.waker.start_time_ns.to_string(), "waker_comm": comm(&raw.waker_comm),
                "wakee_pid": pair.wakee.pid, "wakee_tgid": raw.wakee_tgid,
                "wakee_start_time_ns": pair.wakee.start_time_ns.to_string(), "wakee_comm": comm(&raw.wakee_comm),
                "waker_cpu": raw.waker_cpu, "wakee_cpu": wakee_cpu,
                "waker_llc": waker_llc, "wakee_llc": wakee_llc, "waker_node": waker_node, "wakee_node": wakee_node,
                "wakeups": raw.wakeups, "latency": histogram_json(&raw.latency.histogram()),
                "tracked_since_unix_ms": wall_time(raw.first_seen_ns, observed_ns, observed_unix_ms),
                "interval_count": interval.map(|value| value.count), "per_second": interval.map(|value| value.per_second),
                "same_cpu": raw.same_cpu, "same_llc": raw.same_llc, "cross_llc": raw.cross_llc,
                "cross_numa": raw.cross_numa, "unknown_locality": raw.unknown_locality,
            }));
        }
        for key in expired {
            entries.remove(&key);
        }
        summary["wakeups_total"] = json!(wakeups_total);
        self.previous_rows = entries;
        Ok(rows)
    }

    fn read_ipis(
        &mut self,
        elapsed_ns: Option<u64>,
        topology: &TopologyView,
        health: RawHealth,
        summary: &mut Value,
    ) -> Result<Vec<Value>> {
        let entries = read_map(
            self.object.as_ref().unwrap(),
            "explore_ipis",
            self.kind.capacity(self.cpu_limit),
        )?;
        let mut candidates = Vec::with_capacity(entries.len());
        let mut current_counts = HashMap::with_capacity(entries.len());
        let mut total = 0u64;
        for (key, bytes) in &entries {
            let pair: RawIpiKey = decode(key)?;
            let count: u64 = decode(bytes)?;
            total = total.saturating_add(count);
            let identity = (pair.source_cpu, pair.target_cpu);
            let previous = self.previous_ipis.get(&identity).copied();
            let interval = counter_interval(count, previous, elapsed_ns);
            candidates.push((pair, count, interval));
            current_counts.insert(identity, count);
        }
        summary["tracked_count"] = json!(candidates.len());
        let candidates = math::select_top_rows(candidates, ROW_LIMIT, |left, right| {
            right
                .2
                .map(|interval| interval.count)
                .unwrap_or(right.1)
                .cmp(&left.2.map(|interval| interval.count).unwrap_or(left.1))
                .then_with(|| right.1.cmp(&left.1))
                .then_with(|| left.0.source_cpu.cmp(&right.0.source_cpu))
                .then_with(|| left.0.target_cpu.cmp(&right.0.target_cpu))
        });
        let mut rows = Vec::with_capacity(candidates.len());
        for (pair, count, interval) in candidates {
            let (llc_from, numa_from) = cpu_location(topology, pair.source_cpu);
            let (llc_to, numa_to) = cpu_location(topology, pair.target_cpu);
            rows.push(json!({
                "source_cpu": pair.source_cpu, "target_cpu": pair.target_cpu, "count": count,
                "interval_count": interval.map(|value| value.count), "per_second": interval.map(|value| value.per_second),
                "llc_from": llc_from, "llc_to": llc_to, "numa_from": numa_from, "numa_to": numa_to,
            }));
        }
        let interval = counter_interval(
            health.ipi_targets,
            self.previous_health.map(|old| old.ipi_targets),
            elapsed_ns,
        );
        summary["per_second"] = json!(interval.map(|value| value.per_second));
        summary["interval_count"] = json!(interval.map(|value| value.count));
        summary["total"] = json!(health.ipi_targets);
        summary["stored_pair_total"] = json!(total);
        summary["lost_targets_total"] =
            json!((health.ipi_mask_read_failures == 0).then_some(health.tracking_failures));
        summary["map_lost_targets_total"] = json!(health.tracking_failures);
        summary["loss_definition"] = json!("map insertion failures count exact lost targets; a failed cpumask read loses an unknown number of targets");
        summary["cpumask_read_failures_total"] = json!(health.ipi_mask_read_failures);
        summary["send_cpu_events_total"] = json!(health.ipi_send_cpu_events);
        summary["send_cpumask_events_total"] = json!(health.ipi_send_cpumask_events);
        summary["send_cpu_available"] = json!(self.attached_programs.contains("ex_ipi_send_cpu"));
        summary["send_cpumask_available"] =
            json!(self.attached_programs.contains("ex_ipi_send_cpumask"));
        summary["cpumask_cpu_limit"] = json!(self.cpu_limit.min(CPU_CAPACITY));
        summary["cpumask_truncated"] = json!(self.cpu_limit > CPU_CAPACITY);
        summary["definition"] = json!("one observed IPI notification per target CPU; vector delivery and handled interrupts are not counted");
        summary["row_selection"] = json!(
            "largest observed interval target-pair counts; only top128 display rows formatted"
        );
        self.previous_ipis = current_counts;
        Ok(rows)
    }

    fn read_pressure(
        &self,
        _now_ns: u64,
        topology: &TopologyView,
        summary: &mut Value,
    ) -> Result<Vec<Value>> {
        let entries = read_map(
            self.object.as_ref().unwrap(),
            "explore_pressure",
            CPU_CAPACITY as usize,
        )?;
        let now_ns = monotonic_ns()?;
        let now_unix_ms = unix_ms();
        let mut rows = Vec::with_capacity(entries.len());
        let mut maximum: Option<u64> = None;
        for (key, bytes) in entries {
            let cpu: u32 = decode(&key)?;
            let raw: RawPressure = decode(&bytes)?;
            let (llc, node) = cpu_location(topology, cpu);
            maximum = Some(maximum.map_or(raw.pressure, |previous| previous.max(raw.pressure)));
            rows.push(json!({
                "cpu": cpu, "llc": llc, "node": node, "pressure": raw.pressure,
                "capacity_scale": 1024, "last_update_unix_ms": wall_time(raw.updated_at_ns, now_ns, now_unix_ms),
                "age_ms": now_ns.saturating_sub(raw.updated_at_ns) as f64 / 1_000_000.0,
            }));
        }
        rows.sort_by_key(|row| row["cpu"].as_u64().unwrap_or(u64::MAX));
        summary["max_pressure"] = json!(maximum);
        summary["capacity_scale"] = json!(1024);
        summary["observed_cpus"] = json!(rows.len());
        summary["host_cpus"] = json!(topology.cpu_count);
        summary["coverage"] = json!("latest update for each target CPU observed since attachment; initial CPU values are unknown");
        summary["target_cpu_identity"] =
            json!("tracepoint argument, not the CPU executing the tracepoint");
        Ok(rows)
    }

    fn read_scx(&mut self, elapsed_ns: Option<u64>, summary: &mut Value) -> Result<Vec<Value>> {
        let mut raw = RawScx::default();
        let context = unsafe {
            std::slice::from_raw_parts_mut(
                (&mut raw as *mut RawScx).cast::<u8>(),
                size_of::<RawScx>(),
            )
        };
        let program = self
            .object
            .as_ref()
            .unwrap()
            .progs_mut()
            .find(|program| program.name() == "ex_collect_scx_events")
            .context("SCX events read program is missing")?;
        let return_value = program
            .test_run(ProgramInput {
                context_in: Some(context),
                ..Default::default()
            })
            .context("reading kernel sched_ext event counters")?
            .return_value;
        if return_value != 0 {
            bail!(
                "Kernel scx_bpf_events is unsupported or read failed (return {})",
                return_value as i32
            );
        }
        if raw.supported_mask == 0 {
            bail!("Kernel scx_event_stats has none of the requested fields");
        }
        let mut rows = Vec::new();
        let mut rate = 0.0;
        let mut rate_count = 0usize;
        for (index, name) in SCX_NAMES.iter().enumerate() {
            if raw.supported_mask & (1 << index) == 0 {
                continue;
            }
            if raw.counts[index] > i64::MAX as u64 {
                bail!("Kernel {name} reported a negative counter");
            }
            let previous = self
                .previous_scx
                .filter(|old| old.supported_mask & (1 << index) != 0)
                .map(|old| old.counts[index]);
            let interval = counter_interval(raw.counts[index], previous, elapsed_ns);
            if let Some(interval) = interval {
                rate += interval.per_second;
                rate_count += 1;
            }
            rows.push(json!({ "name": name, "total": raw.counts[index],
                "interval_count": interval.map(|value| value.count), "per_second": interval.map(|value| value.per_second) }));
        }
        summary["counter_scope"] =
            json!("kernel scheduler session; counters may predate optional observer attachment");
        summary["supported_mask"] = json!(raw.supported_mask);
        summary["unsupported_fields"] = json!(SCX_NAMES
            .iter()
            .enumerate()
            .filter(|(index, _)| raw.supported_mask & (1 << index) == 0)
            .map(|(_, name)| name)
            .collect::<Vec<_>>());
        summary["per_second"] = json!((rate_count > 0).then_some(rate));
        self.previous_scx = Some(raw);
        Ok(rows)
    }
}

impl Drop for ProbeFamily {
    fn drop(&mut self) {
        self.links.clear();
    }
}

/// Optional independent observers. Failure in one family never prevents another
/// family from loading, or changes the existing inspector's observer attachment.
pub struct ExploreProbeCollector {
    topology: TopologyView,
    support: ProbeSupport,
    families: Vec<ProbeFamily>,
    sample_seq: u64,
}

impl ExploreProbeCollector {
    pub fn new(topology: TopologyView) -> Result<Self> {
        let support = ProbeSupport::discover(&topology);
        let families = [
            FamilyKind::Dsqs,
            FamilyKind::Tasks,
            FamilyKind::Wakers,
            FamilyKind::Scx,
            FamilyKind::Ipis,
            FamilyKind::Pressure,
        ]
        .into_iter()
        .map(|kind| ProbeFamily::new(kind, &support, &topology))
        .collect();
        Ok(Self {
            topology,
            support,
            families,
            sample_seq: 0,
        })
    }

    pub fn collect(&mut self) -> BTreeMap<String, ExploreGroup> {
        self.sample_seq = self.sample_seq.saturating_add(1);
        let now = std::time::Instant::now();
        if self.families.iter().any(|family| family.retry_due(now)) {
            self.support = ProbeSupport::discover(&self.topology);
            for family in &mut self.families {
                if family.retry_due(now) {
                    family.retry(&self.support, &self.topology);
                }
            }
        }
        self.families
            .iter_mut()
            .map(|family| {
                (
                    family.kind.key().into(),
                    family.collect(&self.topology, self.sample_seq),
                )
            })
            .collect()
    }
}

fn object_map<'a>(object: &'a Object, name: &str) -> Result<Map<'a>> {
    object
        .maps()
        .find(|map| map.name() == name)
        .with_context(|| format!("Explore BPF map {name} is unavailable"))
}

fn read_map(object: &Object, name: &str, capacity: usize) -> Result<BTreeMap<Vec<u8>, Vec<u8>>> {
    io::read_map(object, name, capacity)
}

fn read_health(object: &Object) -> Result<RawHealth> {
    let map = object_map(object, "explore_health")?;
    let cpus = map
        .lookup_percpu(&0u32.to_ne_bytes(), MapFlags::ANY)?
        .context("Explore health counter is missing")?;
    let mut total = RawHealth::default();
    for bytes in cpus {
        let value: RawHealth = decode(&bytes)?;
        total.tracking_failures = total
            .tracking_failures
            .saturating_add(value.tracking_failures);
        total.state_failures = total.state_failures.saturating_add(value.state_failures);
        total.depth_failures = total.depth_failures.saturating_add(value.depth_failures);
        total.ipi_send_cpu_events = total
            .ipi_send_cpu_events
            .saturating_add(value.ipi_send_cpu_events);
        total.ipi_send_cpumask_events = total
            .ipi_send_cpumask_events
            .saturating_add(value.ipi_send_cpumask_events);
        total.ipi_targets = total.ipi_targets.saturating_add(value.ipi_targets);
        total.ipi_mask_read_failures = total
            .ipi_mask_read_failures
            .saturating_add(value.ipi_mask_read_failures);
        total.ipi_mask_truncated = total
            .ipi_mask_truncated
            .saturating_add(value.ipi_mask_truncated);
        total.waker_wakeups_seen = total
            .waker_wakeups_seen
            .saturating_add(value.waker_wakeups_seen);
        total.waker_selected_wakeups = total
            .waker_selected_wakeups
            .saturating_add(value.waker_selected_wakeups);
        total.waker_matched_samples = total
            .waker_matched_samples
            .saturating_add(value.waker_matched_samples);
        total.waker_origins_seen = total
            .waker_origins_seen
            .saturating_add(value.waker_origins_seen);
        total.waker_origins_selected = total
            .waker_origins_selected
            .saturating_add(value.waker_origins_selected);
        total.waker_origins_missing = total
            .waker_origins_missing
            .saturating_add(value.waker_origins_missing);
        total.waker_running_wakeups = total
            .waker_running_wakeups
            .saturating_add(value.waker_running_wakeups);
        total.task_running_wakeups = total
            .task_running_wakeups
            .saturating_add(value.task_running_wakeups);
        total.dsq_unverified_moves = total
            .dsq_unverified_moves
            .saturating_add(value.dsq_unverified_moves);
        total.task_unverified_moves = total
            .task_unverified_moves
            .saturating_add(value.task_unverified_moves);
    }
    Ok(total)
}

fn read_aggregate_histogram(object: &Object, name: &str) -> Result<Histogram> {
    let map = object_map(object, name)?;
    let cpus = map
        .lookup_percpu(&0u32.to_ne_bytes(), MapFlags::ANY)?
        .context("Sampled aggregate histogram is missing")?;
    let mut result = Histogram::default();
    for bytes in cpus {
        result.merge(&decode::<RawHistogram>(&bytes)?.histogram());
    }
    Ok(result)
}

/// Only integer/byte-array repr(C) types call this helper; all bit patterns are valid.
fn decode<T: Copy>(bytes: &[u8]) -> Result<T> {
    if bytes.len() != size_of::<T>() {
        bail!(
            "Explore BPF ABI size mismatch: expected {}, got {}",
            size_of::<T>(),
            bytes.len()
        );
    }
    Ok(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<T>()) })
}

fn histogram_json(histogram: &Histogram) -> Value {
    // A live map snapshot is not atomic. Even a successful max CAS can be read
    // before a new sample's bucket, so live percentiles always keep bucket bounds.
    let mut quantiles = histogram.clone();
    quantiles.max_known = false;
    let samples = histogram.samples();
    json!({
        "samples": histogram.samples(), "mean_us": histogram.mean_us(),
        "p50_us": quantiles.quantile_us(50.0), "p95_us": (samples >= 20).then(|| quantiles.quantile_us(95.0)).flatten(), "p99_us": (samples >= 100).then(|| quantiles.quantile_us(99.0)).flatten(),
        "max_us": histogram.exact_max_us(), "max_update_failures": histogram.max_update_failures,
        "buckets": histogram.buckets.as_slice(), "bucket_unit": "ns", "bucket_scale": "log2",
        "quantile_method": "bucket upper bound; never clipped to a live maximum",
        "quantile_sample_floor": {"p95":20,"p99":100},
    })
}

fn comm(bytes: &[u8; 16]) -> String {
    String::from_utf8_lossy(
        &bytes[..bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len())],
    )
    .into_owned()
}

fn cpu_location(topology: &TopologyView, cpu: u32) -> (Option<u32>, Option<u32>) {
    topology
        .cpus
        .binary_search_by_key(&cpu, |info| info.cpu)
        .ok()
        .map_or((None, None), |index| {
            (
                Some(topology.cpus[index].llc),
                Some(topology.cpus[index].node),
            )
        })
}

fn cpu_list_limit(value: &str) -> Option<u32> {
    value
        .trim()
        .split(',')
        .filter_map(|item| item.rsplit('-').next()?.trim().parse::<u32>().ok())
        .max()?
        .checked_add(1)
}

fn wall_time(event_ns: u64, now_ns: u64, now_unix_ms: u64) -> Option<u64> {
    let age_ns = now_ns.checked_sub(event_ns)?;
    now_unix_ms.checked_sub(age_ns / 1_000_000)
}

fn monotonic_ns() -> Result<u64> {
    let mut timestamp = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut timestamp) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("reading monotonic clock for optional probe interval");
    }
    Ok((timestamp.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(timestamp.tv_nsec as u64))
}

fn read_proc_cpu(identity: TaskIdentity) -> Result<(u64, u64)> {
    let hertz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if hertz <= 0 {
        bail!("Kernel clock tick frequency is unavailable");
    }
    read_proc_cpu_at(
        std::path::Path::new(&format!("/proc/{}", identity.pid)),
        identity,
        hertz as u64,
    )
}

fn read_proc_cpu_at(
    directory: &std::path::Path,
    identity: TaskIdentity,
    hertz: u64,
) -> Result<(u64, u64)> {
    let held_directory =
        fs::File::open(directory).context("opening identified task's procfs directory")?;
    // Pin the procfs directory so replacing /proc/<pid> during these reads cannot
    // silently redirect the CPU runtime read to a newly created task with that PID.
    let anchored =
        std::path::PathBuf::from(format!("/proc/self/fd/{}", held_directory.as_raw_fd()));
    let before = fs::read_to_string(anchored.join("stat"))
        .context("reading task birth identity before CPU runtime")?;
    let start_ticks =
        math::proc_start_ticks(&before).context("malformed task /proc stat identity")?;
    if !math::proc_identity_matches(identity, start_ticks, hertz) {
        bail!(
            "Task PID {} was reused or its birth identity does not match the BPF observation",
            identity.pid
        );
    }
    let runtime = fs::read_to_string(anchored.join("schedstat"))
        .context("reading kernel task CPU runtime")?;
    let runtime_ns = math::schedstat_runtime_ns(&runtime)
        .context("malformed /proc task schedstat CPU runtime")?;
    let after = fs::read_to_string(anchored.join("stat"))
        .context("revalidating task birth identity after CPU runtime")?;
    let after_ticks =
        math::proc_start_ticks(&after).context("malformed revalidated task /proc stat identity")?;
    if after_ticks != start_ticks || !math::proc_identity_matches(identity, after_ticks, hertz) {
        bail!("Task identity changed while reading CPU runtime");
    }
    Ok((runtime_ns, monotonic_ns()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::explore_bpf_skel::types;

    #[test]
    fn decoding_sizes_match_generated_bpf_map_abi() {
        assert_eq!(
            size_of::<RawTaskKey>(),
            size_of::<types::explore_task_key>()
        );
        assert_eq!(size_of::<RawDsq>(), size_of::<types::explore_dsq_metrics>());
        assert_eq!(
            size_of::<RawTask>(),
            size_of::<types::explore_task_metrics>()
        );
        assert_eq!(
            size_of::<RawPairKey>(),
            size_of::<types::explore_pair_key>()
        );
        assert_eq!(
            size_of::<RawWaker>(),
            size_of::<types::explore_waker_metrics>()
        );
        assert_eq!(size_of::<RawIpiKey>(), size_of::<types::explore_ipi_key>());
        assert_eq!(
            size_of::<RawPressure>(),
            size_of::<types::explore_pressure_value>()
        );
        assert_eq!(size_of::<RawHealth>(), size_of::<types::explore_health>());
        assert_eq!(size_of::<RawScx>(), size_of::<types::explore_scx_result>());
    }

    #[test]
    fn legacy_and_versioned_insert_symbols_never_attach_duplicate_aliases() {
        let support = ProbeSupport {
            symbols: [
                "scx_bpf_dsq_insert___v2",
                "scx_bpf_dsq_insert",
                "scx_bpf_dispatch",
                "__scx_bpf_dsq_insert_vtime",
                "scx_bpf_dsq_insert_vtime",
                "scx_bpf_dispatch_vtime",
                "scx_bpf_dsq_move",
                "scx_bpf_dispatch_from_dsq",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
            tracepoints: BTreeSet::new(),
            cpu_limit: 16,
        };
        assert_eq!(
            support.insertion_programs("ex_dsq"),
            ["ex_dsq_insert_v2", "ex_dsq_insert_args", "ex_dsq_move"]
                .into_iter()
                .map(str::to_owned)
                .collect()
        );
    }

    #[test]
    fn unavailable_ipi_and_pressure_symbols_do_not_block_task_selection() {
        let support = ProbeSupport {
            symbols: BTreeSet::new(),
            tracepoints: ["sched_switch"].into_iter().map(str::to_owned).collect(),
            cpu_limit: 2,
        };
        assert_eq!(
            support.programs(FamilyKind::Tasks).unwrap(),
            ["ex_tasks_switch"].into_iter().map(str::to_owned).collect()
        );
        assert!(support.programs(FamilyKind::Ipis).is_err());
        assert!(support.programs(FamilyKind::Pressure).is_err());
        assert!(support.programs(FamilyKind::Wakers).is_err());
    }

    #[test]
    fn unknown_cpu_locality_is_null_and_not_cpu_zero() {
        let topology = TopologyView::from_cpus(Vec::new()).unwrap();
        assert_eq!(cpu_location(&topology, 7), (None, None));
    }

    #[test]
    fn sparse_possible_cpu_ids_bound_cpumask_by_highest_id() {
        assert_eq!(cpu_list_limit("0-7,80-95\n"), Some(96));
        assert_eq!(cpu_list_limit(""), None);
    }

    #[test]
    fn dsq_storage_covers_cpu_local_queues_without_expanding_display_rows() {
        let topology = TopologyView::from_cpus(Vec::new()).unwrap();
        for (cpu_limit, capacity) in [(316, 888), (96, 448), (0, 256), (u32::MAX, 16384)] {
            let support = ProbeSupport {
                symbols: BTreeSet::new(),
                tracepoints: BTreeSet::new(),
                cpu_limit,
            };
            let family = ProbeFamily::new(FamilyKind::Dsqs, &support, &topology);
            let summary = family.summary(None, RawHealth::default());
            assert_eq!(summary["map_capacity"], capacity, "CPU limit {cpu_limit}");
            assert_eq!(summary["row_limit"], 256);
        }
    }

    #[test]
    fn ipi_storage_covers_directed_cpu_pairs_with_a_bounded_allocation() {
        let topology = TopologyView::from_cpus(Vec::new()).unwrap();
        for (cpu_limit, capacity) in [(316, 99856), (96, 9216), (0, 1), (u32::MAX, 1048576)] {
            let support = ProbeSupport {
                symbols: BTreeSet::new(),
                tracepoints: BTreeSet::new(),
                cpu_limit,
            };
            let family = ProbeFamily::new(FamilyKind::Ipis, &support, &topology);
            let summary = family.summary(None, RawHealth::default());
            assert_eq!(summary["map_capacity"], capacity, "CPU limit {cpu_limit}");
            assert_eq!(summary["row_limit"], 128);
        }
    }

    #[test]
    fn retry_refreshes_cpu_bounds_before_attachment_selection() {
        let topology = TopologyView::from_cpus(Vec::new()).unwrap();
        for (initial, possible, limit, ipi_capacity, dsq_capacity, scan_limit) in [
            (2, "0-2", 3, 9, 262, 3),
            (3, "0-1", 2, 4, 260, 2),
            (2, "0-7,80-95", 96, 9216, 448, 96),
            (96, "0-3,8", 9, 81, 274, 9),
            (2, "0-7,8191", 8192, 1048576, 16384, 4096),
        ] {
            let initial_support = ProbeSupport {
                symbols: BTreeSet::new(),
                tracepoints: BTreeSet::new(),
                cpu_limit: initial,
            };
            let refreshed_support = ProbeSupport {
                symbols: BTreeSet::new(),
                tracepoints: BTreeSet::new(),
                cpu_limit: cpu_list_limit(possible).unwrap(),
            };
            for (kind, capacity) in [
                (FamilyKind::Ipis, ipi_capacity),
                (FamilyKind::Dsqs, dsq_capacity),
            ] {
                let mut family = ProbeFamily::new(kind, &initial_support, &topology);
                family.retry(&refreshed_support, &topology);
                assert_eq!(
                    family.summary(None, RawHealth::default())["map_capacity"],
                    capacity,
                    "retry from {initial} CPUs to {possible} for {kind:?}"
                );
                assert_eq!(family.cpu_limit, limit);
                assert_eq!(family.cpu_limit.min(CPU_CAPACITY), scan_limit);
            }
        }
    }

    #[test]
    fn malformed_map_values_are_source_errors() {
        assert!(decode::<RawHealth>(&[0u8; 4]).is_err());
        assert!(decode::<u64>(&[0u8; 16]).is_err());
    }

    #[test]
    fn future_event_timestamps_are_not_relabelled_as_present() {
        assert_eq!(wall_time(4_000_000, 3_000_000, 1000), None);
        assert_eq!(wall_time(1_000_000, 3_000_000, 1000), Some(998));
    }

    #[test]
    fn no_observations_have_null_latency_fields() {
        let value = histogram_json(&Histogram::default());
        assert_eq!(value["samples"], 0);
        assert!(value["mean_us"].is_null());
        assert!(value["p95_us"].is_null());
        assert!(value["max_us"].is_null());
    }

    #[test]
    fn new_probe_family_does_not_claim_a_first_interval() {
        let topology = TopologyView::from_cpus(Vec::new()).unwrap();
        let support = ProbeSupport {
            symbols: BTreeSet::new(),
            tracepoints: BTreeSet::new(),
            cpu_limit: 1,
        };
        let family = ProbeFamily::new(FamilyKind::Dsqs, &support, &topology);
        let value = family.summary(None, RawHealth::default());
        assert_eq!(value["interval_valid"], false);
        assert!(value["interval_ms"].is_null());
        assert!(value["tracking_failures_interval"].is_null());
        assert_eq!(value["sample_rate"], 64);
        assert_eq!(value["cpu_owner_attribution"], "none");
    }

    #[test]
    fn task_cpu_read_uses_schedstat_runtime_and_validates_birth_identity() {
        let directory = std::env::temp_dir().join(format!(
            "mitosis-explore-proc-cpu-{}-{}",
            std::process::id(),
            unix_ms()
        ));
        fs::create_dir(&directory).unwrap();
        let stat = format!(
            "42 (odd ) worker ( name) S {} 123 0 0",
            vec!["0"; 18].join(" ")
        );
        fs::write(directory.join("stat"), stat).unwrap();
        fs::write(directory.join("schedstat"), "2000000 0 5\n").unwrap();
        let identity = TaskIdentity {
            pid: 42,
            start_time_ns: 1_230_000_000,
        };
        let result = read_proc_cpu_at(&directory, identity, 100);
        fs::remove_dir_all(&directory).unwrap();
        assert_eq!(result.unwrap().0, 2_000_000);
    }

    #[test]
    fn task_cpu_read_rejects_a_reused_pid_instead_of_inheriting_runtime() {
        let directory = std::env::temp_dir().join(format!(
            "mitosis-explore-proc-reuse-{}-{}",
            std::process::id(),
            unix_ms()
        ));
        fs::create_dir(&directory).unwrap();
        let stat = format!("42 (worker) S {} 999 0 0", vec!["0"; 18].join(" "));
        fs::write(directory.join("stat"), stat).unwrap();
        fs::write(directory.join("schedstat"), "2000000 0 5\n").unwrap();
        let identity = TaskIdentity {
            pid: 42,
            start_time_ns: 1_230_000_000,
        };
        let result = read_proc_cpu_at(&directory, identity, 100);
        fs::remove_dir_all(&directory).unwrap();
        assert!(result.is_err());
    }

    #[test]
    #[ignore = "Manual native smoke check requires BPF observation privileges; never starts or stops a scheduler"]
    fn native_optional_probe_smoke() {
        let started = std::time::Instant::now();
        let topology = TopologyView::discover().unwrap();
        let mut collector = ExploreProbeCollector::new(topology).unwrap();
        let first = collector.collect();
        let mut last = first.clone();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let mut read_times_ms = Vec::new();
        while std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(250));
            let read_started = std::time::Instant::now();
            last = collector.collect();
            read_times_ms.push(read_started.elapsed().as_secs_f64() * 1000.0);
        }
        let digest = last.iter().map(|(name, group)| (name, json!({
            "available": group.available, "error": group.error, "partial": group.partial,
            "rows": group.rows.len(), "summary": group.summary,
            "first_two_rows": group.rows.iter().take(2).collect::<Vec<_>>(),
        }))).collect::<BTreeMap<_, _>>();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "elapsed_ms": started.elapsed().as_secs_f64() * 1000.0,
                "read_times_ms": read_times_ms, "groups": digest,
            }))
            .unwrap()
        );
        for required in ["tasks", "dsqs", "wakers", "ipis"] {
            let group = &last[required];
            assert!(
                group.available,
                "required Big probe group {required} failed: {:?}",
                group.error
            );
            assert!(group.summary["interval_valid"].as_bool().unwrap_or(false));
        }
        for (name, group) in &last {
            if group.available {
                continue;
            }
            let error = group.error.as_deref().unwrap_or("");
            assert!(
                matches!(name.as_str(), "scx_events" | "pressure"),
                "unexpected unavailable group {name}: {error}"
            );
            assert!(!error.contains("loading independent") && !error.contains("Required"), "present optional probe must not silently fail verifier/attachment: {name}: {error}");
        }
        let first_tasks = &first["tasks"];
        for row in &first_tasks.rows {
            assert!(row["cpu_equivalents"].is_null());
        }
        if !last["tasks"].rows.is_empty() {
            assert!(
                last["tasks"]
                    .rows
                    .iter()
                    .any(|row| row["runtime_ns"].is_u64()),
                "no sampled task CPU runtime identity validated"
            );
        }
    }

    #[test]
    fn untrusted_kprobe_task_arguments_never_reach_task_storage_helper() {
        let object = ObjectBuilder::default()
            .open_memory(EXPLORE_OBJECT)
            .unwrap();
        for program in object
            .progs()
            .filter(|program| program.section().to_string_lossy().starts_with("kprobe/"))
        {
            assert!(
                !program
                    .insns()
                    .iter()
                    .any(|instruction| instruction.code == 0x85
                        && instruction.src_reg() == 0
                        && instruction.imm == 156),
                "{} calls task_storage_get with an untrusted kprobe argument",
                program.name().to_string_lossy()
            );
        }
        for name in ["explore_dsq_states", "explore_task_states"] {
            let map = object.maps().find(|map| map.name() == name).unwrap();
            assert!(matches!(
                map.map_type(),
                libbpf_rs::MapType::Hash | libbpf_rs::MapType::LruHash
            ));
            assert!(map.max_entries() > 0 && map.max_entries() <= 16384);
        }
    }

    #[test]
    fn ipi_mask_iteration_uses_kernel_bounded_loop_helper() {
        let object = ObjectBuilder::default()
            .open_memory(EXPLORE_OBJECT)
            .unwrap();
        let program = object
            .progs()
            .find(|program| program.name() == "ex_ipi_send_cpumask")
            .unwrap();
        assert!(
            program
                .insns()
                .iter()
                .any(|instruction| instruction.code == 0x85
                    && instruction.src_reg() == 0
                    && instruction.imm == 181),
            "cpumask iteration must avoid nested verifier-unrolled CPU loops"
        );
    }

    #[test]
    fn task_and_waker_admission_maps_cannot_freeze_when_old_identities_fill_capacity() {
        let object = ObjectBuilder::default()
            .open_memory(EXPLORE_OBJECT)
            .unwrap();
        for name in [
            "explore_tasks",
            "explore_task_states",
            "explore_wakers",
            "explore_waker_states",
        ] {
            let map = object.maps().find(|map| map.name() == name).unwrap();
            assert_eq!(
                map.map_type(),
                libbpf_rs::MapType::LruHash,
                "{name} must continue admitting recent identities"
            );
            assert_eq!(map.max_entries(), 4096);
        }
    }

    #[test]
    fn bounded_lru_scope_does_not_claim_exact_loss_or_lifetime_pair_counters() {
        let topology = TopologyView::from_cpus(Vec::new()).unwrap();
        let support = ProbeSupport {
            symbols: BTreeSet::new(),
            tracepoints: BTreeSet::new(),
            cpu_limit: 1,
        };
        let family = ProbeFamily::new(FamilyKind::Wakers, &support, &topology);
        let summary = family.summary(None, RawHealth::default());
        assert_eq!(summary["counters_can_reset"], true);
        assert_eq!(summary["storage_evictions_unknown"], true);
        assert!(summary["storage_evictions_total"].is_null());
        assert!(summary["counter_scope"]
            .as_str()
            .unwrap()
            .contains("admission"));
    }

    #[test]
    fn aggregate_latency_history_is_independent_of_lru_row_admission() {
        let object = ObjectBuilder::default()
            .open_memory(EXPLORE_OBJECT)
            .unwrap();
        for name in [
            "explore_dsq_latency",
            "explore_dsq_running",
            "explore_task_delay",
            "explore_waker_latency",
        ] {
            let map = object.maps().find(|map| map.name() == name);
            assert!(
                map.is_some(),
                "{name} is needed so row eviction cannot reset aggregate history"
            );
            let map = map.unwrap();
            assert_eq!(map.map_type(), libbpf_rs::MapType::PercpuArray);
            assert_eq!(map.max_entries(), 1);
        }
    }

    #[test]
    fn live_histogram_quantiles_do_not_clip_to_a_racing_maximum() {
        let mut histogram = Histogram::default();
        histogram.buckets[10] = 20;
        histogram.max_ns = 1500;
        let value = histogram_json(&histogram);
        assert_eq!(value["p95_us"].as_f64(), Some(2.047));
    }

    #[test]
    fn waker_attribution_requires_an_original_waking_context_hook() {
        let object = ObjectBuilder::default()
            .open_memory(EXPLORE_OBJECT)
            .unwrap();
        assert!(
            object
                .progs()
                .any(|program| program.name() == "ex_wakers_waking"),
            "success tracepoints may emit from unrelated deferred target context"
        );
        let support = ProbeSupport {
            symbols: BTreeSet::new(),
            tracepoints: ["sched_switch", "sched_wakeup"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            cpu_limit: 2,
        };
        assert!(
            support.programs(FamilyKind::Wakers).is_err(),
            "origin-less success events cannot identify an original waker"
        );
    }

    #[test]
    fn high_percentiles_require_twenty_and_one_hundred_sampled_events() {
        let mut histogram = Histogram::default();
        histogram.buckets[10] = 19;
        let value = histogram_json(&histogram);
        assert!(value["p95_us"].is_null());
        assert!(value["p99_us"].is_null());
        histogram.buckets[10] = 20;
        let value = histogram_json(&histogram);
        assert_eq!(value["p95_us"].as_f64(), Some(2.047));
        assert!(value["p99_us"].is_null());
        histogram.buckets[10] = 100;
        assert_eq!(histogram_json(&histogram)["p99_us"].as_f64(), Some(2.047));
    }

    #[test]
    fn failed_family_can_retry_inside_the_same_epoch_after_backoff() {
        let topology = TopologyView::from_cpus(Vec::new()).unwrap();
        let support = ProbeSupport {
            symbols: BTreeSet::new(),
            tracepoints: BTreeSet::new(),
            cpu_limit: 1,
        };
        let family = ProbeFamily::new(FamilyKind::Dsqs, &support, &topology);
        assert!(!family.retry_due(std::time::Instant::now()));
        assert!(family.retry_due(std::time::Instant::now() + std::time::Duration::from_secs(31)));
    }
}
