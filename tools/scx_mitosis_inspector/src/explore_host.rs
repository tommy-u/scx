// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-2.0-only

//! Read-only, optional host telemetry for the Explore screen.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::explore_model::ExploreGroup;
use crate::lifecycle::{unix_ms, SampleMeta};
use crate::topology::{CpuInfo, TopologyView};
use serde_json::{json, Value};

const MAX_ATTRIBUTE_BYTES: u64 = 4096;
const MAX_DOMAINS: usize = 4096;
const MAX_IDLE_STATES: usize = 64;
const MAX_SENSOR_ENTRIES: usize = 8192;
const MAX_POWER_DEPTH: usize = 4;
const MAX_BANDWIDTH_CONTROLS: usize = 256;
const MAX_BANDWIDTH_CONTRIBUTIONS: usize = 4096;
const MAX_BANDWIDTH_MONITOR_METADATA: usize = 8192;

pub struct ExploreHostCollector {
    topology: TopologyView,
    paths: HostPaths,
    bandwidth: BTreeMap<PathBuf, CounterSample>,
    bandwidth_members: BTreeMap<String, BTreeSet<u32>>,
    bandwidth_monitors: BTreeMap<String, BTreeMap<String, CounterIdentity>>,
    idle: BTreeMap<(u32, u32), IdleSample>,
    power: BTreeMap<String, PowerSample>,
    domain_topology: Option<BTreeMap<u32, DomainTopology>>,
    metadata: BTreeMap<&'static str, SampleMeta>,
}

struct CounterSample {
    value: u64,
    at: Instant,
    identity: CounterIdentity,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct CounterIdentity {
    device: u64,
    inode: u64,
}
struct IdleSample {
    time_us: u64,
    entries: u64,
    name: String,
    disabled: Option<bool>,
    at: Instant,
}
struct PowerSample {
    energy_uj: u64,
    max_energy_range_uj: Option<u64>,
    at: Instant,
}
struct DomainTopology {
    llc: u32,
    node: u32,
    package: Option<u32>,
    cpus: Vec<u32>,
}

struct CounterReading {
    raw: Option<u64>,
    rate: Option<f64>,
    status: &'static str,
    error: Option<String>,
    identity: Option<CounterIdentity>,
}

struct BandwidthControl {
    path: PathBuf,
    domains: Result<BTreeMap<u32, PathBuf>, String>,
}

struct BandwidthDomainReadings {
    local: CounterReading,
    total: CounterReading,
    occupancy: CounterReading,
}

struct BandwidthInventory {
    controls: BTreeMap<String, BandwidthControl>,
    complete: bool,
    errors: Vec<String>,
}

struct HostPaths {
    cpu: PathBuf,
    resctrl: PathBuf,
    hwmon: PathBuf,
    thermal: PathBuf,
    powercap: PathBuf,
}

impl Default for HostPaths {
    fn default() -> Self {
        Self {
            cpu: "/sys/devices/system/cpu".into(),
            resctrl: "/sys/fs/resctrl".into(),
            hwmon: "/sys/class/hwmon".into(),
            thermal: "/sys/class/thermal".into(),
            powercap: "/sys/class/powercap".into(),
        }
    }
}

impl ExploreHostCollector {
    pub fn new(topology: &TopologyView) -> Self {
        Self {
            topology: topology.clone(),
            paths: HostPaths::default(),
            bandwidth: BTreeMap::new(),
            bandwidth_members: BTreeMap::new(),
            bandwidth_monitors: BTreeMap::new(),
            idle: BTreeMap::new(),
            power: BTreeMap::new(),
            domain_topology: None,
            metadata: BTreeMap::new(),
        }
    }

    pub fn collect(&mut self) -> BTreeMap<String, ExploreGroup> {
        let mut groups = BTreeMap::new();
        let bandwidth = self.collect_bandwidth(Instant::now());
        groups.insert("bandwidth".into(), self.stamp("bandwidth", bandwidth));
        let idle = self.collect_idle(Instant::now());
        groups.insert("idle".into(), self.stamp("idle", idle));
        let thermal = self.collect_thermal();
        groups.insert("thermal".into(), self.stamp("thermal", thermal));
        let power = self.collect_power(Instant::now());
        groups.insert("power".into(), self.stamp("power", power));
        groups
    }

    fn stamp(&mut self, key: &'static str, mut group: ExploreGroup) -> ExploreGroup {
        let now = unix_ms();
        let meta = self.metadata.entry(key).or_default();
        meta.sample_seq = meta.sample_seq.saturating_add(1);
        meta.captured_at_unix_ms = Some(now);
        if group.available {
            meta.last_success_at_unix_ms = Some(now);
        }
        meta.error = if group.available {
            None
        } else {
            group.error.clone()
        };
        group.meta = meta.clone();
        group
    }

    fn collect_bandwidth(&mut self, now: Instant) -> ExploreGroup {
        const SCOPE: &str = "resctrl root + control-group parent aggregates · hardware L3 domains";
        let features = match read_text(&self.paths.resctrl.join("info/L3_MON/mon_features")) {
            Ok(features) => features
                .split_whitespace()
                .map(str::to_string)
                .collect::<BTreeSet<_>>(),
            Err(error) => {
                self.bandwidth.clear();
                self.bandwidth_members.clear();
                self.bandwidth_monitors.clear();
                return ExploreGroup::unavailable(
                    SCOPE,
                    format!("resctrl L3 monitoring is unavailable: {error}"),
                );
            }
        };
        if !["mbm_local_bytes", "mbm_total_bytes", "llc_occupancy"]
            .iter()
            .any(|key| features.contains(*key))
        {
            self.bandwidth.clear();
            self.bandwidth_members.clear();
            self.bandwidth_monitors.clear();
            return ExploreGroup::unavailable(
                SCOPE,
                "resctrl exposes no local bandwidth, total bandwidth, or LLC occupancy monitoring",
            );
        }
        let inventory = discover_bandwidth_controls(&self.paths.resctrl);
        let contribution_count = inventory
            .controls
            .values()
            .filter_map(|control| control.domains.as_ref().ok())
            .map(BTreeMap::len)
            .sum::<usize>();
        if contribution_count > MAX_BANDWIDTH_CONTRIBUTIONS {
            self.bandwidth.clear();
            self.bandwidth_members.clear();
            self.bandwidth_monitors.clear();
            return ExploreGroup::unavailable(SCOPE, format!("resctrl exposes {contribution_count} parent-domain contributions, exceeding the {MAX_BANDWIDTH_CONTRIBUTIONS} sample read limit"));
        }
        let current_members = inventory
            .controls
            .iter()
            .map(|(name, control)| {
                let ids = control
                    .domains
                    .as_ref()
                    .map(|domains| domains.keys().copied().collect())
                    .unwrap_or_else(|_| {
                        self.bandwidth_members
                            .get(name)
                            .cloned()
                            .unwrap_or_default()
                    });
                (name.clone(), ids)
            })
            .collect::<BTreeMap<String, BTreeSet<u32>>>();
        // A removed group contributed at the start of this interval. Its last
        // interval cannot be measured once its end counters disappear. Keep it
        // in the required rate set for one interval, but not in current gauges.
        let mut rate_members = self.bandwidth_members.clone();
        for (name, ids) in &current_members {
            rate_members
                .entry(name.clone())
                .or_default()
                .extend(ids.iter().copied());
        }
        let domain_ids = rate_members
            .values()
            .flatten()
            .copied()
            .collect::<BTreeSet<_>>();
        if self
            .domain_topology
            .as_ref()
            .is_none_or(|map| domain_ids.iter().any(|id| !map.contains_key(id)))
        {
            self.domain_topology = Some(discover_domain_topology(&self.topology, &self.paths.cpu));
        }
        let current_names = current_members.keys().cloned().collect::<Vec<_>>();
        let rate_names = rate_members.keys().cloned().collect::<Vec<_>>();
        let mut rows = Vec::new();
        let mut errors = inventory.errors.clone();
        let mut seen_paths = BTreeSet::new();
        let mut parent_reads = BTreeMap::new();
        let mut monitor_metadata_remaining = MAX_BANDWIDTH_MONITOR_METADATA;
        for (name, control) in &inventory.controls {
            let monitor_path = control.path.join("mon_groups");
            let previous = self.bandwidth_monitors.get(name).cloned();
            let before = read_monitor_fingerprint(&monitor_path, &mut monitor_metadata_remaining);
            if previous.is_none() || before.as_ref().ok() != previous.as_ref() {
                self.invalidate_bandwidth_control(&control.path);
            }
            let mut readings = BTreeMap::new();
            if let Ok(domains) = &control.domains {
                for (id, path) in domains {
                    let local = self.read_bandwidth_counter(
                        path,
                        "mbm_local_bytes",
                        features.contains("mbm_local_bytes"),
                        now,
                        &mut seen_paths,
                    );
                    let total = self.read_bandwidth_counter(
                        path,
                        "mbm_total_bytes",
                        features.contains("mbm_total_bytes"),
                        now,
                        &mut seen_paths,
                    );
                    let occupancy = if features.contains("llc_occupancy") {
                        read_resctrl_gauge(&path.join("llc_occupancy"))
                    } else {
                        missing_counter(
                            "unsupported",
                            "LLC occupancy is not supported by this resctrl source".into(),
                        )
                    };
                    readings.insert(
                        *id,
                        BandwidthDomainReadings {
                            local,
                            total,
                            occupancy,
                        },
                    );
                }
            }
            let after = read_monitor_fingerprint(&monitor_path, &mut monitor_metadata_remaining);
            let confirmed = matches!((&before, &after), (Ok(a), Ok(b)) if a == b);
            let status = if before.is_err() || after.is_err() {
                "unavailable"
            } else if !confirmed
                || previous
                    .as_ref()
                    .is_some_and(|old| Some(old) != before.as_ref().ok())
            {
                "reset"
            } else if previous.is_none() {
                "baseline"
            } else {
                "measured"
            };
            let reason = if status == "unavailable" {
                before.as_ref().err().or(after.as_ref().err()).cloned()
            } else if status == "reset" {
                Some(format!("{}: child monitor membership changed; parent bandwidth interval is unavailable", monitor_path.display()))
            } else {
                None
            };
            if status == "unavailable" || status == "reset" {
                for values in readings.values_mut() {
                    for value in [&mut values.local, &mut values.total] {
                        value.rate = None;
                        if value.raw.is_some() {
                            value.status = status;
                        }
                        if let Some(reason) = &reason {
                            value.error = Some(
                                value
                                    .error
                                    .as_ref()
                                    .map(|old| format!("{old}; {reason}"))
                                    .unwrap_or_else(|| reason.clone()),
                            );
                        }
                    }
                }
            }
            // A mid-read change leaves no trustworthy current baseline. The
            // next stable read primes it; a change between reads can use this
            // complete new parent snapshot and recover on the next interval.
            if !confirmed {
                self.invalidate_bandwidth_control(&control.path);
            }
            match after {
                Ok(fingerprint) => {
                    self.bandwidth_monitors.insert(name.clone(), fingerprint);
                }
                Err(_) => {
                    self.bandwidth_monitors.remove(name);
                }
            }
            parent_reads.extend(
                readings
                    .into_iter()
                    .map(|(id, values)| ((name.clone(), id), values)),
            );
        }
        let mut any_available = false;
        let mut mapped = 0;
        let mut partial = !inventory.complete;
        for domain_id in domain_ids {
            let mut contributions = Vec::new();
            let mut row_errors = Vec::new();
            for control_name in &rate_names {
                let current = inventory.controls.get(control_name);
                let (local, total, occupancy) = if let Some(values) =
                    parent_reads.remove(&(control_name.clone(), domain_id))
                {
                    (values.local, values.total, values.occupancy)
                } else {
                    let reason = match current {
                        Some(control) => control.domains.as_ref().err().cloned().unwrap_or_else(|| format!("resctrl control {control_name}: L3 domain {domain_id} is unavailable")),
                        None if inventory.complete => format!("resctrl control {control_name} was removed during this interval; its final counters are unavailable"),
                        None => format!("resctrl control {control_name} cannot be confirmed because the control inventory is incomplete"),
                    };
                    (
                        missing_counter("unavailable", reason.clone()),
                        missing_counter("unavailable", reason.clone()),
                        missing_counter("unavailable", reason),
                    )
                };
                any_available |=
                    local.raw.is_some() || total.raw.is_some() || occupancy.raw.is_some();
                row_errors.extend(
                    [
                        local.error.clone(),
                        total.error.clone(),
                        occupancy.error.clone(),
                    ]
                    .into_iter()
                    .flatten(),
                );
                contributions.push(json!({
                    "control_group": control_name, "current": current.is_some(),
                    "mbm_local_bytes": local.raw, "mbm_total_bytes": total.raw,
                    "mbm_local_bps": local.rate, "mbm_total_bps": total.rate, "llc_occupancy_bytes": occupancy.raw,
                    "local_status": local.status, "total_status": total.status, "occupancy_status": occupancy.status,
                    "local_error": local.error, "total_error": total.error, "occupancy_error": occupancy.error,
                }));
            }
            let current_contributions = contributions
                .iter()
                .filter(|row| row["current"] == true)
                .cloned()
                .collect::<Vec<_>>();
            let local_rate = inventory
                .complete
                .then(|| sum_complete_f64(&contributions, "mbm_local_bps"))
                .flatten();
            let total_rate = inventory
                .complete
                .then(|| sum_complete_f64(&contributions, "mbm_total_bps"))
                .flatten();
            let occupancy = inventory
                .complete
                .then(|| sum_complete_u64(&current_contributions, "llc_occupancy_bytes"))
                .flatten();
            let raw_local = inventory
                .complete
                .then(|| sum_complete_u64(&current_contributions, "mbm_local_bytes"))
                .flatten();
            let raw_total = inventory
                .complete
                .then(|| sum_complete_u64(&current_contributions, "mbm_total_bytes"))
                .flatten();
            let join = self
                .domain_topology
                .as_ref()
                .and_then(|map| map.get(&domain_id));
            mapped += usize::from(join.is_some());
            if join.is_none() {
                row_errors.push(format!("resctrl domain {domain_id} cannot be matched uniquely to the inspector's L3 topology"));
            }
            partial |= !row_errors.is_empty()
                || local_rate.is_none()
                || total_rate.is_none()
                || occupancy.is_none();
            errors.extend(row_errors.iter().cloned());
            rows.push(json!({
                "domain_id": domain_id, "llc": join.map(|x| x.llc), "node": join.map(|x| x.node),
                "package": join.map(|x| x.package), "cpus": join.map(|x| x.cpus.clone()).unwrap_or_default(),
                "topology_available": join.is_some(), "mbm_local_bytes": raw_local, "mbm_total_bytes": raw_total,
                "mbm_local_bps": local_rate, "mbm_total_bps": total_rate, "llc_occupancy_bytes": occupancy,
                "local_status": aggregate_bandwidth_status(&contributions, "local_status", inventory.complete, local_rate.is_some()),
                "total_status": aggregate_bandwidth_status(&contributions, "total_status", inventory.complete, total_rate.is_some()),
                "occupancy_status": aggregate_bandwidth_status(&current_contributions, "occupancy_status", inventory.complete, occupancy.is_some()),
                "control_group_count": current_names.len(), "control_group_names": current_names,
                "rate_group_count": rate_names.len(), "rate_group_names": rate_names,
                "local_expected_contributions": rate_names.len(), "local_measured_contributions": measured_contributions(&contributions, "mbm_local_bps"),
                "total_expected_contributions": rate_names.len(), "total_measured_contributions": measured_contributions(&contributions, "mbm_total_bps"),
                "occupancy_expected_contributions": current_names.len(), "occupancy_measured_contributions": measured_contributions(&current_contributions, "llc_occupancy_bytes"),
                "contributions": contributions, "error": joined_errors(&row_errors),
            }));
        }
        self.bandwidth.retain(|path, _| seen_paths.contains(path));
        self.bandwidth_monitors
            .retain(|name, _| current_members.contains_key(name));
        self.bandwidth_members = current_members;
        if rows.is_empty() && errors.is_empty() {
            errors.push("resctrl exposes no mon_L3_* monitor domains".into());
        }
        let summary = json!({
            "source": "resctrl", "monitor": "all_control_groups", "domain_count": rows.len(), "mapped_domain_count": mapped,
            "control_group_count": current_names.len(), "control_group_names": current_names,
            "rate_group_count": rate_names.len(), "rate_group_names": rate_names, "inventory_complete": inventory.complete,
            "features": features, "mbm_local_bps": sum_complete_f64(&rows, "mbm_local_bps"),
            "mbm_total_bps": sum_complete_f64(&rows, "mbm_total_bps"), "llc_occupancy_bytes": sum_complete_u64(&rows, "llc_occupancy_bytes"),
            "coverage_scope": "exposed_parent_domain_files",
            "scope_note": "Root + all top-level control groups with mon_data. Linux already includes child monitor counters in each parent reading, so those counters are not added separately. Coverage describes exposed parent-domain files, not internal RMID/node coverage or scheduler-cell attribution.",
        });
        group_with_rows(SCOPE, summary, rows, any_available, partial, errors)
    }

    fn invalidate_bandwidth_control(&mut self, control: &Path) {
        let mon_data = control.join("mon_data");
        self.bandwidth
            .retain(|path, _| !path.starts_with(&mon_data));
    }

    fn read_bandwidth_counter(
        &mut self,
        domain_path: &Path,
        metric: &'static str,
        supported: bool,
        now: Instant,
        seen: &mut BTreeSet<PathBuf>,
    ) -> CounterReading {
        let path = domain_path.join(metric);
        seen.insert(path.clone());
        if !supported {
            self.bandwidth.remove(&path);
            return missing_counter(
                "unsupported",
                format!("{metric} is not supported by this resctrl source"),
            );
        }
        let current = read_resctrl_gauge(&path);
        let Some(value) = current.raw else {
            self.bandwidth.remove(&path);
            return current;
        };
        let Some(identity) = current.identity else {
            self.bandwidth.remove(&path);
            return missing_counter(
                "read_error",
                format!("{}: counter identity is unavailable", path.display()),
            );
        };
        let previous = self
            .bandwidth
            .get(&path)
            .filter(|sample| sample.identity == identity);
        let elapsed = previous
            .and_then(|sample| now.checked_duration_since(sample.at))
            .unwrap_or_default();
        let delta = counter_delta(previous.map(|sample| sample.value), value, elapsed);
        let rate = delta
            .value
            .map(|delta| delta as f64 / elapsed.as_secs_f64());
        self.bandwidth.insert(
            path,
            CounterSample {
                value,
                at: now,
                identity,
            },
        );
        CounterReading {
            raw: Some(value),
            rate,
            status: delta.status,
            error: delta_error(delta.status, metric),
            identity: Some(identity),
        }
    }

    fn collect_idle(&mut self, now: Instant) -> ExploreGroup {
        const SCOPE: &str = "Logical CPU idle states · completed idle intervals";
        let mut rows = Vec::new();
        let mut errors = Vec::new();
        let mut seen = BTreeSet::new();
        let mut any_available = false;
        let mut measured_cpus = 0;
        let mut total_idle_pct = 0.0;
        for cpu in self.topology.cpus.clone() {
            let root = self.paths.cpu.join(format!("cpu{}/cpuidle", cpu.cpu));
            let states = child_paths(&root, MAX_IDLE_STATES).map(|paths| {
                paths
                    .into_iter()
                    .filter_map(|(name, path)| Some((indexed_name(&name, "state")?, path)))
                    .collect::<BTreeMap<_, _>>()
            });
            let states = match states {
                Ok(states) if !states.is_empty() => states,
                result => {
                    let error = result.err().unwrap_or_else(|| {
                        format!("{}: no cpuidle state counters", root.display())
                    });
                    errors.push(error.clone());
                    rows.push(json!({ "cpu": cpu.cpu, "node": cpu.node, "llc": cpu.llc, "package": cpu.core_topology_available.then_some(cpu.package),
                        "core": cpu.core_topology_available.then_some(cpu.core), "core_topology_available": cpu.core_topology_available,
                        "state": null, "name": "Unavailable", "description": null,
                        "time_us": null, "entries": null, "residency_us": null, "entries_delta": null,
                        "residency_pct": null, "entries_per_second": null, "exit_latency_us": null,
                        "disabled": null, "status": "unavailable", "error": error }));
                    continue;
                }
            };
            let mut cpu_rows = Vec::new();
            for (state, path) in states {
                let key = (cpu.cpu, state);
                seen.insert(key);
                let mut row_errors = Vec::new();
                let name = value_or_error(read_text(&path.join("name")), &mut row_errors);
                let description = optional_text(&path.join("desc"), &mut row_errors);
                let time_us = value_or_error(read_u64(&path.join("time")), &mut row_errors);
                let entries = value_or_error(read_u64(&path.join("usage")), &mut row_errors);
                let exit_latency_us =
                    value_or_error(read_u64(&path.join("latency")), &mut row_errors);
                let disabled =
                    optional_u64(&path.join("disable"), &mut row_errors).and_then(|value| {
                        match value {
                            0 => Some(false),
                            1 => Some(true),
                            _ => {
                                row_errors
                                    .push(format!("{}: invalid disable flag", path.display()));
                                None
                            }
                        }
                    });
                any_available |= time_us.is_some() && entries.is_some();
                let mut time_delta = None;
                let mut entries_delta = None;
                let mut pct = None;
                let mut entry_rate = None;
                let mut elapsed_ms = None;
                let mut status = "read_error";
                if let (Some(time_us), Some(entries), Some(name)) =
                    (time_us, entries, name.as_ref())
                {
                    let previous = self.idle.get(&key);
                    let elapsed = previous
                        .and_then(|sample| now.checked_duration_since(sample.at))
                        .unwrap_or_default();
                    elapsed_ms = previous.map(|_| elapsed.as_secs_f64() * 1000.0);
                    let same_state = previous
                        .is_some_and(|sample| sample.name == *name && sample.disabled == disabled);
                    let previous = previous.filter(|_| same_state);
                    let residency =
                        counter_delta(previous.map(|sample| sample.time_us), time_us, elapsed);
                    let usage =
                        counter_delta(previous.map(|sample| sample.entries), entries, elapsed);
                    status = if !same_state && self.idle.contains_key(&key) {
                        "reset"
                    } else {
                        residency.status
                    };
                    if residency.value.is_some() && usage.value.is_some() {
                        time_delta = residency.value;
                        entries_delta = usage.value;
                        pct = residency_pct(time_delta.unwrap(), elapsed);
                        entry_rate = Some(entries_delta.unwrap() as f64 / elapsed.as_secs_f64());
                        if pct.is_some_and(|value| value > 100.0) {
                            pct = None;
                            status = "accounting_catchup";
                            row_errors.push("Idle time attributed on state exit exceeds this wall interval; residency percentage is unavailable".into());
                        }
                    } else if usage.status == "reset" {
                        status = "reset";
                    }
                    if let Some(error) = delta_error(status, "cpuidle") {
                        row_errors.push(error);
                    }
                    self.idle.insert(
                        key,
                        IdleSample {
                            time_us,
                            entries,
                            name: name.clone(),
                            disabled,
                            at: now,
                        },
                    );
                } else {
                    self.idle.remove(&key);
                }
                errors.extend(row_errors.iter().cloned());
                cpu_rows.push(json!({
                    "cpu": cpu.cpu, "node": cpu.node, "llc": cpu.llc,
                    "package": cpu.core_topology_available.then_some(cpu.package), "core": cpu.core_topology_available.then_some(cpu.core),
                    "core_topology_available": cpu.core_topology_available,
                    "state": state, "name": name.unwrap_or_else(|| format!("State {state}")), "description": description,
                    "time_us": time_us, "entries": entries, "residency_us": time_delta, "entries_delta": entries_delta,
                    "residency_pct": pct, "entries_per_second": entry_rate, "exit_latency_us": exit_latency_us,
                    "disabled": disabled, "interval_ms": elapsed_ms, "status": status, "error": joined_errors(&row_errors),
                }));
            }
            if let Some(pct) = sum_complete_f64(&cpu_rows, "residency_pct") {
                if pct <= 100.0 {
                    measured_cpus += 1;
                    total_idle_pct += pct;
                } else {
                    errors.push(format!(
                        "CPU {}: completed idle accounting exceeds the full wall interval",
                        cpu.cpu
                    ));
                    for row in &mut cpu_rows {
                        row["residency_pct"] = Value::Null;
                        row["status"] = json!("accounting_catchup");
                        row["error"] =
                            json!("Completed idle accounting exceeds the full wall interval");
                    }
                }
            }
            rows.extend(cpu_rows);
        }
        self.idle.retain(|key, _| seen.contains(key));
        let complete = !self.topology.cpus.is_empty() && measured_cpus == self.topology.cpus.len();
        let idle_pct = complete.then(|| total_idle_pct / measured_cpus as f64);
        let summary = json!({
            "source": "cpuidle", "cpu_count": self.topology.cpus.len(), "state_count": rows.iter().filter(|row| row["state"].is_u64()).count(),
            "measured_cpu_count": measured_cpus, "idle_residency_pct": idle_pct, "active_or_unaccounted_pct": idle_pct.map(|pct| 100.0 - pct),
            "scope_note": "Residency uses the full elapsed wall interval, including active time. Kernel idle time is accounted on state exit; long completed sleeps can require a new interval. Exit latency is the driver's advertised latency in microseconds.",
        });
        let partial = !errors.is_empty();
        group_with_rows(SCOPE, summary, rows, any_available, partial, errors)
    }

    fn collect_thermal(&mut self) -> ExploreGroup {
        const SCOPE: &str =
            "Hardware temperature sensors · labels and scopes supplied by the kernel";
        let mut rows = Vec::new();
        let mut errors = Vec::new();
        match child_paths(&self.paths.hwmon, MAX_SENSOR_ENTRIES) {
            Ok(devices) => {
                for (device_id, path) in devices
                    .into_iter()
                    .filter(|(name, _)| indexed_name(name, "hwmon").is_some())
                {
                    let mut device_errors = Vec::new();
                    let device = value_or_error(read_text(&path.join("name")), &mut device_errors)
                        .unwrap_or_else(|| device_id.clone());
                    let channels = match child_paths(&path, MAX_SENSOR_ENTRIES) {
                        Ok(paths) => paths
                            .into_iter()
                            .filter_map(|(name, _)| {
                                let prefix = name.strip_suffix("_input")?;
                                indexed_name(prefix, "temp")
                            })
                            .collect::<BTreeSet<_>>(),
                        Err(error) => {
                            errors.push(error);
                            continue;
                        }
                    };
                    let packages = channels
                        .iter()
                        .filter_map(|index| {
                            read_text(&path.join(format!("temp{index}_label")))
                                .ok()
                                .and_then(|label| indexed_name(&label, "Package id "))
                        })
                        .collect::<BTreeSet<_>>();
                    let core_package = (packages.len() == 1).then(|| *packages.first().unwrap());
                    for index in channels {
                        let mut row_errors = device_errors.clone();
                        let label = optional_text(
                            &path.join(format!("temp{index}_label")),
                            &mut row_errors,
                        )
                        .unwrap_or_else(|| format!("{device} temp{index}"));
                        let package = indexed_name(&label, "Package id ");
                        let core = indexed_name(&label, "Core ");
                        let scope = if package.is_some() {
                            "package"
                        } else if core.is_some() {
                            "physical core"
                        } else {
                            "sensor"
                        };
                        let temperature = value_or_error(
                            read_temperature(&path.join(format!("temp{index}_input"))),
                            &mut row_errors,
                        );
                        let high = optional_temperature(
                            &path.join(format!("temp{index}_max")),
                            &mut row_errors,
                        );
                        let critical = optional_temperature(
                            &path.join(format!("temp{index}_crit")),
                            &mut row_errors,
                        );
                        let alarm = optional_flag(
                            &path.join(format!("temp{index}_crit_alarm")),
                            &mut row_errors,
                        )
                        .or_else(|| {
                            optional_flag(&path.join(format!("temp{index}_alarm")), &mut row_errors)
                        });
                        errors.extend(row_errors.iter().cloned());
                        rows.push(json!({
                        "sensor_id": format!("hwmon:{device_id}:temp{index}"), "source": "hwmon", "device": device,
                        "label": label, "scope": scope, "package": package.or(core.and(core_package)), "core": core,
                        "temperature_celsius": temperature, "high_celsius": high, "critical_celsius": critical,
                        "alarm": alarm, "error": joined_errors(&row_errors),
                    }));
                    }
                }
            }
            Err(error) => errors.push(error),
        }
        match child_paths(&self.paths.thermal, MAX_SENSOR_ENTRIES) {
            Ok(zones) => {
                for (zone_id, path) in zones
                    .into_iter()
                    .filter(|(name, _)| indexed_name(name, "thermal_zone").is_some())
                {
                    let mut row_errors = Vec::new();
                    let label = value_or_error(read_text(&path.join("type")), &mut row_errors)
                        .unwrap_or_else(|| zone_id.clone());
                    let temperature =
                        value_or_error(read_temperature(&path.join("temp")), &mut row_errors);
                    let mut high = None;
                    let mut critical = None;
                    match child_paths(&path, MAX_SENSOR_ENTRIES) {
                        Ok(attributes) => {
                            for (name, _) in attributes {
                                let Some(prefix) = name.strip_suffix("_type") else {
                                    continue;
                                };
                                if indexed_name(prefix, "trip_point_").is_none() {
                                    continue;
                                }
                                let kind =
                                    value_or_error(read_text(&path.join(&name)), &mut row_errors);
                                match kind.as_deref() {
                                    Some("critical") => {
                                        critical = optional_temperature(
                                            &path.join(format!("{prefix}_temp")),
                                            &mut row_errors,
                                        )
                                    }
                                    Some("hot") => {
                                        high = optional_temperature(
                                            &path.join(format!("{prefix}_temp")),
                                            &mut row_errors,
                                        )
                                    }
                                    _ => {}
                                }
                            }
                        }
                        Err(error) => row_errors.push(error),
                    }
                    errors.extend(row_errors.iter().cloned());
                    rows.push(json!({
                    "sensor_id": format!("thermal:{zone_id}"), "source": "thermal", "device": zone_id,
                    "label": label, "scope": "thermal zone", "package": null, "core": null,
                    "temperature_celsius": temperature, "high_celsius": high, "critical_celsius": critical,
                    "alarm": null, "error": joined_errors(&row_errors),
                }));
                }
            }
            Err(error) => errors.push(error),
        }
        let temperatures = rows
            .iter()
            .filter_map(|row| row["temperature_celsius"].as_f64())
            .collect::<Vec<_>>();
        let available = !temperatures.is_empty();
        let summary = json!({
            "source": "hwmon + thermal", "sensor_count": rows.len(), "measured_sensor_count": temperatures.len(),
            "max_temperature_celsius": temperatures.into_iter().reduce(f64::max),
            "scope_note": "Sensors may describe a package, a physical core, a device, or a thermal zone. Package and zone readings are not duplicated across logical CPUs.",
        });
        if rows.is_empty() && errors.is_empty() {
            errors.push("No hwmon temperature channels or thermal zones are exposed".into());
        }
        let partial = !errors.is_empty();
        group_with_rows(SCOPE, summary, rows, available, partial, errors)
    }

    fn collect_power(&mut self, now: Instant) -> ExploreGroup {
        const SCOPE: &str =
            "Powercap hardware energy domains · package total excludes nested domains";
        let (domains, mut errors) = discover_power_domains(&self.paths.powercap);
        let mut rows = Vec::new();
        let mut seen = BTreeSet::new();
        let mut any_available = false;
        for domain in domains {
            seen.insert(domain.id.clone());
            let mut row_errors = Vec::new();
            let name = value_or_error(read_text(&domain.path.join("name")), &mut row_errors)
                .unwrap_or_else(|| domain.id.clone());
            let package = indexed_name(&name, "package-");
            let energy = value_or_error(read_u64(&domain.path.join("energy_uj")), &mut row_errors);
            let max = optional_u64(&domain.path.join("max_energy_range_uj"), &mut row_errors);
            let limits = read_power_limits(&domain.path, &mut row_errors);
            let mut rate = None;
            let mut interval_ms = None;
            let mut status = "read_error";
            if let Some(energy) = energy {
                if max.is_some_and(|max| max == 0 || energy >= max) {
                    status = "invalid_counter";
                    self.power.remove(&domain.id);
                } else {
                    any_available = true;
                    let previous = self.power.get(&domain.id);
                    let delta = match previous {
                        Some(previous) => {
                            let elapsed =
                                now.checked_duration_since(previous.at).unwrap_or_default();
                            interval_ms = Some(elapsed.as_secs_f64() * 1000.0);
                            if elapsed.is_zero() {
                                Delta {
                                    value: None,
                                    status: "invalid_interval",
                                }
                            } else if previous.max_energy_range_uj != max {
                                Delta {
                                    value: None,
                                    status: "reset",
                                }
                            } else {
                                let delta = energy_delta(previous.energy_uj, energy, max);
                                rate = delta.value.and_then(|value| watts(value, elapsed));
                                delta
                            }
                        }
                        None => Delta {
                            value: None,
                            status: "baseline",
                        },
                    };
                    status = delta.status;
                    self.power.insert(
                        domain.id.clone(),
                        PowerSample {
                            energy_uj: energy,
                            max_energy_range_uj: max,
                            at: now,
                        },
                    );
                }
            } else {
                self.power.remove(&domain.id);
            }
            if let Some(error) = delta_error(status, "powercap energy") {
                row_errors.push(error);
            }
            errors.extend(row_errors.iter().cloned());
            rows.push(json!({
                "domain_id": domain.id, "domain": name, "parent_domain_id": domain.parent,
                "scope": if package.is_some() { "package" } else { "domain" }, "package": package,
                "energy_uj": energy, "max_energy_range_uj": max, "power_watts": rate, "interval_ms": interval_ms,
                "included_in_total": package.is_some(), "power_limits": limits, "status": status, "error": joined_errors(&row_errors),
            }));
        }
        self.power.retain(|id, _| seen.contains(id));
        let package_counts = rows.iter().filter_map(|row| row["package"].as_u64()).fold(
            BTreeMap::<u64, usize>::new(),
            |mut counts, id| {
                *counts.entry(id).or_default() += 1;
                counts
            },
        );
        for row in &mut rows {
            if row["package"]
                .as_u64()
                .is_some_and(|id| package_counts[&id] > 1)
            {
                row["included_in_total"] = json!(false);
                row["error"] = json!(
                    "Multiple powercap energy sources name this package; excluded from the total"
                );
                errors.push("Duplicate powercap package source excluded from the total".into());
            }
        }
        let package_rows = rows
            .iter()
            .filter(|row| row["included_in_total"] == true)
            .cloned()
            .collect::<Vec<_>>();
        let all_packages_unique = package_counts.values().all(|count| *count == 1);
        let summary = json!({
            "source": "powercap", "domain_count": rows.len(), "package_count": package_counts.len(),
            "package_power_watts": if all_packages_unique { sum_complete_f64(&package_rows, "power_watts") } else { None },
            "scope_note": "Watts are derived from changes in microjoules over elapsed seconds. The total sums unique package domains only; core, DRAM, GPU, and platform domains remain separate. First, reset, and failed intervals are unavailable.",
        });
        if rows.is_empty() && errors.is_empty() {
            errors.push("No powercap energy domains are exposed by this host".into());
        }
        let partial = !errors.is_empty();
        group_with_rows(SCOPE, summary, rows, any_available, partial, errors)
    }
}

struct PowerDomain {
    id: String,
    path: PathBuf,
    parent: Option<String>,
}

fn discover_bandwidth_controls(root: &Path) -> BandwidthInventory {
    let root_domains = read_bandwidth_domains(&root.join("mon_data"));
    let mut inventory = BandwidthInventory {
        complete: root_domains.is_ok(),
        errors: root_domains.as_ref().err().cloned().into_iter().collect(),
        controls: BTreeMap::from([(
            "/".into(),
            BandwidthControl {
                path: root.to_path_buf(),
                domains: root_domains,
            },
        )]),
    };
    let entries = match child_paths(root, MAX_DOMAINS) {
        Ok(entries) => entries,
        Err(error) => {
            inventory.complete = false;
            inventory.errors.push(error);
            return inventory;
        }
    };
    for (name, path) in entries {
        // CTRL_MON directories are top-level peers. These three directories
        // are not additional controls. Child MON identities are sampled separately; their counters are never traversed.
        if matches!(name.as_str(), "info" | "mon_data" | "mon_groups") {
            continue;
        }
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => continue,
            Err(error) => {
                inventory.complete = false;
                inventory
                    .errors
                    .push(format!("{}: {error}", path.display()));
                continue;
            }
        }
        let mon_data = path.join("mon_data");
        let domains = match fs::symlink_metadata(&mon_data) {
            Ok(metadata) if metadata.is_dir() => read_bandwidth_domains(&mon_data),
            Ok(_) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => Err(format!("{}: {error}", mon_data.display())),
        };
        if let Err(error) = &domains {
            inventory.complete = false;
            inventory.errors.push(error.clone());
        }
        inventory
            .controls
            .insert(name, BandwidthControl { path, domains });
        if inventory.controls.len() > MAX_BANDWIDTH_CONTROLS {
            inventory.complete = false;
            inventory.errors.push(format!(
                "resctrl control inventory exceeds the {MAX_BANDWIDTH_CONTROLS} group read limit"
            ));
            break;
        }
    }
    inventory
}

fn read_monitor_fingerprint(
    path: &Path,
    remaining: &mut usize,
) -> Result<BTreeMap<String, CounterIdentity>, String> {
    let entries = fs::read_dir(path).map_err(|error| {
        format!(
            "{}: monitor membership is unreadable: {error}",
            path.display()
        )
    })?;
    let mut fingerprint = BTreeMap::new();
    for (index, entry) in entries.enumerate() {
        if *remaining == 0 || index >= MAX_DOMAINS {
            return Err(format!(
                "{}: monitor membership metadata exceeds the sample read limit",
                path.display()
            ));
        }
        *remaining -= 1;
        let entry = entry.map_err(|error| {
            format!(
                "{}: monitor membership is unreadable: {error}",
                path.display()
            )
        })?;
        let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
            format!(
                "{}: monitor identity is unreadable: {error}",
                entry.path().display()
            )
        })?;
        if !metadata.is_dir() {
            continue;
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| format!("{}: monitor name is not valid UTF-8", path.display()))?;
        fingerprint.insert(
            name,
            CounterIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            },
        );
    }
    Ok(fingerprint)
}

fn read_bandwidth_domains(mon_data: &Path) -> Result<BTreeMap<u32, PathBuf>, String> {
    let mut domains = BTreeMap::new();
    for (name, path) in child_paths(mon_data, MAX_DOMAINS)? {
        let Some(suffix) = name.strip_prefix("mon_L3_") else {
            continue;
        };
        let metadata =
            fs::symlink_metadata(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        if !metadata.is_dir() {
            continue;
        }
        let id = u32::from_str_radix(suffix, 16)
            .map_err(|_| format!("{}: invalid hexadecimal resctrl L3 domain", path.display()))?;
        if domains.insert(id, path).is_some() {
            return Err(format!(
                "{}: duplicate resctrl L3 domain {id}",
                mon_data.display()
            ));
        }
    }
    if domains.is_empty() {
        return Err(format!(
            "{}: resctrl exposes no mon_L3_* monitor domains",
            mon_data.display()
        ));
    }
    Ok(domains)
}

fn missing_counter(status: &'static str, error: String) -> CounterReading {
    CounterReading {
        raw: None,
        rate: None,
        status,
        error: Some(error),
        identity: None,
    }
}

fn measured_contributions(rows: &[Value], metric: &str) -> usize {
    rows.iter().filter(|row| row[metric].is_number()).count()
}

fn aggregate_bandwidth_status(
    rows: &[Value],
    key: &str,
    inventory_complete: bool,
    measured: bool,
) -> &'static str {
    if !inventory_complete {
        return "unavailable";
    }
    if measured {
        return "measured";
    }
    for status in [
        "read_error",
        "unavailable",
        "unassigned",
        "reset",
        "invalid_interval",
        "baseline",
        "unsupported",
    ] {
        if rows.iter().any(|row| row[key].as_str() == Some(status)) {
            return status;
        }
    }
    "unavailable"
}

fn power_zone_name(name: &str) -> bool {
    let Some((driver, ids)) = name.split_once(':') else {
        return false;
    };
    !driver.is_empty()
        && ids
            .split(':')
            .all(|id| !id.is_empty() && id.bytes().all(|byte| byte.is_ascii_digit()))
}

fn discover_power_domains(root: &Path) -> (Vec<PowerDomain>, Vec<String>) {
    let mut out = Vec::new();
    let mut errors = Vec::new();
    let starts = match child_paths(root, MAX_DOMAINS) {
        Ok(paths) => paths,
        Err(error) => return (out, vec![format!("powercap is unavailable: {error}")]),
    };
    let mut queue = VecDeque::from(
        starts
            .into_iter()
            .map(|(_, path)| (path, 0))
            .collect::<Vec<_>>(),
    );
    let mut visited = BTreeSet::new();
    while let Some((path, depth)) = queue.pop_front() {
        match fs::metadata(&path) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => continue,
            Err(error) => {
                errors.push(format!("{}: {error}", path.display()));
                continue;
            }
        }
        let identity = match fs::canonicalize(&path) {
            Ok(identity) => identity,
            Err(error) => {
                errors.push(format!("{}: {error}", path.display()));
                continue;
            }
        };
        if !visited.insert(identity) {
            continue;
        }
        if visited.len() > MAX_DOMAINS {
            errors.push("powercap domain traversal exceeds the read limit".into());
            break;
        }
        let Some(id) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if power_zone_name(id) {
            let parent = id
                .rsplit_once(':')
                .map(|(prefix, _)| prefix)
                .filter(|prefix| power_zone_name(prefix))
                .map(str::to_string);
            out.push(PowerDomain {
                id: id.to_string(),
                path: path.clone(),
                parent,
            });
        }
        match child_paths(&path, MAX_DOMAINS) {
            Ok(children) => {
                for (name, child) in children {
                    if !power_zone_name(&name) {
                        continue;
                    }
                    if depth == MAX_POWER_DEPTH {
                        errors.push(format!(
                            "{}: powercap nesting exceeds the read limit",
                            child.display()
                        ));
                    } else {
                        queue.push_back((child, depth + 1));
                    }
                }
            }
            Err(error) => errors.push(error),
        }
    }
    out.sort_by(|left, right| left.id.cmp(&right.id));
    (out, errors)
}

fn read_power_limits(path: &Path, errors: &mut Vec<String>) -> Vec<Value> {
    let attributes = match child_paths(path, MAX_DOMAINS) {
        Ok(attributes) => attributes,
        Err(error) => {
            errors.push(error);
            return Vec::new();
        }
    };
    let indexes = attributes
        .iter()
        .filter_map(|(name, _)| indexed_name(name.strip_suffix("_power_limit_uw")?, "constraint_"))
        .collect::<BTreeSet<_>>();
    indexes
        .into_iter()
        .map(|index| {
            let prefix = format!("constraint_{index}");
            let name = optional_text(&path.join(format!("{prefix}_name")), errors)
                .unwrap_or_else(|| format!("Constraint {index}"));
            let limit = value_or_error(
                read_u64(&path.join(format!("{prefix}_power_limit_uw"))),
                errors,
            )
            .map(|value| value as f64 / 1_000_000.0);
            let window = optional_u64(&path.join(format!("{prefix}_time_window_us")), errors);
            json!({ "name": name, "power_limit_watts": limit, "time_window_us": window })
        })
        .collect()
}

fn read_text(path: &Path) -> Result<String, String> {
    let file = File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut value = String::new();
    file.take(MAX_ATTRIBUTE_BYTES + 1)
        .read_to_string(&mut value)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    if value.len() as u64 > MAX_ATTRIBUTE_BYTES {
        return Err(format!(
            "{}: attribute exceeds the read limit",
            path.display()
        ));
    }
    Ok(value.trim().to_string())
}

fn read_u64(path: &Path) -> Result<u64, String> {
    read_text(path)?
        .parse()
        .map_err(|_| format!("{}: invalid unsigned counter", path.display()))
}

fn value_or_error<T>(result: Result<T, String>, errors: &mut Vec<String>) -> Option<T> {
    match result {
        Ok(value) => Some(value),
        Err(error) => {
            errors.push(error);
            None
        }
    }
}

fn optional_text(path: &Path, errors: &mut Vec<String>) -> Option<String> {
    match fs::metadata(path) {
        Ok(_) => value_or_error(read_text(path), errors),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            errors.push(format!("{}: {error}", path.display()));
            None
        }
    }
}

fn optional_u64(path: &Path, errors: &mut Vec<String>) -> Option<u64> {
    let value = optional_text(path, errors)?;
    match value.parse() {
        Ok(value) => Some(value),
        Err(_) => {
            errors.push(format!("{}: invalid unsigned counter", path.display()));
            None
        }
    }
}

fn optional_flag(path: &Path, errors: &mut Vec<String>) -> Option<bool> {
    match optional_u64(path, errors)? {
        0 => Some(false),
        1 => Some(true),
        _ => {
            errors.push(format!("{}: invalid boolean flag", path.display()));
            None
        }
    }
}

fn read_temperature(path: &Path) -> Result<f64, String> {
    let value = read_text(path)?
        .parse::<i64>()
        .map_err(|_| format!("{}: invalid millidegree temperature", path.display()))?;
    if !(-273_150..=1_000_000).contains(&value) {
        return Err(format!(
            "{}: temperature is outside a physical millidegree range",
            path.display()
        ));
    }
    Ok(value as f64 / 1000.0)
}

fn optional_temperature(path: &Path, errors: &mut Vec<String>) -> Option<f64> {
    let value = optional_text(path, errors)?;
    match value.parse::<i64>() {
        Ok(value) if (-273_150..=1_000_000).contains(&value) => Some(value as f64 / 1000.0),
        _ => {
            errors.push(format!(
                "{}: invalid millidegree temperature",
                path.display()
            ));
            None
        }
    }
}

fn read_resctrl_gauge(path: &Path) -> CounterReading {
    // Bind the bytes and lineage to the same open file. Reopening the path
    // between a metadata read and a counter read could mix old/new controls.
    let mut identity = None;
    let result = (|| -> Result<String, String> {
        let file = File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
        let metadata = file
            .metadata()
            .map_err(|error| format!("{}: {error}", path.display()))?;
        identity = Some(CounterIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        });
        let mut value = String::new();
        file.take(MAX_ATTRIBUTE_BYTES + 1)
            .read_to_string(&mut value)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        if value.len() as u64 > MAX_ATTRIBUTE_BYTES {
            return Err(format!(
                "{}: attribute exceeds the read limit",
                path.display()
            ));
        }
        Ok(value.trim().to_string())
    })();
    match result {
        Ok(value) if value.eq_ignore_ascii_case("Unavailable") => missing_counter(
            "unavailable",
            format!("{}: kernel reports Unavailable", path.display()),
        ),
        Ok(value) if value.eq_ignore_ascii_case("Unassigned") => missing_counter(
            "unassigned",
            format!(
                "{}: kernel reports Unassigned (the monitoring event has no assigned counter)",
                path.display()
            ),
        ),
        Ok(value) if value.eq_ignore_ascii_case("Error") => missing_counter(
            "read_error",
            format!("{}: kernel reports Error", path.display()),
        ),
        Ok(value) => match value.parse() {
            Ok(raw) => CounterReading {
                raw: Some(raw),
                rate: None,
                status: "measured",
                error: None,
                identity,
            },
            Err(_) => missing_counter(
                "read_error",
                format!("{}: invalid resctrl counter ({value})", path.display()),
            ),
        },
        Err(error) => missing_counter("read_error", error),
    }
}

fn child_paths(path: &Path, limit: usize) -> Result<Vec<(String, PathBuf)>, String> {
    let mut rows = Vec::new();
    let entries = fs::read_dir(path).map_err(|error| format!("{}: {error}", path.display()))?;
    for entry in entries.take(limit + 1) {
        let entry = entry.map_err(|error| format!("{}: {error}", path.display()))?;
        if rows.len() == limit {
            return Err(format!(
                "{}: directory exceeds the {limit} entry read limit",
                path.display()
            ));
        }
        if let Some(name) = entry.file_name().to_str() {
            rows.push((name.to_string(), entry.path()));
        }
    }
    rows.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(rows)
}

fn indexed_name(name: &str, prefix: &str) -> Option<u32> {
    let suffix = name.strip_prefix(prefix)?;
    if suffix.is_empty() || !suffix.bytes().all(|x| x.is_ascii_digit()) {
        return None;
    }
    suffix.parse().ok()
}

fn discover_domain_topology(
    topology: &TopologyView,
    cpu_path: &Path,
) -> BTreeMap<u32, DomainTopology> {
    let mut kernel_groups = BTreeMap::<u32, Vec<CpuInfo>>::new();
    for cpu in &topology.cpus {
        let cache = cpu_path.join(format!("cpu{}/cache", cpu.cpu));
        let entries = child_paths(&cache, MAX_IDLE_STATES).unwrap_or_default();
        let id = entries
            .iter()
            .filter(|(name, _)| indexed_name(name, "index").is_some())
            .find_map(|(_, path)| {
                let level = read_u64(&path.join("level")).ok()?;
                let kind = read_text(&path.join("type")).ok()?;
                if level != 3 || !matches!(kind.as_str(), "Unified" | "Data") {
                    return None;
                }
                read_u64(&path.join("id")).ok()?.try_into().ok()
            });
        if let Some(id) = id {
            kernel_groups.entry(id).or_default().push(*cpu);
        }
    }
    kernel_groups
        .into_iter()
        .filter_map(|(id, mut cpus)| {
            cpus.sort_by_key(|cpu| cpu.cpu);
            let first = cpus.first()?;
            if cpus.iter().any(|cpu| {
                cpu.llc != first.llc || cpu.node != first.node || cpu.package != first.package
            }) {
                return None;
            }
            let ids = cpus.iter().map(|cpu| cpu.cpu).collect::<Vec<_>>();
            let expected = topology
                .llc_groups
                .iter()
                .find(|group| group.llc == first.llc)?;
            if ids != expected.cpus {
                return None;
            }
            Some((
                id,
                DomainTopology {
                    llc: first.llc,
                    node: first.node,
                    package: cpus
                        .iter()
                        .all(|cpu| cpu.core_topology_available)
                        .then_some(first.package),
                    cpus: ids,
                },
            ))
        })
        .collect()
}

fn delta_error(status: &str, metric: &str) -> Option<String> {
    match status {
        "reset" => Some(format!(
            "{metric}: counter reset; waiting for a fresh interval"
        )),
        "invalid_interval" => Some(format!("{metric}: no positive elapsed interval")),
        "invalid_counter" => Some(format!("{metric}: counter is outside its exported range")),
        _ => None,
    }
}

fn joined_errors(errors: &[String]) -> Option<String> {
    if errors.is_empty() {
        return None;
    }
    let mut text = errors
        .iter()
        .take(8)
        .cloned()
        .collect::<Vec<_>>()
        .join("; ");
    if errors.len() > 8 {
        text.push_str(&format!("; {} additional source errors", errors.len() - 8));
    }
    Some(text)
}

fn group_with_rows(
    scope: &str,
    summary: Value,
    rows: Vec<Value>,
    available: bool,
    partial: bool,
    errors: Vec<String>,
) -> ExploreGroup {
    let mut group = if available {
        ExploreGroup::available(scope, summary.clone(), Vec::new())
    } else {
        ExploreGroup::unavailable(
            scope,
            joined_errors(&errors)
                .unwrap_or_else(|| "No readable hardware measurements are available".into()),
        )
    };
    group.summary = summary;
    group.rows = rows;
    group.partial = partial;
    if available {
        group.error = joined_errors(&errors);
    }
    group
}

fn sum_complete_f64(rows: &[Value], key: &str) -> Option<f64> {
    if rows.is_empty() {
        return None;
    }
    rows.iter()
        .try_fold(0.0, |sum, row| row[key].as_f64().map(|value| sum + value))
}

fn sum_complete_u64(rows: &[Value], key: &str) -> Option<u64> {
    if rows.is_empty() {
        return None;
    }
    rows.iter()
        .try_fold(0_u64, |sum, row| sum.checked_add(row[key].as_u64()?))
}

#[derive(Debug, PartialEq)]
struct Delta {
    value: Option<u64>,
    status: &'static str,
}

fn counter_delta(previous: Option<u64>, current: u64, elapsed: Duration) -> Delta {
    let Some(previous) = previous else {
        return Delta {
            value: None,
            status: "baseline",
        };
    };
    if elapsed.is_zero() {
        return Delta {
            value: None,
            status: "invalid_interval",
        };
    }
    match current.checked_sub(previous) {
        Some(value) => Delta {
            value: Some(value),
            status: "measured",
        },
        None => Delta {
            value: None,
            status: "reset",
        },
    }
}

fn energy_delta(previous: u64, current: u64, max: Option<u64>) -> Delta {
    if max.is_some_and(|max| max == 0 || previous >= max || current >= max) {
        return Delta {
            value: None,
            status: "invalid_counter",
        };
    }
    if let Some(value) = current.checked_sub(previous) {
        return Delta {
            value: Some(value),
            status: "measured",
        };
    }
    // A decrease alone is insufficient evidence for wrapping. Require the
    // old/new values to straddle the exported range boundary; other decreases
    // are treated as resets rather than inventing a large energy delta.
    if let Some(max) = max {
        if previous >= max - max / 4 && current <= max / 4 {
            return Delta {
                value: Some((max - previous) + current),
                status: "wrapped",
            };
        }
    }
    Delta {
        value: None,
        status: "reset",
    }
}

fn residency_pct(idle_us: u64, elapsed: Duration) -> Option<f64> {
    (!elapsed.is_zero()).then(|| idle_us as f64 / (elapsed.as_secs_f64() * 1_000_000.0) * 100.0)
}

fn watts(energy_uj: u64, elapsed: Duration) -> Option<f64> {
    (!elapsed.is_zero()).then(|| energy_uj as f64 / 1_000_000.0 / elapsed.as_secs_f64())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topology::CpuInfo;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Fixture {
        root: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "mitosis-explore-host-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let fixture = Self { root };
            for root in ["cpu", "resctrl", "hwmon", "thermal", "powercap"] {
                fs::create_dir_all(fixture.root.join(root)).unwrap();
            }
            for (cpu, kernel_llc) in [(0, 17), (8, 31)] {
                fixture.write(&format!("cpu/cpu{cpu}/cache/index3/level"), "3");
                fixture.write(&format!("cpu/cpu{cpu}/cache/index3/type"), "Unified");
                fixture.write(
                    &format!("cpu/cpu{cpu}/cache/index3/id"),
                    &kernel_llc.to_string(),
                );
            }
            fixture
        }

        fn write(&self, path: &str, value: &str) {
            let path = self.root.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, value).unwrap();
        }

        fn collector(&self) -> ExploreHostCollector {
            let topology = TopologyView::from_cpus(vec![
                CpuInfo {
                    cpu: 0,
                    node: 2,
                    package: 77,
                    llc: 3,
                    core: 0,
                    core_topology_available: true,
                },
                CpuInfo {
                    cpu: 8,
                    node: 4,
                    package: 88,
                    llc: 5,
                    core: 1,
                    core_topology_available: true,
                },
            ])
            .unwrap();
            let mut collector = ExploreHostCollector::new(&topology);
            collector.paths = HostPaths {
                cpu: self.root.join("cpu"),
                resctrl: self.root.join("resctrl"),
                hwmon: self.root.join("hwmon"),
                thermal: self.root.join("thermal"),
                powercap: self.root.join("powercap"),
            };
            collector
        }

        fn bandwidth(&self, suffix: &str, local: &str, total: &str, occupancy: &str) {
            fs::create_dir_all(self.root.join("resctrl/mon_groups")).unwrap();
            self.write(
                "resctrl/info/L3_MON/mon_features",
                "mbm_local_bytes\nmbm_total_bytes\nllc_occupancy\n",
            );
            for (name, value) in [
                ("mbm_local_bytes", local),
                ("mbm_total_bytes", total),
                ("llc_occupancy", occupancy),
            ] {
                self.write(&format!("resctrl/mon_data/mon_L3_{suffix}/{name}"), value);
            }
        }

        fn bandwidth_control(
            &self,
            control: &str,
            suffix: &str,
            local: &str,
            total: &str,
            occupancy: &str,
        ) {
            fs::create_dir_all(self.root.join(format!("resctrl/{control}/mon_groups"))).unwrap();
            self.write(
                "resctrl/info/L3_MON/mon_features",
                "mbm_local_bytes\nmbm_total_bytes\nllc_occupancy\n",
            );
            for (name, value) in [
                ("mbm_local_bytes", local),
                ("mbm_total_bytes", total),
                ("llc_occupancy", occupancy),
            ] {
                self.write(
                    &format!("resctrl/{control}/mon_data/mon_L3_{suffix}/{name}"),
                    value,
                );
            }
        }

        fn idle(&self, cpu: u32, state: u32, time: u64, usage: u64, latency: u64) {
            for (name, value) in [
                ("name", format!("C{state}")),
                ("desc", format!("Driver idle state {state}")),
                ("time", time.to_string()),
                ("usage", usage.to_string()),
                ("latency", latency.to_string()),
                ("disable", "0".into()),
            ] {
                self.write(&format!("cpu/cpu{cpu}/cpuidle/state{state}/{name}"), &value);
            }
        }

        fn power(&self, domain: &str, name: &str, energy: &str, max: &str) {
            for (file, value) in [
                ("name", name),
                ("energy_uj", energy),
                ("max_energy_range_uj", max),
            ] {
                self.write(&format!("powercap/{domain}/{file}"), value);
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn number(value: &serde_json::Value) -> f64 {
        value.as_f64().expect("numeric telemetry value")
    }

    #[test]
    fn bandwidth_first_sample_has_real_occupancy_and_unknown_rates() {
        let fixture = Fixture::new();
        fixture.bandwidth("11", "1", "2", "128");
        let mut collector = fixture.collector();
        let group = collector.collect_bandwidth(Instant::now());
        assert!(group.available);
        assert_eq!(group.rows[0]["domain_id"], 17);
        assert_eq!(group.rows[0]["llc"], 3);
        assert_eq!(group.rows[0]["mbm_local_bps"], serde_json::Value::Null);
        assert_eq!(group.rows[0]["local_status"], "baseline");
        assert_eq!(group.rows[0]["llc_occupancy_bytes"], 128);
    }

    #[test]
    fn bandwidth_uses_independent_domain_counters_and_elapsed_seconds() {
        let fixture = Fixture::new();
        fixture.bandwidth("11", "1", "1", "128");
        fixture.bandwidth("1f", "10", "10", "256");
        let mut collector = fixture.collector();
        let now = Instant::now();
        collector.collect_bandwidth(now);
        fixture.bandwidth("11", "401", "801", "256");
        fixture.bandwidth("1f", "210", "410", "512");
        let group = collector.collect_bandwidth(now + Duration::from_secs(2));
        assert!(group.available);
        assert_eq!(number(&group.rows[0]["mbm_local_bps"]), 200.0);
        assert_eq!(number(&group.rows[1]["mbm_total_bps"]), 200.0);
        assert_eq!(number(&group.summary["mbm_local_bps"]), 300.0);
        assert_eq!(group.summary["llc_occupancy_bytes"], 768);
    }

    #[test]
    fn bandwidth_control_groups_sum_counter_rates_before_domain_aggregation() {
        let fixture = Fixture::new();
        fixture.bandwidth("11", "100", "200", "5");
        fixture.bandwidth_control("CTRL_MON_0", "11", "1000", "2000", "15");
        let mut collector = fixture.collector();
        let now = Instant::now();
        let first = collector.collect_bandwidth(now);
        assert_eq!(first.summary["control_group_count"], 2);
        assert!(first.rows[0]["mbm_total_bps"].is_null());
        fixture.bandwidth("11", "300", "600", "7");
        fixture.bandwidth_control("CTRL_MON_0", "11", "1400", "2600", "17");
        let group = collector.collect_bandwidth(now + Duration::from_secs(2));
        assert_eq!(group.rows.len(), 1);
        assert_eq!(group.rows[0]["llc"], 3);
        assert_eq!(number(&group.rows[0]["mbm_local_bps"]), 300.0);
        assert_eq!(number(&group.rows[0]["mbm_total_bps"]), 500.0);
        assert_eq!(group.rows[0]["mbm_local_bytes"], 1700);
        assert_eq!(group.rows[0]["mbm_total_bytes"], 3200);
        assert_eq!(group.rows[0]["llc_occupancy_bytes"], 24);
        assert_eq!(number(&group.summary["mbm_total_bps"]), 500.0);
        assert_eq!(
            group.summary["control_group_names"],
            json!(["/", "CTRL_MON_0"])
        );
        assert_eq!(group.rows[0]["total_measured_contributions"], 2);
        assert_eq!(group.rows[0]["total_expected_contributions"], 2);
        assert_eq!(group.summary["monitor"], "all_control_groups");
    }

    #[test]
    fn bandwidth_control_groups_never_walk_or_double_count_child_monitor_groups() {
        let fixture = Fixture::new();
        fixture.bandwidth("11", "100", "200", "5");
        fixture.bandwidth_control("services", "11", "1000", "2000", "15");
        fixture.bandwidth_control("mon_groups/MON_0", "11", "bad", "100000000", "99999");
        fixture.bandwidth_control(
            "services/mon_groups/MON_1",
            "11",
            "bad",
            "200000000",
            "99999",
        );
        let mut collector = fixture.collector();
        let now = Instant::now();
        collector.collect_bandwidth(now);
        fixture.bandwidth("11", "300", "600", "7");
        fixture.bandwidth_control("services", "11", "1400", "2600", "17");
        let group = collector.collect_bandwidth(now + Duration::from_secs(2));
        assert_eq!(number(&group.summary["mbm_total_bps"]), 500.0);
        assert_eq!(group.summary["llc_occupancy_bytes"], 24);
        assert_eq!(
            group.summary["control_group_names"],
            json!(["/", "services"])
        );
        assert!(!group.partial);
    }

    #[test]
    fn bandwidth_control_group_addition_requires_its_own_fresh_rate_interval() {
        let fixture = Fixture::new();
        fixture.bandwidth("11", "100", "100", "5");
        let mut collector = fixture.collector();
        let now = Instant::now();
        collector.collect_bandwidth(now);
        fixture.bandwidth("11", "200", "200", "7");
        fixture.bandwidth_control("CTRL_MON_0", "11", "1000000", "2000000", "17");
        let added = collector.collect_bandwidth(now + Duration::from_secs(1));
        assert!(added.rows[0]["mbm_local_bps"].is_null());
        assert!(added.summary["mbm_total_bps"].is_null());
        assert_eq!(added.rows[0]["total_measured_contributions"], 1);
        assert_eq!(added.rows[0]["total_expected_contributions"], 2);
        assert_eq!(added.rows[0]["total_status"], "baseline");
        assert_eq!(added.summary["llc_occupancy_bytes"], 24);
        fixture.bandwidth("11", "300", "300", "9");
        fixture.bandwidth_control("CTRL_MON_0", "11", "1000050", "2000100", "19");
        let measured = collector.collect_bandwidth(now + Duration::from_secs(2));
        assert_eq!(number(&measured.rows[0]["mbm_local_bps"]), 150.0);
        assert_eq!(number(&measured.rows[0]["mbm_total_bps"]), 200.0);
    }

    #[test]
    fn bandwidth_control_group_counter_reset_invalidates_the_affected_aggregate() {
        let fixture = Fixture::new();
        fixture.bandwidth("11", "100", "200", "5");
        fixture.bandwidth_control("CTRL_MON_0", "11", "1000", "2000", "15");
        let mut collector = fixture.collector();
        let now = Instant::now();
        collector.collect_bandwidth(now);
        fixture.bandwidth("11", "200", "300", "7");
        fixture.bandwidth_control("CTRL_MON_0", "11", "5", "10", "17");
        let reset = collector.collect_bandwidth(now + Duration::from_secs(1));
        assert!(reset.rows[0]["mbm_local_bps"].is_null());
        assert!(reset.summary["mbm_total_bps"].is_null());
        assert_eq!(reset.rows[0]["local_status"], "reset");
        assert_eq!(reset.rows[0]["local_measured_contributions"], 1);
        assert!(reset.partial);
        fixture.bandwidth("11", "300", "400", "9");
        fixture.bandwidth_control("CTRL_MON_0", "11", "35", "50", "19");
        let recovered = collector.collect_bandwidth(now + Duration::from_secs(2));
        assert_eq!(number(&recovered.rows[0]["mbm_local_bps"]), 130.0);
        assert_eq!(number(&recovered.rows[0]["mbm_total_bps"]), 140.0);
    }

    #[test]
    fn bandwidth_control_group_removal_has_one_unknown_interval_without_stale_counter_reuse() {
        let fixture = Fixture::new();
        fixture.bandwidth("11", "100", "200", "5");
        fixture.bandwidth_control("CTRL_MON_0", "11", "1000", "2000", "15");
        let mut collector = fixture.collector();
        let now = Instant::now();
        collector.collect_bandwidth(now);
        fs::remove_dir_all(fixture.root.join("resctrl/CTRL_MON_0")).unwrap();
        fixture.bandwidth("11", "200", "300", "7");
        let removed = collector.collect_bandwidth(now + Duration::from_secs(1));
        assert!(removed.rows[0]["mbm_total_bps"].is_null());
        assert_eq!(removed.summary["control_group_count"], 1);
        assert_eq!(removed.rows[0]["total_expected_contributions"], 2);
        assert_eq!(removed.rows[0]["total_measured_contributions"], 1);
        assert_eq!(removed.summary["llc_occupancy_bytes"], 7);
        fixture.bandwidth("11", "300", "400", "9");
        let settled = collector.collect_bandwidth(now + Duration::from_secs(2));
        assert_eq!(number(&settled.rows[0]["mbm_total_bps"]), 100.0);
        fixture.bandwidth("11", "400", "500", "11");
        fixture.bandwidth_control("CTRL_MON_0", "11", "1000000", "2000000", "13");
        let recreated = collector.collect_bandwidth(now + Duration::from_secs(3));
        assert!(recreated.rows[0]["mbm_total_bps"].is_null());
        fixture.bandwidth("11", "500", "600", "15");
        fixture.bandwidth_control("CTRL_MON_0", "11", "1000020", "2000040", "17");
        let measured = collector.collect_bandwidth(now + Duration::from_secs(4));
        assert_eq!(number(&measured.rows[0]["mbm_total_bps"]), 140.0);
    }

    #[test]
    fn bandwidth_control_group_replacement_between_reads_is_a_new_counter_lineage() {
        let fixture = Fixture::new();
        fixture.bandwidth("11", "100", "200", "5");
        fixture.bandwidth_control("CTRL_MON_0", "11", "1000", "2000", "15");
        let mut collector = fixture.collector();
        let now = Instant::now();
        collector.collect_bandwidth(now);
        fs::rename(
            fixture.root.join("resctrl/CTRL_MON_0"),
            fixture.root.join("old-control"),
        )
        .unwrap();
        fixture.bandwidth("11", "200", "300", "7");
        fixture.bandwidth_control("CTRL_MON_0", "11", "1000000", "2000000", "17");
        let replaced = collector.collect_bandwidth(now + Duration::from_secs(1));
        assert!(replaced.rows[0]["mbm_total_bps"].is_null());
        assert_eq!(replaced.rows[0]["total_status"], "baseline");
        fixture.bandwidth("11", "300", "400", "9");
        fixture.bandwidth_control("CTRL_MON_0", "11", "1000020", "2000040", "19");
        let measured = collector.collect_bandwidth(now + Duration::from_secs(2));
        assert_eq!(number(&measured.rows[0]["mbm_total_bps"]), 140.0);
    }

    #[test]
    fn bandwidth_control_groups_keep_sparse_domains_and_independent_metric_coverage() {
        let fixture = Fixture::new();
        for domain in ["11", "1f"] {
            fixture.bandwidth(domain, "100", "200", "5");
            fixture.bandwidth_control("CTRL_MON_0", domain, "1000", "2000", "15");
        }
        let mut collector = fixture.collector();
        let now = Instant::now();
        collector.collect_bandwidth(now);
        for domain in ["11", "1f"] {
            fixture.bandwidth(domain, "200", "300", "7");
            fixture.bandwidth_control("CTRL_MON_0", domain, "1200", "2300", "17");
        }
        fs::remove_file(
            fixture
                .root
                .join("resctrl/CTRL_MON_0/mon_data/mon_L3_1f/mbm_local_bytes"),
        )
        .unwrap();
        let group = collector.collect_bandwidth(now + Duration::from_secs(1));
        assert_eq!(group.rows.len(), 2);
        assert_eq!(group.rows[0]["domain_id"], 17);
        assert_eq!(group.rows[1]["domain_id"], 31);
        assert_eq!(group.rows[1]["llc"], 5);
        assert_eq!(number(&group.rows[0]["mbm_local_bps"]), 300.0);
        assert!(group.rows[1]["mbm_local_bps"].is_null());
        assert_eq!(number(&group.rows[1]["mbm_total_bps"]), 400.0);
        assert!(group.summary["mbm_local_bps"].is_null());
        assert_eq!(number(&group.summary["mbm_total_bps"]), 800.0);
        assert_eq!(group.rows[1]["local_measured_contributions"], 1);
        assert_eq!(group.rows[1]["local_expected_contributions"], 2);
        assert!(group.partial);
        assert!(group.error.as_ref().unwrap().contains("CTRL_MON_0"));
    }

    #[test]
    fn bandwidth_control_groups_preserve_measured_zero_and_report_complete_coverage() {
        let fixture = Fixture::new();
        fixture.bandwidth("11", "100", "200", "0");
        fixture.bandwidth_control("CTRL_MON_0", "11", "1000", "2000", "0");
        let mut collector = fixture.collector();
        let now = Instant::now();
        collector.collect_bandwidth(now);
        let group = collector.collect_bandwidth(now + Duration::from_secs(1));
        assert_eq!(number(&group.rows[0]["mbm_total_bps"]), 0.0);
        assert_eq!(number(&group.summary["mbm_local_bps"]), 0.0);
        assert_eq!(group.rows[0]["llc_occupancy_bytes"], 0);
        assert_eq!(group.rows[0]["total_measured_contributions"], 2);
        assert_eq!(group.rows[0]["total_expected_contributions"], 2);
        assert!(!group.partial);
    }

    #[test]
    fn bandwidth_child_monitor_deletion_does_not_hide_history_loss_in_a_positive_parent_delta() {
        let fixture = Fixture::new();
        fixture.bandwidth("11", "1000", "2000", "5");
        fixture.bandwidth_control("mon_groups/MON_0", "11", "bad", "bad", "bad");
        let mut collector = fixture.collector();
        let now = Instant::now();
        collector.collect_bandwidth(now);
        fs::remove_dir_all(fixture.root.join("resctrl/mon_groups/MON_0")).unwrap();
        fixture.bandwidth("11", "1100", "2100", "7");
        let changed = collector.collect_bandwidth(now + Duration::from_secs(1));
        assert!(changed.rows[0]["mbm_total_bps"].is_null());
        assert_eq!(changed.rows[0]["total_status"], "reset");
        fixture.bandwidth("11", "1200", "2300", "9");
        let stable = collector.collect_bandwidth(now + Duration::from_secs(2));
        assert_eq!(number(&stable.rows[0]["mbm_total_bps"]), 200.0);
    }

    #[test]
    fn bandwidth_child_monitor_addition_requires_a_fresh_parent_baseline() {
        let fixture = Fixture::new();
        fixture.bandwidth("11", "1000", "2000", "5");
        let mut collector = fixture.collector();
        let now = Instant::now();
        collector.collect_bandwidth(now);
        fixture.bandwidth_control("mon_groups/MON_0", "11", "bad", "bad", "bad");
        fixture.bandwidth("11", "1000000", "2000000", "7");
        let changed = collector.collect_bandwidth(now + Duration::from_secs(1));
        assert!(changed.rows[0]["mbm_total_bps"].is_null());
        fixture.bandwidth("11", "1000100", "2000200", "9");
        let stable = collector.collect_bandwidth(now + Duration::from_secs(2));
        assert_eq!(number(&stable.rows[0]["mbm_total_bps"]), 200.0);
    }

    #[test]
    fn bandwidth_child_monitor_recreation_with_same_name_invalidates_only_its_parent() {
        let fixture = Fixture::new();
        fixture.bandwidth("11", "1000", "2000", "5");
        fixture.bandwidth_control("CTRL_MON_0", "11", "100", "200", "15");
        fixture.bandwidth_control("mon_groups/MON_0", "11", "bad", "bad", "bad");
        let mut collector = fixture.collector();
        let now = Instant::now();
        collector.collect_bandwidth(now);
        fs::rename(
            fixture.root.join("resctrl/mon_groups/MON_0"),
            fixture.root.join("old-monitor"),
        )
        .unwrap();
        fixture.bandwidth_control("mon_groups/MON_0", "11", "bad", "bad", "bad");
        fixture.bandwidth("11", "1100", "2100", "7");
        fixture.bandwidth_control("CTRL_MON_0", "11", "200", "400", "17");
        let changed = collector.collect_bandwidth(now + Duration::from_secs(1));
        assert!(changed.rows[0]["mbm_total_bps"].is_null());
        let control = changed.rows[0]["contributions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["control_group"] == "CTRL_MON_0")
            .unwrap();
        assert_eq!(number(&control["mbm_total_bps"]), 200.0);
        fixture.bandwidth("11", "1200", "2200", "9");
        fixture.bandwidth_control("CTRL_MON_0", "11", "300", "600", "19");
        let stable = collector.collect_bandwidth(now + Duration::from_secs(2));
        assert_eq!(number(&stable.rows[0]["mbm_total_bps"]), 300.0);
    }

    #[test]
    fn bandwidth_unreadable_child_fingerprint_keeps_rates_unknown_until_a_fresh_interval() {
        let fixture = Fixture::new();
        fixture.bandwidth("11", "1000", "2000", "5");
        let mut collector = fixture.collector();
        let now = Instant::now();
        collector.collect_bandwidth(now);
        fs::remove_dir_all(fixture.root.join("resctrl/mon_groups")).unwrap();
        fixture.write("resctrl/mon_groups", "not a directory");
        fixture.write("resctrl/mon_data/mon_L3_11/mbm_total_bytes", "2100");
        let unreadable = collector.collect_bandwidth(now + Duration::from_secs(1));
        assert!(unreadable.rows[0]["mbm_total_bps"].is_null());
        assert_eq!(unreadable.rows[0]["total_status"], "unavailable");
        assert!(unreadable.error.as_ref().unwrap().contains("mon_groups"));
        fs::remove_file(fixture.root.join("resctrl/mon_groups")).unwrap();
        fixture.bandwidth("11", "1100", "2200", "7");
        let baseline = collector.collect_bandwidth(now + Duration::from_secs(2));
        assert!(baseline.rows[0]["mbm_total_bps"].is_null());
        fixture.bandwidth("11", "1200", "2300", "9");
        let stable = collector.collect_bandwidth(now + Duration::from_secs(3));
        assert_eq!(number(&stable.rows[0]["mbm_total_bps"]), 100.0);
    }

    #[test]
    fn resctrl_unassigned_counter_reports_a_capability_gap_without_inventing_zero() {
        let fixture = Fixture::new();
        fixture.bandwidth("11", "Unassigned", "0", "0");
        let reading = read_resctrl_gauge(
            &fixture
                .root
                .join("resctrl/mon_data/mon_L3_11/mbm_local_bytes"),
        );
        assert!(reading.raw.is_none());
        assert_eq!(reading.status, "unassigned");
        assert!(reading.error.as_ref().unwrap().contains("Unassigned"));
    }

    #[test]
    fn bandwidth_read_gap_clears_only_that_metric_baseline() {
        let fixture = Fixture::new();
        fixture.bandwidth("11", "100", "200", "10");
        let mut collector = fixture.collector();
        let now = Instant::now();
        collector.collect_bandwidth(now);
        fixture.bandwidth("11", "Unavailable", "400", "10");
        let gap = collector.collect_bandwidth(now + Duration::from_secs(1));
        assert_eq!(gap.rows[0]["local_status"], "unavailable");
        assert!(gap.partial);
        fixture.bandwidth("11", "900", "600", "10");
        let recovered = collector.collect_bandwidth(now + Duration::from_secs(2));
        assert!(recovered.rows[0]["mbm_local_bps"].is_null());
        assert_eq!(number(&recovered.rows[0]["mbm_total_bps"]), 200.0);
        fixture.bandwidth("11", "950", "800", "10");
        let measured = collector.collect_bandwidth(now + Duration::from_secs(3));
        assert_eq!(number(&measured.rows[0]["mbm_local_bps"]), 50.0);
    }

    #[test]
    fn bandwidth_counter_reset_is_unknown_instead_of_huge_wrapping_rate() {
        let fixture = Fixture::new();
        fixture.bandwidth("11", "1000", "2000", "10");
        let mut collector = fixture.collector();
        let now = Instant::now();
        collector.collect_bandwidth(now);
        fixture.bandwidth("11", "5", "10", "10");
        let group = collector.collect_bandwidth(now + Duration::from_secs(1));
        assert!(group.rows[0]["mbm_local_bps"].is_null());
        assert_eq!(group.rows[0]["local_status"], "reset");
    }

    #[test]
    fn resctrl_domain_ids_never_join_by_dense_ui_llc_id() {
        let fixture = Fixture::new();
        fixture.bandwidth("03", "1", "2", "10");
        let mut collector = fixture.collector();
        let group = collector.collect_bandwidth(Instant::now());
        assert!(group.available);
        assert!(group.partial);
        assert!(group.rows[0]["llc"].is_null());
        assert_eq!(group.rows[0]["topology_available"], false);
    }

    #[test]
    fn resctrl_topology_recovers_after_a_cache_identity_read_gap() {
        let fixture = Fixture::new();
        fixture.bandwidth("11", "1", "2", "10");
        fs::remove_file(fixture.root.join("cpu/cpu0/cache/index3/id")).unwrap();
        let mut collector = fixture.collector();
        let now = Instant::now();
        let missing = collector.collect_bandwidth(now);
        assert_eq!(missing.rows[0]["topology_available"], false);
        fixture.write("cpu/cpu0/cache/index3/id", "17");
        let recovered = collector.collect_bandwidth(now + Duration::from_secs(1));
        assert_eq!(recovered.rows[0]["topology_available"], true);
        assert_eq!(recovered.rows[0]["llc"], 3);
    }

    #[test]
    fn unavailable_physical_topology_does_not_report_fallback_ids_as_real_cores() {
        let fixture = Fixture::new();
        for cpu in [0, 8] {
            fixture.idle(cpu, 0, 1, 1, 0);
        }
        fixture.bandwidth("11", "1", "2", "10");
        let mut collector = fixture.collector();
        collector.topology.cpus[0].core_topology_available = false;
        let idle = collector.collect_idle(Instant::now());
        assert!(idle.rows[0]["core"].is_null());
        assert!(idle.rows[0]["package"].is_null());
        assert_eq!(idle.rows[1]["package"], 88);
        let bandwidth = collector.collect_bandwidth(Instant::now());
        assert_eq!(bandwidth.rows[0]["llc"], 3);
        assert!(bandwidth.rows[0]["package"].is_null());
    }

    #[test]
    fn malformed_resctrl_counter_is_distinct_from_zero() {
        let fixture = Fixture::new();
        fixture.bandwidth("11", "bad", "0", "0");
        let mut collector = fixture.collector();
        let group = collector.collect_bandwidth(Instant::now());
        assert!(group.available);
        assert!(group.partial);
        assert!(group.rows[0]["mbm_local_bytes"].is_null());
        assert_eq!(group.rows[0]["local_status"], "read_error");
        assert_eq!(group.rows[0]["llc_occupancy_bytes"], 0);
    }

    #[test]
    fn absent_resctrl_reports_source_capability_instead_of_zero() {
        let fixture = Fixture::new();
        let mut collector = fixture.collector();
        let group = collector.collect_bandwidth(Instant::now());
        assert!(!group.available);
        assert!(group.error.unwrap().contains("resctrl"));
    }

    #[test]
    fn idle_sampling_preserves_sparse_cpu_ids_and_wall_time_fraction() {
        let fixture = Fixture::new();
        for cpu in [0, 8] {
            fixture.idle(cpu, 0, 100_000, 10, 0);
            fixture.idle(cpu, 1, 200_000, 20, 100);
        }
        let mut collector = fixture.collector();
        let now = Instant::now();
        let first = collector.collect_idle(now);
        assert!(first.available);
        assert!(first.rows.iter().all(|row| row["residency_pct"].is_null()));
        for cpu in [0, 8] {
            fixture.idle(cpu, 0, 200_000, 15, 0);
            fixture.idle(cpu, 1, 400_000, 30, 100);
        }
        let group = collector.collect_idle(now + Duration::from_secs(1));
        assert!(group.available);
        assert_eq!(group.rows.len(), 4);
        assert_eq!(group.rows[2]["cpu"], 8);
        assert_eq!(number(&group.rows[1]["residency_pct"]), 20.0);
        assert_eq!(number(&group.rows[1]["entries_per_second"]), 10.0);
        assert_eq!(group.rows[1]["exit_latency_us"], 100);
        assert_eq!(number(&group.summary["idle_residency_pct"]), 30.0);
        assert_eq!(number(&group.summary["active_or_unaccounted_pct"]), 70.0);
    }

    #[test]
    fn idle_reset_and_read_gap_never_become_known_zero() {
        let fixture = Fixture::new();
        for cpu in [0, 8] {
            fixture.idle(cpu, 0, 1000, 10, 1);
        }
        let mut collector = fixture.collector();
        let now = Instant::now();
        collector.collect_idle(now);
        fixture.idle(0, 0, 100, 1, 1);
        let reset = collector.collect_idle(now + Duration::from_secs(1));
        assert!(reset.rows[0]["residency_pct"].is_null());
        assert_eq!(reset.rows[0]["status"], "reset");
        fixture.write("cpu/cpu0/cpuidle/state0/time", "bad");
        let gap = collector.collect_idle(now + Duration::from_secs(2));
        assert!(gap.rows[0]["residency_pct"].is_null());
        assert_eq!(gap.rows[0]["status"], "read_error");
        fixture.idle(0, 0, 1000, 10, 1);
        let recovered = collector.collect_idle(now + Duration::from_secs(3));
        assert!(recovered.rows[0]["residency_pct"].is_null());
        assert_eq!(recovered.rows[0]["status"], "baseline");
    }

    #[test]
    fn missing_cpu_idle_states_limit_coverage_instead_of_inventing_active_time() {
        let fixture = Fixture::new();
        fixture.idle(0, 0, 1, 1, 0);
        let mut collector = fixture.collector();
        let group = collector.collect_idle(Instant::now());
        assert!(group.available);
        assert!(group.partial);
        assert!(group.summary["idle_residency_pct"].is_null());
        assert!(group.summary["active_or_unaccounted_pct"].is_null());
    }

    #[test]
    fn delayed_idle_accounting_above_wall_time_is_not_clamped_into_false_precision() {
        let fixture = Fixture::new();
        for cpu in [0, 8] {
            fixture.idle(cpu, 0, 1, 1, 0);
        }
        let mut collector = fixture.collector();
        let now = Instant::now();
        collector.collect_idle(now);
        fixture.idle(0, 0, 2_000_001, 2, 0);
        let group = collector.collect_idle(now + Duration::from_secs(1));
        assert!(group.rows[0]["residency_pct"].is_null());
        assert_eq!(group.rows[0]["residency_us"], 2_000_000);
        assert_eq!(group.rows[0]["status"], "accounting_catchup");
        assert!(group.summary["idle_residency_pct"].is_null());
    }

    #[test]
    fn temperatures_keep_real_labels_and_package_scope_without_per_cpu_copying() {
        let fixture = Fixture::new();
        fixture.write("hwmon/hwmon3/name", "coretemp");
        fixture.write("hwmon/hwmon3/temp1_label", "Package id 77");
        fixture.write("hwmon/hwmon3/temp1_input", "60000");
        fixture.write("hwmon/hwmon3/temp2_label", "Core 0");
        fixture.write("hwmon/hwmon3/temp2_input", "55000");
        fixture.write("thermal/thermal_zone1/type", "x86_pkg_temp");
        fixture.write("thermal/thermal_zone1/temp", "42000");
        let mut collector = fixture.collector();
        let group = collector.collect_thermal();
        assert!(group.available);
        assert_eq!(group.rows.len(), 3);
        let package = group
            .rows
            .iter()
            .find(|row| row["label"] == "Package id 77")
            .unwrap();
        assert_eq!(package["scope"], "package");
        assert_eq!(package["package"], 77);
        assert_eq!(package["temperature_celsius"], 60.0);
        let core = group
            .rows
            .iter()
            .find(|row| row["label"] == "Core 0")
            .unwrap();
        assert_eq!(core["scope"], "physical core");
        assert_eq!(core["package"], 77);
        assert_eq!(core["core"], 0);
        assert_eq!(number(&group.summary["max_temperature_celsius"]), 60.0);
    }

    #[test]
    fn thermal_read_errors_are_partial_and_do_not_replace_bad_sensor_with_zero() {
        let fixture = Fixture::new();
        fixture.write("hwmon/hwmon0/name", "nvme");
        fixture.write("hwmon/hwmon0/temp1_label", "Composite");
        fixture.write("hwmon/hwmon0/temp1_input", "bad");
        fixture.write("hwmon/hwmon0/temp2_label", "Sensor 1");
        fixture.write("hwmon/hwmon0/temp2_input", "-5000");
        let mut collector = fixture.collector();
        let group = collector.collect_thermal();
        assert!(group.available);
        assert!(group.partial);
        assert!(group.rows[0]["temperature_celsius"].is_null());
        assert!(group.rows[0]["error"].is_string());
        assert_eq!(number(&group.rows[1]["temperature_celsius"]), -5.0);
    }

    #[test]
    fn package_power_wrap_is_watts_and_subdomains_are_not_double_counted() {
        let fixture = Fixture::new();
        fixture.power(
            "intel-rapl/intel-rapl:0",
            "package-77",
            "90000000",
            "100000000",
        );
        fixture.power(
            "intel-rapl/intel-rapl:0/intel-rapl:0:0",
            "dram",
            "5000000",
            "100000000",
        );
        let mut collector = fixture.collector();
        let now = Instant::now();
        let first = collector.collect_power(now);
        assert!(first.available);
        assert!(first.rows.iter().all(|row| row["power_watts"].is_null()));
        fixture.power(
            "intel-rapl/intel-rapl:0",
            "package-77",
            "10000000",
            "100000000",
        );
        fixture.power(
            "intel-rapl/intel-rapl:0/intel-rapl:0:0",
            "dram",
            "9000000",
            "100000000",
        );
        let group = collector.collect_power(now + Duration::from_secs(2));
        assert!(group.available);
        assert_eq!(group.rows.len(), 2);
        let package = group
            .rows
            .iter()
            .find(|row| row["domain"] == "package-77")
            .unwrap();
        let dram = group
            .rows
            .iter()
            .find(|row| row["domain"] == "dram")
            .unwrap();
        assert_eq!(number(&package["power_watts"]), 10.0);
        assert_eq!(package["included_in_total"], true);
        assert_eq!(package["status"], "wrapped");
        assert_eq!(number(&dram["power_watts"]), 2.0);
        assert_eq!(dram["included_in_total"], false);
        assert_eq!(number(&group.summary["package_power_watts"]), 10.0);
    }

    #[test]
    fn power_read_gap_and_resets_require_new_baseline() {
        let fixture = Fixture::new();
        fixture.power("intel-rapl:0", "package-77", "40000000", "100000000");
        let mut collector = fixture.collector();
        let now = Instant::now();
        collector.collect_power(now);
        fixture.power("intel-rapl:0", "package-77", "20000000", "100000000");
        let reset = collector.collect_power(now + Duration::from_secs(1));
        assert!(reset.rows[0]["power_watts"].is_null());
        assert_eq!(reset.rows[0]["status"], "reset");
        fixture.power("intel-rapl:0", "package-77", "bad", "100000000");
        let gap = collector.collect_power(now + Duration::from_secs(2));
        assert!(!gap.available);
        assert!(gap.rows[0]["power_watts"].is_null());
        fixture.power("intel-rapl:0", "package-77", "40000000", "100000000");
        let recovered = collector.collect_power(now + Duration::from_secs(3));
        assert!(recovered.rows[0]["power_watts"].is_null());
        assert_eq!(recovered.rows[0]["status"], "baseline");
    }

    #[test]
    fn power_limits_preserve_microsecond_units_and_convert_microwatts() {
        let fixture = Fixture::new();
        fixture.power("intel-rapl:0", "package-77", "1", "100000000");
        fixture.write("powercap/intel-rapl:0/constraint_0_name", "long_term");
        fixture.write(
            "powercap/intel-rapl:0/constraint_0_power_limit_uw",
            "505000000",
        );
        fixture.write(
            "powercap/intel-rapl:0/constraint_0_time_window_us",
            "1000000",
        );
        let mut collector = fixture.collector();
        let group = collector.collect_power(Instant::now());
        assert!(group.available);
        assert_eq!(
            number(&group.rows[0]["power_limits"][0]["power_limit_watts"]),
            505.0
        );
        assert_eq!(
            group.rows[0]["power_limits"][0]["time_window_us"],
            1_000_000
        );
    }

    #[test]
    fn group_metadata_advances_attempts_and_preserves_last_success_on_failure() {
        let fixture = Fixture::new();
        fixture.write("hwmon/hwmon0/name", "nvme");
        fixture.write("hwmon/hwmon0/temp1_input", "40000");
        let mut collector = fixture.collector();
        let first = collector.collect();
        assert!(first["thermal"].available);
        assert_eq!(first["thermal"].meta.epoch, 0);
        assert_eq!(first["thermal"].meta.sample_seq, 1);
        assert!(first["thermal"].meta.captured_at_unix_ms.is_some());
        assert_eq!(
            first["thermal"].meta.last_success_at_unix_ms,
            first["thermal"].meta.captured_at_unix_ms
        );
        fixture.write("hwmon/hwmon0/temp1_input", "bad");
        let second = collector.collect();
        assert!(!second["thermal"].available);
        assert_eq!(second["thermal"].meta.sample_seq, 2);
        assert_eq!(
            second["thermal"].meta.last_success_at_unix_ms,
            first["thermal"].meta.last_success_at_unix_ms
        );
        assert!(second["thermal"].meta.error.is_some());
    }

    #[test]
    fn first_counter_interval_is_unknown_not_zero() {
        assert_eq!(
            counter_delta(None, 500, Duration::from_secs(1)),
            Delta {
                value: None,
                status: "baseline"
            }
        );
    }

    #[test]
    fn monotonic_counters_return_actual_delta_including_real_zero() {
        assert_eq!(
            counter_delta(Some(100), 250, Duration::from_secs(2)),
            Delta {
                value: Some(150),
                status: "measured"
            }
        );
        assert_eq!(
            counter_delta(Some(100), 100, Duration::from_secs(1)).value,
            Some(0)
        );
    }

    #[test]
    fn counter_reset_never_becomes_wrapped_huge_delta() {
        assert_eq!(
            counter_delta(Some(1_000), 100, Duration::from_secs(1)),
            Delta {
                value: None,
                status: "reset"
            }
        );
    }

    #[test]
    fn zero_elapsed_time_never_produces_a_rate() {
        assert_eq!(
            counter_delta(Some(1), 2, Duration::ZERO),
            Delta {
                value: None,
                status: "invalid_interval"
            }
        );
        assert_eq!(residency_pct(10, Duration::ZERO), None);
        assert_eq!(watts(10, Duration::ZERO), None);
    }

    #[test]
    fn residency_uses_full_wall_interval_including_active_time() {
        assert_eq!(residency_pct(200_000, Duration::from_secs(1)), Some(20.0));
        assert_eq!(residency_pct(200_000, Duration::from_secs(2)), Some(10.0));
    }

    #[test]
    fn power_is_delta_energy_per_second_not_cumulative_joules() {
        assert_eq!(watts(50_000_000, Duration::from_secs(2)), Some(25.0));
    }

    #[test]
    fn energy_wrap_uses_reported_counter_range() {
        assert_eq!(
            energy_delta(900, 100, Some(1_000)),
            Delta {
                value: Some(200),
                status: "wrapped"
            }
        );
    }

    #[test]
    fn energy_decrease_without_plausible_wrap_is_a_reset() {
        assert_eq!(
            energy_delta(400, 200, Some(1_000)),
            Delta {
                value: None,
                status: "reset"
            }
        );
        assert_eq!(
            energy_delta(900, 100, None),
            Delta {
                value: None,
                status: "reset"
            }
        );
        assert_eq!(
            energy_delta(900, 100, Some(0)),
            Delta {
                value: None,
                status: "invalid_counter"
            }
        );
    }

    #[test]
    fn energy_reading_outside_counter_range_is_unknown() {
        assert_eq!(
            energy_delta(1_200, 100, Some(1_000)),
            Delta {
                value: None,
                status: "invalid_counter"
            }
        );
        assert_eq!(
            energy_delta(100, 1_100, Some(1_000)),
            Delta {
                value: None,
                status: "invalid_counter"
            }
        );
    }
}
