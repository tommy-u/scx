// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::model::{
    summarize_callback_timing, CallbackTimingCounters, CallbackTimingHistory,
    CallbackTimingSnapshot, CpuPair, CpuUsageHistory, RollingHistory, WindowError, CALLBACK_NAMES,
    CALLBACK_TIMING_BUCKETS,
};
use crate::policies::PolicyCatalog;
use crate::scope::TaskScope;
use crate::topology::TopologyView;

#[derive(Clone, Debug, Serialize)]
pub struct CellView {
    pub from: u32,
    pub to: u32,
    pub count: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct SchedulerView {
    pub name: String,
    pub active: bool,
    pub enable_seq: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct CpuUsageView {
    pub cpu: u32,
    pub runtime_ns: u64,
    pub utilization_pct: f64,
}

#[derive(Clone, Debug, Serialize)]
pub struct InspectionSnapshotView {
    pub sequence: u64,
    pub error: Option<String>,
    pub snapshot: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize)]
pub struct PolicyCatalogSnapshotView {
    pub sequence: u64,
    pub error: Option<String>,
    pub catalog: Option<PolicyCatalog>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CallbackTimingStatus {
    Unavailable,
    Unsupported,
    Disabled,
    Ready,
}

#[derive(Clone, Debug, Serialize)]
pub struct CallbackTimingRowView {
    pub callback: String,
    pub samples: u64,
    pub mean_ns: Option<u64>,
    pub p50_ns: Option<u64>,
    pub p95_ns: Option<u64>,
    pub p99_ns: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CallbackTimingView {
    pub sequence: u64,
    pub status: CallbackTimingStatus,
    pub error: Option<String>,
    pub scope: &'static str,
    pub window_ms: Option<u64>,
    pub observed_ms: Option<u64>,
    pub generation: Option<u64>,
    pub sample_rate: u32,
    pub callbacks: Vec<CallbackTimingRowView>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SnapshotView {
    pub sequence: u64,
    pub window_ms: u64,
    pub observed_ms: u64,
    pub total: u64,
    pub rate_per_second: f64,
    pub active_pairs: usize,
    pub scheduler: SchedulerView,
    pub scope: TaskScope,
    pub collector_error: Option<String>,
    pub pair_map_failures: u64,
    pub task_storage_failures: u64,
    pub cpu_usage_observed_ms: u64,
    pub cpu_usage_scope: &'static str,
    pub cpu_usage_error: Option<String>,
    pub cpu_usage: Vec<CpuUsageView>,
    pub cells: Vec<CellView>,
}

struct LiveData {
    history: RollingHistory,
    cpu_history: CpuUsageHistory,
    now_ms: u64,
    cpu_now_ms: u64,
    sequence: u64,
    scheduler: SchedulerView,
    scope: TaskScope,
    collector_error: Option<String>,
    pair_map_failures: u64,
    task_storage_failures: u64,
    cpu_usage_error: Option<String>,
    inspection_sequence: u64,
    inspection_error: Option<String>,
    inspection: Option<serde_json::Value>,
    callback_timing_now_ms: u64,
    callback_timing_history: CallbackTimingHistory,
    callback_timing_status: CallbackTimingStatus,
    callback_timing_error: Option<String>,
    policy_catalog_sequence: u64,
    policy_catalog_error: Option<String>,
    policy_catalog: Option<PolicyCatalog>,
}

#[derive(Clone)]
pub struct Dashboard {
    topology: Arc<TopologyView>,
    live: Arc<RwLock<LiveData>>,
    updates: watch::Sender<u64>,
    max_window_ms: u64,
}

impl Dashboard {
    pub fn new(topology: TopologyView, max_window_ms: u64) -> Self {
        let (updates, _) = watch::channel(0);
        Self {
            topology: Arc::new(topology),
            live: Arc::new(RwLock::new(LiveData {
                history: RollingHistory::new(max_window_ms),
                cpu_history: CpuUsageHistory::new(max_window_ms),
                now_ms: 0,
                cpu_now_ms: 0,
                sequence: 0,
                scheduler: SchedulerView {
                    name: String::new(),
                    active: false,
                    enable_seq: 0,
                },
                scope: TaskScope::All,
                collector_error: None,
                pair_map_failures: 0,
                task_storage_failures: 0,
                cpu_usage_error: None,
                inspection_sequence: 0,
                inspection_error: None,
                inspection: None,
                callback_timing_now_ms: 0,
                callback_timing_history: CallbackTimingHistory::new(max_window_ms),
                callback_timing_status: CallbackTimingStatus::Unavailable,
                callback_timing_error: None,
                policy_catalog_sequence: 0,
                policy_catalog_error: None,
                policy_catalog: None,
            })),
            updates,
            max_window_ms,
        }
    }

    pub fn max_window_ms(&self) -> u64 {
        self.max_window_ms
    }

    pub fn topology(&self) -> Arc<TopologyView> {
        Arc::clone(&self.topology)
    }

    pub fn ingest(&self, at_ms: u64, counts: &BTreeMap<CpuPair, u64>) {
        let sequence = {
            let mut live = self.live.write().expect("dashboard lock poisoned");
            live.history.ingest(at_ms, counts);
            live.now_ms = at_ms;
            live.sequence = live.sequence.wrapping_add(1);
            live.sequence
        };
        self.updates.send_replace(sequence);
    }

    pub fn reset(&self, at_ms: u64, baseline: &BTreeMap<CpuPair, u64>) {
        let sequence = {
            let mut live = self.live.write().expect("dashboard lock poisoned");
            live.history.reset(at_ms, baseline);
            live.cpu_history.reset(at_ms);
            live.now_ms = at_ms;
            live.cpu_now_ms = at_ms;
            live.sequence = live.sequence.wrapping_add(1);
            live.sequence
        };
        self.updates.send_replace(sequence);
    }

    pub fn reset_migrations(&self, at_ms: u64, baseline: &BTreeMap<CpuPair, u64>) {
        let sequence = {
            let mut live = self.live.write().expect("dashboard lock poisoned");
            live.history.reset(at_ms, baseline);
            live.now_ms = at_ms;
            live.sequence = live.sequence.wrapping_add(1);
            live.sequence
        };
        self.updates.send_replace(sequence);
    }

    pub fn reset_cpu_usage(&self, at_ms: u64) {
        let sequence = {
            let mut live = self.live.write().expect("dashboard lock poisoned");
            live.cpu_history.reset(at_ms);
            live.cpu_now_ms = at_ms;
            live.sequence = live.sequence.wrapping_add(1);
            live.sequence
        };
        self.updates.send_replace(sequence);
    }

    pub fn ingest_cpu_usage(&self, at_ms: u64, runtime_ns: &BTreeMap<u32, u64>) {
        let sequence = {
            let mut live = self.live.write().expect("dashboard lock poisoned");
            live.cpu_history.ingest(at_ms, runtime_ns);
            live.cpu_now_ms = at_ms;
            live.sequence = live.sequence.wrapping_add(1);
            live.sequence
        };
        self.updates.send_replace(sequence);
    }

    pub fn set_scheduler(&self, name: impl Into<String>, active: bool, enable_seq: u64) {
        let sequence = {
            let mut live = self.live.write().expect("dashboard lock poisoned");
            live.scheduler = SchedulerView {
                name: name.into(),
                active,
                enable_seq,
            };
            live.sequence = live.sequence.wrapping_add(1);
            live.sequence
        };
        self.updates.send_replace(sequence);
    }

    pub fn set_scope(&self, scope: TaskScope) {
        let sequence = {
            let mut live = self.live.write().expect("dashboard lock poisoned");
            live.scope = scope;
            live.sequence = live.sequence.wrapping_add(1);
            live.sequence
        };
        self.updates.send_replace(sequence);
    }

    pub fn set_collector_health(
        &self,
        error: Option<String>,
        pair_map_failures: u64,
        task_storage_failures: u64,
    ) {
        let sequence = {
            let mut live = self.live.write().expect("dashboard lock poisoned");
            live.collector_error = error;
            live.pair_map_failures = pair_map_failures;
            live.task_storage_failures = task_storage_failures;
            live.sequence = live.sequence.wrapping_add(1);
            live.sequence
        };
        self.updates.send_replace(sequence);
    }

    pub fn set_cpu_usage_error(&self, error: Option<String>) {
        let sequence = {
            let mut live = self.live.write().expect("dashboard lock poisoned");
            live.cpu_usage_error = error;
            live.sequence = live.sequence.wrapping_add(1);
            live.sequence
        };
        self.updates.send_replace(sequence);
    }

    pub fn set_inspection(&self, snapshot: Option<serde_json::Value>, error: Option<String>) {
        let at_ms = self.live.read().expect("dashboard lock poisoned").now_ms;
        self.set_inspection_at(at_ms, snapshot, error);
    }

    pub fn set_inspection_at(
        &self,
        at_ms: u64,
        snapshot: Option<serde_json::Value>,
        error: Option<String>,
    ) {
        let mut live = self.live.write().expect("dashboard lock poisoned");
        live.inspection = snapshot.clone();
        live.inspection_error = error.clone();
        live.inspection_sequence = live.inspection_sequence.wrapping_add(1);
        live.callback_timing_now_ms = at_ms;
        live.callback_timing_error = None;
        match (snapshot.as_ref(), error) {
            (_, Some(error)) => {
                live.callback_timing_history.clear();
                live.callback_timing_status = CallbackTimingStatus::Unavailable;
                live.callback_timing_error = Some(error);
            }
            (None, None) => {
                live.callback_timing_history.clear();
                live.callback_timing_status = CallbackTimingStatus::Unavailable;
            }
            (Some(snapshot), None) => {
                match parse_callback_timing(snapshot, live.scheduler.enable_seq) {
                    Ok(Some(timing)) => {
                        live.callback_timing_status = if timing.sample_rate == 0 {
                            CallbackTimingStatus::Disabled
                        } else {
                            CallbackTimingStatus::Ready
                        };
                        live.callback_timing_history.ingest(at_ms, timing);
                    }
                    Ok(None) => {
                        live.callback_timing_history.clear();
                        live.callback_timing_status = CallbackTimingStatus::Unsupported;
                    }
                    Err(error) => {
                        live.callback_timing_history.clear();
                        live.callback_timing_status = CallbackTimingStatus::Unavailable;
                        live.callback_timing_error = Some(error);
                    }
                }
            }
        }
    }

    pub fn inspection(&self) -> InspectionSnapshotView {
        let live = self.live.read().expect("dashboard lock poisoned");
        InspectionSnapshotView {
            sequence: live.inspection_sequence,
            error: live.inspection_error.clone(),
            snapshot: live.inspection.clone(),
        }
    }

    pub fn set_policy_catalog(&self, catalog: Option<PolicyCatalog>, error: Option<String>) {
        let mut live = self.live.write().expect("dashboard lock poisoned");
        live.policy_catalog = catalog;
        live.policy_catalog_error = error;
        live.policy_catalog_sequence = live.policy_catalog_sequence.wrapping_add(1);
    }

    pub fn policy_catalog(&self) -> PolicyCatalogSnapshotView {
        let live = self.live.read().expect("dashboard lock poisoned");
        PolicyCatalogSnapshotView {
            sequence: live.policy_catalog_sequence,
            error: live.policy_catalog_error.clone(),
            catalog: live.policy_catalog.clone(),
        }
    }

    pub fn callback_timing_window(
        &self,
        window_ms: u64,
    ) -> Result<CallbackTimingView, WindowError> {
        let live = self.live.read().expect("dashboard lock poisoned");
        let timing = live
            .callback_timing_history
            .window(live.callback_timing_now_ms, window_ms)?;
        Ok(callback_timing_view(
            &live,
            "window",
            Some(window_ms),
            timing.as_ref().map(|timing| timing.observed_ms),
            timing.as_ref().map(|timing| timing.generation),
            timing.as_ref().map_or(0, |timing| timing.sample_rate),
            timing.as_ref().map(|timing| &timing.callbacks),
        ))
    }

    pub fn callback_timing_lifetime(&self) -> CallbackTimingView {
        let live = self.live.read().expect("dashboard lock poisoned");
        let timing = live.callback_timing_history.lifetime();
        callback_timing_view(
            &live,
            "lifetime",
            None,
            None,
            timing.map(|timing| timing.generation),
            timing.map_or(0, |timing| timing.sample_rate),
            timing.map(|timing| &timing.callbacks),
        )
    }

    pub fn snapshot(&self, window_ms: u64) -> Result<SnapshotView, WindowError> {
        let live = self.live.read().expect("dashboard lock poisoned");
        let view = live.history.view(live.now_ms, window_ms)?;
        let cpu_view = live.cpu_history.view(live.cpu_now_ms, window_ms)?;
        let cells = view
            .cells
            .into_iter()
            .map(|(pair, count)| CellView {
                from: pair.from,
                to: pair.to,
                count,
            })
            .collect::<Vec<_>>();
        let rate_per_second = if view.observed_ms == 0 {
            0.0
        } else {
            view.total as f64 * 1_000.0 / view.observed_ms as f64
        };
        let cpu_usage = cpu_view
            .runtime_ns
            .into_iter()
            .map(|(cpu, runtime_ns)| {
                let utilization_pct = if cpu_view.observed_ms == 0 {
                    0.0
                } else {
                    runtime_ns as f64 * 100.0 / (cpu_view.observed_ms as f64 * 1_000_000.0)
                };
                CpuUsageView {
                    cpu,
                    runtime_ns,
                    utilization_pct,
                }
            })
            .collect();

        Ok(SnapshotView {
            sequence: live.sequence,
            window_ms,
            observed_ms: view.observed_ms,
            total: view.total,
            rate_per_second,
            active_pairs: cells.len(),
            scheduler: live.scheduler.clone(),
            scope: live.scope.clone(),
            collector_error: live.collector_error.clone(),
            pair_map_failures: live.pair_map_failures,
            task_storage_failures: live.task_storage_failures,
            cpu_usage_observed_ms: cpu_view.observed_ms,
            cpu_usage_scope: "all_snake_tasks",
            cpu_usage_error: live.cpu_usage_error.clone(),
            cpu_usage,
            cells,
        })
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.updates.subscribe()
    }
}

fn callback_timing_view(
    live: &LiveData,
    scope: &'static str,
    window_ms: Option<u64>,
    observed_ms: Option<u64>,
    generation: Option<u64>,
    sample_rate: u32,
    timing: Option<&BTreeMap<String, CallbackTimingCounters>>,
) -> CallbackTimingView {
    let callbacks = timing.map_or_else(Vec::new, |timing| {
        CALLBACK_NAMES
            .iter()
            .filter_map(|name| {
                let summary = summarize_callback_timing(timing.get(*name)?);
                Some(CallbackTimingRowView {
                    callback: (*name).into(),
                    samples: summary.samples,
                    mean_ns: summary.mean_ns,
                    p50_ns: summary.p50_ns,
                    p95_ns: summary.p95_ns,
                    p99_ns: summary.p99_ns,
                })
            })
            .collect()
    });
    CallbackTimingView {
        sequence: live.inspection_sequence,
        status: live.callback_timing_status,
        error: live.callback_timing_error.clone(),
        scope,
        window_ms,
        observed_ms,
        generation,
        sample_rate,
        callbacks,
    }
}

#[derive(Deserialize)]
struct TimingMetricsView {
    callback_timing: BTreeMap<String, CallbackTimingCounters>,
}

fn parse_callback_timing(
    snapshot: &serde_json::Value,
    enable_seq: u64,
) -> Result<Option<CallbackTimingSnapshot>, String> {
    let Some(sample_rate) = snapshot.get("callback_timing_sample_rate") else {
        return Ok(None);
    };
    let sample_rate = sample_rate
        .as_u64()
        .and_then(|rate| u32::try_from(rate).ok())
        .ok_or_else(|| "invalid callback timing sample rate in inspection data".to_string())?;
    let active_slot = snapshot
        .get("active_slot")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "inspection data has no active slot".to_string())?;
    let slot = snapshot
        .get("slots")
        .and_then(serde_json::Value::as_array)
        .and_then(|slots| {
            slots.iter().find(|slot| {
                slot.get("slot").and_then(serde_json::Value::as_u64) == Some(active_slot)
            })
        })
        .ok_or_else(|| "inspection data has no active slot metrics".to_string())?;
    let generation = slot
        .get("generation")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| "active slot has no policy generation".to_string())?;
    let metrics = serde_json::from_value::<TimingMetricsView>(
        slot.get("metrics")
            .cloned()
            .ok_or_else(|| "active slot has no callback timing metrics".to_string())?,
    )
    .map_err(|error| format!("invalid callback timing metrics: {error}"))?;
    if metrics.callback_timing.len() != CALLBACK_NAMES.len()
        || !CALLBACK_NAMES
            .iter()
            .all(|name| metrics.callback_timing.contains_key(*name))
    {
        return Err("active slot does not contain all callback timing rows".into());
    }
    if metrics
        .callback_timing
        .values()
        .any(|timing| timing.buckets.len() != CALLBACK_TIMING_BUCKETS)
    {
        return Err(format!(
            "callback timing histograms must contain {CALLBACK_TIMING_BUCKETS} buckets"
        ));
    }
    Ok(Some(CallbackTimingSnapshot {
        enable_seq,
        generation,
        sample_rate,
        callbacks: metrics.callback_timing,
    }))
}
