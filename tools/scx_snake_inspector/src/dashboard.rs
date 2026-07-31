// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::model::{
    summarize_callback_timing, CallbackTimingCounters, CallbackTimingHistory,
    CallbackTimingSnapshot, CellMetricCounters, CellMetricHistory, CellMetricWindow, CpuPair,
    CpuUsageHistory, RollingHistory, WindowError, CALLBACK_NAMES, CALLBACK_TIMING_BUCKETS,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RuntimeContextView {
    pub scheduler_attach_seq: u64,
    pub observed_at_ms: Option<u64>,
    pub scheduler_active: bool,
    pub policy_generation: Option<u64>,
    pub active_slot: Option<u32>,
    pub fairness: Option<String>,
    pub callback_sample_rate: Option<u32>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CpuUsageView {
    pub cpu: u32,
    pub runtime_ns: u64,
    pub utilization_pct: f64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CellStatsStatus {
    Ready,
    NotApplicable,
    Unsupported,
    Synchronizing,
    Unavailable,
}

#[derive(Clone, Debug, Serialize)]
pub struct CellStatsRowView {
    pub id: u32,
    pub index: u32,
    pub primary_cpu_count: usize,
    pub runtime_ns: u64,
    pub primary_runtime_ns: u64,
    pub borrowed_runtime_ns: u64,
    pub lent_runtime_ns: u64,
    pub normal_enqueues: u64,
    pub affinity_enqueues: u64,
    pub normal_dispatches: u64,
    pub affinity_dispatches: u64,
    pub clock_transitions: u64,
    pub service_cores: Option<f64>,
    pub service_share_pct: Option<f64>,
    pub primary_pct: Option<f64>,
    pub borrowed_pct: Option<f64>,
    pub owned_utilization_pct: Option<f64>,
    pub enqueue_rate_per_second: Option<f64>,
    pub dispatch_rate_per_second: Option<f64>,
    pub affinity_enqueue_share_pct: Option<f64>,
    pub affinity_dispatch_share_pct: Option<f64>,
    pub transition_rate_per_second: Option<f64>,
    pub transitions_per_1k_dispatches: Option<f64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CellStatsView {
    pub status: CellStatsStatus,
    pub error: Option<String>,
    pub scope: &'static str,
    pub source_policy_generation: Option<u64>,
    pub window_ms: u64,
    pub observed_ms: u64,
    pub cells: Vec<CellStatsRowView>,
}

#[derive(Clone, Debug, Serialize)]
pub struct InspectionSnapshotView {
    pub sequence: u64,
    pub context: RuntimeContextView,
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
    pub context: RuntimeContextView,
    pub status: CallbackTimingStatus,
    pub error: Option<String>,
    pub scope: &'static str,
    pub window_ms: Option<u64>,
    pub observed_ms: Option<u64>,
    pub generation: Option<u64>,
    pub sample_rate: u32,
    pub callbacks: Vec<CallbackTimingRowView>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FineTimingStatus {
    Unavailable,
    Unsupported,
    Ready,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FineTimingCaptureState {
    Inactive,
    Collecting,
    Historical,
}

#[derive(Clone, Debug, Serialize)]
pub struct FineTimingStageView {
    pub stage: String,
    pub samples: u64,
    pub mean_ns: Option<u64>,
    pub p50_ns: Option<u64>,
    pub p95_ns: Option<u64>,
    pub p99_ns: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FineTimingDsqOperationView {
    pub dsq_id: String,
    pub operation: String,
    pub outcome: String,
    pub samples: u64,
    pub mean_ns: Option<u64>,
    pub p50_ns: Option<u64>,
    pub p95_ns: Option<u64>,
    pub p99_ns: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FineTimingDsqTransferView {
    pub source_dsq_id: String,
    pub target_dsq_id: String,
    pub samples: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct FineTimingCaptureView {
    pub callback: String,
    pub available: bool,
    pub unavailable_reason: Option<String>,
    pub state: FineTimingCaptureState,
    pub session_id: Option<u64>,
    pub policy_generation: Option<u64>,
    pub started_at_ms: Option<u64>,
    pub stopped_at_ms: Option<u64>,
    pub stages: Vec<FineTimingStageView>,
    pub dsq_operations: Vec<FineTimingDsqOperationView>,
    pub dsq_transfers: Vec<FineTimingDsqTransferView>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FineTimingView {
    pub sequence: u64,
    pub context: RuntimeContextView,
    pub status: FineTimingStatus,
    pub error: Option<String>,
    pub sample_rate: u32,
    pub captures: Vec<FineTimingCaptureView>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueTimingStatus {
    Unavailable,
    Unsupported,
    NotApplicable,
    Disabled,
    Ready,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueTimingCaptureState {
    Inactive,
    Collecting,
    Historical,
}

#[derive(Clone, Debug, Serialize)]
pub struct QueueResidenceView {
    pub samples: u64,
    pub total_ns: u64,
    pub mean_ns: Option<u64>,
    pub p50_ns: Option<u64>,
    pub p95_ns: Option<u64>,
    pub p99_ns: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct QueueDepthView {
    pub samples: u64,
    pub latest: Option<u64>,
    pub p95: Option<u64>,
    pub max: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct QueueTimingDsqView {
    pub dsq_id: String,
    pub cell_index: u32,
    pub queue_class: String,
    pub residence: QueueResidenceView,
    pub depth: QueueDepthView,
}

#[derive(Clone, Debug, Serialize)]
pub struct QueueTimingView {
    pub sequence: u64,
    pub context: RuntimeContextView,
    pub status: QueueTimingStatus,
    pub error: Option<String>,
    pub sample_rate: u32,
    pub state: Option<QueueTimingCaptureState>,
    pub session_id: Option<u64>,
    pub policy_generation: Option<u64>,
    pub started_at_ms: Option<u64>,
    pub stopped_at_ms: Option<u64>,
    pub started_samples: u64,
    pub completed_samples: u64,
    pub dropped_samples: u64,
    pub dsqs: Vec<QueueTimingDsqView>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SnapshotView {
    pub sequence: u64,
    pub context: RuntimeContextView,
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
    pub cell_stats: CellStatsView,
    pub cells: Vec<CellView>,
}

struct LiveData {
    history: RollingHistory,
    cpu_history: CpuUsageHistory,
    cell_history: CellMetricHistory,
    now_ms: u64,
    cpu_now_ms: u64,
    top_policy_generation: Option<u64>,
    top_cells_present: Option<bool>,
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
                cell_history: CellMetricHistory::new(max_window_ms),
                now_ms: 0,
                cpu_now_ms: 0,
                top_policy_generation: None,
                top_cells_present: None,
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

    pub fn runtime_context(&self) -> RuntimeContextView {
        let live = self.live.read().expect("dashboard lock poisoned");
        runtime_context(&live)
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
            live.cell_history.clear();
            live.now_ms = at_ms;
            live.cpu_now_ms = at_ms;
            live.top_policy_generation = None;
            live.top_cells_present = None;
            live.sequence = live.sequence.wrapping_add(1);
            live.sequence
        };
        self.updates.send_replace(sequence);
    }

    pub fn reset_statistics(&self, at_ms: u64, baseline: &BTreeMap<CpuPair, u64>) {
        let sequence = {
            let mut live = self.live.write().expect("dashboard lock poisoned");
            live.history.reset(at_ms, baseline);
            live.cpu_history.reset(at_ms);
            live.cell_history.clear();
            live.now_ms = at_ms;
            live.cpu_now_ms = at_ms;
            live.top_policy_generation = None;
            live.top_cells_present = None;
            live.inspection = None;
            live.inspection_error = None;
            live.inspection_sequence = live.inspection_sequence.wrapping_add(1);
            live.callback_timing_now_ms = at_ms;
            live.callback_timing_history.clear();
            live.callback_timing_status = CallbackTimingStatus::Unavailable;
            live.callback_timing_error = None;
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

    pub fn reset_top_metrics(&self, at_ms: u64) {
        let sequence = {
            let mut live = self.live.write().expect("dashboard lock poisoned");
            live.cpu_history.reset(at_ms);
            live.cell_history.clear();
            live.cpu_now_ms = at_ms;
            live.top_policy_generation = None;
            live.top_cells_present = None;
            live.sequence = live.sequence.wrapping_add(1);
            live.sequence
        };
        self.updates.send_replace(sequence);
    }

    pub fn reset_cpu_usage(&self, at_ms: u64) {
        self.reset_top_metrics(at_ms);
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

    pub fn ingest_top_metrics(
        &self,
        at_ms: u64,
        policy_generation: u64,
        runtime_ns: &BTreeMap<u32, u64>,
        cells: Option<&BTreeMap<u32, CellMetricCounters>>,
    ) {
        let sequence = {
            let mut live = self.live.write().expect("dashboard lock poisoned");
            let generation_changed = live
                .top_policy_generation
                .is_some_and(|previous| previous != policy_generation);
            if generation_changed {
                live.cpu_history.reset(at_ms);
            } else {
                live.cpu_history.ingest(at_ms, runtime_ns);
            }
            live.cpu_now_ms = at_ms;
            live.top_policy_generation = Some(policy_generation);
            live.top_cells_present = Some(cells.is_some());
            if let Some(cells) = cells {
                let scheduler_attach_seq = live.scheduler.enable_seq;
                live.cell_history
                    .ingest(at_ms, scheduler_attach_seq, policy_generation, cells);
            } else {
                live.cell_history.clear();
            }
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
            context: runtime_context(&live),
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

    pub fn fine_timing(&self) -> FineTimingView {
        let live = self.live.read().expect("dashboard lock poisoned");
        if let Some(error) = &live.inspection_error {
            return empty_fine_timing_view(
                &live,
                FineTimingStatus::Unavailable,
                Some(error.clone()),
            );
        }
        let Some(snapshot) = &live.inspection else {
            return empty_fine_timing_view(&live, FineTimingStatus::Unavailable, None);
        };
        let Some(payload) = snapshot.get("fine_timing") else {
            return empty_fine_timing_view(&live, FineTimingStatus::Unsupported, None);
        };
        match serde_json::from_value::<FineTimingPayload>(payload.clone())
            .map_err(|error| format!("invalid fine timing data: {error}"))
            .and_then(validate_fine_timing)
        {
            Ok(payload) => FineTimingView {
                sequence: live.inspection_sequence,
                context: runtime_context(&live),
                status: FineTimingStatus::Ready,
                error: None,
                sample_rate: payload.sample_rate,
                captures: payload
                    .captures
                    .into_iter()
                    .map(|capture| {
                        let unavailable_reason = if payload.sample_rate == 0 {
                            Some(
                                "Enable callback sampling to collect fine-grained timestamps."
                                    .to_owned(),
                            )
                        } else {
                            None
                        };
                        FineTimingCaptureView {
                            callback: capture.callback,
                            available: unavailable_reason.is_none(),
                            unavailable_reason,
                            state: capture.state,
                            session_id: capture.session_id,
                            policy_generation: capture.policy_generation,
                            started_at_ms: capture.started_at_ms,
                            stopped_at_ms: capture.stopped_at_ms,
                            stages: capture
                                .stages
                                .into_iter()
                                .map(|(stage, counters)| {
                                    let summary = summarize_callback_timing(&counters);
                                    FineTimingStageView {
                                        stage,
                                        samples: summary.samples,
                                        mean_ns: summary.mean_ns,
                                        p50_ns: summary.p50_ns,
                                        p95_ns: summary.p95_ns,
                                        p99_ns: summary.p99_ns,
                                    }
                                })
                                .collect(),
                            dsq_operations: capture
                                .dsq_operations
                                .into_iter()
                                .map(|operation| {
                                    let summary = summarize_callback_timing(&operation.timing);
                                    FineTimingDsqOperationView {
                                        dsq_id: operation.dsq_id.to_string(),
                                        operation: operation.operation,
                                        outcome: operation.outcome,
                                        samples: summary.samples,
                                        mean_ns: summary.mean_ns,
                                        p50_ns: summary.p50_ns,
                                        p95_ns: summary.p95_ns,
                                        p99_ns: summary.p99_ns,
                                    }
                                })
                                .collect(),
                            dsq_transfers: capture
                                .dsq_transfers
                                .into_iter()
                                .map(|transfer| FineTimingDsqTransferView {
                                    source_dsq_id: transfer.source_dsq_id.to_string(),
                                    target_dsq_id: transfer.target_dsq_id.to_string(),
                                    samples: transfer.samples,
                                })
                                .collect(),
                        }
                    })
                    .collect(),
            },
            Err(error) => empty_fine_timing_view(&live, FineTimingStatus::Unavailable, Some(error)),
        }
    }

    pub fn queue_timing(&self) -> QueueTimingView {
        let live = self.live.read().expect("dashboard lock poisoned");
        if !live.scheduler.active {
            return empty_queue_timing_view(&live, QueueTimingStatus::Unavailable, None);
        }
        if let Some(error) = &live.inspection_error {
            return empty_queue_timing_view(
                &live,
                QueueTimingStatus::Unavailable,
                Some(error.clone()),
            );
        }
        let Some(snapshot) = &live.inspection else {
            return empty_queue_timing_view(&live, QueueTimingStatus::Unavailable, None);
        };
        let Some(payload) = snapshot.get("queue_timing") else {
            return empty_queue_timing_view(&live, QueueTimingStatus::Unsupported, None);
        };
        match serde_json::from_value::<QueueTimingPayload>(payload.clone())
            .map_err(|error| format!("invalid queue timing data: {error}"))
            .and_then(validate_queue_timing)
        {
            Ok(payload) => queue_timing_view(&live, payload),
            Err(error) => {
                empty_queue_timing_view(&live, QueueTimingStatus::Unavailable, Some(error))
            }
        }
    }

    pub fn snapshot(&self, window_ms: u64) -> Result<SnapshotView, WindowError> {
        let live = self.live.read().expect("dashboard lock poisoned");
        let view = live.history.view(live.now_ms, window_ms)?;
        let cpu_view = live.cpu_history.view(live.cpu_now_ms, window_ms)?;
        let cell_window = live.cell_history.view(live.cpu_now_ms, window_ms)?;
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
        let cell_stats = cell_stats_view(&live, window_ms, cell_window.as_ref());

        Ok(SnapshotView {
            sequence: live.sequence,
            context: runtime_context(&live),
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
            cell_stats,
            cells,
        })
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.updates.subscribe()
    }
}

fn runtime_context(live: &LiveData) -> RuntimeContextView {
    let inspection = live.inspection.as_ref();
    let active_slot = inspection
        .and_then(|snapshot| snapshot.get("active_slot"))
        .and_then(serde_json::Value::as_u64)
        .and_then(|slot| u32::try_from(slot).ok());
    let policy_generation = active_slot.and_then(|active_slot| {
        inspection?
            .get("slots")?
            .as_array()?
            .iter()
            .find(|slot| {
                slot.get("slot").and_then(serde_json::Value::as_u64) == Some(u64::from(active_slot))
            })?
            .get("generation")?
            .as_u64()
    });
    let fairness = inspection
        .and_then(|snapshot| snapshot.pointer("/fairness/mode_name"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let callback_sample_rate = inspection
        .and_then(|snapshot| snapshot.get("callback_timing_sample_rate"))
        .and_then(serde_json::Value::as_u64)
        .and_then(|rate| u32::try_from(rate).ok());

    RuntimeContextView {
        scheduler_attach_seq: live.scheduler.enable_seq,
        observed_at_ms: (live.callback_timing_now_ms > 0).then_some(live.callback_timing_now_ms),
        scheduler_active: live.scheduler.active,
        policy_generation,
        active_slot,
        fairness,
        callback_sample_rate,
    }
}

#[derive(Deserialize)]
struct CellStatsTopology {
    cells: Vec<CellStatsTopologyCell>,
}

#[derive(Deserialize)]
struct CellStatsTopologyCell {
    external_id: u32,
    index: u32,
    primary_cpus: Vec<u32>,
}

fn cell_stats_view(
    live: &LiveData,
    window_ms: u64,
    window: Option<&CellMetricWindow>,
) -> CellStatsView {
    let source_policy_generation = live.top_policy_generation;
    let empty = |status, error| CellStatsView {
        status,
        error,
        scope: "all_snake_tasks",
        source_policy_generation,
        window_ms,
        observed_ms: window.map_or(0, |window| window.observed_ms),
        cells: Vec::new(),
    };
    if !live.scheduler.active {
        return empty(CellStatsStatus::Unavailable, None);
    }
    if let Some(error) = &live.inspection_error {
        return empty(CellStatsStatus::Unavailable, Some(error.clone()));
    }
    let Some(inspection) = &live.inspection else {
        return empty(CellStatsStatus::Unavailable, None);
    };
    let Some(topology) = inspection.get("queue_topology") else {
        return empty(CellStatsStatus::Unsupported, None);
    };
    if topology.is_null() {
        return empty(CellStatsStatus::NotApplicable, None);
    }
    if topology.get("layout").and_then(serde_json::Value::as_str) == Some("llc") {
        return empty(CellStatsStatus::NotApplicable, None);
    }
    if let Some(error) = &live.cpu_usage_error {
        return empty(CellStatsStatus::Unavailable, Some(error.clone()));
    }
    match live.top_cells_present {
        Some(false) => return empty(CellStatsStatus::Unsupported, None),
        None => return empty(CellStatsStatus::Unavailable, None),
        Some(true) => {}
    }
    let context = runtime_context(live);
    let Some(source_policy_generation) = source_policy_generation else {
        return empty(CellStatsStatus::Unavailable, None);
    };
    if context.policy_generation != Some(source_policy_generation) {
        return empty(CellStatsStatus::Synchronizing, None);
    }
    let Some(window) = window else {
        return empty(CellStatsStatus::Unavailable, None);
    };
    if window.scheduler_attach_seq != live.scheduler.enable_seq
        || window.policy_generation != source_policy_generation
    {
        return empty(CellStatsStatus::Synchronizing, None);
    }
    let topology = match serde_json::from_value::<CellStatsTopology>(topology.clone()) {
        Ok(topology) => topology,
        Err(error) => {
            return empty(
                CellStatsStatus::Unavailable,
                Some(format!(
                    "invalid queue topology for cell statistics: {error}"
                )),
            );
        }
    };
    let mut cells_by_id = BTreeMap::new();
    for cell in topology.cells {
        if cells_by_id.insert(cell.external_id, cell).is_some() {
            return empty(
                CellStatsStatus::Unavailable,
                Some("queue topology contains duplicate cell IDs".into()),
            );
        }
    }
    let service_runtime_ns = window
        .cells
        .values()
        .fold(0_u64, |total, cell| total.saturating_add(cell.runtime_ns));
    let mut cells = Vec::with_capacity(window.cells.len());
    for cell in window.cells.values() {
        let Some(topology_cell) = cells_by_id.get(&cell.id) else {
            return empty(
                CellStatsStatus::Unavailable,
                Some(format!(
                    "cell metric {} is absent from the active queue topology",
                    cell.id
                )),
            );
        };
        if topology_cell.index != cell.index {
            return empty(
                CellStatsStatus::Unavailable,
                Some(format!(
                    "cell metric {} has index {}, active topology has index {}",
                    cell.id, cell.index, topology_cell.index
                )),
            );
        }
        cells.push(cell_stats_row(
            cell,
            topology_cell.primary_cpus.len(),
            service_runtime_ns,
            window.observed_ms,
        ));
    }
    CellStatsView {
        status: CellStatsStatus::Ready,
        error: None,
        scope: "all_snake_tasks",
        source_policy_generation: Some(source_policy_generation),
        window_ms,
        observed_ms: window.observed_ms,
        cells,
    }
}

fn cell_stats_row(
    cell: &CellMetricCounters,
    primary_cpu_count: usize,
    service_runtime_ns: u64,
    observed_ms: u64,
) -> CellStatsRowView {
    let enqueues = cell.normal_enqueues.saturating_add(cell.affinity_enqueues);
    let dispatches = cell
        .normal_dispatches
        .saturating_add(cell.affinity_dispatches);
    let observed_ns = observed_ms as f64 * 1_000_000.0;
    let owned_capacity_ns = primary_cpu_count as f64 * observed_ns;
    CellStatsRowView {
        id: cell.id,
        index: cell.index,
        primary_cpu_count,
        runtime_ns: cell.runtime_ns,
        primary_runtime_ns: cell.primary_runtime_ns,
        borrowed_runtime_ns: cell.borrowed_runtime_ns,
        lent_runtime_ns: cell.lent_runtime_ns,
        normal_enqueues: cell.normal_enqueues,
        affinity_enqueues: cell.affinity_enqueues,
        normal_dispatches: cell.normal_dispatches,
        affinity_dispatches: cell.affinity_dispatches,
        clock_transitions: cell.clock_transitions,
        service_cores: (observed_ns > 0.0).then(|| cell.runtime_ns as f64 / observed_ns),
        service_share_pct: percentage(cell.runtime_ns, service_runtime_ns),
        primary_pct: percentage(cell.primary_runtime_ns, cell.runtime_ns),
        borrowed_pct: percentage(cell.borrowed_runtime_ns, cell.runtime_ns),
        owned_utilization_pct: (owned_capacity_ns > 0.0).then(|| {
            (cell.primary_runtime_ns as f64 + cell.lent_runtime_ns as f64) * 100.0
                / owned_capacity_ns
        }),
        enqueue_rate_per_second: per_second(enqueues, observed_ms),
        dispatch_rate_per_second: per_second(dispatches, observed_ms),
        affinity_enqueue_share_pct: percentage(cell.affinity_enqueues, enqueues),
        affinity_dispatch_share_pct: percentage(cell.affinity_dispatches, dispatches),
        transition_rate_per_second: per_second(cell.clock_transitions, observed_ms),
        transitions_per_1k_dispatches: (dispatches > 0)
            .then(|| cell.clock_transitions as f64 * 1_000.0 / dispatches as f64),
    }
}

fn percentage(numerator: u64, denominator: u64) -> Option<f64> {
    (denominator > 0).then(|| numerator as f64 * 100.0 / denominator as f64)
}

fn per_second(count: u64, observed_ms: u64) -> Option<f64> {
    (observed_ms > 0).then(|| count as f64 * 1_000.0 / observed_ms as f64)
}

const QUEUE_RESIDENCE_BUCKETS: usize = 64;
const QUEUE_DEPTH_BUCKETS: usize = 256;

#[derive(Deserialize)]
struct QueueTimingPayload {
    sample_rate: u32,
    state: QueueTimingCaptureState,
    session_id: Option<u64>,
    policy_generation: Option<u64>,
    started_at_ms: Option<u64>,
    stopped_at_ms: Option<u64>,
    started_samples: u64,
    completed_samples: u64,
    dropped_samples: u64,
    dsqs: Vec<QueueTimingDsqPayload>,
}

#[derive(Deserialize)]
struct QueueTimingDsqPayload {
    dsq_id: u64,
    cell_index: u32,
    queue_class: String,
    residence: CallbackTimingCounters,
    depth: QueueDepthPayload,
}

#[derive(Deserialize)]
struct QueueDepthPayload {
    samples: u64,
    latest: u64,
    max: u64,
    buckets: Vec<u64>,
}

fn validate_queue_timing(payload: QueueTimingPayload) -> Result<QueueTimingPayload, String> {
    let mut dsq_ids = BTreeMap::new();
    for dsq in &payload.dsqs {
        if !matches!(dsq.queue_class.as_str(), "normal" | "affinity" | "fairness") {
            return Err(format!("invalid queue class `{}`", dsq.queue_class));
        }
        if dsq.residence.buckets.len() != QUEUE_RESIDENCE_BUCKETS {
            return Err(format!(
                "queue residence histograms must contain {QUEUE_RESIDENCE_BUCKETS} buckets"
            ));
        }
        if dsq.depth.buckets.len() != QUEUE_DEPTH_BUCKETS {
            return Err(format!(
                "queue depth histograms must contain {QUEUE_DEPTH_BUCKETS} buckets"
            ));
        }
        let depth_samples = dsq
            .depth
            .buckets
            .iter()
            .fold(0_u64, |total, count| total.saturating_add(*count));
        if depth_samples != dsq.depth.samples {
            return Err(format!(
                "queue depth histogram for DSQ {} has {depth_samples} samples, expected {}",
                dsq.dsq_id, dsq.depth.samples
            ));
        }
        if dsq.depth.samples > 0 && dsq.depth.latest > dsq.depth.max {
            return Err(format!(
                "queue depth latest value exceeds maximum for DSQ {}",
                dsq.dsq_id
            ));
        }
        if dsq_ids.insert(dsq.dsq_id, ()).is_some() {
            return Err(format!("duplicate queue timing DSQ {}", dsq.dsq_id));
        }
    }
    Ok(payload)
}

fn queue_timing_view(live: &LiveData, payload: QueueTimingPayload) -> QueueTimingView {
    let status = if payload.sample_rate == 0 {
        QueueTimingStatus::Disabled
    } else {
        QueueTimingStatus::Ready
    };
    QueueTimingView {
        sequence: live.inspection_sequence,
        context: runtime_context(live),
        status,
        error: None,
        sample_rate: payload.sample_rate,
        state: Some(payload.state),
        session_id: payload.session_id,
        policy_generation: payload.policy_generation,
        started_at_ms: payload.started_at_ms,
        stopped_at_ms: payload.stopped_at_ms,
        started_samples: payload.started_samples,
        completed_samples: payload.completed_samples,
        dropped_samples: payload.dropped_samples,
        dsqs: payload
            .dsqs
            .into_iter()
            .map(|dsq| {
                let residence = summarize_callback_timing(&dsq.residence);
                QueueTimingDsqView {
                    dsq_id: dsq.dsq_id.to_string(),
                    cell_index: dsq.cell_index,
                    queue_class: dsq.queue_class,
                    residence: QueueResidenceView {
                        samples: residence.samples,
                        total_ns: dsq.residence.total_ns,
                        mean_ns: residence.mean_ns,
                        p50_ns: residence.p50_ns,
                        p95_ns: residence.p95_ns,
                        p99_ns: residence.p99_ns,
                    },
                    depth: QueueDepthView {
                        samples: dsq.depth.samples,
                        latest: (dsq.depth.samples > 0).then_some(dsq.depth.latest),
                        p95: linear_percentile(&dsq.depth.buckets, dsq.depth.samples, 95, 20),
                        max: (dsq.depth.samples > 0).then_some(dsq.depth.max),
                    },
                }
            })
            .collect(),
    }
}

fn linear_percentile(
    buckets: &[u64],
    samples: u64,
    percentile: u64,
    minimum_samples: u64,
) -> Option<u64> {
    if samples < minimum_samples {
        return None;
    }
    let rank = (u128::from(samples) * u128::from(percentile) + 99) / 100;
    let mut cumulative = 0_u128;
    for (value, count) in buckets.iter().enumerate() {
        cumulative += u128::from(*count);
        if cumulative >= rank {
            return u64::try_from(value).ok();
        }
    }
    None
}

fn empty_queue_timing_view(
    live: &LiveData,
    status: QueueTimingStatus,
    error: Option<String>,
) -> QueueTimingView {
    QueueTimingView {
        sequence: live.inspection_sequence,
        context: runtime_context(live),
        status,
        error,
        sample_rate: 0,
        state: None,
        session_id: None,
        policy_generation: None,
        started_at_ms: None,
        stopped_at_ms: None,
        started_samples: 0,
        completed_samples: 0,
        dropped_samples: 0,
        dsqs: Vec::new(),
    }
}

const REQUIRED_FINE_TIMING_CALLBACKS: [&str; 3] = ["select_cpu", "enqueue", "dispatch"];
const FINE_TIMING_CALLBACKS: [&str; 7] = [
    "select_cpu",
    "enqueue",
    "dispatch",
    "runnable",
    "running",
    "stopping",
    "quiescent",
];
const FINE_TIMING_BUCKETS: usize = 32;

#[derive(Deserialize)]
struct FineTimingPayload {
    sample_rate: u32,
    captures: Vec<FineTimingCapturePayload>,
}

#[derive(Deserialize)]
struct FineTimingCapturePayload {
    callback: String,
    state: FineTimingCaptureState,
    session_id: Option<u64>,
    policy_generation: Option<u64>,
    started_at_ms: Option<u64>,
    stopped_at_ms: Option<u64>,
    stages: BTreeMap<String, CallbackTimingCounters>,
    #[serde(default)]
    dsq_operations: Vec<FineTimingDsqOperationPayload>,
    #[serde(default)]
    dsq_transfers: Vec<FineTimingDsqTransferPayload>,
}

#[derive(Deserialize)]
struct FineTimingDsqOperationPayload {
    dsq_id: u64,
    operation: String,
    outcome: String,
    timing: CallbackTimingCounters,
}

#[derive(Deserialize)]
struct FineTimingDsqTransferPayload {
    source_dsq_id: u64,
    target_dsq_id: u64,
    samples: u64,
}

fn validate_fine_timing(payload: FineTimingPayload) -> Result<FineTimingPayload, String> {
    let mut callbacks = BTreeSet::new();
    for capture in &payload.captures {
        if !FINE_TIMING_CALLBACKS.contains(&capture.callback.as_str()) {
            return Err(format!(
                "fine timing data contains unknown callback `{}`",
                capture.callback
            ));
        }
        if !callbacks.insert(capture.callback.as_str()) {
            return Err(format!(
                "fine timing data contains duplicate callback `{}`",
                capture.callback
            ));
        }
    }
    if !REQUIRED_FINE_TIMING_CALLBACKS
        .iter()
        .all(|callback| callbacks.contains(callback))
    {
        return Err("fine timing data must contain select_cpu, enqueue, and dispatch".into());
    }
    if payload.captures.iter().any(|capture| {
        capture
            .stages
            .values()
            .any(|stage| stage.buckets.len() != FINE_TIMING_BUCKETS)
    }) {
        return Err(format!(
            "fine timing histograms must contain {FINE_TIMING_BUCKETS} buckets"
        ));
    }
    for operation in payload
        .captures
        .iter()
        .flat_map(|capture| &capture.dsq_operations)
    {
        if !matches!(operation.operation.as_str(), "insert" | "remove") {
            return Err(format!("invalid DSQ operation `{}`", operation.operation));
        }
        if !matches!(operation.outcome.as_str(), "success" | "miss" | "error") {
            return Err(format!("invalid DSQ outcome `{}`", operation.outcome));
        }
        if operation.timing.buckets.len() != FINE_TIMING_BUCKETS {
            return Err(format!(
                "DSQ operation histograms must contain {FINE_TIMING_BUCKETS} buckets"
            ));
        }
    }
    Ok(payload)
}

fn empty_fine_timing_view(
    live: &LiveData,
    status: FineTimingStatus,
    error: Option<String>,
) -> FineTimingView {
    FineTimingView {
        sequence: live.inspection_sequence,
        context: runtime_context(live),
        status,
        error,
        sample_rate: 0,
        captures: Vec::new(),
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
        context: runtime_context(live),
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
