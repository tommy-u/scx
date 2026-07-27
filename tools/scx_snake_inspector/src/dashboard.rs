// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use serde::Serialize;
use tokio::sync::watch;

use crate::model::{CpuPair, CpuUsageHistory, RollingHistory, WindowError};
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
        let mut live = self.live.write().expect("dashboard lock poisoned");
        live.inspection = snapshot;
        live.inspection_error = error;
        live.inspection_sequence = live.inspection_sequence.wrapping_add(1);
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
