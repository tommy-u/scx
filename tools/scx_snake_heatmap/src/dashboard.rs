// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use serde::Serialize;
use tokio::sync::watch;

use crate::model::{CpuPair, RollingHistory, WindowError};
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
    pub cells: Vec<CellView>,
}

struct LiveData {
    history: RollingHistory,
    now_ms: u64,
    sequence: u64,
    scheduler: SchedulerView,
    scope: TaskScope,
    collector_error: Option<String>,
    pair_map_failures: u64,
    task_storage_failures: u64,
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
                now_ms: 0,
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
            live.now_ms = at_ms;
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

    pub fn snapshot(&self, window_ms: u64) -> Result<SnapshotView, WindowError> {
        let live = self.live.read().expect("dashboard lock poisoned");
        let view = live.history.view(live.now_ms, window_ms)?;
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
            cells,
        })
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.updates.subscribe()
    }
}
