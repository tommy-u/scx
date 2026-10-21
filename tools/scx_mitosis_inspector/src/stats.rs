// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use scx_stats::StatsClient;
use serde::Serialize;
use serde_json::Value;

use crate::collector::Snapshot;
use crate::cpu_allocation::CpuAllocationReader;
use crate::lifecycle::{
    read_scheduler_identity, unix_ms, CollectorStatus, ObserverContext, SampleMeta,
    SharedObserverContext,
};
use crate::stats_history::StatsHistory;

pub const DEFAULT_STATS_PATH: &str = "/var/run/scx/root/stats";
const STATS_TIMEOUT_MS: u64 = 1_000;

#[derive(Clone, Debug, Serialize)]
pub struct StatsSnapshot {
    pub meta: SampleMeta,
    pub collector: ObserverContext,
    pub metrics: Option<Value>,
    pub error: Option<String>,
    pub cpu_cells: Option<BTreeMap<u32, u32>>,
    pub cpu_cells_error: Option<String>,
}

impl Default for StatsSnapshot {
    fn default() -> Self {
        Self {
            meta: SampleMeta {
                error: Some("waiting for Mitosis stats".into()),
                ..Default::default()
            },
            collector: ObserverContext::default(),
            metrics: None,
            error: Some("waiting for Mitosis stats".into()),
            cpu_cells: None,
            cpu_cells_error: Some("waiting for Mitosis CPU ownership".into()),
        }
    }
}

impl StatsSnapshot {
    fn apply_result(&mut self, context: &ObserverContext, at_ms: u64, result: Result<Value>) {
        if self.meta.epoch != context.epoch {
            *self = Self::default();
            self.meta.epoch = context.epoch;
        }
        self.collector = context.clone();
        match result {
            Ok(metrics) => {
                self.meta.sample_seq += 1;
                self.meta.captured_at_unix_ms = Some(at_ms);
                self.meta.last_success_at_unix_ms = Some(at_ms);
                self.meta.error = None;
                self.metrics = Some(metrics);
                self.error = None;
            }
            Err(error) => {
                let error = format!("{error:#}");
                self.meta.error = Some(error.clone());
                self.error = Some(error);
            }
        }
    }
}

fn publish_result(
    state: &Arc<RwLock<StatsSnapshot>>,
    history: &Arc<RwLock<StatsHistory>>,
    observer: &SharedObserverContext,
    expected: &ObserverContext,
    at_ms: u64,
    result: Result<Value>,
    cpu_cells: Result<BTreeMap<u32, u32>>,
) -> bool {
    // Take the source lock first, matching the collector publication lock order.
    let mut snapshot = state.write().expect("stats snapshot lock poisoned");
    let current = observer.read().expect("observer context lock poisoned");
    if *current != *expected || (result.is_ok() && current.status != CollectorStatus::Active) {
        return false;
    }
    snapshot.apply_result(expected, at_ms, result);
    match cpu_cells {
        Ok(owners) => {
            snapshot.cpu_cells = Some(owners);
            snapshot.cpu_cells_error = None;
        }
        Err(error) => {
            snapshot.cpu_cells = None;
            snapshot.cpu_cells_error = Some(format!("{error:#}"));
        }
    }
    // Hold the observer guard until both latest state and history are published.
    // History API readers use the same observer -> history lock order.
    history
        .write()
        .expect("stats history lock poisoned")
        .record(&snapshot, at_ms);
    true
}

fn scheduler_matches(context: &ObserverContext) -> Result<bool> {
    Ok(read_scheduler_identity()?.is_some_and(|identity| {
        Some(identity.enable_seq) == context.scheduler_enable_seq
            && Some(identity.name.as_str()) == context.scheduler_name.as_deref()
    }))
}

pub fn run(
    state: Arc<RwLock<StatsSnapshot>>,
    history: Arc<RwLock<StatsHistory>>,
    observer: SharedObserverContext,
    shutdown: Arc<AtomicBool>,
    stats_path: &Path,
    counters: Arc<RwLock<Snapshot>>,
    cpu_ids: &[u32],
) {
    let mut client = None;
    let mut cpu_reader = None;
    let mut client_epoch = None;
    while !shutdown.load(Ordering::Relaxed) {
        let expected = observer
            .read()
            .expect("observer context lock poisoned")
            .clone();
        if client_epoch != Some(expected.epoch) {
            client = None;
            cpu_reader = None;
            client_epoch = Some(expected.epoch);
        }
        let mut cpu_cells = Err(anyhow::anyhow!("Mitosis CPU ownership is unavailable"));
        let result = if expected.status != CollectorStatus::Active {
            client = None;
            Err(anyhow::anyhow!(expected.error.clone().unwrap_or_else(
                || format!("Mitosis observer is {:?}", expected.status)
            )))
        } else {
            (|| {
                anyhow::ensure!(
                    scheduler_matches(&expected)?,
                    "Mitosis scheduler identity changed"
                );
                let metrics = read_stats(&mut client, stats_path)?;
                cpu_cells = (|| {
                    if cpu_reader.is_none() {
                        let program_id = {
                            let counters = counters.read().expect("counter snapshot lock poisoned");
                            anyhow::ensure!(
                                counters.collector == expected,
                                "waiting for current Mitosis callback"
                            );
                            counters.target_program_ids[3]
                        };
                        cpu_reader = Some(CpuAllocationReader::open(program_id)?);
                    }
                    cpu_reader.as_ref().unwrap().read(cpu_ids)
                })();
                if cpu_cells.is_err() {
                    cpu_reader = None;
                }
                anyhow::ensure!(
                    scheduler_matches(&expected)?,
                    "Mitosis scheduler identity changed during stats read"
                );
                Ok(metrics)
            })()
        };
        if result.is_err() {
            client = None;
            cpu_cells = Err(anyhow::anyhow!("Mitosis stats are unavailable"));
        }
        publish_result(
            &state,
            &history,
            &observer,
            &expected,
            unix_ms(),
            result,
            cpu_cells,
        );
        thread::sleep(Duration::from_secs(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn active(epoch: u64) -> ObserverContext {
        ObserverContext {
            epoch,
            status: CollectorStatus::Active,
            scheduler_enable_seq: Some(7),
            scheduler_name: Some("mitosis".into()),
            error: None,
        }
    }

    #[test]
    fn successful_stats_are_identified_by_collection_time_and_sequence() {
        let mut snapshot = StatsSnapshot::default();
        snapshot.apply_result(&active(3), 100, Ok(json!({"util_pct": 40})));
        assert_eq!(snapshot.meta.epoch, 3);
        assert_eq!(snapshot.meta.sample_seq, 1);
        assert_eq!(snapshot.meta.captured_at_unix_ms, Some(100));
        assert_eq!(snapshot.meta.last_success_at_unix_ms, Some(100));
        assert_eq!(snapshot.metrics, Some(json!({"util_pct": 40})));
        assert_eq!(snapshot.error, None);
    }

    #[test]
    fn failed_reads_preserve_cached_values_without_creating_a_sample() {
        let mut snapshot = StatsSnapshot::default();
        snapshot.apply_result(&active(3), 100, Ok(json!({"util_pct": 40})));
        snapshot.apply_result(&active(3), 200, Err(anyhow::anyhow!("socket closed")));
        assert_eq!(snapshot.metrics, Some(json!({"util_pct": 40})));
        assert_eq!(snapshot.meta.sample_seq, 1);
        assert_eq!(snapshot.meta.last_success_at_unix_ms, Some(100));
        assert_eq!(snapshot.meta.captured_at_unix_ms, Some(100));
        assert_eq!(snapshot.meta.error.as_deref(), Some("socket closed"));
    }

    #[test]
    fn a_late_socket_response_cannot_publish_into_a_new_epoch() {
        let state = Arc::new(RwLock::new(StatsSnapshot::default()));
        let history = Arc::new(RwLock::new(StatsHistory::new()));
        let expected = active(3);
        let observer = Arc::new(RwLock::new(active(4)));
        assert!(!publish_result(
            &state,
            &history,
            &observer,
            &expected,
            200,
            Ok(json!({"old": true})),
            Ok(BTreeMap::from([(0, 9)]))
        ));
        assert!(state.read().unwrap().metrics.is_none());
        assert!(history
            .write()
            .unwrap()
            .view(&active(4), &Default::default(), 200)
            .unwrap()
            .samples
            .is_empty());
        assert!(publish_result(
            &state,
            &history,
            &observer,
            &active(4),
            300,
            Ok(json!({"new": true})),
            Ok(BTreeMap::from([(0, 2)]))
        ));
        assert_eq!(state.read().unwrap().metrics, Some(json!({"new": true})));
        assert_eq!(
            state.read().unwrap().cpu_cells,
            Some(BTreeMap::from([(0, 2)]))
        );
        let history = history
            .write()
            .unwrap()
            .view(&active(4), &Default::default(), 300)
            .unwrap();
        assert_eq!(history.samples.len(), 1);
        assert_eq!(history.samples[0].meta.epoch, 4);
        assert_eq!(history.samples[0].meta.sample_seq, 1);
    }

    #[test]
    fn accepted_stats_publications_fill_history_with_each_collection_timestamp() {
        let state = Arc::new(RwLock::new(StatsSnapshot::default()));
        let history = Arc::new(RwLock::new(StatsHistory::new()));
        let observer = Arc::new(RwLock::new(active(3)));
        for at_ms in [100, 200, 300] {
            assert!(publish_result(
                &state,
                &history,
                &observer,
                &active(3),
                at_ms,
                Ok(json!({"cells": {"0": {"num_cpus": at_ms / 10, "util_pct": 25.0}}})),
                Ok(BTreeMap::new()),
            ));
        }
        let view = history
            .write()
            .unwrap()
            .view(&active(3), &Default::default(), 300)
            .unwrap();
        assert_eq!(view.samples.len(), 3);
        assert_eq!(view.meta, state.read().unwrap().meta);
        for (index, sample) in view.samples.iter().enumerate() {
            assert_eq!(sample.meta.sample_seq, index as u64 + 1);
            assert_eq!(
                sample.meta.captured_at_unix_ms,
                Some((index as u64 + 1) * 100)
            );
            assert_eq!(sample.cells["0"]["num_cpus"], (index as u64 + 1) * 10);
        }
    }

    #[test]
    fn failed_stats_publications_update_history_error_without_a_cached_sample() {
        let state = Arc::new(RwLock::new(StatsSnapshot::default()));
        let history = Arc::new(RwLock::new(StatsHistory::new()));
        let observer = Arc::new(RwLock::new(active(3)));
        assert!(publish_result(
            &state,
            &history,
            &observer,
            &active(3),
            100,
            Ok(json!({"cells": {"0": {"num_cpus": 6}}})),
            Ok(BTreeMap::new()),
        ));
        assert!(publish_result(
            &state,
            &history,
            &observer,
            &active(3),
            200,
            Err(anyhow::anyhow!("socket closed")),
            Err(anyhow::anyhow!("stats unavailable")),
        ));
        let view = history
            .write()
            .unwrap()
            .view(&active(3), &Default::default(), 200)
            .unwrap();
        assert_eq!(view.samples.len(), 1);
        assert_eq!(view.meta, state.read().unwrap().meta);
        assert_eq!(view.meta.error.as_deref(), Some("socket closed"));
        assert_eq!(view.samples[0].meta.error, None);
        assert_eq!(view.samples[0].meta.captured_at_unix_ms, Some(100));
    }

    #[test]
    fn ownership_failures_do_not_hide_stats_or_keep_old_cpu_colors() {
        let state = Arc::new(RwLock::new(StatsSnapshot::default()));
        let history = Arc::new(RwLock::new(StatsHistory::new()));
        let observer = Arc::new(RwLock::new(active(3)));
        assert!(publish_result(
            &state,
            &history,
            &observer,
            &active(3),
            100,
            Ok(json!({"util_pct": 20})),
            Ok(BTreeMap::from([(0, 1)]))
        ));
        assert!(publish_result(
            &state,
            &history,
            &observer,
            &active(3),
            200,
            Ok(json!({"util_pct": 30})),
            Err(anyhow::anyhow!("map unavailable"))
        ));
        let snapshot = state.read().unwrap();
        assert_eq!(snapshot.metrics, Some(json!({"util_pct": 30})));
        assert_eq!(snapshot.error, None);
        assert_eq!(snapshot.cpu_cells, None);
        assert_eq!(snapshot.cpu_cells_error.as_deref(), Some("map unavailable"));
    }
}

fn read_stats(client: &mut Option<StatsClient>, stats_path: &Path) -> Result<Value> {
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
        .context("Mitosis stats client is unavailable")?
        .request("stats", vec![("target".into(), "top".into())])
        .context("reading Mitosis top stats")
}
