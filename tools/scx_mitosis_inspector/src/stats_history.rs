// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::{BTreeMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::lifecycle::{CollectorStatus, ObserverContext, SampleMeta};
use crate::stats::StatsSnapshot;

pub const STATS_HISTORY_RETENTION_MS: u64 = 30 * 60 * 1_000;
pub const STATS_HISTORY_MAX_SAMPLES: usize = 1_801;

#[derive(Clone, Debug, Default, Deserialize)]
pub struct StatsHistoryQuery {
    pub instance_id: Option<String>,
    pub epoch: Option<u64>,
    pub after_seq: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct StatsHistorySample {
    pub meta: SampleMeta,
    pub cells: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct StatsHistoryView {
    pub meta: SampleMeta,
    pub collector: ObserverContext,
    pub instance_id: String,
    pub retention_ms: u64,
    pub reset: bool,
    pub samples: Vec<StatsHistorySample>,
}

#[derive(Debug)]
pub struct StatsHistory {
    instance_id: String,
    meta: SampleMeta,
    samples: VecDeque<StatsHistorySample>,
    last_recorded_seq: u64,
    evicted_through_seq: Option<u64>,
}

impl Default for StatsHistory {
    fn default() -> Self {
        Self::new()
    }
}

impl StatsHistory {
    pub fn new() -> Self {
        let started_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        Self {
            instance_id: format!("{}-{started_at}", std::process::id()),
            meta: StatsSnapshot::default().meta,
            samples: VecDeque::new(),
            last_recorded_seq: 0,
            evicted_through_seq: None,
        }
    }

    pub fn record(&mut self, snapshot: &StatsSnapshot, now_ms: u64) {
        // An API read may already have observed a new epoch before this source
        // publishes. Never let a delayed source result roll the history back.
        if snapshot.meta.epoch < self.meta.epoch
            || (snapshot.meta.epoch == self.meta.epoch
                && snapshot.meta.sample_seq < self.meta.sample_seq)
        {
            self.expire(now_ms);
            return;
        }
        if self.meta.epoch != snapshot.meta.epoch {
            self.clear_epoch(&snapshot.collector);
        }
        self.meta = snapshot.meta.clone();
        if snapshot.collector.status == CollectorStatus::Active
            && snapshot.error.is_none()
            && snapshot.meta.error.is_none()
            && snapshot.meta.sample_seq > self.last_recorded_seq
        {
            if let (Some(_), Some(metrics)) =
                (snapshot.meta.captured_at_unix_ms, snapshot.metrics.as_ref())
            {
                let cells = metrics
                    .get("cells")
                    .and_then(Value::as_object)
                    .into_iter()
                    .flat_map(|cells| cells.iter())
                    .map(|(id, cell)| {
                        let cell = if let Some(fields) = cell.as_object() {
                            ["num_cpus", "util_pct", "smoothed_util_pct"]
                                .into_iter()
                                .filter_map(|key| {
                                    fields.get(key).map(|value| (key.to_owned(), value.clone()))
                                })
                                .collect::<serde_json::Map<_, _>>()
                                .into()
                        } else {
                            cell.clone()
                        };
                        (id.clone(), cell)
                    })
                    .collect();
                self.samples.push_back(StatsHistorySample {
                    meta: snapshot.meta.clone(),
                    cells,
                });
                self.last_recorded_seq = snapshot.meta.sample_seq;
            }
        }
        self.expire(now_ms);
        while self.samples.len() > STATS_HISTORY_MAX_SAMPLES {
            self.evict_oldest();
        }
    }

    pub fn view(
        &mut self,
        current: &ObserverContext,
        query: &StatsHistoryQuery,
        now_ms: u64,
    ) -> Result<StatsHistoryView, String> {
        let cursor = match (&query.instance_id, query.epoch, query.after_seq) {
            (None, None, None) => None,
            (Some(instance_id), Some(epoch), Some(after_seq)) if !instance_id.is_empty() => {
                Some((instance_id.as_str(), epoch, after_seq))
            }
            _ => return Err("instance_id, epoch and after_seq must be supplied together".into()),
        };
        if current.epoch != self.meta.epoch {
            self.clear_epoch(current);
        }
        self.expire(now_ms);
        let reset = cursor.is_none_or(|(instance_id, epoch, after_seq)| {
            instance_id != self.instance_id
                || epoch != self.meta.epoch
                || after_seq > self.meta.sample_seq
                || self
                    .evicted_through_seq
                    .is_some_and(|evicted| after_seq <= evicted)
        });
        let after_seq = if reset { None } else { query.after_seq };
        Ok(StatsHistoryView {
            meta: self.meta.clone(),
            collector: current.clone(),
            instance_id: self.instance_id.clone(),
            retention_ms: STATS_HISTORY_RETENTION_MS,
            reset,
            samples: self
                .samples
                .iter()
                .filter(|sample| after_seq.is_none_or(|seq| sample.meta.sample_seq > seq))
                .cloned()
                .collect(),
        })
    }

    fn clear_epoch(&mut self, current: &ObserverContext) {
        self.meta = SampleMeta {
            epoch: current.epoch,
            error: current
                .error
                .clone()
                .or_else(|| Some("waiting for Mitosis stats".into())),
            ..Default::default()
        };
        self.samples.clear();
        self.last_recorded_seq = 0;
        self.evicted_through_seq = None;
    }

    fn expire(&mut self, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(STATS_HISTORY_RETENTION_MS);
        while self.samples.front().is_some_and(|sample| {
            sample
                .meta
                .captured_at_unix_ms
                .is_some_and(|at_ms| at_ms < cutoff)
        }) {
            self.evict_oldest();
        }
    }

    fn evict_oldest(&mut self) {
        if let Some(sample) = self.samples.pop_front() {
            self.evicted_through_seq = Some(sample.meta.sample_seq);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lifecycle::CollectorStatus;
    use serde_json::json;

    fn active(epoch: u64) -> ObserverContext {
        ObserverContext {
            epoch,
            status: CollectorStatus::Active,
            scheduler_enable_seq: Some(epoch),
            scheduler_name: Some("mitosis".into()),
            error: None,
        }
    }

    fn sample(epoch: u64, seq: u64, at_ms: u64) -> StatsSnapshot {
        StatsSnapshot {
            meta: SampleMeta {
                epoch,
                sample_seq: seq,
                captured_at_unix_ms: Some(at_ms),
                last_success_at_unix_ms: Some(at_ms),
                error: None,
            },
            collector: active(epoch),
            metrics: Some(json!({
                "rebalance_count": seq,
                "cells": {
                    "0": {
                        "num_cpus": 6,
                        "util_pct": 25.5,
                        "smoothed_util_pct": null,
                        "borrowed_pct": 4.5
                    },
                    "7": {"num_cpus": 10},
                    "9": null
                }
            })),
            error: None,
            cpu_cells: None,
            cpu_cells_error: Some("ownership unavailable".into()),
        }
    }

    fn cursor(view: &StatsHistoryView, after_seq: u64) -> StatsHistoryQuery {
        StatsHistoryQuery {
            instance_id: Some(view.instance_id.clone()),
            epoch: Some(view.meta.epoch),
            after_seq: Some(after_seq),
        }
    }

    fn sequences(view: &StatsHistoryView) -> Vec<u64> {
        view.samples
            .iter()
            .map(|sample| sample.meta.sample_seq)
            .collect()
    }

    #[test]
    fn backfill_preserves_each_collection_time_and_only_original_cell_history_fields() {
        let mut history = StatsHistory::new();
        for seq in 1..=3 {
            history.record(&sample(3, seq, seq * 1_000), seq * 1_000);
        }
        let view = history
            .view(&active(3), &StatsHistoryQuery::default(), 3_000)
            .unwrap();
        assert_eq!(sequences(&view), [1, 2, 3]);
        assert_eq!(view.meta.sample_seq, 3);
        assert!(view.reset);
        for (index, sample) in view.samples.iter().enumerate() {
            assert_eq!(sample.meta.epoch, 3);
            assert_eq!(
                sample.meta.captured_at_unix_ms,
                Some((index as u64 + 1) * 1_000)
            );
            assert_eq!(
                sample.cells["0"],
                json!({
                    "num_cpus": 6,
                    "util_pct": 25.5,
                    "smoothed_util_pct": null
                })
            );
            assert_eq!(sample.cells["7"], json!({"num_cpus": 10}));
            assert_eq!(sample.cells["9"], Value::Null);
        }
    }

    #[test]
    fn an_incremental_cursor_backfills_all_missed_samples_without_repeating_the_cursor() {
        let mut history = StatsHistory::new();
        for seq in 1..=3 {
            history.record(&sample(3, seq, seq * 1_000), seq * 1_000);
        }
        let full = history
            .view(&active(3), &StatsHistoryQuery::default(), 3_000)
            .unwrap();
        let incremental = history.view(&active(3), &cursor(&full, 1), 3_000).unwrap();
        assert!(!incremental.reset);
        assert_eq!(sequences(&incremental), [2, 3]);
        let caught_up = history.view(&active(3), &cursor(&full, 3), 3_000).unwrap();
        assert!(!caught_up.reset);
        assert!(caught_up.samples.is_empty());
    }

    #[test]
    fn instance_epoch_and_future_sequence_mismatches_reset_to_full_retained_history() {
        let mut history = StatsHistory::new();
        history.record(&sample(3, 1, 1_000), 1_000);
        let full = history
            .view(&active(3), &StatsHistoryQuery::default(), 1_000)
            .unwrap();
        let mut other_instance = cursor(&full, 1);
        other_instance.instance_id = Some("previous-inspector".into());
        let mut other_epoch = cursor(&full, 1);
        other_epoch.epoch = Some(2);
        for query in [other_instance, other_epoch, cursor(&full, 2)] {
            let view = history.view(&active(3), &query, 1_000).unwrap();
            assert!(view.reset);
            assert_eq!(sequences(&view), [1]);
        }
    }

    #[test]
    fn failed_reads_keep_history_and_report_the_latest_error_without_new_samples() {
        let mut history = StatsHistory::new();
        let mut snapshot = sample(3, 1, 1_000);
        history.record(&snapshot, 1_000);
        snapshot.error = Some("socket closed".into());
        snapshot.meta.error = snapshot.error.clone();
        history.record(&snapshot, 2_000);
        let view = history
            .view(&active(3), &StatsHistoryQuery::default(), 2_000)
            .unwrap();
        assert_eq!(sequences(&view), [1]);
        assert_eq!(view.meta.sample_seq, 1);
        assert_eq!(view.meta.error.as_deref(), Some("socket closed"));
        assert_eq!(view.meta.captured_at_unix_ms, Some(1_000));
        assert_eq!(view.samples[0].meta.error, None);
        assert_eq!(view.samples[0].meta.captured_at_unix_ms, Some(1_000));
    }

    #[test]
    fn retention_expires_by_wall_time_on_reads_even_when_collection_stops() {
        let mut history = StatsHistory::new();
        history.record(&sample(3, 1, 1_000), 1_000);
        let full = history
            .view(&active(3), &StatsHistoryQuery::default(), 1_000)
            .unwrap();
        let view = history
            .view(
                &active(3),
                &cursor(&full, 1),
                1_001 + STATS_HISTORY_RETENTION_MS,
            )
            .unwrap();
        assert!(view.reset);
        assert!(view.samples.is_empty());
        assert_eq!(view.meta.last_success_at_unix_ms, Some(1_000));
    }

    #[test]
    fn failure_publications_expire_samples_and_an_expired_cursor_requests_a_full_reset() {
        let mut history = StatsHistory::new();
        history.record(&sample(3, 1, 1_000), 1_000);
        let latest = sample(3, 2, 1_000 + STATS_HISTORY_RETENTION_MS);
        history.record(&latest, 1_000 + STATS_HISTORY_RETENTION_MS);
        let full = history
            .view(
                &active(3),
                &StatsHistoryQuery::default(),
                1_000 + STATS_HISTORY_RETENTION_MS,
            )
            .unwrap();
        assert_eq!(sequences(&full), [1, 2]);
        let mut failure = latest;
        failure.error = Some("stats unavailable".into());
        failure.meta.error = failure.error.clone();
        history.record(&failure, 1_001 + STATS_HISTORY_RETENTION_MS);
        let view = history
            .view(
                &active(3),
                &cursor(&full, 1),
                1_001 + STATS_HISTORY_RETENTION_MS,
            )
            .unwrap();
        assert!(view.reset);
        assert_eq!(sequences(&view), [2]);
        assert_eq!(view.meta.error.as_deref(), Some("stats unavailable"));
    }

    #[test]
    fn a_record_limit_keeps_memory_bounded_and_resets_an_evicted_cursor() {
        let mut history = StatsHistory::new();
        for seq in 1..=(STATS_HISTORY_MAX_SAMPLES as u64 + 5) {
            history.record(&sample(3, seq, 1_000 + seq), 1_000 + seq);
        }
        let full = history
            .view(&active(3), &StatsHistoryQuery::default(), 3_000)
            .unwrap();
        assert_eq!(full.samples.len(), STATS_HISTORY_MAX_SAMPLES);
        assert_eq!(full.samples.first().unwrap().meta.sample_seq, 6);
        let old_cursor = history.view(&active(3), &cursor(&full, 5), 3_000).unwrap();
        assert!(old_cursor.reset);
        assert_eq!(old_cursor.samples, full.samples);
    }

    #[test]
    fn observer_epoch_changes_clear_history_before_the_next_stats_publication() {
        let mut history = StatsHistory::new();
        history.record(&sample(3, 1, 1_000), 1_000);
        let old = history
            .view(&active(3), &StatsHistoryQuery::default(), 1_000)
            .unwrap();
        let view = history.view(&active(4), &cursor(&old, 1), 2_000).unwrap();
        assert_eq!(view.meta.epoch, 4);
        assert_eq!(view.meta.sample_seq, 0);
        assert!(view.reset);
        assert!(view.samples.is_empty());
        assert_eq!(view.meta.captured_at_unix_ms, None);
        history.record(&sample(3, 2, 2_000), 2_000);
        history.record(&sample(4, 1, 3_000), 3_000);
        let view = history
            .view(&active(4), &StatsHistoryQuery::default(), 3_000)
            .unwrap();
        assert_eq!(sequences(&view), [1]);
        assert_eq!(view.samples[0].meta.epoch, 4);
    }

    #[test]
    fn partial_cursors_and_empty_instance_ids_are_rejected() {
        let mut history = StatsHistory::new();
        for query in [
            StatsHistoryQuery {
                after_seq: Some(1),
                ..Default::default()
            },
            StatsHistoryQuery {
                instance_id: Some("instance".into()),
                epoch: Some(3),
                after_seq: None,
            },
            StatsHistoryQuery {
                instance_id: Some(String::new()),
                epoch: Some(3),
                after_seq: Some(1),
            },
        ] {
            assert!(history.view(&active(3), &query, 1_000).is_err());
        }
    }
}
