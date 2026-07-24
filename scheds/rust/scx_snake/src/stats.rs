// SPDX-License-Identifier: GPL-2.0-only

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use scx_stats::prelude::*;
use scx_stats_derive::{stat_doc, Stats};
use serde::{Deserialize, Serialize};

#[stat_doc]
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize, Stats)]
#[stat(_om_prefix = "rung_", _om_label = "rung_index")]
pub struct RungMetrics {
    #[stat(desc = "Zero-based position in the policy ladder", _om_skip)]
    pub index: u32,
    #[stat(desc = "Userspace operation label", _om_skip)]
    pub operation: String,
    #[stat(desc = "Userspace scope label", _om_skip)]
    pub scope: String,
    #[stat(desc = "Number of times BPF evaluated this rung")]
    pub attempts: u64,
    #[stat(desc = "Number of times this rung supplied an idle CPU hint")]
    pub hits: u64,
    #[stat(desc = "Number of times this rung advanced to the next rung")]
    pub misses: u64,
    #[stat(desc = "Number of invalid or failed rung evaluations")]
    pub errors: u64,
}

impl RungMetrics {
    fn delta(&self, previous: Option<&Self>) -> Self {
        let previous = previous.cloned().unwrap_or_default();
        Self {
            index: self.index,
            operation: self.operation.clone(),
            scope: self.scope.clone(),
            attempts: self.attempts.saturating_sub(previous.attempts),
            hits: self.hits.saturating_sub(previous.hits),
            misses: self.misses.saturating_sub(previous.misses),
            errors: self.errors.saturating_sub(previous.errors),
        }
    }
}

#[stat_doc]
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct Metrics {
    #[stat(desc = "Number of select_cpu callback invocations")]
    pub select_calls: u64,
    #[stat(desc = "Number of idle CPU hints returned by the policy ladder")]
    pub idle_hints: u64,
    #[stat(desc = "Number of times all policy rungs missed")]
    pub ladder_exhaustions: u64,
    #[stat(desc = "Number of exhaustion fallbacks that kept the previous CPU")]
    pub fallback_prev: u64,
    #[stat(desc = "Number of exhaustion fallbacks that selected any affinity-safe CPU")]
    pub fallback_any: u64,
    #[stat(desc = "Number of invalid instructions and policy evaluation errors")]
    pub invalid_errors: u64,
    #[stat(desc = "Number of enqueue callback invocations")]
    pub enqueues: u64,
    #[stat(desc = "Number of running callback invocations")]
    pub running: u64,
    #[stat(desc = "Number of stopping callback invocations")]
    pub stopping: u64,
    #[stat(desc = "Number of quiescent callback invocations")]
    pub quiescent: u64,
    #[stat(desc = "Total nanoseconds spent in select_cpu")]
    pub select_latency_ns: u64,
    #[stat(desc = "Maximum select_cpu latency in nanoseconds since scheduler start")]
    pub select_latency_max_ns: u64,
    #[stat(desc = "Per-rung policy evaluation metrics")]
    pub rungs: BTreeMap<u32, RungMetrics>,
}

impl Metrics {
    pub fn delta(&self, previous: &Self) -> Self {
        Self {
            select_calls: self.select_calls.saturating_sub(previous.select_calls),
            idle_hints: self.idle_hints.saturating_sub(previous.idle_hints),
            ladder_exhaustions: self
                .ladder_exhaustions
                .saturating_sub(previous.ladder_exhaustions),
            fallback_prev: self.fallback_prev.saturating_sub(previous.fallback_prev),
            fallback_any: self.fallback_any.saturating_sub(previous.fallback_any),
            invalid_errors: self.invalid_errors.saturating_sub(previous.invalid_errors),
            enqueues: self.enqueues.saturating_sub(previous.enqueues),
            running: self.running.saturating_sub(previous.running),
            stopping: self.stopping.saturating_sub(previous.stopping),
            quiescent: self.quiescent.saturating_sub(previous.quiescent),
            select_latency_ns: self
                .select_latency_ns
                .saturating_sub(previous.select_latency_ns),
            select_latency_max_ns: self.select_latency_max_ns,
            rungs: self
                .rungs
                .iter()
                .map(|(index, rung)| (*index, rung.delta(previous.rungs.get(index))))
                .collect(),
        }
    }

    pub fn format_text(&self) -> String {
        let average_latency_ns = self
            .select_latency_ns
            .checked_div(self.select_calls)
            .unwrap_or_default();
        let mut output = format!(
            concat!(
                "scx_snake policy stats\n",
                "  select calls: {} | idle hints: {} | ladder exhausted: {}\n",
                "  fallback previous CPU: {} | fallback any allowed CPU: {} | invalid/errors: {}\n",
                "  callbacks enqueue: {} | running: {} | stopping: {} | quiescent: {}\n",
                "  select latency ns total: {} | average: {} | cumulative max: {}\n",
                "  rungs:\n"
            ),
            self.select_calls,
            self.idle_hints,
            self.ladder_exhaustions,
            self.fallback_prev,
            self.fallback_any,
            self.invalid_errors,
            self.enqueues,
            self.running,
            self.stopping,
            self.quiescent,
            self.select_latency_ns,
            average_latency_ns,
            self.select_latency_max_ns,
        );

        for rung in self.rungs.values() {
            output.push_str(&format!(
                "    rung {} {}({}): attempts {} | hits {} | misses {} | errors {}\n",
                rung.index,
                rung.operation,
                rung.scope,
                rung.attempts,
                rung.hits,
                rung.misses,
                rung.errors,
            ));
        }
        output
    }

    pub fn write_text<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(self.format_text().as_bytes())?;
        Ok(())
    }

    pub fn to_ndjson(&self) -> serde_json::Result<String> {
        serde_json::to_string(self).map(|mut encoded| {
            encoded.push('\n');
            encoded
        })
    }
}

pub fn server_data() -> StatsServerData<(), Metrics> {
    let open: Box<dyn StatsOpener<(), Metrics>> = Box::new(move |(req_ch, res_ch)| {
        req_ch.send(())?;
        let mut previous = res_ch.recv()?;

        let read: Box<dyn StatsReader<(), Metrics>> = Box::new(move |_args, (req_ch, res_ch)| {
            req_ch.send(())?;
            let current = res_ch.recv()?;
            let delta = current.delta(&previous);
            previous = current;
            delta.to_json()
        });

        Ok(read)
    });

    StatsServerData::new()
        .add_meta(Metrics::meta())
        .add_meta(RungMetrics::meta())
        .add_ops("top", StatsOps { open, close: None })
}

pub fn monitor(interval: Duration, shutdown: Arc<AtomicBool>) -> Result<()> {
    scx_utils::monitor_stats::<Metrics>(
        &[],
        interval,
        || shutdown.load(Ordering::Relaxed),
        |metrics| metrics.write_text(&mut std::io::stdout()),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn rung(
        index: u32,
        operation: &str,
        scope: &str,
        attempts: u64,
        hits: u64,
        misses: u64,
        errors: u64,
    ) -> RungMetrics {
        RungMetrics {
            index,
            operation: operation.into(),
            scope: scope.into(),
            attempts,
            hits,
            misses,
            errors,
        }
    }

    #[test]
    fn delta_saturates_counters_after_a_reset() {
        let previous = Metrics {
            select_calls: 20,
            idle_hints: 18,
            ladder_exhaustions: 7,
            fallback_prev: 6,
            fallback_any: 5,
            invalid_errors: 4,
            enqueues: 30,
            running: 29,
            stopping: 28,
            quiescent: 3,
            select_latency_ns: 2_000,
            ..Default::default()
        };
        let current = Metrics {
            select_calls: 2,
            idle_hints: 1,
            ladder_exhaustions: 0,
            fallback_prev: 0,
            fallback_any: 0,
            invalid_errors: 0,
            enqueues: 3,
            running: 2,
            stopping: 1,
            quiescent: 0,
            select_latency_ns: 100,
            ..Default::default()
        };

        let delta = current.delta(&previous);

        assert_eq!(delta.select_calls, 0);
        assert_eq!(delta.idle_hints, 0);
        assert_eq!(delta.ladder_exhaustions, 0);
        assert_eq!(delta.fallback_prev, 0);
        assert_eq!(delta.fallback_any, 0);
        assert_eq!(delta.invalid_errors, 0);
        assert_eq!(delta.enqueues, 0);
        assert_eq!(delta.running, 0);
        assert_eq!(delta.stopping, 0);
        assert_eq!(delta.quiescent, 0);
        assert_eq!(delta.select_latency_ns, 0);
    }

    #[test]
    fn delta_keeps_cumulative_max_as_a_gauge() {
        let previous = Metrics {
            select_latency_max_ns: 900,
            ..Default::default()
        };
        let current = Metrics {
            select_latency_max_ns: 750,
            ..Default::default()
        };

        assert_eq!(current.delta(&previous).select_latency_max_ns, 750);
    }

    #[test]
    fn delta_preserves_rung_labels_and_deltas_each_counter() {
        let previous = Metrics {
            rungs: BTreeMap::from([
                (0, rung(0, "claim_idle", "previous_cpu", 10, 7, 3, 0)),
                (1, rung(1, "pick_idle", "task_allowed", 3, 2, 1, 4)),
            ]),
            ..Default::default()
        };
        let current = Metrics {
            rungs: BTreeMap::from([
                (0, rung(0, "claim_idle", "previous_cpu", 16, 11, 5, 1)),
                (1, rung(1, "pick_idle", "task_allowed", 8, 6, 2, 2)),
            ]),
            ..Default::default()
        };

        let delta = current.delta(&previous);

        assert_eq!(
            delta.rungs[&0],
            rung(0, "claim_idle", "previous_cpu", 6, 4, 2, 1)
        );
        assert_eq!(
            delta.rungs[&1],
            rung(1, "pick_idle", "task_allowed", 5, 4, 1, 0)
        );
    }

    #[test]
    fn text_report_calls_successful_selection_an_idle_hint() {
        let metrics = Metrics {
            select_calls: 12,
            idle_hints: 9,
            rungs: BTreeMap::from([(0, rung(0, "claim_idle", "previous_cpu", 12, 9, 3, 0))]),
            ..Default::default()
        };

        let report = metrics.format_text();

        assert!(report.contains("idle hints: 9"));
        assert!(report.contains("rung 0 claim_idle(previous_cpu)"));
        assert!(!report.to_ascii_lowercase().contains("dispatch"));
    }

    #[test]
    fn ndjson_is_one_parseable_json_record() {
        let metrics = Metrics {
            select_calls: 7,
            idle_hints: 4,
            select_latency_max_ns: 123,
            rungs: BTreeMap::from([(0, rung(0, "claim_idle", "previous_cpu", 7, 4, 3, 0))]),
            ..Default::default()
        };

        let encoded = metrics.to_ndjson().expect("metrics should serialize");
        let parsed: serde_json::Value =
            serde_json::from_str(encoded.trim_end()).expect("NDJSON record should parse");

        assert_eq!(encoded.lines().count(), 1);
        assert!(encoded.ends_with('\n'));
        assert_eq!(parsed["select_calls"], 7);
        assert_eq!(parsed["idle_hints"], 4);
        assert_eq!(parsed["select_latency_max_ns"], 123);
        assert_eq!(parsed["rungs"]["0"]["operation"], "claim_idle");
    }
}
