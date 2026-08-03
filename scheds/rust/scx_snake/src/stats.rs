// SPDX-License-Identifier: GPL-2.0-only

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use scx_stats::prelude::*;
use scx_stats_derive::{stat_doc, Stats};
use serde::{Deserialize, Serialize};

use crate::control::{SchedulerRequest, SchedulerResponse};
use crate::fine_timing::FineTimingCallback;
use crate::task_cells::ThreadCellAssignment;

#[stat_doc]
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize, Stats)]
#[stat(_om_prefix = "callback_timing_", _om_label = "callback")]
pub struct CallbackTimingMetrics {
    #[stat(desc = "Total sampled callback execution time")]
    pub total_ns: u64,
    #[stat(desc = "Base-2 nanosecond callback execution-time buckets", _om_skip)]
    pub buckets: Vec<u64>,
}

#[stat_doc]
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize, Stats)]
pub struct RungTimingMetrics {
    #[stat(desc = "Total sampled rung execution time", _om_skip)]
    pub total_ns: u64,
    #[stat(desc = "Base-2 nanosecond rung execution-time buckets", _om_skip)]
    pub buckets: Vec<u64>,
}

impl RungTimingMetrics {
    fn delta(&self, previous: Option<&Self>) -> Self {
        Self {
            total_ns: self
                .total_ns
                .saturating_sub(previous.map_or(0, |metrics| metrics.total_ns)),
            buckets: self
                .buckets
                .iter()
                .enumerate()
                .map(|(index, count)| {
                    count.saturating_sub(
                        previous
                            .and_then(|metrics| metrics.buckets.get(index))
                            .copied()
                            .unwrap_or_default(),
                    )
                })
                .collect(),
        }
    }
}

impl CallbackTimingMetrics {
    fn delta(&self, previous: Option<&Self>) -> Self {
        Self {
            total_ns: self
                .total_ns
                .saturating_sub(previous.map_or(0, |metrics| metrics.total_ns)),
            buckets: self
                .buckets
                .iter()
                .enumerate()
                .map(|(index, count)| {
                    count.saturating_sub(
                        previous
                            .and_then(|metrics| metrics.buckets.get(index))
                            .copied()
                            .unwrap_or_default(),
                    )
                })
                .collect(),
        }
    }
}

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
    #[stat(desc = "Number of times this rung selected an idle CPU")]
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
#[stat(_om_prefix = "queue_rung_", _om_label = "queue_rung_index")]
pub struct QueueRungMetrics {
    #[stat(desc = "Zero-based position in the queue callback ladder", _om_skip)]
    pub index: u32,
    #[stat(desc = "Userspace queue rung label", _om_skip)]
    pub operation: String,
    #[stat(desc = "Number of times BPF evaluated this queue rung")]
    pub attempts: u64,
    #[stat(desc = "Number of successful or candidate-producing evaluations")]
    pub hits: u64,
    #[stat(desc = "Number of inapplicable, empty, or exhausted evaluations")]
    pub misses: u64,
    #[stat(desc = "Number of invalid or failed queue rung evaluations")]
    pub errors: u64,
    #[stat(desc = "Number of times this peek candidate won arbitration")]
    pub selected: u64,
    #[stat(desc = "Number of selected candidates that missed during the atomic move")]
    pub move_misses: u64,
    #[stat(desc = "Number of bounded fallback consumption attempts")]
    pub fallback_attempts: u64,
    #[stat(desc = "Number of bounded fallback attempts that consumed work")]
    pub fallback_hits: u64,
    #[stat(desc = "Number of bounded fallback attempts that found no work")]
    pub fallback_misses: u64,
}

impl QueueRungMetrics {
    fn delta(&self, previous: Option<&Self>) -> Self {
        let previous = previous.cloned().unwrap_or_default();
        Self {
            index: self.index,
            operation: self.operation.clone(),
            attempts: self.attempts.saturating_sub(previous.attempts),
            hits: self.hits.saturating_sub(previous.hits),
            misses: self.misses.saturating_sub(previous.misses),
            errors: self.errors.saturating_sub(previous.errors),
            selected: self.selected.saturating_sub(previous.selected),
            move_misses: self.move_misses.saturating_sub(previous.move_misses),
            fallback_attempts: self
                .fallback_attempts
                .saturating_sub(previous.fallback_attempts),
            fallback_hits: self.fallback_hits.saturating_sub(previous.fallback_hits),
            fallback_misses: self
                .fallback_misses
                .saturating_sub(previous.fallback_misses),
        }
    }
}

#[stat_doc]
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize, Stats)]
#[stat(_om_prefix = "cpu_", _om_label = "cpu")]
pub struct CpuMetrics {
    #[stat(desc = "Logical CPU ID", _om_skip)]
    pub cpu: u32,
    #[stat(desc = "Nanoseconds Snake tasks ran on this CPU")]
    pub runtime_ns: u64,
}

impl CpuMetrics {
    fn delta(&self, previous: Option<&Self>) -> Self {
        Self {
            cpu: self.cpu,
            runtime_ns: self
                .runtime_ns
                .saturating_sub(previous.map_or(0, |metrics| metrics.runtime_ns)),
        }
    }
}

#[stat_doc]
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, Stats)]
#[stat(_om_prefix = "cell_", _om_label = "cell_id")]
pub struct CellMetrics {
    #[stat(desc = "External task-cell ID", _om_skip)]
    pub id: u32,
    #[stat(desc = "Dense queue and clock index", _om_skip)]
    pub index: u32,
    #[stat(desc = "Reuse epoch for the external task-cell ID", _om_skip)]
    pub slot_epoch: u32,
    #[stat(desc = "CPUs primarily owned by this cell")]
    #[serde(default)]
    pub primary_cpu_count: u32,
    #[stat(desc = "Instantaneous cell CPU utilization percentage")]
    #[serde(default)]
    pub utilization_pct: f64,
    #[stat(desc = "EWMA cell CPU utilization percentage")]
    #[serde(default)]
    pub ewma_utilization_pct: f64,
    #[stat(desc = "Percentage of cell runtime borrowed from other cells")]
    #[serde(default)]
    pub borrowed_pct: f64,
    #[stat(desc = "Percentage of owned CPU capacity lent to other cells")]
    #[serde(default)]
    pub lent_pct: f64,
    #[stat(desc = "Runtime charged to tasks in this cell")]
    pub runtime_ns: u64,
    #[stat(desc = "Per-CPU runtime charged to tasks in this cell", _om_skip)]
    #[serde(default)]
    pub runtime_ns_by_cpu: BTreeMap<u32, u64>,
    #[stat(desc = "Runtime consumed on CPUs owned by this cell")]
    pub primary_runtime_ns: u64,
    #[stat(desc = "Runtime this cell consumed on CPUs owned by other cells")]
    pub borrowed_runtime_ns: u64,
    #[stat(desc = "Runtime other cells consumed on CPUs owned by this cell")]
    pub lent_runtime_ns: u64,
    #[stat(desc = "CPU-restricted affinity runtime from other cells on CPUs owned by this cell")]
    pub foreign_affinity_runtime_ns: u64,
    #[stat(desc = "Tasks inserted into normal cell queues")]
    pub normal_enqueues: u64,
    #[stat(desc = "Tasks inserted into affinity queues")]
    pub affinity_enqueues: u64,
    #[stat(desc = "Normal cell tasks selected for execution")]
    pub normal_dispatches: u64,
    #[stat(desc = "Affinity tasks selected for execution")]
    pub affinity_dispatches: u64,
    #[stat(desc = "Task migrations into this cell clock")]
    pub clock_transitions: u64,
}

impl CellMetrics {
    fn delta(&self, previous: Option<&Self>) -> Self {
        let previous = previous
            .filter(|previous| previous.slot_epoch == self.slot_epoch)
            .cloned()
            .unwrap_or_default();
        Self {
            id: self.id,
            index: self.index,
            slot_epoch: self.slot_epoch,
            primary_cpu_count: self.primary_cpu_count,
            utilization_pct: self.utilization_pct,
            ewma_utilization_pct: self.ewma_utilization_pct,
            borrowed_pct: self.borrowed_pct,
            lent_pct: self.lent_pct,
            runtime_ns: self.runtime_ns.saturating_sub(previous.runtime_ns),
            runtime_ns_by_cpu: self
                .runtime_ns_by_cpu
                .iter()
                .filter_map(|(&cpu, &runtime_ns)| {
                    let delta = runtime_ns
                        .saturating_sub(previous.runtime_ns_by_cpu.get(&cpu).copied().unwrap_or(0));
                    (delta > 0).then_some((cpu, delta))
                })
                .collect(),
            primary_runtime_ns: self
                .primary_runtime_ns
                .saturating_sub(previous.primary_runtime_ns),
            borrowed_runtime_ns: self
                .borrowed_runtime_ns
                .saturating_sub(previous.borrowed_runtime_ns),
            lent_runtime_ns: self
                .lent_runtime_ns
                .saturating_sub(previous.lent_runtime_ns),
            foreign_affinity_runtime_ns: self
                .foreign_affinity_runtime_ns
                .saturating_sub(previous.foreign_affinity_runtime_ns),
            normal_enqueues: self
                .normal_enqueues
                .saturating_sub(previous.normal_enqueues),
            affinity_enqueues: self
                .affinity_enqueues
                .saturating_sub(previous.affinity_enqueues),
            normal_dispatches: self
                .normal_dispatches
                .saturating_sub(previous.normal_dispatches),
            affinity_dispatches: self
                .affinity_dispatches
                .saturating_sub(previous.affinity_dispatches),
            clock_transitions: self
                .clock_transitions
                .saturating_sub(previous.clock_transitions),
        }
    }
}

#[stat_doc]
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct Metrics {
    #[stat(desc = "Active userspace policy generation")]
    pub policy_generation: u64,
    #[stat(desc = "Completed managed-cell demand rebalances")]
    #[serde(default)]
    pub managed_rebalance_count: u64,
    #[stat(desc = "Unix timestamp in milliseconds of the latest managed-cell rebalance")]
    #[serde(default)]
    pub managed_last_rebalance_at_ms: u64,
    #[stat(desc = "Active scheduler fairness discipline", _om_skip)]
    pub fairness_mode: String,
    #[stat(desc = "Number of select_cpu callback invocations")]
    pub select_calls: u64,
    #[stat(desc = "Number of dispatch callback invocations")]
    pub dispatch_calls: u64,
    #[stat(desc = "Number of successful direct dispatches to selected idle CPUs")]
    pub direct_dispatches: u64,
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
    #[stat(desc = "Tasks inserted into the explicitly drained shared FIFO DSQ")]
    pub fifo_shared_enqueues: u64,
    #[stat(desc = "Tasks dispatched from the explicitly drained shared FIFO DSQ")]
    pub fifo_shared_dispatches: u64,
    #[stat(desc = "Number of running callback invocations")]
    pub running: u64,
    #[stat(desc = "Running callbacks for tasks intentionally assigned to no cell")]
    pub membership_no_cell_runs: u64,
    #[stat(desc = "Running callbacks for tasks carrying an invalid cell assignment")]
    pub membership_invalid_runs: u64,
    #[stat(desc = "Number of stopping callback invocations")]
    pub stopping: u64,
    #[stat(desc = "Number of quiescent callback invocations")]
    pub quiescent: u64,
    #[stat(desc = "Total nanoseconds spent in select_cpu")]
    pub select_latency_ns: u64,
    #[stat(desc = "Maximum select_cpu latency in nanoseconds for this policy generation")]
    pub select_latency_max_ns: u64,
    #[stat(desc = "Live cell annotation changes placed on an idle CPU in the selected cell")]
    pub cell_rehomes: u64,
    #[stat(desc = "Cell rehome attempts deferred because no task-cell rung selected a CPU")]
    pub cell_rehome_misses: u64,
    #[stat(desc = "Expired running tasks forced through enqueue for pending queue-cell rehomes")]
    pub queue_rehome_preemptions: u64,
    #[stat(desc = "Old-cell normal-queue executions preserved across live cell rehomes")]
    pub queue_stale_rehome_runs: u64,
    #[stat(desc = "Directly borrowed slices forced back through enqueue")]
    pub queue_borrow_yields: u64,
    #[stat(desc = "Tasks inserted into the VTIME ordered queue")]
    pub vtime_enqueues: u64,
    #[stat(desc = "Tasks dispatched from the VTIME ordered queue")]
    pub vtime_dispatches: u64,
    #[stat(desc = "Affinity-restricted tasks inserted into per-CPU VTIME queues")]
    pub vtime_cpu_enqueues: u64,
    #[stat(desc = "Tasks dispatched from per-CPU VTIME queues")]
    pub vtime_cpu_dispatches: u64,
    #[stat(desc = "Synchronous non-idle placements queued for VTIME ordering")]
    pub vtime_strict_preempt_queues: u64,
    #[stat(desc = "Task runtime delivered through the VTIME idle-CPU direct path")]
    pub vtime_direct_runtime_ns: u64,
    #[stat(desc = "Task runtime delivered through the VTIME ordered queue")]
    pub vtime_queued_runtime_ns: u64,
    #[stat(desc = "VTIME sleeper credits clamped to one virtual slice")]
    pub vtime_credit_clamps: u64,
    #[stat(desc = "VTIME cell-clock compare-and-swap retries")]
    pub vtime_clock_cas_retries: u64,
    #[stat(desc = "VTIME cell-clock operations which exhausted the CAS retry budget")]
    pub vtime_clock_cas_exhaustions: u64,
    #[stat(desc = "VTIME state and runtime accounting errors")]
    pub vtime_accounting_errors: u64,
    #[stat(desc = "Equal cell and affinity VTIME heads resolved by alternating ties")]
    pub vtime_equal_head_ties: u64,
    #[stat(desc = "Tasks inserted into the EEVDF eligible deadline queue")]
    pub eevdf_eligible_enqueues: u64,
    #[stat(desc = "Tasks inserted into the EEVDF future virtual-start queue")]
    pub eevdf_future_enqueues: u64,
    #[stat(desc = "Future tasks promoted after becoming EEVDF-eligible")]
    pub eevdf_promotions: u64,
    #[stat(desc = "Work-conserving EEVDF virtual-time frontier advances")]
    pub eevdf_forced_advances: u64,
    #[stat(desc = "Tasks dispatched from the EEVDF eligible queue")]
    pub eevdf_dispatches: u64,
    #[stat(desc = "Synchronous non-idle placements queued for strict fairness")]
    pub eevdf_strict_preempt_queues: u64,
    #[stat(desc = "Task runtime delivered through the idle-CPU direct path")]
    pub eevdf_direct_runtime_ns: u64,
    #[stat(desc = "Task runtime delivered through EEVDF ordered queues")]
    pub eevdf_queued_runtime_ns: u64,
    #[stat(desc = "EEVDF lag values clamped to one virtual request")]
    pub eevdf_lag_clamps: u64,
    #[stat(desc = "Affinity-constrained run starts with stale lag clamped")]
    pub eevdf_run_lag_clamps: u64,
    #[stat(desc = "EEVDF state or runnable-weight accounting errors")]
    pub eevdf_accounting_errors: u64,
    #[stat(desc = "Per-CPU Snake runtime")]
    pub cpus: BTreeMap<u32, CpuMetrics>,
    #[stat(desc = "Per-cell fairness and resource-consumption metrics")]
    pub cells: BTreeMap<u32, CellMetrics>,
    #[stat(desc = "Per-rung policy evaluation metrics")]
    pub rungs: BTreeMap<u32, RungMetrics>,
    #[stat(desc = "Per-rung enqueue callback metrics")]
    pub enqueue_rungs: BTreeMap<u32, QueueRungMetrics>,
    #[stat(desc = "Per-rung dispatch callback metrics")]
    pub dispatch_rungs: BTreeMap<u32, QueueRungMetrics>,
    #[stat(
        desc = "Sampled execution-time histograms for every policy rung",
        _om_skip
    )]
    pub rung_timing: BTreeMap<String, RungTimingMetrics>,
    #[stat(desc = "Sampled callback execution-time histograms", _om_skip)]
    pub callback_timing: BTreeMap<String, CallbackTimingMetrics>,
}

impl Metrics {
    pub fn delta(&self, previous: &Self) -> Self {
        if self.policy_generation != previous.policy_generation {
            let mut fresh = self.clone();
            fresh.managed_rebalance_count = self
                .managed_rebalance_count
                .saturating_sub(previous.managed_rebalance_count);
            return fresh;
        }

        Self {
            policy_generation: self.policy_generation,
            managed_rebalance_count: self
                .managed_rebalance_count
                .saturating_sub(previous.managed_rebalance_count),
            managed_last_rebalance_at_ms: self.managed_last_rebalance_at_ms,
            fairness_mode: self.fairness_mode.clone(),
            select_calls: self.select_calls.saturating_sub(previous.select_calls),
            dispatch_calls: self.dispatch_calls.saturating_sub(previous.dispatch_calls),
            direct_dispatches: self
                .direct_dispatches
                .saturating_sub(previous.direct_dispatches),
            ladder_exhaustions: self
                .ladder_exhaustions
                .saturating_sub(previous.ladder_exhaustions),
            fallback_prev: self.fallback_prev.saturating_sub(previous.fallback_prev),
            fallback_any: self.fallback_any.saturating_sub(previous.fallback_any),
            invalid_errors: self.invalid_errors.saturating_sub(previous.invalid_errors),
            enqueues: self.enqueues.saturating_sub(previous.enqueues),
            fifo_shared_enqueues: self
                .fifo_shared_enqueues
                .saturating_sub(previous.fifo_shared_enqueues),
            fifo_shared_dispatches: self
                .fifo_shared_dispatches
                .saturating_sub(previous.fifo_shared_dispatches),
            running: self.running.saturating_sub(previous.running),
            membership_no_cell_runs: self
                .membership_no_cell_runs
                .saturating_sub(previous.membership_no_cell_runs),
            membership_invalid_runs: self
                .membership_invalid_runs
                .saturating_sub(previous.membership_invalid_runs),
            stopping: self.stopping.saturating_sub(previous.stopping),
            quiescent: self.quiescent.saturating_sub(previous.quiescent),
            select_latency_ns: self
                .select_latency_ns
                .saturating_sub(previous.select_latency_ns),
            select_latency_max_ns: self.select_latency_max_ns,
            cell_rehomes: self.cell_rehomes.saturating_sub(previous.cell_rehomes),
            cell_rehome_misses: self
                .cell_rehome_misses
                .saturating_sub(previous.cell_rehome_misses),
            queue_rehome_preemptions: self
                .queue_rehome_preemptions
                .saturating_sub(previous.queue_rehome_preemptions),
            queue_stale_rehome_runs: self
                .queue_stale_rehome_runs
                .saturating_sub(previous.queue_stale_rehome_runs),
            queue_borrow_yields: self
                .queue_borrow_yields
                .saturating_sub(previous.queue_borrow_yields),
            vtime_enqueues: self.vtime_enqueues.saturating_sub(previous.vtime_enqueues),
            vtime_dispatches: self
                .vtime_dispatches
                .saturating_sub(previous.vtime_dispatches),
            vtime_cpu_enqueues: self
                .vtime_cpu_enqueues
                .saturating_sub(previous.vtime_cpu_enqueues),
            vtime_cpu_dispatches: self
                .vtime_cpu_dispatches
                .saturating_sub(previous.vtime_cpu_dispatches),
            vtime_strict_preempt_queues: self
                .vtime_strict_preempt_queues
                .saturating_sub(previous.vtime_strict_preempt_queues),
            vtime_direct_runtime_ns: self
                .vtime_direct_runtime_ns
                .saturating_sub(previous.vtime_direct_runtime_ns),
            vtime_queued_runtime_ns: self
                .vtime_queued_runtime_ns
                .saturating_sub(previous.vtime_queued_runtime_ns),
            vtime_credit_clamps: self
                .vtime_credit_clamps
                .saturating_sub(previous.vtime_credit_clamps),
            vtime_clock_cas_retries: self
                .vtime_clock_cas_retries
                .saturating_sub(previous.vtime_clock_cas_retries),
            vtime_clock_cas_exhaustions: self
                .vtime_clock_cas_exhaustions
                .saturating_sub(previous.vtime_clock_cas_exhaustions),
            vtime_accounting_errors: self
                .vtime_accounting_errors
                .saturating_sub(previous.vtime_accounting_errors),
            vtime_equal_head_ties: self
                .vtime_equal_head_ties
                .saturating_sub(previous.vtime_equal_head_ties),
            eevdf_eligible_enqueues: self
                .eevdf_eligible_enqueues
                .saturating_sub(previous.eevdf_eligible_enqueues),
            eevdf_future_enqueues: self
                .eevdf_future_enqueues
                .saturating_sub(previous.eevdf_future_enqueues),
            eevdf_promotions: self
                .eevdf_promotions
                .saturating_sub(previous.eevdf_promotions),
            eevdf_forced_advances: self
                .eevdf_forced_advances
                .saturating_sub(previous.eevdf_forced_advances),
            eevdf_dispatches: self
                .eevdf_dispatches
                .saturating_sub(previous.eevdf_dispatches),
            eevdf_strict_preempt_queues: self
                .eevdf_strict_preempt_queues
                .saturating_sub(previous.eevdf_strict_preempt_queues),
            eevdf_direct_runtime_ns: self
                .eevdf_direct_runtime_ns
                .saturating_sub(previous.eevdf_direct_runtime_ns),
            eevdf_queued_runtime_ns: self
                .eevdf_queued_runtime_ns
                .saturating_sub(previous.eevdf_queued_runtime_ns),
            eevdf_lag_clamps: self
                .eevdf_lag_clamps
                .saturating_sub(previous.eevdf_lag_clamps),
            eevdf_run_lag_clamps: self
                .eevdf_run_lag_clamps
                .saturating_sub(previous.eevdf_run_lag_clamps),
            eevdf_accounting_errors: self
                .eevdf_accounting_errors
                .saturating_sub(previous.eevdf_accounting_errors),
            cpus: self
                .cpus
                .iter()
                .map(|(cpu, metrics)| (*cpu, metrics.delta(previous.cpus.get(cpu))))
                .collect(),
            cells: self
                .cells
                .iter()
                .map(|(id, metrics)| (*id, metrics.delta(previous.cells.get(id))))
                .collect(),
            rungs: self
                .rungs
                .iter()
                .map(|(index, rung)| (*index, rung.delta(previous.rungs.get(index))))
                .collect(),
            enqueue_rungs: self
                .enqueue_rungs
                .iter()
                .map(|(index, rung)| (*index, rung.delta(previous.enqueue_rungs.get(index))))
                .collect(),
            dispatch_rungs: self
                .dispatch_rungs
                .iter()
                .map(|(index, rung)| (*index, rung.delta(previous.dispatch_rungs.get(index))))
                .collect(),
            rung_timing: self
                .rung_timing
                .iter()
                .map(|(key, timing)| (key.clone(), timing.delta(previous.rung_timing.get(key))))
                .collect(),
            callback_timing: self
                .callback_timing
                .iter()
                .map(|(name, metrics)| {
                    (
                        name.clone(),
                        metrics.delta(previous.callback_timing.get(name)),
                    )
                })
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
                "scx_snake policy generation {} stats (fairness: {})\n",
                "  select calls: {} | direct dispatches: {} | ladder exhausted: {}\n",
                "  fallback previous CPU: {} | fallback any allowed CPU: {} | invalid/errors: {}\n",
                "  callbacks enqueue: {} | dispatch: {} | running: {} | stopping: {} | quiescent: {}\n",
                "  membership runs no-cell: {} | invalid: {}\n",
                "  managed rebalances: {} | latest at ms: {}\n",
                "  FIFO shared enqueues/dispatches: {}/{}\n",
                "  select latency ns total: {} | average: {} | cumulative max: {}\n",
                "  cell rehomes: {} | deferred rehomes: {} | queue preemptions/stale runs: {}/{} | borrow yields: {}\n",
                "  VTIME enqueues: {} (per-CPU: {}) | dispatches: {} (per-CPU: {}) | strict sync queues: {}\n",
                "  VTIME direct/queued runtime ns: {}/{} | credit clamps: {} | clock CAS retries/exhaustions: {}/{} | accounting errors: {} | equal-head ties: {}\n",
                "  EEVDF eligible/future enqueues: {}/{} | promotions: {} | forced advances: {} | dispatches: {}\n",
                "  EEVDF strict sync queues: {} | direct/queued runtime ns: {}/{} | lag/run-start clamps: {}/{} | accounting errors: {}\n",
                "  rungs:\n"
            ),
            self.policy_generation,
            self.fairness_mode,
            self.select_calls,
            self.direct_dispatches,
            self.ladder_exhaustions,
            self.fallback_prev,
            self.fallback_any,
            self.invalid_errors,
            self.enqueues,
            self.dispatch_calls,
            self.running,
            self.stopping,
            self.quiescent,
            self.membership_no_cell_runs,
            self.membership_invalid_runs,
            self.managed_rebalance_count,
            self.managed_last_rebalance_at_ms,
            self.fifo_shared_enqueues,
            self.fifo_shared_dispatches,
            self.select_latency_ns,
            average_latency_ns,
            self.select_latency_max_ns,
            self.cell_rehomes,
            self.cell_rehome_misses,
            self.queue_rehome_preemptions,
            self.queue_stale_rehome_runs,
            self.queue_borrow_yields,
            self.vtime_enqueues,
            self.vtime_cpu_enqueues,
            self.vtime_dispatches,
            self.vtime_cpu_dispatches,
            self.vtime_strict_preempt_queues,
            self.vtime_direct_runtime_ns,
            self.vtime_queued_runtime_ns,
            self.vtime_credit_clamps,
            self.vtime_clock_cas_retries,
            self.vtime_clock_cas_exhaustions,
            self.vtime_accounting_errors,
            self.vtime_equal_head_ties,
            self.eevdf_eligible_enqueues,
            self.eevdf_future_enqueues,
            self.eevdf_promotions,
            self.eevdf_forced_advances,
            self.eevdf_dispatches,
            self.eevdf_strict_preempt_queues,
            self.eevdf_direct_runtime_ns,
            self.eevdf_queued_runtime_ns,
            self.eevdf_lag_clamps,
            self.eevdf_run_lag_clamps,
            self.eevdf_accounting_errors,
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
        for (ladder, rungs) in [
            ("enqueue", &self.enqueue_rungs),
            ("dispatch", &self.dispatch_rungs),
        ] {
            for rung in rungs.values() {
                output.push_str(&format!(
                    "    {ladder} rung {} {}: attempts {} | hits {} | misses {} | errors {} | selected {} | move_misses {} | fallback {}/{}/{}\n",
                    rung.index,
                    rung.operation,
                    rung.attempts,
                    rung.hits,
                    rung.misses,
                    rung.errors,
                    rung.selected,
                    rung.move_misses,
                    rung.fallback_attempts,
                    rung.fallback_hits,
                    rung.fallback_misses,
                ));
            }
        }
        for cell in self.cells.values() {
            output.push_str(&format!(
                "    cell {}: primary CPUs {} | util/ewma {:.1}/{:.1}% | borrowed/lent {:.1}/{:.1}% | runtime {} | primary {} | borrowed {} | lent {} | normal/affinity enqueues {}/{} | dispatches {}/{} | clock transitions {}\n",
                cell.id,
                cell.primary_cpu_count,
                cell.utilization_pct,
                cell.ewma_utilization_pct,
                cell.borrowed_pct,
                cell.lent_pct,
                cell.runtime_ns,
                cell.primary_runtime_ns,
                cell.borrowed_runtime_ns,
                cell.lent_runtime_ns,
                cell.normal_enqueues,
                cell.affinity_enqueues,
                cell.normal_dispatches,
                cell.affinity_dispatches,
                cell.clock_transitions,
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

pub fn server_data() -> StatsServerData<SchedulerRequest, SchedulerResponse> {
    let open: Box<dyn StatsOpener<SchedulerRequest, SchedulerResponse>> =
        Box::new(move |(req_ch, res_ch)| {
            req_ch.send(SchedulerRequest::Metrics)?;
            let mut previous = match res_ch.recv()? {
                SchedulerResponse::Metrics(metrics) => metrics,
                response => bail!("unexpected response to metrics request: {response:?}"),
            };

            let read: Box<dyn StatsReader<SchedulerRequest, SchedulerResponse>> =
                Box::new(move |_args, (req_ch, res_ch)| {
                    req_ch.send(SchedulerRequest::Metrics)?;
                    let current = match res_ch.recv()? {
                        SchedulerResponse::Metrics(metrics) => metrics,
                        response => {
                            bail!("unexpected response to metrics request: {response:?}")
                        }
                    };
                    let delta = current.delta(&previous);
                    previous = current;
                    delta.to_json()
                });

            Ok(read)
        });

    let update: Box<dyn StatsOpener<SchedulerRequest, SchedulerResponse>> = Box::new(move |_| {
        let read: Box<dyn StatsReader<SchedulerRequest, SchedulerResponse>> =
            Box::new(move |args, (req_ch, res_ch)| {
                let source = args
                    .get("source")
                    .context("policy_update requires a source argument")?
                    .clone();
                req_ch.send(SchedulerRequest::ReplacePolicy { source })?;
                match res_ch.recv()? {
                    SchedulerResponse::ReplacePolicy(Ok(response)) => {
                        Ok(serde_json::to_value(response)?)
                    }
                    SchedulerResponse::ReplacePolicy(Err(error)) => bail!(error),
                    response => {
                        bail!("unexpected response to policy update request: {response:?}")
                    }
                }
            });
        Ok(read)
    });

    let inspect: Box<dyn StatsOpener<SchedulerRequest, SchedulerResponse>> = Box::new(move |_| {
        let read: Box<dyn StatsReader<SchedulerRequest, SchedulerResponse>> =
            Box::new(move |_args, (req_ch, res_ch)| {
                req_ch.send(SchedulerRequest::Inspect)?;
                match res_ch.recv()? {
                    SchedulerResponse::Inspection(snapshot) => Ok(serde_json::to_value(snapshot)?),
                    response => bail!("unexpected response to inspection request: {response:?}"),
                }
            });
        Ok(read)
    });

    let validate_policy: Box<dyn StatsOpener<SchedulerRequest, SchedulerResponse>> =
        Box::new(move |_| {
            let read: Box<dyn StatsReader<SchedulerRequest, SchedulerResponse>> =
                Box::new(move |args, (req_ch, res_ch)| {
                    let source = args
                        .get("source")
                        .context("policy_validate requires a source argument")?
                        .clone();
                    req_ch.send(SchedulerRequest::ValidatePolicy { source })?;
                    match res_ch.recv()? {
                        SchedulerResponse::PolicyValidation(Ok(response)) => {
                            Ok(serde_json::to_value(response)?)
                        }
                        SchedulerResponse::PolicyValidation(Err(error)) => bail!(error),
                        response => {
                            bail!("unexpected response to policy validation request: {response:?}")
                        }
                    }
                });
            Ok(read)
        });

    let set_cell: Box<dyn StatsOpener<SchedulerRequest, SchedulerResponse>> = Box::new(move |_| {
        let read: Box<dyn StatsReader<SchedulerRequest, SchedulerResponse>> =
            Box::new(move |args, (req_ch, res_ch)| {
                let tid = parse_arg::<i32>(args, "tid", "thread_cell_set")?;
                let cell_id = parse_arg::<u32>(args, "cell_id", "thread_cell_set")?;
                req_ch.send(SchedulerRequest::SetThreadCell(ThreadCellAssignment {
                    tid,
                    cell_id,
                }))?;
                receive_thread_cell_response(res_ch.recv()?)
            });
        Ok(read)
    });

    let clear_cell: Box<dyn StatsOpener<SchedulerRequest, SchedulerResponse>> =
        Box::new(move |_| {
            let read: Box<dyn StatsReader<SchedulerRequest, SchedulerResponse>> =
                Box::new(move |args, (req_ch, res_ch)| {
                    let tid = parse_arg::<i32>(args, "tid", "thread_cell_clear")?;
                    req_ch.send(SchedulerRequest::ClearThreadCell { tid })?;
                    receive_thread_cell_response(res_ch.recv()?)
                });
            Ok(read)
        });

    let set_fine_timing: Box<dyn StatsOpener<SchedulerRequest, SchedulerResponse>> =
        Box::new(move |_| {
            let read: Box<dyn StatsReader<SchedulerRequest, SchedulerResponse>> =
                Box::new(move |args, (req_ch, res_ch)| {
                    let callback = args
                        .get("callback")
                        .context("fine_timing_set requires a callback argument")?
                        .parse::<FineTimingCallback>()
                        .map_err(anyhow::Error::msg)?;
                    let enabled = parse_arg::<bool>(args, "enabled", "fine_timing_set")?;
                    req_ch.send(SchedulerRequest::SetFineTiming { callback, enabled })?;
                    match res_ch.recv()? {
                        SchedulerResponse::FineTiming(Ok(response)) => {
                            Ok(serde_json::to_value(response)?)
                        }
                        SchedulerResponse::FineTiming(Err(error)) => bail!(error),
                        response => {
                            bail!("unexpected response to fine timing request: {response:?}")
                        }
                    }
                });
            Ok(read)
        });

    let set_callback_timing_sample_rate: Box<dyn StatsOpener<SchedulerRequest, SchedulerResponse>> =
        Box::new(move |_| {
            let read: Box<dyn StatsReader<SchedulerRequest, SchedulerResponse>> =
                Box::new(move |args, (req_ch, res_ch)| {
                    let sample_rate =
                        parse_arg::<u32>(args, "sample_rate", "callback_timing_sample_rate_set")?;
                    req_ch.send(SchedulerRequest::SetCallbackTimingSampleRate { sample_rate })?;
                    match res_ch.recv()? {
                        SchedulerResponse::CallbackTimingSampleRate(Ok(response)) => {
                            Ok(serde_json::to_value(response)?)
                        }
                        SchedulerResponse::CallbackTimingSampleRate(Err(error)) => bail!(error),
                        response => bail!(
                        "unexpected response to callback timing sample rate request: {response:?}"
                    ),
                    }
                });
            Ok(read)
        });

    let set_queue_timing: Box<dyn StatsOpener<SchedulerRequest, SchedulerResponse>> =
        Box::new(move |_| {
            let read: Box<dyn StatsReader<SchedulerRequest, SchedulerResponse>> =
                Box::new(move |args, (req_ch, res_ch)| {
                    let enabled = parse_arg::<bool>(args, "enabled", "queue_timing_set")?;
                    req_ch.send(SchedulerRequest::SetQueueTiming { enabled })?;
                    match res_ch.recv()? {
                        SchedulerResponse::QueueTiming(Ok(response)) => {
                            Ok(serde_json::to_value(response)?)
                        }
                        SchedulerResponse::QueueTiming(Err(error)) => bail!(error),
                        response => {
                            bail!("unexpected response to queue timing request: {response:?}")
                        }
                    }
                });
            Ok(read)
        });

    let reset_stats: Box<dyn StatsOpener<SchedulerRequest, SchedulerResponse>> =
        Box::new(move |_| {
            let read: Box<dyn StatsReader<SchedulerRequest, SchedulerResponse>> =
                Box::new(move |_args, (req_ch, res_ch)| {
                    req_ch.send(SchedulerRequest::ResetStats)?;
                    receive_stats_reset_response(res_ch.recv()?)
                });
            Ok(read)
        });

    StatsServerData::new()
        .add_meta(Metrics::meta())
        .add_meta(CallbackTimingMetrics::meta())
        .add_meta(CpuMetrics::meta())
        .add_meta(CellMetrics::meta())
        .add_meta(RungMetrics::meta())
        .add_meta(QueueRungMetrics::meta())
        .add_meta(RungTimingMetrics::meta())
        .add_ops("top", StatsOps { open, close: None })
        .add_ops(
            "inspect",
            StatsOps {
                open: inspect,
                close: None,
            },
        )
        .add_ops(
            "policy_validate",
            StatsOps {
                open: validate_policy,
                close: None,
            },
        )
        .add_ops(
            "policy_update",
            StatsOps {
                open: update,
                close: None,
            },
        )
        .add_ops(
            "thread_cell_set",
            StatsOps {
                open: set_cell,
                close: None,
            },
        )
        .add_ops(
            "thread_cell_clear",
            StatsOps {
                open: clear_cell,
                close: None,
            },
        )
        .add_ops(
            "fine_timing_set",
            StatsOps {
                open: set_fine_timing,
                close: None,
            },
        )
        .add_ops(
            "queue_timing_set",
            StatsOps {
                open: set_queue_timing,
                close: None,
            },
        )
        .add_ops(
            "callback_timing_sample_rate_set",
            StatsOps {
                open: set_callback_timing_sample_rate,
                close: None,
            },
        )
        .add_ops(
            "stats_reset",
            StatsOps {
                open: reset_stats,
                close: None,
            },
        )
}

fn parse_arg<T>(args: &BTreeMap<String, String>, key: &str, operation: &str) -> Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let value = args
        .get(key)
        .with_context(|| format!("{operation} requires a {key} argument"))?;
    value
        .parse()
        .map_err(|error| anyhow::anyhow!("invalid {key} `{value}`: {error}"))
}

fn receive_thread_cell_response(response: SchedulerResponse) -> Result<serde_json::Value> {
    match response {
        SchedulerResponse::ThreadCell(Ok(response)) => Ok(serde_json::to_value(response)?),
        SchedulerResponse::ThreadCell(Err(error)) => bail!(error),
        response => bail!("unexpected response to thread cell request: {response:?}"),
    }
}

fn receive_stats_reset_response(response: SchedulerResponse) -> Result<serde_json::Value> {
    match response {
        SchedulerResponse::StatsReset(Ok(response)) => Ok(serde_json::to_value(response)?),
        SchedulerResponse::StatsReset(Err(error)) => bail!(error),
        response => bail!("unexpected response to statistics reset request: {response:?}"),
    }
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
    fn callback_timing_delta_subtracts_totals_and_each_bucket() {
        let previous = Metrics {
            policy_generation: 7,
            callback_timing: BTreeMap::from([(
                "dispatch".into(),
                CallbackTimingMetrics {
                    total_ns: 100,
                    buckets: vec![1, 2, 3],
                },
            )]),
            ..Default::default()
        };
        let current = Metrics {
            policy_generation: 7,
            callback_timing: BTreeMap::from([(
                "dispatch".into(),
                CallbackTimingMetrics {
                    total_ns: 350,
                    buckets: vec![4, 8, 10],
                },
            )]),
            ..Default::default()
        };

        let timing = &current.delta(&previous).callback_timing["dispatch"];

        assert_eq!(timing.total_ns, 250);
        assert_eq!(timing.buckets, vec![3, 6, 7]);
    }

    #[test]
    fn stats_reset_response_serializes_the_control_contract() {
        let response = crate::control::StatsResetResponse {
            generation: 12,
            active_slot: 0,
            reset_at_ms: 8_765,
            fine_timing_stopped: false,
            queue_timing_stopped: true,
        };

        let value = receive_stats_reset_response(SchedulerResponse::StatsReset(Ok(response)))
            .expect("reset response should serialize");

        assert_eq!(
            value,
            serde_json::json!({
                "generation": 12,
                "active_slot": 0,
                "reset_at_ms": 8_765,
                "fine_timing_stopped": false,
                "queue_timing_stopped": true,
            })
        );
    }

    #[test]
    fn delta_saturates_counters_after_a_reset() {
        let previous = Metrics {
            select_calls: 20,
            direct_dispatches: 18,
            ladder_exhaustions: 7,
            fallback_prev: 6,
            fallback_any: 5,
            invalid_errors: 4,
            enqueues: 30,
            fifo_shared_enqueues: 22,
            fifo_shared_dispatches: 21,
            running: 29,
            stopping: 28,
            quiescent: 3,
            select_latency_ns: 2_000,
            queue_rehome_preemptions: 8,
            queue_stale_rehome_runs: 6,
            queue_borrow_yields: 4,
            vtime_cpu_enqueues: 20,
            vtime_cpu_dispatches: 19,
            vtime_clock_cas_retries: 18,
            vtime_clock_cas_exhaustions: 2,
            ..Default::default()
        };
        let current = Metrics {
            select_calls: 2,
            direct_dispatches: 1,
            ladder_exhaustions: 0,
            fallback_prev: 0,
            fallback_any: 0,
            invalid_errors: 0,
            enqueues: 3,
            fifo_shared_enqueues: 2,
            fifo_shared_dispatches: 1,
            running: 2,
            stopping: 1,
            quiescent: 0,
            select_latency_ns: 100,
            queue_rehome_preemptions: 1,
            queue_stale_rehome_runs: 0,
            queue_borrow_yields: 0,
            vtime_cpu_enqueues: 2,
            vtime_cpu_dispatches: 1,
            vtime_clock_cas_retries: 1,
            vtime_clock_cas_exhaustions: 0,
            ..Default::default()
        };

        let delta = current.delta(&previous);

        assert_eq!(delta.select_calls, 0);
        assert_eq!(delta.direct_dispatches, 0);
        assert_eq!(delta.ladder_exhaustions, 0);
        assert_eq!(delta.fallback_prev, 0);
        assert_eq!(delta.fallback_any, 0);
        assert_eq!(delta.invalid_errors, 0);
        assert_eq!(delta.enqueues, 0);
        assert_eq!(delta.fifo_shared_enqueues, 0);
        assert_eq!(delta.fifo_shared_dispatches, 0);
        assert_eq!(delta.running, 0);
        assert_eq!(delta.stopping, 0);
        assert_eq!(delta.quiescent, 0);
        assert_eq!(delta.select_latency_ns, 0);
        assert_eq!(delta.queue_rehome_preemptions, 0);
        assert_eq!(delta.queue_stale_rehome_runs, 0);
        assert_eq!(delta.queue_borrow_yields, 0);
        assert_eq!(delta.vtime_cpu_enqueues, 0);
        assert_eq!(delta.vtime_cpu_dispatches, 0);
        assert_eq!(delta.vtime_clock_cas_retries, 0);
        assert_eq!(delta.vtime_clock_cas_exhaustions, 0);
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
    fn delta_preserves_cpu_ids_and_deltas_runtime() {
        let previous = Metrics {
            cpus: BTreeMap::from([
                (
                    0,
                    CpuMetrics {
                        cpu: 0,
                        runtime_ns: 1_000,
                    },
                ),
                (
                    3,
                    CpuMetrics {
                        cpu: 3,
                        runtime_ns: 4_000,
                    },
                ),
            ]),
            ..Default::default()
        };
        let current = Metrics {
            cpus: BTreeMap::from([
                (
                    0,
                    CpuMetrics {
                        cpu: 0,
                        runtime_ns: 1_750,
                    },
                ),
                (
                    3,
                    CpuMetrics {
                        cpu: 3,
                        runtime_ns: 4_250,
                    },
                ),
            ]),
            ..Default::default()
        };

        let delta = current.delta(&previous);

        assert_eq!(
            delta.cpus[&0],
            CpuMetrics {
                cpu: 0,
                runtime_ns: 750
            }
        );
        assert_eq!(
            delta.cpus[&3],
            CpuMetrics {
                cpu: 3,
                runtime_ns: 250
            }
        );
    }

    #[test]
    fn cell_delta_preserves_per_cpu_runtime_attribution() {
        let previous = CellMetrics {
            id: 7,
            index: 2,
            slot_epoch: 4,
            runtime_ns: 5_000,
            runtime_ns_by_cpu: BTreeMap::from([(0, 1_000), (3, 4_000)]),
            foreign_affinity_runtime_ns: 400,
            ..Default::default()
        };
        let current = CellMetrics {
            id: 7,
            index: 2,
            slot_epoch: 4,
            runtime_ns: 6_000,
            runtime_ns_by_cpu: BTreeMap::from([(0, 1_750), (3, 4_250)]),
            foreign_affinity_runtime_ns: 650,
            ..Default::default()
        };

        let delta = current.delta(Some(&previous));

        assert_eq!(delta.slot_epoch, 4);
        assert_eq!(delta.runtime_ns, 1_000);
        assert_eq!(delta.foreign_affinity_runtime_ns, 250);
        assert_eq!(
            delta.runtime_ns_by_cpu,
            BTreeMap::from([(0, 750), (3, 250)])
        );
    }

    #[test]
    fn cell_delta_rebases_when_a_slot_epoch_changes() {
        let previous = CellMetrics {
            id: 7,
            index: 2,
            slot_epoch: 4,
            runtime_ns: 5_000,
            foreign_affinity_runtime_ns: 400,
            ..Default::default()
        };
        let current = CellMetrics {
            id: 7,
            index: 2,
            slot_epoch: 5,
            runtime_ns: 900,
            foreign_affinity_runtime_ns: 75,
            ..Default::default()
        };

        let delta = current.delta(Some(&previous));

        assert_eq!(delta.slot_epoch, 5);
        assert_eq!(delta.runtime_ns, 900);
        assert_eq!(delta.foreign_affinity_runtime_ns, 75);
    }

    #[test]
    fn generation_change_uses_the_new_generation_as_a_fresh_baseline() {
        let previous = Metrics {
            policy_generation: 7,
            select_calls: 100,
            rungs: BTreeMap::from([(0, rung(0, "claim_idle", "previous_cpu", 100, 80, 20, 0))]),
            ..Default::default()
        };
        let current = Metrics {
            policy_generation: 8,
            select_calls: 3,
            rungs: BTreeMap::from([(0, rung(0, "pick_random_idle", "task_allowed", 3, 2, 1, 0))]),
            ..Default::default()
        };

        assert_eq!(current.delta(&previous), current);
    }

    #[test]
    fn managed_rebalance_count_remains_an_event_counter_across_generations() {
        let previous = Metrics {
            policy_generation: 7,
            managed_rebalance_count: 3,
            managed_last_rebalance_at_ms: 100,
            ..Default::default()
        };
        let current = Metrics {
            policy_generation: 8,
            managed_rebalance_count: 4,
            managed_last_rebalance_at_ms: 200,
            ..Default::default()
        };

        let delta = current.delta(&previous);
        assert_eq!(delta.managed_rebalance_count, 1);
        assert_eq!(delta.managed_last_rebalance_at_ms, 200);
    }

    #[test]
    fn text_report_calls_successful_selection_a_direct_dispatch() {
        let metrics = Metrics {
            select_calls: 12,
            direct_dispatches: 9,
            membership_no_cell_runs: 6,
            membership_invalid_runs: 1,
            rungs: BTreeMap::from([(0, rung(0, "claim_idle", "previous_cpu", 12, 9, 3, 0))]),
            ..Default::default()
        };

        let report = metrics.format_text();

        assert!(report.contains("direct dispatches: 9"));
        assert!(report.contains("membership runs no-cell: 6 | invalid: 1"));
        assert!(report.contains("rung 0 claim_idle(previous_cpu)"));
    }

    #[test]
    fn ndjson_is_one_parseable_json_record() {
        let metrics = Metrics {
            select_calls: 7,
            direct_dispatches: 4,
            select_latency_max_ns: 123,
            cpus: BTreeMap::from([(
                2,
                CpuMetrics {
                    cpu: 2,
                    runtime_ns: 8_500,
                },
            )]),
            rungs: BTreeMap::from([(0, rung(0, "claim_idle", "previous_cpu", 7, 4, 3, 0))]),
            ..Default::default()
        };

        let encoded = metrics.to_ndjson().expect("metrics should serialize");
        let parsed: serde_json::Value =
            serde_json::from_str(encoded.trim_end()).expect("NDJSON record should parse");

        assert_eq!(encoded.lines().count(), 1);
        assert!(encoded.ends_with('\n'));
        assert_eq!(parsed["select_calls"], 7);
        assert_eq!(parsed["direct_dispatches"], 4);
        assert_eq!(parsed["select_latency_max_ns"], 123);
        assert_eq!(parsed["cpus"]["2"]["cpu"], 2);
        assert_eq!(parsed["cpus"]["2"]["runtime_ns"], 8_500);
        assert_eq!(parsed["rungs"]["0"]["operation"], "claim_idle");
    }

    #[test]
    fn ndjson_exposes_per_cell_cpu_runtime() {
        let metrics = Metrics {
            cells: BTreeMap::from([(
                7,
                CellMetrics {
                    id: 7,
                    index: 2,
                    runtime_ns: 10_000,
                    runtime_ns_by_cpu: BTreeMap::from([(1, 2_500), (9, 7_500)]),
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };

        let encoded = metrics.to_ndjson().expect("metrics should serialize");
        let parsed: serde_json::Value = serde_json::from_str(encoded.trim_end()).unwrap();

        assert_eq!(parsed["cells"]["7"]["runtime_ns_by_cpu"]["1"], 2_500);
        assert_eq!(parsed["cells"]["7"]["runtime_ns_by_cpu"]["9"], 7_500);
    }
}
