// SPDX-License-Identifier: GPL-2.0-only

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::bpf_intf;
use crate::mask_tables::ResolvedMaskTable;
use crate::policy::{self, CompiledPolicy};

/// Userspace policy state committed alongside the active BPF ladder slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimePolicy {
    pub source: String,
    pub compiled: CompiledPolicy,
    pub generation: u64,
    pub active_slot: u32,
}

/// Acknowledgment returned only after a replacement ladder is active.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PolicyUpdateResponse {
    pub generation: u64,
    pub rung_count: usize,
    pub mask_table_count: usize,
    pub summary: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PolicyValidationResponse {
    pub rung_count: usize,
    pub mask_table_count: usize,
    pub cell_count: usize,
    #[serde(default)]
    pub queue_policy: bool,
    pub summary: String,
}

impl PolicyValidationResponse {
    pub fn from_policy(policy: &CompiledPolicy) -> Self {
        let rung_count = policy.rungs.len();
        let mask_table_count = policy.mask_tables.len();
        let cell_count = policy.cells.len();
        let queue_policy = policy.queues.is_some();
        Self {
            rung_count,
            mask_table_count,
            cell_count,
            queue_policy,
            summary: format!(
                "{rung_count} {}, {mask_table_count} mask {}, {cell_count} {}",
                if rung_count == 1 { "rung" } else { "rungs" },
                if mask_table_count == 1 {
                    "table"
                } else {
                    "tables"
                },
                if cell_count == 1 { "cell" } else { "cells" },
            ),
        }
    }
}

/// Ordered inactive-slot operations with publication as the commit point.
pub trait PolicyBackend {
    fn wait_for_slot_quiescent(&mut self, slot: u32) -> Result<()>;
    fn write_ladder(&mut self, slot: u32, generation: u64, policy: &CompiledPolicy) -> Result<()>;
    fn write_mask_tables(&mut self, slot: u32, tables: &[ResolvedMaskTable]) -> Result<()>;
    fn write_queue_topology(&mut self, slot: u32, generation: u64) -> Result<()>;
    fn write_managed_membership(
        &mut self,
        slot: u32,
        generation: u64,
        policy: &CompiledPolicy,
    ) -> Result<()>;
    fn prepare_ladder(&mut self, slot: u32) -> Result<()>;
    fn clear_stats(&mut self, slot: u32) -> Result<()>;
    fn publish_ladder(&mut self, slot: u32) -> Result<()>;
}

impl RuntimePolicy {
    pub fn new(source: String, compiled: CompiledPolicy) -> Self {
        Self {
            source,
            compiled,
            generation: 1,
            active_slot: 0,
        }
    }

    pub fn advance_for_restart(&mut self) -> Result<()> {
        self.generation = self
            .generation
            .checked_add(1)
            .context("policy generation overflow")?;
        self.active_slot = 0;
        Ok(())
    }

    fn response(&self) -> PolicyUpdateResponse {
        let rung_count = self.compiled.rungs.len();
        let mask_table_count = self.compiled.mask_tables.len();
        PolicyUpdateResponse {
            generation: self.generation,
            rung_count,
            mask_table_count,
            summary: format!(
                "{rung_count} {}, {mask_table_count} mask {}",
                if rung_count == 1 { "rung" } else { "rungs" },
                if mask_table_count == 1 {
                    "table"
                } else {
                    "tables"
                }
            ),
        }
    }
}

pub fn replace_policy<B, R>(
    current: &mut RuntimePolicy,
    source: String,
    resolve_tables: R,
    backend: &mut B,
) -> Result<PolicyUpdateResponse>
where
    B: PolicyBackend,
    R: FnOnce(&CompiledPolicy) -> Result<Vec<ResolvedMaskTable>>,
{
    let compiled = policy::compile_policy(&source).context("compiling replacement policy")?;
    let tables = resolve_tables(&compiled).context("resolving replacement policy mask tables")?;
    activate_compiled_policy(current, source, compiled, &tables, backend)
}

pub fn activate_compiled_policy<B>(
    current: &mut RuntimePolicy,
    source: String,
    compiled: CompiledPolicy,
    tables: &[ResolvedMaskTable],
    backend: &mut B,
) -> Result<PolicyUpdateResponse>
where
    B: PolicyBackend,
{
    let generation = current
        .generation
        .checked_add(1)
        .context("policy generation overflow")?;
    let slot = inactive_slot(current.active_slot)?;
    let candidate = RuntimePolicy {
        source,
        compiled,
        generation,
        active_slot: slot,
    };
    let response = candidate.response();

    backend.wait_for_slot_quiescent(slot)?;
    backend.write_ladder(slot, generation, &candidate.compiled)?;
    backend.write_mask_tables(slot, tables)?;
    backend.write_queue_topology(slot, generation)?;
    backend.write_managed_membership(slot, generation, &candidate.compiled)?;
    backend.prepare_ladder(slot)?;
    backend.clear_stats(slot)?;
    backend.publish_ladder(slot)?;

    *current = candidate;
    Ok(response)
}

/// Reinstall the active policy into the inactive slot and publish its empty
/// statistics bank without changing the policy generation or scheduler state.
pub fn reset_stats<B>(
    current: &mut RuntimePolicy,
    tables: &[ResolvedMaskTable],
    backend: &mut B,
) -> Result<u32>
where
    B: PolicyBackend,
{
    let slot = inactive_slot(current.active_slot)?;
    backend.wait_for_slot_quiescent(slot)?;
    backend.write_ladder(slot, current.generation, &current.compiled)?;
    backend.write_mask_tables(slot, tables)?;
    backend.write_queue_topology(slot, current.generation)?;
    backend.write_managed_membership(slot, current.generation, &current.compiled)?;
    backend.prepare_ladder(slot)?;
    backend.clear_stats(slot)?;
    backend.publish_ladder(slot)?;
    current.active_slot = slot;
    Ok(slot)
}

pub fn inactive_slot(active: u32) -> Result<u32> {
    if active >= bpf_intf::SNAKE_LADDER_SLOTS {
        bail!("invalid active ladder slot {active}");
    }
    Ok(active ^ 1)
}

pub fn mask_data_index(slot: u32, table_id: u32, cpu: u32) -> Result<u32> {
    if slot >= bpf_intf::SNAKE_LADDER_SLOTS {
        bail!("invalid ladder slot {slot}");
    }
    if table_id >= bpf_intf::SNAKE_MAX_MASK_TABLES {
        bail!("invalid mask table {table_id}");
    }
    if cpu >= bpf_intf::SNAKE_MAX_CPUS {
        bail!("invalid CPU {cpu}");
    }

    Ok(
        slot * bpf_intf::SNAKE_MAX_MASK_TABLES * bpf_intf::SNAKE_MAX_CPUS
            + table_id * bpf_intf::SNAKE_MAX_CPUS
            + cpu,
    )
}

pub fn stat_index(slot: u32, stat: u32) -> Result<u32> {
    if slot >= bpf_intf::SNAKE_LADDER_SLOTS {
        bail!("invalid ladder slot {slot}");
    }
    if stat >= bpf_intf::snake_stat_SNAKE_NR_STATS {
        bail!("invalid statistic {stat}");
    }
    Ok(slot * bpf_intf::snake_stat_SNAKE_NR_STATS + stat)
}

pub fn callback_timing_index(slot: u32, callback: u32) -> Result<u32> {
    if slot >= bpf_intf::SNAKE_LADDER_SLOTS {
        bail!("invalid ladder slot {slot}");
    }
    if callback >= bpf_intf::snake_callback_SNAKE_NR_CALLBACKS {
        bail!("invalid callback {callback}");
    }
    Ok(slot * bpf_intf::snake_callback_SNAKE_NR_CALLBACKS + callback)
}

pub fn cell_stat_index(slot: u32, cell: u32, stat: u32) -> Result<u32> {
    if slot >= bpf_intf::SNAKE_LADDER_SLOTS {
        bail!("invalid ladder slot {slot}");
    }
    if cell >= bpf_intf::SNAKE_MAX_QUEUE_CELLS {
        bail!("invalid queue cell {cell}");
    }
    if stat >= bpf_intf::snake_cell_stat_SNAKE_NR_CELL_STATS {
        bail!("invalid cell statistic {stat}");
    }
    Ok((slot * bpf_intf::SNAKE_MAX_QUEUE_CELLS + cell)
        * bpf_intf::snake_cell_stat_SNAKE_NR_CELL_STATS
        + stat)
}

pub fn nonzero_reader_counts(raw: &[Vec<u8>]) -> Result<Vec<(usize, u32)>> {
    raw.iter()
        .enumerate()
        .filter_map(|(cpu, bytes)| {
            let decoded = <[u8; std::mem::size_of::<u32>()]>::try_from(bytes.as_slice())
                .map(u32::from_ne_bytes)
                .map_err(|_| {
                    anyhow::anyhow!(
                        "CPU {cpu} reader count has {} bytes, expected {}",
                        bytes.len(),
                        std::mem::size_of::<u32>()
                    )
                });
            match decoded {
                Ok(0) => None,
                Ok(count) => Some(Ok((cpu, count))),
                Err(error) => Some(Err(error)),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use anyhow::{bail, Result};

    use super::*;
    use crate::mask_tables::ResolvedMaskTable;
    use crate::policy::{self, CompiledPolicy};

    const INITIAL: &str = r#"
[[rung]]
operation = "claim_idle"
scope = "previous_cpu"
"#;

    const REPLACEMENT: &str = r#"
fallback = "any_allowed"

[[rung]]
operation = "pick_random_idle"
scope = "task_allowed"
"#;

    #[derive(Default)]
    struct RecordingBackend {
        fail_at: Option<&'static str>,
        steps: Vec<&'static str>,
        ladder_writes: Vec<(u32, u64)>,
    }

    impl RecordingBackend {
        fn record(&mut self, step: &'static str) -> Result<()> {
            self.steps.push(step);
            if self.fail_at == Some(step) {
                bail!("injected failure at {step}");
            }
            Ok(())
        }
    }

    impl PolicyBackend for RecordingBackend {
        fn wait_for_slot_quiescent(&mut self, _slot: u32) -> Result<()> {
            self.record("wait")
        }

        fn write_ladder(
            &mut self,
            slot: u32,
            generation: u64,
            _policy: &CompiledPolicy,
        ) -> Result<()> {
            self.ladder_writes.push((slot, generation));
            self.record("write_ladder")
        }

        fn write_mask_tables(&mut self, _slot: u32, _tables: &[ResolvedMaskTable]) -> Result<()> {
            self.record("write_masks")
        }

        fn write_queue_topology(&mut self, _slot: u32, _generation: u64) -> Result<()> {
            self.record("write_topology")
        }

        fn write_managed_membership(
            &mut self,
            _slot: u32,
            _generation: u64,
            _policy: &CompiledPolicy,
        ) -> Result<()> {
            self.record("write_membership")
        }

        fn prepare_ladder(&mut self, _slot: u32) -> Result<()> {
            self.record("prepare")
        }

        fn clear_stats(&mut self, _slot: u32) -> Result<()> {
            self.record("clear_stats")
        }

        fn publish_ladder(&mut self, _slot: u32) -> Result<()> {
            self.record("publish")
        }
    }

    fn initial_state() -> RuntimePolicy {
        RuntimePolicy::new(
            INITIAL.to_owned(),
            policy::compile_policy(INITIAL).expect("initial policy should compile"),
        )
    }

    #[test]
    fn replacement_stages_everything_before_publication() {
        let mut current = initial_state();
        let mut backend = RecordingBackend::default();

        let response = replace_policy(
            &mut current,
            REPLACEMENT.to_owned(),
            |_| Ok(Vec::new()),
            &mut backend,
        )
        .expect("replacement should activate");

        assert_eq!(
            backend.steps,
            [
                "wait",
                "write_ladder",
                "write_masks",
                "write_topology",
                "write_membership",
                "prepare",
                "clear_stats",
                "publish"
            ]
        );
        assert_eq!(current.generation, 2);
        assert_eq!(current.active_slot, 1);
        assert_eq!(current.source, REPLACEMENT);
        assert_eq!(response.generation, 2);
        assert_eq!(response.rung_count, 1);
        assert_eq!(response.mask_table_count, 0);
        assert_eq!(response.summary, "1 rung, 0 mask tables");
    }

    #[test]
    fn policy_validation_reports_whether_queue_topology_is_configured() {
        let placement = policy::compile_policy(INITIAL).unwrap();
        assert!(!PolicyValidationResponse::from_policy(&placement).queue_policy);

        let queued = policy::compile_policy(
            r#"
[queues]
layout = "cell"

[[rung]]
operation = "pick_idle"
scope = "task_allowed"
"#,
        )
        .unwrap();
        assert!(PolicyValidationResponse::from_policy(&queued).queue_policy);
    }

    #[test]
    fn every_prepublication_failure_preserves_active_state() {
        for fail_at in [
            "wait",
            "write_ladder",
            "write_masks",
            "write_topology",
            "write_membership",
            "prepare",
            "clear_stats",
            "publish",
        ] {
            let mut current = initial_state();
            let original = current.clone();
            let mut backend = RecordingBackend {
                fail_at: Some(fail_at),
                ..Default::default()
            };

            assert!(replace_policy(
                &mut current,
                REPLACEMENT.to_owned(),
                |_| Ok(Vec::new()),
                &mut backend,
            )
            .is_err());
            assert_eq!(current, original, "state changed after {fail_at} failure");
        }
    }

    #[test]
    fn stats_reset_reinstalls_the_same_generation_before_flipping_slots() {
        let mut current = initial_state();
        current.generation = 9;
        let original_source = current.source.clone();
        let original_policy = current.compiled.clone();
        let mut backend = RecordingBackend::default();

        let active_slot = reset_stats(&mut current, &[], &mut backend)
            .expect("statistics reset should publish a fresh slot");

        assert_eq!(
            backend.steps,
            [
                "wait",
                "write_ladder",
                "write_masks",
                "write_topology",
                "write_membership",
                "prepare",
                "clear_stats",
                "publish"
            ]
        );
        assert_eq!(backend.ladder_writes, [(1, 9)]);
        assert_eq!(active_slot, 1);
        assert_eq!(current.active_slot, 1);
        assert_eq!(current.generation, 9);
        assert_eq!(current.source, original_source);
        assert_eq!(current.compiled, original_policy);
    }

    #[test]
    fn stats_reset_failure_preserves_the_runtime_policy() {
        for fail_at in [
            "wait",
            "write_ladder",
            "write_masks",
            "write_topology",
            "write_membership",
            "prepare",
            "clear_stats",
            "publish",
        ] {
            let mut current = initial_state();
            let original = current.clone();
            let mut backend = RecordingBackend {
                fail_at: Some(fail_at),
                ..Default::default()
            };

            assert!(reset_stats(&mut current, &[], &mut backend).is_err());
            assert_eq!(current, original, "state changed after {fail_at} failure");
        }
    }

    #[test]
    fn compile_and_topology_failures_do_not_touch_the_backend() {
        let mut current = initial_state();
        let original = current.clone();
        let mut backend = RecordingBackend::default();

        assert!(replace_policy(
            &mut current,
            "not valid toml".to_owned(),
            |_| Ok(Vec::new()),
            &mut backend,
        )
        .is_err());
        assert_eq!(current, original);
        assert!(backend.steps.is_empty());

        assert!(replace_policy(
            &mut current,
            REPLACEMENT.to_owned(),
            |_| bail!("topology unavailable"),
            &mut backend,
        )
        .is_err());
        assert_eq!(current, original);
        assert!(backend.steps.is_empty());
    }

    #[test]
    fn reader_diagnostics_report_only_nonzero_cpus() {
        let raw = vec![
            0_u32.to_ne_bytes().to_vec(),
            2_u32.to_ne_bytes().to_vec(),
            0_u32.to_ne_bytes().to_vec(),
            7_u32.to_ne_bytes().to_vec(),
        ];

        assert_eq!(nonzero_reader_counts(&raw).unwrap(), [(1, 2), (3, 7)]);
    }
}
