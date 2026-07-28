// SPDX-License-Identifier: GPL-2.0-only

use std::collections::BTreeMap;

use scx_snake::fairness::FairnessMode;
use serde::Serialize;

use crate::bpf_intf;
use crate::mask_tables::ResolvedMaskTable;
use crate::policy::{
    CompiledPolicy, CompiledRung, Fallback, InputSource, MaskTableSource, Opcode,
    QueueDispatchSource, QueueEnqueueTarget, QueueLayout, QueueMaskKind, QueuePolicy,
    RUNG_FLAG_INTERSECT_TASK_ALLOWED, RUNG_FLAG_PICK_IDLE_CORE, RUNG_FLAG_PICK_RANDOM,
};
use crate::queue_topology::QueueTopology;
use crate::stats::{Metrics, RungMetrics};

#[derive(Clone, Debug)]
pub struct SlotPolicy {
    slot: u32,
    generation: u64,
    source: String,
    compiled: CompiledPolicy,
    resolved_tables: Vec<ResolvedMaskTable>,
    activated_at_ms: u64,
    deactivated_at_ms: Option<u64>,
    frozen_metrics: Option<Metrics>,
}

impl SlotPolicy {
    pub fn new(
        slot: u32,
        generation: u64,
        source: String,
        compiled: CompiledPolicy,
        resolved_tables: Vec<ResolvedMaskTable>,
        activated_at_ms: u64,
    ) -> Self {
        assert!(slot < 2, "Snake has exactly two ladder slots");
        Self {
            slot,
            generation,
            source,
            compiled,
            resolved_tables,
            activated_at_ms,
            deactivated_at_ms: None,
            frozen_metrics: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotState {
    Active,
    Inactive,
    Empty,
}

#[derive(Clone, Debug, Serialize)]
pub struct ChoiceView {
    pub value: String,
    pub label: String,
    pub description: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct FieldReferenceView {
    pub selected: ChoiceView,
    pub valid: Vec<ChoiceView>,
    pub other: Vec<ChoiceView>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RungInspectionView {
    pub index: u32,
    pub operation: String,
    pub scope: String,
    pub opcode: FieldReferenceView,
    pub input: FieldReferenceView,
    pub flags: FieldReferenceView,
    pub data: FieldReferenceView,
    pub metrics: Option<RungMetrics>,
}

#[derive(Clone, Debug, Serialize)]
pub struct MaskTableInspectionView {
    pub id: u32,
    pub name: String,
    pub source: String,
    pub entry_count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct PolicyInspectionView {
    pub source: String,
    pub fallback: FieldReferenceView,
    pub rungs: Vec<RungInspectionView>,
    pub queues: Option<QueuePolicyInspectionView>,
    pub mask_tables: Vec<MaskTableInspectionView>,
}

#[derive(Clone, Debug, Serialize)]
pub struct QueueRungInspectionView {
    pub index: u32,
    pub operation: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct QueuePolicyInspectionView {
    pub layout: String,
    pub enqueue: Vec<QueueRungInspectionView>,
    pub dispatch: Vec<QueueRungInspectionView>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SlotInspectionView {
    pub slot: u32,
    pub state: SlotState,
    pub generation: Option<u64>,
    pub activated_at_ms: Option<u64>,
    pub deactivated_at_ms: Option<u64>,
    pub policy: Option<PolicyInspectionView>,
    pub metrics: Option<Metrics>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CellInspectionView {
    pub id: u32,
    pub cpus: Vec<u32>,
    pub task_count: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct TaskMappingInspectionView {
    pub tid: i32,
    pub tgid: i32,
    pub name: String,
    pub state: String,
    pub current_cpu: Option<u32>,
    pub cell_id: u32,
    pub cell_defined: bool,
    pub allowed_cpus: String,
    pub cgroup: String,
    pub needs_rehome: bool,
    pub source: String,
    pub membership: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct InspectionView {
    pub schema_version: u32,
    pub active_slot: u32,
    pub callback_timing_sample_rate: u32,
    pub fairness: FairnessInspectionView,
    pub queue_topology: Option<QueueTopologyInspectionView>,
    pub slots: Vec<SlotInspectionView>,
    pub cells: Vec<CellInspectionView>,
    pub task_mappings: Vec<TaskMappingInspectionView>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FairnessInspectionView {
    pub mode_name: String,
    pub clock_model: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct QueueCellInspectionView {
    pub external_id: u32,
    pub index: u32,
    pub synthetic: bool,
    pub cpu_weight: u32,
    pub clock_index: u32,
    pub primary_cpus: Vec<u32>,
    pub borrowable_cpus: Vec<u32>,
    pub normal_queue_indices: Vec<u32>,
}

#[derive(Clone, Debug, Serialize)]
pub struct NormalQueueInspectionView {
    pub index: u32,
    pub dsq_id: u64,
    pub cell_index: u32,
    pub cell_id: u32,
    pub clock_index: u32,
    pub llc_id: Option<u32>,
    pub consumer_cpus: Vec<u32>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CpuQueueRouteInspectionView {
    pub cpu: u32,
    pub owner_cell_id: u32,
    pub owner_cell_index: u32,
    pub llc_id: u32,
    pub normal_queue_index: u32,
    pub normal_dsq_id: u64,
    pub affinity_dsq_id: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct QueueTopologyInspectionView {
    pub layout: String,
    pub affinity_queue_count: usize,
    pub cells: Vec<QueueCellInspectionView>,
    pub normal_queues: Vec<NormalQueueInspectionView>,
    pub cpu_routes: Vec<CpuQueueRouteInspectionView>,
}

pub struct Inspector {
    active_slot: u32,
    callback_timing_sample_rate: u32,
    fairness: FairnessInspectionView,
    queue_topology: Option<QueueTopologyInspectionView>,
    slots: [Option<SlotPolicy>; 2],
    assignments: BTreeMap<i32, u32>,
}

impl Inspector {
    pub fn new(
        active: SlotPolicy,
        fairness: FairnessMode,
        queue_topology: Option<QueueTopology>,
    ) -> Self {
        let active_slot = active.slot;
        let mut slots = std::array::from_fn(|_| None);
        slots[active_slot as usize] = Some(active);
        Self {
            active_slot,
            callback_timing_sample_rate: 64,
            fairness: fairness_view(fairness, queue_topology.is_some()),
            queue_topology: queue_topology.as_ref().map(queue_topology_view),
            slots,
            assignments: BTreeMap::new(),
        }
    }

    pub fn with_callback_timing_sample_rate(mut self, sample_rate: u32) -> Self {
        self.callback_timing_sample_rate = sample_rate;
        self
    }

    pub fn activate(&mut self, next: SlotPolicy, frozen_metrics: Metrics, at_ms: u64) {
        if let Some(previous) = self.slots[self.active_slot as usize].as_mut() {
            previous.deactivated_at_ms = Some(at_ms);
            previous.frozen_metrics = Some(frozen_metrics);
        }
        self.active_slot = next.slot;
        self.slots[self.active_slot as usize] = Some(next);
    }

    pub fn set_assignment(&mut self, tid: i32, cell_id: u32) {
        self.assignments.insert(tid, cell_id);
    }

    pub fn clear_assignment(&mut self, tid: i32) {
        self.assignments.remove(&tid);
    }

    pub fn assignments(&self) -> impl Iterator<Item = (i32, u32)> + '_ {
        self.assignments
            .iter()
            .map(|(&tid, &cell_id)| (tid, cell_id))
    }

    pub fn snapshot(
        &self,
        active_metrics: Metrics,
        mut task_mappings: Vec<TaskMappingInspectionView>,
    ) -> InspectionView {
        task_mappings.sort_by_key(|mapping| (mapping.cell_id, mapping.tgid, mapping.tid));
        let active_cells = self.slots[self.active_slot as usize]
            .as_ref()
            .map(|slot| &slot.compiled.cells);
        let mut cells = active_cells
            .into_iter()
            .flat_map(|cells| cells.iter())
            .map(|(&id, cpus)| CellInspectionView {
                id,
                cpus: cpus.iter().copied().collect(),
                task_count: task_mappings
                    .iter()
                    .filter(|mapping| mapping.cell_id == id)
                    .count(),
            })
            .collect::<Vec<_>>();
        if let Some(cell0) = self
            .queue_topology
            .as_ref()
            .and_then(|topology| topology.cells.iter().find(|cell| cell.external_id == 0))
        {
            cells.push(CellInspectionView {
                id: 0,
                cpus: cell0.primary_cpus.clone(),
                task_count: task_mappings
                    .iter()
                    .filter(|mapping| mapping.cell_id == 0)
                    .count(),
            });
            cells.sort_by_key(|cell| cell.id);
        }
        let slots = (0..2)
            .map(|slot| match &self.slots[slot] {
                Some(policy) => {
                    let state = if policy.slot == self.active_slot {
                        SlotState::Active
                    } else {
                        SlotState::Inactive
                    };
                    let metrics = if state == SlotState::Active {
                        Some(active_metrics.clone())
                    } else {
                        policy.frozen_metrics.clone()
                    };
                    slot_view(policy, state, metrics)
                }
                None => SlotInspectionView {
                    slot: slot as u32,
                    state: SlotState::Empty,
                    generation: None,
                    activated_at_ms: None,
                    deactivated_at_ms: None,
                    policy: None,
                    metrics: None,
                },
            })
            .collect();

        InspectionView {
            schema_version: 1,
            active_slot: self.active_slot,
            callback_timing_sample_rate: self.callback_timing_sample_rate,
            fairness: self.fairness.clone(),
            queue_topology: self.queue_topology.clone(),
            slots,
            cells,
            task_mappings,
        }
    }
}

fn fairness_view(mode: FairnessMode, has_queue_topology: bool) -> FairnessInspectionView {
    let clock_model = match (mode, has_queue_topology) {
        (FairnessMode::Fifo, _) => "no virtual-time clock",
        (FairnessMode::Eevdf, _) => "one global aggregate virtual-time clock",
        (FairnessMode::Vtime, true) => "one clock per cell shared by normal and affinity queues",
        (FairnessMode::Vtime, false) => "one shared global VTIME clock",
    };
    FairnessInspectionView {
        mode_name: mode.as_str().into(),
        clock_model: clock_model.into(),
    }
}

fn queue_topology_view(topology: &QueueTopology) -> QueueTopologyInspectionView {
    let cell_id_by_index = topology
        .cells
        .iter()
        .map(|cell| (cell.index, cell.external_id))
        .collect::<BTreeMap<_, _>>();
    QueueTopologyInspectionView {
        layout: match topology.layout {
            QueueLayout::Cell => "cell",
            QueueLayout::CellLlc => "cell_llc",
        }
        .into(),
        affinity_queue_count: topology.cpu_queues.len(),
        cells: topology
            .cells
            .iter()
            .map(|cell| QueueCellInspectionView {
                external_id: cell.external_id,
                index: cell.index,
                synthetic: cell.external_id == 0,
                cpu_weight: cell.cpu_weight,
                clock_index: cell.index,
                primary_cpus: cell.primary.iter().copied().collect(),
                borrowable_cpus: cell.borrowable.iter().copied().collect(),
                normal_queue_indices: cell.normal_queues.clone(),
            })
            .collect(),
        normal_queues: topology
            .normal_queues
            .iter()
            .map(|queue| NormalQueueInspectionView {
                index: queue.index,
                dsq_id: u64::from(bpf_intf::SNAKE_NORMAL_DSQ_BASE) + u64::from(queue.index),
                cell_index: queue.cell_index,
                cell_id: cell_id_by_index[&queue.cell_index],
                clock_index: queue.clock_index,
                llc_id: queue.llc_id,
                consumer_cpus: queue.consumers.iter().copied().collect(),
            })
            .collect(),
        cpu_routes: topology
            .cpu_queues
            .values()
            .map(|route| CpuQueueRouteInspectionView {
                cpu: route.cpu,
                owner_cell_id: cell_id_by_index[&route.owner_cell_index],
                owner_cell_index: route.owner_cell_index,
                llc_id: route.llc_id,
                normal_queue_index: route.normal_queue_index,
                normal_dsq_id: u64::from(bpf_intf::SNAKE_NORMAL_DSQ_BASE)
                    + u64::from(route.normal_queue_index),
                affinity_dsq_id: u64::from(bpf_intf::SNAKE_AFFINITY_DSQ_BASE)
                    + u64::from(route.cpu),
            })
            .collect(),
    }
}

fn slot_view(
    policy: &SlotPolicy,
    state: SlotState,
    metrics: Option<Metrics>,
) -> SlotInspectionView {
    let rung_metrics = metrics
        .as_ref()
        .map(|metrics| &metrics.rungs)
        .cloned()
        .unwrap_or_default();
    let rungs = policy
        .compiled
        .rungs
        .iter()
        .enumerate()
        .map(|(index, rung)| {
            rung_view(
                &policy.compiled,
                index,
                rung,
                rung_metrics.get(&(index as u32)),
            )
        })
        .collect();
    let mask_tables = policy
        .compiled
        .mask_tables
        .iter()
        .map(|table| MaskTableInspectionView {
            id: table.id,
            name: table.name.clone(),
            source: mask_table_source_name(table.source).into(),
            entry_count: policy
                .resolved_tables
                .iter()
                .find(|resolved| resolved.id == table.id)
                .map_or(0, |resolved| resolved.entries.len()),
        })
        .collect();

    SlotInspectionView {
        slot: policy.slot,
        state,
        generation: Some(policy.generation),
        activated_at_ms: Some(policy.activated_at_ms),
        deactivated_at_ms: policy.deactivated_at_ms,
        policy: Some(PolicyInspectionView {
            source: policy.source.clone(),
            fallback: fallback_reference(policy.compiled.fallback),
            rungs,
            queues: policy.compiled.queues.as_ref().map(queue_policy_view),
            mask_tables,
        }),
        metrics,
    }
}

fn queue_policy_view(queues: &QueuePolicy) -> QueuePolicyInspectionView {
    QueuePolicyInspectionView {
        layout: match queues.layout {
            QueueLayout::Cell => "cell",
            QueueLayout::CellLlc => "cell_llc",
        }
        .into(),
        enqueue: queues
            .enqueue
            .iter()
            .enumerate()
            .map(|(index, target)| QueueRungInspectionView {
                index: index as u32,
                operation: match target {
                    QueueEnqueueTarget::Cell => "cell",
                    QueueEnqueueTarget::Affinity => "affinity",
                }
                .into(),
            })
            .collect(),
        dispatch: queues
            .dispatch
            .iter()
            .enumerate()
            .map(|(index, source)| QueueRungInspectionView {
                index: index as u32,
                operation: match source {
                    QueueDispatchSource::Cell => "cell",
                    QueueDispatchSource::Affinity => "affinity",
                    QueueDispatchSource::MinVtime => "min_vtime(cell,affinity)",
                }
                .into(),
            })
            .collect(),
    }
}

fn rung_view(
    policy: &CompiledPolicy,
    index: usize,
    rung: &CompiledRung,
    metrics: Option<&RungMetrics>,
) -> RungInspectionView {
    RungInspectionView {
        index: index as u32,
        operation: operation_name(rung).into(),
        scope: scope_name(policy, rung),
        opcode: opcode_reference(policy, rung),
        input: input_reference(policy, rung),
        flags: flags_reference(policy, rung),
        data: data_reference(policy, rung),
        metrics: metrics.cloned(),
    }
}

fn choice(
    value: impl Into<String>,
    label: impl Into<String>,
    description: impl Into<String>,
) -> ChoiceView {
    ChoiceView {
        value: value.into(),
        label: label.into(),
        description: description.into(),
    }
}

fn split_choices<T: Copy>(
    selected: T,
    candidates: &[(T, &'static str, &'static str)],
    mut is_valid: impl FnMut(T) -> bool,
    value: impl Fn(T) -> String,
) -> FieldReferenceView
where
    T: PartialEq,
{
    let build = |candidate: &(T, &'static str, &'static str)| {
        choice(value(candidate.0), candidate.1, candidate.2)
    };
    let selected_choice = candidates
        .iter()
        .find(|candidate| candidate.0 == selected)
        .map(build)
        .unwrap_or_else(|| choice(value(selected), value(selected), "Unknown ABI value"));
    let (valid, other) = candidates
        .iter()
        .partition::<Vec<_>, _>(|candidate| is_valid(candidate.0));
    FieldReferenceView {
        selected: selected_choice,
        valid: valid.into_iter().map(build).collect(),
        other: other.into_iter().map(build).collect(),
    }
}

fn opcode_reference(policy: &CompiledPolicy, rung: &CompiledRung) -> FieldReferenceView {
    const OPCODES: &[(Opcode, &str, &str)] = &[
        (
            Opcode::ClaimIdle,
            "Claim idle CPU",
            "Claim the previous CPU when it is idle.",
        ),
        (
            Opcode::PickIdle,
            "Pick idle CPU",
            "Pick an idle CPU from the supplied task mask.",
        ),
        (
            Opcode::PickIdleMaskTable,
            "Pick from mask table",
            "Pick an idle CPU from a resolved mask-table entry.",
        ),
        (
            Opcode::PickRandomIdle,
            "Pick random idle CPU",
            "Choose uniformly from eligible idle CPUs.",
        ),
        (
            Opcode::KernelDefault,
            "Kernel default",
            "Delegate CPU selection to the kernel default policy.",
        ),
        (
            Opcode::SyncWakeAffine,
            "Synchronous wake affinity",
            "Prefer the waking CPU, LLC, or NUMA node for a synchronous wakeup.",
        ),
        (
            Opcode::PickIdleQueueMask,
            "Pick from queue cell",
            "Pick an idle CPU from the task cell's resolved primary or borrowable mask.",
        ),
    ];
    split_choices(
        rung.opcode,
        OPCODES,
        |opcode| valid_rung(CompiledRung { opcode, ..*rung }, policy.mask_tables.len()),
        |opcode| opcode_name(opcode).into(),
    )
}

fn input_reference(policy: &CompiledPolicy, rung: &CompiledRung) -> FieldReferenceView {
    const INPUTS: &[(InputSource, &str, &str)] = &[
        (
            InputSource::CpuPrev,
            "Previous CPU",
            "Use the task's previous CPU as the lookup key.",
        ),
        (
            InputSource::MaskTaskAllowed,
            "Task allowed mask",
            "Use the task's current CPU affinity mask.",
        ),
        (
            InputSource::TaskCell,
            "Task cell",
            "Use the task's live cell annotation as the lookup key.",
        ),
        (
            InputSource::QueueCell,
            "Resolved queue cell",
            "Use the dense queue cell resolved from the task annotation.",
        ),
    ];
    split_choices(
        rung.input,
        INPUTS,
        |input| valid_rung(CompiledRung { input, ..*rung }, policy.mask_tables.len()),
        |input| input_name(input).into(),
    )
}

fn flags_reference(policy: &CompiledPolicy, rung: &CompiledRung) -> FieldReferenceView {
    const FLAGS: &[(u32, &str, &str)] = &[
        (
            0,
            "No flags",
            "Apply the opcode without optional refinements.",
        ),
        (
            RUNG_FLAG_INTERSECT_TASK_ALLOWED,
            "Intersect task affinity",
            "Intersect the selected table mask with the task's allowed CPUs.",
        ),
        (
            RUNG_FLAG_PICK_IDLE_CORE,
            "Whole idle core",
            "Only select a CPU when all of its SMT siblings are idle.",
        ),
        (
            RUNG_FLAG_INTERSECT_TASK_ALLOWED | RUNG_FLAG_PICK_IDLE_CORE,
            "Affinity + whole core",
            "Apply both task-affinity intersection and whole-core selection.",
        ),
        (
            RUNG_FLAG_PICK_RANDOM,
            "Random idle CPU",
            "Choose uniformly from the resolved queue-cell mask.",
        ),
        (
            RUNG_FLAG_PICK_RANDOM | RUNG_FLAG_PICK_IDLE_CORE,
            "Random whole idle core",
            "Choose uniformly from wholly idle cores in the resolved queue-cell mask.",
        ),
    ];
    split_choices(
        rung.flags,
        FLAGS,
        |flags| valid_rung(CompiledRung { flags, ..*rung }, policy.mask_tables.len()),
        |flags| format!("0x{flags:08x}"),
    )
}

fn data_reference(policy: &CompiledPolicy, rung: &CompiledRung) -> FieldReferenceView {
    #[derive(Clone)]
    enum DataChoice {
        Zero,
        Table(u32, String),
        Pair(u32, String, u32, String),
        QueueMask(QueueMaskKind),
    }

    impl DataChoice {
        fn value(&self) -> String {
            match self {
                Self::Zero => "0".into(),
                Self::Table(id, _) => format!("table:{id}"),
                Self::Pair(llc, _, node, _) => format!("tables:{llc},{node}"),
                Self::QueueMask(kind) => format!("queue_mask:{}", *kind as u64),
            }
        }

        fn view(&self) -> ChoiceView {
            match self {
                Self::Zero => choice(
                    "0",
                    "No data",
                    "This opcode does not consume the data field.",
                ),
                Self::Table(id, name) => choice(
                    format!("table:{id}"),
                    format!("Table {id}: {name}"),
                    "Use this installed mask table as the rung operand.",
                ),
                Self::Pair(llc, llc_name, node, node_name) => choice(
                    format!("tables:{llc},{node}"),
                    format!("LLC {llc_name} + node {node_name}"),
                    "Pack the LLC table in the low word and NUMA-node table in the high word.",
                ),
                Self::QueueMask(QueueMaskKind::Primary) => choice(
                    "queue_mask:1",
                    "Cell primary CPUs",
                    "Use CPUs exclusively allocated to the task cell.",
                ),
                Self::QueueMask(QueueMaskKind::Borrowable) => choice(
                    "queue_mask:2",
                    "Cell borrowable CPUs",
                    "Use claimed CPUs allocated to another cell.",
                ),
            }
        }
    }

    let mut candidates = vec![DataChoice::Zero];
    candidates.push(DataChoice::QueueMask(QueueMaskKind::Primary));
    candidates.push(DataChoice::QueueMask(QueueMaskKind::Borrowable));
    for table in &policy.mask_tables {
        candidates.push(DataChoice::Table(table.id, table.name.clone()));
    }
    for llc in &policy.mask_tables {
        for node in &policy.mask_tables {
            candidates.push(DataChoice::Pair(
                llc.id,
                llc.name.clone(),
                node.id,
                node.name.clone(),
            ));
        }
    }
    let selected_value = match rung.opcode {
        Opcode::PickIdleMaskTable => format!("table:{}", rung.data as u32),
        Opcode::PickRandomIdle if rung.input != InputSource::MaskTaskAllowed => {
            format!("table:{}", rung.data as u32)
        }
        Opcode::SyncWakeAffine => {
            format!("tables:{},{}", rung.data as u32, (rung.data >> 32) as u32)
        }
        Opcode::PickIdleQueueMask => format!("queue_mask:{}", rung.data),
        _ => "0".into(),
    };
    let selected = candidates
        .iter()
        .find(|candidate| candidate.value() == selected_value)
        .map(DataChoice::view)
        .unwrap_or_else(|| {
            choice(
                selected_value.clone(),
                selected_value,
                "Unknown data operand",
            )
        });
    let data_kind = match rung.opcode {
        Opcode::PickIdleMaskTable => 1,
        Opcode::PickRandomIdle if rung.input != InputSource::MaskTaskAllowed => 1,
        Opcode::SyncWakeAffine => 2,
        Opcode::PickIdleQueueMask => 3,
        _ => 0,
    };
    let (valid, other): (Vec<_>, Vec<_>) = candidates.into_iter().partition(|candidate| {
        matches!(
            (data_kind, candidate),
            (0, DataChoice::Zero)
                | (1, DataChoice::Table(_, _))
                | (2, DataChoice::Pair(_, _, _, _))
                | (3, DataChoice::QueueMask(_))
        )
    });
    FieldReferenceView {
        selected,
        valid: valid.iter().map(DataChoice::view).collect(),
        other: other.iter().map(DataChoice::view).collect(),
    }
}

fn fallback_reference(selected: Fallback) -> FieldReferenceView {
    const FALLBACKS: &[(Fallback, &str, &str)] = &[
        (
            Fallback::PreviousCpu,
            "Previous CPU",
            "Keep the task on its previous CPU when every rung misses.",
        ),
        (
            Fallback::AnyAllowed,
            "Any allowed CPU",
            "Let the kernel select any CPU permitted by task affinity.",
        ),
    ];
    split_choices(
        selected,
        FALLBACKS,
        |_| true,
        |fallback| fallback_name(fallback).into(),
    )
}

fn valid_rung(rung: CompiledRung, nr_mask_tables: usize) -> bool {
    let table = rung.data < nr_mask_tables as u64;
    let pair = (rung.data as u32 as usize) < nr_mask_tables
        && ((rung.data >> 32) as u32 as usize) < nr_mask_tables;
    let queue_flags = rung.flags == 0
        || rung.flags == RUNG_FLAG_PICK_IDLE_CORE
        || rung.flags == RUNG_FLAG_PICK_RANDOM
        || rung.flags == RUNG_FLAG_PICK_RANDOM | RUNG_FLAG_PICK_IDLE_CORE;
    (rung.opcode == Opcode::ClaimIdle
        && rung.flags == 0
        && rung.input == InputSource::CpuPrev
        && rung.data == 0)
        || (rung.opcode == Opcode::PickIdle
            && matches!(rung.flags, 0 | RUNG_FLAG_PICK_IDLE_CORE)
            && rung.input == InputSource::MaskTaskAllowed
            && rung.data == 0)
        || (rung.opcode == Opcode::PickRandomIdle
            && ((matches!(rung.flags, 0 | RUNG_FLAG_PICK_IDLE_CORE)
                && rung.input == InputSource::MaskTaskAllowed
                && rung.data == 0)
                || ((rung.flags == RUNG_FLAG_INTERSECT_TASK_ALLOWED
                    || rung.flags == RUNG_FLAG_INTERSECT_TASK_ALLOWED | RUNG_FLAG_PICK_IDLE_CORE)
                    && matches!(rung.input, InputSource::CpuPrev | InputSource::TaskCell)
                    && table)))
        || (rung.opcode == Opcode::KernelDefault
            && rung.flags == 0
            && rung.input == InputSource::MaskTaskAllowed
            && rung.data == 0)
        || (rung.opcode == Opcode::SyncWakeAffine
            && rung.flags == 0
            && rung.input == InputSource::MaskTaskAllowed
            && pair)
        || (rung.opcode == Opcode::PickIdleMaskTable
            && matches!(rung.input, InputSource::CpuPrev | InputSource::TaskCell)
            && (rung.flags == RUNG_FLAG_INTERSECT_TASK_ALLOWED
                || rung.flags == RUNG_FLAG_INTERSECT_TASK_ALLOWED | RUNG_FLAG_PICK_IDLE_CORE)
            && table)
        || (rung.opcode == Opcode::PickIdleQueueMask
            && rung.input == InputSource::QueueCell
            && queue_flags
            && matches!(
                rung.data,
                value if value == QueueMaskKind::Primary as u64
                    || value == QueueMaskKind::Borrowable as u64
            ))
}

fn operation_name(rung: &CompiledRung) -> &'static str {
    if rung.flags & RUNG_FLAG_PICK_RANDOM != 0 {
        return if rung.flags & RUNG_FLAG_PICK_IDLE_CORE != 0 {
            "pick_random_idle_core"
        } else {
            "pick_random_idle"
        };
    }
    if rung.flags & RUNG_FLAG_PICK_IDLE_CORE != 0 {
        return if rung.opcode == Opcode::PickRandomIdle {
            "pick_random_idle_core"
        } else {
            "pick_idle_core"
        };
    }
    match rung.opcode {
        Opcode::ClaimIdle => "claim_idle",
        Opcode::PickIdle | Opcode::PickIdleMaskTable | Opcode::PickIdleQueueMask => "pick_idle",
        Opcode::PickRandomIdle => "pick_random_idle",
        Opcode::KernelDefault => "kernel_default",
        Opcode::SyncWakeAffine => "sync_wake_affine",
    }
}

fn scope_name(policy: &CompiledPolicy, rung: &CompiledRung) -> String {
    match (rung.opcode, rung.input) {
        (Opcode::PickIdleMaskTable | Opcode::PickRandomIdle, InputSource::TaskCell) => {
            "task_cell".into()
        }
        (Opcode::PickIdleMaskTable | Opcode::PickRandomIdle, InputSource::CpuPrev) => policy
            .mask_tables
            .iter()
            .find(|table| u64::from(table.id) == rung.data)
            .map(|table| table.name.clone())
            .unwrap_or_else(|| format!("mask_table_{}", rung.data)),
        (Opcode::PickIdleQueueMask, InputSource::QueueCell)
            if rung.data == QueueMaskKind::Primary as u64 =>
        {
            "task_cell".into()
        }
        (Opcode::PickIdleQueueMask, InputSource::QueueCell)
            if rung.data == QueueMaskKind::Borrowable as u64 =>
        {
            "task_cell_borrowable".into()
        }
        (_, InputSource::CpuPrev) => "previous_cpu".into(),
        (_, InputSource::MaskTaskAllowed) => "task_allowed".into(),
        (_, InputSource::TaskCell) => "task_cell".into(),
        (_, InputSource::QueueCell) => "queue_cell".into(),
    }
}

fn opcode_name(opcode: Opcode) -> &'static str {
    match opcode {
        Opcode::ClaimIdle => "claim_idle",
        Opcode::PickIdle => "pick_idle",
        Opcode::PickIdleMaskTable => "pick_idle_mask_table",
        Opcode::PickRandomIdle => "pick_random_idle",
        Opcode::KernelDefault => "kernel_default",
        Opcode::SyncWakeAffine => "sync_wake_affine",
        Opcode::PickIdleQueueMask => "pick_idle_queue_mask",
    }
}

fn input_name(input: InputSource) -> &'static str {
    match input {
        InputSource::CpuPrev => "cpu_prev",
        InputSource::MaskTaskAllowed => "mask_task_allowed",
        InputSource::TaskCell => "task_cell",
        InputSource::QueueCell => "queue_cell",
    }
}

fn fallback_name(fallback: Fallback) -> &'static str {
    match fallback {
        Fallback::PreviousCpu => "previous_cpu",
        Fallback::AnyAllowed => "any_allowed",
    }
}

fn mask_table_source_name(source: MaskTableSource) -> &'static str {
    match source {
        MaskTableSource::PreviousLlcByCpu => "previous_llc_by_cpu",
        MaskTableSource::PreviousNodeByCpu => "previous_node_by_cpu",
        MaskTableSource::SplitLlcByCore { .. } => "split_llc_by_core",
        MaskTableSource::TaskCellById => "task_cell_by_id",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::policy;
    use crate::queue_topology;
    use crate::stats::{Metrics, RungMetrics};
    use scx_snake::fairness::FairnessMode;

    const FIRST_POLICY: &str = r#"
[[rung]]
operation = "claim_idle"
scope = "previous_cpu"
"#;

    const SECOND_POLICY: &str = r#"
fallback = "any_allowed"

[[cell]]
id = 7
cpus = "0-1"

[[rung]]
operation = "pick_idle"
scope = "task_cell"

[[rung]]
operation = "pick_idle"
scope = "task_allowed"
"#;

    const QUEUE_BORROW_POLICY: &str = r#"
[queues]
layout = "cell"

[[rung]]
operation = "pick_random_idle_core"
scope = "task_cell_borrowable"
"#;

    fn slot(slot: u32, generation: u64, source: &str, activated_at_ms: u64) -> SlotPolicy {
        SlotPolicy::new(
            slot,
            generation,
            source.into(),
            policy::compile_policy(source).expect("policy should compile"),
            Vec::new(),
            activated_at_ms,
        )
    }

    fn metrics(generation: u64, attempts: u64) -> Metrics {
        Metrics {
            policy_generation: generation,
            rungs: BTreeMap::from([(
                0,
                RungMetrics {
                    index: 0,
                    operation: "claim_idle".into(),
                    scope: "previous_cpu".into(),
                    attempts,
                    hits: attempts.saturating_sub(1),
                    misses: 1,
                    errors: 0,
                },
            )]),
            ..Default::default()
        }
    }

    #[test]
    fn activation_preserves_the_previous_slot_and_its_frozen_metrics() {
        let mut inspector =
            Inspector::new(slot(0, 1, FIRST_POLICY, 1_000), FairnessMode::Fifo, None)
                .with_callback_timing_sample_rate(128);
        inspector.activate(slot(1, 2, SECOND_POLICY, 2_000), metrics(1, 30), 2_000);

        let view = inspector.snapshot(metrics(2, 8), Vec::new());

        assert_eq!(view.schema_version, 1);
        assert_eq!(view.active_slot, 1);
        assert_eq!(view.callback_timing_sample_rate, 128);
        assert_eq!(view.slots.len(), 2);
        assert_eq!(view.slots[0].state, SlotState::Inactive);
        assert_eq!(view.slots[0].generation, Some(1));
        assert_eq!(view.slots[0].deactivated_at_ms, Some(2_000));
        assert_eq!(
            view.slots[0].metrics.as_ref().unwrap().rungs[&0].attempts,
            30
        );
        assert_eq!(view.slots[1].state, SlotState::Active);
        assert_eq!(view.slots[1].generation, Some(2));
        assert_eq!(
            view.slots[1].metrics.as_ref().unwrap().rungs[&0].attempts,
            8
        );
    }

    #[test]
    fn rung_fields_separate_context_valid_choices_from_other_abi_choices() {
        let inspector = Inspector::new(slot(0, 2, SECOND_POLICY, 1_000), FairnessMode::Fifo, None);

        let view = inspector.snapshot(metrics(2, 8), Vec::new());
        let policy = view.slots[0].policy.as_ref().unwrap();
        let task_allowed = &policy.rungs[1];

        assert_eq!(task_allowed.opcode.selected.value, "pick_idle");
        assert!(task_allowed
            .opcode
            .valid
            .iter()
            .any(|choice| choice.value == "pick_random_idle"));
        assert!(task_allowed
            .opcode
            .other
            .iter()
            .any(|choice| choice.value == "claim_idle"));
        assert_eq!(task_allowed.data.selected.value, "0");
        assert!(task_allowed
            .data
            .valid
            .iter()
            .any(|choice| choice.value == "0"));
        assert!(task_allowed
            .data
            .other
            .iter()
            .any(|choice| choice.value == "table:0"));
    }

    #[test]
    fn borrowing_rung_round_trips_through_inspection() {
        let inspector = Inspector::new(
            slot(0, 3, QUEUE_BORROW_POLICY, 1_000),
            FairnessMode::Vtime,
            None,
        );
        let view = inspector.snapshot(metrics(3, 4), Vec::new());
        let rung = &view.slots[0].policy.as_ref().unwrap().rungs[0];

        assert_eq!(rung.operation, "pick_random_idle_core");
        assert_eq!(rung.scope, "task_cell_borrowable");
        assert_eq!(rung.opcode.selected.value, "pick_idle_queue_mask");
        assert_eq!(rung.input.selected.value, "queue_cell");
        assert_eq!(
            rung.flags.selected.value,
            format!("0x{:08x}", RUNG_FLAG_PICK_RANDOM | RUNG_FLAG_PICK_IDLE_CORE)
        );
        assert_eq!(rung.data.selected.value, "queue_mask:2");
    }

    #[test]
    fn queue_callback_ladders_round_trip_in_configured_order() {
        let inspector = Inspector::new(
            slot(
                0,
                4,
                r#"
[queues]
layout = "cell_llc"

[[queues.enqueue]]
target = "cell"

[[queues.enqueue]]
target = "affinity"

[[queues.dispatch]]
source = "cell"

[[queues.dispatch]]
source = "affinity"

[[cell]]
id = 7
cpus = "0-3"

[[rung]]
operation = "pick_idle"
scope = "task_cell"
"#,
                1_000,
            ),
            FairnessMode::Vtime,
            None,
        );

        let view = inspector.snapshot(metrics(4, 1), Vec::new());
        let queues = view.slots[0]
            .policy
            .as_ref()
            .unwrap()
            .queues
            .as_ref()
            .expect("queue policy should be inspected");

        assert_eq!(queues.layout, "cell_llc");
        assert_eq!(
            queues
                .enqueue
                .iter()
                .map(|rung| (rung.index, rung.operation.as_str()))
                .collect::<Vec<_>>(),
            vec![(0, "cell"), (1, "affinity")]
        );
        assert_eq!(
            queues
                .dispatch
                .iter()
                .map(|rung| (rung.index, rung.operation.as_str()))
                .collect::<Vec<_>>(),
            vec![(0, "cell"), (1, "affinity")]
        );
    }

    #[test]
    fn min_vtime_dispatch_round_trips_as_one_combined_operation() {
        let inspector = Inspector::new(
            slot(
                0,
                5,
                r#"
[queues]
layout = "cell"
enqueue = [{ target = "cell" }, { target = "affinity" }]
dispatch = [{ operation = "min_vtime" }]

[[cell]]
id = 7
cpus = "0-3"

[[rung]]
operation = "pick_idle"
scope = "task_cell"
"#,
                1_000,
            ),
            FairnessMode::Vtime,
            None,
        );

        let view = inspector.snapshot(metrics(5, 1), Vec::new());
        let dispatch = &view.slots[0]
            .policy
            .as_ref()
            .unwrap()
            .queues
            .as_ref()
            .unwrap()
            .dispatch;

        assert_eq!(dispatch.len(), 1);
        assert_eq!(dispatch[0].operation, "min_vtime(cell,affinity)");
    }

    #[test]
    fn placement_only_policy_has_no_queue_callback_ladders() {
        let inspector = Inspector::new(slot(0, 5, FIRST_POLICY, 1_000), FairnessMode::Fifo, None);
        let view = inspector.snapshot(metrics(5, 1), Vec::new());

        assert!(view.slots[0].policy.as_ref().unwrap().queues.is_none());
    }

    #[test]
    fn resolved_queue_topology_exposes_allocation_dsq_and_cpu_routes() {
        let source = r#"
[queues]
layout = "cell_llc"

[[cell]]
id = 7
cpus = "0-2"
cpu_weight = 2

[[rung]]
operation = "pick_idle"
scope = "task_cell"
"#;
        let active = slot(0, 6, source, 1_000);
        let topology = queue_topology::resolve_queue_topology(
            &active.compiled,
            &[0, 1, 2, 3].into_iter().collect(),
            &BTreeMap::from([(0, 10), (1, 10), (2, 20), (3, 20)]),
        )
        .unwrap()
        .unwrap();
        let inspector = Inspector::new(active, FairnessMode::Vtime, Some(topology));

        let view = inspector.snapshot(metrics(6, 1), Vec::new());
        let resolved = view
            .queue_topology
            .as_ref()
            .expect("queue topology should be inspected");

        assert_eq!(view.fairness.mode_name, "vtime");
        assert_eq!(
            view.fairness.clock_model,
            "one clock per cell shared by normal and affinity queues"
        );
        assert_eq!(resolved.layout, "cell_llc");
        assert_eq!(resolved.affinity_queue_count, 4);
        assert_eq!(resolved.cells[0].external_id, 0);
        assert!(resolved.cells[0].synthetic);
        assert_eq!(resolved.cells[1].external_id, 7);
        assert_eq!(resolved.cells[1].cpu_weight, 2);
        assert_eq!(resolved.cells[1].clock_index, resolved.cells[1].index);
        assert!(!resolved.cells[1].primary_cpus.is_empty());
        assert_eq!(resolved.normal_queues[0].dsq_id, 0x20000000);
        assert_eq!(resolved.cpu_routes[0].affinity_dsq_id, 0x10000000);
        assert_eq!(resolved.cpu_routes[3].affinity_dsq_id, 0x10000003);
    }

    #[test]
    fn placement_only_inspection_still_describes_fairness_without_queue_topology() {
        let inspector = Inspector::new(slot(0, 7, FIRST_POLICY, 1_000), FairnessMode::Fifo, None);
        let view = inspector.snapshot(metrics(7, 1), Vec::new());

        assert_eq!(view.fairness.mode_name, "fifo");
        assert_eq!(view.fairness.clock_model, "no virtual-time clock");
        assert!(view.queue_topology.is_none());
    }
}
