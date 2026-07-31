// SPDX-License-Identifier: GPL-2.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Component, Path};

use serde::Deserialize;

pub const MAX_RUNGS: usize = 8;
pub const MAX_MASK_TABLES: usize = 4;
pub const MAX_CELL_IDS: u32 = 1024;
pub const MAX_QUEUE_CELLS: usize = 32;
pub const MAX_QUEUE_RUNGS: usize = 8;
pub const RUNG_FLAG_INTERSECT_TASK_ALLOWED: u32 = 1;
pub const RUNG_FLAG_PICK_IDLE_CORE: u32 = 1 << 1;
pub const RUNG_FLAG_PICK_RANDOM: u32 = 1 << 2;
pub const QUEUE_RUNG_FLAG_DIRECT_DISPATCH: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Opcode {
    ClaimIdle = 1,
    PickIdle = 2,
    PickIdleMaskTable = 3,
    PickRandomIdle = 4,
    KernelDefault = 5,
    SyncWakeAffine = 6,
    PickIdleQueueMask = 7,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum InputSource {
    CpuPrev = 1,
    MaskTaskAllowed = 2,
    TaskCell = 3,
    QueueCell = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u64)]
pub enum QueueMaskKind {
    Primary = 1,
    Borrowable = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct CompiledRung {
    pub opcode: Opcode,
    pub input: InputSource,
    pub flags: u32,
    pub data: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledPolicy {
    pub fallback: Fallback,
    pub rungs: Vec<CompiledRung>,
    pub mask_tables: Vec<MaskTableSpec>,
    pub cells: BTreeMap<u32, BTreeSet<u32>>,
    pub cell_cpu_weights: BTreeMap<u32, u32>,
    pub queues: Option<QueuePolicy>,
    pub membership: Option<MembershipPolicy>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipPolicy {
    pub parent: String,
    pub reconcile_ms: u64,
    pub assignments: BTreeMap<String, u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueLayout {
    Cell,
    CellLlc,
    Llc,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueuePolicy {
    pub layout: QueueLayout,
    pub cell0_cpu_weight: u32,
    pub direct_dispatch: bool,
    pub enqueue: Vec<QueueEnqueueRung>,
    pub dispatch: Vec<QueueDispatchRung>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum QueueEnqueueAction {
    TryInsert = 1,
    Insert = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum QueueEnqueueTarget {
    Cell = 1,
    Affinity = 2,
    Local = 3,
    Cpu = 4,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueEnqueueRung {
    pub action: QueueEnqueueAction,
    pub target: QueueEnqueueTarget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum QueueDispatchAction {
    Peek = 1,
    Consume = 2,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u32)]
pub enum QueueDispatchSource {
    Cell = 1,
    Affinity = 2,
    Cpu = 3,
    Local = 4,
    Remote = 5,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum QueueDispatchOperation {
    MinVtime = 1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueueDispatchRung {
    pub action: QueueDispatchAction,
    pub source: Option<QueueDispatchSource>,
    pub operation: Option<QueueDispatchOperation>,
    pub fallback: Vec<QueueDispatchSource>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Fallback {
    PreviousCpu = 1,
    AnyAllowed = 2,
}

/// Userspace source that materializes a topology-blind mask table for BPF.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaskTableSource {
    PreviousLlcByCpu,
    PreviousNodeByCpu,
    SplitLlcByCore { parts: u32 },
    TaskCellById,
}

/// Named mask table allocated to a dense mechanical table ID.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaskTableSpec {
    pub id: u32,
    pub name: String,
    pub source: MaskTableSource,
}

impl CompiledPolicy {
    pub fn dump(&self) -> String {
        let mut output = format!("fallback: {}\n", self.fallback.as_str());
        if let Some(queues) = &self.queues {
            let cell_weight = if queues.layout == QueueLayout::Llc {
                String::new()
            } else {
                format!(" cell0_cpu_weight={}", queues.cell0_cpu_weight)
            };
            output.push_str(&format!(
                "queues: layout={}{}{} enqueue={} dispatch={}\n",
                queues.layout.as_str(),
                cell_weight,
                if queues.direct_dispatch {
                    " direct_dispatch=true"
                } else {
                    ""
                },
                queues
                    .enqueue
                    .iter()
                    .map(QueueEnqueueRung::describe)
                    .collect::<Vec<_>>()
                    .join(","),
                queues
                    .dispatch
                    .iter()
                    .map(QueueDispatchRung::describe)
                    .collect::<Vec<_>>()
                    .join(","),
            ));
        }
        if let Some(membership) = &self.membership {
            output.push_str(&format!(
                "membership: parent={} reconcile_ms={} assignments={}\n",
                membership.parent,
                membership.reconcile_ms,
                membership
                    .assignments
                    .iter()
                    .map(|(child, cell)| format!("{child}:{cell}"))
                    .collect::<Vec<_>>()
                    .join(","),
            ));
        }
        output.push_str(
            &self
                .rungs
                .iter()
                .enumerate()
                .map(|(index, rung)| {
                    format!(
                        "rung {index}: opcode={} input={} flags={:#010x} data={:#018x}\n",
                        rung.opcode.as_str(),
                        rung.input.as_str(),
                        rung.flags,
                        rung.data,
                    )
                })
                .collect::<String>(),
        );
        output
    }
}

impl QueueLayout {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cell => "cell",
            Self::CellLlc => "cell_llc",
            Self::Llc => "llc",
        }
    }
}

impl QueueEnqueueAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TryInsert => "try_insert",
            Self::Insert => "insert",
        }
    }
}

impl QueueEnqueueTarget {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cell => "cell",
            Self::Affinity => "affinity",
            Self::Local => "local",
            Self::Cpu => "cpu",
        }
    }
}

impl QueueEnqueueRung {
    pub fn describe(&self) -> String {
        if matches!(
            self.target,
            QueueEnqueueTarget::Cell | QueueEnqueueTarget::Affinity
        ) {
            return self.target.as_str().into();
        }
        format!("{}({})", self.action.as_str(), self.target.as_str())
    }
}

impl QueueDispatchAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Peek => "peek",
            Self::Consume => "consume",
        }
    }
}

impl QueueDispatchSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cell => "cell",
            Self::Affinity => "affinity",
            Self::Cpu => "cpu",
            Self::Local => "local",
            Self::Remote => "remote",
        }
    }
}

impl QueueDispatchOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MinVtime => "min_vtime",
        }
    }
}

impl QueueDispatchRung {
    pub fn describe(&self) -> String {
        if let Some(source) = self.source {
            if matches!(
                source,
                QueueDispatchSource::Cell | QueueDispatchSource::Affinity
            ) {
                return source.as_str().into();
            }
            return format!("{}({})", self.action.as_str(), source.as_str());
        }
        let operation = self
            .operation
            .expect("compiled dispatch rung has a source or operation");
        if self.fallback.is_empty() {
            return match operation {
                QueueDispatchOperation::MinVtime => "min_vtime(cell,affinity)".into(),
            };
        }
        format!(
            "{}({};fallback={})",
            self.action.as_str(),
            operation.as_str(),
            self.fallback
                .iter()
                .map(|source| source.as_str())
                .collect::<Vec<_>>()
                .join(",")
        )
    }
}

impl Fallback {
    fn as_str(self) -> &'static str {
        match self {
            Self::PreviousCpu => "previous_cpu",
            Self::AnyAllowed => "any_allowed",
        }
    }
}

impl Opcode {
    fn as_str(self) -> &'static str {
        match self {
            Self::ClaimIdle => "claim_idle",
            Self::PickIdle => "pick_idle",
            Self::PickIdleMaskTable => "pick_idle_mask_table",
            Self::PickRandomIdle => "pick_random_idle",
            Self::KernelDefault => "kernel_default",
            Self::SyncWakeAffine => "sync_wake_affine",
            Self::PickIdleQueueMask => "pick_idle_queue_mask",
        }
    }
}

impl InputSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::CpuPrev => "cpu_prev",
            Self::MaskTaskAllowed => "mask_task_allowed",
            Self::TaskCell => "task_cell",
            Self::QueueCell => "queue_cell",
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct PolicyError(String);

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for PolicyError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticPolicy {
    fallback: Option<String>,
    queues: Option<SemanticQueuePolicy>,
    membership: Option<SemanticMembershipPolicy>,
    #[serde(default)]
    cell: Vec<SemanticCell>,
    #[serde(default)]
    partition: Vec<SemanticPartition>,
    #[serde(default)]
    rung: Vec<SemanticRung>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticMembershipPolicy {
    parent: String,
    #[serde(default = "default_membership_reconcile_ms")]
    reconcile_ms: u64,
    #[serde(default)]
    assignment: Vec<SemanticMembershipAssignment>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticMembershipAssignment {
    child: String,
    cell: u32,
}

const fn default_membership_reconcile_ms() -> u64 {
    1_000
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticCell {
    id: u32,
    cpus: String,
    cpu_weight: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticQueuePolicy {
    layout: String,
    cell0_cpu_weight: Option<u32>,
    #[serde(default)]
    direct_dispatch: bool,
    enqueue: Option<Vec<SemanticQueueEnqueueRung>>,
    dispatch: Option<Vec<SemanticQueueDispatchRung>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticQueueEnqueueRung {
    action: Option<String>,
    target: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticQueueDispatchRung {
    action: Option<String>,
    source: Option<String>,
    operation: Option<String>,
    #[serde(default)]
    fallback: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticPartition {
    name: String,
    provider: String,
    parts: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SemanticRung {
    operation: String,
    scope: String,
}

pub fn compile_policy(source: &str) -> Result<CompiledPolicy, PolicyError> {
    let policy: SemanticPolicy = toml::from_str(source)
        .map_err(|error| PolicyError(format!("invalid policy TOML: {error}")))?;

    if policy.rung.is_empty() {
        return Err(PolicyError("policy must contain at least one rung".into()));
    }
    if policy.rung.len() > MAX_RUNGS {
        return Err(PolicyError(format!(
            "policy has too many rungs: maximum is {MAX_RUNGS}"
        )));
    }

    let fallback = match policy.fallback.as_deref() {
        None | Some("previous_cpu") => Fallback::PreviousCpu,
        Some("any_allowed") => Fallback::AnyAllowed,
        Some(fallback) => {
            return Err(PolicyError(format!(
                "unknown fallback `{fallback}`; expected `previous_cpu` or `any_allowed`"
            )))
        }
    };

    if let Some((index, _)) = policy
        .rung
        .iter()
        .enumerate()
        .find(|(_, rung)| rung.operation == "kernel_default")
    {
        if index + 1 != policy.rung.len() {
            return Err(PolicyError(format!(
                "rung {index}: operation `kernel_default` must be the last rung"
            )));
        }
    }

    let queues = compile_queue_policy(policy.queues.as_ref(), policy.cell.len())?;
    let queue_layout = queues.as_ref().map(|queues| queues.layout);
    let (cells, cell_cpu_weights) = compile_cells(&policy.cell, queues.is_some())?;
    let membership = compile_membership(policy.membership.as_ref(), queue_layout, &cells)?;
    let partitions = compile_partitions(&policy.partition)?;
    let mut mask_tables = Vec::new();
    let mut rungs = Vec::with_capacity(policy.rung.len());
    for (index, rung) in policy.rung.iter().enumerate() {
        rungs.push(compile_rung(
            index,
            rung,
            &partitions,
            !cells.is_empty(),
            queue_layout,
            &mut mask_tables,
        )?);
    }

    Ok(CompiledPolicy {
        fallback,
        rungs,
        mask_tables,
        cells,
        cell_cpu_weights,
        queues,
        membership,
    })
}

fn compile_membership(
    membership: Option<&SemanticMembershipPolicy>,
    queue_layout: Option<QueueLayout>,
    cells: &BTreeMap<u32, BTreeSet<u32>>,
) -> Result<Option<MembershipPolicy>, PolicyError> {
    let Some(membership) = membership else {
        return Ok(None);
    };
    if queue_layout.is_none() {
        return Err(PolicyError(
            "userspace membership requires a [queues] policy".into(),
        ));
    }
    if queue_layout == Some(QueueLayout::Llc) {
        return Err(PolicyError(
            "queue layout `llc` does not support membership".into(),
        ));
    }
    let parent = Path::new(&membership.parent);
    if !parent.is_absolute() {
        return Err(PolicyError(
            "membership parent must be an absolute path".into(),
        ));
    }
    if membership.reconcile_ms < 50 {
        return Err(PolicyError(
            "membership reconcile_ms must be at least 50".into(),
        ));
    }

    let mut assignments = BTreeMap::new();
    for assignment in &membership.assignment {
        let mut components = Path::new(&assignment.child).components();
        if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
            return Err(PolicyError(format!(
                "membership child must be one path component: `{}`",
                assignment.child
            )));
        }
        if !cells.contains_key(&assignment.cell) {
            return Err(PolicyError(format!(
                "membership child `{}` references undefined cell {}",
                assignment.child, assignment.cell
            )));
        }
        if assignments
            .insert(assignment.child.clone(), assignment.cell)
            .is_some()
        {
            return Err(PolicyError(format!(
                "membership has duplicate child `{}`",
                assignment.child
            )));
        }
    }

    Ok(Some(MembershipPolicy {
        parent: membership.parent.clone(),
        reconcile_ms: membership.reconcile_ms,
        assignments,
    }))
}

fn compile_queue_policy(
    queues: Option<&SemanticQueuePolicy>,
    declared_cells: usize,
) -> Result<Option<QueuePolicy>, PolicyError> {
    let Some(queues) = queues else {
        return Ok(None);
    };
    let layout = match queues.layout.as_str() {
        "cell" => QueueLayout::Cell,
        "cell_llc" => QueueLayout::CellLlc,
        "llc" => QueueLayout::Llc,
        layout => {
            return Err(PolicyError(format!(
                "unknown queue layout `{layout}`; expected `cell`, `cell_llc`, or `llc`"
            )))
        }
    };
    if layout == QueueLayout::Llc && declared_cells != 0 {
        return Err(PolicyError(
            "queue layout `llc` does not support declared cells".into(),
        ));
    }
    if layout == QueueLayout::Llc && queues.cell0_cpu_weight.is_some() {
        return Err(PolicyError(
            "queue layout `llc` does not support cell0_cpu_weight".into(),
        ));
    }
    if queues.direct_dispatch && layout != QueueLayout::Llc {
        return Err(PolicyError(
            "direct dispatch requires queue layout `llc`".into(),
        ));
    }
    if layout != QueueLayout::Llc && declared_cells >= MAX_QUEUE_CELLS {
        return Err(PolicyError(format!(
            "queue policies support at most {} declared cells plus synthetic cell 0",
            MAX_QUEUE_CELLS - 1
        )));
    }
    let cell0_cpu_weight = queues.cell0_cpu_weight.unwrap_or(1);
    if cell0_cpu_weight == 0 {
        return Err(PolicyError(
            "queue default cell weight must be positive".into(),
        ));
    }
    let (enqueue, dispatch) = if queues.enqueue.is_none() && queues.dispatch.is_none() {
        default_queue_callbacks(layout)
    } else {
        let enqueue = compile_queue_enqueue(queues.enqueue.as_deref().unwrap_or(&[]), layout)?;
        let dispatch = compile_queue_dispatch(queues.dispatch.as_deref().unwrap_or(&[]), layout)?;
        validate_queue_callback_pair(layout, &enqueue, &dispatch)?;
        (enqueue, dispatch)
    };
    Ok(Some(QueuePolicy {
        layout,
        cell0_cpu_weight,
        direct_dispatch: queues.direct_dispatch,
        enqueue,
        dispatch,
    }))
}

fn default_queue_callbacks(layout: QueueLayout) -> (Vec<QueueEnqueueRung>, Vec<QueueDispatchRung>) {
    if layout == QueueLayout::Llc {
        return (
            vec![
                QueueEnqueueRung {
                    action: QueueEnqueueAction::TryInsert,
                    target: QueueEnqueueTarget::Local,
                },
                QueueEnqueueRung {
                    action: QueueEnqueueAction::Insert,
                    target: QueueEnqueueTarget::Cpu,
                },
            ],
            vec![
                llc_dispatch_peek(QueueDispatchSource::Cpu),
                llc_dispatch_peek(QueueDispatchSource::Local),
                llc_dispatch_peek(QueueDispatchSource::Remote),
                QueueDispatchRung {
                    action: QueueDispatchAction::Consume,
                    source: None,
                    operation: Some(QueueDispatchOperation::MinVtime),
                    fallback: vec![
                        QueueDispatchSource::Cpu,
                        QueueDispatchSource::Local,
                        QueueDispatchSource::Remote,
                    ],
                },
            ],
        );
    }
    (
        vec![
            QueueEnqueueRung {
                action: QueueEnqueueAction::TryInsert,
                target: QueueEnqueueTarget::Cell,
            },
            QueueEnqueueRung {
                action: QueueEnqueueAction::Insert,
                target: QueueEnqueueTarget::Affinity,
            },
        ],
        vec![
            legacy_dispatch_source(QueueDispatchSource::Affinity),
            legacy_dispatch_source(QueueDispatchSource::Cell),
        ],
    )
}

fn llc_dispatch_peek(source: QueueDispatchSource) -> QueueDispatchRung {
    QueueDispatchRung {
        action: QueueDispatchAction::Peek,
        source: Some(source),
        operation: None,
        fallback: Vec::new(),
    }
}

fn legacy_dispatch_source(source: QueueDispatchSource) -> QueueDispatchRung {
    QueueDispatchRung {
        action: QueueDispatchAction::Consume,
        source: Some(source),
        operation: None,
        fallback: Vec::new(),
    }
}

fn compile_queue_enqueue(
    rungs: &[SemanticQueueEnqueueRung],
    layout: QueueLayout,
) -> Result<Vec<QueueEnqueueRung>, PolicyError> {
    if rungs.is_empty() {
        return Err(PolicyError("queue enqueue ladder must not be empty".into()));
    }
    if rungs.len() > MAX_QUEUE_RUNGS {
        return Err(PolicyError(format!(
            "queue enqueue ladder has too many rungs: maximum is {MAX_QUEUE_RUNGS}"
        )));
    }

    if layout == QueueLayout::Llc {
        return compile_llc_queue_enqueue(rungs);
    }

    let mut compiled: Vec<QueueEnqueueRung> = Vec::with_capacity(rungs.len());
    for rung in rungs {
        if rung.action.is_some() {
            return Err(PolicyError(
                "explicit enqueue actions require queue layout `llc`".into(),
            ));
        }
        let (action, target) = match rung.target.as_str() {
            "cell" => (QueueEnqueueAction::TryInsert, QueueEnqueueTarget::Cell),
            "affinity" => (QueueEnqueueAction::Insert, QueueEnqueueTarget::Affinity),
            target => {
                return Err(PolicyError(format!(
                    "unknown enqueue target `{target}`; expected `cell` or `affinity`"
                )))
            }
        };
        if compiled.iter().any(|rung| rung.target == target) {
            return Err(PolicyError(format!(
                "duplicate enqueue target `{}`",
                target.as_str()
            )));
        }
        compiled.push(QueueEnqueueRung { action, target });
    }

    if !compiled
        .iter()
        .any(|rung| rung.target == QueueEnqueueTarget::Affinity)
    {
        return Err(PolicyError(
            "queue enqueue ladder must contain `affinity`".into(),
        ));
    }
    if compiled.last().map(|rung| rung.target) != Some(QueueEnqueueTarget::Affinity) {
        return Err(PolicyError(
            "enqueue target `affinity` must be terminal".into(),
        ));
    }
    Ok(compiled)
}

fn compile_llc_queue_enqueue(
    rungs: &[SemanticQueueEnqueueRung],
) -> Result<Vec<QueueEnqueueRung>, PolicyError> {
    let mut compiled = Vec::with_capacity(rungs.len());
    for (index, rung) in rungs.iter().enumerate() {
        let action = match rung.action.as_deref() {
            Some("try_insert") => QueueEnqueueAction::TryInsert,
            Some("insert") => QueueEnqueueAction::Insert,
            Some(action) => {
                return Err(PolicyError(format!(
                    "unknown enqueue action `{action}`; expected `try_insert` or `insert`"
                )))
            }
            None => {
                return Err(PolicyError(
                    "queue layout `llc` enqueue rungs must specify `action`".into(),
                ))
            }
        };
        let target = match rung.target.as_str() {
            "local" => QueueEnqueueTarget::Local,
            "cpu" => QueueEnqueueTarget::Cpu,
            target => {
                return Err(PolicyError(format!(
                    "unknown LLC enqueue target `{target}`; expected `local` or `cpu`"
                )))
            }
        };
        match (action, target) {
            (QueueEnqueueAction::TryInsert, QueueEnqueueTarget::Local) => {}
            (QueueEnqueueAction::Insert, QueueEnqueueTarget::Cpu) => {}
            (QueueEnqueueAction::TryInsert, _) => {
                return Err(PolicyError(
                    "enqueue action `try_insert` must target `local`".into(),
                ))
            }
            (QueueEnqueueAction::Insert, _) => {
                return Err(PolicyError(
                    "enqueue action `insert` must target `cpu`".into(),
                ))
            }
        }
        if compiled
            .iter()
            .any(|compiled: &QueueEnqueueRung| compiled.target == target)
        {
            return Err(PolicyError(format!(
                "duplicate enqueue target `{}`",
                target.as_str()
            )));
        }
        if action == QueueEnqueueAction::Insert && index + 1 != rungs.len() {
            return Err(PolicyError(
                "enqueue action `insert` must be terminal".into(),
            ));
        }
        compiled.push(QueueEnqueueRung { action, target });
    }
    if compiled.last()
        != Some(&QueueEnqueueRung {
            action: QueueEnqueueAction::Insert,
            target: QueueEnqueueTarget::Cpu,
        })
    {
        return Err(PolicyError(
            "queue enqueue ladder must end with `insert` targeting `cpu`".into(),
        ));
    }
    if compiled.len() != 2
        || compiled[0]
            != (QueueEnqueueRung {
                action: QueueEnqueueAction::TryInsert,
                target: QueueEnqueueTarget::Local,
            })
    {
        return Err(PolicyError(
            "queue layout `llc` enqueue ladder must try `local` before inserting into `cpu`".into(),
        ));
    }
    Ok(compiled)
}

fn compile_queue_dispatch(
    rungs: &[SemanticQueueDispatchRung],
    layout: QueueLayout,
) -> Result<Vec<QueueDispatchRung>, PolicyError> {
    if rungs.is_empty() {
        return Err(PolicyError(
            "queue dispatch ladder must not be empty".into(),
        ));
    }
    if rungs.len() > MAX_QUEUE_RUNGS {
        return Err(PolicyError(format!(
            "queue dispatch ladder has too many rungs: maximum is {MAX_QUEUE_RUNGS}"
        )));
    }

    if layout == QueueLayout::Llc {
        return compile_llc_queue_dispatch(rungs);
    }

    let mut compiled: Vec<QueueDispatchRung> = Vec::with_capacity(rungs.len());
    for rung in rungs {
        if rung.action.is_some() || !rung.fallback.is_empty() {
            return Err(PolicyError(
                "explicit dispatch actions and fallback require queue layout `llc`".into(),
            ));
        }
        let compiled_rung = match (rung.source.as_deref(), rung.operation.as_deref()) {
            (Some("cell"), None) => legacy_dispatch_source(QueueDispatchSource::Cell),
            (Some("affinity"), None) => legacy_dispatch_source(QueueDispatchSource::Affinity),
            (Some(source), None) => {
                return Err(PolicyError(format!(
                    "unknown dispatch source `{source}`; expected `cell` or `affinity`"
                )))
            }
            (None, Some("min_vtime")) => QueueDispatchRung {
                action: QueueDispatchAction::Consume,
                source: None,
                operation: Some(QueueDispatchOperation::MinVtime),
                fallback: Vec::new(),
            },
            (None, Some(operation)) => {
                return Err(PolicyError(format!(
                    "unknown dispatch operation `{operation}`; expected `min_vtime`"
                )))
            }
            _ => {
                return Err(PolicyError(
                    "dispatch rung must specify exactly one of `source` or `operation`".into(),
                ))
            }
        };
        if compiled.contains(&compiled_rung) {
            return Err(PolicyError(format!(
                "duplicate dispatch source `{}`",
                compiled_rung.describe()
            )));
        }
        compiled.push(compiled_rung);
    }

    let has_min_vtime = compiled
        .iter()
        .any(|rung| rung.operation == Some(QueueDispatchOperation::MinVtime));
    if has_min_vtime && compiled.len() != 1 {
        return Err(PolicyError(
            "min_vtime must be the sole dispatch operation".into(),
        ));
    }

    if !compiled
        .iter()
        .any(|rung| rung.source == Some(QueueDispatchSource::Affinity))
        && !has_min_vtime
    {
        return Err(PolicyError(
            "queue dispatch ladder must contain `affinity`".into(),
        ));
    }
    Ok(compiled)
}

fn compile_llc_queue_dispatch(
    rungs: &[SemanticQueueDispatchRung],
) -> Result<Vec<QueueDispatchRung>, PolicyError> {
    let mut compiled = Vec::with_capacity(rungs.len());
    let mut peek_sources = BTreeSet::new();
    for (index, rung) in rungs.iter().enumerate() {
        match rung.action.as_deref() {
            Some("peek") => {
                if rung.operation.is_some() || !rung.fallback.is_empty() {
                    return Err(PolicyError(
                        "dispatch action `peek` accepts only `source`".into(),
                    ));
                }
                let source = compile_llc_dispatch_source(rung.source.as_deref())?;
                if !peek_sources.insert(source) {
                    return Err(PolicyError(format!(
                        "duplicate dispatch peek source `{}`",
                        source.as_str()
                    )));
                }
                compiled.push(llc_dispatch_peek(source));
            }
            Some("consume") => {
                if index + 1 != rungs.len() {
                    return Err(PolicyError(
                        "dispatch action `consume` must be terminal".into(),
                    ));
                }
                if rung.source.is_some() {
                    return Err(PolicyError(
                        "dispatch action `consume` accepts `operation`, not `source`".into(),
                    ));
                }
                let operation = match rung.operation.as_deref() {
                    Some("min_vtime") => QueueDispatchOperation::MinVtime,
                    Some(operation) => {
                        return Err(PolicyError(format!(
                            "unknown dispatch operation `{operation}`; expected `min_vtime`"
                        )))
                    }
                    None => {
                        return Err(PolicyError(
                            "dispatch action `consume` must specify `operation`".into(),
                        ))
                    }
                };
                let mut fallback_set = BTreeSet::new();
                let mut fallback = Vec::with_capacity(rung.fallback.len());
                for source in &rung.fallback {
                    let source = compile_llc_dispatch_source(Some(source))?;
                    if !fallback_set.insert(source) {
                        return Err(PolicyError(format!(
                            "duplicate dispatch fallback source `{}`",
                            source.as_str()
                        )));
                    }
                    fallback.push(source);
                }
                if fallback_set != peek_sources {
                    return Err(PolicyError(
                        "dispatch fallback must reference every configured peek source exactly once"
                            .into(),
                    ));
                }
                compiled.push(QueueDispatchRung {
                    action: QueueDispatchAction::Consume,
                    source: None,
                    operation: Some(operation),
                    fallback,
                });
            }
            Some(action) => {
                return Err(PolicyError(format!(
                    "unknown dispatch action `{action}`; expected `peek` or `consume`"
                )))
            }
            None => {
                return Err(PolicyError(
                    "queue layout `llc` dispatch rungs must specify `action`".into(),
                ))
            }
        }
    }
    if compiled.last().map(|rung| rung.action) != Some(QueueDispatchAction::Consume) {
        return Err(PolicyError(
            "queue dispatch ladder must end with `consume`".into(),
        ));
    }
    let required = BTreeSet::from([
        QueueDispatchSource::Cpu,
        QueueDispatchSource::Local,
        QueueDispatchSource::Remote,
    ]);
    if peek_sources != required {
        return Err(PolicyError(
            "queue layout `llc` dispatch ladder must peek `cpu`, `local`, and `remote` exactly once"
                .into(),
        ));
    }
    let consume = compiled
        .pop()
        .expect("validated LLC dispatch ladder has terminal consume");
    compiled.sort_by_key(|rung| rung.source);
    compiled.push(consume);
    Ok(compiled)
}

fn compile_llc_dispatch_source(source: Option<&str>) -> Result<QueueDispatchSource, PolicyError> {
    match source {
        Some("cpu") => Ok(QueueDispatchSource::Cpu),
        Some("local") => Ok(QueueDispatchSource::Local),
        Some("remote") => Ok(QueueDispatchSource::Remote),
        Some(source) => Err(PolicyError(format!(
            "unknown LLC dispatch source `{source}`; expected `cpu`, `local`, or `remote`"
        ))),
        None => Err(PolicyError(
            "dispatch action `peek` must specify `source`".into(),
        )),
    }
}

fn validate_queue_callback_pair(
    layout: QueueLayout,
    enqueue: &[QueueEnqueueRung],
    dispatch: &[QueueDispatchRung],
) -> Result<(), PolicyError> {
    if layout == QueueLayout::Llc {
        return Ok(());
    }
    let enqueue_has_cell = enqueue
        .iter()
        .any(|rung| rung.target == QueueEnqueueTarget::Cell);
    let min_vtime = dispatch
        .iter()
        .any(|rung| rung.operation == Some(QueueDispatchOperation::MinVtime));
    if min_vtime
        && !(enqueue
            .iter()
            .any(|rung| rung.target == QueueEnqueueTarget::Cell)
            && enqueue
                .iter()
                .any(|rung| rung.target == QueueEnqueueTarget::Affinity))
    {
        return Err(PolicyError(
            "min_vtime requires both `cell` and `affinity` enqueue targets".into(),
        ));
    }
    let dispatch_has_cell = dispatch
        .iter()
        .any(|rung| rung.source == Some(QueueDispatchSource::Cell))
        || min_vtime;
    match (enqueue_has_cell, dispatch_has_cell) {
        (true, false) => Err(PolicyError(
            "queue dispatch ladder must contain `cell` when enqueue contains `cell`".into(),
        )),
        (false, true) => Err(PolicyError(
            "queue dispatch ladder must not contain `cell` when enqueue omits `cell`".into(),
        )),
        _ => Ok(()),
    }
}

fn compile_cells(
    cells: &[SemanticCell],
    queue_policy: bool,
) -> Result<(BTreeMap<u32, BTreeSet<u32>>, BTreeMap<u32, u32>), PolicyError> {
    let mut compiled = BTreeMap::new();
    let mut weights = BTreeMap::new();

    for (index, cell) in cells.iter().enumerate() {
        if cell.id >= MAX_CELL_IDS {
            return Err(PolicyError(format!(
                "cell {index}: ID {} exceeds maximum {}",
                cell.id,
                MAX_CELL_IDS - 1
            )));
        }
        if compiled.contains_key(&cell.id) {
            return Err(PolicyError(format!(
                "cell {index}: duplicate ID {}",
                cell.id
            )));
        }
        if queue_policy && cell.id == 0 {
            return Err(PolicyError(
                "cell ID 0 is reserved for unannotated tasks in queue policies".into(),
            ));
        }
        if !queue_policy && cell.cpu_weight.is_some() {
            return Err(PolicyError(format!(
                "cell {index}: cpu_weight requires a [queues] policy"
            )));
        }
        let weight = cell.cpu_weight.unwrap_or(1);
        if weight == 0 {
            return Err(PolicyError(format!(
                "cell {index}: cpu_weight must be positive"
            )));
        }

        let cpus = scx_utils::read_cpulist(&cell.cpus)
            .map_err(|error| PolicyError(format!("cell {index}: invalid CPU list: {error:#}")))?
            .into_iter()
            .map(|cpu| {
                u32::try_from(cpu).map_err(|_| {
                    PolicyError(format!("cell {index}: CPU {cpu} does not fit a CPU ID"))
                })
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        if cpus.is_empty() {
            return Err(PolicyError(format!(
                "cell {index}: CPU list must not be empty"
            )));
        }
        if let Some(cpu) = cpus.iter().find(|&&cpu| cpu >= MAX_CELL_IDS) {
            return Err(PolicyError(format!(
                "cell {index}: CPU {cpu} exceeds mask capacity {}",
                MAX_CELL_IDS - 1
            )));
        }
        compiled.insert(cell.id, cpus);
        weights.insert(cell.id, weight);
    }

    Ok((compiled, weights))
}

fn compile_partitions(
    partitions: &[SemanticPartition],
) -> Result<BTreeMap<String, MaskTableSource>, PolicyError> {
    let mut compiled = BTreeMap::new();

    for (index, partition) in partitions.iter().enumerate() {
        if matches!(
            partition.name.as_str(),
            "previous_cpu"
                | "previous_llc"
                | "previous_node"
                | "task_allowed"
                | "task_cell"
                | "task_cell_borrowable"
        ) {
            return Err(PolicyError(format!(
                "partition {index}: name `{}` is reserved",
                partition.name
            )));
        }
        if compiled.contains_key(&partition.name) {
            return Err(PolicyError(format!(
                "partition {index}: duplicate name `{}`",
                partition.name
            )));
        }

        let source = match partition.provider.as_str() {
            "split_llcs" => {
                if partition.parts < 2 {
                    return Err(PolicyError(format!(
                        "partition {index}: split_llcs requires at least two parts"
                    )));
                }
                let parts = partition.parts.try_into().map_err(|_| {
                    PolicyError(format!(
                        "partition {index}: part count {} is too large",
                        partition.parts
                    ))
                })?;
                MaskTableSource::SplitLlcByCore { parts }
            }
            provider => {
                return Err(PolicyError(format!(
                    "partition {index}: unknown provider `{provider}`"
                )))
            }
        };
        compiled.insert(partition.name.clone(), source);
    }

    Ok(compiled)
}

fn compile_rung(
    index: usize,
    rung: &SemanticRung,
    partitions: &BTreeMap<String, MaskTableSource>,
    has_cells: bool,
    queue_layout: Option<QueueLayout>,
    mask_tables: &mut Vec<MaskTableSpec>,
) -> Result<CompiledRung, PolicyError> {
    let queue_mode = queue_layout.is_some();
    if !matches!(
        rung.scope.as_str(),
        "previous_cpu"
            | "previous_llc"
            | "previous_node"
            | "task_allowed"
            | "task_cell"
            | "task_cell_borrowable"
    ) && !partitions.contains_key(&rung.scope)
    {
        return Err(PolicyError(format!(
            "rung {index}: unknown scope `{}`",
            rung.scope
        )));
    }
    if rung.scope == "task_cell" && !has_cells && !queue_mode {
        return Err(PolicyError(format!(
            "rung {index}: scope `task_cell` requires at least one cell"
        )));
    }
    if rung.scope == "task_cell_borrowable" && !queue_mode {
        return Err(PolicyError(format!(
            "rung {index}: scope `task_cell_borrowable` requires a [queues] policy"
        )));
    }
    if queue_layout == Some(QueueLayout::Llc)
        && matches!(rung.scope.as_str(), "task_cell" | "task_cell_borrowable")
    {
        return Err(PolicyError(
            "queue layout `llc` does not support task-cell scopes".into(),
        ));
    }

    if queue_mode
        && matches!(rung.scope.as_str(), "task_cell" | "task_cell_borrowable")
        && matches!(
            rung.operation.as_str(),
            "pick_idle" | "pick_idle_core" | "pick_random_idle" | "pick_random_idle_core"
        )
    {
        let data = if rung.scope == "task_cell" {
            QueueMaskKind::Primary
        } else {
            QueueMaskKind::Borrowable
        };
        return Ok(CompiledRung {
            opcode: Opcode::PickIdleQueueMask,
            input: InputSource::QueueCell,
            flags: if rung.operation.ends_with("_core") {
                RUNG_FLAG_PICK_IDLE_CORE
            } else {
                0
            } | if rung.operation.starts_with("pick_random") {
                RUNG_FLAG_PICK_RANDOM
            } else {
                0
            },
            data: data as u64,
        });
    }
    if rung.scope == "task_cell_borrowable" {
        return Err(PolicyError(format!(
            "rung {index}: operation `{}` is incompatible with scope `{}`",
            rung.operation, rung.scope
        )));
    }

    match rung.operation.as_str() {
        "claim_idle" if rung.scope == "previous_cpu" => Ok(CompiledRung {
            opcode: Opcode::ClaimIdle,
            input: InputSource::CpuPrev,
            flags: 0,
            data: 0,
        }),
        "claim_idle" => Err(PolicyError(format!(
            "rung {index}: operation `{}` is incompatible with scope `{}`",
            rung.operation, rung.scope
        ))),
        operation @ ("pick_idle" | "pick_idle_core") if rung.scope == "task_allowed" => {
            Ok(CompiledRung {
                opcode: Opcode::PickIdle,
                input: InputSource::MaskTaskAllowed,
                flags: if operation == "pick_idle_core" {
                    RUNG_FLAG_PICK_IDLE_CORE
                } else {
                    0
                },
                data: 0,
            })
        }
        "pick_idle" | "pick_idle_core" if rung.scope == "previous_cpu" => {
            Err(PolicyError(format!(
                "rung {index}: operation `{}` is incompatible with scope `{}`",
                rung.operation, rung.scope
            )))
        }
        operation @ ("pick_idle" | "pick_idle_core") if rung.scope == "task_cell" => {
            let table_id = intern_mask_table(
                index,
                &rung.scope,
                MaskTableSource::TaskCellById,
                mask_tables,
            )?;
            Ok(CompiledRung {
                opcode: Opcode::PickIdleMaskTable,
                input: InputSource::TaskCell,
                flags: RUNG_FLAG_INTERSECT_TASK_ALLOWED
                    | if operation == "pick_idle_core" {
                        RUNG_FLAG_PICK_IDLE_CORE
                    } else {
                        0
                    },
                data: table_id.into(),
            })
        }
        operation @ ("pick_idle" | "pick_idle_core") => {
            let source = mask_table_source(&rung.scope, partitions);
            let table_id = intern_mask_table(index, &rung.scope, source, mask_tables)?;

            Ok(CompiledRung {
                opcode: Opcode::PickIdleMaskTable,
                input: InputSource::CpuPrev,
                flags: RUNG_FLAG_INTERSECT_TASK_ALLOWED
                    | if operation == "pick_idle_core" {
                        RUNG_FLAG_PICK_IDLE_CORE
                    } else {
                        0
                    },
                data: table_id.into(),
            })
        }
        operation @ ("pick_random_idle" | "pick_random_idle_core")
            if rung.scope == "task_allowed" =>
        {
            Ok(CompiledRung {
                opcode: Opcode::PickRandomIdle,
                input: InputSource::MaskTaskAllowed,
                flags: if operation == "pick_random_idle_core" {
                    RUNG_FLAG_PICK_IDLE_CORE
                } else {
                    0
                },
                data: 0,
            })
        }
        "pick_random_idle" | "pick_random_idle_core" if rung.scope == "previous_cpu" => {
            Err(PolicyError(format!(
                "rung {index}: operation `{}` is incompatible with scope `{}`",
                rung.operation, rung.scope
            )))
        }
        operation @ ("pick_random_idle" | "pick_random_idle_core") if rung.scope == "task_cell" => {
            let table_id = intern_mask_table(
                index,
                &rung.scope,
                MaskTableSource::TaskCellById,
                mask_tables,
            )?;
            Ok(CompiledRung {
                opcode: Opcode::PickRandomIdle,
                input: InputSource::TaskCell,
                flags: RUNG_FLAG_INTERSECT_TASK_ALLOWED
                    | if operation == "pick_random_idle_core" {
                        RUNG_FLAG_PICK_IDLE_CORE
                    } else {
                        0
                    },
                data: table_id.into(),
            })
        }
        operation @ ("pick_random_idle" | "pick_random_idle_core") => {
            let source = mask_table_source(&rung.scope, partitions);
            let table_id = intern_mask_table(index, &rung.scope, source, mask_tables)?;

            Ok(CompiledRung {
                opcode: Opcode::PickRandomIdle,
                input: InputSource::CpuPrev,
                flags: RUNG_FLAG_INTERSECT_TASK_ALLOWED
                    | if operation == "pick_random_idle_core" {
                        RUNG_FLAG_PICK_IDLE_CORE
                    } else {
                        0
                    },
                data: table_id.into(),
            })
        }
        "kernel_default" if rung.scope == "task_allowed" => Ok(CompiledRung {
            opcode: Opcode::KernelDefault,
            input: InputSource::MaskTaskAllowed,
            flags: 0,
            data: 0,
        }),
        "kernel_default" => Err(PolicyError(format!(
            "rung {index}: operation `{}` is incompatible with scope `{}`",
            rung.operation, rung.scope
        ))),
        "sync_wake_affine" if rung.scope == "task_allowed" => {
            let llc_table = intern_mask_table(
                index,
                "previous_llc",
                MaskTableSource::PreviousLlcByCpu,
                mask_tables,
            )?;
            let node_table = intern_mask_table(
                index,
                "previous_node",
                MaskTableSource::PreviousNodeByCpu,
                mask_tables,
            )?;

            Ok(CompiledRung {
                opcode: Opcode::SyncWakeAffine,
                input: InputSource::MaskTaskAllowed,
                flags: 0,
                data: u64::from(llc_table) | (u64::from(node_table) << 32),
            })
        }
        "sync_wake_affine" => Err(PolicyError(format!(
            "rung {index}: operation `{}` is incompatible with scope `{}`",
            rung.operation, rung.scope
        ))),
        operation => Err(PolicyError(format!(
            "rung {index}: unknown operation `{operation}`"
        ))),
    }
}

fn mask_table_source(
    scope: &str,
    partitions: &BTreeMap<String, MaskTableSource>,
) -> MaskTableSource {
    match scope {
        "previous_llc" => MaskTableSource::PreviousLlcByCpu,
        "previous_node" => MaskTableSource::PreviousNodeByCpu,
        "task_cell" => MaskTableSource::TaskCellById,
        _ => *partitions
            .get(scope)
            .expect("scope existence was validated before table lowering"),
    }
}

fn intern_mask_table(
    rung_index: usize,
    name: &str,
    source: MaskTableSource,
    mask_tables: &mut Vec<MaskTableSpec>,
) -> Result<u32, PolicyError> {
    if let Some(table) = mask_tables.iter().find(|table| table.name == name) {
        return Ok(table.id);
    }
    if mask_tables.len() >= MAX_MASK_TABLES {
        return Err(PolicyError(format!(
            "rung {rung_index}: policy requires more than {MAX_MASK_TABLES} mask tables"
        )));
    }

    let id = mask_tables.len() as u32;
    mask_tables.push(MaskTableSpec {
        id,
        name: name.into(),
        source,
    });
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KERNEL_DEFAULT_SIM_POLICY: &str = include_str!("../examples/kernel-default-sim.toml");

    const TWO_RUNG_POLICY: &str = r#"
[[rung]]
operation = "claim_idle"
scope = "previous_cpu"

[[rung]]
operation = "pick_idle"
scope = "task_allowed"
"#;

    const PREVIOUS_LLC_POLICY: &str = r#"
[[rung]]
operation = "pick_idle"
scope = "previous_llc"
"#;

    const WHOLE_CORE_LLC_POLICY: &str = r#"
[[rung]]
operation = "pick_idle_core"
scope = "previous_llc"

[[rung]]
operation = "pick_idle"
scope = "previous_llc"
"#;

    const PREVIOUS_NODE_POLICY: &str = r#"
[[rung]]
operation = "pick_idle_core"
scope = "previous_node"

[[rung]]
operation = "pick_idle"
scope = "previous_node"
"#;

    const SUB_LLC_POLICY: &str = r#"
[[partition]]
name = "previous_llc_half"
provider = "split_llcs"
parts = 2

[[rung]]
operation = "pick_idle"
scope = "previous_llc_half"

[[rung]]
operation = "pick_idle"
scope = "previous_llc"
"#;

    const RANDOM_IDLE_POLICY: &str = r#"
fallback = "any_allowed"

[[rung]]
operation = "pick_random_idle"
scope = "task_allowed"
"#;

    const RANDOM_LLC_POLICY: &str = include_str!("../examples/llc-random.toml");

    const RANDOM_HALF_LLC_POLICY: &str = include_str!("../examples/llc-half-random.toml");

    const RANDOM_WHOLE_CORE_POLICY: &str = include_str!("../examples/llc-whole-core-random.toml");

    const KERNEL_DEFAULT_POLICY: &str = r#"
[[rung]]
operation = "kernel_default"
scope = "task_allowed"
"#;

    const SYNC_WAKE_POLICY: &str = r#"
[[rung]]
operation = "pick_idle"
scope = "previous_llc"

[[rung]]
operation = "pick_idle"
scope = "previous_node"

[[rung]]
operation = "sync_wake_affine"
scope = "task_allowed"
"#;

    fn error_for(source: &str) -> String {
        compile_policy(source)
            .expect_err("policy should be rejected")
            .to_string()
    }

    #[test]
    fn parses_and_lowers_supported_rungs_in_order() {
        let policy = compile_policy(TWO_RUNG_POLICY).expect("policy should compile");

        assert_eq!(
            policy.rungs,
            vec![
                CompiledRung {
                    opcode: Opcode::ClaimIdle,
                    input: InputSource::CpuPrev,
                    flags: 0,
                    data: 0,
                },
                CompiledRung {
                    opcode: Opcode::PickIdle,
                    input: InputSource::MaskTaskAllowed,
                    flags: 0,
                    data: 0,
                },
            ]
        );
    }

    #[test]
    fn lowers_overlapping_task_cells_to_one_sparse_mask_table() {
        let policy = compile_policy(
            r#"
[[cell]]
id = 7
cpus = "0-3"

[[cell]]
id = 8
cpus = "2-5"

[[rung]]
operation = "pick_idle"
scope = "task_cell"
"#,
        )
        .expect("cell policy should compile");

        assert_eq!(policy.mask_tables.len(), 1);
        assert_eq!(policy.mask_tables[0].name, "task_cell");
        assert!(policy.dump().contains("input=task_cell"));
        assert_eq!(policy.cells[&7], BTreeSet::from([0, 1, 2, 3]));
        assert_eq!(policy.cells[&8], BTreeSet::from([2, 3, 4, 5]));
    }

    #[test]
    fn queue_mode_lowers_primary_and_borrowable_cell_scopes_without_mask_tables() {
        let policy = compile_policy(
            r#"
[queues]
layout = "cell"

[[cell]]
id = 7
cpus = "0-3"

[[rung]]
operation = "pick_idle"
scope = "task_cell"

[[rung]]
operation = "pick_idle"
scope = "task_cell_borrowable"
"#,
        )
        .expect("queue cell scopes should compile");

        assert!(policy.mask_tables.is_empty());
        assert_eq!(policy.rungs[0].opcode, Opcode::PickIdleQueueMask);
        assert_eq!(policy.rungs[0].input, InputSource::QueueCell);
        assert_eq!(policy.rungs[0].data, QueueMaskKind::Primary as u64);
        assert_eq!(policy.rungs[1].opcode, Opcode::PickIdleQueueMask);
        assert_eq!(policy.rungs[1].input, InputSource::QueueCell);
        assert_eq!(policy.rungs[1].data, QueueMaskKind::Borrowable as u64);
    }

    #[test]
    fn queue_cell_idle_operations_preserve_random_and_core_semantics() {
        let cases = [
            ("pick_idle", 0),
            ("pick_idle_core", RUNG_FLAG_PICK_IDLE_CORE),
            ("pick_random_idle", RUNG_FLAG_PICK_RANDOM),
            (
                "pick_random_idle_core",
                RUNG_FLAG_PICK_RANDOM | RUNG_FLAG_PICK_IDLE_CORE,
            ),
        ];

        for (operation, flags) in cases {
            let policy = compile_policy(&format!(
                r#"
[queues]
layout = "cell"
[[rung]]
operation = "{operation}"
scope = "task_cell_borrowable"
"#
            ))
            .unwrap_or_else(|error| panic!("{operation} should compile: {error}"));

            assert_eq!(policy.rungs[0].opcode, Opcode::PickIdleQueueMask);
            assert_eq!(policy.rungs[0].flags, flags);
            assert_eq!(policy.rungs[0].data, QueueMaskKind::Borrowable as u64);
        }
    }

    #[test]
    fn borrowing_scope_requires_queue_mode() {
        let error = error_for(
            r#"
[[cell]]
id = 7
cpus = "0-3"
[[rung]]
operation = "pick_idle"
scope = "task_cell_borrowable"
"#,
        );

        assert!(error.contains("requires a [queues] policy"), "{error}");
    }

    #[test]
    fn compiles_weighted_cell_queue_policy() {
        let policy = compile_policy(
            r#"
[queues]
layout = "cell_llc"
cell0_cpu_weight = 2

[[cell]]
id = 7
cpus = "0-3"
cpu_weight = 5

[[cell]]
id = 8
cpus = "2-5"

[[rung]]
operation = "pick_idle"
scope = "task_cell"
"#,
        )
        .expect("weighted queue policy should compile");

        assert_eq!(policy.queues.as_ref().unwrap().layout, QueueLayout::CellLlc);
        assert_eq!(policy.queues.as_ref().unwrap().cell0_cpu_weight, 2);
        assert_eq!(policy.cell_cpu_weights[&7], 5);
        assert_eq!(policy.cell_cpu_weights[&8], 1);
    }

    #[test]
    fn queue_callback_ladders_default_to_compatible_ordering() {
        let policy = compile_policy(
            r#"
[queues]
layout = "cell"

[[cell]]
id = 7
cpus = "0-3"

[[rung]]
operation = "pick_idle"
scope = "task_cell"
"#,
        )
        .expect("queue policy should compile");

        let queues = policy.queues.as_ref().unwrap();
        let (expected_enqueue, expected_dispatch) = default_queue_callbacks(QueueLayout::Cell);
        assert_eq!(queues.enqueue, expected_enqueue);
        assert_eq!(queues.dispatch, expected_dispatch);
        assert!(policy
            .dump()
            .contains("enqueue=cell,affinity dispatch=affinity,cell"));
    }

    #[test]
    fn llc_queue_policy_defaults_to_local_routing_and_min_vtime_dispatch() {
        let policy = compile_policy(
            r#"
[queues]
layout = "llc"

[[rung]]
operation = "pick_idle"
scope = "task_allowed"
"#,
        )
        .expect("global LLC queue policy should compile");

        let queues = policy.queues.as_ref().unwrap();
        assert_eq!(queues.layout.as_str(), "llc");
        assert!(policy.cells.is_empty());
        assert!(policy.cell_cpu_weights.is_empty());
        assert!(policy.membership.is_none());
        assert!(policy.dump().contains(
            "enqueue=try_insert(local),insert(cpu) dispatch=peek(cpu),peek(local),peek(remote),consume(min_vtime;fallback=cpu,local,remote)"
        ));
        assert!(!policy.dump().contains("direct_dispatch=true"));
    }

    #[test]
    fn llc_queue_policy_can_enable_direct_dispatch() {
        let policy = compile_policy(
            r#"
[queues]
layout = "llc"
direct_dispatch = true

[[rung]]
operation = "pick_idle"
scope = "task_allowed"
"#,
        )
        .expect("global LLC queue policy should support direct dispatch");

        assert!(policy.dump().contains("direct_dispatch=true"));

        let error = error_for(
            r#"
[queues]
layout = "cell"
direct_dispatch = true

[[cell]]
id = 7
cpus = "0-3"

[[rung]]
operation = "pick_idle"
scope = "task_cell"
"#,
        );
        assert!(
            error.contains("direct dispatch requires queue layout `llc`"),
            "{error}"
        );
    }

    #[test]
    fn compiles_explicit_llc_queue_callback_ladders() {
        let policy = compile_policy(
            r#"
[queues]
layout = "llc"

[[queues.enqueue]]
action = "try_insert"
target = "local"

[[queues.enqueue]]
action = "insert"
target = "cpu"

[[queues.dispatch]]
action = "peek"
source = "cpu"

[[queues.dispatch]]
action = "peek"
source = "local"

[[queues.dispatch]]
action = "peek"
source = "remote"

[[queues.dispatch]]
action = "consume"
operation = "min_vtime"
fallback = ["cpu", "local", "remote"]

[[rung]]
operation = "pick_idle"
scope = "task_allowed"
"#,
        )
        .expect("explicit LLC callback ladders should compile");

        assert!(policy.dump().contains(
            "enqueue=try_insert(local),insert(cpu) dispatch=peek(cpu),peek(local),peek(remote),consume(min_vtime;fallback=cpu,local,remote)"
        ));

        let reordered = compile_policy(
            r#"
[queues]
layout = "llc"
enqueue = [{ action = "try_insert", target = "local" }, { action = "insert", target = "cpu" }]
dispatch = [
  { action = "peek", source = "remote" },
  { action = "peek", source = "cpu" },
  { action = "peek", source = "local" },
  { action = "consume", operation = "min_vtime", fallback = ["remote", "cpu", "local"] },
]
[[rung]]
operation = "pick_idle"
scope = "task_allowed"
"#,
        )
        .expect("LLC peek order should be semantically neutral");
        assert!(reordered.dump().contains(
            "dispatch=peek(cpu),peek(local),peek(remote),consume(min_vtime;fallback=remote,cpu,local)"
        ));
    }

    #[test]
    fn rejects_invalid_llc_enqueue_ladders() {
        let cases = [
            (
                "enqueue = [{ action = \"insert\", target = \"cpu\" }, { action = \"try_insert\", target = \"local\" }]",
                "enqueue action `insert` must be terminal",
            ),
            (
                "enqueue = [{ action = \"try_insert\", target = \"local\" }]",
                "enqueue ladder must end with `insert` targeting `cpu`",
            ),
            (
                "enqueue = [{ action = \"try_insert\", target = \"local\" }, { action = \"insert\", target = \"local\" }]",
                "enqueue action `insert` must target `cpu`",
            ),
        ];

        for (enqueue, expected) in cases {
            let source = format!(
                "[queues]\nlayout = \"llc\"\n{enqueue}\ndispatch = [{{ action = \"peek\", source = \"cpu\" }}, {{ action = \"peek\", source = \"local\" }}, {{ action = \"peek\", source = \"remote\" }}, {{ action = \"consume\", operation = \"min_vtime\", fallback = [\"cpu\", \"local\", \"remote\"] }}]\n[[rung]]\noperation = \"pick_idle\"\nscope = \"task_allowed\"\n"
            );
            let error = error_for(&source);
            assert!(error.contains(expected), "{error}");
        }
    }

    #[test]
    fn rejects_invalid_llc_dispatch_ladders() {
        let cases = [
            (
                "dispatch = [{ action = \"consume\", operation = \"min_vtime\", fallback = [\"cpu\", \"local\", \"remote\"] }, { action = \"peek\", source = \"cpu\" }]",
                "dispatch action `consume` must be terminal",
            ),
            (
                "dispatch = [{ action = \"peek\", source = \"cpu\" }, { action = \"peek\", source = \"cpu\" }, { action = \"consume\", operation = \"min_vtime\", fallback = [\"cpu\"] }]",
                "duplicate dispatch peek source `cpu`",
            ),
            (
                "dispatch = [{ action = \"peek\", source = \"cpu\" }, { action = \"peek\", source = \"local\" }, { action = \"consume\", operation = \"min_vtime\", fallback = [\"cpu\"] }]",
                "fallback must reference every configured peek source exactly once",
            ),
            (
                "dispatch = [{ action = \"peek\", source = \"cpu\" }, { action = \"consume\", operation = \"min_vtime\", fallback = [\"cpu\", \"cpu\"] }]",
                "duplicate dispatch fallback source `cpu`",
            ),
            (
                "dispatch = [{ action = \"peek\", source = \"cpu\" }]",
                "dispatch ladder must end with `consume`",
            ),
        ];

        for (dispatch, expected) in cases {
            let source = format!(
                "[queues]\nlayout = \"llc\"\nenqueue = [{{ action = \"try_insert\", target = \"local\" }}, {{ action = \"insert\", target = \"cpu\" }}]\n{dispatch}\n[[rung]]\noperation = \"pick_idle\"\nscope = \"task_allowed\"\n"
            );
            let error = error_for(&source);
            assert!(error.contains(expected), "{error}");
        }
    }

    #[test]
    fn llc_queue_policy_rejects_cell_semantics() {
        let cases = [
            (
                "cell0_cpu_weight = 2\n",
                "queue layout `llc` does not support cell0_cpu_weight",
            ),
            (
                r#"
[[cell]]
id = 7
cpus = "0"
"#,
                "queue layout `llc` does not support declared cells",
            ),
            (
                r#"
[membership]
parent = "/sys/fs/cgroup/workloads"
"#,
                "queue layout `llc` does not support membership",
            ),
        ];

        for (extra, expected) in cases {
            let source = format!(
                "[queues]\nlayout = \"llc\"\n{extra}\n[[rung]]\noperation = \"pick_idle\"\nscope = \"task_allowed\"\n"
            );
            let error = error_for(&source);
            assert!(error.contains(expected), "{error}");
        }

        for scope in ["task_cell", "task_cell_borrowable"] {
            let error = error_for(&format!(
                "[queues]\nlayout = \"llc\"\n[[rung]]\noperation = \"pick_idle\"\nscope = \"{scope}\"\n"
            ));
            assert!(
                error.contains("queue layout `llc` does not support task-cell scopes"),
                "{error}"
            );
        }
    }

    #[test]
    fn compiles_explicit_queue_callback_ladders() {
        let policy = compile_policy(
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
        )
        .expect("explicit queue callback ladders should compile");

        let queues = policy.queues.as_ref().unwrap();
        assert_eq!(
            queues.enqueue,
            vec![
                QueueEnqueueRung {
                    action: QueueEnqueueAction::TryInsert,
                    target: QueueEnqueueTarget::Cell,
                },
                QueueEnqueueRung {
                    action: QueueEnqueueAction::Insert,
                    target: QueueEnqueueTarget::Affinity,
                },
            ]
        );
        assert_eq!(
            queues.dispatch,
            vec![
                legacy_dispatch_source(QueueDispatchSource::Cell),
                legacy_dispatch_source(QueueDispatchSource::Affinity),
            ]
        );
    }

    #[test]
    fn compiles_min_vtime_dispatch_operation() {
        let policy = compile_policy(
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
        )
        .expect("min_vtime dispatch should compile");

        assert_eq!(policy.queues.as_ref().unwrap().dispatch.len(), 1);
        assert!(policy.dump().contains("dispatch=min_vtime(cell,affinity)"));
    }

    #[test]
    fn rejects_invalid_min_vtime_dispatch_ladders() {
        let cases = [
            (
                "enqueue = [{ target = \"affinity\" }]\ndispatch = [{ operation = \"min_vtime\" }]",
                "min_vtime requires both `cell` and `affinity` enqueue targets",
            ),
            (
                "enqueue = [{ target = \"cell\" }, { target = \"affinity\" }]\ndispatch = [{ operation = \"min_vtime\" }, { source = \"cell\" }]",
                "min_vtime must be the sole dispatch operation",
            ),
            (
                "enqueue = [{ target = \"cell\" }, { target = \"affinity\" }]\ndispatch = [{ source = \"cell\", operation = \"min_vtime\" }]",
                "dispatch rung must specify exactly one of `source` or `operation`",
            ),
        ];

        for (callbacks, expected) in cases {
            let source = format!(
                "[queues]\nlayout = \"cell\"\n{callbacks}\n[[rung]]\noperation = \"pick_idle\"\nscope = \"task_allowed\"\n"
            );
            let error = error_for(&source);
            assert!(error.contains(expected), "{error}");
        }
    }

    #[test]
    fn compiles_affinity_only_queue_callback_ladders() {
        let policy = compile_policy(
            r#"
[queues]
layout = "cell"

[[queues.enqueue]]
target = "affinity"

[[queues.dispatch]]
source = "affinity"

[[cell]]
id = 7
cpus = "0-3"

[[rung]]
operation = "pick_idle"
scope = "task_cell"
"#,
        )
        .expect("affinity-only callback ladders should compile");

        let queues = policy.queues.as_ref().unwrap();
        assert_eq!(
            queues.enqueue,
            vec![QueueEnqueueRung {
                action: QueueEnqueueAction::Insert,
                target: QueueEnqueueTarget::Affinity,
            }]
        );
        assert_eq!(
            queues.dispatch,
            vec![legacy_dispatch_source(QueueDispatchSource::Affinity)]
        );
    }

    #[test]
    fn rejects_invalid_queue_enqueue_ladders() {
        let cases = [
            ("enqueue = []\ndispatch = []", "enqueue ladder must not be empty"),
            (
                "enqueue = [{ target = \"cell\" }]\ndispatch = [{ source = \"cell\" }]",
                "enqueue ladder must contain `affinity`",
            ),
            (
                "enqueue = [{ target = \"affinity\" }, { target = \"cell\" }]\ndispatch = [{ source = \"affinity\" }, { source = \"cell\" }]",
                "enqueue target `affinity` must be terminal",
            ),
            (
                "enqueue = [{ target = \"cell\" }, { target = \"cell\" }, { target = \"affinity\" }]\ndispatch = [{ source = \"affinity\" }, { source = \"cell\" }]",
                "duplicate enqueue target `cell`",
            ),
            (
                "enqueue = [{ target = \"bogus\" }, { target = \"affinity\" }]\ndispatch = [{ source = \"affinity\" }]",
                "unknown enqueue target `bogus`",
            ),
        ];

        for (callbacks, expected) in cases {
            let source = format!(
                "[queues]\nlayout = \"cell\"\n{callbacks}\n[[rung]]\noperation = \"pick_idle\"\nscope = \"task_allowed\"\n"
            );
            let error = error_for(&source);
            assert!(error.contains(expected), "{error}");
        }
    }

    #[test]
    fn rejects_invalid_queue_dispatch_ladders() {
        let cases = [
            (
                "enqueue = [{ target = \"affinity\" }]\ndispatch = []",
                "dispatch ladder must not be empty",
            ),
            (
                "enqueue = [{ target = \"affinity\" }]\ndispatch = [{ source = \"cell\" }]",
                "dispatch ladder must contain `affinity`",
            ),
            (
                "enqueue = [{ target = \"affinity\" }]\ndispatch = [{ source = \"affinity\" }, { source = \"affinity\" }]",
                "duplicate dispatch source `affinity`",
            ),
            (
                "enqueue = [{ target = \"cell\" }, { target = \"affinity\" }]\ndispatch = [{ source = \"affinity\" }]",
                "dispatch ladder must contain `cell` when enqueue contains `cell`",
            ),
            (
                "enqueue = [{ target = \"affinity\" }]\ndispatch = [{ source = \"affinity\" }, { source = \"cell\" }]",
                "dispatch ladder must not contain `cell` when enqueue omits `cell`",
            ),
            (
                "enqueue = [{ target = \"affinity\" }]\ndispatch = [{ source = \"bogus\" }]",
                "unknown dispatch source `bogus`",
            ),
        ];

        for (callbacks, expected) in cases {
            let source = format!(
                "[queues]\nlayout = \"cell\"\n{callbacks}\n[[rung]]\noperation = \"pick_idle\"\nscope = \"task_allowed\"\n"
            );
            let error = error_for(&source);
            assert!(error.contains(expected), "{error}");
        }
    }

    #[test]
    fn rejects_partially_omitted_queue_callback_ladders() {
        for (callbacks, expected) in [
            (
                "enqueue = [{ target = \"affinity\" }]",
                "dispatch ladder must not be empty",
            ),
            (
                "dispatch = [{ source = \"affinity\" }]",
                "enqueue ladder must not be empty",
            ),
        ] {
            let source = format!(
                "[queues]\nlayout = \"cell\"\n{callbacks}\n[[rung]]\noperation = \"pick_idle\"\nscope = \"task_allowed\"\n"
            );
            let error = error_for(&source);
            assert!(error.contains(expected), "{error}");
        }
    }

    #[test]
    fn rejects_queue_callback_ladders_longer_than_eight_rungs() {
        let enqueue = (0..9)
            .map(|_| "{ target = \"affinity\" }")
            .collect::<Vec<_>>()
            .join(", ");
        let source = format!(
            "[queues]\nlayout = \"cell\"\nenqueue = [{enqueue}]\ndispatch = [{{ source = \"affinity\" }}]\n[[rung]]\noperation = \"pick_idle\"\nscope = \"task_allowed\"\n"
        );

        let error = error_for(&source);
        assert!(error.contains("enqueue ladder has too many rungs: maximum is 8"));
    }

    #[test]
    fn queue_policy_rejects_reserved_cell_zero() {
        let error = error_for(
            r#"
[queues]
layout = "cell"

[[cell]]
id = 0
cpus = "0"

[[rung]]
operation = "pick_idle"
scope = "task_cell"
"#,
        );

        assert!(error.contains("cell ID 0 is reserved"), "{error}");
    }

    #[test]
    fn queue_policy_rejects_more_than_31_declared_cells() {
        let mut source = String::from("[queues]\nlayout = \"cell\"\n");
        for id in 1..=32 {
            source.push_str(&format!("[[cell]]\nid = {id}\ncpus = \"{}\"\n", id - 1));
        }
        source.push_str("[[rung]]\noperation = \"pick_idle\"\nscope = \"task_cell\"\n");

        let error = error_for(&source);
        assert!(error.contains("at most 31 declared cells"), "{error}");
    }

    #[test]
    fn queue_policy_rejects_zero_weights() {
        for source in [
            r#"
[queues]
layout = "cell"
cell0_cpu_weight = 0
[[rung]]
operation = "pick_idle"
scope = "task_allowed"
"#,
            r#"
[queues]
layout = "cell"
[[cell]]
id = 1
cpus = "0"
cpu_weight = 0
[[rung]]
operation = "pick_idle"
scope = "task_cell"
"#,
        ] {
            let error = error_for(source);
            assert!(error.contains("weight must be positive"), "{error}");
        }
    }

    #[test]
    fn cell_weight_requires_queue_policy() {
        let error = error_for(
            r#"
[[cell]]
id = 7
cpus = "0-3"
cpu_weight = 2

[[rung]]
operation = "pick_idle"
scope = "task_cell"
"#,
        );

        assert!(
            error.contains("cpu_weight requires a [queues] policy"),
            "{error}"
        );
    }

    #[test]
    fn rejects_task_cell_scope_without_cell_definitions() {
        let error = error_for(
            r#"
[[rung]]
operation = "pick_idle"
scope = "task_cell"
"#,
        );
        assert!(error.contains("requires at least one cell"));
    }

    #[test]
    fn rejects_duplicate_and_out_of_range_cells() {
        let duplicate = error_for(
            r#"
[[cell]]
id = 7
cpus = "0"
[[cell]]
id = 7
cpus = "1"
[[rung]]
operation = "pick_idle"
scope = "task_cell"
"#,
        );
        assert!(duplicate.contains("duplicate ID 7"));

        let out_of_range = error_for(
            r#"
[[cell]]
id = 1024
cpus = "0"
[[rung]]
operation = "pick_idle"
scope = "task_cell"
"#,
        );
        assert!(out_of_range.contains("exceeds maximum 1023"));
    }

    #[test]
    fn lowers_previous_llc_to_a_topology_blind_mask_table_lookup() {
        let policy = compile_policy(PREVIOUS_LLC_POLICY).expect("policy should compile");

        assert_eq!(
            policy.rungs,
            vec![CompiledRung {
                opcode: Opcode::PickIdleMaskTable,
                input: InputSource::CpuPrev,
                flags: RUNG_FLAG_INTERSECT_TASK_ALLOWED,
                data: 0,
            }]
        );
        assert_eq!(
            policy.mask_tables,
            vec![MaskTableSpec {
                id: 0,
                name: "previous_llc".into(),
                source: MaskTableSource::PreviousLlcByCpu,
            }]
        );
    }

    #[test]
    fn lowers_whole_core_idle_before_any_idle_in_previous_llc() {
        let policy = compile_policy(WHOLE_CORE_LLC_POLICY).expect("policy should compile");

        assert_eq!(
            policy.rungs,
            vec![
                CompiledRung {
                    opcode: Opcode::PickIdleMaskTable,
                    input: InputSource::CpuPrev,
                    flags: RUNG_FLAG_INTERSECT_TASK_ALLOWED | RUNG_FLAG_PICK_IDLE_CORE,
                    data: 0,
                },
                CompiledRung {
                    opcode: Opcode::PickIdleMaskTable,
                    input: InputSource::CpuPrev,
                    flags: RUNG_FLAG_INTERSECT_TASK_ALLOWED,
                    data: 0,
                },
            ]
        );
        assert_eq!(policy.mask_tables.len(), 1);
        assert_eq!(policy.mask_tables[0].name, "previous_llc");
    }

    #[test]
    fn lowers_previous_node_rungs_to_one_shared_mask_table() {
        let policy = compile_policy(PREVIOUS_NODE_POLICY).expect("policy should compile");

        assert_eq!(policy.rungs.len(), 2);
        assert_eq!(
            policy.rungs[0].flags,
            RUNG_FLAG_INTERSECT_TASK_ALLOWED | RUNG_FLAG_PICK_IDLE_CORE
        );
        assert_eq!(policy.rungs[0].data, 0);
        assert_eq!(policy.rungs[1].flags, RUNG_FLAG_INTERSECT_TASK_ALLOWED);
        assert_eq!(policy.rungs[1].data, 0);
        assert_eq!(
            policy.mask_tables,
            vec![MaskTableSpec {
                id: 0,
                name: "previous_node".into(),
                source: MaskTableSource::PreviousNodeByCpu,
            }]
        );
    }

    #[test]
    fn lowers_named_partition_before_its_parent_llc() {
        let policy = compile_policy(SUB_LLC_POLICY).expect("policy should compile");

        assert_eq!(
            policy.rungs,
            vec![
                CompiledRung {
                    opcode: Opcode::PickIdleMaskTable,
                    input: InputSource::CpuPrev,
                    flags: RUNG_FLAG_INTERSECT_TASK_ALLOWED,
                    data: 0,
                },
                CompiledRung {
                    opcode: Opcode::PickIdleMaskTable,
                    input: InputSource::CpuPrev,
                    flags: RUNG_FLAG_INTERSECT_TASK_ALLOWED,
                    data: 1,
                },
            ]
        );
        assert_eq!(
            policy.mask_tables,
            vec![
                MaskTableSpec {
                    id: 0,
                    name: "previous_llc_half".into(),
                    source: MaskTableSource::SplitLlcByCore { parts: 2 },
                },
                MaskTableSpec {
                    id: 1,
                    name: "previous_llc".into(),
                    source: MaskTableSource::PreviousLlcByCpu,
                },
            ]
        );
    }

    #[test]
    fn lowers_random_idle_with_a_neutral_fallback() {
        let policy = compile_policy(RANDOM_IDLE_POLICY).expect("policy should compile");

        assert_eq!(policy.fallback, Fallback::AnyAllowed);
        assert_eq!(
            policy.rungs,
            vec![CompiledRung {
                opcode: Opcode::PickRandomIdle,
                input: InputSource::MaskTaskAllowed,
                flags: 0,
                data: 0,
            }]
        );
        assert!(policy.mask_tables.is_empty());
    }

    #[test]
    fn lowers_random_llc_idle_to_a_topology_blind_mask_table_lookup() {
        let policy = compile_policy(RANDOM_LLC_POLICY).expect("policy should compile");

        assert_eq!(policy.fallback, Fallback::AnyAllowed);
        assert_eq!(
            policy.rungs,
            vec![
                CompiledRung {
                    opcode: Opcode::PickRandomIdle,
                    input: InputSource::CpuPrev,
                    flags: RUNG_FLAG_INTERSECT_TASK_ALLOWED,
                    data: 0,
                },
                CompiledRung {
                    opcode: Opcode::PickRandomIdle,
                    input: InputSource::MaskTaskAllowed,
                    flags: 0,
                    data: 0,
                },
            ]
        );
        assert_eq!(
            policy.mask_tables,
            vec![MaskTableSpec {
                id: 0,
                name: "previous_llc".into(),
                source: MaskTableSource::PreviousLlcByCpu,
            }]
        );
    }

    #[test]
    fn lowers_random_whole_core_idle_with_the_core_flag() {
        let policy = compile_policy(RANDOM_WHOLE_CORE_POLICY).expect("policy should compile");

        assert_eq!(policy.rungs.len(), 3);
        assert_eq!(policy.rungs[0].opcode, Opcode::PickRandomIdle);
        assert_eq!(policy.rungs[0].input, InputSource::CpuPrev);
        assert_eq!(
            policy.rungs[0].flags,
            RUNG_FLAG_INTERSECT_TASK_ALLOWED | RUNG_FLAG_PICK_IDLE_CORE
        );
        assert_eq!(policy.mask_tables.len(), 1);
        assert_eq!(policy.mask_tables[0].name, "previous_llc");
    }

    #[test]
    fn lowers_random_half_llc_before_random_whole_llc() {
        let policy = compile_policy(RANDOM_HALF_LLC_POLICY).expect("policy should compile");

        assert_eq!(policy.fallback, Fallback::AnyAllowed);
        assert_eq!(policy.rungs.len(), 3);
        assert!(policy
            .rungs
            .iter()
            .all(|rung| rung.opcode == Opcode::PickRandomIdle));
        assert_eq!(policy.rungs[0].data, 0);
        assert_eq!(policy.rungs[1].data, 1);
        assert_eq!(policy.rungs[2].input, InputSource::MaskTaskAllowed);
        assert_eq!(
            policy
                .mask_tables
                .iter()
                .map(|table| table.name.as_str())
                .collect::<Vec<_>>(),
            vec!["previous_llc_half", "previous_llc"]
        );
    }

    #[test]
    fn lowers_kernel_default_for_the_task_allowed_scope() {
        let policy = compile_policy(KERNEL_DEFAULT_POLICY).expect("policy should compile");

        assert_eq!(
            policy.rungs,
            vec![CompiledRung {
                opcode: Opcode::KernelDefault,
                input: InputSource::MaskTaskAllowed,
                flags: 0,
                data: 0,
            }]
        );
        assert!(policy.mask_tables.is_empty());
    }

    #[test]
    fn lowers_sync_wake_affine_with_reused_llc_and_node_tables() {
        let policy = compile_policy(SYNC_WAKE_POLICY).expect("policy should compile");

        assert_eq!(policy.rungs.len(), 3);
        assert_eq!(policy.rungs[2].data, (1_u64 << 32) | 0);
        assert!(policy.dump().contains(
            "rung 2: opcode=sync_wake_affine input=mask_task_allowed flags=0x00000000 data=0x0000000100000000"
        ));
        assert_eq!(
            policy
                .mask_tables
                .iter()
                .map(|table| (table.id, table.name.as_str(), table.source))
                .collect::<Vec<_>>(),
            vec![
                (0, "previous_llc", MaskTableSource::PreviousLlcByCpu),
                (1, "previous_node", MaskTableSource::PreviousNodeByCpu),
            ]
        );
    }

    #[test]
    fn golden_kernel_default_simulation_uses_eight_rungs_and_two_tables() {
        let policy =
            compile_policy(KERNEL_DEFAULT_SIM_POLICY).expect("simulation policy should compile");

        assert_eq!(policy.fallback, Fallback::PreviousCpu);
        let queues = policy
            .queues
            .as_ref()
            .expect("kernel-default simulation should shard VTIME queues by LLC");
        assert_eq!(queues.layout, QueueLayout::Llc);
        assert_eq!(
            queues
                .enqueue
                .iter()
                .map(QueueEnqueueRung::describe)
                .collect::<Vec<_>>(),
            ["try_insert(local)", "insert(cpu)"]
        );
        assert_eq!(
            queues
                .dispatch
                .iter()
                .map(QueueDispatchRung::describe)
                .collect::<Vec<_>>(),
            [
                "peek(cpu)",
                "peek(local)",
                "peek(remote)",
                "consume(min_vtime;fallback=cpu,local,remote)",
            ]
        );
        assert_eq!(
            policy.rungs,
            vec![
                CompiledRung {
                    opcode: Opcode::SyncWakeAffine,
                    input: InputSource::MaskTaskAllowed,
                    flags: 0,
                    data: 1_u64 << 32,
                },
                CompiledRung {
                    opcode: Opcode::PickIdleMaskTable,
                    input: InputSource::CpuPrev,
                    flags: RUNG_FLAG_INTERSECT_TASK_ALLOWED | RUNG_FLAG_PICK_IDLE_CORE,
                    data: 0,
                },
                CompiledRung {
                    opcode: Opcode::PickIdleMaskTable,
                    input: InputSource::CpuPrev,
                    flags: RUNG_FLAG_INTERSECT_TASK_ALLOWED | RUNG_FLAG_PICK_IDLE_CORE,
                    data: 1,
                },
                CompiledRung {
                    opcode: Opcode::PickIdle,
                    input: InputSource::MaskTaskAllowed,
                    flags: RUNG_FLAG_PICK_IDLE_CORE,
                    data: 0,
                },
                CompiledRung {
                    opcode: Opcode::ClaimIdle,
                    input: InputSource::CpuPrev,
                    flags: 0,
                    data: 0,
                },
                CompiledRung {
                    opcode: Opcode::PickIdleMaskTable,
                    input: InputSource::CpuPrev,
                    flags: RUNG_FLAG_INTERSECT_TASK_ALLOWED,
                    data: 0,
                },
                CompiledRung {
                    opcode: Opcode::PickIdleMaskTable,
                    input: InputSource::CpuPrev,
                    flags: RUNG_FLAG_INTERSECT_TASK_ALLOWED,
                    data: 1,
                },
                CompiledRung {
                    opcode: Opcode::PickIdle,
                    input: InputSource::MaskTaskAllowed,
                    flags: 0,
                    data: 0,
                },
            ]
        );
        assert_eq!(
            policy.mask_tables,
            vec![
                MaskTableSpec {
                    id: 0,
                    name: "previous_llc".into(),
                    source: MaskTableSource::PreviousLlcByCpu,
                },
                MaskTableSpec {
                    id: 1,
                    name: "previous_node".into(),
                    source: MaskTableSource::PreviousNodeByCpu,
                },
            ]
        );
    }

    #[test]
    fn defaults_existing_policies_to_previous_cpu_fallback() {
        let policy = compile_policy(TWO_RUNG_POLICY).expect("policy should compile");

        assert_eq!(policy.fallback, Fallback::PreviousCpu);
    }

    #[test]
    fn rejects_an_empty_ladder() {
        assert!(error_for("").contains("at least one rung"));
    }

    #[test]
    fn rejects_unknown_operations() {
        let error = error_for(
            r#"
[[rung]]
operation = "spin_the_wheel"
scope = "previous_cpu"
"#,
        );
        assert!(error.contains("unknown operation `spin_the_wheel`"));
    }

    #[test]
    fn rejects_unknown_scopes() {
        let error = error_for(
            r#"
[[rung]]
operation = "claim_idle"
scope = "previous_socket"
"#,
        );
        assert!(error.contains("unknown scope `previous_socket`"));
    }

    #[test]
    fn rejects_incompatible_operation_and_scope() {
        let claim_error = error_for(
            r#"
[[rung]]
operation = "claim_idle"
scope = "task_allowed"
"#,
        );
        assert!(claim_error.contains("claim_idle"));
        assert!(claim_error.contains("task_allowed"));
        assert!(claim_error.contains("incompatible"));

        let llc_claim_error = error_for(
            r#"
[[rung]]
operation = "claim_idle"
scope = "previous_llc"
"#,
        );
        assert!(llc_claim_error.contains("claim_idle"));
        assert!(llc_claim_error.contains("previous_llc"));
        assert!(llc_claim_error.contains("incompatible"));

        let pick_error = error_for(
            r#"
[[rung]]
operation = "pick_idle"
scope = "previous_cpu"
"#,
        );
        assert!(pick_error.contains("pick_idle"));
        assert!(pick_error.contains("previous_cpu"));
        assert!(pick_error.contains("incompatible"));

        let sync_error = error_for(
            r#"
[[rung]]
operation = "sync_wake_affine"
scope = "previous_llc"
"#,
        );
        assert!(sync_error.contains("sync_wake_affine"));
        assert!(sync_error.contains("previous_llc"));
        assert!(sync_error.contains("incompatible"));
    }

    #[test]
    fn rejects_more_than_max_rungs() {
        let source = (0..=MAX_RUNGS)
            .map(|_| {
                r#"
[[rung]]
operation = "claim_idle"
scope = "previous_cpu"
"#
            })
            .collect::<String>();

        let error = error_for(&source);
        assert!(error.contains("too many rungs"));
        assert!(error.contains(&MAX_RUNGS.to_string()));
    }

    #[test]
    fn rejects_missing_required_rung_fields() {
        let missing_operation = error_for(
            r#"
[[rung]]
scope = "previous_cpu"
"#,
        );
        assert!(missing_operation.contains("operation"));

        let missing_scope = error_for(
            r#"
[[rung]]
operation = "claim_idle"
"#,
        );
        assert!(missing_scope.contains("scope"));
    }

    #[test]
    fn rejects_invalid_partition_declarations() {
        let one_part = error_for(
            r#"
[[partition]]
name = "too_small"
provider = "split_llcs"
parts = 1

[[rung]]
operation = "pick_idle"
scope = "too_small"
"#,
        );
        assert!(one_part.contains("at least two parts"));

        let unknown_provider = error_for(
            r#"
[[partition]]
name = "custom"
provider = "unknown"
parts = 2

[[rung]]
operation = "pick_idle"
scope = "custom"
"#,
        );
        assert!(unknown_provider.contains("unknown provider `unknown`"));

        let reserved_name = error_for(
            r#"
[[partition]]
name = "previous_llc"
provider = "split_llcs"
parts = 2

[[rung]]
operation = "pick_idle"
scope = "previous_llc"
"#,
        );
        assert!(reserved_name.contains("name `previous_llc` is reserved"));

        let duplicate_name = error_for(
            r#"
[[partition]]
name = "duplicate"
provider = "split_llcs"
parts = 2

[[partition]]
name = "duplicate"
provider = "split_llcs"
parts = 3

[[rung]]
operation = "pick_idle"
scope = "duplicate"
"#,
        );
        assert!(duplicate_name.contains("duplicate name `duplicate`"));
    }

    #[test]
    fn rejects_unknown_fallbacks() {
        let error = error_for(
            r#"
fallback = "nearest_moon"

[[rung]]
operation = "pick_idle"
scope = "task_allowed"
"#,
        );

        assert!(error.contains("unknown fallback `nearest_moon`"));
    }

    #[test]
    fn rejects_a_nonterminal_kernel_default_rung() {
        let error = error_for(
            r#"
[[rung]]
operation = "kernel_default"
scope = "task_allowed"

[[rung]]
operation = "pick_idle"
scope = "task_allowed"
"#,
        );

        assert!(error.contains("kernel_default"));
        assert!(error.contains("last rung"));
    }

    #[test]
    fn dumps_compiled_instructions() {
        let policy = compile_policy(TWO_RUNG_POLICY).expect("policy should compile");

        assert_eq!(
            policy.dump(),
            concat!(
                "fallback: previous_cpu\n",
                "rung 0: opcode=claim_idle input=cpu_prev flags=0x00000000 data=0x0000000000000000\n",
                "rung 1: opcode=pick_idle input=mask_task_allowed flags=0x00000000 data=0x0000000000000000\n",
            )
        );
    }

    #[test]
    fn compiles_userspace_membership_policy() {
        let policy = compile_policy(
            r#"
[queues]
layout = "cell"

[membership]
parent = "/sys/fs/cgroup/workloads"
reconcile_ms = 250

[[membership.assignment]]
child = "batch"
cell = 1

[[cell]]
id = 1
cpus = "0-3"

[[rung]]
operation = "pick_idle"
scope = "task_cell"
"#,
        )
        .expect("membership policy should compile");

        let membership = policy.membership.expect("membership should be present");
        assert_eq!(membership.parent, "/sys/fs/cgroup/workloads");
        assert_eq!(membership.reconcile_ms, 250);
        assert_eq!(membership.assignments.get("batch"), Some(&1));
    }

    #[test]
    fn membership_requires_queue_mode_and_defined_cells() {
        let without_queues = error_for(
            r#"
[membership]
parent = "/sys/fs/cgroup/workloads"
[[membership.assignment]]
child = "batch"
cell = 1
[[rung]]
operation = "pick_idle"
scope = "task_allowed"
"#,
        );
        assert!(without_queues.contains("membership requires a [queues] policy"));

        let unknown_cell = error_for(
            r#"
[queues]
layout = "cell"
[membership]
parent = "/sys/fs/cgroup/workloads"
[[membership.assignment]]
child = "batch"
cell = 7
[[rung]]
operation = "pick_idle"
scope = "task_allowed"
"#,
        );
        assert!(unknown_cell.contains("undefined cell 7"));
    }

    #[test]
    fn membership_rejects_ambiguous_paths_and_duplicate_children() {
        for (parent, child, expected) in [
            ("workloads", "batch", "parent must be an absolute path"),
            (
                "/sys/fs/cgroup/workloads",
                "batch/subgroup",
                "child must be one path component",
            ),
            (
                "/sys/fs/cgroup/workloads",
                "..",
                "child must be one path component",
            ),
        ] {
            let error = error_for(&format!(
                r#"
[queues]
layout = "cell"
[membership]
parent = "{parent}"
[[membership.assignment]]
child = "{child}"
cell = 1
[[cell]]
id = 1
cpus = "0"
[[rung]]
operation = "pick_idle"
scope = "task_cell"
"#
            ));
            assert!(error.contains(expected), "{error}");
        }

        let duplicate = error_for(
            r#"
[queues]
layout = "cell"
[membership]
parent = "/sys/fs/cgroup/workloads"
[[membership.assignment]]
child = "batch"
cell = 1
[[membership.assignment]]
child = "batch"
cell = 2
[[cell]]
id = 1
cpus = "0"
[[cell]]
id = 2
cpus = "1"
[[rung]]
operation = "pick_idle"
scope = "task_cell"
"#,
        );
        assert!(duplicate.contains("duplicate child `batch`"));
    }
}
