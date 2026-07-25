// SPDX-License-Identifier: GPL-2.0-only

use std::collections::BTreeMap;
use std::fmt;

use serde::Deserialize;

pub const MAX_RUNGS: usize = 8;
pub const MAX_MASK_TABLES: usize = 4;
pub const RUNG_FLAG_INTERSECT_TASK_ALLOWED: u32 = 1;
pub const RUNG_FLAG_PICK_IDLE_CORE: u32 = 1 << 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Opcode {
    ClaimIdle = 1,
    PickIdle = 2,
    PickIdleMaskTable = 3,
    PickRandomIdle = 4,
    KernelDefault = 5,
    SyncWakeAffine = 6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum InputSource {
    CpuPrev = 1,
    MaskTaskAllowed = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct CompiledRung {
    pub opcode: Opcode,
    pub input: InputSource,
    pub flags: u32,
    pub data: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub struct CompiledPolicy {
    pub fallback: Fallback,
    pub rungs: Vec<CompiledRung>,
    pub mask_tables: Vec<MaskTableSpec>,
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
        }
    }
}

impl InputSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::CpuPrev => "cpu_prev",
            Self::MaskTaskAllowed => "mask_task_allowed",
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
    #[serde(default)]
    partition: Vec<SemanticPartition>,
    #[serde(default)]
    rung: Vec<SemanticRung>,
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

    let partitions = compile_partitions(&policy.partition)?;
    let mut mask_tables = Vec::new();
    let mut rungs = Vec::with_capacity(policy.rung.len());
    for (index, rung) in policy.rung.iter().enumerate() {
        rungs.push(compile_rung(index, rung, &partitions, &mut mask_tables)?);
    }

    Ok(CompiledPolicy {
        fallback,
        rungs,
        mask_tables,
    })
}

fn compile_partitions(
    partitions: &[SemanticPartition],
) -> Result<BTreeMap<String, MaskTableSource>, PolicyError> {
    let mut compiled = BTreeMap::new();

    for (index, partition) in partitions.iter().enumerate() {
        if matches!(
            partition.name.as_str(),
            "previous_cpu" | "previous_llc" | "previous_node" | "task_allowed"
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
    mask_tables: &mut Vec<MaskTableSpec>,
) -> Result<CompiledRung, PolicyError> {
    if !matches!(
        rung.scope.as_str(),
        "previous_cpu" | "previous_llc" | "previous_node" | "task_allowed"
    ) && !partitions.contains_key(&rung.scope)
    {
        return Err(PolicyError(format!(
            "rung {index}: unknown scope `{}`",
            rung.scope
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
        "pick_random_idle" if rung.scope == "task_allowed" => Ok(CompiledRung {
            opcode: Opcode::PickRandomIdle,
            input: InputSource::MaskTaskAllowed,
            flags: 0,
            data: 0,
        }),
        "pick_random_idle" => Err(PolicyError(format!(
            "rung {index}: operation `{}` is incompatible with scope `{}`",
            rung.operation, rung.scope
        ))),
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
}
