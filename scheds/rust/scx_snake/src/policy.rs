// SPDX-License-Identifier: GPL-2.0-only

use std::fmt;

use serde::Deserialize;

pub const MAX_RUNGS: usize = 8;
pub const RUNG_FLAG_INTERSECT_TASK_ALLOWED: u32 = 1;
pub const PREVIOUS_LLC_TABLE_ID: u32 = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Opcode {
    ClaimIdle = 1,
    PickIdle = 2,
    PickIdleMaskTable = 3,
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
    pub rungs: Vec<CompiledRung>,
    pub mask_tables: Vec<MaskTableSpec>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaskTableSource {
    PreviousLlcByCpu,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaskTableSpec {
    pub id: u32,
    pub source: MaskTableSource,
}

impl CompiledPolicy {
    pub fn dump(&self) -> String {
        self.rungs
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
            .collect()
    }
}

impl Opcode {
    fn as_str(self) -> &'static str {
        match self {
            Self::ClaimIdle => "claim_idle",
            Self::PickIdle => "pick_idle",
            Self::PickIdleMaskTable => "pick_idle_mask_table",
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
    #[serde(default)]
    rung: Vec<SemanticRung>,
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

    let mut rungs = Vec::with_capacity(policy.rung.len());
    let mut mask_tables = Vec::new();
    for (index, rung) in policy.rung.iter().enumerate() {
        let (compiled, mask_table) = compile_rung(index, rung)?;
        rungs.push(compiled);
        if let Some(mask_table) = mask_table {
            if !mask_tables.contains(&mask_table) {
                mask_tables.push(mask_table);
            }
        }
    }

    Ok(CompiledPolicy { rungs, mask_tables })
}

fn compile_rung(
    index: usize,
    rung: &SemanticRung,
) -> Result<(CompiledRung, Option<MaskTableSpec>), PolicyError> {
    let opcode = match rung.operation.as_str() {
        "claim_idle" => Opcode::ClaimIdle,
        "pick_idle" => Opcode::PickIdle,
        operation => {
            return Err(PolicyError(format!(
                "rung {index}: unknown operation `{operation}`"
            )))
        }
    };

    let input = match rung.scope.as_str() {
        "previous_cpu" => InputSource::CpuPrev,
        "task_allowed" => InputSource::MaskTaskAllowed,
        "previous_llc" => InputSource::CpuPrev,
        scope => {
            return Err(PolicyError(format!(
                "rung {index}: unknown scope `{scope}`"
            )))
        }
    };

    let compatible = matches!(
        (rung.operation.as_str(), rung.scope.as_str()),
        ("claim_idle", "previous_cpu")
            | ("pick_idle", "task_allowed")
            | ("pick_idle", "previous_llc")
    );
    if !compatible {
        return Err(PolicyError(format!(
            "rung {index}: operation `{}` is incompatible with scope `{}`",
            rung.operation, rung.scope
        )));
    }

    let (opcode, flags, data, mask_table) = if rung.scope == "previous_llc" {
        (
            Opcode::PickIdleMaskTable,
            RUNG_FLAG_INTERSECT_TASK_ALLOWED,
            PREVIOUS_LLC_TABLE_ID as u64,
            Some(MaskTableSpec {
                id: PREVIOUS_LLC_TABLE_ID,
                source: MaskTableSource::PreviousLlcByCpu,
            }),
        )
    } else {
        (opcode, 0, 0, None)
    };

    Ok((
        CompiledRung {
            opcode,
            input,
            flags,
            data,
        },
        mask_table,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

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
                data: PREVIOUS_LLC_TABLE_ID as u64,
            }]
        );
        assert_eq!(
            policy.mask_tables,
            vec![MaskTableSpec {
                id: PREVIOUS_LLC_TABLE_ID,
                source: MaskTableSource::PreviousLlcByCpu,
            }]
        );
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
scope = "previous_node"
"#,
        );
        assert!(error.contains("unknown scope `previous_node`"));
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
    fn dumps_compiled_instructions() {
        let policy = compile_policy(TWO_RUNG_POLICY).expect("policy should compile");

        assert_eq!(
            policy.dump(),
            concat!(
                "rung 0: opcode=claim_idle input=cpu_prev flags=0x00000000 data=0x0000000000000000\n",
                "rung 1: opcode=pick_idle input=mask_task_allowed flags=0x00000000 data=0x0000000000000000\n",
            )
        );
    }
}
