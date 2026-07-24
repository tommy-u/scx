// SPDX-License-Identifier: GPL-2.0-only

use std::fmt;

use serde::Deserialize;

pub const MAX_RUNGS: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Opcode {
    ClaimIdle = 1,
    PickIdle = 2,
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

    let rungs = policy
        .rung
        .iter()
        .enumerate()
        .map(|(index, rung)| compile_rung(index, rung))
        .collect::<Result<_, _>>()?;

    Ok(CompiledPolicy { rungs })
}

fn compile_rung(index: usize, rung: &SemanticRung) -> Result<CompiledRung, PolicyError> {
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
        scope => {
            return Err(PolicyError(format!(
                "rung {index}: unknown scope `{scope}`"
            )))
        }
    };

    if !matches!(
        (opcode, input),
        (Opcode::ClaimIdle, InputSource::CpuPrev)
            | (Opcode::PickIdle, InputSource::MaskTaskAllowed)
    ) {
        return Err(PolicyError(format!(
            "rung {index}: operation `{}` is incompatible with scope `{}`",
            rung.operation, rung.scope
        )));
    }

    Ok(CompiledRung {
        opcode,
        input,
        flags: 0,
        data: 0,
    })
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
scope = "previous_llc"
"#,
        );
        assert!(error.contains("unknown scope `previous_llc`"));
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
