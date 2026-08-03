// SPDX-License-Identifier: GPL-2.0-only

use std::fs;
use std::path::Path;

use serde::Serialize;

use crate::bpf_intf;
use crate::managed_cells::resolve_managed_cells;
use crate::mask_tables::resolve_mask_tables;
use crate::policy::{self, CompiledPolicy};
use crate::queue_topology::resolve_host_queue_topology;

const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Serialize)]
struct ValidationLimits {
    placement_rungs: usize,
    generic_placement_rungs: usize,
    queue_rungs: usize,
    mask_tables: usize,
}

#[derive(Debug, Serialize)]
struct ValidationSummary {
    rung_count: usize,
    mask_table_count: usize,
    cell_count: usize,
    queue_policy: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    queue_layout: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    direct_dispatch: Option<bool>,
}

#[derive(Debug, Serialize)]
struct ValidationError {
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    column: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct ValidationReport {
    schema_version: u32,
    valid: bool,
    abi_version: u32,
    limits: ValidationLimits,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy: Option<ValidationSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ValidationError>,
}

impl ValidationReport {
    pub fn is_valid(&self) -> bool {
        self.valid
    }

    fn success(policy: &CompiledPolicy) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            valid: true,
            abi_version: bpf_intf::SNAKE_ABI_VERSION,
            limits: validation_limits(),
            policy: Some(ValidationSummary {
                rung_count: policy.rungs.len(),
                mask_table_count: policy.mask_tables.len(),
                cell_count: policy.cells.len(),
                queue_policy: policy.queues.is_some(),
                queue_layout: policy.queues.as_ref().map(|queues| queues.layout.as_str()),
                direct_dispatch: policy.queues.as_ref().map(|queues| queues.direct_dispatch),
            }),
            error: None,
        }
    }

    fn failure(error: ValidationError) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            valid: false,
            abi_version: bpf_intf::SNAKE_ABI_VERSION,
            limits: validation_limits(),
            policy: None,
            error: Some(error),
        }
    }
}

fn validation_limits() -> ValidationLimits {
    ValidationLimits {
        placement_rungs: policy::MAX_RUNGS,
        generic_placement_rungs: policy::MAX_GENERIC_RUNGS,
        queue_rungs: policy::MAX_QUEUE_RUNGS,
        mask_tables: policy::MAX_MASK_TABLES,
    }
}

fn source_line_column(source: &str, offset: usize) -> Option<(usize, usize)> {
    let prefix = source.get(..offset)?;
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix, |(_, current_line)| current_line)
        .chars()
        .count()
        + 1;
    Some((line, column))
}

pub fn validate_policy_file(path: &Path) -> ValidationReport {
    let source = match fs::read_to_string(path) {
        Ok(source) => source,
        Err(error) => {
            return ValidationReport::failure(ValidationError {
                code: "policy_read_failed",
                message: format!("reading policy {}: {error}", path.display()),
                line: None,
                column: None,
            });
        }
    };
    validate_policy_source(&source)
}

pub fn validate_policy_source(source: &str) -> ValidationReport {
    let mut policy = match policy::compile_policy(&source) {
        Ok(policy) => policy,
        Err(error) => {
            let location = error
                .source_span(&source)
                .and_then(|span| source_line_column(&source, span.start));
            return ValidationReport::failure(ValidationError {
                code: error.code(),
                message: error.to_string(),
                line: location.map(|(line, _)| line),
                column: location.map(|(_, column)| column),
            });
        }
    };
    if let Err(error) = resolve_managed_cells(&mut policy) {
        return ValidationReport::failure(ValidationError {
            code: "managed_cell_resolution_failed",
            message: format!("{error:#}"),
            line: None,
            column: None,
        });
    }
    if let Err(error) = resolve_mask_tables(&policy) {
        return ValidationReport::failure(ValidationError {
            code: "mask_resolution_failed",
            message: format!("{error:#}"),
            line: None,
            column: None,
        });
    }
    if let Err(error) = resolve_host_queue_topology(&policy) {
        return ValidationReport::failure(ValidationError {
            code: "queue_topology_resolution_failed",
            message: format!("{error:#}"),
            line: None,
            column: None,
        });
    }
    ValidationReport::success(&policy)
}
