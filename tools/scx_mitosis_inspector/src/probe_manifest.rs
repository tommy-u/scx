// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use crate::ProbeManifestRow;

#[derive(Clone, Copy, Debug)]
pub struct ProbeManifestInputs {
    pub callback_timing_sample_rate: u32,
    pub event_timing_sample_rate: u32,
    pub dsq_enabled: bool,
    pub dsq_available: bool,
    pub scheduler_events_enabled: bool,
    pub irqs_enabled: bool,
    pub hardirq_available: bool,
    pub block_io_enabled: bool,
    pub block_io_available: bool,
    pub runtime_accounting_enabled: bool,
}

pub fn build_probe_manifest(inputs: ProbeManifestInputs) -> Vec<ProbeManifestRow> {
    vec![
        row("Callback counters", "active", "Exact", "Mitosis callbacks"),
        sampled_row(
            "Callback latency",
            inputs.callback_timing_sample_rate,
            "Mitosis callbacks",
        ),
        sampled_row(
            "Scheduler timing and CPU runtime",
            inputs.event_timing_sample_rate,
            "Whole host",
        ),
        row("CPU migrations", "active", "Exact", "Whole host"),
        requested_row(
            "DSQ performance",
            inputs.dsq_enabled,
            inputs.dsq_available,
            "Exact",
            "Whole host",
        ),
        requested_row(
            "Scheduler activity",
            inputs.scheduler_events_enabled,
            inputs.scheduler_events_enabled,
            "Exact",
            "Whole host",
        ),
        requested_row(
            "Softirq timing",
            inputs.irqs_enabled,
            inputs.irqs_enabled,
            "Exact",
            "Whole host",
        ),
        requested_row(
            "Hard IRQ timing",
            inputs.irqs_enabled,
            inputs.hardirq_available,
            "Exact",
            "Whole host",
        ),
        requested_row(
            "Block I/O",
            inputs.block_io_enabled,
            inputs.block_io_available,
            "Exact",
            "Whole host",
        ),
        row(
            "Inspector runtime accounting",
            if inputs.runtime_accounting_enabled {
                "active"
            } else {
                "unavailable"
            },
            "Kernel cumulative",
            "Inspector BPF",
        ),
    ]
}

fn sampled_row(group: &'static str, rate: u32, scope: &'static str) -> ProbeManifestRow {
    if rate == 0 {
        row(group, "disabled", "Off", scope)
    } else {
        row(group, "active", format!("Sampled 1/{rate}"), scope)
    }
}

fn requested_row(
    group: &'static str,
    enabled: bool,
    available: bool,
    mode: &'static str,
    scope: &'static str,
) -> ProbeManifestRow {
    let status = if !enabled {
        "disabled"
    } else if available {
        "active"
    } else {
        "unavailable"
    };
    row(group, status, mode, scope)
}

fn row(
    group: &'static str,
    status: &'static str,
    mode: impl Into<String>,
    scope: &'static str,
) -> ProbeManifestRow {
    ProbeManifestRow {
        group,
        status,
        mode: mode.into(),
        scope,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinguishes_disabled_and_unavailable_groups() {
        let rows = build_probe_manifest(ProbeManifestInputs {
            callback_timing_sample_rate: 1024,
            event_timing_sample_rate: 0,
            dsq_enabled: true,
            dsq_available: false,
            scheduler_events_enabled: false,
            irqs_enabled: true,
            hardirq_available: true,
            block_io_enabled: true,
            block_io_available: false,
            runtime_accounting_enabled: false,
        });

        assert_eq!(rows[1].mode, "Sampled 1/1024");
        assert_eq!(rows[2].status, "disabled");
        assert_eq!(rows[4].status, "unavailable");
        assert_eq!(rows[5].status, "disabled");
        assert_eq!(rows[8].status, "unavailable");
    }
}
