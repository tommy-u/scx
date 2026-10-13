// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::time::{Duration, Instant};

use anyhow::{Result, bail};

use crate::{MAX_CELLS, bpf_intf};

/// Runtime deltas over one accepted demand sampling interval.
pub struct DemandSample {
    pub interval_ns: u64,
    pub running_ns: [u64; MAX_CELLS],
    pub on_own_ns: [u64; MAX_CELLS],
    pub lent_ns: [u64; MAX_CELLS],
}

#[derive(Default)]
pub struct DemandSampler {
    // read_cpu_ctxs() returns all possible CPUs in CPU-ID order. Keep the
    // baselines in that order, independent of changing CPU ownership.
    prev_cpu_running_ns: Vec<[u64; MAX_CELLS]>,
    sampled_at: Option<Instant>,
}

impl DemandSampler {
    pub fn sample(
        &mut self,
        cpu_ctxs: &[bpf_intf::cpu_ctx],
        sampled_at: Instant,
        monitor_interval: Duration,
    ) -> Result<Option<DemandSample>> {
        // Events can wake the loop early. A skipped sample must leave both
        // the counters and their timestamp at the last accepted sample.
        let interval_ns = match self.sampled_at {
            Some(prev) if sampled_at.duration_since(prev) < monitor_interval / 2 => {
                return Ok(None);
            }
            Some(prev) => Some(sampled_at.duration_since(prev).as_nanos() as u64),
            None => None,
        };

        // Validate the whole snapshot before advancing any baselines.
        for (cpu, ctx) in cpu_ctxs.iter().enumerate() {
            if ctx.cell as usize >= MAX_CELLS {
                bail!(
                    "CPU {} has invalid cell assignment {} (MAX_CELLS={})",
                    cpu,
                    ctx.cell,
                    MAX_CELLS
                );
            }
        }

        let mut running_ns = [0u64; MAX_CELLS];
        let mut on_own_ns = [0u64; MAX_CELLS];
        let mut lent_ns = [0u64; MAX_CELLS];

        for (cpu, ctx) in cpu_ctxs.iter().enumerate() {
            let owner = ctx.cell as usize;
            // A CPU without a baseline only seeds its counters.
            let prev = self.prev_cpu_running_ns.get(cpu).unwrap_or(&ctx.running_ns);
            for cell in 0..MAX_CELLS {
                // Subtract before grouping by owner so reassignment cannot
                // import runtime accumulated under a previous owner. Charge
                // the whole interval to the owner in this snapshot.
                let delta = ctx.running_ns[cell].saturating_sub(prev[cell]);
                running_ns[cell] += delta;
                if owner == cell {
                    on_own_ns[cell] += delta;
                } else {
                    lent_ns[owner] += delta;
                }
            }
        }

        // Preserve every task-cell slot, including cells currently inactive.
        self.prev_cpu_running_ns.clear();
        self.prev_cpu_running_ns
            .extend(cpu_ctxs.iter().map(|ctx| ctx.running_ns));
        self.sampled_at = Some(sampled_at);

        // The first call only seeds the counters and timestamp.
        Ok(interval_ns.map(|interval_ns| DemandSample {
            interval_ns,
            running_ns,
            on_own_ns,
            lent_ns,
        }))
    }
}
