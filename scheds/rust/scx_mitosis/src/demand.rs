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

#[cfg(test)]
mod tests {
    use super::*;

    const INTERVAL: Duration = Duration::from_secs(1);

    fn cpu(owner: u32, running_ns: &[(usize, u64)]) -> bpf_intf::cpu_ctx {
        let mut ctx = bpf_intf::cpu_ctx {
            pinned_waiting_since: 0,
            cstats: [[0; crate::NR_CSTATS]; MAX_CELLS],
            cell_cycles: [0; MAX_CELLS],
            running_ns: [0; MAX_CELLS],
            vtime_now: 0,
            cell: owner,
            subcell: 0,
            llc: 0,
        };
        for &(cell, ns) in running_ns {
            ctx.running_ns[cell] = ns;
        }
        ctx
    }

    fn sample(
        sampler: &mut DemandSampler,
        cpus: &[bpf_intf::cpu_ctx],
        sampled_at: Instant,
    ) -> DemandSample {
        sampler
            .sample(cpus, sampled_at, INTERVAL)
            .expect("valid CPU snapshot")
            .expect("sampling interval elapsed")
    }

    fn assert_runtime(sample: &DemandSample, running: [u64; 2], own: [u64; 2], lent: [u64; 2]) {
        assert_eq!(sample.running_ns[..2], running);
        assert_eq!(sample.on_own_ns[..2], own);
        assert_eq!(sample.lent_ns[..2], lent);
    }

    #[test]
    fn first_sample_seeds_counters() {
        let t = Instant::now();
        let cpus = [
            cpu(0, &[(0, 100_000_000_000), (1, 10_000_000_000)]),
            cpu(1, &[(1, 200_000_000_000)]),
        ];
        let mut sampler = DemandSampler::default();

        assert!(sampler.sample(&cpus, t, INTERVAL).unwrap().is_none());
        let sample = sample(&mut sampler, &cpus, t + INTERVAL);
        assert_eq!(sample.interval_ns, 1_000_000_000);
        assert_eq!(sample.running_ns, [0; MAX_CELLS]);
        assert_eq!(sample.on_own_ns, [0; MAX_CELLS]);
        assert_eq!(sample.lent_ns, [0; MAX_CELLS]);
    }

    #[test]
    fn stable_owners_count_new_runtime() {
        let t = Instant::now();
        let before = [
            cpu(0, &[(0, 100_000_000_000)]),
            cpu(1, &[(1, 200_000_000_000)]),
        ];
        let after = [
            cpu(0, &[(0, 100_400_000_000), (1, 100_000_000)]),
            cpu(1, &[(0, 100_000_000), (1, 200_400_000_000)]),
        ];
        let mut sampler = DemandSampler::default();
        sampler.sample(&before, t, INTERVAL).unwrap();

        let sample = sample(&mut sampler, &after, t + INTERVAL);
        assert_runtime(
            &sample,
            [500_000_000, 500_000_000],
            [400_000_000, 400_000_000],
            [100_000_000, 100_000_000],
        );
    }

    #[test]
    fn owner_swap_without_runtime_has_no_lending() {
        let t = Instant::now();
        let history = 433_535_600_000;
        let before = [cpu(0, &[(0, history)]), cpu(1, &[(1, history)])];
        let swapped = [cpu(1, &[(0, history)]), cpu(0, &[(1, history)])];
        let mut sampler = DemandSampler::default();
        sampler.sample(&before, t, INTERVAL).unwrap();

        for (i, cpus) in [&swapped, &before].into_iter().enumerate() {
            let sample = sample(&mut sampler, cpus, t + INTERVAL * (i as u32 + 1));
            assert_eq!(sample.running_ns, [0; MAX_CELLS]);
            assert_eq!(sample.on_own_ns, [0; MAX_CELLS]);
            assert_eq!(sample.lent_ns, [0; MAX_CELLS]);
        }
    }

    #[test]
    fn owner_swap_attributes_only_interval_runtime() {
        let t = Instant::now();
        let before = [
            cpu(0, &[(0, 100_000_000_000), (1, 10_000_000_000)]),
            cpu(1, &[]),
        ];
        // Swap at the start of the interval, then run both task cells on both CPUs.
        let after = [
            cpu(1, &[(0, 100_100_000_000), (1, 10_150_000_000)]),
            cpu(0, &[(0, 400_000_000), (1, 350_000_000)]),
        ];
        let mut sampler = DemandSampler::default();
        sampler.sample(&before, t, INTERVAL).unwrap();

        let sample = sample(&mut sampler, &after, t + INTERVAL);
        assert_runtime(
            &sample,
            [500_000_000, 500_000_000],
            [400_000_000, 150_000_000],
            [350_000_000, 100_000_000],
        );
    }

    #[test]
    fn borrowing_and_lending_conserve_runtime_across_reassignments() {
        let t = Instant::now();
        let before = [
            cpu(0, &[(0, 1_000), (1, 400), (2, 500)]),
            cpu(1, &[(0, 300), (1, 2_000), (2, 700)]),
            cpu(2, &[(0, 600), (1, 800), (2, 3_000)]),
        ];
        let snapshots = [
            [
                cpu(1, &[(0, 1_030), (1, 410), (2, 520)]),
                cpu(2, &[(0, 320), (1, 2_030), (2, 710)]),
                cpu(0, &[(0, 610), (1, 820), (2, 3_030)]),
            ],
            [
                cpu(2, &[(0, 1_060), (1, 420), (2, 540)]),
                cpu(0, &[(0, 340), (1, 2_060), (2, 720)]),
                cpu(1, &[(0, 620), (1, 840), (2, 3_060)]),
            ],
        ];
        let mut sampler = DemandSampler::default();
        sampler.sample(&before, t, INTERVAL).unwrap();

        for (i, cpus) in snapshots.iter().enumerate() {
            let sample = sample(&mut sampler, cpus, t + INTERVAL * (i as u32 + 1));
            let borrowed: u64 = sample
                .running_ns
                .iter()
                .zip(&sample.on_own_ns)
                .map(|(&running, &own)| running - own)
                .sum();
            assert_eq!(sample.running_ns.iter().sum::<u64>(), 180);
            assert_eq!(borrowed, sample.lent_ns.iter().sum::<u64>());
        }
    }

    #[test]
    fn skipped_samples_preserve_counter_and_time_baselines() {
        let t = Instant::now();
        let before = [cpu(0, &[(0, 100_000_000_000), (1, 10_000_000_000)])];
        let skipped = [cpu(1, &[(0, 100_100_000_000), (1, 10_050_000_000)])];
        let after = [cpu(1, &[(0, 100_300_000_000), (1, 10_150_000_000)])];
        let mut sampler = DemandSampler::default();
        sampler.sample(&before, t, INTERVAL).unwrap();

        assert!(
            sampler
                .sample(&skipped, t + Duration::from_millis(250), INTERVAL)
                .unwrap()
                .is_none()
        );
        let sample = sample(&mut sampler, &after, t + Duration::from_millis(750));
        assert_eq!(sample.interval_ns, 750_000_000);
        assert_runtime(
            &sample,
            [300_000_000, 150_000_000],
            [0, 150_000_000],
            [0, 300_000_000],
        );
    }

    #[test]
    fn decreased_counter_becomes_next_baseline() {
        let t = Instant::now();
        let mut sampler = DemandSampler::default();
        sampler
            .sample(&[cpu(0, &[(0, 100), (1, 100)])], t, INTERVAL)
            .unwrap();

        let reset = sample(&mut sampler, &[cpu(0, &[(0, 10), (1, 105)])], t + INTERVAL);
        assert_runtime(&reset, [0, 5], [0, 0], [5, 0]);

        let next = sample(
            &mut sampler,
            &[cpu(0, &[(0, 15), (1, 106)])],
            t + INTERVAL * 2,
        );
        assert_runtime(&next, [5, 1], [5, 0], [1, 0]);
    }

    #[test]
    fn tracks_task_cells_without_cpu_ownership() {
        let t = Instant::now();
        let cell = MAX_CELLS - 1;
        let mut sampler = DemandSampler::default();
        sampler
            .sample(&[cpu(0, &[(cell, 100_000_000_000)])], t, INTERVAL)
            .unwrap();

        for i in 1..=2 {
            let sample = sample(
                &mut sampler,
                &[cpu(0, &[(cell, 100_000_000_000 + u64::from(i) * 10)])],
                t + INTERVAL * i,
            );
            assert_eq!(sample.running_ns[cell], 10);
            assert_eq!(sample.on_own_ns[cell], 0);
            assert_eq!(sample.lent_ns[0], 10);
        }
    }

    #[test]
    fn invalid_owner_does_not_advance_baselines() {
        let t = Instant::now();
        let mut sampler = DemandSampler::default();
        sampler
            .sample(&[cpu(0, &[(0, 100)]), cpu(1, &[(1, 100)])], t, INTERVAL)
            .unwrap();

        let invalid = [cpu(0, &[(0, 150)]), cpu(MAX_CELLS as u32, &[(1, 150)])];
        assert!(sampler.sample(&invalid, t + INTERVAL, INTERVAL).is_err());

        let next = sample(
            &mut sampler,
            &[cpu(0, &[(0, 200)]), cpu(1, &[(1, 200)])],
            t + INTERVAL * 2,
        );
        assert_eq!(next.interval_ns, 2_000_000_000);
        assert_runtime(&next, [100, 100], [100, 100], [0, 0]);
    }
}
