// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};

const SHARDS: usize = crate::bpf_intf::consts_DSQ_DEPTH_SHARDS as usize;
const BUCKETS: usize = crate::bpf_intf::consts_DSQ_DEPTH_BUCKETS as usize;
const WINDOW: Duration = Duration::from_secs(60);

pub type Snapshot = [[u64; BUCKETS]; SHARDS];

/// Pool enqueue observations, using wrapping deltas of cumulative counters.
pub fn summarize_delta(previous: &Snapshot, current: &Snapshot) -> u64 {
    // Each individual delta fits u64, but their pooled count need not.
    let mut buckets = [0u128; BUCKETS];
    for shard in 0..SHARDS {
        for (bucket, count) in buckets.iter_mut().enumerate() {
            *count += current[shard][bucket].wrapping_sub(previous[shard][bucket]) as u128;
        }
    }
    let total: u128 = buckets.iter().sum();
    if total == 0 {
        return 0;
    }
    let rank = total - total / 100;
    let mut cumulative = 0;
    for (bucket, count) in buckets.iter().enumerate() {
        cumulative += count;
        if cumulative >= rank {
            return if bucket == BUCKETS - 1 {
                16384
            } else {
                (1u64 << bucket) - 1
            };
        }
    }
    unreachable!("P99 rank must be in the histogram")
}

struct CellWindow {
    cgroup_id: u64,
    baseline: Snapshot,
    sampled_at: Instant,
    p99: u64,
}

#[derive(Default)]
pub struct DsqDepthStats {
    // Validated cell IDs bound this map to MAX_CELLS entries.
    cells: BTreeMap<u32, CellWindow>,
}

impl DsqDepthStats {
    pub fn reconcile(
        &mut self,
        identities: &[(u64, u32)],
        now: Instant,
        mut read: impl FnMut(u32) -> Result<Snapshot>,
    ) -> Result<()> {
        let mut active = BTreeMap::new();
        for &(cgroup_id, cell_id) in identities {
            if cell_id >= crate::bpf_intf::consts_MAX_CELLS {
                bail!("DSQ depth cell ID {} exceeds MAX_CELLS", cell_id);
            }
            active.insert(cell_id, cgroup_id);
        }
        // Cell 0 is permanent, regardless of the root cgroup's inode.
        active.insert(0, 0);

        // Seed only new owners. CPU or subcell changes keep the same window.
        let mut seeds = Vec::new();
        for (&cell_id, &cgroup_id) in &active {
            if self
                .cells
                .get(&cell_id)
                .is_some_and(|cell| cell.cgroup_id == cgroup_id)
            {
                continue;
            }
            seeds.push((
                cell_id,
                CellWindow {
                    cgroup_id,
                    baseline: read(cell_id)?,
                    sampled_at: now,
                    p99: 0,
                },
            ));
        }
        self.cells.retain(|cell_id, _| active.contains_key(cell_id));
        self.cells.extend(seeds);
        Ok(())
    }

    pub fn collect(
        &mut self,
        now: Instant,
        mut read: impl FnMut(u32) -> Result<Snapshot>,
    ) -> Result<()> {
        for (&cell_id, cell) in &mut self.cells {
            if now.duration_since(cell.sampled_at) < WINDOW {
                continue;
            }
            let current = read(cell_id)?;
            cell.p99 = summarize_delta(&cell.baseline, &current);
            cell.baseline = current;
            cell.sampled_at = now;
        }
        Ok(())
    }

    pub fn summary(&self, cell_id: u32) -> u64 {
        self.cells.get(&cell_id).map_or(0, |cell| cell.p99)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const EMPTY: Snapshot = [[0; 16]; 4];

    fn observations(bucket: usize, count: u64) -> Snapshot {
        let mut snapshot = EMPTY;
        snapshot[0][bucket] = count;
        snapshot
    }

    #[test]
    fn pools_observations_across_all_shards() {
        let mut current = EMPTY;
        for shard in &mut current {
            shard[1] = 25;
        }
        assert_eq!(summarize_delta(&EMPTY, &current), 1);
    }

    #[test]
    fn uses_nearest_rank_p99() {
        for (low, high, expected) in [(99, 1, 1), (98, 2, 7)] {
            let mut current = observations(1, low);
            current[1][3] = high;
            assert_eq!(summarize_delta(&EMPTY, &current), expected);
        }
    }

    #[test]
    fn reports_bucket_upper_edges_and_terminal_cap() {
        for (bucket, expected) in [(0, 0), (1, 1), (2, 3), (3, 7), (14, 16383), (15, 16384)] {
            assert_eq!(summarize_delta(&EMPTY, &observations(bucket, 1)), expected);
        }
    }

    #[test]
    fn no_new_observations_reports_zero() {
        let previous = observations(3, 100);
        assert_eq!(summarize_delta(&previous, &previous), 0);
    }

    #[test]
    fn counts_wrapping_cumulative_deltas() {
        let previous = observations(3, u64::MAX - 1);
        let current = observations(3, 1);
        assert_eq!(summarize_delta(&previous, &current), 7);
    }

    #[test]
    fn pooled_counts_do_not_overflow_u64() {
        let mut current = EMPTY;
        current[0][1] = u64::MAX;
        current[1][3] = u64::MAX;
        assert_eq!(summarize_delta(&EMPTY, &current), 7);
    }

    #[test]
    fn reads_at_sixty_seconds_and_retains_cache_between_windows() {
        let start = Instant::now();
        let mut stats = DsqDepthStats::default();
        let mut seeds = Vec::new();
        stats
            .reconcile(&[(42, 1)], start, |id| {
                seeds.push(id);
                Ok(EMPTY)
            })
            .unwrap();
        assert_eq!(seeds, [0, 1]);
        stats
            .collect(start + Duration::from_secs(59), |_| panic!("early read"))
            .unwrap();
        assert_eq!(stats.summary(1), 0);
        let mut due = Vec::new();
        stats
            .collect(start + Duration::from_secs(60), |id| {
                due.push(id);
                Ok(observations(3, 100))
            })
            .unwrap();
        assert_eq!(due, [0, 1]);
        assert_eq!(stats.summary(1), 7);
        stats
            .collect(start + Duration::from_secs(119), |_| panic!("early read"))
            .unwrap();
        assert_eq!(stats.summary(1), 7);
    }

    #[test]
    fn empty_completed_window_replaces_positive_summary() {
        let start = Instant::now();
        let mut stats = DsqDepthStats::default();
        stats.reconcile(&[], start, |_| Ok(EMPTY)).unwrap();
        stats
            .collect(start + Duration::from_secs(60), |_| {
                Ok(observations(3, 100))
            })
            .unwrap();
        assert_eq!(stats.summary(0), 7);
        stats
            .collect(start + Duration::from_secs(120), |_| {
                Ok(observations(3, 100))
            })
            .unwrap();
        assert_eq!(stats.summary(0), 0);
    }

    #[test]
    fn unchanged_identity_preserves_baseline_deadline_and_cache() {
        let start = Instant::now();
        let mut stats = DsqDepthStats::default();
        stats.reconcile(&[(42, 1)], start, |_| Ok(EMPTY)).unwrap();
        stats
            .collect(start + Duration::from_secs(60), |_| {
                Ok(observations(3, 100))
            })
            .unwrap();
        stats
            .reconcile(&[(42, 1), (99, 0)], start + Duration::from_secs(90), |_| {
                panic!("unchanged identity read")
            })
            .unwrap();
        assert_eq!(stats.summary(1), 7);
        stats
            .collect(start + Duration::from_secs(120), |_| {
                Ok(observations(3, 100))
            })
            .unwrap();
        assert_eq!(stats.summary(1), 0);
    }

    #[test]
    fn reused_cell_seeds_current_counters_and_removes_deleted_cells() {
        let start = Instant::now();
        let mut stats = DsqDepthStats::default();
        stats
            .reconcile(&[(42, 1), (43, 2)], start, |_| Ok(EMPTY))
            .unwrap();
        stats
            .collect(start + Duration::from_secs(60), |_| {
                Ok(observations(3, 100))
            })
            .unwrap();
        let mut seeded = Vec::new();
        stats
            .reconcile(&[(44, 1)], start + Duration::from_secs(70), |id| {
                seeded.push(id);
                Ok(observations(3, 100))
            })
            .unwrap();
        assert_eq!(seeded, [1]);
        assert_eq!(stats.summary(1), 0);
        assert_eq!(stats.summary(2), 0);
        let mut due = Vec::new();
        stats
            .collect(start + Duration::from_secs(120), |id| {
                due.push(id);
                Ok(observations(3, 100))
            })
            .unwrap();
        assert_eq!(due, [0]);
        stats
            .collect(start + Duration::from_secs(130), |id| {
                assert_eq!(id, 1);
                let mut current = observations(3, 100);
                current[0][1] = 100;
                Ok(current)
            })
            .unwrap();
        assert_eq!(stats.summary(1), 1);
    }

    #[test]
    fn removed_and_readded_identity_is_reseeded() {
        let start = Instant::now();
        let mut stats = DsqDepthStats::default();
        stats.reconcile(&[(42, 1)], start, |_| Ok(EMPTY)).unwrap();
        stats
            .reconcile(&[], start + Duration::from_secs(10), |_| {
                panic!("root reseeded")
            })
            .unwrap();
        let mut seeded = Vec::new();
        stats
            .reconcile(&[(42, 1)], start + Duration::from_secs(20), |id| {
                seeded.push(id);
                Ok(observations(3, 100))
            })
            .unwrap();
        assert_eq!(seeded, [1]);
        stats
            .collect(start + Duration::from_secs(80), |id| {
                if id == 1 {
                    Ok(observations(3, 100))
                } else {
                    Ok(EMPTY)
                }
            })
            .unwrap();
        assert_eq!(stats.summary(1), 0);
    }

    #[test]
    fn rejects_cell_ids_outside_bounded_storage() {
        let mut stats = DsqDepthStats::default();
        assert!(
            stats
                .reconcile(&[(42, 256)], Instant::now(), |_| Ok(EMPTY))
                .is_err()
        );
    }

    #[test]
    fn failed_reads_preserve_window_for_retry() {
        let start = Instant::now();
        let mut stats = DsqDepthStats::default();
        stats.reconcile(&[], start, |_| Ok(EMPTY)).unwrap();
        assert!(
            stats
                .collect(start + Duration::from_secs(60), |_| anyhow::bail!(
                    "read failed"
                ))
                .is_err()
        );
        stats
            .collect(start + Duration::from_secs(61), |_| {
                Ok(observations(2, 100))
            })
            .unwrap();
        assert_eq!(stats.summary(0), 3);
    }
}
