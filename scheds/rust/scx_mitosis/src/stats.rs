use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;

use scx_stats::prelude::*;
use scx_stats_derive::stat_doc;
use scx_stats_derive::Stats;

use crate::DistributionStats;

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(_om_prefix = "c_")]
#[stat(top)]
pub struct CellMetrics {
    #[stat(desc = "Number of cpus")]
    pub num_cpus: u32,
    #[stat(
        desc = "Cgroup path of this cell, relative to the cgroup root (\"/\" for the root cell)",
        _om_skip
    )]
    pub cgroup_path: String,
    #[stat(desc = "Local queue %")]
    pub local_q_pct: f64,
    #[stat(desc = "CPU queue %")]
    pub cpu_q_pct: f64,
    #[stat(desc = "Cell queue %")]
    pub cell_q_pct: f64,
    #[stat(desc = "Borrowed CPU %")]
    pub borrowed_pct: f64,
    #[stat(desc = "Affinity violations % of global")]
    pub affn_violations_pct: f64,
    #[stat(desc = "Steal %")]
    pub steal_pct: f64,
    #[stat(desc = "Orphaned LLC DSQ drain events")]
    pub drain_cnt: u64,
    #[stat(desc = "Slice shrink events")]
    pub slice_shrink: u64,
    #[stat(desc = "Slice shrink at max")]
    pub slice_shrink_max: u64,
    #[stat(desc = "Slice shrink proportional")]
    pub slice_shrink_proportional: u64,
    #[stat(desc = "Slice shrink at min")]
    pub slice_shrink_min: u64,
    #[stat(desc = "Decision share % of global")]
    pub share_of_decisions_pct: f64,
    #[stat(desc = "Cell scheduling decisions")]
    total_decisions: u64,
    #[stat(desc = "CPU utilization %")]
    pub util_pct: f64,
    #[stat(desc = "Borrowed CPU time % of running")]
    pub demand_borrow_pct: f64,
    #[stat(desc = "Lent CPU time %")]
    pub lent_pct: f64,
    #[stat(desc = "EWMA-smoothed utilization %")]
    pub smoothed_util_pct: f64,
}

impl CellMetrics {
    pub fn update(&mut self, ds: &DistributionStats) {
        self.local_q_pct = ds.local_q_pct;
        self.cpu_q_pct = ds.cpu_q_pct;
        self.cell_q_pct = ds.cell_q_pct;
        self.borrowed_pct = ds.borrowed_pct;
        self.affn_violations_pct = ds.affn_viol_pct;
        self.steal_pct = ds.steal_pct;
        self.share_of_decisions_pct = ds.share_of_decisions_pct;
        self.total_decisions = ds.total_decisions;
    }

    pub fn update_demand(&mut self, util_pct: f64, demand_borrow_pct: f64, lent_pct: f64) {
        self.util_pct = util_pct;
        self.demand_borrow_pct = demand_borrow_pct;
        self.lent_pct = lent_pct;
    }
}

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
pub struct BorrowFlowMetrics {
    #[stat(desc = "Cell consuming another cell's CPU capacity")]
    pub borrower_cell: u32,
    #[stat(desc = "Cell supplying CPU capacity")]
    pub lender_cell: u32,
    #[stat(desc = "Borrowed runtime in the latest collection interval (ns)")]
    pub runtime_ns: u64,
    #[stat(desc = "Borrowed runtime as a percentage of borrower runtime")]
    pub borrower_runtime_pct: f64,
    #[stat(desc = "Borrowed runtime as a percentage of lender CPU capacity")]
    pub lender_capacity_pct: f64,
}

pub(crate) fn build_borrow_flows(
    runtime: &[[u64; crate::MAX_CELLS]; crate::MAX_CELLS],
    borrower_runtime: &[u64; crate::MAX_CELLS],
    lender_capacity: &[u64; crate::MAX_CELLS],
    active: &[bool; crate::MAX_CELLS],
) -> BTreeMap<String, BorrowFlowMetrics> {
    let mut flows = BTreeMap::new();
    for lender in 0..crate::MAX_CELLS {
        for borrower in 0..crate::MAX_CELLS {
            let runtime_ns = runtime[lender][borrower];
            if lender == borrower || runtime_ns == 0 || !active[lender] || !active[borrower] {
                continue;
            }

            let borrower_runtime_pct = if borrower_runtime[borrower] > 0 {
                100.0 * runtime_ns as f64 / borrower_runtime[borrower] as f64
            } else {
                0.0
            };
            let lender_capacity_pct = if lender_capacity[lender] > 0 {
                100.0 * runtime_ns as f64 / lender_capacity[lender] as f64
            } else {
                0.0
            };
            flows.insert(
                format!("{borrower}_from_{lender}"),
                BorrowFlowMetrics {
                    borrower_cell: borrower as u32,
                    lender_cell: lender as u32,
                    runtime_ns,
                    borrower_runtime_pct,
                    lender_capacity_pct,
                },
            );
        }
    }
    flows
}

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct Metrics {
    #[stat(desc = "Number of cells")]
    pub num_cells: u32,
    #[stat(desc = "Local queue %")]
    pub local_q_pct: f64,
    #[stat(desc = "CPU queue %")]
    pub cpu_q_pct: f64,
    #[stat(desc = "Cell queue %")]
    pub cell_q_pct: f64,
    #[stat(desc = "Borrowed CPU %")]
    pub borrowed_pct: f64,
    #[stat(desc = "Affinity violations % of global")]
    pub affn_violations_pct: f64,
    #[stat(desc = "Steal %")]
    pub steal_pct: f64,
    #[stat(desc = "Orphaned LLC DSQ drain events")]
    pub drain_cnt: u64,
    #[stat(desc = "Slice shrink events")]
    pub slice_shrink: u64,
    #[stat(desc = "Slice shrink at max")]
    pub slice_shrink_max: u64,
    #[stat(desc = "Slice shrink proportional")]
    pub slice_shrink_proportional: u64,
    #[stat(desc = "Slice shrink at min")]
    pub slice_shrink_min: u64,
    #[stat(desc = "Decision share % of global")]
    pub share_of_decisions_pct: f64,
    #[stat(desc = "Cell scheduling decisions")]
    total_decisions: u64,
    #[stat(desc = "CPU utilization %")]
    pub util_pct: f64,
    #[stat(desc = "Borrowed CPU time % of running")]
    pub demand_borrow_pct: f64,
    #[stat(desc = "Lent CPU time %")]
    pub lent_pct: f64,
    #[stat(desc = "Number of rebalancing events")]
    pub rebalance_count: u64,
    #[stat(
        desc = "1 if the cell-0 holdout has taken a CPU already claimed by a workload cell, else 0"
    )]
    pub enforced_holdout: u64,
    #[stat(desc = "Pairwise cell borrowing in the latest collection interval")]
    pub borrow_flows: BTreeMap<String, BorrowFlowMetrics>,
    #[stat(desc = "Per-cell metrics")]
    pub cells: BTreeMap<u32, CellMetrics>,
}

impl Metrics {
    pub fn update(&mut self, ds: &DistributionStats) {
        self.local_q_pct = ds.local_q_pct;
        self.cpu_q_pct = ds.cpu_q_pct;
        self.cell_q_pct = ds.cell_q_pct;
        self.borrowed_pct = ds.borrowed_pct;
        self.affn_violations_pct = ds.affn_viol_pct;
        self.steal_pct = ds.steal_pct;
        self.share_of_decisions_pct = ds.share_of_decisions_pct;
        self.total_decisions = ds.total_decisions;
    }

    pub fn update_demand(&mut self, util_pct: f64, demand_borrow_pct: f64, lent_pct: f64) {
        self.util_pct = util_pct;
        self.demand_borrow_pct = demand_borrow_pct;
        self.lent_pct = lent_pct;
    }

    fn delta(&self, _: &Self) -> Self {
        Self { ..self.clone() }
    }

    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(w, "{}", serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}

pub fn server_data() -> StatsServerData<(), Metrics> {
    let open: Box<dyn StatsOpener<(), Metrics>> = Box::new(move |(req_ch, res_ch)| {
        req_ch.send(())?;
        let mut prev = res_ch.recv()?;

        let read: Box<dyn StatsReader<(), Metrics>> = Box::new(move |_args, (req_ch, res_ch)| {
            req_ch.send(())?;
            let cur = res_ch.recv()?;
            let delta = cur.delta(&prev);
            prev = cur;
            delta.to_json()
        });

        Ok(read)
    });

    StatsServerData::new()
        .add_meta(Metrics::meta())
        .add_meta(CellMetrics::meta())
        .add_meta(BorrowFlowMetrics::meta())
        .add_ops("top", StatsOps { open, close: None })
}

pub fn monitor(intv: Duration, shutdown: Arc<AtomicBool>) -> Result<()> {
    scx_utils::monitor_stats::<Metrics>(
        &[],
        intv,
        || shutdown.load(Ordering::Relaxed),
        |metrics| metrics.format(&mut std::io::stdout()),
    )
}

#[cfg(test)]
mod tests {
    use super::build_borrow_flows;
    use crate::MAX_CELLS;

    #[test]
    fn borrow_flows_preserve_borrower_and_lender_direction() {
        let mut runtime = [[0u64; MAX_CELLS]; MAX_CELLS];
        let mut borrower_runtime = [0u64; MAX_CELLS];
        let mut lender_capacity = [0u64; MAX_CELLS];
        let mut active = [false; MAX_CELLS];

        // Rows are lenders and columns are borrowers.
        runtime[0][1] = 250;
        runtime[2][1] = 750;
        borrower_runtime[1] = 2_000;
        lender_capacity[0] = 1_000;
        lender_capacity[2] = 3_000;
        active[0] = true;
        active[1] = true;
        active[2] = true;

        let flows = build_borrow_flows(&runtime, &borrower_runtime, &lender_capacity, &active);

        assert_eq!(flows.len(), 2);
        let from_zero = &flows["1_from_0"];
        assert_eq!(from_zero.borrower_cell, 1);
        assert_eq!(from_zero.lender_cell, 0);
        assert_eq!(from_zero.runtime_ns, 250);
        assert_eq!(from_zero.borrower_runtime_pct, 12.5);
        assert_eq!(from_zero.lender_capacity_pct, 25.0);
        let from_two = &flows["1_from_2"];
        assert_eq!(from_two.borrower_cell, 1);
        assert_eq!(from_two.lender_cell, 2);
        assert_eq!(from_two.borrower_runtime_pct, 37.5);
        assert_eq!(from_two.lender_capacity_pct, 25.0);
    }

    #[test]
    fn borrow_flows_exclude_own_runtime_stale_cells_and_zero_edges() {
        let mut runtime = [[0u64; MAX_CELLS]; MAX_CELLS];
        let mut borrower_runtime = [0u64; MAX_CELLS];
        let mut lender_capacity = [0u64; MAX_CELLS];
        let mut active = [false; MAX_CELLS];

        runtime[0][0] = 900;
        runtime[0][1] = 100;
        borrower_runtime[0] = 900;
        borrower_runtime[1] = 100;
        lender_capacity[0] = 1_000;
        active[0] = true;

        let flows = build_borrow_flows(&runtime, &borrower_runtime, &lender_capacity, &active);
        assert!(flows.is_empty());
    }
}
