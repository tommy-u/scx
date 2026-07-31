// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::{HashMap, HashSet};

use libbpf_rs::query::{ProgInfoIter, ProgramInfo};
use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BpfProgramStatsRow {
    pub id: u32,
    pub name: String,
    pub run_count: u64,
    pub run_time_ns: u64,
    pub average_runtime_ns: Option<u64>,
    pub recursion_misses: u64,
    pub verified_insns: Option<u32>,
}

/// Read cumulative kernel runtime counters for the requested BPF programs.
///
/// Rows follow the order of `target_program_ids`. A target that was unloaded or
/// cannot be queried while the iterator is running is omitted.
pub fn query_bpf_program_stats(target_program_ids: &[u32]) -> Vec<BpfProgramStatsRow> {
    let targets: HashSet<_> = target_program_ids.iter().copied().collect();
    let mut rows: HashMap<_, _> = ProgInfoIter::default()
        .filter(|info| targets.contains(&info.id))
        .map(|info| (info.id, row_from_info(&info)))
        .collect();

    target_program_ids
        .iter()
        .filter_map(|id| rows.remove(id))
        .collect()
}

fn row_from_info(info: &ProgramInfo) -> BpfProgramStatsRow {
    BpfProgramStatsRow {
        id: info.id,
        name: info.name.to_string_lossy().into_owned(),
        run_count: info.run_cnt,
        run_time_ns: info.run_time_ns,
        average_runtime_ns: average_runtime_ns(info.run_time_ns, info.run_cnt),
        recursion_misses: info.recursion_misses,
        verified_insns: (info.verified_insns != 0).then_some(info.verified_insns),
    }
}

fn average_runtime_ns(run_time_ns: u64, run_count: u64) -> Option<u64> {
    (run_count != 0).then(|| run_time_ns / run_count)
}

#[cfg(test)]
mod tests {
    use super::average_runtime_ns;

    #[test]
    fn average_requires_at_least_one_run() {
        assert_eq!(average_runtime_ns(100, 0), None);
        assert_eq!(average_runtime_ns(100, 4), Some(25));
    }
}
