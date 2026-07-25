// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use scx_snake_heatmap::topology::{CpuInfo, TopologyView};

fn cpu(cpu: u32, node: u32, package: u32, llc: u32, core: u32) -> CpuInfo {
    CpuInfo {
        cpu,
        node,
        package,
        llc,
        core,
    }
}

#[test]
fn topology_order_groups_node_package_llc_and_core() {
    let topology = TopologyView::from_cpus(vec![
        cpu(0, 1, 1, 3, 8),
        cpu(1, 0, 0, 1, 5),
        cpu(2, 0, 0, 0, 2),
        cpu(3, 0, 0, 0, 2),
        cpu(4, 0, 0, 1, 1),
    ])
    .unwrap();

    assert_eq!(topology.numeric_order, vec![0, 1, 2, 3, 4]);
    assert_eq!(topology.topology_order, vec![2, 3, 4, 1, 0]);
}

#[test]
fn duplicate_cpu_ids_are_rejected() {
    let result = TopologyView::from_cpus(vec![cpu(3, 0, 0, 0, 0), cpu(3, 1, 1, 1, 1)]);

    assert!(result.is_err());
}

#[test]
fn host_discovery_returns_the_same_cpu_set_in_both_orders() {
    let topology = TopologyView::discover().unwrap();
    let mut topology_ids = topology.topology_order.clone();
    topology_ids.sort_unstable();

    assert!(!topology.cpus.is_empty());
    assert_eq!(topology.numeric_order, topology_ids);
    assert_eq!(topology.cpus.len(), topology.numeric_order.len());
}
