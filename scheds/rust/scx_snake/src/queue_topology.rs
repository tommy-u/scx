// SPDX-License-Identifier: GPL-2.0-only

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context, Result};
use scx_utils::Topology;

use crate::cell_allocation::{resolve_cell_allocation, CellAllocation};
use crate::policy::{CompiledPolicy, QueueLayout};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueueCell {
    pub index: u32,
    pub external_id: u32,
    pub cpu_weight: u32,
    pub primary: BTreeSet<u32>,
    pub borrowable: BTreeSet<u32>,
    pub normal_queues: Vec<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NormalQueue {
    pub index: u32,
    pub cell_index: Option<u32>,
    pub clock_index: u32,
    pub llc_id: Option<u32>,
    pub consumers: BTreeSet<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CpuQueue {
    pub cpu: u32,
    pub owner_cell_index: Option<u32>,
    pub llc_id: u32,
    pub normal_queue_index: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueueTopology {
    pub layout: QueueLayout,
    pub nr_clock_domains: u32,
    pub cells: Vec<QueueCell>,
    pub cell_index_by_id: BTreeMap<u32, u32>,
    pub normal_queues: Vec<NormalQueue>,
    pub cpu_queues: BTreeMap<u32, CpuQueue>,
}

pub fn resolve_queue_topology(
    policy: &CompiledPolicy,
    available_cpus: &BTreeSet<u32>,
    cpu_to_llc: &BTreeMap<u32, u32>,
) -> Result<Option<QueueTopology>> {
    let Some(queues) = &policy.queues else {
        return Ok(None);
    };
    for &cpu in available_cpus {
        if !cpu_to_llc.contains_key(&cpu) {
            bail!("CPU {cpu} has no LLC mapping");
        }
    }
    if queues.layout == QueueLayout::Llc {
        return Ok(Some(compile_llc_queue_topology(
            available_cpus,
            cpu_to_llc,
        )?));
    }
    let allocation = resolve_cell_allocation(policy, available_cpus)?
        .expect("queue policy existence was checked above");
    Ok(Some(compile_queue_topology(
        queues.layout,
        allocation,
        cpu_to_llc,
    )?))
}

pub fn resolve_host_queue_topology(policy: &CompiledPolicy) -> Result<Option<QueueTopology>> {
    if policy.queues.is_none() {
        return Ok(None);
    }
    let topology = Topology::new().context("discovering CPU topology for queue policy")?;
    let available_cpus = topology
        .all_cpus
        .keys()
        .map(|&cpu| cpu.try_into().context("CPU ID does not fit u32"))
        .collect::<Result<BTreeSet<_>>>()?;
    let cpu_to_llc = topology
        .all_cpus
        .values()
        .map(|cpu| {
            Ok((
                cpu.id.try_into().context("CPU ID does not fit u32")?,
                cpu.llc_id.try_into().context("LLC ID does not fit u32")?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    resolve_queue_topology(policy, &available_cpus, &cpu_to_llc)
}

pub fn dump_queue_topology(topology: &QueueTopology) -> String {
    let mut output = format!(
        "queue topology: layout={} clocks={} cells={} normal_queues={} affinity_queues={}\n",
        topology.layout.as_str(),
        topology.nr_clock_domains,
        topology.cells.len(),
        topology.normal_queues.len(),
        topology.cpu_queues.len(),
    );
    for cell in &topology.cells {
        output.push_str(&format!(
            "  cell {} (index {}): cpu_weight={} primary=[{}] borrowable=[{}] normal_queues={:?}\n",
            cell.external_id,
            cell.index,
            cell.cpu_weight,
            cpulist(&cell.primary),
            cpulist(&cell.borrowable),
            cell.normal_queues,
        ));
    }
    for queue in &topology.normal_queues {
        output.push_str(&format!(
            "  normal queue {}: cell_index={:?} clock_index={} llc={:?} consumers=[{}]\n",
            queue.index,
            queue.cell_index,
            queue.clock_index,
            queue.llc_id,
            cpulist(&queue.consumers),
        ));
    }
    output
}

fn cpulist(cpus: &BTreeSet<u32>) -> String {
    cpus.iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn compile_queue_topology(
    layout: QueueLayout,
    allocation: CellAllocation,
    cpu_to_llc: &BTreeMap<u32, u32>,
) -> Result<QueueTopology> {
    let cell_index_by_id = allocation
        .cells
        .keys()
        .enumerate()
        .map(|(index, &cell_id)| Ok((cell_id, u32::try_from(index)?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let mut cells = allocation
        .cells
        .values()
        .map(|cell| QueueCell {
            index: cell_index_by_id[&cell.id],
            external_id: cell.id,
            cpu_weight: cell.cpu_weight,
            primary: cell.primary.clone(),
            borrowable: cell.borrowable.clone(),
            normal_queues: Vec::new(),
        })
        .collect::<Vec<_>>();
    let mut normal_queues = Vec::new();
    let mut normal_by_cell_llc = BTreeMap::new();

    for cell in &mut cells {
        let groups = match layout {
            QueueLayout::Cell => BTreeMap::from([(None, cell.primary.clone())]),
            QueueLayout::CellLlc => {
                let mut by_llc: BTreeMap<Option<u32>, BTreeSet<u32>> = BTreeMap::new();
                for &cpu in &cell.primary {
                    by_llc
                        .entry(Some(cpu_to_llc[&cpu]))
                        .or_default()
                        .insert(cpu);
                }
                by_llc
            }
            QueueLayout::Llc => unreachable!("LLC topology does not use cell allocation"),
        };
        for (llc_id, consumers) in groups {
            if consumers.is_empty() {
                continue;
            }
            let index = u32::try_from(normal_queues.len())?;
            normal_queues.push(NormalQueue {
                index,
                cell_index: Some(cell.index),
                clock_index: cell.index,
                llc_id,
                consumers,
            });
            cell.normal_queues.push(index);
            normal_by_cell_llc.insert((cell.index, llc_id), index);
        }
    }
    if normal_queues.len() > allocation.cpu_owners.len() {
        bail!(
            "queue topology has {} normal queues for only {} CPUs",
            normal_queues.len(),
            allocation.cpu_owners.len()
        );
    }

    let cpu_queues = allocation
        .cpu_owners
        .iter()
        .map(|(&cpu, &owner_id)| {
            let owner_cell_index = cell_index_by_id[&owner_id];
            let llc_id = cpu_to_llc[&cpu];
            let queue_key = match layout {
                QueueLayout::Cell => (owner_cell_index, None),
                QueueLayout::CellLlc => (owner_cell_index, Some(llc_id)),
                QueueLayout::Llc => unreachable!("LLC topology does not use cell allocation"),
            };
            let normal_queue_index =
                normal_by_cell_llc.get(&queue_key).copied().ok_or_else(|| {
                    anyhow::anyhow!(
                        "CPU {cpu} owner cell {owner_id} has no normal queue for LLC {llc_id}"
                    )
                })?;
            Ok((
                cpu,
                CpuQueue {
                    cpu,
                    owner_cell_index: Some(owner_cell_index),
                    llc_id,
                    normal_queue_index,
                },
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;

    Ok(QueueTopology {
        layout,
        nr_clock_domains: u32::try_from(cells.len())?,
        cells,
        cell_index_by_id,
        normal_queues,
        cpu_queues,
    })
}

fn compile_llc_queue_topology(
    available_cpus: &BTreeSet<u32>,
    cpu_to_llc: &BTreeMap<u32, u32>,
) -> Result<QueueTopology> {
    let mut cpus_by_llc: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
    for &cpu in available_cpus {
        cpus_by_llc.entry(cpu_to_llc[&cpu]).or_default().insert(cpu);
    }

    let mut normal_queues = Vec::with_capacity(cpus_by_llc.len());
    let mut normal_by_llc = BTreeMap::new();
    for (llc_id, consumers) in cpus_by_llc {
        let index = u32::try_from(normal_queues.len())?;
        normal_queues.push(NormalQueue {
            index,
            cell_index: None,
            clock_index: 0,
            llc_id: Some(llc_id),
            consumers,
        });
        normal_by_llc.insert(llc_id, index);
    }
    if normal_queues.len() > available_cpus.len() {
        bail!(
            "queue topology has {} normal queues for only {} CPUs",
            normal_queues.len(),
            available_cpus.len()
        );
    }

    let cpu_queues = available_cpus
        .iter()
        .map(|&cpu| {
            let llc_id = cpu_to_llc[&cpu];
            Ok((
                cpu,
                CpuQueue {
                    cpu,
                    owner_cell_index: None,
                    llc_id,
                    normal_queue_index: normal_by_llc[&llc_id],
                },
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;

    Ok(QueueTopology {
        layout: QueueLayout::Llc,
        nr_clock_domains: 1,
        cells: Vec::new(),
        cell_index_by_id: BTreeMap::new(),
        normal_queues,
        cpu_queues,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy;

    fn compile(layout: &str) -> CompiledPolicy {
        policy::compile_policy(&format!(
            r#"
[queues]
layout = "{layout}"

[[cell]]
id = 7
cpus = "0-3"

[[cell]]
id = 19
cpus = "2-5"

[[rung]]
operation = "pick_idle"
scope = "task_cell"
"#
        ))
        .expect("policy should compile")
    }

    fn topology(layout: &str) -> QueueTopology {
        let policy = compile(layout);
        resolve_queue_topology(
            &policy,
            &BTreeSet::from([0, 1, 2, 3, 4, 5]),
            &BTreeMap::from([(0, 10), (1, 10), (2, 20), (3, 20), (4, 10), (5, 20)]),
        )
        .expect("queue topology should resolve")
        .expect("queue policy should have a topology")
    }

    #[test]
    fn cell_layout_has_one_normal_queue_per_dense_cell() {
        let topology = topology("cell");

        assert_eq!(topology.cells.len(), 3);
        assert_eq!(topology.normal_queues.len(), 3);
        assert_eq!(topology.cpu_queues.len(), 6);
        assert_eq!(
            topology.cell_index_by_id,
            BTreeMap::from([(0, 0), (7, 1), (19, 2)])
        );
        for cell in &topology.cells {
            assert_eq!(cell.normal_queues.len(), 1);
            let queue = &topology.normal_queues[cell.normal_queues[0] as usize];
            assert_eq!(queue.cell_index, Some(cell.index));
            assert_eq!(queue.clock_index, cell.index);
            assert_eq!(queue.llc_id, None);
            assert_eq!(queue.consumers, cell.primary);
        }
    }

    #[test]
    fn cell_llc_layout_creates_only_owned_cell_llc_pairs() {
        let topology = topology("cell_llc");

        assert!(topology.normal_queues.len() <= topology.cpu_queues.len());
        for queue in &topology.normal_queues {
            assert_eq!(Some(queue.clock_index), queue.cell_index);
            assert!(queue.llc_id.is_some());
            assert!(!queue.consumers.is_empty());
            assert!(queue
                .consumers
                .iter()
                .all(|cpu| topology.cpu_queues[cpu].llc_id == queue.llc_id.unwrap()));
        }
        for cpu in topology.cpu_queues.values() {
            let queue = &topology.normal_queues[cpu.normal_queue_index as usize];
            assert_eq!(queue.cell_index, cpu.owner_cell_index);
            assert!(queue.consumers.contains(&cpu.cpu));
        }
    }

    #[test]
    fn llc_layout_creates_one_global_clock_queue_per_llc_without_cells() {
        let policy = policy::compile_policy(
            r#"
[queues]
layout = "llc"

[[rung]]
operation = "pick_idle"
scope = "task_allowed"
"#,
        )
        .expect("LLC policy should compile");
        let topology = resolve_queue_topology(
            &policy,
            &BTreeSet::from([0, 1, 2, 3, 4, 5]),
            &BTreeMap::from([(0, 10), (1, 10), (2, 20), (3, 20), (4, 10), (5, 20)]),
        )
        .expect("LLC topology should resolve")
        .expect("queue policy should have a topology");

        assert_eq!(topology.layout.as_str(), "llc");
        assert!(topology.cells.is_empty());
        assert!(topology.cell_index_by_id.is_empty());
        assert_eq!(topology.nr_clock_domains, 1);
        assert_eq!(topology.normal_queues.len(), 2);
        assert_eq!(topology.cpu_queues.len(), 6);
        assert!(topology
            .normal_queues
            .iter()
            .all(|queue| queue.clock_index == 0));
        assert!(topology
            .normal_queues
            .iter()
            .all(|queue| queue.cell_index.is_none()));
        assert_eq!(
            topology
                .normal_queues
                .iter()
                .map(|queue| (queue.llc_id, queue.consumers.clone()))
                .collect::<Vec<_>>(),
            vec![
                (Some(10), BTreeSet::from([0, 1, 4])),
                (Some(20), BTreeSet::from([2, 3, 5])),
            ]
        );
        for route in topology.cpu_queues.values() {
            assert!(route.owner_cell_index.is_none());
            let queue = &topology.normal_queues[route.normal_queue_index as usize];
            assert_eq!(queue.llc_id, Some(route.llc_id));
            assert!(queue.consumers.contains(&route.cpu));
        }
    }

    #[test]
    fn missing_llc_mapping_is_rejected() {
        let policy = compile("cell_llc");
        let error = resolve_queue_topology(
            &policy,
            &BTreeSet::from([0, 1, 2, 3, 4, 5]),
            &BTreeMap::from([(0, 0)]),
        )
        .unwrap_err()
        .to_string();

        assert!(error.contains("CPU 1 has no LLC mapping"), "{error}");
    }

    #[test]
    fn placement_only_policy_has_no_queue_topology() {
        let policy = policy::compile_policy(
            r#"
[[rung]]
operation = "pick_idle"
scope = "task_allowed"
"#,
        )
        .unwrap();
        assert_eq!(
            resolve_queue_topology(&policy, &BTreeSet::from([0]), &BTreeMap::from([(0, 0)]))
                .unwrap(),
            None
        );
    }

    #[test]
    fn topology_dump_distinguishes_primary_and_borrowable_cpus() {
        let topology = QueueTopology {
            layout: QueueLayout::Cell,
            nr_clock_domains: 1,
            cells: vec![QueueCell {
                index: 0,
                external_id: 7,
                cpu_weight: 1,
                primary: BTreeSet::from([1]),
                borrowable: BTreeSet::from([2]),
                normal_queues: vec![0],
            }],
            cell_index_by_id: BTreeMap::from([(7, 0)]),
            normal_queues: Vec::new(),
            cpu_queues: BTreeMap::new(),
        };

        let dump = dump_queue_topology(&topology);
        assert!(dump.contains("primary=[1] borrowable=[2]"), "{dump}");
    }
}
