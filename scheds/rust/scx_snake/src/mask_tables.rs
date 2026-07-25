// SPDX-License-Identifier: GPL-2.0-only

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context, Result};
use scx_utils::Topology;

use crate::bpf_intf;
use crate::policy::{MaskTableSource, MaskTableSpec};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedMaskTable {
    pub id: u32,
    pub source: MaskTableSource,
    pub entries: BTreeMap<u32, BTreeSet<u32>>,
}

/// Minimal topology identity needed by core-preserving partition providers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CpuLocation {
    llc: u32,
    core: u32,
}

pub fn resolve_mask_tables(specs: &[MaskTableSpec]) -> Result<Vec<ResolvedMaskTable>> {
    if specs.is_empty() {
        return Ok(Vec::new());
    }

    let topology = Topology::new().context("discovering CPU cache topology")?;
    let needs_llc = specs.iter().any(|spec| {
        matches!(
            spec.source,
            MaskTableSource::PreviousLlcByCpu | MaskTableSource::SplitLlcByCore { .. }
        )
    });
    if needs_llc && topology.all_llcs.is_empty() {
        bail!("CPU topology contains no LLCs");
    }
    if needs_llc {
        if let Some(cpu) = topology
            .all_cpus
            .values()
            .find(|cpu| cpu.l2_id == usize::MAX && cpu.l3_id == usize::MAX)
        {
            bail!("CPU {} has no discoverable last-level cache", cpu.id);
        }
    }

    let cpu_to_llc = if needs_llc {
        topology
            .all_cpus
            .values()
            .map(|cpu| {
                Ok((
                    cpu.id.try_into().context("CPU ID does not fit u32")?,
                    cpu.llc_id.try_into().context("LLC ID does not fit u32")?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?
    } else {
        BTreeMap::new()
    };
    let cpu_to_node = topology
        .all_cpus
        .values()
        .map(|cpu| {
            Ok((
                cpu.id.try_into().context("CPU ID does not fit u32")?,
                cpu.node_id
                    .try_into()
                    .context("NUMA node ID does not fit u32")?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let cpu_locations = if needs_llc {
        topology
            .all_cpus
            .values()
            .map(|cpu| {
                Ok((
                    cpu.id.try_into().context("CPU ID does not fit u32")?,
                    CpuLocation {
                        llc: cpu.llc_id.try_into().context("LLC ID does not fit u32")?,
                        core: cpu.core_id.try_into().context("core ID does not fit u32")?,
                    },
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?
    } else {
        BTreeMap::new()
    };

    specs
        .iter()
        .map(|spec| match spec.source {
            MaskTableSource::PreviousLlcByCpu => build_previous_llc_table(spec.id, &cpu_to_llc),
            MaskTableSource::PreviousNodeByCpu => build_previous_node_table(spec.id, &cpu_to_node),
            MaskTableSource::SplitLlcByCore { parts } => {
                build_split_llc_table(spec.id, &cpu_locations, parts)
            }
        })
        .collect()
}

fn build_previous_llc_table(id: u32, cpu_to_llc: &BTreeMap<u32, u32>) -> Result<ResolvedMaskTable> {
    build_cpu_keyed_group_table(id, cpu_to_llc, MaskTableSource::PreviousLlcByCpu, "LLC")
}

fn build_previous_node_table(
    id: u32,
    cpu_to_node: &BTreeMap<u32, u32>,
) -> Result<ResolvedMaskTable> {
    build_cpu_keyed_group_table(
        id,
        cpu_to_node,
        MaskTableSource::PreviousNodeByCpu,
        "NUMA node",
    )
}

fn build_cpu_keyed_group_table(
    id: u32,
    cpu_to_group: &BTreeMap<u32, u32>,
    source: MaskTableSource,
    group_name: &str,
) -> Result<ResolvedMaskTable> {
    if cpu_to_group.is_empty() {
        bail!("CPU topology contains no CPUs");
    }

    let mut group_to_cpus: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
    for (&cpu, &group) in cpu_to_group {
        group_to_cpus.entry(group).or_default().insert(cpu);
    }

    let entries = cpu_to_group
        .iter()
        .map(|(&cpu, group)| {
            let cpus = group_to_cpus
                .get(group)
                .cloned()
                .with_context(|| format!("CPU {cpu} references missing {group_name} {group}"))?;
            Ok((cpu, cpus))
        })
        .collect::<Result<_>>()?;

    Ok(ResolvedMaskTable {
        id,
        source,
        entries,
    })
}

fn build_split_llc_table(
    id: u32,
    cpu_locations: &BTreeMap<u32, CpuLocation>,
    parts: u32,
) -> Result<ResolvedMaskTable> {
    if cpu_locations.is_empty() {
        bail!("CPU topology contains no CPUs");
    }
    if parts < 2 {
        bail!("LLC split requires at least two parts");
    }
    let parts = parts as usize;
    let mut llcs: BTreeMap<u32, BTreeMap<u32, BTreeSet<u32>>> = BTreeMap::new();
    for (&cpu, location) in cpu_locations {
        llcs.entry(location.llc)
            .or_default()
            .entry(location.core)
            .or_default()
            .insert(cpu);
    }

    let mut entries = BTreeMap::new();
    for (llc, cores) in llcs {
        if cores.len() < parts {
            bail!(
                "LLC {llc} has {} cores and cannot be split into {parts} non-empty parts",
                cores.len()
            );
        }

        let cores_per_part = cores.len() / parts;
        let larger_parts = cores.len() % parts;
        let mut core_iter = cores.into_values();
        for part in 0..parts {
            let mut cpus = BTreeSet::new();
            let part_cores = cores_per_part + usize::from(part < larger_parts);
            for _ in 0..part_cores {
                cpus.extend(
                    core_iter
                        .next()
                        .expect("part sizes account for every LLC core"),
                );
            }
            for &cpu in &cpus {
                entries.insert(cpu, cpus.clone());
            }
        }
    }

    Ok(ResolvedMaskTable {
        id,
        source: MaskTableSource::SplitLlcByCore {
            parts: parts as u32,
        },
        entries,
    })
}

pub fn dump_mask_tables(tables: &[ResolvedMaskTable]) -> String {
    let mut output = String::new();
    for table in tables {
        output.push_str(&format!("mask table {} {:?}:\n", table.id, table.source));
        for (cpu, cpus) in &table.entries {
            output.push_str(&format!(
                "  key cpu {cpu}: [{}]\n",
                cpus.iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            ));
        }
    }
    output
}

pub fn serialize_entry(cpus: &BTreeSet<u32>) -> Result<bpf_intf::snake_mask_data> {
    let mut data = bpf_intf::snake_mask_data {
        valid: 1,
        bits: [0; bpf_intf::SNAKE_MASK_BYTES as usize],
    };

    for &cpu in cpus {
        if cpu >= bpf_intf::SNAKE_MAX_CPUS {
            bail!(
                "CPU {cpu} exceeds mask table capacity {}",
                bpf_intf::SNAKE_MAX_CPUS
            );
        }
        let byte = (cpu / 8) as usize;
        let bit = cpu % 8;
        data.bits[byte] |= 1 << bit;
    }

    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpu(llc: u32, core: u32) -> CpuLocation {
        CpuLocation { llc, core }
    }

    #[test]
    fn builds_a_cpu_keyed_table_from_llc_membership() {
        let cpu_to_llc = BTreeMap::from([(0, 10), (1, 10), (2, 20), (3, 20)]);

        let table = build_previous_llc_table(0, &cpu_to_llc).expect("table should build");

        assert_eq!(table.id, 0);
        assert_eq!(table.entries[&0], BTreeSet::from([0, 1]));
        assert_eq!(table.entries[&1], BTreeSet::from([0, 1]));
        assert_eq!(table.entries[&2], BTreeSet::from([2, 3]));
        assert_eq!(table.entries[&3], BTreeSet::from([2, 3]));
    }

    #[test]
    fn builds_a_cpu_keyed_table_from_node_membership() {
        let cpu_to_node = BTreeMap::from([(0, 0), (1, 1), (2, 0), (3, 1)]);

        let table = build_previous_node_table(1, &cpu_to_node).expect("table should build");

        assert_eq!(table.id, 1);
        assert_eq!(table.source, MaskTableSource::PreviousNodeByCpu);
        assert_eq!(table.entries[&0], BTreeSet::from([0, 2]));
        assert_eq!(table.entries[&1], BTreeSet::from([1, 3]));
        assert_eq!(table.entries[&2], BTreeSet::from([0, 2]));
        assert_eq!(table.entries[&3], BTreeSet::from([1, 3]));
        assert!(dump_mask_tables(&[table]).contains("mask table 1 PreviousNodeByCpu"));
    }

    #[test]
    fn splits_each_llc_in_half_without_splitting_cores() {
        let topology = BTreeMap::from([
            (0, cpu(10, 100)),
            (8, cpu(10, 100)),
            (1, cpu(10, 101)),
            (9, cpu(10, 101)),
            (2, cpu(10, 102)),
            (10, cpu(10, 102)),
            (3, cpu(10, 103)),
            (11, cpu(10, 103)),
            (4, cpu(20, 200)),
            (12, cpu(20, 200)),
            (5, cpu(20, 201)),
            (13, cpu(20, 201)),
            (6, cpu(20, 202)),
            (14, cpu(20, 202)),
            (7, cpu(20, 203)),
            (15, cpu(20, 203)),
        ]);

        let table = build_split_llc_table(0, &topology, 2).expect("table should build");

        assert_eq!(table.entries[&0], BTreeSet::from([0, 1, 8, 9]));
        assert_eq!(table.entries[&8], BTreeSet::from([0, 1, 8, 9]));
        assert_eq!(table.entries[&2], BTreeSet::from([2, 3, 10, 11]));
        assert_eq!(table.entries[&4], BTreeSet::from([4, 5, 12, 13]));
        assert_eq!(table.entries[&6], BTreeSet::from([6, 7, 14, 15]));
    }

    #[test]
    fn supports_more_than_two_balanced_parts() {
        let topology = BTreeMap::from([
            (0, cpu(10, 100)),
            (1, cpu(10, 101)),
            (2, cpu(10, 102)),
            (3, cpu(10, 103)),
            (4, cpu(10, 104)),
        ]);

        let table = build_split_llc_table(0, &topology, 3).expect("table should build");

        assert_eq!(table.entries[&0], BTreeSet::from([0, 1]));
        assert_eq!(table.entries[&2], BTreeSet::from([2, 3]));
        assert_eq!(table.entries[&4], BTreeSet::from([4]));
    }

    #[test]
    fn rejects_more_parts_than_an_llc_has_cores() {
        let topology = BTreeMap::from([
            (0, cpu(10, 100)),
            (1, cpu(10, 101)),
            (2, cpu(20, 200)),
            (3, cpu(20, 201)),
            (4, cpu(20, 202)),
        ]);

        let error = build_split_llc_table(0, &topology, 3)
            .expect_err("undersized LLC should be rejected")
            .to_string();

        assert!(error.contains("LLC 10 has 2 cores"));
        assert!(error.contains("3 non-empty parts"));
    }

    #[test]
    fn rejects_an_empty_topology() {
        let error = build_previous_llc_table(0, &BTreeMap::new())
            .expect_err("empty topology should be rejected")
            .to_string();

        assert!(error.contains("no CPUs"));
    }

    #[test]
    fn serializes_mask_bits_for_the_bpf_table() {
        let data =
            serialize_entry(&BTreeSet::from([0, 63, 64, 1023])).expect("mask should serialize");

        assert_eq!(data.valid, 1);
        assert_eq!(data.bits[0], 0x01);
        assert_eq!(data.bits[7], 0x80);
        assert_eq!(data.bits[8], 0x01);
        assert_eq!(data.bits[127], 0x80);
    }

    #[test]
    fn rejects_a_cpu_outside_the_bpf_table_capacity() {
        let error = serialize_entry(&BTreeSet::from([1024]))
            .expect_err("out-of-range CPU should fail")
            .to_string();

        assert!(error.contains("exceeds mask table capacity"));
    }
}
