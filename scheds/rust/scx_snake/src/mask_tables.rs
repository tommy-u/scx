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

pub fn resolve_mask_tables(specs: &[MaskTableSpec]) -> Result<Vec<ResolvedMaskTable>> {
    if specs.is_empty() {
        return Ok(Vec::new());
    }

    let topology = Topology::new().context("discovering CPU cache topology")?;
    if topology.all_llcs.is_empty() {
        bail!("CPU topology contains no LLCs");
    }
    if let Some(cpu) = topology
        .all_cpus
        .values()
        .find(|cpu| cpu.l2_id == usize::MAX && cpu.l3_id == usize::MAX)
    {
        bail!("CPU {} has no discoverable last-level cache", cpu.id);
    }

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

    specs
        .iter()
        .map(|spec| match spec.source {
            MaskTableSource::PreviousLlcByCpu => build_previous_llc_table(spec.id, &cpu_to_llc),
        })
        .collect()
}

fn build_previous_llc_table(id: u32, cpu_to_llc: &BTreeMap<u32, u32>) -> Result<ResolvedMaskTable> {
    if cpu_to_llc.is_empty() {
        bail!("CPU topology contains no CPUs");
    }

    let mut llc_to_cpus: BTreeMap<u32, BTreeSet<u32>> = BTreeMap::new();
    for (&cpu, &llc) in cpu_to_llc {
        llc_to_cpus.entry(llc).or_default().insert(cpu);
    }

    let entries = cpu_to_llc
        .iter()
        .map(|(&cpu, llc)| {
            let cpus = llc_to_cpus
                .get(llc)
                .cloned()
                .with_context(|| format!("CPU {cpu} references missing LLC {llc}"))?;
            Ok((cpu, cpus))
        })
        .collect::<Result<_>>()?;

    Ok(ResolvedMaskTable {
        id,
        source: MaskTableSource::PreviousLlcByCpu,
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
