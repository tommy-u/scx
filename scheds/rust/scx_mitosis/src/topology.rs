// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow, bail};
use scx_utils::{Cpumask, Topology};

use crate::bpf_intf;
use crate::bpf_skel::OpenBpfSkel;
use crate::bpf_skel::types::llc_cpumask;

const MAX_LLCS: usize = bpf_intf::consts_MAX_LLCS as usize;
const MAX_CPUS: usize = bpf_intf::consts_MAX_CPUS as usize;
const CPUMASK_LONG_ENTRIES: usize = bpf_intf::consts_CPUMASK_LONG_ENTRIES as usize;

pub struct MitosisTopology {
    pub cpu_to_llc: BTreeMap<usize, usize>,
    pub llc_to_cpus: BTreeMap<usize, Cpumask>,
}

impl MitosisTopology {
    pub fn new(topology: &Topology) -> Result<Self> {
        let nr_llc = topology.all_llcs.len();
        if !(1..=MAX_LLCS).contains(&nr_llc) {
            bail!("LLC topology must contain between 1 and {MAX_LLCS} domains, got {nr_llc}");
        }
        for (expected, (&id, llc)) in topology.all_llcs.iter().enumerate() {
            if id != expected || llc.id != id {
                bail!(
                    "LLC IDs must be dense: expected {expected}, got {id} (domain {})",
                    llc.id
                );
            }
            if llc.kernel_id == usize::MAX {
                bail!("LLC information is unavailable for domain {id}");
            }
        }

        if topology.all_cpus.len() != topology.span.weight() {
            bail!("online CPU topology does not match its CPU mask");
        }

        // Possible CPUs absent from the online topology retain inactive slots.
        let mut cpu_to_llc: BTreeMap<usize, usize> = (0..*scx_utils::NR_CPUS_POSSIBLE)
            .map(|cpu| (cpu, 0))
            .collect();
        for cpu in topology.span.iter() {
            if cpu >= MAX_CPUS {
                bail!("CPU {cpu} exceeds the supported CPU range 0..{MAX_CPUS}");
            }
            let cpu_topology = topology
                .all_cpus
                .get(&cpu)
                .with_context(|| format!("online CPU {cpu} is missing from topology"))?;
            let llc = topology
                .all_llcs
                .get(&cpu_topology.llc_id)
                .with_context(|| {
                    format!("CPU {cpu} maps to missing LLC {}", cpu_topology.llc_id)
                })?;
            if !llc.span.test_cpu(cpu) {
                bail!("CPU {cpu} is outside its assigned LLC {} mask", llc.id);
            }
            cpu_to_llc.insert(cpu, llc.id);
        }

        let mut llc_to_cpus = BTreeMap::new();
        for llc in topology.all_llcs.values() {
            llc_to_cpus.insert(llc.id, llc.span.clone());
        }

        Ok(MitosisTopology {
            cpu_to_llc,
            llc_to_cpus,
        })
    }

    pub fn apply(&self, skel: &mut OpenBpfSkel) -> Result<()> {
        // TODO: rodata
        let bss = skel
            .maps
            .bss_data
            .as_mut()
            .ok_or_else(|| anyhow!("bss_data not available"))?;
        self.apply_topology(&mut bss.cpu_to_llc, &mut bss.llc_to_cpus)
    }

    fn apply_topology(
        &self,
        cpu_to_llc: &mut [u32],
        llc_to_cpus: &mut [llc_cpumask; MAX_LLCS],
    ) -> Result<()> {
        for (&cpu, &llc_id) in &self.cpu_to_llc {
            if cpu >= cpu_to_llc.len() {
                bail!("invalid cpu {cpu}");
            }
            cpu_to_llc[cpu] = llc_id as u32;
        }

        for (&llc, cpumask) in &self.llc_to_cpus {
            if llc >= llc_to_cpus.len() {
                bail!("invalid llc {llc}");
            }

            let raw_span = cpumask.as_raw_slice();
            // Is this overkill?
            if raw_span.len() > llc_to_cpus[llc].bits.len() {
                bail!(
                    "invalid span {llc}: {} > {}",
                    raw_span.len(),
                    llc_to_cpus[llc].bits.len()
                );
            }

            llc_to_cpus[llc].bits = [0; CPUMASK_LONG_ENTRIES];
            llc_to_cpus[llc].bits[..raw_span.len()].copy_from_slice(raw_span);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn accepts_single_llc_zero() {
        let (topology, _) = scx_utils::testutils::make_test_topo(1, 1, 2, 1);
        let mapped = MitosisTopology::new(&topology).unwrap();
        assert_eq!(mapped.cpu_to_llc[&0], 0);
        assert_eq!(mapped.cpu_to_llc[&1], 0);
        assert!(mapped.llc_to_cpus[&0].test_cpu(0));
        assert!(mapped.llc_to_cpus[&0].test_cpu(1));
    }

    #[test]
    fn rejects_unavailable_llc_identity_with_populated_mappings() {
        let (mut topology, _) = scx_utils::testutils::make_test_topo(1, 4, 1, 1);
        for llc in topology.all_llcs.values_mut() {
            Arc::make_mut(llc).kernel_id = usize::MAX;
        }
        assert!(MitosisTopology::new(&topology).is_err());
    }

    #[test]
    fn rejects_unsupported_llc_count() {
        for count in [0, 17] {
            let (topology, _) = scx_utils::testutils::make_test_topo(1, count, 1, 1);
            assert!(MitosisTopology::new(&topology).is_err());
        }
    }

    #[test]
    fn rejects_nondense_llc_id() {
        let (mut topology, _) = scx_utils::testutils::make_test_topo(1, 1, 1, 1);
        let mut llc = topology.all_llcs.remove(&0).unwrap();
        Arc::make_mut(&mut llc).id = 16;
        topology.all_llcs.insert(16, llc);
        assert!(MitosisTopology::new(&topology).is_err());
    }

    #[test]
    fn rejects_cpu_outside_its_llc_mask() {
        let (mut topology, _) = scx_utils::testutils::make_test_topo(1, 1, 2, 1);
        Arc::make_mut(topology.all_llcs.get_mut(&0).unwrap())
            .span
            .clear_cpu(1)
            .unwrap();
        assert!(MitosisTopology::new(&topology).is_err());
    }

    #[test]
    fn accepts_offline_cpu_holes() {
        let (mut topology, _) = scx_utils::testutils::make_test_topo(1, 1, 2, 1);
        topology.span.clear_cpu(1).unwrap();
        topology.all_cpus.remove(&1);
        Arc::make_mut(topology.all_llcs.get_mut(&0).unwrap())
            .span
            .clear_cpu(1)
            .unwrap();
        let mapped = MitosisTopology::new(&topology).unwrap();
        assert_eq!(mapped.cpu_to_llc[&0], 0);
        assert_eq!(mapped.cpu_to_llc[&1], 0);
        assert!(!mapped.llc_to_cpus[&0].test_cpu(1));
    }

    fn check_llc_cpu(llc_to_cpus: &[llc_cpumask; MAX_LLCS], llc: usize, cpu: usize) -> bool {
        let long_idx = cpu / 64;
        let bit_idx = cpu % 64;
        llc_to_cpus[llc].bits[long_idx] & (1u64 << bit_idx) != 0
    }

    #[test]
    fn test_topology() {
        let (topology, _) = scx_utils::testutils::make_test_topo(
            1,  // nodes
            16, // llcs
            8,  // cores
            2,  // cpus
        );
        let mitosis_topology = MitosisTopology::new(&topology).unwrap();

        let mut cpu_to_llc = [0u32; bpf_intf::consts_MAX_CPUS as usize];
        let mut llc_to_cpus = [llc_cpumask {
            bits: [0; CPUMASK_LONG_ENTRIES],
        }; MAX_LLCS];

        mitosis_topology
            .apply_topology(&mut cpu_to_llc, &mut llc_to_cpus)
            .unwrap();

        assert_eq!(cpu_to_llc[0], 0);
        assert_eq!(cpu_to_llc[15], 0);
        assert_eq!(cpu_to_llc[16], 1);
        assert_eq!(cpu_to_llc[255], 15);

        for llc in 0..MAX_LLCS {
            let first_cpu = llc * 16;
            let last_cpu = first_cpu + 15;

            assert!(check_llc_cpu(&llc_to_cpus, llc, first_cpu));
            assert!(check_llc_cpu(&llc_to_cpus, llc, last_cpu));

            if llc > 0 {
                assert!(!check_llc_cpu(&llc_to_cpus, llc, first_cpu - 1));
            }
            if llc + 1 < MAX_LLCS {
                assert!(!check_llc_cpu(&llc_to_cpus, llc, last_cpu + 1));
            }
        }
    }
}
