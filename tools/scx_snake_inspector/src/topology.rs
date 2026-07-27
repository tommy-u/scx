// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::error::Error;
use std::fmt::{Display, Formatter};

use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct CpuInfo {
    pub cpu: u32,
    pub node: u32,
    pub package: u32,
    pub llc: u32,
    pub core: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TopologyView {
    pub cpus: Vec<CpuInfo>,
    pub numeric_order: Vec<u32>,
    pub topology_order: Vec<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TopologyError(String);

impl Display for TopologyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for TopologyError {}

impl TopologyView {
    pub fn discover() -> Result<Self, TopologyError> {
        let topology = scx_utils::Topology::new()
            .map_err(|error| TopologyError(format!("cannot discover CPU topology: {error}")))?;
        let cpus = topology
            .all_cpus
            .values()
            .map(|cpu| {
                Ok(CpuInfo {
                    cpu: as_u32("CPU", cpu.id)?,
                    node: as_u32("NUMA node", cpu.node_id)?,
                    package: as_u32("package", cpu.package_id)?,
                    llc: as_u32("LLC", cpu.llc_id)?,
                    core: as_u32("core", cpu.core_id)?,
                })
            })
            .collect::<Result<Vec<_>, TopologyError>>()?;
        Self::from_cpus(cpus)
    }

    pub fn from_cpus(mut cpus: Vec<CpuInfo>) -> Result<Self, TopologyError> {
        cpus.sort_by_key(|cpu| cpu.cpu);
        if cpus.windows(2).any(|pair| pair[0].cpu == pair[1].cpu) {
            return Err(TopologyError("duplicate CPU ID in topology".into()));
        }

        let numeric_order = cpus.iter().map(|cpu| cpu.cpu).collect();
        let mut topology_cpus = cpus.clone();
        topology_cpus.sort_by_key(|cpu| (cpu.node, cpu.package, cpu.llc, cpu.core, cpu.cpu));
        let topology_order = topology_cpus.iter().map(|cpu| cpu.cpu).collect();

        Ok(Self {
            cpus,
            numeric_order,
            topology_order,
        })
    }
}

fn as_u32(kind: &str, value: usize) -> Result<u32, TopologyError> {
    u32::try_from(value).map_err(|_| TopologyError(format!("{kind} ID {value} exceeds u32")))
}
