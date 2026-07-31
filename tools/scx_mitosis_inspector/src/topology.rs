// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs;
use std::path::Path;

use serde::Serialize;

const SYS_CPU_PATH: &str = "/sys/devices/system/cpu";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct CpuInfo {
    pub cpu: u32,
    pub node: u32,
    pub package: u32,
    pub llc: u32,
    pub core: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LlcGroup {
    pub llc: u32,
    pub node: u32,
    pub cpus: Vec<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TopologyView {
    pub cpu_count: u32,
    pub cpus: Vec<CpuInfo>,
    pub llc_groups: Vec<LlcGroup>,
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
        Self::discover_from(Path::new(SYS_CPU_PATH))
    }

    fn discover_from(sys_cpu: &Path) -> Result<Self, TopologyError> {
        let cpu_ids = discover_cpu_ids(sys_cpu);
        let mut discovered = Vec::with_capacity(cpu_ids.len());

        for cpu in cpu_ids {
            let cpu_path = sys_cpu.join(format!("cpu{cpu}"));
            let package = read_u32(&cpu_path.join("topology/physical_package_id")).unwrap_or(0);
            let core = read_u32(&cpu_path.join("topology/core_id")).unwrap_or(cpu);
            let node = discover_node(&cpu_path).unwrap_or(0);
            let llc_key = discover_llc_key(&cpu_path, package);
            discovered.push((cpu, node, package, core, llc_key));
        }

        // Dense LLC IDs make the JSON convenient for both tables and heatmaps.
        let llc_keys = discovered
            .iter()
            .map(|entry| entry.4.clone())
            .collect::<BTreeSet<_>>();
        let llc_ids = llc_keys
            .into_iter()
            .enumerate()
            .map(|(id, key)| (key, id as u32))
            .collect::<BTreeMap<_, _>>();
        let cpus = discovered
            .into_iter()
            .map(|(cpu, node, package, core, llc_key)| CpuInfo {
                cpu,
                node,
                package,
                llc: llc_ids[&llc_key],
                core,
            })
            .collect();

        Self::from_cpus(cpus)
    }

    pub fn from_cpus(mut cpus: Vec<CpuInfo>) -> Result<Self, TopologyError> {
        cpus.sort_by_key(|cpu| cpu.cpu);
        if cpus.windows(2).any(|pair| pair[0].cpu == pair[1].cpu) {
            return Err(TopologyError("duplicate CPU ID in topology".into()));
        }
        let cpu_count = cpus
            .len()
            .try_into()
            .map_err(|_| TopologyError("CPU count exceeds u32".into()))?;
        let numeric_order = cpus.iter().map(|cpu| cpu.cpu).collect();
        let mut topology_cpus = cpus.clone();
        topology_cpus.sort_by_key(|cpu| (cpu.node, cpu.package, cpu.llc, cpu.core, cpu.cpu));
        let topology_order = topology_cpus.iter().map(|cpu| cpu.cpu).collect();

        let mut groups = BTreeMap::<u32, LlcGroup>::new();
        for cpu in &cpus {
            let group = groups.entry(cpu.llc).or_insert_with(|| LlcGroup {
                llc: cpu.llc,
                node: cpu.node,
                cpus: Vec::new(),
            });
            group.cpus.push(cpu.cpu);
        }

        Ok(Self {
            cpu_count,
            cpus,
            llc_groups: groups.into_values().collect(),
            numeric_order,
            topology_order,
        })
    }
}

fn discover_cpu_ids(sys_cpu: &Path) -> Vec<u32> {
    for list_name in ["online", "possible"] {
        if let Ok(value) = fs::read_to_string(sys_cpu.join(list_name)) {
            let cpus = parse_cpu_list(&value);
            if !cpus.is_empty() {
                return cpus;
            }
        }
    }

    let mut cpus = fs::read_dir(sys_cpu)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| {
            entry
                .file_name()
                .to_str()
                .and_then(|name| name.strip_prefix("cpu"))
                .filter(|suffix| {
                    !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
                })
                .and_then(|suffix| suffix.parse().ok())
        })
        .collect::<Vec<_>>();
    cpus.sort_unstable();
    cpus.dedup();
    if !cpus.is_empty() {
        return cpus;
    }

    let count = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1);
    (0..count).filter_map(|cpu| cpu.try_into().ok()).collect()
}

fn discover_node(cpu_path: &Path) -> Option<u32> {
    fs::read_dir(cpu_path)
        .ok()?
        .filter_map(Result::ok)
        .find_map(|entry| {
            entry
                .file_name()
                .to_str()
                .and_then(|name| name.strip_prefix("node"))
                .and_then(|node| node.parse().ok())
        })
}

fn discover_llc_key(cpu_path: &Path, package: u32) -> String {
    let mut candidates = fs::read_dir(cpu_path.join("cache"))
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            let level = read_u32(&path.join("level"))?;
            let kind = fs::read_to_string(path.join("type")).ok()?;
            if !matches!(kind.trim(), "Data" | "Unified") {
                return None;
            }
            let shared = fs::read_to_string(path.join("shared_cpu_list"))
                .ok()
                .map(|list| parse_cpu_list(&list))
                .filter(|cpus| !cpus.is_empty())
                .map(|cpus| {
                    cpus.into_iter()
                        .map(|cpu| cpu.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                });
            let id = read_u32(&path.join("id"));
            Some((level, shared, id))
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|candidate| candidate.0);

    match candidates.pop() {
        Some((_, Some(shared), _)) => format!("cpus:{shared}"),
        Some((_, None, Some(id))) => format!("package:{package}:cache:{id}"),
        _ => format!("package:{package}"),
    }
}

fn read_u32(path: &Path) -> Option<u32> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn parse_cpu_list(value: &str) -> Vec<u32> {
    let mut cpus = BTreeSet::new();
    for item in value.trim().split(',') {
        if let Some((start, end)) = item.split_once('-') {
            if let (Ok(start), Ok(end)) = (start.trim().parse::<u32>(), end.trim().parse::<u32>()) {
                if start <= end {
                    cpus.extend(start..=end);
                }
            }
        } else if let Ok(cpu) = item.trim().parse() {
            cpus.insert(cpu);
        }
    }
    cpus.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kernel_cpu_lists() {
        assert_eq!(parse_cpu_list("0-2,5,8-9\n"), vec![0, 1, 2, 5, 8, 9]);
    }

    #[test]
    fn builds_orders_and_llc_groups() {
        let view = TopologyView::from_cpus(vec![
            CpuInfo {
                cpu: 3,
                node: 1,
                package: 1,
                llc: 2,
                core: 1,
            },
            CpuInfo {
                cpu: 0,
                node: 0,
                package: 0,
                llc: 0,
                core: 0,
            },
            CpuInfo {
                cpu: 2,
                node: 1,
                package: 1,
                llc: 2,
                core: 0,
            },
        ])
        .unwrap();

        assert_eq!(view.cpu_count, 3);
        assert_eq!(view.numeric_order, vec![0, 2, 3]);
        assert_eq!(view.topology_order, vec![0, 2, 3]);
        assert_eq!(view.llc_groups[1].cpus, vec![2, 3]);
    }

    #[test]
    fn discovers_current_host() {
        let view = TopologyView::discover().unwrap();
        assert!(view.cpu_count > 0);
        assert_eq!(view.cpu_count as usize, view.cpus.len());
        assert!(!view.llc_groups.is_empty());
    }
}
