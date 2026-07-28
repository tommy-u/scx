// SPDX-License-Identifier: GPL-2.0-only

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context, Result};

use crate::policy::CompiledPolicy;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellResources {
    pub id: u32,
    pub cpu_weight: u32,
    pub claimed: BTreeSet<u32>,
    pub primary: BTreeSet<u32>,
    pub borrowable: BTreeSet<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CellAllocation {
    pub cells: BTreeMap<u32, CellResources>,
    pub cpu_owners: BTreeMap<u32, u32>,
}

pub fn resolve_cell_allocation(
    policy: &CompiledPolicy,
    available_cpus: &BTreeSet<u32>,
) -> Result<Option<CellAllocation>> {
    let Some(queue_policy) = &policy.queues else {
        return Ok(None);
    };
    if available_cpus.is_empty() {
        bail!("cannot allocate cell resources without available CPUs");
    }
    for (&cell_id, claimed) in &policy.cells {
        if let Some(cpu) = claimed.difference(available_cpus).next() {
            bail!("cell {cell_id} references unavailable CPU {cpu}");
        }
    }

    let nr_cells = policy.cells.len() + 1;
    if available_cpus.len() < nr_cells {
        bail!(
            "cell queue policy requires at least {nr_cells} CPUs for {nr_cells} cells, but only {} are available",
            available_cpus.len()
        );
    }

    let mut claims = policy.cells.clone();
    claims.insert(0, available_cpus.clone());
    let mut weights = policy.cell_cpu_weights.clone();
    weights.insert(0, queue_policy.cell0_cpu_weight);
    let targets = weighted_targets(available_cpus.len(), &weights)?;
    let explicit_claimants = explicit_claimants(&policy.cells, available_cpus);

    let mut cpu_owners = BTreeMap::new();
    let mut minimum_order = policy
        .cells
        .iter()
        .map(|(&cell_id, cpus)| (cpus.len(), cell_id))
        .collect::<Vec<_>>();
    minimum_order.sort_unstable();
    for (_, cell_id) in minimum_order {
        let mut visited = BTreeSet::new();
        if !assign_minimum(cell_id, &policy.cells, &mut cpu_owners, &mut visited) {
            bail!("cell {cell_id} cannot be assigned a primary CPU");
        }
    }

    let cell0_cpu = available_cpus
        .iter()
        .copied()
        .filter(|cpu| !cpu_owners.contains_key(cpu))
        .min_by_key(|cpu| {
            let claimants = explicit_claimants.get(cpu).map_or(0, BTreeSet::len);
            (
                usize::from(claimants != 0),
                usize::MAX - claimants,
                *cpu as usize,
            )
        })
        .context("no CPU remains for synthetic cell 0")?;
    cpu_owners.insert(cell0_cpu, 0);

    for &cpu in available_cpus {
        if !cpu_owners.contains_key(&cpu)
            && explicit_claimants.get(&cpu).is_none_or(BTreeSet::is_empty)
        {
            cpu_owners.insert(cpu, 0);
        }
    }

    let mut remaining = available_cpus
        .iter()
        .copied()
        .filter(|cpu| !cpu_owners.contains_key(cpu))
        .collect::<Vec<_>>();
    remaining.sort_by_key(|cpu| (explicit_claimants.get(cpu).map_or(0, BTreeSet::len), *cpu));
    for cpu in remaining {
        let mut candidates = explicit_claimants.get(&cpu).cloned().unwrap_or_default();
        let counts = assigned_counts(&cpu_owners);
        if counts.get(&0).copied().unwrap_or(0) < targets[&0] {
            candidates.insert(0);
        }
        let owner = choose_owner(&candidates, &counts, &targets, &weights)
            .with_context(|| format!("CPU {cpu} has no eligible cell owner"))?;
        cpu_owners.insert(cpu, owner);
    }

    if cpu_owners.len() != available_cpus.len() {
        bail!("cell allocation did not assign every available CPU");
    }

    let mut cells = BTreeMap::new();
    for (&cell_id, claimed) in &claims {
        let primary = cpu_owners
            .iter()
            .filter_map(|(&cpu, &owner)| (owner == cell_id).then_some(cpu))
            .collect::<BTreeSet<_>>();
        if primary.is_empty() {
            bail!("cell {cell_id} has no primary CPU");
        }
        let borrowable = claimed.difference(&primary).copied().collect();
        cells.insert(
            cell_id,
            CellResources {
                id: cell_id,
                cpu_weight: weights[&cell_id],
                claimed: claimed.clone(),
                primary,
                borrowable,
            },
        );
    }

    Ok(Some(CellAllocation { cells, cpu_owners }))
}

fn weighted_targets(
    total_cpus: usize,
    weights: &BTreeMap<u32, u32>,
) -> Result<BTreeMap<u32, usize>> {
    if weights.is_empty() || total_cpus < weights.len() {
        bail!("not enough CPUs to give every cell a primary CPU");
    }
    let total_weight = weights.values().try_fold(0_u64, |sum, &weight| {
        sum.checked_add(u64::from(weight))
            .context("cell CPU weight total overflow")
    })?;
    if total_weight == 0 {
        bail!("cell CPU weight total must be positive");
    }
    let distributable = total_cpus - weights.len();
    let mut assigned = weights.len();
    let mut shares = weights
        .iter()
        .map(|(&cell_id, &weight)| {
            let numerator = distributable as u64 * u64::from(weight);
            let extra = (numerator / total_weight) as usize;
            assigned += extra;
            (cell_id, 1 + extra, numerator % total_weight)
        })
        .collect::<Vec<_>>();
    shares.sort_by_key(|(cell_id, _, remainder)| (std::cmp::Reverse(*remainder), *cell_id));
    for (_, target, _) in shares.iter_mut().take(total_cpus - assigned) {
        *target += 1;
    }
    Ok(shares
        .into_iter()
        .map(|(cell_id, target, _)| (cell_id, target))
        .collect())
}

fn explicit_claimants(
    cells: &BTreeMap<u32, BTreeSet<u32>>,
    available_cpus: &BTreeSet<u32>,
) -> BTreeMap<u32, BTreeSet<u32>> {
    available_cpus
        .iter()
        .filter_map(|&cpu| {
            let claimants = cells
                .iter()
                .filter_map(|(&cell_id, cpus)| cpus.contains(&cpu).then_some(cell_id))
                .collect::<BTreeSet<_>>();
            (!claimants.is_empty()).then_some((cpu, claimants))
        })
        .collect()
}

fn assign_minimum(
    cell_id: u32,
    claims: &BTreeMap<u32, BTreeSet<u32>>,
    cpu_owners: &mut BTreeMap<u32, u32>,
    visited: &mut BTreeSet<u32>,
) -> bool {
    let Some(cpus) = claims.get(&cell_id) else {
        return false;
    };
    for &cpu in cpus {
        if !visited.insert(cpu) {
            continue;
        }
        let previous = cpu_owners.get(&cpu).copied();
        if previous.is_none()
            || assign_minimum(
                previous.expect("checked above"),
                claims,
                cpu_owners,
                visited,
            )
        {
            cpu_owners.insert(cpu, cell_id);
            return true;
        }
    }
    false
}

fn assigned_counts(cpu_owners: &BTreeMap<u32, u32>) -> BTreeMap<u32, usize> {
    let mut counts = BTreeMap::new();
    for owner in cpu_owners.values() {
        *counts.entry(*owner).or_default() += 1;
    }
    counts
}

fn choose_owner(
    candidates: &BTreeSet<u32>,
    assigned: &BTreeMap<u32, usize>,
    targets: &BTreeMap<u32, usize>,
    weights: &BTreeMap<u32, u32>,
) -> Option<u32> {
    candidates.iter().copied().max_by(|a, b| {
        let a_assigned = assigned.get(a).copied().unwrap_or(0);
        let b_assigned = assigned.get(b).copied().unwrap_or(0);
        let a_deficit = targets[a] as i64 - a_assigned as i64;
        let b_deficit = targets[b] as i64 - b_assigned as i64;
        a_deficit.cmp(&b_deficit).then_with(|| {
            let a_scaled = a_assigned as u128 * u128::from(weights[b]);
            let b_scaled = b_assigned as u128 * u128::from(weights[a]);
            b_scaled.cmp(&a_scaled).then_with(|| b.cmp(a))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy;

    fn compile(cells: &str) -> CompiledPolicy {
        policy::compile_policy(&format!(
            r#"
[queues]
layout = "cell"
{cells}
[[rung]]
operation = "pick_idle"
scope = "task_allowed"
"#
        ))
        .expect("policy should compile")
    }

    fn allocation(policy: &CompiledPolicy, cpus: &[u32]) -> CellAllocation {
        resolve_cell_allocation(policy, &cpus.iter().copied().collect())
            .expect("allocation should resolve")
            .expect("queue policy should produce an allocation")
    }

    #[test]
    fn placement_only_policy_has_no_resource_allocation() {
        let policy = policy::compile_policy(
            r#"
[[cell]]
id = 0
cpus = "0-1"
[[rung]]
operation = "pick_idle"
scope = "task_cell"
"#,
        )
        .expect("placement policy should compile");

        assert_eq!(
            resolve_cell_allocation(&policy, &BTreeSet::from([0, 1])).unwrap(),
            None
        );
    }

    #[test]
    fn overlapping_claims_resolve_to_exclusive_primary_owners() {
        let policy = compile(
            r#"
[[cell]]
id = 7
cpus = "0-3"

[[cell]]
id = 8
cpus = "2-5"
"#,
        );
        let allocation = allocation(&policy, &[0, 1, 2, 3, 4, 5]);

        assert_eq!(allocation.cells.len(), 3);
        assert!(allocation.cells.contains_key(&0));
        assert_eq!(allocation.cpu_owners.len(), 6);
        assert_eq!(
            allocation
                .cells
                .values()
                .flat_map(|cell| cell.primary.iter().copied())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([0, 1, 2, 3, 4, 5])
        );
        for (&cpu, &owner) in &allocation.cpu_owners {
            assert!(allocation.cells[&owner].primary.contains(&cpu));
        }
        assert!(allocation.cells[&7]
            .primary
            .is_disjoint(&allocation.cells[&8].primary));
        assert_eq!(
            allocation.cells[&7].borrowable,
            allocation.cells[&7]
                .claimed
                .difference(&allocation.cells[&7].primary)
                .copied()
                .collect()
        );
        assert_eq!(
            allocation.cells[&8].borrowable,
            allocation.cells[&8]
                .claimed
                .difference(&allocation.cells[&8].primary)
                .copied()
                .collect()
        );
    }

    #[test]
    fn contested_cpus_follow_configured_weights_deterministically() {
        let policy = compile(
            r#"
[[cell]]
id = 7
cpus = "0-7"
cpu_weight = 1

[[cell]]
id = 8
cpus = "0-7"
cpu_weight = 3
"#,
        );
        let first = allocation(&policy, &[0, 1, 2, 3, 4, 5, 6, 7]);
        let second = allocation(&policy, &[0, 1, 2, 3, 4, 5, 6, 7]);

        assert_eq!(first, second);
        assert_eq!(first.cells[&0].primary.len(), 2);
        assert_eq!(first.cells[&7].primary.len(), 2);
        assert_eq!(first.cells[&8].primary.len(), 4);
    }

    #[test]
    fn unclaimed_cpus_belong_to_synthetic_cell_zero() {
        let policy = compile(
            r#"
[[cell]]
id = 7
cpus = "0-1"
"#,
        );
        let allocation = allocation(&policy, &[0, 1, 2, 3]);

        assert_eq!(allocation.cells[&0].primary, BTreeSet::from([2, 3]));
        assert_eq!(allocation.cells[&0].claimed, BTreeSet::from([0, 1, 2, 3]));
        assert_eq!(allocation.cells[&0].borrowable, BTreeSet::from([0, 1]));
        assert_eq!(allocation.cells[&7].primary, BTreeSet::from([0, 1]));
    }

    #[test]
    fn rejects_unavailable_and_insufficient_cpus() {
        let unavailable = compile(
            r#"
[[cell]]
id = 7
cpus = "0,9"
"#,
        );
        let error = resolve_cell_allocation(&unavailable, &BTreeSet::from([0, 1]))
            .unwrap_err()
            .to_string();
        assert!(error.contains("unavailable CPU 9"), "{error}");

        let too_many = compile(
            r#"
[[cell]]
id = 7
cpus = "0"
[[cell]]
id = 8
cpus = "0"
"#,
        );
        let error = resolve_cell_allocation(&too_many, &BTreeSet::from([0, 1]))
            .unwrap_err()
            .to_string();
        assert!(error.contains("requires at least 3 CPUs"), "{error}");
    }
}
