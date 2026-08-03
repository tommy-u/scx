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

#[cfg(test)]
pub fn resolve_cell_allocation(
    policy: &CompiledPolicy,
    available_cpus: &BTreeSet<u32>,
) -> Result<Option<CellAllocation>> {
    resolve_cell_allocation_with_llcs(policy, available_cpus, &BTreeMap::new())
}

pub fn resolve_cell_allocation_with_llcs(
    policy: &CompiledPolicy,
    available_cpus: &BTreeSet<u32>,
    cpu_to_llc: &BTreeMap<u32, u32>,
) -> Result<Option<CellAllocation>> {
    if policy.managed_cells.is_some() {
        return resolve_managed_cell_allocation(policy, available_cpus, cpu_to_llc, None).map(Some);
    }
    resolve_static_cell_allocation(policy, available_cpus)
}

pub fn resolve_managed_cell_allocation(
    policy: &CompiledPolicy,
    available_cpus: &BTreeSet<u32>,
    cpu_to_llc: &BTreeMap<u32, u32>,
    demand_weights: Option<&BTreeMap<u32, f64>>,
) -> Result<CellAllocation> {
    if policy.queues.is_none() {
        bail!("managed cells require a queue policy");
    }
    if available_cpus.is_empty() {
        bail!("cannot allocate cell resources without available CPUs");
    }

    let mut specs = vec![ManagedCellSpec {
        id: 0,
        constraint: None,
        allowed: available_cpus.clone(),
    }];
    for &cell_id in policy.cells.keys() {
        let allowed = policy.cells[&cell_id]
            .intersection(available_cpus)
            .copied()
            .collect::<BTreeSet<_>>();
        let constraint = policy
            .cell_cpu_constraints
            .get(&cell_id)
            .cloned()
            .unwrap_or_else(|| Some(policy.cells[&cell_id].clone()))
            .map(|constraint| constraint.intersection(&allowed).copied().collect());
        specs.push(ManagedCellSpec {
            id: cell_id,
            constraint,
            allowed,
        });
    }
    specs.sort_by_key(|spec| spec.id);

    let weights = managed_weights(policy, &specs, demand_weights)?;
    let targets = weighted_targets_f64(available_cpus.len(), &weights)?;
    let contention = managed_contention(&specs);
    let holdout = compute_cell0_holdout(
        available_cpus,
        &contention,
        policy
            .managed_cells
            .as_ref()
            .expect("checked above")
            .cell0_min_cpus,
        cpu_to_llc,
        &specs,
    );
    let (mut primary, contested, unclaimed) =
        classify_managed_cpus(available_cpus, &contention, &holdout);
    let mut assigned = primary
        .iter()
        .map(|(&cell_id, cpus)| (cell_id, cpus.len()))
        .collect::<BTreeMap<_, _>>();
    let initial_deficit = targets
        .iter()
        .map(|(&cell_id, &target)| {
            (
                cell_id,
                target.saturating_sub(assigned.get(&cell_id).copied().unwrap_or(0)) as f64,
            )
        })
        .collect::<BTreeMap<_, _>>();

    for (claimants, cpus) in contested {
        let mut recipients = claimants
            .iter()
            .map(|cell_id| (*cell_id, initial_deficit[cell_id]))
            .collect::<Vec<_>>();
        if recipients.iter().all(|(_, weight)| *weight == 0.0) {
            recipients.iter_mut().for_each(|(_, weight)| *weight = 1.0);
        }
        for (cell_id, cpus) in distribute_cpus_proportional(&cpus, &recipients)? {
            *assigned.entry(cell_id).or_default() += cpus.len();
            primary.entry(cell_id).or_default().extend(cpus);
        }
    }

    let mut unclaimed_groups = BTreeMap::<Vec<u32>, Vec<u32>>::new();
    for cpu in unclaimed {
        let eligible = specs
            .iter()
            .filter(|spec| spec.constraint.is_none() && spec.allowed.contains(&cpu))
            .map(|spec| spec.id)
            .collect::<Vec<_>>();
        unclaimed_groups.entry(eligible).or_default().push(cpu);
    }
    for (eligible, cpus) in unclaimed_groups {
        let mut recipients = eligible
            .into_iter()
            .map(|cell_id| {
                let target = targets[&cell_id];
                let current = assigned.get(&cell_id).copied().unwrap_or(0);
                (cell_id, target.saturating_sub(current) as f64)
            })
            .collect::<Vec<_>>();
        if recipients.iter().all(|(_, weight)| *weight == 0.0) {
            recipients.iter_mut().for_each(|(_, weight)| *weight = 1.0);
        }
        for (cell_id, cpus) in distribute_cpus_proportional(&cpus, &recipients)? {
            *assigned.entry(cell_id).or_default() += cpus.len();
            primary.entry(cell_id).or_default().extend(cpus);
        }
    }

    build_managed_allocation(policy, available_cpus, &specs, &contention, primary)
}

fn resolve_static_cell_allocation(
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

#[derive(Clone, Debug)]
struct ManagedCellSpec {
    id: u32,
    constraint: Option<BTreeSet<u32>>,
    allowed: BTreeSet<u32>,
}

fn managed_weights(
    policy: &CompiledPolicy,
    specs: &[ManagedCellSpec],
    demand_weights: Option<&BTreeMap<u32, f64>>,
) -> Result<BTreeMap<u32, f64>> {
    let queue_policy = policy.queues.as_ref().context("missing queue policy")?;
    specs
        .iter()
        .map(|spec| {
            let weight = match demand_weights {
                Some(weights) => *weights
                    .get(&spec.id)
                    .with_context(|| format!("cell {} is missing a demand weight", spec.id))?,
                None if spec.id == 0 => f64::from(queue_policy.cell0_cpu_weight),
                None => f64::from(policy.cell_cpu_weights.get(&spec.id).copied().unwrap_or(1)),
            };
            if !weight.is_finite() || weight < 0.0 {
                bail!("cell {} has invalid demand weight {weight}", spec.id);
            }
            Ok((spec.id, weight))
        })
        .collect()
}

fn weighted_targets_f64(
    total_cpus: usize,
    weights: &BTreeMap<u32, f64>,
) -> Result<BTreeMap<u32, usize>> {
    if weights.is_empty() || total_cpus < weights.len() {
        bail!(
            "not enough CPUs ({total_cpus}) for {} cells (need at least 1 each)",
            weights.len()
        );
    }
    let total_weight = weights.values().sum::<f64>();
    if total_weight <= 0.0 {
        let per = total_cpus / weights.len();
        let remainder = total_cpus % weights.len();
        return Ok(weights
            .keys()
            .enumerate()
            .map(|(index, &cell_id)| (cell_id, per + usize::from(index < remainder)))
            .collect());
    }

    let distributable = total_cpus - weights.len();
    let mut assigned = weights.len();
    let mut shares = weights
        .iter()
        .map(|(&cell_id, &weight)| {
            let exact = weight / total_weight * distributable as f64;
            let extra = exact.floor() as usize;
            assigned += extra;
            (cell_id, 1 + extra, exact.fract())
        })
        .collect::<Vec<_>>();
    shares.sort_by(|left, right| {
        right
            .2
            .total_cmp(&left.2)
            .then_with(|| left.0.cmp(&right.0))
    });
    for (_, count, _) in shares.iter_mut().take(total_cpus - assigned) {
        *count += 1;
    }
    Ok(shares
        .into_iter()
        .map(|(cell_id, count, _)| (cell_id, count))
        .collect())
}

fn distribute_cpus_proportional(
    cpus: &[u32],
    recipients: &[(u32, f64)],
) -> Result<BTreeMap<u32, Vec<u32>>> {
    if cpus.is_empty() || recipients.is_empty() {
        bail!("CPU distribution requires CPUs and recipients");
    }
    if recipients
        .iter()
        .any(|(_, weight)| !weight.is_finite() || *weight < 0.0)
    {
        bail!("CPU distribution weights must be finite and non-negative");
    }

    let total_weight = recipients.iter().map(|(_, weight)| *weight).sum::<f64>();
    let mut allocations = if total_weight <= 0.0 {
        let per = cpus.len() / recipients.len();
        let remainder = cpus.len() % recipients.len();
        recipients
            .iter()
            .enumerate()
            .map(|(index, (cell_id, _))| (*cell_id, per + usize::from(index < remainder), false))
            .collect::<Vec<_>>()
    } else {
        let mut assigned = 0;
        let mut raw = recipients
            .iter()
            .map(|(cell_id, weight)| {
                let exact = weight / total_weight * cpus.len() as f64;
                let count = exact.floor() as usize;
                assigned += count;
                (*cell_id, count, exact.fract(), *weight > 0.0)
            })
            .collect::<Vec<_>>();
        raw.sort_by(|left, right| {
            right
                .2
                .total_cmp(&left.2)
                .then_with(|| left.0.cmp(&right.0))
        });
        for (_, count, _, _) in raw.iter_mut().take(cpus.len() - assigned) {
            *count += 1;
        }
        loop {
            let Some(starved) = raw
                .iter()
                .position(|(_, count, _, positive)| *positive && *count == 0)
            else {
                break;
            };
            let Some(donor) = raw
                .iter()
                .enumerate()
                .filter(|(_, (_, count, _, _))| *count > 1)
                .max_by_key(|(index, (_, count, _, _))| (*count, *index))
                .map(|(index, _)| index)
            else {
                break;
            };
            raw[donor].1 -= 1;
            raw[starved].1 += 1;
        }
        raw.into_iter()
            .map(|(cell_id, count, _, positive)| (cell_id, count, positive))
            .collect()
    };

    allocations.sort_by_key(|(cell_id, _, _)| *cell_id);
    let mut cpu_iter = cpus.iter().copied();
    let mut result = BTreeMap::new();
    for (cell_id, count, _) in allocations {
        let assigned = cpu_iter.by_ref().take(count).collect::<Vec<_>>();
        if assigned.len() != count {
            bail!("cell {cell_id} CPU distribution was short");
        }
        if !assigned.is_empty() {
            result.insert(cell_id, assigned);
        }
    }
    Ok(result)
}

fn managed_contention(specs: &[ManagedCellSpec]) -> BTreeMap<u32, Vec<u32>> {
    let mut contention = BTreeMap::<u32, Vec<u32>>::new();
    for spec in specs {
        if let Some(constraint) = &spec.constraint {
            for &cpu in constraint {
                contention.entry(cpu).or_default().push(spec.id);
            }
        }
    }
    for claimants in contention.values_mut() {
        claimants.sort_unstable();
    }
    contention
}

fn compute_cell0_holdout(
    available_cpus: &BTreeSet<u32>,
    contention: &BTreeMap<u32, Vec<u32>>,
    cell0_min_cpus: usize,
    cpu_to_llc: &BTreeMap<u32, u32>,
    specs: &[ManagedCellSpec],
) -> BTreeSet<u32> {
    let protected = protected_unpinned_cpus(available_cpus, contention, specs);
    let mut unclaimed = available_cpus
        .iter()
        .filter(|cpu| !contention.contains_key(cpu) && !protected.contains(cpu))
        .copied()
        .collect::<Vec<_>>();
    unclaimed.sort_by_key(|cpu| {
        let eligible_children = specs
            .iter()
            .filter(|spec| spec.id != 0 && spec.constraint.is_none() && spec.allowed.contains(cpu))
            .count();
        (eligible_children, *cpu)
    });
    let mut holdout = unclaimed
        .into_iter()
        .take(cell0_min_cpus)
        .collect::<BTreeSet<_>>();
    if holdout.len() >= cell0_min_cpus {
        return holdout;
    }

    let mut llc_cells = BTreeMap::<u32, BTreeSet<u32>>::new();
    for (&cpu, claimants) in contention {
        if let Some(&llc) = cpu_to_llc.get(&cpu) {
            llc_cells.entry(llc).or_default().extend(claimants);
        }
    }
    let partition_size = |cpu: u32| {
        cpu_to_llc
            .get(&cpu)
            .and_then(|llc| llc_cells.get(llc))
            .map_or(0, BTreeSet::len)
    };
    let mut cell_claimed = BTreeMap::<u32, Vec<u32>>::new();
    for (&cpu, claimants) in contention {
        if !available_cpus.contains(&cpu) {
            continue;
        }
        for &cell_id in claimants {
            cell_claimed.entry(cell_id).or_default().push(cpu);
        }
    }
    let mut taken_from = cell_claimed
        .keys()
        .map(|&cell_id| (cell_id, 0usize))
        .collect::<BTreeMap<_, _>>();

    while holdout.len() < cell0_min_cpus {
        let remaining = cell_claimed
            .iter()
            .map(|(&cell_id, cpus)| {
                (
                    cell_id,
                    cpus.iter()
                        .filter(|cpu| {
                            !holdout.contains(cpu)
                                && contention.get(cpu).is_some_and(|c| c.len() == 1)
                        })
                        .count(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let reservable = |cpu: u32| {
            contention
                .get(&cpu)
                .is_some_and(|claimants| claimants.iter().all(|cell| remaining[cell] >= 2))
        };
        let donor = cell_claimed
            .iter()
            .filter(|(_, cpus)| {
                cpus.iter()
                    .any(|cpu| !holdout.contains(cpu) && reservable(*cpu))
            })
            .map(|(&cell_id, _)| cell_id)
            .min_by(|left, right| {
                taken_from[left]
                    .cmp(&taken_from[right])
                    .then_with(|| remaining[right].cmp(&remaining[left]))
                    .then_with(|| left.cmp(right))
            });
        let Some(donor) = donor else {
            break;
        };
        let cpu = cell_claimed[&donor]
            .iter()
            .copied()
            .filter(|cpu| !holdout.contains(cpu) && reservable(*cpu))
            .min_by(|left, right| {
                let left_contested = contention[left].len() > 1;
                let right_contested = contention[right].len() > 1;
                left_contested
                    .cmp(&right_contested)
                    .then_with(|| partition_size(*right).cmp(&partition_size(*left)))
                    .then_with(|| left.cmp(right))
            })
            .expect("selected donor has a reservable CPU");
        holdout.insert(cpu);
        *taken_from.entry(donor).or_default() += 1;
    }
    holdout
}

fn protected_unpinned_cpus(
    available_cpus: &BTreeSet<u32>,
    contention: &BTreeMap<u32, Vec<u32>>,
    specs: &[ManagedCellSpec],
) -> BTreeSet<u32> {
    fn assign(
        cell_id: u32,
        eligible: &BTreeMap<u32, BTreeSet<u32>>,
        owners: &mut BTreeMap<u32, u32>,
        visited: &mut BTreeSet<u32>,
    ) -> bool {
        for &cpu in &eligible[&cell_id] {
            if !visited.insert(cpu) {
                continue;
            }
            let previous = owners.get(&cpu).copied();
            if previous.is_none()
                || assign(previous.expect("checked above"), eligible, owners, visited)
            {
                owners.insert(cpu, cell_id);
                return true;
            }
        }
        false
    }

    let eligible = specs
        .iter()
        .filter(|spec| spec.id != 0 && spec.constraint.is_none())
        .map(|spec| {
            let cpus = spec
                .allowed
                .intersection(available_cpus)
                .filter(|cpu| !contention.contains_key(cpu))
                .copied()
                .collect::<BTreeSet<_>>();
            (spec.id, cpus)
        })
        .collect::<BTreeMap<_, _>>();
    let mut order = eligible
        .iter()
        .map(|(&cell_id, cpus)| (cpus.len(), cell_id))
        .collect::<Vec<_>>();
    order.sort_unstable();
    let mut owners = BTreeMap::new();
    for (_, cell_id) in order {
        if !assign(cell_id, &eligible, &mut owners, &mut BTreeSet::new()) {
            return BTreeSet::new();
        }
    }
    owners.keys().copied().collect()
}

fn classify_managed_cpus(
    available_cpus: &BTreeSet<u32>,
    contention: &BTreeMap<u32, Vec<u32>>,
    holdout: &BTreeSet<u32>,
) -> (
    BTreeMap<u32, BTreeSet<u32>>,
    BTreeMap<Vec<u32>, Vec<u32>>,
    Vec<u32>,
) {
    let mut primary = BTreeMap::<u32, BTreeSet<u32>>::new();
    if !holdout.is_empty() {
        primary.insert(0, holdout.clone());
    }
    let mut contested = BTreeMap::<Vec<u32>, Vec<u32>>::new();
    let mut unclaimed = Vec::new();
    for &cpu in available_cpus {
        if holdout.contains(&cpu) {
            continue;
        }
        match contention.get(&cpu) {
            None => unclaimed.push(cpu),
            Some(claimants) if claimants.len() == 1 => {
                primary.entry(claimants[0]).or_default().insert(cpu);
            }
            Some(claimants) => contested.entry(claimants.clone()).or_default().push(cpu),
        }
    }
    (primary, contested, unclaimed)
}

fn build_managed_allocation(
    policy: &CompiledPolicy,
    available_cpus: &BTreeSet<u32>,
    specs: &[ManagedCellSpec],
    contention: &BTreeMap<u32, Vec<u32>>,
    primary: BTreeMap<u32, BTreeSet<u32>>,
) -> Result<CellAllocation> {
    let mut cells = BTreeMap::new();
    let mut cpu_owners = BTreeMap::new();
    for spec in specs {
        let primary = primary.get(&spec.id).cloned().unwrap_or_default();
        if primary.is_empty() {
            bail!(
                "cell {} has no CPUs assigned (nr_cpus={}, num_cells={})",
                spec.id,
                available_cpus.len(),
                specs.len()
            );
        }
        let claimed = spec
            .constraint
            .clone()
            .unwrap_or_else(|| spec.allowed.clone());
        if !primary.is_subset(&claimed) && spec.id != 0 {
            bail!("cell {} has a primary CPU outside its cpuset", spec.id);
        }
        let borrowable = claimed.difference(&primary).copied().collect();
        for &cpu in &primary {
            if cpu_owners.insert(cpu, spec.id).is_some() {
                bail!("CPU {cpu} has multiple primary owners");
            }
        }
        let cpu_weight = if spec.id == 0 {
            policy
                .queues
                .as_ref()
                .expect("queue policy")
                .cell0_cpu_weight
        } else {
            policy.cell_cpu_weights.get(&spec.id).copied().unwrap_or(1)
        };
        cells.insert(
            spec.id,
            CellResources {
                id: spec.id,
                cpu_weight,
                claimed,
                primary,
                borrowable,
            },
        );
    }
    for &cpu in available_cpus {
        if !cpu_owners.contains_key(&cpu) {
            bail!("CPU {cpu} is not assigned to any cell");
        }
    }
    for (&cpu, claimants) in contention {
        if !available_cpus.contains(&cpu) {
            continue;
        }
        let owner = cpu_owners[&cpu];
        if owner != 0 && !claimants.contains(&owner) {
            bail!("claimed CPU {cpu} is assigned to non-claimant cell {owner}");
        }
    }
    Ok(CellAllocation { cells, cpu_owners })
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

    fn managed(constraints: &[(u32, Option<&[u32]>)], cell0_min_cpus: usize) -> CompiledPolicy {
        let mut policy = policy::compile_policy(&format!(
            r#"
[managed_cells]
parent = "/workloads"
cell0_min_cpus = {cell0_min_cpus}

[queues]
layout = "cell"

[[rung]]
operation = "pick_idle"
scope = "task_cell"
"#
        ))
        .expect("managed policy should compile");
        for &(cell_id, cpus) in constraints {
            let constraint = cpus.map(|cpus| cpus.iter().copied().collect::<BTreeSet<_>>());
            policy.cells.insert(
                cell_id,
                constraint
                    .clone()
                    .unwrap_or_else(|| (0..64).collect::<BTreeSet<_>>()),
            );
            policy.cell_cpu_constraints.insert(cell_id, constraint);
            policy.cell_cpu_weights.insert(cell_id, 1);
        }
        policy
    }

    fn managed_allocation(
        policy: &CompiledPolicy,
        cpus: &[u32],
        demands: Option<&BTreeMap<u32, f64>>,
    ) -> Result<CellAllocation> {
        let available = cpus.iter().copied().collect::<BTreeSet<_>>();
        let llcs = cpus
            .iter()
            .map(|&cpu| (cpu, cpu / 2))
            .collect::<BTreeMap<_, _>>();
        resolve_managed_cell_allocation(policy, &available, &llcs, demands)
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

    #[test]
    fn managed_no_children_assigns_every_cpu_to_cell_zero() {
        let allocation = managed_allocation(&managed(&[], 0), &[0, 1, 2, 3], None).unwrap();

        assert_eq!(allocation.cells.keys().copied().collect::<Vec<_>>(), [0]);
        assert_eq!(allocation.cells[&0].primary, BTreeSet::from([0, 1, 2, 3]));
        assert!(allocation.cells[&0].borrowable.is_empty());
    }

    #[test]
    fn managed_full_cpuset_coverage_needs_a_cell_zero_holdout() {
        let policy = managed(&[(1, Some(&[0, 1])), (2, Some(&[2, 3]))], 0);
        let error = managed_allocation(&policy, &[0, 1, 2, 3], None)
            .unwrap_err()
            .to_string();
        assert!(error.contains("cell 0 has no CPUs assigned"), "{error}");

        let policy = managed(&[(1, Some(&[0, 1])), (2, Some(&[2, 3]))], 1);
        let allocation = managed_allocation(&policy, &[0, 1, 2, 3], None).unwrap();
        assert_eq!(allocation.cells[&0].primary.len(), 1);
        assert!(!allocation.cells[&1].primary.is_empty());
        assert!(!allocation.cells[&2].primary.is_empty());
    }

    #[test]
    fn managed_holdout_never_takes_a_childs_last_exclusive_cpu() {
        let policy = managed(&[(1, Some(&[0, 1])), (2, Some(&[2, 3]))], 3);
        let allocation = managed_allocation(&policy, &[0, 1, 2, 3], None).unwrap();

        assert_eq!(allocation.cells[&0].primary.len(), 2);
        assert_eq!(allocation.cells[&1].primary.len(), 1);
        assert_eq!(allocation.cells[&2].primary.len(), 1);
    }

    #[test]
    fn managed_holdout_never_takes_an_unpinned_childs_last_cpu() {
        let policy = managed(&[(1, None)], 4);
        let allocation = managed_allocation(&policy, &[0, 1], None).unwrap();

        assert_eq!(allocation.cells[&0].primary.len(), 1);
        assert_eq!(allocation.cells[&1].primary.len(), 1);
    }

    #[test]
    fn managed_unpinned_cells_split_only_unclaimed_cpus() {
        let policy = managed(&[(1, Some(&[0, 1])), (2, None), (3, None)], 0);
        let allocation = managed_allocation(&policy, &[0, 1, 2, 3, 4], None).unwrap();

        assert_eq!(allocation.cells[&1].primary, BTreeSet::from([0, 1]));
        assert_eq!(allocation.cells[&0].primary.len(), 1);
        assert_eq!(allocation.cells[&2].primary.len(), 1);
        assert_eq!(allocation.cells[&3].primary.len(), 1);
        assert!(allocation.cells[&2]
            .primary
            .is_subset(&BTreeSet::from([2, 3, 4])));
        assert!(allocation.cells[&3]
            .primary
            .is_subset(&BTreeSet::from([2, 3, 4])));
    }

    #[test]
    fn managed_overlapping_constraints_split_contested_cpus() {
        let policy = managed(&[(1, Some(&[0, 1, 2])), (2, Some(&[1, 2, 3]))], 1);
        let allocation = managed_allocation(&policy, &[0, 1, 2, 3, 4], None).unwrap();

        assert_eq!(allocation.cpu_owners.len(), 5);
        assert!(allocation.cells[&1]
            .primary
            .is_subset(&BTreeSet::from([0, 1, 2])));
        assert!(allocation.cells[&2]
            .primary
            .is_subset(&BTreeSet::from([1, 2, 3])));
        assert!(allocation.cells[&1]
            .primary
            .is_disjoint(&allocation.cells[&2].primary));
    }

    #[test]
    fn managed_borrowable_masks_respect_constraints() {
        let policy = managed(&[(1, Some(&[0, 1, 2])), (2, None)], 0);
        let allocation = managed_allocation(&policy, &[0, 1, 2, 3, 4], None).unwrap();

        assert_eq!(
            allocation.cells[&1].borrowable,
            BTreeSet::from([0, 1, 2])
                .difference(&allocation.cells[&1].primary)
                .copied()
                .collect()
        );
        assert_eq!(
            allocation.cells[&2].borrowable,
            BTreeSet::from([0, 1, 2, 3, 4])
                .difference(&allocation.cells[&2].primary)
                .copied()
                .collect()
        );
    }

    #[test]
    fn managed_target_rounding_prefers_the_lowest_cell_id() {
        let weights = BTreeMap::from([(0, 1.0), (1, 1.0), (2, 1.0)]);

        assert_eq!(
            weighted_targets_f64(10, &weights).unwrap(),
            BTreeMap::from([(0, 4), (1, 3), (2, 3)])
        );
    }

    #[test]
    fn managed_demand_weights_allocate_cpus_proportionally() {
        let policy = managed(&[(1, None), (2, None)], 0);
        let demands = BTreeMap::from([(0, 1.0), (1, 1.0), (2, 3.0)]);

        let allocation =
            managed_allocation(&policy, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], Some(&demands)).unwrap();

        assert_eq!(allocation.cells[&0].primary.len(), 3);
        assert_eq!(allocation.cells[&1].primary.len(), 2);
        assert_eq!(allocation.cells[&2].primary.len(), 5);
    }

    #[test]
    fn managed_demand_weights_preserve_constraints_and_holdout() {
        let policy = managed(&[(1, Some(&[0, 1, 2])), (2, None)], 1);
        let demands = BTreeMap::from([(0, 0.0), (1, 80.0), (2, 20.0)]);
        let allocation = managed_allocation(&policy, &[0, 1, 2, 3, 4, 5], Some(&demands)).unwrap();

        assert_eq!(allocation.cells[&0].primary.len(), 1);
        assert_eq!(allocation.cells[&1].primary, BTreeSet::from([0, 1, 2]));
        assert!(allocation.cells[&2]
            .primary
            .is_subset(&BTreeSet::from([3, 4, 5])));
        assert_eq!(allocation.cells[&2].primary.len(), 2);
    }

    #[test]
    fn managed_demand_weights_reject_missing_cells() {
        let policy = managed(&[(1, None), (2, None)], 0);
        let demands = BTreeMap::from([(0, 1.0), (1, 1.0)]);

        let error = managed_allocation(&policy, &[0, 1, 2], Some(&demands))
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("cell 2 is missing a demand weight"),
            "{error}"
        );
    }

    #[test]
    fn managed_demand_weights_reject_negative_and_non_finite_values() {
        let policy = managed(&[(1, None)], 0);
        for invalid in [-1.0, f64::NAN, f64::INFINITY] {
            let demands = BTreeMap::from([(0, 1.0), (1, invalid)]);

            let error = managed_allocation(&policy, &[0, 1], Some(&demands))
                .unwrap_err()
                .to_string();

            assert!(error.contains("invalid demand weight"), "{error}");
        }
    }
}
