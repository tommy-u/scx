// SPDX-License-Identifier: GPL-2.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use log::warn;

use crate::policy::{CompiledPolicy, MembershipPolicy, MAX_CELL_IDS};

pub fn resolve_managed_cells(policy: &mut CompiledPolicy) -> Result<()> {
    resolve_managed_cells_at(policy, Path::new("/sys/fs/cgroup"))
}

fn resolve_managed_cells_at(policy: &mut CompiledPolicy, cgroup_root: &Path) -> Result<()> {
    let Some(managed) = policy.managed_cells.clone() else {
        return Ok(());
    };
    let parent = resolved_parent(cgroup_root, Path::new(&managed.parent));
    if !fs::metadata(&parent)
        .with_context(|| format!("reading managed cell parent {}", parent.display()))?
        .is_dir()
    {
        bail!(
            "managed cell parent {} is not a directory",
            parent.display()
        );
    }

    let excluded = managed
        .exclude_children
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut children = Vec::new();
    for entry in fs::read_dir(&parent)
        .with_context(|| format!("enumerating managed cell parent {}", parent.display()))?
    {
        let entry = entry.with_context(|| format!("enumerating {}", parent.display()))?;
        if !entry
            .file_type()
            .with_context(|| format!("reading file type for {}", entry.path().display()))?
            .is_dir()
        {
            continue;
        }
        let name = entry.file_name().into_string().map_err(|name| {
            anyhow::anyhow!(
                "managed child name is not valid UTF-8: {}",
                name.to_string_lossy()
            )
        })?;
        if !excluded.contains(name.as_str()) {
            let inode = entry
                .metadata()
                .with_context(|| format!("reading metadata for {}", entry.path().display()))?
                .ino();
            children.push((name, entry.path(), inode));
        }
    }
    children.sort_by(|left, right| left.0.cmp(&right.0));
    let previous_assignments = policy
        .membership
        .as_ref()
        .map(|membership| membership.assignments.clone())
        .unwrap_or_default();
    let previous_inodes = policy
        .membership
        .as_ref()
        .and_then(|membership| membership.child_inodes.clone())
        .unwrap_or_default();

    let mut cells = BTreeMap::new();
    let mut constraints = BTreeMap::new();
    let mut weights = BTreeMap::new();
    let mut epochs = policy.cell_slot_epochs.clone();
    let mut assignments = BTreeMap::new();
    let mut child_inodes = BTreeMap::new();
    let mut used_ids = BTreeSet::new();
    let mut retained_ids = BTreeMap::new();
    for (name, _, _) in &children {
        let Some(cell_id) = previous_assignments.get(name).copied() else {
            continue;
        };
        if cell_id > 0
            && usize::try_from(cell_id).is_ok_and(|id| id <= managed.max_children)
            && used_ids.insert(cell_id)
        {
            retained_ids.insert(name.clone(), cell_id);
        }
    }
    for (name, path, inode) in children {
        let previous_id = retained_ids.get(&name).copied();
        let cell_id = match previous_id {
            Some(cell_id) => {
                if previous_inodes.get(&name).copied() != Some(inode) {
                    let next = epochs
                        .get(&cell_id)
                        .copied()
                        .unwrap_or(0)
                        .checked_add(1)
                        .context("managed cell slot epoch overflow")?;
                    epochs.insert(cell_id, next);
                }
                cell_id
            }
            None => {
                let Some(cell_id) = (1..=u32::try_from(managed.max_children)?)
                    .find(|cell_id| !used_ids.contains(cell_id))
                else {
                    warn!(
                        "managed child {name} remains in cell 0: all {} managed cell slots are occupied",
                        managed.max_children
                    );
                    continue;
                };
                let next = epochs
                    .get(&cell_id)
                    .copied()
                    .unwrap_or(0)
                    .checked_add(1)
                    .context("managed cell slot epoch overflow")?;
                epochs.insert(cell_id, next);
                cell_id
            }
        };
        used_ids.insert(cell_id);
        let (cpus, constraint) = read_stable_cpu_domain(&path, cgroup_root, &name)?;
        let current_inode = fs::metadata(&path)
            .with_context(|| format!("rechecking managed child {}", path.display()))?
            .ino();
        if current_inode != inode {
            bail!("managed child {name} identity changed during discovery");
        }
        cells.insert(cell_id, cpus);
        constraints.insert(cell_id, constraint);
        weights.insert(cell_id, 1);
        child_inodes.insert(name.clone(), inode);
        assignments.insert(name, cell_id);
    }

    let parent = parent
        .to_str()
        .context("managed cell parent is not valid UTF-8")?
        .to_owned();
    policy.cells = cells;
    policy.cell_cpu_constraints = constraints;
    policy.cell_cpu_weights = weights;
    policy.cell_slot_epochs = epochs;
    policy.membership = Some(MembershipPolicy {
        parent,
        reconcile_ms: managed.reconcile_ms,
        assignments,
        child_inodes: Some(child_inodes),
    });
    Ok(())
}

fn read_optional_cpu_file(path: &Path) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

fn read_effective_cpu_file(path: &Path, cgroup_root: &Path) -> Result<String> {
    let mut current = Some(path);
    while let Some(directory) = current {
        let effective_path = directory.join("cpuset.cpus.effective");
        if let Some(value) = read_optional_cpu_file(&effective_path)? {
            return Ok(value);
        }
        if directory == cgroup_root {
            break;
        }
        current = directory.parent();
    }
    bail!(
        "managed child {} has no effective cpuset in its cgroup ancestry",
        path.display()
    )
}

fn parse_cpu_file(value: &str, path: &Path, name: &str) -> Result<BTreeSet<u32>> {
    let cpus = scx_utils::read_cpulist(value)
        .with_context(|| format!("parsing {}", path.display()))?
        .into_iter()
        .map(|cpu| {
            u32::try_from(cpu)
                .with_context(|| format!("CPU {cpu} in {} does not fit u32", path.display()))
        })
        .collect::<Result<BTreeSet<_>>>()?;
    if let Some(cpu) = cpus.iter().find(|&&cpu| cpu >= MAX_CELL_IDS) {
        bail!(
            "managed child {name} CPU {cpu} exceeds mask capacity {}",
            MAX_CELL_IDS - 1
        );
    }
    Ok(cpus)
}

fn read_stable_cpu_domain(
    path: &Path,
    cgroup_root: &Path,
    name: &str,
) -> Result<(BTreeSet<u32>, Option<BTreeSet<u32>>)> {
    let configured_path = path.join("cpuset.cpus");
    let effective_path = path.join("cpuset.cpus.effective");
    let configured_before = read_optional_cpu_file(&configured_path)?;
    let effective_before = read_effective_cpu_file(path, cgroup_root)?;
    let configured_after = read_optional_cpu_file(&configured_path)?;
    let effective_after = read_effective_cpu_file(path, cgroup_root)?;
    if configured_before != configured_after || effective_before != effective_after {
        bail!("managed child {name} CPU domain changed during discovery");
    }

    let effective = effective_before.trim();
    if effective.is_empty() {
        bail!("managed child {name} has an empty effective CPU set");
    }
    let cpus = parse_cpu_file(effective, &effective_path, name)?;
    debug_assert!(!cpus.is_empty());
    let constraint = configured_before
        .as_deref()
        .map(str::trim)
        .filter(|configured| !configured.is_empty())
        .map(|configured| parse_cpu_file(configured, &configured_path, name))
        .transpose()?;
    Ok((cpus, constraint))
}

fn resolved_parent(cgroup_root: &Path, configured: &Path) -> PathBuf {
    if configured.starts_with(cgroup_root) {
        return configured.to_owned();
    }
    cgroup_root.join(
        configured
            .strip_prefix(Path::new("/"))
            .expect("managed cell parent is validated as absolute"),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::resolve_managed_cells_at;
    use crate::cell_allocation::resolve_cell_allocation;
    use crate::policy::{self, CompiledPolicy};

    fn temporary_root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "snake-managed-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn policy(parent: &str, max_children: usize, excluded: &[&str]) -> CompiledPolicy {
        let excluded = excluded
            .iter()
            .map(|child| format!("\"{child}\""))
            .collect::<Vec<_>>()
            .join(", ");
        policy::compile_policy(&format!(
            r#"
[managed_cells]
parent = "{parent}"
max_children = {max_children}
exclude_children = [{excluded}]
reconcile_ms = 250

[queues]
layout = "cell_llc"

[[rung]]
operation = "pick_idle_core"
scope = "task_cell"
"#
        ))
        .expect("managed policy should compile")
    }

    fn add_child(parent: &Path, name: &str, effective_cpus: &str) -> PathBuf {
        let child = parent.join(name);
        fs::create_dir_all(&child).unwrap();
        fs::write(child.join("cpuset.cpus"), effective_cpus).unwrap();
        fs::write(child.join("cpuset.cpus.effective"), effective_cpus).unwrap();
        child
    }

    fn set_cpuset(child: &Path, cpus: &str) {
        fs::write(child.join("cpuset.cpus"), cpus).unwrap();
    }

    #[test]
    fn direct_children_become_flat_cells_with_deterministic_ids() {
        let root = temporary_root("flat");
        let parent = root.join("workload.slice/workload-tw.slice");
        fs::create_dir_all(&parent).unwrap();
        let zeta = add_child(&parent, "zeta.service", "8-9,24-25\n");
        add_child(&zeta, "nested", "8\n");
        add_child(&parent, "alpha.service", "0-1,16-17\n");
        add_child(&parent, "systemd-workaround.service", "2-3\n");
        let mut policy = policy(
            "/workload.slice/workload-tw.slice",
            31,
            &["systemd-workaround.service"],
        );

        resolve_managed_cells_at(&mut policy, &root).unwrap();

        assert_eq!(
            policy.cells,
            BTreeMap::from([
                (1, BTreeSet::from([0, 1, 16, 17])),
                (2, BTreeSet::from([8, 9, 24, 25])),
            ])
        );
        assert_eq!(policy.cell_cpu_weights, BTreeMap::from([(1, 1), (2, 1)]));
        assert_eq!(policy.cell_slot_epochs, BTreeMap::from([(1, 1), (2, 1)]));
        let membership = policy.membership.expect("membership should be synthesized");
        assert_eq!(membership.parent, parent.to_string_lossy());
        assert_eq!(membership.reconcile_ms, 250);
        assert_eq!(
            membership
                .child_inodes
                .as_ref()
                .expect("managed children should pin cgroup identities")
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            ["alpha.service", "zeta.service"]
        );
        assert_eq!(
            membership.assignments,
            BTreeMap::from([("alpha.service".into(), 1), ("zeta.service".into(), 2)])
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn filesystem_absolute_parent_is_not_prefixed_twice() {
        let root = temporary_root("absolute");
        let parent = root.join("workloads");
        fs::create_dir_all(&parent).unwrap();
        add_child(&parent, "batch", "4-5\n");
        let mut policy = policy(&parent.to_string_lossy(), 1, &[]);

        resolve_managed_cells_at(&mut policy, &root).unwrap();

        assert_eq!(policy.membership.unwrap().parent, parent.to_string_lossy());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn discovery_leaves_capacity_overflow_unassigned_and_rejects_empty_cpusets() {
        let root = temporary_root("invalid");
        let parent = root.join("workloads");
        fs::create_dir_all(&parent).unwrap();
        add_child(&parent, "alpha", "0\n");
        add_child(&parent, "beta", "1\n");
        let mut too_many = policy("/workloads", 1, &[]);

        resolve_managed_cells_at(&mut too_many, &root).unwrap();
        assert_eq!(
            too_many.membership.unwrap().assignments,
            BTreeMap::from([("alpha".into(), 1)])
        );

        fs::remove_dir_all(parent.join("beta")).unwrap();
        fs::write(parent.join("alpha/cpuset.cpus.effective"), "\n").unwrap();
        let mut empty = policy("/workloads", 1, &[]);
        let error = resolve_managed_cells_at(&mut empty, &root)
            .unwrap_err()
            .to_string();
        assert!(error.contains("empty effective CPU set"), "{error}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn missing_child_cpuset_files_inherit_the_parent_effective_domain() {
        let root = temporary_root("inherited-controller");
        let parent = root.join("workloads");
        fs::create_dir_all(parent.join("batch")).unwrap();
        fs::write(parent.join("cpuset.cpus.effective"), "0-3\n").unwrap();
        let mut policy = policy("/workloads", 1, &[]);

        resolve_managed_cells_at(&mut policy, &root).unwrap();

        assert_eq!(policy.cells[&1], BTreeSet::from([0, 1, 2, 3]));
        assert_eq!(policy.cell_cpu_constraints[&1], None);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn repeated_discovery_preserves_slots_and_epochs_across_churn() {
        let root = temporary_root("churn");
        let parent = root.join("workloads");
        fs::create_dir_all(&parent).unwrap();
        add_child(&parent, "alpha", "0-1\n");
        add_child(&parent, "beta", "2-3\n");
        let mut policy = policy("/workloads", 2, &[]);

        resolve_managed_cells_at(&mut policy, &root).unwrap();
        assert_eq!(
            policy.membership.as_ref().unwrap().assignments,
            BTreeMap::from([("alpha".into(), 1), ("beta".into(), 2)])
        );

        fs::remove_dir_all(parent.join("alpha")).unwrap();
        resolve_managed_cells_at(&mut policy, &root).unwrap();
        assert_eq!(
            policy.membership.as_ref().unwrap().assignments,
            BTreeMap::from([("beta".into(), 2)])
        );
        assert_eq!(policy.cell_slot_epochs, BTreeMap::from([(1, 1), (2, 1)]));

        add_child(&parent, "gamma", "4-5\n");
        resolve_managed_cells_at(&mut policy, &root).unwrap();
        assert_eq!(
            policy.membership.as_ref().unwrap().assignments,
            BTreeMap::from([("beta".into(), 2), ("gamma".into(), 1)])
        );
        assert_eq!(policy.cell_slot_epochs, BTreeMap::from([(1, 2), (2, 1)]));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn same_name_replacement_advances_the_slot_epoch() {
        let root = temporary_root("replacement");
        let parent = root.join("workloads");
        fs::create_dir_all(&parent).unwrap();
        add_child(&parent, "alpha", "0-1\n");
        let mut policy = policy("/workloads", 1, &[]);

        resolve_managed_cells_at(&mut policy, &root).unwrap();
        let old_inode = policy
            .membership
            .as_ref()
            .unwrap()
            .child_inodes
            .as_ref()
            .unwrap()["alpha"];

        fs::remove_dir_all(parent.join("alpha")).unwrap();
        add_child(&parent, "replacement", "2-3\n");
        fs::rename(parent.join("replacement"), parent.join("alpha")).unwrap();
        resolve_managed_cells_at(&mut policy, &root).unwrap();

        let membership = policy.membership.as_ref().unwrap();
        assert_ne!(
            membership.child_inodes.as_ref().unwrap()["alpha"],
            old_inode
        );
        assert_eq!(membership.assignments["alpha"], 1);
        assert_eq!(policy.cell_slot_epochs[&1], 2);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_new_earlier_name_cannot_renumber_an_existing_child() {
        let root = temporary_root("stable-order");
        let parent = root.join("workloads");
        fs::create_dir_all(&parent).unwrap();
        add_child(&parent, "beta", "2-3\n");
        let mut policy = policy("/workloads", 2, &[]);
        resolve_managed_cells_at(&mut policy, &root).unwrap();
        assert_eq!(policy.membership.as_ref().unwrap().assignments["beta"], 1);

        add_child(&parent, "alpha", "0-1\n");
        resolve_managed_cells_at(&mut policy, &root).unwrap();

        assert_eq!(
            policy.membership.as_ref().unwrap().assignments,
            BTreeMap::from([("alpha".into(), 2), ("beta".into(), 1)])
        );
        assert_eq!(policy.cell_slot_epochs, BTreeMap::from([(1, 1), (2, 1)]));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn excess_new_children_remain_unassigned_in_cell_zero() {
        let root = temporary_root("overflow");
        let parent = root.join("workloads");
        fs::create_dir_all(&parent).unwrap();
        add_child(&parent, "alpha", "0\n");
        let mut policy = policy("/workloads", 1, &[]);
        resolve_managed_cells_at(&mut policy, &root).unwrap();

        add_child(&parent, "beta", "1\n");
        resolve_managed_cells_at(&mut policy, &root).unwrap();

        assert_eq!(
            policy.membership.as_ref().unwrap().assignments,
            BTreeMap::from([("alpha".into(), 1)])
        );
        assert!(!policy.cells.values().any(|cpus| cpus.contains(&1)));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inherited_cpuset_is_unpinned_and_only_uses_unclaimed_cpus() {
        let root = temporary_root("inherited-cpuset");
        let parent = root.join("workloads");
        fs::create_dir_all(&parent).unwrap();
        add_child(&parent, "pinned", "0-1\n");
        let inherited = add_child(&parent, "inherited", "0-3\n");
        set_cpuset(&inherited, "\n");
        let mut policy = policy("/workloads", 2, &[]);

        resolve_managed_cells_at(&mut policy, &root).unwrap();
        let allocation = resolve_cell_allocation(&policy, &BTreeSet::from([0, 1, 2, 3]))
            .unwrap()
            .unwrap();
        let assignments = &policy.membership.as_ref().unwrap().assignments;
        let pinned_id = assignments["pinned"];
        let inherited_id = assignments["inherited"];

        assert_eq!(allocation.cells[&pinned_id].primary.len(), 2);
        assert_eq!(allocation.cells[&inherited_id].primary.len(), 1);
        assert_eq!(allocation.cells[&0].primary.len(), 1);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inherited_cpuset_never_owns_cpus_outside_its_effective_mask() {
        let root = temporary_root("inherited-effective-bound");
        let parent = root.join("workloads");
        fs::create_dir_all(&parent).unwrap();
        let child = add_child(&parent, "restricted", "0-3\n");
        set_cpuset(&child, "\n");
        let mut policy = policy("/workloads", 1, &[]);

        resolve_managed_cells_at(&mut policy, &root).unwrap();
        let allocation =
            resolve_cell_allocation(&policy, &BTreeSet::from([0, 1, 2, 3, 4, 5, 6, 7]))
                .unwrap()
                .unwrap();
        let cell_id = policy.membership.as_ref().unwrap().assignments["restricted"];

        assert!(allocation.cells[&cell_id]
            .primary
            .is_subset(&BTreeSet::from([0, 1, 2, 3])));
        assert!(allocation.cells[&cell_id]
            .borrowable
            .is_subset(&BTreeSet::from([0, 1, 2, 3])));
        assert!(BTreeSet::from([4, 5, 6, 7]).is_subset(&allocation.cells[&0].primary));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn configured_cpuset_changes_constraints_without_reusing_the_slot() {
        let root = temporary_root("constraint-change");
        let parent = root.join("workloads");
        fs::create_dir_all(&parent).unwrap();
        let child = add_child(&parent, "alpha", "0-3\n");
        set_cpuset(&child, "0-1\n");
        let mut policy = policy("/workloads", 1, &[]);

        resolve_managed_cells_at(&mut policy, &root).unwrap();
        let cell_id = policy.membership.as_ref().unwrap().assignments["alpha"];
        let slot_epoch = policy.cell_slot_epochs[&cell_id];
        assert_eq!(
            policy.cell_cpu_constraints[&cell_id],
            Some(BTreeSet::from([0, 1]))
        );

        let pinned = policy.clone();
        set_cpuset(&child, "\n");
        resolve_managed_cells_at(&mut policy, &root).unwrap();

        assert_ne!(policy, pinned);
        assert_eq!(
            policy.membership.as_ref().unwrap().assignments["alpha"],
            cell_id
        );
        assert_eq!(policy.cell_slot_epochs[&cell_id], slot_epoch);
        assert_eq!(policy.cell_cpu_constraints[&cell_id], None);
        fs::remove_dir_all(root).unwrap();
    }
}
