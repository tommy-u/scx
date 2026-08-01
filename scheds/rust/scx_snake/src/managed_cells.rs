// SPDX-License-Identifier: GPL-2.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

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
    if children.len() > managed.max_children {
        bail!(
            "managed cell parent {} has {} managed children; maximum is {}",
            parent.display(),
            children.len(),
            managed.max_children
        );
    }

    let mut cells = BTreeMap::new();
    let mut weights = BTreeMap::new();
    let mut epochs = BTreeMap::new();
    let mut assignments = BTreeMap::new();
    let mut child_inodes = BTreeMap::new();
    for (index, (name, path, inode)) in children.into_iter().enumerate() {
        let cell_id = u32::try_from(index + 1).context("managed cell ID overflow")?;
        let effective_path = path.join("cpuset.cpus.effective");
        let cpulist = fs::read_to_string(&effective_path)
            .with_context(|| format!("reading {}", effective_path.display()))?;
        let cpulist = cpulist.trim();
        if cpulist.is_empty() {
            bail!("managed child {name} has an empty effective CPU set");
        }
        let cpus = scx_utils::read_cpulist(cpulist)
            .with_context(|| format!("parsing {}", effective_path.display()))?
            .into_iter()
            .map(|cpu| {
                u32::try_from(cpu)
                    .with_context(|| format!("CPU {cpu} in {} does not fit u32", path.display()))
            })
            .collect::<Result<BTreeSet<_>>>()?;
        debug_assert!(!cpus.is_empty());
        if let Some(cpu) = cpus.iter().find(|&&cpu| cpu >= MAX_CELL_IDS) {
            bail!(
                "managed child {name} CPU {cpu} exceeds mask capacity {}",
                MAX_CELL_IDS - 1
            );
        }
        let current_inode = fs::metadata(&path)
            .with_context(|| format!("rechecking managed child {}", path.display()))?
            .ino();
        if current_inode != inode {
            bail!("managed child {name} identity changed during discovery");
        }
        cells.insert(cell_id, cpus);
        weights.insert(cell_id, 1);
        epochs.insert(cell_id, 1);
        child_inodes.insert(name.clone(), inode);
        assignments.insert(name, cell_id);
    }

    let parent = parent
        .to_str()
        .context("managed cell parent is not valid UTF-8")?
        .to_owned();
    policy.cells = cells;
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
        fs::write(child.join("cpuset.cpus.effective"), effective_cpus).unwrap();
        child
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
    fn discovery_rejects_capacity_overflow_and_empty_effective_cpusets() {
        let root = temporary_root("invalid");
        let parent = root.join("workloads");
        fs::create_dir_all(&parent).unwrap();
        add_child(&parent, "alpha", "0\n");
        add_child(&parent, "beta", "1\n");
        let mut too_many = policy("/workloads", 1, &[]);

        let error = resolve_managed_cells_at(&mut too_many, &root)
            .unwrap_err()
            .to_string();
        assert!(error.contains("2 managed children"), "{error}");
        assert!(error.contains("maximum is 1"), "{error}");

        fs::remove_dir_all(parent.join("beta")).unwrap();
        fs::write(parent.join("alpha/cpuset.cpus.effective"), "\n").unwrap();
        let mut empty = policy("/workloads", 1, &[]);
        let error = resolve_managed_cells_at(&mut empty, &root)
            .unwrap_err()
            .to_string();
        assert!(error.contains("empty effective CPU set"), "{error}");
        fs::remove_dir_all(root).unwrap();
    }
}
