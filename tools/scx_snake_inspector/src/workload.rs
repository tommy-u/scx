// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

pub const MAX_WORKLOAD_TIDS: usize = 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WorkloadTarget {
    Tid { tid: i32 },
    Tgid { tgid: i32 },
    Cgroup { path: String },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorkloadCellResponse {
    pub target: String,
    pub cell_id: Option<u32>,
    pub matched: usize,
    pub updated: usize,
    pub transient: Vec<i32>,
    pub rehome_requested: usize,
}

impl WorkloadTarget {
    pub fn label(&self) -> String {
        match self {
            Self::Tid { tid } => format!("TID {tid}"),
            Self::Tgid { tgid } => format!("TGID {tgid}"),
            Self::Cgroup { path } => format!("cgroup {path}"),
        }
    }
}

pub fn resolve_workload_target(
    target: &WorkloadTarget,
    proc_root: &Path,
    cgroup_root: &Path,
) -> Result<Vec<i32>> {
    let tids = match target {
        WorkloadTarget::Tid { tid } => BTreeSet::from([valid_tid(*tid)?]),
        WorkloadTarget::Tgid { tgid } => resolve_tgid(*tgid, proc_root)?,
        WorkloadTarget::Cgroup { path } => resolve_cgroup(path, cgroup_root)?,
    };
    if tids.is_empty() {
        bail!("{} currently contains no threads", target.label());
    }
    if tids.len() > MAX_WORKLOAD_TIDS {
        bail!(
            "{} resolves to {} threads; at most {MAX_WORKLOAD_TIDS} may be changed at once",
            target.label(),
            tids.len()
        );
    }
    Ok(tids.into_iter().collect())
}

fn valid_tid(tid: i32) -> Result<i32> {
    if tid <= 0 {
        bail!("thread IDs must be positive");
    }
    Ok(tid)
}

fn resolve_tgid(tgid: i32, proc_root: &Path) -> Result<BTreeSet<i32>> {
    valid_tid(tgid)?;
    let task_dir = proc_root.join(tgid.to_string()).join("task");
    let entries = fs::read_dir(&task_dir)
        .with_context(|| format!("reading current threads for TGID {tgid}"))?;
    let mut tids = BTreeSet::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("reading {}", task_dir.display()))?;
        let Ok(tid) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        tids.insert(valid_tid(tid)?);
    }
    Ok(tids)
}

fn resolve_cgroup(path: &str, cgroup_root: &Path) -> Result<BTreeSet<i32>> {
    let root = cgroup_root
        .canonicalize()
        .context("resolving cgroup root")?;
    let requested = Path::new(path.trim());
    if requested.as_os_str().is_empty() {
        bail!("cgroup path is required");
    }
    let relative = if requested.is_absolute() {
        requested
            .strip_prefix(&root)
            .or_else(|_| requested.strip_prefix("/"))
            .context("invalid absolute cgroup path")?
    } else {
        requested
    };
    let start = root
        .join(relative)
        .canonicalize()
        .with_context(|| format!("resolving cgroup path {path}"))?;
    if !start.starts_with(&root) || !start.is_dir() {
        bail!("cgroup path escapes the cgroup root or is not a directory");
    }

    let mut pending = vec![start];
    let mut tids = BTreeSet::new();
    while let Some(directory) = pending.pop() {
        read_thread_file(&directory.join("cgroup.threads"), &mut tids)?;
        if tids.len() > MAX_WORKLOAD_TIDS {
            break;
        }
        for entry in fs::read_dir(&directory)
            .with_context(|| format!("reading cgroup directory {}", directory.display()))?
        {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if !file_type.is_dir() || file_type.is_symlink() {
                continue;
            }
            let child = entry.path().canonicalize()?;
            if child.starts_with(&root) {
                pending.push(child);
            }
        }
    }
    Ok(tids)
}

fn read_thread_file(path: &Path, tids: &mut BTreeSet<i32>) -> Result<()> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("reading cgroup threads from {}", path.display()))?;
    for line in contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        let tid = line
            .parse::<i32>()
            .with_context(|| format!("invalid thread ID `{line}` in {}", path.display()))?;
        tids.insert(valid_tid(tid)?);
    }
    Ok(())
}
