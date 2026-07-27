// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const MAX_TRACKED_TGIDS: usize = 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ScopeRequest {
    All,
    Tgids { tgids: Vec<u32> },
    Cgroup { path: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskScope {
    All,
    Tgids(Vec<u32>),
    Cgroup { path: PathBuf, cgroup_id: u64 },
}

impl TaskScope {
    pub fn tgids(tgids: Vec<u32>) -> Self {
        Self::Tgids(tgids)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeError(String);

impl ScopeError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl Display for ScopeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for ScopeError {}

pub fn resolve_scope(request: ScopeRequest, cgroup_root: &Path) -> Result<TaskScope, ScopeError> {
    match request {
        ScopeRequest::All => Ok(TaskScope::All),
        ScopeRequest::Tgids { mut tgids } => {
            tgids.sort_unstable();
            tgids.dedup();
            if tgids.is_empty() {
                return Err(ScopeError::new("at least one TGID is required"));
            }
            if tgids[0] == 0 {
                return Err(ScopeError::new("TGID 0 is not a userspace process"));
            }
            if tgids.len() > MAX_TRACKED_TGIDS {
                return Err(ScopeError::new(format!(
                    "at most {MAX_TRACKED_TGIDS} TGIDs may be tracked"
                )));
            }
            Ok(TaskScope::tgids(tgids))
        }
        ScopeRequest::Cgroup { path } => resolve_cgroup_scope(&path, cgroup_root),
    }
}

fn resolve_cgroup_scope(path: &str, cgroup_root: &Path) -> Result<TaskScope, ScopeError> {
    let path = path.trim();
    if path.is_empty() {
        return Err(ScopeError::new("cgroup path is required"));
    }

    let root = cgroup_root
        .canonicalize()
        .map_err(|error| ScopeError::new(format!("cannot resolve cgroup root: {error}")))?;
    let requested = Path::new(path);
    let relative = if requested.is_absolute() {
        requested
            .strip_prefix(&root)
            .or_else(|_| requested.strip_prefix("/"))
            .map_err(|_| ScopeError::new("invalid absolute cgroup path"))?
    } else {
        requested
    };
    let resolved = root
        .join(relative)
        .canonicalize()
        .map_err(|error| ScopeError::new(format!("cannot resolve cgroup path: {error}")))?;
    if !resolved.starts_with(&root) {
        return Err(ScopeError::new("cgroup path escapes the cgroup root"));
    }
    let metadata = resolved
        .metadata()
        .map_err(|error| ScopeError::new(format!("cannot inspect cgroup path: {error}")))?;
    if !metadata.is_dir() {
        return Err(ScopeError::new("cgroup path is not a directory"));
    }

    Ok(TaskScope::Cgroup {
        path: resolved,
        cgroup_id: metadata.ino(),
    })
}
