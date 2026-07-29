// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::fs;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

const MAX_POLICY_BYTES: u64 = 1_048_576;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyFile {
    pub id: String,
    pub name: String,
    pub source: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PolicyValidation {
    pub rung_count: usize,
    pub mask_table_count: usize,
    pub cell_count: usize,
    pub summary: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PolicyActivation {
    pub generation: u64,
    pub rung_count: usize,
    pub mask_table_count: usize,
    pub summary: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PolicyChoice {
    pub id: String,
    pub name: String,
    pub source: String,
    pub rung_count: usize,
    pub mask_table_count: usize,
    pub cell_count: usize,
    pub summary: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct InvalidPolicy {
    pub id: String,
    pub name: String,
    pub source: String,
    pub error: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct PolicyCatalog {
    pub policies: Vec<PolicyChoice>,
    pub invalid: Vec<InvalidPolicy>,
}

pub fn discover_policy_files(root: &Path) -> Result<Vec<PolicyFile>> {
    let root = root
        .canonicalize()
        .with_context(|| format!("resolving policy directory {}", root.display()))?;
    if !root.is_dir() {
        bail!("policy path {} is not a directory", root.display());
    }
    let mut entries = fs::read_dir(&root)
        .with_context(|| format!("reading policy directory {}", root.display()))?
        .collect::<std::io::Result<Vec<_>>>()?;
    entries.sort_by_key(|entry| entry.file_name());

    let mut files = Vec::new();
    for entry in entries {
        let file_type = entry.file_type()?;
        let path = entry.path();
        if !file_type.is_file()
            || file_type.is_symlink()
            || path.extension().is_none_or(|ext| ext != "toml")
        {
            continue;
        }
        let id = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("policy filename is not valid UTF-8"))?;
        let source = read_regular_policy(&root, &path)?;
        files.push(PolicyFile {
            name: display_name(&id),
            id,
            source,
        });
    }
    Ok(files)
}

pub fn validate_policy_files(
    files: Vec<PolicyFile>,
    mut validate: impl FnMut(&str) -> Result<PolicyValidation>,
) -> PolicyCatalog {
    let mut catalog = PolicyCatalog::default();
    for file in files {
        match validate(&file.source) {
            Ok(validation) => catalog.policies.push(PolicyChoice {
                id: file.id,
                name: file.name,
                source: file.source,
                rung_count: validation.rung_count,
                mask_table_count: validation.mask_table_count,
                cell_count: validation.cell_count,
                summary: validation.summary,
            }),
            Err(error) => catalog.invalid.push(InvalidPolicy {
                id: file.id,
                name: file.name,
                source: file.source,
                error: format!("{error:#}"),
            }),
        }
    }
    catalog
}

pub fn load_policy_source(root: &Path, id: &str) -> Result<String> {
    let relative = Path::new(id);
    if relative.extension().is_none_or(|ext| ext != "toml")
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || relative.components().count() != 1
    {
        bail!("invalid policy ID {id:?}");
    }
    let root = root
        .canonicalize()
        .with_context(|| format!("resolving policy directory {}", root.display()))?;
    read_regular_policy(&root, &root.join(relative))
}

fn read_regular_policy(root: &Path, path: &Path) -> Result<String> {
    if path.parent() != Some(root) {
        bail!("policy {} escapes the configured directory", path.display());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("opening policy {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("reading policy metadata {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("policy {} is not a regular file", path.display());
    }
    if metadata.len() > MAX_POLICY_BYTES {
        bail!("policy {} exceeds 1 MiB", path.display());
    }
    let mut source = String::with_capacity(metadata.len() as usize);
    file.read_to_string(&mut source)
        .with_context(|| format!("reading policy {}", path.display()))?;
    Ok(source)
}

fn display_name(id: &str) -> String {
    PathBuf::from(id)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or(id)
        .replace(['-', '_'], " ")
}
