// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::fs;
use std::os::unix::fs::symlink;

use anyhow::bail;
use scx_snake_inspector::policies::{
    discover_policy_files, load_policy_source, validate_policy_files, PolicyValidation,
};

#[test]
fn policy_library_lists_only_direct_regular_toml_files_and_separates_invalid_entries() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    fs::write(
        root.path().join("balanced.toml"),
        "[[rung]]\noperation = \"pick_idle\"\nscope = \"task_allowed\"\n",
    )
    .unwrap();
    fs::write(root.path().join("broken.toml"), "not policy toml").unwrap();
    fs::write(root.path().join("notes.txt"), "ignore me").unwrap();
    fs::create_dir(root.path().join("nested.toml")).unwrap();
    symlink(outside.path(), root.path().join("escape.toml")).unwrap();

    let files = discover_policy_files(root.path()).unwrap();
    assert_eq!(
        files
            .iter()
            .map(|file| file.id.as_str())
            .collect::<Vec<_>>(),
        vec!["balanced.toml", "broken.toml"]
    );
    let catalog = validate_policy_files(files, |source| {
        if source.starts_with("not policy") {
            bail!("invalid policy");
        }
        Ok(PolicyValidation {
            rung_count: 1,
            mask_table_count: 0,
            cell_count: 0,
            summary: "1 rung, 0 mask tables, 0 cells".into(),
        })
    });

    assert_eq!(catalog.policies.len(), 1);
    assert_eq!(catalog.policies[0].id, "balanced.toml");
    assert_eq!(catalog.invalid.len(), 1);
    assert_eq!(catalog.invalid[0].id, "broken.toml");
}

#[test]
fn policy_source_loading_rejects_traversal_and_symlinks() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    fs::write(root.path().join("valid.toml"), "policy").unwrap();
    symlink(outside.path(), root.path().join("escape.toml")).unwrap();

    assert_eq!(
        load_policy_source(root.path(), "valid.toml").unwrap(),
        "policy"
    );
    assert!(load_policy_source(root.path(), "../valid.toml").is_err());
    assert!(load_policy_source(root.path(), "/tmp/valid.toml").is_err());
    assert!(load_policy_source(root.path(), "escape.toml").is_err());
}
