// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::fs;
use std::os::unix::fs::{symlink, MetadataExt};

use scx_snake_inspector::scope::{resolve_scope, ScopeRequest, TaskScope, MAX_TRACKED_TGIDS};

#[test]
fn tgid_scope_is_sorted_deduplicated_and_nonzero() {
    let scope = resolve_scope(
        ScopeRequest::Tgids {
            tgids: vec![42, 7, 42],
        },
        "/sys/fs/cgroup".as_ref(),
    )
    .unwrap();

    assert_eq!(scope, TaskScope::Tgids(vec![7, 42]));
    assert!(resolve_scope(
        ScopeRequest::Tgids { tgids: vec![] },
        "/sys/fs/cgroup".as_ref()
    )
    .is_err());
    assert!(resolve_scope(
        ScopeRequest::Tgids { tgids: vec![0] },
        "/sys/fs/cgroup".as_ref()
    )
    .is_err());
}

#[test]
fn tgid_scope_has_a_hard_map_capacity_limit() {
    let tgids = (1..=(MAX_TRACKED_TGIDS as u32 + 1)).collect();

    assert!(resolve_scope(ScopeRequest::Tgids { tgids }, "/sys/fs/cgroup".as_ref()).is_err());
}

#[test]
fn cgroup_scope_resolves_beneath_the_configured_root() {
    let root = tempfile::tempdir().unwrap();
    let workload = root.path().join("services/workload");
    fs::create_dir_all(&workload).unwrap();

    let scope = resolve_scope(
        ScopeRequest::Cgroup {
            path: "/services/workload".into(),
        },
        root.path(),
    )
    .unwrap();

    assert_eq!(
        scope,
        TaskScope::Cgroup {
            path: workload.canonicalize().unwrap(),
            cgroup_id: workload.metadata().unwrap().ino(),
        }
    );
}

#[test]
fn cgroup_scope_rejects_a_symlink_escape() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    symlink(outside.path(), root.path().join("escape")).unwrap();

    assert!(resolve_scope(
        ScopeRequest::Cgroup {
            path: "escape".into(),
        },
        root.path(),
    )
    .is_err());
}
