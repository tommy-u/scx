// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::fs;

use scx_snake_inspector::workload::{resolve_workload_target, WorkloadTarget};

#[test]
fn resolves_tid_and_all_current_tgid_threads() {
    let proc_root = tempfile::tempdir().unwrap();
    let cgroup_root = tempfile::tempdir().unwrap();
    for tid in [42, 44, 43] {
        fs::create_dir_all(proc_root.path().join("42/task").join(tid.to_string())).unwrap();
    }
    fs::create_dir_all(proc_root.path().join("42/task/not-a-tid")).unwrap();

    assert_eq!(
        resolve_workload_target(
            &WorkloadTarget::Tid { tid: 77 },
            proc_root.path(),
            cgroup_root.path(),
        )
        .unwrap(),
        vec![77]
    );
    assert_eq!(
        resolve_workload_target(
            &WorkloadTarget::Tgid { tgid: 42 },
            proc_root.path(),
            cgroup_root.path(),
        )
        .unwrap(),
        vec![42, 43, 44]
    );
}

#[test]
fn resolves_deduplicated_threads_from_a_cgroup_subtree() {
    let proc_root = tempfile::tempdir().unwrap();
    let cgroup_root = tempfile::tempdir().unwrap();
    let workload = cgroup_root.path().join("workload.slice");
    let child = workload.join("child");
    fs::create_dir_all(&child).unwrap();
    fs::write(workload.join("cgroup.threads"), "31\n30\n").unwrap();
    fs::write(child.join("cgroup.threads"), "32\n31\n").unwrap();

    assert_eq!(
        resolve_workload_target(
            &WorkloadTarget::Cgroup {
                path: "/workload.slice".into(),
            },
            proc_root.path(),
            cgroup_root.path(),
        )
        .unwrap(),
        vec![30, 31, 32]
    );
}

#[test]
fn rejects_invalid_ids_empty_targets_and_cgroup_escapes() {
    let proc_root = tempfile::tempdir().unwrap();
    let cgroup_root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path(), cgroup_root.path().join("escape")).unwrap();

    for target in [
        WorkloadTarget::Tid { tid: 0 },
        WorkloadTarget::Tgid { tgid: 0 },
        WorkloadTarget::Cgroup {
            path: "/escape".into(),
        },
    ] {
        assert!(
            resolve_workload_target(&target, proc_root.path(), cgroup_root.path()).is_err(),
            "target should be rejected: {target:?}"
        );
    }
}
