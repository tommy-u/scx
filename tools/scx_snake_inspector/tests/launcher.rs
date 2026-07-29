// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use scx_snake_inspector::launcher::{LaunchFairness, LaunchRequest, SnakeLauncher};

fn executable(path: &Path, body: &str) {
    fs::write(path, body).unwrap();
    let mut permissions = fs::metadata(path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).unwrap();
}

fn fixture(script: &str) -> (tempfile::TempDir, SnakeLauncher, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let binary = root.path().join("scx_snake");
    executable(&binary, script);
    let policies = root.path().join("policies");
    fs::create_dir(&policies).unwrap();
    fs::write(
        policies.join("basic.toml"),
        "[[rung]]\noperation = \"claim_idle\"\nscope = \"previous_cpu\"\n",
    )
    .unwrap();
    let ops = root.path().join("ops");
    fs::write(&ops, "\n").unwrap();
    let launcher = SnakeLauncher::with_ops_path(&binary, &policies, &ops).unwrap();
    (root, launcher, ops)
}

fn wait_until(timeout: Duration, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while !predicate() {
        assert!(Instant::now() < deadline, "condition did not become true");
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn launch_uses_only_typed_optional_arguments() {
    let script = r#"#!/bin/sh
printf '%s\n' "$@" >"$(dirname "$0")/argv"
trap 'exit 0' INT TERM
while :; do sleep 1; done
"#;
    let (root, launcher, _) = fixture(script);

    let status = launcher
        .start(LaunchRequest {
            policy_id: "basic.toml".into(),
            fairness: Some(LaunchFairness::Vtime),
            callback_timing_sample_rate: Some(128),
            exit_dump_len: Some(4096),
            verbose: true,
        })
        .unwrap();
    assert!(status.managed);
    assert_eq!(status.policy_id.as_deref(), Some("basic.toml"));

    let argv_path = root.path().join("argv");
    wait_until(Duration::from_secs(2), || argv_path.exists());
    let policy = root
        .path()
        .join("policies/basic.toml")
        .canonicalize()
        .unwrap();
    assert_eq!(
        fs::read_to_string(argv_path)
            .unwrap()
            .lines()
            .collect::<Vec<_>>(),
        vec![
            "--policy",
            policy.to_str().unwrap(),
            "--fairness",
            "vtime",
            "--callback-timing-sample-rate",
            "128",
            "--exit-dump-len",
            "4096",
            "--verbose",
        ]
    );

    launcher.stop().unwrap();
    assert!(!launcher.status().unwrap().managed);
}

#[test]
fn omitted_optional_settings_emit_no_optional_flags() {
    let script = r#"#!/bin/sh
printf '%s\n' "$@" >"$(dirname "$0")/argv"
trap 'exit 0' INT TERM
while :; do sleep 1; done
"#;
    let (root, launcher, _) = fixture(script);

    launcher
        .start(LaunchRequest {
            policy_id: "basic.toml".into(),
            fairness: None,
            callback_timing_sample_rate: None,
            exit_dump_len: None,
            verbose: false,
        })
        .unwrap();

    let argv_path = root.path().join("argv");
    wait_until(Duration::from_secs(2), || argv_path.exists());
    let policy = root
        .path()
        .join("policies/basic.toml")
        .canonicalize()
        .unwrap();
    assert_eq!(
        fs::read_to_string(argv_path)
            .unwrap()
            .lines()
            .collect::<Vec<_>>(),
        vec!["--policy", policy.to_str().unwrap()]
    );
    launcher.stop().unwrap();
}

#[test]
fn policy_ids_cannot_escape_the_allowlisted_directory() {
    let (root, launcher, _) = fixture("#!/bin/sh\nexit 0\n");
    fs::write(root.path().join("outside.toml"), "outside").unwrap();
    std::os::unix::fs::symlink(
        root.path().join("outside.toml"),
        root.path().join("policies/link.toml"),
    )
    .unwrap();

    for policy_id in [
        "../outside.toml",
        "link.toml",
        "basic.txt",
        "/tmp/basic.toml",
    ] {
        let error = launcher
            .start(LaunchRequest {
                policy_id: policy_id.into(),
                fairness: None,
                callback_timing_sample_rate: None,
                exit_dump_len: None,
                verbose: false,
            })
            .unwrap_err();
        assert!(
            error.to_string().contains("policy"),
            "unexpected error for {policy_id}: {error:#}"
        );
    }
}

#[test]
fn invalid_sample_rate_is_rejected_before_spawn() {
    let (root, launcher, _) = fixture("#!/bin/sh\ntouch \"$(dirname \"$0\")/spawned\"\n");
    let error = launcher
        .start(LaunchRequest {
            policy_id: "basic.toml".into(),
            fairness: Some(LaunchFairness::Fifo),
            callback_timing_sample_rate: Some(3),
            exit_dump_len: None,
            verbose: false,
        })
        .unwrap_err();

    assert!(error.to_string().contains("sample rate"));
    assert!(!root.path().join("spawned").exists());
}

#[test]
fn start_refuses_any_attached_scheduler_and_stop_never_signals_it() {
    let (root, launcher, ops) = fixture("#!/bin/sh\ntouch \"$(dirname \"$0\")/spawned\"\n");
    fs::write(&ops, "another_scheduler\n").unwrap();

    let error = launcher
        .start(LaunchRequest {
            policy_id: "basic.toml".into(),
            fairness: None,
            callback_timing_sample_rate: None,
            exit_dump_len: None,
            verbose: false,
        })
        .unwrap_err();
    assert!(error.to_string().contains("another_scheduler"));
    assert!(!root.path().join("spawned").exists());

    let error = launcher.stop().unwrap_err();
    assert!(error.to_string().contains("not managed"));
    assert_eq!(fs::read_to_string(ops).unwrap(), "another_scheduler\n");
}

#[test]
fn launcher_owns_at_most_one_child_and_drop_stops_it() {
    let script = r#"#!/bin/sh
trap 'exit 0' INT TERM
while :; do sleep 1; done
"#;
    let (_root, launcher, _) = fixture(script);
    let request = LaunchRequest {
        policy_id: "basic.toml".into(),
        fairness: None,
        callback_timing_sample_rate: None,
        exit_dump_len: None,
        verbose: false,
    };
    let first = launcher.start(request.clone()).unwrap();
    let pid = first.pid.unwrap();
    assert!(launcher
        .start(request)
        .unwrap_err()
        .to_string()
        .contains("already"));

    drop(launcher);
    wait_until(Duration::from_secs(2), || unsafe {
        libc::kill(pid as i32, 0) == -1
    });
}

#[test]
fn status_reaps_a_child_that_exits_on_its_own() {
    let (_root, launcher, _) = fixture("#!/bin/sh\nsleep 0.05\nexit 7\n");
    launcher
        .start(LaunchRequest {
            policy_id: "basic.toml".into(),
            fairness: None,
            callback_timing_sample_rate: None,
            exit_dump_len: None,
            verbose: false,
        })
        .unwrap();

    wait_until(Duration::from_secs(2), || {
        !launcher.status().unwrap().managed
    });
    let status = launcher.status().unwrap();
    assert!(!status.managed);
    assert!(status.last_exit.as_deref().unwrap().contains('7'));
}

#[test]
fn allowlisted_policies_are_available_while_scheduler_is_stopped() {
    let (_root, launcher, _) = fixture("#!/bin/sh\nexit 0\n");

    let policies = launcher.policies().unwrap();

    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0].id, "basic.toml");
    assert_eq!(policies[0].name, "basic");
}
