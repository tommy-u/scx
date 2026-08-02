// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::path::PathBuf;
use std::process::Command;

fn focus_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vm_matrix_focus.sh")
}

fn local_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vm_matrix_local.sh")
}

#[test]
fn dry_run_expands_every_kernel_and_vm_size_for_one_target() {
    let output = Command::new("bash")
        .arg(focus_script())
        .args([
            "vtime",
            "basic.toml",
            "/bin/true",
            "/bin/true",
            "/tmp/snake-focused-test",
        ])
        .env("SNAKE_TESTING_DRY_RUN", "1")
        .env(
            "SNAKE_TESTING_KERNELS",
            "linux-6.13=/bin/true linux-7.1=/bin/true",
        )
        .env("SNAKE_TESTING_VM_SIZES", "one=1:1G standard=8:4G")
        .output()
        .expect("focused matrix dry run should start");

    assert!(
        output.status.success(),
        "dry run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.matches("vm_matrix_local.sh").count(), 4);
    assert_eq!(stdout.matches("SNAKE_TESTING_FAIRNESS=vtime").count(), 4);
    assert_eq!(stdout.matches("SNAKE_TESTING_POLICY=basic.toml").count(), 4);
    assert_eq!(stdout.matches("SNAKE_TESTING_GUEST_CPUS=1").count(), 2);
    assert_eq!(stdout.matches("SNAKE_TESTING_GUEST_CPUS=8").count(), 2);
    assert!(stdout.contains("linux-6.13-one"));
    assert!(stdout.contains("linux-6.13-standard"));
    assert!(stdout.contains("linux-7.1-one"));
    assert!(stdout.contains("linux-7.1-standard"));
}

#[test]
fn dry_run_rejects_malformed_kernel_and_vm_size_specs() {
    let bad_kernel = Command::new("bash")
        .arg(focus_script())
        .args(["fifo", "basic.toml", "/bin/true", "/bin/true"])
        .env("SNAKE_TESTING_DRY_RUN", "1")
        .env("SNAKE_TESTING_KERNELS", "missing-launcher")
        .output()
        .unwrap();
    assert!(!bad_kernel.status.success());
    assert!(
        String::from_utf8_lossy(&bad_kernel.stderr).contains("kernel entries must use LABEL=VNG")
    );

    let bad_size = Command::new("bash")
        .arg(focus_script())
        .args(["fifo", "basic.toml", "/bin/true", "/bin/true"])
        .env("SNAKE_TESTING_DRY_RUN", "1")
        .env("SNAKE_TESTING_KERNELS", "host=/bin/true")
        .env("SNAKE_TESTING_VM_SIZES", "broken=8")
        .output()
        .unwrap();
    assert!(!bad_size.status.success());
    assert!(String::from_utf8_lossy(&bad_size.stderr)
        .contains("VM size entries must use LABEL=CPUS:MEMORY"));
}

#[test]
fn local_runner_rejects_an_incomplete_fairness_policy_pair() {
    let output = Command::new("bash")
        .arg(local_script())
        .args(["/bin/true", "/bin/true", "/tmp/snake-incomplete-target"])
        .env("SNAKE_TESTING_FAIRNESS", "fifo")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("SNAKE_TESTING_FAIRNESS and SNAKE_TESTING_POLICY must be used together"));
}
