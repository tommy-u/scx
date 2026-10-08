// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::{fs, io::Write};

fn vm_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vtime_orphan_drain_vm.sh")
}

fn dry_run(verbose: &str) -> std::process::Output {
    Command::new("bash")
        .arg(vm_script())
        .args(["/tmp/snake-orphan-drain-dry-run", "/bin/true", "/bin/true"])
        .env("SNAKE_TESTING_DRY_RUN", "1")
        .env("SNAKE_TEST_VERBOSE", verbose)
        .env("VNG", "/bin/true")
        .output()
        .expect("orphan-drain VM dry run should start")
}

#[test]
fn dry_run_expands_a_two_llc_orphan_drain_guest() {
    let output = dry_run("0");

    assert!(
        output.status.success(),
        "dry run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("/bin/true --run"));
    assert!(stdout.contains("--cpus 12\\,sockets=2\\,cores=6\\,threads=1"));
    assert!(stdout.contains("--memory 4G"));
    assert!(stdout.contains("--user root"));
    assert!(stdout.contains("vtime_orphan_drain_vm.sh --guest"));
    assert!(stdout.contains("env SNAKE_TEST_VERBOSE=0"));
}

#[test]
fn dry_run_forwards_verifier_diagnostics_to_the_guest() {
    let output = dry_run("1");
    assert!(output.status.success());
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .contains("env SNAKE_TEST_VERBOSE=1"));
}

#[test]
fn dry_run_rejects_invalid_verbosity() {
    let output = dry_run("2");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("SNAKE_TEST_VERBOSE must be 0 or 1"));
}

#[test]
fn kernel_log_check_accepts_the_expected_debug_scheduler_stall_only() {
    let script = fs::read_to_string(vm_script()).unwrap();
    let function = script
        .split_once("kernel_log_has_unexpected_failure() {")
        .unwrap()
        .1
        .split_once("\ninside_vm()")
        .unwrap()
        .0;
    let command = format!(
        "kernel_log_has_unexpected_failure() {{{function}\nkernel_log_has_unexpected_failure /dev/stdin"
    );
    let expected_stall =
        "[21.979750] sched_ext: BPF scheduler \"snake_debug\" disabled (runnable task stall)\n\
        [21.979756] sched_ext: snake_debug: python3[679] failed to run for 7.388s\n\
        [21.979763]    scx_watchdog_workfn+0x1ac/0x200\n";
    for (log, unexpected) in [
        (expected_stall.to_owned(), false),
        (
            format!("{expected_stall}[22.0] BUG: bad kernel state\n"),
            true,
        ),
        ("[22.0] sched_ext: snake_debug: error\n".into(), true),
        ("[22.0] Oops: bad kernel state\n".into(), true),
        ("[22.0] RCU detected a stall\n".into(), true),
    ] {
        let mut child = Command::new("bash")
            .args(["-c", &command])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(log.as_bytes())
            .unwrap();
        assert_eq!(child.wait().unwrap().code(), Some(i32::from(!unexpected)));
    }
}
