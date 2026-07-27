// SPDX-License-Identifier: GPL-2.0-only

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

#[test]
fn dump_policy_is_available_without_a_316_cpu_host() {
    let output = Command::new(env!("CARGO_BIN_EXE_scx_snake_cell_gallery"))
        .arg("--dump-policy")
        .output()
        .expect("gallery binary should execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("policy should be UTF-8");
    assert!(stdout.starts_with("fallback = \"previous_cpu\""));
    assert!(stdout.contains("operation = \"pick_random_idle\""));
}

#[test]
fn zero_interval_is_rejected_by_the_cli() {
    let output = Command::new(env!("CARGO_BIN_EXE_scx_snake_cell_gallery"))
        .args(["--interval", "0", "--start-immediately"])
        .output()
        .expect("gallery binary should execute");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("greater than zero"));
}

#[test]
fn live_execution_requires_a_restore_policy() {
    let output = Command::new(env!("CARGO_BIN_EXE_scx_snake_cell_gallery"))
        .args(["--start-immediately", "--cycles", "1"])
        .output()
        .expect("gallery binary should execute");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--restore-policy is required"));
}

#[test]
fn generated_policy_compiles_with_the_snake_binary() {
    let gallery = Command::new(env!("CARGO_BIN_EXE_scx_snake_cell_gallery"))
        .arg("--dump-policy")
        .output()
        .expect("gallery policy generator should execute");
    assert!(gallery.status.success());

    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(5)
        .expect("gallery crate should be inside the scx workspace");
    let mut compiler = Command::new(env!("CARGO"))
        .current_dir(workspace_root)
        .args([
            "run",
            "--quiet",
            "-p",
            "scx_snake",
            "--",
            "--policy",
            "/dev/stdin",
            "--dump-compiled-policy",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Snake policy compiler should start");
    compiler
        .stdin
        .take()
        .expect("compiler stdin should be piped")
        .write_all(&gallery.stdout)
        .expect("generated policy should be written");
    let output = compiler
        .wait_with_output()
        .expect("Snake policy compiler should finish");

    assert!(
        output.status.success(),
        "policy compiler failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("compiled policy should be UTF-8");
    assert!(stdout.contains("opcode=pick_random_idle input=task_cell"));
    assert!(stdout.contains("key cell 783:"));
}
