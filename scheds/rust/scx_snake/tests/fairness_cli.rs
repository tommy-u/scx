// SPDX-License-Identifier: GPL-2.0-only

use std::process::Command;

#[test]
fn help_exposes_source_dependent_defaults_and_experimental_modes() {
    let output = Command::new(env!("CARGO_BIN_EXE_scx_snake"))
        .arg("--help")
        .output()
        .expect("Snake should execute");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("help should be UTF-8");
    assert!(stdout.contains("--fairness <FAIRNESS>"));
    assert!(stdout.contains("Defaults to FIFO for --policy"));
    assert!(stdout.contains("mitosis-sim defaults to VTIME"));
    assert!(stdout.contains("--profile <PROFILE>"));
    assert!(stdout.contains("vtime"));
    assert!(stdout.contains("eevdf"));
    assert!(stdout.contains("experimental"));
}

#[test]
fn unknown_fairness_mode_is_rejected() {
    let output = Command::new(env!("CARGO_BIN_EXE_scx_snake"))
        .args(["--fairness", "deadline-tree", "--help"])
        .output()
        .expect("Snake should execute");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid value"));
}
