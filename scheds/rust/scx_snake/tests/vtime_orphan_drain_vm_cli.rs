// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::path::PathBuf;
use std::process::Command;

fn vm_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vtime_orphan_drain_vm.sh")
}

#[test]
fn dry_run_expands_a_two_llc_orphan_drain_guest() {
    let output = Command::new("bash")
        .arg(vm_script())
        .args(["/tmp/snake-orphan-drain-dry-run", "/bin/true", "/bin/true"])
        .env("SNAKE_TESTING_DRY_RUN", "1")
        .env("VNG", "/bin/true")
        .output()
        .expect("orphan-drain VM dry run should start");

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
}
