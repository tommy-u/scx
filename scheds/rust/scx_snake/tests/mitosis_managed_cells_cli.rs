// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn vm_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("mitosis_managed_cells_vm.sh")
}

#[test]
fn dry_run_expands_the_managed_workload_guest() {
    let output = Command::new("bash")
        .arg(vm_script())
        .args([
            "/tmp/snake-managed-workloads-dry-run",
            "/bin/true",
            "/bin/true",
        ])
        .env("SNAKE_TESTING_DRY_RUN", "1")
        .env("SNAKE_TESTING_GUEST_CPUS", "8")
        .env("SNAKE_TESTING_GUEST_MEMORY", "4G")
        .env("VNG", "/bin/true")
        .output()
        .expect("managed-workload VM dry run should start");

    assert!(
        output.status.success(),
        "dry run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("/bin/true --run"));
    assert!(stdout.contains("--cpus 8"));
    assert!(stdout.contains("--memory 4G"));
    assert!(stdout.contains("--user root"));
    assert!(stdout.contains("--exec"));
    assert!(stdout.contains("mitosis_managed_cells_vm.sh"));
}

#[test]
fn guest_discovers_cells_before_loading_them() {
    let source = fs::read_to_string(vm_script()).expect("VM test script should be readable");
    let attached = source
        .find("wait_for \"empty managed-cell topology\"")
        .expect("guest should verify the initially empty topology");
    let created = source
        .find("mkdir \"${managed_parent}/${cell_names[index]}\"")
        .expect("guest should create managed child cgroups");
    let discovered = source
        .find("wait_for \"four managed workload cells\"")
        .expect("guest should wait for live child discovery");
    let loaded = source
        .find("launch_workload cpu-saturation")
        .expect("guest should start the workload set");
    let populated = source
        .find("wait_for \"four populated managed workload cells\"")
        .expect("guest should verify live task membership");

    assert!(attached < created);
    assert!(created < discovered);
    assert!(discovered < loaded);
    assert!(loaded < populated);
}
