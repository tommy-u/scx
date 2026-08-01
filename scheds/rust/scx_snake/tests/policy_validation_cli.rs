// SPDX-License-Identifier: GPL-2.0-only

use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn policy_file(name: &str, source: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "scx-snake-policy-validation-{}-{name}.toml",
        std::process::id()
    ));
    fs::write(&path, source).expect("temporary policy should be writable");
    path
}

#[test]
fn valid_policy_validation_is_structured_json() {
    let path = policy_file(
        "valid",
        r#"
[[rung]]
operation = "pick_idle"
scope = "task_allowed"
"#,
    );
    let path_arg = path.to_string_lossy().into_owned();
    let output = Command::new(env!("CARGO_BIN_EXE_scx_snake"))
        .args(["--policy", &path_arg, "--validate-policy"])
        .output()
        .expect("Snake should execute");
    let _ = fs::remove_file(path);

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("validation should emit JSON");
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["valid"], true);
    assert_eq!(report["abi_version"], 29);
    assert_eq!(report["limits"]["placement_rungs"], 16);
    assert_eq!(report["limits"]["generic_placement_rungs"], 9);
    assert_eq!(report["limits"]["queue_rungs"], 8);
    assert_eq!(report["policy"]["rung_count"], 1);
    assert_eq!(report["policy"]["queue_policy"], false);
    assert!(report.get("error").is_none());
}

#[test]
fn invalid_policy_validation_reports_stable_code_and_location() {
    let path = policy_file(
        "invalid",
        r#"
[[rung]]
operation = "pick_idle"
scope = "task_allowed"
unexpected = true
"#,
    );
    let path_arg = path.to_string_lossy().into_owned();
    let output = Command::new(env!("CARGO_BIN_EXE_scx_snake"))
        .args(["--policy", &path_arg, "--validate-policy"])
        .output()
        .expect("Snake should execute");
    let _ = fs::remove_file(path);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("validation failure should emit JSON");
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["valid"], false);
    assert_eq!(report["abi_version"], 29);
    assert_eq!(report["error"]["code"], "invalid_policy_toml");
    assert!(report["error"]["message"]
        .as_str()
        .is_some_and(|message| message.contains("unexpected")));
    assert!(report["error"]["line"].as_u64().is_some());
    assert!(report["error"]["column"].as_u64().is_some());
    assert!(report.get("policy").is_none());
}
