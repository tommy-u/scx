// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::time::Duration;

use clap::Parser;
use scx_snake_inspector::cli::{parse_duration, parse_loopback_address, Args};

#[test]
fn durations_accept_milliseconds_seconds_minutes_and_hours() {
    assert_eq!(parse_duration("250ms").unwrap(), Duration::from_millis(250));
    assert_eq!(parse_duration("10s").unwrap(), Duration::from_secs(10));
    assert_eq!(parse_duration("5m").unwrap(), Duration::from_secs(300));
    assert_eq!(parse_duration("1h").unwrap(), Duration::from_secs(3600));
    assert_eq!(parse_duration("12").unwrap(), Duration::from_secs(12));
    assert!(parse_duration("0s").is_err());
    assert!(parse_duration("1.5s").is_err());
}

#[test]
fn listen_address_must_be_loopback() {
    assert!(parse_loopback_address("127.0.0.1:8787").is_ok());
    assert!(parse_loopback_address("[::1]:8787").is_ok());
    assert!(parse_loopback_address("0.0.0.0:8787").is_err());
    assert!(parse_loopback_address("192.168.1.5:8787").is_err());
}

#[test]
fn policy_directory_can_be_overridden() {
    let args = Args::try_parse_from(["scx_snake_inspector", "--policy-dir", "/tmp/snake-policies"])
        .unwrap();

    assert_eq!(
        args.policy_dir,
        std::path::PathBuf::from("/tmp/snake-policies")
    );
}

#[test]
fn snake_binary_can_be_overridden() {
    let args =
        Args::try_parse_from(["scx_snake_inspector", "--snake-bin", "/opt/scx_snake"]).unwrap();

    assert_eq!(args.snake_bin, std::path::PathBuf::from("/opt/scx_snake"));
}

#[test]
fn vm_testing_is_opt_in_and_enforces_one_minute_cases() {
    let defaults = Args::try_parse_from(["scx_snake_inspector"]).unwrap();
    assert!(!defaults.enable_testing);
    assert_eq!(defaults.testing_duration, Duration::from_secs(60));
    assert_eq!(defaults.testing_shard_index, 0);
    assert_eq!(defaults.testing_shard_count, 1);

    let configured = Args::try_parse_from([
        "scx_snake_inspector",
        "--enable-testing",
        "--testing-duration",
        "90s",
        "--testing-shard-index",
        "3",
        "--testing-shard-count",
        "8",
        "--testing-artifact-dir",
        "/tmp/snake-matrix",
    ])
    .unwrap();
    assert!(configured.enable_testing);
    assert_eq!(configured.testing_duration, Duration::from_secs(90));
    assert_eq!(configured.testing_shard_index, 3);
    assert_eq!(configured.testing_shard_count, 8);
    assert_eq!(
        configured.testing_artifact_dir,
        std::path::PathBuf::from("/tmp/snake-matrix")
    );
    assert!(configured.validate().is_ok());

    let too_short = Args::try_parse_from([
        "scx_snake_inspector",
        "--enable-testing",
        "--testing-duration",
        "59s",
    ])
    .unwrap();
    assert_eq!(
        too_short.validate().unwrap_err(),
        "--testing-duration must be at least 60s"
    );

    let aggregate = Args::try_parse_from([
        "scx_snake_inspector",
        "--enable-testing",
        "--testing-shard-count",
        "8",
        "--testing-import-dir",
        "/tmp/snake-campaign",
        "--testing-isolated",
    ])
    .unwrap();
    assert_eq!(
        aggregate.testing_import_dir,
        vec![std::path::PathBuf::from("/tmp/snake-campaign")]
    );
    assert!(aggregate.testing_isolated);
    assert!(aggregate.validate().is_ok());
}

#[test]
fn aggregate_view_accepts_multiple_campaign_directories() {
    let args = Args::try_parse_from([
        "scx_snake_inspector",
        "--enable-testing",
        "--testing-import-dir",
        "/tmp/snake-campaign-6.13",
        "--testing-import-dir",
        "/tmp/snake-campaign-6.16",
    ])
    .unwrap();

    assert_eq!(
        args.testing_import_dir,
        vec![
            std::path::PathBuf::from("/tmp/snake-campaign-6.13"),
            std::path::PathBuf::from("/tmp/snake-campaign-6.16"),
        ]
    );
}
