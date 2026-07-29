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
