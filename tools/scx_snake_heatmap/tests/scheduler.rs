// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use scx_snake_heatmap::scheduler::{GateChange, SchedulerGate};

#[test]
fn gate_tracks_snake_start_restart_and_stop() {
    let mut gate = SchedulerGate::new("snake");

    assert_eq!(gate.observe("", 0), GateChange::None);
    assert!(!gate.is_active());

    assert_eq!(gate.observe("snake", 7), GateChange::Started);
    assert!(gate.is_active());
    assert_eq!(gate.observe("snake", 7), GateChange::None);

    assert_eq!(gate.observe("snake", 8), GateChange::Restarted);
    assert!(gate.is_active());

    assert_eq!(gate.observe("scx_rusty", 9), GateChange::Stopped);
    assert!(!gate.is_active());
    assert_eq!(gate.observe("scx_rusty", 9), GateChange::None);

    assert_eq!(gate.observe("snake", 10), GateChange::Started);
    assert!(gate.is_active());
}

#[test]
fn gate_accepts_the_packaged_snake_ops_name() {
    let mut gate = SchedulerGate::new("snake");

    assert_eq!(
        gate.observe("snake_1.1.1_x86_64_unknown_linux_gnu", 288),
        GateChange::Started
    );
    assert!(gate.is_active());
}
