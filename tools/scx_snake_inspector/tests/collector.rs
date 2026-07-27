// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::path::PathBuf;

use scx_snake_inspector::collector::{
    decode_counter_entry, decode_cpu_runtime_stats, decode_inspection_stats, find_symbol_address,
    CollectorConfig,
};
use scx_snake_inspector::model::CpuPair;
use scx_snake_inspector::scope::TaskScope;

#[test]
fn collector_config_matches_the_bpf_abi() {
    let scope = TaskScope::Cgroup {
        path: PathBuf::from("/sys/fs/cgroup/workload"),
        cgroup_id: 99,
    };
    let config = CollectorConfig::new(true, 7, &scope);
    let mut expected = Vec::new();
    expected.extend_from_slice(&1_u32.to_ne_bytes());
    expected.extend_from_slice(&2_u32.to_ne_bytes());
    expected.extend_from_slice(&7_u32.to_ne_bytes());
    expected.extend_from_slice(&0_u32.to_ne_bytes());
    expected.extend_from_slice(&99_u64.to_ne_bytes());

    assert_eq!(config.to_bytes(), expected);
}

#[test]
fn migration_counter_entry_decodes_native_bpf_bytes() {
    let mut key = Vec::new();
    key.extend_from_slice(&17_u32.to_ne_bytes());
    key.extend_from_slice(&3_u32.to_ne_bytes());
    let value = 44_u64.to_ne_bytes();

    assert_eq!(
        decode_counter_entry(&key, &value).unwrap(),
        (CpuPair::new(17, 3), 44)
    );
    assert!(decode_counter_entry(&key[..7], &value).is_err());
    assert!(decode_counter_entry(&key, &value[..7]).is_err());
}

#[test]
fn kallsyms_lookup_matches_the_exact_nonzero_symbol() {
    let kallsyms = concat!(
        "0000000000000000 D ext_sched_class_debug\n",
        "ffffffff81e00120 D ext_sched_class\n",
        "ffffffff81e00200 D idle_sched_class\n",
    );

    assert_eq!(
        find_symbol_address(kallsyms, "ext_sched_class").unwrap(),
        0xffffffff81e00120
    );
    assert!(find_symbol_address(kallsyms, "missing_sched_class").is_err());
    assert!(
        find_symbol_address("0000000000000000 D ext_sched_class\n", "ext_sched_class").is_err()
    );
}

#[test]
fn snake_stats_decode_per_cpu_runtime_and_ignore_other_metrics() {
    let payload = serde_json::json!({
        "policy_generation": 4,
        "select_calls": 99,
        "cpus": {
            "0": {"cpu": 0, "runtime_ns": 1250},
            "7": {"cpu": 7, "runtime_ns": 8750}
        }
    });

    assert_eq!(
        decode_cpu_runtime_stats(payload).unwrap(),
        std::collections::BTreeMap::from([(0, 1250), (7, 8750)])
    );
    assert!(decode_cpu_runtime_stats(serde_json::json!({"select_calls": 4})).is_err());
}

#[test]
fn snake_inspection_requires_the_supported_schema_and_two_slots() {
    let payload = serde_json::json!({
        "schema_version": 1,
        "active_slot": 0,
        "slots": [
            {"slot": 0, "state": "active"},
            {"slot": 1, "state": "empty"}
        ],
        "cells": [],
        "task_mappings": []
    });

    let decoded = decode_inspection_stats(payload.clone()).unwrap();
    assert_eq!(decoded, payload);
    assert!(decode_inspection_stats(serde_json::json!({
        "schema_version": 2,
        "active_slot": 0,
        "slots": [],
        "cells": [],
        "task_mappings": []
    }))
    .is_err());
    assert!(decode_inspection_stats(serde_json::json!({
        "schema_version": 1,
        "active_slot": 0,
        "slots": [{"slot": 0}],
        "cells": [],
        "task_mappings": []
    }))
    .is_err());
}
