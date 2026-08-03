// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::path::PathBuf;

use scx_snake_inspector::collector::{
    decode_counter_entry, decode_inspection_stats, decode_top_stats, find_symbol_address,
    parse_host_cpu_times, CollectorConfig,
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
fn snake_top_stats_decode_cpu_and_optional_cell_metrics_together() {
    let payload = serde_json::json!({
        "policy_generation": 4,
        "select_calls": 99,
        "cpus": {
            "0": {"cpu": 0, "runtime_ns": 1250},
            "7": {"cpu": 7, "runtime_ns": 8750}
        },
        "cells": {
            "3": {
                "id": 3,
                "index": 1,
                "slot_epoch": 6,
                "primary_cpu_count": 2,
                "utilization_pct": 50.0,
                "ewma_utilization_pct": 42.0,
                "borrowed_pct": 30.0,
                "lent_pct": 10.0,
                "runtime_ns": 1000,
                "runtime_ns_by_cpu": {"0": 250, "7": 750},
                "primary_runtime_ns": 700,
                "borrowed_runtime_ns": 300,
                "lent_runtime_ns": 200,
                "foreign_affinity_runtime_ns": 75,
                "normal_enqueues": 9,
                "affinity_enqueues": 2,
                "normal_dispatches": 8,
                "affinity_dispatches": 1,
                "clock_transitions": 4
            }
        }
    });

    let decoded = decode_top_stats(payload).unwrap();
    assert_eq!(decoded.policy_generation, 4);
    assert_eq!(
        decoded.cpus,
        std::collections::BTreeMap::from([(0, 1250), (7, 8750)])
    );
    let cells = decoded.cells.unwrap();
    assert_eq!(cells[&3].id, 3);
    assert_eq!(cells[&3].slot_epoch, Some(6));
    assert_eq!(cells[&3].primary_cpu_count, Some(2));
    assert_eq!(cells[&3].utilization_pct, Some(50.0));
    assert_eq!(cells[&3].ewma_utilization_pct, Some(42.0));
    assert_eq!(cells[&3].foreign_affinity_runtime_ns, Some(75));
    assert_eq!(cells[&3].runtime_ns, 1000);
    assert_eq!(
        cells[&3].runtime_ns_by_cpu,
        Some(std::collections::BTreeMap::from([(0, 250), (7, 750)]))
    );

    let absent = decode_top_stats(serde_json::json!({
        "policy_generation": 4,
        "cpus": {"0": {"cpu": 0, "runtime_ns": 1}}
    }))
    .unwrap();
    assert!(absent.cells.is_none());
    let empty = decode_top_stats(serde_json::json!({
        "policy_generation": 4,
        "cpus": {"0": {"cpu": 0, "runtime_ns": 1}},
        "cells": {}
    }))
    .unwrap();
    assert_eq!(empty.cells, Some(std::collections::BTreeMap::new()));
}

#[test]
fn snake_top_stats_distinguishes_older_cell_metrics_without_cpu_attribution() {
    let decoded = decode_top_stats(serde_json::json!({
        "policy_generation": 4,
        "cpus": {"0": {"cpu": 0, "runtime_ns": 1}},
        "cells": {"3": {
            "id": 3,
            "index": 1,
            "runtime_ns": 1,
            "primary_runtime_ns": 1,
            "borrowed_runtime_ns": 0,
            "lent_runtime_ns": 0,
            "normal_enqueues": 0,
            "affinity_enqueues": 0,
            "normal_dispatches": 0,
            "affinity_dispatches": 0,
            "clock_transitions": 0
        }}
    }))
    .unwrap();

    let cell = &decoded.cells.unwrap()[&3];
    assert_eq!(cell.runtime_ns_by_cpu, None);
    assert_eq!(cell.slot_epoch, None);
    assert_eq!(cell.ewma_utilization_pct, None);
    assert_eq!(cell.foreign_affinity_runtime_ns, None);
}

#[test]
fn proc_stat_parser_keeps_sparse_cpu_ids_and_separate_capacity_categories() {
    let parsed = parse_host_cpu_times(concat!(
        "cpu  100 20 30 400 50 6 7 8 90 10\n",
        "cpu2 100 20 30 400 50 6 7 8 90 10\n",
        "cpu9 9 1 2 30 4 5 6 7\n",
        "intr 1234\n",
    ))
    .unwrap();

    assert_eq!(parsed.keys().copied().collect::<Vec<_>>(), vec![2, 9]);
    assert_eq!(parsed[&2].task_ticks, 150);
    assert_eq!(parsed[&2].irq_ticks, 6);
    assert_eq!(parsed[&2].softirq_ticks, 7);
    assert_eq!(parsed[&2].idle_ticks, 400);
    assert_eq!(parsed[&2].iowait_ticks, 50);
    assert_eq!(parsed[&2].steal_ticks, 8);
    assert_eq!(parsed[&9].task_ticks, 12);
}

#[test]
fn proc_stat_parser_rejects_duplicate_or_malformed_cpu_rows() {
    assert!(parse_host_cpu_times("cpu2 1 2 3 4\ncpu2 5 6 7 8\n").is_err());
    assert!(parse_host_cpu_times("cpuX 1 2 3 4\n").is_err());
    assert!(parse_host_cpu_times("cpu2 1 nope 3 4\n").is_err());
    assert!(parse_host_cpu_times("intr 1234\n").is_err());
}

#[test]
fn snake_top_stats_reject_mismatched_map_keys() {
    assert!(decode_top_stats(serde_json::json!({
        "policy_generation": 4,
        "cpus": {"0": {"cpu": 1, "runtime_ns": 1}}
    }))
    .is_err());
    assert!(decode_top_stats(serde_json::json!({
        "policy_generation": 4,
        "cpus": {"0": {"cpu": 0, "runtime_ns": 1}},
        "cells": {"3": {
            "id": 4,
            "index": 0,
            "runtime_ns": 0,
            "primary_runtime_ns": 0,
            "borrowed_runtime_ns": 0,
            "lent_runtime_ns": 0,
            "normal_enqueues": 0,
            "affinity_enqueues": 0,
            "normal_dispatches": 0,
            "affinity_dispatches": 0,
            "clock_transitions": 0
        }}
    }))
    .is_err());
    assert!(decode_top_stats(serde_json::json!({
        "policy_generation": 4,
        "cpus": {}
    }))
    .is_err());
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
