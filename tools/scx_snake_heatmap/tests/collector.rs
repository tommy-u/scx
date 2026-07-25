// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::path::PathBuf;

use scx_snake_heatmap::collector::{decode_counter_entry, find_symbol_address, CollectorConfig};
use scx_snake_heatmap::model::CpuPair;
use scx_snake_heatmap::scope::TaskScope;

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
