// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-2.0-only
include!(concat!(env!("OUT_DIR"), "/explore_bpf_skel.rs"));

/// The owned libbpf object avoids storing a skeleton borrowing its own open object.
pub const EXPLORE_OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/explore_bpf.bpf.o"));
