// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

pub mod bpf_skel {
    include!(concat!(env!("OUT_DIR"), "/bpf_skel.rs"));
}
pub mod api;
pub mod collector;
pub mod host_context;
pub mod model;
pub mod stats;

pub use model::{
    build_callback_timing_rows, build_counters, build_timing_metric_row,
    parse_callback_timing_sample_rate, summarize_callback_timing, CallbackCounter,
    CallbackTimingCounters, CallbackTimingRow, CallbackTimingSummary, TimingMetricRow,
    CALLBACK_NAMES, CALLBACK_TIMING_BUCKETS,
};

pub fn program_name_matches(loaded: &str, expected: &str) -> bool {
    loaded.as_bytes() == &expected.as_bytes()[..expected.len().min(15)]
}
