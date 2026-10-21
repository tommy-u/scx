// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-2.0-only

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::{json, Value};

use crate::lifecycle::{CollectorStatus, ObserverContext, SampleMeta};

pub const EXPLORE_GROUPS: [&str; 11] = [
    "dsqs",
    "tasks",
    "perf",
    "bandwidth",
    "wakers",
    "scx_events",
    "ipis",
    "idle",
    "pressure",
    "thermal",
    "power",
];
pub const EXPLORE_PROBE_GROUPS: [&str; 6] =
    ["dsqs", "tasks", "wakers", "scx_events", "ipis", "pressure"];

/// A source can be available with individual rows unavailable. `partial` and
/// row errors describe that coverage without substituting zeros for failures.
#[derive(Clone, Debug, Serialize)]
pub struct ExploreGroup {
    pub available: bool,
    pub error: Option<String>,
    pub meta: SampleMeta,
    pub scope: String,
    pub summary: Value,
    pub rows: Vec<Value>,
    pub partial: bool,
}

impl ExploreGroup {
    pub fn available(scope: impl Into<String>, summary: Value, rows: Vec<Value>) -> Self {
        Self {
            available: true,
            error: None,
            meta: SampleMeta::default(),
            scope: scope.into(),
            summary,
            rows,
            partial: false,
        }
    }

    pub fn unavailable(scope: impl Into<String>, error: impl Into<String>) -> Self {
        let error = error.into();
        Self {
            available: false,
            error: Some(error.clone()),
            meta: SampleMeta {
                error: Some(error),
                ..SampleMeta::default()
            },
            scope: scope.into(),
            summary: json!({}),
            rows: Vec::new(),
            partial: false,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ExploreSnapshot {
    pub meta: SampleMeta,
    pub collector: ObserverContext,
    pub groups: BTreeMap<String, ExploreGroup>,
}

impl Default for ExploreSnapshot {
    fn default() -> Self {
        Self {
            meta: SampleMeta::default(),
            collector: ObserverContext::default(),
            groups: EXPLORE_GROUPS
                .into_iter()
                .map(|key| {
                    (
                        key.into(),
                        ExploreGroup::unavailable("Whole host", "Waiting for Explore collection"),
                    )
                })
                .collect(),
        }
    }
}

impl ExploreSnapshot {
    /// Keep host readings usable when Mitosis stops, while rejecting data from
    /// detailed probes attached to a different scheduler session.
    pub fn mask_incompatible_probes(&mut self, current: &ObserverContext) {
        for key in EXPLORE_PROBE_GROUPS {
            let Some(group) = self.groups.get_mut(key) else {
                continue;
            };
            if group.available
                && (current.status != CollectorStatus::Active
                    || self.collector != *current
                    || group.meta.epoch != current.epoch)
            {
                group.available = false;
                group.error =
                    Some("Detailed probes belong to a different scheduler session".into());
                group.meta.error = group.error.clone();
                group.summary = json!({});
                group.rows.clear();
            }
        }
        self.collector = current.clone();
    }
}
