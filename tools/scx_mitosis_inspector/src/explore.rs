// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-2.0-only

use std::time::{Duration, Instant};

use crate::explore_host::ExploreHostCollector;
use crate::explore_model::{ExploreGroup, ExploreSnapshot, EXPLORE_PROBE_GROUPS};
use crate::explore_perf::ExplorePerfCollector;
use crate::explore_probes::ExploreProbeCollector;
use crate::lifecycle::{unix_ms, CollectorStatus, ObserverContext, SampleMeta};
use crate::topology::TopologyView;

/// Independent optional collection: failures here never tear down the existing
/// callback observer. Each underlying source preserves its own clock and seq.
pub struct ExploreCollector {
    host: ExploreHostCollector,
    perf: ExplorePerfCollector,
    topology: TopologyView,
    probes: Option<ExploreProbeCollector>,
    probe_epoch: Option<u64>,
    probe_retry_at: Instant,
    probe_error: String,
    sample_seq: u64,
    last_success_at: Option<u64>,
}

impl ExploreCollector {
    pub fn new(topology: TopologyView) -> Self {
        let llc_ids = topology.cpus.iter().map(|cpu| (cpu.cpu, cpu.llc)).collect();
        Self {
            host: ExploreHostCollector::new(&topology),
            perf: ExplorePerfCollector::new(topology.numeric_order.clone()).with_llc_ids(llc_ids),
            topology,
            probes: None,
            probe_epoch: None,
            probe_retry_at: Instant::now(),
            probe_error: "Waiting for detailed probe attachment".into(),
            sample_seq: 0,
            last_success_at: None,
        }
    }

    pub fn collect(&mut self, observer: &ObserverContext) -> ExploreSnapshot {
        let mut groups = self.host.collect();
        groups.insert("perf".into(), self.perf.collect());

        if observer.status != CollectorStatus::Active {
            self.probes = None;
            self.probe_epoch = None;
            for key in EXPLORE_PROBE_GROUPS {
                groups.insert(
                    key.into(),
                    ExploreGroup::unavailable(
                        "Whole host",
                        format!(
                            "Mitosis observer is {:?}; detailed probes are waiting",
                            observer.status
                        ),
                    ),
                );
            }
        } else {
            if self.probe_epoch != Some(observer.epoch) {
                self.probes = None;
                self.probe_epoch = Some(observer.epoch);
                self.probe_retry_at = Instant::now();
            }
            if self.probes.is_none() && Instant::now() >= self.probe_retry_at {
                match ExploreProbeCollector::new(self.topology.clone()) {
                    Ok(probes) => self.probes = Some(probes),
                    Err(error) => {
                        self.probe_error = format!("Optional probe attachment failed: {error:#}");
                        self.probe_retry_at = Instant::now() + Duration::from_secs(30);
                    }
                }
            }
            if let Some(probes) = &mut self.probes {
                for (key, mut group) in probes.collect() {
                    group.meta.epoch = observer.epoch;
                    groups.insert(key, group);
                }
            } else {
                for key in EXPLORE_PROBE_GROUPS {
                    groups.insert(
                        key.into(),
                        ExploreGroup::unavailable("Whole host", &self.probe_error),
                    );
                }
            }
        }

        self.sample_seq = self.sample_seq.saturating_add(1);
        let at = unix_ms();
        let any_available = groups.values().any(|group| group.available);
        if any_available {
            self.last_success_at = Some(at);
        }
        ExploreSnapshot {
            meta: SampleMeta {
                epoch: observer.epoch,
                sample_seq: self.sample_seq,
                captured_at_unix_ms: Some(at),
                last_success_at_unix_ms: self.last_success_at,
                // An unsupported source report is still a successful collection
                // attempt. Its actual errors belong to the individual groups.
                error: None,
            },
            collector: observer.clone(),
            groups,
        }
    }
}
