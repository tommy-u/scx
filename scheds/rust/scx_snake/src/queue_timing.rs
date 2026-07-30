// SPDX-License-Identifier: GPL-2.0-only

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

pub const RESIDENCE_BUCKETS: usize = 64;
pub const DEPTH_BUCKETS: usize = 256;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueClass {
    Normal,
    Affinity,
    Fairness,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct QueueTimingControlResponse {
    pub enabled: bool,
    pub session_id: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueTimingCaptureState {
    Inactive,
    Collecting,
    Historical,
}

pub fn validate_capture_start(sample_rate: u32) -> Result<(), String> {
    if sample_rate == 0 {
        return Err("queue timing requires callback timing sampling to be enabled".into());
    }
    Ok(())
}

impl TryFrom<u32> for QueueClass {
    type Error = String;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Normal),
            1 => Ok(Self::Affinity),
            2 => Ok(Self::Fairness),
            _ => Err(format!("unknown queue class {value}")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueTimingEvent {
    pub session_id: u64,
    pub dsq_id: u64,
    pub residence_ns: u64,
    pub cell_index: u32,
    pub queue_class: QueueClass,
    pub depth_after_insert: u32,
    pub depth_after_dispatch: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueueTimingCapture {
    pub session_id: u64,
    pub sample_rate: u32,
    pub policy_generation: u64,
    pub started_at_ms: u64,
    pub stopped_at_ms: Option<u64>,
}

#[derive(Clone, Debug, Default)]
pub struct QueueTimingState {
    next_session_id: u64,
    capture: Option<QueueTimingCapture>,
}

impl QueueTimingState {
    pub fn start(
        &mut self,
        sample_rate: u32,
        policy_generation: u64,
        started_at_ms: u64,
    ) -> QueueTimingCapture {
        if let Some(capture) = self
            .capture()
            .filter(|capture| capture.stopped_at_ms.is_none())
        {
            return capture.clone();
        }
        self.next_session_id = self.next_session_id.wrapping_add(1).max(1);
        let capture = QueueTimingCapture {
            session_id: self.next_session_id,
            sample_rate,
            policy_generation,
            started_at_ms,
            stopped_at_ms: None,
        };
        self.capture = Some(capture.clone());
        capture
    }

    pub fn stop(&mut self, stopped_at_ms: u64) -> bool {
        let Some(capture) = self.capture.as_mut() else {
            return false;
        };
        if capture.stopped_at_ms.is_some() {
            return false;
        }
        capture.stopped_at_ms = Some(stopped_at_ms);
        true
    }

    pub fn clear(&mut self) -> bool {
        let stopped_active_capture = self.is_enabled();
        self.capture = None;
        stopped_active_capture
    }

    pub fn capture(&self) -> Option<&QueueTimingCapture> {
        self.capture.as_ref()
    }

    pub fn is_enabled(&self) -> bool {
        self.capture()
            .is_some_and(|capture| capture.stopped_at_ms.is_none())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResidenceHistogram {
    pub total_ns: u64,
    pub buckets: Vec<u64>,
}

impl Default for ResidenceHistogram {
    fn default() -> Self {
        Self {
            total_ns: 0,
            buckets: vec![0; RESIDENCE_BUCKETS],
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DepthHistogram {
    pub samples: u64,
    pub latest: u32,
    pub max: u32,
    pub buckets: Vec<u64>,
}

impl Default for DepthHistogram {
    fn default() -> Self {
        Self {
            samples: 0,
            latest: 0,
            max: 0,
            buckets: vec![0; DEPTH_BUCKETS],
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DsqTiming {
    pub dsq_id: u64,
    pub cell_index: u32,
    pub queue_class: QueueClass,
    pub residence: ResidenceHistogram,
    pub depth: DepthHistogram,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct QueueTimingInspectionView {
    pub sample_rate: u32,
    pub state: QueueTimingCaptureState,
    pub session_id: Option<u64>,
    pub policy_generation: Option<u64>,
    pub started_at_ms: Option<u64>,
    pub stopped_at_ms: Option<u64>,
    pub started_samples: u64,
    pub completed_samples: u64,
    pub dropped_samples: u64,
    pub dsqs: Vec<DsqTiming>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct QueueTimingCounters {
    pub started_samples: u64,
    pub completed_samples: u64,
    pub dropped_samples: u64,
}

pub fn inspection_view(
    sample_rate: u32,
    state: &QueueTimingState,
    counters: QueueTimingCounters,
    accumulator: &QueueTimingAccumulator,
) -> QueueTimingInspectionView {
    let capture = state.capture();
    let state = match capture {
        Some(capture) if capture.stopped_at_ms.is_none() => QueueTimingCaptureState::Collecting,
        Some(_) => QueueTimingCaptureState::Historical,
        None => QueueTimingCaptureState::Inactive,
    };
    QueueTimingInspectionView {
        sample_rate: capture.map_or(sample_rate, |capture| capture.sample_rate),
        state,
        session_id: capture.map(|capture| capture.session_id),
        policy_generation: capture.map(|capture| capture.policy_generation),
        started_at_ms: capture.map(|capture| capture.started_at_ms),
        stopped_at_ms: capture.and_then(|capture| capture.stopped_at_ms),
        started_samples: counters.started_samples,
        completed_samples: counters.completed_samples,
        dropped_samples: counters.dropped_samples,
        dsqs: capture
            .map(|capture| accumulator.dsqs(capture.session_id))
            .unwrap_or_default(),
    }
}

impl DsqTiming {
    fn new(event: QueueTimingEvent) -> Self {
        Self {
            dsq_id: event.dsq_id,
            cell_index: event.cell_index,
            queue_class: event.queue_class,
            residence: ResidenceHistogram::default(),
            depth: DepthHistogram::default(),
        }
    }

    fn record(&mut self, event: QueueTimingEvent) {
        let residence_bucket = if event.residence_ns > 1 {
            (u64::BITS - 1 - event.residence_ns.leading_zeros()) as usize
        } else {
            0
        }
        .min(RESIDENCE_BUCKETS - 1);
        self.residence.total_ns = self.residence.total_ns.saturating_add(event.residence_ns);
        self.residence.buckets[residence_bucket] =
            self.residence.buckets[residence_bucket].saturating_add(1);

        for depth in [event.depth_after_insert, event.depth_after_dispatch] {
            let bucket = usize::try_from(depth)
                .unwrap_or(DEPTH_BUCKETS - 1)
                .min(DEPTH_BUCKETS - 1);
            self.depth.samples = self.depth.samples.saturating_add(1);
            self.depth.max = self.depth.max.max(depth);
            self.depth.buckets[bucket] = self.depth.buckets[bucket].saturating_add(1);
        }
        self.depth.latest = event.depth_after_dispatch;
    }
}

#[derive(Debug, Default)]
pub struct QueueTimingAccumulator {
    session_id: Option<u64>,
    active: bool,
    dsqs: BTreeMap<u64, DsqTiming>,
}

impl QueueTimingAccumulator {
    pub fn reset(&mut self, session_id: u64) {
        self.session_id = Some(session_id);
        self.active = true;
        self.dsqs.clear();
    }

    pub fn record(&mut self, event: QueueTimingEvent) {
        if !self.active || self.session_id != Some(event.session_id) {
            return;
        }
        self.dsqs
            .entry(event.dsq_id)
            .or_insert_with(|| DsqTiming::new(event))
            .record(event);
    }

    pub fn stop(&mut self) {
        self.active = false;
    }

    pub fn clear(&mut self) {
        self.session_id = None;
        self.active = false;
        self.dsqs.clear();
    }

    pub fn dsqs(&self, session_id: u64) -> Vec<DsqTiming> {
        if self.session_id != Some(session_id) {
            return Vec::new();
        }
        self.dsqs.values().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(
        session_id: u64,
        dsq_id: u64,
        cell_index: u32,
        queue_class: QueueClass,
        residence_ns: u64,
        depth_after_insert: u32,
        depth_after_dispatch: u32,
    ) -> QueueTimingEvent {
        QueueTimingEvent {
            session_id,
            dsq_id,
            residence_ns,
            cell_index,
            queue_class,
            depth_after_insert,
            depth_after_dispatch,
        }
    }

    #[test]
    fn explicit_stop_freezes_a_historical_capture_and_start_replaces_it() {
        let mut state = QueueTimingState::default();

        let first = state.start(64, 7, 100);
        assert!(state.is_enabled());
        assert_eq!(state.capture(), Some(&first));

        assert!(state.stop(250));
        assert!(!state.is_enabled());
        assert_eq!(
            state.capture().and_then(|capture| capture.stopped_at_ms),
            Some(250)
        );
        assert!(!state.stop(300));

        let second = state.start(64, 8, 400);
        assert!(second.session_id > first.session_id);
        assert_eq!(second.policy_generation, 8);
        assert_eq!(second.started_at_ms, 400);
        assert_eq!(second.stopped_at_ms, None);
    }

    #[test]
    fn clear_discards_history_but_never_reuses_a_session_id() {
        let mut state = QueueTimingState::default();
        let first = state.start(64, 7, 100);
        state.stop(200);

        assert!(!state.clear());
        assert!(state.capture().is_none());

        let second = state.start(64, 7, 300);
        assert!(second.session_id > first.session_id);
        assert!(state.clear());
        assert!(state.capture().is_none());
    }

    #[test]
    fn accumulator_uses_base_two_residence_and_capped_linear_depth_buckets() {
        let mut accumulator = QueueTimingAccumulator::default();
        accumulator.reset(11);

        accumulator.record(event(11, 0x2000, 3, QueueClass::Normal, 1, 2, 300));
        accumulator.record(event(11, 0x2000, 3, QueueClass::Normal, 8, 9, 10));

        let dsqs = accumulator.dsqs(11);
        assert_eq!(dsqs.len(), 1);
        let dsq = &dsqs[0];
        assert_eq!(dsq.dsq_id, 0x2000);
        assert_eq!(dsq.cell_index, 3);
        assert_eq!(dsq.queue_class, QueueClass::Normal);
        assert_eq!(dsq.residence.total_ns, 9);
        assert_eq!(dsq.residence.buckets[0], 1);
        assert_eq!(dsq.residence.buckets[3], 1);
        assert_eq!(dsq.residence.buckets.iter().sum::<u64>(), 2);
        assert_eq!(dsq.depth.samples, 4);
        assert_eq!(dsq.depth.latest, 10);
        assert_eq!(dsq.depth.max, 300);
        assert_eq!(dsq.depth.buckets[2], 1);
        assert_eq!(dsq.depth.buckets[9], 1);
        assert_eq!(dsq.depth.buckets[10], 1);
        assert_eq!(dsq.depth.buckets[255], 1);
    }

    #[test]
    fn accumulator_rejects_stale_events_and_sorts_dsqs_by_id() {
        let mut accumulator = QueueTimingAccumulator::default();
        accumulator.reset(20);
        accumulator.record(event(19, 9, 0, QueueClass::Normal, 4, 1, 0));
        accumulator.record(event(20, 9, 0, QueueClass::Affinity, 4, 1, 0));
        accumulator.record(event(20, 3, 1, QueueClass::Normal, 2, 2, 1));

        assert_eq!(
            accumulator
                .dsqs(20)
                .iter()
                .map(|dsq| dsq.dsq_id)
                .collect::<Vec<_>>(),
            vec![3, 9]
        );

        accumulator.stop();
        accumulator.record(event(20, 12, 0, QueueClass::Normal, 8, 1, 0));
        assert_eq!(accumulator.dsqs(20).len(), 2);

        accumulator.reset(21);
        accumulator.record(event(20, 1, 0, QueueClass::Normal, 8, 1, 0));
        assert!(accumulator.dsqs(21).is_empty());
        assert!(accumulator.dsqs(20).is_empty());
    }

    #[test]
    fn inspection_serializes_the_additive_capture_contract() {
        let view = QueueTimingInspectionView {
            sample_rate: 64,
            state: QueueTimingCaptureState::Collecting,
            session_id: Some(23),
            policy_generation: Some(9),
            started_at_ms: Some(1_000),
            stopped_at_ms: None,
            started_samples: 5,
            completed_samples: 4,
            dropped_samples: 1,
            dsqs: Vec::new(),
        };

        let value = serde_json::to_value(view).expect("inspection should serialize");
        assert_eq!(value["sample_rate"], 64);
        assert_eq!(value["state"], "collecting");
        assert_eq!(value["session_id"], 23);
        assert_eq!(value["policy_generation"], 9);
        assert_eq!(value["started_samples"], 5);
        assert_eq!(value["completed_samples"], 4);
        assert_eq!(value["dropped_samples"], 1);
        assert_eq!(value["dsqs"], serde_json::json!([]));
    }

    #[test]
    fn inspection_builder_reports_collecting_and_historical_captures() {
        let mut state = QueueTimingState::default();
        let capture = state.start(64, 9, 1_000);
        let mut accumulator = QueueTimingAccumulator::default();
        accumulator.reset(capture.session_id);
        accumulator.record(event(
            capture.session_id,
            7,
            2,
            QueueClass::Affinity,
            32,
            3,
            2,
        ));
        let counters = QueueTimingCounters {
            started_samples: 2,
            completed_samples: 1,
            dropped_samples: 1,
        };

        let collecting = inspection_view(64, &state, counters, &accumulator);
        assert_eq!(collecting.state, QueueTimingCaptureState::Collecting);
        assert_eq!(collecting.session_id, Some(capture.session_id));
        assert_eq!(collecting.dsqs.len(), 1);

        state.stop(1_500);
        accumulator.stop();
        let historical = inspection_view(128, &state, counters, &accumulator);
        assert_eq!(historical.state, QueueTimingCaptureState::Historical);
        assert_eq!(historical.sample_rate, 64);
        assert_eq!(historical.stopped_at_ms, Some(1_500));
        assert_eq!(historical.completed_samples, 1);

        state.clear();
        accumulator.clear();
        let inactive = inspection_view(64, &state, QueueTimingCounters::default(), &accumulator);
        assert_eq!(inactive.state, QueueTimingCaptureState::Inactive);
        assert_eq!(inactive.session_id, None);
        assert!(inactive.dsqs.is_empty());
    }

    #[test]
    fn capture_start_requires_sampling_but_not_queue_topology() {
        assert_eq!(
            validate_capture_start(0),
            Err("queue timing requires callback timing sampling to be enabled".into())
        );
        assert_eq!(validate_capture_start(64), Ok(()));
        assert_eq!(QueueClass::try_from(2), Ok(QueueClass::Fairness));
    }
}
