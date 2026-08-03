// SPDX-License-Identifier: GPL-2.0-only

//! Bank-aware demand sampling for dynamic managed-cell allocation.
//!
//! The tracker owns no policy or BPF state. Callers provide cumulative counters,
//! active identities, the counter-bank identity, and the sampling timestamp.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Instant;

/// `(policy_generation, active_slot)` identifying one cumulative-counter bank.
pub type CounterBank = (u64, u32);

/// Stable cell identity across topology publications.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CellIdentity {
    pub id: u32,
    pub slot_epoch: u32,
}

/// Cumulative counters and capacity for one active cell.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DemandSample {
    pub runtime_ns: u64,
    pub primary_ns: u64,
    pub borrowed_ns: u64,
    pub lent_ns: u64,
    pub primary_cpus: usize,
}

impl DemandSample {
    fn counters_decreased_from(self, previous: Self) -> bool {
        self.runtime_ns < previous.runtime_ns
            || self.primary_ns < previous.primary_ns
            || self.borrowed_ns < previous.borrowed_ns
            || self.lent_ns < previous.lent_ns
    }
}

/// One complete active-bank observation.
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub counter_bank: CounterBank,
    pub sampled_at: Instant,
    pub cells: BTreeMap<CellIdentity, DemandSample>,
}

/// Most recently computed demand gauges for one cell.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DemandGauges {
    /// Total cell runtime divided by owned-primary-CPU capacity.
    pub util_pct: f64,
    /// Borrowed runtime as a percentage of total cell runtime.
    pub borrowed_pct: f64,
    /// Runtime lent to other cells as a percentage of owned capacity.
    pub lent_pct: f64,
    /// Smoothed utilization, absent until the first nonzero runtime delta.
    pub ewma_pct: Option<f64>,
}

impl Default for DemandGauges {
    fn default() -> Self {
        Self {
            util_pct: 0.0,
            borrowed_pct: 0.0,
            lent_pct: 0.0,
            ewma_pct: None,
        }
    }
}

/// Invalid configuration or snapshot input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DemandError {
    InvalidEwmaAlpha,
    InvalidThreshold,
    NoPrimaryCpus(CellIdentity),
    NonIncreasingSampleTime(CellIdentity),
}

impl fmt::Display for DemandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEwmaAlpha => {
                formatter.write_str("EWMA alpha must be finite and in (0, 1]")
            }
            Self::InvalidThreshold => {
                formatter.write_str("demand spread threshold must be finite and non-negative")
            }
            Self::NoPrimaryCpus(identity) => write!(
                formatter,
                "cell {} epoch {} has no primary CPUs",
                identity.id, identity.slot_epoch
            ),
            Self::NonIncreasingSampleTime(identity) => write!(
                formatter,
                "cell {} epoch {} sample time did not advance",
                identity.id, identity.slot_epoch
            ),
        }
    }
}

impl std::error::Error for DemandError {}

#[derive(Clone, Debug)]
struct CellState {
    baseline: DemandSample,
    sampled_at: Instant,
    gauges: DemandGauges,
}

/// Demand state for the identities in the latest snapshot.
#[derive(Clone, Debug)]
pub struct DemandTracker {
    ewma_alpha: f64,
    counter_bank: Option<CounterBank>,
    cells: BTreeMap<CellIdentity, CellState>,
}

impl DemandTracker {
    /// Creates a tracker with an EWMA smoothing factor in `(0, 1]`.
    pub fn new(ewma_alpha: f64) -> Result<Self, DemandError> {
        if !ewma_alpha.is_finite() || ewma_alpha <= 0.0 || ewma_alpha > 1.0 {
            return Err(DemandError::InvalidEwmaAlpha);
        }
        Ok(Self {
            ewma_alpha,
            counter_bank: None,
            cells: BTreeMap::new(),
        })
    }

    pub fn set_ewma_alpha(&mut self, ewma_alpha: f64) -> Result<(), DemandError> {
        if !ewma_alpha.is_finite() || ewma_alpha <= 0.0 || ewma_alpha > 1.0 {
            return Err(DemandError::InvalidEwmaAlpha);
        }
        self.ewma_alpha = ewma_alpha;
        Ok(())
    }

    /// Applies a complete snapshot transactionally.
    ///
    /// A first observation, counter-bank change, or counter decrease establishes
    /// a fresh baseline. Bank changes preserve EWMA for the same identity. New
    /// identities inherit the average initialized EWMA of surviving identities.
    pub fn step(&mut self, snapshot: Snapshot) -> Result<(), DemandError> {
        let same_bank = self.counter_bank == Some(snapshot.counter_bank);
        if let Some((&identity, _)) = snapshot
            .cells
            .iter()
            .find(|(_, sample)| sample.primary_cpus == 0)
        {
            return Err(DemandError::NoPrimaryCpus(identity));
        }
        if same_bank {
            for (&identity, sample) in &snapshot.cells {
                let Some(state) = self.cells.get(&identity) else {
                    continue;
                };
                if !sample.counters_decreased_from(state.baseline)
                    && snapshot.sampled_at <= state.sampled_at
                {
                    return Err(DemandError::NonIncreasingSampleTime(identity));
                }
            }
        }
        let previous = std::mem::take(&mut self.cells);
        let surviving_ewmas = previous
            .iter()
            .filter(|(identity, _)| snapshot.cells.contains_key(identity))
            .filter_map(|(_, state)| state.gauges.ewma_pct)
            .collect::<Vec<_>>();
        let new_identity_seed = (!surviving_ewmas.is_empty())
            .then(|| surviving_ewmas.iter().sum::<f64>() / surviving_ewmas.len() as f64);
        self.counter_bank = Some(snapshot.counter_bank);
        self.cells = snapshot
            .cells
            .into_iter()
            .map(|(identity, baseline)| {
                let gauges = if same_bank {
                    previous.get(&identity).map_or_else(
                        || DemandGauges {
                            ewma_pct: new_identity_seed,
                            ..DemandGauges::default()
                        },
                        |state| {
                            if baseline.counters_decreased_from(state.baseline) {
                                return DemandGauges {
                                    ewma_pct: state.gauges.ewma_pct,
                                    ..DemandGauges::default()
                                };
                            }
                            let elapsed_ns = snapshot
                                .sampled_at
                                .saturating_duration_since(state.sampled_at)
                                .as_nanos() as f64;
                            let runtime_ns = baseline
                                .runtime_ns
                                .saturating_sub(state.baseline.runtime_ns);
                            let borrowed_ns = baseline
                                .borrowed_ns
                                .saturating_sub(state.baseline.borrowed_ns);
                            let lent_ns = baseline.lent_ns.saturating_sub(state.baseline.lent_ns);
                            let capacity_ns = elapsed_ns * baseline.primary_cpus as f64;
                            let util_pct = 100.0 * runtime_ns as f64 / capacity_ns;
                            let borrowed_pct = if runtime_ns == 0 {
                                0.0
                            } else {
                                (100.0 * borrowed_ns as f64 / runtime_ns as f64).min(100.0)
                            };
                            let lent_pct = (100.0 * lent_ns as f64 / capacity_ns).min(100.0);
                            let ewma_pct = if runtime_ns == 0 && lent_ns == 0 {
                                state.gauges.ewma_pct
                            } else {
                                Some(state.gauges.ewma_pct.map_or(util_pct, |previous| {
                                    self.ewma_alpha * util_pct + (1.0 - self.ewma_alpha) * previous
                                }))
                            };
                            DemandGauges {
                                util_pct,
                                borrowed_pct,
                                lent_pct,
                                ewma_pct,
                            }
                        },
                    )
                } else {
                    DemandGauges {
                        ewma_pct: previous
                            .get(&identity)
                            .map_or(new_identity_seed, |state| state.gauges.ewma_pct),
                        ..DemandGauges::default()
                    }
                };
                (
                    identity,
                    CellState {
                        baseline,
                        sampled_at: snapshot.sampled_at,
                        gauges,
                    },
                )
            })
            .collect();
        Ok(())
    }

    /// Returns the active cumulative-counter bank, if any snapshot was applied.
    pub fn counter_bank(&self) -> Option<CounterBank> {
        self.counter_bank
    }

    /// Returns the latest gauges for one active identity.
    pub fn gauge(&self, identity: CellIdentity) -> Option<DemandGauges> {
        self.cells.get(&identity).map(|state| state.gauges)
    }

    /// Returns the latest gauges for all active identities.
    #[cfg(test)]
    pub fn gauges(&self) -> BTreeMap<CellIdentity, DemandGauges> {
        self.cells
            .iter()
            .map(|(&identity, state)| (identity, state.gauges))
            .collect()
    }

    /// Returns allocator weights keyed by external cell ID.
    ///
    /// Cells without an initialized EWMA have weight zero.
    pub fn demand_weights(&self) -> BTreeMap<u32, f64> {
        self.cells
            .iter()
            .map(|(identity, state)| (identity.id, state.gauges.ewma_pct.unwrap_or(0.0)))
            .collect()
    }

    pub fn projected_demand_weights(
        &self,
        identities: impl IntoIterator<Item = CellIdentity>,
    ) -> BTreeMap<u32, f64> {
        let identities = identities.into_iter().collect::<Vec<_>>();
        let surviving = identities
            .iter()
            .filter_map(|identity| self.cells.get(identity)?.gauges.ewma_pct)
            .collect::<Vec<_>>();
        let seed = if surviving.is_empty() {
            0.0
        } else {
            surviving.iter().sum::<f64>() / surviving.len() as f64
        };
        identities
            .into_iter()
            .map(|identity| {
                let weight = self
                    .cells
                    .get(&identity)
                    .and_then(|state| state.gauges.ewma_pct)
                    .unwrap_or(seed);
                (identity.id, weight)
            })
            .collect()
    }

    /// Returns `max(EWMA) - min(EWMA)` when at least two cells are active.
    pub fn spread_pct(&self) -> Option<f64> {
        if self.cells.len() < 2 {
            return None;
        }
        let mut weights = self
            .cells
            .values()
            .map(|state| state.gauges.ewma_pct.unwrap_or(0.0));
        let first = weights.next()?;
        let (minimum, maximum) = weights.fold((first, first), |(minimum, maximum), weight| {
            (minimum.min(weight), maximum.max(weight))
        });
        Some(maximum - minimum)
    }

    /// Tests the current spread against a finite, non-negative threshold.
    pub fn spread_at_least(&self, threshold_pct: f64) -> Result<bool, DemandError> {
        if !threshold_pct.is_finite() || threshold_pct < 0.0 {
            return Err(DemandError::InvalidThreshold);
        }
        Ok(self
            .spread_pct()
            .is_some_and(|spread| spread >= threshold_pct))
    }

    /// Returns the number of active identities.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.cells.len()
    }

    /// Returns whether the latest snapshot contains no cells.
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::{Duration, Instant};

    use super::*;

    fn identity(id: u32, slot_epoch: u32) -> CellIdentity {
        CellIdentity { id, slot_epoch }
    }

    fn sample(runtime_ns: u64, primary_cpus: usize) -> DemandSample {
        DemandSample {
            runtime_ns,
            primary_ns: runtime_ns,
            borrowed_ns: 0,
            lent_ns: 0,
            primary_cpus,
        }
    }

    fn counters(
        runtime_ns: u64,
        primary_ns: u64,
        borrowed_ns: u64,
        lent_ns: u64,
        primary_cpus: usize,
    ) -> DemandSample {
        DemandSample {
            runtime_ns,
            primary_ns,
            borrowed_ns,
            lent_ns,
            primary_cpus,
        }
    }

    #[test]
    fn retuning_ewma_alpha_preserves_the_active_baseline() {
        let started = Instant::now();
        let cell = identity(7, 2);
        let mut tracker = DemandTracker::new(0.5).unwrap();

        tracker
            .step(snapshot((1, 0), started, [(cell, sample(0, 1))]))
            .unwrap();
        tracker
            .step(snapshot(
                (1, 0),
                started + std::time::Duration::from_secs(1),
                [(cell, sample(500_000_000, 1))],
            ))
            .unwrap();
        assert_eq!(tracker.gauge(cell).unwrap().ewma_pct, Some(50.0));

        tracker.set_ewma_alpha(1.0).unwrap();
        tracker
            .step(snapshot(
                (1, 0),
                started + std::time::Duration::from_secs(2),
                [(cell, sample(1_500_000_000, 1))],
            ))
            .unwrap();

        assert_eq!(tracker.counter_bank(), Some((1, 0)));
        assert_eq!(tracker.gauge(cell).unwrap().ewma_pct, Some(100.0));
    }

    fn snapshot(
        counter_bank: CounterBank,
        sampled_at: Instant,
        cells: impl IntoIterator<Item = (CellIdentity, DemandSample)>,
    ) -> Snapshot {
        Snapshot {
            counter_bank,
            sampled_at,
            cells: cells.into_iter().collect::<BTreeMap<_, _>>(),
        }
    }

    #[test]
    fn first_snapshot_establishes_a_baseline_without_demand() {
        let started = Instant::now();
        let cell = identity(7, 3);
        let mut tracker = DemandTracker::new(0.5).unwrap();

        tracker
            .step(snapshot((1, 0), started, [(cell, sample(500, 2))]))
            .unwrap();

        assert_eq!(
            tracker.gauge(cell),
            Some(DemandGauges {
                util_pct: 0.0,
                borrowed_pct: 0.0,
                lent_pct: 0.0,
                ewma_pct: None,
            })
        );
        assert_eq!(tracker.counter_bank(), Some((1, 0)));
        assert_eq!(tracker.len(), 1);
        assert!(!tracker.is_empty());
    }

    #[test]
    fn elapsed_runtime_updates_instantaneous_gauges_and_ewma() {
        let started = Instant::now();
        let cell = identity(7, 3);
        let mut tracker = DemandTracker::new(0.5).unwrap();
        tracker
            .step(snapshot((1, 0), started, [(cell, counters(0, 0, 0, 0, 2))]))
            .unwrap();

        tracker
            .step(snapshot(
                (1, 0),
                started + Duration::from_secs(1),
                [(
                    cell,
                    counters(1_000_000_000, 750_000_000, 250_000_000, 400_000_000, 2),
                )],
            ))
            .unwrap();

        let gauges = tracker.gauge(cell).unwrap();
        assert_eq!(gauges.util_pct, 50.0);
        assert_eq!(gauges.borrowed_pct, 25.0);
        assert_eq!(gauges.lent_pct, 20.0);
        assert_eq!(gauges.ewma_pct, Some(50.0));
    }

    #[test]
    fn no_activity_leaves_ewma_unchanged() {
        let started = Instant::now();
        let cell = identity(7, 3);
        let mut tracker = DemandTracker::new(0.5).unwrap();
        tracker
            .step(snapshot((1, 0), started, [(cell, counters(0, 0, 0, 0, 2))]))
            .unwrap();
        tracker
            .step(snapshot(
                (1, 0),
                started + Duration::from_secs(1),
                [(
                    cell,
                    counters(1_000_000_000, 750_000_000, 250_000_000, 400_000_000, 2),
                )],
            ))
            .unwrap();

        tracker
            .step(snapshot(
                (1, 0),
                started + Duration::from_secs(2),
                [(
                    cell,
                    counters(1_000_000_000, 750_000_000, 250_000_000, 400_000_000, 2),
                )],
            ))
            .unwrap();

        let gauges = tracker.gauge(cell).unwrap();
        assert_eq!(gauges.util_pct, 0.0);
        assert_eq!(gauges.borrowed_pct, 0.0);
        assert_eq!(gauges.lent_pct, 0.0);
        assert_eq!(gauges.ewma_pct, Some(50.0));
    }

    #[test]
    fn lending_only_interval_decays_ewma_toward_zero() {
        let started = Instant::now();
        let cell = identity(7, 3);
        let mut tracker = DemandTracker::new(0.5).unwrap();
        tracker
            .step(snapshot((1, 0), started, [(cell, counters(0, 0, 0, 0, 2))]))
            .unwrap();
        tracker
            .step(snapshot(
                (1, 0),
                started + Duration::from_secs(1),
                [(cell, counters(1_000_000_000, 1_000_000_000, 0, 0, 2))],
            ))
            .unwrap();

        tracker
            .step(snapshot(
                (1, 0),
                started + Duration::from_secs(2),
                [(
                    cell,
                    counters(1_000_000_000, 1_000_000_000, 0, 1_000_000_000, 2),
                )],
            ))
            .unwrap();

        let gauges = tracker.gauge(cell).unwrap();
        assert_eq!(gauges.util_pct, 0.0);
        assert_eq!(gauges.lent_pct, 50.0);
        assert_eq!(gauges.ewma_pct, Some(25.0));
    }

    #[test]
    fn counter_bank_change_rebases_but_preserves_ewma() {
        let started = Instant::now();
        let cell = identity(7, 3);
        let mut tracker = DemandTracker::new(0.5).unwrap();
        tracker
            .step(snapshot((1, 0), started, [(cell, counters(0, 0, 0, 0, 2))]))
            .unwrap();
        tracker
            .step(snapshot(
                (1, 0),
                started + Duration::from_secs(1),
                [(cell, counters(1_000_000_000, 1_000_000_000, 0, 0, 2))],
            ))
            .unwrap();
        assert_eq!(tracker.gauge(cell).unwrap().ewma_pct, Some(50.0));

        tracker
            .step(snapshot(
                (1, 1),
                started + Duration::from_secs(2),
                [(cell, counters(100, 100, 0, 0, 2))],
            ))
            .unwrap();
        assert_eq!(
            tracker.gauge(cell),
            Some(DemandGauges {
                util_pct: 0.0,
                borrowed_pct: 0.0,
                lent_pct: 0.0,
                ewma_pct: Some(50.0),
            })
        );

        tracker
            .step(snapshot(
                (1, 1),
                started + Duration::from_secs(3),
                [(cell, counters(1_000_000_100, 1_000_000_100, 0, 0, 2))],
            ))
            .unwrap();
        assert_eq!(tracker.gauge(cell).unwrap().util_pct, 50.0);
        assert_eq!(tracker.gauge(cell).unwrap().ewma_pct, Some(50.0));
    }

    #[test]
    fn any_counter_decrease_rebases_the_cell() {
        let started = Instant::now();
        let cell = identity(7, 3);
        let mut tracker = DemandTracker::new(0.5).unwrap();
        tracker
            .step(snapshot((1, 0), started, [(cell, counters(0, 0, 0, 0, 2))]))
            .unwrap();
        tracker
            .step(snapshot(
                (1, 0),
                started + Duration::from_secs(1),
                [(cell, counters(1_000_000_000, 1_000_000_000, 0, 0, 2))],
            ))
            .unwrap();

        tracker
            .step(snapshot(
                (1, 0),
                started + Duration::from_secs(2),
                [(cell, counters(1_500_000_000, 100, 0, 0, 2))],
            ))
            .unwrap();
        assert_eq!(
            tracker.gauge(cell),
            Some(DemandGauges {
                util_pct: 0.0,
                borrowed_pct: 0.0,
                lent_pct: 0.0,
                ewma_pct: Some(50.0),
            })
        );

        tracker
            .step(snapshot(
                (1, 0),
                started + Duration::from_secs(3),
                [(cell, counters(2_500_000_000, 1_000_000_100, 0, 0, 2))],
            ))
            .unwrap();
        assert_eq!(tracker.gauge(cell).unwrap().util_pct, 50.0);
        assert_eq!(tracker.gauge(cell).unwrap().ewma_pct, Some(50.0));
    }

    #[test]
    fn new_identity_seeds_from_survivors_and_removed_identity_is_dropped() {
        let started = Instant::now();
        let cell0 = identity(0, 0);
        let removed = identity(7, 3);
        let added = identity(9, 1);
        let mut tracker = DemandTracker::new(1.0).unwrap();
        tracker
            .step(snapshot(
                (1, 0),
                started,
                [
                    (cell0, counters(0, 0, 0, 0, 1)),
                    (removed, counters(0, 0, 0, 0, 1)),
                ],
            ))
            .unwrap();
        tracker
            .step(snapshot(
                (1, 0),
                started + Duration::from_secs(1),
                [
                    (cell0, counters(400_000_000, 400_000_000, 0, 0, 1)),
                    (removed, counters(800_000_000, 800_000_000, 0, 0, 1)),
                ],
            ))
            .unwrap();

        tracker
            .step(snapshot(
                (1, 0),
                started + Duration::from_secs(2),
                [
                    (cell0, counters(400_000_000, 400_000_000, 0, 0, 1)),
                    (added, counters(0, 0, 0, 0, 1)),
                ],
            ))
            .unwrap();

        assert_eq!(tracker.gauge(cell0).unwrap().ewma_pct, Some(40.0));
        assert_eq!(tracker.gauge(added).unwrap().ewma_pct, Some(40.0));
        assert_eq!(tracker.gauge(removed), None);
        assert_eq!(tracker.len(), 2);
    }

    #[test]
    fn reused_numeric_id_is_a_new_identity() {
        let started = Instant::now();
        let cell0 = identity(0, 0);
        let old = identity(7, 3);
        let replacement = identity(7, 4);
        let mut tracker = DemandTracker::new(1.0).unwrap();
        tracker
            .step(snapshot(
                (1, 0),
                started,
                [
                    (cell0, counters(0, 0, 0, 0, 1)),
                    (old, counters(0, 0, 0, 0, 1)),
                ],
            ))
            .unwrap();
        tracker
            .step(snapshot(
                (1, 0),
                started + Duration::from_secs(1),
                [
                    (cell0, counters(200_000_000, 200_000_000, 0, 0, 1)),
                    (old, counters(800_000_000, 800_000_000, 0, 0, 1)),
                ],
            ))
            .unwrap();

        tracker
            .step(snapshot(
                (2, 1),
                started + Duration::from_secs(2),
                [
                    (cell0, counters(0, 0, 0, 0, 1)),
                    (replacement, counters(0, 0, 0, 0, 1)),
                ],
            ))
            .unwrap();

        assert_eq!(tracker.gauge(old), None);
        assert_eq!(tracker.gauge(cell0).unwrap().ewma_pct, Some(20.0));
        assert_eq!(tracker.gauge(replacement).unwrap().ewma_pct, Some(20.0));
    }

    #[test]
    fn projected_weights_preserve_survivors_and_seed_new_epochs() {
        let started = Instant::now();
        let cell0 = identity(0, 0);
        let old = identity(7, 3);
        let replacement = identity(7, 4);
        let added = identity(8, 1);
        let mut tracker = DemandTracker::new(1.0).unwrap();
        tracker
            .step(snapshot(
                (1, 0),
                started,
                [(cell0, sample(0, 1)), (old, sample(0, 1))],
            ))
            .unwrap();
        tracker
            .step(snapshot(
                (1, 0),
                started + Duration::from_secs(1),
                [
                    (cell0, sample(200_000_000, 1)),
                    (old, sample(800_000_000, 1)),
                ],
            ))
            .unwrap();

        assert_eq!(
            tracker.projected_demand_weights([cell0, replacement, added]),
            BTreeMap::from([(0, 20.0), (7, 20.0), (8, 20.0)])
        );
    }

    #[test]
    fn exposes_gauges_weights_and_threshold_spread() {
        let started = Instant::now();
        let cell0 = identity(0, 0);
        let cell7 = identity(7, 3);
        let mut tracker = DemandTracker::new(1.0).unwrap();
        tracker
            .step(snapshot(
                (1, 0),
                started,
                [
                    (cell0, counters(0, 0, 0, 0, 1)),
                    (cell7, counters(0, 0, 0, 0, 1)),
                ],
            ))
            .unwrap();
        tracker
            .step(snapshot(
                (1, 0),
                started + Duration::from_secs(1),
                [
                    (cell0, counters(200_000_000, 200_000_000, 0, 0, 1)),
                    (cell7, counters(800_000_000, 800_000_000, 0, 0, 1)),
                ],
            ))
            .unwrap();

        assert_eq!(tracker.gauges().len(), 2);
        assert_eq!(
            tracker.demand_weights(),
            BTreeMap::from([(0, 20.0), (7, 80.0)])
        );
        assert_eq!(tracker.spread_pct(), Some(60.0));
        assert!(tracker.spread_at_least(60.0).unwrap());
        assert!(!tracker.spread_at_least(60.1).unwrap());
    }

    #[test]
    fn zero_primary_capacity_is_rejected_without_changing_state() {
        let started = Instant::now();
        let cell = identity(7, 3);
        let mut tracker = DemandTracker::new(0.5).unwrap();
        tracker
            .step(snapshot(
                (1, 0),
                started,
                [(cell, counters(10, 10, 0, 0, 1))],
            ))
            .unwrap();
        let before = tracker.gauges();

        let error = tracker
            .step(snapshot(
                (1, 0),
                started + Duration::from_secs(1),
                [(cell, counters(20, 20, 0, 0, 0))],
            ))
            .unwrap_err();

        assert_eq!(error, DemandError::NoPrimaryCpus(cell));
        assert_eq!(tracker.gauges(), before);
        assert_eq!(tracker.counter_bank(), Some((1, 0)));
    }

    #[test]
    fn non_increasing_sample_time_is_rejected_transactionally() {
        let started = Instant::now();
        let cell = identity(7, 3);
        let mut tracker = DemandTracker::new(0.5).unwrap();
        tracker
            .step(snapshot(
                (1, 0),
                started,
                [(cell, counters(10, 10, 0, 0, 1))],
            ))
            .unwrap();
        let before = tracker.gauges();

        let error = tracker
            .step(snapshot(
                (1, 0),
                started,
                [(cell, counters(20, 20, 0, 0, 1))],
            ))
            .unwrap_err();

        assert_eq!(error, DemandError::NonIncreasingSampleTime(cell));
        assert_eq!(tracker.gauges(), before);
    }

    #[test]
    fn validates_ewma_alpha_and_spread_threshold() {
        assert_eq!(
            DemandTracker::new(0.0).unwrap_err(),
            DemandError::InvalidEwmaAlpha
        );
        assert_eq!(
            DemandTracker::new(-0.1).unwrap_err(),
            DemandError::InvalidEwmaAlpha
        );
        assert_eq!(
            DemandTracker::new(1.1).unwrap_err(),
            DemandError::InvalidEwmaAlpha
        );
        assert_eq!(
            DemandTracker::new(f64::NAN).unwrap_err(),
            DemandError::InvalidEwmaAlpha
        );
        let tracker = DemandTracker::new(1.0).unwrap();
        assert_eq!(
            tracker.spread_at_least(-0.1).unwrap_err(),
            DemandError::InvalidThreshold
        );
        assert_eq!(
            tracker.spread_at_least(f64::INFINITY).unwrap_err(),
            DemandError::InvalidThreshold
        );
        assert!(!tracker.spread_at_least(0.0).unwrap());
    }

    #[test]
    fn later_observations_are_blended_with_alpha() {
        let started = Instant::now();
        let cell = identity(7, 3);
        let mut tracker = DemandTracker::new(0.25).unwrap();
        tracker
            .step(snapshot((1, 0), started, [(cell, counters(0, 0, 0, 0, 1))]))
            .unwrap();
        tracker
            .step(snapshot(
                (1, 0),
                started + Duration::from_secs(1),
                [(cell, counters(1_000_000_000, 1_000_000_000, 0, 0, 1))],
            ))
            .unwrap();
        assert_eq!(tracker.gauge(cell).unwrap().ewma_pct, Some(100.0));

        tracker
            .step(snapshot(
                (1, 0),
                started + Duration::from_secs(2),
                [(cell, counters(1_200_000_000, 1_200_000_000, 0, 0, 1))],
            ))
            .unwrap();

        assert_eq!(tracker.gauge(cell).unwrap().util_pct, 20.0);
        assert_eq!(tracker.gauge(cell).unwrap().ewma_pct, Some(80.0));
    }
}
