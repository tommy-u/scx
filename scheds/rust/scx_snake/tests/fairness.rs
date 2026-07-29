// SPDX-License-Identifier: GPL-2.0-only

use scx_snake::fairness::{
    advance_virtual_time, clamp_virtual_lag, clamp_vtime_credit, is_eligible, later_vtime_frontier,
    min_vtime_dispatch_class, next_dispatch_class, project_vtime, replenish_vtime_budget,
    restore_vruntime, scale_inverse_weight, translate_vruntime, virtual_deadline, vtime_run_start,
    vtime_run_weight, vtime_service_ns, vtime_slice_ns, DispatchClass, FairnessMode, BASE_WEIGHT,
    EEVDF_SLICE_NS, VTIME_MIN_SLICE_NS, VTIME_SLICE_NS,
};

#[test]
fn fifo_is_the_default_fairness_mode() {
    assert_eq!(FairnessMode::default(), FairnessMode::Fifo);
}

#[test]
fn task_service_scales_inversely_with_weight() {
    assert_eq!(scale_inverse_weight(5_000_000, 100).unwrap(), 5_000_000);
    assert_eq!(scale_inverse_weight(5_000_000, 50).unwrap(), 10_000_000);
    assert_eq!(scale_inverse_weight(5_000_000, 200).unwrap(), 2_500_000);
    assert!(scale_inverse_weight(5_000_000, 0).is_err());
}

#[test]
fn low_weight_vtime_quantum_stays_below_the_watchdog_budget() {
    const CPUS: u64 = 248;
    const PEERS: u64 = CPUS * 10;
    const WATCHDOG_NS: u64 = 5_000_000_000;

    let slice = vtime_slice_ns(1).unwrap();
    let lead = scale_inverse_weight(slice, 1).unwrap();
    let catchup = (u128::from(PEERS) * u128::from(lead)).div_ceil(u128::from(CPUS));

    assert_eq!(slice, VTIME_MIN_SLICE_NS);
    assert_eq!(lead, 100_000_000);
    assert!(catchup < u128::from(WATCHDOG_NS));
}

#[test]
fn weight_scaled_vtime_quanta_preserve_service_ratio() {
    let low_slice = vtime_slice_ns(1).unwrap();
    let base_slice = vtime_slice_ns(BASE_WEIGHT).unwrap();

    let low_charge = scale_inverse_weight(low_slice, 1).unwrap();
    let base_charge = scale_inverse_weight(base_slice, BASE_WEIGHT).unwrap();
    let base_quanta = low_charge / base_charge;

    assert_eq!(low_charge % base_charge, 0);
    assert_eq!(low_slice * BASE_WEIGHT, base_slice * base_quanta);
    assert_eq!(vtime_slice_ns(10_000).unwrap(), base_slice);
    assert_eq!(vtime_slice_ns(0).unwrap(), base_slice);
}

#[test]
fn vtime_service_is_bounded_by_the_assigned_slice() {
    let low_weight_slice = vtime_slice_ns(1).unwrap();
    let base_weight_slice = vtime_slice_ns(BASE_WEIGHT).unwrap();

    let overrun = vtime_service_ns(11_213_262, low_weight_slice, 0);
    assert_eq!(overrun, low_weight_slice);
    assert_eq!(scale_inverse_weight(overrun, 1).unwrap(), 100_000_000);

    let yielded = vtime_service_ns(1_000, base_weight_slice, 0);
    assert_eq!(yielded, base_weight_slice);

    let partial = vtime_service_ns(1_000_000, base_weight_slice, 4_000_000);
    assert_eq!(partial, 1_000_000);
}

#[test]
fn retained_vtime_slices_extend_the_service_budget() {
    let slice = vtime_slice_ns(BASE_WEIGHT).unwrap();
    let budget = replenish_vtime_budget(slice, 0, slice);

    assert_eq!(budget, 2 * slice);
    assert_eq!(vtime_service_ns(2 * slice, budget, 0), 2 * slice);
    assert_eq!(replenish_vtime_budget(slice, 2_000_000, slice), 8_000_000);
    assert_eq!(replenish_vtime_budget(u64::MAX - 1, 0, slice), u64::MAX);
}

#[test]
fn yield_projection_forfeits_the_remaining_vtime_budget() {
    let slice = vtime_slice_ns(BASE_WEIGHT).unwrap();
    let candidate_vtime = 1_000_000;
    let projected = project_vtime(0, 1_000, slice, 0, BASE_WEIGHT).unwrap();

    assert!(projected > candidate_vtime);
    assert_eq!(projected, slice);
}

#[test]
fn queued_weight_change_preserves_the_slice_assignment_weight() {
    let assigned_weight = BASE_WEIGHT;
    let live_weight = 1;
    let slice = vtime_slice_ns(assigned_weight).unwrap();
    let run_weight = vtime_run_weight(assigned_weight, live_weight);

    assert_eq!(run_weight, assigned_weight);
    assert_eq!(
        scale_inverse_weight(slice, run_weight).unwrap(),
        VTIME_SLICE_NS
    );
}

#[test]
fn run_start_reclamps_vtime_after_a_long_queue_wait() {
    const STALE_NORMAL: u64 = 3_051_160_894;
    const AFFINITY_HEAD: u64 = 11_876_096_903;
    const CELL_FRONTIER: u64 = 22_424_010_766;
    const WATCHDOG_NS: u64 = 5_000_000_000;

    let slice = vtime_slice_ns(BASE_WEIGHT).unwrap();
    let stale_projected = project_vtime(STALE_NORMAL, slice, slice, 0, BASE_WEIGHT).unwrap();

    assert_eq!(AFFINITY_HEAD - STALE_NORMAL, 8_824_936_009);
    assert!(AFFINITY_HEAD - STALE_NORMAL > WATCHDOG_NS);
    assert!(stale_projected < AFFINITY_HEAD);

    let run_start = vtime_run_start(STALE_NORMAL, CELL_FRONTIER);
    assert_eq!(run_start, CELL_FRONTIER - VTIME_SLICE_NS);
    let reclamped_projected = project_vtime(run_start, slice, slice, 0, BASE_WEIGHT).unwrap();
    assert!(reclamped_projected > AFFINITY_HEAD);
}

#[test]
fn vtime_is_a_distinct_experimental_fairness_mode() {
    assert_eq!(FairnessMode::Vtime.as_str(), "vtime");
    assert_ne!(FairnessMode::Vtime, FairnessMode::Eevdf);
}

#[test]
fn vtime_frontier_advances_to_the_later_running_task() {
    assert_eq!(later_vtime_frontier(10, 20), 20);
    assert_eq!(later_vtime_frontier(20, 10), 20);
    assert_eq!(later_vtime_frontier(u64::MAX - 5, 4), 4);
}

#[test]
fn vtime_sleeper_credit_is_bounded_to_one_slice() {
    let frontier = 100_000_000;

    assert_eq!(
        clamp_vtime_credit(frontier - 2 * VTIME_SLICE_NS, frontier),
        frontier - VTIME_SLICE_NS
    );
    assert_eq!(
        clamp_vtime_credit(frontier - VTIME_SLICE_NS / 2, frontier),
        frontier - VTIME_SLICE_NS / 2
    );
    assert_eq!(
        clamp_vtime_credit(frontier + VTIME_SLICE_NS, frontier),
        frontier + VTIME_SLICE_NS
    );
}

#[test]
fn cell_clock_transition_preserves_only_bounded_lag() {
    assert_eq!(translate_vruntime(90, 100, 1_000, 20), 990);
    assert_eq!(translate_vruntime(50, 100, 1_000, 20), 980);
    assert_eq!(translate_vruntime(140, 100, 1_000, 20), 1_020);
    assert_eq!(translate_vruntime(110, 100, 1_000, 20), 1_010);
}

#[test]
fn dispatch_classes_alternate_without_comparing_clocks() {
    let first = next_dispatch_class(true, true, DispatchClass::Affinity).unwrap();
    assert_eq!(first, (DispatchClass::Affinity, DispatchClass::Normal));
    let second = next_dispatch_class(true, true, first.1).unwrap();
    assert_eq!(second, (DispatchClass::Normal, DispatchClass::Affinity));
    assert_eq!(
        next_dispatch_class(true, false, DispatchClass::Affinity),
        Some((DispatchClass::Normal, DispatchClass::Affinity))
    );
    assert_eq!(
        next_dispatch_class(false, true, DispatchClass::Normal),
        Some((DispatchClass::Affinity, DispatchClass::Normal))
    );
    assert_eq!(
        next_dispatch_class(false, false, DispatchClass::Normal),
        None
    );
}

#[test]
fn min_vtime_selects_the_earliest_available_head() {
    assert_eq!(
        min_vtime_dispatch_class(Some(10), Some(20), DispatchClass::Normal),
        Some((DispatchClass::Normal, DispatchClass::Normal))
    );
    assert_eq!(
        min_vtime_dispatch_class(Some(20), Some(10), DispatchClass::Normal),
        Some((DispatchClass::Affinity, DispatchClass::Normal))
    );
    assert_eq!(
        min_vtime_dispatch_class(Some(10), None, DispatchClass::Affinity),
        Some((DispatchClass::Normal, DispatchClass::Affinity))
    );
    assert_eq!(
        min_vtime_dispatch_class(None, Some(10), DispatchClass::Normal),
        Some((DispatchClass::Affinity, DispatchClass::Normal))
    );
    assert_eq!(
        min_vtime_dispatch_class(None, None, DispatchClass::Normal),
        None
    );
}

#[test]
fn min_vtime_alternates_equal_heads_and_handles_wraparound() {
    let first = min_vtime_dispatch_class(Some(10), Some(10), DispatchClass::Normal).unwrap();
    assert_eq!(first, (DispatchClass::Normal, DispatchClass::Affinity));
    let second = min_vtime_dispatch_class(Some(10), Some(10), first.1).unwrap();
    assert_eq!(second, (DispatchClass::Affinity, DispatchClass::Normal));

    assert_eq!(
        min_vtime_dispatch_class(Some(u64::MAX - 5), Some(4), DispatchClass::Normal,),
        Some((DispatchClass::Normal, DispatchClass::Normal))
    );
}

#[test]
fn global_clock_advances_by_total_runnable_weight() {
    assert_eq!(advance_virtual_time(10, 5_000_000, 200).unwrap(), 2_500_010);
    assert!(advance_virtual_time(10, 5_000_000, 0).is_err());
}

#[test]
fn eligibility_and_deadline_use_the_aggregate_frontier() {
    let frontier = 40_000_000;
    assert!(is_eligible(frontier - 1, frontier));
    assert!(is_eligible(frontier, frontier));
    assert!(!is_eligible(frontier + 1, frontier));
    assert_eq!(
        virtual_deadline(frontier, 50).unwrap(),
        frontier + EEVDF_SLICE_NS * 2
    );
}

#[test]
fn sleeper_lag_is_bounded_to_one_weight_scaled_request() {
    let request = EEVDF_SLICE_NS * 2;
    assert_eq!(clamp_virtual_lag(50_000_000, request), request as i64);
    assert_eq!(clamp_virtual_lag(-50_000_000, request), -(request as i64));
    assert_eq!(clamp_virtual_lag(123, request), 123);
    assert_eq!(restore_vruntime(100_000_000, request as i64), 90_000_000);
    assert_eq!(
        restore_vruntime(100_000_000, -(request as i64)),
        110_000_000
    );
}
