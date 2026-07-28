// SPDX-License-Identifier: GPL-2.0-only

use scx_snake::fairness::{
    advance_virtual_time, clamp_virtual_lag, clamp_vtime_credit, is_eligible, later_vtime_frontier,
    min_vtime_dispatch_class, next_dispatch_class, restore_vruntime, scale_inverse_weight,
    translate_vruntime, virtual_deadline, DispatchClass, FairnessMode, EEVDF_SLICE_NS,
    VTIME_SLICE_NS,
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
