// SPDX-License-Identifier: GPL-2.0-only

use scx_snake::fairness::{
    advance_virtual_time, clamp_virtual_lag, is_eligible, restore_vruntime, scale_inverse_weight,
    virtual_deadline, FairnessMode, EEVDF_SLICE_NS,
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
