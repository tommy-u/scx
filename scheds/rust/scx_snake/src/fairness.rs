// SPDX-License-Identifier: GPL-2.0-only

use clap::ValueEnum;

pub const BASE_WEIGHT: u64 = 100;
pub const EEVDF_SLICE_NS: u64 = 5_000_000;
pub const VTIME_SLICE_NS: u64 = 5_000_000;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum FairnessMode {
    #[default]
    Fifo = 1,
    Eevdf = 2,
    Vtime = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchClass {
    Normal,
    Affinity,
}

impl FairnessMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fifo => "fifo",
            Self::Eevdf => "eevdf",
            Self::Vtime => "vtime",
        }
    }
}

fn vtime_before(lhs: u64, rhs: u64) -> bool {
    (lhs.wrapping_sub(rhs) as i64) < 0
}

pub fn later_vtime_frontier(frontier: u64, candidate: u64) -> u64 {
    if vtime_before(frontier, candidate) {
        candidate
    } else {
        frontier
    }
}

pub fn clamp_vtime_credit(vruntime: u64, frontier: u64) -> u64 {
    let minimum = frontier.wrapping_sub(VTIME_SLICE_NS);

    if vtime_before(vruntime, minimum) {
        minimum
    } else {
        vruntime
    }
}

pub fn translate_vruntime(vruntime: u64, old_frontier: u64, new_frontier: u64, limit: u64) -> u64 {
    let limit = i64::try_from(limit).unwrap_or(i64::MAX);
    let lag = (vruntime.wrapping_sub(old_frontier) as i64).clamp(-limit, limit);

    if lag >= 0 {
        new_frontier.wrapping_add(lag as u64)
    } else {
        new_frontier.wrapping_sub(lag.unsigned_abs())
    }
}

pub fn next_dispatch_class(
    normal_ready: bool,
    affinity_ready: bool,
    next: DispatchClass,
) -> Option<(DispatchClass, DispatchClass)> {
    match (normal_ready, affinity_ready) {
        (false, false) => None,
        (true, false) => Some((DispatchClass::Normal, DispatchClass::Affinity)),
        (false, true) => Some((DispatchClass::Affinity, DispatchClass::Normal)),
        (true, true) => match next {
            DispatchClass::Normal => Some((DispatchClass::Normal, DispatchClass::Affinity)),
            DispatchClass::Affinity => Some((DispatchClass::Affinity, DispatchClass::Normal)),
        },
    }
}

pub fn min_vtime_dispatch_class(
    normal_vtime: Option<u64>,
    affinity_vtime: Option<u64>,
    equal_preference: DispatchClass,
) -> Option<(DispatchClass, DispatchClass)> {
    match (normal_vtime, affinity_vtime) {
        (None, None) => None,
        (Some(_), None) => Some((DispatchClass::Normal, equal_preference)),
        (None, Some(_)) => Some((DispatchClass::Affinity, equal_preference)),
        (Some(normal), Some(affinity)) if vtime_before(normal, affinity) => {
            Some((DispatchClass::Normal, equal_preference))
        }
        (Some(normal), Some(affinity)) if vtime_before(affinity, normal) => {
            Some((DispatchClass::Affinity, equal_preference))
        }
        (Some(_), Some(_)) => match equal_preference {
            DispatchClass::Normal => Some((DispatchClass::Normal, DispatchClass::Affinity)),
            DispatchClass::Affinity => Some((DispatchClass::Affinity, DispatchClass::Normal)),
        },
    }
}

pub fn scale_inverse_weight(delta_ns: u64, weight: u64) -> Result<u64, &'static str> {
    if weight == 0 {
        return Err("weight must be non-zero");
    }
    delta_ns
        .checked_mul(BASE_WEIGHT)
        .map(|scaled| scaled / weight)
        .ok_or("weighted duration overflowed")
}

pub fn advance_virtual_time(
    virtual_time: u64,
    delta_ns: u64,
    runnable_weight: u64,
) -> Result<u64, &'static str> {
    Ok(virtual_time.wrapping_add(scale_inverse_weight(delta_ns, runnable_weight)?))
}

pub fn virtual_deadline(vruntime: u64, weight: u64) -> Result<u64, &'static str> {
    Ok(vruntime.wrapping_add(scale_inverse_weight(EEVDF_SLICE_NS, weight)?))
}

pub fn is_eligible(vruntime: u64, virtual_time: u64) -> bool {
    (vruntime.wrapping_sub(virtual_time) as i64) <= 0
}

pub fn clamp_virtual_lag(lag: i64, virtual_request: u64) -> i64 {
    let limit = i64::try_from(virtual_request).unwrap_or(i64::MAX);
    lag.clamp(-limit, limit)
}

pub fn restore_vruntime(virtual_time: u64, lag: i64) -> u64 {
    if lag >= 0 {
        virtual_time.wrapping_sub(lag as u64)
    } else {
        virtual_time.wrapping_add(lag.unsigned_abs())
    }
}
