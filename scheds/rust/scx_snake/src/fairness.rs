// SPDX-License-Identifier: GPL-2.0-only

use clap::ValueEnum;

pub const BASE_WEIGHT: u64 = 100;
pub const EEVDF_SLICE_NS: u64 = 5_000_000;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum)]
pub enum FairnessMode {
    #[default]
    Fifo = 1,
    Eevdf = 2,
}

impl FairnessMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fifo => "fifo",
            Self::Eevdf => "eevdf",
        }
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
