// SPDX-License-Identifier: GPL-2.0-only

use serde::{Deserialize, Serialize};

pub const DEFAULT_VTIME_SLICE_US: u64 = 5_000;
pub const MIN_VTIME_SLICE_US: u64 = 1_000;
pub const DEFAULT_SLICE_SHRINK_MIN_US: u64 = 500;
pub const DEFAULT_SLICE_SHRINK_MAX_US: u64 = 4_000;
pub const DEFAULT_SLICE_SHRINK_MULTIPLIER: u32 = 2;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct ManagedCellResizingParameters {
    pub sample_ms: u64,
    pub threshold_pct: f64,
    pub cooldown_ms: u64,
    pub ewma_alpha: f64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct UserspaceParameters {
    pub managed_reconcile_ms: u64,
    pub resizing: ManagedCellResizingParameters,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SliceShrinkingParameters {
    pub enabled: bool,
    pub min_us: u64,
    pub max_us: u64,
    pub multiplier: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BpfSliceParameters {
    pub vtime_slice_us: u64,
    pub slice_shrinking: SliceShrinkingParameters,
}

impl Default for BpfSliceParameters {
    fn default() -> Self {
        Self {
            vtime_slice_us: DEFAULT_VTIME_SLICE_US,
            slice_shrinking: SliceShrinkingParameters {
                enabled: false,
                min_us: DEFAULT_SLICE_SHRINK_MIN_US,
                max_us: DEFAULT_SLICE_SHRINK_MAX_US,
                multiplier: DEFAULT_SLICE_SHRINK_MULTIPLIER,
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BpfParameters {
    pub callback_timing_sample_rate: u32,
    pub queue_timing_enabled: bool,
    pub fairness: String,
    pub queue_layout: Option<String>,
    pub direct_dispatch: Option<bool>,
    pub vtime_slice_us: u64,
    pub slice_shrinking: SliceShrinkingParameters,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct SchedulerParameters {
    pub userspace: Option<UserspaceParameters>,
    pub bpf: BpfParameters,
}

impl UserspaceParameters {
    pub fn validate(self) -> Result<Self, String> {
        if self.managed_reconcile_ms < 50 {
            return Err("managed_reconcile_ms must be at least 50".into());
        }
        if self.resizing.sample_ms == 0 {
            return Err("sample_ms must be positive".into());
        }
        if !self.resizing.threshold_pct.is_finite() || self.resizing.threshold_pct < 0.0 {
            return Err("threshold_pct must be finite and non-negative".into());
        }
        if self.resizing.cooldown_ms == 0 {
            return Err("cooldown_ms must be positive".into());
        }
        if !self.resizing.ewma_alpha.is_finite()
            || self.resizing.ewma_alpha <= 0.0
            || self.resizing.ewma_alpha > 1.0
        {
            return Err("ewma_alpha must be finite and in (0, 1]".into());
        }
        Ok(self)
    }

    pub fn threshold_milli_pct(&self) -> Result<u32, String> {
        scaled_milli(self.resizing.threshold_pct, "threshold_pct")
    }

    pub fn ewma_alpha_milli(&self) -> Result<u32, String> {
        scaled_milli(self.resizing.ewma_alpha, "ewma_alpha")
    }
}

impl BpfSliceParameters {
    pub fn validate(self) -> Result<Self, String> {
        if self.vtime_slice_us < MIN_VTIME_SLICE_US {
            return Err(format!(
                "vtime_slice_us must be at least {MIN_VTIME_SLICE_US}"
            ));
        }
        if self.slice_shrinking.min_us == 0 {
            return Err("slice shrinking min_us must be positive".into());
        }
        if self.slice_shrinking.max_us <= self.slice_shrinking.min_us {
            return Err("slice shrinking max_us must be greater than min_us".into());
        }
        if self.slice_shrinking.max_us > self.vtime_slice_us {
            return Err("slice shrinking max_us must not exceed vtime_slice_us".into());
        }
        if self.slice_shrinking.multiplier == 0 {
            return Err("slice shrinking multiplier must be positive".into());
        }
        self.vtime_slice_ns()?;
        self.slice_shrink_min_ns()?;
        self.slice_shrink_max_ns()?;
        Ok(self)
    }

    pub fn vtime_slice_ns(&self) -> Result<u64, String> {
        microseconds_to_nanoseconds(self.vtime_slice_us, "vtime_slice_us")
    }

    pub fn slice_shrink_min_ns(&self) -> Result<u64, String> {
        microseconds_to_nanoseconds(self.slice_shrinking.min_us, "min_us")
    }

    pub fn slice_shrink_max_ns(&self) -> Result<u64, String> {
        microseconds_to_nanoseconds(self.slice_shrinking.max_us, "max_us")
    }
}

fn microseconds_to_nanoseconds(value: u64, name: &str) -> Result<u64, String> {
    value
        .checked_mul(1_000)
        .ok_or_else(|| format!("{name} is outside the supported range"))
}

fn scaled_milli(value: f64, name: &str) -> Result<u32, String> {
    let scaled = (value * 1_000.0).round();
    if !scaled.is_finite() || scaled < 0.0 || scaled > f64::from(u32::MAX) {
        return Err(format!("{name} is outside the supported range"));
    }
    Ok(scaled as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> UserspaceParameters {
        UserspaceParameters {
            managed_reconcile_ms: 1_000,
            resizing: ManagedCellResizingParameters {
                sample_ms: 1_000,
                threshold_pct: 20.0,
                cooldown_ms: 5_000,
                ewma_alpha: 0.3,
            },
        }
    }

    #[test]
    fn accepts_operational_managed_cell_parameters() {
        assert_eq!(valid().clone().validate().unwrap(), valid());
    }

    #[test]
    fn rejects_invalid_managed_cell_parameters() {
        let mut cases = Vec::new();

        let mut reconcile = valid();
        reconcile.managed_reconcile_ms = 49;
        cases.push((reconcile, "reconcile_ms"));

        let mut sample = valid();
        sample.resizing.sample_ms = 0;
        cases.push((sample, "sample_ms"));

        let mut threshold = valid();
        threshold.resizing.threshold_pct = f64::NAN;
        cases.push((threshold, "threshold_pct"));

        let mut cooldown = valid();
        cooldown.resizing.cooldown_ms = 0;
        cases.push((cooldown, "cooldown_ms"));

        let mut alpha = valid();
        alpha.resizing.ewma_alpha = 1.1;
        cases.push((alpha, "ewma_alpha"));

        for (parameters, field) in cases {
            let error = parameters.validate().unwrap_err();
            assert!(error.contains(field), "{error}");
        }
    }

    #[test]
    fn accepts_mitosis_slice_parameters() {
        let parameters = BpfSliceParameters {
            vtime_slice_us: 20_000,
            slice_shrinking: SliceShrinkingParameters {
                enabled: true,
                min_us: 500,
                max_us: 4_000,
                multiplier: 2,
            },
        };

        assert_eq!(parameters.clone().validate().unwrap(), parameters);
        assert_eq!(parameters.vtime_slice_ns().unwrap(), 20_000_000);
        assert_eq!(parameters.slice_shrink_min_ns().unwrap(), 500_000);
        assert_eq!(parameters.slice_shrink_max_ns().unwrap(), 4_000_000);
    }

    #[test]
    fn rejects_invalid_slice_parameters() {
        let valid = || BpfSliceParameters {
            vtime_slice_us: 20_000,
            slice_shrinking: SliceShrinkingParameters {
                enabled: true,
                min_us: 500,
                max_us: 4_000,
                multiplier: 2,
            },
        };
        let mut cases = Vec::new();

        let mut zero_slice = valid();
        zero_slice.vtime_slice_us = 0;
        cases.push((zero_slice, "vtime_slice_us"));

        let mut short_slice = valid();
        short_slice.vtime_slice_us = 999;
        short_slice.slice_shrinking.max_us = 900;
        cases.push((short_slice, "vtime_slice_us"));

        let mut zero_min = valid();
        zero_min.slice_shrinking.min_us = 0;
        cases.push((zero_min, "min_us"));

        let mut inverted = valid();
        inverted.slice_shrinking.min_us = 5_000;
        cases.push((inverted, "max_us"));

        let mut above_slice = valid();
        above_slice.slice_shrinking.max_us = 21_000;
        cases.push((above_slice, "vtime_slice_us"));

        let mut zero_multiplier = valid();
        zero_multiplier.slice_shrinking.multiplier = 0;
        cases.push((zero_multiplier, "multiplier"));

        for (parameters, field) in cases {
            let error = parameters.validate().unwrap_err();
            assert!(error.contains(field), "{error}");
        }
    }
}
