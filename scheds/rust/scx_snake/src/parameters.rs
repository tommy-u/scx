// SPDX-License-Identifier: GPL-2.0-only

use serde::{Deserialize, Serialize};

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
pub struct BpfParameters {
    pub callback_timing_sample_rate: u32,
    pub queue_timing_enabled: bool,
    pub fairness: String,
    pub queue_layout: Option<String>,
    pub direct_dispatch: Option<bool>,
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
}
