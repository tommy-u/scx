// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateChange {
    None,
    Started,
    Restarted,
    Stopped,
}

#[derive(Debug)]
pub struct SchedulerGate {
    expected_name: String,
    active_seq: Option<u64>,
}

impl SchedulerGate {
    pub fn new(expected_name: impl Into<String>) -> Self {
        Self {
            expected_name: expected_name.into(),
            active_seq: None,
        }
    }

    pub fn observe(&mut self, scheduler_name: &str, enable_seq: u64) -> GateChange {
        if !self.matches(scheduler_name.trim()) {
            return if self.active_seq.take().is_some() {
                GateChange::Stopped
            } else {
                GateChange::None
            };
        }

        match self.active_seq.replace(enable_seq) {
            None => GateChange::Started,
            Some(previous) if previous != enable_seq => GateChange::Restarted,
            Some(_) => GateChange::None,
        }
    }

    pub fn is_active(&self) -> bool {
        self.active_seq.is_some()
    }

    fn matches(&self, scheduler_name: &str) -> bool {
        scheduler_name == self.expected_name
            || scheduler_name
                .strip_prefix(&self.expected_name)
                .is_some_and(|suffix| suffix.starts_with('_'))
    }
}
