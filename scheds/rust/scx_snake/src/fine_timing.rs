// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use serde::{Deserialize, Serialize};

use crate::bpf_intf;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FineTimingCallback {
    SelectCpu,
    Enqueue,
    Dispatch,
}

impl FineTimingCallback {
    pub const ALL: [Self; 3] = [Self::SelectCpu, Self::Enqueue, Self::Dispatch];

    pub const fn index(self) -> usize {
        match self {
            Self::SelectCpu => 0,
            Self::Enqueue => 1,
            Self::Dispatch => 2,
        }
    }

    pub const fn enabled_mask(self) -> u32 {
        match self {
            Self::SelectCpu => bpf_intf::SNAKE_FINE_TIMING_SELECT_CPU,
            Self::Enqueue => bpf_intf::SNAKE_FINE_TIMING_ENQUEUE,
            Self::Dispatch => bpf_intf::SNAKE_FINE_TIMING_DISPATCH,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SelectCpu => "select_cpu",
            Self::Enqueue => "enqueue",
            Self::Dispatch => "dispatch",
        }
    }
}

impl std::str::FromStr for FineTimingCallback {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "select_cpu" => Ok(Self::SelectCpu),
            "enqueue" => Ok(Self::Enqueue),
            "dispatch" => Ok(Self::Dispatch),
            _ => Err(format!("unknown fine timing callback `{value}`")),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FineTimingControlResponse {
    pub callback: FineTimingCallback,
    pub enabled: bool,
    pub session_id: Option<u64>,
}

const SELECT_STAGES: [FineTimingStage; 7] = [
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_SELECT_ACQUIRE_LADDER,
        name: "acquire_ladder",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_SELECT_POLICY_LADDER,
        name: "policy_ladder",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_SELECT_QUEUE_TARGET,
        name: "queue_target",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_SELECT_DIRECT_INSERT,
        name: "direct_insert",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_SELECT_STRICT_PREEMPT,
        name: "strict_preempt",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_SELECT_FALLBACK,
        name: "fallback",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_SELECT_FINISH,
        name: "finish",
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FineTimingStage {
    pub id: u32,
    pub name: &'static str,
}

const ENQUEUE_STAGES: [FineTimingStage; 14] = [
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_ENQUEUE_ACQUIRE_LADDER,
        name: "acquire_ladder",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_ENQUEUE_CANCEL_DIRECT,
        name: "cancel_direct",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_ENQUEUE_PREPARE_RUNNABLE,
        name: "prepare_runnable",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_ENQUEUE_PREPARE_ROUTE_LOOKUP,
        name: "prepare_route_lookup",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_ENQUEUE_PREPARE_TASK_STORAGE,
        name: "prepare_task_storage",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_ENQUEUE_PREPARE_CELL_CLOCK,
        name: "prepare_cell_clock",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_ENQUEUE_PREPARE_CREDIT_CLAMP,
        name: "prepare_credit_clamp",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_ENQUEUE_CELL_VALIDATE,
        name: "cell_validate",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_ENQUEUE_PICK_TARGET,
        name: "pick_target",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_ENQUEUE_NORMAL_DSQ_INSERT,
        name: "normal_dsq_insert",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_ENQUEUE_NORMAL_ACCOUNT_KICK,
        name: "normal_account_kick",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_ENQUEUE_AFFINITY_DSQ_INSERT,
        name: "affinity_dsq_insert",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_ENQUEUE_AFFINITY_PATH,
        name: "affinity_path",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_ENQUEUE_FINISH,
        name: "finish",
    },
];

const DISPATCH_STAGES: [FineTimingStage; 19] = [
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_DISPATCH_ACQUIRE_LADDER,
        name: "acquire_ladder",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_DISPATCH_ROUTE_LOOKUP,
        name: "route_lookup",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_DISPATCH_LOCAL_DSQ_CHECK,
        name: "local_dsq_check",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_DISPATCH_STATE_LOOKUP,
        name: "state_lookup",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_DISPATCH_NORMAL_HEAD_PEEK,
        name: "normal_head_peek",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_DISPATCH_REMOTE_SCAN_1_QUEUE,
        name: "remote_scan_1_queue",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_DISPATCH_REMOTE_SCAN_2_4_QUEUES,
        name: "remote_scan_2_4_queues",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_DISPATCH_REMOTE_SCAN_5_8_QUEUES,
        name: "remote_scan_5_8_queues",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_DISPATCH_REMOTE_SCAN_9_PLUS_QUEUES,
        name: "remote_scan_9_plus_queues",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_DISPATCH_AFFINITY_HEAD_PEEK,
        name: "affinity_head_peek",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_DISPATCH_ARBITRATE,
        name: "arbitrate",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_DISPATCH_KEEP_RUNNING,
        name: "keep_running",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_DISPATCH_MOVE_TO_LOCAL,
        name: "move_to_local_helper",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_DISPATCH_MOVE_NORMAL_SUCCESS,
        name: "move_to_local_normal_success",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_DISPATCH_MOVE_NORMAL_MISS,
        name: "move_to_local_normal_miss",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_DISPATCH_MOVE_AFFINITY_SUCCESS,
        name: "move_to_local_affinity_success",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_DISPATCH_MOVE_AFFINITY_MISS,
        name: "move_to_local_affinity_miss",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_DISPATCH_REPLENISH,
        name: "replenish",
    },
    FineTimingStage {
        id: bpf_intf::snake_fine_timing_stage_SNAKE_FINE_TIMING_DISPATCH_FINISH,
        name: "finish",
    },
];

pub fn stages(callback: FineTimingCallback) -> &'static [FineTimingStage] {
    match callback {
        FineTimingCallback::SelectCpu => &SELECT_STAGES,
        FineTimingCallback::Enqueue => &ENQUEUE_STAGES,
        FineTimingCallback::Dispatch => &DISPATCH_STAGES,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FineTimingSession {
    pub session_id: u64,
    pub policy_generation: u64,
    pub started_at_ms: u64,
    pub stopped_at_ms: Option<u64>,
}

#[derive(Clone, Debug, Default)]
pub struct FineTimingState {
    next_session_id: u64,
    sessions: [Option<FineTimingSession>; 3],
}

impl FineTimingState {
    pub fn start(
        &mut self,
        callback: FineTimingCallback,
        policy_generation: u64,
        started_at_ms: u64,
    ) -> FineTimingSession {
        if let Some(session) = self
            .session(callback)
            .filter(|session| session.stopped_at_ms.is_none())
        {
            return session.clone();
        }
        self.next_session_id = self.next_session_id.wrapping_add(1).max(1);
        let session = FineTimingSession {
            session_id: self.next_session_id,
            policy_generation,
            started_at_ms,
            stopped_at_ms: None,
        };
        self.sessions[callback.index()] = Some(session.clone());
        session
    }

    pub fn stop(&mut self, callback: FineTimingCallback, stopped_at_ms: u64) {
        if let Some(session) = self.sessions[callback.index()].as_mut() {
            session.stopped_at_ms.get_or_insert(stopped_at_ms);
        }
    }

    pub fn clear(&mut self) -> bool {
        let stopped_active_capture = FineTimingCallback::ALL
            .into_iter()
            .any(|callback| self.is_enabled(callback));
        self.sessions = [None, None, None];
        stopped_active_capture
    }

    pub fn session(&self, callback: FineTimingCallback) -> Option<&FineTimingSession> {
        self.sessions[callback.index()].as_ref()
    }

    pub fn is_enabled(&self, callback: FineTimingCallback) -> bool {
        self.session(callback)
            .is_some_and(|session| session.stopped_at_ms.is_none())
    }

    pub fn bpf_config(&self) -> bpf_intf::snake_fine_timing_config {
        let mut config = bpf_intf::snake_fine_timing_config {
            session_ids: [0; 3],
            enabled_mask: 0,
            reserved: 0,
        };
        for callback in FineTimingCallback::ALL {
            let Some(session) = self.session(callback) else {
                continue;
            };
            config.session_ids[callback.index()] = session.session_id;
            if session.stopped_at_ms.is_none() {
                config.enabled_mask |= callback.enabled_mask();
            }
        }
        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clear_discards_active_and_historical_sessions() {
        let mut state = FineTimingState::default();
        let previous = state.start(FineTimingCallback::SelectCpu, 4, 100);
        state.start(FineTimingCallback::Enqueue, 4, 200);
        state.stop(FineTimingCallback::Enqueue, 300);

        let stopped_active_capture = state.clear();

        assert!(stopped_active_capture);
        for callback in FineTimingCallback::ALL {
            assert!(state.session(callback).is_none());
            assert!(!state.is_enabled(callback));
        }
        let config = state.bpf_config();
        assert_eq!(config.enabled_mask, 0);
        assert_eq!(config.session_ids, [0; 3]);
        let next = state.start(FineTimingCallback::SelectCpu, 4, 400);
        assert_ne!(next.session_id, previous.session_id);
    }
}
