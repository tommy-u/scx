// SPDX-License-Identifier: GPL-2.0-only

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use scx_stats::StatsClient;

use crate::fine_timing::{FineTimingCallback, FineTimingControlResponse};
use crate::inspection::InspectionView;
use crate::parameters::{BpfSliceParameters, UserspaceParameters};
use crate::queue_timing::QueueTimingControlResponse;
use crate::runtime_policy::{PolicyUpdateResponse, PolicyValidationResponse};
use crate::stats::Metrics;
use crate::task_cells::{ThreadCellAssignment, ThreadCellResponse};

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct CallbackTimingRateResponse {
    pub sample_rate: u32,
    pub fine_timing_stopped: bool,
    pub queue_timing_stopped: bool,
}

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct StatsResetResponse {
    pub generation: u64,
    pub active_slot: u32,
    pub reset_at_ms: u64,
    pub fine_timing_stopped: bool,
    pub queue_timing_stopped: bool,
}

const UPDATE_TIMEOUT_MS: u64 = 15_000;

/// Requests serialized through the scheduler's main userspace loop.
#[derive(Debug)]
pub enum SchedulerRequest {
    Metrics,
    Inspect,
    ValidatePolicy {
        source: String,
    },
    ReplacePolicy {
        source: String,
    },
    SetThreadCell(ThreadCellAssignment),
    ClearThreadCell {
        tid: i32,
    },
    SetFineTiming {
        callback: FineTimingCallback,
        enabled: bool,
    },
    SetQueueTiming {
        enabled: bool,
    },
    SetCallbackTimingSampleRate {
        sample_rate: u32,
    },
    SetUserspaceParameters(UserspaceParameters),
    SetBpfSliceParameters(BpfSliceParameters),
    ResetStats,
}

/// Typed responses routed back through the shared stats socket.
#[derive(Debug)]
pub enum SchedulerResponse {
    Metrics(Metrics),
    Inspection(InspectionView),
    PolicyValidation(std::result::Result<PolicyValidationResponse, String>),
    ReplacePolicy(std::result::Result<PolicyUpdateResponse, String>),
    ThreadCell(std::result::Result<ThreadCellResponse, String>),
    FineTiming(std::result::Result<FineTimingControlResponse, String>),
    QueueTiming(std::result::Result<QueueTimingControlResponse, String>),
    CallbackTimingSampleRate(std::result::Result<CallbackTimingRateResponse, String>),
    UserspaceParameters(std::result::Result<UserspaceParameters, String>),
    BpfSliceParameters(std::result::Result<BpfSliceParameters, String>),
    StatsReset(std::result::Result<StatsResetResponse, String>),
}

#[cfg(test)]
pub fn request_userspace_parameters(
    client: &mut StatsClient,
    parameters: &UserspaceParameters,
) -> Result<UserspaceParameters> {
    client.request(
        "stats",
        vec![
            ("target".into(), "userspace_parameters_set".into()),
            (
                "managed_reconcile_ms".into(),
                parameters.managed_reconcile_ms.to_string(),
            ),
            (
                "sample_ms".into(),
                parameters.resizing.sample_ms.to_string(),
            ),
            (
                "threshold_pct".into(),
                parameters.resizing.threshold_pct.to_string(),
            ),
            (
                "cooldown_ms".into(),
                parameters.resizing.cooldown_ms.to_string(),
            ),
            (
                "ewma_alpha".into(),
                parameters.resizing.ewma_alpha.to_string(),
            ),
        ],
    )
}

#[cfg(test)]
pub fn request_stats_reset(client: &mut StatsClient) -> Result<StatsResetResponse> {
    client.request("stats", vec![("target".into(), "stats_reset".into())])
}

#[cfg(test)]
pub fn request_callback_timing_sample_rate(
    client: &mut StatsClient,
    sample_rate: u32,
) -> Result<CallbackTimingRateResponse> {
    client.request(
        "stats",
        vec![
            ("target".into(), "callback_timing_sample_rate_set".into()),
            ("sample_rate".into(), sample_rate.to_string()),
        ],
    )
}

#[cfg(test)]
pub fn request_fine_timing(
    client: &mut StatsClient,
    callback: FineTimingCallback,
    enabled: bool,
) -> Result<FineTimingControlResponse> {
    client.request(
        "stats",
        vec![
            ("target".into(), "fine_timing_set".into()),
            ("callback".into(), callback.as_str().into()),
            ("enabled".into(), enabled.to_string()),
        ],
    )
}

#[cfg(test)]
pub fn request_queue_timing(
    client: &mut StatsClient,
    enabled: bool,
) -> Result<QueueTimingControlResponse> {
    client.request(
        "stats",
        vec![
            ("target".into(), "queue_timing_set".into()),
            ("enabled".into(), enabled.to_string()),
        ],
    )
}

pub fn request_set_thread_cell(
    client: &mut StatsClient,
    assignment: ThreadCellAssignment,
) -> Result<ThreadCellResponse> {
    client.request(
        "stats",
        vec![
            ("target".into(), "thread_cell_set".into()),
            ("tid".into(), assignment.tid.to_string()),
            ("cell_id".into(), assignment.cell_id.to_string()),
        ],
    )
}

pub fn request_clear_thread_cell(client: &mut StatsClient, tid: i32) -> Result<ThreadCellResponse> {
    client.request(
        "stats",
        vec![
            ("target".into(), "thread_cell_clear".into()),
            ("tid".into(), tid.to_string()),
        ],
    )
}

pub fn set_running_thread_cell(assignment: ThreadCellAssignment) -> Result<ThreadCellResponse> {
    let mut client = StatsClient::new()
        .connect(Some(UPDATE_TIMEOUT_MS))
        .context("connecting to the running scx scheduler")?;
    request_set_thread_cell(&mut client, assignment).with_context(|| {
        format!(
            "assigning TID {} to cell {}",
            assignment.tid, assignment.cell_id
        )
    })
}

pub fn clear_running_thread_cell(tid: i32) -> Result<ThreadCellResponse> {
    let mut client = StatsClient::new()
        .connect(Some(UPDATE_TIMEOUT_MS))
        .context("connecting to the running scx scheduler")?;
    request_clear_thread_cell(&mut client, tid)
        .with_context(|| format!("clearing cell annotation for TID {tid}"))
}

pub fn request_policy_update(
    client: &mut StatsClient,
    source: &str,
) -> Result<PolicyUpdateResponse> {
    client.request(
        "stats",
        vec![
            ("target".into(), "policy_update".into()),
            ("source".into(), source.into()),
        ],
    )
}

pub fn update_policy_file(path: &Path) -> Result<PolicyUpdateResponse> {
    let source = fs::read_to_string(path)
        .with_context(|| format!("reading replacement policy {}", path.display()))?;
    let mut client = StatsClient::new()
        .connect(Some(UPDATE_TIMEOUT_MS))
        .context("connecting to the running scx scheduler")?;
    request_policy_update(&mut client, &source)
        .with_context(|| format!("replacing policy with {}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::thread;

    use scx_stats::{StatsClient, StatsServer};

    use super::*;
    use crate::stats;

    const SOURCE: &str = r#"
[[rung]]
operation = "pick_random_idle"
scope = "task_allowed"
"#;

    fn socket_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("snake-{name}-{}.sock", std::process::id()))
    }

    #[test]
    fn policy_update_round_trips_source_and_activation_ack() {
        let path = socket_path("update-ok");
        let server = StatsServer::new(stats::server_data())
            .set_path(&path)
            .launch()
            .expect("test server should launch");
        let (responses, requests) = server.channels();
        let worker = thread::spawn(move || {
            let SchedulerRequest::ReplacePolicy { source } =
                requests.recv().expect("request should arrive")
            else {
                panic!("expected a replacement request");
            };
            assert_eq!(source, SOURCE);
            responses
                .send(SchedulerResponse::ReplacePolicy(Ok(PolicyUpdateResponse {
                    generation: 9,
                    rung_count: 1,
                    mask_table_count: 0,
                    summary: "1 rung, 0 mask tables".into(),
                })))
                .expect("response should send");
        });

        let mut client = StatsClient::new()
            .set_path(&path)
            .connect(Some(1_000))
            .expect("client should connect");
        let response = request_policy_update(&mut client, SOURCE)
            .expect("policy update should be acknowledged");

        assert_eq!(response.generation, 9);
        assert_eq!(response.rung_count, 1);
        worker.join().expect("worker should finish");
        drop(server);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn policy_update_rejection_is_returned_to_the_client() {
        let path = socket_path("update-rejected");
        let server = StatsServer::new(stats::server_data())
            .set_path(&path)
            .launch()
            .expect("test server should launch");
        let (responses, requests) = server.channels();
        let worker = thread::spawn(move || {
            let _ = requests.recv().expect("request should arrive");
            responses
                .send(SchedulerResponse::ReplacePolicy(Err(
                    "invalid replacement".into()
                )))
                .expect("response should send");
        });

        let mut client = StatsClient::new()
            .set_path(&path)
            .connect(Some(1_000))
            .expect("client should connect");
        let error =
            request_policy_update(&mut client, SOURCE).expect_err("rejected update should fail");

        assert!(format!("{error:#}").contains("invalid replacement"));
        worker.join().expect("worker should finish");
        drop(server);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn fine_timing_control_round_trips_callback_and_enabled_state() {
        use crate::fine_timing::{FineTimingCallback, FineTimingControlResponse};

        let path = socket_path("fine-timing");
        let server = StatsServer::new(stats::server_data())
            .set_path(&path)
            .launch()
            .expect("test server should launch");
        let (responses, requests) = server.channels();
        let worker = thread::spawn(move || {
            let SchedulerRequest::SetFineTiming { callback, enabled } =
                requests.recv().expect("request should arrive")
            else {
                panic!("expected a fine timing request");
            };
            assert_eq!(callback, FineTimingCallback::SelectCpu);
            assert!(enabled);
            responses
                .send(SchedulerResponse::FineTiming(Ok(
                    FineTimingControlResponse {
                        callback,
                        enabled,
                        session_id: Some(9),
                    },
                )))
                .expect("response should send");
        });

        let mut client = StatsClient::new()
            .set_path(&path)
            .connect(Some(1_000))
            .expect("client should connect");
        let response = request_fine_timing(&mut client, FineTimingCallback::SelectCpu, true)
            .expect("fine timing update should be acknowledged");

        assert!(response.enabled);
        assert_eq!(response.session_id, Some(9));
        worker.join().expect("worker should finish");
        drop(server);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn queue_timing_control_round_trips_enabled_state() {
        use crate::queue_timing::QueueTimingControlResponse;

        let path = socket_path("queue-timing");
        let server = StatsServer::new(stats::server_data())
            .set_path(&path)
            .launch()
            .expect("test server should launch");
        let (responses, requests) = server.channels();
        let worker = thread::spawn(move || {
            let SchedulerRequest::SetQueueTiming { enabled } =
                requests.recv().expect("request should arrive")
            else {
                panic!("expected a queue timing request");
            };
            assert!(enabled);
            responses
                .send(SchedulerResponse::QueueTiming(Ok(
                    QueueTimingControlResponse {
                        enabled,
                        session_id: Some(17),
                    },
                )))
                .expect("response should send");
        });

        let mut client = StatsClient::new()
            .set_path(&path)
            .connect(Some(1_000))
            .expect("client should connect");
        let response = request_queue_timing(&mut client, true)
            .expect("queue timing update should be acknowledged");

        assert!(response.enabled);
        assert_eq!(response.session_id, Some(17));
        worker.join().expect("worker should finish");
        drop(server);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn callback_timing_rate_control_round_trips_runtime_rate() {
        let path = socket_path("callback-rate");
        let server = StatsServer::new(stats::server_data())
            .set_path(&path)
            .launch()
            .expect("test server should launch");
        let (responses, requests) = server.channels();
        let worker = thread::spawn(move || {
            let SchedulerRequest::SetCallbackTimingSampleRate { sample_rate } =
                requests.recv().expect("request should arrive")
            else {
                panic!("expected a callback timing rate request");
            };
            assert_eq!(sample_rate, 128);
            responses
                .send(SchedulerResponse::CallbackTimingSampleRate(Ok(
                    CallbackTimingRateResponse {
                        sample_rate,
                        fine_timing_stopped: true,
                        queue_timing_stopped: true,
                    },
                )))
                .expect("response should send");
        });

        let mut client = StatsClient::new()
            .set_path(&path)
            .connect(Some(1_000))
            .expect("client should connect");
        let response = request_callback_timing_sample_rate(&mut client, 128)
            .expect("rate update should be acknowledged");

        assert_eq!(response.sample_rate, 128);
        assert!(response.fine_timing_stopped);
        assert!(response.queue_timing_stopped);
        worker.join().expect("worker should finish");
        drop(server);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn stats_reset_round_trips_the_atomic_reset_result() {
        let path = socket_path("stats-reset");
        let server = StatsServer::new(stats::server_data())
            .set_path(&path)
            .launch()
            .expect("test server should launch");
        let (responses, requests) = server.channels();
        let worker = thread::spawn(move || {
            let SchedulerRequest::ResetStats = requests.recv().expect("request should arrive")
            else {
                panic!("expected a statistics reset request");
            };
            responses
                .send(SchedulerResponse::StatsReset(Ok(StatsResetResponse {
                    generation: 9,
                    active_slot: 1,
                    reset_at_ms: 4_200,
                    fine_timing_stopped: true,
                    queue_timing_stopped: true,
                })))
                .expect("response should send");
        });

        let mut client = StatsClient::new()
            .set_path(&path)
            .connect(Some(1_000))
            .expect("client should connect");
        let response = request_stats_reset(&mut client).expect("reset should be acknowledged");

        assert_eq!(
            response,
            StatsResetResponse {
                generation: 9,
                active_slot: 1,
                reset_at_ms: 4_200,
                fine_timing_stopped: true,
                queue_timing_stopped: true,
            }
        );
        worker.join().expect("worker should finish");
        drop(server);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn thread_cell_assignment_round_trips_through_the_control_socket() {
        let path = socket_path("cell-set");
        let server = StatsServer::new(stats::server_data())
            .set_path(&path)
            .launch()
            .expect("test server should launch");
        let (responses, requests) = server.channels();
        let worker = thread::spawn(move || {
            let SchedulerRequest::SetThreadCell(assignment) =
                requests.recv().expect("request should arrive")
            else {
                panic!("expected a thread cell request");
            };
            assert_eq!(assignment.tid, 4812);
            assert_eq!(assignment.cell_id, 7);
            responses
                .send(SchedulerResponse::ThreadCell(Ok(ThreadCellResponse {
                    tid: 4812,
                    cell_id: Some(7),
                    rehome_requested: true,
                })))
                .expect("response should send");
        });

        let mut client = StatsClient::new()
            .set_path(&path)
            .connect(Some(1_000))
            .expect("client should connect");
        let response = request_set_thread_cell(
            &mut client,
            ThreadCellAssignment {
                tid: 4812,
                cell_id: 7,
            },
        )
        .expect("assignment should be acknowledged");

        assert_eq!(response.tid, 4812);
        assert_eq!(response.cell_id, Some(7));
        assert!(response.rehome_requested);
        worker.join().expect("worker should finish");
        drop(server);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn inspection_snapshot_round_trips_through_the_stats_socket() {
        let path = socket_path("inspect");
        let server = StatsServer::new(stats::server_data())
            .set_path(&path)
            .launch()
            .expect("test server should launch");
        let (responses, requests) = server.channels();
        let worker = thread::spawn(move || {
            let SchedulerRequest::Inspect = requests.recv().expect("request should arrive") else {
                panic!("expected an inspection request");
            };
            responses
                .send(SchedulerResponse::Inspection(
                    crate::inspection::InspectionView {
                        schema_version: 1,
                        active_slot: 1,
                        callback_timing_sample_rate: 64,
                        fine_timing: crate::inspection::FineTimingInspectionView::default(),
                        queue_timing: None,
                        parameters: None,
                        fairness: crate::inspection::FairnessInspectionView {
                            mode_name: "fifo".into(),
                            clock_model: "no virtual-time clock".into(),
                        },
                        queue_topology: None,
                        topology_lifecycle: crate::inspection::TopologyLifecycleInspectionView {
                            current_generation: 1,
                            managed: false,
                            transitions: Vec::new(),
                        },
                        slots: Vec::new(),
                        cells: Vec::new(),
                        task_mappings: Vec::new(),
                    },
                ))
                .expect("response should send");
        });

        let mut client = StatsClient::new()
            .set_path(&path)
            .connect(Some(1_000))
            .expect("client should connect");
        let response = client
            .request::<serde_json::Value>("stats", vec![("target".into(), "inspect".into())])
            .expect("inspection should be returned");

        assert_eq!(response["active_slot"], 1);
        assert_eq!(response["slots"], serde_json::json!([]));
        worker.join().expect("worker should finish");
        drop(server);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn policy_validation_round_trips_without_an_activation_request() {
        let path = socket_path("policy-validate");
        let server = StatsServer::new(stats::server_data())
            .set_path(&path)
            .launch()
            .expect("test server should launch");
        let (responses, requests) = server.channels();
        let worker = thread::spawn(move || {
            let SchedulerRequest::ValidatePolicy { source } =
                requests.recv().expect("request should arrive")
            else {
                panic!("expected a policy validation request");
            };
            assert_eq!(source, SOURCE);
            responses
                .send(SchedulerResponse::PolicyValidation(Ok(
                    crate::runtime_policy::PolicyValidationResponse {
                        rung_count: 1,
                        mask_table_count: 0,
                        cell_count: 0,
                        queue_policy: false,
                        summary: "1 rung, 0 mask tables, 0 cells".into(),
                    },
                )))
                .expect("response should send");
        });

        let mut client = StatsClient::new()
            .set_path(&path)
            .connect(Some(1_000))
            .expect("client should connect");
        let response = client
            .request::<serde_json::Value>(
                "stats",
                vec![
                    ("target".into(), "policy_validate".into()),
                    ("source".into(), SOURCE.into()),
                ],
            )
            .expect("validation should be returned");

        assert_eq!(response["rung_count"], 1);
        assert_eq!(response["cell_count"], 0);
        worker.join().expect("worker should finish");
        drop(server);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn userspace_parameter_update_round_trips_effective_values() {
        let path = socket_path("userspace-parameters");
        let server = StatsServer::new(stats::server_data())
            .set_path(&path)
            .launch()
            .expect("test server should launch");
        let (responses, requests) = server.channels();
        let parameters = UserspaceParameters {
            managed_reconcile_ms: 750,
            resizing: crate::parameters::ManagedCellResizingParameters {
                sample_ms: 500,
                threshold_pct: 12.5,
                cooldown_ms: 2_500,
                ewma_alpha: 0.45,
            },
        };
        let expected = parameters.clone();
        let worker = thread::spawn(move || {
            let SchedulerRequest::SetUserspaceParameters(request) =
                requests.recv().expect("request should arrive")
            else {
                panic!("expected a userspace parameter request");
            };
            assert_eq!(request, expected);
            responses
                .send(SchedulerResponse::UserspaceParameters(Ok(request)))
                .expect("response should send");
        });

        let mut client = StatsClient::new()
            .set_path(&path)
            .connect(Some(1_000))
            .expect("client should connect");
        let response = request_userspace_parameters(&mut client, &parameters)
            .expect("userspace parameters should be acknowledged");

        assert_eq!(response, parameters);
        worker.join().expect("worker should finish");
        drop(server);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn bpf_slice_parameter_update_round_trips_effective_values() {
        let path = socket_path("bpf-slice-parameters");
        let server = StatsServer::new(stats::server_data())
            .set_path(&path)
            .launch()
            .expect("test server should launch");
        let (responses, requests) = server.channels();
        let parameters = crate::parameters::BpfSliceParameters {
            vtime_slice_us: 20_000,
            slice_shrinking: crate::parameters::SliceShrinkingParameters {
                enabled: true,
                min_us: 500,
                max_us: 4_000,
                multiplier: 2,
            },
        };
        let expected = parameters.clone();
        let worker = thread::spawn(move || {
            let SchedulerRequest::SetBpfSliceParameters(request) =
                requests.recv().expect("request should arrive")
            else {
                panic!("expected a BPF slice parameter request");
            };
            assert_eq!(request, expected);
            responses
                .send(SchedulerResponse::BpfSliceParameters(Ok(request)))
                .expect("response should send");
        });

        let mut client = StatsClient::new()
            .set_path(&path)
            .connect(Some(1_000))
            .expect("client should connect");
        let response: crate::parameters::BpfSliceParameters = client
            .request(
                "stats",
                vec![
                    ("target".into(), "bpf_slice_parameters_set".into()),
                    ("vtime_slice_us".into(), "20000".into()),
                    ("slice_shrinking_enabled".into(), "true".into()),
                    ("slice_shrink_min_us".into(), "500".into()),
                    ("slice_shrink_max_us".into(), "4000".into()),
                    ("slice_shrink_multiplier".into(), "2".into()),
                ],
            )
            .expect("BPF slice parameters should be acknowledged");

        assert_eq!(response, parameters);
        worker.join().expect("worker should finish");
        drop(server);
        let _ = fs::remove_file(path);
    }
}
