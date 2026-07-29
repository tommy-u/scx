// SPDX-License-Identifier: GPL-2.0-only

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use scx_stats::StatsClient;

use crate::fine_timing::{FineTimingCallback, FineTimingControlResponse};
use crate::inspection::InspectionView;
use crate::runtime_policy::{PolicyUpdateResponse, PolicyValidationResponse};
use crate::stats::Metrics;
use crate::task_cells::{ThreadCellAssignment, ThreadCellResponse};

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
                        fairness: crate::inspection::FairnessInspectionView {
                            mode_name: "fifo".into(),
                            clock_model: "no virtual-time clock".into(),
                        },
                        queue_topology: None,
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
}
