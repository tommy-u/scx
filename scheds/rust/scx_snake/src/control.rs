// SPDX-License-Identifier: GPL-2.0-only

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use scx_stats::StatsClient;

use crate::runtime_policy::PolicyUpdateResponse;
use crate::stats::Metrics;

const UPDATE_TIMEOUT_MS: u64 = 15_000;

/// Requests serialized through the scheduler's main userspace loop.
#[derive(Debug)]
pub enum SchedulerRequest {
    Metrics,
    ReplacePolicy { source: String },
}

/// Typed responses routed back through the shared stats socket.
#[derive(Debug)]
pub enum SchedulerResponse {
    Metrics(Metrics),
    ReplacePolicy(std::result::Result<PolicyUpdateResponse, String>),
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
}
