// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Duration;

use anyhow::{Context, Result};
use scx_stats::StatsClient;
use serde::Serialize;
use serde_json::Value;

pub const DEFAULT_STATS_PATH: &str = "/var/run/scx/root/stats";
const STATS_TIMEOUT_MS: u64 = 1_000;

#[derive(Clone, Debug, Serialize)]
pub struct StatsSnapshot {
    pub metrics: Option<Value>,
    pub error: Option<String>,
}

impl Default for StatsSnapshot {
    fn default() -> Self {
        Self {
            metrics: None,
            error: Some("waiting for Mitosis stats".into()),
        }
    }
}

pub fn run(state: Arc<RwLock<StatsSnapshot>>, shutdown: Arc<AtomicBool>, stats_path: &Path) {
    let mut client = None;

    while !shutdown.load(Ordering::Relaxed) {
        match read_stats(&mut client, stats_path) {
            Ok(metrics) => {
                *state.write().expect("stats snapshot lock poisoned") = StatsSnapshot {
                    metrics: Some(metrics),
                    error: None,
                };
            }
            Err(error) => {
                client = None;
                state.write().expect("stats snapshot lock poisoned").error =
                    Some(format!("{error:#}"));
            }
        }
        thread::sleep(Duration::from_secs(1));
    }
}

fn read_stats(client: &mut Option<StatsClient>, stats_path: &Path) -> Result<Value> {
    if client.is_none() {
        *client = Some(
            StatsClient::new()
                .set_path(stats_path)
                .connect(Some(STATS_TIMEOUT_MS))
                .with_context(|| format!("connecting to {}", stats_path.display()))?,
        );
    }
    client
        .as_mut()
        .context("Mitosis stats client is unavailable")?
        .request("stats", vec![("target".into(), "top".into())])
        .context("reading Mitosis top stats")
}
