// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "scx_snake_inspector", version, about)]
pub struct Args {
    /// Initial rolling window shown in the page.
    #[arg(long, default_value = "10s", value_parser = parse_duration)]
    pub window: Duration,

    /// Maximum rolling history retained in memory.
    #[arg(long, default_value = "5m", value_parser = parse_duration)]
    pub max_window: Duration,

    /// Loopback address, or a wildcard address on HTTP Secure Web Apps ports 44100-44109.
    #[arg(long, default_value = "127.0.0.1:8787", value_parser = parse_listen_address)]
    pub listen: SocketAddr,

    /// Directory containing selectable Snake TOML policies.
    #[arg(long, default_value = "scheds/rust/scx_snake/examples")]
    pub policy_dir: PathBuf,

    /// Snake executable used for scheduler launches from the dashboard.
    #[arg(long, default_value = "target/release/scx_snake")]
    pub snake_bin: PathBuf,

    /// Enable VM-only scheduler matrix execution from the dashboard.
    #[arg(long)]
    pub enable_testing: bool,

    /// Runtime for each scheduler/workload combination.
    #[arg(long, default_value = "60s", value_parser = parse_duration)]
    pub testing_duration: Duration,

    /// Zero-based matrix shard assigned to this inspector.
    #[arg(long, default_value_t = 0)]
    pub testing_shard_index: usize,

    /// Total number of matrix shards.
    #[arg(long, default_value_t = 1)]
    pub testing_shard_count: usize,

    /// Directory where case results and diagnostic logs are retained.
    #[arg(long, default_value = "/tmp/scx-snake-testing")]
    pub testing_artifact_dir: PathBuf,

    /// Read-only campaign directory containing shard-N/run.json files.
    #[arg(long, requires = "enable_testing")]
    pub testing_import_dir: Option<PathBuf>,

    /// Disable unrelated host integrations in dedicated test guests/viewers.
    #[arg(long, requires = "enable_testing")]
    pub testing_isolated: bool,
}

impl Args {
    pub fn validate(&self) -> Result<(), String> {
        if self.window > self.max_window {
            return Err("--window cannot exceed --max-window".into());
        }
        if self.enable_testing && self.testing_duration < Duration::from_secs(60) {
            return Err("--testing-duration must be at least 60s".into());
        }
        if self.enable_testing && self.testing_shard_count == 0 {
            return Err("--testing-shard-count must be greater than zero".into());
        }
        if self.enable_testing && self.testing_shard_index >= self.testing_shard_count {
            return Err("--testing-shard-index must be less than --testing-shard-count".into());
        }
        Ok(())
    }

    pub fn window_ms(&self) -> Result<u64, String> {
        duration_ms(self.window)
    }

    pub fn max_window_ms(&self) -> Result<u64, String> {
        duration_ms(self.max_window)
    }
}

pub fn parse_duration(value: &str) -> Result<Duration, String> {
    let value = value.trim();
    let (number, multiplier) = if let Some(number) = value.strip_suffix("ms") {
        (number, 1_u64)
    } else if let Some(number) = value.strip_suffix('s') {
        (number, 1_000)
    } else if let Some(number) = value.strip_suffix('m') {
        (number, 60_000)
    } else if let Some(number) = value.strip_suffix('h') {
        (number, 3_600_000)
    } else {
        (value, 1_000)
    };
    let number = number
        .parse::<u64>()
        .map_err(|_| format!("invalid duration: {value}"))?;
    let milliseconds = number
        .checked_mul(multiplier)
        .ok_or_else(|| format!("duration is too large: {value}"))?;
    if milliseconds == 0 {
        return Err("duration must be greater than zero".into());
    }
    Ok(Duration::from_millis(milliseconds))
}

pub fn parse_listen_address(value: &str) -> Result<SocketAddr, String> {
    let address = value
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid listen address: {error}"))?;
    if address.ip().is_loopback()
        || (address.ip().is_unspecified() && (44_100..=44_109).contains(&address.port()))
    {
        return Ok(address);
    }
    Err(
        "listen address must be loopback, or wildcard on Secure Web Apps HTTP ports 44100-44109"
            .into(),
    )
}

fn duration_ms(duration: Duration) -> Result<u64, String> {
    u64::try_from(duration.as_millis()).map_err(|_| "duration exceeds u64 milliseconds".into())
}
