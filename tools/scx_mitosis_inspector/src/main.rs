// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use scx_mitosis_inspector::api::{router, ApiContext};
use scx_mitosis_inspector::collector::{self, Snapshot};
use scx_mitosis_inspector::host_context::HostContextView;
use scx_mitosis_inspector::stats::{self, StatsSnapshot, DEFAULT_STATS_PATH};
use scx_mitosis_inspector::system_stats::SystemStatsCollector;
use scx_mitosis_inspector::{
    build_callback_timing_rows, build_counters, parse_callback_timing_sample_rate,
    CallbackTimingCounters, CALLBACK_NAMES,
};

#[derive(Debug, Parser)]
struct Opts {
    /// Address exposed by the inspector HTTP server.
    #[clap(long, default_value = "0.0.0.0:44105")]
    listen: SocketAddr,

    /// Mitosis statistics socket.
    #[clap(long, default_value = DEFAULT_STATS_PATH)]
    stats_path: PathBuf,

    /// Sample one in every N callback executions for latency; zero disables it.
    #[clap(
        long,
        default_value_t = 1024,
        value_parser = parse_callback_timing_sample_rate,
        value_name = "N"
    )]
    callback_timing_sample_rate: u32,

    /// Sample one in every N scheduler events for latency; zero disables it.
    #[clap(
        long,
        default_value_t = 64,
        value_parser = parse_callback_timing_sample_rate,
        value_name = "N"
    )]
    event_timing_sample_rate: u32,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();
    let host_context = HostContextView::discover().context("discovering host context")?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let state = Arc::new(RwLock::new(Snapshot {
        scheduler: "scx_mitosis",
        target_program_ids: [0; 5],
        uptime_seconds: 0,
        counters: build_counters([0; 5], [0; 5], Duration::ZERO),
        callback_timing_sample_rate: opts.callback_timing_sample_rate,
        event_timing_sample_rate: opts.event_timing_sample_rate,
        callback_timings: build_callback_timing_rows(&vec![
            CallbackTimingCounters::default();
            CALLBACK_NAMES.len()
        ]),
        scheduler_timings: Vec::new(),
        migrations: Vec::new(),
        cpu_runtime: Vec::new(),
        bpf_program_stats: Vec::new(),
        dsq_metrics: Default::default(),
        scheduler_events: Vec::new(),
    }));
    let (ready_tx, ready_rx) = mpsc::channel();
    let collector_state = state.clone();
    let collector_shutdown = shutdown.clone();
    let callback_timing_sample_rate = opts.callback_timing_sample_rate;
    let event_timing_sample_rate = opts.event_timing_sample_rate;
    let collector = std::thread::spawn(move || {
        collector::run(
            collector_state,
            collector_shutdown,
            ready_tx,
            callback_timing_sample_rate,
            event_timing_sample_rate,
        )
    });

    ready_rx
        .recv_timeout(Duration::from_secs(15))
        .context("collector did not become ready")??;

    let stats_state = Arc::new(RwLock::new(StatsSnapshot::default()));
    let stats_collector_state = stats_state.clone();
    let stats_shutdown = shutdown.clone();
    let stats_path = opts.stats_path.clone();
    let stats_collector = std::thread::Builder::new()
        .name("mitosis-stats-collector".into())
        .spawn(move || stats::run(stats_collector_state, stats_shutdown, &stats_path))
        .context("starting Mitosis stats collector")?;

    let mut system_collector = SystemStatsCollector::new();
    let system_state = Arc::new(RwLock::new(system_collector.collect()));
    let system_collector_state = system_state.clone();
    let system_shutdown = shutdown.clone();
    let system_collector = std::thread::Builder::new()
        .name("mitosis-system-collector".into())
        .spawn(move || {
            while !system_shutdown.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_secs(1));
                *system_collector_state
                    .write()
                    .expect("system snapshot lock poisoned") = system_collector.collect();
            }
        })
        .context("starting system stats collector")?;

    let listener = tokio::net::TcpListener::bind(opts.listen)
        .await
        .with_context(|| format!("binding inspector to {}", opts.listen))?;
    println!("Mitosis inspector listening on http://{}", opts.listen);
    let context = ApiContext::new(state, stats_state, system_state, host_context);
    let server = axum::serve(listener, router(context)).with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    });
    let result = server.await.context("serving inspector");

    shutdown.store(true, Ordering::Relaxed);
    let collector_result = match collector.join() {
        Ok(collector_result) => collector_result.context("callback collector stopped"),
        Err(_) => Err(anyhow::anyhow!("callback collector thread panicked")),
    };
    let stats_result = stats_collector
        .join()
        .map_err(|_| anyhow::anyhow!("Mitosis stats collector thread panicked"));
    let system_result = system_collector
        .join()
        .map_err(|_| anyhow::anyhow!("system stats collector thread panicked"));
    collector_result?;
    stats_result?;
    system_result?;
    result
}
