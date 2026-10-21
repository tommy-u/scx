// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use scx_mitosis_inspector::api::{router, ApiContext};
use scx_mitosis_inspector::collector::{self, CollectorCommand, CollectorConfig, Snapshot};
use scx_mitosis_inspector::explore::ExploreCollector;
use scx_mitosis_inspector::explore_model::ExploreSnapshot;
use scx_mitosis_inspector::host_context::HostContextView;
use scx_mitosis_inspector::lifecycle::{unix_ms, ObserverContext};
use scx_mitosis_inspector::migration_history::{parse_duration, MigrationHistory};
use scx_mitosis_inspector::parse_callback_timing_sample_rate;
use scx_mitosis_inspector::replay::{ReplayHistory, ReplaySources, REPLAY_RETENTION_MS};
use scx_mitosis_inspector::replay_migrations::ReplayMigrationHistory;
use scx_mitosis_inspector::scheduler_config;
use scx_mitosis_inspector::stats::{self, StatsSnapshot, DEFAULT_STATS_PATH};
use scx_mitosis_inspector::stats_history::StatsHistory;
use scx_mitosis_inspector::system_stats::{self, SystemStatsCollector};

#[derive(Debug, Parser)]
struct Opts {
    /// Address exposed by the inspector HTTP server.
    #[clap(long, default_value = "[::]:44103")]
    listen: SocketAddr,

    /// Mitosis statistics socket.
    #[clap(long, default_value = DEFAULT_STATS_PATH)]
    stats_path: PathBuf,

    /// Initial rolling migration window shown in the heatmap.
    #[clap(long, default_value = "10s", value_parser = parse_duration)]
    window: Duration,

    /// Maximum rolling migration history retained in memory.
    #[clap(long, default_value = "5m", value_parser = parse_duration)]
    max_window: Duration,

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

    /// Do not attach DSQ insert, move, residence, or depth probes.
    #[clap(long)]
    disable_dsq: bool,

    /// Do not attach exact scheduler event counters.
    #[clap(long)]
    disable_scheduler_events: bool,

    /// Do not attach hardirq or softirq probes.
    #[clap(long)]
    disable_irqs: bool,

    /// Do not attach block request issue or completion probes.
    #[clap(long)]
    disable_block_io: bool,

    /// Disable the separate Explore hardware and detailed scheduling collectors.
    #[clap(long)]
    disable_explore: bool,
}

fn run_supervised_worker<T>(
    name: &'static str,
    shutdown: Arc<AtomicBool>,
    exits: tokio::sync::mpsc::Sender<&'static str>,
    worker: impl FnOnce() -> T,
) -> T {
    // Notify before propagating a panic, including when a poisoned lock caused
    // it. Main must stop serving instead of waiting for Ctrl-C to join workers.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(worker));
    if !shutdown.load(Ordering::Relaxed) {
        let _ = exits.try_send(name);
    }
    match result {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let opts = Opts::parse();
    anyhow::ensure!(
        opts.window <= opts.max_window,
        "--window cannot exceed --max-window"
    );
    let migration_window_ms =
        u64::try_from(opts.window.as_millis()).context("initial migration window is too large")?;
    let migration_max_window_ms = u64::try_from(opts.max_window.as_millis())
        .context("maximum migration window is too large")?;
    let migration_history = Arc::new(RwLock::new(MigrationHistory::new(migration_max_window_ms)));
    let host_context = HostContextView::discover().context("discovering host context")?;
    let replay_history = Arc::new(RwLock::new(ReplayHistory::new()));
    let replay_migration_history = Arc::new(RwLock::new(ReplayMigrationHistory::new(
        REPLAY_RETENTION_MS,
        migration_max_window_ms,
        &host_context.topology,
    )));
    let shutdown = Arc::new(AtomicBool::new(false));
    let (worker_exits, mut worker_exit_rx) = tokio::sync::mpsc::channel(5);
    // Bind first: the UI remains available while attachment waits or recovers.
    let listener = tokio::net::TcpListener::bind(opts.listen)
        .await
        .with_context(|| format!("binding inspector to {}", opts.listen))?;
    let observer = Arc::new(RwLock::new(ObserverContext::default()));
    let scheduler_config = Arc::new(RwLock::new(
        scheduler_config::SchedulerConfigSnapshot::default(),
    ));
    let (commands, commands_rx) = mpsc::sync_channel(16);
    let collector_config = CollectorConfig {
        callback_timing_sample_rate: opts.callback_timing_sample_rate,
        event_timing_sample_rate: opts.event_timing_sample_rate,
        enable_dsq: !opts.disable_dsq,
        enable_scheduler_events: !opts.disable_scheduler_events,
        enable_irqs: !opts.disable_irqs,
        enable_block_io: !opts.disable_block_io,
    };
    let state = Arc::new(RwLock::new(Snapshot::empty(collector_config)));
    let collector_state = state.clone();
    let collector_migration_history = migration_history.clone();
    let collector_observer = observer.clone();
    let collector_scheduler_config = scheduler_config.clone();
    let collector_shutdown = shutdown.clone();
    let collector_exits = worker_exits.clone();
    let collector = std::thread::spawn(move || {
        run_supervised_worker(
            "callback collector",
            collector_shutdown.clone(),
            collector_exits,
            || {
                collector::run(
                    collector_state,
                    collector_migration_history,
                    collector_observer,
                    collector_scheduler_config,
                    collector_shutdown,
                    commands_rx,
                    collector_config,
                )
            },
        )
    });

    let stats_state = Arc::new(RwLock::new(StatsSnapshot::default()));
    let stats_history = Arc::new(RwLock::new(StatsHistory::new()));
    let stats_collector_state = stats_state.clone();
    let stats_collector_history = stats_history.clone();
    let stats_shutdown = shutdown.clone();
    let stats_observer = observer.clone();
    let stats_path = opts.stats_path.clone();
    let stats_counters = state.clone();
    let stats_cpu_ids = host_context.topology.numeric_order.clone();
    let stats_exits = worker_exits.clone();
    let stats_collector = std::thread::Builder::new()
        .name("mitosis-stats-collector".into())
        .spawn(move || {
            run_supervised_worker(
                "Mitosis stats collector",
                stats_shutdown.clone(),
                stats_exits,
                || {
                    stats::run(
                        stats_collector_state,
                        stats_collector_history,
                        stats_observer,
                        stats_shutdown,
                        &stats_path,
                        stats_counters,
                        &stats_cpu_ids,
                    )
                },
            )
        })
        .context("starting Mitosis stats collector")?;

    let mut system_collector = SystemStatsCollector::new();
    let system_state = Arc::new(RwLock::new(system_collector.collect()));
    let system_collector_state = system_state.clone();
    let system_shutdown = shutdown.clone();
    let system_observer = observer.clone();
    let system_exits = worker_exits.clone();
    let system_collector = std::thread::Builder::new()
        .name("mitosis-system-collector".into())
        .spawn(move || {
            run_supervised_worker(
                "system stats collector",
                system_shutdown.clone(),
                system_exits,
                || {
                    while !system_shutdown.load(Ordering::Relaxed) {
                        std::thread::sleep(Duration::from_secs(1));
                        let expected = system_observer
                            .read()
                            .expect("observer context lock poisoned")
                            .clone();
                        let sample = system_collector.collect();
                        system_stats::publish_sample(
                            &system_collector_state,
                            &system_observer,
                            &expected,
                            sample,
                        );
                    }
                },
            )
        })
        .context("starting system stats collector")?;

    let replay_counters = state.clone();
    let explore_state = Arc::new(RwLock::new(ExploreSnapshot::default()));
    let explore_collector_state = explore_state.clone();
    let explore_observer = observer.clone();
    let explore_shutdown = shutdown.clone();
    let explore_topology = host_context.topology.clone();
    let explore_disabled = opts.disable_explore;
    let explore_exits = worker_exits.clone();
    let explore_collector = std::thread::Builder::new()
        .name("mitosis-explore-collector".into())
        .spawn(move || {
            run_supervised_worker(
                "Explore collector",
                explore_shutdown.clone(),
                explore_exits,
                || {
                    let mut source =
                        (!explore_disabled).then(|| ExploreCollector::new(explore_topology));
                    let cadence = Duration::from_secs(1);
                    let mut deadline = Instant::now();
                    while !explore_shutdown.load(Ordering::Relaxed) {
                        let expected = explore_observer
                            .read()
                            .expect("observer lock poisoned")
                            .clone();
                        let sample = if let Some(source) = &mut source {
                            source.collect(&expected)
                        } else {
                            let mut sample = ExploreSnapshot::default();
                            sample.collector = expected.clone();
                            for group in sample.groups.values_mut() {
                                group.error =
                                    Some("Explore collection was disabled at startup".into());
                                group.meta.error = group.error.clone();
                            }
                            sample
                        };
                        let mut current_sample = explore_collector_state
                            .write()
                            .expect("Explore lock poisoned");
                        let current = explore_observer.read().expect("observer lock poisoned");
                        if *current == expected {
                            *current_sample = sample;
                        }
                        drop(current);
                        drop(current_sample);
                        deadline += cadence;
                        let now = Instant::now();
                        if deadline <= now {
                            deadline = now + cadence;
                        }
                        std::thread::sleep(deadline.saturating_duration_since(now));
                    }
                },
            )
        })
        .context("starting Explore collector")?;

    let replay_stats = stats_state.clone();
    let replay_system = system_state.clone();
    let replay_config = scheduler_config.clone();
    let replay_observer = observer.clone();
    let replay_state = replay_history.clone();
    let replay_migrations = replay_migration_history.clone();
    let replay_shutdown = shutdown.clone();
    let replay_explore = explore_state.clone();
    let replay_exits = worker_exits.clone();
    let replay_collector = std::thread::Builder::new()
        .name("mitosis-replay-collector".into())
        .spawn(move || {
            run_supervised_worker(
                "replay collector",
                replay_shutdown.clone(),
                replay_exits,
                || {
                    let cadence = Duration::from_secs(1);
                    let mut deadline = Instant::now();
                    while !replay_shutdown.load(Ordering::Relaxed) {
                        // Never retain the observer guard while acquiring source locks:
                        // source writers acquire their source before the observer.
                        let expected = replay_observer
                            .read()
                            .expect("observer lock poisoned")
                            .clone();
                        let counters = replay_counters
                            .read()
                            .expect("snapshot lock poisoned")
                            .compact_clone_without_migrations();
                        let stats = replay_stats
                            .read()
                            .expect("stats snapshot lock poisoned")
                            .clone();
                        let system = replay_system
                            .read()
                            .expect("system snapshot lock poisoned")
                            .clone();
                        let config = replay_config
                            .read()
                            .expect("scheduler config lock poisoned")
                            .clone();
                        let explore = replay_explore
                            .read()
                            .expect("Explore lock poisoned")
                            .clone();
                        let current = replay_observer
                            .read()
                            .expect("observer lock poisoned")
                            .clone();
                        if current == expected {
                            let at_unix_ms = unix_ms();
                            // Derive migration deltas while borrowing the exact source
                            // captured above. The lifetime array never enters replay
                            // snapshots. If it changed, try on the next cadence.
                            {
                                let source =
                                    replay_counters.read().expect("snapshot lock poisoned");
                                if source.meta == counters.meta && source.collector == expected {
                                    replay_migrations
                                        .write()
                                        .expect("replay migration lock poisoned")
                                        .ingest(at_unix_ms, &source);
                                }
                            }
                            // Projection, JSON encoding and compression do not need the
                            // replay ring lock. Only publish after rechecking the epoch.
                            match ReplayHistory::prepare_frame(
                                at_unix_ms,
                                &expected,
                                ReplaySources {
                                    counters,
                                    stats,
                                    system,
                                    config,
                                },
                                Some(explore),
                            ) {
                                Ok(prepared) => {
                                    let mut replay =
                                        replay_state.write().expect("replay history lock poisoned");
                                    // A successful reset may have happened during
                                    // preparation. Hold this guard through publication
                                    // so an old frame cannot enter the cleared ring.
                                    let current =
                                        replay_observer.read().expect("observer lock poisoned");
                                    if *current == expected {
                                        if let Err(error) = replay.record_prepared(prepared) {
                                            eprintln!("Mitosis replay: {error}");
                                        }
                                    }
                                }
                                Err(error) => eprintln!("Mitosis replay: {error}"),
                            }
                        }
                        deadline += cadence;
                        let now = Instant::now();
                        if deadline <= now {
                            // Skip missed deadlines instead of creating burst samples.
                            deadline = now + cadence;
                        }
                        std::thread::sleep(deadline.saturating_duration_since(now));
                    }
                },
            )
        })
        .context("starting replay collector")?;
    drop(worker_exits);

    println!("Mitosis inspector listening on http://{}", opts.listen);
    let context = ApiContext::new(
        state,
        stats_state,
        system_state,
        host_context,
        migration_history,
        migration_window_ms,
        commands.clone(),
        observer,
    )
    .with_stats_history(stats_history)
    .with_scheduler_config_state(scheduler_config)
    .with_replay_state(replay_history, replay_migration_history);
    let context = context.with_explore_state(explore_state);
    let signal_shutdown = shutdown.clone();
    let signal_commands = commands.clone();
    let server = axum::serve(listener, router(context)).with_graceful_shutdown(async move {
        let _ = tokio::signal::ctrl_c().await;
        signal_shutdown.store(true, Ordering::Relaxed);
        let _ = signal_commands.try_send(CollectorCommand::Shutdown);
    });
    let result = tokio::select! {
        result = server => result.context("serving inspector"),
        Some(worker) = worker_exit_rx.recv() => {
            Err(anyhow::anyhow!("{worker} stopped unexpectedly; stopping inspector"))
        }
    };

    shutdown.store(true, Ordering::Relaxed);
    let _ = commands.try_send(CollectorCommand::Shutdown);
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
    let replay_result = replay_collector
        .join()
        .map_err(|_| anyhow::anyhow!("replay collector thread panicked"));
    let explore_result = explore_collector
        .join()
        .map_err(|_| anyhow::anyhow!("Explore collector thread panicked"));
    collector_result?;
    stats_result?;
    system_result?;
    replay_result?;
    explore_result?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn panicked_worker_notifies_the_server_without_waiting_for_join() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let (exits, mut receiver) = tokio::sync::mpsc::channel(1);
        let worker = std::thread::spawn(move || {
            run_supervised_worker("test collector", shutdown, exits, || {
                panic!("controlled worker failure")
            })
        });
        let notification = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
            .await
            .expect("worker failure must wake the server");
        assert_eq!(notification, Some("test collector"));
        assert!(worker.join().is_err());
    }

    #[tokio::test]
    async fn unexpected_worker_return_notifies_the_server_and_preserves_its_result() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let (exits, mut receiver) = tokio::sync::mpsc::channel(1);
        let worker = std::thread::spawn(move || {
            run_supervised_worker("test collector", shutdown, exits, || {
                Err::<(), _>("controlled collection error")
            })
        });
        let notification = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
            .await
            .expect("unexpected worker exit must wake the server");
        assert_eq!(notification, Some("test collector"));
        assert_eq!(worker.join().unwrap(), Err("controlled collection error"));
    }

    #[test]
    fn requested_worker_shutdown_does_not_report_an_unexpected_exit() {
        let shutdown = Arc::new(AtomicBool::new(true));
        let (exits, mut receiver) = tokio::sync::mpsc::channel(1);
        let retained_sender = exits.clone();
        let worker = std::thread::spawn(move || {
            run_supervised_worker("test collector", shutdown, exits, || ())
        });
        worker.join().unwrap();
        assert!(receiver.try_recv().is_err());
        drop(retained_sender);
    }

    #[test]
    fn default_listener_accepts_ipv6_connections() {
        let mut address = Opts::parse_from(["scx_mitosis_inspector"]).listen;
        address.set_port(0);
        let listener = std::net::TcpListener::bind(address).unwrap();
        let endpoint = SocketAddr::new(
            std::net::Ipv6Addr::LOCALHOST.into(),
            listener.local_addr().unwrap().port(),
        );
        std::net::TcpStream::connect_timeout(&endpoint, Duration::from_secs(1))
            .expect("the default listener must accept IPv6 clients");
    }
}
