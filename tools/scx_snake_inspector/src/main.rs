// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::io::IsTerminal;
use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc;
use std::thread;

use anyhow::{Context, Result};
use clap::Parser;
use scx_snake_inspector::api::{router, ApiContext};
use scx_snake_inspector::cli::Args;
use scx_snake_inspector::collector::{run_collector, CollectorCommand, CollectorOptions};
use scx_snake_inspector::dashboard::Dashboard;
use scx_snake_inspector::host_context::HostContextService;
use scx_snake_inspector::launcher::SnakeLauncher;
use scx_snake_inspector::testing::{
    discover_testing_catalog, MatrixConfig, TestingController, TestingExecutionConfig,
};
use scx_snake_inspector::topology::TopologyView;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    args.validate().map_err(anyhow::Error::msg)?;
    let initial_window_ms = args.window_ms().map_err(anyhow::Error::msg)?;
    let max_window_ms = args.max_window_ms().map_err(anyhow::Error::msg)?;

    let topology = TopologyView::discover()?;
    let hostname = hostname_from_environment();
    let host_context = HostContextService::system(hostname.clone(), topology.cpus.len());
    if !args.testing_isolated {
        host_context.spawn_refresh_tasks();
    }
    let dashboard = Dashboard::new(topology, max_window_ms);
    let launcher = SnakeLauncher::new(&args.snake_bin, &args.policy_dir)?;
    let testing = if args.enable_testing {
        let duration_secs = args.testing_duration.as_secs();
        let catalog = discover_testing_catalog(&args.snake_bin, &args.policy_dir)?;
        let matrix = MatrixConfig::new(
            duration_secs,
            args.testing_shard_index,
            args.testing_shard_count,
        )?;
        let matrix = if let Some(fairness) = args.testing_fairness {
            matrix.with_target(
                &catalog,
                fairness,
                args.testing_policy.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("--testing-fairness requires --testing-policy")
                })?,
            )?
        } else {
            matrix
        };
        let controller = TestingController::new(matrix).with_catalog(catalog);
        Some(if !args.testing_import_dir.is_empty() {
            controller.with_import_dirs(&args.testing_import_dir)
        } else {
            controller.with_execution(TestingExecutionConfig::system(
                &args.snake_bin,
                &args.policy_dir,
                &args.testing_artifact_dir,
            ))
        })
    } else {
        None
    };
    let token = session_token()?;
    let (command_tx, command_rx) = mpsc::channel();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let collector = if args.testing_isolated {
        drop(command_rx);
        None
    } else {
        let collector_dashboard = dashboard.clone();
        let collector_options = CollectorOptions {
            policy_dir: args.policy_dir.clone(),
            ..Default::default()
        };
        Some(
            thread::Builder::new()
                .name("snake-migration-collector".into())
                .spawn(move || {
                    let result =
                        run_collector(collector_dashboard.clone(), command_rx, collector_options);
                    if let Err(error) = &result {
                        collector_dashboard.set_collector_health(Some(format!("{error:#}")), 0, 0);
                    }
                    result
                })
                .context("failed to start collector thread")?,
        )
    };

    let mut context = ApiContext::new(
        dashboard,
        command_tx.clone(),
        token,
        "/sys/fs/cgroup".into(),
    )
    .with_initial_window_ms(initial_window_ms)
    .with_launcher(launcher.clone())
    .with_host_context(host_context)
    .with_shutdown(shutdown_rx);
    if let Some(testing) = &testing {
        context = context.with_testing(testing.clone());
    }
    if args.listen.ip().is_unspecified() {
        for host in secure_web_app_allowed_hosts(&hostname) {
            context = context.with_allowed_host(host);
        }
    }
    let listener = TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("failed to bind dashboard to {}", args.listen))?;
    let address = listener.local_addr()?;
    println!(
        "{}",
        startup_message(
            address,
            &ssh_destination_from_environment(),
            std::io::stdout().is_terminal(),
        )
    );

    let graceful_shutdown = async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    };
    let server_result = axum::serve(listener, router(context))
        .with_graceful_shutdown(graceful_shutdown)
        .await;
    if let Some(testing) = testing {
        testing.shutdown();
    }
    launcher.shutdown();
    let _ = command_tx.send(CollectorCommand::Shutdown);
    if let Some(collector) = collector {
        collector
            .join()
            .map_err(|_| anyhow::anyhow!("collector thread panicked"))??;
    }

    server_result.context("dashboard server failed")?;
    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

fn session_token() -> Result<String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).context("failed to generate session token")?;
    let mut token = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut token, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(token)
}

fn startup_message(address: SocketAddr, destination: &str, color: bool) -> String {
    let (inspector_heading, forwarding_heading) = if color {
        (
            "\x1b[1;32mSnake inspector:\x1b[0m",
            "\x1b[1;36mSSH port forwarding:\x1b[0m",
        )
    } else {
        ("Snake inspector:", "SSH port forwarding:")
    };
    format!(
        "{inspector_heading}\nhttp://{address}\n\n{forwarding_heading}\n{}",
        ssh_forwarding_command(address, destination)
    )
}

fn ssh_forwarding_command(address: SocketAddr, destination: &str) -> String {
    let forwarding_host = match address.ip() {
        IpAddr::V4(address) => address.to_string(),
        IpAddr::V6(address) => format!("[{address}]"),
    };
    format!(
        "ssh -N -L {port}:{forwarding_host}:{port} {destination}",
        port = address.port()
    )
}

fn ssh_destination_from_environment() -> String {
    let sudo_user = std::env::var("SUDO_USER").ok();
    let user = std::env::var("USER").ok();
    let hostname = std::env::var("HOSTNAME").ok();
    ssh_destination(sudo_user.as_deref(), user.as_deref(), hostname.as_deref())
}

fn hostname_from_environment() -> String {
    let environment = std::env::var("HOSTNAME").ok();
    let kernel = std::fs::read_to_string("/proc/sys/kernel/hostname").ok();
    resolve_hostname(environment.as_deref(), kernel.as_deref())
}

fn resolve_hostname(environment: Option<&str>, kernel: Option<&str>) -> String {
    environment
        .into_iter()
        .chain(kernel)
        .map(str::trim)
        .find(|hostname| !hostname.is_empty())
        .unwrap_or("localhost")
        .into()
}

fn secure_web_app_hostname(hostname: &str) -> String {
    if hostname.ends_with(".fbinfra.net") {
        return hostname.into();
    }
    let hostname = hostname.strip_suffix(".facebook.com").unwrap_or(hostname);
    format!("{hostname}.fbinfra.net")
}

fn secure_web_app_allowed_hosts(hostname: &str) -> [String; 3] {
    [
        secure_web_app_hostname(hostname),
        hostname.into(),
        "www.edge.x2p.facebook.net".into(),
    ]
}

fn ssh_destination(sudo_user: Option<&str>, user: Option<&str>, hostname: Option<&str>) -> String {
    let user = sudo_user
        .filter(|user| !user.is_empty())
        .or_else(|| user.filter(|user| !user.is_empty()))
        .unwrap_or("<user>");
    let hostname = hostname
        .filter(|hostname| !hostname.is_empty())
        .unwrap_or("<host>");
    format!("{user}@{hostname}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_message_colors_headings_and_isolates_copyable_text() {
        let address = "127.0.0.1:43210".parse().unwrap();

        assert_eq!(
            startup_message(address, "alice@compute.example.com", true),
            concat!(
                "\x1b[1;32mSnake inspector:\x1b[0m\n",
                "http://127.0.0.1:43210\n\n",
                "\x1b[1;36mSSH port forwarding:\x1b[0m\n",
                "ssh -N -L 43210:127.0.0.1:43210 alice@compute.example.com"
            )
        );
    }

    #[test]
    fn startup_message_omits_color_when_output_is_redirected() {
        let address = "127.0.0.1:43210".parse().unwrap();

        assert_eq!(
            startup_message(address, "alice@example.com", false),
            concat!(
                "Snake inspector:\n",
                "http://127.0.0.1:43210\n\n",
                "SSH port forwarding:\n",
                "ssh -N -L 43210:127.0.0.1:43210 alice@example.com"
            )
        );
    }

    #[test]
    fn ssh_destination_prefers_the_user_who_invoked_sudo() {
        assert_eq!(
            ssh_destination(Some("alice"), Some("root"), Some("compute.example.com")),
            "alice@compute.example.com"
        );
    }

    #[test]
    fn secure_web_app_hosts_include_the_x2p_bridge_identity() {
        assert_eq!(
            secure_web_app_allowed_hosts("devbig008.atn3.facebook.com"),
            [
                "devbig008.atn3.fbinfra.net",
                "devbig008.atn3.facebook.com",
                "www.edge.x2p.facebook.net",
            ],
        );
    }

    #[test]
    fn hostname_resolution_uses_the_kernel_name_without_an_environment_value() {
        assert_eq!(
            resolve_hostname(None, Some("devbig008.atn3.facebook.com\n")),
            "devbig008.atn3.facebook.com"
        );
        assert_eq!(
            resolve_hostname(Some(""), Some("host.example\n")),
            "host.example"
        );
        assert_eq!(resolve_hostname(None, Some("\n")), "localhost");
    }
}
