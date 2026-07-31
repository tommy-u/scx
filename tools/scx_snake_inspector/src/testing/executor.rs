// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde::Serialize;

use super::{
    failure_signature, CaseJob, CaseOutcome, Fairness, TestEnvironment, TestRun,
    TestingExecutionConfig, WorkloadCommand,
};

const ATTACH_TIMEOUT: Duration = Duration::from_secs(30);
const STOP_TIMEOUT: Duration = Duration::from_secs(8);
const POLL_INTERVAL: Duration = Duration::from_millis(100);

pub(super) enum ExecutionResult {
    Finished {
        outcome: CaseOutcome,
        elapsed_ms: u64,
    },
    Aborted,
}

#[derive(Serialize)]
struct CaseArtifact<'a> {
    schema_version: u32,
    case_id: &'a str,
    fairness: Fairness,
    policy_id: &'a str,
    workload: super::Workload,
    elapsed_ms: u64,
    passed: bool,
    failure: Option<&'a str>,
}

pub(super) fn preflight(config: &TestingExecutionConfig) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("VM testing requires root privileges");
    }
    if config.require_vm && !inside_vm() {
        bail!("VM testing refuses to run outside a virtual machine");
    }
    if !config.snake_bin.is_file() {
        bail!(
            "Snake binary does not exist: {}",
            config.snake_bin.display()
        );
    }
    if !config.policy_dir.is_dir() {
        bail!(
            "policy directory does not exist: {}",
            config.policy_dir.display()
        );
    }
    for command in ["stress-ng", "taskset", "dmesg"] {
        if !command_available(command) {
            bail!("required testing command is unavailable: {command}");
        }
    }
    let state = fs::read_to_string(&config.sched_ext_state).with_context(|| {
        format!(
            "reading sched_ext state from {}",
            config.sched_ext_state.display()
        )
    })?;
    if state.trim() != "disabled" {
        bail!("sched_ext must be disabled before starting the testing matrix");
    }
    fs::create_dir_all(&config.artifact_dir).with_context(|| {
        format!(
            "creating testing artifact directory {}",
            config.artifact_dir.display()
        )
    })?;
    Ok(())
}

pub(super) fn test_environment(config: &TestingExecutionConfig) -> Result<TestEnvironment> {
    let kernel_release = fs::read_to_string("/proc/sys/kernel/osrelease")
        .context("reading kernel release")?
        .trim()
        .to_owned();
    let output = Command::new(&config.snake_bin)
        .arg("--version")
        .output()
        .context("reading Snake version")?;
    if !output.status.success() {
        bail!("Snake --version exited with {}", output.status);
    }
    let snake_version = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let virtualization = Command::new("systemd-detect-virt")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".into());
    let memory_bytes = fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|meminfo| {
            meminfo.lines().find_map(|line| {
                line.strip_prefix("MemTotal:")?
                    .split_whitespace()
                    .next()?
                    .parse::<u64>()
                    .ok()
            })
        })
        .and_then(|kilobytes| kilobytes.checked_mul(1024))
        .unwrap_or(0);
    let boot_command = std::env::var("SNAKE_TESTING_VM_BOOT_COMMAND")
        .ok()
        .filter(|command| !command.is_empty())
        .or_else(|| fs::read_to_string("/proc/cmdline").ok())
        .map(|command| command.trim().to_owned())
        .unwrap_or_default();
    let mut file = File::open(&config.snake_bin)
        .with_context(|| format!("opening {}", config.snake_bin.display()))?;
    let mut buffer = [0_u8; 64 * 1024];
    let mut hash = 0xcbf29ce484222325_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        for byte in &buffer[..read] {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    Ok(TestEnvironment {
        kernel_release,
        snake_version,
        snake_fingerprint: format!("fnv1a64:{hash:016x}"),
        virtualization,
        cpu_count: available_cpus(),
        memory_bytes,
        boot_command,
    })
}

pub(super) fn persist_run(config: &TestingExecutionConfig, run: &TestRun) -> Result<()> {
    fs::create_dir_all(&config.artifact_dir)?;
    let temporary = config.artifact_dir.join("run.json.tmp");
    let destination = config.artifact_dir.join("run.json");
    let bytes = serde_json::to_vec_pretty(run)?;
    fs::write(&temporary, bytes)?;
    fs::rename(temporary, destination)?;
    Ok(())
}

pub(super) fn execute_case(
    config: &TestingExecutionConfig,
    job: &CaseJob,
    duration_secs: u64,
    stop_requested: &AtomicBool,
) -> ExecutionResult {
    let started = Instant::now();
    let result = execute_case_inner(config, job, duration_secs, stop_requested);
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let execution = match result {
        Ok(()) => ExecutionResult::Finished {
            outcome: CaseOutcome::Passed,
            elapsed_ms,
        },
        Err(_error) if stop_requested.load(Ordering::Acquire) => ExecutionResult::Aborted,
        Err(error) => ExecutionResult::Finished {
            outcome: CaseOutcome::Failed(format!("{error:#}")),
            elapsed_ms,
        },
    };
    let _ = write_case_artifact(config, job, elapsed_ms, &execution);
    execution
}

fn execute_case_inner(
    config: &TestingExecutionConfig,
    job: &CaseJob,
    duration_secs: u64,
    stop_requested: &AtomicBool,
) -> Result<()> {
    let case_dir = config.artifact_dir.join(&job.id);
    fs::create_dir_all(&case_dir)?;
    let policy = config.policy_dir.join(&job.policy_id);
    if !policy.is_file() {
        bail!("policy does not exist: {}", policy.display());
    }
    fs::copy(&policy, case_dir.join("policy.toml"))?;
    let dmesg_before = read_dmesg()?;
    fs::write(case_dir.join("dmesg-before.txt"), &dmesg_before)?;

    let scheduler_log_path = case_dir.join("scheduler.log");
    let scheduler_log = File::create(&scheduler_log_path)?;
    let mut scheduler = Command::new(&config.snake_bin);
    scheduler
        .args([
            "--policy",
            policy.to_string_lossy().as_ref(),
            "--fairness",
            job.fairness.as_str(),
            "--stats",
            "1",
            "--stats-format",
            "json",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::from(scheduler_log.try_clone()?))
        .stderr(Stdio::from(scheduler_log));
    configure_process_group(&mut scheduler);
    let mut scheduler = scheduler.spawn().with_context(|| {
        format!(
            "starting Snake with {} and {:?}",
            job.policy_id, job.fairness
        )
    })?;

    let result = (|| {
        wait_for_attach(config, &mut scheduler, &scheduler_log_path, stop_requested)?;
        let workload = WorkloadCommand::for_workload(job.workload, available_cpus())?;
        fs::write(
            case_dir.join("workload-command.txt"),
            format!("{} {}\n", workload.program, workload.args.join(" ")),
        )?;
        let workload_log = File::create(case_dir.join("workload.log"))?;
        let mut command = Command::new(&workload.program);
        command
            .args(&workload.args)
            .stdin(Stdio::null())
            .stdout(Stdio::from(workload_log.try_clone()?))
            .stderr(Stdio::from(workload_log));
        configure_process_group(&mut command);
        let mut workload = command
            .spawn()
            .with_context(|| format!("starting {:?} workload", job.workload))?;
        let workload_result = monitor_case(
            config,
            &mut scheduler,
            &mut workload,
            Duration::from_secs(duration_secs),
            &dmesg_before,
            &scheduler_log_path,
            stop_requested,
        );
        stop_child_group(&mut workload, libc::SIGTERM, Duration::from_secs(3));
        workload_result
    })();

    stop_child_group(&mut scheduler, libc::SIGINT, STOP_TIMEOUT);
    let final_dmesg = read_dmesg().unwrap_or_default();
    let delta = dmesg_delta(&dmesg_before, &final_dmesg);
    fs::write(case_dir.join("dmesg-new.txt"), &delta)?;
    result?;
    let scheduler_output = fs::read_to_string(&scheduler_log_path)?;
    if let Some(error) = scheduler_stats_failure(&scheduler_output) {
        bail!("scheduler error counters: {error}");
    }
    if let Some(signature) = failure_signature(&delta) {
        bail!("kernel failure: {signature}");
    }
    let state = fs::read_to_string(&config.sched_ext_state)?;
    if state.trim() != "disabled" {
        bail!("sched_ext remained enabled after the case");
    }
    Ok(())
}

fn wait_for_attach(
    config: &TestingExecutionConfig,
    scheduler: &mut Child,
    scheduler_log: &Path,
    stop_requested: &AtomicBool,
) -> Result<()> {
    let deadline = Instant::now() + ATTACH_TIMEOUT;
    loop {
        if stop_requested.load(Ordering::Acquire) {
            bail!("test run stopped while waiting for Snake to attach");
        }
        if let Some(status) = scheduler.try_wait()? {
            bail!(scheduler_exit_message(
                "before attaching",
                status,
                scheduler_log
            ));
        }
        if fs::read_to_string(&config.sched_ext_state).is_ok_and(|state| state.trim() == "enabled")
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("timed out waiting for Snake to attach");
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn monitor_case(
    _config: &TestingExecutionConfig,
    scheduler: &mut Child,
    workload: &mut Child,
    duration: Duration,
    dmesg_before: &str,
    scheduler_log: &Path,
    stop_requested: &AtomicBool,
) -> Result<()> {
    let deadline = Instant::now() + duration;
    let mut next_log_check = Instant::now();
    loop {
        if stop_requested.load(Ordering::Acquire) {
            bail!("test run stopped");
        }
        if let Some(status) = scheduler.try_wait()? {
            bail!(scheduler_exit_message(
                "during workload",
                status,
                scheduler_log
            ));
        }
        if let Some(status) = workload.try_wait()? {
            bail!(
                "workload exited before 60-second window: {}",
                format_status(status)
            );
        }
        let now = Instant::now();
        if now >= deadline {
            return Ok(());
        }
        if now >= next_log_check {
            let dmesg = read_dmesg()?;
            if let Some(signature) = failure_signature(&dmesg_delta(dmesg_before, &dmesg)) {
                bail!("kernel failure: {signature}");
            }
            next_log_check = now + Duration::from_secs(1);
        }
        thread::sleep(POLL_INTERVAL.min(deadline.saturating_duration_since(now)));
    }
}

fn write_case_artifact(
    config: &TestingExecutionConfig,
    job: &CaseJob,
    elapsed_ms: u64,
    execution: &ExecutionResult,
) -> Result<()> {
    let case_dir = config.artifact_dir.join(&job.id);
    fs::create_dir_all(&case_dir)?;
    let (passed, failure) = match execution {
        ExecutionResult::Finished { outcome, .. } => match outcome {
            CaseOutcome::Passed => (true, None),
            CaseOutcome::Failed(failure) => (false, Some(failure.as_str())),
        },
        ExecutionResult::Aborted => (false, Some("aborted")),
    };
    let artifact = CaseArtifact {
        schema_version: 1,
        case_id: &job.id,
        fairness: job.fairness,
        policy_id: &job.policy_id,
        workload: job.workload,
        elapsed_ms,
        passed,
        failure,
    };
    let temporary = case_dir.join("result.json.tmp");
    let destination = case_dir.join("result.json");
    let mut file = File::create(&temporary)?;
    serde_json::to_writer_pretty(&mut file, &artifact)?;
    file.write_all(b"\n")?;
    fs::rename(temporary, destination)?;
    Ok(())
}

fn stop_child_group(child: &mut Child, signal: i32, timeout: Duration) {
    if matches!(child.try_wait(), Ok(None)) {
        unsafe {
            libc::kill(-(child.id() as i32), signal);
        }
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if !matches!(child.try_wait(), Ok(None)) {
                return;
            }
            thread::sleep(POLL_INTERVAL);
        }
        unsafe {
            libc::kill(-(child.id() as i32), libc::SIGKILL);
        }
    }
    let _ = child.wait();
}

fn configure_process_group(command: &mut Command) {
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

fn read_dmesg() -> Result<String> {
    let output = Command::new("dmesg").output().context("running dmesg")?;
    if !output.status.success() {
        bail!("dmesg failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn dmesg_delta(before: &str, after: &str) -> String {
    let before = before.lines().collect::<Vec<_>>();
    let after = after.lines().collect::<Vec<_>>();
    let overlap = (0..=before.len().min(after.len()))
        .rev()
        .find(|overlap| before[before.len() - overlap..] == after[..*overlap])
        .unwrap_or(0);
    after[overlap..].join("\n")
}

fn scheduler_stats_failure(log: &str) -> Option<String> {
    const COUNTERS: [&str; 3] = [
        "invalid_errors",
        "vtime_accounting_errors",
        "eevdf_accounting_errors",
    ];
    let mut maxima = [0_u64; COUNTERS.len()];
    for line in log.lines() {
        let Ok(stats) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        for (index, counter) in COUNTERS.iter().enumerate() {
            if let Some(value) = stats.get(counter).and_then(serde_json::Value::as_u64) {
                maxima[index] = maxima[index].max(value);
            }
        }
    }
    let errors = COUNTERS
        .into_iter()
        .zip(maxima)
        .filter(|(_, value)| *value > 0)
        .map(|(counter, value)| format!("{counter}={value}"))
        .collect::<Vec<_>>();
    (!errors.is_empty()).then(|| errors.join(", "))
}

fn command_available(command: &str) -> bool {
    Command::new("sh")
        .args(["-c", "command -v \"$1\" >/dev/null", "sh", command])
        .status()
        .is_ok_and(|status| status.success())
}

fn inside_vm() -> bool {
    Command::new("systemd-detect-virt")
        .args(["--vm", "--quiet"])
        .status()
        .is_ok_and(|status| status.success())
        || fs::read_to_string("/proc/cpuinfo").is_ok_and(|cpuinfo| {
            cpuinfo
                .split_whitespace()
                .any(|field| field == "hypervisor")
        })
}

fn available_cpus() -> usize {
    thread::available_parallelism().map_or(1, usize::from)
}

fn format_status(status: ExitStatus) -> String {
    status.code().map_or_else(
        || "terminated by signal".into(),
        |code| format!("exit {code}"),
    )
}

fn scheduler_exit_message(phase: &str, status: ExitStatus, scheduler_log: &Path) -> String {
    let detail = fs::read_to_string(scheduler_log).ok().and_then(|log| {
        let mut tail = log
            .lines()
            .filter(|line| !line.trim().is_empty())
            .rev()
            .take(3)
            .collect::<Vec<_>>();
        tail.reverse();
        (!tail.is_empty()).then(|| tail.join(" | "))
    });
    match detail {
        Some(detail) => format!("Snake exited {phase}: {}; {detail}", format_status(status)),
        None => format!("Snake exited {phase}: {}", format_status(status)),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{dmesg_delta, scheduler_stats_failure, ATTACH_TIMEOUT};

    #[test]
    fn attach_timeout_covers_slow_bpf_startup() {
        assert!(ATTACH_TIMEOUT >= Duration::from_secs(30));
    }

    #[test]
    fn dmesg_delta_handles_append_rollover_and_clear() {
        assert_eq!(dmesg_delta("one\ntwo", "one\ntwo\nthree"), "three");
        assert_eq!(dmesg_delta("one\ntwo\nthree", "two\nthree\nfour"), "four");
        assert_eq!(
            dmesg_delta("one\ntwo", "fresh\nmessages"),
            "fresh\nmessages"
        );
    }

    #[test]
    fn scheduler_stats_report_nonzero_error_counters() {
        let clean = r#"not json
{"invalid_errors":0,"vtime_accounting_errors":0,"eevdf_accounting_errors":0}"#;
        assert_eq!(scheduler_stats_failure(clean), None);

        let failed = r#"{"invalid_errors":1,"vtime_accounting_errors":0}
{"invalid_errors":1,"vtime_accounting_errors":2,"eevdf_accounting_errors":0}"#;
        assert_eq!(
            scheduler_stats_failure(failed).as_deref(),
            Some("invalid_errors=1, vtime_accounting_errors=2")
        );
    }
}
