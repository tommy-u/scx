// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::policies::discover_policy_files;

const DEFAULT_OPS_PATH: &str = "/sys/kernel/sched_ext/root/ops";
const STOP_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchFairness {
    Fifo,
    Vtime,
    Eevdf,
}

impl LaunchFairness {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Fifo => "fifo",
            Self::Vtime => "vtime",
            Self::Eevdf => "eevdf",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchRequest {
    pub policy_id: String,
    #[serde(default)]
    pub fairness: Option<LaunchFairness>,
    #[serde(default)]
    pub callback_timing_sample_rate: Option<u32>,
    #[serde(default)]
    pub exit_dump_len: Option<u32>,
    #[serde(default)]
    pub verbose: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct LaunchOptions {
    pub fairness: Option<LaunchFairness>,
    pub callback_timing_sample_rate: Option<u32>,
    pub exit_dump_len: Option<u32>,
    pub verbose: bool,
    pub preserved_args: Vec<String>,
}

impl From<&LaunchRequest> for LaunchOptions {
    fn from(request: &LaunchRequest) -> Self {
        Self {
            fairness: request.fairness,
            callback_timing_sample_rate: request.callback_timing_sample_rate,
            exit_dump_len: request.exit_dump_len,
            verbose: request.verbose,
            preserved_args: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LaunchPolicy {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct LauncherStatus {
    pub managed: bool,
    pub controllable: bool,
    pub control_error: Option<String>,
    pub active: bool,
    pub scheduler_name: Option<String>,
    pub pid: Option<u32>,
    pub uptime_ms: Option<u64>,
    pub current_command: Option<Vec<String>>,
    pub policy_id: Option<String>,
    pub launch: Option<LaunchOptions>,
    pub last_exit: Option<String>,
}

#[derive(Clone)]
pub struct SnakeLauncher {
    inner: Arc<Mutex<Supervisor>>,
}

struct OwnedChild {
    child: Child,
    current_command: Vec<String>,
    request: LaunchRequest,
    executable: PathBuf,
    preserved_args: Vec<String>,
}

struct Supervisor {
    snake_bin: PathBuf,
    policy_dir: PathBuf,
    ops_path: PathBuf,
    proc_root: PathBuf,
    child: Option<OwnedChild>,
    last_exit: Option<String>,
}

impl SnakeLauncher {
    pub fn new(snake_bin: &Path, policy_dir: &Path) -> Result<Self> {
        Self::with_paths(
            snake_bin,
            policy_dir,
            Path::new(DEFAULT_OPS_PATH),
            Path::new("/proc"),
        )
    }

    pub fn with_ops_path(snake_bin: &Path, policy_dir: &Path, ops_path: &Path) -> Result<Self> {
        Self::with_paths(snake_bin, policy_dir, ops_path, Path::new("/proc"))
    }

    pub fn with_paths(
        snake_bin: &Path,
        policy_dir: &Path,
        ops_path: &Path,
        proc_root: &Path,
    ) -> Result<Self> {
        let snake_bin = snake_bin
            .canonicalize()
            .with_context(|| format!("resolving Snake binary {}", snake_bin.display()))?;
        let binary_metadata = fs::metadata(&snake_bin)
            .with_context(|| format!("reading Snake binary {}", snake_bin.display()))?;
        if !binary_metadata.is_file() || binary_metadata.permissions().mode() & 0o111 == 0 {
            bail!(
                "Snake binary {} is not an executable file",
                snake_bin.display()
            );
        }
        let policy_dir = policy_dir
            .canonicalize()
            .with_context(|| format!("resolving policy directory {}", policy_dir.display()))?;
        if !policy_dir.is_dir() {
            bail!("policy path {} is not a directory", policy_dir.display());
        }
        Ok(Self {
            inner: Arc::new(Mutex::new(Supervisor {
                snake_bin,
                policy_dir,
                ops_path: ops_path.to_path_buf(),
                proc_root: proc_root.to_path_buf(),
                child: None,
                last_exit: None,
            })),
        })
    }

    pub fn policies(&self) -> Result<Vec<LaunchPolicy>> {
        let supervisor = self.inner.lock().expect("launcher lock poisoned");
        Ok(discover_policy_files(&supervisor.policy_dir)?
            .into_iter()
            .map(|policy| LaunchPolicy {
                id: policy.id,
                name: policy.name,
            })
            .collect())
    }

    pub fn start(&self, request: LaunchRequest) -> Result<LauncherStatus> {
        let mut supervisor = self.inner.lock().expect("launcher lock poisoned");
        supervisor.refresh_child()?;
        if supervisor.child.is_some() {
            bail!("Snake is already managed by this inspector");
        }
        if let Some(name) = supervisor.attached_scheduler()? {
            bail!("scheduler {name} is already attached");
        }
        let executable = supervisor.snake_bin.clone();
        supervisor.spawn(executable, request, Vec::new())?;
        supervisor.status()
    }

    pub fn restart(&self, request: LaunchRequest) -> Result<LauncherStatus> {
        let mut supervisor = self.inner.lock().expect("launcher lock poisoned");
        supervisor.restart(request)?;
        supervisor.status()
    }

    pub fn status(&self) -> Result<LauncherStatus> {
        self.inner.lock().expect("launcher lock poisoned").status()
    }

    pub fn stop(&self) -> Result<LauncherStatus> {
        let mut supervisor = self.inner.lock().expect("launcher lock poisoned");
        supervisor.refresh_child()?;
        if supervisor.child.is_some() {
            supervisor.stop_owned();
        } else if let Some(name) = supervisor.attached_scheduler()? {
            if !is_snake_scheduler(&name) {
                bail!("attached scheduler {name} is not Snake and cannot be controlled");
            }
            let external = supervisor.external_process()?;
            stop_process(&external)?;
        }
        supervisor.status()
    }

    pub fn shutdown(&self) {
        if let Ok(mut supervisor) = self.inner.lock() {
            supervisor.stop_owned();
        }
    }
}

impl Supervisor {
    fn refresh_child(&mut self) -> Result<()> {
        let status = match self.child.as_mut() {
            Some(owned) => owned.child.try_wait().context("checking managed Snake")?,
            None => None,
        };
        if let Some(status) = status {
            self.last_exit = Some(format_exit(status));
            self.child = None;
        }
        Ok(())
    }

    fn attached_scheduler(&self) -> Result<Option<String>> {
        let name = match fs::read_to_string(&self.ops_path) {
            Ok(name) => name,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("reading scheduler state from {}", self.ops_path.display())
                });
            }
        };
        let name = name.trim();
        Ok((!name.is_empty()).then(|| name.to_owned()))
    }

    fn status(&mut self) -> Result<LauncherStatus> {
        self.refresh_child()?;
        let scheduler_name = self.attached_scheduler()?;
        let external =
            if self.child.is_none() && scheduler_name.as_deref().is_some_and(is_snake_scheduler) {
                Some(self.external_process())
            } else {
                None
            };
        let external_process = external.as_ref().and_then(|result| result.as_ref().ok());
        let control_error = if self.child.is_some() || scheduler_name.is_none() {
            None
        } else if !scheduler_name.as_deref().is_some_and(is_snake_scheduler) {
            Some(format!(
                "attached scheduler {} is not Snake",
                scheduler_name.as_deref().unwrap_or("unknown")
            ))
        } else {
            external
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|error| format!("{error:#}"))
        };
        let child_launch = self.child.as_ref().map(|owned| {
            let mut options = LaunchOptions::from(&owned.request);
            options.preserved_args.clone_from(&owned.preserved_args);
            options
        });
        let external_launch = external_process.map(|process| process.launch.clone());
        let pid = self
            .child
            .as_ref()
            .map(|owned| owned.child.id())
            .or_else(|| external_process.map(|process| process.pid));
        Ok(LauncherStatus {
            managed: self.child.is_some(),
            controllable: self.child.is_some() || external_process.is_some(),
            control_error,
            active: scheduler_name.is_some(),
            scheduler_name,
            pid,
            uptime_ms: pid.and_then(|pid| process_uptime_ms(&self.proc_root, pid)),
            current_command: self
                .child
                .as_ref()
                .map(|owned| owned.current_command.clone())
                .or_else(|| external_process.map(|process| process.current_command.clone())),
            policy_id: self
                .child
                .as_ref()
                .map(|owned| owned.request.policy_id.clone())
                .or_else(|| external_process.and_then(|process| process.policy_id.clone())),
            launch: child_launch.or(external_launch),
            last_exit: self.last_exit.clone(),
        })
    }

    fn restart(&mut self, request: LaunchRequest) -> Result<()> {
        self.refresh_child()?;
        if self.child.is_none() {
            let scheduler = self
                .attached_scheduler()?
                .ok_or_else(|| anyhow::anyhow!("Snake is not running"))?;
            if !is_snake_scheduler(&scheduler) {
                bail!("attached scheduler {scheduler} is not Snake");
            }
        }
        validate_sample_rate(request.callback_timing_sample_rate)?;
        resolve_policy_path(&self.policy_dir, &request.policy_id)?;

        let external = if self.child.is_none() {
            Some(self.external_process()?)
        } else {
            None
        };
        let (executable, preserved_args) = self.child.as_ref().map_or_else(
            || {
                let external = external.as_ref().expect("external process was discovered");
                (
                    external.executable.clone(),
                    external.launch.preserved_args.clone(),
                )
            },
            |owned| (owned.executable.clone(), owned.preserved_args.clone()),
        );
        validate_executable(&executable)?;
        if self.child.is_some() {
            self.stop_owned();
        } else {
            stop_process(external.as_ref().expect("external process was discovered"))?;
        }
        self.spawn(executable, request, preserved_args)
    }

    fn spawn(
        &mut self,
        executable: PathBuf,
        request: LaunchRequest,
        preserved_args: Vec<String>,
    ) -> Result<()> {
        validate_sample_rate(request.callback_timing_sample_rate)?;
        let policy_path = resolve_policy_path(&self.policy_dir, &request.policy_id)?;
        let mut args = launch_args(&request, &policy_path);
        args.extend(preserved_args.iter().cloned());
        let current_command = std::iter::once(executable.to_string_lossy().into_owned())
            .chain(args.iter().cloned())
            .collect();
        let mut command = Command::new(&executable);
        command
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command
            .spawn()
            .with_context(|| format!("starting Snake from {}", executable.display()))?;
        self.last_exit = None;
        self.child = Some(OwnedChild {
            child,
            current_command,
            request,
            executable,
            preserved_args,
        });
        Ok(())
    }

    fn external_process(&self) -> Result<ExternalProcess> {
        let expected_name = self
            .snake_bin
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("configured Snake binary has no filename"))?;
        let mut candidates = Vec::new();
        for entry in fs::read_dir(&self.proc_root)
            .with_context(|| format!("reading process directory {}", self.proc_root.display()))?
        {
            let entry = entry?;
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            let cmdline = match read_cmdline(&entry.path().join("cmdline")) {
                Ok(cmdline) if !cmdline.is_empty() => cmdline,
                _ => continue,
            };
            let matches_name = Path::new(&cmdline[0])
                .file_name()
                .is_some_and(|name| name == expected_name);
            if !matches_name {
                continue;
            }
            let pidfd = open_pidfd(pid)?;
            if read_cmdline(&entry.path().join("cmdline")).ok().as_ref() != Some(&cmdline) {
                continue;
            }
            let executable = fs::read_link(entry.path().join("exe"))
                .with_context(|| format!("reading executable for Snake PID {pid}"))?;
            let (policy_id, launch) = parse_external_launch(&self.policy_dir, &cmdline)?;
            candidates.push(ExternalProcess {
                pid,
                executable,
                current_command: cmdline,
                policy_id,
                launch,
                pidfd,
            });
        }
        match candidates.len() {
            0 => bail!("no scx_snake process matches the attached scheduler"),
            1 => Ok(candidates.pop().expect("one candidate must exist")),
            count => bail!("multiple ({count}) scx_snake processes match the attached scheduler"),
        }
    }

    fn stop_owned(&mut self) {
        let Some(owned) = self.child.as_mut() else {
            return;
        };
        let pid = owned.child.id() as i32;
        if matches!(owned.child.try_wait(), Ok(None)) {
            unsafe {
                libc::kill(-pid, libc::SIGINT);
            }
            let deadline = Instant::now() + STOP_TIMEOUT;
            loop {
                match owned.child.try_wait() {
                    Ok(Some(status)) => {
                        self.last_exit = Some(format_exit(status));
                        break;
                    }
                    Ok(None) if Instant::now() < deadline => {
                        thread::sleep(Duration::from_millis(50));
                    }
                    Ok(None) => {
                        unsafe {
                            libc::kill(-pid, libc::SIGKILL);
                        }
                        self.last_exit = owned.child.wait().ok().map(format_exit);
                        break;
                    }
                    Err(error) => {
                        self.last_exit = Some(format!("wait failed: {error}"));
                        break;
                    }
                }
            }
        }
        self.child = None;
    }
}

fn process_uptime_ms(proc_root: &Path, pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(proc_root.join(pid.to_string()).join("stat")).ok()?;
    let (_, fields) = stat.rsplit_once(')')?;
    let started_ticks = fields.split_whitespace().nth(19)?.parse::<u64>().ok()?;
    let ticks_per_second = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks_per_second <= 0 {
        return None;
    }
    let system_uptime_seconds = fs::read_to_string(proc_root.join("uptime"))
        .ok()?
        .split_whitespace()
        .next()?
        .parse::<f64>()
        .ok()?;
    if !system_uptime_seconds.is_finite() || system_uptime_seconds < 0.0 {
        return None;
    }
    let started_seconds = started_ticks as f64 / ticks_per_second as f64;
    Some(((system_uptime_seconds - started_seconds).max(0.0) * 1_000.0) as u64)
}

struct ExternalProcess {
    pid: u32,
    executable: PathBuf,
    current_command: Vec<String>,
    policy_id: Option<String>,
    launch: LaunchOptions,
    pidfd: OwnedFd,
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        self.stop_owned();
    }
}

fn validate_sample_rate(rate: Option<u32>) -> Result<()> {
    if let Some(rate) = rate {
        if rate != 0 && (!rate.is_power_of_two() || rate > 4096) {
            bail!("callback timing sample rate must be zero or a power of two through 4096");
        }
    }
    Ok(())
}

fn validate_executable(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("reading Snake executable {}", path.display()))?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        bail!("Snake executable {} is not executable", path.display());
    }
    Ok(())
}

fn is_snake_scheduler(name: &str) -> bool {
    name == "snake" || name.starts_with("snake_")
}

fn read_cmdline(path: &Path) -> Result<Vec<String>> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    bytes
        .split(|byte| *byte == 0)
        .filter(|argument| !argument.is_empty())
        .map(|argument| {
            String::from_utf8(argument.to_vec())
                .with_context(|| format!("process argument in {} is not UTF-8", path.display()))
        })
        .collect()
}

fn parse_external_launch(
    policy_dir: &Path,
    cmdline: &[String],
) -> Result<(Option<String>, LaunchOptions)> {
    let mut policy = None;
    let mut launch = LaunchOptions::default();
    let mut index = 1;
    while index < cmdline.len() {
        let argument = &cmdline[index];
        let (name, inline_value) = argument
            .split_once('=')
            .map_or((argument.as_str(), None), |(name, value)| {
                (name, Some(value))
            });
        match name {
            "--policy" => {
                let (value, consumed) = launch_option_value(cmdline, index, inline_value, name)?;
                policy = Some(value.to_owned());
                index += consumed;
            }
            "--fairness" => {
                let (value, consumed) = launch_option_value(cmdline, index, inline_value, name)?;
                launch.fairness = Some(match value {
                    "fifo" => LaunchFairness::Fifo,
                    "vtime" => LaunchFairness::Vtime,
                    "eevdf" => LaunchFairness::Eevdf,
                    other => bail!("unsupported fairness mode {other:?} in external Snake command"),
                });
                index += consumed;
            }
            "--callback-timing-sample-rate" => {
                let (value, consumed) = launch_option_value(cmdline, index, inline_value, name)?;
                launch.callback_timing_sample_rate =
                    Some(value.parse().with_context(|| {
                        format!("invalid callback timing sample rate {value:?}")
                    })?);
                index += consumed;
            }
            "--exit-dump-len" => {
                let (value, consumed) = launch_option_value(cmdline, index, inline_value, name)?;
                launch.exit_dump_len = Some(
                    value
                        .parse()
                        .with_context(|| format!("invalid exit dump length {value:?}"))?,
                );
                index += consumed;
            }
            "--verbose" | "-v" => {
                launch.verbose = true;
                index += 1;
            }
            _ => {
                launch.preserved_args.push(argument.clone());
                index += 1;
            }
        }
    }
    validate_sample_rate(launch.callback_timing_sample_rate)?;
    let policy_id = policy.and_then(|policy| {
        let id = Path::new(&policy).file_name()?.to_str()?;
        policy_dir.join(id).is_file().then(|| id.to_owned())
    });
    Ok((policy_id, launch))
}

fn launch_option_value<'a>(
    cmdline: &'a [String],
    index: usize,
    inline_value: Option<&'a str>,
    option: &str,
) -> Result<(&'a str, usize)> {
    if let Some(value) = inline_value {
        if value.is_empty() {
            bail!("external Snake option {option} has an empty value");
        }
        return Ok((value, 1));
    }
    cmdline
        .get(index + 1)
        .map(|value| (value.as_str(), 2))
        .ok_or_else(|| anyhow::anyhow!("external Snake option {option} is missing its value"))
}

fn open_pidfd(pid: u32) -> Result<OwnedFd> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("opening pidfd for Snake PID {pid}"));
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn stop_process(process: &ExternalProcess) -> Result<()> {
    send_pidfd_signal(&process.pidfd, libc::SIGINT)
        .with_context(|| format!("stopping external Snake PID {}", process.pid))?;
    if wait_pidfd(&process.pidfd, STOP_TIMEOUT)? {
        return Ok(());
    }
    send_pidfd_signal(&process.pidfd, libc::SIGKILL)
        .with_context(|| format!("force-stopping external Snake PID {}", process.pid))?;
    if !wait_pidfd(&process.pidfd, Duration::from_secs(2))? {
        bail!("external Snake PID {} did not exit", process.pid);
    }
    Ok(())
}

fn send_pidfd_signal(pidfd: &OwnedFd, signal: i32) -> Result<()> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result < 0 {
        return Err(std::io::Error::last_os_error()).context("sending pidfd signal");
    }
    Ok(())
}

fn wait_pidfd(pidfd: &OwnedFd, timeout: Duration) -> Result<bool> {
    let milliseconds = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
    let mut pollfd = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let result = unsafe { libc::poll(&mut pollfd, 1, milliseconds) };
        if result > 0 {
            return Ok(true);
        }
        if result == 0 {
            return Ok(false);
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error).context("waiting for Snake process exit");
        }
    }
}

fn resolve_policy_path(root: &Path, id: &str) -> Result<PathBuf> {
    let relative = Path::new(id);
    if relative
        .extension()
        .is_none_or(|extension| extension != "toml")
        || relative.components().count() != 1
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("invalid policy ID {id:?}");
    }
    let candidate = root.join(relative);
    let metadata = fs::symlink_metadata(&candidate)
        .with_context(|| format!("reading policy {}", candidate.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("policy {} is not a regular file", candidate.display());
    }
    let candidate = candidate
        .canonicalize()
        .with_context(|| format!("resolving policy {}", candidate.display()))?;
    if candidate.parent() != Some(root) {
        bail!(
            "policy {} escapes the configured directory",
            candidate.display()
        );
    }
    Ok(candidate)
}

fn launch_args(request: &LaunchRequest, policy: &Path) -> Vec<String> {
    let mut args = vec!["--policy".into(), policy.to_string_lossy().into_owned()];
    if let Some(fairness) = request.fairness {
        args.extend(["--fairness".into(), fairness.as_str().into()]);
    }
    if let Some(rate) = request.callback_timing_sample_rate {
        args.extend(["--callback-timing-sample-rate".into(), rate.to_string()]);
    }
    if let Some(length) = request.exit_dump_len {
        args.extend(["--exit-dump-len".into(), length.to_string()]);
    }
    if request.verbose {
        args.push("--verbose".into());
    }
    args
}

fn format_exit(status: ExitStatus) -> String {
    status
        .code()
        .map_or_else(|| status.to_string(), |code| format!("exit code {code}"))
}
