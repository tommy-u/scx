// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::fs;
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
}

impl LaunchFairness {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Fifo => "fifo",
            Self::Vtime => "vtime",
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
}

impl From<&LaunchRequest> for LaunchOptions {
    fn from(request: &LaunchRequest) -> Self {
        Self {
            fairness: request.fairness,
            callback_timing_sample_rate: request.callback_timing_sample_rate,
            exit_dump_len: request.exit_dump_len,
            verbose: request.verbose,
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
    pub active: bool,
    pub scheduler_name: Option<String>,
    pub pid: Option<u32>,
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
    request: LaunchRequest,
}

struct Supervisor {
    snake_bin: PathBuf,
    policy_dir: PathBuf,
    ops_path: PathBuf,
    child: Option<OwnedChild>,
    last_exit: Option<String>,
}

impl SnakeLauncher {
    pub fn new(snake_bin: &Path, policy_dir: &Path) -> Result<Self> {
        Self::with_ops_path(snake_bin, policy_dir, Path::new(DEFAULT_OPS_PATH))
    }

    pub fn with_ops_path(snake_bin: &Path, policy_dir: &Path, ops_path: &Path) -> Result<Self> {
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
        validate_sample_rate(request.callback_timing_sample_rate)?;
        let policy_path = resolve_policy_path(&supervisor.policy_dir, &request.policy_id)?;
        let args = launch_args(&request, &policy_path);
        let mut command = Command::new(&supervisor.snake_bin);
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
            .with_context(|| format!("starting Snake from {}", supervisor.snake_bin.display()))?;
        supervisor.last_exit = None;
        supervisor.child = Some(OwnedChild { child, request });
        supervisor.status()
    }

    pub fn status(&self) -> Result<LauncherStatus> {
        self.inner.lock().expect("launcher lock poisoned").status()
    }

    pub fn stop(&self) -> Result<LauncherStatus> {
        let mut supervisor = self.inner.lock().expect("launcher lock poisoned");
        supervisor.refresh_child()?;
        if supervisor.child.is_none() {
            if let Some(name) = supervisor.attached_scheduler()? {
                bail!("scheduler {name} is not managed by this inspector");
            }
            return supervisor.status();
        }
        supervisor.stop_owned();
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
        Ok(LauncherStatus {
            managed: self.child.is_some(),
            active: scheduler_name.is_some(),
            scheduler_name,
            pid: self.child.as_ref().map(|owned| owned.child.id()),
            policy_id: self
                .child
                .as_ref()
                .map(|owned| owned.request.policy_id.clone()),
            launch: self
                .child
                .as_ref()
                .map(|owned| LaunchOptions::from(&owned.request)),
            last_exit: self.last_exit.clone(),
        })
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
