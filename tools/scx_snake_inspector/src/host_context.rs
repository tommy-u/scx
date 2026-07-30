// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::ffi::CString;
use std::fs::File;
use std::future::Future;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::process::Command;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceState {
    Loading,
    Ready,
    Stale,
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SourceView<T> {
    pub state: SourceState,
    pub fetched_at_ms: Option<u64>,
    pub message: Option<String>,
    pub data: T,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SourceStatusView {
    pub state: SourceState,
    pub fetched_at_ms: Option<u64>,
    pub message: Option<String>,
}

#[derive(Clone, Debug)]
struct SourceCache<T> {
    data: T,
    fetched_at_ms: Option<u64>,
    message: Option<String>,
    attempted: bool,
}

impl<T: Clone> SourceCache<T> {
    fn new(data: T) -> Self {
        Self {
            data,
            fetched_at_ms: None,
            message: None,
            attempted: false,
        }
    }

    fn succeed(&mut self, fetched_at_ms: u64, data: T) {
        self.data = data;
        self.fetched_at_ms = Some(fetched_at_ms);
        self.message = None;
        self.attempted = true;
    }

    fn fail(&mut self, _attempted_at_ms: u64, message: impl Into<String>) {
        self.message = Some(message.into());
        self.attempted = true;
    }

    fn view(&self) -> SourceView<T> {
        let state = if self.message.is_some() {
            if self.fetched_at_ms.is_some() {
                SourceState::Stale
            } else {
                SourceState::Unavailable
            }
        } else if self.fetched_at_ms.is_some() {
            SourceState::Ready
        } else if self.attempted {
            SourceState::Unavailable
        } else {
            SourceState::Loading
        };
        SourceView {
            state,
            fetched_at_ms: self.fetched_at_ms,
            message: self.message.clone(),
            data: self.data.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct TupperwareTaskView {
    pub job_handle: String,
    pub task_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HostIdentityView {
    pub hostname: String,
    pub ods_entity: String,
    pub cpu_count: usize,
    pub device_id: Option<String>,
    pub datacenter: Option<String>,
    pub region: Option<String>,
    pub machine_pool: Option<String>,
    pub hardware: Option<String>,
    pub stackable: Option<bool>,
    pub reservation_id: Option<String>,
    pub materialization_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AllotmentView {
    pub uuid: String,
    pub state: String,
    pub ownership: String,
    pub shape: String,
    pub owner: Option<String>,
    pub region: Option<String>,
    pub materialization_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HostChartView {
    pub metric: &'static str,
    pub label: &'static str,
    pub description: &'static str,
    pub state: SourceState,
    pub fetched_at_ms: Option<u64>,
    pub message: Option<String>,
    pub image_url: &'static str,
    pub open_url: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HostContextView {
    pub identity: HostIdentityView,
    pub resource_browser: SourceStatusView,
    pub tupperware: SourceView<Vec<TupperwareTaskView>>,
    pub allotments: SourceView<Vec<AllotmentView>>,
    pub charts: Vec<HostChartView>,
}

#[derive(Deserialize)]
struct RawTask {
    job_handle: String,
    task_id: String,
}

#[derive(Deserialize)]
struct RawHostIdentity {
    host_fqdn: String,
    id: Option<String>,
    datacenter_name: Option<String>,
    region: Option<String>,
    machine_pool: Option<String>,
    logical_server_subtype: Option<String>,
    stackable: Option<String>,
    reservation_entitlement_id: Option<String>,
    reservation_info: Option<String>,
    resource_materialization_id: Option<String>,
}

#[derive(Deserialize)]
struct RawReservationInfo {
    guaranteed: Option<String>,
}

#[derive(Deserialize)]
struct RawAllotment {
    uuid: String,
    state: String,
    ownership_type: String,
    capacity_shape_name: String,
    allocation_owner_id: Option<String>,
    region: Option<String>,
    resource_materialization_id: Option<String>,
}

fn present(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty() && value != "-")
}

pub fn ods_entity(hostname: &str) -> String {
    hostname
        .strip_suffix(".facebook.com")
        .unwrap_or(hostname)
        .to_owned()
}

pub fn parse_tupperware_tasks(output: &str) -> Result<Vec<TupperwareTaskView>, String> {
    if output.trim().is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str::<Vec<RawTask>>(output)
        .map(|tasks| {
            tasks
                .into_iter()
                .map(|task| TupperwareTaskView {
                    job_handle: task.job_handle,
                    task_id: task.task_id,
                })
                .collect()
        })
        .map_err(|error| format!("invalid Tupperware task output: {error}"))
}

pub fn parse_host_identity(output: &str, cpu_count: usize) -> Result<HostIdentityView, String> {
    let mut rows = serde_json::from_str::<Vec<RawHostIdentity>>(output)
        .map_err(|error| format!("invalid Resource Browser host output: {error}"))?;
    let row = rows
        .pop()
        .ok_or_else(|| "host is not present in Resource Browser".to_owned())?;
    let reservation_id = present(row.reservation_entitlement_id).or_else(|| {
        row.reservation_info
            .as_deref()
            .and_then(|value| serde_json::from_str::<RawReservationInfo>(value).ok())
            .and_then(|info| present(info.guaranteed))
    });
    Ok(HostIdentityView {
        ods_entity: ods_entity(&row.host_fqdn),
        hostname: row.host_fqdn,
        cpu_count,
        device_id: present(row.id),
        datacenter: present(row.datacenter_name),
        region: present(row.region),
        machine_pool: present(row.machine_pool),
        hardware: present(row.logical_server_subtype),
        stackable: row
            .stackable
            .as_deref()
            .and_then(|value| value.parse().ok()),
        reservation_id,
        materialization_id: present(row.resource_materialization_id),
    })
}

pub fn parse_allotments(output: &str) -> Result<Vec<AllotmentView>, String> {
    serde_json::from_str::<Vec<RawAllotment>>(output)
        .map(|rows| {
            rows.into_iter()
                .map(|row| AllotmentView {
                    uuid: row.uuid,
                    state: row.state,
                    ownership: row.ownership_type,
                    shape: row.capacity_shape_name,
                    owner: present(row.allocation_owner_id),
                    region: present(row.region),
                    materialization_id: present(row.resource_materialization_id),
                })
                .collect()
        })
        .map_err(|error| format!("invalid Resource Browser allotment output: {error}"))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandInvocation {
    pub program: String,
    pub args: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandOutput {
    pub stdout: Vec<u8>,
}

impl CommandOutput {
    pub fn text(output: &str) -> Self {
        Self {
            stdout: output.as_bytes().to_vec(),
        }
    }

    fn stdout_text(&self) -> Result<&str, String> {
        std::str::from_utf8(&self.stdout)
            .map_err(|error| format!("command output is not UTF-8: {error}"))
    }
}

pub type CommandFuture<'a> =
    Pin<Box<dyn Future<Output = Result<CommandOutput, String>> + Send + 'a>>;

pub trait CommandRunner: Send + Sync {
    fn run<'a>(&'a self, invocation: CommandInvocation, timeout: Duration) -> CommandFuture<'a>;
}

#[derive(Default)]
pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run<'a>(&'a self, invocation: CommandInvocation, timeout: Duration) -> CommandFuture<'a> {
        Box::pin(async move {
            let mut command = Command::new(&invocation.program);
            command
                .args(&invocation.args)
                .kill_on_drop(true)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let output = tokio::time::timeout(timeout, command.output())
                .await
                .map_err(|_| format!("{} timed out", invocation.program))?
                .map_err(|error| format!("cannot run {}: {error}", invocation.program))?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let detail = stderr
                    .lines()
                    .find(|line| !line.trim().is_empty())
                    .unwrap_or("command failed");
                return Err(format!(
                    "{} exited with {}: {}",
                    invocation.program,
                    output.status,
                    truncate_message(detail)
                ));
            }
            Ok(CommandOutput {
                stdout: output.stdout,
            })
        })
    }
}

fn truncate_message(message: &str) -> String {
    message.chars().take(240).collect()
}

pub fn process_invocation(
    program: &str,
    args: &[String],
    sudo_user: Option<&str>,
) -> CommandInvocation {
    if let Some(user) = sudo_user.filter(|user| !user.is_empty() && *user != "root") {
        let mut wrapped = vec![
            "-n".into(),
            "-u".into(),
            user.into(),
            "--".into(),
            program.into(),
        ];
        wrapped.extend_from_slice(args);
        CommandInvocation {
            program: "sudo".into(),
            args: wrapped,
        }
    } else {
        CommandInvocation {
            program: program.into(),
            args: args.to_vec(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChartMetric {
    CpuPressure,
    SchedulerDelay,
}

impl ChartMetric {
    pub fn slug(self) -> &'static str {
        match self {
            Self::CpuPressure => "cpu-pressure",
            Self::SchedulerDelay => "scheduler-delay",
        }
    }

    pub fn from_slug(slug: &str) -> Option<Self> {
        match slug {
            "cpu-pressure" => Some(Self::CpuPressure),
            "scheduler-delay" => Some(Self::SchedulerDelay),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::CpuPressure => "CPU pressure",
            Self::SchedulerDelay => "Scheduling delay",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::CpuPressure => {
                "Host-wide PSI some: percent of time at least one runnable task lacked CPU."
            }
            Self::SchedulerDelay => {
                "Host-wide aggregate run-queue wait in milliseconds per second; not per-task latency."
            }
        }
    }

    pub fn key(self) -> &'static str {
        match self {
            Self::CpuPressure => "os.pressure.cpu.some",
            Self::SchedulerDelay => "dyno.cpu_delay_total_ms",
        }
    }

    pub fn transform(self) -> &'static str {
        "avg(5m)"
    }

    pub fn window(self) -> &'static str {
        "3_h"
    }

    fn image_url(self) -> &'static str {
        match self {
            Self::CpuPressure => "/api/host-charts/cpu-pressure.png",
            Self::SchedulerDelay => "/api/host-charts/scheduler-delay.png",
        }
    }

    fn open_url(self) -> &'static str {
        match self {
            Self::CpuPressure => "/api/host-charts/cpu-pressure/open",
            Self::SchedulerDelay => "/api/host-charts/scheduler-delay/open",
        }
    }
}

struct HostContextData {
    identity: HostIdentityView,
    resource_browser: SourceCache<()>,
    tupperware: SourceCache<Vec<TupperwareTaskView>>,
    allotments: SourceCache<Vec<AllotmentView>>,
    cpu_pressure: SourceCache<Vec<u8>>,
    scheduler_delay: SourceCache<Vec<u8>>,
}

impl HostContextData {
    fn chart(&self, metric: ChartMetric) -> &SourceCache<Vec<u8>> {
        match metric {
            ChartMetric::CpuPressure => &self.cpu_pressure,
            ChartMetric::SchedulerDelay => &self.scheduler_delay,
        }
    }

    fn chart_mut(&mut self, metric: ChartMetric) -> &mut SourceCache<Vec<u8>> {
        match metric {
            ChartMetric::CpuPressure => &mut self.cpu_pressure,
            ChartMetric::SchedulerDelay => &mut self.scheduler_delay,
        }
    }
}

#[derive(Clone)]
pub struct HostContextService {
    hostname: Arc<str>,
    cpu_count: usize,
    sudo_user: Option<Arc<str>>,
    runner: Arc<dyn CommandRunner>,
    command_gate: Arc<tokio::sync::Mutex<()>>,
    data: Arc<RwLock<HostContextData>>,
}

impl HostContextService {
    pub fn system(hostname: impl Into<String>, cpu_count: usize) -> Self {
        let sudo_user = std::env::var("SUDO_USER")
            .ok()
            .filter(|user| !user.is_empty() && user != "root");
        Self::with_runner(
            hostname,
            cpu_count,
            sudo_user,
            Arc::new(SystemCommandRunner),
        )
    }

    pub fn with_runner(
        hostname: impl Into<String>,
        cpu_count: usize,
        sudo_user: Option<String>,
        runner: Arc<dyn CommandRunner>,
    ) -> Self {
        let hostname = hostname.into();
        let identity = HostIdentityView {
            ods_entity: ods_entity(&hostname),
            hostname: hostname.clone(),
            cpu_count,
            device_id: None,
            datacenter: None,
            region: None,
            machine_pool: None,
            hardware: None,
            stackable: None,
            reservation_id: None,
            materialization_id: None,
        };
        Self {
            hostname: hostname.into(),
            cpu_count,
            sudo_user: sudo_user.map(Into::into),
            runner,
            command_gate: Arc::new(tokio::sync::Mutex::new(())),
            data: Arc::new(RwLock::new(HostContextData {
                identity,
                resource_browser: SourceCache::new(()),
                tupperware: SourceCache::new(Vec::new()),
                allotments: SourceCache::new(Vec::new()),
                cpu_pressure: SourceCache::new(Vec::new()),
                scheduler_delay: SourceCache::new(Vec::new()),
            })),
        }
    }

    pub fn snapshot(&self) -> HostContextView {
        let data = self.data.read().expect("host context lock poisoned");
        let resource_browser = data.resource_browser.view();
        HostContextView {
            identity: data.identity.clone(),
            resource_browser: SourceStatusView {
                state: resource_browser.state,
                fetched_at_ms: resource_browser.fetched_at_ms,
                message: resource_browser.message,
            },
            tupperware: data.tupperware.view(),
            allotments: data.allotments.view(),
            charts: [ChartMetric::CpuPressure, ChartMetric::SchedulerDelay]
                .into_iter()
                .map(|metric| {
                    let view = data.chart(metric).view();
                    HostChartView {
                        metric: metric.slug(),
                        label: metric.label(),
                        description: metric.description(),
                        state: view.state,
                        fetched_at_ms: view.fetched_at_ms,
                        message: view.message,
                        image_url: metric.image_url(),
                        open_url: metric.open_url(),
                    }
                })
                .collect(),
        }
    }

    fn invocation(&self, program: &str, args: Vec<String>) -> CommandInvocation {
        process_invocation(program, &args, self.sudo_user.as_deref())
    }

    async fn run_command(
        &self,
        invocation: CommandInvocation,
        timeout: Duration,
    ) -> Result<CommandOutput, String> {
        let _guard = self.command_gate.lock().await;
        self.runner.run(invocation, timeout).await
    }

    pub async fn refresh_metadata(&self, now_ms: u64) {
        self.refresh_tupperware(now_ms).await;
        self.refresh_resource_browser(now_ms).await;
    }

    pub async fn refresh_tupperware(&self, now_ms: u64) {
        let args = vec![
            "tupperware.host".into(),
            "resolve".into(),
            format!("--hostname={}", self.hostname),
            "--output=json".into(),
            "--no-truncate".into(),
        ];
        let result = self
            .run_command(self.invocation("meta", args), Duration::from_secs(10))
            .await
            .and_then(|output| parse_tupperware_tasks(output.stdout_text()?));
        let mut data = self.data.write().expect("host context lock poisoned");
        match result {
            Ok(tasks) => data.tupperware.succeed(now_ms, tasks),
            Err(error) => data.tupperware.fail(now_ms, truncate_message(&error)),
        }
    }

    pub async fn refresh_resource_browser(&self, now_ms: u64) {
        let args = vec![
            "search".into(),
            format!("--match=host_fqdn={}", self.hostname),
            "--show=id".into(),
            "--show=host_fqdn".into(),
            "--show=datacenter_name".into(),
            "--show=region".into(),
            "--show=logical_server_subtype".into(),
            "--show=machine_pool".into(),
            "--show=stackable".into(),
            "--show=reservation_entitlement_id".into(),
            "--show=reservation_info".into(),
            "--show=resource_materialization_id".into(),
            "--json".into(),
            "--limit=1".into(),
        ];
        let identity = self
            .run_command(self.invocation("rbcli", args), Duration::from_secs(15))
            .await
            .and_then(|output| parse_host_identity(output.stdout_text()?, self.cpu_count));
        let identity = match identity {
            Ok(identity) => {
                let mut data = self.data.write().expect("host context lock poisoned");
                data.identity = identity.clone();
                data.resource_browser.succeed(now_ms, ());
                identity
            }
            Err(error) => {
                let message = truncate_message(&error);
                let mut data = self.data.write().expect("host context lock poisoned");
                data.resource_browser.fail(now_ms, message.clone());
                data.allotments.fail(now_ms, message);
                return;
            }
        };

        let Some(device_id) = identity.device_id else {
            self.data
                .write()
                .expect("host context lock poisoned")
                .allotments
                .fail(now_ms, "Resource Browser device ID unavailable");
            return;
        };
        let args = vec![
            "search".into(),
            "--target=allotments_table".into(),
            format!("--match=device_id={device_id}"),
            "--show=uuid".into(),
            "--show=state".into(),
            "--show=ownership_type".into(),
            "--show=capacity_shape_name".into(),
            "--show=resource_materialization_id".into(),
            "--show=allocation_owner_id".into(),
            "--show=region".into(),
            "--json".into(),
            "--limit=100".into(),
        ];
        let result = self
            .run_command(self.invocation("rbcli", args), Duration::from_secs(15))
            .await
            .and_then(|output| parse_allotments(output.stdout_text()?));
        let mut data = self.data.write().expect("host context lock poisoned");
        match result {
            Ok(allotments) => data.allotments.succeed(now_ms, allotments),
            Err(error) => data.allotments.fail(now_ms, truncate_message(&error)),
        }
    }

    pub async fn refresh_chart(&self, metric: ChartMetric, now_ms: u64) {
        let result = self.generate_chart(metric).await;
        let mut data = self.data.write().expect("host context lock poisoned");
        match result {
            Ok(image) => data.chart_mut(metric).succeed(now_ms, image),
            Err(error) => data
                .chart_mut(metric)
                .fail(now_ms, truncate_message(&error)),
        }
    }

    async fn generate_chart(&self, metric: ChartMetric) -> Result<Vec<u8>, String> {
        let directory = tempfile::Builder::new()
            .prefix("scx-snake-ods-")
            .tempdir()
            .map_err(|error| format!("cannot create ODS chart directory: {error}"))?;
        let directory_handle = File::open(directory.path())
            .map_err(|error| format!("cannot open ODS chart directory: {error}"))?;
        let output_owner = prepare_chart_directory(&directory_handle, self.sudo_user.as_deref())?;
        let path = directory
            .path()
            .join("chart.png")
            .to_string_lossy()
            .into_owned();
        let args = chart_args(
            metric,
            &self
                .data
                .read()
                .expect("host context lock poisoned")
                .identity
                .ods_entity,
        )
        .into_iter()
        .chain([
            "--image".into(),
            path.clone(),
            "--image_size=1200x360".into(),
        ])
        .collect();
        self.run_command(self.invocation("ods", args), Duration::from_secs(20))
            .await?;
        read_chart_png(directory_handle.as_raw_fd(), output_owner)
    }

    pub fn chart_png(&self, metric: ChartMetric) -> Option<Vec<u8>> {
        self.chart_payload(metric).map(|(_, bytes)| bytes)
    }

    pub fn chart_payload(&self, metric: ChartMetric) -> Option<(u64, Vec<u8>)> {
        let data = self.data.read().expect("host context lock poisoned");
        let chart = data.chart(metric);
        chart
            .fetched_at_ms
            .map(|revision| (revision, chart.data.clone()))
    }

    pub async fn fresh_chart_url(&self, metric: ChartMetric) -> Result<String, String> {
        let ods_entity = self
            .data
            .read()
            .expect("host context lock poisoned")
            .identity
            .ods_entity
            .clone();
        let args = chart_args(metric, &ods_entity)
            .into_iter()
            .chain(["--fburlonly".into()])
            .collect();
        let output = self
            .run_command(self.invocation("ods", args), Duration::from_secs(20))
            .await?;
        let url = output.stdout_text()?.trim();
        if !(url.starts_with("https://fburl.com/")
            || url.starts_with("https://www.internalfb.com/"))
        {
            return Err("ODS returned an invalid chart URL".into());
        }
        Ok(url.to_owned())
    }

    pub fn spawn_refresh_tasks(&self) {
        let metadata = self.clone();
        tokio::spawn(async move {
            loop {
                metadata.refresh_tupperware(unix_time_ms()).await;
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });
        let resource_browser = self.clone();
        tokio::spawn(async move {
            loop {
                resource_browser
                    .refresh_resource_browser(unix_time_ms())
                    .await;
                tokio::time::sleep(Duration::from_secs(300)).await;
            }
        });
        for metric in [ChartMetric::CpuPressure, ChartMetric::SchedulerDelay] {
            let charts = self.clone();
            tokio::spawn(async move {
                loop {
                    charts.refresh_chart(metric, unix_time_ms()).await;
                    tokio::time::sleep(Duration::from_secs(120)).await;
                }
            });
        }
    }
}

const PNG_SIGNATURE: &[u8; 8] = b"\x89PNG\r\n\x1a\n";
const MAX_CHART_BYTES: u64 = 32 * 1024 * 1024;

fn prepare_chart_directory(
    directory: &File,
    sudo_user: Option<&str>,
) -> Result<libc::uid_t, String> {
    let effective_uid = unsafe { libc::geteuid() };
    let effective_gid = unsafe { libc::getegid() };
    let (owner_uid, owner_gid) = if effective_uid == 0 {
        match sudo_user {
            Some(user) => lookup_user(user)?,
            None => (effective_uid, effective_gid),
        }
    } else {
        (effective_uid, effective_gid)
    };
    let result = unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) };
    if result != 0 {
        return Err(format!(
            "cannot make ODS chart directory private: {}",
            std::io::Error::last_os_error()
        ));
    }
    if (owner_uid, owner_gid) != (effective_uid, effective_gid) {
        let result = unsafe { libc::fchown(directory.as_raw_fd(), owner_uid, owner_gid) };
        if result != 0 {
            return Err(format!(
                "cannot assign ODS chart directory to {sudo_user:?}: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(owner_uid)
}

fn lookup_user(user: &str) -> Result<(libc::uid_t, libc::gid_t), String> {
    let user = CString::new(user).map_err(|_| "SUDO_USER contains a NUL byte".to_owned())?;
    let suggested = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut capacity = if suggested > 0 {
        suggested as usize
    } else {
        16 * 1024
    };
    loop {
        let mut entry = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut result = std::ptr::null_mut();
        let mut buffer = vec![0_u8; capacity];
        let status = unsafe {
            libc::getpwnam_r(
                user.as_ptr(),
                entry.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE && capacity < 1024 * 1024 {
            capacity *= 2;
            continue;
        }
        if status != 0 {
            return Err(format!(
                "cannot resolve SUDO_USER: {}",
                std::io::Error::from_raw_os_error(status)
            ));
        }
        if result.is_null() {
            return Err("SUDO_USER does not name a local account".into());
        }
        let entry = unsafe { entry.assume_init() };
        return Ok((entry.pw_uid, entry.pw_gid));
    }
}

fn read_chart_png(directory: RawFd, expected_uid: libc::uid_t) -> Result<Vec<u8>, String> {
    let descriptor = unsafe {
        libc::openat(
            directory,
            b"chart.png\0".as_ptr().cast(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(format!(
            "cannot open ODS chart image safely: {}",
            std::io::Error::last_os_error()
        ));
    }
    let file = unsafe { File::from_raw_fd(descriptor) };
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect ODS chart image: {error}"))?;
    if !metadata.is_file() || metadata.uid() != expected_uid || metadata.nlink() != 1 {
        return Err(
            "ODS chart image is not a private regular file owned by the command user".into(),
        );
    }
    if metadata.len() > MAX_CHART_BYTES {
        return Err("ODS chart image exceeds 32 MiB".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_CHART_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read ODS chart image: {error}"))?;
    if bytes.len() as u64 > MAX_CHART_BYTES {
        return Err("ODS chart image exceeds 32 MiB".into());
    }
    if !bytes.starts_with(PNG_SIGNATURE) {
        return Err("ODS chart output is not a PNG image".into());
    }
    Ok(bytes)
}

fn chart_args(metric: ChartMetric, entity: &str) -> Vec<String> {
    vec![
        "query".into(),
        "--stime".into(),
        metric.window().into(),
        entity.into(),
        metric.key().into(),
        metric.transform().into(),
        "--client_id=scx-snake-inspector".into(),
    ]
}

fn unix_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::future::Future;
    use std::os::unix::fs::symlink;
    use std::os::unix::fs::PermissionsExt;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[derive(Default)]
    struct StubRunner {
        calls: Mutex<Vec<CommandInvocation>>,
        fail_metadata: Mutex<bool>,
    }

    impl CommandRunner for StubRunner {
        fn run<'a>(
            &'a self,
            invocation: CommandInvocation,
            _timeout: Duration,
        ) -> Pin<Box<dyn Future<Output = Result<CommandOutput, String>> + Send + 'a>> {
            self.calls.lock().unwrap().push(invocation.clone());
            let fail_metadata = *self.fail_metadata.lock().unwrap();
            Box::pin(async move {
                let joined = invocation.args.join(" ");
                if fail_metadata
                    && (joined.contains("tupperware.host") || invocation.program.ends_with("rbcli"))
                {
                    return Err("metadata command failed".into());
                }
                if joined.contains("tupperware.host") {
                    Ok(CommandOutput::text(
                        r#"[{"job_handle":"tsp_atn/team/job","task_id":"7"}]"#,
                    ))
                } else if joined.contains("allotments_table") {
                    Ok(CommandOutput::text(
                        r#"[{"allocation_owner_id":"tsp_atn.2","capacity_shape_name":"M55","ownership_type":"GUARANTEED","region":"atn","resource_materialization_id":"abc","state":"IN_USE","uuid":"allotment-1"}]"#,
                    ))
                } else if joined.contains("host_fqdn") {
                    Ok(CommandOutput::text(
                        r#"[{"datacenter_name":"atn3","host_fqdn":"devbig008.atn3.facebook.com","id":"332060305","logical_server_subtype":"T2_TRN","machine_pool":"devbig","region":"atn","reservation_entitlement_id":"-","resource_materialization_id":"","stackable":"false"}]"#,
                    ))
                } else if joined.contains("--image") {
                    let path = invocation
                        .args
                        .iter()
                        .position(|arg| arg == "--image")
                        .and_then(|index| invocation.args.get(index + 1))
                        .ok_or_else(|| "image path missing".to_owned())?;
                    let parent_mode =
                        std::fs::metadata(std::path::Path::new(path).parent().unwrap())
                            .map_err(|error| error.to_string())?
                            .permissions()
                            .mode();
                    if parent_mode & 0o077 != 0 || std::path::Path::new(path).exists() {
                        return Err(
                            "chart destination is not private before chart generation".into()
                        );
                    }
                    std::fs::write(path, b"\x89PNG\r\n\x1a\nfake-png")
                        .map_err(|error| error.to_string())?;
                    Ok(CommandOutput::text(""))
                } else if joined.contains("--fburlonly") {
                    Ok(CommandOutput::text("https://fburl.com/ods/example\n"))
                } else {
                    Err(format!("unexpected command: {joined}"))
                }
            })
        }
    }

    #[test]
    fn short_hostname_is_used_as_the_ods_entity() {
        assert_eq!(ods_entity("devbig008.atn3.facebook.com"), "devbig008.atn3");
        assert_eq!(ods_entity("lab-host.example.net"), "lab-host.example.net");
    }

    #[test]
    fn tupperware_task_output_accepts_empty_and_populated_results() {
        assert!(parse_tupperware_tasks("").unwrap().is_empty());
        assert_eq!(
            parse_tupperware_tasks(
                r#"[{"job_handle":"tsp_rva/team/service","task_id":"15","_links":[]}]"#,
            )
            .unwrap(),
            vec![TupperwareTaskView {
                job_handle: "tsp_rva/team/service".into(),
                task_id: "15".into(),
            }]
        );
    }

    #[test]
    fn resource_browser_output_normalizes_host_identity() {
        let rows = json!([{
            "accepted_goal_state": "-",
            "allocation_snapshot": "{\"allotmentsInUse\":{}}",
            "datacenter_name": "atn3",
            "host_fqdn": "devbig008.atn3.facebook.com",
            "id": "332060305",
            "logical_server_subtype": "T2_TRN",
            "machine_pool": "devbig",
            "region": "atn",
            "reservation_entitlement_id": "-",
            "resource_materialization_id": "",
            "stackable": "false"
        }]);

        assert_eq!(
            parse_host_identity(&rows.to_string(), 316).unwrap(),
            HostIdentityView {
                hostname: "devbig008.atn3.facebook.com".into(),
                ods_entity: "devbig008.atn3".into(),
                cpu_count: 316,
                device_id: Some("332060305".into()),
                datacenter: Some("atn3".into()),
                region: Some("atn".into()),
                machine_pool: Some("devbig".into()),
                hardware: Some("T2_TRN".into()),
                stackable: Some(false),
                reservation_id: None,
                materialization_id: None,
            }
        );
    }

    #[test]
    fn resource_browser_uses_reservation_info_when_entitlement_field_is_empty() {
        let rows = json!([{
            "host_fqdn": "twshared21775.04.rva6.facebook.com",
            "id": "326939384",
            "reservation_entitlement_id": "-",
            "reservation_info": "{\"guaranteed\":\"39a684d3-a04c-4729-ba61-5b651acf8a52\"}",
            "resource_materialization_id": "66e20f7043a50",
            "stackable": "true"
        }]);

        let identity = parse_host_identity(&rows.to_string(), 176).unwrap();
        assert_eq!(
            identity.reservation_id.as_deref(),
            Some("39a684d3-a04c-4729-ba61-5b651acf8a52")
        );
        assert_eq!(
            identity.materialization_id.as_deref(),
            Some("66e20f7043a50")
        );
    }

    #[test]
    fn allotment_output_preserves_capacity_and_ownership_fields() {
        let rows = json!([
            {
                "allocation_owner_id": "tsp_rva.4",
                "capacity_shape_name": "M55",
                "ownership_type": "GUARANTEED",
                "region": "rva",
                "resource_materialization_id": "66e20f7043a50",
                "rru_contribution": "-",
                "stackable_behavior": "-",
                "state": "IN_USE",
                "uuid": "10ae7bc4-4432-4c5a-9663-bc4207505066"
            },
            {
                "allocation_owner_id": "",
                "capacity_shape_name": "M55",
                "ownership_type": "GUARANTEED",
                "region": "rva",
                "resource_materialization_id": "66e20f7043a50",
                "rru_contribution": "-",
                "stackable_behavior": "-",
                "state": "READY_TO_RUN_TASKS",
                "uuid": "464012f1-d033-46b6-a875-ff43f3fd80b7"
            }
        ]);

        let parsed = parse_allotments(&rows.to_string()).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].state, "IN_USE");
        assert_eq!(parsed[0].owner.as_deref(), Some("tsp_rva.4"));
        assert_eq!(parsed[1].shape, "M55");
        assert_eq!(parsed[1].owner, None);
    }

    #[test]
    fn source_cache_keeps_last_good_value_when_refresh_fails() {
        let mut cache = SourceCache::new(Vec::<TupperwareTaskView>::new());
        cache.succeed(
            1_000,
            vec![TupperwareTaskView {
                job_handle: "tsp_atn/team/job".into(),
                task_id: "7".into(),
            }],
        );
        cache.fail(2_000, "Tupperware unavailable");

        let view = cache.view();
        assert_eq!(view.state, SourceState::Stale);
        assert_eq!(view.fetched_at_ms, Some(1_000));
        assert_eq!(view.data.len(), 1);
        assert_eq!(view.message.as_deref(), Some("Tupperware unavailable"));
    }

    #[test]
    fn source_cache_is_unavailable_when_first_refresh_fails() {
        let mut cache = SourceCache::new(Vec::<TupperwareTaskView>::new());
        cache.fail(1_000, "command missing");

        assert_eq!(cache.view().state, SourceState::Unavailable);
        assert_eq!(cache.view().fetched_at_ms, None);
    }

    #[test]
    fn process_invocation_uses_fixed_arguments_and_the_invoking_user() {
        assert_eq!(
            process_invocation(
                "ods",
                &["query".into(), "devbig008.atn3".into()],
                Some("tommyu"),
            ),
            CommandInvocation {
                program: "sudo".into(),
                args: vec![
                    "-n".into(),
                    "-u".into(),
                    "tommyu".into(),
                    "--".into(),
                    "ods".into(),
                    "query".into(),
                    "devbig008.atn3".into(),
                ],
            }
        );
    }

    #[test]
    fn chart_metrics_use_exact_documented_ods_series() {
        assert_eq!(ChartMetric::CpuPressure.key(), "os.pressure.cpu.some");
        assert_eq!(ChartMetric::SchedulerDelay.key(), "dyno.cpu_delay_total_ms");
        for metric in [ChartMetric::CpuPressure, ChartMetric::SchedulerDelay] {
            assert_eq!(metric.transform(), "avg(5m)");
            assert_eq!(metric.window(), "3_h");
        }
    }

    #[tokio::test]
    async fn service_refreshes_host_tasks_allotments_and_chart_images() {
        let runner = Arc::new(StubRunner::default());
        let service =
            HostContextService::with_runner("devbig008.atn3.facebook.com", 316, None, runner);

        service.refresh_metadata(1_000).await;
        service.refresh_chart(ChartMetric::CpuPressure, 1_100).await;
        let snapshot = service.snapshot();

        assert_eq!(snapshot.identity.machine_pool.as_deref(), Some("devbig"));
        assert_eq!(snapshot.resource_browser.state, SourceState::Ready);
        assert_eq!(snapshot.tupperware.state, SourceState::Ready);
        assert_eq!(snapshot.tupperware.data[0].task_id, "7");
        assert_eq!(snapshot.allotments.state, SourceState::Ready);
        assert_eq!(snapshot.allotments.data[0].shape, "M55");
        assert_eq!(snapshot.charts[0].state, SourceState::Ready);
        assert_eq!(
            service.chart_png(ChartMetric::CpuPressure).unwrap(),
            b"\x89PNG\r\n\x1a\nfake-png"
        );
    }

    #[test]
    fn chart_reader_rejects_symlinks_and_non_png_files() {
        let directory = tempfile::tempdir().unwrap();
        let directory_handle = File::open(directory.path()).unwrap();
        let secret = directory.path().join("secret");
        std::fs::write(&secret, b"secret").unwrap();
        symlink(&secret, directory.path().join("chart.png")).unwrap();

        let error =
            read_chart_png(directory_handle.as_raw_fd(), unsafe { libc::geteuid() }).unwrap_err();
        assert!(error.contains("safely"));

        std::fs::remove_file(directory.path().join("chart.png")).unwrap();
        std::fs::write(directory.path().join("chart.png"), b"not a png").unwrap();
        let error =
            read_chart_png(directory_handle.as_raw_fd(), unsafe { libc::geteuid() }).unwrap_err();
        assert!(error.contains("not a PNG"));
    }

    #[tokio::test]
    async fn service_keeps_metadata_stale_after_a_failed_refresh() {
        let runner = Arc::new(StubRunner::default());
        let service = HostContextService::with_runner(
            "devbig008.atn3.facebook.com",
            316,
            None,
            runner.clone(),
        );
        service.refresh_metadata(1_000).await;
        *runner.fail_metadata.lock().unwrap() = true;

        service.refresh_metadata(2_000).await;

        let snapshot = service.snapshot();
        assert_eq!(snapshot.resource_browser.state, SourceState::Stale);
        assert_eq!(snapshot.tupperware.state, SourceState::Stale);
        assert_eq!(snapshot.tupperware.data.len(), 1);
        assert_eq!(snapshot.allotments.data.len(), 1);
    }

    #[tokio::test]
    async fn fresh_chart_url_is_generated_only_when_opened() {
        let runner = Arc::new(StubRunner::default());
        let service = HostContextService::with_runner(
            "devbig008.atn3.facebook.com",
            316,
            None,
            runner.clone(),
        );

        assert_eq!(
            service
                .fresh_chart_url(ChartMetric::SchedulerDelay)
                .await
                .unwrap(),
            "https://fburl.com/ods/example"
        );
        assert_eq!(runner.calls.lock().unwrap().len(), 1);
    }
}
