// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

mod executor;

use crate::policies::{discover_policy_files, InvalidPolicy, PolicyCatalog, PolicyChoice};

pub const MIN_DURATION_SECS: u64 = 60;

pub fn discover_testing_catalog(snake_bin: &Path, policy_dir: &Path) -> Result<PolicyCatalog> {
    let files = discover_policy_files(policy_dir)?;
    let mut catalog = PolicyCatalog::default();
    for file in files {
        let path = policy_dir.join(&file.id);
        let queue_policy = file
            .source
            .lines()
            .any(|line| line.trim().starts_with("[queues"));
        let output = Command::new(snake_bin)
            .args([
                "--policy",
                path.to_string_lossy().as_ref(),
                "--dump-compiled-policy",
            ])
            .output()
            .with_context(|| format!("validating testing policy {}", file.id))?;
        if output.status.success() {
            catalog.policies.push(PolicyChoice {
                id: file.id,
                name: file.name,
                source: file.source,
                rung_count: 0,
                mask_table_count: 0,
                cell_count: 0,
                queue_policy,
                summary: "Validated for VM testing".into(),
            });
        } else {
            let error = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            catalog.policies.push(PolicyChoice {
                id: file.id.clone(),
                name: file.name.clone(),
                source: file.source.clone(),
                rung_count: 0,
                mask_table_count: 0,
                cell_count: 0,
                queue_policy,
                summary: "Rejected during VM validation; retained for failure testing".into(),
            });
            catalog.invalid.push(InvalidPolicy {
                id: file.id,
                name: file.name,
                source: file.source,
                error: if error.is_empty() {
                    format!("policy validation exited with {}", output.status)
                } else {
                    error
                },
            });
        }
    }
    Ok(catalog)
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Fairness {
    Fifo,
    Vtime,
    Eevdf,
}

impl Fairness {
    const ALL: [Self; 3] = [Self::Fifo, Self::Vtime, Self::Eevdf];

    const fn as_str(self) -> &'static str {
        match self {
            Self::Fifo => "fifo",
            Self::Vtime => "vtime",
            Self::Eevdf => "eevdf",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Workload {
    CpuSaturation,
    WakerWakee,
    MixedAffinity,
    ForkYield,
}

impl Workload {
    const ALL: [Self; 4] = [
        Self::CpuSaturation,
        Self::WakerWakee,
        Self::MixedAffinity,
        Self::ForkYield,
    ];

    const fn as_str(self) -> &'static str {
        match self {
            Self::CpuSaturation => "cpu_saturation",
            Self::WakerWakee => "waker_wakee",
            Self::MixedAffinity => "mixed_affinity",
            Self::ForkYield => "fork_yield",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct WorkloadCommand {
    pub program: String,
    pub args: Vec<String>,
}

impl WorkloadCommand {
    pub fn for_workload(workload: Workload, cpus: usize) -> Result<Self> {
        if cpus == 0 {
            bail!("workload requires at least one CPU");
        }
        let command = match workload {
            Workload::CpuSaturation => Self::stress_ng([
                "--cpu".into(),
                cpus.saturating_mul(2).to_string(),
                "--cpu-method".into(),
                "loop".into(),
                "--aggressive".into(),
            ]),
            Workload::WakerWakee => Self::stress_ng([
                "--switch".into(),
                cpus.to_string(),
                "--switch-method".into(),
                "pipe".into(),
                "--aggressive".into(),
            ]),
            Workload::MixedAffinity => Self {
                program: "bash".into(),
                args: vec![
                    "-c".into(),
                    format!(
                        "taskset -c 0 stress-ng --cpu {cpus} --cpu-method loop --aggressive & narrow=$!; stress-ng --cpu {cpus} --cpu-method loop --aggressive & wide=$!; wait \"$narrow\" \"$wide\""
                    ),
                ],
            },
            Workload::ForkYield => Self::stress_ng([
                "--fork".into(),
                (cpus / 2).max(1).to_string(),
                "--yield".into(),
                cpus.to_string(),
                "--yield-procs".into(),
                "4".into(),
                "--aggressive".into(),
            ]),
        };
        Ok(command)
    }

    fn stress_ng<const N: usize>(args: [String; N]) -> Self {
        Self {
            program: "stress-ng".into(),
            args: args.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatrixConfig {
    pub duration_secs: u64,
    pub shard_index: usize,
    pub shard_count: usize,
}

impl MatrixConfig {
    pub fn new(duration_secs: u64, shard_index: usize, shard_count: usize) -> Result<Self> {
        if duration_secs < MIN_DURATION_SECS {
            bail!("test duration must be at least {MIN_DURATION_SECS} seconds");
        }
        if shard_count == 0 {
            bail!("shard count must be greater than zero");
        }
        if shard_index >= shard_count {
            bail!("shard index {shard_index} is outside {shard_count} shards");
        }
        Ok(Self {
            duration_secs,
            shard_index,
            shard_count,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MatrixCase {
    pub id: String,
    pub workload: Workload,
    pub shard: usize,
    pub assigned: bool,
    pub status: CaseStatus,
    pub elapsed_ms: u64,
    pub failure: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseStatus {
    Pending,
    Running,
    Passed,
    Skipped,
    Failed,
    Aborted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaseOutcome {
    Passed,
    Failed(String),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MatrixRow {
    pub policy_id: String,
    pub policy_name: String,
    pub queue_policy: bool,
    pub cases: Vec<MatrixCase>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FairnessGroup {
    pub fairness: Fairness,
    pub rows: Vec<MatrixRow>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TestMatrix {
    #[serde(default)]
    pub aggregate: bool,
    #[serde(default)]
    pub reporting_shards: usize,
    #[serde(default)]
    pub catalog_fingerprint: String,
    pub duration_secs: u64,
    pub shard_index: usize,
    pub shard_count: usize,
    pub workloads: Vec<Workload>,
    pub groups: Vec<FairnessGroup>,
    pub total_cases: usize,
    pub assigned_cases: usize,
}

pub fn build_matrix(catalog: &PolicyCatalog, config: MatrixConfig) -> TestMatrix {
    let mut policies = catalog.policies.iter().collect::<Vec<_>>();
    policies.sort_by(|left, right| left.id.cmp(&right.id));
    let skipped_policies = catalog
        .invalid
        .iter()
        .map(|policy| (policy.id.as_str(), policy.error.as_str()))
        .collect::<HashMap<_, _>>();
    let catalog_fingerprint = policy_catalog_fingerprint(&policies);
    let mut ordinal = 0;
    let groups = Fairness::ALL
        .into_iter()
        .map(|fairness| FairnessGroup {
            fairness,
            rows: policies
                .iter()
                .copied()
                .filter(|policy| compatible(policy, fairness))
                .map(|policy| {
                    let skip_reason = skipped_policies.get(policy.id.as_str()).copied();
                    let cases = Workload::ALL
                        .into_iter()
                        .map(|workload| {
                            let shard = ordinal % config.shard_count;
                            ordinal += 1;
                            MatrixCase {
                                id: format!(
                                    "{}/{}/{}",
                                    fairness.as_str(),
                                    policy.id,
                                    workload.as_str()
                                ),
                                workload,
                                shard,
                                assigned: shard == config.shard_index,
                                status: if skip_reason.is_some() {
                                    CaseStatus::Skipped
                                } else {
                                    CaseStatus::Pending
                                },
                                elapsed_ms: 0,
                                failure: skip_reason.map(str::to_owned),
                            }
                        })
                        .collect();
                    MatrixRow {
                        policy_id: policy.id.clone(),
                        policy_name: policy.name.clone(),
                        queue_policy: policy.queue_policy,
                        cases,
                    }
                })
                .collect(),
        })
        .collect::<Vec<_>>();
    let total_cases = ordinal;
    let assigned_cases = groups
        .iter()
        .flat_map(|group| &group.rows)
        .flat_map(|row| &row.cases)
        .filter(|case| case.assigned)
        .count();

    TestMatrix {
        aggregate: false,
        reporting_shards: 0,
        catalog_fingerprint,
        duration_secs: config.duration_secs,
        shard_index: config.shard_index,
        shard_count: config.shard_count,
        workloads: Workload::ALL.to_vec(),
        groups,
        total_cases,
        assigned_cases,
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Idle,
    Running,
    Completed,
    Stopped,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TestRun {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub campaign_id: Option<String>,
    #[serde(default)]
    pub environment: Option<TestEnvironment>,
    #[serde(default)]
    pub shard_environments: Vec<ShardEnvironment>,
    pub status: RunStatus,
    pub matrix: TestMatrix,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TestEnvironment {
    pub kernel_release: String,
    pub snake_version: String,
    pub snake_fingerprint: String,
    #[serde(default)]
    pub virtualization: String,
    #[serde(default)]
    pub cpu_count: usize,
    #[serde(default)]
    pub memory_bytes: u64,
    #[serde(default)]
    pub boot_command: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShardEnvironment {
    pub shard_index: usize,
    pub environment: TestEnvironment,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CaseJob {
    pub id: String,
    pub fairness: Fairness,
    pub policy_id: String,
    pub policy_name: String,
    pub workload: Workload,
}

#[derive(Clone)]
pub struct TestingController {
    config: MatrixConfig,
    catalog: Option<PolicyCatalog>,
    run: Arc<Mutex<Option<TestRun>>>,
    execution: Option<TestingExecutionConfig>,
    import_dirs: Vec<PathBuf>,
    stop_requested: Arc<AtomicBool>,
    worker_active: Arc<AtomicBool>,
}

#[derive(Clone, Debug)]
pub struct TestingExecutionConfig {
    pub snake_bin: PathBuf,
    pub policy_dir: PathBuf,
    pub artifact_dir: PathBuf,
    pub sched_ext_state: PathBuf,
    pub require_vm: bool,
}

impl TestingExecutionConfig {
    pub fn system(snake_bin: &Path, policy_dir: &Path, artifact_dir: &Path) -> Self {
        Self {
            snake_bin: snake_bin.to_path_buf(),
            policy_dir: policy_dir.to_path_buf(),
            artifact_dir: artifact_dir.to_path_buf(),
            sched_ext_state: PathBuf::from("/sys/kernel/sched_ext/state"),
            require_vm: true,
        }
    }
}

impl TestingController {
    pub fn new(config: MatrixConfig) -> Self {
        Self {
            config,
            catalog: None,
            run: Arc::new(Mutex::new(None)),
            execution: None,
            import_dirs: Vec::new(),
            stop_requested: Arc::new(AtomicBool::new(false)),
            worker_active: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn with_execution(mut self, execution: TestingExecutionConfig) -> Self {
        self.execution = Some(execution);
        self
    }

    pub fn with_catalog(mut self, catalog: PolicyCatalog) -> Self {
        self.catalog = Some(catalog);
        self
    }

    pub fn with_import_dir(mut self, import_dir: impl AsRef<Path>) -> Self {
        self.import_dirs = vec![import_dir.as_ref().to_path_buf()];
        self
    }

    pub fn with_import_dirs<I, P>(mut self, import_dirs: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        self.import_dirs = import_dirs
            .into_iter()
            .map(|path| path.as_ref().to_path_buf())
            .collect();
        self
    }

    pub fn snapshot(&self, catalog: &PolicyCatalog) -> Result<TestRun> {
        self.snapshot_available(Some(catalog))
    }

    pub fn snapshot_available(&self, catalog: Option<&PolicyCatalog>) -> Result<TestRun> {
        self.snapshots_available(catalog)?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("no testing campaigns are configured"))
    }

    pub fn snapshots_available(&self, catalog: Option<&PolicyCatalog>) -> Result<Vec<TestRun>> {
        let catalog =
            self.catalog.as_ref().or(catalog).ok_or_else(|| {
                anyhow::anyhow!("validated testing policy catalog is unavailable")
            })?;
        if !self.import_dirs.is_empty() {
            return self
                .import_dirs
                .iter()
                .map(|import_dir| aggregate_snapshot(catalog, self.config, import_dir))
                .collect();
        }
        let run = self
            .run
            .lock()
            .map_err(|_| anyhow::anyhow!("testing controller lock is poisoned"))?;
        Ok(vec![run.clone().unwrap_or_else(|| {
            TestRun::new(build_matrix(catalog, self.config))
        })])
    }

    pub fn start(&self, catalog: &PolicyCatalog) -> Result<TestRun> {
        self.start_available(Some(catalog))
    }

    pub fn start_available(&self, catalog: Option<&PolicyCatalog>) -> Result<TestRun> {
        if !self.import_dirs.is_empty() {
            bail!("aggregate testing view is read-only");
        }
        if self.worker_active.load(Ordering::Acquire) {
            bail!("previous testing worker is still stopping");
        }
        let catalog =
            self.catalog.as_ref().or(catalog).ok_or_else(|| {
                anyhow::anyhow!("validated testing policy catalog is unavailable")
            })?;
        if let Some(execution) = &self.execution {
            executor::preflight(execution)?;
        }
        let mut slot = self
            .run
            .lock()
            .map_err(|_| anyhow::anyhow!("testing controller lock is poisoned"))?;
        if slot
            .as_ref()
            .is_some_and(|run| run.status == RunStatus::Running)
        {
            bail!("test run is already running");
        }
        let mut run = TestRun::new(build_matrix(catalog, self.config));
        run.start()?;
        self.stop_requested.store(false, Ordering::Release);
        if let Some(execution) = &self.execution {
            run.campaign_id = campaign_id(&execution.artifact_dir);
            run.environment = Some(executor::test_environment(execution)?);
            executor::persist_run(execution, &run)?;
        }
        *slot = Some(run.clone());
        if let Some(execution) = self.execution.clone() {
            let controller = self.clone();
            let worker_execution = execution.clone();
            self.worker_active.store(true, Ordering::Release);
            if let Err(error) = thread::Builder::new()
                .name(format!("snake-testing-shard-{}", self.config.shard_index))
                .spawn(move || {
                    controller.execute(worker_execution);
                    controller.worker_active.store(false, Ordering::Release);
                })
            {
                self.worker_active.store(false, Ordering::Release);
                if let Some(run) = slot.as_mut() {
                    let _ = run.stop();
                    let _ = executor::persist_run(&execution, run);
                }
                return Err(anyhow::anyhow!("starting testing worker: {error}"));
            }
        }
        Ok(run)
    }

    pub fn stop(&self) -> Result<TestRun> {
        if !self.import_dirs.is_empty() {
            bail!("aggregate testing view is read-only");
        }
        self.stop_requested.store(true, Ordering::Release);
        let mut slot = self
            .run
            .lock()
            .map_err(|_| anyhow::anyhow!("testing controller lock is poisoned"))?;
        let run = slot
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("test run has not started"))?;
        run.stop()?;
        if let Some(execution) = &self.execution {
            executor::persist_run(execution, run)?;
        }
        Ok(run.clone())
    }

    pub fn is_running(&self) -> bool {
        self.worker_active.load(Ordering::Acquire)
            || self
                .run
                .lock()
                .ok()
                .and_then(|run| run.as_ref().map(|run| run.status == RunStatus::Running))
                .unwrap_or(false)
    }

    pub fn shutdown(&self) {
        self.stop_requested.store(true, Ordering::Release);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while self.worker_active.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
            thread::sleep(std::time::Duration::from_millis(100));
        }
        if let Ok(mut slot) = self.run.lock() {
            if let Some(run) = slot.as_mut() {
                if run.status == RunStatus::Running {
                    let _ = run.stop();
                    if let Some(execution) = &self.execution {
                        let _ = executor::persist_run(execution, run);
                    }
                }
            }
        }
    }

    fn execute(&self, execution: TestingExecutionConfig) {
        let jobs = match self.run.lock() {
            Ok(run) => run.as_ref().map(TestRun::assigned_jobs).unwrap_or_default(),
            Err(_) => return,
        };
        for job in jobs {
            if self.stop_requested.load(Ordering::Acquire) {
                break;
            }
            let started = {
                let Ok(mut slot) = self.run.lock() else {
                    return;
                };
                let Some(run) = slot.as_mut() else {
                    return;
                };
                if run.status != RunStatus::Running || run.begin_case(&job.id).is_err() {
                    return;
                }
                let _ = executor::persist_run(&execution, run);
                true
            };
            if !started {
                return;
            }
            let result = executor::execute_case(
                &execution,
                &job,
                self.config.duration_secs,
                &self.stop_requested,
            );
            let Ok(mut slot) = self.run.lock() else {
                return;
            };
            let Some(run) = slot.as_mut() else {
                return;
            };
            if run.status != RunStatus::Running {
                let _ = executor::persist_run(&execution, run);
                return;
            }
            match result {
                executor::ExecutionResult::Finished {
                    outcome,
                    elapsed_ms,
                } => {
                    let _ = run.finish_case(&job.id, outcome, elapsed_ms);
                }
                executor::ExecutionResult::Aborted => {
                    let _ = run.stop();
                }
            }
            let _ = executor::persist_run(&execution, run);
            if run.status != RunStatus::Running {
                return;
            }
        }
        if let Ok(mut slot) = self.run.lock() {
            if let Some(run) = slot.as_mut() {
                if run.status == RunStatus::Running {
                    let _ = run.complete();
                    let _ = executor::persist_run(&execution, run);
                }
            }
        }
    }
}

fn aggregate_snapshot(
    catalog: &PolicyCatalog,
    config: MatrixConfig,
    import_dir: &Path,
) -> Result<TestRun> {
    let mut aggregate = TestRun::new(build_matrix(catalog, config));
    aggregate.campaign_id = import_dir
        .file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned);
    aggregate.matrix.aggregate = true;
    aggregate.matrix.assigned_cases = aggregate.matrix.total_cases;
    for case in aggregate.cases_mut() {
        case.assigned = true;
    }

    let expected = aggregate
        .matrix
        .groups
        .iter()
        .flat_map(|group| &group.rows)
        .flat_map(|row| &row.cases)
        .map(|case| (case.id.clone(), case.shard))
        .collect::<HashMap<_, _>>();
    let mut statuses = vec![None; config.shard_count];
    let mut reference_environment: Option<TestEnvironment> = None;

    for shard_index in 0..config.shard_count {
        let path = import_dir
            .join(format!("shard-{shard_index}"))
            .join("run.json");
        let bytes = match fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
        };
        if let Some(bytes) = bytes {
            let source: TestRun = serde_json::from_slice(&bytes)
                .with_context(|| format!("parsing {}", path.display()))?;
            validate_imported_shard(
                &source,
                &expected,
                &aggregate.matrix.catalog_fingerprint,
                aggregate.campaign_id.as_deref(),
                config,
                shard_index,
                &path,
            )?;
            if let Some(source_environment) = &source.environment {
                if reference_environment.as_ref().is_some_and(|current| {
                    current.kernel_release != source_environment.kernel_release
                        || current.snake_fingerprint != source_environment.snake_fingerprint
                }) {
                    bail!("{} describes a different test environment", path.display());
                }
                reference_environment = Some(source_environment.clone());
                aggregate.shard_environments.push(ShardEnvironment {
                    shard_index,
                    environment: source_environment.clone(),
                });
            }
            statuses[shard_index] = Some(source.status);
            for source_case in source
                .matrix
                .groups
                .iter()
                .flat_map(|group| &group.rows)
                .flat_map(|row| &row.cases)
                .filter(|case| case.assigned)
            {
                let destination = aggregate.case_mut(&source_case.id)?;
                destination.status = source_case.status;
                destination.elapsed_ms = source_case.elapsed_ms;
                destination.failure.clone_from(&source_case.failure);
            }
        }
        if let Some(exit_status) = imported_exit_status(import_dir, shard_index)? {
            if statuses[shard_index] != Some(RunStatus::Completed) {
                for case in aggregate
                    .cases_mut()
                    .filter(|case| case.shard == shard_index)
                    .filter(|case| matches!(case.status, CaseStatus::Pending | CaseStatus::Running))
                {
                    case.status = CaseStatus::Failed;
                    case.failure = Some(format!(
                        "VM shard {shard_index} exited with status {exit_status}"
                    ));
                }
            }
            statuses[shard_index] = Some(RunStatus::Completed);
        }
    }

    aggregate.matrix.reporting_shards = statuses.iter().flatten().count();
    aggregate.environment = reference_environment;
    aggregate.status = if statuses.iter().all(Option::is_none)
        || statuses
            .iter()
            .flatten()
            .all(|status| *status == RunStatus::Idle)
    {
        RunStatus::Idle
    } else if statuses
        .iter()
        .all(|status| *status == Some(RunStatus::Completed))
    {
        RunStatus::Completed
    } else if statuses.iter().all(Option::is_some)
        && !statuses
            .iter()
            .flatten()
            .any(|status| *status == RunStatus::Running)
        && statuses
            .iter()
            .flatten()
            .any(|status| *status == RunStatus::Stopped)
    {
        RunStatus::Stopped
    } else {
        RunStatus::Running
    };
    Ok(aggregate)
}

fn imported_exit_status(import_dir: &Path, shard_index: usize) -> Result<Option<i32>> {
    let path = import_dir.join(format!("shard-{shard_index}.exit"));
    let value = match fs::read_to_string(&path) {
        Ok(value) => value,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    let status = value
        .trim()
        .parse::<i32>()
        .with_context(|| format!("parsing VM exit status from {}", path.display()))?;
    Ok(Some(status))
}

fn validate_imported_shard(
    source: &TestRun,
    expected: &HashMap<String, usize>,
    expected_catalog_fingerprint: &str,
    expected_campaign_id: Option<&str>,
    config: MatrixConfig,
    shard_index: usize,
    path: &Path,
) -> Result<()> {
    let matrix = &source.matrix;
    if source.schema_version > 1 {
        bail!(
            "{} uses unsupported schema version {}",
            path.display(),
            source.schema_version
        );
    }
    if source
        .campaign_id
        .as_deref()
        .is_some_and(|campaign_id| Some(campaign_id) != expected_campaign_id)
    {
        bail!("{} belongs to a different campaign", path.display());
    }
    if matrix.aggregate {
        bail!("{} contains an aggregate result", path.display());
    }
    if !matrix.catalog_fingerprint.is_empty()
        && matrix.catalog_fingerprint != expected_catalog_fingerprint
    {
        bail!("{} uses a different policy catalog", path.display());
    }
    if matrix.duration_secs != config.duration_secs {
        bail!(
            "{} has duration {} instead of {} seconds",
            path.display(),
            matrix.duration_secs,
            config.duration_secs
        );
    }
    if matrix.shard_count != config.shard_count {
        bail!(
            "{} has shard count {} instead of {}",
            path.display(),
            matrix.shard_count,
            config.shard_count
        );
    }
    if matrix.shard_index != shard_index {
        bail!(
            "{} identifies shard {} instead of {}",
            path.display(),
            matrix.shard_index,
            shard_index
        );
    }
    let source_cases = matrix
        .groups
        .iter()
        .flat_map(|group| &group.rows)
        .flat_map(|row| &row.cases)
        .collect::<Vec<_>>();
    if source_cases.len() != expected.len() {
        bail!(
            "{} contains {} cases instead of {}",
            path.display(),
            source_cases.len(),
            expected.len()
        );
    }
    let mut seen = HashSet::with_capacity(source_cases.len());
    for case in source_cases {
        if !seen.insert(&case.id) {
            bail!("{} contains duplicate case {:?}", path.display(), case.id);
        }
        let expected_shard = expected.get(&case.id).ok_or_else(|| {
            anyhow::anyhow!("{} contains unknown case {:?}", path.display(), case.id)
        })?;
        if case.shard != *expected_shard {
            bail!(
                "{} assigns case {:?} to shard {} instead of {}",
                path.display(),
                case.id,
                case.shard,
                expected_shard
            );
        }
        if case.assigned != (*expected_shard == shard_index) {
            bail!(
                "{} has invalid ownership for case {:?}",
                path.display(),
                case.id
            );
        }
    }
    Ok(())
}

impl TestRun {
    pub fn new(matrix: TestMatrix) -> Self {
        Self {
            schema_version: 1,
            campaign_id: None,
            environment: None,
            shard_environments: Vec::new(),
            status: RunStatus::Idle,
            matrix,
        }
    }

    pub fn start(&mut self) -> Result<()> {
        if self.status != RunStatus::Idle {
            bail!("test run has already started");
        }
        self.status = RunStatus::Running;
        Ok(())
    }

    pub fn assigned_jobs(&self) -> Vec<CaseJob> {
        self.matrix
            .groups
            .iter()
            .flat_map(|group| {
                group.rows.iter().flat_map(move |row| {
                    row.cases
                        .iter()
                        .filter(|case| case.assigned && case.status == CaseStatus::Pending)
                        .map(move |case| CaseJob {
                            id: case.id.clone(),
                            fairness: group.fairness,
                            policy_id: row.policy_id.clone(),
                            policy_name: row.policy_name.clone(),
                            workload: case.workload,
                        })
                })
            })
            .collect()
    }

    pub fn begin_case(&mut self, id: &str) -> Result<()> {
        if self.status != RunStatus::Running {
            bail!("test run is not running");
        }
        if self
            .matrix
            .groups
            .iter()
            .flat_map(|group| &group.rows)
            .flat_map(|row| &row.cases)
            .any(|case| case.status == CaseStatus::Running)
        {
            bail!("another case is already running");
        }
        let case = self.case_mut(id)?;
        if !case.assigned {
            bail!("case is assigned to another shard");
        }
        if case.status != CaseStatus::Pending {
            bail!("case is not pending");
        }
        case.status = CaseStatus::Running;
        case.elapsed_ms = 0;
        case.failure = None;
        Ok(())
    }

    pub fn finish_case(&mut self, id: &str, outcome: CaseOutcome, elapsed_ms: u64) -> Result<()> {
        let case = self.case_mut(id)?;
        if case.status != CaseStatus::Running {
            bail!("case must be running before it can finish");
        }
        case.elapsed_ms = elapsed_ms;
        match outcome {
            CaseOutcome::Passed => case.status = CaseStatus::Passed,
            CaseOutcome::Failed(failure) => {
                case.status = CaseStatus::Failed;
                case.failure = Some(failure);
            }
        }
        Ok(())
    }

    pub fn stop(&mut self) -> Result<()> {
        if self.status != RunStatus::Running {
            bail!("test run is not running");
        }
        for case in self.cases_mut() {
            if case.status == CaseStatus::Running {
                case.status = CaseStatus::Aborted;
            }
        }
        self.status = RunStatus::Stopped;
        Ok(())
    }

    pub fn complete(&mut self) -> Result<()> {
        if self.status != RunStatus::Running {
            bail!("test run is not running");
        }
        if self
            .matrix
            .groups
            .iter()
            .flat_map(|group| &group.rows)
            .flat_map(|row| &row.cases)
            .any(|case| {
                case.assigned && matches!(case.status, CaseStatus::Pending | CaseStatus::Running)
            })
        {
            bail!("assigned cases are still pending");
        }
        self.status = RunStatus::Completed;
        Ok(())
    }

    pub fn case(&self, id: &str) -> Result<&MatrixCase> {
        self.matrix
            .groups
            .iter()
            .flat_map(|group| &group.rows)
            .flat_map(|row| &row.cases)
            .find(|case| case.id == id)
            .ok_or_else(|| anyhow::anyhow!("unknown test case {id:?}"))
    }

    fn case_mut(&mut self, id: &str) -> Result<&mut MatrixCase> {
        self.cases_mut()
            .find(|case| case.id == id)
            .ok_or_else(|| anyhow::anyhow!("unknown test case {id:?}"))
    }

    fn cases_mut(&mut self) -> impl Iterator<Item = &mut MatrixCase> {
        self.matrix
            .groups
            .iter_mut()
            .flat_map(|group| &mut group.rows)
            .flat_map(|row| &mut row.cases)
    }
}

fn compatible(policy: &PolicyChoice, fairness: Fairness) -> bool {
    !policy.queue_policy || fairness == Fairness::Vtime
}

fn campaign_id(artifact_dir: &Path) -> Option<String> {
    artifact_dir
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .map(str::to_owned)
}

fn policy_catalog_fingerprint(policies: &[&PolicyChoice]) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for policy in policies {
        for byte in policy
            .id
            .bytes()
            .chain(std::iter::once(0))
            .chain(policy.source.bytes())
            .chain(std::iter::once(u8::from(policy.queue_policy)))
        {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    format!("fnv1a64:{hash:016x}")
}

pub fn failure_signature(log: &str) -> Option<&str> {
    log.lines().find(|line| {
        let line = line.to_ascii_lowercase();
        line.contains("runnable task stall")
            || line.contains("scx_bpf_error")
            || (line.contains("sched_ext:")
                && ["error", "stall", "watchdog"]
                    .iter()
                    .any(|word| line.contains(word)))
            || (line.contains("snake") && ["error", "stall"].iter().any(|word| line.contains(word)))
            || (line.contains("rcu") && line.contains("stall"))
            || line.contains("soft lockup")
            || line.contains("hard lockup")
            || line.contains("bug:")
            || line.contains("oops:")
            || line.contains("kernel panic")
    })
}
