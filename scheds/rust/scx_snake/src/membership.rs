// SPDX-License-Identifier: GPL-2.0-only

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use libbpf_rs::MapCore;
use log::warn;

use crate::policy::MembershipPolicy;
use crate::task_cells::{self, CellRef};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CellDirectory {
    assignments: BTreeMap<String, CellRef>,
    child_inodes: Option<BTreeMap<String, u64>>,
}

impl CellDirectory {
    pub(crate) fn new(assignments: BTreeMap<String, CellRef>) -> Self {
        Self {
            assignments,
            child_inodes: None,
        }
    }

    pub(crate) fn with_child_inodes(
        assignments: BTreeMap<String, CellRef>,
        child_inodes: BTreeMap<String, u64>,
    ) -> Self {
        Self {
            assignments,
            child_inodes: Some(child_inodes),
        }
    }

    pub(crate) fn from_policy(policy: &MembershipPolicy, slot_epochs: &BTreeMap<u32, u32>) -> Self {
        let assignments = policy
            .assignments
            .iter()
            .map(|(child, &cell_id)| {
                (
                    child.clone(),
                    slot_epochs.get(&cell_id).copied().map_or_else(
                        || CellRef::static_cell(cell_id),
                        |slot_epoch| CellRef {
                            cell_id,
                            slot_epoch,
                        },
                    ),
                )
            })
            .collect();
        match policy.child_inodes.clone() {
            Some(child_inodes) => Self::with_child_inodes(assignments, child_inodes),
            None => Self::new(assignments),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedMembership {
    Cell(CellRef),
}

impl ManagedMembership {
    fn cell_ref(self) -> CellRef {
        match self {
            Self::Cell(cell) => cell,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct KnownTask {
    start_time: u64,
    membership: ManagedMembership,
}

impl KnownTask {
    fn new(start_time: u64, membership: ManagedMembership) -> Self {
        Self {
            start_time,
            membership,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReconcileTimestamp {
    boottime_ns: u64,
}

impl ReconcileTimestamp {
    fn now() -> Result<Self> {
        let mut timestamp = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: timestamp points to writable storage for one timespec.
        if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut timestamp) } != 0 {
            return Err(std::io::Error::last_os_error()).context("reading CLOCK_BOOTTIME");
        }
        Ok(Self {
            boottime_ns: (timestamp.tv_sec as u64)
                .saturating_mul(1_000_000_000)
                .saturating_add(timestamp.tv_nsec as u64),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TaskSchedstat {
    runtime_ns: u64,
    timeslices: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PreassignmentKind {
    NewTask,
    MoveIn,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PreassignmentObservation {
    kind: PreassignmentKind,
    runtime_ns: u64,
    timeslices: u64,
    correction_latency_ns: u64,
}

pub const MANAGED_IDENTITY_LATENCY_BUCKETS: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedIdentityLag {
    pub new_task_candidates: u64,
    pub new_task_affected: u64,
    pub new_task_runtime_ns: u64,
    pub new_task_timeslices: u64,
    pub move_in_candidates: u64,
    pub move_in_affected: u64,
    pub move_in_runtime_upper_bound_ns: u64,
    pub correction_latency_ns_total: u64,
    pub correction_latency_ns_max: u64,
    pub correction_latency_buckets: Vec<u64>,
}

impl Default for ManagedIdentityLag {
    fn default() -> Self {
        Self {
            new_task_candidates: 0,
            new_task_affected: 0,
            new_task_runtime_ns: 0,
            new_task_timeslices: 0,
            move_in_candidates: 0,
            move_in_affected: 0,
            move_in_runtime_upper_bound_ns: 0,
            correction_latency_ns_total: 0,
            correction_latency_ns_max: 0,
            correction_latency_buckets: vec![0; MANAGED_IDENTITY_LATENCY_BUCKETS],
        }
    }
}

impl ManagedIdentityLag {
    pub fn merge(&mut self, other: &Self) {
        self.new_task_candidates = self
            .new_task_candidates
            .saturating_add(other.new_task_candidates);
        self.new_task_affected = self
            .new_task_affected
            .saturating_add(other.new_task_affected);
        self.new_task_runtime_ns = self
            .new_task_runtime_ns
            .saturating_add(other.new_task_runtime_ns);
        self.new_task_timeslices = self
            .new_task_timeslices
            .saturating_add(other.new_task_timeslices);
        self.move_in_candidates = self
            .move_in_candidates
            .saturating_add(other.move_in_candidates);
        self.move_in_affected = self.move_in_affected.saturating_add(other.move_in_affected);
        self.move_in_runtime_upper_bound_ns = self
            .move_in_runtime_upper_bound_ns
            .saturating_add(other.move_in_runtime_upper_bound_ns);
        self.correction_latency_ns_total = self
            .correction_latency_ns_total
            .saturating_add(other.correction_latency_ns_total);
        self.correction_latency_ns_max = self
            .correction_latency_ns_max
            .max(other.correction_latency_ns_max);
        for (bucket, count) in self
            .correction_latency_buckets
            .iter_mut()
            .zip(&other.correction_latency_buckets)
        {
            *bucket = bucket.saturating_add(*count);
        }
    }

    fn record(&mut self, observation: PreassignmentObservation) {
        match observation.kind {
            PreassignmentKind::NewTask => {
                self.new_task_candidates = self.new_task_candidates.saturating_add(1);
                self.new_task_affected = self
                    .new_task_affected
                    .saturating_add(u64::from(observation.runtime_ns > 0));
                self.new_task_runtime_ns = self
                    .new_task_runtime_ns
                    .saturating_add(observation.runtime_ns);
                self.new_task_timeslices = self
                    .new_task_timeslices
                    .saturating_add(observation.timeslices);
                self.correction_latency_ns_total = self
                    .correction_latency_ns_total
                    .saturating_add(observation.correction_latency_ns);
                self.correction_latency_ns_max = self
                    .correction_latency_ns_max
                    .max(observation.correction_latency_ns);
                let bucket = log2_bucket(observation.correction_latency_ns);
                self.correction_latency_buckets[bucket] =
                    self.correction_latency_buckets[bucket].saturating_add(1);
            }
            PreassignmentKind::MoveIn => {
                self.move_in_candidates = self.move_in_candidates.saturating_add(1);
                self.move_in_affected = self
                    .move_in_affected
                    .saturating_add(u64::from(observation.runtime_ns > 0));
                self.move_in_runtime_upper_bound_ns = self
                    .move_in_runtime_upper_bound_ns
                    .saturating_add(observation.runtime_ns);
            }
        }
    }
}

fn log2_bucket(value: u64) -> usize {
    if value > 1 {
        (u64::BITS - 1 - value.leading_zeros()) as usize
    } else {
        0
    }
    .min(MANAGED_IDENTITY_LATENCY_BUCKETS - 1)
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReconcileReport {
    pub discovered: usize,
    pub updated: usize,
    pub transient: usize,
    pub identity_lag: ManagedIdentityLag,
}

pub struct MembershipManager {
    parent: PathBuf,
    directory: CellDirectory,
    interval: Duration,
    next_reconcile: Instant,
    known: HashMap<i32, KnownTask>,
    pidfds: HashMap<i32, OwnedFd>,
    proc_root: PathBuf,
    clock_ticks_per_second: u64,
    previous_reconcile_at: Option<ReconcileTimestamp>,
    bpf_assignments: bool,
}

fn membership_uses_bpf_assignments(policy: &MembershipPolicy) -> bool {
    policy.parent_inode.is_some()
}

impl MembershipManager {
    pub fn new(policy: &MembershipPolicy, slot_epochs: &BTreeMap<u32, u32>) -> Result<Self> {
        let parent = PathBuf::from(&policy.parent);
        let metadata = fs::metadata(&parent)
            .with_context(|| format!("reading membership parent {}", parent.display()))?;
        if !metadata.is_dir() {
            bail!("membership parent {} is not a directory", parent.display());
        }
        let mut manager = Self {
            parent,
            directory: CellDirectory::new(BTreeMap::new()),
            interval: Duration::from_millis(policy.reconcile_ms),
            next_reconcile: Instant::now(),
            known: HashMap::new(),
            pidfds: HashMap::new(),
            proc_root: PathBuf::from("/proc"),
            clock_ticks_per_second: clock_ticks_per_second()?,
            previous_reconcile_at: None,
            bpf_assignments: membership_uses_bpf_assignments(policy),
        };
        manager.replace_directory(CellDirectory::from_policy(policy, slot_epochs));
        Ok(manager)
    }

    pub fn time_until_reconcile(&self) -> Duration {
        self.next_reconcile
            .saturating_duration_since(Instant::now())
    }

    pub fn identity_errors_are_fatal(&self) -> bool {
        self.directory.child_inodes.is_some()
    }

    pub(crate) fn replace_directory(&mut self, directory: CellDirectory) {
        self.directory = directory;
        self.next_reconcile = Instant::now();
        self.previous_reconcile_at = None;
    }

    pub fn reconcile_if_due(&mut self, map: &impl MapCore) -> Result<Option<ReconcileReport>> {
        if Instant::now() < self.next_reconcile {
            return Ok(None);
        }
        self.reconcile(map).map(Some)
    }

    pub fn reconcile(&mut self, map: &impl MapCore) -> Result<ReconcileReport> {
        let observed_at = ReconcileTimestamp::now()?;
        self.next_reconcile = Instant::now() + self.interval;
        self.prune_exited_tasks()?;
        let desired =
            scan_assigned_tasks(&self.parent, &self.proc_root, &self.directory, &self.known)?;
        let mut report = ReconcileReport {
            discovered: desired.len(),
            ..Default::default()
        };
        let mut applied = self.known.clone();

        if self.bpf_assignments {
            for tid in reconciliation_removals(&self.known, &desired) {
                applied.remove(&tid);
                self.pidfds.remove(&tid);
                report.updated += 1;
            }
            for tid in reconciliation_updates(&self.known, &desired) {
                let task = desired
                    .get(&tid)
                    .expect("reconciliation update must have a desired task");
                match task_cells::open_thread(tid) {
                    Ok(pidfd) => {
                        self.pidfds.insert(tid, pidfd);
                        applied.insert(tid, *task);
                        report.updated += 1;
                    }
                    Err(error) if task_cells::task_is_gone(&error) => {
                        applied.remove(&tid);
                        self.pidfds.remove(&tid);
                        report.transient += 1;
                    }
                    Err(error) => {
                        applied.remove(&tid);
                        self.pidfds.remove(&tid);
                        report.transient += 1;
                        warn!(
                            "could not retain TID {tid} during membership observation: {error:#}"
                        );
                    }
                }
            }
            self.known = applied;
            self.previous_reconcile_at = Some(observed_at);
            return Ok(report);
        }

        for tid in reconciliation_removals(&self.known, &desired) {
            applied.remove(&tid);
            let pidfd = self
                .pidfds
                .remove(&tid)
                .with_context(|| format!("managed TID {tid} has no retained pidfd"))?;
            match task_cells::clear_managed_task_cell(map, tid, &pidfd) {
                Ok(()) => report.updated += 1,
                Err(error) if task_cells::task_is_gone(&error) => report.transient += 1,
                Err(error) => {
                    report.transient += 1;
                    warn!("could not clear managed membership for TID {tid}: {error:#}");
                }
            }
        }

        for tid in reconciliation_updates(&self.known, &desired) {
            let task = desired
                .get(&tid)
                .expect("reconciliation update must have a desired task");
            let cell = task.membership.cell_ref();
            let schedstat = if cell.cell_id != 0 && self.previous_reconcile_at.is_some() {
                match read_task_schedstat(&self.proc_root, tid) {
                    Ok(schedstat) => schedstat,
                    Err(error) => {
                        warn!("could not sample preassignment runtime for TID {tid}: {error:#}");
                        None
                    }
                }
            } else {
                None
            };
            match task_cells::set_managed_task_cell(map, tid, cell) {
                Ok(update) => {
                    if update.previous_effective_cell_id == 0
                        && update.effective_cell_id == cell.cell_id
                        && cell.cell_id != 0
                    {
                        if let Some(schedstat) = schedstat {
                            if let Some(observation) = classify_preassignment(
                                task.start_time,
                                self.previous_reconcile_at,
                                observed_at,
                                schedstat,
                                self.clock_ticks_per_second,
                            ) {
                                report.identity_lag.record(observation);
                            }
                        }
                    }
                    self.pidfds.insert(tid, update.pidfd);
                    applied.insert(tid, *task);
                    report.updated += 1;
                }
                Err(error) if task_cells::task_is_gone(&error) => {
                    applied.remove(&tid);
                    self.pidfds.remove(&tid);
                    report.transient += 1;
                }
                Err(error) => {
                    applied.remove(&tid);
                    self.pidfds.remove(&tid);
                    report.transient += 1;
                    warn!("could not tag TID {tid} during membership reconciliation: {error:#}");
                }
            }
        }

        self.known = applied;
        self.previous_reconcile_at = Some(observed_at);
        Ok(report)
    }

    pub fn assignments(&self) -> impl Iterator<Item = (i32, ManagedMembership)> + '_ {
        self.known.iter().map(|(tid, task)| (*tid, task.membership))
    }

    fn prune_exited_tasks(&mut self) -> Result<()> {
        let tids = self.pidfds.keys().copied().collect::<Vec<_>>();
        let mut pollfds = tids
            .iter()
            .map(|tid| libc::pollfd {
                fd: self.pidfds[tid].as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            })
            .collect::<Vec<_>>();
        if pollfds.is_empty() {
            return Ok(());
        }
        // SAFETY: pollfds owns a contiguous initialized array for the duration of poll().
        let result = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as _, 0) };
        if result < 0 {
            return Err(std::io::Error::last_os_error()).context("polling membership pidfds");
        }
        for (tid, pollfd) in tids.into_iter().zip(pollfds) {
            if pollfd.revents != 0 {
                self.pidfds.remove(&tid);
                self.known.remove(&tid);
            }
        }
        Ok(())
    }
}

fn reconciliation_updates(
    known: &HashMap<i32, KnownTask>,
    desired: &HashMap<i32, KnownTask>,
) -> Vec<i32> {
    let mut updates = desired
        .iter()
        .filter_map(|(tid, task)| (known.get(tid) != Some(task)).then_some(*tid))
        .collect::<Vec<_>>();
    updates.sort_unstable();
    updates
}

fn reconciliation_removals(
    known: &HashMap<i32, KnownTask>,
    desired: &HashMap<i32, KnownTask>,
) -> Vec<i32> {
    let mut removals = known
        .keys()
        .filter(|tid| !desired.contains_key(tid))
        .copied()
        .collect::<Vec<_>>();
    removals.sort_unstable();
    removals
}

fn scan_assigned_tasks(
    parent: &Path,
    proc_root: &Path,
    directory: &CellDirectory,
    known: &HashMap<i32, KnownTask>,
) -> Result<HashMap<i32, KnownTask>> {
    let mut tasks = HashMap::new();
    let mut ambiguous = HashSet::new();
    for (child, &cell) in &directory.assignments {
        let expected_inode = directory
            .child_inodes
            .as_ref()
            .map(|inodes| {
                inodes.get(child).copied().with_context(|| {
                    format!("managed child {child} has no recorded cgroup identity")
                })
            })
            .transpose()?;
        scan_cgroup_tree(
            &parent.join(child),
            proc_root,
            cell,
            expected_inode,
            known,
            &mut tasks,
            &mut ambiguous,
        )?;
    }
    for tid in ambiguous {
        if let Some(task) = known.get(&tid) {
            tasks.insert(tid, *task);
        }
    }
    Ok(tasks)
}

fn scan_cgroup_tree(
    root: &Path,
    proc_root: &Path,
    cell: CellRef,
    expected_inode: Option<u64>,
    known: &HashMap<i32, KnownTask>,
    tasks: &mut HashMap<i32, KnownTask>,
    ambiguous: &mut HashSet<i32>,
) -> Result<()> {
    if let Some(expected_inode) = expected_inode {
        verify_child_identity(root, expected_inode)?;
    }
    if !root.exists() {
        return Ok(());
    }
    let mut pending = vec![root.to_path_buf()];
    while let Some(cgroup) = pending.pop() {
        let threads = match fs::read_to_string(cgroup.join("cgroup.threads")) {
            Ok(threads) => threads,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("reading threads from {}", cgroup.display()))
            }
        };
        for tid in threads
            .lines()
            .filter_map(|tid| tid.trim().parse::<i32>().ok())
            .filter(|tid| *tid > 0)
        {
            if ambiguous.contains(&tid) {
                continue;
            }
            let task = if let Some(task) = known
                .get(&tid)
                .filter(|task| task.membership == ManagedMembership::Cell(cell))
            {
                Some(*task)
            } else {
                read_task_start_time(proc_root, tid)?
                    .map(|start_time| KnownTask::new(start_time, ManagedMembership::Cell(cell)))
            };
            let Some(task) = task else {
                continue;
            };
            if tasks
                .get(&tid)
                .is_some_and(|existing| existing.membership != task.membership)
            {
                tasks.remove(&tid);
                ambiguous.insert(tid);
            } else {
                tasks.insert(tid, task);
            }
        }

        let entries = match fs::read_dir(&cgroup) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("enumerating {}", cgroup.display()))
            }
        };
        for entry in entries.flatten() {
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                pending.push(entry.path());
            }
        }
    }
    if let Some(expected_inode) = expected_inode {
        verify_child_identity(root, expected_inode)?;
    }
    Ok(())
}

fn verify_child_identity(root: &Path, expected_inode: u64) -> Result<()> {
    let metadata = fs::metadata(root).with_context(|| {
        format!(
            "managed child {} was removed; restart Snake to resolve managed cells",
            root.display()
        )
    })?;
    if metadata.ino() != expected_inode {
        bail!(
            "managed child {} identity changed; restart Snake to resolve managed cells",
            root.display()
        );
    }
    Ok(())
}

fn read_task_start_time(proc_root: &Path, tid: i32) -> Result<Option<u64>> {
    let stat = match fs::read_to_string(proc_root.join(tid.to_string()).join("stat")) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("reading stat for TID {tid}")),
    };
    parse_task_start_time(&stat).map(Some)
}

fn clock_ticks_per_second() -> Result<u64> {
    // SAFETY: sysconf has no pointer arguments and does not retain state.
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks <= 0 {
        bail!("could not determine clock ticks per second");
    }
    Ok(ticks as u64)
}

fn read_task_schedstat(proc_root: &Path, tid: i32) -> Result<Option<TaskSchedstat>> {
    let schedstat = match fs::read_to_string(proc_root.join(tid.to_string()).join("schedstat")) {
        Ok(schedstat) => schedstat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("reading schedstat for TID {tid}"))
        }
    };
    parse_task_schedstat(&schedstat).map(Some)
}

fn parse_task_schedstat(schedstat: &str) -> Result<TaskSchedstat> {
    let mut fields = schedstat.split_whitespace();
    let runtime_ns = fields
        .next()
        .context("task schedstat has no runtime field")?
        .parse()
        .context("task schedstat has an invalid runtime field")?;
    fields
        .next()
        .context("task schedstat has no runqueue-delay field")?;
    let timeslices = fields
        .next()
        .context("task schedstat has no timeslice field")?
        .parse()
        .context("task schedstat has an invalid timeslice field")?;
    Ok(TaskSchedstat {
        runtime_ns,
        timeslices,
    })
}

fn classify_preassignment(
    task_start_ticks: u64,
    previous_reconcile_at: Option<ReconcileTimestamp>,
    observed_at: ReconcileTimestamp,
    schedstat: TaskSchedstat,
    ticks_per_second: u64,
) -> Option<PreassignmentObservation> {
    let previous_reconcile_at = previous_reconcile_at?;
    if ticks_per_second == 0 {
        return None;
    }
    let start_ns = ((task_start_ticks as u128).saturating_mul(1_000_000_000)
        / ticks_per_second as u128)
        .min(u64::MAX as u128) as u64;
    let is_new_task = start_ns > previous_reconcile_at.boottime_ns;
    let correction_latency_ns = observed_at.boottime_ns.saturating_sub(start_ns);
    let runtime_ns = if is_new_task {
        schedstat.runtime_ns
    } else {
        schedstat.runtime_ns.min(
            observed_at
                .boottime_ns
                .saturating_sub(previous_reconcile_at.boottime_ns),
        )
    };
    Some(PreassignmentObservation {
        kind: if is_new_task {
            PreassignmentKind::NewTask
        } else {
            PreassignmentKind::MoveIn
        },
        runtime_ns,
        timeslices: schedstat.timeslices,
        correction_latency_ns,
    })
}

fn parse_task_start_time(stat: &str) -> Result<u64> {
    stat.rfind(") ")
        .map(|end| &stat[end + 2..])
        .context("task stat has no closing command delimiter")?
        .split_whitespace()
        .nth(19)
        .context("task stat has no starttime field")?
        .parse()
        .context("task stat has an invalid starttime field")
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn task_stat(tid: i32, start_time: u64) -> String {
        let mut fields = vec!["0".to_owned(); 20];
        fields[0] = "R".into();
        fields[19] = start_time.to_string();
        format!("{tid} (worker pool 1) {}", fields.join(" "))
    }

    fn cell(cell_id: u32) -> ManagedMembership {
        ManagedMembership::Cell(CellRef::static_cell(cell_id))
    }

    fn directory(assignments: impl IntoIterator<Item = (&'static str, u32)>) -> CellDirectory {
        CellDirectory::new(
            assignments
                .into_iter()
                .map(|(child, cell_id)| (child.into(), CellRef::static_cell(cell_id)))
                .collect(),
        )
    }

    #[test]
    fn scans_only_assigned_child_trees_and_their_descendants() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("snake-membership-{}-{nonce}", std::process::id()));
        let parent = root.join("cgroup/workloads");
        let proc_root = root.join("proc");
        fs::create_dir_all(parent.join("batch/worker")).unwrap();
        fs::create_dir_all(parent.join("latency")).unwrap();
        fs::create_dir_all(parent.join("ignored")).unwrap();
        fs::write(parent.join("batch/cgroup.threads"), "10\n").unwrap();
        fs::write(parent.join("batch/worker/cgroup.threads"), "11\n").unwrap();
        fs::write(parent.join("latency/cgroup.threads"), "12\n").unwrap();
        fs::write(parent.join("ignored/cgroup.threads"), "13\n").unwrap();
        for tid in 10..=13 {
            fs::create_dir_all(proc_root.join(tid.to_string())).unwrap();
            fs::write(
                proc_root.join(tid.to_string()).join("stat"),
                task_stat(tid, tid as u64 * 100),
            )
            .unwrap();
        }

        let tasks = scan_assigned_tasks(
            &parent,
            &proc_root,
            &directory([("batch", 1), ("latency", 2)]),
            &HashMap::new(),
        )
        .unwrap();

        assert_eq!(tasks.len(), 3);
        assert_eq!(tasks[&10].membership, cell(1));
        assert_eq!(tasks[&11].membership, cell(1));
        assert_eq!(tasks[&12].membership, cell(2));
        assert!(!tasks.contains_key(&13));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn managed_directory_preserves_epoch_for_descendants_and_rejects_recreation() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "snake-membership-identity-{}-{nonce}",
            std::process::id()
        ));
        let parent = root.join("cgroup/workloads");
        let proc_root = root.join("proc");
        let child = parent.join("batch");
        fs::create_dir_all(child.join("nested")).unwrap();
        fs::write(child.join("cgroup.threads"), "").unwrap();
        fs::write(child.join("nested/cgroup.threads"), "10\n").unwrap();
        fs::create_dir_all(proc_root.join("10")).unwrap();
        fs::write(proc_root.join("10/stat"), task_stat(10, 100)).unwrap();
        let inode = fs::metadata(&child).unwrap().ino();
        let cell = CellRef {
            cell_id: 1,
            slot_epoch: 7,
        };
        let directory = CellDirectory::with_child_inodes(
            BTreeMap::from([("batch".into(), cell)]),
            BTreeMap::from([("batch".into(), inode)]),
        );

        let tasks = scan_assigned_tasks(&parent, &proc_root, &directory, &HashMap::new()).unwrap();
        assert_eq!(tasks[&10].membership, ManagedMembership::Cell(cell));

        fs::remove_dir_all(&child).unwrap();
        fs::create_dir_all(&child).unwrap();
        fs::write(child.join("cgroup.threads"), "").unwrap();
        let error = scan_assigned_tasks(&parent, &proc_root, &directory, &HashMap::new())
            .unwrap_err()
            .to_string();
        assert!(error.contains("identity changed"), "{error}");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn racing_duplicate_membership_is_deferred() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "snake-membership-race-{}-{nonce}",
            std::process::id()
        ));
        let parent = root.join("cgroup/workloads");
        let proc_root = root.join("proc");
        fs::create_dir_all(parent.join("batch")).unwrap();
        fs::create_dir_all(parent.join("latency")).unwrap();
        fs::write(parent.join("batch/cgroup.threads"), "10\n").unwrap();
        fs::write(parent.join("latency/cgroup.threads"), "10\n").unwrap();
        fs::create_dir_all(proc_root.join("10")).unwrap();
        fs::write(proc_root.join("10/stat"), task_stat(10, 100)).unwrap();

        let tasks = scan_assigned_tasks(
            &parent,
            &proc_root,
            &directory([("batch", 1), ("latency", 2)]),
            &HashMap::new(),
        )
        .unwrap();

        assert!(
            !tasks.contains_key(&10),
            "a TID observed in two cells must be retried on the next reconciliation"
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn racing_duplicate_preserves_the_last_valid_membership() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "snake-membership-known-race-{}-{nonce}",
            std::process::id()
        ));
        let parent = root.join("cgroup/workloads");
        let proc_root = root.join("proc");
        fs::create_dir_all(parent.join("batch")).unwrap();
        fs::create_dir_all(parent.join("latency")).unwrap();
        fs::write(parent.join("batch/cgroup.threads"), "10\n").unwrap();
        fs::write(parent.join("latency/cgroup.threads"), "10\n").unwrap();
        fs::create_dir_all(proc_root.join("10")).unwrap();
        fs::write(proc_root.join("10/stat"), task_stat(10, 100)).unwrap();
        let known = HashMap::from([(10, KnownTask::new(100, cell(1)))]);

        let tasks = scan_assigned_tasks(
            &parent,
            &proc_root,
            &directory([("batch", 1), ("latency", 2)]),
            &known,
        )
        .unwrap();

        assert_eq!(tasks.get(&10), known.get(&10));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reconciliation_tracks_updates_and_removals_separately() {
        let known = HashMap::from([
            (10, KnownTask::new(100, cell(1))),
            (11, KnownTask::new(200, cell(1))),
            (12, KnownTask::new(300, cell(1))),
        ]);
        let desired = HashMap::from([
            (10, KnownTask::new(100, cell(1))),
            (11, KnownTask::new(201, cell(1))),
            (12, KnownTask::new(300, cell(2))),
            (13, KnownTask::new(400, cell(2))),
        ]);

        assert_eq!(reconciliation_updates(&known, &desired), vec![11, 12, 13]);
        assert!(reconciliation_removals(&known, &desired).is_empty());
        assert_eq!(
            reconciliation_removals(&known, &HashMap::from([(10, desired[&10])])),
            vec![11, 12]
        );
    }

    #[test]
    fn slot_epoch_change_is_a_membership_update() {
        let known = HashMap::from([(
            10,
            KnownTask::new(
                100,
                ManagedMembership::Cell(CellRef {
                    cell_id: 3,
                    slot_epoch: 7,
                }),
            ),
        )]);
        let desired = HashMap::from([(
            10,
            KnownTask::new(
                100,
                ManagedMembership::Cell(CellRef {
                    cell_id: 3,
                    slot_epoch: 8,
                }),
            ),
        )]);

        assert_eq!(reconciliation_updates(&known, &desired), vec![10]);
    }

    #[test]
    fn replacing_the_cell_directory_schedules_an_immediate_reconciliation() {
        let mut manager = MembershipManager {
            parent: PathBuf::from("/unused"),
            directory: directory([("batch", 1)]),
            interval: Duration::from_secs(1),
            next_reconcile: Instant::now() + Duration::from_secs(60),
            known: HashMap::new(),
            pidfds: HashMap::new(),
            proc_root: PathBuf::from("/unused-proc"),
            clock_ticks_per_second: 100,
            previous_reconcile_at: Some(ReconcileTimestamp { boottime_ns: 1 }),
            bpf_assignments: false,
        };
        let replacement = CellDirectory::new(BTreeMap::from([(
            "batch".into(),
            CellRef {
                cell_id: 1,
                slot_epoch: 2,
            },
        )]));

        manager.replace_directory(replacement.clone());

        assert_eq!(manager.directory, replacement);
        assert_eq!(manager.time_until_reconcile(), Duration::ZERO);
        assert_eq!(manager.previous_reconcile_at, None);
    }

    #[test]
    fn policy_directory_carries_managed_cell_slot_epochs() {
        let policy = MembershipPolicy {
            parent: "/unused".into(),
            parent_inode: None,
            reconcile_ms: 1_000,
            assignments: BTreeMap::from([("batch".into(), 3), ("static".into(), 4)]),
            child_inodes: None,
            excluded_child_inodes: BTreeMap::new(),
        };

        let directory = CellDirectory::from_policy(&policy, &BTreeMap::from([(3, 7)]));

        assert_eq!(
            directory.assignments["batch"],
            CellRef {
                cell_id: 3,
                slot_epoch: 7,
            }
        );

        assert!(!membership_uses_bpf_assignments(&policy));
        let mut managed = policy.clone();
        managed.parent_inode = Some(99);
        assert!(membership_uses_bpf_assignments(&managed));
        assert_eq!(directory.assignments["static"], CellRef::static_cell(4));
    }

    #[test]
    fn parses_start_time_when_task_name_contains_spaces() {
        assert_eq!(
            parse_task_start_time(&task_stat(42, 123456)).unwrap(),
            123456
        );
    }

    #[test]
    fn parses_runtime_and_timeslices_from_schedstat() {
        assert_eq!(
            parse_task_schedstat("123456789 42000 17\n").unwrap(),
            TaskSchedstat {
                runtime_ns: 123456789,
                timeslices: 17,
            }
        );
    }

    #[test]
    fn new_task_preassignment_uses_exact_lifetime_runtime() {
        let observation = classify_preassignment(
            110,
            Some(ReconcileTimestamp {
                boottime_ns: 1_000_000_000,
            }),
            ReconcileTimestamp {
                boottime_ns: 1_500_000_000,
            },
            TaskSchedstat {
                runtime_ns: 123_000_000,
                timeslices: 17,
            },
            100,
        )
        .unwrap();

        assert_eq!(observation.kind, PreassignmentKind::NewTask);
        assert_eq!(observation.runtime_ns, 123_000_000);
        assert_eq!(observation.timeslices, 17);
        assert_eq!(observation.correction_latency_ns, 400_000_000);
    }

    #[test]
    fn move_in_preassignment_is_capped_by_the_reconciliation_window() {
        let observation = classify_preassignment(
            50,
            Some(ReconcileTimestamp {
                boottime_ns: 1_000_000_000,
            }),
            ReconcileTimestamp {
                boottime_ns: 1_200_000_000,
            },
            TaskSchedstat {
                runtime_ns: 900_000_000,
                timeslices: 99,
            },
            100,
        )
        .unwrap();

        assert_eq!(observation.kind, PreassignmentKind::MoveIn);
        assert_eq!(observation.runtime_ns, 200_000_000);
        assert_eq!(observation.timeslices, 99);
    }

    #[test]
    fn initial_reconciliation_only_establishes_a_baseline() {
        assert_eq!(
            classify_preassignment(
                50,
                None,
                ReconcileTimestamp {
                    boottime_ns: 1_200_000_000,
                },
                TaskSchedstat {
                    runtime_ns: 900_000_000,
                    timeslices: 99,
                },
                100,
            ),
            None
        );
    }
}
