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

    fn from_policy(policy: &MembershipPolicy, slot_epochs: &BTreeMap<u32, u32>) -> Self {
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
pub struct ReconcileReport {
    pub discovered: usize,
    pub updated: usize,
    pub transient: usize,
}

pub struct MembershipManager {
    parent: PathBuf,
    directory: CellDirectory,
    interval: Duration,
    next_reconcile: Instant,
    known: HashMap<i32, KnownTask>,
    pidfds: HashMap<i32, OwnedFd>,
    proc_root: PathBuf,
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
    }

    pub fn reconcile_if_due(&mut self, map: &impl MapCore) -> Result<Option<ReconcileReport>> {
        if Instant::now() < self.next_reconcile {
            return Ok(None);
        }
        self.reconcile(map).map(Some)
    }

    pub fn reconcile(&mut self, map: &impl MapCore) -> Result<ReconcileReport> {
        self.next_reconcile = Instant::now() + self.interval;
        self.prune_exited_tasks()?;
        let desired =
            scan_assigned_tasks(&self.parent, &self.proc_root, &self.directory, &self.known)?;
        let mut report = ReconcileReport {
            discovered: desired.len(),
            ..Default::default()
        };
        let mut applied = self.known.clone();

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
            match task_cells::set_managed_task_cell(map, tid, cell) {
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
                    warn!("could not tag TID {tid} during membership reconciliation: {error:#}");
                }
            }
        }

        self.known = applied;
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
    }

    #[test]
    fn policy_directory_carries_managed_cell_slot_epochs() {
        let policy = MembershipPolicy {
            parent: "/unused".into(),
            reconcile_ms: 1_000,
            assignments: BTreeMap::from([("batch".into(), 3), ("static".into(), 4)]),
            child_inodes: None,
        };

        let directory = CellDirectory::from_policy(&policy, &BTreeMap::from([(3, 7)]));

        assert_eq!(
            directory.assignments["batch"],
            CellRef {
                cell_id: 3,
                slot_epoch: 7,
            }
        );
        assert_eq!(directory.assignments["static"], CellRef::static_cell(4));
    }

    #[test]
    fn parses_start_time_when_task_name_contains_spaces() {
        assert_eq!(
            parse_task_start_time(&task_stat(42, 123456)).unwrap(),
            123456
        );
    }
}
