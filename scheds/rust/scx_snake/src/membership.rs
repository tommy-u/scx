// SPDX-License-Identifier: GPL-2.0-only

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use libbpf_rs::MapCore;
use log::warn;

use crate::policy::MembershipPolicy;
use crate::task_cells;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedMembership {
    Cell(u32),
}

impl ManagedMembership {
    fn cell_id(self) -> u32 {
        match self {
            Self::Cell(cell_id) => cell_id,
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
    assignments: BTreeMap<String, u32>,
    interval: Duration,
    next_reconcile: Instant,
    known: HashMap<i32, KnownTask>,
    pidfds: HashMap<i32, OwnedFd>,
    proc_root: PathBuf,
}

impl MembershipManager {
    pub fn new(policy: &MembershipPolicy) -> Result<Self> {
        let parent = PathBuf::from(&policy.parent);
        let metadata = fs::metadata(&parent)
            .with_context(|| format!("reading membership parent {}", parent.display()))?;
        if !metadata.is_dir() {
            bail!("membership parent {} is not a directory", parent.display());
        }
        Ok(Self {
            parent,
            assignments: policy.assignments.clone(),
            interval: Duration::from_millis(policy.reconcile_ms),
            next_reconcile: Instant::now(),
            known: HashMap::new(),
            pidfds: HashMap::new(),
            proc_root: PathBuf::from("/proc"),
        })
    }

    pub fn time_until_reconcile(&self) -> Duration {
        self.next_reconcile
            .saturating_duration_since(Instant::now())
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
        let desired = scan_assigned_tasks(
            &self.parent,
            &self.proc_root,
            &self.assignments,
            &self.known,
        )?;
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
            let cell_id = task.membership.cell_id();
            match task_cells::set_managed_task_cell(map, tid, cell_id) {
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
    assignments: &BTreeMap<String, u32>,
    known: &HashMap<i32, KnownTask>,
) -> Result<HashMap<i32, KnownTask>> {
    let mut tasks = HashMap::new();
    for (child, &cell_id) in assignments {
        scan_cgroup_tree(&parent.join(child), proc_root, cell_id, known, &mut tasks)?;
    }
    Ok(tasks)
}

fn scan_cgroup_tree(
    root: &Path,
    proc_root: &Path,
    cell_id: u32,
    known: &HashMap<i32, KnownTask>,
    tasks: &mut HashMap<i32, KnownTask>,
) -> Result<()> {
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
            if let Some(task) = known
                .get(&tid)
                .filter(|task| task.membership == ManagedMembership::Cell(cell_id))
            {
                tasks.insert(tid, *task);
                continue;
            }
            if let Some(start_time) = read_task_start_time(proc_root, tid)? {
                tasks.insert(
                    tid,
                    KnownTask::new(start_time, ManagedMembership::Cell(cell_id)),
                );
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
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn task_stat(tid: i32, start_time: u64) -> String {
        let mut fields = vec!["0".to_owned(); 20];
        fields[0] = "R".into();
        fields[19] = start_time.to_string();
        format!("{tid} (worker pool 1) {}", fields.join(" "))
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
            &BTreeMap::from([("batch".into(), 1), ("latency".into(), 2)]),
            &HashMap::new(),
        )
        .unwrap();

        assert_eq!(tasks.len(), 3);
        assert_eq!(tasks[&10].membership, ManagedMembership::Cell(1));
        assert_eq!(tasks[&11].membership, ManagedMembership::Cell(1));
        assert_eq!(tasks[&12].membership, ManagedMembership::Cell(2));
        assert!(!tasks.contains_key(&13));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reconciliation_tracks_updates_and_removals_separately() {
        let known = HashMap::from([
            (10, KnownTask::new(100, ManagedMembership::Cell(1))),
            (11, KnownTask::new(200, ManagedMembership::Cell(1))),
            (12, KnownTask::new(300, ManagedMembership::Cell(1))),
        ]);
        let desired = HashMap::from([
            (10, KnownTask::new(100, ManagedMembership::Cell(1))),
            (11, KnownTask::new(201, ManagedMembership::Cell(1))),
            (12, KnownTask::new(300, ManagedMembership::Cell(2))),
            (13, KnownTask::new(400, ManagedMembership::Cell(2))),
        ]);

        assert_eq!(reconciliation_updates(&known, &desired), vec![11, 12, 13]);
        assert!(reconciliation_removals(&known, &desired).is_empty());
        assert_eq!(
            reconciliation_removals(&known, &HashMap::from([(10, desired[&10])])),
            vec![11, 12]
        );
    }

    #[test]
    fn parses_start_time_when_task_name_contains_spaces() {
        assert_eq!(
            parse_task_start_time(&task_stat(42, 123456)).unwrap(),
            123456
        );
    }
}
