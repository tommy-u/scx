// SPDX-License-Identifier: GPL-2.0-only

use std::fmt;
use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::str::FromStr;

use anyhow::{bail, Context, Result};
use libbpf_rs::{MapCore, MapFlags};
use serde::{Deserialize, Serialize};

use crate::bpf_intf;
use crate::policy::MAX_CELL_IDS;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CellRef {
    pub cell_id: u32,
    pub slot_epoch: u32,
}

impl CellRef {
    pub const fn static_cell(cell_id: u32) -> Self {
        Self {
            cell_id,
            slot_epoch: 0,
        }
    }
}

/// One CLI request assigning a live thread to a userspace-defined cell.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ThreadCellAssignment {
    pub tid: i32,
    pub cell_id: u32,
}

impl FromStr for ThreadCellAssignment {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        let (tid, cell_id) = value
            .split_once(':')
            .ok_or_else(|| "expected TID:CELL".to_owned())?;
        let tid = parse_tid(tid)?;
        let cell_id = cell_id
            .parse::<u32>()
            .map_err(|error| format!("invalid cell ID `{cell_id}`: {error}"))?;
        if cell_id >= MAX_CELL_IDS {
            return Err(format!(
                "cell ID {cell_id} exceeds maximum {}",
                MAX_CELL_IDS - 1
            ));
        }
        Ok(Self { tid, cell_id })
    }
}

pub fn parse_tid(value: &str) -> std::result::Result<i32, String> {
    let tid = value
        .parse::<i32>()
        .map_err(|error| format!("invalid TID `{value}`: {error}"))?;
    if tid <= 0 {
        return Err("TID must be positive".into());
    }
    Ok(tid)
}

/// Acknowledgment after the kernel task-storage map has been updated.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ThreadCellResponse {
    pub tid: i32,
    pub cell_id: Option<u32>,
    pub rehome_requested: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ThreadCellSnapshot {
    pub tid: i32,
    pub tgid: i32,
    pub name: String,
    pub state: String,
    pub current_cpu: Option<u32>,
    pub cell_id: u32,
    pub cell_epoch: u32,
    pub allowed_cpus: String,
    pub cgroup: String,
    pub needs_rehome: bool,
}

struct TaskStatus {
    tgid: i32,
    name: String,
    state: String,
    allowed_cpus: String,
}

impl fmt::Display for ThreadCellResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.cell_id {
            Some(cell_id) => write!(
                formatter,
                "thread {} assigned to cell {}; placement update requested",
                self.tid, cell_id
            ),
            None if self.rehome_requested => write!(
                formatter,
                "thread {} cell annotation cleared; placement update requested",
                self.tid
            ),
            None => write!(formatter, "thread {} cell annotation cleared", self.tid),
        }
    }
}

fn open_thread(tid: i32) -> Result<OwnedFd> {
    // PIDFD_THREAD is defined as O_EXCL in the Linux UAPI.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, tid, libc::O_EXCL) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("opening pidfd for TID {tid}"));
    }

    // SAFETY: pidfd_open returned a new descriptor owned by this process.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}

pub fn set_thread_cell(
    map: &impl MapCore,
    assignment: ThreadCellAssignment,
    slot_epoch: u32,
) -> Result<bool> {
    update_task_cell(map, assignment.tid, |value| {
        apply_manual_cell(
            value,
            CellRef {
                cell_id: assignment.cell_id,
                slot_epoch,
            },
        )
    })
}

pub(crate) fn set_managed_task_cell(
    map: &impl MapCore,
    tid: i32,
    cell: CellRef,
) -> Result<ManagedTaskCellUpdate> {
    let pidfd = open_thread(tid)?;
    let (previous_effective_cell_id, effective_cell_id) =
        update_task_cell_with_pidfd(map, tid, &pidfd, |value| {
            let previous_effective_cell_id = value.cell_id;
            apply_managed_cell(value, cell);
            (previous_effective_cell_id, value.cell_id)
        })?;
    Ok(ManagedTaskCellUpdate {
        pidfd,
        previous_effective_cell_id,
        effective_cell_id,
    })
}

pub(crate) struct ManagedTaskCellUpdate {
    pub pidfd: OwnedFd,
    pub previous_effective_cell_id: u32,
    pub effective_cell_id: u32,
}

pub(crate) fn clear_managed_task_cell(map: &impl MapCore, tid: i32, pidfd: &OwnedFd) -> Result<()> {
    let Some(mut value) = lookup_task_cell(map, pidfd, tid)? else {
        return Ok(());
    };
    if clear_managed_cell(&mut value) {
        map.update(
            &pidfd.as_raw_fd().to_ne_bytes(),
            bytes_of(&value),
            MapFlags::ANY,
        )
        .with_context(|| format!("clearing managed cell assignment for TID {tid}"))
    } else {
        map.delete(&pidfd.as_raw_fd().to_ne_bytes())
            .with_context(|| format!("returning TID {tid} to no-cell policy"))
    }
}

fn empty_task_cell() -> bpf_intf::snake_task_cell {
    bpf_intf::snake_task_cell {
        cell_id: 0,
        cell_epoch: 0,
        needs_rehome: 0,
        managed_cell_id: 0,
        managed_cell_epoch: 0,
        flags: 0,
    }
}

fn apply_manual_cell(value: &mut bpf_intf::snake_task_cell, cell: CellRef) -> bool {
    let previous = (value.cell_id, value.cell_epoch);
    value.cell_id = cell.cell_id;
    value.cell_epoch = cell.slot_epoch;
    value.flags |= bpf_intf::SNAKE_TASK_CELL_F_MANUAL;
    let changed = previous != (value.cell_id, value.cell_epoch);
    if changed {
        value.needs_rehome = 1;
    }
    changed
}

fn apply_managed_cell(value: &mut bpf_intf::snake_task_cell, cell: CellRef) -> bool {
    let previous = (value.cell_id, value.cell_epoch);
    value.managed_cell_id = cell.cell_id;
    value.managed_cell_epoch = cell.slot_epoch;
    value.flags |= bpf_intf::SNAKE_TASK_CELL_F_MANAGED;
    if value.flags & bpf_intf::SNAKE_TASK_CELL_F_MANUAL == 0 {
        value.cell_id = cell.cell_id;
        value.cell_epoch = cell.slot_epoch;
    }
    let changed = previous != (value.cell_id, value.cell_epoch);
    if changed {
        value.needs_rehome = 1;
    }
    changed
}

fn clear_manual_cell(value: &mut bpf_intf::snake_task_cell) -> bool {
    let previous = (value.cell_id, value.cell_epoch);
    value.flags &= !bpf_intf::SNAKE_TASK_CELL_F_MANUAL;
    if value.flags & bpf_intf::SNAKE_TASK_CELL_F_MANAGED == 0 {
        return false;
    }
    value.cell_id = value.managed_cell_id;
    value.cell_epoch = value.managed_cell_epoch;
    if previous != (value.cell_id, value.cell_epoch) {
        value.needs_rehome = 1;
    }
    true
}

fn clear_managed_cell(value: &mut bpf_intf::snake_task_cell) -> bool {
    value.flags &= !bpf_intf::SNAKE_TASK_CELL_F_MANAGED;
    value.managed_cell_id = 0;
    value.managed_cell_epoch = 0;
    value.flags & bpf_intf::SNAKE_TASK_CELL_F_MANUAL != 0
}

fn update_task_cell<T>(
    map: &impl MapCore,
    tid: i32,
    update: impl FnOnce(&mut bpf_intf::snake_task_cell) -> T,
) -> Result<T> {
    let pidfd = open_thread(tid)?;
    update_task_cell_with_pidfd(map, tid, &pidfd, update)
}

fn update_task_cell_with_pidfd<T>(
    map: &impl MapCore,
    tid: i32,
    pidfd: &OwnedFd,
    update: impl FnOnce(&mut bpf_intf::snake_task_cell) -> T,
) -> Result<T> {
    let mut value = lookup_task_cell(map, pidfd, tid)?.unwrap_or_else(empty_task_cell);
    let result = update(&mut value);
    map.update(
        &pidfd.as_raw_fd().to_ne_bytes(),
        bytes_of(&value),
        MapFlags::ANY,
    )
    .with_context(|| format!("updating cell assignment for TID {tid}"))?;
    Ok(result)
}

pub fn clear_thread_cell(map: &impl MapCore, tid: i32) -> Result<()> {
    if tid <= 0 {
        bail!("TID must be positive");
    }
    let pidfd = open_thread(tid)?;
    let Some(mut value) = lookup_task_cell(map, &pidfd, tid)? else {
        return Ok(());
    };
    if clear_manual_cell(&mut value) {
        map.update(
            &pidfd.as_raw_fd().to_ne_bytes(),
            bytes_of(&value),
            MapFlags::ANY,
        )
        .with_context(|| format!("revealing managed cell assignment for TID {tid}"))
    } else {
        map.delete(&pidfd.as_raw_fd().to_ne_bytes())
            .with_context(|| format!("clearing cell annotation for TID {tid}"))
    }
}

fn lookup_task_cell(
    map: &impl MapCore,
    pidfd: &OwnedFd,
    tid: i32,
) -> Result<Option<bpf_intf::snake_task_cell>> {
    let Some(value) = map
        .lookup(&pidfd.as_raw_fd().to_ne_bytes(), MapFlags::ANY)
        .with_context(|| format!("reading cell assignment for TID {tid}"))?
    else {
        return Ok(None);
    };
    if value.len() != std::mem::size_of::<bpf_intf::snake_task_cell>() {
        bail!(
            "cell assignment for TID {tid} has {} bytes, expected {}",
            value.len(),
            std::mem::size_of::<bpf_intf::snake_task_cell>()
        );
    }
    let mut decoded = std::mem::MaybeUninit::<bpf_intf::snake_task_cell>::uninit();
    // SAFETY: the length was checked and snake_task_cell contains only integer fields.
    unsafe {
        std::ptr::copy_nonoverlapping(
            value.as_ptr(),
            decoded.as_mut_ptr().cast::<u8>(),
            value.len(),
        );
        Ok(Some(decoded.assume_init()))
    }
}

pub fn inspect_thread_cell(map: &impl MapCore, tid: i32) -> Result<Option<ThreadCellSnapshot>> {
    let pidfd = match open_thread(tid) {
        Ok(pidfd) => pidfd,
        Err(error) if task_is_gone(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    let Some(value) = lookup_task_cell(map, &pidfd, tid)? else {
        return Ok(None);
    };
    inspect_thread(
        tid,
        value.cell_id,
        value.cell_epoch,
        value.needs_rehome != 0,
    )
}

pub(crate) fn inspect_thread(
    tid: i32,
    cell_id: u32,
    cell_epoch: u32,
    needs_rehome: bool,
) -> Result<Option<ThreadCellSnapshot>> {
    let status = match fs::read_to_string(format!("/proc/{tid}/status")) {
        Ok(status) => status,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("reading status for TID {tid}")),
    };
    let status =
        parse_task_status(&status).with_context(|| format!("parsing status for TID {tid}"))?;
    let current_cpu = fs::read_to_string(format!("/proc/{tid}/stat"))
        .ok()
        .and_then(|stat| parse_task_cpu(&stat).ok());
    let cgroup = fs::read_to_string(format!("/proc/{tid}/cgroup"))
        .map(|cgroup| parse_task_cgroup(&cgroup))
        .unwrap_or_else(|_| "unavailable".into());

    Ok(Some(ThreadCellSnapshot {
        tid,
        tgid: status.tgid,
        name: status.name,
        state: status.state,
        current_cpu,
        cell_id,
        cell_epoch,
        allowed_cpus: status.allowed_cpus,
        cgroup,
        needs_rehome,
    }))
}

fn parse_task_status(status: &str) -> Result<TaskStatus> {
    let field = |name: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .with_context(|| format!("task status is missing {name}"))
    };
    Ok(TaskStatus {
        name: field("Name:")?.into(),
        state: field("State:")?.into(),
        tgid: field("Tgid:")?
            .parse()
            .context("task status has an invalid Tgid")?,
        allowed_cpus: field("Cpus_allowed_list:")?.into(),
    })
}

fn parse_task_cpu(stat: &str) -> Result<u32> {
    let fields = stat
        .rfind(") ")
        .map(|end| &stat[end + 2..])
        .context("task stat has no closing command delimiter")?
        .split_whitespace()
        .collect::<Vec<_>>();
    fields
        .get(36)
        .context("task stat has no processor field")?
        .parse()
        .context("task stat has an invalid processor field")
}

pub(crate) fn parse_task_cgroup(cgroup: &str) -> String {
    cgroup
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .or_else(|| {
            cgroup
                .lines()
                .find_map(|line| line.rsplit_once(':').map(|(_, path)| path))
        })
        .filter(|path| !path.is_empty())
        .unwrap_or("/")
        .into()
}

pub(crate) fn task_is_gone(error: &anyhow::Error) -> bool {
    error.chain().any(|source| {
        source
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| {
                error.kind() == std::io::ErrorKind::NotFound
                    || error.raw_os_error() == Some(libc::ESRCH)
            })
    })
}

fn bytes_of<T>(value: &T) -> &[u8] {
    // SAFETY: map updates copy exactly size_of::<T>() bytes before this borrow ends.
    unsafe { std::slice::from_raw_parts(value as *const T as *const u8, std::mem::size_of::<T>()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_thread_cell_assignment() {
        assert_eq!(
            "4812:7".parse::<ThreadCellAssignment>().unwrap(),
            ThreadCellAssignment {
                tid: 4812,
                cell_id: 7,
            }
        );
    }

    #[test]
    fn rejects_malformed_or_out_of_range_assignments() {
        assert!("4812".parse::<ThreadCellAssignment>().is_err());
        assert!("0:7".parse::<ThreadCellAssignment>().is_err());
        assert!("4812:1024".parse::<ThreadCellAssignment>().is_err());
    }

    #[test]
    fn cleared_queue_assignment_reports_requested_rehome() {
        let response = ThreadCellResponse {
            tid: 4812,
            cell_id: None,
            rehome_requested: true,
        };

        assert!(response.to_string().contains("placement update requested"));
    }

    #[test]
    fn parses_task_identity_fields_from_proc_records() {
        let status = concat!(
            "Name:\tworker thread\n",
            "State:\tR (running)\n",
            "Tgid:\t4810\n",
            "Cpus_allowed_list:\t0-3,8\n",
        );
        let parsed = parse_task_status(status).expect("status should parse");

        assert_eq!(parsed.name, "worker thread");
        assert_eq!(parsed.state, "R (running)");
        assert_eq!(parsed.tgid, 4810);
        assert_eq!(parsed.allowed_cpus, "0-3,8");
        assert_eq!(
            parse_task_cgroup("7:cpu:/batch\n0::/work.slice/job\n"),
            "/work.slice/job"
        );
    }

    #[test]
    fn parses_current_cpu_from_proc_stat_even_when_comm_contains_spaces() {
        let mut fields = vec!["R"; 37];
        fields[36] = "23";
        let stat = format!("4812 (worker pool 1) {}", fields.join(" "));

        assert_eq!(parse_task_cpu(&stat).unwrap(), 23);
    }

    #[test]
    fn explicit_no_cell_does_not_rehome_implicit_cell_zero() {
        let mut value = empty_task_cell();

        apply_managed_cell(&mut value, CellRef::static_cell(0));

        assert_eq!(value.cell_id, 0);
        assert_eq!(value.needs_rehome, 0);
        assert_ne!(value.flags & bpf_intf::SNAKE_TASK_CELL_F_MANAGED, 0);
    }

    #[test]
    fn managed_updates_rehome_only_when_the_effective_cell_changes() {
        let mut value = empty_task_cell();
        apply_managed_cell(&mut value, CellRef::static_cell(1));
        assert_eq!(value.needs_rehome, 1);

        value.needs_rehome = 0;
        apply_manual_cell(&mut value, CellRef::static_cell(2));
        assert_eq!(value.needs_rehome, 1);

        value.needs_rehome = 0;
        apply_managed_cell(&mut value, CellRef::static_cell(3));
        assert_eq!(value.cell_id, 2);
        assert_eq!(value.needs_rehome, 0);

        assert!(clear_manual_cell(&mut value));
        assert_eq!(value.cell_id, 3);
        assert_eq!(value.needs_rehome, 1);
    }

    #[test]
    fn managed_slot_epoch_change_requests_rehome() {
        let mut value = empty_task_cell();
        let original = CellRef {
            cell_id: 3,
            slot_epoch: 7,
        };
        let replacement = CellRef {
            cell_id: 3,
            slot_epoch: 8,
        };

        assert!(apply_managed_cell(&mut value, original));
        value.needs_rehome = 0;
        assert!(apply_managed_cell(&mut value, replacement));
        assert_eq!(value.needs_rehome, 1);
        assert_eq!(value.cell_epoch, 8);
        assert_eq!(value.managed_cell_epoch, 8);
    }

    #[test]
    fn manual_assignment_carries_the_active_slot_epoch() {
        let mut value = empty_task_cell();
        let cell = CellRef {
            cell_id: 3,
            slot_epoch: 7,
        };

        assert!(apply_manual_cell(&mut value, cell));

        assert_eq!(value.cell_id, 3);
        assert_eq!(value.cell_epoch, 7);
    }

    #[test]
    fn clearing_managed_membership_preserves_only_a_manual_override() {
        let mut managed_only = empty_task_cell();
        apply_managed_cell(&mut managed_only, CellRef::static_cell(1));
        assert!(!clear_managed_cell(&mut managed_only));

        let mut overridden = empty_task_cell();
        apply_managed_cell(&mut overridden, CellRef::static_cell(1));
        apply_manual_cell(&mut overridden, CellRef::static_cell(2));
        overridden.needs_rehome = 0;
        assert!(clear_managed_cell(&mut overridden));
        assert_eq!(overridden.cell_id, 2);
        assert_eq!(overridden.needs_rehome, 0);
    }
}
