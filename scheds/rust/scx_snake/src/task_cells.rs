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

pub fn set_thread_cell(map: &impl MapCore, assignment: ThreadCellAssignment) -> Result<()> {
    let pidfd = open_thread(assignment.tid)?;
    let value = bpf_intf::snake_task_cell {
        cell_id: assignment.cell_id,
        needs_rehome: 1,
    };
    map.update(
        &pidfd.as_raw_fd().to_ne_bytes(),
        bytes_of(&value),
        MapFlags::ANY,
    )
    .with_context(|| {
        format!(
            "assigning TID {} to cell {}",
            assignment.tid, assignment.cell_id
        )
    })
}

pub fn clear_thread_cell(map: &impl MapCore, tid: i32) -> Result<()> {
    if tid <= 0 {
        bail!("TID must be positive");
    }
    let pidfd = open_thread(tid)?;
    map.delete(&pidfd.as_raw_fd().to_ne_bytes())
        .with_context(|| format!("clearing cell annotation for TID {tid}"))
}

pub fn inspect_thread_cell(map: &impl MapCore, tid: i32) -> Result<Option<ThreadCellSnapshot>> {
    let status = match fs::read_to_string(format!("/proc/{tid}/status")) {
        Ok(status) => status,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("reading status for TID {tid}")),
    };
    let status =
        parse_task_status(&status).with_context(|| format!("parsing status for TID {tid}"))?;
    let pidfd = match open_thread(tid) {
        Ok(pidfd) => pidfd,
        Err(error) if task_is_gone(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    let Some(value) = map
        .lookup(&pidfd.as_raw_fd().to_ne_bytes(), MapFlags::ANY)
        .with_context(|| format!("reading cell annotation for TID {tid}"))?
    else {
        return Ok(None);
    };
    if value.len() != std::mem::size_of::<bpf_intf::snake_task_cell>() {
        bail!(
            "cell annotation for TID {tid} has {} bytes, expected {}",
            value.len(),
            std::mem::size_of::<bpf_intf::snake_task_cell>()
        );
    }
    let cell_id = u32::from_ne_bytes(value[0..4].try_into().expect("cell ID has four bytes"));
    let needs_rehome =
        u32::from_ne_bytes(value[4..8].try_into().expect("rehome flag has four bytes")) != 0;
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

fn parse_task_cgroup(cgroup: &str) -> String {
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

fn task_is_gone(error: &anyhow::Error) -> bool {
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
}
