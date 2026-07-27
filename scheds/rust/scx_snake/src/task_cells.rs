// SPDX-License-Identifier: GPL-2.0-only

use std::fmt;
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

}
