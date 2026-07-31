// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::topology::TopologyView;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HostIdentityView {
    pub hostname: String,
    pub kernel_release: String,
    pub cpu_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct HostContextView {
    pub identity: HostIdentityView,
    pub topology: TopologyView,
}

impl HostContextView {
    pub fn discover() -> Result<Self> {
        let topology = TopologyView::discover().context("discovering CPU topology")?;
        Ok(Self {
            identity: HostIdentityView {
                hostname: read_trimmed("/proc/sys/kernel/hostname")?,
                kernel_release: read_trimmed("/proc/sys/kernel/osrelease")?,
                cpu_count: topology.cpu_count as usize,
            },
            topology,
        })
    }
}

fn read_trimmed(path: impl AsRef<Path>) -> Result<String> {
    let path = path.as_ref();
    fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))
        .map(|value| value.trim().to_owned())
}
