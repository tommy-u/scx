// Copyright (c) Meta Platforms, Inc. and affiliates.
// SPDX-License-Identifier: GPL-2.0-only

use std::path::Path;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::Serialize;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct SampleMeta {
    pub epoch: u64,
    pub sample_seq: u64,
    pub captured_at_unix_ms: Option<u64>,
    pub last_success_at_unix_ms: Option<u64>,
    pub error: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectorStatus {
    #[default]
    Waiting,
    Attaching,
    Active,
    Resetting,
    Error,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ObserverContext {
    pub epoch: u64,
    pub status: CollectorStatus,
    pub scheduler_enable_seq: Option<u64>,
    pub scheduler_name: Option<String>,
    pub error: Option<String>,
}

pub type SharedObserverContext = Arc<RwLock<ObserverContext>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SchedulerIdentity {
    pub name: String,
    pub enable_seq: u64,
}

pub fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

pub fn read_scheduler_identity() -> Result<Option<SchedulerIdentity>> {
    read_scheduler_identity_at(Path::new("/sys/kernel/sched_ext"))
}

fn read_scheduler_identity_at(root: &Path) -> Result<Option<SchedulerIdentity>> {
    read_scheduler_identity_with(|name| {
        std::fs::read_to_string(root.join(name))
            .with_context(|| format!("reading sched_ext {name}"))
    })
}

fn read_scheduler_identity_with(
    mut read: impl FnMut(&str) -> Result<String>,
) -> Result<Option<SchedulerIdentity>> {
    if read("state")?.trim() != "enabled" {
        return Ok(None);
    }
    let enable_seq = read("enable_seq")?
        .trim()
        .parse()
        .context("parsing sched_ext enable_seq")?;
    let name = read("root/ops")?.trim().to_string();
    let state_after = read("state")?;
    let seq_after: u64 = read("enable_seq")?
        .trim()
        .parse()
        .context("parsing sched_ext enable_seq")?;
    if state_after.trim() != "enabled" || seq_after != enable_seq || !is_mitosis_name(&name) {
        return Ok(None);
    }
    Ok(Some(SchedulerIdentity { name, enable_seq }))
}

fn is_mitosis_name(name: &str) -> bool {
    name == "mitosis"
        || name.strip_prefix("mitosis_").is_some_and(|suffix| {
            // Cargo builds use semver; Buck builds include a branch and full Git hash.
            let buck_build = suffix
                .strip_suffix("_facebook_buck_build")
                .and_then(|version| version.rsplit_once("_g"))
                .is_some_and(|(branch, hash)| {
                    !branch.is_empty()
                        && branch.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'.'
                        })
                        && hash.len() == 40
                        && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
                });
            let version = suffix.split('_').next().unwrap_or_default();
            let parts: Vec<_> = version.split('.').collect();
            let cargo_build = parts.len() == 3
                && parts
                    .iter()
                    .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'.');
            buck_build || cargo_build
        })
}

#[derive(Default)]
pub(crate) struct RetryBackoff {
    seconds: u64,
}

impl RetryBackoff {
    pub(crate) fn next_delay(&mut self) -> Duration {
        let seconds = self.seconds.max(1);
        self.seconds = seconds.saturating_mul(2).min(30);
        Duration::from_secs(seconds)
    }

    pub(crate) fn reset(&mut self) {
        self.seconds = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct SysfsFixture(std::path::PathBuf);

    impl SysfsFixture {
        fn new(state: &str, ops: Option<&str>, seq: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let root = std::env::temp_dir().join(format!(
                "mitosis-lifecycle-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(root.join("root")).unwrap();
            fs::write(root.join("state"), state).unwrap();
            fs::write(root.join("enable_seq"), seq).unwrap();
            if let Some(ops) = ops {
                fs::write(root.join("root/ops"), ops).unwrap();
            }
            Self(root)
        }
    }

    impl Drop for SysfsFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn recognizes_actual_mitosis_ops_name() {
        let fixture = SysfsFixture::new("enabled\n", Some("mitosis\n"), "71\n");
        assert_eq!(
            read_scheduler_identity_at(&fixture.0).unwrap(),
            Some(SchedulerIdentity {
                name: "mitosis".into(),
                enable_seq: 71
            })
        );
    }

    #[test]
    fn disabled_scheduler_does_not_require_ops() {
        let fixture = SysfsFixture::new("disabled\n", None, "71\n");
        assert_eq!(read_scheduler_identity_at(&fixture.0).unwrap(), None);
    }

    #[test]
    fn rejects_other_scheduler_and_similar_names() {
        for name in [
            "snake",
            "scx_mitosis",
            "mitosis_old",
            "mitosis_",
            "mitosis_fake_1.1.3",
            "mitosis_1fake",
            "mitosis_1.1",
            "mitosis_1.1.3bad",
        ] {
            let fixture = SysfsFixture::new("enabled", Some(name), "71");
            assert_eq!(read_scheduler_identity_at(&fixture.0).unwrap(), None);
        }
    }

    #[test]
    fn enabled_scheduler_read_failure_is_visible() {
        let fixture = SysfsFixture::new("enabled", None, "71");
        assert!(read_scheduler_identity_at(&fixture.0).is_err());
    }

    #[test]
    fn backoff_caps_at_thirty_seconds_and_resets() {
        let mut backoff = RetryBackoff::default();
        let delays: Vec<_> = (0..8).map(|_| backoff.next_delay().as_secs()).collect();
        assert_eq!(delays, [1, 2, 4, 8, 16, 30, 30, 30]);
        backoff.reset();
        assert_eq!(backoff.next_delay().as_secs(), 1);
    }

    #[test]
    fn rejects_identity_that_changes_during_the_read() {
        let mut sequence_reads = 0;
        let identity = read_scheduler_identity_with(|name| {
            Ok(match name {
                "state" => "enabled".into(),
                "root/ops" => "mitosis".into(),
                "enable_seq" => {
                    sequence_reads += 1;
                    sequence_reads.to_string()
                }
                _ => unreachable!(),
            })
        })
        .unwrap();
        assert_eq!(identity, None);
    }

    #[test]
    fn recognizes_versioned_ops_name_used_by_scx_utils() {
        let fixture = SysfsFixture::new(
            "enabled",
            Some("mitosis_1.1.3_x86_64_unknown_linux_gnu"),
            "4",
        );
        let identity = read_scheduler_identity_at(&fixture.0).unwrap().unwrap();
        assert_eq!(identity.name, "mitosis_1.1.3_x86_64_unknown_linux_gnu");
    }

    #[test]
    fn recognizes_buck_built_mitosis_ops_name() {
        let name = "mitosis_main_gb911893af7f8ff8a971b47e99151c19115aa2be1_facebook_buck_build";
        let fixture = SysfsFixture::new("enabled", Some(name), "25");
        let identity = read_scheduler_identity_at(&fixture.0).unwrap();
        assert_eq!(identity.map(|identity| identity.name), Some(name.into()));
    }

    #[test]
    fn rejects_malformed_buck_ops_names() {
        for name in [
            "snake_main_gb911893af7f8ff8a971b47e99151c19115aa2be1_facebook_buck_build",
            "mitosis_main_gb911893a_facebook_buck_build",
            "mitosis_main_gz911893af7f8ff8a971b47e99151c19115aa2be1_facebook_buck_build",
            "mitosis__gb911893af7f8ff8a971b47e99151c19115aa2be1_facebook_buck_build",
            "mitosis_main_gb911893af7f8ff8a971b47e99151c19115aa2be1_other_build",
        ] {
            assert!(!is_mitosis_name(name), "accepted unexpected name {name}");
        }
    }
}
