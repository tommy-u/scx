// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::{BTreeMap, VecDeque};
use std::io::{BufWriter, Read};
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::collector::Snapshot;
use crate::explore_model::{ExploreGroup, ExploreSnapshot};
use crate::lifecycle::{CollectorStatus, ObserverContext, SampleMeta};
use crate::migration_history::MigrationWindowView;
use crate::scheduler_config::SchedulerConfigSnapshot;
use crate::stats::StatsSnapshot;
use crate::system_stats::{MetricSource, PsiStats, SystemStatsSnapshot};

pub const REPLAY_RETENTION_MS: u64 = 30 * 60 * 1_000;
pub const REPLAY_MAX_FRAMES: usize = 1_801;
pub const REPLAY_MAX_BYTES: usize = 256 * 1024 * 1024;

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ReplayQuery {
    pub instance_id: Option<String>,
    pub after_seq: Option<u64>,
    pub window_ms: Option<u64>,
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ReplayViewQuery {
    pub at_unix_ms: Option<u64>,
    pub window_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReplayFrame {
    pub seq: u64,
    pub at_unix_ms: u64,
    pub epochs: BTreeMap<String, u64>,
    pub source_meta: BTreeMap<String, SampleMeta>,
    pub source_available: BTreeMap<String, bool>,
    pub signals: BTreeMap<String, Option<f64>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReplayTimeline {
    pub instance_id: String,
    pub retention_ms: u64,
    pub now_unix_ms: u64,
    pub oldest_at_unix_ms: Option<u64>,
    pub latest_at_unix_ms: Option<u64>,
    pub sample_seq: u64,
    pub reset: bool,
    pub frames: Vec<ReplayFrame>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReplayView {
    pub instance_id: String,
    pub retention_ms: u64,
    pub requested_at_unix_ms: Option<u64>,
    pub at_unix_ms: u64,
    pub oldest_at_unix_ms: Option<u64>,
    pub latest_at_unix_ms: Option<u64>,
    pub now_unix_ms: u64,
    pub collector: ObserverContext,
    pub sources: Value,
    pub migrations: Option<MigrationWindowView>,
    pub source_errors: BTreeMap<String, String>,
}

pub struct ReplaySources {
    pub counters: Snapshot,
    pub stats: StatsSnapshot,
    pub system: SystemStatsSnapshot,
    pub config: SchedulerConfigSnapshot,
}

struct StoredFrame {
    frame: ReplayFrame,
    collector: ObserverContext,
    source_errors: BTreeMap<String, String>,
    compressed_sources: Box<[u8]>,
}

/// An encoded frame ready for a short, ordered publication into the replay ring.
pub struct PreparedReplayFrame(StoredFrame);

/// An owned selection that can be decoded after releasing the replay lock.
pub struct SelectedReplayView {
    view: ReplayView,
    compressed_sources: Box<[u8]>,
}

impl SelectedReplayView {
    pub fn decode(mut self) -> Result<ReplayView, String> {
        let mut inflated = Vec::new();
        ZlibDecoder::new(self.compressed_sources.as_ref())
            .read_to_end(&mut inflated)
            .map_err(|error| format!("decoding replay: {error}"))?;
        self.view.sources = serde_json::from_slice(&inflated)
            .map_err(|error| format!("decoding replay: {error}"))?;
        Ok(self.view)
    }
}

/// A bounded in-memory replay ring. Original source metadata is retained so
/// repeated observations of a cached source never become extra measurements.
pub struct ReplayHistory {
    instance_id: String,
    retention_ms: u64,
    max_frames: usize,
    max_bytes: usize,
    sample_seq: u64,
    frames: VecDeque<StoredFrame>,
    retained_bytes: usize,
    evicted_through_seq: Option<u64>,
}

impl Default for ReplayHistory {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayHistory {
    pub fn new() -> Self {
        Self::with_limits(REPLAY_RETENTION_MS, REPLAY_MAX_FRAMES, REPLAY_MAX_BYTES)
    }

    pub fn with_limits(retention_ms: u64, max_frames: usize, max_bytes: usize) -> Self {
        assert!(retention_ms > 0 && max_frames > 0 && max_bytes > 0);
        let started_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        Self {
            instance_id: format!("{}-{started_at}", std::process::id()),
            retention_ms,
            max_frames,
            max_bytes,
            sample_seq: 0,
            frames: VecDeque::new(),
            retained_bytes: 0,
            evicted_through_seq: None,
        }
    }

    pub fn record(
        &mut self,
        at_unix_ms: u64,
        collector: &ObserverContext,
        sources: ReplaySources,
    ) -> Result<bool, String> {
        self.record_with_explore(at_unix_ms, collector, sources, None)
    }

    pub fn record_with_explore(
        &mut self,
        at_unix_ms: u64,
        collector: &ObserverContext,
        sources: ReplaySources,
        explore: Option<ExploreSnapshot>,
    ) -> Result<bool, String> {
        self.expire(at_unix_ms);
        if self
            .frames
            .back()
            .is_some_and(|last| at_unix_ms <= last.frame.at_unix_ms)
        {
            return Ok(false);
        }
        let prepared = Self::prepare_frame(at_unix_ms, collector, sources, explore)?;
        self.record_prepared(prepared)
    }

    pub fn prepare_frame(
        at_unix_ms: u64,
        collector: &ObserverContext,
        sources: ReplaySources,
        mut explore: Option<ExploreSnapshot>,
    ) -> Result<PreparedReplayFrame, String> {
        let mut source_errors = BTreeMap::new();
        let mut source_available = BTreeMap::new();
        let mut source_meta = BTreeMap::from([
            ("counters".to_owned(), sources.counters.meta.clone()),
            ("stats".to_owned(), sources.stats.meta.clone()),
            ("system".to_owned(), sources.system.meta.clone()),
        ]);
        for (name, meta, observed, active_required, extra_error) in [
            (
                "counters",
                &sources.counters.meta,
                &sources.counters.collector,
                true,
                None,
            ),
            (
                "stats",
                &sources.stats.meta,
                &sources.stats.collector,
                true,
                sources.stats.error.as_deref().or_else(|| {
                    sources
                        .stats
                        .metrics
                        .is_none()
                        .then_some("Mitosis stats payload is unavailable")
                }),
            ),
            (
                "system",
                &sources.system.meta,
                &sources.system.collector,
                false,
                None,
            ),
        ] {
            let error = source_error(meta, observed, collector, at_unix_ms, active_required)
                .or_else(|| extra_error.map(str::to_owned));
            source_available.insert(name.to_owned(), error.is_none());
            if let Some(error) = error {
                source_errors.insert(name.to_owned(), error);
            }
        }
        let mut signals = project_signals(&sources, &source_available);
        if let Some(explore) = explore.as_mut() {
            explore.mask_incompatible_probes(collector);
            source_meta.insert("explore".into(), explore.meta.clone());
            let mut any_available = false;
            for (name, group) in &mut explore.groups {
                let source = format!("explore.{name}");
                source_meta.insert(source.clone(), group.meta.clone());
                let error = if !group.available {
                    Some(
                        group
                            .error
                            .clone()
                            .unwrap_or_else(|| "Explore source is unavailable".into()),
                    )
                } else if let Some(error) = &group.meta.error {
                    Some(error.clone())
                } else if group.meta.sample_seq == 0 || group.meta.captured_at_unix_ms.is_none() {
                    Some("Explore source has no successful measurement".into())
                } else if group
                    .meta
                    .captured_at_unix_ms
                    .is_some_and(|captured| captured > at_unix_ms)
                {
                    Some("Explore source capture time is in the future".into())
                } else {
                    None
                };
                let available = error.is_none();
                any_available |= available;
                source_available.insert(source.clone(), available);
                if let Some(summary) = group.summary.as_object() {
                    for (field, value) in summary {
                        if value.is_number() || value.is_null() {
                            signals.insert(
                                format!("{source}.{field}"),
                                if available {
                                    if memory_signal_field(name, field) {
                                        nonnegative(value.as_f64())
                                    } else {
                                        finite(value.as_f64())
                                    }
                                } else {
                                    None
                                },
                            );
                        }
                    }
                }
                project_explore_memory_signals(name, group, available, &mut signals);
                if let Some(error) = error {
                    source_errors.insert(source, error.clone());
                    group.available = false;
                    group.error = Some(error.clone());
                    group.meta.error = Some(error);
                    group.summary = serde_json::json!({});
                    group.rows.clear();
                }
            }
            source_available.insert("explore".into(), any_available);
        }
        // Defensive for other callers too: drop the owned lifetime array before
        // serialization, rather than constructing an enormous temporary JSON.
        let mut counter_source = sources.counters;
        counter_source.migrations = Vec::new();
        let mut counters =
            serde_json::to_value(counter_source).map_err(|error| error.to_string())?;
        if let Some(error) = source_errors.get("counters") {
            unavailable_counters(&mut counters, error);
        }
        let mut stats = serde_json::to_value(&sources.stats).map_err(|error| error.to_string())?;
        if let Some(error) = source_errors.get("stats") {
            stats["metrics"] = Value::Null;
            stats["cpu_cells"] = Value::Null;
            stats["error"] = Value::String(error.clone());
            stats["cpu_cells_error"] = Value::String(error.clone());
        }
        let mut system =
            serde_json::to_value(&sources.system).map_err(|error| error.to_string())?;
        if let Some(error) = source_errors.get("system") {
            unavailable_system(&mut system, error);
        }
        let mut config =
            serde_json::to_value(&sources.config).map_err(|error| error.to_string())?;
        if !sources.config.available {
            if let Some(error) = &sources.config.error {
                source_errors.insert("config".into(), error.clone());
            }
        } else if let Some(error) = source_errors.get("counters") {
            config = serde_json::to_value(SchedulerConfigSnapshot::default())
                .map_err(|error| error.to_string())?;
            config["error"] = Value::String(error.clone());
            source_errors.insert("config".into(), error.clone());
        }
        let mut full_sources = serde_json::json!({"counters": counters, "stats": stats, "system": system, "config": config});
        if let Some(explore) = explore {
            full_sources["explore"] =
                serde_json::to_value(explore).map_err(|error| error.to_string())?;
        }
        let encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
        let mut buffered = BufWriter::with_capacity(64 * 1024, encoder);
        serde_json::to_writer(&mut buffered, &full_sources)
            .map_err(|error| format!("encoding replay: {error}"))?;
        let compressed_sources = buffered
            .into_inner()
            .map_err(|error| format!("encoding replay: {error}"))?
            .finish()
            .map_err(|error| format!("compressing replay: {error}"))?
            // Keep each retained allocation at its compressed length; unused
            // Vec capacity must not accumulate outside the payload byte budget.
            .into_boxed_slice();
        Ok(PreparedReplayFrame(StoredFrame {
            frame: ReplayFrame {
                seq: 0,
                at_unix_ms,
                epochs: source_meta
                    .iter()
                    .map(|(source, meta)| (source.clone(), meta.epoch))
                    .collect(),
                source_meta,
                source_available,
                signals,
            },
            collector: collector.clone(),
            source_errors,
            compressed_sources,
        }))
    }

    pub fn record_prepared(&mut self, prepared: PreparedReplayFrame) -> Result<bool, String> {
        let mut stored = prepared.0;
        let at_unix_ms = stored.frame.at_unix_ms;
        self.expire(at_unix_ms);
        if self
            .frames
            .back()
            .is_some_and(|last| at_unix_ms <= last.frame.at_unix_ms)
        {
            return Ok(false);
        }
        if stored.compressed_sources.len() > self.max_bytes {
            return Err("replay snapshot exceeds the retained byte limit".into());
        }
        let seq = self
            .sample_seq
            .checked_add(1)
            .ok_or("replay sequence exhausted")?;
        self.sample_seq = seq;
        stored.frame.seq = seq;
        self.retained_bytes += stored.compressed_sources.len();
        self.frames.push_back(stored);
        while self.frames.len() > self.max_frames || self.retained_bytes > self.max_bytes {
            self.evict_oldest();
        }
        Ok(true)
    }

    pub fn timeline(
        &mut self,
        query: &ReplayQuery,
        now_unix_ms: u64,
    ) -> Result<ReplayTimeline, String> {
        let cursor = match (&query.instance_id, query.after_seq) {
            (None, None) => None,
            (Some(instance), Some(seq)) if !instance.is_empty() => Some((instance.as_str(), seq)),
            _ => return Err("instance_id and after_seq must be supplied together".into()),
        };
        self.expire(now_unix_ms);
        let reset = cursor.is_none_or(|(instance, seq)| {
            instance != self.instance_id
                || seq > self.sample_seq
                || self
                    .evicted_through_seq
                    .is_some_and(|evicted| seq <= evicted)
        });
        let (oldest_at_unix_ms, latest_at_unix_ms) = self.bounds();
        Ok(ReplayTimeline {
            instance_id: self.instance_id.clone(),
            retention_ms: self.retention_ms,
            now_unix_ms,
            oldest_at_unix_ms,
            latest_at_unix_ms,
            sample_seq: self.sample_seq,
            reset,
            frames: self
                .frames
                .iter()
                .filter(|stored| reset || query.after_seq.is_none_or(|seq| stored.frame.seq > seq))
                .map(|stored| stored.frame.clone())
                .collect(),
        })
    }

    pub fn view(&mut self, at: Option<u64>, now_ms: u64) -> Result<ReplayView, String> {
        self.select_view(at, now_ms)?.decode()
    }

    pub fn select_view(
        &mut self,
        at: Option<u64>,
        now_ms: u64,
    ) -> Result<SelectedReplayView, String> {
        self.expire(now_ms);
        let stored = self
            .frames
            .iter()
            .rev()
            .find(|stored| at.is_none_or(|at| stored.frame.at_unix_ms <= at))
            .ok_or_else(|| {
                if self.frames.is_empty() {
                    "replay has no retained samples".to_owned()
                } else {
                    "requested time is before the oldest retained sample".to_owned()
                }
            })?;
        let (oldest_at_unix_ms, latest_at_unix_ms) = self.bounds();
        Ok(SelectedReplayView {
            compressed_sources: stored.compressed_sources.clone(),
            view: ReplayView {
                instance_id: self.instance_id.clone(),
                retention_ms: self.retention_ms,
                requested_at_unix_ms: at,
                at_unix_ms: stored.frame.at_unix_ms,
                oldest_at_unix_ms,
                latest_at_unix_ms,
                now_unix_ms: now_ms,
                collector: stored.collector.clone(),
                sources: Value::Null,
                migrations: None,
                source_errors: stored.source_errors.clone(),
            },
        })
    }

    pub fn clear(&mut self) {
        self.frames.clear();
        self.retained_bytes = 0;
        self.evicted_through_seq = Some(self.sample_seq);
    }

    pub fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }

    pub fn bounds(&self) -> (Option<u64>, Option<u64>) {
        (
            self.frames.front().map(|stored| stored.frame.at_unix_ms),
            self.frames.back().map(|stored| stored.frame.at_unix_ms),
        )
    }

    fn expire(&mut self, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(self.retention_ms);
        while self
            .frames
            .front()
            .is_some_and(|stored| stored.frame.at_unix_ms < cutoff)
        {
            self.evict_oldest();
        }
    }

    fn evict_oldest(&mut self) {
        if let Some(stored) = self.frames.pop_front() {
            self.retained_bytes -= stored.compressed_sources.len();
            self.evicted_through_seq = Some(stored.frame.seq);
        }
    }
}

fn memory_signal_field(group: &str, field: &str) -> bool {
    matches!(
        (group, field),
        ("bandwidth", "mbm_total_bps" | "mbm_local_bps")
            | (
                "perf",
                "cache_references_per_second" | "cache_misses_per_second" | "cache_miss_pct"
            )
    )
}

/// LLC signals share their group's capture metadata. The producer supplies the
/// concurrently counted, weighted percentages; projection never averages them.
fn project_explore_memory_signals(
    name: &str,
    group: &ExploreGroup,
    available: bool,
    signals: &mut BTreeMap<String, Option<f64>>,
) {
    let (rows, id_field, fields): (&[Value], &str, &[(&str, Option<&str>)]) = match name {
        "bandwidth" => (
            &group.rows,
            "llc",
            &[
                ("mbm_total_bps", Some("total_status")),
                ("mbm_local_bps", Some("local_status")),
            ],
        ),
        "perf" => (
            group
                .summary
                .get("llcs")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or_default(),
            "llc_id",
            &[
                ("cache_references_per_second", None),
                ("cache_misses_per_second", None),
                ("cache_miss_pct", None),
            ],
        ),
        _ => return,
    };
    let mut llcs = BTreeMap::<u32, Option<&Value>>::new();
    for row in rows {
        let Some(id) = row
            .get(id_field)
            .and_then(Value::as_u64)
            .and_then(|id| u32::try_from(id).ok())
        else {
            continue;
        };
        // LLC 0 is valid. Unknown IDs never become array indexes, and duplicate
        // IDs mask every reading for that LLC instead of choosing a row.
        llcs.entry(id)
            .and_modify(|known| *known = None)
            .or_insert(Some(row));
    }
    for (id, row) in llcs {
        for &(field, status) in fields {
            let value = row
                .filter(|row| {
                    available
                        && row
                            .get("available")
                            .is_none_or(|value| value.as_bool() == Some(true))
                        && row
                            .get("topology_available")
                            .is_none_or(|value| value.as_bool() == Some(true))
                        && status.is_none_or(|status| {
                            row.get(status)
                                .is_none_or(|value| value.as_str() == Some("measured"))
                        })
                })
                .and_then(|row| nonnegative(row.get(field).and_then(Value::as_f64)));
            signals.insert(format!("explore.{name}.llc.{id}.{field}"), value);
        }
    }
}

fn nonnegative(value: Option<f64>) -> Option<f64> {
    finite(value).filter(|value| *value >= 0.0)
}

fn source_error(
    meta: &SampleMeta,
    observed: &ObserverContext,
    expected: &ObserverContext,
    at_ms: u64,
    active_required: bool,
) -> Option<String> {
    if meta.epoch != expected.epoch || observed != expected {
        return Some("source belongs to a different observer epoch or scheduler context".into());
    }
    if active_required && expected.status != CollectorStatus::Active {
        return Some(
            expected
                .error
                .clone()
                .unwrap_or_else(|| format!("Mitosis observer is {:?}", expected.status)),
        );
    }
    if let Some(error) = &meta.error {
        return Some(error.clone());
    }
    if active_required {
        if let Some(error) = &observed.error {
            return Some(error.clone());
        }
    }
    if meta.sample_seq == 0 || meta.captured_at_unix_ms.is_none() {
        return Some("source has no captured sample".into());
    }
    if meta
        .captured_at_unix_ms
        .is_some_and(|capture| capture > at_ms)
    {
        return Some("source capture is after the selected observation".into());
    }
    None
}

fn unavailable_counters(value: &mut Value, error: &str) {
    value["error"] = Value::String(error.into());
    for key in [
        "counters",
        "callback_timings",
        "scheduler_timings",
        "migrations",
        "cpu_runtime",
        "cpu_capacity_loss",
        "bpf_program_stats",
        "inspector_bpf_program_stats",
        "scheduler_events",
        "softirqs",
        "interrupt_cpu",
        "probe_manifest",
    ] {
        value[key] = serde_json::json!([]);
    }
    for key in ["dsq_metrics", "block_io", "hardirqs"] {
        value[key]["available"] = Value::Bool(false);
    }
    value["hardirqs"]["rows"] = serde_json::json!([]);
    value["dsq_metrics"]["residence_buckets"] = serde_json::json!([]);
    value["block_io"]["latency_buckets"] = serde_json::json!([]);
    value["inspector_bpf_cpu_equivalent_pct"] = Value::Null;
    value["inspector_bpf_host_capacity_pct"] = Value::Null;
    value["migration_quality"] = Value::String("unavailable".into());
}

fn unavailable_system(value: &mut Value, error: &str) {
    value["error"] = Value::String(error.into());
    for key in ["cpu", "memory", "network", "frequencies", "sched_ext"] {
        value[key]["available"] = Value::Bool(false);
        value[key]["value"] = Value::Null;
        value[key]["error"] = Value::String(error.into());
    }
    for key in ["cpu", "memory", "io"] {
        value["pressure"][key]["available"] = Value::Bool(false);
        value["pressure"][key]["value"] = Value::Null;
        value["pressure"][key]["error"] = Value::String(error.into());
    }
}

fn finite(value: Option<f64>) -> Option<f64> {
    value.filter(|value| value.is_finite())
}

fn mean(values: impl IntoIterator<Item = f64>) -> Option<f64> {
    let values: Vec<_> = values
        .into_iter()
        .filter(|value| value.is_finite())
        .collect();
    (!values.is_empty())
        .then(|| values.iter().sum::<f64>() / values.len() as f64)
        .and_then(|value| finite(Some(value)))
}

fn sum(values: impl IntoIterator<Item = Option<f64>>) -> Option<f64> {
    let values: Vec<_> = values
        .into_iter()
        .flatten()
        .filter(|value| value.is_finite())
        .collect();
    (!values.is_empty())
        .then(|| values.iter().sum::<f64>())
        .and_then(|value| finite(Some(value)))
}

fn available_value<T>(source: &MetricSource<T>) -> Option<&T> {
    (source.available && source.error.is_none())
        .then_some(source.value.as_ref())
        .flatten()
}

fn pressure(source: &MetricSource<PsiStats>) -> Option<f64> {
    finite(available_value(source).and_then(|value| value.some.map(|some| some.avg10)))
}

fn project_signals(
    sources: &ReplaySources,
    available: &BTreeMap<String, bool>,
) -> BTreeMap<String, Option<f64>> {
    let mut signals: BTreeMap<_, _> = [
        "callbacks.task_cpu",
        "callbacks.irq_cpu",
        "callbacks.other_cpu",
        "callbacks.callbacks",
        "callbacks.wakeup_p95_us",
        "callbacks.dsq_average",
        "callbacks.dsq_max",
        "callbacks.inspector_cpu",
        "callbacks.inspector_host",
        "system.cpu",
        "system.memory",
        "system.io",
        "system.mhz",
        "system.rx",
        "system.tx",
        "system.total",
        "system.completions",
        "system.mib",
        "migration.same_core",
        "migration.same_llc",
        "migration.cross_llc",
        "migration.cross_numa",
    ]
    .into_iter()
    .map(|key| (key.to_owned(), None))
    .collect();
    if available["counters"] {
        let counters = &sources.counters;
        let irq: BTreeMap<_, _> = counters
            .interrupt_cpu
            .iter()
            .map(|row| {
                (
                    row.cpu,
                    finite(Some(row.total_utilization_pct)).unwrap_or(0.0),
                )
            })
            .collect();
        let loss: BTreeMap<_, _> = counters
            .cpu_capacity_loss
            .iter()
            .map(|row| {
                (
                    row.cpu,
                    finite(Some(row.total_utilization_pct)).unwrap_or(0.0),
                )
            })
            .collect();
        signals.insert(
            "callbacks.task_cpu".into(),
            mean(counters.cpu_runtime.iter().map(|row| {
                if row.utilization_pct.is_finite() {
                    (row.utilization_pct
                        - irq.get(&row.cpu).copied().unwrap_or(0.0)
                        - loss.get(&row.cpu).copied().unwrap_or(0.0))
                    .max(0.0)
                } else {
                    f64::NAN
                }
            })),
        );
        signals.insert(
            "callbacks.irq_cpu".into(),
            mean(
                counters
                    .interrupt_cpu
                    .iter()
                    .map(|row| row.total_utilization_pct),
            ),
        );
        signals.insert(
            "callbacks.other_cpu".into(),
            mean(
                counters
                    .cpu_capacity_loss
                    .iter()
                    .map(|row| row.total_utilization_pct),
            ),
        );
        signals.insert(
            "callbacks.callbacks".into(),
            finite(Some(
                counters
                    .counters
                    .iter()
                    .map(|row| row.rate_per_second)
                    .sum(),
            )),
        );
        signals.insert(
            "callbacks.wakeup_p95_us".into(),
            counters
                .scheduler_timings
                .iter()
                .find(|row| row.metric == "wakeup_to_running")
                .and_then(|row| row.p95_ns.map(|value| value as f64 / 1_000.0)),
        );
        signals.insert(
            "callbacks.dsq_average".into(),
            finite(
                counters
                    .dsq_metrics
                    .available
                    .then_some(counters.dsq_metrics.depth_average)
                    .flatten(),
            ),
        );
        signals.insert(
            "callbacks.dsq_max".into(),
            counters
                .dsq_metrics
                .available
                .then_some(counters.dsq_metrics.depth_latest_max as f64),
        );
        signals.insert(
            "callbacks.inspector_cpu".into(),
            finite(counters.inspector_bpf_cpu_equivalent_pct),
        );
        signals.insert(
            "callbacks.inspector_host".into(),
            finite(counters.inspector_bpf_host_capacity_pct),
        );
        signals.insert("system.total".into(), signals["callbacks.irq_cpu"]);
        signals.insert(
            "system.completions".into(),
            finite(
                counters
                    .block_io
                    .available
                    .then_some(counters.block_io.completion_rate_per_second),
            ),
        );
        signals.insert(
            "system.mib".into(),
            finite(
                counters
                    .block_io
                    .available
                    .then_some(counters.block_io.completed_bytes_per_second / (1024.0 * 1024.0)),
            ),
        );
    }
    if available["system"] {
        let system = &sources.system;
        signals.insert("system.cpu".into(), pressure(&system.pressure.cpu));
        signals.insert("system.memory".into(), pressure(&system.pressure.memory));
        signals.insert("system.io".into(), pressure(&system.pressure.io));
        signals.insert(
            "system.mhz".into(),
            available_value(&system.frequencies)
                .and_then(|value| value.average_khz.map(|khz| khz as f64 / 1_000.0)),
        );
        let interfaces = available_value(&system.network)
            .map(|network| network.interfaces.as_slice())
            .unwrap_or_default();
        signals.insert(
            "system.rx".into(),
            sum(interfaces.iter().map(|row| row.rx_bytes_per_second)),
        );
        signals.insert(
            "system.tx".into(),
            sum(interfaces.iter().map(|row| row.tx_bytes_per_second)),
        );
    }
    if available["stats"] {
        if let Some(cells) = sources
            .stats
            .metrics
            .as_ref()
            .and_then(|metrics| metrics.get("cells"))
            .and_then(Value::as_object)
        {
            for (id, cell) in cells {
                let value = |key| finite(cell.get(key).and_then(Value::as_f64));
                let capacity = value("num_cpus");
                let interval = value("util_pct");
                signals.insert(
                    format!("cell.{id}.util"),
                    interval.or_else(|| value("smoothed_util_pct")),
                );
                signals.insert(format!("cell.{id}.assigned_cpus"), capacity);
                signals.insert(
                    format!("cell.{id}.used_cpus"),
                    finite(
                        capacity
                            .filter(|capacity| *capacity > 0.0)
                            .zip(interval)
                            .map(|(capacity, utilization)| capacity * utilization / 100.0),
                    ),
                );
            }
        }
    }
    signals
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collector::CollectorConfig;
    use crate::lifecycle::CollectorStatus;
    use crate::system_stats::{MetricSource, PsiLine, PsiStats, SystemStatsCollector};
    use crate::{
        CallbackCounter, CpuCapacityLossRow, CpuRuntimeRow, InterruptCpuRow, TimingMetricRow,
    };
    use serde_json::json;

    fn active(epoch: u64) -> ObserverContext {
        ObserverContext {
            epoch,
            status: CollectorStatus::Active,
            scheduler_enable_seq: Some(epoch),
            scheduler_name: Some("mitosis".into()),
            error: None,
        }
    }

    fn sources(epoch: u64, seq: u64, at: u64) -> ReplaySources {
        let meta = SampleMeta {
            epoch,
            sample_seq: seq,
            captured_at_unix_ms: Some(at),
            last_success_at_unix_ms: Some(at),
            error: None,
        };
        let mut counters = Snapshot::empty(CollectorConfig {
            callback_timing_sample_rate: 1024,
            event_timing_sample_rate: 64,
            enable_dsq: true,
            enable_scheduler_events: true,
            enable_irqs: true,
            enable_block_io: true,
        });
        counters.meta = meta.clone();
        counters.collector = active(epoch);
        counters.counters = vec![CallbackCounter {
            name: "enqueue",
            count: seq * 100,
            rate_per_second: 7.0,
        }];
        counters.cpu_runtime = vec![CpuRuntimeRow {
            cpu: 0,
            runtime_ns: 800,
            utilization_pct: 80.0,
        }];
        counters.interrupt_cpu = vec![InterruptCpuRow {
            cpu: 0,
            hardirq_utilization_pct: 4.0,
            softirq_utilization_pct: 6.0,
            total_utilization_pct: 10.0,
        }];
        counters.cpu_capacity_loss = vec![CpuCapacityLossRow {
            cpu: 0,
            rt_stop_utilization_pct: 2.0,
            deadline_utilization_pct: 2.0,
            steal_utilization_pct: 1.0,
            total_utilization_pct: 5.0,
        }];
        counters.scheduler_timings = vec![TimingMetricRow {
            metric: "wakeup_to_running",
            samples: 9,
            buckets: vec![0, 4, 5],
            mean_ns: Some(90_000),
            p50_ns: Some(80_000),
            p95_ns: Some(120_000),
            p99_ns: None,
        }];
        counters.dsq_metrics.available = true;
        counters.dsq_metrics.depth_average = Some(3.0);
        counters.dsq_metrics.depth_latest_max = 4;
        counters.inspector_bpf_cpu_equivalent_pct = Some(0.2);
        counters.inspector_bpf_host_capacity_pct = Some(0.1);
        counters.block_io.available = true;
        counters.block_io.completion_rate_per_second = 3.0;
        counters.block_io.completed_bytes_per_second = 8.0 * 1024.0 * 1024.0;
        let stats = StatsSnapshot {
            meta: meta.clone(),
            collector: active(epoch),
            metrics: Some(json!({"rebalance_count": seq, "cells": {
                "0": {"num_cpus": 20, "util_pct": 25.0, "smoothed_util_pct": 40.0, "lent_pct": 7.5},
                "1": {"num_cpus": 3, "smoothed_util_pct": 45.0}
            }})),
            error: None,
            cpu_cells: Some(BTreeMap::from([(0, 0), (1, 1)])),
            cpu_cells_error: None,
        };
        let mut system = SystemStatsCollector::new().collect();
        system.meta = meta;
        system.collector = active(epoch);
        system.captured_at_unix_ms = at;
        let pressure = |value| MetricSource {
            available: true,
            value: Some(PsiStats {
                some: Some(PsiLine {
                    avg10: value,
                    avg60: 0.0,
                    avg300: 0.0,
                    total_us: 100,
                }),
                full: None,
            }),
            error: None,
        };
        system.pressure.cpu = pressure(12.5);
        system.pressure.memory = pressure(2.3);
        system.pressure.io = pressure(1.2);
        if let Some(frequencies) = system.frequencies.value.as_mut() {
            frequencies.average_khz = Some(3_000_000);
        }
        ReplaySources {
            counters,
            stats,
            system,
            config: SchedulerConfigSnapshot::default(),
        }
    }

    fn record(history: &mut ReplayHistory, epoch: u64, seq: u64, at: u64) {
        assert!(history
            .record(at, &active(epoch), sources(epoch, seq, at))
            .unwrap());
    }

    fn timeline(history: &mut ReplayHistory, now: u64) -> ReplayTimeline {
        history.timeline(&ReplayQuery::default(), now).unwrap()
    }

    #[test]
    fn replay_decodes_full_historical_sources_including_histograms_owners_and_borrowing() {
        let mut history = ReplayHistory::new();
        record(&mut history, 1, 1, 1_000);
        let view = history.view(None, 1_000).unwrap();
        assert_eq!(
            view.sources["counters"]["scheduler_timings"][0]["buckets"],
            json!([0, 4, 5])
        );
        assert_eq!(view.sources["stats"]["cpu_cells"], json!({"0": 0, "1": 1}));
        assert_eq!(
            view.sources["stats"]["metrics"]["cells"]["0"]["lent_pct"],
            7.5
        );
        assert_eq!(
            view.sources["config"]["error"],
            "waiting for Mitosis scheduler discovery"
        );
        assert!(history.retained_bytes() > 0);
    }

    #[test]
    fn replay_roundtrips_large_escaped_and_unicode_source_payloads() {
        let mut history = ReplayHistory::new();
        let mut sample = sources(1, 1, 1_000);
        let payload = "capture\t測定 → \"sample\"\n".repeat(8_192);
        sample.stats.metrics = Some(json!({
            "payload": payload,
            "tail": [1, null, "complete"]
        }));
        assert!(history.record(1_000, &active(1), sample).unwrap());

        let view = history.view(None, 1_000).unwrap();
        assert_eq!(
            view.sources["stats"]["metrics"]["payload"].as_str(),
            Some(payload.as_str())
        );
        assert_eq!(
            view.sources["stats"]["metrics"]["tail"],
            json!([1, null, "complete"])
        );
    }

    #[test]
    fn scalar_projection_matches_current_chart_formulas_and_only_utilization_uses_fallback() {
        let mut history = ReplayHistory::new();
        record(&mut history, 1, 1, 1_000);
        let frames = timeline(&mut history, 1_000).frames;
        let signals = &frames[0].signals;
        for (key, expected) in [
            ("callbacks.task_cpu", 65.0),
            ("callbacks.irq_cpu", 10.0),
            ("callbacks.other_cpu", 5.0),
            ("callbacks.callbacks", 7.0),
            ("callbacks.wakeup_p95_us", 120.0),
            ("callbacks.dsq_average", 3.0),
            ("callbacks.dsq_max", 4.0),
            ("callbacks.inspector_cpu", 0.2),
            ("callbacks.inspector_host", 0.1),
            ("system.cpu", 12.5),
            ("system.memory", 2.3),
            ("system.io", 1.2),
            ("system.total", 10.0),
            ("system.completions", 3.0),
            ("system.mib", 8.0),
            ("cell.0.util", 25.0),
            ("cell.0.used_cpus", 5.0),
            ("cell.0.assigned_cpus", 20.0),
            ("cell.1.util", 45.0),
        ] {
            assert_eq!(signals.get(key), Some(&Some(expected)), "{key}");
        }
        assert_eq!(signals.get("cell.1.used_cpus"), Some(&None));
        assert_eq!(
            frames[0].source_meta["stats"].captured_at_unix_ms,
            Some(1_000)
        );
        assert!(frames[0].source_available["stats"]);
        let json = serde_json::to_value(&frames).unwrap();
        assert!(json[0].get("sources").is_none());
    }

    #[test]
    fn missing_stats_payload_is_unavailable_even_with_successful_metadata() {
        let mut history = ReplayHistory::new();
        let mut sample = sources(1, 1, 1_000);
        sample.stats.metrics = None;
        assert!(history.record(1_000, &active(1), sample).unwrap());
        let frame = timeline(&mut history, 1_000).frames.remove(0);
        assert!(!frame.source_available["stats"]);
        assert!(history
            .view(None, 1_000)
            .unwrap()
            .source_errors
            .contains_key("stats"));
    }

    #[test]
    fn invalid_cpu_measurements_are_missing_rather_than_clamped_to_zero() {
        let mut history = ReplayHistory::new();
        let mut sample = sources(1, 1, 1_000);
        sample.counters.cpu_runtime[0].utilization_pct = f64::NAN;
        assert!(history.record(1_000, &active(1), sample).unwrap());
        let frame = timeline(&mut history, 1_000).frames.remove(0);
        assert_eq!(frame.signals["callbacks.task_cpu"], None);
    }

    #[test]
    fn old_epochs_remain_selectable_and_global_sequences_continue() {
        let mut history = ReplayHistory::new();
        record(&mut history, 1, 9, 1_000);
        record(&mut history, 2, 1, 2_000);
        let view = timeline(&mut history, 2_000);
        assert_eq!(
            view.frames
                .iter()
                .map(|frame| frame.seq)
                .collect::<Vec<_>>(),
            [1, 2]
        );
        assert_eq!(view.frames[0].epochs["counters"], 1);
        assert_eq!(view.frames[1].epochs["counters"], 2);
        assert_eq!(history.view(Some(1_500), 2_000).unwrap().collector.epoch, 1);
    }

    #[test]
    fn selection_floors_without_future_values_and_rejects_expired_times() {
        let mut history = ReplayHistory::new();
        record(&mut history, 1, 1, 1_000);
        record(&mut history, 1, 2, 2_000);
        assert_eq!(history.view(Some(1_999), 2_000).unwrap().at_unix_ms, 1_000);
        assert_eq!(history.view(Some(10_000), 2_000).unwrap().at_unix_ms, 2_000);
        assert!(history.view(Some(999), 2_000).is_err());
    }

    #[test]
    fn failed_cached_stats_and_cross_epoch_sources_are_unavailable_without_fabricated_points() {
        let mut history = ReplayHistory::new();
        let mut sample = sources(1, 1, 1_000);
        sample.stats.error = Some("socket closed".into());
        sample.stats.meta.error = Some("socket closed".into());
        assert!(history.record(2_000, &active(1), sample).unwrap());
        let frame = timeline(&mut history, 2_000).frames.remove(0);
        assert!(!frame.source_available["stats"]);
        assert_eq!(frame.source_meta["stats"].captured_at_unix_ms, Some(1_000));
        assert!(frame.signals.get("cell.0.util").is_none_or(Option::is_none));
        let view = history.view(None, 2_000).unwrap();
        assert_eq!(view.source_errors["stats"], "socket closed");
        assert!(view.sources["stats"]["metrics"].is_null());

        assert!(history
            .record(3_000, &active(2), sources(1, 2, 2_000))
            .unwrap());
        let view = history.view(None, 3_000).unwrap();
        assert!(view.sources["stats"]["metrics"].is_null());
        assert!(view.sources["counters"]["counters"]
            .as_array()
            .unwrap()
            .is_empty());
        assert!(view.source_errors.contains_key("counters"));
    }

    #[test]
    fn source_samples_from_the_future_are_rejected_but_host_metrics_work_while_scheduler_waits() {
        let mut history = ReplayHistory::new();
        assert!(history
            .record(1_000, &active(1), sources(1, 1, 1_100))
            .unwrap());
        let frame = timeline(&mut history, 1_000).frames.remove(0);
        assert!(!frame.source_available["counters"]);
        assert!(!frame.source_available["stats"]);
        assert!(!frame.source_available["system"]);
        let mut waiting = active(1);
        waiting.status = CollectorStatus::Waiting;
        let mut sample = sources(1, 2, 2_000);
        sample.system.collector = waiting.clone();
        assert!(history.record(2_000, &waiting, sample).unwrap());
        let frame = timeline(&mut history, 2_000).frames.remove(1);
        assert!(!frame.source_available["counters"]);
        assert!(frame.source_available["system"]);
        assert_eq!(frame.signals["system.cpu"], Some(12.5));
    }

    #[test]
    fn cursors_are_incremental_and_invalid_or_evicted_instances_reset() {
        let mut history = ReplayHistory::new();
        record(&mut history, 1, 1, 1_000);
        let first = timeline(&mut history, 1_000);
        record(&mut history, 1, 2, 2_000);
        let mut query = ReplayQuery {
            instance_id: Some(first.instance_id),
            after_seq: Some(first.sample_seq),
            window_ms: None,
        };
        let update = history.timeline(&query, 2_000).unwrap();
        assert!(!update.reset);
        assert_eq!(
            update
                .frames
                .iter()
                .map(|frame| frame.seq)
                .collect::<Vec<_>>(),
            [2]
        );
        query.instance_id = Some("previous process".into());
        assert!(history.timeline(&query, 2_000).unwrap().reset);
        query.after_seq = None;
        assert!(history.timeline(&query, 2_000).is_err());
    }

    #[test]
    fn time_and_count_caps_report_the_actual_available_bounds() {
        let mut history = ReplayHistory::with_limits(2_000, 2, REPLAY_MAX_BYTES);
        record(&mut history, 1, 1, 1_000);
        record(&mut history, 1, 2, 2_000);
        record(&mut history, 1, 3, 3_000);
        let view = timeline(&mut history, 3_000);
        assert_eq!(view.oldest_at_unix_ms, Some(2_000));
        assert_eq!(view.latest_at_unix_ms, Some(3_000));
        let query = ReplayQuery {
            instance_id: Some(view.instance_id),
            after_seq: Some(1),
            window_ms: None,
        };
        assert!(history.timeline(&query, 3_000).unwrap().reset);
        let expired = timeline(&mut history, 5_001);
        assert!(expired.frames.is_empty());
        assert_eq!(expired.oldest_at_unix_ms, None);
        assert_eq!(history.retained_bytes(), 0);
    }

    #[test]
    fn compressed_snapshot_byte_cap_evicts_whole_frames() {
        let mut probe = ReplayHistory::new();
        record(&mut probe, 1, 1, 1_000);
        let budget = probe.retained_bytes() + 100;
        let mut history =
            ReplayHistory::with_limits(REPLAY_RETENTION_MS, REPLAY_MAX_FRAMES, budget);
        record(&mut history, 1, 1, 1_000);
        record(&mut history, 1, 2, 2_000);
        assert!(history.retained_bytes() <= budget);
        let view = timeline(&mut history, 2_000);
        assert_eq!(view.frames.len(), 1);
        assert_eq!(view.latest_at_unix_ms, Some(2_000));
    }

    #[test]
    fn explicit_reset_clears_retention_without_reusing_sequence_numbers() {
        let mut history = ReplayHistory::new();
        record(&mut history, 1, 1, 1_000);
        let first = timeline(&mut history, 1_000);
        history.clear();
        assert!(timeline(&mut history, 1_000).frames.is_empty());
        record(&mut history, 2, 1, 2_000);
        let query = ReplayQuery {
            instance_id: Some(first.instance_id),
            after_seq: Some(first.sample_seq),
            window_ms: None,
        };
        let update = history.timeline(&query, 2_000).unwrap();
        assert!(update.reset);
        assert!(update.frames[0].seq > first.sample_seq);
    }
}
