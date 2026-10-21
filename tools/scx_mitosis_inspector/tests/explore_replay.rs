use scx_mitosis_inspector::collector::{CollectorConfig, Snapshot};
use scx_mitosis_inspector::explore_model::{ExploreGroup, ExploreSnapshot};
use scx_mitosis_inspector::lifecycle::{ObserverContext, SampleMeta};
use scx_mitosis_inspector::replay::{ReplayHistory, ReplayQuery, ReplaySources};
use scx_mitosis_inspector::scheduler_config::SchedulerConfigSnapshot;
use scx_mitosis_inspector::stats::StatsSnapshot;
use scx_mitosis_inspector::system_stats::SystemStatsCollector;
use serde_json::json;

fn sources() -> ReplaySources {
    ReplaySources {
        counters: Snapshot::empty(CollectorConfig {
            callback_timing_sample_rate: 1024,
            event_timing_sample_rate: 64,
            enable_dsq: true,
            enable_scheduler_events: true,
            enable_irqs: true,
            enable_block_io: true,
        }),
        stats: StatsSnapshot::default(),
        system: SystemStatsCollector::new().collect(),
        config: SchedulerConfigSnapshot::default(),
    }
}

fn explore(seq: u64, captured: u64, ipc: f64) -> ExploreSnapshot {
    let mut result = ExploreSnapshot::default();
    result.meta = SampleMeta {
        sample_seq: seq,
        captured_at_unix_ms: Some(captured),
        last_success_at_unix_ms: Some(captured),
        ..SampleMeta::default()
    };
    let mut group = ExploreGroup::available(
        "Whole CPU",
        json!({"ipc": ipc}),
        vec![json!({"cpu":2,"ipc":ipc})],
    );
    group.meta = result.meta.clone();
    result.groups.insert("perf".into(), group);
    result
}

#[test]
fn past_full_views_keep_explore_tables_and_their_original_sample_time() {
    let mut history = ReplayHistory::new();
    let observer = ObserverContext::default();
    history
        .record_with_explore(2_000, &observer, sources(), Some(explore(7, 1_000, 1.5)))
        .unwrap();
    history
        .record_with_explore(4_000, &observer, sources(), Some(explore(8, 3_000, 3.0)))
        .unwrap();
    let selected = history.view(Some(2_500), 4_000).unwrap();
    assert_eq!(
        selected.sources["explore"]["groups"]["perf"]["summary"]["ipc"],
        json!(1.5)
    );
    assert_eq!(
        selected.sources["explore"]["groups"]["perf"]["meta"]["captured_at_unix_ms"],
        1_000
    );
    assert_eq!(
        selected.sources["explore"]["groups"]["perf"]["rows"][0]["cpu"],
        2
    );
}

#[test]
fn explore_graph_frames_preserve_per_group_metadata_and_real_zero_values() {
    let mut history = ReplayHistory::new();
    history
        .record_with_explore(
            2_000,
            &ObserverContext::default(),
            sources(),
            Some(explore(7, 1_000, 0.0)),
        )
        .unwrap();
    let timeline = history.timeline(&ReplayQuery::default(), 2_000).unwrap();
    let frame = &timeline.frames[0];
    assert_eq!(frame.signals.get("explore.perf.ipc"), Some(&Some(0.0)));
    assert_eq!(
        frame
            .source_meta
            .get("explore.perf")
            .map(|meta| meta.sample_seq),
        Some(7)
    );
    assert_eq!(frame.source_available.get("explore.perf"), Some(&true));
}

#[test]
fn future_explore_sources_are_cleared_instead_of_labeled_historical() {
    let mut history = ReplayHistory::new();
    history
        .record_with_explore(
            2_000,
            &ObserverContext::default(),
            sources(),
            Some(explore(7, 3_000, 2.0)),
        )
        .unwrap();
    let selected = history.view(None, 2_000).unwrap();
    assert_eq!(
        selected.sources["explore"]["groups"]["perf"]["available"],
        false
    );
    assert_eq!(
        selected.sources["explore"]["groups"]["perf"]["rows"],
        json!([])
    );
    assert!(selected
        .source_errors
        .get("explore.perf")
        .is_some_and(|error| error.contains("future")));
}
