use std::sync::{mpsc, Arc, RwLock};

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use http_body_util::BodyExt;
use scx_mitosis_inspector::api::{router, ApiContext};
use scx_mitosis_inspector::collector::{CollectorConfig, Snapshot};
use scx_mitosis_inspector::host_context::{HostContextView, HostIdentityView};
use scx_mitosis_inspector::lifecycle::ObserverContext;
use scx_mitosis_inspector::migration_history::MigrationHistory;
use scx_mitosis_inspector::stats::StatsSnapshot;
use scx_mitosis_inspector::system_stats::SystemStatsCollector;
use scx_mitosis_inspector::topology::{CpuInfo, TopologyView};
use tower::ServiceExt;

fn app() -> axum::Router {
    let (commands, _) = mpsc::sync_channel(1);
    let config = CollectorConfig {
        callback_timing_sample_rate: 1024,
        event_timing_sample_rate: 64,
        enable_dsq: true,
        enable_scheduler_events: true,
        enable_irqs: true,
        enable_block_io: true,
    };
    router(ApiContext::new(
        Arc::new(RwLock::new(Snapshot::empty(config))),
        Arc::new(RwLock::new(StatsSnapshot::default())),
        Arc::new(RwLock::new(SystemStatsCollector::new().collect())),
        HostContextView {
            identity: HostIdentityView {
                hostname: "explore-test".into(),
                kernel_release: "6.13.0".into(),
                cpu_count: 1,
            },
            topology: TopologyView::from_cpus(vec![CpuInfo {
                cpu: 2,
                node: 0,
                package: 0,
                llc: 0,
                core: 0,
                core_topology_available: true,
            }])
            .unwrap(),
        },
        Arc::new(RwLock::new(MigrationHistory::new(300_000))),
        10_000,
        commands,
        Arc::new(RwLock::new(ObserverContext::default())),
    ))
}

#[tokio::test]
async fn explore_sections_live_on_scheduling_and_system_with_the_shared_timeline() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/explore")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
    assert_eq!(response.headers()[header::LOCATION], "/scheduling");

    for path in ["/scheduling", "/system"] {
        let response = app()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("id=\"timelineRange\""), "{path}");
        assert!(html.contains("/assets/explore.js"), "{path}");
        assert!(html.contains("/assets/explore.css"), "{path}");
    }
}

#[tokio::test]
async fn explore_reports_all_sources_before_any_supported_measurement() {
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/api/explore")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    for name in [
        "dsqs",
        "tasks",
        "perf",
        "bandwidth",
        "wakers",
        "scx_events",
        "ipis",
        "idle",
        "pressure",
        "thermal",
        "power",
    ] {
        assert_eq!(value["groups"][name]["available"], false, "{name}");
        assert!(
            value["groups"][name]["error"]
                .as_str()
                .is_some_and(|error| !error.is_empty()),
            "{name}"
        );
        assert!(
            value["groups"][name]["rows"].as_array().unwrap().is_empty(),
            "{name}"
        );
    }
}

#[tokio::test]
async fn explore_assets_do_not_cache_old_code() {
    for uri in ["/assets/explore.js", "/assets/explore.css"] {
        let response = app()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{uri}");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }
}
