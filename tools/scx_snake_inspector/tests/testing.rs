// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::path::PathBuf;
use std::{fs, os::unix::fs::PermissionsExt};

use scx_snake_inspector::policies::{discover_policy_files, PolicyCatalog, PolicyChoice};
use scx_snake_inspector::testing::{
    build_matrix, discover_testing_catalog, failure_signature, CaseOutcome, CaseStatus, Fairness,
    MatrixConfig, RunStatus, TestEnvironment, TestRun, TestingController, Workload,
    WorkloadCommand,
};

fn policy(id: &str, queue_policy: bool) -> PolicyChoice {
    PolicyChoice {
        id: id.into(),
        name: id.trim_end_matches(".toml").replace('-', " "),
        source: String::new(),
        rung_count: 1,
        mask_table_count: 0,
        cell_count: usize::from(queue_policy),
        queue_policy,
        summary: String::new(),
    }
}

#[test]
fn matrix_groups_policies_beneath_each_compatible_fairness_mode() {
    let catalog = PolicyCatalog {
        policies: vec![
            policy("basic.toml", false),
            policy("cell-queues.toml", true),
        ],
        invalid: Vec::new(),
    };

    let matrix = build_matrix(&catalog, MatrixConfig::new(60, 0, 1).unwrap());

    assert_eq!(
        matrix.workloads,
        vec![
            Workload::CpuSaturation,
            Workload::WakerWakee,
            Workload::MixedAffinity,
            Workload::ForkYield,
        ]
    );
    assert_eq!(
        matrix
            .groups
            .iter()
            .map(|group| (group.fairness, group.rows.len()))
            .collect::<Vec<_>>(),
        vec![
            (Fairness::Fifo, 1),
            (Fairness::Vtime, 2),
            (Fairness::Eevdf, 1)
        ]
    );
    assert_eq!(matrix.total_cases, 16);
    assert_eq!(matrix.assigned_cases, 16);
    assert!(matrix.groups[0].rows[0]
        .cases
        .iter()
        .all(|case| case.id.starts_with("fifo/basic.toml/")));
}

#[test]
fn matrix_rejects_short_runs_and_invalid_shards() {
    assert_eq!(
        MatrixConfig::new(59, 0, 1).unwrap_err().to_string(),
        "test duration must be at least 60 seconds"
    );
    assert_eq!(
        MatrixConfig::new(60, 1, 1).unwrap_err().to_string(),
        "shard index 1 is outside 1 shards"
    );
    assert_eq!(
        MatrixConfig::new(60, 0, 0).unwrap_err().to_string(),
        "shard count must be greater than zero"
    );
}

#[test]
fn sharding_is_stable_balanced_and_keeps_the_complete_matrix_visible() {
    let catalog = PolicyCatalog {
        policies: vec![
            policy("basic.toml", false),
            policy("cell-queues.toml", true),
        ],
        invalid: Vec::new(),
    };

    let first = build_matrix(&catalog, MatrixConfig::new(60, 0, 3).unwrap());
    let second = build_matrix(&catalog, MatrixConfig::new(60, 0, 3).unwrap());
    let other = build_matrix(&catalog, MatrixConfig::new(60, 1, 3).unwrap());

    assert_eq!(first, second);
    assert_eq!(first.total_cases, 16);
    assert_eq!(first.assigned_cases, 6);
    assert_eq!(other.assigned_cases, 5);
    let first_ids = first
        .groups
        .iter()
        .flat_map(|group| &group.rows)
        .flat_map(|row| &row.cases)
        .filter(|case| case.assigned)
        .map(|case| case.id.as_str())
        .collect::<Vec<_>>();
    let other_ids = other
        .groups
        .iter()
        .flat_map(|group| &group.rows)
        .flat_map(|row| &row.cases)
        .filter(|case| case.assigned)
        .map(|case| case.id.as_str())
        .collect::<Vec<_>>();
    assert!(first_ids.iter().all(|id| !other_ids.contains(id)));
}

#[test]
fn aggregate_view_imports_live_results_from_every_shard() {
    let catalog = PolicyCatalog {
        policies: vec![policy("basic.toml", false)],
        invalid: Vec::new(),
    };
    let root = tempfile::tempdir().unwrap();

    for shard_index in 0..2 {
        let mut run = TestRun::new(build_matrix(
            &catalog,
            MatrixConfig::new(60, shard_index, 2).unwrap(),
        ));
        run.start().unwrap();
        let case_id = run.assigned_jobs()[0].id.clone();
        run.begin_case(&case_id).unwrap();
        run.finish_case(&case_id, CaseOutcome::Passed, 60_123)
            .unwrap();
        let shard_dir = root.path().join(format!("shard-{shard_index}"));
        fs::create_dir_all(&shard_dir).unwrap();
        fs::write(
            shard_dir.join("run.json"),
            serde_json::to_vec_pretty(&run).unwrap(),
        )
        .unwrap();
    }

    let controller = TestingController::new(MatrixConfig::new(60, 0, 2).unwrap())
        .with_catalog(catalog)
        .with_import_dir(root.path());
    let aggregate = controller.snapshot_available(None).unwrap();

    assert_eq!(aggregate.status, RunStatus::Running);
    assert!(aggregate.matrix.aggregate);
    assert_eq!(aggregate.matrix.reporting_shards, 2);
    assert_eq!(
        aggregate.matrix.assigned_cases,
        aggregate.matrix.total_cases
    );
    assert!(aggregate
        .matrix
        .groups
        .iter()
        .flat_map(|group| &group.rows)
        .flat_map(|row| &row.cases)
        .all(|case| case.assigned));
    assert_eq!(
        aggregate
            .matrix
            .groups
            .iter()
            .flat_map(|group| &group.rows)
            .flat_map(|row| &row.cases)
            .filter(|case| case.status == CaseStatus::Passed)
            .count(),
        2
    );
}

#[test]
fn aggregate_view_imports_one_snapshot_per_kernel_campaign() {
    let catalog = PolicyCatalog {
        policies: vec![policy("basic.toml", false)],
        invalid: Vec::new(),
    };
    let root = tempfile::tempdir().unwrap();
    let mut campaigns = Vec::new();

    for kernel in ["6.13-test", "6.16-test"] {
        let campaign_id = format!("campaign-{kernel}");
        let campaign = root.path().join(&campaign_id);
        let shard_dir = campaign.join("shard-0");
        fs::create_dir_all(&shard_dir).unwrap();
        let mut run = TestRun::new(build_matrix(&catalog, MatrixConfig::new(60, 0, 1).unwrap()));
        run.campaign_id = Some(campaign_id);
        run.environment = Some(TestEnvironment {
            kernel_release: kernel.into(),
            snake_version: "scx_snake test".into(),
            snake_fingerprint: "fnv1a64:test".into(),
            virtualization: "kvm".into(),
            cpu_count: 8,
            memory_bytes: 4 * 1024 * 1024 * 1024,
            boot_command: format!("vng --run /boot/vmlinuz-{kernel}"),
        });
        fs::write(
            shard_dir.join("run.json"),
            serde_json::to_vec_pretty(&run).unwrap(),
        )
        .unwrap();
        campaigns.push(campaign);
    }

    let controller = TestingController::new(MatrixConfig::new(60, 0, 1).unwrap())
        .with_catalog(catalog)
        .with_import_dirs(&campaigns);
    let snapshots = controller.snapshots_available(None).unwrap();
    let first = controller.snapshot_available(None).unwrap();

    assert_eq!(snapshots.len(), 2);
    assert_eq!(
        snapshots
            .iter()
            .map(|run| run.environment.as_ref().unwrap().kernel_release.as_str())
            .collect::<Vec<_>>(),
        vec!["6.13-test", "6.16-test"]
    );
    assert!(snapshots.iter().all(|run| run.matrix.aggregate));
    assert_eq!(first.environment.unwrap().kernel_release, "6.13-test");
}

#[test]
fn aggregate_view_rejects_results_from_a_different_shard_layout() {
    let catalog = PolicyCatalog {
        policies: vec![policy("basic.toml", false)],
        invalid: Vec::new(),
    };
    let root = tempfile::tempdir().unwrap();
    let shard_dir = root.path().join("shard-0");
    fs::create_dir_all(&shard_dir).unwrap();
    let run = TestRun::new(build_matrix(&catalog, MatrixConfig::new(60, 0, 3).unwrap()));
    fs::write(
        shard_dir.join("run.json"),
        serde_json::to_vec_pretty(&run).unwrap(),
    )
    .unwrap();

    let controller = TestingController::new(MatrixConfig::new(60, 0, 2).unwrap())
        .with_catalog(catalog)
        .with_import_dir(root.path());

    assert!(controller
        .snapshot_available(None)
        .unwrap_err()
        .to_string()
        .contains("shard count"));
}

#[test]
fn aggregate_view_turns_a_dead_shard_into_terminal_failures() {
    let catalog = PolicyCatalog {
        policies: vec![policy("basic.toml", false)],
        invalid: Vec::new(),
    };
    let root = tempfile::tempdir().unwrap();
    let shard_dir = root.path().join("shard-0");
    fs::create_dir_all(&shard_dir).unwrap();
    let mut run = TestRun::new(build_matrix(&catalog, MatrixConfig::new(60, 0, 1).unwrap()));
    run.start().unwrap();
    let running = run.assigned_jobs()[0].id.clone();
    run.begin_case(&running).unwrap();
    fs::write(
        shard_dir.join("run.json"),
        serde_json::to_vec_pretty(&run).unwrap(),
    )
    .unwrap();
    fs::write(root.path().join("shard-0.exit"), "17\n").unwrap();

    let controller = TestingController::new(MatrixConfig::new(60, 0, 1).unwrap())
        .with_catalog(catalog)
        .with_import_dir(root.path());
    let aggregate = controller.snapshot_available(None).unwrap();

    assert_eq!(aggregate.status, RunStatus::Completed);
    assert!(aggregate
        .matrix
        .groups
        .iter()
        .flat_map(|group| &group.rows)
        .flat_map(|row| &row.cases)
        .all(|case| {
            case.status == CaseStatus::Failed
                && case.failure.as_deref() == Some("VM shard 0 exited with status 17")
        }));
}

#[test]
fn repository_policy_library_expands_to_35_rows_and_140_cases() {
    let policy_dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../scheds/rust/scx_snake/examples");
    let files = discover_policy_files(&policy_dir).unwrap();
    let catalog = PolicyCatalog {
        policies: files
            .into_iter()
            .map(|file| {
                let queue_policy = file.source.lines().any(|line| line.trim() == "[queues]");
                PolicyChoice {
                    id: file.id,
                    name: file.name,
                    source: file.source,
                    rung_count: 0,
                    mask_table_count: 0,
                    cell_count: 0,
                    queue_policy,
                    summary: String::new(),
                }
            })
            .collect(),
        invalid: Vec::new(),
    };

    let matrix = build_matrix(&catalog, MatrixConfig::new(60, 0, 1).unwrap());

    assert_eq!(catalog.policies.len(), 15);
    assert_eq!(
        matrix
            .groups
            .iter()
            .map(|group| group.rows.len())
            .sum::<usize>(),
        35
    );
    assert_eq!(matrix.total_cases, 140);
    assert!(matrix.catalog_fingerprint.starts_with("fnv1a64:"));
}

#[test]
fn failure_signatures_cover_scheduler_stalls_and_kernel_failures_only() {
    for (log, expected) in [
        (
            "sched_ext: runnable task stall pid=42",
            "sched_ext: runnable task stall pid=42",
        ),
        (
            "snake: scx_bpf_error: invalid DSQ",
            "snake: scx_bpf_error: invalid DSQ",
        ),
        (
            "sched_ext: BPF scheduler watchdog triggered",
            "sched_ext: BPF scheduler watchdog triggered",
        ),
        (
            "watchdog: BUG: soft lockup - CPU#2 stuck",
            "watchdog: BUG: soft lockup - CPU#2 stuck",
        ),
        ("kernel panic - not syncing", "kernel panic - not syncing"),
    ] {
        assert_eq!(failure_signature(log), Some(expected));
    }
    assert_eq!(
        failure_signature("snake: attached successfully\nworkload completed"),
        None
    );
    assert_eq!(
        failure_signature("stress-ng: metrics completed without errors"),
        None
    );
}

#[test]
fn run_state_requires_assigned_cases_to_start_before_they_finish() {
    let catalog = PolicyCatalog {
        policies: vec![policy("basic.toml", false)],
        invalid: Vec::new(),
    };
    let matrix = build_matrix(&catalog, MatrixConfig::new(60, 0, 2).unwrap());
    let mut run = TestRun::new(matrix);
    let assigned = run
        .matrix
        .groups
        .iter()
        .flat_map(|group| &group.rows)
        .flat_map(|row| &row.cases)
        .find(|case| case.assigned)
        .unwrap()
        .id
        .clone();
    let unassigned = run
        .matrix
        .groups
        .iter()
        .flat_map(|group| &group.rows)
        .flat_map(|row| &row.cases)
        .find(|case| !case.assigned)
        .unwrap()
        .id
        .clone();

    assert_eq!(run.status, RunStatus::Idle);
    assert_eq!(
        run.finish_case(&assigned, CaseOutcome::Passed, 60_000)
            .unwrap_err()
            .to_string(),
        "case must be running before it can finish"
    );
    run.start().unwrap();
    assert_eq!(run.status, RunStatus::Running);
    assert_eq!(
        run.begin_case(&unassigned).unwrap_err().to_string(),
        "case is assigned to another shard"
    );
    run.begin_case(&assigned).unwrap();
    assert_eq!(run.case(&assigned).unwrap().status, CaseStatus::Running);
    run.finish_case(&assigned, CaseOutcome::Passed, 60_000)
        .unwrap();
    assert_eq!(run.case(&assigned).unwrap().status, CaseStatus::Passed);
    assert_eq!(run.case(&assigned).unwrap().elapsed_ms, 60_000);
}

#[test]
fn stopping_aborts_the_running_case_and_leaves_completed_results_intact() {
    let catalog = PolicyCatalog {
        policies: vec![policy("basic.toml", false)],
        invalid: Vec::new(),
    };
    let matrix = build_matrix(&catalog, MatrixConfig::new(60, 0, 1).unwrap());
    let mut run = TestRun::new(matrix);
    let ids = run
        .matrix
        .groups
        .iter()
        .flat_map(|group| &group.rows)
        .flat_map(|row| &row.cases)
        .map(|case| case.id.clone())
        .collect::<Vec<_>>();

    run.start().unwrap();
    run.begin_case(&ids[0]).unwrap();
    run.finish_case(&ids[0], CaseOutcome::Passed, 60_125)
        .unwrap();
    run.begin_case(&ids[1]).unwrap();
    run.stop().unwrap();

    assert_eq!(run.status, RunStatus::Stopped);
    assert_eq!(run.case(&ids[0]).unwrap().status, CaseStatus::Passed);
    assert_eq!(run.case(&ids[1]).unwrap().status, CaseStatus::Aborted);
    assert!(run
        .matrix
        .groups
        .iter()
        .flat_map(|group| &group.rows)
        .flat_map(|row| &row.cases)
        .skip(2)
        .all(|case| case.status == CaseStatus::Pending));
}

#[test]
fn workload_commands_cover_cpu_wakeup_affinity_and_process_churn() {
    assert_eq!(
        WorkloadCommand::for_workload(Workload::CpuSaturation, 8).unwrap(),
        WorkloadCommand {
            program: "stress-ng".into(),
            args: vec!["--cpu", "16", "--cpu-method", "loop", "--aggressive"]
                .into_iter()
                .map(String::from)
                .collect(),
        }
    );
    assert_eq!(
        WorkloadCommand::for_workload(Workload::WakerWakee, 8)
            .unwrap()
            .args,
        vec!["--switch", "8", "--switch-method", "pipe", "--aggressive"]
    );
    let mixed = WorkloadCommand::for_workload(Workload::MixedAffinity, 8).unwrap();
    assert_eq!(mixed.program, "bash");
    assert!(mixed.args.join(" ").contains("taskset -c 0"));
    assert!(mixed.args.join(" ").contains("stress-ng --cpu 8"));
    assert_eq!(
        WorkloadCommand::for_workload(Workload::ForkYield, 8)
            .unwrap()
            .args,
        vec![
            "--fork",
            "4",
            "--yield",
            "8",
            "--yield-procs",
            "4",
            "--aggressive",
        ]
    );
    assert_eq!(
        WorkloadCommand::for_workload(Workload::MixedAffinity, 1)
            .unwrap_err()
            .to_string(),
        "mixed-affinity workload requires at least two CPUs"
    );
}

#[test]
fn assigned_jobs_preserve_the_visible_fairness_policy_and_workload_identity() {
    let catalog = PolicyCatalog {
        policies: vec![
            policy("basic.toml", false),
            policy("cell-queues.toml", true),
        ],
        invalid: Vec::new(),
    };
    let run = TestRun::new(build_matrix(&catalog, MatrixConfig::new(60, 1, 3).unwrap()));

    let jobs = run.assigned_jobs();

    assert_eq!(jobs.len(), run.matrix.assigned_cases);
    assert!(jobs.iter().all(|job| job.id.starts_with(&format!(
        "{}/{}/",
        match job.fairness {
            Fairness::Fifo => "fifo",
            Fairness::Vtime => "vtime",
            Fairness::Eevdf => "eevdf",
        },
        job.policy_id
    ))));
    assert!(jobs
        .iter()
        .all(|job| job.policy_id != "cell-queues.toml" || job.fairness == Fairness::Vtime));
}

#[test]
fn testing_catalog_validates_policies_without_attaching_snake() {
    let root = tempfile::tempdir().unwrap();
    let snake = root.path().join("scx_snake");
    fs::write(
        &snake,
        "#!/bin/sh\ncase \"$2\" in *invalid*) echo rejected >&2; exit 1;; esac\nprintf 'compiled\\n'\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&snake).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&snake, permissions).unwrap();
    let policies = root.path().join("policies");
    fs::create_dir(&policies).unwrap();
    fs::write(policies.join("basic.toml"), "[[rung]]\n").unwrap();
    fs::write(policies.join("cell.toml"), "[queues]\n").unwrap();
    fs::write(policies.join("invalid.toml"), "[[rung]]\n").unwrap();

    let catalog = discover_testing_catalog(&snake, &policies).unwrap();

    assert_eq!(
        catalog
            .policies
            .iter()
            .map(|policy| (policy.id.as_str(), policy.queue_policy))
            .collect::<Vec<_>>(),
        vec![("basic.toml", false), ("cell.toml", true)]
    );
    assert_eq!(catalog.invalid.len(), 1);
    assert_eq!(catalog.invalid[0].id, "invalid.toml");
    assert!(catalog.invalid[0].error.contains("rejected"));
}

#[test]
fn controller_can_render_its_startup_catalog_while_scheduler_is_stopped() {
    let catalog = PolicyCatalog {
        policies: vec![policy("basic.toml", false)],
        invalid: Vec::new(),
    };
    let controller =
        TestingController::new(MatrixConfig::new(60, 0, 1).unwrap()).with_catalog(catalog);

    let snapshot = controller.snapshot_available(None).unwrap();

    assert_eq!(snapshot.status, RunStatus::Idle);
    assert_eq!(snapshot.matrix.total_cases, 12);
}
