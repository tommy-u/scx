#![cfg(feature = "ktstr-tests")]
//! scx_mitosis cell-isolation smoke test, and a showcase of the ktstr harness.
//!
//! Two tenants, each in its own cgroup → its own mitosis cell: a small
//! "sensitive" tenant and a CPU "hog". Phase 0 runs under scx_mitosis; phase 1
//! detaches it and reruns under the kernel default (EEVDF). Under mitosis the
//! sensitive tenant should do more work and wait less, and the hog should not be
//! starved. Passing also proves mitosis boots, schedules, and detaches cleanly.
//!
//! ktstr features used: `Scheduler`/`CgroupDef` builders, `#[ktstr_test]` inline
//! topology, `Op::detach_scheduler` for the phase-1 A/B, `VmResult::phase_cgroup`
//! for per-cgroup per-phase stats, and the `claim!`/`Verdict` assertion DSL.

use ktstr::prelude::*;
use std::time::{Duration, Instant};

#[path = "common/mitosis_bpf.rs"]
mod mitosis_bpf;
use mitosis_bpf::{assert_cpu_llcs, bpf_intf, cpu_contexts};

/// scx_mitosis in cell-manager mode: each child of `--cell-parent-cgroup` is a cell.
const MITOSIS_COMPATIBILITY: Scheduler = Scheduler::named("mitosis")
    .binary_discover("scx_mitosis")
    .sched_args(&[
        "--cell-parent-cgroup",
        "/test.slice",
        "--cpu-controller-disabled",
        "--dynamic-affinity-cpu-selection",
        "--enable-borrowing",
        "--enable-rebalancing",
        "--enable-slice-shrinking",
        "--enable-llc-awareness",
        "--exit-dump-len",
        "1048576",
    ]);

const MITOSIS: Scheduler = Scheduler::named("mitosis")
    .binary_discover("scx_mitosis")
    .sched_args(&[
        "--cell-parent-cgroup",
        "/test.slice",
        "--cpu-controller-disabled",
        "--dynamic-affinity-cpu-selection",
        "--enable-borrowing",
        "--enable-rebalancing",
        "--enable-slice-shrinking",
        "--exit-dump-len",
        "1048576",
    ]);

const MITOSIS_VIRTUAL: Scheduler = Scheduler::named("mitosis")
    .binary_discover("scx_mitosis")
    .sched_args(&[
        "--cell-parent-cgroup",
        "/test.slice",
        "--cpu-controller-disabled",
        "--dynamic-affinity-cpu-selection",
        "--enable-borrowing",
        "--enable-rebalancing",
        "--enable-slice-shrinking",
        "--virt-llc=2-2",
        "--exit-dump-len",
        "1048576",
    ]);

const MITOSIS_CHURN: Scheduler = Scheduler::named("mitosis")
    .binary_discover("scx_mitosis")
    .config_file_def("--cell-config {file}", "/include-files/mitosis-churn.json")
    .sched_args(&["--reconfiguration-interval-s", "1"]);

const CHURN_CONFIG: &str = r#"
[
  {
    "name": "pressure",
    "matches": {"CgroupRegex": "/test[.]slice/pressure$"}
  },
  {
    "name": "rest",
    "matches": {},
    "subcells": [
      {"name": "victim", "matches": [[{"CommPrefix": "llc_churn"}]]},
      {"name": "rest", "matches": [[]]}
    ]
  }
]
"#;

const SENSITIVE_WORKERS: usize = 2;
const HOG_WORKERS: usize = 30;
/// Sensitive does at least this much more work under mitosis than under EEVDF.
const MIN_ISOLATION_GAIN: f64 = 1.3;
/// Sensitive waits at most this fraction of its EEVDF runqueue wait under mitosis.
const MAX_DELAY_RATIO: f64 = 0.7;
/// Hog keeps at least this fraction of its EEVDF work under mitosis (not starved).
const HOG_KEEP_FRACTION: f64 = 0.5;

/// Two tenants → two cells. Declared fresh per phase so each phase has its own
/// stats window.
fn interference_workload() -> Step {
    Step::with_defs(
        vec![
            CgroupDef::named("sensitive")
                .workers(SENSITIVE_WORKERS)
                .work_type(WorkType::SpinWait),
            CgroupDef::named("hog")
                .workers(HOG_WORKERS)
                .work_type(WorkType::SpinWait),
        ],
        HoldSpec::frac(0.5),
    )
}

/// Per-cgroup per-phase stats come off the `VmResult`, so the comparison lives here.
fn assert_mitosis_isolates_sensitive(result: &VmResult) -> Result<()> {
    // step 0 = mitosis, step 1 = detached EEVDF.
    let cell = |name: &str, step: u16| result.phase_cgroup(Phase::step(step), name);
    let (Some(sm), Some(se)) = (cell("sensitive", 0), cell("sensitive", 1)) else {
        anyhow::bail!("no per-phase stats for `sensitive`");
    };
    let (Some(hm), Some(he)) = (cell("hog", 0), cell("hog", 1)) else {
        anyhow::bail!("no per-phase stats for `hog`");
    };
    let (Some((sensitive_run_delay_us, _)), Some((eevdf_run_delay_us, _))) =
        (sm.run_delay_summary(), se.run_delay_summary())
    else {
        anyhow::bail!("no run-delay samples for `sensitive`");
    };

    eprintln!(
        "sensitive iters:        mitosis={} eevdf={}",
        sm.total_iterations, se.total_iterations
    );
    eprintln!(
        "sensitive run_delay_us: mitosis={sensitive_run_delay_us:.0} eevdf={eevdf_run_delay_us:.0}"
    );
    eprintln!(
        "hog iters:              mitosis={} eevdf={}",
        hm.total_iterations, he.total_iterations
    );

    // `claim!` labels each value by its name; `into_anyhow_or_log` bails on any
    // failed claim. Sensitive does more work and waits less; the hog is not starved.
    let sensitive_iters = sm.total_iterations as f64;
    let hog_iters = hm.total_iterations as f64;
    let mut verdict = Verdict::new();
    claim!(verdict, sensitive_iters).at_least(se.total_iterations as f64 * MIN_ISOLATION_GAIN);
    claim!(verdict, sensitive_run_delay_us).at_most(eevdf_run_delay_us * MAX_DELAY_RATIO);
    claim!(verdict, hog_iters).at_least(he.total_iterations as f64 * HOG_KEEP_FRACTION);
    verdict.into_anyhow_or_log()
}

#[ktstr_test(
    scheduler = MITOSIS,
    // Workload cgroups land here = the cell-parent, so each becomes a cell.
    workload_root_cgroup = "/test.slice",
    // 16 vCPUs; sensitive(2) + hog(30) = 32 threads oversubscribe them.
    llcs = 4,
    cores = 4,
    threads = 1,
    memory_mib = 512,
    // Two equal phases (frac(0.5) each).
    duration_s = 20,
    watchdog_timeout_s = 10,
    num_snapshots = 12,
    auto_repro = false,
    post_vm = assert_mitosis_isolates_sensitive,
)]
fn mitosis_isolates_sensitive_tenant(ctx: &Ctx) -> Result<AssertResult> {
    let steps = vec![
        // Phase 0: both tenants under scx_mitosis.
        interference_workload(),
        // Phase 1: detach → EEVDF. The op runs before this phase's cgroups spawn.
        interference_workload().set_ops(vec![Op::detach_scheduler()]),
    ];
    execute_steps(ctx, steps)
}

fn assert_mitosis_progress(result: &VmResult) -> Result<()> {
    for step in 0..2 {
        for name in ["sensitive", "hog"] {
            let Some(stats) = result.phase_cgroup(Phase::step(step), name) else {
                anyhow::bail!("no per-phase stats for {name} in step {step}");
            };
            if stats.total_iterations == 0 {
                anyhow::bail!("{name} made no progress in step {step}");
            }
            eprintln!(
                "step={step} cgroup={name} iterations={} run_delay_us={:?}",
                stats.total_iterations,
                stats.run_delay_summary(),
            );
        }
    }
    Ok(())
}

fn run_progress_workload(ctx: &Ctx) -> Result<AssertResult> {
    let checks = ctx.assert.min_iteration_rate(1.0).check_isolation();
    let result = execute_steps_with(
        ctx,
        vec![interference_workload(), interference_workload()],
        Some(&checks),
    )
    .inspect_err(|error| eprintln!("guest progress failed: {error:#}"))?;
    eprintln!(
        "guest progress: total_workers={} total_iterations={}",
        result.stats.total_workers, result.stats.total_iterations,
    );
    for detail in result.failure_details() {
        eprintln!("guest progress assertion failed: {}", detail.message);
    }
    if result.stats.total_workers == 0 || result.stats.total_iterations == 0 {
        eprintln!("guest progress reported no active workers");
        anyhow::bail!("guest progress reported no active workers");
    }
    Ok(result)
}

#[ktstr_test(
    scheduler = MITOSIS,
    workload_root_cgroup = "/test.slice",
    llcs = 1,
    cores = 16,
    threads = 1,
    memory_mib = 512,
    duration_s = 8,
    watchdog_timeout_s = 10,
    num_snapshots = 8,
    auto_repro = false,
    post_vm = assert_mitosis_progress,
)]
fn mitosis_single_llc_default_progress(ctx: &Ctx) -> Result<AssertResult> {
    assert_cpu_llcs(&[0; 16])?;
    run_progress_workload(ctx)
}

#[ktstr_test(
    scheduler = MITOSIS_COMPATIBILITY,
    workload_root_cgroup = "/test.slice",
    llcs = 1,
    cores = 16,
    threads = 1,
    memory_mib = 512,
    duration_s = 8,
    watchdog_timeout_s = 10,
    num_snapshots = 8,
    auto_repro = false,
    post_vm = assert_mitosis_progress,
)]
fn mitosis_single_llc_compatibility_progress(ctx: &Ctx) -> Result<AssertResult> {
    assert_cpu_llcs(&[0; 16])?;
    run_progress_workload(ctx)
}

#[ktstr_test(
    scheduler = MITOSIS,
    workload_root_cgroup = "/test.slice",
    llcs = 4,
    cores = 4,
    threads = 1,
    memory_mib = 512,
    duration_s = 8,
    watchdog_timeout_s = 10,
    num_snapshots = 8,
    auto_repro = false,
    post_vm = assert_mitosis_progress,
)]
fn mitosis_multi_llc_default_progress(ctx: &Ctx) -> Result<AssertResult> {
    assert_cpu_llcs(&[0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3])?;
    run_progress_workload(ctx)
}

#[ktstr_test(
    scheduler = MITOSIS_VIRTUAL,
    workload_root_cgroup = "/test.slice",
    llcs = 1,
    cores = 16,
    threads = 1,
    memory_mib = 512,
    duration_s = 8,
    watchdog_timeout_s = 10,
    num_snapshots = 8,
    auto_repro = false,
    post_vm = assert_mitosis_progress,
)]
fn mitosis_virtual_llc_default_progress(ctx: &Ctx) -> Result<AssertResult> {
    assert_cpu_llcs(&[0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7])?;
    run_progress_workload(ctx)
}

#[derive(Debug)]
struct ChurnState {
    tags: Vec<(u32, u32)>,
    in_use: bool,
    llcs_with_cpus: u64,
    llcs_to_drain: u64,
    queued: [u32; 2],
    // Successful drains, affinity rescues, and affinity violations in cell 0.
    counters: [u64; 3],
}

fn churn_state() -> Result<ChurnState> {
    use libbpf_rs::{MapCore as _, MapFlags, MapHandle, query::MapInfoIter};

    let contexts = cpu_contexts()?;
    let info = MapInfoIter::default()
        .find(|info| info.name.to_str() == Some("cells"))
        .ok_or_else(|| anyhow::anyhow!("Mitosis cell map is missing"))?;
    let map = MapHandle::from_map_id(info.id)?;
    let value = map
        .lookup(&0u32.to_ne_bytes(), MapFlags::ANY)?
        .ok_or_else(|| anyhow::anyhow!("Mitosis root cell is missing"))?;
    if value.len() < std::mem::size_of::<bpf_intf::cell>() {
        anyhow::bail!("Mitosis root cell value is too small");
    }
    // Read the generated C layout; the map buffer is not necessarily aligned.
    let cell = unsafe { std::ptr::read_unaligned(value.as_ptr().cast::<bpf_intf::cell>()) };
    let subcell = &cell.subcells[1];
    let indices = [
        bpf_intf::cell_stat_idx_CSTAT_DRAIN_CNT,
        bpf_intf::cell_stat_idx_CSTAT_DRAIN_AFFN_CNT,
        bpf_intf::cell_stat_idx_CSTAT_AFFN_VIOL,
    ];
    Ok(ChurnState {
        tags: contexts
            .iter()
            .take(4)
            .map(|ctx| (ctx.cell, ctx.subcell))
            .collect(),
        in_use: cell.in_use != 0 && subcell.in_use != 0,
        llcs_with_cpus: subcell.llcs_with_cpus,
        llcs_to_drain: subcell.llcs_to_drain,
        queued: [subcell.llcs[0].nr_queued, subcell.llcs[1].nr_queued],
        counters: indices.map(|idx| contexts.iter().map(|ctx| ctx.cstats[0][idx as usize]).sum()),
    })
}

fn wait_for_churn<T: std::fmt::Debug>(
    description: &str,
    mut probe: impl FnMut() -> Result<(bool, T)>,
) -> Result<T> {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let (ready, state) = probe()?;
        if ready {
            return Ok(state);
        }
        if Instant::now() >= deadline {
            eprintln!("{description} timed out: {state:?}");
            anyhow::bail!("{description} timed out: {state:?}");
        }
        // Configuration and worker progress have no guest-side wait primitive.
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn wait_for_churn_assignment(
    description: &str,
    tags: &[(u32, u32)],
    llcs_with_cpus: u64,
    require_queued: bool,
) -> Result<ChurnState> {
    wait_for_churn(description, || {
        let state = churn_state()?;
        let ready = state.in_use
            && state.tags == tags
            && state.llcs_with_cpus == llcs_with_cpus
            && (!require_queued || state.queued[1] > 0);
        Ok((ready, state))
    })
}

fn wait_for_churn_progress(description: &str, handle: &WorkloadHandle) -> Result<()> {
    let before = handle.snapshot_iterations();
    let (after, state) = wait_for_churn(description, || {
        let now = handle.snapshot_iterations();
        let ready = now.len() == 16 && now.iter().zip(&before).all(|(now, before)| now > before);
        Ok((ready, (now, churn_state()?)))
    })?;
    let delta: Vec<u64> = after.iter().zip(before).map(|(a, b)| a - b).collect();
    eprintln!("{description}: worker_iterations={delta:?} state={state:?}");
    Ok(())
}

/// Moving an empty pressure cell's cpuset changes cell 0's partition from
/// [subcell 0: CPUs 0,1; subcell 1: CPU 2] to [0: CPU 0; 1: CPU 1] and back.
/// Victim workers retain their affinity and never see an empty subcell.
#[ktstr_test(
    scheduler = MITOSIS_CHURN,
    config = CHURN_CONFIG,
    workload_root_cgroup = "/test.slice",
    llcs = 2,
    cores = 2,
    threads = 1,
    memory_mib = 512,
    duration_s = 40,
    watchdog_timeout_s = 10,
    num_snapshots = 8,
    auto_repro = false,
)]
fn mitosis_nonzero_subcell_last_cpu_leaves_llc_and_returns(ctx: &Ctx) -> Result<AssertResult> {
    let result: Result<AssertResult> = (|| {
        assert_cpu_llcs(&[0, 0, 1, 1])?;
        let initial = [(0, 0), (0, 0), (0, 1), (1, 0)];
        let off_llc = [(0, 0), (0, 1), (1, 0), (1, 0)];
        let allowed: std::collections::BTreeSet<usize> = [0, 1, 2].into_iter().collect();
        let mut group = CgroupGroup::new(ctx.cgroups);
        group.add_cgroup("pressure", &[3].into_iter().collect())?;
        group.add_cgroup_no_cpuset("victim")?;
        wait_for_churn_assignment("initial subcell assignment", &initial, 2, false)?;

        let config = WorkloadConfig::default()
            .workers(16)
            .comm("llc_churn")
            .work_type(WorkType::SpinWait)
            .affinity(AffinityIntent::exact([0, 1, 2]));
        let mut handle = WorkloadHandle::spawn(&config)?;
        ctx.cgroups
            .move_tasks("victim", &handle.worker_pids_for_cgroup_procs()?)?;
        handle.start();
        wait_for_churn_progress("initial worker progress", &handle)?;
        let before = wait_for_churn_assignment("queued work before removal", &initial, 2, true)?;
        eprintln!("before removal: {before:?}");

        for (description, cpus, tags, llcs) in [
            ("last CPU left LLC 1", vec![2, 3], off_llc, 1),
            ("last CPU returned to LLC 1", vec![3], initial, 2),
        ] {
            ctx.cgroups
                .set_cpuset("pressure", &cpus.into_iter().collect())?;
            wait_for_churn_assignment(description, &tags, llcs, false)?;
            wait_for_churn_progress(description, &handle)?;
        }

        let after = churn_state()?;
        let counters =
            std::array::from_fn::<_, 3, _>(|idx| after.counters[idx] - before.counters[idx]);
        eprintln!(
            "churn counters: drains={} affinity_rescues={} affinity_violations={} drain_mask={}",
            counters[0], counters[1], counters[2], after.llcs_to_drain,
        );
        let reports = handle.stop_and_collect();
        for report in &reports {
            eprintln!(
                "churn worker tid={} iterations={} cpus={:?} max_gap_ms={} affinity_error={:?}",
                report.tid,
                report.iterations,
                report.cpus_used,
                report.max_gap_ms,
                report.affinity_error,
            );
        }
        let mut verdict = AssertResult::pass();
        for report in &reports {
            if report.affinity_error.is_some() || !report.cpus_used.is_subset(&allowed) {
                verdict.merge(AssertResult::fail_msg(format!(
                    "worker {} violated its affinity: CPUs {:?}, error {:?}",
                    report.tid, report.cpus_used, report.affinity_error,
                )));
            }
        }
        verdict.note_value("queued_before_removal", before.queued[1] as u64);
        verdict.note_value("successful_drains", counters[0]);
        verdict.note_value("affinity_rescues", counters[1]);
        verdict.note_value("affinity_violations", counters[2]);
        if counters[0] == 0 || counters[2] != 0 {
            verdict.merge(AssertResult::fail_msg(format!(
                "expected successful draining without affinity violations: {counters:?}"
            )));
        }
        for detail in verdict.failure_details() {
            eprintln!("nonzero subcell churn assertion failed: {}", detail.message);
        }
        Ok(verdict)
    })();
    if let Err(error) = &result {
        eprintln!("nonzero subcell churn failed: {error:#}");
    }
    result
}
