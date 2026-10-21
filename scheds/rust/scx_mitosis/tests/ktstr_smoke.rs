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

#[path = "../src/bpf_intf.rs"]
mod bpf_intf;

/// scx_mitosis in cell-manager mode: each child of `--cell-parent-cgroup` is a cell.
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
        "--enable-llc-awareness",
        "--exit-dump-len",
        "1048576",
    ]);

const MITOSIS_DEFAULT: Scheduler = Scheduler::named("mitosis")
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
    execute_steps(ctx, vec![interference_workload(), interference_workload()])
}

fn assert_cpu_llcs(expected: &[u32]) -> Result<()> {
    use libbpf_rs::{MapCore as _, MapFlags, MapHandle, query::MapInfoIter};

    let info = MapInfoIter::default()
        .find(|info| info.name.to_str() == Some("cpu_ctxs"))
        .ok_or_else(|| anyhow::anyhow!("Mitosis CPU context map is missing"))?;
    let map = MapHandle::from_map_id(info.id)?;
    let values = map
        .lookup_percpu(&0u32.to_ne_bytes(), MapFlags::ANY)?
        .ok_or_else(|| anyhow::anyhow!("Mitosis CPU contexts are missing"))?;
    let offset = std::mem::offset_of!(bpf_intf::cpu_ctx, llc);
    for (cpu, &llc) in expected.iter().enumerate() {
        let value = values
            .get(cpu)
            .and_then(|value| value.get(offset..offset + 4))
            .ok_or_else(|| anyhow::anyhow!("CPU {cpu} context is missing"))?;
        let actual = u32::from_ne_bytes(value.try_into()?);
        if actual != llc {
            anyhow::bail!("CPU {cpu} uses LLC {actual}, expected {llc}");
        }
    }
    Ok(())
}

#[ktstr_test(
    scheduler = MITOSIS_DEFAULT,
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
fn mitosis_single_llc_compatibility_progress(ctx: &Ctx) -> Result<AssertResult> {
    assert_cpu_llcs(&[0; 16])?;
    run_progress_workload(ctx)
}

#[ktstr_test(
    scheduler = MITOSIS_DEFAULT,
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
fn mitosis_multi_llc_compatibility_progress(ctx: &Ctx) -> Result<AssertResult> {
    assert_cpu_llcs(&[0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3])?;
    run_progress_workload(ctx)
}
