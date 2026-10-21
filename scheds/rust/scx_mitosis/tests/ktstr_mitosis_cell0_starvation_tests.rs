#![cfg(feature = "ktstr-tests")]
//! Cell-0 CPU holdout under mandatory LLC scheduling on two LLCs.

use ktstr::prelude::*;

#[path = "common/mitosis_bpf.rs"]
mod mitosis_bpf;

declare_scheduler!(MITOSIS, {
    name = "mitosis",
    binary = "scx_mitosis",
    topology = (1, 2, 4, 2),
    sched_args = [
        "--exit-dump-len", "1048576",
        "--cpu-controller-disabled",
        "--cell-parent-cgroup", "/ktstr",
        "--enable-borrowing",
        "--cell0-min-cpus", "1",
    ],
});

/// Keep cell 0 running when child cpusets cover both LLCs.
///
/// Alpha and beta claim disjoint cpusets covering all 16 CPUs. The
/// --cell0-min-cpus reservation keeps one CPU for the catch-all cell.
#[ktstr_test(
    scheduler = MITOSIS,
    workload_root_cgroup = "/ktstr",
    llcs = 2,
    cores = 4,
    threads = 2,
    duration_s = 30,
    memory_mib = 256,
)]
fn mitosis_two_llc_cell0_holdout_with_full_coverage_cpusets(ctx: &Ctx) -> Result<AssertResult> {
    mitosis_bpf::assert_cpu_llcs(&[0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1])?;
    let steps = vec![Step::with_defs(
        vec![
            CgroupDef::named("alpha")
                .cpuset(CpusetSpec::exact(0..8))
                .workers(1)
                .work_type(WorkType::SpinWait),
            CgroupDef::named("beta")
                .cpuset(CpusetSpec::exact(8..16))
                .workers(1)
                .work_type(WorkType::SpinWait),
        ],
        HoldSpec::FULL,
    )];
    let checks = ctx.assert.min_iteration_rate(1.0).check_isolation();
    let result = execute_steps_with(ctx, steps, Some(&checks))
        .inspect_err(|error| eprintln!("guest cell0 progress failed: {error:#}"))?;
    eprintln!(
        "guest cell0 progress: total_workers={} total_iterations={}",
        result.stats.total_workers, result.stats.total_iterations,
    );
    for detail in result.failure_details() {
        eprintln!("guest cell0 progress assertion failed: {}", detail.message);
    }
    if result.stats.total_workers == 0 || result.stats.total_iterations == 0 {
        eprintln!("guest cell0 progress reported no active workers");
        anyhow::bail!("guest cell0 progress reported no active workers");
    }
    Ok(result)
}
