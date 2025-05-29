// Copyright (c) Meta Platforms, Inc. and affiliates.

// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.
mod bpf_skel;
pub use bpf_skel::*;
pub mod bpf_intf;

use std::mem::MaybeUninit;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::Context;
use anyhow::Result;
use clap::Parser;
use libbpf_rs::MapCore as _;
use libbpf_rs::OpenObject;
use log::debug;
use log::info;
use log::trace;
use scx_utils::init_libbpf_logging;
use scx_utils::scx_enums;
use scx_utils::scx_ops_attach;
use scx_utils::scx_ops_load;
use scx_utils::scx_ops_open;
use scx_utils::uei_exited;
use scx_utils::uei_report;
use scx_utils::Topology;
use scx_utils::UserExitInfo;
use scx_utils::NR_CPUS_POSSIBLE;
use scx_utils::NR_CPU_IDS;

const MAX_CELLS: usize = bpf_intf::consts_MAX_CELLS as usize;

/// scx_mitosis: A dynamic affinity scheduler
///
/// Cgroups are assigned to a dynamic number of Cells which are assigned to a
/// dynamic set of CPUs. The BPF part does simple vtime scheduling for each cell.
///
/// Userspace makes the dynamic decisions of which Cells should be merged or
/// split and which cpus they should be assigned to.
#[derive(Debug, Parser)]
struct Opts {
    /// Enable verbose output, including libbpf details. Specify multiple
    /// times to increase verbosity.
    #[clap(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Exit debug dump buffer length. 0 indicates default.
    #[clap(long, default_value = "0")]
    exit_dump_len: u32,

    /// Interval to consider reconfiguring the Cells (e.g. merge or split)
    #[clap(long, default_value = "10")]
    reconfiguration_interval_s: u64,

    /// Interval to consider rebalancing CPUs to Cells
    #[clap(long, default_value = "5")]
    rebalance_cpus_interval_s: u64,

    /// Interval to report monitoring information
    #[clap(long, default_value = "1")]
    monitor_interval_s: u64,
}

unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    unsafe {
        ::std::slice::from_raw_parts((p as *const T) as *const u8, ::std::mem::size_of::<T>())
    }
}

struct Scheduler<'a> {
    skel: BpfSkel<'a>,
    prev_percpu_cell_cycles: Vec<[u64; MAX_CELLS]>,
    // Cell as the primary index makes more sense to me [cell][cpu]
    // I can change this to match the cycles vector if needed.
    prev_affin_viol: Vec<[u64; MAX_CELLS]>,
    monitor_interval: std::time::Duration,
}

impl<'a> Scheduler<'a> {
    fn init(opts: &Opts, open_object: &'a mut MaybeUninit<OpenObject>) -> Result<Self> {
        let topology = Topology::new()?;

        let mut skel_builder = BpfSkelBuilder::default();
        skel_builder.obj_builder.debug(opts.verbose > 1);
        init_libbpf_logging(None);
        let mut skel = scx_ops_open!(skel_builder, open_object, mitosis)?;

        skel.struct_ops.mitosis_mut().exit_dump_len = opts.exit_dump_len;

        skel.maps.rodata_data.slice_ns = scx_enums.SCX_SLICE_DFL;

        skel.maps.rodata_data.nr_possible_cpus = *NR_CPUS_POSSIBLE as u32;
        for cpu in topology.all_cores.keys() {
            skel.maps.rodata_data.all_cpus[cpu / 8] |= 1 << (cpu % 8);
        }

        let skel = scx_ops_load!(skel, mitosis, uei)?;

        Ok(Self {
            skel,
            prev_percpu_cell_cycles: vec![[0; MAX_CELLS]; *NR_CPU_IDS],
            prev_affin_viol: vec![[0; MAX_CELLS]; *NR_CPU_IDS],
            monitor_interval: std::time::Duration::from_secs(opts.monitor_interval_s),
        })
    }

    fn run(&mut self, shutdown: Arc<AtomicBool>) -> Result<UserExitInfo> {
        let struct_ops = scx_ops_attach!(self.skel, mitosis)?;
        info!("Mitosis Scheduler Attached");
        while !shutdown.load(Ordering::Relaxed) && !uei_exited!(&self.skel, uei) {
            std::thread::sleep(self.monitor_interval);
            self.debug()?;
        }
        drop(struct_ops);
        uei_report!(&self.skel, uei)
    }

    fn debug_cpu_ctrs(&mut self) -> Result<()> {
        trace!("CPU Cycles:");
        let zero = 0 as libc::__u32;
        let zero_slice = unsafe { any_as_u8_slice(&zero) };
        if let Some(v) = self
            .skel
            .maps
            .cpu_ctxs
            .lookup_percpu(zero_slice, libbpf_rs::MapFlags::ANY)
            .context("Failed to lookup cpu_ctxs map")?
        {
            for (cpu, ctx) in v.iter().enumerate() {
                let cpu_ctx = unsafe {
                    let ptr = ctx.as_slice().as_ptr() as *const bpf_intf::cpu_ctx;
                    &*ptr
                };
                let diff_cycles: Vec<i64> = self.prev_percpu_cell_cycles[cpu]
                    .iter()
                    .zip(cpu_ctx.cell_cycles.iter())
                    .map(|(a, b)| (b - a) as i64)
                    .collect();
                self.prev_percpu_cell_cycles[cpu] = cpu_ctx.cell_cycles;
                trace!("CPU {}: {:?}", cpu, diff_cycles);
            }
        }
        Ok(())
    }

    // 1) Get the affin-viols from BPF
    // 2) Subtract the previous affin-viols from the current ones to get the diff
    // 3) Print the diff (this is all cpus and all cells)
    // 4) Sum the CPUS for each cell and print the sum vector (per cell violations)
    // 5) Sum the Cells for each CPU and print the sum vector (per CPU violations)
    // 6) Sum the CPUS and Cells and print the sum (total violations)

    // Print all affinity violations
    // We could do this with less memory if anyone cares.
    fn debug_affinity_violations(&mut self) -> Result<()> {
        trace!("Affinity Violations:");

        let zero = 0 as libc::__u32;
        let zero_slice = unsafe { any_as_u8_slice(&zero) };

        // The raw affin-viols counters from BPF
        let mut current_affn_viol: Vec<[u64; MAX_CELLS]> = vec![[0; MAX_CELLS]; *NR_CPU_IDS];

        // Load the current affin-viols from BPF
        if let Some(v) = self
            .skel
            .maps
            .cpu_ctxs
            .lookup_percpu(zero_slice, libbpf_rs::MapFlags::ANY)
            .context("Failed to lookup cpu_ctxs map")?
        {
            for (cpu, ctx) in v.iter().enumerate() {
                let cpu_ctx = unsafe {
                    let ptr = ctx.as_slice().as_ptr() as *const bpf_intf::cpu_ctx;
                    &*ptr
                };

                // assert that there are as many entries in cstats as there are cells
                assert_eq!(cpu_ctx.cstats.len(), MAX_CELLS);

                // 1) Raw affin-viols from BPF
                for (i, val) in cpu_ctx.cstats.iter().enumerate() {
                    current_affn_viol[cpu][i] = val[bpf_intf::cell_stat_idx_CSTAT_AFFN_VIOL as usize];
                }
            }
        }

        // Print the current affin-viols
        // for cpu in 0..*NR_CPU_IDS {
        //     let affn_viol: Vec<u64> = current_affn_viol[cpu]
        //         .iter()
        //         .map(|val| *val)
        //         .collect();
        //     trace!("CPU {}: {:?}", cpu, affn_viol);
        // }

        // 2) Subtract the previous affin-viols from the current ones to get the diff
        // The difference between the current and previous affin-viols
        let mut affn_viol_diff: Vec<[u64; MAX_CELLS]> = vec![[0; MAX_CELLS]; *NR_CPU_IDS];

        // Loop over the current affin-viols and subtract the previous ones
        for cpu in 0..*NR_CPU_IDS {
            for (i, val) in current_affn_viol[cpu].iter().enumerate() {
                affn_viol_diff[cpu][i] = val - self.prev_affin_viol[cpu][i];
            }
        }
        // 3) print the diff affin-viols
        for cpu in 0..*NR_CPU_IDS {
            let affn_viol: Vec<u64> = affn_viol_diff[cpu]
                .iter()
                .map(|val| *val)
                .collect();
            trace!("CPU {}: affin-viols {:?}", cpu, affn_viol);
        }

        // update the previous affin-viols
        self.prev_affin_viol = current_affn_viol;

        // 4) Per-Cell violations. Sum the CPUS for each cell.
        let mut per_cell_violations: [u64; MAX_CELLS] = [0; MAX_CELLS];
        for cell in 0..MAX_CELLS {
            for cpu in 0..*NR_CPU_IDS {
                let val = affn_viol_diff[cpu][cell];
                per_cell_violations[cell] += val;
            }
        }
        trace!("Per-Cell violations: {:?}", per_cell_violations);

        // 5) Per-CPU violations. Sum the Cells for each CPU.
        let mut per_cpu_violations: Vec<u64> = vec![0; *NR_CPU_IDS];
        for cpu in 0..*NR_CPU_IDS {
            for cell in 0..MAX_CELLS {
                let val = affn_viol_diff[cpu][cell];
                per_cpu_violations[cpu] += val;
            }
        }
        trace!("Per-CPU violations: {:?}", per_cpu_violations);

        // Sanity check, the sum of the per-cell violations should equal the sum of the per-cpu violations
        assert_eq!(per_cpu_violations.iter().sum::<u64>(), per_cell_violations.iter().sum::<u64>());

        // 6) Total violations. Sum the CPUS and Cells.
        trace!("Total violations: {}", per_cpu_violations.iter().sum::<u64>());

        Ok(())
    }

    /// Output various debugging data like per cell stats, per-cpu stats, etc.
    fn debug(&mut self) -> Result<()> {
        self.debug_cpu_ctrs()?;
        self.debug_affinity_violations()?;
        Ok(())
    }
}

fn main() -> Result<()> {
    let opts = Opts::parse();

    let llv = match opts.verbose {
        0 => simplelog::LevelFilter::Info,
        1 => simplelog::LevelFilter::Debug,
        _ => simplelog::LevelFilter::Trace,
    };
    let mut lcfg = simplelog::ConfigBuilder::new();
    lcfg.set_time_level(simplelog::LevelFilter::Error)
        .set_location_level(simplelog::LevelFilter::Off)
        .set_target_level(simplelog::LevelFilter::Off)
        .set_thread_level(simplelog::LevelFilter::Off);
    simplelog::TermLogger::init(
        llv,
        lcfg.build(),
        simplelog::TerminalMode::Stderr,
        simplelog::ColorChoice::Auto,
    )?;

    debug!("opts={:?}", &opts);

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::Relaxed);
    })
    .context("Error setting Ctrl-C handler")?;

    let mut open_object = MaybeUninit::uninit();
    loop {
        let mut sched = Scheduler::init(&opts, &mut open_object)?;
        if !sched.run(shutdown.clone())?.should_restart() {
            break;
        }
    }

    Ok(())
}
