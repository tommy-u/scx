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

fn default_cell_queue_counters() -> bpf_intf::cell_queue_counters {
    bpf_intf::cell_queue_counters {
        lo_fallback_count: 0,
        hi_fallback_count: 0,
        default_count: 0,
    }
}
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
    // Cycle counters for each cell on each CPU
    prev_percpu_cell_cycles: Vec<[u64; MAX_CELLS]>,
    // Affinity violation counters
    prev_affin_viol: Vec<[u64; MAX_CELLS]>,
    // Queue placement counters. Three for each cell and CPU: lo_fallback, hi_fallback, default
    prev_queue_counters: Vec<[bpf_intf::cell_queue_counters; MAX_CELLS]>,
    monitor_interval: std::time::Duration,
    // Useful for formatting printing. Basically log10(Largest CPU ID) + 1
    largest_cpu_width: usize,
    topology: Topology,
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

        let largest_cpu_width = {
            let largest_cpu = topology.all_cores.keys().max().ok_or_else(|| {
                anyhow::anyhow!("Failed to determine the largest CPU number")
            })?;
            (*largest_cpu as f64).log10().ceil() as usize
        };

        let skel = scx_ops_load!(skel, mitosis, uei)?;

        Ok(Self {
            skel,
            prev_percpu_cell_cycles: vec![[0; MAX_CELLS]; *NR_CPU_IDS],
            prev_affin_viol: vec![[0; MAX_CELLS]; *NR_CPU_IDS],
            prev_queue_counters: vec![[ default_cell_queue_counters(); MAX_CELLS]; *NR_CPU_IDS],
            monitor_interval: std::time::Duration::from_secs(opts.monitor_interval_s),
            largest_cpu_width,
            topology,
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

    fn load_cpu_ctxs(&self) -> Result<Vec<Vec<u8>>> {
        let zero = 0 as libc::__u32;
        let zero_slice = unsafe { any_as_u8_slice(&zero) };

        let v = match self
        .skel
        .maps
        .cpu_ctxs
        .lookup_percpu(zero_slice, libbpf_rs::MapFlags::ANY)
        {
            Ok(Some(v)) => v,
            Ok(None) => return Err(anyhow::anyhow!("Found no values for cpu_ctxs map")),
            Err(e) => return Err(anyhow::anyhow!("Error looking up cpu_ctxs map: {:?}", e)),
        };
        Ok(v)
    }

    fn debug_cpu_ctrs(&mut self) -> Result<()> {
        trace!("CPU Cycles:");
        let v = self.load_cpu_ctxs()?;

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
            trace!("CPU {:width$}: {:?}", cpu, diff_cycles, width = self.largest_cpu_width);
        }
        Ok(())
    }

    // 1) Get the affin-viols from BPF
    // 2) Subtract the previous affin-viols from the current ones to get the diff
    // 3) Print the diff (this is all cpus and all cells)
    // 4) Sum the CPUS for each cell and print the sum vector (per cell violations)
    // 5) Sum the Cells for each CPU and print the sum vector (per CPU violations)
    // 6) Sum the CPUS and Cells and print the sum (total violations)
    fn debug_affinity_violations(&mut self) -> Result<()> {
        trace!("Affinity Violations:");

        // The raw affin-viols counters from BPF
        let mut current_affn_viol: Vec<[u64; MAX_CELLS]> = vec![[0; MAX_CELLS]; *NR_CPU_IDS];

        let v = self.load_cpu_ctxs()?;

        for ctx in v.iter() {
            let cpu_ctx = unsafe {
                let ptr = ctx.as_slice().as_ptr() as *const bpf_intf::cpu_ctx;
                &*ptr
            };

            // 1) Raw affin-viols from BPF
            for &cpu in self.topology.all_cores.keys() {
                for (cell, val) in cpu_ctx.cstats.iter().enumerate() {
                    current_affn_viol[cpu][cell] = val[bpf_intf::cell_stat_idx_CSTAT_AFFN_VIOL as usize];
                }
            }
        }

        // 2) Subtract the previous affin-viols from the current ones to get the diff
        // The difference between the current and previous affin-viols
        let mut affn_viol_diff: Vec<[u64; MAX_CELLS]> = vec![[0; MAX_CELLS]; *NR_CPU_IDS];
        // FIXME: Use loop over valid cpus instead of NR_CPU_IDS

        // Loop over the current affin-viols and subtract the previous ones
        for &cpu in self.topology.all_cores.keys() {
            for (i, val) in current_affn_viol[cpu].iter().enumerate() {
                affn_viol_diff[cpu][i] = val - self.prev_affin_viol[cpu][i];
            }
        }

        // 3) print the diff affin-viols
        for &cpu in self.topology.all_cores.keys() {
            let affn_viol: Vec<u64> = affn_viol_diff[cpu]
                .iter()
                .map(|val| *val)
                .collect();
            trace!("CPU {:width$}: {:?}", cpu, affn_viol, width = self.largest_cpu_width);
        }

        // 4) Per-Cell violations. Sum the CPUS for each cell.
        let mut per_cell_violations: [u64; MAX_CELLS] = [0; MAX_CELLS];
        for cell in 0..MAX_CELLS {
            for &cpu in self.topology.all_cores.keys() {
                let val = affn_viol_diff[cpu][cell];
                per_cell_violations[cell] += val;
            }
        }
        trace!("Per-Cell violations: {:?}", per_cell_violations);

        // 5) Per-CPU violations. Sum the Cells for each CPU.
        let mut per_cpu_violations: Vec<u64> = vec![0; *NR_CPU_IDS];
        for &cpu in self.topology.all_cores.keys() {
            for cell in 0..MAX_CELLS {
                let val = affn_viol_diff[cpu][cell];
                per_cpu_violations[cpu] += val;
            }
        }
        trace!("Per-CPU violations: {:?}", per_cpu_violations);

        // Sanity check, the sum of the per-cell violations should equal the sum of the per-cpu violations
        let total_cpu_violations: u64 = per_cpu_violations.iter().sum();
        let total_cell_violations: u64 = per_cell_violations.iter().sum();

        if total_cpu_violations != total_cell_violations {
            return Err(anyhow::anyhow!(
                "Mismatch in total violations: per CPU = {}, per Cell = {}",
                total_cpu_violations,
                total_cell_violations
            ));
        }

        // 6) Total violations. Sum the CPUS and Cells.
        trace!("Total violations: {}", per_cpu_violations.iter().sum::<u64>());

        // update the previous affin-viols
        self.prev_affin_viol = current_affn_viol;

        Ok(())
    }

    // Follow the pattern of debug_affinity_violations, where it prints out:
    // 0. Get the difference between the prior and current queue values
    // 1. The per CPU per cell DIFF between the prior and current queue values
    // 2. The per cell queue values
    // 3. The per-CPU queue values
    fn debug_priority(&mut self) -> Result<()> {

        let v = self.load_cpu_ctxs()?;

        let mut current_queue_counters: Vec<[bpf_intf::cell_queue_counters; MAX_CELLS]> = vec![[default_cell_queue_counters(); MAX_CELLS]; *NR_CPU_IDS];
        // Get current queue counters
        for (cpu, ctx) in v.iter().enumerate() {
            let cpu_ctx = unsafe {
                let ptr = ctx.as_slice().as_ptr() as *const bpf_intf::cpu_ctx;
                &*ptr
            };

            for cell in 0..MAX_CELLS {
                current_queue_counters[cpu][cell] = cpu_ctx.queue_counters[cell];
            }
        }

        // 0. Get the difference between the prior and current queue values
        let mut diff_counters: Vec<[bpf_intf::cell_queue_counters; MAX_CELLS]> = vec![[default_cell_queue_counters(); MAX_CELLS]; *NR_CPU_IDS];

        for &cpu in self.topology.all_cores.keys() {
            for cell in 0..MAX_CELLS {
                diff_counters[cpu][cell] = bpf_intf::cell_queue_counters {
                    lo_fallback_count: current_queue_counters[cpu][cell].lo_fallback_count - self.prev_queue_counters[cpu][cell].lo_fallback_count,
                    hi_fallback_count: current_queue_counters[cpu][cell].hi_fallback_count - self.prev_queue_counters[cpu][cell].hi_fallback_count,
                    default_count:     current_queue_counters[cpu][cell].default_count     - self.prev_queue_counters[cpu][cell].default_count,
                };
            }
        }

        // 1. Calculate and print the DIFF between prior and current queue values per CPU per cell
        trace!("Per CPU per Cell Queue Counter Diffs:");
        let cpu_counters: Vec<String> = diff_counters.iter().enumerate().map(|(cpu, counters)| {
            let cell_counters: Vec<String> = counters.iter().enumerate().map(|(cell, counter)| {
                format!(
                    "C{} {},{},{}",
                    cell,
                    counter.lo_fallback_count,
                    counter.hi_fallback_count,
                    counter.default_count
                )
            }).collect();
            format!("CPU {:width$}: {}", cpu, cell_counters.join(" "), width = self.largest_cpu_width)
        }).collect();

        trace!("\n{}", cpu_counters.join("\n"));

        // 2. Calculate and print per cell queue values
        let mut per_cell_counters = vec![default_cell_queue_counters(); MAX_CELLS];
        // zero out the per_cell_counters
        // Each element of per_cell_counters is the sum of all cpu's counters for that cell
        for cell in 0..MAX_CELLS {
            let mut tmp_counter = default_cell_queue_counters();
            for &cpu in self.topology.all_cores.keys() {
                tmp_counter.lo_fallback_count += diff_counters[cpu][cell].lo_fallback_count;
                tmp_counter.hi_fallback_count += diff_counters[cpu][cell].hi_fallback_count;
                tmp_counter.default_count     += diff_counters[cpu][cell].default_count;
            }
            per_cell_counters[cell] = tmp_counter;
        }

        let cell_counters: Vec<String> = per_cell_counters.iter().enumerate().map(|(cell, counters)| {
            format!(
                "Cell {}: [{}, {}, {}]",
                cell,
                counters.lo_fallback_count,
                counters.hi_fallback_count,
                counters.default_count
            )
        }).collect();

        trace!("\nPer Cell Queue counters:\n{}", cell_counters.join(" "));

    //     // 3. Calculate and print per CPU queue values (summed across all cells)
    //     trace!("Per CPU Queue Counters (summed across cells):");
        let mut per_cpu_counters = vec![default_cell_queue_counters(); *NR_CPU_IDS];
        for &cpu in self.topology.all_cores.keys() {
            let mut tmp_counter = default_cell_queue_counters();
            for cell in 0..MAX_CELLS {
                tmp_counter.lo_fallback_count += diff_counters[cpu][cell].lo_fallback_count;
                tmp_counter.hi_fallback_count += diff_counters[cpu][cell].hi_fallback_count;
                tmp_counter.default_count     += diff_counters[cpu][cell].default_count;
            }
            per_cpu_counters[cpu] = tmp_counter;
        }

        let cpu_counters: Vec<String> = per_cpu_counters.iter().enumerate().map(|(cpu, counters)| {
            format!(
                "CPU {}: [{}, {}, {}]",
                cpu,
                counters.lo_fallback_count,
                counters.hi_fallback_count,
                counters.default_count
            )
        }).collect();
        trace!("\nPer CPU Queue Counters:\n{}", cpu_counters.join(" "));

        // 4. Calculate and print the total queue values (summed across all cells and all CPUs)
        let mut total_counters: bpf_intf::cell_queue_counters = default_cell_queue_counters();
        for &cpu in self.topology.all_cores.keys() {
            for cell in 0..MAX_CELLS {
                total_counters.lo_fallback_count += diff_counters[cpu][cell].lo_fallback_count;
                total_counters.hi_fallback_count += diff_counters[cpu][cell].hi_fallback_count;
                total_counters.default_count     += diff_counters[cpu][cell].default_count;
            }
        }
        trace!("\nTotal Queue Counters: [{}, {}, {}]", total_counters.lo_fallback_count, total_counters.hi_fallback_count, total_counters.default_count);

        // Update previous queue counters for next time
        self.prev_queue_counters = current_queue_counters;

        Ok(())
    }

    /// Output various debugging data like per cell stats, per-cpu stats, etc.
    fn debug(&mut self) -> Result<()> {
        self.debug_cpu_ctrs()?;
        self.debug_affinity_violations()?;
        self.debug_priority()?;
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

#[cfg(test)]
mod tests {
    use std::mem::MaybeUninit;
    use anyhow::Result;
    use clap::Parser;
    use libbpf_rs::OpenObject;

    use crate::{Opts, Scheduler};
    use crate::bpf_intf;
    use scx_utils::NR_CPU_IDS;

    #[test]
    fn test_debug_cpu_ctrs() -> Result<()> {
        // Generate some synthetic cycle counters

        // Print per cpu per cell

        // Print per cell

        // Print per cpu

        // Check sums of these two are the same

        // Print total

        Ok(())
    }

    #[test]
    fn test_debug_affinity_violations() -> Result<()> {
        // Generate some synthetic affinity violations

        // Print per cpu per cell

        // Print per cell

        // Print per cpu

        // Check sums of these two are the same

        // Print total

        Ok(())
    }

    #[test]
    fn test_debug_priority() -> Result<()> {
        // Generate some synthetic priority stats

        // Print per cpu per cell

        // Print per cell

        // Print per cpu

        // Check sums of these two are the same

        // Print total

        Ok(())
    }

}
