use std::collections::BTreeMap;
use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;

use scx_stats::prelude::*;
use scx_stats_derive::stat_doc;
use scx_stats_derive::Stats;

use crate::DistributionStats;

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(_om_prefix = "c_")]
#[stat(top)]
pub struct CellMetrics {
    #[stat(desc = "Number of cpus")]
    pub num_cpus: u32,
    #[stat(desc = "CPU list string")]
    pub cpulist: String,
    #[stat(desc = "CPU bitmask string")]
    pub cpumask: String,
    #[stat(desc = "Local queue %")]
    pub local_q_pct: f64,
    #[stat(desc = "CPU queue %")]
    pub cpu_q_pct: f64,
    #[stat(desc = "Cell queue %")]
    pub cell_q_pct: f64,
    #[stat(desc = "Borrowed CPU %")]
    pub borrowed_pct: f64,
    #[stat(desc = "Affinity violations % of global")]
    pub affn_violations_pct: f64,
    #[stat(desc = "Steal %")]
    pub steal_pct: f64,
    #[stat(desc = "Decision share % of global")]
    pub share_of_decisions_pct: f64,
    #[stat(desc = "Cell scheduling decisions")]
    total_decisions: u64,
    #[stat(desc = "CPU utilization %")]
    pub util_pct: f64,
    #[stat(desc = "Borrowed CPU time % of running")]
    pub demand_borrow_pct: f64,
    #[stat(desc = "Lent CPU time %")]
    pub lent_pct: f64,
    #[stat(desc = "EWMA-smoothed utilization %")]
    pub smoothed_util_pct: f64,
    #[stat(desc = "Pin idle CPU hits")]
    pub pin_idle_hits: u64,
    #[stat(desc = "Pin idle CPU total")]
    pub pin_idle_total: u64,
    #[stat(desc = "Enqueue pin keeps")]
    pub enq_pin_keeps: u64,
    #[stat(desc = "Enqueue pin total")]
    pub enq_pin_total: u64,
    #[stat(desc = "Kthread kicks")]
    pub kthread_kicks: u64,
    #[stat(desc = "Kthread kick throttled")]
    pub kthread_kick_throttled: u64,
    #[stat(desc = "Per-LLC CPU counts within this cell")]
    pub llc_cpus: BTreeMap<u32, u32>,
    #[stat(desc = "Cgroup name owning this cell")]
    pub cgroup_name: String,
}

impl CellMetrics {
    pub fn update(&mut self, ds: &DistributionStats) {
        self.local_q_pct = ds.local_q_pct;
        self.cpu_q_pct = ds.cpu_q_pct;
        self.cell_q_pct = ds.cell_q_pct;
        self.borrowed_pct = ds.borrowed_pct;
        self.affn_violations_pct = ds.affn_viol_pct;
        self.steal_pct = ds.steal_pct;
        self.share_of_decisions_pct = ds.share_of_decisions_pct;
        self.total_decisions = ds.total_decisions;
    }

    pub fn update_demand(&mut self, util_pct: f64, demand_borrow_pct: f64, lent_pct: f64) {
        self.util_pct = util_pct;
        self.demand_borrow_pct = demand_borrow_pct;
        self.lent_pct = lent_pct;
    }
}

#[stat_doc]
#[derive(Clone, Debug, Default, Serialize, Deserialize, Stats)]
#[stat(top)]
pub struct Metrics {
    #[stat(desc = "Number of cells")]
    pub num_cells: u32,
    #[stat(desc = "Local queue %")]
    pub local_q_pct: f64,
    #[stat(desc = "CPU queue %")]
    pub cpu_q_pct: f64,
    #[stat(desc = "Cell queue %")]
    pub cell_q_pct: f64,
    #[stat(desc = "Borrowed CPU %")]
    pub borrowed_pct: f64,
    #[stat(desc = "Affinity violations % of global")]
    pub affn_violations_pct: f64,
    #[stat(desc = "Steal %")]
    pub steal_pct: f64,
    #[stat(desc = "Decision share % of global")]
    pub share_of_decisions_pct: f64,
    #[stat(desc = "Cell scheduling decisions")]
    total_decisions: u64,
    #[stat(desc = "CPU utilization %")]
    pub util_pct: f64,
    #[stat(desc = "Borrowed CPU time % of running")]
    pub demand_borrow_pct: f64,
    #[stat(desc = "Lent CPU time %")]
    pub lent_pct: f64,
    #[stat(desc = "Number of rebalancing events")]
    pub rebalance_count: u64,
    #[stat(desc = "Per-cell metrics")]
    pub cells: BTreeMap<u32, CellMetrics>,
    #[stat(desc = "Pin idle CPU hits")]
    pub pin_idle_hits: u64,
    #[stat(desc = "Pin idle CPU total")]
    pub pin_idle_total: u64,
    #[stat(desc = "Enqueue pin keeps")]
    pub enq_pin_keeps: u64,
    #[stat(desc = "Enqueue pin total")]
    pub enq_pin_total: u64,
    #[stat(desc = "Kworker kicks per interval")]
    pub kworker_kicks: u64,
    #[stat(desc = "Always-preempt tagged threads")]
    pub always_preempt_tagged: u64,
    #[stat(desc = "Kthread kicks per interval")]
    pub kthread_kicks: u64,
    #[stat(desc = "Kthread kicks throttled per interval")]
    pub kthread_kick_throttled: u64,
    #[stat(desc = "Pinned preempt kicks per interval")]
    pub pinned_kicks: u64,
    #[stat(desc = "Build version string")]
    pub build_version: String,
    #[stat(desc = "Dynamic affinity CPU selection enabled")]
    pub dynamic_affinity_enabled: u32,
    #[stat(desc = "Kworker preempt kick enabled")]
    pub kworker_kick_enabled: u32,
    #[stat(desc = "Pinned preempt kick enabled")]
    pub pinned_kick_enabled: u32,
    #[stat(desc = "Kthread preempt kick enabled")]
    pub kthread_kick_enabled: u32,
    #[stat(desc = "Rebalancing enabled")]
    pub rebalance_enabled: u32,
    #[stat(desc = "Current utilization spread (max-min) %")]
    pub rebalance_spread: f64,
    #[stat(desc = "Spread threshold for triggering rebalance %")]
    pub rebalance_threshold: f64,
    #[stat(desc = "Seconds remaining in rebalance cooldown")]
    pub rebalance_cooldown_remaining: f64,
}

impl Metrics {
    pub fn update(&mut self, ds: &DistributionStats) {
        self.local_q_pct = ds.local_q_pct;
        self.cpu_q_pct = ds.cpu_q_pct;
        self.cell_q_pct = ds.cell_q_pct;
        self.borrowed_pct = ds.borrowed_pct;
        self.affn_violations_pct = ds.affn_viol_pct;
        self.steal_pct = ds.steal_pct;
        self.share_of_decisions_pct = ds.share_of_decisions_pct;
        self.total_decisions = ds.total_decisions;
    }

    pub fn update_demand(&mut self, util_pct: f64, demand_borrow_pct: f64, lent_pct: f64) {
        self.util_pct = util_pct;
        self.demand_borrow_pct = demand_borrow_pct;
        self.lent_pct = lent_pct;
    }

    fn delta(&self, _: &Self) -> Self {
        Self { ..self.clone() }
    }

    fn format<W: Write>(&self, w: &mut W) -> Result<()> {
        writeln!(w, "{}", serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn format_dashboard<W: Write>(&self, w: &mut W, hostname: &str, color: bool) -> Result<()> {
        let now = chrono::Local::now().format("%H:%M:%S");
        let short_host = hostname.split('.').next().unwrap_or(hostname);
        let short_version = self
            .build_version
            .find(" (")
            .map(|i| &self.build_version[..i])
            .unwrap_or(&self.build_version);
        let util_str = format!("util {:.1}%", self.util_pct);
        writeln!(
            w,
            "{} | {} | {} cells | {} | {}",
            ansi("2", short_version, color),
            ansi("2", short_host, color),
            self.num_cells,
            heat_good(self.util_pct, &util_str, color),
            ansi("2", &now.to_string(), color),
        )?;

        // --- Overall ---
        writeln!(w)?;
        writeln!(w, "{}", ansi("1;36", "--- Overall ---", color))?;
        writeln!(
            w,
            "  {}",
            format_distribution_line(
                self.total_decisions,
                self.share_of_decisions_pct,
                self.local_q_pct,
                self.cpu_q_pct,
                self.cell_q_pct,
                self.borrowed_pct,
                self.affn_violations_pct,
                self.steal_pct,
                self.total_decisions,
                color,
            )
        )?;

        // --- Cell Stats ---
        writeln!(w)?;
        writeln!(w, "{}", ansi("1;36", "--- Cell Stats ---", color))?;
        for (cell_id, cm) in &self.cells {
            writeln!(
                w,
                "  {}: {}",
                cell_label(cell_id, cm, color),
                format_distribution_line(
                    cm.total_decisions,
                    cm.share_of_decisions_pct,
                    cm.local_q_pct,
                    cm.cpu_q_pct,
                    cm.cell_q_pct,
                    cm.borrowed_pct,
                    cm.affn_violations_pct,
                    cm.steal_pct,
                    self.total_decisions,
                    color,
                )
            )?;
        }

        // --- Select (pin-select-hit) ---
        writeln!(w)?;
        if self.dynamic_affinity_enabled == 0 {
            writeln!(
                w,
                "{} {}",
                ansi("1;36", "--- Select", color),
                ansi("2", "(disabled) ---", color),
            )?;
        } else {
            writeln!(w, "{}", ansi("1;36", "--- Select ---", color))?;
            {
                let pct = if self.pin_idle_total > 0 {
                    100.0 * (self.pin_idle_hits as f64) / (self.pin_idle_total as f64)
                } else {
                    0.0
                };
                let val = format!(
                    "{:.1}% ({}/{})",
                    pct, self.pin_idle_hits, self.pin_idle_total
                );
                writeln!(
                    w,
                    "  {} {}",
                    ansi("2", "pin-select-hit", color),
                    heat_good(pct, &val, color),
                )?;
            }
            for (cell_id, cm) in &self.cells {
                let pct = if cm.pin_idle_total > 0 {
                    100.0 * (cm.pin_idle_hits as f64) / (cm.pin_idle_total as f64)
                } else {
                    0.0
                };
                let val = format!("{:.1}% ({}/{})", pct, cm.pin_idle_hits, cm.pin_idle_total);
                writeln!(
                    w,
                    "  {}: {} {}",
                    cell_label(cell_id, cm, color),
                    ansi("2", "pin-select-hit", color),
                    heat_good(pct, &val, color),
                )?;
            }
        }

        // --- Enqueue (pin-kept) ---
        writeln!(w)?;
        writeln!(w, "{}", ansi("1;36", "--- Enqueue ---", color))?;
        {
            let pct = if self.enq_pin_total > 0 {
                100.0 * (self.enq_pin_keeps as f64) / (self.enq_pin_total as f64)
            } else {
                0.0
            };
            let val = format!(
                "{:.1}% ({}/{})",
                pct, self.enq_pin_keeps, self.enq_pin_total
            );
            writeln!(
                w,
                "  {} {}",
                ansi("2", "pin-kept", color),
                heat_good(pct, &val, color),
            )?;
        }
        for (cell_id, cm) in &self.cells {
            let pct = if cm.enq_pin_total > 0 {
                100.0 * (cm.enq_pin_keeps as f64) / (cm.enq_pin_total as f64)
            } else {
                0.0
            };
            let val = format!("{:.1}% ({}/{})", pct, cm.enq_pin_keeps, cm.enq_pin_total);
            writeln!(
                w,
                "  {}: {} {}",
                cell_label(cell_id, cm, color),
                ansi("2", "pin-kept", color),
                heat_good(pct, &val, color),
            )?;
        }

        // --- Kworker Kicks ---
        writeln!(w)?;
        if self.kworker_kick_enabled == 0 {
            writeln!(
                w,
                "{} {}",
                ansi("1;36", "--- Kworker Kicks", color),
                ansi("2", "(disabled) ---", color),
            )?;
        } else {
            writeln!(w, "{}", ansi("1;36", "--- Kworker Kicks ---", color))?;
            let kick_str = format_count(self.kworker_kicks);
            let tagged_str = format!(
                "({} threads tagged)",
                format_count(self.always_preempt_tagged)
            );
            writeln!(
                w,
                "  {} {}  {}",
                ansi("2", "kworker-kick:", color),
                if self.kworker_kicks > 0 {
                    ansi("33", &kick_str, color)
                } else {
                    kick_str
                },
                ansi("2", &tagged_str, color),
            )?;
        }

        // --- Kthread Kicks ---
        writeln!(w)?;
        if self.kthread_kick_enabled == 0 {
            writeln!(
                w,
                "{} {}",
                ansi("1;36", "--- Kthread Kicks", color),
                ansi("2", "(disabled) ---", color),
            )?;
        } else {
            writeln!(w, "{}", ansi("1;36", "--- Kthread Kicks ---", color))?;
            {
                let total_throttled: u64 = self
                    .cells
                    .values()
                    .map(|cm| cm.kthread_kick_throttled)
                    .sum();
                let kick_str = format_count(self.kthread_kicks);
                let throttled_str = format_count(total_throttled);
                writeln!(
                    w,
                    "  {} {}  ({})",
                    ansi("2", "kthread-kick:", color),
                    if self.kthread_kicks > 0 {
                        ansi("33", &kick_str, color)
                    } else {
                        kick_str.clone()
                    },
                    if total_throttled > 0 {
                        ansi("31", &format!("{} throttled", throttled_str), color)
                    } else {
                        format!("{} throttled", throttled_str)
                    },
                )?;
            }
            for (cell_id, cm) in &self.cells {
                let cell_kick_str = format_count(cm.kthread_kicks);
                let cell_throttled_str = format_count(cm.kthread_kick_throttled);
                writeln!(
                    w,
                    "  {}: {} {}  ({})",
                    cell_label(cell_id, cm, color),
                    ansi("2", "kthread-kick", color),
                    if cm.kthread_kicks > 0 {
                        ansi("33", &cell_kick_str, color)
                    } else {
                        cell_kick_str
                    },
                    if cm.kthread_kick_throttled > 0 {
                        ansi("31", &format!("{} throttled", cell_throttled_str), color)
                    } else {
                        format!("{} throttled", cell_throttled_str)
                    },
                )?;
            }
        }

        // --- Pinned Kicks ---
        writeln!(w)?;
        if self.pinned_kick_enabled == 0 {
            writeln!(
                w,
                "{} {}",
                ansi("1;36", "--- Pinned Kicks", color),
                ansi("2", "(disabled) ---", color),
            )?;
        } else {
            writeln!(w, "{}", ansi("1;36", "--- Pinned Kicks ---", color))?;
            writeln!(
                w,
                "  {} {}",
                ansi("2", "pinned-kick:", color),
                if self.pinned_kicks > 0 {
                    ansi("33", &format_count(self.pinned_kicks), color)
                } else {
                    format_count(self.pinned_kicks)
                },
            )?;
        }

        // --- Demand ---
        writeln!(w)?;
        writeln!(w, "{}", ansi("1;36", "--- Demand ---", color))?;
        for (cell_id, cm) in &self.cells {
            writeln!(
                w,
                "  {}:  {} {:5.1}%  {} {:4.1}%  {} {:4.1}%  {} {:5.1}%",
                cell_label(cell_id, cm, color),
                ansi("2", "util", color),
                cm.util_pct,
                ansi("2", "borrowed", color),
                cm.demand_borrow_pct,
                ansi("2", "lent", color),
                cm.lent_pct,
                ansi("2", "smoothed", color),
                cm.smoothed_util_pct,
            )?;
        }

        // --- Rebalance ---
        writeln!(w)?;
        if self.rebalance_enabled == 0 {
            writeln!(
                w,
                "{} {}",
                ansi("1;36", "--- Rebalance", color),
                ansi("2", "(disabled) ---", color),
            )?;
        } else {
            writeln!(w, "{}", ansi("1;36", "--- Rebalance ---", color))?;
            writeln!(
                w,
                "  {} {:.1}%  {} {:.1}%  {} {:.1}s  {} {}",
                ansi("2", "spread", color),
                self.rebalance_spread,
                ansi("2", "threshold", color),
                self.rebalance_threshold,
                ansi("2", "cooldown", color),
                self.rebalance_cooldown_remaining,
                ansi("2", "count", color),
                self.rebalance_count,
            )?;
        }

        // --- Pinning ---
        writeln!(w)?;
        writeln!(w, "{}", ansi("1;36", "--- Pinning ---", color))?;
        for (cell_id, cm) in &self.cells {
            writeln!(
                w,
                "  {}: {} {}",
                cell_label(cell_id, cm, color),
                format!("{} cpus", cm.num_cpus),
                &cm.cpulist,
            )?;
            writeln!(w, "            {}", &cm.cpumask,)?;
            if !cm.llc_cpus.is_empty() {
                let llc_parts: Vec<String> = cm
                    .llc_cpus
                    .iter()
                    .map(|(llc_id, count)| format!("LLC {}: {} cpus", llc_id, count))
                    .collect();
                writeln!(w, "            {}", llc_parts.join("  "))?;
            }
        }

        // --- Legend ---
        writeln!(w)?;
        let legend = "\
  Local: found idle CPU in task's own cell      CPU/Cell/Borrow: enqueue destination
  V: affinity violation (cpumask miss)          S: LLC-aware dispatch steal
  pin-select-hit: pinned task found idle CPU    pin-kept: pinned task kept assigned CPU
  kworker-kick: bound kworker/ksoftirqd         kthread-kick: general kthread preempt
  pinned-kick: pinned task vtime preempt";
        writeln!(w, "{}", ansi("2", "--- Legend ---", color))?;
        writeln!(w, "{}", ansi("2", legend, color))?;

        Ok(())
    }
}

fn cell_label(cell_id: &u32, cm: &CellMetrics, color: bool) -> String {
    if cm.cgroup_name.is_empty() {
        ansi("34", &format!("Cell {:2}", cell_id), color)
    } else {
        format!(
            "{} {}",
            ansi("34", &format!("Cell {:2}", cell_id), color),
            ansi("2", &format!("({})", cm.cgroup_name), color),
        )
    }
}

fn format_distribution_line(
    total_decisions: u64,
    share_pct: f64,
    local_pct: f64,
    cpu_pct: f64,
    cell_pct: f64,
    borrow_pct: f64,
    viol_pct: f64,
    steal_pct: f64,
    global_decisions: u64,
    color: bool,
) -> String {
    use std::cmp::max;
    const MIN_WIDTH: usize = 5;
    let width = if global_decisions > 0 {
        max(MIN_WIDTH, (global_decisions as f64).log10().ceil() as usize)
    } else {
        MIN_WIDTH
    };
    format!(
        "{:width$} {:5.1}% | {}:{} {}:{} {}:{} {}:{} | {}:{} {}:{}",
        total_decisions,
        share_pct,
        ansi("2", "Local", color),
        heat_good(local_pct, &format!("{:4.1}%", local_pct), color),
        ansi("2", "CPU", color),
        heat_cost(cpu_pct, &format!("{:4.1}%", cpu_pct), color),
        ansi("2", "Cell", color),
        heat_cost(cell_pct, &format!("{:4.1}%", cell_pct), color),
        ansi("2", "Borrow", color),
        heat_cost(borrow_pct, &format!("{:4.1}%", borrow_pct), color),
        ansi("2", "V", color),
        heat_cost(viol_pct, &format!("{:4.1}%", viol_pct), color),
        ansi("2", "S", color),
        heat_cost(steal_pct, &format!("{:4.1}%", steal_pct), color),
        width = width,
    )
}

fn ansi(code: &str, text: &str, color: bool) -> String {
    if color {
        format!("\x1b[{}m{}\x1b[0m", code, text)
    } else {
        text.to_string()
    }
}

/// Heat color for "good" stats (higher is better): green ≥90%, yellow 50-90%, red <50%
fn heat_good(pct: f64, text: &str, color: bool) -> String {
    if !color {
        return text.to_string();
    }
    if pct >= 90.0 {
        ansi("32", text, true) // green
    } else if pct >= 50.0 {
        ansi("33", text, true) // yellow
    } else {
        ansi("31", text, true) // red
    }
}

/// Heat color for "cost" stats (lower is better): green <1%, yellow 1-10%, red ≥10%
fn heat_cost(pct: f64, text: &str, color: bool) -> String {
    if !color {
        return text.to_string();
    }
    if pct < 1.0 {
        ansi("32", text, true) // green
    } else if pct < 10.0 {
        ansi("33", text, true) // yellow
    } else {
        ansi("31", text, true) // red
    }
}

fn format_count(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.0}K", n as f64 / 1_000.0)
    } else {
        format!("{}", n)
    }
}

pub fn server_data() -> StatsServerData<(), Metrics> {
    let open: Box<dyn StatsOpener<(), Metrics>> = Box::new(move |(req_ch, res_ch)| {
        req_ch.send(())?;
        let mut prev = res_ch.recv()?;

        let read: Box<dyn StatsReader<(), Metrics>> = Box::new(move |_args, (req_ch, res_ch)| {
            req_ch.send(())?;
            let cur = res_ch.recv()?;
            let delta = cur.delta(&prev);
            prev = cur;
            delta.to_json()
        });

        Ok(read)
    });

    StatsServerData::new()
        .add_meta(Metrics::meta())
        .add_meta(CellMetrics::meta())
        .add_ops("top", StatsOps { open, close: None })
}

pub fn monitor(intv: Duration, shutdown: Arc<AtomicBool>) -> Result<()> {
    scx_utils::monitor_stats::<Metrics>(
        &[],
        intv,
        || shutdown.load(Ordering::Relaxed),
        |metrics| metrics.format(&mut std::io::stdout()),
    )
}

pub fn dashboard(
    intv: Duration,
    shutdown: Arc<AtomicBool>,
    log_path: Option<String>,
) -> Result<()> {
    let hostname = {
        let mut buf = [0u8; 256];
        let ret = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
        if ret == 0 {
            let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            String::from_utf8_lossy(&buf[..len]).into_owned()
        } else {
            "unknown".to_string()
        }
    };

    let mut log_file = log_path
        .map(|p| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&p)
        })
        .transpose()?;

    scx_utils::monitor_stats::<Metrics>(
        &[],
        intv,
        || shutdown.load(Ordering::Relaxed),
        |metrics| {
            // Clear screen
            print!("\x1b[2J\x1b[H");
            metrics.format_dashboard(&mut std::io::stdout(), &hostname, true)?;
            std::io::stdout().flush()?;

            // Optionally log to file (no color)
            if let Some(ref mut f) = log_file {
                let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
                writeln!(f, "=== {} ===", ts)?;
                metrics.format_dashboard(f, &hostname, false)?;
                writeln!(f)?;
                f.flush()?;
            }
            Ok(())
        },
    )
}
