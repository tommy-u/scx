# scx_mitosis_inspector

`scx_mitosis_inspector` is a standalone callback and scheduler stats view for
`scx_mitosis`. Its fentry BPF programs attach to the active mitosis
`struct_ops` programs and count `select_cpu`, `enqueue`, `dispatch`, `running`,
and `stopping` without changing the scheduler.

The code follows the same small-module boundaries as `scx_snake_inspector`:
HTTP routes and `ApiContext` live in `api.rs`, target metadata lives in
`host_context.rs`, and callback calculations live in `model.rs`.

Build and start it after `scx_mitosis` is attached:

```bash
cargo build --release --manifest-path tools/scx_mitosis_inspector/Cargo.toml
sudo tools/scx_mitosis_inspector/target/release/scx_mitosis_inspector \
  --listen 0.0.0.0:44105 \
  --window 10s \
  --max-window 5m
```

The process needs permission to enumerate loaded BPF programs and load tracing
BPF programs. The default listen address is `0.0.0.0:44105`.

The callback view is served at `/`. Its section explorer links to each table,
and **Download snapshot** exports all five JSON APIs in one diagnostic file.
The probe-status table reports which measurement groups are active, disabled,
or unavailable and whether each group is exact or sampled. `/system` reports
host CPU, pressure, memory, frequency, network, and sched_ext lifecycle data
from procfs/sysfs. `/stats` is the third,
scheduler-only page: it reads the existing Mitosis `top` stats operation from
`/var/run/scx/root/stats` and renders every global and per-cell field without
changing the scheduler. Override the socket with `--stats-path` when needed.

Each page keeps a browser-local 10-minute history: the callback page correlates
CPU and IRQ utilization, callback rate, wakeup latency, DSQ depth, migration
locality, and inspector runtime; the system page trends pressure, frequency,
network, IRQ, and block I/O; and the scheduler page trends per-cell utilization
and borrowing. Refreshing the page clears this history. Latency histograms and
estimated callback-cost bars reuse counters already collected by the inspector
and do not attach additional BPF programs.

Callback latency is sampled by separate fentry/fexit BPF programs and shown as
mean and approximate p50/p95/p99 values. The default samples one in 1024 calls;
set `--callback-timing-sample-rate 1` to measure every call or `0` to disable
latency capture. Non-zero rates must be powers of two through 4096.

Wakeup-to-running latency is collected from sched tracepoints and uses
`--event-timing-sample-rate`, which defaults to one in 64 events.
The same sampled sched-switch stream reports on-CPU slice duration.
Blocked off-CPU duration is measured from a blocking switch until wakeup.
CPU migration pairs are aggregated from `sched_migrate_task` in a bounded map.
The heatmap reads rolling deltas from `/api/migrations`; its window menu changes
the displayed interval. `--window` sets the initial interval and `--max-window`
sets the bounded server-side retention, which defaults to five minutes. The
lifetime counters remain available in `/api/counters` for compatibility.
Compatible DSQ insert and move symbols are observed with kprobes to report exact
operation counts, queue residence-time histograms, and remaining queue depth.
Scheduler tracepoints provide exact switch, preemption, blocking, wakeup, and
task lifecycle totals with per-second rates.
Softirq entry and exit tracepoints provide per-vector counts, rates, and
duration percentiles.
Hard IRQ entry and exit tracepoints provide per-IRQ counts, rates, duration
percentiles, explicit correlation-loss counters, and device/action names from
`/proc/interrupts` when the host exposes them.
The migration heatmap includes a per-CPU IRQ utilization band from kernel CPU
accounting, split into hardirq and softirq time in its tooltip. A separate
non-SCX band reports RT/stop-class and deadline runtime observed at
`sched_switch`, plus hypervisor steal time from per-CPU `/proc/stat`. NMI and
SMI duration are not generally exported by Linux, so the inspector marks them
unavailable instead of reporting zero. Scheduler and BPF runtime remains a
global signal because kernel BPF stats do not provide a per-CPU breakdown.
When block request tracepoints are available, the inspector reports request
rates, bytes, errors, correlation losses, and completion latency percentiles.
The callback page also reads kernel BPF program run counts and runtime totals;
these fields are populated only when the host has `kernel.bpf_stats_enabled=1`.
It reports the inspector programs separately, including one-CPU-equivalent and
whole-host capacity percentages. Enable kernel runtime accounting temporarily
for an A/B test; the inspector never changes that sysctl.

For staged production attachment, use `--disable-dsq`,
`--disable-scheduler-events`, `--disable-irqs`, and `--disable-block-io` to
exclude exact probe groups. Set either timing sample rate to zero to disable
that sampled timing group.

On a performance-sensitive host, start with all optional groups disabled and
enable them one at a time while comparing the same workload. For a short
measurement window, enable `kernel.bpf_stats_enabled`, use the inspector BPF
overhead table, then restore the host's original sysctl value. Kernel BPF
runtime accounting itself has a cost and should not be left enabled solely for
the inspector.

The top-bar **Reset all stats** button clears inspector-owned BPF maps, starts a
new rolling migration epoch, and clears browser histories. It intentionally
preserves Mitosis's stats socket and kernel-wide counters.

For the 16-vCPU development guest, expose the guest port with QEMU user-mode
networking and run `run-in-vm.sh` as the guest command. The script owns the
scheduler, creates two workload cells with configurable dummy CPU workers, and
stops them when the guest exits. Set `MITOSIS_WORKERS_PER_CELL` to change the
default of four workers per cell.
