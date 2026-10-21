# scx_mitosis_inspector

`scx_mitosis_inspector` is a standalone callback and scheduler stats view for
`scx_mitosis`. Its fentry BPF programs attach to the active mitosis
`struct_ops` programs and count `select_cpu`, `enqueue`, `dispatch`, `running`,
and `stopping` without changing the scheduler.

The code follows the same small-module boundaries as `scx_snake_inspector`:
HTTP routes and `ApiContext` live in `api.rs`, target metadata lives in
`host_context.rs`, and callback calculations live in `model.rs`.

Build and start the inspector from this worktree:

```bash
cargo build --release --manifest-path tools/scx_mitosis_inspector/Cargo.toml
sudo tools/scx_mitosis_inspector/target/release/scx_mitosis_inspector \
  --listen '[::]:44103' \
  --window 10s \
  --max-window 5m
```

The process needs permission to enumerate loaded BPF programs and load tracing
BPF programs. The default listen address is `[::]:44103`, exposing IPv6 and,
on Linux with `net.ipv6.bindv6only=0`, IPv4. On the development host, open
`http://devbig008.atn3.facebook.com:44103/`. The scheduler can run from the existing
`~/scx/target/release/scx_mitosis`; no scheduler changes are required.

HTTP starts while the inspector waits for Mitosis. The collector checks the
active scheduler's name and sched_ext enable sequence before and after attachment
and collection. It drops its observer session when the scheduler stops, restarts,
or collection fails, then retries with backoff capped at 30 seconds. Waiting,
attachment, and collection errors are exposed in the JSON APIs and page status.
The inspector does not launch or stop the scheduler.

## AI access

The inspector serves a browser guide with the timeline at `/guide`, and a
bundled plain-text Markdown guide at `/ai-guide`. Give a remote Codex session the inspector URL and
ask it to read `/ai-guide` first. The guide documents the existing JSON APIs,
measurement intervals, sampling, freshness, and investigation examples. An AI
with HTTP access can use the same collected data as the dashboard.

## Dashboard and measurements

Pages are grouped by the question they answer rather than by the collector
that produced their data:

- **Cells** (`/`, also `/stats`): is mitosis partitioning CPUs as expected?
  CPU placement by cell, cell borrowing, cell history, and global and per-cell
  scheduler metrics.
- **Scheduling** (`/scheduling`): how long do tasks wait, and where do they
  move? The CPU migration matrix, scheduler latency, threads and wakeup
  handoffs, dispatch queues, scheduler activity, and sched_ext health and
  fallbacks.
- **Callbacks** (`/callbacks`): what do mitosis's BPF callbacks cost? Callback
  counts and rates, callback latency, estimated cost, and BPF program runtime.
- **System** (`/system`): is something outside the scheduler interfering? CPU,
  interrupts (softirqs, hard IRQs, IPIs), block I/O, memory and cache, hardware
  counters, idle states, thermal pressure and power, PSI pressure, and network.
- **Configuration** (`/config`): how is mitosis configured?
- **Inspector** (`/inspector`): host environment, per-source freshness and
  errors, probe status, and the inspector's own BPF overhead.
  **Download snapshot** exports the displayed source snapshots in one
  diagnostic file.

The server renders the shared sidebar navigation into every page, and each
page's section explorer links to its tables. The former `/explore` and
`/appendix` pages redirect to Scheduling and Inspector, and section links into
the old Callbacks page forward to the section's new page. The probe-status table
reports which measurement groups are active, disabled, or unavailable and
whether each group is exact or sampled. `/system` reads host CPU, pressure,
memory, frequency, and network data from procfs/sysfs. The Cells page reads the
existing Mitosis `top` stats operation from `/var/run/scx/root/stats` and
renders every global and per-cell field without changing the scheduler.
Override the socket with `--stats-path` when needed.

The Cells CPU placement matrix shows one row per cell and one column per LLC
in LLC number order. Each value counts assigned logical CPUs; a small bar shows
the cell's share of that LLC, and the final column totals its assigned CPUs.
Cgroup names stay beside each row, with full paths and CPU lists on hover.
Unavailable CPU ownership has its own row. The matrix combines host
topology with a read-only projection of the existing Mitosis `cpu_ctxs` map.
The loaded map's BTF validates the owner field layout; `/api/stats` exposes this
mapping as `cpu_cells`, with allocation failures separate from scheduler metrics.
Cell colors match the history graphs. Ownership is observed while configuration
updates may be in progress; it is not a transactionally frozen allocation.

Every workspace has a shared time slider with Live, previous/next sample
controls, a Viewing clock, and a Now clock. Select a past time to replay the
complete screen: line graphs, histograms, heatmaps, CPU placement, tables, and
configuration use retained data at or before that time. The selected absolute
time persists across navigation. Arrow keys step through samples, Home selects
the oldest sample, End returns to Live, and Page Up/Down move thirty seconds.
Clocks include date, seconds, and local timezone. Now follows the host clock
while Viewing remains fixed. Expired selections clamp visibly to the oldest
available time.

The inspector retains up to 30 minutes of replay data in memory. A separate
one-second sampler reads existing snapshots, preserves their source metadata,
and stores compressed complete frames plus lightweight graph history. Browsers
fetch graph history through `/api/timeline` and one selected full frame through
`/api/timeline/view`. Collection continues with closed tabs, laptop sleep, or
SSH tunnel outages. No new startup flags or additional BPF probes are required.
Restarting the inspector clears history and changes its instance ID. Automatic
scheduler epoch changes retain past frames; explicit successful resets clear
the archive and return the browser to Live. Reset is disabled while historical.

Complete frames are bounded by 30 minutes, 1,801 records, and a 256 MiB compressed
snapshot budget. Actual available bounds are reported; a byte limit may shorten
the available interval. Historical migration deltas retain the scrub interval
plus the largest selectable migration window, bounded by 64 MiB. Source errors
and original timestamps remain visible. Repeated cached source snapshots do not
become additional graph measurements.
These retention budgets do not cap total process RSS: live snapshots, metadata,
other migration windows, the allocator, and HTTP responses also use memory.
The HTTP runtime uses two workers. Replay serialization and selected snapshot
decoding happen outside the archive lock; compressed payloads retain only their
encoded bytes.

Each page charts the history of its own signals: Callbacks charts callback
rate; Scheduling charts wakeup latency, DSQ depth, and migration locality;
System charts CPU and IRQ utilization, frequency, block I/O, pressure, and
network; Inspector charts its own BPF runtime. The Cells page trends
per-cell utilization, executed CPU use, and assigned CPU capacity. CPU use is the current interval's
`util_pct * num_cpus / 100`; it measures executed runtime rather than queued demand.
Capacity lines are dashed and both series use CPU units. Cell chart lines break
when measurements are more than three seconds apart, an observer epoch changes,
or a value is unavailable. All line charts share the selected time bounds.
Latency histograms and
estimated callback-cost bars reuse counters already collected by the inspector
and do not attach additional BPF programs.
Latency checkbox menus let you compare several measurements on shared axes.
Selections survive polling; each series has a stable color and a label below the
chart. Hard IRQ details show the ten busiest IRQs by current rate, while all
observed IRQs remain available for comparison. CPU utilization is charted on
the System page beside average frequency and summarized per CPU in the
migration heatmap.

Callback latency is sampled by separate fentry/fexit BPF programs and shown as
mean and approximate p50/p95/p99 values. The default samples one in 1024 calls;
set `--callback-timing-sample-rate 1` to measure every call or `0` to disable
latency capture. Non-zero rates must be powers of two through 4096.

Wakeup-to-running latency is collected from sched tracepoints and uses
`--event-timing-sample-rate`, which defaults to one in 64 events.
The same sampled sched-switch stream reports on-CPU slice duration.
Blocked off-CPU duration is measured from a blocking switch until wakeup.
CPU migration pairs use the task's `orig_cpu` and `dest_cpu` from
`sched_migrate_task`. A shared, non-evicting hash map holds up to the square of the
possible CPU count, capped at 1,048,576 pairs (99,856 entries for 316 CPUs). Failed
updates are counted per CPU and reported as `migration_map_failures`; nonzero
loss marks `migration_quality` as `incomplete`. The map is rebuilt each epoch.
The heatmap reads rolling deltas from the selected timeline view; its window menu changes
the displayed interval. `--window` sets the initial interval and `--max-window`
sets the bounded server-side retention, which defaults to five minutes. The
lifetime counters and rolling windows remain available in `/api/counters` and
`/api/migrations` for compatibility. Replay omits lifetime migration arrays
because its delta history supplies the selected heatmap. HTTP responses use gzip when the client
accepts it, keeping the full pair data practical on remote connections.
The matrix's Mem. BW strip sits below LLC utilization and shows each LLC's
MBM-monitored total traffic in decimal GB/s at the selected time. Colors compare
LLCs within that sample; hover shows the reading, capture time, coverage, and
scale. Missing readings remain unknown. MBM traffic does not measure DRAM-channel
saturation.
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
The Callbacks page also reads kernel BPF program run counts and runtime totals;
these fields are populated only when the host has `kernel.bpf_stats_enabled=1`.
The Inspector page reports the inspector programs separately, including
one-CPU-equivalent and whole-host capacity percentages. Enable kernel runtime accounting temporarily
for an A/B test; the inspector never changes that sysctl.

For staged production attachment, use `--disable-explore`, `--disable-dsq`,
`--disable-scheduler-events`, `--disable-irqs`, and `--disable-block-io` to
exclude optional probe groups. Their programs and unused maps are omitted before
loading. Resources shared with enabled programs remain available. Set either
timing sample rate to zero to disable that latency measurement. Core callback
counts and exact CPU runtime remain active; the probe-status table reports CPU
runtime separately from sampled scheduler timing.

For example:

```bash
sudo tools/scx_mitosis_inspector/target/release/scx_mitosis_inspector \
  --listen 127.0.0.1:44103 \
  --disable-explore --disable-dsq --disable-scheduler-events \
  --disable-irqs --disable-block-io \
  --callback-timing-sample-rate 0 --event-timing-sample-rate 0
```

Scheduler stats still use the existing single reader, normally once per second.
Opening more dashboard tabs does not add scheduler `top` polls.

On a performance-sensitive host, start with all optional groups disabled and
enable them one at a time while comparing the same workload. For a short
measurement window, enable `kernel.bpf_stats_enabled`, use the inspector BPF
overhead table, then restore the host's original sysctl value. Kernel BPF
runtime accounting itself has a cost and should not be left enabled solely for
the inspector.

Each live source publishes its own epoch, sample sequence, collection timestamp,
last successful timestamp, and error in `meta`. Browser polling suppresses
concurrent requests per source, gives each fetch and JSON body five seconds to
complete, and discards invalidated or older responses. Sources publish independently,
so slow probes or migrations do not delay host or scheduler stats. Cached and failed samples do not add history points. The pages
report freshness separately for probes, scheduler stats, and host metrics; new
active epochs establish new counter baselines. Replay separates historical
selection from current collection health. A graph-history request warning does
not erase an independently successful selected full view.

`GET /api/timeline` accepts optional `instance_id` and `after_seq` cursor
parameters supplied together, plus a migration `window_ms`. It returns
`instance_id`, `retention_ms`, `now_unix_ms`, available bounds, `sample_seq`,
`reset`, and ordered `frames`. Frames carry an inspector-global sequence,
observation time, per-source metadata and availability, and compact graph
signals. Original source sequences deduplicate cached measurements within
their observer epoch; frame sequences continue through scheduler restarts.
`reset: true` replaces the previous graph buffer with the returned frames.
The response also advertises `window_ms`, `default_window_ms`, and
`max_window_ms`, including before any frame exists. The browser discovers the
configured window rather than assuming ten seconds; unsupported saved windows
recover to the current server default.

`GET /api/timeline/view?at_unix_ms=T&window_ms=W` returns the floor frame at or
before T, original complete source snapshots, source errors, and a migration
window ending at that time. Omitting T means latest. An expired T returns an
error with bounds for an explicit client clamp. CPU-pair migration windows
filter the selected counter epoch and report actual coverage and quality.
Changing the window while historical retains the selected time and recomputes
both heatmap data and migration locality history. Historical downloads export
the displayed view.

`GET /api/stats/history` returns `meta`, `collector`, `instance_id`,
`retention_ms`, `reset`, and ordered `samples`. Each sample contains `meta` and
original per-cell `num_cpus`, `util_pct`, and `smoothed_util_pct` values when
available. Optional `instance_id`, `epoch`, and `after_seq` query parameters
request only samples after a previously received sequence. `reset: true` means
the caller must replace its previous history with the returned retained buffer.
This occurs on initial load, an inspector instance or epoch change, or a cursor
outside retained history. Deduplicate sequences within an inspector instance
and observer epoch. This cell-only compatibility endpoint clears on observer
epoch changes. The shared timeline uses full replay frames and preserves past
automatic epochs.

The top-bar **Reset all stats** button pauses polling and rebuilds the entire
inspector observer session, including task storage and migration history. A
bounded command queue carries the request; `/api/reset` returns HTTP 200 only
after publishing the new epoch's first snapshot, with its epoch, sample sequence,
and reset timestamp. Browser histories clear on that acknowledgement. Failed
resets report an error and leave browser history visible as stale data while the
observer recovers. The replay archive clears only after successful reset
acknowledgement. Requests expire after 15 seconds, and canceled or expired
queued requests are rejected before work starts. Mitosis's stats socket and
kernel-wide counters are preserved.

For the 16-vCPU development guest, expose the guest port with QEMU user-mode
networking and run `run-in-vm.sh` as the guest command. The script owns the
scheduler, creates two workload cells with configurable dummy CPU workers, and
stops them when the guest exits. Set `MITOSIS_WORKERS_PER_CELL` to change the
default of four workers per cell.


## System memory and cache graphs

The System workspace includes paired aggregate and per-LLC history graphs for
monitored memory bandwidth, cache accesses, cache misses, and cache miss ratio.
A shared LLC selection controls the per-LLC plots; all plots follow the selected
time in the shared replay bar. The per-LLC bandwidth selector compares total or
local monitored traffic. Missing sources, warming intervals and counter resets
remain graph gaps rather than zeros.

Bandwidth uses decimal GB/s from resctrl MBM byte-counter deltas. Root and
top-level control-monitor groups are summed once per L3 domain; the kernel
already includes child monitoring groups in their parent readings. This covers
the visible resctrl control groups, including Tupperware's workload groups.
The selected hardware event filters define the counted memory traffic, so MBM
values do not establish physical DRAM-channel bandwidth or saturation.

Cache access and miss rates use the existing paired PMU counters, expressed in
millions of events per second and grouped by each observed CPU's LLC. Aggregate
miss percentage uses the producer's paired miss/reference totals rather than
averaging the LLC percentages. PMU definitions and multiplexing coverage remain
visible in the source notes. These graphs require no additional BPF probes or
new perf events.

## Explore measurements

The additional scx-top-inspired signals appear as collapsible sections on the
page for the question they answer. Scheduling holds thread CPU usage and
scheduling delay, waker/wakee handoffs, DSQ wait/depth/run distributions, and
kernel sched_ext fallback counters. System holds IPI CPU pairs, PMU hardware
counters, LLC occupancy by memory monitoring domain, idle states, and thermal
pressure, temperature and package power. Memory traffic and cache-miss history
are charted once, with the System memory graphs. Sections remember whether they
are collapsed, and tables support search, sorting and paging. The shared
timeline replays the full tables, distributions and history charts.
`GET /api/explore` exposes the same source data; full replay snapshots include
`sources.explore`.

Collection runs once a second independently of browser requests. Its optional
BPF object is separate from the existing callback object, so unsupported
facilities do not interrupt callback collection. Detailed probes attach while
the Mitosis observer is active and rebuild after observer epoch changes. Host
and hardware readings can remain available while Mitosis is stopped. Use
`--disable-explore` to disable this additional collection entirely.

Each group has `available`, `error`, independent `meta`, `scope`, `summary`,
`rows`, and `partial`. Missing support, first counter baselines, counter resets
and incomplete coverage produce unavailable values rather than zeros. Source
availability and the actual error are visible in every section. Repeated source
sequences are deduplicated in graphs using their original capture time.

Thread detail uses a bounded sampled cohort and validates PID/birth identity
before reading actual CPU runtime from procfs. DSQ waits measure the last
observed queue segment. Unverified iterator moves clear pending residence
instead of attributing a failed move to its requested destination; move-call
attempts and omitted observations remain visible in source coverage.
Wakeup delay measures successful off-CPU wakeup to execution. Already-running
wakees are excluded and counted. Handoffs join the original `sched_waking`
context (or fork parent for new tasks) to a successful wakeup and execution.
Interrupt origins can identify the interrupted task rather than an application
sender. Handoff rates count matched sampled cycles. Bounded task/pair entries
use LRU admission; entry totals can reset after eviction and readmission. The
handoff scalar history uses separate aggregates so pair churn does not distort
its rates or latency. Histograms count unscaled observed samples, and p95/p99
need at least 20/100 samples. Source scopes and coverage describe these limits.
Current CPU ownership does not establish a task's cell membership, so these
tables retain whole-host scope. Failed optional probe families retry
independently while healthy families continue collecting.

PMU collection counts cycles/instructions, cache references/misses and
frontend/backend stalls in concurrent pairs without sampling interrupts. It
reports measured PMU running time, scales multiplexed interval counts, and
computes paired IPC/cache ratios only with valid concurrent measurements.
Support and permissions can differ by counter and CPU; descriptor use and
partial coverage are reported. Bandwidth reads existing resctrl root monitoring
data across existing control-monitor groups without mounting filesystems or
assigning tasks. Idle residency includes
active time in its elapsed-time denominator. Thermal readings retain genuine
sensor labels. Power uses energy deltas divided by elapsed time and avoids
double-counting nested power domains.

All additional sources are read-only. No scheduler configuration, sysctl,
resctrl assignment, power limit or hardware-control setting is changed.

## Verification

```bash
cargo test --locked --manifest-path tools/scx_mitosis_inspector/Cargo.toml
node --test tools/scx_mitosis_inspector/tests/*.js
```

The Rust tests include scheduler identity/epoch guards, reset validation,
migration retention and loss accounting, stats sample metadata, and scheduler
history retention and incremental views, compressed replay, past full views,
and historical migration windows. The Node
contracts exercise delayed and canceled fetches, request timeouts, cached samples,
epoch transitions, partial source failures, migration window changes, and reset
success/failure against the page scripts, together with history backfill,
instance changes, line breaks across unavailable measurements, shared timeline
clocks/controls, frozen historical views, navigation, and late-response guards.


`tests/lifecycle_vm.py` is an optional privileged integration test that refuses to
run outside a virtme guest. It starts its own scheduler and verifies waiting HTTP,
real kernel hash retention beyond 4,096 pairs, remote migration source CPU,
completed reset, scheduler stop, and reattachment after restart. Run it with a
read-only guest filesystem and at least 72 vCPUs (see its module docstring).
