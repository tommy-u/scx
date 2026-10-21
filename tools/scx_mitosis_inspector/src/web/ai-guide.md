# Mitosis inspector: AI guide

Use this guide to investigate a running inspector through HTTP. Its JSON APIs
serve the same collected data used by the dashboard. Collectors normally refresh
about once a second; an HTTP request reads the latest published data and does
not trigger a new measurement. Sources publish independently.

## Connect

Give Codex the inspector's base URL and an investigation question, for example:

> Read http://HOST:44103/ai-guide, then inspect the current scheduler. Explain
> CPU allocation, utilization, borrowing, and callback latency. Cite the API
> fields and collection timestamps supporting each finding, and identify missing
> evidence. If needed, poll for a few seconds to look for correlations.

The Codex session needs HTTP access to that host. Use the existing inspector
address; the default listener is `[::]:44103`. Use a reachable hostname or IP
in the client URL, rather than the wildcard listen address. The IPv6 listener
also accepts IPv4 on Linux with `net.ipv6.bindv6only=0`. These examples use curl;
jq is optional and helps keep large responses manageable. If a configured HTTP
proxy rejects requests to the inspector, connect directly with curl's
`--noproxy HOST` option.

```bash
INSPECTOR_URL='http://HOST:44103'
curl --fail --silent --show-error --compressed "$INSPECTOR_URL/ai-guide"
curl --fail --silent --show-error --compressed "$INSPECTOR_URL/api/stats"
curl --fail --silent --show-error --compressed "$INSPECTOR_URL/api/stats/history"
curl --fail --silent --show-error --compressed "$INSPECTOR_URL/api/timeline"
curl --fail --silent --show-error --compressed "$INSPECTOR_URL/api/system"
curl --fail --silent --show-error --compressed \
  "$INSPECTOR_URL/api/counters?include_migrations=false" |
  jq '{meta, collector, probe_manifest, counters, callback_timings}'
curl --fail --silent --show-error --compressed \
  "$INSPECTOR_URL/api/migrations?window_ms=10000"
```

## Choose an endpoint

| GET endpoint | What it answers |
| --- | --- |
| `/api/host-context` | Hostname, kernel release, and CPU/core/LLC/NUMA topology; use CPU IDs to join other responses. Discovered when the inspector starts. |
| `/api/config` | Scheduler process, executable, version, command line, and option descriptions/defaults, discovered at attachment. Check `available` and `error`. Values are inferred from process arguments and executable help, rather than a readback of all effective BPF configuration. With multiple matching processes, verify the reported identity. |
| `/api/stats` | Scheduler-reported global and per-cell `metrics`, including allocation, utilization, queue decisions, borrowing, and rebalancing. `cpu_cells` maps logical CPU IDs to owning cell IDs; `cpu_cells_error` is separate from the scheduler stats `error`. |
| `/api/stats/history` | Up to 30 minutes of successful scheduler cell samples retained by the inspector. Each sample contains `meta` and original `cells` fields for `num_cpus`, `util_pct`, and `smoothed_util_pct` when available. Use these for recent allocation and utilization investigations without waiting for a new capture. |
| `/api/timeline` | Shared replay bounds, server clock, instance/cursor metadata, and retained compact graph frames across all data pages. Optional `instance_id` and `after_seq` request only new frames; `window_ms` selects historical migration locality. |
| `/api/timeline/view?at_unix_ms=T&window_ms=W` | Complete retained source snapshots at or before T, including counters/histograms, full scheduler stats/CPU owners, System metrics, configuration, source errors, and a migration window ending at the selected time. Omit T for latest. |
| `/api/counters?include_migrations=false` | Callback counts/rates and timings, CPU runtime, scheduler events/timings, DSQ metrics, IRQs, block I/O, kernel BPF runtime, and `probe_manifest`. Omits only the potentially large lifetime `migrations` array. Omitting the query parameter returns that array too. |
| `/api/migrations?window_ms=10000` | Whole-host source-to-destination CPU migration counts over a rolling window. Read `rows`, `total`, `rate_per_second`, `observed_ms`, and `migration_quality`. |
| `/api/system` | Host CPU, memory, PSI pressure, network, CPU frequencies, and sched_ext state from procfs/sysfs. Metric groups expose `available`, `value`, and `error`. |
| `/api/explore` | Per-DSQ/thread scheduling detail, PMU counters, resctrl memory/cache metrics, waker/wakee handoffs, kernel sched_ext events, IPI pairs, idle states, and thermal pressure/temperature/package power. Each group reports independent metadata, coverage and support errors. |

The migration window is in milliseconds. Its default comes from `--window`
(normally 10 seconds). `max_window_ms` reports existing retention, configured by
`--max-window` (normally 5 minutes). Zero or a window beyond retention returns
HTTP 400. `observed_ms` can be shorter than requested after attachment/reset;
the rate uses that observed duration. Counts are collected in interval bins,
so window boundaries have collection-interval granularity.

## Browser pages

Pages are grouped by the question they answer. Timeline signal names are source
namespaces, not page names: for example, `callbacks.*` CPU utilization and
wakeup latency signals are charted on System and Scheduling.

| Page | Question it answers | Main sources |
| --- | --- | --- |
| `/` (Cells; also `/stats`) | Is mitosis partitioning CPUs as expected? | `/api/stats`, `/api/stats/history` |
| `/scheduling` | How long do tasks wait, and where do they move? | `/api/counters` scheduler timings, events and DSQ metrics; `/api/migrations`; `/api/system` sched_ext state; Explore `tasks`, `wakers`, `dsqs`, `scx_events` |
| `/callbacks` | What do mitosis's BPF callbacks cost? | `/api/counters` callback counts, timings and kernel BPF runtime |
| `/system` | Is something outside the scheduler interfering? | `/api/system`; `/api/counters` CPU runtime, IRQs and block I/O; Explore `ipis`, `perf`, `bandwidth`, `idle`, `pressure`, `thermal`, `power` |
| `/config` | How is mitosis configured? | `/api/config` |
| `/inspector` | Is collection healthy, and what does the inspector cost? | Every source's metadata, `probe_manifest`, inspector BPF runtime |

`/explore` and `/appendix` redirect to `/scheduling` and `/inspector`.

Scheduler cell history is collected independently of browser requests and is
retained in memory for `retention_ms` (normally 1800000 ms). The response includes
`instance_id`, `reset`, and ordered `samples`, together with the latest source's
`meta` and current `collector` state. On later requests, pass the returned
`instance_id`, epoch, and last sequence as `instance_id`, `epoch`, and
`after_seq` query parameters to fetch only missed samples. If `reset` is true,
replace the previous history with the returned buffer. This handles inspector
restarts, observer epoch changes, and cursors outside retention. Deduplicate by
`(instance_id, epoch, sample_seq)` and compare only samples from the same
inspector instance and observer epoch.

Old successful history samples remain valid when the latest read fails; inspect
the response's `meta.error` and timestamps for current health. Missing samples
are collection gaps, not evidence of zero activity. This endpoint does not
retain CPU-owner maps or callback timing distributions. Restarting the inspector
or resetting the observer clears its scheduler history. It does not depend on
the migration `--window` or `--max-window` flags.

## Shared timeline and replay

All browser screens have a shared time slider, Live/step controls, and separate
Viewing and Now clocks with date, seconds, and local timezone. The selected
absolute time persists across navigation. Graphs and tables replay data at or
before that selected time. Inspect `/api/timeline` to discover available bounds
before requesting a past full view. `/guide` is the browser guide with the same
controls; `/ai-guide` remains machine-readable Markdown.

`/api/timeline` returns `instance_id`, `retention_ms`, `now_unix_ms`,
`oldest_at_unix_ms`, `latest_at_unix_ms`, `sample_seq`, `reset`, and `frames`.
Each frame has an inspector-global `seq`, observation `at_unix_ms`, source
`epochs`, original `source_meta`, `source_available`, and compact `signals`.
Frame sequences continue through automatic scheduler epoch changes. Pass the
returned `instance_id` and `sample_seq` as `instance_id` and `after_seq` together
for an incremental request. Replace the previous buffer if `reset` is true.
`window_ms`, `default_window_ms`, and `max_window_ms` describe the resolved
request window and server configuration, even before samples are available.
Omit `window_ms` to use the inspector's configured default. Invalid window
responses include valid default/max values for automatic client recovery.

Source metadata is distinct from frame metadata: repeated frame observations
of one cached source sequence are not new measurements. Use original source
capture timestamps and deduplicate `(instance_id, source, epoch, sample_seq)`.
Unavailable/error samples are gaps, not zeros. Never subtract cumulative
counters or join incompatible source epochs across a scheduler restart.

`/api/timeline/view` returns `requested_at_unix_ms`, actual floor-frame
`at_unix_ms`, `collector`, `sources`, `source_errors`, available bounds, server
clock, and `migrations`. Sources retain their original metadata and include all
counter histograms and CPU bands, complete scheduler stats/owners, System
metrics, and configuration. The snapshots are independently collected source
reads, not an atomic scheduler transaction. Inspect per-source capture times
and errors. Expired requests return an error with bounds; do not substitute
current data and label it historical.

Replay retains up to 30 minutes in memory, bounded by record and byte budgets.
The advertised bounds report actual availability. Migration delta bins retain
the scrub interval plus the maximum selectable window (normally 35 minutes),
so `window_ms` can change while viewing the past. Windows exclude future data,
filter the selected counter epoch, and report observed coverage and quality;
their boundaries have collection-interval granularity. Locality signals use
the requested window rather than a fixed ten-second approximation.

Collection continues while the browser is closed or its tunnel is disconnected.
Automatic epoch changes keep past replay frames; a successful explicit reset
clears replay and returns the browser to Live. Failed resets preserve retained
data. Restarting the inspector clears all in-memory history and changes its
instance ID. Historical browser downloads export the selected full view.

## Check freshness and identity first

### System memory and cache graphs

`/system` presents paired aggregate/per-LLC curves for monitored memory
bandwidth, cache accesses, cache misses and cache miss percentage. Their sources
are the retained `explore.bandwidth` and `explore.perf` groups. Per-LLC signals
use `explore.bandwidth.llc.<id>.mbm_total_bps`, `mbm_local_bps`, and
`explore.perf.llc.<id>.cache_references_per_second`, `cache_misses_per_second`,
`cache_miss_pct`; these retain the same source metadata as their aggregate.

Bandwidth is decimal GB/s of MBM-monitored traffic. Aggregate readings sum root
and visible top-level control-monitor groups; child monitoring groups are
already included by their parent and must not be counted twice. Counter filters
define the traffic included. These values do not measure physical DRAM-channel
throughput or percent of sustainable bandwidth.

The CPU migration matrix on `/scheduling` has a Mem. BW strip immediately below
LLC utilization. It displays the selected full snapshot's per-LLC
`mbm_total_bps` in decimal GB/s, joined by mapped `llc` ID. Numeric CPU ordering
can split an LLC into several spans; those spans repeat the same domain rate.
Colors compare measured LLCs within that sample. Hover reports the original
capture time, coverage, and color scale; unavailable readings remain unknown.

Cache accesses/misses are millions of PMU events per second, grouped by CPU LLC.
Miss percentages use paired misses divided by paired references, with producer
coverage and multiplexing. The aggregate is weighted by the underlying paired
counts rather than an average of LLC percentages. Missing data remains null,
and historical plots do not issue live metric requests.

### Explore measurement sources

Eleven source groups appear as nine collapsible browser sections on the page
for their question: `tasks`, `wakers`, `dsqs`, and `scx_events` on
`/scheduling`; `ipis`, `perf`, `bandwidth`, `idle`, and one Thermal pressure &
power section for `pressure`, `thermal`, and `power` on `/system`. `GET /api/explore` returns `meta`,
`collector`, and `groups`; each group has `available`, `error`, its own `meta`,
`scope`, `summary`, `rows`, and `partial`. A successful report of unavailable
sources retains each actual support error. Null values are not zero activity.

Replay full views include `sources.explore`. Compact frames retain per-group
metadata and availability under `explore.<group>` and scalar summary signals
under `explore.<group>.<field>`. Deduplicate each group's original source
sequence and use its capture timestamp, rather than the composite report time.
Host/PMU sources retain their independent lifetime while detailed probe groups
belong to the observer epoch. Automatic scheduler changes retain prior archive
frames; explicit resets clear replay. `--disable-explore` disables collection.

Thread CPU runtime comes from procfs with PID/birth checks and a bounded sampled
thread cohort. DSQ latency covers the last observed queue segment until execution;
unverified iterator moves clear pending residence, and their call attempts and
excluded observations are counted. Wakeup delay covers successful off-CPU
wakeup to execution. Already-on-CPU successes are excluded and counted instead
of being matched to an unrelated later run. Handoffs retain the original
`sched_waking` task/CPU (fork parent for new tasks), join successful wakeup to
execution, and count matched sampled cycles. Interrupt origins can still
identify the interrupted task rather than an application sender. Bounded LRU
entry counters restart after readmission; separate aggregates keep handoff
history independent of pair eviction. Histograms use unscaled observed samples,
bucket upper-bound percentiles, and the existing 20/100-sample p95/p99 floors.
Read sampling, entry scope, coverage and losses before inferring host totals.
Borrowing prevents attributing a task to a cell using CPU ownership alone.

PMU counts include kernel/hypervisor execution on the observed logical CPU.
Concurrent counter pairs support IPC/cache ratios; interval counts are scaled
by measured PMU running time. First baselines, resets, absent running coverage,
offline CPUs and unsupported events remain unavailable. Resctrl bandwidth and
cache occupancy require existing root monitoring data. Power uses energy delta
over elapsed time with exported wrap ranges. Idle-state percentages use elapsed
wall time including active execution; delayed kernel idle accounting is marked
incomplete. Sensor labels preserve actual hardware scope. Collection never
changes scheduler configuration, sysctls, resctrl assignments or power settings.

Each CPU in `/api/host-context` includes `core_topology_available`. When false,
the integer package/core fields are fallbacks and do not establish physical
core or SMT sibling identity. The CPU placement diagram shows those CPUs as
unpaired tiles with dashed outlines.
LLC IDs follow default SCX physical-cache discovery order. Resctrl `domain_id`
is a separate hardware identifier; use each row's mapped `llc` or CPU list for
joins. A scheduler that flattens or virtualizes its topology can use different
LLC identities.

Counters, stats, migrations, and system responses have `meta` and `collector`:

- `meta.epoch` identifies the observer session. Attachment/reset creates a new
  epoch. `collector.scheduler_name` and `scheduler_enable_seq` identify the
  observed scheduler. Treat a new inspector process as a new baseline too.
- `meta.sample_seq` advances independently for each source. The same sequence
  in repeated responses is cached data, not another observation. Sequence
  numbers from different sources need not match.
- `meta.captured_at_unix_ms` and `last_success_at_unix_ms` are Unix timestamps
  in milliseconds. Check their age and `meta.error` before using the values.
  A null capture timestamp or sequence zero means there is no successful sample
  in the current observer session; last-success time can refer to an older one.
- `collector.status` can be `waiting`, `attaching`, `active`, `resetting`, or
  `error`. HTTP 200 alone does not mean probes are actively collecting.
  Host system metrics can still be useful while Mitosis is inactive.
  For `/api/system`, inspect each metric group's availability/error even when
  `meta.error` is null. `/api/stats` can retain cached metrics after a read fails.
- Sources are not an atomic cross-endpoint snapshot. Correlate nearby successful
  timestamps in a compatible epoch; do not subtract or join across a restart or
  reset. `/api/config` has no sample metadata, so qualify its process identity
  and inferred defaults separately.

## Interpret the measurements

| Fields | Meaning and time basis |
| --- | --- |
| Callback `counters[].count`, scheduler event `count`, IRQ counts, DSQ operation counts, block-I/O totals, and lifetime migration counts | Cumulative observed totals since observer attachment/reset. `rate_per_second` fields use differences over the collector's latest interval, which is not necessarily exactly one second. |
| `callback_timings`, `scheduler_timings`, IRQ timing rows, DSQ residence, and block-I/O latency | Cumulative timing distributions since observer attachment/reset. They are not the latest second's percentiles. Durations ending in `_ns` are nanoseconds; divide by 1000 for microseconds. |
| `cpu_runtime[].runtime_ns` / `utilization_pct` | Cumulative non-idle task runtime / latest-interval percentage per logical CPU, measured from sched_switch. Covers the whole host, including non-SCX tasks, and can overlap interrupt time. |
| `interrupt_cpu` | Latest-interval hardirq/softirq percentages derived from probe duration deltas. These are whole-host activity, not attribution to Mitosis. Do not assume runtime and IRQ percentages are disjoint. |
| `cpu_capacity_loss` | Latest-interval policy-based RT (FIFO/RR), deadline, and hypervisor steal percentages. The RT/stop-labelled field does not account for every non-SCX class; SMI/NMI duration is unmeasured. |
| `bpf_program_stats`, `inspector_bpf_program_stats` | Kernel cumulative program-lifetime run counts and runtime. `average_runtime_ns` is a cumulative per-run average, distinct from sampled callback elapsed latency. Runtime accounting requires `kernel.bpf_stats_enabled=1`; missing/zero runtime does not establish zero overhead. Inspector CPU percentages are interval estimates: one-CPU equivalent and whole-host capacity use different denominators. They exclude userspace collection and HTTP-serving cost. |
| `dsq_metrics.depth_average`, `depth_max`, `depth_latest_max` | Average and maximum of observed queue-depth samples, plus the maximum retained in the most recent per-CPU observations. These are not an instantaneous total queue backlog. |
| `/api/stats` `metrics` | Passed through from the scheduler's `top` operation; fields depend on scheduler version. Use its reported utilization/distribution values directly rather than applying observer-counter deltas to every numeric field. |
| `/api/system` | `interval_ms` is time since the previous collection. CPU/network rates use elapsed time since their previous successful source read, which can be longer after errors; initial rates can be null. Totals are kernel counters with their own lifetime. Memory, runnable/blocked task counts, frequency, and sched_ext state are current reads. PSI `avg10`, `avg60`, `avg300` are percentages averaged over 10/60/300 seconds; `total_us` is cumulative stall time in microseconds. Memory/network bytes and frequency `_khz` retain their named units. |

Useful scheduler fields: `cells[id].num_cpus` is assigned logical CPU capacity;
`util_pct * num_cpus / 100` expresses that cell's reported utilization in CPU
units, not queued demand. Borrowing can make cell utilization exceed 100%; do
not clamp it. `smoothed_util_pct` is EWMA-smoothed. `local_q_pct`,
`cpu_q_pct`, and `cell_q_pct` describe queue decisions, not queue lengths.
`borrowed_pct` is a scheduling distribution percentage; `demand_borrow_pct`
describes borrowed running time and `lent_pct` describes lent capacity. They have
different denominators. When present, `borrow_flows` identifies borrower/lender
cells and their latest-interval `runtime_ns`. In the current scheduler,
`total_decisions`, `drain_cnt`, and slice-shrink counts describe its collection
interval; `rebalance_count` is cumulative over scheduler lifetime. CPU ownership
reads can observe an allocation update in progress.

Scheduler timing definitions: `wakeup_to_running` measures a sampled off-CPU
wakeup until next running. Wakeups of tasks still executing are excluded.
`on_cpu_slice` measures a sampled non-idle task's running time until switch-out.
`blocked_off_cpu` starts at an actual blocking switch and ends at wakeup;
preemptions and runnable reschedules are excluded. These are whole-host timings.
The legacy scheduler event name `voluntary_switches` counts non-preempting
runnable reschedules and is displayed as "Runnable reschedules".

## Sampling and missing evidence

- Read `probe_manifest` for active/disabled/unavailable groups and host versus
  Mitosis scope. Empty arrays, null values, or disabled groups do not establish
  zero activity. Availability is reported separately where supported.
- Callback timing defaults to random 1/1024 selection (`callback_timing_sample_rate`);
  scheduler task timing defaults to random 1/64 (`event_timing_sample_rate`).
  These are expected rates, not exactly every Nth event. Zero disables the
  latency measurement. Exact CPU runtime remains active and has a separate
  manifest row from sampled scheduler timing. `--disable-explore` excludes the
  additional Explore probes, hardware counters, and host sources. Optional
  programs and unused maps are omitted before loading; maps shared with enabled
  programs remain available.
- Timing percentiles are histogram bucket upper-bound estimates, not exact
  quantiles. p50 needs at least one sample, p95 at least 20, and p99 at least 100;
  otherwise the field is null. The reported `samples` count is observed timings,
  not total callback/event count. Rare tails can be missed by sampling.
  Explore lifetime maxima use native maximum counters when their quality checks
  pass. Exact interval maxima cannot be recovered by subtracting cumulative
  histograms and remain unavailable.
- Callback elapsed latency can include interruptions; it is not an exclusive
  CPU-time breakdown. Aggregate histograms do not contain individual callback
  timestamps, call stacks, or an exact maximum latency.
- Check `migration_map_failures` / `migration_quality`, hard IRQ
  `metrics_map_full`, `starts_map_full`, `unmatched_exits`, and block-I/O
  `tracking_failures` / `unmatched_completions`. Qualify incomplete evidence.
  An `Exact` manifest label describes unsampled observation, not a guarantee of
  lossless event correlation. DSQ residence uses bounded task tracking without
  a published loss counter.

## Investigation workflow

1. Read host context/config and check source freshness, scheduler identity, and
   probe availability. Use `/api/stats` for Mitosis utilization/allocation and
   `/api/system` for overall host pressure.
2. Choose the relevant counters/timings and inspect sample counts. For a current
   latency question, explicitly label the API's distributions as cumulative.
3. If a trend is needed, poll relevant sources about once a second and retain
   observations in the Codex session. Deduplicate by source epoch/sequence.
   Histogram bucket differences within one epoch can describe new observed
   timings; never average or subtract percentile values to get a window p99.
4. Join CPU IDs to topology and `cpu_cells` when investigating locality. Compare
   nearby interval rates/utilization/pressure while respecting source scope.
5. Report observations and correlations separately from proposed causes. Cite
   endpoint, field, timestamp, epoch, sample count, and collection limitations.
   Individual task decisions or the cause of a specific slow callback require
   additional event evidence beyond these aggregates.

The APIs expose current published data, the rolling migration window, and
retained scheduler cell history through `/api/stats/history`, and shared
complete replay through `/api/timeline` and `/api/timeline/view`. All data pages
load retained graph history and selected snapshots when opened or resumed.
Hidden tabs pause their HTTP polling; becoming visible fetches the missed
archive frames while retaining the selected historical time. A failed reset
preserves history and remains a notice; later successful source reads restore
their fresh status. If a collection worker unexpectedly exits or panics, the
inspector shuts down instead of indefinitely serving a last snapshot as active.
Diagnosis uses the GET endpoints above. `POST /api/reset` is a mutation: it
rebuilds observer state and clears observer totals/history while preserving
scheduler stats and kernel counters. Use it only when the user requests a reset.
