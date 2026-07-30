# scx_snake

[![Snakes and Ladders board](https://commons.wikimedia.org/wiki/Special:Redirect/file/Snakes_and_Ladders.jpg?width=720)](https://en.wikipedia.org/wiki/File:Snakes_and_Ladders.jpg)

`scx_snake` is a minimal Rust `sched_ext` scheduler for experimenting with
declarative scheduling policy. It intentionally keeps task scheduling simple so
that the userspace-to-BPF policy interface is the part under study.

This is an experimental mechanism, not a general-purpose scheduler. Do not use
it for production workloads.

The focused references are:

- [Task Cell Annotations](docs/CELL_POLICY.md): pidfd updates, task storage, and
  annotation lifetime.
- [Cell Queue Policy](docs/QUEUE_POLICY.md): cell allocation, DSQs, callback
  ladders, borrowing, and live-update rules.
- [Fairness](docs/FAIRNESS.md): FIFO, VTIME, EEVDF, clocks, and accounting.
- [Policy Lowering and BPF Data Flow](docs/POLICY_LOWERING.md): compiler stages,
  ABI records, map ownership, and the userspace/BPF boundary.

## Policies

A policy is an ordered ladder of rungs. Each rung combines an operation, such
as `claim_idle`, `pick_idle`, or `pick_idle_core`, with a scope such as
`previous_cpu`, `previous_llc`, `previous_node`, or `task_allowed`. Userspace
validates the TOML and resolves topology; BPF only executes the resulting
bounded instructions and generic CPU masks.

### Minimal policy

Try the previous CPU before searching all allowed idle CPUs:

```toml
fallback = "previous_cpu"

[[rung]]
operation = "claim_idle"
scope = "previous_cpu"

[[rung]]
operation = "pick_idle"
scope = "task_allowed"
```

### Kernel-default simulation

`select_cpu` is the `sched_ext` wakeup callback for choosing where a waking task
should run, and the kernel provides `scx_bpf_select_cpu_dfl()` as its default
implementation. To demonstrate that Snake can express practical scheduling
behavior rather than only toy policies, this example recreates the key parts of
that default as an explicit ladder: sync wake affinity, then wholly idle cores
across increasingly broad topology scopes, then individual idle CPUs. Each
stage also gets its own hit and miss counters:

```toml
fallback = "previous_cpu"

[[rung]]
operation = "sync_wake_affine"
scope = "task_allowed"

[[rung]]
operation = "pick_idle_core"
scope = "previous_llc"

[[rung]]
operation = "pick_idle_core"
scope = "previous_node"

[[rung]]
operation = "pick_idle_core"
scope = "task_allowed"

[[rung]]
operation = "claim_idle"
scope = "previous_cpu"

[[rung]]
operation = "pick_idle"
scope = "previous_llc"

[[rung]]
operation = "pick_idle"
scope = "previous_node"

[[rung]]
operation = "pick_idle"
scope = "task_allowed"
```

A policy contains one to eight rungs. Its fallback is `previous_cpu` by default;
`any_allowed` instead distributes fallback hints across the affinity mask.
Invalid operations and operation/scope combinations are rejected before BPF is
loaded. See [`examples/`](examples/) for random placement, sub-LLC partitions,
whole-core selection, paired demo-only random variants, and the opaque
kernel-default control.

`sync_wake_affine` only handles synchronous wakes. It prefers an idle previous
CPU in the waker's LLC, then the waker CPU when its local DSQ is empty and its
NUMA node has idle capacity. The latter is the only path that intentionally
targets a non-idle CPU, using a preemptive handoff.

### Task cells

Placement-only policies can define arbitrary, overlapping CPU cells and use a
thread's live cell annotation as another ladder scope:

```toml
[[cell]]
id = 7
cpus = "0-3"

[[cell]]
id = 8
cpus = "2-5"

[[rung]]
operation = "pick_idle"
scope = "task_cell"
```

The scheduler writes assignments synchronously to BPF task storage through a
thread pidfd. Sleeping tasks use the new cell at their next wake. Without a
`[queues]` section, continuously runnable tasks also evaluate task-cell rungs
from `enqueue`, keeping placement inside the declared cell whenever an eligible
CPU is idle:

```bash
sudo ./target/release/scx_snake --set-thread-cell 4812:7
sudo ./target/release/scx_snake --clear-thread-cell 4812
```

See [Task Cell Annotations](docs/CELL_POLICY.md) for the control and scheduling
data flow.

Queue policies may also derive assignments from cgroup-v2 child trees entirely
in userspace:

```toml
[membership]
parent = "/sys/fs/cgroup/workloads"

[[membership.assignment]]
child = "batch"
cell = 7
```

Only assigned child trees are scanned. Threads outside them use synthetic cell
0 without a task-storage record. Manual thread assignments override managed
membership. See [Userspace Cgroup Cell Membership](docs/CGROUP_MEMBERSHIP_PROPOSAL.md).

### Cell queue policies

Experimental VTIME policies may turn cell declarations into resource domains
and custom DSQs:

```toml
[queues]
layout = "cell_llc"

[[cell]]
id = 7
cpus = "0-7"
cpu_weight = 2

[[rung]]
operation = "pick_idle"
scope = "task_cell"

[[rung]]
operation = "pick_idle"
scope = "task_cell_borrowable"
```

Userspace resolves overlapping claims and positive CPU weights into disjoint
primary masks. It adds synthetic cell 0 for `NoCell` tasks and creates
either one normal DSQ per cell or one per populated cell/LLC pair. All LLC
shards of a cell share one cell clock. Exactly one affinity escape DSQ is
created per online CPU, and each escape queue uses the clock of the cell that
owns its CPU. Snake never creates a cell-by-CPU DSQ matrix or per-CPU clocks.

Queue enqueue and dispatch callbacks are themselves short TOML ladders. Cell
CPU borrowing is an explicit placement rung that directly claims an idle CPU
owned by another cell. It does not steal already queued work. See
[Cell Queue Policy](docs/QUEUE_POLICY.md) for syntax, clocks, update rules, and
resource accounting. The four queue examples under [`examples/`](examples/)
require `--fairness vtime`.

Queue CPU weights assign real dequeue capacity. Borrowing helps tasks at wakeup
but cannot drain work already waiting in an undersized cell's normal DSQ; such
a policy can still hit the sched_ext runnable-task watchdog while other cells'
CPUs are idle. Size weights for the workload's sustained runnable demand.

## How scheduling works

Userspace owns policy and topology. It converts LLCs, NUMA nodes, and optional
`split_llcs` partitions into generic CPU-keyed mask tables. The BPF side knows
only how to walk instructions and operate on those masks.

### Userspace lowering

The TOML ladder is a userspace language, not the BPF ABI. Before attach or
update, Rust validates each operation/scope pair, assigns reusable mask-table
IDs, resolves topology into CPU masks, and lowers every rung to a fixed record:

```text
{ opcode, input, flags, data }
```

For example, `pick_idle_core(previous_llc)` becomes
`pick_idle_mask_table(cpu_prev, intersect_task_allowed | pick_idle_core,
previous_llc_table_id)`. The words LLC and NUMA never reach BPF; they have
already become table IDs and masks.

The backend command set is deliberately small: `claim_idle`, `pick_idle`,
`pick_idle_mask_table`, `pick_random_idle`, `pick_idle_queue_mask`,
`kernel_default`, and `sync_wake_affine`. Inputs select a CPU, the task's
allowed mask, a placement-only cell, or a dense queue cell. Flags refine the
operation, and `data` carries table IDs or a primary/borrowable selector.
Userspace writes the compiled ladder and masks into an inactive BPF map slot,
asks BPF to validate it, then atomically makes that slot active.

Without `[queues]`, a successful idle-CPU rung dispatches directly to the
selected CPU's local DSQ and skips `enqueue`. Placement-only annotated tasks
also re-evaluate cell rungs from `enqueue`. FIFO puts remaining work on one
scheduler-owned shared DSQ, explicitly drains it from `dispatch`, and kicks an
idle allowed CPU. It does not depend on the built-in global DSQ. Global VTIME
uses one normal DSQ plus per-CPU affinity DSQs under one clock; EEVDF uses
global future and eligible DSQs with an aggregate clock.

With `[queues]`, an ordinary selection records a CPU hint and still flows
through the configured enqueue ladder. The enqueue ladder chooses a cell
normal DSQ or a per-CPU affinity escape DSQ. Dispatch can consume those sources
cyclically or compare them with `operation = "min_vtime"`. A successful
`task_cell_borrowable` rung is the exception: it verifies the foreign owner and
directly dispatches to the idle CPU. All-rung exhaustion remains an
affinity-safe enqueue hint in both modes.

See [Policy Lowering and BPF Data Flow](docs/POLICY_LOWERING.md) for the complete
TOML-to-opcode pipeline, runtime BPF inputs, map exchange, and update protocol.

## Build and run

From the repository root:

```bash
cargo test -p scx_snake
cargo build --release -p scx_snake

sudo ./target/release/scx_snake \
  --policy scheds/rust/scx_snake/examples/kernel-default-sim.toml \
  --fairness fifo \
  --callback-timing-sample-rate 64 \
  --stats 1
```

FIFO is the default. The `--fairness vtime` and `--fairness eevdf` modes are
experimental and should be used only in disposable VMs; changing fairness
requires a restart. EEVDF's affinity-constrained forward-progress test passes,
but its nice-level weighted-share validation is not yet correct. See
[Fairness in scx_snake](docs/FAIRNESS.md) for the clocks, queues, task
accounting, placement interaction, and current limitations.

Callback execution-time sampling defaults to one in every 64 invocations for
`select_cpu`, `enqueue`, `dispatch`, `runnable`, `running`, `stopping`, and
`quiescent`. `--callback-timing-sample-rate N` accepts zero to disable sampling
or a power of two through 4096. Unsampled calls perform only the sampling
decision; sampled calls update a per-CPU base-2 nanosecond histogram without
atomic contention. The inspector can change the rate while Snake is running;
changing it stops active fine-grained and queue-timing captures so each capture
has one sampling rate.

The inspector can independently enable fine-grained timing for `select_cpu`,
`enqueue`, and `dispatch` in every fairness mode. Fine timing reuses the same
sample decision. Sampled stages emit fixed-size records through a bounded BPF
ring buffer, and Snake immediately folds them into one fixed histogram per
stage; individual events are not retained. Select timing separates active
ladder acquisition, the policy walk, its queue/direct/fallback outcome, and
final accounting. Enqueue retains the total runnable-preparation measurement
and breaks out task storage, cell-clock, and credit-clamp work. Dispatch groups
remote normal-queue scans by queue fanout without adding work inside the scan
loop, measures affinity DSQ insertion separately from the full affinity path,
and measures the kernel move-to-local helper both in aggregate and by
normal/affinity success/miss outcome using the same elapsed duration. All BPF
DSQ operations use the typed constructors and shared wrappers in `bpf/dsq.h`.
The mutation wrappers retain both source and destination IDs, allowing
userspace to attribute removal timing to the source and insertion timing to the
destination, including built-in per-CPU local DSQs. The timer stops before one
sampled operation record is emitted; userspace derives both per-queue views and
the aggregate outcome histograms from that record.
Disabling a capture freezes it as historical. Starting a new capture resets
only that callback's histograms, and activating another policy automatically
stops active captures before the generation changes.

Queue-mode policies also support one independent, on-demand queue-timing
capture. It reuses the callback `1/N` sample decision without requiring enqueue
or dispatch fine timing. After a sampled successful normal or affinity DSQ
insertion, Snake records the post-insert depth and measures residence until the
task reaches `running`, where it records post-dispatch depth. Residence uses 64
base-2 nanosecond buckets. Depth uses 256 linear buckets, with bucket 255
covering every depth at or above 255; exact latest and maximum depths are kept
separately. The inspection payload reports started, successfully emitted, and
ring-buffer-dropped samples. Explicitly stopping the capture freezes it as
historical. Rate changes, policy activation, and scheduler shutdown stop an
active capture; resetting statistics clears its history. Queue timing is
rejected when callback sampling is disabled or the scheduler has no queue
topology.

Run a cell queue policy only with VTIME:

```bash
sudo ./target/release/scx_snake \
  --policy scheds/rust/scx_snake/examples/cell-borrowing.toml \
  --fairness vtime \
  --stats 1
```

To observe combined clock-ordered dispatch in the inspector, run the
`min_vtime` example instead:

```bash
sudo ./target/release/scx_snake \
  --policy scheds/rust/scx_snake/examples/cell-min-vtime.toml \
  --fairness vtime \
  --stats 1
```

With `scx_snake_inspector` listening on its default port, open
`http://127.0.0.1:8787/#policy`. The Dispatch ladder should show
`min_vtime(cell,affinity)`, `Lowest VTIME; alternating exact ties`, and no
cyclic cursor marker. Use `Ctrl-C` in the scheduler terminal to stop Snake.

Replace the complete ladder without restarting the scheduler:

```bash
sudo ./target/release/scx_snake \
  --update-policy scheds/rust/scx_snake/examples/random-idle.toml
```

The running process compiles and resolves the new file, prepares it in an
inactive ladder slot, then publishes it with one atomic switch. A rejected
update leaves the current ladder running. Queue topology is attachment-time
state; a live update may reorder dispatch sources or add the cell callback pair,
but may not change the resolved topology or remove a target/source that may
still contain queued work.

The interactive cell demo generates three cells from the host's online CPUs,
including one overlapping cell, and moves two bursty tasks between them. Run
Snake in one terminal, then use another:

```bash
make -C scheds/rust/scx_snake/interactive cell-demo

# Or drive each step manually.
make -C scheds/rust/scx_snake/interactive cell-demo-start
make -C scheds/rust/scx_snake/interactive cell-demo-move CELL=1
make -C scheds/rust/scx_snake/interactive cell-demo-status
make -C scheds/rust/scx_snake/interactive cell-demo-stop
```

The just-for-fun cell-art gallery is a separate crate under
[`demos/cell_gallery`](demos/cell_gallery/). On a 316-CPU presentation host it
defines 952 two-CPU cells once, maps one bursty worker thread to each cell once,
and cycles flower, heart, cat, and snake outlines:

```bash
# Start Snake and the inspector in their own terminals first.
make -C scheds/rust/scx_snake/interactive start
make -C scheds/rust/scx_snake/interactive inspector

# Then start the standalone gallery demo.
make -C scheds/rust/scx_snake/interactive cell-art-gallery
```

In the inspector, select the printed gallery TGID, Numeric CPU order, and a 10
second window. Each image runs for 10 seconds by default, so the rolling window
crossfades naturally into the next image. `Ctrl-C` stops the workers and
restores the configured policy.

Validate EEVDF shares with CPU-bound tasks pinned to one CPU:

```bash
make -C scheds/rust/scx_snake/interactive start FAIRNESS=eevdf
make -C scheds/rust/scx_snake/interactive fairness-demo
```

Inspect the compiled ladder and resolved mask tables without attaching BPF:

```bash
./target/release/scx_snake \
  --policy scheds/rust/scx_snake/examples/kernel-default-sim.toml \
  --dump-compiled-policy
```

## Statistics

The text output from `--stats 1` shows the active policy generation plus
attempts, hits, misses, and errors for each rung. A successful update advances
the generation and starts fresh counters with the new rung labels. Also watch
`direct_dispatches`, `ladder_exhaustions`, `enqueues`, and `invalid_errors`; the
last should remain zero. FIFO also reports shared-DSQ enqueues and explicit
dispatches. VTIME reports ordered enqueues and dispatches, the
per-CPU subset of each, direct/queued runtime, sleeper-credit clamps, and
accounting errors. `min_vtime` dispatch also reports exact head ties resolved by
per-CPU alternation. Queue mode additionally reports each cell's total, primary,
borrowed, and lent runtime, normal and affinity enqueues and execution
selections, and clock transitions, plus keep-running suppressions and
unavoidable old-queue runs for pending live rehomes. Direct-borrow yield counts
confirm that foreign CPUs are reconsidered after one slice. EEVDF also reports
its two queue insertion counts, promotions, forced advances, direct/queued
runtime, lag clamps, and accounting errors.
Queue mode also publishes `membership_no_cell_runs` and
`membership_invalid_runs`; the latter must remain zero.

The inspection stats target also publishes cumulative sampled callback
histograms for the active policy generation. `scx_snake_inspector` turns these
into rolling and policy-lifetime mean, p50, p95, and p99 estimates in its
Callbacks tab. Percentiles are reported as the upper bound of a base-2 bucket;
p95 requires at least 20 samples and p99 at least 100. The same target publishes
the current or historical fine-grained capture for each supported callback.
The inspector's **Reset all stats** action switches to a cleared ladder stats
bank without changing the policy generation or reloading Snake. It also clears
fine-grained and queue-timing capture history while leaving DSQs, clocks,
membership, and task cell assignments intact.

Use `--stats-format json` for NDJSON, `--help-stats` for counter definitions, or
monitor an already running scheduler without a policy:

```bash
sudo ./target/release/scx_snake --monitor 1
```

This workload exercises the synchronous-wake rung:

```bash
stress-ng --pipe 4 --futex 4 --timeout 30s --metrics-brief
```

## Limits

Topology is resolved before a policy is attached or updated. The kernel-default
simulation does not implement distance-ordered remote NUMA search. FIFO
explicitly drains one shared DSQ but has no topology-aware enqueue or stealing
policy. Global VTIME and EEVDF
remain global-clock experiments; only VTIME with `[queues]` provides per-cell
clocks and configurable cell or cell/LLC storage. Queue mode supports at most
31 declared cells plus synthetic cell 0, does not steal queued work across
cells, and cannot change its DSQ topology live. The ABI remains experimental.
