# Fairness in scx_snake

> **Experimental:** FIFO remains the default. Run VTIME and EEVDF only in
> disposable VMs. EEVDF's affinity-constrained forward-progress regression
> passes, but its pinned nice-level demo currently produces approximately equal
> service instead of the expected weighted shares.

Snake separates CPU placement from CPU-time fairness. The policy ladder and
task cells choose where a task may run. The startup `--fairness` option chooses
which runnable task runs when tasks contend for CPU time.

Three disciplines are implemented:

```bash
# Existing behavior and the default.
scx_snake --policy policy.toml --fairness fifo

# Experimental weighted virtual runtime.
scx_snake --policy policy.toml --fairness vtime

# Experimental global EEVDF.
scx_snake --policy policy.toml --fairness eevdf
```

The mode is immutable BPF read-only configuration and requires a scheduler
restart to change. Runtime policy updates and task-to-cell changes do not reset
fairness state. A policy with `[queues]` requires VTIME.

## FIFO control

FIFO is Snake's default control discipline. A successful idle-CPU placement is
inserted directly into that CPU's local DSQ with `SCX_SLICE_DFL` (20 ms). Any
task that reaches `enqueue` goes to one scheduler-owned shared FIFO DSQ with
the same slice. Enqueue claims and kicks an idle allowed CPU when possible, and
`dispatch` explicitly drains the shared DSQ. This preserves stealable fallback
work without depending on the kernel's built-in global DSQ for forward
progress.

FIFO does not provide weighted fairness. It remains available as the control
for placement experiments and compatibility comparisons.

## Global-clock VTIME without `[queues]`

VTIME uses one global custom DSQ for unrestricted tasks and one custom DSQ per
CPU for affinity-restricted tasks. Every queue is ordered by task virtual
runtime and shares the same global clock. VTIME assigns a fixed physical slice
of 5 ms and charges actual runtime using the kernel-provided task weight:

```text
task.vruntime += runtime_ns * 100 / task.weight
```

The global frontier follows the latest virtual runtime observed when a task
starts running:

```text
vtime_now = max(vtime_now, task.vruntime)
```

Before a runnable task is dispatched or enqueued, Snake limits accumulated
sleeper credit to one virtual slice:

```text
task.vruntime = max(task.vruntime, vtime_now - 5 ms)
```

Queued tasks are inserted with `scx_bpf_dsq_insert_vtime()`. A task allowed on
every possible CPU uses the global DSQ. An affinity-restricted task is
distributed to an allowed CPU's custom DSQ and that CPU is kicked if idle. At
dispatch, a CPU compares the heads of its custom DSQ and the global DSQ, then
moves only the earlier task to its FIFO local DSQ. This avoids scanning past a
large incompatible affinity group and preserves VTIME ordering for pinned
tasks. All of these queues still charge the same clock; they do not create
per-CPU entitlements.

Dispatch also projects the currently running task's VTIME through the runtime
it has consumed since `running()`. sched_ext calls `dispatch()` before
`stopping()` records that runtime, so Snake replenishes the current task when
its projected VTIME is still earlier than the queued candidate. Without that
comparison, two CPU-bound tasks alternate regardless of weight.

Successful idle-CPU ladder placement can still use the direct local path;
direct and queued execution use the same runtime accounting.

This policy deliberately has no EEVDF eligibility, virtual requests, deadlines,
or future queue. It is the smaller weighted-fairness control used both directly
and as the ordering mechanism inside cell queue policies.

## VTIME with cell queues

A policy with `[queues]` replaces the global VTIME queue topology. It still
uses 5 ms physical slices and the same per-task weight scaling, but separates
normal cell work from affinity-constrained escape work.

### Normal queues and cell clocks

Each cell has one VTIME clock. The `cell` layout creates one normal ordered DSQ
per cell. The `cell_llc` layout creates one ordered DSQ for each cell/LLC pair
that owns at least one CPU, but every shard for a cell uses that same cell
clock. It does not create an independent fairness domain per LLC.

Only CPUs owned by a cell consume its normal queues. A normal enqueue is safe
only when the task may run on every CPU in the cell's primary mask. In
`cell_llc` mode, a CPU first checks its local shard and may then dispatch the
earliest head from another shard of the same cell. There is no cross-cell
normal-queue stealing.

The cell's `cpu_weight` controls how overlapping CPU claims are resolved into
primary ownership. It is resource allocation, not a VTIME weight. The kernel
task weight continues to control service order among tasks using a cell clock.

### Affinity escape queues and dual coordinates

Snake creates one affinity escape DSQ per online CPU. All escape DSQs share one
global affinity clock, not per-CPU clocks. A task whose affinity excludes any
CPU in its cell's primary mask uses one of these queues so an incompatible
normal-queue consumer cannot block it.

A queue-mode task keeps two virtual-runtime coordinates:

```text
cell_vruntime       service relative to the task cell clock
affinity_vruntime   service relative to the global affinity clock
```

Normal execution advances `cell_vruntime`. Affinity execution advances both
coordinates by the same weight-scaled runtime. The cell coordinate therefore
remembers service received through the escape path when the task later returns
to a normal queue.

When a task changes cells, raw cell vruntimes cannot be compared because the
clocks are independent. Snake preserves the task's lag relative to the old
clock, clamps it to one VTIME slice, and applies that lag to the new clock:

```text
lag = clamp(task.vruntime - old_cell_now, -5 ms, 5 ms)
task.vruntime = new_cell_now + lag
```

The global affinity coordinate persists independently across cell changes.

### Enqueue, dispatch, and borrowing

An ordinary successful placement rung records a CPU hint and proceeds through
the queue enqueue ladder. Its `cell` target tries normal storage and its
required terminal `affinity` target guarantees an affinity-safe escape. The
dispatch ladder visits its configured sources with a per-CPU cyclic cursor;
source order is not permanent priority.

The explicit `task_cell_borrowable` rung is the only direct-dispatch exception.
It may claim an allowed idle CPU owned by another cell. This bypasses ordered
queue comparison for that dispatch, so borrowing is work-conserving placement,
not strict cross-cell VTIME ordering. It also does not steal work that is
already queued.

Task identity and resource consumption remain separate. Runtime always advances
the task cell's VTIME state. Counters classify the execution as primary when it
runs on a CPU owned by that cell, or as borrowed for the task cell and lent for
the CPU-owner cell otherwise. See [`QUEUE_POLICY.md`](QUEUE_POLICY.md) for the
complete topology and callback rules.

## Global EEVDF

EEVDF uses a fixed physical request of 5 ms and `p->scx.weight`, whose baseline
is 100. Each task keeps:

```text
vruntime             weighted service already received
deadline             vruntime + weighted remaining request
request_remaining    unused physical time in the current 5 ms request
active_weight        weight fixed for the current request
pending_weight       most recently supplied kernel weight
```

Runtime is charged as:

```text
task.vruntime += runtime_ns * 100 / task.active_weight
```

The global virtual clock is charged from total runnable weight:

```text
V += runtime_ns * 100 / total_runnable_weight
```

This is deliberately not a maximum-task frontier. A low-weight task can move
its own vruntime far forward, but it cannot drag `V` forward or cause other
tasks' vruntimes to be clamped against its position. This preserves resolution
among tasks receiving most of the CPU service.

### Eligibility and queue order

A task is eligible when:

```text
task.vruntime <= V
```

Snake maintains two global custom DSQs:

| DSQ | Contains | Ordered by |
| --- | --- | --- |
| eligible | Tasks whose virtual start is at or behind `V` | virtual deadline |
| future | Tasks whose virtual start is ahead of `V` | vruntime |

`dispatch` promotes at most 64 newly eligible tasks per call, then dispatches
the earliest eligible deadline that can run on the dispatching CPU. If no
eligible task can run there, Snake advances `V` to that CPU's first
affinity-compatible future task and promotes newly eligible work. The decision
is CPU-local even though the queues are global: eligible work restricted to one
CPU cannot prevent another CPU from advancing to runnable work it can execute.

### Requests, preemption, and weights

A task keeps the unused part of its 5 ms request when it is preempted. It gets a
new deadline only when that request is consumed. Kernel weight changes are
recorded immediately but take effect at the next request boundary, so an
in-flight request cannot change meaning halfway through execution.

Sleeping tasks preserve their lag relative to the aggregate clock:

```text
lag = V - task.vruntime
task.vruntime = new_V - clamp(lag, -virtual_request, virtual_request)
```

The symmetric one-request clamp bounds both sleeper credit and sleeper debt.

### Placement interaction

The ladder and task cells remain placement mechanisms. They do not contain
deadlines or know the EEVDF queue shape.

An EEVDF task may still dispatch directly when a ladder rung actually claims an
idle CPU. The direct path uses the same 5 ms request, runtime charging, and
weight accounting as queued execution. The `sync_wake_affine` rung's non-idle
preemptive result is different: in strict mode it remains a CPU hint and the
task goes through EEVDF ordering instead of bypassing the fair queue.

Task affinity continues to be enforced by sched_ext when a custom DSQ task is
moved to a CPU-local DSQ. A cell assignment influences placement but does not
create a separate fairness domain or entitlement; fairness is global per task.

## Data ownership

Userspace supplies startup mode, compiled placement and callback ladders,
resolved CPU masks, attachment-time queue topology, and live task-to-cell
annotations. BPF reads the kernel task weight and runtime, maintains VTIME or
EEVDF clocks and per-task state, and performs ordering, accounting, and dispatch
decisions. Cell meanings remain entirely in userspace.

Global fairness is implemented in
[`src/bpf/fairness.h`](../src/bpf/fairness.h); queue-mode VTIME is in
[`src/bpf/queue_fairness.h`](../src/bpf/queue_fairness.h). Placement execution
remains in [`src/bpf/ladder.h`](../src/bpf/ladder.h).

## Validation demo

Start Snake in either ordered mode, then run the pinned workload from another
terminal:

```bash
make -C scheds/rust/scx_snake/interactive start FAIRNESS=vtime
make -C scheds/rust/scx_snake/interactive fairness-demo
```

`FAIRNESS_CPU=N` selects the contention CPU and `FAIRNESS_DURATION=N` changes
the measured seconds per case. The demo checks:

1. Two nice-0 tasks are within 15% of equal service.
2. Nice 0 versus nice 5 matches the standard 1024:335 weight ratio within 20%.
3. Adding a nice-19 peer preserves the first ratio within 25%, and every task
   makes progress.

`--stats 1` also exports the active mode, eligible/future enqueues, promotions,
forced clock advances, ordered dispatches, strict sync queues, direct and queued
runtime, lag clamps, and accounting errors. Queue mode adds per-cell total,
primary, borrowed, and lent runtime, normal/affinity enqueues and execution
selections, clock transitions, and live-rehome convergence counters. FIFO
reports shared-DSQ enqueues and explicit dispatches.

The VM-only VTIME regression combines a heavily oversubscribed narrow affinity
group with wide work. It must survive beyond the watchdog interval and report
per-CPU queue activity:

```bash
sudo scheds/rust/scx_snake/tests/vtime_mixed_affinity.sh \
  target/release/scx_snake
```

Cell queue and direct-borrowing regressions are also VM-only:

```bash
sudo scheds/rust/scx_snake/tests/vtime_cell_queues.sh \
  target/release/scx_snake
sudo scheds/rust/scx_snake/tests/vtime_cell_borrowing.sh \
  target/release/scx_snake
```

Additional VM-only contracts cover the remaining queue boundaries:

| Test | Contract |
| --- | --- |
| `fifo_fallback.sh` | Shared FIFO fallback is explicitly drained. |
| `vtime_queue_ladders.sh` | Callback ladders activate, live reorder, and select the configured first ready source. |
| `vtime_max_cells.sh` | 31 declared cells plus cell 0 run under `cell` and `cell_llc`. |
| `vtime_single_runner_rehome.sh` | A running task cannot retain an obsolete cell indefinitely. |
| `vtime_queued_rehome.sh` | An old normal-DSQ run is preserved once, then translated on re-enqueue. |
| `vtime_cell_borrowing.sh` | Direct borrowers yield after one slice before any owner-cell comparison. |

Run queue-layout tests with `SNAKE_QUEUE_LAYOUT=cell_llc` to cover populated
cell/LLC shards sharing one per-cell clock.

The VM-only affinity regression exercises this forward-progress rule:

```bash
sudo scheds/rust/scx_snake/tests/eevdf_affinity_future.sh \
  target/release/scx_snake
```

## Current scope

Global VTIME and EEVDF each use one global fairness clock. Queue-mode VTIME uses
one normal clock per cell plus one global clock for all affinity escape queues;
it deliberately has no per-CPU clocks. Cell CPU weights allocate primary CPUs
but do not provide hierarchical group fairness. There are no per-NUMA clocks,
live fairness-mode changes, queued-work borrowing, or cross-cell normal-queue
stealing. The clocks use BPF spin locks, so scalability under large runnable
sets remains an explicit experiment rather than a production claim.
