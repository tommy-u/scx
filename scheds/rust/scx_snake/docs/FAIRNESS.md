# Fairness in scx_snake

> **Experimental:** FIFO remains the default. Run VTIME and EEVDF only in
> disposable VMs. EEVDF's affinity-constrained forward-progress regression
> passes, but its pinned nice-level demo currently produces approximately equal
> service instead of the expected weighted shares.

Snake separates CPU placement from CPU-time fairness. The policy ladder and
task cells choose where a task may run. The startup `--fairness` option chooses
which runnable task runs when tasks contend for CPU time.

This document is the service-ordering and clock reference. See
[`QUEUE_POLICY.md`](QUEUE_POLICY.md) for queue configuration and resource
ownership, and [`POLICY_LOWERING.md`](POLICY_LOWERING.md) for the userspace/BPF
ABI.

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
runtime and shares the same global clock. VTIME scales its physical slice down
for weights below the baseline of 100, with a 1 ms floor for scheduler-tick
granularity, and caps it at 5 ms for larger weights:

```text
physical_slice_ns = max(1 ms, 5 ms * min(task.weight, 100) / 100)
```

Thus weights 1 through 20 receive 1 ms, weight 50 receives 2.5 ms, and weight
100 or higher receives 5 ms. A weight below 20 advances farther in virtual time
per turn and is therefore chosen less frequently; over a complete virtual
period, physical service remains proportional to task weight. Weights above
100 advance less per 5 ms turn and are chosen more frequently.

Snake derives virtual service from both measured runtime and the consumed
sched_ext slice. Initial dispatch establishes a service budget. Each
keep-running replenishment replaces the current remainder with a new physical
slice and extends that budget. Stopping bounds virtual service to the total
budget accumulated during the continuous run:

```text
service_budget_ns += new_slice_ns - replaced_remaining_slice_ns
consumed_budget_ns = service_budget_ns - remaining_slice_ns
service_ns = min(service_budget_ns, max(runtime_ns, consumed_budget_ns))
task.vruntime += service_ns * 100 / task.weight
```

This means `sched_yield()` forfeits the remaining slice and a non-preemptible
overrun cannot create unbounded virtual debt. Runtime statistics still record
the complete measured runtime, including overruns; only VTIME ordering uses the
bounded service value.

The task weight used to size a slice is retained for that queued or continuous
run. A weight change while the task waits does not reinterpret an already
assigned slice under the new weight; the next enqueue or direct assignment
adopts the new value.

The global frontier follows the latest virtual runtime observed when a task
starts running:

```text
vtime_now = max(vtime_now, task.vruntime)
```

Before a runnable task is dispatched or enqueued, Snake limits accumulated
sleeper or queue-wait credit to one virtual slice:

```text
task.vruntime = max(task.vruntime, vtime_now - 5 ms)
```

The clamp is repeated when the task starts running because a shared frontier can
advance while that task waits in a DSQ. Without the run-start clamp,
`keep_running` could repeatedly replenish an old task for seconds while it
caught up to a newer affinity head.

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

## Global-clock VTIME with LLC queues

`layout = "llc"` keeps the global VTIME service model above but replaces its one
normal DSQ with one normal DSQ per userspace-discovered LLC. It creates no cells
or synthetic cell 0, and all normal and per-CPU queues share the same global
clock. LLC shards reduce contention and favor local consumption without adding
fairness domains or entitlements.

The enqueue ladder first tries the normal queue associated with its selected CPU.
That insert is safe only when every consumer of the queue is contained in the
task's current allowed mask. Narrow work instead uses the terminal per-CPU
escape queue. Queue depth does not redirect enqueues, so the storage decision is
stable and affinity driven.

Each dispatch peeks its CPU queue, local normal queue, and one remote candidate,
then selects the minimum VTIME head. A bounded rotating scan advances past
local, empty, and head-incompatible remote queues until it finds that candidate
or exhausts the configured queues. The selected atomic move can still miss if
the head changes. Dispatch then tries CPU, local, and the sampled remote queue
once each in configured fallback order. The bounded fallback avoids retry loops
while ensuring a stale peek does not hide immediately available local work.

## VTIME with cell queues

A cell queue policy replaces the global VTIME clock topology. It still uses the
same weight-scaled physical slices and bounded-service accounting, but separates
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

A static cell's `cpu_weight` controls how overlapping CPU claims are resolved
into primary ownership. Managed child cells use equal admission weights;
exclusive constraints are honored before their target deficits divide contested
and unclaimed CPUs. These are resource-allocation weights, not VTIME weights.
The kernel task weight continues to control service order among tasks using a
cell clock.

### Affinity escape queues and dual coordinates

Snake creates one affinity escape DSQ per online CPU. Each escape DSQ uses its
CPU owner's cell clock; there are no per-CPU clocks. A task whose affinity
excludes any CPU in its cell's primary mask uses one of these queues so an
incompatible normal-queue consumer cannot block it.

A queue-mode task keeps two virtual-runtime coordinates:

```text
cell_vruntime       service relative to the task cell clock
affinity_vruntime   service relative to the target CPU owner's cell clock
```

Normal execution advances `cell_vruntime`. Affinity execution advances both
coordinates by the same weight-scaled runtime. The task-cell coordinate
remembers service received through the escape path, while the owner-cell
coordinate orders the task against normal work consuming that CPU.

When a task changes cells, raw cell vruntimes cannot be compared because the
clocks are independent. Snake preserves the task's lag relative to the old
clock, clamps it to one VTIME slice, and applies that lag to the new clock:

```text
lag = clamp(task.vruntime - old_cell_now, -5 ms, 5 ms)
task.vruntime = new_cell_now + lag
```

When an affinity target changes to a CPU owned by another cell, Snake translates
the affinity coordinate with the same bounded-lag rule.

### Enqueue, dispatch, and borrowing

The enqueue ladder chooses normal cell storage or an affinity-safe escape. A
source-based dispatch ladder rotates classes without comparing their clocks;
`min_vtime` instead compares normal and affinity heads after both are expressed
in the CPU owner's cell clock, alternating exact ties per CPU.

The `task_cell_borrowable` placement rung is the direct-dispatch exception. It
may use an idle CPU owned by another cell, bypassing ordered comparison for one
slice without stealing already queued work. Runtime still advances the task
cell's VTIME state, while resource counters classify foreign-CPU execution as
borrowed and lent. [`QUEUE_POLICY.md`](QUEUE_POLICY.md) owns the complete
callback, borrowing, and accounting rules.

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

An affinity-constrained runnable task can fall far behind the global clock when
its allowed CPUs cannot deliver its global entitlement. At run start, Snake
bounds that task's stale lag to one weight-scaled virtual request and recomputes
the deadline from the remaining physical request. Thus each stale task can
carry at most one request of catch-up service; recovery time still scales with
the number of tasks in the constrained cohort. This is not a separate fairness
domain or an absolute latency bound. Persistent affinity overload can forfeit
service credit that the allowed CPUs cannot deliver. The
`eevdf_run_lag_clamps` counter records this path separately from sleeper-lag
clamps.

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
resolved CPU masks, active-bank queue topology, and live task-to-cell
annotations. BPF reads the kernel task weight and runtime, maintains VTIME or
EEVDF clocks and per-task state, and performs ordering, accounting, and dispatch
decisions. Cell meanings remain entirely in userspace.

Global fairness is implemented in the `src/bpf/fairness_*.h` modules;
queue-mode VTIME is in
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
runtime, lag clamps, and accounting errors. Every queue policy adds per-rung
enqueue and dispatch outcomes, selections, atomic move misses, and bounded
fallback counters.
Cell layouts also add per-cell total, primary, borrowed, and lent runtime,
normal/affinity enqueues and execution selections, clock transitions, and
live-rehome convergence counters. FIFO reports shared-DSQ enqueues and explicit
dispatches.

The VM-only VTIME regression combines a heavily oversubscribed narrow affinity
group with wide work. It must survive beyond the watchdog interval and report
per-CPU queue activity:

```bash
sudo scheds/rust/scx_snake/tests/vtime_mixed_affinity.sh \
  target/release/scx_snake
```

The focused LLC queue regression validates one global clock with no synthetic
cells, local and per-CPU enqueue paths, dispatch selections, and queue-rung
counter invariants. It runs on a one-LLC guest as an attach/local/CPU smoke test
and additionally requires remote selection when multiple LLC queues exist:

```bash
sudo scheds/rust/scx_snake/tests/vtime_llc_queues.sh \
  target/release/scx_snake
```

For a local virtme-ng guest, `--cpus 8,sockets=2,cores=4,threads=1` exposes two
four-CPU LLCs. The combined gauntlet always runs the focused test and derives
the remote-path expectation from the compiled queue topology.

The EEVDF watchdog regression runs targeted 60-second forms of the Inspector
matrix's mixed-affinity and fork/yield workloads. The fork/yield form pins the
yield cohort and uses a delayed wakee so the stale-lag path is deterministic:

```bash
sudo scheds/rust/scx_snake/tests/eevdf_stall_workload.sh \
  target/release/scx_snake \
  scheds/rust/scx_snake/examples/basic.toml mixed_affinity
sudo scheds/rust/scx_snake/tests/eevdf_stall_workload.sh \
  target/release/scx_snake \
  scheds/rust/scx_snake/examples/basic.toml fork_yield
```

The VTIME watchdog regression requires at least 128 guest CPUs and preserves its
artifacts under `/tmp`. It combines a nice-19 `khugepaged` thread, persistent
normal tasks crossing cell clocks, and repeated affinity/yield-heavy
oversubscription to verify bounded physical slices, run-start credit, slice
forfeiture, and watchdog progress:

```bash
sudo SNAKE_EXPECT_CPUS=256 \
  scheds/rust/scx_snake/tests/vtime_low_weight_yield.sh \
  target/release/scx_snake
```

Cell queue and direct-borrowing regressions are also VM-only:

```bash
sudo scheds/rust/scx_snake/tests/vtime_cell_queues.sh \
  target/release/scx_snake
sudo scheds/rust/scx_snake/tests/vtime_cell_borrowing.sh \
  target/release/scx_snake
```

Inside an isolated guest, the combined gauntlet runs the FIFO fallback, the
targeted EEVDF mixed-affinity and fork/yield regressions, and all applicable
VTIME queue tests. It adds max-cell coverage at 32 CPUs and the low-weight
watchdog campaign at 128 CPUs:

```bash
sudo scheds/rust/scx_snake/tests/vm_gauntlet.sh \
  target/release/scx_snake
```

Additional VM-only contracts cover the remaining queue boundaries:

| Test | Contract |
| --- | --- |
| `fifo_fallback.sh` | Shared FIFO fallback is explicitly drained. |
| `vtime_llc_queues.sh` | Global-clock LLC queues exercise local, CPU, and bounded remote-candidate paths with consistent rung counters. |
| `eevdf_stall_workload.sh` | Bounded mixed-affinity and fork/yield cohorts retain progress across a 60-second watchdog window. |
| `vtime_queue_ladders.sh` | Callback ladders activate, live reorder, switch to `min_vtime`, and dispatch both queue classes. |
| `vtime_max_cells.sh` | 31 declared cells plus cell 0 run under `cell` and `cell_llc`. |
| `vtime_single_runner_rehome.sh` | A sole running task is re-enqueued and cannot retain an obsolete cell indefinitely. |
| `vtime_queued_rehome.sh` | An old normal-DSQ run is preserved once, then translated on re-enqueue. |
| `vtime_cell_borrowing.sh` | Direct borrowers yield after one slice before any owner-cell comparison. |
| `vtime_low_weight_yield.sh` | Weight-1 and stale run-start tasks survive affinity/yield-heavy 256-CPU oversubscription without runnable stalls. |

Run queue-layout tests with `SNAKE_QUEUE_LAYOUT=cell_llc` to cover populated
cell/LLC shards sharing one per-cell clock.

The VM-only affinity regression exercises this forward-progress rule:

```bash
sudo scheds/rust/scx_snake/tests/eevdf_affinity_future.sh \
  target/release/scx_snake
```

## Current scope

Global VTIME and EEVDF each use one global fairness clock. The `llc` queue layout
shards global VTIME storage but not that clock. Cell-layout VTIME uses one clock
per cell for both its normal work and affinity work targeting its CPUs; it has
neither a global affinity clock nor per-CPU clocks. Cell CPU weights allocate
primary CPUs but do not provide hierarchical group fairness. There are no
per-NUMA clocks, live fairness-mode changes, queued-work borrowing, or
cross-cell normal-queue stealing. The clocks use BPF spin locks, so scalability
under large runnable sets remains an explicit experiment rather than a
production claim.
