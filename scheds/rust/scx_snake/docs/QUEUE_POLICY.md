# Cell Queue Policy

Cell queue policies add a resource allocation and custom-DSQ layer to Snake's
existing task-cell annotations. They are experimental, require
`--fairness vtime`, and leave FIFO as the scheduler default.

See [`../examples/cell-queues.toml`](../examples/cell-queues.toml),
[`../examples/cell-llc-queues.toml`](../examples/cell-llc-queues.toml),
[`../examples/cell-min-vtime.toml`](../examples/cell-min-vtime.toml), and
[`../examples/cell-borrowing.toml`](../examples/cell-borrowing.toml) for
complete policies.

This document is the configuration and resource-topology reference. See
[`FAIRNESS.md`](FAIRNESS.md) for the VTIME accounting model and
[`CELL_POLICY.md`](CELL_POLICY.md) for live task annotations.

## Configuration

```toml
[queues]
layout = "cell"
cell0_cpu_weight = 1

[[queues.enqueue]]
target = "cell"

[[queues.enqueue]]
target = "affinity"

[[queues.dispatch]]
source = "affinity"

[[queues.dispatch]]
source = "cell"

[[cell]]
id = 7
cpus = "0-7"
cpu_weight = 2

[[rung]]
operation = "pick_idle"
scope = "task_cell"

[[rung]]
operation = "pick_idle"
scope = "task_allowed"
```

`layout` is either `cell` or `cell_llc`. If both callback ladders are omitted,
Snake uses enqueue `[cell, affinity]` and dispatch `[affinity, cell]`. If either
is specified, both must be specified explicitly. `cell0_cpu_weight` defaults to
1.

## Cells and CPU ownership

Queue mode turns overlapping CPU declarations into an attachment-time resource
allocation:

- Cell ID 0 is reserved for a synthetic cell containing unannotated tasks.
  It claims every online CPU and uses `cell0_cpu_weight`.
- A policy may declare at most 31 cells with IDs 1 through 1023, for 32 queue
  cells including cell 0.
- Every cell weight must be positive. Every cell must receive at least one
  primary CPU, so the host needs at least as many online CPUs as queue cells.
- Declared `cpus` are the CPUs a cell claims. Claims may overlap.
- Overlapping declarations must still admit a distinct claimed primary CPU for
  every declared cell; otherwise allocation is rejected.
- Userspace deterministically assigns one claimed primary CPU to each declared
  cell, reserves one for cell 0, then distributes remaining CPUs by weighted
  target deficit while respecting claims. The resulting primary masks are
  disjoint and cover every online CPU exactly once.
- A cell's borrowable mask is `claimed - primary`. Cell 0 therefore may borrow
  every CPU it does not own.
- External cell IDs are translated to dense BPF indices. The dense index is an
  implementation detail, not part of the annotation interface.

`cpu_weight` and `cell0_cpu_weight` influence primary CPU ownership. They do
not change a task's kernel scheduling weight and are not a promise of
cross-cell runtime fairness. Task VTIME still uses `p->scx.weight` within its
clock domain.

Weights are nevertheless capacity assignments, not cosmetic fairness hints.
Size each cell's weight for its expected worst-case runnable population and
the sched_ext watchdog interval. Select-time borrowing can place a newly
runnable task on an idle borrowed CPU, but it cannot move work that is already
waiting in the cell's normal DSQ. An undersized cell can therefore accumulate
queued work long enough to trigger a runnable-task stall while CPUs owned by
other cells remain idle. Snake deliberately does not hide that policy error by
allowing cross-cell normal-queue stealing.

Use `--dump-compiled-policy` to inspect the resolved primary and borrowable
masks before attaching:

```bash
./target/release/scx_snake \
  --policy scheds/rust/scx_snake/examples/cell-queues.toml \
  --dump-compiled-policy
```

## DSQ layouts

Snake creates all queue-policy DSQs when the scheduler attaches.

| Layout | Normal VTIME DSQs | Clock |
| --- | --- | --- |
| `cell` | One per cell | One per cell |
| `cell_llc` | One for each cell/LLC pair that owns at least one CPU | One per cell, shared by all of that cell's LLC shards |

Both layouts also create exactly one affinity escape DSQ per online CPU. Each
affinity DSQ uses the clock of the cell that owns its CPU. Snake does not create
a cell-by-CPU matrix of DSQs or any per-CPU clocks. In particular, `cell_llc`
creates only populated ownership pairs, not the Cartesian product of all cells
and LLCs. Every normal queue owns at least one CPU, so there are never more
normal queues than online CPUs. CPU IDs may be sparse; descriptors remain keyed
by the real CPU IDs.

The affinity queues exist because a task whose affinity excludes any CPU in
its cell's primary mask cannot safely sit on a normal DSQ consumed by all of
those CPUs. Keeping one ordered escape queue per CPU provides forward progress
and preserves VTIME ordering for pinned tasks without introducing per-CPU
fairness clocks.

## Enqueue ladder

The enqueue ladder is a first-success sequence:

- `cell` inserts into the task cell's normal VTIME DSQ. It succeeds only when
  the task may run on every CPU in that cell's primary mask. For `cell_llc`,
  the selected or chosen primary CPU selects the LLC shard.
- `affinity` inserts into an allowed CPU's affinity escape DSQ. It is the
  required terminal fallback.

Targets cannot be duplicated. `affinity` must be present and terminal. A
policy that enqueues to `cell` must also dispatch from `cell`.

## Dispatch ladder

The dispatch ladder either lists `cell` and `affinity` sources or contains the
single combined operation:

```toml
[[queues.dispatch]]
operation = "min_vtime"
```

`min_vtime` requires both enqueue targets and must be the sole dispatch rung.
It peeks the CPU owner's normal cell queue and that CPU's affinity queue, then
dispatches the earlier VTIME head. Exact ties alternate per CPU, beginning with
the cell queue. Both heads use the CPU owner's cell clock, so the raw comparison
is within one clock domain.

For source rungs, the list is not a stable-priority order. Each CPU keeps a
generation-aware cursor, starts its next dispatch search at that cursor, and
advances past the source that supplied work. This cyclic round robin prevents a
continuously non-empty first source from starving the other source.

For a `cell` source, a CPU first checks its local cell or cell/LLC shard. If
that shard is empty, it may take the earliest VTIME head from another shard of
the same cell. It never steals normal work from another cell. An `affinity`
source consumes only that CPU's escape queue.

## Clocks and task coordinates

Normal queues use one VTIME clock per cell. All `cell_llc` shards for a cell
share that clock, so changing LLC storage does not create a new entitlement
domain.

An affinity queue uses its CPU owner's cell clock. A task keeps two coordinates:

- cell vruntime, charged against its task cell's clock;
- affinity vruntime, translated into the clock of the cell owning its target
  CPU.

Runtime on an affinity queue advances both coordinates. It advances the task
cell coordinate so returning to a normal queue cannot erase service, and the
CPU-owner coordinate so it competes fairly with normal work consuming that CPU.
When either coordinate changes cell domains, Snake preserves its lag relative
to the old and new cell clocks, clamped to one VTIME slice. Raw values are
compared only after both candidates are in the same CPU-owner cell domain.
[`FAIRNESS.md`](FAIRNESS.md) gives the charging and bounded-lag equations.

## Borrowing rung

Queue mode gives the placement ladder two cell scopes:

- `task_cell` searches the task cell's primary mask.
- `task_cell_borrowable` searches its borrowable mask.

Both support `pick_idle`, `pick_idle_core`, `pick_random_idle`, and
`pick_random_idle_core`. The BPF mechanism intersects the selected mask with
the task's live affinity before claiming an idle CPU.

A primary hit records an enqueue hint and still flows through the enqueue
ladder. A borrowable hit is different: Snake verifies that the CPU is owned by
another cell and dispatches the task directly to that idle CPU's local DSQ.
Runtime remains charged to the task's cell clock. Per-cell resource counters
record the same interval as borrowed runtime for the task cell and lent runtime
for the CPU-owner cell.

A direct borrower receives one slice. At the next dispatch decision it may not
compare its cell vruntime with candidates from the unrelated owner-cell clock,
and it may not replenish itself on the foreign CPU. It returns through enqueue,
where the placement ladder can borrow an idle CPU again or the enqueue ladder
can order it normally. This gives newly arrived owner-cell work a scheduling
opportunity after every borrowed slice.

Borrowing is deliberately limited:

- It is select-time, idle-CPU borrowing for newly runnable or waking tasks.
- It does not steal tasks that are already waiting in a normal DSQ.
- It is work-conserving for wake-heavy workloads, not a general queued-work
  balancer.
- Direct borrowing bypasses queue comparison at that instant, so it is not
  strict VTIME order across the borrowed CPU.
- It never changes CPU ownership or creates cross-cell normal-queue stealing.

Consequently, borrowing does not make an underprovisioned cell safe. Once a
burst is queued, only the cell's primary CPUs consume its normal DSQs. Assign
enough primary capacity for sustained backlog, then use borrowing for transient
idle capacity.

## Live updates

Queue topology is attachment-time state because custom DSQs cannot be removed
and recreated as part of an atomic ladder publication. A live policy update
must resolve to the exact same layout, cells, weights, primary allocation,
borrowable masks, normal queues, and affinity queues. Restart Snake to change
any of them.

Callback ladders are part of the double-buffered policy generation. Dispatch
sources may be reordered, a full source pair may switch to or from `min_vtime`,
and a previously unused cell target/source pair may be added when the
attachment-time topology already contains its queues. The enqueue ladder must
still keep `affinity` terminal. A live update may not
remove an active enqueue target or represented dispatch class: work queued by
the old generation could otherwise be stranded. Placement-rung changes remain
live-updateable when the queue topology is unchanged.

A live task-cell assignment is different from a topology update. If the task
is running when its annotation changes, dispatch suppresses keep-running slice
replenishment until the task returns through enqueue, translates its cell
vruntime, and runs under the new cell identity. This prevents an isolated
CPU-bound task from remaining indefinitely in the old cell.

A task already linked on a normal DSQ cannot be atomically removed when its
annotation changes. If the old cell dequeues it first, Snake preserves that
queue decision for one execution: runtime and vruntime remain charged to the
old cell. The pending-rehome check prevents slice renewal, and the following
enqueue translates the task to its requested cell clock, or synthetic cell 0
after a clear. An affinity DSQ is keyed by CPU and ordered in that CPU owner's
cell clock. A task dequeued there may adopt the requested task-cell identity in
`running`; its affinity coordinate remains relative to the executing CPU
owner's clock and is translated if a later target belongs to another owner
cell.

## Accounting and inspection

`--stats` reports each cell's total, primary, borrowed, and lent runtime,
normal and affinity enqueues and execution selections, and clock transitions.
The global
`queue_rehome_preemptions` counter records dispatches that forced an expired
task through enqueue to complete a live reassignment.
`queue_stale_rehome_runs` counts executions preserved on an old normal DSQ
before that re-enqueue. These counters separate fairness identity from resource
consumption:

- task runtime is attributed to the scheduler-adopted cell for that execution;
- primary versus borrowed describes where that task consumed CPU;
- lent describes another cell consuming a CPU owned by this cell.

Affinity escape execution can therefore count as borrowed and lent even when
it did not come from the explicit borrowing rung. Direct borrowing counts as a
normal execution selection even though it bypasses a normal DSQ. The resource
classification follows the actual CPU owner, not the queue class.
`queue_borrow_yields` counts direct borrowed slices forced back through enqueue
instead of being renewed or compared across cell clocks.

The compiled-policy dump includes the resolved queue topology. The web
inspector shows the placement, enqueue, and dispatch ladders; fairness and clock
model; synthetic cell 0 and dense cell indices; weights and resolved primary and
borrowable masks; normal DSQ/LLC consumers; and each CPU's owner cell, normal
DSQ, and affinity DSQ. Per-queue depth and per-cell enqueue, dispatch,
borrowing, lending, and clock-transition metrics remain available through
`--stats` rather than the topology tables.
