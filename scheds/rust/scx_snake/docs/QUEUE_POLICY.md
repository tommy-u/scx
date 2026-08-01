# Queue Policies

Queue policies replace Snake's default global VTIME storage with a fixed-pool
custom-DSQ topology. The global `llc` layout shards one fairness
domain by cache locality; `cell` and `cell_llc` add resource allocation to task
cell annotations. Queue policies require `--fairness vtime` and leave FIFO as
the scheduler default. `mitosis-sim.toml` is the Production profile; the other
files are component and demonstration policies.

See [`../examples/kernel-default-sim.toml`](../examples/kernel-default-sim.toml),
[`../examples/cell-queues.toml`](../examples/cell-queues.toml),
[`../examples/cell-llc-queues.toml`](../examples/cell-llc-queues.toml),
[`../examples/managed-cell-llc.toml`](../examples/managed-cell-llc.toml),
[`../examples/mitosis-sim.toml`](../examples/mitosis-sim.toml),
[`../examples/cell-min-vtime.toml`](../examples/cell-min-vtime.toml), and
[`../examples/cell-borrowing.toml`](../examples/cell-borrowing.toml) for
complete policies.

This document is the configuration and resource-topology reference. See
[`FAIRNESS.md`](FAIRNESS.md) for the VTIME accounting model and
[`CELL_POLICY.md`](CELL_POLICY.md) for live task annotations.

## Configuration

### Global LLC queues

```toml
[queues]
layout = "llc"
enqueue = [
  { action = "try_insert", target = "local" },
  { action = "insert", target = "cpu" },
]
dispatch = [
  { action = "peek", source = "cpu" },
  { action = "peek", source = "local" },
  { action = "peek", source = "remote" },
  { action = "consume", operation = "min_vtime", fallback = ["cpu", "local", "remote"] },
]
```

The `llc` layout rejects cell declarations, cell placement scopes, and
userspace membership. If its callback ladders are omitted, Snake supplies the
exact ladders above. Userspace resolves CPU-to-LLC membership into flat queue
descriptors and consumer masks; BPF receives no LLC topology graph.

### Cell queues

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

For `cell` and `cell_llc`, omitting both callback ladders selects enqueue
`[cell, affinity]` and dispatch `[affinity, cell]`. If either is specified, both
must be specified explicitly. `cell0_cpu_weight` defaults to 1.

## Cells and CPU ownership

The two cell layouts turn overlapping CPU declarations into an attachment-time
resource allocation:

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
| `llc` | One per discovered LLC | One global clock shared by every queue |
| `cell` | One per cell | One per cell |
| `cell_llc` | One for each cell/LLC pair that owns at least one CPU | One per cell, shared by all of that cell's LLC shards |

Every layout also creates exactly one affinity-safe DSQ per online CPU. In
`llc`, all normal and CPU queues use the global clock. In cell layouts, each
affinity queue uses the clock of the cell that owns its CPU. Snake does not
create a cell-by-CPU matrix or any per-CPU clocks. `cell_llc` creates only
populated ownership pairs, not the Cartesian product of all cells and LLCs.
Every normal queue owns at least one CPU, so there are never more normal queues
than online CPUs. CPU IDs may be sparse; descriptors remain keyed by real IDs.

In cell layouts, the affinity queues exist because a task whose affinity
excludes any CPU in its cell's primary mask cannot safely sit on a normal DSQ
consumed by all of those CPUs. Keeping one ordered escape queue per CPU provides
forward progress and preserves VTIME ordering for pinned tasks without
introducing per-CPU fairness clocks.

## Enqueue ladder

The `llc` enqueue ladder is a first-success sequence:

- `try_insert(local)` maps the selected or fallback CPU to its normal queue. It
  succeeds only if that queue's complete consumer mask is a subset of the
  task's live allowed mask.
- terminal `insert(cpu)` stores the task in one allowed CPU's ordered escape
  queue. This is the affinity-safe path; queue depth does not influence the
  choice.

An explicit `llc` enqueue ladder must contain exactly those two rungs in that
order. Snake rejects omitted, duplicated, reordered, or additional targets.

The cell-layout enqueue ladder is also first-success:

- `cell` inserts into the task cell's normal VTIME DSQ. It succeeds only when
  the task may run on every CPU in that cell's primary mask. For `cell_llc`,
  the selected or chosen primary CPU selects the LLC shard.
- `affinity` inserts into an allowed CPU's affinity escape DSQ. It is the
  required terminal fallback.

Targets cannot be duplicated. In cell layouts, `affinity` must be present and
terminal, and a policy that enqueues to `cell` must dispatch from `cell`.

With `direct_dispatch = true`, a successful cell-routed placement bypasses the
custom enqueue ladder and inserts directly into the selected CPU's local DSQ.
Primary, borrowable, and restricted-affinity rungs preserve their respective
resource route. If sched_ext invokes `enqueue` without first invoking
`select_cpu`, Snake retries the placement ladder there before queueing.

## Dispatch ladder

The `llc` dispatch ladder first peeks candidates without moving them:

1. the dispatching CPU's per-CPU queue;
2. its local normal queue;
3. one remote candidate found by a bounded scan from a per-CPU rotating cursor.

The terminal `consume(min_vtime)` rung selects the earliest candidate under the
one global clock. Exact ties rotate by source. A selected atomic move can miss
because the head changed or its affinity excludes the dispatching CPU. The
consume rung then makes at most one direct attempt per configured fallback
source, normally CPU, local, remote. Consume never loops. The remote peek may
scan the configured queues once, advancing past local, empty, or
head-incompatible queues until it finds one eligible candidate. Its cursor
therefore cannot be pinned by a hot or unusable shard.

An explicit `llc` dispatch ladder must contain exactly one `peek` for each of
`cpu`, `local`, and `remote`, followed by one terminal `consume(min_vtime)`.
The three peeks may be ordered freely. The consume fallback must also name all
three sources exactly once; its order is independently configurable.

Cell-layout dispatch either lists `cell` and `affinity` sources or contains the
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

The `llc` layout has one global VTIME coordinate and clock. LLCs are storage and
consumer-locality groups, not entitlements. Normal queues and per-CPU escape
queues therefore compare raw vruntimes directly.

Cell layouts use one VTIME clock per cell. All `cell_llc` shards for a cell
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

## Cell borrowing rung

Cell layouts give the placement ladder two cell scopes:

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

## Mitosis selection ladder

`mitosis-sim.toml` uses `pick_idle_prefer_previous` over four scopes in order:
the task cell's previous-LLC shard, its complete primary mask, its borrowable
mask, and the task's allowed mask only when affinity is restricted. Each rung
tries the previous CPU when its whole SMT core is idle, any idle core, the
previous idle CPU, and finally any idle CPU. Unrestricted tasks therefore stay
local when possible, expand gently through their cell, and borrow only after
primary capacity is busy. Restricted tasks use the terminal affinity route.

This profile models Mitosis cell discovery, CPU ownership, placement, direct
dispatch, borrowing, and one VTIME domain per cell. It does not implement demand
rebalancing, queued-work stealing, or slice shrinking.

## Live updates

Custom DSQs come from a fixed pool created at attachment and are never removed.
An explicit live policy update must resolve to the exact same layout, cells,
weights, primary allocation, borrowable masks, normal queues, and CPU queues.
For `llc`, CPU-to-local routes and normal consumer masks must also match. Restart
Snake to change any of them through policy replacement.

Managed-cell reconciliation may rebind that fixed pool. It first diverts new
enqueues to CPU-local DSQs and waits for custom queues to empty, then stages the
new descriptors and masks beside the policy in the inactive bank. One slot
switch publishes the complete configuration. The old bank is retained until its
callback readers quiesce, after which task membership is reconciled.

Callback ladders are part of the double-buffered policy generation. Cell
dispatch sources may be reordered, a full source pair may switch to or from
`min_vtime`, and a previously unused cell target/source pair may be added when
the active topology already contains its queues. The cell enqueue
ladder must still keep `affinity` terminal. The `llc` layout retains its
validated peek/consume source set and terminal CPU enqueue escape. A live update
may not remove an active enqueue target or represented dispatch class: work
queued by the old generation could otherwise be stranded. Placement-rung
changes remain live-updateable when the queue topology is unchanged.

A live task-cell assignment is different from a topology update. If the task
is running when its annotation changes, dispatch suppresses keep-running slice
replenishment until the task returns through enqueue, translates its cell
vruntime, and runs under the new cell identity. This prevents an isolated
CPU-bound task from remaining indefinitely in the old cell.

A task already linked on a normal DSQ cannot be atomically removed when its
annotation changes. If the old cell dequeues it first, Snake preserves that
queue decision for one execution: runtime and vruntime remain charged to the
old cell. The pending-rehome check prevents slice renewal, and cell queue mode's
`SCX_OPS_ENQ_LAST` setting forces even an isolated previous task through the
following enqueue. That enqueue translates the task to its requested cell
clock, or synthetic cell 0 after a clear. An affinity DSQ is keyed by CPU and
ordered in that CPU owner's cell clock. A task dequeued there may adopt the
requested task-cell identity in `running`; its affinity coordinate remains
relative to the executing CPU owner's clock and is translated if a later target
belongs to another owner cell.

## Accounting and inspection

All queue layouts report enqueue and dispatch rung attempts, hits, misses, and
errors. Dispatch peek rungs also report arbitration selections; the consume
path reports selected atomic move misses from head changes or affinity rejection and
fallback attempts, hits, and misses. These counters obey `attempts = hits +
misses + errors` and `fallback_attempts =
fallback_hits + fallback_misses`.

For cell layouts, `--stats` reports each cell's total, primary, borrowed, and
lent runtime, normal and affinity enqueues and execution selections, and clock
transitions.
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
model; normal DSQ consumers; and each CPU's local normal and per-CPU route. Cell
layouts additionally show synthetic cell 0, dense cell indices, weights, and
resolved primary and borrowable masks. Per-queue depth and per-cell enqueue,
dispatch, borrowing, lending, and clock-transition metrics remain available
through `--stats` rather than the topology tables.
