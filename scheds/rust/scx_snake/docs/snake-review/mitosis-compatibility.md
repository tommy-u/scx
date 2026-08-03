# Mitosis compatibility

Assessment baseline: 2026-08-03 at `c365457b`.

## Executive assessment

Snake now contains both the scheduling data plane and the main managed-resource
control loop needed to simulate a Mitosis host. Its direct-child lifecycle,
cpuset-aware allocation, cell-0 holdout, demand EWMA, ownership rebalancing,
banked topology publication, orphan draining, sibling-LLC stealing, and optional
pinned-waiter slice shrinking are implemented.

The remaining differences are mostly semantic and operational: Snake derives task
identity through userspace polling instead of BPF cgroup inheritance; queued work
does not cross cell boundaries; CPU hotplug is unsupported; and scale, soak,
failure, rollback, and browser evidence are incomplete.

| Dimension | Snake parity | Meaning |
| --- | ---: | --- |
| Static scheduling data plane | **88%** | Cell/LLC and affinity DSQs, VTIME, borrowing, draining, stealing, and slice control exist. |
| Dynamic cell/resource control | **82%** | Lifecycle, holdout, EWMA, rebalancing, and banked owner changes exist; identity is polling-based and hotplug is absent. |
| Operations and diagnostics | **82%** | Managed allocation/rebalance, physical-core placement, and host-tax views exist; scale and failure contracts remain incomplete. |
| Weighted end-to-end behavior | **85% +/-5%** | The Mitosis simulation profile is runnable and dynamically managed, but not production-certified. |

Current dependency chain:

```text
automatic direct-child cells                 IMPLEMENTED (userspace polling)
  -> descendant task identity                IMPLEMENTED (eventual polling)
  -> cpuset allocation and cell-0 holdout    IMPLEMENTED
  -> complete banked topology publication    IMPLEMENTED
  -> elapsed-time demand EWMA                 IMPLEMENTED
  -> controlled CPU ownership rebalance      IMPLEMENTED
  -> orphan drain and sibling recovery       IMPLEMENTED (same cell only)
  -> scale/soak/failure/rollback proof        OPEN
```

## Capability mapping

| Mitosis behavior | Snake status | Current difference or limit |
| --- | --- | --- |
| Direct-child cgroup becomes a cell | Present | Reconciliation polls rather than using inotify/BPF identity. |
| Descendants inherit and live moves refresh | Partial | Recursive userspace reconciliation eventually updates per-thread task storage. |
| Excluded children remain in cell 0 | Present | Exact exclusions are omitted from managed allocation. |
| Cell create/delete and ID reuse | Present | Stable IDs and slot epochs prevent a stale task reference from entering a reused cell. |
| Cpuset-aware resource claims | Present | Effective cpusets and optional local constraints feed deterministic allocation. |
| Configurable cell-0 holdout | Present | The allocator may stop below the requested minimum rather than remove a child's protected final consumer. |
| Demand measurement | Present | Runtime is normalized by elapsed time and tracked with per-identity EWMA. |
| Demand-driven CPU allocation | Present | Threshold and cooldown gate complete-plan ownership changes. |
| Live managed cell/CPU topology | Present | Complete inactive banks stage policy, masks, descriptors, identities, and routes; CPU hotplug remains unsupported. |
| Cell and cell/LLC DSQs | Present | One fairness clock is shared by a cell's LLC shards. |
| Per-CPU affinity queues | Present | One escape DSQ per configured CPU, ordered in the current owner cell clock. |
| Weighted VTIME | Present | Bounded weight-scaled slices and inverse-weight service. |
| Normal/affinity `min_vtime` | Present | Local normal and affinity heads are compared before recovery rungs. |
| Primary and borrowable placement | Present | Live affinity is intersected and foreign ownership is validated. |
| Enqueue-time borrowing | Partial | Direct borrowing is select-time; work already queued cannot use another cell's idle CPU. |
| Same-cell sibling-shard recovery | Present | A bounded sibling scan steals at most one candidate. |
| Orphaned shard drain after owner move | Present | Consumerless same-cell shards remain drainable after an in-place resize. |
| Structural topology drain | Present | Creation, deletion, and epoch reuse close custom enqueue and drain the fixed pool before publication. |
| Pinned-waiter slice shrinking | Present | Base slice, enable bit, min/max, and multiplier are live controls. |
| Task rehome across clocks | Present | Identity/epoch checks and bounded-lag translation converge after unavoidable old-route races. |
| Managed metrics and inspection | Present | Allocation, EWMA, ownership, rebalance, queue recovery, and transition state are visible. |
| Exit and task dumps | Partial | Exit reporting exists; Mitosis-style `.dump`/`.dump_task` callbacks are not complete. |
| Queued-wakeup optimization | Missing | Not needed for initial simulation parity; evaluate only with evidence. |

Implementation evidence is concentrated in
[managed_cells.rs](../../src/managed_cells.rs),
[demand.rs](../../src/demand.rs),
[cell_allocation.rs](../../src/cell_allocation.rs),
[queue_topology.rs](../../src/queue_topology.rs), and the
managed transition coordinator in
[main.rs](../../src/main.rs). Queue semantics are documented
in [QUEUE_POLICY.md](../QUEUE_POLICY.md).

## How the 85% estimate is derived

The aggregate is cross-checked with this 100-point behavior model. Points credit
end-to-end behavior, not the existence of a related primitive.

| Behavior | Weight | Snake points |
| --- | ---: | ---: |
| Automatic direct-child lifecycle | 8 | 8 |
| Descendant membership and live moves | 7 | 5 |
| Stable IDs, exclusions, and cell 0 | 5 | 5 |
| Cpuset allocation and holdout | 10 | 9 |
| Demand controller | 8 | 7 |
| Safe live resource publication | 4 | 4 |
| Cell/LLC and affinity DSQs | 8 | 8 |
| Weighted VTIME and clocks | 8 | 8 |
| Affinity-safe primary placement | 6 | 5 |
| Borrowing on wake and enqueue | 6 | 3 |
| LLC locality, stealing, and orphan drain | 7 | 7 |
| Pinned-task latency control | 5 | 4 |
| Metrics and monitoring | 6 | 6 |
| Exit and debug diagnostics | 4 | 2 |
| Scale and compatibility | 4 | 2 |
| End-to-end acceptance evidence | 4 | 2 |
| **Total** | **100** | **85** |

The +/-5 range reflects unmeasured production-kernel behavior under identity
churn, sustained rebalancing, queued overload, and large-host scale.

## Current managed-mode contract

An illustrative current policy is:

```toml
[managed_cells]
parent = "/sys/fs/cgroup/workloads"
exclude_children = ["system.slice"]
max_children = 31
reconcile_ms = 1000
cell0_min_cpus = 1

[managed_cells.resizing]
sample_ms = 1000
threshold_pct = 20.0
cooldown_ms = 5000
ewma_alpha = 0.30

[queues]
layout = "cell_llc"
```

Current semantics:

- Each admitted non-excluded direct child has a stable numeric ID while its path
  identity remains stable. Slot reuse or same-name inode replacement increments
  the slot epoch.
- Descendants stay in the direct child's cell. Reconciliation retains task pidfds
  and writes `(cell_id, slot_epoch)` into task storage. New threads and cgroup
  moves can temporarily retain an old or cell-0 identity until the next poll.
- A non-empty configured `cpuset.cpus` is a hard allocation constraint. The nearest
  usable `cpuset.cpus.effective` supplies the admitted CPU set. Invalid or empty
  inputs do not silently become unconstrained.
- Cell 0 takes unclaimed CPUs first and then applies deterministic holdout rules.
  It will report a degraded minimum rather than take a child's protected final CPU.
- Presence of `[managed_cells.resizing]` enables demand resizing. Samples use
  elapsed time; EWMA is keyed by `(cell_id, slot_epoch)`; new identities seed from
  surviving cells; threshold and cooldown suppress noise and churn.
- Resource changes compute a complete feasible plan. A new child that cannot get
  a valid consumer remains unbound in cell 0 and is retried. A failed candidate
  does not partially alter the active topology.
- Parent, pool size, fairness mode, and queue layout define the attachment-time
  envelope. Reconciliation/demand timing and VTIME slice/shrinking values have live
  control surfaces; hotplug and a different queue envelope require restart.

The production-shaped example is
[mitosis-sim.toml](../../examples/mitosis-sim.toml).

## Publication and queue invariants

### Complete configuration banks

Snake precreates bounded DSQ and clock pools at attachment. Banked descriptors
assign those objects to the current policy and topology:

```text
Configuration bank
  compiled policy, masks, labels, policy generation
  active cell identity and slot epoch
  primary and borrowable CPU masks
  CPU owner and route
  cell/LLC shard descriptor and DSQ assignment
  one bank generation and reader count
```

The coordinator prepares and validates the inactive bank, closes affected enqueue
paths, publishes one active slot, waits for old readers, and then updates task
membership. Validation or staging failure leaves the active bank running. Mutable
DSQ contents and clocks remain in fixed pools rather than being copied between
banks.

### Structural changes

Create, delete, and slot-epoch reuse divert new custom enqueues to CPU-local DSQs
and globally drain custom queues before rebinding the fixed pool. Logical queued
counts complement kernel DSQ depth so inserts not yet visible to
`dsq_nr_queued()` are included. Retired assignments are not reused until the old
bank is reader-free and the relevant queue state is quiescent.

### Same-identity resize

An ownership resize may retain normal cell/LLC backlog because stable shard indices
remain valid. It still closes custom enqueue and requires affinity DSQs on CPUs
changing owner to be empty; otherwise it falls back to the full structural drain.
After publication, the `cell_orphan` rung moves work from a shard that lost its
last consumer, and the `cell_sibling` rung steals from a populated sibling LLC in
the same cell.

Neither rung crosses a cell boundary. This is the central remaining forward-
progress limit: sustained backlog in an undersized cell cannot consume an idle CPU
owned by a different cell.

### Slice shrinking

VTIME can optionally shorten the current runner when an affinity waiter is
observed. The runtime base slice and shrinking enable/min/max/multiplier values are
validated and published through the control socket and Inspector. Existing queued
tasks retain their assigned slice; later dispatches use the new base. This feature
is implemented but still needs pinned-latency, context-switch, and fairness evidence
before default enablement.

## Inspector parity

Inspector exposes cell ownership, primary/borrowed/lent runtime, instantaneous and
EWMA demand, rebalance count/time, and queue transition state. Capacity lanes
reconcile scheduler work with observed CPU wall time and distinguish other tasks,
IRQ, softirq, steal, and unclassified host tax. Placement heat maps aggregate SMT
siblings by physical core so one busy core is not presented as multiple independent
whole cores.

These models materially improve diagnosis, but they remain browser-side and have
not been proven with a sparse 1,024-CPU pipeline or real-browser E2E CI.

## Remaining roadmap

| Area | Status | Exit gate |
| --- | --- | --- |
| Managed lifecycle and slot epochs | Implemented | Continue churn and failure-injection coverage. |
| Complete banked topology | Implemented | Fault injection proves failed candidates and reader races leave no mixed state. |
| Cpuset allocation and cell-0 holdout | Implemented | Add target-host topology and degraded-holdout evidence. |
| Demand EWMA and rebalancing | Implemented | Long skew/reversal/burst soak shows convergence without oscillation. |
| Orphan drain and sibling stealing | Implemented | Multi-kernel VM runs remain green under queued affinity and resize races. |
| Polling identity | Partial | Fork, exec, and cgroup-move churn cannot run materially in an unintended cell. |
| Cross-cell queued backlog | Open release contract | Guarantee service, reject infeasible sustained demand, or alert/detach before watchdog exposure. |
| CPU hotplug | Open release contract | Support topology change transactionally or detect and detach safely. |
| Observer isolation | Open release gate | Diagnostic and client failures cannot unwind the scheduler loop. |
| Scale, soak, rollback, browser | Open evidence | Target-host curves, sustained canary, exercised rollback, and browser E2E pass. |

## Acceptance matrix

| Area | Current evidence | Remaining evidence |
| --- | --- | --- |
| Lifecycle | Managed workload, churn, deletion/reuse VM tests | High-rate fork/move polling windows and failure injection |
| Cpuset and holdout | Pure allocator and managed resize tests | Production topology diversity and hotplug |
| Publication | Reader lifetime, resize, reuse, and queued-affinity tests | Forced partial failures at every transition boundary |
| Drain and steal | Dedicated Mitosis drain/steal and managed reuse scripts | Scheduled multi-kernel and sustained-load execution |
| Demand | Unit tests and managed resizing VM script | Long skew/reversal/burst/no-op soak and quantitative churn bounds |
| Slice shrinking | Unit, verifier, runtime attach, and live-control coverage | Pinned p95/p99 latency versus context-switch/fairness cost |
| Inspector | Rust/JS models for managed accounting and physical cores | Real browser, multi-client, and 1,024-CPU curves |
| Operations | Normal attach, restart, and exit reporting | Observer faults, canary rollback, restart under load, and alert thresholds |

Detailed release criteria are in
[Validation and risk plan](validation-and-risk-plan.md).
