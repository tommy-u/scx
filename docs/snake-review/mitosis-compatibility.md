# Mitosis compatibility

## Executive assessment

Snake already contains most of the static mechanisms needed to model a Mitosis
host. It does not yet contain Mitosis's defining dynamic control loop.

| Dimension | Snake parity | Meaning |
| --- | ---: | --- |
| Static scheduling data plane | **73%** | Cells, cell/LLC queues, affinity queues, VTIME, borrowing, and accounting exist. |
| Dynamic cell/resource control | **33%** | Static allocation and polling membership exist; dynamic lifecycle and ownership do not. |
| Operations and diagnostics | **67%** | Snake's inspector is stronger in several areas, but managed-cell allocation/rebalance/dump state is absent. |
| Weighted end-to-end behavior | **55% ±5%** | A static policy can resemble Mitosis, but it cannot adapt like Mitosis. |

The missing dependency chain is:

```text
automatic cgroup cells
  -> cgroup-native inherited identity
  -> live cpuset-aware allocation
  -> safe CPU-owner and queue-route changes
  -> demand feedback and controlled rebalancing
```

## What Mitosis actually implements

Mitosis describes dynamic cell split/merge as a goal
([main.rs](../../scheds/rust/scx_mitosis/src/main.rs#L76-L82)), but the current
implementation uses one cell per managed direct child. Workload-driven cell
split/merge is not current parity scope.

| Mitosis capability | Current implementation evidence |
| --- | --- |
| Automatic direct-child lifecycle | Parent inotify plus full reconcile in [cell_manager.rs](../../scheds/rust/scx_mitosis/src/cell_manager.rs#L753-L863) and [cell_manager.rs](../../scheds/rust/scx_mitosis/src/cell_manager.rs#L918-L1045) |
| Excluded child names and catch-all cell 0 | CLI semantics in [main.rs](../../scheds/rust/scx_mitosis/src/main.rs#L122-L142) |
| Cell ID reuse | Freed-ID tracking in [cell_manager.rs](../../scheds/rust/scx_mitosis/src/cell_manager.rs#L1029-L1033) and [cell_manager.rs](../../scheds/rust/scx_mitosis/src/cell_manager.rs#L1107-L1119) |
| Hierarchical cgroup identity | Task refresh in [mitosis.bpf.c](../../scheds/rust/scx_mitosis/src/bpf/mitosis.bpf.c#L300-L400) and hierarchy propagation in [mitosis.bpf.c](../../scheds/rust/scx_mitosis/src/bpf/mitosis.bpf.c#L2116-L2188) |
| Cpuset-aware allocation | Cpuset reads and overlap allocation in [cell_manager.rs](../../scheds/rust/scx_mitosis/src/cell_manager.rs#L1048-L1228) |
| Cell-0 CPU holdout | Protected allocation in [cell_manager.rs](../../scheds/rust/scx_mitosis/src/cell_manager.rs#L290-L418) |
| Demand/EWMA CPU rebalance | Threshold/cooldown loop in [main.rs](../../scheds/rust/scx_mitosis/src/main.rs#L636-L707) and demand calculation in [main.rs](../../scheds/rust/scx_mitosis/src/main.rs#L1092-L1215) |
| Cell/LLC queue domains | Queue creation in [mitosis.bpf.c](../../scheds/rust/scx_mitosis/src/bpf/mitosis.bpf.c#L1809-L1823) and clock/queue structures in [intf.h](../../scheds/rust/scx_mitosis/src/bpf/intf.h#L114-L163) |
| Same-cell recovery and orphan drain | [llc_aware.bpf.h](../../scheds/rust/scx_mitosis/src/bpf/llc_aware.bpf.h#L213-L435) |
| Affinity-safe per-CPU queues | [mitosis.bpf.c](../../scheds/rust/scx_mitosis/src/bpf/mitosis.bpf.c#L227-L294) |
| Idle borrowing on wake and enqueue | [mitosis.bpf.c](../../scheds/rust/scx_mitosis/src/bpf/mitosis.bpf.c#L455-L510) |
| Pinned-waiter slice shrinking | [slice_shrinking.bpf.h](../../scheds/rust/scx_mitosis/src/bpf/slice_shrinking.bpf.h#L6-L175) |
| Live complete configuration | Userspace [main.rs](../../scheds/rust/scx_mitosis/src/main.rs#L709-L794), BPF [mitosis.bpf.c](../../scheds/rust/scx_mitosis/src/bpf/mitosis.bpf.c#L2194-L2242) |
| Managed telemetry and dumps | [stats.rs](../../scheds/rust/scx_mitosis/src/stats.rs#L18-L125), [mitosis.bpf.c](../../scheds/rust/scx_mitosis/src/bpf/mitosis.bpf.c#L1557-L1682) |

Mitosis's apply operation is explicitly **not atomic** and may leave partial state;
userspace treats failure as fatal
([mitosis.bpf.c](../../scheds/rust/scx_mitosis/src/bpf/mitosis.bpf.c#L2207-L2210)).
Snake should not copy that property.

## Capability mapping

| Mitosis behavior | Snake status | Gap |
| --- | --- | --- |
| Direct-child cgroup becomes a cell | Partial | Snake can synthesize cells from direct children at attach; live child lifecycle is still absent. |
| Descendants inherit and live moves refresh | Partial | Recursive userspace polling eventually writes per-thread storage. |
| Excluded children remain in cell 0 | Partial | Attach-time managed mode supports exact exclusions; it has no live identity reuse. |
| Cell create/delete and ID reuse | Missing | Queue cells are attachment-time objects. |
| Cpuset-aware resource claims | Partial | Attach-time discovery reads effective cpusets into the deterministic allocator; live mutation and holdout are absent. |
| Configurable cell-0 holdout | Partial | Snake guarantees cell 0 capacity but has no configurable minimum or diagnostic. |
| Demand measurement | Partial | Runtime, primary, borrowed, and lent counters exist; utilization/EWMA does not. |
| Demand-driven CPU allocation | Missing | No resource controller updates ownership. |
| Live cell/CPU topology | Missing | Topology changes are rejected during policy replacement. |
| Cell and cell/LLC DSQs | Present | One cell clock is shared across a cell's LLC shards. |
| Per-CPU affinity queues | Present | One escape DSQ per configured CPU. |
| Weighted VTIME | Present | Bounded weight-scaled slices and inverse-weight service. |
| Normal/affinity min-vtime | Present | Both heads are compared in the CPU-owner cell clock. |
| Primary and borrowable placement | Present | Live affinity is intersected and foreign ownership validated. |
| Enqueue-time borrowing | Partial/missing | Direct borrowing occurs from `select_cpu`; queued backlog cannot borrow. |
| Cell intersect previous LLC placement | Missing | `previous_llc` and `task_cell` are separate sources. |
| Same-cell sibling-shard recovery | Present | Earliest remote shard head is scanned. |
| Orphaned shard drain after owner move | Missing | Ownership cannot currently move. |
| Pinned-waiter slice shrinking | Missing | Snake's slice is shorter, but no waiter-aware mechanism exists. |
| Task rehome across clocks | Present | One stale run is preserved, then bounded-lag translation converges. |
| Detailed metrics/inspection | Present or stronger | Managed allocation and rebalance fields are missing. |
| Exit and task dumps | Partial | Exit buffer exists; `.dump` and `.dump_task` callbacks do not. |
| Queued-wakeup optimization | Missing | Mitosis conditionally enables it; Snake does not. |

The static queue evidence is in
[queue_topology.rs](../../scheds/rust/scx_snake/src/queue_topology.rs#L131-L230),
borrowing in
[queue_fairness.h](../../scheds/rust/scx_snake/src/bpf/queue_fairness.h#L367-L393),
and Snake's live-topology rejection in
[main.rs](../../scheds/rust/scx_snake/src/main.rs#L1563-L1582).

```mermaid
flowchart LR
    subgraph M[Mitosis behavior]
        C[Direct-child lifecycle]
        P[Cpuset allocation]
        D[Demand EWMA and rebalance]
        Q[Cell and LLC DSQs]
        A[Affinity queues]
        B[Wake and enqueue borrowing]
        L[Pinned latency control]
        O[Metrics and dumps]
    end

    subgraph S[Snake today]
        MP[Explicit polling membership<br/>PARTIAL]
        SA[Static weighted allocation<br/>PARTIAL]
        NM[No resource controller<br/>MISSING]
        SQ[Cell/cell-LLC queues<br/>PRESENT]
        AQ[Per-CPU affinity queues<br/>PRESENT]
        SB[Select-time borrowing<br/>PARTIAL]
        SL[Short fixed bounds only<br/>PARTIAL]
        SO[Inspector and metrics<br/>PRESENT]
    end

    C --> MP
    P --> SA
    D --> NM
    Q --> SQ
    A --> AQ
    B --> SB
    L --> SL
    O --> SO
```

## How the 55% end-to-end estimate is derived

The 73% static-data-plane, 33% dynamic-control, and 67% operations figures are
rounded expert bands using the rubric in
[Feature completeness](feature-completeness.md). The 55% figure is additionally
cross-checked with the following explicit 100-point behavior model. “Snake
points” credit complete behavior, not merely a related primitive.

| Behavior | Weight | Snake points |
| --- | ---: | ---: |
| Automatic direct-child lifecycle | 8 | 2 |
| Descendant membership and live moves | 7 | 4 |
| Stable IDs, exclusions, and cell 0 | 5 | 2 |
| Cpuset allocation and holdout | 10 | 4 |
| Demand controller | 8 | 2 |
| Safe live resource publication | 4 | 0 |
| Cell/LLC and affinity DSQs | 8 | 8 |
| Weighted VTIME and clocks | 8 | 8 |
| Affinity-safe primary placement | 6 | 5 |
| Borrowing on wake and enqueue | 6 | 3 |
| LLC locality, stealing, and orphan drain | 7 | 4 |
| Pinned-task latency control | 5 | 1 |
| Metrics and monitoring | 6 | 6 |
| Exit and debug diagnostics | 4 | 2 |
| Scale and compatibility | 4 | 2 |
| End-to-end acceptance evidence | 4 | 2 |
| **Total** | **100** | **55** |

The ±5 range reflects unmeasured live-kernel behavior, especially borrowing,
fairness, churn, and scale. It is not statistical confidence.

## Managed-mode v1 contract

The attachment-time subset now implements `parent`, `exclude_children`,
`max_children`, and `reconcile_ms`. It assigns sorted direct children to
epoch-bearing slots, reads `cpuset.cpus.effective`, and keeps descendants flat
inside the direct child's cell. It pins the discovered cgroup inode and detaches
on deletion or same-name replacement. It does not watch direct-child lifecycle
or cpuset changes, preserve logical identity across slot reuse, protect a
configurable cell-0 holdout, or rebalance CPUs.

The following remains the recommended contract for the live managed mode.

An illustrative configuration shape is:

```toml
[managed_cells]
parent = "/sys/fs/cgroup/workloads"
exclude_children = ["system.slice"]
max_children = 31
cell0_min_cpus = 1
overflow = "cell0"
allocation = "equal_then_demand"
rebalance_threshold_pct = 20
rebalance_cooldown_ms = 5000
demand_ewma_alpha = 0.30

[queues]
layout = "cell_llc"
```

The controller and rebalance fields are proposed syntax; the attachment-time
fields described above are current. The target live semantics are:

- `[managed_cells]` enables the mode at attachment. It requires VTIME and a
  queue layout; changing the parent, maximum, layout, or fairness mode requires
  restart because it changes the fixed resource envelope.
- Each non-excluded direct child of `parent` gets a stable logical identity key
  derived from cgroup ID plus a userspace birth epoch. Descendants inherit only
  that key in BPF cgroup storage. The active configuration bank maps the key to
  an ephemeral `(cell_slot, slot_epoch)`; cgroup storage never contains a
  reusable cell slot. Exact-basename exclusions remain in cell 0.
- A child claims its successfully read `cpuset.cpus.effective` mask. If the
  cpuset controller is deliberately unavailable for the managed parent, that is
  detected once and every child is unconstrained over online CPUs. A successful
  empty effective mask means zero available capacity. Track the BPF cpuset-change
  generation with every successful read. A transient read failure may retain an
  existing plan only when that independent generation is unchanged. A new child
  with no valid read stays unbound in cell 0; a failed read after a generation
  change, or when the generation cannot be proven, causes controlled detach.
  Missing-file, parse, permission, and I/O errors are never converted into an
  unconstrained claim.
- Initial allocation is equal within cpuset constraints. The later demand
  controller changes desired CPU quantity, not identity or policy. Cell 0 keeps
  at least `cell0_min_cpus` when capacity permits.
- The first release supports at most 31 active managed children plus cell 0, but
  pool space alone does not admit a child. A new child becomes active only if a
  complete feasible plan gives every active normal queue at least one eligible,
  online consumer and preserves the cell-0 contract. Otherwise its logical key
  remains unbound, its tasks resolve to cell 0, an admission/capacity health
  error is emitted, and admission is retried after resources change.
- If an existing active child's effective cpuset changes, immediately revalidate
  the current plan. When it is still valid, keep it while computing and draining
  toward a replacement. When it is already invalid—including an empty effective
  mask—v1 performs a controlled scheduler exit to the kernel scheduler. It never
  retains an affinity-invalid owner or publishes an active normal queue with no
  consumer. A later coordinated cpuset mutation API can provide a no-detach path.
- Managed mode is mutually exclusive with static `[[cell]]` and `[membership]`
  configuration in v1. The attachment-time subset resolves a manual numeric
  assignment to the slot's active epoch. Live slot reuse still needs an
  explicit manual namespace and precedence contract before that API can remain
  enabled safely.
- Policies may use generic task-cell placement, enqueue, and dispatch semantics,
  but may not embed managed slot IDs. A policy candidate is compiled against the
  resource sub-epoch in the active configuration bank, then the coordinator
  rechecks the complete configuration epoch before publishing. Resource churn
  causes a retry, never publication of a policy validated against stale cells or
  masks.
- Threshold, cooldown, and EWMA constants can become live tunables once the
  controller exists. Identity, pool size, fairness, and queue layout remain
  attachment-time settings in the first release.

Static and managed cells should not be mixed until ID namespaces, manual
override precedence, and cross-mode queue retirement have independent tests.

## Critical semantic decisions

These decisions must be explicit before implementation.

### 1. Managed identity and manual overrides

Mitosis has only managed cgroup identity. Snake also has per-thread manual
annotations. A possible future precedence rule is:

```text
effective cell = manual task override ?? managed cgroup cell ?? cell 0
```

However, a numeric managed slot cannot be reused safely while a stale manual
annotation or queued task refers to it. Choose one initial rule:

- use separate manual and managed ID namespaces;
- attach an epoch to every managed cell reference; or
- forbid manual targeting of managed cells until safe epoching exists.

The managed-mode v1 contract above forbids manual targeting. A later release can
add separate namespaces or epoch every reference. This is less flexible but
removes cross-tenant slot-reuse risk from the first implementation.

### 2. Queue pool and cell deletion

Snake creates only populated cell/LLC DSQs. Dynamic cells require stable DSQ
existence even as descriptors change. Precreate a fixed pool of normal DSQs at
attachment, then assign pool slots to active cell/LLC shards. A retired pool slot
must remain quarantined until:

- readers of the old configuration bank are gone;
- no task remains queued on it;
- any running task charged to the retired route has stopped;
- a drain target has observed it empty.

Do not encode cgroup identity directly into a reusable DSQ ID.

### 3. Affinity clocks during CPU-owner changes

This is the hardest incompatibility. Today a CPU affinity DSQ is ordered in its
owner cell's clock. If ownership changes while tasks remain queued, their VTIME
values belong to the old clock.

Safe choices are:

1. use a stable per-CPU affinity clock in managed mode and use cyclic class
   dispatch rather than comparing that head directly with a cell clock; or
2. defer CPU ownership change until its affinity DSQ and running state are
   quiescent.

Simply rewriting `owner_cell_index` is unsafe. This decision needs a targeted
prototype and benchmark before broad controller work.

### 4. Clock and task-cache epochs

Mitosis has per-cell/per-LLC clocks plus per-CPU clocks. Snake intentionally has
one fairness clock per cell, even with LLC shards. Preserve Snake's cell-clock
model for normal work unless benchmarks demonstrate a need to change its fairness
semantics. Mitosis parity should mean operational behavior, not byte-for-byte
algorithm identity.

Mutable clocks, DSQs, and task state cannot be copied into a configuration bank.
They live in a fixed attachment-time pool and are referenced by `(slot,
slot_epoch)`. Each clock object carries the same epoch. Task storage caches the
logical cgroup key, configuration epoch, resolved slot/epoch, and VTIME epoch.
Every callback validates those epochs before reading a clock or queue route.

On mismatch, the task resolves its logical key through the pinned bank. If the
source clock still carries the expected epoch, rehome by translating bounded lag
relative to the two frontiers. If that epoch has already retired or the clock was
reset, the old lag is unknowable: initialize the task at the destination frontier
with neutral lag, reset its slice baseline, and increment a
`stale_epoch_neutral_rehomes` counter. It must never read a clock whose epoch no
longer matches. A missing identity binding falls back to cell 0 and increments a
stale-identity counter.

A cell slot and its clock cannot be rebound until old-bank readers are gone,
normal and affinity queues are empty, and no running task is charged to the old
epoch. Sleeping task caches do not block reuse: their stale epoch forces the
neutral-lag initialization path before they can observe the reset clock. Reset
the clock, install its new epoch, and only then publish the bank that binds the
new logical identity.

### 5. Complete configuration publication

Do not add independently published policy and resource slots. Even if each slot
is internally atomic, a callback can otherwise observe a new policy with old
resources or vice versa. Broaden Snake's existing two policy banks into two
**complete configuration banks**:

```text
Configuration bank
  compiled policy, mask tables, labels, policy generation
  identities: stable logical key -> cell slot/epoch/state
  cells: active, epoch, primary, borrowable, shard descriptors
  cpus: owner cell/epoch, affinity clock epoch and normal route
  shards: DSQ slot, cell/LLC identity, active|retiring|free
  one configuration epoch covering every field above
```

Fixed mutable DSQ and clock objects remain outside the banks because they are
created at attach; the banks contain their assignments and expected epochs. One
userspace `ConfigCoordinator` serializes policy and resource updates. It
snapshots the active bank, applies one candidate change, validates all
cross-invariants, stages the complete inactive bank, rechecks the source epoch,
and publishes one `active_config_slot`. If the epoch changed, it rebuilds rather
than merging.

Cross-validation requires each logical key and slot epoch to be unique, every
active normal shard to have an eligible online consumer, every owner to satisfy
the effective claim, every route to reference an active DSQ/clock epoch, and cell
0 to satisfy its declared holdout or enter the explicit degraded result.

Every BPF callback uses the existing read-pin pattern on that one active slot:
read slot, increment its reader count, re-read the active slot, retry if it
changed, and then use policy and resource fields only from the pinned bank. The
inactive bank cannot be reused until its readers reach zero. Therefore a callback
observes an old or new complete configuration, never a mixed pair. Validation or
staging failure leaves the active bank untouched.

Cgroup storage contains only the stable logical key, never a bank or cell slot.
Lifecycle ordering makes that external input safe:

1. On create, allocate a never-reused birth key, write and reconcile it through
   the existing descendant hierarchy, and leave it unbound so callbacks fall
   back to cell 0. Only after propagation and allocation succeed may a complete
   bank bind that key and be published.
2. On delete, first publish a bank that removes or retires the key binding. New
   callbacks then fall back to cell 0 while callbacks pinned to the old bank may
   finish. Clear cgroup state and reuse the cell slot only after reader
   quiescence, queue drain, running-task quiescence, and slot quarantine.
3. On a task cgroup move, the BPF cgroup-move hook invalidates its cached
   resolution before its next scheduling use. Both the old and new logical keys
   resolve through whichever complete bank the callback pins.

If create-time propagation cannot be confirmed, the key is not admitted. This
ordering is part of the transaction contract, not eventual cleanup.

## Target architecture

```mermaid
flowchart TB
    Events[Cgroup and cpuset events] --> Discovery[ManagedCellDiscovery]
    Discovery --> Identity[Stable logical identity keys]
    Identity --> Specs[Pure CellSpec snapshot]
    Counters[Per-cell runtime counters] --> Demand[Demand sampler using elapsed time]
    Demand --> Specs
    Specs --> Allocator[Deterministic allocator]
    Allocator --> ResourceCandidate[Candidate resource plan]
    Policy[Policy compiler] --> PolicyCandidate[Candidate compiled policy]
    Identity --> Coordinator
    ResourceCandidate --> Coordinator[Single-writer ConfigCoordinator]
    PolicyCandidate --> Coordinator
    Coordinator --> Complete[Complete policy resource and identity bank]
    Complete --> Validate[Userspace and BPF cross-validation]
    Validate --> Inactive[Inactive configuration bank]
    Inactive --> Publish[One atomic active-slot publish]
    Publish --> Context[BPF callbacks pin one complete bank]
    Context --> Effective[Resolve logical identity in pinned bank]
    Cgroup[BPF cgroup stable logical key] --> Effective
    Manual[Future namespaced manual override] --> Effective
    Effective --> BPF[BPF scheduling path]
    BPF --> Drain[Retiring queue drain and quiescence]
    Drain --> Reuse[Release retired cell and DSQ slots]
```

Policy and resource updates converge through the same transaction boundary:

```mermaid
flowchart LR
    Policy[Declarative policy update] --> Build[Build complete inactive bank]
    Managed[Managed-resource update] --> Build
    Build --> Check[Validate policy resource and identity invariants]
    Check --> Slot[Atomic active configuration slot]
    Slot --> Context[Pinned callback context]
    Context --> Placement[Placement ladder]
    Context --> Queueing[Queue routing and fairness]
```

## Implementation sequence

### Phase 0: correctness and semantics

- Decide managed/manual namespaces, deletion behavior, maximum cells, and clock
  semantics.
- Fix or disable EEVDF as a selectable production path.
- Define queued-work forward-progress and CPU-hotplug contracts.
- Add generation/epoch types before any ID reuse.

Exit gate: design invariants and tests are written; no managed cell can be confused
with a reused slot.

### Phase 1: cgroup-native identity

The attach-time scanner is a precursor, not completion of this phase: it
synthesizes cells and recursively tags existing child trees, but it does not
provide live logical identity or create/delete/recreate ordering.

- Add direct-child discovery by path and inode.
- Add exact child exclusions.
- Port only the narrow BPF cgroup-storage inheritance and task-move refresh logic,
  storing a stable logical key rather than a reusable cell slot.
- Implement create-before-bind and unbind-before-clear ordering. Do not publish an
  identity until existing descendants have reconciled.
- Use task storage for cached logical key and resolved configuration/slot epochs;
  reject numeric assignment requests in managed v1 and allow idempotent clear.
- Expose lifecycle and identity generation in inspection.

Exit gate: create/delete/recreate, hierarchy propagation, bank publication, and
descendant task moves can race without resolving a task to a reused slot.

### Phase 2: stable dynamic resource envelope

- Precreate a bounded normal-DSQ pool and existing per-CPU affinity DSQs.
- Broaden the two ladder banks into complete configuration banks with one active
  slot and one reader count per bank.
- Add a single update coordinator and stage/validate/publish the full bank for
  either policy or resource changes.
- Add active, retiring, and free queue-slot states.

Exit gate: a fault-injected update cannot expose a mixed
policy/resource/identity-binding tuple; cell descriptors can be staged without
DSQ creation or partial publication.

### Phase 3: cpuset allocation and cell-0 protection

- Generalize Snake's allocator to consume pure specs:

  ```text
  { identity, optional_claim_mask, weight, minimum_cpus }
  ```

- Treat an explicitly unavailable parent cpuset controller as an all-CPU claim.
- Read effective cpuset constraints so inherited masks are concrete.
- Distinguish a successfully empty effective mask from missing-file, parse,
  permission, and I/O failures.
- Retain a last-good claim after read failure only when the independent BPF
  cpuset-change generation proves no mutation occurred; otherwise detach.
- Add configurable cell-0 minimum and holdout diagnostics.
- Reject new-child admission when no feasible consumer-preserving plan exists.
- Define controlled detach for an existing cell whose new claim invalidates the
  current plan and has no safely publishable replacement.

Exit gate: overlapping, disjoint, empty, inherited, and full-coverage cpuset tests
are deterministic; every active normal queue has an eligible online consumer; and
infeasible changes follow the explicit admission-or-detach result. This phase
produces a pure plan only; it does not yet publish live owner changes.

### Phase 4: CPU moves and draining

- Implement the selected affinity-clock strategy.
- Implement a retirement transition that prevents new work from entering an old
  route while retaining a designated consumer for its backlog.
- Keep disappearing normal shards drainable after publication.
- Kick designated drain CPUs.
- Publish the final CPU-owner change only after affected queues and running state
  satisfy the drain/quiescence contract.
- Quarantine retired cell and DSQ slots until empty, quiescent, and reader-free.
- Epoch every clock and task-cached route. Translate bounded lag only while the
  source epoch exists; initialize stale sleepers at neutral destination lag after
  clock reuse.
- Add same-cell orphan-drain and final-CPU-removal tests.

Exit gate: removing a cell's final CPU in an LLC under backlog cannot trigger the
runnable-task watchdog.

### Phase 5: demand controller

- Convert existing runtime counters using actual elapsed time.
- Apply idle EWMA decay.
- Seed new cells from active-cell average demand.
- Add threshold, cooldown, and no-op assignment suppression.
- Recompute only when inputs or allocation outcome change.
- Publish controller reason, old/new ownership, and convergence metrics.

Exit gate: skew converges, reversal converges, and burst load does not oscillate.

### Phase 6: small data-plane gaps and hardening

- Add a composite `task_cell_previous_llc` placement scope.
- Allow queue-safe enqueue-time primary/borrowable placement reevaluation.
- Add `.dump` and `.dump_task` callbacks.
- Evaluate queued-wakeup optimization.
- Benchmark pinned latency before deciding whether to port slice shrinking.
- Add restart/churn/failure-injection and scale campaigns.

## Mitosis implementation details not to copy

The reference code contains useful concepts and several controller weaknesses:

- idle cells can skip zero-demand EWMA decay;
- capacity uses configured monitor interval rather than actual elapsed time;
- a high spread with unchanged integer allocation can recompute every loop;
- CPU-only rebalance reapplies cgroup ownership and walks the hierarchy;
- stats and demand paths scan all configured cell slots;
- cpuset read errors are collapsed into “no cpuset”;
- the inotify watch omits rename/move events;
- argument validation is effectively empty;
- live BPF configuration is non-atomic.

Snake should import the lifecycle, identity, allocation inputs, and drain concepts,
not the implementation wholesale.

## Acceptance matrix

| Area | Required test |
| --- | --- |
| Identity | Create/delete/path-reuse with new inode; logical key and slot epoch prevent stale reference |
| Inheritance | Fork/exec, descendant moves, hierarchy propagation, and bank publication races resolve through the pinned binding or safely fall back to cell 0 |
| Overrides | Managed v1 rejects numeric set requests; clear is idempotent and falls back to current cgroup identity; future namespaced overrides get separate precedence tests |
| Cpuset | New infeasible/read-failed child stays unbound; unchanged generation may retain a last-good plan; changed or unknown generation plus read failure detaches |
| Cell 0 | Configured minimum held without taking a child's last CPU |
| Publication | Failed inactive validation leaves the active complete bank unchanged; readers see an old or new policy/resource/identity-binding tuple, never mixed state |
| Clock reuse | Live source epoch translates bounded lag; a sleeper waking after source-clock reset starts at neutral destination lag and records the fallback |
| Affinity | CPU owner move with affinity backlog preserves ordering or defers safely |
| Drain | Final consumer removal drains to zero without watchdog stall |
| Demand | Idle decay, elapsed-time normalization, seeding, cooldown, no-op suppression |
| Rebalance | Skew, reversal, burst, and churn converge without oscillation |
| Fairness | Nice-weight shares remain correct across normal, affinity, and borrowed work |
| Operations | Dump and inspector identify active generation, reason, owner, drain, and retirement |

Operational campaigns are expanded in
[Validation and risk plan](validation-and-risk-plan.md).
