# Policy and Mechanism Boundary

Snake keeps semantic scheduling policy in userspace and executes the
latency-sensitive scheduling mechanism in BPF. Userspace compiles and validates
the desired placement, fairness, queue, and clock configuration. BPF consumes
that configuration while handling sched_ext callbacks and operating kernel
dispatch queues.

```mermaid
flowchart LR
    subgraph US["Userspace: Policy and Control Plane"]
        direction TB

        INPUT["CLI and TOML"]
        TOPO["CPU, LLC, and NUMA discovery"]
        COMPILER["Scheduling configuration compiler"]

        PLACE["Placement plan<br/>ladder, masks, borrowing"]
        FAIR["Fairness plan<br/>FIFO, VTIME, EEVDF"]
        QUEUES["Queue-target plan<br/>global, per-CPU affinity,<br/>cell, cell x LLC"]
        CLOCKS["Clock-target plan<br/>global, per-cell,<br/>global affinity escape"]

        VALIDATE["Validate topology, IDs,<br/>capacity, and references"]
        PUBLISH["Publish configuration<br/>rodata and double-buffered maps"]
        OBSERVE["Statistics and inspection"]

        INPUT --> COMPILER
        TOPO --> COMPILER
        COMPILER --> PLACE
        COMPILER --> FAIR
        COMPILER --> QUEUES
        COMPILER --> CLOCKS
        PLACE --> VALIDATE
        FAIR --> VALIDATE
        QUEUES --> VALIDATE
        CLOCKS --> VALIDATE
        VALIDATE --> PUBLISH
    end

    subgraph BPF["BPF: Hot-Path Mechanism"]
        direction TB

        CONFIG["Read active compiled configuration"]
        INIT["Create declared custom DSQs<br/>during scheduler attachment"]
        SELECT["Execute placement ladder"]
        TARGET["Resolve cell, queue,<br/>and clock keys"]
        ACCOUNT["Track task runtime, weight,<br/>vruntime, and sleeper credit"]
        ORDER["Apply ordering mechanism<br/>FIFO insert, vtime insert, EEVDF"]
        DISPATCH["Dispatch eligible work<br/>from custom DSQ to local DSQ"]
        SAFETY["Enforce affinity, kicks,<br/>fallbacks, and forward progress"]
        METRICS["Update counters and diagnostics"]

        CONFIG --> SELECT
        CONFIG --> TARGET
        CONFIG --> ORDER
        CONFIG --> INIT

        SELECT -->|No direct placement| TARGET
        TARGET --> ORDER
        ACCOUNT --> ORDER
        SAFETY -.-> SELECT
        SAFETY -.-> ORDER
        SAFETY -.-> DISPATCH

        SELECT --> METRICS
        ORDER --> METRICS
        DISPATCH --> METRICS
    end

    subgraph KERNEL["Kernel sched_ext Primitives"]
        direction TB

        CALLBACKS["select_cpu, enqueue, running,<br/>stopping, and dispatch callbacks"]
        TASK["Task affinity, weight,<br/>and execution runtime"]
        DSQS["Custom DSQs"]
        LOCAL["Built-in per-CPU local DSQs"]
        RUN["CPU executes task"]
    end

    PUBLISH --> CONFIG
    PUBLISH --> INIT

    CALLBACKS --> SELECT
    CALLBACKS --> ACCOUNT
    CALLBACKS --> DISPATCH
    TASK --> SELECT
    TASK --> ACCOUNT

    INIT -->|scx_bpf_create_dsq| DSQS
    ORDER -->|enqueue| DSQS
    DSQS --> DISPATCH
    DISPATCH --> LOCAL
    SELECT -->|Direct placement or borrowing| LOCAL
    LOCAL --> RUN

    METRICS --> OBSERVE

    classDef policy fill:#dbeafe,stroke:#2563eb,color:#111827
    classDef mechanism fill:#dcfce7,stroke:#16a34a,color:#111827
    classDef kernel fill:#f3f4f6,stroke:#6b7280,color:#111827

    class INPUT,TOPO,COMPILER,PLACE,FAIR,QUEUES,CLOCKS,VALIDATE,PUBLISH,OBSERVE policy
    class CONFIG,INIT,SELECT,TARGET,ACCOUNT,ORDER,DISPATCH,SAFETY,METRICS mechanism
    class CALLBACKS,TASK,DSQS,LOCAL,RUN kernel
```

## Boundary rules

- Userspace decides which policy should exist and validates the complete
  configuration before publishing it.
- BPF performs operations that depend on the current task, CPU, runtime, or DSQ
  state and therefore cannot tolerate a userspace round trip.
- Userspace resolves custom queues and clock domains, while BPF creates and
  operates the corresponding kernel DSQs at attachment.
- Queue placement and clock ownership remain separate. For example, cell x LLC
  queues can share one per-cell clock.
- Policy updates use prepared, validated state and an atomic publication step;
  the BPF hot path never consumes a partially updated configuration.
- BPF retains live affinity checks, idle claims, kicks, fallback behavior, and
  forward-progress mechanisms even when userspace has validated static policy.

## Implemented queue boundary

Without `[queues]`, VTIME uses one global normal queue plus per-CPU affinity
queues under one global clock. With `[queues]`, userspace performs the semantic
work before BPF loads:

1. Add synthetic cell 0 for unannotated tasks.
2. Resolve overlapping claims and weights into disjoint primary CPU owners and
   per-cell borrowable masks.
3. Choose one normal DSQ per cell or one per populated cell/LLC ownership pair.
4. Assign every normal DSQ to its cell clock and every online CPU to one
   affinity escape DSQ.
5. Compile placement, enqueue, and dispatch ladders into topology-blind numeric
   records.

BPF receives dense cell indices, masks, queue descriptors, clock indices, and
callback opcodes. It does not allocate CPU ownership or interpret LLC policy.
At runtime it reads the task annotation and live affinity, maintains two VTIME
coordinates when affinity escape is needed, and moves work through the declared
DSQs.

There is one normal clock per cell even under `cell_llc`; all LLC shards of a
cell share it. The per-CPU affinity DSQs share one global affinity clock. This
is an intentional storage/clock separation and avoids per-CPU fairness clocks.

## Update boundary

Placement and queue callback ladders live in the double-buffered policy slots
and publish atomically. Queue descriptors and DSQs are attachment-time state, so
a live policy replacement must resolve to the same complete queue topology.
Dispatch sources may be reordered and the cell target/source pair may be added,
but an active target or source may not be removed because the old generation
may have left work in its DSQ. Changing the layout, cells, weights, allocation,
or queue set requires restarting Snake.

See [`QUEUE_POLICY.md`](QUEUE_POLICY.md) for the user-facing rules and
[`POLICY_LOWERING.md`](POLICY_LOWERING.md) for the shared ABI.
