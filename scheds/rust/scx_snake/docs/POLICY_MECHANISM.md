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
        QUEUES["Queue-target plan<br/>global, CPU, cell, cell x LLC"]
        CLOCKS["Clock-target plan<br/>global, CPU, cell"]

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
        TARGET["Resolve queue key<br/>and clock key"]
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
    SELECT -->|Idle CPU direct dispatch| LOCAL
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
- Userspace declares custom queues and clock domains, while BPF creates and
  operates the corresponding kernel DSQs.
- Queue placement and clock ownership remain separate. For example, cell x LLC
  queues can share one per-cell clock.
- Policy updates use prepared, validated state and an atomic publication step;
  the BPF hot path never consumes a partially updated configuration.
- BPF retains affinity checks, kicks, fallback behavior, and forward-progress
  guarantees even when userspace has already validated the policy.

The initial VTIME implementation uses one global queue for unrestricted work
and per-CPU queues for affinity-restricted work, all sharing one global clock.
The per-CPU queues prevent large affinity-incompatible scans and preserve VTIME
ordering for pinned tasks. Later user-selected queue targets can add per-cell
and cell x LLC layouts without changing the policy/mechanism boundary.
