# SCX Mitosis Architecture: BPF ↔ Rust Interplay  (updated)

┌─────────────────────────────────────────────────────────────────────────────────┐
│                                INITIALIZATION PHASE                             │
└─────────────────────────────────────────────────────────────────────────────────┘

    USERSPACE (Rust)                          KERNEL SPACE (BPF)
    ┌─────────────────┐                       ┌─────────────────┐
    │   main.rs       │                       │  mitosis.bpf.c  │
    │                 │                       │                 │
    │ 1. Parse opts   │                       │                 │
    │ 2. Get topology │                       │                 │
    │ 3. Open BPF     │ ─────────────────────→│                 │
    │    skeleton     │                       │                 │
    │                 │                       │                 │
    │ 4. Populate     │ ─────────────────────→│ const volatile  │
    │    shared vars  │                       │ .rodata vars:   │
    │    (rodata):    │                       │ - nr_possible_  │
    │    - nr_cpus    │                       │   cpus          │
    │    - nr_l3      │                       │ - nr_l3         │
    │    - all_cpus[] │                       │ - all_cpus[]    │
    │    - slice_ns   │                       │ - slice_ns      │
    │    - smt_enabled│                       │ - smt_enabled   │
    │                 │                       │                 │
    │ 5. Load BPF     │ ─────────────────────→│                 │
    │                 │                       │                 │
    │                 │                       │ 6. mitosis_init()                 │
    │                 │                       │    - Build all_cpumask (kptr)     │
    │                 │                       │    - Create per-CPU DSQs          │
    │                 │                       │      (make_cpu_dsq(cpu))          │
    │                 │                       │    - Create ALL (cell,L3) DSQs    │
    │                 │                       │      (make_cell_l3_dsq(cell,l3))  │
    │                 │                       │    - Init cell_cpumasks[*].{      │
    │                 │                       │        cpumask,tmp_cpumask }      │
    │                 │                       │    - cells[0].in_use = true       │
    │                 │                       │                 │
    │ 7. Populate     │ ─────────────────────→│ BPF Maps:       │
    │    topology     │                       │ - cpu_to_l3     │
    │    maps:        │                       │ - l3_to_cpus    │
    │    set_entry()  │                       │                 │
    │                 │                       │                 │
    │ 8. Attach BPF   │ ─────────────────────→│ 9. BPF program  │
    │                 │                       │    becomes      │
    │                 │                       │    active       │
    └─────────────────┘                       └─────────────────┘


┌─────────────────────────────────────────────────────────────────────────────────┐
│                                 RUNTIME PHASE                                   │
└─────────────────────────────────────────────────────────────────────────────────┘

    USERSPACE (Rust)                           KERNEL SPACE (BPF)
    ┌─────────────────┐                       ┌─────────────────────────────────┐
    │                 │                       │             EVENT HANDLERS      │
    │ PERIODIC LOOP   │                       │             (μs–ms scale)       │
    │ (every 1–10 s)  │                       │ ┌─────────────────────────────┐ │
    │                 │                       │ │ select_cpu()               │ │
    │ ┌─────────────┐ │ ◄─────────────────────┤ │ enqueue()                  │ │
    │ │collect_     │ │   Read counters       │ │ dispatch()                 │ │
    │ │metrics()    │ │   & statistics        │ │ tick() (CPU0 applies cfg)  │ │
    │ └─────────────┘ │                       │ │ running()/stopping()       │ │
    │                 │                       │ └─────────────────────────────┘ │
    │ ┌─────────────┐ │                       │ ┌─────────────────────────────┐ │
    │ │refresh_bpf_ │ │ ─────────────────────→│ │ init_task()                │ │
    │ │cells()      │ │   Update cell         │ │ set_cpumask()              │ │
    │ └─────────────┘ │   view (from BSS)     │ │ cgroup_init/move/exit()    │ │
    │                 │                       │ │ dump()/dump_task()/exit()  │ │
    │ ┌─────────────┐ │                       │ └─────────────────────────────┘ │
    │ │log_queue_   │ │                       └─────────────────────────────────┘
    │ │stats()      │ │
    │ └─────────────┘ │   Also does: read & RESET function_counters
    │                 │              aggregate cpu_ctxs cstats over CPUs
    └─────────────────┘


┌─────────────────────────────────────────────────────────────────────────────────┐
│                            COORDINATION MECHANISMS                              │
└─────────────────────────────────────────────────────────────────────────────────┘

1. SHARED STATE & MAPS
   ┌─────────────────────────────────────────────────────────────────────────────┐
   │  A) BPF↔Rust (bidirectional / Rust reads, sometimes writes)                │
   │     • cpu_ctxs (PERCPU_ARRAY) – stats, vtime (Rust sums deltas)            │
   │     • function_counters (PERCPU_ARRAY) – Rust reads & RESETS periodically  │
   │     • cpu_to_l3 (ARRAY) – populated by Rust                                │
   │     • l3_to_cpus (ARRAY of cpumask) – populated by Rust                    │
   │     • BPF BSS: cells[] (in_use, vtime_now, L3 counts) – Rust reads         │
   │                                                                             │
   │  B) BPF-only (not used directly by Rust)                                   │
   │     • task_ctxs (TASK_STORAGE) – per-task state                            │
   │     • cgrp_ctxs (CGRP_STORAGE) – per-cgroup cell ownership                 │
   │     • cell_cpumasks (ARRAY of {cpumask,tmp_cpumask} kptrs) – double buffer │
   │     • percpu_critical_sections (PERCPU_ARRAY u32) – enter/exit counter     │
   │     • cgrp_init_percpu_cpumask (scratch for cpuset copy)                   │
   │     • l3_ctxs (ARRAY) – present, experimental                              │
   └─────────────────────────────────────────────────────────────────────────────┘

2. CONFIGURATION VERSIONING (BPF-driven atomic updates)
   ┌─────────────────────────────────────────────────────────────────────────────┐
   │ BPF cgroup_init_with_cpuset():                                              │
   │   • Allocate cell, fill cell_cpumask, update cpu_ctx[cpu].cell             │
   │   • __atomic_add_fetch(configuration_seq, 1)   ← writer                    │
   │                                                                             │
   │ BPF tick() on CPU0 (applier):                                              │
   │   • Rebuild root cpumask from all_cpumask minus non-root cell CPUs         │
   │   • Set cpu_ctx[cpu].cell for each CPU                                     │
   │   • Swap cell_cpumasks[root].{cpumask,tmp} via bpf_kptr_xchg()             │
   │   • barrier(); applied_configuration_seq = configuration_seq                │
   │                                                                             │
   │ Hot path (select_cpu/enqueue):                                             │
   │   • maybe_refresh_cell(): if tctx.configuration_seq != applied_* →         │
   │       update_task_cell() (reads cgrp_ctx, recompute cpumask, dsq)          │
   │                                                                             │
   │ (Optional future: Rust could drive config_seq; not used in current code.)  │
   └─────────────────────────────────────────────────────────────────────────────┘

3. CRITICAL SECTIONS (lightweight, RCU-like)
   ┌─────────────────────────────────────────────────────────────────────────────┐
   │  • critical_section_enter()/exit(): bump per-CPU u32 counter; LSB==inside.  │
   │  • select_cpu() and enqueue() wrap refresh→enqueue with this guard.         │
   │  • record()/poll() helpers exist but are not used by current apply path.    │
   └─────────────────────────────────────────────────────────────────────────────┘


┌─────────────────────────────────────────────────────────────────────────────────┐
│                              DATA FLOW EXAMPLE                                 │
└─────────────────────────────────────────────────────────────────────────────────┘

Task Scheduling Decision Flow:
┌─────────────────────────────────────────────────────────────────────────────────┐
│ 1. Task wakes up                                                                │
│    │                                                                            │
│    ▼                                                                            │
│ 2. BPF: mitosis_select_cpu()                                                    │
│    │ ┌─────────────────────────────────────────────────────────────────────┐   │
│    │ │ • critical_section_enter()                                          │   │
│    │ │ • maybe_refresh_cell() - check applied_configuration_seq            │   │
│    │ │ • update_task_cell() - assign cell/dsq & cpumask                    │   │
│    │ │ • pick_idle_cpu() - SMT-aware (idle_smtmask, SCX_PICK_IDLE_CORE)    │   │
│    │ │ • critical_section_exit()                                           │   │
│    │ └─────────────────────────────────────────────────────────────────────┘   │
│    ▼                                                                            │
│ 3. BPF: mitosis_enqueue()                                                       │
│    │ ┌─────────────────────────────────────────────────────────────────────┐   │
│    │ │ • critical_section_enter()                                          │   │
│    │ │ • maybe_refresh_cell()                                              │   │
│    │ │ • Choose basis_vtime (cell or cpu dsq)                              │   │
│    │ │ • Clamp vtime: [basis - slice_ns, basis + 8192*slice_ns]            │   │
│    │ │ • scx_bpf_dsq_insert_vtime()                                        │   │
│    │ │ • If CPU chosen→ scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE)               │   │
│    │ │ • Update cstats in cpu_ctxs                                         │   │
│    │ │ • critical_section_exit()                                           │   │
│    │ └─────────────────────────────────────────────────────────────────────┘   │
│    ▼                                                                            │
│ 4. BPF: mitosis_dispatch()                                                      │
│    │ ┌─────────────────────────────────────────────────────────────────────┐   │
│    │ │ • Compare min vtime from cell DSQ and this CPU DSQ                  │   │
│    │ │ • scx_bpf_dsq_move_to_local(min_src) with fallback to cpu DSQ       │   │
│    │ └─────────────────────────────────────────────────────────────────────┘   │
│    ▼                                                                            │
│ 5. Task runs                                                                    │
│    │                                                                            │
│    ├─► mitosis_running(): sync cell/cpu vtime_now ≥ task vtime                  │
│    └─► mitosis_stopping(): charge vtime += used * 100 / weight                  │
│                                                                                 │
│ Meanwhile, periodically:                                                        │
│ 6. Rust: collect_metrics()                                                      │
│    │ ┌─────────────────────────────────────────────────────────────────────┐   │
│    │ │ • Read & sum cpu_ctxs.cstats deltas                                 │   │
│    │ │ • Read & RESET function_counters                                    │   │
│    │ │ • Refresh cells view from BSS cells[].in_use                         │   │
│    │ │ • Log queue distributions, affinity violations                       │   │
│    │ └─────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘


┌─────────────────────────────────────────────────────────────────────────────────┐
│                            DSQ ID ENCODING QUICK REF                            │
└─────────────────────────────────────────────────────────────────────────────────┘
[User-defined 32-bit DSQ payload]
[31..24]=type, [23..0]=data

type=1 (CPU DSQ)     : make_cpu_dsq(cpu)      → get_cpu_from_dsq()
type=2 (CELL_L3 DSQ) : make_cell_l3_dsq(c,l3) → get_cell(), get_l3()
Helpers: is_cpu_dsq(), is_cell_l3_dsq(), queue_type()


┌─────────────────────────────────────────────────────────────────────────────────┐
│                                KEY INSIGHTS (updated)                           │
└─────────────────────────────────────────────────────────────────────────────────┘
• BPF program handles HIGH-FREQUENCY operations (μs scale):
  - Task selection/enqueue/dispatch
  - SMT-aware idle picking (idle_smtmask, SCX_PICK_IDLE_CORE)
  - Real-time scheduling + per-function counters

• Rust handles LOW-FREQUENCY operations (s scale):
  - Topology & map population (cpu_to_l3, l3_to_cpus)
  - Stats aggregation + function_counters reset
  - Optional policy/visibility; no seq bump in current code

• Config propagation is BPF-driven:
  - cgroup_init_with_cpuset() bumps configuration_seq
  - tick() on CPU0 applies changes and sets applied_configuration_seq
  - Fast path checks with maybe_refresh_cell()

• Cell cpumask double-buffering:
  - cell_cpumasks[cell].{cpumask,tmp_cpumask} allocated at init
  - tick() swaps via bpf_kptr_xchg() for atomic visibility

• Vtime discipline:
  - Clamp idle accrual to one slice; reject extreme future vtime
  - Charge on stopping() proportional to 1/weight

• L3 scheduling status: DSQs + maps exist, selection/dispatch path disabled
  (#if 0; pick_l3_for_task() stubbed)

• No blocking:
  - BPF responds to kernel scheduling events
  - Rust runs periodic maintenance
  - Communication via shared maps/BSS only
