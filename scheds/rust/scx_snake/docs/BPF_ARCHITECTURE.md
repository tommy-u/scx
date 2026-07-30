# BPF Backend Architecture

Snake builds one BPF translation unit from `src/bpf/main.bpf.c`. The headers
under `src/bpf/` are ownership boundaries inside that translation unit, not
separately loaded programs. This keeps sched_ext callback registration, maps,
and the userspace ABI stable while allowing the backend to be changed in small
mechanical units.

This document covers BPF implementation ownership. See
[`POLICY_LOWERING.md`](POLICY_LOWERING.md) for the userspace compiler and map
data flow, [`QUEUE_POLICY.md`](QUEUE_POLICY.md) for queue semantics, and
[`FAIRNESS.md`](FAIRNESS.md) for service-ordering behavior.

## Constraints

- `main.bpf.c` is the only translation unit and owns the sched_ext callback
  surface.
- `intf.h` is the shared userspace/BPF ABI. Map value layouts, opcode values,
  statistics, and event records change only through an explicit ABI change.
- Policy dispatch uses direct calls and bounded `bpf_loop()` callbacks. It does
  not use function pointers or BPF tail calls.
- Expected policy misses use `-ENOENT`. Other negative results propagate to a
  sched_ext callback, which reports the unrecoverable error once.
- Hot-path code operates on lowered opcodes, dense queue indices, generic CPU
  masks, and task state. TOML and topology names remain in userspace.
- Verifier limits are part of the design. A bounded source loop is not enough
  when its body contains a policy interpreter; each such walk has a callback
  boundary with an explicit constant and runtime index check.

## Ownership

| Owner | Files | Responsibility |
| --- | --- | --- |
| Callback entry | `main.bpf.c`, `main.h` | sched_ext hooks, callback lifetime, final error reporting, and fallback completion. |
| Common BPF mechanism | `bpf_common.h`, `policy_bank.h` | maps shared by all modes, active policy acquisition, reader lifetime, and publication slots. |
| ABI | `intf.h` | userspace-visible constants, map records, events, and statistics. |
| Placement policy | `ladder.h`, `cpu_pick.h` | placement rung validation and execution, bounded ladder walks, and CPU selection primitives. |
| Mask runtime | `mask_table.h` | hot-path lookup and selection from materialized generic CPU masks. |
| Mask initialization | `mask_table_init.h` | attachment and policy-update materialization and cleanup. |
| DSQ identity | `dsq_id.h` | typed construction and classification of scheduler DSQ IDs. |
| DSQ operations | `dsq.h` | insert, ordered insert, move, peek, queue depth, and operation timing. |
| Task state | `task_state.h` | the single task-storage adapter, generated BTF runtime layout, and runtime-state lifetime. |
| Fairness facade | `fairness.h`, `fairness_common.h` | mode selection, shared task/weight helpers, and the callback-facing fairness API. |
| Fairness policies | `fairness_fifo.h`, `fairness_vtime.h`, `fairness_eevdf.h` | policy-specific runnable ordering and accounting. |
| Queue state | `queue_state.h`, `queue.h` | queue maps, immutable routing lookup, queue masks, and allowed-CPU selection. |
| Queue initialization | `queue_init.h`, `queue_ladder.h` | queue topology validation, DSQ creation, and callback-ladder validation. |
| Queue enqueue | `queue_enqueue.h` | first-success queue target selection and ordered insertion. |
| Queue dispatch | `queue_dispatch.h` | cyclic source selection, minimum-vtime arbitration, and replenishment. |
| Queue fairness state | `queue_vtime.h`, `queue_fairness.h` | cell clocks, task transitions, rehome state, and queue callback composition. |
| Scheduler mode | `scheduler_mode.h` | the only switch between placement-only fairness and queue-topology callbacks. |
| Telemetry | `stats.h`, `timing.h`, `queue_timing.h` | counters, sampled callback/rung/DSQ timing, and queue residence captures. |

The facade headers are deliberately narrow. Callback code selects a scheduler
mode through `scheduler_mode.h`; scheduler mode selects a fairness policy
through `fairness.h`; both use DSQs and task state through their owning helper
headers. Policy-specific files do not own maps or callback registration that
belong to another layer.

## Verifier boundaries

The placement ladder, placement-only task-cell enqueue walk, queue enqueue
ladder, queue dispatch ladder, and queue allowed-CPU scan use `bpf_loop()`.
Each callback checks both the compile-time maximum and the active runtime
count before indexing policy or queue state.

The loop context contains only the state that must survive callback
invocations. It copies small value contexts such as `snake_ladder_ctx` and
`snake_fine_timing_ctx`; it does not retain pointers to another BPF stack
frame. Complex queue dispatch calculations use real BPF subprogram boundaries
so the combined call stack remains within the kernel's 512-byte limit.

These boundaries are compatibility requirements. Source-level contract tests
in `src/main.rs` guard the bounded walks and stack boundaries, and a release
build must load on a kernel with the standard one-million-instruction verifier
limit.

## Stable surfaces

The refactor does not change:

- map names, map types, or map key/value records;
- sched_ext program and struct-ops names;
- placement, enqueue, or dispatch opcode values;
- DSQ ID encoding;
- task runtime storage size and field inventory;
- statistics and ring-buffer event layouts;
- the two-slot policy publication protocol.

Moving a definition between owning headers is internal. Changing any item
above requires coordinated userspace encoding, BPF validation, inspection,
and compatibility tests.

## Mitosis extraction seams

A Mitosis backend can reuse mechanism without inheriting Snake policy. The
intended extraction order is:

1. Reuse the typed DSQ identity and operation layer.
2. Reuse task-state lifetime, callback reader lifetime, statistics, and timing.
3. Reuse generic mask materialization and topology-blind mask lookup.
4. Reuse queue state, initialization, and routing only if Mitosis adopts the
   same dense-cell and owner-CPU model.
5. Provide a Mitosis scheduler-mode facade and policy implementation behind
   the shared callback-facing contracts.

Snake's opcode ladder, TOML lowering, queue allocation rules, and concrete
FIFO/VTIME/EEVDF policies remain Snake-owned. Shared code should move only when
both backends use the same invariants; similar names alone are not a reason to
merge policy code.

Weighted EEVDF service is explicitly outside this refactor. EEVDF retains its
current experimental behavior and documented service-ratio limitation. That
work needs separate fairness design and validation rather than changes to the
backend ownership boundaries.
