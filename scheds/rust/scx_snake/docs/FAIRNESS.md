# Fairness in scx_snake

> **Experimental:** FIFO remains the default. Run EEVDF only in disposable
> VMs. Its affinity-constrained forward-progress regression passes, but the
> pinned nice-level demo currently produces approximately equal service instead
> of the expected weighted shares.

Snake separates CPU placement from CPU-time fairness. The policy ladder and
task cells choose where a task may run. The startup `--fairness` option chooses
which runnable task runs when tasks contend for CPU time.

Two disciplines are implemented:

```bash
# Existing behavior and the default.
scx_snake --policy policy.toml --fairness fifo

# Experimental global EEVDF.
scx_snake --policy policy.toml --fairness eevdf
```

The mode is immutable BPF read-only configuration and requires a scheduler
restart to change. Runtime policy updates and task-to-cell changes do not reset
fairness state.

## FIFO control

FIFO preserves Snake's original behavior. A successful idle-CPU placement is
inserted directly into that CPU's local DSQ with `SCX_SLICE_DFL` (20 ms). A task
that reaches `enqueue` and cannot be placed by a task-cell rung goes to the
built-in global FIFO DSQ with the same slice.

FIFO does not provide weighted fairness. It remains available as the control
for placement experiments and compatibility comparisons.

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

Userspace supplies startup mode, compiled placement policy, resolved CPU masks,
and live task-to-cell annotations. BPF reads the kernel task weight and runtime,
maintains runnable weight, virtual time, per-task requests and lag, and performs
all eligibility, promotion, and dispatch decisions. Picture/gallery shapes and
cell meanings remain entirely in userspace.

The BPF implementation is isolated in [`src/bpf/fairness.h`](../src/bpf/fairness.h).
Placement execution remains in [`src/bpf/ladder.h`](../src/bpf/ladder.h).

## Validation demo

Start Snake in EEVDF mode, then run the pinned workload from another terminal:

```bash
make -C scheds/rust/scx_snake/interactive start FAIRNESS=eevdf
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
runtime, lag clamps, and accounting errors.

The VM-only affinity regression exercises this forward-progress rule:

```bash
sudo scheds/rust/scx_snake/tests/eevdf_affinity_future.sh \
  target/release/scx_snake
```

## Current scope

The implementation is one global per-task fairness domain. It does not provide
cell-level weights, hierarchical group fairness, per-NUMA clocks, or live mode
switching. The global virtual clock uses a BPF spin lock; scalability under
large runnable sets is an explicit experiment rather than a production claim.
