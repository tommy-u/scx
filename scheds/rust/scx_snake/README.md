# scx_snake

`scx_snake` is a minimal Rust `sched_ext` scheduler for experimenting with
declarative scheduling policy. It intentionally keeps task scheduling simple so
that the userspace-to-BPF policy interface is the part under study.

This is an experimental mechanism, not a general-purpose scheduler. Do not use
it for production workloads.

## Policy model

An idle-CPU policy is an ordered *ladder* of *rungs*. Userspace reads a required
TOML policy, validates its semantic names, and lowers each rung into the generic
mechanical ABI consumed by BPF. The BPF interpreter applies the compiled rungs
in order until one succeeds or the ladder is exhausted.

This split is deliberate. Userspace can eventually understand concepts such as
an LLC or NUMA node and materialize the masks and tables needed to express
them. BPF does not need topology-specific operations: it only interprets
operations, operand sources, flags, and data.

The initial semantic vocabulary has two rungs:

- `claim_idle(previous_cpu)` tries to claim the task's previous CPU when it is
  allowed and idle.
- `pick_idle(task_allowed)` searches the task's allowed CPU mask for an idle
  CPU.
- `pick_idle(previous_llc)` searches the intersection of the task's allowed
  CPUs and the previous CPU's LLC mask. Userspace discovers LLC topology and
  lowers this semantic scope to a generic CPU-keyed mask-table lookup; BPF does
  not contain an LLC-specific operation or topology identifier.

The corresponding TOML is:

```toml
[[rung]]
operation = "claim_idle"
scope = "previous_cpu"

[[rung]]
operation = "pick_idle"
scope = "task_allowed"
```

Userspace lowers these semantic pairs to fixed-size
`{ opcode, input, flags, data }` instructions. A policy must contain between one
and eight rungs; unsupported operation/scope pairs are rejected before BPF is
attached.

See [`examples/basic.toml`](examples/basic.toml) for the complete initial
policy and [`examples/llc.toml`](examples/llc.toml) for the LLC-aware ladder.

## Scheduling behavior

Successful idle-selection rungs dispatch directly to the selected CPU's local
DSQ from `select_cpu`. This preserves the placement selected by the policy and
skips `enqueue` for that task. Tasks that exhaust the ladder are enqueued on the
global FIFO dispatch queue after choosing an affinity-safe fallback CPU.

If every rung misses, the interpreter returns an affinity-safe non-idle CPU and
records ladder exhaustion. There is no implicit default idle search after the
last rung, so the configured ladder describes every idle search the scheduler
performs.

## Build and run

Build the scheduler from the repository root:

```bash
cargo build --release -p scx_snake
```

A policy is required when launching the scheduler:

```bash
sudo ./target/release/scx_snake \
  --policy scheds/rust/scx_snake/examples/basic.toml \
  --stats 1
```

The policy is compiled once at startup. Inspect the exact mechanical ladder
and any resolved mask-table entries without attaching the scheduler:

```bash
./target/release/scx_snake \
  --policy scheds/rust/scx_snake/examples/basic.toml \
  --dump-compiled-policy
```

For the LLC-aware example:

```bash
sudo ./target/release/scx_snake \
  --policy scheds/rust/scx_snake/examples/llc.toml \
  --stats 1
```

## Statistics

`--stats SECONDS` prints in-process periodic statistics. The default text table
is intended for interactive experiments:

```bash
sudo ./target/release/scx_snake \
  --policy scheds/rust/scx_snake/examples/basic.toml \
  --stats 1
```

Use NDJSON when feeding samples to another tool:

```bash
sudo ./target/release/scx_snake \
  --policy scheds/rust/scx_snake/examples/basic.toml \
  --stats 1 \
  --stats-format json
```

An external client can monitor an already running instance without supplying a
policy:

```bash
sudo ./target/release/scx_snake --monitor 1
```

Run `scx_snake --help-stats` for the current counter definitions. The output
includes scheduler lifecycle activity, ladder execution, per-rung outcomes,
exhaustion, and fallback selection so policy behavior is visible from
userspace. `--exit-dump-len` controls the amount of BPF exit diagnostics shown
when the scheduler stops.

## Prototype limitations

- Policies are startup-only and cannot be replaced while the scheduler runs.
- The only topology-aware semantic scope is `previous_llc`.
- LLC topology and mask tables are snapshotted for each attach and rebuilt when
  the scheduler restarts after CPU hotplug.
- The ABI is generic in shape but remains experimental and may change.
- Ladder hits bypass global FIFO ordering through direct local dispatch.
- Exhaustion fallbacks use a global FIFO with no scheduler-specific fairness
  policy.
- The scheduler does not yet express topology-aware search, stealing, or
  draining policies.
