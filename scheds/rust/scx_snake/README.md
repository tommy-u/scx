# scx_snake

[![Snakes and Ladders board](https://commons.wikimedia.org/wiki/Special:Redirect/file/Snakes_and_Ladders.jpg?width=720)](https://en.wikipedia.org/wiki/File:Snakes_and_Ladders.jpg)

`scx_snake` is a minimal Rust `sched_ext` scheduler for experimenting with
declarative scheduling policy. It intentionally keeps task scheduling simple so
that the userspace-to-BPF policy interface is the part under study.

This is an experimental mechanism, not a general-purpose scheduler. Do not use
it for production workloads.

## Policies

A policy is an ordered ladder of rungs. Each rung combines an operation, such
as `claim_idle`, `pick_idle`, or `pick_idle_core`, with a scope such as
`previous_cpu`, `previous_llc`, `previous_node`, or `task_allowed`. Userspace
validates the TOML and resolves topology; BPF only executes the resulting
bounded instructions and generic CPU masks.

### Minimal policy

Try the previous CPU before searching all allowed idle CPUs:

```toml
fallback = "previous_cpu"

[[rung]]
operation = "claim_idle"
scope = "previous_cpu"

[[rung]]
operation = "pick_idle"
scope = "task_allowed"
```

### Kernel-default simulation

`select_cpu` is the `sched_ext` wakeup callback for choosing where a waking task
should run, and the kernel provides `scx_bpf_select_cpu_dfl()` as its default
implementation. To demonstrate that Snake can express practical scheduling
behavior rather than only toy policies, this example recreates the key parts of
that default as an explicit ladder: sync wake affinity, then wholly idle cores
across increasingly broad topology scopes, then individual idle CPUs. Each
stage also gets its own hit and miss counters:

```toml
fallback = "previous_cpu"

[[rung]]
operation = "sync_wake_affine"
scope = "task_allowed"

[[rung]]
operation = "pick_idle_core"
scope = "previous_llc"

[[rung]]
operation = "pick_idle_core"
scope = "previous_node"

[[rung]]
operation = "pick_idle_core"
scope = "task_allowed"

[[rung]]
operation = "claim_idle"
scope = "previous_cpu"

[[rung]]
operation = "pick_idle"
scope = "previous_llc"

[[rung]]
operation = "pick_idle"
scope = "previous_node"

[[rung]]
operation = "pick_idle"
scope = "task_allowed"
```

A policy contains one to eight rungs. Its fallback is `previous_cpu` by default;
`any_allowed` instead distributes fallback hints across the affinity mask.
Invalid operations and operation/scope combinations are rejected before BPF is
loaded. See [`examples/`](examples/) for random placement, sub-LLC partitions,
whole-core selection, and the opaque kernel-default control.

`sync_wake_affine` only handles synchronous wakes. It prefers an idle previous
CPU in the waker's LLC, then the waker CPU when its local DSQ is empty and its
NUMA node has idle capacity. The latter is the only path that intentionally
targets a non-idle CPU, using a preemptive handoff.

## How scheduling works

Userspace owns policy and topology. It converts LLCs, NUMA nodes, and optional
`split_llcs` partitions into generic CPU-keyed mask tables. The BPF side knows
only how to walk instructions and operate on those masks.

### Userspace lowering

The TOML ladder is a userspace language, not the BPF ABI. Before attach or
update, Rust validates each operation/scope pair, assigns reusable mask-table
IDs, resolves topology into CPU masks, and lowers every rung to a fixed record:

```text
{ opcode, input, flags, data }
```

For example, `pick_idle_core(previous_llc)` becomes
`pick_idle_mask_table(cpu_prev, intersect_task_allowed | pick_idle_core,
previous_llc_table_id)`. The words LLC and NUMA never reach BPF; they have
already become table IDs and masks.

The backend command set is deliberately small: `claim_idle`, `pick_idle`,
`pick_idle_mask_table`, `pick_random_idle`, `kernel_default`, and
`sync_wake_affine`. Inputs select either `cpu_prev` or the task's allowed mask;
flags refine the operation, and `data` carries mask-table IDs. Userspace writes
the compiled ladder and masks into an inactive BPF map slot, asks BPF to
validate it, then atomically makes that slot active.

A successful rung dispatches directly to the selected CPU's local DSQ and
skips `enqueue`. If all rungs miss, Snake returns an affinity-safe fallback CPU
hint; `enqueue` then puts the task on the global FIFO DSQ. There is no hidden
idle search after the final rung.

## Build and run

From the repository root:

```bash
cargo test -p scx_snake
cargo build --release -p scx_snake

sudo ./target/release/scx_snake \
  --policy scheds/rust/scx_snake/examples/kernel-default-sim.toml \
  --stats 1
```

Replace the complete ladder without restarting the scheduler:

```bash
sudo ./target/release/scx_snake \
  --update-policy scheds/rust/scx_snake/examples/random-idle.toml
```

The running process compiles and resolves the new file, prepares it in an
inactive ladder slot, then publishes it with one atomic switch. A rejected
update leaves the current ladder running.

Inspect the compiled ladder and resolved mask tables without attaching BPF:

```bash
./target/release/scx_snake \
  --policy scheds/rust/scx_snake/examples/kernel-default-sim.toml \
  --dump-compiled-policy
```

## Statistics

The text output from `--stats 1` shows the active policy generation plus
attempts, hits, misses, and errors for each rung. A successful update advances
the generation and starts fresh counters with the new rung labels. Also watch
`direct_dispatches`, `ladder_exhaustions`, `enqueues`, and `invalid_errors`; the
last should remain zero.

Use `--stats-format json` for NDJSON, `--help-stats` for counter definitions, or
monitor an already running scheduler without a policy:

```bash
sudo ./target/release/scx_snake --monitor 1
```

This workload exercises the synchronous-wake rung:

```bash
stress-ng --pipe 4 --futex 4 --timeout 30s --metrics-brief
```

## Limits

Topology is resolved when a policy is attached or updated. The kernel-default
simulation does not implement distance-ordered remote NUMA search. Exhausted
ladders use a simple global FIFO with no topology-aware enqueue, stealing, or
draining policy. The ABI remains experimental.
