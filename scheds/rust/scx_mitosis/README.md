# scx_mitosis

A cgroup-aware scheduler that isolates workloads into *cells*. The eventual goal is to enable overcomitting workloads on datacenter servers.

## How it works

The direct children of the cgroup passed via `--cell-parent-cgroup` each get
their own *cell*, except for names excluded with `--cell-exclude`, which remain
in cell 0. Each cell owns a dedicated CPU set with a shared dispatch queue.
Tasks within a cell are scheduled using weighted vtime. CPU-pinned tasks
(typically system threads) use per-CPU queues. Cell and CPU tasks compete for
dispatch based on their vtime.

By default, each per-CPU queue maintains an independent vtime frontier. The
startup-only `--flatten-cpu-vtime` option instead uses the vtime frontier shared
by the CPU's owning cell and LLC. The per-CPU dispatch queues remain separate;
only their vtime domain changes. Without LLC awareness, they share the cell's
flat vtime frontier.

The startup-only `--flatten-cell-vtime` option additionally combines every LLC
frontier in a cell into one cell-wide vtime domain. It implies
`--flatten-cpu-vtime`, so every per-CPU and cell/LLC queue in the cell competes
against the same frontier. LLC-specific dispatch queues remain separate for
cache locality; only their vtime accounting is flattened.

On multi-LLC systems, LLC-awareness keeps tasks on cache-sharing CPUs. In this case, the single cell queue is split into multiple queues, one per LLC.

## Usage

```bash
# Basic
scx_mitosis --cell-parent-cgroup /workloads

# With LLC-awareness
scx_mitosis --cell-parent-cgroup /workloads --enable-llc-awareness

# Use the owning cell/LLC vtime for per-CPU queues
scx_mitosis --cell-parent-cgroup /workloads --flatten-cpu-vtime

# Use one vtime domain for every queue in each cell
scx_mitosis --cell-parent-cgroup /workloads --flatten-cell-vtime
```
