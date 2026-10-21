# scx_mitosis

A cgroup-aware scheduler that isolates workloads into *cells*. The eventual goal is to enable overcomitting workloads on datacenter servers.

## How it works

The direct children of the cgroup passed via `--cell-parent-cgroup` each get
their own *cell*, except for names excluded with `--cell-exclude`, which remain
in cell 0. Each cell owns a dedicated CPU set divided into subcells.
Unrestricted tasks use one shared dispatch queue per subcell and logical LLC,
keeping them on cache-sharing CPUs. Tasks are scheduled using weighted vtime.
CPU-pinned tasks (typically system threads) use per-CPU queues. Subcell and CPU
tasks compete for dispatch based on their vtime.

LLC scheduling is always enabled. Startup requires available LLC information,
dense logical LLC IDs, and an LLC mask containing each assigned online CPU.
Real single-LLC systems are supported. There must be 1 to 16 logical LLCs after
any partitioning requested by `--virt-llc`.

`--enable-llc-awareness` remains accepted as a deprecated no-op for existing
launch commands. `--virt-llc` affects scheduling without that flag.

### Resource use

With L logical LLCs and C online CPUs, Mitosis creates `2048 * L + C` custom
DSQs, covering all 256 cells and 8 subcell slots, including inactive slots.
Former flat mode created `2048 + C` DSQs. At 16 LLCs there are 32768 subcell
queues.

Every initialized task, including pinned tasks, allocates two BPF cpumasks
instead of flat mode's one. The extra mask's size depends on the kernel.
Steal, drain and affinity-rescue counters can now become nonzero for workloads
that previously used flat mode.

## Usage

```bash
# Basic
scx_mitosis --cell-parent-cgroup /workloads

# Split each physical LLC into virtual LLCs of eight cores
scx_mitosis --cell-parent-cgroup /workloads --virt-llc=8-8

# Accepted for compatibility; LLC scheduling is already enabled
scx_mitosis --cell-parent-cgroup /workloads --enable-llc-awareness

# Run the scheduler and monitor its stats in the same process
scx_mitosis --cell-parent-cgroup /workloads --monitor-sync 1

# Monitor an already running scheduler from another terminal
scx_mitosis --monitor 1
```
