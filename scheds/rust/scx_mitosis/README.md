# scx_mitosis

A cgroup-aware scheduler that isolates workloads into *cells*. The eventual goal is to enable overcomitting workloads on datacenter servers.

## How it works

The direct children of the cgroup passed via `--cell-parent-cgroup` each get
their own *cell*, except for names excluded with `--cell-exclude`, which remain
in cell 0. Each cell owns a dedicated CPU set with a shared dispatch queue.
Tasks within a cell are scheduled using weighted vtime. CPU-pinned tasks
(typically system threads) use per-CPU queues. Cell and CPU tasks compete for
dispatch based on their vtime.

On multi-LLC systems, LLC-awareness keeps tasks on cache-sharing CPUs. In this case, the single cell queue is split into multiple queues, one per LLC.

## Usage

```bash
# Basic
scx_mitosis --cell-parent-cgroup /workloads

# With LLC-awareness
scx_mitosis --cell-parent-cgroup /workloads --enable-llc-awareness

# Run the scheduler and monitor its stats in the same process
scx_mitosis --cell-parent-cgroup /workloads --monitor-sync 1

# Monitor an already running scheduler from another terminal
scx_mitosis --monitor 1
```

## Shared DSQ depth statistics

Enable `--enable-dsq-depth-stats` to report each cell's
`shared_dsq_enqueue_depth_p99` (`c_shared_dsq_enqueue_depth_p99` in the
metrics schema). It defaults to disabled, which reports zero.

Each observation is the queue depth immediately before an enqueue into a
shared cell or subcell DSQ. Direct local inserts and CPU-pinned DSQs are
excluded. Observations from all of a cell's subcells, LLC queues and CPU
shards are pooled. The percentile is weighted by enqueues, so queues with
more enqueues contribute more observations; it is not a time average or
the maximum of the queues' percentiles.

Userspace publishes the nearest-rank P99 from each completed, approximately
60-second window, measured with monotonic time. Requests between completed
windows retain the cached result. CPU and subcell reconfiguration preserve
the window for the same workload; a new owner of a reused cell ID starts a
new window. The first window and completed windows without observations
report zero.

The histogram approximates depth using bucket upper edges of
0, 1, 3, 7, ..., 16383. Depths of 16384 and above are reported as 16384.
Snapshots of the live counters are approximate because enqueues continue
while they are read. Counters are cumulative and never cleared by readers.
