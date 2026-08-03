# Dynamic Cells Handoff

## Goal

Make `mitosis-sim.toml` create cells for live child cgroups, admit unpinned
workloads like Mitosis, and optionally resize cell CPU ownership from EWMA demand.

## Design

```text
cgroup scan -> stable cell ID/epoch -> optional cpuset constraint
            -> Mitosis CPU allocator -> banked BPF topology publish
runtime counters -> EWMA demand -> proportional reallocation -> banked publish
```

- Empty or unavailable `cpuset.cpus` means unpinned. When a child has no local
  cpuset controller files, its nearest ancestor's effective cpuset bounds it.
- Managed allocation order is exclusive claims, contested groups, then unclaimed
  CPUs shared by cell 0 and unpinned cells.
- `cell0_min_cpus` reserves CPUs without taking a child's last exclusive CPU.
- Resizing is opt-in under `[managed_cells.resizing]`; identity is
  `(cell_id, slot_epoch)` and counter baselines include the active BPF bank.
- Structural publication keeps Snake's drain/stage/flip/quiesce transaction.
  Same-identity resizing keeps stable cell/LLC DSQs live, then BPF drains shards
  that lost all consumers. It briefly closes custom enqueue and uses the global
  drain whenever an affinity DSQ on a CPU changing owner is non-empty,
  preventing that CPU's old-owner clock from starving pinned work. Legacy
  policies also retain the global drain. Allocation or publication failure is
  fatal, and borrowing masks are regenerated each time.
- Per-task custody markers balance normal and affinity depth at exact dispatch
  moves or external dequeue callbacks. Post-close enqueues route CPU-local
  without keeping a structural transition's inflight fence busy. Tasks already
  moved local resolve their stored external cell ID and epoch against the new
  bank before running.
- Live discovery uses a stable cpuset snapshot; transient cgroup churn keeps the
  active topology and retries.

## Status

- Implemented: admission, holdout, effective-cpuset bounds, EWMA tracking,
  weighted banked publication, stats gauges, and focused VM coverage.
- Validated: rapid VM cgroup churn, bidirectional EWMA resizing, and bare-metal
  create/stop/recreate for unpinned, cross-LLC pinned, CPU, and fork workloads.
  Same-name reuse advanced slot epochs; Snake stayed attached with clean kernel
  logs. Inspector and Snake run on the verified release binaries at port 44102.
