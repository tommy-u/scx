# Dynamic Cells Handoff

## Goal

Make `mitosis-sim.toml` create cells for live child cgroups, preserve capacity
for cell 0, admit unpinned workloads like Mitosis, and optionally resize cell CPU
ownership from EWMA demand.

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
- The demand controller samples primary, borrowed, and lent execution, smooths
  capacity-normalized utilization with an EWMA, and reallocates only when the
  configured spread threshold and cooldown allow it.
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
- The Mitosis profile drains orphaned same-cell shards before normal dispatch and
  steals from sibling LLC shards after local candidates are exhausted. Borrowing
  still applies only to newly runnable placement; it does not pull queued work
  across cells.
- Pinned-waiter VTIME slice shrinking is a separate live BPF control. It shortens
  the running task's remaining slice using waiter runtime and configured minimum,
  maximum, and multiplier bounds.

## Operations

- Managed reconciliation and EWMA controls can be changed live, but restart
  reloads them from `mitosis-sim.toml`; live Inspector changes are not written
  back to disk.
- VTIME slice controls are process-local and not part of the TOML policy. Restart
  restores a 5000 us base slice. The built-in `mitosis-sim` profile restores
  shrinking enabled with a 500 us minimum, 4000 us maximum, and multiplier 2;
  custom policy files restore shrinking disabled. Reapply intended non-default
  values after attach.
- CPU hotplug is unsupported while Snake is attached. Attachment-time queue and
  ownership topology does not follow CPUs going online or offline.
- An inspection or metrics failure can currently unwind the scheduler loop.
  Treat the Inspector as an observer, not as the canary rollback mechanism.
- This implementation is suitable for a guarded, noncritical single-host canary
  with independent rollback. It is not production-ready until observer failures
  are isolated, hotplug is supported or safely rejected, cross-cell queued-work
  forward progress has a complete contract, and workload/churn rollout gates have
  been exercised.

## Status

- Implemented: managed admission, cell 0 holdout, effective-cpuset bounds,
  demand EWMA tracking and rebalancing, weighted banked publication,
  orphan draining, sibling-LLC stealing, VTIME slice controls, stats gauges, and
  focused VM coverage.
- Validated: rapid VM cgroup churn, bidirectional EWMA resizing, and bare-metal
  create/stop/recreate for unpinned, cross-LLC pinned, CPU, and fork workloads.
  Same-name reuse advanced slot epochs; Snake stayed attached with clean kernel
  logs. Inspector and Snake run on the verified release binaries at port 44102.
