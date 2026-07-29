# scx_snake_inspector

`scx_snake_inspector` keeps scheduler
activity, installed policy state, cells, and task mappings in one local web
application instead of splitting them across separate tools.

The embedded interface has five views:

- **Activity** counts a migration when a Snake task executes on a different
  CPU than its previous execution slice. It also shows aligned per-CPU runtime.
- **Callbacks** shows sampled execution-time mean, approximate p50, p95, and
  p99 for Snake's seven hot scheduler callbacks over a rolling window or the
  active policy generation's lifetime. It also provides independent
  fine-grained capture controls for `select_cpu`, queue enqueue, and queue
  dispatch.
- **Policy** shows both BPF placement-ladder slots, their rung data, live or
  frozen counters, configured enqueue and dispatch ladders, contextual
  references for encoded fields, resolved queue topology, and a catalog that
  identifies dynamic, restart-required, and invalid TOML policies.
- **Cells** shows declared cell CPU membership, overlaps, and expandable
  current task mappings. It can assign or clear manual cell overrides for one
  TID, every current thread in a TGID, or every current thread in a cgroup
  subtree. TGID and cgroup operations use a bounded snapshot; newly created
  threads are not assigned automatically.
- **Control** starts, stops, or restarts the attached Snake process, shows the
  exact launch command, and distinguishes changes that can be applied
  dynamically from settings that require a scheduler reload.

The Control view accepts only typed launch options. A policy from the
configured allowlist is required; fairness, callback sampling, exit dump
length, and verbose logging are independently optional. FIFO and VTIME are
available, but EEVDF is intentionally not exposed. The inspector refuses to
start while any scheduler is attached. It can adopt an externally launched
Snake when exactly one matching process can be identified, retaining a PID
file descriptor before signaling it. Ambiguous process matches leave lifecycle
controls disabled with the reason shown. Restart preserves arguments not
represented by the form, such as `--stats`, and validates the selected policy
before stopping the current scheduler. A child launched by the inspector is
stopped with the inspector; merely observing an external Snake does not change
its lifetime.

Compatible placement, enqueue, and dispatch ladder policy changes can be
activated dynamically from the Policy view. Selecting a restart-required
policy opens Control with that policy and the current launch settings already
loaded; the complete command remains visible before **Restart Snake** is
pressed. Fairness, task membership, queue topology, cells, weights, CPU masks,
and DSQ layout are attachment-time state and require a reload. Callback
sampling, fine-grained timing, and workload cell assignments are dynamic.
**Reset all stats** atomically switches Snake to
a cleared statistics bank at the same policy generation, rebases the
inspector's rolling histories, and clears fine-grained capture history. It
does not reload the scheduler or alter queues, clocks, membership, or task-cell
assignments.

In queue mode, the Policy view shows fairness and clock mode, synthetic cell 0,
dense cell indices, allocated primary and borrowable masks, cell/LLC normal DSQ
shards, and every CPU's owner, normal DSQ, and affinity DSQ. It does not yet
attach runtime queue depth, enqueue/dispatch, borrowing/lending, or clock
transition metrics to those topology rows; use scheduler statistics for those
counters.

An aligned strip below the matrix shows per-CPU utilization reported by
Snake's stats socket. The strip always covers all Snake tasks; TGID and cgroup
selectors apply only to the migration matrix. Window, CPU order, color scale,
and zoom apply to both Activity visualizations. Policy and Cells require a
Snake build that exports the versioned `inspect` stats target; Activity remains
available with older compatible schedulers. The Callbacks view reports an
unsupported state when the active Snake build predates callback histograms.

Snake defaults callback timing to 1/64. The Callbacks view can change the rate
from disabled through every callback to 1/4096 without restarting Snake. A rate
change freezes active fine-grained captures as **Historical** and begins a new
rolling callback baseline. The inspector retains up to `--max-window` of
one-second histogram deltas and keeps the scheduler's cumulative histogram for
the Lifetime selection. Values are upper bounds of base-2 nanosecond buckets;
p95 is withheld below 20 samples and p99 below 100.

Each fine-grained callback switch starts and stops an independent capture using
the same sample decision. Snake folds bounded ring-buffer samples into fixed
per-stage histograms and does not retain individual events. An unchecked
capture remains visible as **Historical**; a policy update freezes every active
capture before activating the next generation. Select CPU capture is available
whenever callback sampling is enabled; enqueue and dispatch capture additionally
require queue topology mode. Unavailable switches remain visible but disabled
with the requirement shown.

## Build and run

```bash
cargo build --release -p scx_snake
cargo build --release --manifest-path tools/scx_snake_inspector/Cargo.toml
sudo tools/scx_snake_inspector/target/release/scx_snake_inspector
```

The collector needs permission to load tracing BPF programs and read
`/proc/kallsyms`. Build as the normal user first to avoid root-owned build
artifacts.

Useful options:

```text
--window 10s          Initial window selected in the page
--max-window 5m       Maximum rolling history retained in memory
--listen 127.0.0.1:8787
--policy-dir scheds/rust/scx_snake/examples
--snake-bin target/release/scx_snake
```

The listen address is intentionally restricted to loopback. The page remains
available while Snake is stopped and starts a fresh history whenever Snake's
`enable_seq` changes.

The policy directory is treated as an allowlist boundary. Only direct regular
`.toml` files are considered, symlinks are rejected, and Snake validates each
changed file before it appears as an activation choice.

## Verify

```bash
cargo test --manifest-path tools/scx_snake_inspector/Cargo.toml
cargo check --all-targets --manifest-path tools/scx_snake_inspector/Cargo.toml
node --test tools/scx_snake_inspector/tests/web/*.test.mjs
```
