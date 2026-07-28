# scx_snake_inspector

`scx_snake_inspector` keeps scheduler
activity, installed policy state, cells, and task mappings in one local web
application instead of splitting them across separate tools.

The embedded interface has four views:

- **Activity** counts a migration when a Snake task executes on a different
  CPU than its previous execution slice. It also shows aligned per-CPU runtime.
- **Callbacks** shows sampled execution-time mean, approximate p50, p95, and
  p99 for Snake's seven hot scheduler callbacks over a rolling window or the
  active policy generation's lifetime.
- **Policy** shows both BPF placement-ladder slots, their rung data, live or
  frozen counters, configured enqueue and dispatch ladders, contextual
  references for encoded fields, resolved queue topology, and a catalog of
  validated TOML policies that can be activated after confirmation.
- **Cells** shows declared cell CPU membership, overlaps, and expandable
  current task mappings.

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

Callback timing is read-only in the inspector. Snake chooses the launch-time
sample rate with `--callback-timing-sample-rate` and defaults to 1/64. The
inspector retains up to `--max-window` of one-second histogram deltas, resets
the rolling baseline on scheduler restarts or policy-generation changes, and
keeps the scheduler's cumulative histogram for the Lifetime selection. Values
are upper bounds of base-2 nanosecond buckets; p95 is withheld below 20 samples
and p99 below 100.

## Build and run

```bash
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
