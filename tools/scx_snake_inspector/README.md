# scx_snake_inspector

`scx_snake_inspector` keeps scheduler
activity, installed policy state, cells, and task mappings in one local web
application instead of splitting them across separate tools.

The embedded interface has three views:

- **Activity** counts a migration when a Snake task executes on a different
  CPU than its previous execution slice. It also shows aligned per-CPU runtime.
- **Policy** shows both BPF placement-ladder slots, their rung data, live or
  frozen counters, contextual references for the displayed encoded fields, and
  a catalog of validated TOML policies that can be activated after
  confirmation.
- **Cells** shows declared cell CPU membership, overlaps, and expandable
  current task mappings.

The current inspection schema does not expose queue callback ladders or the
resolved queue topology. In queue mode, the page therefore does not show
synthetic cell 0, allocated primary and borrowable masks, cell/LLC DSQ shards,
or per-CPU affinity queues. Use `scx_snake --dump-compiled-policy` and scheduler
statistics for that information.

An aligned strip below the matrix shows per-CPU utilization reported by
Snake's stats socket. The strip always covers all Snake tasks; TGID and cgroup
selectors apply only to the migration matrix. Window, CPU order, color scale,
and zoom apply to both Activity visualizations. Policy and Cells require a
Snake build that exports the versioned `inspect` stats target; Activity remains
available with older compatible schedulers.

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
