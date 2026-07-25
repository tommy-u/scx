# scx_snake_heatmap

`scx_snake_heatmap` is a standalone live CPU migration matrix for Snake. It
counts a migration when a Snake task executes on a different CPU than its
previous execution slice. This measures consecutive execution slices rather
than relying on the `sched_migrate_task` decision tracepoint.

The binary embeds its web UI and serves it on a loopback address. The page
provides rolling-window, CPU-order, color-scale, zoom, TGID, and cgroup
selectors.

## Build and run

```bash
cargo build --release --manifest-path tools/scx_snake_heatmap/Cargo.toml
sudo tools/scx_snake_heatmap/target/release/scx_snake_heatmap
```

The collector needs permission to load tracing BPF programs and read
`/proc/kallsyms`. Build as the normal user first to avoid root-owned build
artifacts.

Useful options:

```text
--window 10s          Initial window selected in the page
--max-window 5m       Maximum rolling history retained in memory
--listen 127.0.0.1:8787
```

The listen address is intentionally restricted to loopback. The page remains
available while Snake is stopped and starts a fresh history whenever Snake's
`enable_seq` changes.

## Verify

```bash
cargo test --manifest-path tools/scx_snake_heatmap/Cargo.toml
cargo check --all-targets --manifest-path tools/scx_snake_heatmap/Cargo.toml
node --test tools/scx_snake_heatmap/tests/web/heatmap.test.mjs
```
