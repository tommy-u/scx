# scx_snake_inspector

`scx_snake_inspector` keeps scheduler
activity, installed policy state, cells, and task mappings in one local web
application instead of splitting them across separate tools.

The embedded interface is organized by purpose rather than a fixed view count:

- **Overview** summarizes host pressure, scheduler outcomes, workload context,
  and the highest-impact tuning signals.
- **Observe** contains **Placement**, which shows CPU utilization and migration
  paths, and **Callback performance**, which shows sampled callback percentiles
  and independent fine-grained captures.
- **Configure** contains **Scheduler & policies**, which catalogs validated
  policies, previews launch impact, and controls start, stop, and restart.
- **Inspect** contains **Policy ladders**, **Queue topology**, and **Cells & tasks**
  for installed BPF state, resolved routing, resource domains, task mappings,
  and bounded workload-cell assignment.
- **Project** contains **Operations**, a concise data-flow, operating-boundary,
  and troubleshooting guide, and **Roadmap**, a dated view of completion
  estimates, release blockers, Mitosis gaps, and implementation dependencies.
- **Debugging** contains **Scheduler info**, with the exact scheduler identity,
  command, non-default configuration, installed policy, and copyable escalation
  snapshot, and **VTIME**, with fairness, clamp, runtime-path, affinity-queue,
  and dispatch-arbitration counters for the active policy generation.
- **Validate** contains **Testing**, a VM-only failure matrix grouped by FIFO,
  VTIME, and EEVDF. Each compatible policy runs for one minute under CPU
  saturation, waker/wakee switching, mixed affinity, and fork/yield churn.

The Project pages are curated presentations of the review under
[`docs/snake-review/`](../../docs/snake-review/README.md); that repository report
remains authoritative. **Feedback** is a separate drawer that collects
section-level notes as one copyable transcript. Notes remain in browser session
storage for the current tab and are never sent to the inspector backend.

The **Scheduler & policies** workspace accepts only typed launch options. A
policy from the configured allowlist is required; fairness, callback sampling,
exit dump length, and verbose logging are independently optional. FIFO is the
default; VTIME and EEVDF are exposed only for policies that support them and
remain experimental. EEVDF's weighted-share validation is known incorrect, so
it should be used only in disposable test environments. The inspector refuses
to start while any scheduler is attached. It can adopt an externally launched
Snake when exactly one matching process can be identified, retaining a PID file
descriptor before signaling it. Ambiguous process matches leave lifecycle
controls disabled with the reason shown. Restart preserves arguments not
represented by the form, such as `--stats`, and validates the selected policy
before stopping the current scheduler. A child launched by the inspector is
stopped with the inspector; merely observing an external Snake does not change
its lifetime.

Compatible placement, enqueue, and dispatch ladder policy changes can be
activated dynamically from **Scheduler & policies**. Selecting a
restart-required policy keeps that candidate and the current launch settings
loaded there; the complete command remains visible before **Restart Snake** is
pressed. Fairness, task membership, queue topology, cells, weights, CPU masks,
and DSQ layout are attachment-time state and require a reload. Callback
sampling, fine-grained timing, and workload cell assignments are dynamic.
**Reset all stats** atomically switches Snake to
a cleared statistics bank at the same policy generation, rebases the
inspector's rolling histories, and clears fine-grained capture history. It
does not reload the scheduler or alter queues, clocks, membership, or task-cell
assignments.

The Queue topology view shows fairness and clock mode, synthetic cell 0, dense
cell indices, allocated primary and borrowable masks, cell/LLC normal DSQ
shards, and every CPU's owner, normal DSQ, and affinity DSQ. Its DSQ activity
table joins sampled insert success/error and removal success/miss latency with
queue residence and depth capture by DSQ. Successful moves are attributed to
both queues, so FIFO mode shows the shared source and each observed per-CPU
local destination.

An aligned strip above the matrix shows per-CPU utilization reported by
Snake's stats socket. The strip always covers all Snake tasks; TGID and cgroup
selectors apply only to the migration matrix. Window, CPU order, color scale,
and zoom apply to both **Placement** visualizations. **Policy ladders** and
**Cells & tasks** require a Snake build that exports the versioned `inspect`
stats target; **Placement** remains available with older compatible schedulers.
**Callback performance** reports an unsupported state when the active Snake
build predates callback histograms.

Snake defaults callback timing to 1/64. **Callback performance** can change the
rate from disabled through every callback to 1/4096 without restarting Snake. A
rate change freezes active fine-grained captures as **Historical** and begins a new
rolling callback baseline. The inspector retains up to `--max-window` of
one-second histogram deltas and keeps the scheduler's cumulative histogram for
the Lifetime selection. Values are upper bounds of base-2 nanosecond buckets;
p95 is withheld below 20 samples and p99 below 100.

Each fine-grained callback switch starts and stops an independent capture using
the same sample decision. Snake folds bounded ring-buffer samples into fixed
per-stage histograms and does not retain individual events. An unchecked
capture remains visible as **Historical**; a policy update freezes every active
capture before activating the next generation. Select CPU capture is available
whenever callback sampling is enabled, as are enqueue and dispatch capture.
Unavailable switches remain visible but disabled with the requirement shown.

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

## VM failure matrix

The testing runner deliberately refuses to execute outside a VM. Start one
shard inside a two-CPU-or-larger guest and use port 8788 when another
inspector is already using the default port:

```bash
sudo tools/scx_snake_inspector/target/release/scx_snake_inspector \
  --listen 127.0.0.1:8788 \
  --enable-testing \
  --testing-isolated \
  --testing-duration 60s \
  --testing-shard-index 0 \
  --testing-shard-count 8 \
  --testing-artifact-dir /tmp/scx-snake-testing/shard-0
```

Open `http://127.0.0.1:8788/#/validate/testing`, then choose **Run assigned
shard**. A check means the scheduler and workload completed the full window
without a kernel failure signature or nonzero scheduler error counter. An X
means Snake exited, reported an invalid scheduler or fairness-accounting error,
or dmesg reported a runnable-task stall, sched_ext error/watchdog, BPF error,
lockup, oops, or panic. Hover a case for its runtime, shard VM allocation,
kernel and Snake build, and VM boot command. This first version does not grade
fairness, throughput, or latency.

For a headless guest, use
`scheds/rust/scx_snake/tests/vm_matrix_shard.sh`. The manual GitHub workflow
`snake-vm-matrix.yml` allocates eight independent guests and uploads one result
tree per shard. Each guest atomically updates `shard-N/run.json` after every
case. New runs record their schema, campaign, policy-catalog fingerprint,
kernel release, Snake version, and Snake binary fingerprint; the aggregate
viewer rejects mismatched shards.

To watch shards that share a campaign directory, start one host Inspector in
read-only aggregate mode:

```bash
tools/scx_snake_inspector/target/release/scx_snake_inspector \
  --listen 127.0.0.1:8788 \
  --enable-testing \
  --testing-isolated \
  --testing-duration 60s \
  --testing-shard-count 8 \
  --testing-import-dir /tmp/scx-snake-testing/campaign-1
```

Repeat `--testing-import-dir` to compare campaigns from different kernels in
one view:

```bash
tools/scx_snake_inspector/target/release/scx_snake_inspector \
  --listen 127.0.0.1:8788 \
  --enable-testing \
  --testing-isolated \
  --testing-duration 60s \
  --testing-shard-count 8 \
  --testing-import-dir /tmp/scx-snake-testing/campaign-6.13 \
  --testing-import-dir /tmp/scx-snake-testing/campaign-6.16
```

The Testing view adds one tab per imported kernel. A kernel tab receives a
check only after every matrix case passes and an X as soon as any case fails.
Repeated runs on the same kernel are disambiguated by campaign name.

The aggregate view polls all eight live `run.json` files and leaves cases from
missing shards pending. Run and Stop are disabled there because each guest
owns its scheduler lifecycle. `--testing-isolated` disables the unrelated
host-context refreshers and tracing collector in dedicated guests/viewers.

On a KVM host with `vng` and a sched_ext-enabled host kernel, launch the eight
guests in parallel with:

```bash
scheds/rust/scx_snake/tests/vm_matrix_local.sh
```

The launcher prints the matching aggregate UI command and the campaign path.
Override guest allocation with `SNAKE_TESTING_SHARDS`,
`SNAKE_TESTING_GUEST_CPUS`, and `SNAKE_TESTING_GUEST_MEMORY`. By default, each
VM timeout is derived from its maximum assigned cases using a 105-second budget
per case plus a three-minute margin. Override the budget with
`SNAKE_TESTING_CASE_BUDGET_SECS` or set the whole timeout with
`SNAKE_TESTING_VM_TIMEOUT_SECS`. Campaign directories must be new or empty.

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
