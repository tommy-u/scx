# Mitosis virtual-time source harnesses

The standalone scripts extract and compile the affected scheduler C
functions from a selected checkout. Deterministic userspace adapters supply
CPU contexts, DSQs, clocks, affinity masks, and kernel helpers. Each script
is independent and requires Bash, Python 3, and a C compiler.

These checks exercise source-level scheduling and accounting invariants.
They do not load BPF, run the BPF verifier, execute kernel callbacks, or
measure a live workload's latency or CPU share. A source pass leaves BPF
loading, verifier compatibility, and live behavior to separate tests.

## Run

From the current checkout, run the same harness against the baseline and
current source:

```bash
./scheds/rust/scx_mitosis/test/vtime/cpu_shared_clock_gap.sh \
    --source /home/tommyu/scx
./scheds/rust/scx_mitosis/test/vtime/cpu_shared_clock_gap.sh \
    --source /home/tommyu/scx-mitosis-vtime-bugfixes
```

Replace the baseline path with a checkout from before the relevant fix,
and select the corresponding script for that fix. The original audited baseline
was fead94e15184e957469b346b129f412641691bbe. The current rebased baseline
is the fork's origin/main at 336d19b6d91182084e21adfa9b337b5172c6efd2.
Use the current harness for both runs so the fixture and assertions are
identical.

`MITOSIS_SOURCE` supplies the source override when `--source` is omitted.
`CC` selects the C compiler. Each script's `--help` describes source
discovery and supported arguments.

Source-mode exit codes:

| Exit | Meaning |
| --- | --- |
| 0 | The checked invariant holds. |
| 1 | The harness reproduced a BUG. |
| 2 | Harness, source extraction, input, or compilation error. |
| 77 | A prerequisite is missing. |

A baseline containing the reported bug is expected to return 1. Each fix
targets exit 0 for its corresponding harness. Exit 2 does not establish that an
issue is fixed; source changes can require updating the adapters.

## Expected checks

These descriptions state the expected invariants and results for the
fixes. Run the selected source to determine which checks hold.

### CPU and shared clock gap

[cpu_shared_clock_gap.sh](cpu_shared_clock_gap.sh)

Move a CPU with an older local clock into a domain whose shared clock is
100 seconds ahead. Two continuously runnable pinned tasks compete with
shared work. The baseline delays shared service by about 200 seconds of
simulated CPU runtime. The fix is expected to align the clocks and serve
shared work within eight 1ms slices.

On main versions with configured subcells, also move a cold CPU into a
hot nonzero subcell through the real subcell-assignment function. CPU and
shared queues must compare in the same clock units after reassignment.
CPU queue tags retain their native units and dispatch converts them using
the CPU bias.

### Task weights

[task_weights.sh](task_weights.sh)

The fixture follows kernel callback order: dispatch with runnable `prev`
occurs before stopping and re-enqueuing it. Renewing `prev` keeps it
running without a stopping or enqueue callback.

For two tasks with weights 100 and 1, the baseline produces an exact 1:1
service split in this schedule. The expected result after the fix is
30000:300 slices, an exact 100:1 split. The three-task case expects
30000:30000:300 slices for weights 100:100:1. The script checks both CPU
and shared DSQs, plus fair renewal and stale-placement rejection controls.

On main versions with demand accounting, retained service must also be
charged once to the CPU-task-clock counters. Renewing a slice preserves
the virtual-time charge's original start timestamp.

The runnable-clock reassignment harness below checks the configuration
transition that the fixed-population weight cases do not cover. Its mixed
queue controls reject clipping legitimately earned weighted lag.

The preserved `--live` mode measures process CPU time using an already
running Mitosis scheduler. Its active binary can differ from the selected
source checkout. Consult `--help` for its run options and interpretation.

### LLC draining and pinned wait protection

[drain_pinned_wait.sh](drain_pinned_wait.sh)

An already overdue CPU DSQ waiter must receive service before an orphan
LLC backlog. The baseline drains that backlog first. Controls require
draining to keep making progress when no pinned waiter is overdue or a
CPU DSQ move fails.

### Rescue wait timer

[rescue_wait_timer.sh](rescue_wait_timer.sh)

A successful affinity rescue into an empty CPU DSQ must start its wait
timer, allowing the rescued task's first wait to receive overdue
protection. Preserve an existing timer's start time. A failed rescue must
leave the target timer and task metadata unchanged.

### Weighted debt cap

[weighted_debt_cap.sh](weighted_debt_cap.sh)

A borrowed 1ms slice at weight 1 adds 100ms of valid virtual-time debt
while leaving the domain clocks unchanged. Enqueue must retain that debt;
the baseline retains only 16ms. A weight-100 control retains its 1ms debt.

An excessive-debt control at weight 200 charges 32ms and expects an 8ms
cap, checking that the limit also shrinks for higher weights. Zero weight
must be rejected before division or insertion.

### Unchanged LLC refresh

[unchanged_llc_refresh.sh](unchanged_llc_refresh.sh)

An affinity change removes a CPU outside the task's cell while its cell,
subcell, LLC, and DSQ stay identical. Preserve both positive debt and
credit through that refresh. Controls require a changed cell, subcell, or
LLC DSQ to reset virtual time to the new domain clock.

### Runnable task across CPU reassignment

[runnable_clock_realign.sh](runnable_clock_realign.sh)

Move a CPU with 100ms of retained clock history into a cell whose shared
queue already has a continuously runnable task. Wake an equal-weight peer
after the real configuration callback. Check both slice renewal and
ordinary re-enqueue, in the root and a nonzero subcell.

Before the weight change, the peer receives service immediately. With the
original weight change, CPU reassignment imports the unrelated 100ms
history into the destination shared clock and the peer waits 99ms. Keeping
CPU queue keys in native units and translating comparisons removes that
imported gap and the additional wait. The resident is only
owed its actual service. The reproducer prints the imported gap and peer
wait for each case and returns 1 if the wait exceeds one additional slice.

```bash
./scheds/rust/scx_mitosis/test/vtime/runnable_clock_realign.sh --source .
```

Controls also retain ordinary weighted lag among two shared tasks and two
pinned tasks with overlapping CPU masks. Run that schedule both with
stable clocks and after a hot CPU joins the cell. Check that repeating an
unchanged nonzero-subcell configuration preserves its clock mapping and
that affinity restoration on the old CPU cannot import the target CPU's
tag before migration finishes.

Configuration fixtures simulate the requested CPU processing its kick.
CPU/shared comparisons use shared clock units, including any CPU bias.
These adapter changes support both representations without relaxing the
original service bounds or weighted-service assertions.
