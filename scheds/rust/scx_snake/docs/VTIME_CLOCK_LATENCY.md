# Cell VTIME Clock Latency Experiment

Date: 2026-08-01

## Decision

Keep cell VTIME clock reads serialized. Lockless reads cut the exact wrapper
latency roughly in half, but the A/B workload did not demonstrate a safe system
win and showed a large, variable shift away from wakeup-heavy switch work. The
runtime implementation was restored to the locked version after the experiment.

## Method

The benchmark used `tests/vtime_clock_latency_vm.sh` with:

- a 16-vCPU VM exposing two LLCs;
- one managed workload cell on CPUs `4-7,12-15` and cell 0 on the other CPUs;
- 4 `stress-ng` CPU, 4 switch, and 4 pipe workers;
- a 5-second warmup and 20-second capture at a 1/256 sample rate; and
- the same Inspector binary in every run.

QEMU and all vCPU threads were constrained to the same 16-host-CPU union. They
were not pinned one-to-one because this host's Python 3.9 `virtme-ng` cannot run
its `zip(..., strict=False)` pinning path. Thus the two guest LLCs do not imply
stable placement on the two selected physical LLCs, and throughput results must
be treated as directional rather than causal.

The locked and lockless variants were each run twice. All four completed runs
reported zero invalid, VTIME accounting, and membership-invalid-run errors.
The lockless variant used `READ_ONCE()` for reads and an optimistic locked slow
path for updates.

The original A/B captures remained enabled while stress-ng shut down, so their
fine-timing sessions are slightly longer than the nominal 20-second interval.
The sample populations are dominated by steady-state events, but they are not
exact fixed-window counters. The harness now freezes the workload before
closing captures and records that freeze interval; no callback-count throughput
claim is made from the original runs.

| Variant | Snake binary SHA-256 |
| --- | --- |
| Locked | `4c9710aa1307f1aa89f8344f398c6d37f8f716f1e0e8f3b56011425c2ef171d3` |
| Lockless | `a031247ea19492fdf193233c805cba0bf4b938583e0cf5516b6fd42b05590e73` |
| Inspector | `17a8b8c33d158abaf5a1135b0af072f2b1d62355a72c9ec3edd9ad0f18e2f8b7` |

## Results

Exact cell-clock read timing was consistent within each variant:

| Callback | Locked mean ns | Lockless mean ns | Locked p95 ns | Lockless p95 ns |
| --- | ---: | ---: | ---: | ---: |
| `select_cpu` | 91-94 | 40-43 | 255 | 63 |
| `enqueue` | 80-83 | 39-40 | 255 | 63 |
| `runnable` | 81-84 | 39 | 255 | 63 |
| `running` | 91-93 | 39-40 | 255 | 63 |

Average stress-ng throughput across each full run, including warmup, moved as
follows:

| stress-ng operation | Locked ops/s | Lockless ops/s | Change |
| --- | ---: | ---: | ---: |
| CPU | 13,663 | 13,242 | -3.1% |
| Switch | 186,119 | 80,976 | -56.5% |
| Pipe | 832,888 | 983,814 | +18.1% |

The locked switch results were 175,414 and 196,824 operations per second. The
lockless results were 61,344 and 100,608 operations per second, a much wider
spread. Pipe throughput moved in the opposite direction. This is not a
defensible throughput win, but the shared host-CPU union and two repetitions are
not controlled enough to call the service-mix shift causal.

## Interpretation

The new wrapper timing does not support the original multi-microsecond shared
clock hypothesis on this workload. A locked read costs about 80-94 ns here.
Removing serialization saves roughly 40-54 ns, but permits CPUs to make VTIME
clamp and translation decisions from different frontier observations. Given
the small local saving, the workload shift, and the physical-pinning caveat,
the experiment does not justify deploying the lockless path.

Raw artifacts, including policies, binary hashes, topology, callback timing,
fine timing, inspection snapshots, stress-ng output, and logs are under:

`/home/tommyu/scx-snake-vm-artifacts/vtime-clock-20260801/`

The relevant directories are `before`, `locked-replay`, `after`, and
`lockless-replay`. Binary hashes are authoritative; the saved Git state records
the harness invocation and is not source provenance for a supplied replay
binary.
