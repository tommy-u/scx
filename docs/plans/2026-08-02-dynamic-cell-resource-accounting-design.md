# Dynamic Cell Resource Accounting

## Goal

Make dynamic cells understandable in two glances:

1. Show every live cell and where its primary CPUs sit in the real host topology.
2. Show a complete, EWMA-smoothed accounting of the capacity owned by each cell.

The accounting is diagnostic input for future rebalancing. It must report absolute
runtime or average cores, not call a utilization percentage "demand."

## Placement Overview

The Layout tab starts with one shared topology atlas. Columns follow the host's
topology order and group logical CPUs by physical core and composite
`(node, package, LLC)` identity. Each logical CPU has exactly one primary-owner
cell color. The cell legend shows name, `cell_id/slot_epoch`, task count, primary
CPU count, and DSQ count.

Selecting a cell emphasizes its primary CPUs and outlines its borrowable CPUs.
The existing cell-to-DSQ bands remain below the atlas as expandable queue detail.
Configured cpuset constraints must not be inferred from effective CPUs; the atlas
only labels a cell pinned or unpinned when Snake exports that distinction.

## Resource Accounting

The Utilization tab contains one aligned lane per live cell. Every lane uses the
same average-core scale and has a capacity background equal to the cell's current
primary CPU count. The dominant bar is an EWMA of:

- home-cell scheduled runtime;
- flexible runtime from other cells;
- affinity-constrained runtime from other cells;
- other scheduled task context not attributed to Snake;
- hard IRQ and softirq time;
- idle and iowait time;
- steal time; and
- residual or overage required to expose imperfect source reconciliation.

The current sample remains available in the lane details. Tooltips give runtime,
average cores, and share of owned capacity for every category. The legend uses a
distinct neutral encoding for idle and residual so they cannot be mistaken for
cell work.

## Data Flow

Snake already exports task-cell runtime per CPU. It will additionally export
affinity-queue runtime per CPU. When an affinity run's task cell differs from the
cell owning its execution CPU, the inspector classifies it as foreign pinned
runtime. Other foreign runtime is flexible borrowed-in work.

The inspector already samples per-CPU `/proc/stat`. It combines host time, Snake
runtime, cell runtime, active primary ownership, and cell identity into one
server-side accounting sample. EWMA state is keyed by `(cell_id, slot_epoch)`.

The active topology generation is part of the sample contract. A generation
change invalidates a window that spans both ownership maps; the first sample on
the new generation establishes a baseline. Managed rebalances preserve EWMA only
after a complete new-generation sample. Cell removal or epoch reuse discards the
old series.

## Degraded States

Older Snake versions may omit affinity runtime. The atlas still renders, while
the accounting lane combines all foreign Snake work and labels the pinned split
unsupported. Missing or misaligned host, Snake, cell, or topology samples produce
a visible synchronizing state rather than inferred values. Arithmetic overage is
shown explicitly and never hidden by clipping.

## Verification

Unit tests cover affinity runtime accounting, source reconciliation, topology
generation changes, epoch reuse, non-contiguous CPU IDs, SMT siblings, and
repeated numeric LLC IDs across packages. Web tests cover atlas ownership,
selection, shared scales, EWMA updates, degraded telemetry, and accessible labels.
Desktop and mobile screenshots verify that labels, topology groups, and accounting
lanes remain readable without overlap.
