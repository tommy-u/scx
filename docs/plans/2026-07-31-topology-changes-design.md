# Topology Changes

## Goal

Extend the Cells & DSQs workspace so it explains both the active topology and
how that topology changed. Operators should be able to identify a managed-cell
transition, its outcome, its slow or failed stage, and the affected cells
without reading scheduler logs.

## Design

The Cells & DSQs page gains two tabs. **Layout** retains the current live cell,
LLC, CPU, and DSQ diagram. **Changes** shows the current topology generation and
a newest-first list of managed topology transition attempts.

Snake owns the transition record. The inspector response exposes a typed,
bounded history rather than deriving success or failure from browser polling.
Each record includes:

- a transition identifier and start/completion timestamps;
- the source and destination topology generations;
- an outcome (`applied`, `deferred`, or `rejected`) and diagnostic detail;
- ordered stage timings for discovery, resolution, drain, publication,
  quiescence, and membership reconciliation when those stages run;
- compact per-cell deltas: identity/epoch, CPUs added and removed, and normal
  and affinity DSQ counts before and after.

The scheduler retains the latest 20 completed attempts in memory. It does not
retain full historic CPU-route tables, which would amplify the existing
inspection payload on large hosts. Static policies and managed policies with no
observed change expose an empty history and the active generation.

The Changes tab summarizes each transition in one row and expands affected-cell
details on demand. Outcome, text, and icons communicate state without relying
on color alone. Failed stages include the scheduler diagnostic. Empty and
unavailable states explain whether managed topology is inactive or simply has
not changed since attachment.

## Verification

Rust unit tests cover lifecycle serialization, bounded history, cell deltas,
and successful/deferred/rejected records. JavaScript unit tests cover the view
model, ordering, labels, empty states, and generation handling. Static DOM tests
cover tab semantics and render hosts. The complete Rust and web test suites run
before the final commit.
