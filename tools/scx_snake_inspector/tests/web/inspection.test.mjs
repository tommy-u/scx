// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  decorateCells,
  fieldReferenceGroups,
  ladderPercentages,
  queueLadderSections,
  queueRungFlow,
  routeFromHash,
  rungLadderPercentages,
  rungPercentages,
  selectionRungHitFlow,
} from "../../src/web/inspection.js";

test("inspection routes default to activity and accept policy and cells", () => {
  assert.equal(routeFromHash(""), "activity");
  assert.equal(routeFromHash("#/activity"), "activity");
  assert.equal(routeFromHash("#/policy"), "policy");
  assert.equal(routeFromHash("#/cells"), "cells");
  assert.equal(routeFromHash("#/unknown"), "activity");
});

test("field references keep context-valid and other ABI choices separate", () => {
  const groups = fieldReferenceGroups({
    selected: { value: "pick_idle", label: "Pick idle", description: "Selected" },
    valid: [
      { value: "pick_idle", label: "Pick idle", description: "Selected" },
      { value: "pick_random_idle", label: "Random", description: "Also valid" },
    ],
    other: [
      { value: "claim_idle", label: "Claim", description: "Invalid with this input" },
    ],
  });

  assert.equal(groups.selected.value, "pick_idle");
  assert.deepEqual(groups.valid.map((choice) => choice.value), [
    "pick_idle",
    "pick_random_idle",
  ]);
  assert.deepEqual(groups.other.map((choice) => choice.value), ["claim_idle"]);
});

test("cell decoration exposes overlaps and mapped tasks", () => {
  const cells = decorateCells(
    [
      { id: 2, cpus: [0, 1], task_count: 1 },
      { id: 7, cpus: [1, 2], task_count: 1 },
    ],
    [
      { tid: 41, tgid: 40, cell_id: 2, name: "alpha" },
      { tid: 72, tgid: 70, cell_id: 7, name: "beta" },
    ],
  );

  assert.deepEqual(cells[0].overlapIds, [7]);
  assert.deepEqual(cells[1].overlapIds, [2]);
  assert.equal(cells[0].tasks[0].tid, 41);
  assert.equal(cells[1].tasks[0].tid, 72);
});

test("rung hit and miss percentages use attempts as the denominator", () => {
  assert.deepEqual(
    rungPercentages({ attempts: 40, hits: 30, misses: 8, errors: 2 }),
    { hit: 75, miss: 20 },
  );
  assert.deepEqual(
    rungPercentages({ attempts: 0, hits: 0, misses: 0, errors: 0 }),
    { hit: 0, miss: 0 },
  );
});

test("rung ladder percentages use all select calls as the denominator", () => {
  assert.deepEqual(
    rungLadderPercentages(
      { attempts: 40, hits: 30, misses: 8, errors: 2 },
      { select_calls: 400 },
    ),
    { hit: 7.5, miss: 2 },
  );
  assert.deepEqual(
    rungLadderPercentages({ attempts: 0, hits: 0, misses: 0 }, { select_calls: 0 }),
    { hit: 0, miss: 0 },
  );
});

test("rung metric columns have stable equal-width geometry", () => {
  const stylesheet = readFileSync(
    new URL("../../src/web/style.css", import.meta.url),
    "utf8",
  );
  const rule = stylesheet.match(/\.rung-metrics\s*\{(?<body>[^}]*)\}/)?.groups?.body;

  assert.ok(rule, "expected a .rung-metrics rule");
  assert.match(rule, /flex:\s*0 0 min\(58%, 320px\)/);
  assert.match(rule, /width:\s*min\(58%, 320px\)/);
  assert.match(rule, /grid-template-columns:\s*repeat\(4, minmax\(0, 1fr\)\)/);
});

test("ladder percentages count each select call once", () => {
  assert.deepEqual(
    ladderPercentages({
      select_calls: 50,
      direct_dispatches: 42,
      ladder_exhaustions: 6,
      invalid_errors: 2,
    }),
    { hit: 84, miss: 12 },
  );
  assert.deepEqual(ladderPercentages({ select_calls: 0 }), { hit: 0, miss: 0 });
});

test("enqueue rung flow is first-success with a terminal affinity fallback", () => {
  assert.deepEqual(queueRungFlow("enqueue", 0, 2), {
    hit: "Queued → stop",
    miss: "Unavailable → rung 1",
  });
  assert.deepEqual(queueRungFlow("enqueue", 1, 2), {
    hit: "Queued → stop",
    miss: "Failure → error",
  });
});

test("dispatch rung flow wraps its cyclic per-CPU cursor", () => {
  assert.deepEqual(queueRungFlow("dispatch", 0, 2), {
    hit: "Work → dispatch",
    miss: "Empty → rung 1",
  });
  assert.deepEqual(queueRungFlow("dispatch", 1, 2), {
    hit: "Work → dispatch",
    miss: "Empty → wrap to rung 0",
  });
});

test("queue ladder sections preserve order and callback semantics", () => {
  assert.deepEqual(queueLadderSections(null), []);

  const sections = queueLadderSections({
    layout: "cell_llc",
    enqueue: [
      { index: 0, operation: "cell" },
      { index: 1, operation: "affinity" },
    ],
    dispatch: [
      { index: 0, operation: "affinity" },
      { index: 1, operation: "cell" },
    ],
  });

  assert.equal(sections[0].title, "Enqueue");
  assert.equal(sections[0].behavior, "First success");
  assert.equal(sections[0].rungs[0].role, "target");
  assert.equal(sections[0].rungs[1].flow.miss, "Failure → error");
  assert.equal(sections[1].title, "Dispatch");
  assert.equal(sections[1].behavior, "Cyclic per-CPU cursor");
  assert.equal(sections[1].rungs[0].operation, "affinity");
  assert.equal(sections[1].rungs[1].flow.miss, "Empty → wrap to rung 0");
});

test("idle selection hits flow into the configured queue path", () => {
  assert.equal(selectionRungHitFlow({ scope: "task_allowed" }, null), "Hit → dispatch");
  assert.equal(
    selectionRungHitFlow({ scope: "task_cell" }, { layout: "cell" }),
    "Hit → enqueue ladder",
  );
  assert.equal(
    selectionRungHitFlow({ scope: "task_cell_borrowable" }, { layout: "cell" }),
    "Hit → direct dispatch",
  );
});
