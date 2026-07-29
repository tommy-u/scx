// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  callbackDurationClass,
  compactCpuList,
  decorateCells,
  fieldReferenceGroups,
  fineTimingCaptureModels,
  formatCallbackDuration,
  ladderPercentages,
  queueTopologyModel,
  queueLadderSections,
  queueRungFlow,
  routeFromHash,
  rungLadderPercentages,
  rungPercentages,
  selectionRungHitFlow,
} from "../../src/web/inspection.js";

test("inspection routes default to activity and accept policy, cells, and callbacks", () => {
  assert.equal(routeFromHash(""), "activity");
  assert.equal(routeFromHash("#/activity"), "activity");
  assert.equal(routeFromHash("#/policy"), "policy");
  assert.equal(routeFromHash("#/cells"), "cells");
  assert.equal(routeFromHash("#/callbacks"), "callbacks");
  assert.equal(routeFromHash("#/unknown"), "activity");
});

test("callback durations consistently use nanoseconds", () => {
  assert.equal(formatCallbackDuration(null), "—");
  assert.equal(formatCallbackDuration(420), "420 ns");
  assert.equal(formatCallbackDuration(1_500), "1,500 ns");
  assert.equal(formatCallbackDuration(2_500_000), "2,500,000 ns");
  assert.equal(formatCallbackDuration(3_000_000_000), "3,000,000,000 ns");
});

test("callback durations over one thousand nanoseconds are warnings", () => {
  assert.equal(callbackDurationClass(null), "");
  assert.equal(callbackDurationClass(1_000), "");
  assert.equal(callbackDurationClass(1_001), "callback-duration-warning");
});

test("fine timing controls preserve independent collecting and historical states", () => {
  const captures = fineTimingCaptureModels({
    captures: [
      { callback: "select_cpu", state: "collecting", session_id: 3, stages: [] },
      { callback: "enqueue", state: "historical", session_id: 2, stages: [] },
      { callback: "dispatch", state: "inactive", session_id: null, stages: [] },
    ],
  });

  assert.deepEqual(
    captures.map(({ callback, checked, stateLabel }) => ({ callback, checked, stateLabel })),
    [
      { callback: "select_cpu", checked: true, stateLabel: "Collecting" },
      { callback: "enqueue", checked: false, stateLabel: "Historical" },
      { callback: "dispatch", checked: false, stateLabel: "Inactive" },
    ],
  );
});

test("callback page contains the fine timing panel host", () => {
  const page = readFileSync(
    new URL("../../src/web/index.html", import.meta.url),
    "utf8",
  );
  assert.match(page, /id="fineTimingPanels"/);
  assert.match(page, /id="fineTimingNotice"/);
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
  assert.equal(sections[1].cyclic, true);
  assert.equal(sections[1].rungs[0].operation, "affinity");
  assert.equal(sections[1].rungs[1].flow.miss, "Empty → wrap to rung 0");
});

test("min_vtime dispatch is presented as a combined clock-order operation", () => {
  const sections = queueLadderSections({
    layout: "cell",
    enqueue: [
      { index: 0, operation: "cell" },
      { index: 1, operation: "affinity" },
    ],
    dispatch: [{ index: 0, operation: "min_vtime(cell,affinity)" }],
  });

  assert.equal(sections[1].behavior, "Lowest VTIME; alternating exact ties");
  assert.equal(sections[1].cyclic, false);
  assert.equal(sections[1].rungs[0].role, "operation");
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

test("resolved queue topology model labels cells and DSQs for display", () => {
  const model = queueTopologyModel(
    {
      mode_name: "vtime",
      clock_model: "one clock per cell shared by normal and affinity queues",
    },
    {
      layout: "cell_llc",
      affinity_queue_count: 2,
      cells: [
        {
          external_id: 0,
          index: 0,
          synthetic: true,
          cpu_weight: 1,
          clock_index: 0,
          primary_cpus: [0],
          borrowable_cpus: [1],
        },
        {
          external_id: 7,
          index: 1,
          synthetic: false,
          cpu_weight: 2,
          clock_index: 1,
          primary_cpus: [1],
          borrowable_cpus: [0],
        },
      ],
      normal_queues: [
        { index: 0, dsq_id: 536870912, cell_index: 0, clock_index: 0, llc_id: 10, consumer_cpus: [0] },
      ],
      cpu_routes: [
        { cpu: 0, owner_cell_id: 0, owner_cell_index: 0, llc_id: 10, normal_queue_index: 0, normal_dsq_id: 536870912, affinity_dsq_id: 268435456 },
      ],
    },
  );

  assert.equal(model.mode, "VTIME");
  assert.equal(model.cells[0].label, "Cell 0 (synthetic)");
  assert.equal(model.cells[1].label, "Cell 7");
  assert.equal(model.normalQueues[0].dsq, "0x20000000");
  assert.equal(model.cpuRoutes[0].affinityDsq, "0x10000000");
});

test("CPU masks are compacted into readable ranges", () => {
  assert.equal(compactCpuList([]), "None");
  assert.equal(compactCpuList([0, 1, 2, 4, 6, 7]), "0-2, 4, 6-7");
});
