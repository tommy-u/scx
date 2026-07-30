// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  schedulerDebugModel,
  overviewModel,
  parseInspectorRoute,
} from "../../src/web/inspection.js";

const page = readFileSync(
  new URL("../../src/web/index.html", import.meta.url),
  "utf8",
);
const script = readFileSync(
  new URL("../../src/web/app.js", import.meta.url),
  "utf8",
);

test("workspace reorganization preserves every existing inspector surface", () => {
  for (const id of [
    "activityView",
    "callbacksView",
    "policyView",
    "cellsView",
    "controlView",
    "policyChoices",
    "slotComparison",
    "queueTopology",
    "schedulerCurrentCommand",
    "schedulerCommandPreview",
    "schedulerSettingsRows",
    "feedbackTranscript",
  ]) {
    assert.match(page, new RegExp(`id="${id}"`), `missing #${id}`);
  }
});

test("workspace reorganization preserves control and feedback behavior", () => {
  for (const behavior of [
    "activateSelectedPolicy",
    "startScheduler",
    "restartScheduler",
    "stopScheduler",
    "resetAllStats",
    "copyFeedback",
    "clearFeedback",
    "toggleFeedbackComposer",
  ]) {
    assert.match(script, new RegExp(`function ${behavior}\\(`), `missing ${behavior}`);
  }
});

test("nested workspace routes are canonical and legacy hashes remain compatible", () => {
  for (const route of [
    "overview",
    "observe/placement",
    "observe/callbacks",
    "configure",
    "inspect/policy-slots",
    "inspect/queue-topology",
    "inspect/cells",
    "debugging",
  ]) {
    assert.deepEqual(parseInspectorRoute(`#/${route}`), {
      route,
      feedbackOpen: false,
    });
  }
  assert.deepEqual(parseInspectorRoute("#/activity"), {
    route: "observe/placement",
    feedbackOpen: false,
  });
  assert.deepEqual(parseInspectorRoute("#/callbacks"), {
    route: "observe/callbacks",
    feedbackOpen: false,
  });
  assert.deepEqual(parseInspectorRoute("#/policy"), {
    route: "inspect/policy-slots",
    feedbackOpen: false,
  });
  assert.deepEqual(parseInspectorRoute("#/control"), {
    route: "configure",
    feedbackOpen: false,
  });
  assert.deepEqual(parseInspectorRoute("#/feedback"), {
    route: "overview",
    feedbackOpen: true,
  });
  assert.deepEqual(parseInspectorRoute("#/unknown"), {
    route: "overview",
    feedbackOpen: false,
  });
});

test("overview model summarizes existing runtime payloads without new thresholds", () => {
  const context = {
    scheduler_attach_seq: 7,
    scheduler_active: true,
    policy_generation: 12,
    active_slot: 1,
    fairness: "vtime",
    callback_sample_rate: 64,
  };
  assert.deepEqual(overviewModel({
    snapshot: {
      context,
      total: 90,
      rate_per_second: 3.5,
      active_pairs: 2,
      observed_ms: 9_500,
      window_ms: 10_000,
      pair_map_failures: 2,
      task_storage_failures: 0,
      cells: [
        { from: 2, to: 6, count: 30 },
        { from: 1, to: 3, count: 60 },
      ],
    },
    callbackTiming: {
      sample_rate: 64,
      generation: 12,
      callbacks: [
        { callback: "select_cpu", samples: 20, p99_ns: 800 },
        { callback: "enqueue", samples: 12, p99_ns: 1_400 },
      ],
    },
    inspection: {
      context,
      fairness: { mode_name: "vtime" },
      cells: [{ id: 0 }, { id: 1 }],
      task_mappings: [{ tid: 10 }, { tid: 11 }, { tid: 12 }],
      queue_topology: {
        layout: "cell",
        affinity_queue_count: 8,
        cpu_routes: [{ cpu: 0 }, { cpu: 1 }],
      },
      slots: [{ slot: 1, state: "active", generation: 12 }],
    },
    control: { context, policy_id: "cell-min-vtime.toml" },
    topology: { numeric_order: [0, 1] },
    errors: ["Callback polling failed", null],
  }), {
    runtime: {
      synchronizing: false,
      statusLabel: "Snake active · Attach #7",
      detailLabel: "cell-min-vtime.toml · VTIME · policy gen 12 · rung set 1 · sampling 1/64",
    },
    warnings: [
      "2 pair-map failures · 0 task-state failures",
      "Callback polling failed",
    ],
    activity: {
      available: true,
      total: 90,
      ratePerSecond: 3.5,
      activePairs: 2,
      observedMs: 9_500,
      windowMs: 10_000,
      busiestRoute: { from: 1, to: 3, count: 60 },
    },
    callbacks: {
      available: true,
      sampleRate: 64,
      generation: 12,
      sampleCount: 32,
      slowest: { callback: "enqueue", samples: 12, p99Ns: 1_400 },
    },
    policy: {
      available: true,
      policyId: "cell-min-vtime.toml",
      fairness: "vtime",
      generation: 12,
      activeSlot: 1,
      queueLayout: "cell",
      cpuRouteCount: 2,
      expectedCpuCount: 2,
      routesComplete: true,
    },
    cells: { available: true, cellCount: 2, taskCount: 3 },
  });
});

test("overview model has explicit empty states before the first poll", () => {
  const model = overviewModel();
  assert.equal(model.runtime.statusLabel, "Waiting for Snake");
  assert.deepEqual(model.warnings, []);
  assert.equal(model.activity.busiestRoute, null);
  assert.equal(model.activity.available, false);
  assert.equal(model.callbacks.slowest, null);
  assert.equal(model.callbacks.available, false);
  assert.equal(model.policy.policyId, null);
  assert.equal(model.policy.available, false);
  assert.equal(model.policy.routesComplete, true);
  assert.deepEqual(model.cells, { available: false, cellCount: 0, taskCount: 0 });
});

test("debug model fully specifies the running scheduler and non-default settings", () => {
  const context = {
    scheduler_attach_seq: 24,
    scheduler_active: true,
    policy_generation: 7,
    active_slot: 1,
    fairness: "vtime",
    callback_sample_rate: 128,
  };
  const model = schedulerDebugModel({
    control: {
      active: true,
      managed: false,
      controllable: true,
      scheduler_name: "snake",
      pid: 4812,
      current_command: [
        "./target/release/scx_snake",
        "--policy",
        "./policies/basic.toml",
        "--fairness",
        "vtime",
        "--stats",
        "1",
      ],
      policy_id: "basic.toml",
      context,
      settings: [
        {
          name: "fairness",
          effective: "vtime",
          default_value: "fifo",
          launch_override: "vtime",
          runtime_observed: true,
          change_mode: "reload",
        },
        {
          name: "callback_timing_sample_rate",
          effective: 128,
          default_value: 64,
          launch_override: 64,
          runtime_observed: true,
          change_mode: "dynamic",
        },
        {
          name: "exit_dump_len",
          effective: 0,
          default_value: 0,
          launch_override: null,
          runtime_observed: false,
          change_mode: "reload",
        },
      ],
    },
    inspection: {
      context,
      active_slot: 1,
      slots: [{
        slot: 1,
        state: "active",
        generation: 7,
        policy: { source: "[[rung]]\noperation = \"pick_idle\"" },
      }],
    },
  });

  assert.equal(model.available, true);
  assert.equal(
    model.command,
    "./target/release/scx_snake --policy ./policies/basic.toml --fairness vtime --stats 1",
  );
  assert.deepEqual(model.identity, {
    schedulerName: "snake",
    pid: 4812,
    ownership: "External / Controllable",
    attachSequence: 24,
    policyId: "basic.toml",
    policyGeneration: 7,
    activeSlot: 1,
  });
  assert.deepEqual(model.nonDefaultSettings, [
    {
      name: "Fairness",
      defaultValue: "FIFO",
      effectiveValue: "VTIME",
      launchOverride: "VTIME",
      source: "Observed from Snake",
      changeLabel: "Reload required",
    },
    {
      name: "Callback sample rate",
      defaultValue: "1 / 64",
      effectiveValue: "1 / 128",
      launchOverride: "1 / 64",
      source: "Observed from Snake; changed after launch",
      changeLabel: "Dynamic",
    },
  ]);
  assert.equal(model.policySource, "[[rung]]\noperation = \"pick_idle\"");
  const snapshot = JSON.parse(model.snapshotText);
  assert.deepEqual(snapshot.scheduler.argv, model.argv);
  assert.equal(snapshot.active_policy.source, model.policySource);
  assert.equal(snapshot.configuration.non_default.length, 2);
});

test("debug model reports unavailable scheduler state without inventing configuration", () => {
  const model = schedulerDebugModel({
    control: {
      active: false,
      settings: [{
        name: "fairness",
        effective: null,
        default_value: "fifo",
        launch_override: null,
        runtime_observed: false,
        change_mode: "reload",
      }],
    },
  });
  assert.equal(model.available, false);
  assert.equal(model.command, "Snake is not running.");
  assert.deepEqual(model.nonDefaultSettings, []);
  assert.equal(model.policySource, null);
  const snapshot = JSON.parse(model.snapshotText);
  assert.equal(snapshot.scheduler.active, false);
  assert.deepEqual(snapshot.configuration.non_default, []);
});

test("page shell exposes grouped navigation and separate diagnostic workspaces", () => {
  for (const fragment of [
    'id="workspaceSidebar"',
    'id="navigationDrawer"',
    'href="#/overview"',
    'href="#/observe/placement"',
    'href="#/observe/callbacks"',
    'href="#/configure"',
    'href="#/inspect/policy-slots"',
    'href="#/inspect/queue-topology"',
    'href="#/inspect/cells"',
    'href="#/debugging"',
    'id="overviewView"',
    'id="queueTopologyView"',
    'id="debuggingView"',
    'data-view="configure"',
  ]) {
    assert.match(page, new RegExp(fragment), `missing ${fragment}`);
  }
  assert.doesNotMatch(page, /id="schedulerPolicy"/);
});

test("feedback is a drawer with a visible draft count", () => {
  assert.match(page, /<dialog[^>]+id="feedbackDrawer"/);
  assert.match(page, /id="feedbackCount"/);
  assert.match(page, /data-feedback-count/);
  assert.match(page, /id="closeFeedback"/);
  assert.match(script, /feedbackDrawer\.showModal\(\)/);
  assert.match(script, /feedbackEntries\.filter/);
  assert.match(script, /\.overview-section-heading/);
  assert.match(script, /policy-choice:\$\{escapeHtml\(selectedFairness\)\}:\$\{escapeHtml\(policy\.id\)\}:select/);
  assert.match(script, /warningSignature/);
  assert.doesNotMatch(script, /role="tab"/);
});

test("policy list clicks select a candidate without immediately mutating Snake", () => {
  const policyClickHandler = script.match(
    /elements\.policyChoices\.addEventListener\("click",[\s\S]*?elements\.confirmPolicyActivation\.addEventListener/,
  )?.[0] || "";
  assert.match(policyClickHandler, /state\.policyCandidate\s*=/);
  assert.match(policyClickHandler, /state\.selectedLifecycleFairness\s*=/);
  assert.doesNotMatch(policyClickHandler, /runPolicyCandidate\(\);/);
  assert.doesNotMatch(script, /policyCandidateAction/);
});
