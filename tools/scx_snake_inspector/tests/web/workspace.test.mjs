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
const styles = readFileSync(
  new URL("../../src/web/style.css", import.meta.url),
  "utf8",
);
const themeScript = readFileSync(
  new URL("../../src/web/theme.js", import.meta.url),
  "utf8",
);
const reviewIndex = readFileSync(
  new URL("../../../../scheds/rust/scx_snake/docs/snake-review/README.md", import.meta.url),
  "utf8",
);
const featureReview = readFileSync(
  new URL("../../../../scheds/rust/scx_snake/docs/snake-review/feature-completeness.md", import.meta.url),
  "utf8",
);
const validationReview = readFileSync(
  new URL("../../../../scheds/rust/scx_snake/docs/snake-review/validation-and-risk-plan.md", import.meta.url),
  "utf8",
);
const mitosisReview = readFileSync(
  new URL("../../../../scheds/rust/scx_snake/docs/snake-review/mitosis-compatibility.md", import.meta.url),
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

test("workspace offers a persistent theme choice before first paint", () => {
  assert.match(page, /<html lang="en" data-theme="system" data-resolved-theme="light">/);
  assert.match(page, /id="themeLight"[^>]+data-theme-preference="light"/);
  assert.match(page, /id="themeSystem"[^>]+data-theme-preference="system"/);
  assert.match(page, /id="themeDark"[^>]+data-theme-preference="dark"/);
  assert.match(page, /id="mobileThemeLight"[^>]+data-theme-preference="light"/);
  assert.match(page, /id="mobileThemeSystem"[^>]+data-theme-preference="system"/);
  assert.match(page, /id="mobileThemeDark"[^>]+data-theme-preference="dark"/);
  assert.ok(
    page.indexOf("data-theme-bootstrap") < page.indexOf("/assets/style.css"),
    "stored theme must be applied before the stylesheet loads",
  );
  assert.match(script, /from "\/assets\/theme\.js"/);
  assert.match(script, /data-theme-preference/);
  assert.match(themeScript, /scx-snake-inspector-theme-v1/);
});

test("dark mode has a complete semantic palette and repaints the canvas", () => {
  assert.match(styles, /:root\[data-resolved-theme="dark"\]\s*{/);
  for (const token of [
    "--background",
    "--surface",
    "--surface-muted",
    "--ink",
    "--muted",
    "--border",
    "--accent",
    "--success-bg",
    "--warning-bg",
    "--danger-bg",
    "--info-bg",
    "--canvas-surface",
    "--canvas-label",
  ]) {
    assert.match(styles, new RegExp(`${token}:`), `missing ${token}`);
  }
  assert.match(script, /function canvasPalette\(/);
  assert.match(script, /getComputedStyle\(document\.documentElement\)/);
  assert.match(script, /drawContrastingOutline\(context,/);
  assert.match(script, /function dsqHeatmapInk\(/);
  assert.match(script, /--heat-ink:\$\{ink\}/);
  assert.doesNotMatch(script, /context\.fillStyle = "#ffffff"/);
  assert.doesNotMatch(script, /context\.fillStyle = "#11161c"/);
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
    "debugging/scheduler",
    "debugging/vtime",
    "project/operations",
    "project/roadmap",
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
  assert.deepEqual(parseInspectorRoute("#/debugging"), {
    route: "debugging/scheduler",
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

test("overview model summarizes runtime payloads without inventing health thresholds", () => {
  const context = {
    scheduler_attach_seq: 7,
    scheduler_active: true,
    policy_generation: 12,
    active_slot: 1,
    fairness: "vtime",
    callback_sample_rate: 64,
  };
  const model = overviewModel({
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
  });
  assert.equal(model.runtime.statusLabel, "Snake active · Attach #7");
  assert.deepEqual(model.warnings, [
    "2 pair-map failures · 0 task-state failures",
    "Callback polling failed",
  ]);
  assert.deepEqual(model.activity.busiestRoute, { from: 1, to: 3, count: 60 });
  assert.deepEqual(model.callbacks.slowest, {
    callback: "enqueue",
    samples: 12,
    p99Ns: 1_400,
  });
  assert.equal(model.policy.routesComplete, true);
  assert.deepEqual(model.cells, { available: true, cellCount: 2, taskCount: 3 });
});

test("overview ranks tuning signals within their own domains and groups host context", () => {
  const fastRungBuckets = Array(64).fill(0);
  fastRungBuckets[5] = 100;
  const slowRungBuckets = Array(64).fill(0);
  slowRungBuckets[11] = 100;
  const context = {
    scheduler_attach_seq: 7,
    scheduler_active: true,
    policy_generation: 12,
    active_slot: 1,
    fairness: "vtime",
    callback_sample_rate: 64,
  };
  const model = overviewModel({
    snapshot: {
      context,
      cell_stats: {
        status: "ready",
        source_policy_generation: 12,
        observed_ms: 10_000,
        cells: [
          { id: 1, owned_utilization_pct: 42, borrowed_pct: 5, lent_pct: 12 },
          { id: 2, owned_utilization_pct: 88, borrowed_pct: 20, lent_pct: 1 },
        ],
      },
    },
    callbackTiming: {
      sample_rate: 64,
      callbacks: [
        { callback: "select_cpu", samples: 100, p99_ns: 900 },
        { callback: "dispatch", samples: 100, p99_ns: 4_000 },
      ],
    },
    inspection: {
      context,
      cells: [],
      task_mappings: [],
      slots: [{
        slot: 1,
        state: "active",
        generation: 12,
        metrics: { select_calls: 100, direct_dispatches: 80, ladder_exhaustions: 20 },
        policy: { rungs: [
          { index: 0, operation: "claim_idle", timing: { total_ns: 6_300, buckets: fastRungBuckets } },
          { index: 1, operation: "load_any", timing: { total_ns: 409_500, buckets: slowRungBuckets } },
        ] },
      }],
    },
    queueTiming: {
      status: "ready",
      sample_rate: 64,
      context,
      capture: {
        state: "collecting",
        policy_generation: 12,
        dropped_samples: 2,
        dsqs: [
          {
            dsq_id: 20,
            queue_class: "normal",
            residence: { samples: 100, p99_ns: 7_000 },
            depth: { samples: 100, p95: 4 },
          },
          {
            dsq_id: 10,
            queue_class: "normal",
            residence: { samples: 100, p99_ns: 12_000 },
            depth: { samples: 100, p95: 9 },
          },
        ],
      },
    },
    hostContext: {
      identity: {
        hostname: "devbig008.atn3.facebook.com",
        ods_entity: "devbig008.atn3",
        cpu_count: 316,
        datacenter: "atn3",
        machine_pool: "devbig",
        hardware: "T2_TRN",
      },
      resource_browser: { state: "ready", fetched_at_ms: 1_000, message: null },
      tupperware: {
        state: "ready",
        fetched_at_ms: 1_000,
        message: null,
        data: [
          { job_handle: "tsp_atn/team/job", task_id: "3" },
          { job_handle: "tsp_atn/team/job", task_id: "1" },
        ],
      },
      allotments: {
        state: "ready",
        fetched_at_ms: 1_000,
        message: null,
        data: [
          { shape: "M55", ownership: "GUARANTEED", state: "IN_USE", owner: "tsp_atn.2" },
          { shape: "M55", ownership: "GUARANTEED", state: "READY_TO_RUN_TASKS", owner: null },
        ],
      },
      charts: [{ metric: "cpu-pressure", state: "ready" }],
    },
  });

  assert.deepEqual(model.tuning.cells.ranked.map((cell) => cell.id), [2, 1]);
  assert.deepEqual(model.tuning.cells.borrowers.map((cell) => cell.id), [2, 1]);
  assert.deepEqual(model.tuning.cells.lenders.map((cell) => cell.id), [1, 2]);
  assert.deepEqual(model.tuning.queues.ranked.map((queue) => queue.dsqId), [10, 20]);
  assert.deepEqual(model.tuning.callbacks.ranked.map((callback) => callback.callback), [
    "dispatch",
    "select_cpu",
  ]);
  assert.deepEqual(model.tuning.rungs.ranked.map((rung) => rung.index), [1, 0]);
  assert.equal(model.activity.directDispatchPct, 80);
  assert.equal(model.activity.exhaustionPct, 20);
  assert.match(model.warnings.join(" "), /2 queue timing samples dropped/);
  assert.equal(model.host.jobs[0].jobHandle, "tsp_atn/team/job");
  assert.deepEqual(model.host.jobs[0].taskIds, ["1", "3"]);
  assert.deepEqual(model.host.allotmentGroups, [
    { shape: "M55", ownership: "GUARANTEED", state: "IN_USE", count: 1, owners: ["tsp_atn.2"] },
    { shape: "M55", ownership: "GUARANTEED", state: "READY_TO_RUN_TASKS", count: 1, owners: [] },
  ]);
  assert.equal(model.host.charts[0].metric, "cpu-pressure");
});

test("overview ranks an idle cell by lending against owned CPU capacity", () => {
  const model = overviewModel({
    snapshot: {
      cell_stats: {
        status: "ready",
        observed_ms: 1_000,
        cells: [
          { id: 1, primary_cpu_count: 2, runtime_ns: 0, lent_runtime_ns: 1_000_000_000 },
          { id: 2, primary_cpu_count: 2, runtime_ns: 1_000_000_000, lent_runtime_ns: 200_000_000 },
        ],
      },
    },
  });

  assert.deepEqual(model.tuning.cells.lenders.map((cell) => cell.id), [1, 2]);
  assert.equal(model.tuning.cells.lenders[0].lentPct, 50);
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

test("VTIME debug model summarizes the active generation without inventing thresholds", async () => {
  const inspectionModule = await import("../../src/web/inspection.js");
  assert.equal(typeof inspectionModule.vtimeDebugModel, "function");
  const current = {
    context: {
      scheduler_attach_seq: 4,
      fairness: "vtime",
      policy_generation: 9,
      active_slot: 1,
    },
    fairness: { mode_name: "vtime" },
    queue_topology: { layout: "llc" },
    active_slot: 1,
    slots: [{
      slot: 1,
      state: "active",
      generation: 9,
      metrics: {
        vtime_enqueues: 100,
        vtime_dispatches: 90,
        vtime_cpu_enqueues: 10,
        vtime_cpu_dispatches: 8,
        vtime_credit_clamps: 25,
        vtime_clock_cas_retries: 7,
        vtime_clock_cas_exhaustions: 0,
        vtime_accounting_errors: 2,
        vtime_equal_head_ties: 5,
        slice_shrink_min: 11,
        slice_shrink_proportional: 12,
        slice_shrink_max: 13,
        vtime_direct_runtime_ns: 20,
        vtime_queued_runtime_ns: 80,
        select_calls: 120,
        fifo_shared_enqueues: 11,
        eevdf_lag_clamps: 4,
        dispatch_rungs: {
          2: {
            index: 2,
            operation: "peek(remote)",
            attempts: 40,
            hits: 20,
            misses: 20,
            selected: 10,
            move_misses: 3,
            errors: 0,
          },
          0: {
            index: 0,
            operation: "peek(cpu)",
            attempts: 40,
            hits: 5,
            misses: 35,
            selected: 4,
            move_misses: 0,
            errors: 0,
          },
        },
      },
    }],
  };
  const model = inspectionModule.vtimeDebugModel(current);

  assert.equal(model.available, true);
  assert.equal(model.modeActive, true);
  assert.equal(model.generation, 9);
  assert.deepEqual(model.clamps, { count: 25, enqueuePct: 25 });
  assert.deepEqual(model.runtime, {
    directNs: 20,
    queuedNs: 80,
    queuedPct: 80,
  });
  assert.deepEqual(model.affinity, {
    enqueues: 10,
    dispatches: 8,
    enqueuePct: 10,
  });
  assert.equal(model.accountingErrors, 2);
  assert.equal(model.equalHeadTies, 5);
  assert.deepEqual(model.dispatchRungs.map((rung) => rung.index), [0, 2]);
  assert.ok(model.counters.relevant.some((counter) => counter.key === "select_calls"));
  assert.ok(model.counters.relevant.some((counter) => counter.key === "vtime_credit_clamps"));
  assert.ok(model.counters.relevant.some((counter) => counter.key === "vtime_clock_cas_retries"));
  assert.ok(model.counters.relevant.some((counter) => counter.key === "vtime_clock_cas_exhaustions"));
  assert.ok(model.counters.relevant.some((counter) => counter.key === "slice_shrink_min"));
  assert.ok(model.counters.relevant.some((counter) => counter.key === "slice_shrink_proportional"));
  assert.ok(model.counters.relevant.some((counter) => counter.key === "slice_shrink_max"));
  assert.ok(model.counters.inactive.some((counter) => counter.key === "fifo_shared_enqueues"));
  assert.ok(model.counters.inactive.some((counter) => counter.key === "eevdf_lag_clamps"));
  assert.ok(!model.counters.inactive.some((counter) => counter.key.startsWith("vtime_")));

  const previous = {
    context: {
      scheduler_attach_seq: 4,
      fairness: "vtime",
      policy_generation: 9,
      active_slot: 1,
    },
    fairness: { mode_name: "vtime" },
    active_slot: 1,
    slots: [{
      slot: 1,
      state: "active",
      generation: 9,
      metrics: {
        vtime_enqueues: 80,
        vtime_dispatches: 70,
        vtime_cpu_enqueues: 6,
        vtime_cpu_dispatches: 4,
        vtime_credit_clamps: 20,
        vtime_clock_cas_retries: 3,
        vtime_clock_cas_exhaustions: 0,
        vtime_accounting_errors: 1,
        vtime_equal_head_ties: 1,
      },
    }],
  };
  const sampled = inspectionModule.vtimeDebugModel(current, {
    previousInspection: previous,
    elapsedMs: 2_000,
  });
  assert.deepEqual(sampled.rates, {
    enqueues: 10,
    dispatches: 10,
    affinityEnqueues: 2,
    affinityDispatches: 2,
    clamps: 2.5,
    equalHeadTies: 2,
    accountingErrors: 0.5,
  });
  const retryCounter = sampled.counters.relevant.find(
    (counter) => counter.key === "vtime_clock_cas_retries",
  );
  const exhaustionCounter = sampled.counters.relevant.find(
    (counter) => counter.key === "vtime_clock_cas_exhaustions",
  );
  assert.deepEqual(
    { value: retryCounter.value, rate: retryCounter.rate },
    { value: 7, rate: 2 },
  );
  assert.deepEqual(
    { value: exhaustionCounter.value, rate: exhaustionCounter.rate },
    { value: 0, rate: 0 },
  );
  assert.equal(inspectionModule.vtimeDebugModel(current).rates.enqueues, null);
  previous.context.policy_generation = 8;
  assert.equal(inspectionModule.vtimeDebugModel(current, {
    previousInspection: previous,
    elapsedMs: 2_000,
  }).rates.enqueues, null);
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
    'href="#/debugging/scheduler"',
    'href="#/debugging/vtime"',
    'href="#/project/operations"',
    'href="#/project/roadmap"',
    'id="overviewView"',
    'id="overviewWindowSelect"',
    'id="overviewScopeMode"',
    'id="overviewContext"',
    'id="overviewFaults"',
    'id="overviewPlacement"',
    'id="overviewCellBalance"',
    'id="overviewQueueing"',
    'id="overviewOverhead"',
    'id="overviewHost"',
    'id="overviewCharts"',
    'id="schedulerUptime"',
    'id="queueTopologyView"',
    'id="debuggingSchedulerView"',
    'id="debuggingVtimeView"',
    'id="operationsView"',
    'id="roadmapView"',
    'data-view="configure"',
  ]) {
    assert.match(page, new RegExp(fragment), `missing ${fragment}`);
  }
  assert.doesNotMatch(page, /id="schedulerPolicy"/);
  assert.match(page, /CPU pressure/);
  assert.match(page, /Scheduling delay/);
  assert.match(script, /\/api\/host-context/);
  assert.match(script, /method: "POST"/);
  assert.match(script, /data-open-ods/);
  assert.match(script, /overviewScopeDirty/);
  assert.match(page, /Window and scope filter live migration activity/);
  assert.match(script, /queueTiming: state\.queueTiming/);
  assert.match(script, /hostContext: state\.hostContext/);
});

test("VTIME debugging workspace renders fairness and arbitration diagnostics", () => {
  for (const fragment of [
    'id="debuggingVtimeFreshness"',
    'id="debuggingVtimeNotice"',
    'id="vtimeClampCount"',
    'id="vtimeClampRate"',
    'id="vtimeAccountingErrors"',
    'id="vtimeQueuedRuntimeShare"',
    'id="vtimeAffinityEnqueueShare"',
    'id="vtimeRelevantCountersTab"',
    'id="vtimeInactiveCountersTab"',
    'id="vtimeRelevantCounterRows"',
    'id="vtimeInactiveCounterRows"',
    'id="vtimeDispatchRows"',
  ]) {
    assert.match(page, new RegExp(fragment), `missing ${fragment}`);
  }
  assert.match(script, /function renderVtimeDebugging\(\)/);
  assert.match(script, /vtimeDebugModel\(inspection,\s*\{/);
  assert.match(page, /role="tablist"[^>]*aria-label="Policy counter relevance"/);
  assert.match(page, />Relevant to this policy<\/button>/);
  assert.match(page, />Not relevant to this policy<\/button>/);
  assert.match(page, />Count \/ sec<\/th>/);
});

test("each workspace heading matches its Explorer label", () => {
  const routes = [
    "overview",
    "observe/placement",
    "observe/callbacks",
    "configure",
    "inspect/policy-slots",
    "inspect/queue-topology",
    "inspect/cells",
    "debugging/scheduler",
    "debugging/vtime",
    "project/operations",
    "project/roadmap",
  ];
  const visibleText = (value) => value.replace(/&amp;/g, "&").trim();

  for (const route of routes) {
    const escapedRoute = route.replace("/", "\\/");
    const explorer = page.match(
      new RegExp(`<a[^>]+data-route="${escapedRoute}"[^>]*>([^<]+)</a>`),
    );
    const workspace = page.match(
      new RegExp(`<section[^>]+data-view="${escapedRoute}"[^>]*>[\\s\\S]*?<h2[^>]*>([^<]+)</h2>`),
    );
    assert.ok(explorer, `missing Explorer entry for ${route}`);
    assert.ok(workspace, `missing workspace heading for ${route}`);
    assert.equal(visibleText(workspace[1]), visibleText(explorer[1]), route);
  }
});

test("project navigation is available in both desktop and mobile explorers", () => {
  for (const route of ["project/operations", "project/roadmap"]) {
    const occurrences = page.match(
      new RegExp(`data-route="${route.replace("/", "\\/")}"`, "g"),
    ) || [];
    assert.equal(occurrences.length, 2, route);
  }
});

test("project roadmap exposes the dated review scores without drifting from the report", () => {
  const reviewDate = reviewIndex.match(/^Assessment date: (.+)$/m)?.[1];
  const baselineCommit = reviewIndex.match(/^Current baseline: `([0-9a-f]+)`$/m)?.[1];
  assert.ok(reviewDate, "assessment date missing from report");
  assert.ok(baselineCommit, "current baseline missing from report");
  assert.match(page, /data-view="project\/roadmap"/);
  assert.match(page, new RegExp(`data-assessment-date="${reviewDate}"`));
  assert.match(page, new RegExp(`data-assessment-commit="${baselineCommit}"`));
  assert.match(page, /Engineering estimate, not test coverage/);
  assert.match(page, /scheds\/rust\/scx_snake\/docs\/snake-review\/README\.md/);

  const scores = new Map([
    ["experimental-completeness", [90, "Snake experimental feature implementation", reviewIndex]],
    ["production-readiness", [45, "Snake production readiness", reviewIndex]],
    ["mitosis-parity", [85, "Overall end-to-end Mitosis behavior parity", reviewIndex]],
    ["rollout-validation", [45, "Overall production validation readiness", validationReview]],
    ["policy-engine", [95, "Policy engine", featureReview]],
    ["placement", [92, "Placement", featureReview]],
    ["observability", [94, "Observability", featureReview]],
    ["lifecycle", [92, "Lifecycle", featureReview]],
    ["inspector", [90, "Inspector", featureReview]],
    ["validation", [87, "Validation/testing", featureReview]],
    ["queue-features", [90, "Queue features", featureReview]],
    ["topology", [84, "Topology", featureReview]],
    ["fairness", [74, "Fairness", featureReview]],
    ["static-identity", [84, "Task identity/cgroups within declared scope", featureReview]],
    ["dynamic-identity", [78, "Mitosis-style dynamic identity and lifecycle", featureReview]],
  ]);

  for (const [key, [value, reportLabel, source]] of scores) {
    assert.match(
      page,
      new RegExp(`data-score-key="${key}"[^>]+data-score-value="${value}"`),
      `${key} missing from roadmap`,
    );
    assert.match(
      source,
      new RegExp(`${reportLabel.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}[^\\n]*${value}%`),
      `${key} drifted from the deep-dive report`,
    );
  }
});

test("roadmap completion bars expose their numeric meaning to assistive technology", () => {
  for (const [key, value] of [
    ["policy-engine", 95],
    ["placement", 92],
    ["observability", 94],
    ["lifecycle", 92],
    ["inspector", 90],
    ["validation", 87],
    ["queue-features", 90],
    ["topology", 84],
    ["fairness", 74],
    ["static-identity", 84],
    ["dynamic-identity", 78],
  ]) {
    assert.match(
      page,
      new RegExp(`<div class="roadmap-score-row" data-score-key="${key}" data-score-value="${value}"><div>[\\s\\S]*?<\\/div><progress[^>]+value="${value}"[^>]+aria-label="[^"]+"`),
      key,
    );
  }
});

test("Mitosis diagram percentages retain stable keys and report provenance", () => {
  for (const [key, value, label] of [
    ["mitosis-static-data-plane", 88, "Static scheduling data plane"],
    ["mitosis-dynamic-control", 82, "Dynamic cell/resource control"],
    ["mitosis-operations", 82, "Operations and diagnostics"],
    ["mitosis-overall", 85, "Weighted end-to-end behavior"],
  ]) {
    assert.match(
      page,
      new RegExp(`data-score-key="${key}"[^>]+data-score-value="${value}"`),
      `${key} missing from Mitosis diagram`,
    );
    assert.match(
      mitosisReview,
      new RegExp(`\\| ${label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")} \\| \\*\\*${value}%`),
      `${key} drifted from Mitosis review`,
    );
  }
  const equivalent = page.match(
    /<table[^>]+data-diagram-equivalent="mitosis-capability-coverage"[\s\S]*?<\/table>/,
  )?.[0] || "";
  for (const value of ["88%", "82%", "85% ±5"]) {
    assert.match(equivalent, new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
});

test("project roadmap leads with launch goals and keeps open work synchronized", () => {
  assert.match(reviewIndex, /## Roadmap priorities/);
  assert.match(page, /id="roadmapGoals"[\s\S]*id="roadmapFeatures"/);
  for (const priority of ["P0", "P1", "P2", "P3"]) {
    assert.match(page, new RegExp(`data-priority="${priority}"`));
    assert.match(page, new RegExp(`${priority}[^<]+`));
  }
  for (const [goal, priority] of [
    ["correctness-forward-progress", "P0"],
    ["production-readiness", "P0"],
    ["scale-soak-rollback", "P1"],
    ["mitosis-parity", "P1"],
    ["inspector-scalability", "P1"],
    ["validation-rollout", "P1"],
    ["policy-research", "P2"],
  ]) {
    assert.match(
      page,
      new RegExp(`data-goal-key="${goal}"[^>]+data-priority="${priority}"`),
    );
  }
  for (const [feature, roadmapKey, priority] of [
    ["observer-isolation", "observer-isolation", "P0"],
    ["queued-work-progress", "queued-cross-cell-progress", "P0"],
    ["hotplug-contract", "hotplug-contract", "P0"],
    ["eevdf-shares", "eevdf-shares", "P0"],
    ["cgroup-identity", "identity-hardening", "P1"],
    ["scale-soak-rollback", "scale-soak-rollback", "P1"],
    ["browser-vm-ci", "browser-vm-ci", "P1"],
    ["inspector-scaling", "inspector-scaling", "P1"],
    ["typed-protocol", "typed-protocol", "P2"],
    ["numa-distance-order", "numa-distance-order", "P2"],
    ["pick-two", "pick-two", "P3"],
  ]) {
    const featureBlock = page.match(
      new RegExp(`<article[^>]+data-feature-key="${feature}"[\\s\\S]*?<\\/article>`),
    )?.[0] || "";
    assert.match(featureBlock, new RegExp(`data-priority="${priority}"`), `${feature} missing ${priority} sticker`);
    assert.match(
      reviewIndex,
      new RegExp("\\| `" + roadmapKey + "` \\|[^\\n]+\\| \\*\\*" + priority + "\\*\\* \\|"),
      `${feature} priority drifted from report key ${roadmapKey}`,
    );
    if (feature !== roadmapKey) {
      assert.match(featureBlock, new RegExp(`data-roadmap-key="${roadmapKey}"`));
    }
  }
});

test("roadmap distinguishes landed work from missing performance evidence", () => {
  const progress = page.match(
    /<section[^>]+id="roadmapProgress"[\s\S]*?<\/section>/,
  )?.[0] || "";
  assert.match(progress, /Managed lifecycle/);
  assert.match(progress, /cell-0 holdout/);
  assert.match(progress, /orphan draining, and sibling stealing/);
  assert.match(progress, /Pinned-latency and fairness evidence remains open/);
  assert.match(progress, /Sparse scale, browser, soak, and rollback evidence remains/);
});

test("roadmap exposes stable release-blocker and ordered milestone keys", () => {
  for (const blocker of [
    "eevdf-weighted-fairness",
    "queued-work-conservation",
    "hotplug-dynamic-owner-contract",
    "observer-isolation",
  ]) {
    assert.match(page, new RegExp(`data-blocker-key="${blocker}"`), blocker);
  }

  const milestones = [
    "correctness-gates",
    "cross-cell-backlog",
    "hotplug-contract",
    "identity-hardening",
    "scale-soak",
    "canary-rollback",
    "hardening",
  ];
  const positions = milestones.map((milestone) => {
    const occurrences = page.match(new RegExp(`data-milestone-key="${milestone}"`, "g")) || [];
    assert.equal(occurrences.length, 2, `${milestone} must label diagram and text equivalent`);
    return page.indexOf(`data-milestone-key="${milestone}"`);
  });
  assert.deepEqual([...positions].sort((left, right) => left - right), positions);
});

test("project pages use accessible static diagrams with canonical workspace links", () => {
  for (const diagram of [
    "inspector-data-flow",
    "operator-workflow",
    "mitosis-capability-coverage",
    "mitosis-implementation-path",
  ]) {
    const block = page.match(
      new RegExp(`<svg[^>]+data-diagram-key="${diagram}"[\\s\\S]*?<\\/svg>`),
    )?.[0] || "";
    assert.match(block, /role="group"/, `${diagram} interactive group role`);
    assert.match(block, /aria-labelledby="[^"]+"/, `${diagram} label`);
    assert.match(block, /<title[^>]*>[^<]+<\/title>/, `${diagram} title`);
    assert.match(block, /<desc[^>]*>[^<]+<\/desc>/, `${diagram} description`);
    assert.match(block, /<a href="#\/(?:overview|observe|configure|inspect|debugging)/, `${diagram} deep link`);
  }
  assert.match(page, /data-diagram-equivalent="inspector-data-flow"/);
  assert.match(page, /data-diagram-equivalent="operator-workflow"/);
  assert.match(page, /data-diagram-equivalent="mitosis-capability-coverage"/);
  assert.match(page, /data-diagram-equivalent="mitosis-implementation-path"/);
  assert.match(page, /Dashboard owns the joined state and rolling histories/);
  assert.doesNotMatch(page, /collector owns the joined snapshot/i);
});

test("feedback is a drawer with a visible draft count", () => {
  const drawer = page.match(/<dialog[^>]+id="feedbackDrawer"[\s\S]*?<\/dialog>/)?.[0] || "";
  assert.match(page, /<dialog[^>]+id="feedbackDrawer"/);
  assert.match(page, /id="feedbackCount"/);
  assert.match(page, /data-feedback-count/);
  assert.match(page, /id="closeFeedback"/);
  assert.match(script, /feedbackDrawer\.showModal\(\)/);
  assert.match(script, /feedbackEntries\.filter/);
  assert.match(script, /\.overview-section-heading/);
  assert.match(script, /policy-choice:\$\{escapeHtml\(selectedFairness\)\}:\$\{escapeHtml\(policy\.id\)\}:select/);
  assert.match(script, /warningSignature/);
  assert.doesNotMatch(drawer, /role="tab"/);
  assert.doesNotMatch(script, /data-feedback-tab/);
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

test("every inspector table opts into one accessible sorting contract", () => {
  const sources = `${page}\n${script}`;
  const tables = sources.match(/<table\b[^>]*>/g) || [];
  const sortableTables = tables.filter((table) => /\bdata-sort-key=/.test(table));

  assert.ok(tables.length >= 10, "expected the inspector's data-table surfaces");
  assert.equal(sortableTables.length, tables.length, "every table template must have a stable sort key");
  for (const key of [
    "callbacks:timing",
    "roadmap:mitosis-capabilities",
    "debugging:settings",
    "callbacks:fine:",
    "policy:slot-comparison",
    "queue:cell-allocation",
    "queue:normal-dsqs",
    "queue:cpu-routes",
    "cell:",
  ]) {
    assert.match(sources, new RegExp(`data-sort-key="[^"]*${key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`), key);
  }
  assert.match(script, /data-table-sort/);
  assert.match(script, /aria-sort/);
  assert.match(script, /enhanceSortableTables\(container\)/);
  assert.match(styles, /\.table-sort-button/);
});
