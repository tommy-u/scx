// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  callbackDurationClass,
  callbackSampleRateOptions,
  compactCpuList,
  decorateCells,
  fieldReferenceGroups,
  fineTimingCaptureModels,
  formatCallbackDuration,
  ladderPercentages,
  policyLibraryModels,
  queueTopologyModel,
  queueLadderSections,
  queueRungFlow,
  routeFromHash,
  schedulerControlModel,
  schedulerControlMessage,
  schedulerCommandPreview,
  schedulerLaunchRequest,
  schedulerSettingModels,
  statsResetDisabled,
  rungLadderPercentages,
  rungPercentages,
  selectionRungHitFlow,
  workloadAssignmentRequest,
} from "../../src/web/inspection.js";

test("inspection routes default to activity and accept every inspector view", () => {
  assert.equal(routeFromHash(""), "activity");
  assert.equal(routeFromHash("#/activity"), "activity");
  assert.equal(routeFromHash("#/policy"), "policy");
  assert.equal(routeFromHash("#/cells"), "cells");
  assert.equal(routeFromHash("#/callbacks"), "callbacks");
  assert.equal(routeFromHash("#/control"), "control");
  assert.equal(routeFromHash("#/unknown"), "activity");
});

test("scheduler launch requests include only checkbox-enabled optional flags", () => {
  assert.deepEqual(
    schedulerLaunchRequest({
      policy_id: "kernel-default-sim.toml",
      fairness_enabled: false,
      fairness: "vtime",
      callback_timing_sample_rate_enabled: true,
      callback_timing_sample_rate: "128",
      exit_dump_len_enabled: true,
      exit_dump_len: "4096",
      verbose: false,
    }),
    {
      policy_id: "kernel-default-sim.toml",
      callback_timing_sample_rate: 128,
      exit_dump_len: 4096,
      verbose: false,
    },
  );

  assert.deepEqual(
    schedulerLaunchRequest({
      policy_id: "cell-borrowing.toml",
      fairness_enabled: true,
      fairness: "vtime",
      callback_timing_sample_rate_enabled: false,
      callback_timing_sample_rate: "7",
      exit_dump_len_enabled: false,
      exit_dump_len: "-1",
      verbose: true,
    }),
    {
      policy_id: "cell-borrowing.toml",
      fairness: "vtime",
      verbose: true,
    },
  );
});

test("scheduler launch requests reject unsafe or unsupported values", () => {
  const base = {
    policy_id: "kernel-default-sim.toml",
    fairness_enabled: false,
    callback_timing_sample_rate_enabled: false,
    exit_dump_len_enabled: false,
    verbose: false,
  };
  assert.throws(() => schedulerLaunchRequest({ ...base, policy_id: "" }), /policy/i);
  assert.throws(
    () => schedulerLaunchRequest({ ...base, fairness_enabled: true, fairness: "eevdf" }),
    /FIFO or VTIME/,
  );
  assert.throws(
    () => schedulerLaunchRequest({
      ...base,
      callback_timing_sample_rate_enabled: true,
      callback_timing_sample_rate: "7",
    }),
    /power of two/,
  );
  assert.throws(
    () => schedulerLaunchRequest({
      ...base,
      exit_dump_len_enabled: true,
      exit_dump_len: "-1",
    }),
    /non-negative integer/,
  );
});

test("scheduler command preview shows required policy and selected flags", () => {
  assert.equal(
    schedulerCommandPreview({
      policy_id: "cell borrowing.toml",
      fairness: "vtime",
      callback_timing_sample_rate: 128,
      exit_dump_len: 4096,
      verbose: true,
    }),
    "scx_snake --policy 'cell borrowing.toml' --fairness vtime --callback-timing-sample-rate 128 --exit-dump-len 4096 --verbose",
  );
  assert.equal(
    schedulerCommandPreview({ policy_id: "kernel-default-sim.toml", verbose: false }),
    "scx_snake --policy kernel-default-sim.toml",
  );
  assert.equal(
    schedulerCommandPreview(
      { policy_id: "cell-borrowing.toml", fairness: "vtime", verbose: false },
      ["--stats", "1"],
    ),
    "scx_snake --policy cell-borrowing.toml --fairness vtime --stats 1",
  );
});

test("scheduler settings distinguish dynamic changes from reload requirements", () => {
  assert.deepEqual(
    schedulerSettingModels([
      { name: "callback_timing_sample_rate", value: 64, change_mode: "dynamic" },
      { name: "fairness", value: "fifo", change_mode: "reload" },
      { name: "stats_reset", value: "On demand", change_mode: "dynamic" },
    ]),
    [
      {
        name: "Callback sample rate",
        value: "64",
        changeMode: "dynamic",
        changeLabel: "Dynamic",
      },
      {
        name: "Fairness",
        value: "fifo",
        changeMode: "reload",
        changeLabel: "Reload required",
      },
      {
        name: "Stats reset",
        value: "On demand",
        changeMode: "dynamic",
        changeLabel: "Dynamic",
      },
    ],
  );
});

test("stats reset is available for managed and external active Snake", () => {
  assert.equal(statsResetDisabled({ active: true, managed: true }, false), false);
  assert.equal(
    statsResetDisabled({ active: true, managed: false, scheduler_name: "snake" }, false),
    false,
  );
  assert.equal(
    statsResetDisabled({ active: true, managed: false, scheduler_name: "snake_ops" }, false),
    false,
  );
  assert.equal(
    statsResetDisabled({ active: true, managed: false, scheduler_name: "scx_mitosis" }, false),
    true,
  );
  assert.equal(statsResetDisabled({ active: false, managed: true }, false), true);
  assert.equal(statsResetDisabled({ active: true, managed: true }, true), true);
});

test("managed spawn state is locked and cannot launch a duplicate scheduler", () => {
  assert.deepEqual(
    schedulerControlModel({ managed: true, active: false, controllable: true }, false, true),
    {
    stateName: "starting",
    stateLabel: "Managed / Starting",
    configLocked: true,
    startDisabled: true,
    stopDisabled: false,
    restartDisabled: true,
    },
  );
  assert.deepEqual(
    schedulerControlModel({ managed: false, active: true, controllable: true }, false, true),
    {
    stateName: "external",
    stateLabel: "External / Controllable",
    configLocked: false,
    startDisabled: true,
    stopDisabled: false,
    restartDisabled: false,
    },
  );
  assert.deepEqual(
    schedulerControlModel({ managed: false, active: true, controllable: false }, false, true),
    {
      stateName: "external",
      stateLabel: "External / Read-only",
      configLocked: true,
      startDisabled: true,
      stopDisabled: true,
      restartDisabled: true,
    },
  );
  assert.deepEqual(schedulerControlModel({ managed: false, active: false }, false, true), {
    stateName: "stopped",
    stateLabel: "Stopped",
    configLocked: false,
    startDisabled: false,
    stopDisabled: true,
    restartDisabled: true,
  });
});

test("scheduler control surfaces external ownership and managed launch exits", () => {
  assert.equal(
    schedulerControlMessage({
      active: true,
      managed: false,
      controllable: false,
      control_error: "multiple Snake processes match",
    }, null),
    "multiple Snake processes match",
  );
  assert.equal(
    schedulerControlMessage({ active: true, managed: false, controllable: true }, null),
    null,
  );
  assert.equal(
    schedulerControlMessage({ active: false, managed: false, last_exit: "exit code 1" }, null),
    "Last managed Snake exit: exit code 1",
  );
  assert.equal(
    schedulerControlMessage({ active: true, managed: false }, "Control unavailable"),
    "Control unavailable",
  );
});

test("control page exposes managed launch controls and settings table", () => {
  const page = readFileSync(
    new URL("../../src/web/index.html", import.meta.url),
    "utf8",
  );
  for (const control of [
    'href="#/control"',
    'id="controlView"',
    'id="schedulerPolicy"',
    'id="schedulerFairnessEnabled"',
    'id="schedulerFairness"',
    'id="schedulerSampleRateEnabled"',
    'id="schedulerSampleRate"',
    'id="schedulerExitDumpEnabled"',
    'id="schedulerExitDumpLen"',
    'id="schedulerVerbose"',
    'id="schedulerCommandPreview"',
    'id="startScheduler"',
    'id="restartScheduler"',
    'id="stopScheduler"',
    'id="resetAllStats"',
    'id="statsResetNotice"',
    'id="schedulerSettingsRows"',
  ]) {
    assert.match(page, new RegExp(control), `missing ${control}`);
  }
  assert.doesNotMatch(page, /value="eevdf"/i);
});

test("control client uses the scheduler lifecycle endpoints", () => {
  const script = readFileSync(
    new URL("../../src/web/app.js", import.meta.url),
    "utf8",
  );
  assert.match(script, /fetch\("\/api\/scheduler\/control"/);
  assert.match(script, /schedulerMutation\("\/api\/scheduler\/start"/);
  assert.match(script, /schedulerMutation\("\/api\/scheduler\/restart"/);
  assert.match(script, /schedulerMutation\("\/api\/scheduler\/stop"/);
  assert.match(script, /fetch\("\/api\/stats\/reset"/);
  assert.match(script, /confirm\("Reset all inspector and Snake statistics\?"\)/);
});

test("policy library separates dynamic, restart-required, and invalid choices", () => {
  const models = policyLibraryModels(
    {
      policies: [
        { id: "basic.toml", name: "Basic", source: "basic", summary: "One rung" },
        { id: "random.toml", name: "Random", source: "random", summary: "Two rungs" },
      ],
      invalid: [
        { id: "cell.toml", error: "restart Snake to apply it" },
        { id: "broken.toml", error: "missing rung" },
      ],
    },
    {
      active: true,
      policy_id: "basic.toml",
      policies: [
        { id: "basic.toml", name: "Basic", change_mode: "dynamic", reload_reasons: [] },
        { id: "random.toml", name: "Random", change_mode: "dynamic", reload_reasons: [] },
        {
          id: "cell.toml",
          name: "Cell",
          change_mode: "reload",
          reload_reasons: ["restart Snake to apply it"],
        },
        {
          id: "broken.toml",
          name: "Broken",
          change_mode: "invalid",
          reload_reasons: ["missing rung"],
        },
      ],
    },
  );

  assert.deepEqual(
    models.map(({ id, changeLabel, actionKind, actionLabel, disabled }) => ({
      id,
      changeLabel,
      actionKind,
      actionLabel,
      disabled,
    })),
    [
      {
        id: "basic.toml",
        changeLabel: "Dynamic",
        actionKind: "active",
        actionLabel: "Active",
        disabled: true,
      },
      {
        id: "random.toml",
        changeLabel: "Dynamic",
        actionKind: "activate",
        actionLabel: "Activate",
        disabled: false,
      },
      {
        id: "cell.toml",
        changeLabel: "Restart required",
        actionKind: "lifecycle",
        actionLabel: "Select for restart",
        disabled: false,
      },
      {
        id: "broken.toml",
        changeLabel: "Invalid",
        actionKind: "invalid",
        actionLabel: "Unavailable",
        disabled: true,
      },
    ],
  );
});

test("control layout has bounded launch fields and a responsive narrow mode", () => {
  const stylesheet = readFileSync(
    new URL("../../src/web/style.css", import.meta.url),
    "utf8",
  );
  assert.match(stylesheet, /\.scheduler-launch-grid\s*\{/);
  assert.match(stylesheet, /\.scheduler-flag-row\s*\{/);
  assert.match(stylesheet, /@media\s*\(max-width:\s*760px\)/);
});

test("callback durations consistently use nanoseconds", () => {
  assert.equal(formatCallbackDuration(null), "—");
  assert.equal(formatCallbackDuration(420), "420 ns");
  assert.equal(formatCallbackDuration(1_500), "1,500 ns");
  assert.equal(formatCallbackDuration(2_500_000), "2,500,000 ns");
  assert.equal(formatCallbackDuration(3_000_000_000), "3,000,000,000 ns");
});

test("callback sampling offers disabled and bounded power-of-two rates", () => {
  const options = callbackSampleRateOptions();
  assert.deepEqual(options[0], { value: 0, label: "Disabled" });
  assert.deepEqual(options[1], { value: 1, label: "Every callback" });
  assert.deepEqual(options.at(-1), { value: 4096, label: "1 / 4,096 callbacks" });
  assert.equal(options.length, 14);
});

test("callback durations over one thousand nanoseconds are warnings", () => {
  assert.equal(callbackDurationClass(null), "");
  assert.equal(callbackDurationClass(1_000), "");
  assert.equal(callbackDurationClass(1_001), "callback-duration-warning");
});

test("fine timing controls preserve independent collecting and historical states", () => {
  const captures = fineTimingCaptureModels({
    captures: [
      {
        callback: "select_cpu",
        state: "collecting",
        session_id: 3,
        available: true,
        unavailable_reason: null,
        stages: [],
      },
      {
        callback: "enqueue",
        state: "historical",
        session_id: 2,
        available: false,
        unavailable_reason: "Requires queue topology mode.",
        stages: [],
      },
      {
        callback: "dispatch",
        state: "inactive",
        session_id: null,
        available: false,
        unavailable_reason: "Requires queue topology mode.",
        stages: [],
      },
    ],
  });

  assert.deepEqual(
    captures.map(({
      callback,
      checked,
      stateLabel,
      available,
      unavailable_reason: unavailableReason,
      availabilityLabel,
      controlDisabled,
    }) => ({
      callback,
      checked,
      stateLabel,
      available,
      unavailableReason,
      availabilityLabel,
      controlDisabled,
    })),
    [
      {
        callback: "select_cpu",
        checked: true,
        stateLabel: "Collecting",
        available: true,
        unavailableReason: null,
        availabilityLabel: "Available",
        controlDisabled: false,
      },
      {
        callback: "enqueue",
        checked: false,
        stateLabel: "Historical",
        available: false,
        unavailableReason: "Requires queue topology mode.",
        availabilityLabel: "Unavailable",
        controlDisabled: true,
      },
      {
        callback: "dispatch",
        checked: false,
        stateLabel: "Inactive",
        available: false,
        unavailableReason: "Requires queue topology mode.",
        availabilityLabel: "Unavailable",
        controlDisabled: true,
      },
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

test("workload assignment requests distinguish TID, TGID, and cgroup targets", () => {
  assert.deepEqual(workloadAssignmentRequest("tid", "41", "2", false), {
    target: { kind: "tid", tid: 41 },
    cell_id: 2,
  });
  assert.deepEqual(workloadAssignmentRequest("tgid", "40", "7", false), {
    target: { kind: "tgid", tgid: 40 },
    cell_id: 7,
  });
  assert.deepEqual(workloadAssignmentRequest("cgroup", "/work.slice", "", true), {
    target: { kind: "cgroup", path: "/work.slice" },
    cell_id: null,
  });
  assert.throws(() => workloadAssignmentRequest("tid", "0", "2", false));
  assert.throws(() => workloadAssignmentRequest("cgroup", "", "2", false));
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
