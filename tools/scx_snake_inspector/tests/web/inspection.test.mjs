// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import * as inspectionState from "../../src/web/inspection.js";

import {
  callbackDurationClass,
  callbackSampleRateOptions,
  compactCpuList,
  decorateCells,
  fieldReferenceGroups,
  fineTimingCaptureModels,
  fineTimingDsqModels,
  formatCallbackDuration,
  ladderPercentages,
  nextPolicyCandidate,
  policyLibraryModels,
  policyInlineActionModel,
  queueTopologyModel,
  queueLadderSections,
  queueRungFlow,
  routeFromHash,
  schedulerControlModel,
  schedulerControlMessage,
  schedulerCommandPreview,
  schedulerCurrentLaunch,
  schedulerLaunchRequest,
  schedulerLifecycleRequest,
  schedulerUptimeLabel,
  schedulerSettingModels,
  statsResetDisabled,
  rungLadderPercentages,
  rungPercentages,
  rungTimingSummary,
  selectionRungHitFlow,
  workloadAssignmentRequest,
} from "../../src/web/inspection.js";

test("scheduler uptime labels tick from the latest control poll", () => {
  assert.equal(schedulerUptimeLabel(null, 10_000, 12_000), "—");
  assert.equal(schedulerUptimeLabel({ active: false }, 10_000, 12_000), "Stopped");
  assert.equal(
    schedulerUptimeLabel({ active: false, pid: 42, uptime_ms: 2_000 }, 10_000, 12_000),
    "Starting · 0:00:04",
  );
  assert.equal(schedulerUptimeLabel({ active: true }, 10_000, 12_000), "Unavailable");
  assert.equal(
    schedulerUptimeLabel({ active: true, uptime_ms: 3_661_000 }, 10_000, 12_500),
    "1:01:03",
  );
  assert.equal(
    schedulerUptimeLabel({ active: true, uptime_ms: 90_061_000 }, 10_000, 12_000),
    "1d 01:01:03",
  );
  assert.equal(
    schedulerUptimeLabel(
      { active: true, uptime_ms: 3_661_000 },
      10_000,
      15_000,
      "control request failed",
    ),
    "Stale · 1:01:01",
  );
  assert.equal(
    schedulerUptimeLabel({ active: false }, 10_000, 15_000, "control request failed"),
    "Stale · stopped",
  );
  assert.equal(
    schedulerUptimeLabel({ active: true }, 10_000, 15_000, "control request failed"),
    "Stale · unavailable",
  );
});

test("inspection routes default to overview and preserve legacy view aliases", () => {
  assert.equal(routeFromHash(""), "overview");
  assert.equal(routeFromHash("#/activity"), "observe/placement");
  assert.equal(routeFromHash("#/policy"), "inspect/policy-slots");
  assert.equal(routeFromHash("#/cells"), "inspect/cells");
  assert.equal(routeFromHash("#/callbacks"), "observe/callbacks");
  assert.equal(routeFromHash("#/control"), "configure");
  assert.equal(routeFromHash("#/feedback"), "overview");
  assert.equal(routeFromHash("#/unknown"), "overview");
});

test("table sort values handle natural text, formatted numbers, units, and missing data", () => {
  assert.equal(typeof inspectionState.tableSortValue, "function");
  assert.equal(typeof inspectionState.compareTableSortValues, "function");
  if (
    typeof inspectionState.tableSortValue !== "function"
    || typeof inspectionState.compareTableSortValues !== "function"
  ) {
    return;
  }

  assert.equal(inspectionState.tableSortValue("1,234/s", "number"), 1_234);
  assert.equal(inspectionState.tableSortValue("12.5%", "percentage"), 12.5);
  assert.equal(inspectionState.tableSortValue("1.5 ms", "duration"), 1_500_000);
  assert.equal(inspectionState.tableSortValue("900 µs", "duration"), 900_000);
  assert.equal(inspectionState.tableSortValue("0x10000000000000000", "bigint"), 0x10000000000000000n);
  assert.equal(inspectionState.tableSortValue("—", "number"), null);

  assert.equal(
    inspectionState.compareTableSortValues("CPU 2", "CPU 10", { type: "text" }),
    -1,
  );
  assert.equal(
    inspectionState.compareTableSortValues("900 µs", "1.5 ms", { type: "duration" }),
    -1,
  );
  assert.equal(
    inspectionState.compareTableSortValues("—", "10", {
      type: "number",
      direction: "ascending",
    }),
    1,
  );
  assert.equal(
    inspectionState.compareTableSortValues("—", "10", {
      type: "number",
      direction: "descending",
    }),
    1,
  );
});

test("table sorting toggles direction and keeps equal rows stable with missing rows last", () => {
  assert.equal(typeof inspectionState.nextTableSortState, "function");
  assert.equal(typeof inspectionState.stableSortTableRows, "function");
  if (
    typeof inspectionState.nextTableSortState !== "function"
    || typeof inspectionState.stableSortTableRows !== "function"
  ) {
    return;
  }

  const ascending = inspectionState.nextTableSortState(null, 2);
  assert.deepEqual(ascending, { column: 2, direction: "ascending" });
  assert.deepEqual(
    inspectionState.nextTableSortState(ascending, 2),
    { column: 2, direction: "descending" },
  );
  assert.deepEqual(
    inspectionState.nextTableSortState({ column: 2, direction: "descending" }, 1),
    { column: 1, direction: "ascending" },
  );

  const rows = inspectionState.stableSortTableRows([
    { id: "first-ten", value: "10", sourceOrder: 0 },
    { id: "missing", value: "—", sourceOrder: 1 },
    { id: "second-ten", value: "10", sourceOrder: 2 },
    { id: "two", value: "2", sourceOrder: 3 },
  ], { type: "number", direction: "descending" });
  assert.deepEqual(
    rows.map((row) => row.id),
    ["first-ten", "second-ten", "two", "missing"],
  );
});

test("runtime contexts match only within the same scheduler attachment and policy generation", () => {
  assert.equal(typeof inspectionState.contextsMatch, "function");
  if (typeof inspectionState.contextsMatch !== "function") {
    return;
  }

  const current = { scheduler_attach_seq: 24, policy_generation: 2 };
  assert.equal(inspectionState.contextsMatch(current, { ...current }), true);
  assert.equal(
    inspectionState.contextsMatch(current, {
      scheduler_attach_seq: 25,
      policy_generation: 2,
    }),
    false,
  );
  assert.equal(
    inspectionState.contextsMatch(current, {
      scheduler_attach_seq: 24,
      policy_generation: 3,
    }),
    false,
  );
  assert.equal(
    inspectionState.contextsMatch(current, {
      scheduler_attach_seq: 24,
      policy_generation: null,
    }),
    true,
  );
});

test("runtime context model distinguishes scheduler attachment from policy generation", () => {
  assert.equal(typeof inspectionState.runtimeContextModel, "function");
  if (typeof inspectionState.runtimeContextModel !== "function") {
    return;
  }

  const context = {
    scheduler_attach_seq: 24,
    scheduler_active: true,
    policy_generation: 2,
    active_slot: 1,
    fairness: "vtime",
    callback_sample_rate: 64,
  };
  assert.deepEqual(
    inspectionState.runtimeContextModel({
      snapshot: { context },
      inspection: { context },
      control: { context, policy_id: "cell-min-vtime.toml" },
    }),
    {
      synchronizing: false,
      statusLabel: "Snake active · Attach #24",
      detailLabel: "cell-min-vtime.toml · VTIME · policy gen 2 · rung set 1 · sampling 1/64",
    },
  );

  assert.equal(
    inspectionState.runtimeContextModel({
      snapshot: { context },
      inspection: {
        context: { ...context, policy_generation: 3 },
      },
      control: { context, policy_id: "cell-min-vtime.toml" },
    }).synchronizing,
    true,
  );
});

test("freshness model retains data but labels failed or overdue polling as stale", () => {
  assert.equal(typeof inspectionState.freshnessModel, "function");
  if (typeof inspectionState.freshnessModel !== "function") {
    return;
  }

  assert.deepEqual(
    inspectionState.freshnessModel({
      hasData: true,
      error: null,
      lastSuccessAt: 9_500,
      pollIntervalMs: 1_000,
      now: 10_000,
    }),
    { state: "fresh", label: "Updated just now", detail: null },
  );
  assert.deepEqual(
    inspectionState.freshnessModel({
      hasData: true,
      error: "request failed",
      lastSuccessAt: 8_000,
      pollIntervalMs: 1_000,
      now: 10_000,
    }),
    { state: "stale", label: "Stale · updated 2s ago", detail: "request failed" },
  );
  assert.equal(
    inspectionState.freshnessModel({
      hasData: true,
      error: null,
      lastSuccessAt: 7_000,
      pollIntervalMs: 1_000,
      now: 10_000,
    }).state,
    "stale",
  );
  assert.deepEqual(
    inspectionState.freshnessModel({
      hasData: false,
      error: "request failed",
      lastSuccessAt: 0,
      pollIntervalMs: 1_000,
      now: 10_000,
    }),
    { state: "unavailable", label: "Unavailable", detail: "request failed" },
  );
});

test("feedback entries keep first-entry order and one draft per element", () => {
  assert.equal(typeof inspectionState.updateFeedbackEntries, "function");
  if (typeof inspectionState.updateFeedbackEntries !== "function") {
    return;
  }

  let entries = inspectionState.updateFeedbackEntries(
    [],
    "Callbacks:Fine-grained-timing:Select-CPU",
    "Show the active stage more clearly.",
  );
  entries = inspectionState.updateFeedbackEntries(
    entries,
    "Policy:Rung-set-0",
    "Make the active rung set easier to scan.",
  );
  entries = inspectionState.updateFeedbackEntries(
    entries,
    "Callbacks:Fine-grained-timing:Select-CPU",
    "Show both active and historical stages.",
  );

  assert.deepEqual(entries, [
    {
      key: "Callbacks:Fine-grained-timing:Select-CPU",
      text: "Show both active and historical stages.",
    },
    { key: "Policy:Rung-set-0", text: "Make the active rung set easier to scan." },
  ]);
});

test("empty feedback removes the element draft", () => {
  assert.equal(typeof inspectionState.updateFeedbackEntries, "function");
  if (typeof inspectionState.updateFeedbackEntries !== "function") {
    return;
  }

  assert.deepEqual(
    inspectionState.updateFeedbackEntries(
      [{ key: "Activity:Controls", text: "Tighten spacing." }],
      "Activity:Controls",
      "  \n ",
    ),
    [],
  );
});

test("feedback transcript preserves multiline text and separates elements", () => {
  assert.equal(typeof inspectionState.formatFeedbackTranscript, "function");
  if (typeof inspectionState.formatFeedbackTranscript !== "function") {
    return;
  }

  assert.equal(
    inspectionState.formatFeedbackTranscript([
      {
        key: "Callbacks:Fine-grained-timing:Select-CPU",
        text: "First thought\nSecond thought",
      },
      { key: "Policy:Rung-set-0", text: "Another request" },
    ]),
    "[Callbacks:Fine-grained-timing:Select-CPU] First thought\nSecond thought\n\n"
      + "[Policy:Rung-set-0] Another request",
  );
});

test("feedback storage parser ignores malformed or duplicate entries", () => {
  assert.equal(typeof inspectionState.parseFeedbackEntries, "function");
  if (typeof inspectionState.parseFeedbackEntries !== "function") {
    return;
  }

  assert.deepEqual(inspectionState.parseFeedbackEntries("not json"), []);
  assert.deepEqual(
    inspectionState.parseFeedbackEntries(JSON.stringify([
      { key: "Activity:Controls", text: "First" },
      { key: "", text: "Missing key" },
      { key: "Activity:Controls", text: "Latest" },
      { key: "Cells:Cell-detail", text: "  " },
      null,
    ])),
    [{ key: "Activity:Controls", text: "Latest" }],
  );
});

test("scheduler launch requests validate the selected policy configuration", () => {
  assert.deepEqual(
    schedulerLaunchRequest({
      policy_id: "kernel-default-sim.toml",
      fairness: "vtime",
      callback_timing_sample_rate: "128",
      exit_dump_len_enabled: true,
      exit_dump_len: "4096",
      verbose: false,
    }),
    {
      policy_id: "kernel-default-sim.toml",
      fairness: "vtime",
      callback_timing_sample_rate: 128,
      exit_dump_len: 4096,
      verbose: false,
    },
  );

  assert.deepEqual(
    schedulerLaunchRequest({
      policy_id: "cell-borrowing.toml",
      fairness: "vtime",
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
    fairness: "vtime",
    exit_dump_len_enabled: false,
    verbose: false,
  };
  assert.throws(() => schedulerLaunchRequest({ ...base, policy_id: "" }), /policy/i);
  assert.throws(
    () => schedulerLaunchRequest({ ...base, fairness: "cfs" }),
    /FIFO, VTIME, or EEVDF/,
  );
  assert.throws(
    () => schedulerLaunchRequest({
      ...base,
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
      [
        "/opt/scx/bin/scx_snake",
        "--policy",
        "/etc/scx/snake/kernel-default-sim.toml",
        "--fairness",
        "fifo",
        "--stats",
        "1",
      ],
    ),
    "/opt/scx/bin/scx_snake --policy /etc/scx/snake/cell-borrowing.toml --fairness vtime --stats 1",
  );
  assert.deepEqual(
    schedulerLaunchRequest({
      policy_id: "basic.toml",
      fairness: "eevdf",
      verbose: false,
    }),
    { policy_id: "basic.toml", fairness: "eevdf", verbose: false },
  );
});

test("lifecycle requests preserve callback launch overrides without materializing defaults", () => {
  const active = {
    active: true,
    policy_id: "basic.toml",
    launch: { exit_dump_len: 0, verbose: false },
    settings: [
      { name: "fairness", effective: "vtime" },
      { name: "callback_timing_sample_rate", effective: 128 },
    ],
  };
  assert.deepEqual(schedulerCurrentLaunch(active), {
    policy_id: "basic.toml",
    fairness: "vtime",
    callback_timing_sample_rate: null,
    exit_dump_len: 0,
    verbose: false,
  });
  assert.deepEqual(
    schedulerLifecycleRequest(active, {
      policy_id: "cell.toml",
      fairness: "eevdf",
      exit_dump_len_enabled: false,
      verbose: true,
    }),
    {
      policy_id: "cell.toml",
      fairness: "eevdf",
      verbose: true,
    },
  );
  for (const sampleRate of [0, 64, 128]) {
    assert.equal(
      schedulerLifecycleRequest({
        ...active,
        launch: {
          ...active.launch,
          callback_timing_sample_rate: sampleRate,
        },
      }, {
        policy_id: "cell.toml",
        fairness: "vtime",
        exit_dump_len_enabled: false,
        verbose: false,
      }).callback_timing_sample_rate,
      sampleRate,
    );
  }
  assert.equal(
    inspectionState.launchDiff(
      schedulerCurrentLaunch(active),
      schedulerLifecycleRequest(active, {
        policy_id: "basic.toml",
        fairness: "vtime",
        exit_dump_len_enabled: true,
        exit_dump_len: 0,
        verbose: false,
      }),
    ).some((change) => change.name === "Callback sample rate"),
    false,
  );
  assert.equal(
    schedulerLifecycleRequest({ active: false }, {
      policy_id: "basic.toml",
      fairness: "fifo",
      exit_dump_len_enabled: false,
      verbose: false,
    }).callback_timing_sample_rate,
    undefined,
  );
});

test("scheduler settings separate effective runtime values from launch overrides", () => {
  assert.deepEqual(
    schedulerSettingModels([
      {
        name: "callback_timing_sample_rate",
        effective: 128,
        launch_override: 64,
        runtime_observed: true,
        change_mode: "dynamic",
      },
      {
        name: "fairness",
        effective: "vtime",
        launch_override: null,
        runtime_observed: true,
        change_mode: "reload",
      },
      {
        name: "stats_reset",
        effective: "On demand",
        launch_override: null,
        runtime_observed: false,
        change_mode: "dynamic",
      },
    ]),
    [
      {
        name: "Callback sample rate",
        effectiveValue: "1 / 128",
        overrideValue: "1 / 64",
        runtimeObserved: true,
        differs: true,
        changeMode: "dynamic",
        changeLabel: "Dynamic",
      },
      {
        name: "Fairness",
        effectiveValue: "VTIME",
        overrideValue: "Omitted; Snake default applies",
        runtimeObserved: true,
        differs: false,
        changeMode: "reload",
        changeLabel: "Reload required",
      },
      {
        name: "Stats reset",
        effectiveValue: "On demand",
        overrideValue: "—",
        runtimeObserved: false,
        differs: false,
        changeMode: "dynamic",
        changeLabel: "Dynamic",
      },
    ],
  );
});

test("scheduler control settings expose authoritative Snake defaults", () => {
  const source = readFileSync(
    new URL("../../src/api.rs", import.meta.url),
    "utf8",
  );
  assert.match(source, /default_value:\s*serde_json::Value/);
  assert.match(source, /name:\s*"fairness"[\s\S]*?default_value:[\s\S]*?LaunchFairness::Fifo/);
  assert.match(source, /name:\s*"callback_timing_sample_rate"[\s\S]*?default_value:[\s\S]*?64/);
  assert.match(source, /name:\s*"exit_dump_len"[\s\S]*?default_value:[\s\S]*?0/);
  assert.match(source, /name:\s*"verbose"[\s\S]*?default_value:[\s\S]*?false/);
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

test("configure workspace exposes policy selection, launch controls, and settings", () => {
  const page = readFileSync(
    new URL("../../src/web/index.html", import.meta.url),
    "utf8",
  );
  for (const control of [
    'href="#/configure"',
    'id="controlView"',
    'id="policyChoices"',
    'id="schedulerExitDumpEnabled"',
    'id="schedulerExitDumpLen"',
    'id="schedulerVerbose"',
    'id="schedulerCommandPreview"',
    'id="startScheduler"',
    'id="restartScheduler"',
    'id="stopScheduler"',
    'id="schedulerSettingsRows"',
  ]) {
    assert.match(page, new RegExp(control), `missing ${control}`);
  }
  assert.doesNotMatch(page, /id="schedulerPolicy"/);
  assert.match(page, /Launch argument overrides/);
  assert.doesNotMatch(page, /id="schedulerFairnessEnabled"|id="schedulerFairness"/);
  assert.doesNotMatch(page, /id="schedulerSampleRateEnabled"|id="schedulerSampleRate"/);
  assert.doesNotMatch(page, /Override fairness|Override callback sampling/);
  assert.match(page, /Effective now/);
  assert.match(page, /Launch override/);
});

test("global statistics reset is exposed by callback performance, not Configure", () => {
  const page = readFileSync(
    new URL("../../src/web/index.html", import.meta.url),
    "utf8",
  );
  const callbacks = page.slice(
    page.indexOf('id="callbacksView"'),
    page.indexOf('id="policyView"'),
  );
  const configure = page.slice(
    page.indexOf('id="controlView"'),
    page.indexOf('id="debuggingView"'),
  );

  assert.match(callbacks, /id="resetAllStats"[^>]*>Reset all statistics<\/button>/);
  assert.match(callbacks, /id="statsResetNotice"/);
  assert.doesNotMatch(configure, /id="resetAllStats"|id="statsResetNotice"/);
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
  assert.match(
    script,
    /confirm\("Reset all Snake and inspector statistics\? This clears placement, cell, callback, and queue histories and stops active captures\."\)/,
  );
});

test("scheduler mutation errors survive successful control polls", () => {
  const script = readFileSync(
    new URL("../../src/web/app.js", import.meta.url),
    "utf8",
  );

  assert.match(script, /schedulerMutationError:\s*null/);
  assert.match(
    script,
    /schedulerControlMessage\(\s*control,\s*state\.schedulerMutationError \|\| state\.schedulerControlError,?\s*\)/,
  );
  assert.match(script, /state\.schedulerMutationError = error\.message/);
});

test("callback reset supersedes an in-flight pre-reset timing request", () => {
  const script = readFileSync(
    new URL("../../src/web/app.js", import.meta.url),
    "utf8",
  );

  assert.match(script, /callbackTimingRequestId:\s*0/);
  assert.match(script, /async function loadCallbackTiming\(\{ force = false \} = \{\}\)/);
  assert.match(script, /const requestId = \+\+state\.callbackTimingRequestId/);
  assert.match(script, /requestId !== state\.callbackTimingRequestId/);
  assert.match(script, /state\.callbackTimingRequestId \+= 1/);
  assert.match(script, /loadCallbackTiming\(\{ force: true \}\)/);
});

test("the global runtime banner names attachment and policy generations unambiguously", () => {
  const page = readFileSync(
    new URL("../../src/web/index.html", import.meta.url),
    "utf8",
  );
  const script = readFileSync(
    new URL("../../src/web/app.js", import.meta.url),
    "utf8",
  );
  assert.match(page, /id="runtimeContextDetail"/);
  assert.match(script, /runtimeContextModel\(/);
  assert.doesNotMatch(script, /Snake active \| generation/);
});

test("poll failures retain the last successful callback and inspection payloads", () => {
  const script = readFileSync(
    new URL("../../src/web/app.js", import.meta.url),
    "utf8",
  );
  assert.doesNotMatch(script, /catch \(error\) \{\s*state\.callbackTiming = null;/);
  assert.doesNotMatch(script, /catch \(error\) \{\s*state\.inspection = null;/);
  assert.match(script, /freshnessModel\(/);
});

test("policy library separates dynamic, restart-required, and invalid choices", () => {
  const models = policyLibraryModels(
    {
      policies: [
        { id: "basic.toml", name: "Basic", source: "basic", summary: "One rung" },
        { id: "random.toml", name: "Random", source: "random", summary: "Two rungs" },
      ],
      invalid: [
        {
          id: "cell.toml",
          name: "Cell",
          source: "[queues]\nlayout = \"cell\"",
          error: "restart Snake to apply it",
        },
        {
          id: "broken.toml",
          name: "Broken",
          source: "not policy toml",
          error: "missing rung",
        },
      ],
    },
    {
      active: true,
      policy_id: "basic.toml",
      context: { fairness: "fifo" },
      policies: [
        {
          id: "basic.toml",
          name: "Basic",
          apply_mode: "live",
          reasons: [],
          supported_fairness: ["fifo", "vtime", "eevdf"],
        },
        {
          id: "random.toml",
          name: "Random",
          apply_mode: "live",
          reasons: [],
          supported_fairness: ["fifo", "vtime", "eevdf"],
        },
        {
          id: "cell.toml",
          name: "Cell",
          apply_mode: "restart",
          reasons: [
            {
              code: "dsq_topology",
              label: "DSQ topology changes",
              detail: "candidate changes the attachment-time queue topology",
            },
            {
              code: "task_membership",
              label: "Task membership changes",
              detail: "candidate changes attachment-time task membership",
            },
          ],
          supported_fairness: ["vtime"],
        },
        {
          id: "broken.toml",
          name: "Broken",
          apply_mode: "invalid",
          reasons: [{ code: "validation_failed", label: "Policy validation failed", detail: "missing rung" }],
          supported_fairness: ["fifo", "vtime", "eevdf"],
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
        changeLabel: "Applies live",
        actionKind: "activate",
        actionLabel: "Apply live",
        disabled: false,
      },
      {
        id: "cell.toml",
        changeLabel: "Restart required",
        actionKind: "lifecycle",
        actionLabel: "Restart Snake",
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

  const invalid = models.find((model) => model.id === "broken.toml");
  assert.equal(invalid.summary, null);
  assert.equal(invalid.reasons[0].detail, "missing rung");
  const restartRequired = models.find((model) => model.id === "cell.toml");
  assert.equal(restartRequired.summary, null);
  assert.deepEqual(restartRequired.reasons.map((reason) => reason.code), [
    "dsq_topology",
    "task_membership",
  ]);
});

test("policy review populates lifecycle state and exposes restart for every valid policy", () => {
  const current = {
    policyId: "random.toml",
    fairness: "fifo",
    actionKind: "activate",
  };
  const live = {
    id: "random.toml",
    selectedFairness: "fifo",
    actionKind: "activate",
    actionLabel: "Apply live",
    disabled: false,
  };

  const control = { active: true, controllable: true };
  assert.deepEqual(policyInlineActionModel(live, current, false, control), {
    expanded: true,
    liveVisible: true,
    liveLabel: "Apply live",
    liveDisabled: false,
    lifecycleVisible: true,
    lifecycleLabel: "Apply Restart",
    lifecycleDisabled: false,
  });
  assert.equal(policyInlineActionModel({ ...live, id: "basic.toml" }, current, false, control).expanded, false);
  assert.deepEqual(
    policyInlineActionModel({ ...live, actionKind: "lifecycle" }, current, false, control),
    {
      expanded: true,
      liveVisible: false,
      liveLabel: "Apply live",
      liveDisabled: true,
      lifecycleVisible: true,
      lifecycleLabel: "Apply Restart",
      lifecycleDisabled: false,
    },
  );

  assert.deepEqual(inspectionState.policyReviewSelection(null, current), {
    candidate: current,
    lifecyclePolicyId: "random.toml",
    lifecycleFairness: "fifo",
  });

  const replacement = {
    policyId: "basic.toml",
    fairness: "fifo",
    actionKind: "activate",
  };
  assert.deepEqual(nextPolicyCandidate(current, replacement), replacement);
  assert.equal(nextPolicyCandidate(current, { ...current }), null);
  const lifecycle = { ...current, actionKind: "lifecycle" };
  assert.equal(nextPolicyCandidate(lifecycle, { ...lifecycle }), null);
});

test("live policy selection renders one inline Apply live panel", () => {
  const script = readFileSync(
    new URL("../../src/web/app.js", import.meta.url),
    "utf8",
  );
  const stylesheet = readFileSync(
    new URL("../../src/web/style.css", import.meta.url),
    "utf8",
  );

  assert.match(script, /class="policy-live-action-panel"/);
  assert.match(script, /data-policy-live-apply/);
  assert.match(script, /data-policy-restart-apply/);
  assert.match(script, /openPolicyDialog\(liveApply\.dataset\.policyLiveApply\)/);
  assert.match(script, /policyReviewSelection\(state\.policyCandidate, nextCandidate\)/);
  assert.match(script, /candidate\.id === state\.policyCandidate\.policyId/);
  assert.match(stylesheet, /\.policy-live-action-panel\s*\{/);
});

test("restart actions do not depend on native confirmation and consume returned control state", () => {
  const script = readFileSync(
    new URL("../../src/web/app.js", import.meta.url),
    "utf8",
  );
  const restartBody = script.match(/async function restartScheduler\(\) \{[\s\S]*?\n\}/)?.[0] || "";

  assert.doesNotMatch(restartBody, /window\.confirm/);
  assert.match(script, /state\.schedulerControl = body/);
});

test("policy library resolves at most one active policy when sources are duplicated", () => {
  const catalog = {
    policies: [
      { id: "copy-a.toml", name: "Copy A", source: "same source", summary: "One rung" },
      { id: "copy-b.toml", name: "Copy B", source: "same source", summary: "One rung" },
    ],
    invalid: [],
  };
  const policies = [
    { id: "copy-a.toml", name: "Copy A", change_mode: "dynamic", reload_reasons: [] },
    { id: "copy-b.toml", name: "Copy B", change_mode: "dynamic", reload_reasons: [] },
  ];

  const authoritative = policyLibraryModels(
    { ...catalog },
    { active: true, policy_id: "copy-b.toml", launch: { fairness: "fifo" }, policies },
    "same source",
    "fifo",
  ).filter((policy) => policy.active);
  assert.deepEqual(authoritative.map((policy) => policy.id), ["copy-b.toml"]);

  const ambiguousFallback = policyLibraryModels(
    { ...catalog },
    { active: true, policy_id: null, launch: { fairness: "fifo" }, policies },
    "same source",
    "fifo",
  ).filter((policy) => policy.active);
  assert.deepEqual(ambiguousFallback, []);
});

test("policy library filters policies beneath the selected fairness approach", () => {
  const catalog = {
    policies: [
      {
        id: "placement.toml",
        name: "Placement",
        source: "[[rung]]\noperation = \"pick_idle\"",
        summary: "Placement only",
      },
    ],
    invalid: [
      {
        id: "cell-queues.toml",
        name: "Cell queues",
        source: "[queues]\nlayout = \"cell\"",
        error: "restart Snake to apply it",
      },
    ],
  };
  const control = {
    active: true,
    policy_id: "placement.toml",
    launch: { fairness: "fifo" },
    policies: [
      {
        id: "placement.toml",
        name: "Placement",
        apply_mode: "live",
        reasons: [],
        supported_fairness: ["fifo", "vtime", "eevdf"],
      },
      {
        id: "cell-queues.toml",
        name: "Cell queues",
        apply_mode: "restart",
        reasons: [{ code: "dsq_topology", label: "DSQ topology changes", detail: "restart required" }],
        supported_fairness: ["vtime"],
      },
    ],
  };

  assert.deepEqual(
    policyLibraryModels(catalog, control, null, "fifo").map((policy) => policy.id),
    ["placement.toml"],
  );
  assert.deepEqual(
    policyLibraryModels(catalog, control, null, "eevdf").map((policy) => policy.id),
    ["placement.toml"],
  );
  assert.deepEqual(
    policyLibraryModels(catalog, control, null, "vtime").map((policy) => policy.id),
    ["placement.toml", "cell-queues.toml"],
  );
  assert.equal(
    policyLibraryModels(catalog, control, null, "eevdf")[0].actionLabel,
    "Restart Snake",
  );
  assert.deepEqual(
    policyLibraryModels(catalog, control, null, "eevdf")[0].reasons[0],
    {
      code: "fairness_change",
      label: "Fairness changes",
      detail: "Fairness approach changes from FIFO to EEVDF.",
    },
  );
});

test("launch diff reports only current-versus-proposed changes", () => {
  assert.equal(typeof inspectionState.launchDiff, "function");
  if (typeof inspectionState.launchDiff !== "function") {
    return;
  }
  assert.deepEqual(
    inspectionState.launchDiff(
      {
        policy_id: "basic.toml",
        fairness: "fifo",
        callback_timing_sample_rate: 64,
        verbose: false,
      },
      {
        policy_id: "cell.toml",
        fairness: "vtime",
        callback_timing_sample_rate: 64,
        verbose: false,
      },
    ),
    [
      { name: "Policy", before: "basic.toml", after: "cell.toml" },
      { name: "Fairness", before: "fifo", after: "vtime" },
    ],
  );
});

test("Policy exposes a tuning context strip and accessible change reasons", () => {
  const page = readFileSync(
    new URL("../../src/web/index.html", import.meta.url),
    "utf8",
  );
  const script = readFileSync(
    new URL("../../src/web/app.js", import.meta.url),
    "utf8",
  );
  assert.match(page, /id="policyContextBar"/);
  assert.match(page, /id="policyActiveContext"/);
  assert.match(page, /id="policyCandidateContext"/);
  assert.match(page, /id="policyCandidateImpact"/);
  assert.doesNotMatch(page, /id="policyCandidateAction"/);
  assert.match(script, /policy-reason-details/);
  assert.match(script, /data-render-key="policy-choice:/);
  assert.doesNotMatch(script, /policy\.hoverDetail \? `title=/);
});

test("policy rung comparison distinguishes active and previous structural state", () => {
  assert.equal(typeof inspectionState.policySlotComparison, "function");
  if (typeof inspectionState.policySlotComparison !== "function") {
    return;
  }
  const comparison = inspectionState.policySlotComparison([
    {
      slot: 0,
      state: "inactive",
      generation: 4,
      policy: {
        rungs: [{ operation: "pick_idle" }],
        fallback: { selected: { label: "Previous CPU" } },
        mask_tables: [],
        queues: null,
      },
    },
    {
      slot: 1,
      state: "active",
      generation: 5,
      policy: {
        rungs: [{ operation: "pick_idle" }, { operation: "pick_any" }],
        fallback: { selected: { label: "Any allowed CPU" } },
        mask_tables: [{ id: 0 }],
        queues: {
          layout: "cell",
          enqueue: [{ operation: "cell" }],
          dispatch: [{ operation: "min_vtime(cell,affinity)" }],
        },
      },
    },
  ]);

  assert.equal(comparison.activeLabel, "Active · rung set 1");
  assert.equal(comparison.previousLabel, "Previous · rung set 0");
  assert.deepEqual(
    comparison.rows.filter((row) => row.changed).map((row) => row.name),
    ["Generation", "Idle rungs", "Fallback", "Mask tables", "Queue layout", "Enqueue ladder", "Dispatch ladder"],
  );
  assert.equal(comparison.rows.find((row) => row.name === "Queue layout").previous, "Not configured");
});

test("policy library renders fairness parents and stacks status over actions", () => {
  const script = readFileSync(
    new URL("../../src/web/app.js", import.meta.url),
    "utf8",
  );
  const stylesheet = readFileSync(
    new URL("../../src/web/style.css", import.meta.url),
    "utf8",
  );

  assert.match(script, /data-policy-fairness=/);
  assert.match(script, /option\.active \? " active"/);
  assert.match(script, /class="policy-reason-details"/);
  assert.match(script, /class="policy-choice-actions"/);
  assert.match(stylesheet, /\.policy-fairness-options\s*\{/);
  assert.match(stylesheet, /\.policy-fairness-option\.active\s*\{/);
  assert.match(stylesheet, /\.policy-choice-actions\s*\{/);
});

test("policy library reserves green cards for active policies and blue for Applies live", () => {
  const script = readFileSync(
    new URL("../../src/web/app.js", import.meta.url),
    "utf8",
  );
  const stylesheet = readFileSync(
    new URL("../../src/web/style.css", import.meta.url),
    "utf8",
  );

  assert.match(
    script,
    /policy\.changeMode === "dynamic"\s*&& !policy\.active\s*\? " applies-live"/,
  );
  assert.match(
    stylesheet,
    /\.policy-choice\.active\s*\{[^}]*background:\s*#e4f5ef;/s,
  );
  assert.match(stylesheet, /\.policy-choice\.active\.selected\s*\{/);
  assert.match(
    stylesheet,
    /\.change-mode\.applies-live\s*\{[^}]*background:\s*#e0eff8;[^}]*border-color:\s*#6b9dbc;/s,
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

test("fine timing DSQ operations merge insert and removal outcomes by queue", () => {
  const timing = (samples, meanNs, p99Ns) => ({
    samples,
    mean_ns: meanNs,
    p50_ns: meanNs,
    p95_ns: p99Ns,
    p99_ns: p99Ns,
  });
  const dsqs = fineTimingDsqModels({
    captures: [
      {
        callback: "enqueue",
        dsq_operations: [{
          dsq_id: 805306368,
          operation: "insert",
          outcome: "success",
          ...timing(100, 800, 2047),
        }],
      },
      {
        callback: "dispatch",
        dsq_operations: [
          {
            dsq_id: 805306368,
            operation: "remove",
            outcome: "success",
            ...timing(20, 12_000, 32_767),
          },
          {
            dsq_id: 805306368,
            operation: "remove",
            outcome: "miss",
            ...timing(200, 300, 511),
          },
        ],
      },
    ],
  });

  assert.equal(dsqs.length, 1);
  assert.equal(dsqs[0].dsqId, "805306368");
  assert.equal(dsqs[0].label, "0x30000000");
  assert.equal(dsqs[0].kind, "FIFO global");
  assert.equal(dsqs[0].insertSuccess.samples, 100);
  assert.equal(dsqs[0].moveSuccess.p99Ns, 32_767);
  assert.equal(dsqs[0].moveMiss.samples, 200);
  assert.equal(dsqs[0].moveMiss.meanNs, 300);
});

test("fine timing DSQ operations preserve and classify per-CPU local DSQ IDs", () => {
  const localCpu7 = "13835058055282163719";
  const dsqs = fineTimingDsqModels({
    captures: [{
      callback: "dispatch",
      dsq_operations: [{
        dsq_id: localCpu7,
        operation: "insert",
        outcome: "success",
        samples: 100,
        mean_ns: 800,
        p50_ns: 511,
        p95_ns: 2047,
        p99_ns: 4095,
      }],
    }],
  });

  assert.equal(dsqs.length, 1);
  assert.equal(dsqs[0].dsqId, localCpu7);
  assert.equal(dsqs[0].label, "0xc000000000000007");
  assert.equal(dsqs[0].kind, "Local CPU 7");
  assert.equal(dsqs[0].insertSuccess.samples, 100);
});

test("fine timing DSQ operations exclude historical policy generations", () => {
  const dsqs = fineTimingDsqModels({
    context: { policy_generation: 9 },
    captures: [{
      callback: "dispatch",
      policy_generation: 8,
      dsq_operations: [{
        dsq_id: 805306368,
        operation: "remove",
        outcome: "miss",
        samples: 100,
        mean_ns: 200,
      }],
    }],
  });

  assert.deepEqual(dsqs, []);
});

test("callback page contains the fine timing panel host", () => {
  const page = readFileSync(
    new URL("../../src/web/index.html", import.meta.url),
    "utf8",
  );
  assert.match(page, /id="fineTimingPanels"/);
  assert.match(page, /id="fineTimingNotice"/);
  assert.match(page, /id="callbackThresholdLegend"/);
  assert.match(page, /1,000 ns/);
  const script = readFileSync(
    new URL("../../src/web/app.js", import.meta.url),
    "utf8",
  );
  assert.match(script, /capture\.started_at_ms/);
  assert.match(script, /capture\.stopped_at_ms/);
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

test("rung timing reports sampled p95 only after twenty samples", () => {
  const buckets = Array(64).fill(0);
  buckets[4] = 19;
  buckets[7] = 1;
  assert.deepEqual(rungTimingSummary({ total_ns: 500, buckets }), {
    samples: 20,
    meanNs: 25,
    p95Ns: 31,
  });

  buckets[4] = 18;
  assert.deepEqual(rungTimingSummary({ total_ns: 475, buckets }), {
    samples: 19,
    meanNs: 25,
    p95Ns: null,
  });
});

test("policy rung rows render sampled p95 and sample count for every ladder", () => {
  const script = readFileSync(
    new URL("../../src/web/app.js", import.meta.url),
    "utf8",
  );
  assert.match(script, /<dt>Sampled p95<\/dt>/);
  assert.match(script, /timing\.samples/);
  assert.match(script, /queue.*timing|timing.*queue/is);
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
  assert.equal(typeof inspectionState.cellQueueFacts, "function");
  assert.deepEqual(inspectionState.cellQueueFacts(model, 7), {
    configured: true,
    primaryCpus: [1],
    borrowableCpus: [0],
    clock: "cell:1",
    weight: 2,
    normalDsqs: [],
  });
});

test("CPU masks are compacted into readable ranges", () => {
  assert.equal(compactCpuList([]), "None");
  assert.equal(compactCpuList([0, 1, 2, 4, 6, 7]), "0-2, 4, 6-7");
});

test("keyed render state restores disclosure, scrolling, and focus only for matching keys", () => {
  assert.equal(typeof inspectionState.captureKeyedRenderState, "function");
  assert.equal(typeof inspectionState.restoreKeyedRenderState, "function");
  if (
    typeof inspectionState.captureKeyedRenderState !== "function"
    || typeof inspectionState.restoreKeyedRenderState !== "function"
  ) {
    return;
  }

  const keyed = (key, values = {}) => ({
    dataset: { renderKey: key },
    open: values.open,
    scrollTop: values.scrollTop ?? 0,
    scrollLeft: values.scrollLeft ?? 0,
    focusCalls: 0,
    focus() {
      this.focusCalls += 1;
    },
  });
  const oldDetails = keyed("policy-slot:0:generation:7", { open: true });
  const oldSummary = keyed("policy-slot:0:generation:7:summary");
  const oldScroller = keyed("queue:7:cpu-routes:scroll", {
    scrollTop: 42,
    scrollLeft: 17,
  });
  const snapshot = inspectionState.captureKeyedRenderState(
    [oldDetails, oldSummary, oldScroller],
    oldSummary,
  );

  const newDetails = keyed("policy-slot:0:generation:7", { open: false });
  const newSummary = keyed("policy-slot:0:generation:7:summary");
  const newScroller = keyed("queue:7:cpu-routes:scroll");
  const changedGeneration = keyed("policy-slot:0:generation:8", { open: false });
  inspectionState.restoreKeyedRenderState(
    [newDetails, newSummary, newScroller, changedGeneration],
    snapshot,
  );

  assert.equal(newDetails.open, true);
  assert.equal(newScroller.scrollTop, 42);
  assert.equal(newScroller.scrollLeft, 17);
  assert.equal(newSummary.focusCalls, 1);
  assert.equal(changedGeneration.open, false);
});

test("keyed render state restores textarea selection after polling replacement", () => {
  const oldTextarea = {
    dataset: { renderKey: "feedback:Policy:Rung-set-0:textarea" },
    scrollTop: 18,
    scrollLeft: 0,
    selectionStart: 6,
    selectionEnd: 12,
    selectionDirection: "forward",
  };
  const snapshot = inspectionState.captureKeyedRenderState([oldTextarea], oldTextarea);
  const newTextarea = {
    dataset: { renderKey: "feedback:Policy:Rung-set-0:textarea" },
    scrollTop: 0,
    scrollLeft: 0,
    selectionStart: 0,
    selectionEnd: 0,
    selectionDirection: "none",
    focusCalls: 0,
    focus() {
      this.focusCalls += 1;
    },
    setSelectionRange(start, end, direction) {
      this.selectionStart = start;
      this.selectionEnd = end;
      this.selectionDirection = direction;
    },
  };

  inspectionState.restoreKeyedRenderState([newTextarea], snapshot);

  assert.equal(newTextarea.focusCalls, 1);
  assert.equal(newTextarea.selectionStart, 6);
  assert.equal(newTextarea.selectionEnd, 12);
  assert.equal(newTextarea.selectionDirection, "forward");
  assert.equal(newTextarea.scrollTop, 18);
});

test("callback sample-rate synchronization preserves drafts and accepts pristine server updates", () => {
  assert.equal(typeof inspectionState.syncCallbackSampleRateControl, "function");
  if (typeof inspectionState.syncCallbackSampleRateControl !== "function") {
    return;
  }

  const control = { value: "128" };
  assert.equal(
    inspectionState.syncCallbackSampleRateControl(control, 64, {
      dirty: true,
      pending: false,
      activeElement: null,
    }),
    false,
  );
  assert.equal(control.value, "128");
  assert.equal(
    inspectionState.syncCallbackSampleRateControl(control, 64, {
      dirty: false,
      pending: false,
      activeElement: control,
    }),
    false,
  );
  assert.equal(
    inspectionState.syncCallbackSampleRateControl(control, 64, {
      dirty: false,
      pending: true,
      activeElement: null,
    }),
    false,
  );
  assert.equal(
    inspectionState.syncCallbackSampleRateControl(control, 64, {
      dirty: false,
      pending: false,
      activeElement: null,
    }),
    true,
  );
  assert.equal(control.value, "64");
  assert.equal(
    inspectionState.syncCallbackSampleRateControl(control, 64, {
      dirty: false,
      pending: false,
      activeElement: null,
    }),
    false,
  );
});

test("polling renderers use stable keys and avoid synchronous hidden-popover rerenders", () => {
  const script = readFileSync(
    new URL("../../src/web/app.js", import.meta.url),
    "utf8",
  );

  for (const keyFragment of [
    "policy-slot:",
    "generation:",
    ":normal-dsqs",
    ":cpu-routes",
    "cell:${cellId}:task:${task.tid}",
  ]) {
    assert.match(script, new RegExp(keyFragment.replaceAll("$", "\\$")));
  }
  assert.match(script, /function replaceKeyedHtml\(/);
  assert.match(script, /requestAnimationFrame\(\(\) =>/);
  assert.match(script, /referencePopover\.classList\.contains\("hidden"\)/);
  assert.match(script, /callbackRateDirty/);
});

test("feedback drawer exposes copy and global clear controls", () => {
  const page = readFileSync(
    new URL("../../src/web/index.html", import.meta.url),
    "utf8",
  );

  for (const fragment of [
    'id="openFeedback"',
    'id="feedbackDrawer"',
    'id="feedbackTranscript"',
    'id="copyFeedback"',
    'id="clearFeedback"',
    'id="feedbackNotice"',
  ]) {
    assert.match(page, new RegExp(fragment), `missing ${fragment}`);
  }
  assert.match(page, /id="feedbackTranscript"[^>]*readonly/);
});

test("every planned feedback target has a stable semantic key", () => {
  const page = readFileSync(
    new URL("../../src/web/index.html", import.meta.url),
    "utf8",
  );
  const script = readFileSync(
    new URL("../../src/web/app.js", import.meta.url),
    "utf8",
  );
  const source = `${page}\n${script}`;
  for (const key of [
    "Activity:Controls",
    "Activity:Migration-summary",
    "Activity:CPU-migration-matrix",
    "Callbacks:Timing-controls",
    "Callbacks:Timing-summary",
    "Callbacks:Callback-percentiles",
    "Callbacks:Fine-grained-timing:",
    "Policy:Policy-library",
    "Policy:Rung-set-",
    "Policy:Resolved-queue-topology",
    "Cells:Workload-assignment",
    "Cells:Cell-browser",
    "Cells:Cell-detail",
    "Control:Launch-configuration",
    "Control:Command-preview",
    "Control:Change-behavior",
  ]) {
    assert.match(source, new RegExp(key), `missing feedback target ${key}`);
  }
});

test("feedback client mirrors inline edits and can copy or clear the whole batch", () => {
  const script = readFileSync(
    new URL("../../src/web/app.js", import.meta.url),
    "utf8",
  );

  assert.match(script, /scx-snake-inspector-feedback-v1/);
  assert.match(script, /sessionStorage/);
  assert.match(script, /expandedFeedbackKeys/);
  assert.match(script, /closest\("\[data-feedback-toggle\]"\)/);
  assert.match(script, /closest\("\[data-feedback-input\]"\)/);
  assert.match(script, /navigator\.clipboard\.writeText/);
  assert.match(script, /document\.execCommand\("copy"\)/);
  assert.match(script, /data-lucide="ear"/);
  assert.match(script, /confirm\("Clear all collected feedback\?"\)/);
});

test("policy choices are separated into production, demo, and component groups", () => {
  assert.equal(typeof inspectionState.policyCategoryGroups, "function");
  const groups = inspectionState.policyCategoryGroups([
    { id: "basic.toml", active: true },
    { id: "cell-borrowing.toml" },
    { id: "cell-llc-queues.toml" },
    { id: "cell-min-vtime.toml" },
    { id: "cell-queues.toml" },
    { id: "kernel-default-sim.toml" },
    { id: "kernel-default.toml" },
    { id: "llc-half-random.toml" },
    { id: "llc-half.toml" },
    { id: "llc-random.toml" },
    { id: "llc-whole-core-random.toml" },
    { id: "llc-whole-core.toml" },
    { id: "llc.toml" },
    { id: "previous-only.toml" },
    { id: "random-idle.toml" },
  ]);

  assert.deepEqual(
    groups.map((group) => [
      group.id,
      group.defaultOpen,
      group.policies.map((policy) => policy.id),
    ]),
    [
      ["production", true, ["kernel-default-sim.toml", "kernel-default.toml"]],
      ["demo", false, [
        "llc-half-random.toml",
        "llc-random.toml",
        "llc-whole-core-random.toml",
        "random-idle.toml",
      ]],
      ["components", true, [
        "basic.toml",
        "cell-borrowing.toml",
        "cell-llc-queues.toml",
        "cell-min-vtime.toml",
        "cell-queues.toml",
        "llc-half.toml",
        "llc-whole-core.toml",
        "llc.toml",
        "previous-only.toml",
      ]],
    ],
  );
});

test("random names are demos and unknown non-random policies are components", () => {
  const groups = inspectionState.policyCategoryGroups([
    { id: "kernel-default-random.toml" },
    { id: "new-random-experiment.toml", active: true },
    { id: "new-placement.toml" },
  ]);

  assert.deepEqual(
    groups.map((group) => [
      group.id,
      group.defaultOpen,
      group.policies.map((policy) => policy.id),
    ]),
    [
      ["production", true, []],
      ["demo", true, ["kernel-default-random.toml", "new-random-experiment.toml"]],
      ["components", false, ["new-placement.toml"]],
    ],
  );
});

test("policy category sections use native disclosures with stable render keys", () => {
  const script = readFileSync(
    new URL("../../src/web/app.js", import.meta.url),
    "utf8",
  );
  const stylesheet = readFileSync(
    new URL("../../src/web/style.css", import.meta.url),
    "utf8",
  );

  assert.match(script, /<details class="policy-category-section"/);
  assert.match(script, /group\.defaultOpen \? " open" : ""/);
  assert.match(script, /data-render-key="policy-category:/);
  assert.match(script, /<summary[^>]*><h5>/);
  assert.match(stylesheet, /\.policy-category-section\s*>\s*summary\s*\{/);
});

test("resolved routing retains and sorts every online CPU route", () => {
  const routes = Array.from({ length: 32 }, (_, cpu) => ({
    cpu: 31 - cpu,
    owner_cell_id: 0,
    owner_cell_index: 0,
    llc_id: 0,
    normal_queue_index: 0,
    normal_dsq_id: 536870912,
    affinity_dsq_id: 268435456 + cpu,
  }));
  const onlineCpus = Array.from({ length: 32 }, (_, cpu) => cpu);
  const complete = queueTopologyModel(
    { mode_name: "vtime" },
    { layout: "cell", affinity_queue_count: 32, cpu_routes: routes },
    onlineCpus,
  );

  assert.equal(complete.cpuRoutes.length, 32);
  assert.equal(complete.cpuRoutes[0].cpu, 0);
  assert.equal(complete.cpuRoutes.at(-1).cpu, 31);
  assert.equal(complete.expectedCpuCount, 32);
  assert.equal(complete.routesComplete, true);

  const incomplete = queueTopologyModel(
    { mode_name: "vtime" },
    { layout: "cell", affinity_queue_count: 32, cpu_routes: routes },
    [...onlineCpus, 32],
  );
  assert.equal(incomplete.routesComplete, false);
});

test("placement-only policies do not expect per-CPU queue routes", () => {
  const model = queueTopologyModel(
    { mode_name: "fifo" },
    null,
    Array.from({ length: 32 }, (_, cpu) => cpu),
  );

  assert.equal(model.expectedCpuCount, 0);
  assert.equal(model.routesComplete, true);
});

test("per-CPU routing delegates vertical scrolling to the document", () => {
  const stylesheet = readFileSync(
    new URL("../../src/web/style.css", import.meta.url),
    "utf8",
  );
  const routeRules = [...stylesheet.matchAll(/\.queue-route-table-wrap\s*\{([^}]*)\}/g)];

  assert.ok(routeRules.length > 0);
  assert.equal(routeRules.some((match) => /max-height\s*:/.test(match[1])), false);
});

test("Cell bars support independent LLC and numeric orderings", () => {
  assert.equal(typeof inspectionState.cellCpuOrder, "function");
  const topology = {
    numeric_order: [0, 1, 2, 3],
    topology_order: [0, 2, 1, 3],
  };

  assert.deepEqual(inspectionState.cellCpuOrder(topology, "llc"), [0, 2, 1, 3]);
  assert.deepEqual(inspectionState.cellCpuOrder(topology, "numeric"), [0, 1, 2, 3]);
});

test("Cell rows reserve task and overlap details for the detail panel", () => {
  const page = readFileSync(
    new URL("../../src/web/index.html", import.meta.url),
    "utf8",
  );
  const script = readFileSync(
    new URL("../../src/web/app.js", import.meta.url),
    "utf8",
  );
  const stylesheet = readFileSync(
    new URL("../../src/web/style.css", import.meta.url),
    "utf8",
  );

  for (const fragment of [
    'id="cellOrderMode"',
    'name="cellCpuOrder"',
    'id="cellBarTooltip"',
  ]) {
    assert.match(page, new RegExp(fragment), `missing ${fragment}`);
  }
  assert.doesNotMatch(script, /class="cell-count"/);
  assert.doesNotMatch(script, /class="cell-overlap"/);
  assert.match(script, /data-cell-cpu=/);
  assert.match(script, /mapped tasks/);
  assert.match(script, /Overlapping cells/);
  assert.doesNotMatch(script, /function renderCells\(\) \{\s*hideCellBarTooltip\(\)/);
  assert.match(stylesheet, /\.cell-order-mode\s*\{[^}]*width:\s*100%/s);
});

test("current scheduler command formats exact argv and unavailable states", () => {
  assert.equal(typeof inspectionState.schedulerCurrentCommand, "function");
  assert.equal(
    inspectionState.schedulerCurrentCommand({
      active: true,
      current_command: [
        "./target/release/scx_snake",
        "--policy",
        "policies/cell demo.toml",
        "--stats",
        "1",
      ],
    }),
    "./target/release/scx_snake --policy 'policies/cell demo.toml' --stats 1",
  );
  assert.equal(
    inspectionState.schedulerCurrentCommand({ active: false, current_command: null }),
    "Snake is not running.",
  );
  assert.equal(
    inspectionState.schedulerCurrentCommand({ active: true, current_command: null }),
    "Command line unavailable.",
  );
});

test("Control feedback buttons use reserved right-aligned anchors", () => {
  const page = readFileSync(
    new URL("../../src/web/index.html", import.meta.url),
    "utf8",
  );
  const script = readFileSync(
    new URL("../../src/web/app.js", import.meta.url),
    "utf8",
  );
  const stylesheet = readFileSync(
    new URL("../../src/web/style.css", import.meta.url),
    "utf8",
  );

  assert.match(page, /id="schedulerCurrentCommand"/);
  assert.ok((page.match(/data-feedback-anchor/g) || []).length >= 3);
  assert.match(script, /matches\("\[data-feedback-anchor\]"\)/);
  assert.match(stylesheet, /\.feedback-heading\s*\{[^}]*justify-content:\s*space-between/s);
  assert.match(stylesheet, /\.scheduler-feedback-anchor\.feedback-heading\s*\{[^}]*justify-content:\s*flex-end/s);
});

const readyCellStatsFixture = {
  status: "ready",
  error: null,
  scope: "all_snake_tasks",
  source_policy_generation: 12,
  window_ms: 30_000,
  observed_ms: 29_500,
  cells: [
    {
      id: 0,
      index: 0,
      primary_cpu_count: 1,
      runtime_ns: 44_250_000_000,
      primary_runtime_ns: 29_500_000_000,
      borrowed_runtime_ns: 14_750_000_000,
      lent_runtime_ns: 7_375_000_000,
      normal_enqueues: 900,
      affinity_enqueues: 100,
      normal_dispatches: 720,
      affinity_dispatches: 80,
      clock_transitions: 16,
      service_cores: 1.5,
      service_share_pct: 60,
      primary_pct: 66.6667,
      borrowed_pct: 33.3333,
      owned_utilization_pct: 62.5,
      enqueue_rate_per_second: 33.8983,
      dispatch_rate_per_second: 27.1186,
      affinity_enqueue_share_pct: 10,
      affinity_dispatch_share_pct: 10,
      transition_rate_per_second: 0.5424,
      transitions_per_1k_dispatches: 20,
    },
    {
      id: 7,
      index: 1,
      primary_cpu_count: 2,
      runtime_ns: 29_500_000_000,
      primary_runtime_ns: 29_500_000_000,
      borrowed_runtime_ns: 0,
      lent_runtime_ns: 14_750_000_000,
      normal_enqueues: 0,
      affinity_enqueues: 0,
      normal_dispatches: 0,
      affinity_dispatches: 0,
      clock_transitions: 0,
      service_cores: 1,
      service_share_pct: 40,
      primary_pct: 100,
      borrowed_pct: 0,
      owned_utilization_pct: 50,
      enqueue_rate_per_second: 0,
      dispatch_rate_per_second: 0,
      affinity_enqueue_share_pct: null,
      affinity_dispatch_share_pct: null,
      transition_rate_per_second: 0,
      transitions_per_1k_dispatches: null,
    },
  ],
};

const collectingQueueTimingFixture = {
  sequence: 18,
  context: {
    scheduler_attach_seq: 4,
    scheduler_active: true,
    policy_generation: 12,
    active_slot: 0,
    fairness: "vtime",
    callback_sample_rate: 64,
  },
  status: "ready",
  error: null,
  sample_rate: 64,
  state: "collecting",
  session_id: 9,
  policy_generation: 12,
  started_at_ms: 1_700_000_000_000,
  stopped_at_ms: null,
  started_samples: 140,
  completed_samples: 120,
  dropped_samples: 2,
  dsqs: [
      {
        dsq_id: 536_870_912,
        queue_class: "normal",
        cpu: null,
        cell_index: 0,
        residence: {
          samples: 120,
          total_ns: 1_020_000,
          mean_ns: 8_500,
          p50_ns: 4_096,
          p95_ns: 16_384,
          p99_ns: 32_768,
        },
        depth: { samples: 120, latest: 2, p95: 6, max: 11 },
      },
      {
        dsq_id: 268_435_456,
        queue_class: "affinity",
        cpu: 0,
        cell_index: 0,
        residence: {
          samples: 19,
          total_ns: 34_200,
          mean_ns: 1_800,
          p50_ns: 1_024,
          p95_ns: 4_096,
          p99_ns: 8_192,
        },
        depth: { samples: 19, latest: 0, p95: 2, max: 3 },
      },
  ],
};

test("cell statistics preserve cell zero, nullable ratios, and all raw counters", () => {
  assert.equal(typeof inspectionState.cellStatsModel, "function");
  const model = inspectionState.cellStatsModel(readyCellStatsFixture);

  assert.equal(model.status, "ready");
  assert.equal(model.policyGeneration, 12);
  assert.equal(model.scope, "all_snake_tasks");
  assert.equal(model.windowMs, 30_000);
  assert.equal(model.observedMs, 29_500);
  assert.equal(model.zeroActivity, false);
  assert.equal(model.cells[0].id, 0);
  assert.equal(model.cells[0].index, 0);
  assert.equal(model.cells[0].primaryCpuCount, 1);
  assert.equal(model.cells[0].raw.clock_transitions, 16);
  assert.equal(model.cells[0].serviceCores, 1.5);
  assert.equal(model.cells[0].normalEnqueueRate, 30.5085);
  assert.equal(model.cells[1].affinityEnqueuePct, null);
  assert.equal(model.cells[1].transitionsPer1kDispatches, null);
});

test("cell statistics distinguish explicit availability and zero-activity states", () => {
  assert.equal(typeof inspectionState.cellStatsModel, "function");
  for (const status of [
    "not_applicable",
    "unsupported",
    "synchronizing",
    "unavailable",
  ]) {
    const model = inspectionState.cellStatsModel({
      ...readyCellStatsFixture,
      status,
      error: null,
      source_policy_generation: null,
      observed_ms: 0,
      cells: [],
    });
    assert.equal(model.status, status);
    assert.notEqual(model.statusLabel, "");
  }

  const zero = inspectionState.cellStatsModel({
    ...readyCellStatsFixture,
    observed_ms: 30_000,
    cells: readyCellStatsFixture.cells.map((cell) => ({
      ...cell,
      runtime_ns: 0,
      primary_runtime_ns: 0,
      borrowed_runtime_ns: 0,
      lent_runtime_ns: 0,
      normal_enqueues: 0,
      affinity_enqueues: 0,
      normal_dispatches: 0,
      affinity_dispatches: 0,
      clock_transitions: 0,
    })),
  });
  assert.equal(zero.status, "ready");
  assert.equal(zero.zeroActivity, true);
});

test("cell statistic formatting never turns an undefined ratio into zero", () => {
  assert.equal(typeof inspectionState.formatCellMetric, "function");
  assert.equal(inspectionState.formatCellMetric(null, "percentage"), "—");
  assert.equal(inspectionState.formatCellMetric(Number.NaN, "cores"), "—");
  assert.equal(inspectionState.formatCellMetric(0, "percentage"), "0.0%");
  assert.equal(inspectionState.formatCellMetric(1.5, "cores"), "1.50");
  assert.equal(inspectionState.formatCellMetric(30.5085, "rate"), "30.5/s");
});

test("queue timing model gates controls and low-sample percentiles", () => {
  assert.equal(typeof inspectionState.queueTimingModel, "function");
  const model = inspectionState.queueTimingModel(collectingQueueTimingFixture, {
    context: collectingQueueTimingFixture.context,
    pending: false,
  });

  assert.equal(model.status, "ready");
  assert.equal(model.sequence, 18);
  assert.equal(model.controlDisabled, false);
  assert.equal(model.checked, true);
  assert.equal(model.stateLabel, "Collecting");
  assert.equal(model.sampleRateLabel, "1 / 64");
  assert.deepEqual(model.counts, { started: 140, completed: 120, dropped: 2 });
  assert.equal(model.dsqs[0].residence.p99Ns, 32_768);
  assert.equal(model.dsqs[1].residence.p95Ns, null);
  assert.equal(model.dsqs[1].residence.p99Ns, null);
  assert.equal(model.dsqs[1].depth.p95, null);

  for (const status of ["unsupported", "not_applicable", "synchronizing", "unavailable"]) {
    const unavailable = inspectionState.queueTimingModel({
      ...collectingQueueTimingFixture,
      status,
      state: null,
      session_id: null,
      dsqs: [],
    });
    assert.equal(unavailable.controlDisabled, true);
    assert.notEqual(unavailable.statusLabel, "");
  }
  assert.equal(
    inspectionState.queueTimingModel({
      ...collectingQueueTimingFixture,
      sample_rate: 0,
      state: null,
      session_id: null,
      dsqs: [],
    }).controlDisabled,
    true,
  );
  const synchronizing = inspectionState.queueTimingModel(collectingQueueTimingFixture, {
    context: { ...collectingQueueTimingFixture.context, policy_generation: 13 },
  });
  assert.equal(synchronizing.status, "synchronizing");
  assert.equal(synchronizing.checked, false);
  assert.deepEqual(synchronizing.dsqs, []);
  assert.deepEqual(synchronizing.counts, { started: 0, completed: 0, dropped: 0 });
});

test("queue timing preserves and labels built-in local DSQ identities", () => {
  const localDsq = "13835058055282163719";
  const model = inspectionState.queueTimingModel({
    ...collectingQueueTimingFixture,
    dsqs: [{
      ...collectingQueueTimingFixture.dsqs[0],
      dsq_id: localDsq,
      queue_class: "fairness",
      cell_index: 4_294_967_295,
    }],
  });

  assert.equal(model.dsqs[0].dsqId, localDsq);
  assert.equal(model.dsqs[0].dsqKey, localDsq);
  assert.equal(model.dsqs[0].kind, "Local CPU 7");
  assert.equal(model.dsqs[0].label, "0xc000000000000007");
});

test("queue timing joins normal DSQs and per-CPU affinity routes by DSQ identity", () => {
  assert.equal(typeof inspectionState.mergeQueueTimingTopology, "function");
  const topology = queueTopologyModel(
    { mode_name: "vtime", clock_model: "one clock per cell" },
    {
      layout: "cell",
      affinity_queue_count: 1,
      cells: [{
        external_id: 0,
        index: 0,
        synthetic: true,
        cpu_weight: 1,
        clock_index: 0,
        primary_cpus: [0],
        borrowable_cpus: [],
      }],
      normal_queues: [{
        index: 0,
        dsq_id: 536_870_912,
        cell_id: 0,
        cell_index: 0,
        clock_index: 0,
        llc_id: null,
        consumer_cpus: [0],
      }],
      cpu_routes: [{
        cpu: 0,
        owner_cell_id: 0,
        owner_cell_index: 0,
        llc_id: 0,
        normal_queue_index: 0,
        normal_dsq_id: 536_870_912,
        affinity_dsq_id: 268_435_456,
      }],
    },
    [0],
  );
  const timing = inspectionState.queueTimingModel(collectingQueueTimingFixture);
  const merged = inspectionState.mergeQueueTimingTopology(topology, timing);

  assert.equal(timing.topologyCompatible, true);
  assert.equal(merged.normalQueues[0].timing.residence.samples, 120);
  assert.equal(merged.cpuRoutes[0].affinityTiming.residence.samples, 19);
  assert.equal(merged.cpuRoutes[0].affinityTiming.depth.latest, 0);

  const historical = inspectionState.queueTimingModel({
    ...collectingQueueTimingFixture,
    state: "historical",
    policy_generation: 11,
    stopped_at_ms: 1_700_000_030_000,
  }, { context: collectingQueueTimingFixture.context });
  const currentTopology = inspectionState.mergeQueueTimingTopology(topology, historical);
  assert.equal(historical.state, "historical");
  assert.equal(historical.topologyCompatible, false);
  assert.equal(currentTopology.normalQueues[0].timing.residence.samples, 0);

  const staleCollecting = inspectionState.queueTimingModel({
    ...collectingQueueTimingFixture,
    policy_generation: 11,
  }, { context: collectingQueueTimingFixture.context });
  assert.equal(staleCollecting.status, "synchronizing");
  assert.equal(staleCollecting.controlDisabled, true);
  assert.deepEqual(staleCollecting.dsqs, []);
});

test("Cells and Policy expose the shared window and on-demand queue capture controls", () => {
  const page = readFileSync(
    new URL("../../src/web/index.html", import.meta.url),
    "utf8",
  );
  const script = readFileSync(
    new URL("../../src/web/app.js", import.meta.url),
    "utf8",
  );

  assert.match(page, /id="cellWindowSelect"/);
  assert.match(page, /aria-label="Cell statistics window"/);
  assert.match(script, /fetch\("\/api\/queue-timing"/);
  assert.match(script, /JSON\.stringify\(\{ enabled \}\)/);
  assert.match(script, /Queue capture/);
  assert.match(script, /Raw window counters/);
  assert.match(script, /Operation-sampled depth/);
  assert.match(script, /Residence p95/);
  assert.match(script, /queue_timing_stopped/);
  assert.doesNotMatch(page, /data-route="queues"/);
});

test("queue timing polling authenticates its GET request", () => {
  const script = readFileSync(
    new URL("../../src/web/app.js", import.meta.url),
    "utf8",
  );

  assert.match(
    script,
    /fetch\("\/api\/queue-timing",\s*\{[^}]*headers:\s*\{\s*"x-snake-token":\s*token\s*\}[^}]*\}\)/s,
  );
});
