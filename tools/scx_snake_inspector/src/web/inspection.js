// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

const ROUTES = new Set(["activity", "policy", "cells", "callbacks", "control", "feedback"]);
const DEMO_POLICY_IDS = new Set([
  "llc-half-random.toml",
  "llc-random.toml",
  "llc-whole-core-random.toml",
  "random-idle.toml",
]);
const callbackDurationFormat = new Intl.NumberFormat("en-US", {
  maximumFractionDigits: 0,
});

export function routeFromHash(hash) {
  const route = String(hash || "").replace(/^#\/?/, "");
  return ROUTES.has(route) ? route : "activity";
}

export function contextsMatch(left, right) {
  if (!left || !right) {
    return true;
  }
  if (left.scheduler_attach_seq !== right.scheduler_attach_seq) {
    return false;
  }
  return left.policy_generation == null
    || right.policy_generation == null
    || left.policy_generation === right.policy_generation;
}

export function runtimeContextModel({ snapshot, inspection, control } = {}) {
  const contexts = [inspection?.context, snapshot?.context, control?.context]
    .filter(Boolean);
  const context = contexts[0] || null;
  const synchronizing = contexts.some((candidate) => !contextsMatch(context, candidate));
  if (!context) {
    return {
      synchronizing: false,
      statusLabel: "Waiting for Snake",
      detailLabel: "Runtime context unavailable",
    };
  }

  const status = context.scheduler_active ? "Snake active" : "Snake stopped";
  const detail = synchronizing
    ? "Synchronizing runtime state…"
    : [
        control?.policy_id || "Policy unknown",
        context.fairness ? String(context.fairness).toUpperCase() : null,
        context.policy_generation == null
          ? null
          : `policy gen ${context.policy_generation}`,
        context.active_slot == null ? null : `slot ${context.active_slot}`,
        context.callback_sample_rate == null
          ? null
          : context.callback_sample_rate === 0
            ? "sampling off"
            : `sampling 1/${context.callback_sample_rate}`,
      ].filter(Boolean).join(" · ");
  return {
    synchronizing,
    statusLabel: `${status} · Attach #${context.scheduler_attach_seq}`,
    detailLabel: detail,
  };
}

export function freshnessModel({
  hasData,
  error,
  lastSuccessAt,
  pollIntervalMs,
  now = Date.now(),
} = {}) {
  if (!hasData) {
    return error
      ? { state: "unavailable", label: "Unavailable", detail: error }
      : { state: "waiting", label: "Waiting for Snake", detail: null };
  }
  const ageMs = Math.max(0, now - Number(lastSuccessAt || 0));
  const stale = Boolean(error) || ageMs > Number(pollIntervalMs || 0) * 2.5;
  if (!stale) {
    return { state: "fresh", label: "Updated just now", detail: null };
  }
  return {
    state: "stale",
    label: `Stale · updated ${Math.round(ageMs / 1_000)}s ago`,
    detail: error || null,
  };
}

export function captureKeyedRenderState(nodes, activeElement = null) {
  const entries = new Map();
  let focusedKey = null;
  for (const node of nodes || []) {
    const key = node?.dataset?.renderKey;
    if (!key) {
      continue;
    }
    entries.set(key, {
      open: typeof node.open === "boolean" ? node.open : null,
      scrollTop: Number.isFinite(node.scrollTop) ? node.scrollTop : 0,
      scrollLeft: Number.isFinite(node.scrollLeft) ? node.scrollLeft : 0,
      selectionStart: Number.isInteger(node.selectionStart) ? node.selectionStart : null,
      selectionEnd: Number.isInteger(node.selectionEnd) ? node.selectionEnd : null,
      selectionDirection: typeof node.selectionDirection === "string"
        ? node.selectionDirection
        : null,
    });
    if (node === activeElement) {
      focusedKey = key;
    }
  }
  return { entries, focusedKey };
}

export function restoreKeyedRenderState(nodes, snapshot) {
  if (!snapshot?.entries) {
    return;
  }
  let focusTarget = null;
  for (const node of nodes || []) {
    const key = node?.dataset?.renderKey;
    const entry = key ? snapshot.entries.get(key) : null;
    if (!entry) {
      continue;
    }
    if (entry.open !== null && typeof node.open === "boolean") {
      node.open = entry.open;
    }
    if (Number.isFinite(node.scrollTop)) {
      node.scrollTop = entry.scrollTop;
    }
    if (Number.isFinite(node.scrollLeft)) {
      node.scrollLeft = entry.scrollLeft;
    }
    if (key === snapshot.focusedKey && typeof node.focus === "function") {
      focusTarget = node;
    }
  }
  focusTarget?.focus({ preventScroll: true });
  const focusEntry = snapshot.focusedKey
    ? snapshot.entries.get(snapshot.focusedKey)
    : null;
  if (
    focusTarget
    && focusEntry?.selectionStart !== null
    && focusEntry?.selectionEnd !== null
    && typeof focusTarget.setSelectionRange === "function"
  ) {
    focusTarget.setSelectionRange(
      focusEntry.selectionStart,
      focusEntry.selectionEnd,
      focusEntry.selectionDirection || "none",
    );
  }
}

export function updateFeedbackEntries(entries, key, text) {
  const normalizedKey = String(key || "").trim();
  if (!normalizedKey) {
    return [...(entries || [])];
  }
  const normalizedText = String(text ?? "").replace(/\r\n?/g, "\n");
  const next = (entries || []).map((entry) => ({ ...entry }));
  const index = next.findIndex((entry) => entry.key === normalizedKey);
  if (!normalizedText.trim()) {
    if (index >= 0) {
      next.splice(index, 1);
    }
    return next;
  }
  const entry = { key: normalizedKey, text: normalizedText };
  if (index >= 0) {
    next[index] = entry;
  } else {
    next.push(entry);
  }
  return next;
}

export function parseFeedbackEntries(serialized) {
  let parsed;
  try {
    parsed = JSON.parse(String(serialized || "[]"));
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) {
    return [];
  }
  return parsed.reduce((entries, entry) => {
    if (!entry || typeof entry.key !== "string" || typeof entry.text !== "string") {
      return entries;
    }
    return updateFeedbackEntries(entries, entry.key, entry.text);
  }, []);
}

export function formatFeedbackTranscript(entries) {
  return (entries || [])
    .filter((entry) => entry?.key && String(entry.text || "").trim())
    .map((entry) => `[${String(entry.key).trim()}] ${String(entry.text).trim()}`)
    .join("\n\n");
}

export function syncCallbackSampleRateControl(
  control,
  serverRate,
  { dirty = false, pending = false, activeElement = null } = {},
) {
  if (!control || serverRate == null || dirty || pending || activeElement === control) {
    return false;
  }
  const value = String(serverRate);
  if (control.value === value) {
    return false;
  }
  control.value = value;
  return true;
}

export function formatCallbackDuration(value) {
  if (value == null || !Number.isFinite(Number(value)) || Number(value) < 0) {
    return "—";
  }
  return `${callbackDurationFormat.format(Math.round(Number(value)))} ns`;
}

export function callbackDurationClass(value) {
  const nanoseconds = Number(value);
  return Number.isFinite(nanoseconds) && nanoseconds > 1_000
    ? "callback-duration-warning"
    : "";
}

const FINE_TIMING_CALLBACKS = [
  { callback: "select_cpu", label: "Select CPU" },
  { callback: "enqueue", label: "Enqueue" },
  { callback: "dispatch", label: "Dispatch" },
];

export function fineTimingCaptureModels(payload) {
  const captures = new Map(
    (payload?.captures || []).map((capture) => [capture.callback, capture]),
  );
  return FINE_TIMING_CALLBACKS.map(({ callback, label }) => {
    const capture = captures.get(callback) || {
      callback,
      state: "inactive",
      session_id: null,
      policy_generation: null,
      started_at_ms: null,
      stopped_at_ms: null,
      stages: [],
    };
    const stateLabel = capture.state === "collecting"
      ? "Collecting"
      : capture.state === "historical"
        ? "Historical"
        : "Inactive";
    const available = capture.available === true;
    return {
      ...capture,
      callback,
      label,
      available,
      unavailable_reason: capture.unavailable_reason || null,
      availabilityLabel: available ? "Available" : "Unavailable",
      controlDisabled: !available,
      checked: capture.state === "collecting",
      stateLabel,
    };
  });
}

function restartReasonLabel(reason) {
  const text = String(reason || "").trim();
  const lower = text.toLowerCase();
  if (lower.includes("queue topology")) {
    return "DSQ topology changes.";
  }
  if (lower.includes("task membership")) {
    return "Task membership changes.";
  }
  if (lower.includes("queue enqueue target")) {
    return "Queue enqueue targets change.";
  }
  if (lower.includes("queue dispatch source")) {
    return "Queue dispatch sources change.";
  }
  const withoutRestart = text
    .replace(/;?\s*restart Snake to apply it\.?$/i, "")
    .replace(/^candidate\s+/i, "Policy ");
  if (!withoutRestart) {
    return "Policy arguments require a new scheduler attachment.";
  }
  return /[.!?]$/.test(withoutRestart) ? withoutRestart : `${withoutRestart}.`;
}

function legacyPolicyReason(reason) {
  const detail = String(reason || "").trim() || "Policy compatibility is unknown.";
  const lower = detail.toLowerCase();
  if (lower.includes("queue topology")) {
    return { code: "dsq_topology", label: "DSQ topology changes", detail };
  }
  if (lower.includes("task membership")) {
    return { code: "task_membership", label: "Task membership changes", detail };
  }
  if (lower.includes("enqueue target")) {
    return { code: "enqueue_targets", label: "Queue enqueue targets change", detail };
  }
  if (lower.includes("dispatch source")) {
    return { code: "dispatch_sources", label: "Queue dispatch sources change", detail };
  }
  return { code: "validation_failed", label: "Policy validation failed", detail };
}

export function policyLibraryModels(
  catalog,
  control,
  activeSource = null,
  selectedFairness = null,
) {
  const valid = new Map((catalog?.policies || []).map((policy) => [policy.id, policy]));
  const invalid = new Map((catalog?.invalid || []).map((policy) => [policy.id, policy]));
  const controls = control?.policies?.length
    ? control.policies
    : [
        ...(catalog?.policies || []).map((policy) => ({
          id: policy.id,
          name: policy.name,
          apply_mode: "live",
          reasons: [],
          supported_fairness: policy.queue_policy
            || /^\s*\[\s*queues(?:\s*\]|\s*\.)/m.test(policy.source || "")
            ? ["vtime"]
            : ["fifo", "vtime", "eevdf"],
          change_mode: "dynamic",
          reload_reasons: [],
        })),
        ...(catalog?.invalid || []).map((policy) => ({
          id: policy.id,
          name: policy.id,
          apply_mode: "invalid",
          reasons: [legacyPolicyReason(policy.error)],
          supported_fairness: /^\s*\[\s*queues(?:\s*\]|\s*\.)/m.test(policy.source || "")
            ? ["vtime"]
            : ["fifo", "vtime", "eevdf"],
          change_mode: "invalid",
          reload_reasons: [policy.error],
        })),
      ];
  const activeFairness = control?.context?.fairness || control?.launch?.fairness || "fifo";
  const controlPolicyId = controls.some((entry) => entry.id === control?.policy_id)
    ? control.policy_id
    : null;
  const sourceMatches = activeSource
    ? controls.filter((entry) => {
        const details = valid.get(entry.id) || invalid.get(entry.id);
        return details?.source?.trim() === activeSource.trim();
      })
    : [];
  const activePolicyId = controlPolicyId
    || (sourceMatches.length === 1 ? sourceMatches[0].id : null);
  return controls.map((entry) => {
    const details = valid.get(entry.id);
    const invalidDetails = invalid.get(entry.id);
    const source = details?.source || invalidDetails?.source || null;
    const fairnessModes = Array.isArray(entry.supported_fairness)
      && entry.supported_fairness.length > 0
      ? entry.supported_fairness
      : /^\s*\[\s*queues(?:\s*\]|\s*\.)/m.test(source || "")
        ? ["vtime"]
        : ["fifo", "vtime", "eevdf"];
    const configuredApplyMode = ["live", "restart", "invalid"].includes(entry.apply_mode)
      ? entry.apply_mode
      : entry.change_mode === "dynamic"
        ? "live"
        : entry.change_mode === "reload"
          ? "restart"
          : "invalid";
    const applyMode = selectedFairness
      && selectedFairness !== activeFairness
      && configuredApplyMode !== "invalid"
      ? "restart"
      : configuredApplyMode;
    const changeMode = applyMode === "live"
      ? "dynamic"
      : applyMode === "restart"
        ? "reload"
        : "invalid";
    const active = (!selectedFairness || selectedFairness === activeFairness)
      && activePolicyId === entry.id;
    const actionKind = active
      ? "active"
      : changeMode === "dynamic"
        ? "activate"
        : changeMode === "reload"
          ? "lifecycle"
          : "invalid";
    const actionLabel = actionKind === "active"
      ? "Active"
      : actionKind === "activate"
        ? "Apply live"
        : actionKind === "lifecycle"
          ? (control?.active ? "Restart Snake" : "Start Snake")
          : "Unavailable";
    const reasons = Array.isArray(entry.reasons) && entry.reasons.length > 0
      ? entry.reasons.map((reason) => ({ ...reason }))
      : (entry.reload_reasons || []).map(legacyPolicyReason);
    if (applyMode === "restart" && selectedFairness && selectedFairness !== activeFairness) {
      reasons.unshift({
        code: "fairness_change",
        label: "Fairness changes",
        detail: `Fairness approach changes from ${activeFairness.toUpperCase()} to ${selectedFairness.toUpperCase()}.`,
      });
    }
    if (applyMode === "invalid" && reasons.length === 0) {
      reasons.push(legacyPolicyReason(invalidDetails?.error || "Policy arguments are invalid."));
    }
    const uniqueReasons = reasons.filter((reason, index, all) =>
      all.findIndex((candidate) => candidate.code === reason.code && candidate.detail === reason.detail)
        === index);
    return {
      ...entry,
      name: details?.name || invalidDetails?.name || entry.name || entry.id,
      source,
      summary: invalidDetails || changeMode === "invalid"
        ? null
        : details?.summary || "No policy details available.",
      reasons: uniqueReasons,
      restartReasons: uniqueReasons.map((reason) => restartReasonLabel(reason.detail)),
      fairnessModes,
      selectedFairness,
      active,
      applyMode,
      changeMode,
      changeLabel: changeMode === "dynamic"
        ? (active ? "Dynamic" : "Applies live")
        : changeMode === "reload"
          ? "Restart required"
          : "Invalid",
      actionKind,
      actionLabel,
      disabled: active || changeMode === "invalid",
    };
  }).filter((policy) => !selectedFairness || policy.fairnessModes.includes(selectedFairness));
}

export function policyCategoryGroups(policies) {
  const groups = [
    { id: "production", label: "Production", policies: [] },
    { id: "demo", label: "Demo", policies: [] },
  ];
  for (const policy of policies || []) {
    groups[DEMO_POLICY_IDS.has(policy.id) ? 1 : 0].policies.push(policy);
  }
  return groups;
}

export function policySlotComparison(slots) {
  const active = (slots || []).find((slot) => slot.state === "active") || null;
  const previous = (slots || []).find((slot) => slot.state === "inactive") || null;
  const label = (role, slot) => slot ? `${role} · slot ${slot.slot}` : `${role} unavailable`;
  if (!active?.policy || !previous?.policy) {
    return {
      activeLabel: label("Active", active),
      previousLabel: label("Previous", previous),
      comparable: false,
      rows: [],
    };
  }
  const fallback = (slot) => slot.policy.fallback?.selected?.label
    || slot.policy.fallback?.selected?.value
    || "Unknown";
  const ladder = (slot, kind) => {
    const rungs = slot.policy.queues?.[kind] || [];
    return rungs.length > 0
      ? rungs.map((rung) => rung.operation).join(" → ")
      : "Not configured";
  };
  const values = [
    ["Generation", active.generation, previous.generation],
    ["Idle rungs", active.policy.rungs?.length || 0, previous.policy.rungs?.length || 0],
    ["Fallback", fallback(active), fallback(previous)],
    ["Mask tables", active.policy.mask_tables?.length || 0, previous.policy.mask_tables?.length || 0],
    ["Queue layout", active.policy.queues?.layout || "Not configured", previous.policy.queues?.layout || "Not configured"],
    ["Enqueue ladder", ladder(active, "enqueue"), ladder(previous, "enqueue")],
    ["Dispatch ladder", ladder(active, "dispatch"), ladder(previous, "dispatch")],
  ];
  return {
    activeLabel: label("Active", active),
    previousLabel: label("Previous", previous),
    comparable: true,
    rows: values.map(([name, activeValue, previousValue]) => ({
      name,
      active: String(activeValue ?? "Unknown"),
      previous: String(previousValue ?? "Unknown"),
      changed: String(activeValue ?? "Unknown") !== String(previousValue ?? "Unknown"),
    })),
  };
}

export function fieldReferenceGroups(reference) {
  return {
    selected: reference?.selected || {
      value: "unknown",
      label: "Unknown",
      description: "No field reference is available.",
    },
    valid: Array.isArray(reference?.valid) ? reference.valid : [],
    other: Array.isArray(reference?.other) ? reference.other : [],
  };
}

export function decorateCells(cells, taskMappings) {
  const tasksByCell = new Map();
  for (const task of taskMappings || []) {
    const tasks = tasksByCell.get(task.cell_id) || [];
    tasks.push(task);
    tasksByCell.set(task.cell_id, tasks);
  }
  return (cells || []).map((cell) => {
    const cpuSet = new Set(cell.cpus || []);
    const overlapIds = (cells || [])
      .filter((candidate) => candidate.id !== cell.id)
      .filter((candidate) => (candidate.cpus || []).some((cpu) => cpuSet.has(cpu)))
      .map((candidate) => candidate.id)
      .sort((left, right) => left - right);
    const tasks = (tasksByCell.get(cell.id) || [])
      .slice()
      .sort((left, right) => left.tid - right.tid);
    return { ...cell, overlapIds, tasks };
  });
}

export function cellCpuOrder(topology, mode) {
  const order = mode === "numeric"
    ? topology?.numeric_order
    : topology?.topology_order;
  return [...(order || [])];
}

export function rungPercentages(metrics) {
  const attempts = Math.max(0, Number(metrics?.attempts) || 0);
  if (attempts === 0) {
    return { hit: 0, miss: 0 };
  }
  return {
    hit: Math.max(0, Number(metrics?.hits) || 0) * 100 / attempts,
    miss: Math.max(0, Number(metrics?.misses) || 0) * 100 / attempts,
  };
}

export function rungLadderPercentages(metrics, ladderMetrics) {
  const selectCalls = Math.max(0, Number(ladderMetrics?.select_calls) || 0);
  if (selectCalls === 0) {
    return { hit: 0, miss: 0 };
  }
  return {
    hit: Math.max(0, Number(metrics?.hits) || 0) * 100 / selectCalls,
    miss: Math.max(0, Number(metrics?.misses) || 0) * 100 / selectCalls,
  };
}

export function ladderPercentages(metrics) {
  const selectCalls = Math.max(0, Number(metrics?.select_calls) || 0);
  if (selectCalls === 0) {
    return { hit: 0, miss: 0 };
  }
  return {
    hit: Math.max(0, Number(metrics?.direct_dispatches) || 0) * 100 / selectCalls,
    miss: Math.max(0, Number(metrics?.ladder_exhaustions) || 0) * 100 / selectCalls,
  };
}

export function queueRungFlow(kind, index, count) {
  const last = index + 1 >= count;
  if (kind === "enqueue") {
    return {
      hit: "Queued → stop",
      miss: last ? "Failure → error" : `Unavailable → rung ${index + 1}`,
    };
  }
  if (kind === "dispatch") {
    return {
      hit: "Work → dispatch",
      miss: last ? "Empty → wrap to rung 0" : `Empty → rung ${index + 1}`,
    };
  }
  throw new Error(`Unknown queue ladder kind: ${kind}`);
}

export function queueLadderSections(queues) {
  if (!queues) {
    return [];
  }
  const dispatch = queues.dispatch || [];
  const minVtime = dispatch.length === 1
    && dispatch[0].operation === "min_vtime(cell,affinity)";
  return [
    {
      kind: "enqueue",
      title: "Enqueue",
      behavior: "First success",
      terminal: "All targets failed → error",
      rungs: (queues.enqueue || []).map((rung, index, all) => ({
        ...rung,
        role: "target",
        flow: queueRungFlow("enqueue", index, all.length),
      })),
    },
    {
      kind: "dispatch",
      title: "Dispatch",
      cyclic: !minVtime,
      behavior: minVtime
        ? "Lowest VTIME; alternating exact ties"
        : "Cyclic per-CPU cursor",
      terminal: minVtime
        ? "Both sources empty → replenish previous task or idle"
        : "All sources empty → replenish previous task or idle",
      rungs: dispatch.map((rung, index, all) => ({
        ...rung,
        role: minVtime ? "operation" : "source",
        flow: minVtime
          ? {
              hit: "Earlier head → dispatch",
              miss: "Both empty → replenish previous task or idle",
            }
          : queueRungFlow("dispatch", index, all.length),
      })),
    },
  ];
}

export function selectionRungHitFlow(rung, queues) {
  if (!queues) {
    return "Hit → dispatch";
  }
  return rung?.scope === "task_cell_borrowable"
    ? "Hit → direct dispatch"
    : "Hit → enqueue ladder";
}

export function workloadAssignmentRequest(kind, value, cellId, clear) {
  const targetValue = String(value ?? "").trim();
  let target;
  if (kind === "tid" || kind === "tgid") {
    const id = Number(targetValue);
    if (!Number.isSafeInteger(id) || id <= 0) {
      throw new Error(`${kind.toUpperCase()} must be a positive integer.`);
    }
    target = { kind, [kind]: id };
  } else if (kind === "cgroup") {
    if (!targetValue) {
      throw new Error("Cgroup path is required.");
    }
    target = { kind, path: targetValue };
  } else {
    throw new Error("Unknown workload target type.");
  }

  let parsedCell = null;
  if (!clear) {
    parsedCell = Number(cellId);
    if (!Number.isSafeInteger(parsedCell) || parsedCell < 0) {
      throw new Error("Select a valid destination cell.");
    }
  }
  return { target, cell_id: parsedCell };
}

export function callbackSampleRateOptions() {
  const options = [{ value: 0, label: "Disabled" }];
  for (let value = 1; value <= 4096; value *= 2) {
    options.push({
      value,
      label: value === 1 ? "Every callback" : `1 / ${value.toLocaleString()} callbacks`,
    });
  }
  return options;
}

export function schedulerLaunchRequest(values) {
  const policyId = String(values?.policy_id || "").trim();
  if (!policyId) {
    throw new Error("Select a policy before starting Snake.");
  }

  const request = {
    policy_id: policyId,
    verbose: Boolean(values?.verbose),
  };
  if (values?.fairness_enabled) {
    const fairness = String(values.fairness || "").toLowerCase();
    if (!["fifo", "vtime", "eevdf"].includes(fairness)) {
      throw new Error("Fairness must be FIFO, VTIME, or EEVDF.");
    }
    request.fairness = fairness;
  }
  if (values?.callback_timing_sample_rate_enabled) {
    const sampleRate = Number(values.callback_timing_sample_rate);
    if (
      !Number.isSafeInteger(sampleRate)
      || sampleRate < 0
      || sampleRate > 4096
      || (sampleRate !== 0 && !isPowerOfTwo(sampleRate))
    ) {
      throw new Error("Callback sample rate must be zero or a power of two through 4096.");
    }
    request.callback_timing_sample_rate = sampleRate;
  }
  if (values?.exit_dump_len_enabled) {
    const exitDumpLen = Number(values.exit_dump_len);
    if (!Number.isSafeInteger(exitDumpLen) || exitDumpLen < 0 || exitDumpLen > 0xffffffff) {
      throw new Error("Exit dump length must be a non-negative integer through 4294967295.");
    }
    request.exit_dump_len = exitDumpLen;
  }
  return request;
}

export function schedulerCommandPreview(request, preservedArgs = []) {
  if (!request?.policy_id) {
    return "scx_snake --policy <select a policy>";
  }
  const args = ["scx_snake", "--policy", shellWord(request.policy_id)];
  if (request.fairness != null) {
    args.push("--fairness", shellWord(request.fairness));
  }
  if (request.callback_timing_sample_rate != null) {
    args.push("--callback-timing-sample-rate", String(request.callback_timing_sample_rate));
  }
  if (request.exit_dump_len != null) {
    args.push("--exit-dump-len", String(request.exit_dump_len));
  }
  if (request.verbose) {
    args.push("--verbose");
  }
  args.push(...preservedArgs.map(shellWord));
  return args.join(" ");
}

export function launchDiff(current, proposed) {
  const fields = [
    ["policy_id", "Policy"],
    ["fairness", "Fairness"],
    ["callback_timing_sample_rate", "Callback sample rate"],
    ["exit_dump_len", "Exit dump length"],
    ["verbose", "Verbose logging"],
  ];
  return fields.flatMap(([field, name]) => {
    const before = field === "verbose" ? Boolean(current?.[field]) : current?.[field] ?? null;
    const after = field === "verbose" ? Boolean(proposed?.[field]) : proposed?.[field] ?? null;
    return Object.is(before, after) ? [] : [{ name, before, after }];
  });
}

export function schedulerCurrentCommand(control) {
  if (!control) {
    return "Command line unavailable.";
  }
  if (!control.active) {
    return "Snake is not running.";
  }
  if (!Array.isArray(control.current_command) || control.current_command.length === 0) {
    return "Command line unavailable.";
  }
  return control.current_command.map(shellWord).join(" ");
}

export function schedulerSettingModels(settings) {
  const labels = {
    fairness: "Fairness",
    callback_timing_sample_rate: "Callback sample rate",
    exit_dump_len: "Exit dump length",
    verbose: "Verbose logging",
    stats_reset: "Stats reset",
  };
  return (settings || []).map((setting) => {
    const changeMode = setting.change_mode === "dynamic" ? "dynamic" : "reload";
    const effective = setting.effective ?? setting.value ?? null;
    const launchOverride = setting.launch_override ?? null;
    const overrideValue = setting.name === "stats_reset"
      ? "—"
      : launchOverride == null
        ? "Omitted; Snake default applies"
        : formatSchedulerSettingValue(setting.name, launchOverride);
    return {
      name: labels[setting.name] || String(setting.name || "Unknown setting"),
      effectiveValue: effective == null
        ? "Not observed"
        : formatSchedulerSettingValue(setting.name, effective),
      overrideValue,
      runtimeObserved: Boolean(setting.runtime_observed),
      differs: effective != null
        && launchOverride != null
        && String(effective) !== String(launchOverride),
      changeMode,
      changeLabel: changeMode === "dynamic" ? "Dynamic" : "Reload required",
    };
  });
}

function formatSchedulerSettingValue(name, value) {
  if (name === "fairness") {
    return String(value).toUpperCase();
  }
  if (name === "callback_timing_sample_rate") {
    const rate = Number(value);
    return rate === 0 ? "Off" : `1 / ${rate.toLocaleString()}`;
  }
  if (name === "verbose") {
    return value ? "Enabled" : "Disabled";
  }
  return String(value);
}

export function statsResetDisabled(control, pending) {
  if (pending || !control?.active) {
    return true;
  }
  if (control.managed) {
    return false;
  }
  const schedulerName = String(control.scheduler_name || "").trim();
  return schedulerName !== "snake" && !schedulerName.startsWith("snake_");
}

export function schedulerControlMessage(control, error) {
  if (error) {
    return error;
  }
  if (control?.active && !control?.controllable) {
    return control.control_error || "The active Snake process cannot be controlled safely.";
  }
  if (!control?.active && control?.last_exit) {
    return `Last managed Snake exit: ${control.last_exit}`;
  }
  return null;
}

export function schedulerControlModel(control, pending, hasPolicy) {
  const active = Boolean(control?.active);
  const managed = Boolean(control?.managed);
  const controllable = Boolean(control?.controllable);
  const stateName = managed ? (active ? "active" : "starting") : (active ? "external" : "stopped");
  return {
    stateName,
    stateLabel: managed
      ? (active ? "Managed / Running" : "Managed / Starting")
      : (active ? (controllable ? "External / Controllable" : "External / Read-only") : "Stopped"),
    configLocked: Boolean(pending) || (active && !controllable) || (managed && !active),
    startDisabled: Boolean(pending) || active || managed || !hasPolicy,
    stopDisabled: Boolean(pending) || !controllable,
    restartDisabled: Boolean(pending) || !active || !controllable || !hasPolicy,
  };
}

function isPowerOfTwo(value) {
  return value > 0 && Math.log2(value) % 1 === 0;
}

function shellWord(value) {
  const word = String(value);
  if (/^[a-zA-Z0-9_./:-]+$/.test(word)) {
    return word;
  }
  return `'${word.replaceAll("'", `'"'"'`)}'`;
}

function formatDsqId(value) {
  const number = Number(value);
  return Number.isSafeInteger(number) && number >= 0
    ? `0x${number.toString(16).padStart(8, "0")}`
    : "unknown";
}

export function compactCpuList(cpus) {
  const values = [...new Set((cpus || []).map(Number).filter(Number.isSafeInteger))]
    .sort((left, right) => left - right);
  if (values.length === 0) {
    return "None";
  }
  const ranges = [];
  let start = values[0];
  let end = start;
  for (const cpu of values.slice(1)) {
    if (cpu === end + 1) {
      end = cpu;
      continue;
    }
    ranges.push(start === end ? String(start) : `${start}-${end}`);
    start = cpu;
    end = cpu;
  }
  ranges.push(start === end ? String(start) : `${start}-${end}`);
  return ranges.join(", ");
}

export function queueTopologyModel(fairness, topology, onlineCpus = null) {
  const affinityQueueCount = Number(topology?.affinity_queue_count) || 0;
  const expectedCpuCount = topology && Array.isArray(onlineCpus)
    ? onlineCpus.length
    : affinityQueueCount;
  const model = {
    mode: String(fairness?.mode_name || "unknown").toUpperCase(),
    clockModel: fairness?.clock_model || "Unknown clock model",
    layout: topology?.layout || null,
    affinityQueueCount,
    expectedCpuCount,
    routesComplete: expectedCpuCount === 0,
    cells: [],
    normalQueues: [],
    cpuRoutes: [],
  };
  if (!topology) {
    return model;
  }
  model.cells = (topology.cells || []).map((cell) => ({
    ...cell,
    label: cell.synthetic
      ? `Cell ${cell.external_id} (synthetic)`
      : `Cell ${cell.external_id}`,
  }));
  model.normalQueues = (topology.normal_queues || []).map((queue) => ({
    ...queue,
    dsq: formatDsqId(queue.dsq_id),
  }));
  model.cpuRoutes = (topology.cpu_routes || [])
    .map((route) => ({
      ...route,
      normalDsq: formatDsqId(route.normal_dsq_id),
      affinityDsq: formatDsqId(route.affinity_dsq_id),
    }))
    .sort((left, right) => left.cpu - right.cpu);
  model.routesComplete = model.cpuRoutes.length === expectedCpuCount;
  return model;
}

export function cellQueueFacts(topologyModel, cellId) {
  const cell = (topologyModel?.cells || [])
    .find((candidate) => Number(candidate.external_id) === Number(cellId));
  if (!cell) {
    return {
      configured: false,
      primaryCpus: [],
      borrowableCpus: [],
      clock: "Not configured",
      weight: null,
      normalDsqs: [],
    };
  }
  return {
    configured: true,
    primaryCpus: [...(cell.primary_cpus || [])],
    borrowableCpus: [...(cell.borrowable_cpus || [])],
    clock: `cell:${cell.clock_index}`,
    weight: cell.cpu_weight ?? null,
    normalDsqs: (topologyModel.normalQueues || [])
      .filter((queue) => Number(queue.cell_id) === Number(cellId))
      .map((queue) => queue.dsq),
  };
}
