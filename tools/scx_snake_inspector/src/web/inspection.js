// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

const ROUTES = new Set(["activity", "policy", "cells", "callbacks", "control"]);
const callbackDurationFormat = new Intl.NumberFormat("en-US", {
  maximumFractionDigits: 0,
});

export function routeFromHash(hash) {
  const route = String(hash || "").replace(/^#\/?/, "");
  return ROUTES.has(route) ? route : "activity";
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

export function policyLibraryModels(catalog, control, activeSource = null) {
  const valid = new Map((catalog?.policies || []).map((policy) => [policy.id, policy]));
  const invalid = new Map((catalog?.invalid || []).map((policy) => [policy.id, policy]));
  const controls = control?.policies?.length
    ? control.policies
    : [
        ...(catalog?.policies || []).map((policy) => ({
          id: policy.id,
          name: policy.name,
          change_mode: "dynamic",
          reload_reasons: [],
        })),
        ...(catalog?.invalid || []).map((policy) => ({
          id: policy.id,
          name: policy.id,
          change_mode: "invalid",
          reload_reasons: [policy.error],
        })),
      ];
  return controls.map((entry) => {
    const details = valid.get(entry.id);
    const invalidDetails = invalid.get(entry.id);
    const changeMode = ["dynamic", "reload", "invalid"].includes(entry.change_mode)
      ? entry.change_mode
      : "invalid";
    const active = control?.policy_id === entry.id
      || Boolean(details?.source && activeSource && details.source.trim() === activeSource.trim());
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
        ? "Activate"
        : actionKind === "lifecycle"
          ? (control?.active ? "Select for restart" : "Select to start")
          : "Unavailable";
    const reasons = entry.reload_reasons || [];
    return {
      ...entry,
      name: details?.name || entry.name || entry.id,
      source: details?.source || null,
      summary: details?.summary || reasons[0] || invalidDetails?.error || "No policy details available.",
      active,
      changeMode,
      changeLabel: changeMode === "dynamic"
        ? "Dynamic"
        : changeMode === "reload"
          ? "Restart required"
          : "Invalid",
      actionKind,
      actionLabel,
      disabled: active || changeMode === "invalid",
    };
  });
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
    if (fairness !== "fifo" && fairness !== "vtime") {
      throw new Error("Fairness must be FIFO or VTIME.");
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
    return {
      name: labels[setting.name] || String(setting.name || "Unknown setting"),
      value: String(setting.value ?? "Unavailable"),
      changeMode,
      changeLabel: changeMode === "dynamic" ? "Dynamic" : "Reload required",
    };
  });
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

export function queueTopologyModel(fairness, topology) {
  const model = {
    mode: String(fairness?.mode_name || "unknown").toUpperCase(),
    clockModel: fairness?.clock_model || "Unknown clock model",
    layout: topology?.layout || null,
    affinityQueueCount: Number(topology?.affinity_queue_count) || 0,
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
  model.cpuRoutes = (topology.cpu_routes || []).map((route) => ({
    ...route,
    normalDsq: formatDsqId(route.normal_dsq_id),
    affinityDsq: formatDsqId(route.affinity_dsq_id),
  }));
  return model;
}
