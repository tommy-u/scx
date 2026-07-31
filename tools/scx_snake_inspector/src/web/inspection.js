// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

const ROUTES = new Set([
  "overview",
  "observe/placement",
  "observe/callbacks",
  "configure",
  "inspect/policy-slots",
  "inspect/queue-topology",
  "inspect/cells",
  "validate/testing",
  "debugging/scheduler",
  "debugging/vtime",
  "project/operations",
  "project/roadmap",
]);
const LEGACY_ROUTES = new Map([
  ["activity", "observe/placement"],
  ["callbacks", "observe/callbacks"],
  ["control", "configure"],
  ["policy", "inspect/policy-slots"],
  ["cells", "inspect/cells"],
  ["debugging", "debugging/scheduler"],
]);
const PRODUCTION_POLICY_IDS = new Set([
  "kernel-default-sim.toml",
  "kernel-default.toml",
]);
const callbackDurationFormat = new Intl.NumberFormat("en-US", {
  maximumFractionDigits: 0,
});
const tableSortCollator = new Intl.Collator(undefined, {
  numeric: true,
  sensitivity: "base",
});
const TABLE_SORT_MISSING_VALUES = new Set([
  "",
  "-",
  "—",
  "n/a",
  "not available",
  "unavailable",
]);
const TABLE_SORT_DURATION_FACTORS = {
  ns: 1,
  us: 1_000,
  "µs": 1_000,
  "μs": 1_000,
  ms: 1_000_000,
  s: 1_000_000_000,
};

function tableSortText(value) {
  return String(value ?? "").replace(/\s+/g, " ").trim();
}

function tableSortNumber(value) {
  if (typeof value === "number") {
    return Number.isFinite(value) ? value : null;
  }
  const normalized = tableSortText(value).replaceAll(",", "");
  const match = normalized.match(
    /^([+-]?(?:\d+(?:\.\d*)?|\.\d+))(?:\s*(?:%|\/s|cores?))?$/i,
  );
  if (!match) {
    return null;
  }
  const number = Number(match[1]);
  return Number.isFinite(number) ? number : null;
}

function tableSortDuration(value) {
  if (typeof value === "number") {
    return Number.isFinite(value) ? value : null;
  }
  const normalized = tableSortText(value).replaceAll(",", "").toLowerCase();
  const match = normalized.match(
    /^([+-]?(?:\d+(?:\.\d*)?|\.\d+))\s*(ns|us|µs|μs|ms|s)$/,
  );
  if (!match) {
    return null;
  }
  const number = Number(match[1]) * TABLE_SORT_DURATION_FACTORS[match[2]];
  return Number.isFinite(number) ? number : null;
}

export function tableSortValue(value, type = "auto") {
  const text = tableSortText(value);
  if (TABLE_SORT_MISSING_VALUES.has(text.toLowerCase())) {
    return null;
  }
  if (type === "text") {
    return text;
  }
  if (type === "duration") {
    return tableSortDuration(value);
  }
  if (type === "percentage" || type === "number") {
    return tableSortNumber(value);
  }
  if (type === "bigint") {
    const normalized = text.replaceAll(",", "");
    if (!/^[+-]?(?:0x[0-9a-f]+|\d+)$/i.test(normalized)) {
      return null;
    }
    try {
      return BigInt(normalized);
    } catch {
      return null;
    }
  }
  const duration = tableSortDuration(value);
  if (duration !== null) {
    return duration;
  }
  if (/^[+-]?(?:0x[0-9a-f]+)$/i.test(text)) {
    try {
      return BigInt(text);
    } catch {
      return text;
    }
  }
  const number = tableSortNumber(value);
  return number === null ? text : number;
}

export function compareTableSortValues(
  leftValue,
  rightValue,
  { type = "auto", direction = "ascending" } = {},
) {
  const left = tableSortValue(leftValue, type);
  const right = tableSortValue(rightValue, type);
  if (left === null || right === null) {
    if (left === right) {
      return 0;
    }
    return left === null ? 1 : -1;
  }
  let comparison;
  if (typeof left === "string" || typeof right === "string") {
    comparison = tableSortCollator.compare(String(left), String(right));
  } else {
    comparison = left < right ? -1 : left > right ? 1 : 0;
  }
  return direction === "descending" ? -comparison : comparison;
}

export function nextTableSortState(current, column) {
  const nextColumn = Number(column);
  return {
    column: nextColumn,
    direction: current?.column === nextColumn && current.direction === "ascending"
      ? "descending"
      : "ascending",
  };
}

export function stableSortTableRows(
  rows,
  { type = "auto", direction = "ascending" } = {},
) {
  return rows
    .map((row, index) => ({
      row,
      index,
      sourceOrder: Number.isFinite(Number(row.sourceOrder))
        ? Number(row.sourceOrder)
        : index,
    }))
    .sort((left, right) => (
      compareTableSortValues(left.row.value, right.row.value, { type, direction })
      || left.sourceOrder - right.sourceOrder
      || left.index - right.index
    ))
    .map(({ row }) => row);
}

export function parseInspectorRoute(hash) {
  const requested = String(hash || "")
    .replace(/^#\/?/, "")
    .replace(/\?.*$/, "")
    .replace(/\/+$/, "");
  if (requested === "feedback") {
    return { route: "overview", feedbackOpen: true };
  }
  const route = LEGACY_ROUTES.get(requested) || requested;
  return {
    route: ROUTES.has(route) ? route : "overview",
    feedbackOpen: false,
  };
}

const TESTING_WORKLOAD_LABELS = {
  cpu_saturation: "CPU saturation",
  waker_wakee: "Waker / wakee",
  mixed_affinity: "Mixed affinity",
  fork_yield: "Fork / yield churn",
};

const TESTING_STATUS = {
  pending: { label: "Pending", symbol: "", className: "pending" },
  running: { label: "Running", symbol: "", className: "running" },
  passed: { label: "Passed", symbol: "✓", className: "passed" },
  failed: { label: "Failed", symbol: "×", className: "failed" },
  aborted: { label: "Stopped", symbol: "", className: "aborted" },
};

function testingRuntimeLabel(status, elapsedMs) {
  if (status === "running") return "In progress";
  if (!elapsedMs) return "Not started";
  return `${(elapsedMs / 1_000).toFixed(1)}s`;
}

function testingMemoryLabel(bytes) {
  if (!bytes) return null;
  return `${(bytes / (1024 ** 3)).toFixed(1)} GiB RAM`;
}

function testingDisplayText(value) {
  return String(value || "").replace(/\u001b\[[0-?]*[ -/]*[@-~]/g, "");
}

function testingCaseTooltip({
  fairness,
  policyName,
  workload,
  status,
  statusLabel,
  elapsedMs,
  failure,
  shard,
  shardCount,
  environment,
}) {
  const lines = [
    `${String(fairness || "unknown").toUpperCase()} · ${policyName} · ${TESTING_WORKLOAD_LABELS[workload] || workload}`,
    `Status: ${statusLabel}`,
    `Runtime: ${testingRuntimeLabel(status, elapsedMs)}`,
    `Shard: ${shard + 1} of ${shardCount}`,
  ];
  if (failure) lines.push(`Failure: ${testingDisplayText(failure)}`);
  if (environment) {
    const vm = [
      environment.virtualization || "VM",
      environment.cpu_count ? `${environment.cpu_count} vCPUs` : null,
      testingMemoryLabel(Number(environment.memory_bytes || 0)),
    ].filter(Boolean);
    if (vm.length) lines.push(`VM: ${vm.join(" · ")}`);
    if (environment.kernel_release) lines.push(`Kernel: ${environment.kernel_release}`);
    const snake = [environment.snake_version, environment.snake_fingerprint].filter(Boolean);
    if (snake.length) lines.push(`Snake: ${snake.join(" · ")}`);
    if (environment.boot_command) lines.push(`Boot: ${environment.boot_command}`);
  }
  return lines.join("\n");
}

function testingGroupResult(rows) {
  const counts = {
    total: 0,
    passed: 0,
    failed: 0,
    running: 0,
    pending: 0,
    stopped: 0,
    unassigned: 0,
  };
  for (const testCase of rows.flatMap((row) => row.cases)) {
    counts.total += 1;
    if (testCase.status === "unassigned") {
      counts.unassigned += 1;
      continue;
    }
    if (testCase.status === "passed") counts.passed += 1;
    else if (testCase.status === "failed") counts.failed += 1;
    else if (testCase.status === "running") counts.running += 1;
    else if (testCase.status === "pending") counts.pending += 1;
    else if (testCase.status === "aborted") counts.stopped += 1;
  }

  let status = "pending";
  if (counts.failed > 0) status = "failed";
  else if (counts.running > 0) status = "running";
  else if (counts.pending > 0 || counts.unassigned > 0) status = "pending";
  else if (counts.total > 0 && counts.passed === counts.total) status = "passed";
  else if (counts.stopped > 0) status = "aborted";

  const presentation = TESTING_STATUS[status] || TESTING_STATUS.pending;
  let label = `${counts.passed} / ${counts.total} passed`;
  if (status === "failed") label = `${counts.failed} failed`;
  else if (status === "running") label = `${counts.running} running · ${label}`;
  else if (status === "aborted") label = `${counts.stopped} stopped`;

  return {
    status,
    label,
    symbol: presentation.symbol,
    className: presentation.className,
    ...counts,
  };
}

export function testingMatrixModel(run) {
  const matrix = run?.matrix || {};
  const aggregate = Boolean(matrix.aggregate);
  const environments = new Map(
    (run?.shard_environments || []).map((item) => [
      Number(item.shard_index),
      item.environment,
    ]),
  );
  if (!aggregate && run?.environment && !environments.has(Number(matrix.shard_index || 0))) {
    environments.set(Number(matrix.shard_index || 0), run.environment);
  }
  const summary = { passed: 0, failed: 0, running: 0, pending: 0 };
  const workloads = (matrix.workloads || []).map((id) => ({
    id,
    label: TESTING_WORKLOAD_LABELS[id] || id,
  }));
  const groups = (matrix.groups || []).map((group) => {
    const rows = (group.rows || []).map((row) => ({
      policyId: row.policy_id,
      policyName: row.policy_name || row.policy_id,
      cases: (row.cases || []).map((testCase) => {
        const shard = Number(testCase.shard ?? matrix.shard_index ?? 0);
        const assigned = aggregate || testCase.assigned !== false;
        const status = assigned ? (testCase.status || "pending") : "unassigned";
        const presentation = assigned
          ? (TESTING_STATUS[status] || TESTING_STATUS.pending)
          : { label: "Other shard", symbol: "", className: "unassigned" };
        if (assigned) {
          if (status === "passed") summary.passed += 1;
          else if (status === "failed") summary.failed += 1;
          else if (status === "running") summary.running += 1;
          else if (status === "pending") summary.pending += 1;
        }
        return {
          id: testCase.id,
          workload: testCase.workload,
          assigned,
          status,
          label: presentation.label,
          symbol: presentation.symbol,
          className: presentation.className,
          elapsedMs: Number(testCase.elapsed_ms || 0),
          failure: testCase.failure || null,
          shard,
          tooltip: testingCaseTooltip({
            fairness: group.fairness,
            policyName: row.policy_name || row.policy_id,
            workload: testCase.workload,
            status,
            statusLabel: presentation.label,
            elapsedMs: Number(testCase.elapsed_ms || 0),
            failure: testCase.failure || null,
            shard,
            shardCount: Number(matrix.shard_count || 1),
            environment: environments.get(shard),
          }),
        };
      }),
    }));
    return {
      fairness: group.fairness,
      label: String(group.fairness || "unknown").toUpperCase(),
      rows,
      result: testingGroupResult(rows),
    };
  });
  const status = String(run?.status || "idle");
  return {
    status,
    statusLabel: status.charAt(0).toUpperCase() + status.slice(1),
    durationSecs: Number(matrix.duration_secs || 60),
    shardIndex: Number(matrix.shard_index || 0),
    shardCount: Number(matrix.shard_count || 1),
    assignedCases: Number(matrix.assigned_cases || 0),
    totalCases: Number(matrix.total_cases || 0),
    aggregate,
    reportingShards: Number(matrix.reporting_shards || 0),
    workloads,
    groups,
    summary,
  };
}

export function testingCampaignTabs(runs, selectedKey = null) {
  const campaigns = Array.isArray(runs) ? runs : [];
  const baseLabels = campaigns.map((run, index) => (
    run?.environment?.kernel_release
      || run?.shard_environments?.[0]?.environment?.kernel_release
      || run?.campaign_id
      || `Campaign ${index + 1}`
  ));
  const baseCounts = new Map();
  for (const label of baseLabels) {
    baseCounts.set(label, (baseCounts.get(label) || 0) + 1);
  }
  const labels = baseLabels.map((label, index) => (
    baseCounts.get(label) > 1
      ? `${label} · ${campaigns[index]?.campaign_id || `Campaign ${index + 1}`}`
      : label
  ));
  const labelCounts = new Map();
  for (const label of labels) {
    labelCounts.set(label, (labelCounts.get(label) || 0) + 1);
  }

  const tabs = campaigns.map((run, index) => {
    const matrix = testingMatrixModel(run);
    const cases = matrix.groups
      .flatMap((group) => group.rows)
      .flatMap((row) => row.cases);
    const total = cases.length;
    const passed = cases.filter((testCase) => testCase.status === "passed").length;
    const failed = cases.filter((testCase) => testCase.status === "failed").length;
    const running = run?.status === "running";
    const complete = run?.status === "completed" && total > 0 && passed === total;
    const status = failed > 0
      ? "failed"
      : (complete ? "passed" : (running ? "running" : "pending"));
    const presentation = TESTING_STATUS[status] || TESTING_STATUS.pending;
    const label = labelCounts.get(labels[index]) > 1
      ? `${labels[index]} · ${index + 1}`
      : labels[index];
    return {
      key: `campaign:${index}`,
      label,
      status,
      symbol: status === "passed" || status === "failed" ? presentation.symbol : "",
      className: presentation.className,
      summary: failed > 0
        ? `${running ? "Running \u00b7 " : ""}${failed} failed`
        : `${running ? "Running \u00b7 " : ""}${passed} / ${total} passed`,
      passed,
      failed,
      total,
      run,
    };
  });
  const selected = tabs.find((tab) => tab.key === selectedKey) || tabs[0] || null;
  return {
    tabs,
    selectedKey: selected?.key || null,
    selectedRun: selected?.run || null,
  };
}

export function routeFromHash(hash) {
  return parseInspectorRoute(hash).route;
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

const CELL_STATUSES = new Set([
  "ready",
  "not_applicable",
  "unsupported",
  "synchronizing",
  "unavailable",
]);
const CELL_STATUS_LABELS = {
  ready: "Ready",
  not_applicable: "Not applicable to this policy",
  unsupported: "Unsupported by this Snake version",
  synchronizing: "Synchronizing policy statistics",
  unavailable: "Cell statistics unavailable",
};
const CELL_COUNTER_FIELDS = [
  "runtime_ns",
  "primary_runtime_ns",
  "borrowed_runtime_ns",
  "lent_runtime_ns",
  "normal_enqueues",
  "affinity_enqueues",
  "normal_dispatches",
  "affinity_dispatches",
  "clock_transitions",
];
const cellMetricNumberFormat = new Intl.NumberFormat("en-US", {
  maximumFractionDigits: 1,
});

function finiteValue(...values) {
  for (const value of values) {
    if (value == null || value === "") {
      continue;
    }
    const number = Number(value);
    if (Number.isFinite(number)) {
      return number;
    }
  }
  return null;
}

export function schedulerUptimeLabel(
  control,
  lastSuccessAt,
  now = Date.now(),
  pollError = null,
  pollIntervalMs = 2_000,
) {
  if (!control) {
    return "—";
  }
  const elapsedSincePoll = Math.max(0, Number(now) - Number(lastSuccessAt || now));
  const stale = elapsedSincePoll > pollIntervalMs * 2
    || (Boolean(pollError) && elapsedSincePoll >= pollIntervalMs * 2);
  if (!control.active && control.pid == null) {
    return stale ? "Stale · stopped" : "Stopped";
  }
  const reported = finiteValue(control.uptime_ms);
  if (reported === null) {
    const state = control.active ? "unavailable" : "starting";
    return stale
      ? `Stale · ${state}`
      : `${state[0].toUpperCase()}${state.slice(1)}`;
  }
  const totalSeconds = Math.floor(
    (Math.max(0, reported) + (stale ? 0 : elapsedSincePoll)) / 1_000,
  );
  const days = Math.floor(totalSeconds / 86_400);
  const hours = Math.floor((totalSeconds % 86_400) / 3_600);
  const minutes = Math.floor((totalSeconds % 3_600) / 60);
  const seconds = totalSeconds % 60;
  const clock = `${days > 0 ? String(hours).padStart(2, "0") : hours}:${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`;
  const uptime = days > 0 ? `${days}d ${clock}` : clock;
  if (stale) {
    return `Stale · ${uptime}`;
  }
  return control.active ? uptime : `Starting · ${uptime}`;
}

function normalizedCell(cell, observedMs) {
  const raw = Object.fromEntries(
    CELL_COUNTER_FIELDS.map((field) => [field, Math.max(0, finiteValue(cell?.[field]) ?? 0)]),
  );
  const observedSeconds = Number(observedMs) > 0 ? Number(observedMs) / 1_000 : null;
  const primaryCpuCount = finiteValue(cell?.primary_cpu_count);
  const ownedCapacityNs = primaryCpuCount > 0 && Number(observedMs) > 0
    ? primaryCpuCount * Number(observedMs) * 1_000_000
    : null;
  const perSecond = (count) => observedSeconds === null
    ? null
    : Number((count / observedSeconds).toFixed(4));
  return {
    id: finiteValue(cell?.id, cell?.cell_id, cell?.external_id),
    index: finiteValue(cell?.index, cell?.cell_index),
    primaryCpuCount,
    raw,
    serviceCores: finiteValue(cell?.service_cores),
    serviceSharePct: finiteValue(cell?.service_share_pct),
    primaryPct: finiteValue(cell?.primary_pct, cell?.primary_runtime_pct),
    borrowedPct: finiteValue(cell?.borrowed_pct, cell?.borrowed_runtime_pct),
    lentPct: finiteValue(cell?.lent_pct, cell?.lent_runtime_pct)
      ?? (ownedCapacityNs === null ? null : raw.lent_runtime_ns * 100 / ownedCapacityNs),
    ownedUtilizationPct: finiteValue(cell?.owned_utilization_pct),
    normalEnqueueRate: finiteValue(
      cell?.normal_enqueues_per_second,
      cell?.normal_enqueue_rate,
      perSecond(raw.normal_enqueues),
    ),
    affinityEnqueueRate: finiteValue(
      cell?.affinity_enqueues_per_second,
      cell?.affinity_enqueue_rate,
      perSecond(raw.affinity_enqueues),
    ),
    normalDispatchRate: finiteValue(
      cell?.normal_dispatches_per_second,
      cell?.normal_dispatch_rate,
      perSecond(raw.normal_dispatches),
    ),
    affinityDispatchRate: finiteValue(
      cell?.affinity_dispatches_per_second,
      cell?.affinity_dispatch_rate,
      perSecond(raw.affinity_dispatches),
    ),
    affinityEnqueuePct: finiteValue(
      cell?.affinity_enqueue_share_pct,
      cell?.affinity_enqueue_pct,
    ),
    affinityDispatchPct: finiteValue(
      cell?.affinity_dispatch_share_pct,
      cell?.affinity_dispatch_pct,
    ),
    clockTransitionRate: finiteValue(
      cell?.transition_rate_per_second,
      cell?.clock_transitions_per_second,
      cell?.clock_transition_rate,
    ),
    transitionsPer1kDispatches: finiteValue(cell?.transitions_per_1k_dispatches),
  };
}

export function cellStatsModel(payload, { policyGeneration = null } = {}) {
  const requestedStatus = String(payload?.status || "unavailable").toLowerCase();
  let status = CELL_STATUSES.has(requestedStatus) ? requestedStatus : "unavailable";
  if (
    status === "ready"
    && policyGeneration != null
    && (payload?.source_policy_generation ?? payload?.policy_generation) != null
    && Number(policyGeneration)
      !== Number(payload.source_policy_generation ?? payload.policy_generation)
  ) {
    status = "synchronizing";
  }
  const cells = (payload?.cells || [])
    .map((cell) => normalizedCell(cell, payload?.observed_ms))
    .filter((cell) => Number.isSafeInteger(cell.id) && cell.id >= 0)
    .sort((left, right) => left.id - right.id);
  const zeroActivity = status === "ready"
    && cells.length > 0
    && cells.every((cell) => CELL_COUNTER_FIELDS.every((field) => cell.raw[field] === 0));
  return {
    status,
    statusLabel: CELL_STATUS_LABELS[status],
    error: payload?.error || null,
    scope: payload?.scope || null,
    policyGeneration: finiteValue(
      payload?.source_policy_generation,
      payload?.policy_generation,
    ),
    windowMs: finiteValue(payload?.window_ms),
    observedMs: finiteValue(payload?.observed_ms),
    zeroActivity,
    cells,
  };
}

export function formatCellMetric(value, kind = "number") {
  const number = finiteValue(value);
  if (number === null) {
    return "—";
  }
  if (kind === "percentage") {
    return `${number.toFixed(1)}%`;
  }
  if (kind === "cores") {
    return number.toFixed(2);
  }
  if (kind === "rate") {
    return `${cellMetricNumberFormat.format(number)}/s`;
  }
  if (kind === "duration") {
    if (number >= 1_000_000_000) {
      return `${cellMetricNumberFormat.format(number / 1_000_000_000)} s`;
    }
    if (number >= 1_000_000) {
      return `${cellMetricNumberFormat.format(number / 1_000_000)} ms`;
    }
    if (number >= 1_000) {
      return `${cellMetricNumberFormat.format(number / 1_000)} µs`;
    }
    return `${cellMetricNumberFormat.format(number)} ns`;
  }
  return cellMetricNumberFormat.format(number);
}

const QUEUE_TIMING_STATUSES = new Set([
  "ready",
  "disabled",
  "not_applicable",
  "unsupported",
  "synchronizing",
  "unavailable",
]);
const QUEUE_TIMING_STATUS_LABELS = {
  ready: "Available",
  disabled: "Sampling disabled",
  not_applicable: "Not applicable",
  unsupported: "Unsupported",
  synchronizing: "Synchronizing",
  unavailable: "Unavailable",
};

function canonicalDsqKey(value) {
  if (value == null || value === "") {
    return null;
  }
  try {
    return BigInt(String(value)).toString();
  } catch {
    return String(value).toLowerCase();
  }
}

function normalizeQueueTimingDsq(dsq) {
  const residence = dsq?.residence || {};
  const depth = dsq?.depth || {};
  const samples = Math.max(0, finiteValue(residence.samples, dsq?.samples) ?? 0);
  const depthSamples = Math.max(0, finiteValue(depth.samples, samples) ?? 0);
  const dsqId = dsq?.dsq_id ?? dsq?.id ?? null;
  return {
    dsqId,
    dsqKey: canonicalDsqKey(dsqId),
    label: formatDsqId(dsqId),
    kind: dsqKind(dsqId),
    queueClass: String(dsq?.queue_class || dsq?.kind || "unknown").toLowerCase(),
    cpu: finiteValue(dsq?.cpu),
    cellId: finiteValue(dsq?.cell_id, dsq?.cell_index),
    cellIndex: finiteValue(dsq?.cell_index),
    residence: {
      samples,
      totalNs: finiteValue(residence.total_ns),
      meanNs: finiteValue(residence.mean_ns, dsq?.mean_ns),
      p50Ns: finiteValue(residence.p50_ns, dsq?.p50_ns),
      p95Ns: samples >= 20 ? finiteValue(residence.p95_ns, dsq?.p95_ns) : null,
      p99Ns: samples >= 100 ? finiteValue(residence.p99_ns, dsq?.p99_ns) : null,
    },
    depth: {
      samples: depthSamples,
      latest: finiteValue(depth.latest, depth.latest_value, dsq?.depth_latest),
      p95: depthSamples >= 20 ? finiteValue(depth.p95, dsq?.depth_p95) : null,
      max: finiteValue(depth.max, dsq?.depth_max),
    },
  };
}

export function queueTimingModel(payload, { context = null, pending = false } = {}) {
  let status = String(payload?.status || "unavailable").toLowerCase();
  if (!QUEUE_TIMING_STATUSES.has(status)) {
    status = "unavailable";
  }
  if (context && payload?.context && !contextsMatch(context, payload.context)) {
    status = "synchronizing";
  }
  const sampleRate = Math.max(0, finiteValue(payload?.sample_rate) ?? 0);
  const payloadCapture = payload?.capture || (
    payload?.state != null
    || payload?.session_id != null
    || Array.isArray(payload?.dsqs)
      ? payload
      : null
  );
  let capture = status === "synchronizing" ? null : payloadCapture;
  let state = ["collecting", "historical"].includes(capture?.state)
    ? capture.state
    : "inactive";
  const captureGeneration = finiteValue(payloadCapture?.policy_generation);
  const contextGeneration = finiteValue(context?.policy_generation);
  const generationMismatch = captureGeneration !== null
    && contextGeneration !== null
    && captureGeneration !== contextGeneration;
  if (state === "collecting" && generationMismatch) {
    status = "synchronizing";
    capture = null;
    state = "inactive";
  }
  const stateLabel = state === "collecting"
    ? "Collecting"
    : state === "historical"
      ? "Historical"
      : "Inactive";
  const topologyCompatible = status !== "synchronizing"
    && !generationMismatch;
  const counts = {
    started: Math.max(0, finiteValue(capture?.started_count, capture?.started_samples) ?? 0),
    completed: Math.max(
      0,
      finiteValue(capture?.completed_count, capture?.completed_samples) ?? 0,
    ),
    dropped: Math.max(
      0,
      finiteValue(
        capture?.dropped_count,
        capture?.dropped_samples,
        capture?.dropped_events,
      ) ?? 0,
    ),
  };
  return {
    sequence: finiteValue(payload?.sequence),
    status,
    statusLabel: QUEUE_TIMING_STATUS_LABELS[status],
    error: payload?.error || null,
    sampleRate,
    sampleRateLabel: sampleRate === 0 ? "Sampling off" : `1 / ${sampleRate.toLocaleString()}`,
    capture,
    state,
    stateLabel,
    topologyCompatible,
    checked: state === "collecting",
    controlDisabled: Boolean(pending) || status !== "ready" || sampleRate === 0,
    counts,
    dsqs: (capture?.dsqs || []).map(normalizeQueueTimingDsq),
  };
}

function emptyQueueTiming() {
  return {
    dsqId: null,
    dsqKey: null,
    queueClass: "unknown",
    cpu: null,
    cellId: null,
    cellIndex: null,
    residence: {
      samples: 0,
      totalNs: null,
      meanNs: null,
      p50Ns: null,
      p95Ns: null,
      p99Ns: null,
    },
    depth: { samples: 0, latest: null, p95: null, max: null },
  };
}

export function mergeQueueTimingTopology(topologyModel, timingModel) {
  const dsqs = timingModel?.topologyCompatible === false
    ? []
    : timingModel?.dsqs || [];
  const findTiming = (dsqId, queueClass) => {
    const key = canonicalDsqKey(dsqId);
    return dsqs.find((timing) => (
      timing.dsqKey === key
      && (timing.queueClass === queueClass || timing.queueClass === "unknown")
    )) || emptyQueueTiming();
  };
  return {
    ...topologyModel,
    normalQueues: (topologyModel?.normalQueues || []).map((queue) => ({
      ...queue,
      timing: findTiming(queue.dsq_id, "normal"),
    })),
    cpuRoutes: (topologyModel?.cpuRoutes || []).map((route) => ({
      ...route,
      affinityTiming: findTiming(route.affinity_dsq_id, "affinity"),
    })),
  };
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
        context.active_slot == null ? null : `rung set ${context.active_slot}`,
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

export function overviewModel({
  snapshot,
  callbackTiming,
  inspection,
  control,
  topology,
  queueTiming,
  hostContext,
  errors = [],
} = {}) {
  const context = inspection?.context || snapshot?.context || control?.context || null;
  const activeSlot = (inspection?.slots || []).find((slot) => slot.state === "active") || null;
  const routes = (snapshot?.cells || [])
    .filter((route) => Number.isFinite(Number(route?.count)));
  const busiestRoute = routes.reduce((busiest, route) => (
    !busiest || Number(route.count) > Number(busiest.count) ? route : busiest
  ), null);
  const callbacks = callbackTiming?.callbacks || [];
  const slowest = callbacks.reduce((candidate, callback) => {
    const p99Ns = Number(callback?.p99_ns);
    if (!Number.isFinite(p99Ns)) {
      return candidate;
    }
    if (!candidate || p99Ns > candidate.p99Ns) {
      return {
        callback: String(callback.callback || "unknown"),
        samples: Math.max(0, Number(callback.samples) || 0),
        p99Ns,
      };
    }
    return candidate;
  }, null);
  const queue = queueTopologyModel(
    inspection?.fairness,
    inspection?.queue_topology,
    topology?.numeric_order || [],
  );
  const cellStats = cellStatsModel(snapshot?.cell_stats, {
    policyGeneration: context?.policy_generation ?? null,
  });
  const timing = queueTimingModel(queueTiming, { context });
  const rankedCallbacks = callbacks
    .map((callback) => ({
      callback: String(callback?.callback || "unknown"),
      samples: Math.max(0, Number(callback?.samples) || 0),
      p99Ns: finiteValue(callback?.p99_ns),
    }))
    .filter((callback) => callback.p99Ns !== null)
    .sort((left, right) => right.p99Ns - left.p99Ns)
    .slice(0, 3);
  const rankedCells = [...cellStats.cells]
    .sort((left, right) => (
      (right.ownedUtilizationPct ?? -1) - (left.ownedUtilizationPct ?? -1)
      || (right.borrowedPct ?? -1) - (left.borrowedPct ?? -1)
      || left.id - right.id
    ))
    .slice(0, 3);
  const rankedBorrowers = [...cellStats.cells]
    .filter((cell) => cell.borrowedPct !== null)
    .sort((left, right) => right.borrowedPct - left.borrowedPct || left.id - right.id)
    .slice(0, 3);
  const rankedLenders = [...cellStats.cells]
    .filter((cell) => cell.lentPct !== null)
    .sort((left, right) => right.lentPct - left.lentPct || left.id - right.id)
    .slice(0, 3);
  const rankedQueues = timing.dsqs
    .map((dsq) => ({
      dsqId: dsq.dsqId,
      queueClass: dsq.queueClass,
      cellId: dsq.cellId,
      cpu: dsq.cpu,
      samples: dsq.residence.samples,
      p99Ns: dsq.residence.p99Ns,
      p95Depth: dsq.depth.p95,
    }))
    .filter((dsq) => dsq.p99Ns !== null || dsq.p95Depth !== null)
    .sort((left, right) => (
      (right.p99Ns ?? -1) - (left.p99Ns ?? -1)
      || (right.p95Depth ?? -1) - (left.p95Depth ?? -1)
    ))
    .slice(0, 3);
  const ladderRates = ladderPercentages(activeSlot?.metrics);
  const rankedRungs = (activeSlot?.policy?.rungs || [])
    .map((rung) => ({
      index: finiteValue(rung?.index),
      operation: String(rung?.operation || "unknown"),
      ...rungTimingSummary(rung?.timing),
    }))
    .filter((rung) => rung.p95Ns !== null)
    .sort((left, right) => right.p95Ns - left.p95Ns)
    .slice(0, 3);
  const jobs = new Map();
  for (const task of hostContext?.tupperware?.data || []) {
    const jobHandle = String(task?.job_handle || "").trim();
    const taskId = String(task?.task_id ?? "").trim();
    if (!jobHandle || !taskId) {
      continue;
    }
    if (!jobs.has(jobHandle)) {
      jobs.set(jobHandle, []);
    }
    jobs.get(jobHandle).push(taskId);
  }
  const allotmentGroups = new Map();
  for (const allotment of hostContext?.allotments?.data || []) {
    const shape = String(allotment?.shape || "Unknown");
    const ownership = String(allotment?.ownership || "Unknown");
    const state = String(allotment?.state || "Unknown");
    const key = `${shape}\u0000${ownership}\u0000${state}`;
    const group = allotmentGroups.get(key) || {
      shape,
      ownership,
      state,
      count: 0,
      owners: [],
    };
    group.count += 1;
    const owner = String(allotment?.owner || "").trim();
    if (owner && !group.owners.includes(owner)) {
      group.owners.push(owner);
    }
    allotmentGroups.set(key, group);
  }
  const reportedWarnings = [
    snapshot?.collector_error,
    snapshot?.pair_map_failures || snapshot?.task_storage_failures
      ? `${Number(snapshot?.pair_map_failures || 0)} pair-map failures · ${Number(snapshot?.task_storage_failures || 0)} task-state failures`
      : null,
    snapshot?.cpu_usage_error,
    callbackTiming?.error,
    inspection?.error,
    timing.counts.dropped > 0
      ? `${timing.counts.dropped} queue timing samples dropped`
      : null,
    queue.expectedCpuCount > 0 && !queue.routesComplete
      ? `CPU routing incomplete: ${queue.cpuRoutes.length} / ${queue.expectedCpuCount}`
      : null,
    ...errors,
  ].filter((warning, index, all) => (
    typeof warning === "string"
    && warning.trim().length > 0
    && all.indexOf(warning) === index
  ));
  return {
    runtime: runtimeContextModel({ snapshot, inspection, control }),
    warnings: reportedWarnings,
    activity: {
      available: Boolean(snapshot),
      total: Math.max(0, Number(snapshot?.total) || 0),
      ratePerSecond: Math.max(0, Number(snapshot?.rate_per_second) || 0),
      activePairs: Math.max(0, Number(snapshot?.active_pairs) || 0),
      observedMs: Math.max(0, Number(snapshot?.observed_ms) || 0),
      windowMs: Math.max(0, Number(snapshot?.window_ms) || 0),
      busiestRoute: busiestRoute
        ? {
            from: Number(busiestRoute.from),
            to: Number(busiestRoute.to),
            count: Number(busiestRoute.count),
          }
        : null,
      selectCalls: Math.max(0, Number(activeSlot?.metrics?.select_calls) || 0),
      directDispatches: Math.max(0, Number(activeSlot?.metrics?.direct_dispatches) || 0),
      ladderExhaustions: Math.max(0, Number(activeSlot?.metrics?.ladder_exhaustions) || 0),
      directDispatchPct: ladderRates.hit,
      exhaustionPct: ladderRates.miss,
    },
    callbacks: {
      available: Boolean(callbackTiming),
      sampleRate: Math.max(0, Number(callbackTiming?.sample_rate) || 0),
      generation: callbackTiming?.generation ?? null,
      sampleCount: callbacks.reduce(
        (total, callback) => total + Math.max(0, Number(callback?.samples) || 0),
        0,
      ),
      slowest,
    },
    policy: {
      available: Boolean(inspection || control),
      policyId: control?.policy_id || null,
      fairness: context?.fairness || inspection?.fairness?.mode_name || null,
      generation: context?.policy_generation ?? activeSlot?.generation ?? null,
      activeSlot: context?.active_slot ?? activeSlot?.slot ?? null,
      queueLayout: queue.layout,
      cpuRouteCount: queue.cpuRoutes.length,
      expectedCpuCount: queue.expectedCpuCount,
      routesComplete: queue.routesComplete,
    },
    cells: {
      available: Boolean(inspection),
      cellCount: inspection?.cells?.length || 0,
      taskCount: inspection?.task_mappings?.length || 0,
    },
    tuning: {
      cells: {
        status: cellStats.status,
        statusLabel: cellStats.statusLabel,
        ranked: rankedCells,
        borrowers: rankedBorrowers,
        lenders: rankedLenders,
      },
      queues: {
        status: timing.status,
        statusLabel: timing.statusLabel,
        state: timing.state,
        stateLabel: timing.stateLabel,
        droppedSamples: timing.counts.dropped,
        ranked: rankedQueues,
      },
      callbacks: {
        available: Boolean(callbackTiming),
        windowMs: finiteValue(callbackTiming?.window_ms),
        ranked: rankedCallbacks,
      },
      rungs: {
        available: rankedRungs.length > 0,
        ranked: rankedRungs,
      },
    },
    host: {
      available: Boolean(hostContext),
      identity: hostContext?.identity || null,
      resourceBrowser: hostContext?.resource_browser || null,
      taskState: hostContext?.tupperware?.state || "loading",
      taskMessage: hostContext?.tupperware?.message || null,
      jobs: [...jobs.entries()]
        .map(([jobHandle, taskIds]) => ({
          jobHandle,
          taskIds: taskIds.sort((left, right) => left.localeCompare(right, undefined, {
            numeric: true,
          })),
        }))
        .sort((left, right) => left.jobHandle.localeCompare(right.jobHandle)),
      allotmentState: hostContext?.allotments?.state || "loading",
      allotmentMessage: hostContext?.allotments?.message || null,
      allotmentGroups: [...allotmentGroups.values()],
      charts: hostContext?.charts || [],
    },
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

export function captureKeyedRenderState(
  nodes,
  activeElement = null,
  viewport = null,
) {
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
  const viewportScroll = Number.isFinite(viewport?.scrollX)
    && Number.isFinite(viewport?.scrollY)
    ? { left: viewport.scrollX, top: viewport.scrollY }
    : null;
  return { entries, focusedKey, viewportScroll };
}

export function restoreKeyedRenderState(nodes, snapshot, viewport = null) {
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
  if (snapshot.viewportScroll && typeof viewport?.scrollTo === "function") {
    viewport.scrollTo(snapshot.viewportScroll.left, snapshot.viewportScroll.top);
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

export function nanosecondDurationClass(value) {
  const nanoseconds = Number(value);
  if (!Number.isFinite(nanoseconds)) {
    return "";
  }
  if (nanoseconds > 10_000) {
    return "duration-critical";
  }
  return nanoseconds > 1_000 ? "duration-warning" : "";
}

const FINE_TIMING_CALLBACKS = [
  { callback: "select_cpu", label: "Select CPU" },
  { callback: "enqueue", label: "Enqueue" },
  { callback: "dispatch", label: "Dispatch" },
  { callback: "runnable", label: "Runnable" },
  { callback: "running", label: "Running" },
  { callback: "stopping", label: "Stopping" },
  { callback: "quiescent", label: "Quiescent" },
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

function emptyDsqOperationTiming() {
  return {
    samples: 0,
    meanNs: null,
    p50Ns: null,
    p95Ns: null,
    p99Ns: null,
  };
}

function normalizeDsqOperationTiming(operation) {
  return {
    samples: Math.max(0, finiteValue(operation?.samples) ?? 0),
    meanNs: finiteValue(operation?.mean_ns),
    p50Ns: finiteValue(operation?.p50_ns),
    p95Ns: finiteValue(operation?.p95_ns),
    p99Ns: finiteValue(operation?.p99_ns),
  };
}

function dsqKind(dsqId) {
  let id;
  try {
    id = BigInt(String(dsqId));
  } catch {
    return "Custom";
  }
  if ((id & 0xffffffff00000000n) === 0xc000000000000000n) {
    return `Local CPU ${id & 0xffffffffn}`;
  }
  if (id === 0x8000000000000002n) {
    return "Local CPU";
  }
  if (id === 0x30000000n) {
    return "FIFO global";
  }
  if (id >= 0x10000000n && id < 0x10000000n + 1024n) {
    return "Affinity";
  }
  if (id >= 0x20000000n && id < 0x20000000n + 1024n) {
    return "Normal";
  }
  if (id === 0n) {
    return "EEVDF eligible";
  }
  if (id === 1n) {
    return "EEVDF future";
  }
  if (id === 2n) {
    return "VTIME global";
  }
  if (id >= 3n && id < 3n + 1024n) {
    return "VTIME CPU";
  }
  return "Custom";
}

export function fineTimingDsqModels(payload) {
  const rows = new Map();
  const currentGeneration = finiteValue(payload?.context?.policy_generation);
  for (const capture of payload?.captures || []) {
    const captureGeneration = finiteValue(capture?.policy_generation);
    if (
      currentGeneration !== null
      && captureGeneration !== null
      && captureGeneration !== currentGeneration
    ) {
      continue;
    }
    for (const operation of capture?.dsq_operations || []) {
      const dsqId = canonicalDsqKey(operation?.dsq_id);
      if (dsqId === null) {
        continue;
      }
      const key = canonicalDsqKey(dsqId);
      if (!rows.has(key)) {
        rows.set(key, {
          dsqId,
          label: formatDsqId(dsqId),
          kind: dsqKind(dsqId),
          insertSuccess: emptyDsqOperationTiming(),
          insertError: emptyDsqOperationTiming(),
          moveSuccess: emptyDsqOperationTiming(),
          moveMiss: emptyDsqOperationTiming(),
        });
      }
      const row = rows.get(key);
      const timing = normalizeDsqOperationTiming(operation);
      if (operation.operation === "insert" && operation.outcome === "success") {
        row.insertSuccess = timing;
      } else if (operation.operation === "insert" && operation.outcome === "error") {
        row.insertError = timing;
      } else if (
        operation.operation === "remove"
        && operation.outcome === "success"
      ) {
        row.moveSuccess = timing;
      } else if (operation.operation === "remove" && operation.outcome === "miss") {
        row.moveMiss = timing;
      }
    }
  }
  return [...rows.values()].sort((left, right) => {
    const leftId = BigInt(left.dsqId);
    const rightId = BigInt(right.dsqId);
    return leftId < rightId ? -1 : leftId > rightId ? 1 : 0;
  });
}

export function dsqActivityModels(operationDsqs, queueTimingDsqs) {
  const rows = new Map();
  const emptyOperations = () => ({
    insertSuccess: emptyDsqOperationTiming(),
    insertError: emptyDsqOperationTiming(),
    moveSuccess: emptyDsqOperationTiming(),
    moveMiss: emptyDsqOperationTiming(),
  });
  const emptyQueue = () => {
    const timing = emptyQueueTiming();
    return { residence: timing.residence, depth: timing.depth };
  };
  const createRow = (dsqId) => ({
    dsqId,
    label: formatDsqId(dsqId),
    kind: dsqKind(dsqId),
    queueClass: "unknown",
    hasOperations: false,
    hasQueueTiming: false,
    ...emptyOperations(),
    ...emptyQueue(),
  });

  for (const timing of queueTimingDsqs || []) {
    const key = timing?.dsqKey ?? canonicalDsqKey(timing?.dsqId);
    if (key === null) {
      continue;
    }
    rows.set(key, {
      ...createRow(key),
      label: timing.label || formatDsqId(key),
      kind: timing.kind || dsqKind(key),
      queueClass: timing.queueClass || "unknown",
      hasQueueTiming: true,
      residence: timing.residence,
      depth: timing.depth,
    });
  }

  for (const operation of operationDsqs || []) {
    const key = canonicalDsqKey(operation?.dsqId);
    if (key === null) {
      continue;
    }
    const row = rows.get(key) || createRow(key);
    rows.set(key, {
      ...row,
      label: operation.label || row.label,
      kind: operation.kind || row.kind,
      hasOperations: true,
      insertSuccess: operation.insertSuccess,
      insertError: operation.insertError,
      moveSuccess: operation.moveSuccess,
      moveMiss: operation.moveMiss,
    });
  }

  return [...rows.values()].sort((left, right) => {
    try {
      const leftId = BigInt(left.dsqId);
      const rightId = BigInt(right.dsqId);
      return leftId < rightId ? -1 : leftId > rightId ? 1 : 0;
    } catch {
      return String(left.dsqId).localeCompare(String(right.dsqId));
    }
  });
}

function emptyTrafficMetric() {
  return { samples: 0, ratePerSecond: null, intensity: 0 };
}

function addTrafficMetric(metric, samples, rateMultiplier) {
  const count = Math.max(0, finiteValue(samples) ?? 0);
  metric.samples += count;
  if (rateMultiplier !== null) {
    metric.ratePerSecond = (metric.ratePerSecond ?? 0) + count * rateMultiplier;
  }
}

function mergeTrafficMetric(target, source) {
  target.samples += source.samples;
  if (source.ratePerSecond !== null) {
    target.ratePerSecond = (target.ratePerSecond ?? 0) + source.ratePerSecond;
  }
}

function captureRateMultiplier(capture, sampleRate, nowMs) {
  const startedAt = finiteValue(capture?.started_at_ms);
  const stoppedAt = finiteValue(capture?.stopped_at_ms);
  const end = stoppedAt ?? finiteValue(nowMs);
  if (sampleRate <= 0 || startedAt === null || end === null || end <= startedAt) {
    return null;
  }
  return sampleRate * 1_000 / (end - startedAt);
}

function trafficScore(metric) {
  return metric.ratePerSecond ?? metric.samples;
}

function trafficIntensity(metric, maxRatePerSecond, maxSamples) {
  const value = maxRatePerSecond > 0 && metric.ratePerSecond !== null
    ? metric.ratePerSecond
    : metric.samples;
  const max = maxRatePerSecond > 0 && metric.ratePerSecond !== null
    ? maxRatePerSecond
    : maxSamples;
  return value > 0 && max > 0 ? Math.log1p(value) / Math.log1p(max) : 0;
}

function compareDsqKeys(left, right) {
  try {
    const leftId = BigInt(left);
    const rightId = BigInt(right);
    return leftId < rightId ? -1 : leftId > rightId ? 1 : 0;
  } catch {
    return String(left).localeCompare(String(right));
  }
}

function trafficGenerationMatches(payload, capture) {
  const currentGeneration = finiteValue(payload?.context?.policy_generation);
  const captureGeneration = finiteValue(capture?.policy_generation);
  return currentGeneration === null
    || captureGeneration === null
    || currentGeneration === captureGeneration;
}

export function dsqActivityHeatmapModel(
  payload,
  queueTimingDsqs = [],
  { limit = 12, nowMs = Date.now() } = {},
) {
  const queueTiming = new Map((queueTimingDsqs || []).map((timing) => [
    timing?.dsqKey ?? canonicalDsqKey(timing?.dsqId),
    timing,
  ]));
  const rows = new Map();
  const sampleRate = Math.max(0, finiteValue(payload?.sample_rate) ?? 0);
  const createRow = (dsqId) => {
    const timing = queueTiming.get(dsqId);
    return {
      dsqId,
      label: formatDsqId(dsqId),
      kind: dsqKind(dsqId),
      queueClass: timing?.queueClass || "unknown",
      insert: emptyTrafficMetric(),
      remove: emptyTrafficMetric(),
      failed: emptyTrafficMetric(),
      total: emptyTrafficMetric(),
      residence: timing?.residence || null,
      depth: timing?.depth || null,
      otherCount: 0,
    };
  };

  for (const capture of payload?.captures || []) {
    if (!trafficGenerationMatches(payload, capture)) {
      continue;
    }
    const rateMultiplier = captureRateMultiplier(capture, sampleRate, nowMs);
    for (const operation of capture?.dsq_operations || []) {
      const dsqId = canonicalDsqKey(operation?.dsq_id);
      if (dsqId === null) {
        continue;
      }
      const samples = Math.max(0, finiteValue(operation?.samples) ?? 0);
      if (samples === 0) {
        continue;
      }
      const row = rows.get(dsqId) || createRow(dsqId);
      rows.set(dsqId, row);
      if (operation.operation === "insert" && operation.outcome === "success") {
        addTrafficMetric(row.insert, samples, rateMultiplier);
        addTrafficMetric(row.total, samples, rateMultiplier);
      } else if (operation.operation === "remove" && operation.outcome === "success") {
        addTrafficMetric(row.remove, samples, rateMultiplier);
        addTrafficMetric(row.total, samples, rateMultiplier);
      } else if (operation.outcome === "miss" || operation.outcome === "error") {
        addTrafficMetric(row.failed, samples, rateMultiplier);
      }
    }
  }

  const ranked = [...rows.values()].sort((left, right) => (
    trafficScore(right.total) - trafficScore(left.total)
    || trafficScore(right.failed) - trafficScore(left.failed)
    || compareDsqKeys(left.dsqId, right.dsqId)
  ));
  const safeLimit = Math.max(1, Math.trunc(finiteValue(limit) ?? 12));
  const visible = ranked.slice(0, safeLimit);
  const remainder = ranked.slice(safeLimit);
  if (remainder.length > 0) {
    const other = createRow(null);
    other.label = "Other";
    other.kind = `${remainder.length} lower-traffic DSQs`;
    other.queueClass = "mixed";
    other.otherCount = remainder.length;
    for (const row of remainder) {
      for (const key of ["insert", "remove", "failed", "total"]) {
        mergeTrafficMetric(other[key], row[key]);
      }
    }
    visible.push(other);
  }

  const metrics = visible.flatMap((row) => [row.insert, row.remove, row.failed]);
  const maxRatePerSecond = Math.max(
    0,
    ...metrics.map((metric) => metric.ratePerSecond ?? 0),
  );
  const maxSamples = Math.max(0, ...metrics.map((metric) => metric.samples));
  for (const row of visible) {
    for (const key of ["insert", "remove", "failed"]) {
      row[key].intensity = trafficIntensity(row[key], maxRatePerSecond, maxSamples);
    }
  }
  return {
    rows: visible,
    totalDsqCount: ranked.length,
    sampleRate,
    rateAvailable: maxRatePerSecond > 0,
    maxRatePerSecond,
    maxSamples,
  };
}

export function dsqTransferHeatmapModel(
  payload,
  { limit = 12, nowMs = Date.now() } = {},
) {
  const sampleRate = Math.max(0, finiteValue(payload?.sample_rate) ?? 0);
  const pairs = new Map();
  const endpointTotals = new Map();
  const total = emptyTrafficMetric();
  for (const capture of payload?.captures || []) {
    if (!trafficGenerationMatches(payload, capture)) {
      continue;
    }
    const rateMultiplier = captureRateMultiplier(capture, sampleRate, nowMs);
    for (const transfer of capture?.dsq_transfers || []) {
      const sourceDsqId = canonicalDsqKey(transfer?.source_dsq_id);
      const targetDsqId = canonicalDsqKey(transfer?.target_dsq_id);
      const samples = Math.max(0, finiteValue(transfer?.samples) ?? 0);
      if (sourceDsqId === null || targetDsqId === null || samples === 0) {
        continue;
      }
      const key = `${sourceDsqId}>${targetDsqId}`;
      const pair = pairs.get(key) || {
        sourceDsqId,
        targetDsqId,
        ...emptyTrafficMetric(),
      };
      addTrafficMetric(pair, samples, rateMultiplier);
      pairs.set(key, pair);
      addTrafficMetric(total, samples, rateMultiplier);
      for (const dsqId of [sourceDsqId, targetDsqId]) {
        const endpoint = endpointTotals.get(dsqId) || emptyTrafficMetric();
        addTrafficMetric(endpoint, samples, rateMultiplier);
        endpointTotals.set(dsqId, endpoint);
      }
    }
  }

  const safeLimit = Math.max(1, Math.trunc(finiteValue(limit) ?? 12));
  const ranked = [...endpointTotals.entries()].sort((left, right) => (
    trafficScore(right[1]) - trafficScore(left[1])
    || compareDsqKeys(left[0], right[0])
  ));
  const significant = ranked.slice(0, safeLimit);
  const significantIds = new Set(significant.map(([dsqId]) => dsqId));
  const hasOther = ranked.length > significant.length;
  const endpoints = significant.map(([dsqId, metric]) => ({
    dsqId,
    label: formatDsqId(dsqId),
    kind: dsqKind(dsqId),
    ...metric,
  }));
  if (hasOther) {
    const other = emptyTrafficMetric();
    for (const [, metric] of ranked.slice(safeLimit)) {
      mergeTrafficMetric(other, metric);
    }
    endpoints.push({
      dsqId: null,
      label: "Other",
      kind: `${ranked.length - significant.length} lower-traffic DSQs`,
      ...other,
    });
  }

  const indexFor = new Map(significant.map(([dsqId], index) => [dsqId, index]));
  const otherIndex = hasOther ? endpoints.length - 1 : null;
  const matrix = endpoints.map(() => endpoints.map(() => ({
    ...emptyTrafficMetric(),
    share: 0,
  })));
  for (const pair of pairs.values()) {
    const row = significantIds.has(pair.sourceDsqId)
      ? indexFor.get(pair.sourceDsqId)
      : otherIndex;
    const column = significantIds.has(pair.targetDsqId)
      ? indexFor.get(pair.targetDsqId)
      : otherIndex;
    if (row === null || column === null || row === undefined || column === undefined) {
      continue;
    }
    mergeTrafficMetric(matrix[row][column], pair);
  }
  const cells = matrix.flat();
  const maxRatePerSecond = Math.max(
    0,
    ...cells.map((cell) => cell.ratePerSecond ?? 0),
  );
  const maxSamples = Math.max(0, ...cells.map((cell) => cell.samples));
  const totalValue = total.ratePerSecond ?? total.samples;
  for (const cell of cells) {
    cell.intensity = trafficIntensity(cell, maxRatePerSecond, maxSamples);
    cell.share = totalValue > 0 ? trafficScore(cell) / totalValue : 0;
  }
  return {
    endpoints,
    matrix,
    total,
    totalEndpointCount: ranked.length,
    sampleRate,
    rateAvailable: maxRatePerSecond > 0,
    maxRatePerSecond,
    maxSamples,
  };
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
    { id: "components", label: "Components", policies: [] },
  ];
  for (const policy of policies || []) {
    const id = String(policy?.id || "").toLowerCase();
    const category = PRODUCTION_POLICY_IDS.has(id)
      ? "production"
      : id.includes("random")
        ? "demo"
        : "components";
    groups.find((group) => group.id === category).policies.push(policy);
  }
  return groups.map((group) => ({
    ...group,
    defaultOpen: group.id === "production" || group.policies.some((policy) => policy.active),
  }));
}

export function policySlotComparison(slots) {
  const active = (slots || []).find((slot) => slot.state === "active") || null;
  const previous = (slots || []).find((slot) => slot.state === "inactive") || null;
  const label = (role, slot) => slot ? `${role} · rung set ${slot.slot}` : `${role} unavailable`;
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

export function queueRungMetricPercentages(metrics, metric, callbackCalls) {
  const attempts = Math.max(0, Number(metrics?.attempts) || 0);
  const callbacks = Math.max(0, Number(callbackCalls) || 0);
  const count = Math.max(0, Number(metrics?.[metric]) || 0);
  return {
    rung: attempts === 0 ? 0 : count * 100 / attempts,
    callback: callbacks === 0 ? 0 : count * 100 / callbacks,
  };
}

export function queueRungCallbackPercentages(metrics, callbackCalls) {
  return {
    hit: queueRungMetricPercentages(metrics, "hits", callbackCalls).callback,
    miss: queueRungMetricPercentages(metrics, "misses", callbackCalls).callback,
  };
}

export function rungTimingSummary(timing) {
  const buckets = Array.isArray(timing?.buckets) ? timing.buckets : [];
  const samples = buckets.reduce(
    (total, count) => total + Math.max(0, Number(count) || 0),
    0,
  );
  const totalNs = Math.max(0, Number(timing?.total_ns) || 0);
  let p95Ns = null;
  if (samples >= 20) {
    const rank = Math.ceil(samples * 0.95);
    let cumulative = 0;
    for (let bucket = 0; bucket < buckets.length; bucket += 1) {
      cumulative += Math.max(0, Number(buckets[bucket]) || 0);
      if (cumulative >= rank) {
        p95Ns = bucket >= 52
          ? Number.MAX_SAFE_INTEGER
          : (2 ** (bucket + 1)) - 1;
        break;
      }
    }
  }
  return {
    samples,
    meanNs: samples > 0 ? Math.floor(totalNs / samples) : null,
    p95Ns,
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

function queueRungAction(rung) {
  if (rung?.action) {
    return rung.action;
  }
  return String(rung?.operation || "").match(/^([a-z_]+)\(/)?.[1] || null;
}

function queueRungSource(rung) {
  if (rung?.source) {
    return rung.source;
  }
  return String(rung?.operation || "").match(/^[a-z_]+\(([^;)]+)/)?.[1] || null;
}

function dispatchFallbackSources(dispatch) {
  const consume = dispatch.find((rung) => queueRungAction(rung) === "consume");
  if (Array.isArray(consume?.fallback)) {
    return new Set(consume.fallback);
  }
  const encoded = String(consume?.operation || "").match(/;fallback=([^)]*)/)?.[1];
  return new Set(encoded ? encoded.split(",") : []);
}

export function queueLadderSections(queues, callbackMetrics = {}) {
  if (!queues) {
    return [];
  }
  const enqueue = queues.enqueue || [];
  const dispatch = queues.dispatch || [];
  const routedEnqueue = enqueue.some(
    (rung) => ["try_insert", "insert"].includes(queueRungAction(rung)),
  );
  const candidateDispatch = dispatch.some(
    (rung) => ["peek", "consume"].includes(queueRungAction(rung)),
  );
  const fallbackSources = dispatchFallbackSources(dispatch);
  const minVtime = dispatch.length === 1
    && dispatch[0].operation === "min_vtime(cell,affinity)";
  return [
    {
      kind: "enqueue",
      title: "Enqueue",
      callbackCalls: callbackMetrics.enqueues,
      behavior: routedEnqueue ? "First applicable route" : "First success",
      terminal: routedEnqueue ? "No route accepted → error" : "All targets failed → error",
      rungs: enqueue.map((rung, index, all) => {
        const action = queueRungAction(rung);
        if (action === "try_insert") {
          return {
            ...rung,
            role: "conditional route",
            metricKeys: [],
            flow: {
              hit: "Queued → stop",
              miss: index + 1 < all.length
                ? `Inapplicable → rung ${index + 1}`
                : "Inapplicable → error",
            },
          };
        }
        if (action === "insert") {
          return {
            ...rung,
            role: "terminal route",
            metricKeys: [],
            flow: {
              hit: "Queued → stop",
              miss: "Insert failure → error",
            },
          };
        }
        return {
          ...rung,
          role: "target",
          metricKeys: [],
          flow: queueRungFlow("enqueue", index, all.length),
        };
      }),
    },
    {
      kind: "dispatch",
      title: "Dispatch",
      callbackCalls: callbackMetrics.dispatch_calls,
      cyclic: !minVtime && !candidateDispatch,
      behavior: candidateDispatch
        ? "Peek candidates → minimum VTIME consume"
        : minVtime
        ? "Lowest VTIME; alternating exact ties"
        : "Cyclic per-CPU cursor",
      terminal: candidateDispatch
        ? "No candidate or fallback work → replenish previous task or idle"
        : minVtime
        ? "Both sources empty → replenish previous task or idle"
        : "All sources empty → replenish previous task or idle",
      rungs: dispatch.map((rung, index, all) => {
        const action = queueRungAction(rung);
        if (action === "peek") {
          const fallbackMetrics = fallbackSources.has(queueRungSource(rung))
            ? ["fallback_attempts", "fallback_hits", "fallback_misses"]
            : [];
          return {
            ...rung,
            role: "candidate",
            metricKeys: ["selected", ...fallbackMetrics],
            flow: {
              hit: "Candidate → accumulate",
              miss: index + 1 < all.length
                ? `Empty → rung ${index + 1}`
                : "Empty → consume",
            },
          };
        }
        if (action === "consume") {
          return {
            ...rung,
            role: "consume",
            metricKeys: ["move_misses"],
            flow: {
              hit: "Winner → dispatch",
              miss: "Move miss or empty → bounded fallback",
            },
          };
        }
        return {
          ...rung,
          role: minVtime ? "operation" : "source",
          metricKeys: [],
          flow: minVtime
            ? {
                hit: "Earlier head → dispatch",
                miss: "Both empty → replenish previous task or idle",
              }
            : queueRungFlow("dispatch", index, all.length),
        };
      }),
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
  const fairness = String(values?.fairness || "").toLowerCase();
  if (!["fifo", "vtime", "eevdf"].includes(fairness)) {
    throw new Error("Fairness must be FIFO, VTIME, or EEVDF.");
  }
  request.fairness = fairness;
  if (values?.callback_timing_sample_rate != null) {
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

function schedulerEffectiveSetting(control, name) {
  const setting = (control?.settings || []).find((candidate) => candidate.name === name);
  return setting?.effective ?? setting?.value ?? null;
}

export function schedulerCurrentLaunch(control) {
  return {
    policy_id: control?.policy_id ?? null,
    fairness: schedulerEffectiveSetting(control, "fairness")
      ?? control?.context?.fairness
      ?? null,
    callback_timing_sample_rate: control?.launch?.callback_timing_sample_rate ?? null,
    exit_dump_len: control?.launch?.exit_dump_len ?? null,
    verbose: Boolean(control?.launch?.verbose),
  };
}

export function schedulerLifecycleRequest(control, values) {
  const sampleRate = control?.active
    ? schedulerCurrentLaunch(control).callback_timing_sample_rate
    : null;
  return schedulerLaunchRequest({
    ...values,
    callback_timing_sample_rate: sampleRate,
  });
}

export function schedulerCommandPreview(request, preservedArgs = [], currentCommand = []) {
  if (!request?.policy_id) {
    return "scx_snake --policy <select a policy>";
  }
  const executable = Array.isArray(currentCommand) && currentCommand.length > 0
    ? currentCommand[0]
    : "scx_snake";
  const currentPolicy = commandOptionValue(currentCommand, "--policy");
  const policy = currentPolicy?.includes("/") && !request.policy_id.includes("/")
    ? `${currentPolicy.slice(0, currentPolicy.lastIndexOf("/") + 1)}${request.policy_id}`
    : request.policy_id;
  const args = [shellWord(executable), "--policy", shellWord(policy)];
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

function commandOptionValue(argv, option) {
  if (!Array.isArray(argv)) {
    return null;
  }
  for (let index = 1; index < argv.length; index += 1) {
    const argument = String(argv[index]);
    if (argument === option) {
      return argv[index + 1] == null ? null : String(argv[index + 1]);
    }
    if (argument.startsWith(`${option}=`)) {
      return argument.slice(option.length + 1) || null;
    }
  }
  return null;
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

export function schedulerDebugModel({ control, inspection } = {}) {
  const context = inspection?.context || control?.context || null;
  const activeSlot = (inspection?.slots || []).find((slot) => (
    slot.state === "active" || slot.slot === inspection?.active_slot
  )) || null;
  const settings = (control?.settings || [])
    .filter((setting) => setting.name !== "stats_reset")
    .map((setting) => {
      const effective = setting.effective ?? setting.value ?? null;
      const defaultValue = setting.default_value ?? null;
      const launchOverride = setting.launch_override ?? null;
      const changedAfterLaunch = setting.runtime_observed
        && launchOverride != null
        && !debugValuesEqual(effective, launchOverride);
      return {
        key: String(setting.name || "unknown"),
        name: schedulerSettingName(setting.name),
        default: defaultValue,
        effective,
        launchOverride,
        defaultValue: defaultValue == null
          ? "Unknown"
          : formatSchedulerSettingValue(setting.name, defaultValue),
        effectiveValue: effective == null
          ? "Not observed"
          : formatSchedulerSettingValue(setting.name, effective),
        launchOverrideValue: launchOverride == null
          ? null
          : formatSchedulerSettingValue(setting.name, launchOverride),
        source: setting.runtime_observed
          ? changedAfterLaunch
            ? "Observed from Snake; changed after launch"
            : "Observed from Snake"
          : launchOverride == null
            ? "Snake default"
            : "Launch command",
        changeLabel: setting.change_mode === "dynamic" ? "Dynamic" : "Reload required",
        nonDefault: effective != null
          && defaultValue != null
          && !debugValuesEqual(effective, defaultValue),
      };
    });
  const preservedArgs = [...(control?.launch?.preserved_args || [])];
  const nonDefaultSettings = settings
    .filter((setting) => setting.nonDefault)
    .map((setting) => ({
      name: setting.name,
      defaultValue: setting.defaultValue,
      effectiveValue: setting.effectiveValue,
      launchOverride: setting.launchOverrideValue,
      source: setting.source,
      changeLabel: setting.changeLabel,
    }));
  if (preservedArgs.length > 0) {
    nonDefaultSettings.push({
      name: "Additional arguments",
      defaultValue: "None",
      effectiveValue: preservedArgs.map(shellWord).join(" "),
      launchOverride: preservedArgs.map(shellWord).join(" "),
      source: "Launch command",
      changeLabel: "Restart required",
    });
  }
  const argv = Array.isArray(control?.current_command)
    ? [...control.current_command]
    : [];
  const identity = {
    schedulerName: control?.scheduler_name || null,
    pid: control?.pid ?? null,
    ownership: schedulerControlModel(control, false, Boolean(control?.policy_id)).stateLabel,
    attachSequence: context?.scheduler_attach_seq ?? null,
    policyId: control?.policy_id || null,
    policyGeneration: context?.policy_generation ?? activeSlot?.generation ?? null,
    activeSlot: context?.active_slot ?? activeSlot?.slot ?? null,
  };
  const policySource = activeSlot?.policy?.source || null;
  const snapshot = {
    schema: "scx_snake_debug_snapshot_v1",
    scheduler: {
      active: Boolean(control?.active),
      name: identity.schedulerName,
      pid: identity.pid,
      ownership: identity.ownership,
      argv,
    },
    runtime_context: context ? { ...context } : null,
    configuration: {
      settings: settings.map((setting) => ({
        name: setting.key,
        default: setting.default,
        effective: setting.effective,
        launch_override: setting.launchOverride,
        source: setting.source,
        application: setting.changeLabel,
      })),
      non_default: settings
        .filter((setting) => setting.nonDefault)
        .map((setting) => ({
          name: setting.key,
          default: setting.default,
          effective: setting.effective,
          launch_override: setting.launchOverride,
          source: setting.source,
        })),
      preserved_args: preservedArgs,
    },
    active_policy: {
      id: identity.policyId,
      generation: identity.policyGeneration,
      slot: identity.activeSlot,
      source: policySource,
    },
  };
  return {
    available: Boolean(control?.active),
    argv,
    command: schedulerCurrentCommand(control),
    identity,
    nonDefaultSettings,
    policySource,
    snapshotText: JSON.stringify(snapshot, null, 2),
  };
}

const POLICY_COUNTER_CATALOG = [
  ["select_calls", "Select CPU calls", "always"],
  ["dispatch_calls", "Dispatch calls", "always"],
  ["direct_dispatches", "Direct dispatches", "always"],
  ["ladder_exhaustions", "Ladder exhaustions", "always"],
  ["fallback_prev", "Previous CPU fallbacks", "always"],
  ["fallback_any", "Any CPU fallbacks", "always"],
  ["invalid_errors", "Invalid instructions and errors", "always"],
  ["enqueues", "Enqueue calls", "always"],
  ["running", "Running calls", "always"],
  ["stopping", "Stopping calls", "always"],
  ["quiescent", "Quiescent calls", "always"],
  ["select_latency_ns", "Select CPU latency (ns)", "always"],
  ["select_latency_max_ns", "Maximum select CPU latency (ns)", "always", false],
  ["fifo_shared_enqueues", "FIFO shared enqueues", "fifo"],
  ["fifo_shared_dispatches", "FIFO shared dispatches", "fifo"],
  ["membership_no_cell_runs", "Runs without a cell", "cell"],
  ["membership_invalid_runs", "Runs with an invalid cell", "cell"],
  ["cell_rehomes", "Cell rehomes", "cell"],
  ["cell_rehome_misses", "Cell rehome misses", "cell"],
  ["queue_rehome_preemptions", "Queue rehome preemptions", "cell"],
  ["queue_stale_rehome_runs", "Stale rehome runs", "cell"],
  ["queue_borrow_yields", "Borrow yields", "cell"],
  ["vtime_enqueues", "VTIME enqueues", "vtime"],
  ["vtime_dispatches", "VTIME dispatches", "vtime"],
  ["vtime_cpu_enqueues", "Affinity enqueues", "vtime"],
  ["vtime_cpu_dispatches", "Affinity dispatches", "vtime"],
  ["vtime_strict_preempt_queues", "Strict preemption queues", "vtime"],
  ["vtime_direct_runtime_ns", "Direct runtime (ns)", "vtime"],
  ["vtime_queued_runtime_ns", "Queued runtime (ns)", "vtime"],
  ["vtime_credit_clamps", "Credit clamps", "vtime"],
  ["vtime_accounting_errors", "VTIME accounting errors", "vtime"],
  ["vtime_equal_head_ties", "Equal-head ties", "vtime_queue"],
  ["eevdf_eligible_enqueues", "EEVDF eligible enqueues", "eevdf"],
  ["eevdf_future_enqueues", "EEVDF future enqueues", "eevdf"],
  ["eevdf_promotions", "EEVDF promotions", "eevdf"],
  ["eevdf_forced_advances", "EEVDF forced advances", "eevdf"],
  ["eevdf_dispatches", "EEVDF dispatches", "eevdf"],
  ["eevdf_strict_preempt_queues", "EEVDF strict preemption queues", "eevdf"],
  ["eevdf_direct_runtime_ns", "EEVDF direct runtime (ns)", "eevdf"],
  ["eevdf_queued_runtime_ns", "EEVDF queued runtime (ns)", "eevdf"],
  ["eevdf_lag_clamps", "EEVDF lag clamps", "eevdf"],
  ["eevdf_run_lag_clamps", "EEVDF run-start lag clamps", "eevdf"],
  ["eevdf_accounting_errors", "EEVDF accounting errors", "eevdf"],
];

function policyCounterRelevant(family, modeName, queueLayout) {
  if (family === "always") {
    return true;
  }
  if (family === "cell") {
    return queueLayout === "cell" || queueLayout === "cell_llc";
  }
  if (family === "vtime_queue") {
    return modeName === "vtime" && Boolean(queueLayout);
  }
  return family === modeName;
}

export function vtimeDebugModel(
  inspection,
  { previousInspection = null, elapsedMs = 0 } = {},
) {
  const context = inspection?.context || null;
  const activeSlot = (inspection?.slots || []).find((slot) => (
    slot.state === "active" || slot.slot === inspection?.active_slot
  )) || null;
  const metrics = activeSlot?.metrics || null;
  const previousContext = previousInspection?.context || null;
  const previousSlot = (previousInspection?.slots || []).find((slot) => (
    slot.state === "active" || slot.slot === previousInspection?.active_slot
  )) || null;
  const previousMetrics = previousSlot?.metrics || null;
  const count = (name) => Math.max(0, Number(metrics?.[name]) || 0);
  const percentage = (value, total) => total > 0 ? value * 100 / total : 0;
  const enqueues = count("vtime_enqueues");
  const dispatches = count("vtime_dispatches");
  const cpuEnqueues = count("vtime_cpu_enqueues");
  const cpuDispatches = count("vtime_cpu_dispatches");
  const creditClamps = count("vtime_credit_clamps");
  const equalHeadTies = count("vtime_equal_head_ties");
  const directRuntimeNs = count("vtime_direct_runtime_ns");
  const queuedRuntimeNs = count("vtime_queued_runtime_ns");
  const totalRuntimeNs = directRuntimeNs + queuedRuntimeNs;
  const generation = context?.policy_generation ?? activeSlot?.generation ?? null;
  const previousGeneration = previousContext?.policy_generation
    ?? previousSlot?.generation
    ?? null;
  const intervalMs = Number(elapsedMs);
  const rateWindowValid = Boolean(
    metrics
    && previousMetrics
    && Number.isFinite(intervalMs)
    && intervalMs > 0
    && contextsMatch(context, previousContext)
    && generation != null
    && generation === previousGeneration,
  );
  const perSecond = (name) => {
    if (!rateWindowValid) {
      return null;
    }
    const current = count(name);
    const previous = Math.max(0, Number(previousMetrics?.[name]) || 0);
    return current >= previous
      ? (current - previous) * 1_000 / intervalMs
      : null;
  };
  const modeName = String(
    inspection?.fairness?.mode_name
      ?? context?.fairness
      ?? metrics?.fairness_mode
      ?? "",
  ).toLowerCase();
  const queueLayout = inspection?.queue_topology?.layout
    ?? activeSlot?.policy?.queues?.layout
    ?? null;
  const dispatchRungs = Object.values(metrics?.dispatch_rungs || {})
    .map((rung) => ({
      index: Math.max(0, Number(rung?.index) || 0),
      operation: String(rung?.operation || "Unknown"),
      attempts: Math.max(0, Number(rung?.attempts) || 0),
      hits: Math.max(0, Number(rung?.hits) || 0),
      misses: Math.max(0, Number(rung?.misses) || 0),
      selected: Math.max(0, Number(rung?.selected) || 0),
      moveMisses: Math.max(0, Number(rung?.move_misses) || 0),
      errors: Math.max(0, Number(rung?.errors) || 0),
    }))
    .sort((left, right) => left.index - right.index);
  const share = (key) => {
    switch (key) {
      case "vtime_enqueues":
        return enqueues > 0 ? 100 : 0;
      case "vtime_dispatches":
        return percentage(dispatches, enqueues);
      case "vtime_cpu_enqueues":
        return percentage(cpuEnqueues, enqueues);
      case "vtime_cpu_dispatches":
        return percentage(cpuDispatches, dispatches);
      case "vtime_credit_clamps":
        return percentage(creditClamps, enqueues);
      case "vtime_equal_head_ties":
        return percentage(equalHeadTies, dispatches);
      default:
        return null;
    }
  };
  const counters = POLICY_COUNTER_CATALOG.map(([
    key,
    label,
    family,
    supportsRate = true,
  ]) => ({
    key,
    label,
    value: count(key),
    rate: supportsRate ? perSecond(key) : null,
    share: share(key),
    relevant: policyCounterRelevant(family, modeName, queueLayout),
  }));

  return {
    available: Boolean(metrics),
    modeActive: modeName === "vtime",
    modeName: modeName || null,
    generation,
    enqueues,
    dispatches,
    dispatchPct: percentage(dispatches, enqueues),
    clamps: {
      count: creditClamps,
      enqueuePct: percentage(creditClamps, enqueues),
    },
    runtime: {
      directNs: directRuntimeNs,
      queuedNs: queuedRuntimeNs,
      queuedPct: percentage(queuedRuntimeNs, totalRuntimeNs),
    },
    affinity: {
      enqueues: cpuEnqueues,
      dispatches: cpuDispatches,
      enqueuePct: percentage(cpuEnqueues, enqueues),
    },
    accountingErrors: count("vtime_accounting_errors"),
    equalHeadTies,
    equalHeadTiePct: percentage(equalHeadTies, dispatches),
    rates: {
      enqueues: perSecond("vtime_enqueues"),
      dispatches: perSecond("vtime_dispatches"),
      affinityEnqueues: perSecond("vtime_cpu_enqueues"),
      affinityDispatches: perSecond("vtime_cpu_dispatches"),
      clamps: perSecond("vtime_credit_clamps"),
      equalHeadTies: perSecond("vtime_equal_head_ties"),
      accountingErrors: perSecond("vtime_accounting_errors"),
    },
    counters: {
      relevant: counters.filter((counter) => counter.relevant),
      inactive: counters.filter((counter) => !counter.relevant),
    },
    dispatchRungs,
  };
}

function schedulerSettingName(name) {
  const labels = {
    fairness: "Fairness",
    callback_timing_sample_rate: "Callback sample rate",
    exit_dump_len: "Exit dump length",
    verbose: "Verbose logging",
    stats_reset: "Stats reset",
  };
  return labels[name] || String(name || "Unknown setting");
}

function debugValuesEqual(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
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

export function policyInlineActionModel(policy, candidate, pending = false, control = null) {
  const valid = policy?.actionKind !== "invalid" && policy?.changeMode !== "invalid";
  const expanded = valid
    && candidate?.policyId === policy.id
    && candidate?.fairness === policy.selectedFairness;
  const liveVisible = policy?.actionKind === "activate";
  const active = Boolean(control?.active);
  return {
    expanded,
    liveVisible,
    liveLabel: "Apply live",
    liveDisabled: Boolean(pending) || !liveVisible || Boolean(policy?.disabled),
    lifecycleVisible: valid,
    lifecycleLabel: active ? "Apply Restart" : "Apply Start",
    lifecycleDisabled: Boolean(pending)
      || !valid
      || (active ? !control?.controllable : Boolean(control?.managed)),
  };
}

export function nextPolicyCandidate(current, next) {
  const sameCandidate = next != null
    && current != null
    && current.policyId === next.policyId
    && current.fairness === next.fairness;
  return sameCandidate ? null : next;
}

export function policyReviewSelection(current, next) {
  return {
    candidate: nextPolicyCandidate(current, next),
    lifecyclePolicyId: next.policyId,
    lifecycleFairness: next.fairness,
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
  try {
    const number = BigInt(String(value));
    if (number < 0n) {
      return "unknown";
    }
    const width = number > 0xffffffffn ? 16 : 8;
    return `0x${number.toString(16).padStart(width, "0")}`;
  } catch {
    return "unknown";
  }
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

const QUEUE_TOPOLOGY_TABS = [
  { id: "activity", label: "Activity" },
  { id: "layout", label: "Queue layout" },
  { id: "routes", label: "CPU routes" },
];

export function queueTopologyTabModel(selected = "activity") {
  const active = QUEUE_TOPOLOGY_TABS.some((tab) => tab.id === selected)
    ? selected
    : QUEUE_TOPOLOGY_TABS[0].id;
  return QUEUE_TOPOLOGY_TABS.map((tab) => ({
    ...tab,
    selected: tab.id === active,
  }));
}

export function nextQueueTopologyTab(selected, key) {
  const tabs = queueTopologyTabModel(selected);
  const index = tabs.findIndex((tab) => tab.selected);
  if (key === "Home") {
    return tabs[0].id;
  }
  if (key === "End") {
    return tabs.at(-1).id;
  }
  if (key === "ArrowRight" || key === "ArrowDown") {
    return tabs[(index + 1) % tabs.length].id;
  }
  if (key === "ArrowLeft" || key === "ArrowUp") {
    return tabs[(index - 1 + tabs.length) % tabs.length].id;
  }
  return tabs[index].id;
}

export function queueTopologyHelp() {
  return {
    dsq: "Dispatch queue identifier shown in hexadecimal; Kind decodes the ID family.",
    kind: "FIFO: FIFO global and Local CPU. VTIME: VTIME global, VTIME CPU, and Local CPU. EEVDF: eligible, future, and Local CPU. Normal and Affinity are valid only for VTIME queue-enabled policies.",
    class: "fairness is valid for FIFO, VTIME, or EEVDF queues; normal and affinity are valid only for VTIME queue-enabled policies.",
    applicability: {
      FIFO: "Valid DSQs: FIFO global and Local CPU.",
      VTIME: "Valid DSQs: VTIME global, VTIME CPU, and Local CPU. Queue-enabled policies may also use Normal and Affinity DSQs.",
      EEVDF: "Valid DSQs: EEVDF eligible, EEVDF future, and Local CPU.",
    },
  };
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
    ownerLabel: queue.cell_id == null ? "Global" : `Cell ${queue.cell_id}`,
    clockLabel: topology.layout === "llc" ? "global" : `cell:${queue.clock_index}`,
  }));
  model.cpuRoutes = (topology.cpu_routes || [])
    .map((route) => ({
      ...route,
      normalDsq: formatDsqId(route.normal_dsq_id),
      affinityDsq: formatDsqId(route.affinity_dsq_id),
      ownerLabel: route.owner_cell_id == null ? "Global" : `Cell ${route.owner_cell_id}`,
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
