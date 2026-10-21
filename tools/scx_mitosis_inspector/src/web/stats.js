const status = document.querySelector("#status");
const statusText = document.querySelector("#statusText");
const number = new Intl.NumberFormat("en-US", { maximumFractionDigits: 2 });
const statsHistory = new MitosisCharts.History(1801);
const trackedCells = new Set();
let historyInstance = null;
let historyEpoch = null;
let historyCursor = null;
let lastHistoryMeta = null;
let historyRetentionMs = 30 * 60 * 1000;
let historyMeta = null;
let historyCollector = null;
let historyError = null;
let refreshGeneration = 0;

function clearHistory(redraw = true) {
  statsHistory.clear();
  trackedCells.clear();
  historyEpoch = null;
  historyCursor = null;
  lastHistoryMeta = null;
  historyMeta = null;
  historyCollector = null;
  historyError = null;
  if (redraw) drawCellHistory();
}
const pageState = MitosisPolling.createPageState({ sourceNames: ["stats"], onEpochChange() {
  invalidateStatsPollers();
  clearHistory();
} });
const chartColors = [
  "var(--series-green)",
  "var(--series-blue)",
  "var(--series-orange)",
  "var(--series-purple)",
  "var(--series-gold)",
  "var(--series-olive)",
  "var(--series-pink)",
  "var(--series-slate)",
];
let cpuTopology = null;
let cpuTopologyError = null;

function renderCpuTopology() {
  if (globalThis.MitosisTimeline) {
    const source = selectedStatsSource();
    const snapshot = source.available ? source.snapshot
      : { ...source.snapshot, cpu_cells: null, cpu_cells_error: source.detail };
    MitosisTopologyStrip.render(document.querySelector("#cpuTopology"), cpuTopology, snapshot, chartColors);
    if (!cpuTopology && cpuTopologyError) {
      document.querySelector("#cpuTopologyStatus").textContent = `CPU topology unavailable: ${cpuTopologyError}`;
    }
    return;
  }
  const source = pageState.state.sources.stats;
  const health = pageState.freshness("stats", 2000);
  const snapshot = health.state === "fresh" ? source.data
    : { ...source.data, cpu_cells: null, cpu_cells_error: health.label };
  MitosisTopologyStrip.render(document.querySelector("#cpuTopology"), cpuTopology, snapshot, chartColors);
  if (!cpuTopology && cpuTopologyError) {
    document.querySelector("#cpuTopologyStatus").textContent = `CPU topology unavailable: ${cpuTopologyError}`;
  }
}

function displayName(name) {
  return name.replaceAll("_", " ");
}

function displayValue(value) {
  if (value === null || value === undefined) return "--";
  if (typeof value === "number") return number.format(value);
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function appendCell(row, tag, value, scope) {
  const cell = document.createElement(tag);
  if (scope) cell.scope = scope;
  cell.textContent = value;
  row.append(cell);
}

function renderGlobal(metrics) {
  const body = document.querySelector("#globalStatsBody");
  body.replaceChildren();
  Object.entries(metrics)
    .filter(([name]) => !["cells", "borrow_flows"].includes(name))
    .forEach(([name, value]) => {
      const row = document.createElement("tr");
      appendCell(row, "th", displayName(name), "row");
      appendCell(row, "td", displayValue(value));
      body.append(row);
    });
}

function cellLabel(cellId) {
  return `Cell ${cellId}`;
}

function percentage(value) {
  return Number.isFinite(value) ? `${number.format(value)}%` : "--";
}

function numericCellIds(flows, cells) {
  const ids = new Set(Object.keys(cells ?? {}).map(Number));
  flows.forEach((flow) => {
    ids.add(Number(flow.borrower_cell));
    ids.add(Number(flow.lender_cell));
  });
  return [...ids].filter(Number.isFinite).sort((left, right) => left - right);
}

function renderBorrowing(metrics) {
  const supported = metrics.borrow_flows !== null && typeof metrics.borrow_flows === "object";
  const flows = Object.values(metrics.borrow_flows ?? {}).filter(
    (flow) => Number.isFinite(flow?.borrower_cell) && Number.isFinite(flow?.lender_cell),
  );
  const cellIds = numericCellIds(flows, metrics.cells);
  const byDirection = new Map(
    flows.map((flow) => [`${flow.borrower_cell}:${flow.lender_cell}`, flow]),
  );
  const maxCapacity = Math.max(
    0,
    ...flows.map((flow) => flow.lender_capacity_pct).filter(Number.isFinite),
  );
  const head = document.querySelector("#borrowMatrixHead");
  const body = document.querySelector("#borrowMatrixBody");
  const edgeBody = document.querySelector("#borrowFlowsBody");
  head.replaceChildren();
  body.replaceChildren();
  edgeBody.replaceChildren();
  document.querySelector("#borrowingHeading").textContent = supported ? "Cell borrowing flows" : "Cell borrowing totals";
  document.querySelector("#borrowingStatus").textContent = supported
    ? "Rows borrow from lending columns · latest scheduler interval"
    : "Per-cell totals · latest scheduler interval · pairwise flows unavailable from this scheduler version";
  document.querySelector(".borrowing-edges").hidden = !supported;
  document.querySelector(".borrowing-layout").classList.toggle("borrowing-totals-layout", !supported);
  document.querySelector("#borrowMatrix").setAttribute("aria-label", supported
    ? "Borrower by lender capacity matrix" : "Per-cell borrowed runtime and lent CPU capacity");

  const header = document.createElement("tr");
  if (!supported) {
    for (const label of ["Cell", "Borrowed runtime", "Lent CPU capacity"]) appendCell(header, "th", label, "col");
    header.children[1].title = "Percentage of this cell's running time spent on other cells' CPUs";
    header.children[2].title = "Percentage of this cell's assigned CPU capacity used by other cells' tasks";
    head.append(header);
    cellIds.forEach((cellId) => {
      const values = metrics.cells?.[cellId];
      const row = document.createElement("tr");
      appendCell(row, "th", cellLabel(cellId), "row");
      appendCell(row, "td", percentage(values?.demand_borrow_pct));
      appendCell(row, "td", percentage(values?.lent_pct));
      body.append(row);
    });
    return;
  }
  appendCell(header, "th", "Borrower ↓ / Lender →", "col");
  cellIds.forEach((cellId) => appendCell(header, "th", cellLabel(cellId), "col"));
  head.append(header);

  cellIds.forEach((borrower) => {
    const row = document.createElement("tr");
    appendCell(row, "th", cellLabel(borrower), "row");
    cellIds.forEach((lender) => {
      const cell = document.createElement("td");
      if (borrower === lender) {
        cell.className = "borrow-cell-own";
        cell.textContent = "Own";
      } else {
        const flow = byDirection.get(`${borrower}:${lender}`);
        const capacity = flow?.lender_capacity_pct;
        const level = maxCapacity > 0 && Number.isFinite(capacity)
          ? Math.max(1, Math.ceil(5 * capacity / maxCapacity))
          : 0;
        cell.className = `borrow-cell borrow-level-${level}`;
        cell.textContent = flow ? percentage(capacity) : "0%";
        cell.title = flow
          ? `${cellLabel(borrower)} used ${percentage(capacity)} of ${cellLabel(lender)} capacity`
          : `No runtime borrowed by ${cellLabel(borrower)} from ${cellLabel(lender)}`;
      }
      row.append(cell);
    });
    body.append(row);
  });

  flows
    .sort((left, right) => (right.runtime_ns ?? 0) - (left.runtime_ns ?? 0))
    .forEach((flow) => {
      const row = document.createElement("tr");
      appendCell(row, "th", cellLabel(flow.borrower_cell), "row");
      appendCell(row, "td", cellLabel(flow.lender_cell));
      appendCell(row, "td", displayValue(flow.runtime_ns / 1e6));
      appendCell(row, "td", percentage(flow.borrower_runtime_pct));
      appendCell(row, "td", percentage(flow.lender_capacity_pct));
      edgeBody.append(row);
    });

  if (flows.length === 0) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 5;
    cell.className = "borrowing-empty";
    cell.textContent = "No cross-cell borrowing in the latest interval";
    row.append(cell);
    edgeBody.append(row);
  }
}

function renderCells(cells) {
  const entries = Object.entries(cells ?? {});
  const columns = [...new Set(entries.flatMap(([, values]) => Object.keys(values)))];
  const head = document.querySelector("#cellStatsHead");
  const body = document.querySelector("#cellStatsBody");
  head.replaceChildren();
  body.replaceChildren();

  const headerRow = document.createElement("tr");
  appendCell(headerRow, "th", "Cell", "col");
  columns.forEach((name) => appendCell(headerRow, "th", displayName(name), "col"));
  head.append(headerRow);

  entries.forEach(([cellId, values]) => {
    const row = document.createElement("tr");
    appendCell(row, "th", cellId, "row");
    columns.forEach((name) => appendCell(row, "td", displayValue(values[name])));
    body.append(row);
  });
  document.querySelector("#cellCount").textContent = number.format(entries.length);
}

function metric(values, ...names) {
  return names.map((name) => values?.[name]).find(Number.isFinite);
}

function historyKey(cellId, signal) {
  return `cell.${cellId}.${signal}`;
}

function appendCellHistory(cells, capturedAt) {
  const sample = {};
  Object.entries(cells ?? {}).forEach(([cellId, values]) => {
    const capacity = metric(values, "num_cpus");
    const intervalUtilization = metric(values, "util_pct");
    const signals = {
      // Smoothed utilization can remain zero when scheduler rebalancing is disabled.
      util: metric(values, "util_pct", "smoothed_util_pct"),
      used_cpus: Number.isFinite(capacity) && capacity > 0 && Number.isFinite(intervalUtilization)
        ? intervalUtilization * capacity / 100 : undefined,
      assigned_cpus: capacity,
    };
    const available = Object.entries(signals).filter(([, value]) => Number.isFinite(value));
    if (available.length === 0) return;
    trackedCells.add(cellId);
    available.forEach(([signal, value]) => {
      sample[historyKey(cellId, signal)] = value;
    });
  });
  statsHistory.push(capturedAt, sample);
}

function drawCellHistory() {
  const timeline = globalThis.MitosisTimeline;
  const state = timeline?.getState();
  const points = (key) => timeline ? timeline.points(key)
    : statsHistory.points(key, { preserveGaps: true });
  const ids = timeline
    ? [...new Set(timeline.keys("cell.").map(key => key.split(".")[1]))]
    : [...trackedCells];
  const cellIds = ids.sort((left, right) => Number(left) - Number(right));
  const range = timeline ? { minX: state.oldestAt,
    maxX: state.mode === "history" ? state.selectedAt : state.latestAt } : {};
  const utilizationSeries = cellIds.map((cellId) => ({
    label: `Cell ${cellId}`,
    color: chartColors[Number(cellId) % chartColors.length],
    points: points(historyKey(cellId, "util")),
  })).filter((series) => series.points.some((point) => Number.isFinite(point.y)));
  let utilizationMax = 100;
  utilizationSeries.forEach((series) => {
    series.points.forEach((point) => {
      if (Number.isFinite(point.y)) utilizationMax = Math.max(utilizationMax, point.y);
    });
  });
  MitosisCharts.drawLineChart(
    document.querySelector("#cellUtilizationChart"),
    utilizationSeries,
    { unit: "%", minY: 0, maxY: utilizationMax, showLegend: false, maxGapMs: 3000, ...range },
  );
  renderCellHistoryLegend("#cellUtilizationLegend", utilizationSeries);

  const balanceSeries = [];
  cellIds.forEach((cellId) => {
    ["used_cpus", "assigned_cpus"].forEach((signal) => {
      const signalPoints = points(historyKey(cellId, signal));
      if (!signalPoints.some((point) => Number.isFinite(point.y))) return;
      balanceSeries.push({
        label: `Cell ${cellId} ${signal === "used_cpus" ? "use" : "capacity"}`,
        color: chartColors[Number(cellId) % chartColors.length],
        dash: signal === "assigned_cpus" ? [6, 4] : [],
        points: signalPoints,
      });
    });
  });
  MitosisCharts.drawLineChart(
    document.querySelector("#cellBalanceChart"),
    balanceSeries,
    { unit: " CPUs", minY: 0, showLegend: false, maxGapMs: 3000, ...range },
  );
  renderCellHistoryLegend("#cellBalanceLegend", balanceSeries);
}

function renderCellHistoryLegend(selector, series) {
  document.querySelector(selector).replaceChildren(...series.map((series) => {
    const item = document.createElement("li");
    const swatch = document.createElement("span");
    const dashed = Boolean(series.dash?.length);
    swatch.className = `series-swatch${dashed ? " series-swatch-dashed" : ""}`;
    swatch.setAttribute("style", `color: ${series.color};${dashed ? "" : ` background-color: ${series.color};`}`);
    swatch.setAttribute("aria-hidden", "true");
    const label = document.createElement("span");
    label.textContent = series.label;
    item.append(swatch, label);
    return item;
  }));
}

function render(snapshot) {
  if (!snapshot.metrics) throw new Error(snapshot.error ?? "Stats unavailable");
  renderBorrowing(snapshot.metrics);
  renderGlobal(snapshot.metrics);
  renderCells(snapshot.metrics.cells);
}

function expireCellHistory() {
  const previousLength = statsHistory.samples.length;
  statsHistory.expireBefore(Date.now() - historyRetentionMs);
  return statsHistory.samples.length !== previousLength;
}

function historyDuration(spanMs) {
  const seconds = Math.max(0, Math.round(spanMs / 1000));
  return seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

function renderHistoryStatus() {
  const target = document.querySelector("#cellHistoryStatus");
  if (!target) return;
  if (globalThis.MitosisTimeline) {
    const state = MitosisTimeline.getState();
    const cutoff = state.mode === "history" ? state.selectedAt : state.latestAt;
    const coverage = Number.isFinite(state.oldestAt) && Number.isFinite(cutoff)
      ? `${historyDuration(Math.max(0, cutoff - state.oldestAt))} available`
      : "Waiting for retained samples";
    const retention = state.retentionMs ?? 30 * 60 * 1000;
    target.textContent = `Last ${number.format(retention / 60000)} minutes · ${coverage}`
      + (state.loading && !state.view ? " · Loading selected time" : "")
      + (state.error ? ` · ${state.error}` : "");
    return;
  }
  const samples = statsHistory.samples;
  const prefix = `Last ${number.format(historyRetentionMs / 60000)} minutes`;
  const health = MitosisPolling.freshnessModel({ hasData: samples.length > 0,
    meta: historyMeta, pollError: historyError || historyMeta?.error
      || (historyCollector && historyCollector.status !== "active"
        ? historyCollector.error || `Scheduler ${historyCollector.status}` : null),
    pollIntervalMs: 2000 });
  const shown = samples.length > 0
    ? `${historyDuration(samples[samples.length - 1].x - samples[0].x)} available`
    : "Waiting for retained samples";
  const error = pageState.state.paused ? "Resetting inspector"
    : historyError || (pageState.state.resetError && lastHistoryMeta?.captured_at_unix_ms <= pageState.state.resetFailureAt
      ? pageState.state.resetError : null) || health.detail;
  target.textContent = `${prefix} · ${shown}${error ? ` · Updates unavailable: ${error}`
    : health.state === "stale" ? ` · ${health.label}` : ""}`;
}

function applyHistory(snapshot) {
  const epoch = snapshot.meta?.epoch;
  if (typeof snapshot.instance_id !== "string" || snapshot.instance_id.length === 0
      || !Number.isSafeInteger(epoch) || epoch < 0 || !Array.isArray(snapshot.samples)
      || !Number.isFinite(snapshot.retention_ms) || snapshot.retention_ms <= 0) {
    throw new Error("History metadata unavailable");
  }
  const instanceChanged = historyInstance !== null && historyInstance !== snapshot.instance_id;
  if (instanceChanged) {
    invalidateStatsPollers();
    clearHistory(false);
    // Epochs and source sequences begin again when the inspector restarts.
    pageState.state.epoch = null;
    pageState.state.resetAt = 0;
    pageState.state.resetError = null;
    pageState.state.resetFailureAt = 0;
    pageState.state.sources.stats = {};
    renderGlobal({});
    renderCells({});
    renderBorrowing({});
  }
  historyInstance = snapshot.instance_id;
  if (pageState.state.epoch !== null && epoch < pageState.state.epoch) {
    historyError = "Waiting for current scheduler history";
    renderHistoryStatus();
    return;
  }
  pageState.observeEpoch(snapshot);
  const epochChanged = historyEpoch !== null && epoch !== historyEpoch;
  const replaceHistory = epochChanged || (snapshot.reset && !pageState.state.resetError);
  if (replaceHistory) clearHistory(false);
  historyEpoch = epoch;
  historyRetentionMs = snapshot.retention_ms;
  historyMeta = snapshot.meta;
  historyCollector = snapshot.collector;
  historyError = null;
  let changed = instanceChanged || replaceHistory;
  const samples = snapshot.samples.filter((sample) =>
    sample?.meta?.epoch === epoch && MitosisPolling.isNewSample(sample.meta, null)
      && sample.cells && typeof sample.cells === "object",
  ).sort((left, right) => left.meta.sample_seq - right.meta.sample_seq);
  samples.forEach((sample) => {
    const at = sample.meta.captured_at_unix_ms;
    if (!MitosisPolling.isNewSample(sample.meta, lastHistoryMeta)
        || (pageState.state.resetAt && at < pageState.state.resetAt)
        || (pageState.state.resetError && at <= pageState.state.resetFailureAt)) return;
    appendCellHistory(sample.cells, at);
    lastHistoryMeta = { ...sample.meta };
    changed = true;
  });
  historyCursor = { instanceId: historyInstance, epoch, afterSeq: lastHistoryMeta?.sample_seq ?? 0 };
  changed = expireCellHistory() || changed;
  if (changed) drawCellHistory();
  renderHistoryStatus();
  renderStatus();
}

function renderStatus() {
  if (globalThis.MitosisTimeline) {
    renderTimelineStatsStatus();
    return;
  }
  const health = pageState.freshness("stats", 2000);
  status.classList.toggle("live", health.state === "fresh");
  status.classList.toggle("stale", health.state === "stale");
  statusText.textContent = health.label;
  const detail = document.querySelector("#sourceStatus");
  if (detail) detail.textContent = pageState.describe({ stats: "Stats" }, 2000);
  const at = pageState.state.sources.stats.meta?.last_success_at_unix_ms;
  document.querySelector("#refreshed").textContent = Number.isFinite(at) ? new Date(at).toLocaleTimeString() : "--";
  const rebalances = displayValue(pageState.state.sources.stats.data?.metrics?.rebalance_count);
  document.querySelector("#reconfigurationCount").textContent = health.state === "stale" && rebalances !== "--"
    ? `${rebalances} (last sample)` : rebalances;
  renderCpuTopology();
  renderHistoryStatus();
}

const topologyPoller = MitosisPolling.createPoller({
  timeoutMs: 6000,
  load: ({ signal }) => MitosisPolling.fetchJson("/api/host-context", signal),
  onResult(snapshot) {
    cpuTopology = snapshot.topology;
    cpuTopologyError = null;
    renderCpuTopology();
  },
  onError(error) {
    cpuTopologyError = error.message;
    renderCpuTopology();
  },
});

function createStatsPoller(options) {
  const source = MitosisPolling.createPoller(options);
  let pending = null;
  return {
    run() {
      if (pending) return pending;
      const request = source.run().finally(() => {
        if (pending === request) pending = null;
      });
      pending = request;
      return request;
    },
    invalidate() {
      source.invalidate();
      pending = null;
    },
  };
}

const poller = createStatsPoller({
  timeoutMs: 6000,
  load: ({ signal }) => MitosisPolling.fetchJson("/api/stats", signal),
  onResult(snapshot) {
    pageState.observeEpoch(snapshot);
    const source = pageState.accept("stats", { status: "fulfilled", value: snapshot });
    if (source.data?.metrics) render(source.data);
    renderStatus();
  },
  onError(error) {
    pageState.accept("stats", { status: "rejected", reason: error });
    renderStatus();
  },
});

const historyPoller = createStatsPoller({
  timeoutMs: 6000,
  load: ({ signal }) => {
    const query = historyCursor
      ? `?instance_id=${encodeURIComponent(historyCursor.instanceId)}&epoch=${historyCursor.epoch}&after_seq=${historyCursor.afterSeq}`
      : "";
    return MitosisPolling.fetchJson(`/api/stats/history${query}`, signal);
  },
  onResult: applyHistory,
  onError(error) {
    historyError = error.message;
    if (expireCellHistory()) drawCellHistory();
    renderHistoryStatus();
  },
});

function invalidateStatsPollers() {
  refreshGeneration += 1;
  poller.invalidate();
  historyPoller.invalidate();
  historyCursor = null;
}

async function refresh() {
  if (globalThis.MitosisTimeline) return MitosisTimeline.refresh();
  renderStatus();
  if (pageState.state.paused) {
    if (expireCellHistory()) drawCellHistory();
    return;
  }
  // An epoch change can cancel history before its response reveals a new instance.
  for (let pass = 0; pass < 3; pass += 1) {
    const generation = refreshGeneration;
    const requests = [poller.run(), historyPoller.run()];
    if (!cpuTopology) requests.push(topologyPoller.run());
    await Promise.all(requests);
    if (pageState.state.paused || generation === refreshGeneration) break;
  }
}
document.addEventListener?.("mitosis-theme-change", drawCellHistory);

function selectedStatsSource() {
  const state = MitosisTimeline.getState();
  const snapshot = state.view?.sources?.stats;
  const historical = state.mode === "history";
  const basis = historical ? state.view?.at_unix_ms : state.nowMs;
  const captured = snapshot?.meta?.captured_at_unix_ms;
  const error = state.view?.source_errors?.stats || snapshot?.meta?.error || snapshot?.error
    || (snapshot && snapshot.collector?.status !== "active"
      ? snapshot.collector?.error || "Scheduler stats unavailable" : null)
    || (Number.isFinite(captured) && Number.isFinite(basis) && captured > basis
      ? "Stats sample is after the selected time" : null);
  const health = MitosisPolling.freshnessModel({
    hasData: Boolean(snapshot?.metrics), meta: snapshot?.meta,
    pollError: error, now: Number.isFinite(basis) ? basis : state.nowMs,
    pollIntervalMs: 2000,
  });
  const available = Boolean(snapshot?.metrics) && health.state === "fresh";
  const detail = error || (!state.view
    ? state.loading ? "Loading selected time" : state.error || "Waiting for selected stats"
    : historical ? "Stats unavailable at selected time" : health.detail || health.label);
  return { state, snapshot, historical, available, detail, health };
}

function renderTimelineStatsStatus() {
  const source = selectedStatsSource();
  status.classList.toggle("live", !source.historical && source.available);
  status.classList.toggle("stale", !source.available && source.health.state === "stale");
  statusText.textContent = source.historical
    ? source.available ? "Historical" : "Historical · unavailable"
    : source.available ? "Live" : source.state.loading ? "Loading" : source.health.label;
  document.querySelector("#sourceStatus").textContent = source.available
    ? source.historical ? "Stats: historical sample" : "Stats: Live"
    : `Stats: ${source.detail}`;
  const at = source.snapshot?.meta?.captured_at_unix_ms;
  document.querySelector("#refreshed").textContent = Number.isFinite(at)
    ? new Date(at).toLocaleTimeString() : "--";
  document.querySelector("#reconfigurationCount").textContent = source.available
    ? displayValue(source.snapshot.metrics.rebalance_count) : "--";
  renderCpuTopology();
  renderHistoryStatus();
}

let renderedTimelineSnapshot = null;
let renderedTimelineChart = null;
function renderTimelineStats(state) {
  const source = selectedStatsSource();
  const snapshot = source.available ? source.snapshot : null;
  if (snapshot !== renderedTimelineSnapshot || !snapshot) {
    if (snapshot) render(snapshot);
    else {
      renderGlobal({});
      renderCells({});
      renderBorrowing({});
      document.querySelector("#cellCount").textContent = "--";
      document.querySelector("#borrowingStatus").textContent = source.detail;
    }
    renderedTimelineSnapshot = snapshot;
  }
  const cutoff = state.mode === "history" ? state.selectedAt : state.latestAt;
  const retained = (state.frames || []).filter(frame => frame.at_unix_ms <= cutoff);
  const signature = [state.instanceId, state.mode, cutoff, state.oldestAt,
    retained.length, retained[0]?.seq, retained[retained.length - 1]?.seq].join(":");
  if (signature !== renderedTimelineChart) {
    renderedTimelineChart = signature;
    drawCellHistory();
  }
  renderTimelineStatsStatus();
  if (!cpuTopology) topologyPoller.run();
}

if (globalThis.MitosisTimeline) {
  MitosisTimeline.subscribe(renderTimelineStats);
} else {
  pageState.bindReset({ invalidate: invalidateStatsPollers }, clearHistory, refresh);
  document.addEventListener?.("visibilitychange", () => {
    if (document.visibilityState === "visible") refresh();
  });
  globalThis.addEventListener?.("focus", refresh);
  globalThis.addEventListener?.("pageshow", refresh);
  refresh();
  setInterval(refresh, 2000);
}
