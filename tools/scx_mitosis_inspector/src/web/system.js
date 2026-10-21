const {
  number, rate, compact, chartColors, tableRow, timingValue, timelineSource, chartRange,
  chartSignature, renderPageStatus, renderKeyValues, drawSelectedLatencyHistogram,
  drawLatencyHistogram, bindSectionNavigation,
} = MitosisSections;
const timeline = MitosisTimeline;
const softirqRows = document.querySelector("#softirqRows");
const hardirqRows = document.querySelector("#hardirqRows");
const blockIoRows = document.querySelector("#blockIoRows");
const softirqLatencyMetric = document.querySelector("#softirqLatencyMetric");
const hardirqLatencyMetric = document.querySelector("#hardirqLatencyMetric");
let latestProbes = null;

function bytes(value) {
  if (value == null) return "--";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let scaled = value;
  let unit = 0;
  while (scaled >= 1024 && unit < units.length - 1) {
    scaled /= 1024;
    unit += 1;
  }
  return `${compact.format(scaled)} ${units[unit]}`;
}

function renderPressure(pressure) {
  const rows = [];
  for (const resource of ["cpu", "memory", "io"]) {
    const source = pressure[resource];
    if (!source.available || !source.value) {
      rows.push(tableRow([resource, "unavailable", "--", "--", "--", "--"]));
      continue;
    }
    for (const scope of ["some", "full"]) {
      const value = source.value[scope];
      if (!value) continue;
      rows.push(tableRow([
        resource,
        scope,
        compact.format(value.avg10),
        compact.format(value.avg60),
        compact.format(value.avg300),
        compact.format(value.total_us),
      ]));
    }
  }
  document.querySelector("#pressureRows").replaceChildren(...rows);
}

function render(snapshot) {
  document.querySelector("#interval").textContent = snapshot.interval_ms == null
    ? "warming up"
    : `${compact.format(snapshot.interval_ms)} ms`;
  const pct = (value) => value == null ? "--" : `${compact.format(value)}%`;
  renderKeyValues(document.querySelector("#systemCpuRows"), snapshot.cpu, {
    busy_pct: pct, user_pct: pct, system_pct: pct, iowait_pct: pct, steal_pct: pct,
  });
  renderPressure(snapshot.pressure);
  renderKeyValues(document.querySelector("#memoryRows"), snapshot.memory, {
    total_bytes: bytes,
    available_bytes: bytes,
    used_bytes: bytes,
    free_bytes: bytes,
    buffers_bytes: bytes,
    cached_bytes: bytes,
    dirty_bytes: bytes,
    swap_total_bytes: bytes,
    swap_free_bytes: bytes,
    swap_used_bytes: bytes,
  });

  const networkRows = snapshot.network.value?.interfaces?.map((item) => tableRow([
    item.interface,
    item.rx_bytes_per_second == null ? "--" : compact.format(item.rx_bytes_per_second),
    item.tx_bytes_per_second == null ? "--" : compact.format(item.tx_bytes_per_second),
    compact.format(item.rx_errors_total),
    compact.format(item.tx_errors_total),
    compact.format(item.rx_dropped_total + item.tx_dropped_total),
  ])) || [tableRow(["Unavailable", "--", "--", "--", "--", snapshot.network.error || "No data"])];
  document.querySelector("#networkRows").replaceChildren(...networkRows);
}

function renderSoftirqs(rows) {
  softirqRows.replaceChildren(...rows.map((row) => tableRow([
    `${row.vector} ${row.name}`,
    number.format(row.count),
    rate.format(row.rate_per_second),
    number.format(row.samples),
    timingValue(row.mean_ns),
    timingValue(row.p50_ns),
    timingValue(row.p95_ns),
    timingValue(row.p99_ns),
  ])));
}

function renderHardirqs(metrics) {
  const losses = metrics.metrics_map_full + metrics.starts_map_full + metrics.unmatched_exits;
  document.querySelector("#hardirqStatus").textContent = metrics.available
    ? `Exact probes active - ${number.format(losses)} correlation losses`
    : "Hard IRQ tracepoints unavailable";
  const busiest = [...metrics.rows].sort((left, right) =>
    right.rate_per_second - left.rate_per_second || right.count - left.count || left.irq - right.irq)
    .slice(0, 10);
  document.querySelector("#hardirqTableSummary").textContent =
    `Showing ${busiest.length} busiest IRQs by current rate · ${number.format(metrics.rows.length)} observed`;
  hardirqRows.replaceChildren(...busiest.map((row) => tableRow([
    number.format(row.irq),
    row.name || "--",
    rate.format(row.rate_per_second),
    timingValue(row.p95_ns),
    timingValue(row.p99_ns),
  ])));
}

function renderBlockIo(metrics) {
  document.querySelector("#blockIoStatus").textContent = metrics.available
    ? "Exact request probes active"
    : "Block request tracepoints unavailable";
  const value = (entry) => entry == null ? "--" : number.format(entry);
  blockIoRows.replaceChildren(...[
    ["Issue events", value(metrics.issue_events)],
    ["Issue events / second", rate.format(metrics.issue_rate_per_second)],
    ["Completion events", value(metrics.completion_events)],
    ["Completion events / second", rate.format(metrics.completion_rate_per_second)],
    ["Completed requests", value(metrics.completed_requests)],
    ["Error events", value(metrics.error_events)],
    ["Issued bytes", value(metrics.issued_bytes)],
    ["Completed bytes", value(metrics.completed_bytes)],
    ["Completed bytes / second", rate.format(metrics.completed_bytes_per_second)],
    ["Unmatched completions", value(metrics.unmatched_completions)],
    ["Tracking failures", value(metrics.tracking_failures)],
    ["Latency samples", value(metrics.latency_samples)],
    ["Latency mean (ns)", value(metrics.latency_mean_ns)],
    ["Latency p50 approx. (ns)", value(metrics.latency_p50_ns)],
    ["Latency p95 approx. (ns)", value(metrics.latency_p95_ns)],
    ["Latency p99 approx. (ns)", value(metrics.latency_p99_ns)],
  ].map(tableRow));
}

function renderProbeCharts(snapshot) {
  drawSelectedLatencyHistogram("softirqLatencyChart", softirqLatencyMetric,
    snapshot.softirqs, "vector", (row) => `${row.vector} ${row.name}`, "timing_buckets");
  drawSelectedLatencyHistogram("hardirqLatencyChart", hardirqLatencyMetric,
    snapshot.hardirqs.rows, "irq", (row) => `${row.irq} ${row.name || "unknown"}`, "timing_buckets");
  drawLatencyHistogram("blockIoLatencyChart", snapshot.block_io.latency_buckets);
}

function renderProbes(snapshot) {
  latestProbes = snapshot;
  renderSoftirqs(snapshot.softirqs);
  renderHardirqs(snapshot.hardirqs);
  renderBlockIo(snapshot.block_io);
  renderProbeCharts(snapshot);
}

function clearProbes() {
  latestProbes = null;
  [softirqRows, hardirqRows, blockIoRows].forEach((target) => target.replaceChildren());
  document.querySelector("#hardirqTableSummary").textContent = "--";
  ["#blockIoStatus", "#hardirqStatus"]
    .forEach((selector) => { document.querySelector(selector).textContent = "Unavailable at selected time"; });
  renderProbeCharts({ softirqs: [], hardirqs: { rows: [] }, block_io: { latency_buckets: [] } });
}

function drawHistory() {
  const range = chartRange(timeline.getState());
  const points = (key) => timeline.points(key);
  const line = MitosisCharts.drawLineChart;
  line(document.querySelector("#cpuHistoryChart"), [
    { label: "SCX est.", color: chartColors.green, points: points("callbacks.task_cpu") },
    { label: "IRQ", color: chartColors.red, points: points("callbacks.irq_cpu") },
    { label: "RT/DL/steal", color: chartColors.orange, points: points("callbacks.other_cpu") },
  ], { ...range, unit: "%", minY: 0, maxY: 100, maxGapMs: 3000 });
  line(document.querySelector("#frequencyHistory"), [
    { label: "Average", color: chartColors.green, points: points("system.mhz") },
  ], { ...range, unit: "MHz", minY: 0, maxGapMs: 3000 });
  line(document.querySelector("#irqHistory"), [
    { label: "IRQ", color: chartColors.orange, points: points("system.total") },
  ], { ...range, unit: "%", minY: 0, maxY: 100, maxGapMs: 3000 });
  line(document.querySelector("#blockRateHistory"), [
    { label: "Completions", color: chartColors.blue, points: points("system.completions") },
  ], { ...range, unit: "IOPS", minY: 0, maxGapMs: 3000 });
  line(document.querySelector("#blockThroughputHistory"), [
    { label: "Completed", color: chartColors.green, points: points("system.mib") },
  ], { ...range, unit: "MiB/s", minY: 0, maxGapMs: 3000 });
  line(document.querySelector("#pressureHistory"), [
    { label: "CPU", color: chartColors.green, points: points("system.cpu") },
    { label: "Memory", color: chartColors.orange, points: points("system.memory") },
    { label: "I/O", color: chartColors.blue, points: points("system.io") },
  ], { ...range, unit: "%", minY: 0, maxGapMs: 3000 });
  line(document.querySelector("#networkHistory"), [
    { label: "RX", color: chartColors.green, points: points("system.rx") },
    { label: "TX", color: chartColors.orange, points: points("system.tx") },
  ], { ...range, unit: "B/s", minY: 0, maxGapMs: 3000 });
}

let renderedView;
let renderedHost;
let renderedProbes;
let renderedChart;
function renderTimeline(state) {
  const host = timelineSource(state, "system");
  const probes = timelineSource(state, "counters");
  const viewChanged = state.view !== renderedView;
  if (viewChanged || host.snapshot !== renderedHost) {
    const unavailable = () => ({ available: false, value: null,
      error: host.health.detail || "No retained system sample" });
    render(host.snapshot || { interval_ms: null, cpu: unavailable(),
      pressure: { cpu: unavailable(), memory: unavailable(), io: unavailable() },
      memory: unavailable(), network: unavailable() });
  }
  if (viewChanged || probes.snapshot !== renderedProbes) {
    if (probes.snapshot) renderProbes(probes.snapshot);
    else clearProbes();
  }
  const signature = chartSignature(state);
  if (signature !== renderedChart) drawHistory();
  renderedView = state.view;
  renderedHost = host.snapshot;
  renderedProbes = probes.snapshot;
  renderedChart = signature;
  renderPageStatus(state, [["System", host], ["Probes", probes]], { liveWhen: "any" });
}

function redraw() {
  drawHistory();
  if (latestProbes) renderProbeCharts(latestProbes);
}

[softirqLatencyMetric, hardirqLatencyMetric].forEach((picker) => picker.addEventListener("change", () => {
  if (latestProbes) renderProbeCharts(latestProbes);
}));
window.addEventListener("resize", redraw);
document.addEventListener?.("mitosis-theme-change", redraw);
bindSectionNavigation();
timeline.subscribe(renderTimeline);
