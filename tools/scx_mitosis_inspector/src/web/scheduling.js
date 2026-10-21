const {
  number, rate, chartColors, timingRow, sampleRateLabel, tableRow, windowLabel, timelineSource,
  chartRange, chartSignature, renderPageStatus, drawSelectedLatencyHistogram, drawLatencyHistogram,
  renderKeyValues, bindSectionNavigation, forwardMovedSections,
} = MitosisSections;
const timeline = MitosisTimeline;
const schedulerTimingRows = document.querySelector("#schedulerTimingRows");
const schedulerEventRows = document.querySelector("#schedulerEventRows");
const migrationRows = document.querySelector("#migrationRows");
const migrationWindow = document.querySelector("#migrationWindow");
const migrationWindowCoverage = document.querySelector("#migrationWindowCoverage");
const migrationQuality = document.querySelector("#migrationQuality");
const dsqMetricRows = document.querySelector("#dsqMetricRows");
const schedExtRows = document.querySelector("#schedExtRows");
const schedulerLatencyMetric = document.querySelector("#schedulerLatencyMetric");
let topology = null;
let latestSnapshot = null;

// Explore links arrive here; hardware and host groups now live on System.
forwardMovedSections({
  "#explorePerf": "/system",
  "#exploreBandwidth": "/system",
  "#exploreIpis": "/system",
  "#exploreIdle": "/system",
  "#exploreHardware": "/system",
});

function configureMigrationWindow(view) {
  const presets = [1_000, 5_000, 10_000, 30_000, 60_000, 120_000, 300_000]
    .filter((value) => value <= view.max_window_ms);
  const values = [...new Set([...presets, view.window_ms, view.max_window_ms])]
    .sort((left, right) => left - right);
  const currentOptions = [...migrationWindow.options].map((option) => Number(option.value));
  if (currentOptions.length !== values.length
      || currentOptions.some((value, index) => value !== values[index])) {
    migrationWindow.replaceChildren(...values.map((value) => {
      const option = document.createElement("option");
      option.value = String(value);
      option.textContent = windowLabel(value);
      return option;
    }));
  }
  migrationWindow.value = String(view.window_ms);
  migrationWindowCoverage.textContent = `${windowLabel(view.observed_ms)} observed · ${rate.format(view.rate_per_second)}/s`;
}

function renderMigrationQuality(view, health) {
  const available = ["complete", "incomplete"].includes(view?.migration_quality)
    && Number.isFinite(view.migration_map_capacity) && view.migration_map_capacity > 0;
  if (!available) {
    migrationQuality.textContent = "Unavailable";
    return;
  }
  const failures = view.migration_map_failures;
  const incomplete = view.migration_quality === "incomplete" || failures > 0;
  const stale = health.state !== "fresh";
  migrationQuality.textContent = `${stale ? "Last sample: " : ""}${incomplete
    ? `Incomplete · ${number.format(failures)} map updates lost` : "Complete"} · capacity ${number.format(view.migration_map_capacity)}`;
}

function renderHistoryCharts() {
  const line = MitosisCharts.drawLineChart;
  const range = chartRange(timeline.getState());
  const points = (key) => timeline.points(`callbacks.${key}`);
  const migrationPoints = (key) => timeline.points(`migration.${key}`);
  line(document.querySelector("#latencyHistoryChart"), [
    { label: "Wakeup p95", color: chartColors.orange, points: points("wakeup_p95_us") },
  ], { ...range, unit: "us", minY: 0, maxGapMs: 3000 });
  line(document.querySelector("#dsqDepthHistoryChart"), [
    { label: "Average", color: chartColors.blue, points: points("dsq_average") },
    { label: "Latest max", color: chartColors.purple, points: points("dsq_max") },
  ], { ...range, minY: 0, maxGapMs: 3000 });
  line(document.querySelector("#migrationLocalityChart"), [
    { label: "Same core", color: chartColors.green, points: migrationPoints("same_core") },
    { label: "Same LLC", color: chartColors.blue, points: migrationPoints("same_llc") },
    { label: "Cross LLC", color: chartColors.orange, points: migrationPoints("cross_llc") },
    { label: "Cross NUMA", color: chartColors.red, points: migrationPoints("cross_numa") },
  ], { ...range, unit: "%", minY: 0, maxY: 100, maxGapMs: 3000 });
}

function renderLatencyCharts(snapshot) {
  drawSelectedLatencyHistogram("schedulerLatencyChart", schedulerLatencyMetric,
    snapshot.scheduler_timings, "metric", (row) => row.metric.replaceAll("_", " "), "buckets");
  drawLatencyHistogram("dsqResidenceChart", snapshot.dsq_metrics.residence_buckets);
}

function renderSchedulerEvents(events) {
  schedulerEventRows.replaceChildren(...events.map((event) => tableRow([
    event.metric === "voluntary_switches" ? "Runnable reschedules" : event.metric.replaceAll("_", " "),
    number.format(event.count),
    rate.format(event.rate_per_second),
  ])));
}

function renderMigrations(migrations) {
  const rows = [...migrations].sort((left, right) =>
    right.count - left.count || left.from_cpu - right.from_cpu || left.to_cpu - right.to_cpu)
    .slice(0, 32).map((migration) => {
      const row = document.createElement("tr");
      [migration.from_cpu, migration.to_cpu, migration.count].forEach((value) => {
        const cell = document.createElement("td");
        cell.textContent = number.format(value);
        row.append(cell);
      });
      return row;
    });
  migrationRows.replaceChildren(...rows);
}

function renderDsqMetrics(metrics) {
  document.querySelector("#dsqStatus").textContent = metrics.available
    ? "Exact aggregate probes active"
    : "No compatible DSQ kernel symbols attached";
  const value = (entry) => entry == null ? "--" : number.format(entry);
  const averageDepth = metrics.depth_average == null
    ? "--"
    : rate.format(metrics.depth_average);
  dsqMetricRows.replaceChildren(...[
    ["Insert calls", value(metrics.insert_count)],
    ["Successful moves", value(metrics.move_count)],
    ["Residence samples", value(metrics.residence_samples)],
    ["Residence mean (ns)", value(metrics.residence_mean_ns)],
    ["Residence p50 approx. (ns)", value(metrics.residence_p50_ns)],
    ["Residence p95 approx. (ns)", value(metrics.residence_p95_ns)],
    ["Residence p99 approx. (ns)", value(metrics.residence_p99_ns)],
    ["Queue-depth samples", value(metrics.depth_samples)],
    ["Average remaining depth", averageDepth],
    ["Largest latest per-CPU depth", value(metrics.depth_latest_max)],
    ["Maximum remaining depth", value(metrics.depth_max)],
  ].map(tableRow));
}

function renderSchedExt(host) {
  const source = host.snapshot?.sched_ext
    || { available: false, value: null, error: host.health.detail || "No retained system sample" };
  renderKeyValues(schedExtRows, source, {
    state: (value) => value,
    switch_all: (value) => value ? "yes" : "no",
  });
}

function updateMigrationHeatmap(snapshot, state = timeline.getState()) {
  const explore = state.view?.sources?.explore;
  const bounds = [state.view?.at_unix_ms,
    state.mode === "history" ? state.selectedAt : null].filter(Number.isFinite);
  MitosisHeatmap.update({ ...snapshot, topology,
    memory_bandwidth: explore?.groups?.bandwidth || null,
    memory_bandwidth_source_error: state.view?.source_errors?.explore
      || state.view?.source_errors?.["explore.bandwidth"] || null,
    memory_bandwidth_view_at_unix_ms: bounds.length ? Math.min(...bounds) : null });
}

function render(snapshot, drawHistory = true) {
  latestSnapshot = snapshot;
  document.querySelector("#eventTimingSampleRate").textContent =
    sampleRateLabel(snapshot.event_timing_sample_rate);
  schedulerTimingRows.replaceChildren(...snapshot.scheduler_timings.map((timing) =>
    timingRow(timing.metric.replaceAll("_", " "), timing)));
  renderSchedulerEvents(snapshot.scheduler_events);
  renderMigrations(snapshot.migrations);
  renderDsqMetrics(snapshot.dsq_metrics);
  if (drawHistory) renderHistoryCharts();
  renderLatencyCharts(snapshot);
  updateMigrationHeatmap(snapshot);
}

function clearProbes() {
  latestSnapshot = null;
  [schedulerTimingRows, schedulerEventRows, dsqMetricRows].forEach((target) => target.replaceChildren());
  document.querySelector("#eventTimingSampleRate").textContent = "--";
  document.querySelector("#dsqStatus").textContent = "Unavailable at selected time";
  renderLatencyCharts({ scheduler_timings: [], dsq_metrics: { residence_buckets: [] } });
}

const emptyHeatmap = (migrationView) => ({ migrations: migrationView?.rows || [],
  cpu_runtime: [], interrupt_cpu: [], cpu_capacity_loss: [] });

let renderedView;
let renderedProbes;
let renderedMigrations;
let renderedHost;
let renderedTopology;
let renderedBound;
let renderedChart;
function renderTimeline(state) {
  const probes = timelineSource(state, "counters");
  const migration = timelineSource(state, "migrations");
  const host = timelineSource(state, "system");
  let migrationView = migration.snapshot;
  if (probes.snapshot && migrationView && probes.snapshot.meta?.epoch !== migrationView.meta?.epoch) {
    migrationView = null;
    migration.health = { state: "unavailable", label: "Unavailable", detail: "Scheduler epochs differ" };
  }
  const viewChanged = state.view !== renderedView || probes.snapshot !== renderedProbes
    || migrationView !== renderedMigrations;
  const bound = state.mode === "history" ? state.selectedAt : null;
  const heatmapChanged = viewChanged || topology !== renderedTopology || bound !== renderedBound;
  const signature = chartSignature(state);
  const chartsChanged = signature !== renderedChart;
  if (migrationView) {
    if (viewChanged) configureMigrationWindow(migrationView);
  } else {
    migrationWindowCoverage.textContent = state.loading ? "Loading selected window" : "No retained migration window";
    if (Number.isFinite(state.windowMs)) migrationWindow.value = String(state.windowMs);
  }
  if (viewChanged && probes.snapshot) {
    render({ ...probes.snapshot, migrations: migrationView?.rows || [], migration_window: migrationView },
      chartsChanged);
  } else if (viewChanged) {
    clearProbes();
    renderMigrations(migrationView?.rows || []);
    updateMigrationHeatmap(emptyHeatmap(migrationView), state);
    if (chartsChanged) renderHistoryCharts();
  } else {
    if (chartsChanged) renderHistoryCharts();
    if (heatmapChanged) updateMigrationHeatmap(latestSnapshot || emptyHeatmap(migrationView), state);
  }
  if (viewChanged || host.snapshot !== renderedHost) renderSchedExt(host);
  renderedView = state.view;
  renderedProbes = probes.snapshot;
  renderedMigrations = migrationView;
  renderedHost = host.snapshot;
  renderedTopology = topology;
  renderedBound = bound;
  renderedChart = signature;
  renderMigrationQuality(migrationView, migration.health);
  renderPageStatus(state, [["Probes", probes], ["Migrations", migration], ["System", host]]);
}

async function refreshHostContext(retryMs = 1000) {
  try {
    const response = await fetch("/api/host-context", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    topology = (await response.json()).topology;
    renderTimeline(timeline.getState());
  } catch {
    setTimeout(() => refreshHostContext(Math.min(retryMs * 2, 30_000)), retryMs);
  }
}

function redraw() {
  renderHistoryCharts();
  if (latestSnapshot) renderLatencyCharts(latestSnapshot);
}

MitosisHeatmap.init({ topology });
document.querySelectorAll("[name=migrationOrder]").forEach((control) => {
  control.addEventListener("change", () => {
    if (control.checked) MitosisHeatmap.setOrderMode(control.value);
  });
});
document.querySelectorAll("[name=migrationScale]").forEach((control) => {
  control.addEventListener("change", () => {
    if (control.checked) MitosisHeatmap.setScale(control.value);
  });
});
document.querySelector("#migrationZoom").addEventListener("input", (event) => {
  MitosisHeatmap.setZoom(event.currentTarget.value);
});
migrationWindow.addEventListener("change", () => timeline.setWindowMs(Number(migrationWindow.value)));
schedulerLatencyMetric.addEventListener("change", () => {
  if (latestSnapshot) renderLatencyCharts(latestSnapshot);
});
window.addEventListener("resize", redraw);
document.addEventListener?.("mitosis-theme-change", redraw);
bindSectionNavigation();
refreshHostContext();
timeline.subscribe(renderTimeline);
