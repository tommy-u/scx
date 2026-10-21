const {
  number, rate, chartColors, tableRow, timelineSource, chartRange, chartSignature,
  renderPageStatus, bindSectionNavigation,
} = MitosisSections;
const timeline = MitosisTimeline;
const probeManifestRows = document.querySelector("#probeManifestRows");
const inspectorBpfProgramRows = document.querySelector("#inspectorBpfProgramRows");
const sourceRows = document.querySelector("#sourceRows");
const downloadSnapshotButton = document.querySelector("#downloadSnapshot");
const snapshotDownloadStatus = document.querySelector("#snapshotDownloadStatus");
const exploreGroups = [
  ["dsqs", "Dispatch queue detail"], ["tasks", "Threads"], ["wakers", "Wakeup handoffs"],
  ["scx_events", "sched_ext fallbacks"], ["perf", "Hardware counters"],
  ["bandwidth", "Memory monitoring domains"], ["ipis", "IPIs"], ["idle", "Idle states"],
  ["pressure", "Thermal pressure"], ["thermal", "Temperature"], ["power", "Package power"],
];
let hostContext = null;
let renderedSources = null;

async function fetchDiagnosticPart(name, path) {
  try {
    const response = await fetch(path, { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return { name, data: await response.json(), error: null };
  } catch (error) {
    return {
      name,
      data: null,
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

function diagnosticFilename(hostname, generatedAt) {
  const host = String(hostname || "host")
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "") || "host";
  const timestamp = generatedAt.replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
  return `scx-mitosis-inspector-${host}-${timestamp}.json`;
}

async function downloadDiagnosticSnapshot() {
  const selected = timeline.getState();
  const endpoints = [
    ["counters", "/api/counters"],
    ["migrations", Number.isFinite(selected.windowMs)
      ? `/api/migrations?window_ms=${selected.windowMs}` : "/api/migrations"],
    ["system", "/api/system"],
    ["scheduler", "/api/stats"],
    ["configuration", "/api/config"],
    ["explore", "/api/explore"],
    ["host_context", "/api/host-context"],
  ];
  downloadSnapshotButton.disabled = true;
  snapshotDownloadStatus.textContent = "Collecting";
  try {
    const generatedAt = new Date().toISOString();
    if (selected.mode === "history" && !selected.view) throw new Error("Selected snapshot is loading");
    const retained = selected.mode === "history" ? selected.view : null;
    const parts = retained ? [
      { name: "counters", data: retained.sources?.counters, error: retained.source_errors?.counters },
      { name: "migrations", data: retained.migrations, error: retained.source_errors?.migrations },
      { name: "system", data: retained.sources?.system, error: retained.source_errors?.system },
      { name: "scheduler", data: retained.sources?.stats, error: retained.source_errors?.stats },
      { name: "configuration", data: retained.sources?.config, error: retained.source_errors?.config },
      { name: "explore", data: retained.sources?.explore, error: retained.source_errors?.explore },
      { name: "host_context", data: hostContext, error: hostContext ? null : "Host context unavailable" },
    ] : await Promise.all(endpoints.map(([name, path]) => fetchDiagnosticPart(name, path)));
    const api = Object.fromEntries(parts.map((part) => [part.name, part.data]));
    const errors = Object.fromEntries(
      parts.filter((part) => part.error).map((part) => [part.name, part.error]),
    );
    const diagnostic = {
      schema_version: 1,
      generated_at: generatedAt,
      source: window.location.origin,
      api,
      errors,
      ...(retained ? { mode: "history", selected_at_unix_ms: retained.at_unix_ms,
        requested_at_unix_ms: retained.requested_at_unix_ms, instance_id: retained.instance_id } : {}),
    };
    const blob = new Blob([`${JSON.stringify(diagnostic, null, 2)}\n`], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = diagnosticFilename(api.host_context?.identity?.hostname, generatedAt);
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 0);
    const unavailable = Object.keys(errors).length;
    snapshotDownloadStatus.textContent = unavailable
      ? `Downloaded; ${unavailable} unavailable`
      : "Downloaded";
  } catch {
    snapshotDownloadStatus.textContent = "Download failed";
  } finally {
    downloadSnapshotButton.disabled = false;
  }
}

function renderHostContext(context) {
  hostContext = context;
  document.querySelector("#hostname").textContent = context.identity.hostname;
  document.querySelector("#kernelRelease").textContent = context.identity.kernel_release;
  document.querySelector("#cpuCount").textContent = number.format(context.identity.cpu_count);
}

async function refreshHostContext(retryMs = 1000) {
  try {
    const response = await fetch("/api/host-context", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    renderHostContext(await response.json());
  } catch {
    setTimeout(() => refreshHostContext(Math.min(retryMs * 2, 30_000)), retryMs);
  }
}

function renderTopUtilization(systemSnapshot, statsSnapshot) {
  const systemUtilization = systemSnapshot?.cpu?.available
    ? systemSnapshot.cpu.value?.busy_pct
    : null;
  const mitosisUtilization = statsSnapshot?.metrics?.util_pct;
  document.querySelector("#systemCpuUtilization").textContent = Number.isFinite(systemUtilization)
    ? `${rate.format(systemUtilization)}%`
    : "--";
  document.querySelector("#mitosisCpuUtilization").textContent = Number.isFinite(mitosisUtilization)
    ? `${rate.format(mitosisUtilization)}%`
    : "--";
}

function renderProbeManifest(rows) {
  probeManifestRows.replaceChildren(...rows.map((entry) => {
    const row = tableRow([entry.group, entry.status, entry.mode, entry.scope]);
    row.children[1].classList.add("probe-status", `probe-status-${entry.status}`);
    return row;
  }));
}

function renderInspectorBpfPrograms(snapshot) {
  const programs = snapshot.inspector_bpf_program_stats || [];
  const enabled = programs.some((program) => program.run_count > 0 || program.run_time_ns > 0);
  document.querySelector("#inspectorOverheadStatus").textContent = enabled
    ? "Kernel runtime counters enabled"
    : "Enable kernel.bpf_stats_enabled temporarily to measure";
  const percentage = (value) => value == null ? "--" : `${rate.format(value)}%`;
  document.querySelector("#inspectorCpuEquivalent").textContent =
    percentage(snapshot.inspector_bpf_cpu_equivalent_pct);
  document.querySelector("#inspectorHostCapacity").textContent =
    percentage(snapshot.inspector_bpf_host_capacity_pct);
  inspectorBpfProgramRows.replaceChildren(...programs.map((program) => tableRow([
    program.name,
    number.format(program.id),
    number.format(program.run_count),
    number.format(program.run_time_ns),
    program.average_runtime_ns == null ? "--" : number.format(program.average_runtime_ns),
  ])));
}

function renderProbes(snapshot) {
  document.querySelector("#scheduler").textContent = snapshot.scheduler;
  document.querySelector("#uptime").textContent = `${snapshot.uptime_seconds}s`;
  renderProbeManifest(snapshot.probe_manifest || []);
  renderInspectorBpfPrograms(snapshot);
}

function clearProbes() {
  probeManifestRows.replaceChildren();
  inspectorBpfProgramRows.replaceChildren();
  ["#scheduler", "#uptime", "#inspectorCpuEquivalent", "#inspectorHostCapacity"]
    .forEach((selector) => { document.querySelector(selector).textContent = "--"; });
  document.querySelector("#inspectorOverheadStatus").textContent = "Unavailable at selected time";
}

function renderOverheadChart() {
  MitosisCharts.drawLineChart(document.querySelector("#overheadHistoryChart"), [
    { label: "One CPU", color: chartColors.red, points: timeline.points("callbacks.inspector_cpu") },
    { label: "Host", color: chartColors.blue, points: timeline.points("callbacks.inspector_host") },
  ], { ...chartRange(timeline.getState()), unit: "%", minY: 0, maxGapMs: 3000 });
}

// Explore groups publish independently; each keeps its own capture and interval.
function exploreSource(state, key) {
  const group = state.view?.sources?.explore?.groups?.[key];
  const error = state.view?.source_errors?.explore || state.view?.source_errors?.[`explore.${key}`]
    || (!group ? "No retained sample" : group.available === true ? null
      : group.error || group.meta?.error || "Source unavailable");
  const health = MitosisPolling.freshnessModel({ hasData: !error, meta: group?.meta, pollError: error,
    now: state.mode === "history" ? state.view?.at_unix_ms ?? state.selectedAt : state.nowMs,
    pollIntervalMs: Number.isFinite(group?.summary?.interval_ms) ? group.summary.interval_ms : 1000 });
  return { snapshot: error ? null : group, health, partial: group?.partial === true };
}

function configSource(state) {
  const config = state.view?.sources?.config;
  const error = state.view?.source_errors?.config || config?.error
    || (!config ? "No retained sample" : config.available ? null : "Unavailable");
  return { status: error ? "Unavailable" : "Available", detail: error || (Number.isFinite(config.pid)
    ? `PID ${config.pid}${config.version ? ` · ${config.version}` : ""}` : "") };
}

function renderSources(state, entries) {
  const capture = (source) => {
    const at = source.snapshot?.meta?.captured_at_unix_ms;
    return Number.isFinite(at) ? new Date(at).toLocaleTimeString() : "--";
  };
  const status = (source) => `${state.mode === "history" && source.health.state === "fresh"
    ? "Historical sample" : source.health.label}${source.partial ? " · partial" : ""}`;
  const config = configSource(state);
  const rows = [...entries.map(([name, source]) => [name, status(source), capture(source),
    source.health.detail || ""]), ["Configuration", config.status, "--", config.detail]];
  const signature = JSON.stringify(rows);
  if (signature === renderedSources) return;
  renderedSources = signature;
  sourceRows.replaceChildren(...rows.map(tableRow));
}

let renderedView;
let renderedProbes;
let renderedChart;
function renderTimeline(state) {
  const probes = timelineSource(state, "counters");
  const migration = timelineSource(state, "migrations");
  const host = timelineSource(state, "system");
  const stats = timelineSource(state, "stats");
  if (state.view !== renderedView || probes.snapshot !== renderedProbes) {
    if (probes.snapshot) renderProbes(probes.snapshot);
    else clearProbes();
  }
  const signature = chartSignature(state);
  if (signature !== renderedChart) renderOverheadChart();
  renderedView = state.view;
  renderedProbes = probes.snapshot;
  renderedChart = signature;
  renderTopUtilization(host.snapshot, stats.snapshot);
  const sources = [["Probes", probes], ["Migrations", migration], ["System", host], ["Stats", stats]];
  renderSources(state, [...sources, ...exploreGroups.map(([key, name]) => [name, exploreSource(state, key)])]);
  renderPageStatus(state, sources);
}

downloadSnapshotButton.addEventListener("click", downloadDiagnosticSnapshot);
window.addEventListener("resize", renderOverheadChart);
document.addEventListener?.("mitosis-theme-change", renderOverheadChart);
bindSectionNavigation();
refreshHostContext();
timeline.subscribe(renderTimeline);
