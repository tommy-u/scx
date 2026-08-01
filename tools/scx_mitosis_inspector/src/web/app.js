const cards = [...document.querySelectorAll("[data-callback]")];
const status = document.querySelector("#status");
const statusText = document.querySelector("#statusText");
const number = new Intl.NumberFormat("en-US");
const rate = new Intl.NumberFormat("en-US", { maximumFractionDigits: 1 });
const callbackTimingRows = document.querySelector("#callbackTimingRows");
const schedulerTimingRows = document.querySelector("#schedulerTimingRows");
const schedulerEventRows = document.querySelector("#schedulerEventRows");
const softirqRows = document.querySelector("#softirqRows");
const blockIoRows = document.querySelector("#blockIoRows");
const hardirqRows = document.querySelector("#hardirqRows");
const migrationRows = document.querySelector("#migrationRows");
const migrationWindow = document.querySelector("#migrationWindow");
const migrationWindowCoverage = document.querySelector("#migrationWindowCoverage");
const cpuUtilizationRows = document.querySelector("#cpuUtilizationRows");
const llcUtilizationRows = document.querySelector("#llcUtilizationRows");
const bpfProgramRows = document.querySelector("#bpfProgramRows");
const inspectorBpfProgramRows = document.querySelector("#inspectorBpfProgramRows");
const dsqMetricRows = document.querySelector("#dsqMetricRows");
const probeManifestRows = document.querySelector("#probeManifestRows");
const downloadSnapshotButton = document.querySelector("#downloadSnapshot");
const snapshotDownloadStatus = document.querySelector("#snapshotDownloadStatus");
const callbackLatencyMetric = document.querySelector("#callbackLatencyMetric");
const schedulerLatencyMetric = document.querySelector("#schedulerLatencyMetric");
const softirqLatencyMetric = document.querySelector("#softirqLatencyMetric");
const hardirqLatencyMetric = document.querySelector("#hardirqLatencyMetric");
const sectionLinks = [...document.querySelectorAll("#sectionNavigation a[href^='#']")];
const sectionTargets = sectionLinks
  .map((link) => ({ link, target: document.querySelector(link.hash) }))
  .filter((entry) => entry.target);
let topology = null;
let latestSnapshot = null;
let sectionUpdatePending = false;
const liveHistory = new MitosisCharts.History(600);
const migrationHistory = new MitosisCharts.History(600);
let migrationWindowMs = null;
let migrationMaxWindowMs = null;

const chartColors = {
  blue: "#2878a6",
  green: "#16795b",
  orange: "#b86b25",
  red: "#b44949",
  purple: "#7557a6",
};

function setActiveSection(activeLink) {
  sectionLinks.forEach((link) => {
    if (link === activeLink) link.setAttribute("aria-current", "location");
    else link.removeAttribute("aria-current");
  });
}

function updateActiveSection() {
  sectionUpdatePending = false;
  if (sectionTargets.length === 0) return;
  const atPageBottom = window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 4;
  let active = sectionTargets[0];
  if (atPageBottom) {
    active = sectionTargets.at(-1);
  } else {
    const threshold = Math.min(160, window.innerHeight * 0.25);
    sectionTargets.forEach((entry) => {
      if (entry.target.getBoundingClientRect().top <= threshold) active = entry;
    });
  }
  setActiveSection(active.link);
}

function scheduleSectionUpdate() {
  if (sectionUpdatePending) return;
  sectionUpdatePending = true;
  requestAnimationFrame(updateActiveSection);
}

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
  const endpoints = [
    ["counters", "/api/counters"],
    ["migrations", migrationWindowMs == null
      ? "/api/migrations"
      : `/api/migrations?window_ms=${migrationWindowMs}`],
    ["system", "/api/system"],
    ["scheduler", "/api/stats"],
    ["host_context", "/api/host-context"],
  ];
  downloadSnapshotButton.disabled = true;
  snapshotDownloadStatus.textContent = "Collecting";
  try {
    const generatedAt = new Date().toISOString();
    const parts = await Promise.all(
      endpoints.map(([name, path]) => fetchDiagnosticPart(name, path)),
    );
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

function finiteAverage(rows, key) {
  const values = (rows || []).map((row) => Number(row[key])).filter(Number.isFinite);
  return values.length
    ? values.reduce((sum, value) => sum + value, 0) / values.length
    : Number.NaN;
}

function syncMetricSelect(select, rows, valueKey, label) {
  const previous = select.value;
  const options = (rows || []).map((row) => {
    const option = document.createElement("option");
    option.value = String(row[valueKey]);
    option.textContent = label(row);
    return option;
  });
  select.replaceChildren(...options);
  if (options.some((option) => option.value === previous)) select.value = previous;
}

function durationLabel(upperNs) {
  if (upperNs === Number.MAX_SAFE_INTEGER) return ">=104d";
  if (upperNs < 1_000) return `${upperNs}ns`;
  if (upperNs < 1_000_000) return `${rate.format(upperNs / 1_000)}us`;
  if (upperNs < 1_000_000_000) return `${rate.format(upperNs / 1_000_000)}ms`;
  return `${rate.format(upperNs / 1_000_000_000)}s`;
}

function windowLabel(milliseconds) {
  if (milliseconds < 1_000) return `${milliseconds}ms`;
  if (milliseconds < 60_000) return `${rate.format(milliseconds / 1_000)}s`;
  return `${rate.format(milliseconds / 60_000)}m`;
}

function configureMigrationWindow(view) {
  migrationWindowMs = view.window_ms;
  migrationMaxWindowMs = view.max_window_ms;
  const presets = [1_000, 5_000, 10_000, 30_000, 60_000, 120_000, 300_000]
    .filter((value) => value <= migrationMaxWindowMs);
  const values = [...new Set([...presets, migrationWindowMs, migrationMaxWindowMs])]
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
  migrationWindow.value = String(migrationWindowMs);
  migrationWindowCoverage.textContent = `${windowLabel(view.observed_ms)} observed · ${rate.format(view.rate_per_second)}/s`;
}

function histogramBuckets(counts) {
  if (!Array.isArray(counts) || counts.length === 0) return [];
  const first = counts.findIndex((count) => count > 0);
  if (first < 0) return [];
  let last = counts.length - 1;
  while (last > first && counts[last] === 0) last -= 1;
  return counts.slice(first, last + 1).map((value, offset) => {
    const index = first + offset;
    const upper = index >= 53 ? Number.MAX_SAFE_INTEGER : (2 ** (index + 1)) - 1;
    return { label: durationLabel(upper), value };
  });
}

function drawLatencyHistogram(canvasId, counts) {
  MitosisCharts.drawHistogram(
    document.querySelector(`#${canvasId}`),
    histogramBuckets(counts),
    { unit: "" },
  );
}

function updateMigrationHistory(migrations, at) {
  if (!topology) return;
  const cpuById = new Map(topology.cpus.map((cpu) => [cpu.cpu, cpu]));
  const totals = { same_core: 0, same_llc: 0, cross_llc: 0, cross_numa: 0 };
  for (const row of migrations || []) {
    const source = cpuById.get(row.from_cpu);
    const destination = cpuById.get(row.to_cpu);
    if (!source || !destination) continue;
    if (source.package === destination.package && source.core === destination.core) {
      totals.same_core += row.count;
    } else if (source.package === destination.package && source.llc === destination.llc) {
      totals.same_llc += row.count;
    } else if (source.node === destination.node) {
      totals.cross_llc += row.count;
    } else {
      totals.cross_numa += row.count;
    }
  }
  const total = Object.values(totals).reduce((sum, value) => sum + value, 0);
  if (total > 0) {
    migrationHistory.push(at, Object.fromEntries(
      Object.entries(totals).map(([key, value]) => [key, value / total * 100]),
    ));
  }
}

function pushLiveHistory(snapshot) {
  const at = Date.now();
  const wakeup = snapshot.scheduler_timings.find(
    (timing) => timing.metric === "wakeup_to_running",
  );
  const irqByCpu = new Map((snapshot.interrupt_cpu || []).map((row) => [
    row.cpu, row.total_utilization_pct,
  ]));
  const lossByCpu = new Map((snapshot.cpu_capacity_loss || []).map((row) => [
    row.cpu, row.total_utilization_pct,
  ]));
  const scxUtilization = (snapshot.cpu_runtime || []).map((row) => ({
    utilization_pct: Math.max(
      0,
      row.utilization_pct - (irqByCpu.get(row.cpu) || 0) - (lossByCpu.get(row.cpu) || 0),
    ),
  }));
  liveHistory.push(at, {
    task_cpu: finiteAverage(scxUtilization, "utilization_pct"),
    irq_cpu: finiteAverage(snapshot.interrupt_cpu, "total_utilization_pct"),
    other_cpu: finiteAverage(snapshot.cpu_capacity_loss, "total_utilization_pct"),
    callbacks: snapshot.counters.reduce((sum, counter) => sum + counter.rate_per_second, 0),
    wakeup_p95_us: wakeup?.p95_ns == null ? Number.NaN : wakeup.p95_ns / 1_000,
    dsq_average: snapshot.dsq_metrics.available
      ? snapshot.dsq_metrics.depth_average
      : Number.NaN,
    dsq_max: snapshot.dsq_metrics.available
      ? snapshot.dsq_metrics.depth_latest_max
      : Number.NaN,
    inspector_cpu: snapshot.inspector_bpf_cpu_equivalent_pct,
    inspector_host: snapshot.inspector_bpf_host_capacity_pct,
  });
  updateMigrationHistory(snapshot.migrations, at);
}

function renderHistoryCharts() {
  const line = MitosisCharts.drawLineChart;
  line(document.querySelector("#cpuHistoryChart"), [
    { label: "SCX est.", color: chartColors.green, points: liveHistory.points("task_cpu") },
    { label: "IRQ", color: chartColors.red, points: liveHistory.points("irq_cpu") },
    { label: "RT/DL/steal", color: chartColors.orange, points: liveHistory.points("other_cpu") },
  ], { unit: "%", minY: 0, maxY: 100 });
  line(document.querySelector("#callbackRateHistoryChart"), [
    { label: "Callbacks", color: chartColors.blue, points: liveHistory.points("callbacks") },
  ], { unit: "/s", minY: 0 });
  line(document.querySelector("#latencyHistoryChart"), [
    { label: "Wakeup p95", color: chartColors.orange, points: liveHistory.points("wakeup_p95_us") },
  ], { unit: "us", minY: 0 });
  line(document.querySelector("#dsqDepthHistoryChart"), [
    { label: "Average", color: chartColors.blue, points: liveHistory.points("dsq_average") },
    { label: "Latest max", color: chartColors.purple, points: liveHistory.points("dsq_max") },
  ], { minY: 0 });
  line(document.querySelector("#overheadHistoryChart"), [
    { label: "One CPU", color: chartColors.red, points: liveHistory.points("inspector_cpu") },
    { label: "Host", color: chartColors.blue, points: liveHistory.points("inspector_host") },
  ], { unit: "%", minY: 0 });
  line(document.querySelector("#migrationLocalityChart"), [
    { label: "Same core", color: chartColors.green, points: migrationHistory.points("same_core") },
    { label: "Same LLC", color: chartColors.blue, points: migrationHistory.points("same_llc") },
    { label: "Cross LLC", color: chartColors.orange, points: migrationHistory.points("cross_llc") },
    { label: "Cross NUMA", color: chartColors.red, points: migrationHistory.points("cross_numa") },
  ], { unit: "%", minY: 0, maxY: 100 });
}

function renderLatencyCharts(snapshot) {
  syncMetricSelect(callbackLatencyMetric, snapshot.callback_timings, "callback", (row) => row.callback);
  syncMetricSelect(schedulerLatencyMetric, snapshot.scheduler_timings, "metric", (row) => row.metric.replaceAll("_", " "));
  syncMetricSelect(softirqLatencyMetric, snapshot.softirqs, "vector", (row) => `${row.vector} ${row.name}`);
  syncMetricSelect(hardirqLatencyMetric, snapshot.hardirqs.rows, "irq", (row) => `${row.irq} ${row.name || "unknown"}`);
  const callback = snapshot.callback_timings.find((row) => String(row.callback) === callbackLatencyMetric.value);
  const scheduler = snapshot.scheduler_timings.find((row) => String(row.metric) === schedulerLatencyMetric.value);
  const softirq = snapshot.softirqs.find((row) => String(row.vector) === softirqLatencyMetric.value);
  const hardirq = snapshot.hardirqs.rows.find((row) => String(row.irq) === hardirqLatencyMetric.value);
  drawLatencyHistogram("callbackLatencyChart", callback?.buckets);
  drawLatencyHistogram("schedulerLatencyChart", scheduler?.buckets);
  drawLatencyHistogram("softirqLatencyChart", softirq?.timing_buckets);
  drawLatencyHistogram("hardirqLatencyChart", hardirq?.timing_buckets);
  drawLatencyHistogram("blockIoLatencyChart", snapshot.block_io.latency_buckets);
  drawLatencyHistogram("dsqResidenceChart", snapshot.dsq_metrics.residence_buckets);
}

function renderCallbackCost(snapshot) {
  const rates = new Map(snapshot.counters.map((counter) => [counter.name, counter.rate_per_second]));
  const items = snapshot.callback_timings.map((timing, index) => ({
    label: timing.callback,
    value: timing.mean_ns == null ? Number.NaN : timing.mean_ns * (rates.get(timing.callback) || 0) / 1_000_000,
    color: [chartColors.blue, chartColors.green, chartColors.orange, chartColors.red, chartColors.purple][index],
  }));
  MitosisCharts.drawBarChart(
    document.querySelector("#callbackCostChart"),
    items,
    { unit: "ms/s" },
  );
}

function renderVisualizations(snapshot, push = false) {
  if (push) pushLiveHistory(snapshot);
  renderHistoryCharts();
  renderLatencyCharts(snapshot);
  renderCallbackCost(snapshot);
}

function timingValue(value) {
  return value == null ? "--" : number.format(value);
}

function timingRow(label, timing) {
  const row = document.createElement("tr");
  const heading = document.createElement("th");
  heading.scope = "row";
  heading.textContent = label;
  row.append(heading);
  [timing.samples, timing.mean_ns, timing.p50_ns, timing.p95_ns, timing.p99_ns]
    .forEach((value) => {
      const cell = document.createElement("td");
      cell.textContent = timingValue(value);
      row.append(cell);
    });
  return row;
}

function sampleRateLabel(sampleRate) {
  return sampleRate === 0 ? "disabled" : `1 / ${number.format(sampleRate)}`;
}

function renderTimings(snapshot) {
  document.querySelector("#callbackTimingSampleRate").textContent =
    sampleRateLabel(snapshot.callback_timing_sample_rate);
  document.querySelector("#eventTimingSampleRate").textContent =
    sampleRateLabel(snapshot.event_timing_sample_rate);

  const rows = snapshot.callback_timings.map((timing) =>
    timingRow(timing.callback, timing));
  callbackTimingRows.replaceChildren(...rows);
  const schedulerRows = snapshot.scheduler_timings.map((timing) =>
    timingRow(timing.metric.replaceAll("_", " "), timing));
  schedulerTimingRows.replaceChildren(...schedulerRows);
}

function renderSchedulerEvents(events) {
  schedulerEventRows.replaceChildren(...events.map((event) => tableRow([
    event.metric.replaceAll("_", " "),
    number.format(event.count),
    rate.format(event.rate_per_second),
  ])));
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

function renderHardirqs(metrics) {
  const losses = metrics.metrics_map_full + metrics.starts_map_full + metrics.unmatched_exits;
  document.querySelector("#hardirqStatus").textContent = metrics.available
    ? `Exact probes active - ${number.format(losses)} correlation losses`
    : "Hard IRQ tracepoints unavailable";
  hardirqRows.replaceChildren(...metrics.rows.map((row) => tableRow([
    number.format(row.irq),
    row.name || "--",
    number.format(row.count),
    rate.format(row.rate_per_second),
    number.format(row.samples),
    timingValue(row.mean_ns),
    timingValue(row.p50_ns),
    timingValue(row.p95_ns),
    timingValue(row.p99_ns),
  ])));
}

function renderProbeManifest(rows) {
  probeManifestRows.replaceChildren(...rows.map((entry) => {
    const row = tableRow([entry.group, entry.status, entry.mode, entry.scope]);
    row.children[1].classList.add("probe-status", `probe-status-${entry.status}`);
    return row;
  }));
}

function renderMigrations(migrations) {
  const rows = migrations.slice(0, 32).map((migration) => {
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

function tableRow(values) {
  const row = document.createElement("tr");
  values.forEach((value, index) => {
    const cell = document.createElement(index === 0 ? "th" : "td");
    if (index === 0) cell.scope = "row";
    cell.textContent = value;
    row.append(cell);
  });
  return row;
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

function renderCpuBreakdown(snapshot) {
  const runtime = Array.isArray(snapshot.cpu_runtime) ? snapshot.cpu_runtime : [];
  const runtimeByCpu = new Map(runtime.map((row) => [row.cpu, row]));
  const lossByCpu = new Map((snapshot.cpu_capacity_loss || []).map((row) => [row.cpu, row]));
  const cpus = topology?.cpus || runtime.map((row) => ({
    cpu: row.cpu, core: row.cpu, llc: 0, node: 0,
  }));
  const ordered = topology?.topology_order || cpus.map((cpu) => cpu.cpu);
  const cpuById = new Map(cpus.map((cpu) => [cpu.cpu, cpu]));
  cpuUtilizationRows.replaceChildren(...ordered.flatMap((cpuId) => {
    const cpu = cpuById.get(cpuId);
    const row = runtimeByCpu.get(cpuId);
    const loss = lossByCpu.get(cpuId);
    if (!cpu || !row) return [];
    return [tableRow([
      number.format(cpu.cpu),
      number.format(cpu.core),
      number.format(cpu.llc),
      number.format(cpu.node),
      `${rate.format(row.utilization_pct)}%`,
      loss ? `${rate.format(loss.rt_stop_utilization_pct)}%` : "--",
      loss ? `${rate.format(loss.deadline_utilization_pct)}%` : "--",
      loss ? `${rate.format(loss.steal_utilization_pct)}%` : "--",
    ])];
  }));

  const groups = topology?.llc_groups || [{ llc: 0, node: 0, cpus: ordered }];
  llcUtilizationRows.replaceChildren(...groups.map((group) => {
    const values = group.cpus
      .map((cpu) => runtimeByCpu.get(cpu)?.utilization_pct)
      .filter((value) => value != null);
    const average = values.length
      ? `${rate.format(values.reduce((sum, value) => sum + value, 0) / values.length)}%`
      : "--";
    return tableRow([
      number.format(group.llc),
      number.format(group.node),
      group.cpus.join(", "),
      average,
    ]);
  }));
}

function renderBpfPrograms(programs) {
  const enabled = programs.some((program) => program.run_count > 0);
  document.querySelector("#bpfRuntimeStatus").textContent = enabled
    ? "Kernel runtime counters enabled"
    : "Kernel runtime counters disabled";
  bpfProgramRows.replaceChildren(...programs.map((program) => tableRow([
    program.name,
    number.format(program.id),
    number.format(program.run_count),
    number.format(program.run_time_ns),
    program.average_runtime_ns == null ? "--" : number.format(program.average_runtime_ns),
    number.format(program.recursion_misses),
    program.verified_insns == null ? "--" : number.format(program.verified_insns),
  ])));
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

function renderHostContext(context) {
  document.querySelector("#hostname").textContent = context.identity.hostname;
  document.querySelector("#kernelRelease").textContent = context.identity.kernel_release;
  document.querySelector("#cpuCount").textContent = number.format(context.identity.cpu_count);
  topology = context.topology;
  if (latestSnapshot) {
    renderCpuBreakdown(latestSnapshot);
    renderVisualizations(latestSnapshot);
    MitosisHeatmap.update({ ...latestSnapshot, topology });
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

function render(snapshot, systemSnapshot, statsSnapshot) {
  latestSnapshot = snapshot;
  document.querySelector("#scheduler").textContent = snapshot.scheduler;
  document.querySelector("#uptime").textContent = `${snapshot.uptime_seconds}s`;
  document.querySelector("#refreshed").textContent = new Date().toLocaleTimeString();
  renderTimings(snapshot);
  renderSchedulerEvents(snapshot.scheduler_events);
  renderSoftirqs(snapshot.softirqs);
  renderBlockIo(snapshot.block_io);
  renderHardirqs(snapshot.hardirqs);
  renderMigrations(snapshot.migrations);
  renderCpuBreakdown(snapshot);
  renderBpfPrograms(snapshot.bpf_program_stats);
  renderInspectorBpfPrograms(snapshot);
  renderDsqMetrics(snapshot.dsq_metrics);
  renderProbeManifest(snapshot.probe_manifest || []);
  renderTopUtilization(systemSnapshot, statsSnapshot);
  renderVisualizations(snapshot, true);
  MitosisHeatmap.update({ ...snapshot, topology });

  const counters = new Map(snapshot.counters.map((counter) => [counter.name, counter]));
  cards.forEach((card, index) => {
    const counter = counters.get(card.dataset.callback);
    if (!counter) return;
    card.querySelector(".count").textContent = number.format(counter.count);
    card.querySelector(".rate").textContent = rate.format(counter.rate_per_second);
    card.querySelector(".program-id").textContent = snapshot.target_program_ids[index];
  });

  status.classList.add("live");
  statusText.textContent = "Live";
}

async function refreshHostContext() {
  const response = await fetch("/api/host-context", { cache: "no-store" });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  renderHostContext(await response.json());
}

async function fetchOptionalSnapshot(path) {
  try {
    const response = await fetch(path, { cache: "no-store" });
    if (!response.ok) return null;
    return response.json();
  } catch {
    return null;
  }
}

async function refresh() {
  try {
    const migrationPath = migrationWindowMs == null
      ? "/api/migrations"
      : `/api/migrations?window_ms=${migrationWindowMs}`;
    const [counterResponse, migrationResponse, systemSnapshot, statsSnapshot] = await Promise.all([
      fetch("/api/counters", { cache: "no-store" }),
      fetch(migrationPath, { cache: "no-store" }),
      fetchOptionalSnapshot("/api/system"),
      fetchOptionalSnapshot("/api/stats"),
    ]);
    if (!counterResponse.ok) throw new Error(`HTTP ${counterResponse.status}`);
    if (!migrationResponse.ok) throw new Error(`HTTP ${migrationResponse.status}`);
    const [snapshot, migrationView] = await Promise.all([
      counterResponse.json(),
      migrationResponse.json(),
    ]);
    configureMigrationWindow(migrationView);
    snapshot.migrations = migrationView.rows;
    snapshot.migration_window = migrationView;
    render(snapshot, systemSnapshot, statsSnapshot);
  } catch (error) {
    status.classList.remove("live");
    statusText.textContent = "Disconnected";
  }
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
migrationWindow.addEventListener("change", () => {
  migrationWindowMs = Number(migrationWindow.value);
  refresh();
});
downloadSnapshotButton.addEventListener("click", downloadDiagnosticSnapshot);
window.addEventListener("mitosis:stats-reset", () => {
  liveHistory.clear();
  migrationHistory.clear();
  renderHistoryCharts();
});
[
  callbackLatencyMetric,
  schedulerLatencyMetric,
  softirqLatencyMetric,
  hardirqLatencyMetric,
].forEach((select) => select.addEventListener("change", () => {
  if (latestSnapshot) renderLatencyCharts(latestSnapshot);
}));
window.addEventListener("scroll", scheduleSectionUpdate, { passive: true });
window.addEventListener("resize", () => {
  scheduleSectionUpdate();
  if (latestSnapshot) renderVisualizations(latestSnapshot);
});
window.addEventListener("hashchange", scheduleSectionUpdate);
updateActiveSection();
refreshHostContext().catch(() => {});
refresh();
setInterval(refresh, 1000);
