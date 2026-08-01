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
const cpuUtilizationRows = document.querySelector("#cpuUtilizationRows");
const llcUtilizationRows = document.querySelector("#llcUtilizationRows");
const bpfProgramRows = document.querySelector("#bpfProgramRows");
const inspectorBpfProgramRows = document.querySelector("#inspectorBpfProgramRows");
const dsqMetricRows = document.querySelector("#dsqMetricRows");
const probeManifestRows = document.querySelector("#probeManifestRows");
const downloadSnapshotButton = document.querySelector("#downloadSnapshot");
const snapshotDownloadStatus = document.querySelector("#snapshotDownloadStatus");
const sectionLinks = [...document.querySelectorAll("#sectionNavigation a[href^='#']")];
const sectionTargets = sectionLinks
  .map((link) => ({ link, target: document.querySelector(link.hash) }))
  .filter((entry) => entry.target);
const FEEDBACK_STORAGE_KEY = "scx-mitosis-inspector-feedback-v1";
const feedbackElements = {
  clear: document.querySelector("#clearFeedback"),
  close: document.querySelector("#closeFeedback"),
  copy: document.querySelector("#copyFeedback"),
  count: document.querySelector("#feedbackCount"),
  drawer: document.querySelector("#feedbackDrawer"),
  notice: document.querySelector("#feedbackNotice"),
  open: document.querySelector("#openFeedback"),
  transcript: document.querySelector("#feedbackTranscript"),
};
const feedbackState = {
  entries: loadFeedbackEntries(),
  expandedKeys: new Set(),
};
let topology = null;
let latestSnapshot = null;
let sectionUpdatePending = false;

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
  const cpus = topology?.cpus || runtime.map((row) => ({
    cpu: row.cpu, core: row.cpu, llc: 0, node: 0,
  }));
  const ordered = topology?.topology_order || cpus.map((cpu) => cpu.cpu);
  const cpuById = new Map(cpus.map((cpu) => [cpu.cpu, cpu]));
  const utilization = runtime.reduce((sum, row) => sum + row.utilization_pct, 0);
  document.querySelector("#overallCpuUtilization").textContent = runtime.length
    ? `${rate.format(utilization / runtime.length)}%`
    : "--";

  cpuUtilizationRows.replaceChildren(...ordered.flatMap((cpuId) => {
    const cpu = cpuById.get(cpuId);
    const row = runtimeByCpu.get(cpuId);
    if (!cpu || !row) return [];
    return [tableRow([
      number.format(cpu.cpu),
      number.format(cpu.core),
      number.format(cpu.llc),
      number.format(cpu.node),
      `${rate.format(row.utilization_pct)}%`,
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
    MitosisHeatmap.update({ ...latestSnapshot, topology });
  }
}

function render(snapshot) {
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

async function refresh() {
  try {
    const response = await fetch("/api/counters", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    render(await response.json());
  } catch (error) {
    status.classList.remove("live");
    statusText.textContent = "Disconnected";
  }
}

function normalizeFeedbackEntries(value) {
  if (!Array.isArray(value)) return [];
  const entries = [];
  for (const entry of value) {
    const key = typeof entry?.key === "string" ? entry.key.trim() : "";
    const text = typeof entry?.text === "string"
      ? entry.text.replace(/\r\n?/g, "\n")
      : "";
    if (!key || !text.trim()) continue;
    const existing = entries.findIndex((candidate) => candidate.key === key);
    const normalized = { key, text };
    if (existing >= 0) entries[existing] = normalized;
    else entries.push(normalized);
  }
  return entries;
}

function loadFeedbackEntries() {
  try {
    return normalizeFeedbackEntries(JSON.parse(
      localStorage.getItem(FEEDBACK_STORAGE_KEY) || "[]",
    ));
  } catch {
    return [];
  }
}

function persistFeedbackEntries() {
  try {
    if (feedbackState.entries.length === 0) {
      localStorage.removeItem(FEEDBACK_STORAGE_KEY);
    } else {
      localStorage.setItem(FEEDBACK_STORAGE_KEY, JSON.stringify(feedbackState.entries));
    }
  } catch {
    showFeedbackNotice("Feedback could not be saved in this browser.", true);
  }
}

function feedbackEntry(key) {
  return feedbackState.entries.find((entry) => entry.key === key) || null;
}

function updateFeedback(key, text) {
  const normalized = String(text ?? "").replace(/\r\n?/g, "\n");
  const index = feedbackState.entries.findIndex((entry) => entry.key === key);
  if (!normalized.trim()) {
    if (index >= 0) feedbackState.entries.splice(index, 1);
  } else if (index >= 0) {
    feedbackState.entries[index] = { key, text: normalized };
  } else {
    feedbackState.entries.push({ key, text: normalized });
  }
  persistFeedbackEntries();
  renderFeedback();
}

function feedbackTranscript() {
  return feedbackState.entries
    .filter((entry) => entry.text.trim())
    .map((entry) => `[${entry.key}] ${entry.text.trim()}`)
    .join("\n\n");
}

function renderFeedback() {
  const transcript = feedbackTranscript();
  const count = feedbackState.entries.length;
  feedbackElements.transcript.value = transcript;
  feedbackElements.copy.disabled = !transcript;
  feedbackElements.clear.disabled = !transcript && feedbackState.expandedKeys.size === 0;
  feedbackElements.count.textContent = number.format(count);
  feedbackElements.count.classList.toggle("has-feedback", count > 0);
  feedbackElements.count.setAttribute(
    "aria-label",
    `${number.format(count)} feedback ${count === 1 ? "draft" : "drafts"}`,
  );
  decorateFeedbackTargets(document);
}

function decorateFeedbackTargets(root) {
  root.querySelectorAll("[data-feedback-key]").forEach(decorateFeedbackTarget);
}

function decorateFeedbackTarget(target) {
  const key = target.dataset.feedbackKey;
  if (!key) return;
  target.classList.add("feedback-target");
  const heading = [...target.children].find((child) => child.matches(
    "header, .view-heading, .table-section-heading",
  ));
  let button = [...target.querySelectorAll("[data-feedback-toggle]")]
    .find((candidate) => candidate.dataset.feedbackToggle === key);
  if (!button) {
    button = document.createElement("button");
    button.type = "button";
    button.className = "feedback-button";
    button.dataset.feedbackToggle = key;
    button.innerHTML = `
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
        stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path d="M6 8.5a6.5 6.5 0 1 1 13 0c0 6-6 6-6 10a3.5 3.5 0 1 1-7 0"></path>
        <path d="M15 8.5a2.5 2.5 0 0 0-5 0v1a2 2 0 1 1 0 4"></path>
      </svg>`;
    button.title = "Leave feedback";
    button.setAttribute("aria-label", `Leave feedback on ${key}`);
    if (heading) {
      heading.classList.add("feedback-heading");
      heading.append(button);
    } else {
      button.classList.add("floating");
      target.prepend(button);
    }
  }

  const expanded = feedbackState.expandedKeys.has(key);
  button.classList.toggle("has-feedback", Boolean(feedbackEntry(key)));
  button.setAttribute("aria-expanded", String(expanded));
  const composerId = `feedback-${key.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
  button.setAttribute("aria-controls", composerId);
  let composer = [...target.querySelectorAll(".feedback-composer")]
    .find((candidate) => candidate.dataset.feedbackComposer === key);
  if (!expanded) {
    composer?.remove();
    return;
  }
  if (!composer) {
    composer = document.createElement("div");
    composer.className = "feedback-composer";
    composer.id = composerId;
    composer.dataset.feedbackComposer = key;
    const input = document.createElement("textarea");
    input.rows = 3;
    input.placeholder = "Feedback";
    input.value = feedbackEntry(key)?.text || "";
    input.dataset.feedbackInput = key;
    input.setAttribute("aria-label", `Feedback on ${key}`);
    composer.append(input);
    if (heading) heading.after(composer);
    else button.after(composer);
  }
}

function toggleFeedbackComposer(key) {
  const opening = !feedbackState.expandedKeys.has(key);
  if (opening) feedbackState.expandedKeys.add(key);
  else feedbackState.expandedKeys.delete(key);
  renderFeedback();
  if (opening) {
    requestAnimationFrame(() => {
      const input = [...document.querySelectorAll("[data-feedback-input]")]
        .find((candidate) => candidate.dataset.feedbackInput === key);
      input?.focus();
      input?.setSelectionRange(input.value.length, input.value.length);
    });
  }
}

function openFeedback() {
  renderFeedback();
  if (typeof feedbackElements.drawer.showModal === "function") {
    feedbackElements.drawer.showModal();
  } else {
    feedbackElements.drawer.setAttribute("open", "");
  }
}

function closeFeedback() {
  if (typeof feedbackElements.drawer.close === "function") feedbackElements.drawer.close();
  else feedbackElements.drawer.removeAttribute("open");
}

function showFeedbackNotice(message, error = false) {
  feedbackElements.notice.textContent = message;
  feedbackElements.notice.classList.remove("hidden");
  feedbackElements.notice.classList.toggle("error", error);
}

async function copyFeedback() {
  const text = feedbackElements.transcript.value;
  if (!text) return;
  let copied = false;
  try {
    await navigator.clipboard.writeText(text);
    copied = true;
  } catch {
    feedbackElements.transcript.focus();
    feedbackElements.transcript.select();
    try {
      copied = document.execCommand("copy");
    } catch {
      copied = false;
    }
  }
  showFeedbackNotice(copied ? "Feedback copied." : "Copy failed; feedback text is selected.", !copied);
}

function clearFeedback() {
  if (!window.confirm("Clear all collected feedback?")) return;
  feedbackState.entries = [];
  feedbackState.expandedKeys.clear();
  persistFeedbackEntries();
  renderFeedback();
  showFeedbackNotice("Feedback cleared.");
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
document.addEventListener("click", (event) => {
  const toggle = event.target.closest("[data-feedback-toggle]");
  if (toggle) toggleFeedbackComposer(toggle.dataset.feedbackToggle);
});
document.addEventListener("input", (event) => {
  const input = event.target.closest("[data-feedback-input]");
  if (input) updateFeedback(input.dataset.feedbackInput, input.value);
});
feedbackElements.open.addEventListener("click", openFeedback);
feedbackElements.close.addEventListener("click", closeFeedback);
feedbackElements.copy.addEventListener("click", copyFeedback);
feedbackElements.clear.addEventListener("click", clearFeedback);
downloadSnapshotButton.addEventListener("click", downloadDiagnosticSnapshot);
window.addEventListener("scroll", scheduleSectionUpdate, { passive: true });
window.addEventListener("resize", scheduleSectionUpdate);
window.addEventListener("hashchange", scheduleSectionUpdate);
renderFeedback();
updateActiveSection();
refreshHostContext().catch(() => {});
refresh();
setInterval(refresh, 1000);
