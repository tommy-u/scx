const cards = [...document.querySelectorAll("[data-callback]")];
const status = document.querySelector("#status");
const statusText = document.querySelector("#statusText");
const number = new Intl.NumberFormat("en-US");
const rate = new Intl.NumberFormat("en-US", { maximumFractionDigits: 1 });
const callbackTimingRows = document.querySelector("#callbackTimingRows");
const schedulerTimingRows = document.querySelector("#schedulerTimingRows");
const migrationRows = document.querySelector("#migrationRows");
const cpuUtilizationRows = document.querySelector("#cpuUtilizationRows");
const llcUtilizationRows = document.querySelector("#llcUtilizationRows");
const bpfProgramRows = document.querySelector("#bpfProgramRows");
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
  renderMigrations(snapshot.migrations);
  renderCpuBreakdown(snapshot);
  renderBpfPrograms(snapshot.bpf_program_stats);
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
renderFeedback();
refreshHostContext().catch(() => {});
refresh();
setInterval(refresh, 1000);
