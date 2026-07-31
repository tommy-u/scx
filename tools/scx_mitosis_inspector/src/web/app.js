const cards = [...document.querySelectorAll("[data-callback]")];
const status = document.querySelector("#status");
const statusText = document.querySelector("#statusText");
const number = new Intl.NumberFormat("en-US");
const rate = new Intl.NumberFormat("en-US", { maximumFractionDigits: 1 });
const callbackTimingRows = document.querySelector("#callbackTimingRows");
const schedulerTimingRows = document.querySelector("#schedulerTimingRows");
const migrationRows = document.querySelector("#migrationRows");

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
  const rows = migrations.map((migration) => {
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

function renderHostContext(context) {
  document.querySelector("#hostname").textContent = context.identity.hostname;
  document.querySelector("#kernelRelease").textContent = context.identity.kernel_release;
  document.querySelector("#cpuCount").textContent = number.format(context.identity.cpu_count);
}

function render(snapshot) {
  document.querySelector("#scheduler").textContent = snapshot.scheduler;
  document.querySelector("#uptime").textContent = `${snapshot.uptime_seconds}s`;
  document.querySelector("#refreshed").textContent = new Date().toLocaleTimeString();
  renderTimings(snapshot);
  renderMigrations(snapshot.migrations);

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

refreshHostContext().catch(() => {});
refresh();
setInterval(refresh, 1000);
