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

MitosisHeatmap.init({ topology });
document.querySelectorAll("[name=migrationOrder]").forEach((control) => {
  control.addEventListener("change", () => {
    if (control.checked) MitosisHeatmap.setOrderMode(control.value);
  });
});
refreshHostContext().catch(() => {});
refresh();
setInterval(refresh, 1000);
