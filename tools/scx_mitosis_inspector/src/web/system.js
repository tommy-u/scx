const status = document.querySelector("#status");
const statusText = document.querySelector("#statusText");
const number = new Intl.NumberFormat("en-US", { maximumFractionDigits: 2 });
const { History, drawLineChart } = MitosisCharts;
const historyPoints = 10 * 60 / 2;
const pressureHistory = new History(historyPoints);
const frequencyHistory = new History(historyPoints);
const networkHistory = new History(historyPoints);
const irqHistory = new History(historyPoints);
const blockHistory = new History(historyPoints);

function row(values) {
  const tr = document.createElement("tr");
  values.forEach((value, index) => {
    const cell = document.createElement(index === 0 ? "th" : "td");
    if (index === 0) cell.scope = "row";
    cell.textContent = value;
    tr.append(cell);
  });
  return tr;
}

function bytes(value) {
  if (value == null) return "--";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let scaled = value;
  let unit = 0;
  while (scaled >= 1024 && unit < units.length - 1) {
    scaled /= 1024;
    unit += 1;
  }
  return `${number.format(scaled)} ${units[unit]}`;
}

function renderKeyValues(target, source, formatters = {}) {
  if (!source.available || !source.value) {
    target.replaceChildren(row(["Unavailable", source.error || "No data"]));
    return;
  }
  target.replaceChildren(...Object.entries(source.value)
    .filter(([, value]) => typeof value !== "object")
    .map(([key, value]) => row([
      key.replaceAll("_", " "),
      formatters[key] ? formatters[key](value) : value == null ? "--" : number.format(value),
    ])));
}

function renderPressure(pressure) {
  const rows = [];
  for (const resource of ["cpu", "memory", "io"]) {
    const source = pressure[resource];
    if (!source.available || !source.value) {
      rows.push(row([resource, "unavailable", "--", "--", "--", "--"]));
      continue;
    }
    for (const scope of ["some", "full"]) {
      const value = source.value[scope];
      if (!value) continue;
      rows.push(row([
        resource,
        scope,
        number.format(value.avg10),
        number.format(value.avg60),
        number.format(value.avg300),
        number.format(value.total_us),
      ]));
    }
  }
  document.querySelector("#pressureRows").replaceChildren(...rows);
}

function render(snapshot) {
  document.querySelector("#interval").textContent = snapshot.interval_ms == null
    ? "warming up"
    : `${number.format(snapshot.interval_ms)} ms`;
  document.querySelector("#refreshed").textContent = new Date().toLocaleTimeString();
  const pct = (value) => value == null ? "--" : `${number.format(value)}%`;
  renderKeyValues(document.querySelector("#systemCpuRows"), snapshot.cpu, {
    busy_pct: pct, user_pct: pct, system_pct: pct, iowait_pct: pct, steal_pct: pct,
  });
  renderKeyValues(document.querySelector("#schedExtRows"), snapshot.sched_ext, {
    state: (value) => value,
    switch_all: (value) => value ? "yes" : "no",
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

  const frequencyRows = snapshot.frequencies.value?.cpus?.map((cpu) => row([
    number.format(cpu.cpu),
    cpu.current_khz == null ? "--" : number.format(cpu.current_khz),
    cpu.error || "available",
  ])) || [row(["Unavailable", "--", snapshot.frequencies.error || "No data"])];
  document.querySelector("#frequencyRows").replaceChildren(...frequencyRows);

  const networkRows = snapshot.network.value?.interfaces?.map((item) => row([
    item.interface,
    item.rx_bytes_per_second == null ? "--" : number.format(item.rx_bytes_per_second),
    item.tx_bytes_per_second == null ? "--" : number.format(item.tx_bytes_per_second),
    number.format(item.rx_errors_total),
    number.format(item.tx_errors_total),
    number.format(item.rx_dropped_total + item.tx_dropped_total),
  ])) || [row(["Unavailable", "--", "--", "--", "--", snapshot.network.error || "No data"])];
  document.querySelector("#networkRows").replaceChildren(...networkRows);

}

function finite(value) {
  return Number.isFinite(value) ? value : Number.NaN;
}

function pressureAvg10(snapshot, resource) {
  const source = snapshot.pressure?.[resource];
  return finite(source?.available ? source.value?.some?.avg10 : null);
}

function sumRates(items, key) {
  const values = (items || []).map((item) => item[key]).filter(Number.isFinite);
  return values.length ? values.reduce((sum, value) => sum + value, 0) : Number.NaN;
}

function average(items, key) {
  const values = (items || []).map((item) => item[key]).filter(Number.isFinite);
  return values.length ? values.reduce((sum, value) => sum + value, 0) / values.length : Number.NaN;
}

function pushHistory(at, systemSnapshot, countersSnapshot) {
  if (systemSnapshot) {
    pressureHistory.push(at, {
      cpu: pressureAvg10(systemSnapshot, "cpu"),
      memory: pressureAvg10(systemSnapshot, "memory"),
      io: pressureAvg10(systemSnapshot, "io"),
    });
    const averageKhz = systemSnapshot.frequencies?.available
      ? systemSnapshot.frequencies.value?.average_khz
      : null;
    frequencyHistory.push(at, {
      mhz: Number.isFinite(averageKhz) ? averageKhz / 1000 : Number.NaN,
    });
    const interfaces = systemSnapshot.network?.available
      ? systemSnapshot.network.value?.interfaces
      : [];
    networkHistory.push(at, {
      rx: sumRates(interfaces, "rx_bytes_per_second"),
      tx: sumRates(interfaces, "tx_bytes_per_second"),
    });
  }

  if (countersSnapshot) {
    irqHistory.push(at, {
      total: average(countersSnapshot.interrupt_cpu, "total_utilization_pct"),
    });
    const block = countersSnapshot.block_io;
    blockHistory.push(at, {
      completions: finite(block?.available ? block.completion_rate_per_second : null),
      mib: finite(block?.available ? block.completed_bytes_per_second / (1024 * 1024) : null),
    });
  }
}

function drawHistory() {
  drawLineChart(document.querySelector("#pressureHistory"), [
    { label: "CPU", color: "#2f7d62", points: pressureHistory.points("cpu") },
    { label: "Memory", color: "#b05b3b", points: pressureHistory.points("memory") },
    { label: "I/O", color: "#3f6f9f", points: pressureHistory.points("io") },
  ], { unit: "%", minY: 0 });
  drawLineChart(document.querySelector("#frequencyHistory"), [
    { label: "Average", color: "#2f7d62", points: frequencyHistory.points("mhz") },
  ], { unit: "MHz", minY: 0 });
  drawLineChart(document.querySelector("#networkHistory"), [
    { label: "RX", color: "#2f7d62", points: networkHistory.points("rx") },
    { label: "TX", color: "#b05b3b", points: networkHistory.points("tx") },
  ], { unit: "B/s", minY: 0 });
  drawLineChart(document.querySelector("#irqHistory"), [
    { label: "IRQ", color: "#b05b3b", points: irqHistory.points("total") },
  ], { unit: "%", minY: 0, maxY: 100 });
  drawLineChart(document.querySelector("#blockRateHistory"), [
    { label: "Completions", color: "#3f6f9f", points: blockHistory.points("completions") },
  ], { unit: "IOPS", minY: 0 });
  drawLineChart(document.querySelector("#blockThroughputHistory"), [
    { label: "Completed", color: "#2f7d62", points: blockHistory.points("mib") },
  ], { unit: "MiB/s", minY: 0 });
}

async function fetchJson(url) {
  const response = await fetch(url, { cache: "no-store" });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return response.json();
}

async function refresh() {
  const [systemResult, countersResult] = await Promise.allSettled([
    fetchJson("/api/system"),
    fetchJson("/api/counters"),
  ]);
  const systemSnapshot = systemResult.status === "fulfilled" ? systemResult.value : null;
  const countersSnapshot = countersResult.status === "fulfilled" ? countersResult.value : null;

  if (systemSnapshot) render(systemSnapshot);
  pushHistory(Date.now(), systemSnapshot, countersSnapshot);
  drawHistory();

  if (!systemSnapshot && !countersSnapshot) {
    status.classList.remove("live");
    statusText.textContent = "Disconnected";
  } else {
    status.classList.add("live");
    if (!systemSnapshot) statusText.textContent = "Probes live; system unavailable";
    else if (!countersSnapshot) statusText.textContent = "System live; probes unavailable";
    else statusText.textContent = "Live";
  }
}

refresh();
setInterval(refresh, 2000);
