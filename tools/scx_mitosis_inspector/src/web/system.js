const status = document.querySelector("#status");
const statusText = document.querySelector("#statusText");
const number = new Intl.NumberFormat("en-US", { maximumFractionDigits: 2 });

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

  status.classList.add("live");
  statusText.textContent = "Live";
}

async function refresh() {
  try {
    const response = await fetch("/api/system", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    render(await response.json());
  } catch (error) {
    status.classList.remove("live");
    statusText.textContent = "Disconnected";
  }
}

refresh();
setInterval(refresh, 2000);
