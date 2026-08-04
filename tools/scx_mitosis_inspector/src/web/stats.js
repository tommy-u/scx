const status = document.querySelector("#status");
const statusText = document.querySelector("#statusText");
const number = new Intl.NumberFormat("en-US", { maximumFractionDigits: 2 });
const statsHistory = new MitosisCharts.History(300);
const trackedCells = new Set();
const chartColors = [
  "var(--series-green)",
  "var(--series-blue)",
  "var(--series-orange)",
  "var(--series-purple)",
  "var(--series-gold)",
  "var(--series-olive)",
  "var(--series-pink)",
  "var(--series-slate)",
];

function displayName(name) {
  return name.replaceAll("_", " ");
}

function displayValue(value) {
  if (value === null || value === undefined) return "--";
  if (typeof value === "number") return number.format(value);
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function appendCell(row, tag, value, scope) {
  const cell = document.createElement(tag);
  if (scope) cell.scope = scope;
  cell.textContent = value;
  row.append(cell);
}

function renderGlobal(metrics) {
  const body = document.querySelector("#globalStatsBody");
  body.replaceChildren();
  Object.entries(metrics)
    .filter(([name]) => !["cells", "borrow_flows"].includes(name))
    .forEach(([name, value]) => {
      const row = document.createElement("tr");
      appendCell(row, "th", displayName(name), "row");
      appendCell(row, "td", displayValue(value));
      body.append(row);
    });
}

function cellLabel(cellId) {
  return `Cell ${cellId}`;
}

function percentage(value) {
  return Number.isFinite(value) ? `${number.format(value)}%` : "--";
}

function numericCellIds(flows, cells) {
  const ids = new Set(Object.keys(cells ?? {}).map(Number));
  flows.forEach((flow) => {
    ids.add(Number(flow.borrower_cell));
    ids.add(Number(flow.lender_cell));
  });
  return [...ids].filter(Number.isFinite).sort((left, right) => left - right);
}

function renderBorrowing(metrics) {
  const supported = Object.hasOwn(metrics, "borrow_flows");
  const flows = Object.values(metrics.borrow_flows ?? {}).filter(
    (flow) => Number.isFinite(flow?.borrower_cell) && Number.isFinite(flow?.lender_cell),
  );
  const cellIds = numericCellIds(flows, metrics.cells);
  const byDirection = new Map(
    flows.map((flow) => [`${flow.borrower_cell}:${flow.lender_cell}`, flow]),
  );
  const maxCapacity = Math.max(
    0,
    ...flows.map((flow) => flow.lender_capacity_pct).filter(Number.isFinite),
  );
  const head = document.querySelector("#borrowMatrixHead");
  const body = document.querySelector("#borrowMatrixBody");
  head.replaceChildren();
  body.replaceChildren();

  const header = document.createElement("tr");
  appendCell(header, "th", "Borrower ↓ / Lender →", "col");
  cellIds.forEach((cellId) => appendCell(header, "th", cellLabel(cellId), "col"));
  head.append(header);

  cellIds.forEach((borrower) => {
    const row = document.createElement("tr");
    appendCell(row, "th", cellLabel(borrower), "row");
    cellIds.forEach((lender) => {
      const cell = document.createElement("td");
      if (borrower === lender) {
        cell.className = "borrow-cell-own";
        cell.textContent = "Own";
      } else {
        const flow = byDirection.get(`${borrower}:${lender}`);
        const capacity = flow?.lender_capacity_pct;
        const level = maxCapacity > 0 && Number.isFinite(capacity)
          ? Math.max(1, Math.ceil(5 * capacity / maxCapacity))
          : 0;
        cell.className = `borrow-cell borrow-level-${level}`;
        cell.textContent = flow ? percentage(capacity) : "0%";
        cell.title = flow
          ? `${cellLabel(borrower)} used ${percentage(capacity)} of ${cellLabel(lender)} capacity`
          : `No runtime borrowed by ${cellLabel(borrower)} from ${cellLabel(lender)}`;
      }
      row.append(cell);
    });
    body.append(row);
  });

  const edgeBody = document.querySelector("#borrowFlowsBody");
  edgeBody.replaceChildren();
  flows
    .sort((left, right) => (right.runtime_ns ?? 0) - (left.runtime_ns ?? 0))
    .forEach((flow) => {
      const row = document.createElement("tr");
      appendCell(row, "th", cellLabel(flow.borrower_cell), "row");
      appendCell(row, "td", cellLabel(flow.lender_cell));
      appendCell(row, "td", displayValue(flow.runtime_ns / 1e6));
      appendCell(row, "td", percentage(flow.borrower_runtime_pct));
      appendCell(row, "td", percentage(flow.lender_capacity_pct));
      edgeBody.append(row);
    });

  if (flows.length === 0) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 5;
    cell.className = "borrowing-empty";
    cell.textContent = supported
      ? "No cross-cell borrowing in the latest interval"
      : "Pairwise borrowing is unavailable from this scheduler version";
    row.append(cell);
    edgeBody.append(row);
  }
}

function renderCells(cells) {
  const entries = Object.entries(cells ?? {});
  const columns = [...new Set(entries.flatMap(([, values]) => Object.keys(values)))];
  const head = document.querySelector("#cellStatsHead");
  const body = document.querySelector("#cellStatsBody");
  head.replaceChildren();
  body.replaceChildren();

  const headerRow = document.createElement("tr");
  appendCell(headerRow, "th", "Cell", "col");
  columns.forEach((name) => appendCell(headerRow, "th", displayName(name), "col"));
  head.append(headerRow);

  entries.forEach(([cellId, values]) => {
    const row = document.createElement("tr");
    appendCell(row, "th", cellId, "row");
    columns.forEach((name) => appendCell(row, "td", displayValue(values[name])));
    body.append(row);
  });
  document.querySelector("#cellCount").textContent = number.format(entries.length);
}

function metric(values, ...names) {
  return names.map((name) => values?.[name]).find(Number.isFinite);
}

function historyKey(cellId, signal) {
  return `cell.${cellId}.${signal}`;
}

function renderCellHistory(cells) {
  const sample = {};
  Object.entries(cells ?? {}).forEach(([cellId, values]) => {
    const signals = {
      util: metric(values, "smoothed_util_pct", "util_pct"),
      demand: metric(values, "demand_borrow_pct"),
      borrowed: metric(values, "borrowed_pct"),
      lent: metric(values, "lent_pct"),
    };
    const available = Object.entries(signals).filter(([, value]) => Number.isFinite(value));
    if (available.length === 0) return;
    trackedCells.add(cellId);
    available.forEach(([signal, value]) => {
      sample[historyKey(cellId, signal)] = value;
    });
  });
  statsHistory.push(Date.now(), sample);
  drawCellHistory();
}

function drawCellHistory() {
  const cellsWithUtilization = [...trackedCells].filter(
    (cellId) => statsHistory.points(historyKey(cellId, "util")).length > 0,
  );
  MitosisCharts.drawLineChart(
    document.querySelector("#cellUtilizationChart"),
    cellsWithUtilization.map((cellId, index) => ({
      label: `Cell ${cellId}`,
      color: chartColors[index % chartColors.length],
      points: statsHistory.points(historyKey(cellId, "util")),
    })),
    { unit: "%", minY: 0, maxY: 100 },
  );

  const balanceSeries = [];
  [...trackedCells].forEach((cellId) => {
    ["demand", "borrowed", "lent"].forEach((signal) => {
      const points = statsHistory.points(historyKey(cellId, signal));
      if (points.length === 0) return;
      balanceSeries.push({
        label: `Cell ${cellId} ${signal}`,
        color: chartColors[balanceSeries.length % chartColors.length],
        points,
      });
    });
  });
  MitosisCharts.drawLineChart(
    document.querySelector("#cellBalanceChart"),
    balanceSeries,
    { unit: "%", minY: 0, maxY: 100 },
  );
}

function render(snapshot) {
  if (!snapshot.metrics) throw new Error(snapshot.error ?? "Stats unavailable");
  renderBorrowing(snapshot.metrics);
  renderGlobal(snapshot.metrics);
  renderCells(snapshot.metrics.cells);
  renderCellHistory(snapshot.metrics.cells);
  document.querySelector("#refreshed").textContent = new Date().toLocaleTimeString();

  status.classList.toggle("live", !snapshot.error);
  status.classList.toggle("stale", Boolean(snapshot.error));
  statusText.textContent = snapshot.error ? "Stale" : "Live";
}

async function refresh() {
  try {
    const response = await fetch("/api/stats", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    render(await response.json());
  } catch (error) {
    status.classList.remove("live", "stale");
    statusText.textContent = "Unavailable";
  }
}

globalThis.addEventListener?.("mitosis:stats-reset", () => {
  statsHistory.clear();
  trackedCells.clear();
  drawCellHistory();
});
document.addEventListener?.("mitosis-theme-change", drawCellHistory);

refresh();
setInterval(refresh, 2000);
