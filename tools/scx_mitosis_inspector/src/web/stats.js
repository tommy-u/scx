const status = document.querySelector("#status");
const statusText = document.querySelector("#statusText");
const number = new Intl.NumberFormat("en-US", { maximumFractionDigits: 2 });
const statsHistory = new MitosisCharts.History(300);
const trackedCells = new Set();
const chartColors = [
  "#16795b",
  "#2878a6",
  "#b45c3d",
  "#8b63a8",
  "#9a711c",
  "#3f6f2c",
  "#bc476b",
  "#4f647a",
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
    .filter(([name]) => name !== "cells")
    .forEach(([name, value]) => {
      const row = document.createElement("tr");
      appendCell(row, "th", displayName(name), "row");
      appendCell(row, "td", displayValue(value));
      body.append(row);
    });
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

refresh();
setInterval(refresh, 2000);
