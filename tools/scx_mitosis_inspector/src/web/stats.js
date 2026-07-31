const status = document.querySelector("#status");
const statusText = document.querySelector("#statusText");
const number = new Intl.NumberFormat("en-US", { maximumFractionDigits: 2 });

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

function render(snapshot) {
  if (!snapshot.metrics) throw new Error(snapshot.error ?? "Stats unavailable");
  renderGlobal(snapshot.metrics);
  renderCells(snapshot.metrics.cells);
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
