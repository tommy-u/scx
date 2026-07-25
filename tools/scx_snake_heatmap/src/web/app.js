// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

import {
  buildMatrix,
  infernoColor,
  normalizeCount,
  parseTgids,
  topologyBoundaries,
} from "/assets/heatmap.js";

const numberFormat = new Intl.NumberFormat();
const token = document.querySelector('meta[name="snake-session-token"]').content;
const initialWindowMs = Number(document.body.dataset.initialWindowMs);
const maxWindowMs = Number(document.body.dataset.maxWindowMs);

const elements = {
  activePairs: document.querySelector("#activePairs"),
  applyScope: document.querySelector("#applyScope"),
  canvas: document.querySelector("#heatmapCanvas"),
  cgroupField: document.querySelector("#cgroupField"),
  cgroupInput: document.querySelector("#cgroupInput"),
  liveStatus: document.querySelector("#liveStatus"),
  liveStatusText: document.querySelector("#liveStatusText"),
  migrationRate: document.querySelector("#migrationRate"),
  notice: document.querySelector("#notice"),
  scopeMode: document.querySelector("#scopeMode"),
  scopeSummary: document.querySelector("#scopeSummary"),
  tgidField: document.querySelector("#tgidField"),
  tgidInput: document.querySelector("#tgidInput"),
  tooltip: document.querySelector("#heatmapTooltip"),
  totalMigrations: document.querySelector("#totalMigrations"),
  viewport: document.querySelector("#heatmapViewport"),
  windowCoverage: document.querySelector("#windowCoverage"),
  windowSelect: document.querySelector("#windowSelect"),
  zoom: document.querySelector("#zoomControl"),
};

const state = {
  eventSource: null,
  geometry: null,
  orderMode: "topology",
  scale: "log",
  snapshot: null,
  topology: null,
  windowMs: initialWindowMs,
  zoom: 1,
};

configureWindowSelector();
bindControls();
start().catch((error) => {
  setStatus("error", "Connection failed");
  showNotice(error.message);
});

async function start() {
  const response = await fetch("/api/topology", { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`Topology request failed (${response.status})`);
  }
  state.topology = await response.json();
  connectEvents();
  renderHeatmap();
}

function configureWindowSelector() {
  const presets = [1_000, 5_000, 10_000, 30_000, 60_000, 120_000, 300_000]
    .filter((value) => value <= maxWindowMs);
  if (!presets.includes(initialWindowMs)) {
    presets.push(initialWindowMs);
    presets.sort((left, right) => left - right);
  }
  for (const value of presets) {
    const option = document.createElement("option");
    option.value = String(value);
    option.textContent = formatDuration(value);
    option.selected = value === initialWindowMs;
    elements.windowSelect.append(option);
  }
}

function bindControls() {
  elements.windowSelect.addEventListener("change", () => {
    state.windowMs = Number(elements.windowSelect.value);
    connectEvents();
  });
  document.querySelectorAll('input[name="cpuOrder"]').forEach((control) => {
    control.addEventListener("change", () => {
      state.orderMode = control.value;
      renderHeatmap();
    });
  });
  document.querySelectorAll('input[name="colorScale"]').forEach((control) => {
    control.addEventListener("change", () => {
      state.scale = control.value;
      renderHeatmap();
    });
  });
  elements.zoom.addEventListener("input", () => {
    state.zoom = Number(elements.zoom.value);
    renderHeatmap();
  });
  elements.scopeMode.addEventListener("change", renderScopeFields);
  elements.applyScope.addEventListener("click", applyScope);
  elements.canvas.addEventListener("pointermove", showTooltip);
  elements.canvas.addEventListener("pointerleave", hideTooltip);
  new ResizeObserver(() => renderHeatmap()).observe(elements.viewport);
}

function renderScopeFields() {
  const mode = elements.scopeMode.value;
  elements.tgidField.classList.toggle("hidden", mode !== "tgids");
  elements.cgroupField.classList.toggle("hidden", mode !== "cgroup");
}

async function applyScope() {
  hideNotice();
  let payload;
  try {
    if (elements.scopeMode.value === "tgids") {
      payload = { kind: "tgids", tgids: parseTgids(elements.tgidInput.value) };
    } else if (elements.scopeMode.value === "cgroup") {
      const path = elements.cgroupInput.value.trim();
      if (!path) {
        throw new Error("Enter a cgroup path");
      }
      payload = { kind: "cgroup", path };
    } else {
      payload = { kind: "all" };
    }
  } catch (error) {
    showNotice(error.message);
    return;
  }

  elements.applyScope.disabled = true;
  try {
    const response = await fetch("/api/scope", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-snake-token": token,
      },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.error || `Scope change failed (${response.status})`);
    }
  } catch (error) {
    showNotice(error.message);
  } finally {
    elements.applyScope.disabled = false;
  }
}

function connectEvents() {
  state.eventSource?.close();
  setStatus("waiting", "Connecting");
  const source = new EventSource(`/api/events?window_ms=${state.windowMs}`);
  state.eventSource = source;
  source.addEventListener("snapshot", (event) => {
    state.snapshot = JSON.parse(event.data);
    renderSnapshot();
  });
  source.addEventListener("error", (event) => {
    if (event.data) {
      const error = JSON.parse(event.data);
      showNotice(error.error || "Stream error");
      return;
    }
    if (source.readyState !== EventSource.OPEN) {
      setStatus("waiting", "Reconnecting");
    }
  });
}

function renderSnapshot() {
  const snapshot = state.snapshot;
  elements.totalMigrations.textContent = numberFormat.format(snapshot.total);
  elements.migrationRate.textContent = `${formatRate(snapshot.rate_per_second)}/s`;
  elements.activePairs.textContent = numberFormat.format(snapshot.active_pairs);
  elements.windowCoverage.textContent = `${formatDuration(snapshot.observed_ms)} / ${formatDuration(snapshot.window_ms)}`;
  elements.scopeSummary.textContent = formatScope(snapshot.scope);

  if (snapshot.collector_error) {
    setStatus("error", "Collector unavailable");
    showNotice(snapshot.collector_error);
  } else {
    if (snapshot.pair_map_failures || snapshot.task_storage_failures) {
      showNotice(
        `${numberFormat.format(snapshot.pair_map_failures)} pair-map failures | ${numberFormat.format(snapshot.task_storage_failures)} task-state failures`,
      );
    } else {
      hideNotice();
    }
    if (snapshot.scheduler.active) {
      setStatus("active", `Snake active | generation ${snapshot.scheduler.enable_seq}`);
    } else {
      const current = snapshot.scheduler.name || "none";
      setStatus("waiting", `Waiting for Snake | current ${current}`);
    }
  }
  renderHeatmap();
}

function renderHeatmap() {
  if (!state.topology) {
    return;
  }
  const cells = state.snapshot?.cells || [];
  const matrix = buildMatrix(state.topology, cells, state.orderMode);
  const cpuCount = matrix.order.length;
  const viewportWidth = Math.max(320, elements.viewport.clientWidth || 800);
  const fitCell = (viewportWidth - 104) / Math.max(1, cpuCount);
  const cellSize = Math.max(2, Math.min(9, fitCell)) * state.zoom;
  const margins = { left: 58, top: 20, right: 18, bottom: 52 };
  const matrixSize = cpuCount * cellSize;
  const width = Math.ceil(margins.left + matrixSize + margins.right);
  const height = Math.ceil(margins.top + matrixSize + margins.bottom);
  const pixelRatio = Math.min(2, window.devicePixelRatio || 1);

  elements.canvas.style.width = `${width}px`;
  elements.canvas.style.height = `${height}px`;
  elements.canvas.width = Math.ceil(width * pixelRatio);
  elements.canvas.height = Math.ceil(height * pixelRatio);
  const context = elements.canvas.getContext("2d");
  context.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
  context.fillStyle = "#ffffff";
  context.fillRect(0, 0, width, height);
  context.fillStyle = "#11161c";
  context.fillRect(margins.left, margins.top, matrixSize, matrixSize);

  for (let row = 0; row < cpuCount; row += 1) {
    for (let column = 0; column < cpuCount; column += 1) {
      const count = matrix.values[row * cpuCount + column];
      if (count === 0) {
        continue;
      }
      context.fillStyle = infernoColor(normalizeCount(count, matrix.max, state.scale));
      context.fillRect(
        margins.left + column * cellSize,
        margins.top + row * cellSize,
        Math.ceil(cellSize),
        Math.ceil(cellSize),
      );
    }
  }

  drawBoundaries(context, matrix, margins, matrixSize, cellSize);
  drawAxes(context, matrix.order, margins, matrixSize, cellSize);
  state.geometry = { cellSize, margins, matrix, matrixSize };
  elements.canvas.setAttribute(
    "aria-label",
    `CPU migration heatmap with ${numberFormat.format(matrix.total)} transitions across ${cpuCount} CPUs`,
  );
}

function drawBoundaries(context, matrix, margins, matrixSize, cellSize) {
  const widths = { node: 3, package: 2.5, llc: 2, core: 1 };
  const colors = { node: "#ffffff", package: "#d7dee4", llc: "#98a8b5", core: "#536471" };
  for (const boundary of topologyBoundaries(state.topology, matrix.order)) {
    const offset = boundary.index * cellSize;
    context.beginPath();
    context.lineWidth = widths[boundary.level];
    context.strokeStyle = colors[boundary.level];
    context.moveTo(margins.left + offset, margins.top);
    context.lineTo(margins.left + offset, margins.top + matrixSize);
    context.moveTo(margins.left, margins.top + offset);
    context.lineTo(margins.left + matrixSize, margins.top + offset);
    context.stroke();
  }
}

function drawAxes(context, order, margins, matrixSize, cellSize) {
  context.fillStyle = "#43515d";
  context.font = "10px ui-monospace, SFMono-Regular, Menlo, monospace";
  context.textBaseline = "middle";
  const labelStep = Math.max(1, Math.ceil(order.length / 24));
  for (let index = 0; index < order.length; index += labelStep) {
    const center = (index + 0.5) * cellSize;
    context.textAlign = "right";
    context.fillText(String(order[index]), margins.left - 7, margins.top + center);
    context.save();
    context.translate(margins.left + center, margins.top + matrixSize + 7);
    context.rotate(-Math.PI / 2);
    context.textAlign = "right";
    context.fillText(String(order[index]), 0, 0);
    context.restore();
  }

  context.fillStyle = "#25313b";
  context.font = "600 11px ui-sans-serif, system-ui, sans-serif";
  context.textAlign = "center";
  context.fillText("Destination CPU", margins.left + matrixSize / 2, margins.top + matrixSize + 40);
  context.save();
  context.translate(13, margins.top + matrixSize / 2);
  context.rotate(-Math.PI / 2);
  context.fillText("Source CPU", 0, 0);
  context.restore();
}

function showTooltip(event) {
  const geometry = state.geometry;
  if (!geometry) {
    return;
  }
  const bounds = elements.canvas.getBoundingClientRect();
  const x = event.clientX - bounds.left - geometry.margins.left;
  const y = event.clientY - bounds.top - geometry.margins.top;
  const column = Math.floor(x / geometry.cellSize);
  const row = Math.floor(y / geometry.cellSize);
  const size = geometry.matrix.order.length;
  if (row < 0 || column < 0 || row >= size || column >= size) {
    hideTooltip();
    return;
  }

  const from = geometry.matrix.order[row];
  const to = geometry.matrix.order[column];
  const count = geometry.matrix.values[row * size + column];
  const cpuInfo = new Map(state.topology.cpus.map((cpu) => [cpu.cpu, cpu]));
  elements.tooltip.textContent = [
    `CPU ${from} -> CPU ${to}`,
    `${numberFormat.format(count)} migrations`,
    topologyLine("Source", cpuInfo.get(from)),
    topologyLine("Destination", cpuInfo.get(to)),
  ].join("\n");

  const viewportBounds = elements.viewport.getBoundingClientRect();
  const left = event.clientX - viewportBounds.left + elements.viewport.scrollLeft + 14;
  const top = event.clientY - viewportBounds.top + elements.viewport.scrollTop + 14;
  elements.tooltip.style.left = `${Math.max(8, left)}px`;
  elements.tooltip.style.top = `${Math.max(8, top)}px`;
  elements.tooltip.classList.remove("hidden");
}

function hideTooltip() {
  elements.tooltip.classList.add("hidden");
}

function topologyLine(label, cpu) {
  if (!cpu) {
    return `${label}: topology unavailable`;
  }
  return `${label}: node ${cpu.node}, package ${cpu.package}, LLC ${cpu.llc}, core ${cpu.core}`;
}

function setStatus(kind, text) {
  elements.liveStatus.className = `live-status ${kind}`;
  elements.liveStatusText.textContent = text;
}

function showNotice(message) {
  elements.notice.textContent = message;
  elements.notice.classList.remove("hidden");
}

function hideNotice() {
  elements.notice.classList.add("hidden");
}

function formatScope(scope) {
  if (scope === "all" || scope?.all !== undefined) {
    return "All Snake tasks";
  }
  if (scope?.tgids) {
    return `TGIDs ${scope.tgids.join(", ")}`;
  }
  if (scope?.cgroup) {
    return `Cgroup ${scope.cgroup.path}`;
  }
  return "Selected task scope";
}

function formatDuration(milliseconds) {
  if (milliseconds < 1_000) {
    return `${milliseconds} ms`;
  }
  const seconds = milliseconds / 1_000;
  if (seconds < 60) {
    return `${Number.isInteger(seconds) ? seconds : seconds.toFixed(1)} s`;
  }
  const minutes = seconds / 60;
  return `${Number.isInteger(minutes) ? minutes : minutes.toFixed(1)} min`;
}

function formatRate(rate) {
  if (rate >= 1_000_000) {
    return `${(rate / 1_000_000).toFixed(1)}M`;
  }
  if (rate >= 1_000) {
    return `${(rate / 1_000).toFixed(1)}k`;
  }
  return rate < 10 ? rate.toFixed(1) : numberFormat.format(Math.round(rate));
}
