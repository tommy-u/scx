// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

import {
  buildCpuUsage,
  buildMatrix,
  infernoColor,
  normalizeCount,
  normalizeUtilization,
  parseTgids,
  topologyBoundaries,
  topologyGroups,
} from "/assets/heatmap.js";
import {
  compactCpuList,
  decorateCells,
  fieldReferenceGroups,
  ladderPercentages,
  queueLadderSections,
  queueTopologyModel,
  routeFromHash,
  rungLadderPercentages,
  rungPercentages,
  selectionRungHitFlow,
} from "/assets/inspection.js";

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
  cellsFreshness: document.querySelector("#cellsFreshness"),
  cellsNotice: document.querySelector("#cellsNotice"),
  cellsView: document.querySelector("#cellsView"),
  cellDetail: document.querySelector("#cellDetail"),
  cellList: document.querySelector("#cellList"),
  liveStatus: document.querySelector("#liveStatus"),
  liveStatusText: document.querySelector("#liveStatusText"),
  migrationRate: document.querySelector("#migrationRate"),
  notice: document.querySelector("#notice"),
  policyFreshness: document.querySelector("#policyFreshness"),
  policyActivationNotice: document.querySelector("#policyActivationNotice"),
  policyChoices: document.querySelector("#policyChoices"),
  policyDialog: document.querySelector("#policyDialog"),
  policyDialogName: document.querySelector("#policyDialogName"),
  policyDialogSource: document.querySelector("#policyDialogSource"),
  policyDialogSummary: document.querySelector("#policyDialogSummary"),
  policyLibraryNotice: document.querySelector("#policyLibraryNotice"),
  policyLibraryStatus: document.querySelector("#policyLibraryStatus"),
  invalidPolicies: document.querySelector("#invalidPolicies"),
  policyNotice: document.querySelector("#policyNotice"),
  policyView: document.querySelector("#policyView"),
  queueTopology: document.querySelector("#queueTopology"),
  primaryNav: document.querySelector("#primaryNav"),
  referencePopover: document.querySelector("#referencePopover"),
  confirmPolicyActivation: document.querySelector("#confirmPolicyActivation"),
  scopeMode: document.querySelector("#scopeMode"),
  scopeSummary: document.querySelector("#scopeSummary"),
  tgidField: document.querySelector("#tgidField"),
  tgidInput: document.querySelector("#tgidInput"),
  tooltip: document.querySelector("#heatmapTooltip"),
  totalMigrations: document.querySelector("#totalMigrations"),
  activityView: document.querySelector("#activityView"),
  slotComparison: document.querySelector("#slotComparison"),
  viewport: document.querySelector("#heatmapViewport"),
  windowCoverage: document.querySelector("#windowCoverage"),
  windowSelect: document.querySelector("#windowSelect"),
  zoom: document.querySelector("#zoomControl"),
};

const state = {
  eventSource: null,
  geometry: null,
  inspection: null,
  inspectionError: null,
  inspectionLoading: false,
  inspectionSequence: 0,
  lastInspectionAt: 0,
  orderMode: "topology",
  popoverPinned: false,
  policyCatalog: null,
  policyCatalogError: null,
  policyCatalogLoading: false,
  policyLibraryMessage: null,
  policyActivationPending: false,
  selectedPolicy: null,
  referenceId: 0,
  references: new Map(),
  route: routeFromHash(window.location.hash),
  scale: "log",
  selectedCellId: null,
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
  renderRoute();
  renderHeatmap();
  await loadInspection();
  await loadPolicyCatalog();
  window.setInterval(loadInspection, 1_000);
  window.setInterval(loadPolicyCatalog, 5_000);
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
  window.addEventListener("hashchange", renderRoute);
  elements.cellList.addEventListener("click", (event) => {
    const control = event.target.closest("[data-cell-id]");
    if (!control) {
      return;
    }
    state.selectedCellId = Number(control.dataset.cellId);
    renderCells();
  });
  elements.policyChoices.addEventListener("click", (event) => {
    const control = event.target.closest("[data-policy-id]");
    if (!control || control.disabled) {
      return;
    }
    openPolicyDialog(control.dataset.policyId);
  });
  elements.confirmPolicyActivation.addEventListener("click", activateSelectedPolicy);
  elements.policyDialog.addEventListener("close", () => {
    state.selectedPolicy = null;
    hideElementNotice(elements.policyActivationNotice);
  });
  document.addEventListener("pointerover", (event) => {
    const control = event.target.closest("[data-reference-id]");
    if (control) {
      showReferencePopover(control);
    }
  });
  document.addEventListener("focusin", (event) => {
    const control = event.target.closest("[data-reference-id]");
    if (control) {
      showReferencePopover(control);
    }
  });
  document.addEventListener("click", (event) => {
    const control = event.target.closest("[data-reference-id]");
    if (control) {
      state.popoverPinned = true;
      showReferencePopover(control);
    } else if (!event.target.closest("#referencePopover")) {
      hideReferencePopover(true);
    }
  });
  document.addEventListener("pointerout", (event) => {
    if (
      event.target.closest("[data-reference-id]") &&
      !state.popoverPinned &&
      !event.relatedTarget?.closest?.("#referencePopover")
    ) {
      hideReferencePopover(false);
    }
  });
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

  const notices = [];
  if (snapshot.collector_error) {
    setStatus("error", "Collector unavailable");
    notices.push(snapshot.collector_error);
  } else {
    if (snapshot.pair_map_failures || snapshot.task_storage_failures) {
      notices.push(
        `${numberFormat.format(snapshot.pair_map_failures)} pair-map failures | ${numberFormat.format(snapshot.task_storage_failures)} task-state failures`,
      );
    }
    if (snapshot.scheduler.active) {
      setStatus("active", `Snake active | generation ${snapshot.scheduler.enable_seq}`);
    } else {
      const current = snapshot.scheduler.name || "none";
      setStatus("waiting", `Waiting for Snake | current ${current}`);
    }
  }
  if (snapshot.cpu_usage_error) {
    notices.push(snapshot.cpu_usage_error);
  }
  if (notices.length > 0) {
    showNotice(notices.join(" | "));
  } else {
    hideNotice();
  }
  renderHeatmap();
}

function renderHeatmap() {
  if (!state.topology) {
    return;
  }
  const cells = state.snapshot?.cells || [];
  const matrix = buildMatrix(state.topology, cells, state.orderMode);
  const usage = buildCpuUsage(
    state.topology,
    state.snapshot?.cpu_usage || [],
    state.orderMode,
  );
  const cpuCount = matrix.order.length;
  const viewportWidth = Math.max(320, elements.viewport.clientWidth || 800);
  const fitCell = (viewportWidth - 104) / Math.max(1, cpuCount);
  const cellSize = Math.max(2, Math.min(9, fitCell)) * state.zoom;
  const margins = { left: 64, top: 20, right: 18 };
  const matrixSize = cpuCount * cellSize;
  const usageTop = margins.top + matrixSize + 68;
  const usageHeight = Math.max(13, Math.min(26, cellSize * 2.5));
  const width = Math.ceil(margins.left + matrixSize + margins.right);
  const height = Math.ceil(usageTop + usageHeight + 46);
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
  drawCpuUsage(context, usage, margins, matrixSize, cellSize, usageTop, usageHeight);
  state.geometry = {
    cellSize,
    margins,
    matrix,
    matrixSize,
    usage,
    usageHeight,
    usageTop,
  };
  elements.canvas.setAttribute(
    "aria-label",
    `CPU migration heatmap with ${numberFormat.format(matrix.total)} transitions and all-Snake utilization across ${cpuCount} CPUs`,
  );
}

function drawCpuUsage(context, usage, margins, matrixSize, cellSize, top, height) {
  context.fillStyle = "#11161c";
  context.fillRect(margins.left, top, matrixSize, height);
  for (let index = 0; index < usage.order.length; index += 1) {
    const utilization = usage.utilizationPct[index];
    if (utilization <= 0) {
      continue;
    }
    context.fillStyle = infernoColor(normalizeUtilization(utilization, state.scale));
    context.fillRect(
      margins.left + index * cellSize,
      top,
      Math.ceil(cellSize),
      height,
    );
  }

  context.fillStyle = "#25313b";
  context.font = "600 10px ui-sans-serif, system-ui, sans-serif";
  context.textAlign = "right";
  context.textBaseline = "middle";
  context.fillText("All Snake", margins.left - 7, top + height / 2);

  const boundaries = topologyBoundaries(state.topology, usage.order);
  for (const boundary of boundaries) {
    const x = margins.left + boundary.index * cellSize;
    context.beginPath();
    context.lineWidth = boundary.level === "llc" ? 2 : 1;
    context.strokeStyle = boundary.level === "llc" ? "#ffffff" : "#6f7f8b";
    context.moveTo(x, top);
    context.lineTo(x, top + height);
    context.stroke();
  }

  context.fillStyle = "#43515d";
  context.font = "10px ui-monospace, SFMono-Regular, Menlo, monospace";
  context.textAlign = "center";
  const labelStep = Math.max(1, Math.ceil(usage.order.length / 24));
  for (let index = 0; index < usage.order.length; index += labelStep) {
    context.fillText(
      String(usage.order[index]),
      margins.left + (index + 0.5) * cellSize,
      top + height + 10,
    );
  }

  const bracketY = top + height + 23;
  context.font = "600 9px ui-sans-serif, system-ui, sans-serif";
  for (const group of topologyGroups(state.topology, usage.order, "llc")) {
    const left = margins.left + group.start * cellSize;
    const right = margins.left + group.end * cellSize;
    context.beginPath();
    context.lineWidth = 1;
    context.strokeStyle = "#82919c";
    context.moveTo(left, bracketY - 3);
    context.lineTo(left, bracketY);
    context.lineTo(right, bracketY);
    context.lineTo(right, bracketY - 3);
    context.stroke();
    if (right - left >= 30 && group.value !== undefined) {
      context.fillText(`LLC ${group.value}`, (left + right) / 2, bracketY + 10);
    }
  }
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
  const canvasX = event.clientX - bounds.left;
  const canvasY = event.clientY - bounds.top;
  const x = canvasX - geometry.margins.left;
  const y = canvasY - geometry.margins.top;
  const column = Math.floor(x / geometry.cellSize);
  const row = Math.floor(y / geometry.cellSize);
  const size = geometry.matrix.order.length;
  if (
    column >= 0 && column < size &&
    canvasY >= geometry.usageTop &&
    canvasY < geometry.usageTop + geometry.usageHeight
  ) {
    const cpu = geometry.usage.order[column];
    const runtimeNs = geometry.usage.runtimeNs[column];
    const utilization = geometry.usage.utilizationPct[column];
    const cpuInfo = new Map(state.topology.cpus.map((entry) => [entry.cpu, entry]));
    elements.tooltip.textContent = [
      `CPU ${cpu}`,
      `All Snake utilization: ${utilization.toFixed(1)}%`,
      `${formatRuntime(runtimeNs)} runtime over ${formatDuration(state.snapshot?.cpu_usage_observed_ms || 0)}`,
      topologyLine("Topology", cpuInfo.get(cpu)),
    ].join("\n");
    positionTooltip(event);
    return;
  }
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

  positionTooltip(event);
}

function positionTooltip(event) {
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

function renderRoute() {
  state.route = routeFromHash(window.location.hash);
  for (const view of [elements.activityView, elements.policyView, elements.cellsView]) {
    view.classList.toggle("hidden", view.dataset.view !== state.route);
  }
  elements.primaryNav.querySelectorAll("[data-route]").forEach((link) => {
    if (link.dataset.route === state.route) {
      link.setAttribute("aria-current", "page");
    } else {
      link.removeAttribute("aria-current");
    }
  });
  hideReferencePopover(true);
  if (state.route === "activity") {
    window.requestAnimationFrame(renderHeatmap);
  } else {
    renderInspectionViews();
  }
}

async function loadInspection() {
  if (state.inspectionLoading) {
    return;
  }
  state.inspectionLoading = true;
  try {
    const response = await fetch("/api/inspection", { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`Inspection request failed (${response.status})`);
    }
    const payload = await response.json();
    state.inspection = payload.snapshot;
    state.inspectionError = payload.error;
    state.inspectionSequence = payload.sequence;
    state.lastInspectionAt = Date.now();
  } catch (error) {
    state.inspectionError = error.message;
  } finally {
    state.inspectionLoading = false;
  }
  renderInspectionViews();
}

async function loadPolicyCatalog() {
  if (state.policyCatalogLoading) {
    return;
  }
  state.policyCatalogLoading = true;
  try {
    const response = await fetch("/api/policies", { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`Policy library request failed (${response.status})`);
    }
    const payload = await response.json();
    state.policyCatalog = payload.catalog;
    state.policyCatalogError = payload.error;
  } catch (error) {
    state.policyCatalogError = error.message;
  } finally {
    state.policyCatalogLoading = false;
  }
  if (state.route === "policy") {
    renderPolicyLibrary();
  }
}

function renderInspectionViews() {
  if (state.route === "policy") {
    if (!elements.referencePopover.classList.contains("hidden")) {
      return;
    }
    renderPolicy();
  } else if (state.route === "cells") {
    renderCells();
  }
}

function renderPolicy() {
  renderInspectionStatus(elements.policyNotice, elements.policyFreshness);
  renderPolicyLibrary();
  state.references.clear();
  state.referenceId = 0;
  if (!state.inspection) {
    elements.slotComparison.replaceChildren();
    elements.queueTopology.replaceChildren();
    elements.queueTopology.classList.add("hidden");
    return;
  }
  elements.slotComparison.innerHTML = state.inspection.slots
    .map(renderSlot)
    .join("");
  renderResolvedQueueTopology();
}

function renderResolvedQueueTopology() {
  const model = queueTopologyModel(
    state.inspection.fairness,
    state.inspection.queue_topology,
  );
  elements.queueTopology.classList.remove("hidden");
  const summary = `
    <dl class="queue-topology-summary">
      <div><dt>Fairness</dt><dd>${escapeHtml(model.mode)}</dd></div>
      <div><dt>Clock model</dt><dd>${escapeHtml(model.clockModel)}</dd></div>
      <div><dt>Layout</dt><dd>${escapeHtml(model.layout || "None")}</dd></div>
      <div><dt>Affinity DSQs</dt><dd>${formatCount(model.affinityQueueCount)}</dd></div>
    </dl>`;
  if (!model.layout) {
    elements.queueTopology.innerHTML = `
      <header class="queue-topology-heading">
        <div><h3>Scheduler execution model</h3><p>Fairness and attachment-time queue topology</p></div>
      </header>
      ${summary}
      <p class="queue-topology-empty">No resolved cell queue topology is installed.</p>`;
    return;
  }
  const cells = model.cells.map((cell) => `
    <tr>
      <th scope="row">${escapeHtml(cell.label)}</th>
      <td>${formatCount(cell.index)}</td>
      <td>${formatCount(cell.cpu_weight)}</td>
      <td><code>cell:${formatCount(cell.clock_index)}</code></td>
      <td class="cpu-mask">${escapeHtml(compactCpuList(cell.primary_cpus))}</td>
      <td class="cpu-mask">${escapeHtml(compactCpuList(cell.borrowable_cpus))}</td>
    </tr>`).join("");
  const queues = model.normalQueues.map((queue) => `
    <tr>
      <th scope="row"><code>${escapeHtml(queue.dsq)}</code></th>
      <td>Cell ${formatCount(queue.cell_id)} <small>index ${formatCount(queue.cell_index)}</small></td>
      <td>${queue.llc_id == null ? "All" : formatCount(queue.llc_id)}</td>
      <td><code>cell:${formatCount(queue.clock_index)}</code></td>
      <td class="cpu-mask">${escapeHtml(compactCpuList(queue.consumer_cpus))}</td>
    </tr>`).join("");
  const routes = model.cpuRoutes.map((route) => `
    <tr>
      <th scope="row">${formatCount(route.cpu)}</th>
      <td>Cell ${formatCount(route.owner_cell_id)} <small>index ${formatCount(route.owner_cell_index)}</small></td>
      <td>${formatCount(route.llc_id)}</td>
      <td><code>${escapeHtml(route.normalDsq)}</code></td>
      <td><code>${escapeHtml(route.affinityDsq)}</code></td>
    </tr>`).join("");
  elements.queueTopology.innerHTML = `
    <header class="queue-topology-heading">
      <div><h3>Resolved queue topology</h3><p>Attachment-time CPU ownership, DSQs, and clock domains</p></div>
    </header>
    ${summary}
    <section class="queue-topology-table-section">
      <h4>Cell allocation</h4>
      <div class="queue-topology-table-wrap">
        <table><thead><tr><th>Cell</th><th>Dense</th><th>Weight</th><th>Clock</th><th>Primary CPUs</th><th>Borrowable CPUs</th></tr></thead><tbody>${cells}</tbody></table>
      </div>
    </section>
    <details class="queue-topology-details">
      <summary>Normal DSQs (${formatCount(model.normalQueues.length)})</summary>
      <div class="queue-topology-table-wrap">
        <table><thead><tr><th>DSQ</th><th>Cell</th><th>LLC</th><th>Clock</th><th>Consumer CPUs</th></tr></thead><tbody>${queues}</tbody></table>
      </div>
    </details>
    <details class="queue-topology-details">
      <summary>Per-CPU routing (${formatCount(model.cpuRoutes.length)} CPUs)</summary>
      <div class="queue-topology-table-wrap queue-route-table-wrap">
        <table><thead><tr><th>CPU</th><th>Owner</th><th>LLC</th><th>Normal DSQ</th><th>Affinity DSQ</th></tr></thead><tbody>${routes}</tbody></table>
      </div>
    </details>`;
}

function renderSlot(slot) {
  const stateLabel = slot.state === "active"
    ? "Active"
    : slot.state === "inactive"
      ? "Inactive"
      : "Empty";
  if (!slot.policy) {
    return `
      <section class="slot-panel empty-slot" aria-label="Ladder slot ${slot.slot}, empty">
        <header class="slot-heading">
          <h3>Slot ${slot.slot}</h3>
          <span class="slot-state empty">${stateLabel}</span>
        </header>
        <p>No ladder is installed in this slot.</p>
      </section>`;
  }
  const metrics = slot.metrics || {};
  const ladderRates = ladderPercentages(metrics);
  const metricKind = slot.state === "active" ? "Live cumulative metrics" : "Frozen last-active metrics";
  const timestamp = slot.state === "active" ? slot.activated_at_ms : slot.deactivated_at_ms;
  const rungs = slot.policy.rungs
    .map((rung, index) => renderRung(
      rung,
      index,
      slot.policy.rungs.length,
      metrics,
      slot.policy.queues,
    ))
    .join("");
  const queueLadders = renderQueuePolicy(slot.policy.queues);
  const maskTables = slot.policy.mask_tables.length > 0
    ? slot.policy.mask_tables.map((table) => `
        <li><code>${escapeHtml(String(table.id))}</code> ${escapeHtml(table.name)}
          <span>${escapeHtml(table.source)} · ${numberFormat.format(table.entry_count)} entries</span>
        </li>`).join("")
    : "<li>None</li>";
  return `
    <section class="slot-panel" aria-label="Ladder slot ${slot.slot}, ${stateLabel}">
      <header class="slot-heading">
        <div>
          <h3>Slot ${slot.slot}</h3>
          <p>Generation ${numberFormat.format(slot.generation)} · ${metricKind}</p>
        </div>
        <span class="slot-state ${escapeHtml(slot.state)}">${stateLabel}</span>
      </header>
      <dl class="slot-summary">
        <div><dt>Observed</dt><dd>${formatTimestamp(timestamp)}</dd></div>
        <div><dt>Select calls</dt><dd>${formatCount(metrics.select_calls)}</dd></div>
        <div><dt>Direct dispatches</dt><dd>${formatCount(metrics.direct_dispatches)}</dd></div>
        <div><dt>Exhaustions</dt><dd>${formatCount(metrics.ladder_exhaustions)}</dd></div>
      </dl>
      <section class="policy-ladder-section idle-ladder-section">
        <header class="ladder-heading">
          <h4>Idle selection</h4>
          <span>Fixed first-match order</span>
        </header>
        <div class="ladder-rail">${rungs}</div>
        <dl class="ladder-summary">
          <div><dt>Entire ladder</dt><dd>${formatCount(metrics.select_calls)} evaluations<small>${formatCount(metrics.invalid_errors)} errors</small></dd></div>
          <div><dt>Hit</dt><dd>${formatCount(metrics.direct_dispatches)}<small>${formatPercentage(ladderRates.hit)}</small></dd></div>
          <div><dt>Miss</dt><dd>${formatCount(metrics.ladder_exhaustions)}<small>${formatPercentage(ladderRates.miss)}</small></dd></div>
        </dl>
        <div class="fallback-row">
          <span>All rungs missed</span>
          <span aria-hidden="true">→</span>
          ${fieldButton("Fallback", slot.policy.fallback)}
          ${slot.policy.queues ? '<span class="fallback-destination">→ enqueue ladder</span>' : ""}
        </div>
      </section>
      ${queueLadders}
      <details class="policy-details">
        <summary>Mask tables and source policy</summary>
        <h4>Installed mask tables</h4>
        <ul class="mask-table-list">${maskTables}</ul>
        <h4>Policy source</h4>
        <pre>${escapeHtml(slot.policy.source)}</pre>
      </details>
    </section>`;
}

function renderQueuePolicy(queues) {
  if (!queues) {
    return `
      <section class="queue-policy-empty">
        <strong>Queue callback ladders</strong>
        <span>Not configured for this policy</span>
      </section>`;
  }
  const sections = queueLadderSections(queues).map(renderQueueLadder).join("");
  return `
    <section class="queue-policy-block">
      <header class="queue-policy-heading">
        <div>
          <h4>Queue callback ladders</h4>
          <p>Installed with this policy generation</p>
        </div>
        <span>Layout <code>${escapeHtml(queues.layout)}</code></span>
      </header>
      ${sections}
    </section>`;
}

function renderQueueLadder(section) {
  const rungs = section.rungs.map((rung) => `
    <article class="rung-row queue-rung-row">
      <div class="rung-index" aria-label="${escapeHtml(section.title)} rung ${rung.index}">${rung.index}</div>
      <div class="rung-body">
        <header>
          <div>
            <h4>${escapeHtml(rung.operation)}</h4>
            <p>${escapeHtml(rung.role)}</p>
          </div>
        </header>
        <div class="rung-flow">
          <span class="hit-flow">${escapeHtml(rung.flow.hit)}</span>
          <span>${escapeHtml(rung.flow.miss)}</span>
        </div>
      </div>
    </article>`).join("");
  const cycle = section.kind === "dispatch" ? '<span aria-hidden="true">↻</span> ' : "";
  return `
    <section class="policy-ladder-section queue-ladder-section">
      <header class="ladder-heading">
        <h4>${escapeHtml(section.title)}</h4>
        <span>${cycle}${escapeHtml(section.behavior)}</span>
      </header>
      <div class="ladder-rail queue-ladder-rail">${rungs}</div>
      <p class="queue-ladder-terminal">${escapeHtml(section.terminal)}</p>
    </section>`;
}

function renderPolicyLibrary() {
  const catalog = state.policyCatalog;
  if (state.policyCatalogError) {
    elements.policyLibraryStatus.textContent = "Unavailable";
    showElementNotice(elements.policyLibraryNotice, state.policyCatalogError);
    elements.policyChoices.replaceChildren();
    elements.invalidPolicies.classList.add("hidden");
    return;
  }
  if (!catalog) {
    elements.policyLibraryStatus.textContent = "Loading policies";
    hideElementNotice(elements.policyLibraryNotice);
    elements.policyChoices.replaceChildren();
    elements.invalidPolicies.classList.add("hidden");
    return;
  }
  if (state.policyLibraryMessage) {
    showElementNotice(
      elements.policyLibraryNotice,
      state.policyLibraryMessage.text,
      state.policyLibraryMessage.kind,
    );
  } else {
    hideElementNotice(elements.policyLibraryNotice);
  }
  elements.policyLibraryStatus.textContent = `${numberFormat.format(catalog.policies.length)} valid policies`;
  const activeSource = state.inspection?.slots
    ?.find((slot) => slot.state === "active")
    ?.policy?.source?.trim();
  if (catalog.policies.length === 0) {
    elements.policyChoices.innerHTML = '<p class="empty-state">No valid TOML policies were found.</p>';
  } else {
    elements.policyChoices.innerHTML = catalog.policies.map((policy) => {
      const active = activeSource && policy.source.trim() === activeSource;
      return `
        <article class="policy-choice${active ? " active" : ""}">
          <div>
            <h4>${escapeHtml(policy.name)}</h4>
            <p><code>${escapeHtml(policy.id)}</code> · ${escapeHtml(policy.summary)}</p>
          </div>
          <button class="${active ? "secondary-button" : "apply-button"}" type="button"
            data-policy-id="${escapeHtml(policy.id)}" ${active ? "disabled" : ""}>
            ${active ? "Active" : "Activate"}
          </button>
        </article>`;
    }).join("");
  }
  const invalid = catalog.invalid || [];
  if (invalid.length === 0) {
    elements.invalidPolicies.classList.add("hidden");
  } else {
    elements.invalidPolicies.classList.remove("hidden");
    elements.invalidPolicies.querySelector("summary").textContent =
      `${numberFormat.format(invalid.length)} invalid policy files`;
    elements.invalidPolicies.querySelector("ul").innerHTML = invalid.map((entry) =>
      `<li><code>${escapeHtml(entry.id)}</code><span>${escapeHtml(entry.error)}</span></li>`
    ).join("");
  }
}

function openPolicyDialog(policyId) {
  const policy = state.policyCatalog?.policies?.find((candidate) => candidate.id === policyId);
  if (!policy) {
    showElementNotice(elements.policyLibraryNotice, `Policy ${policyId} is no longer available.`);
    return;
  }
  state.selectedPolicy = policy;
  state.policyLibraryMessage = null;
  elements.policyDialogName.textContent = policy.name;
  elements.policyDialogSummary.textContent = policy.summary;
  elements.policyDialogSource.textContent = policy.source;
  hideElementNotice(elements.policyActivationNotice);
  elements.policyDialog.showModal();
}

async function activateSelectedPolicy() {
  const policy = state.selectedPolicy;
  if (!policy || state.policyActivationPending) {
    return;
  }
  state.policyActivationPending = true;
  elements.confirmPolicyActivation.disabled = true;
  hideElementNotice(elements.policyActivationNotice);
  try {
    const response = await fetch("/api/policies/activate", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-snake-token": token,
      },
      body: JSON.stringify({ policy_id: policy.id }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(body.error || `Policy activation failed (${response.status})`);
    }
    elements.policyDialog.close();
    state.policyLibraryMessage = {
      text: `Activated ${policy.name} as generation ${numberFormat.format(body.generation)}.`,
      kind: "success",
    };
    await loadInspection();
    await loadPolicyCatalog();
  } catch (error) {
    showElementNotice(elements.policyActivationNotice, error.message);
  } finally {
    state.policyActivationPending = false;
    elements.confirmPolicyActivation.disabled = false;
  }
}

function renderRung(rung, index, count, ladderMetrics, queues) {
  const metrics = rung.metrics || {};
  const percentages = rungPercentages(metrics);
  const ladderRates = rungLadderPercentages(metrics, ladderMetrics);
  const missDestination = index + 1 < count ? `rung ${index + 1}` : "fallback";
  return `
    <article class="rung-row">
      <div class="rung-index" aria-label="Rung ${rung.index}">${rung.index}</div>
      <div class="rung-body">
        <header>
          <div>
            <h4>${escapeHtml(rung.operation)}</h4>
            <p>${escapeHtml(rung.scope)}</p>
          </div>
          <dl class="rung-metrics">
            <div><dt>Attempts</dt><dd>${formatCount(metrics.attempts)}</dd></div>
            <div><dt>Hits</dt><dd>${formatCount(metrics.hits)}<small>${formatPercentage(percentages.hit)} of rung attempts</small><small>${formatPercentage(ladderRates.hit)} of ladder calls</small></dd></div>
            <div><dt>Misses</dt><dd>${formatCount(metrics.misses)}<small>${formatPercentage(percentages.miss)} of rung attempts</small><small>${formatPercentage(ladderRates.miss)} of ladder calls</small></dd></div>
            <div><dt>Errors</dt><dd>${formatCount(metrics.errors)}</dd></div>
          </dl>
        </header>
        <div class="rung-fields">
          ${fieldButton("Opcode", rung.opcode)}
          ${fieldButton("Input", rung.input)}
          ${fieldButton("Flags", rung.flags)}
          ${fieldButton("Data", rung.data)}
        </div>
        <div class="rung-flow">
          <span class="hit-flow">${escapeHtml(selectionRungHitFlow(rung, queues))}</span>
          <span>Miss → ${missDestination}</span>
        </div>
      </div>
    </article>`;
}

function fieldButton(name, reference) {
  const id = `field-reference-${state.referenceId += 1}`;
  state.references.set(id, { name, reference });
  const selected = fieldReferenceGroups(reference).selected;
  return `
    <div class="rung-field">
      <span>${escapeHtml(name)}</span>
      <button type="button" class="field-value" data-reference-id="${id}">
        ${escapeHtml(selected.value)}
      </button>
    </div>`;
}

function showReferencePopover(control) {
  const entry = state.references.get(control.dataset.referenceId);
  if (!entry) {
    return;
  }
  const groups = fieldReferenceGroups(entry.reference);
  elements.referencePopover.innerHTML = `
    <header>
      <span>${escapeHtml(entry.name)}</span>
      <strong>${escapeHtml(groups.selected.label)}</strong>
    </header>
    <p>${escapeHtml(groups.selected.description)}</p>
    ${referenceGroup("Valid here", groups.valid, "valid")}
    ${referenceGroup("Other ABI choices · invalid here", groups.other, "other")}`;
  elements.referencePopover.classList.remove("hidden");
  const bounds = control.getBoundingClientRect();
  const width = Math.min(420, window.innerWidth - 24);
  const left = Math.min(window.innerWidth - width - 12, Math.max(12, bounds.left));
  const below = bounds.bottom + 8;
  const top = below + 360 < window.innerHeight
    ? below
    : Math.max(12, bounds.top - Math.min(360, elements.referencePopover.scrollHeight) - 8);
  elements.referencePopover.style.width = `${width}px`;
  elements.referencePopover.style.left = `${left}px`;
  elements.referencePopover.style.top = `${top}px`;
}

function referenceGroup(title, choices, kind) {
  if (choices.length === 0) {
    return "";
  }
  return `
    <section class="reference-group ${kind}">
      <h5>${escapeHtml(title)}</h5>
      <dl>${choices.map((choice) => `
        <div>
          <dt><code>${escapeHtml(choice.value)}</code> ${escapeHtml(choice.label)}</dt>
          <dd>${escapeHtml(choice.description)}</dd>
        </div>`).join("")}</dl>
    </section>`;
}

function hideReferencePopover(force) {
  if (!force && state.popoverPinned) {
    return;
  }
  state.popoverPinned = false;
  elements.referencePopover.classList.add("hidden");
  if (state.route === "policy" && state.inspection) {
    renderPolicy();
  }
}

function renderCells() {
  renderInspectionStatus(elements.cellsNotice, elements.cellsFreshness);
  if (!state.inspection || !state.topology) {
    elements.cellList.replaceChildren();
    elements.cellDetail.replaceChildren();
    return;
  }
  const definitions = [...state.inspection.cells];
  const definedIds = new Set(definitions.map((cell) => cell.id));
  const orphanIds = [...new Set(
    state.inspection.task_mappings
      .filter((task) => !definedIds.has(task.cell_id))
      .map((task) => task.cell_id),
  )].sort((left, right) => left - right);
  for (const id of orphanIds) {
    definitions.push({ id, cpus: [], task_count: 0, undefined: true });
  }
  const cells = decorateCells(definitions, state.inspection.task_mappings)
    .sort((left, right) => left.id - right.id);
  if (cells.length === 0) {
    elements.cellList.innerHTML = '<p class="empty-state">The active policy defines no cells.</p>';
    elements.cellDetail.replaceChildren();
    return;
  }
  if (!cells.some((cell) => cell.id === state.selectedCellId)) {
    state.selectedCellId = cells[0].id;
  }
  elements.cellList.innerHTML = `
    <div class="cell-axis">${renderCpuAxis()}</div>
    ${cells.map(renderCellRow).join("")}`;
  const selected = cells.find((cell) => cell.id === state.selectedCellId);
  elements.cellDetail.innerHTML = renderCellDetail(selected);
}

function renderCellRow(cell) {
  const selected = cell.id === state.selectedCellId;
  const overlap = cell.overlapIds.length > 0
    ? `Overlaps ${cell.overlapIds.map((id) => `cell ${id}`).join(", ")}`
    : "No overlap";
  const definition = cell.undefined ? "Undefined by active policy" : `${cell.cpus.length} CPUs`;
  return `
    <button class="cell-row${selected ? " selected" : ""}" type="button"
      data-cell-id="${cell.id}" aria-pressed="${selected}">
      <span class="cell-identity"><strong>Cell ${cell.id}</strong><small>${definition}</small></span>
      ${renderCpuStrip(cell)}
      <span class="cell-count"><strong>${numberFormat.format(cell.tasks.length)}</strong><small>tasks</small></span>
      <span class="cell-overlap">${escapeHtml(overlap)}</span>
    </button>`;
}

function renderCpuStrip(cell) {
  const members = new Set(cell.cpus);
  const order = state.topology.topology_order;
  const cpuInfo = new Map(state.topology.cpus.map((cpu) => [cpu.cpu, cpu]));
  return `
    <span class="cell-cpu-strip" style="--cpu-count:${order.length}">
      ${order.map((cpu, index) => {
        const previous = index > 0 ? cpuInfo.get(order[index - 1]) : null;
        const current = cpuInfo.get(cpu);
        const boundary = previous && current && previous.llc !== current.llc ? " llc-boundary" : "";
        return `<i class="cpu-pixel${members.has(cpu) ? " member" : ""}${boundary}"
          title="CPU ${cpu} · LLC ${current?.llc ?? "?"}"></i>`;
      }).join("")}
    </span>`;
}

function renderCpuAxis() {
  const order = state.topology.topology_order;
  const cpuInfo = new Map(state.topology.cpus.map((cpu) => [cpu.cpu, cpu]));
  const labels = [];
  let start = 0;
  while (start < order.length) {
    const llc = cpuInfo.get(order[start])?.llc;
    let end = start + 1;
    while (end < order.length && cpuInfo.get(order[end])?.llc === llc) {
      end += 1;
    }
    labels.push(`<span style="grid-column:${start + 1} / ${end + 1}">LLC ${llc}</span>`);
    start = end;
  }
  return `<span class="cell-axis-labels" style="--cpu-count:${order.length}">${labels.join("")}</span>`;
}

function renderCellDetail(cell) {
  const cpuList = cell.cpus.length > 0 ? cell.cpus.join(", ") : "No active CPU definition";
  const overlap = cell.overlapIds.length > 0
    ? cell.overlapIds.map((id) => `Cell ${id}`).join(", ")
    : "None";
  const tasks = cell.tasks.length > 0
    ? cell.tasks.map(renderTaskMapping).join("")
    : '<p class="empty-state">No live task mappings for this cell.</p>';
  return `
    <header class="cell-detail-heading">
      <div><h3>Cell ${cell.id}</h3><p>${numberFormat.format(cell.tasks.length)} mapped tasks</p></div>
      ${cell.undefined ? '<span class="slot-state warning">Undefined</span>' : ""}
    </header>
    <dl class="cell-facts">
      <div><dt>CPUs</dt><dd>${escapeHtml(cpuList)}</dd></div>
      <div><dt>Overlapping cells</dt><dd>${escapeHtml(overlap)}</dd></div>
    </dl>
    <div class="task-mappings">${tasks}</div>`;
}

function renderTaskMapping(task) {
  const cpu = task.current_cpu === null || task.current_cpu === undefined
    ? "CPU unavailable"
    : `CPU ${task.current_cpu}`;
  return `
    <details class="task-mapping">
      <summary>
        <span><strong>${escapeHtml(task.name || "unnamed")}</strong><small>TID ${task.tid} · TGID ${task.tgid}</small></span>
        <span><strong>${escapeHtml(cpu)}</strong><small>${escapeHtml(task.state || "unknown")}</small></span>
      </summary>
      <dl>
        <div><dt>Allowed CPUs</dt><dd>${escapeHtml(task.allowed_cpus || "unavailable")}</dd></div>
        <div><dt>Cgroup</dt><dd>${escapeHtml(task.cgroup || "unavailable")}</dd></div>
        <div><dt>Placement</dt><dd>${task.needs_rehome ? "Rehome pending" : "Cell placement acknowledged"}</dd></div>
      </dl>
    </details>`;
}

function renderInspectionStatus(notice, freshness) {
  freshness.textContent = state.lastInspectionAt
    ? `Updated ${new Date(state.lastInspectionAt).toLocaleTimeString()}`
    : "Waiting for Snake";
  if (state.inspectionError) {
    notice.textContent = state.inspectionError;
    notice.classList.remove("hidden");
  } else if (!state.inspection) {
    notice.textContent = "Inspection data is unavailable until a compatible Snake scheduler is active.";
    notice.classList.remove("hidden");
  } else {
    notice.classList.add("hidden");
  }
}

function formatTimestamp(milliseconds) {
  if (!milliseconds) {
    return "Unavailable";
  }
  return new Date(milliseconds).toLocaleString();
}

function formatCount(value) {
  return numberFormat.format(Number(value || 0));
}

function formatPercentage(value) {
  return `${Number(value || 0).toFixed(1)}%`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
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

function showElementNotice(element, message, kind = "warning") {
  element.textContent = message;
  element.className = `notice ${kind}`;
}

function hideElementNotice(element) {
  element.classList.add("hidden");
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

function formatRuntime(nanoseconds) {
  if (nanoseconds >= 1_000_000_000) {
    return `${(nanoseconds / 1_000_000_000).toFixed(2)} s`;
  }
  if (nanoseconds >= 1_000_000) {
    return `${(nanoseconds / 1_000_000).toFixed(1)} ms`;
  }
  if (nanoseconds >= 1_000) {
    return `${(nanoseconds / 1_000).toFixed(1)} us`;
  }
  return `${numberFormat.format(nanoseconds)} ns`;
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
