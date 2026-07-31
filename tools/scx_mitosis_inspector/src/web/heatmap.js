// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

(function installMitosisHeatmap(root) {
  "use strict";

  const DEFAULT_IDS = {
    canvas: "migrationHeatmapCanvas",
    tooltip: "migrationHeatmapTooltip",
    viewport: "migrationHeatmapViewport",
  };
  const INFERNO_STOPS = [
    "#000004",
    "#420a68",
    "#932667",
    "#dd513a",
    "#fca50a",
    "#fcffa4",
  ];
  const number = new Intl.NumberFormat("en-US");
  let renderer = null;

  function resolveElement(value, fallbackId) {
    if (value && typeof value !== "string") {
      return value;
    }
    if (typeof document === "undefined") {
      return null;
    }
    return document.querySelector(value || `#${fallbackId}`);
  }

  function cpuId(value) {
    const parsed = Number(value);
    return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null;
  }

  function normalizeCpu(raw) {
    const cpu = cpuId(raw?.cpu ?? raw?.cpu_id ?? raw?.id);
    if (cpu == null) {
      return null;
    }
    return {
      cpu,
      node: raw.node ?? raw.numa_node ?? raw.node_id ?? null,
      package: raw.package ?? raw.package_id ?? raw.socket ?? raw.socket_id ?? null,
      llc: raw.llc ?? raw.llc_id ?? raw.cache_id ?? null,
      core: raw.core ?? raw.core_id ?? null,
    };
  }

  function normalizeMigrations(rows) {
    return (Array.isArray(rows) ? rows : []).flatMap((row) => {
      const from = cpuId(row?.from_cpu ?? row?.from);
      const to = cpuId(row?.to_cpu ?? row?.to);
      const count = Number(row?.count);
      return from == null || to == null || !Number.isFinite(count) || count <= 0
        ? []
        : [{ from, to, count }];
    });
  }

  function topologyFrom(snapshot, override) {
    const raw = override || snapshot?.topology || {};
    const rawCpus = [raw.cpus, raw.cpu_topology, snapshot?.cpus, snapshot?.cpu_topology]
      .find(Array.isArray) || [];
    const cpus = rawCpus.map(normalizeCpu).filter(Boolean);
    return {
      cpus,
      numericOrder: raw.numeric_order || raw.numericOrder || [],
      topologyOrder: raw.topology_order || raw.topologyOrder || [],
    };
  }

  function compareTopology(left, right) {
    for (const key of ["node", "package", "llc", "core", "cpu"]) {
      const a = left[key];
      const b = right[key];
      if (a == null && b != null) return 1;
      if (a != null && b == null) return -1;
      if (a !== b) return Number(a) - Number(b);
    }
    return 0;
  }

  function orderedCpus(topology, migrations, orderMode) {
    const known = new Set(topology.cpus.map((entry) => entry.cpu));
    for (const migration of migrations) {
      known.add(migration.from);
      known.add(migration.to);
    }
    const requested = orderMode === "numeric"
      ? topology.numericOrder
      : topology.topologyOrder;
    for (const value of Array.isArray(requested) ? requested : []) {
      const cpu = cpuId(value);
      if (cpu != null) known.add(cpu);
    }
    const order = [];
    const seen = new Set();
    for (const value of Array.isArray(requested) ? requested : []) {
      const cpu = cpuId(value);
      if (cpu != null && known.has(cpu) && !seen.has(cpu)) {
        seen.add(cpu);
        order.push(cpu);
      }
    }
    const byCpu = new Map(topology.cpus.map((entry) => [entry.cpu, entry]));
    const remaining = [...known].filter((cpu) => !seen.has(cpu));
    remaining.sort(orderMode === "numeric"
      ? (left, right) => left - right
      : (left, right) => compareTopology(
        byCpu.get(left) || { cpu: left },
        byCpu.get(right) || { cpu: right },
      ));
    return order.concat(remaining);
  }

  function buildMatrix(snapshot, options) {
    const migrations = normalizeMigrations(snapshot?.migrations);
    const topology = topologyFrom(snapshot, options?.topology);
    const order = orderedCpus(topology, migrations, options?.orderMode || "topology");
    const positions = new Map(order.map((cpu, index) => [cpu, index]));
    const values = new Float64Array(order.length * order.length);
    let total = 0;
    let max = 0;
    for (const migration of migrations) {
      const row = positions.get(migration.from);
      const column = positions.get(migration.to);
      if (row == null || column == null) continue;
      const offset = row * order.length + column;
      values[offset] += migration.count;
      total += migration.count;
      max = Math.max(max, values[offset]);
    }
    return { max, order, positions, topology, total, values };
  }

  function channel(color, offset) {
    return Number.parseInt(color.slice(offset, offset + 2), 16);
  }

  function infernoColor(position) {
    const scaled = Math.max(0, Math.min(1, position)) * (INFERNO_STOPS.length - 1);
    const left = INFERNO_STOPS[Math.floor(scaled)];
    const right = INFERNO_STOPS[Math.min(INFERNO_STOPS.length - 1, Math.ceil(scaled))];
    const fraction = scaled - Math.floor(scaled);
    const hex = [1, 3, 5].map((offset) => Math.round(
      channel(left, offset) + (channel(right, offset) - channel(left, offset)) * fraction,
    ).toString(16).padStart(2, "0"));
    return `#${hex.join("")}`;
  }

  function intensity(count, max) {
    return count > 0 && max > 0 ? Math.log1p(count) / Math.log1p(max) : 0;
  }

  function topologyBoundaries(matrix) {
    const byCpu = new Map(matrix.topology.cpus.map((entry) => [entry.cpu, entry]));
    const levels = ["node", "package", "llc", "core"];
    const boundaries = [];
    for (let index = 1; index < matrix.order.length; index += 1) {
      const previous = byCpu.get(matrix.order[index - 1]);
      const current = byCpu.get(matrix.order[index]);
      if (!previous || !current) continue;
      const level = levels.find((key) => previous[key] !== current[key]);
      if (level) boundaries.push({ index, level });
    }
    return boundaries;
  }

  function axisIndices(count, limit) {
    if (count <= limit) return Array.from({ length: count }, (_, index) => index);
    return [...new Set(Array.from(
      { length: limit },
      (_, index) => Math.round(index * (count - 1) / (limit - 1)),
    ))];
  }

  function layout(cpuCount, viewportWidth) {
    const left = 56;
    const top = 26;
    const right = 18;
    const bottom = 54;
    const fitted = (Math.max(320, viewportWidth) - left - right) / Math.max(1, cpuCount);
    const cellSize = Math.max(3, Math.min(12, fitted));
    const matrixSize = cpuCount * cellSize;
    return {
      bottom,
      cellSize,
      height: Math.ceil(top + matrixSize + bottom),
      left,
      matrixSize,
      top,
      width: Math.ceil(left + matrixSize + right),
    };
  }

  function drawAxes(context, matrix, geometry) {
    context.fillStyle = "#43515d";
    context.font = "10px ui-monospace, SFMono-Regular, Menlo, monospace";
    context.textBaseline = "middle";
    for (const index of axisIndices(matrix.order.length, 20)) {
      const center = (index + 0.5) * geometry.cellSize;
      context.textAlign = "right";
      context.fillText(String(matrix.order[index]), geometry.left - 7, geometry.top + center);
      context.save();
      context.translate(geometry.left + center, geometry.top + geometry.matrixSize + 7);
      context.rotate(-Math.PI / 2);
      context.fillText(String(matrix.order[index]), 0, 0);
      context.restore();
    }
    context.fillStyle = "#25313b";
    context.font = "600 11px ui-sans-serif, system-ui, sans-serif";
    context.textAlign = "center";
    context.fillText(
      "Destination CPU",
      geometry.left + geometry.matrixSize / 2,
      geometry.top + geometry.matrixSize + 42,
    );
    context.save();
    context.translate(13, geometry.top + geometry.matrixSize / 2);
    context.rotate(-Math.PI / 2);
    context.fillText("Source CPU", 0, 0);
    context.restore();
  }

  function drawBoundaries(context, matrix, geometry) {
    const colors = { node: "#ffffff", package: "#d7dee4", llc: "#98a8b5", core: "#536471" };
    const widths = { node: 3, package: 2.5, llc: 2, core: 1 };
    for (const boundary of topologyBoundaries(matrix)) {
      const offset = boundary.index * geometry.cellSize;
      context.beginPath();
      context.lineWidth = widths[boundary.level];
      context.strokeStyle = colors[boundary.level];
      context.moveTo(geometry.left + offset, geometry.top);
      context.lineTo(geometry.left + offset, geometry.top + geometry.matrixSize);
      context.moveTo(geometry.left, geometry.top + offset);
      context.lineTo(geometry.left + geometry.matrixSize, geometry.top + offset);
      context.stroke();
    }
  }

  function draw() {
    if (!renderer) return;
    const matrix = buildMatrix(renderer.snapshot, renderer);
    const viewportWidth = renderer.viewport?.clientWidth || renderer.canvas.clientWidth || 800;
    const geometry = layout(matrix.order.length, viewportWidth);
    const ratio = Math.min(2, root.devicePixelRatio || 1);
    const context = renderer.canvas.getContext("2d");
    if (!context) return;

    renderer.canvas.style.width = `${geometry.width}px`;
    renderer.canvas.style.height = `${geometry.height}px`;
    renderer.canvas.width = Math.ceil(geometry.width * ratio);
    renderer.canvas.height = Math.ceil(geometry.height * ratio);
    context.setTransform(ratio, 0, 0, ratio, 0, 0);
    context.fillStyle = "#ffffff";
    context.fillRect(0, 0, geometry.width, geometry.height);
    context.fillStyle = "#11161c";
    context.fillRect(geometry.left, geometry.top, geometry.matrixSize, geometry.matrixSize);

    const size = matrix.order.length;
    for (let row = 0; row < size; row += 1) {
      for (let column = 0; column < size; column += 1) {
        const count = matrix.values[row * size + column];
        if (count <= 0) continue;
        context.fillStyle = infernoColor(intensity(count, matrix.max));
        context.fillRect(
          geometry.left + column * geometry.cellSize,
          geometry.top + row * geometry.cellSize,
          Math.ceil(geometry.cellSize),
          Math.ceil(geometry.cellSize),
        );
      }
    }
    drawBoundaries(context, matrix, geometry);
    drawAxes(context, matrix, geometry);
    renderer.geometry = { ...geometry, matrix };
    renderer.canvas.setAttribute(
      "aria-label",
      `CPU migration heatmap with ${number.format(matrix.total)} transitions across ${size} CPUs`,
    );
  }

  function topologyLine(label, entry) {
    if (!entry) return `${label}: topology unavailable`;
    return `${label}: node ${entry.node ?? "?"}, package ${entry.package ?? "?"}, LLC ${entry.llc ?? "?"}, core ${entry.core ?? "?"}`;
  }

  function hideTooltip() {
    if (!renderer?.tooltip) return;
    renderer.tooltip.hidden = true;
    renderer.tooltip.classList?.add("hidden");
  }

  function showTooltip(event) {
    if (!renderer?.geometry || !renderer.tooltip) return;
    const bounds = renderer.canvas.getBoundingClientRect();
    const { geometry } = renderer;
    const column = Math.floor(
      (event.clientX - bounds.left - geometry.left) / geometry.cellSize,
    );
    const row = Math.floor(
      (event.clientY - bounds.top - geometry.top) / geometry.cellSize,
    );
    const size = geometry.matrix.order.length;
    if (row < 0 || column < 0 || row >= size || column >= size) {
      hideTooltip();
      return;
    }
    const from = geometry.matrix.order[row];
    const to = geometry.matrix.order[column];
    const count = geometry.matrix.values[row * size + column];
    const byCpu = new Map(geometry.matrix.topology.cpus.map((entry) => [entry.cpu, entry]));
    renderer.tooltip.textContent = [
      `CPU ${from} -> CPU ${to}`,
      `${number.format(count)} migrations`,
      topologyLine("Source", byCpu.get(from)),
      topologyLine("Destination", byCpu.get(to)),
    ].join("\n");
    const viewportBounds = renderer.viewport?.getBoundingClientRect() || bounds;
    renderer.tooltip.style.left = `${Math.max(8, event.clientX - viewportBounds.left + (renderer.viewport?.scrollLeft || 0) + 14)}px`;
    renderer.tooltip.style.top = `${Math.max(8, event.clientY - viewportBounds.top + (renderer.viewport?.scrollTop || 0) + 14)}px`;
    renderer.tooltip.hidden = false;
    renderer.tooltip.classList?.remove("hidden");
  }

  function scheduleDraw() {
    if (!renderer || renderer.frame != null) return;
    const schedule = root.requestAnimationFrame || ((callback) => root.setTimeout(callback, 0));
    renderer.frame = schedule(() => {
      if (renderer) renderer.frame = null;
      draw();
    });
  }

  function destroy() {
    if (!renderer) return;
    renderer.canvas.removeEventListener("mousemove", showTooltip);
    renderer.canvas.removeEventListener("mouseleave", hideTooltip);
    renderer.resizeObserver?.disconnect();
    renderer = null;
  }

  function init(options) {
    destroy();
    const config = options || {};
    const canvas = resolveElement(config.canvas, DEFAULT_IDS.canvas);
    if (!canvas) {
      throw new Error(`Mitosis heatmap canvas #${DEFAULT_IDS.canvas} was not found`);
    }
    const viewport = resolveElement(config.viewport, DEFAULT_IDS.viewport) || canvas.parentElement;
    renderer = {
      canvas,
      frame: null,
      geometry: null,
      orderMode: config.orderMode === "numeric" ? "numeric" : "topology",
      snapshot: {},
      topology: config.topology,
      tooltip: resolveElement(config.tooltip, DEFAULT_IDS.tooltip),
      viewport,
    };
    canvas.addEventListener("mousemove", showTooltip);
    canvas.addEventListener("mouseleave", hideTooltip);
    if (typeof root.ResizeObserver === "function" && viewport) {
      renderer.resizeObserver = new root.ResizeObserver(scheduleDraw);
      renderer.resizeObserver.observe(viewport);
    }
    draw();
    return root.MitosisHeatmap;
  }

  function update(snapshot, options) {
    if (!renderer) init(options);
    renderer.snapshot = snapshot || {};
    if (options?.topology !== undefined) renderer.topology = options.topology;
    if (options?.orderMode) {
      renderer.orderMode = options.orderMode === "numeric" ? "numeric" : "topology";
    }
    draw();
  }

  function setOrderMode(orderMode) {
    if (!renderer) return;
    renderer.orderMode = orderMode === "numeric" ? "numeric" : "topology";
    draw();
  }

  root.MitosisHeatmap = {
    buildMatrix,
    destroy,
    init,
    setOrderMode,
    update,
  };
})(typeof window === "undefined" ? globalThis : window);
