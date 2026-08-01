// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

(function installMitosisHeatmap(root) {
  "use strict";

  const DEFAULT_IDS = {
    canvas: "migrationHeatmapCanvas",
    legendHigh: "migrationLegendHigh",
    legendLow: "migrationLegendLow",
    pairInspection: "migrationPairInspection",
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
    if (value && typeof value !== "string") return value;
    if (typeof document === "undefined") return null;
    return document.querySelector(value || `#${fallbackId}`);
  }

  function cpuId(value) {
    const parsed = Number(value);
    return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : null;
  }

  function normalizeCpu(raw) {
    const cpu = cpuId(raw?.cpu ?? raw?.cpu_id ?? raw?.id);
    return cpu == null ? null : {
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
    const cpus = (Array.isArray(raw.cpus) ? raw.cpus : [])
      .map(normalizeCpu)
      .filter(Boolean);
    return {
      cpus,
      numeric_order: Array.isArray(raw.numeric_order) ? raw.numeric_order : [],
      topology_order: Array.isArray(raw.topology_order) ? raw.topology_order : [],
    };
  }

  function orderedCpus(topology, migrations, orderMode) {
    const known = new Set(topology.cpus.map((cpu) => cpu.cpu));
    migrations.forEach((migration) => {
      known.add(migration.from);
      known.add(migration.to);
    });
    const requested = orderMode === "numeric"
      ? topology.numeric_order
      : topology.topology_order;
    const order = requested.map(cpuId).filter((cpu) => cpu != null && known.has(cpu));
    const seen = new Set(order);
    const cpuInfo = new Map(topology.cpus.map((cpu) => [cpu.cpu, cpu]));
    const remaining = [...known].filter((cpu) => !seen.has(cpu));
    remaining.sort(orderMode === "numeric"
      ? (left, right) => left - right
      : (left, right) => {
        const a = cpuInfo.get(left) || { cpu: left };
        const b = cpuInfo.get(right) || { cpu: right };
        for (const key of ["node", "package", "llc", "core", "cpu"]) {
          if (a[key] == null && b[key] != null) return 1;
          if (a[key] != null && b[key] == null) return -1;
          if (a[key] !== b[key]) return Number(a[key]) - Number(b[key]);
        }
        return 0;
      });
    return order.concat(remaining);
  }

  function buildMatrix(snapshot, options) {
    const migrations = normalizeMigrations(snapshot?.migrations);
    const topology = topologyFrom(snapshot, options?.topology);
    const order = orderedCpus(topology, migrations, options?.orderMode || "topology");
    const positions = new Map(order.map((cpu, index) => [cpu, index]));
    const values = new Float64Array(order.length * order.length);
    let total = 0;
    for (const migration of migrations) {
      const from = positions.get(migration.from);
      const to = positions.get(migration.to);
      if (from == null || to == null) continue;
      values[from * order.length + to] += migration.count;
      total += migration.count;
    }
    let max = 0;
    let minPositive = Number.POSITIVE_INFINITY;
    for (const value of values) {
      max = Math.max(max, value);
      if (value > 0) minPositive = Math.min(minPositive, value);
    }
    return {
      max,
      minPositive: Number.isFinite(minPositive) ? minPositive : 0,
      order,
      positions,
      topology,
      total,
      values,
    };
  }

  function buildCpuUsage(topology, entries, order) {
    const positions = new Map(order.map((cpu, index) => [cpu, index]));
    const runtimeNs = new Float64Array(order.length);
    const utilizationPct = new Float64Array(order.length);
    for (const entry of Array.isArray(entries) ? entries : []) {
      const index = positions.get(cpuId(entry?.cpu));
      if (index == null) continue;
      runtimeNs[index] = Math.max(0, Number(entry.runtime_ns) || 0);
      utilizationPct[index] = Math.max(0, Number(entry.utilization_pct) || 0);
    }
    return { order, positions, runtimeNs, topology, utilizationPct };
  }

  function buildInterruptUsage(topology, entries, order) {
    const positions = new Map(order.map((cpu, index) => [cpu, index]));
    const hardirqPct = new Float64Array(order.length);
    const softirqPct = new Float64Array(order.length);
    const totalPct = new Float64Array(order.length);
    for (const entry of Array.isArray(entries) ? entries : []) {
      const index = positions.get(cpuId(entry?.cpu));
      if (index == null) continue;
      hardirqPct[index] = Math.max(0, Number(entry.hardirq_utilization_pct) || 0);
      softirqPct[index] = Math.max(0, Number(entry.softirq_utilization_pct) || 0);
      totalPct[index] = Math.max(0, Number(entry.total_utilization_pct) || 0);
    }
    return { hardirqPct, order, positions, softirqPct, topology, totalPct };
  }

  function buildGroupedUsage(usage, identityForCpu) {
    const cpuInfo = new Map(usage.topology.cpus.map((cpu) => [cpu.cpu, cpu]));
    const groups = [];
    const groupIndexes = new Map();
    const cpuGroups = new Int32Array(usage.order.length).fill(-1);
    for (let index = 0; index < usage.order.length; index += 1) {
      const cpu = cpuInfo.get(usage.order[index]);
      const identity = cpu && identityForCpu(cpu);
      if (!identity) continue;
      let groupIndex = groupIndexes.get(identity.key);
      if (groupIndex == null) {
        groupIndex = groups.length;
        groupIndexes.set(identity.key, groupIndex);
        groups.push({ ...identity, cpuCount: 0, cpus: [], runtimeNs: 0, utilizationPct: 0 });
      }
      const group = groups[groupIndex];
      group.cpuCount += 1;
      group.cpus.push(cpu.cpu);
      group.runtimeNs += usage.runtimeNs[index];
      group.utilizationPct += usage.utilizationPct[index];
      cpuGroups[index] = groupIndex;
    }
    groups.forEach((group) => {
      group.utilizationPct = group.cpuCount > 0
        ? group.utilizationPct / group.cpuCount
        : 0;
    });
    const spans = [];
    let start = 0;
    for (let index = 1; index <= cpuGroups.length; index += 1) {
      if (index === cpuGroups.length || cpuGroups[index] !== cpuGroups[start]) {
        if (cpuGroups[start] >= 0) {
          spans.push({ start, end: index, groupIndex: cpuGroups[start] });
        }
        start = index;
      }
    }
    return { groups, spans };
  }

  function buildCoreUsage(usage) {
    return buildGroupedUsage(usage, (cpu) => cpu.core == null ? null : {
      key: `${cpu.node}:${cpu.package}:${cpu.core}`,
      node: cpu.node,
      package: cpu.package,
      core: cpu.core,
    });
  }

  function buildLlcUsage(usage) {
    return buildGroupedUsage(usage, (cpu) => cpu.llc == null ? null : {
      key: `${cpu.node}:${cpu.package}:${cpu.llc}`,
      node: cpu.node,
      package: cpu.package,
      llc: cpu.llc,
    });
  }

  function migrationLocality(topology, from, to) {
    const cpus = new Map(topology.cpus.map((cpu) => [cpu.cpu, cpu]));
    const source = cpus.get(from);
    const destination = cpus.get(to);
    if (!source || !destination) return "Topology unknown";
    if (from === to) return "Same CPU";
    if (source.core === destination.core
        && source.package === destination.package
        && source.node === destination.node) return "Same core";
    if (source.llc === destination.llc
        && source.package === destination.package
        && source.node === destination.node) return "Same LLC";
    if (source.package === destination.package && source.node === destination.node) {
      return "Same package";
    }
    if (source.node === destination.node) return "Same NUMA node";
    return "Cross-NUMA";
  }

  function topologyBoundaries(topology, order) {
    const cpus = new Map(topology.cpus.map((cpu) => [cpu.cpu, cpu]));
    const levels = ["node", "package", "llc", "core"];
    const boundaries = [];
    for (let index = 1; index < order.length; index += 1) {
      const previous = cpus.get(order[index - 1]);
      const current = cpus.get(order[index]);
      if (!previous || !current) continue;
      const level = levels.find((candidate) => previous[candidate] !== current[candidate]);
      if (level) boundaries.push({ index, level });
    }
    return boundaries;
  }

  function topologyGroups(topology, order, level) {
    if (order.length === 0) return [];
    const cpus = new Map(topology.cpus.map((cpu) => [cpu.cpu, cpu]));
    const groups = [];
    let start = 0;
    let value = cpus.get(order[0])?.[level];
    for (let index = 1; index <= order.length; index += 1) {
      const next = index < order.length ? cpus.get(order[index])?.[level] : undefined;
      if (index === order.length || next !== value) {
        groups.push({ start, end: index, value });
        start = index;
        value = next;
      }
    }
    return groups;
  }

  function axisLabelIndices(count, maxLabels = 24) {
    if (count <= 0) return [];
    if (count <= maxLabels) return Array.from({ length: count }, (_, index) => index);
    return [...new Set(Array.from(
      { length: maxLabels },
      (_, index) => Math.round(index * (count - 1) / (maxLabels - 1)),
    ))];
  }

  function heatmapLayout(cpuCount, viewportWidth, zoom) {
    const count = Math.max(1, cpuCount);
    const fitCell = (Math.max(320, viewportWidth) - 104) / count;
    const cellSize = Math.max(2, Math.min(9, fitCell)) * zoom;
    const usageHeight = Math.max(13, Math.min(26, cellSize * 2.5));
    const irqHeight = Math.max(13, Math.min(26, cellSize * 2.5));
    const irqTop = 20;
    const usageTop = irqTop + irqHeight + 4;
    const coreHeight = Math.max(16, Math.min(24, cellSize * 2.5));
    const coreTop = usageTop + usageHeight + 4;
    const llcHeight = Math.max(16, Math.min(24, cellSize * 2.5));
    const llcTop = coreTop + coreHeight + 4;
    const margins = { left: 64, top: llcTop + llcHeight + 10, right: 18 };
    const matrixSize = count * cellSize;
    return {
      cellSize,
      coreHeight,
      coreTop,
      height: Math.ceil(margins.top + matrixSize + 46),
      irqHeight,
      irqTop,
      llcHeight,
      llcTop,
      margins,
      matrixSize,
      usageHeight,
      usageTop,
      width: Math.ceil(margins.left + matrixSize + margins.right),
    };
  }

  function normalizeCount(value, max, scale) {
    if (value <= 0 || max <= 0) return 0;
    return scale === "linear"
      ? Math.min(1, value / max)
      : Math.min(1, Math.log1p(value) / Math.log1p(max));
  }

  function infernoColor(position) {
    const scaled = Math.max(0, Math.min(1, position)) * (INFERNO_STOPS.length - 1);
    const leftIndex = Math.floor(scaled);
    const rightIndex = Math.min(INFERNO_STOPS.length - 1, leftIndex + 1);
    const fraction = scaled - leftIndex;
    const channel = (offset) => Math.round(
      Number.parseInt(INFERNO_STOPS[leftIndex].slice(offset, offset + 2), 16)
      + (Number.parseInt(INFERNO_STOPS[rightIndex].slice(offset, offset + 2), 16)
      - Number.parseInt(INFERNO_STOPS[leftIndex].slice(offset, offset + 2), 16)) * fraction,
    ).toString(16).padStart(2, "0");
    return `#${channel(1)}${channel(3)}${channel(5)}`;
  }

  function drawAxes(context, matrix, geometry) {
    const { cellSize, margins, matrixSize } = geometry;
    context.fillStyle = "#43515d";
    context.font = "10px ui-monospace, SFMono-Regular, Menlo, monospace";
    context.textBaseline = "middle";
    for (const index of axisLabelIndices(matrix.order.length)) {
      const center = (index + 0.5) * cellSize;
      context.textAlign = "right";
      context.fillText(String(matrix.order[index]), margins.left - 7, margins.top + center);
      context.save();
      context.translate(margins.left + center, margins.top + matrixSize + 7);
      context.rotate(-Math.PI / 2);
      context.fillText(String(matrix.order[index]), 0, 0);
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

  function drawBoundaries(context, matrix, geometry) {
    const widths = { node: 3, package: 2.5, llc: 2, core: 1 };
    const colors = { node: "#ffffff", package: "#d7dee4", llc: "#98a8b5", core: "#536471" };
    for (const boundary of topologyBoundaries(matrix.topology, matrix.order)) {
      const offset = boundary.index * geometry.cellSize;
      context.beginPath();
      context.lineWidth = widths[boundary.level];
      context.strokeStyle = colors[boundary.level];
      context.moveTo(geometry.margins.left + offset, geometry.margins.top);
      context.lineTo(geometry.margins.left + offset, geometry.margins.top + geometry.matrixSize);
      context.moveTo(geometry.margins.left, geometry.margins.top + offset);
      context.lineTo(geometry.margins.left + geometry.matrixSize, geometry.margins.top + offset);
      context.stroke();
    }
  }

  function drawCpuUsage(context, usage, geometry, scale) {
    const { cellSize, margins, matrixSize, usageHeight, usageTop } = geometry;
    context.fillStyle = "#11161c";
    context.fillRect(margins.left, usageTop, matrixSize, usageHeight);
    usage.order.forEach((cpu, index) => {
      const utilization = usage.utilizationPct[index];
      if (utilization <= 0) return;
      context.fillStyle = infernoColor(normalizeCount(utilization, 100, scale));
      context.fillRect(margins.left + index * cellSize, usageTop, Math.ceil(cellSize), usageHeight);
    });
    drawBandLabel(context, "Task util", margins.left - 7, usageTop + usageHeight / 2);
    for (const boundary of topologyBoundaries(usage.topology, usage.order)) {
      const x = margins.left + boundary.index * cellSize;
      context.beginPath();
      context.lineWidth = boundary.level === "llc" ? 2 : 1;
      context.strokeStyle = boundary.level === "llc" ? "#ffffff" : "#6f7f8b";
      context.moveTo(x, usageTop);
      context.lineTo(x, usageTop + usageHeight);
      context.stroke();
    }
  }

  function drawInterruptUsage(context, usage, geometry, scale) {
    const { cellSize, irqHeight, irqTop, margins, matrixSize } = geometry;
    const maximum = Math.max(1, ...usage.totalPct);
    context.fillStyle = "#11161c";
    context.fillRect(margins.left, irqTop, matrixSize, irqHeight);
    usage.order.forEach((cpu, index) => {
      const utilization = usage.totalPct[index];
      if (utilization <= 0) return;
      context.fillStyle = infernoColor(normalizeCount(utilization, maximum, scale));
      context.fillRect(margins.left + index * cellSize, irqTop, Math.ceil(cellSize), irqHeight);
    });
    drawBandLabel(context, "IRQ util", margins.left - 7, irqTop + irqHeight / 2);
    for (const boundary of topologyBoundaries(usage.topology, usage.order)) {
      const x = margins.left + boundary.index * cellSize;
      context.beginPath();
      context.lineWidth = boundary.level === "llc" ? 2 : 1;
      context.strokeStyle = boundary.level === "llc" ? "#ffffff" : "#6f7f8b";
      context.moveTo(x, irqTop);
      context.lineTo(x, irqTop + irqHeight);
      context.stroke();
    }
  }

  function drawBandLabel(context, label, x, y) {
    context.fillStyle = "#25313b";
    context.font = "600 10px ui-sans-serif, system-ui, sans-serif";
    context.textAlign = "right";
    context.textBaseline = "middle";
    context.fillText(label, x, y);
  }

  function drawGroupedUsage(context, grouped, geometry, kind, scale) {
    const isCore = kind === "core";
    const top = isCore ? geometry.coreTop : geometry.llcTop;
    const height = isCore ? geometry.coreHeight : geometry.llcHeight;
    for (const span of grouped.spans) {
      const group = grouped.groups[span.groupIndex];
      const left = geometry.margins.left + span.start * geometry.cellSize;
      const width = (span.end - span.start) * geometry.cellSize;
      const intensity = normalizeCount(group.utilizationPct, 100, scale);
      context.fillStyle = infernoColor(intensity);
      context.fillRect(left, top, Math.ceil(width), height);
      context.strokeStyle = "#ffffff";
      context.lineWidth = isCore ? 1 : 2;
      context.strokeRect(left, top, Math.ceil(width), height);
      context.font = "600 9px ui-sans-serif, system-ui, sans-serif";
      context.textAlign = "center";
      context.textBaseline = "middle";
      context.fillStyle = intensity > 0.72 ? "#11161c" : "#ffffff";
      const name = isCore ? `Core ${group.core}` : `LLC ${group.llc}`;
      const labels = [`${name} - ${group.utilizationPct.toFixed(1)}%`, `${group[isCore ? "core" : "llc"]} - ${group.utilizationPct.toFixed(0)}%`];
      const label = labels.find((candidate) => context.measureText(candidate).width <= width - 6);
      if (label) context.fillText(label, left + width / 2, top + height / 2);
    }
    drawBandLabel(context, isCore ? "Core util" : "LLC util", geometry.margins.left - 7, top + height / 2);
  }

  function drawLlcAnnotations(context, matrix, geometry) {
    const groups = topologyGroups(matrix.topology, matrix.order, "llc")
      .filter((group) => group.value != null);
    context.fillStyle = "#43515d";
    context.strokeStyle = "#98a8b5";
    context.lineWidth = 1;
    context.font = "600 9px ui-sans-serif, system-ui, sans-serif";
    context.textAlign = "center";
    context.textBaseline = "middle";
    for (const group of groups) {
      const start = group.start * geometry.cellSize;
      const span = (group.end - group.start) * geometry.cellSize;
      const center = start + span / 2;
      context.fillText(`LLC ${group.value}`, geometry.margins.left + center, 7, Math.max(1, span - 4));
      context.beginPath();
      context.moveTo(geometry.margins.left + start, 16);
      context.lineTo(geometry.margins.left + start + span, 16);
      context.stroke();
      context.save();
      context.translate(27, geometry.margins.top + center);
      context.rotate(-Math.PI / 2);
      context.fillText(`LLC ${group.value}`, 0, 0, Math.max(1, span - 4));
      context.restore();
      context.beginPath();
      context.moveTo(38, geometry.margins.top + start);
      context.lineTo(38, geometry.margins.top + start + span);
      context.stroke();
    }
  }

  function drawPinnedPair(context, matrix, geometry) {
    if (!renderer.pinnedPair) return;
    const row = matrix.positions.get(renderer.pinnedPair.from);
    const column = matrix.positions.get(renderer.pinnedPair.to);
    if (row == null || column == null) return;
    context.strokeStyle = "#00d6a3";
    context.lineWidth = Math.max(2, Math.min(4, geometry.cellSize / 2));
    context.strokeRect(
      geometry.margins.left + column * geometry.cellSize + 1,
      geometry.margins.top + row * geometry.cellSize + 1,
      Math.max(1, geometry.cellSize - 2),
      Math.max(1, geometry.cellSize - 2),
    );
  }

  function topMigrationPair(matrix) {
    if (matrix.max <= 0) return null;
    let offset = 0;
    for (let index = 1; index < matrix.values.length; index += 1) {
      if (matrix.values[index] > matrix.values[offset]) offset = index;
    }
    return {
      from: matrix.order[Math.floor(offset / matrix.order.length)],
      to: matrix.order[offset % matrix.order.length],
      count: matrix.values[offset],
    };
  }

  function pairDetail(title, pair, matrix) {
    const wrapper = document.createElement("div");
    const label = document.createElement("span");
    const route = document.createElement("strong");
    const detail = document.createElement("small");
    label.textContent = title;
    if (!pair) {
      wrapper.className = "migration-pair-empty";
      route.textContent = title === "Selected route"
        ? "Click a matrix cell to keep its details here"
        : "No migrations in this window";
      wrapper.append(label, route);
      return wrapper;
    }
    const share = matrix.total > 0 ? pair.count * 100 / matrix.total : 0;
    route.textContent = `CPU ${pair.from} -> CPU ${pair.to}`;
    detail.textContent = `${number.format(pair.count)} migrations - ${share.toFixed(1)}% - ${migrationLocality(matrix.topology, pair.from, pair.to)}`;
    wrapper.append(label, route, detail);
    return wrapper;
  }

  function renderPairInspection(matrix) {
    if (!renderer.pairInspection) return;
    const pinned = renderer.pinnedPair;
    const row = pinned && matrix.positions.get(pinned.from);
    const column = pinned && matrix.positions.get(pinned.to);
    const selected = pinned ? {
      ...pinned,
      count: row == null || column == null
        ? 0
        : matrix.values[row * matrix.order.length + column],
    } : null;
    const clear = document.createElement("button");
    clear.type = "button";
    clear.className = "heatmap-clear-selection";
    clear.textContent = "Clear selection";
    clear.disabled = !pinned;
    clear.addEventListener("click", () => {
      renderer.pinnedPair = null;
      draw();
    });
    renderer.pairInspection.replaceChildren(
      pairDetail("Busiest route", topMigrationPair(matrix), matrix),
      pairDetail("Selected route", selected, matrix),
      clear,
    );
  }

  function draw() {
    if (!renderer) return;
    const matrix = buildMatrix(renderer.snapshot, renderer);
    const interruptUsage = buildInterruptUsage(
      matrix.topology,
      renderer.snapshot?.interrupt_cpu,
      matrix.order,
    );
    const irqByCpu = new Map(interruptUsage.order.map((cpu, index) => [
      cpu,
      interruptUsage.totalPct[index],
    ]));
    const taskRuntime = (renderer.snapshot?.cpu_runtime || []).map((entry) => ({
      ...entry,
      utilization_pct: Math.max(
        0,
        Number(entry.utilization_pct || 0) - Number(irqByCpu.get(entry.cpu) || 0),
      ),
    }));
    const usage = buildCpuUsage(matrix.topology, taskRuntime, matrix.order);
    const coreUsage = buildCoreUsage(usage);
    const llcUsage = buildLlcUsage(usage);
    const viewportWidth = Math.max(320, renderer.viewport?.clientWidth || 800);
    const geometry = heatmapLayout(matrix.order.length, viewportWidth, renderer.zoom);
    const pixelRatio = Math.min(2, root.devicePixelRatio || 1);
    const context = renderer.canvas.getContext("2d");
    if (!context) return;

    renderer.canvas.style.width = `${geometry.width}px`;
    renderer.canvas.style.height = `${geometry.height}px`;
    renderer.canvas.width = Math.ceil(geometry.width * pixelRatio);
    renderer.canvas.height = Math.ceil(geometry.height * pixelRatio);
    context.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
    context.fillStyle = "#ffffff";
    context.fillRect(0, 0, geometry.width, geometry.height);
    context.fillStyle = "#11161c";
    context.fillRect(geometry.margins.left, geometry.margins.top, geometry.matrixSize, geometry.matrixSize);

    const size = matrix.order.length;
    for (let row = 0; row < size; row += 1) {
      for (let column = 0; column < size; column += 1) {
        const count = matrix.values[row * size + column];
        if (count <= 0) continue;
        context.fillStyle = infernoColor(normalizeCount(count, matrix.max, renderer.scale));
        context.fillRect(
          geometry.margins.left + column * geometry.cellSize,
          geometry.margins.top + row * geometry.cellSize,
          Math.ceil(geometry.cellSize),
          Math.ceil(geometry.cellSize),
        );
      }
    }
    drawBoundaries(context, matrix, geometry);
    drawPinnedPair(context, matrix, geometry);
    drawAxes(context, matrix, geometry);
    drawInterruptUsage(context, interruptUsage, geometry, renderer.scale);
    drawCpuUsage(context, usage, geometry, renderer.scale);
    drawGroupedUsage(context, coreUsage, geometry, "core", renderer.scale);
    drawGroupedUsage(context, llcUsage, geometry, "llc", renderer.scale);
    drawLlcAnnotations(context, matrix, geometry);
    renderer.geometry = { ...geometry, coreUsage, interruptUsage, llcUsage, matrix, usage };
    renderer.legendLow.textContent = number.format(matrix.minPositive);
    renderer.legendHigh.textContent = number.format(matrix.max);
    renderPairInspection(matrix);
    renderer.canvas.setAttribute(
      "aria-label",
      `CPU migration heatmap with ${number.format(matrix.total)} transitions, IRQ utilization, task utilization, whole-core utilization, and LLC utilization across ${size} CPUs`,
    );
  }

  function topologyLine(label, entry) {
    if (!entry) return `${label}: topology unavailable`;
    return `${label}: node ${entry.node ?? "?"}, package ${entry.package ?? "?"}, LLC ${entry.llc ?? "?"}, core ${entry.core ?? "?"}`;
  }

  function formatRuntime(runtimeNs) {
    if (runtimeNs >= 1e9) return `${(runtimeNs / 1e9).toFixed(2)} s`;
    if (runtimeNs >= 1e6) return `${(runtimeNs / 1e6).toFixed(2)} ms`;
    if (runtimeNs >= 1e3) return `${(runtimeNs / 1e3).toFixed(2)} us`;
    return `${number.format(runtimeNs)} ns`;
  }

  function compactCpuList(cpus) {
    if (cpus.length <= 8) return cpus.join(", ");
    return `${cpus.slice(0, 8).join(", ")} +${cpus.length - 8}`;
  }

  function hideTooltip() {
    if (!renderer?.tooltip) return;
    renderer.tooltip.hidden = true;
    renderer.tooltip.classList.add("hidden");
  }

  function positionTooltip(event) {
    const viewportBounds = renderer.viewport.getBoundingClientRect();
    const maxLeft = Math.max(8, renderer.viewport.scrollWidth - renderer.tooltip.offsetWidth - 8);
    const maxTop = Math.max(8, renderer.viewport.scrollHeight - renderer.tooltip.offsetHeight - 8);
    renderer.tooltip.style.left = `${Math.min(maxLeft, Math.max(8, event.clientX - viewportBounds.left + renderer.viewport.scrollLeft + 14))}px`;
    renderer.tooltip.style.top = `${Math.min(maxTop, Math.max(8, event.clientY - viewportBounds.top + renderer.viewport.scrollTop + 14))}px`;
    renderer.tooltip.hidden = false;
    renderer.tooltip.classList.remove("hidden");
  }

  function showTooltip(event) {
    const geometry = renderer?.geometry;
    if (!geometry || !renderer.tooltip) return;
    const bounds = renderer.canvas.getBoundingClientRect();
    const canvasX = event.clientX - bounds.left;
    const canvasY = event.clientY - bounds.top;
    const column = Math.floor((canvasX - geometry.margins.left) / geometry.cellSize);
    const row = Math.floor((canvasY - geometry.margins.top) / geometry.cellSize);
    const size = geometry.matrix.order.length;
    if (column >= 0 && column < size
        && canvasY >= geometry.irqTop
        && canvasY < geometry.irqTop + geometry.irqHeight) {
      const cpu = geometry.interruptUsage.order[column];
      renderer.tooltip.textContent = [
        `CPU ${cpu} IRQ utilization`,
        `Combined: ${geometry.interruptUsage.totalPct[column].toFixed(2)}%`,
        `Hard IRQ: ${geometry.interruptUsage.hardirqPct[column].toFixed(2)}%`,
        `Softirq: ${geometry.interruptUsage.softirqPct[column].toFixed(2)}%`,
      ].join("\n");
      positionTooltip(event);
      return;
    }
    if (column >= 0 && column < size
        && canvasY >= geometry.usageTop
        && canvasY < geometry.usageTop + geometry.usageHeight) {
      const cpu = geometry.usage.order[column];
      const cpuInfo = new Map(geometry.matrix.topology.cpus.map((entry) => [entry.cpu, entry]));
      renderer.tooltip.textContent = [
        `CPU ${cpu}`,
        `CPU utilization: ${geometry.usage.utilizationPct[column].toFixed(1)}%`,
        `${formatRuntime(geometry.usage.runtimeNs[column])} cumulative runtime`,
        topologyLine("Topology", cpuInfo.get(cpu)),
      ].join("\n");
      positionTooltip(event);
      return;
    }
    for (const [top, height, grouped, kind] of [
      [geometry.coreTop, geometry.coreHeight, geometry.coreUsage, "Core"],
      [geometry.llcTop, geometry.llcHeight, geometry.llcUsage, "LLC"],
    ]) {
      if (column < 0 || column >= size || canvasY < top || canvasY >= top + height) continue;
      const span = grouped.spans.find((candidate) => column >= candidate.start && column < candidate.end);
      const group = span && grouped.groups[span.groupIndex];
      if (!group) continue;
      renderer.tooltip.textContent = [
        `${kind} ${kind === "Core" ? group.core : group.llc}`,
        `CPUs ${compactCpuList(group.cpus)}`,
        `Utilization: ${group.utilizationPct.toFixed(1)}% of ${kind.toLowerCase()} capacity`,
        `${formatRuntime(group.runtimeNs)} cumulative runtime`,
        `Node ${group.node}, package ${group.package}`,
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
    const cpuInfo = new Map(geometry.matrix.topology.cpus.map((entry) => [entry.cpu, entry]));
    renderer.tooltip.textContent = [
      `CPU ${from} -> CPU ${to}`,
      `${number.format(count)} migrations`,
      migrationLocality(geometry.matrix.topology, from, to),
      topologyLine("Source", cpuInfo.get(from)),
      topologyLine("Destination", cpuInfo.get(to)),
    ].join("\n");
    positionTooltip(event);
  }

  function pinMigrationPair(event) {
    const geometry = renderer?.geometry;
    if (!geometry) return;
    const bounds = renderer.canvas.getBoundingClientRect();
    const column = Math.floor((event.clientX - bounds.left - geometry.margins.left) / geometry.cellSize);
    const row = Math.floor((event.clientY - bounds.top - geometry.margins.top) / geometry.cellSize);
    const size = geometry.matrix.order.length;
    if (row < 0 || column < 0 || row >= size || column >= size) return;
    renderer.pinnedPair = {
      from: geometry.matrix.order[row],
      to: geometry.matrix.order[column],
    };
    draw();
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
    renderer.canvas.removeEventListener("pointermove", showTooltip);
    renderer.canvas.removeEventListener("pointerleave", hideTooltip);
    renderer.canvas.removeEventListener("click", pinMigrationPair);
    renderer.resizeObserver?.disconnect();
    renderer = null;
  }

  function init(options) {
    destroy();
    const config = options || {};
    const canvas = resolveElement(config.canvas, DEFAULT_IDS.canvas);
    if (!canvas) throw new Error(`Mitosis heatmap canvas #${DEFAULT_IDS.canvas} was not found`);
    const viewport = resolveElement(config.viewport, DEFAULT_IDS.viewport) || canvas.parentElement;
    renderer = {
      canvas,
      frame: null,
      geometry: null,
      legendHigh: resolveElement(config.legendHigh, DEFAULT_IDS.legendHigh),
      legendLow: resolveElement(config.legendLow, DEFAULT_IDS.legendLow),
      orderMode: "topology",
      pairInspection: resolveElement(config.pairInspection, DEFAULT_IDS.pairInspection),
      pinnedPair: null,
      scale: "log",
      snapshot: {},
      topology: config.topology,
      tooltip: resolveElement(config.tooltip, DEFAULT_IDS.tooltip),
      viewport,
      zoom: 1,
    };
    canvas.addEventListener("pointermove", showTooltip);
    canvas.addEventListener("pointerleave", hideTooltip);
    canvas.addEventListener("click", pinMigrationPair);
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
    draw();
  }

  function setOrderMode(orderMode) {
    if (!renderer) return;
    renderer.orderMode = orderMode === "numeric" ? "numeric" : "topology";
    draw();
  }

  function setScale(scale) {
    if (!renderer) return;
    renderer.scale = scale === "linear" ? "linear" : "log";
    draw();
  }

  function setZoom(zoom) {
    if (!renderer) return;
    renderer.zoom = Math.max(0.25, Math.min(3, Number(zoom) || 1));
    draw();
  }

  root.MitosisHeatmap = {
    buildMatrix,
    destroy,
    init,
    setOrderMode,
    setScale,
    setZoom,
    update,
  };
})(typeof window === "undefined" ? globalThis : window);
