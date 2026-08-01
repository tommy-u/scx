// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

export function buildMatrix(topology, cells, orderMode) {
  const sourceOrder = orderMode === "numeric"
    ? topology.numeric_order
    : topology.topology_order;
  const order = [...sourceOrder];
  const positions = new Map(order.map((cpu, index) => [cpu, index]));
  const values = new Float64Array(order.length * order.length);
  let total = 0;

  for (const cell of cells) {
    const from = positions.get(cell.from);
    const to = positions.get(cell.to);
    if (from === undefined || to === undefined || cell.count <= 0) {
      continue;
    }
    const offset = from * order.length + to;
    values[offset] += cell.count;
    total += cell.count;
  }

  let max = 0;
  let minPositive = Number.POSITIVE_INFINITY;
  for (const value of values) {
    max = Math.max(max, value);
    if (value > 0) {
      minPositive = Math.min(minPositive, value);
    }
  }
  return {
    order,
    positions,
    values,
    max,
    minPositive: Number.isFinite(minPositive) ? minPositive : 0,
    total,
  };
}

export function migrationLocality(topology, from, to) {
  const cpus = new Map((topology?.cpus || []).map((cpu) => [cpu.cpu, cpu]));
  const source = cpus.get(from);
  const destination = cpus.get(to);
  if (!source || !destination) {
    return { code: "unknown", label: "Topology unknown" };
  }
  if (from === to) {
    return { code: "same_cpu", label: "Same CPU" };
  }
  if (source.core === destination.core
      && source.package === destination.package
      && source.node === destination.node) {
    return { code: "same_core", label: "Same core" };
  }
  if (source.llc === destination.llc
      && source.package === destination.package
      && source.node === destination.node) {
    return { code: "same_llc", label: "Same LLC" };
  }
  if (source.package === destination.package && source.node === destination.node) {
    return { code: "same_package", label: "Same package" };
  }
  if (source.node === destination.node) {
    return { code: "same_node", label: "Same NUMA node" };
  }
  return { code: "cross_node", label: "Cross-NUMA" };
}

export function buildCpuUsage(topology, entries, orderMode) {
  const sourceOrder = orderMode === "numeric"
    ? topology.numeric_order
    : topology.topology_order;
  const order = [...sourceOrder];
  const positions = new Map(order.map((cpu, index) => [cpu, index]));
  const runtimeNs = new Float64Array(order.length);
  const utilizationPct = new Float64Array(order.length);

  for (const entry of entries) {
    const index = positions.get(entry.cpu);
    if (index === undefined) {
      continue;
    }
    runtimeNs[index] = Math.max(0, entry.runtime_ns || 0);
    utilizationPct[index] = Math.max(0, entry.utilization_pct || 0);
  }
  return { order, positions, runtimeNs, utilizationPct };
}

function buildGroupedUsage(topology, entries, orderMode, identityForCpu) {
  const usage = buildCpuUsage(topology, entries, orderMode);
  const cpuInfo = new Map(topology.cpus.map((cpu) => [cpu.cpu, cpu]));
  const groups = [];
  const groupIndexes = new Map();
  const cpuGroups = new Int32Array(usage.order.length).fill(-1);

  for (let index = 0; index < usage.order.length; index += 1) {
    const cpu = cpuInfo.get(usage.order[index]);
    if (!cpu) {
      continue;
    }
    const identity = identityForCpu(cpu);
    if (!identity) {
      continue;
    }
    const { key } = identity;
    let groupIndex = groupIndexes.get(key);
    if (groupIndex === undefined) {
      groupIndex = groups.length;
      groupIndexes.set(key, groupIndex);
      groups.push({
        ...identity,
        cpuCount: 0,
        runtimeNs: 0,
        utilizationPct: 0,
      });
    }
    const group = groups[groupIndex];
    group.cpuCount += 1;
    group.runtimeNs += usage.runtimeNs[index];
    group.utilizationPct += usage.utilizationPct[index];
    if (group.cpus) {
      group.cpus.push(cpu.cpu);
    }
    cpuGroups[index] = groupIndex;
  }
  for (const group of groups) {
    group.utilizationPct = group.cpuCount > 0
      ? group.utilizationPct / group.cpuCount
      : 0;
  }

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

export function buildLlcUsage(topology, entries, orderMode) {
  return buildGroupedUsage(topology, entries, orderMode, (cpu) => ({
    key: `${cpu.node}:${cpu.package}:${cpu.llc}`,
    node: cpu.node,
    package: cpu.package,
    llc: cpu.llc,
  }));
}

export function buildCoreUsage(topology, entries, orderMode) {
  return buildGroupedUsage(topology, entries, orderMode, (cpu) => (
    cpu.core == null
      ? null
      : {
        key: `${cpu.node}:${cpu.package}:${cpu.core}`,
        node: cpu.node,
        package: cpu.package,
        core: cpu.core,
        cpus: [],
      }
  ));
}

export function axisLabelIndices(count, maxLabels = 24) {
  const total = Math.max(0, Math.trunc(Number(count) || 0));
  if (total === 0) {
    return [];
  }
  const limit = Math.max(2, Math.trunc(Number(maxLabels) || 0));
  if (total <= limit) {
    return Array.from({ length: total }, (_, index) => index);
  }
  return [...new Set(Array.from(
    { length: limit },
    (_, index) => Math.round(index * (total - 1) / (limit - 1)),
  ))];
}

export function heatmapLayout(cpuCount, viewportWidth, zoom) {
  const count = Math.max(1, Math.trunc(Number(cpuCount) || 0));
  const availableWidth = Math.max(320, Number(viewportWidth) || 800);
  const fitCell = (availableWidth - 104) / count;
  const cellSize = Math.max(2, Math.min(9, fitCell)) * (Number(zoom) || 1);
  const usageHeight = Math.max(13, Math.min(26, cellSize * 2.5));
  const usageTop = 20;
  const coreHeight = Math.max(16, Math.min(24, cellSize * 2.5));
  const coreTop = usageTop + usageHeight + 4;
  const llcHeight = Math.max(16, Math.min(24, cellSize * 2.5));
  const llcTop = coreTop + coreHeight + 4;
  const margins = { left: 64, top: llcTop + llcHeight + 10, right: 18 };
  const matrixSize = count * cellSize;
  const width = Math.ceil(margins.left + matrixSize + margins.right);
  const height = Math.ceil(margins.top + matrixSize + 46);
  return {
    cellSize,
    coreHeight,
    coreTop,
    height,
    llcHeight,
    llcTop,
    margins,
    matrixSize,
    usageHeight,
    usageTop,
    width,
  };
}

export function normalizeCount(value, max, scale) {
  if (value <= 0 || max <= 0) {
    return 0;
  }
  if (scale === "linear") {
    return Math.min(1, value / max);
  }
  return Math.min(1, Math.log1p(value) / Math.log1p(max));
}

export function normalizeUtilization(value, scale) {
  return normalizeCount(Math.max(0, Math.min(100, value)), 100, scale);
}

export function topologyBoundaries(topology, order) {
  const cpus = new Map(topology.cpus.map((cpu) => [cpu.cpu, cpu]));
  const levels = ["node", "package", "llc", "core"];
  const boundaries = [];

  for (let index = 1; index < order.length; index += 1) {
    const previous = cpus.get(order[index - 1]);
    const current = cpus.get(order[index]);
    if (!previous || !current) {
      continue;
    }
    const level = levels.find((candidate) => previous[candidate] !== current[candidate]);
    if (level) {
      boundaries.push({ index, level });
    }
  }
  return boundaries;
}

export function topologyGroups(topology, order, level) {
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

export function llcAnnotations(topology, order) {
  if (!Array.isArray(order) || order.length === 0) {
    return [];
  }
  return topologyGroups(topology, order, "llc")
    .filter((group) => group.end > group.start && group.value != null)
    .map((group) => ({
      start: group.start,
      end: group.end,
      llc: group.value,
      label: `LLC ${group.value}`,
    }));
}

export function parseTgids(input) {
  const tokens = input.trim().split(/[\s,]+/).filter(Boolean);
  if (tokens.length === 0) {
    throw new Error("Enter at least one TGID");
  }
  const tgids = tokens.map((token) => {
    const value = Number(token);
    if (!Number.isSafeInteger(value) || value <= 0 || value > 0xffffffff) {
      throw new Error(`Invalid TGID: ${token}`);
    }
    return value;
  });
  const unique = [...new Set(tgids)].sort((left, right) => left - right);
  if (unique.length > 1024) {
    throw new Error("At most 1024 TGIDs may be tracked");
  }
  return unique;
}

const INFERNO_STOPS = [
  "#000004",
  "#420a68",
  "#932667",
  "#dd513a",
  "#fca50a",
  "#fcffa4",
];

export function infernoColor(position) {
  const clamped = Math.max(0, Math.min(1, position));
  const scaled = clamped * (INFERNO_STOPS.length - 1);
  const leftIndex = Math.floor(scaled);
  const rightIndex = Math.min(INFERNO_STOPS.length - 1, leftIndex + 1);
  const fraction = scaled - leftIndex;
  const left = hexToRgb(INFERNO_STOPS[leftIndex]);
  const right = hexToRgb(INFERNO_STOPS[rightIndex]);
  const channel = (name) => Math.round(left[name] + (right[name] - left[name]) * fraction);
  return rgbToHex(channel("red"), channel("green"), channel("blue"));
}

export function contrastTextColor(background, darkText, lightText) {
  const backgroundLuminance = relativeLuminance(background);
  const darkContrast = contrastRatio(backgroundLuminance, relativeLuminance(darkText));
  const lightContrast = contrastRatio(backgroundLuminance, relativeLuminance(lightText));
  return darkContrast >= lightContrast ? darkText : lightText;
}

export function mixHexColors(foreground, background, amount) {
  const clamped = Math.max(0, Math.min(1, amount));
  const front = hexToRgb(foreground);
  const back = hexToRgb(background);
  const channel = (name) => Math.round(
    front[name] * clamped + back[name] * (1 - clamped),
  );
  return rgbToHex(channel("red"), channel("green"), channel("blue"));
}

export function heatmapTextColor(heatColor, surfaceColor, intensity) {
  const background = mixHexColors(heatColor, surfaceColor, intensity);
  return contrastTextColor(background, "#000000", "#ffffff");
}

export function drawContrastingOutline(context, {
  color,
  contrastColor,
  lineWidth,
  rectangle,
}) {
  context.strokeStyle = contrastColor;
  context.lineWidth = lineWidth + 2;
  context.strokeRect(...rectangle);
  context.strokeStyle = color;
  context.lineWidth = lineWidth;
  context.strokeRect(...rectangle);
}

function relativeLuminance(color) {
  const { red, green, blue } = hexToRgb(color);
  const channel = (value) => {
    const normalized = value / 255;
    return normalized <= 0.04045
      ? normalized / 12.92
      : ((normalized + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(red) + 0.7152 * channel(green) + 0.0722 * channel(blue);
}

function contrastRatio(left, right) {
  return (Math.max(left, right) + 0.05) / (Math.min(left, right) + 0.05);
}

function hexToRgb(color) {
  return {
    red: Number.parseInt(color.slice(1, 3), 16),
    green: Number.parseInt(color.slice(3, 5), 16),
    blue: Number.parseInt(color.slice(5, 7), 16),
  };
}

function rgbToHex(red, green, blue) {
  return `#${[red, green, blue]
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("")}`;
}
