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
  for (const value of values) {
    max = Math.max(max, value);
  }
  return { order, positions, values, max, total };
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
