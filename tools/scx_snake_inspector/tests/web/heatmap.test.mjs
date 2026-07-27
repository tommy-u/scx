// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

import assert from "node:assert/strict";
import test from "node:test";

import {
  buildCpuUsage,
  buildMatrix,
  infernoColor,
  normalizeCount,
  normalizeUtilization,
  parseTgids,
  topologyBoundaries,
  topologyGroups,
} from "../../src/web/heatmap.js";

const topology = {
  cpus: [
    { cpu: 0, node: 1, package: 1, llc: 2, core: 4 },
    { cpu: 1, node: 0, package: 0, llc: 0, core: 0 },
    { cpu: 2, node: 0, package: 0, llc: 0, core: 0 },
    { cpu: 3, node: 0, package: 0, llc: 1, core: 1 },
  ],
  numeric_order: [0, 1, 2, 3],
  topology_order: [1, 2, 3, 0],
};

test("buildMatrix places sparse CPU IDs in the selected order", () => {
  const result = buildMatrix(
    topology,
    [
      { from: 1, to: 3, count: 7 },
      { from: 0, to: 1, count: 4 },
      { from: 99, to: 1, count: 100 },
    ],
    "topology",
  );

  assert.deepEqual(result.order, [1, 2, 3, 0]);
  assert.equal(result.values[0 * 4 + 2], 7);
  assert.equal(result.values[3 * 4 + 0], 4);
  assert.equal(result.max, 7);
  assert.equal(result.total, 11);
});

test("normalizeCount supports linear and logarithmic scales", () => {
  assert.equal(normalizeCount(0, 100, "linear"), 0);
  assert.equal(normalizeCount(25, 100, "linear"), 0.25);
  assert.equal(normalizeCount(100, 100, "log"), 1);
  assert.ok(normalizeCount(10, 100, "log") > 0.5);
  assert.equal(normalizeCount(1, 0, "log"), 0);
});

test("buildCpuUsage aligns runtime with the selected CPU order", () => {
  const numeric = buildCpuUsage(
    topology,
    [
      { cpu: 3, runtime_ns: 75, utilization_pct: 30 },
      { cpu: 1, runtime_ns: 25, utilization_pct: 10 },
      { cpu: 99, runtime_ns: 500, utilization_pct: 100 },
    ],
    "numeric",
  );

  assert.deepEqual(numeric.order, [0, 1, 2, 3]);
  assert.deepEqual([...numeric.runtimeNs], [0, 25, 0, 75]);
  assert.deepEqual([...numeric.utilizationPct], [0, 10, 0, 30]);

  const grouped = buildCpuUsage(topology, [{ cpu: 3, runtime_ns: 75, utilization_pct: 30 }], "topology");
  assert.deepEqual(grouped.order, [1, 2, 3, 0]);
  assert.deepEqual([...grouped.utilizationPct], [0, 0, 30, 0]);
});

test("normalizeUtilization uses an absolute zero-to-one-hundred scale", () => {
  assert.equal(normalizeUtilization(0, "linear"), 0);
  assert.equal(normalizeUtilization(25, "linear"), 0.25);
  assert.equal(normalizeUtilization(100, "linear"), 1);
  assert.equal(normalizeUtilization(150, "linear"), 1);
  assert.ok(normalizeUtilization(10, "log") > 0.5);
});

test("topologyBoundaries reports the strongest boundary at each split", () => {
  assert.deepEqual(topologyBoundaries(topology, topology.topology_order), [
    { index: 2, level: "llc" },
    { index: 3, level: "node" },
  ]);
});

test("topologyGroups reports contiguous LLC spans", () => {
  assert.deepEqual(topologyGroups(topology, topology.topology_order, "llc"), [
    { start: 0, end: 2, value: 0 },
    { start: 2, end: 3, value: 1 },
    { start: 3, end: 4, value: 2 },
  ]);
});

test("parseTgids accepts separators and returns sorted unique IDs", () => {
  assert.deepEqual(parseTgids("42, 7  42\n19"), [7, 19, 42]);
  assert.throws(() => parseTgids(""));
  assert.throws(() => parseTgids("0"));
  assert.throws(() => parseTgids("7.5"));
});

test("infernoColor is deterministic and clamps its input", () => {
  assert.equal(infernoColor(-1), "#000004");
  assert.equal(infernoColor(0), "#000004");
  assert.equal(infernoColor(1), "#fcffa4");
  assert.equal(infernoColor(2), "#fcffa4");
  assert.match(infernoColor(0.5), /^#[0-9a-f]{6}$/);
});
