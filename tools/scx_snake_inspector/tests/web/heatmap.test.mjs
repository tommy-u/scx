// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import * as heatmapModule from "../../src/web/heatmap.js";
import {
  buildCpuUsage,
  buildLlcUsage,
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
  assert.equal(result.minPositive, 4);
  assert.equal(result.total, 11);
});

test("migration locality describes the narrowest shared CPU boundary", () => {
  assert.equal(typeof heatmapModule.migrationLocality, "function");
  if (typeof heatmapModule.migrationLocality !== "function") {
    return;
  }
  const extended = {
    ...topology,
    cpus: [
      ...topology.cpus,
      { cpu: 4, node: 0, package: 0, llc: 0, core: 2 },
    ],
  };
  assert.equal(heatmapModule.migrationLocality(extended, 1, 1).code, "same_cpu");
  assert.equal(heatmapModule.migrationLocality(extended, 1, 2).code, "same_core");
  assert.equal(heatmapModule.migrationLocality(extended, 1, 4).code, "same_llc");
  assert.equal(heatmapModule.migrationLocality(extended, 1, 3).code, "same_package");
  assert.equal(heatmapModule.migrationLocality(extended, 3, 0).code, "cross_node");
  assert.equal(heatmapModule.migrationLocality(extended, 99, 1).code, "unknown");
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

test("buildLlcUsage reports capacity-normalized utilization for each LLC", () => {
  const result = buildLlcUsage(
    topology,
    [
      { cpu: 1, runtime_ns: 25, utilization_pct: 10 },
      { cpu: 3, runtime_ns: 75, utilization_pct: 30 },
      { cpu: 99, runtime_ns: 500, utilization_pct: 100 },
    ],
    "topology",
  );

  assert.deepEqual(result.groups, [
    {
      key: "0:0:0",
      node: 0,
      package: 0,
      llc: 0,
      cpuCount: 2,
      runtimeNs: 25,
      utilizationPct: 5,
    },
    {
      key: "0:0:1",
      node: 0,
      package: 0,
      llc: 1,
      cpuCount: 1,
      runtimeNs: 75,
      utilizationPct: 30,
    },
    {
      key: "1:1:2",
      node: 1,
      package: 1,
      llc: 2,
      cpuCount: 1,
      runtimeNs: 0,
      utilizationPct: 0,
    },
  ]);
  assert.deepEqual(result.spans, [
    { start: 0, end: 2, groupIndex: 0 },
    { start: 2, end: 3, groupIndex: 1 },
    { start: 3, end: 4, groupIndex: 2 },
  ]);
});

test("buildLlcUsage keeps repeated LLC IDs separate across packages", () => {
  const repeatedIds = {
    cpus: [
      { cpu: 0, node: 0, package: 0, llc: 0, core: 0 },
      { cpu: 1, node: 0, package: 1, llc: 0, core: 1 },
    ],
    numeric_order: [0, 1],
    topology_order: [0, 1],
  };

  const result = buildLlcUsage(repeatedIds, [
    { cpu: 0, runtime_ns: 10, utilization_pct: 10 },
    { cpu: 1, runtime_ns: 90, utilization_pct: 90 },
  ], "topology");

  assert.deepEqual(result.groups.map((group) => [group.key, group.utilizationPct]), [
    ["0:0:0", 10],
    ["0:1:0", 90],
  ]);
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

test("axis labels sample the full CPU order without omitting either end", () => {
  assert.equal(typeof heatmapModule.axisLabelIndices, "function");
  const indices = heatmapModule.axisLabelIndices(316, 24);

  assert.equal(indices[0], 0);
  assert.equal(indices.at(-1), 315);
  assert.ok(indices.length <= 24);
  assert.equal(new Set(indices).size, indices.length);
  assert.ok(indices.some((index) => index % 2 === 0));
  assert.ok(indices.some((index) => index % 2 === 1));
});

test("heatmap layout places utilization above the migration matrix", () => {
  assert.equal(typeof heatmapModule.heatmapLayout, "function");
  const layout = heatmapModule.heatmapLayout(316, 1440, 1);

  assert.ok(layout.usageTop + layout.usageHeight <= layout.llcTop);
  assert.ok(layout.llcTop + layout.llcHeight < layout.margins.top);
  assert.equal(layout.matrixSize, 316 * layout.cellSize);
  assert.ok(layout.height > layout.margins.top + layout.matrixSize);
});

test("the Activity viewport delegates vertical scrolling to the document", () => {
  const stylesheet = readFileSync(
    new URL("../../src/web/style.css", import.meta.url),
    "utf8",
  );
  const viewportRules = [...stylesheet.matchAll(/\.heatmap-viewport\s*\{([^}]*)\}/g)];

  assert.ok(viewportRules.length > 0);
  assert.equal(viewportRules.some((match) => /max-height\s*:/.test(match[1])), false);
});

test("Activity exposes numeric heat bounds and a persistent-in-session pair inspection", () => {
  const page = readFileSync(new URL("../../src/web/index.html", import.meta.url), "utf8");
  const script = readFileSync(new URL("../../src/web/app.js", import.meta.url), "utf8");

  assert.match(page, /id="legendLow"/);
  assert.match(page, /id="legendHigh"/);
  assert.match(page, /id="migrationPairInspection"/);
  assert.match(script, /pinnedMigrationPair/);
  assert.match(script, /canvas\.addEventListener\("click"/);
});
