"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { buildModel } = require("../src/web/topology_strip.js");
const { page, response, stats, settle } = require("./page_test_support");
const topology = { cpus: [
  { cpu: 8, llc: 7 }, { cpu: 2, llc: 2 }, { cpu: 0, llc: 7 },
  { cpu: 10, llc: 2 }, { cpu: 12, llc: 9 },
] };
const cells = { 0: { cgroup_path: "/", num_cpus: 100 },
  1: { cgroup_path: "/workload.slice/cpu.service", num_cpus: 100 } };
const model = buildModel(topology, { 0: 0, 2: 1, 8: 1, 10: 1 }, cells);
assert.deepEqual(model.llcs.map(llc => llc.id), [2, 7, 9], "matrix columns follow LLC number order");
assert.equal(model.cpuCount, 5);
assert.deepEqual(model.llcs[0].segments.map(segment => [segment.cell, segment.cpus.length, segment.share]), [[1, 2, 1]]);
assert.deepEqual(model.llcs[1].segments.map(segment => [segment.cell, segment.cpus.length, segment.share]), [[0, 1, .5], [1, 1, .5]],
  "cell shares come from observed owners within each LLC, independent of global num_cpus");
assert.deepEqual(model.llcs[2].segments.map(segment => [segment.cell, segment.cpus.length, segment.share]), [[null, 1, 1]],
  "missing ownership stays unknown and does not become Cell 0");
assert.equal(model.unknownCount, 1);
for (const llc of model.llcs) assert.equal(llc.segments.reduce((sum, segment) => sum + segment.share, 0), 1);
assert.deepEqual(model.cells.map(cell => cell.cpus), [[0], [2, 8, 10]]);
assert.equal(buildModel(null, null, cells).llcs.length, 0);
assert.equal(buildModel(topology, { 0: 99 }, cells).unknownCount, 5, "unrecognized cell IDs remain unavailable");
const paired = buildModel({ cpus: [
  { cpu: 40, package: 0, core: 7, llc: 1 },
  { cpu: 2, package: 1, core: 9, llc: 1 },
  { cpu: 80, package: 1, core: 7, llc: 1 },
  { cpu: 24, package: 0, core: 7, llc: 1 },
  { cpu: 18, package: 1, core: 9, llc: 1 },
] }, {}, cells);
assert.deepEqual(paired.llcs[0].cores, [
  { package: 1, id: 9, cpus: [2, 18] },
  { package: 0, id: 7, cpus: [24, 40] },
  { package: 1, id: 7, cpus: [80] },
], "core tiles use real sibling groups and preserve package identity");
const unavailableCore = buildModel({ cpus: [
  { cpu: 0, package: 0, core: 1, llc: 0, core_topology_available: true },
  { cpu: 1, package: 0, core: 1, llc: 0, core_topology_available: false },
] }, {}, cells);
assert.deepEqual(unavailableCore.llcs[0].cores, [
  { package: 0, id: 1, cpus: [0] }, { package: null, id: null, cpus: [1] },
], "fallback integer IDs cannot create a false SMT pair when discovery reports unavailable metadata");
assert.deepEqual(paired.llcs[0].grid, [
  2, 24, 80, null, null, null, null, null,
  18, 40, null, null, null, null, null, null,
], "LLC grids stack real SMT siblings, keep package identity, and leave padding empty");
for (const llc of model.llcs) assert.deepEqual(llc.grid.filter(cpu => cpu !== null), llc.cpus,
  "missing core metadata preserves every sparse CPU ID without inventing SMT pairs");
const wide = buildModel({ cpus: Array.from({ length: 9 }, (_,core) => [
  { cpu: core, package: 0, core, llc: 3 }, { cpu: core + 100, package: 0, core, llc: 3 },
]).flat() }, {}, cells).llcs[0].grid;
assert.equal(wide.filter(cpu => cpu !== null).length, 18, "wrapping a large LLC loses no CPUs");
assert.equal(wide[16], 8);
assert.equal(wide[24], 108, "the last core's SMT pair wraps into a second block");
const html = fs.readFileSync(path.join(__dirname, "../src/web/stats.html"), "utf8");
assert(html.indexOf('id="cpuTopologyHeading"') < html.indexOf('id="borrowingHeading"'), "placement appears above borrowing flows");
assert(html.includes('id="cellPlacementMatrixHead"') && html.includes('id="cellPlacementMatrixBody"'), "cell placement uses a table with cell rows and LLC columns");
assert(!html.includes('id="llcComposition-numeric"'), "composition blocks are replaced");
assert(!html.includes('id="cpuTopology-smt"'), "old CPU and SMT strips are replaced");
async function testCpusetCharts() {
  let snapshot = stats();
  snapshot.metrics.cells = cells;
  snapshot.cpu_cells = { 0: 0, 2: 1, 8: 1, 10: 1 };
  const view = page("stats.js", () => response(snapshot));
  await settle();
  view.read(`cpuTopology = ${JSON.stringify(topology)}`);
  view.context.renderCpuTopology();

  const chart = order => view.element("#cpuTopology").querySelector(`#cellCpuset${order}`);
  const rows = order => chart(order).children.filter(node => Object.hasOwn(node.dataset, "cell"));
  const bar = (order, cell) => rows(order).find(node => String(node.dataset.cell) === String(cell)).children[1];
  const groups = cell => bar("Llc", cell).children;
  const groupButton = group => group.children[0];
  const counts = cell => groups(cell).map(group => groupButton(group).children[1].textContent);
  const dots = (order, cell) => order === "Numeric" ? bar(order, cell).children
    : groups(cell).flatMap(group => groupButton(group).children[0].children.flatMap(core => core.children))
      .filter(node => Object.hasOwn(node.dataset, "cpu"));
  const assigned = (order, cell) => dots(order, cell)
    .filter(node => node.className.includes("cpuset-assigned")).map(node => Number(node.dataset.cpu));

  assert.equal(rows("Numeric").length, 3, "two cell cpusets and an explicit unknown-ownership row");
  for (const [order, cpuIds] of [["Numeric", [0, 2, 8, 10, 12]], ["Llc", [2, 10, 0, 8, 12]]]) {
    assert.deepEqual(dots(order, 1).map(node => Number(node.dataset.cpu)), cpuIds,
      "all real CPU IDs appear exactly once in the requested order, including sparse IDs");
    assert.deepEqual(assigned(order, 0), [0]);
    assert.deepEqual(assigned(order, 1).sort((a, b) => a - b), [2, 8, 10]);
    assert.deepEqual(assigned(order, "unknown"), [12]);
    if (order === "Numeric") {
      assert.equal(bar(order, 1).attributes.get("role"), "img");
      assert.match(bar(order, 1).attributes.get("aria-label"), /2,8,10/);
    }
    assert(dots(order, 0).find(node => Number(node.dataset.cpu) === 12)
      .className.includes("cpuset-unknown"), "unknown ownership cannot become Cell 0");
  }
  assert.deepEqual(chart("Llc").children[0].children[1].children.map(node => Number(node.dataset.llc)), [2, 7, 9]);
  assert.deepEqual(groups(1).map(node => Number(node.dataset.llc)), [2, 7, 9], "each LLC gets a separate grid");
  assert.deepEqual(counts(1), [2, 1, 0],
    "the per-LLC counts use observed membership, including zero allocations");
  assert.match(groupButton(groups(1)[0]).attributes.get("aria-label"), /2 of 2 CPUs/);
  assert.match(groupButton(groups(1)[0]).attributes.get("aria-label"), /2,10/);
  assert.equal(groupButton(groups(1)[0]).attributes.get("tabindex"), "0", "CPU grids support keyboard inspection");
  assert.equal(typeof groupButton(groups(1)[0]).listeners.get("click"), "function",
    "each LLC grid highlights its cell when activated, as in the selected mockup");
  const gridRow = cell => rows("Llc").find(node => String(node.dataset.cell) === String(cell));
  const select = cell => gridRow(cell).children[0].children[0];
  select(1).listeners.get("click")();
  select(1).focus();
  assert.equal(select(1).attributes.get("aria-pressed"), "true");
  assert(gridRow(0).classList.contains("cpuset-grid-muted"), "selecting a cell emphasizes its grid row");
  const unchanged = chart("Numeric").children;
  view.context.renderCpuTopology();
  assert.equal(chart("Numeric").children, unchanged, "unchanged ownership does not rebuild the charts");
  const unchangedGrid = chart("Llc").children;
  view.context.renderCpuTopology();
  assert.equal(chart("Llc").children, unchangedGrid);

  snapshot = stats(2);
  snapshot.metrics.cells = cells;
  snapshot.cpu_cells = { 0: 1, 2: 1, 8: 0, 10: 0, 12: 0 };
  await view.context.refresh();
  assert.deepEqual(assigned("Numeric", 0), [8, 10, 12], "the bars follow live CPU reassignments");
  assert.deepEqual(assigned("Llc", 0).sort((a,b) => a-b), [8, 10, 12], "the grids follow live CPU reassignments");
  assert.deepEqual(counts(0), [1, 1, 1]);
  assert.equal(select(1).attributes.get("aria-pressed"), "true", "highlight selection survives an ownership update");
  assert.equal(view.context.document.activeElement === select(1), true,
    "live ownership updates preserve keyboard focus on the same cell");
  select(1).listeners.get("click")();
  assert(!gridRow(0).classList.contains("cpuset-grid-muted"), "clicking the selected cell restores all rows");
  groupButton(groups(0)[0]).listeners.get("click")();
  assert.equal(select(0).attributes.get("aria-pressed"), "true", "clicking an LLC grid highlights its owning row");
  groupButton(groups(0)[0]).listeners.get("click")();
  groupButton(groups(1)[0]).focus();
  assert.equal(rows("Numeric").length, 2, "the unknown row disappears once ownership is complete");

  view.setNow(20000);
  view.context.renderCpuTopology();
  assert.deepEqual(assigned("Numeric", 0), [], "stale ownership cannot remain colored as current");
  assert.deepEqual(assigned("Numeric", "unknown"), [0, 2, 8, 10, 12]);
  assert.deepEqual(assigned("Llc", 0), [], "stale ownership cannot remain colored in the grid");
  assert.deepEqual(assigned("Llc", "unknown").sort((a,b) => a-b), [0, 2, 8, 10, 12]);
  assert.equal(view.context.document.activeElement === groupButton(groups(1)[0]), true,
    "a focused LLC grid survives an ownership availability update");
  view.read("cpuTopology = null");
  view.context.renderCpuTopology();
  assert.equal(chart("Numeric").children.length, 0, "missing topology clears old cpuset bars");
  assert.equal(chart("Llc").children.length, 0);

  assert(html.indexOf('id="cellCpusetNumeric"') > html.indexOf('id="cellPlacementMatrixBody"'));
  assert(html.indexOf('id="cellCpusetLlc"') < html.indexOf('id="borrowingHeading"'));
}

async function testCoreThreads() {
  const coreTopology = { cpus: [
    { cpu: 0, package: 0, core: 0, llc: 0 }, { cpu: 16, package: 0, core: 0, llc: 0 },
    { cpu: 2, package: 0, core: 1, llc: 0 }, { cpu: 18, package: 0, core: 1, llc: 0 },
    { cpu: 4, package: 0, core: 2, llc: 0 }, { cpu: 20, package: 0, core: 2, llc: 0 },
    { cpu: 6, package: 0, core: 3, llc: 0 }, { cpu: 22, package: 0, core: 3, llc: 0 },
    { cpu: 7, package: 1, core: 3, llc: 0 }, { cpu: 23, package: 1, core: 3, llc: 0 },
    { cpu: 39, package: 1, core: 3, llc: 0 }, { cpu: 8, llc: 1 },
  ] };
  const snapshot = stats();
  snapshot.metrics.cells = { ...cells, 2: { cgroup_path: "/workload.slice/other.service", num_cpus: 100 } };
  snapshot.cpu_cells = { 0: 0, 16: 0, 2: 1, 18: 2, 4: 1, 6: 2, 22: 2, 7: 0, 23: 1, 39: 2, 8: 1 };
  const view = page("stats.js", () => response(snapshot));
  await settle();
  view.read(`cpuTopology = ${JSON.stringify(coreTopology)}`);
  view.context.renderCpuTopology();
  const chart = view.element("#cpuTopology").querySelector("#cellCpusetLlc");
  const row = cell => chart.children.find(node => String(node.dataset.cell) === String(cell));
  const groups = cell => row(cell).children[1].children;
  const tiles = cell => groups(cell).flatMap(group => group.children[0].children[0].children)
    .filter(node => Object.hasOwn(node.dataset, "core"));
  const threads = tile => tile.children.filter(node => Object.hasOwn(node.dataset, "cpu"));
  const core = (cell, key) => tiles(cell).find(node => node.dataset.core === key);
  const root = core(0, "0/0");
  assert(root.className.includes("cpuset-core-assigned"), "Cell 0's complete core gets the same visible enclosure");
  assert.deepEqual(threads(root).map(node => Number(node.dataset.cpu)), [0, 16]);
  assert.equal(root.children.length, 2, "the enclosure contains only this core's observed threads");
  assert(threads(root).every(node => node.className.includes("cpuset-assigned")));
  const split = threads(core(1, "0/1"));
  assert(split.find(node => Number(node.dataset.cpu) === 2).className.includes("cpuset-assigned"));
  const foreign = split.find(node => Number(node.dataset.cpu) === 18);
  assert(foreign.className.includes("cpuset-sibling-foreign"), "the other owner's sibling is shown as context");
  assert(!foreign.className.includes("cpuset-assigned"), "foreign context must not count as this cell's assignment");
  assert.equal(Number(foreign.dataset.owner), 2);
  assert.match(foreign.title, /Cell 2/);
  assert.match(core(1, "0/1").title, /CPU 2.*Cell 1/);
  assert.match(core(1, "0/1").title, /CPU 18.*Cell 2/);
  assert.match(groups(1)[0].children[0].attributes.get("aria-label"), /CPU 18.*Cell 2/,
    "keyboard inspection includes the foreign sibling's identity");
  const unavailable = threads(core(1, "0/2")).find(node => Number(node.dataset.cpu) === 20);
  assert(unavailable.className.includes("cpuset-unknown"));
  assert(!unavailable.className.includes("cpuset-sibling-foreign"), "unavailable ownership is not a known foreign cell");
  assert(!threads(core("unknown", "0/2")).some(node => node.className.includes("cpuset-sibling-foreign")),
    "the unknown row cannot establish that its sibling belongs to a different cell");
  assert(!threads(core(1, "0/3")).some(node => node.className.includes("cpuset-sibling-foreign")),
    "a core with no assigned thread stays neutral in this row");
  assert.equal(threads(core(0, "1/3")).length, 3, "all observed threads appear on wider SMT cores");
  const missingCore = core(1, "cpu:8");
  assert(missingCore.className.includes("cpuset-core-unidentified"));
  assert.equal(threads(missingCore).length, 1, "missing core metadata cannot invent a sibling");
  assert.match(missingCore.title, /Core topology unavailable/);
  for (const [cell, expected] of [[0, [0, 7, 16]], [1, [2, 4, 8, 23]], [2, [6, 18, 22, 39]], ["unknown", [20]]]) {
    const all = tiles(cell).flatMap(threads);
    assert.deepEqual(all.map(node => Number(node.dataset.cpu)).sort((a,b) => a-b),
      coreTopology.cpus.map(cpu => cpu.cpu).sort((a,b) => a-b));
    assert.deepEqual(all.filter(node => node.className.includes("cpuset-assigned"))
      .map(node => Number(node.dataset.cpu)).sort((a,b) => a-b), expected);
    assert.equal(row(cell).children[2].textContent, expected.length, "totals count only assigned logical CPUs");
  }
}

testCpusetCharts().then(testCoreThreads).then(() => console.log("Cell placement and core-thread charts contract: ok"))
  .catch(error => { console.error(error); process.exitCode = 1; });
