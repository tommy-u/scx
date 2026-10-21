"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");
const { page, counters, migrations, stats, system, meta, collector, response, settle, timelineView } = require("./page_test_support");

const heatmapSource = fs.readFileSync(path.join(__dirname, "../src/web/heatmap.js"), "utf8");
const topology = {
  cpus: [
    { cpu: 0, node: 0, package: 0, llc: 8, core: 0 },
    { cpu: 1, node: 0, package: 0, llc: 0, core: 1 },
    { cpu: 2, node: 0, package: 0, llc: 40, core: 2 },
    { cpu: 3, node: 0, package: 0, llc: 8, core: 0 },
    { cpu: 4, node: 0, package: 0, llc: 0, core: 1 },
  ],
  numeric_order: [0, 1, 2, 3, 4],
  topology_order: [1, 4, 0, 3, 2],
};

function row(llc, bps, extra = {}) {
  return { domain_id: 99 - llc, llc, node: 0, package: 0, topology_available: true,
    total_status: "measured", total_error: null, mbm_total_bps: bps,
    total_expected_contributions: 2, total_measured_contributions: 2,
    local_status: "measured", local_error: null, mbm_local_bps: 0,
    local_expected_contributions: 2, local_measured_contributions: 2,
    occupancy_status: "measured", llc_occupancy_bytes: 100,
    control_group_count: 2, control_group_names: ["/", "workload"],
    rate_group_count: 2, rate_group_names: ["/", "workload"],
    contributions: [], error: null, ...extra };
}

function bandwidth(rows = [row(40, 9e9), row(8, 0), row(0, 2e9)], extra = {}) {
  return { available: true, error: null, partial: false, meta: meta(1, 0, 10000),
    scope: "resctrl root + control-group parent aggregates · hardware L3 domains",
    summary: { source: "resctrl", monitor: "all_control_groups", mbm_total_bps: 11e9,
      coverage_scope: "exposed_parent_domain_files", inventory_complete: true,
      scope_note: "Root + all top-level control groups with mon_data. Child monitor counters are included in each parent reading." },
    rows, ...extra };
}

// The real renderer runs against a canvas recorder because Node has no browser canvas.
// Assertions inspect the painted strip, tooltip and click behavior, not renderer internals.
function canvasRecorder(context) {
  const operations = [];
  let retainedPainting = [];
  const painting = () => operations.length ? operations : retainedPainting;
  const drawing = {
    fillStyle: "", strokeStyle: "", lineWidth: 1,
    setTransform() {}, save() {}, restore() {}, translate() {}, rotate() {}, clip() {}, rect() {},
    beginPath() {}, moveTo() {}, lineTo() {}, stroke() {},
    fillRect(x, y, width, height) { operations.push({ kind: "rect", x, y, width, height, color: this.fillStyle }); },
    strokeRect(x, y, width, height) { operations.push({ kind: "border", x, y, width, height, color: this.strokeStyle }); },
    fillText(text, x, y) { operations.push({ kind: "text", text: String(text), x, y }); },
    measureText(text) { return { width: String(text).length * 5 }; },
  };
  const canvas = context.document.querySelector("#migrationHeatmapCanvas");
  const viewport = context.document.querySelector("#migrationHeatmapViewport");
  const tooltip = context.document.querySelector("#migrationHeatmapTooltip");
  canvas.getContext = () => drawing;
  canvas.removeEventListener = type => canvas.listeners.delete(type);
  viewport.clientWidth = 600;
  viewport.scrollWidth = 1000;
  viewport.scrollHeight = 1000;
  viewport.scrollLeft = 0;
  viewport.scrollTop = 0;
  tooltip.offsetWidth = 150;
  tooltip.offsetHeight = 150;
  function matrix() {
    const result = [...painting()].reverse().find(op => op.kind === "rect" && op.x > 0
      && op.width === op.height && op.color === "#11161c");
    assert(result, "the CPU migration matrix is painted");
    return result;
  }
  function strip() {
    const label = [...painting()].reverse().find(op => op.kind === "text" && op.text === "Mem. BW");
    assert(label, "the memory bandwidth strip is painted");
    const box = painting().find(op => op.kind === "rect" && op.x === matrix().x
      && op.width === matrix().width && label.y >= op.y && label.y < op.y + op.height);
    assert(box, "the strip spans the matrix columns");
    return { ...box, centerY: label.y };
  }
  function pointer(column, y = strip().centerY) {
    const box = matrix();
    return { clientX: box.x + (column + 0.5) * box.width / topology.cpus.length, clientY: y };
  }
  return { operations, canvas, tooltip, matrix, strip,
    clear() { if (operations.length) retainedPainting = [...operations]; operations.length = 0; },
    hover(column) {
      canvas.dispatchEvent({ type: "pointermove", ...pointer(column) });
      assert.equal(tooltip.hidden, false, "the strip has a tooltip");
      return tooltip.textContent;
    },
    color(column) {
      const { clientX: x, clientY: y } = pointer(column);
      return [...painting()].reverse().find(op => op.kind === "rect"
        && x >= op.x && x < op.x + op.width && y >= op.y && y < op.y + op.height)?.color;
    },
    click(column, y) { canvas.dispatchEvent({ type: "click", ...pointer(column, y) }); },
  };
}

function renderer(source = bandwidth(), extra = {}) {
  let recording;
  const view = page("heatmap.js", async url => { throw new Error(`Unexpected heatmap fetch ${url}`); }, {
    preload: { "heatmap.js": context => { recording = canvasRecorder(context); } },
  });
  view.context.MitosisHeatmap.init({ topology });
  const snapshot = { ...counters(), topology, memory_bandwidth: source,
    memory_bandwidth_view_at_unix_ms: 10000, ...extra };
  function update(group = source, fields = {}) {
    recording.clear();
    view.context.MitosisHeatmap.update({ ...snapshot, memory_bandwidth: group, ...fields });
  }
  update();
  return { ...view, ...recording, update,
    order(mode) { recording.clear(); view.context.MitosisHeatmap.setOrderMode(mode); },
    scale(mode) { recording.clear(); view.context.MitosisHeatmap.setScale(mode); } };
}

test("the strip joins explicit sparse LLC IDs and displays producer bytes/s in decimal GB/s", () => {
  const view = renderer();
  assert.match(view.hover(0), /LLC 0/);
  assert.match(view.hover(0), /2(?:\.0+)? GB\/s/);
  assert.match(view.hover(2), /LLC 8/);
  assert.match(view.hover(2), /0(?:\.0+)? GB\/s/);
  assert.match(view.hover(4), /LLC 40/);
  assert.match(view.hover(4), /9(?:\.0+)? GB\/s/);
  view.update();
  assert.match(view.hover(0), /2(?:\.0+)? GB\/s/, "redrawing does not compute another counter delta");
});

test("redrawing changed measurements reuses the canvas until its pixel dimensions change", () => {
  const view = renderer();
  const assigned = [];
  for (const dimension of ["width", "height"]) {
    let current = view.canvas[dimension];
    Object.defineProperty(view.canvas, dimension, { configurable: true,
      get: () => current,
      set(value) { assigned.push([dimension, value]); current = value; },
    });
  }
  view.update(bandwidth([row(0, 5e9), row(8, 0), row(40, 9e9)]));
  assert.match(view.hover(0), /5(?:\.0+)? GB\/s/, "the reused canvas paints the new measurement");
  assert.deepEqual(assigned, [], "assigning an unchanged canvas dimension clears and reallocates it");
  view.context.devicePixelRatio = 2;
  view.update();
  assert.equal(assigned.length, 2, "both changed pixel dimensions are resized");
  assert.equal(assigned[0][0], "width");
  assert.equal(assigned[1][0], "height");
});

test("numeric ordering repeats an LLC reading across its CPU spans without multiplying the rate", () => {
  const view = renderer();
  view.order("numeric");
  for (const [column, llc, rate] of [[0, 8, 0], [1, 0, 2], [2, 40, 9], [3, 8, 0], [4, 0, 2]]) {
    assert.match(view.hover(column), new RegExp(`LLC ${llc}\\b`));
    assert.match(view.hover(column), new RegExp(`${rate}(?:\\.0+)? GB/s`));
  }
});

test("invalid rates remain unknown while a measured zero keeps its own color", async t => {
  for (const value of [null, -1, "1000000000", NaN, Infinity]) {
    await t.test(String(value), () => {
      const view = renderer(bandwidth([row(0, value), row(8, 0)]));
      assert.match(view.hover(0), /unknown|unavailable|not measured/i);
      assert.doesNotMatch(view.hover(0), /total[^\n]*0(?:\.0+)? GB\/s/i);
      assert.match(view.hover(2), /0(?:\.0+)? GB\/s/);
      assert.notEqual(view.color(0), view.color(2), "unknown is distinct from measured zero");
    });
  }
});

test("baseline, reset and failed total statuses cannot present a finite rate as a measurement", async t => {
  for (const status of ["baseline", "reset", "not_measured", "read_failed", null]) {
    await t.test(String(status), () => {
      const view = renderer(bandwidth([row(0, 2e9, { total_status: status }), row(8, 0)]));
      assert.match(view.hover(0), /unknown|unavailable|not measured/i);
      assert.doesNotMatch(view.hover(0), /2(?:\.0+)? GB\/s/);
      assert.notEqual(view.color(0), view.color(2));
    });
  }
});

test("partial monitoring preserves independently measured LLC totals and their capture and coverage", () => {
  const source = bandwidth([row(0, 2e9, { package: null, occupancy_status: "read_failed",
    error: "occupancy read failed" }), row(8, null, { total_status: "read_failed", total_measured_contributions: 1 })],
  { partial: true, error: "occupancy read failed", meta: meta(1, 0, 9000, "occupancy read failed"),
    summary: { mbm_total_bps: null, scope_note: "Root + all top-level control groups with mon_data" } });
  const view = renderer(source);
  const measured = view.hover(0);
  assert.match(measured, /2(?:\.0+)? GB\/s/);
  assert.match(measured, /captur/i);
  assert.match(measured, /09(?:[.:]|\b)/, "the original group capture is retained");
  assert.match(measured, /2\s*\/\s*2/);
  assert.match(measured, /measured/i);
  assert.match(measured, /top-level control groups/);
  assert.match(view.hover(2), /unknown|unavailable|not measured/i);
});

test("unmapped and duplicate LLC rows remain unknown instead of joining raw hardware domain IDs", () => {
  const view = renderer(bandwidth([row(null, 9e9, { domain_id: 0 }),
    row(8, 0), row(40, 2e9, { topology_available: false })]));
  assert.match(view.hover(0), /unknown|unavailable|not measured/i);
  assert.match(view.hover(4), /unknown|unavailable|not measured/i);
  view.update(bandwidth([row(0, 2e9), row(0, 3e9), row(8, 0)]));
  assert.match(view.hover(0), /unknown|unavailable|not measured/i);
  assert.match(view.hover(0), /duplicat|ambiguous/i);
});

test("unavailable groups and authoritative source errors clear previously painted rates", async t => {
  for (const change of [{ available: false, error: "resctrl is not mounted" },
    { error: "bandwidth read failed" }, { meta: meta(2, 0, 10000, "bandwidth read failed") }]) {
    await t.test(JSON.stringify(change), () => {
      const view = renderer();
      view.update(bandwidth(undefined, change));
      assert.match(view.hover(0), /unknown|unavailable|not measured/i);
      assert.doesNotMatch(view.hover(0), /2(?:\.0+)? GB\/s/);
    });
  }
  const view = renderer();
  view.update(bandwidth(), { memory_bandwidth_source_error: "Selected archive source failed" });
  assert.match(view.hover(0), /Selected archive source failed/);
  assert.doesNotMatch(view.hover(0), /2(?:\.0+)? GB\/s/);
});

test("a future or missing capture cannot appear at an earlier selected time", () => {
  const view = renderer(bandwidth(undefined, { meta: meta(2, 0, 11000) }));
  assert.match(view.hover(0), /unknown|unavailable|not measured/i);
  view.update(bandwidth(undefined, { meta: { ...meta(), captured_at_unix_ms: null } }));
  assert.match(view.hover(0), /unknown|unavailable|not measured/i);
  view.update(bandwidth(undefined, { meta: meta(3, 0, 10000) }));
  assert.match(view.hover(0), /2(?:\.0+)? GB\/s/);
});

test("unpublished or malformed metadata cannot turn a rate into a recorded measurement", async t => {
  for (const [name, fields] of [
    ["unpublished sequence", { sample_seq: 0 }],
    ["negative sequence", { sample_seq: -1 }],
    ["fractional sequence", { sample_seq: 1.5 }],
    ["string sequence", { sample_seq: "1" }],
    ["unsafe sequence", { sample_seq: Number.MAX_SAFE_INTEGER + 1 }],
    ["negative epoch", { epoch: -1 }],
    ["fractional epoch", { epoch: 0.5 }],
    ["missing epoch", { epoch: null }],
    ["string epoch", { epoch: "0" }],
    ["negative capture", { captured_at_unix_ms: -1 }],
    ["fractional capture", { captured_at_unix_ms: 1.5 }],
    ["out-of-range capture", { captured_at_unix_ms: Number.MAX_SAFE_INTEGER }],
  ]) {
    await t.test(name, () => {
      const view = renderer(bandwidth(undefined, { meta: { ...meta(1, 0, 10000), ...fields } }),
        { memory_bandwidth_view_at_unix_ms: null });
      assert.match(view.hover(0), /unknown|unavailable|not measured/i);
      assert.doesNotMatch(view.hover(0), /2(?:\.0+)? GB\/s/);
    });
  }
  assert.match(renderer(bandwidth(undefined, { meta: meta(1, 0, 10000) })).hover(0), /2(?:\.0+)? GB\/s/,
    "epoch zero belongs to host monitoring and is valid");
});

test("the strip sits under LLC utilization and matrix hover and click use the shifted origin", () => {
  const view = renderer();
  const llcLabel = view.operations.find(op => op.kind === "text" && op.text === "LLC util");
  assert(llcLabel.y < view.strip().y);
  assert(view.strip().y + view.strip().height < view.matrix().y);
  assert.match(view.canvas.getAttribute("aria-label"), /memory bandwidth/i);
  view.click(0, view.strip().centerY);
  assert.equal(view.element("#migrationPairInspection").children[1].children[1].textContent,
    "Click a matrix cell to keep its details here");
  const matrix = view.matrix();
  view.canvas.dispatchEvent({ type: "pointermove", clientX: matrix.x + matrix.width * 1.5 / 5,
    clientY: matrix.y + matrix.height * 0.5 / 5 });
  assert.match(view.tooltip.textContent, /CPU 1 -> CPU 4/);
  view.click(1, matrix.y + matrix.height * 0.5 / 5);
  assert.equal(view.element("#migrationPairInspection").children[1].children[1].textContent, "CPU 1 -> CPU 4");
});

test("the color scale normalizes GB/s against the largest measured LLC and follows the scale control", () => {
  const view = renderer(bandwidth([row(0, 1e9), row(8, 100e9), row(40, 10000e9, { total_status: "baseline" })]));
  assert(Number.parseInt(view.color(0).slice(1, 3), 16) < 128,
    "one GB/s stays visibly below 100 GB/s on the logarithmic scale");
  assert(Number.parseInt(view.color(2).slice(1, 3), 16) > 200,
    "the largest measured LLC sets the brightest color");
  assert.match(view.hover(0), /largest|highest|maximum/i);
  assert.match(view.hover(0), /100(?:\.0+)? GB\/s/);
  assert.match(view.hover(0), /log/i);
  const logarithmicColor = view.color(0);
  view.scale("linear");
  assert.notEqual(view.color(0), logarithmicColor);
  assert.match(view.hover(0), /linear/i);
});

function timelineRenderer(source = bandwidth()) {
  const explore = group => ({ meta: meta(1, 2, 20000), collector: collector(2, "waiting", "Scheduler is not attached"),
    groups: { bandwidth: group } });
  const probes = counters();
  probes.meta = meta(1, 1, 10000);
  let state = { mode: "history", selectedAt: 10000, oldestAt: 10000, latestAt: 20000,
    nowMs: 20000, loading: false, error: null, windowMs: 10000,
    view: timelineView({ counters: probes, explore: explore(source) }, { at: 10000, latestAt: 20000 }) };
  let subscriber;
  let recording;
  const calls = [];
  const timeline = { getState: () => state, subscribe(fn) { subscriber = fn; fn(state); return () => {}; },
    points: () => [], keys: () => [], isLive: () => state.mode === "live", refresh: async () => {}, setWindowMs() {} };
  const view = page("scheduling.js", async url => {
    calls.push(url);
    if (url === "/api/host-context") return response({ identity: { hostname: "fixture", kernel_release: "test", cpu_count: 5 }, topology });
    throw new Error(`Timeline scheduling page requested live source ${url}`);
  }, { now: 20000, globals: { MitosisTimeline: timeline },
    preload: { "scheduling.js": context => {
      recording = canvasRecorder(context);
      vm.runInContext(heatmapSource, context, { filename: "heatmap.js" });
    } },
  });
  return { ...view, ...recording, calls,
    setState(next) { recording.clear(); state = { ...state, ...next }; subscriber(state); },
    setSource(group, errors = {}, probesSource = probes, at = 10000) {
      this.setState({ view: timelineView({ counters: probesSource, explore: explore(group) },
        { at, latestAt: 20000, errors }) });
    } };
}

test("timeline selection owns bandwidth transport and rewinds the strip independently of scheduler probes", async () => {
  const view = timelineRenderer(bandwidth(undefined, { meta: meta(1, 0, 9000) }));
  await settle();
  assert.match(view.hover(0), /2(?:\.0+)? GB\/s/);
  assert.match(view.hover(0), /09(?:[.:]|\b)/);
  view.setState({ mode: "live", selectedAt: 20000 });
  view.setSource(bandwidth([row(0, 4e9), row(8, 0)], { meta: meta(2, 0, 19000) }), {}, null, 20000);
  assert.match(view.hover(0), /4(?:\.0+)? GB\/s/, "host bandwidth survives an absent scheduler probe snapshot");
  view.setState({ mode: "history", selectedAt: 10000 });
  view.setSource(bandwidth(undefined, { meta: meta(1, 0, 9000) }));
  assert.match(view.hover(0), /2(?:\.0+)? GB\/s/);
  assert.deepEqual(view.calls, ["/api/host-context"], "the scheduling page does not fetch live Explore while a timeline owns data");
});

test("live bandwidth uses its containing full view when the graph timeline trails that view", async () => {
  const view = timelineRenderer();
  await settle();
  view.setState({ mode: "live", latestAt: 10000, selectedAt: 10000 });
  view.setSource(bandwidth(undefined, { meta: meta(2, 0, 11100) }), {}, undefined, 11000);
  assert.match(view.hover(0), /unknown|unavailable|not measured/i,
    "a capture after the containing full view is still unavailable");
  const unknownColor = view.color(0);

  view.setSource(bandwidth(undefined, { meta: meta(3, 0, 10900) }), {}, undefined, 11000);
  assert.match(view.hover(0), /Monitored total: 2(?:\.0+)? GB\/s/,
    "a valid capture inside the full view is not cut off by an older graph frame");
  assert.match(view.hover(0), /Captured: 1970-01-01T00:00:10\.900Z/);
  assert.notEqual(view.color(0), unknownColor, "the valid rate paints a measured strip color");

  view.setSource(bandwidth(undefined, { meta: meta(4, 0, 11100) }), {}, undefined, 11000);
  assert.match(view.hover(0), /unknown|unavailable|not measured/i);
  assert.equal(view.color(0), unknownColor);
  assert.deepEqual(view.calls, ["/api/host-context"]);
});

test("historical bandwidth respects the selected time while graph bounds trail the full view", async () => {
  const view = timelineRenderer();
  await settle();
  view.setState({ mode: "history", latestAt: 10000, selectedAt: 10950 });
  view.setSource(bandwidth(undefined, { meta: meta(2, 0, 10900) }), {}, undefined, 11000);
  assert.match(view.hover(0), /Monitored total: 2(?:\.0+)? GB\/s/);
  view.setState({ selectedAt: 10800 });
  assert.match(view.hover(0), /unknown|unavailable|not measured/i,
    "a retained full view cannot show a capture beyond the historical slider selection");
});

test("selected transport warnings preserve bandwidth while source errors and future captures clear it", async () => {
  const view = timelineRenderer();
  await settle();
  view.setState({ error: "Timeline transport interrupted" });
  assert.match(view.hover(0), /2(?:\.0+)? GB\/s/);
  view.setSource(bandwidth(), { "explore.perf": "PMU archive failed" });
  assert.match(view.hover(0), /2(?:\.0+)? GB\/s/);
  for (const key of ["explore", "explore.bandwidth"]) {
    view.setSource(bandwidth(), { [key]: "Selected bandwidth archive failed" });
    assert.match(view.hover(0), /Selected bandwidth archive failed/);
    assert.doesNotMatch(view.hover(0), /2(?:\.0+)? GB\/s/);
  }
  view.setSource(bandwidth(undefined, { meta: meta(2, 0, 11000) }));
  assert.match(view.hover(0), /unknown|unavailable|not measured/i);
});
