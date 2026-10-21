"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { page, meta, collector, response, settle, timelineView } = require("./page_test_support");

const canvases = ["memoryBandwidthTotalHistory", "memoryBandwidthLlcHistory", "memoryCacheAccessTotalHistory",
  "memoryCacheAccessLlcHistory", "memoryCacheMissTotalHistory", "memoryCacheMissLlcHistory",
  "memoryCacheMissPercentTotalHistory", "memoryCacheMissPercentLlcHistory"];

function group(summary, rows, at = 10000) {
  return { available: true, error: null, partial: false, meta: meta(1, 0, at),
    scope: "Host monitoring counters", summary, rows };
}

function sample(at = 10000) {
  return { meta: meta(1, 1, at), collector: collector(), groups: {
    bandwidth: group({ source: "resctrl", monitor: "all_control_groups", interval_ms: 1000,
      mbm_total_bps: 2e9, mbm_local_bps: 7.5e8, scope_note: "Root and all top-level control groups",
      control_group_count: 2, control_group_names: ["root", "workload"], inventory_complete: true }, [
      { domain_id: "00", llc: 2, mbm_total_bps: 5e8, mbm_local_bps: 2e8, total_status: "measured", local_status: "measured" },
      { domain_id: "01", llc: 8, mbm_total_bps: 0, mbm_local_bps: 0, total_status: "measured", local_status: "measured" },
      { domain_id: "02", llc: 40, mbm_total_bps: 1.5e9, mbm_local_bps: 5.5e8, total_status: "measured", local_status: "measured" },
    ], at),
    perf: group({ interval_ms: 1000, cpu_count: 4, cache_sampled_cpus: 3,
      metric_cpu_counts: { cache_references: 4, cache_misses: 3 },
      cache_references_per_second: 1e8, cache_misses_per_second: 1.08e7, cache_miss_pct: 10.8,
      minimum_pmu_coverage_pct: 75, note: "Generic hardware cache events on each CPU",
      llcs: [
        { llc_id: 2, cpu_count: 1, cache_sampled_cpus: 1, cache_references_per_second: 1e6, cache_misses_per_second: 9e5, cache_miss_pct: 90 },
        { llc_id: 8, cpu_count: 1, cache_sampled_cpus: 0, cache_references_per_second: 0, cache_misses_per_second: 0, cache_miss_pct: null },
        { llc_id: 40, cpu_count: 2, cache_sampled_cpus: 2, cache_references_per_second: 9.9e7, cache_misses_per_second: 9.9e6, cache_miss_pct: 10 },
      ] }, [], at),
  } };
}

function signals(snapshot) {
  const values = {};
  for (const [key, group] of Object.entries(snapshot.groups)) {
    // Timeline points retain a null observation when the frame has no finite signal.
    for (const [field, value] of Object.entries(group.summary)) if (typeof value === "number" || value === null) values[`explore.${key}.${field}`] = value;
    const rows = key === "bandwidth" ? group.rows : group.summary.llcs;
    for (const item of rows) {
      const id = key === "bandwidth" ? item.llc : item.llc_id;
      for (const field of key === "bandwidth" ? ["mbm_total_bps", "mbm_local_bps"]
        : ["cache_references_per_second", "cache_misses_per_second", "cache_miss_pct"]) values[`explore.${key}.llc.${id}.${field}`] = item[field];
    }
  }
  return values;
}

function fixture(snapshot = sample(), options = {}) {
  let state = { mode: "history", selectedAt: 10000, oldestAt: 10000, latestAt: 20000,
    nowMs: 20000, frames: [], loading: false, error: null, windowMs: 10000,
    view: timelineView({ explore: snapshot }, { at: 10000, latestAt: 20000, oldestAt: 10000 }), ...options.state };
  let subscriber;
  const values = options.values || signals(snapshot);
  const data = Object.fromEntries(Object.entries(values).map(([key, value]) => [key, [{ x: 10000, y: value }]]));
  Object.assign(data, options.points || {});
  const calls = [];
  const draws = [];
  const timeline = { getState: () => state, subscribe(fn) { subscriber = fn; fn(state); return () => {}; },
    points: key => data[key] || [], keys: prefix => Object.keys(data).filter(key => key.startsWith(prefix)),
    isLive: () => state.mode === "live", refresh: async () => {} };
  const view = page("memory_charts.js", async url => { calls.push(url); return response(sample(20000)); }, {
    globals: { MitosisTimeline: timeline }, storage: options.storage, now: 20000,
    preload: { "memory_charts.js": context => {
      context.MitosisCharts.drawLineChart = (canvas, series, settings) => draws.push({ canvas, series, settings });
    } },
  });
  return { ...view, calls, draws, data, setState(next) { state = { ...state, ...next }; subscriber(state); },
    setSource(next) { state = { ...state, view: { ...state.view, sources: { explore: next } } }; subscriber(state); } };
}

function last(view, id) { return [...view.draws].reverse().find(draw => draw.canvas === view.element(`#${id}`)); }
function boxes(view) { return view.element("#memoryLlcSelection").children.filter(node => node.tagName === "LABEL").map(label => label.children[0]); }

test("System contains eight memory graphs after the memory table and loads the independent module", () => {
  const html = fs.readFileSync(path.join(__dirname, "../src/web/system.html"), "utf8");
  for (const id of [...canvases, "systemMemoryHistory", "memoryLlcSelection", "memoryLlcAll", "memoryLlcNone", "memoryBandwidthLlcMode"]) assert(html.includes(`id="${id}"`), id);
  assert(html.indexOf('id="systemMemoryHistory"') > html.indexOf('id="memoryRows"'));
  assert(html.indexOf('id="systemMemoryHistory"') < html.indexOf('id="explorePerf"'));
  assert(html.includes('/assets/memory_charts.js'));
  assert.match(html, /monitored|MBM/i);
  assert.match(html, /events\/s/);
});

test("aggregate curves use bytes to decimal GB/s and cache events to millions/s", () => {
  const view = fixture();
  for (const id of canvases) assert(last(view, id), `${id} renders`);
  const bandwidth = last(view, canvases[0]);
  assert.equal(bandwidth.settings.unit, "GB/s");
  assert.deepEqual(Array.from(bandwidth.series, item => item.points[0].y), [2, 0.75]);
  const access = last(view, canvases[2]);
  assert.equal(access.settings.unit, "M events/s");
  assert.equal(access.series[0].points[0].y, 100);
  const misses = last(view, canvases[4]);
  assert.equal(misses.settings.unit, "M events/s");
  assert.equal(misses.series[0].points[0].y, 10.8);
  assert.equal(view.calls.length, 0, "the timeline owns all transport on production pages");
});

test("aggregate miss percentage uses the producer weighted paired ratio, not LLC averages", () => {
  const view = fixture();
  const percent = last(view, canvases[6]);
  assert.equal(percent.settings.unit, "%");
  assert.equal(percent.series[0].points[0].y, 10.8);
  assert.match(view.element("#memoryCacheMissPercentTotalValue").textContent, /10\.8/);
  assert.notEqual(percent.series[0].points[0].y, 50);
});

test("LLC overlays and controls follow sparse explicit IDs in numeric order", () => {
  const view = fixture();
  assert.deepEqual(boxes(view).map(input => input.dataset.llc), ["2", "8", "40"]);
  assert(boxes(view).every(input => input.checked));
  const bandwidth = last(view, canvases[1]);
  assert.deepEqual(Array.from(bandwidth.series, item => item.label), ["LLC 2", "LLC 8", "LLC 40"]);
  assert.deepEqual(Array.from(bandwidth.series, item => item.points[0].y), [0.5, 0, 1.5]);
  const access = last(view, canvases[3]);
  assert.deepEqual(Array.from(access.series, item => item.points[0].y), [1, 0, 99]);
});

test("selecting local traffic changes the per-LLC plot without changing total/local aggregate curves", () => {
  const view = fixture();
  view.element("#memoryBandwidthLlcMode").value = "local";
  view.element("#memoryBandwidthLlcMode").dispatchEvent({ type: "change" });
  assert.deepEqual(Array.from(last(view, canvases[1]).series, item => item.points[0].y), [0.2, 0, 0.55]);
  assert.deepEqual(Array.from(last(view, canvases[0]).series, item => item.points[0].y), [2, 0.75]);
});

test("LLC selection survives refresh and navigation and keeps colors stable", () => {
  const storage = new Map();
  const view = fixture(sample(), { storage });
  const color = last(view, canvases[1]).series.find(item => item.label === "LLC 40").color;
  const first = boxes(view)[0];
  first.checked = false;
  first.dispatchEvent({ type: "change" });
  assert.deepEqual(Array.from(last(view, canvases[1]).series, item => item.label), ["LLC 8", "LLC 40"]);
  view.setSource(sample());
  assert.equal(boxes(view)[0], first, "refresh preserves the checkbox DOM and focus");
  assert.equal(first.checked, false);
  const reopened = fixture(sample(), { storage });
  assert.equal(boxes(reopened)[0].checked, false);
  assert.equal(last(reopened, canvases[1]).series.find(item => item.label === "LLC 40").color, color);
});

test("All and None affect only LLC overlays, with a clear empty selection state", () => {
  const view = fixture();
  view.element("#memoryLlcNone").click();
  assert.equal(last(view, canvases[1]).series.length, 0);
  assert.equal(last(view, canvases[0]).series[0].points[0].y, 2);
  assert.match(view.element("#memoryLlcSelectionStatus").textContent, /0|none|select.*LLC/i);
  view.element("#memoryLlcAll").click();
  assert.equal(last(view, canvases[1]).series.length, 3);
  assert(boxes(view).every(input => input.checked));
});

test("new LLCs are included by default All but stay unselected after None", () => {
  const view = fixture();
  const next = sample();
  next.groups.bandwidth.rows.push({ domain_id: "03", llc: 99, mbm_total_bps: 0, mbm_local_bps: 0 });
  view.setSource(next);
  assert.equal(boxes(view).find(input => input.dataset.llc === "99").checked, true);
  view.element("#memoryLlcNone").click();
  const newer = sample();
  newer.groups.bandwidth.rows.push({ domain_id: "04", llc: 100, mbm_total_bps: 0, mbm_local_bps: 0 });
  view.setSource(newer);
  assert.equal(boxes(view).find(input => input.dataset.llc === "100").checked, false);
});

test("historical graphs stop at the selected timestamp and retain gaps and epoch breaks", () => {
  const view = fixture(sample(), { points: { "explore.bandwidth.mbm_total_bps": [
    { x: 10000, y: 2e9 }, { x: 11000, y: null }, { x: 12000, y: 3e9, breakBefore: true }, { x: 20000, y: 9e9 },
  ] }, state: { selectedAt: 12000, view: timelineView({ explore: sample() }, { at: 12000 }) } });
  const chart = last(view, canvases[0]);
  assert.equal(chart.settings.maxX, 12000);
  assert.equal(chart.settings.maxGapMs, 3000);
  assert.deepEqual(Array.from(chart.series[0].points, point => point.y), [2, null, 3]);
  assert.equal(chart.series[0].points[2].breakBefore, true);
  assert.equal(view.calls.length, 0);
});

test("scrubbing rewinds current summaries and preserves the chosen LLCs", () => {
  const view = fixture();
  boxes(view)[0].checked = false;
  boxes(view)[0].dispatchEvent({ type: "change" });
  const next = sample();
  next.groups.bandwidth.summary.mbm_total_bps = 4e9;
  view.setSource(next);
  assert.match(view.element("#memoryBandwidthTotalValue").textContent, /4/);
  view.setSource(sample());
  assert.match(view.element("#memoryBandwidthTotalValue").textContent, /2/);
  assert.equal(boxes(view)[0].checked, false);
});

test("missing historical sources clear current summaries but preserve valid retained curves", () => {
  const view = fixture();
  view.setSource(null);
  assert.match(view.element("#memoryBandwidthTotalValue").textContent, /--|—/);
  assert.match(view.element("#memoryBandwidthSource").textContent, /recorded|retained|selected|unavailable/i);
  assert.equal(last(view, canvases[0]).series[0].points[0].y, 2);
  assert.equal(view.calls.length, 0);
});

test("unsupported source errors stay visible as text and do not affect other valid sources", () => {
  const next = sample();
  next.groups.bandwidth.available = false;
  next.groups.bandwidth.error = '<img src=x onerror="alert(1)"> resctrl is not mounted';
  const view = fixture(next);
  assert.match(view.element("#memoryBandwidthSource").textContent, /resctrl is not mounted/);
  assert.equal(view.element("#memoryBandwidthSource").children.length, 0);
  assert.match(view.element("#memoryBandwidthTotalValue").textContent, /--|—/);
  assert.match(view.element("#memoryCacheAccessTotalValue").textContent, /100/);
});

test("baseline nulls and zero denominators stay unavailable while measured zero remains zero", () => {
  const next = sample();
  next.groups.bandwidth.summary.mbm_total_bps = null;
  next.groups.bandwidth.summary.mbm_local_bps = null;
  next.groups.bandwidth.rows.forEach(row => { row.mbm_total_bps = null; row.mbm_local_bps = null; row.total_status = "baseline"; });
  next.groups.perf.summary.cache_references_per_second = 0;
  next.groups.perf.summary.cache_misses_per_second = 0;
  next.groups.perf.summary.cache_miss_pct = null;
  const view = fixture(next);
  assert.match(view.element("#memoryBandwidthTotalValue").textContent, /--|—/);
  assert.match(view.element("#memoryCacheAccessTotalValue").textContent, /0/);
  assert.match(view.element("#memoryCacheMissPercentTotalValue").textContent, /--|—/);
  assert.equal(last(view, canvases[2]).series[0].points[0].y, 0);
  assert.equal(last(view, canvases[6]).series[0].points[0].y, null);
});

test("an unavailable whole-host traffic total is not rebuilt from surviving valid LLCs", () => {
  const next = sample();
  next.groups.bandwidth.partial = true;
  next.groups.bandwidth.summary.mbm_total_bps = null;
  const view = fixture(next);
  assert.match(view.element("#memoryBandwidthTotalValue").textContent, /--|—/);
  assert.equal(last(view, canvases[0]).series[0].points[0].y, null);
  assert.equal(last(view, canvases[1]).series[0].points[0].y, 0.5);
});

test("source notes include capture time, monitor scope and cache pair coverage", () => {
  const view = fixture();
  assert.match(view.element("#memoryBandwidthSource").textContent, /captur/i);
  assert.match(view.element("#memoryBandwidthSource").textContent, /top-level control groups/i);
  assert.match(view.element("#memoryCacheSource").textContent, /3\s*\/\s*4/);
  assert.match(view.element("#memoryCacheSource").textContent, /pair|ratio|miss/i);
  assert.match(view.element("#memoryCacheSource").textContent, /75/);
});

test("transport warnings preserve selected values; genuine archive-source errors clear them", () => {
  const view = fixture();
  view.setState({ error: "History transport interrupted" });
  assert.match(view.element("#memoryBandwidthTotalValue").textContent, /2/);
  view.setState({ view: timelineView({ explore: sample() }, { at: 10000, errors: { explore: "Selected archive failed" } }) });
  assert.match(view.element("#memoryBandwidthTotalValue").textContent, /--|—/);
  assert.match(view.element("#memoryBandwidthSource").textContent, /Selected archive failed/);
  assert.equal(last(view, canvases[0]).series[0].points[0].y, 2);
});

test("a future wrapper or group cannot masquerade as an earlier selected measurement", () => {
  const next = sample(20000);
  const view = fixture(next);
  assert.match(view.element("#memoryBandwidthTotalValue").textContent, /--|—/);
  const partial = sample();
  partial.groups.perf.meta = meta(2, 0, 20000);
  view.setSource(partial);
  assert.match(view.element("#memoryCacheAccessTotalValue").textContent, /--|—/);
  assert.match(view.element("#memoryBandwidthTotalValue").textContent, /2/);
});

test("host monitoring sources remain valid when the Mitosis observer is waiting", () => {
  const next = sample();
  next.collector = collector(2, "waiting", "Scheduler is not attached");
  const view = fixture(next);
  assert.match(view.element("#memoryBandwidthTotalValue").textContent, /2/);
  assert.match(view.element("#memoryCacheAccessTotalValue").textContent, /100/);
});

test("unmapped or malicious LLC IDs are not turned into fabricated selectable LLCs", () => {
  const next = sample();
  next.groups.bandwidth.rows.push({ domain_id: "04", llc: null, mbm_total_bps: 1e9 });
  next.groups.perf.summary.llcs.push({ llc_id: '<script>alert(1)</script>', cache_miss_pct: 100 });
  const view = fixture(next);
  assert.deepEqual(boxes(view).map(input => input.dataset.llc), ["2", "8", "40"]);
});

test("per-group archive errors clear only the affected current values while history remains retained", () => {
  const view = fixture();
  view.setState({ view: timelineView({ explore: sample() }, { at: 10000,
    errors: { "explore.perf": "Selected PMU source failed" } }) });
  assert.match(view.element("#memoryCacheAccessTotalValue").textContent, /--|—/);
  assert.match(view.element("#memoryCacheSource").textContent, /Selected PMU source failed/);
  assert.match(view.element("#memoryBandwidthTotalValue").textContent, /2/);
  assert.equal(last(view, canvases[2]).series[0].points[0].y, 100);
});
