"use strict";

const { test } = require("node:test");
const assert = require("node:assert/strict");
const { counters, migrations, system, stats, meta, collector, liveTimeline, settle } = require("./page_test_support");

const preferenceKey = "mitosis-explore-sections-v2";

function exploreSnapshot() {
  const group = available => ({ available, partial: false, error: available ? null : "Fixture source unavailable",
    meta: meta(), scope: "Whole host", rows: [], summary: { interval_ms: 1000, sample_rate: 64 } });
  const groups = Object.fromEntries([
    "dsqs", "tasks", "perf", "bandwidth", "wakers", "scx_events", "ipis", "idle", "pressure", "thermal", "power",
  ].map(name => [name, group(["dsqs", "tasks", "perf", "bandwidth"].includes(name))]));
  const latency = { samples: 3, mean_us: 0.004, p50_us: 0.003, p95_us: null, p99_us: null,
    max_us: 0.006, buckets: [0, 2, 1], bucket_scale: "log2", bucket_unit: "ns" };
  groups.dsqs.rows = [{ dsq_id: "31", dsq_hex: "0x1f", insert_events: 7, move_events: 0,
    residence_samples: 3, latency, run: latency, depth: { samples: 3, mean: 1, last: 1, max: 2 } }];
  Object.assign(groups.dsqs.summary, { latency_mean_us: 0.004, latency_p95_us: null, running_mean_us: 0.004 });
  groups.perf.rows = [{ cpu: 0, llc_id: 0, available: true, partial: false, error: null,
    interval_ms: 1000, instructions_per_second: 1000, cycles_per_second: 500, ipc: 2,
    cache_references_per_second: 10, cache_misses_per_second: 1, cache_miss_pct: 10,
    stalled_frontend_cycles_per_second: null, stalled_backend_cycles_per_second: null,
    metrics: {} }];
  Object.assign(groups.perf.summary, { ipc: 2, instructions_per_second: 1000, cycles_per_second: 500 });
  return { meta: meta(), collector: collector(), groups };
}

const workspaces = [
  { script: "scheduling.js", path: "/scheduling", hash: "#exploreDsqs", details: "#exploreDsqsDetails",
    other: "#exploreTasksDetails", preference: "Dsqs", plot: "exploreDsqHistory" },
  { script: "system.js", path: "/system", hash: "#explorePerf", details: "#explorePerfDetails",
    other: "#exploreBandwidthDetails", preference: "Perf", plot: "explorePerfHistory" },
];

async function workspace(spec, { hash = "", readyState = "complete" } = {}) {
  const current = { counters: counters(41), migrations: migrations(), system: system(), stats: stats(),
    explore: exploreSnapshot() };
  const storage = new Map([[preferenceKey, JSON.stringify({ Dsqs: { open: false }, Tasks: { open: false },
    Perf: { open: false }, Bandwidth: { open: false } })]]);
  const draws = [];
  const after = spec.script === "system.js" ? ["memory_charts.js", "explore.js"]
    : spec.script === "scheduling.js" ? ["explore.js"] : [];
  const view = liveTimeline(spec.script, current, {
    storage, location: `http://inspector.test:44103${spec.path}${hash}`,
    navigation: { readyState }, after,
    signals: { "explore.dsqs.latency_mean_us": 0.004, "explore.dsqs.running_mean_us": 0.004,
      "explore.perf.ipc": 2 },
    preload: { [spec.script]: context => {
      const record = type => (canvas, series) => {
        if (canvas) draws.push({ type, target: canvas.id, mainOpen: canvas.closest("details")?.open, series });
      };
      context.MitosisCharts.drawLineChart = record("line");
      context.MitosisCharts.drawHistogramSeries = record("histogram");
    } },
  });
  await view.ready();
  view.navigation.flushToggles();
  return Object.assign(view, { draws });
}

test("same-hash sidebar clicks reveal main details and keep timeline selection and unrelated preferences", async (t) => {
  for (const spec of workspaces) {
    await t.test(spec.path, async () => {
      const view = await workspace(spec, { hash: spec.hash });
      view.context.MitosisTimeline.setAt(10000);
      await view.ready();
      const details = view.navigation.target(spec.details);
      details.open = false;
      view.navigation.flushToggles();
      const retained = view.context.MitosisTimeline.getState().view;
      const requests = view.calls.length;
      const drawn = view.draws.length;
      const link = view.navigation.link(spec.hash);
      assert.ok(link, "the real page HTML must expose the sidebar target");

      link.click();

      assert.equal(details.open, true, "sidebar navigation must reveal a closed section even when its hash is already selected");
      view.navigation.flushToggles();
      await settle();
      assert.equal(JSON.parse(view.storage.get(preferenceKey))[spec.preference].open, true);
      assert.equal(view.navigation.target(spec.other).open, false);
      assert.ok(view.draws.slice(drawn).some(draw => draw.target === spec.plot && draw.mainOpen === true),
        "the native toggle callback redraws the revealed plot after opening");
      const selected = view.context.MitosisTimeline.getState();
      assert.equal(selected.mode, "history");
      assert.equal(selected.selectedAt, 10000);
      assert.equal(selected.view, retained);
      assert.equal(selected.view.sources.counters.counters[0].count, 41);
      assert.equal(view.calls.length, requests, "section navigation must not start new data requests");
      link.click();
      assert.equal(details.open, true, "repeated navigation opens instead of toggling the section closed");
    });
  }
});

test("initial hash reveals queue details after Explore restores closed preferences", async (t) => {
  for (const spec of workspaces) for (const readyState of ["loading", "interactive"]) {
    await t.test(`${spec.path} ${readyState}`, async () => {
      const view = await workspace(spec, { hash: spec.hash, readyState });
      const details = view.navigation.target(spec.details);
      assert.equal(details.open, false, "Explore has restored the saved closed preference before DOMContentLoaded");

      view.navigation.contentLoaded();

      assert.equal(details.open, true, "initial fragment reveal must run after all deferred page scripts and preference restoration");
      assert.equal(view.navigation.scrolls.length, 0, "initial scrolling waits for layout in the next frame");
      view.navigation.flushFrames();
      assert.equal(view.navigation.scrolls.length, 1);
      assert.equal(view.navigation.scrolls[0].target, spec.hash.slice(1));
      assert.equal(view.navigation.scrolls[0].mainOpen, true);
    });
  }
});

test("changed hashes reveal Scheduling and System details without reopening other sections", async (t) => {
  for (const spec of workspaces) {
    await t.test(spec.path, async () => {
      const view = await workspace(spec);
      const details = view.navigation.target(spec.details);
      assert.equal(details.open, false);
      view.navigation.setHash(spec.hash);
      assert.equal(details.open, true);
      assert.equal(view.navigation.target(spec.other).open, false);
      view.navigation.flushToggles();
      assert.equal(JSON.parse(view.storage.get(preferenceKey))[spec.preference].open, true);
    });
  }
});

test("modified sidebar clicks remain native and leave collapsed preferences alone", async (t) => {
  const view = await workspace(workspaces[0]);
  const link = view.navigation.link("#exploreDsqs");
  for (const modifiers of [{ ctrlKey: true }, { metaKey: true }, { shiftKey: true }, { altKey: true }, { button: 1 }]) {
    await t.test(JSON.stringify(modifiers), () => {
      const event = link.click(modifiers);
      assert.equal(event.defaultPrevented, false);
      assert.equal(view.context.location.hash, "");
      assert.equal(view.navigation.target("#exploreDsqsDetails").open, false);
      assert.equal(JSON.parse(view.storage.get(preferenceKey)).Dsqs.open, false);
    });
  }
});

test("callback section navigation does not open its nested metric picker", async () => {
  const view = await workspace({ script: "callbacks.js", path: "/callbacks" });
  const picker = view.navigation.target("#callbackLatencyMetric");
  assert.equal(picker.open, false);
  view.navigation.link("#callback-latency").click();
  assert.equal(picker.open, false, "only direct main details are revealed, not nested controls");
  assert.equal(view.context.location.hash, "#callback-latency");
  assert.equal(view.navigation.target("[data-callback='select_cpu'] .count").textContent, "41");
});

test("legacy callback history resolves inside the canonical rate section without rewriting its hash", async () => {
  const view = await workspace({ script: "callbacks.js", path: "/callbacks" }, { hash: "#live-history" });
  view.context.MitosisTimeline.setAt(10000);
  await view.ready();
  const retained = view.context.MitosisTimeline.getState().view;
  const legacy = view.navigation.target("#live-history");
  const canonical = view.navigation.target("#callback-rate");
  assert.ok(legacy, "the real callback HTML must contain the legacy fragment target");
  assert.equal(view.context.document.querySelectorAll("#live-history").length, 1, "the legacy fragment has a unique real target");
  assert.equal(legacy.closest("#callback-rate"), canonical);
  assert.equal(view.context.location.hash, "#live-history");
  assert.equal(view.navigation.replacements.length, 0);
  assert.equal(view.navigation.target("#callbackRateHistoryChart").closest("#callback-rate"), canonical);
  view.navigation.link("#callback-rate").click();
  assert.equal(view.context.location.hash, "#callback-rate");
  assert.equal(view.navigation.target(view.context.location.hash), canonical);
  assert.equal(view.navigation.target("[data-callback='select_cpu'] .count").textContent, "41");
  assert.equal(view.context.MitosisTimeline.getState().mode, "history");
  assert.equal(view.context.MitosisTimeline.getState().selectedAt, 10000);
  assert.equal(view.context.MitosisTimeline.getState().view, retained);
});

test("a hash change cancels scrolling to the stale initial section", async () => {
  const view = await workspace(workspaces[0], { hash: "#exploreDsqs", readyState: "loading" });
  view.navigation.contentLoaded();
  assert.equal(view.navigation.target("#exploreDsqsDetails").open, true);
  assert.ok(view.navigation.pendingFrames > 0, "initial reveal queues scrolling after layout");
  view.navigation.setHash("#exploreTasks");
  assert.equal(view.navigation.target("#exploreTasksDetails").open, true);
  view.navigation.flushFrames();
  assert.ok(view.navigation.scrolls.every(scroll => scroll.target !== "exploreDsqs"),
    "a queued initial frame cannot scroll back after a newer fragment selection");
  assert.equal(view.context.location.hash, "#exploreTasks");
});
