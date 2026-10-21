"use strict";

const assert = require("node:assert/strict");
const { test } = require("node:test");
const { deferred, meta, collector, counters, migrations, stats, historySnapshot, statsResponse,
  system, response, page, settle, liveTimeline } = require("./page_test_support");

function sources() { return { counters: counters(), migrations: migrations(), stats: stats(), system: system() }; }

test("missing pairwise borrowing shows available cell totals without inventing zero flows", async () => {
  let snapshot = stats();
  snapshot.metrics.cells = {
    0: { demand_borrow_pct: 0, lent_pct: 1.25 },
    1: { demand_borrow_pct: 12.5, lent_pct: 0 },
    2: {},
  };
  const view = page("stats.js", (url) => statsResponse(snapshot, url));
  await settle();
  assert.equal(view.element("#borrowingHeading").textContent, "Cell borrowing totals");
  assert.match(view.element("#borrowingStatus").textContent, /pairwise flows unavailable/i);
  const totals = view.element("#borrowMatrixBody").children;
  assert.deepEqual(totals[0].children.map(cell => cell.textContent), ["Cell 0", "0%", "1.25%"]);
  assert.deepEqual(totals[1].children.map(cell => cell.textContent), ["Cell 1", "12.5%", "0%"]);
  assert.deepEqual(totals[2].children.map(cell => cell.textContent), ["Cell 2", "--", "--"]);
  assert.equal(view.element(".borrowing-edges").hidden, true);

  snapshot = { ...snapshot, meta: meta(2), metrics: { ...snapshot.metrics, borrow_flows: {} } };
  await view.context.refresh();
  assert.equal(view.element("#borrowingHeading").textContent, "Cell borrowing flows");
  assert.equal(view.element(".borrowing-edges").hidden, false);
  assert.equal(view.element("#borrowMatrixBody").children[0].children[2].textContent, "0%",
    "an explicitly empty flow map can establish zero borrowing");
  assert.match(view.element("#borrowFlowsBody").children[0].children[0].textContent, /No cross-cell borrowing/);

  snapshot = { ...snapshot, meta: meta(3), metrics: { ...snapshot.metrics, borrow_flows: null } };
  await view.context.refresh();
  assert.equal(view.element("#borrowingHeading").textContent, "Cell borrowing totals");
  assert.equal(view.element(".borrowing-edges").hidden, true);
  assert.equal(view.element("#borrowFlowsBody").children.length, 0, "old pairwise details are cleared");
});

test("reconfiguration count follows scheduler totals, including zero and missing metrics", async () => {
  let snapshot = stats();
  snapshot.metrics.rebalance_count = 1234;
  const view = page("stats.js", (url) => statsResponse(snapshot, url));
  await settle();
  assert.equal(view.element("#reconfigurationCount").textContent, "1,234");

  snapshot = stats(2);
  snapshot.metrics.rebalance_count = 0;
  await view.context.refresh();
  assert.equal(view.element("#reconfigurationCount").textContent, "0");

  snapshot = stats(3);
  await view.context.refresh();
  assert.equal(view.element("#reconfigurationCount").textContent, "--");
});

test("reconfiguration count marks cached totals and clears them across scheduler epochs", async () => {
  let snapshot = stats();
  snapshot.metrics.rebalance_count = 12;
  const view = page("stats.js", (url) => statsResponse(snapshot, url));
  await settle();

  view.setNow(18000);
  await view.context.refresh();
  assert.equal(view.element("#reconfigurationCount").textContent, "12 (last sample)");

  snapshot = stats(1, 2);
  snapshot.meta.captured_at_unix_ms = snapshot.meta.last_success_at_unix_ms = 18000;
  await view.context.refresh();
  assert.equal(view.element("#reconfigurationCount").textContent, "--");

  snapshot = stats(2, 2);
  snapshot.meta.captured_at_unix_ms = snapshot.meta.last_success_at_unix_ms = 18000;
  snapshot.metrics.rebalance_count = 0;
  await view.context.refresh();
  assert.equal(view.element("#reconfigurationCount").textContent, "0");
});

test("cell utilization prefers current interval values and preserves real zero and missing samples", async () => {
  const snapshot = stats();
  snapshot.metrics.cells = {
    0: { util_pct: 12.5, smoothed_util_pct: 0 },
    1: { util_pct: 0, smoothed_util_pct: 30 },
    2: { smoothed_util_pct: 22 },
    3: { util_pct: null, smoothed_util_pct: 15 },
    4: { util_pct: null, smoothed_util_pct: null },
  };
  const view = page("stats.js", (url) => statsResponse(snapshot, url));
  await settle();
  const values = view.read("statsHistory.samples[0].values");
  assert.equal(values["cell.0.util"], 12.5);
  assert.equal(values["cell.1.util"], 0, "a real zero is not replaced by smoothing");
  assert.equal(values["cell.2.util"], 22, "legacy stats can fall back to smoothing");
  assert.equal(values["cell.3.util"], 15);
  assert(!Object.hasOwn(values, "cell.4.util"), "missing values cannot create a fake zero");
});

test("cell utilization chart includes borrowed utilization peaks until they leave the history", async () => {
  let snapshot = stats();
  snapshot.metrics.cells = { 0: { util_pct: 50 }, 1: { util_pct: 20 } };
  const view = page("stats.js", (url) => statsResponse(snapshot, url));
  await settle();
  view.read("statsHistory.maxPoints = 2");

  const calls = [];
  const context = new Proxy({
    measureText(text) { return { width: String(text).length * 6 }; },
  }, {
    get(target, key) {
      return key in target ? target[key] : (...args) => calls.push([key, ...args]);
    },
  });
  const canvas = view.element("#cellUtilizationChart");
  canvas.getContext = () => context;
  canvas.getBoundingClientRect = () => ({ width: 320, height: 160 });

  function checkScale(maximum) {
    assert(calls.some(([method, text]) => method === "fillText" && text === `${maximum}%`),
      "the utilization axis must include the highest retained value and a 100% minimum");
    const points = calls.filter(([method]) => method === "arc");
    assert(points.length > 0);
    assert(points.every(([, x, y]) => y >= 12 && y <= 138),
      "all cell utilization points must remain inside the plot");
    calls.length = 0;
  }

  view.context.drawCellHistory();
  checkScale(100);
  snapshot = stats(2);
  snapshot.metrics.cells = { 0: { util_pct: 50 }, 1: { util_pct: 150 } };
  await view.context.refresh();
  checkScale(150);
  snapshot = stats(3);
  snapshot.metrics.cells = { 0: { util_pct: 50 }, 1: { util_pct: 20 } };
  await view.context.refresh();
  checkScale(150);
  snapshot = stats(4);
  snapshot.metrics.cells = { 0: { util_pct: 0 }, 1: { util_pct: 20 } };
  await view.context.refresh();
  checkScale(100);
});

test("cell CPU use and capacity share CPU units, follow allocation changes, and preserve missing measurements", async () => {
  let snapshot = stats();
  snapshot.metrics.cells = {
    0: { util_pct: 50, num_cpus: 4, smoothed_util_pct: 0 },
    1: { util_pct: 0, num_cpus: 8, smoothed_util_pct: 30 },
    2: { smoothed_util_pct: 22, num_cpus: 6 },
    3: { util_pct: 75 },
    4: { util_pct: 200, num_cpus: 4 },
  };
  const view = page("stats.js", (url) => statsResponse(snapshot, url));
  await settle();
  const values = view.read("statsHistory.samples[0].values");
  assert.equal(values["cell.0.used_cpus"], 2);
  assert.equal(values["cell.0.assigned_cpus"], 4);
  assert.equal(values["cell.1.used_cpus"], 0);
  assert.equal(values["cell.1.assigned_cpus"], 8);
  assert.equal(values["cell.2.assigned_cpus"], 6);
  assert(!Object.hasOwn(values, "cell.2.used_cpus"), "smoothing cannot stand in for executed CPU time");
  assert(!Object.hasOwn(values, "cell.3.used_cpus"), "unknown capacity cannot produce a CPU quantity");
  assert(!Object.hasOwn(values, "cell.3.assigned_cpus"));
  assert.equal(values["cell.4.used_cpus"], 8, "borrowing can allow use above assigned capacity");
  assert.equal(values["cell.4.assigned_cpus"], 4);
  snapshot = { ...snapshot, meta: meta(2), metrics: { cells: {
    0: { util_pct: 50, num_cpus: 2 },
  } } };
  await view.context.refresh();
  assert.deepEqual(Array.from(view.read('statsHistory.points("cell.0.assigned_cpus")'), (point) => point.y), [4, 2]);
  assert.deepEqual(Array.from(view.read('statsHistory.points("cell.0.used_cpus")'), (point) => point.y), [2, 1]);
});

test("source response bodies arriving after two seconds can still complete within five seconds", async () => {
  const body = deferred();
  let signal;
  const view = page("stats.js", (url, options) => {
    if (url.startsWith("/api/stats/history")) return {
      ok: true, status: 200, json: async () => historySnapshot([await body.promise]),
    };
    signal = options.signal;
    return { ok: true, status: 200, json: () => body.promise };
  });
  await settle();
  view.timeout(2000);
  await settle();
  assert(!signal.aborted, "two seconds is not the source deadline");
  const snapshot = stats();
  snapshot.meta.captured_at_unix_ms = snapshot.meta.last_success_at_unix_ms = 12000;
  view.setNow(13000);
  body.resolve(snapshot);
  await settle();
  assert.equal(view.read("statsHistory.samples.length"), 1);
  assert.equal(view.element("#statusText").textContent, "Live");
});

test("live migration samples disclose lost map updates without claiming collection failed", async () => {
  const current = sources();
  current.migrations.migration_map_failures = 7;
  current.migrations.migration_quality = "incomplete";
  const view = liveTimeline("scheduling.js", current);
  await view.ready();
  assert.equal(view.element("#migrationQuality").textContent,
    "Incomplete · 7 map updates lost · capacity 65,536");
  assert.equal(view.element("#statusText").textContent, "Live");
  await view.advance(8000);
  assert.equal(view.element("#migrationQuality").textContent,
    "Last sample: Incomplete · 7 map updates lost · capacity 65,536");
});

test("waiting migration metadata does not report complete coverage or a zero capacity", async () => {
  const current = sources();
  const view = liveTimeline("scheduling.js", current);
  await view.ready();
  assert.equal(view.element("#migrationQuality").textContent, "Complete · capacity 65,536");
  current.counters = counters(0, 2);
  current.migrations = migrations(0, 2);
  for (const snapshot of [current.counters, current.migrations]) {
    snapshot.meta.captured_at_unix_ms = null;
    snapshot.meta.last_success_at_unix_ms = null;
    snapshot.collector = collector(2, "waiting");
    snapshot.migration_map_capacity = 0;
    snapshot.migration_map_failures = 0;
    snapshot.migration_quality = "unavailable";
  }
  await view.advance();
  assert.equal(view.element("#migrationQuality").textContent, "Unavailable");
  assert(!view.element("#status").classList.contains("live"));
  const waiting = liveTimeline("scheduling.js", current);
  await waiting.ready();
  assert.equal(waiting.element("#migrationQuality").textContent, "Unavailable");
});

test("stats cached payloads retain tables without adding fresh measurements", async () => {
  let snapshot = stats();
  const view = page("stats.js", (url) => statsResponse(snapshot, url));
  await settle();
  assert.equal(view.read("statsHistory.samples.length"), 1);
  snapshot = { ...snapshot, error: "socket disconnected", meta: { ...snapshot.meta, error: "socket disconnected" } };
  await view.context.refresh();
  assert.equal(view.read("statsHistory.samples.length"), 1);
  assert.match(view.element("#statusText").textContent, /stale/i);
  assert.match(view.element("#sourceStatus").textContent, /socket disconnected/);
  assert.equal(view.read("statsHistory.samples[0].x"), 10000);
});

test("successful HTTP contact cannot keep a frozen source live", async () => {
  const snapshot = stats();
  const view = page("stats.js", (url) => statsResponse(snapshot, url));
  await settle();
  view.setNow(18000);
  await view.context.refresh();
  assert.match(view.element("#statusText").textContent, /stale/i);
  assert.match(view.element("#sourceStatus").textContent, /8s/);
  assert(!view.element("#status").classList.contains("live"));
  assert.equal(view.read("statsHistory.samples.length"), 1);
});

test("reset start pauses and invalidates pending polls; acknowledgement fences old samples", async () => {
  let snapshot = stats();
  const old = deferred();
  let delayed = false;
  let requests = 0;
  const view = page("stats.js", (url) => {
    if (url.startsWith("/api/stats/history")) return statsResponse(snapshot, url);
    requests += 1;
    return delayed ? old.promise : response(snapshot);
  });
  await settle();
  delayed = true;
  const pending = view.context.refresh();
  view.emit("mitosis:stats-reset-start");
  view.tick();
  assert.equal(requests, 2, "polling pauses while reset is pending");
  old.resolve(response(stats(9)));
  await pending;
  assert.equal(view.read("statsHistory.samples.length"), 1);
  delayed = false;
  snapshot = stats(1, 2);
  view.emit("mitosis:stats-reset", { epoch: 2, sample_seq: 1, reset_at_unix_ms: 11000 });
  await settle();
  assert.equal(view.read("statsHistory.samples.length"), 0, "pre-boundary stats cannot begin the new history");
  snapshot.meta.captured_at_unix_ms = 12000;
  snapshot.meta.last_success_at_unix_ms = 12000;
  snapshot.meta.sample_seq = 2;
  await view.context.refresh();
  assert.equal(view.read("statsHistory.samples.length"), 1);
});

test("reset failure retains historical data as stale and resumes polling", async () => {
  const snapshot = stats();
  const view = page("stats.js", (url) => statsResponse(snapshot, url));
  await settle();
  view.emit("mitosis:stats-reset-start");
  view.emit("mitosis:stats-reset-failed", { error: "reattach failed" });
  await settle();
  assert.equal(view.read("statsHistory.samples.length"), 1);
  assert.match(view.element("#sourceStatus").textContent, /reattach failed/);
  assert(!view.element("#status").classList.contains("live"));
});

test("a same-epoch source recovers after reset failure only from a sample collected after the failure", async () => {
  let snapshot = stats();
  const view = page("stats.js", (url) => statsResponse(snapshot, url));
  await settle();
  view.setNow(11000);
  view.emit("mitosis:stats-reset-start");
  view.emit("mitosis:stats-reset-failed", { error: "reset queue full" });
  await settle();
  snapshot = stats(2);
  snapshot.meta.captured_at_unix_ms = snapshot.meta.last_success_at_unix_ms = 10500;
  await view.context.refresh();
  assert.equal(view.read("statsHistory.samples.length"), 1);
  assert.match(view.element("#sourceStatus").textContent, /reset queue full/);
  snapshot = stats(3);
  snapshot.meta.captured_at_unix_ms = snapshot.meta.last_success_at_unix_ms = 12000;
  view.setNow(12000);
  await view.context.refresh();
  assert.equal(view.read("statsHistory.samples.length"), 2);
  assert.equal(view.read("statsHistory.samples[1].x"), 12000);
  assert.equal(view.element("#statusText").textContent, "Live");
  assert(!view.element("#sourceStatus").textContent.includes("reset queue full"));
});
