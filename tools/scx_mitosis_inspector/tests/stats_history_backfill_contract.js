"use strict";

const assert = require("node:assert/strict");
const { test } = require("node:test");
const { deferred, meta, stats, historySnapshot, response, page, settle } = require("./page_test_support");

function sample(sequence, captured = sequence * 1000, epoch = 1, cells = { 0: { num_cpus: 32, util_pct: 50 } }) {
  const snapshot = stats(sequence, epoch);
  snapshot.meta = meta(sequence, epoch, captured);
  snapshot.metrics.cells = cells;
  return snapshot;
}

function source(latest, retained) {
  return (url) => response(url.startsWith("/api/stats/history") ? retained : latest);
}

test("initial load includes retained one-second samples older than the latest freshness cutoff", async () => {
  const samples = Array.from({ length: 401 }, (_, index) => sample(index + 1, 1600000 + index * 1000));
  const view = page("stats.js", source(samples[400], historySnapshot(samples)));
  view.setNow(2000000);
  await settle();
  assert.equal(view.read("statsHistory.samples.length"), 401,
    "the chart must load server samples rather than a single browser poll");
  assert.equal(view.read("statsHistory.samples[0].x"), 1600000);
  assert.equal(view.read("statsHistory.samples[400].x"), 2000000);
  assert.equal(view.read('statsHistory.samples[0].values["cell.0.used_cpus"]'), 16);
  assert.match(view.element("#cellHistoryStatus").textContent, /30 minutes/);
  assert.match(view.element("#cellHistoryStatus").textContent, /6m 40s/);
});

test("returning to a visible tab backfills the entire background interval with no duplicated samples", async () => {
  const all = Array.from({ length: 303 }, (_, index) => sample(index + 1));
  let latest = all[2];
  let retained = historySnapshot(all.slice(0, 3));
  const requests = [];
  const view = page("stats.js", (url) => { requests.push(url); return source(latest, retained)(url); });
  view.setNow(3000);
  await settle();
  view.visibility("hidden");
  await settle();
  const before = requests.length;
  latest = all[302];
  retained = historySnapshot(all.slice(2), { reset: false });
  view.setNow(303000);
  view.visibility("visible");
  await settle();
  assert(requests.length > before, "visibilitychange must request an immediate catch-up");
  const query = new URL(requests.filter(url => url.startsWith("/api/stats/history")).slice(-1)[0], "http://inspector");
  assert.equal(query.searchParams.get("instance_id"), "inspector-1");
  assert.equal(query.searchParams.get("epoch"), "1");
  assert.equal(query.searchParams.get("after_seq"), "3");
  assert.equal(view.read("statsHistory.samples.length"), 303);
  assert.deepEqual(Array.from(view.read("statsHistory.samples"), entry => entry.x),
    all.map(entry => entry.meta.captured_at_unix_ms));
  await view.context.refresh();
  assert.equal(view.read("statsHistory.samples.length"), 303, "overlapping responses cannot duplicate history");
  retained = historySnapshot([], { reset: false, latest });
  view.emit("focus");
  await settle();
  const focused = new URL(requests.filter(url => url.startsWith("/api/stats/history")).slice(-1)[0], "http://inspector");
  assert.equal(focused.searchParams.get("after_seq"), "303");
});

test("a failed history request preserves its chart while latest scheduler cards keep advancing", async () => {
  let latest = sample(3);
  const retained = historySnapshot([sample(1), sample(2), latest]);
  let fail = false;
  const view = page("stats.js", (url) => url.startsWith("/api/stats/history") && fail
    ? Promise.reject(new Error("history connection interrupted")) : source(latest, retained)(url));
  view.setNow(3000);
  await settle();
  fail = true;
  latest = sample(4);
  latest.metrics.rebalance_count = 27;
  view.setNow(4000);
  await view.context.refresh();
  assert.equal(view.element("#reconfigurationCount").textContent, "27");
  assert.equal(view.element("#statusText").textContent, "Live");
  assert.equal(view.read("statsHistory.samples.length"), 3);
  assert.match(view.element("#cellHistoryStatus").textContent, /history connection interrupted/);
});

test("refresh keeps publishing latest cards while awaiting a history request already in flight", async () => {
  let latest = sample(1, 10000);
  const pendingHistory = deferred();
  let requests = 0;
  const view = page("stats.js", (url) => {
    if (url.startsWith("/api/stats/history")) { requests += 1; return pendingHistory.promise; }
    return response(latest);
  });
  await settle();
  latest = sample(2, 11000);
  latest.metrics.rebalance_count = 31;
  view.setNow(11000);
  let completed = false;
  const pending = view.context.refresh().then(() => { completed = true; });
  await settle();
  assert.equal(view.element("#reconfigurationCount").textContent, "31");
  assert.equal(requests, 1, "history polling remains single flight");
  assert.equal(completed, false, "awaiting refresh must also await the active history response");
  pendingHistory.resolve(response(historySnapshot([sample(1, 10000), latest])));
  await pending;
  assert.equal(view.read("statsHistory.samples.length"), 2);
});

test("late history responses cannot restore samples from before an acknowledged reset", async () => {
  let latest = sample(1, 10000);
  let retained = historySnapshot([latest]);
  const old = deferred();
  let delayed = false;
  let historySignal;
  const view = page("stats.js", (url, options) => {
    if (url.startsWith("/api/stats/history") && delayed) {
      historySignal = options.signal;
      return old.promise;
    }
    return source(latest, retained)(url);
  });
  await settle();
  delayed = true;
  const pending = view.context.refresh();
  view.emit("mitosis:stats-reset-start");
  assert(historySignal, "reset must invalidate an actual history request");
  assert(historySignal.aborted);
  latest = sample(2, 12000, 2);
  retained = historySnapshot([sample(1, 10000, 2), latest]);
  delayed = false;
  view.setNow(12000);
  view.emit("mitosis:stats-reset", { epoch: 2, sample_seq: 1, reset_at_unix_ms: 11000 });
  await settle();
  old.resolve(response(historySnapshot([sample(99, 13000)])));
  await pending;
  await settle();
  assert.equal(view.read("statsHistory.samples.length"), 1);
  assert.equal(view.read("statsHistory.samples[0].x"), 12000);
  assert.equal(view.read("pageState.state.epoch"), 2);
});

test("browser retention follows elapsed time and caps the chart at 1801 samples", async () => {
  const all = Array.from({ length: 1802 }, (_, index) => sample(index + 1, 199000 + index * 1000));
  let retained = historySnapshot(all);
  const view = page("stats.js", url => source(all[1801], retained)(url));
  view.setNow(2000000);
  await settle();
  assert.equal(view.read("statsHistory.samples.length"), 1801);
  assert.equal(view.read("statsHistory.samples[0].x"), 200000, "the retention boundary itself is included");
  retained = historySnapshot([], { reset: false, latest: all[1801] });
  view.setNow(2001000);
  await view.context.refresh();
  assert.equal(view.read("statsHistory.samples.length"), 1800,
    "retention must expire even when the server returns no new points");
});

test("expiring old points and appending a retained batch redraws each chart only once", async () => {
  let latest = sample(2, 2000000);
  let retained = historySnapshot([sample(1, 200000), latest]);
  const view = page("stats.js", url => source(latest, retained)(url));
  view.setNow(2000000);
  await settle();
  const charts = [];
  view.context.MitosisCharts.drawLineChart = (canvas, series, options) => charts.push({ canvas, series, options });
  latest = sample(3, 2001000);
  retained = historySnapshot([latest], { reset: false });
  view.setNow(2001000);
  await view.context.refresh();
  assert.equal(charts.length, 2, "expiry and the new batch must share one redraw");
  assert.deepEqual(Array.from(view.read("statsHistory.samples"), entry => entry.x), [2000000, 2001000]);
});

test("a restarted inspector at the same epoch clears the latest source sequence floor and rejects old in-flight bodies", async () => {
  let latest = sample(500, 10000);
  let retained = historySnapshot([latest], { instanceId: "old-inspector" });
  const old = deferred();
  let holdOneStatsRequest = false;
  let oldSignal;
  const view = page("stats.js", (url, options) => {
    if (url === "/api/stats" && holdOneStatsRequest) {
      holdOneStatsRequest = false;
      oldSignal = options.signal;
      return old.promise;
    }
    return source(latest, retained)(url);
  });
  await settle();
  holdOneStatsRequest = true;
  latest = sample(1, 11000, 1, { 0: { num_cpus: 6, util_pct: 75 } });
  retained = historySnapshot([latest], { instanceId: "new-inspector" });
  view.setNow(11000);
  const pending = view.context.refresh();
  await settle();
  old.resolve(response(sample(501, 12000)));
  await pending;
  assert(oldSignal.aborted, "an old-instance latest request must be invalidated");
  assert.equal(view.read("statsHistory.samples.length"), 1);
  assert.equal(view.read('statsHistory.samples[0].values["cell.0.assigned_cpus"]'), 6);
  assert.equal(view.read("pageState.state.sources.stats.sampleMeta.sample_seq"), 1);
  assert.equal(view.element("#statusText").textContent, "Live");
});

test("an inspector restart can also restart epoch numbering without retaining the previous scheduler", async () => {
  let latest = sample(50, 10000, 4);
  let retained = historySnapshot([latest], { instanceId: "old" });
  const view = page("stats.js", url => source(latest, retained)(url));
  await settle();
  latest = sample(1, 11000, 1);
  retained = historySnapshot([latest], { instanceId: "new" });
  view.setNow(11000);
  await view.context.refresh();
  assert.equal(view.read("pageState.state.epoch"), 1);
  assert.equal(view.read("pageState.state.sources.stats.sampleMeta.sample_seq"), 1);
  assert.equal(view.read("statsHistory.samples.length"), 1);
  assert.equal(view.read("statsHistory.samples[0].x"), 11000);
});

test("a newer epoch discovered before a changed inspector instance still catches up within one refresh", async () => {
  let latest = sample(50, 10000, 1);
  let retained = historySnapshot([latest], { instanceId: "old" });
  const view = page("stats.js", url => source(latest, retained)(url));
  await settle();
  latest = sample(1, 11000, 2);
  retained = historySnapshot([latest], { instanceId: "new" });
  view.setNow(11000);
  await view.context.refresh();
  assert.equal(view.read("pageState.state.sources.stats.sampleMeta?.sample_seq"), 1,
    "the current latest source must be refetched after both epoch and instance invalidations");
  assert.equal(view.element("#statusText").textContent, "Live");
  assert.equal(view.read("statsHistory.samples.length"), 1);
});

test("a history batch is ordered by sequence, deduplicated, and drawn once with explicit unavailable values", async () => {
  const first = sample(1, 1000, 1, { 0: { num_cpus: 4, util_pct: 150 } });
  const absent = sample(2, 2000, 1, { 0: { num_cpus: 4, util_pct: null } });
  const last = sample(3, 3000, 1, { 0: { num_cpus: 4, util_pct: 0 } });
  const view = page("stats.js", source(last, historySnapshot([last, first, absent, absent], { latest: last })));
  view.setNow(3000);
  const charts = [];
  view.context.MitosisCharts.drawLineChart = (canvas, series, options) => charts.push({ canvas, series, options });
  await settle();
  assert.equal(view.read("statsHistory.samples.length"), 3);
  assert.equal(charts.length, 2, "a retained batch redraws each chart once");
  assert.deepEqual(Array.from(charts[0].series[0].points, point => point.y), [150, null, 0]);
  assert.equal(charts[0].options.maxY, 150, "unavailable values cannot poison the scale or clip borrowing");
  assert.equal(charts[0].options.maxGapMs, 3000);
  assert.equal(charts[1].options.maxGapMs, 3000);
});

test("history request errors do not erase retained data after a failed reset", async () => {
  let latest = sample(1, 10000);
  let retained = historySnapshot([latest]);
  const view = page("stats.js", url => source(latest, retained)(url));
  await settle();
  view.setNow(11000);
  view.emit("mitosis:stats-reset-start");
  view.emit("mitosis:stats-reset-failed", { error: "reset queue full" });
  await settle();
  assert.equal(view.read("statsHistory.samples.length"), 1, "pre-failure history remains available");
  latest = sample(3, 12000);
  retained = historySnapshot([sample(1, 10000), sample(2, 10500), latest]);
  view.setNow(12000);
  await view.context.refresh();
  assert.deepEqual(Array.from(view.read("statsHistory.samples"), entry => entry.x), [10000, 12000],
    "a failed reset cannot append pre-failure points as fresh measurements");
});

test("a full history for many cells computes utilization bounds without argument-count limits", async () => {
  const cells = Object.fromEntries(Array.from({ length: 72 }, (_, cell) =>
    [cell, { num_cpus: 4, util_pct: cell === 71 ? 150 : 50 }]));
  const samples = Array.from({ length: 1801 }, (_, index) => sample(index + 1, 200000 + index * 1000, 1, cells));
  const view = page("stats.js", source(samples[1800], historySnapshot(samples)));
  view.setNow(2000000);
  const charts = [];
  view.context.MitosisCharts.drawLineChart = (canvas, series, options) => charts.push({ series, options });
  await settle();
  assert.equal(view.read("statsHistory.samples.length"), 1801);
  assert.equal(charts[0].series.length, 72);
  assert.equal(charts[0].options.maxY, 150);
  assert(!/unavailable/i.test(view.element("#cellHistoryStatus").textContent));
});
