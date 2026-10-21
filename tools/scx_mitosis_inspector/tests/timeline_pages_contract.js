"use strict";

const assert = require("node:assert/strict");
const { test } = require("node:test");
const { counters, migrations, stats, system, meta, response, page, settle, deferred,
  timelineFrame, timelineArchive, timelineView } = require("./page_test_support");

function configuration(sequence) {
  return { available: true, error: null, pid: sequence, version: `version-${sequence}`,
    executable: "/root/scx_mitosis", command_line: ["/root/scx_mitosis", "--cell0-min-cpus", String(sequence)],
    options: [{ status: "explicit", name: "--cell0-min-cpus", current_value: String(sequence),
      default: "2", group: "placement", description: "Root cell minimum", possible_values: [] }] };
}

function snapshots(sequence, at) {
  const probes = counters(sequence);
  probes.meta = meta(sequence, 1, at);
  probes.counters[0].count = sequence * 100;
  probes.counters[0].rate_per_second = sequence * 10;
  probes.callback_timings = [{ callback: "enqueue", samples: sequence, mean_ns: sequence * 1000,
    p50_ns: sequence * 1000, p95_ns: sequence * 1000, p99_ns: sequence * 1000,
    buckets: [0, sequence * 7] }];
  probes.scheduler_timings = [{ metric: "wakeup_to_running", samples: sequence,
    mean_ns: sequence * 1000, p95_ns: sequence * 1000, buckets: [0, sequence] }];
  probes.cpu_runtime = [{ cpu: 0, utilization_pct: sequence * 10 }];
  probes.interrupt_cpu = [{ cpu: 0, total_utilization_pct: sequence }];
  probes.block_io = { ...probes.block_io, available: true, completion_rate_per_second: sequence * 3,
    completed_bytes_per_second: sequence * 1024 * 1024, latency_buckets: [0, sequence * 5] };
  probes.dsq_metrics = { ...probes.dsq_metrics, available: true,
    depth_average: sequence, depth_latest_max: sequence * 2, residence_buckets: [0, sequence * 4] };
  const host = system(sequence);
  host.meta = meta(sequence, 1, at);
  host.cpu.value.busy_pct = sequence * 25;
  host.pressure.cpu = { available: true, value: { some: { avg10: sequence } } };
  host.frequencies.value.average_khz = sequence * 1000000;
  const scheduler = stats(sequence);
  scheduler.meta = meta(sequence, 1, at);
  scheduler.metrics.util_pct = sequence * 20;
  return { counters: probes, system: host, stats: scheduler, config: configuration(sequence) };
}

function fixture({ sources = [snapshots(1, 10000), snapshots(2, 20000)], storage, late,
    migrationRows } = {}) {
  const calls = [];
  const network = { frameError: null };
  const frames = sources.map((source, index) => timelineFrame(index + 1,
    source.system.meta.captured_at_unix_ms, {
      "callbacks.callbacks": source.counters.counters.reduce((total, counter) => total + counter.rate_per_second, 0),
      "callbacks.task_cpu": (index + 1) * 9,
      "system.cpu": index + 1,
      "system.mhz": (index + 1) * 1000,
      "system.total": index + 1,
      "system.completions": (index + 1) * 3,
      "system.mib": index + 1,
      "migration.same_llc": (index + 1) * 25,
    }, Object.fromEntries(["counters", "stats", "system"].map(name => [name, source[name].meta.epoch]))));
  let latestAt = frames.at(-1).at_unix_ms;
  const fetcher = async (url) => {
    latestAt = frames.at(-1).at_unix_ms;
    calls.push(url);
    const request = new URL(url, "http://inspector.test:44103");
    if (request.pathname === "/api/timeline") {
      if (network.frameError) throw new Error(network.frameError);
      const after = Number(request.searchParams.get("after_seq") || 0);
      return response(timelineArchive(frames.filter(frame => frame.seq > after),
        { now: latestAt, reset: !after, oldestAt: frames[0].at_unix_ms,
          latestAt, sequence: frames.at(-1).seq,
          windowMs: Number(request.searchParams.get("window_ms") || 10000) }));
    }
    if (request.pathname === "/api/timeline/view") {
      const at = Number(request.searchParams.get("at_unix_ms") || latestAt);
      if (late && at === late.at) return late.request.promise;
      let index = 0;
      frames.forEach((frame, candidate) => { if (frame.at_unix_ms <= at) index = candidate; });
      const source = sources[index];
      const window = Number(request.searchParams.get("window_ms") || 10000);
      const epoch = source.counters?.meta?.epoch ?? 1;
      const migration = migrations(index + 1, epoch, window);
      migration.meta = meta(index + 1, epoch, frames[index].at_unix_ms);
      migration.rows[0].count = window / 1000 * (index + 1);
      if (migrationRows) migration.rows = migrationRows;
      return response(timelineView(source, { at: frames[index].at_unix_ms, requestedAt: at,
        oldestAt: frames[0].at_unix_ms, latestAt, now: latestAt, migration,
        observer: source.counters?.collector }));
    }
    if (request.pathname === "/api/host-context") return response({
      identity: { hostname: "test-host", kernel_release: "test-kernel", cpu_count: 2 },
      topology: { cpus: [{ cpu: 0, package: 0, core: 0, llc: 0, node: 0 },
        { cpu: 1, package: 0, core: 1, llc: 0, node: 0 }],
        topology_order: [0, 1], numeric_order: [0, 1],
        llc_groups: [{ llc: 0, node: 0, cpus: [0, 1] }] },
    });
    // Retain real live fixtures to prove a page does not silently fall back to them.
    if (request.pathname === "/api/counters") return response(sources.at(-1).counters);
    if (request.pathname === "/api/system") return response(sources.at(-1).system);
    if (request.pathname === "/api/stats") return response(sources.at(-1).stats);
    if (request.pathname === "/api/config") return response(sources.at(-1).config);
    if (request.pathname === "/api/migrations") return response(migrations(2));
    throw new Error("Unexpected timeline page source " + url);
  };
  return { calls, sources, frames, fetcher, network,
    open(filename, options = {}) { return page(filename, fetcher,
      { timeline: true, now: latestAt, storage, ...options }); } };
}

function last(items, predicate) { return [...items].reverse().find(predicate); }

async function ready(view) {
  await settle();
  view?.timeout(75);
  await settle();
  view?.timeout(75);
  await settle();
}

test("busiest migration pairs rank all retained rows by count before limiting the table", async () => {
  const rows = [...Array.from({ length: 32 }, (_, cpu) => ({ from_cpu: 0, to_cpu: cpu, count: 1 })),
    { from_cpu: 112, to_cpu: 16, count: 9 },
    { from_cpu: 2, to_cpu: 112, count: 9 },
    { from_cpu: 2, to_cpu: 16, count: 9 },
    { from_cpu: 158, to_cpu: 159, count: 439 }];
  const originalOrder = rows.map(row => [row.from_cpu, row.to_cpu, row.count]);
  const data = fixture({ migrationRows: rows });
  const view = data.open("scheduling.js");
  await ready(view);
  const displayed = view.element("#migrationRows").children
    .map(row => row.children.map(cell => cell.textContent));
  assert.equal(displayed.length, 32);
  assert.deepEqual(displayed.slice(0, 4), [
    ["158", "159", "439"], ["2", "16", "9"], ["2", "112", "9"], ["112", "16", "9"],
  ]);
  assert.deepEqual(displayed.at(-1), ["0", "27", "1"]);
  assert.deepEqual(rows.map(row => [row.from_cpu, row.to_cpu, row.count]), originalOrder,
    "ranking cannot mutate the retained source snapshot");
});

test("light history and loading notifications preserve the displayed probe rows until a new view arrives", async (t) => {
  for (const [filename, ids] of [["callbacks.js", ["#callbackTimingRows"]],
    ["scheduling.js", ["#schedulerTimingRows", "#migrationRows"]]]) {
    await t.test(filename, async () => {
      const slow = deferred();
      const data = fixture({ late: { at: 30000, request: slow } });
      const view = data.open(filename);
      await ready(view);
      const rows = ids.map(id => view.element(id).children[0]);
      data.sources.push(snapshots(3, 30000));
      data.frames.push(timelineFrame(3, 30000, { "callbacks.callbacks": 30 }));
      view.setNow(30000);
      const pending = view.context.MitosisTimeline.refresh();
      await settle();
      ids.forEach((id, index) => assert.equal(view.element(id).children[0], rows[index],
        `a light frame cannot rebuild the unchanged ${id}`));
      assert.equal(view.context.MitosisTimeline.points("callbacks.callbacks").at(-1).y, 30,
        "history still advances before the full view completes");
      const migration = migrations(3);
      migration.meta = meta(3, 1, 30000);
      slow.resolve(response(timelineView(data.sources[2], { at: 30000, oldestAt: 10000,
        latestAt: 30000, now: 30000, migration })));
      await pending;
      await ready(view);
      assert.notEqual(view.element(ids[0]).children[0], rows[0], "new probe data replaces the displayed rows");
      if (filename === "callbacks.js") assert.equal(view.element("card").querySelector(".count").textContent, "300");
    });
  }
});

test("a failed reset preserves the archive and a fresh view restores live status with the failure still visible", async () => {
  const data = fixture({ sources: [snapshots(1, 10000)] });
  const view = data.open("callbacks.js");
  await ready(view);
  const retained = view.context.MitosisTimeline.getState().frames[0];
  view.emit("mitosis:stats-reset-start");
  data.sources.push(snapshots(2, 12000));
  data.frames.push(timelineFrame(2, 12000, { "callbacks.callbacks": 20 }));
  view.setNow(12000);
  view.emit("mitosis:stats-reset-failed", { error: "reset queue full" });
  await view.context.MitosisTimeline.refresh();
  await ready(view);
  const state = view.context.MitosisTimeline.getState();
  assert.equal(state.frames.length, 2);
  assert.equal(state.frames[0], retained);
  assert.equal(view.element("card").querySelector(".count").textContent, "200");
  assert.equal(view.element("#statusText").textContent, "Live");
  assert.equal(state.error, null);
  assert.match(view.element("#timelineStatus").textContent, /reset.*failed.*reset queue full/i);
});

test("selected source subscription drives every page without starting its live pollers", async (t) => {
  for (const filename of ["callbacks.js", "scheduling.js", "system.js", "config.js", "inspector.js"]) {
    await t.test(filename, async () => {
      const data = fixture();
      const selected = timelineView(data.sources[0], { at: 10000, oldestAt: 10000,
        latestAt: 20000, now: 20000, migration: migrations(1) });
      const state = { mode: "history", selectedAt: 10000, nowMs: 20000, oldestAt: 10000,
        latestAt: 20000, instanceId: "inspector-1", frames: data.frames,
        view: selected, loading: false, error: null, notice: null, windowMs: 10000 };
      const timeline = { getState: () => state, subscribe(fn) { fn(state); return () => {}; },
        points: key => [{ x: 10000, y: data.frames[0].signals[key] ?? null }],
        keys: () => [], refresh: async () => {}, isLive: () => false,
        setAt() {}, goLive() {}, setWindowMs() {} };
      const view = page(filename, data.fetcher, { now: 20000, globals: { MitosisTimeline: timeline } });
      await ready(view);
      if (filename === "callbacks.js") assert.equal(view.element("card").querySelector(".count").textContent, "100");
      if (filename === "scheduling.js") assert.equal(view.element("#migrationRows").children[0].children[2].textContent, "1");
      if (filename === "system.js") assert.equal(view.element("#systemCpuRows").children[0].children[1].textContent, "25%");
      if (filename === "config.js") assert.equal(view.element("#configurationVersion").textContent, "version-1");
      if (filename === "inspector.js") assert.equal(view.element("#systemCpuUtilization").textContent, "25%");
      assert.equal(data.calls.some(url => /^\/api\/(counters|stats|system|migrations|config)(?:\?|$)/.test(url)), false,
        "a displayed historical subscription cannot issue future live requests");
    });
  }
});

test("Callbacks scrubbing rewinds counters, histograms and server history together", async () => {
  const data = fixture();
  const view = data.open("callbacks.js");
  const charts = [];
  view.context.MitosisCharts.drawLineChart = (canvas, series, options) => charts.push({ canvas, series, options });
  await ready(view);
  assert.equal(view.element("card").querySelector(".count").textContent, "200");
  assert.equal(data.calls.some(url => /^\/api\/(counters|stats|system|migrations)(?:\?|$)/.test(url)), false,
    "the shared controller owns network polling on production pages");
  assert.equal(last(charts, call => call.canvas === view.element("#callbackRateHistoryChart"))
    .series[0].points.length, 2, "opening a page backfills samples recorded before it opened");

  view.context.MitosisTimeline.setAt(10000);
  await ready(view);
  assert.equal(view.element("card").querySelector(".count").textContent, "100");
  assert.equal(view.read("latestSnapshot.callback_timings[0].buckets[1]"), 7);
  const history = last(charts, call => call.canvas === view.element("#callbackRateHistoryChart"));
  assert.deepEqual(Array.from(history.series[0].points, point => point.y), [10]);
  assert.equal(history.options.maxGapMs, 3000);
  assert.equal(history.options.minX, 10000);
  assert.equal(history.options.maxX, 10000);
  assert.match(view.element("#statusText").textContent, /histor|past|paused/i,
    "a valid old capture is historical, not incorrectly stale against today's clock");

  view.context.MitosisTimeline.goLive();
  await ready(view);
  assert.equal(view.element("card").querySelector(".count").textContent, "200");
});

test("Scheduling scrubbing rewinds the migration heatmap and CPU bands", async () => {
  const data = fixture();
  const view = data.open("scheduling.js");
  const heatmaps = [];
  view.context.MitosisHeatmap.update = snapshot => heatmaps.push(snapshot);
  await ready(view);
  assert.equal(heatmaps.at(-1).cpu_runtime[0].utilization_pct, 20);
  view.context.MitosisTimeline.setAt(10000);
  await ready(view);
  assert.equal(heatmaps.at(-1).cpu_runtime[0].utilization_pct, 10);
  assert.match(view.element("#statusText").textContent, /histor|past|paused/i);
});

test("Inspector scrubbing rewinds system and mitosis utilization", async () => {
  const data = fixture();
  const view = data.open("inspector.js");
  await ready(view);
  assert.equal(view.element("#systemCpuUtilization").textContent, "50%");
  assert.equal(view.element("#mitosisCpuUtilization").textContent, "40%");
  assert.equal(view.element("#hostname").textContent, "test-host");
  view.context.MitosisTimeline.setAt(10000);
  await ready(view);
  assert.equal(view.element("#systemCpuUtilization").textContent, "25%");
  assert.equal(view.element("#mitosisCpuUtilization").textContent, "20%");
  assert.equal(view.element("#sourceRows").children[0].children[1].textContent, "Historical sample");
});

test("System scrubbing uses selected tables and retained system/probe series", async () => {
  const charts = [];
  const view = fixture().open("system.js", { preload: {
    "system.js": context => {
      context.MitosisCharts.drawLineChart = (canvas, series, options) => charts.push({ canvas, series, options });
    },
  } });
  await ready(view);
  view.context.MitosisTimeline.setAt(10000);
  await ready(view);
  assert.equal(view.element("#systemCpuRows").children[0].children[1].textContent, "25%");
  const pressure = last(charts, call => call.canvas === view.element("#pressureHistory"));
  assert.deepEqual(Array.from(pressure.series[0].points, point => point.y), [1]);
  const frequency = last(charts, call => call.canvas === view.element("#frequencyHistory"));
  assert.deepEqual(Array.from(frequency.series[0].points, point => point.y), [1000]);
  assert.equal(frequency.options.maxGapMs, 3000);
  assert.equal(frequency.options.minX, 10000);
  assert.equal(frequency.options.maxX, 10000);
  assert.match(view.element("#statusText").textContent, /histor|past|paused/i);
});

test("Configuration scrubbing preserves search and state filters while replacing configuration", async () => {
  const view = fixture().open("config.js");
  await ready(view);
  assert.equal(view.element("#configurationVersion").textContent, "version-2");
  view.element("#configurationSearch").value = "root cell";
  view.context.MitosisTimeline.setAt(10000);
  await ready(view);
  assert.equal(view.element("#configurationVersion").textContent, "version-1");
  assert.equal(view.element("#configurationSearch").value, "root cell");
  assert.equal(view.element("#configurationRows").children.length, 1);
  assert.equal(view.element("#configurationRows").children[0].children[2].textContent, "1");
});

test("selected time persists when moving from callbacks to System", async () => {
  const storage = new Map();
  const data = fixture({ storage });
  const callbacks = data.open("callbacks.js");
  await ready(callbacks);
  callbacks.context.MitosisTimeline.setAt(10000);
  await ready(callbacks);
  const host = data.open("system.js");
  await ready(host);
  assert.equal(host.context.MitosisTimeline.getState().mode, "history");
  assert.equal(host.context.MitosisTimeline.getState().selectedAt, 10000);
  assert.equal(host.element("#systemCpuRows").children[0].children[1].textContent, "25%");
});

test("missing historical probe source clears cards and heatmap instead of displaying current probes", async (t) => {
  for (const filename of ["callbacks.js", "scheduling.js"]) {
    await t.test(filename, async () => {
      const data = fixture();
      const view = data.open(filename);
      const heatmaps = [];
      view.context.MitosisHeatmap.update = snapshot => heatmaps.push(snapshot);
      await ready(view);
      data.sources[0].counters = null;
      view.context.MitosisTimeline.setAt(10000);
      await ready(view);
      if (filename === "callbacks.js") assert.equal(view.element("card").querySelector(".count").textContent, "--");
      else assert.equal(heatmaps.at(-1).cpu_runtime?.length ?? 0, 0);
      assert.match(view.element("#sourceStatus").textContent, /unavailable|no.*sample/i);
    });
  }
});

test("changing migration window while historical refetches that time and keeps the selected mode", async () => {
  const data = fixture();
  const view = data.open("scheduling.js");
  await ready(view);
  view.context.MitosisTimeline.setAt(10000);
  await ready(view);
  view.element("#migrationWindow").value = "60000";
  view.element("#migrationWindow").dispatchEvent({ type: "change" });
  await ready(view);
  assert.equal(view.context.MitosisTimeline.getState().mode, "history");
  assert.equal(view.read("latestSnapshot.migration_window.window_ms"), 60000);
  assert.equal(view.read("latestSnapshot.migrations[0].count"), 60);
  assert(data.calls.some(url => url.startsWith("/api/timeline/view?")
    && url.includes("at_unix_ms=10000") && url.includes("window_ms=60000")));
});

test("a pending future view cannot replace a newer historical selection", async () => {
  const late = { at: 20000, request: deferred() };
  const data = fixture({ late });
  const view = data.open("callbacks.js");
  await ready(view);
  view.context.MitosisTimeline.setAt(10000);
  await ready(view);
  assert.equal(view.element("card").querySelector(".count").textContent, "100");
  late.request.resolve(response(timelineView(data.sources[1], { at: 20000,
    oldestAt: 10000, latestAt: 20000, migration: migrations(2) })));
  await ready(view);
  assert.equal(view.element("card").querySelector(".count").textContent, "100");
});

test("historical diagnostic downloads contain displayed snapshots without querying live sources", async () => {
  const data = fixture();
  const view = data.open("inspector.js");
  await ready(view);
  view.context.MitosisTimeline.setAt(10000);
  await ready(view);
  let blob;
  view.context.URL = class extends URL {
    static createObjectURL(value) { blob = value; return "blob:diagnostic"; }
    static revokeObjectURL() {}
  };
  const before = data.calls.length;
  await view.context.downloadDiagnosticSnapshot();
  const diagnostic = JSON.parse(await blob.text());
  assert.equal(diagnostic.api.counters.counters[0].count, 100);
  assert.equal(diagnostic.selected_at_unix_ms, 10000);
  assert.equal(data.calls.length, before, "a historical download cannot fetch current metrics");
});

test("archive transport warnings preserve valid already-selected source snapshots", async (t) => {
  for (const filename of ["callbacks.js", "system.js", "config.js"]) {
    await t.test(filename, async () => {
      const data = fixture();
      const view = data.open(filename);
      await ready(view);
      view.context.MitosisTimeline.setAt(10000);
      await ready(view);
      data.network.frameError = "archive connection interrupted";
      await view.context.MitosisTimeline.refresh();
      await ready(view);
      if (filename === "callbacks.js") assert.equal(view.element("card").querySelector(".count").textContent, "100");
      if (filename === "system.js") assert.equal(view.element("#systemCpuRows").children[0].children[1].textContent, "25%");
      if (filename === "config.js") assert.equal(view.element("#configurationVersion").textContent, "version-1");
      assert.match(view.element("#timelineStatus").textContent, /archive connection interrupted/);
    });
  }
});

test("new collection and scheduler epochs advance the clock while the selected callbacks remain frozen", async () => {
  const data = fixture();
  const view = data.open("callbacks.js");
  await ready(view);
  view.context.MitosisTimeline.setAt(10000);
  await ready(view);
  const newer = snapshots(3, 30000);
  for (const name of ["counters", "stats", "system"]) {
    newer[name].meta.epoch = 2;
    newer[name].collector = { ...newer[name].collector, epoch: 2, scheduler_enable_seq: 2 };
  }
  data.sources.push(newer);
  data.frames.push(timelineFrame(3, 30000, { "callbacks.callbacks": 30 },
    { counters: 2, stats: 2, system: 2 }));
  await view.context.MitosisTimeline.refresh();
  await ready(view);
  const selected = view.context.MitosisTimeline.getState();
  assert.equal(selected.mode, "history");
  assert.equal(selected.selectedAt, 10000);
  assert.equal(selected.latestAt, 30000);
  assert.equal(selected.nowMs, 30000);
  assert.equal(view.element("card").querySelector(".count").textContent, "100");
  assert.deepEqual(Array.from(view.context.MitosisTimeline.points("callbacks.callbacks"), point => point.y), [10]);
  view.context.MitosisTimeline.goLive();
  await ready(view);
  assert.equal(view.element("card").querySelector(".count").textContent, "300");
});

test("callback histograms redraw the past while preserving latency choices", async () => {
  const sources = [snapshots(1, 10000), snapshots(2, 20000)];
  sources.forEach((source, index) => {
    source.counters.counters.push({ name: "enqueue", count: index + 1, rate_per_second: (index + 1) * 2 });
    source.counters.callback_timings.push({ callback: "stopping", mean_ns: 100,
      buckets: [0, (index + 1) * 3] });
  });
  const seriesCalls = [];
  const histogramCalls = [];
  const barCalls = [];
  const view = fixture({ sources }).open("callbacks.js", { preload: {
    "callbacks.js": context => {
      context.MitosisCharts.drawHistogramSeries = (canvas, series) => seriesCalls.push({ canvas, series });
      context.MitosisCharts.drawHistogram = (canvas, buckets) => histogramCalls.push({ canvas, buckets });
      context.MitosisCharts.drawBarChart = (canvas, items) => barCalls.push({ canvas, items });
    },
  } });
  await ready(view);
  const choices = view.element("#callbackLatencyMetric").querySelector("fieldset").children
    .map(choice => choice.children[0]);
  choices.forEach(choice => { choice.checked = true; });
  view.element("#callbackLatencyMetric").dispatchEvent({ type: "change" });
  const original = last(seriesCalls, call => call.canvas === view.element("#callbackLatencyChart"));
  view.context.MitosisTimeline.setAt(10000);
  await ready(view);
  const historical = last(seriesCalls, call => call.canvas === view.element("#callbackLatencyChart"));
  assert.deepEqual(Array.from(historical.series, series => series.buckets[0].value), [7, 3]);
  assert.deepEqual(Array.from(historical.series, series => series.color),
    Array.from(original.series, series => series.color));
  const after = view.element("#callbackLatencyMetric").querySelector("fieldset").children
    .map(choice => choice.children[0]);
  assert.equal(after[0], choices[0]);
  assert.equal(after[1], choices[1]);
  assert(after.every(choice => choice.checked));
  assert.equal(last(barCalls, call => call.canvas === view.element("#callbackCostChart")).items[0].value, 0.002);
});

test("block I/O and DSQ residence histograms redraw the past on their own pages", async (t) => {
  for (const [filename, chart, value] of [["system.js", "#blockIoLatencyChart", 5],
    ["scheduling.js", "#dsqResidenceChart", 4]]) {
    await t.test(filename, async () => {
      const histogramCalls = [];
      const view = fixture().open(filename, { preload: {
        [filename]: context => {
          context.MitosisCharts.drawHistogram = (canvas, buckets) => histogramCalls.push({ canvas, buckets });
        },
      } });
      await ready(view);
      assert.equal(last(histogramCalls, call => call.canvas === view.element(chart)).buckets[0].value, value * 2);
      view.context.MitosisTimeline.setAt(10000);
      await ready(view);
      assert.equal(last(histogramCalls, call => call.canvas === view.element(chart)).buckets[0].value, value);
    });
  }
});
