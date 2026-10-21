"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { page, meta, collector, response, settle, timelineView } = require("./page_test_support");

const groupKeys = ["dsqs", "tasks", "perf", "bandwidth", "wakers", "scx_events", "ipis", "idle", "pressure", "thermal", "power"];
const targetIds = { dsqs: "#exploreDsqsRows", tasks: "#exploreTasksRows", perf: "#explorePerfRows",
  bandwidth: "#exploreBandwidthRows", wakers: "#exploreWakersRows", scx_events: "#exploreScxEventsRows",
  ipis: "#exploreIpisRows", idle: "#exploreIdleRows", pressure: "#explorePressureRows",
  thermal: "#exploreThermalRows", power: "#explorePowerRows" };

function group(rows, at = 10000, summary = {}) {
  return { available: true, error: null, meta: meta(1, 1, at), scope: "Fixture source scope",
    summary: { interval_ms: 1000, counter_scope: "since attachment", histogram_scope: "since attachment",
      sample_rate: 1, sample_probability: 1, attached_at_unix_ms: 9000, ...summary }, rows, partial: false };
}

function latency(count = 4, mean = 20) {
  return { samples: count, mean_us: mean, p50_us: 12, p95_us: 48, p99_us: 56, max_us: 64,
    buckets: [0, 1, 3, 0] };
}

function snapshot(at = 10000) {
  const metric = (rate, coverage = 75) => ({ available: true, error: null, raw_total: 800,
    raw_delta: 40, scaled_delta: 50, per_second: rate, time_enabled_ns: 1000000000,
    time_running_ns: 750000000, enabled_delta_ns: 1000000000, running_delta_ns: 750000000,
    coverage_pct: coverage, baseline: false });
  return { meta: meta(1, 1, at), collector: collector(), groups: {
    dsqs: group([{ dsq_id: "31", dsq_hex: "0x1f", insert_events: 32, move_events: 2,
      residence_samples: 4, latency: latency(), depth: { samples: 4, mean: 1.5, last: 2, max: 8 },
      run: latency(4, 100) }], at, { latency_mean_us: 20, latency_p95_us: 48, depth_mean: 1.5,
      running_mean_us: 100, sample_rate: 8, sample_probability: 0.125 }),
    tasks: group([{ pid: 13, tgid: 9, start_time_ns: "213123123", comm: "worker", cpu: 3, llc: 1,
      node: 0, cgroup_id: "912341", cpu_equivalents: 0.25, runtime_ns: 5000000,
      delay: latency(), dsq_delay: latency(4, 8), wakeups: 11, switches: 17 }], at,
    { cpu_equivalents: 0.25, delay_mean_us: 20 }),
    perf: group([{ cpu: 3, llc_id: 1, available: true, partial: false, error: null, interval_ms: 1000,
      ipc: 2, cache_miss_pct: 12.5, instructions_per_second: 1000, cycles_per_second: 500,
      cache_references_per_second: 80, cache_misses_per_second: 10,
      stalled_frontend_cycles_per_second: 45, stalled_backend_cycles_per_second: 55,
      metrics: { instructions: metric(1000), cycles: metric(500), cache_references: metric(80),
        cache_misses: metric(10), stalled_frontend_cycles: metric(45), stalled_backend_cycles: metric(55) } }], at,
    { ipc: 2, instructions_per_second: 1000, cycles_per_second: 500, cache_miss_pct: 12.5,
      cpu_count: 4, available_cpus: 1, sampled_cpu_count: 1 }),
    bandwidth: group([{ domain_id: "000a", llc: 1, node: 0, package: 0, cpus: [2, 3], topology_available: true,
      mbm_local_bytes: 1048576, mbm_total_bytes: 2097152, mbm_local_bps: 1048576,
      mbm_total_bps: 2097152, llc_occupancy_bytes: 3145728, local_status: "measured",
      total_status: "measured", occupancy_status: "measured", error: null }], at,
    { source: "resctrl", monitor: "root", domain_count: 1, mapped_domain_count: 1,
      mbm_local_bps: 1048576, mbm_total_bps: 2097152, llc_occupancy_bytes: 3145728,
      scope_note: "Root monitor excludes other monitoring groups" }),
    wakers: group([{ waker_pid: 13, waker_tgid: 9, waker_start_time_ns: "213123123", waker_comm: "worker",
      wakee_pid: 17, wakee_tgid: 9, wakee_start_time_ns: "213123127", wakee_comm: "helper",
      wakeups: 12, latency: latency(), same_cpu: 4, same_llc: 3, cross_llc: 2, cross_numa: 1,
      unknown_locality: 2, waker_cpu: 3, wakee_cpu: 7 }], at, { per_second: 12, latency_mean_us: 20 }),
    scx_events: group([{ name: "SELECT_CPU_FALLBACK", total: 400, interval_count: 5, per_second: 5 }], at,
      { per_second: 5 }),
    ipis: group([{ source_cpu: 3, target_cpu: 7, count: 400, interval_count: 4, per_second: 4,
      llc_from: 1, llc_to: 2, numa_from: 0, numa_to: 1 }], at, { per_second: 4 }),
    idle: group([{ cpu: 3, node: 0, llc: 1, package: 0, core: 3, state: 2, name: "C6",
      description: "Deep idle", time_us: 9000000, entries: 40, residency_us: 500000,
      entries_delta: 3, residency_pct: 50, entries_per_second: 3, exit_latency_us: 200,
      disabled: false, status: "measured", error: null }], at,
    { cpu_count: 4, state_count: 3, measured_cpu_count: 1, idle_residency_pct: 50,
      active_or_unaccounted_pct: 50 }),
    pressure: group([{ cpu: 3, llc: 1, node: 0, pressure: 128, capacity_scale: 1024,
      last_update_unix_ms: 9800 }], at, { max_pressure: 128 }),
    thermal: group([{ sensor_id: "coretemp/temp1", source: "hwmon", device: "coretemp", label: "Package id 0",
      scope: "package", package: 0, core: null, temperature_celsius: 58.5, high_celsius: 90,
      critical_celsius: 100, alarm: false, error: null }], at,
    { sensor_count: 1, max_temperature_celsius: 58.5 }),
    power: group([{ domain_id: "intel-rapl:0", domain: "package-0", parent_domain_id: null, scope: "package",
      package: 0, energy_uj: 12000000, max_energy_range_uj: 24000000, power_watts: 84.5,
      interval_ms: 1000, included_in_total: true, power_limits: [{ name: "long_term",
        power_limit_watts: 125, time_window_us: 2000000 }], status: "measured", error: null }], at,
    { package_count: 1, package_power_watts: 84.5,
      scope_note: "Package power includes only package domains" }),
  } };
}

function fixture(source = snapshot(), options = {}) {
  let state = { mode: "history", selectedAt: 10000, oldestAt: 10000, latestAt: 20000,
    nowMs: 20000, frames: [], windowMs: 10000, loading: false, error: null, notice: null,
    view: timelineView({ explore: source }, { at: 10000, oldestAt: 10000, latestAt: 20000, now: 20000 }),
    ...options.state };
  let subscriber;
  const calls = [];
  const drawCalls = [];
  const points = options.points || {};
  const controller = { getState: () => state, subscribe(fn) { subscriber = fn; fn(state); return () => {}; },
    points: key => points[key] || [], keys: prefix => Object.keys(points).filter(key => key.startsWith(prefix)),
    refresh: async () => {}, isLive: () => state.mode === "live" };
  const view = page("explore.js", async url => { calls.push(url); return response(snapshot(20000)); }, {
    now: 20000, storage: options.storage, globals: { MitosisTimeline: controller },
    preload: { "explore.js": context => {
      context.MitosisCharts.drawLineChart = (canvas, series, config) => drawCalls.push({ type: "line", canvas, series, config });
      context.MitosisCharts.drawHistogramSeries = (canvas, series, config) => drawCalls.push({ type: "histogram", canvas, series, config });
    } },
  });
  return { ...view, calls, drawCalls, setState(next) { state = { ...state, ...next }; subscriber(state); },
    setSource(next) { state = { ...state, view: { ...state.view, sources: { ...state.view.sources, explore: next } } }; subscriber(state); } };
}

function cells(view, key, index = 0) { return view.element(targetIds[key]).children[index]?.children.map(cell => cell.textContent) || []; }

test("Scheduling and System host all nine Explore sections with the shared time controls", () => {
  const pages = { "scheduling.html": ["exploreTasks", "exploreWakers", "exploreDsqs", "exploreScxEvents"],
    "system.html": ["exploreIpis", "explorePerf", "exploreBandwidth", "exploreIdle", "exploreHardware"] };
  const html = Object.fromEntries(Object.keys(pages).map(name =>
    [name, fs.readFileSync(path.join(__dirname, "../src/web", name), "utf8")]));
  for (const [name, sections] of Object.entries(pages)) {
    const other = html[Object.keys(pages).find(candidate => candidate !== name)];
    for (const id of sections) {
      assert(html[name].includes(`id="${id}"`), `${id} is on ${name}`);
      assert(html[name].includes(`id="${id}Details"`), `${id} can collapse`);
      assert(!other.includes(`id="${id}"`), `${id} appears on only one page`);
    }
    for (const id of ["timelineBar", "timelineRange", "timelineSelected", "timelineNow", "resetAllStats"]) {
      assert(html[name].includes(`id="${id}"`), `${id} is present on ${name}`);
    }
    assert(html[name].includes("/assets/explore.css"));
    assert(html[name].indexOf("/assets/timeline.js") < html[name].indexOf("/assets/explore.js"));
    assert.doesNotMatch(html[name], /https?:\/\/|fonts\.google|<iframe/i, "core diagnostics need no external assets");
  }
});

test("all eleven source groups render their actual schema and units", async () => {
  const view = fixture();
  await settle();
  assert.deepEqual(cells(view, "dsqs").slice(0, 7), ["0x1f", "32", "2", "4", "20", "48", "56"]);
  assert.deepEqual(cells(view, "tasks").slice(0, 5), ["13", "worker", "0.25", "48", "48"]);
  assert.deepEqual(cells(view, "perf").slice(0, 7), ["3", "1", "1,000", "500", "2", "80", "10"]);
  assert.deepEqual(cells(view, "bandwidth").slice(0, 7), ["000a", "1", "0", "2–3", "1", "2", "3"]);
  assert.deepEqual(cells(view, "wakers").slice(0, 5), ["worker · 13", "helper · 17", "12", "20", "48"]);
  assert.deepEqual(cells(view, "scx_events"), ["SELECT_CPU_FALLBACK", "400", "5", "5"]);
  assert.deepEqual(cells(view, "ipis").slice(0, 7), ["3", "7", "1 → 2", "0 → 1", "400", "4", "4"]);
  assert.deepEqual(cells(view, "idle").slice(0, 7), ["3", "C6", "Deep idle", "50", "3", "40", "200"]);
  assert.deepEqual(cells(view, "pressure").slice(0, 5), ["3", "1", "0", "128", "12.5"]);
  assert.deepEqual(cells(view, "thermal").slice(0, 6), ["Package id 0", "package 0", "58.5", "90", "100", "No"]);
  assert.deepEqual(cells(view, "power").slice(0, 6), ["package-0", "package", "0", "84.5", "12", "1,000"]);
  assert.equal(view.calls.length, 0, "the shared timeline owns current and historical transport");
});

test("historical source changes rewind every table without requesting live metrics", async () => {
  const view = fixture();
  const old = snapshot();
  old.groups.tasks.rows[0].comm = "past-worker";
  old.groups.power.rows[0].power_watts = 23;
  view.setSource(old);
  assert.equal(cells(view, "tasks")[1], "past-worker");
  assert.equal(cells(view, "power")[3], "23");
  view.setSource(null);
  for (const key of groupKeys) assert.match(cells(view, key).join(" "), /recorded|retained|selected|unavailable/i);
  assert.equal(view.calls.length, 0, "a missing old source cannot be replaced by a current request");
});

test("supported zero counts remain zero while unknown or unsupported values stay unavailable", () => {
  const data = snapshot();
  data.groups.scx_events.rows[0] = { name: "SELECT_CPU_FALLBACK", total: 0, interval_count: 0, per_second: 0 };
  data.groups.tasks.rows[0].cpu_equivalents = 0;
  data.groups.perf.rows[0].ipc = null;
  data.groups.perf.rows[0].cache_misses_per_second = 0;
  data.groups.bandwidth.rows[0].mbm_local_bps = null;
  data.groups.bandwidth.rows[0].local_status = "baseline";
  data.groups.power.rows[0].power_watts = null;
  data.groups.power.rows[0].status = "baseline";
  const view = fixture(data);
  assert.deepEqual(cells(view, "scx_events"), ["SELECT_CPU_FALLBACK", "0", "0", "0"]);
  assert.equal(cells(view, "tasks")[2], "0");
  assert.equal(cells(view, "perf")[4], "--");
  assert.equal(cells(view, "perf")[6], "0");
  assert.equal(cells(view, "bandwidth")[4], "--");
  assert.equal(cells(view, "power")[3], "--");
});

test("source failures show the actual reason and never leave old rows behind", () => {
  const view = fixture();
  const failed = snapshot();
  failed.groups.perf = { ...failed.groups.perf, available: false, error: "PMU denied by kernel", rows: [] };
  failed.groups.bandwidth = { ...failed.groups.bandwidth, available: false, error: "resctrl is not mounted", rows: [] };
  failed.groups.thermal = { ...failed.groups.thermal, available: false, error: "No thermal sensors", rows: [] };
  view.setSource(failed);
  assert.match(cells(view, "perf").join(" "), /PMU denied by kernel/);
  assert.match(cells(view, "bandwidth").join(" "), /resctrl is not mounted/);
  assert.match(cells(view, "thermal").join(" "), /No thermal sensors/);
  assert.equal(cells(view, "tasks")[1], "worker", "unrelated sources retain valid data");
});

test("empty supported groups are described as no observations instead of fabricated zero rows", () => {
  const data = snapshot();
  for (const key of ["dsqs", "tasks", "wakers", "ipis"]) data.groups[key].rows = [];
  const view = fixture(data);
  for (const key of ["dsqs", "tasks", "wakers", "ipis"]) assert.match(cells(view, key).join(" "), /no .*observ|no .*record|no .*track/i);
});

test("strings from task names, kernel labels and source errors are rendered as text", () => {
  const data = snapshot();
  const hostile = '<img src=x onerror="alert(1)">';
  data.groups.tasks.rows[0].comm = hostile;
  data.groups.thermal.rows[0].label = hostile;
  data.groups.bandwidth.error = hostile;
  data.groups.bandwidth.available = false;
  const view = fixture(data);
  assert.equal(cells(view, "tasks")[1], hostile);
  assert.equal(cells(view, "thermal")[0], hostile);
  assert(cells(view, "bandwidth").join(" ").includes(hostile));
  assert.equal(view.element(targetIds.tasks).children[0].children[1].children.length, 0);
  assert.equal(view.element(targetIds.thermal).children[0].children[0].children.length, 0);
});

test("a future source or individual group cannot be shown at an earlier selection", () => {
  const view = fixture(snapshot(20000));
  assert.match(cells(view, "tasks").join(" "), /future|later|selected|retained|recorded|unavailable/i);
  const data = snapshot();
  data.groups.perf.meta = meta(2, 1, 20000);
  view.setSource(data);
  assert.match(cells(view, "perf").join(" "), /future|later|selected|retained|recorded|unavailable/i);
  assert.equal(cells(view, "tasks")[1], "worker");
});

test("hardware status and sampling semantics use actual group metadata", () => {
  const data = snapshot();
  data.groups.tasks.partial = true;
  data.groups.tasks.summary.truncated_rows = 9;
  data.groups.tasks.summary.tracking_failures_total = 3;
  const view = fixture(data);
  assert.match(view.element("#exploreDsqsQuality").textContent, /1\s*(?:\/|in)\s*8/i);
  assert.match(view.element("#exploreDsqsQuality").textContent, /since.*attach|collection began/i);
  assert.match(view.element("#exploreTasksQuality").textContent, /partial|9|3/i);
  assert.match(view.element("#exploreBandwidthQuality").textContent, /excludes other monitoring groups/);
  assert.match(view.element("#exploreIdleQuality").textContent, /driver.*exit|exit.*driver/i);
  assert.match(view.element("#explorePowerQuality").textContent, /includes only package domains/);
});

test("task filtering and sort preferences survive source replacement", () => {
  const data = snapshot();
  data.groups.tasks.rows.push({ ...data.groups.tasks.rows[0], pid: 14, comm: "helper", cpu_equivalents: 0.75 });
  const view = fixture(data);
  const search = view.element("#exploreTasksSearch");
  search.value = "worker";
  search.dispatchEvent({ type: "input" });
  assert.equal(view.element(targetIds.tasks).children.length, 1);
  assert.equal(cells(view, "tasks")[1], "worker");
  view.setSource(data);
  assert.equal(search.value, "worker");
  assert.equal(view.element(targetIds.tasks).children.length, 1);
});

test("history charts use archived scalar points, actual units and an upper bound at the selection", () => {
  const points = { "explore.perf.ipc": [{ x: 10000, y: 2 }, { x: 20000, y: 9 }],
    "explore.bandwidth.mbm_total_bps": [{ x: 10000, y: 2097152 }],
    "explore.bandwidth.llc_occupancy_bytes": [{ x: 10000, y: 3145728 }],
    "explore.tasks.cpu_equivalents": [{ x: 10000, y: 0.25 }],
    "explore.power.package_power_watts": [{ x: 10000, y: 84.5 }] };
  const view = fixture(snapshot(), { points });
  const ipc = view.drawCalls.find(call => call.canvas === view.element("#explorePerfHistory"));
  assert(ipc, "a valid archive series renders its history");
  assert.equal(ipc.config.maxX, 10000);
  assert.equal(ipc.config.maxGapMs, 3000);
  assert.deepEqual(Array.from(ipc.series[0].points, point => point.y), [2]);
  const occupancy = view.drawCalls.find(call => call.canvas === view.element("#exploreOccupancyHistory"));
  assert(occupancy);
  assert.equal(occupancy.config.unit, "MiB");
  assert.deepEqual(Array.from(occupancy.series[0].points, point => point.y), [3]);
  assert(!view.drawCalls.some(call => call.canvas === view.element("#exploreBandwidthHistory")),
    "memory traffic history is charted once, with the System memory graphs");
  const power = view.drawCalls.find(call => call.canvas === view.element("#explorePowerHistory"));
  assert(power);
  assert.equal(power.config.unit, "W");
});

test("transport warnings preserve a valid selected source while displayed values stay historical", () => {
  const view = fixture();
  view.setState({ error: "Archive transport interrupted", nowMs: 25000 });
  assert.equal(cells(view, "tasks")[1], "worker");
  assert.equal(cells(view, "power")[3], "84.5");
  assert.equal(view.element("#exploreTasksStatus").textContent, "Recorded");
});

test("an invalid archived source error clears snapshots instead of displaying current rows", () => {
  const view = fixture();
  view.setState({ view: timelineView({ explore: snapshot() }, { at: 10000,
    errors: { explore: "Selected source failed" } }) });
  assert.match(cells(view, "tasks").join(" "), /Selected source failed/);
  assert.equal(view.calls.length, 0);
});

test("section collapse preferences persist across pages and reopening redraws", () => {
  const storage = new Map();
  const view = fixture(snapshot(), { storage });
  const details = view.element("#exploreTasksDetails");
  assert.equal(details.open, true, "sections start expanded");
  details.open = false;
  details.dispatchEvent({ type: "toggle" });
  assert.deepEqual(JSON.parse(storage.get("mitosis-explore-sections-v2")).Tasks, { open: false });
  const second = fixture(snapshot(), { storage });
  assert.equal(second.element("#exploreTasksDetails").open, false);
  assert.equal(second.element("#exploreDsqsDetails").open, true);
  const drawn = second.drawCalls.length;
  second.element("#exploreTasksDetails").open = true;
  second.element("#exploreTasksDetails").dispatchEvent({ type: "toggle" });
  assert(second.drawCalls.length > drawn, "collapsed canvases redraw once visible");
  assert.equal(second.calls.length, 0);
});

test("nanosecond log2 buckets keep readable time boundaries and observation counts", () => {
  const data = snapshot();
  data.groups.dsqs.rows[0].latency = { ...latency(), bucket_unit: "ns", bucket_scale: "log2",
    buckets: [0, 1, 3, 0] };
  const view = fixture(data);
  const histogram = view.drawCalls.find(call => call.canvas === view.element("#exploreDsqWaitChart"));
  assert(histogram);
  assert.deepEqual(Array.from(histogram.series[0].buckets, bucket => bucket.value), [0, 1, 3, 0]);
  assert.match(histogram.series[0].buckets[1].label, /3 ns/);
  assert.match(histogram.series[0].buckets[2].label, /7 ns/);
  assert.doesNotMatch(histogram.series[0].buckets[1].label, /(?:^|\D)0 µs/);
});

test("absent or invalid histograms do not synthesize distributions from percentile values", () => {
  const data = snapshot();
  data.groups.tasks.rows[0].delay.buckets = null;
  data.groups.tasks.rows[0].dsq_delay.buckets = [0, null, 4];
  data.groups.wakers.rows[0].latency = { ...latency(), samples: 0, buckets: [0, 0, 0] };
  const view = fixture(data);
  assert.equal(view.drawCalls.some(call => call.canvas === view.element("#exploreTaskDelayChart")), false);
  assert.equal(view.drawCalls.some(call => call.canvas === view.element("#exploreWakerDelayChart")), false);
  assert.match(view.element("#exploreWakerSamples").textContent, /0 observed/);
  assert.equal(cells(view, "tasks")[3], "48", "a separately collected percentile remains valid");
});

test("numeric sorting keeps missing values last in both directions and survives a new snapshot", () => {
  const data = snapshot();
  data.groups.tasks.rows.push({ ...data.groups.tasks.rows[0], pid: 14, comm: "helper", cpu_equivalents: 0.75 },
    { ...data.groups.tasks.rows[0], pid: 15, comm: "missing", cpu_equivalents: null });
  const view = fixture(data);
  const header = view.element("#exploreTasksHead").children[2];
  header.children[0].click();
  assert.deepEqual(view.element(targetIds.tasks).children.map(row => row.children[1].textContent), ["helper", "worker", "missing"]);
  assert.equal(header.getAttribute("aria-sort"), "descending");
  header.children[0].click();
  assert.deepEqual(view.element(targetIds.tasks).children.map(row => row.children[1].textContent), ["worker", "helper", "missing"]);
  view.setSource(data);
  assert.deepEqual(view.element(targetIds.tasks).children.map(row => row.children[1].textContent), ["worker", "helper", "missing"]);
});

test("a reused TID cannot silently inherit a selected old thread's distribution", () => {
  const data = snapshot();
  const view = fixture(data);
  const before = view.element("#exploreTaskSelect").value;
  const newer = snapshot();
  newer.groups.tasks.rows[0].start_time_ns = "213123999";
  newer.groups.tasks.rows[0].delay.buckets = [0, 0, 0, 4];
  view.setSource(newer);
  assert.notEqual(view.element("#exploreTaskSelect").value, before);
  assert(view.element("#exploreTaskSelect").value.includes("213123999"));
});

test("host hardware remains readable when scheduler-specific collection is waiting", () => {
  const data = snapshot();
  data.collector = collector(2, "waiting", "Mitosis is not attached");
  data.groups.dsqs = { ...data.groups.dsqs, available: false, error: "Mitosis is not attached", rows: [] };
  data.groups.thermal.meta = meta(1, 0, 10000);
  data.groups.power.meta = meta(1, 0, 10000);
  const view = fixture(data);
  assert.equal(cells(view, "thermal")[2], "58.5");
  assert.equal(cells(view, "power")[3], "84.5");
  assert.match(cells(view, "dsqs").join(" "), /Mitosis is not attached/);
});

test("bounded thread and pair totals use their retained entry scope and expose CPU read failures", () => {
  const data = snapshot();
  data.groups.tasks.summary.counter_scope = "since this thread entered bounded tracking";
  data.groups.tasks.summary.histogram_scope = "since this thread entered bounded tracking";
  data.groups.wakers.summary.counter_scope = "since this pair entered bounded tracking";
  data.groups.wakers.summary.histogram_scope = "since this pair entered bounded tracking";
  data.groups.tasks.rows[0].runtime_scope = "since thread birth";
  data.groups.tasks.rows[0].cpu_error = "Thread CPU read budget exhausted";
  data.groups.tasks.rows[0].cpu_equivalents = null;
  const view = fixture(data);
  assert.match(view.element("#exploreTasksQuality").textContent, /since this thread entered bounded tracking/);
  assert.match(view.element("#exploreWakersQuality").textContent, /since this pair entered bounded tracking/);
  assert.doesNotMatch(view.element("#exploreTasksQuality").textContent, /totals and distributions since collection began/i);
  assert(cells(view, "tasks").includes("Thread CPU read budget exhausted"));
  assert.equal(cells(view, "tasks")[2], "--");
});

test("DSQ distribution containers are visible before canvas preparation after a no-data selection", () => {
  const data = snapshot();
  data.groups.dsqs.rows[0].latency = { ...latency(), samples: 0, buckets: [0, 0, 0, 0] };
  data.groups.dsqs.rows[0].run = { ...latency(), samples: 0, buckets: [0, 0, 0, 0] };
  const view = fixture(data);
  assert.equal(view.element("#exploreDsqDistributions").hidden, true);
  const visibility = [];
  view.context.MitosisCharts.drawHistogramSeries = () => visibility.push(view.element("#exploreDsqDistributions").hidden);
  view.setSource(snapshot());
  assert(visibility.length >= 2);
  assert(visibility.every(value => value === false), "canvas CSS bounds are measured after the container is visible");
});

test("partial idle accounting shows measured CPU coverage while aggregate residency stays unavailable", () => {
  const data = snapshot();
  data.groups.idle.partial = true;
  data.groups.idle.summary.measured_cpu_count = 3;
  data.groups.idle.summary.cpu_count = 4;
  data.groups.idle.summary.idle_residency_pct = null;
  data.groups.idle.summary.active_or_unaccounted_pct = null;
  data.groups.idle.rows[0].status = "accounting_catchup";
  data.groups.idle.rows[0].residency_pct = null;
  const view = fixture(data);
  const facts = view.element("#exploreIdleFacts").children.map(item => item.children.map(part => part.textContent).join(" ")).join(" ");
  assert.match(facts, /3\s*\/\s*4/);
  assert.doesNotMatch(facts, /Idle residency 0/);
  assert.equal(cells(view, "idle")[3], "--");
  assert.match(cells(view, "idle").join(" "), /waiting for idle accounting/i);
});

test("kernel sched_ext totals declare kernel-session scope rather than observer attachment scope", () => {
  const data = snapshot();
  data.groups.scx_events.summary.counter_scope = "kernel scheduler session; counters may predate optional observer attachment";
  const view = fixture(data);
  assert.match(view.element("#exploreScxEventsQuality").textContent, /kernel scheduler session/);
  const totalHeader = view.element("#exploreScxEventsHead").children[1].children[0];
  assert.match(totalHeader.children[0].textContent, /kernel session/i);
});

test("dispatch queue IDs sort numerically while their hexadecimal labels stay unchanged", () => {
  const data = snapshot();
  const original = data.groups.dsqs.rows[0];
  data.groups.dsqs.rows = [31, 32, 16, 10].map(id => ({ ...original, dsq_id: String(id), dsq_hex: `0x${id.toString(16)}` }));
  const view = fixture(data);
  view.element("#exploreDsqsHead").children[0].children[0].click();
  assert.deepEqual(view.element(targetIds.dsqs).children.map(row => row.children[0].textContent), ["0xa", "0x10", "0x1f", "0x20"]);
});

test("partial coverage cannot make a stale live source appear fresh", () => {
  const data = snapshot();
  for (const key of groupKeys) if (key !== "perf") data.groups[key] = { ...data.groups[key], available: false, rows: [], error: "Unsupported here" };
  data.groups.perf.partial = true;
  const view = fixture(data, { state: { mode: "live", nowMs: 25000 } });
  assert.match(view.element("#explorePerfStatus").textContent, /stale/i);
  assert.match(view.element("#explorePerfQuality").textContent, /partial/i);
  assert.equal(view.element("#explorePerfStatus").getAttribute("data-state"), "stale");
});

test("an all-unavailable archived report preserves each source reason despite aggregate metadata error", () => {
  const data = snapshot();
  data.meta.error = "No Explore sources are available";
  for (const key of groupKeys) data.groups[key] = { ...data.groups[key], available: false,
    error: `Unavailable reason for ${key}`, rows: [], summary: {} };
  const view = fixture(data);
  for (const key of groupKeys) assert(cells(view, key).join(" ").includes(`Unavailable reason for ${key}`), key);
  assert.equal(view.calls.length, 0);
});
