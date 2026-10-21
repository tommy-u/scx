"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const web = path.join(__dirname, "../src/web");
const controllerPath = path.join(web, "timeline.js");
const BASE = Date.parse("2026-10-14T07:00:00Z");
const copy = (value) => JSON.parse(JSON.stringify(value));
const deferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};
const settle = async () => { for (let pass = 0; pass < 5; pass += 1) await new Promise(setImmediate); };

function frame(seq, seconds, signals = {}, epochs = {}) {
  return { seq, at_unix_ms: BASE + seconds * 1000,
    epochs: { counters: 1, stats: 1, system: 1, ...epochs },
    signals: { "cell.0.assigned_cpus": seq * 2, "system.cpu_busy": seq * 5, ...signals } };
}

function archive(frames, options = {}) {
  return { instance_id: "inspector-one", retention_ms: 1800000,
    now_unix_ms: BASE + 10000,
    window_ms: 10000, default_window_ms: 10000, max_window_ms: 300000,
    oldest_at_unix_ms: frames[0]?.at_unix_ms ?? null,
    latest_at_unix_ms: frames[frames.length - 1]?.at_unix_ms ?? null,
    sample_seq: frames[frames.length - 1]?.seq ?? 0,
    reset: true, frames, ...options };
}

function view(at, data) {
  const selected = data.frames.filter((sample) => sample.at_unix_ms <= at).at(-1);
  return { instance_id: data.instance_id, retention_ms: data.retention_ms,
    requested_at_unix_ms: at, at_unix_ms: selected?.at_unix_ms ?? null,
    oldest_at_unix_ms: data.oldest_at_unix_ms, latest_at_unix_ms: data.latest_at_unix_ms,
    now_unix_ms: data.now_unix_ms, collector: { epoch: 1, status: "active" },
    sources: { counters: { mark: selected?.seq }, stats: { mark: selected?.seq },
      system: { mark: selected?.seq }, config: { mark: selected?.seq } },
    migrations: { window_ms: data.window_ms ?? 10000, rows: [], total: selected?.seq ?? 0 }, source_errors: {} };
}

function response(value, status = 200) {
  return { ok: status >= 200 && status < 300, status, json: async () => value };
}

class Element {
  constructor() {
    this.attributes = new Map();
    this.listeners = new Map();
    this.dataset = {};
    this.style = { setProperty() {} };
    this.textContent = "";
    this.value = "";
    this.min = "";
    this.max = "";
    this.step = "";
    this.disabled = false;
    const classes = new Set();
    this.classList = { add: (...names) => names.forEach((name) => classes.add(name)),
      remove: (...names) => names.forEach((name) => classes.delete(name)),
      contains: (name) => classes.has(name),
      toggle(name, on) { if (on ?? !classes.has(name)) classes.add(name); else classes.delete(name); } };
  }
  get valueAsNumber() { return Number(this.value); }
  set valueAsNumber(value) { this.value = String(value); }
  setAttribute(name, value) { this.attributes.set(name, String(value)); }
  getAttribute(name) { return this.attributes.get(name) ?? null; }
  removeAttribute(name) { this.attributes.delete(name); }
  addEventListener(type, callback) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(callback);
  }
  dispatch(type, fields = {}) {
    const event = { type, target: this, preventDefault() { this.defaultPrevented = true; }, ...fields };
    for (const callback of this.listeners.get(type) ?? []) callback(event);
    return event;
  }
  getBoundingClientRect() { return { height: 92 }; }
  focus() { this.focused = true; }
}

function harness({ pathname = "/", storage = new Map(), data = archive([frame(1, 1), frame(2, 2), frame(3, 3)]),
    handler = null } = {}) {
  assert.ok(fs.existsSync(controllerPath), "Shared time scrubbing controller has not been implemented");
  const elements = new Map();
  for (const id of ["timelineBar", "timelineLive", "timelinePrevious", "timelineNext", "timelineRange",
    "timelineSelected", "timelineNow", "timelineOldest", "timelineLatest", "timelineStatus", "resetAllStats"])
    elements.set(`#${id}`, new Element());
  let currentArchive = data;
  let customHandler = handler;
  let wall = BASE + 10000;
  let monotonic = 0;
  let nextTimer = 0;
  const timers = new Map();
  const intervals = new Map();
  const listeners = new Map();
  const requests = [];
  const context = { console, AbortController, Intl, URL, URLSearchParams,
    Date: class extends Date { static now() { return wall; } },
    performance: { now: () => monotonic },
    location: { origin: "http://inspector.test", pathname, search: "" },
    sessionStorage: { getItem: (key) => storage.get(key) ?? null,
      setItem: (key, value) => storage.set(key, String(value)), removeItem: (key) => storage.delete(key) },
    document: { visibilityState: "visible", documentElement: { style: { setProperty() {} } },
      querySelector: (key) => elements.get(key) ?? null,
      querySelectorAll: () => [],
      addEventListener(type, callback) {
        if (!listeners.has(type)) listeners.set(type, []);
        listeners.get(type).push(callback);
      } },
    setTimeout(callback, delay) { const id = ++nextTimer; timers.set(id, { callback, delay }); return id; },
    clearTimeout(id) { timers.delete(id); },
    setInterval(callback, delay) { const id = ++nextTimer; intervals.set(id, { callback, delay }); return id; },
    clearInterval(id) { intervals.delete(id); },
    addEventListener(type, callback) {
      if (!listeners.has(type)) listeners.set(type, []);
      listeners.get(type).push(callback);
    },
    dispatchEvent(event) { for (const callback of listeners.get(event.type) ?? []) callback(event); },
    CustomEvent: class { constructor(type, options = {}) { this.type = type; this.detail = options.detail; } },
    fetch: async (url, options) => {
      requests.push({ url, options });
      if (customHandler) {
        const result = customHandler(url, options, currentArchive);
        if (result !== undefined) return result;
      }
      const parsed = new URL(url, "http://inspector.test");
      const windowMs = parsed.searchParams.has("window_ms")
        ? Number(parsed.searchParams.get("window_ms")) : currentArchive.default_window_ms ?? 10000;
      if (!Number.isFinite(windowMs) || windowMs <= 0 || windowMs > currentArchive.max_window_ms) {
        return response({ error: "Unsupported history window", instance_id: currentArchive.instance_id,
          default_window_ms: currentArchive.default_window_ms, max_window_ms: currentArchive.max_window_ms,
          oldest_at_unix_ms: currentArchive.oldest_at_unix_ms, latest_at_unix_ms: currentArchive.latest_at_unix_ms,
          now_unix_ms: currentArchive.now_unix_ms }, 400);
      }
      if (parsed.pathname === "/api/timeline") {
        const cursor = Number(parsed.searchParams.get("after_seq"));
        const sameInstance = parsed.searchParams.get("instance_id") === currentArchive.instance_id;
        return response({ ...currentArchive, window_ms: windowMs,
          reset: !sameInstance,
          frames: sameInstance ? currentArchive.frames.filter((sample) => sample.seq > cursor) : currentArchive.frames });
      }
      if (parsed.pathname === "/api/timeline/view") {
        const at = parsed.searchParams.has("at_unix_ms")
          ? Number(parsed.searchParams.get("at_unix_ms")) : currentArchive.latest_at_unix_ms;
        return response(view(at, { ...currentArchive, window_ms: windowMs }));
      }
      throw new Error(`Unexpected controller request ${url}`);
    } };
  context.window = context;
  context.globalThis = context;
  vm.createContext(context);
  for (const filename of ["polling.js", "timeline.js"])
    vm.runInContext(fs.readFileSync(path.join(web, filename), "utf8"), context, { filename });
  return { context, controller: context.MitosisTimeline, requests, storage,
    element: (id) => elements.get(`#${id}`),
    setArchive(next) { currentArchive = next; },
    setHandler(next) { customHandler = next; },
    emit(type, detail) { context.dispatchEvent(new context.CustomEvent(type, { detail })); },
    advance(ms, { runIntervals = false } = {}) {
      wall += ms;
      monotonic += ms;
      for (const [id, timer] of [...timers]) {
        if (timer.delay <= ms) { timers.delete(id); timer.callback(); }
      }
      if (runIntervals) for (const timer of intervals.values()) if (timer.delay <= ms) timer.callback();
    } };
}

const tests = [];
const test = (name, run) => tests.push({ name, run });

test("startup requests the configured server window rather than assuming ten seconds", async () => {
  const h = harness({ data: archive([frame(1, 1), frame(2, 2), frame(3, 3)],
    { window_ms: 1000, default_window_ms: 1000, max_window_ms: 5000 }) });
  assert.equal(h.controller.getState().windowMs, null);
  await settle();
  assert.equal(new URL(h.requests[0].url, "http://inspector.test").searchParams.has("window_ms"), false);
  assert.equal(h.controller.getState().windowMs, 1000);
  assert.equal(h.controller.getState().frames.length, 3);
  assert.equal(h.controller.getState().view.migrations.window_ms, 1000);
  assert.equal(h.element("timelineRange").disabled, false);
  assert.equal(h.controller.getState().error, null);
});

test("a supported saved window remains selected across pages with a shorter configured default", async () => {
  const storage = new Map([["mitosis-inspector-timeline:http://inspector.test", JSON.stringify({
    instanceId: "inspector-one", mode: "history", selectedAt: BASE + 2000, windowMs: 3000 })]]);
  const h = harness({ storage, data: archive([frame(1, 1), frame(2, 2), frame(3, 3)],
    { window_ms: 1000, default_window_ms: 1000, max_window_ms: 5000 }) });
  await settle();
  assert.equal(new URL(h.requests[0].url, "http://inspector.test").searchParams.get("window_ms"), "3000");
  assert.equal(h.controller.getState().windowMs, 3000);
  assert.equal(h.controller.getState().selectedAt, BASE + 2000);
  assert.equal(h.controller.getState().view.migrations.window_ms, 3000);
});

test("an unsupported saved window recovers to a subsecond server default without changing selected time", async () => {
  const storage = new Map([["mitosis-inspector-timeline:http://inspector.test", JSON.stringify({
    instanceId: "inspector-one", mode: "history", selectedAt: BASE + 2000, windowMs: 10000 })]]);
  const h = harness({ storage, data: archive([frame(1, 1), frame(2, 2), frame(3, 3)],
    { window_ms: 500, default_window_ms: 500, max_window_ms: 5000 }) });
  await settle();
  assert.equal(h.controller.getState().windowMs, 500);
  assert.equal(h.controller.getState().mode, "history");
  assert.equal(h.controller.getState().selectedAt, BASE + 2000);
  assert.equal(h.controller.getState().frames.length, 3);
  assert.equal(h.controller.getState().view.migrations.window_ms, 500);
  assert.equal(h.controller.getState().error, null);
  assert.match(h.controller.getState().notice, /window|default|adjust/i);
  const recovery = h.requests.find((request) => request.url.includes("window_ms=500"));
  assert.ok(recovery && !recovery.url.includes("after_seq="));
});

test("configured window metadata resolves even before the first retained sample", async () => {
  const options = { window_ms: 500, default_window_ms: 500, max_window_ms: 5000 };
  const h = harness({ data: archive([], options) });
  await settle();
  assert.equal(h.controller.getState().windowMs, 500);
  assert.equal(h.element("timelineRange").disabled, true);
  assert.equal(h.controller.getState().error, null);
  h.setArchive(archive([frame(1, 1)], options));
  await h.controller.refresh();
  await settle();
  assert.equal(h.controller.getState().frames.length, 1);
  assert.equal(h.controller.getState().view.migrations.window_ms, 500);
});

test("a late unsupported-window response cannot undo a newer valid window", async () => {
  const oldError = deferred();
  const storage = new Map([["mitosis-inspector-timeline:http://inspector.test", JSON.stringify({
    instanceId: "inspector-one", mode: "live", selectedAt: null, windowMs: 10000 })]]);
  const h = harness({ storage, data: archive([frame(1, 1), frame(2, 2), frame(3, 3)],
    { window_ms: 1000, default_window_ms: 1000, max_window_ms: 5000 }),
    handler: (url) => url.includes("window_ms=10000") ? oldError.promise : undefined });
  h.controller.setWindowMs(1000);
  await settle();
  assert.equal(h.controller.getState().windowMs, 1000);
  oldError.resolve(response({ error: "Unsupported history window", default_window_ms: 500, max_window_ms: 2000 }, 400));
  await settle();
  assert.equal(h.controller.getState().windowMs, 1000);
  assert.equal(h.controller.getState().error, null);
});

test("older archive fixtures can resolve the window from their full view", async () => {
  const h = harness({ handler: (url, options, data) => {
    if (new URL(url, "http://inspector.test").pathname === "/api/timeline") {
      const legacy = { ...data };
      delete legacy.window_ms;
      delete legacy.default_window_ms;
      delete legacy.max_window_ms;
      return response(legacy);
    }
    if (url.startsWith("/api/timeline/view")) return response(view(BASE + 3000, { ...data, window_ms: 500 }));
  } });
  await settle();
  assert.equal(h.controller.getState().windowMs, 500);
  const firstView = h.requests.find((request) => request.url.startsWith("/api/timeline/view"));
  assert.equal(new URL(firstView.url, "http://inspector.test").searchParams.has("window_ms"), false);
});

test("native slider and two clocks reflect the retained range", async () => {
  const h = harness();
  await settle();
  assert.equal(h.controller.getState().mode, "live");
  assert.equal(h.element("timelineRange").min, String(BASE + 1000));
  assert.equal(h.element("timelineRange").max, String(BASE + 3000));
  assert.equal(h.element("timelineRange").disabled, false);
  assert.match(h.element("timelineSelected").textContent, /2026/);
  assert.match(h.element("timelineNow").textContent, /\d{2}:\d{2}:\d{2}/);
  assert.ok(h.element("timelineRange").getAttribute("aria-valuetext"));
  h.element("timelineRange").value = String(BASE + 2000);
  h.element("timelineRange").dispatch("input");
  assert.equal(h.controller.getState().selectedAt, BASE + 2000);
  assert.equal(h.controller.getState().view, null, "A new clock must not show the previous time's tables");
  assert.equal(h.element("resetAllStats").disabled, true);
  h.advance(100);
  await settle();
  assert.equal(h.controller.getState().view.sources.stats.mark, 2);
  const selectedClock = h.element("timelineSelected").textContent;
  const nowClock = h.element("timelineNow").textContent;
  h.advance(1000, { runIntervals: true });
  await settle();
  assert.equal(h.element("timelineSelected").textContent, selectedClock);
  assert.notEqual(h.element("timelineNow").textContent, nowClock);
});

test("future samples are collected while graphs and the historical snapshot stay fixed", async () => {
  const h = harness();
  await settle();
  h.controller.setAt(BASE + 2000);
  h.advance(100);
  await settle();
  const historical = h.controller.getState().view;
  const viewCount = h.requests.filter((request) => request.url.startsWith("/api/timeline/view")).length;
  h.setArchive(archive([frame(1, 1), frame(2, 2), frame(3, 3), frame(4, 4)]));
  await h.controller.refresh();
  await settle();
  assert.equal(h.controller.getState().frames.length, 4);
  assert.equal(h.controller.getState().view, historical);
  assert.equal(h.requests.filter((request) => request.url.startsWith("/api/timeline/view")).length, viewCount);
  assert.deepEqual(copy(h.controller.points("cell.0.assigned_cpus")).map((point) => point.x), [BASE + 1000, BASE + 2000]);
  assert.ok(h.controller.keys("cell.").includes("cell.0.assigned_cpus"));
  assert.ok(h.requests.some((request) => request.url.includes("instance_id=inspector-one") && request.url.includes("after_seq=3")));
});

test("a chosen absolute time survives navigation between workspace pages", async () => {
  const storage = new Map();
  const scheduler = harness({ storage });
  await settle();
  scheduler.controller.setAt(BASE + 2000);
  scheduler.controller.setWindowMs(30000);
  scheduler.advance(100);
  await settle();
  const callbacks = harness({ pathname: "/callbacks", storage });
  await settle();
  assert.equal(callbacks.controller.getState().mode, "history");
  assert.equal(callbacks.controller.getState().selectedAt, BASE + 2000);
  assert.equal(callbacks.controller.getState().windowMs, 30000);
  assert.equal(callbacks.controller.getState().view.sources.counters.mark, 2);
});

test("late responses for old selections cannot overwrite a newer time or Live", async () => {
  const h = harness();
  await settle();
  const oldRequest = deferred();
  h.setHandler((url, options, data) => {
    if (url.includes(`at_unix_ms=${BASE + 1000}`)) return oldRequest.promise;
  });
  h.controller.setAt(BASE + 1000);
  h.advance(100);
  await settle();
  h.controller.setAt(BASE + 2000);
  h.advance(100);
  await settle();
  assert.equal(h.controller.getState().view.sources.stats.mark, 2);
  h.controller.goLive();
  await settle();
  assert.equal(h.controller.getState().view.sources.stats.mark, 3);
  oldRequest.resolve(response(view(BASE + 1000, archive([frame(1, 1), frame(2, 2), frame(3, 3)]))));
  await settle();
  assert.equal(h.controller.getState().mode, "live");
  assert.equal(h.controller.getState().view.sources.stats.mark, 3);
});

test("a delayed full snapshot cannot rewind the clock from a newer light response", async () => {
  const h = harness();
  await settle();
  const pendingView = deferred();
  h.setHandler((url) => url.includes(`at_unix_ms=${BASE + 1000}`) ? pendingView.promise : undefined);
  h.controller.setAt(BASE + 1000);
  h.advance(100);
  await settle();
  h.setArchive(archive([frame(1, 1), frame(2, 2), frame(3, 3), frame(4, 4)], { now_unix_ms: BASE + 13000 }));
  const refresh = h.controller.refresh();
  await settle();
  const newerClock = h.controller.getState().nowMs;
  assert.equal(newerClock, BASE + 13000);
  pendingView.resolve(response(view(BASE + 1000, archive([frame(1, 1), frame(2, 2), frame(3, 3)]))));
  await refresh;
  await settle();
  assert.ok(h.controller.getState().nowMs >= newerClock, "An old full-view response must not rewind Now");
});

test("light responses cannot label a missing full snapshot Live while its retry is pending", async () => {
  const h = harness({ handler: (url) => url.startsWith("/api/timeline/view")
    ? response({ error: "Selected view unavailable" }, 503) : undefined });
  await settle();
  assert.equal(h.controller.getState().view, null);
  assert.match(h.controller.getState().error, /Selected view unavailable/);
  const retry = deferred();
  h.setHandler((url) => url.startsWith("/api/timeline/view") ? retry.promise : undefined);
  const refresh = h.controller.refresh();
  await settle();
  assert.equal(h.controller.getState().view, null);
  assert.equal(h.controller.getState().loading, true, "The full snapshot is still required");
  assert.match(h.controller.getState().error, /Selected view unavailable/);
  assert.notEqual(h.element("timelineStatus").textContent, "Live");
  retry.resolve(response(view(BASE + 3000, archive([frame(1, 1), frame(2, 2), frame(3, 3)]))));
  await refresh;
  await settle();
  assert.equal(h.controller.getState().view.sources.stats.mark, 3);
  assert.equal(h.controller.getState().loading, false);
  assert.equal(h.controller.getState().error, null);
});

test("expired selections clamp visibly and remain historical", async () => {
  const h = harness();
  await settle();
  h.controller.setAt(BASE + 1000);
  h.advance(100);
  await settle();
  h.setArchive(archive([frame(3, 3), frame(4, 4)]));
  await h.controller.refresh();
  await settle();
  assert.equal(h.controller.getState().mode, "history");
  assert.equal(h.controller.getState().selectedAt, BASE + 3000);
  assert.match(h.controller.getState().notice, /oldest|retained|expired/i);
  assert.equal(h.controller.getState().view.sources.stats.mark, 3);
  assert.deepEqual(copy(h.controller.getState().frames).map((sample) => sample.seq), [3, 4]);
});

test("retention advancing during a view request recovers from HTTP400 bounds", async () => {
  const h = harness();
  await settle();
  h.setHandler((url) => {
    if (url.includes(`at_unix_ms=${BASE + 1000}`)) return response({ error: "Requested time expired",
      oldest_at_unix_ms: BASE + 2000, latest_at_unix_ms: BASE + 3000 }, 400);
  });
  h.controller.setAt(BASE + 1000);
  h.advance(100);
  await settle();
  h.advance(1);
  await settle();
  assert.equal(h.controller.getState().mode, "history");
  assert.equal(h.controller.getState().selectedAt, BASE + 2000);
  assert.equal(h.controller.getState().view.sources.stats.mark, 2);
  assert.match(h.controller.getState().notice, /oldest|expired|retained/i);
});

test("an inspector restart clears old frames and returns to the new Live instance", async () => {
  const h = harness();
  await settle();
  h.controller.setAt(BASE + 2000);
  h.advance(100);
  await settle();
  h.setArchive(archive([frame(1, 8)], { instance_id: "inspector-two" }));
  await h.controller.refresh();
  await settle();
  assert.equal(h.controller.getState().mode, "live");
  assert.equal(h.controller.getState().instanceId, "inspector-two");
  assert.deepEqual(copy(h.controller.getState().frames).map((sample) => sample.at_unix_ms), [BASE + 8000]);
  assert.equal(h.element("resetAllStats").disabled, false);
});

test("a new instance learned from the view invalidates in-flight frames from the old instance", async () => {
  const oldData = archive([frame(1, 1), frame(2, 2), frame(3, 3)]);
  const h = harness({ data: oldData });
  await settle();
  const oldFrames = deferred();
  let held = false;
  h.setHandler((url) => {
    if (new URL(url, "http://inspector.test").pathname === "/api/timeline" && !held) {
      held = true;
      return oldFrames.promise;
    }
  });
  let sawNew = false;
  let reverted = false;
  h.controller.subscribe((state) => {
    if (state.instanceId === "inspector-two") sawNew = true;
    if (sawNew && state.instanceId === "inspector-one") reverted = true;
  });
  const refresh = h.controller.refresh();
  await settle();
  h.setArchive(archive([frame(1, 8)], { instance_id: "inspector-two" }));
  h.controller.goLive();
  await settle();
  assert.equal(sawNew, true);
  oldFrames.resolve(response(oldData));
  await refresh;
  await settle();
  assert.equal(reverted, false, "Old frames must never be published after accepting the new instance");
  assert.equal(h.controller.getState().instanceId, "inspector-two");
  assert.deepEqual(copy(h.controller.getState().frames).map((sample) => sample.at_unix_ms), [BASE + 8000]);
});

test("range keyboard and sample buttons support backward, forward, and Live", async () => {
  const h = harness();
  await settle();
  h.element("timelinePrevious").dispatch("click");
  assert.equal(h.controller.getState().selectedAt, BASE + 2000);
  h.element("timelineRange").dispatch("keydown", { key: "ArrowLeft" });
  assert.equal(h.controller.getState().selectedAt, BASE + 1000);
  h.element("timelineRange").dispatch("keydown", { key: "ArrowRight" });
  assert.equal(h.controller.getState().selectedAt, BASE + 2000);
  h.element("timelineRange").dispatch("keydown", { key: "Home" });
  assert.equal(h.controller.getState().selectedAt, BASE + 1000);
  h.element("timelineNext").dispatch("click");
  assert.equal(h.controller.getState().selectedAt, BASE + 2000);
  h.element("timelineRange").dispatch("keydown", { key: "End" });
  assert.equal(h.controller.isLive(), true);
  assert.equal(h.element("resetAllStats").disabled, false);
});

test("source epochs and null measurements mark graph breaks without losing old history", async () => {
  const frames = [frame(1, 1), frame(2, 2, { "cell.0.assigned_cpus": null }),
    frame(3, 3, {}, { stats: 2 }), frame(4, 4)];
  const h = harness({ data: archive(frames) });
  await settle();
  const points = copy(h.controller.points("cell.0.assigned_cpus"));
  assert.equal(points.length, 4);
  assert.equal(points[1].y, null);
  assert.equal(points[2].breakBefore, true);
  assert.equal(points[3].breakBefore, true);
  const systemPoints = copy(h.controller.points("system.cpu_busy"));
  assert.equal(systemPoints[2].breakBefore, false);
});

test("charts keep original source times and skip repeated successful samples", async () => {
  const sample = (seq, seconds, error = null) => ({ epoch: 1, sample_seq: seq,
    captured_at_unix_ms: BASE + seconds * 1000, last_success_at_unix_ms: BASE + seconds * 1000, error });
  const frames = [frame(1, 2), frame(2, 3), frame(3, 4), frame(4, 5), frame(5, 6)];
  frames[0].source_meta = { stats: sample(1, 1) };
  frames[1].source_meta = { stats: sample(1, 1) };
  frames[2].source_meta = { stats: sample(1, 1, "socket unavailable") };
  frames[2].source_available = { stats: false };
  frames[3].source_meta = { stats: sample(2, 4) };
  frames[4].source_meta = { stats: sample(3, 5) };
  delete frames[4].signals["cell.0.assigned_cpus"];
  const h = harness({ data: archive(frames) });
  await settle();
  const points = copy(h.controller.points("cell.0.assigned_cpus"));
  assert.deepEqual(points.map((point) => point.x), [BASE + 1000, BASE + 4000, BASE + 4000, BASE + 5000]);
  assert.deepEqual(points.map((point) => point.y), [2, null, 8, null]);
  assert.equal(points[2].breakBefore, true);
});

test("System probe totals use counter sample times rather than kernel sample times", async () => {
  const f = frame(1, 3, { "system.total": 12, "system.completions": 4, "system.mib": 2 });
  f.source_meta = {
    counters: { epoch: 1, sample_seq: 1, captured_at_unix_ms: BASE + 1000, error: null },
    system: { epoch: 1, sample_seq: 1, captured_at_unix_ms: BASE + 2000, error: null },
  };
  const h = harness({ data: archive([f]) });
  await settle();
  assert.equal(h.controller.points("system.total")[0].x, BASE + 1000);
  assert.equal(h.controller.points("system.completions")[0].x, BASE + 1000);
  assert.equal(h.controller.points("system.mib")[0].x, BASE + 1000);
  assert.equal(h.controller.points("system.cpu_busy")[0].x, BASE + 2000);
});

test("an unavailable gap does not make an old successful sample into a new measurement", async () => {
  const frames = [frame(1, 2), frame(2, 3), frame(3, 4), frame(4, 5)];
  const sample = { epoch: 1, sample_seq: 1, captured_at_unix_ms: BASE + 1000, error: null };
  frames[0].source_meta = { stats: sample };
  frames[1].source_meta = { stats: { ...sample, error: "socket unavailable" } };
  frames[1].source_available = { stats: false };
  frames[2].source_meta = { stats: sample };
  frames[3].source_meta = { stats: { ...sample, sample_seq: 2, captured_at_unix_ms: BASE + 4000 } };
  const h = harness({ data: archive(frames) });
  await settle();
  const points = copy(h.controller.points("cell.0.assigned_cpus"));
  assert.deepEqual(points.map((point) => point.x), [BASE + 1000, BASE + 3000, BASE + 4000]);
  assert.deepEqual(points.map((point) => point.y), [2, null, 8]);
  assert.equal(points[2].breakBefore, true);
});

test("reset failure preserves the selected snapshot and successful reset clears history", async () => {
  const h = harness();
  await settle();
  const previous = h.controller.getState().view;
  h.emit("mitosis:stats-reset-start");
  assert.equal(h.element("resetAllStats").disabled, true);
  h.emit("mitosis:stats-reset-failed", { error: "reset failed" });
  assert.equal(h.controller.getState().view, previous);
  assert.match(h.controller.getState().error, /reset failed/);
  h.setArchive(archive([]));
  h.emit("mitosis:stats-reset", { epoch: 2, sample_seq: 1, reset_at_unix_ms: BASE + 9000 });
  await settle();
  assert.equal(h.controller.getState().mode, "live");
  assert.equal(h.controller.getState().frames.length, 0);
  assert.equal(h.controller.getState().view, null);
});

test("hidden pages pause archive requests and backfill missed frames without moving historical selection", async () => {
  const h = harness();
  await settle();
  h.controller.setAt(BASE + 2000);
  h.advance(75);
  await settle();
  const before = h.requests.length;
  h.context.document.visibilityState = "hidden";
  h.emit("visibilitychange");
  h.setArchive(archive([frame(1, 1), frame(2, 2), frame(3, 3), frame(4, 4), frame(5, 5)]));
  h.advance(10000, { runIntervals: true });
  await h.controller.refresh();
  await settle();
  assert.equal(h.requests.length, before, "hidden tabs cannot issue periodic or manual archive requests");
  h.context.document.visibilityState = "visible";
  h.emit("visibilitychange");
  await settle();
  const resumed = h.requests.slice(before);
  assert(resumed.some(request => request.url.includes("after_seq=3")),
    "resuming requests every retained frame after the previous cursor");
  assert.deepEqual(copy(h.controller.getState().frames).map(sample => sample.seq), [1, 2, 3, 4, 5]);
  assert.equal(h.controller.getState().mode, "history");
  assert.equal(h.controller.getState().selectedAt, BASE + 2000);
  assert.equal(h.controller.getState().view.sources.counters.mark, 2);
});

test("a window change reloads light history without using a cursor", async () => {
  const h = harness();
  await settle();
  h.controller.setWindowMs(30000);
  await settle();
  const latest = h.requests.filter((request) => new URL(request.url, "http://inspector.test").pathname === "/api/timeline").at(-1);
  assert.ok(latest.url.includes("window_ms=30000"));
  assert.ok(!latest.url.includes("after_seq="));
  assert.equal(h.controller.getState().windowMs, 30000);
});

test("static screens share the clocks without downloading full snapshots", async () => {
  const h = harness({ pathname: "/guide" });
  await settle();
  assert.equal(h.controller.getState().frames.length, 3);
  assert.equal(h.requests.some((request) => request.url.startsWith("/api/timeline/view")), false);
  let observed;
  const unsubscribe = h.controller.subscribe((state) => { observed = state; });
  assert.equal(observed, h.controller.getState());
  unsubscribe();
});

test("an empty archive has clear disabled controls and remains usable after first sample", async () => {
  const h = harness({ data: archive([]) });
  await settle();
  assert.equal(h.element("timelineRange").disabled, true);
  assert.match(h.element("timelineStatus").textContent, /waiting|no.*samples/i);
  h.setArchive(archive([frame(1, 1)]));
  await h.controller.refresh();
  await settle();
  assert.equal(h.element("timelineRange").disabled, false);
  assert.equal(h.controller.getState().latestAt, BASE + 1000);
});

test("Explore history uses its own source timestamps and deduplicates cached PMU readings", async () => {
  const frames = [frame(1, 2, { "explore.perf.instructions_per_second": 50 }),
    frame(2, 3, { "explore.perf.instructions_per_second": 99 }),
    frame(3, 4, { "explore.perf.instructions_per_second": 80 })];
  frames[0].source_meta = { "explore.perf": { epoch: 0, sample_seq: 7,
    captured_at_unix_ms: BASE + 1000, error: null } };
  frames[1].source_meta = copy(frames[0].source_meta);
  frames[2].source_meta = { "explore.perf": { epoch: 0, sample_seq: 8,
    captured_at_unix_ms: BASE + 3000, error: null } };
  const h = harness({ data: archive(frames) });
  await settle();
  const points = copy(h.controller.points("explore.perf.instructions_per_second"));
  assert.deepEqual(points.map((point) => point.x), [BASE + 1000, BASE + 3000]);
  assert.deepEqual(points.map((point) => point.y), [50, 80]);
});

test("every HTML workspace has the shared time control and loads it before page code", () => {
  for (const name of ["stats.html", "scheduling.html", "callbacks.html", "system.html", "config.html",
    "inspector.html", "guide.html"]) {
    const file = path.join(web, name);
    assert.ok(fs.existsSync(file), `${name} must be a navigable time-aware workspace`);
    const html = fs.readFileSync(file, "utf8");
    assert.match(html, /id="timelineRange"[^>]*type="range"|type="range"[^>]*id="timelineRange"/);
    assert.ok(html.indexOf('id="timelineBar"') > html.indexOf('</header>'));
    assert.ok(html.indexOf('id="timelineBar"') < html.indexOf('class="workspace-shell"'));
    assert.match(html, /src="\/assets\/polling\.js"/);
    assert.match(html, /src="\/assets\/timeline\.js"/);
    // The server renders the shared workspace navigation, including the guide, into this slot.
    assert.ok(html.includes('<!-- workspace-navigation -->'), `${name} must use the shared navigation`);
  }
});

(async () => {
  let failed = 0;
  for (const { name, run } of tests) {
    try { await run(); process.stdout.write(`PASS ${name}\n`); }
    catch (error) { failed += 1; process.stderr.write(`FAIL ${name}\n${error.stack}\n`); }
  }
  if (failed) process.exitCode = 1;
  else process.stdout.write(`Timeline contracts: ${tests.length} passed\n`);
})();
