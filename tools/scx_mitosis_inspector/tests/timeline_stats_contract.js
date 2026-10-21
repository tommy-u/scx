"use strict";

const assert = require("node:assert/strict");
const { test } = require("node:test");
const { page, stats, response, meta, collector, settle } = require("./page_test_support");

function snapshot(sequence, epoch, at, cpus, utilization, reconfigurations) {
  return { ...stats(sequence, epoch), meta: meta(sequence, epoch, at),
    collector: collector(epoch), cpu_cells: { 0: 0 }, cpu_cells_error: null,
    metrics: { rebalance_count: reconfigurations,
      cells: { 0: { num_cpus: cpus, util_pct: utilization, demand_borrow_pct: 0, lent_pct: 0 } } } };
}

function controlled(initial) {
  let state = initial;
  const listeners = new Set();
  return {
    getState: () => state,
    isLive: () => state.mode === "live",
    subscribe(fn) { listeners.add(fn); fn(state); return () => listeners.delete(fn); },
    refresh: async () => {},
    keys(prefix = "") {
      return [...new Set(state.frames.flatMap(frame => Object.keys(frame.signals)))].filter(key => key.startsWith(prefix));
    },
    points(key) {
      const cutoff = state.mode === "live" ? state.latestAt : state.selectedAt;
      return state.frames.filter(frame => frame.at_unix_ms <= cutoff)
        .map(frame => ({ x: frame.at_unix_ms, y: frame.signals[key] ?? null }));
    },
    emit(next) { state = next; listeners.forEach(fn => fn(state)); },
  };
}

function selection(selectedSnapshot, mode = "history", at = 10000) {
  return { mode, selectedAt: mode === "live" ? null : at, nowMs: 30000,
    oldestAt: 10000, latestAt: 30000, retentionMs: 1800000,
    frames: [
      { at_unix_ms: 10000, signals: { "cell.0.util": 50, "cell.0.used_cpus": 4, "cell.0.assigned_cpus": 8 } },
      { at_unix_ms: 30000, signals: { "cell.0.util": 75, "cell.0.used_cpus": 9, "cell.0.assigned_cpus": 12 } },
    ],
    view: { at_unix_ms: at, sources: { stats: selectedSnapshot }, source_errors: {} },
    loading: false, error: null, notice: null };
}

test("Scheduler renders retained CPU allocation and reconfigurations without starting live stats requests", async () => {
  const past = snapshot(1, 1, 10000, 8, 50, 33);
  const live = snapshot(10, 2, 30000, 12, 75, 99);
  const timeline = controlled(selection(past));
  const requests = [];
  const view = page("stats.js", url => { requests.push(url); return response(live); },
    { globals: { MitosisTimeline: timeline }, now: 30000 });
  await settle();
  assert.equal(view.element("#reconfigurationCount").textContent, "33");
  assert.equal(view.element("#cellCount").textContent, "1");
  const cells = view.element("#cellStatsBody").children;
  assert.equal(cells[0].children[1].textContent, "8");
  assert(!requests.some(url => url === "/api/stats" || url.startsWith("/api/stats/history")),
    "legacy live polling cannot overwrite the selected historical snapshot");
  assert.match(view.element("#statusText").textContent, /historical|past/i);
});

test("Scheduler can scrub back across lower epochs and sequences after returning to Live", async () => {
  const past = snapshot(1, 1, 10000, 8, 50, 33);
  const live = snapshot(10, 2, 30000, 12, 75, 99);
  const timeline = controlled(selection(past));
  const view = page("stats.js", () => response(live), { globals: { MitosisTimeline: timeline }, now: 30000 });
  await settle();
  timeline.emit(selection(live, "live", 30000));
  assert.equal(view.element("#reconfigurationCount").textContent, "99");
  timeline.emit(selection(past));
  assert.equal(view.element("#reconfigurationCount").textContent, "33");
  assert.equal(view.element("#cellStatsBody").children[0].children[1].textContent, "8");
});

test("historical CPU ownership remains visible using selected-time availability", async () => {
  const past = snapshot(1, 1, 10000, 8, 50, 33);
  const timeline = controlled(selection(past));
  const view = page("stats.js", () => response(past), { globals: { MitosisTimeline: timeline }, now: 30000 });
  await settle();
  const topologyStatus = view.element("#cpuTopology").querySelector("#cpuTopologyStatus").textContent;
  assert(topologyStatus.includes("1 cells"),
    "wall-clock age must not turn a valid past placement into unknown ownership");
  assert(!/ownership unavailable/i.test(topologyStatus));
});

test("a pending or unavailable selected snapshot clears values instead of showing current stats", async () => {
  const past = snapshot(1, 1, 10000, 8, 50, 33);
  const timeline = controlled(selection(past));
  const view = page("stats.js", () => response(past), { globals: { MitosisTimeline: timeline }, now: 30000 });
  await settle();
  const pending = { ...selection(past), view: null, loading: true };
  timeline.emit(pending);
  assert.equal(view.element("#reconfigurationCount").textContent, "--");
  assert.equal(view.element("#cellCount").textContent, "--");
  assert.equal(view.element("#cellStatsBody").children.length, 0);
  assert.match(view.element("#sourceStatus").textContent, /loading|waiting/i);
  const unavailable = { ...selection(past), view: {
    at_unix_ms: 10000, sources: { stats: null }, source_errors: { stats: "No stats at selected time" },
  } };
  timeline.emit(unavailable);
  assert.equal(view.element("#cellStatsBody").children.length, 0);
  assert.match(view.element("#sourceStatus").textContent, /No stats at selected time/i);
});
