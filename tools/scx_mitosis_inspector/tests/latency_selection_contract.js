"use strict";

const assert = require("node:assert/strict");
const { test } = require("node:test");
const { counters, migrations, stats, system, meta, liveTimeline } = require("./page_test_support");

// Each latency picker lives on the page for the question it answers.
const pages = { "#callbackLatencyMetric": "callbacks.js", "#schedulerLatencyMetric": "scheduling.js",
  "#softirqLatencyMetric": "system.js", "#hardirqLatencyMetric": "system.js" };

function sources() {
  const snapshot = counters();
  snapshot.callback_timings = [
    { callback: "enqueue", buckets: [0, 2, 0, 0] },
    { callback: "stopping", buckets: [0, 0, 0, 5] },
  ];
  snapshot.scheduler_timings = [
    { metric: "wakeup_to_running", buckets: [0, 1, 0] },
    { metric: "switch", buckets: [0, 0, 4] },
  ];
  snapshot.softirqs = [
    { vector: 1, name: "TIMER", timing_buckets: [0, 3, 0] },
    { vector: 3, name: "NET_RX", timing_buckets: [0, 0, 6] },
  ];
  snapshot.hardirqs = { ...snapshot.hardirqs, available: true, rows: [
    { irq: 1, name: "first", timing_buckets: [0, 1, 0] },
    { irq: 2, name: "second", timing_buckets: [0, 0, 2] },
  ] };
  return { counters: snapshot, migrations: migrations(), stats: stats(), system: system() };
}

async function viewFor(current, id) {
  const view = liveTimeline(pages[id], current);
  await view.ready();
  return view;
}

function inputs(view, id) {
  return view.element(id).querySelector("fieldset").children.map((label) => label.children[0]);
}

for (const id of ["#callbackLatencyMetric", "#schedulerLatencyMetric", "#softirqLatencyMetric", "#hardirqLatencyMetric"]) {
  test(id + " preserves checkbox identities and multiple selections during fresh polls", async () => {
    const current = sources();
    const view = await viewFor(current, id);
    const original = inputs(view, id);
    assert.equal(original.length, 2, "the selector offers independent checkbox choices");
    original.forEach((input) => { input.checked = true; });
    current.counters = { ...current.counters, meta: meta(2) };
    await view.advance();
    const updated = inputs(view, id);
    assert.equal(updated[0], original[0]);
    assert.equal(updated[1], original[1]);
    assert(updated.every((input) => input.checked));
    assert.match(view.element(id).querySelector("summary").textContent, /2 selected/);
  });
}

test("callback selections overlay correctly aligned duration buckets with stable colors", async () => {
  const current = sources();
  const view = await viewFor(current, "#callbackLatencyMetric");
  const choices = inputs(view, "#callbackLatencyMetric");
  assert.equal(choices.length, 2);
  choices.forEach((input) => { input.checked = true; });
  const calls = [];
  view.context.MitosisCharts.drawHistogramSeries = (canvas, series) => calls.push({ canvas, series });
  view.element("#callbackLatencyMetric").listeners.get("change")();
  const callback = calls.find((call) => call.canvas === view.element("#callbackLatencyChart"));
  assert(callback, "selection changes redraw the shared histogram");
  assert.deepEqual(Array.from(callback.series, (item) => item.label), ["enqueue", "stopping"]);
  assert.deepEqual(Array.from(callback.series[0].buckets, (bucket) => bucket.value), [2, 0, 0]);
  assert.deepEqual(Array.from(callback.series[1].buckets, (bucket) => bucket.value), [0, 0, 5]);
  assert.deepEqual(Array.from(callback.series[0].buckets, (bucket) => bucket.label),
    Array.from(callback.series[1].buckets, (bucket) => bucket.label));
  assert.notEqual(callback.series[0].color, callback.series[1].color);
  const stoppingColor = callback.series[1].color;
  choices[0].checked = false;
  calls.length = 0;
  view.element("#callbackLatencyMetric").listeners.get("change")();
  assert.equal(calls[0].series[0].color, stoppingColor, "deselecting a peer cannot recolor a series");
  choices[1].checked = false;
  calls.length = 0;
  view.element("#callbackLatencyMetric").listeners.get("change")();
  assert.equal(calls[0].series.length, 0, "an explicit empty selection stays empty");
});

test("new and renamed softirq choices preserve surviving selections", async () => {
  const current = sources();
  const view = await viewFor(current, "#softirqLatencyMetric");
  const original = inputs(view, "#softirqLatencyMetric");
  assert.equal(original.length, 2);
  original[0].checked = false;
  original[1].checked = true;
  current.counters = { ...current.counters, meta: meta(2), softirqs: [
    { ...current.counters.softirqs[1], name: "NET_RX updated" },
    { vector: 9, name: "RCU", timing_buckets: [1] },
  ] };
  await view.advance();
  const updated = inputs(view, "#softirqLatencyMetric");
  assert.equal(updated[0], original[1]);
  assert.equal(updated[0].checked, true);
  assert.equal(updated[1].checked, false);
  assert.equal(view.element("#softirqLatencyMetric").querySelector("summary").textContent, "3 NET_RX updated");
});

test("hardirq table shows ten currently busiest IRQs without limiting available histogram choices", async () => {
  const current = sources();
  const rows = Array.from({ length: 24 }, (_, irq) => ({
    irq, name: "device " + irq, count: 1000 - irq, rate_per_second: irq,
    samples: 1, p95_ns: 100, p99_ns: 200, timing_buckets: [1],
  }));
  current.counters.hardirqs.rows = rows;
  const view = await viewFor(current, "#hardirqLatencyMetric");
  const displayed = view.element("#hardirqRows").children;
  assert.equal(displayed.length, 10);
  assert.deepEqual(displayed.map((row) => row.children[0].textContent),
    Array.from({ length: 10 }, (_, index) => String(23 - index)));
  assert(displayed.every((row) => row.children.length === 5));
  assert.equal(inputs(view, "#hardirqLatencyMetric").length, 24);
  assert.equal(current.counters.hardirqs.rows, rows, "display sorting cannot mutate the source snapshot");
});

test("a selected metric remains selected after disappearing and reappearing", async () => {
  const current = sources();
  const view = await viewFor(current, "#softirqLatencyMetric");
  const choices = inputs(view, "#softirqLatencyMetric");
  choices[0].checked = false;
  choices[1].checked = true;
  const original = current.counters.softirqs;
  current.counters = { ...current.counters, meta: meta(2), softirqs: [original[0]] };
  await view.advance();
  current.counters = { ...current.counters, meta: meta(3), softirqs: original };
  await view.advance();
  assert.equal(inputs(view, "#softirqLatencyMetric")[1].checked, true);
});
