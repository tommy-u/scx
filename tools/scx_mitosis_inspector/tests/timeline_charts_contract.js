"use strict";

const assert = require("node:assert/strict");
const { test } = require("node:test");
const { drawLineChart } = require("../src/web/charts.js");

function canvas() {
  const calls = [];
  const context = new Proxy({
    measureText(text) { return { width: String(text).length * 6 }; },
  }, {
    get(target, key) {
      return key in target ? target[key] : (...args) => calls.push([key, ...args]);
    },
    set(target, key, value) { target[key] = value; calls.push(["set", key, value]); return true; },
  });
  return { clientWidth: 500, clientHeight: 240, getContext: () => context,
    getBoundingClientRect: () => ({ width: 500, height: 240 }), calls };
}

function seriesPath(view, color) {
  let currentColor;
  let path = [];
  const result = [];
  for (const call of view.calls) {
    if (call[0] === "set" && call[1] === "strokeStyle") currentColor = call[2];
    if (call[0] === "beginPath") path = [];
    if (call[0] === "moveTo" || call[0] === "lineTo") path.push(call[0]);
    if (call[0] === "stroke" && currentColor === color) result.push(...path);
  }
  return result;
}

test("scrubbed lines break between observer epochs even when samples are adjacent", () => {
  const view = canvas();
  drawLineChart(view, [{ color: "#123456", points: [
    { x: 1000, y: 4 }, { x: 2000, y: 6 },
    { x: 3000, y: 1, breakBefore: true }, { x: 4000, y: 2 },
  ] }], { showLegend: false, maxGapMs: 3000 });
  assert.deepEqual(seriesPath(view, "#123456"), ["moveTo", "lineTo", "moveTo", "lineTo"]);
});

test("a selected time bounds the graph and never draws future measurements", () => {
  const view = canvas();
  drawLineChart(view, [{ color: "#123456", points: [
    { x: 1000, y: 4 }, { x: 2000, y: 6 }, { x: 3000, y: 100 },
  ] }], { showLegend: false, minX: 1000, maxX: 2500 });
  assert.deepEqual(seriesPath(view, "#123456"), ["moveTo", "lineTo"]);
  assert.equal(view.calls.filter(([method]) => method === "arc").length, 2,
    "future points cannot leak through point markers");
  const times = view.calls.filter(([method, value]) => method === "fillText" && /^\d\d:\d\d:\d\d$/.test(value));
  const local = value => new Date(value).toLocaleTimeString("en-US", {
    hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23",
  });
  assert.deepEqual(times.map(call => call[1]), [local(1000), local(2500)],
    "graphs share the selected timeline bounds rather than each source's newest point");
});

test("graph time labels use the same local timezone as the timeline clocks", () => {
  const previous = process.env.TZ;
  process.env.TZ = "America/Los_Angeles";
  try {
    const at = 1700000000000;
    const view = canvas();
    drawLineChart(view, [{ points: [{ x: at, y: 1 }, { x: at + 1000, y: 2 }] }], { showLegend: false });
    const expected = new Date(at).toLocaleTimeString("en-US", {
      hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23",
    });
    assert(view.calls.some(([method, label]) => method === "fillText" && label === expected),
      "UTC axis labels cannot disagree with local timeline clocks");
  } finally {
    if (previous === undefined) delete process.env.TZ;
    else process.env.TZ = previous;
  }
});
