"use strict";

const assert = require("assert");
const {
  History,
  drawLineChart,
  drawBarChart,
  drawHistogram,
} = require("../src/web/charts.js");

function fakeCanvas(width = 320, height = 160) {
  const calls = [];
  const context = new Proxy(
    {
      calls,
      measureText(text) {
        return { width: String(text).length * 6 };
      },
      setTransform(...args) {
        calls.push(["setTransform", ...args]);
      },
    },
    {
      get(target, property) {
        if (property in target) {
          return target[property];
        }
        return (...args) => calls.push([property, ...args]);
      },
      set(target, property, value) {
        target[property] = value;
        calls.push(["set", property, value]);
        return true;
      },
    },
  );

  return {
    clientWidth: width,
    clientHeight: height,
    width: 0,
    height: 0,
    getBoundingClientRect() {
      return { width, height };
    },
    getContext(kind) {
      assert.strictEqual(kind, "2d");
      return context;
    },
    context,
  };
}

function testHistory() {
  const history = new History(3);
  history.push(100, { cpu: 1, irq: 0.25 });
  history.push(200, { cpu: 2 });
  history.push(300, { cpu: null, irq: 0.75 });
  history.push(400, { cpu: 4, irq: undefined });

  assert.deepStrictEqual(history.points("cpu"), [
    { x: 200, y: 2 },
    { x: 400, y: 4 },
  ]);
  assert.deepStrictEqual(history.points("irq"), [{ x: 300, y: 0.75 }]);

  history.clear();
  assert.deepStrictEqual(history.points("cpu"), []);
}

function testCharts() {
  global.window = { devicePixelRatio: 2 };

  const lineCanvas = fakeCanvas();
  drawLineChart(
    lineCanvas,
    [
      {
        label: "CPU",
        color: "#2f7d62",
        points: [
          { x: 100, y: 10 },
          { x: 200, y: Number.NaN },
          { x: 300, y: 30 },
        ],
      },
      { label: "empty", color: "#777", points: [] },
    ],
    { unit: "%", minY: 0, maxY: 100 },
  );
  assert.strictEqual(lineCanvas.width, 640);
  assert.strictEqual(lineCanvas.height, 320);
  assert(lineCanvas.context.calls.some((call) => call[0] === "lineTo"));
  assert(
    lineCanvas.context.calls.some(
      (call) => call[0] === "fillText" && /^\d{2}:\d{2}:\d{2}$/.test(call[1]),
    ),
    "rolling charts should label their time range",
  );

  const singlePointCanvas = fakeCanvas();
  drawLineChart(singlePointCanvas, [
    { label: "Current", color: "#2f7d62", points: [{ x: 100, y: 10 }] },
  ], { unit: "%" });
  assert(
    singlePointCanvas.context.calls.some((call) => call[0] === "arc"),
    "a single live sample must remain visible",
  );

  const stableWidth = lineCanvas.width;
  drawLineChart(lineCanvas, [], { unit: "%" });
  assert.strictEqual(lineCanvas.width, stableWidth);

  const barCanvas = fakeCanvas();
  drawBarChart(
    barCanvas,
    [
      { label: "dispatch", value: 4.25, color: "#2f7d62" },
      { label: "invalid", value: Number.NaN, color: "#777" },
    ],
    { unit: "ms/s" },
  );
  assert(barCanvas.context.calls.some((call) => call[0] === "fillRect"));

  const histogramCanvas = fakeCanvas();
  drawHistogram(
    histogramCanvas,
    [
      { label: "1-2 us", value: 8 },
      { label: "2-4 us", value: Infinity },
      { label: "4-8 us", value: 2 },
    ],
    { unit: "events" },
  );
  assert(histogramCanvas.context.calls.some((call) => call[0] === "fillText"));

  assert.doesNotThrow(() => drawBarChart(fakeCanvas(0, 0), [], {}));
  assert.doesNotThrow(() => drawHistogram(fakeCanvas(), null, {}));

  delete global.window;
}

testHistory();
testCharts();
console.log("charts contract: ok");
