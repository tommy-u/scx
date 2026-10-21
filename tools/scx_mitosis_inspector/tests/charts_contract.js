"use strict";

const assert = require("assert");
const {
  History,
  drawLineChart,
  drawBarChart,
  drawHistogram,
  drawHistogramSeries,
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

function seriesPathCalls(canvas, color) {
  let strokeStyle;
  let path = [];
  const calls = [];
  for (const call of canvas.context.calls) {
    if (call[0] === "set" && call[1] === "strokeStyle") strokeStyle = call[2];
    if (call[0] === "beginPath") path = [];
    if (call[0] === "moveTo" || call[0] === "lineTo") path.push(call);
    if (call[0] === "stroke" && strokeStyle === color) calls.push(...path);
  }
  return calls;
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

function testHistoryPreservesGaps() {
  const history = new History(8);
  history.push(1000, { cpu: 2 });
  history.push(2000, { cpu: null });
  history.push(3000, {});
  history.push(4000, { cpu: Number.NaN });
  history.push(5000, { cpu: Infinity });
  history.push(6000, { cpu: "3" });
  history.push(7000, { cpu: 0 });

  assert.deepStrictEqual(history.points("cpu", { preserveGaps: true }), [
    { x: 1000, y: 2 },
    { x: 2000, y: null },
    { x: 3000, y: null },
    { x: 4000, y: null },
    { x: 5000, y: null },
    { x: 6000, y: null },
    { x: 7000, y: 0 },
  ], "opt-in history points preserve unavailable sample timestamps");
  assert.deepStrictEqual(history.points("cpu"), [
    { x: 1000, y: 2 },
    { x: 7000, y: 0 },
  ], "existing callers still receive only finite measurements");
}

function testHistoryExpiresByTime() {
  const history = new History(8);
  history.push(1000, { cpu: 1 });
  history.push(4000, { cpu: 4 });
  history.push(3000, { cpu: 3 });
  history.push(5000, { cpu: 5 });

  assert.strictEqual(typeof history.expireBefore, "function",
    "history supports a time-based retention cutoff");
  history.expireBefore(3000);
  assert.deepStrictEqual(history.points("cpu"), [
    { x: 4000, y: 4 },
    { x: 3000, y: 3 },
    { x: 5000, y: 5 },
  ], "expiration removes older samples and keeps the cutoff boundary");
  history.expireBefore(Number.NaN);
  assert.strictEqual(history.samples.length, 3, "an invalid cutoff cannot erase history");
  history.expireBefore(6000);
  assert.deepStrictEqual(history.points("cpu"), []);
  history.push(7000, { cpu: 7 });
  assert.deepStrictEqual(history.points("cpu"), [{ x: 7000, y: 7 }],
    "collecting resumes after all previous samples expire");
}

function testChartCollectionGaps() {
  const series = [{
    label: "CPU",
    color: "#123456",
    points: [
      { x: 1000, y: 10 },
      { x: 2000, y: 12 },
      { x: 62000, y: 14 },
      { x: 63000, y: 16 },
    ],
  }];
  const canvas = fakeCanvas();
  drawLineChart(canvas, series, { showLegend: false, maxGapMs: 3000 });
  assert.deepStrictEqual(seriesPathCalls(canvas, "#123456").map((call) => call[0]), [
    "moveTo", "lineTo", "moveTo", "lineTo",
  ], "a 60-second collection gap cannot connect otherwise adjacent one-second samples");

  const defaultCanvas = fakeCanvas();
  drawLineChart(defaultCanvas, series, { showLegend: false });
  assert.deepStrictEqual(seriesPathCalls(defaultCanvas, "#123456").map((call) => call[0]), [
    "moveTo", "lineTo", "lineTo", "lineTo",
  ], "charts without an explicit gap threshold keep their existing behavior");

  const boundaryCanvas = fakeCanvas();
  drawLineChart(boundaryCanvas, [{ color: "#123456", points: [
    { x: 1000, y: 10 }, { x: 4000, y: 12 }, { x: 7001, y: 14 },
  ] }], { showLegend: false, maxGapMs: 3000 });
  assert.deepStrictEqual(seriesPathCalls(boundaryCanvas, "#123456").map((call) => call[0]), [
    "moveTo", "lineTo", "moveTo",
  ], "a gap at the threshold remains connected; only a larger gap starts a new path");
}

function testUnavailableChartSamples() {
  for (const unavailable of [null, undefined, Number.NaN, Infinity]) {
    const canvas = fakeCanvas();
    drawLineChart(canvas, [{ color: "#123456", points: [
      { x: 1000, y: 10 },
      { x: 2000, y: 12 },
      { x: 3000, y: unavailable },
      { x: 4000, y: 14 },
      { x: 5000, y: 16 },
    ] }], { showLegend: false, maxGapMs: 3000 });
    assert.deepStrictEqual(seriesPathCalls(canvas, "#123456").map((call) => call[0]), [
      "moveTo", "lineTo", "moveTo", "lineTo",
    ], "an explicit unavailable sample breaks the path even without a large time gap");
  }
}

function testLargeRetainedHistory() {
  const sampleCount = 1801;
  const series = Array.from({ length: 72 }, (_, cell) => ({
    label: `Cell ${cell}`,
    points: Array.from({ length: sampleCount }, (_, sample) => ({
      x: 1000000 + sample * 1000,
      y: cell + sample % 2,
    })),
  }));
  const canvas = fakeCanvas();
  assert.doesNotThrow(() => drawLineChart(canvas, series, {
    showLegend: false, maxGapMs: 3000, unit: "%",
  }), "thirty minutes of many cell series cannot exceed JavaScript's argument limit");
  const markers = canvas.context.calls.filter((call) => call[0] === "arc");
  assert.strictEqual(markers.length, series.length * sampleCount,
    "all retained measurements remain visible");
  assert(markers.every((call) => Number.isFinite(call[1]) && Number.isFinite(call[2])),
    "large-history axis bounds produce finite coordinates");
  assert(canvas.context.calls.some((call) => call[0] === "fillText" && call[1] === "72.0%"),
    "the axis includes the largest value across every series");
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

  const externalLegendCanvas = fakeCanvas();
  drawLineChart(externalLegendCanvas, [
    { label: "Current", points: [{ x: 100, y: 1 }] },
  ], { showLegend: false });
  assert(!externalLegendCanvas.context.calls.some(
    (call) => call[0] === "fillText" && call[1] === "Current",
  ), "a chart with an external legend must not draw a second truncated legend");

  const capacityCanvas = fakeCanvas();
  drawLineChart(capacityCanvas, [
    { label: "Capacity", points: [{ x: 100, y: 4 }, { x: 200, y: 6 }], dash: [6, 4] },
  ], { unit: " CPUs" });
  assert(capacityCanvas.context.calls.some(
    (call) => call[0] === "setLineDash" && call[1].join(",") === "6,4",
  ), "capacity lines are visually distinct from measured CPU use");
  assert.deepStrictEqual(capacityCanvas.context.calls.filter((call) => call[0] === "setLineDash").at(-1)[1], [],
    "dash styling cannot leak into the next chart");
  for (const call of capacityCanvas.context.calls.filter((call) => call[0] === "fillText" && call[1].endsWith(" CPUs"))) {
    assert(call[2] >= capacityCanvas.context.measureText(call[1]).width + 2,
      "CPU axis labels fit inside the canvas");
  }

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

function testHistogramSeries() {
  const canvas = fakeCanvas(640, 260);
  drawHistogramSeries(canvas, [
    { label: "enqueue", color: "#123456", buckets: [
      { label: "3ns", value: 2 }, { label: "7ns", value: 0 },
    ] },
    { label: "stopping", color: "#654321", buckets: [
      { label: "3ns", value: 0 }, { label: "7ns", value: 8 },
    ] },
  ]);
  const outlines = canvas.context.calls.filter((call) => call[0] === "strokeRect");
  assert.strictEqual(outlines.length, 4, "each series has an outline in the shared bucket slots");
  assert.strictEqual(outlines[0][1], outlines[2][1], "the first bins share an x coordinate");
  assert.strictEqual(outlines[1][1], outlines[3][1], "the second bins share an x coordinate");
  assert.strictEqual(outlines[0][4] * 4, outlines[3][4], "both series use one global count scale");
  for (const label of ["enqueue", "stopping", "3ns", "7ns"]) {
    assert(canvas.context.calls.some((call) => call[0] === "fillText" && call[1] === label));
  }
  assert(canvas.context.calls.some((call) => call[0] === "set" && call[1] === "globalAlpha" && call[2] < 1));
  assert.strictEqual(canvas.context.globalAlpha, 1, "opacity cannot leak to the next chart");
  for (const call of outlines) assert(call.slice(1).every(Number.isFinite));
  const empty = fakeCanvas();
  drawHistogramSeries(empty, [{ label: "missing", buckets: [] }]);
  assert(empty.context.calls.some((call) => call[0] === "fillText" && call[1] === "No data"));
}

testHistory();
testHistoryPreservesGaps();
testHistoryExpiresByTime();
testUnavailableChartSamples();
testChartCollectionGaps();
testLargeRetainedHistory();
testCharts();
testHistogramSeries();
console.log("charts contract: ok");
