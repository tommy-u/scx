"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const webRoot = path.join(__dirname, "..", "src", "web");

class FakeElement {
  constructor() {
    this.children = [];
    this.classList = {
      add() {},
      remove() {},
      toggle() {},
    };
    this.textContent = "";
  }

  append(...children) {
    this.children.push(...children);
  }

  replaceChildren(...children) {
    this.children = children;
  }
}

async function testStatsVisuals() {
  const html = fs.readFileSync(path.join(webRoot, "stats.html"), "utf8");
  const chartsScript = html.indexOf('<script src="/assets/charts.js" defer>');
  const statsScript = html.indexOf('<script src="/assets/stats.js" defer>');
  const historySection = html.indexOf('id="cellHistoryHeading"');
  const rawMetrics = html.indexOf('id="globalStatsHeading"');

  assert(chartsScript >= 0, "stats page loads the shared chart helper");
  assert(chartsScript < statsScript, "chart helper loads before stats renderer");
  assert(historySection >= 0, "stats page exposes a cell history section");
  assert(historySection < rawMetrics, "cell history appears before raw metrics");
  assert(html.includes('id="cellUtilizationChart"'));
  assert(html.includes('id="cellBalanceChart"'));

  const elements = new Map();
  const element = (selector) => {
    if (!elements.has(selector)) elements.set(selector, new FakeElement());
    return elements.get(selector);
  };
  const histories = [];
  const lineCharts = [];

  class FakeHistory {
    constructor(maxPoints) {
      this.maxPoints = maxPoints;
      this.samples = [];
      histories.push(this);
    }

    push(timestamp, values) {
      this.samples.push({ timestamp, values });
    }

    points(key) {
      return this.samples
        .filter((sample) => Number.isFinite(sample.values[key]))
        .map((sample) => ({ x: sample.timestamp, y: sample.values[key] }));
    }
  }

  const snapshot = {
    metrics: {
      cells: {
        0: {
          smoothed_util_pct: 61,
          util_pct: 63.5,
          demand_borrow_pct: 4.5,
          borrowed_pct: 8,
          lent_pct: 1.5,
        },
        1: {
          util_pct: 47,
          borrowed_pct: null,
        },
      },
    },
    error: null,
  };

  const context = {
    console,
    Date,
    Intl,
    MitosisCharts: {
      History: FakeHistory,
      drawLineChart(canvas, series, options) {
        lineCharts.push({ canvas, series, options });
      },
    },
    document: {
      querySelector: element,
      createElement: () => new FakeElement(),
    },
    fetch: async () => ({
      ok: true,
      json: async () => snapshot,
    }),
    setInterval() {},
  };

  vm.runInNewContext(
    fs.readFileSync(path.join(webRoot, "stats.js"), "utf8"),
    context,
    { filename: "stats.js" },
  );
  await new Promise((resolve) => setImmediate(resolve));

  assert.strictEqual(histories.length, 1);
  assert.strictEqual(histories[0].maxPoints, 300);
  assert.strictEqual(histories[0].samples.length, 1);

  const values = histories[0].samples[0].values;
  assert.strictEqual(values["cell.0.util"], 61, "smoothed utilization wins");
  assert.strictEqual(values["cell.1.util"], 47, "raw utilization is the fallback");
  assert.strictEqual(values["cell.0.demand"], 4.5);
  assert.strictEqual(values["cell.0.borrowed"], 8);
  assert.strictEqual(values["cell.0.lent"], 1.5);
  assert(!Object.hasOwn(values, "cell.1.borrowed"), "missing values stay absent");

  assert.strictEqual(lineCharts.length, 2);
  assert.deepStrictEqual(
    Array.from(lineCharts[0].series, (series) => series.label),
    ["Cell 0", "Cell 1"],
  );
  assert.deepStrictEqual(
    Array.from(lineCharts[1].series, (series) => series.label),
    ["Cell 0 demand", "Cell 0 borrowed", "Cell 0 lent"],
  );
  assert.strictEqual(lineCharts[0].options.unit, "%");
  assert.strictEqual(lineCharts[1].options.unit, "%");
}

testStatsVisuals()
  .then(() => console.log("stats visuals contract: ok"))
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
