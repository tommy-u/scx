"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const web = path.join(__dirname, "..", "src", "web");
const html = fs.readFileSync(path.join(web, "system.html"), "utf8");
const source = fs.readFileSync(path.join(web, "system.js"), "utf8");

function node() {
  return {
    classList: { add() {}, remove() {} },
    append() {},
    replaceChildren() {},
    textContent: "",
  };
}

function response(value) {
  return { ok: true, json: async () => value };
}

async function settle() {
  await Promise.resolve();
  await Promise.resolve();
  await new Promise((resolve) => setImmediate(resolve));
}

async function main() {
  assert.match(html, /id="resourceHistory"/);
  for (const id of [
    "pressureHistory",
    "frequencyHistory",
    "networkHistory",
    "irqHistory",
    "blockRateHistory",
    "blockThroughputHistory",
  ]) {
    assert.match(html, new RegExp(`id="${id}"`));
  }
  assert(
    html.indexOf("/assets/charts.js") < html.indexOf("/assets/system.js"),
    "charts.js must load before system.js",
  );

  const nodes = new Map();
  const chartCalls = [];
  const fetchCalls = [];
  const systemSnapshot = {
    interval_ms: 2000,
    cpu: { available: true, value: { busy_pct: 50 } },
    sched_ext: { available: true, value: { state: "enabled" } },
    pressure: {
      cpu: { available: true, value: { some: { avg10: 1.5 } } },
      memory: { available: true, value: { some: { avg10: 2.5 } } },
      io: { available: true, value: { some: { avg10: 3.5 } } },
    },
    memory: { available: true, value: { total_bytes: 1024 } },
    frequencies: {
      available: true,
      value: { average_khz: 2500000, cpus: [] },
    },
    network: {
      available: true,
      value: {
        interfaces: [
          { interface: "eth0", rx_bytes_per_second: 1000, tx_bytes_per_second: 2000, rx_errors_total: 0, tx_errors_total: 0, rx_dropped_total: 0, tx_dropped_total: 0 },
          { interface: "eth1", rx_bytes_per_second: 3000, tx_bytes_per_second: 4000, rx_errors_total: 0, tx_errors_total: 0, rx_dropped_total: 0, tx_dropped_total: 0 },
        ],
      },
    },
  };
  const countersSnapshot = {
    interrupt_cpu: [
      { total_utilization_pct: 10 },
      { total_utilization_pct: 30 },
    ],
    block_io: {
      available: true,
      completion_rate_per_second: 7,
      completed_bytes_per_second: 8 * 1024 * 1024,
    },
  };

  class History {
    constructor(maxPoints) {
      assert.strictEqual(maxPoints, 300, "2 second samples should retain 10 minutes");
      this.rows = [];
    }
    push(at, values) {
      this.rows.push({ at, values });
    }
    points(key) {
      return this.rows
        .filter(({ values }) => Number.isFinite(values[key]))
        .map(({ at, values }) => ({ x: at, y: values[key] }));
    }
  }

  const context = {
    console,
    document: {
      createElement() { return node(); },
      querySelector(selector) {
        if (!nodes.has(selector)) nodes.set(selector, node());
        return nodes.get(selector);
      },
    },
    fetch: async (url) => {
      fetchCalls.push(url);
      if (url === "/api/system") return response(systemSnapshot);
      if (url === "/api/counters") return response(countersSnapshot);
      throw new Error(`unexpected URL ${url}`);
    },
    Intl,
    Date,
    Promise,
    setInterval() {},
    MitosisCharts: {
      History,
      drawLineChart(canvas, series, options) {
        chartCalls.push({ canvas, series, options });
      },
    },
  };
  vm.runInNewContext(source, context, { filename: "system.js" });
  await settle();

  assert.deepStrictEqual(fetchCalls.sort(), ["/api/counters", "/api/system"]);
  assert.strictEqual(chartCalls.length, 6);
  assert.deepStrictEqual(
    Array.from(chartCalls[0].series, (series) => series.points[0].y),
    [1.5, 2.5, 3.5],
  );
  assert.strictEqual(chartCalls[1].series[0].points[0].y, 2500);
  assert.deepStrictEqual(
    Array.from(chartCalls[2].series, (series) => series.points[0].y),
    [4000, 6000],
  );
  assert.strictEqual(chartCalls[3].series[0].points[0].y, 20);
  assert.strictEqual(chartCalls[4].series[0].points[0].y, 7);
  assert.strictEqual(chartCalls[5].series[0].points[0].y, 8);

  systemSnapshot.frequencies.value.average_khz = null;
  await context.refresh();
  const frequencyCall = chartCalls[chartCalls.length - 5];
  assert.strictEqual(frequencyCall.series[0].points.length, 1, "missing frequency is not 0 MHz");

  fetchCalls.length = 0;
  context.fetch = async (url) => {
    fetchCalls.push(url);
    if (url === "/api/system") return response(systemSnapshot);
    throw new Error("counters unavailable");
  };
  await context.refresh();
  assert.strictEqual(nodes.get("#statusText").textContent, "System live; probes unavailable");
  assert(nodes.get("#status").classList);
}

main()
  .then(() => console.log("system visuals contract: ok"))
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
