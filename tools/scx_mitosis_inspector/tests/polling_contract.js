"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function helper() {
  const filename = path.join(__dirname, "../src/web/polling.js");
  assert(fs.existsSync(filename), "the shared polling helper must exist");
  const timers = new Map();
  let nextTimer = 0;
  const context = {
    module: { exports: {} },
    AbortController,
    setTimeout(callback) { const id = ++nextTimer; timers.set(id, callback); return id; },
    clearTimeout(id) { timers.delete(id); },
  };
  vm.runInNewContext(fs.readFileSync(filename, "utf8"), context, { filename });
  return { ...context.module.exports, timeout() { [...timers.values()].forEach((callback) => callback()); } };
}

function meta(sequence = 1, values = {}) {
  return { epoch: 1, sample_seq: sequence, captured_at_unix_ms: 1000,
    last_success_at_unix_ms: 1000, error: null, ...values };
}

test("an active poll suppresses duplicate requests", async () => {
  const { createPoller } = helper();
  const response = deferred();
  let requests = 0;
  const results = [];
  const poller = createPoller({ load() { requests += 1; return response.promise; },
    onResult(value) { results.push(value); } });
  const first = poller.run();
  await poller.run();
  assert.equal(requests, 1);
  response.resolve("latest");
  await first;
  assert.deepEqual(results, ["latest"]);
});

test("source polling publishes fast peers independently and skips only busy sources", async () => {
  const { createSourcePoller } = helper();
  const slow = deferred();
  const seen = [];
  let fastRequests = 0;
  let slowRequests = 0;
  const poller = createSourcePoller({ loaders: [
    () => ++fastRequests,
    () => { slowRequests += 1; return slow.promise; },
  ], onResult(results) { seen.push(results); } });
  const first = poller.run();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(seen[0][0].value, 1);
  assert.equal(seen[0][1].status, "pending");
  await poller.run();
  assert.equal(fastRequests, 2);
  assert.equal(slowRequests, 1);
  assert.equal(seen.at(-1)[0].value, 2);
  slow.resolve("slow");
  await first;
  assert.equal(seen.at(-1)[1].value, "slow");
  assert.equal(seen[0][1].status, "pending", "published vectors cannot mutate later");
});

test("source invalidation clears cached results and suppresses late source completion", async () => {
  const { createSourcePoller } = helper();
  const old = deferred();
  const current = deferred();
  let requests = 0;
  const seen = [];
  const poller = createSourcePoller({ loaders: [
    () => "fast", () => ++requests === 1 ? old.promise : current.promise,
  ], onResult(results) { seen.push(results); } });
  const first = poller.run();
  await new Promise((resolve) => setImmediate(resolve));
  poller.invalidate();
  const next = poller.run();
  old.resolve("obsolete");
  await first;
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(seen.at(-1)[1].status, "pending");
  current.resolve("current");
  await next;
  assert(!seen.some((results) => results[1].value === "obsolete"));
});

test("pending sources preserve accepted data and errors without producing new measurements", () => {
  const { createPageState } = helper();
  const page = createPageState({ sourceNames: ["source"], onEpochChange() {} });
  const snapshot = { meta: meta(), collector: { status: "active" } };
  page.observeEpoch(snapshot);
  const source = page.accept("source", { status: "fulfilled", value: snapshot });
  assert(source.newSample);
  page.accept("source", { status: "rejected", reason: new Error("last failure") });
  page.accept("source", { status: "pending" });
  assert.equal(source.data, snapshot);
  assert.equal(source.error, "last failure");
  assert.equal(source.newSample, false);
});

test("invalidation suppresses late success and does not release a newer request", async () => {
  const { createPoller } = helper();
  const responses = [deferred(), deferred()];
  const signals = [];
  const results = [];
  let requests = 0;
  const poller = createPoller({ load({ signal }) {
    signals.push(signal); return responses[requests++].promise;
  }, onResult(value) { results.push(value); } });
  const old = poller.run();
  poller.invalidate();
  assert(signals[0].aborted);
  const current = poller.run();
  responses[0].resolve("old");
  await old;
  await poller.run();
  assert.equal(requests, 2, "the old finally must not release the current request");
  responses[1].resolve("current");
  await current;
  assert.deepEqual(results, ["current"]);
});

test("invalidation suppresses late errors", async () => {
  const { createPoller } = helper();
  const response = deferred();
  const errors = [];
  const poller = createPoller({ load: () => response.promise,
    onError(error) { errors.push(error.message); } });
  const request = poller.run();
  poller.invalidate();
  response.reject(new Error("obsolete error"));
  await request;
  assert.deepEqual(errors, []);
});

test("a timeout releases even an abort-ignoring request", async () => {
  const { createPoller, timeout } = helper();
  const response = deferred();
  const results = [];
  const errors = [];
  let requests = 0;
  const poller = createPoller({ load: () => ++requests === 1 ? response.promise : "recovered",
    onResult(value) { results.push(value); }, onError(error) { errors.push(error.message); } });
  const hanging = poller.run();
  timeout();
  await hanging;
  assert.match(errors[0], /timed out/i);
  await poller.run();
  response.resolve("late");
  await Promise.resolve();
  assert.deepEqual(results, ["recovered"]);
});

test("freshness ages the source sample rather than successful HTTP contact", () => {
  const { freshnessModel } = helper();
  assert.equal(freshnessModel({ hasData: true, meta: meta(), now: 2000, pollIntervalMs: 1000 }).state, "fresh");
  const stale = freshnessModel({ hasData: true, meta: meta(), now: 6000, pollIntervalMs: 1000 });
  assert.equal(stale.state, "stale");
  assert.match(stale.label, /5s/);
  assert.equal(freshnessModel({ hasData: false, now: 1000, pollIntervalMs: 1000 }).state, "waiting");
  assert.equal(freshnessModel({ hasData: false, pollError: "HTTP 503", now: 1000,
    pollIntervalMs: 1000 }).state, "unavailable");
  assert.match(freshnessModel({ hasData: true, meta: meta(), pollError: "HTTP 503",
    now: 2000, pollIntervalMs: 1000 }).detail, /HTTP 503/);
  assert.equal(freshnessModel({ hasData: true, meta: meta(1, { error: "collector stopped" }),
    now: 2000, pollIntervalMs: 1000 }).state, "stale");
});

test("only a new successful sequenced sample can extend history", () => {
  const { isNewSample } = helper();
  assert(isNewSample(meta(), null));
  assert(!isNewSample(meta(), meta()));
  assert(!isNewSample(meta(1), meta(2)));
  assert(!isNewSample(meta(2, { error: "collection failed" }), meta()));
  assert(!isNewSample(null, meta()));
  assert(isNewSample(meta(1, { epoch: 2 }), meta(9)));
  assert(!isNewSample(meta(9), meta(1, { epoch: 2 })));
});
