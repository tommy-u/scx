"use strict";

const assert = require("node:assert/strict");
const { test } = require("node:test");
const { deferred, response, page, settle } = require("./page_test_support");

test("reset emits start immediately and success only after a completed acknowledgement", async () => {
  const reply = deferred();
  const view = page("reset.js", () => reply.promise);
  const request = view.element("#resetAllStats").listeners.get("click")();
  assert.equal(view.events[0]?.type, "mitosis:stats-reset-start");
  assert(view.element("#resetAllStats").disabled);
  const ack = { epoch: 2, sample_seq: 1, reset_at_unix_ms: 11000, scope: "inspector" };
  reply.resolve(response(ack));
  await request;
  assert.equal(view.events[1]?.type, "mitosis:stats-reset");
  assert.deepEqual(view.events[1].detail, ack);
  assert(!view.element("#resetAllStats").disabled);
});

test("a merely accepted reset is a failure, never completion", async () => {
  const view = page("reset.js", () => response({ accepted: true }, 202));
  await view.element("#resetAllStats").listeners.get("click")();
  assert.equal(view.events.at(-1)?.type, "mitosis:stats-reset-failed");
  assert(!view.events.some((event) => event.type === "mitosis:stats-reset"));
  assert.match(view.element("#resetStatsStatus").textContent, /failed/i);
});

test("reset rejection exposes the backend error and does not clear browser history", async () => {
  const view = page("reset.js", () => response({ error: "BPF reattach failed" }, 500));
  await view.element("#resetAllStats").listeners.get("click")();
  assert.equal(view.events.at(-1)?.type, "mitosis:stats-reset-failed");
  assert.match(view.events.at(-1).detail.error, /BPF reattach failed/);
  assert.match(view.element("#resetStatsStatus").textContent, /BPF reattach failed/);
});

for (const phase of ["response", "body"]) {
  test(`reset deadline releases the page when the ${phase} ignores abort`, async () => {
    const stalled = deferred();
    let signal;
    const view = page("reset.js", (url, options) => {
      signal = options.signal;
      return phase === "response" ? stalled.promise
        : { status: 200, ok: true, json: () => stalled.promise };
    });
    const pending = view.element("#resetAllStats").listeners.get("click")();
    await settle();
    view.timeout();
    await settle();
    assert.equal(view.events.at(-1)?.type, "mitosis:stats-reset-failed");
    assert.match(view.element("#resetStatsStatus").textContent, /timed out/i);
    assert(!view.element("#resetAllStats").disabled);
    assert(signal.aborted);
    await pending;
    const ack = { epoch: 2, sample_seq: 1, reset_at_unix_ms: 11000, scope: "inspector" };
    stalled.resolve(phase === "response" ? response(ack) : ack);
    await settle();
    assert(!view.events.some((event) => event.type === "mitosis:stats-reset"));
  });
}
