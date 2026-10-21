(function (root, factory) {
  "use strict";
  const api = factory();
  root.MitosisPolling = api;
  if (typeof module === "object" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  function createPoller({ load, onResult, onError, timeoutMs = 5000 }) {
    let requestId = 0;
    let active = null;

    function invalidate() {
      requestId += 1;
      if (active) {
        const previous = active;
        active = null;
        previous.controller.abort();
        previous.reject(new Error("Request invalidated"));
      }
    }

    async function run() {
      if (active) return;
      const request = { id: ++requestId, controller: new AbortController() };
      active = request;
      const deadline = new Promise((resolve, reject) => {
        request.reject = reject;
        request.timer = setTimeout(() => {
          request.controller.abort();
          reject(new Error(`Request timed out after ${timeoutMs / 1000}s`));
        }, timeoutMs);
      });
      try {
        const result = await Promise.race([load({ signal: request.controller.signal }), deadline]);
        if (request.id === requestId) onResult?.(result);
      } catch (error) {
        if (request.id === requestId) onError?.(error);
      } finally {
        clearTimeout(request.timer);
        if (active === request) active = null;
      }
    }

    return { run, invalidate };
  }

  function createSourcePoller({ loaders, onResult, timeoutMs = 6000 }) {
    const pending = () => loaders.map(() => ({ status: "pending" }));
    let results = pending();
    function publish(index, result) {
      results[index] = result;
      onResult(results.slice());
    }
    const pollers = loaders.map((load, index) => createPoller({ load, timeoutMs,
      onResult(value) { publish(index, { status: "fulfilled", value }); },
      onError(reason) { publish(index, { status: "rejected", reason }); },
    }));
    return {
      run() { return Promise.all(pollers.map((poller) => poller.run())); },
      invalidate() {
        pollers.forEach((poller) => poller.invalidate());
        results = pending();
      },
    };
  }

  function freshnessModel({ hasData, meta, pollError, now = Date.now(), pollIntervalMs = 1000 }) {
    const error = pollError || meta?.error || null;
    if (!hasData) return { state: error ? "unavailable" : "waiting",
      label: error ? "Unavailable" : "Waiting", detail: error };
    const lastSuccess = meta?.last_success_at_unix_ms;
    if (!Number.isFinite(lastSuccess)) {
      return { state: "unavailable", label: "Unavailable", detail: error || "Sample metadata unavailable" };
    }
    const age = Math.max(0, now - lastSuccess);
    if (!error && age <= pollIntervalMs * 2.5) {
      return { state: "fresh", label: "Live", detail: null };
    }
    return { state: "stale", label: `Stale · updated ${Math.round(age / 1000)}s ago`, detail: error };
  }

  function isNewSample(meta, previousMeta) {
    if (!meta || meta.error || !Number.isSafeInteger(meta.epoch) || meta.epoch < 0
        || !Number.isSafeInteger(meta.sample_seq) || meta.sample_seq <= 0
        || !Number.isFinite(meta.captured_at_unix_ms)
        || !Number.isFinite(meta.last_success_at_unix_ms)) return false;
    if (!previousMeta) return true;
    return meta.epoch > previousMeta.epoch
      || (meta.epoch === previousMeta.epoch && meta.sample_seq > previousMeta.sample_seq);
  }

  async function fetchJson(url, signal) {
    const controller = new AbortController();
    let timer;
    let rejectDeadline;
    const deadline = new Promise((resolve, reject) => {
      rejectDeadline = reject;
      // Include response parsing in each source's deadline. The poller's guard
      // is slightly later so this error can be published independently.
      timer = setTimeout(() => {
        controller.abort();
        reject(new Error("Source request timed out after 5s"));
      }, 5000);
    });
    const abort = () => {
      controller.abort();
      rejectDeadline(new Error("Source request cancelled"));
    };
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) abort();
    try {
      const request = async () => {
        const response = await fetch(url, { cache: "no-store", signal: controller.signal });
        const body = await response.json();
        if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
        return body;
      };
      return await Promise.race([request(), deadline]);
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
    }
  }

  function createPageState({ sourceNames, onEpochChange }) {
    const sources = Object.fromEntries(sourceNames.map((name) => [name, {}]));
    const state = { sources, epoch: null, resetAt: 0, paused: false, resetError: null, resetFailureAt: 0 };

    function clearSources() {
      sourceNames.forEach((name) => { sources[name] = {}; });
    }

    function observeEpoch(payload) {
      const epoch = payload?.meta?.epoch;
      if (payload?.collector?.status !== "active" || payload.meta?.error
          || !Number.isSafeInteger(epoch) || epoch < 0
          || (state.epoch !== null && epoch <= state.epoch)) return;
      const previous = state.epoch;
      state.epoch = epoch;
      state.resetAt = 0;
      state.resetError = null;
      state.resetFailureAt = 0;
      if (previous === null) {
        sourceNames.forEach((name) => {
          if (sources[name].observer !== false && sources[name].meta?.epoch !== epoch) sources[name] = {};
        });
      } else {
        clearSources();
        onEpochChange();
      }
    }

    function accept(name, result, observer = true) {
      const source = sources[name];
      source.observer = observer;
      source.newSample = false;
      if (result.status === "pending") return source;
      if (result.status !== "fulfilled") {
        source.error = result.reason?.message || String(result.reason);
        return source;
      }
      const payload = result.value;
      const meta = payload?.meta;
      const collector = payload?.collector;
      const error = meta?.error || payload?.error || (observer && collector?.status !== "active"
        ? collector?.error || `Collector ${collector?.status || "unavailable"}` : null);
      if (!meta || !Number.isSafeInteger(meta.epoch)) {
        source.error = error || "Sample metadata unavailable";
        return source;
      }
      if (state.epoch !== null && (meta.epoch < state.epoch || (observer && meta.epoch !== state.epoch))) {
        source.error = error || "Synchronizing scheduler epoch";
        return source;
      }
      if (state.resetAt && (!Number.isFinite(meta.captured_at_unix_ms)
          || meta.captured_at_unix_ms < state.resetAt)) {
        source.error = error || "Waiting for a post-reset sample";
        return source;
      }
      if (source.sampleMeta && (meta.epoch < source.sampleMeta.epoch
          || (meta.epoch === source.sampleMeta.epoch && meta.sample_seq < source.sampleMeta.sample_seq))) return source;
      source.meta = meta;
      source.error = error;
      if (Number.isFinite(meta.captured_at_unix_ms) && meta.sample_seq > 0) source.data = payload;
      const advancing = !error && isNewSample(meta, source.sampleMeta);
      if (observer && state.resetError && advancing && meta.captured_at_unix_ms > state.resetFailureAt) {
        source.resetRecovered = true;
      }
      source.newSample = advancing && (!observer || !state.resetError || source.resetRecovered);
      if (source.newSample) source.sampleMeta = { ...meta };
      return source;
    }

    function freshness(name, intervalMs) {
      const source = sources[name];
      return freshnessModel({ hasData: Boolean(source.data), meta: source.meta,
        pollError: state.paused ? "Resetting inspector"
          : (source.observer === false || source.resetRecovered ? null : state.resetError) || source.error,
        pollIntervalMs: intervalMs });
    }

    function describe(labels, intervalMs) {
      return Object.entries(labels).map(([name, label]) => {
        const health = freshness(name, intervalMs);
        return `${label}: ${health.label}${health.detail ? ` (${health.detail})` : ""}`;
      }).join(" · ");
    }

    function bindReset(poller, clearHistory, refresh) {
      globalThis.addEventListener?.("mitosis:stats-reset-start", () => {
        state.paused = true;
        poller.invalidate();
        refresh();
      });
      globalThis.addEventListener?.("mitosis:stats-reset", (event) => {
        state.epoch = event.detail.epoch;
        state.resetAt = event.detail.reset_at_unix_ms;
        state.paused = false;
        state.resetError = null;
        state.resetFailureAt = 0;
        poller.invalidate();
        clearSources();
        clearHistory();
        refresh();
      });
      globalThis.addEventListener?.("mitosis:stats-reset-failed", (event) => {
        state.paused = false;
        state.resetError = event.detail?.error || "Inspector reset failed";
        state.resetFailureAt = Date.now();
        sourceNames.forEach((name) => { sources[name].resetRecovered = false; });
        poller.invalidate();
        refresh();
      });
    }

    return { state, observeEpoch, accept, freshness, describe, bindReset };
  }

  return { createPoller, createSourcePoller, freshnessModel, isNewSample, fetchJson, createPageState };
});
