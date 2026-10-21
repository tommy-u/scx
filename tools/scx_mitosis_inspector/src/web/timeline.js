(function installMitosisTimeline(root) {
  "use strict";

  if (root.MitosisTimeline) return;

  const POLL_INTERVAL_MS = 2000;
  const STORAGE_KEY = `mitosis-inspector-timeline:${root.location?.origin || "local"}`;
  const consumers = new Set();
  const failures = { frames: null, view: null, reset: null };
  const elements = Object.fromEntries(["Bar", "Live", "Previous", "Next", "Range", "Selected", "Now",
    "Oldest", "Latest", "Status"].map((name) => [name.toLowerCase(), root.document.querySelector(`#timeline${name}`)]));
  const resetButton = root.document.querySelector("#resetAllStats");
  const originalResetTitle = resetButton?.getAttribute?.("title") || "";
  const dynamicPage = ["/", "/stats", "/scheduling", "/callbacks", "/system", "/config", "/inspector"]
    .includes(root.location?.pathname || "/");

  function storedSelection() {
    try {
      const saved = JSON.parse(root.sessionStorage?.getItem(STORAGE_KEY) || "null");
      if (!saved || (saved.mode !== "live" && saved.mode !== "history")) return null;
      if (saved.mode === "history" && !Number.isFinite(saved.selectedAt)) return null;
      return saved;
    } catch {
      return null;
    }
  }

  const saved = storedSelection();
  const state = {
    mode: saved?.mode || "live",
    selectedAt: saved?.mode === "history" ? saved.selectedAt : null,
    nowMs: Date.now(), oldestAt: null, latestAt: null,
    instanceId: typeof saved?.instanceId === "string" ? saved.instanceId : null,
    frames: [], view: null, loading: true, error: null, notice: null,
    windowMs: Number.isFinite(saved?.windowMs) && saved.windowMs > 0 ? saved.windowMs : null,
  };
  let defaultWindowMs = null;
  let maxWindowMs = null;
  let cursor = null;
  let paused = false;
  let frameRequest = null;
  let viewRequest = null;
  let viewSpec = null;
  let viewGeneration = 0;
  let viewTimer = null;
  let lastViewKey = null;
  let clockOrigin = state.nowMs;
  let clockStarted = monotonicNow();
  let clockSynced = false;

  function monotonicNow() {
    return typeof root.performance?.now === "function" ? root.performance.now() : Date.now();
  }

  function persist() {
    try {
      root.sessionStorage?.setItem(STORAGE_KEY, JSON.stringify({ instanceId: state.instanceId,
        mode: state.mode, selectedAt: state.selectedAt, windowMs: state.windowMs }));
    } catch {
      // Time travel still works when browser storage is unavailable.
    }
  }

  function syncClock(timestamp) {
    if (!Number.isFinite(timestamp)) return;
    const receivedAt = monotonicNow();
    const projected = clockOrigin + Math.max(0, receivedAt - clockStarted);
    clockOrigin = clockSynced ? Math.max(timestamp, projected) : timestamp;
    clockStarted = receivedAt;
    clockSynced = true;
    state.nowMs = clockOrigin;
  }

  const clockFormatter = new Intl.DateTimeFormat(undefined, {
    year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit",
    hourCycle: "h23", timeZoneName: "short",
  });

  function formatTime(timestamp) {
    if (!Number.isFinite(timestamp)) return "--";
    const parts = Object.fromEntries(clockFormatter.formatToParts(new Date(timestamp))
      .filter((part) => part.type !== "literal").map((part) => [part.type, part.value]));
    return `${parts.year}-${parts.month}-${parts.day} ${parts.hour}:${parts.minute}:${parts.second} ${parts.timeZoneName}`;
  }

  function selectedTime() {
    return state.mode === "history" ? state.selectedAt : state.latestAt;
  }

  function hasBounds() {
    return Number.isFinite(state.oldestAt) && Number.isFinite(state.latestAt);
  }

  function renderControls() {
    const at = selectedTime();
    const ready = hasBounds();
    if (elements.bar) {
      elements.bar.dataset.mode = state.mode;
      elements.bar.dataset.error = state.error ? "true" : "false";
      elements.bar.setAttribute("aria-busy", state.loading ? "true" : "false");
    }
    if (elements.range) {
      elements.range.min = ready ? String(state.oldestAt) : "0";
      elements.range.max = ready ? String(state.latestAt) : "1";
      elements.range.step = "1";
      elements.range.value = ready && Number.isFinite(at) ? String(at) : "0";
      elements.range.disabled = !ready || paused;
      elements.range.setAttribute("aria-valuetext", ready
        ? `${state.mode === "live" ? "Live, latest recorded sample" : "Viewing history"}: ${formatTime(at)}`
        : "Waiting for recorded samples");
    }
    if (elements.live) {
      elements.live.setAttribute("aria-pressed", state.mode === "live" ? "true" : "false");
      elements.live.disabled = paused;
    }
    if (elements.previous) elements.previous.disabled = !ready || paused || at <= state.oldestAt;
    if (elements.next) elements.next.disabled = !ready || paused || state.mode === "live";
    if (elements.selected) {
      elements.selected.textContent = formatTime(at);
      if (Number.isFinite(at)) elements.selected.setAttribute("datetime", new Date(at).toISOString());
      else elements.selected.removeAttribute("datetime");
    }
    if (elements.now) {
      elements.now.textContent = formatTime(state.nowMs);
      elements.now.setAttribute("datetime", new Date(state.nowMs).toISOString());
    }
    if (elements.oldest) elements.oldest.textContent = ready ? formatTime(state.oldestAt) : "Waiting for history";
    if (elements.latest) elements.latest.textContent = ready ? formatTime(state.latestAt) : "Present";
    if (elements.status) {
      const text = paused ? "Resetting inspector"
        : state.error ? `History unavailable: ${state.error}`
          : state.notice || (!ready ? "Waiting for recorded samples"
            : state.loading ? "Loading selected time" : state.mode === "history" ? "Viewing history" : "Live");
      if (elements.status.textContent !== text) elements.status.textContent = text;
    }
    if (resetButton) {
      resetButton.disabled = paused || state.mode === "history";
      if (state.mode === "history") resetButton.setAttribute("title", "Return to Live to reset statistics");
      else if (originalResetTitle) resetButton.setAttribute("title", originalResetTitle);
      else resetButton.removeAttribute?.("title");
    }
  }

  function publish() {
    state.error = failures.reset || failures.view || failures.frames || null;
    renderControls();
    for (const consumer of consumers) {
      try { consumer(state); } catch (error) { root.console?.error?.("Timeline renderer failed", error); }
    }
  }

  function boundsFrom(data) {
    if (Object.prototype.hasOwnProperty.call(data, "oldest_at_unix_ms")) {
      state.oldestAt = Number.isFinite(data.oldest_at_unix_ms) ? data.oldest_at_unix_ms : null;
    }
    if (Object.prototype.hasOwnProperty.call(data, "latest_at_unix_ms")) {
      state.latestAt = Number.isFinite(data.latest_at_unix_ms) ? data.latest_at_unix_ms : null;
    }
    syncClock(data.now_unix_ms);
  }

  function trimFrames() {
    if (!hasBounds()) { state.frames = []; return; }
    state.frames = state.frames.filter((frame) => frame.at_unix_ms >= state.oldestAt
      && frame.at_unix_ms <= state.latestAt);
  }

  function invalidateView(clear) {
    viewGeneration += 1;
    root.clearTimeout(viewTimer);
    viewTimer = null;
    viewPoller.invalidate();
    viewRequest = null;
    viewSpec = null;
    lastViewKey = null;
    if (clear) {
      state.view = null;
      failures.view = null;
    }
  }

  function resetInstance(instanceId) {
    framePoller.invalidate();
    frameRequest = null;
    invalidateView(true);
    state.instanceId = instanceId;
    state.frames = [];
    state.oldestAt = null;
    state.latestAt = null;
    state.mode = "live";
    state.selectedAt = null;
    defaultWindowMs = null;
    maxWindowMs = null;
    failures.frames = null;
    failures.view = null;
    failures.reset = null;
    state.notice = "Inspector restarted; showing the new Live instance";
    cursor = null;
    state.loading = true;
  }

  function clampSelection() {
    if (state.mode !== "history" || !hasBounds()) return false;
    const clamped = Math.min(state.latestAt, Math.max(state.oldestAt, state.selectedAt));
    if (clamped === state.selectedAt) return false;
    state.notice = state.selectedAt < state.oldestAt
      ? "Selected time expired; showing the oldest retained sample"
      : "Selected time is beyond the retained range; showing the latest recorded sample";
    state.selectedAt = clamped;
    invalidateView(true);
    state.loading = true;
    persist();
    return true;
  }

  function wantsView() {
    return dynamicPage || consumers.size > 0;
  }

  function hidden() {
    return root.document.visibilityState === "hidden";
  }

  function positiveWindow(value) {
    return Number.isFinite(value) && value > 0;
  }

  function resolveWindow(data) {
    if (positiveWindow(data.default_window_ms)) defaultWindowMs = data.default_window_ms;
    if (positiveWindow(data.max_window_ms)) maxWindowMs = data.max_window_ms;
    const resolved = positiveWindow(data.window_ms) ? data.window_ms
      : state.windowMs === null && positiveWindow(defaultWindowMs) ? defaultWindowMs : state.windowMs;
    if (resolved !== state.windowMs) {
      invalidateView(true);
      state.windowMs = resolved;
    }
  }

  function recoverWindow(error) {
    const data = error.body;
    if (error.status !== 400 || !data || !positiveWindow(data.default_window_ms)
        || !positiveWindow(data.max_window_ms) || data.default_window_ms > data.max_window_ms
        || !positiveWindow(state.windowMs) || state.windowMs <= data.max_window_ms) return false;
    if (typeof data.instance_id === "string" && data.instance_id) {
      if (state.instanceId && state.instanceId !== data.instance_id) resetInstance(data.instance_id);
      else state.instanceId = data.instance_id;
    }
    defaultWindowMs = data.default_window_ms;
    maxWindowMs = data.max_window_ms;
    state.notice = "Window adjusted to the inspector's configured default";
    failures.frames = null;
    failures.view = null;
    setWindowMs(defaultWindowMs);
    return true;
  }

  function currentViewSpec() {
    const selected = state.mode === "history" ? state.selectedAt : null;
    const key = `${state.instanceId}|${state.mode}|${selected ?? state.latestAt}|${state.windowMs}`;
    const query = [];
    if (positiveWindow(state.windowMs)) query.push(`window_ms=${encodeURIComponent(state.windowMs)}`);
    if (selected !== null) query.push(`at_unix_ms=${encodeURIComponent(selected)}`);
    const url = `/api/timeline/view${query.length ? `?${query.join("&")}` : ""}`;
    return { key, url, generation: viewGeneration, instanceId: state.instanceId,
      mode: state.mode, selectedAt: selected, latestAt: state.latestAt, windowMs: state.windowMs };
  }

  function isCurrentView(spec) {
    return spec && spec.generation === viewGeneration && spec.instanceId === state.instanceId
      && spec.mode === state.mode && spec.windowMs === state.windowMs
      && (state.mode === "live" || spec.selectedAt === state.selectedAt);
  }

  async function requestJson(url, signal) {
    const response = await root.fetch(url, { cache: "no-store", signal });
    const data = await response.json();
    if (!response.ok) {
      const error = new Error(data.error || `HTTP ${response.status}`);
      error.status = response.status;
      error.body = data;
      throw error;
    }
    return data;
  }

  const viewPoller = root.MitosisPolling.createPoller({ timeoutMs: 6000,
    async load({ signal }) {
      const spec = viewSpec;
      return { data: await requestJson(spec.url, signal), spec };
    },
    onResult({ data, spec }) {
      if (!isCurrentView(spec) || paused) return;
      if (data.instance_id !== state.instanceId) {
        resetInstance(data.instance_id);
        persist();
        publish();
        runFrames();
        return;
      }
      // A view can complete after newer light frames. Never shrink their bounds.
      syncClock(data.now_unix_ms);
      if (state.windowMs === null && positiveWindow(data.migrations?.window_ms)) {
        state.windowMs = data.migrations.window_ms;
        persist();
      }
      state.view = data;
      state.loading = false;
      failures.view = null;
      failures.reset = null;
      lastViewKey = `${spec.instanceId}|${spec.mode}|${spec.selectedAt ?? spec.latestAt}|${state.windowMs}`;
      publish();
    },
    onError(error) {
      if (!isCurrentView(viewSpec) || paused) return;
      if (recoverWindow(error)) return;
      if (error.status === 400 && error.body && state.mode === "history") {
        boundsFrom(error.body);
        trimFrames();
        if (clampSelection()) {
          publish();
          root.setTimeout(() => loadView(), 0);
          return;
        }
      }
      failures.view = error.message || String(error);
      state.loading = false;
      publish();
    },
  });

  function loadView() {
    if (hidden()) return Promise.resolve();
    if (paused || !wantsView() || !hasBounds()) {
      if (!paused) { state.loading = false; publish(); }
      return Promise.resolve();
    }
    const spec = currentViewSpec();
    if (viewRequest && isCurrentView(viewSpec)) return viewRequest;
    if (state.view && lastViewKey === spec.key) return Promise.resolve();
    root.clearTimeout(viewTimer);
    viewTimer = null;
    state.loading = !state.view;
    publish();
    viewSpec = spec;
    const running = viewPoller.run();
    const joined = Promise.resolve(running).finally(() => {
      if (viewRequest !== joined) return;
      viewRequest = null;
      viewSpec = null;
      if (!paused && state.mode === "live" && state.view && currentViewSpec().key !== lastViewKey) {
        root.setTimeout(() => loadView(), 0);
      }
    });
    viewRequest = joined;
    return joined;
  }

  function scheduleView() {
    root.clearTimeout(viewTimer);
    viewTimer = root.setTimeout(() => {
      viewTimer = null;
      loadView();
    }, 75);
  }

  const framePoller = root.MitosisPolling.createPoller({ timeoutMs: 6000,
    load({ signal }) {
      const query = [];
      if (positiveWindow(state.windowMs)) query.push(`window_ms=${encodeURIComponent(state.windowMs)}`);
      if (state.instanceId && Number.isSafeInteger(cursor)) {
        query.push(`instance_id=${encodeURIComponent(state.instanceId)}`, `after_seq=${cursor}`);
      }
      const url = `/api/timeline${query.length ? `?${query.join("&")}` : ""}`;
      return requestJson(url, signal);
    },
    onResult(data) {
      if (paused) return;
      if (typeof data.instance_id !== "string" || !data.instance_id || !Array.isArray(data.frames)
          || !Number.isSafeInteger(data.sample_seq) || data.sample_seq < 0) {
        failures.frames = "Invalid history response";
        state.loading = false;
        publish();
        return;
      }
      if (state.instanceId && state.instanceId !== data.instance_id) resetInstance(data.instance_id);
      else state.instanceId = data.instance_id;
      resolveWindow(data);
      boundsFrom(data);
      const samples = new Map((data.reset ? [] : state.frames).map((frame) => [frame.seq, frame]));
      for (const frame of data.frames) {
        if (Number.isSafeInteger(frame.seq) && frame.seq > 0 && Number.isFinite(frame.at_unix_ms)
            && frame.signals && typeof frame.signals === "object") samples.set(frame.seq, frame);
      }
      state.frames = [...samples.values()].sort((left, right) => left.at_unix_ms - right.at_unix_ms || left.seq - right.seq);
      trimFrames();
      cursor = data.sample_seq;
      failures.frames = null;
      clampSelection();
      persist();
      state.loading = hasBounds() && wantsView() && !state.view;
      publish();
      loadView();
    },
    onError(error) {
      if (paused) return;
      if (recoverWindow(error)) return;
      failures.frames = error.message || String(error);
      if (!viewRequest) state.loading = false;
      publish();
    },
  });

  function runFrames() {
    if (paused || hidden()) return Promise.resolve();
    if (frameRequest) return frameRequest;
    const running = framePoller.run();
    const joined = Promise.resolve(running).finally(() => {
      if (frameRequest === joined) frameRequest = null;
    });
    frameRequest = joined;
    return joined;
  }

  async function refresh() {
    await runFrames();
    if (!paused && !hidden()) await loadView();
  }

  function floorFrame(timestamp) {
    let result = null;
    for (const frame of state.frames) {
      if (frame.at_unix_ms > timestamp) break;
      result = frame;
    }
    return result;
  }

  function setAt(timestamp) {
    if (paused || !Number.isFinite(timestamp) || !hasBounds()) return;
    const clamped = Math.max(state.oldestAt, Math.min(state.latestAt, timestamp));
    const at = floorFrame(clamped)?.at_unix_ms ?? clamped;
    if (state.mode === "history" && state.selectedAt === at) return;
    invalidateView(true);
    state.mode = "history";
    state.selectedAt = at;
    state.notice = timestamp < state.oldestAt ? "Selected time expired; showing the oldest retained sample" : null;
    state.loading = wantsView();
    persist();
    publish();
    scheduleView();
  }

  function goLive() {
    if (paused) return;
    invalidateView(true);
    state.mode = "live";
    state.selectedAt = null;
    state.notice = null;
    state.loading = wantsView() && hasBounds();
    persist();
    publish();
    loadView();
    runFrames();
  }

  function step(direction) {
    if (paused || !state.frames.length || !Number.isFinite(direction) || direction === 0) return;
    const at = selectedTime();
    if (direction < 0) {
      const previous = state.frames.filter((frame) => frame.at_unix_ms < at).at(-1);
      if (previous) setAt(previous.at_unix_ms);
    } else {
      const next = state.frames.find((frame) => frame.at_unix_ms > at);
      if (!next || next.at_unix_ms >= state.latestAt) goLive();
      else setAt(next.at_unix_ms);
    }
  }

  function setWindowMs(windowMs) {
    if (paused || !positiveWindow(windowMs)) return;
    let resolved = Math.round(windowMs);
    if (resolved <= 0) return;
    if (positiveWindow(maxWindowMs) && resolved > maxWindowMs && positiveWindow(defaultWindowMs)) {
      resolved = defaultWindowMs;
      state.notice = "Window adjusted to the inspector's configured default";
    }
    if (resolved === state.windowMs) { publish(); return; }
    state.windowMs = resolved;
    cursor = null;
    framePoller.invalidate();
    frameRequest = null;
    invalidateView(true);
    state.frames = [];
    state.loading = true;
    failures.frames = null;
    persist();
    publish();
    runFrames();
  }

  function signalSource(key) {
    if (key.startsWith("explore.")) return key.split(".").slice(0, 2).join(".");
    if (key.startsWith("cell.") || key.startsWith("stats.")) return "stats";
    if (key === "system.total" || key === "system.completions" || key === "system.mib") return "counters";
    if (key.startsWith("system.")) return "system";
    return "counters";
  }

  function visibleFrames() {
    const cutoff = selectedTime();
    return Number.isFinite(cutoff) ? state.frames.filter((frame) => frame.at_unix_ms <= cutoff) : [];
  }

  function points(key) {
    const source = signalSource(key);
    const result = [];
    let previousEpoch = null;
    let previousSample = null;
    let previousMissing = false;
    for (const frame of visibleFrames()) {
      const meta = frame.source_meta?.[source];
      const epoch = meta?.epoch ?? frame.epochs?.[source] ?? null;
      const unavailable = frame.source_available?.[source] === false || Boolean(meta?.error);
      const validMeta = meta && Number.isSafeInteger(meta.sample_seq) && meta.sample_seq > 0
        && Number.isFinite(meta.captured_at_unix_ms);
      const sample = validMeta ? `${epoch}:${meta.sample_seq}` : `frame:${frame.seq}`;
      if (!unavailable && sample === previousSample) continue;
      const x = !unavailable && validMeta ? meta.captured_at_unix_ms : frame.at_unix_ms;
      const value = frame.signals?.[key];
      const y = !unavailable && (!meta || validMeta) && Number.isFinite(value) ? value : null;
      const breakBefore = previousMissing || (previousEpoch !== null && epoch !== previousEpoch);
      result.push({ x, y, breakBefore });
      if (!unavailable) previousSample = sample;
      previousEpoch = epoch;
      previousMissing = y === null;
    }
    return result;
  }

  function keys(prefix = "") {
    return [...new Set(visibleFrames().flatMap((frame) => Object.keys(frame.signals || {})))]
      .filter((key) => key.startsWith(prefix)).sort();
  }

  root.MitosisTimeline = {
    getState: () => state,
    subscribe(consumer) {
      consumers.add(consumer);
      consumer(state);
      if (hasBounds()) loadView();
      return () => consumers.delete(consumer);
    },
    points, keys, refresh, setAt, goLive, step, setWindowMs,
    isLive: () => state.mode === "live",
  };

  elements.live?.addEventListener("click", goLive);
  elements.previous?.addEventListener("click", () => step(-1));
  elements.next?.addEventListener("click", () => step(1));
  elements.range?.addEventListener("input", () => {
    const at = Number(elements.range.value);
    if (hasBounds() && at >= state.latestAt) goLive();
    else setAt(at);
  });
  elements.range?.addEventListener("change", () => {
    root.clearTimeout(viewTimer);
    viewTimer = null;
    loadView();
  });
  elements.range?.addEventListener("keydown", (event) => {
    if (!["ArrowLeft", "ArrowDown", "ArrowRight", "ArrowUp", "Home", "End", "PageUp", "PageDown"].includes(event.key)) return;
    event.preventDefault();
    if (event.key === "Home") setAt(state.oldestAt);
    else if (event.key === "End") goLive();
    else if (event.key === "PageUp" || event.key === "PageDown") {
      const delta = event.key === "PageUp" ? 30000 : -30000;
      const target = selectedTime() + delta;
      if (target >= state.latestAt) goLive();
      else setAt(target);
    } else step(event.key === "ArrowRight" || event.key === "ArrowUp" ? 1 : -1);
  });

  function measureBar() {
    const height = elements.bar?.getBoundingClientRect?.().height || elements.bar?.offsetHeight || 92;
    root.document.documentElement.style?.setProperty?.("--timeline-height", `${Math.ceil(height)}px`);
  }
  if (typeof root.ResizeObserver === "function" && elements.bar) new root.ResizeObserver(measureBar).observe(elements.bar);
  root.addEventListener("resize", measureBar);
  measureBar();

  root.addEventListener("mitosis:stats-reset-start", () => {
    paused = true;
    framePoller.invalidate();
    frameRequest = null;
    invalidateView(false);
    publish();
  });
  root.addEventListener("mitosis:stats-reset-failed", (event) => {
    paused = false;
    failures.reset = event.detail?.error || "Inspector reset failed";
    state.notice = `Reset failed: ${failures.reset}`;
    state.loading = false;
    publish();
    refresh();
  });
  root.addEventListener("mitosis:stats-reset", () => {
    paused = false;
    framePoller.invalidate();
    frameRequest = null;
    invalidateView(true);
    cursor = null;
    state.frames = [];
    state.oldestAt = null;
    state.latestAt = null;
    state.mode = "live";
    state.selectedAt = null;
    state.notice = null;
    failures.frames = null;
    failures.view = null;
    failures.reset = null;
    state.loading = true;
    persist();
    publish();
    refresh();
  });
  root.document.addEventListener("visibilitychange", () => {
    if (root.document.visibilityState === "visible") refresh();
    else if (hidden()) {
      framePoller.invalidate();
      frameRequest = null;
      invalidateView(false);
    }
  });
  root.addEventListener("pageshow", () => refresh());
  root.addEventListener("online", () => refresh());
  root.setInterval(() => {
    state.nowMs = clockOrigin + Math.max(0, monotonicNow() - clockStarted);
    renderControls();
  }, 1000);
  root.setInterval(refresh, POLL_INTERVAL_MS);
  renderControls();
  refresh();
})(globalThis);
