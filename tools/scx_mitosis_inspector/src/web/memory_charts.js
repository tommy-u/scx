(() => {
  "use strict";

  const root = document.querySelector("#systemMemoryHistory");
  if (!root) return;
  const timeline = globalThis.MitosisTimeline || null;
  const charts = globalThis.MitosisCharts;
  const format = new Intl.NumberFormat("en-US", { maximumSignificantDigits: 4 });
  const preferenceKey = "mitosis-system-memory-llcs-v1";
  const palette = ["green", "blue", "orange", "purple", "red", "slate", "olive", "gold", "pink"];
  const llcControls = new Map();
  const knownLlcs = new Set();
  let preferences = { mode: "all", selected: [], bandwidth: "total" };
  let state = null;
  let snapshot = null;
  let requestError = null;
  let wholeSourceError = null;
  let resizeFrame = null;

  const element = id => document.querySelector(`#${id}`);
  const metric = value => Number.isFinite(value) ? format.format(value) : "--";
  const llcId = value => Number.isSafeInteger(value) && value >= 0 ? value : null;
  const divide = (value, divisor) => Number.isFinite(value) ? value / divisor : null;
  function capture(at) {
    return Number.isFinite(at) ? new Date(at).toLocaleString("en-US", {
      month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit",
      timeZoneName: "short", hour12: false,
    }) : "unknown time";
  }
  function selectedBound() {
    return state?.mode === "history" ? Math.min(state.selectedAt,
      state.view?.at_unix_ms ?? state.selectedAt) : state?.latestAt ?? null;
  }
  function group(name) {
    const raw = snapshot?.groups?.[name];
    const at = raw?.meta?.captured_at_unix_ms ?? snapshot?.meta?.captured_at_unix_ms;
    const bound = selectedBound();
    let error = wholeSourceError || state?.view?.source_errors?.[`explore.${name}`]
      || (!raw ? requestError || "No retained source at the selected time" : null);
    if (!error && state?.mode === "history" && Number.isFinite(bound) && Number.isFinite(at) && at > bound) error = "No source captured at or before the selected time";
    if (!error && raw?.available !== true) error = raw?.error || raw?.meta?.error || "Source unavailable";
    if (!error && raw?.meta?.error && !raw.partial) error = raw.meta.error;
    const available = Boolean(raw && !error);
    const now = state?.mode === "history" ? bound : state?.nowMs ?? Date.now();
    const health = globalThis.MitosisPolling?.freshnessModel({ hasData: available, meta: raw?.meta,
      pollError: available ? null : error, now,
      pollIntervalMs: Number.isFinite(raw?.summary?.interval_ms) ? raw.summary.interval_ms : 1000 });
    return { raw, at, available, error, stale: available && health?.state === "stale",
      summary: available ? raw.summary || {} : {} };
  }

  function savePreferences() {
    try { localStorage.setItem(preferenceKey, JSON.stringify(preferences)); } catch (_) { /* Storage can be disabled. */ }
  }
  function selectedIds() {
    return [...knownLlcs].sort((a, b) => a - b).filter(id => preferences.mode === "all"
      || preferences.mode === "explicit" && preferences.selected.includes(id));
  }
  function styleFor(id) {
    const cycle = Math.floor(id / palette.length) % 3;
    return { color: `var(--series-${palette[id % palette.length]})`, dash: cycle === 0 ? [] : cycle === 1 ? [5, 3] : [2, 2] };
  }
  function discoverLlcs(bandwidth, perf) {
    if (bandwidth.available) for (const row of bandwidth.raw.rows || []) {
      const id = llcId(row.llc);
      if (id !== null) knownLlcs.add(id);
    }
    if (perf.available) for (const row of perf.summary.llcs || []) {
      const id = llcId(row.llc_id);
      if (id !== null) knownLlcs.add(id);
    }
    if (timeline) for (const name of ["bandwidth", "perf"]) {
      for (const key of timeline.keys?.(`explore.${name}.llc.`) || []) {
        const match = /^explore\.(?:bandwidth|perf)\.llc\.(\d+)\./.exec(key);
        const id = match ? llcId(Number(match[1])) : null;
        if (id !== null) knownLlcs.add(id);
      }
    }
  }
  function renderControls() {
    const selected = new Set(selectedIds());
    const host = element("memoryLlcSelection");
    if (!host) return;
    [...knownLlcs].sort((a, b) => a - b).forEach((id, index) => {
      let control = llcControls.get(id);
      if (!control) {
        const label = document.createElement("label");
        label.classList.add("memory-llc-choice");
        const input = document.createElement("input");
        input.type = "checkbox";
        input.value = String(id);
        input.dataset.llc = String(id);
        input.id = `memory-llc-${id}`;
        input.setAttribute("aria-label", `Show LLC ${id} on memory graphs`);
        const swatch = document.createElement("i");
        swatch.classList.add("memory-llc-swatch");
        swatch.setAttribute("aria-hidden", "true");
        swatch.style.setProperty("--memory-series", styleFor(id).color);
        const name = document.createElement("span");
        name.textContent = `LLC ${id}`;
        label.append(input, swatch, name);
        control = { label, input };
        llcControls.set(id, control);
        input.addEventListener("change", () => {
          const ids = new Set(selectedIds());
          if (input.checked) ids.add(id); else ids.delete(id);
          preferences.mode = "explicit";
          preferences.selected = [...ids].sort((a, b) => a - b);
          savePreferences();
          renderControls();
          draw();
        });
      }
      control.input.checked = selected.has(id);
      const current = [...host.children].filter(node => node.tagName === "LABEL");
      if (current[index] !== control.label) host.insertBefore(control.label, current[index] || null);
    });
    const description = element("memoryLlcSelectionStatus");
    if (description) description.textContent = knownLlcs.size ? selected.size
      ? `${selected.size} of ${knownLlcs.size} LLCs selected · total graphs include all measured sources`
      : "No LLCs selected · choose All or an LLC to show overlays"
      : "Waiting for mapped LLCs or recorded LLC history";
  }

  function archivedPoints(key, divisor = 1) {
    const values = timeline ? timeline.points(key) : [];
    const bound = state?.mode === "history" ? state.selectedAt : state?.latestAt;
    return (values || []).filter(point => Number.isFinite(point.x) && (!Number.isFinite(bound) || point.x <= bound))
      .map(point => ({ ...point, y: divide(point.y, divisor) }));
  }
  function series(label, key, divisor, color, dash = []) {
    return { label, color, dash, points: archivedPoints(key, divisor) };
  }
  function llcSeries(name, field, divisor) {
    return selectedIds().map(id => ({ label: `LLC ${id}`, ...styleFor(id),
      points: archivedPoints(`explore.${name}.llc.${id}.${field}`, divisor) }));
  }
  function drawLegend(canvasId, items) {
    const host = element(`${canvasId}Legend`);
    if (!host) return;
    host.replaceChildren(...items.map(item => {
      const entry = document.createElement("span");
      const swatch = document.createElement("i");
      swatch.classList.add("memory-legend-swatch");
      swatch.setAttribute("aria-hidden", "true");
      swatch.style.setProperty("--memory-series", item.color);
      if (item.dash?.length) swatch.classList.add("memory-legend-dashed");
      const label = document.createElement("span");
      label.textContent = item.label;
      entry.append(swatch, label);
      return entry;
    }));
  }
  function plot(id, items, unit, percentage = false) {
    const canvas = element(id);
    if (!canvas || !charts) return;
    drawLegend(id, items);
    charts.drawLineChart(canvas, items, {
      minX: state?.oldestAt, maxX: state?.mode === "history" ? state.selectedAt : state?.latestAt,
      minY: 0, ...(percentage ? { maxY: 100 } : {}), maxGapMs: 3000, unit, showLegend: false,
    });
  }

  function coverage(measured, total) {
    return Number.isFinite(measured) ? `${metric(measured)}${Number.isFinite(total) ? ` / ${metric(total)}` : ""} CPUs` : null;
  }
  function sourceNote(name, source) {
    const label = name === "bandwidth" ? "MBM traffic" : "CPU cache counters";
    if (!source.available) return `${label}: ${source.error || "Unavailable"}`;
    const s = source.summary;
    const parts = [source.stale ? `${label}: stale sample` : state?.mode === "history" ? `${label}: recorded sample` : `${label}: live`,
      `Captured ${capture(source.at)}`, source.raw.scope, s.scope_note];
    if (Number.isFinite(s.interval_ms) && s.interval_ms > 0) parts.push(`Interval ${metric(s.interval_ms / 1000)} s`);
    if (source.raw.partial) parts.push("Partial coverage");
    if (source.raw.error) parts.push(source.raw.error);
    if (name === "bandwidth") {
      if (Number.isFinite(s.control_group_count)) parts.push(`${metric(s.control_group_count)} control groups monitored`);
      if (s.inventory_complete === false) parts.push("Monitoring group inventory incomplete");
      const statuses = (source.raw.rows || []).flatMap(row => [row.total_status, row.local_status]);
      if (statuses.includes("baseline") || statuses.includes("reset")) parts.push("Interval traffic warming up or rebuilding a counter baseline");
      if (!Number.isFinite(s.mbm_total_bps) && !Number.isFinite(s.mbm_local_bps) && !statuses.includes("baseline") && !statuses.includes("reset")) parts.push("No complete aggregate traffic interval; valid LLC intervals remain visible");
    } else {
      const counts = s.metric_cpu_counts || {};
      const refs = coverage(counts.cache_references ?? counts.cache_references_per_second, s.cpu_count);
      const misses = coverage(counts.cache_misses ?? counts.cache_misses_per_second, s.cpu_count);
      const pairs = coverage(s.cache_sampled_cpus, s.cpu_count);
      if (refs) parts.push(`Access coverage ${refs}`);
      if (misses) parts.push(`Miss coverage ${misses}`);
      if (pairs) parts.push(`Miss ratio from paired counters on ${pairs}`);
      if (Number.isFinite(s.minimum_pmu_coverage_pct)) parts.push(`Minimum PMU running coverage ${metric(s.minimum_pmu_coverage_pct)}%`);
      if (!Number.isFinite(s.cache_references_per_second) && !Number.isFinite(s.cache_misses_per_second)) parts.push("No usable cache interval yet");
      if (s.note) parts.push(s.note);
    }
    return parts.filter(Boolean).join(" · ");
  }
  function draw() {
    const bandwidth = group("bandwidth");
    const perf = group("perf");
    discoverLlcs(bandwidth, perf);
    renderControls();
    const bandwidthValue = element("memoryBandwidthTotalValue");
    if (bandwidthValue) bandwidthValue.textContent = bandwidth.available
      ? `${metric(divide(bandwidth.summary.mbm_total_bps, 1e9))} GB/s · local ${metric(divide(bandwidth.summary.mbm_local_bps, 1e9))} GB/s` : "--";
    const amounts = [
      ["memoryCacheAccessTotalValue", perf.summary.cache_references_per_second, 1e6, "M events/s"],
      ["memoryCacheMissTotalValue", perf.summary.cache_misses_per_second, 1e6, "M events/s"],
      ["memoryCacheMissPercentTotalValue", perf.summary.cache_miss_pct, 1, "%"],
    ];
    for (const [id, value, divisor, unit] of amounts) if (element(id)) element(id).textContent = Number.isFinite(value)
      ? `${metric(value / divisor)}${unit === "%" ? "" : " "}${unit}` : "--";
    if (element("memoryBandwidthSource")) element("memoryBandwidthSource").textContent = sourceNote("bandwidth", bandwidth);
    if (element("memoryCacheSource")) element("memoryCacheSource").textContent = sourceNote("perf", perf);
    plot("memoryBandwidthTotalHistory", [series("Total monitored", "explore.bandwidth.mbm_total_bps", 1e9, "var(--series-green)"),
      series("Local monitored", "explore.bandwidth.mbm_local_bps", 1e9, "var(--series-blue)", [5, 3])], "GB/s");
    plot("memoryBandwidthLlcHistory", llcSeries("bandwidth", preferences.bandwidth === "local" ? "mbm_local_bps" : "mbm_total_bps", 1e9), "GB/s");
    if (element("memoryBandwidthLlcCaption")) element("memoryBandwidthLlcCaption").textContent = `Per LLC · ${preferences.bandwidth} monitored traffic`;
    plot("memoryCacheAccessTotalHistory", [series("All measured CPUs", "explore.perf.cache_references_per_second", 1e6, "var(--series-blue)")], "M events/s");
    plot("memoryCacheAccessLlcHistory", llcSeries("perf", "cache_references_per_second", 1e6), "M events/s");
    plot("memoryCacheMissTotalHistory", [series("All measured CPUs", "explore.perf.cache_misses_per_second", 1e6, "var(--series-orange)")], "M events/s");
    plot("memoryCacheMissLlcHistory", llcSeries("perf", "cache_misses_per_second", 1e6), "M events/s");
    plot("memoryCacheMissPercentTotalHistory", [series("Paired miss / access ratio", "explore.perf.cache_miss_pct", 1, "var(--series-purple)")], "%", true);
    plot("memoryCacheMissPercentLlcHistory", llcSeries("perf", "cache_miss_pct", 1), "%", true);
  }

  function renderTimeline(next) {
    state = next;
    snapshot = next.view?.sources?.explore || null;
    wholeSourceError = next.view?.source_errors?.explore || null;
    if (next.mode === "history" && Number.isFinite(snapshot?.meta?.captured_at_unix_ms)
      && Number.isFinite(selectedBound()) && snapshot.meta.captured_at_unix_ms > selectedBound()) wholeSourceError = "No source captured at or before the selected time";
    requestError = !snapshot ? next.loading ? "Loading the selected memory sample" : "No retained memory source at the selected time" : null;
    draw();
  }

  try {
    const stored = JSON.parse(localStorage.getItem(preferenceKey) || "null");
    if (stored && ["all", "none", "explicit"].includes(stored.mode)) preferences = {
      mode: stored.mode, selected: (Array.isArray(stored.selected) ? stored.selected : []).filter(id => llcId(id) !== null),
      bandwidth: stored.bandwidth === "local" ? "local" : "total",
    };
  } catch (_) { /* Keep defaults if saved settings are unavailable. */ }
  const mode = element("memoryBandwidthLlcMode");
  if (mode) { mode.value = preferences.bandwidth; mode.addEventListener("change", () => {
    preferences.bandwidth = mode.value === "local" ? "local" : "total";
    savePreferences();
    draw();
  }); }
  element("memoryLlcAll")?.addEventListener("click", () => { preferences.mode = "all"; preferences.selected = [];
    savePreferences(); draw(); });
  element("memoryLlcNone")?.addEventListener("click", () => { preferences.mode = "none"; preferences.selected = [];
    savePreferences(); draw(); });
  document.addEventListener?.("mitosis-theme-change", draw);
  globalThis.addEventListener?.("resize", () => {
    if (resizeFrame !== null) cancelAnimationFrame(resizeFrame);
    resizeFrame = requestAnimationFrame(() => { resizeFrame = null; draw(); });
  });
  timeline?.subscribe(renderTimeline);
})();
