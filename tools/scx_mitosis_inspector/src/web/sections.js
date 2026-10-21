(function installMitosisSections(root) {
  "use strict";

  if (root.MitosisSections) return;

  const document = root.document;
  const number = new Intl.NumberFormat("en-US");
  const rate = new Intl.NumberFormat("en-US", { maximumFractionDigits: 1 });
  const compact = new Intl.NumberFormat("en-US", { maximumFractionDigits: 2 });
  const chartColors = {
    blue: "var(--series-blue)",
    green: "var(--series-green)",
    orange: "var(--series-orange)",
    red: "var(--series-red)",
    purple: "var(--series-purple)",
  };
  const latencyColors = new WeakMap();
  const latencySelections = new WeakMap();

  function tableRow(values) {
    const row = document.createElement("tr");
    values.forEach((value, index) => {
      const cell = document.createElement(index === 0 ? "th" : "td");
      if (index === 0) cell.scope = "row";
      cell.textContent = value;
      row.append(cell);
    });
    return row;
  }

  function timingValue(value) {
    return value == null ? "--" : number.format(value);
  }

  function timingRow(label, timing) {
    const row = document.createElement("tr");
    const heading = document.createElement("th");
    heading.scope = "row";
    heading.textContent = label;
    row.append(heading);
    [timing.samples, timing.mean_ns, timing.p50_ns, timing.p95_ns, timing.p99_ns]
      .forEach((value) => {
        const cell = document.createElement("td");
        cell.textContent = timingValue(value);
        row.append(cell);
      });
    return row;
  }

  function sampleRateLabel(sampleRate) {
    return sampleRate === 0 ? "disabled" : `1 / ${number.format(sampleRate)}`;
  }

  function finiteAverage(rows, key) {
    const values = (rows || []).map((row) => Number(row[key])).filter(Number.isFinite);
    return values.length
      ? values.reduce((sum, value) => sum + value, 0) / values.length
      : Number.NaN;
  }

  function durationLabel(upperNs) {
    if (upperNs === Number.MAX_SAFE_INTEGER) return ">=104d";
    if (upperNs < 1_000) return `${upperNs}ns`;
    if (upperNs < 1_000_000) return `${rate.format(upperNs / 1_000)}us`;
    if (upperNs < 1_000_000_000) return `${rate.format(upperNs / 1_000_000)}ms`;
    return `${rate.format(upperNs / 1_000_000_000)}s`;
  }

  function windowLabel(milliseconds) {
    if (milliseconds < 1_000) return `${milliseconds}ms`;
    if (milliseconds < 60_000) return `${rate.format(milliseconds / 1_000)}s`;
    return `${rate.format(milliseconds / 60_000)}m`;
  }

  function bucketUpperNs(index) {
    return index >= 53 ? Number.MAX_SAFE_INTEGER : (2 ** (index + 1)) - 1;
  }

  function histogramBuckets(counts) {
    if (!Array.isArray(counts) || counts.length === 0) return [];
    const first = counts.findIndex((count) => count > 0);
    if (first < 0) return [];
    let last = counts.length - 1;
    while (last > first && counts[last] === 0) last -= 1;
    return counts.slice(first, last + 1).map((value, offset) => ({
      label: durationLabel(bucketUpperNs(first + offset)), value,
    }));
  }

  function drawLatencyHistogram(canvasId, counts) {
    root.MitosisCharts.drawHistogram(
      document.querySelector(`#${canvasId}`),
      histogramBuckets(counts),
      { unit: "" },
    );
  }

  function metricChoices(picker) {
    return [...picker.querySelector("fieldset").children].map((choice) => choice.children[0]);
  }

  function metricColor(picker, value) {
    if (!latencyColors.has(picker)) latencyColors.set(picker, new Map());
    const colors = latencyColors.get(picker);
    if (!colors.has(value)) {
      colors.set(value, `hsl(${(colors.size * 137.508) % 360} 65% 52%)`);
    }
    return colors.get(value);
  }

  function updateMetricSummary(picker) {
    const selected = [...picker.querySelector("fieldset").children]
      .filter((choice) => choice.children[0].checked);
    const text = selected.length === 1 ? selected[0].children[1].textContent
      : selected.length ? `${selected.length} selected` : "Choose metrics";
    const summary = picker.querySelector("summary");
    if (summary.textContent !== text) summary.textContent = text;
  }

  function syncMetricSelect(picker, rows, valueKey, label) {
    const field = picker.querySelector("fieldset");
    if (!rows?.length) {
      updateMetricSummary(picker);
      return;
    }
    const previous = [...field.children];
    if (!latencySelections.has(picker)) latencySelections.set(picker, new Set());
    const selected = latencySelections.get(picker);
    previous.forEach((choice) => {
      const input = choice.children[0];
      if (input.checked) selected.add(input.value);
      else selected.delete(input.value);
    });
    const byValue = new Map(previous.map((choice) => [choice.children[0].value, choice]));
    const ordered = [...rows].sort((left, right) =>
      String(left[valueKey]).localeCompare(String(right[valueKey]), undefined, { numeric: true }));
    const choices = ordered.map((row) => {
      const value = String(row[valueKey]);
      let choice = byValue.get(value);
      if (!choice) {
        choice = document.createElement("label");
        choice.className = "metric-choice";
        const input = document.createElement("input");
        input.type = "checkbox";
        input.value = value;
        input.checked = selected.has(value);
        choice.append(input, document.createElement("span"));
      }
      if (choice.children[1].textContent !== label(row)) choice.children[1].textContent = label(row);
      metricColor(picker, value);
      return choice;
    });
    if (!picker.dataset.initialized) {
      choices[0].children[0].checked = true;
      selected.add(choices[0].children[0].value);
      picker.dataset.initialized = "true";
    }
    // Reconcile individual choices so a surviving focused checkbox stays attached.
    const wanted = new Set(choices);
    previous.filter((choice) => !wanted.has(choice)).forEach((choice) => field.removeChild(choice));
    choices.forEach((choice, index) => {
      if (field.children[index] !== choice) field.insertBefore(choice, field.children[index] || null);
    });
    updateMetricSummary(picker);
  }

  function drawSelectedLatencyHistogram(canvasId, picker, rows, valueKey, label, bucketKey) {
    syncMetricSelect(picker, rows, valueKey, label);
    const byValue = new Map(rows.map((row) => [String(row[valueKey]), row]));
    const selected = metricChoices(picker).filter((choice) => choice.checked)
      .map((choice) => byValue.get(choice.value)).filter(Boolean);
    let first = Infinity;
    let last = -1;
    selected.forEach((row) => {
      (row[bucketKey] || []).forEach((count, index) => {
        if (Number.isFinite(count) && count > 0) {
          first = Math.min(first, index);
          last = Math.max(last, index);
        }
      });
    });
    const series = selected.map((row) => ({
      label: label(row),
      color: metricColor(picker, String(row[valueKey])),
      // All series share the same absolute duration bins, including empty bins.
      buckets: last < first ? [] : Array.from({ length: last - first + 1 }, (_, offset) => ({
        label: durationLabel(bucketUpperNs(first + offset)),
        value: row[bucketKey]?.[first + offset] || 0,
      })),
    }));
    root.MitosisCharts.drawHistogramSeries(document.querySelector(`#${canvasId}`), series,
      { unit: "", showLegend: false });
    const legend = series.map((item) => {
      const entry = document.createElement("li");
      const swatch = document.createElement("span");
      swatch.className = "series-swatch";
      swatch.setAttribute("style", `background-color: ${item.color}`);
      swatch.setAttribute("aria-hidden", "true");
      const text = document.createElement("span");
      text.textContent = item.label;
      entry.append(swatch, text);
      return entry;
    });
    document.querySelector(`#${canvasId}Legend`).replaceChildren(...legend);
  }

  function renderKeyValues(target, source, formatters = {}) {
    if (!source?.available || !source.value) {
      target.replaceChildren(tableRow(["Unavailable", source?.error || "No data"]));
      return;
    }
    target.replaceChildren(...Object.entries(source.value)
      .filter(([, value]) => typeof value !== "object")
      .map(([key, value]) => tableRow([
        key.replaceAll("_", " "),
        formatters[key] ? formatters[key](value) : value == null ? "--" : compact.format(value),
      ])));
  }

  // One selected source from the shared timeline view, with its freshness.
  function timelineSource(state, name, { observer = name !== "system" } = {}) {
    const raw = name === "migrations" ? state.view?.migrations : state.view?.sources?.[name];
    const sourceError = state.view?.source_errors?.[name] || raw?.meta?.error || raw?.error
      || (observer && raw?.collector?.status !== "active" ? raw?.collector?.error
        || (raw ? `Collector ${raw.collector?.status || "unavailable"}` : null) : null);
    const error = sourceError || state.error;
    const snapshot = raw && !sourceError ? raw : null;
    const health = root.MitosisPolling.freshnessModel({ hasData: Boolean(snapshot), meta: raw?.meta,
      pollError: error || (!raw ? state.loading ? "Loading selected sample" : "No retained sample" : null),
      now: state.mode === "history" ? state.view?.at_unix_ms ?? state.selectedAt : state.nowMs,
      pollIntervalMs: 1000 });
    return { snapshot, health };
  }

  function chartRange(state) {
    return state ? { minX: state.oldestAt,
      maxX: state.mode === "history" ? state.selectedAt : state.latestAt } : {};
  }

  // Changes only when retained graph history visible at the selection changes.
  function chartSignature(state) {
    const cutoff = state.mode === "history" ? state.selectedAt : state.latestAt;
    const retained = (state.frames || []).filter((frame) => frame.at_unix_ms <= cutoff);
    return [state.instanceId, state.mode, cutoff, state.oldestAt,
      retained.length, retained[0]?.seq, retained.at(-1)?.seq].join(":");
  }

  function sourceLabel(state, source) {
    return state.mode === "history" && source.health.state === "fresh"
      ? "Historical sample" : source.health.label;
  }

  // The first entry is the page's primary source; "any" pages are live while
  // any of their sources is fresh.
  function renderPageStatus(state, entries, { liveWhen = "primary" } = {}) {
    const sources = entries.map(([, source]) => source);
    const deciding = liveWhen === "any" ? sources : sources.slice(0, 1);
    const live = state.mode === "live" && deciding.some((source) => source.health.state === "fresh");
    const status = document.querySelector("#status");
    status.classList.toggle("live", live);
    status.classList.toggle("stale", !live && state.mode === "live"
      && deciding.some((source) => source.health.state === "stale"));
    document.querySelector("#statusText").textContent = state.loading && !state.view
      ? "Loading selected time"
      : state.mode === "history" ? "Historical" : live ? "Live" : sources[0].health.label;
    const detail = document.querySelector("#sourceStatus");
    if (detail) detail.textContent = entries.map(([name, source]) => `${name}: ${sourceLabel(state, source)}${
      source.health.detail ? ` (${source.health.detail})` : ""}`).join(" · ");
    const at = sources[0].snapshot?.meta?.captured_at_unix_ms;
    const refreshed = document.querySelector("#refreshed");
    if (refreshed) refreshed.textContent = Number.isFinite(at) ? new Date(at).toLocaleTimeString() : "--";
  }

  // Reveals requested sections and highlights the "On this page" link in view.
  function bindSectionNavigation() {
    const links = [...document.querySelectorAll("#sectionNavigation a[href^='#']")];
    const targets = links.map((link) => ({ link, target: document.querySelector(link.hash) }))
      .filter((entry) => entry.target);
    let pending = false;
    function reveal(hash) {
      const entry = targets.find(({ link }) => link.hash === hash);
      if (!entry) return null;
      const details = entry.target.querySelector(":scope > details");
      if (details) details.open = true;
      return entry.target;
    }
    function update() {
      pending = false;
      if (targets.length === 0) return;
      const atPageBottom = root.innerHeight + root.scrollY >= document.documentElement.scrollHeight - 4;
      let active = targets[0];
      if (atPageBottom) {
        active = targets.at(-1);
      } else {
        const threshold = Math.min(160, root.innerHeight * 0.25);
        targets.forEach((entry) => {
          if (entry.target.getBoundingClientRect().top <= threshold) active = entry;
        });
      }
      links.forEach((link) => {
        if (link === active.link) link.setAttribute("aria-current", "location");
        else link.removeAttribute("aria-current");
      });
    }
    function schedule() {
      if (pending) return;
      pending = true;
      root.requestAnimationFrame(update);
    }
    targets.forEach(({ link }) => {
      link.addEventListener("click", (event) => {
        if (event.defaultPrevented || event.button !== 0 || event.ctrlKey || event.metaKey
            || event.shiftKey || event.altKey) return;
        reveal(link.hash);
      });
    });
    root.addEventListener("scroll", schedule, { passive: true });
    root.addEventListener("resize", schedule);
    root.addEventListener("hashchange", () => {
      reveal(root.location?.hash);
      schedule();
    });
    function revealInitialHash() {
      const hash = root.location?.hash;
      const target = reveal(hash);
      if (!target) return;
      root.requestAnimationFrame(() => {
        if (root.location?.hash !== hash) return;
        target.scrollIntoView({ block: "start" });
        update();
      });
    }
    // Deferred page scripts restore collapse preferences before DOMContentLoaded.
    if (document.readyState === "complete") revealInitialHash();
    else document.addEventListener("DOMContentLoaded", revealInitialHash, { once: true });
    update();
  }

  // Sends links to sections that moved off this page to their new page.
  function forwardMovedSections(destinations) {
    const hash = root.location?.hash;
    const destination = hash ? destinations[hash] : null;
    if (destination && destination !== root.location.pathname
        && typeof root.location.replace === "function") {
      root.location.replace(`${destination}${hash}`);
    }
  }

  root.MitosisSections = {
    number, rate, compact, chartColors,
    tableRow, timingValue, timingRow, sampleRateLabel, finiteAverage, durationLabel, windowLabel,
    histogramBuckets, drawLatencyHistogram, metricChoices, metricColor, updateMetricSummary,
    syncMetricSelect, drawSelectedLatencyHistogram, renderKeyValues, timelineSource, chartRange,
    chartSignature, renderPageStatus, bindSectionNavigation, forwardMovedSections,
  };
})(globalThis);
