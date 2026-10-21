(() => {
  "use strict";

  const timeline = globalThis.MitosisTimeline || null;
  const charts = globalThis.MitosisCharts || null;
  const formatter = new Intl.NumberFormat("en-US", { maximumFractionDigits: 2 });
  const mib = 1024 * 1024;
  const pageSize = 50;
  // Sections live on the Scheduling and System pages; each page renders the ones it contains.
  const preferenceKey = "mitosis-explore-sections-v2";
  const sections = ["Dsqs", "Tasks", "Perf", "Bandwidth", "Wakers", "ScxEvents", "Ipis", "Idle", "Hardware"];
  const groupIds = { dsqs: "Dsqs", tasks: "Tasks", perf: "Perf", bandwidth: "Bandwidth",
    wakers: "Wakers", scx_events: "ScxEvents", ipis: "Ipis", idle: "Idle", pressure: "Pressure",
    thermal: "Thermal", power: "Power" };
  const groupLabels = { dsqs: "DSQs", tasks: "Threads", perf: "PMU", bandwidth: "Memory domains",
    wakers: "Handoffs", scx_events: "Fallbacks", ipis: "IPIs", idle: "Idle",
    pressure: "Thermal pressure", thermal: "Temperature", power: "Power" };
  const tableState = {};
  const groupViews = {};
  let displayed = null;
  let selectedState = null;
  let transportError = null;
  let preferences = {};

  const element = id => document.querySelector(id.startsWith("#") ? id : `#${id}`);
  const metric = value => Number.isFinite(value) ? formatter.format(value) : "--";
  const text = value => value == null || value === "" ? "--" : String(value);
  const scaled = (value, scale) => Number.isFinite(value) ? value / scale : null;
  const numberOrNull = value => Number.isFinite(value) ? value : null;
  const groupReport = value => value?.groups && typeof value.groups === "object" && !Array.isArray(value.groups);
  function count(value) {
    if (Number.isFinite(value) && value >= 0) return formatter.format(value);
    if (typeof value === "string" && /^\d+$/.test(value)) {
      try { return formatter.format(BigInt(value)); } catch (_) { /* Display unparsed IDs as text. */ }
    }
    return "--";
  }
  function clock(at) {
    return Number.isFinite(at) ? new Date(at).toLocaleString("en-US", {
      month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit",
      timeZoneName: "short", hour12: false,
    }) : "--";
  }
  function interval(ms) {
    return Number.isFinite(ms) && ms > 0 ? ms >= 1000 ? `${metric(ms / 1000)} s` : `${metric(ms)} ms` : "--";
  }
  function duration(ns) {
    return ns < 1000 ? `${count(ns)} ns` : ns < 1e6 ? `${metric(ns / 1000)} µs`
      : ns < 1e9 ? `${metric(ns / 1e6)} ms` : `${metric(ns / 1e9)} s`;
  }
  function cpuList(values) {
    if (!Array.isArray(values) || !values.length) return "--";
    const cpus = [...new Set(values.filter(value => Number.isInteger(value) && value >= 0))].sort((a, b) => a - b);
    const ranges = [];
    for (let index = 0; index < cpus.length; index += 1) {
      const first = cpus[index];
      let last = first;
      while (index + 1 < cpus.length && cpus[index + 1] === last + 1) last = cpus[++index];
      ranges.push(first === last ? String(first) : `${first}–${last}`);
    }
    return ranges.join(", ") || "--";
  }
  const path = (from, to) => `${text(from)} → ${text(to)}`;
  const bool = value => value === true ? "Yes" : value === false ? "No" : "--";
  const stateLabel = value => ({ measured: "Measured", baseline: "Warming up", reset: "Reset baseline",
    accounting_catchup: "Waiting for idle accounting", read_error: "Read failed", unavailable: "Unavailable", unsupported: "Unsupported" }[value] || text(value));
  function rowStatus(item) {
    if (item.error) return item.error;
    if (item.disabled === true) return "Disabled";
    return item.status ? stateLabel(item.status) : item.available === false ? "Unavailable" : item.partial ? "Partial" : "Measured";
  }
  function pmuCoverage(item) {
    const values = Object.values(item.metrics || {}).map(value => value?.coverage_pct).filter(Number.isFinite);
    return values.length ? Math.min(...values) : null;
  }
  function pmuStatus(item) {
    if (item.error) return item.error;
    if (item.available === false) return "Unavailable";
    if (item.partial) return "Partial";
    const values = Object.values(item.metrics || {});
    return values.some(value => value?.baseline) ? "Warming up" : "Measured";
  }
  function bandwidthStatus(item) {
    if (item.error) return item.error;
    return [...new Set([item.local_status, item.total_status, item.occupancy_status].filter(Boolean))]
      .map(stateLabel).join(" · ") || "--";
  }
  function sensorScope(item) {
    const identity = item.scope === "package" ? item.package : item.scope === "physical core" ? item.core : null;
    return `${text(item.scope)}${identity == null ? "" : ` ${identity}`}`;
  }
  function powerLimits(item) {
    const values = (item.power_limits || []).filter(limit => Number.isFinite(limit.power_limit_watts));
    return values.map(limit => `${metric(limit.power_limit_watts)} W (${text(limit.name)})`).join(" · ") || "--";
  }
  function column(label, key, format = metric, unit = "", options = {}) {
    return { label, value: typeof key === "function" ? key : row => row[key], format, unit, ...options };
  }
  const columns = {
    dsqs: [column("DSQ", row => row.dsq_hex || row.dsq_id, text, "ID", { sortValue: row => row.dsq_id }),
      column("Inserts", "insert_events", count, "total"), column("Moves", "move_events", count, "total"),
      column("Wait samples", row => row.latency?.samples ?? row.residence_samples, count, "observed"),
      column("Wait mean", row => row.latency?.mean_us, metric, "µs"), column("Wait p95", row => row.latency?.p95_us, metric, "µs"),
      column("Wait p99", row => row.latency?.p99_us, metric, "µs"),
      column("Depth mean", row => row.depth?.mean, metric, "tasks"), column("Depth latest", row => row.depth?.last, count, "tasks"),
      column("Depth max", row => row.depth?.max, count, "tasks"), column("Run mean", row => row.run?.mean_us, metric, "µs"),
      column("Run p95", row => row.run?.p95_us, metric, "µs"), column("Run max", row => row.run?.max_us, metric, "µs")],
    tasks: [column("TID", "pid", count), column("Thread", "comm", text, "name", { textual: true }),
      column("CPU use", "cpu_equivalents", metric, "CPUs · interval"), column("Wakeup p95", row => row.delay?.p95_us, metric, "µs"),
      column("DSQ wait p95", row => row.dsq_delay?.p95_us, metric, "µs"),
      column("Runtime", row => scaled(row.runtime_ns, 1e6), metric, "ms · thread lifetime"), column("Wakeups", "wakeups", count, "tracked total"),
      column("Switches", "switches", count, "tracked total"), column("Last CPU", "cpu", count), column("LLC", "llc", count), column("NUMA", "node", count),
      column("CPU read", row => row.cpu_error || (Number.isFinite(row.cpu_equivalents) ? "Measured" : "Warming up"), text, "", { textual: true })],
    perf: [column("CPU", "cpu", count), column("LLC", "llc_id", count),
      column("Instructions", "instructions_per_second", metric, "/s"), column("Cycles", "cycles_per_second", metric, "/s"),
      column("IPC", "ipc", metric, "instructions/cycle"), column("Cache refs", "cache_references_per_second", metric, "/s"),
      column("Cache misses", "cache_misses_per_second", metric, "/s"), column("Cache miss ratio", "cache_miss_pct", metric, "%"),
      column("Frontend stalls", "stalled_frontend_cycles_per_second", metric, "cycles/s"),
      column("Backend stalls", "stalled_backend_cycles_per_second", metric, "cycles/s"),
      column("Min coverage", pmuCoverage, metric, "% PMU running"), column("Status", pmuStatus, text, "", { textual: true })],
    bandwidth: [column("Domain", "domain_id", text), column("LLC", "llc", count), column("NUMA", "node", count),
      column("CPUs", row => cpuList(row.cpus), text, "mapped", { textual: true }),
      column("Local traffic", row => scaled(row.mbm_local_bps, mib), metric, "MiB/s"),
      column("Total traffic", row => scaled(row.mbm_total_bps, mib), metric, "MiB/s"),
      column("LLC occupancy", row => scaled(row.llc_occupancy_bytes, mib), metric, "MiB"),
      column("Status", bandwidthStatus, text, "", { textual: true })],
    wakers: [column("Waker", row => `${text(row.waker_comm)} · ${text(row.waker_pid)}`, text, "name · TID", { textual: true }),
      column("Wakee", row => `${text(row.wakee_comm)} · ${text(row.wakee_pid)}`, text, "name · TID", { textual: true }),
      column("Handoffs", "wakeups", count, "tracked total"), column("Delay mean", row => row.latency?.mean_us, metric, "µs"),
      column("Delay p95", row => row.latency?.p95_us, metric, "µs"), column("Same CPU", "same_cpu", count, "total"),
      column("Same LLC", "same_llc", count, "total"), column("Cross LLC", "cross_llc", count, "total"),
      column("Cross NUMA", "cross_numa", count, "total"), column("Unknown", "unknown_locality", count, "locality"),
      column("Last CPU path", row => path(row.waker_cpu, row.wakee_cpu), text)],
    scx_events: [column("Event", "name", text, "kernel path", { textual: true }),
      column("Total", "total", count, "kernel session"), column("Interval", "interval_count", count, "observed"),
      column("Rate", "per_second", metric, "/s")],
    ipis: [column("From CPU", "source_cpu", count), column("To CPU", "target_cpu", count),
      column("LLC path", row => path(row.llc_from, row.llc_to), text), column("NUMA path", row => path(row.numa_from, row.numa_to), text),
      column("Total", "count", count, "since attachment"), column("Interval", "interval_count", count, "sends"),
      column("Rate", "per_second", metric, "/s")],
    idle: [column("CPU", "cpu", count), column("State", row => row.name || row.state, text),
      column("Description", "description", text, "driver", { textual: true }), column("Residency", "residency_pct", metric, "% elapsed"),
      column("Entries", "entries_per_second", metric, "/s"), column("Entry total", "entries", count, "driver cumulative"),
      column("Driver exit latency", "exit_latency_us", metric, "µs"), column("Time total", row => scaled(row.time_us, 1e6), metric, "s · driver cumulative"),
      column("LLC", "llc", count), column("NUMA", "node", count), column("Status", rowStatus, text, "", { textual: true })],
    pressure: [column("CPU", "cpu", count), column("LLC", "llc", count), column("NUMA", "node", count),
      column("Capacity loss", "pressure", metric, "scale 1024"),
      column("Capacity loss", row => Number.isFinite(row.pressure) && Number.isFinite(row.capacity_scale) && row.capacity_scale > 0
        ? row.pressure / row.capacity_scale * 100 : null, metric, "%"),
      column("Updated", "last_update_unix_ms", clock, "host time", { textual: true })],
    thermal: [column("Sensor", row => row.label || row.sensor_id, text, "driver label", { textual: true }),
      column("Scope", sensorScope, text, "", { textual: true }), column("Temperature", "temperature_celsius", metric, "°C"),
      column("High", "high_celsius", metric, "°C"), column("Critical", "critical_celsius", metric, "°C"),
      column("Alarm", "alarm", bool), column("Device", "device", text, "", { textual: true }),
      column("Error", "error", text, "", { textual: true })],
    power: [column("Domain", "domain", text, "name", { textual: true }), column("Scope", "scope", text),
      column("Package", "package", count), column("Power", "power_watts", metric, "W"),
      column("Energy counter", row => scaled(row.energy_uj, 1e6), metric, "J"), column("Interval", "interval_ms", metric, "ms"),
      column("Limits", powerLimits, text, "configured", { textual: true }), column("Status", rowStatus, text, "", { textual: true })],
  };

  function sourceView(key) {
    const raw = displayed?.groups?.[key];
    let error = !raw ? transportError || "No recorded source at the selected time" : null;
    const upperBound = selectedState?.mode === "history" ? Math.min(selectedState.selectedAt,
      selectedState.view?.at_unix_ms ?? selectedState.selectedAt) : null;
    const capture = raw?.meta?.captured_at_unix_ms ?? displayed?.meta?.captured_at_unix_ms;
    if (Number.isFinite(upperBound) && Number.isFinite(capture) && capture > upperBound) error = "No recorded source at or before the selected time";
    if (!error && raw?.available !== true) error = raw?.error || raw?.meta?.error || "Source unavailable";
    const available = Boolean(raw && !error);
    const now = selectedState?.mode === "history" ? upperBound : selectedState?.nowMs ?? Date.now();
    const health = globalThis.MitosisPolling?.freshnessModel({ hasData: available,
      meta: raw?.meta || displayed?.meta, pollError: available ? null : error, now,
      pollIntervalMs: Number.isFinite(raw?.summary?.interval_ms) ? raw.summary.interval_ms : 1000 });
    const state = !available ? selectedState?.loading && !raw ? "waiting" : "unavailable"
      : health?.state === "stale" ? "stale" : raw.partial ? "partial" : "fresh";
    const label = !available ? state === "waiting" ? "Loading" : "Unavailable"
      : state === "stale" ? selectedState?.mode === "history" ? "Earlier sample" : "Stale"
        : raw.partial ? "Partial" : selectedState?.mode === "history" ? "Recorded" : "Live";
    return { raw, available, error, capture, state, label, rows: available && Array.isArray(raw.rows) ? raw.rows : [] };
  }

  function quality(key, view) {
    if (!view.available) return view.error || "No retained sample";
    const source = view.raw;
    const summary = source.summary || {};
    const parts = [];
    if (source.scope) parts.push(source.scope);
    if (Number.isFinite(view.capture)) parts.push(`Captured ${clock(view.capture)}`);
    if (Number.isFinite(summary.interval_ms) && summary.interval_ms > 0) parts.push(`Interval ${interval(summary.interval_ms)}`);
    if (Number.isFinite(summary.sample_rate) && summary.sample_rate >= 1) parts.push(summary.sample_rate === 1
      ? "Every eligible observation" : `1 in ${count(summary.sample_rate)} eligible observations sampled`);
    if (["dsqs", "tasks", "wakers", "scx_events", "ipis"].includes(key)) {
      const counterScope = summary.counter_scope || (["tasks", "wakers"].includes(key) ? "since this record entered tracking" : "since collection began");
      const histogramScope = summary.histogram_scope || counterScope;
      parts.push(`Totals: ${counterScope}`);
      if (["dsqs", "tasks", "wakers"].includes(key) && histogramScope !== counterScope) parts.push(`Distributions: ${histogramScope}`);
      parts.push("Rates cover the latest collection interval");
      if (summary.interval_valid === false) parts.push("Interval rates warming up");
    }
    if (summary.sample_policy) parts.push(summary.sample_policy);
    if (summary.scope_note) parts.push(summary.scope_note);
    if (summary.note) parts.push(summary.note);
    if (key === "tasks") parts.push("CPU use is in CPU equivalents; runtime spans the thread lifetime; location is the last observed CPU, LLC and NUMA node");
    if (key === "idle") parts.push("Driver exit latency estimate; residency uses full elapsed wall time, including active time");
    if (key === "perf") {
      parts.push("Rates scale for PMU running time; IPC and cache ratio use concurrently counted pairs");
      if (Number.isFinite(summary.ipc_sampled_cpus)) parts.push(`IPC covers ${count(summary.ipc_sampled_cpus)} CPUs`);
      if (Number.isFinite(summary.cache_sampled_cpus)) parts.push(`Cache ratio covers ${count(summary.cache_sampled_cpus)} CPUs`);
    }
    if (key === "pressure") parts.push("Kernel hardware capacity loss; full capacity is 1024");
    if (key === "thermal") parts.push("Sensor labels and scope come from the driver");
    if (key === "power" && !summary.scope_note) parts.push("Package total counts each package once; child domains are shown separately");
    if (source.partial) parts.push("Partial coverage");
    if (Number.isFinite(summary.truncated_rows) && summary.truncated_rows > 0) parts.push(`${count(summary.truncated_rows)} tracked rows omitted`);
    if (Number.isFinite(summary.tracking_failures_total) && summary.tracking_failures_total > 0) parts.push(`${count(summary.tracking_failures_total)} tracking failures since attachment`);
    if (source.error) parts.push(source.error);
    return parts.join(" · ");
  }

  function facts(key, view) {
    const target = element(`explore${groupIds[key]}Facts`);
    if (!target) return;
    const s = view.available ? view.raw.summary || {} : {};
    const values = {
      dsqs: [["Interval wait p95", s.latency_p95_us, "µs"], ["Interval mean depth", s.depth_mean, "tasks"],
        ["Interval run mean", s.running_mean_us, "µs"], ["Tracked queues", s.tracked_count, ""]],
      tasks: [["Tracked CPU use", s.cpu_equivalents, "CPUs"], ["Interval scheduling delay", s.delay_mean_us, "µs"],
        ["Tracked threads", s.tracked_count, ""]],
      perf: [["Instructions / cycle", s.ipc, "IPC"], ["Cache miss ratio", s.cache_miss_pct, "%"],
        ["Measured CPUs", s.sampled_cpus, ""], ["Minimum PMU coverage", s.minimum_pmu_coverage_pct, "%"]],
      bandwidth: [["Local memory traffic", scaled(s.mbm_local_bps, mib), "MiB/s"],
        ["Total memory traffic", scaled(s.mbm_total_bps, mib), "MiB/s"], ["LLC occupancy", scaled(s.llc_occupancy_bytes, mib), "MiB"]],
      wakers: [["Interval handoffs", s.per_second, "/s"], ["Interval mean delay", s.latency_mean_us, "µs"],
        ["Tracked relationships", s.tracked_count, ""]],
      scx_events: [["Interval kernel events", s.per_second, "/s"]],
      ipis: [["Interval IPI sends", s.per_second, "/s"], ["Tracked CPU pairs", s.tracked_count, ""]],
      idle: [["Idle residency", s.idle_residency_pct, "% elapsed"],
        ["Active or unaccounted", s.active_or_unaccounted_pct, "% elapsed"],
        ["Measured CPUs", Number.isFinite(s.measured_cpu_count) && Number.isFinite(s.cpu_count)
          ? `${count(s.measured_cpu_count)} / ${count(s.cpu_count)}` : s.measured_cpu_count, ""]],
      pressure: [["Maximum capacity loss", s.max_pressure, "/ 1024"]],
      thermal: [["Highest temperature", s.max_temperature_celsius, "°C"], ["Sensors", s.sensor_count, ""]],
      power: [["Package total", s.package_power_watts, "W"], ["Packages", s.package_count, ""]],
    }[key] || [];
    target.replaceChildren(...values.filter(([, value]) => Number.isFinite(value) || typeof value === "string" && value.length > 0).map(([label, value, unit]) => {
      const wrapper = document.createElement("div");
      const title = document.createElement("dt");
      const amount = document.createElement("dd");
      title.textContent = label;
      amount.textContent = typeof value === "string" ? value : metric(value);
      if (unit) { const suffix = document.createElement("small"); suffix.textContent = unit; amount.append(suffix); }
      wrapper.append(title, amount);
      return wrapper;
    }));
  }

  function searchText(key, item) {
    if (key === "tasks") return [item.comm, item.pid, item.tgid, item.cpu, item.llc, item.node].map(text).join(" ").toLowerCase();
    if (key === "wakers") return [item.waker_comm, item.wakee_comm, item.waker_pid, item.wakee_pid].map(text).join(" ").toLowerCase();
    if (key === "idle") return [item.cpu, item.state, item.name, item.description, item.llc, item.node].map(text).join(" ").toLowerCase();
    return "";
  }
  function compare(a, b, direction) {
    const missing = value => value == null || typeof value === "number" && !Number.isFinite(value);
    if (missing(a) || missing(b)) return missing(a) === missing(b) ? 0 : missing(a) ? 1 : -1;
    return (typeof a === "number" && typeof b === "number" ? a - b : String(a).localeCompare(String(b), "en-US", { numeric: true })) * direction;
  }
  function renderTable(key) {
    const id = groupIds[key];
    const target = element(`explore${id}Rows`);
    if (!target) return;
    const view = groupViews[key];
    const settings = tableState[key];
    const query = String(element(`explore${id}Search`)?.value || "").trim().toLowerCase();
    let rows = view.rows.filter(item => !query || searchText(key, item).includes(query));
    if (settings.sort != null) {
      const selected = columns[key][settings.sort];
      const sortValue = selected.sortValue || selected.value;
      rows = [...rows].sort((a, b) => compare(sortValue(a), sortValue(b), settings.direction));
    }
    const pageCount = Math.max(1, Math.ceil(rows.length / pageSize));
    settings.page = Math.min(settings.page, pageCount - 1);
    const slice = rows.slice(settings.page * pageSize, (settings.page + 1) * pageSize);
    if (!slice.length) {
      const tr = document.createElement("tr");
      const td = document.createElement("td");
      td.colSpan = columns[key].length;
      td.classList.add("explore-empty");
      td.textContent = !view.available ? view.error : query ? "No observations match this filter"
        : "No observations recorded for this source";
      tr.append(td);
      target.replaceChildren(tr);
    } else {
      target.replaceChildren(...slice.map(item => {
        const tr = document.createElement("tr");
        columns[key].forEach((definition, index) => {
          const td = document.createElement(index === 0 ? "th" : "td");
          if (index === 0) td.scope = "row";
          if (definition.textual) td.classList.add("explore-text");
          td.textContent = definition.format(definition.value(item));
          td.setAttribute("title", td.textContent);
          if (key === "perf" && definition.label === "Status") td.setAttribute("title", Object.entries(item.metrics || {})
            .map(([name, value]) => `${name.replaceAll("_", " ")}: ${value.error || (value.baseline ? "warming up" : value.available ? "supported" : "unavailable")}`)
            .join(" · "));
          tr.append(td);
        });
        return tr;
      }));
    }
    const footer = element(`explore${id}Count`);
    if (footer) footer.textContent = !view.available ? "No selected measurement" : rows.length
      ? `${count(settings.page * pageSize + 1)}–${count(Math.min((settings.page + 1) * pageSize, rows.length))} of ${count(rows.length)} rows${query ? ` · ${count(view.rows.length)} before filtering` : ""}`
      : query ? "0 matching rows" : "0 observations";
    const previous = element(`explore${id}Previous`);
    const next = element(`explore${id}Next`);
    if (previous) previous.disabled = settings.page === 0;
    if (next) next.disabled = settings.page + 1 >= pageCount;
  }
  function initializeTables() {
    for (const [key, definitions] of Object.entries(columns)) {
      const id = groupIds[key];
      tableState[key] = { page: 0, sort: null, direction: -1 };
      const head = element(`explore${id}Head`);
      if (head) head.replaceChildren(...definitions.map((definition, index) => {
        const th = document.createElement("th");
        th.scope = "col";
        th.setAttribute("aria-sort", "none");
        if (definition.textual) th.classList.add("explore-text");
        const button = document.createElement("button");
        button.type = "button";
        button.classList.add("explore-sort");
        button.textContent = definition.label;
        button.setAttribute("aria-label", `Sort ${groupLabels[key]} by ${definition.label}${definition.unit ? ` (${definition.unit})` : ""}`);
        if (definition.unit) { const unit = document.createElement("small"); unit.textContent = definition.unit; button.append(unit); }
        button.addEventListener("click", () => {
          const settings = tableState[key];
          settings.direction = settings.sort === index ? -settings.direction : typeof definition.value(groupViews[key]?.rows?.[0] || {}) === "number" ? -1 : 1;
          settings.sort = index;
          settings.page = 0;
          [...head.children].forEach((cell, position) => cell.setAttribute("aria-sort", position !== index ? "none" : settings.direction > 0 ? "ascending" : "descending"));
          renderTable(key);
        });
        th.append(button);
        return th;
      }));
      element(`explore${id}Search`)?.addEventListener("input", () => { tableState[key].page = 0; renderTable(key); updatePickers(); });
      element(`explore${id}Previous`)?.addEventListener("click", () => { tableState[key].page = Math.max(0, tableState[key].page - 1); renderTable(key); });
      element(`explore${id}Next`)?.addEventListener("click", () => { tableState[key].page += 1; renderTable(key); });
    }
  }

  function legend(canvas, series) {
    const parent = canvas?.parentElement;
    if (!parent) return;
    let target = parent.querySelector(".explore-legend");
    if (!target) { target = document.createElement("div"); target.classList.add("explore-legend"); parent.append(target); }
    target.replaceChildren(...series.map(item => {
      const entry = document.createElement("span");
      const swatch = document.createElement("i");
      swatch.setAttribute("aria-hidden", "true");
      swatch.style.setProperty("--legend-color", item.color);
      const name = document.createElement("span");
      name.textContent = item.label;
      entry.append(swatch, name);
      return entry;
    }));
  }
  function points(key, scale = 1) {
    const raw = timeline ? timeline.points(key) : [];
    const upper = selectedState?.mode === "history" ? selectedState.selectedAt : selectedState?.latestAt ?? Infinity;
    return raw.filter(point => Number.isFinite(point.x) && point.x <= upper).map(point => ({ ...point,
      y: Number.isFinite(point.y) ? point.y / scale : null }));
  }
  const historyCharts = [
    ["exploreDsqHistory", "exploreDsqHistoryPanel", "µs", [["Mean wait", "dsqs.latency_mean_us", "blue"], ["p95 wait", "dsqs.latency_p95_us", "orange"], ["Run mean", "dsqs.running_mean_us", "green"]]],
    ["exploreTaskHistory", "exploreTaskHistoryPanel", "CPUs", [["Tracked use", "tasks.cpu_equivalents", "blue"]]],
    ["exploreTaskDelayHistory", "exploreTaskDelayHistoryPanel", "µs", [["Mean delay", "tasks.delay_mean_us", "orange"]]],
    // Cache miss ratio and memory traffic history are charted with the System memory graphs.
    ["explorePerfHistory", "explorePerfHistoryPanel", "IPC", [["Instructions / cycle", "perf.ipc", "blue"]]],
    ["exploreOccupancyHistory", "exploreOccupancyHistoryPanel", "MiB", [["Occupancy", "bandwidth.llc_occupancy_bytes", "blue", mib]]],
    ["exploreWakerHistory", "exploreWakerHistoryPanel", "/s", [["Observed handoffs", "wakers.per_second", "blue"]]],
    ["exploreScxEventsHistory", "exploreScxEventsHistoryPanel", "/s", [["Kernel events", "scx_events.per_second", "orange"]]],
    ["exploreIpiHistory", "exploreIpiHistoryPanel", "/s", [["IPI sends", "ipis.per_second", "blue"]]],
    ["exploreIdleHistory", "exploreIdleHistoryPanel", "%", [["Idle residency", "idle.idle_residency_pct", "green"]]],
    ["explorePressureHistory", "explorePressureHistoryPanel", "%", [["Capacity loss", "pressure.max_pressure", "orange", 10.24]]],
    ["exploreThermalHistory", "exploreThermalHistoryPanel", "°C", [["Highest sensor", "thermal.max_temperature_celsius", "orange"]]],
    ["explorePowerHistory", "explorePowerHistoryPanel", "W", [["Package total", "power.package_power_watts", "blue"]]],
  ];
  function drawHistory() {
    if (!charts) return;
    for (const [canvasId, panelId, unit, definitions] of historyCharts) {
      const canvas = element(canvasId);
      const panel = element(panelId);
      const series = definitions.map(([label, key, color, scale = 1]) => ({ label,
        color: `var(--series-${color})`, points: points(`explore.${key}`, scale) }));
      const hasData = series.some(item => item.points.some(point => Number.isFinite(point.y)));
      if (panel) panel.hidden = !hasData;
      if (!hasData || !canvas) continue;
      legend(canvas, series);
      charts.drawLineChart(canvas, series, { minX: selectedState?.oldestAt,
        maxX: selectedState?.mode === "history" ? selectedState.selectedAt : selectedState?.latestAt,
        minY: 0, maxGapMs: 3000, unit, showLegend: false });
    }
  }

  const pickerSpecs = [
    { id: "exploreDsqSelect", group: "dsqs", name: row => row.dsq_hex || row.dsq_id,
      identity: row => String(row.dsq_id), samples: "exploreDsqSamples" },
    { id: "exploreTaskSelect", group: "tasks", name: row => `${text(row.comm)} · ${text(row.pid)}`,
      identity: row => `${row.pid}:${row.start_time_ns}`, samples: "exploreTaskSamples" },
    { id: "exploreWakerSelect", group: "wakers", name: row => `${text(row.waker_comm)} · ${text(row.waker_pid)} → ${text(row.wakee_comm)} · ${text(row.wakee_pid)}`,
      identity: row => `${row.waker_pid}:${row.waker_start_time_ns}:${row.wakee_pid}:${row.wakee_start_time_ns}`, samples: "exploreWakerSamples" },
  ];
  const pickerRows = {};
  function updatePickers() {
    for (const spec of pickerSpecs) {
      const target = element(spec.id);
      if (!target) continue;
      const old = target.value;
      const id = groupIds[spec.group];
      const query = String(element(`explore${id}Search`)?.value || "").trim().toLowerCase();
      const rows = (groupViews[spec.group]?.rows || []).filter(item => !query || searchText(spec.group, item).includes(query));
      pickerRows[spec.group] = new Map(rows.map(item => [spec.identity(item), item]));
      target.replaceChildren(...rows.map(item => {
        const option = document.createElement("option");
        option.value = spec.identity(item);
        option.textContent = spec.name(item);
        return option;
      }));
      target.disabled = !rows.length;
      target.value = pickerRows[spec.group].has(old) ? old : rows.length ? spec.identity(rows[0]) : "";
    }
    drawDistributions();
  }
  function histogramSeries(histogram, label, color) {
    if (!histogram || !Number.isFinite(histogram.samples) || histogram.samples <= 0 || !Array.isArray(histogram.buckets)
      || histogram.bucket_unit && histogram.bucket_unit !== "ns" || histogram.bucket_scale && histogram.bucket_scale !== "log2") return null;
    if (!histogram.buckets.length || histogram.buckets.some(value => !Number.isFinite(value) || value < 0)) return null;
    return { label, color: `var(--series-${color})`, buckets: histogram.buckets.map((value, index) => ({
      label: index === 0 ? "≤1 ns" : index === 63 ? `≥${duration(2 ** index)}`
        : `≤${duration(2 ** (index + 1) - 1)}`, value,
    })) };
  }
  function drawHistogram(canvasId, panelId, series) {
    const valid = series.filter(Boolean);
    const hasData = valid.some(item => item.buckets.some(bucket => bucket.value > 0));
    const panel = panelId ? element(panelId) : element(canvasId)?.parentElement;
    if (panel) panel.hidden = !hasData;
    if (!hasData || !charts) return false;
    let first = Infinity;
    let last = -1;
    valid.forEach(item => item.buckets.forEach((bucket, index) => { if (bucket.value > 0) { first = Math.min(first, index); last = Math.max(last, index); } }));
    const canvas = element(canvasId);
    if (!canvas) return false;
    const lower = Math.max(0, first - 1);
    const upper = Math.min(Math.max(...valid.map(item => item.buckets.length)), last + 2);
    const aligned = valid.map(item => ({ ...item, buckets: item.buckets.slice(lower, upper) }));
    legend(canvas, aligned);
    charts.drawHistogramSeries(canvas, aligned, { showLegend: false });
    return true;
  }
  function drawDistributions() {
    const selected = (key, id) => pickerRows[key]?.get(element(id)?.value);
    const dsq = selected("dsqs", "exploreDsqSelect");
    const task = selected("tasks", "exploreTaskSelect");
    const waker = selected("wakers", "exploreWakerSelect");
    const waitSeries = histogramSeries(dsq?.latency, "Queue wait", "blue");
    const runSeries = histogramSeries(dsq?.run, "Running duration", "green");
    const dsqPanel = element("exploreDsqDistributions");
    if (dsqPanel) dsqPanel.hidden = ![waitSeries, runSeries].some(series => series?.buckets.some(bucket => bucket.value > 0));
    drawHistogram("exploreDsqWaitChart", null, [waitSeries]);
    drawHistogram("exploreDsqRunChart", null, [runSeries]);
    drawHistogram("exploreTaskDelayChart", "exploreTaskDistributionPanel", [histogramSeries(task?.delay, "Wakeup delay", "orange"), histogramSeries(task?.dsq_delay, "DSQ wait", "blue")]);
    drawHistogram("exploreWakerDelayChart", "exploreWakerDistributionPanel", [histogramSeries(waker?.latency, "Wakee delay", "blue")]);
    if (element("exploreDsqSamples")) element("exploreDsqSamples").textContent = dsq ? `${count(dsq.latency?.samples)} wait · ${count(dsq.run?.samples)} run samples` : "No observed queue selected";
    if (element("exploreTaskSamples")) element("exploreTaskSamples").textContent = task ? `${count(task.delay?.samples)} wakeup · ${count(task.dsq_delay?.samples)} DSQ samples` : "No observed thread selected";
    if (element("exploreWakerSamples")) element("exploreWakerSamples").textContent = waker ? `${count(waker.latency?.samples)} observed latency samples` : "No observed handoff selected";
  }

  function savePreferences() {
    try { localStorage.setItem(preferenceKey, JSON.stringify(preferences)); } catch (_) { /* Storage can be disabled. */ }
  }
  function initializePreferences() {
    try { const parsed = JSON.parse(localStorage.getItem(preferenceKey) || "{}"); if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) preferences = parsed; } catch (_) { preferences = {}; }
    for (const id of sections) {
      const details = element(`explore${id}Details`);
      if (!details) continue;
      details.open = preferences[id]?.open !== false;
      details.addEventListener("toggle", () => {
        preferences[id] = { open: details.open === true };
        savePreferences();
        // Collapsed canvases have no size, so redraw once they are visible again.
        if (details.open) { drawHistory(); drawDistributions(); }
      });
    }
  }

  function renderHardwareStatus() {
    const badge = element("exploreHardwareStatus");
    if (!badge) return;
    const available = ["pressure", "thermal", "power"].filter(key => groupViews[key].available).length;
    badge.textContent = available ? `${available} / 3 available` : "Unavailable";
    badge.setAttribute("data-state", available === 3 ? "fresh" : available ? "partial" : "unavailable");
  }
  function render() {
    for (const key of Object.keys(groupIds)) {
      const view = sourceView(key);
      groupViews[key] = view;
      const badge = element(`explore${groupIds[key]}Status`);
      if (badge) { badge.textContent = view.label; badge.setAttribute("data-state", view.state); }
      const note = element(`explore${groupIds[key]}Quality`);
      if (note) note.textContent = quality(key, view);
      facts(key, view);
      renderTable(key);
    }
    renderHardwareStatus();
    updatePickers();
    drawHistory();
  }
  function renderTimeline(state) {
    selectedState = state;
    const raw = state.view?.sources?.explore;
    let sourceError = state.view?.source_errors?.explore || (!groupReport(raw) ? raw?.meta?.error : null) || null;
    const upper = state.mode === "history" ? Math.min(state.selectedAt, state.view?.at_unix_ms ?? state.selectedAt) : null;
    if (Number.isFinite(upper) && Number.isFinite(raw?.meta?.captured_at_unix_ms) && raw.meta.captured_at_unix_ms > upper) sourceError = "No recorded source at or before the selected time";
    displayed = raw && !sourceError ? raw : null;
    transportError = sourceError || (!raw ? state.loading ? "Loading selected source" : "No recorded source at the selected time" : null) || raw?.meta?.error || state.error;
    render();
  }

  initializeTables();
  initializePreferences();
  pickerSpecs.forEach(spec => element(spec.id)?.addEventListener("change", drawDistributions));
  document.addEventListener?.("mitosis-theme-change", () => { drawHistory(); drawDistributions(); });
  globalThis.addEventListener?.("resize", () => { drawHistory(); drawDistributions(); });
  timeline?.subscribe(renderTimeline);
})();
