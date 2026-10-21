const {
  number, rate, chartColors, timingRow, sampleRateLabel, tableRow, timelineSource, chartRange,
  chartSignature, renderPageStatus, drawSelectedLatencyHistogram, bindSectionNavigation,
  forwardMovedSections,
} = MitosisSections;
const cards = [...document.querySelectorAll("[data-callback]")];
const timeline = MitosisTimeline;
const callbackTimingRows = document.querySelector("#callbackTimingRows");
const bpfProgramRows = document.querySelector("#bpfProgramRows");
const callbackLatencyMetric = document.querySelector("#callbackLatencyMetric");
let latestSnapshot = null;

// Bookmarks to sections that moved to other pages keep working.
forwardMovedSections({
  "#migration-locality": "/scheduling",
  "#scheduler-latency": "/scheduling",
  "#dsq-performance": "/scheduling",
  "#scheduler-activity": "/scheduling",
  "#softirq-activity": "/system",
  "#hardirq-activity": "/system",
  "#block-io": "/system",
  "#probe-manifest": "/inspector",
  "#inspector-overhead": "/inspector",
});

function renderHistoryCharts() {
  MitosisCharts.drawLineChart(document.querySelector("#callbackRateHistoryChart"), [
    { label: "Callbacks", color: chartColors.blue, points: timeline.points("callbacks.callbacks") },
  ], { ...chartRange(timeline.getState()), unit: "/s", minY: 0, maxGapMs: 3000 });
}

function renderLatencyChart(snapshot) {
  drawSelectedLatencyHistogram("callbackLatencyChart", callbackLatencyMetric,
    snapshot.callback_timings, "callback", (row) => row.callback, "buckets");
}

function renderCallbackCost(snapshot) {
  const rates = new Map(snapshot.counters.map((counter) => [counter.name, counter.rate_per_second]));
  const items = snapshot.callback_timings.map((timing, index) => ({
    label: timing.callback,
    value: timing.mean_ns == null ? Number.NaN : timing.mean_ns * (rates.get(timing.callback) || 0) / 1_000_000,
    color: [chartColors.blue, chartColors.green, chartColors.orange, chartColors.red, chartColors.purple][index],
  }));
  MitosisCharts.drawBarChart(
    document.querySelector("#callbackCostChart"),
    items,
    { unit: "ms/s" },
  );
}

function renderBpfPrograms(programs) {
  const enabled = programs.some((program) => program.run_count > 0);
  document.querySelector("#bpfRuntimeStatus").textContent = enabled
    ? "Kernel runtime counters enabled"
    : "Kernel runtime counters disabled";
  bpfProgramRows.replaceChildren(...programs.map((program) => tableRow([
    program.name,
    number.format(program.id),
    number.format(program.run_count),
    number.format(program.run_time_ns),
    program.average_runtime_ns == null ? "--" : number.format(program.average_runtime_ns),
    number.format(program.recursion_misses),
    program.verified_insns == null ? "--" : number.format(program.verified_insns),
  ])));
}

function renderCards(snapshot) {
  const counters = new Map(snapshot.counters.map((counter) => [counter.name, counter]));
  cards.forEach((card, index) => {
    const counter = counters.get(card.dataset.callback);
    card.querySelector(".count").textContent = counter ? number.format(counter.count) : "--";
    card.querySelector(".rate").textContent = counter ? rate.format(counter.rate_per_second) : "--";
    card.querySelector(".program-id").textContent = counter ? snapshot.target_program_ids[index] ?? "--" : "--";
  });
}

function render(snapshot, drawHistory = true) {
  latestSnapshot = snapshot;
  document.querySelector("#scheduler").textContent = snapshot.scheduler;
  document.querySelector("#callbackTimingSampleRate").textContent =
    sampleRateLabel(snapshot.callback_timing_sample_rate);
  callbackTimingRows.replaceChildren(...snapshot.callback_timings.map((timing) =>
    timingRow(timing.callback, timing)));
  renderBpfPrograms(snapshot.bpf_program_stats);
  renderCards(snapshot);
  if (drawHistory) renderHistoryCharts();
  renderLatencyChart(snapshot);
  renderCallbackCost(snapshot);
}

function clearProbes() {
  latestSnapshot = null;
  callbackTimingRows.replaceChildren();
  bpfProgramRows.replaceChildren();
  cards.forEach((card) => {
    [".count", ".rate", ".program-id"].forEach((selector) => { card.querySelector(selector).textContent = "--"; });
  });
  ["#scheduler", "#callbackTimingSampleRate"]
    .forEach((selector) => { document.querySelector(selector).textContent = "--"; });
  document.querySelector("#bpfRuntimeStatus").textContent = "Unavailable at selected time";
  const empty = { counters: [], callback_timings: [] };
  renderLatencyChart(empty);
  renderCallbackCost(empty);
}

let renderedView;
let renderedProbes;
let renderedChart;
function renderTimeline(state) {
  const probes = timelineSource(state, "counters");
  const viewChanged = state.view !== renderedView || probes.snapshot !== renderedProbes;
  const signature = chartSignature(state);
  const chartsChanged = signature !== renderedChart;
  if (viewChanged && probes.snapshot) {
    render(probes.snapshot, chartsChanged);
  } else {
    if (viewChanged) clearProbes();
    if (chartsChanged) renderHistoryCharts();
  }
  renderedView = state.view;
  renderedProbes = probes.snapshot;
  renderedChart = signature;
  renderPageStatus(state, [["Probes", probes]]);
}

function redraw() {
  renderHistoryCharts();
  if (!latestSnapshot) return;
  renderLatencyChart(latestSnapshot);
  renderCallbackCost(latestSnapshot);
}

callbackLatencyMetric.addEventListener("change", () => {
  if (latestSnapshot) renderLatencyChart(latestSnapshot);
});
window.addEventListener("resize", redraw);
document.addEventListener?.("mitosis-theme-change", redraw);
bindSectionNavigation();
timeline.subscribe(renderTimeline);
