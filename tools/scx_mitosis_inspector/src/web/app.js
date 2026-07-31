const cards = [...document.querySelectorAll("[data-callback]")];
const status = document.querySelector("#status");
const statusText = document.querySelector("#statusText");
const number = new Intl.NumberFormat("en-US");
const rate = new Intl.NumberFormat("en-US", { maximumFractionDigits: 1 });
const callbackTimingRows = document.querySelector("#callbackTimingRows");

function timingValue(value) {
  return value == null ? "--" : number.format(value);
}

function renderCallbackTimings(snapshot) {
  const sampleRate = snapshot.callback_timing_sample_rate;
  document.querySelector("#callbackTimingSampleRate").textContent =
    sampleRate === 0 ? "disabled" : `1 / ${number.format(sampleRate)}`;

  const rows = snapshot.callback_timings.map((timing) => {
    const row = document.createElement("tr");
    const callback = document.createElement("th");
    callback.scope = "row";
    callback.textContent = timing.callback;
    row.append(callback);
    [timing.samples, timing.mean_ns, timing.p50_ns, timing.p95_ns, timing.p99_ns]
      .forEach((value) => {
        const cell = document.createElement("td");
        cell.textContent = timingValue(value);
        row.append(cell);
      });
    return row;
  });
  callbackTimingRows.replaceChildren(...rows);
}

function renderHostContext(context) {
  document.querySelector("#hostname").textContent = context.identity.hostname;
  document.querySelector("#kernelRelease").textContent = context.identity.kernel_release;
  document.querySelector("#cpuCount").textContent = number.format(context.identity.cpu_count);
}

function render(snapshot) {
  document.querySelector("#scheduler").textContent = snapshot.scheduler;
  document.querySelector("#uptime").textContent = `${snapshot.uptime_seconds}s`;
  document.querySelector("#refreshed").textContent = new Date().toLocaleTimeString();
  renderCallbackTimings(snapshot);

  const counters = new Map(snapshot.counters.map((counter) => [counter.name, counter]));
  cards.forEach((card, index) => {
    const counter = counters.get(card.dataset.callback);
    if (!counter) return;
    card.querySelector(".count").textContent = number.format(counter.count);
    card.querySelector(".rate").textContent = rate.format(counter.rate_per_second);
    card.querySelector(".program-id").textContent = snapshot.target_program_ids[index];
  });

  status.classList.add("live");
  statusText.textContent = "Live";
}

async function refreshHostContext() {
  const response = await fetch("/api/host-context", { cache: "no-store" });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  renderHostContext(await response.json());
}

async function refresh() {
  try {
    const response = await fetch("/api/counters", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    render(await response.json());
  } catch (error) {
    status.classList.remove("live");
    statusText.textContent = "Disconnected";
  }
}

refreshHostContext().catch(() => {});
refresh();
setInterval(refresh, 1000);
