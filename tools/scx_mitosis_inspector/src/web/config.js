"use strict";

const status = document.querySelector("#status");
const statusText = document.querySelector("#statusText");
const rows = document.querySelector("#configurationRows");
const inactiveRows = document.querySelector("#inactiveConfigurationRows");
const search = document.querySelector("#configurationSearch");
const number = new Intl.NumberFormat("en-US");
let snapshot = null;
let stateFilter = "all";
const statusOrder = { explicit: 0, default: 1, unset: 2, disabled: 3 };

function cell(tag, value, className) {
  const element = document.createElement(tag);
  element.textContent = value;
  if (className) element.className = className;
  return element;
}

function optionRow(option) {
  const row = document.createElement("tr");
  const stateCell = document.createElement("td");
  stateCell.append(cell("span", option.status, `configuration-status configuration-status-${option.status}`));
  row.append(
    stateCell,
    cell("th", option.name, "configuration-option"),
    cell("td", option.current_value, "configuration-value"),
    cell("td", option.default ?? "--", "configuration-value"),
    cell("td", option.group),
    cell("td", option.description),
  );
  row.children[1].scope = "row";
  return row;
}

function matches(option) {
  if (stateFilter !== "all" && option.status !== stateFilter) return false;
  const query = search.value.trim().toLowerCase();
  if (!query) return true;
  return [
    option.name,
    option.current_value,
    option.default,
    option.group,
    option.description,
    ...(option.possible_values || []),
  ].some((value) => String(value ?? "").toLowerCase().includes(query));
}

function renderRows() {
  const visible = (snapshot?.options || [])
    .filter(matches)
    .sort((left, right) => (statusOrder[left.status] ?? 4) - (statusOrder[right.status] ?? 4));
  const active = visible.filter((option) => ["explicit", "default"].includes(option.status));
  const inactive = visible.filter((option) => ["unset", "disabled"].includes(option.status));
  rows.replaceChildren(...active.map(optionRow));
  inactiveRows.replaceChildren(...inactive.map(optionRow));
  document.querySelector("#activeConfigurationSection").hidden = active.length === 0;
  document.querySelector("#inactiveConfigurationSection").hidden = inactive.length === 0;
  document.querySelector("#configurationMatchCount").textContent =
    `${number.format(visible.length)} of ${number.format(snapshot?.options?.length || 0)} options`;
}

function count(statusName) {
  return snapshot.options.filter((option) => option.status === statusName).length;
}

function render(next) {
  snapshot = next;
  document.querySelector("#configurationPid").textContent = next.pid == null
    ? "--"
    : number.format(next.pid);
  document.querySelector("#configurationVersion").textContent = next.version || "--";
  document.querySelector("#configurationOptionCount").textContent = number.format(next.options.length);
  document.querySelector("#configurationExplicitCount").textContent = number.format(count("explicit"));
  document.querySelector("#configurationDefaultCount").textContent = number.format(count("default"));
  document.querySelector("#configurationInactiveCount").textContent = number.format(
    count("disabled") + count("unset"),
  );
  document.querySelector("#configurationExecutable").textContent = next.executable || "Executable unavailable";
  document.querySelector("#configurationCommandLine").textContent = next.command_line.length
    ? next.command_line.join(" ")
    : "Running command unavailable";
  renderRows();
  status.classList.toggle("live", next.available);
  status.classList.toggle("stale", !next.available);
  statusText.textContent = next.available ? "Live configuration" : (next.error || "Unavailable");
}

async function refresh() {
  try {
    const response = await fetch("/api/config", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    render(await response.json());
  } catch (error) {
    status.classList.remove("live", "stale");
    statusText.textContent = "Unavailable";
  }
}

search.addEventListener("input", renderRows);
document.querySelectorAll("[name=configurationState]").forEach((control) => {
  control.addEventListener("change", () => {
    if (!control.checked) return;
    stateFilter = control.value;
    renderRows();
  });
});

refresh();
