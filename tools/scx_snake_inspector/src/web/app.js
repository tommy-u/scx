// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

import {
  axisLabelIndices,
  buildCpuUsage,
  buildMatrix,
  heatmapLayout,
  infernoColor,
  migrationLocality,
  normalizeCount,
  normalizeUtilization,
  parseTgids,
  topologyBoundaries,
} from "/assets/heatmap.js";
import {
  callbackDurationClass,
  callbackSampleRateOptions,
  captureKeyedRenderState,
  cellQueueFacts,
  cellCpuOrder,
  compactCpuList,
  decorateCells,
  fieldReferenceGroups,
  fineTimingCaptureModels,
  freshnessModel,
  formatCallbackDuration,
  formatFeedbackTranscript,
  ladderPercentages,
  launchDiff,
  parseFeedbackEntries,
  policyCategoryGroups,
  policyLibraryModels,
  policySlotComparison,
  queueLadderSections,
  queueTopologyModel,
  routeFromHash,
  runtimeContextModel,
  restoreKeyedRenderState,
  schedulerCommandPreview,
  schedulerControlModel,
  schedulerControlMessage,
  schedulerCurrentCommand,
  schedulerLaunchRequest,
  schedulerSettingModels,
  statsResetDisabled,
  syncCallbackSampleRateControl,
  updateFeedbackEntries,
  rungLadderPercentages,
  rungPercentages,
  selectionRungHitFlow,
  workloadAssignmentRequest,
} from "/assets/inspection.js";

const numberFormat = new Intl.NumberFormat();
const FEEDBACK_STORAGE_KEY = "scx-snake-inspector-feedback-v1";
const POLICY_FAIRNESS_OPTIONS = [
  {
    id: "fifo",
    label: "FIFO",
    description: "First-in, first-out queueing after placement.",
  },
  {
    id: "vtime",
    label: "VTIME",
    description: "Virtual-time fairness, including cell queue policies.",
  },
  {
    id: "eevdf",
    label: "EEVDF",
    description: "Experimental eligible virtual deadline fairness.",
  },
];
const token = document.querySelector('meta[name="snake-session-token"]').content;
const initialWindowMs = Number(document.body.dataset.initialWindowMs);
const maxWindowMs = Number(document.body.dataset.maxWindowMs);

const elements = {
  activePairs: document.querySelector("#activePairs"),
  applyScope: document.querySelector("#applyScope"),
  canvas: document.querySelector("#heatmapCanvas"),
  callbackCoverage: document.querySelector("#callbackCoverage"),
  callbackFreshness: document.querySelector("#callbacksFreshness"),
  callbackGeneration: document.querySelector("#callbackGeneration"),
  callbackRange: document.querySelector("#callbackRange"),
  callbackRangeSelect: document.querySelector("#callbackRangeSelect"),
  callbackSampleRate: document.querySelector("#callbackSampleRate"),
  callbackSampleRateControl: document.querySelector("#callbackSampleRateControl"),
  applyCallbackSampleRate: document.querySelector("#applyCallbackSampleRate"),
  callbackRateNotice: document.querySelector("#callbackRateNotice"),
  callbacksNotice: document.querySelector("#callbacksNotice"),
  callbacksView: document.querySelector("#callbacksView"),
  callbackTimingRows: document.querySelector("#callbackTimingRows"),
  fineTimingNotice: document.querySelector("#fineTimingNotice"),
  fineTimingPanels: document.querySelector("#fineTimingPanels"),
  feedbackNotice: document.querySelector("#feedbackNotice"),
  feedbackTranscript: document.querySelector("#feedbackTranscript"),
  feedbackView: document.querySelector("#feedbackView"),
  copyFeedback: document.querySelector("#copyFeedback"),
  clearFeedback: document.querySelector("#clearFeedback"),
  cgroupField: document.querySelector("#cgroupField"),
  cgroupInput: document.querySelector("#cgroupInput"),
  cellsFreshness: document.querySelector("#cellsFreshness"),
  cellsNotice: document.querySelector("#cellsNotice"),
  cellsView: document.querySelector("#cellsView"),
  cellDetail: document.querySelector("#cellDetail"),
  cellBarTooltip: document.querySelector("#cellBarTooltip"),
  cellList: document.querySelector("#cellList"),
  cellOrderMode: document.querySelector("#cellOrderMode"),
  workloadTargetKind: document.querySelector("#workloadTargetKind"),
  workloadTargetLabel: document.querySelector("#workloadTargetLabel"),
  workloadTargetValue: document.querySelector("#workloadTargetValue"),
  workloadCellId: document.querySelector("#workloadCellId"),
  assignWorkloadCell: document.querySelector("#assignWorkloadCell"),
  clearWorkloadCell: document.querySelector("#clearWorkloadCell"),
  workloadAssignmentNotice: document.querySelector("#workloadAssignmentNotice"),
  liveStatus: document.querySelector("#liveStatus"),
  liveStatusText: document.querySelector("#liveStatusText"),
  legendHigh: document.querySelector("#legendHigh"),
  legendLow: document.querySelector("#legendLow"),
  runtimeContextDetail: document.querySelector("#runtimeContextDetail"),
  migrationRate: document.querySelector("#migrationRate"),
  migrationPairInspection: document.querySelector("#migrationPairInspection"),
  notice: document.querySelector("#notice"),
  policyFreshness: document.querySelector("#policyFreshness"),
  policyActivationNotice: document.querySelector("#policyActivationNotice"),
  policyActiveContext: document.querySelector("#policyActiveContext"),
  policyCandidateAction: document.querySelector("#policyCandidateAction"),
  policyCandidateContext: document.querySelector("#policyCandidateContext"),
  policyCandidateImpact: document.querySelector("#policyCandidateImpact"),
  policyChoices: document.querySelector("#policyChoices"),
  policyDialog: document.querySelector("#policyDialog"),
  policyDialogName: document.querySelector("#policyDialogName"),
  policyDialogSource: document.querySelector("#policyDialogSource"),
  policyDialogSummary: document.querySelector("#policyDialogSummary"),
  policyLibraryNotice: document.querySelector("#policyLibraryNotice"),
  policyLibraryStatus: document.querySelector("#policyLibraryStatus"),
  invalidPolicies: document.querySelector("#invalidPolicies"),
  policyNotice: document.querySelector("#policyNotice"),
  policyView: document.querySelector("#policyView"),
  queueTopology: document.querySelector("#queueTopology"),
  primaryNav: document.querySelector("#primaryNav"),
  referencePopover: document.querySelector("#referencePopover"),
  resetAllStats: document.querySelector("#resetAllStats"),
  restartScheduler: document.querySelector("#restartScheduler"),
  confirmPolicyActivation: document.querySelector("#confirmPolicyActivation"),
  scopeMode: document.querySelector("#scopeMode"),
  scopeSummary: document.querySelector("#scopeSummary"),
  schedulerCommandPreview: document.querySelector("#schedulerCommandPreview"),
  schedulerPendingChanges: document.querySelector("#schedulerPendingChanges"),
  schedulerCurrentCommand: document.querySelector("#schedulerCurrentCommand"),
  schedulerControlNotice: document.querySelector("#schedulerControlNotice"),
  schedulerControlState: document.querySelector("#schedulerControlState"),
  schedulerControlView: document.querySelector("#controlView"),
  schedulerExitDumpEnabled: document.querySelector("#schedulerExitDumpEnabled"),
  schedulerExitDumpLen: document.querySelector("#schedulerExitDumpLen"),
  schedulerFairness: document.querySelector("#schedulerFairness"),
  schedulerFairnessEnabled: document.querySelector("#schedulerFairnessEnabled"),
  schedulerPolicy: document.querySelector("#schedulerPolicy"),
  schedulerSampleRate: document.querySelector("#schedulerSampleRate"),
  schedulerSampleRateEnabled: document.querySelector("#schedulerSampleRateEnabled"),
  schedulerSettingsRows: document.querySelector("#schedulerSettingsRows"),
  schedulerVerbose: document.querySelector("#schedulerVerbose"),
  statsResetNotice: document.querySelector("#statsResetNotice"),
  startScheduler: document.querySelector("#startScheduler"),
  stopScheduler: document.querySelector("#stopScheduler"),
  tgidField: document.querySelector("#tgidField"),
  tgidInput: document.querySelector("#tgidInput"),
  tooltip: document.querySelector("#heatmapTooltip"),
  totalMigrations: document.querySelector("#totalMigrations"),
  activityView: document.querySelector("#activityView"),
  slotComparison: document.querySelector("#slotComparison"),
  viewport: document.querySelector("#heatmapViewport"),
  windowCoverage: document.querySelector("#windowCoverage"),
  windowSelect: document.querySelector("#windowSelect"),
  zoom: document.querySelector("#zoomControl"),
};

const state = {
  callbackRange: String(initialWindowMs),
  callbackTiming: null,
  callbackTimingError: null,
  callbackTimingLoading: false,
  callbackRatePending: false,
  callbackRateDirty: false,
  cellOrderMode: "llc",
  fineTiming: null,
  fineTimingError: null,
  fineTimingLoading: false,
  lastFineTimingAt: 0,
  fineTimingPending: new Set(),
  feedbackEntries: loadFeedbackEntries(),
  expandedFeedbackKeys: new Set(),
  eventSource: null,
  geometry: null,
  inspection: null,
  inspectionContext: null,
  inspectionError: null,
  inspectionLoading: false,
  inspectionSequence: 0,
  lastInspectionAt: 0,
  lastCallbackTimingAt: 0,
  lastPolicyCatalogAt: 0,
  lastSchedulerControlAt: 0,
  lastSnapshotAt: 0,
  orderMode: "topology",
  popoverPinned: false,
  policyCatalog: null,
  policyCatalogError: null,
  policyCatalogLoading: false,
  policyLibraryMessage: null,
  policyActivationPending: false,
  policyCandidate: null,
  selectedPolicy: null,
  schedulerControl: null,
  schedulerControlError: null,
  schedulerControlLoading: false,
  schedulerControlPending: false,
  schedulerFormInitialized: false,
  selectedPolicyFairness: null,
  selectedLifecycleFairness: null,
  selectedLifecyclePolicyId: null,
  statsResetPending: false,
  referenceId: 0,
  pinnedMigrationPair: null,
  references: new Map(),
  route: routeFromHash(window.location.hash),
  scale: "log",
  selectedCellId: null,
  workloadAssignmentPending: false,
  snapshot: null,
  snapshotError: null,
  topology: null,
  windowMs: initialWindowMs,
  zoom: 1,
};

configureWindowSelector();
configureCallbackRangeSelector();
configureCallbackSampleRateSelector();
configureSchedulerSampleRateSelector();
bindControls();
decorateFeedbackTargets(document);
renderFeedback();
renderWorkloadTargetField();
renderSchedulerControl();
start().catch((error) => {
  setStatus("error", "Connection failed");
  showNotice(error.message);
});

async function start() {
  const response = await fetch("/api/topology", { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`Topology request failed (${response.status})`);
  }
  state.topology = await response.json();
  connectEvents();
  renderRoute();
  renderHeatmap();
  await loadInspection();
  await loadCallbackTiming();
  await loadFineTiming();
  await loadPolicyCatalog();
  await loadSchedulerControl();
  window.setInterval(loadInspection, 1_000);
  window.setInterval(loadCallbackTiming, 1_000);
  window.setInterval(loadFineTiming, 1_000);
  window.setInterval(loadPolicyCatalog, 5_000);
  window.setInterval(loadSchedulerControl, 2_000);
}

function configureWindowSelector() {
  const presets = [1_000, 5_000, 10_000, 30_000, 60_000, 120_000, 300_000]
    .filter((value) => value <= maxWindowMs);
  if (!presets.includes(initialWindowMs)) {
    presets.push(initialWindowMs);
    presets.sort((left, right) => left - right);
  }
  for (const value of presets) {
    const option = document.createElement("option");
    option.value = String(value);
    option.textContent = formatDuration(value);
    option.selected = value === initialWindowMs;
    elements.windowSelect.append(option);
  }
}

function configureCallbackRangeSelector() {
  const presets = [10_000, 30_000, 60_000, 300_000]
    .filter((value) => value <= maxWindowMs);
  if (initialWindowMs <= maxWindowMs && !presets.includes(initialWindowMs)) {
    presets.push(initialWindowMs);
    presets.sort((left, right) => left - right);
  }
  for (const value of presets) {
    const option = document.createElement("option");
    option.value = String(value);
    option.textContent = formatDuration(value);
    option.selected = value === initialWindowMs;
    elements.callbackRangeSelect.append(option);
  }
  const lifetime = document.createElement("option");
  lifetime.value = "lifetime";
  lifetime.textContent = "Policy lifetime";
  elements.callbackRangeSelect.append(lifetime);
}

function configureCallbackSampleRateSelector() {
  for (const optionModel of callbackSampleRateOptions()) {
    const option = document.createElement("option");
    option.value = String(optionModel.value);
    option.textContent = optionModel.label;
    elements.callbackSampleRateControl.append(option);
  }
}

function configureSchedulerSampleRateSelector() {
  for (const optionModel of callbackSampleRateOptions()) {
    const option = document.createElement("option");
    option.value = String(optionModel.value);
    option.textContent = optionModel.label;
    if (optionModel.value === 64) {
      option.selected = true;
    }
    elements.schedulerSampleRate.append(option);
  }
}

function bindControls() {
  elements.windowSelect.addEventListener("change", () => {
    state.windowMs = Number(elements.windowSelect.value);
    connectEvents();
  });
  elements.callbackRangeSelect.addEventListener("change", () => {
    state.callbackRange = elements.callbackRangeSelect.value;
    loadCallbackTiming();
  });
  elements.applyCallbackSampleRate.addEventListener("click", setCallbackSampleRate);
  elements.callbackSampleRateControl.addEventListener("change", () => {
    state.callbackRateDirty = true;
  });
  elements.fineTimingPanels.addEventListener("change", (event) => {
    const control = event.target.closest("[data-fine-timing-callback]");
    if (control) {
      setFineTiming(control.dataset.fineTimingCallback, control.checked);
    }
  });
  document.querySelectorAll('input[name="cpuOrder"]').forEach((control) => {
    control.addEventListener("change", () => {
      state.orderMode = control.value;
      renderHeatmap();
    });
  });
  document.querySelectorAll('input[name="colorScale"]').forEach((control) => {
    control.addEventListener("change", () => {
      state.scale = control.value;
      renderHeatmap();
    });
  });
  elements.zoom.addEventListener("input", () => {
    state.zoom = Number(elements.zoom.value);
    renderHeatmap();
  });
  elements.scopeMode.addEventListener("change", renderScopeFields);
  elements.applyScope.addEventListener("click", applyScope);
  elements.canvas.addEventListener("pointermove", showTooltip);
  elements.canvas.addEventListener("pointerleave", hideTooltip);
  elements.canvas.addEventListener("click", pinMigrationPair);
  elements.migrationPairInspection.addEventListener("click", (event) => {
    if (event.target.closest("[data-clear-migration-pair]")) {
      state.pinnedMigrationPair = null;
      renderHeatmap();
    }
  });
  window.addEventListener("hashchange", renderRoute);
  elements.cellList.addEventListener("click", (event) => {
    const control = event.target.closest("[data-cell-id]");
    if (!control) {
      return;
    }
    state.selectedCellId = Number(control.dataset.cellId);
    renderCells();
  });
  elements.cellList.addEventListener("pointermove", showCellBarTooltip);
  elements.cellList.addEventListener("pointerleave", hideCellBarTooltip);
  elements.cellOrderMode.addEventListener("change", (event) => {
    if (event.target.name !== "cellCpuOrder") {
      return;
    }
    state.cellOrderMode = event.target.value;
    renderCells();
  });
  elements.workloadTargetKind.addEventListener("change", renderWorkloadTargetField);
  elements.assignWorkloadCell.addEventListener("click", () => setWorkloadCell(false));
  elements.clearWorkloadCell.addEventListener("click", () => setWorkloadCell(true));
  for (const control of [
    elements.schedulerPolicy,
    elements.schedulerFairnessEnabled,
    elements.schedulerFairness,
    elements.schedulerSampleRateEnabled,
    elements.schedulerSampleRate,
    elements.schedulerExitDumpEnabled,
    elements.schedulerExitDumpLen,
    elements.schedulerVerbose,
  ]) {
    control.addEventListener("change", () => {
      if (
        control === elements.schedulerPolicy
        || control === elements.schedulerFairnessEnabled
        || control === elements.schedulerFairness
      ) {
        state.selectedLifecyclePolicyId = null;
        state.selectedLifecycleFairness = null;
      }
      state.schedulerFormInitialized = true;
      renderSchedulerControl();
    });
  }
  elements.schedulerExitDumpLen.addEventListener("input", renderSchedulerCommandPreview);
  elements.startScheduler.addEventListener("click", startScheduler);
  elements.restartScheduler.addEventListener("click", restartScheduler);
  elements.stopScheduler.addEventListener("click", stopScheduler);
  elements.resetAllStats.addEventListener("click", resetAllStats);
  elements.copyFeedback.addEventListener("click", copyFeedback);
  elements.clearFeedback.addEventListener("click", clearFeedback);
  document.addEventListener("click", (event) => {
    const toggle = event.target.closest("[data-feedback-toggle]");
    if (toggle) {
      toggleFeedbackComposer(toggle.dataset.feedbackToggle);
    }
  });
  document.addEventListener("input", (event) => {
    const input = event.target.closest("[data-feedback-input]");
    if (input) {
      updateFeedback(input.dataset.feedbackInput, input.value);
    }
  });
  elements.cellDetail.addEventListener("click", (event) => {
    const select = event.target.closest("[data-workload-tid]");
    if (select) {
      document.querySelector('input[name="workloadTargetKind"][value="tid"]').checked = true;
      elements.workloadTargetValue.value = select.dataset.workloadTid;
      renderWorkloadTargetField();
      elements.workloadTargetValue.focus();
      return;
    }
    const clear = event.target.closest("[data-clear-workload-tid]");
    if (clear) {
      setWorkloadCell(true, clear.dataset.clearWorkloadTid);
    }
  });
  elements.policyChoices.addEventListener("click", (event) => {
    const fairnessControl = event.target.closest("[data-policy-fairness]");
    if (fairnessControl && !fairnessControl.dataset.policyId) {
      state.selectedPolicyFairness = fairnessControl.dataset.policyFairness;
      renderPolicyLibrary();
      return;
    }
    const control = event.target.closest("[data-policy-id]");
    if (!control || control.disabled) {
      return;
    }
    state.policyCandidate = {
      policyId: control.dataset.policyId,
      fairness: control.dataset.policyFairness,
      actionKind: control.dataset.policyAction,
    };
    renderPolicyLibrary();
    runPolicyCandidate();
  });
  elements.policyCandidateAction.addEventListener("click", runPolicyCandidate);
  elements.confirmPolicyActivation.addEventListener("click", activateSelectedPolicy);
  elements.policyDialog.addEventListener("close", () => {
    state.selectedPolicy = null;
    hideElementNotice(elements.policyActivationNotice);
  });
  document.addEventListener("pointerover", (event) => {
    const control = event.target.closest("[data-reference-id]");
    if (control) {
      showReferencePopover(control);
    }
  });
  document.addEventListener("focusin", (event) => {
    const control = event.target.closest("[data-reference-id]");
    if (control) {
      showReferencePopover(control);
    }
  });
  document.addEventListener("click", (event) => {
    const control = event.target.closest("[data-reference-id]");
    if (control) {
      state.popoverPinned = true;
      showReferencePopover(control);
    } else if (!event.target.closest("#referencePopover")) {
      hideReferencePopover(true);
    }
  });
  document.addEventListener("pointerout", (event) => {
    if (
      event.target.closest("[data-reference-id]") &&
      !state.popoverPinned &&
      !event.relatedTarget?.closest?.("#referencePopover")
    ) {
      hideReferencePopover(false);
    }
  });
  new ResizeObserver(() => renderHeatmap()).observe(elements.viewport);
}

function loadFeedbackEntries() {
  try {
    return parseFeedbackEntries(sessionStorage.getItem(FEEDBACK_STORAGE_KEY));
  } catch {
    return [];
  }
}

function persistFeedbackEntries() {
  try {
    if (state.feedbackEntries.length === 0) {
      sessionStorage.removeItem(FEEDBACK_STORAGE_KEY);
    } else {
      sessionStorage.setItem(FEEDBACK_STORAGE_KEY, JSON.stringify(state.feedbackEntries));
    }
    return true;
  } catch {
    showElementNotice(elements.feedbackNotice, "Feedback could not be saved for this tab.");
    return false;
  }
}

function feedbackEntry(key) {
  return state.feedbackEntries.find((entry) => entry.key === key) || null;
}

function updateFeedback(key, text) {
  state.feedbackEntries = updateFeedbackEntries(state.feedbackEntries, key, text);
  hideElementNotice(elements.feedbackNotice);
  persistFeedbackEntries();
  renderFeedback();
}

function renderFeedback() {
  const transcript = formatFeedbackTranscript(state.feedbackEntries);
  elements.feedbackTranscript.value = transcript;
  elements.copyFeedback.disabled = !transcript;
  elements.clearFeedback.disabled = !transcript && state.expandedFeedbackKeys.size === 0;
  decorateFeedbackTargets(document);
}

function toggleFeedbackComposer(key) {
  if (!key) {
    return;
  }
  const opening = !state.expandedFeedbackKeys.has(key);
  if (opening) {
    state.expandedFeedbackKeys.add(key);
  } else {
    state.expandedFeedbackKeys.delete(key);
  }
  renderFeedback();
  if (opening) {
    window.requestAnimationFrame(() => {
      const input = [...document.querySelectorAll("[data-feedback-input]")]
        .find((candidate) => candidate.dataset.feedbackInput === key);
      if (input) {
        input.focus();
        input.setSelectionRange(input.value.length, input.value.length);
      }
    });
  }
}

function decorateFeedbackTargets(root) {
  const targets = [];
  if (root?.matches?.("[data-feedback-key]")) {
    targets.push(root);
  }
  targets.push(...(root?.querySelectorAll?.("[data-feedback-key]") || []));
  for (const target of targets) {
    decorateFeedbackTarget(target);
  }
}

function decorateFeedbackTarget(target) {
  const key = target.dataset.feedbackKey;
  if (!key) {
    return;
  }
  target.classList.add("feedback-target");
  const heading = [...target.children].find((child) => child.matches("[data-feedback-anchor]"))
    || [...target.children].find((child) => child.matches(
      "header, .matrix-heading, .fine-timing-panel-heading, .cell-detail-heading",
    ));
  let button = [...target.querySelectorAll("[data-feedback-toggle]")]
    .find((candidate) => candidate.dataset.feedbackToggle === key);
  if (!button) {
    button = document.createElement("button");
    button.type = "button";
    button.className = "feedback-button";
    button.dataset.feedbackToggle = key;
    button.innerHTML = `
      <svg data-lucide="ear" viewBox="0 0 24 24" fill="none" stroke="currentColor"
        stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path d="M6 8.5a6.5 6.5 0 1 1 13 0c0 6-6 6-6 10a3.5 3.5 0 1 1-7 0"></path>
        <path d="M15 8.5a2.5 2.5 0 0 0-5 0v1a2 2 0 1 1 0 4"></path>
      </svg>`;
    button.title = "Leave feedback";
    button.setAttribute("aria-label", "Leave feedback");
    if (heading) {
      heading.classList.add("feedback-heading");
      heading.append(button);
    } else {
      button.classList.add("floating");
      target.prepend(button);
    }
  }

  const composerId = feedbackComposerId(key);
  const expanded = state.expandedFeedbackKeys.has(key);
  const entry = feedbackEntry(key);
  button.classList.toggle("has-feedback", Boolean(entry));
  button.setAttribute("aria-expanded", String(expanded));
  button.setAttribute("aria-controls", composerId);

  let composer = [...target.querySelectorAll(".feedback-composer")]
    .find((candidate) => candidate.dataset.feedbackComposer === key);
  if (!expanded) {
    composer?.remove();
    return;
  }
  if (!composer) {
    composer = document.createElement("div");
    composer.className = "feedback-composer";
    composer.id = composerId;
    composer.dataset.feedbackComposer = key;
    const input = document.createElement("textarea");
    input.rows = 3;
    input.placeholder = "Feedback";
    input.value = entry?.text || "";
    input.dataset.feedbackInput = key;
    input.dataset.renderKey = `feedback:${key}:textarea`;
    input.setAttribute("aria-label", "UI feedback");
    composer.append(input);
    if (heading) {
      heading.after(composer);
    } else {
      button.after(composer);
    }
  }
}

function feedbackComposerId(key) {
  return `feedback-composer-${key.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
}

async function copyFeedback() {
  const transcript = elements.feedbackTranscript.value;
  if (!transcript) {
    return;
  }
  let copied = false;
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(transcript);
      copied = true;
    }
  } catch {
    copied = false;
  }
  if (!copied) {
    elements.feedbackTranscript.focus();
    elements.feedbackTranscript.select();
    try {
      copied = document.execCommand("copy");
    } catch {
      copied = false;
    }
  }
  if (copied) {
    showElementNotice(elements.feedbackNotice, "Feedback copied.", "success");
  } else {
    elements.feedbackTranscript.focus();
    elements.feedbackTranscript.select();
    showElementNotice(elements.feedbackNotice, "Copy failed. The feedback text is selected.");
  }
}

function clearFeedback() {
  if (!window.confirm("Clear all collected feedback?")) {
    return;
  }
  state.feedbackEntries = [];
  state.expandedFeedbackKeys.clear();
  persistFeedbackEntries();
  renderFeedback();
  showElementNotice(elements.feedbackNotice, "Feedback cleared.", "success");
}

function renderScopeFields() {
  const mode = elements.scopeMode.value;
  elements.tgidField.classList.toggle("hidden", mode !== "tgids");
  elements.cgroupField.classList.toggle("hidden", mode !== "cgroup");
}

async function applyScope() {
  hideNotice();
  let payload;
  try {
    if (elements.scopeMode.value === "tgids") {
      payload = { kind: "tgids", tgids: parseTgids(elements.tgidInput.value) };
    } else if (elements.scopeMode.value === "cgroup") {
      const path = elements.cgroupInput.value.trim();
      if (!path) {
        throw new Error("Enter a cgroup path");
      }
      payload = { kind: "cgroup", path };
    } else {
      payload = { kind: "all" };
    }
  } catch (error) {
    showNotice(error.message);
    return;
  }

  elements.applyScope.disabled = true;
  try {
    const response = await fetch("/api/scope", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-snake-token": token,
      },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.error || `Scope change failed (${response.status})`);
    }
  } catch (error) {
    showNotice(error.message);
  } finally {
    elements.applyScope.disabled = false;
  }
}

function connectEvents() {
  state.eventSource?.close();
  setStatus("waiting", "Connecting");
  const source = new EventSource(`/api/events?window_ms=${state.windowMs}`);
  state.eventSource = source;
  source.addEventListener("snapshot", (event) => {
    state.snapshot = JSON.parse(event.data);
    state.snapshotError = null;
    state.lastSnapshotAt = Date.now();
    renderSnapshot();
  });
  source.addEventListener("error", (event) => {
    if (event.data) {
      const error = JSON.parse(event.data);
      state.snapshotError = error.error || "Stream error";
      showNotice(error.error || "Stream error");
      renderRuntimeContext();
      return;
    }
    if (source.readyState !== EventSource.OPEN) {
      state.snapshotError = "Activity stream is reconnecting.";
      renderRuntimeContext();
    }
  });
}

function renderSnapshot() {
  const snapshot = state.snapshot;
  elements.totalMigrations.textContent = numberFormat.format(snapshot.total);
  elements.migrationRate.textContent = `${formatRate(snapshot.rate_per_second)}/s`;
  elements.activePairs.textContent = numberFormat.format(snapshot.active_pairs);
  elements.windowCoverage.textContent = `${formatDuration(snapshot.observed_ms)} / ${formatDuration(snapshot.window_ms)}`;
  elements.scopeSummary.textContent = formatScope(snapshot.scope);

  const notices = [];
  if (snapshot.collector_error) {
    notices.push(snapshot.collector_error);
  } else {
    if (snapshot.pair_map_failures || snapshot.task_storage_failures) {
      notices.push(
        `${numberFormat.format(snapshot.pair_map_failures)} pair-map failures | ${numberFormat.format(snapshot.task_storage_failures)} task-state failures`,
      );
    }
  }
  if (snapshot.cpu_usage_error) {
    notices.push(snapshot.cpu_usage_error);
  }
  if (notices.length > 0) {
    showNotice(notices.join(" | "));
  } else {
    hideNotice();
  }
  renderRuntimeContext();
  renderHeatmap();
}

function renderHeatmap() {
  if (!state.topology) {
    return;
  }
  const cells = state.snapshot?.cells || [];
  const matrix = buildMatrix(state.topology, cells, state.orderMode);
  const usage = buildCpuUsage(
    state.topology,
    state.snapshot?.cpu_usage || [],
    state.orderMode,
  );
  const cpuCount = matrix.order.length;
  const viewportWidth = Math.max(320, elements.viewport.clientWidth || 800);
  const {
    cellSize,
    height,
    margins,
    matrixSize,
    usageHeight,
    usageTop,
    width,
  } = heatmapLayout(cpuCount, viewportWidth, state.zoom);
  const pixelRatio = Math.min(2, window.devicePixelRatio || 1);

  elements.legendLow.textContent = numberFormat.format(matrix.minPositive);
  elements.legendHigh.textContent = numberFormat.format(matrix.max);
  elements.legendLow.parentElement.setAttribute(
    "aria-label",
    `${state.scale === "log" ? "Logarithmic" : "Linear"} heat intensity from ${numberFormat.format(matrix.minPositive)} to ${numberFormat.format(matrix.max)} migrations`,
  );
  renderMigrationPairInspection(matrix);

  elements.canvas.style.width = `${width}px`;
  elements.canvas.style.height = `${height}px`;
  elements.canvas.width = Math.ceil(width * pixelRatio);
  elements.canvas.height = Math.ceil(height * pixelRatio);
  const context = elements.canvas.getContext("2d");
  context.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
  context.fillStyle = "#ffffff";
  context.fillRect(0, 0, width, height);
  context.fillStyle = "#11161c";
  context.fillRect(margins.left, margins.top, matrixSize, matrixSize);

  for (let row = 0; row < cpuCount; row += 1) {
    for (let column = 0; column < cpuCount; column += 1) {
      const count = matrix.values[row * cpuCount + column];
      if (count === 0) {
        continue;
      }
      context.fillStyle = infernoColor(normalizeCount(count, matrix.max, state.scale));
      context.fillRect(
        margins.left + column * cellSize,
        margins.top + row * cellSize,
        Math.ceil(cellSize),
        Math.ceil(cellSize),
      );
    }
  }

  drawBoundaries(context, matrix, margins, matrixSize, cellSize);
  drawPinnedMigrationPair(context, matrix, margins, cellSize);
  drawAxes(context, matrix.order, margins, matrixSize, cellSize);
  drawCpuUsage(context, usage, margins, matrixSize, cellSize, usageTop, usageHeight);
  state.geometry = {
    cellSize,
    margins,
    matrix,
    matrixSize,
    usage,
    usageHeight,
    usageTop,
  };
  elements.canvas.setAttribute(
    "aria-label",
    `CPU migration heatmap with ${numberFormat.format(matrix.total)} transitions and all-Snake utilization across ${cpuCount} CPUs`,
  );
}

function renderMigrationPairInspection(matrix) {
  const top = topMigrationPair(matrix);
  const topMarkup = top
    ? migrationPairMarkup("Busiest route", top.from, top.to, top.count, matrix.total)
    : '<div><span>Busiest route</span><strong>No migrations in this window</strong></div>';
  const pinned = state.pinnedMigrationPair;
  let pinnedMarkup = `
    <div class="migration-pair-empty">
      <span>Selected route</span>
      <strong>Click a matrix cell to keep its details here</strong>
    </div>`;
  if (pinned) {
    const row = matrix.positions.get(pinned.from);
    const column = matrix.positions.get(pinned.to);
    const count = row == null || column == null
      ? 0
      : matrix.values[row * matrix.order.length + column];
    pinnedMarkup = migrationPairMarkup(
      "Selected route",
      pinned.from,
      pinned.to,
      count,
      matrix.total,
    );
  }
  replaceKeyedHtml(elements.migrationPairInspection, `
    ${topMarkup}
    ${pinnedMarkup}
    <button class="secondary-button" type="button" data-clear-migration-pair
      data-render-key="activity:migration-pair:clear" ${pinned ? "" : "disabled"}>Clear selection</button>`);
}

function migrationPairMarkup(title, from, to, count, total) {
  const locality = migrationLocality(state.topology, from, to);
  const share = total > 0 ? count * 100 / total : 0;
  return `
    <div>
      <span>${escapeHtml(title)}</span>
      <strong>CPU ${formatCount(from)} → CPU ${formatCount(to)}</strong>
      <small>${formatCount(count)} migrations · ${formatPercentage(share)} · ${escapeHtml(locality.label)}</small>
    </div>`;
}

function topMigrationPair(matrix) {
  if (matrix.max <= 0) {
    return null;
  }
  const size = matrix.order.length;
  let offset = 0;
  for (let index = 1; index < matrix.values.length; index += 1) {
    if (matrix.values[index] > matrix.values[offset]) {
      offset = index;
    }
  }
  return {
    from: matrix.order[Math.floor(offset / size)],
    to: matrix.order[offset % size],
    count: matrix.values[offset],
  };
}

function drawPinnedMigrationPair(context, matrix, margins, cellSize) {
  const pinned = state.pinnedMigrationPair;
  if (!pinned) {
    return;
  }
  const row = matrix.positions.get(pinned.from);
  const column = matrix.positions.get(pinned.to);
  if (row == null || column == null) {
    return;
  }
  context.strokeStyle = "#00d6a3";
  context.lineWidth = Math.max(2, Math.min(4, cellSize / 2));
  context.strokeRect(
    margins.left + column * cellSize + 1,
    margins.top + row * cellSize + 1,
    Math.max(1, cellSize - 2),
    Math.max(1, cellSize - 2),
  );
}

function drawCpuUsage(context, usage, margins, matrixSize, cellSize, top, height) {
  context.fillStyle = "#11161c";
  context.fillRect(margins.left, top, matrixSize, height);
  for (let index = 0; index < usage.order.length; index += 1) {
    const utilization = usage.utilizationPct[index];
    if (utilization <= 0) {
      continue;
    }
    context.fillStyle = infernoColor(normalizeUtilization(utilization, state.scale));
    context.fillRect(
      margins.left + index * cellSize,
      top,
      Math.ceil(cellSize),
      height,
    );
  }

  context.fillStyle = "#25313b";
  context.font = "600 10px ui-sans-serif, system-ui, sans-serif";
  context.textAlign = "right";
  context.textBaseline = "middle";
  context.fillText("All Snake", margins.left - 7, top + height / 2);

  const boundaries = topologyBoundaries(state.topology, usage.order);
  for (const boundary of boundaries) {
    const x = margins.left + boundary.index * cellSize;
    context.beginPath();
    context.lineWidth = boundary.level === "llc" ? 2 : 1;
    context.strokeStyle = boundary.level === "llc" ? "#ffffff" : "#6f7f8b";
    context.moveTo(x, top);
    context.lineTo(x, top + height);
    context.stroke();
  }
}

function drawBoundaries(context, matrix, margins, matrixSize, cellSize) {
  const widths = { node: 3, package: 2.5, llc: 2, core: 1 };
  const colors = { node: "#ffffff", package: "#d7dee4", llc: "#98a8b5", core: "#536471" };
  for (const boundary of topologyBoundaries(state.topology, matrix.order)) {
    const offset = boundary.index * cellSize;
    context.beginPath();
    context.lineWidth = widths[boundary.level];
    context.strokeStyle = colors[boundary.level];
    context.moveTo(margins.left + offset, margins.top);
    context.lineTo(margins.left + offset, margins.top + matrixSize);
    context.moveTo(margins.left, margins.top + offset);
    context.lineTo(margins.left + matrixSize, margins.top + offset);
    context.stroke();
  }
}

function drawAxes(context, order, margins, matrixSize, cellSize) {
  context.fillStyle = "#43515d";
  context.font = "10px ui-monospace, SFMono-Regular, Menlo, monospace";
  context.textBaseline = "middle";
  for (const index of axisLabelIndices(order.length)) {
    const center = (index + 0.5) * cellSize;
    context.textAlign = "right";
    context.fillText(String(order[index]), margins.left - 7, margins.top + center);
    context.save();
    context.translate(margins.left + center, margins.top + matrixSize + 7);
    context.rotate(-Math.PI / 2);
    context.textAlign = "right";
    context.fillText(String(order[index]), 0, 0);
    context.restore();
  }

  context.fillStyle = "#25313b";
  context.font = "600 11px ui-sans-serif, system-ui, sans-serif";
  context.textAlign = "center";
  context.fillText("Destination CPU", margins.left + matrixSize / 2, margins.top + matrixSize + 40);
  context.save();
  context.translate(13, margins.top + matrixSize / 2);
  context.rotate(-Math.PI / 2);
  context.fillText("Source CPU", 0, 0);
  context.restore();
}

function showTooltip(event) {
  const geometry = state.geometry;
  if (!geometry) {
    return;
  }
  const bounds = elements.canvas.getBoundingClientRect();
  const canvasX = event.clientX - bounds.left;
  const canvasY = event.clientY - bounds.top;
  const x = canvasX - geometry.margins.left;
  const y = canvasY - geometry.margins.top;
  const column = Math.floor(x / geometry.cellSize);
  const row = Math.floor(y / geometry.cellSize);
  const size = geometry.matrix.order.length;
  if (
    column >= 0 && column < size &&
    canvasY >= geometry.usageTop &&
    canvasY < geometry.usageTop + geometry.usageHeight
  ) {
    const cpu = geometry.usage.order[column];
    const runtimeNs = geometry.usage.runtimeNs[column];
    const utilization = geometry.usage.utilizationPct[column];
    const cpuInfo = new Map(state.topology.cpus.map((entry) => [entry.cpu, entry]));
    elements.tooltip.textContent = [
      `CPU ${cpu}`,
      `All Snake utilization: ${utilization.toFixed(1)}%`,
      `${formatRuntime(runtimeNs)} runtime over ${formatDuration(state.snapshot?.cpu_usage_observed_ms || 0)}`,
      topologyLine("Topology", cpuInfo.get(cpu)),
    ].join("\n");
    positionTooltip(event);
    return;
  }
  if (row < 0 || column < 0 || row >= size || column >= size) {
    hideTooltip();
    return;
  }

  const from = geometry.matrix.order[row];
  const to = geometry.matrix.order[column];
  const count = geometry.matrix.values[row * size + column];
  const cpuInfo = new Map(state.topology.cpus.map((cpu) => [cpu.cpu, cpu]));
  elements.tooltip.textContent = [
    `CPU ${from} -> CPU ${to}`,
    `${numberFormat.format(count)} migrations`,
    topologyLine("Source", cpuInfo.get(from)),
    topologyLine("Destination", cpuInfo.get(to)),
  ].join("\n");

  positionTooltip(event);
}

function pinMigrationPair(event) {
  const geometry = state.geometry;
  if (!geometry) {
    return;
  }
  const bounds = elements.canvas.getBoundingClientRect();
  const column = Math.floor(
    (event.clientX - bounds.left - geometry.margins.left) / geometry.cellSize,
  );
  const row = Math.floor(
    (event.clientY - bounds.top - geometry.margins.top) / geometry.cellSize,
  );
  const size = geometry.matrix.order.length;
  if (row < 0 || column < 0 || row >= size || column >= size) {
    return;
  }
  state.pinnedMigrationPair = {
    from: geometry.matrix.order[row],
    to: geometry.matrix.order[column],
  };
  renderHeatmap();
}

function positionTooltip(event) {
  const viewportBounds = elements.viewport.getBoundingClientRect();
  const left = event.clientX - viewportBounds.left + elements.viewport.scrollLeft + 14;
  const top = event.clientY - viewportBounds.top + elements.viewport.scrollTop + 14;
  elements.tooltip.style.left = `${Math.max(8, left)}px`;
  elements.tooltip.style.top = `${Math.max(8, top)}px`;
  elements.tooltip.classList.remove("hidden");
}

function hideTooltip() {
  elements.tooltip.classList.add("hidden");
}

function renderRoute() {
  state.route = routeFromHash(window.location.hash);
  hideCellBarTooltip();
  for (const view of [
    elements.activityView,
    elements.callbacksView,
    elements.policyView,
    elements.cellsView,
    elements.schedulerControlView,
    elements.feedbackView,
  ]) {
    view.classList.toggle("hidden", view.dataset.view !== state.route);
  }
  elements.primaryNav.querySelectorAll("[data-route]").forEach((link) => {
    if (link.dataset.route === state.route) {
      link.setAttribute("aria-current", "page");
    } else {
      link.removeAttribute("aria-current");
    }
  });
  hideReferencePopover(true);
  if (state.route === "activity") {
    window.requestAnimationFrame(renderHeatmap);
  } else if (state.route === "control") {
    renderSchedulerControl();
  } else if (state.route === "feedback") {
    renderFeedback();
  } else {
    renderInspectionViews();
  }
}

async function loadCallbackTiming() {
  if (state.callbackTimingLoading) {
    return;
  }
  state.callbackTimingLoading = true;
  const query = state.callbackRange === "lifetime"
    ? "scope=lifetime"
    : `scope=window&window_ms=${Number(state.callbackRange)}`;
  try {
    const response = await fetch(`/api/callback-timing?${query}`, { cache: "no-store" });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.error || `Callback timing request failed (${response.status})`);
    }
    state.callbackTiming = await response.json();
    state.callbackTimingError = null;
    state.lastCallbackTimingAt = Date.now();
  } catch (error) {
    state.callbackTimingError = error.message;
  } finally {
    state.callbackTimingLoading = false;
  }
  renderRuntimeContext();
  if (state.route === "callbacks") {
    renderCallbackTiming();
  }
}

async function loadFineTiming() {
  if (state.fineTimingLoading) {
    return;
  }
  state.fineTimingLoading = true;
  try {
    const response = await fetch("/api/fine-timing", { cache: "no-store" });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.error || `Fine timing request failed (${response.status})`);
    }
    state.fineTiming = await response.json();
    state.fineTimingError = null;
    state.lastFineTimingAt = Date.now();
  } catch (error) {
    state.fineTimingError = error.message;
  } finally {
    state.fineTimingLoading = false;
  }
  renderRuntimeContext();
  if (state.route === "callbacks") {
    renderFineTiming();
  }
}

async function setFineTiming(callback, enabled) {
  if (state.fineTimingPending.has(callback)) {
    return;
  }
  const model = fineTimingCaptureModels(state.fineTiming)
    .find((capture) => capture.callback === callback);
  if (!model?.available) {
    renderFineTiming();
    return;
  }
  state.fineTimingPending.add(callback);
  state.fineTimingError = null;
  renderFineTiming();
  try {
    const response = await fetch("/api/fine-timing", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-snake-token": token,
      },
      body: JSON.stringify({ callback, enabled }),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.error || `Fine timing update failed (${response.status})`);
    }
    const capture = state.fineTiming?.captures?.find((item) => item.callback === callback);
    if (capture) {
      capture.state = enabled ? "collecting" : "historical";
      capture.session_id = payload.session_id;
    }
  } catch (error) {
    state.fineTimingError = error.message;
  } finally {
    state.fineTimingPending.delete(callback);
    renderFineTiming();
  }
}

async function setCallbackSampleRate() {
  if (state.callbackRatePending) {
    return;
  }
  const sampleRate = Number(elements.callbackSampleRateControl.value);
  state.callbackRatePending = true;
  elements.applyCallbackSampleRate.disabled = true;
  showElementNotice(elements.callbackRateNotice, "Updating callback sampling…", "info");
  try {
    const response = await fetch("/api/callback-timing", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-snake-token": token,
      },
      body: JSON.stringify({ sample_rate: sampleRate }),
    });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || `Sampling update failed (${response.status})`);
    }
    state.callbackRateDirty = false;
    const suffix = payload.fine_timing_stopped
      ? " Active fine-grained captures were preserved as Historical."
      : "";
    showElementNotice(
      elements.callbackRateNotice,
      `Callback sampling updated to ${sampleRate === 0 ? "Disabled" : `1 / ${numberFormat.format(sampleRate)}`}.${suffix}`,
      "success",
    );
    await Promise.all([loadCallbackTiming(), loadFineTiming(), loadInspection()]);
  } catch (error) {
    showElementNotice(elements.callbackRateNotice, error.message);
  } finally {
    state.callbackRatePending = false;
    elements.applyCallbackSampleRate.disabled = false;
  }
}

async function loadInspection() {
  if (state.inspectionLoading) {
    return;
  }
  state.inspectionLoading = true;
  try {
    const response = await fetch("/api/inspection", { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`Inspection request failed (${response.status})`);
    }
    const payload = await response.json();
    state.inspection = payload.snapshot;
    state.inspectionContext = payload.context || null;
    state.inspectionError = payload.error;
    state.inspectionSequence = payload.sequence;
    state.lastInspectionAt = Date.now();
  } catch (error) {
    state.inspectionError = error.message;
  } finally {
    state.inspectionLoading = false;
  }
  renderRuntimeContext();
  renderInspectionViews();
}

async function loadPolicyCatalog() {
  if (state.policyCatalogLoading) {
    return;
  }
  state.policyCatalogLoading = true;
  try {
    const response = await fetch("/api/policies", { cache: "no-store" });
    if (!response.ok) {
      throw new Error(`Policy library request failed (${response.status})`);
    }
    const payload = await response.json();
    state.policyCatalog = payload.catalog;
    state.policyCatalogError = payload.error;
    state.lastPolicyCatalogAt = Date.now();
  } catch (error) {
    state.policyCatalogError = error.message;
  } finally {
    state.policyCatalogLoading = false;
  }
  if (state.route === "policy") {
    renderPolicyLibrary();
  }
}

async function loadSchedulerControl() {
  if (state.schedulerControlLoading) {
    return;
  }
  state.schedulerControlLoading = true;
  try {
    const response = await fetch("/api/scheduler/control", { cache: "no-store" });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.error || `Scheduler control request failed (${response.status})`);
    }
    state.schedulerControl = payload;
    state.schedulerControlError = null;
    state.lastSchedulerControlAt = Date.now();
  } catch (error) {
    state.schedulerControlError = error.message;
  } finally {
    state.schedulerControlLoading = false;
  }
  renderRuntimeContext();
  if (state.route === "control") {
    renderSchedulerControl();
  } else if (state.route === "policy") {
    renderPolicyLibrary();
  }
}

function renderSchedulerControl() {
  const control = state.schedulerControl;
  syncSchedulerPolicyOptions(control?.policies || []);
  if (control && !state.schedulerFormInitialized) {
    hydrateSchedulerLaunchForm(control);
    state.schedulerFormInitialized = true;
  }
  if (
    state.selectedLifecyclePolicyId
    && [...elements.schedulerPolicy.options]
      .some((option) => option.value === state.selectedLifecyclePolicyId && !option.disabled)
  ) {
    elements.schedulerPolicy.value = state.selectedLifecyclePolicyId;
  }
  if (
    state.selectedLifecycleFairness
    && [...elements.schedulerFairness.options]
      .some((option) => option.value === state.selectedLifecycleFairness)
  ) {
    elements.schedulerFairnessEnabled.checked = true;
    elements.schedulerFairness.value = state.selectedLifecycleFairness;
  }
  syncSchedulerFairnessOptions(control);

  const active = Boolean(control?.active);
  const managed = Boolean(control?.managed);
  const model = schedulerControlModel(
    control,
    state.schedulerControlPending,
    Boolean(elements.schedulerPolicy.value),
  );
  const locked = model.configLocked;
  elements.schedulerPolicy.disabled = locked || elements.schedulerPolicy.options.length === 0;
  elements.schedulerFairnessEnabled.disabled = locked;
  elements.schedulerSampleRateEnabled.disabled = locked;
  elements.schedulerExitDumpEnabled.disabled = locked;
  elements.schedulerVerbose.disabled = locked;
  elements.schedulerFairness.disabled = locked || !elements.schedulerFairnessEnabled.checked;
  elements.schedulerSampleRate.disabled = locked || !elements.schedulerSampleRateEnabled.checked;
  elements.schedulerExitDumpLen.disabled = locked || !elements.schedulerExitDumpEnabled.checked;
  elements.startScheduler.disabled = model.startDisabled;
  elements.restartScheduler.disabled = model.restartDisabled;
  elements.stopScheduler.disabled = model.stopDisabled;
  elements.resetAllStats.disabled = statsResetDisabled(control, state.statsResetPending);

  elements.schedulerControlState.className = `scheduler-state ${model.stateName}`;
  elements.schedulerControlState.textContent = model.stateLabel;

  const message = schedulerControlMessage(control, state.schedulerControlError);
  if (message) {
    showElementNotice(elements.schedulerControlNotice, message);
  } else if (state.selectedLifecyclePolicyId) {
    const policy = control?.policies?.find(
      (candidate) => candidate.id === state.selectedLifecyclePolicyId,
    );
    showElementNotice(
      elements.schedulerControlNotice,
      `${policy?.name || state.selectedLifecyclePolicyId} with ${state.selectedLifecycleFairness?.toUpperCase() || "the current fairness mode"} is selected. Review the command, then ${control?.active ? "restart" : "start"} Snake.`,
      "info",
    );
  } else {
    hideElementNotice(elements.schedulerControlNotice);
  }

  elements.schedulerCurrentCommand.textContent = schedulerCurrentCommand(control);
  renderSchedulerCommandPreview();
  renderSchedulerSettings(control);
}

function syncSchedulerPolicyOptions(policies) {
  const signature = policies
    .map((policy) => `${policy.id}:${policy.name}:${policy.change_mode}:${policy.supported_fairness?.join(",") || ""}`)
    .join("|");
  if (elements.schedulerPolicy.dataset.signature === signature) {
    return;
  }
  const selected = elements.schedulerPolicy.value;
  elements.schedulerPolicy.innerHTML = policies.length === 0
    ? '<option value="">No policies available</option>'
    : policies.map((policy) => {
      const mode = policy.change_mode === "dynamic"
        ? "Dynamic"
        : policy.change_mode === "reload"
          ? "Reload required"
          : "Invalid";
      return `<option value="${escapeHtml(policy.id)}" ${policy.change_mode === "invalid" ? "disabled" : ""}>${escapeHtml(policy.name || policy.id)} (${mode})</option>`;
    }).join("");
  if ([...elements.schedulerPolicy.options].some((option) => option.value === selected)) {
    elements.schedulerPolicy.value = selected;
  }
  elements.schedulerPolicy.dataset.signature = signature;
}

function syncSchedulerFairnessOptions(control) {
  const policy = control?.policies?.find(
    (candidate) => candidate.id === elements.schedulerPolicy.value,
  );
  const supported = policy?.supported_fairness?.length
    ? policy.supported_fairness
    : ["fifo", "vtime", "eevdf"];
  for (const option of elements.schedulerFairness.options) {
    option.disabled = !supported.includes(option.value);
  }
  if (!supported.includes(elements.schedulerFairness.value)) {
    elements.schedulerFairness.value = supported[0];
  }
  if (supported.length === 1 && supported[0] !== "fifo") {
    elements.schedulerFairnessEnabled.checked = true;
  }
}

function hydrateSchedulerLaunchForm(control) {
  const launch = control.launch || {};
  const policyId = control.policy_id || launch.policy_id;
  if (
    policyId
    && [...elements.schedulerPolicy.options].some((option) => option.value === policyId)
  ) {
    elements.schedulerPolicy.value = policyId;
  }
  const hasFairness = launch.fairness != null;
  elements.schedulerFairnessEnabled.checked = hasFairness;
  if (hasFairness && ["fifo", "vtime", "eevdf"].includes(launch.fairness)) {
    elements.schedulerFairness.value = launch.fairness;
  }
  const hasSampleRate = launch.callback_timing_sample_rate != null;
  elements.schedulerSampleRateEnabled.checked = hasSampleRate;
  if (hasSampleRate) {
    elements.schedulerSampleRate.value = String(launch.callback_timing_sample_rate);
  }
  const hasExitDump = launch.exit_dump_len != null;
  elements.schedulerExitDumpEnabled.checked = hasExitDump;
  if (hasExitDump) {
    elements.schedulerExitDumpLen.value = String(launch.exit_dump_len);
  }
  elements.schedulerVerbose.checked = Boolean(launch.verbose);
}

function schedulerLaunchFormValues() {
  return {
    policy_id: elements.schedulerPolicy.value,
    fairness_enabled: elements.schedulerFairnessEnabled.checked,
    fairness: elements.schedulerFairness.value,
    callback_timing_sample_rate_enabled: elements.schedulerSampleRateEnabled.checked,
    callback_timing_sample_rate: elements.schedulerSampleRate.value,
    exit_dump_len_enabled: elements.schedulerExitDumpEnabled.checked,
    exit_dump_len: elements.schedulerExitDumpLen.value,
    verbose: elements.schedulerVerbose.checked,
  };
}

function renderSchedulerCommandPreview() {
  try {
    const request = schedulerLaunchRequest(schedulerLaunchFormValues());
    elements.schedulerCommandPreview.textContent = schedulerCommandPreview(
      request,
      state.schedulerControl?.launch?.preserved_args || [],
    );
    const current = {
      policy_id: state.schedulerControl?.policy_id ?? null,
      fairness: state.schedulerControl?.launch?.fairness ?? null,
      callback_timing_sample_rate:
        state.schedulerControl?.launch?.callback_timing_sample_rate ?? null,
      exit_dump_len: state.schedulerControl?.launch?.exit_dump_len ?? null,
      verbose: Boolean(state.schedulerControl?.launch?.verbose),
    };
    const changes = launchDiff(current, request);
    elements.schedulerPendingChanges.innerHTML = changes.length === 0
      ? "No launch changes selected."
      : `<strong>${changes.length} pending launch ${changes.length === 1 ? "change" : "changes"}</strong><ul>${changes.map((change) => `
          <li><span>${escapeHtml(change.name)}</span><code>${escapeHtml(formatLaunchDiffValue(change.before))}</code><span aria-hidden="true">→</span><code>${escapeHtml(formatLaunchDiffValue(change.after))}</code></li>`).join("")}</ul>`;
  } catch (error) {
    elements.schedulerCommandPreview.textContent = error.message;
    elements.schedulerPendingChanges.textContent = "Select a valid launch configuration to compare changes.";
  }
}

function formatLaunchDiffValue(value) {
  if (value == null) {
    return "default";
  }
  if (typeof value === "boolean") {
    return value ? "enabled" : "disabled";
  }
  return String(value);
}

function renderSchedulerSettings(control) {
  const settings = schedulerSettingModels(control?.settings || []);
  elements.schedulerSettingsRows.innerHTML = settings.length === 0
    ? '<tr><td class="scheduler-settings-empty" colspan="4">No scheduler settings reported.</td></tr>'
    : settings.map((setting) => `
      <tr>
        <th scope="row">${escapeHtml(setting.name)}</th>
        <td><code>${escapeHtml(setting.effectiveValue)}</code><small>${setting.runtimeObserved ? "Observed from Snake" : "Derived from launch state"}</small></td>
        <td class="${setting.differs ? "setting-differs" : ""}"><code>${escapeHtml(setting.overrideValue)}</code></td>
        <td><span class="change-mode ${setting.changeMode}">${setting.changeLabel}</span></td>
      </tr>`).join("");
}

async function startScheduler() {
  let request;
  try {
    request = schedulerLaunchRequest(schedulerLaunchFormValues());
  } catch (error) {
    showElementNotice(elements.schedulerControlNotice, error.message);
    return;
  }
  await schedulerMutation("/api/scheduler/start", request);
}

async function restartScheduler() {
  let request;
  try {
    request = schedulerLaunchRequest(schedulerLaunchFormValues());
  } catch (error) {
    showElementNotice(elements.schedulerControlNotice, error.message);
    return;
  }
  if (!window.confirm("Restart the attached Snake scheduler with this configuration?")) {
    return;
  }
  await schedulerMutation("/api/scheduler/restart", request);
}

async function stopScheduler() {
  if (!window.confirm("Stop the attached Snake scheduler?")) {
    return;
  }
  await schedulerMutation("/api/scheduler/stop", {});
}

async function schedulerMutation(path, payload) {
  if (state.schedulerControlPending) {
    return;
  }
  state.schedulerControlPending = true;
  state.schedulerControlError = null;
  renderSchedulerControl();
  try {
    const response = await fetch(path, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-snake-token": token,
      },
      body: JSON.stringify(payload),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(body.error || `Scheduler control failed (${response.status})`);
    }
    state.selectedLifecyclePolicyId = null;
    state.selectedLifecycleFairness = null;
    state.schedulerFormInitialized = false;
    await loadSchedulerControl();
  } catch (error) {
    state.schedulerControlError = error.message;
  } finally {
    state.schedulerControlPending = false;
    renderSchedulerControl();
  }
}

async function resetAllStats() {
  if (state.statsResetPending || !window.confirm("Reset all inspector and Snake statistics?")) {
    return;
  }
  state.statsResetPending = true;
  renderSchedulerControl();
  showElementNotice(elements.statsResetNotice, "Resetting statistics…", "info");
  try {
    const response = await fetch("/api/stats/reset", {
      method: "POST",
      headers: { "x-snake-token": token },
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.error || `Stats reset failed (${response.status})`);
    }
    const captureMessage = payload.fine_timing_stopped
      ? " Fine-grained captures were stopped."
      : "";
    showElementNotice(
      elements.statsResetNotice,
      `Reset generation ${numberFormat.format(payload.generation)}, slot ${numberFormat.format(payload.active_slot)} at ${formatTimestamp(payload.reset_at_ms)}.${captureMessage}`,
      "success",
    );
    await Promise.all([loadInspection(), loadCallbackTiming(), loadFineTiming()]);
  } catch (error) {
    showElementNotice(elements.statsResetNotice, error.message);
  } finally {
    state.statsResetPending = false;
    renderSchedulerControl();
  }
}

function renderInspectionViews() {
  if (state.route === "policy") {
    if (!elements.referencePopover.classList.contains("hidden")) {
      return;
    }
    renderPolicy();
  } else if (state.route === "cells") {
    renderCells();
  } else if (state.route === "callbacks") {
    renderCallbackTiming();
  }
}

function renderCallbackTiming() {
  const timing = state.callbackTiming;
  renderFreshness(
    elements.callbackFreshness,
    Boolean(timing),
    state.callbackTimingError,
    state.lastCallbackTimingAt,
    1_000,
  );
  elements.callbackSampleRate.textContent = timing?.sample_rate > 0
    ? `1 / ${numberFormat.format(timing.sample_rate)}`
    : "Off";
  syncCallbackSampleRateControl(
    elements.callbackSampleRateControl,
    timing?.sample_rate,
    {
      dirty: state.callbackRateDirty,
      pending: state.callbackRatePending,
      activeElement: document.activeElement,
    },
  );
  elements.callbackGeneration.textContent = timing?.generation == null
    ? "—"
    : numberFormat.format(timing.generation);
  elements.callbackRange.textContent = timing?.scope === "lifetime"
    ? "Policy lifetime"
    : timing?.window_ms
      ? formatDuration(timing.window_ms)
      : "—";
  elements.callbackCoverage.textContent = timing?.scope === "lifetime"
    ? "Cumulative"
    : timing?.observed_ms == null
      ? "—"
      : formatDuration(timing.observed_ms);

  const message = state.callbackTimingError
    || timing?.error
    || (timing?.status === "unsupported"
      ? "The active Snake scheduler does not export callback timing data."
      : timing?.status === "disabled"
        ? "Callback timing sampling is disabled."
        : timing?.status === "unavailable"
          ? "Callback timing data is unavailable."
          : timing?.callbacks?.every((row) => Number(row.samples) === 0)
            ? "Waiting for callback timing samples."
            : null);
  if (message) {
    showElementNotice(elements.callbacksNotice, message);
  } else {
    hideElementNotice(elements.callbacksNotice);
  }

  const rows = timing?.callbacks || [];
  elements.callbackTimingRows.innerHTML = rows.length === 0
    ? '<tr><td class="callback-empty" colspan="6">No callback timing rows available.</td></tr>'
    : rows.map((row) => `
      <tr>
        <th scope="row"><code>${escapeHtml(row.callback)}</code></th>
        <td>${formatCount(row.samples)}</td>
        <td class="${callbackDurationClass(row.mean_ns)}">${escapeHtml(formatCallbackDuration(row.mean_ns))}</td>
        <td class="${callbackDurationClass(row.p50_ns)}">${escapeHtml(formatCallbackDuration(row.p50_ns))}</td>
        <td class="${callbackDurationClass(row.p95_ns)}">${escapeHtml(formatCallbackDuration(row.p95_ns))}</td>
        <td class="${callbackDurationClass(row.p99_ns)}">${escapeHtml(formatCallbackDuration(row.p99_ns))}</td>
      </tr>`).join("");
  renderFineTiming();
}

function renderFineTiming() {
  const timing = state.fineTiming;
  const message = state.fineTimingError
    || timing?.error
    || (timing?.status === "unsupported"
      ? "The active Snake scheduler does not support fine-grained timing."
      : timing?.status === "unavailable"
        ? "Fine-grained timing is unavailable."
        : null);
  if (message) {
    showElementNotice(elements.fineTimingNotice, message);
  } else {
    hideElementNotice(elements.fineTimingNotice);
  }

  replaceKeyedHtml(elements.fineTimingPanels, fineTimingCaptureModels(timing)
    .map((capture) => {
      const pending = state.fineTimingPending.has(capture.callback);
      const availabilityId = `fine-${capture.callback}-availability`;
      const availabilityText = capture.available
        ? "Available in current mode"
        : `${capture.availabilityLabel}: ${capture.unavailable_reason || "Not supported in current mode."}`;
      const metadata = capture.session_id == null
        ? "No capture"
        : `Session ${formatCount(capture.session_id)} · policy generation ${formatCount(capture.policy_generation)} · started ${formatTimestamp(capture.started_at_ms)} · ${capture.stopped_at_ms ? `stopped ${formatTimestamp(capture.stopped_at_ms)}` : capture.state === "collecting" ? "collecting now" : "stop time unavailable"}`;
      const stages = capture.stages?.length
        ? capture.stages.map((stage) => `
            <tr>
              <th scope="row"><code>${escapeHtml(stage.stage)}</code></th>
              <td>${formatCount(stage.samples)}</td>
              ${fineTimingDurationCell(stage.mean_ns)}
              ${fineTimingDurationCell(stage.p50_ns)}
              ${fineTimingDurationCell(stage.p95_ns)}
              ${fineTimingDurationCell(stage.p99_ns)}
            </tr>`).join("")
        : '<tr><td class="callback-empty" colspan="6">No captured samples.</td></tr>';
      return `
        <section class="fine-timing-panel" aria-labelledby="fine-${capture.callback}"
          data-feedback-key="Callbacks:Fine-grained-timing:${escapeHtml(capture.label.replaceAll(" ", "-"))}">
          <header class="fine-timing-panel-heading">
            <div>
              <h4 id="fine-${capture.callback}">${escapeHtml(capture.label)}</h4>
              <p>${escapeHtml(metadata)}</p>
            </div>
            <div class="fine-timing-actions">
              <span class="fine-timing-state ${capture.state}">${escapeHtml(capture.stateLabel)}</span>
              <div class="fine-timing-control">
                <label class="fine-timing-toggle" title="${escapeHtml(availabilityText)}">
                  <input type="checkbox" data-fine-timing-callback="${capture.callback}"
                    aria-describedby="${availabilityId}"
                    ${capture.checked ? "checked" : ""}
                    ${capture.controlDisabled || pending ? "disabled" : ""}>
                  <span>Collect Fine-grain Timestamps</span>
                </label>
                <span id="${availabilityId}"
                  class="fine-timing-availability ${capture.available ? "available" : "unavailable"}">
                  ${escapeHtml(availabilityText)}
                </span>
              </div>
            </div>
          </header>
          <div class="fine-timing-table-wrap">
            <table>
              <thead><tr><th>Stage</th><th>Samples</th><th>Mean (ns)</th><th>p50 approx. (ns)</th><th>p95 approx. (ns)</th><th>p99 approx. (ns)</th></tr></thead>
              <tbody>${stages}</tbody>
            </table>
          </div>
        </section>`;
    })
    .join(""));
}

function fineTimingDurationCell(value) {
  return `<td class="${callbackDurationClass(value)}">${escapeHtml(formatCallbackDuration(value))}</td>`;
}

function renderPolicy() {
  renderInspectionStatus(elements.policyNotice, elements.policyFreshness);
  renderPolicyLibrary();
  state.references.clear();
  state.referenceId = 0;
  if (!state.inspection) {
    elements.slotComparison.replaceChildren();
    elements.queueTopology.replaceChildren();
    elements.queueTopology.classList.add("hidden");
    return;
  }
  replaceKeyedHtml(
    elements.slotComparison,
    `${renderPolicySlotComparison(state.inspection.slots)}${state.inspection.slots.map(renderSlot).join("")}`,
  );
  renderResolvedQueueTopology();
}

function renderPolicySlotComparison(slots) {
  const comparison = policySlotComparison(slots);
  if (!comparison.comparable) {
    return `
      <section class="policy-slot-diff unavailable">
        <header><h3>Policy structure comparison</h3><p>A previous installed policy is not available yet.</p></header>
      </section>`;
  }
  const changed = comparison.rows.filter((row) => row.changed).length;
  return `
    <section class="policy-slot-diff">
      <header>
        <div><h3>Policy structure comparison</h3><p>${formatCount(changed)} of ${formatCount(comparison.rows.length)} fields changed</p></div>
        <span>Metrics are excluded because the two slots cover different time periods.</span>
      </header>
      <div class="policy-slot-diff-table-wrap">
        <table>
          <thead><tr><th scope="col">Structure</th><th scope="col">${escapeHtml(comparison.activeLabel)}</th><th scope="col">${escapeHtml(comparison.previousLabel)}</th></tr></thead>
          <tbody>${comparison.rows.map((row) => `
            <tr class="${row.changed ? "changed" : "unchanged"}">
              <th scope="row">${escapeHtml(row.name)}${row.changed ? '<span class="visually-hidden"> changed</span>' : ""}</th>
              <td>${escapeHtml(row.active)}</td>
              <td>${escapeHtml(row.previous)}</td>
            </tr>`).join("")}</tbody>
        </table>
      </div>
    </section>`;
}

function renderResolvedQueueTopology() {
  const model = queueTopologyModel(
    state.inspection.fairness,
    state.inspection.queue_topology,
    state.topology?.numeric_order || [],
  );
  const generation = state.inspection.slots
    .find((slot) => slot.state === "active")
    ?.generation ?? "unknown";
  elements.queueTopology.classList.remove("hidden");
  const summary = `
    <dl class="queue-topology-summary">
      <div><dt>Fairness</dt><dd>${escapeHtml(model.mode)}</dd></div>
      <div><dt>Clock model</dt><dd>${escapeHtml(model.clockModel)}</dd></div>
      <div><dt>Layout</dt><dd>${escapeHtml(model.layout || "None")}</dd></div>
      <div><dt>Affinity DSQs</dt><dd>${formatCount(model.affinityQueueCount)}</dd></div>
      <div><dt>CPU routes</dt><dd>${formatCount(model.cpuRoutes.length)} / ${formatCount(model.expectedCpuCount)}</dd></div>
    </dl>`;
  const routeWarning = model.routesComplete
    ? ""
    : `<p class="notice">Routing data is incomplete: loaded ${formatCount(model.cpuRoutes.length)} of ${formatCount(model.expectedCpuCount)} online CPUs.</p>`;
  if (!model.layout) {
    replaceKeyedHtml(elements.queueTopology, `
      <header class="queue-topology-heading">
        <div><h3>Scheduler execution model</h3><p>Fairness and attachment-time queue topology</p></div>
      </header>
      ${summary}
      <p class="queue-topology-empty">No resolved cell queue topology is installed.</p>`);
    return;
  }
  const cells = model.cells.map((cell) => `
    <tr>
      <th scope="row">${escapeHtml(cell.label)}</th>
      <td>${formatCount(cell.index)}</td>
      <td>${formatCount(cell.cpu_weight)}</td>
      <td><code>cell:${formatCount(cell.clock_index)}</code></td>
      <td class="cpu-mask">${escapeHtml(compactCpuList(cell.primary_cpus))}</td>
      <td class="cpu-mask">${escapeHtml(compactCpuList(cell.borrowable_cpus))}</td>
    </tr>`).join("");
  const queues = model.normalQueues.map((queue) => `
    <tr>
      <th scope="row"><code>${escapeHtml(queue.dsq)}</code></th>
      <td>Cell ${formatCount(queue.cell_id)} <small>index ${formatCount(queue.cell_index)}</small></td>
      <td>${queue.llc_id == null ? "All" : formatCount(queue.llc_id)}</td>
      <td><code>cell:${formatCount(queue.clock_index)}</code></td>
      <td class="cpu-mask">${escapeHtml(compactCpuList(queue.consumer_cpus))}</td>
    </tr>`).join("");
  const routes = model.cpuRoutes.map((route) => `
    <tr>
      <th scope="row">${formatCount(route.cpu)}</th>
      <td>Cell ${formatCount(route.owner_cell_id)} <small>index ${formatCount(route.owner_cell_index)}</small></td>
      <td>${formatCount(route.llc_id)}</td>
      <td><code>${escapeHtml(route.normalDsq)}</code></td>
      <td><code>${escapeHtml(route.affinityDsq)}</code></td>
    </tr>`).join("");
  replaceKeyedHtml(elements.queueTopology, `
    <header class="queue-topology-heading">
      <div><h3>Resolved queue topology</h3><p>Attachment-time CPU ownership, DSQs, and clock domains</p></div>
    </header>
    ${summary}
    ${routeWarning}
    <section class="queue-topology-table-section">
      <h4>Cell allocation</h4>
      <div class="queue-topology-table-wrap" data-render-key="queue:${generation}:cell-allocation:scroll">
        <table><thead><tr><th>Cell</th><th>Dense</th><th>Weight</th><th>Clock</th><th>Primary CPUs</th><th>Borrowable CPUs</th></tr></thead><tbody>${cells}</tbody></table>
      </div>
    </section>
    <details class="queue-topology-details" data-render-key="queue:${generation}:normal-dsqs">
      <summary data-render-key="queue:${generation}:normal-dsqs:summary">Normal DSQs (${formatCount(model.normalQueues.length)})</summary>
      <div class="queue-topology-table-wrap" data-render-key="queue:${generation}:normal-dsqs:scroll">
        <table><thead><tr><th>DSQ</th><th>Cell</th><th>LLC</th><th>Clock</th><th>Consumer CPUs</th></tr></thead><tbody>${queues}</tbody></table>
      </div>
    </details>
    <details class="queue-topology-details" data-render-key="queue:${generation}:cpu-routes">
      <summary data-render-key="queue:${generation}:cpu-routes:summary">Per-CPU routing (${formatCount(model.cpuRoutes.length)} of ${formatCount(model.expectedCpuCount)} online CPUs)</summary>
      <div class="queue-topology-table-wrap queue-route-table-wrap" data-render-key="queue:${generation}:cpu-routes:scroll">
        <table><thead><tr><th>CPU</th><th>Owner</th><th>LLC</th><th>Normal DSQ</th><th>Affinity DSQ</th></tr></thead><tbody>${routes}</tbody></table>
      </div>
    </details>`);
}

function renderSlot(slot) {
  const stateLabel = slot.state === "active"
    ? "Active"
    : slot.state === "inactive"
      ? "Previous"
      : "Empty";
  const roleHeading = slot.state === "active"
    ? "Active policy"
    : slot.state === "inactive"
      ? "Previous policy"
      : `Slot ${slot.slot}`;
  if (!slot.policy) {
    return `
      <section class="slot-panel empty-slot" aria-label="Ladder slot ${slot.slot}, empty"
        data-feedback-key="Policy:Slot-${slot.slot}">
        <header class="slot-heading">
          <h3>${roleHeading}</h3>
          <p>Slot ${slot.slot}</p>
          <span class="slot-state empty">${stateLabel}</span>
        </header>
        <p>No ladder is installed in this slot.</p>
      </section>`;
  }
  const metrics = slot.metrics || {};
  const ladderRates = ladderPercentages(metrics);
  const metricKind = slot.state === "active" ? "Live cumulative metrics" : "Frozen previous-policy metrics";
  const timestamp = slot.state === "active" ? slot.activated_at_ms : slot.deactivated_at_ms;
  const rungs = slot.policy.rungs
    .map((rung, index) => renderRung(
      rung,
      index,
      slot.policy.rungs.length,
      metrics,
      slot.policy.queues,
    ))
    .join("");
  const queueLadders = renderQueuePolicy(slot.policy.queues);
  const maskTables = slot.policy.mask_tables.length > 0
    ? slot.policy.mask_tables.map((table) => `
        <li><code>${escapeHtml(String(table.id))}</code> ${escapeHtml(table.name)}
          <span>${escapeHtml(table.source)} · ${numberFormat.format(table.entry_count)} entries</span>
        </li>`).join("")
    : "<li>None</li>";
  return `
    <section class="slot-panel" aria-label="Ladder slot ${slot.slot}, ${stateLabel}"
      data-feedback-key="Policy:Slot-${slot.slot}">
      <header class="slot-heading">
        <div>
          <h3>${roleHeading}</h3>
          <p>Slot ${slot.slot} · Generation ${numberFormat.format(slot.generation)} · ${metricKind}</p>
        </div>
        <span class="slot-state ${escapeHtml(slot.state)}">${stateLabel}</span>
      </header>
      <dl class="slot-summary">
        <div><dt>Observed</dt><dd>${formatTimestamp(timestamp)}</dd></div>
        <div><dt>Select calls</dt><dd>${formatCount(metrics.select_calls)}</dd></div>
        <div><dt>Direct dispatches</dt><dd>${formatCount(metrics.direct_dispatches)}</dd></div>
        <div><dt>Exhaustions</dt><dd>${formatCount(metrics.ladder_exhaustions)}</dd></div>
      </dl>
      <section class="policy-ladder-section idle-ladder-section">
        <header class="ladder-heading">
          <h4>Idle selection</h4>
          <span>Fixed first-match order</span>
        </header>
        <div class="ladder-rail">${rungs}</div>
        <dl class="ladder-summary">
          <div><dt>Entire ladder</dt><dd>${formatCount(metrics.select_calls)} evaluations<small>${formatCount(metrics.invalid_errors)} errors</small></dd></div>
          <div><dt>Hit</dt><dd>${formatCount(metrics.direct_dispatches)}<small>${formatPercentage(ladderRates.hit)}</small></dd></div>
          <div><dt>Miss</dt><dd>${formatCount(metrics.ladder_exhaustions)}<small>${formatPercentage(ladderRates.miss)}</small></dd></div>
        </dl>
        <div class="fallback-row">
          <span>All rungs missed</span>
          <span aria-hidden="true">→</span>
          ${fieldButton("Fallback", slot.policy.fallback)}
          ${slot.policy.queues ? '<span class="fallback-destination">→ enqueue ladder</span>' : ""}
        </div>
      </section>
      ${queueLadders}
      <details class="policy-details" data-render-key="policy-slot:${slot.slot}:generation:${slot.generation}">
        <summary data-render-key="policy-slot:${slot.slot}:generation:${slot.generation}:summary">Mask tables and source policy</summary>
        <h4>Installed mask tables</h4>
        <ul class="mask-table-list">${maskTables}</ul>
        <h4>Policy source</h4>
        <pre data-render-key="policy-slot:${slot.slot}:generation:${slot.generation}:source-scroll">${escapeHtml(slot.policy.source)}</pre>
      </details>
    </section>`;
}

function renderQueuePolicy(queues) {
  if (!queues) {
    return `
      <section class="queue-policy-empty">
        <strong>Queue callback ladders</strong>
        <span>Not configured for this policy</span>
      </section>`;
  }
  const sections = queueLadderSections(queues).map(renderQueueLadder).join("");
  return `
    <section class="queue-policy-block">
      <header class="queue-policy-heading">
        <div>
          <h4>Queue callback ladders</h4>
          <p>Installed with this policy generation</p>
        </div>
        <span>Layout <code>${escapeHtml(queues.layout)}</code></span>
      </header>
      ${sections}
    </section>`;
}

function renderQueueLadder(section) {
  const rungs = section.rungs.map((rung) => `
    <article class="rung-row queue-rung-row">
      <div class="rung-index" aria-label="${escapeHtml(section.title)} rung ${rung.index}">${rung.index}</div>
      <div class="rung-body">
        <header>
          <div>
            <h4>${escapeHtml(rung.operation)}</h4>
            <p>${escapeHtml(rung.role)}</p>
          </div>
        </header>
        <div class="rung-flow">
          <span class="hit-flow">${escapeHtml(rung.flow.hit)}</span>
          <span>${escapeHtml(rung.flow.miss)}</span>
        </div>
      </div>
    </article>`).join("");
  const cycle = section.cyclic ? '<span aria-hidden="true">↻</span> ' : "";
  return `
    <section class="policy-ladder-section queue-ladder-section">
      <header class="ladder-heading">
        <h4>${escapeHtml(section.title)}</h4>
        <span>${cycle}${escapeHtml(section.behavior)}</span>
      </header>
      <div class="ladder-rail queue-ladder-rail">${rungs}</div>
      <p class="queue-ladder-terminal">${escapeHtml(section.terminal)}</p>
    </section>`;
}

function renderPolicyLibrary() {
  const catalog = state.policyCatalog;
  if (state.policyCatalogError && !state.schedulerControl?.policies?.length) {
    elements.policyLibraryStatus.textContent = "Unavailable";
    showElementNotice(elements.policyLibraryNotice, state.policyCatalogError);
    elements.policyChoices.replaceChildren();
    elements.invalidPolicies.classList.add("hidden");
    return;
  }
  if (!catalog && !state.schedulerControl?.policies?.length) {
    elements.policyLibraryStatus.textContent = "Loading policies";
    hideElementNotice(elements.policyLibraryNotice);
    elements.policyChoices.replaceChildren();
    elements.invalidPolicies.classList.add("hidden");
    return;
  }
  if (state.policyLibraryMessage) {
    showElementNotice(
      elements.policyLibraryNotice,
      state.policyLibraryMessage.text,
      state.policyLibraryMessage.kind,
    );
  } else {
    hideElementNotice(elements.policyLibraryNotice);
  }
  const activeSource = state.inspection?.slots
    ?.find((slot) => slot.state === "active")
    ?.policy?.source?.trim();
  const activeFairness = state.schedulerControl?.context?.fairness
    || state.schedulerControl?.launch?.fairness
    || state.inspection?.fairness?.mode_name
    || "fifo";
  if (!POLICY_FAIRNESS_OPTIONS.some((option) => option.id === state.selectedPolicyFairness)) {
    state.selectedPolicyFairness = activeFairness;
  }
  const selectedFairness = state.selectedPolicyFairness;
  const fairnessModels = POLICY_FAIRNESS_OPTIONS.map((option) => ({
    ...option,
    active: option.id === activeFairness,
    policies: policyLibraryModels(
      catalog,
      state.schedulerControl,
      activeSource,
      option.id,
    ),
  }));
  const selectedModel = fairnessModels.find((option) => option.id === selectedFairness)
    || fairnessModels[0];
  const policies = selectedModel.policies;
  renderPolicyContextBar(fairnessModels, activeFairness);
  const policyCount = new Set(
    fairnessModels.flatMap((option) => option.policies.map((policy) => policy.id)),
  ).size;
  elements.policyLibraryStatus.textContent = `${numberFormat.format(policyCount)} policies`;

  const fairnessOptions = fairnessModels.map((option) => `
    <button class="policy-fairness-option${option.id === selectedFairness ? " selected" : ""}${option.active ? " active" : ""}" type="button"
      role="tab" aria-selected="${option.id === selectedFairness}"
      data-policy-fairness="${escapeHtml(option.id)}">
      <strong>${escapeHtml(option.label)}</strong>
      <span>${numberFormat.format(option.policies.length)} policies${option.active ? " · active" : ""}</span>
    </button>`).join("");
  const policySections = policyCategoryGroups(policies).map((group) => {
    const policyCards = group.policies.length === 0
      ? '<p class="empty-state">No policies in this group.</p>'
      : group.policies.map((policy) => {
        const changeStatus = policy.reasons.length > 0
          ? `<details class="policy-reason-details" data-render-key="policy-choice:${escapeHtml(selectedFairness)}:${escapeHtml(policy.id)}:reasons">
              <summary class="change-mode ${policy.changeMode}" data-render-key="policy-choice:${escapeHtml(selectedFairness)}:${escapeHtml(policy.id)}:reasons:summary">${escapeHtml(policy.changeLabel)}</summary>
              <ul class="policy-reason-list">
                ${policy.reasons.map((reason) => `<li><strong>${escapeHtml(reason.label)}</strong><span>${escapeHtml(reason.detail)}</span></li>`).join("")}
              </ul>
            </details>`
          : `<span class="change-mode ${policy.changeMode}">${escapeHtml(policy.changeLabel)}</span>`;
        return `
      <article class="policy-choice${policy.active ? " active" : ""}${policy.changeMode === "invalid" ? " invalid" : ""}">
        <div class="policy-choice-copy">
          <h4>${escapeHtml(policy.name)}</h4>
          <p><code>${escapeHtml(policy.id)}</code>${policy.summary ? ` · ${escapeHtml(policy.summary)}` : ""}</p>
        </div>
        <div class="policy-choice-actions">
          ${changeStatus}
          <button class="${policy.actionKind === "activate" || policy.actionKind === "lifecycle" ? "apply-button" : "secondary-button"}" type="button"
            data-policy-id="${escapeHtml(policy.id)}"
            data-policy-fairness="${escapeHtml(selectedFairness)}"
            data-policy-action="${escapeHtml(policy.actionKind)}" ${policy.disabled ? "disabled" : ""}>
            ${escapeHtml(policy.actionLabel)}
          </button>
        </div>
      </article>`;
      }).join("");
    return `
      <section class="policy-category-section" data-policy-category="${group.id}">
        <header><h5>${escapeHtml(group.label)}</h5><span>${formatCount(group.policies.length)}</span></header>
        <div class="policy-choice-list">${policyCards}</div>
      </section>`;
  }).join("");
  replaceKeyedHtml(elements.policyChoices, `
    <div class="policy-fairness-options" role="tablist" aria-label="Fairness approach">
      ${fairnessOptions}
    </div>
    <section class="policy-fairness-branch" role="tabpanel">
      <header>
        <div>
          <h4>${escapeHtml(selectedModel.label)} policies</h4>
          <p>${escapeHtml(selectedModel.description)}</p>
        </div>
      </header>
      ${policySections}
    </section>`);
  elements.invalidPolicies.classList.add("hidden");
}

function renderPolicyContextBar(fairnessModels, activeFairness) {
  const active = fairnessModels
    .flatMap((branch) => branch.policies)
    .find((policy) => policy.active);
  elements.policyActiveContext.textContent = active
    ? `${active.name} · ${activeFairness.toUpperCase()}`
    : state.schedulerControl?.active
      ? `Unknown policy · ${activeFairness.toUpperCase()}`
      : "Snake stopped";

  const candidateState = state.policyCandidate;
  const candidate = candidateState
    ? fairnessModels
        .find((branch) => branch.id === candidateState.fairness)
        ?.policies.find((policy) => policy.id === candidateState.policyId)
    : null;
  if (!candidate) {
    elements.policyCandidateContext.textContent = "None selected";
    elements.policyCandidateImpact.textContent = "—";
    elements.policyCandidateAction.textContent = "Select a policy";
    elements.policyCandidateAction.disabled = true;
    return;
  }
  elements.policyCandidateContext.textContent = `${candidate.name} · ${candidate.selectedFairness.toUpperCase()}`;
  const reasonLabels = candidate.reasons.map((reason) => reason.label);
  elements.policyCandidateImpact.textContent = reasonLabels.length > 0
    ? `${candidate.changeLabel}: ${reasonLabels.join(", ")}`
    : candidate.changeLabel;
  state.policyCandidate.actionKind = candidate.actionKind;
  elements.policyCandidateAction.textContent = candidate.actionLabel;
  elements.policyCandidateAction.disabled = candidate.disabled;
}

function runPolicyCandidate() {
  const candidate = state.policyCandidate;
  if (!candidate) {
    return;
  }
  if (candidate.actionKind === "lifecycle") {
    selectPolicyForLifecycle(candidate.policyId, candidate.fairness);
  } else if (candidate.actionKind === "activate") {
    openPolicyDialog(candidate.policyId);
  }
}

function selectPolicyForLifecycle(policyId, fairnessMode) {
  const policy = state.schedulerControl?.policies?.find((candidate) => candidate.id === policyId);
  if (
    !policy
    || policy.change_mode === "invalid"
    || !POLICY_FAIRNESS_OPTIONS.some((option) => option.id === fairnessMode)
  ) {
    showElementNotice(elements.policyLibraryNotice, `Policy ${policyId} is not available for restart.`);
    return;
  }
  state.selectedLifecyclePolicyId = policyId;
  state.selectedLifecycleFairness = fairnessMode;
  state.schedulerFormInitialized = false;
  window.location.hash = "#/control";
  renderRoute();
}

function openPolicyDialog(policyId) {
  const policy = state.policyCatalog?.policies?.find((candidate) => candidate.id === policyId);
  if (!policy) {
    showElementNotice(elements.policyLibraryNotice, `Policy ${policyId} is no longer available.`);
    return;
  }
  state.selectedPolicy = policy;
  state.policyLibraryMessage = null;
  elements.policyDialogName.textContent = policy.name;
  elements.policyDialogSummary.textContent = policy.summary;
  elements.policyDialogSource.textContent = policy.source;
  hideElementNotice(elements.policyActivationNotice);
  elements.policyDialog.showModal();
}

async function activateSelectedPolicy() {
  const policy = state.selectedPolicy;
  if (!policy || state.policyActivationPending) {
    return;
  }
  state.policyActivationPending = true;
  elements.confirmPolicyActivation.disabled = true;
  hideElementNotice(elements.policyActivationNotice);
  try {
    const response = await fetch("/api/policies/activate", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-snake-token": token,
      },
      body: JSON.stringify({ policy_id: policy.id }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(body.error || `Policy activation failed (${response.status})`);
    }
    elements.policyDialog.close();
    state.policyCandidate = null;
    state.policyLibraryMessage = {
      text: `Activated ${policy.name} as generation ${numberFormat.format(body.generation)}.`,
      kind: "success",
    };
    await loadInspection();
    await loadPolicyCatalog();
  } catch (error) {
    showElementNotice(elements.policyActivationNotice, error.message);
  } finally {
    state.policyActivationPending = false;
    elements.confirmPolicyActivation.disabled = false;
  }
}

function renderRung(rung, index, count, ladderMetrics, queues) {
  const metrics = rung.metrics || {};
  const percentages = rungPercentages(metrics);
  const ladderRates = rungLadderPercentages(metrics, ladderMetrics);
  const missDestination = index + 1 < count ? `rung ${index + 1}` : "fallback";
  return `
    <article class="rung-row">
      <div class="rung-index" aria-label="Rung ${rung.index}">${rung.index}</div>
      <div class="rung-body">
        <header>
          <div>
            <h4>${escapeHtml(rung.operation)}</h4>
            <p>${escapeHtml(rung.scope)}</p>
          </div>
          <dl class="rung-metrics">
            <div><dt>Attempts</dt><dd>${formatCount(metrics.attempts)}</dd></div>
            <div><dt>Hits</dt><dd>${formatCount(metrics.hits)}<small>${formatPercentage(percentages.hit)} of rung attempts</small><small>${formatPercentage(ladderRates.hit)} of ladder calls</small></dd></div>
            <div><dt>Misses</dt><dd>${formatCount(metrics.misses)}<small>${formatPercentage(percentages.miss)} of rung attempts</small><small>${formatPercentage(ladderRates.miss)} of ladder calls</small></dd></div>
            <div><dt>Errors</dt><dd>${formatCount(metrics.errors)}</dd></div>
          </dl>
        </header>
        <div class="rung-fields">
          ${fieldButton("Opcode", rung.opcode)}
          ${fieldButton("Input", rung.input)}
          ${fieldButton("Flags", rung.flags)}
          ${fieldButton("Data", rung.data)}
        </div>
        <div class="rung-flow">
          <span class="hit-flow">${escapeHtml(selectionRungHitFlow(rung, queues))}</span>
          <span>Miss → ${missDestination}</span>
        </div>
      </div>
    </article>`;
}

function fieldButton(name, reference) {
  const id = `field-reference-${state.referenceId += 1}`;
  state.references.set(id, { name, reference });
  const selected = fieldReferenceGroups(reference).selected;
  return `
    <div class="rung-field">
      <span>${escapeHtml(name)}</span>
      <button type="button" class="field-value" data-reference-id="${id}">
        ${escapeHtml(selected.value)}
      </button>
    </div>`;
}

function showReferencePopover(control) {
  const entry = state.references.get(control.dataset.referenceId);
  if (!entry) {
    return;
  }
  const groups = fieldReferenceGroups(entry.reference);
  elements.referencePopover.innerHTML = `
    <header>
      <span>${escapeHtml(entry.name)}</span>
      <strong>${escapeHtml(groups.selected.label)}</strong>
    </header>
    <p>${escapeHtml(groups.selected.description)}</p>
    ${referenceGroup("Valid here", groups.valid, "valid")}
    ${referenceGroup("Other ABI choices · invalid here", groups.other, "other")}`;
  elements.referencePopover.classList.remove("hidden");
  const bounds = control.getBoundingClientRect();
  const width = Math.min(420, window.innerWidth - 24);
  const left = Math.min(window.innerWidth - width - 12, Math.max(12, bounds.left));
  const below = bounds.bottom + 8;
  const top = below + 360 < window.innerHeight
    ? below
    : Math.max(12, bounds.top - Math.min(360, elements.referencePopover.scrollHeight) - 8);
  elements.referencePopover.style.width = `${width}px`;
  elements.referencePopover.style.left = `${left}px`;
  elements.referencePopover.style.top = `${top}px`;
}

function referenceGroup(title, choices, kind) {
  if (choices.length === 0) {
    return "";
  }
  return `
    <section class="reference-group ${kind}">
      <h5>${escapeHtml(title)}</h5>
      <dl>${choices.map((choice) => `
        <div>
          <dt><code>${escapeHtml(choice.value)}</code> ${escapeHtml(choice.label)}</dt>
          <dd>${escapeHtml(choice.description)}</dd>
        </div>`).join("")}</dl>
    </section>`;
}

function hideReferencePopover(force) {
  if (!force && state.popoverPinned) {
    return;
  }
  state.popoverPinned = false;
  if (elements.referencePopover.classList.contains("hidden")) {
    return;
  }
  elements.referencePopover.classList.add("hidden");
  if (state.route === "policy" && state.inspection) {
    window.requestAnimationFrame(() => {
      if (
        state.route === "policy"
        && state.inspection
        && elements.referencePopover.classList.contains("hidden")
      ) {
        renderPolicy();
      }
    });
  }
}

function replaceKeyedHtml(container, html) {
  const snapshot = captureKeyedRenderState(
    container.querySelectorAll("[data-render-key]"),
    document.activeElement,
  );
  container.innerHTML = html;
  decorateFeedbackTargets(container);
  restoreKeyedRenderState(
    container.querySelectorAll("[data-render-key]"),
    snapshot,
  );
}

function renderCells() {
  renderInspectionStatus(elements.cellsNotice, elements.cellsFreshness);
  renderWorkloadCellOptions();
  if (!state.inspection || !state.topology) {
    elements.cellList.replaceChildren();
    elements.cellDetail.replaceChildren();
    return;
  }
  const definitions = [...state.inspection.cells];
  const definedIds = new Set(definitions.map((cell) => cell.id));
  const orphanIds = [...new Set(
    state.inspection.task_mappings
      .filter((task) => !definedIds.has(task.cell_id))
      .map((task) => task.cell_id),
  )].sort((left, right) => left - right);
  for (const id of orphanIds) {
    definitions.push({ id, cpus: [], task_count: 0, undefined: true });
  }
  const cells = decorateCells(definitions, state.inspection.task_mappings)
    .sort((left, right) => left.id - right.id);
  if (cells.length === 0) {
    elements.cellList.innerHTML = '<p class="empty-state">The active policy defines no cells.</p>';
    elements.cellDetail.replaceChildren();
    return;
  }
  if (!cells.some((cell) => cell.id === state.selectedCellId)) {
    state.selectedCellId = cells[0].id;
  }
  replaceKeyedHtml(
    elements.cellList,
    `<div class="cell-axis">${renderCpuAxis()}</div>
    ${cells.map(renderCellRow).join("")}`,
  );
  const selected = cells.find((cell) => cell.id === state.selectedCellId);
  const topology = queueTopologyModel(
    state.inspection.fairness,
    state.inspection.queue_topology,
    state.topology.numeric_order || [],
  );
  replaceKeyedHtml(
    elements.cellDetail,
    renderCellDetail(selected, cellQueueFacts(topology, selected.id)),
  );
}

function renderWorkloadTargetField() {
  const kind = document.querySelector('input[name="workloadTargetKind"]:checked')?.value || "tid";
  const cgroup = kind === "cgroup";
  elements.workloadTargetLabel.textContent = cgroup ? "Cgroup subtree" : kind.toUpperCase();
  elements.workloadTargetValue.inputMode = cgroup ? "text" : "numeric";
  elements.workloadTargetValue.placeholder = cgroup ? "/workload.slice" : "4812";
}

function renderWorkloadCellOptions() {
  const cells = state.inspection?.cells || [];
  const signature = cells.map((cell) => cell.id).join(",");
  if (elements.workloadCellId.dataset.signature !== signature) {
    const selected = elements.workloadCellId.value;
    elements.workloadCellId.innerHTML = cells
      .map((cell) => `<option value="${cell.id}">Cell ${cell.id}</option>`)
      .join("");
    if ([...elements.workloadCellId.options].some((option) => option.value === selected)) {
      elements.workloadCellId.value = selected;
    }
    elements.workloadCellId.dataset.signature = signature;
  }
  const disabled = state.workloadAssignmentPending || cells.length === 0;
  elements.workloadCellId.disabled = disabled;
  elements.assignWorkloadCell.disabled = disabled;
  elements.clearWorkloadCell.disabled = state.workloadAssignmentPending;
}

async function setWorkloadCell(clear, tidOverride = null) {
  if (state.workloadAssignmentPending) {
    return;
  }
  const kind = tidOverride === null
    ? document.querySelector('input[name="workloadTargetKind"]:checked')?.value
    : "tid";
  const value = tidOverride ?? elements.workloadTargetValue.value;
  let request;
  try {
    request = workloadAssignmentRequest(kind, value, elements.workloadCellId.value, clear);
  } catch (error) {
    showElementNotice(elements.workloadAssignmentNotice, error.message);
    return;
  }

  state.workloadAssignmentPending = true;
  renderWorkloadCellOptions();
  showElementNotice(
    elements.workloadAssignmentNotice,
    clear ? "Clearing workload override…" : "Assigning workload…",
    "info",
  );
  try {
    const response = await fetch("/api/cells/assignment", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-snake-token": token,
      },
      body: JSON.stringify(request),
    });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || `Workload update failed (${response.status})`);
    }
    const transient = payload.transient?.length
      ? `; ${numberFormat.format(payload.transient.length)} exited during update`
      : "";
    showElementNotice(
      elements.workloadAssignmentNotice,
      `${payload.target}: ${numberFormat.format(payload.updated)} of ${numberFormat.format(payload.matched)} threads updated${transient}.`,
      "success",
    );
    await loadInspection();
  } catch (error) {
    showElementNotice(elements.workloadAssignmentNotice, error.message);
  } finally {
    state.workloadAssignmentPending = false;
    renderWorkloadCellOptions();
  }
}

function renderCellRow(cell) {
  const selected = cell.id === state.selectedCellId;
  const definition = cell.undefined ? "Undefined by active policy" : `${cell.cpus.length} CPUs`;
  return `
    <button class="cell-row${selected ? " selected" : ""}" type="button"
      data-cell-id="${cell.id}" aria-pressed="${selected}">
      <span class="cell-identity"><strong>Cell ${cell.id}</strong><small>${definition}</small></span>
      ${renderCpuStrip(cell)}
    </button>`;
}

function renderCpuStrip(cell) {
  const members = new Set(cell.cpus);
  const order = cellCpuOrder(state.topology, state.cellOrderMode);
  const cpuInfo = new Map(state.topology.cpus.map((cpu) => [cpu.cpu, cpu]));
  return `
    <span class="cell-cpu-strip" style="--cpu-count:${order.length}">
      ${order.map((cpu, index) => {
        const previous = index > 0 ? cpuInfo.get(order[index - 1]) : null;
        const current = cpuInfo.get(cpu);
        const boundary = previous && current && previous.llc !== current.llc ? " llc-boundary" : "";
        const member = members.has(cpu);
        return `<i class="cpu-pixel${member ? " member" : ""}${boundary}"
          data-cell-cpu="${cpu}" data-cell-llc="${current?.llc ?? "?"}" data-cell-member="${member}"
          title="CPU ${cpu} · LLC ${current?.llc ?? "?"}"></i>`;
      }).join("")}
    </span>`;
}

function renderCpuAxis() {
  const order = cellCpuOrder(state.topology, state.cellOrderMode);
  if (state.cellOrderMode === "numeric") {
    const labels = axisLabelIndices(order.length, 18).map((index) =>
      `<span style="grid-column:${index + 1}">${order[index]}</span>`
    );
    return `<span class="cell-axis-labels numeric" style="--cpu-count:${order.length}">${labels.join("")}</span>`;
  }
  const cpuInfo = new Map(state.topology.cpus.map((cpu) => [cpu.cpu, cpu]));
  const labels = [];
  let start = 0;
  while (start < order.length) {
    const llc = cpuInfo.get(order[start])?.llc;
    let end = start + 1;
    while (end < order.length && cpuInfo.get(order[end])?.llc === llc) {
      end += 1;
    }
    labels.push(`<span style="grid-column:${start + 1} / ${end + 1}">LLC ${llc}</span>`);
    start = end;
  }
  return `<span class="cell-axis-labels" style="--cpu-count:${order.length}">${labels.join("")}</span>`;
}

function showCellBarTooltip(event) {
  const pixel = event.target.closest("[data-cell-cpu]");
  if (!pixel) {
    hideCellBarTooltip();
    return;
  }
  const cellId = pixel.closest("[data-cell-id]")?.dataset.cellId || "?";
  const membership = pixel.dataset.cellMember === "true" ? "Member" : "Not a member";
  elements.cellBarTooltip.textContent = `Cell ${cellId} · CPU ${pixel.dataset.cellCpu} · LLC ${pixel.dataset.cellLlc} · ${membership}`;
  elements.cellBarTooltip.style.left = `${Math.min(event.clientX + 12, window.innerWidth - 260)}px`;
  elements.cellBarTooltip.style.top = `${Math.min(event.clientY + 12, window.innerHeight - 48)}px`;
  elements.cellBarTooltip.classList.remove("hidden");
}

function hideCellBarTooltip() {
  elements.cellBarTooltip.classList.add("hidden");
}

function renderCellDetail(cell, queueFacts) {
  const cpuList = cell.cpus.length > 0
    ? compactCpuList(cell.cpus)
    : "No active CPU definition";
  const overlap = cell.overlapIds.length > 0
    ? cell.overlapIds.map((id) => `Cell ${id}`).join(", ")
    : "None";
  const tasks = cell.tasks.length > 0
    ? cell.tasks.map((task) => renderTaskMapping(task, cell.id)).join("")
    : '<p class="empty-state">No live task mappings for this cell.</p>';
  return `
    <header class="cell-detail-heading">
      <div><h3>Cell ${cell.id}</h3><p>${numberFormat.format(cell.tasks.length)} mapped tasks</p></div>
      ${cell.undefined ? '<span class="slot-state warning">Undefined</span>' : ""}
    </header>
    <dl class="cell-facts">
      <div><dt>Policy CPUs</dt><dd>${escapeHtml(cpuList)}</dd></div>
      <div><dt>Overlapping cells</dt><dd>${escapeHtml(overlap)}</dd></div>
      <div><dt>Primary CPUs</dt><dd>${escapeHtml(queueFacts.configured ? compactCpuList(queueFacts.primaryCpus) : "Not configured")}</dd></div>
      <div><dt>Borrowable CPUs</dt><dd>${escapeHtml(queueFacts.configured ? compactCpuList(queueFacts.borrowableCpus) : "Not configured")}</dd></div>
      <div><dt>VTIME clock</dt><dd><code>${escapeHtml(queueFacts.clock)}</code></dd></div>
      <div><dt>Normal DSQs</dt><dd>${escapeHtml(queueFacts.configured ? queueFacts.normalDsqs.join(", ") || "None" : "Not configured")}</dd></div>
      <div><dt>CPU weight</dt><dd>${queueFacts.weight == null ? "—" : formatCount(queueFacts.weight)}</dd></div>
    </dl>
    <div class="task-mappings">${tasks}</div>`;
}

function renderTaskMapping(task, cellId) {
  const cpu = task.current_cpu === null || task.current_cpu === undefined
    ? "CPU unavailable"
    : `CPU ${task.current_cpu}`;
  return `
    <details class="task-mapping" data-render-key="cell:${cellId}:task:${task.tid}">
      <summary data-render-key="cell:${cellId}:task:${task.tid}:summary">
        <span><strong>${escapeHtml(task.name || "unnamed")}</strong><small>TID ${task.tid} · TGID ${task.tgid}</small></span>
        <span><strong>${escapeHtml(cpu)}</strong><small>${escapeHtml(task.state || "unknown")}</small></span>
      </summary>
      <dl>
        <div><dt>Allowed CPUs</dt><dd>${escapeHtml(task.allowed_cpus || "unavailable")}</dd></div>
        <div><dt>Cgroup</dt><dd>${escapeHtml(task.cgroup || "unavailable")}</dd></div>
        <div><dt>Membership</dt><dd>${escapeHtml(task.membership || "unknown")} · ${escapeHtml(task.source || "unknown")}</dd></div>
        <div><dt>Placement</dt><dd>${task.needs_rehome ? "Rehome pending" : "Cell placement acknowledged"}</dd></div>
      </dl>
      <div class="task-mapping-actions">
        <button class="secondary-button" type="button" data-workload-tid="${task.tid}">Move TID</button>
        <button class="secondary-button" type="button" data-clear-workload-tid="${task.tid}">Clear override</button>
      </div>
    </details>`;
}

function renderInspectionStatus(notice, freshness) {
  renderFreshness(
    freshness,
    Boolean(state.inspection),
    state.inspectionError,
    state.lastInspectionAt,
    1_000,
  );
  if (state.inspectionError) {
    notice.textContent = state.inspectionError;
    notice.classList.remove("hidden");
  } else if (!state.inspection) {
    notice.textContent = "Inspection data is unavailable until a compatible Snake scheduler is active.";
    notice.classList.remove("hidden");
  } else {
    notice.classList.add("hidden");
  }
}

function formatTimestamp(milliseconds) {
  if (!milliseconds) {
    return "Unavailable";
  }
  return new Date(milliseconds).toLocaleString();
}

function formatCount(value) {
  return numberFormat.format(Number(value || 0));
}

function formatPercentage(value) {
  return `${Number(value || 0).toFixed(1)}%`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function topologyLine(label, cpu) {
  if (!cpu) {
    return `${label}: topology unavailable`;
  }
  return `${label}: node ${cpu.node}, package ${cpu.package}, LLC ${cpu.llc}, core ${cpu.core}`;
}

function setStatus(kind, text) {
  elements.liveStatus.className = `live-status ${kind}`;
  elements.liveStatusText.textContent = text;
}

function renderRuntimeContext() {
  const model = runtimeContextModel({
    snapshot: state.snapshot,
    inspection: state.inspectionContext ? { context: state.inspectionContext } : null,
    control: state.schedulerControl,
  });
  const collectorError = state.snapshot?.collector_error;
  const kind = collectorError
    ? "error"
    : state.snapshotError || model.synchronizing
      ? "waiting"
      : state.snapshot?.context?.scheduler_active
        || state.inspectionContext?.scheduler_active
        || state.schedulerControl?.context?.scheduler_active
        ? "active"
        : "waiting";
  const suffix = state.snapshotError ? " · reconnecting" : "";
  setStatus(kind, `${model.statusLabel}${suffix}`);
  elements.runtimeContextDetail.textContent = model.detailLabel;
  elements.runtimeContextDetail.classList.toggle(
    "synchronizing",
    model.synchronizing || Boolean(state.snapshotError),
  );
}

function renderFreshness(element, hasData, error, lastSuccessAt, pollIntervalMs) {
  const model = freshnessModel({
    hasData,
    error,
    lastSuccessAt,
    pollIntervalMs,
  });
  element.className = `view-freshness ${model.state}`;
  element.textContent = model.label;
  if (model.detail) {
    element.title = model.detail;
  } else {
    element.removeAttribute("title");
  }
}

function showNotice(message) {
  elements.notice.textContent = message;
  elements.notice.classList.remove("hidden");
}

function hideNotice() {
  elements.notice.classList.add("hidden");
}

function showElementNotice(element, message, kind = "warning") {
  element.textContent = message;
  element.className = `notice ${kind}`;
}

function hideElementNotice(element) {
  element.classList.add("hidden");
}

function formatScope(scope) {
  if (scope === "all" || scope?.all !== undefined) {
    return "All Snake tasks";
  }
  if (scope?.tgids) {
    return `TGIDs ${scope.tgids.join(", ")}`;
  }
  if (scope?.cgroup) {
    return `Cgroup ${scope.cgroup.path}`;
  }
  return "Selected task scope";
}

function formatDuration(milliseconds) {
  if (milliseconds < 1_000) {
    return `${milliseconds} ms`;
  }
  const seconds = milliseconds / 1_000;
  if (seconds < 60) {
    return `${Number.isInteger(seconds) ? seconds : seconds.toFixed(1)} s`;
  }
  const minutes = seconds / 60;
  return `${Number.isInteger(minutes) ? minutes : minutes.toFixed(1)} min`;
}

function formatRuntime(nanoseconds) {
  if (nanoseconds >= 1_000_000_000) {
    return `${(nanoseconds / 1_000_000_000).toFixed(2)} s`;
  }
  if (nanoseconds >= 1_000_000) {
    return `${(nanoseconds / 1_000_000).toFixed(1)} ms`;
  }
  if (nanoseconds >= 1_000) {
    return `${(nanoseconds / 1_000).toFixed(1)} us`;
  }
  return `${numberFormat.format(nanoseconds)} ns`;
}

function formatRate(rate) {
  if (rate >= 1_000_000) {
    return `${(rate / 1_000_000).toFixed(1)}M`;
  }
  if (rate >= 1_000) {
    return `${(rate / 1_000).toFixed(1)}k`;
  }
  return rate < 10 ? rate.toFixed(1) : numberFormat.format(Math.round(rate));
}
