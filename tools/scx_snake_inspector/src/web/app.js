// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

import {
  axisLabelIndices,
  buildCpuUsage,
  buildLlcUsage,
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
  callbackSampleRateOptions,
  captureKeyedRenderState,
  cellQueueFacts,
  cellCpuOrder,
  cellStatsModel,
  compactCpuList,
  decorateCells,
  dsqActivityModels,
  fieldReferenceGroups,
  fineTimingCaptureModels,
  fineTimingDsqModels,
  freshnessModel,
  formatCallbackDuration,
  formatCellMetric,
  formatFeedbackTranscript,
  ladderPercentages,
  launchDiff,
  parseFeedbackEntries,
  policyCategoryGroups,
  policyInlineActionModel,
  policyLibraryModels,
  policyReviewSelection,
  policySlotComparison,
  queueLadderSections,
  queueRungCallbackPercentages,
  queueRungMetricPercentages,
  queueTimingModel,
  queueTopologyModel,
  mergeQueueTimingTopology,
  nanosecondDurationClass,
  overviewModel,
  parseInspectorRoute,
  runtimeContextModel,
  restoreKeyedRenderState,
  schedulerCommandPreview,
  schedulerControlModel,
  schedulerControlMessage,
  schedulerCurrentCommand,
  schedulerCurrentLaunch,
  schedulerDebugModel,
  schedulerLifecycleRequest,
  schedulerUptimeLabel,
  statsResetDisabled,
  stableSortTableRows,
  syncCallbackSampleRateControl,
  nextTableSortState,
  updateFeedbackEntries,
  rungLadderPercentages,
  rungPercentages,
  rungTimingSummary,
  selectionRungHitFlow,
  testingMatrixModel,
  vtimeDebugModel,
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
const tableSortStates = new Map();

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
  feedbackDrawer: document.querySelector("#feedbackDrawer"),
  feedbackCount: document.querySelector("#feedbackCount"),
  closeFeedback: document.querySelector("#closeFeedback"),
  copyFeedback: document.querySelector("#copyFeedback"),
  clearFeedback: document.querySelector("#clearFeedback"),
  copyDebuggingSnapshot: document.querySelector("#copyDebuggingSnapshot"),
  cgroupField: document.querySelector("#cgroupField"),
  cgroupInput: document.querySelector("#cgroupInput"),
  cellsFreshness: document.querySelector("#cellsFreshness"),
  cellsNotice: document.querySelector("#cellsNotice"),
  cellStatsNotice: document.querySelector("#cellStatsNotice"),
  cellWindowSelect: document.querySelector("#cellWindowSelect"),
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
  schedulerUptimeStatus: document.querySelector("#schedulerUptimeStatus"),
  schedulerUptime: document.querySelector("#schedulerUptime"),
  migrationRate: document.querySelector("#migrationRate"),
  migrationPairInspection: document.querySelector("#migrationPairInspection"),
  notice: document.querySelector("#notice"),
  debuggingCommand: document.querySelector("#debuggingCommand"),
  debuggingCopyNotice: document.querySelector("#debuggingCopyNotice"),
  debuggingFreshness: document.querySelector("#debuggingFreshness"),
  debuggingIdentity: document.querySelector("#debuggingIdentity"),
  debuggingNotice: document.querySelector("#debuggingNotice"),
  debuggingPolicyContext: document.querySelector("#debuggingPolicyContext"),
  debuggingPolicySource: document.querySelector("#debuggingPolicySource"),
  debuggingSettingsRows: document.querySelector("#debuggingSettingsRows"),
  debuggingSnapshot: document.querySelector("#debuggingSnapshot"),
  debuggingView: document.querySelector("#debuggingSchedulerView"),
  debuggingVtimeFreshness: document.querySelector("#debuggingVtimeFreshness"),
  debuggingVtimeNotice: document.querySelector("#debuggingVtimeNotice"),
  debuggingVtimeView: document.querySelector("#debuggingVtimeView"),
  vtimeAccountingErrors: document.querySelector("#vtimeAccountingErrors"),
  vtimeAffinityEnqueueShare: document.querySelector("#vtimeAffinityEnqueueShare"),
  vtimeClampCount: document.querySelector("#vtimeClampCount"),
  vtimeClampRate: document.querySelector("#vtimeClampRate"),
  vtimeCounterRows: document.querySelector("#vtimeCounterRows"),
  vtimeDispatchRows: document.querySelector("#vtimeDispatchRows"),
  vtimeGeneration: document.querySelector("#vtimeGeneration"),
  vtimeQueuedRuntimeShare: document.querySelector("#vtimeQueuedRuntimeShare"),
  operationsView: document.querySelector("#operationsView"),
  roadmapView: document.querySelector("#roadmapView"),
  policyFreshness: document.querySelector("#policyFreshness"),
  policyActivationNotice: document.querySelector("#policyActivationNotice"),
  policyActiveContext: document.querySelector("#policyActiveContext"),
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
  queueFreshness: document.querySelector("#queueFreshness"),
  queueNotice: document.querySelector("#queueNotice"),
  queueTopology: document.querySelector("#queueTopology"),
  queueTopologyView: document.querySelector("#queueTopologyView"),
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
  schedulerVerbose: document.querySelector("#schedulerVerbose"),
  statsResetNotice: document.querySelector("#statsResetNotice"),
  startScheduler: document.querySelector("#startScheduler"),
  stopScheduler: document.querySelector("#stopScheduler"),
  testingDetail: document.querySelector("#testingDetail"),
  testingFailed: document.querySelector("#testingFailed"),
  testingMatrix: document.querySelector("#testingMatrix"),
  testingNotice: document.querySelector("#testingNotice"),
  testingPassed: document.querySelector("#testingPassed"),
  testingPending: document.querySelector("#testingPending"),
  testingRunning: document.querySelector("#testingRunning"),
  testingShard: document.querySelector("#testingShard"),
  testingStatus: document.querySelector("#testingStatus"),
  testingView: document.querySelector("#testingView"),
  runTesting: document.querySelector("#runTesting"),
  stopTesting: document.querySelector("#stopTesting"),
  tgidField: document.querySelector("#tgidField"),
  tgidInput: document.querySelector("#tgidInput"),
  tooltip: document.querySelector("#heatmapTooltip"),
  totalMigrations: document.querySelector("#totalMigrations"),
  activityView: document.querySelector("#activityView"),
  overviewView: document.querySelector("#overviewView"),
  overviewWindowSelect: document.querySelector("#overviewWindowSelect"),
  overviewScopeMode: document.querySelector("#overviewScopeMode"),
  overviewScopeValueField: document.querySelector("#overviewScopeValueField"),
  overviewScopeValueLabel: document.querySelector("#overviewScopeValueLabel"),
  overviewScopeValue: document.querySelector("#overviewScopeValue"),
  overviewApplyScope: document.querySelector("#overviewApplyScope"),
  overviewControlNotice: document.querySelector("#overviewControlNotice"),
  overviewContext: document.querySelector("#overviewContext"),
  overviewFaults: document.querySelector("#overviewFaults"),
  overviewPlacement: document.querySelector("#overviewPlacement"),
  overviewCellBalance: document.querySelector("#overviewCellBalance"),
  overviewQueueing: document.querySelector("#overviewQueueing"),
  overviewOverhead: document.querySelector("#overviewOverhead"),
  overviewHost: document.querySelector("#overviewHost"),
  overviewCharts: document.querySelector("#overviewCharts"),
  overviewCpuPressureChart: document.querySelector("#overviewCpuPressureChart"),
  overviewSchedulerDelayChart: document.querySelector("#overviewSchedulerDelayChart"),
  navigationDrawer: document.querySelector("#navigationDrawer"),
  openNavigation: document.querySelector("#openNavigation"),
  closeNavigation: document.querySelector("#closeNavigation"),
  slotComparison: document.querySelector("#slotComparison"),
  viewport: document.querySelector("#heatmapViewport"),
  windowCoverage: document.querySelector("#windowCoverage"),
  windowSelect: document.querySelector("#windowSelect"),
  zoom: document.querySelector("#zoomControl"),
};

const initialRoute = parseInspectorRoute(window.location.hash);

const state = {
  callbackRange: String(initialWindowMs),
  callbackTiming: null,
  callbackTimingError: null,
  callbackTimingLoading: false,
  callbackTimingRequestId: 0,
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
  hostContext: null,
  hostContextError: null,
  hostContextLoading: false,
  lastHostContextAt: 0,
  overviewScopeDirty: false,
  orderMode: "topology",
  popoverPinned: false,
  policyCatalog: null,
  policyCatalogError: null,
  policyCatalogLoading: false,
  policyLibraryMessage: null,
  policyActivationPending: false,
  policyCandidate: null,
  selectedPolicy: null,
  queueTiming: null,
  queueTimingError: null,
  queueTimingLoading: false,
  queueTimingPending: false,
  schedulerControl: null,
  schedulerControlError: null,
  schedulerMutationError: null,
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
  route: initialRoute.route,
  scale: "log",
  selectedCellId: null,
  workloadAssignmentPending: false,
  snapshot: null,
  snapshotError: null,
  topology: null,
  testing: null,
  testingError: null,
  testingLoading: false,
  testingPendingMutation: false,
  selectedTestingCaseId: null,
  windowMs: initialWindowMs,
  zoom: 1,
};

configureWindowSelector();
configureCallbackRangeSelector();
configureCallbackSampleRateSelector();
bindControls();
enhanceSortableTables(document);
decorateFeedbackTargets(document);
renderFeedback();
renderWorkloadTargetField();
renderOverviewScopeField();
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
  await loadQueueTiming();
  await loadCallbackTiming();
  await loadFineTiming();
  await loadPolicyCatalog();
  await loadSchedulerControl();
  await loadTestingMatrix();
  await loadHostContext();
  window.setInterval(loadInspection, 1_000);
  window.setInterval(loadQueueTiming, 1_000);
  window.setInterval(loadCallbackTiming, 1_000);
  window.setInterval(loadFineTiming, 1_000);
  window.setInterval(loadPolicyCatalog, 5_000);
  window.setInterval(loadSchedulerControl, 2_000);
  window.setInterval(loadTestingMatrix, 1_000);
  window.setInterval(renderSchedulerUptime, 1_000);
  window.setInterval(loadHostContext, 30_000);
}

function configureWindowSelector() {
  const presets = [1_000, 5_000, 10_000, 30_000, 60_000, 120_000, 300_000]
    .filter((value) => value <= maxWindowMs);
  if (!presets.includes(initialWindowMs)) {
    presets.push(initialWindowMs);
    presets.sort((left, right) => left - right);
  }
  for (const select of [
    elements.overviewWindowSelect,
    elements.windowSelect,
    elements.cellWindowSelect,
  ]) {
    for (const value of presets) {
      const option = document.createElement("option");
      option.value = String(value);
      option.textContent = formatDuration(value);
      option.selected = value === initialWindowMs;
      select.append(option);
    }
  }
}

function setWindow(value) {
  state.windowMs = Number(value);
  elements.windowSelect.value = String(state.windowMs);
  elements.cellWindowSelect.value = String(state.windowMs);
  elements.overviewWindowSelect.value = String(state.windowMs);
  connectEvents();
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

function bindControls() {
  elements.overviewWindowSelect.addEventListener("change", () => {
    setWindow(elements.overviewWindowSelect.value);
  });
  elements.windowSelect.addEventListener("change", () => {
    setWindow(elements.windowSelect.value);
  });
  elements.cellWindowSelect.addEventListener("change", () => {
    setWindow(elements.cellWindowSelect.value);
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
  elements.queueTopology.addEventListener("change", (event) => {
    const control = event.target.closest("[data-queue-capture]");
    if (control) {
      setQueueTiming(control.checked);
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
  elements.overviewScopeMode.addEventListener("change", () => {
    state.overviewScopeDirty = true;
    renderOverviewScopeField();
  });
  elements.overviewScopeValue.addEventListener("input", () => {
    state.overviewScopeDirty = true;
  });
  elements.overviewApplyScope.addEventListener("click", applyOverviewScope);
  elements.overviewCharts.addEventListener("click", (event) => {
    const control = event.target.closest("[data-open-ods]");
    if (control) {
      openOdsChart(control.dataset.openOds, control);
    }
  });
  elements.canvas.addEventListener("pointermove", showTooltip);
  elements.canvas.addEventListener("pointerleave", hideTooltip);
  elements.canvas.addEventListener("click", pinMigrationPair);
  elements.migrationPairInspection.addEventListener("click", (event) => {
    if (event.target.closest("[data-clear-migration-pair]")) {
      state.pinnedMigrationPair = null;
      renderHeatmap();
    }
  });
  window.addEventListener("hashchange", () => renderRoute({ focusHeading: true }));
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
    elements.schedulerExitDumpEnabled,
    elements.schedulerExitDumpLen,
    elements.schedulerVerbose,
  ]) {
    control.addEventListener("change", () => {
      state.schedulerFormInitialized = true;
      renderSchedulerControl();
    });
  }
  elements.schedulerExitDumpLen.addEventListener("input", renderSchedulerCommandPreview);
  elements.startScheduler.addEventListener("click", startScheduler);
  elements.restartScheduler.addEventListener("click", restartScheduler);
  elements.stopScheduler.addEventListener("click", stopScheduler);
  elements.runTesting.addEventListener("click", () => testingMutation("/api/testing/run"));
  elements.stopTesting.addEventListener("click", () => testingMutation("/api/testing/stop"));
  elements.testingMatrix.addEventListener("click", (event) => {
    const result = event.target.closest("[data-testing-case]");
    if (result) {
      state.selectedTestingCaseId = result.dataset.testingCase;
      renderTesting();
    }
  });
  elements.resetAllStats.addEventListener("click", resetAllStats);
  elements.copyFeedback.addEventListener("click", copyFeedback);
  elements.clearFeedback.addEventListener("click", clearFeedback);
  elements.copyDebuggingSnapshot.addEventListener("click", copyDebuggingSnapshot);
  elements.closeFeedback.addEventListener("click", closeFeedbackDrawer);
  document.querySelectorAll("[data-open-feedback]").forEach((control) => {
    control.addEventListener("click", openFeedbackDrawer);
    control.setAttribute("aria-expanded", "false");
  });
  elements.openNavigation.addEventListener("click", () => {
    if (!elements.navigationDrawer.open) {
      elements.navigationDrawer.showModal();
      elements.openNavigation.setAttribute("aria-expanded", "true");
    }
  });
  elements.closeNavigation.addEventListener("click", () => elements.navigationDrawer.close());
  elements.navigationDrawer.addEventListener("close", () => {
    elements.openNavigation.setAttribute("aria-expanded", "false");
  });
  elements.feedbackDrawer.addEventListener("close", () => {
    document.querySelectorAll("[data-open-feedback]").forEach((control) => {
      control.setAttribute("aria-expanded", "false");
    });
    if (String(window.location.hash).replace(/^#\/?/, "") === "feedback") {
      window.history.replaceState(null, "", "#/overview");
    }
  });
  elements.navigationDrawer.addEventListener("click", (event) => {
    if (event.target.closest("[data-route]")) {
      elements.navigationDrawer.close();
    }
  });
  document.addEventListener("click", (event) => {
    const toggle = event.target.closest("[data-feedback-toggle]");
    if (toggle) {
      toggleFeedbackComposer(toggle.dataset.feedbackToggle);
    }
  });
  document.addEventListener("click", handleTableSortClick);
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
    const restartApply = event.target.closest("[data-policy-restart-apply]");
    if (restartApply && !restartApply.disabled) {
      state.selectedLifecyclePolicyId = restartApply.dataset.policyRestartApply;
      state.selectedLifecycleFairness = restartApply.dataset.policyFairness;
      state.schedulerFormInitialized = true;
      renderSchedulerControl();
      if (state.schedulerControl?.active) {
        restartScheduler();
      } else {
        startScheduler();
      }
      return;
    }
    const liveApply = event.target.closest("[data-policy-live-apply]");
    if (liveApply && !liveApply.disabled) {
      openPolicyDialog(liveApply.dataset.policyLiveApply);
      return;
    }
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
    const nextCandidate = {
      policyId: control.dataset.policyId,
      fairness: control.dataset.policyFairness,
      actionKind: control.dataset.policyAction,
    };
    const selection = policyReviewSelection(state.policyCandidate, nextCandidate);
    state.policyCandidate = selection.candidate;
    state.selectedLifecyclePolicyId = selection.lifecyclePolicyId;
    state.selectedLifecycleFairness = selection.lifecycleFairness;
    state.schedulerFormInitialized = true;
    renderPolicyLibrary();
    renderSchedulerControl();
  });
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
  const draftCount = state.feedbackEntries.filter((entry) => entry.text.trim()).length;
  elements.feedbackTranscript.value = transcript;
  elements.copyFeedback.disabled = !transcript;
  elements.clearFeedback.disabled = !transcript && state.expandedFeedbackKeys.size === 0;
  elements.feedbackCount.textContent = numberFormat.format(draftCount);
  elements.feedbackCount.classList.toggle("hidden", draftCount === 0);
  elements.feedbackCount.classList.toggle("has-feedback", draftCount > 0);
  elements.feedbackCount.setAttribute(
    "aria-label",
    `${numberFormat.format(draftCount)} feedback ${draftCount === 1 ? "draft" : "drafts"}`,
  );
  document.querySelectorAll("[data-feedback-count]").forEach((count) => {
    count.textContent = numberFormat.format(draftCount);
    count.classList.toggle("hidden", draftCount === 0);
    count.classList.toggle("has-feedback", draftCount > 0);
  });
  document.querySelectorAll("[data-open-feedback]").forEach((control) => {
    control.setAttribute(
      "aria-label",
      draftCount === 0
        ? "Open feedback"
        : `Open feedback, ${numberFormat.format(draftCount)} ${draftCount === 1 ? "draft" : "drafts"}`,
    );
  });
  decorateFeedbackTargets(document);
}

function openFeedbackDrawer() {
  renderFeedback();
  if (!elements.feedbackDrawer.open) {
    elements.feedbackDrawer.showModal();
  }
  document.querySelectorAll("[data-open-feedback]").forEach((control) => {
    control.setAttribute("aria-expanded", "true");
  });
}

function closeFeedbackDrawer() {
  elements.feedbackDrawer.close();
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
      "header, .overview-section-heading, .matrix-heading, .fine-timing-panel-heading, .cell-detail-heading",
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
  const copied = await copyTextarea(elements.feedbackTranscript);
  if (copied) {
    showElementNotice(elements.feedbackNotice, "Feedback copied.", "success");
  } else {
    showElementNotice(elements.feedbackNotice, "Copy failed. The feedback text is selected.");
  }
}

async function copyDebuggingSnapshot() {
  const copied = await copyTextarea(elements.debuggingSnapshot);
  if (copied) {
    showElementNotice(elements.debuggingCopyNotice, "Scheduler snapshot copied.", "success");
  } else {
    showElementNotice(
      elements.debuggingCopyNotice,
      "Copy failed. The scheduler snapshot is selected.",
    );
  }
}

async function copyTextarea(textarea) {
  const text = textarea.value;
  if (!text) {
    return false;
  }
  let copied = false;
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
      copied = true;
    }
  } catch {
    copied = false;
  }
  if (!copied) {
    textarea.focus();
    textarea.select();
    try {
      copied = document.execCommand("copy");
    } catch {
      copied = false;
    }
  }
  return copied;
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

function renderOverviewScopeField() {
  const mode = elements.overviewScopeMode.value;
  elements.overviewScopeValueField.classList.toggle("hidden", mode === "all");
  elements.overviewScopeValueLabel.textContent = mode === "tgids" ? "TGIDs" : "Cgroup";
  elements.overviewScopeValue.placeholder = mode === "tgids"
    ? "1204, 1881"
    : "/workload.slice";
  elements.overviewScopeValue.inputMode = mode === "tgids" ? "numeric" : "text";
}

function scopePayload(mode, value) {
  if (mode === "tgids") {
    return { kind: "tgids", tgids: parseTgids(value) };
  }
  if (mode === "cgroup") {
    const path = value.trim();
    if (!path) {
      throw new Error("Enter a cgroup path");
    }
    return { kind: "cgroup", path };
  }
  return { kind: "all" };
}

async function applyScope() {
  hideNotice();
  let payload;
  try {
    const value = elements.scopeMode.value === "tgids"
      ? elements.tgidInput.value
      : elements.cgroupInput.value;
    payload = scopePayload(elements.scopeMode.value, value);
  } catch (error) {
    showNotice(error.message);
    return;
  }

  elements.applyScope.disabled = true;
  try {
    await postScope(payload);
  } catch (error) {
    showNotice(error.message);
  } finally {
    elements.applyScope.disabled = false;
  }
}

async function applyOverviewScope() {
  hideElementNotice(elements.overviewControlNotice);
  let payload;
  try {
    payload = scopePayload(elements.overviewScopeMode.value, elements.overviewScopeValue.value);
  } catch (error) {
    showElementNotice(elements.overviewControlNotice, error.message);
    return;
  }
  elements.overviewApplyScope.disabled = true;
  try {
    await postScope(payload);
    state.overviewScopeDirty = false;
    showElementNotice(elements.overviewControlNotice, "Scope updated.", "success");
  } catch (error) {
    showElementNotice(elements.overviewControlNotice, error.message);
  } finally {
    elements.overviewApplyScope.disabled = false;
  }
}

async function postScope(payload) {
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
  syncOverviewScope(snapshot.scope);

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
  if (state.route === "inspect/cells") {
    renderCells();
  } else if (state.route === "overview") {
    renderOverview();
  } else if (state.route === "debugging/scheduler") {
    renderDebugging();
  }
}

function syncOverviewScope(scope) {
  if (
    state.overviewScopeDirty
    ||
    elements.overviewApplyScope.disabled
    || elements.overviewScopeMode === document.activeElement
    || elements.overviewScopeValue === document.activeElement
  ) {
    return;
  }
  if (scope === "all" || scope?.all !== undefined) {
    elements.overviewScopeMode.value = "all";
    elements.overviewScopeValue.value = "";
  } else if (scope?.tgids) {
    elements.overviewScopeMode.value = "tgids";
    elements.overviewScopeValue.value = scope.tgids.join(", ");
  } else if (scope?.cgroup) {
    elements.overviewScopeMode.value = "cgroup";
    elements.overviewScopeValue.value = scope.cgroup.path || "";
  }
  renderOverviewScopeField();
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
  const llcUsage = buildLlcUsage(
    state.topology,
    state.snapshot?.cpu_usage || [],
    state.orderMode,
  );
  const cpuCount = matrix.order.length;
  const viewportWidth = Math.max(320, elements.viewport.clientWidth || 800);
  const {
    cellSize,
    height,
    llcHeight,
    llcTop,
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
  drawLlcUsage(context, llcUsage, margins, cellSize, llcTop, llcHeight);
  state.geometry = {
    cellSize,
    llcHeight,
    llcTop,
    llcUsage,
    margins,
    matrix,
    matrixSize,
    usage,
    usageHeight,
    usageTop,
  };
  elements.canvas.setAttribute(
    "aria-label",
    `CPU migration heatmap with ${numberFormat.format(matrix.total)} transitions, all-Snake utilization across ${cpuCount} CPUs, and capacity-normalized utilization across ${llcUsage.groups.length} LLCs`,
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

function drawLlcUsage(context, llcUsage, margins, cellSize, top, height) {
  for (const span of llcUsage.spans) {
    const group = llcUsage.groups[span.groupIndex];
    const left = margins.left + span.start * cellSize;
    const width = (span.end - span.start) * cellSize;
    const intensity = normalizeUtilization(group.utilizationPct, state.scale);
    context.fillStyle = infernoColor(intensity);
    context.fillRect(left, top, Math.ceil(width), height);
    context.strokeStyle = "#ffffff";
    context.lineWidth = 2;
    context.strokeRect(left, top, Math.ceil(width), height);

    context.font = "600 9px ui-sans-serif, system-ui, sans-serif";
    context.textAlign = "center";
    context.textBaseline = "middle";
    context.fillStyle = intensity > 0.72 ? "#11161c" : "#ffffff";
    const labels = [
      `LLC ${group.llc} · ${group.utilizationPct.toFixed(1)}%`,
      `${group.llc} · ${group.utilizationPct.toFixed(0)}%`,
    ];
    const label = labels.find((candidate) => context.measureText(candidate).width <= width - 6);
    if (label) {
      context.fillText(label, left + width / 2, top + height / 2);
    }
  }

  context.fillStyle = "#25313b";
  context.font = "600 10px ui-sans-serif, system-ui, sans-serif";
  context.textAlign = "right";
  context.textBaseline = "middle";
  context.fillText("LLC util", margins.left - 7, top + height / 2);
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
  if (
    column >= 0 && column < size &&
    canvasY >= geometry.llcTop &&
    canvasY < geometry.llcTop + geometry.llcHeight
  ) {
    const span = geometry.llcUsage.spans.find((candidate) => (
      column >= candidate.start && column < candidate.end
    ));
    const group = span && geometry.llcUsage.groups[span.groupIndex];
    if (group) {
      elements.tooltip.textContent = [
        `LLC ${group.llc}`,
        `All Snake utilization: ${group.utilizationPct.toFixed(1)}% of LLC capacity`,
        `${formatRuntime(group.runtimeNs)} runtime across ${numberFormat.format(group.cpuCount)} CPUs`,
        `Node ${group.node} · package ${group.package}`,
      ].join("\n");
      positionTooltip(event);
      return;
    }
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

function renderRoute({ focusHeading = false } = {}) {
  const parsed = parseInspectorRoute(window.location.hash);
  state.route = parsed.route;
  hideCellBarTooltip();
  for (const view of [
    elements.overviewView,
    elements.activityView,
    elements.callbacksView,
    elements.policyView,
    elements.queueTopologyView,
    elements.cellsView,
    elements.schedulerControlView,
    elements.testingView,
    elements.debuggingView,
    elements.debuggingVtimeView,
    elements.operationsView,
    elements.roadmapView,
  ]) {
    view.classList.toggle("hidden", view.dataset.view !== state.route);
  }
  document.querySelectorAll("[data-route]").forEach((link) => {
    if (link.dataset.route === state.route) {
      link.setAttribute("aria-current", "page");
    } else {
      link.removeAttribute("aria-current");
    }
  });
  hideReferencePopover(true);
  if (state.route === "overview") {
    renderOverview();
  } else if (state.route === "observe/placement") {
    window.requestAnimationFrame(renderHeatmap);
  } else if (state.route === "configure") {
    renderPolicyLibrary();
    renderSchedulerControl();
  } else if (state.route === "validate/testing") {
    renderTesting();
  } else if (state.route === "debugging/scheduler") {
    renderDebugging();
  } else if (state.route === "debugging/vtime") {
    renderVtimeDebugging();
  } else {
    renderInspectionViews();
  }
  if (parsed.feedbackOpen) {
    openFeedbackDrawer();
  }
  if (focusHeading) {
    window.scrollTo(0, 0);
    window.requestAnimationFrame(() => {
      const heading = document.querySelector(`[data-view="${state.route}"]:not(.hidden) h2`);
      if (heading) {
        heading.tabIndex = -1;
        heading.focus({ preventScroll: true });
      }
    });
  }
}

function renderOverview() {
  const model = overviewModel({
    snapshot: state.snapshot,
    callbackTiming: state.callbackTiming,
    inspection: state.inspection
      ? { ...state.inspection, context: state.inspectionContext }
      : null,
    control: state.schedulerControl,
    topology: state.topology,
    queueTiming: state.queueTiming,
    hostContext: state.hostContext,
    errors: [
      state.snapshotError,
      state.callbackTimingError,
      state.inspectionError,
      state.queueTimingError,
      state.policyCatalogError,
      state.schedulerControlError,
      state.schedulerMutationError,
      state.hostContextError,
    ],
  });
  const identity = model.host.identity || {};
  elements.overviewContext.innerHTML = overviewFacts([
    ["Host", identity.hostname || "Unavailable"],
    ["Location", [identity.datacenter, identity.region].filter(Boolean).join(" · ") || "Unavailable"],
    ["Pool / hardware", [identity.machine_pool, identity.hardware].filter(Boolean).join(" · ") || "Unavailable"],
    ["Logical CPUs", identity.cpu_count == null ? "Unavailable" : formatCount(identity.cpu_count)],
    ["Host data", state.hostContextError
      ? `Stale · last contact ${formatTimestamp(state.lastHostContextAt)}`
      : model.host.resourceBrowser?.state || (model.host.available ? "Local only" : "Loading")],
    ["Scheduler", model.runtime.statusLabel],
    ["Policy", model.runtime.detailLabel],
  ]);

  elements.overviewFaults.classList.toggle("hidden", model.warnings.length === 0);
  const warningSignature = JSON.stringify(model.warnings);
  if (elements.overviewFaults.dataset.warningSignature !== warningSignature) {
    elements.overviewFaults.dataset.warningSignature = warningSignature;
    elements.overviewFaults.innerHTML = model.warnings.length === 0
      ? ""
      : `<strong>Reported faults and incomplete data</strong><ul>${model.warnings.map((warning) => `<li>${escapeHtml(warning)}</li>`).join("")}</ul>`;
  }

  const busiestRoute = model.activity.busiestRoute
    ? `CPU ${formatCount(model.activity.busiestRoute.from)} → CPU ${formatCount(model.activity.busiestRoute.to)} · ${formatCount(model.activity.busiestRoute.count)}`
    : "No migrations in the current window";
  const placementFacts = [
    ["Migrations", formatCount(model.activity.total)],
    ["Rate", `${formatRate(model.activity.ratePerSecond)}/s`],
    ["Busiest route", busiestRoute],
    ["Coverage", `${formatDuration(model.activity.observedMs)} / ${formatDuration(model.activity.windowMs)}`],
  ];
  if (model.activity.selectCalls > 0) {
    placementFacts.splice(2, 0,
      ["Policy-generation direct dispatch", `${formatPercentage(model.activity.directDispatchPct)} · ${formatCount(model.activity.directDispatches)}`],
      ["Policy-generation ladder exhaustion", `${formatPercentage(model.activity.exhaustionPct)} · ${formatCount(model.activity.ladderExhaustions)}`],
    );
  }
  elements.overviewPlacement.innerHTML = model.activity.available
    ? overviewFacts([
        ...placementFacts,
      ])
    : '<span class="overview-empty">Waiting for migration data</span>';

  const topBorrower = model.tuning.cells.borrowers[0];
  const topLender = model.tuning.cells.lenders[0];
  elements.overviewCellBalance.innerHTML = model.tuning.cells.ranked.length > 0
    ? `<div class="overview-cell-highlights">
        <span><small>Largest borrower</small><strong>${topBorrower ? `Cell ${escapeHtml(topBorrower.id)} · ${escapeHtml(formatCellMetric(topBorrower.borrowedPct, "percentage"))}` : "—"}</strong></span>
        <span><small>Largest lender</small><strong>${topLender ? `Cell ${escapeHtml(topLender.id)} · ${escapeHtml(formatCellMetric(topLender.lentPct, "percentage"))}` : "—"}</strong></span>
      </div><ol class="overview-ranking">${model.tuning.cells.ranked.map((cell) => `
        <li><strong>Cell ${escapeHtml(cell.id)}</strong><span>Owned ${escapeHtml(formatCellMetric(cell.ownedUtilizationPct, "percentage"))} · borrowed ${escapeHtml(formatCellMetric(cell.borrowedPct, "percentage"))} · lent ${escapeHtml(formatCellMetric(cell.lentPct, "percentage"))}</span></li>`).join("")}</ol>`
    : `<span class="overview-empty">${escapeHtml(model.tuning.cells.statusLabel)}</span>`;

  elements.overviewQueueing.innerHTML = model.tuning.queues.ranked.length > 0
    ? `<p class="overview-time-basis">Current queue-capture session</p><ol class="overview-ranking">${model.tuning.queues.ranked.map((queue) => `
        <li><strong>DSQ ${escapeHtml(queue.dsqId)}</strong><span>p99 ${escapeHtml(queue.p99Ns == null ? "—" : formatCallbackDuration(queue.p99Ns))} · p95 depth ${escapeHtml(formatNullableCount(queue.p95Depth))} · ${formatCount(queue.samples)} samples</span></li>`).join("")}</ol>`
    : `<span class="overview-empty">${escapeHtml(
        model.tuning.queues.status === "ready" && model.tuning.queues.state === "inactive"
          ? "Queue timing capture is off. Open Queue topology to collect it."
          : model.tuning.queues.statusLabel,
      )}</span>`;

  const callbackRanking = model.tuning.callbacks.ranked.length > 0
    ? `<div><h4>Callbacks · ${escapeHtml(model.tuning.callbacks.windowMs ? formatDuration(model.tuning.callbacks.windowMs) : "selected range")}</h4><ol class="overview-ranking">${model.tuning.callbacks.ranked.map((callback) => `
        <li><strong>${escapeHtml(callback.callback)}</strong><span>p99 ${escapeHtml(formatCallbackDuration(callback.p99Ns))} · ${formatCount(callback.samples)} samples</span></li>`).join("")}</ol></div>`
    : '<span class="overview-empty">No callback samples</span>';
  const rungRanking = model.tuning.rungs.ranked.length > 0
    ? `<div><h4>Policy ladder · current generation</h4><ol class="overview-ranking">${model.tuning.rungs.ranked.map((rung) => `
        <li><strong>Rung ${escapeHtml(rung.index)} · ${escapeHtml(rung.operation)}</strong><span>sampled p95 ${escapeHtml(formatCallbackDuration(rung.p95Ns))} · ${formatCount(rung.samples)} samples</span></li>`).join("")}</ol></div>`
    : '<span class="overview-empty">No sampled rung timing</span>';
  elements.overviewOverhead.innerHTML = `<div class="overview-overhead-groups">${callbackRanking}${rungRanking}</div>`;

  renderOverviewHost(model.host);
  renderOverviewChart(
    elements.overviewCpuPressureChart,
    model.host.charts.find((chart) => chart.metric === "cpu-pressure"),
  );
  renderOverviewChart(
    elements.overviewSchedulerDelayChart,
    model.host.charts.find((chart) => chart.metric === "scheduler-delay"),
  );
}

function overviewFacts(facts) {
  return `<dl>${facts.map(([name, value]) => `
    <div><dt>${escapeHtml(name)}</dt><dd>${escapeHtml(value)}</dd></div>`).join("")}</dl>`;
}

function renderOverviewHost(host) {
  const signature = JSON.stringify([host, state.hostContextError]);
  if (elements.overviewHost.dataset.hostSignature === signature) {
    return;
  }
  elements.overviewHost.dataset.hostSignature = signature;
  if (!host.available) {
    elements.overviewHost.innerHTML = `<span class="overview-empty">${escapeHtml(state.hostContextError || "Host metadata is loading")}</span>`;
    return;
  }
  const identity = host.identity || {};
  const taskContent = host.taskState === "ready" || host.taskState === "stale"
    ? host.jobs.length === 0
      ? '<p class="overview-empty">No Tupperware tasks are assigned to this host.</p>'
      : `<ul class="overview-host-list">${host.jobs.map((job) => `
          <li><strong>${escapeHtml(job.jobHandle)}</strong><span>Tasks ${job.taskIds.map(escapeHtml).join(", ")}</span></li>`).join("")}</ul>`
    : `<p class="overview-empty">${escapeHtml(host.taskMessage || "Tupperware placement is loading")}</p>`;
  const allotmentContent = host.allotmentState === "ready" || host.allotmentState === "stale"
    ? host.allotmentGroups.length === 0
      ? '<p class="overview-empty">No Resource Broker allotments; this host is currently unreserved.</p>'
      : `<ul class="overview-host-list">${host.allotmentGroups.map((group) => `
          <li><strong>${formatCount(group.count)} × ${escapeHtml(group.shape)} · ${escapeHtml(group.ownership)}</strong><span>${escapeHtml(group.state)}${group.owners.length > 0 ? ` · ${group.owners.map(escapeHtml).join(", ")}` : ""}</span></li>`).join("")}</ul>`
    : `<p class="overview-empty">${escapeHtml(host.allotmentMessage || "Allotment data is loading")}</p>`;
  replaceKeyedHtml(elements.overviewHost, `
    ${state.hostContextError ? `<p class="overview-source-stale">Host context is stale · ${escapeHtml(state.hostContextError)} · last successful contact ${escapeHtml(formatTimestamp(state.lastHostContextAt))}</p>` : ""}
    <div class="overview-host-columns">
      <details open data-render-key="overview:tw-tasks">
        <summary data-render-key="overview:tw-tasks:summary">Tupperware tasks · ${formatCount(host.jobs.reduce((total, job) => total + job.taskIds.length, 0))}</summary>
        ${host.taskState === "stale" ? `<p class="overview-source-stale">Stale · ${escapeHtml(host.taskMessage || "refresh failed")}</p>` : ""}
        ${taskContent}
      </details>
      <details open data-render-key="overview:allotments">
        <summary data-render-key="overview:allotments:summary">Allotments · ${formatCount(host.allotmentGroups.reduce((total, group) => total + group.count, 0))}</summary>
        ${host.allotmentState === "stale" ? `<p class="overview-source-stale">Stale · ${escapeHtml(host.allotmentMessage || "refresh failed")}</p>` : ""}
        ${allotmentContent}
      </details>
    </div>
    <dl class="overview-host-identifiers">
      <div><dt>Device</dt><dd>${escapeHtml(identity.device_id || "Unavailable")}</dd></div>
      <div><dt>Reservation</dt><dd>${escapeHtml(identity.reservation_id || "Unreserved")}</dd></div>
      <div><dt>Materialization</dt><dd>${escapeHtml(identity.materialization_id || "None")}</dd></div>
    </dl>`);
}

function renderOverviewChart(container, chart) {
  const signature = JSON.stringify([
    chart?.state,
    chart?.fetched_at_ms,
    chart?.message,
    chart?.image_url,
    chart?.open_url,
    state.hostContextError,
  ]);
  if (container.dataset.chartSignature === signature) {
    return;
  }
  container.dataset.chartSignature = signature;
  if (!chart || !["ready", "stale"].includes(chart.state) || !chart.fetched_at_ms) {
    container.innerHTML = `<span class="overview-empty">${escapeHtml(chart?.message || "ODS chart is loading")}</span>`;
    return;
  }
  container.innerHTML = `
    <button class="overview-chart-image-link" type="button" data-open-ods="${escapeHtml(chart.open_url)}" aria-label="Open ${escapeHtml(chart.label)} in ODS">
      <img src="${escapeHtml(chart.image_url)}?revision=${encodeURIComponent(chart.fetched_at_ms)}" alt="${escapeHtml(chart.label)} over the last three hours">
    </button>
    <footer><span>${chart.state === "stale" || state.hostContextError ? "Stale · last successful chart" : "Updated"} ${escapeHtml(formatTimestamp(chart.fetched_at_ms))}</span><button class="overview-chart-open" type="button" data-open-ods="${escapeHtml(chart.open_url)}">Open in ODS</button></footer>`;
}

async function openOdsChart(endpoint, control) {
  const popup = window.open("about:blank", "_blank");
  if (popup) {
    popup.opener = null;
  }
  control.disabled = true;
  hideElementNotice(elements.overviewControlNotice);
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "x-snake-token": token },
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok || !body.url) {
      throw new Error(body.error || `ODS link request failed (${response.status})`);
    }
    if (popup) {
      popup.location.replace(body.url);
    } else {
      window.open(body.url, "_blank", "noopener");
    }
  } catch (error) {
    if (popup) {
      popup.close();
    }
    showElementNotice(elements.overviewControlNotice, error.message);
  } finally {
    control.disabled = false;
  }
}

function renderDebugging() {
  const inspection = state.inspection
    ? { ...state.inspection, context: state.inspectionContext }
    : null;
  const model = schedulerDebugModel({
    control: state.schedulerControl,
    inspection,
  });
  renderFreshness(
    elements.debuggingFreshness,
    Boolean(state.schedulerControl || inspection),
    state.schedulerControlError || state.inspectionError,
    Math.max(state.lastSchedulerControlAt, state.lastInspectionAt),
    2_000,
  );
  const message = state.schedulerControlError
    || state.inspectionError
    || (!model.available ? "Snake is not running; no active scheduler configuration is available." : null);
  if (message) {
    showElementNotice(elements.debuggingNotice, message, model.available ? "warning" : "info");
  } else {
    hideElementNotice(elements.debuggingNotice);
  }
  const identityFacts = [
    ["Scheduler", model.identity.schedulerName || "Unavailable"],
    ["PID", model.identity.pid == null ? "Unavailable" : formatCount(model.identity.pid)],
    ["Ownership", model.identity.ownership],
    ["Attachment", model.identity.attachSequence == null ? "Unavailable" : `#${formatCount(model.identity.attachSequence)}`],
    ["Policy", model.identity.policyId || "Unavailable"],
    ["Generation", model.identity.policyGeneration == null ? "Unavailable" : formatCount(model.identity.policyGeneration)],
    ["Active rung set", model.identity.activeSlot == null ? "Unavailable" : formatCount(model.identity.activeSlot)],
  ];
  elements.debuggingIdentity.innerHTML = identityFacts.map(([name, value]) => `
    <div><dt>${escapeHtml(name)}</dt><dd>${escapeHtml(value)}</dd></div>`).join("");
  elements.debuggingCommand.textContent = model.command;
  replaceSortableTableBody(elements.debuggingSettingsRows, model.nonDefaultSettings.length === 0
    ? '<tr><td class="debugging-empty" colspan="6">No non-default settings are active.</td></tr>'
    : model.nonDefaultSettings.map((setting) => `
      <tr>
        <th scope="row">${escapeHtml(setting.name)}</th>
        <td><code>${escapeHtml(setting.defaultValue)}</code></td>
        <td><code>${escapeHtml(setting.effectiveValue)}</code></td>
        <td><code>${escapeHtml(setting.launchOverride || "Omitted")}</code></td>
        <td>${escapeHtml(setting.source)}</td>
        <td><span class="change-mode ${setting.changeLabel === "Dynamic" ? "dynamic" : "reload"}">${escapeHtml(setting.changeLabel)}</span></td>
      </tr>`).join(""));
  elements.debuggingPolicyContext.textContent = model.identity.policyId
    ? `${model.identity.policyId} · generation ${model.identity.policyGeneration ?? "unknown"} · rung set ${model.identity.activeSlot ?? "unknown"}`
    : "Unavailable";
  elements.debuggingPolicySource.textContent = model.policySource || "Policy source unavailable.";
  if (document.activeElement !== elements.debuggingSnapshot) {
    elements.debuggingSnapshot.value = model.snapshotText;
  }
  elements.copyDebuggingSnapshot.disabled = !model.snapshotText;
  decorateFeedbackTargets(elements.debuggingView);
}

function renderVtimeDebugging() {
  const inspection = state.inspection
    ? { ...state.inspection, context: state.inspectionContext }
    : null;
  const model = vtimeDebugModel(inspection);
  renderFreshness(
    elements.debuggingVtimeFreshness,
    model.available,
    state.inspectionError,
    state.lastInspectionAt,
    2_000,
  );
  const message = state.inspectionError
    || (!model.available
      ? "Snake inspection data is unavailable."
      : !model.modeActive
        ? `VTIME is not active; current fairness mode is ${String(model.modeName || "unknown").toUpperCase()}.`
        : model.accountingErrors > 0
          ? `${formatCount(model.accountingErrors)} VTIME accounting errors were reported in this generation.`
          : null);
  if (message) {
    showElementNotice(
      elements.debuggingVtimeNotice,
      message,
      model.available && model.modeActive ? "warning" : "info",
    );
  } else {
    hideElementNotice(elements.debuggingVtimeNotice);
  }

  elements.vtimeClampCount.textContent = formatCount(model.clamps.count);
  elements.vtimeClampRate.textContent = `${formatPercentage(model.clamps.enqueuePct)} of enqueues`;
  elements.vtimeAccountingErrors.textContent = formatCount(model.accountingErrors);
  elements.vtimeQueuedRuntimeShare.textContent = formatPercentage(model.runtime.queuedPct);
  elements.vtimeAffinityEnqueueShare.textContent = formatPercentage(model.affinity.enqueuePct);
  elements.vtimeGeneration.textContent = model.generation == null
    ? "Generation unavailable"
    : `Policy generation ${formatCount(model.generation)}`;

  const affinityDispatchPct = model.dispatches > 0
    ? model.affinity.dispatches * 100 / model.dispatches
    : 0;
  const counterRows = [
    ["VTIME enqueues", model.enqueues, model.enqueues > 0 ? 100 : 0],
    ["VTIME dispatches", model.dispatches, model.dispatchPct],
    ["Affinity enqueues", model.affinity.enqueues, model.affinity.enqueuePct],
    ["Affinity dispatches", model.affinity.dispatches, affinityDispatchPct],
    ["Credit clamps", model.clamps.count, model.clamps.enqueuePct],
    ["Equal-head ties", model.equalHeadTies, model.equalHeadTiePct],
    ["Accounting errors", model.accountingErrors, null],
  ];
  replaceSortableTableBody(elements.vtimeCounterRows, counterRows.map(([label, value, share]) => `
    <tr><th scope="row">${escapeHtml(label)}</th><td>${formatCount(value)}</td><td>${share == null ? "—" : formatPercentage(share)}</td></tr>`).join(""));

  replaceSortableTableBody(elements.vtimeDispatchRows, model.dispatchRungs.length === 0
    ? '<tr><td class="debugging-empty" colspan="8">Dispatch rung counters are unavailable.</td></tr>'
    : model.dispatchRungs.map((rung) => `
      <tr>
        <th scope="row">${formatCount(rung.index)}</th>
        <td><code>${escapeHtml(rung.operation)}</code></td>
        <td>${formatCount(rung.attempts)}</td>
        <td>${formatCount(rung.hits)}</td>
        <td>${formatCount(rung.selected)}</td>
        <td>${formatCount(rung.misses)}</td>
        <td>${formatCount(rung.moveMisses)}</td>
        <td>${formatCount(rung.errors)}</td>
      </tr>`).join(""));
  decorateFeedbackTargets(elements.debuggingVtimeView);
}

async function loadCallbackTiming({ force = false } = {}) {
  if (state.callbackTimingLoading && !force) {
    return;
  }
  const requestId = ++state.callbackTimingRequestId;
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
    const timing = await response.json();
    if (requestId !== state.callbackTimingRequestId) {
      return;
    }
    state.callbackTiming = timing;
    state.callbackTimingError = null;
    state.lastCallbackTimingAt = Date.now();
  } catch (error) {
    if (requestId !== state.callbackTimingRequestId) {
      return;
    }
    state.callbackTimingError = error.message;
  } finally {
    if (requestId === state.callbackTimingRequestId) {
      state.callbackTimingLoading = false;
    }
  }
  renderRuntimeContext();
  if (state.route === "observe/callbacks") {
    renderCallbackTiming();
  } else if (state.route === "overview") {
    renderOverview();
  } else if (state.route === "debugging/scheduler") {
    renderDebugging();
  } else if (state.route === "debugging/vtime") {
    renderVtimeDebugging();
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
  if (state.route === "observe/callbacks") {
    renderFineTiming();
  } else if (state.route === "inspect/queue-topology") {
    renderResolvedQueueTopology();
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
    const suffix = [
      payload.fine_timing_stopped
        ? " Active fine-grained captures were preserved as Historical."
        : "",
      payload.queue_timing_stopped
        ? " Active queue capture was preserved as Historical."
        : "",
    ].join("");
    showElementNotice(
      elements.callbackRateNotice,
      `Callback sampling updated to ${sampleRate === 0 ? "Disabled" : `1 / ${numberFormat.format(sampleRate)}`}.${suffix}`,
      "success",
    );
    await Promise.all([
      loadCallbackTiming(),
      loadFineTiming(),
      loadInspection(),
      loadQueueTiming(),
    ]);
  } catch (error) {
    showElementNotice(elements.callbackRateNotice, error.message);
  } finally {
    state.callbackRatePending = false;
    elements.applyCallbackSampleRate.disabled = false;
  }
}

async function loadQueueTiming() {
  if (state.queueTimingLoading) {
    return;
  }
  state.queueTimingLoading = true;
  try {
    const response = await fetch("/api/queue-timing", {
      cache: "no-store",
      headers: { "x-snake-token": token },
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.error || `Queue timing request failed (${response.status})`);
    }
    state.queueTiming = payload;
    state.queueTimingError = null;
  } catch (error) {
    state.queueTimingError = error.message;
  } finally {
    state.queueTimingLoading = false;
  }
  if (state.route === "inspect/queue-topology") {
    renderInspectionViews();
  } else if (state.route === "overview") {
    renderOverview();
  } else if (state.route === "debugging/scheduler") {
    renderDebugging();
  }
}

async function setQueueTiming(enabled) {
  if (state.queueTimingPending) {
    return;
  }
  const model = queueTimingModel(state.queueTiming, {
    context: state.inspectionContext,
  });
  if (model.controlDisabled) {
    renderQueueTopologyView();
    return;
  }
  state.queueTimingPending = true;
  state.queueTimingError = null;
  renderQueueTopologyView();
  try {
    const response = await fetch("/api/queue-timing", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-snake-token": token,
      },
      body: JSON.stringify({ enabled }),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.error || `Queue capture update failed (${response.status})`);
    }
    await loadQueueTiming();
  } catch (error) {
    state.queueTimingError = error.message;
  } finally {
    state.queueTimingPending = false;
    renderQueueTopologyView();
  }
}

async function loadHostContext() {
  if (state.hostContextLoading) {
    return;
  }
  state.hostContextLoading = true;
  try {
    const response = await fetch("/api/host-context", { cache: "no-store" });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.error || `Host context request failed (${response.status})`);
    }
    state.hostContext = await response.json();
    state.hostContextError = null;
    state.lastHostContextAt = Date.now();
  } catch (error) {
    state.hostContextError = error.message;
  } finally {
    state.hostContextLoading = false;
    if (state.route === "overview") {
      renderOverview();
    }
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
  if (state.route === "configure") {
    renderPolicyLibrary();
  } else if (state.route === "overview") {
    renderOverview();
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
  renderStatsResetControl();
  if (state.route === "configure") {
    renderSchedulerControl();
    renderPolicyLibrary();
  } else if (state.route === "overview") {
    renderOverview();
  } else if (state.route === "debugging/scheduler") {
    renderDebugging();
  }
}

async function loadTestingMatrix() {
  if (state.testingLoading) {
    return;
  }
  state.testingLoading = true;
  try {
    const response = await fetch("/api/testing/matrix", { cache: "no-store" });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.error || `Testing matrix request failed (${response.status})`);
    }
    state.testing = payload;
    state.testingError = null;
  } catch (error) {
    state.testingError = error.message;
  } finally {
    state.testingLoading = false;
  }
  if (state.route === "validate/testing") {
    renderTesting();
  } else if (state.route === "configure") {
    renderSchedulerControl();
  }
}

async function testingMutation(endpoint) {
  if (state.testingPendingMutation) {
    return;
  }
  state.testingPendingMutation = true;
  hideElementNotice(elements.testingNotice);
  renderTesting();
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-snake-token": token,
      },
      body: "{}",
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.error || `Testing request failed (${response.status})`);
    }
    state.testing = payload;
    state.testingError = null;
  } catch (error) {
    state.testingError = error.message;
    showElementNotice(elements.testingNotice, error.message, true);
  } finally {
    state.testingPendingMutation = false;
    renderTesting();
  }
}

function renderTesting() {
  if (!state.testing) {
    elements.testingStatus.textContent = state.testingError || "Loading testing matrix";
    elements.runTesting.disabled = true;
    elements.stopTesting.disabled = true;
    elements.testingMatrix.innerHTML = "";
    if (state.testingError) {
      showElementNotice(elements.testingNotice, state.testingError, true);
    }
    return;
  }
  const model = testingMatrixModel(state.testing);
  if (state.testingError) {
    showElementNotice(elements.testingNotice, state.testingError, true);
  } else {
    hideElementNotice(elements.testingNotice);
  }
  const running = model.status === "running";
  elements.testingStatus.textContent = `${model.statusLabel} · ${model.durationSecs}s per case`;
  elements.testingPassed.textContent = numberFormat.format(model.summary.passed);
  elements.testingFailed.textContent = numberFormat.format(model.summary.failed);
  elements.testingRunning.textContent = numberFormat.format(model.summary.running);
  elements.testingPending.textContent = numberFormat.format(model.summary.pending);
  elements.testingShard.textContent = model.aggregate
    ? `All shards · ${model.reportingShards} of ${model.shardCount} reporting · ${model.totalCases} cases`
    : `Shard ${model.shardIndex + 1} of ${model.shardCount} · ${model.assignedCases} assigned of ${model.totalCases}`;
  elements.runTesting.disabled = model.aggregate || running || state.testingPendingMutation;
  elements.stopTesting.disabled = model.aggregate || !running || state.testingPendingMutation;
  const headings = model.workloads
    .map((workload) => `<th scope="col">${escapeHtml(workload.label)}</th>`)
    .join("");
  const rows = model.groups.map((group) => {
    const groupRow = `<tr class="testing-fairness-row"><th colspan="${model.workloads.length + 1}" scope="rowgroup">${escapeHtml(group.label)}</th></tr>`;
    const policyRows = group.rows.map((row) => {
      const byWorkload = new Map(row.cases.map((testCase) => [testCase.workload, testCase]));
      const cells = model.workloads.map((workload) => {
        const testCase = byWorkload.get(workload.id);
        if (!testCase) {
          return '<td><span class="testing-result unassigned">—</span></td>';
        }
        const content = testCase.symbol
          ? `<span class="testing-result-symbol" aria-hidden="true">${testCase.symbol}</span>`
          : escapeHtml(testCase.label);
        return `<td><button class="testing-result ${escapeHtml(testCase.className)}" type="button" data-testing-case="${escapeHtml(testCase.id)}" aria-label="${escapeHtml(`${row.policyName}, ${workload.label}: ${testCase.label}`)}" title="${escapeHtml(testCase.tooltip)}"${testCase.assigned ? "" : " disabled"}>${content}</button></td>`;
      }).join("");
      return `<tr><th scope="row">${escapeHtml(row.policyName)}</th>${cells}</tr>`;
    }).join("");
    return groupRow + policyRows;
  }).join("");
  elements.testingMatrix.innerHTML = `<thead><tr><th scope="col">Policy</th>${headings}</tr></thead><tbody>${rows}</tbody>`;

  const selected = model.groups
    .flatMap((group) => group.rows)
    .flatMap((row) => row.cases.map((testCase) => ({ ...testCase, policyName: row.policyName })))
    .find((testCase) => testCase.id === state.selectedTestingCaseId);
  if (selected) {
    const elapsed = selected.status === "running"
      ? "In progress"
      : (selected.elapsedMs ? `${(selected.elapsedMs / 1_000).toFixed(1)}s` : "Not started");
    const workloadLabel = model.workloads.find((workload) => workload.id === selected.workload)?.label
      || selected.workload;
    elements.testingDetail.innerHTML = `<strong>${escapeHtml(selected.policyName)} · ${escapeHtml(workloadLabel)}</strong><br>Status: ${escapeHtml(selected.label)} · Runtime: ${escapeHtml(elapsed)}${selected.failure ? `<br>Failure: ${escapeHtml(selected.failure)}` : ""}`;
  } else {
    elements.testingDetail.textContent = "Select a result to inspect its runtime and failure details.";
  }
}

function renderSchedulerControl() {
  const control = state.schedulerControl;
  if (control && !state.schedulerFormInitialized) {
    hydrateSchedulerLaunchForm(control);
    state.schedulerFormInitialized = true;
  }
  if (
    state.selectedLifecyclePolicyId
    && Array.isArray(control?.policies)
    && !control?.policies?.some(
      (policy) => policy.id === state.selectedLifecyclePolicyId && policy.change_mode !== "invalid",
    )
  ) {
    state.selectedLifecyclePolicyId = null;
    state.selectedLifecycleFairness = null;
  }

  const model = schedulerControlModel(
    control,
    state.schedulerControlPending,
    Boolean(state.selectedLifecyclePolicyId),
  );
  const testingLocked = state.testing?.status === "running";
  const locked = model.configLocked || testingLocked;
  elements.schedulerExitDumpEnabled.disabled = locked;
  elements.schedulerVerbose.disabled = locked;
  elements.schedulerExitDumpLen.disabled = locked || !elements.schedulerExitDumpEnabled.checked;
  elements.startScheduler.disabled = model.startDisabled || testingLocked;
  elements.restartScheduler.disabled = model.restartDisabled || testingLocked;
  elements.stopScheduler.disabled = model.stopDisabled || testingLocked;
  renderStatsResetControl();

  elements.schedulerControlState.className = `scheduler-state ${model.stateName}`;
  elements.schedulerControlState.textContent = model.stateLabel;

  const message = schedulerControlMessage(
    control,
    state.schedulerMutationError || state.schedulerControlError,
  );
  if (testingLocked) {
    showElementNotice(
      elements.schedulerControlNotice,
      "Scheduler controls are locked while the VM testing matrix is running.",
      "info",
    );
  } else if (message) {
    showElementNotice(elements.schedulerControlNotice, message);
  } else if (state.policyCandidate?.actionKind === "activate") {
    const policy = control?.policies?.find(
      (candidate) => candidate.id === state.policyCandidate.policyId,
    );
    showElementNotice(
      elements.schedulerControlNotice,
      `${policy?.name || state.policyCandidate.policyId} is selected for live activation. Review the inline action, then choose Apply live.`,
      "info",
    );
  } else if (state.policyCandidate && state.selectedLifecyclePolicyId) {
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
}

function renderStatsResetControl() {
  elements.resetAllStats.disabled = statsResetDisabled(
    state.schedulerControl,
    state.statsResetPending,
  );
}

function hydrateSchedulerLaunchForm(control) {
  const launch = control.launch || {};
  const policyId = control.policy_id || launch.policy_id;
  const validPolicies = (control.policies || []).filter(
    (policy) => policy.change_mode !== "invalid",
  );
  state.selectedLifecyclePolicyId = validPolicies.some((policy) => policy.id === policyId)
    ? policyId
    : validPolicies[0]?.id || null;
  const selectedPolicy = validPolicies.find(
    (policy) => policy.id === state.selectedLifecyclePolicyId,
  );
  const supportedFairness = selectedPolicy?.supported_fairness?.length
    ? selectedPolicy.supported_fairness
    : ["fifo", "vtime", "eevdf"];
  const currentFairness = control.context?.fairness || launch.fairness || "fifo";
  state.selectedLifecycleFairness = supportedFairness.includes(currentFairness)
    ? currentFairness
    : supportedFairness[0] || "fifo";
  const hasExitDump = launch.exit_dump_len != null;
  elements.schedulerExitDumpEnabled.checked = hasExitDump;
  if (hasExitDump) {
    elements.schedulerExitDumpLen.value = String(launch.exit_dump_len);
  }
  elements.schedulerVerbose.checked = Boolean(launch.verbose);
}

function schedulerLifecycleValues() {
  return {
    policy_id: state.selectedLifecyclePolicyId || "",
    fairness: state.selectedLifecycleFairness || "",
    exit_dump_len_enabled: elements.schedulerExitDumpEnabled.checked,
    exit_dump_len: elements.schedulerExitDumpLen.value,
    verbose: elements.schedulerVerbose.checked,
  };
}

function renderSchedulerCommandPreview() {
  try {
    const request = schedulerLifecycleRequest(
      state.schedulerControl,
      schedulerLifecycleValues(),
    );
    elements.schedulerCommandPreview.textContent = schedulerCommandPreview(
      request,
      state.schedulerControl?.launch?.preserved_args || [],
      state.schedulerControl?.current_command || [],
    );
    const current = schedulerCurrentLaunch(state.schedulerControl);
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

async function startScheduler() {
  let request;
  try {
    request = schedulerLifecycleRequest(state.schedulerControl, schedulerLifecycleValues());
  } catch (error) {
    showElementNotice(elements.schedulerControlNotice, error.message);
    return;
  }
  await schedulerMutation("/api/scheduler/start", request);
}

async function restartScheduler() {
  let request;
  try {
    request = schedulerLifecycleRequest(state.schedulerControl, schedulerLifecycleValues());
  } catch (error) {
    showElementNotice(elements.schedulerControlNotice, error.message);
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
  state.schedulerMutationError = null;
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
    state.schedulerControl = body;
    state.schedulerMutationError = null;
    state.lastSchedulerControlAt = Date.now();
    state.selectedLifecyclePolicyId = null;
    state.selectedLifecycleFairness = null;
    state.schedulerFormInitialized = false;
    await loadSchedulerControl();
  } catch (error) {
    state.schedulerMutationError = error.message;
  } finally {
    state.schedulerControlPending = false;
    renderSchedulerControl();
  }
}

async function resetAllStats() {
  if (
    state.statsResetPending
    || !window.confirm("Reset all Snake and inspector statistics? This clears placement, cell, callback, and queue histories and stops active captures.")
  ) {
    return;
  }
  state.statsResetPending = true;
  renderStatsResetControl();
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
    const captureMessage = [
      payload.fine_timing_stopped ? " Fine-grained captures were stopped." : "",
      payload.queue_timing_stopped ? " Queue capture was stopped." : "",
    ].join("");
    showElementNotice(
      elements.statsResetNotice,
      `Reset generation ${numberFormat.format(payload.generation)}, rung set ${numberFormat.format(payload.active_slot)} at ${formatTimestamp(payload.reset_at_ms)}.${captureMessage} Coarse callback sampling remains active, so new samples may appear immediately.`,
      "success",
    );
    state.callbackTimingRequestId += 1;
    state.callbackTimingLoading = false;
    state.callbackTiming = null;
    state.callbackTimingError = null;
    state.lastCallbackTimingAt = 0;
    renderCallbackTiming();
    await Promise.all([
      loadInspection(),
      loadCallbackTiming({ force: true }),
      loadFineTiming(),
      loadQueueTiming(),
    ]);
  } catch (error) {
    showElementNotice(elements.statsResetNotice, error.message);
  } finally {
    state.statsResetPending = false;
    renderStatsResetControl();
  }
}

function renderInspectionViews() {
  if (state.route === "inspect/policy-slots") {
    if (!elements.referencePopover.classList.contains("hidden")) {
      return;
    }
    renderPolicySlots();
  } else if (state.route === "inspect/queue-topology") {
    renderQueueTopologyView();
  } else if (state.route === "inspect/cells") {
    renderCells();
  } else if (state.route === "observe/callbacks") {
    renderCallbackTiming();
  } else if (state.route === "overview") {
    renderOverview();
  } else if (state.route === "debugging/scheduler") {
    renderDebugging();
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
  replaceSortableTableBody(elements.callbackTimingRows, rows.length === 0
    ? '<tr><td class="callback-empty" colspan="6">No callback timing rows available.</td></tr>'
    : rows.map((row) => `
      <tr>
        <th scope="row"><code>${escapeHtml(row.callback)}</code></th>
        <td>${formatCount(row.samples)}</td>
        <td class="${nanosecondDurationClass(row.mean_ns)}">${escapeHtml(formatCallbackDuration(row.mean_ns))}</td>
        <td class="${nanosecondDurationClass(row.p50_ns)}">${escapeHtml(formatCallbackDuration(row.p50_ns))}</td>
        <td class="${nanosecondDurationClass(row.p95_ns)}">${escapeHtml(formatCallbackDuration(row.p95_ns))}</td>
        <td class="${nanosecondDurationClass(row.p99_ns)}">${escapeHtml(formatCallbackDuration(row.p99_ns))}</td>
      </tr>`).join(""));
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
            <table data-sort-key="callbacks:fine:${escapeHtml(capture.callback)}">
              <thead><tr><th data-sort-column="0" data-sort-type="text">Stage</th><th data-sort-column="1" data-sort-type="number">Samples</th><th data-sort-column="2" data-sort-type="duration">Mean (ns)</th><th data-sort-column="3" data-sort-type="duration">p50 approx. (ns)</th><th data-sort-column="4" data-sort-type="duration">p95 approx. (ns)</th><th data-sort-column="5" data-sort-type="duration">p99 approx. (ns)</th></tr></thead>
              <tbody>${stages}</tbody>
            </table>
          </div>
        </section>`;
    })
    .join(""));
}

function fineTimingDurationCell(value) {
  return `<td class="${nanosecondDurationClass(value)}">${escapeHtml(formatCallbackDuration(value))}</td>`;
}

function renderPolicySlots() {
  renderInspectionStatus(elements.policyNotice, elements.policyFreshness);
  state.references.clear();
  state.referenceId = 0;
  if (!state.inspection) {
    elements.slotComparison.replaceChildren();
    return;
  }
  replaceKeyedHtml(
    elements.slotComparison,
    `${renderPolicySlotComparison(state.inspection.slots)}${state.inspection.slots.map(renderSlot).join("")}`,
  );
}

function renderQueueTopologyView() {
  renderInspectionStatus(elements.queueNotice, elements.queueFreshness);
  if (!state.inspection) {
    elements.queueTopology.replaceChildren();
    elements.queueTopology.classList.add("hidden");
    return;
  }
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
        <span>Metrics are excluded because the two rung sets cover different time periods.</span>
      </header>
      <div class="policy-slot-diff-table-wrap">
        <table data-sort-key="policy:slot-comparison">
          <thead><tr><th scope="col" data-sort-column="0" data-sort-type="text">Structure</th><th scope="col" data-sort-column="1" data-sort-type="text">${escapeHtml(comparison.activeLabel)}</th><th scope="col" data-sort-column="2" data-sort-type="text">${escapeHtml(comparison.previousLabel)}</th></tr></thead>
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
  const timing = queueTimingModel(
    state.queueTiming,
    {
      context: state.inspectionContext,
      pending: state.queueTimingPending,
    },
  );
  const model = mergeQueueTimingTopology(
    queueTopologyModel(
      state.inspection.fairness,
      state.inspection.queue_topology,
      state.topology?.numeric_order || [],
    ),
    timing,
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
  const captureHeader = renderQueueCaptureHeader(timing);
  const captureError = state.queueTimingError || timing.error;
  const captureNotice = captureError
    ? `<p class="notice queue-capture-notice">${escapeHtml(captureError)}</p>`
    : timing.state === "historical" && !timing.topologyCompatible
      ? `<p class="notice queue-capture-notice">Historical capture policy generation ${formatNullableCount(timing.capture?.policy_generation)} does not match the current queue topology; DSQ measurements are not joined.</p>`
      : "";
  const dsqActivity = renderDsqActivity(dsqActivityModels(
    fineTimingDsqModels(state.fineTiming),
    timing.dsqs,
  ));
  if (!model.layout) {
    replaceKeyedHtml(elements.queueTopology, `
      <header class="queue-topology-heading">
        <div><h3>Scheduler execution model</h3><p>Fairness and attachment-time queue topology</p></div>
        ${captureHeader}
      </header>
      ${summary}
      ${captureNotice}
      ${dsqActivity}
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
      <td>${escapeHtml(queue.ownerLabel)}${queue.cell_index == null ? "" : ` <small>index ${formatCount(queue.cell_index)}</small>`}</td>
      <td>${queue.llc_id == null ? "All" : formatCount(queue.llc_id)}</td>
      <td><code>${escapeHtml(queue.clockLabel)}</code></td>
      <td class="cpu-mask">${escapeHtml(compactCpuList(queue.consumer_cpus))}</td>
      ${renderQueueTimingCells(queue.timing)}
    </tr>`).join("");
  const routes = model.cpuRoutes.map((route) => `
    <tr>
      <th scope="row">${formatCount(route.cpu)}</th>
      <td>${escapeHtml(route.ownerLabel)}${route.owner_cell_index == null ? "" : ` <small>index ${formatCount(route.owner_cell_index)}</small>`}</td>
      <td>${formatCount(route.llc_id)}</td>
      <td><code>${escapeHtml(route.normalDsq)}</code></td>
      <td><code>${escapeHtml(route.affinityDsq)}</code></td>
      ${renderQueueTimingCells(route.affinityTiming)}
    </tr>`).join("");
  const cellAllocation = model.cells.length === 0 ? "" : `
    <section class="queue-topology-table-section">
      <h4>Cell allocation</h4>
      <div class="queue-topology-table-wrap" data-render-key="queue:${generation}:cell-allocation:scroll">
        <table data-sort-key="queue:cell-allocation"><thead><tr><th data-sort-column="0" data-sort-type="text">Cell</th><th data-sort-column="1" data-sort-type="number">Dense</th><th data-sort-column="2" data-sort-type="number">Weight</th><th data-sort-column="3" data-sort-type="text">Clock</th><th data-sort-column="4" data-sort-type="text">Primary CPUs</th><th data-sort-column="5" data-sort-type="text">Borrowable CPUs</th></tr></thead><tbody>${cells}</tbody></table>
      </div>
    </section>`;
  replaceKeyedHtml(elements.queueTopology, `
    <header class="queue-topology-heading">
      <div><h3>Resolved queue topology</h3><p>Attachment-time CPU ownership, DSQs, and clock domains</p></div>
      ${captureHeader}
    </header>
    ${summary}
    ${captureNotice}
    ${routeWarning}
    ${dsqActivity}
    ${cellAllocation}
    <details class="queue-topology-details" data-render-key="queue:${generation}:normal-dsqs">
      <summary data-render-key="queue:${generation}:normal-dsqs:summary">Normal DSQs (${formatCount(model.normalQueues.length)})</summary>
      <div class="queue-topology-table-wrap" data-render-key="queue:${generation}:normal-dsqs:scroll">
        <table class="queue-timing-table" data-sort-key="queue:normal-dsqs"><thead>
          <tr><th rowspan="2" data-sort-column="0" data-sort-type="bigint">DSQ</th><th rowspan="2" data-sort-column="1" data-sort-type="text">Owner</th><th rowspan="2" data-sort-column="2" data-sort-type="number">LLC</th><th rowspan="2" data-sort-column="3" data-sort-type="text">Clock</th><th rowspan="2" data-sort-column="4" data-sort-type="text">Consumer CPUs</th><th colspan="5">Residence</th><th colspan="3">Operation-sampled depth</th></tr>
          <tr><th data-sort-column="5" data-sort-type="number">Samples</th><th data-sort-column="6" data-sort-type="duration">Mean</th><th data-sort-column="7" data-sort-type="duration">p50</th><th aria-label="Residence p95" data-sort-column="8" data-sort-type="duration">p95</th><th aria-label="Residence p99" data-sort-column="9" data-sort-type="duration">p99</th><th data-sort-column="10" data-sort-type="number">Latest</th><th aria-label="Operation-sampled depth p95" data-sort-column="11" data-sort-type="number">p95</th><th data-sort-column="12" data-sort-type="number">Max</th></tr>
        </thead><tbody>${queues}</tbody></table>
      </div>
    </details>
    <details class="queue-topology-details" data-render-key="queue:${generation}:cpu-routes">
      <summary data-render-key="queue:${generation}:cpu-routes:summary">Per-CPU routing (${formatCount(model.cpuRoutes.length)} of ${formatCount(model.expectedCpuCount)} online CPUs)</summary>
      <div class="queue-topology-table-wrap queue-route-table-wrap" data-render-key="queue:${generation}:cpu-routes:scroll">
        <table class="queue-timing-table" data-sort-key="queue:cpu-routes"><thead>
          <tr><th rowspan="2" data-sort-column="0" data-sort-type="number">CPU</th><th rowspan="2" data-sort-column="1" data-sort-type="text">Owner</th><th rowspan="2" data-sort-column="2" data-sort-type="number">LLC</th><th rowspan="2" data-sort-column="3" data-sort-type="bigint">Normal DSQ</th><th rowspan="2" data-sort-column="4" data-sort-type="bigint">Affinity DSQ</th><th colspan="5">Affinity residence</th><th colspan="3">Operation-sampled depth</th></tr>
          <tr><th data-sort-column="5" data-sort-type="number">Samples</th><th data-sort-column="6" data-sort-type="duration">Mean</th><th data-sort-column="7" data-sort-type="duration">p50</th><th aria-label="Residence p95" data-sort-column="8" data-sort-type="duration">p95</th><th aria-label="Residence p99" data-sort-column="9" data-sort-type="duration">p99</th><th data-sort-column="10" data-sort-type="number">Latest</th><th aria-label="Operation-sampled depth p95" data-sort-column="11" data-sort-type="number">p95</th><th data-sort-column="12" data-sort-type="number">Max</th></tr>
        </thead><tbody>${routes}</tbody></table>
      </div>
    </details>`);
}

function renderDsqActivity(dsqs) {
  const rows = dsqs.map((dsq) => `
    <tr>
      <th scope="row"><code>${escapeHtml(dsq.label)}</code></th>
      <td>${escapeHtml(dsq.kind)}</td>
      <td>${dsq.queueClass === "unknown" ? "—" : escapeHtml(dsq.queueClass)}</td>
      ${renderDsqOperationTimingCells(dsq.insertSuccess, dsq.hasOperations)}
      <td>${dsq.hasOperations ? formatCount(dsq.insertError.samples) : "—"}</td>
      ${renderDsqOperationTimingCells(dsq.moveSuccess, dsq.hasOperations)}
      ${renderDsqOperationTimingCells(dsq.moveMiss, dsq.hasOperations)}
      ${renderQueueTimingCells(dsq, dsq.hasQueueTiming)}
    </tr>`).join("");
  const body = rows || '<tr><td colspan="21" class="callback-empty">No sampled DSQ activity.</td></tr>';
  return `
    <details class="queue-topology-details" open data-render-key="queue:dsq-activity">
      <summary data-render-key="queue:dsq-activity:summary">DSQ activity (${formatCount(dsqs.length)})</summary>
      <div class="queue-topology-table-wrap" data-render-key="queue:dsq-activity:scroll">
        <table class="queue-timing-table" data-sort-key="queue:dsq-activity"><thead>
          <tr><th rowspan="2" data-sort-column="0" data-sort-type="bigint">DSQ</th><th rowspan="2" data-sort-column="1" data-sort-type="text">Kind</th><th rowspan="2" data-sort-column="2" data-sort-type="text">Class</th><th colspan="3">Insert success</th><th rowspan="2" data-sort-column="6" data-sort-type="number">Insert errors</th><th colspan="3">Remove success</th><th colspan="3">Remove miss</th><th colspan="5">Residence</th><th colspan="3">Operation-sampled depth</th></tr>
          <tr><th data-sort-column="3" data-sort-type="number">Samples</th><th data-sort-column="4" data-sort-type="duration">Mean</th><th data-sort-column="5" data-sort-type="duration">p99</th><th data-sort-column="7" data-sort-type="number">Samples</th><th data-sort-column="8" data-sort-type="duration">Mean</th><th data-sort-column="9" data-sort-type="duration">p99</th><th data-sort-column="10" data-sort-type="number">Samples</th><th data-sort-column="11" data-sort-type="duration">Mean</th><th data-sort-column="12" data-sort-type="duration">p99</th><th data-sort-column="13" data-sort-type="number">Samples</th><th data-sort-column="14" data-sort-type="duration">Mean</th><th data-sort-column="15" data-sort-type="duration">p50</th><th aria-label="Residence p95" data-sort-column="16" data-sort-type="duration">p95</th><th aria-label="Residence p99" data-sort-column="17" data-sort-type="duration">p99</th><th data-sort-column="18" data-sort-type="number">Latest</th><th aria-label="Operation-sampled depth p95" data-sort-column="19" data-sort-type="number">p95</th><th data-sort-column="20" data-sort-type="number">Max</th></tr>
        </thead><tbody>${body}</tbody></table>
      </div>
    </details>`;
}

function renderDsqOperationTimingCells(timing, available = true) {
  if (!available) {
    return "<td>—</td><td>—</td><td>—</td>";
  }
  return `
    <td>${formatCount(timing.samples)}</td>
    <td class="${nanosecondDurationClass(timing.meanNs)}">${escapeHtml(formatCallbackDuration(timing.meanNs))}</td>
    <td class="${nanosecondDurationClass(timing.p99Ns)}">${escapeHtml(formatCallbackDuration(timing.p99Ns))}</td>`;
}

function renderQueueCaptureHeader(timing) {
  const showCaptureState = timing.status === "ready"
    || (timing.status === "disabled" && timing.state === "historical");
  const stateClass = showCaptureState ? timing.state : timing.status;
  const statusLabel = showCaptureState ? timing.stateLabel : timing.statusLabel;
  const capture = timing.capture;
  const session = capture?.session_id == null
    ? "No capture session"
    : `Session ${formatCount(capture.session_id)} · policy generation ${formatCount(capture.policy_generation)} · started ${formatTimestamp(capture.started_at_ms)} · ${capture.stopped_at_ms ? `stopped ${formatTimestamp(capture.stopped_at_ms)}` : timing.state === "collecting" ? "collecting now" : "stop time unavailable"}`;
  const reason = timing.controlDisabled
    ? timing.status === "ready" && timing.sampleRate === 0
      ? "Enable callback sampling to collect queue timing."
      : timing.statusLabel
    : "Sample queue residence and operation-point depth.";
  return `
    <div class="queue-capture-control">
      <div class="queue-capture-state">
        <span class="fine-timing-state ${escapeHtml(stateClass)}">${escapeHtml(statusLabel)}</span>
        <span>${escapeHtml(timing.sampleRateLabel)}</span>
      </div>
      <label class="fine-timing-toggle" title="${escapeHtml(reason)}">
        <input type="checkbox" data-queue-capture
          ${timing.checked ? "checked" : ""}
          ${timing.controlDisabled ? "disabled" : ""}>
        <span>Queue capture</span>
      </label>
      <small>${escapeHtml(session)} · ${formatCount(timing.counts.started)} started · ${formatCount(timing.counts.completed)} completed · ${formatCount(timing.counts.dropped)} dropped</small>
    </div>`;
}

function renderQueueTimingCells(timing, available = true) {
  if (!available) {
    return "<td>—</td><td>—</td><td>—</td><td>—</td><td>—</td><td>—</td><td>—</td><td>—</td>";
  }
  return `
    <td>${formatCount(timing.residence.samples)}</td>
    <td class="${nanosecondDurationClass(timing.residence.meanNs)}">${escapeHtml(formatCallbackDuration(timing.residence.meanNs))}</td>
    <td class="${nanosecondDurationClass(timing.residence.p50Ns)}">${escapeHtml(formatCallbackDuration(timing.residence.p50Ns))}</td>
    <td class="${nanosecondDurationClass(timing.residence.p95Ns)}">${escapeHtml(formatCallbackDuration(timing.residence.p95Ns))}</td>
    <td class="${nanosecondDurationClass(timing.residence.p99Ns)}">${escapeHtml(formatCallbackDuration(timing.residence.p99Ns))}</td>
    <td>${formatNullableCount(timing.depth.latest)}</td>
    <td>${formatNullableCount(timing.depth.p95)}</td>
    <td>${formatNullableCount(timing.depth.max)}</td>`;
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
      : `Rung set ${slot.slot}`;
  if (!slot.policy) {
    return `
      <section class="slot-panel empty-slot" aria-label="Ladder rung set ${slot.slot}, empty"
        data-feedback-key="Policy:Rung-set-${slot.slot}">
        <header class="slot-heading">
          <h3>${roleHeading}</h3>
          <p>Rung set ${slot.slot}</p>
          <span class="slot-state empty">${stateLabel}</span>
        </header>
        <p>No ladder is installed in this rung set.</p>
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
  const queueLadders = renderQueuePolicy(slot.policy.queues, metrics);
  const maskTables = slot.policy.mask_tables.length > 0
    ? slot.policy.mask_tables.map((table) => `
        <li><code>${escapeHtml(String(table.id))}</code> ${escapeHtml(table.name)}
          <span>${escapeHtml(table.source)} · ${numberFormat.format(table.entry_count)} entries</span>
        </li>`).join("")
    : "<li>None</li>";
  return `
    <section class="slot-panel" aria-label="Ladder rung set ${slot.slot}, ${stateLabel}"
      data-feedback-key="Policy:Rung-set-${slot.slot}">
      <header class="slot-heading">
        <div>
          <h3>${roleHeading}</h3>
          <p>Rung set ${slot.slot} · Generation ${numberFormat.format(slot.generation)} · ${metricKind}</p>
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

function renderQueuePolicy(queues, callbackMetrics) {
  if (!queues) {
    return `
      <section class="queue-policy-empty">
        <strong>Queue callback ladders</strong>
        <span>Not configured for this policy</span>
      </section>`;
  }
  const sections = queueLadderSections(queues, callbackMetrics)
    .map(renderQueueLadder)
    .join("");
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
          ${renderQueueRungMetrics(rung, section.callbackCalls)}
          ${renderRungTiming(rung.timing)}
        </header>
        ${renderQueueRungOutcomes(rung, section.callbackCalls)}
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

function renderQueueRungMetrics(rung, callbackCalls) {
  const metrics = rung.metrics || {};
  const percentages = rungPercentages(metrics);
  const callbackRates = queueRungCallbackPercentages(metrics, callbackCalls);
  return `
    <dl class="rung-metrics queue-rung-metrics">
      <div><dt>Attempts</dt><dd>${formatCount(metrics.attempts)}</dd></div>
      <div><dt>Hits</dt><dd>${formatCount(metrics.hits)}<small>${formatPercentage(percentages.hit)} of rung attempts</small><small>${formatPercentage(callbackRates.hit)} of callback calls</small></dd></div>
      <div><dt>Misses</dt><dd>${formatCount(metrics.misses)}<small>${formatPercentage(percentages.miss)} of rung attempts</small><small>${formatPercentage(callbackRates.miss)} of callback calls</small></dd></div>
      <div><dt>Errors</dt><dd>${formatCount(metrics.errors)}</dd></div>
    </dl>`;
}

function renderQueueRungOutcomes(rung, callbackCalls) {
  const labels = {
    selected: "Selected",
    move_misses: "Move misses",
    fallback_attempts: "Fallback attempts",
    fallback_hits: "Fallback hits",
    fallback_misses: "Fallback misses",
  };
  const metrics = rung.metrics || {};
  const outcomes = (rung.metricKeys || []).map((metric) => {
    const percentages = queueRungMetricPercentages(metrics, metric, callbackCalls);
    return `
      <div>
        <dt>${labels[metric]}</dt>
        <dd>${formatCount(metrics[metric])}<small>${formatPercentage(percentages.rung)} of rung attempts</small><small>${formatPercentage(percentages.callback)} of callback calls</small></dd>
      </div>`;
  }).join("");
  return outcomes ? `<dl class="queue-rung-outcomes">${outcomes}</dl>` : "";
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
      aria-pressed="${option.id === selectedFairness}"
      data-render-key="policy-fairness:${escapeHtml(option.id)}"
      data-policy-fairness="${escapeHtml(option.id)}">
      <strong>${escapeHtml(option.label)}</strong>
      <span>${numberFormat.format(option.policies.length)} policies${option.active ? " · active" : ""}</span>
    </button>`).join("");
  const policySections = policyCategoryGroups(policies).map((group) => {
    const activePolicyId = group.policies.find((policy) => policy.active)?.id || "inactive";
    const policyCards = group.policies.length === 0
      ? '<p class="empty-state">No policies in this group.</p>'
      : group.policies.map((policy) => {
        const selected = state.policyCandidate?.policyId === policy.id
          && state.policyCandidate?.fairness === selectedFairness;
        const inlineAction = policyInlineActionModel(
          policy,
          state.policyCandidate,
          state.policyActivationPending,
          state.schedulerControl,
        );
        const inlineActionId = `policy-live-action-${policy.id}-${selectedFairness}`;
        const appliesLiveClass = policy.changeMode === "dynamic" && !policy.active
          ? " applies-live"
          : "";
        const changeStatus = policy.reasons.length > 0
          ? `<details class="policy-reason-details" data-render-key="policy-choice:${escapeHtml(selectedFairness)}:${escapeHtml(policy.id)}:reasons">
              <summary class="change-mode ${policy.changeMode}${appliesLiveClass}" data-render-key="policy-choice:${escapeHtml(selectedFairness)}:${escapeHtml(policy.id)}:reasons:summary">${escapeHtml(policy.changeLabel)}</summary>
              <ul class="policy-reason-list">
                ${policy.reasons.map((reason) => `<li><strong>${escapeHtml(reason.label)}</strong><span>${escapeHtml(reason.detail)}</span></li>`).join("")}
              </ul>
            </details>`
          : `<span class="change-mode ${policy.changeMode}${appliesLiveClass}">${escapeHtml(policy.changeLabel)}</span>`;
        return `
      <article class="policy-choice${policy.active ? " active" : ""}${selected ? " selected" : ""}${inlineAction.expanded ? " has-inline-action" : ""}${policy.changeMode === "invalid" ? " invalid" : ""}">
        <div class="policy-choice-copy">
          <h4>${escapeHtml(policy.name)}</h4>
          <p><code>${escapeHtml(policy.id)}</code>${policy.summary ? ` · ${escapeHtml(policy.summary)}` : ""}</p>
        </div>
        <div class="policy-choice-actions">
          ${changeStatus}
          <span class="policy-action-intent">${escapeHtml(policy.actionLabel)}</span>
          <button class="secondary-button policy-select-button" type="button"
            data-policy-id="${escapeHtml(policy.id)}"
            data-policy-fairness="${escapeHtml(selectedFairness)}"
            data-render-key="policy-choice:${escapeHtml(selectedFairness)}:${escapeHtml(policy.id)}:select"
            data-policy-action="${escapeHtml(policy.actionKind)}" aria-pressed="${selected}"
            aria-expanded="${inlineAction.expanded}"${inlineAction.expanded ? ` aria-controls="${escapeHtml(inlineActionId)}"` : ""}${policy.changeMode === "invalid" ? " disabled" : ""}>
            ${inlineAction.expanded ? "Close" : selected ? "Selected" : "Review"}
          </button>
        </div>
        ${inlineAction.expanded ? `
          <section class="policy-live-action-panel" id="${escapeHtml(inlineActionId)}" aria-label="Apply ${escapeHtml(policy.name)}">
            ${inlineAction.liveVisible ? `
              <div class="policy-review-action-row">
                <div>
                  <strong>Apply without restarting Snake</strong>
                  <span>Install this policy as the next generation while the scheduler keeps running.</span>
                </div>
                <button class="apply-button" type="button"
                  data-policy-live-apply="${escapeHtml(policy.id)}"
                  ${inlineAction.liveDisabled ? "disabled" : ""}>${escapeHtml(inlineAction.liveLabel)}</button>
              </div>` : ""}
            ${inlineAction.lifecycleVisible ? `
              <div class="policy-review-action-row">
                <div>
                  <strong>Apply with scheduler restart</strong>
                  <span>Start a new Snake attachment using the command shown in Next start or restart.</span>
                </div>
                <button class="apply-button" type="button"
                  data-policy-restart-apply="${escapeHtml(policy.id)}"
                  data-policy-fairness="${escapeHtml(selectedFairness)}"
                  ${inlineAction.lifecycleDisabled ? "disabled" : ""}>${escapeHtml(inlineAction.lifecycleLabel)}</button>
              </div>` : ""}
          </section>` : ""}
      </article>`;
      }).join("");
    return `
      <details class="policy-category-section"${group.defaultOpen ? " open" : ""}
        data-policy-category="${group.id}"
        data-render-key="policy-category:${escapeHtml(group.id)}:${escapeHtml(activePolicyId)}">
        <summary data-render-key="policy-category:${escapeHtml(group.id)}:${escapeHtml(activePolicyId)}:summary"><h5>${escapeHtml(group.label)}</h5><span>${formatCount(group.policies.length)}</span></summary>
        <div class="policy-choice-list">${policyCards}</div>
      </details>`;
  }).join("");
  replaceKeyedHtml(elements.policyChoices, `
    <div class="policy-fairness-options" role="group" aria-label="Fairness approach">
      ${fairnessOptions}
    </div>
    <section class="policy-fairness-branch">
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
    return;
  }
  elements.policyCandidateContext.textContent = `${candidate.name} · ${candidate.selectedFairness.toUpperCase()}`;
  const reasonLabels = candidate.reasons.map((reason) => reason.label);
  elements.policyCandidateImpact.textContent = reasonLabels.length > 0
    ? `${candidate.changeLabel}: ${reasonLabels.join(", ")}`
    : candidate.changeLabel;
  state.policyCandidate.actionKind = candidate.actionKind;
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
          ${renderRungTiming(rung.timing)}
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

function renderRungTiming(rawTiming) {
  const timing = rungTimingSummary(rawTiming);
  const value = timing.p95Ns == null
    ? "—"
    : formatCallbackDuration(timing.p95Ns);
  return `
    <dl class="rung-timing">
      <div><dt>Sampled p95</dt><dd class="${nanosecondDurationClass(timing.p95Ns)}">${escapeHtml(value)}<small>${formatCount(timing.samples)} samples</small></dd></div>
    </dl>`;
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
  if (state.route === "inspect/policy-slots" && state.inspection) {
    window.requestAnimationFrame(() => {
      if (
        state.route === "inspect/policy-slots"
        && state.inspection
        && elements.referencePopover.classList.contains("hidden")
      ) {
        renderPolicySlots();
      }
    });
  }
}

function handleTableSortClick(event) {
  const button = event.target.closest("[data-table-sort]");
  if (!button) {
    return;
  }
  const table = button.closest("table[data-sort-key]");
  const header = button.closest("th[data-sort-column]");
  if (!table || !header) {
    return;
  }
  event.preventDefault();
  const key = table.dataset.sortKey;
  const next = nextTableSortState(
    tableSortStates.get(key),
    Number(header.dataset.sortColumn),
  );
  tableSortStates.set(key, next);
  applyTableSort(table, next);
}

function enhanceSortableTables(root) {
  const tables = [
    ...(root.matches?.("table[data-sort-key]") ? [root] : []),
    ...root.querySelectorAll("table[data-sort-key]"),
  ];
  for (const table of tables) {
    enhanceSortableTable(table);
  }
}

function enhanceSortableTable(table) {
  const key = table.dataset.sortKey;
  for (const header of table.querySelectorAll("thead th[data-sort-column]")) {
    header.setAttribute("scope", "col");
    let button = header.querySelector(":scope > [data-table-sort]");
    if (!button) {
      const label = header.getAttribute("aria-label") || header.textContent.trim();
      header.dataset.sortLabel = label;
      button = document.createElement("button");
      button.type = "button";
      button.className = "table-sort-button";
      button.dataset.tableSort = header.dataset.sortColumn;
      button.dataset.renderKey = `table-sort:${key}:${header.dataset.sortColumn}`;
      const visibleLabel = document.createElement("span");
      visibleLabel.className = "table-sort-label";
      while (header.firstChild) {
        visibleLabel.append(header.firstChild);
      }
      const indicator = document.createElement("span");
      indicator.className = "table-sort-indicator";
      indicator.dataset.tableSortIndicator = "";
      indicator.setAttribute("aria-hidden", "true");
      button.append(visibleLabel, indicator);
      header.append(button);
    }
  }
  applyTableSort(table, tableSortStates.get(key));
}

function applyTableSort(table, sortState) {
  for (const header of table.querySelectorAll("thead th[data-sort-column]")) {
    const column = Number(header.dataset.sortColumn);
    const active = sortState?.column === column;
    const direction = active ? sortState.direction : null;
    if (direction) {
      header.setAttribute("aria-sort", direction);
    } else {
      header.removeAttribute("aria-sort");
    }
    const button = header.querySelector(":scope > [data-table-sort]");
    if (!button) {
      continue;
    }
    const label = header.dataset.sortLabel || header.textContent.trim();
    const nextDirection = direction === "ascending" ? "descending" : "ascending";
    const status = direction
      ? `Sorted ${direction}. Activate to sort ${nextDirection}.`
      : "Not sorted. Activate to sort ascending.";
    button.setAttribute("aria-label", `${label}. ${status}`);
    button.title = direction
      ? `Sort ${label} ${nextDirection}`
      : `Sort ${label} ascending`;
    const indicator = button.querySelector("[data-table-sort-indicator]");
    if (indicator) {
      indicator.textContent = direction === "ascending"
        ? "\u2191"
        : direction === "descending"
          ? "\u2193"
          : "\u2195";
    }
  }
  if (!sortState) {
    return;
  }
  const header = table.querySelector(
    `thead th[data-sort-column="${sortState.column}"]`,
  );
  const type = header?.dataset.sortType || "auto";
  for (const body of table.tBodies) {
    const sortableRows = [];
    const fixedRows = [];
    for (const [index, row] of [...body.rows].entries()) {
      const cell = row.cells[sortState.column];
      if (!cell || (row.cells.length === 1 && row.cells[0].colSpan > 1)) {
        fixedRows.push(row);
        continue;
      }
      if (!row.dataset.sortSourceOrder) {
        row.dataset.sortSourceOrder = String(index);
      }
      sortableRows.push({
        row,
        sourceOrder: Number(row.dataset.sortSourceOrder),
        value: cell.dataset.sortValue ?? cell.textContent,
      });
    }
    const fragment = document.createDocumentFragment();
    for (const entry of stableSortTableRows(sortableRows, {
      type,
      direction: sortState.direction,
    })) {
      fragment.append(entry.row);
    }
    for (const row of fixedRows) {
      fragment.append(row);
    }
    body.append(fragment);
  }
}

function replaceSortableTableBody(body, html) {
  body.innerHTML = html;
  enhanceSortableTable(body.closest("table[data-sort-key]"));
}

function replaceKeyedHtml(container, html) {
  const snapshot = captureKeyedRenderState(
    container.querySelectorAll("[data-render-key]"),
    document.activeElement,
    window,
  );
  container.innerHTML = html;
  decorateFeedbackTargets(container);
  enhanceSortableTables(container);
  restoreKeyedRenderState(
    container.querySelectorAll("[data-render-key]"),
    snapshot,
    window,
  );
}

function renderCells() {
  renderInspectionStatus(elements.cellsNotice, elements.cellsFreshness);
  renderWorkloadCellOptions();
  const statsModel = cellStatsModel(state.snapshot?.cell_stats, {
    policyGeneration: state.inspectionContext?.policy_generation,
  });
  renderCellStatsStatus(statsModel);
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
  const statsByCell = new Map(
    statsModel.status === "ready"
      ? statsModel.cells.map((cell) => [cell.id, cell])
      : [],
  );
  const cells = decorateCells(definitions, state.inspection.task_mappings)
    .map((cell) => ({ ...cell, stats: statsByCell.get(cell.id) || null }))
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
    renderCellDetail(selected, cellQueueFacts(topology, selected.id), statsModel),
  );
}

function renderCellStatsStatus(model) {
  let message = model.error;
  if (!message && model.status !== "ready") {
    message = model.statusLabel;
  } else if (!message && model.zeroActivity) {
    message = "No cell activity was observed in the selected window.";
  } else if (!message && model.cells.length === 0) {
    message = "No cell statistics rows are available for the selected window.";
  }
  if (message) {
    showElementNotice(
      elements.cellStatsNotice,
      message,
      model.status === "unavailable" ? "warning" : "info",
    );
  } else {
    hideElementNotice(elements.cellStatsNotice);
  }
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
  const stats = cell.stats;
  const affinity = stats
    ? `${formatCellMetric(stats.affinityEnqueuePct, "percentage")} enq · ${formatCellMetric(stats.affinityDispatchPct, "percentage")} dispatch`
    : "—";
  return `
    <button class="cell-row${selected ? " selected" : ""}" type="button"
      data-cell-id="${cell.id}" aria-pressed="${selected}">
      <span class="cell-identity"><strong>Cell ${cell.id}</strong><small>${definition}</small></span>
      ${renderCpuStrip(cell)}
      <span class="cell-row-stats">
        <span><small>Service</small><strong>${formatCellMetric(stats?.serviceCores, "cores")} cores · ${formatCellMetric(stats?.serviceSharePct, "percentage")}</strong></span>
        <span><small>Borrowed</small><strong>${formatCellMetric(stats?.borrowedPct, "percentage")}</strong></span>
        <span><small>Lent runtime</small><strong>${formatCellMetric(stats?.raw.lent_runtime_ns, "duration")}</strong></span>
        <span><small>Affinity path</small><strong>${affinity}</strong></span>
      </span>
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

function renderCellDetail(cell, queueFacts, statsModel) {
  const cpuList = cell.cpus.length > 0
    ? compactCpuList(cell.cpus)
    : "No active CPU definition";
  const overlap = cell.overlapIds.length > 0
    ? cell.overlapIds.map((id) => `Cell ${id}`).join(", ")
    : "None";
  const tasks = cell.tasks.length > 0
    ? cell.tasks.map((task) => renderTaskMapping(task, cell.id)).join("")
    : '<p class="empty-state">No live task mappings for this cell.</p>';
  const stats = cell.stats;
  const coverage = statsModel.status !== "ready"
    ? statsModel.statusLabel
    : statsModel.observedMs == null || statsModel.windowMs == null
    ? statsModel.statusLabel
    : `${formatDuration(statsModel.observedMs)} observed of ${formatDuration(statsModel.windowMs)}`;
  return `
    <header class="cell-detail-heading">
      <div><h3>Cell ${cell.id}</h3><p>${numberFormat.format(cell.tasks.length)} mapped tasks · ${escapeHtml(coverage)}</p></div>
      ${cell.undefined ? '<span class="slot-state warning">Undefined</span>' : ""}
    </header>
    <dl class="cell-facts cell-identity-facts">
      <div><dt>Policy CPUs</dt><dd>${escapeHtml(cpuList)}</dd></div>
      <div><dt>Overlapping cells</dt><dd>${escapeHtml(overlap)}</dd></div>
      <div><dt>Primary CPUs</dt><dd>${escapeHtml(queueFacts.configured ? compactCpuList(queueFacts.primaryCpus) : "Not configured")}</dd></div>
      <div><dt>Borrowable CPUs</dt><dd>${escapeHtml(queueFacts.configured ? compactCpuList(queueFacts.borrowableCpus) : "Not configured")}</dd></div>
      <div><dt>VTIME clock</dt><dd><code>${escapeHtml(queueFacts.clock)}</code></dd></div>
      <div><dt>Normal DSQs</dt><dd>${escapeHtml(queueFacts.configured ? queueFacts.normalDsqs.join(", ") || "None" : "Not configured")}</dd></div>
      <div><dt>CPU weight</dt><dd>${queueFacts.weight == null ? "—" : formatCount(queueFacts.weight)}</dd></div>
    </dl>
    <section class="cell-stat-groups" aria-label="Cell window statistics">
      <div class="cell-stat-group">
        <h4>Service</h4>
        <dl class="cell-facts">
          <div><dt>Service cores</dt><dd>${formatCellMetric(stats?.serviceCores, "cores")}</dd></div>
          <div><dt>Service share</dt><dd>${formatCellMetric(stats?.serviceSharePct, "percentage")}</dd></div>
        </dl>
      </div>
      <div class="cell-stat-group">
        <h4>Placement</h4>
        <dl class="cell-facts">
          <div><dt>Primary runtime</dt><dd>${formatCellMetric(stats?.primaryPct, "percentage")}</dd></div>
          <div><dt>Owned utilization</dt><dd>${formatCellMetric(stats?.ownedUtilizationPct, "percentage")}</dd></div>
        </dl>
      </div>
      <div class="cell-stat-group">
        <h4>Capacity exchange</h4>
        <dl class="cell-facts">
          <div><dt>Borrowed share</dt><dd>${formatCellMetric(stats?.borrowedPct, "percentage")}</dd></div>
          <div><dt>Lent runtime</dt><dd>${formatCellMetric(stats?.raw.lent_runtime_ns, "duration")}</dd></div>
        </dl>
      </div>
      <div class="cell-stat-group wide">
        <h4>Queue paths</h4>
        <dl class="cell-facts">
          <div><dt>Normal enqueue</dt><dd>${formatCellMetric(stats?.normalEnqueueRate, "rate")}</dd></div>
          <div><dt>Affinity enqueue</dt><dd>${formatCellMetric(stats?.affinityEnqueueRate, "rate")} · ${formatCellMetric(stats?.affinityEnqueuePct, "percentage")}</dd></div>
          <div><dt>Normal dispatch</dt><dd>${formatCellMetric(stats?.normalDispatchRate, "rate")}</dd></div>
          <div><dt>Affinity dispatch</dt><dd>${formatCellMetric(stats?.affinityDispatchRate, "rate")} · ${formatCellMetric(stats?.affinityDispatchPct, "percentage")}</dd></div>
        </dl>
      </div>
      <div class="cell-stat-group wide">
        <h4>Clock transitions</h4>
        <dl class="cell-facts">
          <div><dt>Transition rate</dt><dd>${formatCellMetric(stats?.clockTransitionRate, "rate")}</dd></div>
          <div><dt>Per 1k dispatches</dt><dd>${formatCellMetric(stats?.transitionsPer1kDispatches)}</dd></div>
        </dl>
      </div>
    </section>
    ${renderRawCellStats(stats, cell.id)}
    <div class="task-mappings">${tasks}</div>`;
}

function renderRawCellStats(stats, cellId) {
  const rows = [
    ["runtime_ns", "Runtime", "duration"],
    ["primary_runtime_ns", "Primary runtime", "duration"],
    ["borrowed_runtime_ns", "Borrowed runtime", "duration"],
    ["lent_runtime_ns", "Lent runtime", "duration"],
    ["normal_enqueues", "Normal enqueues", "number"],
    ["affinity_enqueues", "Affinity enqueues", "number"],
    ["normal_dispatches", "Normal dispatches", "number"],
    ["affinity_dispatches", "Affinity dispatches", "number"],
    ["clock_transitions", "Clock transitions", "number"],
  ];
  return `
    <details class="cell-raw-stats" data-render-key="cell:${cellId}:raw-stats">
      <summary data-render-key="cell:${cellId}:raw-stats:summary">Raw window counters</summary>
      <div class="cell-raw-table-wrap">
        <table data-sort-key="cell:${cellId}:raw-stats"><thead><tr><th data-sort-column="0" data-sort-type="text">Counter</th><th data-sort-column="1" data-sort-type="auto">Value</th></tr></thead><tbody>
          ${rows.map(([field, label, kind]) => `
            <tr><th scope="row"><code>${field}</code><small>${label}</small></th><td>${formatCellMetric(stats?.raw[field], kind)}</td></tr>`).join("")}
        </tbody></table>
      </div>
    </details>`;
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

function formatNullableCount(value) {
  return value == null || !Number.isFinite(Number(value))
    ? "—"
    : numberFormat.format(Number(value));
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
  renderSchedulerUptime();
}

function renderSchedulerUptime() {
  const control = state.schedulerControl;
  elements.schedulerUptime.textContent = schedulerUptimeLabel(
    control,
    state.lastSchedulerControlAt,
    Date.now(),
    state.schedulerControlError,
  );
  const label = elements.schedulerUptime.textContent;
  const stale = label.startsWith("Stale");
  elements.schedulerUptimeStatus.classList.toggle("active", Boolean(control?.active) && !stale);
  elements.schedulerUptimeStatus.classList.toggle("stopped", Boolean(control && !control.active));
  elements.schedulerUptimeStatus.classList.toggle("stale", stale);
  elements.schedulerUptimeStatus.classList.toggle(
    "unavailable",
    label === "Unavailable",
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
