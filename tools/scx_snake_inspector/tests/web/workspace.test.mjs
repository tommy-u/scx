// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const page = readFileSync(
  new URL("../../src/web/index.html", import.meta.url),
  "utf8",
);
const script = readFileSync(
  new URL("../../src/web/app.js", import.meta.url),
  "utf8",
);

test("workspace reorganization preserves every existing inspector surface", () => {
  for (const id of [
    "activityView",
    "callbacksView",
    "policyView",
    "cellsView",
    "controlView",
    "policyChoices",
    "slotComparison",
    "queueTopology",
    "schedulerCurrentCommand",
    "schedulerCommandPreview",
    "schedulerSettingsRows",
    "feedbackTranscript",
  ]) {
    assert.match(page, new RegExp(`id="${id}"`), `missing #${id}`);
  }
});

test("workspace reorganization preserves control and feedback behavior", () => {
  for (const behavior of [
    "runPolicyCandidate",
    "activateSelectedPolicy",
    "startScheduler",
    "restartScheduler",
    "stopScheduler",
    "resetAllStats",
    "copyFeedback",
    "clearFeedback",
    "toggleFeedbackComposer",
  ]) {
    assert.match(script, new RegExp(`function ${behavior}\\(`), `missing ${behavior}`);
  }
});
