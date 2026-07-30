// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  parseInspectorRoute,
  testingMatrixModel,
} from "../../src/web/inspection.js";

const page = readFileSync(
  new URL("../../src/web/index.html", import.meta.url),
  "utf8",
);
const script = readFileSync(
  new URL("../../src/web/app.js", import.meta.url),
  "utf8",
);
const styles = readFileSync(
  new URL("../../src/web/style.css", import.meta.url),
  "utf8",
);

test("testing is a canonical inspector workspace", () => {
  assert.deepEqual(parseInspectorRoute("#/validate/testing"), {
    route: "validate/testing",
    feedbackOpen: false,
  });
  assert.match(page, /data-route="validate\/testing"[^>]*>Testing</);
  assert.match(page, /id="testingView"[^>]+data-view="validate\/testing"/);
  for (const id of [
    "testingStatus",
    "testingMatrix",
    "testingDetail",
    "runTesting",
    "stopTesting",
  ]) {
    assert.match(page, new RegExp(`id="${id}"`));
  }
});

test("testing model keeps fairness as the major row and workloads as columns", () => {
  const model = testingMatrixModel({
    status: "running",
    shard_environments: [{
      shard_index: 0,
      environment: {
        virtualization: "kvm",
        cpu_count: 8,
        memory_bytes: 4 * (1024 ** 3),
        kernel_release: "6.18.0-test",
        snake_version: "scx_snake 1.1.1",
        boot_command: "vng --run --cpus 8 --memory 4G",
      },
    }],
    matrix: {
      duration_secs: 60,
      shard_index: 0,
      shard_count: 8,
      total_cases: 8,
      assigned_cases: 4,
      workloads: ["cpu_saturation", "waker_wakee"],
      groups: [
        {
          fairness: "fifo",
          rows: [
            {
              policy_id: "basic.toml",
              policy_name: "basic",
              cases: [
                {
                  id: "fifo/basic.toml/cpu_saturation",
                  workload: "cpu_saturation",
                  assigned: true,
                  status: "passed",
                  elapsed_ms: 60_125,
                  failure: null,
                },
                {
                  id: "fifo/basic.toml/waker_wakee",
                  workload: "waker_wakee",
                  assigned: true,
                  status: "failed",
                  elapsed_ms: 31_000,
                  failure: "kernel failure: runnable task stall pid=42",
                },
              ],
            },
          ],
        },
      ],
    },
  });

  assert.equal(model.statusLabel, "Running");
  assert.deepEqual(model.workloads.map((workload) => workload.label), [
    "CPU saturation",
    "Waker / wakee",
  ]);
  assert.equal(model.groups[0].label, "FIFO");
  assert.equal(model.groups[0].rows[0].policyName, "basic");
  assert.equal(model.groups[0].rows[0].cases[0].symbol, "✓");
  assert.equal(model.groups[0].rows[0].cases[0].label, "Passed");
  assert.match(model.groups[0].rows[0].cases[0].tooltip, /Runtime: 60\.1s/);
  assert.match(model.groups[0].rows[0].cases[0].tooltip, /VM: kvm · 8 vCPUs · 4\.0 GiB RAM/);
  assert.match(model.groups[0].rows[0].cases[0].tooltip, /Kernel: 6\.18\.0-test/);
  assert.match(model.groups[0].rows[0].cases[0].tooltip, /Boot: vng --run --cpus 8/);
  assert.equal(model.groups[0].rows[0].cases[1].symbol, "×");
  assert.match(model.groups[0].rows[0].cases[1].failure, /runnable task stall/);
  assert.deepEqual(model.summary, {
    passed: 1,
    failed: 1,
    running: 0,
    pending: 0,
  });
});

test("testing UI loads live results and exposes authenticated controls", () => {
  assert.match(script, /fetch\("\/api\/testing\/matrix"/);
  assert.match(script, /testingMutation\("\/api\/testing\/run"/);
  assert.match(script, /testingMutation\("\/api\/testing\/stop"/);
  assert.match(script, /title="\$\{escapeHtml\(testCase\.tooltip\)\}"/);
  assert.match(styles, /\.testing-matrix/);
  assert.match(styles, /\.testing-result\.passed/);
  assert.match(styles, /\.testing-result\.failed/);
});

test("aggregate testing model includes results owned by remote shards", () => {
  const model = testingMatrixModel({
    status: "running",
    matrix: {
      aggregate: true,
      reporting_shards: 3,
      duration_secs: 60,
      shard_index: 0,
      shard_count: 8,
      total_cases: 1,
      assigned_cases: 1,
      workloads: ["cpu_saturation"],
      groups: [{
        fairness: "eevdf",
        rows: [{
          policy_id: "basic.toml",
          cases: [{
            id: "eevdf/basic.toml/cpu_saturation",
            workload: "cpu_saturation",
            assigned: false,
            status: "passed",
            elapsed_ms: 60_001,
            failure: null,
          }],
        }],
      }],
    },
  });

  assert.equal(model.aggregate, true);
  assert.equal(model.reportingShards, 3);
  assert.equal(model.groups[0].rows[0].cases[0].assigned, true);
  assert.equal(model.groups[0].rows[0].cases[0].symbol, "✓");
  assert.equal(model.summary.passed, 1);
});

test("stopped cases are neutral and are not counted as pending failures", () => {
  const model = testingMatrixModel({
    status: "stopped",
    matrix: {
      workloads: ["cpu_saturation"],
      groups: [{
        fairness: "fifo",
        rows: [{
          policy_id: "basic.toml",
          cases: [{
            id: "fifo/basic.toml/cpu_saturation",
            workload: "cpu_saturation",
            assigned: true,
            status: "aborted",
          }],
        }],
      }],
    },
  });

  const stopped = model.groups[0].rows[0].cases[0];
  assert.equal(stopped.label, "Stopped");
  assert.equal(stopped.symbol, "");
  assert.deepEqual(model.summary, {
    passed: 0,
    failed: 0,
    running: 0,
    pending: 0,
  });
});
