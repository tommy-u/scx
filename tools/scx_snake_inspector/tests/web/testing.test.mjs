// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  parseInspectorRoute,
  testingCampaignTabs,
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
    "testingKernelTabs",
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
        snake_fingerprint: "fnv1a64:0123456789abcdef",
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
                  failure: "\u001b[31mkernel failure: runnable task stall pid=42\u001b[0m",
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
  assert.match(model.groups[0].rows[0].cases[0].tooltip, /fnv1a64:0123456789abcdef/);
  assert.match(model.groups[0].rows[0].cases[0].tooltip, /Boot: vng --run --cpus 8/);
  assert.equal(model.groups[0].rows[0].cases[1].symbol, "×");
  assert.match(model.groups[0].rows[0].cases[1].failure, /runnable task stall/);
  assert.match(
    model.groups[0].rows[0].cases[1].tooltip,
    /Failure: kernel failure: runnable task stall pid=42/,
  );
  assert.doesNotMatch(model.groups[0].rows[0].cases[1].tooltip, /\u001b/);
  assert.deepEqual(model.groups[0].result, {
    status: "failed",
    label: "1 failed",
    symbol: "×",
    className: "failed",
    total: 2,
    passed: 1,
    failed: 1,
    running: 0,
    pending: 0,
    stopped: 0,
    unassigned: 0,
  });
  assert.deepEqual(model.summary, {
    passed: 1,
    failed: 1,
    running: 0,
    pending: 0,
  });
});

test("testing UI loads live results and exposes authenticated controls", () => {
  assert.match(script, /fetch\("\/api\/testing\/campaigns"/);
  assert.match(script, /testingMutation\("\/api\/testing\/run"/);
  assert.match(script, /testingMutation\("\/api\/testing\/stop"/);
  assert.doesNotMatch(script, /title="\$\{escapeHtml\(testCase\.tooltip\)\}"/);
  assert.match(page, /id="testingTooltip"[^>]*role="tooltip"/);
  assert.match(script, /data-testing-tooltip=/);
  assert.match(script, /class="visually-hidden"/);
  assert.match(script, /testingMatrix\.addEventListener\("pointermove"/);
  assert.match(script, /testingMatrix\.addEventListener\("pointerleave"/);
  assert.match(script, /testingMatrix\.addEventListener\("focusin"/);
  assert.match(script, /testingMatrix\.addEventListener\("focusout"/);
  assert.match(script, /testingTooltip\.setAttribute\("aria-hidden", "false"\)/);
  assert.match(script, /testingTooltip\.setAttribute\("aria-hidden", "true"\)/);
  assert.match(script, /window\.addEventListener\("resize", \(\) => hideTestingTooltip\(\)\)/);
  assert.match(script, /window\.addEventListener\("scroll", \(\) => hideTestingTooltip\(\), true\)/);
  assert.match(script, /hoveredTestingCaseId/);
  assert.match(script, /testingMatrixMarkup/);
  assert.match(script, /hideTestingTooltip\("pointer"\)/);
  assert.match(script, /data-testing-fairness-toggle=/);
  assert.match(script, /data-testing-campaign=/);
  assert.match(script, /collapsedTestingFairness/);
  assert.match(script, /selectedTestingCampaignKey/);
  assert.match(script, /aria-expanded=/);
  assert.match(script, /aria-selected=/);
  assert.match(styles, /\.testing-matrix/);
  assert.match(styles, /\.testing-result\.passed/);
  assert.match(styles, /\.testing-result\.failed/);
  assert.match(styles, /\.testing-tooltip\s*\{/);
  assert.match(styles, /\.testing-fairness-toggle\s*\{/);
  assert.match(styles, /\.testing-kernel-tabs\s*\{/);
  assert.match(styles, /\.testing-matrix-wrap\s*\{[^}]*contain:\s*layout;/s);
});

test("fairness result passes only when every case passes", () => {
  const model = testingMatrixModel({
    status: "completed",
    matrix: {
      aggregate: true,
      workloads: ["cpu_saturation", "waker_wakee"],
      groups: [{
        fairness: "fifo",
        rows: [{
          policy_id: "basic.toml",
          cases: [
            {
              id: "fifo/basic.toml/cpu_saturation",
              workload: "cpu_saturation",
              status: "passed",
            },
            {
              id: "fifo/basic.toml/waker_wakee",
              workload: "waker_wakee",
              status: "passed",
            },
          ],
        }],
      }],
    },
  });

  assert.deepEqual(model.groups[0].result, {
    status: "passed",
    label: "2 / 2 passed",
    symbol: "✓",
    className: "passed",
    total: 2,
    passed: 2,
    failed: 0,
    running: 0,
    pending: 0,
    stopped: 0,
    unassigned: 0,
  });
});

test("kernel tabs show whole-campaign pass and failure outcomes", () => {
  const campaign = (campaignId, kernel, status, caseStatuses) => ({
    campaign_id: campaignId,
    environment: { kernel_release: kernel },
    status,
    matrix: {
      aggregate: true,
      workloads: ["cpu_saturation", "mixed_affinity"],
      groups: [{
        fairness: "eevdf",
        rows: [{
          policy_id: "basic.toml",
          cases: caseStatuses.map((caseStatus, index) => ({
            id: `eevdf/basic.toml/${index ? "mixed_affinity" : "cpu_saturation"}`,
            workload: index ? "mixed_affinity" : "cpu_saturation",
            status: caseStatus,
          })),
        }],
      }],
    },
  });
  const runs = [
    campaign("campaign-613", "6.13-test", "completed", ["passed", "passed"]),
    campaign("campaign-616", "6.16-test", "completed", ["passed", "failed"]),
    campaign("campaign-next", "6.17-test", "running", ["passed", "running"]),
  ];

  const model = testingCampaignTabs(runs, "campaign:1");

  assert.equal(model.selectedKey, "campaign:1");
  assert.equal(model.selectedRun, runs[1]);
  assert.deepEqual(
    model.tabs.map(({ key, label, status, symbol, passed, failed, total }) => ({
      key,
      label,
      status,
      symbol,
      passed,
      failed,
      total,
    })),
    [
      {
        key: "campaign:0",
        label: "6.13-test",
        status: "passed",
        symbol: "✓",
        passed: 2,
        failed: 0,
        total: 2,
      },
      {
        key: "campaign:1",
        label: "6.16-test",
        status: "failed",
        symbol: "×",
        passed: 1,
        failed: 1,
        total: 2,
      },
      {
        key: "campaign:2",
        label: "6.17-test",
        status: "running",
        symbol: "",
        passed: 1,
        failed: 0,
        total: 2,
      },
    ],
  );
});

test("running kernel tabs identify the campaign as running", () => {
  const run = {
    campaign_id: "campaign-next",
    environment: { kernel_release: "7.0-test" },
    status: "running",
    matrix: {
      aggregate: true,
      workloads: ["cpu_saturation", "mixed_affinity"],
      groups: [{
        fairness: "eevdf",
        rows: [{
          policy_id: "basic.toml",
          cases: [
            {
              id: "eevdf/basic.toml/cpu_saturation",
              workload: "cpu_saturation",
              status: "passed",
            },
            {
              id: "eevdf/basic.toml/mixed_affinity",
              workload: "mixed_affinity",
              status: "running",
            },
          ],
        }],
      }],
    },
  };
  const [tab] = testingCampaignTabs([run]).tabs;

  assert.equal(tab.status, "running");
  assert.equal(tab.summary, "Running \u00b7 1 / 2 passed");
  assert.equal(tab.symbol, "");
  assert.match(
    script,
    /aria-label="\$\{escapeHtml\(`\$\{tab\.label\}: \$\{tab\.summary\}`\)\}"/,
  );

  run.matrix.groups[0].rows[0].cases[1].status = "failed";
  const [failedTab] = testingCampaignTabs([run]).tabs;
  assert.equal(failedTab.status, "failed");
  assert.equal(failedTab.summary, "Running \u00b7 1 failed");
  assert.equal(failedTab.symbol, "×");
});

test("duplicate kernel tab labels are disambiguated without changing selection keys", () => {
  const runs = ["first-run", "second-run"].map((campaignId) => ({
    campaign_id: campaignId,
    environment: { kernel_release: "6.16-test" },
    status: "idle",
    matrix: { aggregate: true, workloads: [], groups: [] },
  }));

  const model = testingCampaignTabs(runs, "campaign:1");

  assert.deepEqual(model.tabs.map((tab) => tab.key), ["campaign:0", "campaign:1"]);
  assert.deepEqual(model.tabs.map((tab) => tab.label), [
    "6.16-test · first-run",
    "6.16-test · second-run",
  ]);
  assert.equal(model.selectedKey, "campaign:1");
});

test("local fairness result stays pending while other shards are unreported", () => {
  const model = testingMatrixModel({
    status: "completed",
    matrix: {
      aggregate: false,
      workloads: ["cpu_saturation", "waker_wakee"],
      groups: [{
        fairness: "fifo",
        rows: [{
          policy_id: "basic.toml",
          cases: [
            {
              id: "fifo/basic.toml/cpu_saturation",
              workload: "cpu_saturation",
              assigned: true,
              status: "passed",
            },
            {
              id: "fifo/basic.toml/waker_wakee",
              workload: "waker_wakee",
              assigned: false,
              status: "pending",
            },
          ],
        }],
      }],
    },
  });

  assert.deepEqual(model.groups[0].result, {
    status: "pending",
    label: "1 / 2 passed",
    symbol: "",
    className: "pending",
    total: 2,
    passed: 1,
    failed: 0,
    running: 0,
    pending: 0,
    stopped: 0,
    unassigned: 1,
  });
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
