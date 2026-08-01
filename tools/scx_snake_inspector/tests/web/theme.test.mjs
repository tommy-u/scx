// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import * as heatmapModule from "../../src/web/heatmap.js";
import * as themeModule from "../../src/web/theme.js";
import {
  createThemeController,
  loadThemePreference,
  normalizeThemePreference,
  resolveTheme,
} from "../../src/web/theme.js";

const styles = readFileSync(
  new URL("../../src/web/style.css", import.meta.url),
  "utf8",
);

function cssVariables(block) {
  return new Map(
    [...block.matchAll(/--([\w-]+):\s*([^;]+);/g)]
      .map((match) => [match[1], match[2].trim()]),
  );
}

function relativeLuminance(hex) {
  const channels = hex.match(/[0-9a-f]{2}/gi).map((channel) => parseInt(channel, 16) / 255);
  const [red, green, blue] = channels.map((channel) => (
    channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4
  ));
  return 0.2126 * red + 0.7152 * green + 0.0722 * blue;
}

function contrastRatio(left, right) {
  const lighter = Math.max(relativeLuminance(left), relativeLuminance(right));
  const darker = Math.min(relativeLuminance(left), relativeLuminance(right));
  return (lighter + 0.05) / (darker + 0.05);
}

function mixHex(foreground, background, amount) {
  const channels = (hex) => hex.match(/[0-9a-f]{2}/gi).map((channel) => parseInt(channel, 16));
  const front = channels(foreground);
  const back = channels(background);
  return `#${front.map((channel, index) => (
    Math.round(channel * amount + back[index] * (1 - amount))
      .toString(16)
      .padStart(2, "0")
  )).join("")}`;
}

test("theme preferences accept only light, system, and dark", () => {
  assert.equal(normalizeThemePreference("light"), "light");
  assert.equal(normalizeThemePreference("system"), "system");
  assert.equal(normalizeThemePreference("dark"), "dark");
  assert.equal(normalizeThemePreference("sepia"), "system");
  assert.equal(normalizeThemePreference(null), "system");
});

test("system theme resolves against the current color-scheme preference", () => {
  assert.equal(resolveTheme("system", false), "light");
  assert.equal(resolveTheme("system", true), "dark");
  assert.equal(resolveTheme("light", true), "light");
  assert.equal(resolveTheme("dark", false), "dark");
});

test("stored theme loading is validated and tolerates unavailable storage", () => {
  assert.equal(loadThemePreference({ getItem: () => "dark" }), "dark");
  assert.equal(loadThemePreference({ getItem: () => "sepia" }), "system");
  assert.equal(loadThemePreference({ getItem: () => { throw new Error("blocked"); } }), "system");
});

test("theme controller persists explicit choices and follows system changes", () => {
  const applied = [];
  const persisted = [];
  const controller = createThemeController({
    preference: "system",
    systemDark: false,
    onApply: (state) => applied.push(state),
    onPersist: (preference) => persisted.push(preference),
  });

  assert.deepEqual(applied, [{ preference: "system", resolved: "light" }]);
  controller.systemChanged(true);
  assert.deepEqual(applied.at(-1), { preference: "system", resolved: "dark" });
  assert.deepEqual(persisted, []);

  controller.select("light");
  assert.deepEqual(applied.at(-1), { preference: "light", resolved: "light" });
  assert.deepEqual(persisted, ["light"]);

  controller.systemChanged(false);
  assert.deepEqual(applied.at(-1), { preference: "light", resolved: "light" });

  controller.select("system");
  assert.deepEqual(applied.at(-1), { preference: "system", resolved: "light" });
  assert.deepEqual(persisted, ["light", "system"]);
});

test("applying a page theme synchronizes controls and repaints visualizations", () => {
  assert.equal(typeof themeModule.applyThemeToDocument, "function");
  const root = { dataset: {} };
  const controls = [
    { dataset: { themePreference: "light" }, checked: false },
    { dataset: { themePreference: "system" }, checked: false },
    { dataset: { themePreference: "dark" }, checked: false },
  ];
  let repaints = 0;

  themeModule.applyThemeToDocument({
    root,
    controls,
    theme: { preference: "dark", resolved: "dark" },
    repaint: () => { repaints += 1; },
  });
  assert.deepEqual(root.dataset, { theme: "dark", resolvedTheme: "dark" });
  assert.deepEqual(controls.map((control) => control.checked), [false, false, true]);

  themeModule.applyThemeToDocument({
    root,
    controls,
    theme: { preference: "system", resolved: "light" },
    repaint: () => { repaints += 1; },
  });
  assert.deepEqual(root.dataset, { theme: "system", resolvedTheme: "light" });
  assert.deepEqual(controls.map((control) => control.checked), [false, true, false]);
  assert.equal(repaints, 2);
});

test("component styles use theme tokens instead of light-only literals", () => {
  const componentStyles = styles.slice(styles.indexOf(".testing-controls"));
  const intentionalDataColors = new Set([
    "#000004",
    "#420a68",
    "#932667",
    "#dd513a",
    "#fca50a",
    "#fcffa4",
  ]);
  const declarationValues = [...componentStyles.matchAll(
    /(?:^|[;{])\s*[\w-]+\s*:\s*([^;{}]+);/gm,
  )].map((match) => match[1]);
  const rawColors = new Set(
    declarationValues.flatMap((value) => (
      value.match(/#[0-9a-fA-F]{3,8}(?![0-9a-fA-F])|rgba?\([^)]*\)/g) || []
    )),
  );
  const lightOnlyColors = [...rawColors]
    .map((color) => color.toLowerCase())
    .filter((color) => !intentionalDataColors.has(color));
  assert.deepEqual(lightOnlyColors, []);
});

test("dark primary actions retain readable contrast", () => {
  const rootBlock = styles.match(/:root\s*\{([^}]+)\}/s)?.[1] || "";
  const darkBlock = styles.match(/:root\[data-resolved-theme="dark"\]\s*\{([^}]+)\}/s)?.[1] || "";
  const rootTokens = cssVariables(rootBlock);
  const darkTokens = cssVariables(darkBlock);
  const onStrong = rootTokens.get("on-strong");

  for (const token of ["primary-action", "primary-action-hover"]) {
    assert.ok(contrastRatio(onStrong, darkTokens.get(token)) >= 4.5);
  }
});

test("DSQ heatmaps compute readable foregrounds across both themes", () => {
  assert.equal(typeof heatmapModule.heatmapTextColor, "function");
  if (typeof heatmapModule.heatmapTextColor !== "function") return;
  const rootBlock = styles.match(/:root\s*\{([^}]+)\}/s)?.[1] || "";
  const darkBlock = styles.match(/:root\[data-resolved-theme="dark"\]\s*\{([^}]+)\}/s)?.[1] || "";
  for (const tokens of [cssVariables(rootBlock), cssVariables(darkBlock)]) {
    for (const token of ["active", "accent", "warning-strong"]) {
      for (const intensity of [0, 0.3, 0.6, 0.68, 1]) {
        const background = mixHex(
          tokens.get(token),
          tokens.get("surface-muted"),
          intensity,
        );
        const ink = heatmapModule.heatmapTextColor(
          tokens.get(token),
          tokens.get("surface-muted"),
          intensity,
        );
        assert.ok(
          contrastRatio(ink, background) >= 4.5,
          `heatmap ink lacks contrast for --${token} at ${intensity}`,
        );
      }
    }
  }
  assert.match(
    styles,
    /\.dsq-traffic-cell,\s*\.dsq-traffic-cell small,\s*\.dsq-transfer-cell\s*\{[^}]*color:\s*var\(--heat-ink\);/s,
  );
});

test("canvas contrast tokens use true black and white ink", () => {
  const rootBlock = styles.match(/:root\s*\{([^}]+)\}/s)?.[1] || "";
  const darkBlock = styles.match(/:root\[data-resolved-theme="dark"\]\s*\{([^}]+)\}/s)?.[1] || "";
  for (const tokens of [cssVariables(rootBlock), cssVariables(darkBlock)]) {
    assert.equal(tokens.get("canvas-dark-text"), "#000000");
    assert.equal(tokens.get("canvas-light-text"), "#ffffff");
  }
});

test("desktop navigation scrolls independently above the fixed theme footer", () => {
  assert.match(styles, /\.workspace-sidebar\s*\{[^}]*overflow:\s*hidden;/s);
  assert.match(
    styles,
    /\.workspace-sidebar\s*>\s*\.workspace-navigation\s*\{[^}]*min-height:\s*0;[^}]*overflow-y:\s*auto;/s,
  );
  assert.match(styles, /\.workspace-sidebar-footer\s*\{[^}]*flex:\s*0 0 auto;/s);
});
