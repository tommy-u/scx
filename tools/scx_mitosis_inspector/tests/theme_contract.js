"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const source = fs.readFileSync(
  path.join(__dirname, "..", "src", "web", "theme.js"),
  "utf8",
);

const listeners = new Map();
const toggleListeners = new Map();
const dispatched = [];
const stored = new Map();
const toggle = {
  checked: false,
  addEventListener(type, callback) {
    toggleListeners.set(type, callback);
  },
};
const documentElement = { dataset: {}, style: {} };

const context = {
  CustomEvent: class CustomEvent {
    constructor(type, options) {
      this.type = type;
      this.detail = options.detail;
    }
  },
  document: {
    documentElement,
    addEventListener(type, callback) {
      listeners.set(type, callback);
    },
    dispatchEvent(event) {
      dispatched.push(event);
    },
    querySelectorAll(selector) {
      assert.strictEqual(selector, "[data-theme-toggle]");
      return [toggle];
    },
  },
  localStorage: {
    getItem(key) { return stored.get(key) ?? null; },
    setItem(key, value) { stored.set(key, value); },
  },
  matchMedia(query) {
    assert.strictEqual(query, "(prefers-color-scheme: dark)");
    return { matches: true, addEventListener() {} };
  },
};
context.globalThis = context;

vm.runInNewContext(source, context, { filename: "theme.js" });
assert.strictEqual(documentElement.dataset.theme, "dark");
assert.strictEqual(documentElement.style.colorScheme, "dark");

listeners.get("DOMContentLoaded")();
assert.strictEqual(toggle.checked, true);

toggle.checked = false;
toggleListeners.get("change")();
assert.strictEqual(documentElement.dataset.theme, "light");
assert.strictEqual(stored.get("mitosis-inspector-theme"), "light");
assert.strictEqual(dispatched.at(-1).type, "mitosis-theme-change");
assert.strictEqual(dispatched.at(-1).detail.theme, "light");

console.log("theme contract: ok");
