"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");
const vm = require("vm");

class FakeNode {
  constructor() {
    this.children = [];
    this.classList = { remove() {}, toggle() {} };
    this.textContent = "";
    this.value = "";
  }

  addEventListener() {}
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = children; }
}

async function main() {
  const nodes = new Map();
  const node = (selector) => {
    if (!nodes.has(selector)) nodes.set(selector, new FakeNode());
    return nodes.get(selector);
  };
  const snapshot = {
    available: true,
    error: null,
    pid: 7,
    executable: "/usr/bin/scx_mitosis",
    version: "scx_mitosis test",
    command_line: ["scx_mitosis"],
    options: [
      { name: "--unset-b", status: "unset", current_value: "unset", default: null, group: "Options", description: "", possible_values: [] },
      { name: "--default-a", status: "default", current_value: "1", default: "1", group: "Options", description: "", possible_values: [] },
      { name: "--explicit-a", status: "explicit", current_value: "2", default: null, group: "Options", description: "", possible_values: [] },
      { name: "--disabled-a", status: "disabled", current_value: "disabled", default: null, group: "Options", description: "", possible_values: [] },
      { name: "--unset-a", status: "unset", current_value: "unset", default: null, group: "Options", description: "", possible_values: [] },
    ],
  };
  const context = {
    console,
    document: {
      createElement() { return new FakeNode(); },
      querySelector: node,
      querySelectorAll() { return []; },
    },
    fetch: async () => ({ ok: true, json: async () => snapshot }),
    Intl,
  };
  vm.runInNewContext(
    fs.readFileSync(path.join(__dirname, "..", "src", "web", "config.js"), "utf8"),
    context,
    { filename: "config.js" },
  );
  await new Promise((resolve) => setImmediate(resolve));

  const activeNames = nodes.get("#configurationRows").children
    .map((row) => row.children[1].textContent);
  assert.deepStrictEqual(activeNames, [
    "--explicit-a",
    "--default-a",
  ]);
  const inactiveNames = nodes.get("#inactiveConfigurationRows").children
    .map((row) => row.children[1].textContent);
  assert.deepStrictEqual(inactiveNames, [
    "--unset-b",
    "--unset-a",
    "--disabled-a",
  ]);
}

main()
  .then(() => console.log("config visuals contract: ok"))
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
