"use strict";

const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { Blob } = require("node:buffer");

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

function meta(sequence = 1, epoch = 1, captured = 10000, error = null) {
  return { epoch, sample_seq: sequence, captured_at_unix_ms: captured,
    last_success_at_unix_ms: captured, error };
}

function collector(epoch = 1, status = "active", error = null) {
  return { epoch, status, scheduler_enable_seq: epoch, scheduler_name: "scx_mitosis", error };
}

function counters(sequence = 1, epoch = 1) {
  return { meta: meta(sequence, epoch), collector: collector(epoch), scheduler: "scx_mitosis",
    migration_map_capacity: 65536, migration_map_failures: 0, migration_quality: "complete",
    target_program_ids: [1, 2, 3, 4, 5], uptime_seconds: 10, callback_timing_sample_rate: 1024,
    event_timing_sample_rate: 64, counters: [{ name: "select_cpu", count: sequence, rate_per_second: 1 }],
    callback_timings: [], scheduler_timings: [], scheduler_events: [], softirqs: [],
    migrations: [], cpu_runtime: [], cpu_capacity_loss: [], bpf_program_stats: [],
    inspector_bpf_program_stats: [], inspector_bpf_cpu_equivalent_pct: null,
    inspector_bpf_host_capacity_pct: null, interrupt_cpu: [], probe_manifest: [],
    dsq_metrics: { available: false, depth_average: null, depth_latest_max: null },
    block_io: { available: false, completion_rate_per_second: null, completed_bytes_per_second: null },
    hardirqs: { available: false, metrics_map_full: 0, starts_map_full: 0, unmatched_exits: 0, rows: [] } };
}

function migrations(sequence = 1, epoch = 1, window = 10000) {
  return { meta: meta(sequence, epoch), collector: collector(epoch), window_ms: window,
    migration_map_capacity: 65536, migration_map_failures: 0, migration_quality: "complete",
    max_window_ms: 300000, observed_ms: 1000, total: sequence, rate_per_second: sequence,
    rows: [{ from_cpu: 0, to_cpu: 1, count: sequence }] };
}

function stats(sequence = 1, epoch = 1) {
  return { meta: meta(sequence, epoch), collector: collector(epoch), error: null,
    metrics: { util_pct: 50, cells: { 0: { util_pct: sequence * 10 } } } };
}

function historySnapshot(samples, { instanceId = "inspector-1", retentionMs = 1800000,
    reset = true, latest = samples[samples.length - 1] ?? stats(0) } = {}) {
  return { meta: { ...latest.meta }, collector: { ...latest.collector }, instance_id: instanceId,
    retention_ms: retentionMs, reset,
    samples: samples.map((snapshot) => ({ meta: { ...snapshot.meta }, cells: snapshot.metrics?.cells ?? {} })) };
}

function statsResponse(snapshot, url) {
  if (url.startsWith("/api/stats/history")) {
    return response(historySnapshot(snapshot.meta.error ? [] : [snapshot],
      { latest: snapshot, reset: !url.includes("after_seq=") }));
  }
  if (url === "/api/stats") return response(snapshot);
  throw new Error(`Unexpected stats source ${url}`);
}

function system(sequence = 1, epoch = 1) {
  const unavailable = () => ({ available: false, value: null, error: "unsupported" });
  return { meta: meta(sequence, epoch), collector: collector(epoch), captured_at_unix_ms: 10000,
    interval_ms: 2000, cpu: { available: true, value: { busy_pct: 50 } }, memory: unavailable(),
    pressure: { cpu: unavailable(), memory: unavailable(), io: unavailable() },
    sched_ext: { available: true, value: { state: "enabled", enable_seq: epoch } },
    network: { available: true, value: { interfaces: [] } },
    frequencies: { available: true, value: { average_khz: 1000000, cpus: [] } } };
}

function response(value, status = 200) {
  return { ok: status >= 200 && status < 300, status, json: async () => value };
}

function timelineFrame(sequence, at, signals = {}, epochs = {}) {
  return { seq: sequence, at_unix_ms: at,
    epochs: { counters: 1, stats: 1, system: 1, ...epochs }, signals,
    source_meta: Object.fromEntries(["counters", "stats", "system"].map(name =>
      [name, meta(sequence, epochs[name] ?? 1, at)])),
    source_available: { counters: true, stats: true, system: true } };
}

function timelineArchive(frames, { instanceId = "inspector-1", retentionMs = 1800000,
    now = frames.at(-1)?.at_unix_ms ?? 10000, reset = true,
    oldestAt = frames[0]?.at_unix_ms ?? null, latestAt = frames.at(-1)?.at_unix_ms ?? null,
    sequence = frames.at(-1)?.seq ?? 0, defaultWindowMs = 10000,
    maxWindowMs = 300000, windowMs = defaultWindowMs } = {}) {
  return { instance_id: instanceId, retention_ms: retentionMs, now_unix_ms: now,
    oldest_at_unix_ms: oldestAt, latest_at_unix_ms: latestAt,
    sample_seq: sequence, reset, frames, window_ms: windowMs,
    default_window_ms: defaultWindowMs, max_window_ms: maxWindowMs };
}

function timelineView(sources = {}, { instanceId = "inspector-1", retentionMs = 1800000,
    at = Math.max(0, ...Object.values(sources).map(source => source?.meta?.captured_at_unix_ms ?? 0)),
    requestedAt = at, oldestAt = at, latestAt = at, now = latestAt,
    migration = null, errors = {}, observer = collector() } = {}) {
  return { instance_id: instanceId, retention_ms: retentionMs, requested_at_unix_ms: requestedAt,
    at_unix_ms: at, oldest_at_unix_ms: oldestAt, latest_at_unix_ms: latestAt,
    now_unix_ms: now, collector: observer,
    sources: { counters: null, stats: null, system: null, config: null, ...sources },
    migrations: migration, source_errors: errors };
}

class Element {
  constructor() {
    this.children = [];
    this.listeners = new Map();
    this.attributes = new Map();
    this.dataset = {};
    this.textContent = "";
    this.value = "";
    this.disabled = false;
    this.hidden = false;
    this.style = { setProperty() {}, removeProperty() {} };
    const names = new Set();
    this.classList = {
      add: (...values) => values.forEach((value) => names.add(value)),
      remove: (...values) => values.forEach((value) => names.delete(value)),
      toggle(value, enabled) { if (enabled ?? !names.has(value)) names.add(value); else names.delete(value); },
      contains: (value) => names.has(value),
    };
    this.parts = new Map();
  }
  get options() { return this.children; }
  contains(node) { return this === node || this.children.some(child => child.contains?.(node)); }
  focus() { if (this.ownerDocument) this.ownerDocument.activeElement = this; }
  append(...children) {
    children.forEach(child => { if (child && typeof child === "object") child.parentElement = this; });
    this.children.push(...children);
  }
  insertBefore(child, before) {
    const current = this.children.indexOf(child);
    if (current >= 0) this.children.splice(current, 1);
    const index = before == null ? this.children.length : this.children.indexOf(before);
    if (index < 0) throw new Error("Reference node is not a child");
    this.children.splice(index, 0, child);
    return child;
  }
  removeChild(child) {
    const index = this.children.indexOf(child);
    if (index < 0) throw new Error("Node is not a child");
    this.children.splice(index, 1);
    return child;
  }
  replaceChildren(...children) { this.children = []; this.append(...children); }
  setAttribute(key, value) { this.attributes.set(key, value); }
  getAttribute(key) { return this.attributes.get(key) ?? null; }
  removeAttribute(key) { this.attributes.delete(key); }
  addEventListener(type, callback) { this.listeners.set(type, callback); }
  dispatchEvent(event) {
    event.currentTarget = this;
    event.target ??= this;
    this.listeners.get(event.type)?.(event);
    return !event.defaultPrevented;
  }
  getBoundingClientRect() { return { width: 600, height: 80, top: 0, left: 0 }; }
  remove() { this.parentElement?.removeChild(this); }
  click() { this.dispatchEvent({ type: "click" }); }
  querySelector(key) {
    if (!this.parts.has(key)) this.parts.set(key, new Element());
    return this.parts.get(key);
  }
  querySelectorAll() { return []; }
}

// Opt-in DOM support for navigation integration tests. It reads the page's real
// IDs, anchors and ancestry; default page fixtures keep their existing behavior.
function navigationDocument(html, context, settings = {}) {
  const frames = new Map();
  const toggles = new Map();
  const scrolls = [];
  let frameId = 0;
  const decode = (value) => String(value).replace(/&(?:amp|lt|gt|quot|apos|#(\d+)|#x([\da-f]+));/gi,
    (entity, decimal, hexadecimal) => decimal || hexadecimal
      ? String.fromCodePoint(parseInt(decimal || hexadecimal, hexadecimal ? 16 : 10))
      : ({ "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&apos;": "'" })[entity]);
  const descendants = (node) => node.children.flatMap(child => [child, ...descendants(child)]);
  function simpleMatch(node, selector) {
    const id = selector.match(/^#([\w-]+)$/);
    if (id) return node.id === id[1];
    const attribute = selector.match(/^([\w-]+)?\[([\w-]+)(?:(\^?=)["']?([^"'\]]*)["']?)?\]$/);
    if (attribute) {
      const [, tag, name, operator, value] = attribute;
      const actual = node.getAttribute(name);
      return (!tag || node.tagName === tag.toUpperCase()) && actual !== null
        && (!operator || (operator === "^=" ? actual.startsWith(value) : actual === value));
    }
    if (selector.startsWith(".")) return node.classList.contains(selector.slice(1));
    return node.tagName === selector.toUpperCase();
  }
  function matches(node, selector) {
    const parts = selector.trim().split(/\s+/);
    if (!simpleMatch(node, parts.pop())) return false;
    let parent = node.parentElement;
    while (parts.length) {
      const wanted = parts.pop();
      while (parent && !simpleMatch(parent, wanted)) parent = parent.parentElement;
      if (!parent) return false;
      parent = parent.parentElement;
    }
    return true;
  }
  function navigate(href, replace = false) {
    const before = context.location;
    const next = new URL(href, before);
    next.replace = url => navigate(url, true);
    context.location = next;
    if (replace) replacements.push(next.href);
    if (next.hash !== before.hash) context.dispatchEvent({ type: "hashchange",
      oldURL: before.href, newURL: next.href });
  }
  const replacements = [];
  context.location.replace = href => navigate(href, true);
  class HtmlElement extends Element {
    constructor(tagName, attributes = {}) {
      super();
      this.tagName = tagName.toUpperCase();
      this._text = "";
      this._open = Object.hasOwn(attributes, "open");
      this._classes = new Set();
      this.classList = {
        add: (...names) => names.forEach(name => this._classes.add(name)),
        remove: (...names) => names.forEach(name => this._classes.delete(name)),
        contains: name => this._classes.has(name),
        toggle: (name, enabled) => { if (enabled ?? !this._classes.has(name)) this._classes.add(name); else this._classes.delete(name); },
      };
      for (const [name, value] of Object.entries(attributes)) {
        this.attributes.set(name, value);
        if (name === "class") this.className = value;
        else if (name === "id") this.id = value;
        else if (name.startsWith("data-")) this.dataset[name.slice(5).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase())] = value;
        else if (["value", "name", "type"].includes(name)) this[name] = value;
      }
      this.hidden = Object.hasOwn(attributes, "hidden");
      this.checked = Object.hasOwn(attributes, "checked");
      this.disabled = Object.hasOwn(attributes, "disabled");
      if (this.tagName === "CANVAS") this.getContext = () => null;
    }
    get className() { return [...this._classes].join(" "); }
    set className(value) { this._classes = new Set(String(value).split(/\s+/).filter(Boolean)); }
    get textContent() { return (this._text || "") + this.children.map(child => child.textContent).join(""); }
    set textContent(value) { this._text = String(value); this.children = []; }
    get open() { return this._open; }
    set open(value) {
      const next = Boolean(value);
      if (next !== this._open) {
        this._open = next;
        if (next) this.attributes.set("open", ""); else this.attributes.delete("open");
        toggles.set(this, true);
      }
    }
    get href() { return new URL(this.getAttribute("href") || "", context.location).href; }
    get hash() { return new URL(this.href).hash; }
    get firstElementChild() { return this.children[0] || null; }
    setAttribute(name, value) {
      super.setAttribute(name, String(value));
      if (name === "id") this.id = String(value);
      if (name === "class") this.className = value;
    }
    matches(selector) { return matches(this, selector); }
    closest(selector) {
      for (let node = this; node; node = node.parentElement) if (matches(node, selector)) return node;
      return null;
    }
    querySelectorAll(selector) {
      if (selector.startsWith(":scope > ")) return this.children.filter(node => matches(node, selector.slice(9)));
      return descendants(this).filter(node => matches(node, selector));
    }
    querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
    replaceChildren(...children) { this._text = ""; super.replaceChildren(...children); }
    click(overrides = {}) {
      const event = { type: "click", button: 0, ctrlKey: false, metaKey: false,
        shiftKey: false, altKey: false, defaultPrevented: false,
        preventDefault() { this.defaultPrevented = true; }, ...overrides };
      this.dispatchEvent(event);
      if (this.tagName === "A" && !event.defaultPrevented && event.button === 0
        && !event.ctrlKey && !event.metaKey && !event.shiftKey && !event.altKey) navigate(this.href);
      return event;
    }
    getBoundingClientRect() {
      return { width: 600, height: this.tagName === "DETAILS" && !this.open ? 0 : 80,
        top: (this.layoutTop || 0) - context.scrollY, left: 0 };
    }
    scrollIntoView(options) {
      const main = this.tagName === "DETAILS" ? this : this.querySelector(":scope > details");
      scrolls.push({ target: this.id, hash: context.location.hash,
        mainOpen: main ? main.open : null, options });
      context.scrollY = this.layoutTop || 0;
    }
  }
  const root = new HtmlElement("document");
  const stack = [root];
  const voidTags = new Set(["AREA", "BASE", "BR", "COL", "EMBED", "HR", "IMG", "INPUT", "LINK", "META", "PARAM", "SOURCE", "TRACK", "WBR"]);
  let section = 0;
  for (const token of html.match(/<!--[\s\S]*?-->|<[^>]+>|[^<]+/g) || []) {
    if (token.startsWith("<!--") || token.startsWith("<!")) continue;
    const closing = token.match(/^<\/([\w-]+)/);
    if (closing) {
      let index = stack.length - 1;
      while (index > 0 && stack[index].tagName !== closing[1].toUpperCase()) index -= 1;
      if (index > 0) stack.splice(index);
      continue;
    }
    const opening = token.match(/^<([\w-]+)([\s\S]*?)\/?\s*>$/);
    if (!opening) { stack.at(-1)._text += decode(token); continue; }
    const attributes = {};
    for (const match of opening[2].matchAll(/([^\s=/>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g)) {
      attributes[match[1]] = decode(match[2] ?? match[3] ?? match[4] ?? "");
    }
    const node = new HtmlElement(opening[1], attributes);
    node.layoutTop = node.tagName === "SECTION" ? 400 + section++ * 200 : stack.at(-1).layoutTop;
    node.ownerDocument = context.document;
    stack.at(-1).append(node);
    if (!voidTags.has(node.tagName) && !token.endsWith("/>")) stack.push(node);
  }
  context.document.querySelector = selector => root.querySelector(selector);
  context.document.querySelectorAll = selector => root.querySelectorAll(selector);
  context.document.createElement = tag => { const node = new HtmlElement(tag); node.ownerDocument = context.document; return node; };
  context.document.getElementById = id => root.querySelector(`#${id}`);
  context.document.readyState = settings.readyState || "complete";
  context.document.documentElement.scrollHeight = 400 + section * 200;
  context.requestAnimationFrame = callback => { const id = ++frameId; frames.set(id, callback); return id; };
  context.cancelAnimationFrame = id => frames.delete(id);
  return {
    html, scrolls, replacements,
    target: hash => root.querySelector(hash),
    link: hash => root.querySelectorAll("#sectionNavigation a[href^='#']").find(node => node.hash === hash),
    setHash: hash => navigate(hash),
    contentLoaded() { context.document.readyState = "interactive"; context.document.dispatchEvent({ type: "DOMContentLoaded" }); context.document.readyState = "complete"; },
    flushToggles() { const pending = [...toggles.keys()]; toggles.clear(); pending.forEach(node => node.dispatchEvent({ type: "toggle" })); },
    flushFrames() { const pending = [...frames.values()]; frames.clear(); pending.forEach(callback => callback()); },
    get pendingFrames() { return frames.size; },
  };
}

function page(filename, fetcher, options = {}) {
  const elements = new Map();
  const listeners = new Map();
  const documentListeners = new Map();
  const intervals = [];
  const events = [];
  const timers = new Map();
  let timerId = 0;
  let now = options.now ?? 10000;
  const element = (key) => {
    if (!elements.has(key)) elements.set(key, new Element());
    return elements.get(key);
  };
  const card = element("card");
  card.dataset.callback = "select_cpu";
  const storage = options.storage ?? new Map();
  const storageApi = { getItem(key) { return storage.has(key) ? storage.get(key) : null; },
    setItem(key, value) { storage.set(key, String(value)); }, removeItem(key) { storage.delete(key); } };
  const pathnames = { "stats.js": "/", "scheduling.js": "/scheduling", "callbacks.js": "/callbacks",
    "system.js": "/system", "config.js": "/config", "inspector.js": "/inspector" };
  let location = new URL(options.location ?? `http://inspector.test:44103${pathnames[filename] ?? "/"}`);
  const context = {
    console, AbortController, Intl, URL, Blob,
    Date: class extends Date {
      constructor(...args) { super(...(args.length ? args : [now])); }
      static now() { return now; }
    },
    sessionStorage: storageApi, localStorage: storageApi,
    location,
    history: { replaceState(state, title, url) {
      location = new URL(url, location);
      context.location = location;
    } },
    fetch: (...args) => filename === "stats.js" && args[0] === "/api/host-context"
      ? Promise.resolve(response({ topology: { cpus: [{ cpu: 0, package: 0, core: 0, llc: 0, node: 0 }] } }))
      : fetcher(...args),
    document: { createElement: (tagName) => {
      const node = new Element();
      node.tagName = String(tagName || "div").toUpperCase();
      node.ownerDocument = context.document;
      return node;
    }, activeElement: null, visibilityState: "visible", querySelector: element,
      querySelectorAll: (key) => key === "[data-callback]" ? [card] : [],
      addEventListener(type, callback) {
        if (!documentListeners.has(type)) documentListeners.set(type, []);
        documentListeners.get(type).push(callback);
      },
      dispatchEvent(event) {
        for (const callback of documentListeners.get(event.type) || []) callback(event);
      }, documentElement: { scrollHeight: 1000, style: { setProperty() {}, removeProperty() {} } } },
    setInterval(callback) { intervals.push(callback); },
    setTimeout(callback, delay) { const id = ++timerId; timers.set(id, { callback, delay }); return id; },
    clearTimeout(id) { timers.delete(id); },
    addEventListener(type, callback) {
      if (!listeners.has(type)) listeners.set(type, []);
      listeners.get(type).push(callback);
    },
    dispatchEvent(event) {
      events.push(event);
      for (const callback of listeners.get(event.type) || []) callback(event);
    },
    CustomEvent: class { constructor(type, options = {}) { this.type = type; this.detail = options.detail; } },
    confirm: () => true,
    innerHeight: 800, scrollY: 0,
    requestAnimationFrame(callback) { callback(); return 1; }, cancelAnimationFrame() {},
    MitosisHeatmap: { init() {}, update() {}, setOrderMode() {}, setScale() {}, setZoom() {} },
  };
  context.window = context;
  context.globalThis = context;
  Object.assign(context, options.globals || {});
  const web = path.join(__dirname, "../src/web");
  const navigation = options.navigation ? navigationDocument(
    fs.readFileSync(path.join(web, options.navigation.html || filename.replace(".js", ".html")), "utf8"),
    context, options.navigation) : null;
  vm.createContext(context);
  for (const script of ["charts.js", "polling.js", "topology_strip.js", "sections.js",
    ...(options.timeline ? ["timeline.js"] : []), filename, ...(options.after || [])]) {
    options.preload?.[script]?.(context);
    vm.runInContext(fs.readFileSync(path.join(web, script), "utf8"), context, { filename: script });
  }
  return { context, element: navigation ? selector => context.document.querySelector(selector) : element,
    navigation, events, storage, setNow(value) { now = value; },
    read(expression) { return vm.runInContext(expression, context); },
    tick() { intervals.forEach((callback) => callback()); },
    emit(type, detail) { context.dispatchEvent(new context.CustomEvent(type, { detail })); },
    visibility(state) {
      context.document.visibilityState = state;
      context.document.dispatchEvent(new context.CustomEvent("visibilitychange"));
    },
    timeout(delay = Infinity) { [...timers].filter(([, timer]) => timer.delay <= delay)
      .forEach(([id, timer]) => { timers.delete(id); timer.callback(); }); },
    loadReset() { vm.runInContext(fs.readFileSync(path.join(web, "reset.js"), "utf8"), context); } };
}

async function settle() { await new Promise((resolve) => setImmediate(resolve)); }

function hostContext() {
  return { identity: { hostname: "test-host", kernel_release: "test-kernel", cpu_count: 2 },
    topology: { cpus: [{ cpu: 0, package: 0, core: 0, llc: 0, node: 0 },
      { cpu: 1, package: 0, core: 1, llc: 0, node: 0 }], topology_order: [0, 1],
    numeric_order: [0, 1], llc_groups: [{ llc: 0, node: 0, cpus: [0, 1] }] } };
}

// Lets pending fetches resolve and fires the timeline's short view debounce.
async function ready(view) {
  await settle();
  view?.timeout(75);
  await settle();
  view?.timeout(75);
  await settle();
}

// Serves the shared timeline from mutable live sources. Each advance() publishes one
// new frame whose full view holds whatever `current` contains at that moment.
function liveTimeline(filename, current, options = {}) {
  const frames = [timelineFrame(1, 10000, options.signals || {})];
  const calls = [];
  const fetcher = async (url) => {
    calls.push(url);
    const request = new URL(url, "http://inspector.test:44103");
    const oldestAt = frames[0].at_unix_ms;
    const latest = frames.at(-1);
    if (request.pathname === "/api/timeline") {
      const after = Number(request.searchParams.get("after_seq") || 0);
      return response(timelineArchive(frames.filter(frame => frame.seq > after), { now: latest.at_unix_ms,
        reset: !after, oldestAt, latestAt: latest.at_unix_ms, sequence: latest.seq }));
    }
    if (request.pathname === "/api/timeline/view") {
      const { migrations: migration = null, ...sources } = current;
      return response(timelineView(sources, { at: latest.at_unix_ms, oldestAt,
        latestAt: latest.at_unix_ms, migration }));
    }
    if (request.pathname === "/api/host-context") return response(hostContext());
    throw new Error(`Unexpected timeline page source ${url}`);
  };
  const view = page(filename, fetcher, { timeline: true, now: 10000, ...options });
  return Object.assign(view, { calls, frames, ready: () => ready(view),
    async advance(ms = 1000) {
      const at = frames.at(-1).at_unix_ms + ms;
      frames.push(timelineFrame(frames.at(-1).seq + 1, at));
      view.setNow(at);
      await view.context.MitosisTimeline.refresh();
      await ready(view);
    } });
}

module.exports = { deferred, meta, collector, counters, migrations, stats, historySnapshot,
  statsResponse, system, response, page, settle, ready, hostContext, liveTimeline,
  timelineFrame, timelineArchive, timelineView };
