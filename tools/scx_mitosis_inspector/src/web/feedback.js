(function () {
  "use strict";

  const storageKey = "scx-mitosis-inspector-feedback-v1";
  const number = new Intl.NumberFormat("en-US");

  function ensureFeedbackShell() {
    if (!document.querySelector("#openFeedback")) {
      const button = document.createElement("button");
      button.className = "workspace-feedback-button";
      button.id = "openFeedback";
      button.type = "button";
      button.setAttribute("aria-controls", "feedbackDrawer");
      button.innerHTML = `
        <span>Review feedback</span>
        <span class="feedback-count" id="feedbackCount" aria-label="0 feedback drafts">0</span>`;
      document.querySelector(".workspace-sidebar")?.append(button);
    }
    if (!document.querySelector("#feedbackDrawer")) {
      const drawer = document.createElement("dialog");
      drawer.className = "feedback-drawer";
      drawer.id = "feedbackDrawer";
      drawer.setAttribute("aria-labelledby", "feedbackTitle");
      drawer.innerHTML = `
        <div class="feedback-drawer-surface">
          <header class="feedback-drawer-heading">
            <div>
              <h2 id="feedbackTitle">Feedback</h2>
              <p>Collected inspector change requests</p>
            </div>
            <button class="feedback-drawer-close" id="closeFeedback" type="button" aria-label="Close feedback">&times;</button>
          </header>
          <section class="feedback-workspace" aria-labelledby="feedbackTranscriptTitle">
            <header class="feedback-workspace-heading">
              <h3 id="feedbackTranscriptTitle">Collected feedback</h3>
              <div class="feedback-actions">
                <button id="copyFeedback" type="button" disabled>Copy</button>
                <button id="clearFeedback" type="button" disabled>Clear</button>
              </div>
            </header>
            <textarea id="feedbackTranscript" aria-label="Collected feedback" readonly spellcheck="false"></textarea>
            <p class="feedback-notice hidden" id="feedbackNotice" role="status" aria-live="polite"></p>
          </section>
        </div>`;
      document.body.append(drawer);
    }
  }

  function normalizeEntries(value) {
    if (!Array.isArray(value)) return [];
    const entries = [];
    for (const entry of value) {
      const key = typeof entry?.key === "string" ? entry.key.trim() : "";
      const text = typeof entry?.text === "string" ? entry.text.replace(/\r\n?/g, "\n") : "";
      if (!key || !text.trim()) continue;
      const existing = entries.findIndex((candidate) => candidate.key === key);
      if (existing >= 0) entries[existing] = { key, text };
      else entries.push({ key, text });
    }
    return entries;
  }

  function loadEntries() {
    try {
      return normalizeEntries(JSON.parse(localStorage.getItem(storageKey) || "[]"));
    } catch {
      return [];
    }
  }

  ensureFeedbackShell();
  const elements = {
    clear: document.querySelector("#clearFeedback"),
    close: document.querySelector("#closeFeedback"),
    copy: document.querySelector("#copyFeedback"),
    count: document.querySelector("#feedbackCount"),
    drawer: document.querySelector("#feedbackDrawer"),
    notice: document.querySelector("#feedbackNotice"),
    open: document.querySelector("#openFeedback"),
    transcript: document.querySelector("#feedbackTranscript"),
  };
  const state = { entries: loadEntries(), expandedKeys: new Set() };

  function showNotice(message, error = false) {
    elements.notice.textContent = message;
    elements.notice.classList.remove("hidden");
    elements.notice.classList.toggle("error", error);
  }

  function persistEntries() {
    try {
      if (state.entries.length === 0) localStorage.removeItem(storageKey);
      else localStorage.setItem(storageKey, JSON.stringify(state.entries));
    } catch {
      showNotice("Feedback could not be saved in this browser.", true);
    }
  }

  function entryFor(key) {
    return state.entries.find((entry) => entry.key === key) || null;
  }

  function transcript() {
    return state.entries
      .filter((entry) => entry.text.trim())
      .map((entry) => `[${entry.key}] ${entry.text.trim()}`)
      .join("\n\n");
  }

  function decorateTarget(target) {
    const key = target.dataset.feedbackKey;
    if (!key) return;
    target.classList.add("feedback-target");
    const heading = [...target.children].find((child) => child.matches(
      "header, .view-heading, .table-section-heading, .section-heading",
    ));
    let button = [...target.querySelectorAll("[data-feedback-toggle]")]
      .find((candidate) => candidate.dataset.feedbackToggle === key);
    if (!button) {
      button = document.createElement("button");
      button.type = "button";
      button.className = "feedback-button";
      button.dataset.feedbackToggle = key;
      button.innerHTML = `
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor"
          stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <path d="M6 8.5a6.5 6.5 0 1 1 13 0c0 6-6 6-6 10a3.5 3.5 0 1 1-7 0"></path>
          <path d="M15 8.5a2.5 2.5 0 0 0-5 0v1a2 2 0 1 1 0 4"></path>
        </svg>`;
      button.title = "Leave feedback";
      button.setAttribute("aria-label", `Leave feedback on ${key}`);
      if (heading) {
        heading.classList.add("feedback-heading");
        heading.append(button);
      } else {
        button.classList.add("floating");
        target.prepend(button);
      }
    }
    const expanded = state.expandedKeys.has(key);
    button.classList.toggle("has-feedback", Boolean(entryFor(key)));
    button.setAttribute("aria-expanded", String(expanded));
    const composerId = `feedback-${key.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
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
      input.value = entryFor(key)?.text || "";
      input.dataset.feedbackInput = key;
      input.setAttribute("aria-label", `Feedback on ${key}`);
      composer.append(input);
      if (heading) heading.after(composer);
      else button.after(composer);
    }
  }

  function render() {
    const text = transcript();
    const count = state.entries.length;
    elements.transcript.value = text;
    elements.copy.disabled = !text;
    elements.clear.disabled = !text && state.expandedKeys.size === 0;
    elements.count.textContent = number.format(count);
    elements.count.classList.toggle("has-feedback", count > 0);
    elements.count.setAttribute(
      "aria-label",
      `${number.format(count)} feedback ${count === 1 ? "draft" : "drafts"}`,
    );
    document.querySelectorAll("[data-feedback-key]").forEach(decorateTarget);
  }

  function update(key, text) {
    const normalized = String(text ?? "").replace(/\r\n?/g, "\n");
    const index = state.entries.findIndex((entry) => entry.key === key);
    if (!normalized.trim()) {
      if (index >= 0) state.entries.splice(index, 1);
    } else if (index >= 0) state.entries[index] = { key, text: normalized };
    else state.entries.push({ key, text: normalized });
    persistEntries();
    render();
  }

  function toggle(key) {
    const opening = !state.expandedKeys.has(key);
    if (opening) state.expandedKeys.add(key);
    else state.expandedKeys.delete(key);
    render();
    if (opening) requestAnimationFrame(() => {
      const input = [...document.querySelectorAll("[data-feedback-input]")]
        .find((candidate) => candidate.dataset.feedbackInput === key);
      input?.focus();
      input?.setSelectionRange(input.value.length, input.value.length);
    });
  }

  async function copy() {
    const text = elements.transcript.value;
    if (!text) return;
    let copied = false;
    try {
      await navigator.clipboard.writeText(text);
      copied = true;
    } catch {
      elements.transcript.focus();
      elements.transcript.select();
      try {
        copied = document.execCommand("copy");
      } catch {
        copied = false;
      }
    }
    showNotice(copied ? "Feedback copied." : "Copy failed; feedback text is selected.", !copied);
  }

  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-feedback-toggle]");
    if (button) toggle(button.dataset.feedbackToggle);
  });
  document.addEventListener("input", (event) => {
    const input = event.target.closest("[data-feedback-input]");
    if (input) update(input.dataset.feedbackInput, input.value);
  });
  elements.open.addEventListener("click", () => {
    render();
    if (typeof elements.drawer.showModal === "function") elements.drawer.showModal();
    else elements.drawer.setAttribute("open", "");
  });
  elements.close.addEventListener("click", () => {
    if (typeof elements.drawer.close === "function") elements.drawer.close();
    else elements.drawer.removeAttribute("open");
  });
  elements.copy.addEventListener("click", copy);
  elements.clear.addEventListener("click", () => {
    if (!window.confirm("Clear all collected feedback?")) return;
    state.entries = [];
    state.expandedKeys.clear();
    persistEntries();
    render();
    showNotice("Feedback cleared.");
  });
  render();
})();
