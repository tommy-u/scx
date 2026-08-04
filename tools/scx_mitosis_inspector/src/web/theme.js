(function installMitosisTheme(root) {
  "use strict";

  const STORAGE_KEY = "mitosis-inspector-theme";
  const media = typeof root.matchMedia === "function"
    ? root.matchMedia("(prefers-color-scheme: dark)")
    : null;

  function storedTheme() {
    try {
      const value = root.localStorage?.getItem(STORAGE_KEY);
      return value === "dark" || value === "light" ? value : null;
    } catch {
      return null;
    }
  }

  function preferredTheme() {
    return storedTheme() || (media?.matches ? "dark" : "light");
  }

  function syncControls(theme) {
    root.document.querySelectorAll("[data-theme-toggle]").forEach((control) => {
      control.checked = theme === "dark";
    });
  }

  function applyTheme(theme, persist) {
    const next = theme === "dark" ? "dark" : "light";
    root.document.documentElement.dataset.theme = next;
    root.document.documentElement.style.colorScheme = next;
    syncControls(next);
    if (persist) {
      try {
        root.localStorage?.setItem(STORAGE_KEY, next);
      } catch {
        // Theme selection still works when browser storage is unavailable.
      }
    }
    root.document.dispatchEvent(new root.CustomEvent("mitosis-theme-change", {
      detail: { theme: next },
    }));
  }

  applyTheme(preferredTheme(), false);

  root.document.addEventListener("DOMContentLoaded", () => {
    syncControls(root.document.documentElement.dataset.theme);
    root.document.querySelectorAll("[data-theme-toggle]").forEach((control) => {
      control.addEventListener("change", () => {
        applyTheme(control.checked ? "dark" : "light", true);
      });
    });
  });

  media?.addEventListener?.("change", (event) => {
    if (!storedTheme()) applyTheme(event.matches ? "dark" : "light", false);
  });

  root.MitosisTheme = { apply: (theme) => applyTheme(theme, true) };
})(globalThis);
