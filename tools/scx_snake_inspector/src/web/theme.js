// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

export const THEME_STORAGE_KEY = "scx-snake-inspector-theme-v1";

const THEME_PREFERENCES = new Set(["light", "system", "dark"]);

export function normalizeThemePreference(value) {
  return THEME_PREFERENCES.has(value) ? value : "system";
}

export function resolveTheme(preference, systemDark) {
  const normalized = normalizeThemePreference(preference);
  return normalized === "system" ? (systemDark ? "dark" : "light") : normalized;
}

export function loadThemePreference(storage) {
  try {
    return normalizeThemePreference(storage?.getItem(THEME_STORAGE_KEY));
  } catch (_error) {
    return "system";
  }
}

export function saveThemePreference(storage, preference) {
  try {
    storage?.setItem(THEME_STORAGE_KEY, normalizeThemePreference(preference));
  } catch (_error) {
    // A blocked storage API should not prevent an in-page theme change.
  }
}

export function applyThemeToDocument({ root, controls, theme, repaint }) {
  root.dataset.theme = theme.preference;
  root.dataset.resolvedTheme = theme.resolved;
  for (const control of controls) {
    control.checked = control.dataset.themePreference === theme.preference;
  }
  repaint();
}

export function createThemeController({
  preference = "system",
  systemDark = false,
  onApply = () => {},
  onPersist = () => {},
} = {}) {
  let selected = normalizeThemePreference(preference);
  let prefersDark = Boolean(systemDark);

  function current() {
    return {
      preference: selected,
      resolved: resolveTheme(selected, prefersDark),
    };
  }

  function apply() {
    const state = current();
    onApply(state);
    return state;
  }

  apply();

  return {
    select(preferenceValue) {
      selected = normalizeThemePreference(preferenceValue);
      onPersist(selected);
      return apply();
    },
    systemChanged(dark) {
      prefersDark = Boolean(dark);
      return selected === "system" ? apply() : current();
    },
    current,
  };
}
