export type Theme = "doppler" | "index";

export const THEMES: { id: Theme; label: string }[] = [
  { id: "doppler", label: "Doppler" },
  { id: "index", label: "Index" },
];

const KEY = "lockbox.theme";

/** The saved theme; storage can be unavailable, so fall back to the default. */
export function loadTheme(): Theme {
  try {
    const saved = localStorage.getItem(KEY);
    return saved === "index" ? "index" : "doppler";
  } catch {
    return "doppler";
  }
}

export function applyTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
  try {
    localStorage.setItem(KEY, theme);
  } catch {
    // Appearance is a convenience; not saving it is fine.
  }
}
