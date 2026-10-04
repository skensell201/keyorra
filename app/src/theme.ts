export type Theme = "system" | "light" | "dark" | "index";
type Resolved = Exclude<Theme, "system">;

export const THEMES: { id: Theme; label: string }[] = [
  { id: "system", label: "System" },
  { id: "light", label: "Light" },
  { id: "dark", label: "Dark" },
  { id: "index", label: "Index" },
];

const KEY = "lockbox.theme";
const DARK_QUERY = "(prefers-color-scheme: dark)";

/** The saved theme; storage can be unavailable, so fall back to following the system. */
export function loadTheme(): Theme {
  try {
    const saved = localStorage.getItem(KEY);
    return THEMES.some((t) => t.id === saved) ? (saved as Theme) : "system";
  } catch {
    return "system";
  }
}

function systemIsDark(): boolean {
  return typeof window.matchMedia === "function" && window.matchMedia(DARK_QUERY).matches;
}

function resolve(theme: Theme): Resolved {
  if (theme !== "system") return theme;
  return systemIsDark() ? "dark" : "light";
}

let stopFollowing: (() => void) | null = null;

/** Applies and remembers the theme; "system" keeps following macOS appearance changes. */
export function applyTheme(theme: Theme): void {
  stopFollowing?.();
  stopFollowing = null;
  paint(resolve(theme));
  if (theme === "system" && typeof window.matchMedia === "function") {
    const query = window.matchMedia(DARK_QUERY);
    const onChange = () => paint(resolve("system"));
    query.addEventListener?.("change", onChange);
    stopFollowing = () => query.removeEventListener?.("change", onChange);
  }
  try {
    localStorage.setItem(KEY, theme);
  } catch {
    // Appearance is a convenience; not saving it is fine.
  }
}

function paint(resolved: Resolved): void {
  document.documentElement.dataset.theme = resolved;
  // The window's vibrancy material follows the window appearance, so keep it in step.
  if ("__TAURI_INTERNALS__" in window) {
    import("@tauri-apps/api/window")
      .then(({ getCurrentWindow }) => getCurrentWindow().setTheme(resolved === "light" ? "light" : "dark"))
      .catch(() => {});
  }
}
