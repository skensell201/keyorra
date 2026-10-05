export type Theme = "system" | "light" | "dark" | "index";
type Resolved = Exclude<Theme, "system">;

export const THEMES: { id: Theme; label: string }[] = [
  { id: "system", label: "System" },
  { id: "light", label: "Light" },
  { id: "dark", label: "Dark" },
  { id: "index", label: "Index" },
];

const KEY = "keepsake.theme";
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
  if (theme === "system") {
    // Let the window follow macOS again, so prefers-color-scheme reports the real appearance.
    setWindowTheme(null);
    paint(resolve("system"));
    if (typeof window.matchMedia === "function") {
      const query = window.matchMedia(DARK_QUERY);
      const onChange = () => paint(resolve("system"));
      query.addEventListener?.("change", onChange);
      stopFollowing = () => query.removeEventListener?.("change", onChange);
    }
  } else {
    paint(theme);
    // The window's vibrancy material follows the window appearance, so keep it in step.
    setWindowTheme(theme === "light" ? "light" : "dark");
  }
  try {
    localStorage.setItem(KEY, theme);
  } catch {
    // Appearance is a convenience; not saving it is fine.
  }
}

function paint(resolved: Resolved): void {
  document.documentElement.dataset.theme = resolved;
}

function setWindowTheme(theme: "light" | "dark" | null): void {
  if (!("__TAURI_INTERNALS__" in window)) return;
  import("@tauri-apps/api/window")
    .then(({ getCurrentWindow }) => getCurrentWindow().setTheme(theme))
    .catch(() => {});
}
