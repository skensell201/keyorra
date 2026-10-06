import { useRef, type KeyboardEvent } from "react";

/**
 * Roving focus for a tablist: only the chosen tab is in the Tab order; the arrow keys of its
 * orientation move between tabs (wrapping), Home and End jump to the ends. Moving selects.
 */
export function useTabs<T extends string>(
  ids: readonly T[],
  current: T,
  select: (id: T) => void,
  orientation: "vertical" | "horizontal",
) {
  const tabs = useRef<Partial<Record<T, HTMLButtonElement | null>>>({});
  const [back, forward] = orientation === "vertical" ? ["ArrowUp", "ArrowDown"] : ["ArrowLeft", "ArrowRight"];

  function onKeyDown(e: KeyboardEvent<HTMLElement>) {
    const at = ids.indexOf(current);
    const next =
      e.key === forward
        ? (at + 1) % ids.length
        : e.key === back
          ? (at - 1 + ids.length) % ids.length
          : e.key === "Home"
            ? 0
            : e.key === "End"
              ? ids.length - 1
              : -1;
    if (next < 0) return;
    e.preventDefault();
    const id = ids[next];
    select(id);
    tabs.current[id]?.focus();
  }

  /** Props for one tab; `panel` is the id of the panel it controls. */
  function tab(id: T, panel: string) {
    return {
      ref: (el: HTMLButtonElement | null) => {
        tabs.current[id] = el;
      },
      role: "tab" as const,
      "aria-selected": current === id,
      "aria-controls": panel,
      tabIndex: current === id ? 0 : -1,
      onClick: () => select(id),
    };
  }

  return { onKeyDown, tab };
}

/** The name a tab is read with: its label, and how many things in it wait for you. */
export function tabName(label: string, count: number) {
  return count > 0 ? `${label}, ${count} ${count === 1 ? "needs" : "need"} attention` : label;
}
