// Shared anti-clickjacking checks for the in-page UI (inline menu, save bar).

/** True for filters that hide or wash out the page; invert() (Dark Reader) and the like are fine. */
export function hidingFilter(filter: string): boolean {
  if (!filter || filter === "none") return false;
  if (/opacity\(/.test(filter)) return true;
  for (const m of filter.matchAll(/(brightness|contrast)\(\s*([\d.]+)(%?)/g)) {
    const v = parseFloat(m[2]) / (m[3] ? 100 : 1);
    if (v < 0.5) return true;
  }
  return false;
}

export function plain(v: string): boolean {
  return !v || v === "none";
}

/** A click only counts if the user could see the menu: not hidden, faded, masked, clipped, filtered or covered. */
export function defaultVisible(_e: MouseEvent, host: HTMLElement, target: HTMLElement): boolean {
  if (host.hasAttribute("tabindex")) return false;
  if (host.checkVisibility?.({ opacityProperty: true, visibilityProperty: true } as any) === false) return false;
  const hs = getComputedStyle(host);
  const ds = getComputedStyle(document.documentElement);
  for (const cs of [hs, ds]) {
    if (parseFloat(cs.opacity) < 0.9) return false;
    if (hidingFilter(cs.filter)) return false;
    if (!plain(cs.getPropertyValue("mask-image")) || !plain(cs.getPropertyValue("-webkit-mask-image"))) return false;
    if (!plain(cs.getPropertyValue("clip-path"))) return false;
    const blend = cs.getPropertyValue("mix-blend-mode");
    if (blend && blend !== "normal") return false;
  }
  if (!plain(hs.transform)) return false;
  // Hit-test the centre of the activated button: whatever is on top there must be our host.
  const r = target.getBoundingClientRect();
  if (r.width > 0 && r.height > 0 && typeof document.elementFromPoint === "function") {
    const hit = document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2);
    if (hit !== host) return false;
  }
  return true;
}

/** Chromium can tell whether anything covers an element (trackVisibility); elsewhere this is a no-op.
 * Keep the UI free of transforms, filters and backdrop-filter: they make Chromium report it invisible. */
export class VisibilityTracker {
  private seen = new Map<Element, boolean | undefined>();
  private observer: IntersectionObserver | null = null;

  /** Whether the browser provides visibility tracking at all. */
  get active(): boolean {
    return this.observer !== null;
  }

  observe(el: Element): void {
    if (typeof IntersectionObserver !== "function") return;
    this.observer ??= new IntersectionObserver(
      (entries) => {
        for (const entry of entries) this.seen.set(entry.target, "isVisible" in entry ? (entry as any).isVisible === true : undefined);
      },
      { trackVisibility: true, delay: 100, threshold: [1] } as IntersectionObserverInit,
    );
    this.observer.observe(el);
  }

  unobserve(el: Element): void {
    this.observer?.unobserve(el);
    this.seen.delete(el);
  }

  /** False only when the browser reported the element as covered or hidden. */
  ok(el: Element | null): boolean {
    return !el || !this.observer || this.seen.get(el) !== false;
  }
}
