// The Lockbox icon inside focused login fields and its dropdown, isolated in a shadow root.
import type { Candidate, State } from "./client";

export interface MenuActions {
  list(): Promise<{ state: State; items: Candidate[] }>;
  fill(itemId: string): Promise<void>;
  unlock(): Promise<void>;
}

const KEYHOLE = `<svg viewBox="0 0 24 24" width="14" height="14" aria-hidden="true"><circle cx="12" cy="9" r="4" fill="currentColor"/><path d="M10.2 11.5h3.6l1.2 8h-6z" fill="currentColor"/></svg>`;

const STYLE = `
:host { all: initial; }
* { box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", system-ui, sans-serif; }
.icon { position: fixed; z-index: 2147483646; width: 24px; height: 24px; border-radius: 7px; border: 0; padding: 0;
  display: grid; place-items: center; background: #111; color: #fff; cursor: pointer; box-shadow: 0 1px 3px rgba(0,0,0,.25);
  transition: transform 120ms cubic-bezier(.2,.8,.2,1), opacity 120ms; }
.icon:hover { transform: scale(1.08); }
.panel { position: fixed; z-index: 2147483647; min-width: 260px; max-width: 340px; padding: 6px; border-radius: 16px;
  background: rgba(255,255,255,.96); color: #111; box-shadow: 0 12px 40px rgba(17,17,17,.2), 0 2px 6px rgba(17,17,17,.08);
  backdrop-filter: blur(20px); animation: pop 160ms cubic-bezier(.2,.8,.2,1); font-size: 13px; }
@media (prefers-color-scheme: dark) { .panel { background: rgba(32,32,34,.96); color: #f5f5f7; } .icon { background: #f5f5f7; color: #111; } }
@keyframes pop { from { opacity: 0; transform: translateY(-4px) scale(.98); } to { opacity: 1; transform: none; } }
.item, .unlock { width: 100%; display: flex; align-items: center; gap: 10px; padding: 8px 10px; border: 0; border-radius: 10px;
  background: transparent; color: inherit; text-align: left; cursor: pointer; font-size: 13px; }
.item:hover, .item:focus-visible, .unlock:hover { background: rgba(127,127,127,.14); outline: none; }
.mono { width: 28px; height: 28px; border-radius: 8px; display: grid; place-items: center; flex-shrink: 0;
  background: rgba(127,127,127,.16); font-weight: 800; text-transform: uppercase; }
.text { display: flex; flex-direction: column; min-width: 0; }
.title { font-weight: 600; } .sub { opacity: .6; font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.note { padding: 10px; opacity: .7; }
@media (prefers-reduced-motion: reduce) { .panel { animation: none; } .icon { transition: none; } }
`;

export interface MenuOptions {
  /** Receives the (closed) shadow root; for tests only. */
  onRoot?: (root: ShadowRoot) => void;
  /** Whether an event comes from the user. Defaults to `isTrusted`. */
  trusted?: (e: Event) => boolean;
  /** Whether the menu is really visible to the user (anti-clickjacking). */
  visible?: (e: MouseEvent, host: HTMLElement, target: HTMLElement) => boolean;
  /** Item clicks sooner than this after the panel opened are ignored. */
  settleMs?: number;
}

/** True for filters that hide or wash out the page; invert() (Dark Reader) and the like are fine. */
function hidingFilter(filter: string): boolean {
  if (!filter || filter === "none") return false;
  if (/opacity\(/.test(filter)) return true;
  for (const m of filter.matchAll(/(brightness|contrast)\(\s*([\d.]+)(%?)/g)) {
    const v = parseFloat(m[2]) / (m[3] ? 100 : 1);
    if (v < 0.5) return true;
  }
  return false;
}

function plain(v: string): boolean {
  return !v || v === "none";
}

/** A click only counts if the user could see the menu: not hidden, faded, masked, clipped, filtered or covered. */
function defaultVisible(_e: MouseEvent, host: HTMLElement, target: HTMLElement): boolean {
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

export class InlineMenu {
  private host: HTMLElement;
  private root: ShadowRoot;
  private icon: HTMLButtonElement;
  private panel: HTMLDivElement | null = null;
  private openedAt = 0;
  private field: HTMLInputElement | null = null;
  private watched = new WeakSet<HTMLInputElement>();
  private trusted: (e: Event) => boolean;
  private visible: (e: MouseEvent, host: HTMLElement, target: HTMLElement) => boolean;
  private seen = new Map<Element, boolean | undefined>();
  private observer: IntersectionObserver | null = null;
  private settleMs: number;

  constructor(
    private actions: MenuActions,
    options: MenuOptions = {},
  ) {
    this.trusted = options.trusted ?? ((e) => e.isTrusted);
    this.visible = options.visible ?? defaultVisible;
    this.settleMs = options.settleMs ?? 300;
    this.host = document.createElement("lockbox-inline");
    this.host.style.setProperty("opacity", "1", "important");
    // Closed: page scripts cannot reach in and click the buttons.
    this.root = this.host.attachShadow({ mode: "closed" });
    options.onRoot?.(this.root);
    const style = document.createElement("style");
    style.textContent = STYLE;
    this.icon = document.createElement("button");
    this.icon.className = "icon";
    this.icon.type = "button";
    this.icon.setAttribute("aria-label", "Fill with Lockbox");
    this.icon.innerHTML = KEYHOLE;
    this.icon.hidden = true;
    this.icon.addEventListener("mousedown", (e) => e.preventDefault());
    this.observe(this.icon);
    this.icon.addEventListener("click", (e) => {
      if (this.allowed(e)) void this.open();
    });
    this.root.append(style, this.icon);
    document.documentElement.append(this.host);
    window.addEventListener("scroll", () => this.place(), true);
    window.addEventListener("resize", () => this.place());
    document.addEventListener("mousedown", (e) => {
      if (e.composedPath().includes(this.host)) return;
      this.close();
      if (this.field !== document.activeElement) this.icon.hidden = true;
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && this.panel) this.close();
    });
  }

  /** Chromium can tell whether anything covers an element (trackVisibility); elsewhere this is a no-op. */
  private observe(el: Element): void {
    if (typeof IntersectionObserver !== "function") return;
    this.observer ??= new IntersectionObserver(
      (entries) => {
        for (const entry of entries) this.seen.set(entry.target, "isVisible" in entry ? (entry as any).isVisible === true : undefined);
      },
      { trackVisibility: true, delay: 100, threshold: [1] } as IntersectionObserverInit,
    );
    this.observer.observe(el);
  }

  private allowed(e: MouseEvent): boolean {
    const target = e.currentTarget as HTMLElement;
    if (!this.trusted(e) || !this.visible(e, this.host, target)) return false;
    if (!this.observer) return true;
    // The icon and the panel (which holds the items) must both have been reported fully visible, if the browser says.
    const watched = target === this.icon ? [target] : [target, this.panel];
    return watched.every((el) => !el || this.seen.get(el) !== false);
  }

  /** In a modal <dialog> only the dialog's subtree is interactive, so the host has to live there. */
  private attach(field: HTMLInputElement): void {
    let parent: HTMLElement = document.documentElement;
    try {
      parent = field.closest<HTMLElement>("dialog:modal") ?? parent;
    } catch {
      /* :modal unsupported */
    }
    if (this.host.parentNode !== parent) parent.append(this.host);
  }

  watch(field: HTMLInputElement): void {
    if (this.watched.has(field)) return;
    this.watched.add(field);
    const show = () => {
      this.field = field;
      this.attach(field);
      this.icon.hidden = false;
      this.place();
    };
    field.addEventListener("focus", show);
    if (document.activeElement === field) show();
    field.addEventListener("blur", () => setTimeout(() => !this.panel && (this.icon.hidden = true), 150));
  }

  async open(): Promise<void> {
    this.close();
    const panel = document.createElement("div");
    panel.className = "panel";
    panel.setAttribute("role", "menu");
    panel.append(note("Loading…"));
    this.root.append(panel);
    this.panel = panel;
    this.observe(panel);
    this.openedAt = Date.now();
    this.place();
    let result: { state: State; items: Candidate[] };
    try {
      result = await this.actions.list();
    } catch {
      if (this.panel === panel) panel.replaceChildren(note("Lockbox was updated — reload the page."));
      return;
    }
    if (this.panel !== panel) return;
    const { state, items } = result;
    panel.replaceChildren();
    const unlock = (label: string) =>
      button("unlock", label, (e) => {
        if (this.allowed(e)) void this.actions.unlock().catch(() => {});
      });
    if (state === "locked") {
      panel.append(note("Lockbox is locked"), unlock("Unlock Lockbox"));
    } else if (state === "unpaired" || state === "pairing") {
      panel.append(note("Connect this browser: open the Lockbox extension in the toolbar."));
    } else if (state === "noApp") {
      panel.append(note("Lockbox isn't running."), unlock("Open Lockbox"));
    } else if (items.length === 0) {
      panel.append(note("No logins for this site"));
    } else {
      for (const item of items) {
        panel.append(
          entry(item, (e) => {
            if (!this.allowed(e) || Date.now() - this.openedAt < this.settleMs) return;
            void this.choose(item.id);
          }),
        );
      }
    }
  }

  close(): void {
    if (this.panel) {
      this.observer?.unobserve(this.panel);
      this.seen.delete(this.panel);
    }
    this.panel?.remove();
    this.panel = null;
  }

  private async choose(itemId: string): Promise<void> {
    this.close();
    this.icon.hidden = true;
    try {
      await this.actions.fill(itemId);
    } catch {
      /* the page was reloaded or the extension updated */
    }
  }

  private place(): void {
    if (!this.field) return;
    const r = this.field.getBoundingClientRect();
    this.icon.style.left = `${r.right - 30}px`;
    this.icon.style.top = `${r.top + (r.height - 24) / 2}px`;
    if (this.panel) {
      this.panel.style.left = `${Math.max(8, r.right - 300)}px`;
      this.panel.style.top = `${r.bottom + 6}px`;
    }
  }
}

function note(text: string): HTMLElement {
  const el = document.createElement("div");
  el.className = "note";
  el.textContent = text;
  return el;
}

function button(className: string, text: string, onClick: (e: MouseEvent) => void): HTMLButtonElement {
  const b = document.createElement("button");
  b.type = "button";
  b.className = className;
  b.textContent = text;
  b.addEventListener("click", onClick);
  return b;
}

function entry(item: Candidate, onClick: (e: MouseEvent) => void): HTMLButtonElement {
  const b = button("item", "", onClick);
  b.setAttribute("role", "menuitem");
  const mono = document.createElement("span");
  mono.className = "mono";
  mono.textContent = item.title.match(/[\p{L}\p{N}]/u)?.[0] ?? "•";
  const text = document.createElement("span");
  text.className = "text";
  const title = document.createElement("span");
  title.className = "title";
  title.textContent = item.title;
  const sub = document.createElement("span");
  sub.className = "sub";
  sub.textContent = item.username + (item.hasTotp ? " · one-time code" : "");
  text.append(title, sub);
  b.append(mono, text);
  return b;
}
