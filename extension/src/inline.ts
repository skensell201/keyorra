// The Keyorra icon inside focused login fields and its dropdown, isolated in a shadow root.
import type { Candidate, CardSummary, IdentitySummary, State } from "./client";
import { defaultVisible, VisibilityTracker } from "./visibility";

export type MenuMode = "logins" | "generator" | "cards" | "identities";

export interface MenuActions {
  list(): Promise<{ state: State; items: Candidate[] }>;
  fill(itemId: string): Promise<void>;
  unlock(): Promise<void>;
  generate(): Promise<{ state: State; value: string }>;
  useGenerated(value: string, field: HTMLInputElement): Promise<void>;
  cards(): Promise<{ state: State; items: CardSummary[] }>;
  fillCard(itemId: string, field: HTMLInputElement): Promise<void>;
  identities(): Promise<{ state: State; items: IdentitySummary[] }>;
  fillIdentity(itemId: string, field: HTMLInputElement): Promise<void>;
}

const KEYHOLE = `<svg viewBox="0 0 24 24" width="14" height="14" aria-hidden="true"><circle cx="12" cy="9" r="4" fill="currentColor"/><path d="M10.2 11.5h3.6l1.2 8h-6z" fill="currentColor"/></svg>`;

const STYLE = `
:host { all: initial; }
* { box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", system-ui, sans-serif; }
.icon { position: fixed; z-index: 2147483646; width: 24px; height: 24px; border-radius: 7px; border: 0; padding: 0;
  display: grid; place-items: center; background: #111; color: #fff; cursor: pointer; box-shadow: 0 1px 3px rgba(0,0,0,.25);
  transition: box-shadow 120ms; }
.icon[hidden], .panel[hidden] { display: none !important; }
.icon:hover { filter: none; box-shadow: 0 1px 6px rgba(0,0,0,.35); }
.panel { position: fixed; z-index: 2147483647; min-width: 260px; max-width: 340px; padding: 6px; border-radius: 16px;
  background: rgba(255,255,255,.96); color: #111; box-shadow: 0 12px 40px rgba(17,17,17,.2), 0 2px 6px rgba(17,17,17,.08);
  animation: pop 160ms cubic-bezier(.2,.8,.2,1); font-size: 13px; }
@media (prefers-color-scheme: dark) { .panel { background: rgba(32,32,34,.96); color: #f5f5f7; } .icon { background: #f5f5f7; color: #111; } }
@keyframes pop { from { opacity: 0; transform: translateY(-4px) scale(.98); } to { opacity: 1; transform: none; } }
.item, .unlock { width: 100%; display: flex; align-items: center; gap: 10px; padding: 8px 10px; border: 0; border-radius: 10px;
  background: transparent; color: inherit; text-align: left; cursor: pointer; font-size: 13px; }
.item:hover, .item:focus-visible, .unlock:hover { background: rgba(127,127,127,.14); outline: none; }
.mono { width: 28px; height: 28px; border-radius: 8px; display: grid; place-items: center; flex-shrink: 0;
  background: rgba(127,127,127,.16); font-weight: 800; text-transform: uppercase; }
.text { display: flex; flex-direction: column; min-width: 0; }
.title { font-weight: 600; } .sub { opacity: .6; font-size: 12px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.generated { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; opacity: .7; white-space: nowrap; }
.note { padding: 10px; opacity: .7; }
@media (prefers-reduced-motion: reduce) { .panel { animation: none; } .icon { transition: none; } }
`;

export interface MenuOptions {
  /** Receives the (closed) shadow root; for tests only. */
  onRoot?: (root: ShadowRoot) => void;
  /** Whether an event comes from the user. Defaults to `isTrusted`. */
  trusted?: (e: Event) => boolean;
  /** Whether the menu is really visible to the user (anti-clickjacking). */
  visible?: (e: MouseEvent, host: HTMLElement, target: HTMLElement, parent: Node | null) => boolean;
  /** Item clicks sooner than this after the panel opened are ignored. */
  settleMs?: number;
  /** Without visibility tracking, cards and addresses need a second click at least this long after the first. */
  confirmMs?: number;
  /** How long the "Click again to fill" prompt stays. */
  confirmWindowMs?: number;
}

/** Loopback, *.localhost and private addresses count as secure, like in the app. */
export function secureHost(loc: { protocol: string; hostname?: string }): boolean {
  if (loc.protocol === "https:") return true;
  const host = (loc.hostname ?? "").toLowerCase().replace(/^\[|\]$/g, "");
  if (host === "localhost" || host.endsWith(".localhost")) return true;
  const v4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    return a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
  }
  if (host === "::1") return true;
  return /^f[cd][0-9a-f]{0,2}:/.test(host);
}

export class InlineMenu {
  private host: HTMLElement;
  private root: ShadowRoot;
  private icon: HTMLButtonElement;
  private panel: HTMLDivElement | null = null;
  private openedAt = 0;
  private field: HTMLInputElement | null = null;
  private watched = new WeakSet<HTMLInputElement>();
  private modes = new WeakMap<HTMLInputElement, MenuMode>();
  private trusted: (e: Event) => boolean;
  private visible: (e: MouseEvent, host: HTMLElement, target: HTMLElement, parent: Node | null) => boolean;
  private tracker = new VisibilityTracker();
  private settleMs: number;
  private confirmMs: number;
  private confirmWindowMs: number;
  /** Where the host was attached; a page that moves it is refused. */
  private parent: Node | null = null;
  private armed: { button: HTMLElement; at: number; timer: ReturnType<typeof setTimeout>; restore: () => void } | null = null;

  constructor(
    private actions: MenuActions,
    options: MenuOptions = {},
  ) {
    this.trusted = options.trusted ?? ((e) => e.isTrusted);
    this.visible = options.visible ?? defaultVisible;
    this.settleMs = options.settleMs ?? 300;
    this.confirmMs = options.confirmMs ?? 300;
    this.confirmWindowMs = options.confirmWindowMs ?? 3000;
    this.host = document.createElement("keyorra-inline");
    this.host.style.setProperty("opacity", "1", "important");
    // Closed: page scripts cannot reach in and click the buttons.
    this.root = this.host.attachShadow({ mode: "closed" });
    options.onRoot?.(this.root);
    const style = document.createElement("style");
    style.textContent = STYLE;
    this.icon = document.createElement("button");
    this.icon.className = "icon";
    this.icon.type = "button";
    this.icon.setAttribute("aria-label", "Fill with Keyorra");
    this.icon.innerHTML = KEYHOLE;
    this.icon.hidden = true;
    this.icon.addEventListener("mousedown", (e) => e.preventDefault());
    this.observe(this.icon);
    this.icon.addEventListener("click", (e) => {
      if (this.allowed(e)) void this.open();
    });
    this.root.append(style, this.icon);
    document.documentElement.append(this.host);
    this.parent = document.documentElement;
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

  private observe(el: Element): void {
    this.tracker.observe(el);
  }

  private allowed(e: MouseEvent): boolean {
    const target = e.currentTarget as HTMLElement;
    if (!this.trusted(e) || !this.visible(e, this.host, target, this.parent)) return false;
    if (!this.tracker.active) return true;
    // The icon and the panel (which holds the items) must both have been reported fully visible, if the browser says.
    const watched = target === this.icon ? [target] : [target, this.panel];
    return watched.every((el) => this.tracker.ok(el));
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
    this.parent = parent;
  }

  isWatched(field: HTMLInputElement): boolean {
    return this.watched.has(field);
  }

  watch(field: HTMLInputElement, mode: MenuMode = "logins"): void {
    this.modes.set(field, mode);
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
    const field = this.field;
    const mode = (field && this.modes.get(field)) || "logins";
    let state: State;
    let items: { id: string; title: string; sub: string; mono?: boolean }[] = [];
    let generated = "";
    try {
      if (mode === "generator") {
        const r = await this.actions.generate();
        state = r.state;
        generated = r.value;
      } else if (mode === "cards") {
        const r = await this.actions.cards();
        state = r.state;
        items = r.items.map((c) => ({ id: c.id, title: c.title, sub: c.last4 ? `•••• ${c.last4}` : "" }));
      } else if (mode === "identities") {
        const r = await this.actions.identities();
        state = r.state;
        items = r.items.map((c) => ({ id: c.id, title: c.title, sub: c.detail }));
      } else {
        const r = await this.actions.list();
        state = r.state;
        items = r.items.map((c) => ({ id: c.id, title: c.title, sub: c.username + (c.hasTotp ? " · one-time code" : "") }));
      }
    } catch {
      if (this.panel === panel) panel.replaceChildren(note("Keyorra was updated — reload the page."));
      return;
    }
    if (this.panel !== panel) return;
    panel.replaceChildren();
    const unlock = (label: string) =>
      button("unlock", label, (e) => {
        if (this.allowed(e)) void this.actions.unlock().catch(() => {});
      });
    // Browsers without visibility tracking (Firefox, Safari) cannot tell that something covers the panel,
    // so cards and addresses need a second, deliberate click in our own panel.
    const pick = (run: () => Promise<void>, confirm = false) => (e: MouseEvent) => {
      if (!this.allowed(e) || Date.now() - this.openedAt < this.settleMs) return;
      if (confirm && !this.tracker.active && !this.confirmed(e.currentTarget as HTMLElement)) return;
      void this.choose(run);
    };
    if (state === "locked") {
      panel.append(note("Keyorra is locked"), unlock("Unlock Keyorra"));
    } else if (state === "unpaired" || state === "pairing") {
      panel.append(note("Connect this browser: open the Keyorra extension in the toolbar."));
    } else if (state === "noApp") {
      panel.append(note("Keyorra isn't running."), unlock("Open Keyorra"));
    } else if (mode === "generator") {
      if (!generated) {
        panel.append(note("Couldn't generate a password"));
        return;
      }
      panel.append(generatedEntry(generated, pick(() => (field ? this.actions.useGenerated(generated, field) : Promise.resolve()))));
    } else if (items.length === 0) {
      const secure = secureHost(location);
      panel.append(
        note(
          mode === "cards"
            ? secure ? "No cards in Keyorra" : "Cards are only filled on secure pages"
            : mode === "identities"
              ? secure ? "No addresses in Keyorra" : "Addresses are only filled on secure pages"
              : "No logins for this site",
        ),
      );
    } else {
      for (const item of items) {
        const run =
          mode === "cards"
            ? () => (field ? this.actions.fillCard(item.id, field) : Promise.resolve())
            : mode === "identities"
              ? () => (field ? this.actions.fillIdentity(item.id, field) : Promise.resolve())
              : () => this.actions.fill(item.id);
        panel.append(entry(item, pick(run, mode === "cards" || mode === "identities")));
      }
    }
  }

  /** First click arms the item ("Click again to fill"); a later click inside the window confirms. */
  private confirmed(button: HTMLElement): boolean {
    const now = Date.now();
    if (this.armed?.button === button && now - this.armed.at >= this.confirmMs) {
      this.disarm();
      return true;
    }
    if (this.armed?.button === button) return false; // too soon after the first click
    this.disarm();
    const title = button.querySelector(".title");
    const original = title?.textContent ?? "";
    if (title) title.textContent = "Click again to fill";
    const timer = setTimeout(() => this.disarm(), this.confirmWindowMs);
    this.armed = {
      button,
      at: now,
      timer,
      restore: () => {
        if (title) title.textContent = original;
      },
    };
    return false;
  }

  private disarm(): void {
    if (!this.armed) return;
    clearTimeout(this.armed.timer);
    this.armed.restore();
    this.armed = null;
  }

  close(): void {
    this.disarm();
    if (this.panel) {
      this.tracker.unobserve(this.panel);
    }
    this.panel?.remove();
    this.panel = null;
  }

  private async choose(run: () => Promise<void>): Promise<void> {
    this.close();
    this.icon.hidden = true;
    try {
      await run();
    } catch {
      /* the page was reloaded or the extension updated */
    }
  }

  private following = false;

  /** Pages move fields without scrolling (messages or results appearing above): follow while shown. */
  private follow(): void {
    if (this.following || typeof requestAnimationFrame !== "function") return;
    this.following = true;
    const tick = () => {
      if (this.icon.hidden && !this.panel) {
        this.following = false;
        return;
      }
      this.place();
      requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }

  private place(): void {
    if (!this.field) return;
    this.follow();
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

function entry(item: { title: string; sub: string }, onClick: (e: MouseEvent) => void): HTMLButtonElement {
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
  sub.textContent = item.sub;
  text.append(title, sub);
  b.append(mono, text);
  return b;
}

/** Middle-truncates so the ends stay recognisable. */
function shorten(value: string): string {
  return value.length > 18 ? `${value.slice(0, 8)}…${value.slice(-4)}` : value;
}

function generatedEntry(value: string, onClick: (e: MouseEvent) => void): HTMLButtonElement {
  const b = button("item", "", onClick);
  b.setAttribute("role", "menuitem");
  const mono = document.createElement("span");
  mono.className = "mono";
  mono.textContent = "✦";
  const text = document.createElement("span");
  text.className = "text";
  const title = document.createElement("span");
  title.className = "title";
  title.textContent = "Use a strong password";
  const sub = document.createElement("span");
  sub.className = "generated";
  sub.textContent = shorten(value);
  text.append(title, sub);
  b.append(mono, text);
  return b;
}
