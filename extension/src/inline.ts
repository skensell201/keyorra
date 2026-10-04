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

export class InlineMenu {
  private host: HTMLElement;
  private root: ShadowRoot;
  private icon: HTMLButtonElement;
  private panel: HTMLDivElement | null = null;
  private field: HTMLInputElement | null = null;

  constructor(private actions: MenuActions) {
    this.host = document.createElement("lockbox-inline");
    this.root = this.host.attachShadow({ mode: "open" });
    const style = document.createElement("style");
    style.textContent = STYLE;
    this.icon = document.createElement("button");
    this.icon.className = "icon";
    this.icon.type = "button";
    this.icon.setAttribute("aria-label", "Fill with Lockbox");
    this.icon.innerHTML = KEYHOLE;
    this.icon.hidden = true;
    this.icon.addEventListener("mousedown", (e) => e.preventDefault());
    this.icon.addEventListener("click", () => this.open());
    this.root.append(style, this.icon);
    document.documentElement.append(this.host);
    window.addEventListener("scroll", () => this.place(), true);
    window.addEventListener("resize", () => this.place());
    document.addEventListener("mousedown", (e) => {
      if (!e.composedPath().includes(this.host)) this.close();
    });
  }

  watch(field: HTMLInputElement): void {
    if (field.dataset.lockbox) return;
    field.dataset.lockbox = "1";
    field.addEventListener("focus", () => {
      this.field = field;
      this.icon.hidden = false;
      this.place();
    });
    field.addEventListener("blur", () => setTimeout(() => !this.panel && (this.icon.hidden = true), 150));
  }

  async open(): Promise<void> {
    this.close();
    const panel = document.createElement("div");
    panel.className = "panel";
    panel.setAttribute("role", "listbox");
    panel.append(note("Loading…"));
    this.root.append(panel);
    this.panel = panel;
    this.place();
    const { state, items } = await this.actions.list();
    if (this.panel !== panel) return;
    panel.replaceChildren();
    if (state === "locked") {
      panel.append(note("Lockbox is locked"), button("unlock", "Unlock Lockbox", () => this.actions.unlock()));
    } else if (state === "unpaired") {
      panel.append(note("Connect this browser: open the Lockbox extension in the toolbar."));
    } else if (state === "noApp") {
      panel.append(note("Lockbox isn't running."), button("unlock", "Open Lockbox", () => this.actions.unlock()));
    } else if (items.length === 0) {
      panel.append(note("No logins for this site"));
    } else {
      for (const item of items) panel.append(entry(item, () => this.choose(item.id)));
    }
  }

  close(): void {
    this.panel?.remove();
    this.panel = null;
  }

  private async choose(itemId: string): Promise<void> {
    this.close();
    this.icon.hidden = true;
    await this.actions.fill(itemId);
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

function button(className: string, text: string, onClick: () => void): HTMLButtonElement {
  const b = document.createElement("button");
  b.type = "button";
  b.className = className;
  b.textContent = text;
  b.addEventListener("click", onClick);
  return b;
}

function entry(item: Candidate, onClick: () => void): HTMLButtonElement {
  const b = button("item", "", onClick);
  b.setAttribute("role", "option");
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
