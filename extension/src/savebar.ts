// "Save this login?" bar at the top-right of the page, isolated in a closed shadow root.
import type { LookupStatus } from "./client";
import { defaultVisible, VisibilityTracker } from "./visibility";

export interface SaveBarActions {
  save(): Promise<void>;
  dismiss(): void;
}

export interface SaveBarOptions {
  /** Receives the (closed) shadow root; for tests only. */
  onRoot?: (root: ShadowRoot) => void;
  /** Whether an event comes from the user. Defaults to `isTrusted`. */
  trusted?: (e: Event) => boolean;
  /** Whether the bar is really visible to the user (anti-clickjacking). */
  visible?: (e: MouseEvent, host: HTMLElement, target: HTMLElement, parent: Node | null) => boolean;
  /** Clicks sooner than this after the bar appeared are ignored. */
  settleMs?: number;
}

const AUTO_HIDE_MS = 30_000;

const STYLE = `
:host { all: initial; }
* { box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", system-ui, sans-serif; }
.bar { position: fixed; top: 16px; right: 16px; z-index: 2147483647; width: 320px; max-width: calc(100vw - 32px); padding: 14px;
  border-radius: 16px; background: rgba(255,255,255,.98); color: #111; font-size: 13px; line-height: 1.4;
  box-shadow: 0 12px 40px rgba(17,17,17,.2), 0 2px 6px rgba(17,17,17,.08); }
.msg { font-weight: 600; overflow-wrap: anywhere; }
.sub { opacity: .6; margin-top: 2px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.row { display: flex; gap: 8px; margin-top: 12px; justify-content: flex-end; }
button { border: 0; border-radius: 10px; padding: 7px 14px; font-size: 13px; cursor: pointer; background: rgba(127,127,127,.16); color: inherit; }
button:hover, button:focus-visible { filter: none; outline: 2px solid rgba(127,127,127,.4); }
.primary { background: #111; color: #fff; font-weight: 600; }
@media (prefers-color-scheme: dark) { .bar { background: rgba(32,32,34,.98); color: #f5f5f7; } .primary { background: #f5f5f7; color: #111; } }
`;

export class SaveBar {
  private host: HTMLElement;
  private root: ShadowRoot;
  private bar: HTMLDivElement | null = null;
  private shownAt = 0;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private trusted: (e: Event) => boolean;
  private visible: (e: MouseEvent, host: HTMLElement, target: HTMLElement, parent: Node | null) => boolean;
  private parent: Node | null = null;
  private hideMs = AUTO_HIDE_MS;
  private settleMs: number;
  private tracker = new VisibilityTracker();

  constructor(
    private actions: SaveBarActions,
    options: SaveBarOptions = {},
  ) {
    this.trusted = options.trusted ?? ((e) => e.isTrusted);
    this.visible = options.visible ?? defaultVisible;
    this.settleMs = options.settleMs ?? 300;
    this.host = document.createElement("lockbox-savebar");
    this.host.style.setProperty("opacity", "1", "important");
    // The host is in the page only while the bar is shown.
    this.root = this.host.attachShadow({ mode: "closed" });
    options.onRoot?.(this.root);
    const style = document.createElement("style");
    style.textContent = STYLE;
    this.root.append(style);
  }

  show(info: { username: string; status: Exclude<LookupStatus, "same"> }): void {
    this.hide();
    const update = info.status === "changed";
    const bar = document.createElement("div");
    bar.className = "bar";
    bar.setAttribute("role", "alertdialog");
    const msg = document.createElement("div");
    msg.className = "msg";
    msg.id = "msg";
    bar.setAttribute("aria-labelledby", "msg");
    msg.textContent = `${update ? "Update password for" : "Save login for"} ${location.host}?`;
    const sub = document.createElement("div");
    sub.className = "sub";
    sub.textContent = info.username;
    const row = document.createElement("div");
    row.className = "row";
    const no = this.button("", "Not now", () => {
      this.hide();
      this.actions.dismiss();
    });
    const yes = this.button("primary", update ? "Update" : "Save", () => void this.save(bar, msg, sub, row));
    row.append(no, yes);
    bar.append(msg);
    if (info.username) bar.append(sub);
    bar.append(row);
    this.root.append(bar);
    this.bar = bar;
    this.tracker.observe(bar);
    this.shownAt = Date.now();
    document.documentElement.append(this.host);
    this.parent = document.documentElement;
    // Reading the bar (pointer or keyboard focus) pauses the auto-hide.
    for (const ev of ["mouseenter", "focusin"]) bar.addEventListener(ev, () => clearTimeout(this.timer));
    for (const ev of ["mouseleave", "focusout"]) bar.addEventListener(ev, () => this.schedule(this.hideMs));
    document.addEventListener("keydown", this.onKey, true);
    this.schedule(AUTO_HIDE_MS);
  }

  hide(): void {
    clearTimeout(this.timer);
    document.removeEventListener("keydown", this.onKey, true);
    if (this.bar) this.tracker.unobserve(this.bar);
    this.bar?.remove();
    this.bar = null;
    this.host.remove();
  }

  private schedule(ms: number): void {
    clearTimeout(this.timer);
    this.hideMs = ms;
    this.timer = setTimeout(() => this.hide(), ms);
  }

  private onKey = (e: KeyboardEvent): void => {
    if (e.key !== "Escape" || !this.bar || !this.trusted(e)) return;
    this.hide();
    this.actions.dismiss();
  };

  private async save(bar: HTMLElement, msg: HTMLElement, sub: HTMLElement, row: HTMLElement): Promise<void> {
    let text = "Saved";
    try {
      await this.actions.save();
    } catch {
      text = "Couldn't save";
    }
    if (this.bar !== bar) return;
    row.remove();
    sub.remove();
    msg.textContent = text;
    this.schedule(2000);
  }

  private button(className: string, text: string, onClick: () => void): HTMLButtonElement {
    const b = document.createElement("button");
    b.type = "button";
    b.className = className;
    b.textContent = text;
    b.addEventListener("mousedown", (e) => e.preventDefault());
    b.addEventListener("click", (e) => {
      if (!this.allowed(e)) return;
      onClick();
    });
    return b;
  }

  /** Trusted, visible, covered by nothing, and on screen long enough for the user to have seen it. */
  private allowed(e: MouseEvent): boolean {
    const target = e.currentTarget as HTMLElement;
    if (!this.trusted(e) || !this.visible(e, this.host, target, this.parent)) return false;
    if (Date.now() - this.shownAt < this.settleMs) return false;
    return this.tracker.ok(target) && this.tracker.ok(this.bar);
  }
}
