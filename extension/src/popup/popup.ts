import type { Candidate, Result, State, ToBackground, ToContent } from "../messages";

export interface PopupDeps {
  ask<T>(msg: ToBackground): Promise<Result<T>>;
  activeTab(): Promise<{ id?: number; url?: string }>;
  fillInTab(tabId: number, itemId: string): Promise<{ filled?: number; error?: string } | void>;
  close(): void;
  sleep(ms: number): Promise<void>;
}

const MARK = `<span class="mark"><svg viewBox="0 0 24 24" width="14" height="14" aria-hidden="true"><circle cx="12" cy="9" r="4" fill="currentColor"/><path d="M10.2 11.5h3.6l1.2 8h-6z" fill="currentColor"/></svg></span>`;

function el<K extends keyof HTMLElementTagNameMap>(tag: K, props: Partial<HTMLElementTagNameMap[K]> = {}, ...children: (Node | string)[]) {
  const node = Object.assign(document.createElement(tag), props);
  node.append(...children);
  return node;
}

function shell(root: HTMLElement, ...content: Node[]): void {
  const header = el("header");
  header.innerHTML = MARK;
  header.append("Keyorra");
  root.replaceChildren(header, ...content);
}

export async function renderPopup(root: HTMLElement, deps: PopupDeps): Promise<void> {
  const state = await deps.ask<State>({ type: "state" });
  const value: State = state.ok ? state.value : state.error === "other" ? "noApp" : state.error;
  if (value === "noApp") {
    shell(root, el("p", { textContent: "Keyorra isn't running." }), el("button", { className: "primary", textContent: "Open Keyorra", onclick: () => deps.ask({ type: "show" }) }));
  } else if (value === "locked") {
    shell(root, el("p", { textContent: "Keyorra is locked." }), el("button", { className: "primary", textContent: "Unlock", onclick: () => deps.ask({ type: "show" }) }));
  } else if (value === "pairing") {
    // The popup was closed while the user was approving in the app: show the code again and keep waiting.
    const c = await deps.ask<string | null>({ type: "pairingCode" });
    await waitForApproval(root, deps, c.ok ? c.value : null);
  } else if (value === "unpaired") {
    const connect = el("button", { className: "primary", textContent: "Connect" });
    connect.onclick = () => {
      connect.disabled = true;
      void pair(root, deps);
    };
    shell(root, el("p", { textContent: "Connect this browser to Keyorra. You'll confirm a code in the app." }), connect);
  } else {
    await showLogins(root, deps);
  }
}

async function pair(root: HTMLElement, deps: PopupDeps): Promise<void> {
  const r = await deps.ask<{ code: string }>({ type: "pair" });
  if (!r.ok) {
    shell(root, el("p", { textContent: r.error === "locked" ? "Unlock Keyorra first, then try again." : r.message }));
    return;
  }
  await waitForApproval(root, deps, r.value.code);
}

async function waitForApproval(root: HTMLElement, deps: PopupDeps, rawCode: string | null): Promise<void> {
  if (!rawCode) {
    shell(root, el("p", { textContent: "Waiting for approval in the Keyorra app…" }));
  } else {
    const code = `${rawCode.slice(0, 3)} ${rawCode.slice(3)}`;
    shell(root, el("p", { textContent: "Confirm this code in the Keyorra app:" }), el("div", { className: "code", textContent: code }));
  }
  for (let i = 0; i < 120; i++) {
    const s = await deps.ask<"none" | "waiting" | "paired" | "denied">({ type: "pairStatus" });
    if (s.ok && s.value === "paired") return showLogins(root, deps);
    if (!s.ok) {
      shell(root, el("p", { textContent: "Keyorra isn't running." }));
      return;
    }
    if (s.value === "none") return renderPopup(root, deps);
    if (s.value === "denied") {
      shell(root, el("p", { textContent: "Connection was declined." }));
      return;
    }
    await deps.sleep(1000);
  }
  shell(root, el("p", { textContent: "Timed out. Open the popup to try again." }));
}

async function showLogins(root: HTMLElement, deps: PopupDeps): Promise<void> {
  const tab = await deps.activeTab();
  const host = safeHost(tab.url);
  if (!/^https?:/.test(tab.url ?? "")) {
    shell(root, el("p", { textContent: "Open a website to fill a login." }));
    return;
  }
  const r = await deps.ask<Candidate[]>({ type: "list", url: tab.url });
  const items = r.ok ? r.value : [];
  if (items.length === 0) {
    shell(root, el("p", { textContent: host ? `No logins for ${host}` : "Open a website to fill a login." }));
    return;
  }
  const list = el("ul");
  for (const item of items) {
    const button = el("button", { className: "item", onclick: async () => {
      let outcome: { filled?: number; error?: string } | void = undefined;
      if (tab.id !== undefined) {
        try {
          outcome = await deps.fillInTab(tab.id, item.id);
        } catch {
          shell(root, el("p", { textContent: "Reload this page to fill." }));
          return;
        }
      }
      if (outcome && outcome.error) shell(root, el("p", { textContent: outcome.error }));
      else if (outcome && outcome.filled === 0) shell(root, el("p", { textContent: "No login fields found on this page." }));
      else deps.close();
    } });
    const text = el("span", { className: "text" }, el("span", { textContent: item.title }), el("span", { className: "sub", textContent: item.username }));
    button.append(el("span", { className: "mono", textContent: item.title.match(/[\p{L}\p{N}]/u)?.[0] ?? "•" }), text);
    list.append(el("li", {}, button));
  }
  shell(root, list);
}

function safeHost(url?: string): string {
  try {
    return url ? new URL(url).hostname : "";
  } catch {
    return "";
  }
}

// Wire up when loaded as the real popup (tests import renderPopup directly).
if (typeof chrome !== "undefined" && chrome.runtime?.id && document.getElementById("app")) {
  renderPopup(document.getElementById("app")!, {
    ask: (msg) => chrome.runtime.sendMessage(msg),
    activeTab: async () => (await chrome.tabs.query({ active: true, currentWindow: true }))[0] ?? {},
    fillInTab: async (tabId, itemId) => {
      return await chrome.tabs.sendMessage(tabId, { type: "fill-item", itemId } satisfies ToContent, { frameId: 0 });
    },
    close: () => window.close(),
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
  });
}
