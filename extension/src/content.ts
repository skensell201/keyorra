import { findLoginFields } from "./detect";
import { fillLogin } from "./fill";
import { InlineMenu } from "./inline";
import { ask, type Candidate, type Credentials, type State, type ToContent } from "./messages";

async function list(): Promise<{ state: State; items: Candidate[] }> {
  const r = await ask<Candidate[]>({ type: "list" });
  if (r.ok) return { state: "ready", items: r.value };
  return { state: r.error === "other" ? "ready" : r.error, items: [] };
}

/** Fills the page's fields; returns how many were filled. */
async function fillItem(itemId: string): Promise<number> {
  const r = await ask<Credentials>({ type: "fill", itemId });
  if (!r.ok) throw new Error(r.message);
  return fillLogin(findLoginFields(document), r.value);
}

const menu = new InlineMenu({
  list,
  fill: async (itemId) => {
    await fillItem(itemId);
  },
  unlock: async () => {
    await ask({ type: "show" });
  },
});

function scan(): void {
  const f = findLoginFields(document);
  for (const field of [f.username, f.password, f.totp]) if (field) menu.watch(field);
}

function addsInput(m: MutationRecord): boolean {
  for (const n of m.addedNodes) {
    if (n instanceof HTMLInputElement) return true;
    if (n instanceof Element && n.querySelector("input")) return true;
  }
  return false;
}

// At most one scan per 300 ms: a pending timer is never pushed back, so busy pages still get scanned.
let timer: number | undefined;
new MutationObserver((mutations) => {
  if (timer !== undefined || !mutations.some(addsInput)) return;
  timer = window.setTimeout(() => {
    timer = undefined;
    scan();
  }, 300);
}).observe(document.documentElement, { childList: true, subtree: true });
scan();
// A field can gain focus before the mutation scan ran (or be shown without any mutation).
document.addEventListener("focusin", (e) => e.target instanceof HTMLInputElement && scan(), true);

chrome.runtime.onMessage.addListener((msg: ToContent, _sender, respond) => {
  (async () => {
    if (msg.type === "fill-item") return { filled: await fillItem(msg.itemId) };
    if (msg.type === "fill-best") {
      const { items } = await list();
      return { filled: items[0] ? await fillItem(items[0].id) : 0 };
    }
    return { filled: 0 };
  })().then(respond, (e) => respond({ error: e instanceof Error ? e.message : String(e) }));
  return true;
});
