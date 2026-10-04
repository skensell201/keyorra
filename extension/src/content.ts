import { watchSubmissions, type Submission } from "./capture";
import { findLoginFields } from "./detect";
import { fillLogin } from "./fill";
import { InlineMenu } from "./inline";
import { ask, type Candidate, type Credentials, type LookupStatus, type State, type ToContent } from "./messages";
import { SaveBar } from "./savebar";
import type { PendingSave } from "./pending";

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

// ---- offer to save or update a login after sign-in ----

let offer: { username: string; password: string; itemId: string | null } | null = null;

const saveBar = new SaveBar({
  save: async () => {
    if (!offer) return;
    const r = await ask<string>({ type: "save", username: offer.username, password: offer.password, itemId: offer.itemId });
    if (!r.ok) throw new Error(r.message);
    offer = null;
  },
  dismiss: () => {
    offer = null;
  },
});

function showOffer(o: PendingSave): void {
  offer = { username: o.username, password: o.password, itemId: o.itemId };
  saveBar.show({ username: o.username, status: o.status });
}

async function onSubmission(s: Submission): Promise<void> {
  const r = await ask<{ status: LookupStatus; itemId: string | null }>({ type: "lookup", username: s.username, password: s.password });
  if (!r.ok || r.value.status === "same") return;
  const o: PendingSave = { ...s, itemId: r.value.itemId, status: r.value.status };
  // The page may navigate right away: show the bar now and let the background carry it over.
  showOffer(o);
  void ask({ type: "pendingSave", ...o });
}

watchSubmissions(document, (s) => void onSubmission(s).catch(() => {}));

if (window === window.top) {
  void ask<PendingSave | null>({ type: "takePendingSave" })
    .then((r) => r.ok && r.value && showOffer(r.value))
    .catch(() => {});
}

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
