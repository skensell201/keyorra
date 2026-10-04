import { watchSubmissions, type Submission } from "./capture";
import { findAddressFields, findCardFields, findLoginFields, findNewPasswordFields, usable } from "./detect";
import { fillAddress, fillCard, fillLogin, fillNewPassword } from "./fill";
import { InlineMenu, type MenuMode } from "./inline";
import { ask, type Candidate, type CardFill, type CardSummary, type Credentials, type IdentityFill, type IdentitySummary, type LookupStatus, type State, type ToContent } from "./messages";
import { SaveBar } from "./savebar";
import type { PendingSave } from "./pending";

async function list(): Promise<{ state: State; items: Candidate[] }> {
  const r = await ask<Candidate[]>({ type: "list" });
  if (r.ok) return { state: "ready", items: r.value };
  return { state: r.error === "other" ? "ready" : r.error, items: [] };
}

async function query<T>(msg: Parameters<typeof ask>[0]): Promise<{ state: State; value: T | null }> {
  const r = await ask<T>(msg);
  if (r.ok) return { state: "ready", value: r.value };
  return { state: r.error === "other" ? "ready" : r.error, value: null };
}

/** The input the user last focused: card and address fills stay within its form. */
let lastField: HTMLInputElement | null = null;
const scopeOf = (): Document | HTMLElement => lastField?.form ?? document;

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
  generate: async () => {
    const r = await query<string>({ type: "generate" });
    return { state: r.state, value: r.value ?? "" };
  },
  useGenerated: async (password) => {
    fillNewPassword(findNewPasswordFields(document), password);
    const username = findLoginFields(lastField?.form ?? document).username?.value ?? "";
    // A draft right away; if this fails, the save bar after submitting still offers it.
    await ask({ type: "save", username, password, itemId: null }).catch(() => {});
  },
  cards: async () => {
    const r = await query<CardSummary[]>({ type: "cards" });
    return { state: r.state, items: r.value ?? [] };
  },
  fillCard: async (itemId) => {
    const r = await ask<CardFill>({ type: "fillCard", itemId });
    if (!r.ok) throw new Error(r.message);
    fillCard(findCardFields(scopeOf()), r.value);
  },
  identities: async () => {
    const r = await query<IdentitySummary[]>({ type: "identities" });
    return { state: r.state, items: r.value ?? [] };
  },
  fillIdentity: async (itemId) => {
    const r = await ask<IdentityFill>({ type: "fillIdentity", itemId });
    if (!r.ok) throw new Error(r.message);
    fillAddress(findAddressFields(scopeOf()), r.value);
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

/** Change-password forms have no username field: if exactly one login matches this site, it is the account. */
async function withUsername(s: Submission): Promise<Submission> {
  if (s.username) return s;
  const r = await ask<Candidate[]>({ type: "list" });
  return r.ok && r.value.length === 1 ? { ...s, username: r.value[0].username } : s;
}

async function onSubmission(raw: Submission): Promise<void> {
  const s = await withUsername(raw);
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
  // One mode per field; later (higher precedence) assignments win: generator > cards > identities > logins.
  const modes = new Map<HTMLInputElement, MenuMode>();
  const f = findLoginFields(document);
  for (const field of [f.username, f.password, f.totp]) if (field) modes.set(field, "logins");
  const addr = findAddressFields(document);
  for (const field of Object.values(addr)) if (field instanceof HTMLInputElement && usable(field)) modes.set(field, "identities");
  const card = findCardFields(document);
  for (const field of Object.values(card)) if (field instanceof HTMLInputElement && usable(field)) modes.set(field, "cards");
  for (const field of findNewPasswordFields(document)) modes.set(field, "generator");
  for (const [field, mode] of modes) menu.watch(field, mode);
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
document.addEventListener(
  "focusin",
  (e) => {
    if (!(e.target instanceof HTMLInputElement)) return;
    lastField = e.target;
    scan();
  },
  true,
);

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
