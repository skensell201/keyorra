import { authorize } from "./access";
import { idbDelete, idbGet, idbPut } from "./idb";
import { Client, LockedError, NoAppError, UnpairedError, type Pairing } from "./client";
import { PendingSaves, offerFor } from "./pending";
import type { ErrorKind, Result, ToBackground, ToContent } from "./messages";

const HOST = "app.keepsake.bridge";

// The pairing key is kept in IndexedDB, which only this worker opens; chrome.storage is readable by content scripts.
const client = new Client((msg) => chrome.runtime.sendNativeMessage(HOST, msg), {
  get: () => idbGet<Pairing>("pairing"),
  set: (p) => idbPut("pairing", p).then(() => {}),
  clear: () => idbDelete("pairing").then(() => {}),
  getPending: () => idbGet<Pairing>("pending"),
  setPending: (p) => (p ? idbPut("pending", p) : idbDelete("pending")).then(() => {}),
});

// Logins awaiting a save across a page navigation: memory only, never page storage.
const pending = new PendingSaves();
chrome.tabs.onRemoved.addListener((tabId) => pending.clear(tabId));

function browserName(): string {
  const ua = navigator.userAgent;
  if (/Firefox\//.test(ua)) return "Firefox";
  if (/YaBrowser\//.test(ua)) return "Yandex";
  if (/OPR\//.test(ua)) return "Opera";
  if (/Edg\//.test(ua)) return "Edge";
  if (/Vivaldi\//.test(ua)) return "Vivaldi";
  return "Chrome";
}

function kind(e: unknown): ErrorKind {
  if (e instanceof LockedError) return "locked";
  if (e instanceof UnpairedError) return "unpaired";
  if (e instanceof NoAppError) return "noApp";
  return "other";
}

async function handle(msg: ToBackground, sender: chrome.runtime.MessageSender): Promise<unknown> {
  const decision = authorize(msg, sender, chrome.runtime.id, chrome.runtime.getURL(""));
  if (!decision.ok) throw new Error(decision.message);
  switch (msg.type) {
    case "state":
      return client.state();
    case "pair":
      return client.startPairing(browserName());
    case "pairStatus":
      return client.pairingResult();
    case "pairingCode":
      return client.pairingCode();
    case "show":
      return client.show();
    case "list":
      return client.list(decision.url);
    case "fill":
      return client.fill(decision.url, msg.itemId);
    case "lookup":
      return client.lookup(decision.url, msg.username, msg.password);
    case "save":
      return client.save(decision.url, msg.username, msg.password, msg.itemId, msg.draft === true);
    case "generate":
      return client.generate();
    case "cards":
      return client.cards(decision.url);
    case "fillCard":
      return client.fillCard(decision.url, msg.itemId);
    case "identities":
      return client.identities(decision.url);
    case "fillIdentity":
      return client.fillIdentity(decision.url, msg.itemId);
    case "submitted": {
      // Decided here, not in the page: the page often navigates before the app answers.
      const offer = await offerFor(msg, (u, p) => client.lookup(decision.url, u, p));
      if (offer && sender.frameId === 0 && sender.tab?.id !== undefined) pending.set(sender.tab.id, offer, decision.url);
      return offer;
    }
    case "takePendingSave":
      return sender.tab?.id === undefined ? null : pending.take(sender.tab.id, decision.url);
    case "clearPendingSave":
      if (sender.tab?.id !== undefined) pending.clear(sender.tab.id);
      return null;
  }
}

chrome.runtime.onMessage.addListener((msg: ToBackground, sender, respond) => {
  handle(msg, sender).then(
    (value) => respond({ ok: true, value } satisfies Result<unknown>),
    (e) => respond({ ok: false, error: kind(e), message: e instanceof Error ? e.message : String(e) } satisfies Result<unknown>),
  );
  return true;
});

chrome.commands.onCommand.addListener((command, tab) => {
  if (command !== "fill-login" || tab?.id === undefined) return;
  chrome.tabs.sendMessage(tab.id, { type: "fill-best" } satisfies ToContent, { frameId: 0 }).catch(() => {});
});
