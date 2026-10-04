import { Client, LockedError, NoAppError, UnpairedError, type Pairing } from "./client";
import type { ErrorKind, Result, ToBackground, ToContent } from "./messages";

const HOST = "app.lockbox.bridge";

const client = new Client((msg) => chrome.runtime.sendNativeMessage(HOST, msg), {
  get: async () => ((await chrome.storage.local.get("pairing")).pairing as Pairing | undefined) ?? null,
  set: (p) => chrome.storage.local.set({ pairing: p }),
  clear: () => chrome.storage.local.remove("pairing"),
  getPending: async () => ((await chrome.storage.session.get("pending")).pending as Pairing | undefined) ?? null,
  setPending: (p) => (p ? chrome.storage.session.set({ pending: p }) : chrome.storage.session.remove("pending")),
});

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

/** Content scripts: the URL of the frame that asked, as the browser reports it. Popup: the active tab's. */
async function pageUrl(msg: { url?: string }, sender: chrome.runtime.MessageSender): Promise<string> {
  if (sender.tab) return sender.url ?? sender.tab.url ?? "";
  if (msg.url) return msg.url;
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab?.url ?? "";
}

async function handle(msg: ToBackground, sender: chrome.runtime.MessageSender): Promise<unknown> {
  switch (msg.type) {
    case "state":
      return client.state();
    case "pair":
      return client.startPairing(browserName());
    case "pairStatus":
      return client.pairingResult();
    case "show":
      return client.show();
    case "list":
      return client.list(await pageUrl(msg, sender));
    case "fill":
      if (!sender.tab) throw new Error("Fill is only available from the page");
      return client.fill(await pageUrl({}, sender), msg.itemId);
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
