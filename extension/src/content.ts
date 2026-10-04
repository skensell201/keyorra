import { findLoginFields } from "./detect";
import { fillLogin } from "./fill";
import { InlineMenu } from "./inline";
import { ask, type Candidate, type Credentials, type State, type ToContent } from "./messages";

async function list(): Promise<{ state: State; items: Candidate[] }> {
  const r = await ask<Candidate[]>({ type: "list" });
  if (r.ok) return { state: "ready", items: r.value };
  return { state: r.error === "other" ? "ready" : r.error, items: [] };
}

async function fillItem(itemId: string): Promise<void> {
  const r = await ask<Credentials>({ type: "fill", itemId });
  if (r.ok) fillLogin(findLoginFields(document), r.value);
}

const menu = new InlineMenu({
  list,
  fill: fillItem,
  unlock: async () => {
    await ask({ type: "show" });
  },
});

function scan(): void {
  const f = findLoginFields(document);
  for (const field of [f.username, f.password, f.totp]) if (field) menu.watch(field);
}

let timer: number | undefined;
new MutationObserver(() => {
  clearTimeout(timer);
  timer = window.setTimeout(scan, 300);
}).observe(document.documentElement, { childList: true, subtree: true });
scan();

chrome.runtime.onMessage.addListener((msg: ToContent, _sender, respond) => {
  (async () => {
    if (msg.type === "fill-item") await fillItem(msg.itemId);
    if (msg.type === "fill-best") {
      const { items } = await list();
      if (items[0]) await fillItem(items[0].id);
    }
  })().then(() => respond({}), () => respond({}));
  return true;
});
