// Who may send which request to the background. Content scripts run next to untrusted pages, so
// they get only what they need: the URL they act on is the one the browser reports, never one they send.
import type { ToBackground } from "./messages";

export interface Sender {
  id?: string;
  url?: string;
}

export type Decision = { ok: true; url: string } | { ok: false; message: string };

export function authorize(msg: ToBackground, sender: Sender, extensionId: string, extensionBase: string): Decision {
  const extPage = sender.id === extensionId && !!sender.url?.startsWith(extensionBase);
  const page = !extPage && /^https?:/.test(sender.url ?? "");
  const refuse = (): Decision => ({ ok: false, message: "Not allowed from here" });
  switch (msg?.type) {
    case "state":
    case "show":
      return extPage || page ? { ok: true, url: "" } : refuse();
    case "pair":
    case "pairStatus":
    case "pairingCode":
      return extPage ? { ok: true, url: "" } : refuse();
    case "list":
      if (page) return { ok: true, url: sender.url! };
      return extPage && msg.url ? { ok: true, url: msg.url } : refuse();
    case "fill":
    case "lookup":
    case "save":
    case "generate":
    case "cards":
    case "fillCard":
    case "identities":
    case "fillIdentity":
    case "pendingSave":
    case "takePendingSave":
      return page ? { ok: true, url: sender.url! } : refuse();
    default:
      return { ok: false, message: "Unknown request" };
  }
}
