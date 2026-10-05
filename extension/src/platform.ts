// Per-browser differences the background needs: the pairing name and how native messages go out.
import type { Send } from "./client";

/** The name shown for this browser in the app's pairing dialog and its list of paired browsers. */
export function browserName(ua: string, extensionBase: string): string {
  // Safari's user agent mentions only "Safari"; its extension pages have their own scheme.
  if (extensionBase.startsWith("safari-web-extension:")) return "Safari";
  if (/Firefox\//.test(ua)) return "Firefox";
  if (/YaBrowser\//.test(ua)) return "Yandex";
  if (/OPR\//.test(ua)) return "Opera";
  if (/Edg\//.test(ua)) return "Edge";
  if (/Vivaldi\//.test(ua)) return "Vivaldi";
  return "Chrome";
}

interface NativeRuntime {
  sendNativeMessage(application: string, message: object): Promise<any>;
}

/**
 * Sends one message to the app and resolves with its reply. Chromium and Firefox reject when the
 * native host cannot reach the app; Safari's app extension answers `{ kind: "noApp" }` instead,
 * which is turned into the same rejection so the client reports "noApp" either way.
 */
export function nativeSender(runtime: NativeRuntime, host: string): Send {
  return async (msg) => {
    const reply = await runtime.sendNativeMessage(host, msg);
    if (reply == null) throw new Error("No reply from Keepsake");
    if (reply.kind === "noApp") throw new Error(reply.message ?? "Keepsake is not running");
    return reply;
  };
}

/** Safari and Firefox expose the promise-based `browser` namespace; Chromium only `chrome`. */
export function nativeRuntime(): NativeRuntime {
  const b = (globalThis as { browser?: { runtime?: NativeRuntime } }).browser;
  return b?.runtime?.sendNativeMessage ? b.runtime : (chrome.runtime as unknown as NativeRuntime);
}
