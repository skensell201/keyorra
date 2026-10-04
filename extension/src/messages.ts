import type { Candidate, Credentials, State } from "./client";

/** Requests to the background; the page URL for content scripts comes from the browser, not the message. */
export type ToBackground =
  | { type: "state" }
  | { type: "pair" }
  | { type: "pairStatus" }
  | { type: "pairingCode" }
  | { type: "show" }
  | { type: "list"; url?: string }
  | { type: "fill"; itemId: string };

/** Requests from the popup/shortcut to the content script in the top frame. */
export type ToContent = { type: "fill-item"; itemId: string } | { type: "fill-best" };

export type ErrorKind = "noApp" | "locked" | "unpaired" | "other";
export type Result<T> = { ok: true; value: T } | { ok: false; error: ErrorKind; message: string };

export type { Candidate, Credentials, State };

export async function ask<T>(msg: ToBackground): Promise<Result<T>> {
  return chrome.runtime.sendMessage(msg);
}
