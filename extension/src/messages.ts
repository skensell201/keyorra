import type { Candidate, CardFill, CardSummary, Credentials, IdentityFill, IdentitySummary, LookupStatus, State } from "./client";

/** Requests to the background; the page URL for content scripts comes from the browser, not the message. */
export type ToBackground =
  | { type: "state" }
  | { type: "pair" }
  | { type: "pairStatus" }
  | { type: "pairingCode" }
  | { type: "show" }
  | { type: "list"; url?: string }
  | { type: "fill"; itemId: string }
  | { type: "lookup"; username: string; password: string }
  | { type: "save"; username: string; password: string; itemId: string | null }
  | { type: "generate" }
  | { type: "cards" }
  | { type: "fillCard"; itemId: string }
  | { type: "identities" }
  | { type: "fillIdentity"; itemId: string }
  | { type: "pendingSave"; username: string; password: string; itemId: string | null; status: Exclude<LookupStatus, "same"> }
  | { type: "takePendingSave" };

/** Requests from the popup/shortcut to the content script in the top frame. */
export type ToContent = { type: "fill-item"; itemId: string } | { type: "fill-best" };

export type ErrorKind = "noApp" | "locked" | "unpaired" | "other";
export type Result<T> = { ok: true; value: T } | { ok: false; error: ErrorKind; message: string };

export type { Candidate, CardFill, CardSummary, Credentials, IdentityFill, IdentitySummary, LookupStatus, State };

export async function ask<T>(msg: ToBackground): Promise<Result<T>> {
  return chrome.runtime.sendMessage(msg);
}
