// A login waiting to be saved after the page navigated. Lives only in the background's memory,
// per tab, for a minute, and is handed back only to a page on the same host.
import type { LookupStatus } from "./client";

export interface PendingSave {
  username: string;
  password: string;
  itemId: string | null;
  status: Exclude<LookupStatus, "same">;
}

interface Entry {
  data: PendingSave;
  host: string;
  expires: number;
}

function hostOf(url: string): string | null {
  try {
    return new URL(url).host || null;
  } catch {
    return null;
  }
}

export class PendingSaves {
  private entries = new Map<number, Entry>();

  constructor(
    private now: () => number = Date.now,
    private ttlMs = 60_000,
  ) {}

  set(tabId: number, data: PendingSave, url: string): void {
    const host = hostOf(url);
    if (!host) return;
    this.entries.set(tabId, { data, host, expires: this.now() + this.ttlMs });
  }

  /** Returns and forgets the save if it is fresh and `url` has the same host; otherwise null (and keeps it). */
  take(tabId: number, url: string): PendingSave | null {
    const e = this.entries.get(tabId);
    if (!e) return null;
    if (this.now() > e.expires) {
      this.entries.delete(tabId);
      return null;
    }
    if (hostOf(url) !== e.host) return null;
    this.entries.delete(tabId);
    return e.data;
  }

  clear(tabId: number): void {
    this.entries.delete(tabId);
  }
}

export interface Submission {
  username: string;
  password: string;
  /** A draft this page saved from the generator: the submission updates it. */
  draftId: string | null;
}

type Lookup = (username: string, password: string) => Promise<{ status: LookupStatus; itemId: string | null }>;

/** What to offer after a sign-in: nothing when the app already has it, else save or update. */
export async function offerFor(s: Submission, lookup: Lookup): Promise<PendingSave | null> {
  if (s.draftId) return { username: s.username, password: s.password, itemId: s.draftId, status: "changed" };
  const r = await lookup(s.username, s.password);
  if (r.status === "same") return null;
  return { username: s.username, password: s.password, itemId: r.itemId, status: r.status };
}
