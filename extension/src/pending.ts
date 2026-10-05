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

/** Somewhere that outlives the background page (storage.session: memory only, extension-only). */
export interface PendingStore {
  load(): Promise<unknown>;
  save(value: unknown): Promise<void>;
}

export class PendingSaves {
  private entries = new Map<number, Entry>();
  private restored: Promise<void> | null = null;
  private writing: Promise<void> = Promise.resolve();

  constructor(
    private now: () => number = Date.now,
    private ttlMs = 60_000,
    private store?: PendingStore,
  ) {}

  set(tabId: number, data: PendingSave, url: string): void {
    const host = hostOf(url);
    if (!host) return;
    this.entries.set(tabId, { data, host, expires: this.now() + this.ttlMs });
    this.persist();
  }

  /** Resolves once every change so far is written to the store. */
  flushed(): Promise<void> {
    return this.writing;
  }

  private persist(): void {
    if (!this.store) return;
    const snapshot = Object.fromEntries(this.entries);
    this.writing = this.writing.then(() => this.store!.save(snapshot)).catch(() => {});
  }

  /** Safari unloads a non-persistent background page between pages: reload what it parked. */
  private restore(): Promise<void> {
    if (!this.store) return Promise.resolve();
    this.restored ??= this.store
      .load()
      .then((v) => {
        if (!v || typeof v !== "object") return;
        for (const [k, e] of Object.entries(v as Record<string, Entry>)) {
          const id = Number(k);
          if (!this.entries.has(id)) this.entries.set(id, e);
        }
      })
      .catch(() => {});
    return this.restored;
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
    this.persist();
    return e.data;
  }

  clear(tabId: number): void {
    this.entries.delete(tabId);
    this.inFlight.delete(tabId);
    this.persist();
  }

  private inFlight = new Map<number, Promise<unknown>>();

  /** A sign-in from this tab is still being checked with the app. */
  track(tabId: number, work: Promise<unknown>): void {
    const done = work.catch(() => {}).finally(() => {
      if (this.inFlight.get(tabId) === done) this.inFlight.delete(tabId);
    });
    this.inFlight.set(tabId, done);
  }

  /** Like take, but first waits (up to timeoutMs) for a check still in flight: the next page can
   * load before the app has answered, especially in Safari. */
  async waitAndTake(tabId: number, url: string, timeoutMs = 5000): Promise<PendingSave | null> {
    const work = this.inFlight.get(tabId);
    if (work) await Promise.race([work, new Promise((r) => setTimeout(r, timeoutMs))]);
    await this.restore();
    return this.take(tabId, url);
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
