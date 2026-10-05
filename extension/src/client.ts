// Talks to the Keyorra app: pairing, then sealed list/fill calls. Transport and storage are injected.
import { commitment, derive, fromB64, newKeyPair, openReply, seal, toB64 } from "./crypto";

export type State = "noApp" | "unpaired" | "pairing" | "locked" | "ready";

export interface Pairing {
  clientId: string;
  /** base64 session key */
  key: string;
  /** the confirmation code, kept with a pending pairing so the popup can show it again */
  code?: string;
}

export interface PairingStore {
  get(): Promise<Pairing | null>;
  set(p: Pairing): Promise<void>;
  clear(): Promise<void>;
  getPending(): Promise<Pairing | null>;
  setPending(p: Pairing | null): Promise<void>;
}

export interface Candidate {
  id: string;
  title: string;
  username: string;
  hasTotp: boolean;
}

export interface Credentials {
  username: string;
  password: string;
  totp: string | null;
}

export interface CardSummary {
  id: string;
  title: string;
  last4: string;
}

export interface CardFill {
  name: string;
  number: string;
  expMonth: string;
  expYear: string;
  cvc: string;
}

export interface IdentitySummary {
  id: string;
  title: string;
  detail: string;
}

export interface IdentityFill {
  givenName: string;
  familyName: string;
  email: string;
  phone: string;
  street: string;
  city: string;
  postalCode: string;
  country: string;
}

export type LookupStatus = "new" | "changed" | "same";

export type Send = (msg: object) => Promise<any>;

export class LockedError extends Error {}
export class UnpairedError extends Error {}
export class NoAppError extends Error {}

export class Client {
  constructor(
    private send: Send,
    private store: PairingStore,
  ) {}

  async state(): Promise<State> {
    let status: any;
    try {
      status = await this.send({ kind: "status" });
    } catch {
      return "noApp";
    }
    if (!(await this.store.get())) {
      if (!(await this.store.getPending())) return "unpaired";
      // The popup may have been closed while the user approved in the app.
      const result = await this.pairingResult();
      if (result === "waiting") return "pairing";
      if (result !== "paired") return "unpaired";
    }
    if (status?.locked) return "locked";
    try {
      await this.request({ op: "ping" });
      return "ready";
    } catch (e) {
      if (e instanceof UnpairedError) return "unpaired";
      if (e instanceof LockedError) return "locked";
      throw e;
    }
  }

  async startPairing(name: string): Promise<{ code: string }> {
    const keys = newKeyPair();
    // Commit to the public key first, reveal it second: the app's key is fixed before it learns ours.
    const res = await this.transport({ kind: "pair", commit: toB64(commitment(keys.public)), name });
    if (res.kind === "locked") throw new LockedError();
    if (res.kind !== "pairPending") throw new Error(res.message ?? "Pairing failed");
    const serverPub = fromB64(res.serverPub);
    const revealed = await this.transport({ kind: "pairReveal", clientId: res.clientId, clientPub: toB64(keys.public) });
    if (revealed.kind === "locked") throw new LockedError();
    if (revealed.kind !== "pairPending") throw new Error(revealed.message ?? "Pairing failed");
    const { key, code } = derive(keys, serverPub, keys.public, serverPub);
    await this.store.setPending({ clientId: res.clientId, key: toB64(key), code });
    return { code };
  }

  /** The code of the pairing in progress, if any. */
  async pairingCode(): Promise<string | null> {
    return (await this.store.getPending())?.code ?? null;
  }

  async pairingResult(): Promise<"none" | "waiting" | "paired" | "denied"> {
    const pending = await this.store.getPending();
    if (!pending) return "none";
    const res = await this.transport({ kind: "pairStatus", clientId: pending.clientId });
    // A locked app can still approve later: keep the pending pairing.
    if (res.kind === "pairPending" || res.kind === "locked") return "waiting";
    await this.store.setPending(null);
    if (res.kind === "paired") {
      await this.store.set({ clientId: pending.clientId, key: pending.key });
      return "paired";
    }
    return "denied";
  }

  async list(url: string): Promise<Candidate[]> {
    return (await this.request({ op: "list", url })).items;
  }

  async fill(url: string, itemId: string): Promise<Credentials> {
    const r = await this.request({ op: "fill", url, itemId });
    return { username: r.username, password: r.password, totp: r.totp ?? null };
  }

  async lookup(url: string, username: string, password: string): Promise<{ status: LookupStatus; itemId: string | null }> {
    const r = await this.request({ op: "lookup", url, username, password });
    return { status: r.status, itemId: r.itemId ?? null };
  }

  /** Returns the id of the saved item; the app never sends secrets back. */
  async save(url: string, username: string, password: string, itemId: string | null, draft = false): Promise<string> {
    return (await this.request({ op: "save", url, username, password, itemId, ...(draft ? { draft: true } : {}) })).saved;
  }

  async generate(): Promise<string> {
    return (await this.request({ op: "generate" })).generated;
  }

  async cards(url: string): Promise<CardSummary[]> {
    return (await this.request({ op: "cards", url })).cards;
  }

  async fillCard(url: string, itemId: string): Promise<CardFill> {
    return (await this.request({ op: "fillCard", url, itemId })).card;
  }

  async identities(url: string): Promise<IdentitySummary[]> {
    return (await this.request({ op: "identities", url })).identities;
  }

  async fillIdentity(url: string, itemId: string): Promise<IdentityFill> {
    return (await this.request({ op: "fillIdentity", url, itemId })).identity;
  }

  async show(): Promise<void> {
    await this.transport({ kind: "show" });
  }

  private async transport(msg: object): Promise<any> {
    try {
      return await this.send(msg);
    } catch {
      throw new NoAppError();
    }
  }

  private async request(req: object): Promise<any> {
    let pairing = await this.store.get();
    if (!pairing && (await this.store.getPending())) {
      await this.pairingResult();
      pairing = await this.store.get();
    }
    if (!pairing) throw new UnpairedError();
    const key = fromB64(pairing.key);
    const requestBox = seal(key, pairing.clientId, "req", req);
    const res = await this.transport({ kind: "call", clientId: pairing.clientId, box: requestBox });
    if (res.kind === "locked") throw new LockedError();
    if (res.kind === "unknownClient") {
      await this.store.clear();
      throw new UnpairedError();
    }
    if (res.kind !== "reply") throw new Error(res.message ?? "Keyorra error");
    const reply = openReply<any>(key, pairing.clientId, requestBox, res.box);
    if (!reply) throw new Error("Keyorra sent a reply that did not authenticate");
    if (reply.error) throw new Error(reply.error);
    return reply;
  }
}
