import { beforeEach, expect, test } from "vitest";
import { Client, LockedError, type Pairing, type PairingStore } from "./client";
import { commitment, derive, fromB64, newKeyPair, nonceOf, open, seal, toB64 } from "./crypto";

class FakeApp {
  locked = false;
  running = true;
  approved = false;
  keys = new Map<string, Uint8Array>();
  pendingKey: Uint8Array | null = null;
  commit = "";
  server = newKeyPair();
  code = "";
  /** Answer calls with a reply bound to some other request. */
  replayReply = false;
  requests: any[] = [];
  items = [{ id: "i1", title: "GitHub", username: "ivan", hasTotp: false }];

  async send(msg: any): Promise<any> {
    if (!this.running) throw new Error("Native host has exited.");
    switch (msg.kind) {
      case "status":
        return { kind: "status", locked: this.locked, version: 1 };
      case "pair":
        this.commit = msg.commit;
        this.server = newKeyPair();
        return { kind: "pairPending", clientId: "c1", serverPub: toB64(this.server.public) };
      case "pairReveal": {
        const clientPub = fromB64(msg.clientPub);
        if (msg.clientId !== "c1" || toB64(commitment(clientPub)) !== this.commit) {
          return { kind: "error", message: "Pairing check failed" };
        }
        const d = derive(this.server, clientPub, clientPub, this.server.public)!;
        this.pendingKey = d.key;
        this.code = d.code;
        return { kind: "pairPending", clientId: "c1", serverPub: toB64(this.server.public) };
      }
      case "pairStatus":
        if (!this.approved) return { kind: "pairPending", clientId: "c1", serverPub: "" };
        this.keys.set("c1", this.pendingKey!);
        return { kind: "paired" };
      case "call": {
        if (this.locked) return { kind: "locked" };
        const key = this.keys.get(msg.clientId);
        if (!key) return { kind: "unknownClient" };
        const req = open<any>(key, msg.clientId, "req", msg.box)!;
        this.requests.push(req);
        const replies: Record<string, object> = {
          ping: { pong: true },
          list: { items: this.items },
          lookup: { status: "changed", itemId: "i1" },
          save: { saved: "i2" },
          generate: { generated: "Gen-pw-1" },
          cards: { cards: [{ id: "c9", title: "Visa", last4: "1111" }] },
          fillCard: { card: { name: "IVAN", number: "4111111111111111", expMonth: "12", expYear: "2027", cvc: "123" } },
          identities: { identities: [{ id: "n1", title: "Home", detail: "Hanoi" }] },
          fillIdentity: {
            identity: { givenName: "Ivan", familyName: "K", email: "i@x.io", phone: "1", street: "S", city: "Hanoi", postalCode: "10", country: "VN" },
          },
        };
        const reply = replies[req.op] ?? { username: "ivan", password: "pw", totp: null };
        const requestNonce = this.replayReply ? new Uint8Array(24).fill(9) : nonceOf(msg.box)!;
        return { kind: "reply", box: seal(key, msg.clientId, { requestNonce }, reply) };
      }
    }
  }
}

class MemoryStore implements PairingStore {
  pairing: Pairing | null = null;
  pending: Pairing | null = null;
  async get() { return this.pairing; }
  async set(p: Pairing) { this.pairing = p; }
  async clear() { this.pairing = null; }
  async getPending() { return this.pending; }
  async setPending(p: Pairing | null) { this.pending = p; }
}

let app: FakeApp;
let store: MemoryStore;
let client: Client;

beforeEach(() => {
  app = new FakeApp();
  store = new MemoryStore();
  client = new Client((m) => app.send(m), store);
});

test("no app, unpaired, paired, locked", async () => {
  app.running = false;
  expect(await client.state()).toBe("noApp");
  app.running = true;
  expect(await client.state()).toBe("unpaired");

  const { code } = await client.startPairing("Chrome");
  expect(code).toBe(app.code);
  expect(await client.pairingResult()).toBe("waiting");
  app.approved = true;
  expect(await client.pairingResult()).toBe("paired");
  expect(await client.state()).toBe("ready");

  app.locked = true;
  expect(await client.state()).toBe("locked");
  await expect(client.list("https://github.com")).rejects.toBeInstanceOf(LockedError);
});

test("lists and fills once paired", async () => {
  await client.startPairing("Chrome");
  app.approved = true;
  await client.pairingResult();
  expect(await client.list("https://github.com")).toEqual(app.items);
  expect(await client.fill("https://github.com", "i1")).toEqual({ username: "ivan", password: "pw", totp: null });
});

test("a forgotten pairing resets to unpaired", async () => {
  await client.startPairing("Chrome");
  app.approved = true;
  await client.pairingResult();
  app.keys.clear();
  expect(await client.state()).toBe("unpaired");
  expect(store.pairing).toBeNull();
});

test("pairing sends the commitment first and reveals the key second", async () => {
  const sent: string[] = [];
  const spy = new Client(async (m: any) => (sent.push(m.kind), app.send(m)), store);
  await spy.startPairing("Chrome");
  expect(sent).toEqual(["pair", "pairReveal"]);
});

test("a refused reveal fails the pairing and stores nothing", async () => {
  const bad = new Client(async (m: any) => {
    const res = await app.send(m);
    return m.kind === "pair" ? { ...res, clientId: "other" } : res;
  }, store);
  await expect(bad.startPairing("Chrome")).rejects.toThrow("Pairing check failed");
  expect(await store.getPending()).toBeNull();
});

test("a reply bound to another request is rejected", async () => {
  await client.startPairing("Chrome");
  app.approved = true;
  await client.pairingResult();
  app.replayReply = true;
  await expect(client.list("https://github.com")).rejects.toThrow("did not authenticate");
});

test("a denied pairing is reported and cleared", async () => {
  await client.startPairing("Chrome");
  app.send = async (m: any) => (m.kind === "pairStatus" ? { kind: "pairDenied" } : { kind: "error" });
  expect(await client.pairingResult()).toBe("denied");
  expect(await store.getPending()).toBeNull();
  expect(store.pairing).toBeNull();
});

test("a pairing in progress survives the popup closing", async () => {
  const { code } = await client.startPairing("Chrome");
  expect(await client.pairingCode()).toBe(code);
  expect(await client.state()).toBe("pairing");
  app.approved = true;
  expect(await client.state()).toBe("ready");
  expect(await client.pairingCode()).toBeNull();
  expect(store.pairing).not.toHaveProperty("code");
});

test("a denied pending pairing ends as unpaired; nothing pending is reported as none", async () => {
  expect(await client.pairingResult()).toBe("none");
  await client.startPairing("Chrome");
  app.send = async (m: any) => (m.kind === "pairStatus" ? { kind: "pairDenied" } : { kind: "status", locked: false });
  expect(await client.state()).toBe("unpaired");
  expect(await client.pairingCode()).toBeNull();
});

test("a locked app keeps the pending pairing; a request resolves a pending pairing first", async () => {
  await client.startPairing("Chrome");
  const real = app.send.bind(app);
  app.send = async (m: any) => (m.kind === "pairStatus" ? { kind: "locked" } : real(m));
  expect(await client.pairingResult()).toBe("waiting");
  expect(await client.pairingCode()).not.toBeNull();
  app.send = real;
  app.approved = true;
  expect(await client.list("https://github.com")).toEqual(app.items);
});

test("save, generate, cards and identities send the right op and return the inner value", async () => {
  await client.startPairing("Chrome");
  app.approved = true;
  await client.pairingResult();
  const url = "https://github.com/login";

  expect(await client.lookup(url, "ivan", "pw")).toEqual({ status: "changed", itemId: "i1" });
  expect(await client.save(url, "ivan", "pw", null)).toBe("i2");
  expect(await client.save(url, "ivan", "gen", null, true)).toBe("i2");
  expect(await client.generate()).toBe("Gen-pw-1");
  expect(await client.cards(url)).toEqual([{ id: "c9", title: "Visa", last4: "1111" }]);
  expect((await client.fillCard(url, "c9")).number).toBe("4111111111111111");
  expect(await client.identities(url)).toEqual([{ id: "n1", title: "Home", detail: "Hanoi" }]);
  expect((await client.fillIdentity(url, "n1")).givenName).toBe("Ivan");

  expect(app.requests).toEqual([
    { op: "lookup", url, username: "ivan", password: "pw" },
    { op: "save", url, username: "ivan", password: "pw", itemId: null },
    { op: "save", url, username: "ivan", password: "gen", itemId: null, draft: true },
    { op: "generate" },
    { op: "cards", url },
    { op: "fillCard", url, itemId: "c9" },
    { op: "identities", url },
    { op: "fillIdentity", url, itemId: "n1" },
  ]);
});
