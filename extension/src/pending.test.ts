import { beforeEach, expect, test } from "vitest";
import { PendingSaves, offerFor } from "./pending";

let now = 0;
let p: PendingSaves;
const data = { username: "u", password: "p", itemId: null, status: "new" as const };

beforeEach(() => {
  now = 1000;
  p = new PendingSaves(() => now, 60_000);
});

test("take returns the save for the same tab and host once", () => {
  p.set(1, data, "https://github.com/session");
  expect(p.take(1, "https://github.com/")).toEqual(data);
  expect(p.take(1, "https://github.com/")).toBeNull();
});

test("a different host or tab gets nothing and does not consume it", () => {
  p.set(1, data, "https://github.com/session");
  expect(p.take(1, "https://evil.com/")).toBeNull();
  expect(p.take(1, "https://github.com:8443/")).toBeNull();
  expect(p.take(2, "https://github.com/")).toBeNull();
  expect(p.take(1, "https://github.com/")).toEqual(data);
});

test("it expires after 60 s", () => {
  p.set(1, data, "https://github.com/");
  now += 60_001;
  expect(p.take(1, "https://github.com/")).toBeNull();
});

test("a newer save replaces the older one; bad URLs are refused", () => {
  p.set(1, data, "https://a.com/");
  p.set(1, { ...data, username: "v" }, "https://a.com/");
  expect(p.take(1, "https://a.com/")?.username).toBe("v");
  p.set(1, data, "not a url");
  expect(p.take(1, "not a url")).toBeNull();
});

test("clear drops a tab's save", () => {
  p.set(1, data, "https://a.com/");
  p.clear(1);
  expect(p.take(1, "https://a.com/")).toBeNull();
});

test("an offer comes from the app's lookup, or updates the page's own draft without asking", async () => {
  const lookup = async (u: string, pw: string) =>
    pw === "same" ? { status: "same" as const, itemId: "i1" } : u === "known" ? { status: "changed" as const, itemId: "i1" } : { status: "new" as const, itemId: null };
  expect(await offerFor({ username: "known", password: "same", draftId: null }, lookup)).toBeNull();
  expect(await offerFor({ username: "known", password: "x", draftId: null }, lookup)).toEqual({ username: "known", password: "x", itemId: "i1", status: "changed" });
  expect(await offerFor({ username: "me", password: "x", draftId: null }, lookup)).toEqual({ username: "me", password: "x", itemId: null, status: "new" });
  expect(await offerFor({ username: "me", password: "same", draftId: "d1" }, lookup)).toEqual({ username: "me", password: "same", itemId: "d1", status: "changed" });
});
