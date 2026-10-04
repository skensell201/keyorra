import { expect, test } from "vitest";
import { authorize } from "./access";

const ID = "abc";
const BASE = "chrome-extension://abc/";
const ext = { id: ID, url: `${BASE}popup.html` };
const page = { id: ID, url: "https://github.com/login" };
const run = (msg: any, sender: any) => authorize(msg, sender, ID, BASE);

test("pairing only from the extension's own pages", () => {
  for (const type of ["pair", "pairStatus", "pairingCode"]) {
    expect(run({ type }, ext).ok).toBe(true);
    expect(run({ type }, page).ok).toBe(false);
    expect(run({ type }, {}).ok).toBe(false);
  }
});

test("state and show are also open to pages", () => {
  for (const type of ["state", "show"]) {
    expect(run({ type }, page).ok).toBe(true);
    expect(run({ type }, ext).ok).toBe(true);
    expect(run({ type }, { id: ID, url: "file:///x" }).ok).toBe(false);
  }
});

test("a page's list and fill use the URL the browser reports", () => {
  expect(run({ type: "list", url: "https://evil.com" }, page)).toEqual({ ok: true, url: "https://github.com/login" });
  expect(run({ type: "fill", itemId: "i", url: "https://evil.com" }, page)).toEqual({ ok: true, url: "https://github.com/login" });
});

test("the popup lists with its own URL but cannot fill", () => {
  expect(run({ type: "list", url: "https://github.com" }, ext)).toEqual({ ok: true, url: "https://github.com" });
  expect(run({ type: "list" }, ext).ok).toBe(false);
  expect(run({ type: "fill", itemId: "i" }, ext).ok).toBe(false);
});

test("another extension and unknown types are refused", () => {
  expect(run({ type: "pair" }, { id: "other", url: `${BASE}x.html` }).ok).toBe(false);
  expect(run({ type: "nope" }, ext).ok).toBe(false);
  expect(run(undefined, ext).ok).toBe(false);
});

const PAGE_URL = "https://github.com/login";
const pageOnly: any[] = [
  { type: "lookup", username: "u", password: "p" },
  { type: "save", username: "u", password: "p", itemId: null },
  { type: "generate" },
  { type: "cards" },
  { type: "fillCard", itemId: "i" },
  { type: "identities" },
  { type: "fillIdentity", itemId: "i" },
];

test("save, generate, cards and identities are for http(s) pages and use the browser's URL", () => {
  for (const msg of pageOnly) {
    expect(run({ ...msg, url: "https://evil.com" }, page)).toEqual({ ok: true, url: PAGE_URL });
    expect(run(msg, { id: ID, url: "file:///x" }).ok).toBe(false);
    expect(run(msg, {}).ok).toBe(false);
  }
});

test("save, generate, cards and identities are refused from extension pages and other extensions", () => {
  for (const msg of pageOnly) {
    expect(run({ ...msg, url: "https://github.com" }, ext).ok).toBe(false);
    expect(run(msg, { id: "other", url: "chrome-extension://other/x.html" }).ok).toBe(false);
  }
});

const submitted = { type: "submitted", username: "u", password: "p", draftId: null };
const top = { ...page, frameId: 0 };

test("submissions come from any page frame and use the browser's URL", () => {
  expect(run({ ...submitted, url: "https://evil.com" }, top)).toEqual({ ok: true, url: PAGE_URL });
  expect(run(submitted, { ...page, frameId: 3 })).toEqual({ ok: true, url: PAGE_URL });
  expect(run(submitted, { ...ext, frameId: 0 }).ok).toBe(false);
  expect(run(submitted, { id: ID, url: "file:///x", frameId: 0 }).ok).toBe(false);
  expect(run(submitted, {}).ok).toBe(false);
});

test("submitted validates its fields", () => {
  expect(run({ ...submitted, draftId: "d1" }, top).ok).toBe(true);
  expect(run({ ...submitted, username: 5 }, top).ok).toBe(false);
  expect(run({ ...submitted, password: undefined }, top).ok).toBe(false);
  expect(run({ ...submitted, draftId: 7 }, top).ok).toBe(false);
});

test("taking and clearing a pending save is top-frame only and uses the browser's URL", () => {
  for (const msg of [{ type: "takePendingSave" }, { type: "clearPendingSave" }]) {
    expect(run({ ...msg, url: "https://evil.com" }, top)).toEqual({ ok: true, url: PAGE_URL });
    expect(run(msg, { ...page, frameId: 3 }).ok).toBe(false);
    expect(run(msg, page).ok).toBe(false);
    expect(run(msg, { ...ext, frameId: 0 }).ok).toBe(false);
    expect(run(msg, {}).ok).toBe(false);
  }
});

test("the content script can no longer park arbitrary pending saves", () => {
  expect(run({ type: "pendingSave", username: "u", password: "p", itemId: null, status: "new" }, top).ok).toBe(false);
});
