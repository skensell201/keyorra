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
