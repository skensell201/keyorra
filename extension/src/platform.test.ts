import { expect, test } from "vitest";
import { Client, type Pairing } from "./client";
import { browserName, nativeSender } from "./platform";

const SAFARI_UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15";
const CHROME_UA =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";
const FIREFOX_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:143.0) Gecko/20100101 Firefox/143.0";

test("Safari pairs as Safari, though its user agent looks like any WebKit browser", () => {
  expect(browserName(SAFARI_UA, "safari-web-extension://3E1F7A2B-0000-4000-8000-000000000000/")).toBe("Safari");
  expect(browserName(CHROME_UA, "chrome-extension://kaaofpbpmnghapcafbbhjflonijdijbj/")).toBe("Chrome");
  expect(browserName(FIREFOX_UA, "moz-extension://5a1b2c3d-0000-4000-8000-000000000000/")).toBe("Firefox");
  expect(browserName(`${CHROME_UA} Edg/140.0.0.0`, "chrome-extension://x/")).toBe("Edge");
});

const memory = () => {
  let pairing: Pairing | null = null;
  let pending: Pairing | null = null;
  return {
    get: async () => pairing,
    set: async (p: Pairing) => void (pairing = p),
    clear: async () => void (pairing = null),
    getPending: async () => pending,
    setPending: async (p: Pairing | null) => void (pending = p),
  };
};

test("Safari's noApp answer reads as a missing app, like a Chromium host that exits", async () => {
  const safari = nativeSender({ sendNativeMessage: async () => ({ kind: "noApp", message: "connect: No such file" }) }, "h");
  expect(await new Client(safari, memory()).state()).toBe("noApp");
  const empty = nativeSender({ sendNativeMessage: async () => undefined }, "h");
  expect(await new Client(empty, memory()).state()).toBe("noApp");
  const chromium = nativeSender({ sendNativeMessage: () => Promise.reject(new Error("Native host has exited.")) }, "h");
  expect(await new Client(chromium, memory()).state()).toBe("noApp");
});

test("replies from the app pass through untouched", async () => {
  const seen: unknown[] = [];
  const send = nativeSender(
    {
      sendNativeMessage: async (host, msg) => {
        seen.push([host, msg]);
        return { kind: "status", locked: true, version: 1 };
      },
    },
    "app.keyorra.bridge",
  );
  expect(await send({ kind: "status" })).toEqual({ kind: "status", locked: true, version: 1 });
  expect(seen).toEqual([["app.keyorra.bridge", { kind: "status" }]]);
});
