import { expect, test } from "vitest";
import { commitment, derive, fromB64, newKeyPair, nonceOf, open, openReply, seal, toB64 } from "./crypto";

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const fromHex = (h: string) => Uint8Array.from(h.match(/../g)!, (x) => parseInt(x, 16));
const CLIENT_ID = "11111111-1111-4111-8111-111111111111";

test("matches the shared test vectors", () => {
  const client = newKeyPair(new Uint8Array(32).fill(1));
  const server = newKeyPair(new Uint8Array(32).fill(2));
  expect(hex(client.public)).toBe("a4e09292b651c278b9772c569f5fa9bb13d906b46ab68c9df9dc2b4409f8a209");
  expect(hex(server.public)).toBe("ce8d3ad1ccb633ec7b70c17814a5c76ecd029685050d344745ba05870e587d59");
  const d = derive(client, server.public, client.public, server.public);
  expect(hex(d.key)).toBe("a178ba3480042df492c34be53f4b5698d8225ccb1315b67df195bf5842f451ab");
  expect(d.code).toBe("381262");
  expect(seal(d.key, CLIENT_ID, "req", { op: "ping" }, new Uint8Array(24).fill(3))).toBe(
    "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMD1AE3nLoQfQz8s+kYte/Lb0sVrtQoMnmqsIE17w4=",
  );
  expect(hex(commitment(client.public))).toBe("0508377f5f81fe96b49ca9716290979eb78f4998351ea5839718bcb263fd3f72");
});

test("replies match the shared vector and are bound to their request", () => {
  const key = fromHex("a178ba3480042df492c34be53f4b5698d8225ccb1315b67df195bf5842f451ab");
  const requestBox = seal(key, CLIENT_ID, "req", { op: "ping" }, new Uint8Array(24).fill(3));
  const replyVector = "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEygTHFmx53/OhKi8d/MurWGQxk4F6NCh6C7zMkk8=";
  expect(openReply(key, CLIENT_ID, requestBox, replyVector)).toEqual({ pong: true });
  const otherRequest = seal(key, CLIENT_ID, "req", { op: "ping" }, new Uint8Array(24).fill(5));
  expect(openReply(key, CLIENT_ID, otherRequest, replyVector)).toBeNull();
  expect(openReply(key, "other", requestBox, replyVector)).toBeNull();
  expect(openReply(key, CLIENT_ID, "AAAA", replyVector)).toBeNull();
});

test("boxes are bound to key, client and direction", () => {
  const key = new Uint8Array(32).fill(7);
  const boxed = seal(key, CLIENT_ID, "req", { hello: 1 });
  expect(open(key, CLIENT_ID, "req", boxed)).toEqual({ hello: 1 });
  expect(open(key, CLIENT_ID, { requestNonce: new Uint8Array(24) }, boxed)).toBeNull();
  expect(open(key, "other", "req", boxed)).toBeNull();
  expect(open(new Uint8Array(32).fill(8), CLIENT_ID, "req", boxed)).toBeNull();
  expect(open(key, CLIENT_ID, "req", "AAAA")).toBeNull();
  expect(seal(key, CLIENT_ID, "req", { hello: 1 })).not.toBe(boxed);
});

test("nonceOf reads the nonce of a well-formed box only", () => {
  const boxed = seal(new Uint8Array(32).fill(7), CLIENT_ID, "req", {}, new Uint8Array(24).fill(9));
  expect(nonceOf(boxed)).toEqual(new Uint8Array(24).fill(9));
  expect(nonceOf("AAAA")).toBeNull();
  expect(nonceOf("!!!")).toBeNull();
});

test("base64 round trip", () => {
  const bytes = new Uint8Array([0, 1, 254, 255]);
  expect(fromB64(toB64(bytes))).toEqual(bytes);
});
