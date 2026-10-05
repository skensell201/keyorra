// Mirrors crates/keepsake-session/src/bridge/crypto.rs; both are pinned by the same test vectors.
import { x25519 } from "@noble/curves/ed25519.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes } from "@noble/hashes/utils.js";

// Format label from the Lockbox days; kept so existing vaults and pairings stay readable.
export const PROTOCOL = "lockbox-bridge-v1";
const enc = new TextEncoder();
const dec = new TextDecoder();

export interface KeyPair {
  secret: Uint8Array;
  public: Uint8Array;
}

export function newKeyPair(secret: Uint8Array = randomBytes(32)): KeyPair {
  return { secret, public: x25519.getPublicKey(secret) };
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

export function derive(own: KeyPair, peerPublic: Uint8Array, clientPublic: Uint8Array, serverPublic: Uint8Array) {
  const shared = x25519.getSharedSecret(own.secret, peerPublic);
  const hash = (label: string) => sha256(concat(enc.encode(`${PROTOCOL}/${label}`), shared, clientPublic, serverPublic));
  const key = hash("key");
  const c = hash("code");
  const n = ((c[0] << 24) >>> 0) + (c[1] << 16) + (c[2] << 8) + c[3];
  return { key, code: String(n % 1_000_000).padStart(6, "0") };
}

const NONCE_LEN = 24;
const TAG_LEN = 16;

/** What the client sends before revealing its public key. */
export function commitment(clientPublic: Uint8Array): Uint8Array {
  return sha256(concat(enc.encode(`${PROTOCOL}/commit`), clientPublic));
}

/** A request, or a reply bound to the nonce of the request box it answers. */
export type Direction = "req" | { requestNonce: Uint8Array };

function aad(clientId: string, direction: Direction): Uint8Array {
  const head = enc.encode(`${PROTOCOL}/${clientId}/`);
  return direction === "req"
    ? concat(head, enc.encode("req"))
    : concat(head, enc.encode("res/"), direction.requestNonce);
}

/** The nonce of a well-formed box, or null. */
export function nonceOf(boxed: string): Uint8Array | null {
  try {
    const raw = fromB64(boxed);
    return raw.length < NONCE_LEN + TAG_LEN ? null : raw.slice(0, NONCE_LEN);
  } catch {
    return null;
  }
}

export function seal(key: Uint8Array, clientId: string, direction: Direction, value: unknown, nonce: Uint8Array = randomBytes(24)): string {
  const ciphertext = xchacha20poly1305(key, nonce, aad(clientId, direction)).encrypt(enc.encode(JSON.stringify(value)));
  return toB64(concat(nonce, ciphertext));
}

export function open<T>(key: Uint8Array, clientId: string, direction: Direction, boxed: string): T | null {
  try {
    const raw = fromB64(boxed);
    if (raw.length < NONCE_LEN + TAG_LEN) return null;
    const plain = xchacha20poly1305(key, raw.slice(0, NONCE_LEN), aad(clientId, direction)).decrypt(raw.slice(NONCE_LEN));
    return JSON.parse(dec.decode(plain)) as T;
  } catch {
    return null;
  }
}

/** Opens a reply; it only authenticates against the request box it answers. */
export function openReply<T>(key: Uint8Array, clientId: string, requestBox: string, boxed: string): T | null {
  const requestNonce = nonceOf(requestBox);
  return requestNonce ? open<T>(key, clientId, { requestNonce }, boxed) : null;
}

export function toB64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function fromB64(text: string): Uint8Array {
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}
