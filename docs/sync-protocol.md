# Keyorra Sync Protocol

Version: 1 (draft). Status: sections 1–8 are defined and implemented in `crates/keyorra-sync`
(plan A1a); later sections are placeholders filled by later plans. The design rationale is in
`docs/superpowers/specs/2026-10-05-keyorra-sync-design.md`; this document is the normative
description. Any change to bytes on the wire changes this file in the same commit.

Test vectors: `docs/sync-test-vectors/a1a.json` (fixed inputs → exact outputs). An
implementation is conforming for this part when it reproduces every value in that file.

## 1. Notation

- `‖` concatenation; `x:N` a field of N bytes; integers in headers are unsigned big-endian
  (`u32` = 4 bytes, `u64` = 8 bytes).
- `SHA-256`, `HKDF-SHA256` (RFC 5869), `Ed25519` (RFC 8032, verification with the strict
  rules of `ed25519-dalek` `verify_strict`), `XChaCha20-Poly1305` (draft-irtf-cfrg-xchacha;
  sealed output is `nonce:24 ‖ ciphertext ‖ tag:16`).
- `Argon2id` (RFC 9106, version 0x13).
- `canonical(v)`: the deterministic CBOR encoding of section 3.
- Hex in this document and in the vectors is lowercase.

## 2. Labels

Every label is used as `label ‖ 0x00 ‖ parts…`, so no label is a prefix of another.

| Label | Used for |
|---|---|
| `keyorra/sync/v1/kek` | HKDF info for `KEK_sync` |
| `keyorra/sync/v1/server-auth` | HKDF info for `AUTH` |
| `keyorra/sync/v1/segment-key` | HKDF info for `K_seg` |
| `keyorra/sync/v1/account-key` | AAD of the wrapped account key |
| `keyorra/sync/v1/header` | header signature |
| `keyorra/sync/v1/body` | AAD of record bodies |
| `keyorra/sync/v1/version` | version hash |
| `keyorra/sync/v1/chunk` | AAD of attachment chunks |
| `keyorra/sync/v1/segment` | segment signature |
| `keyorra/sync/v1/snapshot` | snapshot signature |
| `keyorra/sync/v1/chain-genesis` | first link of a stream's hash chain |
| `keyorra/sync/v1/chain` | every further link |

## 3. Canonical CBOR

A subset of RFC 8949: major types 0 (unsigned integer), 2 (byte string), 3 (UTF-8 text),
4 (array), 5 (map) and the simple values `false` (0xf4), `true` (0xf5), `null` (0xf6).

Encoding: the shortest head for every length or integer; definite lengths only; map entries
sorted by the bytewise order of their encoded keys, no duplicate keys.

Decoding is strict and rejects: non-shortest heads, indefinite lengths, reserved
additional-information values, negative integers, tags, floats and other simple values,
unsorted or duplicate map keys, invalid UTF-8, lengths beyond the input, nesting deeper
than 32, and trailing bytes. Structures are maps with text keys and exactly the listed
fields.

## 4. Padding

`pad(data) = data ‖ 0x80 ‖ 0x00…` up to `max(1024, padme(len(data) + 1))` bytes, where
`padme(L)` (Padmé, PURBs paper, PETS 2019) is: for `L < 2`, `L`; otherwise
`E = floor(log2 L)`, `S = floor(log2 E) + 1`, `mask = 2^(E−S) − 1`,
`padme(L) = (L + mask) & ~mask`. Unpadding strips trailing zeros, requires the last
non-zero byte to be `0x80` and the total length to equal the formula. Applied to segment
payloads, snapshot payloads and attachment chunks.

## 5. Secret Key and keys

**Secret Key.** 16 random bytes `SK` and an independent 4-character id (random digits of
the alphabet below). Display: `ID-ddddd-ddddd-ddddd-ddddd-ddddd-dc` where the 26 `d` are the
big-endian base32 digits of `SK` as a 128-bit integer (Crockford alphabet
`0123456789ABCDEFGHJKMNPQRSTVWXYZ`; the first digit is at most 7) and `c` is
`"0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U"[SK mod 37]`. Parsing ignores case, hyphens and
whitespace and maps `I`, `L` → `1` and `O` → `0`.

**Derivation.**

```
U        = Argon2id(password, salt, m, t, p, 32 bytes)        salt, m, t, p from the account header
M        = HKDF-Extract(salt = SK, ikm = U)
KEK_sync = HKDF-Expand(M, "keyorra/sync/v1/kek\0" ‖ account_id, 32)
AUTH     = HKDF-Expand(M, "keyorra/sync/v1/server-auth\0" ‖ account_id, 32)
K_seg    = HKDF(salt = account_id, ikm = AK, info = "keyorra/sync/v1/segment-key\0", 32)
```

KDF parameters read from a header must satisfy, before Argon2 runs: `m ≤ 1048576` KiB,
`1 ≤ t ≤ 10`, `1 ≤ p ≤ 4` (and Argon2's own minimum `m ≥ 8p`).

## 6. Account header

```
Header = { "keyorra_sync": 1, "account_id": bytes16, "epoch": uint32, "generation": uint32,
           "root_device": bytes16, "kdf": { "m_kib", "t", "p" }, "salt": bytes16,
           "secret_key_id": text(4), "wrapped_account_key": bytes }
wrapped_account_key = XChaCha20-Poly1305(KEK_sync, nonce, AK,
                        aad = "keyorra/sync/v1/account-key\0" ‖ account_id ‖ epoch:u32 ‖ generation:u32)
HeaderFile = { "header": Header, "author": bytes16, "sig": bytes64 }
sig        = Ed25519(author key, "keyorra/sync/v1/header\0" ‖ canonical(Header))
file name  = hex8(epoch) ‖ "-" ‖ hex(author) ‖ ".hdr"
```

A `keyorra_sync` value other than 1 is "unsupported", not "malformed". Which header counts
(highest epoch, matching log entry, tie-breaks) is defined in section 10.

## 7. Record envelopes, versions and bodies

```
Version  = { "vector": { bytes16 → uint ≥ 1 }, "hlc": uint, "author": bytes16 }
Envelope = { "format": 1, "kind": "vault" | "item" | "attachment", "record_id": bytes16,
             "vault_id": bytes16 | null, "schema": uint32, "version": Version,
             "tombstone": bool, "body": bytes | null }
version_hash = SHA-256("keyorra/sync/v1/version\0" ‖ canonical([kind, record_id, version]))
header_hash  = SHA-256(canonical(envelope with "body" = null))
body (item, attachment) = XChaCha20-Poly1305(vault key, nonce, payload,
                            aad = "keyorra/sync/v1/body\0" ‖ account_id ‖ header_hash)
body (vault) = the plaintext payload (protected by the segment layer)
```

Rules: `tombstone` is true exactly when `body` is null; `item` and `attachment` envelopes
have a `vault_id`. Unknown `format` or `kind`: unsupported (kept, not interpreted). The
payload contents and the merge rules are defined in section 9.

## 8. Framing: chunks, segments, snapshots

**Attachment chunk** (at most 4 MiB of data):

```
chunk = "KYC1" ‖ XChaCha20-Poly1305(attachment key, nonce, pad(data),
          aad = "keyorra/sync/v1/chunk\0" ‖ account_id ‖ attachment_id:16 ‖ index:u32 ‖ count:u32)
name  = hex(SHA-256(chunk))
```

**Segment.**

```
header  = "KYS1" ‖ collection:u8 (= 0) ‖ device_id:16 ‖ first_seq:u64 ‖ last_seq:u64 ‖ prev_hash:32 ‖ last_hash:32
segment = header ‖ nonce:24 ‖ XChaCha20-Poly1305(K_seg, nonce, pad(canonical(payload)), aad = header ‖ nonce)
payload = { "entries": [entry, …], "sig": Ed25519(device key, "keyorra/sync/v1/segment\0" ‖ header ‖ canonical(entries)) }
chain_0 = SHA-256("keyorra/sync/v1/chain-genesis\0" ‖ account_id ‖ device_id)
chain_n = SHA-256("keyorra/sync/v1/chain\0" ‖ chain_{n−1} ‖ canonical(entry_n))
```

`first_seq ≥ 1`; the entry count equals `last_seq − first_seq + 1`; `last_hash` is the chain
over the entries starting from `prev_hash`; the canonical entries are at most 4 MiB. A
non-zero collection is unsupported in version 1 (reserved for shared vaults).

**Snapshot.**

```
header   = "KYP1" ‖ collection:u8 (= 0) ‖ author:16
snapshot = header ‖ nonce:24 ‖ XChaCha20-Poly1305(K_seg, nonce, pad(canonical(payload)), aad = header ‖ nonce)
payload  = { "body": …, "sig": Ed25519(author key, "keyorra/sync/v1/snapshot\0" ‖ header ‖ canonical(body)) }
name     = hex(SHA-256(snapshot))
```

## 9. Fold and presentation

To be defined by plan A1b (sibling sets, presentation rules, conflict copies).

## 10. Streams, entries and trust

To be defined by plan A1c (entry types, endorsement, acceptance rule, causal delivery,
headers as log entries, snapshot contents, restore, clone detection).

## 11. Folder transport

To be defined by plan A2.

## 12. Server API

To be defined by plans B1 and B2.
