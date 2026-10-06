# Keyorra Sync A1c-2 Implementation Plan (recovery and bootstrap, on root-only authority)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Everything a device needs to start, recover and continue, on top of root-only authority (the main device alone approves and removes devices): account headers as signed entries of the main device's stream, binding the main device's id **and key**; the main device's **advertised head** as a signed file in the store; joining from the header files (highest epoch only); snapshots for bootstrap (from the main device only), anchoring and "Restore from this Mac"; retiring the device id when another copy of it wrote or its key is gone (the new id is pending until the main device approves it); and the outbox persistence hook for A1d.

**Builds on:** `feat/sync-design` at `5a771ab` (root-only authority with the third review's fixes: vault ids commit to creator and key, bounded claims, key codes on approval, advertised root head hook, deterministic rejection).

**Verified:** every task was applied in order in a scratch worktree from `5a771ab`; the full suite passes (223 tests, 1 ignored), clippy is clean, and the adversary and convergence property tests pass at 2000 cases in release.

**Architecture:** `keyorra-sync` stays pure. New modules: `account` (choosing and unlocking header files when joining), `pack` (the snapshot body), `root_head` (the main device's signed head file). The engine gains four submodules: `engine/headers` (header entries, adoption, old-file deletion, the root head file), `engine/snapshots` (writing, bootstrap, anchoring, restore), `engine/retire` (new id and key; the main device instead asks to start over), `engine/outbox` (persistence hook). `Transport` gains header, snapshot and root-head file operations. `Header` gains `root_key`, which changes the pinned test vectors (regenerated deliberately).

**Tech Stack:** unchanged.

## Spec changes (patch for the coordinator to apply with this plan)

Apply to `docs/superpowers/specs/2026-10-05-keyorra-sync-design.md`:

1. **§4.2, "Retiring" paragraph**, replace with:

   > Retiring: local unsynced edits are kept; the device generates a new id and key and joins with `SelfJoin`, pending until the main device approves it (comparing the key code); its first entries are the queued edits as new versions. Only the main device removes the old id (A3 suggests it). **The main device never retires**: its id and key anchor the account. If another copy of it wrote, or its key is gone, it stops writing and the user is asked to start a new account from a device and carry the data over (A1d/A3 flow, §4.3).

2. **§4.3, "The root's head is advertised"**: replace "the account header (A1c-2) and the setup code carry the root's current head" with "a small file signed by the main device (`root.head`, rewritten after every confirmed append) and the setup code carry the root's current head; a reader only moves it forward". (The header itself cannot carry the head: it is bound into the wrapped account key and changes only with the password.)

3. **§4.7 Account headers**: add the field `root_key` (the main device's public key, bound like every other field) and state: "Only the main device publishes headers (a master password change happens there); a `Header` entry in another stream is ignored. A joining device takes the main device's id and key from the header it unlocked, never from the streams. Old header files are deleted once every approved device has adopted the new epoch (`HeaderSeen`)." Remove the rule about concurrent epochs and the lowest author (there is only one publisher).

4. **§4.8 Snapshots**: add: "What a snapshot vouches for depends on its author. A device with nothing yet bootstraps only from a snapshot of the main device (verified with the key from the header). A snapshot of the main device anchors any stream; a snapshot of another approved device anchors only its own stream. Restoring another device's rolled-back stream is done on the main device."

5. **§12**, the A1c-2 line: "Headers (root-published, root key bound), root head file, join from headers, snapshots (root bootstrap, author-scoped anchoring, restore), retire (pending re-approval; the main device asks to start over), outbox hook."

And to `docs/sync-protocol.md`: §6 header fields gain `"root_key": bytes32`; §10.1 gains the entries `header`, `header_seen`, `snapshot` (shapes below, Task 2); §10.2 gains "A `header` entry counts only in the root's stream"; §11 (folder transport) lists `root.head` next to the header and snapshot files.

## Decisions

- **Root-published headers.** A master password change is done on the main device. Otherwise a stolen approved device could publish a header with a password of its own and, once "everyone adopted it", get the old header files deleted. Readers ignore a `Header` entry outside the root's stream and one that names another root or root key.
- **The header binds the root key.** It is part of the header's binding (the AAD of the wrapped account key), so only someone with the master password and Secret Key can change it. A joiner gets the root key from the header it unlocked. This makes `Engine::join`'s `root_key` argument (added on root-only authority) well-founded.
- **Root head file, not header field.** The head changes on every root append; the header changes only with the password. The root signs `(account_id, seq, hash)` under its own label and rewrites `root.head` after each confirmed append; readers verify with the root key and only move forward. The setup code shown by the main device may carry the same head (A3), so a fresh joiner is covered even if the store serves an old file.
- **Snapshots are scoped by author.** Only the root's word covers trust and other devices' records, so only a root snapshot bootstraps; a non-root snapshot anchors only its author's own stream; `restore(stream)` of another device's stream is refused on a non-root device.
- **Retiring.** A non-root device continues under a new id with `SelfJoin` and is pending until the root approves it with the key code; its unconfirmed changes are written again under the new id. The main device never retires: `Event::RootMustStartOver` and it stops writing (the "start a new account and carry the data over" flow is A1d/A3). An own-stream conflict counts as evidence when the store shows it directly (append conflict, stored head ahead) or the root's checkpoint says so; another device's claim about the own stream stays a dispute.
- **Outbox hook.** The engine saves `OutboxState` after every queued entry, after sealing a segment (before the append, so a restart retries the same bytes) and after every confirmation. A1d stores it in the same transaction as the local change.
- **Not here:** UI for alarms, codes and the start-over flow (A3); the setup code format with the root head (A3); key rotation and GC (C1).

## Conventions for every task

- Test first: write the test, run it, see it fail for the expected reason, implement, see it pass, commit.
- English only. Every commit message ends with these two lines (omitted below; always add them):

```
Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_016B8vpfBkT1rhCY8NF4kPbd
```

- Rust from the repo root. After each task: `cargo fmt --all`; `cargo clippy -p keyorra-sync --all-targets -- -D warnings` clean; `cargo test -p keyorra-sync` green.
- Shell: an `rtk` proxy may filter output; `rtk proxy <cmd>` runs it raw. Plain `grep` with a glob through the proxy can miss matches; use `grep -rn <dir>`.
- Patches below are `git diff` output against `5a771ab`; apply them with `git apply` (or by hand), in task order.
- Work on `feat/sync-design`; do not push.

## File map

```
crates/keyorra-sync/Cargo.toml                 test-utils feature forwards keyorra-core/test-utils
crates/keyorra-sync/src/header.rs              + Header::root_key (bound); sample_header for tests
crates/keyorra-sync/src/vectors.rs             header vector gains root_key (vectors regenerated)
docs/sync-test-vectors/a1a.json                regenerated (deliberate format change)
crates/keyorra-sync/src/entry.rs               + Header, HeaderSeen, Snapshot entries; heads_value/heads_from
crates/keyorra-sync/src/trust.rs               ignores the new entry kinds
crates/keyorra-sync/src/snapshot.rs            decrypt_snapshot + UnverifiedSnapshot::verify
crates/keyorra-sync/src/labels.rs              + ROOT_HEAD
crates/keyorra-sync/src/root_head.rs           NEW the main device's signed head file
crates/keyorra-sync/src/transport.rs           + header, snapshot and root head file operations
crates/keyorra-sync/src/faults.rs              the wrappers pass them through
crates/keyorra-sync/src/account.rs             NEW join candidates and unlocking
crates/keyorra-sync/src/pack.rs                NEW snapshot body
crates/keyorra-sync/src/fold.rs                + Fold::forget_after
crates/keyorra-sync/src/engine.rs              plumbing: events, fields, hooks in sync/receive/push
crates/keyorra-sync/src/engine/headers.rs      NEW
crates/keyorra-sync/src/engine/snapshots.rs    NEW
crates/keyorra-sync/src/engine/retire.rs       NEW
crates/keyorra-sync/src/engine/outbox.rs       NEW
crates/keyorra-sync/src/engine/recovery_tests.rs NEW
crates/keyorra-sync/src/engine/tests.rs        test transports pass the new operations; W1 test uses the file
crates/keyorra-sync/src/engine/attack_tests.rs NoHeads passes them; W3 joiner may retire
crates/keyorra-sync/src/testkit.rs             add_device, test_header, MemoryKeys, MemoryOutbox
crates/keyorra-sync/src/lib.rs                 + account, pack, root_head
docs/sync-protocol.md, spec                    see "Spec changes" above (Task 12)
```

---
### Task 1: The header binds the main device's key

**Files:** Modify `crates/keyorra-sync/src/header.rs`, `crates/keyorra-sync/src/vectors.rs`, `crates/keyorra-sync/src/testkit.rs` (header helper comes in Task 7), `crates/keyorra-sync/Cargo.toml`, `docs/sync-test-vectors/a1a.json`.

- [ ] **Step 1: Failing test.**

In `header.rs` `wrapped_key_is_bound_to_every_other_header_field`, add a tampered case `Header { root_key: [0x43; 32], ..h.clone() }`, and give `header_for` the field `root_key: [0x42; 32]`. Run `cargo test -p keyorra-sync header`: it does not compile (no field).

- [ ] **Step 2: Implement.**

Apply the patch (it also makes the test module `pub(crate)` with `sample_header`, used by later tasks):

```diff
diff --git a/crates/keyorra-sync/src/header.rs b/crates/keyorra-sync/src/header.rs
index bd9e11e..77e47f1 100644
--- a/crates/keyorra-sync/src/header.rs
+++ b/crates/keyorra-sync/src/header.rs
@@ -27,18 +27,23 @@ pub struct Header {
     pub epoch: u32,
     pub generation: u32,
     pub root_device: DeviceId,
+    /// The main device's public key: how a joining device learns it (never from the store's
+    /// streams). Bound into the wrapped account key like every other field, so only someone
+    /// with the master password and Secret Key can change it.
+    pub root_key: [u8; 32],
     pub kdf: KdfParams,
     pub salt: [u8; 16],
     pub secret_key_id: String,
     pub wrapped_account_key: Vec<u8>,
 }
 
-const FIELDS: [&str; 9] = [
+const FIELDS: [&str; 10] = [
     "keyorra_sync",
     "account_id",
     "epoch",
     "generation",
     "root_device",
+    "root_key",
     "kdf",
     "salt",
     "secret_key_id",
@@ -129,6 +134,7 @@ impl Header {
             ("epoch", Value::Uint(self.epoch.into())),
             ("generation", Value::Uint(self.generation.into())),
             ("root_device", Value::bytes(self.root_device)),
+            ("root_key", Value::bytes(self.root_key)),
             (
                 "kdf",
                 Value::map(vec![
@@ -169,6 +175,7 @@ impl Header {
             epoch: f.get("epoch")?.as_u32()?,
             generation: f.get("generation")?.as_u32()?,
             root_device: f.get("root_device")?.as_array_of()?,
+            root_key: f.get("root_key")?.as_array_of()?,
             kdf: KdfParams {
                 m_kib: kdf.get("m_kib")?.as_u32()?,
                 t: kdf.get("t")?.as_u32()?,
@@ -240,9 +247,14 @@ impl HeaderFile {
 }
 
 #[cfg(test)]
-mod tests {
+pub(crate) mod tests {
     use super::*;
 
+    /// A valid header for other modules' tests.
+    pub(crate) fn sample_header() -> Header {
+        header_for("pw", &Key::from_bytes([0x30; 32]), 1)
+    }
+
     const ACCOUNT: AccountId = [0x10; 16];
     const DEVICE: DeviceId = [0x40; 16];
     const SALT: [u8; 16] = [0x20; 16];
@@ -259,6 +271,7 @@ mod tests {
             epoch,
             generation: 1,
             root_device: DEVICE,
+            root_key: [0x42; 32],
             kdf,
             salt: SALT,
             secret_key_id: "A3K7".into(),
@@ -333,6 +346,10 @@ mod tests {
                 root_device: [0x41; 16],
                 ..h.clone()
             },
+            Header {
+                root_key: [0x43; 32],
+                ..h.clone()
+            },
             Header {
                 secret_key_id: "B3K7".into(),
                 ..h.clone()
```

```diff
diff --git a/crates/keyorra-sync/Cargo.toml b/crates/keyorra-sync/Cargo.toml
index a0b65c6..7f44643 100644
--- a/crates/keyorra-sync/Cargo.toml
+++ b/crates/keyorra-sync/Cargo.toml
@@ -20,7 +20,7 @@ zeroize = "1"
 
 [features]
 # Exposes the fault-injecting transport and the simulated cluster to other crates' tests.
-test-utils = []
+test-utils = ["keyorra-core/test-utils"]
 
 [dev-dependencies]
 keyorra-core = { path = "../keyorra-core", features = ["test-utils"] }
```

- [ ] **Step 3: Vectors.**

Apply:

```diff
diff --git a/crates/keyorra-sync/src/vectors.rs b/crates/keyorra-sync/src/vectors.rs
index 29c1cc7..35b5bce 100644
--- a/crates/keyorra-sync/src/vectors.rs
+++ b/crates/keyorra-sync/src/vectors.rs
@@ -89,6 +89,7 @@ pub(crate) fn compute() -> BTreeMap<String, String> {
         epoch: 1,
         generation: 1,
         root_device: device_id,
+        root_key: device_key.verifying_key().to_bytes(),
         kdf: KDF,
         salt,
         secret_key_id: "A3K7".into(),
```

Then `cargo test -p keyorra-sync write_vectors -- --ignored` (deliberate format change: the header gained a field) and check that only the header-related values in `docs/sync-test-vectors/a1a.json` changed.

- [ ] **Step 4: Run and commit.**

`cargo test -p keyorra-sync` green. Commit: `Sync A1c-2: the account header binds the main device's key`.

---

### Task 2: Header, header-seen and snapshot entries

**Files:** Modify `crates/keyorra-sync/src/entry.rs`, `crates/keyorra-sync/src/trust.rs`.

- [ ] **Step 1: Failing test.**

In `entry.rs` `samples()` add `Entry::Header(crate::header::tests::sample_header())`, `Entry::HeaderSeen { epoch: 3 }` and `Entry::Snapshot { name: [5; 32], frontier: … }` (see the patch), and extend `only_first_entries_carry_their_own_key` with three `false`. It fails to compile.

- [ ] **Step 2: Implement.**

Shapes:

```text
{ "header": Header }                        an account header (root's stream only)
{ "header_seen": epoch }                    the writer adopted this header epoch
{ "snapshot": { "name": bytes32, "frontier": { bytes16 → [seq, hash] } } }
```

Apply:

```diff
diff --git a/crates/keyorra-sync/src/entry.rs b/crates/keyorra-sync/src/entry.rs
index cd8586d..4362ea5 100644
--- a/crates/keyorra-sync/src/entry.rs
+++ b/crates/keyorra-sync/src/entry.rs
@@ -5,9 +5,12 @@
 //!       | { "checkpoint": { bytes16 → [seq, hash] } }        heads of other streams applied by the writer
 //!       | { "genesis": { "account_id", "key", "name" } }     the root device, first entry of its stream
 //!       | { "self_join": { "key", "name", "sig" } }          a device that joined with the Emergency Kit
-//!       | { "endorse": { "device", "key", "name", "sig" } }  a live device vouches for another one
+//!       | { "endorse": { "device", "key", "name", "sig" } }  the main device approves a device
 //!       | { "revoke": { "device", "last_valid_seq", "last_valid_hash" } }
 //!                                                          entries of `device` after the cut stop counting
+//!       | { "header": Header }                               an account header (plan A1c-2)
+//!       | { "header_seen": epoch }                           the writer adopted this header epoch
+//!       | { "snapshot": { "name", "frontier" } }             the writer published this snapshot
 //! sig   = Ed25519(signer, "keyorra/sync/v1/endorse\0" ‖ account_id ‖ device ‖ key)
 //! ```
 //!
@@ -21,6 +24,7 @@ use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
 use crate::cbor::Value;
 use crate::envelope::Envelope;
 use crate::error::{malformed, Error, Result};
+use crate::header::Header;
 use crate::labels::{self, tagged};
 use crate::{AccountId, DeviceId};
 
@@ -61,6 +65,46 @@ pub enum Entry {
         /// refers to (zeros for a cut at 0).
         last_valid_hash: [u8; 32],
     },
+    Header(Header),
+    HeaderSeen {
+        epoch: u32,
+    },
+    Snapshot {
+        /// SHA-256 of the snapshot file.
+        name: [u8; 32],
+        frontier: Heads,
+    },
+}
+
+pub(crate) fn heads_value(heads: &Heads) -> Value {
+    Value::Map(
+        heads
+            .iter()
+            .map(|(d, h)| {
+                (
+                    Value::bytes(d),
+                    Value::Array(vec![Value::Uint(h.seq), Value::bytes(h.hash)]),
+                )
+            })
+            .collect(),
+    )
+}
+
+pub(crate) fn heads_from(value: &Value) -> Result<Heads> {
+    let mut heads = Heads::new();
+    for (d, h) in value.as_map()? {
+        let [seq, hash] = h.as_list()? else {
+            return Err(malformed("head"));
+        };
+        heads.insert(
+            d.as_array_of()?,
+            Head {
+                seq: seq.as_uint()?,
+                hash: hash.as_array_of()?,
+            },
+        );
+    }
+    Ok(heads)
 }
 
 /// What an endorsement (or a self-join) signs.
@@ -98,20 +142,7 @@ impl Entry {
     pub fn to_value(&self) -> Value {
         let (tag, body) = match self {
             Entry::Put(env) => ("put", env.to_value()),
-            Entry::Checkpoint(heads) => (
-                "checkpoint",
-                Value::Map(
-                    heads
-                        .iter()
-                        .map(|(d, h)| {
-                            (
-                                Value::bytes(d),
-                                Value::Array(vec![Value::Uint(h.seq), Value::bytes(h.hash)]),
-                            )
-                        })
-                        .collect(),
-                ),
-            ),
+            Entry::Checkpoint(heads) => ("checkpoint", heads_value(heads)),
             Entry::Genesis {
                 account_id,
                 key,
@@ -158,6 +189,15 @@ impl Entry {
                     ("last_valid_hash", Value::bytes(last_valid_hash)),
                 ]),
             ),
+            Entry::Header(header) => ("header", header.to_value()),
+            Entry::HeaderSeen { epoch } => ("header_seen", Value::Uint((*epoch).into())),
+            Entry::Snapshot { name, frontier } => (
+                "snapshot",
+                Value::map(vec![
+                    ("name", Value::bytes(name)),
+                    ("frontier", heads_value(frontier)),
+                ]),
+            ),
         };
         Value::map(vec![(tag, body)])
     }
@@ -171,22 +211,7 @@ impl Entry {
         let tag = tag.as_text()?;
         Ok(match tag {
             "put" => Entry::Put(Envelope::from_value(body)?),
-            "checkpoint" => {
-                let mut heads = Heads::new();
-                for (d, h) in body.as_map()? {
-                    let [seq, hash] = h.as_list()? else {
-                        return Err(malformed("checkpoint head"));
-                    };
-                    heads.insert(
-                        d.as_array_of()?,
-                        Head {
-                            seq: seq.as_uint()?,
-                            hash: hash.as_array_of()?,
-                        },
-                    );
-                }
-                Entry::Checkpoint(heads)
-            }
+            "checkpoint" => Entry::Checkpoint(heads_from(body)?),
             "genesis" => {
                 let f = body.fields(&["account_id", "key", "name"])?;
                 Entry::Genesis {
@@ -220,6 +245,17 @@ impl Entry {
                     last_valid_hash: f.get("last_valid_hash")?.as_array_of()?,
                 }
             }
+            "header" => Entry::Header(Header::from_value(body)?),
+            "header_seen" => Entry::HeaderSeen {
+                epoch: body.as_u32()?,
+            },
+            "snapshot" => {
+                let f = body.fields(&["name", "frontier"])?;
+                Entry::Snapshot {
+                    name: f.get("name")?.as_array_of()?,
+                    frontier: heads_from(f.get("frontier")?)?,
+                }
+            }
             other => return Err(Error::Unsupported(format!("entry type {other}"))),
         })
     }
@@ -291,6 +327,20 @@ mod tests {
                 last_valid_seq: 12,
                 last_valid_hash: [6; 32],
             },
+            Entry::Header(crate::header::tests::sample_header()),
+            Entry::HeaderSeen { epoch: 3 },
+            Entry::Snapshot {
+                name: [5; 32],
+                frontier: [(
+                    [2; 16],
+                    Head {
+                        seq: 9,
+                        hash: [8; 32],
+                    },
+                )]
+                .into_iter()
+                .collect(),
+            },
         ]
     }
 
@@ -335,6 +385,9 @@ mod tests {
     #[test]
     fn only_first_entries_carry_their_own_key() {
         let keys: Vec<bool> = samples().iter().map(|e| e.own_key().is_some()).collect();
-        assert_eq!(keys, [false, false, true, true, false, false]);
+        assert_eq!(
+            keys,
+            [false, false, true, true, false, false, false, false, false]
+        );
     }
 }
```

```diff
diff --git a/crates/keyorra-sync/src/trust.rs b/crates/keyorra-sync/src/trust.rs
index 4762851..5b6132c 100644
--- a/crates/keyorra-sync/src/trust.rs
+++ b/crates/keyorra-sync/src/trust.rs
@@ -293,7 +293,11 @@ impl Trust {
                     }
                 }
             }
-            Entry::Put(_) | Entry::Checkpoint(_) => Ok(false),
+            Entry::Put(_)
+            | Entry::Checkpoint(_)
+            | Entry::Header(_)
+            | Entry::HeaderSeen { .. }
+            | Entry::Snapshot { .. } => Ok(false),
         }
     }
 }
```

- [ ] **Step 3: Run and commit.**

Commit: `Sync A1c-2: header, header-seen and snapshot entries`.

---

### Task 3: Snapshots: decrypt first, verify with a key found later

**Files:** Modify `crates/keyorra-sync/src/snapshot.rs`.

- [ ] **Step 1: Failing test and implementation.**

The test `decrypt_then_verify_equals_open` is in the patch; add it first, see it fail to compile, then apply the rest:

```diff
diff --git a/crates/keyorra-sync/src/snapshot.rs b/crates/keyorra-sync/src/snapshot.rs
index 363f9a1..c8a87e2 100644
--- a/crates/keyorra-sync/src/snapshot.rs
+++ b/crates/keyorra-sync/src/snapshot.rs
@@ -109,6 +109,31 @@ pub fn open_snapshot(
     author: &VerifyingKey,
     snapshot: &[u8],
 ) -> Result<(SnapshotHeader, Value)> {
+    decrypt_snapshot(segment_key, snapshot)?.verify(author)
+}
+
+/// A decrypted snapshot whose signature is not checked yet: the author's key may only be known
+/// from the trust entries inside it (bootstrap, plan A1c-2).
+#[derive(Clone, Debug)]
+pub struct UnverifiedSnapshot {
+    pub header: SnapshotHeader,
+    pub body: Value,
+    sig: [u8; 64],
+}
+
+impl UnverifiedSnapshot {
+    pub fn verify(self, author: &VerifyingKey) -> Result<(SnapshotHeader, Value)> {
+        author
+            .verify_strict(
+                &signed_message(&self.header.to_bytes(), &self.body),
+                &Signature::from_bytes(&self.sig),
+            )
+            .map_err(|_| Error::BadSignature)?;
+        Ok((self.header, self.body))
+    }
+}
+
+pub fn decrypt_snapshot(segment_key: &Key, snapshot: &[u8]) -> Result<UnverifiedSnapshot> {
     if snapshot.len() > max_snapshot_len() {
         return Err(malformed("snapshot larger than allowed"));
     }
@@ -127,15 +152,9 @@ pub fn open_snapshot(
     }
     let payload = cbor::decode(content)?;
     let f = payload.fields(&["body", "sig"])?;
-    let body = f.get("body")?;
+    let body = f.get("body")?.clone();
     let sig: [u8; 64] = f.get("sig")?.as_array_of()?;
-    author
-        .verify_strict(
-            &signed_message(&header_bytes, body),
-            &Signature::from_bytes(&sig),
-        )
-        .map_err(|_| Error::BadSignature)?;
-    Ok((header, body.clone()))
+    Ok(UnverifiedSnapshot { header, body, sig })
 }
 
 /// The file/blob name: lowercase hex SHA-256 of the snapshot bytes.
@@ -182,6 +201,21 @@ mod tests {
         assert_eq!(sealed().len(), HEADER_LEN + NONCE_LEN + 1024 + 16);
     }
 
+    #[test]
+    fn decrypt_then_verify_equals_open() {
+        let unverified = decrypt_snapshot(&k_seg(), &sealed()).unwrap();
+        assert_eq!(unverified.body, body());
+        let other = SigningKey::from_bytes(&[0x42; 32]).verifying_key();
+        assert!(matches!(
+            unverified.clone().verify(&other),
+            Err(Error::BadSignature)
+        ));
+        assert_eq!(
+            unverified.verify(&signer().verifying_key()).unwrap(),
+            open_snapshot(&k_seg(), &signer().verifying_key(), &sealed()).unwrap()
+        );
+    }
+
     #[test]
     fn author_bytes_wrong_key_and_wrong_signer_fail() {
         let pk = signer().verifying_key();
```

- [ ] **Step 2: Run and commit.**

Commit: `Sync A1c-2: snapshots open in two steps`.

---

### Task 4: Store files: headers, snapshots, the main device's head

**Files:** Create `crates/keyorra-sync/src/root_head.rs`; modify `labels.rs`, `transport.rs`, `faults.rs`, `lib.rs` (the `root_head` line; `account` and `pack` come with Tasks 5 and 6).

- [ ] **Step 1: Failing tests.**

`headers_and_snapshots_are_stored_by_name` (transport, in the patch) and the `root_head` module test below. They fail to compile.

- [ ] **Step 2: Implement the root head file.**

Create `crates/keyorra-sync/src/root_head.rs`:

```rust
//! The main device's advertised head (spec §4.3, review W1): a small file the root rewrites
//! after every confirmed append, signed with its key, so every device can tell whether the
//! store withholds the root's newest entries (a removal, an approval).
//!
//! ```text
//! file = canonical({ "account_id": bytes16, "seq": uint, "hash": bytes32, "sig": bytes64 })
//! sig  = Ed25519(root_sk, "keyorra/sync/v1/root-head\0" ‖ account_id ‖ seq:u64be ‖ hash)
//! ```
//!
//! A reader only moves its advertised head forward, so an old file served later changes
//! nothing; a store that serves no file or an old one is no worse than before, and the setup
//! code (which carries the root's head when a device joins) and checkpoints cover the rest.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::cbor::{self, Value};
use crate::entry::Head;
use crate::error::{Error, Result};
use crate::labels::{self, tagged};
use crate::AccountId;

/// The file name in the store.
pub const ROOT_HEAD_FILE: &str = "root.head";
const MAX_LEN: usize = 512;

fn message(account_id: &AccountId, head: &Head) -> Vec<u8> {
    tagged(
        labels::ROOT_HEAD,
        &[account_id, &head.seq.to_be_bytes(), &head.hash],
    )
}

pub fn seal_root_head(account_id: &AccountId, head: &Head, root: &SigningKey) -> Vec<u8> {
    let sig = root.sign(&message(account_id, head)).to_bytes();
    cbor::encode(&Value::map(vec![
        ("account_id", Value::bytes(account_id)),
        ("seq", Value::Uint(head.seq)),
        ("hash", Value::bytes(head.hash)),
        ("sig", Value::bytes(sig)),
    ]))
}

pub fn open_root_head(account_id: &AccountId, root: &VerifyingKey, bytes: &[u8]) -> Result<Head> {
    let value = cbor::decode_limited(bytes, MAX_LEN)?;
    let f = value.fields(&["account_id", "seq", "hash", "sig"])?;
    let file_account: AccountId = f.get("account_id")?.as_array_of()?;
    if file_account != *account_id {
        return Err(Error::Refused("root head of another account".into()));
    }
    let head = Head {
        seq: f.get("seq")?.as_uint()?,
        hash: f.get("hash")?.as_array_of()?,
    };
    let sig: [u8; 64] = f.get("sig")?.as_array_of()?;
    root.verify_strict(&message(account_id, &head), &Signature::from_bytes(&sig))
        .map_err(|_| Error::BadSignature)?;
    Ok(head)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_root_head_file_opens_only_with_the_root_key_and_account() {
        let root = SigningKey::from_bytes(&[1; 32]);
        let head = Head {
            seq: 42,
            hash: [7; 32],
        };
        let bytes = seal_root_head(&[9; 16], &head, &root);
        assert_eq!(
            open_root_head(&[9; 16], &root.verifying_key(), &bytes).unwrap(),
            head
        );
        let other = SigningKey::from_bytes(&[2; 32]).verifying_key();
        assert!(open_root_head(&[9; 16], &other, &bytes).is_err());
        assert!(open_root_head(&[8; 16], &root.verifying_key(), &bytes).is_err());
        assert!(open_root_head(&[9; 16], &root.verifying_key(), b"junk").is_err());
    }
}
```

Add the label:

```diff
diff --git a/crates/keyorra-sync/src/labels.rs b/crates/keyorra-sync/src/labels.rs
index b30907d..58d9ad1 100644
--- a/crates/keyorra-sync/src/labels.rs
+++ b/crates/keyorra-sync/src/labels.rs
@@ -17,6 +17,7 @@ pub const CONFLICT_COPY: &[u8] = b"keyorra/sync/v1/conflict-copy";
 pub const ENDORSE: &[u8] = b"keyorra/sync/v1/endorse";
 pub const VAULT_ID: &[u8] = b"keyorra/sync/v1/vault-id";
 pub const KEY_FINGERPRINT: &[u8] = b"keyorra/sync/v1/key-fingerprint";
+pub const ROOT_HEAD: &[u8] = b"keyorra/sync/v1/root-head";
 
 pub const ALL: &[&[u8]] = &[
     KEK,
@@ -35,6 +36,7 @@ pub const ALL: &[&[u8]] = &[
     ENDORSE,
     VAULT_ID,
     KEY_FINGERPRINT,
+    ROOT_HEAD,
 ];
 
 /// `label ‖ 0x00 ‖ parts[0] ‖ parts[1] ‖ …`. Parts are fixed-length or the last field.
```

- [ ] **Step 3: Implement the store operations.**

Apply:

```diff
diff --git a/crates/keyorra-sync/src/transport.rs b/crates/keyorra-sync/src/transport.rs
index 9671180..e9e81be 100644
--- a/crates/keyorra-sync/src/transport.rs
+++ b/crates/keyorra-sync/src/transport.rs
@@ -7,6 +7,7 @@ use std::sync::{Arc, Mutex};
 
 use crate::error::Result;
 use crate::segment::SegmentHeader;
+use crate::snapshot::{snapshot_name, SnapshotHeader};
 use crate::DeviceId;
 
 #[derive(Clone, Debug, PartialEq, Eq)]
@@ -37,6 +38,26 @@ pub trait Transport {
     /// The highest `last_seq` stored for `stream` (from file names or server metadata, without
     /// reading segments): how a device notices that a stream went backwards (spec §4.5).
     fn head(&self, stream: &DeviceId) -> Result<Option<u64>>;
+    /// Account header files as (file name, content) (spec §4.7).
+    fn headers(&self) -> Result<Vec<(String, Fetched<Vec<u8>>)>>;
+    fn put_header(&self, name: &str, bytes: &[u8]) -> Result<()>;
+    fn delete_header(&self, name: &str) -> Result<()>;
+    /// Snapshots as (name = lowercase hex SHA-256 of the file, author) (spec §4.8).
+    fn snapshots(&self) -> Result<Vec<(String, DeviceId)>>;
+    fn get_snapshot(&self, name: &str) -> Result<Fetched<Vec<u8>>>;
+    /// Stores a snapshot under its name, which it returns.
+    fn put_snapshot(&self, bytes: &[u8]) -> Result<String>;
+    fn delete_snapshot(&self, name: &str) -> Result<()>;
+    /// The main device's advertised head file ([`crate::root_head`]).
+    fn root_head_file(&self) -> Result<Fetched<Vec<u8>>>;
+    fn put_root_head_file(&self, bytes: &[u8]) -> Result<()>;
+}
+
+#[derive(Clone, Debug, Default)]
+struct Files {
+    headers: BTreeMap<String, Vec<u8>>,
+    snapshots: BTreeMap<String, Vec<u8>>,
+    root_head: Option<Vec<u8>>,
 }
 
 /// One stream: segment bytes by first sequence number.
@@ -46,6 +67,7 @@ type Stream = BTreeMap<u64, Vec<u8>>;
 #[derive(Clone, Debug, Default)]
 pub struct MemoryTransport {
     streams: Arc<Mutex<BTreeMap<DeviceId, Stream>>>,
+    files: Arc<Mutex<Files>>,
 }
 
 impl MemoryTransport {
@@ -57,6 +79,7 @@ impl MemoryTransport {
     pub fn deep_copy(&self) -> MemoryTransport {
         MemoryTransport {
             streams: Arc::new(Mutex::new(self.streams.lock().unwrap().clone())),
+            files: Arc::new(Mutex::new(self.files.lock().unwrap().clone())),
         }
     }
 
@@ -96,6 +119,69 @@ impl Transport for MemoryTransport {
             .map(|h| h.last_seq))
     }
 
+    fn headers(&self) -> Result<Vec<(String, Fetched<Vec<u8>>)>> {
+        let files = self.files.lock().unwrap();
+        Ok(files
+            .headers
+            .iter()
+            .map(|(n, b)| (n.clone(), Fetched::Ready(b.clone())))
+            .collect())
+    }
+
+    fn put_header(&self, name: &str, bytes: &[u8]) -> Result<()> {
+        let mut files = self.files.lock().unwrap();
+        files.headers.insert(name.to_owned(), bytes.to_vec());
+        Ok(())
+    }
+
+    fn delete_header(&self, name: &str) -> Result<()> {
+        self.files.lock().unwrap().headers.remove(name);
+        Ok(())
+    }
+
+    fn snapshots(&self) -> Result<Vec<(String, DeviceId)>> {
+        let files = self.files.lock().unwrap();
+        Ok(files
+            .snapshots
+            .iter()
+            .filter_map(|(n, b)| Some((n.clone(), SnapshotHeader::parse(b).ok()?.author)))
+            .collect())
+    }
+
+    fn get_snapshot(&self, name: &str) -> Result<Fetched<Vec<u8>>> {
+        let files = self.files.lock().unwrap();
+        Ok(files
+            .snapshots
+            .get(name)
+            .map_or(Fetched::Missing, |b| Fetched::Ready(b.clone())))
+    }
+
+    fn put_snapshot(&self, bytes: &[u8]) -> Result<String> {
+        SnapshotHeader::parse(bytes)?;
+        let name = snapshot_name(bytes);
+        let mut files = self.files.lock().unwrap();
+        files.snapshots.insert(name.clone(), bytes.to_vec());
+        Ok(name)
+    }
+
+    fn delete_snapshot(&self, name: &str) -> Result<()> {
+        self.files.lock().unwrap().snapshots.remove(name);
+        Ok(())
+    }
+
+    fn root_head_file(&self) -> Result<Fetched<Vec<u8>>> {
+        let files = self.files.lock().unwrap();
+        Ok(files
+            .root_head
+            .clone()
+            .map_or(Fetched::Missing, Fetched::Ready))
+    }
+
+    fn put_root_head_file(&self, bytes: &[u8]) -> Result<()> {
+        self.files.lock().unwrap().root_head = Some(bytes.to_vec());
+        Ok(())
+    }
+
     fn append(&self, segment: &[u8]) -> Result<AppendOutcome> {
         let header = SegmentHeader::parse(segment)?;
         let mut streams = self.streams.lock().unwrap();
@@ -174,6 +260,32 @@ mod tests {
         assert!(t.append(b"junk").is_err());
     }
 
+    #[test]
+    fn headers_and_snapshots_are_stored_by_name() {
+        let t = MemoryTransport::new();
+        t.put_header("00000001-aa.hdr", b"h1").unwrap();
+        assert_eq!(
+            t.headers().unwrap(),
+            vec![("00000001-aa.hdr".to_owned(), Fetched::Ready(b"h1".to_vec()))]
+        );
+        t.delete_header("00000001-aa.hdr").unwrap();
+        assert!(t.headers().unwrap().is_empty());
+        let snap = crate::snapshot::seal_snapshot(
+            &Key::from_bytes([1; 32]),
+            &SigningKey::from_bytes(&[2; 32]),
+            [7; 16],
+            Value::Null,
+            &mut rand::rngs::OsRng,
+        )
+        .unwrap();
+        let name = t.put_snapshot(&snap).unwrap();
+        assert_eq!(t.snapshots().unwrap(), vec![(name.clone(), [7; 16])]);
+        assert_eq!(t.get_snapshot(&name).unwrap(), Fetched::Ready(snap));
+        t.delete_snapshot(&name).unwrap();
+        assert_eq!(t.get_snapshot(&name).unwrap(), Fetched::Missing);
+        assert!(t.put_snapshot(b"junk").is_err());
+    }
+
     #[test]
     fn a_deep_copy_does_not_share_storage() {
         let t = MemoryTransport::new();
```

```diff
diff --git a/crates/keyorra-sync/src/faults.rs b/crates/keyorra-sync/src/faults.rs
index 0dc0e7b..9c339e9 100644
--- a/crates/keyorra-sync/src/faults.rs
+++ b/crates/keyorra-sync/src/faults.rs
@@ -146,6 +146,42 @@ impl<T: Transport> Transport for Faulty<T> {
         self.inner.head(stream)
     }
 
+    fn headers(&self) -> Result<Vec<(String, Fetched<Vec<u8>>)>> {
+        self.inner.headers()
+    }
+
+    fn put_header(&self, name: &str, bytes: &[u8]) -> Result<()> {
+        self.inner.put_header(name, bytes)
+    }
+
+    fn delete_header(&self, name: &str) -> Result<()> {
+        self.inner.delete_header(name)
+    }
+
+    fn snapshots(&self) -> Result<Vec<(String, DeviceId)>> {
+        self.inner.snapshots()
+    }
+
+    fn get_snapshot(&self, name: &str) -> Result<Fetched<Vec<u8>>> {
+        self.inner.get_snapshot(name)
+    }
+
+    fn put_snapshot(&self, bytes: &[u8]) -> Result<String> {
+        self.inner.put_snapshot(bytes)
+    }
+
+    fn delete_snapshot(&self, name: &str) -> Result<()> {
+        self.inner.delete_snapshot(name)
+    }
+
+    fn root_head_file(&self) -> Result<Fetched<Vec<u8>>> {
+        self.inner.root_head_file()
+    }
+
+    fn put_root_head_file(&self, bytes: &[u8]) -> Result<()> {
+        self.inner.put_root_head_file(bytes)
+    }
+
     fn append(&self, segment: &[u8]) -> Result<AppendOutcome> {
         let f = self.faults();
         if self.roll(f.fail_before_append) {
@@ -199,6 +235,42 @@ impl<T: Transport> Transport for Rollback<T> {
             head
         })
     }
+
+    fn headers(&self) -> Result<Vec<(String, Fetched<Vec<u8>>)>> {
+        self.inner.headers()
+    }
+
+    fn put_header(&self, name: &str, bytes: &[u8]) -> Result<()> {
+        self.inner.put_header(name, bytes)
+    }
+
+    fn delete_header(&self, name: &str) -> Result<()> {
+        self.inner.delete_header(name)
+    }
+
+    fn snapshots(&self) -> Result<Vec<(String, DeviceId)>> {
+        self.inner.snapshots()
+    }
+
+    fn get_snapshot(&self, name: &str) -> Result<Fetched<Vec<u8>>> {
+        self.inner.get_snapshot(name)
+    }
+
+    fn put_snapshot(&self, bytes: &[u8]) -> Result<String> {
+        self.inner.put_snapshot(bytes)
+    }
+
+    fn delete_snapshot(&self, name: &str) -> Result<()> {
+        self.inner.delete_snapshot(name)
+    }
+
+    fn root_head_file(&self) -> Result<Fetched<Vec<u8>>> {
+        self.inner.root_head_file()
+    }
+
+    fn put_root_head_file(&self, bytes: &[u8]) -> Result<()> {
+        self.inner.put_root_head_file(bytes)
+    }
 }
 
 /// A store that shows one stream from another store: one side of a fork (two histories of
@@ -237,6 +309,41 @@ impl<T: Transport, U: Transport> Transport for Overlay<T, U> {
             self.base.head(stream)
         }
     }
+    fn headers(&self) -> Result<Vec<(String, Fetched<Vec<u8>>)>> {
+        self.base.headers()
+    }
+
+    fn put_header(&self, name: &str, bytes: &[u8]) -> Result<()> {
+        self.base.put_header(name, bytes)
+    }
+
+    fn delete_header(&self, name: &str) -> Result<()> {
+        self.base.delete_header(name)
+    }
+
+    fn snapshots(&self) -> Result<Vec<(String, DeviceId)>> {
+        self.base.snapshots()
+    }
+
+    fn get_snapshot(&self, name: &str) -> Result<Fetched<Vec<u8>>> {
+        self.base.get_snapshot(name)
+    }
+
+    fn put_snapshot(&self, bytes: &[u8]) -> Result<String> {
+        self.base.put_snapshot(bytes)
+    }
+
+    fn delete_snapshot(&self, name: &str) -> Result<()> {
+        self.base.delete_snapshot(name)
+    }
+
+    fn root_head_file(&self) -> Result<Fetched<Vec<u8>>> {
+        self.base.root_head_file()
+    }
+
+    fn put_root_head_file(&self, bytes: &[u8]) -> Result<()> {
+        self.base.put_root_head_file(bytes)
+    }
 }
 
 #[cfg(test)]
```

Test transports that implement `Transport` (in `engine/tests.rs`: `Upto`, `BrokenStream`; in `engine/attack_tests.rs`: `NoHeads`) pass the nine new operations through to their inner store (patches in Task 11 show them; add them now so the crate compiles).

- [ ] **Step 4: Run and commit.**

Commit: `Sync A1c-2: header, snapshot and root head files in the store`.

---

### Task 5: Joining from the header files

**Files:** Create `crates/keyorra-sync/src/account.rs`; add `pub mod account;` to `lib.rs`.

- [ ] **Step 1: Tests first.**

The module's tests (in the file below): only the highest epoch, in author order; junk, renamed and pending files ignored; no fallback to an older epoch; the real unlock refuses cheap KDF parameters from storage.

- [ ] **Step 2: Implement.**

`crates/keyorra-sync/src/account.rs`:

```rust
//! Joining an existing account from the header files in the store (spec §4.7).
//!
//! Only the highest epoch present is used. If several files share it (two devices changed
//! the master password concurrently), they are tried in ascending author order. There is no
//! fallback to a lower epoch, even if the password fails: an old password must not open the
//! account. A header that unlocks still counts only once the joined device finds the same
//! header as a signed log entry of its author ([`Engine::header_confirmed`]).
//!
//! [`Engine::header_confirmed`]: crate::engine::Engine::header_confirmed

use keyorra_core::crypto::Key;

use crate::error::{Error, Result};
use crate::header::{Header, HeaderFile};
use crate::secret_key::SecretKey;
use crate::transport::Fetched;

/// The header files a joining device may try, best first: well-formed, stored under their
/// proper name, highest epoch only, ascending author.
pub fn join_candidates(files: &[(String, Fetched<Vec<u8>>)]) -> Vec<HeaderFile> {
    let mut decoded: Vec<HeaderFile> = files
        .iter()
        .filter_map(|(name, f)| match f {
            Fetched::Ready(bytes) => HeaderFile::decode(bytes)
                .ok()
                .filter(|h| h.file_name() == *name),
            _ => None,
        })
        .collect();
    let Some(top) = decoded.iter().map(|h| h.header.epoch).max() else {
        return Vec::new();
    };
    decoded.retain(|h| h.header.epoch == top);
    decoded.sort_by_key(|h| h.author);
    decoded
}

/// Tries the candidates with `unlock`; the first that opens wins.
pub fn unlock_join_with(
    files: &[(String, Fetched<Vec<u8>>)],
    mut unlock: impl FnMut(&Header) -> Result<Key>,
) -> Result<(HeaderFile, Key)> {
    let candidates = join_candidates(files);
    if candidates.is_empty() {
        return Err(Error::NotFound("no account header in this location".into()));
    }
    for candidate in candidates {
        if let Ok(key) = unlock(&candidate.header) {
            return Ok((candidate, key));
        }
    }
    Err(Error::WrongPassword)
}

/// Joins with the master password and the Secret Key.
pub fn unlock_join(
    files: &[(String, Fetched<Vec<u8>>)],
    password: &str,
    secret_key: &SecretKey,
) -> Result<(HeaderFile, Key)> {
    unlock_join_with(files, |h| h.unlock(password, secret_key).map(|(k, _)| k))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::tests::sample_header;
    use ed25519_dalek::SigningKey;

    fn file(epoch: u32, author: u8, tag: u8) -> (String, Fetched<Vec<u8>>) {
        let mut header = sample_header();
        header.epoch = epoch;
        header.salt = [tag; 16];
        let f = HeaderFile::sign(header, [author; 16], &SigningKey::from_bytes(&[author; 32]));
        (f.file_name(), Fetched::Ready(f.encode()))
    }

    fn salt_of(h: &HeaderFile) -> u8 {
        h.header.salt[0]
    }

    #[test]
    fn only_the_highest_epoch_in_author_order() {
        let files = vec![
            file(1, 1, 10),
            file(2, 3, 23),
            file(2, 2, 22),
            file(1, 4, 14),
        ];
        let c = join_candidates(&files);
        assert_eq!(c.iter().map(salt_of).collect::<Vec<_>>(), vec![22, 23]);
    }

    #[test]
    fn junk_renamed_and_pending_files_are_ignored() {
        let (_, good) = file(1, 1, 10);
        let files = vec![
            ("00000009-ff.hdr".to_owned(), good),
            ("x".to_owned(), Fetched::Ready(b"junk".to_vec())),
            ("00000005-aa.hdr".to_owned(), Fetched::Pending),
            file(1, 2, 12),
        ];
        assert_eq!(
            join_candidates(&files)
                .iter()
                .map(salt_of)
                .collect::<Vec<_>>(),
            vec![12]
        );
    }

    #[test]
    fn no_fallback_to_an_older_epoch() {
        let files = vec![file(1, 1, 10), file(2, 1, 20)];
        // Only the epoch-1 header would open (the old password): joining must fail.
        let result = unlock_join_with(&files, |h| {
            if h.salt[0] == 10 {
                Ok(Key::from_bytes([1; 32]))
            } else {
                Err(Error::WrongPassword)
            }
        });
        assert!(matches!(result, Err(Error::WrongPassword)));
        let (chosen, _) = unlock_join_with(&files, |h| {
            if h.salt[0] == 20 {
                Ok(Key::from_bytes([2; 32]))
            } else {
                Err(Error::WrongPassword)
            }
        })
        .unwrap();
        assert_eq!(chosen.header.epoch, 2);
        assert!(matches!(
            unlock_join_with(&[], |_| unreachable!()),
            Err(Error::NotFound(_))
        ));
    }

    #[test]
    fn concurrent_epochs_try_the_next_author() {
        let files = vec![file(2, 1, 21), file(2, 2, 22)];
        let (chosen, _) = unlock_join_with(&files, |h| {
            if h.salt[0] == 22 {
                Ok(Key::from_bytes([2; 32]))
            } else {
                Err(Error::WrongPassword)
            }
        })
        .unwrap();
        assert_eq!(chosen.author, [2; 16]);
    }

    #[test]
    fn the_real_unlock_refuses_cheap_kdf_parameters_from_storage() {
        // `sample_header` uses test-only Argon2 parameters, below the floor for synced headers.
        let files = vec![file(1, 1, 10)];
        let sk = SecretKey::from_bytes([1; 16]);
        assert!(unlock_join(&files, "pw", &sk).is_err());
    }
}
```

The joining device then builds its engine with `Engine::join(…, header.root_device, VerifyingKey::from_bytes(&header.root_key)?, …)`: the main device's key comes from the header it unlocked (Task 9 tests it end to end). With a single publisher, equal epochs only appear if a store plants a forged file; trying authors in order and confirming against the root's entry (`header_confirmed`) handles it.

- [ ] **Step 3: Run and commit.**

Commit: `Sync A1c-2: join from the highest-epoch header file`.

---

### Task 6: The snapshot body

**Files:** Create `crates/keyorra-sync/src/pack.rs`; add `pub mod pack;` to `lib.rs`.

- [ ] **Step 1: Tests first.**

`round_trips_through_canonical_cbor`, `only_trust_and_header_entries_belong_in_a_snapshot` (in the file).

- [ ] **Step 2: Implement.**

`crates/keyorra-sync/src/pack.rs`:

```rust
//! The body of a snapshot (spec §4.8): everything a device needs to start from it.
//!
//! ```text
//! body = { "account_id": bytes16,
//!          "frontier": { device → [seq, hash] },   every stream's position the snapshot covers
//!          "floors":   { device → seq },           below these, segments are not needed by it
//!          "entries":  [[device, seq, entry], …],  the main device's trust and header entries,
//!                                                  everyone's header-seen entries, positioned
//!          "versions": [[device, seq, envelope], …] } every admitted record version
//! ```
//!
//! Versions keep their stream positions, so a revocation learned later still applies to them
//! (the receiver's admission decides), and all admitted versions are included (not only the
//! sibling sets) so such a refold has what it needs. Floors equal the frontier in phase A;
//! garbage collection (C1) uses them.

use std::collections::BTreeMap;

use crate::cbor::Value;
use crate::entry::{heads_from, heads_value, Entry, Head, Heads};
use crate::envelope::Envelope;
use crate::error::{malformed, Error, Result};
use crate::{AccountId, DeviceId};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotBody {
    pub account_id: AccountId,
    pub frontier: Heads,
    pub floors: BTreeMap<DeviceId, u64>,
    pub entries: Vec<(DeviceId, u64, Entry)>,
    pub versions: Vec<(DeviceId, u64, Envelope)>,
}

fn positioned(device: &DeviceId, seq: u64, value: Value) -> Value {
    Value::Array(vec![Value::bytes(device), Value::Uint(seq), value])
}

fn unpositioned(value: &Value) -> Result<(DeviceId, u64, &Value)> {
    let [device, seq, inner] = value.as_list()? else {
        return Err(malformed("positioned entry"));
    };
    Ok((device.as_array_of()?, seq.as_uint()?, inner))
}

impl SnapshotBody {
    pub fn to_value(&self) -> Value {
        Value::map(vec![
            ("account_id", Value::bytes(self.account_id)),
            ("frontier", heads_value(&self.frontier)),
            (
                "floors",
                Value::Map(
                    self.floors
                        .iter()
                        .map(|(d, s)| (Value::bytes(d), Value::Uint(*s)))
                        .collect(),
                ),
            ),
            (
                "entries",
                Value::Array(
                    self.entries
                        .iter()
                        .map(|(d, s, e)| positioned(d, *s, e.to_value()))
                        .collect(),
                ),
            ),
            (
                "versions",
                Value::Array(
                    self.versions
                        .iter()
                        .map(|(d, s, e)| positioned(d, *s, e.to_value()))
                        .collect(),
                ),
            ),
        ])
    }

    pub fn from_value(value: &Value) -> Result<SnapshotBody> {
        let f = value.fields(&["account_id", "frontier", "floors", "entries", "versions"])?;
        let mut floors = BTreeMap::new();
        for (d, s) in f.get("floors")?.as_map()? {
            floors.insert(d.as_array_of()?, s.as_uint()?);
        }
        let entries = f
            .get("entries")?
            .as_list()?
            .iter()
            .map(|v| {
                let (d, s, e) = unpositioned(v)?;
                Ok((d, s, Entry::from_value(e)?))
            })
            .collect::<Result<_>>()?;
        let versions = f
            .get("versions")?
            .as_list()?
            .iter()
            .map(|v| {
                let (d, s, e) = unpositioned(v)?;
                Ok((d, s, Envelope::from_value(e)?))
            })
            .collect::<Result<_>>()?;
        Ok(SnapshotBody {
            account_id: f.get("account_id")?.as_array_of()?,
            frontier: heads_from(f.get("frontier")?)?,
            floors,
            entries,
            versions,
        })
    }

    /// The position the snapshot covers for `device`.
    pub fn covers(&self, device: &DeviceId) -> Option<Head> {
        self.frontier.get(device).copied()
    }
}

/// A snapshot's entries must be trust or header entries.
pub fn check_entries(body: &SnapshotBody) -> Result<()> {
    for (_, _, e) in &body.entries {
        if matches!(
            e,
            Entry::Put(_) | Entry::Checkpoint(_) | Entry::Snapshot { .. }
        ) {
            return Err(Error::Malformed("snapshot entry of the wrong kind".into()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor;
    use crate::envelope::{RecordKind, Version};
    use uuid::Uuid;

    fn body() -> SnapshotBody {
        SnapshotBody {
            account_id: [0x10; 16],
            frontier: [(
                [1; 16],
                Head {
                    seq: 7,
                    hash: [3; 32],
                },
            )]
            .into_iter()
            .collect(),
            floors: [([1; 16], 7)].into_iter().collect(),
            entries: vec![(
                [1; 16],
                2,
                Entry::Revoke {
                    device: [2; 16],
                    last_valid_seq: 4,
                    last_valid_hash: [5; 32],
                },
            )],
            versions: vec![(
                [1; 16],
                5,
                Envelope {
                    kind: RecordKind::Item,
                    record_id: Uuid::from_bytes([0x60; 16]),
                    vault_id: Some(Uuid::from_bytes([0x61; 16])),
                    schema: 1,
                    version: Version {
                        vector: [([1; 16], 1)].into_iter().collect(),
                        hlc: 9,
                        author: [1; 16],
                    },
                    tombstone: true,
                    body: None,
                },
            )],
        }
    }

    #[test]
    fn round_trips_through_canonical_cbor() {
        let b = body();
        let bytes = cbor::encode(&b.to_value());
        assert_eq!(
            SnapshotBody::from_value(&cbor::decode(&bytes).unwrap()).unwrap(),
            b
        );
        assert_eq!(b.covers(&[1; 16]).unwrap().seq, 7);
        assert!(b.covers(&[2; 16]).is_none());
    }

    #[test]
    fn only_trust_and_header_entries_belong_in_a_snapshot() {
        let mut b = body();
        check_entries(&b).unwrap();
        b.entries
            .push(([1; 16], 3, Entry::Checkpoint(Heads::new())));
        assert!(check_entries(&b).is_err());
    }
}
```

- [ ] **Step 3: Run and commit.**

Commit: `Sync A1c-2: snapshot body`.

---

### Task 7: Engine plumbing and the outbox hook

**Files:** Modify `crates/keyorra-sync/src/engine.rs`, `crates/keyorra-sync/src/fold.rs`, `crates/keyorra-sync/src/testkit.rs`, `crates/keyorra-sync/src/lib.rs`; create `crates/keyorra-sync/src/engine/outbox.rs` and the start of `crates/keyorra-sync/src/engine/recovery_tests.rs`.

- [ ] **Step 1: Test first.**

Create `engine/recovery_tests.rs` with this head and the outbox test:

```rust
//! Plan A1c-2: retiring the id, account headers and the root's advertised head, snapshots,
//! restore, the outbox hook. All under root-only authority (spec §4.3).

use std::collections::BTreeSet;

use rand::SeedableRng;
use uuid::Uuid;

use super::tests::clone_of;
use super::*;
use crate::account::unlock_join_with;
use crate::faults::{Faults, Rollback};
use crate::testkit::{
    device_id, device_name, signer, test_header, unlock_test_header, Cluster, MemoryKeys,
    MemoryOutbox, ACCOUNT_ID, ACCOUNT_KEY, PASSWORD, START_MS,
};
use crate::transport::MemoryTransport;

const ITEM: Uuid = Uuid::from_bytes([0x60; 16]);

fn titles(view: &View) -> BTreeSet<String> {
    view.items
        .values()
        .filter_map(|v| v.payload.as_ref())
        .filter_map(|p| serde_json::from_slice::<serde_json::Value>(&p.item_json).ok())
        .filter_map(|v| v["title"].as_str().map(str::to_owned))
        .collect()
}

fn shared(n: usize) -> (Cluster, Uuid) {
    let mut c = Cluster::new(n, 11, Faults::NONE);
    let vault = c.devices[0].create_vault("Personal", START_MS).unwrap();
    c.devices[0]
        .save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "base", &[]),
            START_MS,
        )
        .unwrap();
    c.heal();
    (c, vault)
}

fn save(c: &mut Cluster, i: usize, vault: Uuid, id: Uuid, title: &str) {
    c.devices[i]
        .save_item(vault, id, &Cluster::item_json(id, title, &[]), c.clocks[i])
        .unwrap();
}

/// The main device approves device `i`'s new id, comparing the code shown on it.
fn approve_retired(c: &mut Cluster, i: usize) {
    let id = c.devices[i].device();
    let code = c.devices[i].key_fingerprint();
    c.sync(0).unwrap();
    c.devices[0].approve(id, &code, c.clocks[0]).unwrap();
}

// ---- outbox persistence ----

#[test]
fn a_sealed_segment_is_retried_byte_for_byte_after_a_restart() {
    let (mut c, vault) = shared(2);
    let saved = MemoryOutbox::default();
    c.devices[1].set_outbox_store(Box::new(saved.clone()));
    save(&mut c, 1, vault, ITEM, "survives");
    // The append lands but its outcome is lost, then the app quits.
    c.links[1].set_faults(Faults {
        fail_after_append: 100,
        ..Faults::NONE
    });
    c.sync(1).unwrap();
    let state = saved.0.lock().unwrap().clone().unwrap();
    assert!(
        state.unsent.is_some(),
        "sealed bytes were saved before the append"
    );
    // Restart: same fold and keys (A1d restores those), outbox from the store.
    let mut restarted = clone_of(&c.devices[1]);
    restarted.restore_outbox(state).unwrap();
    let store = MemoryTransport::clone(&c.store);
    restarted.sync(&store, c.clocks[1]).unwrap();
    let events = restarted.take_events();
    assert!(!events.contains(&Event::OwnStreamConflict), "{events:?}");
    assert!(restarted.is_idle());
    c.sync(0).unwrap();
    assert!(titles(&c.devices[0].view()).contains("survives"));
}
```

`approve_retired` and `titles` are used by later tasks. It fails to compile.

- [ ] **Step 2: Fold and testkit.**

Apply:

```diff
diff --git a/crates/keyorra-sync/src/fold.rs b/crates/keyorra-sync/src/fold.rs
index bbcfb33..3120c2e 100644
--- a/crates/keyorra-sync/src/fold.rs
+++ b/crates/keyorra-sync/src/fold.rs
@@ -421,6 +421,15 @@ impl Fold {
             .unwrap_or_default()
     }
 
+    /// Forgets what `stream` carried after `seq` (this device's own unconfirmed versions once
+    /// another copy of it took those positions; plan A1c-2). Call `refold` afterwards.
+    pub fn forget_after(&mut self, stream: &DeviceId, seq: u64) {
+        for versions in self.retained.values_mut() {
+            versions.retain(|(a, _)| a.stream != *stream || a.seq <= seq);
+        }
+        self.retained.retain(|_, v| !v.is_empty());
+    }
+
     pub fn set(&self, kind: RecordKind, id: Uuid) -> Option<&SiblingSet> {
         self.sets.get(&(kind, id))
     }
```

```diff
diff --git a/crates/keyorra-sync/src/testkit.rs b/crates/keyorra-sync/src/testkit.rs
index aace2e6..8dd09e8 100644
--- a/crates/keyorra-sync/src/testkit.rs
+++ b/crates/keyorra-sync/src/testkit.rs
@@ -7,10 +7,18 @@ use rand::rngs::StdRng;
 use rand::SeedableRng;
 use uuid::Uuid;
 
-use crate::engine::Engine;
+use std::collections::BTreeSet;
+use std::sync::{Arc, Mutex};
+
+use keyorra_core::crypto::KdfParams;
+
+use crate::engine::{DeviceKeys, Engine, OutboxState, OutboxStore};
 use crate::error::Result;
 use crate::faults::{Faults, Faulty};
 use crate::fold::View;
+use crate::header::{wrap_account_key, Header};
+use crate::keys::derive_sync_keys;
+use crate::secret_key::SecretKey;
 use crate::transport::MemoryTransport;
 use crate::DeviceId;
 
@@ -141,6 +149,30 @@ impl Cluster {
         }
     }
 
+    /// A further device joins (device 0 is the root) and device 0 approves it; returns its
+    /// index. It has nothing yet: its first sync starts from a snapshot if there is one.
+    pub fn add_device(&mut self, seed: u64) -> usize {
+        let i = self.devices.len();
+        self.devices.push(Engine::join(
+            device_id(i),
+            signer(i),
+            &device_name(i),
+            ACCOUNT_ID,
+            Key::from_bytes(ACCOUNT_KEY),
+            device_id(0),
+            signer(0).verifying_key(),
+            StdRng::seed_from_u64(seed),
+        ));
+        self.links
+            .push(Faulty::new(self.store.clone(), Faults::NONE, seed));
+        self.clocks.push(self.clocks[0]);
+        let key = self.devices[i].verifying_key();
+        self.devices[0]
+            .endorse(device_id(i), &key, &device_name(i), self.clocks[0])
+            .unwrap();
+        i
+    }
+
     /// A minimal item JSON, as the local store would write it.
     pub fn item_json(id: Uuid, title: &str, attachments: &[Uuid]) -> Vec<u8> {
         let atts: Vec<serde_json::Value> = attachments
@@ -155,3 +187,70 @@ impl Cluster {
         .unwrap()
     }
 }
+
+/// The password and Secret Key of the test account.
+pub const PASSWORD: &str = "correct horse battery staple";
+
+pub fn secret_key() -> SecretKey {
+    SecretKey::from_bytes([0x01; 16])
+}
+
+/// A valid account header of the test account (cheap, test-only KDF parameters).
+pub fn test_header(epoch: u32, password: &str) -> Header {
+    let kdf = KdfParams::INSECURE_FAST;
+    let salt = [epoch as u8; 16];
+    let keys = derive_sync_keys(password, &salt, kdf, &secret_key(), &ACCOUNT_ID).unwrap();
+    let mut header = Header {
+        account_id: ACCOUNT_ID,
+        epoch,
+        generation: 1,
+        root_device: device_id(0),
+        root_key: signer(0).verifying_key().to_bytes(),
+        kdf,
+        salt,
+        secret_key_id: "A3K7".into(),
+        wrapped_account_key: vec![],
+    };
+    header.wrapped_account_key = wrap_account_key(
+        &keys.kek,
+        &Key::from_bytes(ACCOUNT_KEY),
+        &header,
+        &mut rand::rngs::OsRng,
+    );
+    header
+}
+
+/// Opens a test header (without the floor on remote KDF parameters).
+pub fn unlock_test_header(header: &Header, password: &str) -> Result<Key> {
+    let keys = derive_sync_keys(
+        password,
+        &header.salt,
+        header.kdf,
+        &secret_key(),
+        &header.account_id,
+    )?;
+    header.unwrap_account_key(&keys.kek)
+}
+
+/// A key store in memory; shared between clones so a test can look inside.
+#[derive(Clone, Default)]
+pub struct MemoryKeys(pub Arc<Mutex<BTreeSet<DeviceId>>>);
+
+impl DeviceKeys for MemoryKeys {
+    fn holds(&self, device: &DeviceId) -> bool {
+        self.0.lock().unwrap().contains(device)
+    }
+    fn store(&mut self, device: DeviceId, _key: &SigningKey) {
+        self.0.lock().unwrap().insert(device);
+    }
+}
+
+/// The last saved outbox state, shared so a test can "restart" from it.
+#[derive(Clone, Default)]
+pub struct MemoryOutbox(pub Arc<Mutex<Option<OutboxState>>>);
+
+impl OutboxStore for MemoryOutbox {
+    fn save(&mut self, state: &OutboxState) {
+        *self.0.lock().unwrap() = Some(state.clone());
+    }
+}
```

- [ ] **Step 3: Engine.**

Apply the engine patch. It declares the four submodules (create `headers.rs`, `snapshots.rs`, `retire.rs` from Tasks 8–10 as they come; until then the hooks they provide can be stubbed, or apply Tasks 7–10 together and commit them one by one), turns `Unsent` into the public `SealedSegment`, adds the events `Retired`, `RootMustStartOver`, `HeaderAdopted`, `SnapshotWritten`, `Anchored`, `RollbackRepaired`, the fields for headers, snapshots, retiring and the root log (the root's applied trust entries, for snapshots), and the hooks in `sync`, `check_stored_head`, `receive_stream`, `check_own_claim`, `push` and `apply_root_entry`:

```diff
diff --git a/crates/keyorra-sync/src/engine.rs b/crates/keyorra-sync/src/engine.rs
index 08e8494..d1d3e91 100644
--- a/crates/keyorra-sync/src/engine.rs
+++ b/crates/keyorra-sync/src/engine.rs
@@ -20,8 +20,11 @@
 //! alarm that pauses nothing (their records count for nobody anyway). Checkpoint claims unmet
 //! for a day raise [`Event::Withheld`] (a warning).
 //!
-//! Plan A1c-2 adds account headers, snapshots, restore, retiring the device id and the outbox
-//! persistence hook; A3 the editor's base version; C1 key rotation and GC.
+//! Plan A1c-2 adds, in submodules: account headers as signed entries of the main device's
+//! stream and its advertised head (`headers`), snapshots for bootstrap, anchoring and restore
+//! (`snapshots`), retiring the device id when another copy of this device wrote or its key is
+//! gone (`retire`), and the outbox persistence hook for A1d (`outbox`). Still later: the
+//! editor's base version (A3), key rotation and GC (C1).
 
 use std::collections::{BTreeMap, BTreeSet, VecDeque};
 use std::fmt;
@@ -39,6 +42,7 @@ use crate::entry::{sign_endorsement, Entry, Head, Heads};
 use crate::envelope::{Envelope, RecordKind};
 use crate::error::{Error, Result};
 use crate::fold::{Accepted, Admission, Fold, RecordKey, View};
+use crate::header::{Header, HeaderFile};
 use crate::keys::segment_key;
 use crate::payload::{AttachmentPayload, Doc, ItemPayload, VaultPayload};
 use crate::present::{present_item, present_vault, ItemState};
@@ -49,6 +53,15 @@ use crate::transport::{AppendOutcome, Fetched, Transport};
 use crate::trust::Trust;
 use crate::{AccountId, DeviceId};
 
+mod headers;
+mod outbox;
+mod retire;
+mod snapshots;
+
+pub use outbox::{NoOutboxStore, OutboxState, OutboxStore};
+pub use retire::{DeviceKeys, KeepKeys, RetireReason};
+pub use snapshots::{SNAPSHOT_EVERY_ENTRIES, SNAPSHOT_EVERY_MS};
+
 /// Entries per segment; keeps segments well below the 4 MiB cap for ordinary records.
 const MAX_ENTRIES_PER_SEGMENT: usize = 256;
 /// Received entries waiting to be applied, per stream; beyond this a stream is not read further
@@ -218,15 +231,46 @@ pub enum Event {
     Alarm(Alarm),
     /// The main device removed this one: it reads but no longer writes. A3 offers to rejoin.
     Removed,
-    /// Someone else wrote at this device's next position (retiring the id: plan A1c-2).
+    /// Someone else wrote at this device's next position: another copy of this device.
     OwnStreamConflict,
+    /// This device continues under a new id (spec §4.2), pending the main device's approval.
+    Retired {
+        old: DeviceId,
+        new: DeviceId,
+        reason: RetireReason,
+    },
+    /// The main device itself would have to retire (another copy of it wrote, or its key is
+    /// gone): it stops writing; the user starts a new account from a device and carries the
+    /// data over (A1d/A3).
+    RootMustStartOver {
+        reason: RetireReason,
+    },
+    /// A newer account header (a master password change on the main device).
+    HeaderAdopted {
+        epoch: u32,
+    },
+    SnapshotWritten {
+        name: String,
+    },
+    /// Positions of `stream` up to `seq` were taken from a snapshot by `by` (restore).
+    Anchored {
+        stream: DeviceId,
+        seq: u64,
+        by: DeviceId,
+    },
+    /// A rollback of `stream` that a snapshot already covers: nothing is lost, no alarm.
+    RollbackRepaired {
+        stream: DeviceId,
+    },
 }
 
-struct Unsent {
-    bytes: Vec<u8>,
-    versions: usize,
-    last_seq: u64,
-    last_hash: [u8; 32],
+/// A sealed segment that the store has not confirmed yet: retried byte for byte.
+#[derive(Clone, Debug, PartialEq, Eq)]
+pub struct SealedSegment {
+    pub bytes: Vec<u8>,
+    pub versions: usize,
+    pub last_seq: u64,
+    pub last_hash: [u8; 32],
 }
 
 /// A received record that has not been applied yet.
@@ -298,7 +342,7 @@ pub struct Engine<R> {
     sent: Head,
     /// Chain hash of every own entry, confirmed or queued.
     own_hashes: BTreeMap<u64, [u8; 32]>,
-    unsent: Option<Unsent>,
+    unsent: Option<SealedSegment>,
     outbox: Vec<Value>,
     next_seq: u64,
     /// Heads in the last checkpoint this device wrote, and when.
@@ -313,8 +357,32 @@ pub struct Engine<R> {
     /// How many unapproved devices the user has already seen in an alarm.
     unapproved_seen: usize,
     removed_reported: bool,
-    /// Set after `OwnStreamConflict`: nothing more is written (plan A1c-2 retires the id).
+    /// Set when the main device would have to retire: nothing more is written.
     halted: bool,
+    keys: Box<dyn DeviceKeys>,
+    outbox_store: Box<dyn OutboxStore>,
+    /// Set when another copy of this device was noticed; handled at the end of the round.
+    retire_due: Option<RetireReason>,
+    /// The main device's `Header` entries `(seq, header)` and everyone's `HeaderSeen`.
+    header_entries: Vec<(u64, Header)>,
+    header_seen: Vec<(DeviceId, u64, u32)>,
+    adopted_epoch: u32,
+    /// Own header files waiting for their entry's segment to be confirmed.
+    header_files_out: Vec<(u64, HeaderFile)>,
+    /// Header files below this epoch were deleted.
+    deleted_below: u32,
+    snapshot_ref: Option<snapshots::SnapshotRef>,
+    own_snapshots: Vec<String>,
+    entries_since_snapshot: u64,
+    last_snapshot_ms: Option<u64>,
+    revoked_since_snapshot: bool,
+    /// Own position at which this device restored its own rolled-back stream.
+    restored_own: Option<u64>,
+    bootstrap_tried: bool,
+    /// The own head last written to the root head file (main device).
+    root_head_written: u64,
+    /// The main device's trust entries applied so far, in its stream's order (for snapshots).
+    root_log: Vec<(u64, Entry)>,
     /// Tests only: an attacker's copy of the engine, which writes whatever it is told,
     /// removed or not.
     #[cfg(test)]
@@ -411,6 +479,23 @@ impl<R: RngCore + CryptoRng> Engine<R> {
             root_head_advertised: None,
             removed_reported: false,
             halted: false,
+            keys: Box::new(KeepKeys),
+            outbox_store: Box::new(NoOutboxStore),
+            retire_due: None,
+            header_entries: Vec::new(),
+            header_seen: Vec::new(),
+            adopted_epoch: 0,
+            header_files_out: Vec::new(),
+            deleted_below: 0,
+            snapshot_ref: None,
+            own_snapshots: Vec::new(),
+            entries_since_snapshot: 0,
+            last_snapshot_ms: None,
+            revoked_since_snapshot: false,
+            restored_own: None,
+            bootstrap_tried: false,
+            root_head_written: 0,
+            root_log: Vec::new(),
             #[cfg(test)]
             forging: false,
             clock_reported: BTreeSet::new(),
@@ -1097,12 +1182,16 @@ impl<R: RngCore + CryptoRng> Engine<R> {
             let result = self.trust.apply_root(seq, &entry, |d| {
                 seen.as_ref().and_then(|h| h.get(d)).map_or(0, |h| h.seq)
             });
+            if result.is_ok() {
+                self.root_log.push((seq, entry.clone()));
+            }
             match result {
                 Ok(c) => changed = c,
                 Err(e) if !self.forging() => return Err(Error::Refused(e.to_string())),
                 Err(_) => {}
             }
         }
+        self.note_header_entry(self.device, seq, &entry);
         self.queue(entry);
         if changed {
             self.trust_changed();
@@ -1136,6 +1225,7 @@ impl<R: RngCore + CryptoRng> Engine<R> {
             .insert(self.next_seq, chain_next(&prev, &value));
         self.outbox.push(value);
         self.next_seq += 1;
+        self.entries_since_snapshot += 1;
         debug_assert_eq!(
             self.next_seq,
             self.unsent.as_ref().map_or(self.sent.seq, |u| u.last_seq)
@@ -1143,6 +1233,7 @@ impl<R: RngCore + CryptoRng> Engine<R> {
                 + 1,
             "own sequence numbers out of step"
         );
+        self.save_outbox();
     }
 
     // ---- sync ----
@@ -1153,14 +1244,36 @@ impl<R: RngCore + CryptoRng> Engine<R> {
     /// returned afterwards. Alarms do not make a round fail: a rollback or fork pauses only
     /// its stream (the own stream: nothing is pushed), see [`Engine::alarms`].
     pub fn sync(&mut self, transport: &impl Transport, wall_ms: u64) -> Result<()> {
+        if self.sent.seq > 0 && !self.keys.holds(&self.device) {
+            self.retire(RetireReason::KeyMissing, wall_ms)?;
+        }
+        if !self.bootstrap_tried {
+            self.bootstrap_tried = true;
+            self.bootstrap(transport, wall_ms)?;
+        }
+        self.read_root_head_file(transport);
         let pulled = self.pull(transport, wall_ms);
+        if let Some(reason) = self.retire_due.take() {
+            self.retire(reason, wall_ms)?;
+        }
+        self.adopt_header(wall_ms);
+        self.delete_old_headers(transport);
         if self.can_write() {
             self.materialize(wall_ms)?;
             self.checkpoint_if_stale(wall_ms);
         }
         if !self.paused(&self.device) {
             self.push(transport);
+            if let Some(reason) = self.retire_due.take() {
+                self.retire(reason, wall_ms)?;
+                self.push(transport);
+            }
+            if self.can_write() && self.is_idle() && self.snapshot_due(wall_ms) {
+                self.write_snapshot(transport, wall_ms)?;
+                self.push(transport);
+            }
         }
+        self.write_root_head_file(transport);
         pulled
     }
 
@@ -1191,7 +1304,7 @@ impl<R: RngCore + CryptoRng> Engine<R> {
                 if self.paused(stream) {
                     continue;
                 }
-                match self.receive_stream(transport, stream) {
+                match self.receive_stream(transport, stream, wall_ms) {
                     Ok(p) => progress |= p,
                     Err(e) => self.events.push(Event::ListingFailed {
                         from: *stream,
@@ -1220,11 +1333,17 @@ impl<R: RngCore + CryptoRng> Engine<R> {
             Ok(stored) => {
                 let stored = stored.unwrap_or(0);
                 if stored < received && !self.acknowledged_rollbacks.contains(&(*stream, stored)) {
-                    self.raise(Alarm::Rollback {
-                        stream: *stream,
-                        received,
-                        stored,
-                    });
+                    if self.snapshot_covers(transport, stream, received) {
+                        self.acknowledged_rollbacks.insert((*stream, stored));
+                        self.events
+                            .push(Event::RollbackRepaired { stream: *stream });
+                    } else {
+                        self.raise(Alarm::Rollback {
+                            stream: *stream,
+                            received,
+                            stored,
+                        });
+                    }
                 }
             }
             Err(e) => self.events.push(Event::HeadUnknown {
@@ -1264,7 +1383,12 @@ impl<R: RngCore + CryptoRng> Engine<R> {
 
     /// Receives every segment of `stream` that continues its chain, up to its cut. Returns
     /// whether any was received.
-    fn receive_stream(&mut self, transport: &impl Transport, stream: &DeviceId) -> Result<bool> {
+    fn receive_stream(
+        &mut self,
+        transport: &impl Transport,
+        stream: &DeviceId,
+        wall_ms: u64,
+    ) -> Result<bool> {
         let mut head = self.heads.get(stream).copied().unwrap_or(Head {
             seq: 0,
             hash: chain_genesis(&self.account_id, stream),
@@ -1331,6 +1455,13 @@ impl<R: RngCore + CryptoRng> Engine<R> {
                             first_seq: want,
                         },
                     );
+                } else if candidates.iter().any(|(s, _)| *s > want)
+                    && self.anchor_stream(transport, stream, wall_ms)
+                {
+                    // A gap the store cannot fill (a restored rollback): a snapshot covers it.
+                    head = self.heads.get(stream).copied().unwrap_or(head);
+                    received = true;
+                    continue;
                 }
                 return Ok(received);
             };
@@ -1390,6 +1521,8 @@ impl<R: RngCore + CryptoRng> Engine<R> {
                 }
             }
             let count = entries.len();
+            self.entries_since_snapshot += count as u64;
+            self.confirm_snapshot_ref(stream, segment.header.first_seq, &entries);
             for (seq, entry) in entries {
                 match entry {
                     Entry::Checkpoint(heads) => {
@@ -1419,6 +1552,9 @@ impl<R: RngCore + CryptoRng> Engine<R> {
                     }
                     // The first entry of an approved self-joined stream: nothing to do.
                     Entry::SelfJoin { .. } if seq == 1 && !is_root => {}
+                    Entry::Snapshot { .. } => {}
+                    Entry::HeaderSeen { .. } => self.note_header_entry(*stream, seq, &entry),
+                    Entry::Header(_) if is_root => self.note_header_entry(*stream, seq, &entry),
                     entry if is_root => self.apply_root_entry(seq, &entry),
                     _ => self.events.push(Event::TrustEntryIgnored {
                         from: *stream,
@@ -1500,7 +1636,7 @@ impl<R: RngCore + CryptoRng> Engine<R> {
     fn check_own_claim(&mut self, claimed: &Head, by: DeviceId) {
         let known = self.own_hashes.get(&claimed.seq);
         if known.is_some_and(|h| *h != claimed.hash) {
-            self.claim_mismatch(self.device, claimed.seq, by);
+            self.own_claim_mismatch(claimed.seq, by);
             return;
         }
         if claimed.seq <= self.sent.seq {
@@ -1514,7 +1650,18 @@ impl<R: RngCore + CryptoRng> Engine<R> {
                 self.unsent = None;
             }
             _ if known.is_some() => {}
-            _ => self.claim_mismatch(self.device, claimed.seq, by),
+            _ => self.own_claim_mismatch(claimed.seq, by),
+        }
+    }
+
+    /// Another history of this device's own stream: if the main device says so, another
+    /// copy of this device wrote there and this one retires; anyone else's word is a dispute.
+    fn own_claim_mismatch(&mut self, seq: u64, by: DeviceId) {
+        if by == self.trust.root() {
+            self.events.push(Event::OwnStreamConflict);
+            self.retire_due = Some(RetireReason::OtherCopyWrote);
+        } else {
+            self.claim_mismatch(self.device, seq, by);
         }
     }
 
@@ -1637,8 +1784,17 @@ impl<R: RngCore + CryptoRng> Engine<R> {
                 .filter(|h| hashes.get(d).and_then(|x| x.get(&h.seq)) == Some(&h.hash))
                 .map_or(0, |h| h.seq)
         };
-        match self.trust.apply_root(seq, entry, seen) {
-            Ok(true) => self.trust_changed(),
+        let result = self.trust.apply_root(seq, entry, seen);
+        if result.is_ok() && !self.root_log.iter().any(|(s, _)| *s == seq) {
+            self.root_log.push((seq, entry.clone()));
+        }
+        match result {
+            Ok(true) => {
+                if matches!(entry, Entry::Revoke { .. }) {
+                    self.revoked_since_snapshot = true;
+                }
+                self.trust_changed()
+            }
             Ok(false) => {}
             Err(e) => self.events.push(Event::TrustEntryIgnored {
                 from: root,
@@ -1846,14 +2002,18 @@ impl<R: RngCore + CryptoRng> Engine<R> {
     }
 
     fn push(&mut self, transport: &impl Transport) {
-        if self.halted || (self.unsent.is_none() && self.outbox.is_empty()) {
+        if self.halted || self.retire_due.is_some() {
+            return;
+        }
+        self.upload_header_files(transport);
+        if self.unsent.is_none() && self.outbox.is_empty() {
             return;
         }
         // The store's head of this device's own stream must be where this device left it.
         match transport.head(&self.device) {
             Ok(stored) => {
                 let stored = stored.unwrap_or(0);
-                if stored < self.sent.seq {
+                if stored < self.sent.seq && self.restored_own != Some(self.sent.seq) {
                     self.raise(Alarm::Rollback {
                         stream: self.device,
                         received: self.sent.seq,
@@ -1862,8 +2022,8 @@ impl<R: RngCore + CryptoRng> Engine<R> {
                     return;
                 }
                 if stored > self.sent.seq && self.unsent.is_none() {
-                    self.halted = true;
                     self.events.push(Event::OwnStreamConflict);
+                    self.retire_due = Some(RetireReason::OtherCopyWrote);
                     return;
                 }
             }
@@ -1891,12 +2051,14 @@ impl<R: RngCore + CryptoRng> Engine<R> {
                 let bytes =
                     seal_segment(&self.segment_key, &self.signer, &at, entries, &mut self.rng)
                         .expect("own entries fit a segment");
-                self.unsent = Some(Unsent {
+                self.unsent = Some(SealedSegment {
                     bytes,
                     versions,
                     last_seq,
                     last_hash,
                 });
+                // Persisted before the append, so a restart retries these exact bytes.
+                self.save_outbox();
             }
             let unsent = self.unsent.as_ref().expect("set above");
             match transport.append(&unsent.bytes) {
@@ -1909,12 +2071,14 @@ impl<R: RngCore + CryptoRng> Engine<R> {
                         versions: unsent.versions,
                     });
                     self.unsent = None;
+                    self.save_outbox();
+                    self.upload_header_files(transport);
                 }
                 Ok(AppendOutcome::Conflict) => {
                     // Someone else wrote at this device's next position: another copy of this
-                    // device (plan A1c-2 retires the id). Nothing more is written meanwhile.
-                    self.halted = true;
+                    // device (a clone, a restored backup). This device continues under a new id.
                     self.events.push(Event::OwnStreamConflict);
+                    self.retire_due = Some(RetireReason::OtherCopyWrote);
                     return;
                 }
                 Err(e) => {
@@ -1931,4 +2095,6 @@ mod adversary_tests;
 #[cfg(test)]
 mod attack_tests;
 #[cfg(test)]
+mod recovery_tests;
+#[cfg(test)]
 mod tests;
```

- [ ] **Step 4: Outbox.**

`crates/keyorra-sync/src/engine/outbox.rs`:

```rust
//! The outbox persistence hook (for plan A1d): everything needed to continue the own stream
//! after a restart. The engine saves it after every queued entry, after sealing a segment
//! (before the append, so a restart retries the same bytes instead of resealing with a new
//! nonce, which the store would answer with `Conflict`) and after every confirmation.

use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboxState {
    pub device: DeviceId,
    pub next_seq: u64,
    pub sent: Head,
    /// Chain hash of every own entry, confirmed or queued.
    pub own_hashes: BTreeMap<u64, [u8; 32]>,
    pub unsent: Option<SealedSegment>,
    /// Queued entries, canonical CBOR.
    pub outbox: Vec<Vec<u8>>,
}

/// Where A1d keeps [`OutboxState`] (in the same transaction as the local change).
pub trait OutboxStore: Send {
    fn save(&mut self, state: &OutboxState);
}

/// Nothing is persisted (tests, and until A1d).
pub struct NoOutboxStore;

impl OutboxStore for NoOutboxStore {
    fn save(&mut self, _: &OutboxState) {}
}

impl<R: RngCore + CryptoRng> Engine<R> {
    pub fn set_outbox_store(&mut self, store: Box<dyn OutboxStore>) {
        self.outbox_store = store;
    }

    pub fn outbox_state(&self) -> OutboxState {
        OutboxState {
            device: self.device,
            next_seq: self.next_seq,
            sent: self.sent,
            own_hashes: self.own_hashes.clone(),
            unsent: self.unsent.clone(),
            outbox: self.outbox.iter().map(crate::cbor::encode).collect(),
        }
    }

    /// Continues from a persisted state after a restart (A1d also restores the fold).
    pub fn restore_outbox(&mut self, state: OutboxState) -> Result<()> {
        if state.device != self.device {
            return Err(Error::Refused("outbox of another device".into()));
        }
        let outbox = state
            .outbox
            .iter()
            .map(|b| crate::cbor::decode(b))
            .collect::<Result<Vec<Value>>>()?;
        self.next_seq = state.next_seq;
        self.sent = state.sent;
        self.own_hashes = state.own_hashes;
        self.unsent = state.unsent;
        self.outbox = outbox;
        Ok(())
    }

    pub(super) fn save_outbox(&mut self) {
        let state = self.outbox_state();
        self.outbox_store.save(&state);
    }
}
```

- [ ] **Step 5: Run and commit.**

Commit: `Sync A1c-2: engine plumbing and the outbox persistence hook`.

---

### Task 8: Account headers and the main device's head in the engine

**Files:** Create `crates/keyorra-sync/src/engine/headers.rs`; extend `recovery_tests.rs`.

- [ ] **Step 1: Failing tests.**

Add to `recovery_tests.rs` (sections "account headers" and "the main device's advertised head"):

```rust
#[test]
fn a_header_file_follows_its_confirmed_entry_and_only_the_root_publishes() {
    let (mut c, _) = shared(2);
    c.devices[0]
        .publish_header(test_header(1, PASSWORD), c.clocks[0])
        .unwrap();
    assert!(
        c.store.headers().unwrap().is_empty(),
        "not before its segment is confirmed"
    );
    c.sync(0).unwrap();
    let files = c.store.headers().unwrap();
    assert_eq!(files.len(), 1);
    c.sync(1).unwrap();
    assert_eq!(c.devices[1].header_epoch(), 1);
    let Fetched::Ready(bytes) = &files[0].1 else {
        panic!()
    };
    let file = HeaderFile::decode(bytes).unwrap();
    assert_eq!(c.devices[1].header_confirmed(&file), Some(true));
    // The same header signed by another device is not confirmed.
    let forged = HeaderFile::sign(file.header.clone(), device_id(1), &signer(1));
    assert_eq!(c.devices[1].header_confirmed(&forged), Some(false));
    // Wrong root, root key or epoch are refused; another device cannot publish at all.
    let mut wrong = test_header(2, PASSWORD);
    wrong.root_device = device_id(1);
    assert!(c.devices[0].publish_header(wrong, c.clocks[0]).is_err());
    let mut wrong = test_header(2, PASSWORD);
    wrong.root_key = signer(1).verifying_key().to_bytes();
    assert!(c.devices[0].publish_header(wrong, c.clocks[0]).is_err());
    assert!(c.devices[0]
        .publish_header(test_header(3, PASSWORD), c.clocks[0])
        .is_err());
    assert!(c.devices[1]
        .publish_header(test_header(2, PASSWORD), c.clocks[1])
        .is_err());
}
#[test]
fn a_header_entry_from_another_device_is_ignored() {
    let (mut c, _) = shared(2);
    c.devices[0]
        .publish_header(test_header(1, PASSWORD), c.clocks[0])
        .unwrap();
    c.heal();
    // A stolen device writes a header with a password of its own.
    c.devices[1].queue(Entry::Header(test_header(2, "thief")));
    c.devices[1].push(&c.store);
    c.sync(0).unwrap();
    assert_eq!(c.devices[0].header_epoch(), 1);
}
#[test]
fn a_password_change_is_adopted_and_old_header_files_go_away() {
    let (mut c, _) = shared(3);
    c.devices[0]
        .publish_header(test_header(1, PASSWORD), c.clocks[0])
        .unwrap();
    c.heal();
    c.devices[0]
        .publish_header(test_header(2, "new password"), c.clocks[0])
        .unwrap();
    c.heal();
    for i in [1, 2] {
        assert!(c.devices[i]
            .take_events()
            .iter()
            .any(|e| matches!(e, Event::HeaderAdopted { epoch: 2 })));
    }
    c.heal();
    let epochs: Vec<u32> = c
        .store
        .headers()
        .unwrap()
        .into_iter()
        .filter_map(|(_, f)| match f {
            Fetched::Ready(b) => HeaderFile::decode(&b).ok().map(|h| h.header.epoch),
            _ => None,
        })
        .collect();
    assert_eq!(epochs, vec![2], "every approved device adopted epoch 2");
}
#[test]
fn the_root_head_file_reveals_a_withheld_root_tail() {
    let (mut c, _) = shared(2);
    let before = c.devices[0].sent.seq;
    c.devices[0].revoke(device_id(1), c.clocks[0]).unwrap();
    c.sync(0).unwrap();
    assert!(matches!(
        c.store.root_head_file().unwrap(),
        Fetched::Ready(_)
    ));
    // A store that hides the root's newest segment but serves the head file.
    let hiding = Rollback {
        inner: c.store.clone(),
        stream: device_id(0),
        keep_through: before,
    };
    let mut fresh = Engine::join(
        device_id(6),
        signer(6),
        &device_name(6),
        ACCOUNT_ID,
        Key::from_bytes(ACCOUNT_KEY),
        device_id(0),
        signer(0).verifying_key(),
        rand::rngs::StdRng::seed_from_u64(6),
    );
    fresh.sync(&hiding, c.clocks[0]).unwrap();
    assert!(!fresh.root_confirmed());
    assert!(fresh
        .alarms()
        .iter()
        .any(|a| matches!(a, Alarm::RootBehind { .. })));
    fresh.sync(&c.store, c.clocks[0]).unwrap();
    assert!(fresh.root_confirmed());
    assert!(fresh.trust().device(&device_id(1)).unwrap().cut.is_some());
}
```

- [ ] **Step 2: Implement.**

`crates/keyorra-sync/src/engine/headers.rs`:

```rust
//! Account headers as signed entries of the main device's stream (spec §4.7), and the main
//! device's advertised head.
//!
//! Only the main device publishes headers (a master password change happens there): a header
//! counts only as a `Header` entry of the root's stream, and must name the root and its key.
//! The header file in the store is what a joining device reads before it has any key; it is
//! uploaded once the entry's segment is confirmed. The header in force is the highest epoch.
//! Once every approved device has adopted an epoch (`HeaderSeen`, or the root's own `Header`),
//! older header files are deleted, because an old header still opens the account with the old
//! password.

use crate::root_head::{open_root_head, seal_root_head, ROOT_HEAD_FILE};

use super::*;

impl<R: RngCore + CryptoRng> Engine<R> {
    /// The account header in force.
    pub fn current_header(&self) -> Option<&Header> {
        self.header_entries
            .iter()
            .map(|(_, h)| h)
            .max_by_key(|h| h.epoch)
    }

    pub fn header_epoch(&self) -> u32 {
        self.current_header().map_or(0, |h| h.epoch)
    }

    /// Publishes the next account header (creating the account, changing the master
    /// password). Main device only; its epoch must be one more than the current one.
    pub fn publish_header(&mut self, header: Header, wall_ms: u64) -> Result<()> {
        if !self.is_root() {
            return Err(Error::Refused(
                "only the main device publishes account headers".into(),
            ));
        }
        self.require_writable()?;
        self.check_header(&header).map_err(Error::Refused)?;
        let next = self.header_epoch() + 1;
        if header.epoch != next {
            return Err(Error::Refused(format!("the next header epoch is {next}")));
        }
        self.write_entry(Entry::Header(header.clone()), wall_ms)?;
        let seq = self.next_seq - 1;
        self.adopted_epoch = header.epoch;
        let file = HeaderFile::sign(header, self.device, &self.signer);
        self.header_files_out.push((seq, file));
        Ok(())
    }

    pub(super) fn check_header(&self, header: &Header) -> std::result::Result<(), String> {
        if header.account_id != self.account_id {
            return Err("header of another account".into());
        }
        if header.root_device != self.trust.root() {
            return Err("header names another main device".into());
        }
        if header.root_key != self.trust.root_key().to_bytes() {
            return Err("header names another key of the main device".into());
        }
        if header.generation != 1 {
            return Err("key generations other than 1 need key rotation (C1)".into());
        }
        if header.epoch == 0 {
            return Err("header epoch 0".into());
        }
        Ok(())
    }

    /// Keeps track of the root's `Header` entries and everyone's `HeaderSeen` entries,
    /// written or received.
    pub(super) fn note_header_entry(&mut self, stream: DeviceId, seq: u64, entry: &Entry) {
        match entry {
            Entry::Header(h) if stream == self.trust.root() => {
                if let Err(reason) = self.check_header(h) {
                    self.events.push(Event::TrustEntryIgnored {
                        from: stream,
                        seq,
                        reason,
                    });
                    return;
                }
                if !self.header_entries.iter().any(|(s, _)| *s == seq) {
                    self.header_entries.push((seq, h.clone()));
                }
            }
            Entry::HeaderSeen { epoch }
                if !self
                    .header_seen
                    .iter()
                    .any(|(d, s, _)| *d == stream && *s == seq) =>
            {
                self.header_seen.push((stream, seq, *epoch));
            }
            _ => {}
        }
    }

    /// Adopts a newer header epoch and tells the main device.
    pub(super) fn adopt_header(&mut self, wall_ms: u64) {
        let epoch = self.header_epoch();
        if epoch <= self.adopted_epoch || !self.can_write() {
            return;
        }
        self.adopted_epoch = epoch;
        if !self.is_root() {
            self.events.push(Event::HeaderAdopted { epoch });
            let _ = self.write_entry(Entry::HeaderSeen { epoch }, wall_ms);
        }
    }

    /// The highest epoch every approved device (not removed) has adopted.
    fn epoch_adopted_by_all(&self) -> u32 {
        let adopted = |device: &DeviceId| {
            if *device == self.trust.root() {
                return self.header_epoch();
            }
            self.header_seen
                .iter()
                .filter(|(d, s, _)| d == device && self.trust.admits(d, *s))
                .map(|(_, _, e)| *e)
                .max()
                .unwrap_or(0)
        };
        self.trust
            .devices()
            .iter()
            .filter(|(_, info)| info.cut.is_none())
            .map(|(d, _)| adopted(d))
            .min()
            .unwrap_or(0)
    }

    /// Deletes header files of epochs that every approved device has moved past.
    pub(super) fn delete_old_headers(&mut self, transport: &impl Transport) {
        let all = self.epoch_adopted_by_all();
        if all <= 1 || all <= self.deleted_below {
            return;
        }
        let Ok(files) = transport.headers() else {
            return;
        };
        for (name, file) in files {
            if let Fetched::Ready(bytes) = file {
                if HeaderFile::decode(&bytes).is_ok_and(|h| h.header.epoch < all) {
                    let _ = transport.delete_header(&name);
                }
            }
        }
        self.deleted_below = all;
    }

    /// Uploads own header files whose entries the store has confirmed.
    pub(super) fn upload_header_files(&mut self, transport: &impl Transport) {
        let confirmed = self.sent.seq;
        let mut waiting = Vec::new();
        for (seq, file) in std::mem::take(&mut self.header_files_out) {
            let uploaded = seq <= confirmed
                && transport
                    .put_header(&file.file_name(), &file.encode())
                    .is_ok();
            if !uploaded {
                waiting.push((seq, file));
            }
        }
        self.header_files_out = waiting;
    }

    /// Whether the header file this device joined with is backed by the root's log entry:
    /// `None` while that is not known yet, `Some(false)` for a forged or mismatching file (an
    /// alarm for A3).
    pub fn header_confirmed(&self, file: &HeaderFile) -> Option<bool> {
        if file.author != self.trust.root() || file.verify(&self.trust.root_key()).is_err() {
            return Some(false);
        }
        let entries: Vec<&Header> = self.header_entries.iter().map(|(_, h)| h).collect();
        if entries.iter().any(|h| **h == file.header) {
            Some(true)
        } else if entries.iter().any(|h| h.epoch == file.header.epoch) {
            Some(false)
        } else {
            None
        }
    }

    /// The main device writes its confirmed head for everyone to compare with.
    pub(super) fn write_root_head_file(&mut self, transport: &impl Transport) {
        if !self.is_root() || self.sent.seq == 0 || self.root_head_written == self.sent.seq {
            return;
        }
        let bytes = seal_root_head(&self.account_id, &self.sent, &self.signer);
        if transport.put_root_head_file(&bytes).is_ok() {
            self.root_head_written = self.sent.seq;
        }
    }

    /// Other devices read it (only forward; a bad file is ignored).
    pub(super) fn read_root_head_file(&mut self, transport: &impl Transport) {
        if self.is_root() {
            return;
        }
        let Ok(Fetched::Ready(bytes)) = transport.root_head_file() else {
            return;
        };
        if let Ok(head) = open_root_head(&self.account_id, &self.trust.root_key(), &bytes) {
            self.set_root_head(head);
        }
    }

    /// The name of the root head file, for transports that list files.
    pub fn root_head_file_name() -> &'static str {
        ROOT_HEAD_FILE
    }
}
```

- [ ] **Step 3: Existing W1 test.**

`review_w1_a_withheld_root_tail_is_noticed_against_the_advertised_head` (engine/tests.rs) no longer needs `set_root_head`: the head file advertises it. See its part of the patch in Task 11.

- [ ] **Step 4: Run and commit.**

Commit: `Sync A1c-2: root-published account headers and the root head file`.

---

### Task 9: Snapshots: bootstrap from the main device, anchoring, restore

**Files:** Create `crates/keyorra-sync/src/engine/snapshots.rs`; extend `recovery_tests.rs`.

- [ ] **Step 1: Failing tests.**

Add (sections "account headers" end and "rollback and restore"):

```rust
#[test]
fn a_new_device_joins_from_the_header_and_starts_from_the_roots_snapshot() {
    let (mut c, vault) = shared(2);
    c.devices[0]
        .publish_header(test_header(1, PASSWORD), c.clocks[0])
        .unwrap();
    save(&mut c, 1, vault, Uuid::from_bytes([0x61; 16]), "second");
    c.heal();
    c.devices[0].write_snapshot(&c.store, c.clocks[0]).unwrap();
    c.heal();
    // The newcomer has only the store, the password and the Secret Key; the header gives the
    // main device and its key.
    let files = c.store.headers().unwrap();
    let (file, account_key) =
        unlock_join_with(&files, |h| unlock_test_header(h, PASSWORD)).unwrap();
    assert_eq!(account_key.as_bytes(), &ACCOUNT_KEY);
    assert!(unlock_join_with(&files, |h| unlock_test_header(h, "wrong")).is_err());
    let header = &file.header;
    let mut fresh = Engine::join(
        device_id(5),
        signer(5),
        &device_name(5),
        ACCOUNT_ID,
        account_key,
        header.root_device,
        ed25519_dalek::VerifyingKey::from_bytes(&header.root_key).unwrap(),
        rand::rngs::StdRng::seed_from_u64(5),
    );
    fresh.sync(&c.store, c.clocks[0]).unwrap();
    assert!(fresh.alarms().is_empty(), "{:?}", fresh.alarms());
    assert_eq!(fresh.header_confirmed(&file), Some(true));
    assert!(titles(&fresh.view()).contains("second"));
    assert_eq!(fresh.view(), c.devices[0].view());
}
#[test]
fn only_the_main_devices_snapshot_bootstraps_a_newcomer() {
    let (mut c, vault) = shared(2);
    save(&mut c, 1, vault, Uuid::from_bytes([0x61; 16]), "second");
    c.heal();
    // Only device 1 (not the main device) wrote a snapshot.
    c.devices[1].write_snapshot(&c.store, c.clocks[1]).unwrap();
    c.heal();
    let i = c.add_device(97);
    assert!(!c.devices[i].bootstrap(&c.store, c.clocks[0]).unwrap());
    // It still reads everything from the streams.
    c.heal();
    c.assert_converged();
}
#[test]
fn a_snapshot_its_author_never_chained_is_treated_as_a_fork() {
    let (mut c, vault) = shared(2);
    // A copy of the main device writes a snapshot into another store; only the file is planted.
    let elsewhere = c.store.deep_copy();
    let mut copy = clone_of(&c.devices[0]);
    let name = copy.write_snapshot(&elsewhere, c.clocks[0]).unwrap();
    let Fetched::Ready(bytes) = elsewhere.get_snapshot(&name).unwrap() else {
        panic!()
    };
    c.store.put_snapshot(&bytes).unwrap();
    // The main device itself goes on writing, never mentioning that snapshot.
    for n in 0..3 {
        save(&mut c, 0, vault, ITEM, &format!("v{n}"));
        c.sync(0).unwrap();
    }
    let i = c.add_device(98);
    c.sync(0).unwrap();
    let _ = c.sync(i);
    assert!(matches!(
        c.devices[i].alarms().first(),
        Some(Alarm::Fork { stream, .. }) if *stream == device_id(0)
    ));
}
#[test]
fn own_snapshots_are_pruned_to_the_newest_two_and_written_when_due() {
    let (mut c, _) = shared(2);
    for _ in 0..3 {
        c.devices[0].write_snapshot(&c.store, c.clocks[0]).unwrap();
        c.sync(0).unwrap();
    }
    let own = c
        .store
        .snapshots()
        .unwrap()
        .into_iter()
        .filter(|(_, a)| *a == device_id(0))
        .count();
    assert_eq!(own, 2);
    c.devices[1].entries_since_snapshot = SNAPSHOT_EVERY_ENTRIES;
    c.devices[1].last_snapshot_ms = Some(c.clocks[1]);
    c.sync(1).unwrap();
    assert!(c.devices[1]
        .take_events()
        .iter()
        .any(|e| matches!(e, Event::SnapshotWritten { .. })));
}
#[test]
fn after_a_restored_backup_everyone_continues_from_a_snapshot() {
    let (mut c, vault) = shared(3);
    let backup = c.store.deep_copy();
    save(&mut c, 1, vault, ITEM, "after the backup");
    c.sync(1).unwrap();
    c.sync(0).unwrap();
    // The store is restored from the backup: device 1's last segment is gone.
    let store = backup;
    // The main device received it: a rollback alarm (only that stream pauses); it restores.
    c.devices[0].sync(&store, c.clocks[0]).unwrap();
    assert!(matches!(
        c.devices[0].alarms().first(),
        Some(Alarm::Rollback { stream, .. }) if *stream == device_id(1)
    ));
    c.devices[0]
        .restore(&store, device_id(1), c.clocks[0])
        .unwrap();
    assert!(c.devices[0].alarms().is_empty());
    // Device 1's own stream went back: it notices before its next write, restores, goes on.
    save(&mut c, 1, vault, Uuid::from_bytes([0x61; 16]), "later");
    c.devices[1].sync(&store, c.clocks[1]).unwrap();
    assert!(matches!(
        c.devices[1].alarms().first(),
        Some(Alarm::Rollback { stream, .. }) if *stream == device_id(1)
    ));
    c.devices[1]
        .restore(&store, device_id(1), c.clocks[1])
        .unwrap();
    c.devices[1].sync(&store, c.clocks[1]).unwrap();
    // Device 2 never saw the lost segment: it is anchored by a snapshot and catches up.
    c.devices[2].sync(&store, c.clocks[2]).unwrap();
    assert!(c.devices[2]
        .take_events()
        .iter()
        .any(|e| matches!(e, Event::Anchored { .. })));
    for _ in 0..4 {
        for i in 0..3 {
            c.devices[i].sync(&store, c.clocks[i]).unwrap();
        }
        c.tick(1_000);
    }
    let view = c.devices[0].view();
    for d in &c.devices {
        assert_eq!(d.view(), view);
    }
    let seen = titles(&view);
    assert!(
        seen.contains("after the backup") && seen.contains("later"),
        "{seen:?}"
    );
}
#[test]
fn only_the_main_device_restores_another_devices_stream() {
    let (mut c, vault) = shared(3);
    let backup = c.store.deep_copy();
    save(&mut c, 1, vault, ITEM, "after the backup");
    c.sync(1).unwrap();
    c.sync(2).unwrap();
    c.devices[2].sync(&backup, c.clocks[2]).unwrap();
    assert!(matches!(
        c.devices[2].restore(&backup, device_id(1), c.clocks[2]),
        Err(Error::Refused(_))
    ));
}
#[test]
fn a_rollback_a_snapshot_already_covers_raises_no_alarm() {
    let (mut c, vault) = shared(3);
    let backup = c.store.deep_copy();
    save(&mut c, 1, vault, ITEM, "after the backup");
    c.sync(1).unwrap();
    c.sync(0).unwrap();
    c.sync(2).unwrap();
    let store = backup;
    c.devices[0].sync(&store, c.clocks[0]).unwrap();
    c.devices[0]
        .restore(&store, device_id(1), c.clocks[0])
        .unwrap();
    c.devices[2].sync(&store, c.clocks[2]).unwrap();
    assert!(c.devices[2].alarms().is_empty());
    assert!(c.devices[2]
        .take_events()
        .iter()
        .any(|e| matches!(e, Event::RollbackRepaired { .. })));
}
```

- [ ] **Step 2: Implement.**

`crates/keyorra-sync/src/engine/snapshots.rs`:

```rust
//! Snapshots (spec §4.8): written after many entries, after a week, after a removal, and on
//! restore; used to bootstrap a device that has nothing yet, and to anchor a stream whose
//! segments the store lost (a rollback that someone restored).
//!
//! Under root-only authority (spec §4.3) what a snapshot may vouch for depends on its author:
//! - a device bootstraps only from a snapshot of the **main device** (verified with the root
//!   key from the account header), since only the root's word covers trust and other devices'
//!   records;
//! - a snapshot of the main device anchors any stream it covers; a snapshot of another
//!   (approved) device anchors only that device's own stream ("Restore from this Mac" of a
//!   rolled-back own stream).
//!
//! A snapshot is chained into its author's log by a `Snapshot` entry written right after it.
//! A device that started from a snapshot checks that entry in the author's next segments; a
//! snapshot that its author's log never mentions is treated as a fork.

use crate::pack::{check_entries, SnapshotBody};
use crate::snapshot::{decrypt_snapshot, seal_snapshot};

use super::*;

/// A snapshot is due after this many new entries…
pub const SNAPSHOT_EVERY_ENTRIES: u64 = 500;
/// …or this long after the last one.
pub const SNAPSHOT_EVERY_MS: u64 = 7 * 24 * 60 * 60 * 1000;
/// Own snapshots kept in the store (older ones are deleted).
const KEEP_OWN_SNAPSHOTS: usize = 2;
/// The author's `Snapshot` entry must appear within this many segments after the frontier.
const SNAPSHOT_ENTRY_WITHIN: u64 = 3;

/// The snapshot this device started from (or anchored on), until its author's log confirms it.
#[derive(Clone, Debug)]
pub(super) struct SnapshotRef {
    author: DeviceId,
    name: [u8; 32],
    after_seq: u64,
    segments: u64,
}

fn name_bytes(name: &str) -> Option<[u8; 32]> {
    data_encoding::HEXLOWER
        .decode(name.as_bytes())
        .ok()?
        .try_into()
        .ok()
}

impl<R: RngCore + CryptoRng> Engine<R> {
    pub(super) fn snapshot_due(&mut self, wall_ms: u64) -> bool {
        let Some(last) = self.last_snapshot_ms else {
            self.last_snapshot_ms = Some(wall_ms);
            return false;
        };
        self.entries_since_snapshot >= SNAPSHOT_EVERY_ENTRIES
            || self.revoked_since_snapshot
            || wall_ms >= last + SNAPSHOT_EVERY_MS
    }

    /// Writes a snapshot of everything this device has received and confirmed, stores it,
    /// and chains it into the own stream. Returns its name.
    pub fn write_snapshot(&mut self, transport: &impl Transport, wall_ms: u64) -> Result<String> {
        self.require_writable()?;
        let mut frontier = self.heads.clone();
        frontier.insert(self.device, self.sent);
        let within = |d: &DeviceId, s: u64| frontier.get(d).is_some_and(|h| s <= h.seq);
        let root = self.trust.root();
        let mut entries: Vec<(DeviceId, u64, Entry)> = self
            .root_log
            .iter()
            .filter(|(s, _)| within(&root, *s))
            .map(|(s, e)| (root, *s, e.clone()))
            .collect();
        entries.extend(
            self.header_entries
                .iter()
                .filter(|(s, _)| within(&root, *s))
                .map(|(s, h)| (root, *s, Entry::Header(h.clone()))),
        );
        entries.extend(
            self.header_seen
                .iter()
                .filter(|(d, s, _)| within(d, *s))
                .map(|(d, s, e)| (*d, *s, Entry::HeaderSeen { epoch: *e })),
        );
        entries.sort_by_key(|(d, s, _)| (*d, *s));
        let admitted: Vec<Accepted> = self
            .fold
            .retained()
            .filter(|a| self.trust.admits(&a.stream, a.seq) && within(&a.stream, a.seq))
            .cloned()
            .collect();
        let mut versions = Vec::with_capacity(admitted.len());
        for a in admitted {
            versions.push((a.stream, a.seq, self.reseal(&a)?));
        }
        let body = SnapshotBody {
            account_id: self.account_id,
            floors: frontier.iter().map(|(d, h)| (*d, h.seq)).collect(),
            frontier: frontier.clone(),
            entries,
            versions,
        };
        let bytes = seal_snapshot(
            &self.segment_key,
            &self.signer,
            self.device,
            body.to_value(),
            &mut self.rng,
        )?;
        let name = transport.put_snapshot(&bytes)?;
        let name_raw =
            name_bytes(&name).ok_or_else(|| Error::Transport("bad snapshot name".into()))?;
        self.write_entry(
            Entry::Snapshot {
                name: name_raw,
                frontier,
            },
            wall_ms,
        )?;
        self.own_snapshots.push(name.clone());
        while self.own_snapshots.len() > KEEP_OWN_SNAPSHOTS {
            let old = self.own_snapshots.remove(0);
            let _ = transport.delete_snapshot(&old);
        }
        self.entries_since_snapshot = 0;
        self.last_snapshot_ms = Some(wall_ms);
        self.revoked_since_snapshot = false;
        self.events
            .push(Event::SnapshotWritten { name: name.clone() });
        Ok(name)
    }

    /// An accepted version as an envelope again (the body re-sealed with a fresh nonce under
    /// the vault's key: the version and its content are what count, not the ciphertext).
    fn reseal(&mut self, a: &Accepted) -> Result<Envelope> {
        let mut envelope = Envelope {
            kind: a.kind,
            record_id: a.record_id,
            vault_id: a.vault_id,
            schema: SCHEMA_VERSION,
            version: a.version.clone(),
            tombstone: a.doc == Doc::Tombstone,
            body: None,
        };
        match &a.doc {
            Doc::Tombstone => {}
            Doc::Vault(_) => envelope.body = Some(a.doc.encode().to_vec()),
            Doc::Item(_) | Doc::Attachment(_) => {
                let vault = a
                    .vault_id
                    .ok_or_else(|| Error::NotFound("vault id".into()))?;
                let key = self
                    .writer_vault_key(vault)
                    .ok_or_else(|| Error::NotFound(format!("key of vault {vault}")))?;
                envelope.seal_body(&key, &self.account_id, &a.doc.encode(), &mut self.rng);
            }
        }
        Ok(envelope)
    }

    /// Opens and checks a snapshot: this account, entries of the right kinds, signed by its
    /// author with the key this device knows for it, the author admitted at its own frontier
    /// position. Returns the body and the author.
    fn check_snapshot(&self, bytes: &[u8]) -> Option<(SnapshotBody, DeviceId)> {
        let unverified = decrypt_snapshot(&self.segment_key, bytes).ok()?;
        let body = SnapshotBody::from_value(&unverified.body).ok()?;
        if body.account_id != self.account_id || check_entries(&body).is_err() {
            return None;
        }
        let author = unverified.header.author;
        let at = body.frontier.get(&author)?.seq;
        if !self.trust.admits(&author, at) {
            return None;
        }
        let key = self.trust.key(&author)?;
        unverified.verify(&key).ok()?;
        Some((body, author))
    }

    /// The streams a snapshot by `author` may vouch for.
    fn vouches_for(&self, author: &DeviceId, stream: &DeviceId) -> bool {
        *author == self.trust.root() || author == stream
    }

    /// A device with nothing yet starts from the newest snapshot of the main device it can
    /// verify (the one covering the most). Returns whether it did.
    pub fn bootstrap(&mut self, transport: &impl Transport, wall_ms: u64) -> Result<bool> {
        if !self.heads.is_empty() || self.fold.retained().next().is_some() || self.is_root() {
            return Ok(false);
        }
        let root = self.trust.root();
        let mut best: Option<(u64, String, SnapshotBody)> = None;
        for (name, author) in transport.snapshots()? {
            if author != root {
                continue;
            }
            let Ok(Fetched::Ready(bytes)) = transport.get_snapshot(&name) else {
                continue;
            };
            let Some((body, _)) = self.check_snapshot(&bytes) else {
                continue;
            };
            let score = body.frontier.values().map(|h| h.seq).sum::<u64>();
            if best.as_ref().is_none_or(|(s, ..)| score > *s) {
                best = Some((score, name, body));
            }
        }
        let Some((_, name, body)) = best else {
            return Ok(false);
        };
        self.load_snapshot(root, &name, body, None, wall_ms);
        Ok(true)
    }

    /// Fills a gap in `stream` from the snapshot (one that may vouch for it) that covers it
    /// furthest. Returns whether the stream's head moved.
    pub(super) fn anchor_stream(
        &mut self,
        transport: &impl Transport,
        stream: &DeviceId,
        wall_ms: u64,
    ) -> bool {
        let head = self.heads.get(stream).map_or(0, |h| h.seq);
        let Ok(listing) = transport.snapshots() else {
            return false;
        };
        let mut best: Option<(u64, String, DeviceId, SnapshotBody)> = None;
        for (name, author) in listing {
            if !self.vouches_for(&author, stream) {
                continue;
            }
            let Ok(Fetched::Ready(bytes)) = transport.get_snapshot(&name) else {
                continue;
            };
            let Some((body, author)) = self.check_snapshot(&bytes) else {
                continue;
            };
            let cover = body.covers(stream).map_or(0, |h| h.seq);
            if cover > head && best.as_ref().is_none_or(|(c, ..)| cover > *c) {
                best = Some((cover, name, author, body));
            }
        }
        let Some((cover, name, author, body)) = best else {
            return false;
        };
        self.load_snapshot(author, &name, body, Some(*stream), wall_ms);
        self.events.push(Event::Anchored {
            stream: *stream,
            seq: cover,
            by: author,
        });
        true
    }

    /// Whether a snapshot that may vouch for `stream` covers it up to `seq` (a rollback of it
    /// loses nothing).
    pub(super) fn snapshot_covers(
        &self,
        transport: &impl Transport,
        stream: &DeviceId,
        seq: u64,
    ) -> bool {
        let Ok(listing) = transport.snapshots() else {
            return false;
        };
        listing.into_iter().any(|(name, author)| {
            if !self.vouches_for(&author, stream) {
                return false;
            }
            let Ok(Fetched::Ready(bytes)) = transport.get_snapshot(&name) else {
                return false;
            };
            self.check_snapshot(&bytes)
                .and_then(|(body, _)| body.covers(stream))
                .is_some_and(|h| h.seq >= seq)
        })
    }

    /// Applies a snapshot: the main device's trust and header entries in order, everyone's
    /// header-seen entries, and the versions of the streams it may vouch for (`only`: just
    /// that one stream), whose heads move to its frontier.
    fn load_snapshot(
        &mut self,
        author: DeviceId,
        name: &str,
        body: SnapshotBody,
        only: Option<DeviceId>,
        wall_ms: u64,
    ) {
        let root = self.trust.root();
        let from_root = author == root;
        let wanted = |d: &DeviceId| match only {
            Some(s) => *d == s,
            None => true,
        } && (from_root || *d == author);
        if from_root {
            for (stream, seq, entry) in &body.entries {
                match entry {
                    Entry::Header(_) | Entry::HeaderSeen { .. } => {
                        self.note_header_entry(*stream, *seq, entry)
                    }
                    _ if *stream == root && !self.root_log.iter().any(|(s, _)| s == seq) => {
                        self.apply_root_entry(*seq, entry)
                    }
                    _ => {}
                }
            }
        }
        for (stream, seq, env) in body.versions {
            if !wanted(&stream) {
                continue;
            }
            let known = self.heads.get(&stream).map_or(0, |h| h.seq);
            if seq <= known {
                continue;
            }
            self.lanes
                .entry((stream, (env.kind, env.record_id)))
                .or_default()
                .push_back(Pending {
                    seq,
                    env,
                    doc: None,
                });
            *self.pending_count.entry(stream).or_insert(0) += 1;
        }
        for (device, head) in &body.frontier {
            if *device == self.device || !wanted(device) {
                continue;
            }
            let known = self.heads.get(device).map_or(0, |h| h.seq);
            if head.seq > known {
                self.heads.insert(*device, *head);
                self.hashes
                    .entry(*device)
                    .or_default()
                    .insert(head.seq, head.hash);
            }
        }
        self.apply_pending(wall_ms);
        if author != self.device {
            if let (Some(raw), Some(at)) = (name_bytes(name), body.frontier.get(&author)) {
                self.snapshot_ref = Some(SnapshotRef {
                    author,
                    name: raw,
                    after_seq: at.seq,
                    segments: 0,
                });
            }
        }
    }

    /// Checks a received segment of the author of the snapshot this device started from.
    pub(super) fn confirm_snapshot_ref(
        &mut self,
        stream: &DeviceId,
        first_seq: u64,
        entries: &[(u64, Entry)],
    ) {
        let Some(r) = &mut self.snapshot_ref else {
            return;
        };
        if r.author != *stream || first_seq <= r.after_seq {
            return;
        }
        let name = r.name;
        if entries
            .iter()
            .any(|(_, e)| matches!(e, Entry::Snapshot { name: n, .. } if *n == name))
        {
            self.snapshot_ref = None;
            return;
        }
        r.segments += 1;
        if r.segments >= SNAPSHOT_ENTRY_WITHIN {
            let seq = r.after_seq + 1;
            self.snapshot_ref = None;
            self.raise(Alarm::Fork {
                stream: *stream,
                seq,
            });
        }
    }

    /// "Restore from this Mac" after a rollback alarm about `stream`: writes a snapshot of
    /// everything this device has, so the others can continue from it, and resumes. A
    /// snapshot of the main device restores any stream; one of another device only its own.
    pub fn restore(
        &mut self,
        transport: &impl Transport,
        stream: DeviceId,
        wall_ms: u64,
    ) -> Result<()> {
        let Some(alarm) = self
            .alarms
            .iter()
            .find(|a| matches!(a, Alarm::Rollback { stream: s, .. } if *s == stream))
            .cloned()
        else {
            return Err(Error::Refused(
                "there is no rollback of that stream to restore".into(),
            ));
        };
        if !self.vouches_for(&self.device, &stream) {
            return Err(Error::Refused(
                "only the main device can restore another device's changes".into(),
            ));
        }
        let Alarm::Rollback { stored, .. } = alarm else {
            unreachable!("filtered above")
        };
        self.alarms.retain(|a| *a != alarm);
        if stream == self.device {
            self.restored_own = Some(self.sent.seq);
        } else {
            self.acknowledged_rollbacks.insert((stream, stored));
        }
        self.write_snapshot(transport, wall_ms)?;
        self.push(transport);
        Ok(())
    }
}
```

- [ ] **Step 3: Run and commit.**

Commit: `Sync A1c-2: snapshots scoped by author: bootstrap, anchoring, restore`.

---

### Task 10: Retiring the device id

**Files:** Create `crates/keyorra-sync/src/engine/retire.rs`; extend `recovery_tests.rs`.

- [ ] **Step 1: Failing tests.**

Add (section "retiring the id"):

```rust
#[test]
fn another_copy_writing_makes_this_device_continue_under_a_new_id_pending_approval() {
    let (mut c, vault) = shared(2);
    let old = c.devices[1].device();
    let mut twin = clone_of(&c.devices[1]);
    twin.save_item(
        vault,
        ITEM,
        &Cluster::item_json(ITEM, "twin", &[]),
        c.clocks[1],
    )
    .unwrap();
    twin.push(&c.store);
    save(&mut c, 1, vault, ITEM, "me");
    c.sync(1).unwrap();
    let events = c.devices[1].take_events();
    assert!(events.contains(&Event::OwnStreamConflict));
    assert!(events.iter().any(|e| matches!(
        e,
        Event::Retired { old: o, reason: RetireReason::OtherCopyWrote, .. } if *o == old
    )));
    assert_ne!(c.devices[1].device(), old);
    // Pending: it writes, but nothing of the new id counts for others until approved.
    assert!(c.devices[1].can_write());
    c.sync(1).unwrap();
    c.sync(0).unwrap();
    assert_eq!(c.devices[0].alarms(), vec![Alarm::Unapproved { count: 1 }]);
    assert!(!titles(&c.devices[0].view()).contains("me"));
    approve_retired(&mut c, 1);
    c.heal();
    c.assert_converged();
    // Both copies' changes survive: one shown, the other as a conflict copy.
    let seen = titles(&c.devices[0].view());
    assert!(seen.contains("twin") && seen.contains("me"), "{seen:?}");
}
#[test]
fn the_main_device_never_retires_it_asks_to_start_over() {
    let (mut c, vault) = shared(2);
    let mut twin = clone_of(&c.devices[0]);
    twin.save_item(
        vault,
        ITEM,
        &Cluster::item_json(ITEM, "twin", &[]),
        c.clocks[0],
    )
    .unwrap();
    twin.push(&c.store);
    save(&mut c, 0, vault, ITEM, "me");
    c.sync(0).unwrap();
    assert_eq!(c.devices[0].device(), device_id(0));
    assert!(c.devices[0]
        .take_events()
        .iter()
        .any(|e| matches!(e, Event::RootMustStartOver { .. })));
    let before = c.devices[0].sent.seq;
    save(&mut c, 0, vault, ITEM, "after");
    c.sync(0).unwrap();
    assert_eq!(c.devices[0].sent.seq, before, "it writes nothing more");
}
#[test]
fn a_missing_device_key_retires_the_id() {
    let (mut c, vault) = shared(2);
    let old = c.devices[1].device();
    let keys = MemoryKeys::default();
    c.devices[1].set_device_keys(Box::new(keys.clone()));
    save(&mut c, 1, vault, ITEM, "after restore");
    c.sync(1).unwrap();
    let new = c.devices[1].device();
    assert_ne!(new, old);
    assert!(keys.holds(&new), "the new key went to the key store");
    assert!(c.devices[1].take_events().iter().any(|e| matches!(
        e,
        Event::Retired {
            reason: RetireReason::KeyMissing,
            ..
        }
    )));
    approve_retired(&mut c, 1);
    c.heal();
    c.assert_converged();
    assert!(titles(&c.devices[0].view()).contains("after restore"));
}
```

- [ ] **Step 2: Implement.**

`crates/keyorra-sync/src/engine/retire.rs`:

```rust
//! Retiring the device id (spec §4.2): when another copy of this device wrote to its stream
//! (a clone, a restored backup, Migration Assistant) or its signing key is gone from the key
//! store, this device stops using the id and continues under a new id and key. It joins with
//! `SelfJoin` (pending: its writes count for nobody else until the main device approves it,
//! comparing the key code) and writes its own unconfirmed changes again under the new id. The
//! old id is not removed here: only the main device removes devices (A3 points to it).
//!
//! The main device cannot retire (its id and key are the account's anchor): it stops writing
//! and asks the user to start a new account from a device and carry the data over.

use super::*;

/// The device's signing keys. A1d keeps them in the Keychain with
/// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, so a database restored or copied to
/// another Mac finds no key and retires.
pub trait DeviceKeys: Send {
    fn holds(&self, device: &DeviceId) -> bool;
    fn store(&mut self, device: DeviceId, key: &SigningKey);
}

/// Assumes every key is held and stores nothing (tests, and until A1d).
pub struct KeepKeys;

impl DeviceKeys for KeepKeys {
    fn holds(&self, _: &DeviceId) -> bool {
        true
    }
    fn store(&mut self, _: DeviceId, _: &SigningKey) {}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetireReason {
    /// The signing key is not in this device's key store.
    KeyMissing,
    /// Another copy of this device wrote to its stream.
    OtherCopyWrote,
}

impl<R: RngCore + CryptoRng> Engine<R> {
    pub fn set_device_keys(&mut self, keys: Box<dyn DeviceKeys>) {
        self.keys = keys;
    }

    pub(super) fn retire(&mut self, reason: RetireReason, wall_ms: u64) -> Result<()> {
        if self.is_root() {
            if !self.halted {
                self.halted = true;
                self.events.push(Event::RootMustStartOver { reason });
            }
            return Ok(());
        }
        let old = self.device;
        let cut = self.sent.seq;
        // The last own version of every record written after the last confirmed position.
        let mut again: BTreeMap<RecordKey, Accepted> = BTreeMap::new();
        for a in self.fold.retained() {
            if a.stream == old && a.seq > cut {
                let newer = again.get(&a.key()).is_none_or(|b| a.seq > b.seq);
                if newer {
                    again.insert(a.key(), a.clone());
                }
            }
        }
        // Those positions now belong to the other copy: forget them under the old id.
        self.fold.forget_after(&old, cut);
        self.header_seen.retain(|(d, s, _)| *d != old || *s <= cut);
        self.trust_changed();
        let mut id = [0u8; 16];
        self.rng.fill_bytes(&mut id);
        let mut secret = Zeroizing::new([0u8; 32]);
        self.rng.fill_bytes(&mut secret[..]);
        let signer = SigningKey::from_bytes(&secret);
        self.keys.store(id, &signer);
        self.device = id;
        self.signer = signer;
        self.sent = Head {
            seq: 0,
            hash: chain_genesis(&self.account_id, &id),
        };
        self.own_hashes.clear();
        self.unsent = None;
        self.outbox.clear();
        self.next_seq = 1;
        self.last_checkpoint = None;
        self.retire_due = None;
        self.self_join(wall_ms)?;
        for (_, a) in again {
            let edit = matches!(a.doc, Doc::Item(_));
            self.write_with(a.kind, a.record_id, a.vault_id, a.doc, wall_ms, edit)?;
        }
        self.events.push(Event::Retired {
            old,
            new: id,
            reason,
        });
        Ok(())
    }
}
```

- [ ] **Step 3: Run and commit.**

Commit: `Sync A1c-2: retiring the device id (pending re-approval); the main device starts over`.

---

### Task 11: Existing tests on the new store and recovery

**Files:** Modify `crates/keyorra-sync/src/engine/tests.rs`, `crates/keyorra-sync/src/engine/attack_tests.rs`.

- [ ] **Step 1: Apply.**

Test transports pass the new operations through; `clone_of` copies the root log and header state and is `pub(super)` (recovery tests use it); the W1 test relies on the root head file; the W3 test accepts that a joiner whose segment was replaced in the store retires to a new id (it found another copy wrote its stream) instead of only raising `ApprovedWithAnotherKey`:

```diff
diff --git a/crates/keyorra-sync/src/engine/tests.rs b/crates/keyorra-sync/src/engine/tests.rs
index e8a4ebc..5abb224 100644
--- a/crates/keyorra-sync/src/engine/tests.rs
+++ b/crates/keyorra-sync/src/engine/tests.rs
@@ -188,6 +188,33 @@ impl Transport for Upto<'_> {
     fn head(&self, stream: &DeviceId) -> Result<Option<u64>> {
         self.inner.head(stream)
     }
+    fn headers(&self) -> Result<Vec<(String, Fetched<Vec<u8>>)>> {
+        self.inner.headers()
+    }
+    fn put_header(&self, name: &str, bytes: &[u8]) -> Result<()> {
+        self.inner.put_header(name, bytes)
+    }
+    fn delete_header(&self, name: &str) -> Result<()> {
+        self.inner.delete_header(name)
+    }
+    fn snapshots(&self) -> Result<Vec<(String, DeviceId)>> {
+        self.inner.snapshots()
+    }
+    fn get_snapshot(&self, name: &str) -> Result<Fetched<Vec<u8>>> {
+        self.inner.get_snapshot(name)
+    }
+    fn put_snapshot(&self, bytes: &[u8]) -> Result<String> {
+        self.inner.put_snapshot(bytes)
+    }
+    fn delete_snapshot(&self, name: &str) -> Result<()> {
+        self.inner.delete_snapshot(name)
+    }
+    fn root_head_file(&self) -> Result<Fetched<Vec<u8>>> {
+        self.inner.root_head_file()
+    }
+    fn put_root_head_file(&self, bytes: &[u8]) -> Result<()> {
+        self.inner.put_root_head_file(bytes)
+    }
 }
 
 #[test]
@@ -463,6 +490,33 @@ impl Transport for BrokenStream<'_> {
     fn head(&self, stream: &DeviceId) -> Result<Option<u64>> {
         self.inner.head(stream)
     }
+    fn headers(&self) -> Result<Vec<(String, Fetched<Vec<u8>>)>> {
+        self.inner.headers()
+    }
+    fn put_header(&self, name: &str, bytes: &[u8]) -> Result<()> {
+        self.inner.put_header(name, bytes)
+    }
+    fn delete_header(&self, name: &str) -> Result<()> {
+        self.inner.delete_header(name)
+    }
+    fn snapshots(&self) -> Result<Vec<(String, DeviceId)>> {
+        self.inner.snapshots()
+    }
+    fn get_snapshot(&self, name: &str) -> Result<Fetched<Vec<u8>>> {
+        self.inner.get_snapshot(name)
+    }
+    fn put_snapshot(&self, bytes: &[u8]) -> Result<String> {
+        self.inner.put_snapshot(bytes)
+    }
+    fn delete_snapshot(&self, name: &str) -> Result<()> {
+        self.inner.delete_snapshot(name)
+    }
+    fn root_head_file(&self) -> Result<Fetched<Vec<u8>>> {
+        self.inner.root_head_file()
+    }
+    fn put_root_head_file(&self, bytes: &[u8]) -> Result<()> {
+        self.inner.put_root_head_file(bytes)
+    }
 }
 
 #[test]
@@ -652,7 +706,7 @@ fn after_an_own_stream_conflict_the_device_stops_pushing() {
 }
 
 /// A second engine with the same id, key and state: a cloned or restored Mac.
-fn clone_of(e: &Engine<rand::rngs::StdRng>) -> Engine<rand::rngs::OsRng> {
+pub(super) fn clone_of(e: &Engine<rand::rngs::StdRng>) -> Engine<rand::rngs::OsRng> {
     let i = (e.device[0] - 1) as usize;
     let mut twin = Engine::join(
         e.device,
@@ -674,6 +728,9 @@ fn clone_of(e: &Engine<rand::rngs::StdRng>) -> Engine<rand::rngs::OsRng> {
     twin.hashes = e.hashes.clone();
     twin.checkpoint_bounds = e.checkpoint_bounds.clone();
     twin.last_checkpoint = e.last_checkpoint.clone();
+    twin.root_log = e.root_log.clone();
+    twin.header_entries = e.header_entries.clone();
+    twin.header_seen = e.header_seen.clone();
     twin
 }
 
@@ -1214,14 +1271,8 @@ fn review_w1_a_withheld_root_tail_is_noticed_against_the_advertised_head() {
         stream: device_id(0),
         last_seq: before,
     };
-    c.devices[1].sync(&hiding, c.clocks[1]).unwrap();
-    assert!(
-        c.devices[1].root_confirmed(),
-        "nothing advertised yet: nothing to compare"
-    );
-    // The account header / setup code carries the root's current head.
+    // The root's head file (plan A1c-2) advertises its current head.
     let advertised = c.devices[0].root_head();
-    c.devices[1].set_root_head(advertised);
     c.devices[1].sync(&hiding, c.clocks[1]).unwrap();
     assert!(!c.devices[1].root_confirmed());
     assert_eq!(
```

```diff
diff --git a/crates/keyorra-sync/src/engine/attack_tests.rs b/crates/keyorra-sync/src/engine/attack_tests.rs
index eda534a..fb5788d 100644
--- a/crates/keyorra-sync/src/engine/attack_tests.rs
+++ b/crates/keyorra-sync/src/engine/attack_tests.rs
@@ -225,6 +225,33 @@ impl Transport for NoHeads {
     fn head(&self, _: &DeviceId) -> Result<Option<u64>> {
         Err(Error::Transport("no metadata".into()))
     }
+    fn headers(&self) -> Result<Vec<(String, Fetched<Vec<u8>>)>> {
+        self.0.headers()
+    }
+    fn put_header(&self, name: &str, bytes: &[u8]) -> Result<()> {
+        self.0.put_header(name, bytes)
+    }
+    fn delete_header(&self, name: &str) -> Result<()> {
+        self.0.delete_header(name)
+    }
+    fn snapshots(&self) -> Result<Vec<(String, DeviceId)>> {
+        self.0.snapshots()
+    }
+    fn get_snapshot(&self, name: &str) -> Result<Fetched<Vec<u8>>> {
+        self.0.get_snapshot(name)
+    }
+    fn put_snapshot(&self, bytes: &[u8]) -> Result<String> {
+        self.0.put_snapshot(bytes)
+    }
+    fn delete_snapshot(&self, name: &str) -> Result<()> {
+        self.0.delete_snapshot(name)
+    }
+    fn root_head_file(&self) -> Result<Fetched<Vec<u8>>> {
+        self.0.root_head_file()
+    }
+    fn put_root_head_file(&self, bytes: &[u8]) -> Result<()> {
+        self.0.put_root_head_file(bytes)
+    }
 }
 
 #[test]
@@ -751,6 +778,17 @@ fn review_w3_approval_checks_the_key_shown_on_the_joining_device() {
         .unwrap();
     c.sync(0).unwrap();
     joiner.sync(&c.store, START_MS).unwrap();
-    assert!(!joiner.can_write());
-    assert!(joiner.alarms().contains(&Alarm::ApprovedWithAnotherKey));
+    // The joiner finds its id taken by another key: it does not write under it (plan A1c-2:
+    // the store already holds someone else's segment there, so it retires to a new id and
+    // asks for approval again).
+    let retired = joiner
+        .take_events()
+        .iter()
+        .any(|e| matches!(e, Event::Retired { .. }));
+    assert!(
+        retired || joiner.alarms().contains(&Alarm::ApprovedWithAnotherKey),
+        "{:?}",
+        joiner.alarms()
+    );
+    assert!(joiner.device() != device_id(5) || !joiner.can_write());
 }
```

- [ ] **Step 2: Property tests.**

`PROPTEST_CASES=2000 cargo test --release -p keyorra-sync -- adversary convergence` passes (snapshots are written when due during these runs).

- [ ] **Step 3: Commit.**

`Sync A1c-2: existing tests on header, snapshot and root head files`.

---

### Task 12: Spec and protocol

**Files:** Modify `docs/superpowers/specs/2026-10-05-keyorra-sync-design.md`, `docs/sync-protocol.md`.

- [ ] **Step 1: Apply the "Spec changes" above.**

Also document `root.head` in the folder layout (spec §5.1) next to the header and snapshot files.

- [ ] **Step 2: Commit.**

`docs: A1c-2 headers, root head file, snapshots, retiring`.

---

### Task 13: Final verification

**Files:** —

- [ ] **Step 1: Run.**

`cargo fmt --all --check`; `cargo clippy -p keyorra-sync --all-targets -- -D warnings`; `cargo test -p keyorra-sync` (223 passed, 1 ignored when verified); `PROPTEST_CASES=20000 cargo test --release -p keyorra-sync -- adversary convergence`.

- [ ] **Step 2: Check.**

`git status` clean apart from untracked files that are not part of this plan; no push.

---

