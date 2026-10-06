# Keyorra Sync A1c-1 Implementation Plan (streams and trust)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the streams trustworthy: typed, signed stream entries; the root device's `Genesis`; endorsement and Emergency-Kit self-join (with an alarm on every other device); revocation whose cut is part of the admission rule and refolds the state; per-record causal delivery instead of stream stalls (review I6); checkpoints; detection of rollback, forks and withheld changes with a pausing alarm; and fault transports that roll back or fork a stream.

**Split:** the spec's A1c was too large for one reviewable plan. This is **A1c-1**. **A1c-2** (recovery and bootstrap) follows: clone/restore detection with a device-key store hook and retiring the device id, account headers as signed entries (highest-epoch join, concurrent epochs, old-epoch deletion), snapshots (bootstrap with per-stream floors, restore after a rollback), and outbox persistence hooks for A1d. Spec §12 lists both.

**Architecture:** `keyorra-sync` stays pure. New: `entry` (the entry types and endorsement statements) and `trust` (introduced devices and cuts, derived from all trust entries in `(stream, seq)` order; it is also the fold's `Admission`). `segment` splits opening into `decrypt_segment` + `Unverified::verify`, because the root's and a self-joined device's first segment carry their own key. `transport` gains `head` (the stored head of a stream, for rollback detection). `faults` gains `Rollback` and `Overlay`. `fold` gains orphaned-copy proposals (a copy written only by a since-removed device is written again). The engine is rewritten around two layers: a **log** layer that receives segments strictly in chain order (signature, continuity, checkpoint claims, forks) and an **apply** layer with per-record buffering. The `Directory` trait and `set_admission` from A1b are gone: trust supplies both. `testkit::Cluster` now builds a real account (device 0 creates it and approves the others).

**Tech Stack:** unchanged from A1b.

**Spec:** `docs/superpowers/specs/2026-10-05-keyorra-sync-design.md` §4.1, §4.3–4.6 (revised in the same commit as this plan), §11 suites 3, 5, 6, §12 (A1c-1).

**Builds on:** `feat/sync-design` at `dafcfbb` (A1b with the review fixes).

## Decisions

- **Device names travel in `Genesis`, `Endorse` and `SelfJoin`**; there is no device record kind. Renaming a device is A3.
- **Self-certified first segments.** The root's stream is readable before anything else is known: its first segment verifies with the key inside its `Genesis` (only for the stream the account header names as root). A self-joined device's first segment verifies with the key inside its `SelfJoin`. Every other stream needs an endorsement first.
- **Revocation rule** (made precise, spec §4.3): a `Revoke` counts if the revoker revokes itself, or is introduced without the revoked device, and if it was written before the revoker's own cut, ignoring a cut that came from the device being revoked. So mutual revocations both apply (as the spec says), a device endorsed after its endorser's cut cannot revoke it back, and a removed device cannot remove others afterwards. It is a closed-form computation, not an iteration that could oscillate.
- **Per-record causal delivery** (review I6). A received segment advances its stream at once; its entries then apply as soon as their needs are met (vault key; earlier versions of other devices counted by the vector; same-stream order per record; trust entries in one lane). Checkpoints are for detection only.
- **Checkpoints** are written before the first entry after the writer's received heads changed (not as the first entry of every segment: inserting one at sealing time would shift sequence numbers already given to entries), and hourly by a device that only reads.
- **Detection.** Fork: a received segment that does not continue the chain, or a checkpoint that disagrees with a received segment end, or a checkpoint claiming the own stream beyond what was written (except the segment whose append outcome was lost: then it counts as confirmed). Rollback: `Transport::head` behind the received head (others) or the confirmed head (own). Withheld: a claim unmet for 24 h (warning). Fork and rollback raise an `Alarm`; while raised, `sync` does nothing and returns `Error::Refused`; `clear_alarm` resumes (restore is A1c-2).
- **Who writes.** A device not introduced yet reads but its writes are refused; a removed device (own cut) stops writing, materialising and checkpointing. When every device was removed, owed copies stay owed (tests account for that).
- **Revocation races** (found by the property test). Devices that received a removed device's later versions before they heard of the revocation may have built on them; those versions are theirs and keep counting. But a conflict copy written only by the removed device, of a version that still counts, would vanish: the fold now proposes it again (`View::orphan_copies`) and any writable device writes it.
- **Not here:** clone handling beyond stopping (`OwnStreamConflict`), headers, snapshots, restore, persisted outbox (A1c-2/A1d); the approval code exchange and UI (A3/B).

## Conventions for every task

- Test first: write the test, run it, see it fail for the expected reason, implement, see it pass, commit.
- English only. Every commit message ends with these two lines (omitted below; always add them):

```
Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_016B8vpfBkT1rhCY8NF4kPbd
```

- Rust from the repo root. After each task: `cargo fmt --all`; `cargo clippy -p keyorra-sync --all-targets -- -D warnings` clean.
- Shell: an `rtk` proxy may filter output; `rtk proxy <cmd>` runs it raw. Plain `grep` with a glob through the proxy can miss matches; use `grep -rn <dir>`.
- proptest writes newly found failure seeds to `crates/keyorra-sync/proptest-regressions/convergence_tests.txt`; commit that file with the task that produced it.
- Work on `feat/sync-design`; do not push.

## File map

```
crates/keyorra-sync/src/segment.rs          decrypt_segment + Unverified::verify; open_segment uses them
crates/keyorra-sync/src/labels.rs           + ENDORSE
crates/keyorra-sync/src/entry.rs            NEW stream entries, endorsement statements
crates/keyorra-sync/src/trust.rs            NEW introduced devices and cuts; Admission
crates/keyorra-sync/src/transport.rs        + Transport::head, MemoryTransport::deep_copy
crates/keyorra-sync/src/faults.rs           + head for Faulty, Rollback, Overlay
crates/keyorra-sync/src/fold.rs             + View::orphan_copies, View::owes_copies
crates/keyorra-sync/src/engine.rs           rewritten: log layer, apply layer, trust, alarms
crates/keyorra-sync/src/engine/tests.rs     rewritten for the new API, + trust/detection tests
crates/keyorra-sync/src/testkit.rs          a real account: create, join, approve
crates/keyorra-sync/src/convergence_tests.rs revocations in the properties; admission-aware oracle
crates/keyorra-sync/src/lib.rs              + entry, trust
docs/sync-protocol.md                       §2 label, §10 written
docs/superpowers/specs/2026-10-05-keyorra-sync-design.md   §4.1, §4.3–4.6, §12 (with this plan)
```

---

### Task 1: Segments: decrypt first, verify with a key found inside

**Files:** Modify `crates/keyorra-sync/src/segment.rs`.

- [ ] **Step 1: Failing test.** In `segment.rs`, add to `mod tests` (before `header_parse_rejects_bad_magic_collection_and_seqs`):

```rust
    #[test]
    fn decrypt_then_verify_equals_open() {
        let unverified = decrypt_segment(&k_seg(), &sealed()).unwrap();
        assert_eq!(unverified.entries, entries());
        let other = SigningKey::from_bytes(&[0x42; 32]).verifying_key();
        assert!(matches!(
            unverified.clone().verify(&other),
            Err(Error::BadSignature)
        ));
        assert_eq!(
            unverified.verify(&signer().verifying_key()).unwrap(),
            open_segment(&k_seg(), &signer().verifying_key(), &sealed()).unwrap()
        );
    }
```

- [ ] **Step 2: Run, expect failure.** `cargo test -p keyorra-sync segment::` → does not compile (`decrypt_segment` missing).

- [ ] **Step 3: Implement.** Replace the whole `open_segment` function with:

```rust
pub fn open_segment(segment_key: &Key, author: &VerifyingKey, segment: &[u8]) -> Result<Segment> {
    decrypt_segment(segment_key, segment)?.verify(author)
}

/// A decrypted segment whose signature is not checked yet: for streams whose key is carried
/// by their own first entry (the root's `Genesis`, a `SelfJoin`; plan A1c).
#[derive(Clone, Debug)]
pub struct Unverified {
    pub header: SegmentHeader,
    pub entries: Vec<Value>,
    entries_value: Value,
    sig: [u8; 64],
}

impl Unverified {
    /// Checks the signature, the entry count and the chain.
    pub fn verify(self, author: &VerifyingKey) -> Result<Segment> {
        author
            .verify_strict(
                &signed_message(&self.header.to_bytes(), &self.entries_value),
                &Signature::from_bytes(&self.sig),
            )
            .map_err(|_| Error::BadSignature)?;
        if self.entries.len() as u64 != self.header.entry_count() {
            return Err(malformed("segment entry count"));
        }
        if chain(&self.header.prev_hash, &self.entries) != self.header.last_hash {
            return Err(malformed("segment chain"));
        }
        Ok(Segment {
            header: self.header,
            entries: self.entries,
        })
    }
}

/// Decrypts and decodes a segment without checking who signed it.
pub fn decrypt_segment(segment_key: &Key, segment: &[u8]) -> Result<Unverified> {
    let header = SegmentHeader::parse(segment)?;
    let header_bytes = header.to_bytes();
    let sealed = &segment[HEADER_LEN..];
    let nonce: &[u8; NONCE_LEN] = sealed
        .get(..NONCE_LEN)
        .and_then(|n| n.try_into().ok())
        .ok_or_else(|| malformed("segment nonce"))?;
    let padded = crypto::open(segment_key, sealed, &aad(&header_bytes, nonce))
        .map_err(|_| Error::Decrypt)?;
    let content = unpad(&padded)?;
    if content.len() > MAX_ENTRIES_LEN + 128 {
        return Err(malformed("segment payload larger than allowed"));
    }
    let payload = cbor::decode(content)?;
    let f = payload.fields(&["entries", "sig"])?;
    let entries_value = f.get("entries")?.clone();
    let sig: [u8; 64] = f.get("sig")?.as_array_of()?;
    if cbor::encode(&entries_value).len() > MAX_ENTRIES_LEN {
        return Err(malformed("segment too large"));
    }
    let entries = entries_value.as_list()?.to_vec();
    Ok(Unverified {
        header,
        entries,
        entries_value,
        sig,
    })
}
```

- [ ] **Step 4: Run.** `cargo test -p keyorra-sync segment::` → all pass (the existing segment tests now go through the split path).

- [ ] **Step 5: Commit.**

```bash
git add crates/keyorra-sync/src/segment.rs
git commit -m "sync: open segments in two steps, decrypt then verify"
```

### Task 2: Stream entries

**Files:** Modify `crates/keyorra-sync/src/labels.rs`, `crates/keyorra-sync/src/lib.rs`; create `crates/keyorra-sync/src/entry.rs`.

- [ ] **Step 1: Label.** In `labels.rs`, after `CONFLICT_COPY`, add `pub const ENDORSE: &[u8] = b"keyorra/sync/v1/endorse";` and append `ENDORSE,` to `ALL` (the existing label test then covers it).
- [ ] **Step 2: Failing tests.** Add `pub mod entry;` to `lib.rs` and create `crates/keyorra-sync/src/entry.rs` with only the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor;
    use crate::envelope::{RecordKind, Version};
    use uuid::Uuid;

    const ACCOUNT: AccountId = [0x10; 16];

    fn samples() -> Vec<Entry> {
        let signer = SigningKey::from_bytes(&[0x41; 32]);
        let key = signer.verifying_key().to_bytes();
        vec![
            Entry::Put(Envelope {
                kind: RecordKind::Item,
                record_id: Uuid::from_bytes([0x60; 16]),
                vault_id: Some(Uuid::from_bytes([0x61; 16])),
                schema: 1,
                version: Version {
                    vector: [([1; 16], 1)].into_iter().collect(),
                    hlc: 7,
                    author: [1; 16],
                },
                tombstone: true,
                body: None,
            }),
            Entry::Checkpoint(
                [(
                    [2; 16],
                    Head {
                        seq: 4,
                        hash: [9; 32],
                    },
                )]
                .into_iter()
                .collect(),
            ),
            Entry::Genesis {
                account_id: ACCOUNT,
                key,
                name: "MacBook Pro".into(),
            },
            Entry::SelfJoin {
                key,
                name: "MacBook Air".into(),
                sig: sign_endorsement(&signer, &ACCOUNT, &[3; 16], &key),
            },
            Entry::Endorse {
                device: [3; 16],
                key,
                name: "MacBook Air".into(),
                sig: sign_endorsement(&signer, &ACCOUNT, &[3; 16], &key),
            },
            Entry::Revoke {
                device: [3; 16],
                last_valid_seq: 12,
            },
        ]
    }

    #[test]
    fn every_entry_round_trips_through_canonical_cbor() {
        for entry in samples() {
            let bytes = cbor::encode(&entry.to_value());
            assert_eq!(
                Entry::from_value(&cbor::decode(&bytes).unwrap()).unwrap(),
                entry
            );
        }
    }

    #[test]
    fn unknown_types_are_unsupported_and_shapes_are_checked() {
        let future = Value::map(vec![("passkey", Value::Null)]);
        assert!(matches!(
            Entry::from_value(&future),
            Err(Error::Unsupported(_))
        ));
        let two = Value::map(vec![("revoke", Value::Null), ("put", Value::Null)]);
        assert!(matches!(Entry::from_value(&two), Err(Error::Malformed(_))));
        let bad = Value::map(vec![("revoke", Value::map(vec![]))]);
        assert!(matches!(Entry::from_value(&bad), Err(Error::Malformed(_))));
    }

    #[test]
    fn endorsements_are_bound_to_account_device_and_key() {
        let signer = SigningKey::from_bytes(&[0x41; 32]);
        let pk = signer.verifying_key();
        let key = [7; 32];
        let sig = sign_endorsement(&signer, &ACCOUNT, &[3; 16], &key);
        assert!(verify_endorsement(&pk, &ACCOUNT, &[3; 16], &key, &sig));
        assert!(!verify_endorsement(&pk, &[0x11; 16], &[3; 16], &key, &sig));
        assert!(!verify_endorsement(&pk, &ACCOUNT, &[4; 16], &key, &sig));
        assert!(!verify_endorsement(&pk, &ACCOUNT, &[3; 16], &[8; 32], &sig));
        let other = SigningKey::from_bytes(&[0x42; 32]).verifying_key();
        assert!(!verify_endorsement(&other, &ACCOUNT, &[3; 16], &key, &sig));
    }

    #[test]
    fn only_first_entries_carry_their_own_key() {
        let keys: Vec<bool> = samples().iter().map(|e| e.own_key().is_some()).collect();
        assert_eq!(keys, [false, false, true, true, false, false]);
    }
}
```

`cargo test -p keyorra-sync entry::` → does not compile (`Entry`, `Head`, `sign_endorsement`, … missing).

- [ ] **Step 3: Implement.** Put this above the test module:

````rust
//! Stream entries (spec §4.1): what a device's log segments carry.
//!
//! ```text
//! entry = { "put": Envelope }
//!       | { "checkpoint": { bytes16 → [seq, hash] } }        heads of other streams applied by the writer
//!       | { "genesis": { "account_id", "key", "name" } }     the root device, first entry of its stream
//!       | { "self_join": { "key", "name", "sig" } }          a device that joined with the Emergency Kit
//!       | { "endorse": { "device", "key", "name", "sig" } }  a live device vouches for another one
//!       | { "revoke": { "device", "last_valid_seq" } }       entries of `device` after the cut stop counting
//! sig   = Ed25519(signer, "keyorra/sync/v1/endorse\0" ‖ account_id ‖ device ‖ key)
//! ```
//!
//! `endorse` is signed by the endorsing device, `self_join` by the joining device itself. The
//! same signature is what a server checks when a device is approved (spec §6.4).

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::cbor::Value;
use crate::envelope::Envelope;
use crate::error::{malformed, Error, Result};
use crate::labels::{self, tagged};
use crate::{AccountId, DeviceId};

/// A stream position: the sequence number and chain hash of an entry (normally the last entry
/// of a segment).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Head {
    pub seq: u64,
    pub hash: [u8; 32],
}

pub type Heads = BTreeMap<DeviceId, Head>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry {
    Put(Envelope),
    Checkpoint(Heads),
    Genesis {
        account_id: AccountId,
        key: [u8; 32],
        name: String,
    },
    SelfJoin {
        key: [u8; 32],
        name: String,
        sig: [u8; 64],
    },
    Endorse {
        device: DeviceId,
        key: [u8; 32],
        name: String,
        sig: [u8; 64],
    },
    Revoke {
        device: DeviceId,
        last_valid_seq: u64,
    },
}

/// What an endorsement (or a self-join) signs.
pub fn endorse_statement(account_id: &AccountId, device: &DeviceId, key: &[u8; 32]) -> Vec<u8> {
    tagged(labels::ENDORSE, &[account_id, device, key])
}

pub fn sign_endorsement(
    signer: &SigningKey,
    account_id: &AccountId,
    device: &DeviceId,
    key: &[u8; 32],
) -> [u8; 64] {
    signer
        .sign(&endorse_statement(account_id, device, key))
        .to_bytes()
}

pub fn verify_endorsement(
    signer: &VerifyingKey,
    account_id: &AccountId,
    device: &DeviceId,
    key: &[u8; 32],
    sig: &[u8; 64],
) -> bool {
    signer
        .verify_strict(
            &endorse_statement(account_id, device, key),
            &Signature::from_bytes(sig),
        )
        .is_ok()
}

impl Entry {
    pub fn to_value(&self) -> Value {
        let (tag, body) = match self {
            Entry::Put(env) => ("put", env.to_value()),
            Entry::Checkpoint(heads) => (
                "checkpoint",
                Value::Map(
                    heads
                        .iter()
                        .map(|(d, h)| {
                            (
                                Value::bytes(d),
                                Value::Array(vec![Value::Uint(h.seq), Value::bytes(h.hash)]),
                            )
                        })
                        .collect(),
                ),
            ),
            Entry::Genesis {
                account_id,
                key,
                name,
            } => (
                "genesis",
                Value::map(vec![
                    ("account_id", Value::bytes(account_id)),
                    ("key", Value::bytes(key)),
                    ("name", Value::text(name)),
                ]),
            ),
            Entry::SelfJoin { key, name, sig } => (
                "self_join",
                Value::map(vec![
                    ("key", Value::bytes(key)),
                    ("name", Value::text(name)),
                    ("sig", Value::bytes(sig)),
                ]),
            ),
            Entry::Endorse {
                device,
                key,
                name,
                sig,
            } => (
                "endorse",
                Value::map(vec![
                    ("device", Value::bytes(device)),
                    ("key", Value::bytes(key)),
                    ("name", Value::text(name)),
                    ("sig", Value::bytes(sig)),
                ]),
            ),
            Entry::Revoke {
                device,
                last_valid_seq,
            } => (
                "revoke",
                Value::map(vec![
                    ("device", Value::bytes(device)),
                    ("last_valid_seq", Value::Uint(*last_valid_seq)),
                ]),
            ),
        };
        Value::map(vec![(tag, body)])
    }

    /// Unknown entry types are `Unsupported` (a newer app wrote them), never `Malformed`.
    pub fn from_value(value: &Value) -> Result<Entry> {
        let map = value.as_map()?;
        let [(tag, body)] = map else {
            return Err(malformed("entry must have exactly one type"));
        };
        let tag = tag.as_text()?;
        Ok(match tag {
            "put" => Entry::Put(Envelope::from_value(body)?),
            "checkpoint" => {
                let mut heads = Heads::new();
                for (d, h) in body.as_map()? {
                    let [seq, hash] = h.as_list()? else {
                        return Err(malformed("checkpoint head"));
                    };
                    heads.insert(
                        d.as_array_of()?,
                        Head {
                            seq: seq.as_uint()?,
                            hash: hash.as_array_of()?,
                        },
                    );
                }
                Entry::Checkpoint(heads)
            }
            "genesis" => {
                let f = body.fields(&["account_id", "key", "name"])?;
                Entry::Genesis {
                    account_id: f.get("account_id")?.as_array_of()?,
                    key: f.get("key")?.as_array_of()?,
                    name: f.get("name")?.as_text()?.to_owned(),
                }
            }
            "self_join" => {
                let f = body.fields(&["key", "name", "sig"])?;
                Entry::SelfJoin {
                    key: f.get("key")?.as_array_of()?,
                    name: f.get("name")?.as_text()?.to_owned(),
                    sig: f.get("sig")?.as_array_of()?,
                }
            }
            "endorse" => {
                let f = body.fields(&["device", "key", "name", "sig"])?;
                Entry::Endorse {
                    device: f.get("device")?.as_array_of()?,
                    key: f.get("key")?.as_array_of()?,
                    name: f.get("name")?.as_text()?.to_owned(),
                    sig: f.get("sig")?.as_array_of()?,
                }
            }
            "revoke" => {
                let f = body.fields(&["device", "last_valid_seq"])?;
                Entry::Revoke {
                    device: f.get("device")?.as_array_of()?,
                    last_valid_seq: f.get("last_valid_seq")?.as_uint()?,
                }
            }
            other => return Err(Error::Unsupported(format!("entry type {other}"))),
        })
    }

    /// The key a stream's first entry carries for itself (root `Genesis`, `SelfJoin`).
    pub fn own_key(&self) -> Option<[u8; 32]> {
        match self {
            Entry::Genesis { key, .. } | Entry::SelfJoin { key, .. } => Some(*key),
            _ => None,
        }
    }
}
````

- [ ] **Step 4: Run.** `cargo test -p keyorra-sync -- entry:: labels::` → all pass.

- [ ] **Step 5: Commit.**

```bash
git add crates/keyorra-sync/src/labels.rs crates/keyorra-sync/src/lib.rs crates/keyorra-sync/src/entry.rs
git commit -m "sync: stream entries and endorsement statements"
```

### Task 3: Trust

**Files:** Create `crates/keyorra-sync/src/trust.rs`; modify `crates/keyorra-sync/src/lib.rs`.

Which devices are introduced and where their cuts are, from all recorded trust entries (spec §4.3 and §4.6 as revised; protocol §10.2).

- [ ] **Step 1: Failing tests.** Add `pub mod trust;` to `lib.rs` and create `trust.rs` with only the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::entry::sign_endorsement;
    use ed25519_dalek::SigningKey;

    const ACCOUNT: AccountId = [0x10; 16];
    const ROOT: DeviceId = [1; 16];
    const B: DeviceId = [2; 16];
    const C: DeviceId = [3; 16];
    const D: DeviceId = [4; 16];

    fn signer(d: &DeviceId) -> SigningKey {
        SigningKey::from_bytes(&[0x40 + d[0]; 32])
    }

    fn pk(d: &DeviceId) -> VerifyingKey {
        signer(d).verifying_key()
    }

    fn genesis() -> Entry {
        Entry::Genesis {
            account_id: ACCOUNT,
            key: pk(&ROOT).to_bytes(),
            name: "root".into(),
        }
    }

    fn endorse(by: &DeviceId, device: &DeviceId) -> Entry {
        let key = pk(device).to_bytes();
        Entry::Endorse {
            device: *device,
            key,
            name: "dev".into(),
            sig: sign_endorsement(&signer(by), &ACCOUNT, device, &key),
        }
    }

    fn self_join(device: &DeviceId) -> Entry {
        let key = pk(device).to_bytes();
        Entry::SelfJoin {
            key,
            name: "kit".into(),
            sig: sign_endorsement(&signer(device), &ACCOUNT, device, &key),
        }
    }

    fn revoke(device: &DeviceId, last_valid_seq: u64) -> Entry {
        Entry::Revoke {
            device: *device,
            last_valid_seq,
        }
    }

    fn rec(t: &mut Trust, stream: DeviceId, seq: u64, e: Entry) -> Result<bool, TrustError> {
        t.record(stream, &pk(&stream), seq, &e)
    }

    fn base() -> Trust {
        let mut t = Trust::new(ACCOUNT, ROOT);
        rec(&mut t, ROOT, 1, genesis()).unwrap();
        rec(&mut t, ROOT, 2, endorse(&ROOT, &B)).unwrap();
        t
    }

    #[test]
    fn root_and_endorsed_devices_are_admitted() {
        let t = base();
        assert_eq!(t.device(&ROOT).unwrap().introduced, Introduction::Root);
        assert_eq!(
            t.device(&B).unwrap().introduced,
            Introduction::Endorsed {
                by: ROOT,
                at_seq: 2
            }
        );
        assert!(t.admits(&B, 1_000));
        assert!(!t.admits(&C, 1));
        assert_eq!(t.key(&B), Some(pk(&B)));
    }

    #[test]
    fn introductions_are_checked() {
        let mut t = Trust::new(ACCOUNT, ROOT);
        assert_eq!(rec(&mut t, ROOT, 2, genesis()), Err(TrustError::Misplaced));
        assert_eq!(rec(&mut t, B, 1, genesis()), Err(TrustError::Misplaced));
        let other = Entry::Genesis {
            account_id: [0x11; 16],
            key: pk(&ROOT).to_bytes(),
            name: "x".into(),
        };
        assert_eq!(rec(&mut t, ROOT, 1, other), Err(TrustError::WrongAccount));
        rec(&mut t, ROOT, 1, genesis()).unwrap();
        let mut forged = endorse(&ROOT, &B);
        if let Entry::Endorse { sig, .. } = &mut forged {
            sig[0] ^= 1;
        }
        assert_eq!(rec(&mut t, ROOT, 2, forged), Err(TrustError::BadSignature));
        assert_eq!(rec(&mut t, C, 2, self_join(&C)), Err(TrustError::Misplaced));
    }

    #[test]
    fn a_device_cannot_get_two_keys() {
        let mut t = base();
        let key = pk(&C).to_bytes();
        let twisted = Entry::Endorse {
            device: B,
            key,
            name: "evil".into(),
            sig: sign_endorsement(&signer(&ROOT), &ACCOUNT, &B, &key),
        };
        assert_eq!(
            rec(&mut t, ROOT, 3, twisted),
            Err(TrustError::KeyConflict(B))
        );
    }

    #[test]
    fn self_joined_devices_count_and_are_listed() {
        let mut t = base();
        assert!(rec(&mut t, C, 1, self_join(&C)).unwrap());
        assert_eq!(t.device(&C).unwrap().introduced, Introduction::SelfJoined);
        assert_eq!(
            t.self_joined().map(|(d, _)| *d).collect::<Vec<_>>(),
            vec![C]
        );
    }

    #[test]
    fn a_revocation_cuts_the_stream_and_its_later_endorsements() {
        let mut t = base();
        rec(&mut t, B, 5, endorse(&B, &C)).unwrap();
        rec(&mut t, B, 9, endorse(&B, &D)).unwrap();
        assert!(t.device(&D).is_some());
        rec(&mut t, ROOT, 3, revoke(&B, 7)).unwrap();
        assert_eq!(t.device(&B).unwrap().cut, Some(7));
        assert!(t.admits(&B, 7) && !t.admits(&B, 8));
        assert!(t.device(&C).is_some(), "endorsed before the cut");
        assert!(t.device(&D).is_none(), "endorsed after the cut");
    }

    #[test]
    fn a_device_endorsed_after_the_cut_cannot_revoke_its_endorser_back() {
        let mut t = base();
        rec(&mut t, B, 5, endorse(&B, &C)).unwrap();
        rec(&mut t, ROOT, 3, revoke(&B, 4)).unwrap();
        // C exists only through B's post-cut endorsement; its revocation of the root is void.
        rec(&mut t, C, 1, revoke(&ROOT, 1)).unwrap();
        assert!(t.device(&C).is_none());
        assert_eq!(t.device(&ROOT).unwrap().cut, None);
        assert_eq!(t.device(&B).unwrap().cut, Some(4));
    }

    #[test]
    fn mutual_revocations_both_apply_and_self_revocation_counts() {
        let mut t = base();
        rec(&mut t, C, 1, self_join(&C)).unwrap();
        rec(&mut t, B, 3, revoke(&C, 2)).unwrap();
        rec(&mut t, C, 3, revoke(&B, 1)).unwrap();
        assert_eq!(t.device(&B).unwrap().cut, Some(1));
        assert_eq!(t.device(&C).unwrap().cut, Some(2));
        let mut u = base();
        rec(&mut u, B, 4, revoke(&B, 3)).unwrap();
        assert_eq!(u.device(&B).unwrap().cut, Some(3));
        // The earliest cut wins.
        rec(&mut u, ROOT, 3, revoke(&B, 1)).unwrap();
        assert_eq!(u.device(&B).unwrap().cut, Some(1));
    }

    #[test]
    fn a_revoked_device_cannot_revoke_others_after_its_cut() {
        let mut t = base();
        rec(&mut t, ROOT, 3, endorse(&ROOT, &C)).unwrap();
        rec(&mut t, ROOT, 4, revoke(&B, 2)).unwrap();
        rec(&mut t, B, 6, revoke(&C, 1)).unwrap();
        assert_eq!(t.device(&C).unwrap().cut, None);
        assert_eq!(t.device(&B).unwrap().cut, Some(2));
    }

    #[test]
    fn arrival_order_does_not_matter() {
        let entries = [
            (ROOT, 1, genesis()),
            (ROOT, 2, endorse(&ROOT, &B)),
            (B, 5, endorse(&B, &C)),
            (C, 1, revoke(&ROOT, 9)),
            (ROOT, 3, revoke(&B, 4)),
            (D, 1, self_join(&D)),
        ];
        let mut reference = Trust::new(ACCOUNT, ROOT);
        for (s, q, e) in entries.iter().cloned() {
            rec(&mut reference, s, q, e).unwrap();
        }
        for rotation in 0..entries.len() {
            let mut t = Trust::new(ACCOUNT, ROOT);
            for (s, q, e) in entries
                .iter()
                .cycle()
                .skip(rotation)
                .take(entries.len())
                .cloned()
            {
                rec(&mut t, s, q, e).unwrap();
            }
            assert_eq!(t.devices(), reference.devices(), "rotation {rotation}");
        }
    }
}
```

`cargo test -p keyorra-sync trust::` → does not compile.

- [ ] **Step 2: Implement.** Put this above the test module:

```rust
//! Which devices count (spec §4.3, §4.6): derived from the trust entries of all streams.
//!
//! - The **root** (named by the account header) is introduced by `Genesis`, the first entry
//!   of its own stream. A **self-joined** device by `SelfJoin`, the first entry of its own
//!   stream (an alarm on every other device). Any other device by an `Endorse` from an
//!   introduced device, made at a position that device may still write at.
//! - `Revoke { device, last_valid_seq }` cuts `device`'s stream: later positions stop
//!   counting. It counts if the revoker is introduced without relying on the revoked device
//!   (so a device endorsed after its endorser's cut cannot revoke it back) or revokes itself,
//!   and if it was written before the revoker's own cut, unless that cut came from the device
//!   being revoked (mutual revocations both apply). Several revocations of one device: the
//!   earliest cut wins.
//!
//! Everything is recomputed from the recorded entries in `(stream, seq)` order, so the result
//! does not depend on the order in which entries arrived.

use std::collections::BTreeMap;
use std::fmt;

use ed25519_dalek::VerifyingKey;

use crate::entry::{verify_endorsement, Entry};
use crate::fold::Admission;
use crate::{AccountId, DeviceId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Introduction {
    Root,
    /// Joined with the Emergency Kit, approved by no other device.
    SelfJoined,
    Endorsed {
        by: DeviceId,
        at_seq: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceInfo {
    pub key: VerifyingKey,
    pub name: String,
    pub introduced: Introduction,
    /// Entries after this sequence number do not count.
    pub cut: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustError {
    /// `Genesis`/`SelfJoin` anywhere but at sequence 1, or `Genesis` outside the root stream.
    Misplaced,
    WrongAccount,
    BadSignature,
    /// A device id endorsed with two different keys.
    KeyConflict(DeviceId),
}

impl fmt::Display for TrustError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustError::Misplaced => f.write_str("introduction entry out of place"),
            TrustError::WrongAccount => f.write_str("genesis of another account"),
            TrustError::BadSignature => f.write_str("endorsement signature does not verify"),
            TrustError::KeyConflict(d) => write!(
                f,
                "device {} endorsed with two keys",
                data_encoding::HEXLOWER.encode(&d[..4])
            ),
        }
    }
}

#[derive(Clone, Debug)]
struct Recorded {
    stream: DeviceId,
    seq: u64,
    entry: Entry,
}

#[derive(Clone, Debug)]
pub struct Trust {
    account_id: AccountId,
    root: DeviceId,
    recorded: Vec<Recorded>,
    devices: BTreeMap<DeviceId, DeviceInfo>,
}

type Known = BTreeMap<DeviceId, (VerifyingKey, String, Introduction)>;

impl Trust {
    pub fn new(account_id: AccountId, root: DeviceId) -> Trust {
        Trust {
            account_id,
            root,
            recorded: Vec::new(),
            devices: BTreeMap::new(),
        }
    }

    pub fn root(&self) -> DeviceId {
        self.root
    }

    pub fn devices(&self) -> &BTreeMap<DeviceId, DeviceInfo> {
        &self.devices
    }

    pub fn device(&self, device: &DeviceId) -> Option<&DeviceInfo> {
        self.devices.get(device)
    }

    pub fn key(&self, device: &DeviceId) -> Option<VerifyingKey> {
        self.devices.get(device).map(|d| d.key)
    }

    /// Checks and records a trust entry found at `(stream, seq)`, whose segment verified with
    /// `stream_key`. Other entries are ignored. Returns whether the derived state changed.
    pub fn record(
        &mut self,
        stream: DeviceId,
        stream_key: &VerifyingKey,
        seq: u64,
        entry: &Entry,
    ) -> Result<bool, TrustError> {
        match entry {
            Entry::Genesis {
                account_id, key, ..
            } => {
                if seq != 1 || stream != self.root || key != stream_key.as_bytes() {
                    return Err(TrustError::Misplaced);
                }
                if *account_id != self.account_id {
                    return Err(TrustError::WrongAccount);
                }
            }
            Entry::SelfJoin { key, sig, .. } => {
                if seq != 1 || key != stream_key.as_bytes() {
                    return Err(TrustError::Misplaced);
                }
                if !verify_endorsement(stream_key, &self.account_id, &stream, key, sig) {
                    return Err(TrustError::BadSignature);
                }
            }
            Entry::Endorse {
                device, key, sig, ..
            } => {
                if !verify_endorsement(stream_key, &self.account_id, device, key, sig) {
                    return Err(TrustError::BadSignature);
                }
                let conflicting = self.recorded.iter().any(|r| match &r.entry {
                    Entry::Endorse {
                        device: d, key: k, ..
                    } => d == device && k != key,
                    Entry::SelfJoin { key: k, .. } => r.stream == *device && k != key,
                    Entry::Genesis { key: k, .. } => r.stream == *device && k != key,
                    _ => false,
                });
                if conflicting {
                    return Err(TrustError::KeyConflict(*device));
                }
            }
            Entry::Revoke { .. } => {}
            Entry::Put(_) | Entry::Checkpoint(_) => return Ok(false),
        }
        if self
            .recorded
            .iter()
            .any(|r| r.stream == stream && r.seq == seq)
        {
            return Ok(false);
        }
        let at = self
            .recorded
            .partition_point(|r| (r.stream, r.seq) < (stream, seq));
        self.recorded.insert(
            at,
            Recorded {
                stream,
                seq,
                entry: entry.clone(),
            },
        );
        let derived = self.derive();
        let changed = derived != self.devices;
        self.devices = derived;
        Ok(changed)
    }

    /// Devices introduced through `SelfJoin`.
    pub fn self_joined(&self) -> impl Iterator<Item = (&DeviceId, &DeviceInfo)> {
        self.devices
            .iter()
            .filter(|(_, d)| d.introduced == Introduction::SelfJoined)
    }

    fn derive(&self) -> BTreeMap<DeviceId, DeviceInfo> {
        let no_cuts = BTreeMap::new();
        // Candidates: revocations by a device introduced without the revoked one (or by the
        // device itself), as (revoker, revoker's seq, target, cut).
        let candidates: Vec<(DeviceId, u64, DeviceId, u64)> = self
            .recorded
            .iter()
            .filter_map(|r| match &r.entry {
                Entry::Revoke {
                    device,
                    last_valid_seq,
                } if r.stream == *device
                    || self.closure(&no_cuts, Some(device)).contains_key(&r.stream) =>
                {
                    Some((r.stream, r.seq, *device, *last_valid_seq))
                }
                _ => None,
            })
            .collect();
        // A revocation written after its author was itself cut does not count, except when
        // that cut came from the device being revoked now (mutual revocations both apply).
        let cut_of = |device: &DeviceId, ignoring: &DeviceId| {
            candidates
                .iter()
                .filter(|(by, _, target, _)| target == device && by != ignoring)
                .map(|(_, _, _, cut)| *cut)
                .min()
        };
        let mut cuts: BTreeMap<DeviceId, u64> = BTreeMap::new();
        for (by, at, target, cut) in &candidates {
            if by == target || cut_of(by, target).is_none_or(|c| *at <= c) {
                let e = cuts.entry(*target).or_insert(*cut);
                *e = (*e).min(*cut);
            }
        }
        self.closure(&cuts, None)
            .into_iter()
            .map(|(id, (key, name, introduced))| {
                (
                    id,
                    DeviceInfo {
                        key,
                        name,
                        introduced,
                        cut: cuts.get(&id).copied(),
                    },
                )
            })
            .collect()
    }

    /// Devices introduced when `cuts` apply, leaving out `excluded` and everything that
    /// depends on it.
    fn closure(&self, cuts: &BTreeMap<DeviceId, u64>, excluded: Option<&DeviceId>) -> Known {
        let mut known = Known::new();
        for r in &self.recorded {
            if Some(&r.stream) == excluded {
                continue;
            }
            match &r.entry {
                Entry::Genesis { key, name, .. } => {
                    if let Ok(k) = VerifyingKey::from_bytes(key) {
                        known.insert(r.stream, (k, name.clone(), Introduction::Root));
                    }
                }
                Entry::SelfJoin { key, name, .. } => {
                    if let Ok(k) = VerifyingKey::from_bytes(key) {
                        known.entry(r.stream).or_insert((
                            k,
                            name.clone(),
                            Introduction::SelfJoined,
                        ));
                    }
                }
                _ => {}
            }
        }
        loop {
            let mut changed = false;
            for r in &self.recorded {
                let Entry::Endorse {
                    device, key, name, ..
                } = &r.entry
                else {
                    continue;
                };
                if Some(device) == excluded
                    || known.contains_key(device)
                    || !known.contains_key(&r.stream)
                    || cuts.get(&r.stream).is_some_and(|c| r.seq > *c)
                {
                    continue;
                }
                if let Ok(k) = VerifyingKey::from_bytes(key) {
                    known.insert(
                        *device,
                        (
                            k,
                            name.clone(),
                            Introduction::Endorsed {
                                by: r.stream,
                                at_seq: r.seq,
                            },
                        ),
                    );
                    changed = true;
                }
            }
            if !changed {
                return known;
            }
        }
    }
}

impl Admission for Trust {
    fn admits(&self, stream: &DeviceId, seq: u64) -> bool {
        self.devices
            .get(stream)
            .is_some_and(|d| d.cut.is_none_or(|c| seq <= c))
    }
}
```

- [ ] **Step 3: Run.** `cargo test -p keyorra-sync trust::` → 9 passed. (`mutual_revocations_both_apply_and_self_revocation_counts` and `a_revoked_device_cannot_revoke_others_after_its_cut` pin the revocation rule; `arrival_order_does_not_matter` its determinism.)

- [ ] **Step 4: Commit.**

```bash
git add crates/keyorra-sync/src/trust.rs crates/keyorra-sync/src/lib.rs
git commit -m "sync: trust: introduced devices and revocation cuts"
```

### Task 4: Stored heads, and transports that roll back or fork

**Files:** Modify `crates/keyorra-sync/src/transport.rs`, `crates/keyorra-sync/src/faults.rs`, `crates/keyorra-sync/src/engine/tests.rs` (two test transports).

- [ ] **Step 1: Failing tests.** In `transport.rs`, extend `stores_by_device_and_first_seq` after its `segments(&[9; 16], 0)` assertion with:

```rust
        assert_eq!(t.head(&a).unwrap(), Some(2));
        assert_eq!(t.head(&[9; 16]).unwrap(), None);
```

and add before `clones_share_storage`:

```rust
    #[test]
    fn a_deep_copy_does_not_share_storage() {
        let t = MemoryTransport::new();
        let u = t.deep_copy();
        t.append(&segment([1; 16], 1, 0)).unwrap();
        assert!(u.streams().unwrap().is_empty());
    }
```

In `faults.rs`, add before `appends_can_fail_before_or_after_landing`:

```rust
    #[test]
    fn rollback_hides_later_segments_and_lowers_the_head() {
        let r = Rollback {
            inner: store(5),
            stream: D,
            keep_through: 3,
        };
        assert_eq!(r.segments(&D, 0).unwrap().len(), 3);
        assert_eq!(r.head(&D).unwrap(), Some(3));
    }

    #[test]
    fn overlay_shows_one_stream_from_elsewhere() {
        let o = Overlay {
            base: MemoryTransport::new(),
            overlay: store(2),
            stream: D,
        };
        assert_eq!(o.streams().unwrap(), vec![D]);
        assert_eq!(o.segments(&D, 0).unwrap().len(), 2);
        assert_eq!(o.head(&D).unwrap(), Some(2));
    }
```

`cargo test -p keyorra-sync -- transport:: faults::` → does not compile (`head`, `deep_copy`, `Rollback`, `Overlay` missing).

- [ ] **Step 2: Implement.** In the `Transport` trait, after `append`:

```rust
    /// The highest `last_seq` stored for `stream` (from file names or server metadata, without
    /// reading segments): how a device notices that a stream went backwards (spec §4.5).
    fn head(&self, stream: &DeviceId) -> Result<Option<u64>>;
```
In `MemoryTransport`'s inherent impl, before `dump`:

```rust
    /// An independent copy of everything stored now (tests: one side of a fork).
    pub fn deep_copy(&self) -> MemoryTransport {
        MemoryTransport {
            streams: Arc::new(Mutex::new(self.streams.lock().unwrap().clone())),
        }
    }
```
and in `impl Transport for MemoryTransport`, before `append`:

```rust
    fn head(&self, stream: &DeviceId) -> Result<Option<u64>> {
        let streams = self.streams.lock().unwrap();
        Ok(streams
            .get(stream)
            .and_then(|segs| segs.values().next_back())
            .and_then(|b| SegmentHeader::parse(b).ok())
            .map(|h| h.last_seq))
    }
```
In `faults.rs`, in `impl<T: Transport> Transport for Faulty<T>`, before `append`:

```rust
    fn head(&self, stream: &DeviceId) -> Result<Option<u64>> {
        self.inner.head(stream)
    }
```
and before `#[cfg(test)]`:

```rust
/// A store that went back in time for one stream: segments after `keep_through` are gone
/// (a restored backup, a sync client that lost files). Appends still go through.
pub struct Rollback<T> {
    pub inner: T,
    pub stream: DeviceId,
    pub keep_through: u64,
}

impl<T: Transport> Transport for Rollback<T> {
    fn streams(&self) -> Result<Vec<DeviceId>> {
        self.inner.streams()
    }

    fn segments(&self, stream: &DeviceId, after_seq: u64) -> Result<Vec<Fetched<Vec<u8>>>> {
        let all = self.inner.segments(stream, after_seq)?;
        if *stream != self.stream {
            return Ok(all);
        }
        Ok(all
            .into_iter()
            .filter(|f| match f {
                Fetched::Ready(b) => crate::segment::SegmentHeader::parse(b)
                    .is_ok_and(|h| h.last_seq <= self.keep_through),
                _ => true,
            })
            .collect())
    }

    fn append(&self, segment: &[u8]) -> Result<AppendOutcome> {
        self.inner.append(segment)
    }

    fn head(&self, stream: &DeviceId) -> Result<Option<u64>> {
        let head = self.inner.head(stream)?;
        Ok(if *stream == self.stream {
            head.map(|h| h.min(self.keep_through)).filter(|h| *h > 0)
        } else {
            head
        })
    }
}

/// A store that shows one stream from another store: one side of a fork (two histories of
/// one device, e.g. a cloned Mac), as a store that keeps devices partitioned would.
pub struct Overlay<T, U> {
    pub base: T,
    pub overlay: U,
    pub stream: DeviceId,
}

impl<T: Transport, U: Transport> Transport for Overlay<T, U> {
    fn streams(&self) -> Result<Vec<DeviceId>> {
        let mut streams = self.base.streams()?;
        if !streams.contains(&self.stream) {
            streams.push(self.stream);
        }
        Ok(streams)
    }

    fn segments(&self, stream: &DeviceId, after_seq: u64) -> Result<Vec<Fetched<Vec<u8>>>> {
        if *stream == self.stream {
            self.overlay.segments(stream, after_seq)
        } else {
            self.base.segments(stream, after_seq)
        }
    }

    fn append(&self, segment: &[u8]) -> Result<AppendOutcome> {
        self.base.append(segment)
    }

    fn head(&self, stream: &DeviceId) -> Result<Option<u64>> {
        if *stream == self.stream {
            self.overlay.head(stream)
        } else {
            self.base.head(stream)
        }
    }
}
```
The engine's test transports (`Upto`, `BrokenStream` in `engine/tests.rs`) need the new method too; add to each impl:

```rust
    fn head(&self, stream: &DeviceId) -> Result<Option<u64>> {
        self.inner.head(stream)
    }
```

(That file is rewritten in Task 6; this keeps the crate compiling in between.)
- [ ] **Step 3: Run.** `cargo test -p keyorra-sync` → all pass.

- [ ] **Step 4: Commit.**

```bash
git add crates/keyorra-sync/src/transport.rs crates/keyorra-sync/src/faults.rs crates/keyorra-sync/src/engine/tests.rs
git commit -m "sync: stored stream heads; rollback and fork fault transports"
```

### Task 5: Fold: copies orphaned by a revocation are owed again

**Files:** Modify `crates/keyorra-sync/src/fold.rs`, `crates/keyorra-sync/src/engine.rs`, `crates/keyorra-sync/src/testkit.rs`.

- [ ] **Step 1: Failing test.** In `fold.rs`, add before `vault_deletion_is_undone_by_live_items`:

```rust
    #[test]
    fn a_copy_written_only_by_a_removed_device_is_owed_again() {
        struct CutB;
        impl Admission for CutB {
            fn admits(&self, stream: &DeviceId, seq: u64) -> bool {
                *stream != B || seq <= 1
            }
        }
        let mut f = Fold::default();
        f.accept(item(A, 1, &[(A, 1)], 5, json("a", &[])), &CutB)
            .unwrap();
        f.accept(item(B, 1, &[(B, 1)], 9, json("b", &[])), &CutB)
            .unwrap();
        let copy = f.view().resolutions[0].copies[0].clone();
        // B wrote the copy (of A's version) after its cut: it does not count.
        f.accept(
            Accepted {
                stream: B,
                seq: 2,
                kind: RecordKind::Item,
                record_id: copy.copy_id,
                vault_id: copy.vault_id,
                version: Version {
                    vector: [(B, 1)].into_iter().collect(),
                    hlc: 10,
                    author: B,
                },
                doc: Doc::Item(copy.payload.clone()),
            },
            &CutB,
        )
        .unwrap();
        let view = f.view();
        assert_eq!(view.orphan_copies.len(), 1);
        assert_eq!(view.orphan_copies[0].copy_id, copy.copy_id);
        assert!(view.owes_copies());
        // With B fully admitted the copy counts and nothing is owed for it.
        f.refold(&AdmitAll);
        assert!(f.view().orphan_copies.is_empty());
    }
```

`cargo test -p keyorra-sync fold::` → does not compile (`orphan_copies`, `owes_copies` missing).

- [ ] **Step 2: Implement.** In `struct View`, after `attachment_copies`, and at the top of `impl View`:

```rust
    /// Conflict copies whose only versions no longer count (written by a device that was
    /// revoked since), of a source version that still counts: written again by a device
    /// that may write, so the copied content does not disappear with the revocation.
    pub orphan_copies: Vec<PendingCopy>,
}

impl View {
    /// Whether conflict copies or their attachment records are still owed.
    pub fn owes_copies(&self) -> bool {
        !self.resolutions.is_empty()
            || !self.attachment_copies.is_empty()
            || !self.orphan_copies.is_empty()
    }
```
(the `impl View {` line is the existing one: `owes_copies` goes at its top). In `Fold::view`, before the loop over vault sets:

```rust
        for ((kind, id), versions) in &self.retained {
            if *kind != RecordKind::Item || self.sets.contains_key(&(*kind, *id)) {
                continue;
            }
            let orphan = versions.iter().find_map(|(a, _)| {
                let Doc::Item(p) = &a.doc else { return None };
                if !p.content_from.is_empty() {
                    return None;
                }
                let marker = crate::payload::conflict_marker(p)?;
                let source_counts = self
                    .retained
                    .get(&(RecordKind::Item, marker.of))?
                    .iter()
                    .any(|(s, admitted)| *admitted && s.hash() == marker.version);
                source_counts.then(|| PendingCopy {
                    copy_id: *id,
                    vault_id: a.vault_id,
                    payload: p.clone(),
                })
            });
            view.orphan_copies.extend(orphan);
        }
```
In `engine.rs` (A1b version), `materialize_passes` writes them: replace `if view.resolutions.is_empty() && view.attachment_copies.is_empty() { return Ok(true); }` with

```rust
            if !view.owes_copies() {
                return Ok(true);
            }
            for copy in view.orphan_copies {
                let doc = Doc::Item(copy.payload);
                self.write(RecordKind::Item, copy.copy_id, copy.vault_id, doc, wall_ms)?;
            }
```

and its final `Ok(view.resolutions.is_empty() && view.attachment_copies.is_empty())` with `Ok(!view.owes_copies())`. In `testkit.rs`, `assert_converged` asserts `!first.owes_copies()`. (Task 6 replaces both files; the full versions there contain these changes.)
- [ ] **Step 3: Run.** `cargo test -p keyorra-sync` → all pass.

- [ ] **Step 4: Commit.**

```bash
git add crates/keyorra-sync/src/fold.rs crates/keyorra-sync/src/engine.rs crates/keyorra-sync/src/testkit.rs
git commit -m "sync: copies orphaned by a revocation are owed again"
```

### Task 6: The engine on trusted streams

**Files:** Replace `crates/keyorra-sync/src/engine.rs`, `crates/keyorra-sync/src/engine/tests.rs`, `crates/keyorra-sync/src/testkit.rs`.

The A1b engine is restructured, so the files are given whole. Kept from A1b unchanged: the local item/vault/attachment writes, `vault_payload`, `item_in_state`, `materialize`/`materialize_passes` (with Task 5's change) and `settle_before_edit`. New: constructors `create_account` (writes `Genesis`) and `join`; `self_join`, `endorse`, `revoke`, `trust`, `can_write`, `alarm`, `clear_alarm`, `verifying_key`; `sync(transport, wall_ms)` without a directory; the log layer (`receive_stream`, `check_claims`, `check_own_claim`, `settle_claim`, `report_withheld`, `check_stored_head`), the apply layer (`apply_pending`, `apply`), checkpoints (`reserve_seq`, `checkpoint_if_stale`), and the own-head check in `push`. Removed: `Directory`, `StaticDirectory`, `set_admission`, `decode_segment`.

- [ ] **Step 1: Failing tests.** Replace `crates/keyorra-sync/src/testkit.rs` with:

```rust
//! A simulated set of devices sharing one transport, for the engine's tests and for the
//! transport plans that rerun them (spec §11, suites 3–5, 9).

use ed25519_dalek::SigningKey;
use keyorra_core::crypto::Key;
use rand::rngs::StdRng;
use rand::SeedableRng;
use uuid::Uuid;

use crate::engine::Engine;
use crate::error::Result;
use crate::faults::{Faults, Faulty};
use crate::fold::View;
use crate::transport::MemoryTransport;
use crate::DeviceId;

pub const ACCOUNT_ID: [u8; 16] = [0x10; 16];
pub const ACCOUNT_KEY: [u8; 32] = [0x30; 32];
/// 2026-09-21, a fixed start so runs repeat.
pub const START_MS: u64 = 1_790_000_000_000;

pub struct Cluster {
    pub store: MemoryTransport,
    pub links: Vec<Faulty<MemoryTransport>>,
    pub devices: Vec<Engine<StdRng>>,
    /// Wall clock of each device (they may disagree).
    pub clocks: Vec<u64>,
}

pub fn device_id(i: usize) -> DeviceId {
    [i as u8 + 1; 16]
}

pub fn signer(i: usize) -> SigningKey {
    SigningKey::from_bytes(&[0x40 + i as u8; 32])
}

pub fn device_name(i: usize) -> String {
    format!("Device {i}")
}

impl Cluster {
    /// Device 0 creates the account and approves every other device; all are in step.
    pub fn new(n: usize, seed: u64, faults: Faults) -> Cluster {
        let mut c = Cluster::unapproved(n, seed, faults);
        for i in 1..n {
            let key = c.devices[i].verifying_key();
            c.devices[0]
                .endorse(device_id(i), &key, &device_name(i), START_MS)
                .unwrap();
        }
        c.heal();
        for link in &c.links {
            link.set_faults(faults);
        }
        c
    }

    /// Device 0 creates the account; the others have joined but nobody approved them yet.
    pub fn unapproved(n: usize, seed: u64, faults: Faults) -> Cluster {
        let store = MemoryTransport::new();
        let mut devices = Vec::new();
        let mut links = Vec::new();
        for i in 0..n {
            let rng = StdRng::seed_from_u64(seed.wrapping_add(i as u64));
            let key = Key::from_bytes(ACCOUNT_KEY);
            devices.push(if i == 0 {
                Engine::create_account(
                    device_id(0),
                    signer(0),
                    &device_name(0),
                    ACCOUNT_ID,
                    key,
                    rng,
                    START_MS,
                )
            } else {
                Engine::join(
                    device_id(i),
                    signer(i),
                    &device_name(i),
                    ACCOUNT_ID,
                    key,
                    device_id(0),
                    rng,
                )
            });
            links.push(Faulty::new(
                store.clone(),
                faults,
                seed ^ (0x5eed + i as u64),
            ));
        }
        Cluster {
            store,
            links,
            devices,
            clocks: vec![START_MS; n],
        }
    }

    pub fn sync(&mut self, i: usize) -> Result<()> {
        self.devices[i].sync(&self.links[i], self.clocks[i])
    }

    /// Advances every wall clock.
    pub fn tick(&mut self, ms: u64) {
        for c in &mut self.clocks {
            *c += ms;
        }
    }

    /// Turns faults off and syncs everyone until nothing changes; returns the rounds needed.
    pub fn heal(&mut self) -> usize {
        for link in &self.links {
            link.set_faults(Faults::NONE);
        }
        let mut last: Vec<View> = Vec::new();
        for round in 1..=50 {
            for i in 0..self.devices.len() {
                self.sync(i).expect("no faults while healing");
            }
            self.tick(1_000);
            let views: Vec<View> = self.devices.iter().map(|d| d.view()).collect();
            if views == last && self.devices.iter().all(|d| d.is_idle()) {
                return round;
            }
            last = views;
        }
        panic!("devices did not settle within 50 rounds");
    }

    pub fn assert_converged(&self) {
        let first = self.devices[0].view();
        for (i, d) in self.devices.iter().enumerate().skip(1) {
            assert_eq!(d.view(), first, "device {i} differs from device 0");
        }
        if self.devices.iter().any(|d| d.can_write()) {
            assert!(!first.owes_copies(), "conflict copies left to materialise");
        }
    }

    /// A minimal item JSON, as the local store would write it.
    pub fn item_json(id: Uuid, title: &str, attachments: &[Uuid]) -> Vec<u8> {
        let atts: Vec<serde_json::Value> = attachments
            .iter()
            .map(|a| serde_json::json!({ "id": a.to_string(), "name": "file" }))
            .collect();
        serde_json::to_vec(&serde_json::json!({
            "id": id.to_string(),
            "title": title,
            "attachments": atts,
        }))
        .unwrap()
    }
}
```

Replace `crates/keyorra-sync/src/engine/tests.rs` with:

```rust
use uuid::Uuid;

use super::*;
use crate::entry::Entry;
use crate::envelope::Version;
use crate::faults::Faults;
use crate::faults::{Overlay, Rollback};
use crate::payload::conflict_marker;
use crate::testkit::{device_id, device_name, signer, Cluster, ACCOUNT_ID, ACCOUNT_KEY, START_MS};

const ITEM: Uuid = Uuid::from_bytes([0x60; 16]);

fn title(view: &View, id: Uuid) -> String {
    let p = view.items[&id].payload.as_ref().expect("item has content");
    let v: serde_json::Value = serde_json::from_slice(&p.item_json).unwrap();
    v["title"].as_str().unwrap().to_owned()
}

/// Two devices that share a vault with one item "base".
fn shared(n: usize) -> (Cluster, Uuid) {
    let mut c = Cluster::new(n, 1, Faults::NONE);
    let vault = c.devices[0].create_vault("Personal", START_MS).unwrap();
    let json = Cluster::item_json(ITEM, "base", &[]);
    c.devices[0]
        .save_item(vault, ITEM, &json, START_MS)
        .unwrap();
    c.heal();
    (c, vault)
}

#[test]
fn a_second_device_sees_what_the_first_wrote() {
    let (c, vault) = shared(2);
    let view = c.devices[1].view();
    assert_eq!(view.vaults[&vault].name, "Personal");
    assert_eq!(title(&view, ITEM), "base");
    c.assert_converged();
}

#[test]
fn concurrent_edits_converge_to_the_later_edit_plus_one_copy() {
    let (mut c, vault) = shared(2);
    c.devices[0]
        .save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "from A", &[]),
            c.clocks[0],
        )
        .unwrap();
    c.tick(5_000);
    c.devices[1]
        .save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "from B", &[]),
            c.clocks[1],
        )
        .unwrap();
    c.heal();
    c.assert_converged();
    let view = c.devices[0].view();
    assert_eq!(title(&view, ITEM), "from B");
    let copies = view.conflict_copies();
    assert_eq!(copies.len(), 1);
    assert_eq!(title(&view, copies[0]), "from A");
    let marker = conflict_marker(view.items[&copies[0]].payload.as_ref().unwrap()).unwrap();
    assert_eq!((marker.of, marker.from_device), (ITEM, device_id(0)));
}

#[test]
fn both_devices_resolving_at_once_still_make_one_copy() {
    let (mut c, vault) = shared(2);
    c.devices[0]
        .save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "A", &[]),
            c.clocks[0],
        )
        .unwrap();
    c.devices[1]
        .save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "B", &[]),
            c.clocks[1],
        )
        .unwrap();
    // Each pushes its edit, then each pulls the other's and resolves on its own.
    c.sync(0).unwrap();
    c.sync(1).unwrap();
    c.sync(0).unwrap();
    c.heal();
    c.assert_converged();
    assert_eq!(c.devices[0].view().conflict_copies().len(), 1);
}

#[test]
fn an_edit_beats_a_concurrent_delete() {
    let (mut c, vault) = shared(2);
    c.devices[0].trash_item(ITEM, 100, c.clocks[0]).unwrap();
    c.tick(1_000);
    c.devices[1]
        .save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "edited", &[]),
            c.clocks[1],
        )
        .unwrap();
    c.heal();
    c.assert_converged();
    let view = c.devices[0].view();
    assert_eq!(view.items[&ITEM].state, ItemState::Live);
    assert_eq!(title(&view, ITEM), "edited");
    assert!(view.conflict_copies().is_empty());
}

#[test]
fn a_concurrent_edit_beats_a_purge_and_keeps_its_id() {
    let (mut c, vault) = shared(2);
    c.devices[0].trash_item(ITEM, 100, c.clocks[0]).unwrap();
    c.heal();
    c.devices[0].purge_item(ITEM, c.clocks[0]).unwrap();
    c.devices[1].restore_item(ITEM, c.clocks[1]).unwrap();
    c.devices[1]
        .save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "still needed", &[]),
            c.clocks[1],
        )
        .unwrap();
    c.heal();
    c.assert_converged();
    let view = c.devices[0].view();
    assert_eq!(view.items[&ITEM].state, ItemState::Live);
    assert_eq!(title(&view, ITEM), "still needed");
    assert!(view.conflict_copies().is_empty());
}

#[test]
fn a_restore_beats_a_concurrent_purge() {
    let (mut c, _) = shared(2);
    c.devices[0].trash_item(ITEM, 100, c.clocks[0]).unwrap();
    c.heal();
    c.clocks[0] += 10_000; // the purge is the later write
    c.devices[0].purge_item(ITEM, c.clocks[0]).unwrap();
    c.devices[1].restore_item(ITEM, c.clocks[1]).unwrap();
    c.heal();
    c.assert_converged();
    let view = c.devices[0].view();
    assert_eq!(view.items[&ITEM].state, ItemState::Live);
    assert_eq!(title(&view, ITEM), "base");
}

/// Serves one stream only up to a sequence number.
struct Upto<'a> {
    inner: &'a crate::transport::MemoryTransport,
    stream: DeviceId,
    last_seq: u64,
}

impl Transport for Upto<'_> {
    fn streams(&self) -> Result<Vec<DeviceId>> {
        self.inner.streams()
    }
    fn segments(&self, stream: &DeviceId, after: u64) -> Result<Vec<Fetched<Vec<u8>>>> {
        let all = self.inner.segments(stream, after)?;
        if *stream != self.stream {
            return Ok(all);
        }
        Ok(all
            .into_iter()
            .filter(|f| match f {
                Fetched::Ready(b) => {
                    SegmentHeader::parse(b).is_ok_and(|h| h.last_seq <= self.last_seq)
                }
                _ => true,
            })
            .collect())
    }
    fn append(&self, segment: &[u8]) -> Result<AppendOutcome> {
        self.inner.append(segment)
    }
    fn head(&self, stream: &DeviceId) -> Result<Option<u64>> {
        self.inner.head(stream)
    }
}

#[test]
fn a_deleted_copy_stays_deleted_when_another_device_also_wrote_it() {
    let (mut c, vault) = shared(2);
    let (a, b) = (device_id(0), device_id(1));
    // Both edit and push without seeing each other.
    let json = |t: &str| Cluster::item_json(ITEM, t, &[]);
    c.devices[0]
        .save_item(vault, ITEM, &json("A"), c.clocks[0])
        .unwrap();
    c.devices[1]
        .save_item(vault, ITEM, &json("B"), c.clocks[1])
        .unwrap();
    let (a0, b0) = (c.devices[0].sent.seq, c.devices[1].sent.seq);
    let hide_b = Upto {
        inner: &c.store,
        stream: b,
        last_seq: b0,
    };
    c.devices[0].sync(&hide_b, c.clocks[0]).unwrap();
    let hide_a = Upto {
        inner: &c.store,
        stream: a,
        last_seq: a0,
    };
    c.devices[1].sync(&hide_a, c.clocks[1]).unwrap();
    let (a1, b1) = (c.devices[0].sent.seq, c.devices[1].sent.seq);
    // Each now sees the other's edit (and nothing else) and writes the same copy.
    let b_edit = Upto {
        inner: &c.store,
        stream: b,
        last_seq: b1,
    };
    c.devices[0].sync(&b_edit, c.clocks[0]).unwrap();
    let a_edit = Upto {
        inner: &c.store,
        stream: a,
        last_seq: a1,
    };
    c.devices[1].sync(&a_edit, c.clocks[1]).unwrap();
    let copy = c.devices[0].view().conflict_copies()[0];
    assert_eq!(c.devices[1].view().conflict_copies(), vec![copy]);
    // A deletes the copy for good; B's own copy must not bring it back.
    c.devices[0].trash_item(copy, 1, c.clocks[0]).unwrap();
    c.devices[0].purge_item(copy, c.clocks[0]).unwrap();
    c.heal();
    c.assert_converged();
    assert_eq!(c.devices[0].view().items[&copy].state, ItemState::Purged);
}

#[test]
fn deleting_a_vault_is_undone_by_a_concurrent_new_item() {
    let mut c = Cluster::new(2, 2, Faults::NONE);
    let vault = c.devices[0].create_vault("Work", START_MS).unwrap();
    c.heal();
    c.devices[0].delete_vault(vault, c.clocks[0]).unwrap();
    c.devices[1]
        .save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "new", &[]),
            c.clocks[1],
        )
        .unwrap();
    c.heal();
    c.assert_converged();
    let v = &c.devices[0].view().vaults[&vault];
    assert!(!v.deleted && v.revived);
}

#[test]
fn conflict_copies_get_their_own_attachment_records() {
    let (mut c, vault) = shared(2);
    let att = c.devices[0]
        .add_attachment(vault, ITEM, "scan.pdf", 10, c.clocks[0])
        .unwrap();
    c.devices[0]
        .save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "with scan", &[att]),
            c.clocks[0],
        )
        .unwrap();
    c.devices[1]
        .save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "later", &[]),
            c.clocks[1] + 1_000,
        )
        .unwrap();
    c.heal();
    c.assert_converged();
    let view = c.devices[1].view();
    let copy = view.conflict_copies()[0];
    let refs = crate::payload::attachment_refs(view.items[&copy].payload.as_ref().unwrap());
    assert_eq!(refs.len(), 1);
    assert_ne!(refs[0], att);
    assert_eq!(view.attachments[&refs[0]].item_id, copy);
    assert_eq!(view.attachments[&refs[0]].key, view.attachments[&att].key);
}

#[test]
fn items_wait_for_their_vault_key_from_another_stream() {
    // Device 2 (id [3;16]) reads stream [2;16] (device 1) before [1;16]? Streams are listed in
    // id order, so make device 1's write depend on device 0's vault: device 2 must read device
    // 0 first. Reverse the order by letting the higher id create the vault.
    let mut c = Cluster::new(3, 3, Faults::NONE);
    let vault = c.devices[1].create_vault("Shared", START_MS).unwrap();
    c.sync(1).unwrap();
    c.sync(0).unwrap();
    c.devices[0]
        .save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "x", &[]),
            c.clocks[0],
        )
        .unwrap();
    c.sync(0).unwrap();
    c.sync(2).unwrap();
    let events = c.devices[2].take_events();
    assert!(events
        .iter()
        .any(|e| matches!(e, Event::Waiting { from, .. } if *from == device_id(0))));
    assert_eq!(title(&c.devices[2].view(), ITEM), "x");
}

#[test]
fn a_clock_far_ahead_is_reported_and_not_adopted() {
    let (mut c, vault) = shared(2);
    c.clocks[1] += 60 * 60 * 1000;
    c.devices[1]
        .save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "future", &[]),
            c.clocks[1],
        )
        .unwrap();
    c.sync(1).unwrap();
    c.sync(0).unwrap();
    let events = c.devices[0].take_events();
    assert!(events
        .iter()
        .any(|e| matches!(e, Event::ClockAhead { ahead_ms, .. } if *ahead_ms > 3_000_000)));
    // Device 0's next write is not dragged an hour ahead.
    c.devices[0]
        .save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "now", &[]),
            c.clocks[0],
        )
        .unwrap();
    let set = c.devices[0].fold().set(RecordKind::Item, ITEM).unwrap();
    let own = set
        .siblings()
        .iter()
        .find(|s| s.version.author == device_id(0))
        .unwrap();
    assert!(crate::clock::physical_ms(own.version.hlc) < c.clocks[0] + 60_000);
}

#[test]
fn a_lost_append_outcome_is_retried_without_duplicating() {
    let (mut c, vault) = shared(2);
    c.links[0].set_faults(Faults {
        fail_after_append: 100,
        ..Faults::NONE
    });
    c.devices[0]
        .save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "once", &[]),
            c.clocks[0],
        )
        .unwrap();
    c.sync(0).unwrap();
    assert!(!c.devices[0].is_idle());
    let segments_before = c.store.dump().len();
    c.links[0].set_faults(Faults::NONE);
    c.sync(0).unwrap();
    assert!(c.devices[0].is_idle());
    assert_eq!(c.store.dump().len(), segments_before);
    c.heal();
    c.assert_converged();
}

#[test]
fn a_segment_breaking_the_rules_blocks_its_stream() {
    let (mut c, vault) = shared(2);
    // Device 1 signs a version that claims device 0 wrote it.
    let env = Envelope {
        kind: RecordKind::Item,
        record_id: ITEM,
        vault_id: Some(vault),
        schema: 1,
        version: Version {
            vector: [(device_id(0), 9)].into_iter().collect(),
            hlc: 1,
            author: device_id(0),
        },
        tombstone: true,
        body: None,
    };
    env.check().unwrap();
    let at = StreamPosition {
        device_id: device_id(1),
        first_seq: c.devices[1].sent.seq + 1,
        prev_hash: c.devices[1].sent.hash,
    };
    let k_seg = segment_key(&Key::from_bytes(ACCOUNT_KEY), &ACCOUNT_ID);
    let entry = Entry::Put(env).to_value();
    let mut rng = rand::rngs::OsRng;
    let seg = seal_segment(&k_seg, &signer(1), &at, vec![entry], &mut rng).unwrap();
    assert_eq!(c.store.append(&seg).unwrap(), AppendOutcome::Appended);
    c.sync(0).unwrap();
    let events = c.devices[0].take_events();
    assert!(events
        .iter()
        .any(|e| matches!(e, Event::Rejected { from, .. } if *from == device_id(1))));
    assert_eq!(title(&c.devices[0].view(), ITEM), "base");
}

#[test]
fn convergence_through_chaos_with_a_fixed_seed() {
    let mut c = Cluster::new(3, 7, Faults::CHAOS);
    let vault = c.devices[0].create_vault("Personal", START_MS).unwrap();
    for _ in 0..10 {
        for i in 0..3 {
            let _ = c.sync(i);
        }
    }
    let ids: Vec<Uuid> = (0..4u8).map(|n| Uuid::from_bytes([0x70 + n; 16])).collect();
    for step in 0..60usize {
        let d = step % 3;
        let id = ids[step % ids.len()];
        let json = Cluster::item_json(id, &format!("v{step}"), &[]);
        let _ = c.devices[d].save_item(vault, id, &json, c.clocks[d]);
        if step % 7 == 0 {
            let _ = c.devices[d].trash_item(id, step as u64, c.clocks[d]);
        }
        let _ = c.sync((step * 5) % 3);
        c.tick(700);
    }
    c.heal();
    c.assert_converged();
}

/// Lists everything, but listing one stream's segments fails.
struct BrokenStream<'a> {
    inner: &'a crate::transport::MemoryTransport,
    broken: DeviceId,
}

impl Transport for BrokenStream<'_> {
    fn streams(&self) -> Result<Vec<DeviceId>> {
        self.inner.streams()
    }
    fn segments(&self, stream: &DeviceId, after: u64) -> Result<Vec<Fetched<Vec<u8>>>> {
        if *stream == self.broken {
            return Err(Error::Transport("listing failed".into()));
        }
        self.inner.segments(stream, after)
    }
    fn append(&self, segment: &[u8]) -> Result<AppendOutcome> {
        self.inner.append(segment)
    }
    fn head(&self, stream: &DeviceId) -> Result<Option<u64>> {
        self.inner.head(stream)
    }
}

#[test]
fn a_failed_listing_does_not_let_the_next_edit_swallow_a_conflict() {
    // Review repro: A pulls B's concurrent edit, listing C's stream fails, A edits again.
    let (mut c, vault) = shared(3);
    let other = Uuid::from_bytes([0x61; 16]);
    c.devices[2]
        .save_item(
            vault,
            other,
            &Cluster::item_json(other, "c", &[]),
            c.clocks[2],
        )
        .unwrap();
    c.sync(2).unwrap();
    // B's edit is older, so A's "a" is shown and "b" is the side that needs a copy.
    c.devices[1]
        .save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "b", &[]),
            c.clocks[1],
        )
        .unwrap();
    c.clocks[0] += 5_000;
    c.devices[0]
        .save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "a", &[]),
            c.clocks[0],
        )
        .unwrap();
    c.sync(1).unwrap();
    let broken = BrokenStream {
        inner: &c.store,
        broken: device_id(2),
    };
    let _ = c.devices[0].sync(&broken, c.clocks[0]);
    c.devices[0]
        .save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "a2", &[]),
            c.clocks[0],
        )
        .unwrap();
    c.heal();
    c.assert_converged();
    let view = c.devices[0].view();
    let titles: Vec<String> = view.items.keys().map(|i| title(&view, *i)).collect();
    assert!(titles.contains(&"b".to_owned()), "{titles:?}");
}

#[test]
fn a_failed_listing_is_an_event_and_other_streams_are_still_read() {
    let (mut c, vault) = shared(3);
    c.devices[1]
        .save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "b", &[]),
            c.clocks[1],
        )
        .unwrap();
    c.sync(1).unwrap();
    let other = Uuid::from_bytes([0x61; 16]);
    c.devices[2]
        .save_item(
            vault,
            other,
            &Cluster::item_json(other, "c", &[]),
            c.clocks[2],
        )
        .unwrap();
    c.sync(2).unwrap();
    let broken = BrokenStream {
        inner: &c.store,
        broken: device_id(1),
    };
    c.devices[0].sync(&broken, c.clocks[0]).unwrap();
    let events = c.devices[0].take_events();
    assert!(events
        .iter()
        .any(|e| matches!(e, Event::ListingFailed { from, .. } if *from == device_id(1))));
    assert!(events
        .iter()
        .any(|e| matches!(e, Event::Pulled { from, .. } if *from == device_id(2))));
}

#[test]
fn a_vault_with_live_items_cannot_be_deleted_and_trashed_ones_are_purged_with_it() {
    let (mut c, vault) = shared(1);
    assert!(matches!(
        c.devices[0].delete_vault(vault, c.clocks[0]),
        Err(Error::Refused(_))
    ));
    c.devices[0].trash_item(ITEM, 1, c.clocks[0]).unwrap();
    c.devices[0].delete_vault(vault, c.clocks[0]).unwrap();
    let view = c.devices[0].view();
    assert!(view.vaults[&vault].deleted);
    assert_eq!(view.items[&ITEM].state, ItemState::Purged);
}

#[test]
fn stalls_and_clock_warnings_are_reported_once() {
    let (mut c, vault) = shared(2);
    c.clocks[1] += 60 * 60 * 1000;
    for n in 0..3 {
        let json = Cluster::item_json(ITEM, &format!("future {n}"), &[]);
        c.devices[1]
            .save_item(vault, ITEM, &json, c.clocks[1])
            .unwrap();
        c.sync(1).unwrap();
    }
    c.sync(0).unwrap();
    c.sync(0).unwrap();
    let events = c.devices[0].take_events();
    let ahead = events
        .iter()
        .filter(|e| matches!(e, Event::ClockAhead { .. }))
        .count();
    assert_eq!(ahead, 1);
    // A segment that keeps waiting is reported once, not on every round.
    let mut d = Cluster::new(3, 3, Faults::NONE);
    let shared_vault = d.devices[1].create_vault("Shared", START_MS).unwrap();
    d.sync(1).unwrap();
    d.sync(0).unwrap();
    d.devices[0]
        .save_item(
            shared_vault,
            ITEM,
            &Cluster::item_json(ITEM, "x", &[]),
            d.clocks[0],
        )
        .unwrap();
    d.sync(0).unwrap();
    let only_a = Upto {
        inner: &d.store,
        stream: device_id(1),
        last_seq: 0,
    };
    for _ in 0..3 {
        d.devices[2].sync(&only_a, d.clocks[2]).unwrap();
    }
    let waiting = d.devices[2]
        .take_events()
        .into_iter()
        .filter(|e| matches!(e, Event::Waiting { .. }))
        .count();
    assert_eq!(waiting, 1);
}

#[test]
fn after_an_own_stream_conflict_the_device_stops_pushing() {
    let (mut c, vault) = shared(1);
    // Another copy of this device (a restored backup) already wrote at its next position.
    let mut twin = clone_of(&c.devices[0]);
    twin.save_item(
        vault,
        ITEM,
        &Cluster::item_json(ITEM, "twin", &[]),
        c.clocks[0],
    )
    .unwrap();
    twin.push(&c.store);
    c.devices[0]
        .save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "me", &[]),
            c.clocks[0],
        )
        .unwrap();
    c.sync(0).unwrap();
    c.sync(0).unwrap();
    let events = c.devices[0].take_events();
    assert_eq!(
        events
            .iter()
            .filter(|e| **e == Event::OwnStreamConflict)
            .count(),
        1
    );
    assert!(!c.devices[0].is_idle());
}

/// A second engine with the same id, key and state: a cloned or restored Mac.
fn clone_of(e: &Engine<rand::rngs::StdRng>) -> Engine<rand::rngs::OsRng> {
    let i = (e.device[0] - 1) as usize;
    let mut twin = Engine::join(
        e.device,
        signer(i),
        &device_name(i),
        ACCOUNT_ID,
        Key::from_bytes(ACCOUNT_KEY),
        e.trust.root(),
        rand::rngs::OsRng,
    );
    twin.sent = e.sent;
    twin.own_ends = e.own_ends.clone();
    twin.next_seq = e.next_seq;
    twin.vault_keys = e.vault_keys.clone();
    twin.fold = e.fold.clone();
    twin.trust = e.trust.clone();
    twin.heads = e.heads.clone();
    twin.ends = e.ends.clone();
    twin.last_checkpoint = e.last_checkpoint.clone();
    twin
}

#[test]
fn a_removed_devices_later_changes_stop_counting_everywhere() {
    let (mut c, vault) = shared(3);
    c.devices[0].revoke(device_id(1), c.clocks[0]).unwrap();
    // Device 1 has not heard of it yet and keeps editing.
    c.devices[1]
        .save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "after the cut", &[]),
            c.clocks[1],
        )
        .unwrap();
    c.heal();
    c.assert_converged();
    for d in &c.devices {
        assert_eq!(title(&d.view(), ITEM), "base");
    }
    assert!(!c.devices[1].can_write());
    assert!(matches!(
        c.devices[1].save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "x", &[]),
            c.clocks[1]
        ),
        Err(Error::Refused(_))
    ));
}

#[test]
fn an_unapproved_device_reads_but_cannot_write() {
    let mut c = Cluster::unapproved(2, 4, Faults::NONE);
    let vault = c.devices[0].create_vault("Personal", START_MS).unwrap();
    c.devices[0]
        .save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "base", &[]),
            START_MS,
        )
        .unwrap();
    c.sync(0).unwrap();
    c.sync(1).unwrap();
    // The root's stream verifies with the key in its own Genesis.
    assert_eq!(title(&c.devices[1].view(), ITEM), "base");
    assert!(!c.devices[1].can_write());
    assert!(matches!(
        c.devices[1].save_item(vault, ITEM, &Cluster::item_json(ITEM, "x", &[]), START_MS),
        Err(Error::Refused(_))
    ));
    let key = c.devices[1].verifying_key();
    c.devices[0]
        .endorse(device_id(1), &key, &device_name(1), START_MS)
        .unwrap();
    c.heal();
    assert!(c.devices[1].can_write());
    c.devices[1]
        .save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "approved", &[]),
            c.clocks[1],
        )
        .unwrap();
    c.heal();
    c.assert_converged();
    assert_eq!(title(&c.devices[0].view(), ITEM), "approved");
}

#[test]
fn approval_can_come_from_any_approved_device() {
    let mut c = Cluster::unapproved(3, 5, Faults::NONE);
    let key1 = c.devices[1].verifying_key();
    c.devices[0]
        .endorse(device_id(1), &key1, &device_name(1), START_MS)
        .unwrap();
    c.heal();
    let key2 = c.devices[2].verifying_key();
    c.devices[1]
        .endorse(device_id(2), &key2, &device_name(2), c.clocks[1])
        .unwrap();
    c.heal();
    let info = c.devices[0].trust().device(&device_id(2)).unwrap().clone();
    assert_eq!(
        info.introduced,
        crate::trust::Introduction::Endorsed {
            by: device_id(1),
            at_seq: info_seq(&c, 1)
        }
    );
    assert!(c.devices[2].can_write());
}

/// The sequence number of device `i`'s last confirmed entry.
fn info_seq(c: &Cluster, i: usize) -> u64 {
    c.devices[i].sent.seq
}

#[test]
fn a_self_join_works_and_alarms_every_other_device() {
    let mut c = Cluster::unapproved(3, 6, Faults::NONE);
    let key1 = c.devices[1].verifying_key();
    c.devices[0]
        .endorse(device_id(1), &key1, &device_name(1), START_MS)
        .unwrap();
    c.heal();
    c.devices[2].self_join(c.clocks[2]).unwrap();
    assert!(c.devices[2].can_write());
    c.heal();
    for i in [0, 1] {
        let events = c.devices[i].take_events();
        let alarms: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, Event::SelfJoined { device, .. } if *device == device_id(2)))
            .collect();
        assert_eq!(alarms.len(), 1, "device {i}");
    }
    assert!(!c.devices[2]
        .take_events()
        .iter()
        .any(|e| matches!(e, Event::SelfJoined { .. })));
    // A self-join must be a stream's first entry.
    assert!(matches!(
        c.devices[2].self_join(c.clocks[2]),
        Err(Error::Refused(_))
    ));
}

#[test]
fn a_device_can_remove_itself() {
    let (mut c, vault) = shared(2);
    c.devices[1].revoke(device_id(1), c.clocks[1]).unwrap();
    assert!(!c.devices[1].can_write());
    c.heal();
    let cut = c.devices[0]
        .trust()
        .device(&device_id(1))
        .unwrap()
        .cut
        .unwrap();
    assert!(
        cut < info_seq(&c, 1),
        "the revocation itself is after the cut"
    );
    assert!(matches!(
        c.devices[1].save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "x", &[]),
            c.clocks[1]
        ),
        Err(Error::Refused(_))
    ));
}

#[test]
fn a_rolled_back_stream_pauses_syncing() {
    let (mut c, vault) = shared(2);
    c.devices[1]
        .save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "newer", &[]),
            c.clocks[1],
        )
        .unwrap();
    c.sync(1).unwrap();
    c.sync(0).unwrap();
    let received = c.devices[0].heads[&device_id(1)].seq;
    let restored_backup = Rollback {
        inner: c.store.clone(),
        stream: device_id(1),
        keep_through: received - 1,
    };
    let err = c.devices[0]
        .sync(&restored_backup, c.clocks[0])
        .unwrap_err();
    assert!(matches!(err, Error::Refused(_)));
    assert!(matches!(
        c.devices[0].alarm(),
        Some(Alarm::Rollback { stream, .. }) if *stream == device_id(1)
    ));
    // Paused until the user decides.
    assert!(matches!(
        c.devices[0].sync(&c.store, c.clocks[0]),
        Err(Error::Refused(_))
    ));
    c.devices[0].clear_alarm();
    c.devices[0].sync(&c.store, c.clocks[0]).unwrap();
}

#[test]
fn a_rollback_of_the_own_stream_is_noticed_before_writing() {
    let (mut c, vault) = shared(1);
    let sent = c.devices[0].sent.seq;
    let restored_backup = Rollback {
        inner: c.store.clone(),
        stream: device_id(0),
        keep_through: sent - 1,
    };
    c.devices[0]
        .save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "x", &[]),
            c.clocks[0],
        )
        .unwrap();
    let _ = c.devices[0].sync(&restored_backup, c.clocks[0]);
    assert!(matches!(
        c.devices[0].alarm(),
        Some(Alarm::Rollback { stream, .. }) if *stream == device_id(0)
    ));
}

#[test]
fn a_fork_is_detected_through_another_devices_checkpoint() {
    let (mut c, vault) = shared(3);
    // A clone of device 1 writes into a copy of the store that device 0 is shown.
    let side = c.store.deep_copy();
    let mut clone = clone_of(&c.devices[1]);
    clone
        .save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "clone", &[]),
            c.clocks[1],
        )
        .unwrap();
    clone.push(&side);
    c.devices[1]
        .save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "real", &[]),
            c.clocks[1],
        )
        .unwrap();
    c.sync(1).unwrap();
    let partitioned = Overlay {
        base: c.store.clone(),
        overlay: side,
        stream: device_id(1),
    };
    c.devices[0].sync(&partitioned, c.clocks[0]).unwrap();
    assert!(
        c.devices[0].alarm().is_none(),
        "one history alone looks fine"
    );
    // Device 2 sees the real history and says so in its next checkpoint.
    c.sync(2).unwrap();
    let other = Uuid::from_bytes([0x61; 16]);
    c.devices[2]
        .save_item(
            vault,
            other,
            &Cluster::item_json(other, "x", &[]),
            c.clocks[2],
        )
        .unwrap();
    c.sync(2).unwrap();
    let _ = c.devices[0].sync(&partitioned, c.clocks[0]);
    assert!(matches!(
        c.devices[0].alarm(),
        Some(Alarm::Fork { stream, .. }) if *stream == device_id(1)
    ));
}

#[test]
fn a_segment_that_does_not_continue_the_chain_is_a_fork() {
    let (mut c, vault) = shared(2);
    let side = c.store.deep_copy();
    let mut clone = clone_of(&c.devices[1]);
    clone
        .save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "clone", &[]),
            c.clocks[1],
        )
        .unwrap();
    clone.push(&side);
    // Device 0 first sees the clone's history...
    let partitioned = Overlay {
        base: c.store.clone(),
        overlay: side,
        stream: device_id(1),
    };
    c.devices[0].sync(&partitioned, c.clocks[0]).unwrap();
    // ...then the real device writes twice and device 0 is shown the real stream.
    for t in ["real 1", "real 2"] {
        c.devices[1]
            .save_item(vault, ITEM, &Cluster::item_json(ITEM, t, &[]), c.clocks[1])
            .unwrap();
        c.sync(1).unwrap();
    }
    let _ = c.devices[0].sync(&c.store, c.clocks[0]);
    assert!(matches!(c.devices[0].alarm(), Some(Alarm::Fork { .. })));
}

#[test]
fn withheld_changes_are_reported_after_a_day() {
    let (mut c, vault) = shared(3);
    c.devices[1]
        .save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "hidden", &[]),
            c.clocks[1],
        )
        .unwrap();
    c.sync(1).unwrap();
    let before = c.devices[0].heads[&device_id(1)].seq;
    // Device 2 receives it and writes; device 0 is never shown device 1's new segment.
    c.sync(2).unwrap();
    let other = Uuid::from_bytes([0x61; 16]);
    c.devices[2]
        .save_item(
            vault,
            other,
            &Cluster::item_json(other, "x", &[]),
            c.clocks[2],
        )
        .unwrap();
    c.sync(2).unwrap();
    let withholding = Upto {
        inner: &c.store,
        stream: device_id(1),
        last_seq: before,
    };
    c.devices[0].sync(&withholding, c.clocks[0]).unwrap();
    let count = |events: Vec<Event>| {
        events
            .iter()
            .filter(|e| matches!(e, Event::Withheld { from, .. } if *from == device_id(1)))
            .count()
    };
    assert_eq!(count(c.devices[0].take_events()), 0);
    c.clocks[0] += WITHHELD_AFTER_MS + 1;
    c.devices[0].sync(&withholding, c.clocks[0]).unwrap();
    c.devices[0].sync(&withholding, c.clocks[0]).unwrap();
    assert_eq!(count(c.devices[0].take_events()), 1);
    // Delivered at last: the claim is settled.
    c.devices[0].sync(&c.store, c.clocks[0]).unwrap();
    assert!(c.devices[0].claims.is_empty());
}

#[test]
fn a_waiting_record_does_not_hold_back_other_records_of_the_stream() {
    let (mut c, vault) = shared(3);
    // Device 2 creates a vault that device 0 is not shown yet.
    let hidden_vault = c.devices[2].create_vault("Later", c.clocks[2]).unwrap();
    c.sync(2).unwrap();
    let hidden_head = c.devices[0].heads[&device_id(2)].seq;
    c.sync(1).unwrap();
    let other = Uuid::from_bytes([0x61; 16]);
    // One segment of device 1: an item in the hidden vault, then an item in the shared one.
    c.devices[1]
        .save_item(
            hidden_vault,
            other,
            &Cluster::item_json(other, "waits", &[]),
            c.clocks[1],
        )
        .unwrap();
    c.devices[1]
        .save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "flows", &[]),
            c.clocks[1],
        )
        .unwrap();
    c.sync(1).unwrap();
    let hide_vault = Upto {
        inner: &c.store,
        stream: device_id(2),
        last_seq: hidden_head,
    };
    c.devices[0].sync(&hide_vault, c.clocks[0]).unwrap();
    let view = c.devices[0].view();
    assert_eq!(title(&view, ITEM), "flows");
    assert!(!view.items.contains_key(&other));
    c.devices[0].sync(&c.store, c.clocks[0]).unwrap();
    assert_eq!(title(&c.devices[0].view(), other), "waits");
}

#[test]
fn a_read_only_device_still_writes_checkpoints_now_and_then() {
    let (mut c, vault) = shared(2);
    let before = c.devices[1].sent.seq;
    for n in 0..3 {
        c.devices[0]
            .save_item(
                vault,
                ITEM,
                &Cluster::item_json(ITEM, &format!("v{n}"), &[]),
                c.clocks[0],
            )
            .unwrap();
        c.sync(0).unwrap();
        c.sync(1).unwrap();
    }
    assert_eq!(
        c.devices[1].sent.seq, before,
        "no checkpoint within the hour"
    );
    c.clocks[1] += CHECKPOINT_EVERY_MS;
    c.sync(1).unwrap();
    assert_eq!(c.devices[1].sent.seq, before + 1);
}
```

- [ ] **Step 2: Run, expect failure.** `cargo test -p keyorra-sync` → does not compile (`Engine::create_account`, `join`, `Alarm`, `Event::SelfJoined`, … missing).

- [ ] **Step 3: Implement.** Replace `crates/keyorra-sync/src/engine.rs` with:

```rust
//! The sync engine of one device (spec §4): local writes, reading every other device's
//! stream, applying what it carries, materialising conflict copies, and writing its own stream.
//!
//! Reading has two layers. The **log** layer receives segments strictly in order per stream:
//! signature (the key comes from [`Trust`], or from the stream's own first entry for the root
//! and for self-joined devices), chain continuity, checkpoint claims; a segment that does not
//! continue the known head is a fork. The **apply** layer then applies the received entries
//! with per-record buffering: an entry waits only for what it needs (the vault key of its
//! vault, earlier writes of other devices to the same record, earlier entries of its own
//! stream for the same record), so independent records keep flowing (causal delivery).
//!
//! Trust entries (`Genesis`, `SelfJoin`, `Endorse`, `Revoke`) feed [`Trust`], which is also
//! the fold's admission policy: a revocation's cut refolds the state.
//!
//! Rollback (a stream's stored head behind what this device already received) and forks (a
//! segment or a checkpoint that contradicts a received position) raise an [`Alarm`] and pause
//! syncing until the user decides. Checkpoint claims that stay unmet for a day raise
//! [`Event::Withheld`].
//!
//! Deliberate limitations, picked up later: clone detection and retiring the device id,
//! account headers, snapshots, restore after a rollback (plan A1c-2); a persisted outbox and
//! persisted sealed bytes (`OutboxStore` hook, plan A1d); the editor's base version (A3).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ed25519_dalek::{SigningKey, VerifyingKey};
use keyorra_core::crypto::{self, Key};
use keyorra_core::model::SCHEMA_VERSION;
use rand::{CryptoRng, RngCore};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::cbor::Value;
use crate::clock::{Hlc, Observed};
use crate::entry::{sign_endorsement, Entry, Head, Heads};
use crate::envelope::{Envelope, RecordKind};
use crate::error::{Error, Result};
use crate::fold::{Accepted, Admission, Fold, RecordKey, View};
use crate::keys::segment_key;
use crate::payload::{AttachmentPayload, Doc, ItemPayload, VaultPayload};
use crate::present::{present_item, present_vault, ItemState};
use crate::segment::{
    chain, chain_genesis, decrypt_segment, seal_segment, SegmentHeader, StreamPosition,
};
use crate::transport::{AppendOutcome, Fetched, Transport};
use crate::trust::Trust;
use crate::{AccountId, DeviceId};

/// Entries per segment; keeps segments well below the 4 MiB cap for ordinary records.
const MAX_ENTRIES_PER_SEGMENT: usize = 256;
/// A device that only reads still writes a checkpoint this often when its heads moved.
pub const CHECKPOINT_EVERY_MS: u64 = 60 * 60 * 1000;
/// Checkpoint claims unmet for this long are reported as withheld (spec §4.5).
pub const WITHHELD_AFTER_MS: u64 = 24 * 60 * 60 * 1000;

/// Something that pauses syncing until the user decides (spec §4.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Alarm {
    /// The store holds fewer segments of `stream` than this device already received.
    Rollback {
        stream: DeviceId,
        received: u64,
        stored: u64,
    },
    /// Two different histories of `stream` at `seq`: a segment that does not continue the
    /// received chain, or a checkpoint that disagrees with it.
    Fork { stream: DeviceId, seq: u64 },
}

impl fmt::Display for Alarm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let short = |d: &DeviceId| data_encoding::HEXLOWER.encode(&d[..4]);
        match self {
            Alarm::Rollback {
                stream,
                received,
                stored,
            } => write!(
                f,
                "changes of {} were rolled back: received up to {received}, stored up to {stored}",
                short(stream)
            ),
            Alarm::Fork { stream, seq } => {
                write!(f, "two different histories of {} at {seq}", short(stream))
            }
        }
    }
}

/// What happened, for the Sync log (spec §9.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Pulled {
        from: DeviceId,
        versions: usize,
    },
    Pushed {
        versions: usize,
    },
    PushFailed(String),
    /// A segment could not be read (half-synced, damaged); retried next round.
    Unreadable {
        from: DeviceId,
        first_seq: u64,
    },
    /// An entry waits for something (a vault key, earlier changes, a newer app).
    Waiting {
        from: DeviceId,
        first_seq: u64,
        reason: String,
    },
    /// Listing a stream's segments failed; the other streams are still read.
    ListingFailed {
        from: DeviceId,
        reason: String,
    },
    /// Conflict copies are still owed after materialising (or writing them failed); item
    /// edits are refused until a later round writes them. An alarm.
    MaterializeIncomplete(String),
    /// A signed entry broke the rules; the stream is no longer read. An alarm.
    Rejected {
        from: DeviceId,
        first_seq: u64,
        reason: String,
    },
    ClockAhead {
        from: DeviceId,
        ahead_ms: u64,
    },
    Resolved {
        record: Uuid,
        copies: usize,
    },
    /// A device joined with the Emergency Kit, approved by no other device (spec §4.3).
    SelfJoined {
        device: DeviceId,
        name: String,
    },
    /// Other devices claim changes of `from` up to `claimed_seq` that the store has not
    /// delivered for a day.
    Withheld {
        from: DeviceId,
        claimed_seq: u64,
    },
    /// Syncing paused.
    Alarm(Alarm),
    /// Someone else wrote at this device's next position (retiring the id: plan A1c-2).
    OwnStreamConflict,
}

struct Unsent {
    bytes: Vec<u8>,
    versions: usize,
    last_seq: u64,
    last_hash: [u8; 32],
}

/// A received entry that has not been applied yet.
#[derive(Clone, Debug)]
struct Pending {
    stream: DeviceId,
    seq: u64,
    entry: Entry,
}

/// Entries of one stream apply in order within a lane: per record for `Put`, all trust
/// entries together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lane {
    Record(RecordKey),
    Trust,
}

impl Pending {
    fn lane(&self) -> Lane {
        match &self.entry {
            Entry::Put(env) => Lane::Record((env.kind, env.record_id)),
            _ => Lane::Trust,
        }
    }
}

enum Applied {
    Done,
    Wait(String),
    Reject(String),
}

/// A checkpoint claim of a position not received yet.
#[derive(Clone, Copy, Debug)]
struct Claim {
    head: Head,
    since_ms: u64,
}

pub struct Engine<R> {
    device: DeviceId,
    signer: SigningKey,
    name: String,
    account_id: AccountId,
    account_key: Key,
    segment_key: Key,
    rng: R,
    hlc: Hlc,
    fold: Fold,
    trust: Trust,
    vault_keys: BTreeMap<Uuid, Key>,
    /// Per other device: the last received position.
    heads: Heads,
    /// Per other device: chain hash at the end of every received segment.
    ends: BTreeMap<DeviceId, BTreeMap<u64, [u8; 32]>>,
    /// Received entries waiting to be applied.
    pending: Vec<Pending>,
    claims: BTreeMap<DeviceId, Claim>,
    withheld_reported: BTreeSet<DeviceId>,
    blocked: BTreeSet<DeviceId>,
    /// Last own position confirmed by the transport.
    sent: Head,
    /// Chain hash at the end of every own segment confirmed by the transport.
    own_ends: BTreeMap<u64, [u8; 32]>,
    unsent: Option<Unsent>,
    outbox: Vec<Value>,
    next_seq: u64,
    /// Heads in the last checkpoint this device wrote, and when.
    last_checkpoint: Option<(Heads, u64)>,
    events: Vec<Event>,
    alarm: Option<Alarm>,
    /// Set after `OwnStreamConflict`: this device stops pushing (plan A1c-2 retires it).
    halted: bool,
    clock_reported: BTreeSet<DeviceId>,
    self_join_reported: BTreeSet<DeviceId>,
    /// The last stall reported per stream (`Waiting`/`Unreadable`), to report changes only.
    stalls: BTreeMap<DeviceId, Event>,
}

impl<R: RngCore + CryptoRng> Engine<R> {
    /// The first device of a new account: its stream starts with `Genesis`.
    pub fn create_account(
        device: DeviceId,
        signer: SigningKey,
        name: &str,
        account_id: AccountId,
        account_key: Key,
        rng: R,
        wall_ms: u64,
    ) -> Self {
        let mut engine = Self::join(device, signer, name, account_id, account_key, device, rng);
        let genesis = Entry::Genesis {
            account_id,
            key: engine.signer.verifying_key().to_bytes(),
            name: name.to_owned(),
        };
        engine
            .write_entry(genesis, wall_ms)
            .expect("the first entry of a new account");
        engine
    }

    /// A further device of an existing account (`root` comes from the account header). It
    /// reads what it can, and can write once another device endorses it or after
    /// [`self_join`](Self::self_join).
    pub fn join(
        device: DeviceId,
        signer: SigningKey,
        name: &str,
        account_id: AccountId,
        account_key: Key,
        root: DeviceId,
        rng: R,
    ) -> Self {
        Engine {
            device,
            signer,
            name: name.to_owned(),
            account_id,
            segment_key: segment_key(&account_key, &account_id),
            account_key,
            rng,
            hlc: Hlc::default(),
            fold: Fold::default(),
            trust: Trust::new(account_id, root),
            vault_keys: BTreeMap::new(),
            heads: Heads::new(),
            ends: BTreeMap::new(),
            pending: Vec::new(),
            claims: BTreeMap::new(),
            withheld_reported: BTreeSet::new(),
            blocked: BTreeSet::new(),
            sent: Head {
                seq: 0,
                hash: chain_genesis(&account_id, &device),
            },
            own_ends: BTreeMap::new(),
            unsent: None,
            outbox: Vec::new(),
            next_seq: 1,
            last_checkpoint: None,
            events: Vec::new(),
            alarm: None,
            halted: false,
            clock_reported: BTreeSet::new(),
            self_join_reported: BTreeSet::new(),
            stalls: BTreeMap::new(),
        }
    }

    pub fn device(&self) -> DeviceId {
        self.device
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signer.verifying_key()
    }

    pub fn view(&self) -> View {
        self.fold.view()
    }

    pub fn fold(&self) -> &Fold {
        &self.fold
    }

    pub fn trust(&self) -> &Trust {
        &self.trust
    }

    /// Nothing waiting to be pushed.
    pub fn is_idle(&self) -> bool {
        self.outbox.is_empty() && self.unsent.is_none()
    }

    pub fn take_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    /// Why syncing is paused, if it is.
    pub fn alarm(&self) -> Option<&Alarm> {
        self.alarm.as_ref()
    }

    /// The user looked at the alarm and chose to continue (A3; restoring is plan A1c-2).
    pub fn clear_alarm(&mut self) {
        self.alarm = None;
    }

    /// Whether this device's next entry would count (introduced and not revoked).
    pub fn can_write(&self) -> bool {
        self.trust.admits(&self.device, self.next_seq)
    }

    /// Reports a stall of `from`'s stream unless the same one was reported last.
    fn stall(&mut self, from: DeviceId, event: Event) {
        if self.stalls.get(&from) != Some(&event) {
            self.stalls.insert(from, event.clone());
            self.events.push(event);
        }
    }

    fn raise(&mut self, alarm: Alarm) {
        if self.alarm.is_none() {
            self.events.push(Event::Alarm(alarm.clone()));
            self.alarm = Some(alarm);
        }
    }

    // ---- trust ----

    /// Joins without approval, with the Emergency Kit: the stream's first entry is a
    /// `SelfJoin`, and every other device raises an alarm (spec §4.3).
    pub fn self_join(&mut self, wall_ms: u64) -> Result<()> {
        if self.next_seq != 1 {
            return Err(Error::Refused("self-join must be the first entry".into()));
        }
        let key = self.signer.verifying_key().to_bytes();
        let sig = sign_endorsement(&self.signer, &self.account_id, &self.device, &key);
        let entry = Entry::SelfJoin {
            key,
            name: self.name.clone(),
            sig,
        };
        self.write_entry(entry, wall_ms)
    }

    /// Approves another device (after the code comparison of spec §6.4).
    pub fn endorse(
        &mut self,
        device: DeviceId,
        key: &VerifyingKey,
        name: &str,
        wall_ms: u64,
    ) -> Result<()> {
        self.require_writable()?;
        let key = key.to_bytes();
        let sig = sign_endorsement(&self.signer, &self.account_id, &device, &key);
        let entry = Entry::Endorse {
            device,
            key,
            name: name.to_owned(),
            sig,
        };
        self.write_entry(entry, wall_ms)
    }

    /// Removes a device: its entries after the last position this device received stop
    /// counting everywhere. Revoking this device itself ends its participation.
    pub fn revoke(&mut self, device: DeviceId, wall_ms: u64) -> Result<()> {
        self.require_writable()?;
        let last_valid_seq = if device == self.device {
            self.next_seq - 1
        } else {
            self.heads.get(&device).map_or(0, |h| h.seq)
        };
        let entry = Entry::Revoke {
            device,
            last_valid_seq,
        };
        self.write_entry(entry, wall_ms)
    }

    fn require_writable(&self) -> Result<()> {
        if self.can_write() {
            Ok(())
        } else {
            Err(Error::Refused(
                "this device is not approved, or was removed".into(),
            ))
        }
    }

    // ---- local writes ----

    pub fn create_vault(&mut self, name: &str, wall_ms: u64) -> Result<Uuid> {
        let mut id = [0u8; 16];
        self.rng.fill_bytes(&mut id);
        let id = uuid::Builder::from_random_bytes(id).into_uuid();
        let mut raw = Zeroizing::new([0u8; 32]);
        self.rng.fill_bytes(&mut raw[..]);
        let key = Key::from_bytes(*raw);
        let wrapped_key = crypto::wrap_vault_key(&self.account_key, id, &key);
        self.vault_keys.insert(id, key);
        let doc = Doc::Vault(VaultPayload {
            name: name.to_owned(),
            wrapped_key,
            deleted: false,
        });
        self.write(RecordKind::Vault, id, None, doc, wall_ms)?;
        Ok(id)
    }

    pub fn rename_vault(&mut self, id: Uuid, name: &str, wall_ms: u64) -> Result<()> {
        let mut p = self.vault_payload(id)?;
        p.name = name.to_owned();
        self.write(RecordKind::Vault, id, None, Doc::Vault(p), wall_ms)
    }

    /// Deletes an empty vault (as the local store does): refused while it has live items;
    /// items of it in Recently Deleted are purged first.
    pub fn delete_vault(&mut self, id: Uuid, wall_ms: u64) -> Result<()> {
        self.settle_before_edit(wall_ms)?;
        let mut p = self.vault_payload(id)?;
        let view = self.fold.view();
        let in_vault = |state: ItemState| {
            view.items
                .iter()
                .filter(move |(_, v)| v.state == state && v.vault_id == Some(id))
                .map(|(item, _)| *item)
                .collect::<Vec<_>>()
        };
        let live = in_vault(ItemState::Live);
        if !live.is_empty() {
            return Err(Error::Refused(format!("vault has {} items", live.len())));
        }
        for item in in_vault(ItemState::Trashed) {
            self.write(RecordKind::Item, item, Some(id), Doc::Tombstone, wall_ms)?;
        }
        p.deleted = true;
        self.write(RecordKind::Vault, id, None, Doc::Vault(p), wall_ms)
    }

    /// Creates or edits an item (and makes it live again if it was trashed).
    pub fn save_item(
        &mut self,
        vault_id: Uuid,
        id: Uuid,
        item_json: &[u8],
        wall_ms: u64,
    ) -> Result<()> {
        self.settle_before_edit(wall_ms)?;
        let doc = Doc::Item(ItemPayload {
            item_json: Zeroizing::new(item_json.to_vec()),
            deleted_at: None,
            content_from: Default::default(), // this write: set by `write_with`
        });
        self.write_with(RecordKind::Item, id, Some(vault_id), doc, wall_ms, true)
    }

    pub fn trash_item(&mut self, id: Uuid, at_secs: u64, wall_ms: u64) -> Result<()> {
        self.settle_before_edit(wall_ms)?;
        let (vault_id, mut p) = self.item_in_state(id, ItemState::Live)?;
        p.deleted_at = Some(at_secs);
        self.write(RecordKind::Item, id, vault_id, Doc::Item(p), wall_ms)
    }

    pub fn restore_item(&mut self, id: Uuid, wall_ms: u64) -> Result<()> {
        self.settle_before_edit(wall_ms)?;
        let (vault_id, mut p) = self.item_in_state(id, ItemState::Trashed)?;
        p.deleted_at = None;
        self.write(RecordKind::Item, id, vault_id, Doc::Item(p), wall_ms)
    }

    /// Permanently deletes an item in Recently Deleted.
    pub fn purge_item(&mut self, id: Uuid, wall_ms: u64) -> Result<()> {
        self.settle_before_edit(wall_ms)?;
        let (vault_id, _) = self.item_in_state(id, ItemState::Trashed)?;
        self.write(RecordKind::Item, id, vault_id, Doc::Tombstone, wall_ms)
    }

    /// Adds an attachment record (its chunks are uploaded by the transports' plans).
    /// The caller also saves the item with the new reference.
    pub fn add_attachment(
        &mut self,
        vault_id: Uuid,
        item_id: Uuid,
        name: &str,
        size: u64,
        wall_ms: u64,
    ) -> Result<Uuid> {
        let mut id = [0u8; 16];
        self.rng.fill_bytes(&mut id);
        let id = uuid::Builder::from_random_bytes(id).into_uuid();
        let mut key = Zeroizing::new([0u8; 32]);
        self.rng.fill_bytes(&mut key[..]);
        let doc = Doc::Attachment(AttachmentPayload {
            item_id,
            name: name.to_owned(),
            size,
            key,
            chunk_size: crate::chunk::MAX_CHUNK as u32,
            chunks: Vec::new(),
        });
        self.write(RecordKind::Attachment, id, Some(vault_id), doc, wall_ms)?;
        Ok(id)
    }

    pub fn remove_attachment(&mut self, id: Uuid, wall_ms: u64) -> Result<()> {
        let vault_id = self
            .fold
            .set(RecordKind::Attachment, id)
            .and_then(|s| s.top())
            .and_then(|s| s.vault_id)
            .ok_or_else(|| Error::NotFound(format!("attachment {id}")))?;
        self.write(
            RecordKind::Attachment,
            id,
            Some(vault_id),
            Doc::Tombstone,
            wall_ms,
        )
    }

    fn vault_payload(&self, id: Uuid) -> Result<VaultPayload> {
        self.fold
            .set(RecordKind::Vault, id)
            .and_then(|s| present_vault(s, false))
            .map(|p| p.payload.clone())
            .ok_or_else(|| Error::NotFound(format!("vault {id}")))
    }

    fn item_in_state(&self, id: Uuid, want: ItemState) -> Result<(Option<Uuid>, ItemPayload)> {
        let set = self
            .fold
            .set(RecordKind::Item, id)
            .ok_or_else(|| Error::NotFound(format!("item {id}")))?;
        let p = present_item(id, set);
        match (p.state == want, p.visible) {
            (true, Some(v)) => match &v.doc {
                Doc::Item(payload) => {
                    let mut payload = payload.clone();
                    if payload.content_from.is_empty() {
                        // A copy as first written: its content originates in that version.
                        payload.content_from = v.version.vector.clone();
                    }
                    Ok((v.vault_id, payload))
                }
                _ => Err(Error::NotFound(format!("item {id} in state {want:?}"))),
            },
            _ => Err(Error::NotFound(format!("item {id} in state {want:?}"))),
        }
    }

    /// A write that keeps the payload's `content_from` (trash, restore, collapse, and copies
    /// as first written, whose empty `content_from` marks them; spec §3.5).
    fn write(
        &mut self,
        kind: RecordKind,
        id: Uuid,
        vault_id: Option<Uuid>,
        doc: Doc,
        wall_ms: u64,
    ) -> Result<()> {
        self.write_with(kind, id, vault_id, doc, wall_ms, false)
    }

    /// `edit`: the item's content changes here, so `content_from` becomes the new version.
    fn write_with(
        &mut self,
        kind: RecordKind,
        id: Uuid,
        vault_id: Option<Uuid>,
        doc: Doc,
        wall_ms: u64,
        edit: bool,
    ) -> Result<()> {
        self.require_writable()?;
        let hlc = self.hlc.tick(wall_ms);
        let version = self.fold.next_version(kind, id, self.device, hlc);
        let mut doc = doc;
        if let Doc::Item(p) = &mut doc {
            if edit {
                p.content_from = version.vector.clone();
            }
        }
        let mut envelope = Envelope {
            kind,
            record_id: id,
            vault_id,
            schema: SCHEMA_VERSION,
            version: version.clone(),
            tombstone: doc == Doc::Tombstone,
            body: None,
        };
        match &doc {
            Doc::Tombstone => {}
            Doc::Vault(_) => envelope.body = Some(doc.encode().to_vec()),
            Doc::Item(_) | Doc::Attachment(_) => {
                let vault = vault_id.ok_or_else(|| Error::NotFound("vault id".into()))?;
                let key = self
                    .vault_keys
                    .get(&vault)
                    .ok_or_else(|| Error::NotFound(format!("key of vault {vault}")))?;
                envelope.seal_body(key, &self.account_id, &doc.encode(), &mut self.rng);
            }
        }
        envelope.check()?;
        let seq = self.reserve_seq(wall_ms);
        let accepted = Accepted {
            stream: self.device,
            seq,
            kind,
            record_id: id,
            vault_id,
            version,
            doc,
        };
        self.fold
            .accept(accepted, &self.trust)
            .expect("a local write always follows the rules");
        self.queue(Entry::Put(envelope));
        Ok(())
    }

    /// Writes a trust entry (recorded at once) or a checkpoint.
    fn write_entry(&mut self, entry: Entry, wall_ms: u64) -> Result<()> {
        // `Genesis` and `SelfJoin` must be the stream's first entry: no checkpoint before them.
        let introduction = matches!(entry, Entry::Genesis { .. } | Entry::SelfJoin { .. });
        let seq = if introduction {
            self.next_seq
        } else {
            self.reserve_seq(wall_ms)
        };
        let key = self.signer.verifying_key();
        let changed = self
            .trust
            .record(self.device, &key, seq, &entry)
            .map_err(|e| Error::Refused(e.to_string()))?;
        if changed {
            self.fold.refold(&self.trust);
        }
        self.queue(entry);
        Ok(())
    }

    /// The sequence number of the next entry, after writing a checkpoint first if what this
    /// device has received changed since its last one: readers learn which heads the entries
    /// that follow were written against.
    fn reserve_seq(&mut self, wall_ms: u64) -> u64 {
        let due = self
            .last_checkpoint
            .as_ref()
            .is_none_or(|(heads, _)| *heads != self.heads);
        if due && !self.heads.is_empty() {
            self.last_checkpoint = Some((self.heads.clone(), wall_ms));
            self.queue(Entry::Checkpoint(self.heads.clone()));
        }
        self.next_seq
    }

    fn queue(&mut self, entry: Entry) {
        self.outbox.push(entry.to_value());
        self.next_seq += 1;
        debug_assert_eq!(
            self.next_seq,
            self.unsent.as_ref().map_or(self.sent.seq, |u| u.last_seq)
                + self.outbox.len() as u64
                + 1,
            "own sequence numbers out of step"
        );
    }

    // ---- sync ----

    /// One round: receive and apply everything readable, materialise conflict copies, push.
    /// Whatever was applied is always materialised and pushed, even if the transport failed
    /// part of the way (a failed stream listing is only an event); the error, if any, is
    /// returned afterwards. While an [`Alarm`] is raised, nothing happens.
    pub fn sync(&mut self, transport: &impl Transport, wall_ms: u64) -> Result<()> {
        if let Some(alarm) = &self.alarm {
            return Err(Error::Refused(format!("sync paused: {alarm}")));
        }
        let pulled = self.pull(transport, wall_ms);
        if self.alarm.is_none() {
            if self.can_write() {
                self.materialize(wall_ms)?;
                self.checkpoint_if_stale(wall_ms);
            }
            self.push(transport);
        }
        match &self.alarm {
            Some(alarm) => Err(Error::Refused(format!("sync paused: {alarm}"))),
            None => pulled,
        }
    }

    fn checkpoint_if_stale(&mut self, wall_ms: u64) {
        let stale = match &self.last_checkpoint {
            None => true,
            Some((heads, at)) => *heads != self.heads && wall_ms >= at + CHECKPOINT_EVERY_MS,
        };
        if stale && self.outbox.is_empty() && !self.heads.is_empty() {
            self.last_checkpoint = Some((self.heads.clone(), wall_ms));
            self.queue(Entry::Checkpoint(self.heads.clone()));
        }
    }

    fn pull(&mut self, transport: &impl Transport, wall_ms: u64) -> Result<()> {
        let streams: Vec<DeviceId> = transport
            .streams()?
            .into_iter()
            .filter(|d| *d != self.device && !self.blocked.contains(d))
            .collect();
        for stream in &streams {
            self.check_stored_head(transport, stream);
        }
        loop {
            let mut progress = false;
            for stream in &streams {
                if self.alarm.is_some() {
                    return Ok(());
                }
                match self.receive_stream(transport, stream, wall_ms) {
                    Ok(p) => progress |= p,
                    Err(e) => self.events.push(Event::ListingFailed {
                        from: *stream,
                        reason: e.to_string(),
                    }),
                }
            }
            progress |= self.apply_pending(wall_ms);
            if !progress || self.alarm.is_some() {
                break;
            }
        }
        self.report_withheld(wall_ms);
        Ok(())
    }

    /// Rollback: the store's head of a stream is behind what this device received.
    fn check_stored_head(&mut self, transport: &impl Transport, stream: &DeviceId) {
        let received = self.heads.get(stream).map_or(0, |h| h.seq);
        if received == 0 {
            return;
        }
        if let Ok(stored) = transport.head(stream) {
            let stored = stored.unwrap_or(0);
            if stored < received {
                self.raise(Alarm::Rollback {
                    stream: *stream,
                    received,
                    stored,
                });
            }
        }
    }

    /// Receives every segment of `stream` that continues its chain. Returns whether any was.
    fn receive_stream(
        &mut self,
        transport: &impl Transport,
        stream: &DeviceId,
        wall_ms: u64,
    ) -> Result<bool> {
        let mut head = self.heads.get(stream).copied().unwrap_or(Head {
            seq: 0,
            hash: chain_genesis(&self.account_id, stream),
        });
        let mut candidates: Vec<(u64, Vec<u8>)> = transport
            .segments(stream, head.seq)?
            .into_iter()
            .filter_map(|f| match f {
                Fetched::Ready(b) => Some(b),
                Fetched::Pending | Fetched::Missing => None,
            })
            .filter_map(|b| {
                let h = SegmentHeader::parse(&b).ok()?;
                (h.device_id == *stream && h.first_seq > head.seq).then_some((h.first_seq, b))
            })
            .collect();
        candidates.sort_by_key(|(seq, _)| *seq);
        let mut received = false;
        loop {
            let want = head.seq + 1;
            let mut opened = None;
            let mut tried = false;
            for (_, bytes) in candidates.iter().filter(|(s, _)| *s == want) {
                tried = true;
                let Ok(unverified) = decrypt_segment(&self.segment_key, bytes) else {
                    continue;
                };
                let key = self.trust.key(stream).or_else(|| {
                    // The root and self-joined devices carry their key in their first entry.
                    let first = unverified.entries.first()?;
                    let entry = Entry::from_value(first).ok()?;
                    let own = match &entry {
                        Entry::Genesis { .. } if *stream == self.trust.root() => entry.own_key(),
                        Entry::SelfJoin { .. } => entry.own_key(),
                        _ => None,
                    };
                    (want == 1).then_some(own).flatten()?;
                    VerifyingKey::from_bytes(&own?).ok()
                });
                let Some(key) = key else { continue };
                if let Ok(segment) = unverified.verify(&key) {
                    opened = Some((segment, key));
                    break;
                }
            }
            let Some((segment, key)) = opened else {
                if tried {
                    self.stall(
                        *stream,
                        Event::Unreadable {
                            from: *stream,
                            first_seq: want,
                        },
                    );
                }
                return Ok(received);
            };
            if segment.header.prev_hash != head.hash {
                self.raise(Alarm::Fork {
                    stream: *stream,
                    seq: want,
                });
                return Ok(received);
            }
            let mut entries = Vec::new();
            for (i, value) in segment.entries.iter().enumerate() {
                let seq = segment.header.first_seq + i as u64;
                match Entry::from_value(value) {
                    Ok(Entry::Put(env)) if env.version.author != *stream => {
                        self.reject(
                            stream,
                            seq,
                            "version author is not the stream's device".into(),
                        );
                        return Ok(received);
                    }
                    Ok(entry) => entries.push(Pending {
                        stream: *stream,
                        seq,
                        entry,
                    }),
                    Err(Error::Unsupported(what)) => {
                        self.stall(
                            *stream,
                            Event::Waiting {
                                from: *stream,
                                first_seq: seq,
                                reason: format!("needs a newer app: {what}"),
                            },
                        );
                        return Ok(received);
                    }
                    Err(e) => {
                        self.reject(stream, seq, e.to_string());
                        return Ok(received);
                    }
                }
            }
            for p in &entries {
                if let Entry::Checkpoint(heads) = &p.entry {
                    self.check_claims(heads, wall_ms);
                }
            }
            // Trust entries of a self-certified first segment are recorded right away, so the
            // rest of the stream can be verified.
            for p in &entries {
                if matches!(p.entry, Entry::Genesis { .. } | Entry::SelfJoin { .. }) {
                    if let Err(e) = self.trust.record(*stream, &key, p.seq, &p.entry) {
                        self.reject(stream, p.seq, e.to_string());
                        return Ok(received);
                    }
                    self.fold.refold(&self.trust);
                    self.report_self_joins();
                }
            }
            head = Head {
                seq: segment.header.last_seq,
                hash: segment.header.last_hash,
            };
            self.heads.insert(*stream, head);
            self.ends
                .entry(*stream)
                .or_default()
                .insert(head.seq, head.hash);
            self.settle_claim(stream);
            self.events.push(Event::Pulled {
                from: *stream,
                versions: entries.len(),
            });
            self.pending.extend(entries.into_iter().filter(|p| {
                !matches!(
                    p.entry,
                    Entry::Checkpoint(_) | Entry::Genesis { .. } | Entry::SelfJoin { .. }
                )
            }));
            self.stalls.remove(stream);
            received = true;
        }
    }

    /// Compares a checkpoint's heads with what this device knows: a different hash at a known
    /// position is a fork; a position not received yet becomes a claim.
    fn check_claims(&mut self, heads: &Heads, wall_ms: u64) {
        for (device, claimed) in heads {
            if *device == self.device {
                self.check_own_claim(claimed);
                continue;
            }
            let ends = self.ends.get(device);
            if let Some(hash) = ends.and_then(|e| e.get(&claimed.seq)) {
                if *hash != claimed.hash {
                    self.raise(Alarm::Fork {
                        stream: *device,
                        seq: claimed.seq,
                    });
                }
                continue;
            }
            let received = self.heads.get(device).map_or(0, |h| h.seq);
            if claimed.seq > received {
                let claim = self.claims.entry(*device).or_insert(Claim {
                    head: *claimed,
                    since_ms: wall_ms,
                });
                if claimed.seq > claim.head.seq {
                    claim.head = *claimed;
                }
            }
        }
    }

    /// Another device claims a position of this device's own stream.
    fn check_own_claim(&mut self, claimed: &Head) {
        if claimed.seq <= self.sent.seq {
            if self
                .own_ends
                .get(&claimed.seq)
                .is_some_and(|h| *h != claimed.hash)
            {
                self.raise(Alarm::Fork {
                    stream: self.device,
                    seq: claimed.seq,
                });
            }
            return;
        }
        // Beyond what the store confirmed: it may be the segment whose append outcome was
        // lost; anything else was written by another copy of this device.
        match &self.unsent {
            Some(u) if u.last_seq == claimed.seq && u.last_hash == claimed.hash => {
                self.sent = *claimed;
                self.own_ends.insert(claimed.seq, claimed.hash);
                self.unsent = None;
            }
            _ => self.raise(Alarm::Fork {
                stream: self.device,
                seq: claimed.seq,
            }),
        }
    }

    /// After receiving more of `stream`: a claim it reached is settled, or a fork.
    fn settle_claim(&mut self, stream: &DeviceId) {
        let Some(claim) = self.claims.get(stream).copied() else {
            return;
        };
        let received = self.heads.get(stream).map_or(0, |h| h.seq);
        if claim.head.seq > received {
            return;
        }
        self.claims.remove(stream);
        self.withheld_reported.remove(stream);
        if let Some(hash) = self.ends.get(stream).and_then(|e| e.get(&claim.head.seq)) {
            if *hash != claim.head.hash {
                self.raise(Alarm::Fork {
                    stream: *stream,
                    seq: claim.head.seq,
                });
            }
        }
    }

    fn report_withheld(&mut self, wall_ms: u64) {
        let overdue: Vec<(DeviceId, u64)> = self
            .claims
            .iter()
            .filter(|(d, c)| {
                wall_ms >= c.since_ms + WITHHELD_AFTER_MS && !self.withheld_reported.contains(*d)
            })
            .map(|(d, c)| (*d, c.head.seq))
            .collect();
        for (from, claimed_seq) in overdue {
            self.withheld_reported.insert(from);
            self.events.push(Event::Withheld { from, claimed_seq });
        }
    }

    /// Applies every pending entry whose needs are met, repeatedly. Returns whether any was.
    fn apply_pending(&mut self, wall_ms: u64) -> bool {
        let mut any = false;
        loop {
            let mut applied = false;
            let mut i = 0;
            while i < self.pending.len() {
                let p = self.pending[i].clone();
                let blocked_lane = self.blocked.contains(&p.stream)
                    || self.pending[..i]
                        .iter()
                        .any(|q| q.stream == p.stream && q.lane() == p.lane());
                if blocked_lane {
                    i += 1;
                    continue;
                }
                match self.apply(&p, wall_ms) {
                    Applied::Done => {
                        self.pending.remove(i);
                        applied = true;
                    }
                    Applied::Wait(reason) => {
                        self.stall(
                            p.stream,
                            Event::Waiting {
                                from: p.stream,
                                first_seq: p.seq,
                                reason,
                            },
                        );
                        i += 1;
                    }
                    Applied::Reject(reason) => {
                        self.reject(&p.stream, p.seq, reason);
                        i = 0;
                    }
                }
            }
            if !applied {
                return any;
            }
            any = true;
        }
    }

    fn apply(&mut self, p: &Pending, wall_ms: u64) -> Applied {
        let env = match &p.entry {
            Entry::Put(env) => env,
            entry => {
                let Some(key) = self.trust.key(&p.stream) else {
                    return Applied::Wait("device not introduced yet".into());
                };
                return match self.trust.record(p.stream, &key, p.seq, entry) {
                    Ok(changed) => {
                        if changed {
                            self.fold.refold(&self.trust);
                            self.report_self_joins();
                        }
                        Applied::Done
                    }
                    Err(e) => Applied::Reject(e.to_string()),
                };
            }
        };
        let mut new_key = None;
        let doc = if env.tombstone {
            Doc::Tombstone
        } else if env.kind == RecordKind::Vault {
            let body = env.body.as_deref().unwrap_or_default();
            let doc = match Doc::decode(RecordKind::Vault, body) {
                Ok(doc) => doc,
                Err(e) => return Applied::Reject(e.to_string()),
            };
            if let Doc::Vault(v) = &doc {
                match crypto::unwrap_vault_key(&self.account_key, env.record_id, &v.wrapped_key) {
                    Ok(key) => new_key = Some(key),
                    Err(_) => return Applied::Reject("vault key does not unwrap".into()),
                }
            }
            doc
        } else {
            let vault = env.vault_id.expect("checked by Envelope::from_value");
            let Some(key) = self.vault_keys.get(&vault) else {
                return Applied::Wait(format!("key of vault {vault} not known yet"));
            };
            let Ok(plain) = env.open_body(key, &self.account_id) else {
                return Applied::Reject("body does not open".into());
            };
            match Doc::decode(env.kind, &plain) {
                Ok(doc) => doc,
                Err(e) => return Applied::Reject(e.to_string()),
            }
        };
        let accepted = Accepted {
            stream: p.stream,
            seq: p.seq,
            kind: env.kind,
            record_id: env.record_id,
            vault_id: env.vault_id,
            version: env.version.clone(),
            doc,
        };
        match self
            .fold
            .missing_dependency(std::slice::from_ref(&accepted))
        {
            Err(rejection) => return Applied::Reject(rejection.to_string()),
            Ok(Some(device)) => {
                return Applied::Wait(format!(
                    "needs earlier changes from {}",
                    data_encoding::HEXLOWER.encode(&device[..4])
                ))
            }
            Ok(None) => {}
        }
        let hlc = accepted.version.hlc;
        if let Err(rejection) = self.fold.accept(accepted, &self.trust) {
            return Applied::Reject(rejection.to_string());
        }
        if let Some(key) = new_key {
            self.vault_keys.insert(env.record_id, key);
        }
        if let Observed::TooFarAhead { ahead_ms } = self.hlc.observe(hlc, wall_ms) {
            if self.clock_reported.insert(p.stream) {
                self.events.push(Event::ClockAhead {
                    from: p.stream,
                    ahead_ms,
                });
            }
        }
        Applied::Done
    }

    fn report_self_joins(&mut self) {
        let new: Vec<(DeviceId, String)> = self
            .trust
            .self_joined()
            .filter(|(d, _)| **d != self.device && !self.self_join_reported.contains(*d))
            .map(|(d, info)| (*d, info.name.clone()))
            .collect();
        for (device, name) in new {
            self.self_join_reported.insert(device);
            self.events.push(Event::SelfJoined { device, name });
        }
    }

    /// A rule-breaking entry: its stream is no longer read and its pending entries dropped.
    fn reject(&mut self, stream: &DeviceId, first_seq: u64, reason: String) {
        self.blocked.insert(*stream);
        self.pending.retain(|p| p.stream != *stream);
        self.events.push(Event::Rejected {
            from: *stream,
            first_seq,
            reason,
        });
    }

    /// Writes the conflict copies, and the attachment records they need, that the fold asks
    /// for (spec §3.5). Each pass removes what it wrote from the next view. If copies are still
    /// owed afterwards, or a write fails, `Event::MaterializeIncomplete` is raised and item
    /// edits are refused until a later round succeeds.
    fn materialize(&mut self, wall_ms: u64) -> Result<()> {
        let result = self.materialize_passes(wall_ms);
        match &result {
            Ok(true) => {}
            Ok(false) => self.events.push(Event::MaterializeIncomplete(
                "conflict copies still owed after materialising".into(),
            )),
            Err(e) => self
                .events
                .push(Event::MaterializeIncomplete(e.to_string())),
        }
        result.map(|_| ())
    }

    /// Returns whether nothing is owed any more.
    fn materialize_passes(&mut self, wall_ms: u64) -> Result<bool> {
        for _ in 0..4 {
            let view = self.fold.view();
            if !view.owes_copies() {
                return Ok(true);
            }
            for copy in view.orphan_copies {
                let doc = Doc::Item(copy.payload);
                self.write(RecordKind::Item, copy.copy_id, copy.vault_id, doc, wall_ms)?;
            }
            for r in view.resolutions {
                for copy in &r.copies {
                    let doc = Doc::Item(copy.payload.clone());
                    self.write(RecordKind::Item, copy.copy_id, copy.vault_id, doc, wall_ms)?;
                }
                self.write(
                    RecordKind::Item,
                    r.record_id,
                    r.vault_id,
                    r.collapse,
                    wall_ms,
                )?;
                self.events.push(Event::Resolved {
                    record: r.record_id,
                    copies: r.copies.len(),
                });
            }
            for a in view.attachment_copies {
                let doc = Doc::Attachment(a.payload);
                self.write(RecordKind::Attachment, a.id, a.vault_id, doc, wall_ms)?;
            }
        }
        let view = self.fold.view();
        Ok(!view.owes_copies())
    }

    /// Item edits first write any conflict copies the fold owes, so an edit can never
    /// collapse a conflict whose losing side has no copy yet; if that fails, the edit is
    /// refused.
    fn settle_before_edit(&mut self, wall_ms: u64) -> Result<()> {
        if self.materialize_passes(wall_ms)? {
            Ok(())
        } else {
            Err(Error::Refused(
                "conflict copies are still being written; try again".into(),
            ))
        }
    }

    fn push(&mut self, transport: &impl Transport) {
        if self.halted || (self.unsent.is_none() && self.outbox.is_empty()) {
            return;
        }
        // The store's head of this device's own stream must be where this device left it.
        if let Ok(stored) = transport.head(&self.device) {
            let stored = stored.unwrap_or(0);
            if stored < self.sent.seq {
                self.raise(Alarm::Rollback {
                    stream: self.device,
                    received: self.sent.seq,
                    stored,
                });
                return;
            }
            if stored > self.sent.seq && self.unsent.is_none() {
                self.halted = true;
                self.events.push(Event::OwnStreamConflict);
                return;
            }
        }
        loop {
            if self.unsent.is_none() {
                if self.outbox.is_empty() {
                    return;
                }
                let take = self.outbox.len().min(MAX_ENTRIES_PER_SEGMENT);
                let entries: Vec<Value> = self.outbox.drain(..take).collect();
                let at = StreamPosition {
                    device_id: self.device,
                    first_seq: self.sent.seq + 1,
                    prev_hash: self.sent.hash,
                };
                let last_hash = chain(&at.prev_hash, &entries);
                let versions = entries.len();
                let bytes =
                    seal_segment(&self.segment_key, &self.signer, &at, entries, &mut self.rng)
                        .expect("own entries fit a segment");
                self.unsent = Some(Unsent {
                    bytes,
                    versions,
                    last_seq: at.first_seq + versions as u64 - 1,
                    last_hash,
                });
            }
            let unsent = self.unsent.as_ref().expect("set above");
            match transport.append(&unsent.bytes) {
                Ok(AppendOutcome::Appended | AppendOutcome::AlreadyThere) => {
                    self.sent = Head {
                        seq: unsent.last_seq,
                        hash: unsent.last_hash,
                    };
                    self.own_ends.insert(unsent.last_seq, unsent.last_hash);
                    self.events.push(Event::Pushed {
                        versions: unsent.versions,
                    });
                    self.unsent = None;
                }
                Ok(AppendOutcome::Conflict) => {
                    // Someone else wrote at this device's next position: a clone or a
                    // restored copy of this device. Stop writing; plan A1c-2 retires the id.
                    self.halted = true;
                    self.events.push(Event::OwnStreamConflict);
                    return;
                }
                Err(e) => {
                    self.events.push(Event::PushFailed(e.to_string()));
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
```

- [ ] **Step 4: Run.** `cargo test -p keyorra-sync` → all pass (`engine::` filter: 31 tests). `cargo clippy -p keyorra-sync --all-targets -- -D warnings` and `--features test-utils` clean.

- [ ] **Step 5: Commit.**

```bash
git add crates/keyorra-sync/src/engine.rs crates/keyorra-sync/src/engine crates/keyorra-sync/src/testkit.rs
git commit -m "sync: engine on trusted streams: trust, per-record delivery, checkpoints, alarms"
```

### Task 7: Property tests with revocations

**Files:** Replace `crates/keyorra-sync/src/convergence_tests.rs`; `crates/keyorra-sync/proptest-regressions/convergence_tests.txt` (updated by proptest).

New: an `Op::Revoke { dev, target }` (self-revocation included); the no-lost-edit oracle counts only admitted edits as needing to stay visible, while any edit (admitted or not) may supersede an earlier one; purges count only when admitted; a new check that versions after a cut never reach a sibling set; the order-independence replay uses the device's trust as admission; both copy checks are skipped when copies are still owed because every device was removed. A fixed regression test pins the revocation race found while writing this plan.

- [ ] **Step 1: Write.** Replace `crates/keyorra-sync/src/convergence_tests.rs` with:

```rust
//! Property tests (spec §11, suite 6): random edits on several devices, delivered through a
//! misbehaving transport, always end in the same state everywhere, independent of order, and
//! concurrent edits are never silently dropped.

use std::collections::BTreeSet;

use proptest::prelude::*;
use uuid::Uuid;

use crate::envelope::RecordKind;
use crate::faults::Faults;
use crate::fold::{Admission, Fold, View};
use crate::payload::{attachment_refs, Doc};
use crate::present::{present_item, ItemState};
use crate::testkit::{Cluster, START_MS};

const ITEMS: usize = 4;

#[derive(Clone, Debug)]
enum Op {
    Save { dev: usize, item: usize },
    Trash { dev: usize, item: usize },
    Restore { dev: usize, item: usize },
    Purge { dev: usize, item: usize },
    Attach { dev: usize, item: usize },
    Detach { dev: usize, item: usize },
    RenameVault { dev: usize },
    DeleteVault { dev: usize },
    Revoke { dev: usize, target: usize },
    Sync { dev: usize },
    Tick { ms: u16 },
}

fn op(devices: usize) -> impl Strategy<Value = Op> {
    let d = 0..devices;
    let i = 0..ITEMS;
    prop_oneof![
        4 => (d.clone(), i.clone()).prop_map(|(dev, item)| Op::Save { dev, item }),
        2 => (d.clone(), i.clone()).prop_map(|(dev, item)| Op::Trash { dev, item }),
        1 => (d.clone(), i.clone()).prop_map(|(dev, item)| Op::Restore { dev, item }),
        3 => (d.clone(), i.clone()).prop_map(|(dev, item)| Op::Purge { dev, item }),
        1 => (d.clone(), i.clone()).prop_map(|(dev, item)| Op::Attach { dev, item }),
        1 => (d.clone(), i.clone()).prop_map(|(dev, item)| Op::Detach { dev, item }),
        1 => d.clone().prop_map(|dev| Op::RenameVault { dev }),
        1 => d.clone().prop_map(|dev| Op::DeleteVault { dev }),
        1 => (d.clone(), d.clone()).prop_map(|(dev, target)| Op::Revoke { dev, target }),
        5 => d.prop_map(|dev| Op::Sync { dev }),
        2 => (0u16..20_000).prop_map(|ms| Op::Tick { ms }),
    ]
}

fn item_id(i: usize) -> Uuid {
    Uuid::from_bytes([0x70 + i as u8; 16])
}

fn title_of(view: &View, id: Uuid) -> Option<String> {
    let p = view.items.get(&id)?.payload.as_ref()?;
    let v: serde_json::Value = serde_json::from_slice(&p.item_json).ok()?;
    Some(v["title"].as_str()?.to_owned())
}

/// Wall-clock offset of each device from the shared start, in ms (up to ±15 minutes, so
/// beyond the 5-minute bound the HLC refuses to adopt).
fn offsets() -> impl Strategy<Value = Vec<i64>> {
    prop::collection::vec(-900_000i64..900_000, 4)
}

/// Runs `ops` on a fresh cluster; every save writes a unique title. Returns the cluster and
/// the vault id. Operations that do not apply (trash a missing item, …) are skipped.
fn run(devices: usize, seed: u64, faults: Faults, ops: &[Op]) -> (Cluster, Uuid) {
    run_skewed(devices, seed, faults, ops, &[])
}

fn run_skewed(
    devices: usize,
    seed: u64,
    faults: Faults,
    ops: &[Op],
    offsets: &[i64],
) -> (Cluster, Uuid) {
    let mut c = Cluster::new(devices, seed, Faults::NONE);
    let vault = c.devices[0].create_vault("Personal", START_MS).unwrap();
    c.heal();
    for (clock, offset) in c.clocks.iter_mut().zip(offsets) {
        *clock = clock.saturating_add_signed(*offset);
    }
    for link in &c.links {
        link.set_faults(faults);
    }
    for (step, op) in ops.iter().enumerate() {
        match *op {
            Op::Save { dev, item } => {
                let id = item_id(item);
                let refs = c.devices[dev]
                    .view()
                    .items
                    .get(&id)
                    .and_then(|v| v.payload.as_ref().map(attachment_refs))
                    .unwrap_or_default();
                let json = Cluster::item_json(id, &format!("t{step}"), &refs);
                let _ = c.devices[dev].save_item(vault, id, &json, c.clocks[dev]);
            }
            Op::Trash { dev, item } => {
                let _ = c.devices[dev].trash_item(item_id(item), step as u64, c.clocks[dev]);
            }
            Op::Restore { dev, item } => {
                let _ = c.devices[dev].restore_item(item_id(item), c.clocks[dev]);
            }
            Op::Purge { dev, item } => {
                let _ = c.devices[dev].purge_item(item_id(item), c.clocks[dev]);
            }
            Op::Attach { dev, item } => {
                let id = item_id(item);
                let view = c.devices[dev].view();
                let Some(live) = view.items.get(&id).filter(|v| v.state == ItemState::Live) else {
                    continue;
                };
                let mut refs = attachment_refs(live.payload.as_ref().unwrap());
                let title = title_of(&view, id).unwrap_or_default();
                // Refused once this device is removed; skipped then.
                let Ok(att) = c.devices[dev].add_attachment(vault, id, "file", 1, c.clocks[dev])
                else {
                    continue;
                };
                refs.push(att);
                let json = Cluster::item_json(id, &title, &refs);
                let _ = c.devices[dev].save_item(vault, id, &json, c.clocks[dev]);
            }
            Op::Detach { dev, item } => {
                let id = item_id(item);
                let view = c.devices[dev].view();
                let Some(live) = view.items.get(&id).filter(|v| v.state == ItemState::Live) else {
                    continue;
                };
                let mut refs = attachment_refs(live.payload.as_ref().unwrap());
                let Some(att) = refs.pop() else { continue };
                let title = title_of(&view, id).unwrap_or_default();
                let _ = c.devices[dev].remove_attachment(att, c.clocks[dev]);
                let json = Cluster::item_json(id, &title, &refs);
                let _ = c.devices[dev].save_item(vault, id, &json, c.clocks[dev]);
            }
            Op::RenameVault { dev } => {
                let _ = c.devices[dev].rename_vault(vault, &format!("v{step}"), c.clocks[dev]);
            }
            Op::DeleteVault { dev } => {
                let _ = c.devices[dev].delete_vault(vault, c.clocks[dev]);
            }
            Op::Revoke { dev, target } => {
                let _ = c.devices[dev].revoke(crate::testkit::device_id(target), c.clocks[dev]);
            }
            Op::Sync { dev } => {
                let _ = c.sync(dev);
            }
            Op::Tick { ms } => c.tick(u64::from(ms)),
        }
    }
    c.heal();
    (c, vault)
}

/// Every non-stale sibling of every item is accounted for: shown, or present as a copy.
fn assert_nothing_unaccounted(fold: &Fold, view: &View) {
    if view.owes_copies() {
        return; // only when no device may write any more (all were removed)
    }
    for ((kind, id), set) in fold.sets() {
        if *kind != RecordKind::Item {
            continue;
        }
        let p = present_item(*id, set);
        for copy in &p.copies {
            assert!(
                view.items.contains_key(&copy.copy_id),
                "copy {} of {id} was never written",
                copy.copy_id
            );
        }
    }
}

proptest! {
    // 48 cases by default; `PROPTEST_CASES=20000 cargo test --release …` for a stress run.
    #![proptest_config(ProptestConfig {
        cases: std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(48),
        ..ProptestConfig::default()
    })]

    #[test]
    fn devices_converge_through_chaos(
        devices in 2usize..=4,
        seed in any::<u64>(),
        ops in prop::collection::vec(op(4), 1..60),
        skew in offsets(),
    ) {
        let ops: Vec<Op> = ops.into_iter().map(|o| clamp(o, devices)).collect();
        let (c, _) = run_skewed(devices, seed, Faults::CHAOS, &ops, &skew);
        c.assert_converged();
        for d in &c.devices {
            assert_nothing_unaccounted(d.fold(), &d.view());
            assert_no_lost_edit(d.fold(), &d.view(), d.trust());
            assert_cut_versions_hidden(d.fold(), d.trust());
        }
    }

    #[test]
    fn the_fold_does_not_depend_on_delivery_order(
        seed in any::<u64>(),
        ops in prop::collection::vec(op(3), 1..40),
        shuffle in any::<u64>(),
        skew in offsets(),
    ) {
        let (c, _) = run_skewed(3, seed, Faults::NONE, &ops, &skew);
        assert_no_lost_edit(c.devices[0].fold(), &c.devices[0].view(), c.devices[0].trust());
        let reference = c.devices[0].view();
        // Replay every accepted version, interleaving the streams pseudo-randomly while keeping
        // each stream's own order.
        let mut streams: Vec<Vec<_>> = Vec::new();
        for a in c.devices[0].fold().retained() {
            match streams.iter_mut().find(|s: &&mut Vec<crate::fold::Accepted>| s[0].stream == a.stream) {
                Some(s) => s.push(a.clone()),
                None => streams.push(vec![a.clone()]),
            }
        }
        for s in &mut streams {
            s.sort_by_key(|a| a.seq);
        }
        let mut fold = Fold::default();
        let mut state = shuffle;
        while streams.iter().any(|s| !s.is_empty()) {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            // Any stream whose next version's dependencies are applied (causal delivery).
            let ready: Vec<usize> = (0..streams.len())
                .filter(|i| {
                    streams[*i].first().is_some_and(|a| {
                        fold.missing_dependency(std::slice::from_ref(a)) == Ok(None)
                    })
                })
                .collect();
            prop_assert!(!ready.is_empty(), "no stream can make progress");
            let pick = ready[(state >> 33) as usize % ready.len()];
            let next = streams[pick].remove(0);
            fold.accept(next, c.devices[0].trust()).unwrap();
        }
        prop_assert_eq!(fold.view(), reference);
    }

    #[test]
    fn concurrent_edits_are_never_lost(
        seed in any::<u64>(),
        first in 0usize..2,
        gap in 0u64..120_000,
        chaos in any::<bool>(),
    ) {
        let faults = if chaos { Faults::CHAOS } else { Faults::NONE };
        let mut c = Cluster::new(2, seed, Faults::NONE);
        let vault = c.devices[0].create_vault("Personal", START_MS).unwrap();
        let id = item_id(0);
        c.devices[0].save_item(vault, id, &Cluster::item_json(id, "base", &[]), START_MS).unwrap();
        c.heal();
        for link in &c.links {
            link.set_faults(faults);
        }
        let second = 1 - first;
        c.devices[first].save_item(vault, id, &Cluster::item_json(id, "one", &[]), c.clocks[first]).unwrap();
        c.clocks[second] += gap;
        c.devices[second].save_item(vault, id, &Cluster::item_json(id, "two", &[]), c.clocks[second]).unwrap();
        for _ in 0..3 {
            let _ = c.sync(first);
            let _ = c.sync(second);
        }
        c.heal();
        c.assert_converged();
        let view = c.devices[0].view();
        let titles: BTreeSet<String> = view.items.keys().filter_map(|i| title_of(&view, *i)).collect();
        prop_assert!(titles.contains("one") && titles.contains("two"), "{:?}", titles);
        prop_assert_eq!(view.conflict_copies().len(), 1);
    }
}

fn clamp(op: Op, devices: usize) -> Op {
    let f = |d: usize| d % devices;
    match op {
        Op::Save { dev, item } => Op::Save { dev: f(dev), item },
        Op::Trash { dev, item } => Op::Trash { dev: f(dev), item },
        Op::Restore { dev, item } => Op::Restore { dev: f(dev), item },
        Op::Purge { dev, item } => Op::Purge { dev: f(dev), item },
        Op::Attach { dev, item } => Op::Attach { dev: f(dev), item },
        Op::Detach { dev, item } => Op::Detach { dev: f(dev), item },
        Op::RenameVault { dev } => Op::RenameVault { dev: f(dev) },
        Op::DeleteVault { dev } => Op::DeleteVault { dev: f(dev) },
        Op::Revoke { dev, target } => Op::Revoke {
            dev: f(dev),
            target: f(target),
        },
        Op::Sync { dev } => Op::Sync { dev: f(dev) },
        Op::Tick { ms } => Op::Tick { ms },
    }
}

#[test]
fn tombstones_and_vaults_survive_the_replay_too() {
    // A deterministic smoke run of `run` that exercises purge and vault deletion.
    let ops = vec![
        Op::Save { dev: 0, item: 0 },
        Op::Sync { dev: 0 },
        Op::Sync { dev: 1 },
        Op::Trash { dev: 1, item: 0 },
        Op::Purge { dev: 1, item: 0 },
        Op::Sync { dev: 1 },
        Op::Sync { dev: 0 },
        Op::DeleteVault { dev: 0 },
        Op::Save { dev: 1, item: 1 },
    ];
    let (c, vault) = run(2, 9, Faults::NONE, &ops);
    c.assert_converged();
    let view = c.devices[0].view();
    assert_eq!(view.items[&item_id(0)].state, ItemState::Purged);
    assert!(view.vaults[&vault].revived);
    let _ = Doc::Tombstone;
}

/// The review's oracle: on every item record that is not purged, every edit (a version whose
/// `content_from` is its own vector) that no other edit of the record dominates must still be
/// visible somewhere (as the item or as a conflict copy, live or in Recently Deleted).
/// Refinement: an edit that a purge has seen (a tombstone dominates it) was deleted on purpose,
/// even when a concurrent edit keeps the record itself alive.
/// Versions after a revocation's cut never reach a sibling set.
fn assert_cut_versions_hidden(fold: &Fold, admission: &dyn Admission) {
    for a in fold.retained() {
        if admission.admits(&a.stream, a.seq) {
            continue;
        }
        let hash = a.hash();
        let shown = fold
            .sets()
            .any(|(_, set)| set.siblings().iter().any(|s| s.hash == hash));
        assert!(
            !shown,
            "a version after its device's cut is in a sibling set"
        );
    }
}

/// Skipped while copies are still owed: when every device was removed, nobody can write them.
fn assert_no_lost_edit(fold: &Fold, view: &View, admission: &dyn Admission) {
    if view.owes_copies() {
        return;
    }
    let titles: BTreeSet<String> = view
        .items
        .keys()
        .filter_map(|i| title_of(view, *i))
        .collect();
    let mut records: Vec<Uuid> = fold
        .retained()
        .filter(|a| a.kind == RecordKind::Item)
        .map(|a| a.record_id)
        .collect();
    records.dedup();
    for record in records {
        if view
            .items
            .get(&record)
            .is_none_or(|v| v.state == ItemState::Purged)
        {
            continue;
        }
        // Every edit, admitted or not, can supersede an earlier one (its author replaced it);
        // only admitted edits must stay visible.
        let edits: Vec<_> = fold
            .retained()
            .filter(|a| a.kind == RecordKind::Item && a.record_id == record)
            .filter_map(|a| match &a.doc {
                Doc::Item(p) if p.content_from == a.version.vector => Some((a, p)),
                _ => None,
            })
            .collect();
        let purges: Vec<_> = fold
            .retained()
            .filter(|a| {
                a.kind == RecordKind::Item && a.record_id == record && a.doc == Doc::Tombstone
            })
            .filter(|a| admission.admits(&a.stream, a.seq))
            .collect();
        for (a, p) in &edits {
            if !admission.admits(&a.stream, a.seq) {
                continue;
            }
            let purged = purges.iter().any(|t| {
                crate::vv::compare(&a.version.vector, &t.version.vector)
                    == crate::vv::Causality::Before
            });
            if purged {
                continue;
            }
            let dominated = edits.iter().any(|(b, _)| {
                crate::vv::compare(&a.version.vector, &b.version.vector)
                    == crate::vv::Causality::Before
            });
            if dominated {
                continue;
            }
            let v: serde_json::Value = serde_json::from_slice(&p.item_json).unwrap();
            let title = v["title"].as_str().unwrap_or_default();
            assert!(
                titles.contains(title),
                "edit {title:?} of {record} was lost; visible: {titles:?}"
            );
        }
    }
}

#[test]
fn review_counterexample_stale_rule_loses_an_edit() {
    let ops = vec![
        Op::Sync { dev: 2 },
        Op::Save { dev: 0, item: 0 },
        Op::Sync { dev: 0 },
        Op::Save { dev: 2, item: 0 },
        Op::Sync { dev: 2 },
        Op::Sync { dev: 2 },
        Op::Save { dev: 1, item: 0 },
        Op::Sync { dev: 0 },
    ];
    for faults in [Faults::NONE, Faults::CHAOS] {
        let (c, _) = run(3, 16642519616933440452, faults, &ops);
        c.assert_converged();
        let view = c.devices[0].view();
        assert_no_lost_edit(c.devices[0].fold(), &view, c.devices[0].trust());
    }
}

#[test]
fn a_copy_written_by_a_device_removed_later_is_written_again() {
    // Found by the revocation property: device 2 wrote the copy of "t0" before anyone knew it
    // had been removed; the copy must not disappear with device 2's later changes.
    let ops = vec![
        Op::Save { dev: 1, item: 1 },
        Op::Sync { dev: 1 },
        Op::Revoke { dev: 1, target: 2 },
        Op::Save { dev: 2, item: 1 },
        Op::Sync { dev: 2 },
        Op::Sync { dev: 0 },
        Op::Trash { dev: 0, item: 1 },
    ];
    let (c, _) = run(3, 0, Faults::NONE, &ops);
    c.assert_converged();
    let view = c.devices[0].view();
    assert_no_lost_edit(c.devices[0].fold(), &view, c.devices[0].trust());
    let titles: BTreeSet<String> = view
        .items
        .keys()
        .filter_map(|i| title_of(&view, *i))
        .collect();
    assert!(titles.contains("t0"), "{titles:?}");
}
```

- [ ] **Step 2: Run.** `cargo test -p keyorra-sync convergence_tests` → 6 passed. To see the new regression test bite, temporarily replace `view.orphan_copies.extend(orphan);` in `fold.rs` with `let _ = orphan;`: `a_copy_written_by_a_device_removed_later_is_written_again` and `a_copy_written_only_by_a_removed_device_is_owed_again` fail. Revert.
- [ ] **Step 3: Stress.** `PROPTEST_CASES=20000 cargo test -p keyorra-sync --release convergence_tests` → green (about 30 s).

- [ ] **Step 4: Commit.**

```bash
git add crates/keyorra-sync/src/convergence_tests.rs crates/keyorra-sync/proptest-regressions
git commit -m "sync: property tests with revocations and an admission-aware oracle"
```

### Task 8: Protocol document

**Files:** Modify `docs/sync-protocol.md`.

- [ ] **Step 1: Status line and label.** The status sentence becomes:

```markdown
Version: 1 (draft). Status: sections 1–8 are defined and implemented in `crates/keyorra-sync`
(plan A1a), section 9 by plan A1b, section 10 by plan A1c-1 (headers, snapshots and clone
handling follow in plan A1c-2); later sections are placeholders filled by later plans.
```

Add to the §2 table after the `conflict-copy` row:

```markdown
| `keyorra/sync/v1/endorse` | endorsement and self-join statements |
```

- [ ] **Step 2: Section 10.** Replace "## 10. Streams, entries and trust" (up to "## 11. Folder transport") with:

````markdown
## 10. Streams, entries and trust

### 10.1 Entries

```
entry = { "put": Envelope }
      | { "checkpoint": { bytes16 → [seq, hash] } }
      | { "genesis": { "account_id": bytes16, "key": bytes32, "name": text } }
      | { "self_join": { "key": bytes32, "name": text, "sig": bytes64 } }
      | { "endorse": { "device": bytes16, "key": bytes32, "name": text, "sig": bytes64 } }
      | { "revoke": { "device": bytes16, "last_valid_seq": uint } }
statement = "keyorra/sync/v1/endorse\0" ‖ account_id ‖ device ‖ key
```

An entry is a map with exactly one key; an unknown key is "unsupported" (a newer app wrote
it: the stream waits, nothing is rejected). `endorse.sig` is the endorsing device's Ed25519
signature over the statement for the endorsed device; `self_join.sig` the joining device's
own signature over the statement for itself. `checkpoint` lists, for other streams, the
position (the last entry of a segment: sequence number and chain hash) that the writer had
received when it wrote the entries that follow. A writer adds a checkpoint before the first
entry it writes after what it has received changed, and a device that only reads writes one
at least every hour while its received positions change. `put.version.author` must be the
stream's device.

### 10.2 Trust

The account header names the **root** device. Trust is derived from all accepted `genesis`,
`self_join`, `endorse` and `revoke` entries, ordered by `(stream, seq)`, so it does not depend
on arrival order:

1. `genesis` is valid only as entry 1 of the root's stream, with this account's id and the
   key that signs the stream. `self_join` is valid only as entry 1 of its own stream, with
   the key that signs the stream and a valid signature. An `endorse` must verify with the key
   of the stream that carries it; a device id endorsed with two different keys is a
   rejection.
2. **Introduced devices**: the root (by `genesis`), self-joined devices, and, repeatedly, every
   device endorsed by an introduced device at a position not after that device's cut.
3. **Cuts**: a `revoke` counts if the revoker is the revoked device itself, or is introduced
   without the revoked device (step 2 with that device and everything only it introduced left
   out), and if its position is not after the revoker's own cut, where that cut ignores
   revocations made by the device being revoked now (so mutual revocations both apply). A
   device's cut is the smallest `last_valid_seq` among the revocations of it that count.
4. A stream position `(device, seq)` **counts** (is admitted) iff the device is introduced and
   `seq` is not after its cut. The fold (§9.4) builds sibling sets from admitted versions
   only and is rebuilt whenever trust changes.

A device that is not introduced yet can read but does not write. A device whose own cut is
set does not write any more. Other devices report a self-joined device once (an alarm).

### 10.3 Reading streams

A device keeps, per other stream, the last received position (initially `(0, chain_0)`)
and the chain hash at the end of every received segment. It receives the segment whose
`first_seq` is the next one, verified with the stream device's key from §10.2, or, for
entry 1 of the root's stream or of a self-joining stream, with the key in that entry. A
segment that does not open is retried later. A received segment whose `prev_hash` is not the
known hash is a **fork**. A `put` whose author is not the stream's device rejects the stream.

Received entries are then applied with per-record buffering: an entry waits only for what it
needs, and entries of one stream keep their order within their lane (per record for `put`,
one lane for trust entries):

- an item or attachment `put` waits for the key of its vault (from any stream's vault record);
- a `put` whose `vector[X]` (X ≠ author) exceeds X's highest applied counter for that record
  waits for X's earlier versions (§9.3);
- a trust entry waits until the stream's device is introduced.

Checkpoints are compared on receipt: a listed position that this device has received with a
different chain hash is a **fork**; a listed position of this device's own stream beyond what
the store confirmed is a fork, unless it is exactly the segment whose append outcome was lost
(then it counts as confirmed); a listed position not received yet is a **claim**, settled
when the position arrives (a different hash then is a fork). A claim unmet for 24 hours is
reported as withheld (a warning, not a pause).

**Rollback**: before reading, a device compares each stream's stored head (`Transport::head`)
with its own received position, and before writing, the stored head of its own stream with
its last confirmed position; a stored head behind is a rollback. A stored head of its own
stream ahead of its confirmed position means another copy of the device wrote there: the
device stops writing (clone handling: plan A1c-2).

A fork or a rollback pauses syncing until the user decides; the round reports it as an error.

### 10.4 Conflict copies after a revocation

A conflict copy whose versions were all written by a device that is no longer admitted, of a
source version that is still admitted, is written again (same content) by a device that may
write, so that the copied content does not disappear with the revocation (§9.6).
````

- [ ] **Step 3: Check against the code.** Entry field names and the trust rules match `entry.rs` and `trust.rs`; the reading rules match `Engine::receive_stream`, `apply`, `check_claims`, `check_stored_head` and `push`.

- [ ] **Step 4: Commit.**

```bash
git add docs/sync-protocol.md
git commit -m "docs: sync protocol section 10, streams and trust"
```

### Task 9: Final verification

- [ ] **Step 1: Everything green.**

```bash
cargo fmt --all -- --check
cargo clippy -p keyorra-core -p keyorra-session -p keyorra-sync --all-targets -- -D warnings
cargo clippy -p keyorra-sync --features test-utils -- -D warnings
cargo test --workspace
PROPTEST_CASES=20000 cargo test -p keyorra-sync --release convergence_tests
```

Expected: no diffs, no warnings, every `test result:` line `ok`; keyorra-sync: 173 passed, 1 ignored.
- [ ] **Step 2: No leftovers.** `grep -rn "Directory\|set_admission\|AdmitAll" crates/keyorra-sync/src` → matches only in `fold.rs` (`AdmitAll`, its definition and tests).
- [ ] **Step 3: Spec cross-check.** Every bullet of the A1c-1 row in spec §12 is covered (Tasks 1–8); nothing of A1c-2 (clone retirement, headers, snapshots, restore, outbox hooks) has been started.
- [ ] **Step 4: Wrap up.** If a step needed a fix, commit it as `sync: A1c-1 verification fixes`. Do not push.
