# Keyorra Sync A1b Implementation Plan (the fold)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn accepted record versions into the state the user sees, the same on every device: hybrid logical clocks, version vectors, plaintext payloads, per-record sibling sets, the presentation rules (visible winner, edit beats delete, purge is final, vault deletion undone by live items, deterministic conflict copies), version validation, the fold with a clean admission hook for A1c, a first engine that writes, pulls, materialises copies and pushes, an in-memory transport, a fault-injecting transport, and property tests for convergence.

**Architecture:** Everything lands in `crates/keyorra-sync` (pure: wall time and randomness are passed in). Layers, bottom up: `clock` (HLC) and `vv` (version vectors) → `payload` (what an opened body contains) → `siblings` (antichain per record) → `present` (pure presentation of one sibling set) → `fold` (all accepted versions, validation, admission, the `View`) → `transport` (trait + `MemoryTransport`) and `faults` (a misbehaving wrapper) → `engine` (one device) → `testkit` (a simulated cluster) and property tests. A1c replaces two seams: `engine::Directory` (whose signatures count) and `fold::Admission` (which stream positions count).

**Tech Stack:** as A1a, plus `serde_json` 1 as a normal dependency (item JSON handling), the `uuid` feature `v8`, and `proptest` 1 (dev, new in `Cargo.lock`).

**Spec:** `docs/superpowers/specs/2026-10-05-keyorra-sync-design.md` §3.3 (versions), §3.4 (sibling sets and the fold), §3.5 (presentation), §4.3–4.4 (only the parts without trust), §11 suites 2, 4, 5, 6, §12 (A1b). Revised in the same commit as this plan (see "Spec changes").

**Builds on:** A1a as hardened at `d5ca382` (sealing functions take an RNG; `Envelope::seal_body(…, rng)`; `seal_segment(…, rng)`).

## Decisions

- **Scope against the spec's A1b row.** In: versions/HLC, validation, payloads, sibling sets, presentation, conflict copies and their materialisation, the fold, a first engine, `MemoryTransport`, the fault-injecting transport (moved here from A1c: transient faults only), property tests. Out: the store migration, single change path and `Item.extra` move to a new plan **A1d** (store integration), because they are only testable once the engine writes into the store; entry types other than `Put`, endorsement, revocation cuts, causal delivery, headers, snapshots, rollback/fork faults stay in **A1c**.
- **Pure presentation.** `present_item`, `present_vault`, `present_attachment` are functions of one sibling set; the fold calls them. Nothing in the visible state depends on arrival order (property-tested).
- **`content_from` (spec change).** Comparing a trashed sibling's content with the concurrent edit, as the spec said, cannot tell a pure delete from an edit-then-delete: a pure delete carries the *old* content, which differs from the concurrent edit. Each item payload therefore records the version vector of the write that last changed its content. A sibling whose `content_from` another sibling has already seen is *stale* (a pure delete or restore) and never becomes a copy, and fresh siblings are preferred for display. This gives: edit beats delete, edit beats a pure restore, purge is final but concurrent *edits* survive as copies.
- **Conflict copies are byte-identical everywhere (spec change).** The stored title is not modified; the app renders "(conflict from <device name>)" from the `conflict` marker, because device names may differ between devices at the moment of writing. Copy ids derive from the copied sibling's own version hash.
- **Copies never wait for attachments (spec change).** A copy's attachment references get derived ids and keep `copied_from`; any device that knows the original attachment writes the copy's attachment record later. Without this, a copy whose attachment had not arrived would have to wait, and a user edit in the meantime would collapse the conflict without a copy.
- **Materialisation happens at the end of every pull**, before control returns to the user, so a user edit never collapses an unmaterialised conflict.
- **Item JSON is handled as `serde_json::Value`**, not as `keyorra-core`'s `Item`, so copies keep fields the local store does not know yet (A1d adds `Item.extra`).
- **Validation and atomicity.** A segment's versions are validated together (`Fold::accept_batch`) and applied all-or-nothing. A violation rejects the segment, blocks that stream and raises `Event::Rejected`; A1c decides what an alarm does beyond that.
- **Hooks for A1c.** `engine::Directory` (verifying key per device; `StaticDirectory` here) and `fold::Admission` (`AdmitAll` here). The fold retains every accepted version so `Fold::refold` can apply a revocation cut later; a test proves a cut resurfaces dominated versions.
- **Faults are transient.** The fault transport hides streams, reports `Pending`, omits, truncates, flips bits, duplicates and shuffles listings, and fails appends before or after they land, each with a seeded probability. Permanent damage, rollback and forks need the trust layer (A1c).
- **Plaintext in memory.** Payloads keep item JSON and attachment keys in `Zeroizing` buffers and redact them in `Debug`. The fold exists only while the vault is unlocked (spec decision 3); A1d persists retained versions encrypted.
- **Not done here:** chunk upload (attachment payloads in tests carry no chunk names), the Sync log persistence, any UI.

## Spec changes (same commit as this plan)

- §3.5: `content_from`, stale siblings, "best" = fresh before stale, then rank; copies keep their title, the app renders the suffix; copy attachment records via `copied_from`; materialisation by any device whose fold shows a missing copy.
- §12: A1b row updated; A1c row loses the fault transport (keeps rollback/fork faults); new row **A1d Store integration** (migration v2, single change path, `Item.extra` and the `conflict` field, engine ↔ store).

## Conventions for every task

- Test first: write the test, run it, see it fail for the expected reason, implement, see it pass, commit.
- English only. Every commit message ends with these two lines (omitted below; always add them):

```
Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_016B8vpfBkT1rhCY8NF4kPbd
```

- Rust from the repo root. After each task: `cargo fmt --all`; `cargo clippy -p keyorra-sync --all-targets -- -D warnings` clean.
- Tests use fixed bytes and seeded generators (`StdRng::seed_from_u64`, the fault transport's own SplitMix64), so failures replay. proptest prints the minimal failing case; keep it as a regular test when fixing.
- Shell: an `rtk` proxy may filter output; `rtk proxy <cmd>` runs it raw. Plain `grep` with a glob through the proxy can miss matches; use `grep -rn <dir>`.
- Work on `feat/sync-design` (or a branch from it); do not push.

## File map

```
crates/keyorra-sync/Cargo.toml              serde_json → dependencies, uuid feature v8, feature test-utils, dev proptest
Cargo.lock                                  + proptest and its dependencies
crates/keyorra-sync/src/labels.rs           + CONFLICT_COPY
crates/keyorra-sync/src/error.rs            + NotFound, Transport
crates/keyorra-sync/src/lib.rs              new modules
crates/keyorra-sync/src/clock.rs            NEW hybrid logical clock
crates/keyorra-sync/src/vv.rs               NEW version vectors
crates/keyorra-sync/src/payload.rs          NEW item/vault/attachment payloads, content equality, copy JSON
crates/keyorra-sync/src/siblings.rs         NEW sibling sets
crates/keyorra-sync/src/present.rs          NEW presentation, conflict-copy ids
crates/keyorra-sync/src/fold.rs             NEW fold, validation, admission hook, View, resolutions
crates/keyorra-sync/src/transport.rs        NEW Transport trait, MemoryTransport
crates/keyorra-sync/src/faults.rs           NEW fault-injecting transport (test-utils)
crates/keyorra-sync/src/engine.rs           NEW one device: writes, pull, materialise, push
crates/keyorra-sync/src/engine/tests.rs     NEW engine scenarios
crates/keyorra-sync/src/testkit.rs          NEW simulated cluster (test-utils)
crates/keyorra-sync/src/convergence_tests.rs NEW property tests
docs/sync-protocol.md                       §2 label, §9 written, §10 stream reading (A1b part)
docs/superpowers/specs/2026-10-05-keyorra-sync-design.md   §3.5, §12 (with this plan)
```

---

### Task 1: Dependencies, the conflict-copy label, two error kinds

**Files:** Modify `crates/keyorra-sync/Cargo.toml`, `Cargo.lock`, `crates/keyorra-sync/src/labels.rs`, `crates/keyorra-sync/src/error.rs`.

- [ ] **Step 1: Failing test.** The existing `labels_are_distinct_versioned_and_nul_free` test iterates `ALL`; add the new label to `ALL` first (after `CHAIN`):

```rust
    CONFLICT_COPY,
```

`cargo test -p keyorra-sync labels::` → does not compile (`CONFLICT_COPY` not found).

- [ ] **Step 2: Implement.** In `labels.rs`, after `CHAIN`:

```rust
pub const CONFLICT_COPY: &[u8] = b"keyorra/sync/v1/conflict-copy";
```

In `error.rs`, before the `Core` variant:

```rust
    /// A record the caller named does not exist (or is not in the needed state).
    #[error("not found: {0}")]
    NotFound(String),
    /// The folder or server could not be reached or refused the operation; retried later.
    #[error("transport: {0}")]
    Transport(String),
```

In `crates/keyorra-sync/Cargo.toml`, the sections from `[dependencies]` on become:

```toml
[dependencies]
data-encoding = "2"
ed25519-dalek = { version = "2", features = ["zeroize"] }
hkdf = "0.12"
keyorra-core = { path = "../keyorra-core" }
rand = "0.8"
serde_json = "1"
sha2 = "0.10"
thiserror = "2"
uuid = { version = "1", features = ["v8"] }
zeroize = "1"

[features]
# Exposes the fault-injecting transport and the simulated cluster to other crates' tests.
test-utils = []

[dev-dependencies]
keyorra-core = { path = "../keyorra-core", features = ["test-utils"] }
proptest = "1"
```

- [ ] **Step 3: Run.** `cargo test -p keyorra-sync` → all A1a tests pass (`Cargo.lock` gains `proptest` and its dependencies); clippy clean.

- [ ] **Step 4: Commit.**

```bash
git add crates/keyorra-sync/Cargo.toml Cargo.lock crates/keyorra-sync/src/labels.rs crates/keyorra-sync/src/error.rs
git commit -m "sync: A1b dependencies, conflict-copy label, NotFound and Transport errors"
```

### Task 2: Hybrid logical clock

**Files:** Create `crates/keyorra-sync/src/clock.rs`; modify `crates/keyorra-sync/src/lib.rs`.

The clock behind every version's `hlc` (spec §3.3), including the rule that a remote clock more than 5 minutes ahead is not adopted.

- [ ] **Step 1: Failing tests.** Add `pub mod clock;` to `lib.rs` (keep the module lines sorted) and create `crates/keyorra-sync/src/clock.rs` with only the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const T: u64 = 1_790_000_000_000;

    #[test]
    fn tick_follows_wall_time() {
        let mut c = Hlc::default();
        assert_eq!(c.tick(T), pack(T, 0));
        assert_eq!(c.tick(T + 5), pack(T + 5, 0));
    }

    #[test]
    fn tick_never_goes_back_when_the_clock_does() {
        let mut c = Hlc::default();
        let a = c.tick(T);
        let b = c.tick(T);
        let d = c.tick(T - 60_000);
        assert!(a < b && b < d);
        assert_eq!(b, pack(T, 1));
        assert_eq!(physical_ms(d), T);
    }

    #[test]
    fn observe_moves_the_clock_forward() {
        let mut c = Hlc::default();
        c.tick(T);
        assert_eq!(c.observe(pack(T + 1_000, 7), T), Observed::Adopted);
        assert_eq!(c.tick(T), pack(T + 1_000, 8));
    }

    #[test]
    fn observe_refuses_timestamps_too_far_ahead() {
        let mut c = Hlc::default();
        c.tick(T);
        let before = c.last();
        let ahead = pack(T + MAX_AHEAD_MS + 1, 0);
        assert_eq!(
            c.observe(ahead, T),
            Observed::TooFarAhead {
                ahead_ms: MAX_AHEAD_MS + 1
            }
        );
        assert_eq!(c.last(), before);
        assert_eq!(c.observe(pack(T + MAX_AHEAD_MS, 0), T), Observed::Adopted);
    }

    #[test]
    fn observe_ignores_the_past() {
        let mut c = Hlc::default();
        c.tick(T);
        assert_eq!(c.observe(pack(T - 10, 0), T), Observed::Adopted);
        assert_eq!(c.last(), pack(T, 0));
    }
}
```

- [ ] **Step 2: Run, expect failure.** `cargo test -p keyorra-sync clock::` → does not compile (`Hlc`, `pack`, `physical_ms` missing).

- [ ] **Step 3: Implement.** Put this above the test module in `crates/keyorra-sync/src/clock.rs`:

```rust
//! Hybrid logical clock: `hlc = unix_ms << 16 | counter`. It follows wall time when clocks are
//! sane and still moves forward when they are not. The wall time is always passed in.

/// A remote clock more than this far ahead of ours is not adopted (spec §3.3).
pub const MAX_AHEAD_MS: u64 = 5 * 60 * 1000;
const MAX_MS: u64 = (1 << 48) - 1;

pub fn pack(unix_ms: u64, counter: u16) -> u64 {
    assert!(unix_ms <= MAX_MS, "unix milliseconds beyond 48 bits");
    unix_ms << 16 | u64::from(counter)
}

pub fn physical_ms(hlc: u64) -> u64 {
    hlc >> 16
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observed {
    /// Folded into the local clock.
    Adopted,
    /// More than [`MAX_AHEAD_MS`] ahead of the local wall clock: not adopted; worth a log line.
    TooFarAhead { ahead_ms: u64 },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Hlc {
    last: u64,
}

impl Hlc {
    pub fn new(last: u64) -> Hlc {
        Hlc { last }
    }

    pub fn last(&self) -> u64 {
        self.last
    }

    /// The timestamp for a new local write.
    pub fn tick(&mut self, wall_ms: u64) -> u64 {
        let next = pack(wall_ms.min(MAX_MS), 0).max(self.last + 1);
        self.last = next;
        next
    }

    /// Takes a remote timestamp into account, unless it is too far in the future.
    pub fn observe(&mut self, remote: u64, wall_ms: u64) -> Observed {
        let remote_ms = physical_ms(remote);
        if remote_ms > wall_ms.saturating_add(MAX_AHEAD_MS) {
            return Observed::TooFarAhead {
                ahead_ms: remote_ms - wall_ms,
            };
        }
        self.last = self.last.max(remote);
        Observed::Adopted
    }
}
```

- [ ] **Step 4: Run, expect success.** `cargo test -p keyorra-sync clock::` → all pass; `cargo clippy -p keyorra-sync --all-targets -- -D warnings` clean; `cargo fmt --all`.

- [ ] **Step 5: Commit.**

```bash
git add crates/keyorra-sync/src/clock.rs crates/keyorra-sync/src/lib.rs
git commit -m "sync: hybrid logical clock with a 5-minute future bound"
```

### Task 3: Version vectors

**Files:** Create `crates/keyorra-sync/src/vv.rs`; modify `crates/keyorra-sync/src/lib.rs`.

Dominance (`Before`/`After`/`Equal`/`Concurrent`) and join.

- [ ] **Step 1: Failing tests.** Add `pub mod vv;` to `lib.rs` (keep the module lines sorted) and create `crates/keyorra-sync/src/vv.rs` with only the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const A: DeviceId = [1; 16];
    const B: DeviceId = [2; 16];

    fn v(entries: &[(DeviceId, u64)]) -> Vector {
        entries.iter().copied().collect()
    }

    #[test]
    fn compare_covers_all_four_cases() {
        assert_eq!(compare(&v(&[(A, 1)]), &v(&[(A, 1)])), Causality::Equal);
        assert_eq!(compare(&v(&[(A, 1)]), &v(&[(A, 2)])), Causality::Before);
        assert_eq!(
            compare(&v(&[(A, 1), (B, 1)]), &v(&[(A, 1)])),
            Causality::After
        );
        assert_eq!(
            compare(&v(&[(A, 2)]), &v(&[(A, 1), (B, 1)])),
            Causality::Concurrent
        );
        assert_eq!(compare(&v(&[]), &v(&[(B, 1)])), Causality::Before);
    }

    #[test]
    fn join_takes_the_maximum_per_device() {
        let j = join([&v(&[(A, 2)]), &v(&[(A, 1), (B, 3)])]);
        assert_eq!(j, v(&[(A, 2), (B, 3)]));
        assert_eq!(compare(&j, &v(&[(A, 2)])), Causality::After);
    }
}
```

- [ ] **Step 2: Run, expect failure.** `cargo test -p keyorra-sync vv::` → does not compile (`compare`, `join`, `Causality` missing).

- [ ] **Step 3: Implement.** Put this above the test module in `crates/keyorra-sync/src/vv.rs`:

```rust
//! Version vectors: per record, how many writes of each device a version includes.

use std::collections::BTreeMap;

use crate::DeviceId;

pub type Vector = BTreeMap<DeviceId, u64>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Causality {
    Equal,
    /// `a` happened before `b` (`b` dominates).
    Before,
    /// `a` dominates `b`.
    After,
    Concurrent,
}

pub fn compare(a: &Vector, b: &Vector) -> Causality {
    let (mut a_more, mut b_more) = (false, false);
    for device in a.keys().chain(b.keys()) {
        let (x, y) = (
            a.get(device).copied().unwrap_or(0),
            b.get(device).copied().unwrap_or(0),
        );
        a_more |= x > y;
        b_more |= y > x;
    }
    match (a_more, b_more) {
        (false, false) => Causality::Equal,
        (false, true) => Causality::Before,
        (true, false) => Causality::After,
        (true, true) => Causality::Concurrent,
    }
}

/// Element-wise maximum.
pub fn join<'a>(vectors: impl IntoIterator<Item = &'a Vector>) -> Vector {
    let mut out = Vector::new();
    for v in vectors {
        for (device, n) in v {
            let e = out.entry(*device).or_insert(0);
            *e = (*e).max(*n);
        }
    }
    out
}
```

- [ ] **Step 4: Run, expect success.** `cargo test -p keyorra-sync vv::` → all pass; `cargo clippy -p keyorra-sync --all-targets -- -D warnings` clean; `cargo fmt --all`.

- [ ] **Step 5: Commit.**

```bash
git add crates/keyorra-sync/src/vv.rs crates/keyorra-sync/src/lib.rs
git commit -m "sync: version vector comparison and join"
```

### Task 4: Payloads

**Files:** Create `crates/keyorra-sync/src/payload.rs`; modify `crates/keyorra-sync/src/lib.rs`.

What an opened body contains, with `content_from`; content equality ignoring `updated_at`; the conflict-copy JSON (new id, marker, attachment ids with `copied_from`). Secrets are redacted in `Debug`.

- [ ] **Step 1: Failing tests.** Add `pub mod payload;` to `lib.rs` (keep the module lines sorted) and create `crates/keyorra-sync/src/payload.rs` with only the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    fn item(json: &str, deleted_at: Option<u64>) -> ItemPayload {
        ItemPayload {
            item_json: Zeroizing::new(json.as_bytes().to_vec()),
            deleted_at,
            content_from: [([1; 16], 1)].into_iter().collect(),
        }
    }

    fn attachment() -> AttachmentPayload {
        AttachmentPayload {
            item_id: Uuid::from_bytes([1; 16]),
            name: "scan.pdf".into(),
            size: 5,
            key: Zeroizing::new([2; 32]),
            chunk_size: 4 * 1024 * 1024,
            chunks: vec![[3; 32]],
        }
    }

    #[test]
    fn every_kind_round_trips() {
        let docs = [
            (
                RecordKind::Item,
                Doc::Item(item(r#"{"title":"a"}"#, Some(7))),
            ),
            (RecordKind::Item, Doc::Item(item(r#"{"title":"a"}"#, None))),
            (
                RecordKind::Vault,
                Doc::Vault(VaultPayload {
                    name: "Personal".into(),
                    wrapped_key: vec![9; 72],
                    deleted: true,
                }),
            ),
            (RecordKind::Attachment, Doc::Attachment(attachment())),
        ];
        for (kind, doc) in docs {
            assert_eq!(doc.kind(), Some(kind));
            assert_eq!(Doc::decode(kind, &doc.encode()).unwrap(), doc);
        }
    }

    #[test]
    fn decode_checks_shape_and_kind() {
        let vault = Doc::Vault(VaultPayload {
            name: "x".into(),
            wrapped_key: vec![],
            deleted: false,
        })
        .encode();
        assert!(matches!(
            Doc::decode(RecordKind::Item, &vault),
            Err(Error::Malformed(_))
        ));
        let not_object = Doc::Item(item("[1]", None)).encode();
        assert!(matches!(
            Doc::decode(RecordKind::Item, &not_object),
            Err(Error::Malformed(_))
        ));
        let mut no_origin = item("{}", None);
        no_origin.content_from.clear();
        let no_origin = Doc::Item(no_origin).encode();
        assert!(matches!(
            Doc::decode(RecordKind::Item, &no_origin),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn content_equality_ignores_updated_at_and_deleted_at_only() {
        let a = item(r#"{"title":"a","updated_at":1}"#, None);
        assert!(item_content_eq(
            &a,
            &item(r#"{"updated_at":2,"title":"a"}"#, Some(5))
        ));
        assert!(!item_content_eq(
            &a,
            &item(r#"{"title":"b","updated_at":1}"#, None)
        ));
    }

    #[test]
    fn copy_json_gets_new_id_marker_and_attachment_ids() {
        let (old_att, new_att) = (Uuid::from_bytes([5; 16]), Uuid::from_bytes([6; 16]));
        let original = item(
            &format!(
                r#"{{"id":"x","title":"GitHub","attachments":[{{"id":"{old_att}","name":"a"}}]}}"#
            ),
            None,
        );
        let marker = ConflictMarker {
            of: Uuid::from_bytes([4; 16]),
            version: [7; 32],
            from_device: [8; 16],
        };
        let copy_id = Uuid::from_bytes([9; 16]);
        let json = copy_item_json(&original, copy_id, &marker, &[(old_att, new_att)]).unwrap();
        let copy = item(std::str::from_utf8(&json).unwrap(), None);
        let v: Json = serde_json::from_slice(&json).unwrap();
        assert_eq!(v["id"], copy_id.to_string());
        assert_eq!(v["title"], "GitHub");
        assert_eq!(attachment_refs(&copy), vec![new_att]);
        assert_eq!(copied_attachment_refs(&copy), vec![(new_att, old_att)]);
        assert_eq!(copied_attachment_refs(&original), vec![]);
        assert_eq!(conflict_marker(&copy), Some(marker));
        assert_eq!(conflict_marker(&original), None);
    }

    #[test]
    fn debug_hides_secrets() {
        let shown = format!(
            "{:?} {:?}",
            item(r#"{"password":"hunter2"}"#, None),
            attachment()
        );
        assert!(!shown.contains("hunter2"));
        assert!(!shown.contains("[2, 2"));
    }
}
```

- [ ] **Step 2: Run, expect failure.** `cargo test -p keyorra-sync payload::` → does not compile (`Doc`, `ItemPayload`, … missing).

- [ ] **Step 3: Implement.** Put this above the test module in `crates/keyorra-sync/src/payload.rs`:

````rust
//! Plaintext payloads of record versions: what an envelope's body carries once opened.
//!
//! ```text
//! item       = { "item": bytes (the Item JSON, as stored locally), "deleted_at": uint | null,
//!                "content_from": { bytes16 → uint } }
//! vault      = { "name": text, "wrapped_key": bytes, "deleted": bool }
//! attachment = { "item_id": bytes16, "name": text, "size": uint, "key": bytes32,
//!                "chunk_size": uint, "chunks": [bytes32, …] }
//! ```

use std::fmt;

use serde_json::Value as Json;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::cbor::{self, Value};
use crate::envelope::RecordKind;
use crate::error::{malformed, Result};
use crate::vv::Vector;

#[derive(Clone, PartialEq, Eq)]
pub struct ItemPayload {
    /// The item exactly as the local store serializes it (JSON object).
    pub item_json: Zeroizing<Vec<u8>>,
    /// Unix seconds when it was moved to Recently Deleted.
    pub deleted_at: Option<u64>,
    /// The version vector of the write that last changed `item_json`. Trashing and restoring
    /// keep it; an edit sets it to its own vector. Lets the fold tell a pure delete or restore
    /// from an edit (spec §3.5). Empty only before [`Engine`](crate::engine) fills it in.
    pub content_from: Vector,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultPayload {
    pub name: String,
    /// The vault key wrapped by the account key (`keyorra-core` `wrap_vault_key`).
    pub wrapped_key: Vec<u8>,
    pub deleted: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct AttachmentPayload {
    pub item_id: Uuid,
    pub name: String,
    pub size: u64,
    /// The attachment's own random key; its chunks are sealed with it.
    pub key: Zeroizing<[u8; 32]>,
    pub chunk_size: u32,
    pub chunks: Vec<[u8; 32]>,
}

/// The decoded content of one record version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Doc {
    Item(ItemPayload),
    Vault(VaultPayload),
    Attachment(AttachmentPayload),
    /// A purged record.
    Tombstone,
}

impl fmt::Debug for ItemPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ItemPayload")
            .field("item_json", &format_args!("{} bytes", self.item_json.len()))
            .field("deleted_at", &self.deleted_at)
            .field("content_from", &self.content_from)
            .finish()
    }
}

impl fmt::Debug for AttachmentPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AttachmentPayload")
            .field("item_id", &self.item_id)
            .field("size", &self.size)
            .field("chunks", &self.chunks.len())
            .finish_non_exhaustive()
    }
}

impl Doc {
    pub fn kind(&self) -> Option<RecordKind> {
        match self {
            Doc::Item(_) => Some(RecordKind::Item),
            Doc::Vault(_) => Some(RecordKind::Vault),
            Doc::Attachment(_) => Some(RecordKind::Attachment),
            Doc::Tombstone => None,
        }
    }

    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let value = match self {
            Doc::Item(p) => Value::map(vec![
                ("item", Value::bytes(&*p.item_json)),
                ("deleted_at", p.deleted_at.map_or(Value::Null, Value::Uint)),
                (
                    "content_from",
                    Value::Map(
                        p.content_from
                            .iter()
                            .map(|(d, n)| (Value::bytes(d), Value::Uint(*n)))
                            .collect(),
                    ),
                ),
            ]),
            Doc::Vault(p) => Value::map(vec![
                ("name", Value::text(&p.name)),
                ("wrapped_key", Value::bytes(&p.wrapped_key)),
                ("deleted", Value::Bool(p.deleted)),
            ]),
            Doc::Attachment(p) => Value::map(vec![
                ("item_id", Value::bytes(p.item_id.as_bytes())),
                ("name", Value::text(&p.name)),
                ("size", Value::Uint(p.size)),
                ("key", Value::bytes(*p.key)),
                ("chunk_size", Value::Uint(p.chunk_size.into())),
                (
                    "chunks",
                    Value::Array(p.chunks.iter().map(Value::bytes).collect()),
                ),
            ]),
            Doc::Tombstone => return Zeroizing::new(Vec::new()),
        };
        Zeroizing::new(cbor::encode(&value))
    }

    pub fn decode(kind: RecordKind, bytes: &[u8]) -> Result<Doc> {
        let value = cbor::decode(bytes)?;
        Ok(match kind {
            RecordKind::Item => {
                let f = value.fields(&["item", "deleted_at", "content_from"])?;
                let item_json = Zeroizing::new(f.get("item")?.as_bytes()?.to_vec());
                if !matches!(
                    serde_json::from_slice::<Json>(&item_json),
                    Ok(Json::Object(_))
                ) {
                    return Err(malformed("item payload is not a JSON object"));
                }
                let mut content_from = Vector::new();
                for (device, n) in f.get("content_from")?.as_map()? {
                    content_from.insert(device.as_array_of()?, n.as_uint()?);
                }
                if content_from.is_empty() || content_from.values().any(|n| *n == 0) {
                    return Err(malformed("item content_from"));
                }
                Doc::Item(ItemPayload {
                    item_json,
                    deleted_at: match f.get("deleted_at")? {
                        Value::Null => None,
                        v => Some(v.as_uint()?),
                    },
                    content_from,
                })
            }
            RecordKind::Vault => {
                let f = value.fields(&["name", "wrapped_key", "deleted"])?;
                Doc::Vault(VaultPayload {
                    name: f.get("name")?.as_text()?.to_owned(),
                    wrapped_key: f.get("wrapped_key")?.as_bytes()?.to_vec(),
                    deleted: f.get("deleted")?.as_bool()?,
                })
            }
            RecordKind::Attachment => {
                let f =
                    value.fields(&["item_id", "name", "size", "key", "chunk_size", "chunks"])?;
                Doc::Attachment(AttachmentPayload {
                    item_id: Uuid::from_bytes(f.get("item_id")?.as_array_of()?),
                    name: f.get("name")?.as_text()?.to_owned(),
                    size: f.get("size")?.as_uint()?,
                    key: Zeroizing::new(f.get("key")?.as_array_of()?),
                    chunk_size: f.get("chunk_size")?.as_u32()?,
                    chunks: f
                        .get("chunks")?
                        .as_list()?
                        .iter()
                        .map(|c| c.as_array_of())
                        .collect::<Result<_>>()?,
                })
            }
        })
    }
}

fn parse_object(json: &[u8]) -> Option<serde_json::Map<String, Json>> {
    match serde_json::from_slice::<Json>(json) {
        Ok(Json::Object(map)) => Some(map),
        _ => None,
    }
}

/// "Same content" for items (spec §3.5): equal JSON values once `updated_at` is ignored.
/// `deleted_at` and `content_from` live outside the JSON, so they are ignored too.
pub fn item_content_eq(a: &ItemPayload, b: &ItemPayload) -> bool {
    match (parse_object(&a.item_json), parse_object(&b.item_json)) {
        (Some(mut x), Some(mut y)) => {
            x.remove("updated_at");
            y.remove("updated_at");
            x == y
        }
        _ => a.item_json == b.item_json,
    }
}

/// The attachment ids an item refers to (`attachments[].id`).
pub fn attachment_refs(item: &ItemPayload) -> Vec<Uuid> {
    parse_object(&item.item_json)
        .and_then(|o| o.get("attachments").cloned())
        .and_then(|a| match a {
            Json::Array(list) => Some(list),
            _ => None,
        })
        .unwrap_or_default()
        .iter()
        .filter_map(|a| a.get("id")?.as_str()?.parse().ok())
        .collect()
}

/// Attachments of a conflict copy that stand for an attachment of the original:
/// (attachment id in the copy, original attachment id).
pub fn copied_attachment_refs(item: &ItemPayload) -> Vec<(Uuid, Uuid)> {
    let Some(Json::Array(list)) =
        parse_object(&item.item_json).and_then(|o| o.get("attachments").cloned())
    else {
        return Vec::new();
    };
    list.iter()
        .filter_map(|a| {
            let id = a.get("id")?.as_str()?.parse().ok()?;
            let from = a.get("copied_from")?.as_str()?.parse().ok()?;
            Some((id, from))
        })
        .collect()
}

/// The conflict marker stored in a conflict copy (`conflict` field of the item JSON).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConflictMarker {
    pub of: Uuid,
    pub version: [u8; 32],
    pub from_device: crate::DeviceId,
}

/// The item JSON of a conflict copy: new id, the conflict marker, attachment ids replaced
/// through `attachments` (old → new, with `copied_from` = old so the attachment record can be
/// created by whichever device knows the original). The title is left alone; the app shows the
/// "(conflict from …)" suffix from the marker, so the copy is the same on every device.
pub fn copy_item_json(
    item: &ItemPayload,
    copy_id: Uuid,
    marker: &ConflictMarker,
    attachments: &[(Uuid, Uuid)],
) -> Result<Zeroizing<Vec<u8>>> {
    let mut obj = parse_object(&item.item_json).ok_or_else(|| malformed("item JSON"))?;
    obj.insert("id".into(), Json::String(copy_id.to_string()));
    obj.insert(
        "conflict".into(),
        serde_json::json!({
            "of": marker.of.to_string(),
            "version": data_encoding::HEXLOWER.encode(&marker.version),
            "from_device": data_encoding::HEXLOWER.encode(&marker.from_device),
        }),
    );
    if let Some(Json::Array(list)) = obj.get_mut("attachments") {
        for entry in list.iter_mut() {
            let Some(old) = entry
                .get("id")
                .and_then(Json::as_str)
                .and_then(|s| s.parse::<Uuid>().ok())
            else {
                continue;
            };
            if let Some((_, new)) = attachments.iter().find(|(o, _)| *o == old) {
                entry["id"] = Json::String(new.to_string());
                entry["copied_from"] = Json::String(old.to_string());
            }
        }
    }
    Ok(Zeroizing::new(
        serde_json::to_vec(&Json::Object(obj)).expect("JSON values serialize"),
    ))
}

/// The conflict marker of an item, if it is a conflict copy.
pub fn conflict_marker(item: &ItemPayload) -> Option<ConflictMarker> {
    let obj = parse_object(&item.item_json)?;
    let c = obj.get("conflict")?;
    let hex = |k: &str| {
        data_encoding::HEXLOWER
            .decode(c.get(k)?.as_str()?.as_bytes())
            .ok()
    };
    Some(ConflictMarker {
        of: c.get("of")?.as_str()?.parse().ok()?,
        version: hex("version")?.try_into().ok()?,
        from_device: hex("from_device")?.try_into().ok()?,
    })
}
````

- [ ] **Step 4: Run, expect success.** `cargo test -p keyorra-sync payload::` → all pass; `cargo clippy -p keyorra-sync --all-targets -- -D warnings` clean; `cargo fmt --all`.

- [ ] **Step 5: Commit.**

```bash
git add crates/keyorra-sync/src/payload.rs crates/keyorra-sync/src/lib.rs
git commit -m "sync: record payloads, content equality and conflict-copy JSON"
```

### Task 5: Sibling sets

**Files:** Create `crates/keyorra-sync/src/siblings.rs`; modify `crates/keyorra-sync/src/lib.rs`.

The antichain per record. Equal vectors are the same version; insertion order never matters.

- [ ] **Step 1: Failing tests.** Add `pub mod siblings;` to `lib.rs` (keep the module lines sorted) and create `crates/keyorra-sync/src/siblings.rs` with only the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    const A: [u8; 16] = [1; 16];
    const B: [u8; 16] = [2; 16];
    const C: [u8; 16] = [3; 16];

    fn sib(author: [u8; 16], hlc: u64, vector: &[([u8; 16], u64)]) -> Sibling {
        let mut hash = [0u8; 32];
        hash[..16].copy_from_slice(&author);
        hash[16..24].copy_from_slice(&hlc.to_be_bytes());
        Sibling {
            version: Version {
                vector: vector.iter().copied().collect::<BTreeMap<_, _>>(),
                hlc,
                author,
            },
            hash,
            vault_id: None,
            doc: Doc::Tombstone,
        }
    }

    #[test]
    fn newer_replaces_older_and_older_is_ignored() {
        let mut s = SiblingSet::default();
        assert!(s.insert(sib(A, 1, &[(A, 1)])));
        assert!(s.insert(sib(A, 2, &[(A, 2)])));
        assert!(!s.insert(sib(A, 1, &[(A, 1)])));
        assert_eq!(s.siblings().len(), 1);
        assert_eq!(s.top().unwrap().version.hlc, 2);
    }

    #[test]
    fn concurrent_versions_are_kept_and_a_join_collapses_them() {
        let mut s = SiblingSet::default();
        s.insert(sib(A, 5, &[(A, 1)]));
        s.insert(sib(B, 3, &[(B, 1)]));
        assert_eq!(s.siblings().len(), 2);
        assert_eq!(s.top().unwrap().version.author, A);
        assert!(s.insert(sib(C, 9, &[(A, 1), (B, 1), (C, 1)])));
        assert_eq!(s.siblings().len(), 1);
    }

    #[test]
    fn rank_breaks_hlc_ties_by_author() {
        let mut s = SiblingSet::default();
        s.insert(sib(A, 5, &[(A, 1)]));
        s.insert(sib(B, 5, &[(B, 1)]));
        assert_eq!(s.top().unwrap().version.author, B);
    }

    #[test]
    fn insertion_order_does_not_matter() {
        let versions = [
            sib(A, 1, &[(A, 1)]),
            sib(B, 2, &[(B, 1)]),
            sib(A, 3, &[(A, 2)]),
            sib(C, 4, &[(A, 1), (C, 1)]),
            sib(B, 5, &[(A, 2), (B, 2)]),
        ];
        let mut reference = SiblingSet::default();
        for v in versions.iter().cloned() {
            reference.insert(v);
        }
        for rotation in 0..versions.len() {
            for reversed in [false, true] {
                let mut order: Vec<_> = versions
                    .iter()
                    .cycle()
                    .skip(rotation)
                    .take(versions.len())
                    .collect();
                if reversed {
                    order.reverse();
                }
                let mut s = SiblingSet::default();
                for v in order {
                    s.insert(v.clone());
                }
                assert_eq!(s, reference, "rotation {rotation}, reversed {reversed}");
            }
        }
    }
}
```

- [ ] **Step 2: Run, expect failure.** `cargo test -p keyorra-sync siblings::` → does not compile (`Sibling`, `SiblingSet` missing).

- [ ] **Step 3: Implement.** Put this above the test module in `crates/keyorra-sync/src/siblings.rs`:

```rust
//! Sibling sets: per record, the accepted versions that no other accepted version dominates
//! (an antichain, in the spirit of dotted version vectors). The set depends only on which
//! versions were added, never on the order, which is what makes devices converge.

use uuid::Uuid;

use crate::envelope::Version;
use crate::payload::Doc;
use crate::vv::{compare, Causality};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sibling {
    pub version: Version,
    /// `version_hash` of the version; also its identity.
    pub hash: [u8; 32],
    /// The envelope's `vault_id` (items and attachments).
    pub vault_id: Option<Uuid>,
    pub doc: Doc,
}

impl Sibling {
    /// The order that picks the visible sibling: higher HLC, then higher author id.
    pub fn rank(&self) -> (u64, [u8; 16]) {
        (self.version.hlc, self.version.author)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SiblingSet {
    /// Kept sorted by `hash`, so equal sets are equal values.
    siblings: Vec<Sibling>,
}

impl SiblingSet {
    pub fn siblings(&self) -> &[Sibling] {
        &self.siblings
    }

    pub fn is_empty(&self) -> bool {
        self.siblings.is_empty()
    }

    /// Adds `s` unless an existing sibling equals or dominates it; drops the siblings it
    /// dominates. Returns whether `s` was added.
    pub fn insert(&mut self, s: Sibling) -> bool {
        let mut dominated = Vec::new();
        for (i, existing) in self.siblings.iter().enumerate() {
            match compare(&s.version.vector, &existing.version.vector) {
                Causality::Equal | Causality::Before => return false,
                Causality::After => dominated.push(i),
                Causality::Concurrent => {}
            }
        }
        for i in dominated.into_iter().rev() {
            self.siblings.remove(i);
        }
        let at = self.siblings.partition_point(|x| x.hash < s.hash);
        self.siblings.insert(at, s);
        true
    }

    /// The sibling with the highest rank.
    pub fn top(&self) -> Option<&Sibling> {
        self.siblings.iter().max_by_key(|s| s.rank())
    }
}
```

- [ ] **Step 4: Run, expect success.** `cargo test -p keyorra-sync siblings::` → all pass; `cargo clippy -p keyorra-sync --all-targets -- -D warnings` clean; `cargo fmt --all`.

- [ ] **Step 5: Commit.**

```bash
git add crates/keyorra-sync/src/siblings.rs crates/keyorra-sync/src/lib.rs
git commit -m "sync: sibling sets"
```

### Task 6: Presentation and conflict-copy ids

**Files:** Create `crates/keyorra-sync/src/present.rs`; modify `crates/keyorra-sync/src/lib.rs`.

Pure functions of one sibling set (spec §3.5 as revised). The pinned copy id was cross-checked with Python (`hashlib`, `uuid`).

- [ ] **Step 1: Failing tests.** Add `pub mod present;` to `lib.rs` (keep the module lines sorted) and create `crates/keyorra-sync/src/present.rs` with only the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::Version;
    use crate::vv::Vector;
    use zeroize::Zeroizing;

    const A: [u8; 16] = [1; 16];
    const B: [u8; 16] = [2; 16];
    const C: [u8; 16] = [3; 16];
    const ID: Uuid = Uuid::from_bytes([0x60; 16]);

    fn vector(entries: &[([u8; 16], u64)]) -> Vector {
        entries.iter().copied().collect()
    }

    fn sib(author: [u8; 16], hlc: u64, version: &[([u8; 16], u64)], doc: Doc) -> Sibling {
        let mut hash = [0u8; 32];
        hash[..16].copy_from_slice(&author);
        hash[16..24].copy_from_slice(&hlc.to_be_bytes());
        Sibling {
            version: Version {
                vector: vector(version),
                hlc,
                author,
            },
            hash,
            vault_id: Some(Uuid::from_bytes([0x61; 16])),
            doc,
        }
    }

    /// An item whose content was last changed at `content_from`.
    fn item(title: &str, deleted_at: Option<u64>, content_from: &[([u8; 16], u64)]) -> Doc {
        Doc::Item(ItemPayload {
            item_json: Zeroizing::new(format!(r#"{{"title":"{title}"}}"#).into_bytes()),
            deleted_at,
            content_from: vector(content_from),
        })
    }

    /// A fresh edit: the content was changed by this very version.
    fn edit(author: [u8; 16], hlc: u64, version: &[([u8; 16], u64)], title: &str) -> Sibling {
        sib(author, hlc, version, item(title, None, version))
    }

    fn set(siblings: Vec<Sibling>) -> SiblingSet {
        let mut s = SiblingSet::default();
        for x in siblings {
            assert!(s.insert(x));
        }
        s
    }

    /// (state, author of the visible sibling, [(author of a copied sibling, trashed)]).
    type Summary = (ItemState, Option<[u8; 16]>, Vec<([u8; 16], bool)>);

    fn summary(p: &ItemPresentation) -> Summary {
        (
            p.state,
            p.visible.map(|v| v.version.author),
            p.copies
                .iter()
                .map(|c| (c.source.version.author, c.trashed))
                .collect(),
        )
    }

    #[test]
    fn copy_ids_are_deterministic_v8_and_distinct() {
        let a = conflict_copy_id(ID, &[1; 32]);
        assert_eq!(a, conflict_copy_id(ID, &[1; 32]));
        assert_eq!(a.get_version_num(), 8);
        assert_ne!(a, conflict_copy_id(ID, &[2; 32]));
        assert_ne!(a, conflict_copy_id(Uuid::from_bytes([0x62; 16]), &[1; 32]));
        assert_ne!(
            copy_attachment_id(a, ID),
            copy_attachment_id(a, Uuid::from_bytes([0x62; 16]))
        );
        // Pinned (cross-checked with Python hashlib).
        assert_eq!(a.to_string(), "fa11d85b-0a1a-8caa-8441-ad95ab1ee22b");
    }

    #[test]
    fn single_live_version_has_no_copies() {
        let s = set(vec![edit(A, 1, &[(A, 1)], "a")]);
        assert_eq!(
            summary(&present_item(ID, &s)),
            (ItemState::Live, Some(A), vec![])
        );
    }

    #[test]
    fn concurrent_edits_keep_the_top_and_copy_the_rest() {
        let s = set(vec![
            edit(A, 5, &[(A, 1)], "a"),
            edit(B, 9, &[(B, 1)], "b"),
            edit(C, 7, &[(C, 1)], "c"),
        ]);
        let p = present_item(ID, &s);
        assert_eq!(
            summary(&p),
            (ItemState::Live, Some(B), vec![(C, false), (A, false)])
        );
        assert_eq!(
            p.copies[0].copy_id,
            conflict_copy_id(ID, &p.copies[0].source.hash)
        );
    }

    #[test]
    fn equal_content_makes_no_copy() {
        let s = set(vec![
            edit(A, 5, &[(A, 1)], "same"),
            edit(B, 9, &[(B, 1)], "same"),
        ]);
        assert_eq!(
            summary(&present_item(ID, &s)),
            (ItemState::Live, Some(B), vec![])
        );
        // Two losers with the same content make one copy.
        let s = set(vec![
            edit(A, 5, &[(A, 1)], "x"),
            edit(B, 9, &[(B, 1)], "y"),
            edit(C, 7, &[(C, 1)], "x"),
        ]);
        assert_eq!(summary(&present_item(ID, &s)).2, vec![(C, false)]);
    }

    #[test]
    fn a_pure_delete_loses_to_a_concurrent_edit_without_a_copy() {
        // C wrote "base"; A trashed it unchanged while B edited it. A ranks higher.
        let s = set(vec![
            sib(A, 9, &[(C, 1), (A, 1)], item("base", Some(100), &[(C, 1)])),
            edit(B, 5, &[(C, 1), (B, 1)], "edited"),
        ]);
        assert_eq!(
            summary(&present_item(ID, &s)),
            (ItemState::Live, Some(B), vec![])
        );
    }

    #[test]
    fn an_edit_then_trash_survives_in_recently_deleted() {
        // A edited "base" to "mine" (A:1) and then trashed it (A:2), concurrently with B's edit.
        let s = set(vec![
            sib(
                A,
                9,
                &[(C, 1), (A, 2)],
                item("mine", Some(100), &[(C, 1), (A, 1)]),
            ),
            edit(B, 5, &[(C, 1), (B, 1)], "edited"),
        ]);
        assert_eq!(
            summary(&present_item(ID, &s)),
            (ItemState::Live, Some(B), vec![(A, true)])
        );
    }

    #[test]
    fn a_pure_restore_loses_to_a_concurrent_edit_without_a_copy() {
        // "base" was trashed by C; A restored it unchanged while B edited and restored it.
        // The edit shows even when the restore ranks higher.
        let s = set(vec![
            sib(A, 9, &[(C, 2), (A, 1)], item("base", None, &[(C, 1)])),
            edit(B, 5, &[(C, 2), (B, 1)], "edited"),
        ]);
        assert_eq!(
            summary(&present_item(ID, &s)),
            (ItemState::Live, Some(B), vec![])
        );
        let s = set(vec![
            sib(A, 3, &[(C, 2), (A, 1)], item("base", None, &[(C, 1)])),
            edit(B, 5, &[(C, 2), (B, 1)], "edited"),
        ]);
        assert_eq!(
            summary(&present_item(ID, &s)),
            (ItemState::Live, Some(B), vec![])
        );
    }

    #[test]
    fn purge_is_final_and_live_edits_become_copies() {
        let s = set(vec![
            sib(A, 1, &[(C, 2), (A, 1)], Doc::Tombstone),
            edit(B, 9, &[(C, 2), (B, 1)], "b"),
            sib(C, 5, &[(C, 3)], item("c", Some(3), &[(C, 3)])),
        ]);
        assert_eq!(
            summary(&present_item(ID, &s)),
            (ItemState::Purged, Some(A), vec![(B, false)])
        );
        // A restore without an edit, concurrent with the purge, leaves nothing to keep.
        let s = set(vec![
            sib(A, 1, &[(C, 2), (A, 1)], Doc::Tombstone),
            sib(B, 9, &[(C, 2), (B, 1)], item("base", None, &[(C, 1)])),
        ]);
        assert_eq!(
            summary(&present_item(ID, &s)),
            (ItemState::Purged, Some(A), vec![])
        );
    }

    #[test]
    fn all_trashed_shows_the_top_trashed_and_copies_differing_edits() {
        let s = set(vec![
            sib(A, 1, &[(A, 2)], item("a", Some(1), &[(A, 1)])),
            sib(B, 9, &[(B, 2)], item("b", Some(2), &[(B, 1)])),
        ]);
        assert_eq!(
            summary(&present_item(ID, &s)),
            (ItemState::Trashed, Some(B), vec![(A, true)])
        );
    }

    #[test]
    fn deleted_vault_is_revived_by_live_items() {
        let vault = |name: &str, deleted: bool| {
            Doc::Vault(VaultPayload {
                name: name.into(),
                wrapped_key: vec![1, 2, 3],
                deleted,
            })
        };
        let s = set(vec![
            sib(A, 9, &[(A, 1)], vault("Work", true)),
            sib(B, 5, &[(B, 1)], vault("Job", false)),
        ]);
        let p = present_vault(&s, false).unwrap();
        assert!(p.deleted && !p.revived && !p.key_mismatch);
        assert_eq!(p.payload.name, "Work");
        let p = present_vault(&s, true).unwrap();
        assert!(!p.deleted && p.revived);
        let odd = Doc::Vault(VaultPayload {
            name: "Job".into(),
            wrapped_key: vec![9],
            deleted: false,
        });
        let s = set(vec![
            sib(A, 9, &[(A, 1)], vault("Work", false)),
            sib(B, 5, &[(B, 1)], odd),
        ]);
        assert!(present_vault(&s, false).unwrap().key_mismatch);
    }

    #[test]
    fn attachment_tombstone_wins() {
        let att = Doc::Attachment(AttachmentPayload {
            item_id: ID,
            name: "a".into(),
            size: 1,
            key: Zeroizing::new([0; 32]),
            chunk_size: 1,
            chunks: vec![],
        });
        let s = set(vec![sib(A, 9, &[(A, 1)], att.clone())]);
        assert!(present_attachment(&s).is_some());
        let s = set(vec![
            sib(A, 9, &[(A, 1)], att),
            sib(B, 1, &[(B, 1)], Doc::Tombstone),
        ]);
        assert!(present_attachment(&s).is_none());
    }
}
```

- [ ] **Step 2: Run, expect failure.** `cargo test -p keyorra-sync present::` → does not compile (`present_item`, `conflict_copy_id`, … missing).

- [ ] **Step 3: Implement.** Put this above the test module in `crates/keyorra-sync/src/present.rs`:

```rust
//! Presentation: what the user sees for a record, given its sibling set (spec §3.5).
//! Everything here is a pure function of the set, so every device shows the same thing.

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::labels::{self, tagged};
use crate::payload::{item_content_eq, AttachmentPayload, Doc, ItemPayload, VaultPayload};
use crate::siblings::{Sibling, SiblingSet};
use crate::vv::{compare, Causality};

fn uuid_v8(digest: &[u8]) -> Uuid {
    Uuid::new_v8(digest[..16].try_into().expect("SHA-256 has 32 bytes"))
}

/// Id of the conflict copy made from sibling `version_hash` of record `record_id`:
/// `UUIDv8(SHA-256("keyorra/sync/v1/conflict-copy\0" ‖ record_id ‖ version_hash)[0..16])`.
pub fn conflict_copy_id(record_id: Uuid, version_hash: &[u8; 32]) -> Uuid {
    uuid_v8(&Sha256::digest(tagged(
        labels::CONFLICT_COPY,
        &[record_id.as_bytes(), version_hash],
    )))
}

/// Id of the attachment record a conflict copy gets for one of the original's attachments:
/// `UUIDv8(SHA-256("keyorra/sync/v1/conflict-copy\0" ‖ copy_id ‖ attachment_id)[0..16])`
/// (32 input bytes after the label, against 48 for an item copy, so the two never collide).
pub fn copy_attachment_id(copy_id: Uuid, attachment_id: Uuid) -> Uuid {
    uuid_v8(&Sha256::digest(tagged(
        labels::CONFLICT_COPY,
        &[copy_id.as_bytes(), attachment_id.as_bytes()],
    )))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ItemState {
    Live,
    Trashed,
    Purged,
}

/// One sibling that must become a conflict copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CopyOf<'a> {
    pub copy_id: Uuid,
    pub source: &'a Sibling,
    /// The copy goes to Recently Deleted (an edited-then-trashed sibling).
    pub trashed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemPresentation<'a> {
    pub state: ItemState,
    /// The sibling shown; `None` only for an empty set.
    pub visible: Option<&'a Sibling>,
    pub copies: Vec<CopyOf<'a>>,
}

fn payload(s: &Sibling) -> Option<&ItemPayload> {
    match &s.doc {
        Doc::Item(p) => Some(p),
        _ => None,
    }
}

fn state(s: &Sibling) -> ItemState {
    match payload(s) {
        None => ItemState::Purged,
        Some(p) if p.deleted_at.is_some() => ItemState::Trashed,
        Some(_) => ItemState::Live,
    }
}

/// Spec §3.5 for items. A sibling is *stale* when another sibling has seen its content (its
/// `content_from` is covered by that sibling's version): it only trashed or restored content
/// that the other side then kept or replaced.
///
/// Shown: a purge if there is one (purge is final), else the best live sibling (an edit beats a
/// delete), else the best trashed one, where "best" prefers fresh over stale siblings, then the
/// higher HLC, then the higher author id. Every other sibling becomes a copy unless it is stale
/// or its content is already shown. With a purge, only live siblings can become copies.
pub fn present_item(record_id: Uuid, set: &SiblingSet) -> ItemPresentation<'_> {
    let stale = |s: &Sibling| {
        payload(s).is_some_and(|p| {
            set.siblings().iter().any(|o| {
                !std::ptr::eq(o, s)
                    && matches!(
                        compare(&p.content_from, &o.version.vector),
                        Causality::Equal | Causality::Before
                    )
            })
        })
    };
    let mut by_rank: Vec<&Sibling> = set.siblings().iter().collect();
    by_rank.sort_by_key(|s| std::cmp::Reverse((!stale(s), s.rank())));
    let first = |st: ItemState| by_rank.iter().copied().find(|s| state(s) == st);
    let (shown_state, visible) = match (
        first(ItemState::Purged),
        first(ItemState::Live),
        first(ItemState::Trashed),
    ) {
        (Some(p), _, _) => (ItemState::Purged, p),
        (None, Some(l), _) => (ItemState::Live, l),
        (None, None, Some(t)) => (ItemState::Trashed, t),
        (None, None, None) => {
            return ItemPresentation {
                state: ItemState::Purged,
                visible: None,
                copies: vec![],
            }
        }
    };
    let mut shown: Vec<&ItemPayload> = payload(visible).into_iter().collect();
    let mut copies = Vec::new();
    for s in by_rank {
        if std::ptr::eq(s, visible) {
            continue;
        }
        let Some(p) = payload(s) else { continue };
        if shown_state == ItemState::Purged && p.deleted_at.is_some() {
            continue;
        }
        if stale(s) || shown.iter().any(|x| item_content_eq(x, p)) {
            continue;
        }
        shown.push(p);
        copies.push(CopyOf {
            copy_id: conflict_copy_id(record_id, &s.hash),
            source: s,
            trashed: p.deleted_at.is_some(),
        });
    }
    ItemPresentation {
        state: shown_state,
        visible: Some(visible),
        copies,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultPresentation<'a> {
    pub payload: &'a VaultPayload,
    /// Shown as deleted: the visible version is deleted and no live item remains in it.
    pub deleted: bool,
    /// The visible version is deleted but live items keep the vault (spec §3.5).
    pub revived: bool,
    /// Siblings disagree on the wrapped vault key: an alarm, never expected before rotation.
    pub key_mismatch: bool,
}

pub fn present_vault(set: &SiblingSet, has_live_items: bool) -> Option<VaultPresentation<'_>> {
    let vaults: Vec<(&Sibling, &VaultPayload)> = set
        .siblings()
        .iter()
        .filter_map(|s| match &s.doc {
            Doc::Vault(p) => Some((s, p)),
            _ => None,
        })
        .collect();
    let (_, top) = vaults.iter().max_by_key(|(s, _)| s.rank())?;
    let key_mismatch = vaults.iter().any(|(_, p)| p.wrapped_key != top.wrapped_key);
    Some(VaultPresentation {
        payload: top,
        deleted: top.deleted && !has_live_items,
        revived: top.deleted && has_live_items,
        key_mismatch,
    })
}

/// A tombstone sibling wins; otherwise the top-ranked version. `None` = removed.
pub fn present_attachment(set: &SiblingSet) -> Option<(&Sibling, &AttachmentPayload)> {
    if set.siblings().iter().any(|s| s.doc == Doc::Tombstone) {
        return None;
    }
    let top = set.top()?;
    match &top.doc {
        Doc::Attachment(p) => Some((top, p)),
        _ => None,
    }
}
```

- [ ] **Step 4: Run, expect success.** `cargo test -p keyorra-sync present::` → all pass; `cargo clippy -p keyorra-sync --all-targets -- -D warnings` clean; `cargo fmt --all`.

- [ ] **Step 5: Commit.**

```bash
git add crates/keyorra-sync/src/present.rs crates/keyorra-sync/src/lib.rs
git commit -m "sync: presentation rules and conflict-copy ids"
```

### Task 7: The fold

**Files:** Create `crates/keyorra-sync/src/fold.rs`; modify `crates/keyorra-sync/src/lib.rs`.

Retains every accepted version, validates (author, counter, kind, no vault tombstones; whole batches atomically), builds sibling sets under an `Admission` policy, and computes the `View`: vaults, items, live attachments, conflict copies to write (`resolutions`) and copy attachment records to write (`attachment_copies`).

- [ ] **Step 1: Failing tests.** Add `pub mod fold;` to `lib.rs` (keep the module lines sorted) and create `crates/keyorra-sync/src/fold.rs` with only the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::{conflict_marker, VaultPayload};
    use crate::present::conflict_copy_id;
    use zeroize::Zeroizing;

    const A: DeviceId = [1; 16];
    const B: DeviceId = [2; 16];
    const ITEM: Uuid = Uuid::from_bytes([0x60; 16]);
    const VAULT: Uuid = Uuid::from_bytes([0x61; 16]);
    const ATT: Uuid = Uuid::from_bytes([0x62; 16]);

    fn json(title: &str, attachments: &[Uuid]) -> Doc {
        let atts: Vec<String> = attachments
            .iter()
            .map(|a| format!(r#"{{"id":"{a}"}}"#))
            .collect();
        Doc::Item(ItemPayload {
            item_json: Zeroizing::new(
                format!(
                    r#"{{"title":"{title}","attachments":[{}]}}"#,
                    atts.join(",")
                )
                .into_bytes(),
            ),
            deleted_at: None,
            // A device that never writes here: every test version counts as a fresh edit.
            content_from: [([9; 16], 1)].into_iter().collect(),
        })
    }

    fn item(
        stream: DeviceId,
        seq: u64,
        vector: &[(DeviceId, u64)],
        hlc: u64,
        doc: Doc,
    ) -> Accepted {
        Accepted {
            stream,
            seq,
            kind: RecordKind::Item,
            record_id: ITEM,
            vault_id: Some(VAULT),
            version: Version {
                vector: vector.iter().copied().collect(),
                hlc,
                author: stream,
            },
            doc,
        }
    }

    fn vault(stream: DeviceId, seq: u64, n: u64, hlc: u64, deleted: bool) -> Accepted {
        Accepted {
            stream,
            seq,
            kind: RecordKind::Vault,
            record_id: VAULT,
            vault_id: None,
            version: Version {
                vector: [(stream, n)].into_iter().collect(),
                hlc,
                author: stream,
            },
            doc: Doc::Vault(VaultPayload {
                name: "Work".into(),
                wrapped_key: vec![1],
                deleted,
            }),
        }
    }

    fn attachment(stream: DeviceId, seq: u64) -> Accepted {
        Accepted {
            stream,
            seq,
            kind: RecordKind::Attachment,
            record_id: ATT,
            vault_id: Some(VAULT),
            version: Version {
                vector: [(stream, 1)].into_iter().collect(),
                hlc: 1,
                author: stream,
            },
            doc: Doc::Attachment(AttachmentPayload {
                item_id: ITEM,
                name: "scan.pdf".into(),
                size: 3,
                key: Zeroizing::new([7; 32]),
                chunk_size: 3,
                chunks: vec![[8; 32]],
            }),
        }
    }

    #[test]
    fn validation_rules() {
        let mut f = Fold::default();
        let mut wrong_author = item(A, 1, &[(A, 1)], 1, json("a", &[]));
        wrong_author.version.author = B;
        assert_eq!(
            f.accept(wrong_author, &AdmitAll),
            Err(Rejection::WrongAuthor)
        );
        assert_eq!(
            f.accept(item(A, 1, &[(A, 2)], 1, json("a", &[])), &AdmitAll),
            Err(Rejection::CounterNotNext {
                expected: 1,
                got: 2
            })
        );
        let mut mismatch = item(A, 1, &[(A, 1)], 1, json("a", &[]));
        mismatch.kind = RecordKind::Attachment;
        assert_eq!(f.accept(mismatch, &AdmitAll), Err(Rejection::KindMismatch));
        let mut tomb = vault(A, 1, 1, 1, false);
        tomb.doc = Doc::Tombstone;
        assert_eq!(f.accept(tomb, &AdmitAll), Err(Rejection::VaultTombstone));
        assert_eq!(
            f.accept(item(A, 1, &[(A, 1)], 1, json("a", &[])), &AdmitAll),
            Ok(Accept::New)
        );
        assert_eq!(
            f.accept(item(A, 1, &[(A, 1)], 1, json("a", &[])), &AdmitAll),
            Ok(Accept::Duplicate)
        );
        // A second, different version with the same counter is a replay or a bug.
        assert_eq!(
            f.accept(item(A, 2, &[(A, 1)], 2, json("b", &[])), &AdmitAll),
            Err(Rejection::CounterNotNext {
                expected: 2,
                got: 1
            })
        );
        assert_eq!(
            f.accept(item(A, 2, &[(A, 2)], 2, json("b", &[])), &AdmitAll),
            Ok(Accept::New)
        );
    }

    #[test]
    fn a_batch_is_all_or_nothing() {
        let mut f = Fold::default();
        let good = item(A, 1, &[(A, 1)], 1, json("a", &[]));
        let next = item(A, 2, &[(A, 2)], 2, json("b", &[]));
        let skip = item(A, 3, &[(A, 4)], 3, json("c", &[]));
        assert_eq!(
            f.accept_batch(vec![good.clone(), next.clone(), skip], &AdmitAll),
            Err(Rejection::CounterNotNext {
                expected: 3,
                got: 4
            })
        );
        assert_eq!(f.retained().count(), 0);
        assert_eq!(
            f.accept_batch(vec![good.clone(), next, good], &AdmitAll),
            Ok(2)
        );
    }

    #[test]
    fn concurrent_edits_produce_one_resolution_with_a_copy() {
        let mut f = Fold::default();
        f.accept(item(A, 1, &[(A, 1)], 1, json("base", &[])), &AdmitAll)
            .unwrap();
        f.accept(item(A, 2, &[(A, 2)], 5, json("from A", &[])), &AdmitAll)
            .unwrap();
        f.accept(
            item(B, 1, &[(A, 1), (B, 1)], 9, json("from B", &[])),
            &AdmitAll,
        )
        .unwrap();
        let view = f.view();
        let shown = view.items[&ITEM].payload.clone().unwrap();
        assert!(std::str::from_utf8(&shown.item_json)
            .unwrap()
            .contains("from B"));
        assert_eq!(view.resolutions.len(), 1);
        let r = &view.resolutions[0];
        assert_eq!(r.record_id, ITEM);
        assert_eq!(r.collapse, Doc::Item(shown));
        let copy = &r.copies[0];
        let loser_hash = version_hash(
            RecordKind::Item,
            ITEM,
            &item(A, 2, &[(A, 2)], 5, json("", &[])).version,
        );
        assert_eq!(copy.copy_id, conflict_copy_id(ITEM, &loser_hash));
        let marker = conflict_marker(&copy.payload).unwrap();
        assert_eq!((marker.of, marker.from_device), (ITEM, A));
    }

    #[test]
    fn a_materialised_copy_is_not_proposed_again() {
        let mut f = Fold::default();
        f.accept(item(A, 1, &[(A, 1)], 5, json("a", &[])), &AdmitAll)
            .unwrap();
        f.accept(item(B, 1, &[(B, 1)], 9, json("b", &[])), &AdmitAll)
            .unwrap();
        let copy = f.view().resolutions[0].copies[0].clone();
        let mut written = copy.payload.clone();
        written.content_from = [(B, 1)].into_iter().collect();
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
                doc: Doc::Item(written),
            },
            &AdmitAll,
        )
        .unwrap();
        assert!(f.view().resolutions.is_empty());
        assert_eq!(f.view().conflict_copies().len(), 1);
    }

    #[test]
    fn a_copy_gets_its_attachment_records_once_the_original_is_known() {
        let mut f = Fold::default();
        f.accept(item(A, 1, &[(A, 1)], 5, json("a", &[ATT])), &AdmitAll)
            .unwrap();
        f.accept(item(B, 1, &[(B, 1)], 9, json("b", &[])), &AdmitAll)
            .unwrap();
        // The copy does not wait for the attachment record.
        let copy = f.view().resolutions[0].copies[0].clone();
        let new_att = copy_attachment_id(copy.copy_id, ATT);
        assert_eq!(
            crate::payload::copied_attachment_refs(&copy.payload),
            vec![(new_att, ATT)]
        );
        let mut written = copy.payload.clone();
        written.content_from = [(B, 1)].into_iter().collect();
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
                doc: Doc::Item(written),
            },
            &AdmitAll,
        )
        .unwrap();
        assert!(
            f.view().attachment_copies.is_empty(),
            "original not known yet"
        );
        f.accept(attachment(A, 2), &AdmitAll).unwrap();
        let proposed = f.view().attachment_copies;
        assert_eq!(proposed.len(), 1);
        assert_eq!(proposed[0].id, new_att);
        assert_eq!(proposed[0].payload.item_id, copy.copy_id);
        assert_eq!(proposed[0].payload.key, Zeroizing::new([7; 32]));
    }

    #[test]
    fn vault_deletion_is_undone_by_live_items() {
        let mut f = Fold::default();
        f.accept(vault(A, 1, 1, 1, false), &AdmitAll).unwrap();
        f.accept(vault(A, 2, 2, 2, true), &AdmitAll).unwrap();
        assert!(f.view().vaults[&VAULT].deleted);
        f.accept(item(B, 1, &[(B, 1)], 3, json("new", &[])), &AdmitAll)
            .unwrap();
        let v = &f.view().vaults[&VAULT];
        assert!(!v.deleted && v.revived);
    }

    #[test]
    fn refold_applies_a_cut_and_resurfaces_dominated_versions() {
        struct Cut(DeviceId, u64);
        impl Admission for Cut {
            fn admits(&self, stream: &DeviceId, seq: u64) -> bool {
                stream != &self.0 || seq <= self.1
            }
        }
        let mut f = Fold::default();
        f.accept(item(A, 1, &[(A, 1)], 1, json("by A", &[])), &AdmitAll)
            .unwrap();
        f.accept(
            item(B, 7, &[(A, 1), (B, 1)], 2, json("by B", &[])),
            &AdmitAll,
        )
        .unwrap();
        assert_eq!(f.set(RecordKind::Item, ITEM).unwrap().siblings().len(), 1);
        f.refold(&Cut(B, 6));
        let shown = f.view().items[&ITEM].payload.clone().unwrap();
        assert!(std::str::from_utf8(&shown.item_json)
            .unwrap()
            .contains("by A"));
        f.refold(&AdmitAll);
        let shown = f.view().items[&ITEM].payload.clone().unwrap();
        assert!(std::str::from_utf8(&shown.item_json)
            .unwrap()
            .contains("by B"));
    }

    #[test]
    fn next_version_dominates_all_siblings_and_counts_own_writes() {
        let mut f = Fold::default();
        f.accept(item(A, 1, &[(A, 1)], 5, json("a", &[])), &AdmitAll)
            .unwrap();
        f.accept(item(B, 1, &[(B, 1)], 9, json("b", &[])), &AdmitAll)
            .unwrap();
        let v = f.next_version(RecordKind::Item, ITEM, A, 10);
        assert_eq!(v.vector, [(A, 2), (B, 1)].into_iter().collect());
        let fresh = f.next_version(RecordKind::Item, Uuid::from_bytes([9; 16]), B, 11);
        assert_eq!(fresh.vector, [(B, 1)].into_iter().collect());
    }

    #[test]
    fn the_view_does_not_depend_on_arrival_order() {
        let versions = vec![
            vault(A, 1, 1, 1, false),
            item(A, 2, &[(A, 1)], 2, json("base", &[ATT])),
            attachment(A, 3),
            item(B, 1, &[(A, 1), (B, 1)], 6, json("B", &[ATT])),
            item(A, 4, &[(A, 2)], 7, json("A", &[ATT])),
        ];
        let reference = {
            let mut f = Fold::default();
            for v in &versions {
                f.accept(v.clone(), &AdmitAll).unwrap();
            }
            f.view()
        };
        // Any order that keeps each stream's own order.
        let orders: [&[usize]; 3] = [&[3, 0, 1, 2, 4], &[0, 3, 1, 4, 2], &[3, 0, 1, 4, 2]];
        for order in orders {
            let mut f = Fold::default();
            for &i in order {
                f.accept(versions[i].clone(), &AdmitAll).unwrap();
            }
            assert_eq!(f.view(), reference, "{order:?}");
        }
    }
}
```

- [ ] **Step 2: Run, expect failure.** `cargo test -p keyorra-sync fold::` → does not compile (`Fold`, `Accepted`, `Admission`, `View`, … missing).

- [ ] **Step 3: Implement.** Put this above the test module in `crates/keyorra-sync/src/fold.rs`:

```rust
//! The fold: local state as a deterministic function of the accepted versions (spec §3.4).
//!
//! Every accepted version is retained; the sibling sets are built from the retained versions
//! that the [`Admission`] policy admits. Plan A1c supplies the real policy (endorsement and
//! revocation cuts) and calls [`Fold::refold`] when it changes; until then [`AdmitAll`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use uuid::Uuid;

use crate::envelope::{version_hash, RecordKind, Version};
use crate::payload::{
    attachment_refs, copied_attachment_refs, copy_item_json, AttachmentPayload, ConflictMarker,
    Doc, ItemPayload,
};
use crate::present::{
    copy_attachment_id, present_attachment, present_item, present_vault, ItemState,
};
use crate::siblings::{Sibling, SiblingSet};
use crate::vv::{join, Vector};
use crate::DeviceId;

pub type RecordKey = (RecordKind, Uuid);

/// A version that passed the stream checks, with its decoded content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accepted {
    /// The device whose stream carried it.
    pub stream: DeviceId,
    /// Its position in that stream.
    pub seq: u64,
    pub kind: RecordKind,
    pub record_id: Uuid,
    pub vault_id: Option<Uuid>,
    pub version: Version,
    pub doc: Doc,
}

impl Accepted {
    pub fn key(&self) -> RecordKey {
        (self.kind, self.record_id)
    }

    pub fn hash(&self) -> [u8; 32] {
        version_hash(self.kind, self.record_id, &self.version)
    }

    fn sibling(&self) -> Sibling {
        Sibling {
            version: self.version.clone(),
            hash: self.hash(),
            vault_id: self.vault_id,
            doc: self.doc.clone(),
        }
    }
}

/// Which stream positions count. A1c: endorsed devices, up to their revocation cut.
pub trait Admission {
    fn admits(&self, stream: &DeviceId, seq: u64) -> bool;
}

/// Every position counts (until A1c).
pub struct AdmitAll;

impl Admission for AdmitAll {
    fn admits(&self, _: &DeviceId, _: u64) -> bool {
        true
    }
}

/// Why a version was refused (spec §3.3). A live device signed it, so this is an alarm.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Rejection {
    /// `version.author` is not the device whose stream carried the version.
    WrongAuthor,
    /// `vector[author]` must be one more than the author's previous version of the record.
    CounterNotNext { expected: u64, got: u64 },
    /// The payload does not match the envelope kind.
    KindMismatch,
    /// Vaults are deleted with a flag, never purged.
    VaultTombstone,
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Rejection::WrongAuthor => f.write_str("version author is not the stream's device"),
            Rejection::CounterNotNext { expected, got } => {
                write!(f, "version counter {got}, expected {expected}")
            }
            Rejection::KindMismatch => f.write_str("payload does not match the record kind"),
            Rejection::VaultTombstone => f.write_str("vault tombstone"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Accept {
    New,
    /// Already accepted (same version hash); nothing changed.
    Duplicate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemView {
    pub state: ItemState,
    pub vault_id: Option<Uuid>,
    /// `None` when purged.
    pub payload: Option<ItemPayload>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultView {
    pub name: String,
    pub wrapped_key: Vec<u8>,
    pub deleted: bool,
    pub revived: bool,
    pub key_mismatch: bool,
}

/// A conflict copy that does not exist yet as a record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingCopy {
    pub copy_id: Uuid,
    pub vault_id: Option<Uuid>,
    pub payload: ItemPayload,
}

/// An attachment record a conflict copy refers to but nobody has written yet: the original's
/// attachment, re-pointed at the copy (same key, same chunks).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachmentCopy {
    pub id: Uuid,
    pub vault_id: Option<Uuid>,
    pub payload: AttachmentPayload,
}

/// What the first device to see a conflict writes (spec §3.5, "Materialising copies"):
/// the copies, then a version of the original that collapses its sibling set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resolution {
    pub record_id: Uuid,
    pub copies: Vec<PendingCopy>,
    /// The visible content, rewritten as a new version (an item payload or a tombstone).
    pub collapse: Doc,
    pub vault_id: Option<Uuid>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct View {
    pub vaults: BTreeMap<Uuid, VaultView>,
    pub items: BTreeMap<Uuid, ItemView>,
    /// Live attachments only.
    pub attachments: BTreeMap<Uuid, AttachmentPayload>,
    pub resolutions: Vec<Resolution>,
    pub attachment_copies: Vec<AttachmentCopy>,
}

impl View {
    /// Items that are conflict copies (live or in Recently Deleted).
    pub fn conflict_copies(&self) -> Vec<Uuid> {
        self.items
            .iter()
            .filter(|(_, v)| {
                v.payload
                    .as_ref()
                    .is_some_and(|p| crate::payload::conflict_marker(p).is_some())
            })
            .map(|(id, _)| *id)
            .collect()
    }
}

#[derive(Clone, Debug, Default)]
pub struct Fold {
    retained: BTreeMap<RecordKey, Vec<Accepted>>,
    sets: BTreeMap<RecordKey, SiblingSet>,
}

impl Fold {
    /// Validates and retains `a`; it joins the sibling set if `admission` admits its position.
    pub fn accept(&mut self, a: Accepted, admission: &impl Admission) -> Result<Accept, Rejection> {
        check_shape(&a)?;
        let hash = a.hash();
        let versions = self.retained.entry(a.key()).or_default();
        if versions.iter().any(|v| v.hash() == hash) {
            return Ok(Accept::Duplicate);
        }
        let expected = own_counter(versions, &a.stream) + 1;
        let got = a.version.vector.get(&a.stream).copied().unwrap_or(0);
        if got != expected {
            return Err(Rejection::CounterNotNext { expected, got });
        }
        if admission.admits(&a.stream, a.seq) {
            self.sets.entry(a.key()).or_default().insert(a.sibling());
        }
        versions.push(a);
        Ok(Accept::New)
    }

    /// Accepts a whole segment's versions, or none of them: everything is validated first.
    /// Returns how many were new.
    pub fn accept_batch(
        &mut self,
        batch: Vec<Accepted>,
        admission: &impl Admission,
    ) -> Result<usize, Rejection> {
        let mut counters: BTreeMap<(RecordKey, DeviceId), u64> = BTreeMap::new();
        let mut seen = BTreeSet::new();
        for a in &batch {
            check_shape(a)?;
            let hash = a.hash();
            let retained = self.retained.get(&a.key()).map_or(&[][..], |v| v);
            if seen.contains(&hash) || retained.iter().any(|v| v.hash() == hash) {
                continue;
            }
            let counter = counters
                .entry((a.key(), a.stream))
                .or_insert_with(|| own_counter(retained, &a.stream));
            let got = a.version.vector.get(&a.stream).copied().unwrap_or(0);
            if got != *counter + 1 {
                return Err(Rejection::CounterNotNext {
                    expected: *counter + 1,
                    got,
                });
            }
            *counter = got;
            seen.insert(hash);
        }
        let mut new = 0;
        for a in batch {
            if self.accept(a, admission)? == Accept::New {
                new += 1;
            }
        }
        Ok(new)
    }

    /// Rebuilds every sibling set from the retained versions under a new admission policy.
    pub fn refold(&mut self, admission: &impl Admission) {
        self.sets.clear();
        for (key, versions) in &self.retained {
            for v in versions {
                if admission.admits(&v.stream, v.seq) {
                    self.sets.entry(*key).or_default().insert(v.sibling());
                }
            }
        }
    }

    pub fn set(&self, kind: RecordKind, id: Uuid) -> Option<&SiblingSet> {
        self.sets.get(&(kind, id))
    }

    pub fn sets(&self) -> impl Iterator<Item = (&RecordKey, &SiblingSet)> {
        self.sets.iter()
    }

    pub fn retained(&self) -> impl Iterator<Item = &Accepted> {
        self.retained.values().flatten()
    }

    pub fn contains(&self, kind: RecordKind, id: Uuid) -> bool {
        self.retained.contains_key(&(kind, id))
    }

    /// The version a new local write by `author` gets: it dominates every sibling.
    pub fn next_version(&self, kind: RecordKind, id: Uuid, author: DeviceId, hlc: u64) -> Version {
        let key = (kind, id);
        let mut vector = self
            .sets
            .get(&key)
            .map(|s| join(s.siblings().iter().map(|x| &x.version.vector)))
            .unwrap_or_default();
        let own = own_counter(self.retained.get(&key).map_or(&[][..], |v| v), &author);
        let counter = vector.get(&author).copied().unwrap_or(0).max(own) + 1;
        vector.insert(author, counter);
        Version {
            vector,
            hlc,
            author,
        }
    }

    pub fn view(&self) -> View {
        let mut view = View::default();
        for ((kind, id), set) in &self.sets {
            if *kind == RecordKind::Attachment {
                if let Some((_, p)) = present_attachment(set) {
                    view.attachments.insert(*id, p.clone());
                }
            }
        }
        for ((kind, id), set) in &self.sets {
            if *kind != RecordKind::Item {
                continue;
            }
            let p = present_item(*id, set);
            let Some(visible) = p.visible else { continue };
            let payload = match &visible.doc {
                Doc::Item(x) => Some(x.clone()),
                _ => None,
            };
            view.items.insert(
                *id,
                ItemView {
                    state: p.state,
                    vault_id: visible.vault_id,
                    payload: payload.clone(),
                },
            );
            let copies: Vec<PendingCopy> = p
                .copies
                .iter()
                .filter(|c| !self.contains(RecordKind::Item, c.copy_id))
                .map(|c| {
                    let Doc::Item(source) = &c.source.doc else {
                        unreachable!("copies are made of items")
                    };
                    let map: Vec<(Uuid, Uuid)> = attachment_refs(source)
                        .into_iter()
                        .map(|r| (r, copy_attachment_id(c.copy_id, r)))
                        .collect();
                    let marker = ConflictMarker {
                        of: *id,
                        version: c.source.hash,
                        from_device: c.source.version.author,
                    };
                    PendingCopy {
                        copy_id: c.copy_id,
                        vault_id: c.source.vault_id,
                        payload: ItemPayload {
                            item_json: copy_item_json(source, c.copy_id, &marker, &map)
                                .expect("item payloads are JSON objects"),
                            deleted_at: if c.trashed { source.deleted_at } else { None },
                            // Filled with the copy's own version when it is written.
                            content_from: Vector::new(),
                        },
                    }
                })
                .collect();
            if !copies.is_empty() {
                view.resolutions.push(Resolution {
                    record_id: *id,
                    copies,
                    collapse: visible.doc.clone(),
                    vault_id: visible.vault_id,
                });
            }
            if let Some(payload) = &payload {
                for (copy_att, original) in copied_attachment_refs(payload) {
                    if self.contains(RecordKind::Attachment, copy_att) {
                        continue;
                    }
                    if let Some(source) = view.attachments.get(&original) {
                        let mut a = source.clone();
                        a.item_id = *id;
                        view.attachment_copies.push(AttachmentCopy {
                            id: copy_att,
                            vault_id: visible.vault_id,
                            payload: a,
                        });
                    }
                }
            }
        }
        for ((kind, id), set) in &self.sets {
            if *kind != RecordKind::Vault {
                continue;
            }
            let has_live = view
                .items
                .values()
                .any(|i| i.state == ItemState::Live && i.vault_id == Some(*id));
            if let Some(p) = present_vault(set, has_live) {
                view.vaults.insert(
                    *id,
                    VaultView {
                        name: p.payload.name.clone(),
                        wrapped_key: p.payload.wrapped_key.clone(),
                        deleted: p.deleted,
                        revived: p.revived,
                        key_mismatch: p.key_mismatch,
                    },
                );
            }
        }
        view
    }
}

fn check_shape(a: &Accepted) -> Result<(), Rejection> {
    if a.version.author != a.stream {
        return Err(Rejection::WrongAuthor);
    }
    match a.doc.kind() {
        Some(k) if k != a.kind => Err(Rejection::KindMismatch),
        None if a.kind == RecordKind::Vault => Err(Rejection::VaultTombstone),
        _ => Ok(()),
    }
}

fn own_counter(versions: &[Accepted], author: &DeviceId) -> u64 {
    versions
        .iter()
        .filter(|v| &v.version.author == author)
        .filter_map(|v| v.version.vector.get(author).copied())
        .max()
        .unwrap_or(0)
}
```

- [ ] **Step 4: Run, expect success.** `cargo test -p keyorra-sync fold::` → all pass; `cargo clippy -p keyorra-sync --all-targets -- -D warnings` clean; `cargo fmt --all`.

- [ ] **Step 5: Commit.**

```bash
git add crates/keyorra-sync/src/fold.rs crates/keyorra-sync/src/lib.rs
git commit -m "sync: the fold with validation, admission hook and resolutions"
```

### Task 8: Transport trait and in-memory transport

**Files:** Create `crates/keyorra-sync/src/transport.rs`; modify `crates/keyorra-sync/src/lib.rs`.

The subset of the spec's `Transport` that A1b needs (streams, segments, append). Headers, snapshots and chunks are added by the plans that use them.

- [ ] **Step 1: Failing tests.** Add `pub mod transport;` to `lib.rs` (keep the module lines sorted) and create `crates/keyorra-sync/src/transport.rs` with only the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::Value;
    use crate::segment::{chain_genesis, seal_segment, StreamPosition};
    use ed25519_dalek::SigningKey;
    use keyorra_core::crypto::Key;

    fn segment(device: DeviceId, first_seq: u64, entry: u64) -> Vec<u8> {
        let at = StreamPosition {
            device_id: device,
            first_seq,
            prev_hash: chain_genesis(&[0; 16], &device),
        };
        let mut rng = rand::rngs::OsRng;
        seal_segment(
            &Key::from_bytes([1; 32]),
            &SigningKey::from_bytes(&[2; 32]),
            &at,
            vec![Value::Uint(entry)],
            &mut rng,
        )
        .unwrap()
    }

    #[test]
    fn stores_by_device_and_first_seq() {
        let t = MemoryTransport::new();
        let (a, b) = ([1; 16], [2; 16]);
        assert_eq!(
            t.append(&segment(a, 1, 0)).unwrap(),
            AppendOutcome::Appended
        );
        assert_eq!(
            t.append(&segment(a, 2, 0)).unwrap(),
            AppendOutcome::Appended
        );
        assert_eq!(
            t.append(&segment(b, 1, 0)).unwrap(),
            AppendOutcome::Appended
        );
        assert_eq!(t.streams().unwrap(), vec![a, b]);
        assert_eq!(t.segments(&a, 0).unwrap().len(), 2);
        assert_eq!(t.segments(&a, 1).unwrap().len(), 1);
        assert_eq!(t.segments(&[9; 16], 0).unwrap(), vec![]);
        assert_eq!(t.dump().len(), 3);
    }

    #[test]
    fn retries_are_idempotent_and_overwrites_conflict() {
        let t = MemoryTransport::new();
        let seg = segment([1; 16], 1, 0);
        t.append(&seg).unwrap();
        assert_eq!(t.append(&seg).unwrap(), AppendOutcome::AlreadyThere);
        assert_eq!(
            t.append(&segment([1; 16], 1, 5)).unwrap(),
            AppendOutcome::Conflict
        );
        assert!(t.append(b"junk").is_err());
    }

    #[test]
    fn clones_share_storage() {
        let t = MemoryTransport::new();
        let u = t.clone();
        t.append(&segment([1; 16], 1, 0)).unwrap();
        assert_eq!(u.streams().unwrap().len(), 1);
    }
}
```

- [ ] **Step 2: Run, expect failure.** `cargo test -p keyorra-sync transport::` → does not compile (`Transport`, `MemoryTransport`, `Fetched`, `AppendOutcome` missing).

- [ ] **Step 3: Implement.** Put this above the test module in `crates/keyorra-sync/src/transport.rs`:

```rust
//! Where segments live: the transport trait, and an in-memory transport for tests and for the
//! engine's own test suites. Folder (A2) and server (B2) transports implement the same trait;
//! headers, snapshots and chunks are added to it by the plans that need them.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::error::Result;
use crate::segment::SegmentHeader;
use crate::DeviceId;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fetched<T> {
    Ready(T),
    /// Exists but cannot be read yet (not downloaded, half-synced): try again later.
    Pending,
    /// Listed but gone.
    Missing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppendOutcome {
    Appended,
    /// The same bytes were already there (a retried append that had succeeded).
    AlreadyThere,
    /// Different bytes already occupy this position of the stream.
    Conflict,
}

pub trait Transport {
    /// Devices that have a stream.
    fn streams(&self) -> Result<Vec<DeviceId>>;
    /// Segments of `stream` that start after `after_seq`, in no particular order.
    fn segments(&self, stream: &DeviceId, after_seq: u64) -> Result<Vec<Fetched<Vec<u8>>>>;
    /// Stores a segment under its device and first sequence number (from its header).
    fn append(&self, segment: &[u8]) -> Result<AppendOutcome>;
}

/// One stream: segment bytes by first sequence number.
type Stream = BTreeMap<u64, Vec<u8>>;

/// Segments in memory, shared by every clone (one clone per simulated device).
#[derive(Clone, Debug, Default)]
pub struct MemoryTransport {
    streams: Arc<Mutex<BTreeMap<DeviceId, Stream>>>,
}

impl MemoryTransport {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every stored segment, for "what the transport sees" and for tests.
    pub fn dump(&self) -> Vec<(DeviceId, u64, usize)> {
        let streams = self.streams.lock().unwrap();
        streams
            .iter()
            .flat_map(|(d, segs)| segs.iter().map(move |(seq, b)| (*d, *seq, b.len())))
            .collect()
    }
}

impl Transport for MemoryTransport {
    fn streams(&self) -> Result<Vec<DeviceId>> {
        Ok(self.streams.lock().unwrap().keys().copied().collect())
    }

    fn segments(&self, stream: &DeviceId, after_seq: u64) -> Result<Vec<Fetched<Vec<u8>>>> {
        let streams = self.streams.lock().unwrap();
        Ok(streams
            .get(stream)
            .map(|segs| {
                segs.range(after_seq + 1..)
                    .map(|(_, b)| Fetched::Ready(b.clone()))
                    .collect()
            })
            .unwrap_or_default())
    }

    fn append(&self, segment: &[u8]) -> Result<AppendOutcome> {
        let header = SegmentHeader::parse(segment)?;
        let mut streams = self.streams.lock().unwrap();
        let stream = streams.entry(header.device_id).or_default();
        match stream.get(&header.first_seq) {
            Some(existing) if existing == segment => Ok(AppendOutcome::AlreadyThere),
            Some(_) => Ok(AppendOutcome::Conflict),
            None => {
                stream.insert(header.first_seq, segment.to_vec());
                Ok(AppendOutcome::Appended)
            }
        }
    }
}
```

- [ ] **Step 4: Run, expect success.** `cargo test -p keyorra-sync transport::` → all pass; `cargo clippy -p keyorra-sync --all-targets -- -D warnings` clean; `cargo fmt --all`.

- [ ] **Step 5: Commit.**

```bash
git add crates/keyorra-sync/src/transport.rs crates/keyorra-sync/src/lib.rs
git commit -m "sync: transport trait and in-memory transport"
```

### Task 9: Fault-injecting transport

**Files:** Create `crates/keyorra-sync/src/faults.rs`; modify `crates/keyorra-sync/src/lib.rs`.

Wraps any transport; every fault is transient and seeded. Compiled for tests and behind the `test-utils` feature, so A2 and B2 can rerun the engine suites through it.

- [ ] **Step 1: Failing tests.** Add `#[cfg(any(test, feature = "test-utils"))] pub mod faults;` to `lib.rs` (keep the module lines sorted) and create `crates/keyorra-sync/src/faults.rs` with only the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::Value;
    use crate::segment::{chain_genesis, seal_segment, StreamPosition};
    use crate::transport::MemoryTransport;
    use ed25519_dalek::SigningKey;
    use keyorra_core::crypto::Key;

    const D: DeviceId = [1; 16];

    fn store(n: u64) -> MemoryTransport {
        let t = MemoryTransport::new();
        let mut rng = rand::rngs::OsRng;
        for seq in 1..=n {
            let at = StreamPosition {
                device_id: D,
                first_seq: seq,
                prev_hash: chain_genesis(&[0; 16], &D),
            };
            let seg = seal_segment(
                &Key::from_bytes([1; 32]),
                &SigningKey::from_bytes(&[2; 32]),
                &at,
                vec![Value::Uint(seq)],
                &mut rng,
            )
            .unwrap();
            t.append(&seg).unwrap();
        }
        t
    }

    #[test]
    fn no_faults_is_transparent() {
        let t = store(5);
        let f = Faulty::new(t.clone(), Faults::NONE, 1);
        assert_eq!(f.segments(&D, 0).unwrap(), t.segments(&D, 0).unwrap());
        assert_eq!(f.streams().unwrap(), vec![D]);
    }

    #[test]
    fn same_seed_same_faults() {
        let t = store(20);
        let a = Faulty::new(t.clone(), Faults::CHAOS, 42);
        let b = Faulty::new(t, Faults::CHAOS, 42);
        for _ in 0..5 {
            assert_eq!(a.segments(&D, 0).unwrap(), b.segments(&D, 0).unwrap());
        }
    }

    #[test]
    fn chaos_produces_every_kind_of_damage() {
        let t = store(20);
        let clean = t.segments(&D, 0).unwrap();
        let f = Faulty::new(t, Faults::CHAOS, 7);
        let (mut pending, mut damaged, mut duplicated, mut short) = (0, 0, 0, 0);
        for _ in 0..50 {
            let got = f.segments(&D, 0).unwrap();
            short += usize::from(got.len() < clean.len());
            duplicated += usize::from(got.len() > clean.len());
            for g in &got {
                match g {
                    Fetched::Pending => pending += 1,
                    Fetched::Ready(b) if !clean.contains(&Fetched::Ready(b.clone())) => {
                        damaged += 1
                    }
                    _ => {}
                }
            }
        }
        assert!(pending > 0 && damaged > 0 && duplicated > 0 && short > 0);
    }

    #[test]
    fn appends_can_fail_before_or_after_landing() {
        let t = MemoryTransport::new();
        let seg = store(1).segments(&D, 0).unwrap().remove(0);
        let Fetched::Ready(seg) = seg else { panic!() };
        let before = Faulty::new(
            t.clone(),
            Faults {
                fail_before_append: 100,
                ..Faults::NONE
            },
            1,
        );
        assert!(before.append(&seg).is_err());
        assert!(t.streams().unwrap().is_empty());
        let after = Faulty::new(
            t.clone(),
            Faults {
                fail_after_append: 100,
                ..Faults::NONE
            },
            1,
        );
        assert!(after.append(&seg).is_err());
        assert_eq!(t.streams().unwrap(), vec![D]);
    }
}
```

- [ ] **Step 2: Run, expect failure.** `cargo test -p keyorra-sync faults::` → does not compile (`Faulty`, `Faults` missing).

- [ ] **Step 3: Implement.** Put this above the test module in `crates/keyorra-sync/src/faults.rs`:

```rust
//! A transport that misbehaves the way synced folders and networks do (spec §11, suite 5):
//! files not downloaded yet, half-synced files, bit rot, sync-client duplicates, any listing
//! order, streams that show up late, writes that fail before or after they land.
//! Every fault is transient and drawn from a seeded generator, so a failing case replays.

use std::sync::Mutex;

use crate::error::{Error, Result};
use crate::transport::{AppendOutcome, Fetched, Transport};
use crate::DeviceId;

/// Probabilities in percent, per segment read or per append.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Faults {
    /// A stream is left out of the listing.
    pub hide_stream: u8,
    /// A segment is reported as `Pending`.
    pub pending: u8,
    /// A segment is left out of the listing.
    pub omit: u8,
    /// A segment is returned cut short (half-synced).
    pub truncate: u8,
    /// One bit of a segment is flipped.
    pub flip: u8,
    /// A segment is listed twice.
    pub duplicate: u8,
    /// The listing comes back shuffled.
    pub shuffle: u8,
    /// An append fails without storing anything.
    pub fail_before_append: u8,
    /// An append stores the segment, then reports a failure.
    pub fail_after_append: u8,
}

impl Faults {
    pub const NONE: Faults = Faults {
        hide_stream: 0,
        pending: 0,
        omit: 0,
        truncate: 0,
        flip: 0,
        duplicate: 0,
        shuffle: 0,
        fail_before_append: 0,
        fail_after_append: 0,
    };

    /// Everything at once, often enough to matter.
    pub const CHAOS: Faults = Faults {
        hide_stream: 10,
        pending: 15,
        omit: 10,
        truncate: 10,
        flip: 5,
        duplicate: 15,
        shuffle: 50,
        fail_before_append: 15,
        fail_after_append: 15,
    };
}

pub struct Faulty<T> {
    inner: T,
    faults: Mutex<Faults>,
    state: Mutex<u64>,
}

impl<T: Transport> Faulty<T> {
    pub fn new(inner: T, faults: Faults, seed: u64) -> Self {
        Faulty {
            inner,
            faults: Mutex::new(faults),
            state: Mutex::new(seed),
        }
    }

    /// Changes the fault rates (e.g. `Faults::NONE` to let everything heal).
    pub fn set_faults(&self, faults: Faults) {
        *self.faults.lock().unwrap() = faults;
    }

    /// SplitMix64.
    fn next(&self) -> u64 {
        let mut s = self.state.lock().unwrap();
        *s = s.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = *s;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn roll(&self, percent: u8) -> bool {
        percent > 0 && self.next() % 100 < u64::from(percent)
    }

    fn faults(&self) -> Faults {
        *self.faults.lock().unwrap()
    }
}

impl<T: Transport> Transport for Faulty<T> {
    fn streams(&self) -> Result<Vec<DeviceId>> {
        let f = self.faults();
        let mut out = self.inner.streams()?;
        out.retain(|_| !self.roll(f.hide_stream));
        Ok(out)
    }

    fn segments(&self, stream: &DeviceId, after_seq: u64) -> Result<Vec<Fetched<Vec<u8>>>> {
        let f = self.faults();
        let mut out = Vec::new();
        for fetched in self.inner.segments(stream, after_seq)? {
            let Fetched::Ready(mut bytes) = fetched else {
                out.push(fetched);
                continue;
            };
            if self.roll(f.omit) {
                continue;
            }
            if self.roll(f.pending) {
                out.push(Fetched::Pending);
                continue;
            }
            if self.roll(f.truncate) {
                let keep = (self.next() as usize) % bytes.len();
                bytes.truncate(keep);
            } else if self.roll(f.flip) {
                let bit = (self.next() as usize) % (bytes.len() * 8);
                bytes[bit / 8] ^= 1 << (bit % 8);
            }
            if self.roll(f.duplicate) {
                out.push(Fetched::Ready(bytes.clone()));
            }
            out.push(Fetched::Ready(bytes));
        }
        if self.roll(f.shuffle) {
            for i in (1..out.len()).rev() {
                let j = (self.next() as usize) % (i + 1);
                out.swap(i, j);
            }
        }
        Ok(out)
    }

    fn append(&self, segment: &[u8]) -> Result<AppendOutcome> {
        let f = self.faults();
        if self.roll(f.fail_before_append) {
            return Err(Error::Transport("append failed".into()));
        }
        let outcome = self.inner.append(segment)?;
        if self.roll(f.fail_after_append) {
            return Err(Error::Transport("append outcome lost".into()));
        }
        Ok(outcome)
    }
}
```

- [ ] **Step 4: Run, expect success.** `cargo test -p keyorra-sync faults::` → all pass; `cargo clippy -p keyorra-sync --all-targets -- -D warnings` clean; `cargo fmt --all`.

- [ ] **Step 5: Commit.**

```bash
git add crates/keyorra-sync/src/faults.rs crates/keyorra-sync/src/lib.rs
git commit -m "sync: fault-injecting transport"
```

### Task 10: The engine and a simulated cluster

**Files:** Create `crates/keyorra-sync/src/engine.rs`, `crates/keyorra-sync/src/engine/tests.rs`, `crates/keyorra-sync/src/testkit.rs`; modify `crates/keyorra-sync/src/lib.rs`.

One device: local writes (vault create/rename/delete, item save/trash/restore/purge, attachment add/remove), `sync` = pull every readable segment in order (waiting for vault keys from other streams, all-or-nothing per segment), materialise conflict copies and their attachment records, push its own stream (retrying the same bytes after a failed append). `testkit::Cluster` simulates several devices sharing one `MemoryTransport` through per-device `Faulty` links, with per-device wall clocks.

- [ ] **Step 1: Failing tests.** Add to `lib.rs`:

```rust
pub mod engine;
#[cfg(any(test, feature = "test-utils"))]
pub mod testkit;
```

Create `crates/keyorra-sync/src/testkit.rs`:

```rust
//! A simulated set of devices sharing one transport, for the engine's tests and for the
//! transport plans that rerun them (spec §11, suites 3–5, 9).

use ed25519_dalek::SigningKey;
use keyorra_core::crypto::Key;
use rand::rngs::StdRng;
use rand::SeedableRng;
use uuid::Uuid;

use crate::engine::{Engine, StaticDirectory};
use crate::error::Result;
use crate::faults::{Faults, Faulty};
use crate::fold::View;
use crate::transport::MemoryTransport;
use crate::DeviceId;

pub const ACCOUNT_ID: [u8; 16] = [0x10; 16];
/// 2026-09-21, a fixed start so runs repeat.
pub const START_MS: u64 = 1_790_000_000_000;

pub struct Cluster {
    pub store: MemoryTransport,
    pub links: Vec<Faulty<MemoryTransport>>,
    pub devices: Vec<Engine<StdRng>>,
    pub directory: StaticDirectory,
    /// Wall clock of each device (they may disagree).
    pub clocks: Vec<u64>,
}

pub fn device_id(i: usize) -> DeviceId {
    [i as u8 + 1; 16]
}

impl Cluster {
    pub fn new(n: usize, seed: u64, faults: Faults) -> Cluster {
        let store = MemoryTransport::new();
        let mut directory = StaticDirectory::default();
        let mut devices = Vec::new();
        let mut links = Vec::new();
        for i in 0..n {
            let signer = SigningKey::from_bytes(&[0x40 + i as u8; 32]);
            directory.0.insert(device_id(i), signer.verifying_key());
            devices.push(Engine::new(
                device_id(i),
                signer,
                ACCOUNT_ID,
                Key::from_bytes([0x30; 32]),
                StdRng::seed_from_u64(seed.wrapping_add(i as u64)),
            ));
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
            directory,
            clocks: vec![START_MS; n],
        }
    }

    pub fn sync(&mut self, i: usize) -> Result<()> {
        self.devices[i].sync(&self.links[i], &self.directory, self.clocks[i])
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
        assert!(
            first.resolutions.is_empty(),
            "conflict copies left to materialise"
        );
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

Create `crates/keyorra-sync/src/engine/tests.rs`:

```rust
use uuid::Uuid;

use super::*;
use crate::cbor::Value;
use crate::envelope::Version;
use crate::faults::Faults;
use crate::payload::conflict_marker;
use crate::testkit::{device_id, Cluster, START_MS};

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
fn a_purge_is_final_but_a_concurrent_edit_survives_as_a_copy() {
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
    assert_eq!(view.items[&ITEM].state, ItemState::Purged);
    let copies = view.conflict_copies();
    assert_eq!(copies.len(), 1);
    assert_eq!(title(&view, copies[0]), "still needed");
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
        first_seq: 1,
        prev_hash: chain_genesis(&crate::testkit::ACCOUNT_ID, &device_id(1)),
    };
    let signer = SigningKey::from_bytes(&[0x41; 32]);
    let k_seg = segment_key(&Key::from_bytes([0x30; 32]), &crate::testkit::ACCOUNT_ID);
    let entry = Value::map(vec![("put", env.to_value())]);
    let mut rng = rand::rngs::OsRng;
    let seg = seal_segment(&k_seg, &signer, &at, vec![entry], &mut rng).unwrap();
    c.store.append(&seg).unwrap();
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
```

Create `crates/keyorra-sync/src/engine.rs` containing only:

```rust
#[cfg(test)]
mod tests;
```

- [ ] **Step 2: Run, expect failure.** `cargo test -p keyorra-sync engine::` → does not compile (`Engine`, `Event`, `StaticDirectory` missing).

- [ ] **Step 3: Implement.** Replace `engine.rs` with:

```rust
//! The sync engine of one device: local writes, pulling other devices' streams into the fold,
//! materialising conflict copies, and pushing its own stream (spec §4.1–4.4, without the trust
//! layer). Plan A1c adds endorsement and revocation (through [`Directory`] and
//! [`Admission`](crate::fold::Admission)), checkpoints, causal delivery, headers, snapshots
//! and clone detection.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{SigningKey, VerifyingKey};
use keyorra_core::crypto::{self, Key};
use keyorra_core::model::SCHEMA_VERSION;
use rand::{CryptoRng, RngCore};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::cbor::Value;
use crate::clock::{Hlc, Observed};
use crate::envelope::{Envelope, RecordKind};
use crate::error::{Error, Result};
use crate::fold::{Accepted, AdmitAll, Fold, View};
use crate::keys::segment_key;
use crate::payload::{AttachmentPayload, Doc, ItemPayload, VaultPayload};
use crate::present::{present_item, present_vault, ItemState};
use crate::segment::{
    chain, chain_genesis, open_segment, seal_segment, SegmentHeader, StreamPosition,
};
use crate::transport::{AppendOutcome, Fetched, Transport};
use crate::{AccountId, DeviceId};

/// Entries per segment; keeps segments well below the 4 MiB cap for ordinary records.
const MAX_ENTRIES_PER_SEGMENT: usize = 256;

/// Whose signatures count. Plan A1c derives it from endorsements; tests use a fixed map.
pub trait Directory {
    fn verifying_key(&self, device: &DeviceId) -> Option<VerifyingKey>;
}

#[derive(Clone, Debug, Default)]
pub struct StaticDirectory(pub BTreeMap<DeviceId, VerifyingKey>);

impl Directory for StaticDirectory {
    fn verifying_key(&self, device: &DeviceId) -> Option<VerifyingKey> {
        self.0.get(device).copied()
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
    /// A segment waits for something (a vault key from another stream, a newer app).
    Waiting {
        from: DeviceId,
        first_seq: u64,
        reason: String,
    },
    /// A signed segment broke the rules; the stream is no longer read. An alarm.
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
    /// Someone else wrote at this device's next position (clone detection is plan A1c).
    OwnStreamConflict,
}

struct Unsent {
    bytes: Vec<u8>,
    versions: usize,
    last_seq: u64,
    last_hash: [u8; 32],
}

enum Stop {
    Wait(String),
    Reject(String),
}

pub struct Engine<R> {
    device: DeviceId,
    signer: SigningKey,
    account_id: AccountId,
    account_key: Key,
    segment_key: Key,
    rng: R,
    hlc: Hlc,
    fold: Fold,
    vault_keys: BTreeMap<Uuid, Key>,
    /// Per other device: last applied (seq, chain hash).
    heads: BTreeMap<DeviceId, (u64, [u8; 32])>,
    blocked: BTreeSet<DeviceId>,
    /// Last own (seq, chain hash) confirmed by the transport.
    sent: (u64, [u8; 32]),
    unsent: Option<Unsent>,
    outbox: Vec<Value>,
    next_seq: u64,
    events: Vec<Event>,
}

impl<R: RngCore + CryptoRng> Engine<R> {
    pub fn new(
        device: DeviceId,
        signer: SigningKey,
        account_id: AccountId,
        account_key: Key,
        rng: R,
    ) -> Self {
        Engine {
            device,
            signer,
            account_id,
            segment_key: segment_key(&account_key, &account_id),
            account_key,
            rng,
            hlc: Hlc::default(),
            fold: Fold::default(),
            vault_keys: BTreeMap::new(),
            heads: BTreeMap::new(),
            blocked: BTreeSet::new(),
            sent: (0, chain_genesis(&account_id, &device)),
            unsent: None,
            outbox: Vec::new(),
            next_seq: 1,
            events: Vec::new(),
        }
    }

    pub fn device(&self) -> DeviceId {
        self.device
    }

    pub fn view(&self) -> View {
        self.fold.view()
    }

    pub fn fold(&self) -> &Fold {
        &self.fold
    }

    /// Nothing waiting to be pushed.
    pub fn is_idle(&self) -> bool {
        self.outbox.is_empty() && self.unsent.is_none()
    }

    pub fn take_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
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

    pub fn delete_vault(&mut self, id: Uuid, wall_ms: u64) -> Result<()> {
        let mut p = self.vault_payload(id)?;
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
        let doc = Doc::Item(ItemPayload {
            item_json: Zeroizing::new(item_json.to_vec()),
            deleted_at: None,
            content_from: Default::default(), // this write: filled in by `write`
        });
        self.write(RecordKind::Item, id, Some(vault_id), doc, wall_ms)
    }

    pub fn trash_item(&mut self, id: Uuid, at_secs: u64, wall_ms: u64) -> Result<()> {
        let (vault_id, mut p) = self.item_in_state(id, ItemState::Live)?;
        p.deleted_at = Some(at_secs);
        self.write(RecordKind::Item, id, vault_id, Doc::Item(p), wall_ms)
    }

    pub fn restore_item(&mut self, id: Uuid, wall_ms: u64) -> Result<()> {
        let (vault_id, mut p) = self.item_in_state(id, ItemState::Trashed)?;
        p.deleted_at = None;
        self.write(RecordKind::Item, id, vault_id, Doc::Item(p), wall_ms)
    }

    /// Permanently deletes an item in Recently Deleted.
    pub fn purge_item(&mut self, id: Uuid, wall_ms: u64) -> Result<()> {
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
        match (p.state == want, p.visible.map(|v| (&v.doc, v.vault_id))) {
            (true, Some((Doc::Item(payload), vault_id))) => Ok((vault_id, payload.clone())),
            _ => Err(Error::NotFound(format!("item {id} in state {want:?}"))),
        }
    }

    fn write(
        &mut self,
        kind: RecordKind,
        id: Uuid,
        vault_id: Option<Uuid>,
        doc: Doc,
        wall_ms: u64,
    ) -> Result<()> {
        let hlc = self.hlc.tick(wall_ms);
        let version = self.fold.next_version(kind, id, self.device, hlc);
        let mut doc = doc;
        if let Doc::Item(p) = &mut doc {
            if p.content_from.is_empty() {
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
        let accepted = Accepted {
            stream: self.device,
            seq: self.next_seq,
            kind,
            record_id: id,
            vault_id,
            version,
            doc,
        };
        self.fold
            .accept(accepted, &AdmitAll)
            .expect("a local write always follows the rules");
        self.outbox
            .push(Value::map(vec![("put", envelope.to_value())]));
        self.next_seq += 1;
        Ok(())
    }

    // ---- sync ----

    /// One round: pull everything readable, materialise conflict copies, push.
    /// Transport errors while pulling are returned; push failures are logged and retried.
    pub fn sync(
        &mut self,
        transport: &impl Transport,
        directory: &impl Directory,
        wall_ms: u64,
    ) -> Result<()> {
        self.pull(transport, directory, wall_ms)?;
        self.materialize(wall_ms)?;
        self.push(transport);
        Ok(())
    }

    fn pull(
        &mut self,
        transport: &impl Transport,
        directory: &impl Directory,
        wall_ms: u64,
    ) -> Result<()> {
        let streams: Vec<DeviceId> = transport
            .streams()?
            .into_iter()
            .filter(|d| *d != self.device && !self.blocked.contains(d))
            .collect();
        loop {
            let mut progress = false;
            for stream in &streams {
                progress |= self.pull_stream(transport, directory, stream, wall_ms)?;
            }
            if !progress {
                return Ok(());
            }
        }
    }

    /// Applies every segment of `stream` that is next in line. Returns whether any was applied.
    fn pull_stream(
        &mut self,
        transport: &impl Transport,
        directory: &impl Directory,
        stream: &DeviceId,
        wall_ms: u64,
    ) -> Result<bool> {
        if self.blocked.contains(stream) {
            return Ok(false);
        }
        let Some(author) = directory.verifying_key(stream) else {
            return Ok(false);
        };
        let (mut head_seq, mut head_hash) = self
            .heads
            .get(stream)
            .copied()
            .unwrap_or((0, chain_genesis(&self.account_id, stream)));
        let mut candidates: Vec<(u64, Vec<u8>)> = transport
            .segments(stream, head_seq)?
            .into_iter()
            .filter_map(|f| match f {
                Fetched::Ready(b) => Some(b),
                Fetched::Pending | Fetched::Missing => None,
            })
            .filter_map(|b| {
                let h = SegmentHeader::parse(&b).ok()?;
                (h.device_id == *stream && h.first_seq > head_seq).then_some((h.first_seq, b))
            })
            .collect();
        candidates.sort_by_key(|(seq, _)| *seq);
        let mut applied = false;
        loop {
            let want = head_seq + 1;
            let mut opened = None;
            let mut tried = false;
            for (_, bytes) in candidates.iter().filter(|(s, _)| *s == want) {
                tried = true;
                if let Ok(seg) = open_segment(&self.segment_key, &author, bytes) {
                    opened = Some(seg);
                    break;
                }
            }
            let Some(segment) = opened else {
                if tried {
                    self.events.push(Event::Unreadable {
                        from: *stream,
                        first_seq: want,
                    });
                }
                return Ok(applied);
            };
            if segment.header.prev_hash != head_hash {
                self.events.push(Event::Waiting {
                    from: *stream,
                    first_seq: want,
                    reason: "chain does not continue from the known head".into(),
                });
                return Ok(applied);
            }
            match self.decode_segment(stream, &segment.header, &segment.entries) {
                Ok((batch, keys)) => {
                    let observed: Vec<u64> = batch.iter().map(|a| a.version.hlc).collect();
                    match self.fold.accept_batch(batch, &AdmitAll) {
                        Ok(n) => {
                            self.vault_keys.extend(keys);
                            for hlc in observed {
                                if let Observed::TooFarAhead { ahead_ms } =
                                    self.hlc.observe(hlc, wall_ms)
                                {
                                    self.events.push(Event::ClockAhead {
                                        from: *stream,
                                        ahead_ms,
                                    });
                                }
                            }
                            self.events.push(Event::Pulled {
                                from: *stream,
                                versions: n,
                            });
                        }
                        Err(rejection) => {
                            self.reject(stream, want, rejection.to_string());
                            return Ok(applied);
                        }
                    }
                }
                Err(Stop::Wait(reason)) => {
                    self.events.push(Event::Waiting {
                        from: *stream,
                        first_seq: want,
                        reason,
                    });
                    return Ok(applied);
                }
                Err(Stop::Reject(reason)) => {
                    self.reject(stream, want, reason);
                    return Ok(applied);
                }
            }
            head_seq = segment.header.last_seq;
            head_hash = segment.header.last_hash;
            self.heads.insert(*stream, (head_seq, head_hash));
            applied = true;
        }
    }

    fn reject(&mut self, stream: &DeviceId, first_seq: u64, reason: String) {
        self.blocked.insert(*stream);
        self.events.push(Event::Rejected {
            from: *stream,
            first_seq,
            reason,
        });
    }

    /// Decodes a segment's entries; vault keys learned on the way are returned, not stored, so
    /// nothing changes unless the whole segment is accepted.
    #[allow(clippy::type_complexity)]
    fn decode_segment(
        &self,
        stream: &DeviceId,
        header: &SegmentHeader,
        entries: &[Value],
    ) -> std::result::Result<(Vec<Accepted>, Vec<(Uuid, Key)>), Stop> {
        let mut batch = Vec::new();
        let mut keys: Vec<(Uuid, Key)> = Vec::new();
        for (i, entry) in entries.iter().enumerate() {
            let put = entry
                .fields(&["put"])
                .and_then(|f| f.get("put").cloned())
                .map_err(|_| Stop::Reject("unknown entry".into()))?;
            let env = match Envelope::from_value(&put) {
                Ok(env) => env,
                Err(Error::Unsupported(what)) => {
                    return Err(Stop::Wait(format!("needs a newer app: {what}")))
                }
                Err(e) => return Err(Stop::Reject(e.to_string())),
            };
            let doc = if env.tombstone {
                Doc::Tombstone
            } else if env.kind == RecordKind::Vault {
                let body = env.body.as_deref().unwrap_or_default();
                let doc = Doc::decode(RecordKind::Vault, body)
                    .map_err(|e| Stop::Reject(e.to_string()))?;
                if let Doc::Vault(p) = &doc {
                    let key =
                        crypto::unwrap_vault_key(&self.account_key, env.record_id, &p.wrapped_key)
                            .map_err(|_| Stop::Reject("vault key does not unwrap".into()))?;
                    keys.push((env.record_id, key));
                }
                doc
            } else {
                let vault = env.vault_id.expect("checked by Envelope::from_value");
                let key = keys
                    .iter()
                    .rev()
                    .find(|(id, _)| *id == vault)
                    .map(|(_, k)| k)
                    .or_else(|| self.vault_keys.get(&vault))
                    .ok_or_else(|| Stop::Wait(format!("key of vault {vault} not known yet")))?;
                let plain = env
                    .open_body(key, &self.account_id)
                    .map_err(|_| Stop::Reject("body does not open".into()))?;
                Doc::decode(env.kind, &plain).map_err(|e| Stop::Reject(e.to_string()))?
            };
            batch.push(Accepted {
                stream: *stream,
                seq: header.first_seq + i as u64,
                kind: env.kind,
                record_id: env.record_id,
                vault_id: env.vault_id,
                version: env.version,
                doc,
            });
        }
        Ok((batch, keys))
    }

    /// Writes the conflict copies, and the attachment records they need, that the fold asks
    /// for (spec §3.5). Each pass removes what it wrote from the next view.
    fn materialize(&mut self, wall_ms: u64) -> Result<()> {
        for _ in 0..4 {
            let view = self.fold.view();
            if view.resolutions.is_empty() && view.attachment_copies.is_empty() {
                return Ok(());
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
        Ok(())
    }

    fn push(&mut self, transport: &impl Transport) {
        loop {
            if self.unsent.is_none() {
                if self.outbox.is_empty() {
                    return;
                }
                let take = self.outbox.len().min(MAX_ENTRIES_PER_SEGMENT);
                let entries: Vec<Value> = self.outbox.drain(..take).collect();
                let at = StreamPosition {
                    device_id: self.device,
                    first_seq: self.sent.0 + 1,
                    prev_hash: self.sent.1,
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
                    self.sent = (unsent.last_seq, unsent.last_hash);
                    self.events.push(Event::Pushed {
                        versions: unsent.versions,
                    });
                    self.unsent = None;
                }
                Ok(AppendOutcome::Conflict) => {
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

- [ ] **Step 4: Run, expect success.** `cargo test -p keyorra-sync engine::` → 12 passed (including `convergence_through_chaos_with_a_fixed_seed`); `cargo clippy -p keyorra-sync --all-targets -- -D warnings` and `cargo clippy -p keyorra-sync --features test-utils -- -D warnings` clean.

- [ ] **Step 5: Commit.**

```bash
git add crates/keyorra-sync/src/engine.rs crates/keyorra-sync/src/engine crates/keyorra-sync/src/testkit.rs crates/keyorra-sync/src/lib.rs
git commit -m "sync: first engine: local writes, pull, materialise, push"
```

### Task 11: Property tests

**Files:** Create `crates/keyorra-sync/src/convergence_tests.rs`; modify `crates/keyorra-sync/src/lib.rs`.

Three properties (48 cases each by default) and one fixed smoke run:
- `devices_converge_through_chaos`: 2–4 devices, up to 60 random operations (save, trash, restore, purge, attach, detach, rename/delete the vault, sync, clock ticks) through `Faults::CHAOS`; after healing, every device has the same `View`, nothing is left to materialise, and every copy the presentation asks for exists.
- `the_fold_does_not_depend_on_delivery_order`: all accepted versions replayed into a fresh `Fold` in a random interleaving that keeps each stream's order give the same `View`.
- `concurrent_edits_are_never_lost`: two concurrent edits of one item (either order, any clock gap, with or without chaos) both survive: one shown, one as the single conflict copy.

- [ ] **Step 1: Write the tests.** Append to `lib.rs`:

```rust

#[cfg(test)]
mod convergence_tests;
```

Create `crates/keyorra-sync/src/convergence_tests.rs`:

```rust
//! Property tests (spec §11, suite 6): random edits on several devices, delivered through a
//! misbehaving transport, always end in the same state everywhere, independent of order, and
//! concurrent edits are never silently dropped.

use std::collections::BTreeSet;

use proptest::prelude::*;
use uuid::Uuid;

use crate::envelope::RecordKind;
use crate::faults::Faults;
use crate::fold::{AdmitAll, Fold, View};
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
    Sync { dev: usize },
    Tick { ms: u16 },
}

fn op(devices: usize) -> impl Strategy<Value = Op> {
    let d = 0..devices;
    let i = 0..ITEMS;
    prop_oneof![
        4 => (d.clone(), i.clone()).prop_map(|(dev, item)| Op::Save { dev, item }),
        1 => (d.clone(), i.clone()).prop_map(|(dev, item)| Op::Trash { dev, item }),
        1 => (d.clone(), i.clone()).prop_map(|(dev, item)| Op::Restore { dev, item }),
        1 => (d.clone(), i.clone()).prop_map(|(dev, item)| Op::Purge { dev, item }),
        1 => (d.clone(), i.clone()).prop_map(|(dev, item)| Op::Attach { dev, item }),
        1 => (d.clone(), i.clone()).prop_map(|(dev, item)| Op::Detach { dev, item }),
        1 => d.clone().prop_map(|dev| Op::RenameVault { dev }),
        1 => d.clone().prop_map(|dev| Op::DeleteVault { dev }),
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

/// Runs `ops` on a fresh cluster; every save writes a unique title. Returns the cluster and
/// the vault id. Operations that do not apply (trash a missing item, …) are skipped.
fn run(devices: usize, seed: u64, faults: Faults, ops: &[Op]) -> (Cluster, Uuid) {
    let mut c = Cluster::new(devices, seed, Faults::NONE);
    let vault = c.devices[0].create_vault("Personal", START_MS).unwrap();
    c.heal();
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
                let att = c.devices[dev]
                    .add_attachment(vault, id, "file", 1, c.clocks[dev])
                    .unwrap();
                refs.push(att);
                let json = Cluster::item_json(id, &title, &refs);
                c.devices[dev]
                    .save_item(vault, id, &json, c.clocks[dev])
                    .unwrap();
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
                c.devices[dev]
                    .save_item(vault, id, &json, c.clocks[dev])
                    .unwrap();
            }
            Op::RenameVault { dev } => {
                let _ = c.devices[dev].rename_vault(vault, &format!("v{step}"), c.clocks[dev]);
            }
            Op::DeleteVault { dev } => {
                let _ = c.devices[dev].delete_vault(vault, c.clocks[dev]);
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
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    #[test]
    fn devices_converge_through_chaos(
        devices in 2usize..=4,
        seed in any::<u64>(),
        ops in prop::collection::vec(op(4), 1..60),
    ) {
        let ops: Vec<Op> = ops.into_iter().map(|o| clamp(o, devices)).collect();
        let (c, _) = run(devices, seed, Faults::CHAOS, &ops);
        c.assert_converged();
        for d in &c.devices {
            assert_nothing_unaccounted(d.fold(), &d.view());
        }
    }

    #[test]
    fn the_fold_does_not_depend_on_delivery_order(
        seed in any::<u64>(),
        ops in prop::collection::vec(op(3), 1..40),
        shuffle in any::<u64>(),
    ) {
        let (c, _) = run(3, seed, Faults::NONE, &ops);
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
            let live: Vec<usize> = (0..streams.len()).filter(|i| !streams[*i].is_empty()).collect();
            let pick = live[(state >> 33) as usize % live.len()];
            let next = streams[pick].remove(0);
            fold.accept(next, &AdmitAll).unwrap();
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
```

- [ ] **Step 2: Run.** `cargo test -p keyorra-sync convergence_tests` → 4 passed. They pass on first run because Tasks 2–10 were test-driven. To see them bite, temporarily stop `SiblingSet::insert` from removing dominated siblings (`Causality::After => {}`): `the_fold_does_not_depend_on_delivery_order` and the smoke test fail. (Making `present_item` ignore staleness is caught by the unit and engine tests instead, e.g. `an_edit_beats_a_concurrent_delete`.) Revert.
- [ ] **Step 3: Stress once.** Temporarily set `cases: 2000` and run `cargo test -p keyorra-sync --release convergence_tests`; expect a pass in a few seconds; restore `cases: 48`.

- [ ] **Step 4: Commit.**

```bash
git add crates/keyorra-sync/src/convergence_tests.rs crates/keyorra-sync/src/lib.rs
git commit -m "sync: property tests for convergence, order independence and lost edits"
```

### Task 12: Protocol document

**Files:** Modify `docs/sync-protocol.md`.

- [ ] **Step 1: Status line.** Replace the first sentence block under the title with:

```markdown
Version: 1 (draft). Status: sections 1–8 are defined and implemented in `crates/keyorra-sync`
(plan A1a), section 9 and the first part of section 10 by plan A1b; later sections are
placeholders filled by later plans.
```

- [ ] **Step 2: Label.** Add to the table in §2, after the `chain` row:

```markdown
| `keyorra/sync/v1/conflict-copy` | ids of conflict copies and of their attachment records |
```

- [ ] **Step 3: Sections 9 and 10.** Replace the placeholder sections "## 9. Fold and presentation" and "## 10. Streams, entries and trust" (up to "## 11. Folder transport") with:

````markdown
## 9. Payloads, versions, fold and presentation

### 9.1 Payloads

The opened body of an envelope (section 7) is the canonical CBOR of:

```
item       = { "item": bytes, "deleted_at": uint | null, "content_from": { bytes16 → uint ≥ 1 } }
vault      = { "name": text, "wrapped_key": bytes, "deleted": bool }
attachment = { "item_id": bytes16, "name": text, "size": uint, "key": bytes32,
               "chunk_size": uint, "chunks": [bytes32, …] }
```

`item` is the item's JSON object exactly as the local store serializes it; `deleted_at` is
unix seconds (in Recently Deleted when set); `content_from` (never empty) is the version
vector of the write that last changed `item`. `wrapped_key` is the vault key sealed by the
account key (`keyorra-core` `wrap_vault_key`). `key` is the attachment's own key; `chunks`
are chunk names (section 8). A tombstone envelope has no payload. Vaults are never
tombstoned; they are deleted with `deleted = true`.

### 9.2 Clocks and new versions

`hlc = unix_ms << 16 | counter`. A new local write takes `max(wall_ms << 16, last + 1)`. A
received version whose physical part is more than 300 000 ms ahead of the local wall clock
is accepted but does not move the local clock (and is logged).

A new version of record `r` by device `D`: `vector = join(vectors of r's siblings)` with
`vector[D] = max(that, D's previous counter for r) + 1`. An edit sets the item's
`content_from` to the new vector; trashing and restoring keep the previous `content_from`.

### 9.3 Validation

A segment's versions are accepted together or not at all. For each version carried by the
stream of device `S`: `version.author = S`; `vector[S]` is exactly one more than the
highest `vector[S]` among `S`'s versions of the same record already accepted (or in the same
segment), or 1; the payload decodes as the envelope's kind; a vault is never a tombstone. A
version already accepted (same version hash) is ignored. A violation rejects the segment and
stops reading that stream (an alarm).

### 9.4 Sibling sets and the fold

For every record, the sibling set is the set of accepted, admitted versions that no other
accepted, admitted version dominates (vector ≥ in every entry and different). Equal vectors
count as the same version. The set depends only on which versions were accepted, not on
their order. Every accepted version is retained so the sets can be rebuilt when admission
changes (section 10).

### 9.5 Presentation

Ranks: `(hlc, author)` compared as `(u64, bytes16)`, higher wins.

**Items.** A sibling is *live* (no `deleted_at`), *trashed* (`deleted_at` set) or *purged*
(tombstone). It is *stale* when another sibling's vector covers (≥ in every entry) its
`content_from`. Siblings are ordered fresh before stale, then by rank. Shown: the first
purged sibling if any; else the first live one; else the first trashed one. Every other
sibling becomes a conflict copy unless it is stale, its content equals content already shown
(the shown sibling's or an earlier copy's; JSON values compared without `updated_at`), or
(with a purge shown) it is trashed. A trashed sibling's copy keeps its `deleted_at`.

**Vaults.** Shown: the highest-ranked sibling's payload. It counts as deleted only if it is
`deleted` and no live item has this vault; otherwise a `deleted` vault is shown as revived.
Siblings with different `wrapped_key` raise an alarm.

**Attachments.** Removed if any sibling is a tombstone; otherwise the highest-ranked payload.

### 9.6 Conflict copies

For a copied sibling `s` of item `r`:

```
copy_id            = UUIDv8(SHA-256("keyorra/sync/v1/conflict-copy\0" ‖ r ‖ version_hash(s))[0..16])
copy attachment id = UUIDv8(SHA-256("keyorra/sync/v1/conflict-copy\0" ‖ copy_id ‖ attachment_id)[0..16])
```

(UUIDv8: the first 16 bytes with the version nibble set to 8 and the RFC 4122 variant.) The
copy's JSON is `s`'s JSON with `"id"` = `copy_id`, `"conflict"` = `{ "of": r, "version":
hex(version_hash(s)), "from_device": hex(s.author) }`, and every attachment reference's `"id"`
replaced by its copy attachment id with `"copied_from"` = the original id. The title is not
changed.

A device whose fold shows a copy that does not exist as a record writes, before its next user
edit: each missing copy (a new record; `content_from` = its own version), then a version of
`r` with the shown sibling's content and `content_from` (or a tombstone if `r` is purged).
For each attachment reference with `copied_from` in a shown copy whose record does not exist,
a device that has the original attachment live writes it: the original payload with
`item_id` = the copy.

## 10. Streams, entries and trust

**Entries (A1b).** `Put = { "put": Envelope }`. Further entry types, the device directory,
admission, causal delivery and the rest of this section: plan A1c.

**Reading a stream (A1b).** A device keeps, per other stream, the last applied
`(seq, chain hash)` (initially `(0, chain_0)`). It applies the segment whose `first_seq` is
the next seq and whose `prev_hash` is the known hash, verified with the stream device's key;
duplicates and later segments wait. A segment that does not open is retried later. A segment
whose item or attachment needs a vault key not known yet waits until the vault record has
been read from any stream.
````

- [ ] **Step 4: Check against the code.** Field names (`content_from`, `copied_from`, `conflict`, `of`, `version`, `from_device`), the 300 000 ms bound, and the validation rules match `payload.rs`, `clock.rs`, `fold.rs`. Fix the document where it disagrees, unless the code contradicts the spec.

- [ ] **Step 5: Commit.**

```bash
git add docs/sync-protocol.md
git commit -m "docs: sync protocol section 9 and stream reading"
```

### Task 13: Final verification

- [ ] **Step 1: Everything green.**

```bash
cargo fmt --all -- --check
cargo clippy -p keyorra-core -p keyorra-session -p keyorra-sync --all-targets -- -D warnings
cargo clippy -p keyorra-sync --features test-utils -- -D warnings
cargo test -p keyorra-core -p keyorra-session -p keyorra-sync
```

Expected: no diffs, no warnings, every `test result:` line `ok`; keyorra-sync: 125 passed, 1 ignored (A1a's `write_vectors`).

- [ ] **Step 2: Purity.** `grep -rnE "std::(fs|net|time|env|process)|SystemTime|thread_rng|OsRng" crates/keyorra-sync/src` → only test code and A1a's `vectors.rs`; nothing in `engine.rs`, `fold.rs`, `present.rs`, `transport.rs` outside `#[cfg(test)]`.
- [ ] **Step 3: A1a vectors untouched.** `git diff d5ca382 -- docs/sync-test-vectors` is empty and `vectors_match_the_pinned_file` passes.
- [ ] **Step 4: Spec cross-check.** Every bullet of the revised A1b row in spec §12 is covered (Tasks 2–11); none of A1c (entry types beyond `Put`, endorsement, causal delivery, headers, snapshots) or A1d (store) has been started.
- [ ] **Step 5: Wrap up.** If a step needed a fix, commit it as `sync: A1b verification fixes`. Do not push.
