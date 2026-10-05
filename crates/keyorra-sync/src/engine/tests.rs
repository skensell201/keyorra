use uuid::Uuid;

use super::*;
use crate::entry::Entry;
use crate::envelope::Version;
use crate::faults::Faults;
use crate::faults::{Overlay, Rollback};
use crate::payload::conflict_marker;
use crate::testkit::{device_id, device_name, signer, Cluster, ACCOUNT_ID, ACCOUNT_KEY, START_MS};
use rand::SeedableRng;

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
        e.trust.root_key(),
        rand::rngs::OsRng,
    );
    twin.sent = e.sent;
    twin.own_hashes = e.own_hashes.clone();
    twin.next_seq = e.next_seq;
    twin.unwrapped = e.unwrapped.clone();
    twin.fold = e.fold.clone();
    twin.trust = e.trust.clone();
    twin.heads = e.heads.clone();
    twin.hashes = e.hashes.clone();
    twin.checkpoint_bounds = e.checkpoint_bounds.clone();
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
    // The root's stream verifies with the root key from the header / setup code.
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
fn only_the_main_device_approves() {
    let mut c = Cluster::unapproved(3, 5, Faults::NONE);
    let key1 = c.devices[1].verifying_key();
    c.devices[0]
        .endorse(device_id(1), &key1, &device_name(1), START_MS)
        .unwrap();
    c.heal();
    let key2 = c.devices[2].verifying_key();
    assert!(matches!(
        c.devices[1].endorse(device_id(2), &key2, &device_name(2), c.clocks[1]),
        Err(Error::Refused(_))
    ));
    c.devices[0]
        .endorse(device_id(2), &key2, &device_name(2), c.clocks[0])
        .unwrap();
    c.heal();
    let info = c.devices[1].trust().device(&device_id(2)).unwrap().clone();
    assert_eq!(
        info.introduced,
        crate::trust::Introduction::Endorsed {
            at_seq: c.devices[0].sent.seq
        }
    );
    assert!(c.devices[2].can_write());
}

#[test]
fn a_self_joined_device_is_pending_until_the_main_device_decides() {
    let (mut c, vault) = shared(3);
    // Device 2 is replaced by a fresh device that joins with the Emergency Kit.
    let mut kit = Engine::join(
        device_id(5),
        signer(5),
        "Kit",
        ACCOUNT_ID,
        Key::from_bytes(ACCOUNT_KEY),
        device_id(0),
        signer(0).verifying_key(),
        rand::rngs::StdRng::seed_from_u64(5),
    );
    kit.sync(&c.store, START_MS).unwrap();
    kit.self_join(START_MS).unwrap();
    assert!(kit.can_write());
    assert!(!kit.is_root());
    kit.save_item(
        vault,
        ITEM,
        &Cluster::item_json(ITEM, "pending", &[]),
        START_MS,
    )
    .unwrap();
    assert_eq!(title(&kit.view(), ITEM), "pending", "visible on itself");
    kit.sync(&c.store, START_MS).unwrap();
    for i in 0..3 {
        c.sync(i).unwrap();
        assert_eq!(c.devices[i].alarms(), vec![Alarm::Unapproved { count: 1 }]);
        assert_eq!(
            title(&c.devices[i].view(), ITEM),
            "base",
            "pending for others"
        );
    }
    // Accepting the alarm only notes it; approving brings the pending edit in.
    assert!(c.devices[1].accept_alarm(&Alarm::Unapproved { count: 1 }));
    assert!(c.devices[1].alarms().is_empty());
    c.devices[0].approve(device_id(5), c.clocks[0]).unwrap();
    assert!(c.devices[0].alarms().is_empty(), "approving resolves it");
    c.heal();
    for i in 0..3 {
        assert_eq!(title(&c.devices[i].view(), ITEM), "pending");
    }
    assert!(matches!(kit.self_join(START_MS), Err(Error::Refused(_))));
}

#[test]
fn only_the_main_device_removes_and_it_cannot_remove_itself() {
    let (mut c, _) = shared(2);
    assert!(matches!(
        c.devices[1].revoke(device_id(1), c.clocks[1]),
        Err(Error::Refused(_))
    ));
    assert!(matches!(
        c.devices[0].revoke(device_id(0), c.clocks[0]),
        Err(Error::Refused(_))
    ));
    c.devices[0].revoke(device_id(1), c.clocks[0]).unwrap();
    c.heal();
    assert!(!c.devices[1].can_write());
    assert!(c.devices[1].take_events().contains(&Event::Removed));
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
    c.devices[0].sync(&restored_backup, c.clocks[0]).unwrap();
    let alarm = c.devices[0].alarms()[0].clone();
    assert!(matches!(alarm, Alarm::Rollback { stream, .. } if stream == device_id(1)));
    // That stream is paused until the user decides; the others are not.
    c.devices[1]
        .save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "later", &[]),
            c.clocks[1],
        )
        .unwrap();
    c.sync(1).unwrap();
    c.devices[0].sync(&c.store, c.clocks[0]).unwrap();
    assert_eq!(title(&c.devices[0].view(), ITEM), "newer");
    assert!(c.devices[0].accept_alarm(&alarm));
    c.devices[0].sync(&c.store, c.clocks[0]).unwrap();
    assert_eq!(title(&c.devices[0].view(), ITEM), "later");
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
        c.devices[0].alarms().first().cloned(),
        Some(Alarm::Rollback { stream, .. }) if stream == device_id(0)
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
        c.devices[0].alarms().is_empty(),
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
    // Device 2 is not the main device: a dispute (either side may be lying).
    assert!(matches!(
        c.devices[0].alarms().first().cloned(),
        Some(Alarm::Disputed { stream, by, .. }) if stream == device_id(1) && by == device_id(2)
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
    assert!(matches!(
        c.devices[0].alarms().first().cloned(),
        Some(Alarm::Fork { .. })
    ));
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

#[test]
fn review_w2_an_absurd_claim_does_not_silence_real_withholding() {
    let (mut c, vault) = shared(4);
    // Approved device 3 claims device 1 is at an absurd position.
    let mut claims = Heads::new();
    claims.insert(
        device_id(1),
        Head {
            seq: 1 << 40,
            hash: [7; 32],
        },
    );
    c.devices[3].queue(Entry::Checkpoint(claims));
    c.devices[3].push(&c.store);
    c.sync(0).unwrap();
    c.clocks[0] += WITHHELD_AFTER_MS + 1;
    c.sync(0).unwrap();
    let withheld = |events: Vec<Event>| -> Vec<u64> {
        events
            .iter()
            .filter_map(|e| match e {
                Event::Withheld { from, claimed_seq } if *from == device_id(1) => {
                    Some(*claimed_seq)
                }
                _ => None,
            })
            .collect()
    };
    assert!(
        withheld(c.devices[0].take_events()).is_empty(),
        "absurd claims are ignored"
    );
    // Now device 1's new segment is really withheld from device 0.
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
    let real = c.devices[1].sent.seq;
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
    c.clocks[0] += WITHHELD_AFTER_MS + 1;
    c.devices[0].sync(&withholding, c.clocks[0]).unwrap();
    assert_eq!(withheld(c.devices[0].take_events()), vec![real]);
}

#[test]
fn review_w2_claims_of_a_device_removed_before_them_are_dropped() {
    let (mut c, _) = shared(4);
    let received = c.devices[0].heads[&device_id(1)].seq;
    let mut claims = Heads::new();
    claims.insert(
        device_id(1),
        Head {
            seq: received + 3,
            hash: [7; 32],
        },
    );
    c.devices[2].queue(Entry::Checkpoint(claims));
    c.devices[2].push(&c.store);
    let cut_before = c.devices[0].heads[&device_id(2)].seq;
    c.sync(3).unwrap();
    assert!(!c.devices[3].claims.is_empty());
    // The root removes device 2 at a position before that checkpoint.
    let hash = c.devices[0].hashes[&device_id(2)][&cut_before];
    c.devices[0].queue(Entry::Revoke {
        device: device_id(2),
        last_valid_seq: cut_before,
        last_valid_hash: hash,
    });
    c.devices[0].push(&c.store);
    c.sync(3).unwrap();
    assert!(c.devices[3].claims.is_empty());
}
