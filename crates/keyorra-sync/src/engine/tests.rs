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
}

#[test]
fn a_deleted_copy_stays_deleted_when_another_device_also_wrote_it() {
    let (mut c, vault) = shared(2);
    let (a, b) = (device_id(0), device_id(1));
    // Both edit and push without seeing each other.
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
    let a_head = c.devices[0].sent.0;
    let b_head = c.devices[1].sent.0;
    let only_own_a = Upto {
        inner: &c.store,
        stream: b,
        last_seq: b_head,
    };
    c.devices[0]
        .sync(&only_own_a, &c.directory, c.clocks[0])
        .unwrap();
    let only_own_b = Upto {
        inner: &c.store,
        stream: a,
        last_seq: a_head,
    };
    c.devices[1]
        .sync(&only_own_b, &c.directory, c.clocks[1])
        .unwrap();
    // Each now sees the other's edit (and nothing else) and writes the same copy.
    let a_view = Upto {
        inner: &c.store,
        stream: b,
        last_seq: b_head + 1,
    };
    c.devices[0]
        .sync(&a_view, &c.directory, c.clocks[0])
        .unwrap();
    let b_view = Upto {
        inner: &c.store,
        stream: a,
        last_seq: a_head + 1,
    };
    c.devices[1]
        .sync(&b_view, &c.directory, c.clocks[1])
        .unwrap();
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
    let _ = c.devices[0].sync(&broken, &c.directory, c.clocks[0]);
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
    c.devices[0]
        .sync(&broken, &c.directory, c.clocks[0])
        .unwrap();
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
        d.devices[2]
            .sync(&only_a, &d.directory, d.clocks[2])
            .unwrap();
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
    // Another copy of this device already wrote at its next position.
    let mut twin = Engine::new(
        device_id(0),
        SigningKey::from_bytes(&[0x40; 32]),
        crate::testkit::ACCOUNT_ID,
        Key::from_bytes([0x30; 32]),
        rand::rngs::OsRng,
    );
    twin.sent = c.devices[0].sent;
    twin.next_seq = c.devices[0].next_seq;
    twin.vault_keys = c.devices[0].vault_keys.clone();
    twin.fold = c.devices[0].fold.clone();
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

#[test]
fn an_injected_admission_policy_hides_cut_versions() {
    let (mut c, vault) = shared(2);
    c.devices[1]
        .save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "from B", &[]),
            c.clocks[1],
        )
        .unwrap();
    c.heal();
    assert_eq!(title(&c.devices[0].view(), ITEM), "from B");
    struct Cut(DeviceId);
    impl crate::fold::Admission for Cut {
        fn admits(&self, stream: &DeviceId, _: u64) -> bool {
            *stream != self.0
        }
    }
    c.devices[0].set_admission(Box::new(Cut(device_id(1))));
    assert_eq!(title(&c.devices[0].view(), ITEM), "base");
}
