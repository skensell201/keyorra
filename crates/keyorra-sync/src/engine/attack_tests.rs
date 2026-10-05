//! Regression tests for the trust review: a removed device that keeps its keys, a device that
//! joined with the Emergency Kit, and a store that lies. Each test is one attack.

use uuid::Uuid;

use super::*;
use crate::entry::Entry;
use crate::faults::{Faults, Rollback};
use crate::payload::VaultPayload;
use crate::testkit::{device_id, device_name, signer, Cluster, ACCOUNT_ID, ACCOUNT_KEY, START_MS};
use crate::transport::MemoryTransport;

const ITEM: Uuid = Uuid::from_bytes([0x60; 16]);

fn title(view: &View, id: Uuid) -> String {
    let p = view.items[&id].payload.as_ref().expect("item has content");
    let v: serde_json::Value = serde_json::from_slice(&p.item_json).unwrap();
    v["title"].as_str().unwrap().to_owned()
}

/// `n` devices sharing a vault with one item "base"; device 1 is then removed by the root,
/// and everyone knows. Device 1 keeps its keys and now writes whatever it likes.
fn with_removed_device(n: usize) -> (Cluster, Uuid) {
    let mut c = Cluster::new(n, 1, Faults::NONE);
    let vault = c.devices[0].create_vault("Personal", START_MS).unwrap();
    let json = Cluster::item_json(ITEM, "base", &[]);
    c.devices[0]
        .save_item(vault, ITEM, &json, START_MS)
        .unwrap();
    c.heal();
    c.devices[0].revoke(device_id(1), c.clocks[0]).unwrap();
    c.heal();
    assert!(!c.devices[1].can_write());
    c.devices[1].forging = true;
    (c, vault)
}

/// Writes raw entries to device `i`'s stream, as an attacker with its signing key can.
fn forge(c: &mut Cluster, i: usize, entries: Vec<Entry>) {
    for entry in entries {
        c.devices[i].queue(entry);
    }
    c.devices[i].push(&c.store);
}

fn rejected(events: &[Event]) -> bool {
    events.iter().any(|e| matches!(e, Event::Rejected { .. }))
}

/// Syncs every honest device (all but `skip`) a few rounds; returns their events.
fn settle(c: &mut Cluster, skip: &[usize]) -> Vec<Vec<Event>> {
    for _ in 0..4 {
        for i in 0..c.devices.len() {
            if !skip.contains(&i) {
                let _ = c.sync(i);
            }
        }
        c.tick(1_000);
    }
    (0..c.devices.len())
        .map(|i| c.devices[i].take_events())
        .collect()
}

#[test]
fn review_c6_a_removed_device_cannot_replace_a_vault_key() {
    let (mut c, vault) = with_removed_device(3);
    let honest_key = c.devices[0].view().vaults[&vault].wrapped_key.clone();
    let mut raw = [7u8; 32];
    raw[0] = 1;
    let wrapped_key =
        crypto::wrap_vault_key(&Key::from_bytes(ACCOUNT_KEY), vault, &Key::from_bytes(raw));
    c.devices[1]
        .write(
            RecordKind::Vault,
            vault,
            None,
            Doc::Vault(VaultPayload {
                name: "Personal".into(),
                wrapped_key,
                deleted: false,
            }),
            c.clocks[1],
        )
        .unwrap();
    c.sync(1).unwrap();
    // The root keeps writing in the vault; everyone else must keep reading it.
    let json = Cluster::item_json(ITEM, "after", &[]);
    c.devices[0]
        .save_item(vault, ITEM, &json, c.clocks[0])
        .unwrap();
    let events = settle(&mut c, &[1]);
    for i in [0, 2] {
        assert!(!rejected(&events[i]), "device {i}: {:?}", events[i]);
        let view = c.devices[i].view();
        assert_eq!(title(&view, ITEM), "after", "device {i}");
        assert_eq!(view.vaults[&vault].wrapped_key, honest_key);
    }
}

#[test]
fn review_c7a_two_keys_for_one_id_quarantine_it_and_reject_nobody() {
    let (mut c, vault) = {
        let mut c = Cluster::new(3, 1, Faults::NONE);
        let vault = c.devices[0].create_vault("Personal", START_MS).unwrap();
        c.heal();
        (c, vault)
    };
    // A stolen approved device and the root approve the same new id with different keys.
    let stolen = signer(8).verifying_key();
    let real = signer(5).verifying_key();
    c.devices[1]
        .endorse(device_id(5), &stolen, "Thief", c.clocks[1])
        .unwrap();
    c.sync(1).unwrap();
    c.devices[0]
        .endorse(device_id(5), &real, &device_name(5), c.clocks[0])
        .unwrap();
    settle(&mut c, &[]);
    let alarm = Alarm::KeyConflict {
        device: device_id(5),
    };
    for i in 0..3 {
        assert_eq!(
            c.devices[i].alarms(),
            std::slice::from_ref(&alarm),
            "device {i}"
        );
        assert!(c.devices[i].trust().device(&device_id(5)).is_none());
        assert!(c.devices[i].accept_alarm(&alarm));
    }
    // Nobody rejected anyone: the root's stream is still read.
    let json = Cluster::item_json(ITEM, "later", &[]);
    c.devices[0]
        .save_item(vault, ITEM, &json, c.clocks[0])
        .unwrap();
    let events = settle(&mut c, &[]);
    for (i, events) in events.iter().enumerate() {
        assert!(!rejected(events), "device {i}");
        assert_eq!(title(&c.devices[i].view(), ITEM), "later");
    }
}

#[test]
fn review_c7a_an_approval_beats_a_self_join_of_the_same_id_in_any_order() {
    for root_first in [true, false] {
        let mut c = Cluster::new(2, 1, Faults::NONE);
        // A thief with the Emergency Kit self-joins under the id the root approves.
        let mut thief = Engine::join(
            device_id(5),
            signer(8),
            "Thief",
            ACCOUNT_ID,
            Key::from_bytes(ACCOUNT_KEY),
            device_id(0),
            rand::rngs::OsRng,
        );
        thief.pin_root_key(signer(0).verifying_key());
        let real = signer(5).verifying_key();
        if root_first {
            c.devices[0]
                .endorse(device_id(5), &real, &device_name(5), c.clocks[0])
                .unwrap();
            c.sync(0).unwrap();
        }
        thief.self_join(START_MS).unwrap();
        thief.sync(&c.store, START_MS).unwrap();
        if !root_first {
            let _ = c.sync(0); // pauses on the self-join alarm, but still pushes nothing new
            c.devices[0].accept_alarm(&Alarm::SelfJoined {
                device: device_id(5),
                name: "Thief".into(),
            });
            c.devices[0]
                .endorse(device_id(5), &real, &device_name(5), c.clocks[0])
                .unwrap();
            c.sync(0).unwrap();
        }
        let _ = c.sync(1);
        let _ = c.sync(1);
        let d = c.devices[1].trust().device(&device_id(5)).unwrap();
        assert_eq!(d.key, real, "root_first = {root_first}");
        assert!(
            c.devices[1].alarms().is_empty(),
            "root_first = {root_first}"
        );
        assert!(!rejected(&c.devices[1].take_events()));
    }
}

#[test]
fn review_c7b_checkpoints_past_a_cut_raise_nothing() {
    let (mut c, _) = with_removed_device(3);
    let mut claims = Heads::new();
    claims.insert(
        device_id(2),
        Head {
            seq: 1,
            hash: [9; 32],
        },
    );
    claims.insert(
        device_id(0),
        Head {
            seq: 1_000,
            hash: [9; 32],
        },
    );
    forge(&mut c, 1, vec![Entry::Checkpoint(claims)]);
    settle(&mut c, &[1]);
    c.tick(2 * WITHHELD_AFTER_MS);
    let events = settle(&mut c, &[1]);
    for i in [0, 2] {
        assert!(c.devices[i].alarms().is_empty(), "device {i}");
        assert!(
            !events[i]
                .iter()
                .any(|e| matches!(e, Event::Withheld { .. })),
            "device {i}"
        );
    }
}

#[test]
fn review_c7c_a_rewrite_inside_a_segment_is_a_fork() {
    let mut c = Cluster::new(3, 1, Faults::NONE);
    let vault = c.devices[0].create_vault("Personal", START_MS).unwrap();
    for t in ["a", "b", "c"] {
        let json = Cluster::item_json(ITEM, t, &[]);
        c.devices[0]
            .save_item(vault, ITEM, &json, c.clocks[0])
            .unwrap();
    }
    c.heal();
    // Device 2 (approved) claims a different history in the middle of the root's segment.
    let mid = c.devices[0].sent.seq - 1;
    let mut claims = Heads::new();
    claims.insert(
        device_id(0),
        Head {
            seq: mid,
            hash: [9; 32],
        },
    );
    forge(&mut c, 2, vec![Entry::Checkpoint(claims)]);
    assert!(c.sync(1).is_err());
    assert_eq!(
        c.devices[1].alarms(),
        [Alarm::Fork {
            stream: device_id(0),
            seq: mid
        }]
    );
}

#[test]
fn a_revocation_naming_another_history_is_a_fork() {
    let (mut c, _) = {
        let mut c = Cluster::new(3, 1, Faults::NONE);
        let vault = c.devices[0].create_vault("Personal", START_MS).unwrap();
        c.heal();
        (c, vault)
    };
    let seq = c.devices[1].sent.seq;
    forge(
        &mut c,
        0,
        vec![Entry::Revoke {
            device: device_id(1),
            last_valid_seq: seq,
            last_valid_hash: [9; 32],
        }],
    );
    assert!(c.sync(2).is_err());
    assert_eq!(
        c.devices[2].alarms(),
        [Alarm::Fork {
            stream: device_id(1),
            seq
        }]
    );
}

#[test]
fn alarms_queue_up_and_are_accepted_one_by_one() {
    let mut c = Cluster::new(3, 1, Faults::NONE);
    c.devices[0].create_vault("Personal", START_MS).unwrap();
    c.heal();
    let r1 = c.devices[2].heads[&device_id(0)].seq;
    let r2 = c.devices[2].heads[&device_id(1)].seq;
    let restored = Rollback {
        inner: Rollback {
            inner: c.store.clone(),
            stream: device_id(0),
            keep_through: r1 - 1,
        },
        stream: device_id(1),
        keep_through: r2 - 1,
    };
    assert!(c.devices[2].sync(&restored, c.clocks[2]).is_err());
    let alarms = c.devices[2].alarms().to_vec();
    assert_eq!(alarms.len(), 2, "{alarms:?}");
    assert!(c.devices[2].accept_alarm(&alarms[0]));
    assert!(c.sync(2).is_err(), "still paused by the second alarm");
    assert!(c.devices[2].accept_alarm(&alarms[1]));
    c.sync(2).unwrap();
}

/// A store whose stream heads cannot be read.
struct NoHeads(MemoryTransport);

impl Transport for NoHeads {
    fn streams(&self) -> Result<Vec<DeviceId>> {
        self.0.streams()
    }
    fn segments(&self, stream: &DeviceId, after_seq: u64) -> Result<Vec<Fetched<Vec<u8>>>> {
        self.0.segments(stream, after_seq)
    }
    fn append(&self, segment: &[u8]) -> Result<AppendOutcome> {
        self.0.append(segment)
    }
    fn head(&self, _: &DeviceId) -> Result<Option<u64>> {
        Err(Error::Transport("no metadata".into()))
    }
}

#[test]
fn heads_that_cannot_be_read_are_reported() {
    let mut c = Cluster::new(2, 1, Faults::NONE);
    c.devices[0].create_vault("Personal", START_MS).unwrap();
    c.heal();
    c.devices[1].create_vault("Work", c.clocks[1]).unwrap();
    c.devices[1]
        .sync(&NoHeads(c.store.clone()), c.clocks[1])
        .unwrap();
    let events = c.devices[1].take_events();
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::HeadUnknown { stream, .. } if *stream == device_id(0))),
        "{events:?}"
    );
    assert!(events
        .iter()
        .any(|e| matches!(e, Event::HeadUnknown { stream, .. } if *stream == device_id(1))));
}

#[test]
fn a_store_with_another_root_is_not_trusted() {
    // Someone with the account key writes a whole account under the root's id, with their
    // own key. A device paired with the real root (its key pinned) trusts none of it.
    let store = MemoryTransport::new();
    let mut impostor = Engine::create_account(
        device_id(0),
        signer(9),
        "Root",
        ACCOUNT_ID,
        Key::from_bytes(ACCOUNT_KEY),
        rand::rngs::OsRng,
        START_MS,
    );
    impostor.create_vault("Bait", START_MS).unwrap();
    impostor.sync(&store, START_MS).unwrap();
    let mut joiner = Engine::join(
        device_id(1),
        signer(1),
        &device_name(1),
        ACCOUNT_ID,
        Key::from_bytes(ACCOUNT_KEY),
        device_id(0),
        rand::rngs::OsRng,
    );
    joiner.pin_root_key(signer(0).verifying_key());
    joiner.sync(&store, START_MS).unwrap();
    assert!(joiner.trust().device(&device_id(0)).is_none());
    assert!(joiner.view().vaults.is_empty());
    assert!(joiner
        .take_events()
        .iter()
        .any(|e| matches!(e, Event::Unreadable { from, .. } if *from == device_id(0))));
}

#[test]
fn review_c4_a_self_joined_device_cannot_remove_anyone() {
    let mut c = Cluster::new(2, 1, Faults::NONE);
    let vault = c.devices[0].create_vault("Personal", START_MS).unwrap();
    c.heal();
    let mut thief = Engine::join(
        device_id(5),
        signer(5),
        "Thief",
        ACCOUNT_ID,
        Key::from_bytes(ACCOUNT_KEY),
        device_id(0),
        rand::rngs::OsRng,
    );
    thief.pin_root_key(signer(0).verifying_key());
    thief.self_join(START_MS).unwrap();
    assert!(
        thief.revoke(device_id(0), START_MS).is_err(),
        "refused locally"
    );
    thief.forging = true;
    thief.revoke(device_id(0), START_MS).unwrap();
    thief.revoke(device_id(1), START_MS).unwrap();
    thief.sync(&c.store, START_MS).unwrap();
    for i in 0..2 {
        assert!(c.sync(i).is_err(), "paused by the self-join");
        let alarm = c.devices[i].alarms()[0].clone();
        assert!(matches!(alarm, Alarm::SelfJoined { .. }));
        assert!(c.devices[i]
            .trust()
            .device(&device_id(0))
            .unwrap()
            .cut
            .is_none());
        assert!(c.devices[i]
            .trust()
            .device(&device_id(1))
            .unwrap()
            .cut
            .is_none());
    }
    // The user removes it; the alarm resolves itself everywhere.
    c.devices[0].revoke(device_id(5), c.clocks[0]).unwrap();
    assert!(c.devices[0].alarms().is_empty());
    c.sync(0).unwrap();
    c.sync(1).unwrap();
    assert!(c.devices[1].alarms().is_empty());
    let json = Cluster::item_json(ITEM, "still here", &[]);
    c.devices[0]
        .save_item(vault, ITEM, &json, c.clocks[0])
        .unwrap();
    c.heal();
    assert_eq!(title(&c.devices[1].view(), ITEM), "still here");
}

#[test]
fn review_c5_a_removed_device_cannot_launder_content_as_a_copy() {
    let (mut c, vault) = with_removed_device(3);
    // A forged "conflict copy" of the root's item, with content of the thief's choosing.
    let source = c.devices[0]
        .fold()
        .retained()
        .find(|a| a.record_id == ITEM)
        .unwrap()
        .clone();
    let copy_id = crate::present::conflict_copy_id(ITEM, &source.hash());
    let json = serde_json::to_vec(&serde_json::json!({
        "id": copy_id.to_string(),
        "title": "forged",
        "attachments": [],
        "conflict": {
            "of": ITEM.to_string(),
            "version": data_encoding::HEXLOWER.encode(&source.hash()),
            "from_device": data_encoding::HEXLOWER.encode(&device_id(0)),
        },
    }))
    .unwrap();
    c.devices[1]
        .write(
            RecordKind::Item,
            copy_id,
            Some(vault),
            Doc::Item(crate::payload::ItemPayload {
                item_json: Zeroizing::new(json),
                deleted_at: None,
                content_from: crate::vv::Vector::new(),
            }),
            c.clocks[1],
        )
        .unwrap();
    c.sync(1).unwrap();
    settle(&mut c, &[1]);
    for i in [0, 2] {
        let view = c.devices[i].view();
        if let Some(copy) = view.items.get(&copy_id) {
            assert_eq!(title(&view, copy_id), "base", "device {i}: regenerated");
            assert!(copy.payload.is_some());
        }
        assert!(!view
            .items
            .keys()
            .any(|id| view.items[id].payload.is_some() && title(&view, *id) == "forged"));
    }
}
