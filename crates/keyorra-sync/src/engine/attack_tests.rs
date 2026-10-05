//! Regression tests for the trust review: a removed device that keeps its keys, a device that
//! joined with the Emergency Kit, and a store that lies. Each test is one attack.

use uuid::Uuid;

use super::*;
use crate::entry::{sign_endorsement, Entry};
use crate::faults::Faults;
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
fn review_c7c_a_rewrite_inside_a_segment_is_noticed() {
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
    forge(&mut c, 2, vec![Entry::Checkpoint(claims.clone())]);
    c.sync(1).unwrap();
    // From another device it is a dispute (it may be lying), pausing nothing...
    assert_eq!(
        c.devices[1].alarms(),
        vec![Alarm::Disputed {
            stream: device_id(0),
            seq: mid,
            by: device_id(2),
        }]
    );
    // ...from the main device a fork, pausing that stream.
    let mid1 = c.devices[1].sent.seq;
    let mut claims = Heads::new();
    claims.insert(
        device_id(1),
        Head {
            seq: mid1,
            hash: [9; 32],
        },
    );
    forge(&mut c, 0, vec![Entry::Checkpoint(claims)]);
    c.sync(2).unwrap();
    assert!(c.devices[2].alarms().contains(&Alarm::Fork {
        stream: device_id(1),
        seq: mid1
    }));
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
    c.sync(2).unwrap();
    assert_eq!(
        c.devices[2].alarms(),
        vec![Alarm::Fork {
            stream: device_id(1),
            seq
        }]
    );
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
    fn headers(&self) -> Result<Vec<(String, Fetched<Vec<u8>>)>> {
        self.0.headers()
    }
    fn put_header(&self, name: &str, bytes: &[u8]) -> Result<()> {
        self.0.put_header(name, bytes)
    }
    fn delete_header(&self, name: &str) -> Result<()> {
        self.0.delete_header(name)
    }
    fn snapshots(&self) -> Result<Vec<(String, DeviceId)>> {
        self.0.snapshots()
    }
    fn get_snapshot(&self, name: &str) -> Result<Fetched<Vec<u8>>> {
        self.0.get_snapshot(name)
    }
    fn put_snapshot(&self, bytes: &[u8]) -> Result<String> {
        self.0.put_snapshot(bytes)
    }
    fn delete_snapshot(&self, name: &str) -> Result<()> {
        self.0.delete_snapshot(name)
    }
    fn root_head_file(&self) -> Result<Fetched<Vec<u8>>> {
        self.0.root_head_file()
    }
    fn put_root_head_file(&self, bytes: &[u8]) -> Result<()> {
        self.0.put_root_head_file(bytes)
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
    // own key. A device that knows the real root's key (header, setup code) trusts none of it.
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
        signer(0).verifying_key(),
        rand::rngs::OsRng,
    );
    joiner.sync(&store, START_MS).unwrap();
    assert!(joiner.view().vaults.is_empty());
    assert!(joiner
        .take_events()
        .iter()
        .any(|e| matches!(e, Event::Unreadable { from, .. } if *from == device_id(0))));
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

/// A device that joins with the Emergency Kit under `id`, its own key from `signer(key)`.
fn kit(id: DeviceId, key: usize) -> Engine<rand::rngs::OsRng> {
    let mut e = Engine::join(
        id,
        signer(key),
        "Kit",
        ACCOUNT_ID,
        Key::from_bytes(ACCOUNT_KEY),
        device_id(0),
        signer(0).verifying_key(),
        rand::rngs::OsRng,
    );
    e.forging = true;
    e
}

fn ignored(events: &[Event]) -> usize {
    events
        .iter()
        .filter(|e| matches!(e, Event::TrustEntryIgnored { .. }))
        .count()
}

#[test]
fn review_n1_c1_c2_c3_a_stolen_approved_device_cannot_remove_or_approve_anyone() {
    // Device 1 is approved and stolen: it removes the root and device 2 (at 0), approves a
    // puppet, removes itself at 0 to erase its history, and is never removed in time.
    let mut c = Cluster::new(3, 1, Faults::NONE);
    let vault = c.devices[0].create_vault("Personal", START_MS).unwrap();
    let json = Cluster::item_json(ITEM, "by device 1", &[]);
    c.heal();
    c.devices[1]
        .save_item(vault, ITEM, &json, c.clocks[1])
        .unwrap();
    c.heal();
    c.devices[1].forging = true;
    let puppet = signer(8).verifying_key();
    let entries = vec![
        Entry::Revoke {
            device: device_id(0),
            last_valid_seq: 0,
            last_valid_hash: [0; 32],
        },
        Entry::Revoke {
            device: device_id(2),
            last_valid_seq: 0,
            last_valid_hash: [0; 32],
        },
        Entry::Revoke {
            device: device_id(1),
            last_valid_seq: 0,
            last_valid_hash: [0; 32],
        },
        Entry::Endorse {
            device: device_id(8),
            key: puppet.to_bytes(),
            name: "puppet".into(),
            sig: sign_endorsement(&signer(1), &ACCOUNT_ID, &device_id(8), &puppet.to_bytes()),
        },
    ];
    forge(&mut c, 1, entries);
    let events = settle(&mut c, &[1]);
    for i in [0, 2] {
        assert_eq!(ignored(&events[i]), 4, "device {i}");
        let t = c.devices[i].trust();
        for d in 0..3 {
            assert!(t.device(&device_id(d)).unwrap().cut.is_none(), "device {d}");
        }
        assert!(t.device(&device_id(8)).is_none());
        assert_eq!(
            title(&c.devices[i].view(), ITEM),
            "by device 1",
            "history kept"
        );
        assert!(c.devices[i].can_write());
    }
}

#[test]
fn review_n2_c7a_the_first_approval_of_an_id_is_final() {
    let mut c = Cluster::new(3, 1, Faults::NONE);
    c.devices[0].create_vault("Personal", START_MS).unwrap();
    c.heal();
    // A stolen device approves an honest id with its own key; the root (a forged copy of
    // it, the only thing that could) approves the same id again with another key.
    c.devices[1].forging = true;
    c.devices[1]
        .endorse(
            device_id(2),
            &signer(8).verifying_key(),
            "evil",
            c.clocks[1],
        )
        .unwrap();
    c.sync(1).unwrap();
    c.devices[0].forging = true;
    c.devices[0]
        .endorse(
            device_id(2),
            &signer(8).verifying_key(),
            "again",
            c.clocks[0],
        )
        .unwrap();
    c.devices[0].forging = false;
    let events = settle(&mut c, &[]);
    for (i, events) in events.iter().enumerate() {
        let t = c.devices[i].trust();
        assert_eq!(
            t.key(&device_id(2)),
            Some(signer(2).verifying_key()),
            "device {i}"
        );
        assert!(c.devices[i].alarms().is_empty());
        assert!(!rejected(events));
    }
    assert!(c.devices[2].can_write());
}

#[test]
fn review_n3_trust_is_one_pass_over_the_root_stream() {
    // Many approvals and removals: every device ends with the same trust, in one round.
    let mut c = Cluster::new(2, 1, Faults::NONE);
    for k in 0..300u16 {
        let id: DeviceId = [
            0x80 | (k >> 8) as u8,
            k as u8,
            9,
            9,
            9,
            9,
            9,
            9,
            9,
            9,
            9,
            9,
            9,
            9,
            9,
            9,
        ];
        let key = SigningKey::from_bytes(&[(k % 250) as u8 + 1; 32]).verifying_key();
        c.devices[0].endorse(id, &key, "d", START_MS).unwrap();
        if k % 3 == 0 {
            c.devices[0].revoke(id, START_MS).unwrap();
        }
    }
    c.sync(0).unwrap();
    let started = std::time::Instant::now();
    c.sync(1).unwrap();
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    assert_eq!(
        c.devices[1].trust().devices(),
        c.devices[0].trust().devices()
    );
}

#[test]
fn review_n4_a_thief_is_never_credited_under_an_approved_id() {
    // A thief self-joins under an id that sorts before the root's and writes; later the root
    // approves that id for a real device with another key. Fresh devices read the thief's
    // stream only with the key the root gave, so nothing of the thief counts.
    let mut c = Cluster::new(2, 1, Faults::NONE);
    let vault = c.devices[0].create_vault("Personal", START_MS).unwrap();
    c.heal();
    let id: DeviceId = [0; 16];
    let mut thief = kit(id, 7);
    thief.sync(&c.store, START_MS).unwrap();
    thief.self_join(START_MS).unwrap();
    let json = Cluster::item_json(ITEM, "EVIL", &[]);
    thief.save_item(vault, ITEM, &json, START_MS).unwrap();
    thief.sync(&c.store, START_MS).unwrap();
    c.devices[0]
        .endorse(id, &signer(9).verifying_key(), "real", c.clocks[0])
        .unwrap();
    c.heal();
    let mut fresh = kit(device_id(5), 5);
    fresh.forging = false;
    fresh.sync(&c.store, START_MS).unwrap();
    fresh.sync(&c.store, START_MS).unwrap();
    for view in [c.devices[0].view(), c.devices[1].view(), fresh.view()] {
        assert!(
            !view.items.contains_key(&ITEM),
            "nothing of the thief counts"
        );
    }
    assert!(c.devices[1]
        .trust()
        .device(&device_id(1))
        .unwrap()
        .cut
        .is_none());
}

#[test]
fn review_n5_a_cut_bound_counts_only_on_the_readers_chain() {
    // The root's checkpoint claims device 1 at a far position with a hash nobody has; its
    // removal of device 1 then cuts where it says, not at the claimed position.
    let mut c = Cluster::new(3, 1, Faults::NONE);
    c.devices[0].create_vault("Personal", START_MS).unwrap();
    c.heal();
    let seq = c.devices[1].sent.seq;
    let mut claims = Heads::new();
    claims.insert(
        device_id(1),
        Head {
            seq: 500,
            hash: [9; 32],
        },
    );
    let hash = c.devices[0].hashes[&device_id(1)][&seq];
    forge(
        &mut c,
        0,
        vec![
            Entry::Checkpoint(claims),
            Entry::Revoke {
                device: device_id(1),
                last_valid_seq: seq,
                last_valid_hash: hash,
            },
        ],
    );
    c.sync(2).unwrap();
    assert_eq!(
        c.devices[2].trust().device(&device_id(1)).unwrap().cut,
        Some(seq)
    );
}

#[test]
fn review_n6_removing_a_self_joined_thief_hides_all_it_wrote() {
    let mut c = Cluster::new(2, 1, Faults::NONE);
    let vault = c.devices[0].create_vault("Personal", START_MS).unwrap();
    c.heal();
    let mut thief = kit(device_id(5), 5);
    thief.sync(&c.store, START_MS).unwrap();
    thief.self_join(START_MS).unwrap();
    for t in ["one", "two"] {
        let json = Cluster::item_json(ITEM, t, &[]);
        thief.save_item(vault, ITEM, &json, START_MS).unwrap();
    }
    thief.sync(&c.store, START_MS).unwrap();
    c.sync(0).unwrap();
    assert_eq!(c.devices[0].alarms(), vec![Alarm::Unapproved { count: 1 }]);
    c.devices[0].revoke(device_id(5), c.clocks[0]).unwrap();
    assert!(c.devices[0].alarms().is_empty(), "removing resolves it");
    c.heal();
    thief.sync(&c.store, START_MS).unwrap();
    for view in [c.devices[0].view(), c.devices[1].view()] {
        assert!(!view.items.contains_key(&ITEM));
    }
    assert!(!thief.can_write() || thief.forging);
    assert!(thief.take_events().contains(&Event::Removed));
}

#[test]
fn self_joins_raise_one_aggregated_alarm_that_pauses_nothing() {
    let mut c = Cluster::new(2, 1, Faults::NONE);
    let vault = c.devices[0].create_vault("Personal", START_MS).unwrap();
    c.heal();
    for k in 0..5 {
        let mut t = kit(device_id(10 + k), 10 + k);
        t.self_join(START_MS).unwrap();
        t.sync(&c.store, START_MS).unwrap();
    }
    c.devices[0]
        .save_item(
            vault,
            ITEM,
            &Cluster::item_json(ITEM, "still", &[]),
            c.clocks[0],
        )
        .unwrap();
    c.heal();
    assert_eq!(c.devices[1].alarms(), vec![Alarm::Unapproved { count: 5 }]);
    assert_eq!(title(&c.devices[1].view(), ITEM), "still");
    assert!(c.devices[1].accept_alarm(&Alarm::Unapproved { count: 5 }));
    let mut t = kit(device_id(20), 20);
    t.self_join(START_MS).unwrap();
    t.sync(&c.store, START_MS).unwrap();
    c.sync(1).unwrap();
    assert_eq!(c.devices[1].alarms(), vec![Alarm::Unapproved { count: 6 }]);
}

#[test]
fn a_rollback_pauses_only_its_stream_and_repeats_aggregate() {
    let mut c = Cluster::new(3, 1, Faults::NONE);
    let vault = c.devices[0].create_vault("Personal", START_MS).unwrap();
    c.heal();
    for t in ["a", "b", "c"] {
        c.devices[1]
            .save_item(vault, ITEM, &Cluster::item_json(ITEM, t, &[]), c.clocks[1])
            .unwrap();
        c.sync(1).unwrap();
    }
    c.sync(2).unwrap();
    let received = c.devices[2].heads[&device_id(1)].seq;
    for keep in [received - 1, received - 2] {
        let store = crate::faults::Rollback {
            inner: c.store.clone(),
            stream: device_id(1),
            keep_through: keep,
        };
        c.devices[2].sync(&store, c.clocks[2]).unwrap();
    }
    let alarms = c.devices[2].alarms();
    assert_eq!(alarms.len(), 1, "{alarms:?}");
    let other = Uuid::from_bytes([0x61; 16]);
    c.devices[0]
        .save_item(
            vault,
            other,
            &Cluster::item_json(other, "root", &[]),
            c.clocks[0],
        )
        .unwrap();
    c.sync(0).unwrap();
    c.sync(2).unwrap();
    assert_eq!(
        title(&c.devices[2].view(), other),
        "root",
        "other streams keep flowing"
    );
}

/// A vault version written by device `i` with a version and wrapped key of its choosing.
fn forged_vault_put(i: usize, vault: Uuid, wrapped_key: Vec<u8>, hlc: u64) -> Entry {
    let doc = Doc::Vault(VaultPayload {
        name: "Personal".into(),
        wrapped_key,
        deleted: false,
    });
    Entry::Put(Envelope {
        kind: RecordKind::Vault,
        record_id: vault,
        vault_id: None,
        schema: SCHEMA_VERSION,
        version: crate::envelope::Version {
            vector: [(device_id(i), 1)].into_iter().collect(),
            hlc,
            author: device_id(i),
        },
        tombstone: false,
        body: Some(doc.encode().to_vec()),
    })
}

#[test]
fn review_v1_an_approved_device_cannot_take_over_a_vault_key() {
    for garbage in [true, false] {
        let mut c = Cluster::new(3, 1, Faults::NONE);
        let vault = c.devices[0].create_vault("Personal", START_MS).unwrap();
        c.heal();
        let honest = c.devices[0].view().vaults[&vault].wrapped_key.clone();
        // Still approved, device 1 writes a "creation" of the vault with the earliest
        // possible version: a garbage key, or a valid key of its own.
        let wrapped = if garbage {
            vec![0xab; 72]
        } else {
            crypto::wrap_vault_key(
                &Key::from_bytes(ACCOUNT_KEY),
                vault,
                &Key::from_bytes([5; 32]),
            )
        };
        forge(&mut c, 1, vec![forged_vault_put(1, vault, wrapped, 1)]);
        c.heal();
        c.devices[0].revoke(device_id(1), c.clocks[0]).unwrap();
        c.heal();
        for i in [0, 2] {
            let json = Cluster::item_json(ITEM, &format!("by {i}"), &[]);
            c.devices[i]
                .save_item(vault, ITEM, &json, c.clocks[i])
                .unwrap_or_else(|e| panic!("garbage={garbage} device {i}: {e}"));
            c.heal();
            assert_eq!(title(&c.devices[2 - i].view(), ITEM), format!("by {i}"));
        }
        // New vault versions carry the creator's key.
        c.devices[2]
            .rename_vault(vault, "Renamed", c.clocks[2])
            .unwrap();
        c.heal();
        for i in [0, 2] {
            let v = &c.devices[i].view().vaults[&vault];
            assert_eq!(v.name, "Renamed");
            assert_eq!(v.wrapped_key, honest, "garbage={garbage}");
        }
    }
}

#[test]
fn review_w3_approval_checks_the_key_shown_on_the_joining_device() {
    let mut c = Cluster::new(2, 1, Faults::NONE);
    c.devices[0].create_vault("Personal", START_MS).unwrap();
    c.heal();
    // A thief with folder access puts its own SelfJoin where the genuine joiner's goes.
    let mut thief = kit(device_id(5), 7);
    thief.self_join(START_MS).unwrap();
    thief.sync(&c.store, START_MS).unwrap();
    let mut joiner = kit(device_id(5), 5);
    joiner.forging = false;
    joiner.self_join(START_MS).unwrap();
    joiner.sync(&c.store, START_MS).unwrap();
    c.sync(0).unwrap();
    // The user compares the code shown on the joining Mac: it does not match.
    let shown = joiner.key_fingerprint();
    assert!(matches!(
        c.devices[0].approve(device_id(5), &shown, c.clocks[0]),
        Err(Error::Refused(_))
    ));
    // Had the main device approved the thief's key, the joiner notices and stops writing.
    let thief_code = thief.key_fingerprint();
    c.devices[0]
        .approve(device_id(5), &thief_code, c.clocks[0])
        .unwrap();
    c.sync(0).unwrap();
    joiner.sync(&c.store, START_MS).unwrap();
    // The joiner finds its id taken by another key: it does not write under it (plan A1c-2:
    // the store already holds someone else's segment there, so it retires to a new id and
    // asks for approval again).
    let retired = joiner
        .take_events()
        .iter()
        .any(|e| matches!(e, Event::Retired { .. }));
    assert!(
        retired || joiner.alarms().contains(&Alarm::ApprovedWithAnotherKey),
        "{:?}",
        joiner.alarms()
    );
    assert!(joiner.device() != device_id(5) || !joiner.can_write());
}
