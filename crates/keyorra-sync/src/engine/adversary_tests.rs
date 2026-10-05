//! Property tests with an adversary (spec §11, suite 6): honest devices edit through a
//! misbehaving transport while
//! - a removed device that kept its keys (the "stolen" device) writes whatever it likes past
//!   its cut: records, approvals, removals, checkpoints, a new vault key, forged conflict
//!   copies, and a second history of its stream;
//! - someone with the Emergency Kit self-joins (the "thief"), writes, and tries to remove
//!   devices, until the user removes it;
//! - the store rolls streams back.
//!
//! Whatever happens, the honest devices end in the same state, nobody honest is removed,
//! nothing forged shows, no admitted edit is lost, and a device that joins afterwards sees
//! exactly what the others see.

use proptest::prelude::*;
use rand::rngs::StdRng;
use rand::SeedableRng;
use uuid::Uuid;

use super::*;
use crate::convergence_tests::{
    assert_cut_versions_hidden, assert_no_lost_edit, assert_nothing_unaccounted, item_id, title_of,
    written,
};
use crate::faults::{Faults, Overlay, Rollback};
use crate::payload::{ItemPayload, VaultPayload};
use crate::segment::{seal_segment, StreamPosition};
use crate::testkit::{device_id, device_name, signer, Cluster, ACCOUNT_ID, ACCOUNT_KEY, START_MS};

/// Honest devices are 0..HONEST; the stolen device is `STOLEN`.
const HONEST: usize = 3;
const STOLEN: usize = HONEST;
const ITEMS: usize = 3;

fn thief_id() -> DeviceId {
    device_id(7)
}

fn puppet_key() -> VerifyingKey {
    signer(8).verifying_key()
}

#[derive(Clone, Debug)]
enum Op {
    Save {
        dev: usize,
        item: usize,
    },
    Trash {
        dev: usize,
        item: usize,
    },
    Sync {
        dev: usize,
    },
    Tick {
        ms: u16,
    },
    /// `dev` syncs through a store that lost the second half of `stream`.
    Rollback {
        dev: usize,
        stream: usize,
    },
    StolenSave {
        item: usize,
    },
    /// Approves an honest id with another key (`target < HONEST`) or a puppet.
    StolenEndorse {
        target: usize,
    },
    StolenRevoke {
        target: usize,
        at: u8,
    },
    StolenCheckpoint {
        target: usize,
        seq: u8,
    },
    StolenVaultKey,
    StolenCopy {
        item: usize,
    },
    /// A second history of the stolen device's stream, shown to `dev` by a partitioned store.
    StolenFork {
        dev: usize,
    },
    SelfJoin,
    ThiefSave {
        item: usize,
    },
    ThiefRevoke {
        target: usize,
    },
    ThiefEndorse,
}

fn op() -> impl Strategy<Value = Op> {
    let d = 0..HONEST;
    let i = 0..ITEMS;
    prop_oneof![
        4 => (d.clone(), i.clone()).prop_map(|(dev, item)| Op::Save { dev, item }),
        1 => (d.clone(), i.clone()).prop_map(|(dev, item)| Op::Trash { dev, item }),
        5 => d.clone().prop_map(|dev| Op::Sync { dev }),
        1 => (0u16..20_000).prop_map(|ms| Op::Tick { ms }),
        1 => (d.clone(), 0..=STOLEN).prop_map(|(dev, stream)| Op::Rollback { dev, stream }),
        2 => i.clone().prop_map(|item| Op::StolenSave { item }),
        1 => (0..=HONEST).prop_map(|target| Op::StolenEndorse { target }),
        2 => (0..=STOLEN, any::<u8>()).prop_map(|(target, at)| Op::StolenRevoke { target, at: at % 8 }),
        1 => (0..=STOLEN, any::<u8>()).prop_map(|(target, seq)| Op::StolenCheckpoint { target, seq: seq % 40 }),
        1 => Just(Op::StolenVaultKey),
        1 => i.clone().prop_map(|item| Op::StolenCopy { item }),
        1 => d.clone().prop_map(|dev| Op::StolenFork { dev }),
        1 => Just(Op::SelfJoin),
        1 => i.prop_map(|item| Op::ThiefSave { item }),
        1 => (0..HONEST).prop_map(|target| Op::ThiefRevoke { target }),
        1 => Just(Op::ThiefEndorse),
    ]
}

struct World {
    c: Cluster,
    vault: Uuid,
    vault_key: Vec<u8>,
    thief: Option<Engine<StdRng>>,
    seed: u64,
}

/// Honest devices share a vault with ITEMS items; the root then removed the stolen device,
/// and everyone (the stolen device too) knows.
fn setup(seed: u64) -> World {
    let mut c = Cluster::new(HONEST + 1, seed, Faults::NONE);
    let vault = c.devices[0].create_vault("Personal", START_MS).unwrap();
    for item in 0..ITEMS {
        let id = item_id(item);
        let json = Cluster::item_json(id, &format!("base{item}"), &[]);
        c.devices[0].save_item(vault, id, &json, START_MS).unwrap();
    }
    c.heal();
    c.devices[0].revoke(device_id(STOLEN), c.clocks[0]).unwrap();
    c.heal();
    assert!(!c.devices[STOLEN].can_write());
    c.devices[STOLEN].forging = true;
    for link in &c.links {
        link.set_faults(Faults::CHAOS);
    }
    let vault_key = c.devices[0].view().vaults[&vault].wrapped_key.clone();
    World {
        c,
        vault,
        vault_key,
        thief: None,
        seed,
    }
}

impl World {
    fn stolen(&mut self) -> &mut Engine<StdRng> {
        &mut self.c.devices[STOLEN]
    }

    /// The stolen device pushes what it wrote.
    fn stolen_push(&mut self) {
        let store = self.c.store.clone();
        self.stolen().push(&store);
    }

    fn forge(&mut self, entry: Entry) {
        self.stolen().queue(entry);
        self.stolen_push();
    }

    fn thief_push(&mut self) {
        let store = self.c.store.clone();
        if let Some(t) = &mut self.thief {
            t.push(&store);
        }
    }

    fn run(&mut self, step: usize, op: &Op) {
        let clock = self.c.clocks[0];
        let vault = self.vault;
        match *op {
            Op::Save { dev, item } => {
                let id = item_id(item);
                let json = Cluster::item_json(id, &format!("t{step}"), &[]);
                let _ = self.c.devices[dev].save_item(vault, id, &json, self.c.clocks[dev]);
            }
            Op::Trash { dev, item } => {
                let _ = self.c.devices[dev].trash_item(item_id(item), step as u64, clock);
            }
            Op::Sync { dev } => {
                let _ = self.c.sync(dev);
            }
            Op::Tick { ms } => self.c.tick(u64::from(ms)),
            Op::Rollback { dev, stream } => {
                let stream = device_id(stream);
                let received = self.c.devices[dev].heads.get(&stream).map_or(0, |h| h.seq);
                if received >= 2 {
                    let store = Rollback {
                        inner: self.c.store.clone(),
                        stream,
                        keep_through: received / 2,
                    };
                    let _ = self.c.devices[dev].sync(&store, clock);
                }
            }
            Op::StolenSave { item } => {
                let id = item_id(item);
                let json = Cluster::item_json(id, &format!("evil{step}"), &[]);
                let _ = self.stolen().save_item(vault, id, &json, clock);
                self.stolen_push();
            }
            Op::StolenEndorse { target } => {
                let id = if target < HONEST {
                    device_id(target)
                } else {
                    device_id(8)
                };
                let _ = self.stolen().endorse(id, &puppet_key(), "evil", clock);
                self.stolen_push();
            }
            Op::StolenRevoke { target, at } => self.forge(Entry::Revoke {
                device: device_id(target),
                last_valid_seq: u64::from(at),
                last_valid_hash: [at; 32],
            }),
            Op::StolenCheckpoint { target, seq } => {
                let mut heads = Heads::new();
                heads.insert(
                    device_id(target),
                    Head {
                        seq: u64::from(seq),
                        hash: [0xee; 32],
                    },
                );
                self.forge(Entry::Checkpoint(heads));
            }
            Op::StolenVaultKey => {
                let wrapped_key = crypto::wrap_vault_key(
                    &Key::from_bytes(ACCOUNT_KEY),
                    vault,
                    &Key::from_bytes([step as u8 | 1; 32]),
                );
                let doc = Doc::Vault(VaultPayload {
                    name: format!("evil{step}"),
                    wrapped_key,
                    deleted: false,
                });
                let _ = self
                    .stolen()
                    .write(RecordKind::Vault, vault, None, doc, clock);
                self.stolen_push();
            }
            Op::StolenCopy { item } => {
                let id = item_id(item);
                let Some(source) = self
                    .stolen()
                    .fold()
                    .retained()
                    .find(|a| a.record_id == id)
                    .cloned()
                else {
                    return;
                };
                let copy_id = crate::present::conflict_copy_id(id, &source.hash());
                let json = serde_json::to_vec(&serde_json::json!({
                    "id": copy_id.to_string(),
                    "title": format!("evil{step}"),
                    "attachments": [],
                    "conflict": {
                        "of": id.to_string(),
                        "version": data_encoding::HEXLOWER.encode(&source.hash()),
                        "from_device": data_encoding::HEXLOWER.encode(&source.version.author),
                    },
                }))
                .unwrap();
                let doc = Doc::Item(ItemPayload {
                    item_json: Zeroizing::new(json),
                    deleted_at: None,
                    content_from: crate::vv::Vector::new(),
                });
                let _ = self
                    .stolen()
                    .write(RecordKind::Item, copy_id, Some(vault), doc, clock);
                self.stolen_push();
            }
            Op::StolenFork { dev } => {
                // One history goes to a copy of the store, another to the store itself.
                let fork = self.c.store.deep_copy();
                let s = &self.c.devices[STOLEN];
                let at = StreamPosition {
                    device_id: device_id(STOLEN),
                    first_seq: s.sent.seq + 1,
                    prev_hash: s.sent.hash,
                };
                let mut rng = StdRng::seed_from_u64(self.seed ^ step as u64);
                let segment_key =
                    crate::keys::segment_key(&Key::from_bytes(ACCOUNT_KEY), &ACCOUNT_ID);
                let other = Entry::Checkpoint(Heads::new()).to_value();
                let bytes = seal_segment(&segment_key, &signer(STOLEN), &at, vec![other], &mut rng)
                    .unwrap();
                fork.append(&bytes).unwrap();
                self.forge(Entry::Checkpoint(s_heads(&self.c.devices[STOLEN])));
                let partitioned = Overlay {
                    base: self.c.store.clone(),
                    overlay: fork,
                    stream: device_id(STOLEN),
                };
                let _ = self.c.devices[dev].sync(&partitioned, clock);
            }
            Op::SelfJoin => {
                if self.thief.is_some() {
                    return;
                }
                let mut t = Engine::join(
                    thief_id(),
                    signer(7),
                    "Thief",
                    ACCOUNT_ID,
                    Key::from_bytes(ACCOUNT_KEY),
                    device_id(0),
                    StdRng::seed_from_u64(self.seed ^ 7),
                );
                t.pin_root_key(signer(0).verifying_key());
                let store = self.c.store.clone();
                let _ = t.sync(&store, clock);
                t.self_join(clock).unwrap();
                t.forging = true;
                self.thief = Some(t);
                self.thief_push();
            }
            Op::ThiefSave { item } => {
                if let Some(t) = &mut self.thief {
                    let id = item_id(item);
                    let json = Cluster::item_json(id, &format!("j{step}"), &[]);
                    let _ = t.save_item(vault, id, &json, clock);
                }
                self.thief_push();
            }
            Op::ThiefRevoke { target } => {
                if let Some(t) = &mut self.thief {
                    let _ = t.revoke(device_id(target), clock);
                }
                self.thief_push();
            }
            Op::ThiefEndorse => {
                if let Some(t) = &mut self.thief {
                    let _ = t.endorse(device_id(8), &puppet_key(), "puppet", clock);
                }
                self.thief_push();
            }
        }
    }

    /// The user's decisions on device `i`: the root removes a self-joined device; rollbacks
    /// are accepted; a fork may only be of the stolen device's stream, and is accepted.
    fn decide(&mut self, i: usize) {
        for alarm in self.c.devices[i].alarms().to_vec() {
            match &alarm {
                Alarm::SelfJoined { device, .. } => {
                    if i == 0 {
                        self.c.devices[0].revoke(*device, self.c.clocks[0]).unwrap();
                    }
                }
                Alarm::KeyConflict { .. } => panic!("device {i}: {alarm}"),
                Alarm::Fork { stream, .. } => {
                    assert_eq!(*stream, device_id(STOLEN), "device {i}: {alarm}");
                    assert!(self.c.devices[i].accept_alarm(&alarm));
                }
                Alarm::Rollback { .. } => {
                    assert!(self.c.devices[i].accept_alarm(&alarm));
                }
            }
        }
    }

    /// Faults off; the honest devices (and `extra`) sync and decide until nothing changes.
    fn heal(&mut self, extra: &mut Option<Engine<StdRng>>) {
        for link in &self.c.links {
            link.set_faults(Faults::NONE);
        }
        let mut last = Vec::new();
        for _ in 0..80 {
            for i in 0..HONEST {
                self.decide(i);
                let _ = self.c.sync(i);
            }
            if let Some(e) = extra {
                assert!(e.alarms().is_empty(), "late device: {:?}", e.alarms());
                let _ = e.sync(&self.c.store, self.c.clocks[0]);
            }
            self.c.tick(1_000);
            let views: Vec<View> = (0..HONEST).map(|i| self.c.devices[i].view()).collect();
            let quiet = (0..HONEST)
                .all(|i| self.c.devices[i].is_idle() && self.c.devices[i].alarms().is_empty());
            if quiet && views == last {
                return;
            }
            last = views;
        }
        panic!("honest devices did not settle");
    }
}

fn s_heads(e: &Engine<StdRng>) -> Heads {
    e.heads.clone()
}

fn check(seed: u64, ops: &[Op]) {
    let mut w = setup(seed);
    for (step, op) in ops.iter().enumerate() {
        w.run(step, op);
    }
    w.heal(&mut None);
    // A device that joins now, approved by the root, must see what the others see.
    let mut late = Engine::join(
        device_id(9),
        signer(9),
        &device_name(9),
        ACCOUNT_ID,
        Key::from_bytes(ACCOUNT_KEY),
        device_id(0),
        StdRng::seed_from_u64(seed ^ 9),
    );
    late.pin_root_key(signer(0).verifying_key());
    let key = late.verifying_key();
    w.c.devices[0]
        .endorse(device_id(9), &key, &device_name(9), w.c.clocks[0])
        .unwrap();
    let mut extra = Some(late);
    w.heal(&mut extra);
    let late = extra.unwrap();

    let first = w.c.devices[0].view();
    for i in 1..HONEST {
        assert_eq!(
            w.c.devices[i].view(),
            first,
            "device {i} differs from device 0"
        );
    }
    assert_eq!(late.view(), first, "the late device differs");
    assert!(!first.owes_copies());
    let mut honest: Vec<&Engine<StdRng>> = w.c.devices[..HONEST].iter().collect();
    let all = {
        let mut v = honest.clone();
        v.push(&late);
        written(&v)
    };
    honest.push(&late);
    for d in honest {
        let trust = d.trust();
        for i in 0..HONEST {
            assert!(
                trust.device(&device_id(i)).unwrap().cut.is_none(),
                "device {i} was removed"
            );
        }
        assert!(trust.device(&device_id(STOLEN)).unwrap().cut.is_some());
        if w.thief.is_some() {
            assert!(trust.device(&thief_id()).is_none_or(|t| t.cut.is_some()));
        }
        assert!(trust.device(&device_id(8)).is_none(), "a puppet got in");
        let view = d.view();
        assert_eq!(view.vaults[&w.vault].wrapped_key, w.vault_key);
        for id in view.items.keys() {
            let title = title_of(&view, *id).unwrap_or_default();
            assert!(!title.starts_with("evil"), "forged content shows: {title}");
        }
        assert_nothing_unaccounted(d.fold(), &view);
        assert_no_lost_edit(d.fold(), &view, trust, &all);
        assert_cut_versions_hidden(d.fold(), trust);
    }
}

proptest! {
    // 32 cases by default; `PROPTEST_CASES=20000 cargo test --release …` for a stress run.
    #![proptest_config(ProptestConfig {
        cases: std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(32),
        ..ProptestConfig::default()
    })]

    #[test]
    fn honest_devices_withstand_a_stolen_device_a_thief_and_a_lying_store(
        seed in any::<u64>(),
        ops in prop::collection::vec(op(), 1..50),
    ) {
        check(seed, &ops);
    }
}

#[test]
fn every_attack_in_one_fixed_run() {
    // A fixed run through every kind of attack, so a regression shows without proptest.
    let ops = vec![
        Op::Save { dev: 1, item: 0 },
        Op::StolenSave { item: 0 },
        Op::StolenRevoke { target: 0, at: 0 },
        Op::StolenRevoke {
            target: STOLEN,
            at: 0,
        },
        Op::StolenEndorse { target: HONEST },
        Op::StolenEndorse { target: 1 },
        Op::StolenCheckpoint { target: 2, seq: 1 },
        Op::StolenVaultKey,
        Op::StolenCopy { item: 1 },
        Op::Sync { dev: 2 },
        Op::StolenFork { dev: 2 },
        Op::SelfJoin,
        Op::ThiefSave { item: 2 },
        Op::ThiefRevoke { target: 0 },
        Op::ThiefEndorse,
        Op::Sync { dev: 0 },
        Op::Rollback { dev: 1, stream: 0 },
        Op::Save { dev: 2, item: 0 },
    ];
    check(3, &ops);
}
