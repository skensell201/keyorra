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
    let joined = unlock_join_with(&files, None, None, |h| unlock_test_header(h, PASSWORD)).unwrap();
    assert!(!joined.roots_disagree);
    let (file, account_key) = (joined.file, joined.account_key);
    assert_eq!(account_key.as_bytes(), &ACCOUNT_KEY);
    assert!(unlock_join_with(&files, None, None, |h| unlock_test_header(h, "wrong")).is_err());
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
    // Device 1's own stream went back, but the main device's snapshot covers it: nothing
    // to restore, it goes on.
    save(&mut c, 1, vault, Uuid::from_bytes([0x61; 16]), "later");
    c.devices[1].sync(&store, c.clocks[1]).unwrap();
    assert!(
        c.devices[1].alarms().is_empty(),
        "{:?}",
        c.devices[1].alarms()
    );
    assert!(c.devices[1]
        .take_events()
        .iter()
        .any(|e| matches!(e, Event::RollbackRepaired { .. })));
    // Device 2 never saw the lost segment: it is anchored by the main device's snapshot.
    c.devices[2].sync(&store, c.clocks[2]).unwrap();
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

/// An outbox store whose saves fail while `failing` is set.
#[derive(Clone, Default)]
struct FlakyOutbox(std::sync::Arc<std::sync::atomic::AtomicBool>);

impl OutboxStore for FlakyOutbox {
    fn save(&mut self, _: &OutboxState) -> Result<()> {
        if self.0.load(std::sync::atomic::Ordering::SeqCst) {
            Err(Error::Transport("disk full".into()))
        } else {
            Ok(())
        }
    }
}

#[test]
fn nothing_is_appended_while_the_outbox_cannot_be_saved() {
    let (mut c, vault) = shared(2);
    let flaky = FlakyOutbox::default();
    c.devices[1].set_outbox_store(Box::new(flaky.clone()));
    flaky.0.store(true, std::sync::atomic::Ordering::SeqCst);
    let before = c.store.head(&device_id(1)).unwrap();
    save(&mut c, 1, vault, ITEM, "unsaved");
    c.sync(1).unwrap();
    assert_eq!(c.store.head(&device_id(1)).unwrap(), before, "not appended");
    assert!(c.devices[1]
        .take_events()
        .iter()
        .any(|e| matches!(e, Event::OutboxNotSaved(_))));
    flaky.0.store(false, std::sync::atomic::Ordering::SeqCst);
    c.sync(1).unwrap();
    c.sync(0).unwrap();
    assert!(titles(&c.devices[0].view()).contains("unsaved"));
}

#[test]
fn an_inconsistent_outbox_state_is_refused() {
    let (mut c, vault) = shared(2);
    save(&mut c, 1, vault, ITEM, "queued");
    let good = c.devices[1].outbox_state();
    let mut restarted = clone_of(&c.devices[1]);
    let mut bad = good.clone();
    bad.next_seq += 1;
    assert!(restarted.restore_outbox(bad).is_err());
    let mut bad = good.clone();
    bad.own_hashes.clear();
    assert!(restarted.restore_outbox(bad).is_err());
    restarted.restore_outbox(good).unwrap();
}

#[test]
fn a_restored_outbox_must_chain_its_queued_entries() {
    let (mut c, vault) = shared(2);
    save(&mut c, 1, vault, ITEM, "queued");
    let good = c.devices[1].outbox_state();
    assert!(!good.outbox.is_empty());
    let mut restarted = clone_of(&c.devices[1]);
    let mut bad = good.clone();
    let last = bad.outbox.len() - 1;
    bad.outbox[last] = crate::cbor::encode(&Entry::Checkpoint(Heads::new()).to_value());
    assert!(restarted.restore_outbox(bad).is_err());
    restarted.restore_outbox(good).unwrap();
}

#[test]
fn own_segments_covered_by_a_root_snapshot_are_not_kept() {
    let (mut c, vault) = shared(2);
    for t in ["a", "b", "c"] {
        save(&mut c, 1, vault, ITEM, t);
        c.sync(1).unwrap();
    }
    assert!(c.devices[1].own_segments.len() >= 3);
    c.sync(0).unwrap();
    c.devices[0].write_snapshot(&c.store, c.clocks[0]).unwrap();
    c.sync(0).unwrap();
    c.sync(1).unwrap();
    let covered = c.devices[0].heads[&device_id(1)].seq;
    assert!(c.devices[1]
        .own_segments
        .keys()
        .all(|first| *first > covered));
}

#[test]
fn a_device_repairs_its_own_rolled_back_stream_by_appending_it_again() {
    let (mut c, vault) = shared(3);
    let backup = c.store.deep_copy();
    save(&mut c, 1, vault, ITEM, "after the backup");
    c.sync(1).unwrap();
    let store = backup;
    save(&mut c, 1, vault, Uuid::from_bytes([0x61; 16]), "later");
    // It appends the lost segment again by itself (it kept it): no alarm (review F1).
    c.devices[1].sync(&store, c.clocks[1]).unwrap();
    assert!(
        c.devices[1].alarms().is_empty(),
        "{:?}",
        c.devices[1].alarms()
    );
    assert!(c.devices[1]
        .take_events()
        .iter()
        .any(|e| matches!(e, Event::RollbackRepaired { .. })));
    c.devices[2].sync(&store, c.clocks[2]).unwrap();
    let seen = titles(&c.devices[2].view());
    assert!(
        seen.contains("after the backup") && seen.contains("later"),
        "{seen:?}"
    );
}
