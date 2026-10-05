//! Plan A1d: an engine continues after a restart from its outbox, kept segments and memo.

use rand::SeedableRng;
use uuid::Uuid;

use super::*;
use crate::faults::Faults;
use crate::testkit::{device_id, device_name, signer, Cluster, ACCOUNT_ID, ACCOUNT_KEY, START_MS};

const ITEM: Uuid = Uuid::from_bytes([0x60; 16]);

fn title(view: &View, id: Uuid) -> String {
    let p = view.items[&id].payload.as_ref().expect("item has content");
    let v: serde_json::Value = serde_json::from_slice(&p.item_json).unwrap();
    v["title"].as_str().unwrap().to_owned()
}

/// What the app would persist, and a fresh engine continuing from it.
fn restart(c: &mut Cluster, i: usize) {
    let e = &c.devices[i];
    let saved = Resumed {
        outbox: e.outbox_state(),
        own_segments: e.own_segments().clone(),
        memo: EngineMemo::from_bytes(&e.memo().to_bytes()).unwrap(),
    };
    let fresh = Engine::resume(
        device_id(i),
        signer(i),
        &device_name(i),
        ACCOUNT_ID,
        Key::from_bytes(ACCOUNT_KEY),
        device_id(0),
        signer(0).verifying_key(),
        rand::rngs::StdRng::seed_from_u64(1000 + i as u64),
        saved,
    )
    .unwrap();
    c.devices[i] = fresh;
}

fn shared(n: usize) -> (Cluster, Uuid) {
    let mut c = Cluster::new(n, 21, Faults::NONE);
    let vault = c.devices[0].create_vault("Personal", START_MS).unwrap();
    let json = Cluster::item_json(ITEM, "base", &[]);
    c.devices[0]
        .save_item(vault, ITEM, &json, START_MS)
        .unwrap();
    c.heal();
    (c, vault)
}

#[test]
fn a_restarted_device_reads_everything_again_and_goes_on() {
    let (mut c, vault) = shared(3);
    let json = Cluster::item_json(ITEM, "by 1", &[]);
    c.devices[1]
        .save_item(vault, ITEM, &json, c.clocks[1])
        .unwrap();
    c.heal();
    let before = c.devices[1].view();
    restart(&mut c, 1);
    assert!(
        !c.devices[1].can_write(),
        "nothing new before its own stream is read"
    );
    c.sync(1).unwrap();
    assert!(!c.devices[1].is_rebuilding());
    assert_eq!(c.devices[1].view(), before);
    // It goes on writing where it left off: no conflict with its own earlier edit.
    let json = Cluster::item_json(ITEM, "after restart", &[]);
    c.devices[1]
        .save_item(vault, ITEM, &json, c.clocks[1])
        .unwrap();
    c.heal();
    c.assert_converged();
    assert_eq!(title(&c.devices[0].view(), ITEM), "after restart");
    assert!(c.devices[0].view().conflict_copies().is_empty());
}

#[test]
fn queued_changes_survive_a_restart_and_land_once() {
    let (mut c, vault) = shared(2);
    // Offline: the change is queued and its segment sealed, but never confirmed.
    c.links[1].set_faults(Faults {
        fail_before_append: 100,
        ..Faults::NONE
    });
    let json = Cluster::item_json(ITEM, "offline", &[]);
    c.devices[1]
        .save_item(vault, ITEM, &json, c.clocks[1])
        .unwrap();
    let _ = c.sync(1);
    let other = Uuid::from_bytes([0x61; 16]);
    let json = Cluster::item_json(other, "queued", &[]);
    c.devices[1]
        .save_item(vault, other, &json, c.clocks[1])
        .unwrap();
    restart(&mut c, 1);
    assert!(
        c.devices[1].view().items.is_empty(),
        "nothing read back yet"
    );
    c.heal();
    c.assert_converged();
    let view = c.devices[0].view();
    assert_eq!(title(&view, ITEM), "offline");
    assert_eq!(title(&view, other), "queued");
    assert!(view.conflict_copies().is_empty());
}

#[test]
fn the_main_device_restarts_with_its_trust() {
    let (mut c, vault) = shared(3);
    c.devices[0].revoke(device_id(2), c.clocks[0]).unwrap();
    c.heal();
    restart(&mut c, 0);
    c.sync(0).unwrap();
    assert!(c.devices[0].is_root());
    assert!(c.devices[0]
        .trust()
        .device(&device_id(2))
        .unwrap()
        .cut
        .is_some());
    let json = Cluster::item_json(ITEM, "root again", &[]);
    c.devices[0]
        .save_item(vault, ITEM, &json, c.clocks[0])
        .unwrap();
    c.heal();
    c.assert_converged();
    assert_eq!(title(&c.devices[1].view(), ITEM), "root again");
}

#[test]
fn a_history_that_changed_while_the_app_was_closed_is_a_fork() {
    let (mut c, vault) = shared(3);
    let e = &c.devices[2];
    let mut memo = e.memo();
    // Pretend device 2 had received another history of device 1 before the restart.
    let h = memo.heads.get_mut(&device_id(1)).unwrap();
    h.hash = [9; 32];
    let saved = Resumed {
        outbox: e.outbox_state(),
        own_segments: e.own_segments().clone(),
        memo,
    };
    c.devices[2] = Engine::resume(
        device_id(2),
        signer(2),
        &device_name(2),
        ACCOUNT_ID,
        Key::from_bytes(ACCOUNT_KEY),
        device_id(0),
        signer(0).verifying_key(),
        rand::rngs::StdRng::seed_from_u64(7),
        saved,
    )
    .unwrap();
    let _ = vault;
    c.sync(2).unwrap();
    assert!(c.devices[2]
        .alarms()
        .iter()
        .any(|a| matches!(a, Alarm::Fork { stream, .. } if *stream == device_id(1))));
}

#[test]
fn the_memo_round_trips() {
    let memo = EngineMemo {
        accepted_alarms: vec![
            Alarm::Fork {
                stream: [1; 16],
                seq: 3,
            },
            Alarm::Disputed {
                stream: [2; 16],
                seq: 4,
                by: [3; 16],
            },
            Alarm::Rollback {
                stream: [4; 16],
                received: 9,
                stored: 2,
            },
            Alarm::ForeignHeader {
                epoch: 7,
                root: [5; 16],
            },
        ],
        acknowledged_rollbacks: vec![([4; 16], 2)],
        blocked: vec![[1; 16]],
        unapproved_seen: 2,
        heads: [(
            [6; 16],
            Head {
                seq: 11,
                hash: [7; 32],
            },
        )]
        .into_iter()
        .collect(),
        root_head_advertised: Some(Head {
            seq: 12,
            hash: [8; 32],
        }),
        root_time: Some((100, 200)),
        own_covered: 5,
    };
    assert_eq!(EngineMemo::from_bytes(&memo.to_bytes()).unwrap(), memo);
}

#[test]
fn an_existing_vault_is_adopted_with_its_id_and_key() {
    let mut c = Cluster::new(2, 3, Faults::NONE);
    let id = Uuid::from_bytes([0x44; 16]);
    let key = Key::from_bytes([0x55; 32]);
    c.devices[0].adopt_vault(id, "Old", &key, START_MS).unwrap();
    let json = Cluster::item_json(ITEM, "kept", &[]);
    c.devices[0].save_item(id, ITEM, &json, START_MS).unwrap();
    assert!(c.devices[0]
        .adopt_vault(id, "Again", &key, START_MS)
        .is_err());
    c.heal();
    let view = c.devices[1].view();
    assert_eq!(view.vaults[&id].name, "Old");
    assert_eq!(title(&view, ITEM), "kept");
    let wrapped = &view.vaults[&id].wrapped_key;
    let unwrapped = crypto::unwrap_vault_key(&Key::from_bytes(ACCOUNT_KEY), id, wrapped).unwrap();
    assert_eq!(unwrapped.as_bytes(), key.as_bytes());
}
