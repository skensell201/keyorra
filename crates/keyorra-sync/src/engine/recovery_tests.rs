#![allow(unused_imports, dead_code)] // TEMPORARY: removed in Task 10 (later tasks use these)
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
