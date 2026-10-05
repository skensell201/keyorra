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
