//! What the Sync screen shows and does (plan A3): alarms with their explanations and the
//! actions that fit, the log, a check of the local copy against sync, and the files as the
//! folder holds them.

use keyorra_core::model::Item;
use keyorra_core::store::{ItemEntry, Store};
use keyorra_sync::engine::{Alarm, Event, RetireReason};
use keyorra_sync::present::ItemState;
use keyorra_sync::transport::{InventoryEntry, Transport};
use keyorra_sync::{DeviceId, Error, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::Synced;

/// One alarm as the Sync screen shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AlarmView {
    /// Stable while the alarm stands; actions name it.
    pub id: String,
    pub kind: &'static str,
    pub title: String,
    pub explanation: String,
    /// What the user can do: "accept", "restore", "remove", "leave".
    pub actions: Vec<&'static str>,
}

/// The result of "Verify everything".
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyReport {
    pub items: usize,
    /// Items here that cannot be decrypted.
    pub damaged: usize,
    pub attachments: usize,
    /// Attachments here whose content cannot be decrypted.
    pub damaged_attachments: usize,
    /// Items whose content here differs from what sync shows (and that wait for no local
    /// change): titles, for the user.
    pub differing: Vec<String>,
    /// Sync has them, this vault does not.
    pub missing: usize,
}

fn alarm_id(alarm: &Alarm) -> String {
    let digest = Sha256::digest(format!("{alarm:?}").as_bytes());
    data_encoding::HEXLOWER.encode(&digest[..8])
}

impl<T: Transport> Synced<T> {
    /// A device's name as the account knows it, or the start of its id.
    pub fn device_label(&self, device: &DeviceId) -> String {
        let trust = self.engine.trust();
        if *device == self.engine.device() {
            return "This Mac".to_owned();
        }
        trust
            .device(device)
            .map(|d| d.name.clone())
            .or_else(|| trust.unapproved().get(device).map(|d| d.name.clone()))
            .unwrap_or_else(|| format!("device {}", data_encoding::HEXLOWER.encode(&device[..4])))
    }

    pub fn alarm_views(&self) -> Vec<AlarmView> {
        let main = self.engine.is_root();
        let me = self.engine.device();
        self.engine
            .alarms()
            .iter()
            .map(|alarm| {
                let (kind, title, explanation, actions): (_, String, String, Vec<&'static str>) =
                    match alarm {
                        Alarm::Rollback { stream, .. } if *stream == me => (
                            "rollback",
                            "This Mac's changes are missing from the sync folder".into(),
                            "The folder holds fewer of this Mac's changes than it wrote: an \
                             old copy of the folder was restored, or files were deleted. \
                             Restore puts them back from this Mac."
                                .into(),
                            vec!["restore", "accept"],
                        ),
                        Alarm::Rollback { stream, .. } => (
                            "rollback",
                            format!(
                                "Changes of {} went missing from the sync folder",
                                self.device_label(stream)
                            ),
                            "The folder holds fewer of that device's changes than this Mac \
                             already has: an old copy of the folder was restored, or files \
                             were deleted. Its newer changes are paused here."
                                .into(),
                            if main {
                                vec!["restore", "accept"]
                            } else {
                                vec!["accept"]
                            },
                        ),
                        Alarm::Fork { stream, .. } => (
                            "fork",
                            format!("Two different histories of {}", self.device_label(stream)),
                            "The folder shows that device's changes in two versions: a copy of \
                             that Mac (a restored backup) wrote too, or the files were tampered \
                             with. Its changes are paused here. If you do not recognise this, \
                             remove the device on your main Mac."
                                .into(),
                            if main && *stream != me {
                                vec!["remove", "accept"]
                            } else {
                                vec!["accept"]
                            },
                        ),
                        Alarm::OwnStreamTampered { .. } => (
                            "ownStreamTampered",
                            "Something occupies this Mac's place in the sync folder".into(),
                            "A file that is not this Mac's sits where its next changes go. \
                             Remove it from the folder and try again, or let this Mac continue \
                             under a new identity (the main Mac approves it again)."
                                .into(),
                            vec!["accept", "leave"],
                        ),
                        Alarm::Disputed { stream, by, .. } => (
                            "disputed",
                            format!(
                                "{} reports another history of {}",
                                self.device_label(by),
                                self.device_label(stream)
                            ),
                            "One of the two is wrong or tampered with. Nothing is paused; if it \
                             repeats, remove the device you do not trust."
                                .into(),
                            vec!["accept"],
                        ),
                        Alarm::RootBehind { .. } => (
                            "rootBehind",
                            "Not all of the main Mac's changes are here yet".into(),
                            "Until they are, changes of other devices count as unconfirmed. \
                             This clears by itself once the folder catches up."
                                .into(),
                            vec![],
                        ),
                        Alarm::ForeignHeader { .. } => (
                            "foreignHeader",
                            "An account file names another main Mac".into(),
                            "Someone with your master password and Secret Key wrote it. Devices \
                             that join with the Emergency Kit alone could trust it. Consider \
                             starting a new account from your main Mac."
                                .into(),
                            vec!["accept"],
                        ),
                        Alarm::ApprovedWithAnotherKey => (
                            "approvedWithAnotherKey",
                            "The main Mac approved this Mac with another key".into(),
                            "This Mac's request to join was replaced on the way. It writes \
                             nothing. Join again and compare the code carefully."
                                .into(),
                            vec!["leave"],
                        ),
                        Alarm::Unapproved { count } => (
                            "unapproved",
                            format!("{count} device(s) wait for the main Mac's approval"),
                            "They joined with the Emergency Kit. Their changes count for nobody \
                             until the main Mac approves them."
                                .into(),
                            vec![],
                        ),
                    };
                AlarmView {
                    id: alarm_id(alarm),
                    kind,
                    title,
                    explanation,
                    actions,
                }
            })
            .collect()
    }

    /// Does `action` for the alarm named `id`.
    pub fn alarm_action(&mut self, id: &str, action: &str, wall_ms: u64) -> Result<()> {
        let alarm = self
            .engine
            .alarms()
            .into_iter()
            .find(|a| alarm_id(a) == id)
            .ok_or_else(|| Error::NotFound("that alarm is gone".into()))?;
        let offered = self
            .alarm_views()
            .into_iter()
            .find(|v| v.id == id)
            .is_some_and(|v| v.actions.contains(&action));
        if !offered {
            return Err(Error::Refused(format!(
                "{action} is not offered for this alarm"
            )));
        }
        match (action, &alarm) {
            ("accept", _) => {
                self.engine.accept_alarm(&alarm);
                Ok(())
            }
            ("restore", Alarm::Rollback { stream, .. }) => {
                self.engine.restore(&self.transport, *stream, wall_ms)
            }
            ("remove", Alarm::Fork { stream, .. }) => self.engine.revoke(*stream, wall_ms),
            ("leave", _) => self.engine.leave_id(wall_ms),
            _ => Err(Error::Refused(format!("{action} does not fit this alarm"))),
        }
    }

    /// The main Mac removes a device (it can no longer read what is written from now on;
    /// what it had stays with it).
    pub fn remove_device(&mut self, device: DeviceId, wall_ms: u64) -> Result<()> {
        self.engine.revoke(device, wall_ms)
    }

    /// Whether other devices' changes are confirmed by the main Mac's newest decisions.
    pub fn root_confirmed(&self) -> bool {
        self.engine.root_confirmed()
    }

    /// The files of the account as the store holds them.
    pub fn inventory(&self) -> Result<Vec<InventoryEntry>> {
        self.transport.inventory()
    }

    /// Checks the local copy: everything decrypts, and every live item matches what sync
    /// shows (records with local changes waiting are left out).
    pub fn verify(&self, store: &Store) -> Result<VerifyReport> {
        let mut report = VerifyReport::default();
        let pending: std::collections::BTreeSet<uuid::Uuid> =
            store.pending_changes()?.into_iter().map(|c| c.id).collect();
        let mut entries = store.list_items(None)?;
        entries.extend(store.deleted_items()?);
        for entry in &entries {
            report.items += 1;
            if matches!(entry, ItemEntry::Damaged { .. }) {
                report.damaged += 1;
            }
        }
        for id in store.attachment_ids()? {
            report.attachments += 1;
            if store.attachment_content(id).is_err() {
                report.damaged_attachments += 1;
            }
        }
        let view = self.engine.view();
        for (id, v) in &view.items {
            if pending.contains(id) || v.state != ItemState::Live {
                continue;
            }
            let (Some(p), Some(vault)) = (&v.payload, v.vault_id) else {
                continue;
            };
            let Ok(mut synced) = serde_json::from_slice::<Item>(&p.item_json) else {
                continue;
            };
            synced.id = *id;
            synced.vault_id = vault;
            match store.item_state(*id)? {
                Some((local, None)) if local == synced => {}
                Some((local, _)) => report.differing.push(local.title),
                None => report.missing += 1,
            }
        }
        Ok(report)
    }

    /// A line for the Sync log, for the events worth a line.
    pub fn describe(&self, event: &Event) -> Option<String> {
        Some(match event {
            Event::Pulled { from, versions } => format!(
                "Received {versions} change(s) from {}",
                self.device_label(from)
            ),
            Event::Pushed { versions } => format!("Sent {versions} change(s)"),
            Event::PushFailed(e) => format!("Sending failed: {e}"),
            Event::Unreadable { from, .. } => format!(
                "A file of {} could not be read yet; trying again",
                self.device_label(from)
            ),
            Event::Rejected { from, reason, .. } => format!(
                "Changes of {} were refused: {reason}",
                self.device_label(from)
            ),
            Event::Alarm(a) => format!("Alarm: {a}"),
            Event::Resolved { copies, .. } => format!("Made {copies} conflict copy(ies)"),
            Event::Retired { reason, .. } => format!(
                "This Mac continues under a new identity ({}); the main Mac approves it again",
                match reason {
                    RetireReason::OtherCopyWrote => "another copy of it wrote",
                    RetireReason::KeyMissing => "its device key is gone",
                }
            ),
            Event::RootMustStartOver { .. } => {
                "The main Mac's identity was copied or lost: start a new account from it".into()
            }
            Event::HeaderAdopted { epoch } => {
                format!("The master password was changed on the main Mac (epoch {epoch})")
            }
            Event::RootSilent { .. } => "The main Mac has not synced for a week".into(),
            Event::OwnStreamCleaned { seq } => {
                format!("Removed a stray file at this Mac's position {seq}")
            }
            Event::OutboxNotSaved(e) => format!("Could not save what is waiting to be sent: {e}"),
            Event::RollbackRepaired { stream } => format!(
                "Changes of {} missing from the folder are covered by a snapshot",
                self.device_label(stream)
            ),
            Event::Removed => "This Mac was removed from the account".into(),
            _ => return None,
        })
    }
}
