//! Retiring the device id (spec §4.2): when another copy of this device wrote to its stream
//! (a clone, a restored backup, Migration Assistant) or its signing key is gone from the key
//! store, this device stops using the id and continues under a new id and key. It joins with
//! `SelfJoin` (pending: its writes count for nobody else until the main device approves it,
//! comparing the key code) and writes its own unconfirmed changes again under the new id. The
//! old id is not removed here: only the main device removes devices (A3 points to it).
//!
//! The main device cannot retire (its id and key are the account's anchor): it stops writing
//! and asks the user to start a new account from a device and carry the data over.

use super::*;

/// The device's signing keys. A1d keeps them in the Keychain with
/// `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, so a database restored or copied to
/// another Mac finds no key and retires.
pub trait DeviceKeys: Send {
    fn holds(&self, device: &DeviceId) -> bool;
    fn store(&mut self, device: DeviceId, key: &SigningKey);
}

/// Assumes every key is held and stores nothing (tests, and until A1d).
pub struct KeepKeys;

impl DeviceKeys for KeepKeys {
    fn holds(&self, _: &DeviceId) -> bool {
        true
    }
    fn store(&mut self, _: DeviceId, _: &SigningKey) {}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetireReason {
    /// The signing key is not in this device's key store.
    KeyMissing,
    /// Another copy of this device wrote to its stream.
    OtherCopyWrote,
}

impl<R: RngCore + CryptoRng> Engine<R> {
    pub fn set_device_keys(&mut self, keys: Box<dyn DeviceKeys>) {
        self.keys = keys;
    }

    pub(super) fn retire(&mut self, reason: RetireReason, wall_ms: u64) -> Result<()> {
        if self.is_root() {
            if !self.halted {
                self.halted = true;
                self.events.push(Event::RootMustStartOver { reason });
            }
            return Ok(());
        }
        let old = self.device;
        let cut = self.sent.seq;
        // The last own version of every record written after the last confirmed position.
        let mut again: BTreeMap<RecordKey, Accepted> = BTreeMap::new();
        for a in self.fold.retained() {
            if a.stream == old && a.seq > cut {
                let newer = again.get(&a.key()).is_none_or(|b| a.seq > b.seq);
                if newer {
                    again.insert(a.key(), a.clone());
                }
            }
        }
        // Those positions now belong to the other copy: forget them under the old id.
        self.fold.forget_after(&old, cut);
        self.header_seen.retain(|(d, s, _)| *d != old || *s <= cut);
        self.trust_changed();
        let mut id = [0u8; 16];
        self.rng.fill_bytes(&mut id);
        let mut secret = Zeroizing::new([0u8; 32]);
        self.rng.fill_bytes(&mut secret[..]);
        let signer = SigningKey::from_bytes(&secret);
        self.keys.store(id, &signer);
        self.device = id;
        self.signer = signer;
        self.sent = Head {
            seq: 0,
            hash: chain_genesis(&self.account_id, &id),
        };
        self.own_hashes.clear();
        self.unsent = None;
        self.outbox.clear();
        self.next_seq = 1;
        self.last_checkpoint = None;
        self.retire_due = None;
        self.self_join(wall_ms)?;
        for (_, a) in again {
            let edit = matches!(a.doc, Doc::Item(_));
            self.write_with(a.kind, a.record_id, a.vault_id, a.doc, wall_ms, edit)?;
        }
        self.events.push(Event::Retired {
            old,
            new: id,
            reason,
        });
        Ok(())
    }
}
