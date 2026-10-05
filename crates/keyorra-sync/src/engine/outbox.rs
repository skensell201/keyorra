//! The outbox persistence hook (for plan A1d): everything needed to continue the own stream
//! after a restart. The engine saves it after every queued entry, after sealing a segment
//! (before the append, so a restart retries the same bytes instead of resealing with a new
//! nonce, which the store would answer with `Conflict`) and after every confirmation.

use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboxState {
    pub device: DeviceId,
    pub next_seq: u64,
    pub sent: Head,
    /// Chain hash of every own entry, confirmed or queued.
    pub own_hashes: BTreeMap<u64, [u8; 32]>,
    pub unsent: Option<SealedSegment>,
    /// Queued entries, canonical CBOR.
    pub outbox: Vec<Vec<u8>>,
}

/// Where A1d keeps [`OutboxState`] (in the same transaction as the local change).
pub trait OutboxStore: Send {
    fn save(&mut self, state: &OutboxState);
}

/// Nothing is persisted (tests, and until A1d).
pub struct NoOutboxStore;

impl OutboxStore for NoOutboxStore {
    fn save(&mut self, _: &OutboxState) {}
}

impl<R: RngCore + CryptoRng> Engine<R> {
    pub fn set_outbox_store(&mut self, store: Box<dyn OutboxStore>) {
        self.outbox_store = store;
    }

    pub fn outbox_state(&self) -> OutboxState {
        OutboxState {
            device: self.device,
            next_seq: self.next_seq,
            sent: self.sent,
            own_hashes: self.own_hashes.clone(),
            unsent: self.unsent.clone(),
            outbox: self.outbox.iter().map(crate::cbor::encode).collect(),
        }
    }

    /// Continues from a persisted state after a restart (A1d also restores the fold).
    pub fn restore_outbox(&mut self, state: OutboxState) -> Result<()> {
        if state.device != self.device {
            return Err(Error::Refused("outbox of another device".into()));
        }
        let outbox = state
            .outbox
            .iter()
            .map(|b| crate::cbor::decode(b))
            .collect::<Result<Vec<Value>>>()?;
        self.next_seq = state.next_seq;
        self.sent = state.sent;
        self.own_hashes = state.own_hashes;
        self.unsent = state.unsent;
        self.outbox = outbox;
        Ok(())
    }

    pub(super) fn save_outbox(&mut self) {
        let state = self.outbox_state();
        self.outbox_store.save(&state);
    }
}
