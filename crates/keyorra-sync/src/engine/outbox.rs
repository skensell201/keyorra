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

impl OutboxState {
    /// Canonical CBOR (the app seals it with the account key).
    pub fn to_bytes(&self) -> Vec<u8> {
        let head = |h: &Head| Value::Array(vec![Value::Uint(h.seq), Value::bytes(h.hash)]);
        crate::cbor::encode(&Value::map(vec![
            ("device", Value::bytes(self.device)),
            ("next_seq", Value::Uint(self.next_seq)),
            ("sent", head(&self.sent)),
            (
                "own_hashes",
                Value::Array(
                    self.own_hashes
                        .iter()
                        .map(|(s, h)| Value::Array(vec![Value::Uint(*s), Value::bytes(h)]))
                        .collect(),
                ),
            ),
            (
                "unsent",
                match &self.unsent {
                    None => Value::Null,
                    Some(u) => Value::Array(vec![
                        Value::bytes(&u.bytes),
                        Value::Uint(u.versions as u64),
                        Value::Uint(u.last_seq),
                        Value::bytes(u.last_hash),
                    ]),
                },
            ),
            (
                "outbox",
                Value::Array(self.outbox.iter().map(Value::bytes).collect()),
            ),
        ]))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<OutboxState> {
        let v = crate::cbor::decode(bytes)?;
        let f = v.fields(&[
            "device",
            "next_seq",
            "sent",
            "own_hashes",
            "unsent",
            "outbox",
        ])?;
        let head = |v: &Value| -> Result<Head> {
            let [s, h] = v.as_list()? else {
                return Err(crate::error::malformed("head"));
            };
            Ok(Head {
                seq: s.as_uint()?,
                hash: h.as_array_of()?,
            })
        };
        Ok(OutboxState {
            device: f.get("device")?.as_array_of()?,
            next_seq: f.get("next_seq")?.as_uint()?,
            sent: head(f.get("sent")?)?,
            own_hashes: f
                .get("own_hashes")?
                .as_list()?
                .iter()
                .map(|p| head(p).map(|h| (h.seq, h.hash)))
                .collect::<Result<_>>()?,
            unsent: match f.get("unsent")? {
                Value::Null => None,
                u => {
                    let [b, n, s, h] = u.as_list()? else {
                        return Err(crate::error::malformed("unsent"));
                    };
                    Some(SealedSegment {
                        bytes: b.as_bytes()?.to_vec(),
                        versions: n.as_uint()? as usize,
                        last_seq: s.as_uint()?,
                        last_hash: h.as_array_of()?,
                    })
                }
            },
            outbox: f
                .get("outbox")?
                .as_list()?
                .iter()
                .map(|b| b.as_bytes().map(<[u8]>::to_vec))
                .collect::<Result<_>>()?,
        })
    }
}

/// Where A1d keeps [`OutboxState`] (in the same transaction as the local change).
pub trait OutboxStore: Send {
    /// Persists `state`. On an error the engine appends nothing until a save succeeds, so it
    /// never sends what a restart would not know about (review minor).
    fn save(&mut self, state: &OutboxState) -> Result<()>;
}

/// Nothing is persisted (tests, and until A1d).
pub struct NoOutboxStore;

impl OutboxStore for NoOutboxStore {
    fn save(&mut self, _: &OutboxState) -> Result<()> {
        Ok(())
    }
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

    /// Continues from a persisted state after a restart (A1d also restores the fold). The
    /// state must be consistent: positions add up, and every own position from the confirmed
    /// one on has its chain hash (the unsent segment's end included).
    pub fn restore_outbox(&mut self, state: OutboxState) -> Result<()> {
        if state.device != self.device {
            return Err(Error::Refused("outbox of another device".into()));
        }
        let after_unsent = state.unsent.as_ref().map_or(state.sent.seq, |u| u.last_seq);
        if state.next_seq != after_unsent + state.outbox.len() as u64 + 1 {
            return Err(Error::Refused("outbox positions do not add up".into()));
        }
        let covered =
            (state.sent.seq.max(1)..state.next_seq).all(|seq| state.own_hashes.contains_key(&seq));
        let sent_ok =
            state.sent.seq == 0 || state.own_hashes.get(&state.sent.seq) == Some(&state.sent.hash);
        let unsent_ok = state
            .unsent
            .as_ref()
            .is_none_or(|u| state.own_hashes.get(&u.last_seq) == Some(&u.last_hash));
        if !covered || !sent_ok || !unsent_ok {
            return Err(Error::Refused(
                "outbox chain hashes are missing or wrong".into(),
            ));
        }
        let outbox = state
            .outbox
            .iter()
            .map(|b| crate::cbor::decode(b))
            .collect::<Result<Vec<Value>>>()?;
        // The queued entries must be exactly the ones whose chain hashes were kept.
        let mut prev = if after_unsent == 0 {
            chain_genesis(&self.account_id, &self.device)
        } else {
            *state
                .own_hashes
                .get(&after_unsent)
                .ok_or_else(|| Error::Refused("outbox chain hashes are missing".into()))?
        };
        for (i, value) in outbox.iter().enumerate() {
            prev = chain_next(&prev, value);
            if state.own_hashes.get(&(after_unsent + 1 + i as u64)) != Some(&prev) {
                return Err(Error::Refused(
                    "queued outbox entries do not match their chain hashes".into(),
                ));
            }
        }
        self.next_seq = state.next_seq;
        self.sent = state.sent;
        self.own_hashes = state.own_hashes;
        self.unsent = state.unsent;
        self.outbox = outbox;
        Ok(())
    }

    /// Saves the state; returns whether it was saved (otherwise nothing is appended).
    pub(super) fn save_outbox(&mut self) -> bool {
        let state = self.outbox_state();
        match self.outbox_store.save(&state) {
            Ok(()) => {
                self.outbox_unsaved = false;
                true
            }
            Err(e) => {
                self.outbox_unsaved = true;
                self.events.push(Event::OutboxNotSaved(e.to_string()));
                false
            }
        }
    }
}
