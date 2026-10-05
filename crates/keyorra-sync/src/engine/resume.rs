//! Continuing after a restart (plan A1d). The engine keeps no database of its own: the store
//! holds the streams, so a restarted engine reads them again, its own stream included (the
//! fold, trust and headers are rebuilt from them, from the main device's newest snapshot if
//! there is one). What cannot be read again is persisted by the app next to the vault:
//! - the outbox ([`OutboxState`]: positions, chain hashes, the unsent segment, queued entries),
//! - the own confirmed segments kept for repairs ([`Engine::own_segments`]),
//! - a small memo of decisions and observations ([`EngineMemo`]): accepted alarms,
//!   acknowledged rollbacks, streams no longer read, the devices awaiting approval already
//!   shown, the heads last received (a different history after the restart is a fork), the
//!   main device's advertised head and time, and how far its snapshots cover the own stream.
//!
//! Until the own stream is read again up to the confirmed position, nothing new is written;
//! then the queued own entries are applied again and the engine goes on as before.

use crate::cbor::Value;
use crate::entry::{heads_from, heads_value};
use crate::error::malformed;

use super::*;

/// What an engine remembers across restarts besides the streams and its outbox.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct EngineMemo {
    pub accepted_alarms: Vec<Alarm>,
    pub acknowledged_rollbacks: Vec<(DeviceId, u64)>,
    pub blocked: Vec<DeviceId>,
    pub unapproved_seen: u64,
    /// The heads last received from other streams.
    pub heads: Heads,
    pub root_head_advertised: Option<Head>,
    /// The main device's time in its head file, and the local time it last advanced.
    pub root_time: Option<(u64, u64)>,
    pub own_covered: u64,
}

fn alarm_value(a: &Alarm) -> Option<Value> {
    Some(match a {
        Alarm::Rollback {
            stream,
            received,
            stored,
        } => Value::Array(vec![
            Value::text("rollback"),
            Value::bytes(stream),
            Value::Uint(*received),
            Value::Uint(*stored),
        ]),
        Alarm::Fork { stream, seq } => Value::Array(vec![
            Value::text("fork"),
            Value::bytes(stream),
            Value::Uint(*seq),
        ]),
        Alarm::Disputed { stream, seq, by } => Value::Array(vec![
            Value::text("disputed"),
            Value::bytes(stream),
            Value::Uint(*seq),
            Value::bytes(by),
        ]),
        Alarm::ForeignHeader { epoch, root } => Value::Array(vec![
            Value::text("foreign_header"),
            Value::Uint((*epoch).into()),
            Value::bytes(root),
        ]),
        // Computed from state, or noted by count: nothing to remember.
        Alarm::OwnStreamTampered { .. }
        | Alarm::Unapproved { .. }
        | Alarm::RootBehind { .. }
        | Alarm::ApprovedWithAnotherKey => return None,
    })
}

fn alarm_from(v: &Value) -> Result<Alarm> {
    let list = v.as_list()?;
    let tag = list.first().ok_or_else(|| malformed("alarm"))?.as_text()?;
    Ok(match (tag, list) {
        ("rollback", [_, s, r, t]) => Alarm::Rollback {
            stream: s.as_array_of()?,
            received: r.as_uint()?,
            stored: t.as_uint()?,
        },
        ("fork", [_, s, q]) => Alarm::Fork {
            stream: s.as_array_of()?,
            seq: q.as_uint()?,
        },
        ("disputed", [_, s, q, b]) => Alarm::Disputed {
            stream: s.as_array_of()?,
            seq: q.as_uint()?,
            by: b.as_array_of()?,
        },
        ("foreign_header", [_, e, r]) => Alarm::ForeignHeader {
            epoch: e.as_u32()?,
            root: r.as_array_of()?,
        },
        _ => return Err(malformed("alarm")),
    })
}

fn opt_head(h: &Option<Head>) -> Value {
    match h {
        Some(h) => Value::Array(vec![Value::Uint(h.seq), Value::bytes(h.hash)]),
        None => Value::Null,
    }
}

impl EngineMemo {
    /// Canonical CBOR; the app seals it with the account key.
    pub fn to_bytes(&self) -> Vec<u8> {
        crate::cbor::encode(&Value::map(vec![
            (
                "accepted_alarms",
                Value::Array(
                    self.accepted_alarms
                        .iter()
                        .filter_map(alarm_value)
                        .collect(),
                ),
            ),
            (
                "acknowledged_rollbacks",
                Value::Array(
                    self.acknowledged_rollbacks
                        .iter()
                        .map(|(d, s)| Value::Array(vec![Value::bytes(d), Value::Uint(*s)]))
                        .collect(),
                ),
            ),
            (
                "blocked",
                Value::Array(self.blocked.iter().map(Value::bytes).collect()),
            ),
            ("unapproved_seen", Value::Uint(self.unapproved_seen)),
            ("heads", heads_value(&self.heads)),
            ("root_head", opt_head(&self.root_head_advertised)),
            (
                "root_time",
                match self.root_time {
                    Some((r, l)) => Value::Array(vec![Value::Uint(r), Value::Uint(l)]),
                    None => Value::Null,
                },
            ),
            ("own_covered", Value::Uint(self.own_covered)),
        ]))
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<EngineMemo> {
        let v = crate::cbor::decode(bytes)?;
        let f = v.fields(&[
            "accepted_alarms",
            "acknowledged_rollbacks",
            "blocked",
            "unapproved_seen",
            "heads",
            "root_head",
            "root_time",
            "own_covered",
        ])?;
        let pair = |v: &Value| -> Result<(u64, Value)> {
            let [a, b] = v.as_list()? else {
                return Err(malformed("pair"));
            };
            Ok((a.as_uint()?, b.clone()))
        };
        Ok(EngineMemo {
            accepted_alarms: f
                .get("accepted_alarms")?
                .as_list()?
                .iter()
                .map(alarm_from)
                .collect::<Result<_>>()?,
            acknowledged_rollbacks: f
                .get("acknowledged_rollbacks")?
                .as_list()?
                .iter()
                .map(|v| {
                    let [d, s] = v.as_list()? else {
                        return Err(malformed("rollback"));
                    };
                    Ok((d.as_array_of()?, s.as_uint()?))
                })
                .collect::<Result<_>>()?,
            blocked: f
                .get("blocked")?
                .as_list()?
                .iter()
                .map(|v| v.as_array_of())
                .collect::<Result<_>>()?,
            unapproved_seen: f.get("unapproved_seen")?.as_uint()?,
            heads: heads_from(f.get("heads")?)?,
            root_head_advertised: match f.get("root_head")? {
                Value::Null => None,
                v => {
                    let (seq, hash) = pair(v)?;
                    Some(Head {
                        seq,
                        hash: hash.as_array_of()?,
                    })
                }
            },
            root_time: match f.get("root_time")? {
                Value::Null => None,
                v => {
                    let [r, l] = v.as_list()? else {
                        return Err(malformed("root time"));
                    };
                    Some((r.as_uint()?, l.as_uint()?))
                }
            },
            own_covered: f.get("own_covered")?.as_uint()?,
        })
    }
}

/// What an engine needs to continue after a restart.
pub struct Resumed {
    pub outbox: OutboxState,
    /// Own confirmed segments kept for repairs, by first position.
    pub own_segments: BTreeMap<u64, Vec<u8>>,
    pub memo: EngineMemo,
}

impl<R: RngCore + CryptoRng> Engine<R> {
    /// Continues a device after a restart: an engine like [`Engine::join`] that knows its
    /// outbox, its kept segments and its memo, and reads the streams (its own included)
    /// again on its next sync.
    #[allow(clippy::too_many_arguments)]
    pub fn resume(
        device: DeviceId,
        signer: SigningKey,
        name: &str,
        account_id: AccountId,
        account_key: Key,
        root: DeviceId,
        root_key: VerifyingKey,
        rng: R,
        state: Resumed,
    ) -> Result<Self> {
        let mut e = Self::join(
            device,
            signer,
            name,
            account_id,
            account_key,
            root,
            root_key,
            rng,
        );
        e.restore_outbox(state.outbox)?;
        e.own_segments = state.own_segments;
        let m = state.memo;
        e.accepted_alarms = m.accepted_alarms.into_iter().collect();
        e.acknowledged_rollbacks = m.acknowledged_rollbacks.into_iter().collect();
        e.blocked = m.blocked.into_iter().collect();
        e.unapproved_seen = m.unapproved_seen as usize;
        e.remembered_heads = m.heads;
        e.root_head_advertised = m.root_head_advertised;
        e.root_time = m.root_time.map(|(root_ms, since_ms)| RootTime {
            root_ms,
            since_ms,
            reported: false,
        });
        e.own_covered = m.own_covered;
        e.rebuilding = e.sent.seq > 0 || e.unsent.is_some() || !e.outbox.is_empty();
        // A fresh device that only queued its first entries has nothing to read back.
        if e.sent.seq == 0 {
            e.finish_rebuild_now();
        }
        Ok(e)
    }

    /// The memo to persist (after every sync round).
    pub fn memo(&self) -> EngineMemo {
        let mut heads = self.heads.clone();
        // What was received before a restart and not read again yet is still remembered.
        for (stream, h) in &self.remembered_heads {
            if heads.get(stream).is_none_or(|x| x.seq < h.seq) {
                heads.insert(*stream, *h);
            }
        }
        heads.remove(&self.device);
        EngineMemo {
            accepted_alarms: self.accepted_alarms.iter().cloned().collect(),
            acknowledged_rollbacks: self.acknowledged_rollbacks.iter().copied().collect(),
            blocked: self.blocked.iter().copied().collect(),
            unapproved_seen: self.unapproved_seen as u64,
            heads,
            root_head_advertised: self.root_head_advertised,
            root_time: self.root_time.map(|t| (t.root_ms, t.since_ms)),
            own_covered: self.own_covered,
        }
    }

    /// The own confirmed segments kept for repairs (to persist with the outbox).
    pub fn own_segments(&self) -> &BTreeMap<u64, Vec<u8>> {
        &self.own_segments
    }

    /// Whether the engine is still reading its own stream again after a restart.
    pub fn is_rebuilding(&self) -> bool {
        self.rebuilding
    }

    /// Called after each pull while rebuilding: once the own stream is read up to the
    /// confirmed position, the queued own entries are applied again.
    pub(super) fn finish_rebuild(&mut self, wall_ms: u64) {
        let read = self.heads.get(&self.device).map_or(0, |h| h.seq);
        if read < self.sent.seq {
            return;
        }
        self.finish_rebuild_now();
        self.apply_pending(wall_ms);
    }

    /// After every pull: each stream read again up to what was received before the restart
    /// is compared once; a history that differs is a fork (review A1d I2). Until then the
    /// remembered head also counts for the rollback check.
    pub(super) fn check_remembered(&mut self) {
        let remembered = std::mem::take(&mut self.remembered_heads);
        for (stream, h) in remembered {
            if self.trust.is_removed(&stream) {
                continue;
            }
            let read = self.heads.get(&stream).map_or(0, |x| x.seq);
            if read < h.seq {
                self.remembered_heads.insert(stream, h);
                continue;
            }
            let known = self.hashes.get(&stream).and_then(|x| x.get(&h.seq));
            if known.is_some_and(|k| *k != h.hash) {
                self.raise(Alarm::Fork { stream, seq: h.seq });
            }
        }
    }

    fn finish_rebuild_now(&mut self) {
        self.heads.remove(&self.device);
        self.rebuilding = false;
        // The unsent segment and the queued entries, at their positions.
        let mut queued: Vec<Value> = Vec::new();
        if let Some(u) = &self.unsent {
            if let Ok(seg) = decrypt_segment(&self.segment_key, &u.bytes)
                .and_then(|x| x.verify(&self.signer.verifying_key()))
            {
                queued.extend(seg.entries);
            }
        }
        queued.extend(self.outbox.iter().cloned());
        let first = self.sent.seq + 1;
        for (i, value) in queued.iter().enumerate() {
            let seq = first + i as u64;
            let Ok(entry) = Entry::from_value(value) else {
                continue;
            };
            match entry {
                Entry::Put(env) => {
                    self.lanes
                        .entry((self.device, (env.kind, env.record_id)))
                        .or_default()
                        .push_back(Pending {
                            seq,
                            env,
                            doc: None,
                        });
                }
                Entry::SelfJoin { .. } if seq == 1 && !self.is_root() => {
                    self.trust.set_pending_self(self.device)
                }
                Entry::Header(_) | Entry::HeaderSeen { .. } => {
                    self.note_header_entry(self.device, seq, &entry)
                }
                Entry::Genesis { .. } | Entry::Endorse { .. } | Entry::Revoke { .. }
                    if self.is_root() =>
                {
                    self.apply_root_entry(seq, &entry)
                }
                _ => {}
            }
        }
    }
}
