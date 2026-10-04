//! Serving the browser extension: pairing and the list/fill requests.

use std::path::Path;

use lockbox_core::store::ItemEntry;
use lockbox_core::totp::Totp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::Session;
use crate::bridge::crypto::{
    self, b64, commitment, derive, nonce_of, public_from_b64, Direction, KeyPair,
};
use crate::bridge::protocol::{Candidate, Inbound, Outbound, Reply, Request, VERSION};
use crate::bridge::site::{matches, Site};
use crate::error::{CmdError, CmdResult, ErrorKind};

/// How long a pairing request waits for approval in the app.
pub const PAIRING_TTL_SECS: u64 = 300;
/// Unapproved pairings allowed before `pair` is refused for a while.
pub const MAX_PAIR_FAILURES: u32 = 5;
pub const PAIR_COOLDOWN_SECS: u64 = 600;
const PAIRINGS_META: &str = "bridge.pairings";
pub(super) const GUARD_FILE: &str = "pairing-guard.json";

/// Something the app window should react to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BridgeEvent {
    /// Bring the window to the front (e.g. so the user can unlock).
    Show,
    /// Ask the user to confirm a browser.
    PairRequest(PairingRequest),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingRequest {
    pub client_id: String,
    pub name: String,
    pub code: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairedBrowser {
    pub client_id: String,
    pub name: String,
    pub created_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingState {
    /// The extension committed to its key; the app has not seen the key yet.
    AwaitingReveal,
    Waiting,
    Approved,
    Denied,
}

pub(super) struct PendingPairing {
    client_id: String,
    name: String,
    commit: [u8; 32],
    server: KeyPair,
    key: Option<Zeroizing<[u8; 32]>>,
    created_at: u64,
    state: PendingState,
}

impl PendingPairing {
    fn unapproved(&self) -> bool {
        matches!(
            self.state,
            PendingState::AwaitingReveal | PendingState::Waiting
        )
    }
}

/// Failed-pairing counter, kept in `pairing-guard.json` so a restart doesn't reset it. Not secret.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub(super) struct PairGuard {
    pub failures: u32,
    pub blocked_until: u64,
}

impl PairGuard {
    /// Missing or damaged files mean no failures.
    pub fn load(path: &Path) -> Self {
        std::fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    /// Atomic write (temp file + rename).
    fn save(&self, path: &Path) -> std::io::Result<()> {
        let tmp = path.with_extension("json.tmp");
        std::fs::write(
            &tmp,
            serde_json::to_vec_pretty(self).expect("guard serializes"),
        )?;
        std::fs::rename(&tmp, path)
    }
}

/// Stored sealed in the vault.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Pairing {
    client_id: String,
    name: String,
    key: Zeroizing<String>,
    created_at: u64,
}

fn error(message: &str) -> Outbound {
    Outbound::Error {
        message: message.into(),
    }
}

impl Session {
    /// One message from the extension; the event, if any, is for the app window.
    pub fn bridge(&mut self, msg: Inbound, now: u64) -> (Outbound, Option<BridgeEvent>) {
        match msg {
            Inbound::Status => (
                Outbound::Status {
                    locked: self.store.is_none(),
                    version: VERSION,
                },
                None,
            ),
            Inbound::Show => (Outbound::Ok, Some(BridgeEvent::Show)),
            Inbound::Pair { commit, name } => self.start_pairing(&commit, &name, now),
            Inbound::PairReveal {
                client_id,
                client_pub,
            } => self.reveal_pairing(&client_id, &client_pub, now),
            Inbound::PairStatus { client_id } => (self.pairing_status(&client_id, now), None),
            Inbound::Call { client_id, sealed } => {
                (self.serve_call(&client_id, &sealed, now), None)
            }
        }
    }

    pub fn approve_pairing(&mut self, client_id: &str, now: u64) -> CmdResult<()> {
        self.store()?;
        self.forget_expired(now);
        let expired = || CmdError::new(ErrorKind::NotFound, "This request has expired");
        let pending = self
            .pending
            .as_mut()
            .filter(|p| p.client_id == client_id && p.state == PendingState::Waiting)
            .ok_or_else(expired)?;
        let key = pending.key.as_ref().ok_or_else(expired)?;
        let record = Pairing {
            client_id: pending.client_id.clone(),
            name: pending.name.clone(),
            key: Zeroizing::new(b64(&key[..])),
            created_at: now,
        };
        let mut all = self.load_pairings()?;
        all.retain(|p| p.client_id != record.client_id);
        all.push(record);
        self.save_pairings(&all)?;
        if let Some(p) = self.pending.as_mut() {
            p.state = PendingState::Approved;
        }
        self.set_guard(0, 0);
        Ok(())
    }

    pub fn deny_pairing(&mut self, client_id: &str) {
        let denied = match self.pending.as_mut() {
            Some(p) if p.client_id == client_id && p.unapproved() => {
                p.state = PendingState::Denied;
                true
            }
            _ => false,
        };
        if denied {
            self.record_pair_failure();
        }
    }

    pub fn paired_browsers(&self) -> CmdResult<Vec<PairedBrowser>> {
        Ok(self
            .load_pairings()?
            .into_iter()
            .map(|p| PairedBrowser {
                client_id: p.client_id,
                name: p.name,
                created_at: p.created_at,
            })
            .collect())
    }

    pub fn remove_paired_browser(&mut self, client_id: &str) -> CmdResult<()> {
        let mut all = self.load_pairings()?;
        all.retain(|p| p.client_id != client_id);
        self.save_pairings(&all)?;
        if self
            .pending
            .as_ref()
            .is_some_and(|p| p.client_id == client_id)
        {
            self.pending = None;
        }
        Ok(())
    }

    /// Clears the pending pairing; one nobody approved counts as a failure.
    pub(super) fn drop_pending_pairing(&mut self) {
        if let Some(p) = self.pending.take() {
            if p.unapproved() {
                self.record_pair_failure();
            }
        }
    }

    fn start_pairing(
        &mut self,
        commit: &str,
        name: &str,
        now: u64,
    ) -> (Outbound, Option<BridgeEvent>) {
        if self.store.is_none() {
            return (Outbound::Locked, Some(BridgeEvent::Show));
        }
        self.forget_expired(now);
        // A new request replaces the old one; an unapproved old one counts against the cap.
        self.drop_pending_pairing();
        if self.pair_failures >= MAX_PAIR_FAILURES {
            // The block starts at the first refusal; a stored value from a clock that was far
            // ahead is clamped (and saved) so it can't block for longer than the cooldown.
            let latest = now.saturating_add(PAIR_COOLDOWN_SECS);
            if self.pair_blocked_until == 0 || self.pair_blocked_until > latest {
                self.set_guard(self.pair_failures, latest);
            }
            if now < self.pair_blocked_until {
                return (
                    error(
                        "Too many pairing attempts. Open Lockbox and try again in a few minutes.",
                    ),
                    Some(BridgeEvent::Show),
                );
            }
            self.set_guard(0, 0);
        }
        let Some(commit) = public_from_b64(commit) else {
            return (error("Bad pairing request"), None);
        };
        let server = KeyPair::random();
        let client_id = Uuid::new_v4().to_string();
        let reply = Outbound::PairPending {
            client_id: client_id.clone(),
            server_pub: b64(&server.public),
        };
        self.pending = Some(PendingPairing {
            client_id,
            name: clean_name(name),
            commit,
            server,
            key: None,
            created_at: now,
            state: PendingState::AwaitingReveal,
        });
        (reply, None)
    }

    fn reveal_pairing(
        &mut self,
        client_id: &str,
        client_pub: &str,
        now: u64,
    ) -> (Outbound, Option<BridgeEvent>) {
        if self.store.is_none() {
            return (Outbound::Locked, Some(BridgeEvent::Show));
        }
        self.forget_expired(now);
        let waiting = self
            .pending
            .as_ref()
            .is_some_and(|p| p.client_id == client_id && p.state == PendingState::AwaitingReveal);
        if !waiting {
            return (Outbound::UnknownClient, None);
        }
        let mut pending = self.pending.take().expect("checked above");
        let derived = public_from_b64(client_pub)
            .filter(|public| commitment(public) == pending.commit)
            .and_then(|public| derive(&pending.server, &public, &public, &pending.server.public));
        let Some(derived) = derived else {
            self.record_pair_failure();
            return (error("Pairing check failed"), None);
        };
        pending.key = Some(derived.key);
        pending.state = PendingState::Waiting;
        let reply = Outbound::PairPending {
            client_id: pending.client_id.clone(),
            server_pub: b64(&pending.server.public),
        };
        let event = BridgeEvent::PairRequest(PairingRequest {
            client_id: pending.client_id.clone(),
            name: pending.name.clone(),
            code: derived.code,
        });
        self.pending = Some(pending);
        (reply, Some(event))
    }

    fn pairing_status(&mut self, client_id: &str, now: u64) -> Outbound {
        self.forget_expired(now);
        if let Some(p) = self.pending.as_ref().filter(|p| p.client_id == client_id) {
            return match p.state {
                PendingState::AwaitingReveal | PendingState::Waiting => Outbound::PairPending {
                    client_id: client_id.to_owned(),
                    server_pub: b64(&p.server.public),
                },
                PendingState::Approved => {
                    self.pending = None;
                    Outbound::Paired
                }
                PendingState::Denied => {
                    self.pending = None;
                    Outbound::PairDenied
                }
            };
        }
        match self.load_pairings() {
            Ok(all) if all.iter().any(|p| p.client_id == client_id) => Outbound::Paired,
            Ok(_) => Outbound::UnknownClient,
            Err(e) if self.store.is_some() => error(&e.message),
            Err(_) => Outbound::Locked,
        }
    }

    fn serve_call(&mut self, client_id: &str, sealed: &str, now: u64) -> Outbound {
        if self.store.is_none() {
            return Outbound::Locked;
        }
        let all = match self.load_pairings() {
            Ok(all) => all,
            Err(e) => return error(&e.message),
        };
        let Some(pairing) = all.into_iter().find(|p| p.client_id == client_id) else {
            return Outbound::UnknownClient;
        };
        let Some(key) = public_from_b64(&pairing.key).map(Zeroizing::new) else {
            return error("Damaged pairing");
        };
        let Some(request_nonce) = nonce_of(sealed) else {
            return error("Malformed message");
        };
        let Some(plain) = crypto::open(&key, client_id, Direction::Request, sealed) else {
            return error("Message did not authenticate");
        };
        let reply = match serde_json::from_slice::<Request>(&plain) {
            Ok(request) => self.serve_request(request, now),
            Err(_) => Reply::Error {
                error: "Unknown request".into(),
            },
        };
        let json = Zeroizing::new(serde_json::to_vec(&reply).expect("reply serializes"));
        Outbound::Reply {
            sealed: crypto::seal(
                &key,
                client_id,
                Direction::Response { request_nonce },
                &json,
            ),
        }
    }

    fn serve_request(&mut self, request: Request, now: u64) -> Reply {
        match request {
            Request::Ping => Reply::Pong { pong: true },
            // Not activity: the extension may list on its own; only a fill keeps the vault open.
            Request::List { url } => Reply::Items {
                items: self.candidates(&url),
            },
            Request::Fill { url, item_id } => self.credentials(&url, item_id, now),
            // Served from the following tasks.
            _ => Reply::Error {
                error: "Unknown request".into(),
            },
        }
    }

    fn candidates(&self, url: &str) -> Vec<Candidate> {
        let (Some(page), Some(store)) = (Site::of(url), self.store.as_ref()) else {
            return Vec::new();
        };
        let Ok(entries) = store.list_items(None) else {
            return Vec::new();
        };
        let mut found: Vec<_> = entries
            .into_iter()
            .filter_map(|e| match e {
                ItemEntry::Ok(item) => {
                    let best = item.urls.iter().filter_map(|u| matches(&page, u)).max()?;
                    Some((best, item))
                }
                ItemEntry::Damaged { .. } => None,
            })
            .collect();
        found.sort_by(|(ma, a), (mb, b)| {
            mb.cmp(ma)
                .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
        });
        found
            .into_iter()
            .map(|(_, item)| Candidate {
                id: item.id,
                title: item.title.clone(),
                username: item.username().unwrap_or_default().to_owned(),
                has_totp: item.totp().is_some_and(|raw| Totp::parse(raw).is_ok()),
            })
            .collect()
    }

    fn credentials(&mut self, url: &str, item_id: Uuid, now: u64) -> Reply {
        let Some(page) = Site::of(url) else {
            return Reply::Error {
                error: "This page can't be filled".into(),
            };
        };
        let item = match self
            .store()
            .and_then(|s| s.get_item(item_id).map_err(Into::into))
        {
            Ok(item) => item,
            Err(e) => return Reply::Error { error: e.message },
        };
        if !item.urls.iter().any(|u| matches(&page, u).is_some()) {
            return Reply::Error {
                error: "This login doesn't belong to this site".into(),
            };
        }
        self.touch(now);
        Reply::Credentials {
            username: item.username().unwrap_or_default().to_owned(),
            password: item.password().unwrap_or_default().to_owned(),
            totp: item
                .totp()
                .and_then(|raw| Totp::parse(raw).ok())
                .map(|t| t.code_at(now)),
        }
    }

    /// An unapproved request that timed out counts as a failure.
    /// An unapproved request that timed out counts as a failure. A clock that went backwards
    /// (`now < created_at`) also counts as expired.
    fn forget_expired(&mut self, now: u64) {
        let expired = self
            .pending
            .as_ref()
            .is_some_and(|p| now < p.created_at || now - p.created_at > PAIRING_TTL_SECS);
        if expired {
            self.drop_pending_pairing();
        }
    }

    fn record_pair_failure(&mut self) {
        self.set_guard(
            self.pair_failures.saturating_add(1),
            self.pair_blocked_until,
        );
    }

    /// Best effort: a failed write must not break pairing, the in-memory count still holds.
    fn set_guard(&mut self, failures: u32, blocked_until: u64) {
        if (self.pair_failures, self.pair_blocked_until) == (failures, blocked_until) {
            return;
        }
        self.pair_failures = failures;
        self.pair_blocked_until = blocked_until;
        let _ = PairGuard {
            failures,
            blocked_until,
        }
        .save(&self.guard_path);
    }

    fn load_pairings(&self) -> CmdResult<Vec<Pairing>> {
        match self.store()?.sealed_meta(PAIRINGS_META)? {
            None => Ok(Vec::new()),
            Some(bytes) => serde_json::from_slice(&bytes)
                .map_err(|_| CmdError::new(ErrorKind::Other, "Browser pairings are damaged")),
        }
    }

    fn save_pairings(&mut self, all: &[Pairing]) -> CmdResult<()> {
        let json = Zeroizing::new(serde_json::to_vec(all).expect("pairings serialize"));
        Ok(self.store_mut()?.set_sealed_meta(PAIRINGS_META, &json)?)
    }
}

fn clean_name(name: &str) -> String {
    let name: String = name
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .take(40)
        .collect();
    if name.is_empty() {
        "Browser".into()
    } else {
        name
    }
}
