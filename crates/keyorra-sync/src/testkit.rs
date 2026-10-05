//! A simulated set of devices sharing one transport, for the engine's tests and for the
//! transport plans that rerun them (spec §11, suites 3–5, 9).

use ed25519_dalek::SigningKey;
use keyorra_core::crypto::Key;
use rand::rngs::StdRng;
use rand::SeedableRng;
use uuid::Uuid;

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use keyorra_core::crypto::KdfParams;

use crate::engine::{DeviceKeys, Engine, OutboxState, OutboxStore};
use crate::error::Result;
use crate::faults::{Faults, Faulty};
use crate::fold::View;
use crate::header::{wrap_account_key, Header};
use crate::keys::derive_sync_keys;
use crate::secret_key::SecretKey;
use crate::transport::MemoryTransport;
use crate::DeviceId;

pub const ACCOUNT_ID: [u8; 16] = [0x10; 16];
pub const ACCOUNT_KEY: [u8; 32] = [0x30; 32];
/// 2026-09-21, a fixed start so runs repeat.
pub const START_MS: u64 = 1_790_000_000_000;

pub struct Cluster {
    pub store: MemoryTransport,
    pub links: Vec<Faulty<MemoryTransport>>,
    pub devices: Vec<Engine<StdRng>>,
    /// Wall clock of each device (they may disagree).
    pub clocks: Vec<u64>,
}

pub fn device_id(i: usize) -> DeviceId {
    [i as u8 + 1; 16]
}

pub fn signer(i: usize) -> SigningKey {
    SigningKey::from_bytes(&[0x40 + i as u8; 32])
}

pub fn device_name(i: usize) -> String {
    format!("Device {i}")
}

impl Cluster {
    /// Device 0 creates the account and approves every other device; all are in step.
    pub fn new(n: usize, seed: u64, faults: Faults) -> Cluster {
        let mut c = Cluster::unapproved(n, seed, faults);
        for i in 1..n {
            let key = c.devices[i].verifying_key();
            c.devices[0]
                .endorse(device_id(i), &key, &device_name(i), START_MS)
                .unwrap();
        }
        c.heal();
        for link in &c.links {
            link.set_faults(faults);
        }
        c
    }

    /// Device 0 creates the account; the others have joined but nobody approved them yet.
    pub fn unapproved(n: usize, seed: u64, faults: Faults) -> Cluster {
        let store = MemoryTransport::new();
        let mut devices = Vec::new();
        let mut links = Vec::new();
        for i in 0..n {
            let rng = StdRng::seed_from_u64(seed.wrapping_add(i as u64));
            let key = Key::from_bytes(ACCOUNT_KEY);
            devices.push(if i == 0 {
                Engine::create_account(
                    device_id(0),
                    signer(0),
                    &device_name(0),
                    ACCOUNT_ID,
                    key,
                    rng,
                    START_MS,
                )
            } else {
                Engine::join(
                    device_id(i),
                    signer(i),
                    &device_name(i),
                    ACCOUNT_ID,
                    key,
                    device_id(0),
                    signer(0).verifying_key(),
                    rng,
                )
            });
            links.push(Faulty::new(
                store.clone(),
                faults,
                seed ^ (0x5eed + i as u64),
            ));
        }
        Cluster {
            store,
            links,
            devices,
            clocks: vec![START_MS; n],
        }
    }

    pub fn sync(&mut self, i: usize) -> Result<()> {
        self.devices[i].sync(&self.links[i], self.clocks[i])
    }

    /// Advances every wall clock.
    pub fn tick(&mut self, ms: u64) {
        for c in &mut self.clocks {
            *c += ms;
        }
    }

    /// Turns faults off and syncs everyone until nothing changes; returns the rounds needed.
    pub fn heal(&mut self) -> usize {
        for link in &self.links {
            link.set_faults(Faults::NONE);
        }
        let mut last: Vec<View> = Vec::new();
        for round in 1..=50 {
            for i in 0..self.devices.len() {
                self.sync(i).expect("no faults while healing");
            }
            self.tick(1_000);
            let views: Vec<View> = self.devices.iter().map(|d| d.view()).collect();
            if views == last && self.devices.iter().all(|d| d.is_idle()) {
                return round;
            }
            last = views;
        }
        panic!("devices did not settle within 50 rounds");
    }

    pub fn assert_converged(&self) {
        let first = self.devices[0].view();
        for (i, d) in self.devices.iter().enumerate().skip(1) {
            assert_eq!(d.view(), first, "device {i} differs from device 0");
        }
        if self.devices.iter().any(|d| d.can_write()) {
            assert!(!first.owes_copies(), "conflict copies left to materialise");
        }
    }

    /// A further device joins (device 0 is the root) and device 0 approves it; returns its
    /// index. It has nothing yet: its first sync starts from a snapshot if there is one.
    pub fn add_device(&mut self, seed: u64) -> usize {
        let i = self.devices.len();
        self.devices.push(Engine::join(
            device_id(i),
            signer(i),
            &device_name(i),
            ACCOUNT_ID,
            Key::from_bytes(ACCOUNT_KEY),
            device_id(0),
            signer(0).verifying_key(),
            StdRng::seed_from_u64(seed),
        ));
        self.links
            .push(Faulty::new(self.store.clone(), Faults::NONE, seed));
        self.clocks.push(self.clocks[0]);
        let key = self.devices[i].verifying_key();
        self.devices[0]
            .endorse(device_id(i), &key, &device_name(i), self.clocks[0])
            .unwrap();
        i
    }

    /// A minimal item JSON, as the local store would write it.
    pub fn item_json(id: Uuid, title: &str, attachments: &[Uuid]) -> Vec<u8> {
        let atts: Vec<serde_json::Value> = attachments
            .iter()
            .map(|a| serde_json::json!({ "id": a.to_string(), "name": "file" }))
            .collect();
        serde_json::to_vec(&serde_json::json!({
            "id": id.to_string(),
            "title": title,
            "attachments": atts,
        }))
        .unwrap()
    }
}

/// The password and Secret Key of the test account.
pub const PASSWORD: &str = "correct horse battery staple";

pub fn secret_key() -> SecretKey {
    SecretKey::from_bytes([0x01; 16])
}

/// A valid account header of the test account (cheap, test-only KDF parameters).
pub fn test_header(epoch: u32, password: &str) -> Header {
    let kdf = KdfParams::INSECURE_FAST;
    let salt = [epoch as u8; 16];
    let keys = derive_sync_keys(password, &salt, kdf, &secret_key(), &ACCOUNT_ID).unwrap();
    let mut header = Header {
        account_id: ACCOUNT_ID,
        epoch,
        generation: 1,
        root_device: device_id(0),
        root_key: signer(0).verifying_key().to_bytes(),
        kdf,
        salt,
        secret_key_id: "A3K7".into(),
        wrapped_account_key: vec![],
    };
    header.wrapped_account_key = wrap_account_key(
        &keys.kek,
        &Key::from_bytes(ACCOUNT_KEY),
        &header,
        &mut rand::rngs::OsRng,
    );
    header
}

/// Opens a test header (without the floor on remote KDF parameters).
pub fn unlock_test_header(header: &Header, password: &str) -> Result<Key> {
    let keys = derive_sync_keys(
        password,
        &header.salt,
        header.kdf,
        &secret_key(),
        &header.account_id,
    )?;
    header.unwrap_account_key(&keys.kek)
}

/// A key store in memory; shared between clones so a test can look inside.
#[derive(Clone, Default)]
pub struct MemoryKeys(pub Arc<Mutex<BTreeSet<DeviceId>>>);

impl DeviceKeys for MemoryKeys {
    fn holds(&self, device: &DeviceId) -> bool {
        self.0.lock().unwrap().contains(device)
    }
    fn store(&mut self, device: DeviceId, _key: &SigningKey) {
        self.0.lock().unwrap().insert(device);
    }
}

/// The last saved outbox state, shared so a test can "restart" from it.
#[derive(Clone, Default)]
pub struct MemoryOutbox(pub Arc<Mutex<Option<OutboxState>>>);

impl OutboxStore for MemoryOutbox {
    fn save(&mut self, state: &OutboxState) -> Result<()> {
        *self.0.lock().unwrap() = Some(state.clone());
        Ok(())
    }
}
