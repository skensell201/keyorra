//! A simulated set of devices sharing one transport, for the engine's tests and for the
//! transport plans that rerun them (spec §11, suites 3–5, 9).

use ed25519_dalek::SigningKey;
use keyorra_core::crypto::Key;
use rand::rngs::StdRng;
use rand::SeedableRng;
use uuid::Uuid;

use crate::engine::{Engine, StaticDirectory};
use crate::error::Result;
use crate::faults::{Faults, Faulty};
use crate::fold::View;
use crate::transport::MemoryTransport;
use crate::DeviceId;

pub const ACCOUNT_ID: [u8; 16] = [0x10; 16];
/// 2026-09-21, a fixed start so runs repeat.
pub const START_MS: u64 = 1_790_000_000_000;

pub struct Cluster {
    pub store: MemoryTransport,
    pub links: Vec<Faulty<MemoryTransport>>,
    pub devices: Vec<Engine<StdRng>>,
    pub directory: StaticDirectory,
    /// Wall clock of each device (they may disagree).
    pub clocks: Vec<u64>,
}

pub fn device_id(i: usize) -> DeviceId {
    [i as u8 + 1; 16]
}

impl Cluster {
    pub fn new(n: usize, seed: u64, faults: Faults) -> Cluster {
        let store = MemoryTransport::new();
        let mut directory = StaticDirectory::default();
        let mut devices = Vec::new();
        let mut links = Vec::new();
        for i in 0..n {
            let signer = SigningKey::from_bytes(&[0x40 + i as u8; 32]);
            directory.0.insert(device_id(i), signer.verifying_key());
            devices.push(Engine::new(
                device_id(i),
                signer,
                ACCOUNT_ID,
                Key::from_bytes([0x30; 32]),
                StdRng::seed_from_u64(seed.wrapping_add(i as u64)),
            ));
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
            directory,
            clocks: vec![START_MS; n],
        }
    }

    pub fn sync(&mut self, i: usize) -> Result<()> {
        self.devices[i].sync(&self.links[i], &self.directory, self.clocks[i])
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
        assert!(
            first.resolutions.is_empty(),
            "conflict copies left to materialise"
        );
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
