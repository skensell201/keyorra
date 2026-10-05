//! Plan A2-2: attachment contents as chunks next to the streams.

use uuid::Uuid;

use super::*;
use crate::faults::Faults;
use crate::testkit::{Cluster, START_MS};

const ITEM: Uuid = Uuid::from_bytes([0x60; 16]);
const ATT: Uuid = Uuid::from_bytes([0x61; 16]);

/// Device 0 attaches `bytes` to ITEM (chunks of `chunk_size`) and uploads the chunks.
fn attach(c: &mut Cluster, vault: Uuid, bytes: &[u8], chunk_size: usize) {
    let (payload, chunks) = c.devices[0]
        .seal_attachment(ATT, ITEM, "scan.pdf", bytes, chunk_size)
        .unwrap();
    for chunk in &chunks {
        c.store.put_chunk(chunk).unwrap();
    }
    c.devices[0]
        .write_attachment(vault, ATT, payload, START_MS)
        .unwrap();
    let json = Cluster::item_json(ITEM, "with a file", &[ATT]);
    c.devices[0]
        .save_item(vault, ITEM, &json, START_MS)
        .unwrap();
    c.heal();
}

fn chunks_of(c: &Cluster, payload: &AttachmentPayload) -> Vec<Vec<u8>> {
    payload
        .chunks
        .iter()
        .map(|h| {
            match c
                .store
                .get_chunk(&data_encoding::HEXLOWER.encode(h))
                .unwrap()
            {
                Fetched::Ready(b) => b,
                other => panic!("chunk {other:?}"),
            }
        })
        .collect()
}

fn shared() -> (Cluster, Uuid) {
    let mut c = Cluster::new(2, 31, Faults::NONE);
    let vault = c.devices[0].create_vault("Personal", START_MS).unwrap();
    c.heal();
    (c, vault)
}

#[test]
fn an_attachment_travels_as_chunks_and_opens_elsewhere() {
    let (mut c, vault) = shared();
    let bytes: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
    attach(&mut c, vault, &bytes, 300);
    let view = c.devices[1].view();
    let payload = view.attachments[&ATT].clone();
    assert_eq!(payload.chunks.len(), 4);
    assert_eq!(payload.chunks_for, ATT);
    let opened = c.devices[1]
        .open_attachment(&payload, &chunks_of(&c, &payload))
        .unwrap();
    assert_eq!(&opened[..], &bytes[..]);
}

#[test]
fn chunks_out_of_place_are_refused() {
    let (mut c, vault) = shared();
    attach(&mut c, vault, b"0123456789", 4);
    let payload = c.devices[1].view().attachments[&ATT].clone();
    let mut chunks = chunks_of(&c, &payload);
    chunks.swap(0, 1);
    assert!(c.devices[1].open_attachment(&payload, &chunks).is_err());
    let chunks = chunks_of(&c, &payload);
    assert!(c.devices[1]
        .open_attachment(&payload, &chunks[..2])
        .is_err());
    // The same chunks under another attachment's id do not open.
    let mut moved = payload.clone();
    moved.chunks_for = Uuid::from_bytes([0x62; 16]);
    assert!(c.devices[1].open_attachment(&moved, &chunks).is_err());
}

#[test]
fn a_conflict_copy_opens_the_original_chunks() {
    let (mut c, vault) = shared();
    attach(&mut c, vault, b"shared bytes", 5);
    for (i, title) in [(0, "edit 0"), (1, "edit 1")] {
        let json = Cluster::item_json(ITEM, title, &[ATT]);
        c.devices[i]
            .save_item(vault, ITEM, &json, c.clocks[i])
            .unwrap();
    }
    c.heal();
    let view = c.devices[0].view();
    let copy = view
        .attachments
        .iter()
        .find(|(id, _)| **id != ATT)
        .map(|(_, p)| p.clone())
        .expect("the copy's attachment");
    assert_eq!(copy.chunks_for, ATT);
    assert_ne!(copy.item_id, ITEM);
    let opened = c.devices[1]
        .open_attachment(&copy, &chunks_of(&c, &copy))
        .unwrap();
    assert_eq!(&opened[..], b"shared bytes");
}
