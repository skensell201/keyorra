//! Deterministic test vectors: fixed inputs → exact bytes, pinned in
//! `docs/sync-test-vectors/a1a.json` so that any other implementation (and any future change
//! here) can be checked against them. Regenerate only on a deliberate format change:
//! `cargo test -p keyorra-sync write_vectors -- --ignored`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use keyorra_core::crypto::{derive_kek, KdfParams, Key, NONCE_LEN};
use uuid::Uuid;

use crate::cbor::{self, Value};
use crate::chunk::{chunk_name, seal_chunk, ChunkPlace};
use crate::envelope::{Envelope, RecordKind, Version};
use crate::header::{wrap_account_key, Header, HeaderFile};
use crate::keys::{derive_sync_keys, segment_key};
use crate::pad::padme;
use crate::secret_key::SecretKey;
use crate::segment::{chain_genesis, seal_segment, StreamPosition};
use crate::snapshot::{seal_snapshot, snapshot_name};

const PASSWORD: &str = "correct horse battery staple";
/// Cheap Argon2 parameters so the vectors run fast. Never used for a real account.
const KDF: KdfParams = KdfParams {
    m_kib: 64,
    t: 1,
    p: 1,
};

fn seq<const N: usize>(start: u8) -> [u8; N] {
    std::array::from_fn(|i| start.wrapping_add(i as u8))
}

fn hex(b: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(b)
}

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/sync-test-vectors/a1a.json")
}

pub(crate) fn compute() -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut put = |k: &str, v: String| {
        out.insert(k.to_owned(), v);
    };

    let account_id = seq::<16>(0x10);
    let salt = seq::<16>(0x20);
    let secret_key = SecretKey::from_bytes(seq::<16>(0x00));
    let account_key = Key::from_bytes(seq::<32>(0x30));
    let device_id = seq::<16>(0x70);
    let device_key = SigningKey::from_bytes(&seq::<32>(0x40));
    let vault_key = Key::from_bytes(seq::<32>(0x90));
    let attachment_key = Key::from_bytes(seq::<32>(0xb0));

    put("in.password", PASSWORD.to_owned());
    put(
        "in.kdf",
        format!("m_kib={} t={} p={}", KDF.m_kib, KDF.t, KDF.p),
    );
    put("in.account_id", hex(&account_id));
    put("in.salt", hex(&salt));
    put("in.secret_key", hex(secret_key.as_bytes()));
    put("in.account_key", hex(account_key.as_bytes()));
    put("in.device_id", hex(&device_id));
    put("in.device_signing_seed", hex(&seq::<32>(0x40)));
    put("in.vault_key", hex(vault_key.as_bytes()));
    put("in.attachment_key", hex(attachment_key.as_bytes()));

    put("secret_key.display", secret_key.display("A3K7").to_string());
    put(
        "device.public_key",
        hex(device_key.verifying_key().as_bytes()),
    );

    let u = derive_kek(PASSWORD, &salt, KDF).unwrap();
    put("keys.argon2id_u", hex(u.as_bytes()));
    let keys = derive_sync_keys(PASSWORD, &salt, KDF, &secret_key, &account_id).unwrap();
    put("keys.kek_sync", hex(keys.kek.as_bytes()));
    put("keys.auth", hex(keys.auth.as_bytes()));
    let k_seg = segment_key(&account_key, &account_id);
    put("keys.segment_key", hex(k_seg.as_bytes()));

    let header = Header {
        account_id,
        epoch: 1,
        generation: 1,
        root_device: device_id,
        kdf: KDF,
        salt,
        secret_key_id: "A3K7".into(),
        wrapped_account_key: wrap_account_key(
            &keys.kek,
            &account_key,
            &account_id,
            1,
            1,
            &seq::<NONCE_LEN>(0x60),
        ),
    };
    let file = HeaderFile::sign(header, device_id, &device_key);
    put("header.file", hex(&file.encode()));
    put("header.file_name", file.file_name());

    let version = Version {
        vector: BTreeMap::from([(device_id, 1)]),
        hlc: 1_790_000_000_000 << 16,
        author: device_id,
    };
    let mut item = Envelope {
        kind: RecordKind::Item,
        record_id: Uuid::from_bytes(seq::<16>(0xd0)),
        vault_id: Some(Uuid::from_bytes(seq::<16>(0xe0))),
        schema: 1,
        version,
        tombstone: false,
        body: None,
    };
    item.seal_body(
        &vault_key,
        &account_id,
        br#"{"title":"GitHub"}"#,
        &seq::<NONCE_LEN>(0x80),
    );
    put("envelope.item", hex(&cbor::encode(&item.to_value())));
    put("envelope.item.header_hash", hex(&item.header_hash()));
    put("envelope.item.version_hash", hex(&item.version_hash()));

    let place = ChunkPlace {
        account_id,
        attachment_id: Uuid::from_bytes(seq::<16>(0xf0)),
        index: 0,
        count: 1,
    };
    let chunk = seal_chunk(
        &attachment_key,
        &place,
        b"attachment bytes",
        &seq::<NONCE_LEN>(0xa0),
    )
    .unwrap();
    put("chunk", hex(&chunk));
    put("chunk.name", chunk_name(&chunk));

    let genesis = chain_genesis(&account_id, &device_id);
    put("segment.chain_genesis", hex(&genesis));
    let at = StreamPosition {
        device_id,
        first_seq: 1,
        prev_hash: genesis,
    };
    let entries = vec![Value::map(vec![("put", item.to_value())])];
    let segment = seal_segment(&k_seg, &device_key, &at, entries, &seq::<NONCE_LEN>(0xc0)).unwrap();
    put("segment", hex(&segment));

    let body = Value::map(vec![("records", Value::Array(vec![item.to_value()]))]);
    let snapshot = seal_snapshot(
        &k_seg,
        &device_key,
        device_id,
        body,
        &seq::<NONCE_LEN>(0xe8),
    );
    put("snapshot", hex(&snapshot));
    put("snapshot.name", snapshot_name(&snapshot));

    for len in [1025u64, 5000, 1_000_000] {
        put(&format!("padme.{len}"), padme(len).to_string());
    }
    out
}

fn to_json(map: &BTreeMap<String, String>) -> String {
    serde_json::to_string_pretty(map).unwrap() + "\n"
}

#[test]
fn vectors_match_the_pinned_file() {
    let text = std::fs::read_to_string(path())
        .expect("docs/sync-test-vectors/a1a.json missing: run the ignored write_vectors test");
    let pinned: BTreeMap<String, String> = serde_json::from_str(&text).unwrap();
    let computed = compute();
    for (key, value) in &computed {
        assert_eq!(pinned.get(key), Some(value), "vector {key}");
    }
    assert_eq!(
        pinned.len(),
        computed.len(),
        "extra keys in the pinned file"
    );
    assert_eq!(text, to_json(&computed), "file formatting drifted");
}

#[test]
fn vectors_open_again() {
    use crate::segment::open_segment;
    use crate::snapshot::open_snapshot;
    let v = compute();
    let unhex = |k: &str| data_encoding::HEXLOWER.decode(v[k].as_bytes()).unwrap();
    let file = HeaderFile::decode(&unhex("header.file")).unwrap();
    let device = SigningKey::from_bytes(&seq::<32>(0x40)).verifying_key();
    file.verify(&device).unwrap();
    let secret = SecretKey::parse(&v["secret_key.display"]).unwrap().1;
    let (ak, _) = file.header.unlock(PASSWORD, &secret).unwrap();
    assert_eq!(hex(ak.as_bytes()), v["in.account_key"]);
    let k_seg = segment_key(&ak, &file.header.account_id);
    let segment = open_segment(&k_seg, &device, &unhex("segment")).unwrap();
    let item = Envelope::from_value(
        segment.entries[0]
            .fields(&["put"])
            .unwrap()
            .get("put")
            .unwrap(),
    )
    .unwrap();
    let vault_key = Key::from_bytes(seq::<32>(0x90));
    assert_eq!(
        &*item.open_body(&vault_key, &file.header.account_id).unwrap(),
        br#"{"title":"GitHub"}"#
    );
    open_snapshot(&k_seg, &device, &unhex("snapshot")).unwrap();
}

#[test]
#[ignore = "rewrites docs/sync-test-vectors/a1a.json; run only on a deliberate format change"]
fn write_vectors() {
    std::fs::create_dir_all(path().parent().unwrap()).unwrap();
    std::fs::write(path(), to_json(&compute())).unwrap();
}
