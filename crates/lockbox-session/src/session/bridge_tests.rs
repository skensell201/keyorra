use super::bridge::{PAIRING_TTL_SECS, PAIR_COOLDOWN_SECS};
use super::tests::{personal, save_login, unlocked_session, PW};
use super::*;
use crate::bridge::crypto::{
    self, b64, commitment, derive, nonce_of, public_from_b64, Direction, KeyPair,
};
use crate::bridge::protocol::{Inbound, Outbound};
use lockbox_core::model::{Field, FieldValue, Item, ItemKind, Section};
use serde_json::{json, Value};

/// Plays the extension's side.
struct Ext {
    keys: KeyPair,
    client_id: String,
    key: [u8; 32],
    code: String,
}

fn commit_of(keys: &KeyPair) -> String {
    b64(&commitment(&keys.public))
}

fn start(s: &mut Session, keys: &KeyPair, now: u64) -> (Outbound, Option<BridgeEvent>) {
    s.bridge(
        Inbound::Pair {
            commit: commit_of(keys),
            name: "Chrome".into(),
        },
        now,
    )
}

fn reveal(
    s: &mut Session,
    keys: &KeyPair,
    client_id: &str,
    now: u64,
) -> (Outbound, Option<BridgeEvent>) {
    s.bridge(
        Inbound::PairReveal {
            client_id: client_id.into(),
            client_pub: b64(&keys.public),
        },
        now,
    )
}

fn pair(s: &mut Session) -> (Ext, PairingRequest) {
    let keys = KeyPair::random();
    let (out, event) = start(s, &keys, 1_000);
    assert_eq!(event, None, "nothing to approve before the reveal");
    let Outbound::PairPending {
        client_id,
        server_pub,
    } = out
    else {
        panic!("{out:?}")
    };
    let server_pub = public_from_b64(&server_pub).unwrap();
    let (out, event) = reveal(s, &keys, &client_id, 1_000);
    assert!(matches!(out, Outbound::PairPending { .. }), "{out:?}");
    let d = derive(&keys, &server_pub, &keys.public, &server_pub).unwrap();
    let Some(BridgeEvent::PairRequest(request)) = event else {
        panic!("no pairing event")
    };
    (
        Ext {
            keys,
            client_id,
            key: *d.key,
            code: d.code,
        },
        request,
    )
}

fn paired(s: &mut Session) -> Ext {
    let (ext, request) = pair(s);
    s.approve_pairing(&request.client_id, 1_000).unwrap();
    assert_eq!(
        s.bridge(
            Inbound::PairStatus {
                client_id: ext.client_id.clone()
            },
            1_000
        )
        .0,
        Outbound::Paired
    );
    ext
}

fn call(s: &mut Session, ext: &Ext, request: Value, now: u64) -> Value {
    let sealed = crypto::seal(
        &ext.key,
        &ext.client_id,
        Direction::Request,
        request.to_string().as_bytes(),
    );
    let request_nonce = nonce_of(&sealed).unwrap();
    match s
        .bridge(
            Inbound::Call {
                client_id: ext.client_id.clone(),
                sealed,
            },
            now,
        )
        .0
    {
        Outbound::Reply { sealed } => {
            let plain = crypto::open(
                &ext.key,
                &ext.client_id,
                Direction::Response { request_nonce },
                &sealed,
            )
            .unwrap();
            serde_json::from_slice(&plain).unwrap()
        }
        other => json!({ "outbound": format!("{other:?}") }),
    }
}

#[test]
fn status_and_show() {
    let (_dir, mut s) = unlocked_session();
    assert_eq!(
        s.bridge(Inbound::Status, 1_000).0,
        Outbound::Status {
            locked: false,
            version: 1
        }
    );
    assert_eq!(
        s.bridge(Inbound::Show, 1_000),
        (Outbound::Ok, Some(BridgeEvent::Show))
    );
    s.lock();
    assert_eq!(
        s.bridge(Inbound::Status, 1_000).0,
        Outbound::Status {
            locked: true,
            version: 1
        }
    );
}

#[test]
fn pairing_shows_the_same_code_on_both_sides_and_needs_approval() {
    let (_dir, mut s) = unlocked_session();
    let (ext, request) = pair(&mut s);
    assert_eq!(request.code, ext.code);
    assert_eq!(request.name, "Chrome");
    assert!(matches!(
        s.bridge(
            Inbound::PairStatus {
                client_id: ext.client_id.clone()
            },
            1_001
        )
        .0,
        Outbound::PairPending { .. }
    ));
    assert_eq!(
        call(&mut s, &ext, json!({"op": "ping"}), 1_001),
        json!({"outbound": "UnknownClient"})
    );
    s.approve_pairing(&request.client_id, 1_002).unwrap();
    assert_eq!(
        s.bridge(
            Inbound::PairStatus {
                client_id: ext.client_id.clone()
            },
            1_003
        )
        .0,
        Outbound::Paired
    );
    assert_eq!(
        call(&mut s, &ext, json!({"op": "ping"}), 1_004),
        json!({"pong": true})
    );
    let _ = &ext.keys;
}

#[test]
fn denied_and_expired_pairings() {
    let (_dir, mut s) = unlocked_session();
    let (ext, request) = pair(&mut s);
    s.deny_pairing(&request.client_id);
    assert_eq!(
        s.bridge(
            Inbound::PairStatus {
                client_id: ext.client_id.clone()
            },
            1_001
        )
        .0,
        Outbound::PairDenied
    );
    let (_ext2, request2) = pair(&mut s);
    let err = s
        .approve_pairing(&request2.client_id, 1_000 + PAIRING_TTL_SECS + 1)
        .unwrap_err();
    assert_eq!(err.kind, ErrorKind::NotFound);
}

#[test]
fn pairing_needs_an_unlocked_vault() {
    let (_dir, mut s) = unlocked_session();
    s.lock();
    let keys = KeyPair::random();
    let (out, event) = start(&mut s, &keys, 1_000);
    assert_eq!((out, event), (Outbound::Locked, Some(BridgeEvent::Show)));
}

#[test]
fn lists_and_fills_logins_for_the_page_site_only() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let mut github = save_login(&mut s, p, "GitHub", "ivan", "gh-pass");
    github.urls = vec!["https://github.com".into()];
    let github = s.save_item(github, 1_000).unwrap();
    let mut gist = save_login(&mut s, p, "Gist", "ivan2", "gist-pass");
    gist.urls = vec!["https://gist.github.com".into()];
    s.save_item(gist, 1_000).unwrap();
    let mut other = save_login(&mut s, p, "Bank", "me", "bank-pass");
    other.urls = vec!["https://bank.example".into()];
    let other = s.save_item(other, 1_000).unwrap();
    let ext = paired(&mut s);

    let list = call(
        &mut s,
        &ext,
        json!({"op": "list", "url": "https://gist.github.com/new"}),
        1_000,
    );
    let titles: Vec<_> = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["title"].as_str().unwrap())
        .collect();
    assert_eq!(
        titles,
        ["Gist", "GitHub"],
        "exact host first, then same site"
    );
    assert_eq!(list["items"][1]["username"], "ivan");
    assert!(
        list["items"][0].get("password").is_none(),
        "no secrets in a list"
    );

    let creds = call(
        &mut s,
        &ext,
        json!({"op": "fill", "url": "https://github.com/login", "itemId": github.id}),
        1_000,
    );
    assert_eq!(
        creds,
        json!({"username": "ivan", "password": "gh-pass", "totp": null})
    );

    let refused = call(
        &mut s,
        &ext,
        json!({"op": "fill", "url": "https://github.com/login", "itemId": other.id}),
        1_000,
    );
    assert_eq!(refused["error"], "This login doesn't belong to this site");
    let none = call(
        &mut s,
        &ext,
        json!({"op": "list", "url": "chrome://settings"}),
        1_000,
    );
    assert_eq!(none, json!({"items": []}));
}

#[test]
fn fill_includes_the_current_one_time_code() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let mut item = save_login(&mut s, p, "GitHub", "ivan", "pw");
    item.urls = vec!["https://github.com".into()];
    item.fields.push(lockbox_core::model::Field {
        id: "otp".into(),
        label: "one-time password".into(),
        value: FieldValue::Totp("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into()),
        purpose: None,
    });
    let item = s.save_item(item, 1_000).unwrap();
    let ext = paired(&mut s);
    let creds = call(
        &mut s,
        &ext,
        json!({"op": "fill", "url": "https://github.com/", "itemId": item.id}),
        59,
    );
    assert_eq!(creds["totp"], "287082");
    let list = call(
        &mut s,
        &ext,
        json!({"op": "list", "url": "https://github.com/"}),
        59,
    );
    assert_eq!(list["items"][0]["hasTotp"], true);
}

#[test]
fn locked_vault_and_unknown_clients() {
    let (_dir, mut s) = unlocked_session();
    let ext = paired(&mut s);
    s.lock();
    assert_eq!(
        call(&mut s, &ext, json!({"op": "ping"}), 1_000),
        json!({"outbound": "Locked"})
    );
    s.unlock(PW, 1_000).unwrap();
    assert_eq!(
        call(&mut s, &ext, json!({"op": "ping"}), 1_000),
        json!({"pong": true}),
        "pairings survive locking"
    );

    let stranger = Ext {
        keys: KeyPair::random(),
        client_id: "nobody".into(),
        key: [9; 32],
        code: String::new(),
    };
    assert_eq!(
        call(&mut s, &stranger, json!({"op": "ping"}), 1_000),
        json!({"outbound": "UnknownClient"})
    );
    let forged = Ext {
        keys: KeyPair::random(),
        client_id: ext.client_id.clone(),
        key: [9; 32],
        code: String::new(),
    };
    assert!(
        call(&mut s, &forged, json!({"op": "ping"}), 1_000)["outbound"]
            .as_str()
            .unwrap()
            .starts_with("Error")
    );
}

#[test]
fn paired_browsers_can_be_listed_and_removed() {
    let (_dir, mut s) = unlocked_session();
    let ext = paired(&mut s);
    let list = s.paired_browsers().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(
        (list[0].client_id.as_str(), list[0].name.as_str()),
        (ext.client_id.as_str(), "Chrome")
    );
    s.remove_paired_browser(&ext.client_id).unwrap();
    assert!(s.paired_browsers().unwrap().is_empty());
    assert_eq!(
        call(&mut s, &ext, json!({"op": "ping"}), 1_000),
        json!({"outbound": "UnknownClient"})
    );
}

#[test]
fn a_reveal_that_does_not_match_the_commitment_is_refused() {
    let (_dir, mut s) = unlocked_session();
    let keys = KeyPair::random();
    let (out, _) = start(&mut s, &keys, 1_000);
    let Outbound::PairPending { client_id, .. } = out else {
        panic!("{out:?}")
    };
    let other = KeyPair::random();
    let (out, event) = reveal(&mut s, &other, &client_id, 1_000);
    assert_eq!(
        out,
        Outbound::Error {
            message: "Pairing check failed".into()
        }
    );
    assert_eq!(event, None);
    // The attempt is gone: even the honest reveal can't continue it.
    let (out, event) = reveal(&mut s, &keys, &client_id, 1_000);
    assert_eq!(out, Outbound::UnknownClient);
    assert_eq!(event, None);
}

#[test]
fn a_degenerate_client_key_is_refused() {
    let (_dir, mut s) = unlocked_session();
    let zero = [0u8; 32];
    let (out, _) = s.bridge(
        Inbound::Pair {
            commit: b64(&commitment(&zero)),
            name: "Chrome".into(),
        },
        1_000,
    );
    let Outbound::PairPending { client_id, .. } = out else {
        panic!("{out:?}")
    };
    let (out, event) = s.bridge(
        Inbound::PairReveal {
            client_id,
            client_pub: b64(&zero),
        },
        1_000,
    );
    assert_eq!(
        out,
        Outbound::Error {
            message: "Pairing check failed".into()
        }
    );
    assert_eq!(event, None);
}

#[test]
fn a_second_pair_replaces_the_first() {
    let (_dir, mut s) = unlocked_session();
    let first = KeyPair::random();
    let (out, _) = start(&mut s, &first, 1_000);
    let Outbound::PairPending {
        client_id: first_id,
        ..
    } = out
    else {
        panic!("{out:?}")
    };
    let (_ext2, request2) = pair(&mut s);
    let (out, event) = reveal(&mut s, &first, &first_id, 1_000);
    assert_eq!(out, Outbound::UnknownClient);
    assert_eq!(event, None);
    assert!(s.approve_pairing(&first_id, 1_000).is_err());
    s.approve_pairing(&request2.client_id, 1_000).unwrap();
}

#[test]
fn a_pending_pairing_before_the_reveal_reports_pending() {
    let (_dir, mut s) = unlocked_session();
    let keys = KeyPair::random();
    let (out, _) = start(&mut s, &keys, 1_000);
    let Outbound::PairPending { client_id, .. } = out else {
        panic!("{out:?}")
    };
    assert!(matches!(
        s.bridge(
            Inbound::PairStatus {
                client_id: client_id.clone()
            },
            1_001
        )
        .0,
        Outbound::PairPending { .. }
    ));
    assert!(
        s.approve_pairing(&client_id, 1_001).is_err(),
        "can't approve before the code exists"
    );
}

fn too_many() -> Outbound {
    Outbound::Error {
        message: "Too many pairing attempts. Open Lockbox and try again in a few minutes.".into(),
    }
}

#[test]
fn repeated_pairing_attempts_hit_the_cap_and_the_cooldown() {
    let (_dir, mut s) = unlocked_session();
    // Each new pair replaces the previous unapproved one, which counts as a failure.
    for _ in 0..5 {
        let (out, _) = start(&mut s, &KeyPair::random(), 1_000);
        assert!(matches!(out, Outbound::PairPending { .. }), "{out:?}");
    }
    let (out, event) = start(&mut s, &KeyPair::random(), 1_000);
    assert_eq!((out, event), (too_many(), Some(BridgeEvent::Show)));
    let (out, _) = start(&mut s, &KeyPair::random(), 1_000 + PAIR_COOLDOWN_SECS - 1);
    assert_eq!(out, too_many());
    let (out, _) = start(&mut s, &KeyPair::random(), 1_000 + PAIR_COOLDOWN_SECS);
    assert!(matches!(out, Outbound::PairPending { .. }), "{out:?}");
}

#[test]
fn denied_and_expired_attempts_count_as_failures() {
    let (_dir, mut s) = unlocked_session();
    for _ in 0..3 {
        let (_ext, request) = pair(&mut s);
        s.deny_pairing(&request.client_id);
    }
    // Two expirations: the pending attempt expires when the next one starts.
    let mut now = 1_000;
    for _ in 0..2 {
        let (out, _) = start(&mut s, &KeyPair::random(), now);
        assert!(matches!(out, Outbound::PairPending { .. }), "{out:?}");
        now += PAIRING_TTL_SECS + 1;
    }
    let (out, _) = start(&mut s, &KeyPair::random(), now);
    assert_eq!(out, too_many());
}

#[test]
fn an_approval_resets_the_failure_count() {
    let (_dir, mut s) = unlocked_session();
    for _ in 0..4 {
        let (_ext, request) = pair(&mut s);
        s.deny_pairing(&request.client_id);
    }
    let _ = paired(&mut s);
    for _ in 0..4 {
        let (_ext, request) = pair(&mut s);
        s.deny_pairing(&request.client_id);
    }
    let (out, _) = start(&mut s, &KeyPair::random(), 1_000);
    assert!(matches!(out, Outbound::PairPending { .. }), "{out:?}");
}

#[test]
fn the_attempt_cap_survives_locking_and_a_restart() {
    let (_dir, mut s) = unlocked_session();
    for _ in 0..5 {
        let (_ext, request) = pair(&mut s);
        s.deny_pairing(&request.client_id);
    }
    assert_eq!(start(&mut s, &KeyPair::random(), 1_000).0, too_many());
    s.lock();
    s.unlock(PW, 1_000).unwrap();
    assert_eq!(start(&mut s, &KeyPair::random(), 1_000).0, too_many());

    let path = s.path.clone();
    drop(s);
    let mut again = Session::new(path.clone(), KdfParams::INSECURE_FAST, 1_000);
    again.unlock(PW, 1_000).unwrap();
    assert_eq!(start(&mut again, &KeyPair::random(), 1_001).0, too_many());
    let (out, _) = start(
        &mut again,
        &KeyPair::random(),
        1_000 + PAIR_COOLDOWN_SECS + 1,
    );
    assert!(matches!(out, Outbound::PairPending { .. }), "{out:?}");

    // A damaged guard file means no failures.
    std::fs::write(path.with_file_name("pairing-guard.json"), b"{not json").unwrap();
    let mut third = Session::new(path, KdfParams::INSECURE_FAST, 1_000);
    third.unlock(PW, 1_000).unwrap();
    let (out, _) = start(&mut third, &KeyPair::random(), 1_000);
    assert!(matches!(out, Outbound::PairPending { .. }), "{out:?}");
}

#[test]
fn replies_are_bound_to_the_request_they_answer() {
    let (_dir, mut s) = unlocked_session();
    let ext = paired(&mut s);
    let ping = |s: &mut Session| {
        let sealed = crypto::seal(
            &ext.key,
            &ext.client_id,
            Direction::Request,
            br#"{"op":"ping"}"#,
        );
        let nonce = nonce_of(&sealed).unwrap();
        let Outbound::Reply { sealed: reply } = s
            .bridge(
                Inbound::Call {
                    client_id: ext.client_id.clone(),
                    sealed,
                },
                1_000,
            )
            .0
        else {
            panic!("no reply")
        };
        (nonce, reply)
    };
    let (nonce_a, reply_a) = ping(&mut s);
    let (nonce_b, _) = ping(&mut s);
    assert!(crypto::open(
        &ext.key,
        &ext.client_id,
        Direction::Response {
            request_nonce: nonce_a
        },
        &reply_a
    )
    .is_some());
    assert!(crypto::open(
        &ext.key,
        &ext.client_id,
        Direction::Response {
            request_nonce: nonce_b
        },
        &reply_a
    )
    .is_none());
}

fn guard_failures(s: &Session) -> u32 {
    s.pair_failures
}

#[test]
fn locking_counts_an_unapproved_pairing_as_a_failure() {
    let (_dir, mut s) = unlocked_session();
    for _ in 0..5 {
        let (_ext, _request) = pair(&mut s);
        s.lock();
        s.unlock(PW, 1_000).unwrap();
    }
    assert_eq!(start(&mut s, &KeyPair::random(), 1_000).0, too_many());
}

#[test]
fn locking_after_an_approval_is_not_a_failure() {
    let (_dir, mut s) = unlocked_session();
    let _ext = paired(&mut s);
    s.lock();
    assert_eq!(guard_failures(&s), 0);
}

#[test]
fn auto_lock_counts_an_unapproved_pairing_as_a_failure() {
    let (_dir, mut s) = unlocked_session();
    let (out, _) = start(&mut s, &KeyPair::random(), 1_000);
    assert!(matches!(out, Outbound::PairPending { .. }));
    assert!(s.tick(1_000 + 600));
    assert_eq!(guard_failures(&s), 1);
}

#[test]
fn a_blocked_until_far_in_the_future_is_clamped_to_the_cooldown() {
    let (_dir, s) = unlocked_session();
    let path = s.path.clone();
    drop(s);
    std::fs::write(
        path.with_file_name("pairing-guard.json"),
        br#"{"failures":5,"blockedUntil":99999999999}"#,
    )
    .unwrap();
    let mut s = Session::new(path, KdfParams::INSECURE_FAST, 1_000);
    s.unlock(PW, 1_000).unwrap();
    assert_eq!(start(&mut s, &KeyPair::random(), 1_000).0, too_many());
    let (out, _) = start(&mut s, &KeyPair::random(), 1_000 + PAIR_COOLDOWN_SECS);
    assert!(matches!(out, Outbound::PairPending { .. }), "{out:?}");
}

#[test]
fn a_clock_that_goes_backwards_expires_the_pairing() {
    let (_dir, mut s) = unlocked_session();
    let (_ext, request) = pair(&mut s);
    let err = s.approve_pairing(&request.client_id, 500).unwrap_err();
    assert_eq!(err.kind, ErrorKind::NotFound);
}

#[test]
fn polling_the_status_expires_a_stale_pairing() {
    let (_dir, mut s) = unlocked_session();
    let (ext, _request) = pair(&mut s);
    let late = 1_000 + PAIRING_TTL_SECS + 1;
    assert_eq!(
        s.bridge(
            Inbound::PairStatus {
                client_id: ext.client_id.clone()
            },
            late
        )
        .0,
        Outbound::UnknownClient
    );
    assert_eq!(guard_failures(&s), 1);
}

#[test]
fn removing_a_browser_clears_its_pending_pairing() {
    let (_dir, mut s) = unlocked_session();
    let (_ext, request) = pair(&mut s);
    s.remove_paired_browser(&request.client_id).unwrap();
    assert!(s.approve_pairing(&request.client_id, 1_001).is_err());
}

#[test]
fn damaged_pairings_are_an_error_and_are_not_overwritten() {
    let (_dir, mut s) = unlocked_session();
    let (ext, request) = pair(&mut s);
    s.store_mut()
        .unwrap()
        .set_sealed_meta("bridge.pairings", b"garbage")
        .unwrap();
    let err = s.approve_pairing(&request.client_id, 1_001).unwrap_err();
    assert_eq!(
        (err.kind, err.message.as_str()),
        (ErrorKind::Other, "Browser pairings are damaged")
    );
    assert!(s.paired_browsers().is_err());
    assert_eq!(
        s.store()
            .unwrap()
            .sealed_meta("bridge.pairings")
            .unwrap()
            .unwrap()
            .as_slice(),
        b"garbage"
    );
    let sealed = crypto::seal(
        &ext.key,
        &ext.client_id,
        Direction::Request,
        br#"{"op":"ping"}"#,
    );
    assert_eq!(
        s.bridge(
            Inbound::Call {
                client_id: ext.client_id.clone(),
                sealed
            },
            1_001
        )
        .0,
        Outbound::Error {
            message: "Browser pairings are damaged".into()
        }
    );
}

#[test]
fn has_totp_needs_a_secret_that_parses() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let mut item = save_login(&mut s, p, "GitHub", "ivan", "pw");
    item.urls = vec!["https://github.com".into()];
    item.fields.push(lockbox_core::model::Field {
        id: "otp".into(),
        label: "one-time password".into(),
        value: FieldValue::Totp("not a secret!!".into()),
        purpose: None,
    });
    // Imported items can carry secrets that save_item would reject.
    s.store_mut().unwrap().save_item(&item).unwrap();
    let ext = paired(&mut s);
    let list = call(
        &mut s,
        &ext,
        json!({"op": "list", "url": "https://github.com/"}),
        1_000,
    );
    assert_eq!(list["items"][0]["hasTotp"], false);
}

#[test]
fn listing_does_not_extend_auto_lock_but_filling_does() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let mut item = save_login(&mut s, p, "GitHub", "ivan", "pw");
    item.urls = vec!["https://github.com".into()];
    let item = s.save_item(item, 1_000).unwrap();
    let ext = paired(&mut s);
    call(
        &mut s,
        &ext,
        json!({"op": "list", "url": "https://github.com/"}),
        1_500,
    );
    assert!(s.tick(1_600), "a list is not activity");
    s.unlock(PW, 1_600).unwrap();
    let creds = call(
        &mut s,
        &ext,
        json!({"op": "fill", "url": "https://github.com/", "itemId": item.id}),
        1_700,
    );
    assert_eq!(creds["password"], "pw");
    assert!(!s.tick(2_200), "a fill is activity");
}

#[test]
fn an_https_login_is_refused_on_an_http_page() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let mut item = save_login(&mut s, p, "GitHub", "ivan", "pw");
    item.urls = vec!["https://github.com".into()];
    let item = s.save_item(item, 1_000).unwrap();
    let ext = paired(&mut s);
    let list = call(
        &mut s,
        &ext,
        json!({"op": "list", "url": "http://github.com/"}),
        1_000,
    );
    assert_eq!(list, json!({"items": []}));
    let refused = call(
        &mut s,
        &ext,
        json!({"op": "fill", "url": "http://github.com/", "itemId": item.id}),
        1_000,
    );
    assert_eq!(refused["error"], "This login doesn't belong to this site");
}

#[test]
fn a_trashed_login_is_neither_listed_nor_filled() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let mut item = save_login(&mut s, p, "GitHub", "ivan", "pw");
    item.urls = vec!["https://github.com".into()];
    let item = s.save_item(item, 1_000).unwrap();
    let ext = paired(&mut s);
    s.delete_item(item.id, 1_000).unwrap();
    let list = call(
        &mut s,
        &ext,
        json!({"op": "list", "url": "https://github.com/"}),
        1_000,
    );
    assert_eq!(list, json!({"items": []}));
    let refused = call(
        &mut s,
        &ext,
        json!({"op": "fill", "url": "https://github.com/", "itemId": item.id}),
        1_000,
    );
    assert!(refused["error"].is_string(), "{refused}");
    assert!(refused.get("password").is_none());
}

#[test]
fn lookup_tells_new_changed_and_same_without_revealing_passwords() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let mut gh = save_login(&mut s, p, "GitHub", "ivan", "old-pass");
    gh.urls = vec!["https://github.com".into()];
    let gh = s.save_item(gh, 1_000).unwrap();
    let ext = paired(&mut s);
    let look = |s: &mut Session, user: &str, pw: &str| {
        call(
            s,
            &ext,
            json!({"op": "lookup", "url": "https://github.com/login", "username": user, "password": pw}),
            1_000,
        )
    };
    assert_eq!(
        look(&mut s, "ivan", "old-pass"),
        json!({"status": "same", "itemId": gh.id})
    );
    assert_eq!(
        look(&mut s, "ivan", "new-pass"),
        json!({"status": "changed", "itemId": gh.id})
    );
    assert_eq!(
        look(&mut s, "someone-else", "x"),
        json!({"status": "new", "itemId": null})
    );
    assert!(!look(&mut s, "ivan", "new-pass")
        .to_string()
        .contains("old-pass"));
}

#[test]
fn save_creates_a_login_for_the_site_and_update_keeps_history() {
    let (_dir, mut s) = unlocked_session();
    let ext = paired(&mut s);
    let created = call(
        &mut s,
        &ext,
        json!({"op": "save", "url": "https://shop.example.com/signup", "username": "me@x.com", "password": "pw1", "itemId": null}),
        2_000,
    );
    let id: uuid::Uuid = serde_json::from_value(created["saved"].clone()).unwrap();
    let item = s.item(id, 2_000).unwrap();
    assert_eq!(item.title, "shop.example.com");
    assert_eq!(item.urls, ["https://shop.example.com"]);
    assert_eq!(
        (item.username(), item.password()),
        (Some("me@x.com"), Some("pw1"))
    );

    let updated = call(
        &mut s,
        &ext,
        json!({"op": "save", "url": "https://shop.example.com/account", "username": "me@x.com", "password": "pw2", "itemId": id}),
        3_000,
    );
    assert_eq!(updated["saved"], json!(id));
    let item = s.item(id, 3_000).unwrap();
    assert_eq!(item.password(), Some("pw2"));
    assert_eq!(item.password_history[0].value, "pw1");
}

#[test]
fn save_refuses_other_sites_items_insecure_downgrades_and_empty_passwords() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let mut bank = save_login(&mut s, p, "Bank", "me", "bank-pw");
    bank.urls = vec!["https://bank.example".into()];
    let bank = s.save_item(bank, 1_000).unwrap();
    let ext = paired(&mut s);
    let r = call(
        &mut s,
        &ext,
        json!({"op": "save", "url": "https://evil.example.org", "username": "me", "password": "x", "itemId": bank.id}),
        1_000,
    );
    assert_eq!(r["error"], "This login doesn't belong to this site");
    assert_eq!(s.item(bank.id, 1_000).unwrap().password(), Some("bank-pw"));
    let r = call(
        &mut s,
        &ext,
        json!({"op": "save", "url": "https://a.example", "username": "me", "password": "", "itemId": null}),
        1_000,
    );
    assert_eq!(r["error"], "Nothing to save");
    let r = call(
        &mut s,
        &ext,
        json!({"op": "save", "url": "chrome://settings", "username": "me", "password": "x", "itemId": null}),
        1_000,
    );
    assert_eq!(r["error"], "This page can't be saved");
}

#[test]
fn generate_returns_a_strong_password() {
    let (_dir, mut s) = unlocked_session();
    let ext = paired(&mut s);
    let a = call(&mut s, &ext, json!({"op": "generate"}), 1_000)["generated"]
        .as_str()
        .unwrap()
        .to_owned();
    let b = call(&mut s, &ext, json!({"op": "generate"}), 1_000)["generated"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(a.chars().count(), 20);
    assert_ne!(a, b);
}

fn card(s: &mut Session, title: &str, number: &str, expiry: &str) -> Item {
    let p = personal(s);
    let mut item = s.new_item(p, ItemKind::CreditCard, 1_000).unwrap();
    item.title = title.into();
    for f in &mut item.fields {
        match f.id.as_str() {
            "cardholder" => f.value = FieldValue::Text("IVAN K".into()),
            "number" => f.value = FieldValue::Concealed(number.into()),
            "expiry" => f.value = FieldValue::Text(expiry.into()),
            "cvv" => f.value = FieldValue::Concealed("123".into()),
            _ => {}
        }
    }
    s.save_item(item, 1_000).unwrap()
}

#[test]
fn cards_are_listed_masked_and_filled_on_secure_pages_only() {
    let (_dir, mut s) = unlocked_session();
    let visa = card(&mut s, "Visa", "4111 1111 1111 1111", "12/27");
    let ext = paired(&mut s);
    let list = call(
        &mut s,
        &ext,
        json!({"op": "cards", "url": "https://shop.example"}),
        1_000,
    );
    assert_eq!(
        list,
        json!({"cards": [{"id": visa.id, "title": "Visa", "last4": "1111"}]})
    );
    let filled = call(
        &mut s,
        &ext,
        json!({"op": "fillCard", "url": "https://shop.example", "itemId": visa.id}),
        1_000,
    );
    assert_eq!(
        filled,
        json!({"card": {"name": "IVAN K", "number": "4111111111111111", "expMonth": "12", "expYear": "2027", "cvc": "123"}})
    );
    let insecure = call(
        &mut s,
        &ext,
        json!({"op": "cards", "url": "http://shop.example"}),
        1_000,
    );
    assert_eq!(insecure, json!({"cards": []}));
    let refused = call(
        &mut s,
        &ext,
        json!({"op": "fillCard", "url": "http://shop.example", "itemId": visa.id}),
        1_000,
    );
    assert_eq!(refused["error"], "Cards are only filled on secure pages");
}

#[test]
fn imported_cards_with_month_year_and_labels_work() {
    // 1Password imports put card fields in a section with labels and a MonthYear expiry.
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let mut item = Item::new(p, ItemKind::CreditCard, "Imported", 1_000);
    item.sections.push(Section {
        id: "s".into(),
        title: String::new(),
        fields: vec![
            Field {
                id: "ccnum".into(),
                label: "number".into(),
                value: FieldValue::Concealed("5500000000000004".into()),
                purpose: None,
            },
            Field {
                id: "expiry".into(),
                label: "expiry date".into(),
                value: FieldValue::MonthYear(202803),
                purpose: None,
            },
            Field {
                id: "cvv".into(),
                label: "verification number".into(),
                value: FieldValue::Concealed("999".into()),
                purpose: None,
            },
            Field {
                id: "cardholder".into(),
                label: "cardholder name".into(),
                value: FieldValue::Text("A B".into()),
                purpose: None,
            },
        ],
    });
    let item = s.save_item(item, 1_000).unwrap();
    let ext = paired(&mut s);
    let filled = call(
        &mut s,
        &ext,
        json!({"op": "fillCard", "url": "https://x.example", "itemId": item.id}),
        1_000,
    );
    assert_eq!(
        filled["card"],
        json!({"name": "A B", "number": "5500000000000004", "expMonth": "03", "expYear": "2028", "cvc": "999"})
    );
}

#[test]
fn identities_are_listed_and_filled() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let mut id = s.new_item(p, ItemKind::Identity, 1_000).unwrap();
    id.title = "Home".into();
    for f in &mut id.fields {
        match f.id.as_str() {
            "first-name" => f.value = FieldValue::Text("Ivan".into()),
            "last-name" => f.value = FieldValue::Text("K".into()),
            "email" => f.value = FieldValue::Email("ivan@example.com".into()),
            "phone" => f.value = FieldValue::Phone("+84 1".into()),
            _ => {}
        }
    }
    let text = |id: &str, value: &str| Field {
        id: id.into(),
        label: id.into(),
        value: FieldValue::Text(value.into()),
        purpose: None,
    };
    id.sections.push(Section {
        id: "addr".into(),
        title: "Address".into(),
        fields: vec![
            text("street", "Main st 1"),
            text("city", "Hanoi"),
            text("zip", "100000"),
            text("country", "VN"),
        ],
    });
    let id = s.save_item(id, 1_000).unwrap();
    let ext = paired(&mut s);
    let list = call(
        &mut s,
        &ext,
        json!({"op": "identities", "url": "https://shop.example"}),
        1_000,
    );
    assert_eq!(
        list,
        json!({"identities": [{"id": id.id, "title": "Home", "detail": "Ivan K · Hanoi"}]})
    );
    let filled = call(
        &mut s,
        &ext,
        json!({"op": "fillIdentity", "url": "https://shop.example", "itemId": id.id}),
        1_000,
    );
    assert_eq!(
        filled["identity"],
        json!({"givenName": "Ivan", "familyName": "K", "email": "ivan@example.com", "phone": "+84 1", "street": "Main st 1", "city": "Hanoi", "postalCode": "100000", "country": "VN"})
    );
}
