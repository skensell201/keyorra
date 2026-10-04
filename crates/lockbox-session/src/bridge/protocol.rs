//! JSON messages between the extension and the app. Secrets only travel inside `box`.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Inbound {
    Status,
    Show,
    #[serde(rename_all = "camelCase")]
    Pair {
        commit: String,
        name: String,
    },
    #[serde(rename_all = "camelCase")]
    PairReveal {
        client_id: String,
        client_pub: String,
    },
    #[serde(rename_all = "camelCase")]
    PairStatus {
        client_id: String,
    },
    #[serde(rename_all = "camelCase")]
    Call {
        client_id: String,
        #[serde(rename = "box")]
        sealed: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Outbound {
    Status {
        locked: bool,
        version: u32,
    },
    Ok,
    #[serde(rename_all = "camelCase")]
    PairPending {
        client_id: String,
        server_pub: String,
    },
    Paired,
    PairDenied,
    Locked,
    UnknownClient,
    Reply {
        #[serde(rename = "box")]
        sealed: String,
    },
    Error {
        message: String,
    },
}

/// Inside a request box.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "camelCase")]
pub enum Request {
    Ping,
    List {
        url: String,
    },
    #[serde(rename_all = "camelCase")]
    Fill {
        url: String,
        item_id: Uuid,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Candidate {
    pub id: Uuid,
    pub title: String,
    pub username: String,
    pub has_totp: bool,
}

/// Inside a reply box.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Reply {
    Items {
        items: Vec<Candidate>,
    },
    Credentials {
        username: String,
        password: String,
        totp: Option<String>,
    },
    Pong {
        pong: bool,
    },
    Error {
        error: String,
    },
}

pub const VERSION: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn inbound(v: serde_json::Value) -> Inbound {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn parses_what_the_extension_sends() {
        assert_eq!(inbound(json!({"kind": "status"})), Inbound::Status);
        assert_eq!(inbound(json!({"kind": "show"})), Inbound::Show);
        assert_eq!(
            inbound(json!({"kind": "pair", "commit": "AAA", "name": "Chrome"})),
            Inbound::Pair {
                commit: "AAA".into(),
                name: "Chrome".into()
            }
        );
        assert_eq!(
            inbound(json!({"kind": "pairReveal", "clientId": "c1", "clientPub": "BBB"})),
            Inbound::PairReveal {
                client_id: "c1".into(),
                client_pub: "BBB".into()
            }
        );
        assert_eq!(
            inbound(json!({"kind": "pairStatus", "clientId": "c1"})),
            Inbound::PairStatus {
                client_id: "c1".into()
            }
        );
        assert_eq!(
            inbound(json!({"kind": "call", "clientId": "c1", "box": "B"})),
            Inbound::Call {
                client_id: "c1".into(),
                sealed: "B".into()
            }
        );
        assert!(serde_json::from_value::<Inbound>(json!({"kind": "nope"})).is_err());
    }

    #[test]
    fn serializes_what_the_app_answers() {
        let s = |o: &Outbound| serde_json::to_value(o).unwrap();
        assert_eq!(
            s(&Outbound::Status {
                locked: true,
                version: 1
            }),
            json!({"kind": "status", "locked": true, "version": 1})
        );
        assert_eq!(s(&Outbound::Ok), json!({"kind": "ok"}));
        assert_eq!(
            s(&Outbound::PairPending {
                client_id: "c1".into(),
                server_pub: "S".into()
            }),
            json!({"kind": "pairPending", "clientId": "c1", "serverPub": "S"})
        );
        assert_eq!(s(&Outbound::Paired), json!({"kind": "paired"}));
        assert_eq!(s(&Outbound::PairDenied), json!({"kind": "pairDenied"}));
        assert_eq!(s(&Outbound::Locked), json!({"kind": "locked"}));
        assert_eq!(
            s(&Outbound::UnknownClient),
            json!({"kind": "unknownClient"})
        );
        assert_eq!(
            s(&Outbound::Reply { sealed: "B".into() }),
            json!({"kind": "reply", "box": "B"})
        );
        assert_eq!(
            s(&Outbound::Error {
                message: "x".into()
            }),
            json!({"kind": "error", "message": "x"})
        );
    }

    #[test]
    fn requests_and_replies_inside_the_box() {
        let id = uuid::Uuid::nil();
        assert_eq!(
            serde_json::from_value::<Request>(json!({"op": "ping"})).unwrap(),
            Request::Ping
        );
        assert_eq!(
            serde_json::from_value::<Request>(json!({"op": "list", "url": "https://a.com"}))
                .unwrap(),
            Request::List {
                url: "https://a.com".into()
            }
        );
        assert_eq!(
            serde_json::from_value::<Request>(
                json!({"op": "fill", "url": "https://a.com", "itemId": id})
            )
            .unwrap(),
            Request::Fill {
                url: "https://a.com".into(),
                item_id: id
            }
        );
        let items = Reply::Items {
            items: vec![Candidate {
                id,
                title: "A".into(),
                username: "u".into(),
                has_totp: true,
            }],
        };
        assert_eq!(
            serde_json::to_value(&items).unwrap(),
            json!({"items": [{"id": id, "title": "A", "username": "u", "hasTotp": true}]})
        );
        let creds = Reply::Credentials {
            username: "u".into(),
            password: "p".into(),
            totp: None,
        };
        assert_eq!(
            serde_json::to_value(&creds).unwrap(),
            json!({"username": "u", "password": "p", "totp": null})
        );
        assert_eq!(
            serde_json::to_value(Reply::Pong { pong: true }).unwrap(),
            json!({"pong": true})
        );
        assert_eq!(
            serde_json::to_value(Reply::Error { error: "e".into() }).unwrap(),
            json!({"error": "e"})
        );
    }
}
