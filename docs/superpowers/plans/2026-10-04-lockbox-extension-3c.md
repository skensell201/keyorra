# Lockbox Browser Extension 3c Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The extension saves new or changed logins after you sign in, suggests a strong password on sign-up / change-password forms, and fills credit cards and addresses.

**Architecture:** Same split as 3a. New request types go into the sealed `Request`/`Reply` protocol and are served by `Session` (`crates/lockbox-session/src/session/bridge.rs`), unit-tested in Rust. The extension gains detectors for new-password, card and address fields, a "save login" bar and generator/card/address dropdowns built on the existing closed-shadow `InlineMenu` patterns (trusted clicks + visibility checks). All values that leave the app go only to the frame that asked, after a trusted user action.

**Tech Stack:** as 3a (Rust, TypeScript, Vitest + jsdom).

**Spec:** spec addendum "browser extension in detail" + "Hardening after review". This plan adds the 3c rules below.

**3c rules (security):**
- *Save/update* only from an http(s) page frame (sender URL from the browser), after the user clicks "Save"/"Update" in the extension's own bar (trusted click, visibility-checked). Saving never returns secrets. Updating keeps the old password in history (`save_item` already records it), so an unwanted update can be undone in the app.
- *Lookup before save* answers only `new` / `changed` / `same` — never the stored password.
- *Generate* returns a fresh password; the extension saves a **draft** login (title = host, username if known) at once, so a generated password can't be lost if sign-up fails.
- *Cards and identities* are not tied to sites. They are listed and filled only on **secure** pages (https, or local per `Site.local`), only after a trusted click in our dropdown; the list shows title + last 4 digits / city, never full numbers.

**Conventions for every task:** as in plan 3a: TDD (see the failing test first), `cargo fmt`/clippy `-D warnings`, `pnpm test && pnpm typecheck` (from `extension/`), English only, commit messages end with `Co-Authored-By: Claude Opus 5.5 (1M context) <noreply@anthropic.com>`. Vitest 5: braced `beforeEach`. Scripted replacements must assert their match exists. `rtk proxy <cmd>` shows raw output.

## File map

```
crates/lockbox-session/src/bridge/protocol.rs     + Request/Reply variants
crates/lockbox-session/src/session/bridge.rs      + lookup, save, generate, cards, identities
crates/lockbox-session/src/session/bridge_tests.rs + tests
extension/src/messages.ts, access.ts, background.ts, client.ts (+tests)   new message types
extension/src/detect.ts (+test)                    new-password, card, address fields
extension/src/fill.ts (+test)                      fillCard, fillAddress, fillNewPassword
extension/src/capture.ts (+test)                   NEW: remember submitted credentials
extension/src/savebar.ts (+test)                   NEW: "Save login?" bar (closed shadow)
extension/src/inline.ts (+test)                    menu modes: logins | generator | cards | identities
extension/src/content.ts                           wiring
```

---

### Task 1: Protocol — new requests and replies (Rust)

**Files:** `crates/lockbox-session/src/bridge/protocol.rs` (+ its tests).

- [ ] **Step 1: Failing test** — extend the protocol tests:

```rust
    #[test]
    fn requests_and_replies_for_saving_generating_cards_and_identities() {
        let id = uuid::Uuid::nil();
        let parse = |v: serde_json::Value| serde_json::from_value::<Request>(v).unwrap();
        assert_eq!(
            parse(json!({"op": "lookup", "url": "https://a.com", "username": "u", "password": "p"})),
            Request::Lookup { url: "https://a.com".into(), username: "u".into(), password: "p".into() }
        );
        assert_eq!(
            parse(json!({"op": "save", "url": "https://a.com", "username": "u", "password": "p", "itemId": null})),
            Request::Save { url: "https://a.com".into(), username: "u".into(), password: "p".into(), item_id: None }
        );
        assert_eq!(parse(json!({"op": "generate"})), Request::Generate);
        assert_eq!(parse(json!({"op": "cards", "url": "https://a.com"})), Request::Cards { url: "https://a.com".into() });
        assert_eq!(
            parse(json!({"op": "fillCard", "url": "https://a.com", "itemId": id})),
            Request::FillCard { url: "https://a.com".into(), item_id: id }
        );
        assert_eq!(parse(json!({"op": "identities", "url": "https://a.com"})), Request::Identities { url: "https://a.com".into() });
        assert_eq!(
            parse(json!({"op": "fillIdentity", "url": "https://a.com", "itemId": id})),
            Request::FillIdentity { url: "https://a.com".into(), item_id: id }
        );

        let s = |r: Reply| serde_json::to_value(r).unwrap();
        assert_eq!(s(Reply::Lookup { status: LookupStatus::Changed, item_id: Some(id) }), json!({"status": "changed", "itemId": id}));
        assert_eq!(s(Reply::Saved { saved: id }), json!({"saved": id}));
        assert_eq!(s(Reply::Generated { generated: "pw".into() }), json!({"generated": "pw"}));
        assert_eq!(
            s(Reply::Cards { cards: vec![CardSummary { id, title: "Visa".into(), last4: "1111".into() }] }),
            json!({"cards": [{"id": id, "title": "Visa", "last4": "1111"}]})
        );
        assert_eq!(
            s(Reply::Card { card: CardFill { name: "IVAN".into(), number: "4111".into(), exp_month: "12".into(), exp_year: "2027".into(), cvc: "123".into() } }),
            json!({"card": {"name": "IVAN", "number": "4111", "expMonth": "12", "expYear": "2027", "cvc": "123"}})
        );
        assert_eq!(
            s(Reply::Identities { identities: vec![IdentitySummary { id, title: "Home".into(), detail: "Hanoi".into() }] }),
            json!({"identities": [{"id": id, "title": "Home", "detail": "Hanoi"}]})
        );
        let fill = IdentityFill { given_name: "Ivan".into(), ..IdentityFill::default() };
        assert_eq!(s(Reply::Identity { identity: fill })["identity"]["givenName"], "Ivan");
    }
```

- [ ] **Step 2: Run** → compile errors.
- [ ] **Step 3: Implement** — add to `Request` (keep `#[serde(tag = "op", rename_all = "camelCase")]`):

```rust
    Lookup { url: String, username: String, password: String },
    #[serde(rename_all = "camelCase")]
    Save { url: String, username: String, password: String, item_id: Option<Uuid> },
    Generate,
    Cards { url: String },
    #[serde(rename_all = "camelCase")]
    FillCard { url: String, item_id: Uuid },
    Identities { url: String },
    #[serde(rename_all = "camelCase")]
    FillIdentity { url: String, item_id: Uuid },
```

new types:

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LookupStatus {
    New,
    Changed,
    Same,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CardSummary { pub id: Uuid, pub title: String, pub last4: String }

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CardFill { pub name: String, pub number: String, pub exp_month: String, pub exp_year: String, pub cvc: String }

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentitySummary { pub id: Uuid, pub title: String, pub detail: String }

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityFill {
    pub given_name: String,
    pub family_name: String,
    pub email: String,
    pub phone: String,
    pub street: String,
    pub city: String,
    pub postal_code: String,
    pub country: String,
}
```

and `Reply` variants (untagged; each has a unique top-level key so the TS side can tell them apart):

```rust
    #[serde(rename_all = "camelCase")]
    Lookup { status: LookupStatus, item_id: Option<Uuid> },
    Saved { saved: Uuid },
    Generated { generated: String },
    Cards { cards: Vec<CardSummary> },
    Card { card: CardFill },
    Identities { identities: Vec<IdentitySummary> },
    Identity { identity: IdentityFill },
```

Put the new untagged variants **after** `Credentials` and before `Pong`/`Error` so existing replies still serialize the same. (Untagged deserialization isn't used on the Rust side.)

- [ ] **Step 4: Run** tests + clippy. **Step 5: Commit** — `"Protocol: save, generate, cards and identities"`

---

### Task 2: Session — lookup, save, generate (Rust)

**Files:** `crates/lockbox-session/src/session/bridge.rs`, `bridge_tests.rs`.

- [ ] **Step 1: Failing tests** (append to `bridge_tests.rs`; reuse the `paired()`/`call()` helpers there):

```rust
#[test]
fn lookup_tells_new_changed_and_same_without_revealing_passwords() {
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let mut gh = save_login(&mut s, p, "GitHub", "ivan", "old-pass");
    gh.urls = vec!["https://github.com".into()];
    let gh = s.save_item(gh, 1_000).unwrap();
    let ext = paired(&mut s);
    let look = |s: &mut Session, user: &str, pw: &str| {
        call(s, &ext, json!({"op": "lookup", "url": "https://github.com/login", "username": user, "password": pw}), 1_000)
    };
    assert_eq!(look(&mut s, "ivan", "old-pass"), json!({"status": "same", "itemId": gh.id}));
    assert_eq!(look(&mut s, "ivan", "new-pass"), json!({"status": "changed", "itemId": gh.id}));
    assert_eq!(look(&mut s, "someone-else", "x"), json!({"status": "new", "itemId": null}));
    assert!(!look(&mut s, "ivan", "new-pass").to_string().contains("old-pass"));
}

#[test]
fn save_creates_a_login_for_the_site_and_update_keeps_history() {
    let (_dir, mut s) = unlocked_session();
    let ext = paired(&mut s);
    let created = call(&mut s, &ext, json!({"op": "save", "url": "https://shop.example.com/signup", "username": "me@x.com", "password": "pw1", "itemId": null}), 2_000);
    let id: uuid::Uuid = serde_json::from_value(created["saved"].clone()).unwrap();
    let item = s.item(id, 2_000).unwrap();
    assert_eq!(item.title, "shop.example.com");
    assert_eq!(item.urls, ["https://shop.example.com"]);
    assert_eq!((item.username(), item.password()), (Some("me@x.com"), Some("pw1")));

    let updated = call(&mut s, &ext, json!({"op": "save", "url": "https://shop.example.com/account", "username": "me@x.com", "password": "pw2", "itemId": id}), 3_000);
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
    let r = call(&mut s, &ext, json!({"op": "save", "url": "https://evil.example.org", "username": "me", "password": "x", "itemId": bank.id}), 1_000);
    assert_eq!(r["error"], "This login doesn't belong to this site");
    assert_eq!(s.item(bank.id, 1_000).unwrap().password(), Some("bank-pw"));
    let r = call(&mut s, &ext, json!({"op": "save", "url": "https://a.example", "username": "me", "password": "", "itemId": null}), 1_000);
    assert_eq!(r["error"], "Nothing to save");
    let r = call(&mut s, &ext, json!({"op": "save", "url": "chrome://settings", "username": "me", "password": "x", "itemId": null}), 1_000);
    assert_eq!(r["error"], "This page can't be saved");
}

#[test]
fn generate_returns_a_strong_password() {
    let (_dir, mut s) = unlocked_session();
    let ext = paired(&mut s);
    let a = call(&mut s, &ext, json!({"op": "generate"}), 1_000)["generated"].as_str().unwrap().to_owned();
    let b = call(&mut s, &ext, json!({"op": "generate"}), 1_000)["generated"].as_str().unwrap().to_owned();
    assert_eq!(a.chars().count(), 20);
    assert_ne!(a, b);
}
```

- [ ] **Step 2: Run** → failures.
- [ ] **Step 3: Implement** in `serve_request`:

```rust
            Request::Lookup { url, username, password } => self.lookup(&url, &username, &password),
            Request::Save { url, username, password, item_id } => self.save_login(&url, &username, &password, item_id, now),
            Request::Generate => match lockbox_core::generator::password(&Default::default()) {
                Ok(generated) => Reply::Generated { generated },
                Err(e) => Reply::Error { error: e.to_string() },
            },
```

helpers (inside `impl Session` in `bridge.rs`):

```rust
    /// Same-site logins whose username matches (case-insensitive), best match first.
    fn same_user(&self, page: &Site, username: &str) -> Option<Item> {
        let store = self.store.as_ref()?;
        let entries = store.list_items(None).ok()?;
        let mut found: Vec<(Match, Item)> = entries
            .into_iter()
            .filter_map(|e| match e {
                ItemEntry::Ok(item) if item.kind == ItemKind::Login => {
                    let m = item.urls.iter().filter_map(|u| matches(page, u)).max()?;
                    let same = item.username().unwrap_or_default().eq_ignore_ascii_case(username.trim());
                    same.then_some((m, item))
                }
                _ => None,
            })
            .collect();
        found.sort_by(|a, b| b.0.cmp(&a.0));
        found.into_iter().next().map(|(_, item)| item)
    }

    fn lookup(&self, url: &str, username: &str, password: &str) -> Reply {
        let Some(page) = Site::of(url) else { return Reply::Error { error: "This page can't be saved".into() } };
        match self.same_user(&page, username) {
            Some(item) if item.password() == Some(password) => Reply::Lookup { status: LookupStatus::Same, item_id: Some(item.id) },
            Some(item) => Reply::Lookup { status: LookupStatus::Changed, item_id: Some(item.id) },
            None => Reply::Lookup { status: LookupStatus::New, item_id: None },
        }
    }

    fn save_login(&mut self, url: &str, username: &str, password: &str, item_id: Option<Uuid>, now: u64) -> Reply {
        let Some(page) = Site::of(url) else { return Reply::Error { error: "This page can't be saved".into() } };
        if password.is_empty() {
            return Reply::Error { error: "Nothing to save".into() };
        }
        let result = match item_id {
            Some(id) => self.update_password(&page, id, username, password, now),
            None => self.create_login(&page, username, password, now),
        };
        match result {
            Ok(id) => Reply::Saved { saved: id },
            Err(e) => Reply::Error { error: e.message },
        }
    }

    fn update_password(&mut self, page: &Site, id: Uuid, username: &str, password: &str, now: u64) -> CmdResult<Uuid> {
        let mut item = self.item(id, now)?;
        if !item.urls.iter().any(|u| matches(page, u).is_some()) {
            return Err(CmdError::new(ErrorKind::Invalid, "This login doesn't belong to this site"));
        }
        if let Some(f) = item.fields.iter_mut().find(|f| f.purpose == Some(Purpose::Username)) {
            if f.value.as_str().unwrap_or_default().is_empty() && !username.is_empty() {
                f.value = FieldValue::Text(username.to_owned());
            }
        }
        set_password_field(&mut item, password);
        Ok(self.save_item(item, now)?.id)
    }

    fn create_login(&mut self, page: &Site, username: &str, password: &str, now: u64) -> CmdResult<Uuid> {
        let vault = self.vaults(now)?.into_iter().next().ok_or_else(|| CmdError::new(ErrorKind::NotFound, "No vault to save into"))?;
        let mut item = self.new_item(vault.id, ItemKind::Login, now)?;
        item.title = page.host.clone();
        item.urls = vec![format!("{}://{}", if page.secure { "https" } else { "http" }, page.host_with_port())];
        if let Some(f) = item.fields.iter_mut().find(|f| f.purpose == Some(Purpose::Username)) {
            f.value = FieldValue::Text(username.trim().to_owned());
        }
        set_password_field(&mut item, password);
        Ok(self.save_item(item, now)?.id)
    }
```

with a free function:

```rust
fn set_password_field(item: &mut Item, password: &str) {
    match item.fields.iter_mut().find(|f| f.purpose == Some(Purpose::Password)) {
        Some(f) => f.value = FieldValue::Concealed(password.to_owned()),
        None => item.fields.push(Field {
            id: "password".into(),
            label: "password".into(),
            value: FieldValue::Concealed(password.to_owned()),
            purpose: Some(Purpose::Password),
        }),
    }
}
```

`Session::save_item` already records the old password in history and keeps `created_at`. `Site` needs `host_with_port()`: add to `bridge/site.rs` a `pub port: Option<u16>` (from `url.port()`) and `pub fn host_with_port(&self) -> String` (`host` or `host:port`); add a site test (`http://localhost:8765/x` → `localhost:8765`). Imports: `Item, ItemKind, Field, FieldValue, Purpose` from `lockbox_core::model`, `Match` from `site`, `LookupStatus` from protocol.

`list`, `lookup`, `generate` do not count as activity; `save` does (via `save_item`/`item`, which call `touch`).

- [ ] **Step 4: Run** tests + clippy. **Step 5: Commit** — `"Serve save, lookup and generate to the extension"`

---

### Task 3: Session — cards and identities (Rust)

- [ ] **Step 1: Failing tests:**

```rust
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
    let list = call(&mut s, &ext, json!({"op": "cards", "url": "https://shop.example"}), 1_000);
    assert_eq!(list, json!({"cards": [{"id": visa.id, "title": "Visa", "last4": "1111"}]}));
    let filled = call(&mut s, &ext, json!({"op": "fillCard", "url": "https://shop.example", "itemId": visa.id}), 1_000);
    assert_eq!(filled, json!({"card": {"name": "IVAN K", "number": "4111111111111111", "expMonth": "12", "expYear": "2027", "cvc": "123"}}));
    let insecure = call(&mut s, &ext, json!({"op": "cards", "url": "http://shop.example"}), 1_000);
    assert_eq!(insecure, json!({"cards": []}));
    let refused = call(&mut s, &ext, json!({"op": "fillCard", "url": "http://shop.example", "itemId": visa.id}), 1_000);
    assert_eq!(refused["error"], "Cards are only filled on secure pages");
}

#[test]
fn imported_cards_with_month_year_and_labels_work() {
    // 1Password imports put card fields in a section with labels and a MonthYear expiry.
    let (_dir, mut s) = unlocked_session();
    let p = personal(&mut s);
    let mut item = lockbox_core::model::Item::new(p, ItemKind::CreditCard, "Imported", 1_000);
    item.sections.push(lockbox_core::model::Section {
        id: "s".into(),
        title: String::new(),
        fields: vec![
            Field { id: "ccnum".into(), label: "number".into(), value: FieldValue::Concealed("5500000000000004".into()), purpose: None },
            Field { id: "expiry".into(), label: "expiry date".into(), value: FieldValue::MonthYear(202803), purpose: None },
            Field { id: "cvv".into(), label: "verification number".into(), value: FieldValue::Concealed("999".into()), purpose: None },
            Field { id: "cardholder".into(), label: "cardholder name".into(), value: FieldValue::Text("A B".into()), purpose: None },
        ],
    });
    let item = s.save_item(item, 1_000).unwrap();
    let ext = paired(&mut s);
    let filled = call(&mut s, &ext, json!({"op": "fillCard", "url": "https://x.example", "itemId": item.id}), 1_000);
    assert_eq!(filled["card"], json!({"name": "A B", "number": "5500000000000004", "expMonth": "03", "expYear": "2028", "cvc": "999"}));
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
    id.sections.push(lockbox_core::model::Section {
        id: "addr".into(),
        title: "Address".into(),
        fields: vec![
            Field { id: "street".into(), label: "street".into(), value: FieldValue::Text("Main st 1".into()), purpose: None },
            Field { id: "city".into(), label: "city".into(), value: FieldValue::Text("Hanoi".into()), purpose: None },
            Field { id: "zip".into(), label: "zip".into(), value: FieldValue::Text("100000".into()), purpose: None },
            Field { id: "country".into(), label: "country".into(), value: FieldValue::Text("VN".into()), purpose: None },
        ],
    });
    let id = s.save_item(id, 1_000).unwrap();
    let ext = paired(&mut s);
    let list = call(&mut s, &ext, json!({"op": "identities", "url": "https://shop.example"}), 1_000);
    assert_eq!(list, json!({"identities": [{"id": id.id, "title": "Home", "detail": "Ivan K · Hanoi"}]}));
    let filled = call(&mut s, &ext, json!({"op": "fillIdentity", "url": "https://shop.example", "itemId": id.id}), 1_000);
    assert_eq!(
        filled["identity"],
        json!({"givenName": "Ivan", "familyName": "K", "email": "ivan@example.com", "phone": "+84 1", "street": "Main st 1", "city": "Hanoi", "postalCode": "100000", "country": "VN"})
    );
}
```

- [ ] **Step 2: Run** → failures.
- [ ] **Step 3: Implement** — a field lookup by id or label across built-in fields and sections:

```rust
/// First non-empty value among fields whose id or lowercase label is in `names`.
fn field_text(item: &Item, names: &[&str]) -> String {
    item.fields
        .iter()
        .chain(item.sections.iter().flat_map(|s| s.fields.iter()))
        .filter(|f| names.contains(&f.id.as_str()) || names.contains(&f.label.to_lowercase().as_str()))
        .find_map(|f| match &f.value {
            FieldValue::MonthYear(ym) => Some(format!("{:02}/{}", ym % 100, ym / 100)),
            v => v.as_str().map(str::to_owned).filter(|s| !s.trim().is_empty()),
        })
        .unwrap_or_default()
}

const CARD_NAME: &[&str] = &["cardholder", "cardholder name", "name on card"];
const CARD_NUMBER: &[&str] = &["number", "ccnum", "card number"];
const CARD_EXPIRY: &[&str] = &["expiry", "expiry date", "expiration date", "expires"];
const CARD_CVC: &[&str] = &["cvv", "cvc", "verification number", "security code"];

/// "12/27", "12/2027", "2027-12", "122027" → ("12", "2027").
fn split_expiry(raw: &str) -> (String, String) {
    let digits: Vec<&str> = raw.split(|c: char| !c.is_ascii_digit()).filter(|s| !s.is_empty()).collect();
    let (m, y) = match digits.as_slice() {
        [a, b] if a.len() == 4 => (b.to_string(), a.to_string()),
        [a, b] => (a.to_string(), b.to_string()),
        [one] if one.len() == 6 => (one[..2].to_string(), one[2..].to_string()),
        [one] if one.len() == 4 => (one[..2].to_string(), one[2..].to_string()),
        _ => (String::new(), String::new()),
    };
    let year = if y.len() == 2 { format!("20{y}") } else { y };
    (format!("{:0>2}", m), year)
}
```

and the request arms + helpers:

```rust
            Request::Cards { url } => Reply::Cards { cards: self.cards(&url) },
            Request::FillCard { url, item_id } => self.card(&url, item_id, now),
            Request::Identities { url } => Reply::Identities { identities: self.identities(&url) },
            Request::FillIdentity { url, item_id } => self.identity(&url, item_id, now),
```

```rust
    fn secure_page(url: &str) -> bool {
        Site::of(url).is_some_and(|s| s.secure || s.local)
    }

    fn items_of(&self, kind: ItemKind) -> Vec<Item> {
        let Some(store) = self.store.as_ref() else { return Vec::new() };
        let mut items: Vec<Item> = store
            .list_items(None)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|e| match e {
                ItemEntry::Ok(item) if item.kind == kind => Some(item),
                _ => None,
            })
            .collect();
        items.sort_by(|a, b| a.title.to_lowercase().cmp(&b.title.to_lowercase()));
        items
    }

    fn cards(&self, url: &str) -> Vec<CardSummary> {
        if !Self::secure_page(url) {
            return Vec::new();
        }
        self.items_of(ItemKind::CreditCard)
            .into_iter()
            .map(|item| {
                let digits: String = field_text(&item, CARD_NUMBER).chars().filter(char::is_ascii_digit).collect();
                let last4 = digits.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
                CardSummary { id: item.id, title: item.title, last4 }
            })
            .collect()
    }

    fn card(&mut self, url: &str, id: Uuid, now: u64) -> Reply {
        if !Self::secure_page(url) {
            return Reply::Error { error: "Cards are only filled on secure pages".into() };
        }
        let item = match self.item(id, now) {
            Ok(item) if item.kind == ItemKind::CreditCard => item,
            Ok(_) => return Reply::Error { error: "Not a card".into() },
            Err(e) => return Reply::Error { error: e.message },
        };
        let (exp_month, exp_year) = split_expiry(&field_text(&item, CARD_EXPIRY));
        Reply::Card {
            card: CardFill {
                name: field_text(&item, CARD_NAME),
                number: field_text(&item, CARD_NUMBER).chars().filter(char::is_ascii_digit).collect(),
                exp_month,
                exp_year,
                cvc: field_text(&item, CARD_CVC),
            },
        }
    }

    fn identities(&self, url: &str) -> Vec<IdentitySummary> {
        if !Self::secure_page(url) {
            return Vec::new();
        }
        self.items_of(ItemKind::Identity)
            .into_iter()
            .map(|item| {
                let f = identity_fill(&item);
                let name = [f.given_name.as_str(), f.family_name.as_str()].iter().filter(|s| !s.is_empty()).copied().collect::<Vec<_>>().join(" ");
                let detail = [name.as_str(), f.city.as_str()].iter().filter(|s| !s.is_empty()).copied().collect::<Vec<_>>().join(" · ");
                IdentitySummary { id: item.id, title: item.title, detail }
            })
            .collect()
    }

    fn identity(&mut self, url: &str, id: Uuid, now: u64) -> Reply {
        if !Self::secure_page(url) {
            return Reply::Error { error: "Addresses are only filled on secure pages".into() };
        }
        match self.item(id, now) {
            Ok(item) if item.kind == ItemKind::Identity => Reply::Identity { identity: identity_fill(&item) },
            Ok(_) => Reply::Error { error: "Not an identity".into() },
            Err(e) => Reply::Error { error: e.message },
        }
    }
```

```rust
fn identity_fill(item: &Item) -> IdentityFill {
    IdentityFill {
        given_name: field_text(item, &["first-name", "firstname", "first name"]),
        family_name: field_text(item, &["last-name", "lastname", "last name"]),
        email: field_text(item, &["email", "e-mail"]),
        phone: field_text(item, &["phone", "cell", "mobile", "telephone"]),
        street: field_text(item, &["street", "address", "address line 1"]),
        city: field_text(item, &["city", "town"]),
        postal_code: field_text(item, &["zip", "postal code", "postcode"]),
        country: field_text(item, &["country"]),
    }
}
```

`card`/`identity` call `self.item()` which touches auto-lock (they are user-initiated fills); `cards`/`identities` lists don't. Note: the identity test's section field id "street"/"city"… match by id; imported 1Password addresses come as one joined "address" text — that goes to `street` via the "address" label; acceptable for now.

- [ ] **Step 4: Run** tests + clippy. **Step 5: Commit** — `"Serve cards and identities to the extension"`

---

### Task 4: Extension — client, messages, access rules

**Files:** `extension/src/client.ts`, `messages.ts`, `access.ts`, `background.ts` (+ `client.test.ts`, `access.test.ts`).

- [ ] **Step 1: Failing tests**
  - `client.test.ts`: extend the fake app to answer `lookup` (`{status, itemId}`), `save` (`{saved}`), `generate` (`{generated}`), `cards`, `fillCard`, `identities`, `fillIdentity`; test that `client.lookup(url,u,p)`, `client.save(url,u,p,itemId|null)`, `client.generate()`, `client.cards(url)`, `client.fillCard(url,id)`, `client.identities(url)`, `client.fillIdentity(url,id)` send the right `op` and return the inner value.
  - `access.test.ts`: `lookup`, `save`, `generate`, `cards`, `fillCard`, `identities`, `fillIdentity` are allowed **only from http(s) pages** and always use `sender.url` (a `url` in the message is ignored); refused from extension pages and from other extensions.
- [ ] **Step 2: Run** → fail.
- [ ] **Step 3: Implement**
  - `client.ts` methods (same `request()` path as `list`/`fill`):
    ```ts
    lookup(url: string, username: string, password: string): Promise<{ status: "new" | "changed" | "same"; itemId: string | null }>
    save(url: string, username: string, password: string, itemId: string | null): Promise<string>   // returns the saved id
    generate(): Promise<string>
    cards(url: string): Promise<CardSummary[]>
    fillCard(url: string, itemId: string): Promise<CardFill>
    identities(url: string): Promise<IdentitySummary[]>
    fillIdentity(url: string, itemId: string): Promise<IdentityFill>
    ```
    with exported interfaces mirroring the Rust serde shapes (`CardSummary {id,title,last4}`, `CardFill {name,number,expMonth,expYear,cvc}`, `IdentitySummary {id,title,detail}`, `IdentityFill {givenName,familyName,email,phone,street,city,postalCode,country}`).
  - `messages.ts` `ToBackground` gains `{type:"lookup";username;password}`, `{type:"save";username;password;itemId:string|null}`, `{type:"generate"}`, `{type:"cards"}`, `{type:"fillCard";itemId}`, `{type:"identities"}`, `{type:"fillIdentity";itemId}`.
  - `access.ts`: these types → page-only, `url = sender.url`.
  - `background.ts`: dispatch them to the client with the authorized URL.
- [ ] **Step 4: Run** `pnpm test && pnpm typecheck`. **Step 5: Commit** — `"Extension client: save, generate, cards and identities"`

---

### Task 5: Extension — detect and fill new-password, card and address fields

**Files:** `extension/src/detect.ts`, `fill.ts` (+ tests).

- [ ] **Step 1: Failing tests** (jsdom):
  - `findNewPasswordFields(document)` returns visible password inputs with `autocomplete="new-password"`, or — on forms with two or three password inputs — the ones after the first (change-password: current + new + confirm → new+confirm; sign-up: password + confirm → both). A login form with one password → `[]`.
  - `findCardFields(document)` → `{ number, name, exp, expMonth, expYear, cvc }`, each `HTMLInputElement|HTMLSelectElement|null`, by `autocomplete` (`cc-number`, `cc-name`, `cc-exp`, `cc-exp-month`, `cc-exp-year`, `cc-csc`) first, then name/id/placeholder hints (`/card.?num|cc.?num|cardnumber/i`, `/name.?on.?card|cardholder|cc.?name/i`, `/exp(iry|iration)?(.?date)?$|mm.?yy|cc.?exp$/i`, `/exp.*month|cc.?month|\bmm\b/i`, `/exp.*year|cc.?year|\byy(yy)?\b/i`, `/cvc|cvv|csc|security.?code/i`). Test a Stripe-like form and a form with month/year selects.
  - `findAddressFields(document)` → `{ givenName, familyName, name, email, phone, street, city, postalCode, country }` by `autocomplete` (`given-name`, `family-name`, `name`, `email`, `tel`, `street-address`/`address-line1`, `address-level2`, `postal-code`, `country`/`country-name`) then hints.
  - `fillCard(fields, card)`: number into number; name; `exp` single field gets `MM/YY`; selects get the matching option (`12`, `2027` or `27`, by value or text); cvc. `fillAddress(fields, identity)`: `name` gets "given family" when there are no split fields. `fillNewPassword(fields, pw)`: all new-password fields. All via `setValue` (selects: set `.value` + dispatch `input`/`change`).
- [ ] **Step 2–4:** implement (respect the existing `usable()` visibility rules for every field), `pnpm test && pnpm typecheck`.
- [ ] **Step 5: Commit** — `"Detect and fill new-password, card and address fields"`

---

### Task 6: Extension — capture submitted logins and the save bar

**Files:** create `extension/src/capture.ts`, `savebar.ts` (+ tests); modify `content.ts`.

- [ ] **Step 1: Failing tests**
  - `capture.test.ts`: `watchSubmissions(document, onSubmit)` calls `onSubmit({username, password})` when (a) a form containing a filled password field is submitted, (b) a button of type submit / with text matching `/sign.?in|log.?in|continue|next|войти|далее/i` inside such a form is clicked, (c) Enter is pressed in the password field. For sign-up/change forms the **new** password is reported. Empty password → no call. The username comes from `findLoginFields` (or the email field of a sign-up form). Duplicate submissions within 2 s are reported once.
  - `savebar.test.ts`: `new SaveBar({ save, dismiss }, { onRoot, trusted, visible })` (same injectable test hooks as `InlineMenu`) shows "Save login for **example.com**?" with the username, or "Update password for **example.com**?" for `changed`; buttons "Save"/"Update" and "Not now"; untrusted clicks do nothing; the bar auto-hides after 30 s; text set via `textContent` only; closed shadow root.
- [ ] **Step 3: Implement**
  - `capture.ts`: listeners on `submit` (capture phase), `click` (capture, `event.isTrusted` only), `keydown` Enter in password inputs; read values at that moment.
  - `savebar.ts`: fixed bar at the top-right of the viewport (z-index max), closed shadow, styles like the inline menu (light/dark via `prefers-color-scheme`), same `allowed()` checks as `InlineMenu` (copy the `defaultVisible` logic into a shared `visibility.ts` and import it from both).
  - `content.ts` (top frame and subframes): on submit → `ask({type:"lookup", username, password})`; `same` → nothing; `new`/`changed` → keep `{username,password,itemId}` in `sessionStorage` of the page? **No** (page can read it). Keep it in the content script's memory and, because the page usually navigates after login, also send it to the background: `ask({type:"pendingSave", ...})` stored **in the background's memory only** (per tab, cleared after 60 s), and on the next page load in that tab the content script asks `{type:"takePendingSave"}` and shows the bar. Add these two message types: page-only, keyed by `sender.tab.id`; `takePendingSave` returns it only when the new page's registrable domain equals the stored one (use a tiny `sameSite(a,b)` helper comparing hostnames' last two labels is **not** enough — reuse the `list` call: the app decides; simplest: store the URL and only show the bar if `new URL(stored).hostname` ends with the current hostname's registrable part as reported by `ask({type:"list"})` returning candidates? Keep it simple and safe: show only if `new URL(stored).host === location.host`).
  - "Save"/"Update" → `ask({type:"save", username, password, itemId})` → bar shows "Saved" for 2 s.
- [ ] **Step 4: Run** `pnpm test && pnpm typecheck`. **Step 5: Commit** — `"Offer to save or update logins after sign-in"`

---

### Task 7: Extension — generator, card and address dropdowns

**Files:** `extension/src/inline.ts` (+test), `content.ts`.

- [ ] **Step 1: Failing tests** (`inline.test.ts`, with the existing `onRoot`/`trusted`/`visible`/`settleMs` hooks):
  - Watching a field with mode `"generator"`: opening the menu shows "Use a strong password" with the generated value (monospace, middle-truncated) from `actions.generate()`; picking it calls `actions.useGenerated(value)`.
  - Mode `"cards"`: items show title and `•••• 1111`; picking calls `actions.fillCard(id)`; empty → "No cards in Lockbox"; on an insecure page the list is empty → "Cards are only filled on secure pages".
  - Mode `"identities"`: items show title and detail; picking calls `actions.fillIdentity(id)`.
- [ ] **Step 2–3: Implement**
  - `InlineMenu.watch(field, mode = "logins")`; `MenuActions` gains `generate`, `useGenerated`, `cards`, `fillCard`, `identities`, `fillIdentity`. The panel builder switches on the mode; all checks (`allowed`, settle time) unchanged.
  - `content.ts` `scan()`: login fields → `"logins"`; new-password fields → `"generator"` (if a field is both, generator wins on sign-up forms); card fields → `"cards"`; address fields → `"identities"`.
  - `useGenerated(pw)`: `fillNewPassword(findNewPasswordFields(document), pw)`, then save a **draft** right away: `ask({type:"save", username: <login/email field value or "">, password: pw, itemId: null})`, and remember `{itemId: saved}` so the save bar after submit becomes an *update* of that draft (lookup will report `same` if unchanged — then no bar).
- [ ] **Step 4: Run** `pnpm test && pnpm typecheck && pnpm build`. **Step 5: Commit** — `"Generator, card and address dropdowns"`

---

### Task 8: Manual run in Chrome (controller), docs

- [ ] Full checks: `cargo fmt --check`, clippy (core, session, app), `cargo test`, app `pnpm test`, extension `pnpm test && pnpm typecheck && pnpm build`.
- [ ] Test pages in `/tmp/lbtest` served on `http://localhost:8765` (local → counts as secure): `signup.html` (email, password, confirm), `change.html` (current, new, confirm), `checkout.html` (cc-number, cc-name, cc-exp, cc-csc; and a variant with month/year selects), `address.html` (given/family name, email, tel, street, city, postal code, country select). Each page shows submitted values after submit.
- [ ] Check by hand: sign up → generator → draft saved → submit → no duplicate; login with a new password on `login.html` → "Update password?" → Update → password history in the app; checkout fills a card; address fills; save bar ignores untrusted clicks.
- [ ] README: mention saving, generator, cards and addresses. Merge/push per the user.

## Self-review notes

- 3c rules (top of plan) map to: lookup/save (Tasks 2, 4, 6), generator draft (2, 7), cards/identities on secure pages only with masked lists (3, 4, 7).
- Pending-save state lives only in the background's memory (not page storage) and is shown only on the same host.
- Untagged `Reply` variants all have distinct top-level keys (`items`, `username`, `pong`, `error`, `status`, `saved`, `generated`, `cards`, `card`, `identities`, `identity`).
