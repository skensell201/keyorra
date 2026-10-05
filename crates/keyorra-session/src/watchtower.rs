//! The Watchtower report the UI shows: weak, reused, breached and missing-2FA passwords.
//! Breach counts come from a cache of Have I Been Pwned answers the session keeps in memory.

use std::collections::{BTreeSet, HashMap};
use std::fmt::Write as _;

use keyorra_core::model::{Item, ItemKind};
use keyorra_core::watchtower::{self, hibp, FindingKind};
use serde::Serialize;
use zeroize::{Zeroize, Zeroizing};

use crate::bridge::site::Site;
use crate::dto::ItemSummary;

/// Registrable domains known to offer authenticator-app codes; see the file's header.
const TOTP_SITES: &str = include_str!("../assets/totp-sites.txt");

/// SHA-1 of a password: the key of the breach cache. Raw bytes, wiped when dropped.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PasswordHash([u8; 20]);

impl PasswordHash {
    pub fn of(password: &str) -> Self {
        Self(hibp::sha1(password))
    }

    /// Upper-case hex, for the Have I Been Pwned range query.
    pub fn hex(&self) -> Zeroizing<String> {
        let mut out = Zeroizing::new(String::with_capacity(40));
        for b in self.0 {
            let _ = write!(out, "{b:02X}");
        }
        out
    }
}

impl Drop for PasswordHash {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for PasswordHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PasswordHash(..)")
    }
}

/// Have I Been Pwned answers: how often each password was seen in breaches.
pub type BreachCache = HashMap<PasswordHash, u64>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub item: ItemSummary,
    pub detail: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub breached: Vec<Finding>,
    pub reused: Vec<Finding>,
    pub weak: Vec<Finding>,
    pub missing_two_factor: Vec<Finding>,
    /// Every current password has a cached breach answer.
    pub breaches_checked: bool,
    /// Distinct passwords without a breach answer yet.
    pub unchecked_passwords: usize,
}

pub fn report(items: &[Item], breaches: &BreachCache) -> Report {
    let by_id: HashMap<_, _> = items.iter().map(|i| (i.id, i)).collect();
    let finding = |id, detail: String| Finding {
        item: ItemSummary::of(by_id[&id]),
        detail,
    };
    let weak = watchtower::weak(items)
        .into_iter()
        .map(|f| match f.kind {
            FindingKind::Weak { score } => {
                finding(f.item_id, format!("Weak password (strength {score} of 4)"))
            }
            _ => unreachable!("weak() only reports weak passwords"),
        })
        .collect();
    let reused = watchtower::reused(items)
        .into_iter()
        .map(|f| match f.kind {
            FindingKind::Reused { count } => {
                let others = count - 1;
                let s = if others == 1 { "" } else { "s" };
                finding(
                    f.item_id,
                    format!("Same password as {others} other item{s}"),
                )
            }
            _ => unreachable!("reused() only reports reuse"),
        })
        .collect();
    let breached = items
        .iter()
        .filter_map(|item| {
            let count = *breaches.get(&PasswordHash::of(password(item)?))?;
            (count > 0).then(|| {
                finding(
                    item.id,
                    format!("Found {} times in data breaches", thousands(count)),
                )
            })
        })
        .collect();
    let missing_two_factor = items
        .iter()
        .filter_map(|item| {
            let domain = totp_domain(item)?;
            Some(finding(
                item.id,
                format!("{domain} offers one-time passwords"),
            ))
        })
        .collect();
    let unchecked_passwords = unchecked_hashes(items, breaches).len();
    let mut report = Report {
        breached,
        reused,
        weak,
        missing_two_factor,
        breaches_checked: unchecked_passwords == 0,
        unchecked_passwords,
    };
    for list in [
        &mut report.breached,
        &mut report.reused,
        &mut report.weak,
        &mut report.missing_two_factor,
    ] {
        list.sort_by(|a, b| {
            a.item
                .title
                .to_lowercase()
                .cmp(&b.item.title.to_lowercase())
                .then(a.item.id.cmp(&b.item.id))
        });
    }
    report
}

impl Report {
    /// Items with at least one finding (the sidebar badge).
    pub fn item_count(&self) -> usize {
        [
            &self.breached,
            &self.reused,
            &self.weak,
            &self.missing_two_factor,
        ]
        .into_iter()
        .flatten()
        .map(|f| f.item.id)
        .collect::<BTreeSet<_>>()
        .len()
    }
}

/// Distinct password hashes with no cached breach answer, sorted.
pub fn unchecked_hashes(items: &[Item], breaches: &BreachCache) -> Vec<PasswordHash> {
    items
        .iter()
        .filter_map(password)
        .map(PasswordHash::of)
        .filter(|h| !breaches.contains_key(h))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn password(item: &Item) -> Option<&str> {
    item.password().filter(|p| !p.is_empty())
}

/// The site's domain when this login has no one-time password but its site offers them.
fn totp_domain(item: &Item) -> Option<String> {
    if item.kind != ItemKind::Login || item.totp().is_some() {
        return None;
    }
    item.urls.iter().find_map(|url| {
        let url = if url.contains("://") {
            url.clone()
        } else {
            format!("https://{url}")
        };
        let domain = Site::of(&url)?.domain;
        totp_sites().any(|d| d == domain).then_some(domain)
    })
}

fn totp_sites() -> impl Iterator<Item = &'static str> {
    TOTP_SITES
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
}

/// 3861493 → "3,861,493".
fn thousands(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyorra_core::model::{Field, FieldValue};
    use uuid::Uuid;

    fn login(title: &str, password: &str, url: &str) -> Item {
        let mut item = Item::new(Uuid::new_v4(), ItemKind::Login, title, 0);
        if !password.is_empty() {
            item.set_password(password, 0);
        }
        if !url.is_empty() {
            item.urls.push(url.into());
        }
        item
    }

    fn titles(list: &[Finding]) -> Vec<&str> {
        list.iter().map(|f| f.item.title.as_str()).collect()
    }

    #[test]
    fn weak_and_reused_with_details() {
        let items = [
            login("Bank", "password", ""),
            login("Alpha", "Tr0ub4dor&3-horse-staple!", ""),
            login("Zulu", "Tr0ub4dor&3-horse-staple!", ""),
        ];
        let r = report(&items, &BreachCache::new());
        assert_eq!(titles(&r.weak), ["Bank"]);
        assert!(r.weak[0].detail.starts_with("Weak password (strength "));
        assert_eq!(titles(&r.reused), ["Alpha", "Zulu"]);
        assert_eq!(r.reused[0].detail, "Same password as 1 other item");
    }

    #[test]
    fn breaches_come_from_the_cache_only() {
        let items = [
            login("Old", "password", ""),
            login("New", "n3w-Unique-Pass!", ""),
        ];
        let r = report(&items, &BreachCache::new());
        assert!(r.breached.is_empty());
        assert!(!r.breaches_checked);
        assert_eq!(r.unchecked_passwords, 2);

        let mut cache = BreachCache::new();
        cache.insert(PasswordHash::of("password"), 3_861_493);
        cache.insert(PasswordHash::of("n3w-Unique-Pass!"), 0);
        let r = report(&items, &cache);
        assert_eq!(titles(&r.breached), ["Old"]);
        assert_eq!(
            r.breached[0].detail,
            "Found 3,861,493 times in data breaches"
        );
        assert!(r.breaches_checked);
        assert_eq!(r.unchecked_passwords, 0);
    }

    #[test]
    fn unchecked_hashes_are_distinct_and_skip_empty_passwords() {
        let items = [
            login("A", "same", ""),
            login("B", "same", ""),
            login("C", "", ""),
        ];
        assert_eq!(
            unchecked_hashes(&items, &BreachCache::new()),
            [PasswordHash::of("same")]
        );
    }

    #[test]
    fn missing_two_factor_for_known_sites_without_a_code() {
        let mut with_code = login("GitHub work", "x", "https://github.com/login");
        with_code.fields.push(Field {
            id: "otp".into(),
            label: "one-time password".into(),
            value: FieldValue::Totp("JBSWY3DPEHPK3PXP".into()),
            purpose: None,
            extra: Default::default(),
        });
        let items = [
            login("GitHub", "x", "https://github.com/login"),
            login("Google", "x", "accounts.google.com"),
            login("Local NAS", "x", "http://192.168.1.10"),
            login("Unknown", "x", "https://example.org"),
            with_code,
        ];
        let r = report(&items, &BreachCache::new());
        assert_eq!(titles(&r.missing_two_factor), ["GitHub", "Google"]);
        assert_eq!(
            r.missing_two_factor[0].detail,
            "github.com offers one-time passwords"
        );
    }

    #[test]
    fn site_list_is_clean() {
        let sites: Vec<_> = totp_sites().collect();
        assert!(sites.len() > 40);
        for d in &sites {
            assert_eq!(*d, d.to_ascii_lowercase(), "{d}");
            assert_eq!(
                Site::of(&format!("https://{d}")).unwrap().domain,
                *d,
                "{d} is not eTLD+1"
            );
        }
    }

    #[test]
    fn password_hash_hex_matches_hibp_format() {
        let h = PasswordHash::of("password");
        assert_eq!(*h.hex(), hibp::sha1_hex_upper("password"));
        assert_eq!(format!("{h:?}"), "PasswordHash(..)", "never printed");
    }

    #[test]
    fn item_count_counts_each_item_once() {
        let items = [
            login("A", "password", ""),
            login("B", "password", "https://github.com"),
        ];
        let r = report(&items, &BreachCache::new());
        assert_eq!(r.item_count(), 2);
    }

    #[test]
    fn thousands_groups_digits() {
        assert_eq!(thousands(7), "7");
        assert_eq!(thousands(1_000), "1,000");
        assert_eq!(thousands(3_861_493), "3,861,493");
    }
}
