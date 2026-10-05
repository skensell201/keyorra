//! Have I Been Pwned "range" API with k-anonymity: only the first 5 hex
//! characters of the password's SHA-1 leave the machine.

use std::collections::HashMap;
use std::time::Duration;

use sha1::{Digest, Sha1};

use super::{Finding, FindingKind};
use crate::model::Item;
use crate::{Error, Result};

pub const DEFAULT_BASE_URL: &str = "https://api.pwnedpasswords.com";

pub struct Hibp {
    base_url: String,
    agent: ureq::Agent,
}

impl Default for Hibp {
    fn default() -> Self {
        Self::with_base_url(DEFAULT_BASE_URL)
    }
}

impl Hibp {
    pub fn with_base_url(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(15))
                .build(),
        }
    }

    /// How many times the password appears in known breaches (0 = not found).
    pub fn breach_count(&self, password: &str) -> Result<u64> {
        let hash = sha1_hex_upper(password);
        let (prefix, suffix) = hash.split_at(5);
        let network = |e: &dyn std::fmt::Display| Error::Network(e.to_string());
        let body = self
            .agent
            .get(&format!("{}/range/{prefix}", self.base_url))
            .set("Add-Padding", "true")
            .set("User-Agent", "Keepsake")
            .call()
            .map_err(|e| network(&e))?
            .into_string()
            .map_err(|e| network(&e))?;
        Ok(count_in_range(&body, suffix))
    }
}

pub fn sha1_hex_upper(password: &str) -> String {
    Sha1::digest(password.as_bytes())
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect()
}

/// Parses `SUFFIX:COUNT` lines; padding lines have count 0.
pub fn count_in_range(body: &str, suffix: &str) -> u64 {
    body.lines()
        .find_map(|line| {
            let (s, count) = line.trim().split_once(':')?;
            s.eq_ignore_ascii_case(suffix)
                .then(|| count.trim().parse().unwrap_or(0))
        })
        .unwrap_or(0)
}

/// Items whose password appears in a breach. Each distinct password is queried once.
pub fn breached(items: &[Item], hibp: &Hibp) -> Result<Vec<Finding>> {
    let mut cache: HashMap<&str, u64> = HashMap::new();
    let mut out = Vec::new();
    for item in items {
        let Some(password) = item.password().filter(|p| !p.is_empty()) else {
            continue;
        };
        let count = match cache.get(password) {
            Some(count) => *count,
            None => {
                let count = hibp.breach_count(password)?;
                cache.insert(password, count);
                count
            }
        };
        if count > 0 {
            out.push(Finding {
                item_id: item.id,
                kind: FindingKind::Breached { count },
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ItemKind;
    use crate::Error;
    use uuid::Uuid;

    const PASSWORD_SHA1: &str = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8";

    #[test]
    fn sha1_is_uppercase_hex() {
        assert_eq!(sha1_hex_upper("password"), PASSWORD_SHA1);
    }

    #[test]
    fn count_in_range_finds_suffix_case_insensitively() {
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:0\r\n1e4c9b93f3f0682250b6cf8331b7ee68fd8:3861493\r\n";
        assert_eq!(
            count_in_range(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8"),
            3861493
        );
        assert_eq!(count_in_range(body, "FFFF"), 0);
    }

    #[test]
    fn only_the_hash_prefix_is_sent() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/range/5BAA6")
            .match_header("add-padding", "true")
            .with_body("1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\n")
            .create();
        let hibp = Hibp::with_base_url(&server.url());
        assert_eq!(hibp.breach_count("password").unwrap(), 3861493);
        mock.assert();
    }

    #[test]
    fn breached_reports_items_and_queries_each_password_once() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/range/5BAA6")
            .with_body("1E4C9B93F3F0682250B6CF8331B7EE68FD8:10\r\n")
            .expect(1)
            .create();
        let other_prefix = sha1_hex_upper("unbreached-zz9")[..5].to_owned();
        let other = server
            .mock("GET", format!("/range/{other_prefix}").as_str())
            .with_body("")
            .expect(1)
            .create();
        let mut a = Item::new(Uuid::new_v4(), ItemKind::Login, "a", 0);
        a.set_password("password", 0);
        let mut b = a.clone();
        b.id = Uuid::new_v4();
        let mut c = Item::new(Uuid::new_v4(), ItemKind::Login, "c", 0);
        c.set_password("unbreached-zz9", 0);

        let findings = breached(
            &[a.clone(), b.clone(), c],
            &Hibp::with_base_url(&server.url()),
        )
        .unwrap();
        assert_eq!(
            findings,
            vec![
                Finding {
                    item_id: a.id,
                    kind: FindingKind::Breached { count: 10 }
                },
                Finding {
                    item_id: b.id,
                    kind: FindingKind::Breached { count: 10 }
                },
            ]
        );
        mock.assert();
        other.assert();
    }

    #[test]
    fn network_failure_is_a_network_error() {
        let hibp = Hibp::with_base_url("http://127.0.0.1:9");
        assert!(matches!(
            hibp.breach_count("password"),
            Err(Error::Network(_))
        ));
    }
}
