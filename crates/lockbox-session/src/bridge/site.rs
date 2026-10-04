//! Which saved logins belong to a web page: same registrable domain (eTLD+1).

use url::{Host, Url};

/// A web page's host and registrable domain. Only http(s) pages have one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Site {
    pub host: String,
    pub domain: String,
}

impl Site {
    pub fn of(url: &str) -> Option<Site> {
        let url = Url::parse(url).ok()?;
        if !matches!(url.scheme(), "http" | "https") {
            return None;
        }
        let host = url.host_str()?.trim_end_matches('.').to_ascii_lowercase();
        let domain = match url.host()? {
            // IP addresses only ever match themselves.
            Host::Ipv4(_) | Host::Ipv6(_) => host.clone(),
            Host::Domain(_) => psl::domain_str(&host)
                .map(str::to_owned)
                .unwrap_or_else(|| host.clone()),
        };
        Some(Site { host, domain })
    }
}

/// How well a saved URL fits a page; better matches compare greater.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Match {
    SameSite,
    SameHost,
}

pub fn matches(page: &Site, saved_url: &str) -> Option<Match> {
    let saved = Site::of(saved_url).or_else(|| Site::of(&format!("https://{saved_url}")))?;
    if saved.host == page.host {
        Some(Match::SameHost)
    } else if saved.domain == page.domain {
        Some(Match::SameSite)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(url: &str) -> Site {
        Site::of(url).unwrap()
    }

    #[test]
    fn registrable_domain_uses_the_public_suffix_list() {
        assert_eq!(
            site("https://accounts.google.com/signin").domain,
            "google.com"
        );
        assert_eq!(site("https://www.bbc.co.uk/").domain, "bbc.co.uk");
        assert_eq!(site("https://ivan.github.io/x").domain, "ivan.github.io");
        assert_eq!(site("https://GitHub.COM./login").host, "github.com");
        assert_eq!(site("http://192.168.1.10:8006/").domain, "192.168.1.10");
        assert_eq!(site("http://localhost:8765/login.html").domain, "localhost");
    }

    #[test]
    fn only_web_pages_have_a_site() {
        for url in [
            "chrome://settings",
            "file:///Users/x/a.html",
            "about:blank",
            "not a url",
        ] {
            assert_eq!(Site::of(url), None, "{url}");
        }
    }

    #[test]
    fn matching_saved_urls() {
        let page = site("https://github.com/login");
        assert_eq!(matches(&page, "https://github.com"), Some(Match::SameHost));
        assert_eq!(
            matches(&page, "github.com"),
            Some(Match::SameHost),
            "imported URLs may lack a scheme"
        );
        assert_eq!(
            matches(&site("https://gist.github.com/"), "https://github.com"),
            Some(Match::SameSite)
        );
        assert_eq!(matches(&page, "https://evil-github.com"), None);
        assert_eq!(
            matches(&site("https://a.github.io/"), "https://b.github.io"),
            None
        );
        assert_eq!(
            matches(
                &site("http://192.168.1.10:8006/"),
                "https://192.168.1.10:8006"
            ),
            Some(Match::SameHost)
        );
        assert_eq!(
            matches(&site("http://192.168.1.10/"), "http://192.168.1.11"),
            None
        );
        assert!(Match::SameHost > Match::SameSite);
    }
}
