//! The native-messaging host: how browsers start us and where their host manifests live.

use std::path::{Path, PathBuf};

use serde_json::json;

pub const HOST_NAME: &str = "app.lockbox.bridge";
pub const CHROMIUM_EXTENSION_ID: &str = "kaaofpbpmnghapcafbbhjflonijdijbj";
pub const FIREFOX_EXTENSION_ID: &str = "lockbox@lockbox.app";

/// Chromium passes the caller's origin; Firefox passes the manifest path and the extension id.
pub fn is_host_launch(args: &[String]) -> bool {
    args.iter()
        .skip(1)
        .any(|a| a.starts_with("chrome-extension://") || a == FIREFOX_EXTENSION_ID)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    Chromium,
    Firefox,
}

pub struct Browser {
    pub name: &'static str,
    /// Profile folder under `~/Library/Application Support`.
    pub dir: &'static str,
    pub family: Family,
}

pub const BROWSERS: &[Browser] = &[
    Browser {
        name: "Chrome",
        dir: "Google/Chrome",
        family: Family::Chromium,
    },
    Browser {
        name: "Chrome Beta",
        dir: "Google/Chrome Beta",
        family: Family::Chromium,
    },
    Browser {
        name: "Chromium",
        dir: "Chromium",
        family: Family::Chromium,
    },
    Browser {
        name: "Opera",
        dir: "com.operasoftware.Opera",
        family: Family::Chromium,
    },
    Browser {
        name: "Yandex",
        dir: "Yandex/YandexBrowser",
        family: Family::Chromium,
    },
    Browser {
        name: "Brave",
        dir: "BraveSoftware/Brave-Browser",
        family: Family::Chromium,
    },
    Browser {
        name: "Edge",
        dir: "Microsoft Edge",
        family: Family::Chromium,
    },
    Browser {
        name: "Vivaldi",
        dir: "Vivaldi",
        family: Family::Chromium,
    },
    Browser {
        name: "Arc",
        dir: "Arc/User Data",
        family: Family::Chromium,
    },
    Browser {
        name: "Firefox",
        dir: "Mozilla",
        family: Family::Firefox,
    },
];

pub struct Manifest {
    pub browser: &'static str,
    pub path: PathBuf,
    pub contents: String,
}

/// Host manifests for every browser whose profile folder exists under `app_support`.
pub fn manifests(app_support: &Path, exe: &Path) -> Vec<Manifest> {
    BROWSERS
        .iter()
        .filter(|b| app_support.join(b.dir).is_dir())
        .map(|b| Manifest {
            browser: b.name,
            path: app_support
                .join(b.dir)
                .join("NativeMessagingHosts")
                .join(format!("{HOST_NAME}.json")),
            contents: manifest_json(b.family, exe),
        })
        .collect()
}

fn manifest_json(family: Family, exe: &Path) -> String {
    let mut m = json!({
        "name": HOST_NAME,
        "description": "Lockbox password manager",
        "path": exe.to_string_lossy(),
        "type": "stdio",
    });
    match family {
        Family::Chromium => {
            m["allowed_origins"] = json!([format!("chrome-extension://{CHROMIUM_EXTENSION_ID}/")])
        }
        Family::Firefox => m["allowed_extensions"] = json!([FIREFOX_EXTENSION_ID]),
    }
    serde_json::to_string_pretty(&m).expect("manifest serializes")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn recognises_browser_launches() {
        assert!(is_host_launch(&args(&[
            "lockbox-app",
            "chrome-extension://kaaofpbpmnghapcafbbhjflonijdijbj/"
        ])));
        assert!(is_host_launch(&args(&[
            "lockbox-app",
            "/x/app.lockbox.bridge.json",
            "lockbox@lockbox.app"
        ])));
        assert!(!is_host_launch(&args(&["lockbox-app"])));
        assert!(!is_host_launch(&args(&["lockbox-app", "--hidden"])));
    }

    #[test]
    fn writes_manifests_only_for_installed_browsers() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("Google/Chrome")).unwrap();
        std::fs::create_dir_all(dir.path().join("Mozilla")).unwrap();
        let exe = std::path::Path::new("/Applications/Lockbox.app/Contents/MacOS/lockbox-app");
        let found = manifests(dir.path(), exe);
        let names: Vec<_> = found.iter().map(|m| m.browser).collect();
        assert_eq!(names, ["Chrome", "Firefox"]);
        assert_eq!(
            found[0].path,
            dir.path()
                .join("Google/Chrome/NativeMessagingHosts/app.lockbox.bridge.json")
        );

        let chrome: serde_json::Value = serde_json::from_str(&found[0].contents).unwrap();
        assert_eq!(chrome["name"], "app.lockbox.bridge");
        assert_eq!(chrome["type"], "stdio");
        assert_eq!(chrome["path"], exe.to_str().unwrap());
        assert_eq!(
            chrome["allowed_origins"][0],
            "chrome-extension://kaaofpbpmnghapcafbbhjflonijdijbj/"
        );
        assert!(chrome.get("allowed_extensions").is_none());

        let firefox: serde_json::Value = serde_json::from_str(&found[1].contents).unwrap();
        assert_eq!(firefox["allowed_extensions"][0], "lockbox@lockbox.app");
        assert!(firefox.get("allowed_origins").is_none());
    }
}
