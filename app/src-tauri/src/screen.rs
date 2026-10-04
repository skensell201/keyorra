//! Whether the macOS login session's screen is locked (CoreGraphics session dictionary).

#[cfg(target_os = "macos")]
pub fn is_locked() -> bool {
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::boolean::CFBoolean;
    use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
    use core_foundation::string::CFString;

    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGSessionCopyCurrentDictionary() -> CFDictionaryRef;
    }

    // SAFETY: the function follows the Create rule (we own the returned dictionary) and may
    // return NULL when there is no GUI session.
    let raw = unsafe { CGSessionCopyCurrentDictionary() };
    if raw.is_null() {
        return false;
    }
    let dict: CFDictionary<CFString, CFType> = unsafe { CFDictionary::wrap_under_create_rule(raw) };
    dict.find(CFString::from_static_string("CGSSessionScreenIsLocked"))
        .and_then(|value| value.downcast::<CFBoolean>())
        .map(bool::from)
        .unwrap_or(false)
}

#[cfg(not(target_os = "macos"))]
pub fn is_locked() -> bool {
    false
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    #[test]
    fn screen_lock_flag_reads() {
        // Cross-check against what `ioreg` reports for the same session flag, so the test
        // holds whether or not the screen happens to be locked while it runs.
        let out = std::process::Command::new("ioreg")
            .args(["-n", "Root", "-d1", "-a"])
            .output()
            .expect("ioreg runs");
        let text = String::from_utf8_lossy(&out.stdout);
        // The value element follows the key; the flag is set when that element is <true/>.
        let expected = text
            .split("CGSSessionScreenIsLocked")
            .nth(1)
            .is_some_and(|rest| {
                let value = rest.split("<key>").next().unwrap_or("");
                value.contains("<true/>")
            });
        assert_eq!(super::is_locked(), expected);
    }
}
