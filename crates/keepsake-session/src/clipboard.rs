use sha2::{Digest, Sha256};

/// Remembers what we put on the clipboard (only as a hash) so we clear it later — and only if it
/// still holds our copy. Times are Unix seconds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClipboardGuard {
    pending: Option<Pending>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Pending {
    digest: [u8; 32],
    clear_at: u64,
}

impl ClipboardGuard {
    pub const DEFAULT_CLEAR_SECS: u64 = 90;

    pub fn copied(&mut self, text: &str, now: u64, clear_after: u64) {
        self.pending = Some(Pending {
            digest: digest(text),
            clear_at: now.saturating_add(clear_after),
        });
    }

    pub fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Call periodically with the clipboard's current text; `true` means clear it now.
    pub fn should_clear(&mut self, now: u64, current: Option<&str>) -> bool {
        let Some(pending) = self.pending else {
            return false;
        };
        match current {
            Some(text) if digest(text) == pending.digest => {
                if now >= pending.clear_at {
                    self.pending = None;
                    true
                } else {
                    false
                }
            }
            _ => {
                self.pending = None;
                false
            }
        }
    }
}

fn digest(text: &str) -> [u8; 32] {
    Sha256::digest(text.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clears_our_copy_when_time_is_up() {
        let mut g = ClipboardGuard::default();
        g.copied("hunter2", 100, 90);
        assert!(g.is_pending());
        assert!(!g.should_clear(189, Some("hunter2")));
        assert!(g.should_clear(190, Some("hunter2")));
        assert!(!g.is_pending());
        assert!(!g.should_clear(500, Some("hunter2")), "only once");
    }

    #[test]
    fn leaves_the_clipboard_alone_if_the_user_copied_something_else() {
        let mut g = ClipboardGuard::default();
        g.copied("hunter2", 100, 90);
        assert!(!g.should_clear(120, Some("my own text")));
        assert!(!g.is_pending(), "forget once it's no longer ours");
        assert!(!g.should_clear(300, Some("hunter2")));
    }

    #[test]
    fn empty_clipboard_cancels() {
        let mut g = ClipboardGuard::default();
        g.copied("hunter2", 100, 90);
        assert!(!g.should_clear(300, None));
        assert!(!g.is_pending());
    }

    #[test]
    fn a_new_copy_replaces_the_old_one() {
        let mut g = ClipboardGuard::default();
        g.copied("first", 100, 90);
        g.copied("second", 150, 90);
        assert!(!g.should_clear(200, Some("second")));
        assert!(g.should_clear(240, Some("second")));
    }
}
