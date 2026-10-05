/// Locks the vault after a period without user activity. Times are Unix seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AutoLock {
    timeout_secs: u64,
    last_activity: u64,
}

impl AutoLock {
    pub const DEFAULT_TIMEOUT_SECS: u64 = 10 * 60;

    pub fn new(timeout_secs: u64, now: u64) -> Self {
        Self {
            timeout_secs,
            last_activity: now,
        }
    }

    pub fn set_timeout(&mut self, timeout_secs: u64) {
        self.timeout_secs = timeout_secs;
    }

    pub fn touch(&mut self, now: u64) {
        self.last_activity = self.last_activity.max(now);
    }

    pub fn is_due(&self, now: u64) -> bool {
        now.saturating_sub(self.last_activity) >= self.timeout_secs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn due_only_after_the_timeout() {
        let lock = AutoLock::new(60, 1_000);
        assert!(!lock.is_due(1_059));
        assert!(lock.is_due(1_060));
    }

    #[test]
    fn touch_postpones_and_never_moves_back() {
        let mut lock = AutoLock::new(60, 1_000);
        lock.touch(1_050);
        assert!(!lock.is_due(1_100));
        lock.touch(900);
        assert!(
            !lock.is_due(1_100),
            "an older timestamp must not shorten the timer"
        );
        assert!(lock.is_due(1_110));
    }

    #[test]
    fn timeout_can_change() {
        let mut lock = AutoLock::new(60, 1_000);
        lock.set_timeout(300);
        assert!(!lock.is_due(1_299));
        assert!(lock.is_due(1_300));
    }

    #[test]
    fn clock_going_backwards_does_not_lock() {
        let lock = AutoLock::new(60, 1_000);
        assert!(!lock.is_due(10));
    }
}
