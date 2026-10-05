/// Slows down password guessing: a few free attempts, then a doubling wait. Times are Unix seconds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UnlockThrottle {
    failures: u32,
    blocked_until: u64,
}

impl UnlockThrottle {
    pub const FREE_ATTEMPTS: u32 = 5;
    pub const MAX_DELAY_SECS: u64 = 300;

    /// `Ok` if an attempt is allowed now, otherwise the seconds to wait.
    pub fn check(&self, now: u64) -> Result<(), u64> {
        if now < self.blocked_until {
            Err(self.blocked_until - now)
        } else {
            Ok(())
        }
    }

    pub fn record_failure(&mut self, now: u64) {
        self.failures = self.failures.saturating_add(1);
        if self.failures >= Self::FREE_ATTEMPTS {
            let exponent = self.failures - Self::FREE_ATTEMPTS;
            let delay = 1u64
                .checked_shl(exponent)
                .unwrap_or(u64::MAX)
                .min(Self::MAX_DELAY_SECS);
            self.blocked_until = now.saturating_add(delay);
        }
    }

    pub fn record_success(&mut self) {
        *self = Self::default();
    }

    pub fn failures(&self) -> u32 {
        self.failures
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_attempts_then_doubling_delay() {
        let mut t = UnlockThrottle::default();
        for _ in 0..UnlockThrottle::FREE_ATTEMPTS - 1 {
            t.record_failure(100);
            assert_eq!(t.check(100), Ok(()));
        }
        t.record_failure(100); // 5th failure
        assert_eq!(t.check(100), Err(1));
        assert_eq!(t.check(101), Ok(()));
        t.record_failure(101); // 6th
        assert_eq!(t.check(101), Err(2));
        t.record_failure(103); // 7th
        assert_eq!(t.check(103), Err(4));
    }

    #[test]
    fn delay_is_capped() {
        let mut t = UnlockThrottle::default();
        for _ in 0..80 {
            t.record_failure(0);
        }
        assert_eq!(t.check(0), Err(UnlockThrottle::MAX_DELAY_SECS));
    }

    #[test]
    fn success_resets() {
        let mut t = UnlockThrottle::default();
        for _ in 0..10 {
            t.record_failure(0);
        }
        t.record_success();
        assert_eq!(t.check(0), Ok(()));
        assert_eq!(t.failures(), 0);
    }
}
