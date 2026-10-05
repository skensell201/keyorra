//! Hybrid logical clock: `hlc = unix_ms << 16 | counter`. It follows wall time when clocks are
//! sane and still moves forward when they are not. The wall time is always passed in.

/// A remote clock more than this far ahead of ours is not adopted (spec §3.3).
pub const MAX_AHEAD_MS: u64 = 5 * 60 * 1000;
const MAX_MS: u64 = (1 << 48) - 1;

pub fn pack(unix_ms: u64, counter: u16) -> u64 {
    assert!(unix_ms <= MAX_MS, "unix milliseconds beyond 48 bits");
    unix_ms << 16 | u64::from(counter)
}

pub fn physical_ms(hlc: u64) -> u64 {
    hlc >> 16
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observed {
    /// Folded into the local clock.
    Adopted,
    /// More than [`MAX_AHEAD_MS`] ahead of the local wall clock: not adopted; worth a log line.
    TooFarAhead { ahead_ms: u64 },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Hlc {
    last: u64,
}

impl Hlc {
    pub fn new(last: u64) -> Hlc {
        Hlc { last }
    }

    pub fn last(&self) -> u64 {
        self.last
    }

    /// The timestamp for a new local write.
    pub fn tick(&mut self, wall_ms: u64) -> u64 {
        let next = pack(wall_ms.min(MAX_MS), 0).max(self.last + 1);
        self.last = next;
        next
    }

    /// Takes a remote timestamp into account, unless it is too far in the future.
    pub fn observe(&mut self, remote: u64, wall_ms: u64) -> Observed {
        let remote_ms = physical_ms(remote);
        if remote_ms > wall_ms.saturating_add(MAX_AHEAD_MS) {
            return Observed::TooFarAhead {
                ahead_ms: remote_ms - wall_ms,
            };
        }
        self.last = self.last.max(remote);
        Observed::Adopted
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: u64 = 1_790_000_000_000;

    #[test]
    fn tick_follows_wall_time() {
        let mut c = Hlc::default();
        assert_eq!(c.tick(T), pack(T, 0));
        assert_eq!(c.tick(T + 5), pack(T + 5, 0));
    }

    #[test]
    fn tick_never_goes_back_when_the_clock_does() {
        let mut c = Hlc::default();
        let a = c.tick(T);
        let b = c.tick(T);
        let d = c.tick(T - 60_000);
        assert!(a < b && b < d);
        assert_eq!(b, pack(T, 1));
        assert_eq!(physical_ms(d), T);
    }

    #[test]
    fn observe_moves_the_clock_forward() {
        let mut c = Hlc::default();
        c.tick(T);
        assert_eq!(c.observe(pack(T + 1_000, 7), T), Observed::Adopted);
        assert_eq!(c.tick(T), pack(T + 1_000, 8));
    }

    #[test]
    fn observe_refuses_timestamps_too_far_ahead() {
        let mut c = Hlc::default();
        c.tick(T);
        let before = c.last();
        let ahead = pack(T + MAX_AHEAD_MS + 1, 0);
        assert_eq!(
            c.observe(ahead, T),
            Observed::TooFarAhead {
                ahead_ms: MAX_AHEAD_MS + 1
            }
        );
        assert_eq!(c.last(), before);
        assert_eq!(c.observe(pack(T + MAX_AHEAD_MS, 0), T), Observed::Adopted);
    }

    #[test]
    fn observe_ignores_the_past() {
        let mut c = Hlc::default();
        c.tick(T);
        assert_eq!(c.observe(pack(T - 10, 0), T), Observed::Adopted);
        assert_eq!(c.last(), pack(T, 0));
    }
}
