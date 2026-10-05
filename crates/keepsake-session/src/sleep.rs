/// Notices that the Mac slept. Housekeeping passes two clocks: wall time, and a monotonic
/// "awake" clock that does not advance during sleep (on macOS `Instant` is CLOCK_UPTIME_RAW).
/// If wall time moved on much more than awake time, the machine was suspended. A long wait
/// for a lock advances both clocks equally and is not sleep.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SleepDetector {
    last: Option<(u64, u64)>,
}

impl SleepDetector {
    pub const GAP_SECS: u64 = 60;

    /// Records a tick (`wall` and `awake` in seconds); `true` if the wall clock gained more
    /// than `GAP_SECS` on the awake clock since the previous one.
    pub fn observe(&mut self, wall: u64, awake: u64) -> bool {
        let slept = self.last.is_some_and(|(prev_wall, prev_awake)| {
            let wall_gap = wall.saturating_sub(prev_wall);
            let awake_gap = awake.saturating_sub(prev_awake);
            wall_gap.saturating_sub(awake_gap) > Self::GAP_SECS
        });
        self.last = Some((wall, awake));
        slept
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notices_wall_time_running_ahead_of_awake_time() {
        let mut d = SleepDetector::default();
        assert!(!d.observe(1_000, 10), "first observation");
        assert!(!d.observe(1_002, 12));
        assert!(
            !d.observe(1_002 + 5_000, 12 + 5_000),
            "both clocks moved: just busy"
        );
        assert!(!d.observe(1_002 + 5_000 + SleepDetector::GAP_SECS, 12 + 5_000));
        let (w, a) = (1_002 + 5_000 + SleepDetector::GAP_SECS, 12 + 5_000);
        assert!(d.observe(w + SleepDetector::GAP_SECS + 1 + 2, a + 2));
        assert!(!d.observe(500, 1), "clock going backwards is not sleep");
    }
}
