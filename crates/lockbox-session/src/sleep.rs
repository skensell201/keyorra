/// Notices that the Mac slept: housekeeping ticks every couple of seconds, so a big jump in
/// wall-clock time between two ticks means the process was suspended.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SleepDetector {
    last: Option<u64>,
}

impl SleepDetector {
    pub const GAP_SECS: u64 = 60;

    /// Records a tick; `true` if more than `GAP_SECS` passed since the previous one.
    pub fn observe(&mut self, now: u64) -> bool {
        let slept = self
            .last
            .is_some_and(|last| now > last && now - last > Self::GAP_SECS);
        self.last = Some(now);
        slept
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notices_a_jump_in_wall_clock_time() {
        let mut d = SleepDetector::default();
        assert!(!d.observe(1_000), "first observation");
        assert!(!d.observe(1_002));
        assert!(!d.observe(1_002 + SleepDetector::GAP_SECS));
        assert!(d.observe(1_003 + 2 * SleepDetector::GAP_SECS));
        assert!(!d.observe(500), "clock going backwards is not sleep");
    }
}
