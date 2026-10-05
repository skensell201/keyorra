//! Version vectors: per record, how many writes of each device a version includes.

use std::collections::BTreeMap;

use crate::DeviceId;

pub type Vector = BTreeMap<DeviceId, u64>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Causality {
    Equal,
    /// `a` happened before `b` (`b` dominates).
    Before,
    /// `a` dominates `b`.
    After,
    Concurrent,
}

pub fn compare(a: &Vector, b: &Vector) -> Causality {
    let (mut a_more, mut b_more) = (false, false);
    for device in a.keys().chain(b.keys()) {
        let (x, y) = (
            a.get(device).copied().unwrap_or(0),
            b.get(device).copied().unwrap_or(0),
        );
        a_more |= x > y;
        b_more |= y > x;
    }
    match (a_more, b_more) {
        (false, false) => Causality::Equal,
        (false, true) => Causality::Before,
        (true, false) => Causality::After,
        (true, true) => Causality::Concurrent,
    }
}

/// Element-wise maximum.
pub fn join<'a>(vectors: impl IntoIterator<Item = &'a Vector>) -> Vector {
    let mut out = Vector::new();
    for v in vectors {
        for (device, n) in v {
            let e = out.entry(*device).or_insert(0);
            *e = (*e).max(*n);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: DeviceId = [1; 16];
    const B: DeviceId = [2; 16];

    fn v(entries: &[(DeviceId, u64)]) -> Vector {
        entries.iter().copied().collect()
    }

    #[test]
    fn compare_covers_all_four_cases() {
        assert_eq!(compare(&v(&[(A, 1)]), &v(&[(A, 1)])), Causality::Equal);
        assert_eq!(compare(&v(&[(A, 1)]), &v(&[(A, 2)])), Causality::Before);
        assert_eq!(
            compare(&v(&[(A, 1), (B, 1)]), &v(&[(A, 1)])),
            Causality::After
        );
        assert_eq!(
            compare(&v(&[(A, 2)]), &v(&[(A, 1), (B, 1)])),
            Causality::Concurrent
        );
        assert_eq!(compare(&v(&[]), &v(&[(B, 1)])), Causality::Before);
    }

    #[test]
    fn join_takes_the_maximum_per_device() {
        let j = join([&v(&[(A, 2)]), &v(&[(A, 1), (B, 3)])]);
        assert_eq!(j, v(&[(A, 2), (B, 3)]));
        assert_eq!(compare(&j, &v(&[(A, 2)])), Causality::After);
    }
}
