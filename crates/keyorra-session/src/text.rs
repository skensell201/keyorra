//! Wording helpers for the strings the app shows.

use std::fmt::Display;

/// "1 change", "3 changes": a count with its noun in the right number.
pub(crate) fn plural<T: Display + PartialEq + From<u8>>(count: T, one: &str, many: &str) -> String {
    if count == T::from(1) {
        format!("{count} {one}")
    } else {
        format!("{count} {many}")
    }
}

#[cfg(test)]
mod tests {
    use super::plural;

    #[test]
    fn counts_take_the_right_number() {
        assert_eq!(plural(1usize, "change", "changes"), "1 change");
        assert_eq!(plural(0u64, "change", "changes"), "0 changes");
        assert_eq!(
            plural(3u32, "conflict copy", "conflict copies"),
            "3 conflict copies"
        );
    }
}
