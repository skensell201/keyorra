use std::sync::OnceLock;

static RAW: &str = include_str!("../assets/eff_large_wordlist.txt");

/// The EFF long wordlist (7776 words), parsed once.
pub fn words() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| {
        RAW.lines()
            .filter_map(|line| line.split_whitespace().nth(1))
            .collect()
    })
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_all_eff_words() {
        let w = words();
        assert_eq!(w.len(), 7776);
        assert_eq!(w[0], "abacus");
        assert_eq!(w[7775], "zoom");
    }
}
