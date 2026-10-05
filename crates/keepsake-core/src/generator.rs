use rand::{rngs::OsRng, seq::SliceRandom, Rng};

use crate::{Error, Result};

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>?/~";
const AMBIGUOUS: &str = "Il1O0o";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswordOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub avoid_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PassphraseOptions {
    pub words: usize,
    pub separator: String,
    pub capitalize: bool,
    pub include_number: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            words: 5,
            separator: "-".into(),
            capitalize: false,
            include_number: false,
        }
    }
}

/// Random password with at least one character from every enabled class.
pub fn password(opts: &PasswordOptions) -> Result<String> {
    if !(8..=100).contains(&opts.length) {
        return Err(Error::Invalid("password length must be 8-100".into()));
    }
    let classes: Vec<Vec<char>> = [
        (opts.lowercase, LOWER),
        (opts.uppercase, UPPER),
        (opts.digits, DIGITS),
        (opts.symbols, SYMBOLS),
    ]
    .into_iter()
    .filter(|(enabled, _)| *enabled)
    .map(|(_, set)| {
        set.chars()
            .filter(|c| !(opts.avoid_ambiguous && AMBIGUOUS.contains(*c)))
            .collect()
    })
    .collect();
    if classes.is_empty() {
        return Err(Error::Invalid("enable at least one character set".into()));
    }
    let all: Vec<char> = classes.concat();
    let mut rng = OsRng;
    let mut out: Vec<char> = classes
        .iter()
        .map(|set| *set.choose(&mut rng).expect("non-empty set"))
        .collect();
    while out.len() < opts.length {
        out.push(*all.choose(&mut rng).expect("non-empty set"));
    }
    out.shuffle(&mut rng);
    Ok(out.into_iter().collect())
}

/// Random words from the EFF long wordlist.
pub fn passphrase(opts: &PassphraseOptions) -> Result<String> {
    if !(3..=10).contains(&opts.words) {
        return Err(Error::Invalid("passphrase must have 3-10 words".into()));
    }
    let words = crate::wordlist::words();
    let mut rng = OsRng;
    let mut parts: Vec<String> = (0..opts.words)
        .map(|_| {
            let word = *words.choose(&mut rng).expect("wordlist is not empty");
            if opts.capitalize {
                capitalize(word)
            } else {
                word.to_owned()
            }
        })
        .collect();
    if opts.include_number {
        let i = rng.gen_range(0..parts.len());
        let digit = char::from(b'0' + rng.gen_range(0..10u8));
        parts[i].push(digit);
    }
    Ok(parts.join(&opts.separator))
}

fn capitalize(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    #[test]
    fn default_password_has_every_class() {
        for _ in 0..200 {
            let p = password(&PasswordOptions::default()).unwrap();
            assert_eq!(p.chars().count(), 20);
            assert!(p.chars().any(|c| c.is_ascii_lowercase()));
            assert!(p.chars().any(|c| c.is_ascii_uppercase()));
            assert!(p.chars().any(|c| c.is_ascii_digit()));
            assert!(p.chars().any(|c| SYMBOLS.contains(c)));
        }
    }

    #[test]
    fn respects_disabled_classes_and_ambiguous_filter() {
        let opts = PasswordOptions {
            length: 64,
            symbols: false,
            uppercase: false,
            avoid_ambiguous: true,
            ..PasswordOptions::default()
        };
        for _ in 0..100 {
            let p = password(&opts).unwrap();
            assert!(p
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
            assert!(!p.chars().any(|c| AMBIGUOUS.contains(c)));
        }
    }

    #[test]
    fn rejects_bad_options() {
        let none = PasswordOptions {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            ..PasswordOptions::default()
        };
        assert!(matches!(password(&none), Err(Error::Invalid(_))));
        for length in [7, 101] {
            let opts = PasswordOptions {
                length,
                ..PasswordOptions::default()
            };
            assert!(matches!(password(&opts), Err(Error::Invalid(_))));
        }
    }

    /// Smoke test against modulo bias: 16000 digits, each should appear ~1600 times.
    #[test]
    fn digits_are_roughly_uniform() {
        let opts = PasswordOptions {
            length: 8,
            lowercase: false,
            uppercase: false,
            symbols: false,
            ..PasswordOptions::default()
        };
        let mut counts = [0u32; 10];
        for _ in 0..2000 {
            for c in password(&opts).unwrap().chars() {
                counts[c.to_digit(10).unwrap() as usize] += 1;
            }
        }
        for (digit, n) in counts.iter().enumerate() {
            assert!(
                (1400..=1800).contains(n),
                "digit {digit} appeared {n} times"
            );
        }
    }

    #[test]
    fn passphrase_uses_wordlist_and_separator() {
        // EFF words may contain '-', so split on a separator that never appears in them.
        let opts = PassphraseOptions {
            words: 5,
            separator: " ".into(),
            capitalize: false,
            include_number: false,
        };
        let p = passphrase(&opts).unwrap();
        let parts: Vec<_> = p.split(' ').collect();
        assert_eq!(parts.len(), 5);
        assert!(parts.iter().all(|w| crate::wordlist::words().contains(w)));
    }

    #[test]
    fn passphrase_capitalizes_and_adds_one_digit() {
        let opts = PassphraseOptions {
            words: 4,
            separator: ".".into(),
            capitalize: true,
            include_number: true,
        };
        let p = passphrase(&opts).unwrap();
        let parts: Vec<_> = p.split('.').collect();
        assert_eq!(parts.len(), 4);
        assert!(parts
            .iter()
            .all(|w| w.chars().next().unwrap().is_ascii_uppercase()));
        assert_eq!(p.chars().filter(|c| c.is_ascii_digit()).count(), 1);
    }

    #[test]
    fn passphrase_word_count_bounds() {
        for words in [2, 11] {
            let opts = PassphraseOptions {
                words,
                ..PassphraseOptions::default()
            };
            assert!(matches!(passphrase(&opts), Err(Error::Invalid(_))));
        }
    }
}
