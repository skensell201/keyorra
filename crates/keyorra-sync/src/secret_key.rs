//! The Secret Key: 128 random bits mixed into the key that protects the synced header.
//!
//! Shown as `ID-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XC`: a 4-character id (20 random bits,
//! independent of the key, safe to publish), 26 Crockford base32 digits carrying the 128 key
//! bits (big-endian, the top 2 bits of the first digit zero), and one Crockford check
//! character (the key as an integer mod 37). Parsing ignores case and hyphens and reads
//! `I`/`L` as `1` and `O` as `0`.

use rand::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::error::{malformed, Result};

const DIGITS: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CHECK: &[u8; 37] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U";
const ID_LEN: usize = 4;
const KEY_DIGITS: usize = 26;

pub struct SecretKey(Zeroizing<[u8; 16]>);

impl SecretKey {
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// A fresh key and its independent public id.
    pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> (SecretKey, String) {
        let mut bytes = Zeroizing::new([0u8; 16]);
        rng.fill_bytes(&mut bytes[..]);
        let id = (0..ID_LEN)
            .map(|_| DIGITS[(rng.next_u32() & 31) as usize] as char)
            .collect();
        (SecretKey(bytes), id)
    }

    /// The human form, e.g. for the Emergency Kit.
    pub fn display(&self, id: &str) -> Zeroizing<String> {
        let value = u128::from_be_bytes(*self.0);
        let mut chars: Vec<u8> = (0..KEY_DIGITS)
            .map(|i| DIGITS[((value >> (5 * (KEY_DIGITS - 1 - i))) & 31) as usize])
            .collect();
        chars.push(CHECK[(value % 37) as usize]);
        let mut out = Zeroizing::new(id.to_owned());
        for group in chars.chunks(5) {
            out.push('-');
            out.push_str(std::str::from_utf8(group).expect("ASCII"));
        }
        chars.iter_mut().for_each(|c| *c = 0);
        out
    }

    /// Parses [`display`](Self::display) output; returns the id and the key.
    pub fn parse(text: &str) -> Result<(String, SecretKey)> {
        let chars: Zeroizing<Vec<u8>> = Zeroizing::new(
            text.bytes()
                .filter(|&b| b != b'-' && !b.is_ascii_whitespace())
                .map(|b| match b.to_ascii_uppercase() {
                    b'I' | b'L' => b'1',
                    b'O' => b'0',
                    other => other,
                })
                .collect(),
        );
        if chars.len() != ID_LEN + KEY_DIGITS + 1 {
            return Err(malformed("secret key length"));
        }
        let digit = |c: u8| {
            DIGITS
                .iter()
                .position(|&d| d == c)
                .ok_or_else(|| malformed("secret key character"))
        };
        for &c in &chars[..ID_LEN] {
            digit(c)?;
        }
        let mut value: u128 = 0;
        for &c in &chars[ID_LEN..ID_LEN + KEY_DIGITS] {
            let d = digit(c)? as u128;
            value = value
                .checked_mul(32)
                .and_then(|v| v.checked_add(d))
                .ok_or_else(|| malformed("secret key out of range"))?;
        }
        if chars[ID_LEN + KEY_DIGITS] != CHECK[(value % 37) as usize] {
            return Err(malformed("secret key check character"));
        }
        let id = String::from_utf8(chars[..ID_LEN].to_vec()).expect("ASCII");
        Ok((id, SecretKey::from_bytes(value.to_be_bytes())))
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    fn sample() -> SecretKey {
        SecretKey::from_bytes(*b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f")
    }

    #[test]
    fn display_has_the_documented_shape() {
        // Cross-checked with an independent Python encoder.
        let shown = sample().display("A3K7");
        assert_eq!(&*shown, "A3K7-00041-06105-0R3GG-28A1C-60T3G-F6");
        let groups: Vec<_> = shown.split('-').map(str::len).collect();
        assert_eq!(groups, [4, 5, 5, 5, 5, 5, 2]);
    }

    #[test]
    fn parse_round_trips_and_forgives_case_and_lookalikes() {
        let shown = sample().display("A3K7");
        let (id, key) = SecretKey::parse(&shown).unwrap();
        assert_eq!(id, "A3K7");
        assert_eq!(key.as_bytes(), sample().as_bytes());
        let sloppy = shown.to_lowercase().replace('1', "l").replace('0', "o");
        let (_, key) = SecretKey::parse(&sloppy).unwrap();
        assert_eq!(key.as_bytes(), sample().as_bytes());
    }

    #[test]
    fn parse_rejects_typos() {
        let shown = sample().display("A3K7").to_string();
        let mut typo = shown.clone().into_bytes();
        typo[6] = if typo[6] == b'2' { b'3' } else { b'2' };
        let typo = String::from_utf8(typo).unwrap();
        for bad in [
            &typo[..],
            &shown[..shown.len() - 1],
            "A3K7",
            &format!("{shown}0"),
        ] {
            assert!(
                matches!(SecretKey::parse(bad), Err(Error::Malformed(_))),
                "{bad}"
            );
        }
        // A first digit above 7 would need more than 128 bits.
        let too_big = format!("A3K7-8{}", &shown[6..]);
        assert!(SecretKey::parse(&too_big).is_err());
    }

    #[test]
    fn extreme_keys_round_trip() {
        for bytes in [[0u8; 16], [0xff; 16]] {
            let shown = SecretKey::from_bytes(bytes).display("0000");
            assert_eq!(SecretKey::parse(&shown).unwrap().1.as_bytes(), &bytes);
        }
    }

    #[test]
    fn generate_gives_fresh_keys_and_ids_from_the_alphabet() {
        let mut rng = rand::rngs::OsRng;
        let (a, id) = SecretKey::generate(&mut rng);
        let (b, _) = SecretKey::generate(&mut rng);
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert_eq!(id.len(), 4);
        assert!(id.bytes().all(|c| DIGITS.contains(&c)));
    }

    #[test]
    fn debug_hides_the_key() {
        assert_eq!(format!("{:?}", sample()), "SecretKey(..)");
    }
}
