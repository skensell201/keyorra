//! Length hiding: `data ‖ 0x80 ‖ 0x00…` up to a Padmé length (Nikitin et al., "Reducing
//! Metadata Leakage from Encrypted Files and Communication with PURBs", PETS 2019), never
//! below [`MIN_PADDED`]. Padmé leaks O(log log L) bits of the length and adds at most ~12%.

use crate::error::{malformed, Result};

pub const MIN_PADDED: usize = 1024;
const MARKER: u8 = 0x80;

/// The Padmé length for `len` (unchanged below 2).
pub fn padme(len: u64) -> u64 {
    if len < 2 {
        return len;
    }
    let e = 63 - u64::from(len.leading_zeros()); // floor(log2 len)
    let s = 64 - u64::from(e.leading_zeros()); // floor(log2 e) + 1
    let mask = (1u64 << (e - s)) - 1;
    (len + mask) & !mask
}

/// Total padded size for `content_len` bytes of content (the marker byte included).
pub fn padded_len(content_len: usize) -> usize {
    let needed = content_len + 1;
    (padme(needed as u64) as usize).max(MIN_PADDED)
}

pub fn pad(data: &[u8]) -> Vec<u8> {
    let total = padded_len(data.len());
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(data);
    out.push(MARKER);
    out.resize(total, 0);
    out
}

/// Inverse of [`pad`]; rejects any other padding (wrong marker, wrong total length).
pub fn unpad(padded: &[u8]) -> Result<&[u8]> {
    let marker = padded
        .iter()
        .rposition(|&b| b != 0)
        .ok_or_else(|| malformed("padding"))?;
    if padded[marker] != MARKER || padded_len(marker) != padded.len() {
        return Err(malformed("padding"));
    }
    Ok(&padded[..marker])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    #[test]
    fn padme_matches_hand_computed_values() {
        // L = 1025: E = 10, S = 4, mask = 2^6 - 1 → 1088.
        for (len, expected) in [
            (0, 0),
            (1, 1),
            (2, 2),
            (9, 10),
            (100, 104),
            (1025, 1088),
            (4_194_305, 4_325_376),
            (1 << 20, 1 << 20),
        ] {
            assert_eq!(padme(len), expected, "padme({len})");
        }
    }

    #[test]
    fn padme_overhead_is_at_most_12_percent_and_monotonic() {
        let mut prev = 0;
        for len in 2..200_000u64 {
            let p = padme(len);
            assert!(p >= len && p >= prev);
            assert!((p - len) * 100 <= len * 12, "len {len} → {p}");
            prev = p;
        }
    }

    #[test]
    fn small_inputs_pad_to_the_minimum() {
        assert_eq!(pad(b"").len(), MIN_PADDED);
        assert_eq!(pad(&[1; 1023]).len(), MIN_PADDED);
        assert_eq!(pad(&[1; 1024]).len(), padme(1025) as usize);
    }

    #[test]
    fn round_trips_including_trailing_zeros_in_the_data() {
        for data in [&b""[..], b"x", &[0u8; 10], &[0x80; 5], &[7u8; 5000]] {
            assert_eq!(unpad(&pad(data)).unwrap(), data);
        }
    }

    #[test]
    fn rejects_foreign_padding() {
        let mut p = pad(b"abc");
        p[3] = 0x81;
        assert!(matches!(unpad(&p), Err(Error::Malformed(_))));
        assert!(matches!(unpad(&[0u8; 1024]), Err(Error::Malformed(_))));
        let mut short = pad(b"abc");
        short.truncate(1000);
        assert!(matches!(unpad(&short), Err(Error::Malformed(_))));
        let mut long = pad(b"abc");
        long.push(0);
        assert!(matches!(unpad(&long), Err(Error::Malformed(_))));
    }
}
