//! Deterministic CBOR (RFC 8949 §4.2.1) for the small subset the sync formats use:
//! unsigned integers, byte strings, text strings, arrays, maps, booleans and null.
//!
//! Encoding is canonical: shortest heads, definite lengths, map entries sorted by the bytes of
//! their encoded keys. Decoding is strict and accepts *only* canonical input, so every value
//! has exactly one encoding and hashing re-encoded data equals hashing the received bytes.
//! Not supported on purpose: negative integers, floats, tags, indefinite lengths.

use crate::error::{malformed, Result};

const MAX_DEPTH: usize = 32;
/// Containers never reserve more than this many elements up front, whatever length they
/// claim: the claim is bounded by the input size, but an element is much larger than the
/// byte that announces it.
const MAX_PREALLOC: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Uint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// Entries in any order; [`encode`] sorts them. Duplicate keys are a programming error.
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
}

impl Value {
    pub fn bytes(b: impl AsRef<[u8]>) -> Value {
        Value::Bytes(b.as_ref().to_vec())
    }

    pub fn text(s: impl Into<String>) -> Value {
        Value::Text(s.into())
    }

    /// A map with text keys, the shape every sync structure uses.
    pub fn map(entries: Vec<(&str, Value)>) -> Value {
        Value::Map(
            entries
                .into_iter()
                .map(|(k, v)| (Value::text(k), v))
                .collect(),
        )
    }

    pub fn as_uint(&self) -> Result<u64> {
        match self {
            Value::Uint(n) => Ok(*n),
            _ => Err(malformed("expected unsigned integer")),
        }
    }

    pub fn as_u32(&self) -> Result<u32> {
        u32::try_from(self.as_uint()?).map_err(|_| malformed("integer exceeds u32"))
    }

    pub fn as_bytes(&self) -> Result<&[u8]> {
        match self {
            Value::Bytes(b) => Ok(b),
            _ => Err(malformed("expected byte string")),
        }
    }

    pub fn as_array_of<const N: usize>(&self) -> Result<[u8; N]> {
        self.as_bytes()?
            .try_into()
            .map_err(|_| malformed(format!("expected {N} bytes")))
    }

    pub fn as_text(&self) -> Result<&str> {
        match self {
            Value::Text(s) => Ok(s),
            _ => Err(malformed("expected text")),
        }
    }

    pub fn as_bool(&self) -> Result<bool> {
        match self {
            Value::Bool(b) => Ok(*b),
            _ => Err(malformed("expected bool")),
        }
    }

    pub fn as_list(&self) -> Result<&[Value]> {
        match self {
            Value::Array(a) => Ok(a),
            _ => Err(malformed("expected array")),
        }
    }

    pub fn as_map(&self) -> Result<&[(Value, Value)]> {
        match self {
            Value::Map(m) => Ok(m),
            _ => Err(malformed("expected map")),
        }
    }

    /// A text-keyed map that must have exactly the keys `names` (in any order).
    pub fn fields(&self, names: &[&str]) -> Result<Fields<'_>> {
        let map = self.as_map()?;
        if map.len() != names.len() {
            return Err(malformed(format!("expected {} fields", names.len())));
        }
        for (k, _) in map {
            let k = k.as_text()?;
            if !names.contains(&k) {
                return Err(malformed(format!("unexpected field {k}")));
            }
        }
        Ok(Fields(map))
    }
}

/// Lookup into a map checked by [`Value::fields`].
pub struct Fields<'a>(&'a [(Value, Value)]);

impl<'a> Fields<'a> {
    pub fn get(&self, name: &str) -> Result<&'a Value> {
        self.0
            .iter()
            .find(|(k, _)| matches!(k, Value::Text(t) if t == name))
            .map(|(_, v)| v)
            .ok_or_else(|| malformed(format!("missing field {name}")))
    }
}

pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write(value, &mut out);
    out
}

fn head(major: u8, n: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    if n < 24 {
        out.push(m | n as u8);
    } else if n <= 0xff {
        out.extend_from_slice(&[m | 24, n as u8]);
    } else if n <= 0xffff {
        out.push(m | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= 0xffff_ffff {
        out.push(m | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

fn write(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Uint(n) => head(0, *n, out),
        Value::Bytes(b) => {
            head(2, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            head(3, s.len() as u64, out);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(items) => {
            head(4, items.len() as u64, out);
            for item in items {
                write(item, out);
            }
        }
        Value::Map(entries) => {
            let mut encoded: Vec<(Vec<u8>, &Value)> =
                entries.iter().map(|(k, v)| (encode(k), v)).collect();
            encoded.sort_by(|a, b| a.0.cmp(&b.0));
            for pair in encoded.windows(2) {
                assert!(pair[0].0 != pair[1].0, "duplicate CBOR map key");
            }
            head(5, encoded.len() as u64, out);
            for (k, v) in encoded {
                out.extend_from_slice(&k);
                write(v, out);
            }
        }
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Null => out.push(0xf6),
    }
}

/// [`decode`] for input from an unauthenticated source: input longer than `max_len` bytes is
/// refused before any parsing.
pub fn decode_limited(bytes: &[u8], max_len: usize) -> Result<Value> {
    if bytes.len() > max_len {
        return Err(malformed("CBOR input larger than allowed"));
    }
    decode(bytes)
}

/// Decodes exactly one canonical value; trailing bytes are an error.
pub fn decode(bytes: &[u8]) -> Result<Value> {
    let mut reader = Reader { bytes, pos: 0 };
    let value = reader.value(0)?;
    if reader.pos != bytes.len() {
        return Err(malformed("trailing bytes after CBOR value"));
    }
    Ok(value)
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.bytes.len())
            .ok_or_else(|| malformed("truncated CBOR"))?;
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn head(&mut self) -> Result<(u8, u8, u64)> {
        let first = self.take(1)?[0];
        let (major, info) = (first >> 5, first & 0x1f);
        let n = match info {
            0..=23 => info as u64,
            24 => {
                let n = self.take(1)?[0] as u64;
                if n < 24 {
                    return Err(malformed("non-shortest CBOR head"));
                }
                n
            }
            25 => {
                let n = u16::from_be_bytes(self.take(2)?.try_into().unwrap()) as u64;
                if n <= 0xff {
                    return Err(malformed("non-shortest CBOR head"));
                }
                n
            }
            26 => {
                let n = u32::from_be_bytes(self.take(4)?.try_into().unwrap()) as u64;
                if n <= 0xffff {
                    return Err(malformed("non-shortest CBOR head"));
                }
                n
            }
            27 => {
                let n = u64::from_be_bytes(self.take(8)?.try_into().unwrap());
                if n <= 0xffff_ffff {
                    return Err(malformed("non-shortest CBOR head"));
                }
                n
            }
            _ => return Err(malformed("indefinite or reserved CBOR length")),
        };
        Ok((major, info, n))
    }

    fn len(&self, n: u64) -> Result<usize> {
        // Every element takes at least one byte, so a length beyond the input is a lie.
        usize::try_from(n)
            .ok()
            .filter(|&n| n <= self.bytes.len() - self.pos)
            .ok_or_else(|| malformed("CBOR length exceeds input"))
    }

    fn value(&mut self, depth: usize) -> Result<Value> {
        if depth > MAX_DEPTH {
            return Err(malformed("CBOR nested too deeply"));
        }
        let (major, info, n) = self.head()?;
        match major {
            0 => Ok(Value::Uint(n)),
            2 => {
                let len = self.len(n)?;
                Ok(Value::Bytes(self.take(len)?.to_vec()))
            }
            3 => {
                let len = self.len(n)?;
                let raw = self.take(len)?.to_vec();
                String::from_utf8(raw)
                    .map(Value::Text)
                    .map_err(|_| malformed("CBOR text is not UTF-8"))
            }
            4 => {
                let len = self.len(n)?;
                let mut items = Vec::with_capacity(len.min(MAX_PREALLOC));
                for _ in 0..len {
                    items.push(self.value(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                let len = self.len(n)?;
                let mut entries = Vec::with_capacity(len.min(MAX_PREALLOC));
                let mut last_key: Option<&[u8]> = None;
                for _ in 0..len {
                    let start = self.pos;
                    let key = self.value(depth + 1)?;
                    let key_bytes = &self.bytes[start..self.pos];
                    if last_key.is_some_and(|last| last >= key_bytes) {
                        return Err(malformed("CBOR map keys not in canonical order"));
                    }
                    last_key = Some(key_bytes);
                    let value = self.value(depth + 1)?;
                    entries.push((key, value));
                }
                Ok(Value::Map(entries))
            }
            7 => match info {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                _ => Err(malformed("unsupported CBOR simple value or float")),
            },
            _ => Err(malformed("unsupported CBOR major type")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;

    fn hex(b: &[u8]) -> String {
        data_encoding::HEXLOWER.encode(b)
    }

    fn unhex(s: &str) -> Vec<u8> {
        data_encoding::HEXLOWER.decode(s.as_bytes()).unwrap()
    }

    fn uints(range: std::ops::RangeInclusive<u64>) -> Value {
        Value::Array(range.map(Value::Uint).collect())
    }

    /// RFC 8949 Appendix A, the examples inside our subset.
    #[test]
    fn rfc8949_appendix_a_examples() {
        let cases: Vec<(Value, &str)> = vec![
            (Value::Uint(0), "00"),
            (Value::Uint(23), "17"),
            (Value::Uint(24), "1818"),
            (Value::Uint(100), "1864"),
            (Value::Uint(1000), "1903e8"),
            (Value::Uint(1_000_000), "1a000f4240"),
            (Value::Uint(1_000_000_000_000), "1b000000e8d4a51000"),
            (Value::Uint(u64::MAX), "1bffffffffffffffff"),
            (Value::Bool(false), "f4"),
            (Value::Bool(true), "f5"),
            (Value::Null, "f6"),
            (Value::bytes([]), "40"),
            (Value::bytes([1, 2, 3, 4]), "4401020304"),
            (Value::text(""), "60"),
            (Value::text("a"), "6161"),
            (Value::text("IETF"), "6449455446"),
            (Value::text("\u{fc}"), "62c3bc"),
            (Value::Array(vec![]), "80"),
            (uints(1..=3), "83010203"),
            (
                Value::Array(vec![Value::Uint(1), uints(2..=3), uints(4..=5)]),
                "8301820203820405",
            ),
            (
                uints(1..=25),
                "98190102030405060708090a0b0c0d0e0f101112131415161718181819",
            ),
            (Value::Map(vec![]), "a0"),
            (
                Value::map(vec![("a", Value::Uint(1)), ("b", uints(2..=3))]),
                "a26161016162820203",
            ),
        ];
        for (value, expected) in cases {
            assert_eq!(hex(&encode(&value)), expected, "{value:?}");
            assert_eq!(decode(&unhex(expected)).unwrap(), value, "{expected}");
        }
    }

    #[test]
    fn map_keys_are_sorted_by_encoded_bytes() {
        // Shorter text keys sort first because the length is part of the encoding.
        let value = Value::map(vec![
            ("aa", Value::Uint(3)),
            ("b", Value::Uint(2)),
            ("a", Value::Uint(1)),
        ]);
        assert_eq!(hex(&encode(&value)), "a361610161620262616103");
    }

    #[test]
    #[should_panic(expected = "duplicate CBOR map key")]
    fn duplicate_keys_are_a_programming_error() {
        encode(&Value::map(vec![("a", Value::Null), ("a", Value::Null)]));
    }

    #[test]
    fn decoding_rejects_everything_non_canonical() {
        for bad in [
            "1817",       // 23 in two bytes
            "190017",     // 23 in three bytes
            "1a000000ff", // 255 in five bytes
            "1b00000000ffffffff",
            "5f4100ff",           // indefinite byte string
            "9f01ff",             // indefinite array
            "20",                 // negative integer
            "c100",               // tag
            "f93c00",             // half float
            "f7",                 // undefined
            "a2616201616101",     // keys out of order
            "a2616101616102",     // duplicate key
            "62c328",             // invalid UTF-8
            "4401",               // truncated
            "0000",               // trailing byte
            "9bffffffffffffffff", // absurd length
        ] {
            assert!(
                matches!(decode(&unhex(bad)), Err(Error::Malformed(_))),
                "{bad} should be rejected"
            );
        }
    }

    #[test]
    fn decoding_limits_nesting() {
        let mut bytes = vec![0x81; 40];
        bytes.push(0x00);
        assert!(matches!(decode(&bytes), Err(Error::Malformed(_))));
    }

    #[test]
    fn length_bombs_do_not_reserve_memory_or_pass() {
        // 30 nested arrays, each claiming as many elements as there are bytes left, then
        // nothing to back the claims.
        let total = 200_000usize;
        let mut bytes = Vec::new();
        for _ in 0..30 {
            let left = (total - bytes.len() - 5) as u32;
            bytes.push(0x9a);
            bytes.extend_from_slice(&left.to_be_bytes());
        }
        bytes.resize(total, 0x80);
        assert!(matches!(decode(&bytes), Err(Error::Malformed(_))));
        // The same for a map and for a huge byte string claim.
        let mut map = vec![0xba];
        map.extend_from_slice(&1_000_000u32.to_be_bytes());
        map.resize(1_000_005, 0);
        assert!(matches!(decode(&map), Err(Error::Malformed(_))));
    }

    #[test]
    fn limited_decode_refuses_oversized_input_up_front() {
        let ok = vec![0x80];
        assert!(decode_limited(&ok, 1).is_ok());
        assert!(matches!(
            decode_limited(&[0x82, 0, 0], 2),
            Err(Error::Malformed(_))
        ));
    }

    #[test]
    fn fields_require_exactly_the_named_keys() {
        let v = Value::map(vec![("a", Value::Uint(1)), ("b", Value::Null)]);
        let f = v.fields(&["a", "b"]).unwrap();
        assert_eq!(f.get("a").unwrap(), &Value::Uint(1));
        assert!(v.fields(&["a"]).is_err());
        assert!(v.fields(&["a", "c"]).is_err());
        assert!(Value::Uint(1).fields(&[]).is_err());
    }
}
