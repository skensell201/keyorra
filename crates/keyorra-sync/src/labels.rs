//! Domain-separation labels. Every label is used as `label ‖ 0x00 ‖ parts…` (see [`tagged`]),
//! so no label can be a prefix of another.

pub const KEK: &[u8] = b"keyorra/sync/v1/kek";
pub const SERVER_AUTH: &[u8] = b"keyorra/sync/v1/server-auth";
pub const SEGMENT_KEY: &[u8] = b"keyorra/sync/v1/segment-key";
pub const ACCOUNT_KEY: &[u8] = b"keyorra/sync/v1/account-key";
pub const HEADER: &[u8] = b"keyorra/sync/v1/header";
pub const BODY: &[u8] = b"keyorra/sync/v1/body";
pub const VERSION: &[u8] = b"keyorra/sync/v1/version";
pub const CHUNK: &[u8] = b"keyorra/sync/v1/chunk";
pub const SEGMENT: &[u8] = b"keyorra/sync/v1/segment";
pub const SNAPSHOT: &[u8] = b"keyorra/sync/v1/snapshot";
pub const CHAIN_GENESIS: &[u8] = b"keyorra/sync/v1/chain-genesis";
pub const CHAIN: &[u8] = b"keyorra/sync/v1/chain";

pub const ALL: &[&[u8]] = &[
    KEK,
    SERVER_AUTH,
    SEGMENT_KEY,
    ACCOUNT_KEY,
    HEADER,
    BODY,
    VERSION,
    CHUNK,
    SEGMENT,
    SNAPSHOT,
    CHAIN_GENESIS,
    CHAIN,
];

/// `label ‖ 0x00 ‖ parts[0] ‖ parts[1] ‖ …`. Parts are fixed-length or the last field.
pub fn tagged(label: &[u8], parts: &[&[u8]]) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(label.len() + 1 + parts.iter().map(|p| p.len()).sum::<usize>());
    out.extend_from_slice(label);
    out.push(0);
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_distinct_versioned_and_nul_free() {
        for (i, a) in ALL.iter().enumerate() {
            assert!(a.starts_with(b"keyorra/sync/v1/"), "{a:?}");
            assert!(!a.contains(&0));
            for b in &ALL[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    #[test]
    fn tagged_terminates_the_label() {
        assert_eq!(tagged(b"x", &[b"ab", b"c"]), b"x\0abc");
        assert_eq!(tagged(b"x", &[]), b"x\0");
        // "chain" vs "chain-genesis" cannot collide thanks to the terminator.
        assert!(!tagged(CHAIN_GENESIS, &[]).starts_with(&tagged(CHAIN, &[])));
    }
}
