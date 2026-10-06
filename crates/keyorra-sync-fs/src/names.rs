//! The exact file names of the account folder (spec §5.1). A file counts only if its name
//! matches its directory's pattern; anything else (a sync client's conflict copy
//! `x (1).seg`, `.DS_Store`, a half-written temp file) is ignored.

use keyorra_sync::DeviceId;

pub const ACCOUNT: &str = "account";
pub const STREAMS: &str = "streams";
pub const SNAPSHOTS: &str = "snapshots";
pub const CHUNKS: &str = "chunks";
pub const ROOT_HEAD: &str = "root.head";
pub const README: &str = "README-KEYORRA.txt";
/// Temp files when the app's temp directory is on another volume: inside the folder, under
/// a name iCloud does not upload and readers ignore.
pub const NOSYNC_TMP: &str = ".keyorra-tmp.nosync";

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn device_dir(device: &DeviceId) -> String {
    data_encoding::HEXLOWER.encode(device)
}

pub fn parse_device_dir(name: &str) -> Option<DeviceId> {
    if !is_hex(name, 32) {
        return None;
    }
    data_encoding::HEXLOWER
        .decode(name.as_bytes())
        .ok()?
        .try_into()
        .ok()
}

pub fn segment_file(first_seq: u64) -> String {
    format!("{first_seq:016x}.seg")
}

pub fn parse_segment_file(name: &str) -> Option<u64> {
    let stem = name.strip_suffix(".seg")?;
    is_hex(stem, 16).then(|| u64::from_str_radix(stem, 16).ok())?
}

/// `<epoch:08x>-<device hex>.hdr`, as `HeaderFile::file_name` makes it.
pub fn is_header_file(name: &str) -> bool {
    let Some(stem) = name.strip_suffix(".hdr") else {
        return false;
    };
    let mut parts = stem.splitn(2, '-');
    matches!((parts.next(), parts.next()), (Some(e), Some(d)) if is_hex(e, 8) && is_hex(d, 32))
}

pub fn is_snapshot_name(name: &str) -> bool {
    is_hex(name, 64)
}

pub fn snapshot_file(name: &str) -> String {
    format!("{name}.snap")
}

pub fn parse_snapshot_file(file: &str) -> Option<&str> {
    file.strip_suffix(".snap").filter(|n| is_snapshot_name(n))
}

pub fn is_chunk_name(name: &str) -> bool {
    is_hex(name, 64)
}

/// An evicted iCloud file shows as `.<name>.icloud`: the file exists but is not on this Mac.
pub fn placeholder_of(file: &str) -> Option<&str> {
    file.strip_prefix('.')?.strip_suffix(".icloud")
}

pub fn placeholder_name(file: &str) -> String {
    format!(".{file}.icloud")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exact_names_count() {
        assert_eq!(parse_segment_file("000000000000002a.seg"), Some(42));
        for bad in [
            "000000000000002a (1).seg",
            "000000000000002A.seg",
            "2a.seg",
            "000000000000002a.seg.tmp",
            ".000000000000002a.seg",
        ] {
            assert_eq!(parse_segment_file(bad), None, "{bad}");
        }
        assert!(is_header_file(&format!("00000001-{}.hdr", "ab".repeat(16))));
        assert!(!is_header_file(&format!(
            "00000001-{} (1).hdr",
            "ab".repeat(16)
        )));
        assert!(!is_header_file("root.head"));
        assert_eq!(parse_device_dir(&"0f".repeat(16)), Some([0x0f; 16]));
        assert_eq!(parse_device_dir(".DS_Store"), None);
        assert_eq!(
            parse_snapshot_file(&format!("{}.snap", "1".repeat(64))),
            Some(&*"1".repeat(64))
        );
        assert_eq!(
            parse_snapshot_file(&format!("{} 2.snap", "1".repeat(64))),
            None
        );
        assert_eq!(
            placeholder_of(".000000000000002a.seg.icloud"),
            Some("000000000000002a.seg")
        );
        assert_eq!(placeholder_of("000000000000002a.seg"), None);
    }
}
