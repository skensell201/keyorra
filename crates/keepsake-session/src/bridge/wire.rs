//! Native-messaging framing (4-byte little-endian length + JSON), also used on the socket.

use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// Chrome's limit for messages from the host.
pub const MAX_FRAME: u32 = 1024 * 1024;

/// `Ok(None)` at a clean end of stream.
pub fn read_frame(r: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    let mut got = 0;
    while got < len.len() {
        match r.read(&mut len[got..]) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => got += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let n = u32::from_le_bytes(len);
    if n > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame too large",
        ));
    }
    let mut buf = vec![0u8; n as usize];
    r.read_exact(&mut buf)?;
    Ok(Some(buf))
}

pub fn write_frame(w: &mut impl Write, data: &[u8]) -> io::Result<()> {
    if data.len() > MAX_FRAME as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "frame too large",
        ));
    }
    w.write_all(&(data.len() as u32).to_le_bytes())?;
    w.write_all(data)?;
    w.flush()
}

/// The app's socket; the native host finds it from `$HOME` alone.
pub fn socket_path(home: &Path) -> PathBuf {
    home.join("Library/Application Support/app.keepsake.mac/bridge.sock")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frames_round_trip_little_endian() {
        let mut buf = Vec::new();
        write_frame(&mut buf, br#"{"kind":"status"}"#).unwrap();
        assert_eq!(&buf[..4], &17u32.to_le_bytes());
        let mut r = Cursor::new(buf);
        assert_eq!(
            read_frame(&mut r).unwrap().unwrap(),
            br#"{"kind":"status"}"#
        );
        assert_eq!(read_frame(&mut r).unwrap(), None, "clean end of stream");
    }

    #[test]
    fn rejects_oversized_and_truncated_frames() {
        let mut huge = (MAX_FRAME + 1).to_le_bytes().to_vec();
        huge.extend_from_slice(b"x");
        assert!(read_frame(&mut Cursor::new(huge)).is_err());
        let mut short = 10u32.to_le_bytes().to_vec();
        short.extend_from_slice(b"abc");
        assert!(read_frame(&mut Cursor::new(short)).is_err());
        assert!(write_frame(&mut Vec::new(), &vec![0u8; MAX_FRAME as usize + 1]).is_err());
    }

    #[test]
    fn a_truncated_length_prefix_is_an_error() {
        assert!(read_frame(&mut Cursor::new(vec![1u8, 0])).is_err());
        assert_eq!(read_frame(&mut Cursor::new(Vec::new())).unwrap(), None);
    }

    #[test]
    fn socket_lives_in_the_app_data_folder() {
        assert_eq!(
            socket_path(std::path::Path::new("/Users/ivan")),
            std::path::PathBuf::from(
                "/Users/ivan/Library/Application Support/app.keepsake.mac/bridge.sock"
            )
        );
    }
}
