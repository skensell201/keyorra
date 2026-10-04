//! Started by the browser: a pipe between its stdio and the running app's socket.

use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use lockbox_session::bridge::wire::socket_path;

pub fn run() -> i32 {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return 1;
    };
    let Ok(stream) = connect(&socket_path(&home)) else {
        return 1;
    };
    let Ok(mut to_app) = stream.try_clone() else {
        return 1;
    };
    // The framing is identical on both sides, so bytes are copied as they are.
    std::thread::spawn(move || {
        let _ = io::copy(&mut io::stdin().lock(), &mut to_app);
        let _ = to_app.shutdown(Shutdown::Write);
    });
    let mut from_app = stream;
    let _ = relay(&mut from_app, &mut io::stdout().lock());
    0
}

/// Copies and flushes after every read. Rust's stdout is line-buffered and frames carry no
/// newline, so a plain `io::copy` would hold the reply until the browser closed stdin — which
/// the browser only does after it got the reply.
fn relay(from: &mut impl Read, to: &mut impl Write) -> io::Result<()> {
    let mut buf = [0u8; 8192];
    loop {
        let n = from.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        to.write_all(&buf[..n])?;
        to.flush()?;
    }
}

/// Connects to the app, starting it in the background if it isn't running.
fn connect(socket: &Path) -> io::Result<UnixStream> {
    if let Ok(s) = UnixStream::connect(socket) {
        return Ok(s);
    }
    let _ = Command::new("open")
        .args(["-g", "-b", "app.lockbox.mac"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    for _ in 0..60 {
        std::thread::sleep(Duration::from_millis(250));
        if let Ok(s) = UnixStream::connect(socket) {
            return Ok(s);
        }
    }
    UnixStream::connect(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Records what was flushed, like a line-buffered stdout that only emits on flush.
    #[derive(Default)]
    struct Flushed {
        pending: Vec<u8>,
        out: Vec<u8>,
    }

    impl Write for Flushed {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.pending.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            self.out.append(&mut self.pending);
            Ok(())
        }
    }

    #[test]
    fn relay_flushes_every_chunk() {
        let frame = b"\x10\0\0\0{\"kind\":\"status\"}";
        let mut to = Flushed::default();
        relay(&mut &frame[..], &mut to).unwrap();
        assert_eq!(
            to.out, frame,
            "everything read is flushed, nothing waits for a newline"
        );
        assert!(to.pending.is_empty());
    }
}
