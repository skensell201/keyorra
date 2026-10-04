//! Started by the browser: a pipe between its stdio and the running app's socket.

use std::io;
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
    let _ = io::copy(&mut from_app, &mut io::stdout().lock());
    0
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
