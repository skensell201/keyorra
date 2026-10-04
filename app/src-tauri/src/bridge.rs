//! Serves the browser extension over a Unix socket; the native host pipes the browser to it.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::Duration;

use lockbox_session::bridge::protocol::{Inbound, Outbound};
use lockbox_session::bridge::wire::{read_frame, write_frame};
use lockbox_session::BridgeEvent;
use tauri::{AppHandle, Emitter, Manager};

use crate::{lock_session, now, AppState};

/// A client that stalls mid-frame must not hold its thread forever.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

pub fn serve(app: AppHandle, socket: PathBuf) {
    if let Some(dir) = socket.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    // A stale socket from a previous run would make bind fail.
    let _ = std::fs::remove_file(&socket);
    let listener = match UnixListener::bind(&socket) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("lockbox: browser bridge unavailable: {e}");
            return;
        }
    };
    let _ = std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600));
    for stream in listener.incoming().flatten() {
        let app = app.clone();
        std::thread::spawn(move || connection(app, stream));
    }
}

fn connection(app: AppHandle, mut stream: UnixStream) {
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    while let Ok(Some(frame)) = read_frame(&mut stream) {
        let reply = match serde_json::from_slice::<Inbound>(&frame) {
            Ok(msg) => {
                let (out, event) = {
                    let state = app.state::<AppState>();
                    let mut session = lock_session(&state);
                    session.bridge(msg, now())
                };
                if let Some(event) = event {
                    on_event(&app, event);
                }
                out
            }
            Err(_) => Outbound::Error {
                message: "Unknown message".into(),
            },
        };
        let bytes = serde_json::to_vec(&reply).expect("outbound serializes");
        if write_frame(&mut stream, &bytes).is_err() {
            break;
        }
    }
}

fn on_event(app: &AppHandle, event: BridgeEvent) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
    if let BridgeEvent::PairRequest(request) = event {
        let _ = app.emit("pair-request", request);
    }
}
