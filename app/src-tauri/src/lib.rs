mod bridge;
mod commands;
pub mod native_host;
mod screen;

use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use keepsake_core::crypto::KdfParams;
use keepsake_session::Session;
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_clipboard_manager::ClipboardExt;

/// The one session behind every command.
pub struct AppState(Mutex<Session>);

/// A poisoned lock only means a command panicked mid-way; the session itself stays usable.
pub(crate) fn lock_session(state: &AppState) -> MutexGuard<'_, Session> {
    state.0.lock().unwrap_or_else(|e| e.into_inner())
}

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .setup(|app| {
            let path = app.path().app_data_dir()?.join("keepsake.db");
            app.manage(AppState(Mutex::new(Session::new(
                path,
                KdfParams::DEFAULT,
                now(),
            ))));
            let handle = app.handle().clone();
            std::thread::spawn(move || housekeeping(handle));
            if let Some(home) = std::env::var_os("HOME").map(std::path::PathBuf::from) {
                let socket = keepsake_session::bridge::wire::socket_path(&home);
                let bridge_app = app.handle().clone();
                std::thread::spawn(move || bridge::serve(bridge_app, socket));
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::status,
            commands::create_vault_file,
            commands::unlock,
            commands::lock,
            commands::vaults,
            commands::create_vault,
            commands::items,
            commands::item,
            commands::new_item,
            commands::save_item,
            commands::delete_item,
            commands::totp,
            commands::copy_field,
            commands::generate,
            commands::import_preview,
            commands::import_apply,
            commands::deleted_items,
            commands::restore_item,
            commands::settings,
            commands::update_settings,
            commands::change_password,
            commands::connect_browsers,
            commands::approve_pairing,
            commands::deny_pairing,
            commands::paired_browsers,
            commands::remove_paired_browser,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Keepsake");
}

/// Every two seconds: lock when idle (and tell the window), clear the clipboard once our copy
/// has expired — but only if it still holds our copy.
fn housekeeping(app: AppHandle) {
    // `Instant` does not advance while the Mac sleeps (CLOCK_UPTIME_RAW), unlike wall time.
    let start = Instant::now();
    loop {
        std::thread::sleep(Duration::from_secs(2));
        let state = app.state::<AppState>();
        // Read the flag before taking the lock. Sleep is detected from wall time vs the
        // monotonic `start` clock, so a command holding the lock for a long time (both clocks
        // advance) does not look like sleep.
        let screen_locked = screen::is_locked();
        // The lock spans the clipboard calls on purpose: a copy command must not arm the guard
        // and write between our read and our clear, or we would wipe the fresh copy.
        let mut session = lock_session(&state);
        let t = now();
        let locked = session.tick_with(t, start.elapsed().as_secs(), screen_locked);
        if session.clipboard_pending() {
            let current = app.clipboard().read_text().ok();
            if session.clipboard_should_clear(t, current.as_deref()) {
                let _ = app.clipboard().clear();
            }
        }
        drop(session);
        if locked {
            let _ = app.emit("locked", ());
        }
    }
}
