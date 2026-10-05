mod bridge;
mod commands;
pub mod native_host;
mod quick;
mod screen;
mod syncfolder;
mod touchid;
mod tray;

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use keyorra_core::crypto::KdfParams;
use keyorra_session::Session;
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
        .plugin(quick::plugin())
        .setup(|app| {
            let path = app.path().app_data_dir()?.join("keyorra.db");
            let mut session = Session::new(path, KdfParams::DEFAULT, now());
            session.set_keyring(Box::new(touchid::MacKeyring));
            // Sync over iCloud Drive (plan A2; A3 lets the user pick another synced folder).
            let changed = Arc::new(AtomicBool::new(false));
            let place = syncfolder::icloud_place();
            if let Some(place) = place.clone() {
                let temp = app.path().app_data_dir()?.join("sync-tmp");
                // Nothing is created in iCloud Drive before sync is turned on; the watcher
                // starts once the folder exists (housekeeping, review A2 M3).
                session.set_sync_link(Box::new(syncfolder::FolderLink::new(
                    place,
                    temp,
                    Arc::new(syncfolder::MacCloud),
                    Box::new(|| Box::new(touchid::device_keys())),
                    syncfolder::computer_name(),
                )));
            }
            app.manage(AppState(Mutex::new(session)));
            // After `manage`: both call commands that need the session. Neither is essential;
            // without them Keyorra still works from its main window.
            if let Err(e) = tray::install(app.handle()) {
                eprintln!("keyorra: menu bar icon unavailable: {e}");
            }
            if let Err(e) = quick::install(app.handle()) {
                eprintln!("keyorra: quick search unavailable: {e}");
            }
            let handle = app.handle().clone();
            std::thread::spawn(move || housekeeping(handle, changed, place));
            if let Some(home) = std::env::var_os("HOME").map(std::path::PathBuf::from) {
                let socket = keyorra_session::bridge::wire::socket_path(&home);
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
            commands::start_over,
            commands::rename_vault,
            commands::delete_vault,
            commands::watchtower,
            commands::watchtower_count,
            commands::check_breaches,
            commands::quick_copy,
            commands::quick_hide,
            commands::touch_id_state,
            commands::enable_touch_id,
            commands::disable_touch_id,
            commands::unlock_with_touch_id,
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
        .on_window_event(|window, event| {
            // Closing the main window keeps Keyorra in the menu bar; Quit is in the tray menu.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building Keyorra")
        .run(|app, event| {
            if let tauri::RunEvent::Reopen {
                has_visible_windows: false,
                ..
            } = event
            {
                tray::show_main(app);
            }
        });
}

/// Every two seconds: lock when idle (and tell the window), clear the clipboard once our copy
/// has expired — but only if it still holds our copy.
fn housekeeping(app: AppHandle, changed: Arc<AtomicBool>, place: Option<std::path::PathBuf>) {
    // `Instant` does not advance while the Mac sleeps (CLOCK_UPTIME_RAW), unlike wall time.
    let start = Instant::now();
    let mut schedule = syncfolder::Schedule::new(changed.clone());
    let mut watcher: Option<syncfolder::Watcher> = None;
    loop {
        std::thread::sleep(Duration::from_secs(2));
        // Changes are watched as soon as the sync place exists (sync turned on here or on
        // another Mac), not only from the next launch.
        if watcher.is_none() {
            if let Some(p) = place.as_ref().filter(|p| p.is_dir()) {
                watcher = syncfolder::Watcher::start(p, changed.clone());
            }
        }
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
        // Sync while unlocked: on a change in the folder, and every minute.
        let mut synced = false;
        if session.status() == keyorra_session::session::Status::Unlocked
            && session.sync_status().is_ok_and(|s| s.enabled)
            && schedule.due(t)
        {
            synced = session.sync_now(t).is_ok();
        }
        drop(session);
        if locked {
            let _ = app.emit("locked", ());
        }
        if synced {
            let _ = app.emit("synced", ());
        }
    }
}
