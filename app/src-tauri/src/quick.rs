//! The ⌘⇧Space quick-search window: small, floating, hidden when it loses focus.

use std::sync::atomic::{AtomicBool, Ordering};

use tauri::{AppHandle, Emitter, Manager, WebviewUrl, WebviewWindowBuilder, WindowEvent};
use tauri_plugin_global_shortcut::{Code, GlobalShortcutExt, Modifiers, Shortcut, ShortcutState};

pub const LABEL: &str = "quick";

/// While set, losing focus does not hide the window (the Touch ID sheet takes focus).
static HOLD: AtomicBool = AtomicBool::new(false);

/// Keeps the quick window open while it lives.
pub struct HoldOpen;

impl HoldOpen {
    pub fn new() -> Self {
        HOLD.store(true, Ordering::SeqCst);
        HoldOpen
    }
}

impl Drop for HoldOpen {
    fn drop(&mut self) {
        HOLD.store(false, Ordering::SeqCst);
    }
}

pub fn shortcut() -> Shortcut {
    Shortcut::new(Some(Modifiers::SUPER | Modifiers::SHIFT), Code::Space)
}

/// Creates the hidden window and registers the shortcut. A taken shortcut is not fatal.
pub fn install(app: &AppHandle) -> tauri::Result<()> {
    let window = WebviewWindowBuilder::new(app, LABEL, WebviewUrl::App("index.html#quick".into()))
        .title("Keepsake Quick Search")
        .inner_size(640.0, 420.0)
        .resizable(false)
        .decorations(false)
        .transparent(true)
        .always_on_top(true)
        .skip_taskbar(true)
        .visible(false)
        .center()
        .build()?;
    let handle = window.clone();
    window.on_window_event(move |event| {
        if let WindowEvent::Focused(false) = event {
            if !HOLD.load(Ordering::SeqCst) {
                let _ = handle.hide();
            }
        }
    });
    if let Err(e) = app.global_shortcut().register(shortcut()) {
        eprintln!("keepsake: ⌘⇧Space is not available: {e}");
    }
    Ok(())
}

pub fn plugin() -> tauri::plugin::TauriPlugin<tauri::Wry> {
    tauri_plugin_global_shortcut::Builder::new()
        .with_handler(|app, shortcut, event| {
            if *shortcut == self::shortcut() && event.state() == ShortcutState::Pressed {
                toggle(app);
            }
        })
        .build()
}

pub fn toggle(app: &AppHandle) {
    let Some(window) = app.get_webview_window(LABEL) else {
        return;
    };
    if window.is_visible().unwrap_or(false) {
        let _ = window.hide();
        return;
    }
    let _ = window.center();
    let _ = window.show();
    let _ = window.set_focus();
    let _ = app.emit_to(LABEL, "quick-open", ());
}

pub fn hide(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(LABEL) {
        let _ = window.hide();
    }
}
