//! Menu bar icon: Open Keepsake, Quick search, Lock, Quit.

use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Emitter, Manager};

use crate::{lock_session, quick, AppState};

pub const GLYPH_SIZE: u32 = 36;

/// The keyhole mark as a template image (black on transparent; macOS tints it).
pub fn glyph(size: u32) -> Vec<u8> {
    let s = size as f32 / 24.0; // the mark is drawn on a 24×24 grid, like Keyhole.tsx
    let mut rgba = vec![0u8; (size * size * 4) as usize];
    for y in 0..size {
        for x in 0..size {
            let (px, py) = ((x as f32 + 0.5) / s, (y as f32 + 0.5) / s);
            let in_circle = (px - 12.0).powi(2) + (py - 9.0).powi(2) <= 16.0;
            // Trapezoid from (10.2, 11.5)-(13.8, 11.5) down to (9, 19.5)-(15, 19.5).
            let t = (py - 11.5) / 8.0;
            let half = 1.8 + 1.2 * t;
            let in_stem = (0.0..=1.0).contains(&t) && (px - 12.0).abs() <= half;
            if in_circle || in_stem {
                rgba[((y * size + x) * 4 + 3) as usize] = 255;
            }
        }
    }
    rgba
}

pub fn install(app: &AppHandle) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Open Keepsake", true, None::<&str>)?;
    let quick = MenuItem::with_id(app, "quick", "Quick Search", true, None::<&str>)?;
    let lock = MenuItem::with_id(app, "lock", "Lock", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit Keepsake", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(app, &[&open, &quick, &lock, &separator, &quit])?;
    TrayIconBuilder::with_id("main")
        .icon(Image::new_owned(glyph(GLYPH_SIZE), GLYPH_SIZE, GLYPH_SIZE))
        .icon_as_template(true)
        .tooltip("Keepsake")
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => show_main(app),
            "quick" => quick::toggle(app),
            "lock" => {
                lock_session(&app.state::<AppState>()).lock();
                let _ = app.emit("locked", ());
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .build(app)?;
    Ok(())
}

pub fn show_main(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glyph_is_a_keyhole() {
        let size = GLYPH_SIZE;
        let px = glyph(size);
        assert_eq!(px.len(), (size * size * 4) as usize);
        let alpha = |x: u32, y: u32| px[((y * size + x) * 4 + 3) as usize];
        assert_eq!(alpha(size / 2, size * 9 / 24), 255, "circle centre");
        assert_eq!(alpha(size / 2, size * 18 / 24), 255, "stem");
        assert_eq!(alpha(0, 0), 0, "corner");
        assert_eq!(alpha(size / 2, size - 1), 0, "below the stem");
        assert!(
            px.chunks(4).all(|p| p[..3] == [0, 0, 0]),
            "template images are black"
        );
    }
}
