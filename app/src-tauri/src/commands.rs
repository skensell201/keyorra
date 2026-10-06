//! Tauri commands: each locks the session and calls one `Session` method.

use std::path::PathBuf;

use keyorra_core::model::{Item, ItemKind};
use keyorra_core::watchtower::Hibp;
use keyorra_session::dto::{
    GeneratorRequest, ImportPreview, ImportResult, ItemFilter, ItemSummary, TotpCode, VaultDto,
};
use keyorra_session::touchid::TouchIdState;
use keyorra_session::watchtower::Report;
use keyorra_session::{CmdError, CmdResult, ErrorKind, PairedBrowser, QuickCopy, Settings, Status};
use tauri::{AppHandle, Emitter, State};
use tauri_plugin_clipboard_manager::ClipboardExt;
use uuid::Uuid;

use crate::{lock_session, now, AppState};

#[tauri::command(async)]
pub fn status(state: State<'_, AppState>) -> CmdResult<Status> {
    Ok(lock_session(&state).status())
}

#[tauri::command(async)]
pub fn create_vault_file(state: State<'_, AppState>, password: String) -> CmdResult<()> {
    lock_session(&state).create(&password, now())
}

#[tauri::command(async)]
pub fn unlock(app: AppHandle, state: State<'_, AppState>, password: String) -> CmdResult<()> {
    lock_session(&state).unlock(&password, now())?;
    // Both windows (main and quick search) follow the lock state.
    let _ = app.emit("unlocked", ());
    Ok(())
}

#[tauri::command(async)]
pub fn lock(app: AppHandle, state: State<'_, AppState>) -> CmdResult<()> {
    lock_session(&state).lock();
    let _ = app.emit("locked", ());
    Ok(())
}

#[tauri::command(async)]
pub fn quick_copy(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
    what: QuickCopy,
) -> CmdResult<()> {
    let mut session = lock_session(&state);
    let text = session.copy_quick(id, what, now())?;
    app.clipboard()
        .write_text(text)
        .map_err(|e| CmdError::new(ErrorKind::Other, format!("Clipboard: {e}")))
}

#[tauri::command(async)]
pub fn quick_hide(app: AppHandle) {
    crate::quick::hide(&app);
}

#[tauri::command(async)]
pub fn vaults(state: State<'_, AppState>) -> CmdResult<Vec<VaultDto>> {
    lock_session(&state).vaults(now())
}

#[tauri::command(async)]
pub fn create_vault(state: State<'_, AppState>, name: String) -> CmdResult<VaultDto> {
    lock_session(&state).create_vault(&name, now())
}

#[tauri::command(async)]
pub fn items(state: State<'_, AppState>, filter: ItemFilter) -> CmdResult<Vec<ItemSummary>> {
    lock_session(&state).items(&filter, now())
}

#[tauri::command(async)]
pub fn item(state: State<'_, AppState>, id: Uuid) -> CmdResult<Item> {
    lock_session(&state).item(id, now())
}

#[tauri::command(async)]
pub fn new_item(state: State<'_, AppState>, vault_id: Uuid, kind: ItemKind) -> CmdResult<Item> {
    lock_session(&state).new_item(vault_id, kind, now())
}

#[tauri::command(async)]
pub fn save_item(state: State<'_, AppState>, item: Item) -> CmdResult<Item> {
    lock_session(&state).save_item(item, now())
}

#[tauri::command(async)]
pub fn delete_item(state: State<'_, AppState>, id: Uuid) -> CmdResult<()> {
    lock_session(&state).delete_item(id, now())
}

#[tauri::command(async)]
pub fn totp(state: State<'_, AppState>, id: Uuid) -> CmdResult<Option<TotpCode>> {
    lock_session(&state).totp(id, now())
}

#[tauri::command(async)]
pub fn copy_field(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
    field: String,
) -> CmdResult<()> {
    // Hold the lock across arming the guard and writing, so housekeeping can't see a half-done copy.
    let mut session = lock_session(&state);
    let text = session.copy_value(id, &field, now())?;
    app.clipboard()
        .write_text(text)
        .map_err(|e| CmdError::new(ErrorKind::Other, format!("Clipboard: {e}")))
}

#[tauri::command(async)]
pub fn generate(request: GeneratorRequest) -> CmdResult<String> {
    request.generate()
}

#[tauri::command(async)]
pub fn import_preview(state: State<'_, AppState>, path: String) -> CmdResult<ImportPreview> {
    lock_session(&state).import_preview(&PathBuf::from(path), now())
}

#[tauri::command(async)]
pub fn import_apply(state: State<'_, AppState>) -> CmdResult<ImportResult> {
    lock_session(&state).import_apply(now())
}

#[tauri::command(async)]
pub fn deleted_items(state: State<'_, AppState>) -> CmdResult<Vec<ItemSummary>> {
    lock_session(&state).deleted_items(now())
}

#[tauri::command(async)]
pub fn restore_item(state: State<'_, AppState>, id: Uuid) -> CmdResult<()> {
    lock_session(&state).restore_item(id, now())
}

#[tauri::command(async)]
pub fn settings(state: State<'_, AppState>) -> CmdResult<Settings> {
    Ok(lock_session(&state).settings())
}

#[tauri::command(async)]
pub fn update_settings(state: State<'_, AppState>, settings: Settings) -> CmdResult<Settings> {
    lock_session(&state).update_settings(settings, now())
}

#[tauri::command(async)]
pub fn change_password(
    state: State<'_, AppState>,
    current: String,
    new_password: String,
) -> CmdResult<()> {
    lock_session(&state).change_password(&current, &new_password, now())
}

#[tauri::command(async)]
pub fn connect_browsers() -> CmdResult<Vec<String>> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| CmdError::new(ErrorKind::Other, "HOME is not set"))?;
    let exe =
        std::env::current_exe().map_err(|e| CmdError::new(ErrorKind::Other, e.to_string()))?;
    if exe.to_string_lossy().contains("/AppTranslocation/") {
        return Err(CmdError::new(
            ErrorKind::Invalid,
            "Move Keyorra to Applications, then try again",
        ));
    }
    let app_support = home.join("Library/Application Support");
    let mut done = Vec::new();
    let mut failure = None;
    for m in keyorra_session::bridge::host::manifests(&app_support, &exe) {
        let written = match m.path.parent() {
            Some(dir) => std::fs::create_dir_all(dir),
            None => Ok(()),
        }
        .and_then(|_| std::fs::write(&m.path, m.contents));
        match written {
            Ok(()) => done.push(m.browser.to_string()),
            Err(e) => failure = Some(e.to_string()),
        }
    }
    if done.is_empty() {
        if let Some(message) = failure {
            return Err(CmdError::new(ErrorKind::Other, message));
        }
    }
    let safari =
        keyorra_session::bridge::host::safari_status(std::path::Path::new("/Applications"));
    done.push(safari.to_string());
    Ok(done)
}

#[tauri::command(async)]
pub fn approve_pairing(state: State<'_, AppState>, client_id: String) -> CmdResult<()> {
    lock_session(&state).approve_pairing(&client_id, now())
}

#[tauri::command(async)]
pub fn deny_pairing(state: State<'_, AppState>, client_id: String) -> CmdResult<()> {
    lock_session(&state).deny_pairing(&client_id);
    Ok(())
}

#[tauri::command(async)]
pub fn paired_browsers(state: State<'_, AppState>) -> CmdResult<Vec<PairedBrowser>> {
    lock_session(&state).paired_browsers()
}

#[tauri::command(async)]
pub fn remove_paired_browser(state: State<'_, AppState>, client_id: String) -> CmdResult<()> {
    lock_session(&state).remove_paired_browser(&client_id)
}

#[tauri::command(async)]
pub fn start_over(state: State<'_, AppState>) -> CmdResult<String> {
    let aside = lock_session(&state).start_over(now())?;
    Ok(aside.display().to_string())
}

#[tauri::command(async)]
pub fn rename_vault(state: State<'_, AppState>, id: Uuid, name: String) -> CmdResult<VaultDto> {
    lock_session(&state).rename_vault(id, &name, now())
}

#[tauri::command(async)]
pub fn delete_vault(state: State<'_, AppState>, id: Uuid) -> CmdResult<()> {
    lock_session(&state).delete_vault(id, now())
}

#[tauri::command(async)]
pub fn watchtower(state: State<'_, AppState>) -> CmdResult<Report> {
    lock_session(&state).watchtower(now())
}

/// The sidebar badge: cached in the session until the next write, so it is cheap to ask.
#[tauri::command(async)]
pub fn watchtower_count(state: State<'_, AppState>) -> CmdResult<usize> {
    lock_session(&state).watchtower_count()
}

/// Asks Have I Been Pwned about every unchecked password, without holding the session: only
/// the first five hex characters of each SHA-1 leave the Mac.
#[tauri::command(async)]
pub fn check_breaches(state: State<'_, AppState>) -> CmdResult<Report> {
    let hashes = lock_session(&state).breach_hashes_to_check(now())?;
    let hibp = Hibp::default();
    let mut results = Vec::with_capacity(hashes.len());
    for hash in hashes {
        match hibp.breach_count_for_hash(&hash.hex()) {
            Ok(count) => results.push((hash, count)),
            Err(e) => {
                // Keep what we learned; the next check continues from there.
                lock_session(&state).record_breaches(results);
                return Err(CmdError::new(
                    ErrorKind::Other,
                    format!("Couldn't reach Have I Been Pwned: {e}"),
                ));
            }
        }
    }
    let mut session = lock_session(&state);
    session.record_breaches(results);
    session.watchtower(now())
}

#[tauri::command(async)]
pub fn touch_id_state(state: State<'_, AppState>) -> TouchIdState {
    lock_session(&state).touch_id_state(crate::touchid::available(), now())
}

#[tauri::command(async)]
pub fn enable_touch_id(state: State<'_, AppState>) -> CmdResult<()> {
    if !crate::touchid::available() {
        return Err(CmdError::new(
            ErrorKind::Invalid,
            "Touch ID isn't available on this Mac",
        ));
    }
    let (blob, public) = crate::touchid::create_key()
        .map_err(|e| CmdError::new(ErrorKind::Other, format!("Secure Enclave: {e:?}")))?;
    lock_session(&state).enable_touch_id(blob, &public, now())
}

#[tauri::command(async)]
pub fn disable_touch_id(state: State<'_, AppState>) {
    lock_session(&state).disable_touch_id();
}

/// Shows the Touch ID prompt (blocking this worker thread, never the session) and unlocks.
#[tauri::command(async)]
pub fn unlock_with_touch_id(app: AppHandle, state: State<'_, AppState>) -> CmdResult<()> {
    use crate::touchid::Failure;
    let request = lock_session(&state).touch_id_request(now())?;
    let peer: [u8; 65] = request
        .ephemeral_public
        .as_slice()
        .try_into()
        .map_err(|_| {
            CmdError::new(
                ErrorKind::PasswordRequired,
                "Touch ID needs to be set up again",
            )
        })?;
    let _hold = crate::quick::HoldOpen::new();
    let shared = match crate::touchid::agree(&request.enclave_key, &peer, "unlock Keyorra") {
        Ok(shared) => shared,
        Err(Failure::Cancelled) => return Err(CmdError::new(ErrorKind::Cancelled, "Cancelled")),
        Err(Failure::Lockout) => {
            return Err(CmdError::new(
                ErrorKind::PasswordRequired,
                "Touch ID is locked after too many tries. Use your master password.",
            ))
        }
        Err(Failure::Invalid) => {
            lock_session(&state).disable_touch_id();
            return Err(CmdError::new(
                ErrorKind::PasswordRequired,
                "Your fingerprints changed. Unlock with your master password, then turn Touch ID on again in Settings.",
            ));
        }
        Err(_) => {
            return Err(CmdError::new(
                ErrorKind::PasswordRequired,
                "Touch ID isn't available right now. Use your master password.",
            ))
        }
    };
    lock_session(&state).unlock_with_touch_id(&request, &shared, now())?;
    let _ = app.emit("unlocked", ());
    Ok(())
}

// ---- sync (plan A3) ----

use crate::syncfolder::{describe_place, PlaceInfo, SyncPlace};
use keyorra_session::session::{BackupFile, EmergencyKitDto, JoinOutcome, SyncScreenDto};
use keyorra_session::sync::VerifyReport;
use std::sync::Arc;

#[tauri::command(async)]
pub fn sync_screen(state: State<'_, AppState>) -> CmdResult<SyncScreenDto> {
    lock_session(&state).sync_screen()
}

#[tauri::command(async)]
pub fn sync_now(app: AppHandle, state: State<'_, AppState>) -> CmdResult<SyncScreenDto> {
    let mut session = lock_session(&state);
    session.sync_now(now())?;
    let screen = session.sync_screen();
    drop(session);
    let _ = app.emit("synced", ());
    screen
}

#[tauri::command(async)]
pub fn enable_sync(state: State<'_, AppState>, password: String) -> CmdResult<EmergencyKitDto> {
    lock_session(&state).enable_sync(&password, now())
}

#[tauri::command(async)]
pub fn join_sync(
    app: AppHandle,
    state: State<'_, AppState>,
    password: String,
    code: String,
) -> CmdResult<JoinOutcome> {
    let outcome = lock_session(&state).join_sync(&password, &code, now())?;
    let _ = app.emit("synced", ());
    Ok(outcome)
}

#[tauri::command(async)]
pub fn disable_sync(state: State<'_, AppState>) -> CmdResult<()> {
    lock_session(&state).disable_sync(now())
}

#[tauri::command(async)]
pub fn approve_device(state: State<'_, AppState>, id: String, code: String) -> CmdResult<()> {
    lock_session(&state).approve_device(&id, &code, now())
}

#[tauri::command(async)]
pub fn sync_alarm_action(state: State<'_, AppState>, id: String, action: String) -> CmdResult<()> {
    lock_session(&state).sync_alarm_action(&id, &action, now())
}

#[tauri::command(async)]
pub fn remove_sync_device(state: State<'_, AppState>, id: String) -> CmdResult<()> {
    lock_session(&state).remove_sync_device(&id, now())
}

#[tauri::command(async)]
pub fn verify_sync(state: State<'_, AppState>) -> CmdResult<VerifyReport> {
    lock_session(&state).verify_sync()
}

#[tauri::command(async)]
pub fn sync_folder_files(
    state: State<'_, AppState>,
) -> CmdResult<Vec<keyorra_session::session::FolderFile>> {
    lock_session(&state).sync_folder_files()
}

#[tauri::command(async)]
pub fn emergency_kit(
    state: State<'_, AppState>,
    password: Option<String>,
) -> CmdResult<EmergencyKitDto> {
    lock_session(&state).emergency_kit(password.as_deref(), now())
}

#[tauri::command(async)]
pub fn start_new_sync_account(
    state: State<'_, AppState>,
    password: String,
) -> CmdResult<EmergencyKitDto> {
    lock_session(&state).start_new_sync_account(&password, now())
}

#[tauri::command(async)]
pub fn backups(state: State<'_, AppState>) -> CmdResult<Vec<BackupFile>> {
    lock_session(&state).backups()
}

#[tauri::command(async)]
pub fn delete_backup(state: State<'_, AppState>, name: String) -> CmdResult<()> {
    lock_session(&state).delete_backup(&name, now())
}

#[tauri::command(async)]
pub fn sync_place(places: State<'_, Arc<SyncPlace>>) -> Option<PlaceInfo> {
    places.current().map(|p| describe_place(&p))
}

/// Chooses where accounts go (`None`: iCloud Drive); only while sync is off.
#[tauri::command(async)]
pub fn set_sync_place(
    state: State<'_, AppState>,
    places: State<'_, Arc<SyncPlace>>,
    path: Option<String>,
) -> CmdResult<PlaceInfo> {
    let mut session = lock_session(&state);
    // Locked, whether sync is on is not known: refused (review A3 I2).
    session.may_change_sync_place()?;
    let place = places
        .set(path.as_deref().map(std::path::Path::new))
        .map_err(|e| CmdError::new(ErrorKind::Invalid, e))?;
    if let Some(link) = places.link() {
        session.set_sync_link(Box::new(link));
    }
    Ok(describe_place(&place))
}

/// The setup code on the clipboard, concealed from clipboard managers and cleared after 90
/// seconds at most. It is read here, under the same rule as the Emergency Kit (unlocked, the
/// master password entered in the last few minutes or given now), so it never reaches the
/// web view.
#[tauri::command(async)]
pub fn copy_setup_code(state: State<'_, AppState>, password: Option<String>) -> CmdResult<()> {
    let mut session = lock_session(&state);
    let t = now();
    let kit = session.emergency_kit(password.as_deref(), t)?;
    let code = zeroize::Zeroizing::new(kit.setup_code);
    crate::syncfolder::copy_concealed(&code).map_err(|e| CmdError::new(ErrorKind::Other, e))?;
    session.copied_secret(&code, t);
    Ok(())
}
