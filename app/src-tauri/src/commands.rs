//! Tauri commands: each locks the session and calls one `Session` method.

use std::path::PathBuf;

use lockbox_core::model::{Item, ItemKind};
use lockbox_session::dto::{
    GeneratorRequest, ImportPreview, ImportResult, ItemFilter, ItemSummary, TotpCode, VaultDto,
};
use lockbox_session::{CmdError, CmdResult, ErrorKind, Status};
use tauri::{AppHandle, State};
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
pub fn unlock(state: State<'_, AppState>, password: String) -> CmdResult<()> {
    lock_session(&state).unlock(&password, now())
}

#[tauri::command(async)]
pub fn lock(state: State<'_, AppState>) -> CmdResult<()> {
    lock_session(&state).lock();
    Ok(())
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
