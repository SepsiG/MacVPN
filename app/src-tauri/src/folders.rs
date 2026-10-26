//! The folder commands (spec 3; the logic is `macvpn_app_core::folders`): create, rename, colour, collapse, move
//! and delete folders, and move or colour an item. Every argument is validated: ids are UUID-shaped and must name
//! an existing folder or a listed item, a colour is a palette id or null, a name passes the folder-name rule (and
//! is bounded here first), the delete mode is allow-listed.

use macvpn_app_core::folders;
use std::sync::Arc;
use tauri::State;

use crate::commands::validate_key;
use crate::state::AppState;

type Shared<'a> = State<'a, Arc<AppState>>;

/// A folder name argument, before the folder-name rule (64 characters) is applied by the core.
const MAX_NAME_BYTES: usize = 1024;
/// The longest palette id (`purple`, `indigo`, …).
const MAX_COLOR_BYTES: usize = 16;

fn bounded_name(name: &str) -> Result<(), String> {
    if name.len() > MAX_NAME_BYTES { Err("name too long".into()) } else { Ok(()) }
}

fn bounded_color(color: Option<&str>) -> Result<(), String> {
    if color.is_some_and(|c| c.len() > MAX_COLOR_BYTES) { Err("invalid colour".into()) } else { Ok(()) }
}

fn ids(values: &[Option<&str>]) -> Result<(), String> {
    values.iter().flatten().try_for_each(|id| validate_key(id))
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, String> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(|e| e.to_string())
}

/// "New folder" in `parent` (null: the top level); the new folder's id.
#[tauri::command]
pub async fn folder_create(state: Shared<'_>, parent: Option<String>, name: String) -> Result<String, String> {
    ids(&[parent.as_deref()])?;
    bounded_name(&name)?;
    let shared = state.inner().clone();
    blocking(move || folders::create(&shared.manager, parent.as_deref(), &name)).await?
}

#[tauri::command]
pub async fn folder_rename(state: Shared<'_>, id: String, name: String) -> Result<(), String> {
    ids(&[Some(&id)])?;
    bounded_name(&name)?;
    let shared = state.inner().clone();
    blocking(move || folders::rename(&shared.manager, &id, &name)).await?
}

#[tauri::command]
pub async fn folder_set_color(state: Shared<'_>, id: String, color: Option<String>) -> Result<(), String> {
    ids(&[Some(&id)])?;
    bounded_color(color.as_deref())?;
    let shared = state.inner().clone();
    blocking(move || folders::set_color(&shared.manager, &id, color.as_deref())).await?
}

#[tauri::command]
pub async fn folder_set_collapsed(state: Shared<'_>, id: String, collapsed: bool) -> Result<(), String> {
    ids(&[Some(&id)])?;
    let shared = state.inner().clone();
    blocking(move || folders::set_collapsed(&shared.manager, &id, collapsed)).await?
}

/// Moves or reorders a folder: under `parent` (null: the top level) at `position` among its subfolders.
#[tauri::command]
pub async fn folder_move(state: Shared<'_>, id: String, parent: Option<String>, position: usize) -> Result<(), String> {
    ids(&[Some(&id), parent.as_deref()])?;
    let shared = state.inner().clone();
    blocking(move || folders::move_folder(&shared.manager, &id, parent.as_deref(), position)).await?
}

/// `mode`: `moveUp` or `deleteContents`. The deleted connections get the delete's usual clean-up (their native
/// log collection stopped, the Profiles pane opened for a native one where the platform does not remove its
/// profile itself), then a refresh.
#[tauri::command]
pub async fn folder_delete(window: tauri::Window, state: Shared<'_>, id: String, mode: String) -> Result<(), String> {
    crate::guard::only(&window, "folder_delete", crate::manage::MANAGE_WINDOW)?;
    ids(&[Some(&id)])?;
    let shared = state.inner().clone();
    blocking(move || {
        let deleted = folders::delete(&shared.manager, &shared.connections, &id, &mode)?;
        for c in &deleted {
            shared.native_logs.remove(&c.id);
        }
        if deleted.iter().any(|c| c.kind.is_native())
            && crate::manage::opens_native_settings_after_delete(
                shared.native_profiles.removes_profiles(),
                shared.env.sandbox,
            )
        {
            crate::platform::get().shell().open_native_profile_settings();
        }
        if !deleted.is_empty() {
            shared.manager.refresh();
        }
        Ok(())
    })
    .await?
}

/// An item (a managed connection or a system VPN) into `folder` (null: the top level).
#[tauri::command]
pub async fn item_move(state: Shared<'_>, key: String, folder: Option<String>) -> Result<(), String> {
    ids(&[Some(&key), folder.as_deref()])?;
    let shared = state.inner().clone();
    blocking(move || folders::move_item(&shared.manager, &key, folder.as_deref())).await?
}

/// An item's own colour (null: "Use folder colour").
#[tauri::command]
pub async fn item_set_color(state: Shared<'_>, key: String, color: Option<String>) -> Result<(), String> {
    ids(&[Some(&key)])?;
    bounded_color(color.as_deref())?;
    let shared = state.inner().clone();
    blocking(move || folders::set_item_color(&shared.manager, &key, color.as_deref())).await?
}
