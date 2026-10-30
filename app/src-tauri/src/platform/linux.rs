//! Linux: `LinPlatform` (`macvpn-platform-linux`) and the Tauri glue: the `GtkWindow` handle, one instance per user
//! and session bus (a second launch forwards its files), the files of this launch (`linvpn %F`), the exit hook for
//! SIGTERM, the tray icon and the card panel.
//!
//! Spike L0-2's answers (CP-L0, 2026-10-29): the tray is LinVPN's own StatusNotifierItem (variant S; Tauri's Linux
//! tray delivers no click), and the card panel on Wayland is the popover window as a transparent maximized overlay
//! (`FORCE_X11 = false`: Mutter centres every positioned toplevel and GNOME has no layer shell). The overlay covers
//! the work area of its monitor, the page draws the card at its top-right (8 px below the top bar), and the GDK
//! window's input region is the card's rectangle, so a click anywhere else passes through to the window below (and
//! takes the focus, which hides the panel). GTK resets the input shape on every size allocation, so the region is
//! applied again from `size-allocate`. Every window carries the program name `linvpn` as its Wayland app id (the
//! `.deb`'s desktop entry `linvpn.desktop`), so the dock shows LinVPN's icon for them, the overlay's too.

use gtk::glib::object::ObjectType;
use gtk::prelude::{GtkWindowExt, WidgetExt};
use macvpn_app_core::open_files::{ShowYourself, show_yourself as show_yourself_decision};
use macvpn_platform_api::{NativeWindow, Platform};
use macvpn_platform_linux::pure::placement::{card_input_rect, panel_position};
use macvpn_platform_linux::{Claim, InstanceGuard, LinPlatform, SniTray, TrayEvent};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use tauri::{AppHandle, Manager, Url, WebviewWindow};

use crate::state::AppState;

static PLATFORM: OnceLock<LinPlatform> = OnceLock::new();
static INSTANCE: OnceLock<InstanceGuard> = OnceLock::new();
static OWN_TRAY: OnceLock<SniTray> = OnceLock::new();
/// The card's rectangle in the overlay as the page reported it last (CSS pixels: left, top, width, height).
static CARD: Mutex<Option<(f64, f64, f64, f64)>> = Mutex::new(None);

/// The first call decides (`sandbox`: memory key store and preferences, no D-Bus at construction).
pub fn init(sandbox: bool) -> &'static dyn Platform {
    PLATFORM.get_or_init(|| LinPlatform::new(sandbox))
}

pub fn get() -> Option<&'static dyn Platform> {
    PLATFORM.get().map(|p| p as &'static dyn Platform)
}

/// The window's `GtkWindow *` (the `GtkApplicationWindow` Tauri builds; `lin::chrome` takes its own reference).
pub fn native_window(w: &tauri::WebviewWindow) -> Option<NativeWindow> {
    w.gtk_window().ok().map(|g| NativeWindow(g.as_ptr().cast()))
}

/// The same for a window whose web view is not attached yet (a window just created).
pub fn native_window_of(w: &tauri::Window) -> Option<NativeWindow> {
    w.gtk_window().ok().map(|g| NativeWindow(g.as_ptr().cast()))
}

/// The absolute file arguments of this launch (the desktop entry's `linvpn %F`); options are not files.
fn launch_files() -> Vec<PathBuf> {
    macvpn_platform_linux::pure::instance::launch_files(std::env::args_os().skip(1))
}

fn urls(paths: &[PathBuf]) -> Vec<Url> {
    paths.iter().filter_map(|p| Url::from_file_path(p).ok()).collect()
}

/// Before Tauri: the first launch owns the session-bus name; a later one hands its files over and exits 0.
/// `--after-update` (the updater's relaunch) waits for the old process to let go. No session bus: LinVPN runs anyway
/// (a desktop without one has no tray either; the control socket's lock still keeps one control server per user).
pub fn claim_instance() -> bool {
    let sandbox = super::Environment::sandbox_home().ok().flatten();
    let after_update = std::env::args_os().any(|a| a == "--after-update");
    match macvpn_platform_linux::claim_instance(sandbox.as_deref(), &launch_files(), after_update) {
        Ok(Claim::First(guard)) => {
            let _ = INSTANCE.set(guard);
            true
        }
        Ok(Claim::Forwarded) => false,
        Err(e) => {
            eprintln!("LinVPN: single instance: {e}");
            true
        }
    }
}

/// At setup: the NetworkManager engine is prepared in the background (`LinPlatform::prepare_engine`); SIGTERM's
/// quit goes through `AppHandle::exit`; this launch's files go through the same handler as macOS'
/// `RunEvent::Opened` (queued behind the setup); later launches arrive through the single-instance name (an empty
/// list: [`show_yourself`]); the installed LinVPN watches its package ([`watch_package_upgrade`]). A process the
/// supervisor started again logs why.
pub fn configure_app(app: &mut tauri::App) {
    if let Some(reason) = restart_reason() {
        eprintln!("LinVPN: started again by its supervisor: the previous app process ended unexpectedly ({reason})");
    }
    // The NetworkManager engine: a crashed run's runtime files swept, the secret agent registered (not in the
    // sandbox; a thread of its own, NetworkManager may be slow to answer).
    if let Some(platform) = PLATFORM.get() {
        let _ = std::thread::Builder::new().name("linvpn-nm-prepare".into()).spawn(|| platform.prepare_engine());
    }
    let handle = app.handle().clone();
    let exit = handle.clone();
    macvpn_platform_linux::set_exit_hook(Box::new(move || exit.exit(0)));
    watch_package_upgrade(&handle);
    let files = urls(&launch_files());
    if !files.is_empty() {
        let h = handle.clone();
        let _ = handle.run_on_main_thread(move || crate::open_files::opened(&h, &files));
    }
    if let Some(guard) = INSTANCE.get() {
        let h = handle.clone();
        guard.listen(Box::new(move |paths| {
            let target = h.clone();
            let _ = h.run_on_main_thread(move || {
                if paths.is_empty() {
                    show_yourself(&target);
                } else {
                    crate::open_files::opened(&target, &urls(&paths));
                }
            });
        }));
    }
}

/// The installed LinVPN (`/usr/bin/linvpn`, not the sandbox) restarts into a package upgraded from outside the app
/// (`apt-get install ./linvpn_*.deb`): `macvpn_platform_linux::watch_package_upgrade` relaunches it as the in-app
/// update does, then the app quits at once (`commands::terminate`: no quit questions, the tunnels stay up). It
/// waits while the editor has unsaved changes and while the in-app update installs (that one relaunches itself;
/// `is_installing` stays set until the app quits).
fn watch_package_upgrade(app: &AppHandle) {
    let Some(state) = app.try_state::<Arc<AppState>>() else { return };
    let state = state.inner().clone();
    // `bundle`: `/usr/bin/linvpn` when this process is the installed binary (none for a development build).
    if state.env.sandbox || state.env.bundle.is_none() {
        return;
    }
    let busy = {
        let state = state.clone();
        Box::new(move || state.connections.has_unsaved_changes() || state.updates.is_installing())
    };
    let home = state.env.home.clone();
    let app = app.clone();
    let quit = Box::new(move || crate::commands::terminate(&app, &state));
    macvpn_platform_linux::watch_package_upgrade(home, env!("CARGO_PKG_VERSION").into(), busy, quit);
}

/// As on Windows: an open window comes forward, else Connections (or the vault's window while it is closed). The
/// windows are built on a thread of their own (not from the main thread's queue).
fn show_yourself(app: &AppHandle) {
    let Some(state) = app.try_state::<Arc<AppState>>() else { return };
    let open = crate::dock::DOCK_WINDOWS.iter().any(|label| app.get_webview_window(label).is_some());
    match show_yourself_decision(open, crate::open_files::vault_ready(&state)) {
        ShowYourself::BringForward => crate::dock::reopen(app),
        ShowYourself::Connections => {
            let app = app.clone();
            std::thread::spawn(move || {
                if let Err(e) = crate::commands::open(&app, crate::manage::MANAGE_WINDOW) {
                    eprintln!("LinVPN: the Connections window: {e}");
                }
            });
        }
        ShowYourself::Vault => {
            let (app, state) = (app.clone(), state.inner().clone());
            std::thread::spawn(move || crate::open_files::show_vault_window(&app, &state));
        }
    }
}

/// GNOME shows every real window in its overview and dock by itself.
pub fn set_window_presence(_app: &AppHandle, _shown: bool) {}

/// Linux has no `Reopen` / `Opened` run events: a second launch arrives through [`configure_app`]'s listener.
pub fn on_run_event(_app: &AppHandle, _event: &tauri::RunEvent) {}

/// First thing in `main`, before any thread and before GTK: the program name (the windows' app id `linvpn`) and
/// WebKit's renderer (`macvpn_platform_linux::prepare_process`).
pub fn harden_dll_search() {
    macvpn_platform_linux::prepare_process();
}

pub fn helper_mode() -> Option<i32> {
    None
}

/// The `.deb` update relaunches through `linvpn --after-update` (a normal launch), never a mode of its own.
pub fn relaunch() -> bool {
    false
}

/// The installed LinVPN supervises its GUI process (`macvpn_platform_linux::supervise`; not the sandbox, not a
/// development build).
pub fn supervise() -> Option<i32> {
    let sandbox = !matches!(super::Environment::sandbox_home(), Ok(None));
    macvpn_platform_linux::supervise(sandbox)
}

pub fn restart_reason() -> Option<String> {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    macvpn_platform_linux::pure::supervisor::restart_reason(&args)
}

#[cfg(debug_assertions)]
pub fn test_install_mode() -> Option<i32> {
    None
}

pub fn supported() -> Result<(), String> {
    Ok(())
}

/// No app menu: the windows keep their native text shortcuts and Quit is in the panel and the tray's menu.
pub fn uses_app_menu() -> bool {
    false
}

// MARK: - The tray icon

/// LinVPN's StatusNotifierItem. Its clicks arrive on ksni's thread and go to the main thread: `Toggle` (a double or
/// middle click) shows or hides the panel, the menu's "Open LinVPN" only shows it, "Quit LinVPN" is the menu's Quit.
pub fn create_own_tray(app: &AppHandle, rgba: &[u8], width: u32, height: u32, tooltip: &str) -> bool {
    let target = app.clone();
    let on_event = move |event: TrayEvent| {
        let app = target.clone();
        let _ = target.run_on_main_thread(move || match event {
            TrayEvent::Toggle { token, .. } => crate::tray::toggle_menu_activated(&app, token),
            TrayEvent::Open { token } => crate::tray::show_menu_activated(&app, token),
            TrayEvent::Quit => {
                if let Some(state) = app.try_state::<Arc<AppState>>() {
                    crate::commands::request_quit(&app, &state, macvpn_app_core::quit::QuitOrigin::Menu);
                }
            }
        });
    };
    match SniTray::spawn(rgba, width, height, tooltip, on_event) {
        Ok(tray) => OWN_TRAY.set(tray).is_ok(),
        Err(e) => {
            eprintln!("LinVPN: the tray icon: {e}");
            false
        }
    }
}

pub fn set_own_tray_icon(rgba: &[u8], width: u32, height: u32, tooltip: &str) -> bool {
    match OWN_TRAY.get() {
        Some(tray) => {
            tray.set_icon(rgba, width, height, tooltip);
            true
        }
        None => false,
    }
}

// MARK: - The card panel (the overlay)

/// The overlay's window: resizable for GTK (a window with a fixed size cannot be maximized; it has no frame to drag),
/// and its input region kept after every size allocation (GtkWindow resets the input shape there).
pub fn prepare_menu_window(window: &WebviewWindow) {
    let Ok(gtk_window) = window.gtk_window() else {
        eprintln!("LinVPN: the panel has no GTK window");
        return;
    };
    gtk_window.set_resizable(true);
    gtk_window.connect_size_allocate(|w, _| apply_input_region(w));
}

pub fn menu_is_overlay() -> bool {
    true
}

/// The activation token the tray's host sent (Mutter's focus rules), then maximized (the work area of its monitor)
/// before it is shown, so no frame at the popover's own size is ever drawn.
pub fn present_menu_overlay(window: &WebviewWindow, activation_token: Option<&str>) -> bool {
    let Ok(gtk_window) = window.gtk_window() else { return false };
    if let Some(token) = activation_token {
        gtk_window.set_startup_id(token);
    }
    // tao puts back the config's `resizable: false` at the first configure event.
    gtk_window.set_resizable(true);
    gtk_window.maximize();
    apply_input_region(&gtk_window);
    true
}

pub fn set_menu_card(window: &WebviewWindow, card: (f64, f64, f64, f64)) {
    *CARD.lock().unwrap_or_else(PoisonError::into_inner) = Some(card);
    if let Ok(gtk_window) = window.gtk_window() {
        apply_input_region(&gtk_window);
    }
}

/// Only the card takes input (`pure::placement::card_input_rect`; GDK's window coordinates are logical pixels, as
/// the page's CSS pixels are).
fn apply_input_region(window: &gtk::ApplicationWindow) {
    let Some(gdk_window) = window.window() else { return };
    let size = (u32::try_from(gdk_window.width()).unwrap_or(0), u32::try_from(gdk_window.height()).unwrap_or(0));
    let card = *CARD.lock().unwrap_or_else(PoisonError::into_inner);
    let (x, y, width, height) = card_input_rect(size, card);
    let region = gtk::cairo::Region::create_rectangle(&gtk::cairo::RectangleInt::new(x, y, width, height));
    gdk_window.input_shape_combine_region(&region, 0, 0);
}

/// The work area's top-right corner (outside the overlay: the Xwayland fallback's explicit position).
pub fn corner_position(work_area: (i32, i32, u32, u32), window: (u32, u32)) -> Option<(i32, i32)> {
    Some(panel_position(work_area, window))
}

/// The IPsec SAs' counters through `linvpn-xfrmd` (charon-nm has no interface of its own).
pub fn ikev2_reports_liveness() -> bool {
    true
}

/// NetworkManager's strongSwan plugin takes the client certificate and key as files: at connect the engine writes the
/// imported ones (PEM) into the connection's private runtime directory (`nm_plan::strongswan`).
pub fn imports_client_certificates() -> bool {
    true
}

/// charon-nm loads `usercert` as an X.509 certificate only: a PKCS#12 file is converted to PEM at import with the
/// system's `openssl pkcs12` (`macvpn_platform_linux::convert_pkcs12`).
pub fn pkcs12_converter() -> Option<macvpn_app_core::connections::Pkcs12Converter> {
    Some(std::sync::Arc::new(|der: &[u8], password: &str| macvpn_platform_linux::convert_pkcs12(der, password)))
}

/// LinVPN's strongSwan credential folder (`$XDG_DATA_HOME/LinVPN/swanctl`), whose `x509` / `x509ca` files the
/// IKEv2 plan uses for `certs` / `cacerts`.
pub fn swanctl_folder() -> Option<std::path::PathBuf> {
    PLATFORM.get().map(LinPlatform::swanctl_folder)
}
