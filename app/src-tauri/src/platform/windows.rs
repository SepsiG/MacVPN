//! Windows: `WinPlatform` (`macvpn-platform-win`) and the Tauri glue: the `HWND`, one instance per user (a second
//! launch forwards its files), the files of this launch, no app menu, no Dock-like presence (Windows shows a taskbar
//! button for each real window by itself).

use macvpn_app_core::open_files::{ShowYourself, show_yourself as show_yourself_decision};
use macvpn_platform_api::{NativeWindow, Platform};
use macvpn_platform_win::{Claim, InstanceGuard, WinPlatform, claim};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use tauri::{AppHandle, Manager, Url};

use crate::state::AppState;

static PLATFORM: OnceLock<WinPlatform> = OnceLock::new();
static INSTANCE: OnceLock<InstanceGuard> = OnceLock::new();

/// The first call decides (`sandbox`: memory key store and preferences). Main thread, before any window.
pub fn init(sandbox: bool) -> &'static dyn Platform {
    PLATFORM.get_or_init(|| WinPlatform::new(sandbox))
}

pub fn get() -> Option<&'static dyn Platform> {
    PLATFORM.get().map(|p| p as &'static dyn Platform)
}

/// The window's `HWND`.
pub fn native_window(w: &tauri::WebviewWindow) -> Option<NativeWindow> {
    w.hwnd().ok().map(|hwnd| NativeWindow(hwnd.0))
}

/// The same for a window whose web view is not attached yet (a window just created).
pub fn native_window_of(w: &tauri::Window) -> Option<NativeWindow> {
    w.hwnd().ok().map(|hwnd| NativeWindow(hwnd.0))
}

/// The absolute file arguments of this launch (Explorer passes `"%1"`).
fn launch_files() -> Vec<PathBuf> {
    std::env::args_os().skip(1).map(PathBuf::from).filter(|p| p.is_absolute()).collect()
}

fn urls(paths: &[PathBuf]) -> Vec<Url> {
    paths.iter().filter_map(|p| Url::from_file_path(p).ok()).collect()
}

pub fn claim_instance() -> bool {
    match claim(&launch_files()) {
        Ok(Claim::First(guard)) => {
            let _ = INSTANCE.set(guard);
            true
        }
        Ok(Claim::Forwarded) => false,
        // Fails closed (`claim`'s contract): a first instance that does not answer, a name taken by someone else or
        // files the message cannot carry never lead to a second WinVPN on the same data. A GUI app has no console:
        // the user is told in a message box before WinVPN exits.
        Err(e) => {
            eprintln!("WinVPN: single instance: {e}");
            macvpn_platform_win::show_claim_failure(&e);
            std::process::exit(1);
        }
    }
}

/// At setup: this launch's files go through the same handler as macOS' `RunEvent::Opened` (queued behind the
/// setup, so the open-files state is attached first); later launches arrive through the forwarding pipe (an empty
/// list: [`show_yourself`]).
pub fn configure_app(app: &mut tauri::App) {
    let handle = app.handle().clone();
    let files = urls(&launch_files());
    if !files.is_empty() {
        let h = handle.clone();
        let _ = handle.run_on_main_thread(move || crate::open_files::opened(&h, &files));
    }
    if let Some(guard) = INSTANCE.get() {
        let h = handle.clone();
        let listening = guard.listen(Box::new(move |paths| {
            let target = h.clone();
            let _ = h.run_on_main_thread(move || {
                if paths.is_empty() {
                    show_yourself(&target);
                } else {
                    crate::open_files::opened(&target, &urls(&paths));
                }
            });
        }));
        if let Err(e) = listening {
            eprintln!("WinVPN: the open-files pipe: {e}");
        }
    }
}

/// A second launch without files (Start menu, a shortcut): an open window comes forward; with only the tray
/// running, the Connections window opens (or the vault's window while the vault is closed), so the launch always
/// shows something. Main thread; the windows are built on a thread of their own (building one from the main
/// thread's queue would wait for the main thread itself on Windows).
fn show_yourself(app: &AppHandle) {
    let Some(state) = app.try_state::<Arc<AppState>>() else { return };
    let open = crate::dock::DOCK_WINDOWS.iter().any(|label| app.get_webview_window(label).is_some());
    match show_yourself_decision(open, crate::open_files::vault_ready(&state)) {
        ShowYourself::BringForward => crate::dock::reopen(app),
        ShowYourself::Connections => {
            let app = app.clone();
            std::thread::spawn(move || {
                if let Err(e) = crate::commands::open(&app, crate::manage::MANAGE_WINDOW) {
                    eprintln!("WinVPN: the Connections window: {e}");
                }
            });
        }
        ShowYourself::Vault => {
            let (app, state) = (app.clone(), state.inner().clone());
            std::thread::spawn(move || crate::open_files::show_vault_window(&app, &state));
        }
    }
}

/// Windows shows a taskbar button for every visible window except the popover (`skipTaskbar`).
pub fn set_window_presence(_app: &AppHandle, _shown: bool) {}

/// Windows has no `Reopen` / `Opened` run events: a second launch arrives through [`configure_app`]'s pipe.
pub fn on_run_event(_app: &AppHandle, _event: &tauri::RunEvent) {}

/// The process' DLL search: System32 only (`macvpn_winsys::dll::harden_process_search`); first thing in `main`.
pub fn harden_dll_search() {
    macvpn_platform_win::harden_dll_search();
}

/// `WinVPN.exe --winvpn-openvpn-step …` (started elevated by System Status' OpenVPN install) and `WinVPN.exe
/// --winvpn-trust-ca-step <file>` (started elevated by **Trust This CA in Windows…**).
pub fn helper_mode() -> Option<i32> {
    let args = text_args()?;
    // The steps' codes have bit 29 set and fit an i32 (`pure::openvpn_install::StepResult::code`,
    // `pure::admin_steps::TrustStep::code`).
    macvpn_platform_win::openvpn_elevated_step(&args)
        .or_else(|| macvpn_platform_win::trust_ca_elevated_step(&args))
        .map(|code| code as i32)
}

/// The arguments as text; `None` when one is not Unicode (then no special mode applies).
fn text_args() -> Option<Vec<String>> {
    std::env::args_os().skip(1).map(|a| a.into_string().ok()).collect()
}

/// No supervisor on Windows.
pub fn supervise() -> Option<i32> {
    None
}

pub fn restart_reason() -> Option<String> {
    None
}

/// `--relaunch --target <WinVPN.exe> --msi <msi> --sha256 <hex> --log <log>` exactly
/// (`pure::update::parse_relaunch`): runs the relauncher and returns `true`.
pub fn relaunch() -> bool {
    let Some(relaunch) = text_args().and_then(|a| macvpn_platform_win::pure::update::parse_relaunch(&a)) else {
        return false;
    };
    macvpn_platform_win::relaunch_after(&relaunch);
    true
}

/// Debug builds only (CP2): `WinVPN.exe --test-install-msi <absolute path>` installs that MSI as an update would
/// (held deny-write, msiexec through UAC, the relauncher), without download or signature. `scripts/build-msi.sh`
/// refuses a release WinVPN.exe that contains the option.
#[cfg(debug_assertions)]
pub fn test_install_mode() -> Option<i32> {
    let args = text_args()?;
    let [flag, msi] = args.as_slice() else { return None };
    if flag != "--test-install-msi" {
        return None;
    }
    match macvpn_platform_win::test_install_msi(std::path::Path::new(msi)) {
        Ok(message) => {
            println!("WinVPN: {message}");
            Some(0)
        }
        Err(e) => {
            eprintln!("WinVPN: --test-install-msi: {e}");
            Some(1)
        }
    }
}

pub fn supported() -> Result<(), String> {
    Ok(())
}

pub fn uses_app_menu() -> bool {
    false
}

/// Tauri's tray icon (no own one).
pub fn create_own_tray(_app: &AppHandle, _rgba: &[u8], _width: u32, _height: u32, _tooltip: &str) -> bool {
    false
}

pub fn set_own_tray_icon(_rgba: &[u8], _width: u32, _height: u32, _tooltip: &str) -> bool {
    false
}

/// The popover is a plain window at its tray icon (no overlay).
pub fn prepare_menu_window(_window: &tauri::WebviewWindow) {}

pub fn menu_is_overlay() -> bool {
    false
}

pub fn present_menu_overlay(_window: &tauri::WebviewWindow, _activation_token: Option<&str>) -> bool {
    false
}

pub fn set_menu_card(_window: &tauri::WebviewWindow, _card: (f64, f64, f64, f64)) {}

/// The tray icon's rectangle gives the place.
pub fn corner_position(_work_area: (i32, i32, u32, u32), _window: (u32, u32)) -> Option<(i32, i32)> {
    None
}

/// None: no import on Windows (see `imports_client_certificates`).
pub fn pkcs12_converter() -> Option<macvpn_app_core::connections::Pkcs12Converter> {
    None
}

pub fn ikev2_reports_liveness() -> bool {
    false
}

pub fn imports_client_certificates() -> bool {
    false
}

/// None: Windows' IKEv2 authenticates with a certificate of the computer's store, not with swanctl files.
pub fn swanctl_folder() -> Option<std::path::PathBuf> {
    None
}
