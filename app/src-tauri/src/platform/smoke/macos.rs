//! The smoke driver's macOS-only part (debug builds on macOS): what reads AppKit back (the popover's shape, the
//! window numbers for `screencapture`, the Dock icon's activation policy, the forced appearance), the screenshots,
//! the old Keychain items the migration moves, the mock Homebrew report and the DMG update's sandbox steps. The
//! portable driver (`super`) calls these through `#[cfg(target_os = "macos")]` lines; on Windows and Linux those
//! steps print `MacVPN smoke: <step>: skipped on Windows` / `… on Linux`. The plain Unix helpers are in `unix.rs`.

use macvpn_core::update::Release;
use macvpn_platform_api::{SetupReport, SmokeHooks, UpdateOutcome};
use macvpn_platform_mac::temp_dir::{make_private_temp_directory, write_script};
use macvpn_platform_mac::update_installer::{self, InstallerError, UpdateSteps, VerifiedDownload};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tauri::{AppHandle, Manager};

use super::{SEEDED_L2TP, SEEDED_PSK, eval, wait_for};
use crate::platform::Environment;
use crate::platform::macos::mac;

/// A smoke run seeds the sandbox's in-memory "old Keychain" with one item (`SEEDED_L2TP`'s PSK).
pub(super) fn seed_legacy_keychain() {
    mac().seed_legacy_keychain(&[(
        "local.macvpn.secrets".to_string(),
        format!("{SEEDED_L2TP}.psk"),
        SEEDED_PSK.as_bytes().to_vec(),
    )]);
}

/// MACVPN_SMOKE_DARK (`SMOKE_DARK=1`): the app's windows in dark mode, for the screenshots; MACVPN_SMOKE_LIGHT
/// (`SMOKE_LIGHT=1`): in light mode, whatever the system's setting.
pub(super) fn appearance() {
    if std::env::var_os("MACVPN_SMOKE_DARK").is_some() {
        eprintln!("MacVPN smoke: dark={}", mac().force_appearance(true));
    } else if std::env::var_os("MACVPN_SMOKE_LIGHT").is_some() {
        eprintln!("MacVPN smoke: light={}", mac().force_appearance(false));
    }
}

/// The mock System Status report: Homebrew is there, `sstpc` is missing, root layer 7 is installed (8 bundled).
pub(super) fn mock_report() -> SetupReport {
    SetupReport {
        package_manager: Some("/opt/homebrew".into()),
        required_tools: &macvpn_platform_mac::setup_checker::SetupChecker::REQUIRED_TOOLS,
        missing_tools: vec!["sstpc".into()],
        installed_root_version: Some("7".into()),
        bundled_root_version: Some("8".into()),
        sudo_works: true,
        missing_root_files: vec![],
        engine_missing: None,
        engine: None,
        later_kinds: Vec::new(),
        outdated_packages: Vec::new(),
        ras: None,
        ras_unsupported_kinds: Vec::new(),
        nm: None,
    }
}

/// The mock report with the root layer up to date: the control API's client may connect.
pub(super) fn ready_report() -> SetupReport {
    SetupReport { installed_root_version: Some("8".into()), ..mock_report() }
}

/// [`ready_report`] once `sstpc` was installed (outside the app): nothing missing.
pub(super) fn installed_report() -> SetupReport {
    SetupReport { missing_tools: Vec::new(), ..ready_report() }
}

/// The update steps in the sandbox (see the module docs).
pub(super) struct SandboxUpdate {
    tmp: PathBuf,
    cache: PathBuf,
}

impl SandboxUpdate {
    pub fn new(env: &Environment) -> Self {
        SandboxUpdate {
            tmp: env.staging_parent().unwrap_or_else(|| env.home.join("tmp")),
            cache: env.home.join("Library/Caches/MacVPN"),
        }
    }

    fn pause() {
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// The update in the sandbox: `install_update` over [`SandboxUpdate`], for `<sandbox>/Applications/MacVPN.app`.
pub(super) fn update_install(
    env: &Environment,
    release: &Release,
    stage: &dyn Fn(String),
    confirm_quit: Box<dyn FnOnce() -> bool + '_>,
) -> Result<UpdateOutcome, String> {
    let steps = SandboxUpdate::new(env);
    let bundle = env.home.join("Applications/MacVPN.app");
    let pid = i32::try_from(std::process::id()).map_err(|e| e.to_string())?;
    update_installer::install_update(&steps, release, &bundle, pid, |s| stage(s.message()), confirm_quit)
        .map_err(|e| e.to_string())
}

impl UpdateSteps for SandboxUpdate {
    fn check_install_target(&self, bundle: &Path) -> Result<PathBuf, InstallerError> {
        Self::pause();
        Ok(bundle.to_path_buf())
    }

    fn download_verified(&self, release: &Release) -> Result<VerifiedDownload, InstallerError> {
        Self::pause();
        let directory = make_private_temp_directory("macvpn-download", &self.tmp)?;
        let dmg = directory.join(&release.package.name);
        std::fs::write(&dmg, b"sandbox")?;
        Ok(VerifiedDownload { dmg, directory, sha256: "0".repeat(64) })
    }

    fn mount(&self, _download: &VerifiedDownload) -> Result<String, InstallerError> {
        Self::pause();
        let mount = make_private_temp_directory("macvpn-mount", &self.tmp)?;
        Ok(mount.to_string_lossy().into_owned())
    }

    fn verify_app(&self, _app: &Path, _expected_version: &str) -> Result<(), InstallerError> {
        Self::pause();
        Ok(())
    }

    fn write_helper(&self, make_script: &dyn Fn(&Path) -> String) -> Result<PathBuf, InstallerError> {
        let dir = make_private_temp_directory("macvpn-update", &self.tmp)?;
        Ok(write_script(&make_script(&dir), &dir, "update.sh")?)
    }

    fn launch_helper(&self, script: &Path) -> Result<(), InstallerError> {
        eprintln!("MacVPN (sandbox): update helper written, not run: {}", script.display());
        Ok(())
    }

    fn detach(&self, mount_point: &str) {
        let _ = std::fs::remove_dir_all(mount_point);
    }

    fn cache_directory(&self) -> PathBuf {
        self.cache.clone()
    }
}

/// The popover shown: its rounded corners as AppKit holds them (`MacVPN smoke: menu: shape …`), with the window
/// number. With `MACVPN_SMOKE_SHOTS` set, it stays shown until the shell took its screenshot ([`shoot`]); then it
/// hides.
pub(super) fn menu_shape(app: &AppHandle) {
    let Some(window) = app.get_webview_window(crate::tray::MENU_WINDOW) else {
        return eprintln!("MacVPN smoke: menu: ERROR no menu window");
    };
    crate::tray::show_menu(app);
    std::thread::sleep(Duration::from_secs(2));
    let (tx, rx) = std::sync::mpsc::channel();
    let target = window.clone();
    let _ = window.run_on_main_thread(move || {
        let _ = tx.send(crate::platform::native_window(&target).and_then(|w| mac().window_shape(w)));
    });
    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(Some(shape)) => eprintln!(
            "MacVPN smoke: menu: shape radius={} masks={} opaque={} shadow={} window={}",
            shape.radius, shape.masks, shape.opaque, shape.shadow, shape.number
        ),
        _ => eprintln!("MacVPN smoke: menu: ERROR no shape"),
    }
    shoot(app, crate::tray::MENU_WINDOW, "menu", Duration::ZERO);
    crate::tray::hide_menu(app);
}

/// With screenshots on: the Connections window with the folder tree and its Credentials section open.
pub(super) fn manage_shot(app: &AppHandle) {
    if shots_dir().is_none() {
        return;
    }
    if let Err(e) = crate::commands::open(app, "manage") {
        return eprintln!("MacVPN smoke: shot manage-credentials ERROR {e}");
    }
    std::thread::sleep(Duration::from_secs(1));
    if let Some(window) = app.get_webview_window("manage") {
        let _ = window.eval("document.querySelector('button.shared-credentials')?.click();");
    }
    shoot(app, "manage", "manage-credentials", Duration::from_secs(2));
}

/// With screenshots on: the Connections window with the New menu open, then a connection's context menu at the
/// window's right edge (`popover-shots.js`; manage.js checks they lie inside the window), then the search with
/// results and with none.
pub(super) fn popover_shots(app: &AppHandle, dir: &Path) {
    if shots_dir().is_none() {
        return;
    }
    let source = match std::fs::read_to_string(dir.join("popover-shots.js")) {
        Ok(source) => source,
        Err(e) => return eprintln!("MacVPN smoke: shot new-menu ERROR {e}"),
    };
    if let Err(e) = crate::commands::open(app, "manage").and_then(|()| eval(app, "manage", with_shot(&source))) {
        return eprintln!("MacVPN smoke: shot new-menu ERROR {e}");
    }
    shoot(app, "manage", "new-menu", Duration::from_secs(1));
    shoot(app, "manage", "context-menu", Duration::from_secs(2));
    shoot(app, "manage", "search-results", Duration::from_secs(2));
    shoot(app, "manage", "search-empty", Duration::from_secs(2));
}

/// `MACVPN_SMOKE_SHOTS`: where the shell puts the screenshots (`scripts/smoke-manage.sh`, `SMOKE_SHOTS`).
fn shots_dir() -> Option<PathBuf> {
    std::env::var_os("MACVPN_SMOKE_SHOTS").map(PathBuf::from)
}

/// A window script that waits for its screenshot (`window.smokeShot`) when screenshots are on.
pub(super) fn with_shot(source: &str) -> String {
    if shots_dir().is_some() { format!("window.smokeShot = 'pending';\n{source}") } else { source.to_string() }
}

/// The window's number for `screencapture -l` (read on the main thread).
fn window_number(app: &AppHandle, label: &str) -> Option<isize> {
    let window = app.get_webview_window(label)?;
    let (tx, rx) = std::sync::mpsc::channel();
    let target = window.clone();
    let _ = window.run_on_main_thread(move || {
        let _ = tx.send(crate::platform::native_window(&target).and_then(|w| mac().window_number(w)));
    });
    rx.recv_timeout(Duration::from_secs(5)).ok().flatten()
}

/// With screenshots on: after `settle`, logs `MacVPN smoke: shot <name> window=<number>`, waits until the shell
/// took it (`<dir>/<name>.done`, at most 20 s) and lets the window's script go on (`window.smokeShot`).
pub(super) fn shoot(app: &AppHandle, label: &str, name: &str, settle: Duration) {
    let Some(dir) = shots_dir() else { return };
    std::thread::sleep(settle);
    let Some(number) = window_number(app, label) else {
        return eprintln!("MacVPN smoke: shot {name} ERROR no window");
    };
    eprintln!("MacVPN smoke: shot {name} window={number}");
    let done = dir.join(format!("{name}.done"));
    let _ = wait_for(20, || done.exists().then_some(()));
    if let Some(window) = app.get_webview_window(label) {
        let _ = window.eval("window.smokeShot = 'done';");
    }
}

/// `NSApp.activationPolicy` is Regular (the Dock icon is shown), read on the main thread.
pub(super) fn regular(app: &AppHandle) -> String {
    let (tx, rx) = std::sync::mpsc::channel();
    let _ = app.run_on_main_thread(move || {
        let _ = tx.send(mac().activation_policy_is_regular());
    });
    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(Some(regular)) => regular.to_string(),
        _ => "unknown".into(),
    }
}

/// The Dock icon with the windows the scripts left open: shown; a Dock click (`dock::reopen`) brings back a
/// minimized Connections window and opens nothing; once every window is closed, hidden again.
pub(super) fn dock(app: &AppHandle) {
    let open = || crate::dock::DOCK_WINDOWS.iter().filter(|l| app.get_webview_window(l).is_some()).count();
    let before = open();
    eprintln!("MacVPN smoke: dock: windows open regular={}", regular(app));
    if let Some(manage) = app.get_webview_window(crate::manage::MANAGE_WINDOW) {
        let _ = manage.minimize();
        let minimized = wait_for(5, || manage.is_minimized().ok().filter(|m| *m)).is_some();
        crate::dock::reopen(app);
        let restored = wait_for(5, || manage.is_minimized().ok().filter(|m| !*m)).is_some();
        eprintln!("MacVPN smoke: dock: reopen minimized={minimized} restored={restored} windows={before}->{}", open());
    }
    for label in crate::dock::DOCK_WINDOWS {
        if let Some(window) = app.get_webview_window(label) {
            let _ = window.close();
        }
    }
    let closed = wait_for(10, || (open() == 0).then_some(())).is_some();
    // The policy is applied on the main thread after the last window's `Destroyed`.
    std::thread::sleep(Duration::from_millis(500));
    eprintln!("MacVPN smoke: dock: closed={closed} regular={}", regular(app));
}
