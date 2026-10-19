//! Development only (debug builds): the sandbox's stand-ins for the steps that would change the system, and the
//! smoke test driver.
//!
//! - [`SandboxUpdate`]: the update steps in the sandbox. Every stage runs against `<sandbox>/tmp` (nothing is
//!   downloaded, mounted or verified), the helper script is written but never run, and "launching" it only logs.
//! - `MACVPN_SMOKE_DIR=<absolute dir>` (with `MACVPN_SANDBOX_HOME` only): mock data (a System Status report with
//!   a missing tool and an older root layer, an offered release whose notes hold markup), then the scripts of
//!   that directory run in the real windows one after the other – `manage.js` (Connections), `setup.js` (System
//!   Status), `update.js` (Update) – each finishing by renaming its seeded connection (`SMOKE …`, `SETUP …`,
//!   `UPDATE …`), and `prompt.js` answers a mock code prompt and a mock web sign-in in their prompt windows.
//!   `quit.js` (Connections) runs the quit flows' edge cases (a selection during the quit's question, the Update
//!   window closed during an install and while its question is shown; `QUIT …`). Last, `system.js` leaves an unsaved change and answers the quit question the shell's quit Apple Event
//!   raises. The results go to stderr (`MacVPN smoke: …`, first the language), ending with `MacVPN smoke: done`.
//!   `scripts/smoke-manage.sh` checks them. Release builds do not contain this module.

use macvpn_core::date::Date;
use macvpn_core::mfa::{AuthPrompt, AuthPromptKind, AuthPromptResult, PromptDeadline};
use macvpn_core::models::{parse_uuid, uuid_string};
use macvpn_core::update::{Release, ReleaseAsset};
use macvpn_platform_mac::setup_checker::SetupReport;
use macvpn_platform_mac::temp_dir::{make_private_temp_directory, write_script};
use macvpn_platform_mac::update_installer::{InstallerError, UpdateSteps, VerifiedDownload};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Manager};

use crate::platform::Environment;
use crate::state::AppState;

/// The seeded connections whose names carry the scripts' results (`scripts/smoke-manage.sh`).
const MANAGE_RESULT: &str = "11111111-2222-4333-8444-555555555555";
const SETUP_RESULT: &str = "41111111-2222-4333-8444-555555555555";
const UPDATE_RESULT: &str = "51111111-2222-4333-8444-555555555555";
const QUIT_RESULT: &str = "71111111-2222-4333-8444-555555555555";

fn smoke_dir(state: &AppState) -> Option<PathBuf> {
    let dir = std::env::var_os("MACVPN_SMOKE_DIR").map(PathBuf::from)?;
    (state.env.sandbox && dir.is_absolute()).then_some(dir)
}

/// The mock System Status report: Homebrew is there, `sstpc` is missing, root layer 6 is installed (7 bundled).
pub fn setup_report(state: &AppState) -> Option<SetupReport> {
    smoke_dir(state)?;
    Some(SetupReport {
        brew_prefix: Some("/opt/homebrew".into()),
        missing_tools: vec!["sstpc".into()],
        installed_root_version: Some("6".into()),
        bundled_root_version: Some("7".into()),
        sudo_works: true,
        missing_root_files: vec![],
    })
}

fn mock_release() -> Release {
    let asset = |name: &str| ReleaseAsset {
        name: name.into(),
        url: format!("https://github.com/SepsiG/MacVPN/releases/download/v9.9.9/{name}"),
    };
    Release {
        tag: "v9.9.9".into(),
        version: "9.9.9".into(),
        notes: "**Smoke** release with `code` and *emphasis*.\n<script>window.smokeInjected = true</script><img src=x onerror=\"window.smokeInjected = true\">\n[a link](https://example.com)".into(),
        page_url: Some("https://github.com/SepsiG/MacVPN/releases/tag/v9.9.9".into()),
        published_at: Some(Date::from_time_interval_since_1970(1_700_000_000.0)),
        dmg: asset("MacVPN-9.9.9.dmg"),
        checksum: asset("MacVPN-9.9.9.dmg.sha256"),
        signature: Some(asset("MacVPN-9.9.9.dmg.sig")),
    }
}

/// The update steps in the sandbox (see the module docs).
pub struct SandboxUpdate {
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

impl UpdateSteps for SandboxUpdate {
    fn check_install_target(&self, bundle: &Path) -> Result<PathBuf, InstallerError> {
        Self::pause();
        Ok(bundle.to_path_buf())
    }

    fn download_verified(&self, release: &Release) -> Result<VerifiedDownload, InstallerError> {
        Self::pause();
        let directory = make_private_temp_directory("macvpn-download", &self.tmp)?;
        let dmg = directory.join(&release.dmg.name);
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

pub fn start(app: &AppHandle, state: &Arc<AppState>) {
    let Some(dir) = smoke_dir(state) else {
        if std::env::var_os("MACVPN_SMOKE_DIR").is_some() {
            eprintln!("MacVPN: MACVPN_SMOKE_DIR needs MACVPN_SANDBOX_HOME and an absolute path");
        }
        return;
    };
    state.updates.consider(mock_release());
    // The language the core picked from the preferred languages (`scripts/smoke-manage.sh` can force it).
    eprintln!("MacVPN smoke: language {}", macvpn_core::l10n::AppLanguage::current().raw_value());
    let app = app.clone();
    let state = state.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(2));
        for (window, script, id, prefix) in [
            ("manage", "manage.js", MANAGE_RESULT, "SMOKE"),
            ("setup", "setup.js", SETUP_RESULT, "SETUP"),
            ("update", "update.js", UPDATE_RESULT, "UPDATE"),
        ] {
            let result = run_script(&app, &dir, window, script, &|| renamed(&state, id, prefix));
            eprintln!("MacVPN smoke: {window}: {}", result.unwrap_or_else(|e| format!("ERROR {e}")));
        }
        prompts(&app, &state, &dir);
        let result = run_script(&app, &dir, "manage", "quit.js", &|| renamed(&state, QUIT_RESULT, "QUIT"));
        eprintln!("MacVPN smoke: quit: {}", result.unwrap_or_else(|e| format!("ERROR {e}")));
        // Last: an unsaved change for the shell's quit request (logout's way, through applicationShouldTerminate).
        let ready = run_script(&app, &dir, "manage", "system.js", &|| {
            state.connections.has_unsaved_changes().then(|| "unsaved change ready".to_string())
        });
        eprintln!("MacVPN smoke: system: {}", ready.unwrap_or_else(|e| format!("ERROR {e}")));
        eprintln!("MacVPN smoke: done");
    });
}

/// The seeded connection's name once it starts with `prefix`.
fn renamed(state: &AppState, id: &str, prefix: &str) -> Option<String> {
    let id = parse_uuid(id)?;
    state.manager.connections().into_iter().find(|c| c.id == id).map(|c| c.name).filter(|n| n.starts_with(prefix))
}

fn wait_for<T>(seconds: u64, f: impl Fn() -> Option<T>) -> Option<T> {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < deadline {
        if let Some(value) = f() {
            return Some(value);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    None
}

fn eval(app: &AppHandle, label: &str, script: String) -> Result<(), String> {
    // The page needs a moment to load its UI and the first view model.
    std::thread::sleep(Duration::from_secs(3));
    app.get_webview_window(label).ok_or("no window")?.eval(script).map_err(|e| e.to_string())
}

fn run_script(
    app: &AppHandle,
    dir: &Path,
    window: &str,
    script: &str,
    done: &dyn Fn() -> Option<String>,
) -> Result<String, String> {
    let source = std::fs::read_to_string(dir.join(script)).map_err(|e| e.to_string())?;
    crate::commands::open(app, window)?;
    eval(app, window, source)?;
    wait_for(90, done).ok_or_else(|| "no result".into())
}

/// A code prompt and a web sign-in, each answered by `prompt.js` in its prompt window.
fn prompts(app: &AppHandle, state: &Arc<AppState>, dir: &Path) {
    let Ok(source) = std::fs::read_to_string(dir.join("prompt.js")) else {
        eprintln!("MacVPN smoke: prompt: ERROR no prompt.js");
        return;
    };
    let connection = uuid_string(&parse_uuid(MANAGE_RESULT).expect("uuid"));
    for kind in [
        AuthPromptKind::Code { text: "Smoke: enter 123456".into(), echo: false, from_server: true },
        AuthPromptKind::WebAuth { url: "https://sso.example.com/auth?session=smoke".into() },
    ] {
        let broker = state.broker.clone();
        let prompt = AuthPrompt {
            connection_id: connection.clone(),
            connection_name: "Smoke A".into(),
            kind,
            deadline: PromptDeadline::new(Date::now()),
        };
        let waiting = std::thread::spawn(move || broker.present(prompt, Date::now()));
        let label =
            wait_for(10, || state.broker.pending().first().map(|p| macvpn_app_core::notify::prompt_window_label(p.id)))
                .and_then(|label| wait_for(10, || app.get_webview_window(&label).map(|_| label.clone())));
        let Some(label) = label else {
            eprintln!("MacVPN smoke: prompt: ERROR no prompt window");
            return;
        };
        if let Err(e) = eval(app, &label, source.clone()) {
            eprintln!("MacVPN smoke: prompt: ERROR {e}");
        }
        // The mock code is compared, not logged.
        let result = match waiting.join() {
            Ok(AuthPromptResult::Code(code)) => format!("code {}", if code == "123456" { "ok" } else { "wrong" }),
            Ok(other) => format!("{other:?}"),
            Err(_) => "panicked".into(),
        };
        let closed = wait_for(10, || app.get_webview_window(&label).is_none().then_some(())).is_some();
        eprintln!("MacVPN smoke: prompt: {result} closed={closed}");
    }
}
