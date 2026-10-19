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
//!   window closed during an install and while its question is shown; `QUIT …`). Before that, the control API:
//!   `control.js` (Connections) turns "Allow other apps to control VPNs" on in the Paired apps section, the shell's
//!   test client (`control-client.mjs`) pairs – `pairing.js` checks and approves it in the pairing window –, says
//!   hello, lists, brings a seeded connection up through [`FakeRoot`] and closes its socket, after which the
//!   connection must go down; `control.js` then turns the setting off and the socket must be gone (`CONTROL …`).
//!   Then the live system VPN list: the run's native layer is [`FakeNative`] (a service list the driver changes;
//!   nothing reaches `scutil` or a real VPN), and the driver triggers the debounced reload itself in place of the
//!   SystemConfiguration watcher. `live.js` (Connections) opens a fake system VPN's detail; the driver removes the
//!   service, the script checks the "removed from macOS" banner and the disabled form, the driver adds a new
//!   service, the script waits for its row; `live-menu.js` checks the menu popover (never reopened) shows it too
//!   (`LIVE …`, `MENU …`).
//!   The credential prompt: `credentials.js` answers the `cred-*` window of a seeded OpenVPN connection with a bare
//!   `auth-user-pass` and nothing stored (user name and password typed, "Save" left ticked); once [`FakeRoot`]
//!   connected it, the in-memory secret store holds both values, and a second connect asks nothing. A second seeded
//!   connection's `up` fails once with the sign-in failure: the re-prompt shows the retry line and is cancelled, and
//!   the connection ends disconnected without a failure (`MacVPN smoke: credentials: …`).
//!   Last, `system.js` leaves an unsaved change and answers the quit question the shell's quit Apple Event
//!   raises. Between the window scripts and the prompts, the Dock icon is checked (`NSApp.activationPolicy`): shown with the windows open, a Dock click (`dock::reopen`) restoring a minimized window without
//!   opening any, hidden again once they are closed and while only a prompt is open. The results go to stderr (`MacVPN smoke: …`, first the language), ending with `MacVPN smoke: done`.
//!   `scripts/smoke-manage.sh` checks them. Release builds do not contain this module.

use macvpn_app_core::deps::{NativeController, RootClient, SystemService};
use macvpn_core::date::Date;
use macvpn_core::mfa::{AuthPrompt, AuthPromptKind, AuthPromptResult, AuthResponseKind, PromptDeadline};
use macvpn_core::models::{ConnectionState, Secrets, VPNKind, parse_uuid, uuid_string};
use macvpn_core::native::NativeKind;
use macvpn_core::status::RootStatus;
use macvpn_core::update::{Release, ReleaseAsset};
use macvpn_platform_mac::setup_checker::SetupReport;
use macvpn_platform_mac::temp_dir::{make_private_temp_directory, write_script};
use macvpn_platform_mac::update_installer::{InstallerError, UpdateSteps, VerifiedDownload};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Manager};
use uuid::Uuid;

use crate::platform::Environment;
use crate::state::AppState;

/// The seeded connections whose names carry the scripts' results (`scripts/smoke-manage.sh`).
const MANAGE_RESULT: &str = "11111111-2222-4333-8444-555555555555";
const SETUP_RESULT: &str = "41111111-2222-4333-8444-555555555555";
const UPDATE_RESULT: &str = "51111111-2222-4333-8444-555555555555";
const QUIT_RESULT: &str = "71111111-2222-4333-8444-555555555555";
const CONTROL_RESULT: &str = "81111111-2222-4333-8444-555555555555";
/// The connection the control API's test client brings up (through [`FakeRoot`]).
const CONTROL_VPN: &str = "91111111-2222-4333-8444-555555555555";
const LIVE_RESULT: &str = "C1111111-2222-4333-8444-555555555555";
const LIVE_MENU_RESULT: &str = "C2111111-2222-4333-8444-555555555555";
/// [`FakeNative`]'s system VPNs: listed from the start, removed by the live step; added by it.
const LIVE_A: &str = "D1111111-2222-4333-8444-555555555555";
const LIVE_B: &str = "D2111111-2222-4333-8444-555555555555";
/// The credential prompt's connections: nothing stored; stored, but the first `up` is a sign-in failure.
const CRED: &str = "A1111111-2222-4333-8444-555555555555";
const CRED_RETRY: &str = "B1111111-2222-4333-8444-555555555555";
/// What `credentials.js` types (compared here, never logged).
const CRED_USER: &str = "smoke-user";
const CRED_PASSWORD: &str = "smoke-pass-4711";

fn smoke_dir(state: &AppState) -> Option<PathBuf> {
    smoke_dir_of(&state.env)
}

fn smoke_dir_of(env: &Environment) -> Option<PathBuf> {
    let dir = std::env::var_os("MACVPN_SMOKE_DIR").map(PathBuf::from)?;
    (env.sandbox && dir.is_absolute()).then_some(dir)
}

/// The smoke run's root helper: `up` marks the connection connected (as `mvpn status` would then list it), `down`
/// clears it; nothing runs. Each call is logged for `scripts/smoke-manage.sh`.
#[derive(Default)]
pub struct FakeRoot {
    up: Mutex<Vec<(Uuid, VPNKind, f64)>>,
    /// These connections' next `up` fails with the sign-in failure (once).
    fail_once: Mutex<Vec<Uuid>>,
}

/// [`FakeRoot`] in a smoke run, `None` otherwise.
pub fn fake_root(env: &Environment) -> Option<Arc<dyn RootClient>> {
    smoke_dir_of(env).map(|_| {
        let root = FakeRoot::default();
        root.fail_once.lock().unwrap_or_else(PoisonError::into_inner).extend(parse_uuid(CRED_RETRY));
        Arc::new(root) as Arc<dyn RootClient>
    })
}

impl RootClient for FakeRoot {
    fn status(&self) -> Result<Vec<RootStatus>, String> {
        Ok(self
            .up
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(id, kind, since)| RootStatus {
                id: *id,
                kind: kind.raw_value().into(),
                state: "connected".into(),
                iface: Some("utun99".into()),
                ip: Some("10.99.0.2".into()),
                since: Some(*since),
            })
            .collect())
    }

    fn up(&self, kind: VPNKind, id: &Uuid, secrets: &Secrets, _: bool, _: &[String]) -> Result<(), String> {
        // Which credentials arrived on "stdin", never their values.
        let set = |name: &str, value: &Option<String>| {
            value.as_deref().is_some_and(|v| !v.is_empty()).then(|| format!(" {name}=set"))
        };
        let fields: String =
            [set("username", &secrets.username), set("password", &secrets.password)].into_iter().flatten().collect();
        eprintln!("MacVPN smoke: fake root: up {}{fields}", uuid_string(id));
        std::thread::sleep(Duration::from_millis(500));
        {
            let mut fail = self.fail_once.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(index) = fail.iter().position(|u| u == id) {
                fail.remove(index);
                // As `mvpn` reports it: the last stderr line, in the app's language.
                return Err(macvpn_core::l10n::tr("Authentication failed (AUTH_FAILED)", &[]));
            }
        }
        let mut up = self.up.lock().unwrap_or_else(PoisonError::into_inner);
        up.retain(|(u, _, _)| u != id);
        up.push((*id, kind, Date::now().time_interval_since_1970()));
        Ok(())
    }

    fn down(&self, _: VPNKind, id: &Uuid) -> Result<(), String> {
        eprintln!("MacVPN smoke: fake root: down {}", uuid_string(id));
        self.up.lock().unwrap_or_else(PoisonError::into_inner).retain(|(u, _, _)| u != id);
        Ok(())
    }

    fn respond(&self, _: &Uuid, _: AuthResponseKind, _: &str) -> Result<(), String> {
        Ok(())
    }
}

/// The smoke run's native layer: a system VPN list the driver changes. Start and stop only log (and set the
/// status); nothing reaches `scutil` or `SCNetworkConnection`.
#[derive(Default)]
pub struct FakeNative {
    services: Mutex<Vec<SystemService>>,
}

static FAKE_NATIVE: OnceLock<Arc<FakeNative>> = OnceLock::new();

/// [`FakeNative`] in a smoke run, `None` otherwise.
pub fn fake_native(env: &Environment) -> Option<Arc<dyn NativeController>> {
    smoke_dir_of(env)?;
    let fake = FAKE_NATIVE.get_or_init(|| {
        let native = FakeNative::default();
        native.add(LIVE_A, "Smoke Live A");
        Arc::new(native)
    });
    Some(fake.clone() as Arc<dyn NativeController>)
}

impl FakeNative {
    fn services(&self) -> std::sync::MutexGuard<'_, Vec<SystemService>> {
        self.services.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn add(&self, id: &str, name: &str) {
        self.services().push(SystemService::new(id, name, "L2TP", "Disconnected"));
    }

    fn remove(&self, id: &str) {
        self.services().retain(|s| s.id != id);
    }

    fn set_status(&self, id: &str, status: &str) {
        if let Some(s) = self.services().iter_mut().find(|s| s.id == id) {
            s.status = status.into();
        }
    }
}

impl NativeController for FakeNative {
    fn list(&self) -> Result<Vec<SystemService>, String> {
        Ok(self.services().clone())
    }

    fn remote_address(&self, _: &str) -> Option<String> {
        None
    }

    fn start(&self, service_id: &str, _: Option<NativeKind>, _: &Secrets) -> Result<(), String> {
        eprintln!("MacVPN smoke: fake native: start {service_id}");
        self.set_status(service_id, "Connected");
        Ok(())
    }

    fn stop(&self, service_id: &str) -> Result<(), String> {
        eprintln!("MacVPN smoke: fake native: stop {service_id}");
        self.set_status(service_id, "Disconnected");
        Ok(())
    }
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
        dock(&app);
        prompts(&app, &state, &dir);
        eprintln!("MacVPN smoke: dock: prompt only regular={}", regular(&app));
        credentials(&app, &state, &dir);
        control(&app, &state, &dir);
        live(&app, &state, &dir);
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

/// `NSApp.activationPolicy` is Regular (the Dock icon is shown), read on the main thread.
fn regular(app: &AppHandle) -> String {
    let (tx, rx) = std::sync::mpsc::channel();
    let _ = app.run_on_main_thread(move || {
        let _ = tx.send(macvpn_platform_mac::app_hooks::activation_policy_is_regular());
    });
    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(Some(regular)) => regular.to_string(),
        _ => "unknown".into(),
    }
}

/// The Dock icon with the windows the scripts left open: shown; a Dock click (`dock::reopen`) brings back a
/// minimized Connections window and opens nothing; once every window is closed, hidden again.
fn dock(app: &AppHandle) {
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

/// The control API end to end (see the module docs): `control.js` drives the Paired apps section in the
/// Connections window, the shell's test client talks to the socket, `pairing.js` answers the pairing window. The
/// steps are logged as `MacVPN smoke: control: …` lines.
fn control(app: &AppHandle, state: &Arc<AppState>, dir: &Path) {
    let say = |line: String| eprintln!("MacVPN smoke: control: {line}");
    // The mock System Status report has an outdated root layer: the client's `up` would be `setup_required`.
    *state.setup.write().unwrap_or_else(PoisonError::into_inner) =
        SetupReport { installed_root_version: Some("7".into()), ..setup_report(state).unwrap_or_default() };
    let socket = state.env.application_support().join("control").join("macvpn.sock");
    let source = match std::fs::read_to_string(dir.join("control.js")) {
        Ok(source) => source,
        Err(e) => return say(format!("ERROR control.js: {e}")),
    };
    if let Err(e) = crate::commands::open(app, "manage").and_then(|()| eval(app, "manage", source)) {
        return say(format!("ERROR {e}"));
    }
    // The script turns the setting on through the switch.
    let on = wait_for(30, || state.control.is_running().then_some(())).is_some();
    say(format!("on running={on} socket={}", socket.exists()));
    if !on {
        return;
    }
    say(format!("listening {}", socket.display()));
    // The shell starts the test client, which asks for pairing: the window gets `pairing.js`.
    let label = wait_for(60, || {
        state.control.pairing.pending().first().map(|p| macvpn_app_core::pairing::pairing_window_label(p.id))
    })
    .and_then(|label| wait_for(10, || app.get_webview_window(&label).map(|_| label.clone())));
    let Some(label) = label else { return say("ERROR no pairing window".into()) };
    match std::fs::read_to_string(dir.join("pairing.js")) {
        Ok(source) => {
            if let Err(e) = eval(app, &label, source) {
                say(format!("ERROR pairing.js: {e}"));
            }
        }
        Err(e) => return say(format!("ERROR pairing.js: {e}")),
    }
    let closed = wait_for(20, || app.get_webview_window(&label).is_none().then_some(())).is_some();
    let clients = state.control.view(true).clients;
    let paired = clients.iter().map(|c| format!("{}:{}", c.name, c.allowed.join("+"))).collect::<Vec<_>>().join(",");
    say(format!("paired [{paired}] window_closed={closed}"));
    // The client's lease: up, held by the client, down after it closed its socket.
    let held = wait_for(60, || {
        let connected = state.manager.state(CONTROL_VPN).is_connected();
        let holders = state.control.holders().get(CONTROL_VPN).cloned().unwrap_or_default();
        (connected && !holders.is_empty()).then(|| holders.join(","))
    });
    say(format!("held_by={}", held.unwrap_or_else(|| "none".into())));
    let released = wait_for(60, || {
        (state.manager.state(CONTROL_VPN) == ConnectionState::Disconnected && state.control.holders().is_empty())
            .then_some(())
    })
    .is_some();
    say(format!("released disconnected={released}"));
    // The script turns the setting off: the socket goes.
    let result = wait_for(60, || renamed(state, CONTROL_RESULT, "CONTROL")).unwrap_or_else(|| "no result".into());
    say(format!("ui: {result}"));
    let gone = wait_for(15, || (!socket.exists()).then_some(())).is_some();
    say(format!("off running={} socket={}", state.control.is_running(), !gone));
}

/// The live system VPN list (see the module docs), logged as `MacVPN smoke: live: …` lines.
fn live(app: &AppHandle, state: &Arc<AppState>, dir: &Path) {
    let say = |line: String| eprintln!("MacVPN smoke: live: {line}");
    let Some(fake) = FAKE_NATIVE.get() else { return say("ERROR no fake native".into()) };
    let listed = |id: &str| state.manager.system_services().iter().any(|s| s.id == id);
    // How long the debounced reload takes to show a change (the poll fallback alone would take up to 5 s).
    let reload = |change: &dyn Fn(), id: &str, present: bool| {
        change();
        let started = Instant::now();
        state.live.trigger();
        wait_for(10, || (listed(id) == present).then(|| started.elapsed().as_millis()))
    };
    let after = |ms: Option<u128>| ms.map_or_else(|| "never".to_string(), |ms| ms.to_string());
    let source = match std::fs::read_to_string(dir.join("live.js")) {
        Ok(source) => source,
        Err(e) => return say(format!("ERROR live.js: {e}")),
    };
    if let Err(e) = crate::commands::open(app, "manage").and_then(|()| eval(app, "manage", source)) {
        return say(format!("ERROR {e}"));
    }
    // The script selects the fake system VPN and its editor opens.
    let shown = wait_for(30, || {
        (state.connections.selected().as_deref() == Some(LIVE_A)
            && state.connections.draft_fields().contains_key(LIVE_A))
        .then_some(())
    });
    say(format!("editor open={}", shown.is_some()));
    // Deleted in "System Settings".
    let removed = reload(&|| fake.remove(LIVE_A), LIVE_A, false);
    let marked = wait_for(5, || state.connections.view().selected_removed.then_some(())).is_some();
    say(format!("removed listed={} selected_removed={marked}", after(removed)));
    // Time for the script to check the read-only detail, then a new VPN.
    std::thread::sleep(Duration::from_secs(2));
    let added = reload(&|| fake.add(LIVE_B, "Smoke Live B"), LIVE_B, true);
    say(format!("added listed={}", after(added)));
    let result = wait_for(60, || renamed(state, LIVE_RESULT, "LIVE")).unwrap_or_else(|| "no result".into());
    say(format!("ui: {result}"));
    // The menu popover was created at launch and is never reopened: its rows follow the view model.
    let menu = std::fs::read_to_string(dir.join("live-menu.js"))
        .map_err(|e| e.to_string())
        .and_then(|source| eval(app, crate::tray::MENU_WINDOW, source))
        .map(|()| wait_for(30, || renamed(state, LIVE_MENU_RESULT, "MENU")).unwrap_or_else(|| "no result".into()));
    say(format!("menu: {}", menu.unwrap_or_else(|e| format!("ERROR {e}"))));
}

/// The credential prompt end to end (see the module docs), logged as `MacVPN smoke: credentials: …` lines.
fn credentials(app: &AppHandle, state: &Arc<AppState>, dir: &Path) {
    use macvpn_app_core::deps::SecretField;
    let say = |line: String| eprintln!("MacVPN smoke: credentials: {line}");
    let source = match std::fs::read_to_string(dir.join("credentials.js")) {
        Ok(source) => source,
        Err(e) => return say(format!("ERROR credentials.js: {e}")),
    };
    let find = |id: &str| {
        let id = parse_uuid(id)?;
        state.manager.connections().into_iter().find(|c| c.id == id)
    };
    let (Some(cred), Some(retry)) = (find(CRED), find(CRED_RETRY)) else {
        return say("ERROR the seeded connections are missing".into());
    };
    let key = uuid_string(&cred.id);
    // Connects on a worker (the manager blocks while the window is open); the window gets the script.
    let connect = |c: &macvpn_core::models::Connection| {
        let (manager, c) = (state.manager.clone(), c.clone());
        std::thread::spawn(move || manager.connect(&c, false))
    };
    let window = || {
        wait_for(15, || state.credential_broker.pending().first().cloned()).and_then(|p| {
            let label = macvpn_app_core::notify::credential_window_label(p.id);
            wait_for(10, || app.get_webview_window(&label).map(|_| (label.clone(), p.clone())))
        })
    };

    // 1. Nothing stored: the window asks for the user name and the password; saved once connected.
    let worker = connect(&cred);
    let Some((label, view)) = window() else { return say("ERROR no credential window".into()) };
    say(format!("first fields={} retry={}", view.fields.join("+"), view.message.is_some()));
    if let Err(e) = eval(app, &label, source.clone()) {
        say(format!("ERROR {e}"));
    }
    let _ = worker.join();
    let connected = wait_for(15, || state.manager.state(&key).is_connected().then_some(())).is_some();
    let secrets = &state.connections.deps().secrets;
    let saved = wait_for(10, || {
        let user = secrets.get(&cred.id, SecretField::Username);
        let password = secrets.get(&cred.id, SecretField::Password);
        (user.as_deref() == Some(CRED_USER) && password.as_deref() == Some(CRED_PASSWORD)).then_some(())
    })
    .is_some();
    let closed = wait_for(10, || app.get_webview_window(&label).is_none().then_some(())).is_some();
    say(format!("first connected={connected} saved={} closed={closed}", if saved { "yes" } else { "no" }));

    // 2. Stored now: a second connect asks nothing.
    state.manager.disconnect(&cred);
    let worker = connect(&cred);
    let asked = wait_for(5, || {
        let asked = state.credential_broker.prompt_for_connection(&key).is_some();
        (asked || state.manager.state(&key).is_connected()).then_some(asked)
    });
    if asked == Some(true) {
        state.credential_broker.dismiss(&key);
    }
    let _ = worker.join();
    say(format!("second prompt={} connected={}", asked.unwrap_or(true), state.manager.state(&key).is_connected()));
    state.manager.disconnect(&cred);

    // 3. A sign-in failure: one re-prompt with the retry line, cancelled; no failure.
    let retry_key = uuid_string(&retry.id);
    // The sandbox's in-memory store, never the Keychain.
    let writer = &state.connections.deps().secret_writer;
    writer.set("stored-user", &retry.id, SecretField::Username);
    writer.set("stored-pass", &retry.id, SecretField::Password);
    let worker = connect(&retry);
    let Some((label, view)) = window() else { return say("ERROR no re-prompt window".into()) };
    let expected = macvpn_core::credentials::sign_in_failed_text();
    say(format!(
        "retry fields={} message={} prefilled={}",
        view.fields.join("+"),
        view.message.as_deref() == Some(expected.as_str()),
        view.username.as_deref() == Some("stored-user")
    ));
    if let Err(e) = eval(app, &label, source) {
        say(format!("ERROR {e}"));
    }
    let _ = worker.join();
    let closed = wait_for(10, || app.get_webview_window(&label).is_none().then_some(())).is_some();
    let final_state = match state.manager.state(&retry_key) {
        ConnectionState::Disconnected => "disconnected".to_string(),
        ConnectionState::Failed(_) => "failed".to_string(),
        other => format!("{other:?}"),
    };
    say(format!("retry state={final_state} closed={closed}"));
}
