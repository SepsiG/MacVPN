//! Development only (debug builds on macOS and Windows; the app reaches it through the `platform::smoke_*`
//! facades): the sandbox's stand-ins for the steps that would change the system, and the smoke test driver. This
//! file is the portable driver; `macos.rs` holds what reads AppKit back (the popover's shape, the Dock icon, the
//! window numbers and screenshots, the appearance), the old Keychain items, the mock Homebrew report and the DMG
//! update's steps. On Windows those steps print `MacVPN smoke: <step>: skipped on Windows` (the prefix stays
//! `MacVPN smoke:` on both, `scripts/smoke-manage.sh` greps it), System Status' mock report has the engine rows, and
//! `MACVPN_SMOKE_LANG` (`SMOKE_LANG`) forces the language (macOS: `-AppleLanguages`).
//!
//! - The update in the sandbox: macOS `macos::SandboxUpdate` (every stage runs against `<sandbox>/tmp`, nothing is
//!   downloaded, mounted or verified, the helper script is written but never run, and "launching" it only logs);
//!   Windows: the stages and the quit questions only (no MSI, no msiexec, no relauncher).
//! - `MACVPN_SMOKE_DIR=<absolute dir>` (with `MACVPN_SANDBOX_HOME` only): mock data (a System Status report with
//!   a missing tool and an older root layer, an offered release whose notes hold markup), then the scripts of
//!   that directory run in the real windows one after the other – `manage.js` (Connections), `setup.js` (System
//!   Status), `update.js` (Update) – each finishing by renaming its seeded connection (`SMOKE …`, `SETUP …`,
//!   `UPDATE …`), and `prompt.js` answers a mock code prompt and a mock web sign-in in their prompt windows.
//!   `quit.js` (Connections) runs the quit flows' edge cases (a selection during the quit's question, the Update
//!   window closed during an install and while its question is shown; `QUIT …`). Before that, the control API:
//!   `control.js` (Connections) turns "Allow other apps to control VPNs" on in the Paired apps section, the shell's
//!   test client (`control-client.mjs`) pairs – `pairing.js` checks and approves it in the pairing window –, says
//!   hello, lists, brings a seeded connection up through [`FakeHelper`] and closes its socket, after which the
//!   connection must go down; `control.js` then turns the setting off and the socket must be gone (`CONTROL …`).
//!   Then the live system VPN list: the run's native layer is [`FakeNative`] (a service list the driver changes;
//!   nothing reaches `scutil` or a real VPN), and the driver triggers the debounced reload itself in place of the
//!   SystemConfiguration watcher. `live.js` (Connections) opens a fake system VPN's detail; the driver removes the
//!   service, the script checks the "removed from macOS" banner and the disabled form, the driver adds a new
//!   service, the script waits for its row; `live-menu.js` checks the menu popover (never reopened) shows it too
//!   (`LIVE …`, `MENU …`, the version line included and not clipped). Then the popover is shown and its rounded
//!   corners are read back from AppKit (`MacVPN smoke: menu: shape …`, with the window number for screenshots;
//!   Windows: DWM's corner preference, `MacVPN smoke: menu: corners round=…`, `false` on Windows 10).
//!   The credential prompt: `credentials.js` answers the `cred-*` window of a seeded OpenVPN connection with a bare
//!   `auth-user-pass` and nothing stored (user name and password typed, "Save" left ticked); once [`FakeHelper`]
//!   connected it, the in-memory secret store holds both values, and a second connect asks nothing. A second seeded
//!   connection's `up` fails once with the sign-in failure: the re-prompt shows the retry line and is cancelled, and
//!   the connection ends disconnected without a failure (`MacVPN smoke: credentials: …`). Last, the largest credential
//!   window (the retry line, all four fields and a refused answer's error: `credentials-largest.js`). Every prompt,
//!   credential and pairing script checks its real window fits its content (`scrollHeight <= clientHeight`).
//!   `MACVPN_SMOKE_SHOTS` (`SMOKE_SHOTS=<dir>`): each of those windows and the menu wait for the shell's screenshot
//!   ([`shoot`]), so do the Connections window's New menu and a context menu (`popover-shots.js`);
//!   `MACVPN_SMOKE_DARK` (`SMOKE_DARK=1`) puts the app in dark mode, `MACVPN_SMOKE_LIGHT` (`SMOKE_LIGHT=1`) in light.
//!   Folders: `folders.js` (Connections) creates a folder from the New menu, a subfolder from its context menu,
//!   colours the folder, drags a seeded connection into the subfolder, collapses and expands the folder, and
//!   deletes the subfolder moving its contents up (`FOLDERS …`; the folders are kept in the vault).
//!   After the folders, the 2.0 features (`features.rs`: `appearance.js`, `engines.js`, `notices.js`, `reconnect.js`;
//!   the scripted network, the recorded notices and the engines step's reports are its hooks). On Windows then
//!   WinVPN 2c's native VPNs (`ras.rs`: `ras.js`; [`FakeNative`] answers each connection's `WinVPN-<UUID>` entry
//!   as the `RasEngine` does, listed while the sandbox engine keeps its saved profile, and dials nothing).
//!   Last, `system.js` leaves an unsaved change and answers the quit question the shell's quit Apple Event
//!   raises. Between the window scripts and the prompts, the Dock icon is checked (`NSApp.activationPolicy`): shown with the windows open, a Dock click (`dock::reopen`) restoring a minimized window without
//!   opening any, hidden again once they are closed and while only a prompt is open. The results go to stderr (`MacVPN smoke: …`, first the language), ending with `MacVPN smoke: done`.
//!   `scripts/smoke-manage.sh` checks them. Release builds do not contain this module.

use macvpn_app_core::deps::{HelperClient, NativeController, SystemVpn};
use macvpn_core::date::Date;
use macvpn_core::mfa::{AuthPrompt, AuthPromptKind, AuthPromptResult, AuthResponseKind, PromptDeadline};
use macvpn_core::models::{ConnectionState, Secrets, VPNKind, parse_uuid, uuid_string};
use macvpn_core::native::NativeKind;
use macvpn_core::status::RootStatus;
use macvpn_core::update::{Release, ReleaseAsset};
use macvpn_platform_api::{SetupReport, UpdateOutcome};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Manager};
use uuid::Uuid;

use super::Environment;
use crate::state::AppState;

mod features;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod ras;
#[cfg(target_os = "macos")]
use macos::{private_temp_dir, shoot, with_shot};

pub use features::{network, notice, recheck_unthrottled, records_notices};

/// The seeded connections whose names carry the scripts' results (`scripts/smoke-manage.sh`).
const MANAGE_RESULT: &str = "11111111-2222-4333-8444-555555555555";
const SETUP_RESULT: &str = "41111111-2222-4333-8444-555555555555";
const UPDATE_RESULT: &str = "51111111-2222-4333-8444-555555555555";
const QUIT_RESULT: &str = "71111111-2222-4333-8444-555555555555";
const CONTROL_RESULT: &str = "81111111-2222-4333-8444-555555555555";
/// The connection the control API's test client brings up (through [`FakeHelper`]).
const CONTROL_VPN: &str = "91111111-2222-4333-8444-555555555555";
const LIVE_RESULT: &str = "C1111111-2222-4333-8444-555555555555";
const LIVE_MENU_RESULT: &str = "C2111111-2222-4333-8444-555555555555";
/// The folders step's connection: dragged into a folder by `folders.js`, then carries its result.
const FOLDERS_RESULT: &str = "E1111111-2222-4333-8444-555555555555";
/// [`FakeNative`]'s system VPNs: listed from the start, removed by the live step; added by it.
const LIVE_A: &str = "D1111111-2222-4333-8444-555555555555";
const LIVE_B: &str = "D2111111-2222-4333-8444-555555555555";
/// The credential prompt's connections: nothing stored; stored, but the first `up` is a sign-in failure.
const CRED: &str = "A1111111-2222-4333-8444-555555555555";
const CRED_RETRY: &str = "B1111111-2222-4333-8444-555555555555";
/// What `credentials.js` types (compared here, never logged).
const CRED_USER: &str = "smoke-user";
const CRED_PASSWORD: &str = "smoke-pass-4711";
/// The shared credential step's connections (OpenVPN, a bare `auth-user-pass`, nothing stored), and what
/// `shared.js` / `shared-prompt.js` enter (compared here, never logged).
const SHARED_ONE: &str = "E3111111-2222-4333-8444-555555555555";
const SHARED_TWO: &str = "E4111111-2222-4333-8444-555555555555";
const SHARED_USER: &str = "smoke-shared";
const SHARED_PASSWORD: &str = "smoke-shared-pass";

/// The smoke run's 1.1 Keychain item (the in-memory one): the migration must move it into the vault.
const SEEDED_L2TP: &str = "31111111-2222-4333-8444-555555555555";
const SEEDED_PSK: &str = "seeded-psk-0815";

/// A smoke run seeds the sandbox's in-memory "old Keychain" with one item (`SEEDED_L2TP`'s PSK). Windows has no
/// old Keychain: there the smoke run's language is forced instead (`MACVPN_SMOKE_LANG=en|hu`, the step that runs
/// after the platform's core hooks and before any window).
pub fn seed_legacy_keychain(env: &Environment) {
    if smoke_dir_of(env).is_some() {
        #[cfg(target_os = "macos")]
        macos::seed_legacy_keychain();
        #[cfg(windows)]
        windows_language();
    }
}

/// `MACVPN_SMOKE_LANG=en|hu`: the preferred UI languages of this run (Windows' `GetUserPreferredUILanguages` cannot
/// be changed for one process).
#[cfg(windows)]
fn windows_language() {
    match std::env::var("MACVPN_SMOKE_LANG").as_deref() {
        Ok(lang @ ("en" | "hu")) => macvpn_core::l10n::AppLanguage::set_preferred_languages(vec![lang.to_string()]),
        Ok(other) => eprintln!("MacVPN smoke: MACVPN_SMOKE_LANG: en or hu, not {other}"),
        Err(_) => {}
    }
}

/// The recovery key of the vault the smoke run created (for its recovery step; never logged).
static RECOVERY_KEY: Mutex<Option<zeroize::Zeroizing<String>>> = Mutex::new(None);

/// `vault_create` hands its key over in a smoke run (debug builds only).
pub fn remember_recovery_key(key: &str) {
    if std::env::var_os("MACVPN_SMOKE_DIR").is_some() {
        *RECOVERY_KEY.lock().unwrap_or_else(PoisonError::into_inner) = Some(zeroize::Zeroizing::new(key.to_string()));
    }
}

fn smoke_dir(state: &AppState) -> Option<PathBuf> {
    smoke_dir_of(&state.env)
}

fn smoke_dir_of(env: &Environment) -> Option<PathBuf> {
    let dir = std::env::var_os("MACVPN_SMOKE_DIR").map(PathBuf::from)?;
    (env.sandbox && dir.is_absolute()).then_some(dir)
}

/// The smoke run's root helper: `up` marks the connection connected (as `mvpn status` would then list it), `down`
/// clears it; nothing runs. Each call is logged for `scripts/smoke-manage.sh`. The driver can make a connected one
/// report `failed` ([`FakeHelper::fail`]: a drop), and counts the calls ([`FakeHelper::calls`]).
#[derive(Default)]
pub struct FakeHelper {
    /// The connections `status` lists: id, kind, since, and the state it reports (`connected`, or `failed`).
    up: Mutex<Vec<(Uuid, VPNKind, f64, &'static str)>>,
    /// These connections' next `up` fails with the sign-in failure (once).
    fail_once: Mutex<Vec<Uuid>>,
    /// Every `up` and `down`, in order.
    log: Mutex<Vec<(&'static str, Uuid)>>,
}

static FAKE_HELPER: OnceLock<Arc<FakeHelper>> = OnceLock::new();

/// [`FakeHelper`] in a smoke run, `None` otherwise.
pub fn fake_helper(env: &Environment) -> Option<Arc<dyn HelperClient>> {
    smoke_dir_of(env)?;
    let fake = FAKE_HELPER.get_or_init(|| {
        let root = FakeHelper::default();
        root.fail_once.lock().unwrap_or_else(PoisonError::into_inner).extend(parse_uuid(CRED_RETRY));
        Arc::new(root)
    });
    Some(fake.clone() as Arc<dyn HelperClient>)
}

impl FakeHelper {
    /// The connection now reports `failed` (its tunnel went down without a `down`): the next refresh sees a drop.
    fn fail(&self, id: &Uuid) {
        for entry in self.up.lock().unwrap_or_else(PoisonError::into_inner).iter_mut().filter(|e| e.0 == *id) {
            entry.3 = "failed";
        }
    }

    /// How many `op` (`up` / `down`) calls `id` got.
    fn calls(&self, op: &str, id: &Uuid) -> usize {
        self.log.lock().unwrap_or_else(PoisonError::into_inner).iter().filter(|(o, u)| *o == op && u == id).count()
    }

    fn record(&self, op: &'static str, id: &Uuid) {
        self.log.lock().unwrap_or_else(PoisonError::into_inner).push((op, *id));
    }
}

impl HelperClient for FakeHelper {
    fn status(&self) -> Result<Vec<RootStatus>, String> {
        Ok(self
            .up
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .map(|(id, kind, since, state)| RootStatus {
                id: *id,
                kind: kind.raw_value().into(),
                state: (*state).into(),
                iface: Some("utun99".into()),
                ip: Some("10.99.0.2".into()),
                since: Some(*since),
            })
            .collect())
    }

    fn up(
        &self,
        kind: VPNKind,
        id: &Uuid,
        config: &[u8],
        secrets: &Secrets,
        _: bool,
        _: &[String],
    ) -> Result<(), String> {
        // The stdin `mvpn up` would read (root layer 8: the config frame, then the secrets), read back as the root
        // layer does. Which credentials arrived, never their values.
        let stdin = macvpn_core::helper_args::up_stdin(config, secrets);
        let Some(names) = framed_secret_names(&stdin, config) else {
            eprintln!("MacVPN smoke: fake root: up {} ERROR bad stdin frame", uuid_string(id));
            return Err("bad stdin frame".into());
        };
        let fields: String =
            ["username", "password"].into_iter().filter(|n| names.contains(n)).map(|n| format!(" {n}=set")).collect();
        eprintln!("MacVPN smoke: fake root: up {}{fields}", uuid_string(id));
        self.record("up", id);
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
        up.retain(|(u, ..)| u != id);
        up.push((*id, kind, Date::now().time_interval_since_1970(), "connected"));
        Ok(())
    }

    fn down(&self, _: VPNKind, id: &Uuid) -> Result<(), String> {
        eprintln!("MacVPN smoke: fake root: down {}", uuid_string(id));
        self.record("down", id);
        self.up.lock().unwrap_or_else(PoisonError::into_inner).retain(|(u, ..)| u != id);
        Ok(())
    }

    fn respond(&self, _: &Uuid, _: AuthResponseKind, _: &str) -> Result<(), String> {
        Ok(())
    }

    /// "Clear Log…" (manage.js): logged with whether the note is the localized header the time filter reads.
    fn clear_log(&self, id: &Uuid, note: &str) -> Result<(), String> {
        let expected = macvpn_core::log::cleared_note("");
        let prefix = expected.trim_end_matches(" ═══").trim_end();
        let ok = note.starts_with(prefix) && macvpn_app_core::logs::line_time(note).is_some();
        eprintln!("MacVPN smoke: fake root: clear-log {} note={}", uuid_string(id), if ok { "ok" } else { "bad" });
        Ok(())
    }
}

/// Reads `mvpn up`'s framed stdin back: `config <length>\n`, exactly that many config bytes (equal to `config`),
/// then `key=value` secret lines. The keys with a non-empty value; `None`: a malformed frame.
fn framed_secret_names(stdin: &[u8], config: &[u8]) -> Option<Vec<&'static str>> {
    let newline = stdin.iter().position(|b| *b == b'\n')?;
    let length: usize = std::str::from_utf8(&stdin[..newline]).ok()?.strip_prefix("config ")?.parse().ok()?;
    let rest = &stdin[newline + 1..];
    let (framed, lines) = (rest.get(..length)?, rest.get(length..)?);
    if framed != config {
        return None;
    }
    let lines = std::str::from_utf8(lines).ok()?;
    let mut names = Vec::new();
    for line in lines.lines() {
        let (key, value) = line.split_once('=')?;
        let name = ["username", "password", "psk", "keypass", "otp", "challenge"].into_iter().find(|n| *n == key)?;
        if !value.is_empty() {
            names.push(name);
        }
    }
    Some(names)
}

/// The smoke run's native layer: a system VPN list the driver changes. Start and stop only log (and set the
/// status); nothing reaches `scutil` or `SCNetworkConnection`. Windows: like the `RasEngine`, every connection's
/// own service is its entry `WinVPN-<UUID>`, listed (as `L2TP`) while the sandbox's RAS engine keeps the
/// connection's saved profile `<data>\ras\<UUID>.ras` (written when an L2TP connection is saved, deleted with its
/// entry): the sandbox's engine writes the entry, this stand-in dials nothing (no `RasDialW`, no PSK stored).
#[derive(Default)]
pub struct FakeNative {
    services: Mutex<Vec<SystemVpn>>,
    /// Windows: the sandbox engine's `<data>\ras` folder.
    #[cfg(windows)]
    ras_dir: Option<PathBuf>,
    /// Windows: the managed entries' states (`Connected` after a start, until the stop).
    #[cfg(windows)]
    managed: Mutex<std::collections::HashMap<String, String>>,
    /// Every start and stop (`start <id> <which secrets were set>`, `stop <id>`), in order.
    calls: Mutex<Vec<String>>,
}

static FAKE_NATIVE: OnceLock<Arc<FakeNative>> = OnceLock::new();

/// [`FakeNative`] in a smoke run, `None` otherwise.
pub fn fake_native(env: &Environment) -> Option<Arc<dyn NativeController>> {
    smoke_dir_of(env)?;
    let fake = FAKE_NATIVE.get_or_init(|| {
        #[cfg(windows)]
        let native = FakeNative {
            ras_dir: Some(env.application_support().join(macvpn_core::ras::names::PHONEBOOK_DIR)),
            ..FakeNative::default()
        };
        #[cfg(not(windows))]
        let native = FakeNative::default();
        native.add(LIVE_A, "Smoke Live A");
        Arc::new(native)
    });
    Some(fake.clone() as Arc<dyn NativeController>)
}

impl FakeNative {
    fn services(&self) -> std::sync::MutexGuard<'_, Vec<SystemVpn>> {
        self.services.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn add(&self, id: &str, name: &str) {
        self.services().push(SystemVpn::new(id, name, "L2TP", "Disconnected"));
    }

    fn remove(&self, id: &str) {
        self.services().retain(|s| s.id != id);
    }

    fn set_status(&self, id: &str, status: &str) {
        if let Some(s) = self.services().iter_mut().find(|s| s.id == id) {
            s.status = status.into();
        }
        #[cfg(windows)]
        if macvpn_core::ras::names::connection_id(id).is_some() {
            self.managed.lock().unwrap_or_else(PoisonError::into_inner).insert(id.into(), status.into());
        }
    }

    /// Whether `line` (`start <id>…` / `stop <id>`) was called.
    #[cfg_attr(not(windows), allow(dead_code))]
    fn recorded(&self, line: &str) -> bool {
        self.calls.lock().unwrap_or_else(PoisonError::into_inner).iter().any(|l| l == line)
    }

    fn record(&self, line: String) {
        eprintln!("MacVPN smoke: fake native: {line}");
        self.calls.lock().unwrap_or_else(PoisonError::into_inner).push(line);
    }

    /// Windows: the entries of the connections whose saved profile the sandbox's RAS engine keeps.
    #[cfg(windows)]
    fn managed_entries(&self) -> Vec<SystemVpn> {
        let Some(dir) = &self.ras_dir else { return Vec::new() };
        let Ok(files) = std::fs::read_dir(dir) else { return Vec::new() };
        let states = self.managed.lock().unwrap_or_else(PoisonError::into_inner);
        let mut entries: Vec<SystemVpn> = files
            .flatten()
            .filter_map(|f| {
                let name = f.file_name().into_string().ok()?;
                let id = parse_uuid(name.strip_suffix(".ras")?)?;
                let entry = macvpn_core::ras::names::entry_name(&id);
                let status = states.get(&entry).map_or("Disconnected", String::as_str);
                Some(SystemVpn::new(&entry, &entry, "L2TP", status))
            })
            .collect();
        entries.sort_by(|a, b| a.id.cmp(&b.id));
        entries
    }
}

impl NativeController for FakeNative {
    fn list(&self) -> Result<Vec<SystemVpn>, String> {
        #[cfg(windows)]
        let mut services = self.managed_entries();
        #[cfg(not(windows))]
        let mut services = Vec::new();
        services.extend(self.services().iter().cloned());
        Ok(services)
    }

    fn remote_address(&self, _: &str) -> Option<String> {
        None
    }

    /// Logs which secrets arrived (never their values).
    fn start(&self, service_id: &str, _: Option<NativeKind>, secrets: &Secrets) -> Result<(), String> {
        let set = |name: &str, value: &Option<String>| {
            if value.as_deref().is_some_and(|v| !v.is_empty()) { format!(" {name}=set") } else { String::new() }
        };
        self.record(format!(
            "start {service_id}{}{}{}",
            set("username", &secrets.username),
            set("password", &secrets.password),
            set("psk", &secrets.psk)
        ));
        self.set_status(service_id, "Connected");
        Ok(())
    }

    fn stop(&self, service_id: &str) -> Result<(), String> {
        self.record(format!("stop {service_id}"));
        self.set_status(service_id, "Disconnected");
        Ok(())
    }

    /// Windows: the connection's entry `WinVPN-<UUID>`, as the `RasEngine` answers (macOS: none).
    #[cfg(windows)]
    fn managed_service_id(&self, connection: &Uuid) -> Option<String> {
        Some(macvpn_core::ras::names::entry_name(connection))
    }
}

/// The mock System Status report. macOS: Homebrew is there, `sstpc` is missing, root layer 7 is installed (8
/// bundled). Windows: the engine rows – the WinVPN Service running, OpenVPN Community not installed ("Install"),
/// WireGuard loaded – and the green Windows VPN client row (WinVPN 2c). While the engines step runs, its own reports instead
/// ([`features::Engines`]).
pub fn setup_report(state: &AppState) -> Option<SetupReport> {
    smoke_dir(state)?;
    if let Some(report) = features::engines_report() {
        return Some(report);
    }
    #[cfg(target_os = "macos")]
    return Some(macos::mock_report());
    #[cfg(windows)]
    return Some(windows_report(false));
}

/// The report once the control API's client connects: every row usable (macOS: the root layer up to date, `sstpc`
/// still missing; Windows: OpenVPN Community installed with both drivers).
fn ready_report() -> SetupReport {
    #[cfg(target_os = "macos")]
    return macos::ready_report();
    #[cfg(windows)]
    return windows_report(true);
}

/// The engine rows from the facts the WinVPN Service would report (`engine::report`, the real texts), with
/// OpenVPN Community missing or (`openvpn`) installed at the pinned version with DCO and TAP-Windows6, and the
/// Windows VPN client row as `SystemSetup::check` adds it (`ras_connect::complete_report`; no Windows service is
/// read in the sandbox).
#[cfg(windows)]
fn windows_report(openvpn: bool) -> SetupReport {
    use macvpn_core::service_proto::{EngineFacts, OpenVpnFacts, SERVICE_VERSION, WireGuardFacts};
    use macvpn_platform_win::pure::{engine, openvpn_pins::OPENVPN_VERSION};
    let openvpn = if openvpn {
        OpenVpnFacts {
            version: Some(OPENVPN_VERSION.into()),
            path: Some(r"C:\Program Files\OpenVPN\bin\openvpn.exe".into()),
            dco: Some("2.8.13.0".into()),
            tap_windows6: Some("9.27.0.0".into()),
            problem: None,
        }
    } else {
        OpenVpnFacts {
            version: None,
            path: None,
            dco: None,
            tap_windows6: None,
            problem: Some(macvpn_core::l10n::tr("OpenVPN Community is not installed.", &[])),
        }
    };
    let facts = EngineFacts {
        service_version: SERVICE_VERSION,
        problem: None,
        openvpn,
        wireguard: WireGuardFacts { dll_version: Some("1.1.0".into()), problem: None },
    };
    let mut report = engine::report(
        engine::Reach::Facts(facts),
        OPENVPN_VERSION,
        &macvpn_platform_win::pure::openvpn_install::Upgrade::None,
        &macvpn_platform_win::pure::wireguard_update::Offer::None,
    );
    macvpn_platform_win::pure::ras_connect::complete_report(&mut report);
    report
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
        package: asset("MacVPN-9.9.9.dmg"),
        checksum: asset("MacVPN-9.9.9.dmg.sha256"),
        signature: Some(asset("MacVPN-9.9.9.dmg.sig")),
    }
}

/// The update in the sandbox. macOS: `install_update` over `macos::SandboxUpdate`, for
/// `<sandbox>/Applications/MacVPN.app`. Windows: the updater's stages and its quit questions; nothing is downloaded,
/// no msiexec and no relauncher starts.
pub fn update_install(
    env: &Environment,
    release: &Release,
    stage: &dyn Fn(String),
    confirm_quit: Box<dyn FnOnce() -> bool + '_>,
) -> Result<UpdateOutcome, String> {
    #[cfg(target_os = "macos")]
    return macos::update_install(env, release, stage, confirm_quit);
    #[cfg(windows)]
    {
        let _ = (env, release);
        let pause = || std::thread::sleep(Duration::from_millis(300));
        // The order of `WinUpdater::install`: the quit questions come after "Quitting and restarting…".
        for text in [
            macvpn_core::l10n::tr("Downloading…", &[]),
            macvpn_core::l10n::tr("Preparing the installation…", &[]),
            macvpn_core::l10n::tr("Quitting and restarting…", &[]),
        ] {
            stage(text);
            pause();
        }
        if !confirm_quit() {
            return Ok(UpdateOutcome::Cancelled);
        }
        eprintln!("MacVPN (sandbox): update installer not run");
        Ok(UpdateOutcome::HelperLaunched)
    }
}

pub fn start(app: &AppHandle, state: &Arc<AppState>) {
    let Some(dir) = smoke_dir(state) else {
        if std::env::var_os("MACVPN_SMOKE_DIR").is_some() {
            eprintln!("MacVPN: MACVPN_SMOKE_DIR needs MACVPN_SANDBOX_HOME and an absolute path");
        }
        return;
    };
    grant_report_commands(app);
    state.updates.consider(mock_release());
    #[cfg(target_os = "macos")]
    macos::appearance();
    // The language the core picked from the preferred languages (`scripts/smoke-manage.sh` can force it).
    eprintln!("MacVPN smoke: language {}", macvpn_core::l10n::AppLanguage::current().raw_value());
    let app = app.clone();
    let state = state.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(2));
        // First the vault: the seeded 1.1 data is migration input (`vault-create.js`).
        vault_create(&app, &state, &dir);
        features::use_ready_report(&state, true);
        for (window, script, id, prefix) in [
            ("manage", "manage.js", MANAGE_RESULT, "SMOKE"),
            ("setup", "setup.js", SETUP_RESULT, "SETUP"),
            ("update", "update.js", UPDATE_RESULT, "UPDATE"),
        ] {
            if window == "setup" {
                features::use_ready_report(&state, false);
            }
            let result = run_script(&app, &dir, window, script, &|| renamed(&state, id, prefix));
            eprintln!("MacVPN smoke: {window}: {}", result.unwrap_or_else(|e| format!("ERROR {e}")));
        }
        #[cfg(target_os = "macos")]
        macos::dock(&app);
        #[cfg(windows)]
        {
            skipped("dock");
            close_windows(&app);
        }
        prompts(&app, &state, &dir);
        #[cfg(target_os = "macos")]
        eprintln!("MacVPN smoke: dock: prompt only regular={}", macos::regular(&app));
        credentials(&app, &state, &dir);
        backup(&app, &state, &dir);
        control(&app, &state, &dir);
        live(&app, &state, &dir);
        folders(&app, &state, &dir);
        // The 2.0 features: the Appearance setting, a missing engine, the notices, auto-reconnect.
        features::run(&app, &state, &dir);
        // WinVPN 2c: the native VPNs' forms, reasons, the Cisco copy and the L2TP / IKEv2 / SSTP connects.
        #[cfg(windows)]
        ras::run(&app, &state, &dir);
        #[cfg(target_os = "macos")]
        macos::menu_shape(&app);
        #[cfg(windows)]
        menu_corners(&app);
        shared(&app, &state, &dir);
        team_catalog(&app, &state, &dir);
        opened_files(&app, &state, &dir);
        publishing(&app, &state, &dir);
        #[cfg(target_os = "macos")]
        {
            macos::manage_shot(&app);
            macos::popover_shots(&app, &dir);
        }
        #[cfg(windows)]
        if std::env::var_os("MACVPN_SMOKE_SHOTS").is_some() {
            skipped("shots");
        }
        let result = run_script(&app, &dir, "manage", "quit.js", &|| renamed(&state, QUIT_RESULT, "QUIT"));
        eprintln!("MacVPN smoke: quit: {}", result.unwrap_or_else(|e| format!("ERROR {e}")));
        // Lock, unlock with the password (after a wrong one), with the recovery key, and with the new password.
        vault_lock_unlock(&app, &state, &dir);
        dump(&state);
        // Last: an unsaved change for the shell's quit request (logout's way, through applicationShouldTerminate).
        let ready = run_script(&app, &dir, "manage", "system.js", &|| {
            state.connections.has_unsaved_changes().then(|| "unsaved change ready".to_string())
        });
        #[cfg(windows)]
        let ready_now = ready.is_ok();
        eprintln!("MacVPN smoke: system: {}", ready.unwrap_or_else(|e| format!("ERROR {e}")));
        // Windows: the app's own lifecycle window gets logoff's WM_QUERYENDSESSION (macOS: the shell sends the
        // quit Apple Event after `done`). The handler blocks for now; system.js answers the question.
        #[cfg(windows)]
        if ready_now {
            let blocked = macvpn_platform_win::smoke::query_end_session() == Some(0);
            eprintln!("MacVPN smoke: system: quit request blocked={blocked}");
        }
        eprintln!("MacVPN smoke: done");
    });
}

/// Whether a smoke run is going on (set by [`start`]; never in a release build, which has no smoke module).
static RUNNING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The scripts report through a seeded connection's name (`editor_open` / `editor_save`), from whichever window
/// they test, and `update.js` / `quit.js` drive the quit flows across windows (`editor_update`, `resolve_unsaved`;
/// `quit`, `update_install`, `close_window` from the Connections window). The per-window capability files grant
/// those only where the UI uses them, so the smoke run adds them at runtime (debug builds only), and `guard`'s
/// window check lets the Connections window start the update ([`permits`]).
fn grant_report_commands(app: &AppHandle) {
    use tauri::ipc::CapabilityBuilder;
    RUNNING.store(true, std::sync::atomic::Ordering::SeqCst);
    let report = CapabilityBuilder::new("smoke-report")
        .windows([crate::tray::MENU_WINDOW, crate::system::SETUP_WINDOW, crate::update_window::UPDATE_WINDOW])
        .permission("allow-editor-open")
        .permission("allow-editor-save")
        .permission("allow-editor-update")
        .permission("allow-resolve-unsaved");
    let quit = CapabilityBuilder::new("smoke-quit")
        .window(crate::manage::MANAGE_WINDOW)
        .permission("allow-quit")
        .permission("allow-update-install")
        .permission("allow-close-window");
    for capability in [report, quit] {
        if let Err(e) = app.add_capability(capability) {
            eprintln!("MacVPN smoke: ERROR capability: {e}");
        }
    }
}

/// The smoke run's extra caller of a window-checked command: `quit.js` (Connections) starts the update.
pub fn permits(label: &str, command: &str) -> bool {
    RUNNING.load(std::sync::atomic::Ordering::SeqCst)
        && label == crate::manage::MANAGE_WINDOW
        && command == "update_install"
}

/// A macOS-only step on Windows (the line `scripts/smoke-manage.sh` expects there).
#[cfg(windows)]
fn skipped(step: &str) {
    eprintln!("MacVPN smoke: {step}: skipped on Windows");
}

/// Windows: the popover shown, DWM's corner preference read back (`round=false` on Windows 10, which has no round
/// corners), then hidden.
#[cfg(windows)]
fn menu_corners(app: &AppHandle) {
    let Some(window) = app.get_webview_window(crate::tray::MENU_WINDOW) else {
        return eprintln!("MacVPN smoke: menu: ERROR no menu window");
    };
    crate::tray::show_menu(app);
    std::thread::sleep(Duration::from_secs(2));
    let (tx, rx) = std::sync::mpsc::channel();
    let target = window.clone();
    let _ = window.run_on_main_thread(move || {
        let _ = tx.send(crate::platform::native_window(&target).map(macvpn_platform_win::smoke::corners_round));
    });
    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(Some(round)) => eprintln!("MacVPN smoke: menu: corners round={round}"),
        _ => eprintln!("MacVPN smoke: menu: ERROR no window handle"),
    }
    crate::tray::hide_menu(app);
}

/// Windows, in place of the Dock step: its end state, every window the scripts left open closed.
#[cfg(windows)]
fn close_windows(app: &AppHandle) {
    let open = || crate::dock::DOCK_WINDOWS.iter().filter(|l| app.get_webview_window(l).is_some()).count();
    for label in crate::dock::DOCK_WINDOWS {
        if let Some(window) = app.get_webview_window(label) {
            let _ = window.close();
        }
    }
    let closed = wait_for(10, || (open() == 0).then_some(())).is_some();
    eprintln!("MacVPN smoke: windows: closed={closed}");
}

/// No screenshots on Windows: a window script runs on without waiting for one.
#[cfg(windows)]
fn with_shot(source: &str) -> String {
    source.to_string()
}

#[cfg(windows)]
fn shoot(_: &AppHandle, _: &str, _: &str, _: Duration) {}

/// A private directory under `base` (Windows: owner-only DACL, a new random name).
#[cfg(windows)]
fn private_temp_dir(prefix: &str, base: &Path) -> Result<PathBuf, String> {
    let dir = base.join(format!("{prefix}.{}", Uuid::new_v4().simple()));
    std::fs::create_dir(&dir).map_err(|e| e.to_string())?;
    macvpn_core::fsx::ensure_private_dir(&dir).map(|_| dir).map_err(|e| e.to_string())
}

/// What a file's permissions are, in the Unix terms the checks use: `600` (owner only), `644` (everyone may
/// read), else `other` (Windows: the DACL's shape, `fsx::has_access`).
#[cfg(windows)]
fn mode(path: &Path) -> String {
    use macvpn_core::fsx::{self, Access, Follow};
    match fsx::stat_path(path, Follow::No) {
        Ok(stat) if fsx::has_access(&stat, Access::Private) => "600".into(),
        Ok(stat) if fsx::has_access(&stat, Access::Shared) => "644".into(),
        _ => "other".into(),
    }
}

#[cfg(target_os = "macos")]
use macos::mode;

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
        let prompt_kind = if matches!(kind, AuthPromptKind::Code { .. }) { "code" } else { "web" };
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
        let shot = if matches!(prompt_kind, "code") { "mfa-code" } else { "mfa-web" };
        if let Err(e) = eval(app, &label, with_shot(&source)) {
            eprintln!("MacVPN smoke: prompt: ERROR {e}");
        }
        shoot(app, &label, shot, Duration::from_secs(2));
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
    // The mock System Status report has an outdated root layer (Windows: no OpenVPN): the client's `up` would be
    // `setup_required`.
    features::use_ready_report(state, true);
    // macOS: the socket file; Windows: the named pipe of the running server (which has no file to look at: opening
    // the pipe's path would connect to it).
    #[cfg(target_os = "macos")]
    let socket = state.env.application_support().join("control").join("macvpn.sock");
    #[cfg(target_os = "macos")]
    let (present, endpoint) = (|| socket.exists(), || socket.display().to_string());
    #[cfg(windows)]
    let (present, endpoint) = (|| state.control.endpoint().is_some(), || state.control.endpoint().unwrap_or_default());
    let source = match std::fs::read_to_string(dir.join("control.js")) {
        Ok(source) => source,
        Err(e) => return say(format!("ERROR control.js: {e}")),
    };
    if let Err(e) = crate::commands::open(app, "manage").and_then(|()| eval(app, "manage", source)) {
        return say(format!("ERROR {e}"));
    }
    // The script turns the setting on through the switch.
    let on = wait_for(30, || state.control.is_running().then_some(())).is_some();
    say(format!("on running={on} socket={}", present()));
    if !on {
        return;
    }
    say(format!("listening {}", endpoint()));
    // The shell starts the test client, which asks for pairing: the window gets `pairing.js`.
    let label = wait_for(60, || {
        state.control.pairing.pending().first().map(|p| macvpn_app_core::pairing::pairing_window_label(p.id))
    })
    .and_then(|label| wait_for(10, || app.get_webview_window(&label).map(|_| label.clone())));
    let Some(label) = label else { return say("ERROR no pairing window".into()) };
    match std::fs::read_to_string(dir.join("pairing.js")) {
        Ok(source) => {
            if let Err(e) = eval(app, &label, with_shot(&source)) {
                say(format!("ERROR pairing.js: {e}"));
            }
            shoot(app, &label, "pairing", Duration::from_secs(2));
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
    let gone = wait_for(15, || (!present()).then_some(())).is_some();
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

/// Folders and colours (spec 3) through the Connections window (`folders.js`, see the module docs), then the
/// backend's view of the result, logged as `MacVPN smoke: folders: …` lines.
fn folders(app: &AppHandle, state: &Arc<AppState>, dir: &Path) {
    let say = |line: String| eprintln!("MacVPN smoke: folders: {line}");
    let result = run_script(app, dir, "manage", "folders.js", &|| renamed(state, FOLDERS_RESULT, "FOLDERS"));
    say(format!("ui: {}", result.unwrap_or_else(|e| format!("ERROR {e}"))));
    let tree = state.manager.folder_tree();
    let work = state.manager.folders().into_iter().find(|f| f.name == "SMOKE Work");
    let placed = state.manager.placement(FOLDERS_RESULT).and_then(|p| p.folder);
    say(format!(
        "store work={} colour={} subfolders={} item_in_work={}",
        work.is_some(),
        work.as_ref().and_then(|w| w.color).map_or("none", |c| c.as_str()),
        work.as_ref().map_or(0, |w| tree.children(Some(w.id)).len()),
        work.as_ref().is_some_and(|w| placed == Some(w.id)),
    ));
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
    if let Err(e) = eval(app, &label, with_shot(&source)) {
        say(format!("ERROR {e}"));
    }
    // The smallest window: the user name and the password.
    shoot(app, &label, "cred-small", Duration::from_secs(2));
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

    // 4. The most a credential window shows: the retry line, all four fields, "Save" and its hint, and the error
    //    of a refused answer. `credentials-largest.js` checks it fits and cancels (Connect when anything is wrong).
    let largest = match std::fs::read_to_string(dir.join("credentials-largest.js")) {
        Ok(source) => source,
        Err(e) => return say(format!("ERROR credentials-largest.js: {e}")),
    };
    let broker = state.credential_broker.clone();
    let prompt = macvpn_core::credentials::CredentialPrompt {
        connection_id: retry_key.clone(),
        connection_name: "Zz Credentials, the largest window".into(),
        kind: VPNKind::L2tp,
        fields: vec![
            macvpn_core::credentials::CredentialField::Username,
            macvpn_core::credentials::CredentialField::Password,
            macvpn_core::credentials::CredentialField::Psk,
            macvpn_core::credentials::CredentialField::KeyPassword,
        ],
        username: None,
        retry: true,
        deadline: PromptDeadline::new(Date::now()),
        credential: None,
    };
    let waiting = std::thread::spawn(move || broker.present(prompt, Date::now()));
    let Some((label, view)) = window() else { return say("ERROR no largest window".into()) };
    if let Err(e) = eval(app, &label, with_shot(&largest)) {
        say(format!("ERROR {e}"));
    }
    // The lock, the refused Connect and the resize come first.
    shoot(app, &label, "cred-large", Duration::from_secs(4));
    let answer = match waiting.join() {
        Ok(macvpn_core::credentials::CredentialAnswer::Cancelled) => "cancelled",
        Ok(macvpn_core::credentials::CredentialAnswer::Provided { .. }) => "connect",
        Err(_) => "panicked",
    };
    let closed = wait_for(10, || app.get_webview_window(&label).is_none().then_some(())).is_some();
    say(format!("largest fields={} answer={answer} closed={closed}", view.fields.join("+")));
}

// MARK: - The vault

/// What the smoke run types as the master password: at creation, after the recovery reset (compared by the vault
/// only, never logged).
const MASTER: &str = "smoke-master-4711";
const MASTER_RESET: &str = "smoke-reset-0815";
const MASTER_CHANGED: &str = "smoke-changed-2024";

/// Where the connections are written for `scripts/smoke-manage.sh` to check (the vault is encrypted): the 1.1 layout
/// (`connections/<UUID>/{meta.json,config}`) under the sandbox home. Smoke runs only (test data, no secret).
pub fn dump(state: &AppState) {
    let Some(_) = smoke_dir(state) else { return };
    let dir = state.env.home.join("smoke-dump/connections");
    let _ = std::fs::remove_dir_all(&dir);
    let store = macvpn_core::store::ConnectionStore::new(dir);
    let repo = &state.connections.deps().store;
    let Ok(list) = repo.list() else { return eprintln!("MacVPN smoke: dump: ERROR the vault is not readable") };
    for c in &list {
        let config = repo.load_config(&c.id).ok();
        if let Err(e) = store.save(c, config.as_deref()) {
            eprintln!("MacVPN smoke: dump: ERROR {e}");
        }
    }
    eprintln!("MacVPN smoke: dump: {} connections", list.len());
}

/// A vault window's script with its placeholders filled in (`__MODE__`, `__PASSWORD__`, `__NEW_PASSWORD__`,
/// `__RECOVERY_KEY__`); evaluated in `label`.
fn vault_script(app: &AppHandle, dir: &Path, label: &str, script: &str, values: &[(&str, &str)]) -> Result<(), String> {
    let mut source = std::fs::read_to_string(dir.join(script)).map_err(|e| e.to_string())?;
    for (placeholder, value) in values {
        source = source.replace(placeholder, value);
    }
    wait_for(20, || app.get_webview_window(label).map(|_| ())).ok_or("no window")?;
    eval(app, label, source)
}

/// The create window in migration mode (see the module docs), logged as `MacVPN smoke: vault: …` lines.
fn vault_create(app: &AppHandle, state: &Arc<AppState>, dir: &Path) {
    use macvpn_app_core::deps::SecretField;
    let say = |line: String| eprintln!("MacVPN smoke: vault: {line}");
    let setup = state.vault.view(false).1;
    say(format!(
        "create window migrating={} keychain_items={}",
        setup.as_ref().is_some_and(|s| s.migrating),
        setup.as_ref().map_or(0, |s| s.keychain_items)
    ));
    if let Err(e) = vault_script(app, dir, crate::vault::CREATE_WINDOW, "vault-create.js", &[("__PASSWORD__", MASTER)])
    {
        return say(format!("ERROR {e}"));
    }
    let done = wait_for(120, || {
        (state.vault.lifecycle.state() == macvpn_app_core::vault::VaultState::Unlocked
            && app.get_webview_window(crate::vault::CREATE_WINDOW).is_none())
        .then_some(())
    })
    .is_some();
    let support = state.env.application_support();
    let files_gone = !support.join("connections").exists() && !support.join("connection-order.json").exists();
    let marker = support.join(macvpn_app_core::migration::MARKER).exists();
    let key = recovery_key().is_some();
    let secret = parse_uuid(SEEDED_L2TP)
        .and_then(|id| state.connections.deps().secrets.get(&id, SecretField::Psk))
        .is_some_and(|psk| psk == SEEDED_PSK);
    let pinned = state.manager.is_pinned("21111111-2222-4333-8444-555555555555");
    say(format!(
        "created done={done} connections={} secret={} pinned={pinned} files_gone={files_gone} marker={marker} key={key}",
        state.manager.connections().len(),
        if secret { "yes" } else { "no" },
    ));
}

fn recovery_key() -> Option<zeroize::Zeroizing<String>> {
    RECOVERY_KEY.lock().unwrap_or_else(PoisonError::into_inner).clone()
}

/// Locks the vault the way "Lock now" does.
fn lock(state: &Arc<AppState>) {
    state.vault.lifecycle.lock();
    crate::vault::after_lock(state);
}

/// No seeded connection name anywhere in the view model (the menu and every window read it).
fn names_hidden(state: &AppState) -> bool {
    let vm = format!("{:?}", state.view_model());
    !vm.contains("Seeded") && !vm.contains("Zz ")
}

/// Opens the unlock window (unless the menu's "Unlock…" did), runs `vault-unlock.js`, and waits for the vault to
/// open.
fn unlock_with(app: &AppHandle, state: &Arc<AppState>, dir: &Path, values: &[(&str, &str)]) -> bool {
    let opened = if app.get_webview_window(crate::vault::UNLOCK_WINDOW).is_some() {
        Ok(())
    } else {
        crate::vault::open_window(app, state, crate::vault::UNLOCK_WINDOW)
    };
    if let Err(e) = opened.and_then(|()| vault_script(app, dir, crate::vault::UNLOCK_WINDOW, "vault-unlock.js", values))
    {
        eprintln!("MacVPN smoke: vault: ERROR {e}");
        return false;
    }
    wait_for(90, || {
        (state.vault.lifecycle.is_unlocked() && app.get_webview_window(crate::vault::UNLOCK_WINDOW).is_none())
            .then_some(())
    })
    .is_some()
}

/// Lock now from the menu, the locked menu, unlock (password after a wrong one, recovery key, new password), and the
/// master password changed in its window (see the module docs), logged as `MacVPN smoke: vault: …` lines.
fn vault_lock_unlock(app: &AppHandle, state: &Arc<AppState>, dir: &Path) {
    let say = |line: String| eprintln!("MacVPN smoke: vault: {line}");
    let count = || state.manager.connections().len();
    let before = count();
    // The menu: "Show “Lock Now”" in the settings, "Lock Now", the locked menu's "Unlock…" (vault-menu.js).
    let menu = vault_script(app, dir, crate::tray::MENU_WINDOW, "vault-menu.js", &[("__MODE__", "lock")]);
    let locked = wait_for(30, || (!state.vault.lifecycle.is_unlocked()).then_some(())).is_some();
    let hidden = locked && names_hidden(state);
    let window = wait_for(30, || app.get_webview_window(crate::vault::UNLOCK_WINDOW).map(|_| ())).is_some();
    say(format!(
        "menu lock_now={locked} names_hidden={hidden} unlock_window={window}{}",
        menu.err().map(|e| format!(" ERROR {e}")).unwrap_or_default()
    ));
    say(format!("locked state={:?} names_hidden={}", state.vault.view(false).0.state, names_hidden(state)));
    let ok = unlock_with(app, state, dir, &[("__MODE__", "wrong-then-right"), ("__PASSWORD__", MASTER)]);
    say(format!("unlocked password={ok} names_back={}", count() == before));

    let Some(key) = recovery_key() else { return say("ERROR no recovery key".into()) };
    lock(state);
    let ok = unlock_with(
        app,
        state,
        dir,
        &[("__MODE__", "recovery"), ("__RECOVERY_KEY__", key.as_str()), ("__NEW_PASSWORD__", MASTER_RESET)],
    );
    say(format!("unlocked recovery={ok} names_back={}", count() == before));

    lock(state);
    let ok = unlock_with(app, state, dir, &[("__MODE__", "password"), ("__PASSWORD__", MASTER_RESET)]);
    say(format!("unlocked new_password={ok} names_back={}", count() == before));

    // "Change Master Password…" in the menu's settings, then the password window (vault-password.js).
    let changed = vault_script(app, dir, crate::tray::MENU_WINDOW, "vault-menu.js", &[("__MODE__", "change")])
        .and_then(|()| {
            vault_script(
                app,
                dir,
                crate::vault::PASSWORD_WINDOW,
                "vault-password.js",
                &[("__PASSWORD__", MASTER_RESET), ("__NEW_PASSWORD__", MASTER_CHANGED)],
            )
        })
        .map(|()| {
            wait_for(60, || app.get_webview_window(crate::vault::PASSWORD_WINDOW).is_none().then_some(())).is_some()
        });
    say(format!(
        "password window closed={}",
        changed.unwrap_or_else(|e| {
            say(format!("ERROR {e}"));
            false
        })
    ));
    lock(state);
    let ok = unlock_with(app, state, dir, &[("__MODE__", "password"), ("__PASSWORD__", MASTER_CHANGED)]);
    say(format!("unlocked changed_password={ok} names_back={}", count() == before));
}

/// Shared credentials end to end (spec 3a; see `scripts/smoke/shared.js`), logged as `MacVPN smoke: shared: …`:
/// the Credentials section adds "Smoke Cred" (a user name, no password) and links the two seeded "Zz Shared"
/// connections through their editors' selector; connecting the first asks for the password only, naming the
/// credential and "used by 2", and "Save" stores it in the credential, so the second connects without a prompt;
/// Delete with "Copy into each connection" gives both their own copies; an import whose metadata names "Smoke
/// Import" asks first (with the config's server) and links only after the answer.
fn shared(app: &AppHandle, state: &Arc<AppState>, dir: &Path) {
    use macvpn_app_core::deps::SecretField;
    let say = |line: String| eprintln!("MacVPN smoke: shared: {line}");
    let (Ok(source), Ok(prompt_source)) =
        (std::fs::read_to_string(dir.join("shared.js")), std::fs::read_to_string(dir.join("shared-prompt.js")))
    else {
        return say("ERROR shared.js / shared-prompt.js".into());
    };
    let find = |id: &str| {
        let id = parse_uuid(id)?;
        state.manager.connections().into_iter().find(|c| c.id == id)
    };
    let (Some(one), Some(two)) = (find(SHARED_ONE), find(SHARED_TWO)) else {
        return say("ERROR the seeded connections are missing".into());
    };
    let Some(credentials) = state.connections.shared_credentials() else { return say("ERROR no vault".into()) };
    let secrets = state.connections.deps().secrets.clone();
    let phase = |phase: &str| {
        let script = format!("window.__smokeShared = '{phase}';\n{source}");
        if let Err(e) = crate::commands::open(app, "manage").and_then(|()| eval(app, "manage", script)) {
            say(format!("ERROR {phase}: {e}"));
        }
    };
    let smoke_cred = || credentials.list().ok()?.into_iter().find(|s| s.credential.name == "Smoke Cred");

    // 1. Add the credential and link both connections, in the window.
    phase("setup");
    let linked = wait_for(60, || {
        let a = secrets.credential_for(&one.id)?;
        let b = secrets.credential_for(&two.id)?;
        (a.name == "Smoke Cred" && b.name == "Smoke Cred").then_some(a.used_by)
    });
    let user_ok = smoke_cred().is_some_and(|c| c.credential.username == SHARED_USER && !c.credential.has_password);
    say(format!("linked={} used_by={} user={user_ok}", linked.is_some(), linked.unwrap_or(0)));

    // 2. The first connect asks for the password only, naming the credential; "Save" stores it there.
    let connect = |c: &macvpn_core::models::Connection| {
        let (manager, c) = (state.manager.clone(), c.clone());
        std::thread::spawn(move || manager.connect(&c, false))
    };
    let worker = connect(&one);
    let window = wait_for(15, || state.credential_broker.pending().first().cloned()).and_then(|p| {
        let label = macvpn_app_core::notify::credential_window_label(p.id);
        wait_for(10, || app.get_webview_window(&label).map(|_| (label.clone(), p.clone())))
    });
    let Some((label, view)) = window else { return say("ERROR no credential window".into()) };
    say(format!(
        "prompt fields={} credential={} used_by={}",
        view.fields.join("+"),
        view.credential_name.as_deref().unwrap_or("-"),
        view.used_by.unwrap_or(0)
    ));
    if let Err(e) = eval(app, &label, prompt_source) {
        say(format!("ERROR {e}"));
    }
    let _ = worker.join();
    let key_one = uuid_string(&one.id);
    let connected = wait_for(15, || state.manager.state(&key_one).is_connected().then_some(())).is_some();
    let saved = wait_for(10, || smoke_cred().filter(|c| c.credential.has_password)).is_some()
        && secrets.get(&two.id, SecretField::Password).as_deref() == Some(SHARED_PASSWORD);
    say(format!("first connected={connected} saved_in_credential={saved}"));

    // The second linked connection: nothing to ask.
    let key_two = uuid_string(&two.id);
    let worker = connect(&two);
    let asked = wait_for(5, || {
        let asked = state.credential_broker.prompt_for_connection(&key_two).is_some();
        (asked || state.manager.state(&key_two).is_connected()).then_some(asked)
    });
    if asked == Some(true) {
        state.credential_broker.dismiss(&key_two);
    }
    let _ = worker.join();
    say(format!("second prompt={} connected={}", asked.unwrap_or(true), state.manager.state(&key_two).is_connected()));
    state.manager.disconnect(&one);
    state.manager.disconnect(&two);

    // 3. Delete, "Copy into each connection": both keep the values as their own.
    phase("delete");
    let copied = wait_for(30, || {
        let own = |c: &macvpn_core::models::Connection| {
            secrets.credential_for(&c.id).is_none()
                && secrets.get(&c.id, SecretField::Username).as_deref() == Some(SHARED_USER)
                && secrets.get(&c.id, SecretField::Password).as_deref() == Some(SHARED_PASSWORD)
        };
        (smoke_cred().is_none() && own(&one) && own(&two)).then_some(())
    })
    .is_some();
    say(format!("deleted copied={copied}"));

    // 4. An import naming an existing credential: the question first, the link only after "Use".
    if let Err(e) = state.connections.add_credential("Smoke Import", "import-user", None) {
        return say(format!("ERROR {e}"));
    }
    let Some(base) = state.env.staging_parent() else { return say("ERROR no sandbox tmp".into()) };
    let Ok(folder) = private_temp_dir("macvpn-smoke-import", &base) else {
        return say("ERROR no import folder".into());
    };
    let path = folder.join("Zz Shared import.ovpn");
    let text = "# macvpn-meta: {\"credentialName\":\"Smoke Import\"}\nclient\ndev tun\nremote vpn.example.com 1194\nauth-user-pass\n";
    if let Err(e) = std::fs::write(&path, text) {
        return say(format!("ERROR {e}"));
    }
    let importing = state.clone();
    let worker = std::thread::spawn(move || importing.connections.import_paths(&[path]));
    let imported = || state.connections.deps().store.list().ok()?.into_iter().find(|c| c.name == "Zz Shared import");
    let asked = wait_for(15, || state.connections.questions().current()).is_some();
    let before = imported().is_some_and(|c| secrets.credential_for(&c.id).is_none());
    say(format!("import asked={asked} unlinked_before_answer={before}"));
    phase("import");
    let _ = worker.join();
    let after = imported().and_then(|c| secrets.credential_for(&c.id)).map(|c| c.name);
    let stored = imported().and_then(|c| state.connections.deps().store.load_config(&c.id).ok());
    say(format!(
        "import linked={} meta_stripped={}",
        after.as_deref() == Some("Smoke Import"),
        stored.is_some_and(|t| t.starts_with("client\n"))
    ));
    let _ = std::fs::remove_dir_all(&folder);
}

/// The backup step's seeded connections: the canary (its name, config line and password must never be in the file
/// in clear) and one added after the backup (gone after "Replace everything").
const BACKUP_CANARY: &str = "F1111111-2222-4333-8444-555555555555";
const BACKUP_EXTRA: &str = "F2111111-2222-4333-8444-555555555555";
const BACKUP_CANARY_NAME: &str = "Smoke Backup canary";
const BACKUP_CANARY_LINE: &str = "remote smoke-canary.example.com 1194";
const BACKUP_CANARY_SECRET: &str = "smoke-canary-secret-4711";
/// The smoke run's backup file, in place of the save and open panels: `<sandbox>/tmp/smoke.macvpnbackup`.
pub fn backup_file(state: &AppState) -> Option<PathBuf> {
    smoke_dir(state)?;
    let dir = state.env.home.join("tmp");
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir.join("smoke.macvpnbackup"))
}

/// The vault's backup service (attached in `build_state`).
fn backup_service(state: &AppState) -> Result<Arc<macvpn_app_core::backup::BackupService>, String> {
    state.backup.service().ok_or_else(|| "no backup service".to_string())
}

/// The full backup: `backup.js` backs the vault up into the sandbox `tmp` (the file must be 0600 and hold no seeded
/// name, config line or secret in clear); the canary is renamed; `restore.js` first tries a wrong password (the
/// generic message), then merges with Overwrite (the name is back); then a connection is added and the canary
/// renamed again, and `restore.js` replaces everything (the name is back, the added connection gone, the control
/// API not switched on although the backup had it on). `MacVPN smoke: backup: …`.
fn backup(app: &AppHandle, state: &Arc<AppState>, dir: &Path) {
    use macvpn_core::models::{Connection, SecretField};
    let say = |line: String| eprintln!("MacVPN smoke: backup: {line}");
    let (Ok(backup_js), Ok(restore_js)) =
        (std::fs::read_to_string(dir.join("backup.js")), std::fs::read_to_string(dir.join("restore.js")))
    else {
        return say("ERROR backup.js / restore.js missing".into());
    };
    let service = match backup_service(state) {
        Ok(service) => service,
        Err(e) => return say(format!("ERROR no vault: {e}")),
    };
    let vault = service.vault().clone();
    let (Some(canary_id), Some(extra_id)) = (parse_uuid(BACKUP_CANARY), parse_uuid(BACKUP_EXTRA)) else { return };
    let save = |id: Uuid, name: &str| {
        let c = Connection::with_id(id, name, VPNKind::Openvpn, Date::now());
        let config = format!("client\ndev tun\n{BACKUP_CANARY_LINE}\n");
        vault.with(|v| v.save_connection(&c, Some(&config)))
    };
    let name = || {
        vault
            .with_read(|v| Ok(v.connections()?.into_iter().find(|s| s.connection.id == canary_id)))
            .ok()
            .flatten()
            .map(|s| s.connection.name)
    };
    let seeded = save(canary_id, BACKUP_CANARY_NAME).and_then(|()| {
        vault.with(|v| v.set_secret(&uuid_string(&canary_id), SecretField::Password, BACKUP_CANARY_SECRET))
    });
    if let Err(e) = seeded {
        return say(format!("ERROR seeding the vault: {e}"));
    }
    // The backup carries the control API on; the restore must not switch it on by itself.
    state.prefs.set_bool(crate::control::ENABLED_KEY, true);
    let Some(file) = backup_file(state) else { return };
    let _ = std::fs::remove_file(&file);

    // 1. Back up.
    let run = |window: &str, source: String| crate::backup::show(app, window).and_then(|()| eval(app, window, source));
    if let Err(e) = run(crate::backup::BACKUP_WINDOW, backup_js.replace("__MASTER__", MASTER)) {
        return say(format!("ERROR {e}"));
    }
    let written = wait_for(60, || {
        let closed = app.get_webview_window(crate::backup::BACKUP_WINDOW).is_none();
        (closed && file.exists()).then_some(())
    });
    state.prefs.set_bool(crate::control::ENABLED_KEY, false);
    let Some(()) = written else { return say("ERROR no backup file".into()) };
    let mode = mode(&file);
    let bytes = std::fs::read(&file).unwrap_or_default();
    let clear = [BACKUP_CANARY_NAME, BACKUP_CANARY_LINE, BACKUP_CANARY_SECRET, "Seeded A"]
        .iter()
        .any(|needle| bytes.windows(needle.len()).any(|w| w == needle.as_bytes()));
    say(format!("saved mode={mode} clear={}", if clear { "yes" } else { "no" }));

    // 2. A wrong password, then Merge with Overwrite.
    if let Err(e) = save(canary_id, "Smoke changed") {
        return say(format!("ERROR {e}"));
    }
    if let Err(e) = run(crate::backup::RESTORE_WINDOW, format!("window.__SMOKE_RESTORE__ = 'merge';\n{restore_js}")) {
        return say(format!("ERROR {e}"));
    }
    let merged = wait_for(90, || {
        let closed = app.get_webview_window(crate::backup::RESTORE_WINDOW).is_none();
        (closed && name().as_deref() == Some(BACKUP_CANARY_NAME)).then_some(())
    });
    say(format!("merge restored={}", if merged.is_some() { "yes" } else { "no" }));

    // 3. Replace everything.
    if let Err(e) = save(canary_id, "Smoke changed again").and_then(|()| save(extra_id, "Smoke added later")) {
        return say(format!("ERROR {e}"));
    }
    if let Err(e) = run(crate::backup::RESTORE_WINDOW, format!("window.__SMOKE_RESTORE__ = 'replace';\n{restore_js}")) {
        return say(format!("ERROR {e}"));
    }
    let replaced = wait_for(90, || {
        let closed = app.get_webview_window(crate::backup::RESTORE_WINDOW).is_none();
        (closed && name().as_deref() == Some(BACKUP_CANARY_NAME)).then_some(())
    });
    let extra_gone =
        vault.with_read(|v| Ok(v.connections()?.iter().all(|s| s.connection.id != extra_id))).unwrap_or(false);
    let control = state.prefs.bool(crate::control::ENABLED_KEY).unwrap_or(false);
    say(format!(
        "replace restored={} extra-gone={} control-api={}",
        if replaced.is_some() { "yes" } else { "no" },
        if extra_gone { "yes" } else { "no" },
        if control { "on" } else { "off" }
    ));
    let _ = std::fs::remove_file(&file);
}

// MARK: - Team catalogs (the subscriber's side)

/// The team catalog step's result connection (created in the vault for the step, deleted after it).
const CATALOG_RESULT: &str = "E5111111-2222-4333-8444-555555555555";
const CATALOG_NAME: &str = "Smoke Catalog";
/// A config line that must never be in the catalog file in clear.
const CATALOG_CONFIG_LINE: &str = "remote smoke-team.example.com 1194";

/// The pre-sealed fixture catalog of the step: version 1 holds "Smoke Team A" (in the teal folder "Smoke Team", with
/// a risky `user` line) and "Smoke Team B"; version 2 renames A and adds "Smoke Team C". Signed with a throwaway admin
/// key and encrypted with a throwaway team key, both made here (never logged).
struct SmokeCatalog {
    admin: macvpn_core::catalog::keys::AdminKey,
    team: macvpn_core::catalog::keys::TeamKey,
    id: Uuid,
}

impl SmokeCatalog {
    fn new() -> Result<Self, String> {
        use macvpn_core::catalog::keys::{AdminKey, TeamKey};
        let entropy = super::get().entropy();
        Ok(SmokeCatalog {
            admin: AdminKey::generate(&*entropy).map_err(|e| e.to_string())?,
            team: TeamKey::generate(&*entropy).map_err(|e| e.to_string())?,
            id: Uuid::new_v4(),
        })
    }

    fn write(&self, path: &Path, version: u64) -> Result<(), String> {
        use macvpn_core::catalog::format::{CatalogHeaderInput, seal_catalog};
        use macvpn_core::catalog::payload::{CatalogConnection, CatalogFolder, CatalogPayload, PAYLOAD_VERSION};
        use macvpn_core::vault::FolderColor;
        let folder = Uuid::from_u128(0x5A0E_0001);
        let connection = |n: u128, name: &str, folder: Option<Uuid>, extra: &str| CatalogConnection {
            id: Uuid::from_u128(0x5A0E_1000 + n),
            name: name.into(),
            kind: VPNKind::Openvpn,
            folder,
            color: None,
            config: zeroize::Zeroizing::new(format!("client\ndev tun\n{CATALOG_CONFIG_LINE}\n{extra}")),
            native: None,
            otp: Default::default(),
            slot: None,
            secret_refs: Default::default(),
        };
        let mut connections = vec![
            connection(1, if version == 1 { "Smoke Team A" } else { "Smoke Team A2" }, Some(folder), "user nobody\n"),
            connection(2, "Smoke Team B", None, ""),
        ];
        if version > 1 {
            connections.push(connection(3, "Smoke Team C", Some(folder), ""));
        }
        let payload = CatalogPayload {
            version: PAYLOAD_VERSION,
            folders: vec![CatalogFolder {
                id: folder,
                parent: None,
                name: "Smoke Team".into(),
                color: Some(FolderColor::Teal),
                position: 0,
            }],
            connections,
            credential_slots: vec![],
            shared_secrets: Default::default(),
        };
        let input = CatalogHeaderInput {
            catalog_id: self.id,
            name: CATALOG_NAME.into(),
            version,
            created: Date::now(),
            successor_key: None,
        };
        let bytes = seal_catalog(input, &payload, &self.team, &self.admin, &*super::get().entropy())
            .map_err(|e| e.to_string())?;
        std::fs::write(path, bytes).map_err(|e| e.to_string())
    }
}

/// The subscriber's UI end to end (plan Task 16), in the Connections window, phase by phase (`catalog.js`, each
/// phase writing its result into [`CATALOG_RESULT`]'s name: `CATALOG <phase> OK` / `… FAILED <checks>`):
/// `preview` adds the catalog through the file source (the open panel replaced by [`panel_file`]) with the team key
/// and the fingerprint typed, and checks the preview; `subscribe` compares, subscribes and checks the detail and the
/// Team badges; `readonly` opens a team connection (the read-only note, the disabled config, the risky checkbox
/// active, the context menu's allowed actions, a refused drag with its reason); then version 2 is written and
/// `update` clicks "Refresh now" (the outcome line, the renamed and the added connection); `ask` and `unsubscribe`
/// confirm the unsubscribe. `MacVPN smoke: catalog: …` lines; the keys are only substituted into the script.
fn team_catalog(app: &AppHandle, state: &Arc<AppState>, dir: &Path) {
    use macvpn_core::models::Connection;
    let say = |line: String| eprintln!("MacVPN smoke: catalog: {line}");
    let source = match std::fs::read_to_string(dir.join("catalog.js")) {
        Ok(source) => source,
        Err(e) => return say(format!("ERROR catalog.js: {e}")),
    };
    let (Some(file), Some(result_id)) =
        (panel_file(state, macvpn_core::catalog::format::EXTENSION), parse_uuid(CATALOG_RESULT))
    else {
        return;
    };
    let fixture = match SmokeCatalog::new() {
        Ok(fixture) => fixture,
        Err(e) => return say(format!("ERROR {e}")),
    };
    if let Err(e) = fixture.write(&file, 1) {
        return say(format!("ERROR {e}"));
    }
    let bytes = std::fs::read(&file).unwrap_or_default();
    let clear = ["Smoke Team A", CATALOG_CONFIG_LINE].iter().any(|n| bytes.windows(n.len()).any(|w| w == n.as_bytes()));
    say(format!("fixture written clear={}", if clear { "yes" } else { "no" }));
    let vault = match backup_service(state) {
        Ok(service) => service.vault().clone(),
        Err(e) => return say(format!("ERROR {e}")),
    };
    let result = Connection::with_id(result_id, "Zz Catalog result", VPNKind::Openvpn, Date::now());
    if let Err(e) = vault.with(|v| v.save_connection(&result, Some("client\ndev tun\nremote vpn.example.com 1194\n"))) {
        return say(format!("ERROR {e}"));
    }
    state.manager.reload();

    let team_key = fixture.team.to_text();
    let fingerprint = fixture.admin.public().fingerprint().to_text();
    let phase = |phase: &str, shot: Option<&str>| {
        let script = format!("window.__smokeCatalog = '{phase}';\n{source}")
            .replace("__TEAM_KEY__", &team_key)
            .replace("__FINGERPRINT__", &fingerprint);
        let prefix = format!("CATALOG {phase} ");
        let outcome = crate::commands::open(app, "manage").and_then(|()| eval(app, "manage", script)).and_then(|()| {
            wait_for(60, || renamed(state, CATALOG_RESULT, &prefix)).ok_or_else(|| "no result".to_string())
        });
        say(format!("{phase}: {}", outcome.unwrap_or_else(|e| format!("ERROR {e}"))));
        if let Some(name) = shot {
            shoot(app, "manage", name, Duration::from_millis(600));
        }
    };
    let names = || {
        let badges = state.catalog.service.badges();
        let mut names: Vec<String> = state
            .manager
            .connections()
            .into_iter()
            .filter(|c| badges.contains_key(&uuid_string(&c.id)))
            .map(|c| c.name)
            .collect();
        names.sort();
        names.join("+")
    };

    phase("preview", Some("catalog-preview"));
    phase("subscribe", Some("catalog-detail"));
    let views = state.catalog.service.view();
    let read_only = state
        .manager
        .connections()
        .into_iter()
        .find(|c| c.name == "Smoke Team A")
        .and_then(|c| state.catalog.service.read_only_reason(&uuid_string(&c.id)))
        .is_some();
    say(format!(
        "subscribed catalogs={} version={} items={} read_only={read_only} team_folders={}",
        views.len(),
        views.first().and_then(|v| v.version).unwrap_or(0),
        names(),
        state.manager.folders().len(),
    ));
    phase("readonly", Some("catalog-readonly"));

    // Version 2 on the "share"; the UI's "Refresh now" applies it.
    if let Err(e) = fixture.write(&file, 2) {
        return say(format!("ERROR {e}"));
    }
    phase("update", Some("catalog-refreshed"));
    let version = state.catalog.service.view().first().and_then(|v| v.version).unwrap_or(0);
    say(format!("updated version={version} items={}", names()));

    phase("ask", Some("catalog-unsubscribe"));
    phase("unsubscribe", None);
    say(format!("unsubscribed catalogs={} items={}", state.catalog.service.view().len(), names().len()));

    let _ = vault.with(|v| v.delete_connection(&result_id));
    state.manager.reload();
    let _ = std::fs::remove_dir_all(file.parent().unwrap_or(&file));
}

// MARK: - Files opened from Finder

/// The open step's result connection (created in the vault for the step, deleted after it).
const OPEN_RESULT: &str = "E6111111-2222-4333-8444-555555555555";
/// The OpenVPN fixtures inline this CA file (the import's report then has a line for each file).
const OPEN_CA: &str = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUSmokeOpen\n-----END CERTIFICATE-----\n";

/// Files opened from Finder (`open.js`), the open event simulated with sandbox fixtures through
/// [`crate::open_files::receive`] (what `RunEvent::Opened` calls): one `.ovpn` with the Connections window closed
/// (it opens, the report appears), two at once, the team catalog fixture (the add dialog with the file source, the
/// key and the fingerprint still empty; cancelled, nothing subscribed), one while the vault is locked (the unlock
/// window, nothing imported before the unlock, imported after it) and one whose unlock is cancelled (dropped). None of
/// them connects, and no path reaches the view model. `MacVPN smoke: open: …` lines.
fn opened_files(app: &AppHandle, state: &Arc<AppState>, dir: &Path) {
    use macvpn_core::models::Connection;
    let say = |line: String| eprintln!("MacVPN smoke: open: {line}");
    let source = match std::fs::read_to_string(dir.join("open.js")) {
        Ok(source) => source,
        Err(e) => return say(format!("ERROR open.js: {e}")),
    };
    let Some(result_id) = parse_uuid(OPEN_RESULT) else { return };
    let Some(base) = state.env.staging_parent() else { return say("ERROR no sandbox tmp".into()) };
    let Ok(folder) = private_temp_dir("macvpn-smoke-open", &base) else {
        return say("ERROR no fixture folder".into());
    };
    let ovpn = |name: &str| -> Option<PathBuf> {
        let path = folder.join(format!("{name}.ovpn"));
        std::fs::write(&path, "client\ndev tun\nremote open.example.com 1194\nca ca.crt\n").ok()?;
        Some(path)
    };
    let fixtures = (
        std::fs::write(folder.join("ca.crt"), OPEN_CA).ok(),
        ovpn("Zz Open one"),
        ovpn("Zz Open two"),
        ovpn("Zz Open three"),
        ovpn("Zz Open locked"),
        ovpn("Zz Open cancelled"),
    );
    let (Some(()), Some(one), Some(two), Some(three), Some(locked), Some(cancelled)) = fixtures else {
        return say("ERROR fixtures".into());
    };
    // The team catalog fixture of the catalog step, sealed again under its own name.
    let catalog = folder.join("Smoke Open.macvpncatalog");
    if let Err(e) = SmokeCatalog::new().and_then(|fixture| fixture.write(&catalog, 1)) {
        return say(format!("ERROR {e}"));
    }
    let vault = match backup_service(state) {
        Ok(service) => service.vault().clone(),
        Err(e) => return say(format!("ERROR {e}")),
    };
    let result = Connection::with_id(result_id, "Zz Open result", VPNKind::Openvpn, Date::now());
    if let Err(e) = vault.with(|v| v.save_connection(&result, Some("client\ndev tun\nremote vpn.example.com 1194\n"))) {
        return say(format!("ERROR {e}"));
    }
    state.manager.reload();

    let imported = |name: &str| -> Option<Uuid> {
        state.connections.deps().store.list().ok()?.into_iter().find(|c| c.name == name).map(|c| c.id)
    };
    let connected = |names: &[&str]| {
        names.iter().filter_map(|n| imported(n)).any(|id| state.manager.state(&uuid_string(&id)).is_connected())
    };
    let phase = |phase: &str, names: &[&str]| {
        let names = format!("[{}]", names.iter().map(|n| format!("'{n}'")).collect::<Vec<_>>().join(", "));
        let script = format!("window.__smokeOpen = '{phase}';\nwindow.__smokeOpenNames = {names};\n{source}");
        let prefix = format!("OPEN {phase} ");
        let outcome = wait_for(20, || app.get_webview_window("manage").map(|_| ()))
            .ok_or_else(|| "no Connections window".to_string())
            .and_then(|()| eval(app, "manage", script))
            .and_then(|()| {
                wait_for(60, || renamed(state, OPEN_RESULT, &prefix)).ok_or_else(|| "no result".to_string())
            });
        say(format!("{phase}: {}", outcome.unwrap_or_else(|e| format!("ERROR {e}"))));
    };

    // One file, the Connections window closed: it opens and shows the report.
    if let Some(window) = app.get_webview_window("manage") {
        let _ = window.destroy();
    }
    wait_for(10, || app.get_webview_window("manage").is_none().then_some(()));
    crate::open_files::receive(app, state, vec![one.clone()]);
    let window = wait_for(20, || app.get_webview_window("manage").map(|_| ())).is_some();
    let done = wait_for(30, || imported("Zz Open one")).is_some();
    say(format!("one window={window} imported={done} connected={}", connected(&["Zz Open one"])));
    phase("one", &["Zz Open one.ovpn"]);

    // Two files at once: one import, one report.
    crate::open_files::receive(app, state, vec![two.clone(), three.clone()]);
    let done = wait_for(30, || imported("Zz Open two").zip(imported("Zz Open three"))).is_some();
    say(format!("two imported={done} connected={}", connected(&["Zz Open two", "Zz Open three"])));
    phase("two", &["Zz Open two.ovpn", "Zz Open three.ovpn"]);

    // The team catalog file: the add dialog with the file source.
    crate::open_files::receive(app, state, vec![catalog.clone()]);
    phase("catalog", &["Smoke Open.macvpncatalog"]);
    say(format!("catalog subscribed={}", state.catalog.service.view().len()));

    // Nothing of the paths in the view model (the menu and every window read it).
    let folder_text = folder.to_string_lossy().into_owned();
    let vm = format!("{:?}", state.view_model());
    say(format!(
        "view_model_paths={}",
        if vm.contains(&folder_text) || vm.contains(".macvpncatalog") { "yes" } else { "no" }
    ));

    // Locked: the unlock window, the import after the unlock.
    lock(state);
    crate::open_files::receive(app, state, vec![locked.clone()]);
    let window = wait_for(20, || app.get_webview_window(crate::vault::UNLOCK_WINDOW).map(|_| ())).is_some();
    std::thread::sleep(Duration::from_secs(1));
    let before = imported("Zz Open locked").is_some();
    say(format!("locked unlock_window={window} imported_before_unlock={before}"));
    let unlocked = unlock_with(app, state, dir, &[("__MODE__", "password"), ("__PASSWORD__", MASTER)]);
    let done = wait_for(30, || imported("Zz Open locked")).is_some();
    say(format!("locked unlocked={unlocked} imported={done} connected={}", connected(&["Zz Open locked"])));
    phase("locked", &["Zz Open locked.ovpn"]);

    // Locked, the unlock window closed: the file is dropped.
    lock(state);
    crate::open_files::receive(app, state, vec![cancelled.clone()]);
    let window =
        wait_for(20, || app.get_webview_window(crate::vault::UNLOCK_WINDOW)).is_some_and(|w| w.destroy().is_ok());
    wait_for(10, || app.get_webview_window(crate::vault::UNLOCK_WINDOW).is_none().then_some(()));
    let unlocked = unlock_with(app, state, dir, &[("__MODE__", "password"), ("__PASSWORD__", MASTER)]);
    std::thread::sleep(Duration::from_secs(3));
    say(format!("cancelled closed={window} unlocked={unlocked} imported={}", imported("Zz Open cancelled").is_some()));

    for name in ["Zz Open one", "Zz Open two", "Zz Open three", "Zz Open locked", "Zz Open cancelled"] {
        if let Some(id) = imported(name) {
            let _ = vault.with(|v| v.delete_connection(&id));
        }
    }
    let _ = vault.with(|v| v.delete_connection(&result_id));
    state.manager.reload();
    let _ = std::fs::remove_dir_all(&folder);
}

// MARK: - Publishing (the publisher's side)

/// The smoke run's stand-in for the save and open panels of the catalog files (debug builds only):
/// `<sandbox>/tmp/smoke-share/smoke.<extension>`: the subscriber's file source (a `.macvpncatalog`, sealed by
/// [`team_catalog`] with the core's own functions) and the publisher's catalog and admin key files (a `.macvpncatalog`
/// or a `.macvpnadminkey`, written by the UI in [`publishing`]). Each step removes the folder when it is done.
pub fn panel_file(state: &AppState, extension: &str) -> Option<PathBuf> {
    smoke_dir(state)?;
    let dir = state.env.home.join("tmp").join("smoke-share");
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir.join(format!("smoke.{extension}")))
}

/// The publishing step's seeded folder and connection (published by `publish.js`).
const PUBLISH_CONNECTION: &str = "F3111111-2222-4333-8444-555555555555";
const PUBLISH_FOLDER_NAME: &str = "Smoke Publish";
const PUBLISH_CONNECTION_NAME: &str = "Smoke Published";
const PUBLISH_CONFIG_LINE: &str = "remote smoke-publish.example.com 1194";

/// Publishing (spec 7) through the real UI, `publish.js` phase by phase: the admin key and the backup key
/// generated, a seeded folder published to the sandbox file (0644, opens with the stored team key and the admin
/// key's fingerprint, no seeded text in clear), published again (v2), the team key rotated (v3: the old team key no
/// longer opens it), the backup key exported with "remove after" (offline, the key file 0600) and imported again.
/// `MacVPN smoke: publish: …`. With screenshots on, the section and the wizard's steps are taken.
fn publishing(app: &AppHandle, state: &Arc<AppState>, dir: &Path) {
    use macvpn_core::catalog::format::{CatalogError, OpenRequest, Trust, open_catalog};
    use macvpn_core::models::Connection;
    use macvpn_core::vault::AdminKeyRole;
    let say = |line: String| eprintln!("MacVPN smoke: publish: {line}");
    let Ok(source) = std::fs::read_to_string(dir.join("publish.js")) else {
        return say("ERROR publish.js missing".into());
    };
    let vault = match backup_service(state) {
        Ok(service) => service.vault().clone(),
        Err(e) => return say(format!("ERROR no vault: {e}")),
    };
    let Some(id) = parse_uuid(PUBLISH_CONNECTION) else { return };
    let seeded = vault.with(|v| {
        let folder = v.create_folder(None, PUBLISH_FOLDER_NAME)?;
        let c = Connection::with_id(id, PUBLISH_CONNECTION_NAME, VPNKind::Openvpn, Date::now());
        v.save_connection(&c, Some(&format!("client\ndev tun\n{PUBLISH_CONFIG_LINE}\n")))?;
        v.set_item_folder(PUBLISH_CONNECTION, Some(folder))?;
        Ok(folder)
    });
    let folder = match seeded {
        Ok(folder) => folder,
        Err(e) => return say(format!("ERROR seeding: {e}")),
    };
    state.manager.reload_all();
    state.publisher.mark();
    let (Some(catalog_file), Some(key_file)) = (
        panel_file(state, macvpn_core::catalog::format::EXTENSION),
        panel_file(state, macvpn_core::catalog::admin_file::EXTENSION),
    ) else {
        return say("ERROR no sandbox tmp".into());
    };
    let _ = std::fs::remove_file(&catalog_file);
    let _ = std::fs::remove_file(&key_file);
    let script = source.replace("__FOLDER__", &uuid_string(&folder));
    let phase = |phase: &str| {
        let source = with_shot(&format!("window.__smokePublish = '{phase}';\n{script}"));
        if let Err(e) = crate::commands::open(app, "manage").and_then(|()| eval(app, "manage", source)) {
            say(format!("ERROR {phase}: {e}"));
        }
    };
    let keys = || vault.with_read(|v| v.admin_keys()).unwrap_or_default();
    let publication = || vault.with_read(|v| Ok(v.publications()?.into_iter().next())).ok().flatten();
    let version = |n: u64| move || publication().filter(|p| p.version == n);
    let opens = |team_key: &macvpn_core::catalog::keys::TeamKey| -> Result<u64, CatalogError> {
        let bytes = std::fs::read(&catalog_file).map_err(|e| CatalogError::Io(e.to_string()))?;
        let pinned = keys().into_iter().find(|k| k.role == AdminKeyRole::Primary).map(|k| k.fingerprint);
        let pinned = pinned.ok_or(CatalogError::UnknownPublisher)?;
        let trust = Trust { pinned, publisher_key: None, successor: None };
        let request = OpenRequest { trust: &trust, catalog_id: None, applied_version: None, team_key };
        open_catalog(&bytes, &request).map(|opened| opened.header.version)
    };
    let team_key =
        |p: &macvpn_core::vault::PublicationRecord| vault.with_read(|v| v.publication_team_key(p.catalog_id));

    // 1. The admin key and the backup key.
    phase("keys");
    let generated = wait_for(30, || (keys().len() == 2).then_some(()));
    say(format!("keys generated={}", generated.is_some()));
    shoot(app, "manage", "publishing-keys", Duration::from_secs(2));

    // 2. The wizard: the folder, the review, the name, the file (v1), the team key once.
    phase("select");
    shoot(app, "manage", "publish-select", Duration::from_secs(3));
    phase("review");
    shoot(app, "manage", "publish-review", Duration::from_secs(4));
    phase("name");
    let first = wait_for(60, version(1));
    shoot(app, "manage", "publish-reveal", Duration::from_secs(3));
    phase("reveal");
    let Some(first) = first else { return say("ERROR no version 1".into()) };
    let bytes = std::fs::read(&catalog_file).unwrap_or_default();
    let clear = [PUBLISH_CONNECTION_NAME, PUBLISH_CONFIG_LINE, PUBLISH_FOLDER_NAME]
        .iter()
        .any(|needle| bytes.windows(needle.len()).any(|w| w == needle.as_bytes()));
    let opened = team_key(&first).map_err(|e| e.to_string()).and_then(|k| opens(&k).map_err(|e| e.to_string()));
    say(format!(
        "v1 mode={} opens={} clear={}",
        mode(&catalog_file),
        opened.map_or_else(|e| format!("ERROR {e}"), |v| format!("v{v}")),
        if clear { "yes" } else { "no" }
    ));
    std::thread::sleep(Duration::from_secs(4));
    shoot(app, "manage", "publications", Duration::from_secs(2));

    // 3. Publish again: v2.
    phase("again");
    let second = wait_for(60, version(2));
    say(format!("again version={}", second.as_ref().map_or(0, |p| p.version)));

    // 4. Rotate the team key: v3, the old key no longer opens the file.
    let old_key = second.as_ref().and_then(|p| team_key(p).ok());
    phase("rotate");
    shoot(app, "manage", "publish-rotate", Duration::from_secs(8));
    let third = wait_for(90, version(3));
    let old_refused = old_key.as_ref().map(|k| matches!(opens(k), Err(CatalogError::WrongTeamKey)));
    let new_opens = third.as_ref().and_then(|p| team_key(p).ok()).map(|k| opens(&k).ok());
    say(format!(
        "rotate version={} old_key_refused={} new_key_opens={}",
        third.as_ref().map_or(0, |p| p.version),
        old_refused.unwrap_or(false),
        new_opens.flatten().map_or_else(|| "no".to_string(), |v| format!("v{v}"))
    ));
    std::thread::sleep(Duration::from_secs(4));

    // 5. Export the backup key (removed after), then import it again.
    let offline = || keys().into_iter().find(|k| k.role == AdminKeyRole::Backup).map(|k| k.offline);
    phase("export");
    let exported = wait_for(90, || (offline() == Some(true) && key_file.exists()).then_some(()));
    shoot(app, "manage", "publishing-offline", Duration::from_secs(2));
    say(format!("export offline={} mode={}", exported.is_some(), mode(&key_file)));
    phase("import");
    let imported = wait_for(90, || (offline() == Some(false)).then_some(()));
    say(format!("import online={}", imported.is_some()));
    let _ = std::fs::remove_dir_all(catalog_file.parent().unwrap_or(&catalog_file));
}
