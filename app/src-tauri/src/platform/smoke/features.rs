//! The 2.0 features in the smoke run (features plan, Task 15), after the folders step. Each section prints its steps
//! and ends with `MacVPN smoke: <section>: ok` or `… FAILED <checks>` (`scripts/smoke-manage.sh` expects the `ok`):
//!
//! - `appearance` (`appearance.js`): the menu's Settings – Dark, Light, Match System clicked in the popover; after
//!   each, `prefers-color-scheme: dark` in the popover and in the Connections window (Match System: the value the
//!   popover had before the first click).
//! - `engines` (`engines.js`): with a report that lacks one engine (macOS: `sstpc`, so SSTP; Windows: OpenVPN
//!   Community), a seeded row of that kind in the popover says "Not installed: … – System Status", its switch is
//!   disabled and the link opens System Status; the Connections window's New menu has no such item; a file of that
//!   kind opened from Finder / Explorer (`open_files::receive`) is refused with the gate's text and not imported.
//!   Then the engine "is installed outside the app": the popover is shown again and its background check (not
//!   throttled during this step) makes the row usable within 2 s.
//! - `notices` (driver-side, the switch in the popover): a connect posts "… connected", a drop (the stand-in
//!   helper reports `failed`) "… disconnected"; with "Connection Notifications" off neither posts; it is switched on
//!   again. The sandbox posts no real notification: [`notice`] records them (`MacVPN smoke: notice: …`).
//! - `reconnect` (driver-side, the detail's switch in the Connections window): the physical network is scripted
//!   ([`network`]; the sandbox has no probe) and the sleep and wake are sent to the reconnect driver as the
//!   lifecycle hooks would. Home → drop after the wake → a second `up` within `SETTLE + 2` s and "… reconnected";
//!   another network → "… not reconnected" with "You are on a different network."; the switch off → no `up`; a
//!   tunnel routing 10.20.30.0/24 still up after waking at the office (on 10.20.30.0/24) → a `down` and "… so it
//!   was disconnected."; the same tunnel waking at a café → stays up.
//!
//! The step's connections and its result connection (the scripts write `<SECTION> <phase> OK|FAILED …` into its
//! name) are created in the vault here and deleted at the end, so the later steps and the final checks see the
//! same connections as before.

use macvpn_app_core::connection_notices::{self, Notice};
use macvpn_app_core::notify::NotificationContent;
use macvpn_app_core::reconnect::{self as planner, Skip};
use macvpn_app_core::{RowState, TrayIcon};
use macvpn_core::date::Date;
use macvpn_core::l10n::{self, Arg};
use macvpn_core::models::{Connection, ConnectionState, VPNKind, parse_uuid, uuid_string};
use macvpn_core::netaddr::IpPrefix;
use macvpn_platform_api::{Gateway, NetworkSnapshot, SetupReport};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Manager};

use super::{FAKE_HELPER, FakeHelper, eval, private_temp_dir, renamed, smoke_dir, wait_for};
use crate::reconnect::{Event, connected_keys};
use crate::state::AppState;

/// Where the scripts write their results (`<SECTION> <phase> …`).
const RESULT: &str = "F5111111-2222-4333-8444-555555555555";
/// The engines step's row (macOS: SSTP; Windows: OpenVPN).
const ENGINES: &str = "F6111111-2222-4333-8444-555555555555";
const ENGINES_NAME: &str = "Zz Engines";
/// The notices step's connection.
const NOTICES: &str = "F7111111-2222-4333-8444-555555555555";
const NOTICES_NAME: &str = "Zz Notices";
/// Auto-reconnect: a connection without routes, and one that routes the office network.
const HOME_VPN: &str = "F8111111-2222-4333-8444-555555555555";
const HOME_NAME: &str = "Zz Reconnect home";
const OFFICE_VPN: &str = "F9111111-2222-4333-8444-555555555555";
const OFFICE_NAME: &str = "Zz Reconnect office";
const OVPN: &str = "client\ndev tun\nremote vpn.example.com 1194\n";
#[cfg(target_os = "macos")]
const SSTP: &str = "server=vpn.example.com\nport=443\nuser=alice\ncert=system\nroute_all=yes\npeer_dns=yes\n";

// MARK: - The hooks the app calls (through the `platform::smoke_*` facades)

/// The notices the sandbox "posted": title, body, the connection's key.
static POSTED: Mutex<Vec<(String, String, String)>> = Mutex::new(Vec::new());

/// A smoke run records the connection notices (the sandbox posts none): the switch is shown and honoured.
pub fn records_notices(state: &AppState) -> bool {
    smoke_dir(state).is_some()
}

/// Records a notice the app would post (`MacVPN smoke: notice: <title> | <body>`).
pub fn notice(state: &AppState, content: &NotificationContent) {
    if !records_notices(state) {
        return;
    }
    eprintln!("MacVPN smoke: notice: {} | {}", content.title, content.body);
    let entry = (content.title.clone(), content.body.clone(), content.user_info.1.clone());
    POSTED.lock().unwrap_or_else(PoisonError::into_inner).push(entry);
}

fn posted() -> Vec<(String, String, String)> {
    POSTED.lock().unwrap_or_else(PoisonError::into_inner).clone()
}

/// The physical network the reconnect driver sees in a smoke run (`None`: none scripted, as without a probe).
static NETWORK: Mutex<Option<NetworkSnapshot>> = Mutex::new(None);

pub fn network(state: &AppState) -> Option<NetworkSnapshot> {
    smoke_dir(state)?;
    NETWORK.lock().unwrap_or_else(PoisonError::into_inner).clone()
}

fn set_network(snapshot: Option<NetworkSnapshot>) {
    *NETWORK.lock().unwrap_or_else(PoisonError::into_inner) = snapshot;
}

/// The engines step's System Status report (`None`: the run's usual mock).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Engines {
    Usual,
    /// One engine missing (macOS: `sstpc`; Windows: OpenVPN Community), the rest usable.
    Missing,
    /// That engine was installed outside the app.
    Installed,
    /// The run's "ready" report (OpenVPN usable), for `manage.js`.
    Ready,
}

static ENGINES_MODE: Mutex<Engines> = Mutex::new(Engines::Usual);
/// The background check of the popover and the Connections window runs every time (only during the step).
static UNTHROTTLED: AtomicBool = AtomicBool::new(false);

pub fn engines_report() -> Option<SetupReport> {
    let mode = *ENGINES_MODE.lock().unwrap_or_else(PoisonError::into_inner);
    match mode {
        Engines::Usual => None,
        Engines::Missing => Some(missing_report()),
        Engines::Installed => Some(installed_report()),
        Engines::Ready => Some(super::ready_report()),
    }
}

/// The run's "ready" report from now on (`on`; every later check, the background ones among them, returns it), or
/// the usual mock report again (`!on`), stored at once. The Connections window's New menu and its imports offer
/// only the kinds whose engine is usable (features plan, Task 13): `manage.js` creates an OpenVPN connection and
/// the steps after the control API's import OpenVPN files, so they run on the ready report; System Status' step
/// checks the mock one.
pub fn use_ready_report(state: &AppState, on: bool) {
    set_engines(if on { Engines::Ready } else { Engines::Usual });
    crate::system::check(state);
}

pub fn recheck_unthrottled() -> bool {
    UNTHROTTLED.load(Ordering::SeqCst)
}

fn set_engines(mode: Engines) {
    *ENGINES_MODE.lock().unwrap_or_else(PoisonError::into_inner) = mode;
}

#[cfg(target_os = "macos")]
fn missing_report() -> SetupReport {
    super::macos::ready_report()
}

#[cfg(target_os = "macos")]
fn installed_report() -> SetupReport {
    super::macos::installed_report()
}

#[cfg(windows)]
fn missing_report() -> SetupReport {
    super::windows_report(false)
}

#[cfg(windows)]
fn installed_report() -> SetupReport {
    super::windows_report(true)
}

/// The kind whose engine the step's report lacks, its fixture's extension and config.
#[cfg(target_os = "macos")]
const ENGINE_KIND: (VPNKind, &str, &str) = (VPNKind::Sstp, "sstp", SSTP);
#[cfg(windows)]
const ENGINE_KIND: (VPNKind, &str, &str) = (VPNKind::Openvpn, "ovpn", OVPN);

// MARK: - The sections

pub fn run(app: &AppHandle, state: &Arc<AppState>, dir: &Path) {
    let vault = match super::backup_service(state) {
        Ok(service) => service.vault().clone(),
        Err(e) => return eprintln!("MacVPN smoke: features: ERROR {e}"),
    };
    let seeds = [
        (RESULT, "Zz Features result", VPNKind::Openvpn, OVPN.to_string()),
        (ENGINES, ENGINES_NAME, ENGINE_KIND.0, ENGINE_KIND.2.to_string()),
        (NOTICES, NOTICES_NAME, VPNKind::Openvpn, OVPN.to_string()),
        (HOME_VPN, HOME_NAME, VPNKind::Openvpn, OVPN.to_string()),
        (OFFICE_VPN, OFFICE_NAME, VPNKind::Openvpn, format!("{OVPN}route 10.20.30.0 255.255.255.0\n")),
    ];
    for (id, name, kind, config) in &seeds {
        let Some(uuid) = parse_uuid(id) else { return };
        let c = Connection::with_id(uuid, *name, *kind, Date::now());
        if let Err(e) = vault.with(|v| v.save_connection(&c, Some(config))) {
            return eprintln!("MacVPN smoke: features: ERROR seeding {name}: {e}");
        }
    }
    state.manager.reload();

    appearance(app, state, dir);
    engines(app, state, dir);
    notices(app, state, dir);
    reconnect(app, state, dir);

    // Back to the run's state: nothing connected, every switch on, the step's connections gone.
    set_network(None);
    for (id, ..) in &seeds {
        let Some(uuid) = parse_uuid(id) else { continue };
        if let Some(c) = connection(state, id)
            && state.manager.state(id).is_active()
        {
            state.manager.disconnect(&c);
        }
        planner::set_enabled(state.prefs.as_ref(), &uuid, true);
        let _ = vault.with(|v| v.delete_connection(&uuid));
        state.reconnect.send(Event::Forget(uuid_string(&uuid)));
    }
    state.manager.reload();
}

fn connection(state: &AppState, id: &str) -> Option<Connection> {
    let id = parse_uuid(id)?;
    state.manager.connections().into_iter().find(|c| c.id == id)
}

/// One phase of a section's script in `window` (`manage` is opened first): `window.__smoke` holds the phase, the
/// result connection and `vars`; the script writes `<SECTION> <phase> OK …` / `… FAILED <checks>` into the result
/// connection's name. What follows the prefix, or the error.
fn phase(
    app: &AppHandle,
    state: &AppState,
    dir: &Path,
    (window, script): (&str, &str),
    (section, phase): (&str, &str),
    vars: &[(&str, String)],
) -> Result<String, String> {
    let source = std::fs::read_to_string(dir.join(script)).map_err(|e| format!("{script}: {e}"))?;
    let mut fields = vec![("section", js(section)), ("phase", js(phase)), ("result", js(RESULT))];
    fields.extend(vars.iter().cloned());
    let smoke = format!(
        "{{ {} }}",
        fields.iter().map(|(name, value)| format!("{name}: {value}")).collect::<Vec<_>>().join(", ")
    );
    if window == crate::manage::MANAGE_WINDOW {
        crate::commands::open(app, window)?;
    }
    eval(app, window, format!("window.__smoke = {smoke};\n{source}"))?;
    let prefix = format!("{section} {phase} ");
    wait_for(60, || renamed(state, RESULT, &prefix)).map(|n| n[prefix.len()..].to_string()).ok_or("no result".into())
}

/// A JavaScript string literal of `text`.
pub(super) fn js(text: &str) -> String {
    let mut out = String::from("\"");
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() || c == '\u{2028}' || c == '\u{2029}' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `ok` or `FAILED <the checks>`.
pub(super) fn verdict(checks: &[(&str, bool)]) -> String {
    let failed: Vec<&str> = checks.iter().filter(|(_, ok)| !ok).map(|(name, _)| *name).collect();
    if failed.is_empty() { "ok".into() } else { format!("FAILED {}", failed.join(",")) }
}

fn passed(outcome: &Result<String, String>) -> bool {
    outcome.as_deref().is_ok_and(|o| o.starts_with("OK"))
}

fn shown(outcome: &Result<String, String>) -> String {
    match outcome {
        Ok(o) => o.clone(),
        Err(e) => format!("ERROR {e}"),
    }
}

// MARK: Appearance

/// The `dark=` value a phase reported.
fn dark(outcome: &Result<String, String>) -> Option<bool> {
    let o = outcome.as_deref().ok()?;
    match o.split_whitespace().find_map(|w| w.strip_prefix("dark="))? {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

fn appearance(app: &AppHandle, state: &Arc<AppState>, dir: &Path) {
    let say = |line: String| eprintln!("MacVPN smoke: appearance: {line}");
    let menu = (crate::tray::MENU_WINDOW, "appearance.js");
    let manage = (crate::manage::MANAGE_WINDOW, "appearance.js");
    // The setting starts at Match System: the popover's value now is the system's (macOS: unless SMOKE_DARK or
    // SMOKE_LIGHT forced the app's appearance; then Match System is not compared).
    let initial = phase(app, state, dir, menu, ("APPEARANCE", "initial"), &[]);
    let forced = std::env::var_os("MACVPN_SMOKE_DARK").is_some() || std::env::var_os("MACVPN_SMOKE_LIGHT").is_some();
    let system = if forced { None } else { dark(&initial) };
    let mut checks = vec![("initial", passed(&initial) && (forced || system.is_some()))];
    let mut values = Vec::new();
    for (mode, expected) in [("dark", Some(true)), ("light", Some(false)), ("system", system)] {
        let vars = [("mode", js(mode)), ("expected", expected.map_or_else(|| "null".to_string(), |e| e.to_string()))];
        let in_menu = phase(app, state, dir, menu, ("APPEARANCE", &format!("menu-{mode}")), &vars);
        let in_manage = phase(app, state, dir, manage, ("APPEARANCE", &format!("manage-{mode}")), &vars);
        let value = |o: &Result<String, String>| dark(o).map_or_else(|| shown(o), |d| d.to_string());
        values.push(format!("{mode}={}/{}", value(&in_menu), value(&in_manage)));
        let matches = |o: &Result<String, String>| passed(o) && (expected.is_none() || dark(o) == expected);
        checks.push((
            if mode == "dark" {
                "menuDark"
            } else if mode == "light" {
                "menuLight"
            } else {
                "menuSystem"
            },
            matches(&in_menu),
        ));
        checks.push((
            if mode == "dark" {
                "windowDark"
            } else if mode == "light" {
                "windowLight"
            } else {
                "windowSystem"
            },
            matches(&in_manage),
        ));
    }
    let stored = macvpn_app_core::appearance::Appearance::load(state.prefs.as_ref()).raw_value();
    checks.push(("storedSystem", stored == "system"));
    // popover/Connections window
    say(format!("{} (popover/window; system before={})", values.join(" "), shown(&initial)));
    #[cfg(target_os = "macos")]
    if forced {
        // Match System dropped the forced appearance: the later screenshots want it back.
        super::macos::appearance();
    }
    say(verdict(&checks));
}

// MARK: Engines

fn engines(app: &AppHandle, state: &Arc<AppState>, dir: &Path) {
    let say = |line: String| eprintln!("MacVPN smoke: engines: {line}");
    let (kind, extension, config) = ENGINE_KIND;
    let key = parse_uuid(ENGINES).map(|u| uuid_string(&u)).unwrap_or_default();
    set_engines(Engines::Missing);
    let report = crate::system::check(state);
    let text = report.unavailable_text(kind).unwrap_or_default();
    let engine = report.missing_engine(kind).map(|m| m.name).unwrap_or_default();
    let refusal = l10n::tr("%@ is not installed. Install it in System Status first.", &[Arg::Str(&engine)]);
    say(format!("missing {} row=\"{text}\"", kind.raw_value()));

    // The popover's row: the text, the disabled switch, the link to System Status.
    if let Some(window) = app.get_webview_window("setup") {
        let _ = window.destroy();
    }
    wait_for(10, || app.get_webview_window("setup").is_none().then_some(()));
    let menu = (crate::tray::MENU_WINDOW, "engines.js");
    let manage = (crate::manage::MANAGE_WINDOW, "engines.js");
    let vars = [
        ("name", js(ENGINES_NAME)),
        ("id", js(&key)),
        ("kind", js(kind.raw_value())),
        ("text", js(&text)),
        ("refusal", js(&refusal)),
    ];
    let row = phase(app, state, dir, menu, ("ENGINES", "menu"), &vars);
    let setup_shown =
        wait_for(15, || app.get_webview_window("setup").filter(|w| w.is_visible().unwrap_or(false)).map(|_| ()))
            .is_some();
    if let Some(window) = app.get_webview_window("setup") {
        let _ = window.destroy();
    }
    say(format!("row {} setup_window={setup_shown}", shown(&row)));

    // The New menu, then a file of that kind opened from Finder / Explorer.
    let new = phase(app, state, dir, manage, ("ENGINES", "new"), &vars);
    say(format!("new menu {}", shown(&new)));
    let imported_name = "Zz Engines import";
    let fixture = state
        .env
        .staging_parent()
        .ok_or_else(|| "no sandbox tmp".to_string())
        .and_then(|base| private_temp_dir("macvpn-smoke-engines", &base))
        .and_then(|folder| {
            let path = folder.join(format!("{imported_name}.{extension}"));
            std::fs::write(&path, config).map(|()| (folder, path)).map_err(|e| e.to_string())
        });
    let (import, imported) = match fixture {
        Ok((folder, path)) => {
            crate::open_files::receive(app, state, vec![path]);
            let outcome = phase(app, state, dir, manage, ("ENGINES", "import"), &vars);
            let imported =
                state.connections.deps().store.list().is_ok_and(|l| l.iter().any(|c| c.name == imported_name));
            let _ = std::fs::remove_dir_all(&folder);
            (outcome, imported)
        }
        Err(e) => (Err(e), false),
    };
    say(format!("import {} imported={imported}", shown(&import)));

    // Installed outside the app: the popover shown again checks in the background, the row is usable at once.
    set_engines(Engines::Installed);
    UNTHROTTLED.store(true, Ordering::SeqCst);
    let started = Instant::now();
    crate::tray::show_menu(app);
    let usable = || state.view_model().rows.iter().any(|r| r.id == key && r.available).then(|| started.elapsed());
    let after = wait_for(10, usable);
    UNTHROTTLED.store(false, Ordering::SeqCst);
    let ready = phase(app, state, dir, menu, ("ENGINES", "after"), &vars);
    crate::tray::hide_menu(app);
    let within = after.is_some_and(|d| d <= Duration::from_secs(2));
    say(format!(
        "installed usable_after_ms={} {}",
        after.map_or_else(|| "never".to_string(), |d| d.as_millis().to_string()),
        shown(&ready)
    ));
    // The run's ready report again (the later steps were written against it).
    use_ready_report(state, true);
    say(verdict(&[
        ("row", passed(&row)),
        ("setupWindow", setup_shown),
        ("newMenu", passed(&new)),
        ("importRefused", passed(&import) && !imported),
        ("installedWithin2s", within),
        ("rowUsable", passed(&ready)),
    ]));
}

// MARK: Notices

fn fake() -> Option<&'static Arc<FakeHelper>> {
    FAKE_HELPER.get()
}

/// Connects as the user does (on a worker: the manager blocks) and waits for `connected`.
fn connect(state: &AppState, id: &str) -> bool {
    let Some(c) = connection(state, id) else { return false };
    let manager = state.manager.clone();
    let _ = std::thread::spawn(move || manager.connect(&c, false)).join();
    wait_for(15, || state.manager.state(id).is_connected().then_some(())).is_some()
}

/// The tunnel went down by itself: the stand-in helper reports `failed`, the next refresh sees the drop.
fn drop_tunnel(state: &AppState, id: &str) -> bool {
    let (Some(fake), Some(uuid)) = (fake(), parse_uuid(id)) else { return false };
    fake.fail(&uuid);
    state.manager.refresh();
    wait_for(10, || matches!(state.manager.state(id), ConnectionState::Failed(_)).then_some(())).is_some()
}

fn calls(op: &str, id: &str) -> usize {
    match (fake(), parse_uuid(id)) {
        (Some(fake), Some(uuid)) => fake.calls(op, &uuid),
        _ => 0,
    }
}

/// The notice's title and body as the app builds them (the run's language).
fn expected(notice: &Notice, name: &str) -> (String, String) {
    let content = connection_notices::content_named(notice, name, String::new());
    (content.title, content.body)
}

/// A notice with this title (and body, when given) was recorded after the first `since` ones.
fn posted_since(since: usize, title: &str, body: Option<&str>) -> bool {
    posted().iter().skip(since).any(|(t, b, _)| t == title && body.is_none_or(|body| b == body))
}

fn notices(app: &AppHandle, state: &Arc<AppState>, dir: &Path) {
    let say = |line: String| eprintln!("MacVPN smoke: notices: {line}");
    let key = parse_uuid(NOTICES).map(|u| uuid_string(&u)).unwrap_or_default();
    let menu = (crate::tray::MENU_WINDOW, "notices.js");
    let label = l10n::tr("Connection Notifications", &[]);
    let (connected_title, _) =
        expected(&Notice::Connected { key: key.clone(), name: NOTICES_NAME.into() }, NOTICES_NAME);
    let dropped = Notice::Dropped { key: key.clone(), name: NOTICES_NAME.into(), reason: None };
    let (dropped_title, _) = expected(&dropped, NOTICES_NAME);

    let start = posted().len();
    let up = connect(state, &key);
    let connected = wait_for(10, || posted_since(start, &connected_title, None).then_some(())).is_some();
    let down = drop_tunnel(state, &key);
    let disconnected = wait_for(10, || posted_since(start, &dropped_title, None).then_some(())).is_some();
    say(format!("on up={up} connected_notice={connected} drop={down} disconnected_notice={disconnected}"));

    // The switch off in the popover's settings: neither notice.
    let off = phase(app, state, dir, menu, ("NOTICES", "off"), &[("label", js(&label)), ("on", "false".into())]);
    let switched_off = !connection_notices::enabled(state.prefs.as_ref());
    let start = posted().len();
    let up = connect(state, &key);
    let down = drop_tunnel(state, &key);
    std::thread::sleep(Duration::from_secs(3));
    let silent = posted().len() == start;
    say(format!("off {} switch_off={switched_off} up={up} drop={down} silent={silent}", shown(&off)));
    let on = phase(app, state, dir, menu, ("NOTICES", "on"), &[("label", js(&label)), ("on", "true".into())]);
    let switched_on = connection_notices::enabled(state.prefs.as_ref());
    say(format!("on again {} switch_on={switched_on}", shown(&on)));
    if let Some(c) = connection(state, &key) {
        state.manager.disconnect(&c);
    }
    say(verdict(&[
        ("connected", connected),
        ("disconnected", disconnected),
        ("switchOff", passed(&off) && switched_off),
        ("silentWhenOff", silent),
        ("switchOn", passed(&on) && switched_on),
    ]));
}

// MARK: Auto-reconnect

/// A scripted physical network: the default gateway (its MAC's last byte), the Wi-Fi name, the connected subnets.
fn snapshot(gateway: &str, mac: u8, ssid: Option<&str>, connected: &[&str]) -> Option<NetworkSnapshot> {
    Some(NetworkSnapshot {
        gateway: Some(Gateway {
            ip: gateway.parse().ok()?,
            mac: Some([0xa4, 0x2b, 0xb0, 0x00, 0x00, mac]),
            interface: "en0".into(),
            ssid: ssid.map(str::to_string),
        }),
        connected: connected.iter().filter_map(|p| IpPrefix::parse(p)).collect(),
    })
}

fn home() -> Option<NetworkSnapshot> {
    snapshot("192.168.1.1", 1, Some("Home"), &["192.168.1.0/24"])
}

/// The lid closed (the reconnect driver learns which connections were up and the network), then `during` (the
/// network changes meanwhile), then the wake.
fn sleep_and_wake(state: &AppState, during: Option<NetworkSnapshot>) {
    state.reconnect.send(Event::Sleep(connected_keys(state)));
    // The driver reads the network of the sleep before it changes.
    std::thread::sleep(Duration::from_secs(1));
    set_network(during);
    state.reconnect.send(Event::Wake(connected_keys(state)));
}

fn reconnect(app: &AppHandle, state: &Arc<AppState>, dir: &Path) {
    let say = |line: String| eprintln!("MacVPN smoke: reconnect: {line}");
    let home_key = parse_uuid(HOME_VPN).map(|u| uuid_string(&u)).unwrap_or_default();
    let office_key = parse_uuid(OFFICE_VPN).map(|u| uuid_string(&u)).unwrap_or_default();
    let settle = Duration::from_secs_f64(planner::SETTLE);
    let mut checks: Vec<(&str, bool)> = Vec::new();

    // 1. Home, the tunnel drops while asleep: reconnected on the same network.
    set_network(home());
    let up = connect(state, &home_key);
    let ups = calls("up", &home_key);
    let start = posted().len();
    sleep_and_wake(state, home());
    let woke = Instant::now();
    let dropped = drop_tunnel(state, &home_key);
    let again = wait_for(15, || (calls("up", &home_key) > ups).then(|| woke.elapsed()));
    let back = wait_for(10, || state.manager.state(&home_key).is_connected().then_some(())).is_some();
    let (title, _) = expected(&Notice::Reconnected { key: home_key.clone(), name: HOME_NAME.into() }, HOME_NAME);
    let noticed = wait_for(10, || posted_since(start, &title, None).then_some(())).is_some();
    let in_time = again.is_some_and(|d| d <= settle + Duration::from_secs(2));
    say(format!(
        "home up={up} drop={dropped} up_again_after_ms={} connected={back} reconnected_notice={noticed}",
        again.map_or_else(|| "never".to_string(), |d| d.as_millis().to_string())
    ));
    checks.extend([("homeReconnected", up && dropped && in_time && back), ("reconnectedNotice", noticed)]);

    // 2. Woken on another network: not reconnected, and why.
    let ups = calls("up", &home_key);
    let start = posted().len();
    sleep_and_wake(state, snapshot("192.168.77.1", 2, Some("Elsewhere"), &["192.168.77.0/24"]));
    let dropped = drop_tunnel(state, &home_key);
    let skip = Notice::NotReconnected { key: home_key.clone(), name: HOME_NAME.into(), why: Skip::DifferentNetwork };
    let (title, body) = expected(&skip, HOME_NAME);
    let noticed = wait_for(15, || posted_since(start, &title, Some(&body)).then_some(())).is_some();
    let stayed = calls("up", &home_key) == ups;
    say(format!("elsewhere drop={dropped} not_reconnected_notice={noticed} no_up={stayed}"));
    checks.extend([("otherNetwork", dropped && noticed && stayed)]);

    // 3. The detail's switch off: no reconnect, no notice.
    set_network(home());
    let up = connect(state, &home_key);
    state.connections.select(Some(home_key.clone()));
    let manage = (crate::manage::MANAGE_WINDOW, "reconnect.js");
    let vars = |on: bool| [("name", js(HOME_NAME)), ("id", js(&home_key)), ("on", on.to_string())];
    let off = phase(app, state, dir, manage, ("RECONNECT", "off"), &vars(false));
    let switched_off = parse_uuid(&home_key).is_some_and(|u| !planner::is_enabled(state.prefs.as_ref(), &u));
    let ups = calls("up", &home_key);
    let start = posted().len();
    sleep_and_wake(state, home());
    let dropped = drop_tunnel(state, &home_key);
    std::thread::sleep(settle + Duration::from_secs(3));
    let (reconnected, _) = expected(&Notice::Reconnected { key: home_key.clone(), name: HOME_NAME.into() }, HOME_NAME);
    let quiet = calls("up", &home_key) == ups && !posted_since(start, &reconnected, None);
    let on = phase(app, state, dir, manage, ("RECONNECT", "on"), &vars(true));
    let switched_on = parse_uuid(&home_key).is_some_and(|u| planner::is_enabled(state.prefs.as_ref(), &u));
    say(format!(
        "switch {} off={switched_off} up={up} drop={dropped} no_up={quiet}; {} on={switched_on}",
        shown(&off),
        shown(&on)
    ));
    checks.extend([
        ("switchOff", passed(&off) && switched_off && up && dropped && quiet),
        ("switchOn", passed(&on) && switched_on),
    ]);

    // 4. A tunnel that survives the sleep, woken at the office on the network it routes: disconnected, and why.
    set_network(home());
    let up = connect(state, &office_key);
    let downs = calls("down", &office_key);
    let start = posted().len();
    let office = snapshot("10.20.30.1", 3, Some("Office"), &["10.20.30.0/24"]);
    sleep_and_wake(state, office);
    let down = wait_for(15, || (calls("down", &office_key) > downs).then_some(())).is_some();
    let prefix = IpPrefix::parse("10.20.30.0/24");
    let why = prefix.map_or(Skip::Unidentified, Skip::DirectlyReachable);
    let (title, body) = expected(&Notice::DisconnectedHere { key: office_key.clone(), why }, OFFICE_NAME);
    let noticed = wait_for(10, || posted_since(start, &title, Some(&body)).then_some(())).is_some();
    say(format!("office up={up} down={down} disconnected_notice={noticed}"));
    checks.extend([("officeDisconnected", up && down), ("officeNotice", noticed)]);

    // 5. The same tunnel woken at a café: it stays up.
    set_network(home());
    let up = connect(state, &office_key);
    let downs = calls("down", &office_key);
    sleep_and_wake(state, snapshot("172.16.5.1", 4, Some("Cafe"), &["172.16.5.0/24"]));
    std::thread::sleep(settle + Duration::from_secs(3));
    let stays = calls("down", &office_key) == downs && state.manager.state(&office_key).is_connected();
    say(format!("cafe up={up} stays_connected={stays}"));
    checks.push(("cafeStays", up && stays));

    // 6. The network goes away under the tunnel (Wi-Fi off): "Waiting for network…" in its row and the tray, never
    // connected; back on the same network: connected again, the tunnel left alone.
    // The home connection's failure (step 3) would win the tray: it is cleared first.
    if let Some(c) = connection(state, &home_key) {
        state.manager.disconnect(&c);
    }
    let cafe = snapshot("172.16.5.1", 4, Some("Cafe"), &["172.16.5.0/24"]);
    let downs = calls("down", &office_key);
    let shows = |row: RowState, tray: TrayIcon| {
        let vm = state.view_model();
        let state_of = vm.rows.iter().find(|r| r.id == office_key).map(|r| r.state.clone());
        (vm.tray == tray && state_of.is_some_and(|s| std::mem::discriminant(&s) == std::mem::discriminant(&row)))
            .then_some(())
    };
    set_network(Some(NetworkSnapshot::default()));
    state.reconnect.send(Event::NetworkChanged);
    let lost = Instant::now();
    let waiting = wait_for(15, || shows(RowState::WaitingForNetwork, TrayIcon::WaitingForNetwork)).is_some();
    let debounced = lost.elapsed() >= Duration::from_secs_f64(planner::NETWORK_DEBOUNCE - 0.5);
    set_network(cafe);
    state.reconnect.send(Event::NetworkChanged);
    let connected = RowState::Connected { ip: None, since: None };
    let back = wait_for(15, || shows(connected.clone(), TrayIcon::Active)).is_some();
    let untouched = calls("down", &office_key) == downs;
    say(format!("network loss waiting={waiting} debounced={debounced} back={back} untouched={untouched}"));
    checks.push(("networkLoss", waiting && debounced && back && untouched));
    for key in [&home_key, &office_key] {
        if let Some(c) = connection(state, key) {
            state.manager.disconnect(&c);
        }
    }
    say(verdict(&checks));
}
