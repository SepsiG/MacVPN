//! The smoke run's Linux parts: the stand-in System Status report (LinVPN L-b's NetworkManager rows from stand-in
//! facts: every kind usable through the run's stand-ins, [`super::FakeHelper`] and [`super::FakeNative`]; no
//! NetworkManager or PackageKit is asked), the NetworkManager step ([`nm`]), the skipped AppKit steps, the sandbox's
//! update in the order of `LinUpdater::install`, and logout as SIGTERM to this process
//! (`macvpn_platform_linux::smoke::send_terminate`), which the platform's GLib signal source hands to the terminate
//! handler.
//!
//! The NetworkManager step (L-b Task 25; `nm.js` with the expected texts from `strings.json`, the run's language, in
//! `window.__smoke`), after the 2.0 features, sandbox and stand-ins only:
//!
//! - System Status shows the NetworkManager rows of the stand-in report with SSTP's plugin missing (red, with
//!   Install); Install runs the sandbox's `install_tools` (no PackageKit), then the driver flips the stand-in
//!   (the plugin "installed") and the row turns green;
//! - an OpenVPN connection with `peer-fingerprint` is greyed with the Linux reason, its editor shows it, Connect is
//!   disabled;
//! - an OpenVPN editor's "Send all traffic over VPN": Always adds `redirect-gateway def1` to the config text, Server
//!   decides removes it; Always and Save store it (the driver reads the stored config);
//! - an L2TP connection: "Save" (nothing to approve) writes the plan record under the sandbox's data folder, and
//!   [`super::FakeNative`] then lists its service `linvpn-<UUID>`; Connect → connected through the stand-in (with
//!   the user name, the password and the PSK) → Disconnect;
//! - a Cisco IPsec connection is not greyed (unlike Windows);
//! - a stand-in helper connection's Log tab shows the lines of its log (the engine's `<data>/logs/<UUID>.log`,
//!   written here); "Clear Log…" clears it, the cleared note first.
//!
//! The driver checks the backend's side and prints `MacVPN smoke: nm: ok` or `… FAILED <checks>`. The step's
//! connections are created in the vault here and deleted at the end with their plan record and log, so the later
//! steps see the same connections as before.

use macvpn_app_core::deps::{HelperClient, NativeController};
use macvpn_core::date::Date;
use macvpn_core::l10n::{self, Arg};
use macvpn_core::models::{Connection, NativeSettings, VPNKind, parse_uuid, uuid_string};
use macvpn_core::nm_plan::{
    SERVICE_L2TP, SERVICE_OPENVPN_STOCK, SERVICE_SSTP, SERVICE_STRONGSWAN, SERVICE_VPNC, names,
};
use macvpn_core::update::Release;
use macvpn_platform_api::{SetupReport, UpdateOutcome};
use macvpn_platform_linux::pure::nm::plugins::{self, Facts};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tauri::{AppHandle, Manager};

use super::features::{js, verdict};
use super::{FAKE_HELPER, FAKE_NATIVE, eval, renamed, wait_for};
use crate::platform::Environment;
use crate::state::AppState;

/// The stand-in's SSTP plugin is missing (only during the NetworkManager step, until its Install).
static SSTP_MISSING: AtomicBool = AtomicBool::new(false);

/// The stand-in facts: NetworkManager 1.54.3 with LinVPN's OpenVPN service, OpenVPN 2.7.0 and every plugin (SSTP's
/// only with `sstp`), as `lin::nm::plugins::facts` would read them on the VM.
fn facts(sstp: bool) -> Facts {
    let mut services = vec![SERVICE_OPENVPN_STOCK, SERVICE_L2TP, SERVICE_STRONGSWAN, SERVICE_VPNC];
    if sstp {
        services.push(SERVICE_SSTP);
    }
    Facts {
        nm_version: Some("1.54.3".into()),
        services: services.into_iter().map(String::from).collect(),
        linvpn_openvpn: true,
        openvpn_version: Some("2.7.0".into()),
        eap_mschapv2: true,
        eap_identity: true,
    }
}

/// The real rows (`plugins::report`, the real texts) from the stand-in facts.
fn nm_report(sstp: bool) -> SetupReport {
    SetupReport {
        package_manager: Some("PackageKit".into()),
        nm: Some(plugins::report(&facts(sstp))),
        ..SetupReport::unknown()
    }
}

/// Every kind usable (SSTP's plugin missing only while the NetworkManager step wants it so).
pub(super) fn report() -> SetupReport {
    nm_report(!SSTP_MISSING.load(Ordering::SeqCst))
}

/// The engines step's report: SSTP's plugin missing, so SSTP is "Not installed", every other kind usable.
pub(super) fn missing_report() -> SetupReport {
    nm_report(false)
}

/// An AppKit step on Linux (the line `scripts/smoke-manage.sh` expects there).
pub(super) fn skipped(step: &str) {
    eprintln!("MacVPN smoke: {step}: skipped on Linux");
}

/// Logout's quit request: SIGTERM to this process.
pub(super) fn logout() {
    macvpn_platform_linux::smoke::send_terminate();
}

/// The updater's stages and its quit question in `LinUpdater::install`'s order; nothing is downloaded, no pkexec
/// runs and nothing is installed.
pub(super) fn update_install(
    _env: &Environment,
    _release: &Release,
    stage: &dyn Fn(String),
    confirm_quit: Box<dyn FnOnce() -> bool + '_>,
) -> Result<UpdateOutcome, String> {
    let pause = || std::thread::sleep(Duration::from_millis(300));
    for text in [macvpn_core::l10n::tr("Downloading…", &[]), macvpn_core::l10n::tr("Quitting and restarting…", &[])]
    {
        stage(text);
        pause();
    }
    if !confirm_quit() {
        return Ok(UpdateOutcome::Cancelled);
    }
    stage(macvpn_core::l10n::tr("Installing…", &[]));
    eprintln!("MacVPN (sandbox): update installer not run");
    Ok(UpdateOutcome::HelperLaunched)
}

// MARK: - The NetworkManager step

/// Where `nm.js` writes its results (`NM <phase> OK` / `NM <phase> FAILED <checks>`).
const RESULT: &str = "AC111111-2222-4333-8444-555555555555";
const FINGERPRINT: &str = "AC211111-2222-4333-8444-555555555555";
const FINGERPRINT_NAME: &str = "Zz NM fingerprint";
const ROUTING: &str = "AC311111-2222-4333-8444-555555555555";
const ROUTING_NAME: &str = "Zz NM routing";
const L2TP: &str = "AC411111-2222-4333-8444-555555555555";
const L2TP_NAME: &str = "Zz NM L2TP";
const CISCO: &str = "AC511111-2222-4333-8444-555555555555";
const CISCO_NAME: &str = "Zz NM Cisco";
const LOG: &str = "AC611111-2222-4333-8444-555555555555";
const LOG_NAME: &str = "Zz NM log";
/// What `nm.js` types into the L2TP form (compared by the stand-in's log line only: never logged).
const L2TP_PASSWORD: &str = "smoke-nm-pass";
const L2TP_PSK: &str = "smoke-nm-psk";
/// The stand-in helper connection's log lines (as the engine's connection log would hold them; no secret).
const LOG_LINES: [&str; 2] =
    ["NetworkManager stand-in: connection activated (smoke)", "NetworkManager stand-in: VPN state 5 (smoke)"];

const OVPN: &str = "client\ndev tun\nremote vpn.example.com 1194\n";

/// The Linux reason of `peer-fingerprint` (`nm_plan::openvpn`'s text).
fn fingerprint_reason() -> String {
    l10n::tr(
        "Not supported on Linux: %@ (NetworkManager cannot check the server this way; use a CA)",
        &[Arg::Str("peer-fingerprint")],
    )
}

/// A seeded connection: id, name, kind, config, native settings.
type Seed = (&'static str, &'static str, VPNKind, Option<String>, Option<NativeSettings>);

fn native(server: &str, account: &str, group: &str) -> Option<NativeSettings> {
    Some(NativeSettings {
        server: server.into(),
        account: account.into(),
        group_name: group.into(),
        send_all_traffic: true,
    })
}

/// One phase of `nm.js` in `window` (opened first): what follows `NM <phase> `, or the error.
fn phase(
    app: &AppHandle,
    state: &AppState,
    source: &str,
    window: &str,
    name: &str,
    vars: &[(&str, String)],
) -> Result<String, String> {
    let mut fields = vec![("phase", js(name)), ("result", js(RESULT))];
    fields.extend(vars.iter().cloned());
    let smoke = format!(
        "{{ {} }}",
        fields.iter().map(|(name, value)| format!("{name}: {value}")).collect::<Vec<_>>().join(", ")
    );
    crate::commands::open(app, window)?;
    eval(app, window, format!("window.__smoke = {smoke};\n{source}"))?;
    let prefix = format!("NM {name} ");
    wait_for(120, || renamed(state, RESULT, &prefix)).map(|n| n[prefix.len()..].to_string()).ok_or("no result".into())
}

fn passed(outcome: &Result<String, String>) -> bool {
    outcome.as_deref().is_ok_and(|o| o == "OK")
}

/// Writes the stand-in helper's log of `id` (0600 in its private folder), as the engine's connection log.
fn write_log(id: &uuid::Uuid) -> Result<(), String> {
    let path = FAKE_HELPER.get().and_then(|h| h.log_path(id)).ok_or("no stand-in log")?;
    let dir = path.parent().ok_or("no log folder")?;
    macvpn_core::fsx::ensure_private_dir(dir).map_err(|e| e.to_string())?;
    let mut file =
        std::fs::OpenOptions::new().create(true).append(true).mode(0o600).open(&path).map_err(|e| e.to_string())?;
    file.write_all(LOG_LINES.iter().map(|l| format!("{l}\n")).collect::<String>().as_bytes()).map_err(|e| e.to_string())
}

/// LinVPN L-b's NetworkManager rows and VPN rows over the stand-ins (the module's documentation).
pub(super) fn nm(app: &AppHandle, state: &Arc<AppState>, dir: &Path) {
    let say = |line: String| eprintln!("MacVPN smoke: nm: {line}");
    let source = match std::fs::read_to_string(dir.join("nm.js")) {
        Ok(source) => source,
        Err(e) => return say(format!("ERROR nm.js: {e}")),
    };
    let vault = match super::backup_service(state) {
        Ok(service) => service.vault().clone(),
        Err(e) => return say(format!("ERROR {e}")),
    };
    let fingerprint = format!("{OVPN}peer-fingerprint {}\n", ["AB"; 32].join(":"));
    let seeds: [Seed; 6] = [
        (RESULT, "Zz NM result", VPNKind::Openvpn, Some(OVPN.into()), None),
        (FINGERPRINT, FINGERPRINT_NAME, VPNKind::Openvpn, Some(fingerprint), None),
        (ROUTING, ROUTING_NAME, VPNKind::Openvpn, Some(OVPN.into()), None),
        (L2TP, L2TP_NAME, VPNKind::L2tp, None, native("l2tp-nm.example.com", "carol", "")),
        (CISCO, CISCO_NAME, VPNKind::Cisco, None, native("cisco-nm.example.com", "dave", "smoke")),
        (LOG, LOG_NAME, VPNKind::Openvpn, Some(OVPN.into()), None),
    ];
    for (id, name, kind, config, settings) in &seeds {
        let Some(uuid) = parse_uuid(id) else { return };
        let mut c = Connection::with_id(uuid, *name, *kind, Date::now());
        c.native.clone_from(settings);
        if let Err(e) = vault.with(|v| v.save_connection(&c, config.as_deref())) {
            return say(format!("ERROR seeding {name}: {e}"));
        }
    }
    let logged = parse_uuid(LOG).ok_or_else(|| "bad id".to_string()).and_then(|id| write_log(&id));
    state.manager.reload();

    let key = |id: &str| parse_uuid(id).map(|u| uuid_string(&u)).unwrap_or_default();
    let service = |id: &str| parse_uuid(id).map(|u| names::service_id(&u)).unwrap_or_default();
    let listed = |id: &str| {
        let wanted = service(id);
        FAKE_NATIVE.get().and_then(|n| n.list().ok()).is_some_and(|l| l.iter().any(|s| s.id == wanted))
    };
    let row = |id: &str| {
        let wanted = key(id);
        state.view_model().rows.into_iter().find(|r| r.id == wanted)
    };
    let record = |id: &str| {
        parse_uuid(id)
            .map(|u| state.env.application_support().join("nm").join(format!("{}.json", u.hyphenated())))
            .is_some_and(|p| p.is_file())
    };
    let reason = fingerprint_reason();
    let l2tp_before = listed(L2TP) || record(L2TP);
    let fingerprint_greyed = row(FINGERPRINT)
        .is_some_and(|r| !r.available && r.unavailable_reason.as_deref().is_some_and(|t| t.contains(&reason)));
    let cisco_usable = row(CISCO).is_some_and(|r| r.available && r.unavailable_reason.is_none());
    say(format!(
        "rows l2tp_before_save={l2tp_before} fingerprint_greyed={fingerprint_greyed} cisco_usable={cisco_usable} log_written={}",
        logged.is_ok()
    ));

    // System Status: SSTP's plugin missing; Install runs the sandbox's install, then the stand-in has it.
    let setup_window = crate::system::SETUP_WINDOW;
    if let Some(window) = app.get_webview_window(setup_window) {
        let _ = window.destroy();
    }
    SSTP_MISSING.store(true, Ordering::SeqCst);
    crate::system::check(state);
    let setup_vars = [
        ("nmDetail", js("NetworkManager 1.54.3")),
        ("sstpMissing", js(&l10n::tr("Not installed: %@", &[Arg::Str("network-manager-sstp")]))),
        ("installed", js(&l10n::tr("Installed", &[]))),
        ("installOutput", js("sandbox: PackageKit is not asked")),
    ];
    let setup = phase(app, state, &source, setup_window, "setup", &setup_vars);
    let install_ran = state.view_model().setup.brew_output.contains("sandbox: PackageKit is not asked");
    SSTP_MISSING.store(false, Ordering::SeqCst);
    crate::system::check(state);
    let green = phase(app, state, &source, setup_window, "green", &setup_vars);
    if let Some(window) = app.get_webview_window(setup_window) {
        let _ = window.destroy();
    }
    say(format!("setup {} install_ran={install_ran} green {}", shown(&setup), shown(&green)));

    // The Connections window.
    let vars = [
        ("fingerprint", js(&key(FINGERPRINT))),
        ("fingerprintName", js(FINGERPRINT_NAME)),
        ("fingerprintReason", js(&reason)),
        ("routing", js(&key(ROUTING))),
        ("routingName", js(ROUTING_NAME)),
        (
            "routingLabels",
            js(&[l10n::tr("Server decides", &[]), l10n::tr("Always", &[]), l10n::tr("Never (split tunnel)", &[])]
                .join("|")),
        ),
        ("l2tp", js(&key(L2TP))),
        ("l2tpName", js(L2TP_NAME)),
        ("password", js(L2TP_PASSWORD)),
        ("psk", js(L2TP_PSK)),
        ("saveLabel", js(&l10n::tr("Save", &[]))),
        (
            "approveNote",
            js(&l10n::tr(
                "Saving creates and opens a configuration profile. Approve it in System Settings → General → Device Management (Profiles). After each change it has to be approved again. The password is not in the profile: MacVPN passes it when connecting (from System Settings, macOS asks for it).",
                &[],
            )),
        ),
        (
            "saveNote",
            js(&l10n::tr(
                "Saving writes the Windows VPN entry of this connection at once; there is nothing to approve. The password is not in it: MacVPN passes it when connecting.",
                &[],
            )),
        ),
        ("cisco", js(&key(CISCO))),
        ("ciscoName", js(CISCO_NAME)),
        ("log", js(&key(LOG))),
        ("logName", js(LOG_NAME)),
        ("logLine", js(LOG_LINES[0])),
        ("clearedNote", js(macvpn_core::log::cleared_note("").trim_end_matches(" ═══").trim_end())),
    ];
    let ui = phase(app, state, &source, crate::manage::MANAGE_WINDOW, "manage", &vars);
    say(format!("manage {}", shown(&ui)));

    // The backend's part: the stored config, the plan record, the stand-ins' calls, the cleared log.
    let stored = parse_uuid(ROUTING)
        .and_then(|u| state.connections.deps().store.load_config_wiped(&u).ok())
        .is_some_and(|c| c.lines().any(|l| l.trim() == "redirect-gateway def1"));
    let l2tp_record = record(L2TP);
    let l2tp_listed = listed(L2TP);
    let native_has = |line: &str| FAKE_NATIVE.get().is_some_and(|n| n.recorded(line));
    let l2tp_started = native_has(&format!("start {} username=set password=set psk=set", service(L2TP)));
    let l2tp_stopped = native_has(&format!("stop {}", service(L2TP)));
    let helper = |op: &str, id: &str| {
        let (Some(fake), Some(uuid)) = (FAKE_HELPER.get(), parse_uuid(id)) else { return 0 };
        fake.calls(op, &uuid)
    };
    let log_up_down = helper("up", LOG) == 1 && helper("down", LOG) >= 1;
    let never_helper = [FINGERPRINT, L2TP, CISCO].iter().all(|id| helper("up", id) == 0);
    let log_path = parse_uuid(LOG).and_then(|u| FAKE_HELPER.get().and_then(|h| h.log_path(&u)));
    let log_text = log_path.as_ref().and_then(|p| std::fs::read_to_string(p).ok()).unwrap_or_default();
    let log_cleared = !log_text.is_empty() && !LOG_LINES.iter().any(|l| log_text.contains(l));
    say(format!(
        "backend stored_always={stored} l2tp_record={l2tp_record} l2tp_listed={l2tp_listed} l2tp_started={l2tp_started} l2tp_stopped={l2tp_stopped} log_helper={log_up_down} log_cleared={log_cleared}"
    ));

    // Back to the run's state: nothing connected, the step's connections, the plan record and the log gone.
    for (id, ..) in &seeds {
        let Some(uuid) = parse_uuid(id) else { continue };
        let key = uuid_string(&uuid);
        let Some(c) = state.manager.connections().into_iter().find(|c| c.id == uuid) else { continue };
        if state.manager.state(&key).is_active() {
            state.manager.disconnect(&c);
        }
        if c.kind.is_native() {
            state.native_profiles.remove(&uuid);
        }
        let _ = vault.with(|v| v.delete_connection(&uuid));
    }
    if let Some(path) = &log_path {
        let _ = std::fs::remove_file(path);
    }
    state.manager.reload();
    let removed = !listed(L2TP) && !record(L2TP);
    say(format!("removed records_gone={removed}"));
    say(verdict(&[
        ("logWritten", logged.is_ok()),
        ("notListedBeforeSave", !l2tp_before),
        ("fingerprintGreyed", fingerprint_greyed),
        ("ciscoUsable", cisco_usable),
        ("setup", passed(&setup)),
        ("installRan", install_ran),
        ("green", passed(&green)),
        ("ui", passed(&ui)),
        ("storedAlways", stored),
        ("l2tpRecord", l2tp_record),
        ("l2tpListed", l2tp_listed),
        ("l2tpStarted", l2tp_started),
        ("l2tpStopped", l2tp_stopped),
        ("logHelper", log_up_down),
        ("neverHelper", never_helper),
        ("logCleared", log_cleared),
        ("recordsRemoved", removed),
    ]));
}

fn shown(outcome: &Result<String, String>) -> String {
    match outcome {
        Ok(o) => o.clone(),
        Err(e) => format!("ERROR {e}"),
    }
}
