//! WinVPN 2c's native VPNs in the Windows smoke run (2c plan, Task 14), after the 2.0 features. Sandbox and
//! stand-ins only: the L2TP entries are the sandbox RAS engine's (its private phonebook under
//! `MACVPN_SANDBOX_HOME`; saving writes the entry, nothing stores a PSK in Windows), every connect goes to the
//! run's stand-ins ([`super::FakeNative`] for L2TP, [`super::FakeHelper`] for IKEv2 and SSTP): no `RasDialW`, no
//! network. `ras.js` runs in the Connections window with the expected texts from `strings.json` (the run's
//! language) in `window.__smoke`:
//!
//! - the New menu offers L2TP but not Cisco IPsec (option A);
//! - an IKEv2 connection with `local auth = psk`: the row is greyed with the Windows reason, the editor shows it,
//!   Connect is disabled;
//! - a Cisco IPsec connection: greyed with option A's text, **Make an L2TP/IPsec Copy** selects "<name> (L2TP)"
//!   (whose entry the sandbox engine writes);
//! - an IKEv2 (EAP) connection: the editor's "On Windows: EAP-MSCHAPv2 · …" summary; Connect → connected →
//!   Disconnect through the stand-in helper; an SSTP connection the same;
//! - an L2TP connection: not listed before its first save; password and PSK typed, **Save** (no profile to
//!   approve) writes the entry, which is then listed; Connect → connected (the stand-in got the user name, the
//!   password and the PSK) → Disconnect.
//!
//! The driver checks the backend's side (the rows' reasons, the stand-ins' calls, the entries listed) and prints
//! `MacVPN smoke: ras: ok` or `… FAILED <checks>`. The step's connections (and the copy) are created in the vault
//! here and deleted at the end with their entries, so the later steps see the same connections as before.

use macvpn_app_core::deps::{NativeController, SecretField};
use macvpn_core::date::Date;
use macvpn_core::l10n::{self, Arg};
use macvpn_core::models::{Connection, NativeSettings, VPNKind, parse_uuid, uuid_string};
use macvpn_core::ras::names;
use std::path::Path;
use std::sync::Arc;
use tauri::AppHandle;

use super::features::{js, verdict};
use super::{FAKE_HELPER, FAKE_NATIVE, eval, renamed, wait_for};
use crate::state::AppState;

/// Where `ras.js` writes its result (`RAS OK` / `RAS FAILED <checks>`).
const RESULT: &str = "AB111111-2222-4333-8444-555555555555";
const L2TP: &str = "AB211111-2222-4333-8444-555555555555";
const L2TP_NAME: &str = "Zz RAS L2TP";
const CISCO: &str = "AB311111-2222-4333-8444-555555555555";
const CISCO_NAME: &str = "Zz RAS Cisco";
const IKEV2: &str = "AB411111-2222-4333-8444-555555555555";
const IKEV2_NAME: &str = "Zz RAS IKEv2";
const IKEV2_PSK: &str = "AB511111-2222-4333-8444-555555555555";
const IKEV2_PSK_NAME: &str = "Zz RAS IKEv2 PSK";
const SSTP: &str = "AB611111-2222-4333-8444-555555555555";
const SSTP_NAME: &str = "Zz RAS SSTP";
/// What `ras.js` types into the L2TP form (compared by the stand-in's log line only: never logged).
const L2TP_PASSWORD: &str = "smoke-ras-pass";
const L2TP_PSK: &str = "smoke-ras-psk";

const OVPN: &str = "client\ndev tun\nremote vpn.example.com 1194\n";
const SSTP_CONFIG: &str =
    "server=sstp-ras.example.com\nport=443\nuser=erin\ncert=system\nroute_all=yes\npeer_dns=yes\n";
/// IKEv2 with EAP-MSCHAPv2: what Windows' client runs (the 2c plan's reference).
const IKEV2_EAP: &str = "connections {\n  office {\n    version = 2\n    remote_addrs = ikev2-ras.example.com\n    vips = 0.0.0.0\n    proposals = aes256-sha256-modp2048\n    local { auth = eap-mschapv2\n            eap_id = frank }\n    remote { auth = pubkey\n             id = ikev2-ras.example.com }\n    children { net { remote_ts = 10.0.0.0/8\n                     esp_proposals = aes256-sha256 } }\n  }\n}\n";

/// The reason a pre-shared key IKEv2 connection gets on Windows (the literal `strings.json` key).
fn ikev2_psk_reason() -> String {
    l10n::tr(
        "Not supported on Windows: local auth = psk (the Windows IKEv2 client cannot sign in with a pre-shared key; use EAP-MSCHAPv2 or a computer certificate)",
        &[],
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

pub fn run(app: &AppHandle, state: &Arc<AppState>, dir: &Path) {
    let say = |line: String| eprintln!("MacVPN smoke: ras: {line}");
    let vault = match super::backup_service(state) {
        Ok(service) => service.vault().clone(),
        Err(e) => return say(format!("ERROR {e}")),
    };
    let ikev2_psk = IKEV2_EAP.replace("auth = eap-mschapv2", "auth = psk").replace("auth = pubkey", "auth = psk");
    let seeds: [Seed; 6] = [
        (RESULT, "Zz RAS result", VPNKind::Openvpn, Some(OVPN.into()), None),
        (L2TP, L2TP_NAME, VPNKind::L2tp, None, native("l2tp-ras.example.com", "carol", "")),
        (CISCO, CISCO_NAME, VPNKind::Cisco, None, native("cisco-ras.example.com", "dave", "smoke")),
        (IKEV2, IKEV2_NAME, VPNKind::Strongswan, Some(IKEV2_EAP.into()), None),
        (IKEV2_PSK, IKEV2_PSK_NAME, VPNKind::Strongswan, Some(ikev2_psk), None),
        (SSTP, SSTP_NAME, VPNKind::Sstp, Some(SSTP_CONFIG.into()), None),
    ];
    for (id, name, kind, config, settings) in &seeds {
        let Some(uuid) = parse_uuid(id) else { return };
        let mut c = Connection::with_id(uuid, *name, *kind, Date::now());
        c.native.clone_from(settings);
        if let Err(e) = vault.with(|v| v.save_connection(&c, config.as_deref())) {
            return say(format!("ERROR seeding {name}: {e}"));
        }
    }
    // The helper kinds' stored secrets (the sandbox's in-memory store): their connects ask nothing.
    let writer = &state.connections.deps().secret_writer;
    for (id, user) in [(IKEV2, Some("frank")), (SSTP, None)] {
        let Some(uuid) = parse_uuid(id) else { continue };
        if let Some(user) = user {
            writer.set(user, &uuid, SecretField::Username);
        }
        writer.set("smoke-ras-helper-pass", &uuid, SecretField::Password);
    }
    state.manager.reload();

    let key = |id: &str| parse_uuid(id).map(|u| uuid_string(&u)).unwrap_or_default();
    let entry = |id: &str| parse_uuid(id).map(|u| names::entry_name(&u)).unwrap_or_default();
    let listed = |id: &str| {
        let wanted = entry(id);
        FAKE_NATIVE.get().and_then(|n| n.list().ok()).is_some_and(|l| l.iter().any(|s| s.id == wanted))
    };
    let row = |id: &str| {
        let wanted = key(id);
        state.view_model().rows.into_iter().find(|r| r.id == wanted)
    };
    let cisco_reason = macvpn_platform_win::pure::cisco::unsupported();
    let greyed = |id: &str, reason: &str| {
        row(id).is_some_and(|r| !r.available && r.unavailable_reason.as_deref().is_some_and(|t| t.contains(reason)))
    };
    let l2tp_before = listed(L2TP);
    let psk_greyed = greyed(IKEV2_PSK, &ikev2_psk_reason());
    let cisco_greyed = greyed(CISCO, &cisco_reason);
    let eap_usable = row(IKEV2).is_some_and(|r| r.available);
    say(format!(
        "rows l2tp_listed_before_save={l2tp_before} ikev2_psk_greyed={psk_greyed} cisco_greyed={cisco_greyed} ikev2_usable={eap_usable}"
    ));

    // The window's part.
    let copy_name = format!("{CISCO_NAME} (L2TP)");
    let vars = [
        ("result", js(RESULT)),
        ("l2tp", js(&key(L2TP))),
        ("l2tpName", js(L2TP_NAME)),
        ("cisco", js(&key(CISCO))),
        ("ciscoName", js(CISCO_NAME)),
        ("copyName", js(&copy_name)),
        ("ikev2", js(&key(IKEV2))),
        ("ikev2Name", js(IKEV2_NAME)),
        ("ikev2Psk", js(&key(IKEV2_PSK))),
        ("ikev2PskName", js(IKEV2_PSK_NAME)),
        ("sstp", js(&key(SSTP))),
        ("sstpName", js(SSTP_NAME)),
        ("password", js(L2TP_PASSWORD)),
        ("psk", js(L2TP_PSK)),
        ("pskReason", js(&ikev2_psk_reason())),
        ("ciscoReason", js(&cisco_reason)),
        ("copyLabel", js(&l10n::tr("Make an L2TP/IPsec Copy", &[]))),
        ("summary", js(&l10n::tr("On Windows: %@", &[Arg::Str("EAP-MSCHAPv2")]))),
        ("saveLabel", js(&l10n::tr("Save", &[]))),
        ("l2tpLabel", js(VPNKind::L2tp.display_name())),
        ("ciscoLabel", js(VPNKind::Cisco.display_name())),
    ];
    let smoke =
        format!("{{ {} }}", vars.iter().map(|(name, value)| format!("{name}: {value}")).collect::<Vec<_>>().join(", "));
    let ui = std::fs::read_to_string(dir.join("ras.js"))
        .map_err(|e| format!("ras.js: {e}"))
        .and_then(|source| {
            crate::commands::open(app, crate::manage::MANAGE_WINDOW)?;
            eval(app, crate::manage::MANAGE_WINDOW, format!("window.__smoke = {smoke};\n{source}"))
        })
        .and_then(|()| wait_for(180, || renamed(state, RESULT, "RAS")).ok_or_else(|| "no result".to_string()));
    let ui_ok = ui.as_deref().is_ok_and(|r| r == "RAS OK");
    say(format!("ui: {}", ui.unwrap_or_else(|e| format!("ERROR {e}"))));

    // The backend's part: the stand-ins' calls and the entries.
    let log_has = |line: &str| FAKE_NATIVE.get().is_some_and(|n| n.recorded(line));
    let l2tp_entry = entry(L2TP);
    let l2tp_listed = listed(L2TP);
    let l2tp_started = log_has(&format!("start {l2tp_entry} username=set password=set psk=set"));
    let l2tp_stopped = log_has(&format!("stop {l2tp_entry}"));
    let helper = |op: &str, id: &str| {
        let (Some(fake), Some(uuid)) = (FAKE_HELPER.get(), parse_uuid(id)) else { return 0 };
        fake.calls(op, &uuid)
    };
    let ikev2_up_down = helper("up", IKEV2) == 1 && helper("down", IKEV2) >= 1;
    let sstp_up_down = helper("up", SSTP) == 1 && helper("down", SSTP) >= 1;
    let never_helper = [L2TP, CISCO, IKEV2_PSK].iter().all(|id| helper("up", id) == 0);
    let copy = state.manager.connections().into_iter().find(|c| c.name == copy_name);
    let copy_l2tp = copy.as_ref().is_some_and(|c| c.kind == VPNKind::L2tp);
    let copy_listed = copy.as_ref().is_some_and(|c| listed(&uuid_string(&c.id)));
    let cisco_untouched = !listed(CISCO);
    say(format!(
        "backend l2tp_listed={l2tp_listed} l2tp_started={l2tp_started} l2tp_stopped={l2tp_stopped} ikev2_helper={ikev2_up_down} sstp_helper={sstp_up_down} copy_l2tp={copy_l2tp} copy_listed={copy_listed}"
    ));

    // Back to the run's state: nothing connected, the step's connections, their entries and the copy gone.
    let mut ids: Vec<uuid::Uuid> = seeds.iter().filter_map(|(id, ..)| parse_uuid(id)).collect();
    ids.extend(copy.as_ref().map(|c| c.id));
    for uuid in &ids {
        let id = uuid_string(uuid);
        let Some(c) = state.manager.connections().into_iter().find(|c| c.id == *uuid) else { continue };
        if state.manager.state(&id).is_active() {
            state.manager.disconnect(&c);
        }
        // The sandbox engine's entry and saved profile (the L2TP ones; the others have none).
        if c.kind == VPNKind::L2tp {
            state.native_profiles.remove(uuid);
        }
        let _ = vault.with(|v| v.delete_connection(uuid));
    }
    state.manager.reload();
    let removed = !listed(L2TP) && copy.as_ref().is_none_or(|c| !listed(&uuid_string(&c.id)));
    say(format!("removed entries_gone={removed}"));
    say(verdict(&[
        ("notListedBeforeSave", !l2tp_before),
        ("ikev2PskGreyed", psk_greyed),
        ("ciscoGreyed", cisco_greyed),
        ("ikev2Usable", eap_usable),
        ("ui", ui_ok),
        ("l2tpListed", l2tp_listed),
        ("l2tpStarted", l2tp_started),
        ("l2tpStopped", l2tp_stopped),
        ("ikev2Helper", ikev2_up_down),
        ("sstpHelper", sstp_up_down),
        ("neverHelper", never_helper),
        ("copyL2tp", copy_l2tp),
        ("copyListed", copy_listed),
        ("ciscoNoEntry", cisco_untouched),
        ("entriesRemoved", removed),
    ]));
}
