//! IKEv2 from a strongSwan `swanctl.conf`: the first connection and its first child (the ones macOS initiates)
//! translated to the Windows IKEv2 client, or the precise reasons it cannot.
//!
//! The validator runs first (an invalid config is its error). Then the validated text is read with the
//! validator's own scanner (`StrongSwanValidator::visit`), so there is no second parser. Keys that matter
//! are translated; keys whose non-default value changes behaviour Windows cannot reproduce are reasons; a few
//! whose effect Windows covers its own way (`dpd_action = restart`, `start_action`) are warnings on the plan;
//! every other allowed key is ignored (Windows has its own timers, DPD, MOBIKE and rekeying).

use super::policy::{self, WINDOWS_DEFAULT_FOR_STRONGSWAN, WindowsPolicy};
use super::{
    Auth, DefaultRoute, Needs, RasEntryPlan, Strategy, Unsupported, config_text, not_supported, quoted, setting,
};
use crate::l10n::{self, Arg};
use crate::netaddr::IpPrefix;
use crate::swift_str::ascii_lowercased;
use crate::validators::strongswan::{Context, Section, Visit};
use crate::validators::{ConfigValidator, StrongSwanValidator};
use std::collections::HashMap;
use std::net::IpAddr;

/// Connection keys whose value must be one of the defaults (empty list: the key must be absent).
const CONN_RULES: &[(&str, &[&str])] = &[
    ("if_id_in", &["0"]),
    ("if_id_out", &["0"]),
    ("ppk_id", &[]),
    ("ppk_required", &["no"]),
    // Windows dials IKE on port 500 (4500 after NAT detection) only.
    ("remote_port", &["500"]),
];

/// Child keys whose value must be one of the defaults. `dpd_action = restart` and `start_action` are warnings
/// (coordinator decision 2026-10-25, see [`child_warnings`]).
const CHILD_RULES: &[(&str, &[&str])] = &[
    ("mode", &["tunnel"]),
    ("dpd_action", &["clear", "none", "restart"]),
    ("close_action", &["none"]),
    ("if_id_in", &["0"]),
    ("if_id_out", &["0"]),
    ("mark_in", &["0"]),
    ("mark_in_sa", &["no"]),
    ("mark_out", &["0"]),
    ("set_mark_in", &["0"]),
    ("set_mark_out", &["0"]),
    ("hostaccess", &["no"]),
];

/// The keys of the first connection, its first `local` / `remote` sections and its first child (a repeated key:
/// the last value, as strongSwan reads it). Values are the items joined with a space.
#[derive(Default)]
struct Swan {
    connection: Option<String>,
    child: Option<String>,
    conn: HashMap<String, String>,
    local_sections: Vec<String>,
    local: HashMap<String, String>,
    remote_sections: Vec<String>,
    remote: HashMap<String, String>,
    child_keys: HashMap<String, String>,
}

/// The first connection and its first child are the ones macOS initiates (`StrongSwanValidator::names` reads the
/// same two from the lines; this reads them from the sections, so a compact layout such as
/// `children { net { … } }` works too).
fn read(text: &str) -> Swan {
    let mut swan = Swan::default();
    StrongSwanValidator::visit(text, &mut |path: &[Section], event: Visit<'_>| {
        if path.len() < 2 || path[0].context != Context::Connections || path[1].context != Context::Conn {
            return;
        }
        let connection = swan.connection.get_or_insert_with(|| path[1].name.clone());
        if path[1].name != *connection {
            return;
        }
        let first_section = |names: &mut Vec<String>, name: &str| {
            if !names.iter().any(|n| n == name) {
                names.push(name.to_string());
            }
            names[0] == name
        };
        let in_child = path.len() == 4 && path[2].context == Context::Children && path[3].context == Context::Child;
        match event {
            Visit::Open => match path.len() {
                3 if path[2].context == Context::Local => {
                    first_section(&mut swan.local_sections, &path[2].name);
                }
                3 if path[2].context == Context::Remote => {
                    first_section(&mut swan.remote_sections, &path[2].name);
                }
                4 if in_child => {
                    swan.child.get_or_insert_with(|| path[3].name.clone());
                }
                _ => {}
            },
            Visit::Key(key, items) => {
                let value = items.join(" ");
                match path.len() {
                    2 => {
                        swan.conn.insert(key.to_string(), value);
                    }
                    3 if path[2].context == Context::Local => {
                        if first_section(&mut swan.local_sections, &path[2].name) {
                            swan.local.insert(key.to_string(), value);
                        }
                    }
                    3 if path[2].context == Context::Remote => {
                        if first_section(&mut swan.remote_sections, &path[2].name) {
                            swan.remote.insert(key.to_string(), value);
                        }
                    }
                    4 if in_child && swan.child.as_deref() == Some(path[3].name.as_str()) => {
                        swan.child_keys.insert(key.to_string(), value);
                    }
                    _ => {}
                }
            }
        }
    });
    swan
}

/// The plan of a strongSwan config.
pub fn plan_ikev2(config: &[u8]) -> Result<RasEntryPlan, Unsupported> {
    let text = config_text(config)?;
    let issues = StrongSwanValidator.validate(&text);
    if !issues.is_empty() {
        return Err(Unsupported::from_issues(&issues));
    }
    let swan = read(&text);
    if swan.connection.is_none() {
        return Err(Unsupported::invalid(vec![l10n::tr("Missing connections block", &[])]));
    }
    let mut reasons = Vec::new();

    match swan.conn.get("version").map(|v| v.trim()) {
        None | Some("0") | Some("2") => {}
        Some("1") => reasons.push(not_supported("version", "1 (IKEv1)")),
        Some(other) => reasons.push(not_supported("version", other)),
    }
    let server = match server(swan.conn.get("remote_addrs").map(String::as_str)) {
        Ok(server) => Some(server),
        Err(reason) => {
            reasons.push(reason);
            None
        }
    };
    check_rules(&swan.conn, CONN_RULES, &mut reasons);
    if let Some(vips) = swan.conn.get("vips") {
        let dynamic = ["0.0.0.0", "::", "%any", "%any4", "%any6"];
        if !vips.split(',').map(str::trim).filter(|v| !v.is_empty()).all(|v| dynamic.contains(&v)) {
            reasons.push(not_supported("vips", vips));
        }
    }

    // Authentication: one round each way.
    if swan.local_sections.len() > 1 || swan.remote_sections.len() > 1 {
        reasons.push(l10n::tr("Not supported on Windows: more than one authentication round", &[]));
    }
    if let Some(round) = swan.local.get("round")
        && !matches!(round.trim(), "0" | "1")
    {
        reasons.push(not_supported("local round", round));
    }
    let local_auth = swan.local.get("auth").map_or("pubkey", |v| v.trim());
    let remote_auth = swan.remote.get("auth").map_or("pubkey", |v| v.trim());
    let remote_lower = ascii_lowercased(remote_auth);
    let expect_remote = |wanted: &str, reasons: &mut Vec<String>| {
        if remote_lower != wanted {
            reasons.push(not_supported("remote auth", remote_auth));
        }
    };
    let auth = match ascii_lowercased(local_auth).as_str() {
        "eap-mschapv2" | "eap" => {
            expect_remote("pubkey", &mut reasons);
            Some(Auth::EapMsChapV2)
        }
        "psk" => {
            // The RAS spike (Task 2, Windows 11 26H2): `Add-VpnConnection` has no PSK method, RAS refuses
            // `RASEO2_UsePreSharedKeyForIkev2Initiator` alone (87), and with EAP or a certificate the dial fails
            // at once with E_FAIL. Restored only if a CP1 lab test proves an entry form that connects.
            reasons.push(l10n::tr(
                "Not supported on Windows: local auth = psk (the Windows IKEv2 client cannot sign in with a pre-shared key; use EAP-MSCHAPv2 or a computer certificate)",
                &[],
            ));
            None
        }
        "pubkey" => {
            expect_remote("pubkey", &mut reasons);
            Some(Auth::MachineCertificate)
        }
        _ => {
            reasons.push(not_supported("local auth", local_auth));
            None
        }
    };
    // Windows checks the server certificate's name against the address it dials.
    if remote_lower == "pubkey"
        && let (Some(server), Some(id)) = (&server, swan.remote.get("id"))
    {
        let id = id.trim();
        let id = id.strip_prefix('@').unwrap_or(id);
        if id != "%any" && ascii_lowercased(id) != ascii_lowercased(server) {
            reasons.push(l10n::tr(
                "On Windows the server's identity must be its address: set remote_addrs to the name in the server certificate.",
                &[],
            ));
        }
    }

    let ike = match swan.conn.get("proposals") {
        None => Some(WINDOWS_DEFAULT_FOR_STRONGSWAN.ike()),
        Some(value) => policy::ike_from_proposals(&policy::split_proposals(value)).or_else(|| {
            reasons.push(l10n::tr(
                "Windows supports none of these IKE proposals: %@. Windows offers: %@",
                &[Arg::Str(&quoted(value)), Arg::Str(policy::IKE_OFFER)],
            ));
            None
        }),
    };
    let fragmentation = swan.conn.get("fragmentation").is_none_or(|v| ascii_lowercased(v.trim()) != "no");

    // The child: routes, traffic selectors, behaviour, ESP.
    let (default_route, ts_as_routes) = match remote_ts(swan.child_keys.get("remote_ts").map(String::as_str)) {
        Ok(routing) => routing,
        Err(reason) => {
            reasons.push(reason);
            (DefaultRoute::None, true)
        }
    };
    if let Some(local_ts) = swan.child_keys.get("local_ts")
        && !local_ts
            .split(',')
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .all(|v| v == "dynamic" || IpPrefix::parse(v).is_some_and(|p| p.len == 0))
    {
        reasons.push(not_supported("local_ts", local_ts));
    }
    check_rules(&swan.child_keys, CHILD_RULES, &mut reasons);
    let warnings = child_warnings(&swan.child_keys);
    let esp = match swan.child_keys.get("esp_proposals") {
        None => Some(WINDOWS_DEFAULT_FOR_STRONGSWAN.esp()),
        Some(value) => policy::esp_from_proposals(&policy::split_proposals(value)).or_else(|| {
            reasons.push(l10n::tr(
                "Windows supports none of these ESP proposals: %@. Windows offers: %@",
                &[Arg::Str(&quoted(value)), Arg::Str(policy::ESP_OFFER)],
            ));
            None
        }),
    };

    let (Some(server), Some(auth), Some(ike), Some(esp), true) = (server, auth, ike, esp, reasons.is_empty()) else {
        return Err(Unsupported::windows(reasons));
    };
    let (user, needs) = match auth {
        Auth::EapMsChapV2 => {
            let eap_id = swan.local.get("eap_id").map_or("", |v| v.trim());
            let user = if eap_id.starts_with('%') { "" } else { eap_id };
            (user.to_string(), Needs { user: true, password: true, psk: false })
        }
        Auth::Ikev2Psk => (String::new(), Needs { user: false, password: false, psk: true }),
        Auth::MachineCertificate | Auth::MsChapV2 { .. } => (String::new(), Needs::default()),
    };
    Ok(RasEntryPlan {
        strategy: Strategy::Ikev2,
        server,
        auth,
        default_route,
        ts_as_routes,
        ike_fragmentation: fragmentation,
        interface_metric: None,
        policy: Some(WindowsPolicy::from_choices(ike, esp)),
        user,
        needs,
        warnings,
    })
}

/// The child keys Windows does not apply but whose purpose it covers its own way: the connection still runs.
fn child_warnings(keys: &HashMap<String, String>) -> Vec<String> {
    let mut warnings = Vec::new();
    if let Some(value) = keys.get("dpd_action")
        && ascii_lowercased(value.trim()) == "restart"
    {
        warnings.push(l10n::tr(
            "Ignored on Windows: %@ (Windows itself redials a dropped connection)",
            &[Arg::Str(&setting("dpd_action", value))],
        ));
    }
    if let Some(value) = keys.get("start_action")
        && ascii_lowercased(value.trim()) != "none"
    {
        warnings.push(l10n::tr(
            "Ignored on Windows: %@ (the connection starts when you connect it)",
            &[Arg::Str(&setting("start_action", value))],
        ));
    }
    warnings
}

/// A rule violation for each key of `rules` whose value is not one of its defaults.
fn check_rules(keys: &HashMap<String, String>, rules: &[(&str, &[&str])], reasons: &mut Vec<String>) {
    for (key, defaults) in rules {
        if let Some(value) = keys.get(*key)
            && !defaults.contains(&ascii_lowercased(value.trim()).as_str())
        {
            reasons.push(not_supported(key, value));
        }
    }
}

/// `remote_addrs`: exactly one host name or address (no list, range, subnet or `%any`).
fn server(remote_addrs: Option<&str>) -> Result<String, String> {
    let value = remote_addrs.unwrap_or("");
    let hosts: Vec<&str> = value.split(',').map(str::trim).filter(|h| !h.is_empty()).collect();
    let [host] = hosts.as_slice() else {
        return Err(if hosts.is_empty() {
            l10n::tr(
                "On Windows the server address is required: set remote_addrs to the server's name or address.",
                &[],
            )
        } else {
            not_supported("remote_addrs", value)
        });
    };
    if super::server_has_control(host) {
        return Err(super::server_control_reason());
    }
    let range = host.split_once('-').is_some_and(|(a, b)| a.parse::<IpAddr>().is_ok() && b.parse::<IpAddr>().is_ok());
    if host.contains('/') || host.starts_with('%') || host.contains(' ') || range {
        return Err(not_supported("remote_addrs", value));
    }
    Ok(host.to_string())
}

/// `remote_ts`: absent, `dynamic` or `0.0.0.0/0` → full tunnel (`::/0` too → IPv6 as well); otherwise a split
/// tunnel whose selectors become routes. Selectors with a protocol or port, or ranges, cannot be routes.
fn remote_ts(value: Option<&str>) -> Result<(DefaultRoute, bool), String> {
    let (mut v4, mut v6, mut split) = (false, false, false);
    for item in value.unwrap_or("").split(',').map(str::trim).filter(|v| !v.is_empty()) {
        if item == "dynamic" {
            continue;
        }
        match IpPrefix::parse(item) {
            Some(p) if p.len == 0 && p.addr.is_ipv4() => v4 = true,
            Some(p) if p.len == 0 => v6 = true,
            Some(_) => split = true,
            None => return Err(not_supported("remote_ts", item)),
        }
    }
    Ok(match (v4, v6, split) {
        (true, true, _) => (DefaultRoute::Both, false),
        (true, false, _) => (DefaultRoute::Ipv4, false),
        (false, true, _) => {
            return Err(l10n::tr("Not supported on Windows: remote_ts = ::/0 without 0.0.0.0/0", &[]));
        }
        (false, false, true) => (DefaultRoute::None, true),
        (false, false, false) => (DefaultRoute::Ipv4, false),
    })
}
