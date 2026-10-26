//! The `RasEngine`'s decisions without a Win32 call (WinVPN 2c, Task 8): the saved profile of an L2TP connection
//! (what `NativeProfiles::build` hands to `install`), the credentials one dial takes from the vault secrets, the
//! per-connection "not on Windows" reason, the error context of a dial, the log's header and line shapes, and the
//! System Status facts of the Windows VPN client. Compiled and tested on every OS.

use super::ras_errors::ErrorContext;
use macvpn_core::l10n::{self, Arg};
use macvpn_core::models::{Connection, Secrets, VPNKind, uuid_string};
use macvpn_core::ras::{self, Auth, DefaultRoute, Needs, RasEntryPlan, Strategy};
use macvpn_core::validators::{CertMode, SSTPConfig};
use macvpn_platform_api::{EngineRow, SetupReport};
use uuid::Uuid;
use zeroize::Zeroizing;

/// The first line of a saved profile (format version 1).
const PROFILE_MAGIC: &str = "winvpn-ras-profile 1";
/// A profile is a few short lines; anything larger is not one of ours.
const PROFILE_MAX: usize = 16 * 1024;

/// The profile `NativeProfiles::build` returns: the L2TP plan (no secret: the password and the PSK come from the
/// vault at each connect), or the reasons the connection cannot have an entry on Windows (Cisco IPsec, invalid
/// settings), which `install` then answers. Values are escaped (`%`, CR, LF), so a value never adds a line.
pub fn encode_profile(plan: &Result<RasEntryPlan, ras::Unsupported>) -> Zeroizing<Vec<u8>> {
    let mut lines = vec![PROFILE_MAGIC.to_string()];
    match plan {
        Ok(plan) if plan.strategy == Strategy::L2tp => {
            let route = match plan.default_route {
                DefaultRoute::None => "none",
                DefaultRoute::Ipv4 => "ipv4",
                DefaultRoute::Both => "both",
            };
            lines.push("strategy=l2tp".into());
            lines.push(format!("server={}", escape(&plan.server)));
            lines.push(format!("user={}", escape(&plan.user)));
            lines.push(format!("route={route}"));
        }
        // Only L2TP is saved as a profile (IKEv2 and SSTP entries are written at each connect).
        Ok(_) => lines.push(format!("error={}", escape(&entry_damaged()))),
        Err(u) => lines.extend(u.reasons.iter().map(|r| format!("error={}", escape(r)))),
    }
    let mut out = lines.join("\n");
    out.push('\n');
    Zeroizing::new(out.into_bytes())
}

/// The plan of a profile [`encode_profile`] wrote (`Err`: the reasons it carries, or "not a profile" for anything
/// else; a profile file is untrusted input: bounded, strict).
pub fn decode_profile(bytes: &[u8]) -> Result<RasEntryPlan, String> {
    let invalid = entry_damaged;
    if bytes.len() > PROFILE_MAX {
        return Err(invalid());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    let mut lines = text.lines();
    if lines.next() != Some(PROFILE_MAGIC) {
        return Err(invalid());
    }
    let (mut strategy, mut server, mut user, mut route) = (None, None, None, None);
    let mut errors = Vec::new();
    for line in lines {
        let (key, value) = line.split_once('=').ok_or_else(invalid)?;
        let value = unescape(value).ok_or_else(invalid)?;
        match key {
            "strategy" => strategy = Some(value),
            "server" => server = Some(value),
            "user" => user = Some(value),
            "route" => route = Some(value),
            "error" => errors.push(value),
            _ => return Err(invalid()),
        }
    }
    if !errors.is_empty() {
        return Err(errors.join("\n"));
    }
    let default_route = match route.as_deref() {
        Some("none") => DefaultRoute::None,
        Some("ipv4") => DefaultRoute::Ipv4,
        Some("both") => DefaultRoute::Both,
        _ => return Err(invalid()),
    };
    match (strategy.as_deref(), server, user) {
        (Some("l2tp"), Some(server), Some(user)) if !server.is_empty() => Ok(RasEntryPlan {
            strategy: Strategy::L2tp,
            server,
            auth: Auth::MsChapV2 { psk: true },
            default_route,
            ts_as_routes: false,
            ike_fragmentation: false,
            interface_metric: None,
            policy: None,
            user,
            needs: Needs { user: true, password: true, psk: true },
            warnings: Vec::new(),
        }),
        _ => Err(invalid()),
    }
}

/// A managed entry WinVPN cannot use: its saved profile is missing or not WinVPN's.
pub fn entry_damaged() -> String {
    l10n::tr("Save this connection again: its Windows VPN entry is missing or damaged.", &[])
}

fn escape(value: &str) -> String {
    value.replace('%', "%25").replace('\r', "%0D").replace('\n', "%0A")
}

fn unescape(value: &str) -> Option<String> {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(p) = rest.find('%') {
        out.push_str(&rest[..p]);
        let code = rest.get(p + 1..p + 3)?;
        out.push(match code {
            "25" => '%',
            "0D" => '\r',
            "0A" => '\n',
            _ => return None,
        });
        rest = &rest[p + 3..];
    }
    out.push_str(rest);
    Some(out)
}

/// The user name of one dial: the vault's (or the credential prompt's) when the plan asks for it and it is set,
/// else the one the connection names (L2TP account, SSTP `user`, IKEv2 `eap_id`), as macOS' start options
/// override the profile's account name. `user@domain` goes as it is; there is no separate domain.
pub fn dial_user(plan: &RasEntryPlan, secrets: &Secrets) -> String {
    match secrets.username.as_deref().filter(|u| plan.needs.user && !u.is_empty()) {
        Some(user) => user.to_string(),
        None => plan.user.clone(),
    }
}

/// The password of one dial, exactly as the manager prepared it (with the one-time code already appended,
/// `mfa::apply_code`); empty for a computer certificate.
pub fn dial_password(plan: &RasEntryPlan, secrets: &Secrets) -> Zeroizing<String> {
    let password = if plan.needs.password { secrets.password.as_deref().unwrap_or("") } else { "" };
    Zeroizing::new(password.to_string())
}

/// The PSK the dial writes to Windows' RAS credential store first (L2TP): `None` when the plan takes none; an
/// error when it takes one and the vault has none (the credential prompt asks for it before this point).
pub fn dial_psk<'a>(plan: &RasEntryPlan, secrets: &'a Secrets) -> Result<Option<&'a str>, String> {
    if !plan.needs.psk {
        return Ok(None);
    }
    match secrets.psk.as_deref().filter(|p| !p.is_empty()) {
        Some(psk) => Ok(Some(psk)),
        None => Err(l10n::tr("Missing: %@", &[Arg::Str(&l10n::tr("Pre-shared key (PSK)", &[]))])),
    }
}

/// Why this connection cannot connect on Windows (`NativeSupport`): the first Windows reason of its plan (Cisco
/// IPsec, IKEv2 / SSTP settings Windows lacks). An invalid config is not a Windows limit (the editor and the
/// connect say what is wrong, as on macOS), and OpenVPN / WireGuard are not RAS kinds: `None`.
pub fn unsupported_reason(connection: &Connection, config: &[u8]) -> Option<String> {
    match ras::plan_for(connection, config)? {
        Ok(_) => None,
        Err(u) if u.invalid_config => None,
        Err(u) => u.reasons.into_iter().next(),
    }
}

/// The error context of a dial (`config`: the SSTP config, for its certificate mode).
pub fn error_context(plan: &RasEntryPlan, config: &[u8]) -> ErrorContext {
    let custom_ca = plan.strategy == Strategy::Sstp
        && std::str::from_utf8(config).is_ok_and(|t| SSTPConfig::parse(t).cert == CertMode::Ca);
    ErrorContext::for_plan(plan, custom_ca)
}

/// The connection kind a RAS strategy belongs to (an entry found after a relaunch).
pub fn kind_of(strategy: Strategy) -> VPNKind {
    match strategy {
        Strategy::L2tp => VPNKind::L2tp,
        Strategy::Sstp => VPNKind::Sstp,
        Strategy::Ikev2 => VPNKind::Strongswan,
    }
}

/// `SystemVpn.type_label` of an entry.
pub fn type_label(strategy: Strategy) -> &'static str {
    match strategy {
        Strategy::L2tp => "L2TP",
        Strategy::Sstp => "SSTP",
        Strategy::Ikev2 => "IKEv2",
    }
}

/// The kinds the `RasEngine` answers through the `HelperClient` (on macOS the root layer's): IKEv2 and SSTP.
pub fn is_helper_kind(kind: VPNKind) -> bool {
    matches!(kind, VPNKind::Strongswan | VPNKind::Sstp)
}

/// The first line of a connect in the connection's log: `═══ <local time> up <kind> <UUID>[ (debug)] ═══`, the
/// root layer's header shape (the Log tab shows it as a header).
pub fn header(time: &str, kind: VPNKind, id: &Uuid, debug: bool) -> String {
    let debug = if debug { " (debug)" } else { "" };
    format!("═══ {time} up {} {}{debug} ═══", kind.raw_value(), uuid_string(id))
}

/// An error line of the log (the Log tab's error filter: `✗`).
pub fn error_line(line: &str) -> String {
    format!("✗ {line}")
}

/// `YYYY-MM-DD HH:MM:SS` of a local (y, m, d, h, mi, s).
pub fn timestamp((y, mo, d, h, mi, s): (i32, u32, u32, u32, u32, u32)) -> String {
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}")
}

/// System Status with the RAS engine: L2TP, IKEv2 and SSTP no longer come "later" and follow the Windows VPN
/// client row (green: built into Windows; the Windows services RAS needs are read by the system VPN list's task),
/// whatever the WinVPN Service's state. Cisco IPsec keeps its own answer.
pub fn complete_report(report: &mut SetupReport) {
    report.later_kinds.retain(|(kind, _)| !matches!(kind, VPNKind::L2tp | VPNKind::Strongswan | VPNKind::Sstp));
    report.ras = Some(EngineRow { ok: true, usable: true, detail: l10n::tr("Built into Windows", &[]), action: None });
}
