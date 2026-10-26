//! The user's own Windows VPNs (the "system VPNs", the entries of Windows' default phonebooks) without system
//! calls: their labels and IDs, their status from a RAS connection, how a start signs in, which connection belongs
//! to which entry, and System Status' Windows VPN client row from the Windows services RAS needs.
//!
//! WinVPN never edits, renames or deletes these entries: it lists them, dials and hangs them up.

use macvpn_core::l10n::{self, Arg};
use macvpn_core::models::{VPNKind, uuid_string};
use macvpn_platform_api::{EngineRow, SetupReport};

/// The protocol of a system entry (its `dwVpnStrategy`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    L2tp,
    Ikev2,
    Sstp,
    /// Automatic, PPTP or anything else.
    Other,
}

/// The `SystemVpn.type_label` of an entry: `L2TP`, `IKEv2`, `SSTP` (Windows only) or `VPN`.
pub fn type_label(kind: EntryKind) -> &'static str {
    match kind {
        EntryKind::L2tp => "L2TP",
        EntryKind::Ikev2 => "IKEv2",
        EntryKind::Sstp => "SSTP",
        EntryKind::Other => "VPN",
    }
}

/// The `SystemVpn.id` of an entry: its `guidId` as an upper-case UUID (so `SystemVpn::secret_id` works and the
/// ID survives a rename in Settings). An entry without a GUID (all zero) gets `RAS:<name>`, which is not a UUID
/// (no stored secrets for it).
pub fn system_id(guid: Option<[u8; 16]>, name: &str) -> String {
    match guid.filter(|g| g.iter().any(|&b| b != 0)) {
        Some(g) => uuid_string(&uuid::Uuid::from_bytes(g)),
        None => format!("RAS:{name}"),
    }
}

/// `RASCS_Connected`.
const RASCS_CONNECTED: u32 = 0x2000;
/// `RASCS_Disconnected`.
const RASCS_DISCONNECTED: u32 = 0x2001;

/// The `SystemVpn.status` of an entry with a RAS connection in `state` (`RasGetConnectStatusW`): a connection
/// with an error, or one that ended, is `Disconnected`.
pub fn connection_status(state: u32, error: u32) -> &'static str {
    match (state, error) {
        (_, e) if e != 0 => "Disconnected",
        (RASCS_CONNECTED, _) => "Connected",
        (RASCS_DISCONNECTED, _) => "Disconnected",
        _ => "Connecting",
    }
}

/// Two phonebook paths name the same file: compared without regard to letter case (Windows' file names; the
/// connection list returns the path exactly as its dialler passed it), `/` as `\`, a `\\?\` prefix ignored.
/// Empty paths never match.
pub fn same_phonebook(a: &str, b: &str) -> bool {
    fn norm(p: &str) -> String {
        let p = p.strip_prefix(r"\\?\").unwrap_or(p);
        p.chars().map(|c| if c == '/' { '\\' } else { c }).flat_map(char::to_uppercase).collect()
    }
    !a.is_empty() && !b.is_empty() && norm(a) == norm(b)
}

/// A RAS connection is the entry's: the same `guidId` (when both have one), else the same name in the same
/// phonebook. (A connection whose phonebook path is not reported counts by name only.)
pub fn is_connection_of(conn: (&str, &str, [u8; 16]), entry: (&str, &str, Option<[u8; 16]>)) -> bool {
    let (conn_name, conn_book, conn_guid) = conn;
    let (name, book, guid) = entry;
    let zero = |g: &[u8; 16]| g.iter().all(|&b| b == 0);
    if let Some(g) = guid.filter(|g| !zero(g))
        && !zero(&conn_guid)
    {
        return g == conn_guid;
    }
    conn_name == name && (conn_book.is_empty() || same_phonebook(conn_book, book))
}

/// What Windows saved for signing in to an entry (whether a user name and a password are saved).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SavedSignIn {
    pub user: bool,
    pub password: bool,
}

/// How a system VPN is started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Start {
    /// `RasDialW` with the password WinVPN stores for it (and the OTP code), Windows' saved user name.
    Params,
    /// `RasDialW` with what Windows saved (or nothing: a computer-certificate entry needs no password).
    Saved,
    /// Windows' own sign-in window (`RasDialDlgW`): the user types what is missing there.
    Dialog,
}

/// The start of a system VPN: WinVPN's stored password first (when Windows knows the user name to go with it),
/// then Windows' saved credentials, else Windows' sign-in window. `needs_password`: the entry signs in with a
/// user name and password (not a computer certificate).
pub fn how_to_start(needs_password: bool, stored_password: bool, saved: SavedSignIn) -> Start {
    if !needs_password {
        return Start::Saved;
    }
    match (stored_password && saved.user, saved.password) {
        (true, _) => Start::Params,
        (false, true) => Start::Saved,
        (false, false) => Start::Dialog,
    }
}

/// Whether WinVPN writes the PSK the user stored in it for a system VPN into Windows' RAS credential store: only
/// for an L2TP PSK entry, only with a stored PSK, and only when Windows has none saved for that entry (the user's
/// own entry and what Windows keeps for it are never changed; a PSK Windows has is used as it is).
pub fn store_psk(l2tp_psk_entry: bool, stored_in_winvpn: bool, windows_has_one: bool) -> bool {
    l2tp_psk_entry && stored_in_winvpn && !windows_has_one
}

/// A Windows service the VPN client needs: its service name, its English display name and the kinds it serves.
pub struct RasService {
    pub name: &'static str,
    pub display: &'static str,
    pub kinds: &'static [VPNKind],
}

/// The Windows services of the RAS VPNs. They are demand-start services: *stopped* is normal; only *disabled*
/// breaks the kinds they serve.
pub const RAS_SERVICES: &[RasService] = &[
    RasService {
        name: "RasMan",
        display: "Remote Access Connection Manager",
        kinds: &[VPNKind::L2tp, VPNKind::Strongswan, VPNKind::Sstp],
    },
    RasService {
        name: "IKEEXT",
        display: "IKE and AuthIP IPsec Keying Modules",
        kinds: &[VPNKind::L2tp, VPNKind::Strongswan],
    },
    RasService { name: "PolicyAgent", display: "IPsec Policy Agent", kinds: &[VPNKind::L2tp] },
    RasService { name: "SstpSvc", display: "Secure Socket Tunneling Protocol Service", kinds: &[VPNKind::Sstp] },
];

/// The text of a disabled service.
pub fn service_disabled(service: &RasService) -> String {
    let named = format!("{} ({})", service.display, service.name);
    l10n::tr(
        "The Windows service %@ is disabled. An administrator must set it to Manual (services.msc).",
        &[Arg::Str(&named)],
    )
}

/// System Status' Windows VPN client row and the kinds a disabled service makes unavailable (with its text, for
/// `SetupReport::ras_unsupported_kinds`), from `disabled(service name)`: green "Built into Windows" when none is
/// disabled; red with each disabled service's text otherwise. The row stays usable unless `RasMan` (which every
/// RAS connection needs) is disabled.
pub fn ras_row(disabled: impl Fn(&str) -> bool) -> (EngineRow, Vec<(VPNKind, String)>) {
    let mut kinds: Vec<(VPNKind, String)> = Vec::new();
    let mut texts = Vec::new();
    let mut usable = true;
    for service in RAS_SERVICES.iter().filter(|s| disabled(s.name)) {
        let text = service_disabled(service);
        usable &= service.name != "RasMan";
        for kind in service.kinds {
            if !kinds.iter().any(|(k, _)| k == kind) {
                kinds.push((*kind, text.clone()));
            }
        }
        texts.push(text);
    }
    let ok = texts.is_empty();
    let detail = if ok { l10n::tr("Built into Windows", &[]) } else { texts.join(" ") };
    (EngineRow { ok, usable, detail, action: None }, kinds)
}

/// Sets `report`'s one Windows VPN client row from [`ras_row`] (replacing the engine's green row) and adds the
/// kinds a disabled service makes unavailable to `ras_unsupported_kinds`, each kind once (a kind already there,
/// Cisco IPsec, keeps its own reason).
pub fn apply_ras_row(report: &mut SetupReport, disabled: impl Fn(&str) -> bool) {
    let (row, kinds) = ras_row(disabled);
    report.ras = Some(row);
    for (kind, reason) in kinds {
        if report.ras_unsupported_reason(kind).is_none() {
            report.ras_unsupported_kinds.push((kind, reason));
        }
    }
}
