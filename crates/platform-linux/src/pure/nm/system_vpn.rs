//! Which NetworkManager profiles are system VPNs, their type labels, states and server addresses (resolved point
//! 14; L-b Task 22). Only NM's own values are read, so every OS tests them.

use crate::pure::nm::state::{ActiveState, VpnState};
use macvpn_core::nm_plan::{
    self, SERVICE_L2TP, SERVICE_OPENVPN, SERVICE_OPENVPN_STOCK, SERVICE_SSTP, SERVICE_STRONGSWAN, SERVICE_VPNC,
};
use std::collections::BTreeMap;

/// `Settings.Connection.Flags` that never make a system VPN: 2 nm-generated, 4 volatile (LinVPN's own or another
/// app's in-memory connection), 8 external (an interface NM did not configure, e.g. `wg-quick`'s).
const NOT_THE_USERS: u32 = 2 | 4 | 8;

/// The label of a profile (`SystemVpn::type_label`; the manager and the UI match on it). Only the plugins macOS
/// has a native kind for get their own label; the stock OpenVPN plugin and WireGuard are "(app)" as on macOS.
pub fn type_label(nm_type: &str, service_type: Option<&str>) -> &'static str {
    if nm_type == "wireguard" {
        return "WireGuard (app)";
    }
    match service_type {
        Some(SERVICE_L2TP) => "L2TP",
        Some(SERVICE_VPNC) => "Cisco IPsec",
        Some(SERVICE_STRONGSWAN) => "IKEv2",
        Some(SERVICE_OPENVPN_STOCK | SERVICE_OPENVPN) => "OpenVPN (app)",
        _ => "VPN",
    }
}

/// `user:<name>` or `user:<name>:` (NM keeps a reserved third field).
fn permits(entry: &str, user: &str) -> bool {
    let Some(rest) = entry.strip_prefix("user:") else { return false };
    rest.strip_suffix(':').unwrap_or(rest) == user
}

/// A saved `vpn` / `wireguard` profile the user can see (`permissions` empty = every user, or naming `user`), not
/// generated, volatile or external, and not one LinVPN made (`linvpn_made`: [`is_linvpn_made`]).
pub fn is_listed(nm_type: &str, permissions: &[String], flags: u32, user: &str, linvpn_made: bool) -> bool {
    matches!(nm_type, "vpn" | "wireguard")
        && flags & NOT_THE_USERS == 0
        && !linvpn_made
        && (permissions.is_empty() || permissions.iter().any(|p| permits(p, user)))
}

/// LinVPN's own connection: its UUID is a derived one (UUIDv8, resolved point 3; no other NM client makes
/// version 8 UUIDs) or its id is a managed service id (`linvpn-…`).
pub fn is_linvpn_made(uuid: &str, id: &str) -> bool {
    uuid::Uuid::parse_str(uuid).is_ok_and(|u| u.get_version_num() == 8)
        || id.starts_with(nm_plan::names::SERVICE_PREFIX)
}

/// `SystemVpn::status` of an active connection: `Connected` only when NM (and, for a VPN, its plugin) says
/// activated; activating or a VPN still in its plugin's steps `Connecting`; `Disconnecting`; else `Disconnected`.
pub fn status(active: ActiveState, vpn: Option<VpnState>) -> &'static str {
    if matches!(vpn, Some(VpnState::Failed | VpnState::Disconnected)) {
        return "Disconnected";
    }
    match (active, vpn) {
        (ActiveState::Activated, None | Some(VpnState::Activated)) => "Connected",
        (ActiveState::Activated | ActiveState::Activating, _) => "Connecting",
        (ActiveState::Deactivating, _) => "Disconnecting",
        (ActiveState::Deactivated | ActiveState::Unknown, _) => "Disconnected",
    }
}

/// The host of `host`, `host:port`, `host:port:proto`, `[v6]:port` or `host port` (a bare IPv6 address stays
/// whole).
fn host_of(item: &str) -> Option<String> {
    let item = item.trim();
    let host = if let Some(rest) = item.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        let first = item.split_whitespace().next().unwrap_or("");
        if first.matches(':').count() > 2 { first } else { first.split(':').next().unwrap_or("") }
    };
    let host = host.trim();
    (!host.is_empty() && !host.chars().any(char::is_control)).then(|| host.to_string())
}

/// The server of a profile from its `vpn.data` (WireGuard: the first peer's `endpoint`, which `NmClient::profiles`
/// puts into `data`): the first of a list (`remote = a.example.com:1194:udp, b.example.com` → `a.example.com`).
pub fn remote_address(service_type: Option<&str>, data: &BTreeMap<String, String>) -> Option<String> {
    let key = match service_type {
        None => "endpoint",
        Some(SERVICE_L2TP | SERVICE_SSTP) => "gateway",
        Some(SERVICE_VPNC) => "IPSec gateway",
        Some(SERVICE_STRONGSWAN) => "address",
        Some(SERVICE_OPENVPN_STOCK | SERVICE_OPENVPN) => "remote",
        Some(_) => return None,
    };
    let value = data.get(key)?;
    value.split(',').find_map(host_of)
}

/// The secret keys of a system VPN's plugin that LinVPN's agent may answer with the stored secrets (L2TP and Cisco,
/// as on macOS): `(password key, PSK key)`.
pub fn secret_keys(service_type: Option<&str>) -> Option<(&'static str, &'static str)> {
    match service_type {
        Some(SERVICE_L2TP) => Some(("password", "ipsec-psk")),
        Some(SERVICE_VPNC) => Some(("Xauth password", "IPSec secret")),
        _ => None,
    }
}
