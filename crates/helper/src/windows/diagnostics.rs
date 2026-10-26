//! The debug-mode diagnostics of the WinVPN Service (WinVPN 2c, G-6): what macOS' `snapshot` writes with `--debug`
//! (`macos/updown.rs`: the server's resolution, the IPv4 routes, DNS, the interfaces; "diagnostics (before)" and
//! "(after)"), and the WireGuard peer status macOS gets from `wg show` after a connect. Pure: the service core
//! decides when (only in debug mode, see `service::Service::up`), the host reads the system (`sys::diag`, read-only
//! IP Helper calls) and wireguard-nt (`WireGuardGetConfiguration`, decoded by `wg_nt::peer_status`).
//!
//! Nothing here can hold a key: [`PeerStatus`] has no key field, and the snapshot is addresses and names only.
//! Every line still goes through the connection's masked log sink. System strings (adapter names) are untrusted:
//! control characters become spaces, and each list is bounded.

use crate::shared::l10n::tr;
use macvpn_core::models::VPNKind;
use std::net::{IpAddr, SocketAddr};

/// At most this many routes, DNS lines and interfaces each are written (the rest is counted).
pub const MAX_ITEMS: usize = 200;
/// The longest adapter name written.
const MAX_NAME: usize = 128;

/// One IPv4 route of the system's forwarding table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub destination: IpAddr,
    pub prefix_len: u8,
    /// The next hop (`0.0.0.0`: on-link).
    pub next_hop: IpAddr,
    /// The adapter's friendly name (or its LUID when unknown).
    pub interface: String,
    /// The route metric plus the interface metric.
    pub metric: u32,
}

/// One adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub name: String,
    pub up: bool,
    /// (address, on-link prefix length)
    pub addresses: Vec<(IpAddr, u8)>,
}

/// What the host read of the system.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    /// The connection's server as the config names it (`None`: no host found, or not a valid name).
    pub server: Option<String>,
    /// Its addresses (empty: not resolved).
    pub resolved: Vec<IpAddr>,
    pub routes: Vec<Route>,
    /// (adapter, its DNS servers), adapters with DNS servers only.
    pub dns: Vec<(String, Vec<IpAddr>)>,
    pub interfaces: Vec<Interface>,
    /// What could not be read (a fixed English word and the error: for the log).
    pub problems: Vec<String>,
}

/// One WireGuard peer's status after the connect: what `wg show` prints of a peer, without its public or
/// preshared key (and nothing of the interface's).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeerStatus {
    pub endpoint: Option<SocketAddr>,
    /// The latest handshake, Unix seconds (`None`: none yet).
    pub last_handshake: Option<u64>,
    pub rx: u64,
    pub tx: u64,
    pub allowed_ips: usize,
}

/// A system string on one line, bounded.
fn clean(s: &str) -> String {
    s.chars().take(MAX_NAME).map(|c| if c.is_control() { ' ' } else { c }).collect()
}

/// A step header in the macOS shape (`▶ [mvpn] diagnostics (before)`), with WinVPN's tag.
fn step(text: &str) -> String {
    format!("▶ [WinVPN] {text}")
}

fn bounded<T>(items: &[T], mut line: impl FnMut(&T) -> String) -> Vec<String> {
    let mut out: Vec<String> = items.iter().take(MAX_ITEMS).map(&mut line).collect();
    if items.len() > MAX_ITEMS {
        out.push(format!("  … {} more", items.len() - MAX_ITEMS));
    }
    out
}

fn addresses(list: &[IpAddr]) -> String {
    list.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
}

/// The diagnostics block: "▶ [WinVPN] diagnostics (<label>)", then the server's resolution, the IPv4 routes, the
/// DNS servers and the interfaces, one line per route / DNS adapter / interface (as macOS' `dscacheutil`,
/// `netstat -rn -f inet`, `scutil --dns` and `ifconfig -l`).
pub fn snapshot_lines(label: &str, s: &Snapshot) -> Vec<String> {
    let mut out = vec![step(&format!("{} ({label})", tr("diagnostics", &[])))];
    if let Some(server) = &s.server {
        out.push(format!("$ resolve {server}"));
        out.push(if s.resolved.is_empty() {
            "  (not resolved)".to_string()
        } else {
            format!("  {}", addresses(&s.resolved))
        });
    }
    out.push(format!("$ IPv4 routes ({})", s.routes.len()));
    out.extend(bounded(&s.routes, |r| {
        let via = if r.next_hop.is_unspecified() { "on-link".to_string() } else { format!("via {}", r.next_hop) };
        format!("  {}/{} {via} dev {} metric {}", r.destination, r.prefix_len, clean(&r.interface), r.metric)
    }));
    out.push("$ DNS servers".to_string());
    out.extend(bounded(&s.dns, |(name, servers)| format!("  {}: {}", clean(name), addresses(servers))));
    out.push(format!("$ interfaces ({})", s.interfaces.len()));
    out.extend(bounded(&s.interfaces, |i| {
        let state = if i.up { "up" } else { "down" };
        let addrs: Vec<String> = i.addresses.iter().map(|(a, l)| format!("{a}/{l}")).collect();
        if addrs.is_empty() {
            format!("  {} ({state})", clean(&i.name))
        } else {
            format!("  {} ({state}) {}", clean(&i.name), addrs.join(", "))
        }
    }));
    out.extend(s.problems.iter().map(|p| format!("  ({})", clean(p))));
    out
}

/// A byte count as `wg show` writes it (`1.50 KiB`).
pub fn bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64;
    let mut unit = 0;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    format!("{v:.2} {}", UNITS[unit])
}

/// The WireGuard peer status block after a connect (`now`: Unix seconds): one line per peer with its endpoint,
/// latest handshake, transfer and the number of allowed IPs. Never a key.
pub fn peer_lines(adapter: &str, peers: &[PeerStatus], now: u64) -> Vec<String> {
    let mut out = vec![step(&format!("WireGuard peer status ({})", clean(adapter)))];
    out.extend(bounded(peers, |p| {
        let endpoint = p.endpoint.map_or_else(|| "(none)".to_string(), |e| e.to_string());
        let handshake = match p.last_handshake {
            Some(t) => format!("{} s ago", now.saturating_sub(t)),
            None => "none yet".to_string(),
        };
        format!(
            "  peer: endpoint {endpoint}, allowed ips {}, latest handshake {handshake}, transfer {} received, {} sent",
            p.allowed_ips,
            bytes(p.rx),
            bytes(p.tx)
        )
    }));
    if peers.is_empty() {
        out.push("  (no peers)".to_string());
    }
    out
}

/// A server name or address the snapshot may resolve: letters, digits, `.`, `-`, `:` only (macOS' rule).
fn is_server(s: &str) -> bool {
    !s.is_empty() && s.len() <= 253 && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b':' | b'-'))
}

/// The connection's server as macOS' `server_of` finds it: OpenVPN's first `remote` outside an inline block
/// (`<connection>` is not one), WireGuard's first `Endpoint` without its port. `None` when there is none or it is not
/// a plain name or address.
pub fn server_of(kind: VPNKind, config: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(config).ok()?;
    let found = match kind {
        VPNKind::Openvpn => {
            let mut block = String::new();
            let mut found = None;
            for l in text.lines() {
                let t = l.trim();
                if !block.is_empty() {
                    if t == format!("</{block}>") {
                        block.clear();
                    }
                    continue;
                }
                if t.len() > 2
                    && t.starts_with('<')
                    && t.ends_with('>')
                    && t[1..t.len() - 1].bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                    && t != "<connection>"
                {
                    block = t[1..t.len() - 1].to_string();
                    continue;
                }
                let mut fields = t.split([' ', '\t']).filter(|f| !f.is_empty());
                if fields.next().is_some_and(|f| f.eq_ignore_ascii_case("remote")) {
                    found = fields.next().map(str::to_string);
                    break;
                }
            }
            found
        }
        VPNKind::Wireguard => text.lines().find_map(|l| {
            let (key, value) = l.split_once('=')?;
            if !key.trim().eq_ignore_ascii_case("endpoint") {
                return None;
            }
            let v: String = value.chars().filter(|c| !c.is_whitespace()).collect();
            Some(strip_port(&v))
        }),
        _ => None,
    };
    found.filter(|s| is_server(s))
}

/// `host:port` → `host`, `[v6]:port` → `v6`.
fn strip_port(v: &str) -> String {
    if let Some(rest) = v.strip_prefix('[') {
        return rest.split(']').next().unwrap_or_default().to_string();
    }
    match v.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') && port.bytes().all(|b| b.is_ascii_digit()) => host.to_string(),
        _ => v.to_string(),
    }
}
