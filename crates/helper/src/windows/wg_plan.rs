//! A WireGuard config as the WinVPN Service applies it with wireguard-nt and IP Helper: the keys and peers
//! (for [`crate::windows::wg_nt::encode`]) and the adapter's addresses, routes, DNS settings and MTU. Pure.
//!
//! The text is checked by core's validator (the Windows tier: no `FwMark`, `Table` only `auto` or `off`) first and
//! refused on any issue, so every value used here is a validated one. The parser is strict on top of that and
//! refuses what it cannot represent unambiguously: a key that does not decode to exactly 32 bytes, a repeated
//! single-valued key, a peer without a public key, an address `std` cannot read (for example `010.0.0.1`), an
//! endpoint host a resolver would read as a number (`3221225994`, `1.2.3`, `x.0x7f`). Lines are read as the
//! validator reads them (`\n` lines, a trailing `\r` dropped, the comment from `#` cut, space/tab trimmed,
//! case-insensitive keys and section headers).

use crate::shared::l10n::tr;
use crate::shared::limits::SRC_MAX;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use macvpn_core::TargetOs;
use macvpn_core::swift_str::{self, ascii_lowercased, trim_space_tab};
use macvpn_core::validators::WireGuardValidator;
use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use zeroize::Zeroizing;

/// An IP prefix (`Address`, `AllowedIPs`): an address and a length (at most 32 or 128). Without `/n` the full
/// length (wg-quick's rule).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Prefix {
    addr: IpAddr,
    len: u8,
}

impl Prefix {
    /// `a.b.c.d[/n]` or `x:y::z[/n]`; `n` is 1–3 decimal digits not above the family's length.
    pub fn parse(s: &str) -> Result<Prefix, String> {
        let bad = || tr("Invalid value: %@", &[s]);
        let (addr, len) = match s.split_once('/') {
            Some((a, n)) => (a, Some(n)),
            None => (s, None),
        };
        let addr: IpAddr = addr.parse().map_err(|_| bad())?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let len = match len {
            None => max,
            Some(n) if (1..=3).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_digit()) => {
                n.parse::<u8>().ok().filter(|&n| n <= max).ok_or_else(bad)?
            }
            Some(_) => return Err(bad()),
        };
        Ok(Prefix { addr, len })
    }

    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    pub fn prefix_len(&self) -> u8 {
        self.len
    }

    /// The prefix with its host bits cleared (`10.1.2.3/8` → `10.0.0.0/8`).
    pub fn masked(&self) -> Prefix {
        let addr = match self.addr {
            IpAddr::V4(a) => {
                let mask = u32::MAX.checked_shl(32 - u32::from(self.len)).unwrap_or(0);
                IpAddr::V4(Ipv4Addr::from(u32::from(a) & mask))
            }
            IpAddr::V6(a) => {
                let mask = u128::MAX.checked_shl(128 - u32::from(self.len)).unwrap_or(0);
                IpAddr::V6(Ipv6Addr::from(u128::from(a) & mask))
            }
        };
        Prefix { addr, len: self.len }
    }

    /// No host bits set (a route destination as IP Helper takes it).
    pub fn is_canonical(&self) -> bool {
        self.masked() == *self
    }
}

/// A peer's `Endpoint`: an address, or a host name the service resolves once at `up`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    Addr(SocketAddr),
    Host(String, u16),
}

/// A `[Peer]` section. Public keys are not secret; the preshared key is.
pub struct Peer {
    pub public_key: [u8; 32],
    pub preshared_key: Option<Zeroizing<[u8; 32]>>,
    pub endpoint: Option<Endpoint>,
    /// Seconds; `off` and `0` are `None`.
    pub keepalive: Option<u16>,
    /// As written (`wg_nt::encode` and [`Plan::routes`] use them masked).
    pub allowed: Vec<Prefix>,
}

/// The whole config.
pub struct Plan {
    pub private_key: Zeroizing<[u8; 32]>,
    /// `0` (a random port) is `None`.
    pub listen_port: Option<u16>,
    /// The adapter's addresses, host bits kept (`10.0.0.2/24`: the address and its on-link prefix).
    pub addresses: Vec<Prefix>,
    pub dns_servers: Vec<IpAddr>,
    pub dns_search: Vec<String>,
    pub mtu: Option<u32>,
    /// `Table = off`: no routes.
    pub routes_enabled: bool,
    pub peers: Vec<Peer>,
}

impl Plan {
    /// The routes to add: every peer's AllowedIPs, masked, in order, duplicates removed; none for `Table = off`.
    pub fn routes(&self) -> Vec<Prefix> {
        if !self.routes_enabled {
            return Vec::new();
        }
        let mut seen = HashSet::new();
        self.peers.iter().flat_map(|p| p.allowed.iter().map(Prefix::masked)).filter(|p| seen.insert(*p)).collect()
    }
}

impl fmt::Debug for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Peer")
            .field("public_key", &STANDARD.encode(self.public_key))
            .field("preshared_key", &self.preshared_key.as_ref().map(|_| "<redacted>"))
            .field("endpoint", &self.endpoint)
            .field("keepalive", &self.keepalive)
            .field("allowed", &self.allowed)
            .finish()
    }
}

impl fmt::Debug for Plan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Plan")
            .field("private_key", &"<redacted>")
            .field("listen_port", &self.listen_port)
            .field("addresses", &self.addresses)
            .field("dns_servers", &self.dns_servers)
            .field("dns_search", &self.dns_search)
            .field("mtu", &self.mtu)
            .field("routes_enabled", &self.routes_enabled)
            .field("peers", &self.peers)
            .finish()
    }
}

/// A key: standard base64 with its padding, exactly 32 bytes (43 characters and `=`), non-zero trailing bits
/// refused. Decoded straight into a zeroized buffer.
pub fn decode_key(b64: &str) -> Result<Zeroizing<[u8; 32]>, String> {
    let bad = || tr("Invalid value: %@", &["key"]);
    if b64.len() != 44 {
        return Err(bad());
    }
    let mut key = Zeroizing::new([0u8; 32]);
    match STANDARD.decode_slice(b64, key.as_mut_slice()) {
        Ok(32) => Ok(key),
        _ => Err(bad()),
    }
}

/// `1`–`10` decimal digits (the validator's `is_number`) within `lo..=hi`.
fn number(value: &str, lo: u32, hi: u32) -> Option<u32> {
    if !(1..=10).contains(&value.len()) || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse::<u64>().ok().filter(|n| (u64::from(lo)..=u64::from(hi)).contains(n)).map(|n| n as u32)
}

/// A host name the service may resolve: letters, digits, `_`, `-` and dots, at most 253 characters, no empty label
/// (a trailing dot allowed), and a last label that is not a number (`1.2.3`, `3221225994`, `x.0x7f` would be
/// read as IPv4 by `getaddrinfo`'s `inet_aton` rules).
fn is_host_name(host: &str) -> bool {
    let name = host.strip_suffix('.').unwrap_or(host);
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    let label_ok = |l: &str| {
        !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    if !name.split('.').all(label_ok) || name.starts_with('-') {
        return false;
    }
    let last = name.rsplit('.').next().unwrap_or(name);
    let numeric = last.bytes().all(|b| b.is_ascii_digit())
        || (last.len() >= 2
            && last[..2].eq_ignore_ascii_case("0x")
            && last[2..].bytes().all(|b| b.is_ascii_hexdigit()));
    !numeric
}

/// `a.b.c.d:port`, `[v6]:port` or `host:port`, the port 1–65535.
fn parse_endpoint(value: &str) -> Result<Endpoint, String> {
    let bad = || tr("Invalid value: %@", &["endpoint"]);
    if let Some(rest) = value.strip_prefix('[') {
        let (addr, port) = rest.split_once("]:").ok_or_else(bad)?;
        let addr: Ipv6Addr = addr.parse().map_err(|_| bad())?;
        let port = number(port, 1, 65535).ok_or_else(bad)? as u16;
        return Ok(Endpoint::Addr(SocketAddr::V6(SocketAddrV6::new(addr, port, 0, 0))));
    }
    let (host, port) = value.rsplit_once(':').ok_or_else(bad)?;
    let port = number(port, 1, 65535).ok_or_else(bad)? as u16;
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        return Ok(Endpoint::Addr(SocketAddr::from((v4, port))));
    }
    if !is_host_name(host) {
        return Err(bad());
    }
    Ok(Endpoint::Host(host.to_string(), port))
}

fn prefixes(value: &str) -> Result<Vec<Prefix>, String> {
    swift_str::split(value, ",", usize::MAX, false).into_iter().map(|s| Prefix::parse(trim_space_tab(s))).collect()
}

#[derive(Default)]
struct PeerDraft {
    public_key: Option<[u8; 32]>,
    preshared_key: Option<Zeroizing<[u8; 32]>>,
    endpoint: Option<Endpoint>,
    keepalive: Option<u16>,
    allowed: Vec<Prefix>,
}

enum Section {
    None,
    Interface,
    Peer,
}

/// The plan of a WireGuard config (see the module documentation for what is refused). The error is a localized
/// message.
pub fn parse(text: &str) -> Result<Plan, String> {
    if text.len() as u64 > SRC_MAX {
        return Err(tr("The config is too large (1 MB at most)", &[]));
    }
    if let Some(issue) = WireGuardValidator.validate_for(TargetOs::Windows, text).first() {
        return Err(issue.display());
    }
    let mut private_key: Option<Zeroizing<[u8; 32]>> = None;
    let mut listen_port = None;
    let (mut addresses, mut dns_servers, mut dns_search) = (Vec::new(), Vec::new(), Vec::new());
    let (mut mtu, mut routes_enabled) = (None, true);
    let mut interfaces = 0;
    let mut peers: Vec<PeerDraft> = Vec::new();
    let mut section = Section::None;
    // Single-valued keys already seen in the current section.
    let mut seen: HashSet<String> = HashSet::new();
    for raw in text.split('\n') {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        let before_comment = swift_str::split(raw, "#", 1, false).into_iter().next().unwrap_or("");
        let line = trim_space_tab(before_comment);
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            seen.clear();
            section = match ascii_lowercased(line).as_str() {
                "[interface]" => {
                    interfaces += 1;
                    Section::Interface
                }
                "[peer]" => {
                    peers.push(PeerDraft::default());
                    Section::Peer
                }
                _ => return Err(tr("Unknown section", &[])),
            };
            continue;
        }
        let (key, value) = line.split_once('=').ok_or_else(|| tr("Invalid line", &[]))?;
        let key = ascii_lowercased(trim_space_tab(key));
        let value = trim_space_tab(value);
        let invalid = || tr("Invalid value: %@", &[&key]);
        let single = !matches!(key.as_str(), "address" | "dns" | "allowedips");
        if single && !seen.insert(key.clone()) {
            return Err(tr("Duplicate key: %@", &[&key]));
        }
        match (&section, key.as_str()) {
            (Section::Interface, "privatekey") => private_key = Some(decode_key(value)?),
            (Section::Interface, "listenport") => {
                listen_port = Some(number(value, 0, 65535).ok_or_else(invalid)? as u16).filter(|&p| p != 0);
            }
            (Section::Interface, "address") => addresses.extend(prefixes(value)?),
            (Section::Interface, "dns") => {
                for item in swift_str::split(value, ",", usize::MAX, false).into_iter().map(trim_space_tab) {
                    match item.parse::<IpAddr>() {
                        Ok(ip) => dns_servers.push(ip),
                        Err(_) if is_host_name(item) => dns_search.push(item.to_string()),
                        Err(_) => return Err(invalid()),
                    }
                }
            }
            (Section::Interface, "mtu") => mtu = Some(number(value, 576, 9000).ok_or_else(invalid)?),
            (Section::Interface, "table") => {
                routes_enabled = match value {
                    "auto" => true,
                    "off" => false,
                    _ => return Err(tr("Not supported on Windows: %@", &[&key])),
                }
            }
            (Section::Interface, "fwmark") => return Err(tr("Not supported on Windows: %@", &[&key])),
            (Section::Peer, k) => {
                let Some(peer) = peers.last_mut() else { return Err(tr("Key not allowed: %@", &[&key])) };
                match k {
                    "publickey" => peer.public_key = Some(*decode_key(value)?),
                    "presharedkey" => peer.preshared_key = Some(decode_key(value)?),
                    "allowedips" => peer.allowed.extend(prefixes(value)?),
                    "endpoint" => peer.endpoint = Some(parse_endpoint(value)?),
                    "persistentkeepalive" => {
                        peer.keepalive = if value == "off" {
                            None
                        } else {
                            Some(number(value, 0, 65535).ok_or_else(invalid)? as u16).filter(|&k| k != 0)
                        };
                    }
                    _ => return Err(tr("Key not allowed: %@", &[&key])),
                }
            }
            _ => return Err(tr("Key not allowed: %@", &[&key])),
        }
    }
    if interfaces != 1 {
        return Err(tr("Exactly one [Interface] section is required", &[]));
    }
    let private_key = private_key.ok_or_else(|| tr("Missing PrivateKey", &[]))?;
    let no_peer = || tr("At least one [Peer] with a PublicKey is required", &[]);
    if peers.is_empty() {
        return Err(no_peer());
    }
    let peers = peers
        .into_iter()
        .map(|d| {
            Ok(Peer {
                public_key: d.public_key.ok_or_else(no_peer)?,
                preshared_key: d.preshared_key,
                endpoint: d.endpoint,
                keepalive: d.keepalive,
                allowed: d.allowed,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(Plan { private_key, listen_port, addresses, dns_servers, dns_search, mtu, routes_enabled, peers })
}
