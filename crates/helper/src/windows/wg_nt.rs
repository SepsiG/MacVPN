//! The configuration block `WireGuardSetConfiguration` takes (wireguard-nt's `wireguard.h`, 1.1): a
//! `WIREGUARD_INTERFACE`, then each `WIREGUARD_PEER` followed by its `WIREGUARD_ALLOWED_IP`s. All three structs are
//! `ALIGNED(8)`; little-endian; `SOCKADDR_INET` holds the port in network order. The private and preshared keys are
//! in the buffer: it is `Zeroizing`. Pure; built only from a [`Plan`] (a validated config) and the endpoints the
//! service resolved for it.
//!
//! The offsets (Task 14 checks them with MSVC against the header):
//! - `WIREGUARD_INTERFACE` (80): `Flags` 0 (u32), `ListenPort` 4 (u16), `PrivateKey` 6 (32), `PublicKey` 38 (32),
//!   `PeersCount` 72 (u32).
//! - `WIREGUARD_PEER` (136): `Flags` 0 (u32), `Reserved` 4 (u32), `PublicKey` 8 (32), `PresharedKey` 40 (32),
//!   `PersistentKeepalive` 72 (u16), `Endpoint` 76 (`SOCKADDR_INET`, 28), `TxBytes` 104, `RxBytes` 112,
//!   `LastHandshake` 120 (u64 each), `AllowedIPsCount` 128 (u32).
//! - `WIREGUARD_ALLOWED_IP` (24): `Address` 0 (16: `IN_ADDR` or `IN6_ADDR`), `AddressFamily` 16 (u16), `Cidr` 18 (u8),
//!   `Flags` 20 (u32, `WIREGUARD_ALLOWED_IP_FLAG`, new in 1.1 where 0.10.1 had padding: always 0, "add").

use crate::shared::cli::is_uuid;
use crate::shared::l10n::tr;
use crate::windows::diagnostics::PeerStatus;
use crate::windows::wg_plan::{Endpoint, Plan, Prefix};
use macvpn_core::update::sha256_hex;
use std::net::{IpAddr, SocketAddr};
use zeroize::Zeroizing;

pub const INTERFACE_SIZE: usize = 80;
pub const PEER_SIZE: usize = 136;
pub const ALLOWED_IP_SIZE: usize = 24;
/// The largest block `encode` builds (a 1 MB config stays far below it); larger fails closed.
pub const MAX_BYTES: usize = 8 << 20;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 23;

pub const IF_HAS_PUBLIC_KEY: u32 = 1 << 0;
pub const IF_HAS_PRIVATE_KEY: u32 = 1 << 1;
pub const IF_HAS_LISTEN_PORT: u32 = 1 << 2;
pub const IF_REPLACE_PEERS: u32 = 1 << 3;
pub const PEER_HAS_PUBLIC_KEY: u32 = 1 << 0;
pub const PEER_HAS_PRESHARED_KEY: u32 = 1 << 1;
pub const PEER_HAS_PERSISTENT_KEEPALIVE: u32 = 1 << 2;
pub const PEER_HAS_ENDPOINT: u32 = 1 << 3;
pub const PEER_REPLACE_ALLOWED_IPS: u32 = 1 << 5;
/// `WIREGUARD_PEER_UPDATE_ONLY` (1.1's name of 0.10.1's `WIREGUARD_PEER_UPDATE`): never set (peers are replaced).
pub const PEER_UPDATE_ONLY: u32 = 1 << 7;
/// `WIREGUARD_ALLOWED_IP.Flags` of an allowed IP that is added (1.1; `WIREGUARD_ALLOWED_IP_REMOVE` is `1 << 0`).
pub const ALLOWED_IP_ADD: u32 = 0;

fn put(buf: &mut [u8], at: usize, bytes: &[u8]) {
    buf[at..at + bytes.len()].copy_from_slice(bytes);
}

fn sockaddr_inet(addr: &SocketAddr) -> [u8; 28] {
    let mut s = [0u8; 28];
    match addr {
        SocketAddr::V4(a) => {
            put(&mut s, 0, &AF_INET.to_le_bytes());
            put(&mut s, 2, &a.port().to_be_bytes());
            put(&mut s, 4, &a.ip().octets());
        }
        SocketAddr::V6(a) => {
            put(&mut s, 0, &AF_INET6.to_le_bytes());
            put(&mut s, 2, &a.port().to_be_bytes());
            put(&mut s, 4, &a.flowinfo().to_be_bytes());
            put(&mut s, 8, &a.ip().octets());
            put(&mut s, 24, &a.scope_id().to_le_bytes());
        }
    }
    s
}

/// One allowed IP, host bits cleared.
fn allowed_ip(p: &Prefix) -> [u8; ALLOWED_IP_SIZE] {
    let p = p.masked();
    let mut b = [0u8; ALLOWED_IP_SIZE];
    match p.addr() {
        IpAddr::V4(a) => {
            put(&mut b, 0, &a.octets());
            put(&mut b, 16, &AF_INET.to_le_bytes());
        }
        IpAddr::V6(a) => {
            put(&mut b, 0, &a.octets());
            put(&mut b, 16, &AF_INET6.to_le_bytes());
        }
    }
    b[18] = p.prefix_len();
    // `Flags`: no `WIREGUARD_ALLOWED_IP_REMOVE` (add the allowed IP).
    put(&mut b, 20, &ALLOWED_IP_ADD.to_le_bytes());
    b
}

/// Whether `resolved` is what the service may send for `endpoint`: nothing for no endpoint, the address itself
/// for an address, an address with the same port for a host name.
fn fits(endpoint: Option<&Endpoint>, resolved: Option<&SocketAddr>) -> bool {
    match (endpoint, resolved) {
        (None, None) => true,
        (Some(Endpoint::Addr(a)), Some(r)) => a == r,
        (Some(Endpoint::Host(_, port)), Some(r)) => r.port() == *port,
        _ => false,
    }
}

/// The configuration block. `resolved[i]` is peer `i`'s endpoint as resolved by the service (`None`: the config
/// has no endpoint). Fails closed when `resolved` does not fit the plan (one entry per peer, see [`fits`]) or the
/// block would exceed [`MAX_BYTES`].
pub fn encode(plan: &Plan, resolved: &[Option<SocketAddr>]) -> Result<Zeroizing<Vec<u8>>, String> {
    let bad_endpoint = || tr("Invalid value: %@", &["endpoint"]);
    if resolved.len() != plan.peers.len()
        || !plan.peers.iter().zip(resolved).all(|(p, r)| fits(p.endpoint.as_ref(), r.as_ref()))
    {
        return Err(bad_endpoint());
    }
    let too_large = || tr("The config is too large (1 MB at most)", &[]);
    let total = plan
        .peers
        .iter()
        .try_fold(INTERFACE_SIZE, |sum, p| {
            p.allowed.len().checked_mul(ALLOWED_IP_SIZE)?.checked_add(PEER_SIZE)?.checked_add(sum)
        })
        .filter(|&t| t <= MAX_BYTES)
        .ok_or_else(too_large)?;
    // Both counts are below MAX_BYTES / 24 here.
    let count = |n: usize| u32::try_from(n).map_err(|_| too_large());
    let mut buf = Zeroizing::new(vec![0u8; total]);
    let mut flags = IF_HAS_PRIVATE_KEY | IF_REPLACE_PEERS;
    if let Some(port) = plan.listen_port {
        flags |= IF_HAS_LISTEN_PORT;
        put(&mut buf, 4, &port.to_le_bytes());
    }
    put(&mut buf, 0, &flags.to_le_bytes());
    put(&mut buf, 6, plan.private_key.as_slice());
    put(&mut buf, 72, &count(plan.peers.len())?.to_le_bytes());
    let mut at = INTERFACE_SIZE;
    for (peer, endpoint) in plan.peers.iter().zip(resolved) {
        let mut flags = PEER_HAS_PUBLIC_KEY | PEER_REPLACE_ALLOWED_IPS;
        put(&mut buf, at + 8, &peer.public_key);
        if let Some(psk) = &peer.preshared_key {
            flags |= PEER_HAS_PRESHARED_KEY;
            put(&mut buf, at + 40, psk.as_slice());
        }
        if let Some(k) = peer.keepalive {
            flags |= PEER_HAS_PERSISTENT_KEEPALIVE;
            put(&mut buf, at + 72, &k.to_le_bytes());
        }
        if let Some(addr) = endpoint {
            flags |= PEER_HAS_ENDPOINT;
            put(&mut buf, at + 76, &sockaddr_inet(addr));
        }
        put(&mut buf, at, &flags.to_le_bytes());
        put(&mut buf, at + 128, &count(peer.allowed.len())?.to_le_bytes());
        at += PEER_SIZE;
        for p in &peer.allowed {
            put(&mut buf, at, &allowed_ip(p));
            at += ALLOWED_IP_SIZE;
        }
    }
    debug_assert_eq!(at, total);
    Ok(buf)
}

/// Seconds between 1601-01-01 (`FILETIME`) and 1970-01-01.
const FILETIME_UNIX_OFFSET: u64 = 11_644_473_600;

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// A `SOCKADDR_INET` (28 bytes at `at`; `None`: no address family set).
fn endpoint_at(b: &[u8], at: usize) -> Option<SocketAddr> {
    let s = b.get(at..at + 28)?;
    let port = u16::from_be_bytes([s[2], s[3]]);
    match u16_at(s, 0)? {
        AF_INET => {
            let ip: [u8; 4] = s[4..8].try_into().ok()?;
            Some(SocketAddr::from((ip, port)))
        }
        AF_INET6 => {
            let ip: [u8; 16] = s[8..24].try_into().ok()?;
            Some(SocketAddr::from((ip, port)))
        }
        _ => None,
    }
}

/// The peers' status in a block `WireGuardGetConfiguration` returned (the layout above; debug mode, G-6): endpoint,
/// latest handshake (`FILETIME` → Unix seconds; 0: none yet), received / sent bytes and the number of allowed IPs.
/// It reads no key: the private, public and preshared keys stay in the caller's (zeroized) buffer. A block that is
/// cut short ends the list (fails closed: the peers read so far).
pub fn peer_status(block: &[u8]) -> Vec<PeerStatus> {
    let Some(count) = u32_at(block, 72) else { return Vec::new() };
    let mut out = Vec::new();
    let mut at = INTERFACE_SIZE;
    for _ in 0..count {
        let (Some(tx), Some(rx), Some(handshake), Some(allowed)) =
            (u64_at(block, at + 104), u64_at(block, at + 112), u64_at(block, at + 120), u32_at(block, at + 128))
        else {
            break;
        };
        let Some(next) = (allowed as usize).checked_mul(ALLOWED_IP_SIZE).and_then(|n| n.checked_add(at + PEER_SIZE))
        else {
            break;
        };
        out.push(PeerStatus {
            endpoint: endpoint_at(block, at + 76),
            last_handshake: (handshake != 0).then(|| (handshake / 10_000_000).saturating_sub(FILETIME_UNIX_OFFSET)),
            rx,
            tx,
            allowed_ips: allowed as usize,
        });
        if next > block.len() {
            break;
        }
        at = next;
    }
    out
}

/// The domain separator of the adapter identity hash (a new one gives every connection new adapters).
const IDENTITY_LABEL: &str = "WinVPN wireguard-nt adapter v1\n";

/// SHA-256 of the label and the canonical (upper-case) ID; `None` unless `id` is a hyphenated UUID.
fn identity_hash(id: &str) -> Option<[u8; 32]> {
    if !is_uuid(id) {
        return None;
    }
    let hex = sha256_hex(format!("{IDENTITY_LABEL}{}", id.to_ascii_uppercase()).as_bytes());
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

/// The adapter's name for connection `id`: `WinVPN` and 8 lower-case hex digits of a hash of the ID (letters and
/// digits only; deterministic, and never text a caller chose). `None` unless `id` is a UUID.
pub fn adapter_name(id: &str) -> Option<String> {
    let h = identity_hash(id)?;
    Some(format!("WinVPN{:02x}{:02x}{:02x}{:02x}", h[16], h[17], h[18], h[19]))
}

/// The adapter's GUID for connection `id` (RFC 9562 byte order, version 4 and variant bits set): the first 16 bytes
/// of a hash of the ID. Stable per connection, so Windows keeps one network profile for it, and not the ID itself,
/// so a caller cannot request the GUID of an adapter that already exists. `None` unless `id` is a UUID.
pub fn adapter_guid(id: &str) -> Option<[u8; 16]> {
    let h = identity_hash(id)?;
    let mut g = [0u8; 16];
    g.copy_from_slice(&h[..16]);
    g[6] = (g[6] & 0x0f) | 0x40;
    g[8] = (g[8] & 0x3f) | 0x80;
    Some(g)
}

/// What `SetInterfaceDnsSettings` gets: comma-separated server lists per family (`None`: no server of that family,
/// cleared by [`dns_calls`]) and the search list. Built only from the plan's parsed addresses and validated domain
/// names (no commas in either). No search list without a server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsLists {
    pub v4: Option<String>,
    pub v6: Option<String>,
    pub search: String,
}

pub fn dns_lists(plan: &Plan) -> DnsLists {
    let join = |v6: bool| {
        let list: Vec<String> =
            plan.dns_servers.iter().filter(|a| a.is_ipv6() == v6).map(ToString::to_string).collect();
        (!list.is_empty()).then(|| list.join(","))
    };
    let search = if plan.dns_servers.is_empty() { String::new() } else { plan.dns_search.join(",") };
    DnsLists { v4: join(false), v6: join(true), search }
}

/// One `SetInterfaceDnsSettings` call: the family, its servers (comma-separated; empty clears them) and, when
/// `Some`, the interface's search list (empty clears it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsCall {
    pub ipv6: bool,
    pub servers: String,
    pub search: Option<String>,
}

/// The DNS calls of an `up`: always both families and the search list, empty ones clearing. The adapter's GUID is
/// the same for a connection every time (derived from its ID), and Windows keeps an interface's DNS settings in the
/// registry by GUID after the adapter is gone, so a value an earlier session set (a server or search domain the
/// config no longer has) would come back on the new adapter unless it is overwritten.
pub fn dns_calls(lists: &DnsLists) -> [DnsCall; 2] {
    [
        DnsCall { ipv6: false, servers: lists.v4.clone().unwrap_or_default(), search: Some(lists.search.clone()) },
        DnsCall { ipv6: true, servers: lists.v6.clone().unwrap_or_default(), search: None },
    ]
}

/// A file version as System Status shows it: `major.minor.build`, and `.revision` when it is not 0.
pub fn version_string((major, minor, build, revision): (u16, u16, u16, u16)) -> String {
    if revision == 0 { format!("{major}.{minor}.{build}") } else { format!("{major}.{minor}.{build}.{revision}") }
}
