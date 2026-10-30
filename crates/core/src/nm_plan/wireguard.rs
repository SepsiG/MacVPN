//! WireGuard through NetworkManager's built-in `wireguard` connection type (LinVPN L-b, Task 5).
//!
//! The text is checked by the validator (the Linux tier) first and refused on any issue, so every value read here
//! is a validated one. The parser is strict on top of that (the WinVPN service's `wg_plan` rules): a key that does
//! not decode to exactly 32 bytes, a repeated single-valued key, a peer without a public key, an address `std`
//! cannot read, or an endpoint host a resolver would read as a number is an invalid config. Lines are read as the
//! validator reads them (`\n` lines, a trailing `\r` dropped, the comment from `#` cut, space/tab trimmed,
//! case-insensitive keys and section headers).
//!
//! The private key and every preshared key are [`SecretItem`]s (never in [`NmPlan::settings`]); their flags are
//! `caps.secret_mode.flags()` (a peer's `preshared-key-flags` is set by `lin::nm::value` from
//! [`NmWgPeer::has_preshared_key`]). `Table = <number>` cannot be expressed: NetworkManager routes through its own
//! table.

use super::{
    Input, NmAddress, NmPlan, NmValue, NmWgPeer, SecretItem, SecretKey, SecretValue, Settings, Unsupported,
    connection_section, dns, names,
};
use crate::l10n::{self, Arg};
use crate::models::VPNKind;
use crate::swift_str::{self, ascii_lowercased, trim_space_tab};
use crate::target_os::TargetOs;
use crate::validators::WireGuardValidator;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use zeroize::Zeroizing;

#[derive(Default)]
struct PeerDraft {
    public_key: Option<String>,
    preshared_key: Option<Zeroizing<String>>,
    endpoint: Option<String>,
    keepalive: u32,
    allowed: Vec<String>,
}

#[derive(Default)]
struct Parsed {
    private_key: Option<Zeroizing<String>>,
    v4: Vec<NmAddress>,
    v6: Vec<NmAddress>,
    dns4: Vec<String>,
    dns6: Vec<String>,
    domains: Vec<String>,
    mtu: Option<u32>,
    listen_port: Option<u32>,
    fwmark: Option<u32>,
    peer_routes: bool,
    table: Option<String>,
    peers: Vec<PeerDraft>,
}

enum Section {
    None,
    Interface,
    Peer,
}

pub fn plan(input: &Input) -> Result<NmPlan, Unsupported> {
    let invalid = |m: String| Unsupported::invalid(vec![m]);
    let text = swift_str::string_from_utf8_data(input.config.to_vec())
        .map(Zeroizing::new)
        .ok_or_else(|| invalid(l10n::tr("The config is not UTF-8 text", &[])))?;
    let issues = WireGuardValidator.validate_for(TargetOs::Linux, &text);
    if !issues.is_empty() {
        return Err(Unsupported::invalid(issues.iter().map(|i| i.display()).collect()));
    }
    let p = parse(&text).map_err(invalid)?;
    if let Some(n) = &p.table {
        return Err(Unsupported::linux(vec![l10n::tr(
            "Not supported on Linux: Table = %@ (NetworkManager uses its own routing table)",
            &[Arg::Str(n)],
        )]));
    }
    let private_key = p.private_key.ok_or_else(|| invalid(l10n::tr("Missing PrivateKey", &[])))?;
    let flags = input.caps.secret_mode.flags();
    let c = input.connection;
    let iface = names::iface(names::IFACE_WIREGUARD, &c.id);

    let mut secrets = vec![SecretItem {
        setting: "wireguard",
        key: SecretKey::Plain("private-key".into()),
        value: SecretValue::Literal(private_key),
    }];
    let mut peers = Vec::new();
    let mut full = false;
    for d in p.peers {
        let public_key =
            d.public_key.ok_or_else(|| invalid(l10n::tr("At least one [Peer] with a PublicKey is required", &[])))?;
        full |= d.allowed.iter().any(|a| is_default_route(a));
        let has_preshared_key = d.preshared_key.is_some();
        if let Some(psk) = d.preshared_key {
            secrets.push(SecretItem {
                setting: "wireguard",
                key: SecretKey::WgPeerPsk { public_key: public_key.clone() },
                value: SecretValue::Literal(psk),
            });
        }
        peers.push(NmWgPeer {
            public_key,
            endpoint: d.endpoint,
            allowed_ips: d.allowed,
            persistent_keepalive: d.keepalive,
            has_preshared_key,
        });
    }

    let mut wg = BTreeMap::new();
    wg.insert("private-key-flags".into(), NmValue::U32(flags));
    wg.insert("peers".into(), NmValue::WgPeers(peers));
    if let Some(mtu) = p.mtu {
        wg.insert("mtu".into(), NmValue::U32(mtu));
    }
    if let Some(port) = p.listen_port {
        wg.insert("listen-port".into(), NmValue::U32(port));
    }
    if let Some(mark) = p.fwmark {
        wg.insert("fwmark".into(), NmValue::U32(mark));
    }
    if !p.peer_routes {
        wg.insert("peer-routes".into(), NmValue::Bool(false));
    }

    let mut warnings = Vec::new();
    let ipv4 = ip_section(p.v4, p.dns4, full, &p.domains, &mut warnings);
    let ipv6 = ip_section(p.v6, p.dns6, full, &p.domains, &mut warnings);

    let mut settings = Settings::new();
    settings.insert("connection".into(), connection_section(c, input.uid, input.user, "wireguard", Some(&iface)));
    settings.insert("wireguard".into(), wg);
    settings.insert("ipv4".into(), ipv4);
    settings.insert("ipv6".into(), ipv6);

    let summary = l10n::tr("On Linux: NetworkManager's WireGuard (interface %@)", &[Arg::Str(&iface)]);
    Ok(NmPlan {
        kind: VPNKind::Wireguard,
        service_type: None,
        settings,
        secrets,
        files: Vec::new(),
        iface: Some(iface),
        summary: Some(summary),
        warnings,
    })
}

/// `ipv4` / `ipv6`: `manual` with the addresses of that family, else `disabled` (and that family's DNS servers
/// dropped with a warning: NM has no link to send them over). DNS search domains go to every enabled family.
fn ip_section(
    addresses: Vec<NmAddress>,
    servers: Vec<String>,
    full: bool,
    domains: &[String],
    warnings: &mut Vec<String>,
) -> BTreeMap<String, NmValue> {
    let mut s = BTreeMap::new();
    if addresses.is_empty() {
        s.insert("method".into(), NmValue::Str("disabled".into()));
        for server in servers {
            warnings.push(l10n::tr(
                "Ignored on Linux: DNS = %@ (the connection has no Address of that IP version)",
                &[Arg::Str(&server)],
            ));
        }
        return s;
    }
    s.insert("method".into(), NmValue::Str("manual".into()));
    s.insert("address-data".into(), NmValue::Addresses(addresses));
    s.insert("never-default".into(), NmValue::Bool(!full));
    if !servers.is_empty() {
        s.insert("dns-data".into(), NmValue::StrList(servers));
    }
    s.extend(dns::section_extras(full, domains));
    s
}

/// `0.0.0.0/0` or `::/0` (any spelling `std` reads, `0/0` style prefixes included).
fn is_default_route(allowed: &str) -> bool {
    matches!(allowed.split_once('/'), Some((a, "0")) if a.parse::<IpAddr>().is_ok_and(|ip| ip.is_unspecified()))
}

fn parse(text: &str) -> Result<Parsed, String> {
    let mut p = Parsed { peer_routes: true, ..Parsed::default() };
    let mut interfaces = 0;
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
                    p.peers.push(PeerDraft::default());
                    Section::Peer
                }
                _ => return Err(l10n::tr("Unknown section", &[])),
            };
            continue;
        }
        let (key, value) = line.split_once('=').ok_or_else(|| l10n::tr("Invalid line", &[]))?;
        let key = ascii_lowercased(trim_space_tab(key));
        let value = trim_space_tab(value);
        let bad = || l10n::tr("Invalid value: %@", &[Arg::Str(&key)]);
        let single = !matches!(key.as_str(), "address" | "dns" | "allowedips");
        if single && !seen.insert(key.clone()) {
            return Err(l10n::tr("Duplicate key: %@", &[Arg::Str(&key)]));
        }
        match (&section, key.as_str()) {
            (Section::Interface, "privatekey") => p.private_key = Some(checked_key(value).ok_or_else(bad)?),
            (Section::Interface, "address") => {
                for item in list(value) {
                    let a = address(item).ok_or_else(bad)?;
                    if a.address.contains(':') { p.v6.push(a) } else { p.v4.push(a) }
                }
            }
            (Section::Interface, "dns") => {
                for item in list(value) {
                    match item.parse::<IpAddr>() {
                        Ok(IpAddr::V4(ip)) => p.dns4.push(ip.to_string()),
                        Ok(IpAddr::V6(ip)) => p.dns6.push(ip.to_string()),
                        Err(_) if is_host_name(item) => p.domains.push(item.trim_end_matches('.').to_string()),
                        Err(_) => return Err(bad()),
                    }
                }
            }
            (Section::Interface, "mtu") => p.mtu = Some(number(value, 576, 9000).ok_or_else(bad)?),
            (Section::Interface, "listenport") => {
                p.listen_port = Some(number(value, 0, 65535).ok_or_else(bad)?).filter(|&n| n != 0);
            }
            (Section::Interface, "fwmark") => {
                let v = ascii_lowercased(value);
                let mark = match v.strip_prefix("0x") {
                    _ if v == "off" => 0,
                    Some(hex) if (1..=8).contains(&hex.len()) => u32::from_str_radix(hex, 16).map_err(|_| bad())?,
                    Some(_) => return Err(bad()),
                    None => number(&v, 0, u32::MAX).ok_or_else(bad)?,
                };
                p.fwmark = Some(mark).filter(|&m| m != 0);
            }
            (Section::Interface, "table") => match ascii_lowercased(value).as_str() {
                "auto" => {}
                "off" => p.peer_routes = false,
                n => p.table = Some(number(n, 0, u32::MAX).ok_or_else(bad)?.to_string()),
            },
            (Section::Peer, k) => {
                let Some(peer) = p.peers.last_mut() else {
                    return Err(l10n::tr("Key not allowed: %@", &[Arg::Str(&key)]));
                };
                match k {
                    "publickey" => peer.public_key = Some(checked_key(value).ok_or_else(bad)?.to_string()),
                    "presharedkey" => peer.preshared_key = Some(checked_key(value).ok_or_else(bad)?),
                    "allowedips" => {
                        for item in list(value) {
                            address(item).ok_or_else(bad)?;
                            peer.allowed.push(item.to_string());
                        }
                    }
                    "endpoint" => peer.endpoint = Some(endpoint(value).ok_or_else(bad)?),
                    "persistentkeepalive" => {
                        peer.keepalive = if value == "off" { 0 } else { number(value, 0, 65535).ok_or_else(bad)? };
                    }
                    _ => return Err(l10n::tr("Key not allowed: %@", &[Arg::Str(&key)])),
                }
            }
            _ => return Err(l10n::tr("Key not allowed: %@", &[Arg::Str(&key)])),
        }
    }
    if interfaces != 1 {
        return Err(l10n::tr("Exactly one [Interface] section is required", &[]));
    }
    if p.peers.is_empty() {
        return Err(l10n::tr("At least one [Peer] with a PublicKey is required", &[]));
    }
    Ok(p)
}

fn list(value: &str) -> impl Iterator<Item = &str> {
    swift_str::split(value, ",", usize::MAX, false).into_iter().map(trim_space_tab)
}

/// A key: standard base64 with its padding that decodes to exactly 32 bytes (non-zero trailing bits refused).
/// Returned as written; the decoded bytes are zeroized.
fn checked_key(b64: &str) -> Option<Zeroizing<String>> {
    if b64.len() != 44 {
        return None;
    }
    let mut buf = Zeroizing::new([0u8; 32]);
    matches!(STANDARD.decode_slice(b64, buf.as_mut_slice()), Ok(32)).then(|| Zeroizing::new(b64.to_string()))
}

/// `a.b.c.d[/n]` or `x:y::z[/n]` (without `/n` the full length), the address as `std` prints it.
fn address(s: &str) -> Option<NmAddress> {
    let (a, n) = match s.split_once('/') {
        Some((a, n)) => (a, Some(n)),
        None => (s, None),
    };
    let ip: IpAddr = a.parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = match n {
        None => max,
        Some(n) if (1..=3).contains(&n.len()) => number(n, 0, max)?,
        Some(_) => return None,
    };
    Some(NmAddress { address: ip.to_string(), prefix })
}

/// `1`–`10` decimal digits within `lo..=hi`.
fn number(value: &str, lo: u32, hi: u32) -> Option<u32> {
    if !(1..=10).contains(&value.len()) || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse::<u64>().ok().filter(|n| (u64::from(lo)..=u64::from(hi)).contains(n)).map(|n| n as u32)
}

/// A host name NM may resolve: letters, digits, `_`, `-` and dots, at most 253 characters, no empty label (a
/// trailing dot allowed), and a last label that is not a number (`1.2.3`, `3221225994`, `x.0x7f` would be read as
/// IPv4 by `inet_aton`'s rules).
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

/// `a.b.c.d:port`, `[v6]:port` or `host:port` (port 1–65535), kept as written.
fn endpoint(value: &str) -> Option<String> {
    let ok = if let Some(rest) = value.strip_prefix('[') {
        let (addr, port) = rest.split_once("]:")?;
        addr.parse::<Ipv6Addr>().is_ok() && number(port, 1, 65535).is_some()
    } else {
        let (host, port) = value.rsplit_once(':')?;
        number(port, 1, 65535).is_some() && (host.parse::<Ipv4Addr>().is_ok() || is_host_name(host))
    };
    ok.then(|| value.to_string())
}
