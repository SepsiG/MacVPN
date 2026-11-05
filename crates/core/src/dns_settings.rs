//! Per-connection DNS settings (macOS, root layer 15): the mode (Automatic, Strict, Full, Targeted) and the
//! connection's own DNS servers and domains. Stored in `meta.json` under `dns` (only when not the default, so the
//! file stays byte-identical for every connection that never touched it), and sent to the root layer as optional
//! lines of the `up` frame (`dns-mode=…`, `dns-servers=…`, `dns-domains=…`, `dns-override=1`).
//!
//! Pure: the root helper re-validates every line with the same rules (`accept`), the app validates before saving
//! (`validate`). Linux and Windows store and round-trip the field but never use it.

use crate::l10n::{self, Arg};
use crate::models::VPNKind;
use crate::netaddr::IpPrefix;
use crate::openvpn_routing::{self, Routing};
use crate::validators::SSTPConfig;
use serde_json::{Map, Value};
use std::net::IpAddr;

/// At most this many own (and VPN-sent) DNS servers, the root layer's `Dns::within_limits`.
pub const MAX_SERVERS: usize = 16;
/// At most this many own (and VPN-sent) domains.
pub const MAX_DOMAINS: usize = 32;

/// How the VPN's DNS is put into effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub enum DnsMode {
    /// Every name through the VPN's DNS; when it cannot resolve internet names, only the VPN's domains use it.
    #[default]
    Automatic,
    /// Every name through the VPN's DNS, never a fallback (DNS stays in the tunnel), no local-network entry.
    Strict,
    /// Every name through the VPN's DNS, also when it does not work; the local network's own names stay local.
    Full,
    /// Only the VPN's domains (and reverse zones) use the VPN's DNS.
    Targeted,
}

impl DnsMode {
    pub const ALL: [DnsMode; 4] = [DnsMode::Automatic, DnsMode::Strict, DnsMode::Full, DnsMode::Targeted];

    pub fn raw(self) -> &'static str {
        match self {
            DnsMode::Automatic => "automatic",
            DnsMode::Strict => "strict",
            DnsMode::Full => "full",
            DnsMode::Targeted => "targeted",
        }
    }

    pub fn from_raw(s: &str) -> Option<DnsMode> {
        DnsMode::ALL.into_iter().find(|m| m.raw() == s)
    }
}

/// The connection's own setting (stored in `meta.json` under `dns`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Hash)]
pub struct DnsSetting {
    pub mode: DnsMode,
    /// Own DNS servers (IP literals), used when the VPN sends none, or always with `override_vpn`.
    pub servers: Vec<String>,
    /// Own domains: always match domains of the VPN's DNS (split-horizon names); search domains when the VPN sent
    /// none, or with `override_vpn`. Lower-case, without a trailing dot.
    pub domains: Vec<String>,
    /// "Use these instead of the VPN's DNS": needs at least one own server.
    pub override_vpn: bool,
}

/// An IPv4 or IPv6 literal as `std` reads it (stricter than the hook's shape check: every octet in range).
pub fn is_dns_server(s: &str) -> bool {
    s.parse::<IpAddr>().is_ok()
}

/// A DNS domain as the root layer's search-domain rule has it (one rule for the app and the root layer): letters,
/// digits, `.`, `-`, `_`, starting with a letter, a digit or `_`, at most 253 bytes.
pub fn is_dns_domain(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 253
        && (b[0].is_ascii_alphanumeric() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_'))
}

/// A domain as stored: lower-case, without trailing dots, surrounding blanks trimmed.
pub fn normalize_domain(s: &str) -> String {
    s.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// The JSON array of strings, or `None` for anything else.
fn strings(v: Option<&Value>) -> Option<Vec<String>> {
    match v {
        None | Some(Value::Null) => Some(Vec::new()),
        Some(Value::Array(a)) => a.iter().map(|x| x.as_str().map(str::to_string)).collect(),
        Some(_) => None,
    }
}

fn json_strings(v: &[String]) -> Value {
    Value::Array(v.iter().cloned().map(Value::String).collect())
}

/// The shared list check: every value valid, not too many. The message is the first problem, localized.
fn check_lists(servers: &[String], domains: &[String], override_vpn: bool) -> Result<(), String> {
    if let Some(bad) = servers.iter().find(|s| !is_dns_server(s)) {
        return Err(l10n::tr("Not a valid DNS server address: %@", &[Arg::Str(bad)]));
    }
    if servers.len() > MAX_SERVERS {
        return Err(l10n::tr("At most %ld DNS servers can be set.", &[Arg::Int(MAX_SERVERS as i64)]));
    }
    if let Some(bad) = domains.iter().find(|d| !is_dns_domain(d) || d.ends_with('.')) {
        return Err(l10n::tr("Not a valid domain: %@", &[Arg::Str(bad)]));
    }
    if domains.len() > MAX_DOMAINS {
        return Err(l10n::tr("At most %ld domains can be set.", &[Arg::Int(MAX_DOMAINS as i64)]));
    }
    if override_vpn && servers.is_empty() {
        return Err(l10n::tr("Using your own DNS instead of the VPN's needs at least one DNS server.", &[]));
    }
    Ok(())
}

impl DnsSetting {
    pub fn is_default(&self) -> bool {
        *self == DnsSetting::default()
    }

    /// Lenient, as `otp`: `None` for a value of the wrong shape (the caller then uses the default). An unknown mode
    /// (a newer version's) is Automatic; domains are normalized.
    pub fn from_json(v: &Value) -> Option<DnsSetting> {
        let obj = v.as_object()?;
        let mode = match obj.get("mode") {
            None | Some(Value::Null) => DnsMode::Automatic,
            Some(Value::String(s)) => DnsMode::from_raw(s).unwrap_or_default(),
            Some(_) => return None,
        };
        let servers = strings(obj.get("servers"))?;
        let domains = strings(obj.get("domains"))?.iter().map(|d| normalize_domain(d)).collect();
        let override_vpn = match obj.get("override") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => return None,
        };
        Some(DnsSetting { mode, servers, domains, override_vpn })
    }

    /// `{"mode":…,"servers":[…],"domains":[…],"override":…}` (the caller writes it only when not the default).
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("mode".into(), Value::String(self.mode.raw().into()));
        m.insert("servers".into(), json_strings(&self.servers));
        m.insert("domains".into(), json_strings(&self.domains));
        m.insert("override".into(), Value::Bool(self.override_vpn));
        Value::Object(m)
    }

    /// The editor's check before saving: the localized message of the first problem.
    pub fn validate(&self) -> Result<(), String> {
        check_lists(&self.servers, &self.domains, self.override_vpn)
    }

    /// What the root layer gets; `None` for the default (nothing is sent, the frame stays as before root layer 15).
    pub fn request(&self) -> Option<DnsRequest> {
        (!self.is_default()).then(|| DnsRequest {
            mode: self.mode,
            servers: self.servers.clone(),
            domains: self.domains.clone(),
            override_vpn: self.override_vpn,
        })
    }
}

/// What the root layer gets (frame lines, root layer 15). The default is what an `up` without DNS lines means.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsRequest {
    pub mode: DnsMode,
    pub servers: Vec<String>,
    pub domains: Vec<String>,
    pub override_vpn: bool,
}

/// The frame keys, in the order they are written.
pub const FRAME_KEYS: [&str; 4] = ["dns-mode", "dns-servers", "dns-domains", "dns-override"];

/// A comma-separated list in which every item passes `ok`; empty items or an empty list are refused (the renderer
/// never writes either).
fn list(value: &str, ok: fn(&str) -> bool) -> Option<Vec<String>> {
    let v: Vec<String> = value.split(',').map(str::to_string).collect();
    v.iter().all(|x| ok(x)).then_some(v)
}

impl DnsRequest {
    /// `dns-mode=<m>\n` always; `dns-servers=a,b\n` / `dns-domains=a,b\n` when not empty; `dns-override=1\n` when
    /// set.
    pub fn frame_lines(&self) -> String {
        let mut s = format!("dns-mode={}\n", self.mode.raw());
        if !self.servers.is_empty() {
            s.push_str(&format!("dns-servers={}\n", self.servers.join(",")));
        }
        if !self.domains.is_empty() {
            s.push_str(&format!("dns-domains={}\n", self.domains.join(",")));
        }
        if self.override_vpn {
            s.push_str("dns-override=1\n");
        }
        s
    }

    /// One line's key and value; `false` if invalid (the frame is then refused whole). Duplicates are the caller's
    /// to refuse (the frame parser keeps one "seen" slot per key).
    pub fn accept(&mut self, key: &str, value: &str) -> bool {
        match key {
            "dns-mode" => DnsMode::from_raw(value).map(|m| self.mode = m).is_some(),
            "dns-servers" => list(value, is_dns_server).map(|v| self.servers = v).is_some(),
            "dns-domains" => list(value, |d| is_dns_domain(d) && !d.ends_with('.') && d == d.to_ascii_lowercase())
                .map(|v| self.domains = v)
                .is_some(),
            "dns-override" => match value {
                "1" => {
                    self.override_vpn = true;
                    true
                }
                "0" => {
                    self.override_vpn = false;
                    true
                }
                _ => false,
            },
            _ => false,
        }
    }

    /// The lists within the limits, and `override` only with servers.
    pub fn valid(&self) -> bool {
        check_lists(&self.servers, &self.domains, self.override_vpn).is_ok()
    }

    /// The request from `key=value` lines (the frame's DNS part, or `<run>/dns-request` without the prefix handled
    /// by the caller); `None` on any bad, unknown or repeated line, or an invalid whole.
    pub fn from_frame_lines(text: &str) -> Option<DnsRequest> {
        let mut r = DnsRequest::default();
        let mut seen = [false; FRAME_KEYS.len()];
        for line in text.lines() {
            let (k, v) = line.split_once('=')?;
            let i = FRAME_KEYS.iter().position(|x| *x == k)?;
            if std::mem::replace(&mut seen[i], true) || !r.accept(k, v) {
                return None;
            }
        }
        r.valid().then_some(r)
    }
}

/// `Some(true)` full tunnel, `Some(false)` split, `None`: the server decides (OpenVPN without a local choice) or a
/// kind the DNS manager does not handle. Static, from the stored config; the root layer decides again after
/// connect from the routing table.
pub fn full_tunnel_hint(kind: VPNKind, config: &str) -> Option<bool> {
    match kind {
        VPNKind::Openvpn => match openvpn_routing::read(config) {
            Routing::Always => Some(true),
            Routing::Never => Some(false),
            Routing::ServerDecides => None,
        },
        VPNKind::Wireguard => Some(config.lines().any(|line| {
            let Some((k, v)) = line.split_once('=') else { return false };
            k.trim().eq_ignore_ascii_case("allowedips")
                && v.split(',').filter_map(|a| IpPrefix::parse(a.trim())).any(|p| p.len == 0)
        })),
        VPNKind::Sstp => Some(SSTPConfig::parse(config).route_all),
        _ => None,
    }
}
