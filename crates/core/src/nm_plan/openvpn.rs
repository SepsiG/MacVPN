//! OpenVPN through LinVPN's own NetworkManager service (`SERVICE_OPENVPN`, decision 8; L0-1's mapping).
//!
//! The validator runs first, with Linux's tiers (an invalid config is its error, not a Linux limit). Then the
//! config is read the way the validator reads it (top-level directives, inline blocks, `<connection>` blocks) and
//! becomes:
//! - `vpn.data`: only keys NM-openvpn 1.12.5's service accepts (`valid_properties[]` of
//!   `src/nm-openvpn-service.c`; any other key fails the connection) plus the four keys of LinVPN's patch
//!   (`packaging/linux/nm-linvpn-openvpn/`): `linvpn-redirect-gateway` (flags), `linvpn-pull-filter` (lines
//!   `ignore|accept|reject "<text>"`, text `[A-Za-z0-9 _.:/-]{1,64}`, at most 16), `linvpn-route-nopull` (`yes`),
//!   `linvpn-verb` (`0`–`4`, raises OpenVPN's `--verb`);
//! - the inline blocks as [`RuntimeFile`]s, named by `vpn.data` as `<runtime dir>/<file>`;
//! - the profile's routes and DNS as `ipv4`/`ipv6` settings; "Send all traffic over VPN" (resolved points 4, 6
//!   and 7) as `never-default` and the `linvpn-*` keys;
//! - the password, the key password and an inline proxy password as agent secrets (the static challenge needs no
//!   key: the agent answers `password` in the packed form app-core prepared; CRV1 is `challenge-response`,
//!   always asked).
//!
//! The user name is not a secret and not known here (it is a vault field): for `connection-type` `password` /
//! `password-tls` the engine sets `vpn.user-name` and `data.username` from `Secrets::username` (L-b Task 21),
//! unless the config's inline `<auth-user-pass>` block named one (then the plan already did).
//!
//! L0-1's refusals (a server check NM cannot pass, a route past the tunnel, an unflattenable `<connection>`, a
//! `pull-filter` the service cannot pass, `compress stub*`) are [`Unsupported::linux`] reasons: the config stays
//! valid for macOS and Windows. A directive NetworkManager drops is the validator's RISKY finding ("Ignored by
//! NetworkManager on Linux", `platform_reasons(TargetOs::Linux)`), never also a warning here; the warning
//! "Ignored by NetworkManager on Linux: …" names only what the tiers cannot see: arguments (`redirect-gateway
//! block-local`, `dns server … dnssec|transport|sni`) and routes NM cannot express (a host name, a bad mask).

use super::{
    FLAG_NOT_REQUIRED, FLAG_NOT_SAVED, Input, NmPlan, NmRoute, NmValue, RuntimeFile, SERVICE_OPENVPN, SecretItem,
    SecretKey, SecretValue, Unsupported, connection_section, dns, linux_path, names, vpn_section,
};
use crate::l10n::{self, Arg};
use crate::models::{SecretField, VPNKind};
use crate::netaddr::IpPrefix;
use crate::openvpn_routing::{self, Routing};
use crate::swift_str::{ascii_lowercased, trim_space_tab};
use crate::target_os::TargetOs;
use crate::validators::OpenVPNValidator;
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use zeroize::Zeroizing;

/// The inline blocks that become runtime files, in the order of [`NmPlan::files`].
const FILES: [(&str, &str); 10] = [
    ("ca", "ca.pem"),
    ("cert", "cert.pem"),
    ("key", "key.pem"),
    ("pkcs12", "pkcs12.p12"),
    ("extra-certs", "extra-certs.pem"),
    ("crl-verify", "crl.pem"),
    ("tls-auth", "tls-auth.key"),
    ("tls-crypt", "tls-crypt.key"),
    ("tls-crypt-v2", "tls-crypt-v2.key"),
    ("secret", "static.key"),
];

/// The directives a `<connection>` block may hold to be flattened into the `remote` list.
const FLATTENABLE: [&str; 4] = ["remote", "proto", "port", "nobind"];

/// The service's `linvpn-pull-filter` limits (`linvpn_args_add` in the patch).
const MAX_PULL_FILTERS: usize = 16;

/// What the config holds, in order (the validator's reading).
enum Item {
    Directive(Vec<String>),
    Block(String, Zeroizing<String>),
    Connection { directives: Vec<Vec<String>>, has_block: bool },
}

fn is_open_tag(line: &str) -> bool {
    line.len() > 2
        && line.starts_with('<')
        && line.ends_with('>')
        && line[1..line.len() - 1].bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// A directive line's tokens, the name normalized (lower-case, no `--`), `setenv opt` unwrapped once (as OpenVPN
/// does). `None`: a line the tokenizer rejects (the validator has refused it already).
fn directive(line: &str) -> Option<Vec<String>> {
    let mut tokens: Vec<String> = OpenVPNValidator::tokenize(line)?.into_iter().map(|t| t.text).collect();
    tokens[0] = OpenVPNValidator::directive_name(tokens.first()?)?;
    if tokens[0] == "setenv" && tokens.len() >= 3 && ascii_lowercased(&tokens[1]) == "opt" {
        tokens.drain(..2);
        tokens[0] = OpenVPNValidator::directive_name(&tokens[0])?;
    }
    Some(tokens)
}

/// The config's items, read as `OpenVPNValidator::validate_full_for` reads it (blocks, comments, `<connection>`).
fn scan(text: &str) -> Vec<Item> {
    let mut items = Vec::new();
    let mut block: Option<(String, Zeroizing<String>)> = None;
    let mut connection: Option<(Vec<Vec<String>>, bool)> = None;
    let mut nested_block = false;
    for raw in text.split('\n') {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        let line = trim_space_tab(raw);
        if nested_block {
            nested_block = !line.starts_with("</");
            continue;
        }
        if let Some((name, content)) = &mut block {
            if line.starts_with("</") {
                items.push(Item::Block(std::mem::take(name), std::mem::take(content)));
                block = None;
            } else {
                content.push_str(line);
                content.push('\n');
            }
            continue;
        }
        if let Some((directives, has_block)) = &mut connection {
            if line.starts_with("</") {
                items.push(Item::Connection { directives: std::mem::take(directives), has_block: *has_block });
                connection = None;
            } else if is_open_tag(line) {
                *has_block = true;
                nested_block = true;
            } else if !line.is_empty() && !line.starts_with('#') && !line.starts_with(';') {
                directives.extend(directive(line));
            }
            continue;
        }
        if is_open_tag(line) {
            let name = ascii_lowercased(&line[1..line.len() - 1]);
            if name == "connection" {
                connection = Some((Vec::new(), false));
            } else {
                block = Some((name, Zeroizing::new(String::new())));
            }
            continue;
        }
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(tokens) = directive(line) {
            items.push(Item::Directive(tokens));
        }
    }
    items
}

/// `udp`, `tcp`, … as NM-openvpn's `remote` list writes them (`tcp-client` is `tcp`).
fn normalize_proto(p: &str) -> String {
    let p = ascii_lowercased(p);
    p.strip_suffix("-client").map(str::to_string).unwrap_or(p)
}

/// One `remote` with its own and its `<connection>` block's port and proto (the profile-wide ones are known only
/// at the end: OpenVPN applies `port`/`proto` wherever they stand).
struct Remote {
    host: String,
    port: Option<String>,
    proto: Option<String>,
}

#[derive(Default)]
struct Reader {
    data: BTreeMap<String, String>,
    reasons: Vec<String>,
    ignored: BTreeSet<String>,
    remotes: Vec<Remote>,
    port: Option<String>,
    proto: Option<String>,
    blocks: BTreeMap<String, Zeroizing<String>>,
    auth_user_pass: bool,
    key_direction: Option<String>,
    tls_auth_direction: Option<String>,
    secret_direction: Option<String>,
    dev_kind: Option<String>,
    dev_type: Option<String>,
    redirect: Option<Vec<String>>,
    pull_filters: Vec<String>,
    route_nopull: bool,
    routes4: Vec<NmRoute>,
    routes6: Vec<NmRoute>,
    route_metric: Option<i64>,
    dns4: Vec<String>,
    dns6: Vec<String>,
    domains: Vec<String>,
}

fn reason_server_check(name: &str) -> String {
    l10n::tr(
        "Not supported on Linux: %@ (NetworkManager cannot check the server this way; use a CA)",
        &[Arg::Str(name)],
    )
}

fn reason_route(route: &str) -> String {
    l10n::tr("Not supported on Linux: a route outside the tunnel (%@)", &[Arg::Str(route)])
}

fn reason_pull_filter(filter: &str) -> String {
    l10n::tr("Not supported on Linux: pull-filter %@", &[Arg::Str(filter)])
}

/// The service's text rule for a `pull-filter` (`linvpn_text_ok`): `^[A-Za-z0-9 _.:/-]{1,64}$`.
fn pull_filter_text_ok(text: &str) -> bool {
    (1..=64).contains(&text.len())
        && text.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b' ' | b'_' | b'.' | b':' | b'/' | b'-'))
}

/// An address of `dhcp-option DNS` or `dns server … address` (OpenVPN 2.6: `addr`, `addr:port`, `[v6]:port`).
fn dns_address(s: &str) -> Option<IpAddr> {
    if let Some(rest) = s.strip_prefix('[') {
        return rest.split_once(']')?.0.parse().ok();
    }
    s.parse().ok().or_else(|| s.rsplit_once(':').and_then(|(a, _)| a.parse::<Ipv4Addr>().ok().map(IpAddr::V4)))
}

impl Reader {
    fn set(&mut self, key: &str, value: impl Into<String>) {
        self.data.insert(key.into(), value.into());
    }

    fn refuse(&mut self, reason: String) {
        if !self.reasons.contains(&reason) {
            self.reasons.push(reason);
        }
    }

    fn add_dns(&mut self, addr: IpAddr) {
        let list = if addr.is_ipv4() { &mut self.dns4 } else { &mut self.dns6 };
        let s = addr.to_string();
        if !list.contains(&s) {
            list.push(s);
        }
    }

    fn add_domain(&mut self, d: String) {
        if !self.domains.contains(&d) {
            self.domains.push(d);
        }
    }

    fn connection(&mut self, directives: &[Vec<String>], has_block: bool) {
        if has_block || directives.iter().any(|d| !FLATTENABLE.contains(&d[0].as_str())) {
            self.refuse(l10n::tr(
                "Not supported on Linux: a <connection> block with settings other than remote, proto, port and nobind",
                &[],
            ));
            return;
        }
        let port = directives.iter().rev().find(|d| d[0] == "port").and_then(|d| d.get(1)).cloned();
        let proto =
            directives.iter().rev().find(|d| d[0] == "proto").and_then(|d| d.get(1)).map(|p| normalize_proto(p));
        for d in directives.iter().filter(|d| d[0] == "remote") {
            self.remote(d, port.clone(), proto.clone());
        }
    }

    fn remote(&mut self, d: &[String], port: Option<String>, proto: Option<String>) {
        let Some(host) = d.get(1) else { return };
        self.remotes.push(Remote {
            host: host.clone(),
            port: d.get(2).cloned().or(port),
            proto: d.get(3).map(|p| normalize_proto(p)).or(proto),
        });
    }

    /// `route network [netmask] [gateway] [metric]` (OpenVPN's defaults: a host route into the tunnel).
    fn route(&mut self, d: &[String]) {
        let arg = |i: usize| d.get(i).map(String::as_str);
        let outside = |s: Option<&str>| matches!(s, Some("net_gateway" | "remote_host"));
        if outside(arg(1)) || outside(arg(3)) {
            self.refuse(reason_route(&d[1..].join(" ")));
            return;
        }
        let Ok(network) = d[1].parse::<Ipv4Addr>() else {
            // A host name (OpenVPN resolves it) or `vpn_gateway` as the network: NM routes take addresses.
            self.ignored.insert("route".into());
            return;
        };
        let netmask = match arg(2) {
            None | Some("default") => Ipv4Addr::BROADCAST,
            Some(m) => match m.parse() {
                Ok(m) => m,
                Err(_) => {
                    self.ignored.insert("route".into());
                    return;
                }
            },
        };
        let next_hop = match arg(3) {
            None | Some("vpn_gateway" | "default") => None,
            Some(g) => match g.parse::<Ipv4Addr>() {
                Ok(g) => Some(g.to_string()),
                Err(_) => {
                    self.ignored.insert("route".into());
                    return;
                }
            },
        };
        let Some(prefix) = IpPrefix::from_mask(network, netmask) else {
            self.ignored.insert("route".into());
            return;
        };
        if prefix.len == 0 {
            // A default route of the profile reaches NM through the plugin, where `never-default` filters it.
            return;
        }
        let metric = arg(4).and_then(|m| m.parse().ok());
        self.routes4.push(NmRoute { dest: prefix.addr.to_string(), prefix: prefix.len.into(), next_hop, metric });
    }

    /// `route-ipv6 network/len [gateway] [metric]`.
    fn route_ipv6(&mut self, d: &[String]) {
        let gateway = d.get(2).map(String::as_str);
        if matches!(gateway, Some("net_gateway" | "remote_host")) {
            self.refuse(reason_route(&d[1..].join(" ")));
            return;
        }
        let Some(prefix) = IpPrefix::parse(&d[1]).filter(|p| p.addr.is_ipv6()) else {
            self.ignored.insert("route-ipv6".into());
            return;
        };
        if prefix.len == 0 {
            return;
        }
        let next_hop = gateway.and_then(|g| g.parse::<std::net::Ipv6Addr>().ok()).map(|g| g.to_string());
        let metric = d.get(3).and_then(|m| m.parse().ok());
        self.routes6.push(NmRoute { dest: prefix.addr.to_string(), prefix: prefix.len.into(), next_hop, metric });
    }

    fn dhcp_option(&mut self, d: &[String]) {
        let value = d.get(2).cloned().unwrap_or_default();
        match ascii_lowercased(&d[1]).as_str() {
            "dns" | "dns6" => {
                if let Some(a) = dns_address(&value) {
                    self.add_dns(a);
                }
            }
            "domain" | "domain-search" if !value.is_empty() => self.add_domain(value),
            // WINS, NBDD, NTP, NBT, NBS, DISABLE-NBT, PROXY_*, ADAPTER_DOMAIN_SUFFIX: Windows only.
            _ => {}
        }
    }

    /// OpenVPN 2.6's `dns search-domains d…` and `dns server n address|resolve-domains …`.
    fn dns(&mut self, d: &[String]) {
        match ascii_lowercased(&d[1]).as_str() {
            "search-domains" => d[2..].iter().for_each(|x| self.add_domain(x.clone())),
            "server" if d.len() >= 4 => match ascii_lowercased(&d[3]).as_str() {
                "address" => d[4..].iter().filter_map(|a| dns_address(a)).for_each(|a| self.add_dns(a)),
                "resolve-domains" => d[4..].iter().for_each(|x| self.add_domain(format!("~{x}"))),
                // `dnssec`, `transport`, `sni`: NetworkManager's DNS settings have no per-server equivalent.
                other => {
                    self.ignored.insert(format!("dns server … {other}"));
                }
            },
            _ => {
                self.ignored.insert("dns".into());
            }
        }
    }

    fn directive(&mut self, d: &[String]) {
        let name = d[0].as_str();
        let arg = |i: usize| d.get(i).cloned();
        let yes = "yes";
        match name {
            "remote" => self.remote(d, None, None),
            "proto" => self.proto = arg(1).map(|p| normalize_proto(&p)),
            "port" | "rport" => self.port = arg(1),
            "float"
            | "remote-random"
            | "remote-random-hostname"
            | "tun-ipv6"
            | "allow-pull-fqdn"
            | "push-peer-info"
            | "ncp-disable" => self.set(name, yes),
            // `server-poll-timeout` is `connect-timeout`'s new name (OpenVPN 2.4).
            "connect-timeout" | "server-poll-timeout" => {
                if let Some(v) = arg(1) {
                    self.set("connect-timeout", v);
                }
            }
            // OpenVPN types a device by its name's prefix unless `dev-type` says it.
            "dev" => self.dev_kind = arg(1).map(|v| if v.starts_with("tap") { "tap".into() } else { "tun".into() }),
            "dev-type" => self.dev_type = arg(1),
            "auth"
            | "cipher"
            | "data-ciphers-fallback"
            | "tls-cipher"
            | "tls-version-max"
            | "remote-cert-tls"
            | "ns-cert-type"
            | "allow-compression"
            | "mtu-disc"
            | "ping"
            | "ping-exit"
            | "ping-restart" => {
                if let Some(v) = arg(1) {
                    self.set(name, v);
                }
            }
            "keysize" => {
                if let Some(v) = arg(1).filter(|v| v.parse::<u16>().is_ok_and(|n| n >= 1)) {
                    self.set(name, v);
                }
            }
            "data-ciphers" | "ncp-ciphers" => {
                if let Some(v) = arg(1) {
                    self.set("data-ciphers", v);
                }
            }
            "tls-version-min" => {
                if let Some(v) = arg(1) {
                    self.set(name, v);
                    if arg(2).as_deref() == Some("or-highest") {
                        self.set("tls-version-min-or-highest", yes);
                    } else {
                        self.data.remove("tls-version-min-or-highest");
                    }
                }
            }
            "verify-x509-name" => {
                if let Some(v) = arg(1) {
                    let kind = arg(2).unwrap_or_else(|| "subject".into());
                    self.set(name, format!("{kind}:{v}"));
                }
            }
            "reneg-sec" => {
                if let Some(v) = arg(1) {
                    self.set("reneg-seconds", v);
                }
            }
            "tun-mtu" => {
                if let Some(v) = arg(1) {
                    self.set("tunnel-mtu", v);
                }
            }
            "fragment" => {
                if let Some(v) = arg(1) {
                    self.set("fragment-size", v);
                }
            }
            "mssfix" => self.set(name, arg(1).unwrap_or_else(|| yes.into())),
            "keepalive" => {
                if let (Some(a), Some(b)) = (arg(1), arg(2)) {
                    self.set("ping", a);
                    self.set("ping-restart", b);
                }
            }
            "max-routes" => {
                if let Some(v) = arg(1) {
                    self.set(name, v);
                }
            }
            // NM-openvpn: `comp-lzo=no` means "no option" (old plasma-nm); `no-by-default` is `--comp-lzo no`.
            "comp-lzo" => {
                let v = match arg(1).as_deref() {
                    Some("yes") => "yes",
                    Some("no") => "no-by-default",
                    _ => "adaptive",
                };
                self.set(name, v);
            }
            "compress" => match arg(1).as_deref() {
                None => self.set(name, yes),
                Some(v @ ("lzo" | "lz4" | "lz4-v2")) => self.set(name, v),
                Some(v) => {
                    let reason = l10n::tr("Not supported on Linux: compress %@", &[Arg::Str(v)]);
                    self.refuse(reason);
                }
            },
            "http-proxy" | "socks-proxy" => {
                self.set("proxy-type", if name == "http-proxy" { "http" } else { "socks" });
                if let Some(v) = arg(1) {
                    self.set("proxy-server", v);
                }
                match arg(2) {
                    Some(p) => self.set("proxy-port", p),
                    None => {
                        self.data.remove("proxy-port");
                    }
                }
            }
            "http-proxy-retry" | "socks-proxy-retry" => self.set("proxy-retry", yes),
            "ifconfig" => {
                if let (Some(l), Some(r)) = (arg(1), arg(2)) {
                    self.set("local-ip", l);
                    self.set("remote-ip", r);
                }
            }
            "route" if d.len() >= 2 => self.route(d),
            "route-ipv6" if d.len() >= 2 => self.route_ipv6(d),
            "route-metric" => self.route_metric = arg(1).and_then(|m| m.parse().ok()),
            "dhcp-option" if d.len() >= 2 => self.dhcp_option(d),
            "dns" if d.len() >= 3 => self.dns(d),
            "redirect-gateway" => {
                if d[1..].iter().any(|f| ascii_lowercased(f) == "block-local") {
                    // LinVPN's service routes it as a plain full tunnel (L0-1b: NM has no such primitive).
                    self.ignored.insert("redirect-gateway block-local".into());
                }
                self.redirect = Some(d[1..].to_vec());
            }
            "route-nopull" => self.route_nopull = true,
            "pull-filter" if d.len() == 3 => {
                let line = format!("{} \"{}\"", d[1], d[2]);
                let passable = ["ignore", "accept", "reject"].contains(&d[1].as_str()) && pull_filter_text_ok(&d[2]);
                if passable && self.pull_filters.len() < MAX_PULL_FILTERS {
                    self.pull_filters.push(line);
                } else {
                    self.refuse(reason_pull_filter(&line));
                }
            }
            "verb" => {
                if let Some(v) = arg(1).and_then(|v| v.parse::<u8>().ok()) {
                    self.set("linvpn-verb", v.min(4).to_string());
                }
            }
            "peer-fingerprint" | "verify-hash" => self.refuse(reason_server_check(name)),
            "remote-cert-ku" | "remote-cert-eku" => self.refuse(l10n::tr(
                "Not supported on Linux: %@ (NetworkManager cannot pass this server check)",
                &[Arg::Str(name)],
            )),
            "auth-user-pass" => self.auth_user_pass = true,
            "key-direction" => self.key_direction = arg(1),
            "tls-auth" => self.tls_auth_direction = arg(2),
            "secret" => self.secret_direction = arg(2),
            // The other blocks' `[inline]` directives: the blocks themselves carry the content.
            "ca"
            | "cert"
            | "key"
            | "pkcs12"
            | "extra-certs"
            | "crl-verify"
            | "tls-crypt"
            | "tls-crypt-v2"
            | "dh"
            | "http-proxy-user-pass" => {}
            // Every other name maps to nothing and needs no note here: the validator already reports the ones
            // NetworkManager drops (`platform_reasons(TargetOs::Linux)`, RISKY "Ignored by NetworkManager on
            // Linux", acknowledged by the user) and unknown ones (RISKY), so a warning would say it twice; the
            // names it keeps SAFE on Linux (`nobind`, `persist-tun`, `lport 0`, the Windows-only options, …) are
            // no-ops under NetworkManager (Task 6's table). Only arguments the tiers cannot see are warned about.
            _ => {}
        }
    }

    fn block(&mut self, name: String, content: Zeroizing<String>) {
        match name.as_str() {
            "peer-fingerprint" | "verify-hash" => self.refuse(reason_server_check(&name)),
            "auth-user-pass" => {
                self.auth_user_pass = true;
                self.blocks.insert(name, content);
            }
            _ => {
                self.blocks.insert(name, content);
            }
        }
    }
}

/// The first two lines of an inline credentials block (user name, password).
fn credentials(block: &str) -> (String, Zeroizing<String>) {
    let mut lines = block.lines();
    let user = lines.next().unwrap_or("").to_string();
    (user, Zeroizing::new(lines.next().unwrap_or("").to_string()))
}

/// The file's content: the block's lines (space/tab-trimmed, as the validator reads them, one `\n` each).
/// `<pkcs12>` is base64 in the config and DER on disk (OpenVPN decodes it the same way; an undecodable block is
/// written as is and fails as it would anywhere).
fn file_data(block: &str, content: &Zeroizing<String>) -> Zeroizing<Vec<u8>> {
    if block == "pkcs12" {
        let compact: Zeroizing<String> = Zeroizing::new(content.chars().filter(|c| !c.is_ascii_whitespace()).collect());
        if let Some(der) = crate::swift_base64::decode(&compact) {
            return Zeroizing::new(der);
        }
    }
    Zeroizing::new(content.as_bytes().to_vec())
}

fn path_in(dir: &Path, file: &str) -> String {
    linux_path(dir, &[file])
}

pub fn plan(input: &Input) -> Result<NmPlan, Unsupported> {
    let text = std::str::from_utf8(input.config)
        .map_err(|_| Unsupported::invalid(vec![l10n::tr("The config is not UTF-8 text", &[])]))?;
    let text = text.strip_prefix('\u{FEFF}').unwrap_or(text);
    let acknowledged: HashSet<String> = input.connection.acknowledged_risky_directives.iter().cloned().collect();
    let validation = OpenVPNValidator.validate_full_for(TargetOs::Linux, text, &acknowledged);
    if !validation.issues.is_empty() {
        return Err(Unsupported::invalid(validation.issues.iter().map(|i| i.display()).collect()));
    }

    let mut r = Reader::default();
    for item in scan(text) {
        match item {
            Item::Directive(d) => r.directive(&d),
            Item::Block(name, content) => r.block(name, content),
            Item::Connection { directives, has_block } => r.connection(&directives, has_block),
        }
    }
    if !r.reasons.is_empty() {
        return Err(Unsupported::linux(r.reasons));
    }

    let caps = input.caps;
    let flags = caps.secret_mode.flags().to_string();
    let mut secrets = Vec::new();
    let mut user_name = None;

    // Transport: every remote with its port and proto spelled out (the profile-wide ones, then OpenVPN's).
    let port = r.port.clone().unwrap_or_else(|| "1194".into());
    let proto = r.proto.clone().unwrap_or_else(|| "udp".into());
    let remote = r
        .remotes
        .iter()
        .map(|x| {
            let host =
                if x.host.parse::<std::net::Ipv6Addr>().is_ok() { format!("[{}]", x.host) } else { x.host.clone() };
            format!("{host}:{}:{}", x.port.as_deref().unwrap_or(&port), x.proto.as_deref().unwrap_or(&proto))
        })
        .collect::<Vec<_>>()
        .join(", ");
    r.set("remote", remote);
    let iface = names::iface(names::IFACE_OPENVPN, &input.connection.id);
    r.set("dev", iface.clone());
    // LinVPN's name (resolved point 16) tells OpenVPN nothing: the type is always explicit.
    let dev_type = r.dev_type.clone().or_else(|| r.dev_kind.clone()).unwrap_or_else(|| "tun".into());
    r.set("dev-type", dev_type);

    // Files and the connection type.
    let mut files = Vec::new();
    for (block, file) in FILES {
        let Some(content) = r.blocks.get(block) else { continue };
        files.push(RuntimeFile { name: file.into(), data: file_data(block, content) });
        let path = path_in(input.runtime_dir, file);
        match block {
            "ca" | "cert" | "key" | "extra-certs" | "tls-crypt" | "tls-crypt-v2" => r.set(block, path),
            "pkcs12" => {
                if !r.blocks.contains_key("cert") {
                    r.set("cert", path);
                }
            }
            "crl-verify" => r.set("crl-verify-file", path),
            "tls-auth" => {
                r.set("ta", path);
                if let Some(dir) = r.tls_auth_direction.clone().or_else(|| r.key_direction.clone()) {
                    r.set("ta-dir", dir);
                }
            }
            "secret" => {
                r.set("static-key", path);
                if let Some(dir) = r.secret_direction.clone().or_else(|| r.key_direction.clone()) {
                    r.set("static-key-direction", dir);
                }
            }
            _ => {}
        }
    }
    let static_key = r.blocks.contains_key("secret");
    let has_cert = r.blocks.contains_key("cert") || r.blocks.contains_key("pkcs12");
    let connection_type = match (static_key, has_cert, r.auth_user_pass) {
        (true, _, _) => "static-key",
        (false, true, true) => "password-tls",
        (false, false, true) => "password",
        (false, _, false) => "tls",
    };
    r.set("connection-type", connection_type);
    if !static_key {
        r.data.entry("reneg-seconds".into()).or_insert_with(|| "3600".into());
    }

    // Secrets (resolved point 8): the password (packed by app-core for a static challenge), CRV1's response
    // (always asked), the key password, an inline proxy password.
    if r.auth_user_pass && !static_key {
        r.set("password-flags", flags.clone());
        r.set("challenge-response-flags", FLAG_NOT_SAVED.to_string());
        let value = match r.blocks.get("auth-user-pass") {
            Some(block) => {
                let (user, password) = credentials(block);
                if !user.is_empty() {
                    r.set("username", user.clone());
                    user_name = Some(user);
                }
                SecretValue::Literal(password)
            }
            None => SecretValue::Field(SecretField::Password),
        };
        secrets.push(SecretItem { setting: "vpn", key: SecretKey::Plain("password".into()), value });
    }
    // The key password only when the key needs one (the connect prompt's rule): an encrypted PEM `<key>`, or a
    // `<pkcs12>` that does not open with an empty password (or cannot be checked). An unprotected key (pfSense's
    // "Archive" PKCS#12, a plain PEM key, also with a bare `askpass`) is NOT_REQUIRED: an agent-owned `cert-pass`
    // with no value ends in NO_SECRETS or GNOME's password dialog.
    let client_key = r.blocks.contains_key("key") || r.blocks.contains_key("pkcs12");
    if !static_key && client_key {
        if crate::certificates::openvpn_key_needs_password(text) {
            r.set("cert-pass-flags", flags.clone());
            secrets.push(SecretItem {
                setting: "vpn",
                key: SecretKey::Plain("cert-pass".into()),
                value: SecretValue::Field(SecretField::KeyPassword),
            });
        } else {
            r.set("cert-pass-flags", FLAG_NOT_REQUIRED.to_string());
        }
    }
    if let Some(block) = r.blocks.get("http-proxy-user-pass").filter(|_| r.data.contains_key("proxy-type")) {
        let (user, password) = credentials(block);
        r.set("http-proxy-username", user);
        r.set("http-proxy-password-flags", flags.clone());
        secrets.push(SecretItem {
            setting: "vpn",
            key: SecretKey::Plain("http-proxy-password".into()),
            value: SecretValue::Literal(password),
        });
    }

    // Routing (resolved points 4, 6 and 7).
    let routing = openvpn_routing::read(text);
    if routing != Routing::Never
        && let Some(flags) = &r.redirect
    {
        let flags = if flags.is_empty() { "def1".to_string() } else { flags.join(" ") };
        r.set("linvpn-redirect-gateway", flags);
    }
    if !r.pull_filters.is_empty() {
        let lines = r.pull_filters.join("\n");
        r.set("linvpn-pull-filter", lines);
    }
    if r.route_nopull {
        r.set("linvpn-route-nopull", "yes");
    }
    let redirect_ipv6 = r.redirect.as_ref().is_some_and(|f| f.iter().any(|x| x == "ipv6"));
    let (never4, never6) = match (caps.openvpn_push_visible, routing) {
        (_, Routing::Never) => (true, true),
        (true, _) => (false, false),
        (false, Routing::Always) => (false, !redirect_ipv6),
        (false, Routing::ServerDecides) => (true, true),
    };
    let full = routing == Routing::Always;

    let mut ipv4 = BTreeMap::new();
    let mut ipv6 = BTreeMap::new();
    for (s, never) in [(&mut ipv4, never4), (&mut ipv6, never6)] {
        s.insert("method".to_string(), NmValue::Str("auto".into()));
        s.insert("never-default".to_string(), NmValue::Bool(never));
        if r.route_nopull {
            s.insert("ignore-auto-routes".to_string(), NmValue::Bool(true));
            s.insert("ignore-auto-dns".to_string(), NmValue::Bool(true));
        }
    }
    if !r.routes4.is_empty() {
        ipv4.insert("route-data".into(), NmValue::Routes(std::mem::take(&mut r.routes4)));
    }
    if !r.routes6.is_empty() {
        ipv6.insert("route-data".into(), NmValue::Routes(std::mem::take(&mut r.routes6)));
    }
    if let Some(m) = r.route_metric {
        ipv4.insert("route-metric".into(), NmValue::I64(m));
    }
    if !r.dns4.is_empty() {
        ipv4.insert("dns-data".into(), NmValue::StrList(std::mem::take(&mut r.dns4)));
    }
    if !r.dns6.is_empty() {
        ipv6.insert("dns-data".into(), NmValue::StrList(std::mem::take(&mut r.dns6)));
    }
    let extras = dns::section_extras(full, &r.domains);
    if let Some(priority) = extras.get("dns-priority") {
        ipv6.insert("dns-priority".into(), priority.clone());
    }
    ipv4.extend(extras);

    let mut warnings = Vec::new();
    if !r.ignored.is_empty() {
        let names = r.ignored.iter().cloned().collect::<Vec<_>>().join(", ");
        warnings.push(l10n::tr("Ignored by NetworkManager on Linux: %@", &[Arg::Str(&names)]));
    }
    if !caps.openvpn_push_visible && routing == Routing::ServerDecides {
        warnings.push(l10n::tr(
            "OpenVPN 2.7 or later is needed to follow the server's redirect-gateway; this connection uses a split tunnel unless set to Always.",
            &[],
        ));
    }
    let summary = match (routing, caps.openvpn_push_visible) {
        (Routing::ServerDecides, true) => l10n::tr(
            "On Linux: NetworkManager with LinVPN's OpenVPN service · the server decides about all traffic",
            &[],
        ),
        (Routing::Always, _) => {
            l10n::tr("On Linux: NetworkManager with LinVPN's OpenVPN service · all traffic over the VPN", &[])
        }
        (Routing::Never | Routing::ServerDecides, _) => {
            l10n::tr("On Linux: NetworkManager with LinVPN's OpenVPN service · only the VPN's networks", &[])
        }
    };

    let mut settings = BTreeMap::new();
    settings.insert("connection".into(), connection_section(input.connection, input.uid, input.user, "vpn", None));
    settings.insert("vpn".into(), vpn_section(SERVICE_OPENVPN, user_name.as_deref(), std::mem::take(&mut r.data)));
    settings.insert("ipv4".into(), ipv4);
    settings.insert("ipv6".into(), ipv6);
    Ok(NmPlan {
        kind: VPNKind::Openvpn,
        service_type: Some(SERVICE_OPENVPN),
        settings,
        secrets,
        files,
        iface: Some(iface),
        summary: Some(summary),
        warnings,
    })
}
