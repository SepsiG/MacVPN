//! `mvpn hook ovpn-dns <run-dir> <log> [openvpn's extra arguments…]`: the OpenVPN `--up` / `--down` hook (root),
//! also used for SSTP (mvpn passes the DNS servers from the pppd log in OpenVPN form). Successor of `ovpn-dns`.
//!
//! The hook runs as root with the environment OpenVPN gives it, which includes the config's `setenv` lines (the
//! validator forbids the dangerous names; this is defence in depth). Only the variables OpenVPN sets for the hook
//! and the hook uses are read: `script_type`, `dev`, `ifconfig_local`, `foreign_option_N`; nothing else of the
//! environment is consulted, and `networksetup` runs with an explicit minimal environment. Server-sent values are
//! never evaluated: strict format checks only. The DNS goes to the DNS manager ([`crate::macos::dns`], root layer
//! 15: the dynamic store), which applies the connection's DNS mode and own DNS (`<run>/dns-request`) and gives
//! everything back when the connection goes `down` (a `<run>/dns-backup` of an older root layer is still restored).
//!
//! `script_type=check` prints the accepted DNS / DOMAIN values (tests); `check-env` prints the names of the
//! variables the hook acts on (tests).

use crate::macos::dns::{Dns, Manager, is_search_domain, log_over_limits};
use crate::macos::dns_legacy::NetworkSetup;
use crate::macos::dns_plan::Pushed;
use crate::macos::fsx;
use crate::macos::log::Log;
use crate::macos::paths::{is_dir, is_file, is_symlink};
use macvpn_core::netaddr::IpPrefix;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

/// At most this many routes, DNS servers, addresses and domains are read from the environment.
const ENV_MAX: usize = 256;

/// The allowlisted environment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HookEnv {
    pub script_type: String,
    pub dev: String,
    pub ifconfig_local: String,
    /// `foreign_option_1`, `foreign_option_2`, … up to the first missing one.
    pub foreign: Vec<String>,
    /// `route_network_N` / `route_netmask_N` (root layer 15: the reverse zones of the routed private networks).
    pub routes4: Vec<(String, String)>,
    /// `route_ipv6_network_N` (`addr/len`).
    pub routes6: Vec<String>,
    /// OpenVPN 2.7 `--dns-updown` (`script_type=dns-up`): the `--dns` options, or the name of the file holding them
    /// when OpenVPN dropped its privileges (`dns_vars_file`).
    pub dns: DnsVars,
    pub dns_vars_file: String,
}

/// OpenVPN 2.7's `--dns` variables of `dns-up`: `dns_search_domain_N` and per server `dns_server_N_address_M`,
/// `_port_M`, `_resolve_domain_M`, `_dnssec`, `_transport` (N and M from 1, up to the first missing one).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsVars {
    pub search: Vec<String>,
    pub servers: Vec<DnsServerVars>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsServerVars {
    pub addresses: Vec<String>,
    pub ports: Vec<String>,
    pub resolve: Vec<String>,
    pub dnssec: String,
    pub transport: String,
}

/// `prefix1`, `prefix2`, … up to the first missing one (at most [`ENV_MAX`]).
fn numbered(get: &dyn Fn(&str) -> Option<String>, name: &dyn Fn(usize) -> String) -> Vec<String> {
    let mut out = Vec::new();
    while out.len() < ENV_MAX {
        match get(&name(out.len() + 1)) {
            Some(v) => out.push(v),
            None => break,
        }
    }
    out
}

impl DnsVars {
    /// Only the allowlisted `dns_*` names are asked for.
    pub fn from_lookup(get: &dyn Fn(&str) -> Option<String>) -> DnsVars {
        let search = numbered(get, &|n| format!("dns_search_domain_{n}"));
        let mut servers = Vec::new();
        for n in 1..=8 {
            let addresses = numbered(get, &|m| format!("dns_server_{n}_address_{m}"));
            if addresses.is_empty() {
                break;
            }
            servers.push(DnsServerVars {
                ports: (1..=addresses.len())
                    .map(|m| get(&format!("dns_server_{n}_port_{m}")).unwrap_or_default())
                    .collect(),
                addresses,
                resolve: numbered(get, &|m| format!("dns_server_{n}_resolve_domain_{m}")),
                dnssec: get(&format!("dns_server_{n}_dnssec")).unwrap_or_default(),
                transport: get(&format!("dns_server_{n}_transport")).unwrap_or_default(),
            });
        }
        DnsVars { search, servers }
    }

    /// The servers, search domains and resolve-only domains of the first profile the system resolver can use
    /// (plain transport, no DNSSEC requirement, port 53), as OpenVPN's own `find_compat_profile` picks it; every
    /// value checked, the rest dropped.
    pub fn compatible(&self) -> (Vec<String>, Vec<String>, Vec<String>) {
        let ok = |s: &&DnsServerVars| {
            matches!(s.transport.as_str(), "" | "plain")
                && matches!(s.dnssec.as_str(), "" | "no")
                && s.ports.iter().all(|p| p.is_empty() || p == "53")
        };
        let domain = |d: &String| is_search_domain(d.trim_end_matches('.'));
        let clean = |v: &[String]| -> Vec<String> {
            v.iter().filter(|d| domain(d)).map(|d| d.trim_end_matches('.').to_string()).collect()
        };
        let search = clean(&self.search);
        match self.servers.iter().find(ok) {
            Some(s) => (s.addresses.iter().filter(|a| is_pushed_dns(a)).cloned().collect(), search, clean(&s.resolve)),
            None => (Vec::new(), search, Vec::new()),
        }
    }
}

/// The names `dns_vars_file` may set (a `NAME=value` line each): exactly the `dns_*` names of [`DnsVars`].
fn is_dns_var_name(n: &str) -> bool {
    let num = |s: &str| !s.is_empty() && s.len() <= 3 && s.bytes().all(|b| b.is_ascii_digit());
    if let Some(i) = n.strip_prefix("dns_search_domain_") {
        return num(i);
    }
    let Some(rest) = n.strip_prefix("dns_server_") else { return false };
    let Some((i, field)) = rest.split_once('_') else { return false };
    if !num(i) {
        return false;
    }
    if matches!(field, "dnssec" | "transport") {
        return true;
    }
    ["address_", "port_", "resolve_domain_"].iter().any(|p| field.strip_prefix(p).is_some_and(num))
}

/// `dns_vars_file`: a regular file (not a symlink), at most 64 KiB, `NAME=value` lines with allowlisted names only
/// (any other line makes the whole file refused); the values stay literal (never sourced or expanded).
pub fn read_dns_vars_file(p: &Path) -> Option<std::collections::BTreeMap<String, String>> {
    let data = fsx::read_private(p, 64 * 1024)?;
    let text = String::from_utf8(data).ok()?;
    let mut vars = std::collections::BTreeMap::new();
    for line in text.lines().filter(|l| !l.is_empty()) {
        let (k, v) = line.split_once('=')?;
        if !is_dns_var_name(k) || vars.insert(k.to_string(), v.to_string()).is_some() {
            return None;
        }
    }
    Some(vars)
}

impl HookEnv {
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> HookEnv {
        let mut foreign = Vec::new();
        while let Some(o) = get(&format!("foreign_option_{}", foreign.len() + 1)) {
            foreign.push(o);
        }
        let networks = numbered(&get, &|n| format!("route_network_{n}"));
        let routes4 = networks
            .into_iter()
            .enumerate()
            .map(|(i, n)| (n, get(&format!("route_netmask_{}", i + 1)).unwrap_or_default()))
            .collect();
        HookEnv {
            script_type: get("script_type").unwrap_or_default(),
            dev: get("dev").unwrap_or_default(),
            ifconfig_local: get("ifconfig_local").unwrap_or_default(),
            foreign,
            routes4,
            routes6: numbered(&get, &|n| format!("route_ipv6_network_{n}")),
            dns: DnsVars::from_lookup(&get),
            dns_vars_file: get("dns_vars_file").unwrap_or_default(),
        }
    }

    fn from_env() -> HookEnv {
        Self::from_lookup(|k| std::env::var_os(k).map(|v| v.to_string_lossy().into_owned()))
    }

    /// `parse_options`: the accepted DNS servers (`DNS`, `DNS6`) and search domains (`DOMAIN`, `DOMAIN-SEARCH`).
    pub fn options(&self) -> (Vec<String>, Vec<String>) {
        let mut dns = Vec::new();
        let mut doms = Vec::new();
        for o in &self.foreign {
            if let Some(v) = o.strip_prefix("dhcp-option DNS ").or_else(|| o.strip_prefix("dhcp-option DNS6 ")) {
                if is_pushed_dns(v) {
                    dns.push(v.to_string());
                }
            } else if let Some(v) =
                o.strip_prefix("dhcp-option DOMAIN ").or_else(|| o.strip_prefix("dhcp-option DOMAIN-SEARCH "))
                && is_search_domain(v)
            {
                doms.push(v.to_string());
            }
        }
        (dns, doms)
    }

    /// The routed networks, strictly: a bad network or mask is dropped.
    pub fn routes(&self) -> Vec<IpPrefix> {
        let v4 = self
            .routes4
            .iter()
            .filter(|(n, m)| is_ipv4(n) && is_ipv4(m))
            .filter_map(|(n, m)| IpPrefix::from_mask(n.parse::<Ipv4Addr>().ok()?, m.parse::<Ipv4Addr>().ok()?));
        let v6 = self.routes6.iter().filter(|r| r.contains('/')).filter_map(|r| IpPrefix::parse(r));
        v4.chain(v6).collect()
    }
}

/// `^([0-9]{1,3}\.){3}[0-9]{1,3}$`
pub fn is_ipv4(s: &str) -> bool {
    let p: Vec<&str> = s.split('.').collect();
    p.len() == 4 && p.iter().all(|x| (1..=3).contains(&x.len()) && x.bytes().all(|b| b.is_ascii_digit()))
}

/// Hex digits and colons, at least one hex digit, at least two colons, at most 39 bytes (eight full groups).
pub fn is_ipv6(s: &str) -> bool {
    (1..=39).contains(&s.len())
        && s.bytes().all(|b| b.is_ascii_hexdigit() || b == b':')
        && s.bytes().any(|b| b.is_ascii_hexdigit())
        && s.bytes().filter(|&b| b == b':').count() >= 2
}

pub fn is_dns(s: &str) -> bool {
    is_ipv4(s) || is_ipv6(s)
}

/// A VPN-sent DNS server the DNS manager takes: [`is_dns`]'s shape and an address as the session and the ledger
/// read it (`is_dns_server`: no leading zeros, no octet over 255, a valid IPv6 notation).
pub fn is_pushed_dns(s: &str) -> bool {
    is_dns(s) && macvpn_core::dns_settings::is_dns_server(s)
}

/// `^(utun|ppp)[0-9]+$`
fn is_tunnel_dev(s: &str) -> bool {
    let n = s.strip_prefix("utun").or_else(|| s.strip_prefix("ppp"));
    n.is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// One `dns-backup` line → (service, DNS words, domain words). The fields are TAB-separated (runs of TABs count
/// as one, as `read` with `IFS=$'\t'` does); the lists split at blanks. No word is ever glob-expanded.
pub fn parse_backup_line(line: &str) -> Option<(String, Vec<String>, Vec<String>)> {
    let trimmed = line.trim_matches('\t');
    let mut parts = trimmed.splitn(2, '\t');
    let svc = parts.next().unwrap_or_default().to_string();
    let rest = parts.next().unwrap_or_default().trim_start_matches('\t');
    let mut parts = rest.splitn(2, '\t');
    let dns = parts.next().unwrap_or_default();
    let doms = parts.next().unwrap_or_default().trim_start_matches('\t');
    if svc.is_empty() {
        return None;
    }
    let words = |s: &str| s.split([' ', '\t', '\n']).filter(|w| !w.is_empty()).map(String::from).collect::<Vec<_>>();
    Some((svc, words(dns), words(doms)))
}

/// The DNS manager of the hook: as root the real dynamic store (`dns::manager`). Not as root only for a run
/// directory of the caller's own (test mode, `scripts/test-root.sh` with `MVPN_DYNSTORE`): an openvpn that dropped
/// its privileges runs the hook as another user on root's run directory, and never changes DNS.
fn hook_manager(run: &Path) -> Option<Manager> {
    use std::os::unix::fs::MetadataExt;
    let euid = crate::macos::sys::geteuid();
    if euid != 0 && !std::fs::symlink_metadata(run).is_ok_and(|m| m.uid() == euid) {
        return None;
    }
    crate::macos::dns::manager(&crate::macos::paths::Settings::load())
}

/// Root layer 14's manager, only for a run directory's `dns-backup` of a root layer before the ledger (root only).
fn legacy_manager() -> Option<crate::macos::dns_legacy::Manager> {
    (crate::macos::sys::geteuid() == 0).then(|| {
        let ns = Box::new(NetworkSetup { program: PathBuf::from(crate::macos::paths::NETWORKSETUP) });
        crate::macos::dns_legacy::Manager::new(
            PathBuf::from(crate::macos::paths::DNS_BASE),
            Box::new(crate::macos::dns_sc::ScNet::system(ns)),
        )
    })
}

/// The connection id: the run directory's name (`/var/run/macvpn/<uuid>`).
fn run_id(run: &Path) -> Option<String> {
    let id = run.file_name()?.to_str()?;
    crate::shared::cli::is_uuid(id).then(|| id.to_string())
}

/// `mvpn hook ovpn-dns …`; always exits 0, like the bash hook.
pub fn main(args: &[String]) -> i32 {
    let env = HookEnv::from_env();
    run(&env, args);
    0
}

fn run(env: &HookEnv, args: &[String]) {
    let (Some(run), Some(log)) = (args.first(), args.get(1)) else { return };
    let run = PathBuf::from(run);
    let log = PathBuf::from(log);
    if !is_dir(&run) {
        return;
    }
    let lang_file = run.join("lang");
    let hu = is_file(&lang_file)
        && !is_symlink(&lang_file)
        && crate::macos::log::read_range(&lang_file, 0, 3).is_some_and(|d| {
            let mut d = d;
            while d.last() == Some(&b'\n') {
                d.pop();
            }
            d == b"hu"
        });
    macvpn_core::l10n::AppLanguage::set_override(Some(if hu {
        macvpn_core::l10n::AppLanguage::Hu
    } else {
        macvpn_core::l10n::AppLanguage::En
    }));
    let log = Log::at(log);
    match env.script_type.as_str() {
        "check-env" => {
            // The variables the hook acts on: the allowlisted ones present (exactly what `HookEnv::from_lookup`
            // asks for and finds), and the fixed PATH / LC_ALL of its children. Nothing else is read.
            let present = std::cell::RefCell::new(Vec::new());
            let _ = HookEnv::from_lookup(|k| {
                let v = std::env::var_os(k).map(|v| v.to_string_lossy().into_owned());
                if v.is_some() {
                    present.borrow_mut().push(k.to_string());
                }
                v
            });
            let mut present = present.into_inner();
            present.push("LC_ALL".into());
            present.push("PATH".into());
            present.sort();
            for n in present {
                out!("{n}");
            }
        }
        "check" => {
            let (dns, doms) = env.options();
            for v in dns {
                out!("DNS {v}");
            }
            for v in doms {
                out!("DOMAIN {v}");
            }
        }
        "up" => up(env, &run, &log, hook_manager(&run).as_ref()),
        "dns-up" => dns_up(env, &run, &log),
        // The `--down` hook releases (so the order is the same as on OpenVPN 2.6).
        "dns-down" => {}
        "down" => down(&run, &log, hook_manager(&run).as_ref(), legacy_manager().as_ref()),
        _ => {}
    }
}

/// The `--dns-updown` marker of OpenVPN 2.7 (`<run>/dns-updown`): the compatible `--dns` profile `dns-up` found,
/// for the `--up` hook (whose environment then has no DNS foreign options).
const UPDOWN: &str = "dns-updown";

/// `script_type=dns-up` (OpenVPN 2.7 `--dns-updown`, before `--up`): records the compatible `--dns` profile,
/// `resolve-domains` included; the `--up` hook applies it together with the routes.
fn dns_up(env: &HookEnv, run: &Path, log: &Log) {
    use crate::macos::ctx::tr;
    let vars = if env.dns_vars_file.is_empty() {
        env.dns.clone()
    } else {
        match read_dns_vars_file(Path::new(&env.dns_vars_file)) {
            Some(map) => DnsVars::from_lookup(&|k| map.get(k).cloned()),
            None => {
                log.step(&tr("the DNS variables file of OpenVPN was refused", &[]));
                DnsVars::default()
            }
        }
    };
    let (servers, search, resolve) = vars.compatible();
    let text = format!("servers={}\nsearch={}\nresolve={}\n", servers.join(","), search.join(","), resolve.join(","));
    let _ = fsx::write_file(&run.join(UPDOWN), text.as_bytes(), 0o600);
}

/// The marker's lists, strictly (every value checked); `None` without a marker.
fn read_updown(run: &Path) -> Option<(Vec<String>, Vec<String>, Vec<String>)> {
    let text = String::from_utf8(fsx::read_private(&run.join(UPDOWN), 64 * 1024)?).ok()?;
    let mut v: [Option<Vec<String>>; 3] = [None, None, None];
    for line in text.lines() {
        let (k, val) = line.split_once('=')?;
        let i = ["servers", "search", "resolve"].iter().position(|x| *x == k)?;
        let items: Vec<String> = val.split(',').filter(|x| !x.is_empty()).map(str::to_string).collect();
        let ok =
            if i == 0 { items.iter().all(|x| is_pushed_dns(x)) } else { items.iter().all(|x| is_search_domain(x)) };
        if !ok || v[i].replace(items).is_some() {
            return None;
        }
    }
    let [a, b, c] = v;
    Some((a?, b?, c?))
}

fn up(env: &HookEnv, run: &Path, log: &Log, m: Option<&Manager>) {
    use crate::macos::ctx::tr;
    if is_tunnel_dev(&env.dev) {
        let _ = fsx::write_line(&run.join("iface"), &env.dev);
    } else {
        log.step(&tr("unexpected interface name, not recorded", &[]));
    }
    if is_ipv4(&env.ifconfig_local) {
        let _ = fsx::write_line(&run.join("ip"), &env.ifconfig_local);
    }
    // OpenVPN 2.7 with `--dns-updown`: the `--dns` profile `dns-up` recorded; otherwise the foreign options.
    let (servers, search, resolve) = read_updown(run).unwrap_or_else(|| {
        let (servers, search) = env.options();
        (servers, search, Vec::new())
    });
    let mut pushed = Pushed { servers, search, resolve, routes: env.routes() };
    // A VPN's DNS outside the limits is refused whole, as before; the connection's own DNS may still apply.
    let sent = Dns { servers: pushed.servers.clone(), domains: pushed.search.clone() };
    if !sent.servers.is_empty() && !sent.within_limits() {
        log_over_limits(&sent, log);
        pushed = Pushed { routes: pushed.routes, ..Default::default() };
    }
    if sent.servers.is_empty() {
        log.step(&tr("the server sent no DNS", &[]));
    }
    match (m, run_id(run)) {
        // The DNS manager decides with the connection's own settings (`<run>/dns-request`).
        (Some(m), Some(id)) => {
            m.acquire(&id, run, &pushed, log);
        }
        _ if !sent.servers.is_empty() => log.step(&tr("not running as root: DNS not changed", &[])),
        _ => {}
    }
}

fn down(run: &Path, log: &Log, m: Option<&Manager>, legacy: Option<&crate::macos::dns_legacy::Manager>) {
    if let (Some(m), Some(id)) = (m, run_id(run)) {
        m.release(&id, run, log);
    }
    // A connection set up by a root layer before the ledger: its own backup.
    let backup = run.join("dns-backup");
    if let Some(legacy) = legacy
        && is_file(&backup)
        && !is_symlink(&backup)
    {
        legacy.restore_legacy(&backup, log);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macos::dns_store::Store;

    fn env(vars: &[(&str, &str)]) -> HookEnv {
        let v: Vec<(String, String)> = vars.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
        HookEnv::from_lookup(move |k| v.iter().find(|(a, _)| a == k).map(|(_, b)| b.clone()))
    }

    #[test]
    fn strict_dns_and_domain() {
        let e = env(&[
            ("foreign_option_1", "dhcp-option DNS 10.0.0.1"),
            ("foreign_option_2", "dhcp-option DNS 1.2.3"),
            ("foreign_option_3", "dhcp-option DNS ::"),
            ("foreign_option_4", "dhcp-option DNS fd00::53"),
            ("foreign_option_5", "dhcp-option DNS 1:2"),
            ("foreign_option_6", "dhcp-option DNS 1.1.1.1.1"),
            ("foreign_option_7", "dhcp-option DOMAIN corp.example"),
            ("foreign_option_8", "dhcp-option DOMAIN -evil"),
            ("foreign_option_9", "dhcp-option DOMAIN .x"),
            ("foreign_option_10", "dhcp-option DOMAIN a b"),
            ("foreign_option_12", "dhcp-option DNS 9.9.9.9"),
        ]);
        assert_eq!(env_options(&e), (vec!["10.0.0.1".into(), "fd00::53".into()], vec!["corp.example".into()]));
        assert!(!is_dns("1.1.1.1;touch /tmp/x"));
    }

    /// A pushed server the session and the ledger would refuse (leading zeros, an octet over 255) is dropped here.
    #[test]
    fn pushed_servers_use_the_ledgers_rule() {
        let e = env(&[
            ("foreign_option_1", "dhcp-option DNS 010.8.0.1"),
            ("foreign_option_2", "dhcp-option DNS 10.8.0.256"),
            ("foreign_option_3", "dhcp-option DNS 10.8.0.1"),
            ("foreign_option_4", "dhcp-option DNS6 fd00::53:"),
            ("dns_server_1_address_1", "010.8.0.1"),
            ("dns_server_1_address_2", "10.8.0.2"),
        ]);
        assert_eq!(e.options().0, ["10.8.0.1"]);
        assert_eq!(e.dns.compatible().0, ["10.8.0.2"]);
        let (base, run) = temp_run();
        std::fs::write(run.join(UPDOWN), "servers=010.8.0.1\nsearch=\nresolve=\n").unwrap();
        std::fs::set_permissions(run.join(UPDOWN), std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
        assert_eq!(read_updown(&run), None);
        fsx::remove_rf(&base);
    }

    #[test]
    fn pushed_domains_use_the_ledgers_rule() {
        let long = format!("a{}", ".b".repeat(126)); // 253 bytes
        let longer = format!("{long}c");
        let e = env(&[
            ("foreign_option_1", "dhcp-option DNS 10.0.0.1"),
            ("foreign_option_2", &format!("dhcp-option DOMAIN {long}")),
            ("foreign_option_3", &format!("dhcp-option DOMAIN {longer}")),
            ("foreign_option_4", "dhcp-option DOMAIN _ldap.corp.example"),
        ]);
        assert_eq!(e.options().1, vec![long, "_ldap.corp.example".to_string()]);
        // An IPv6 address is at most 39 bytes in this notation.
        assert!(is_ipv6("fd00:0000:0000:0000:0000:0000:0000:0053"));
        assert!(!is_ipv6(&format!("fd00{}", ":0".repeat(20))));
    }

    #[test]
    fn an_oversized_pushed_dns_list_leaves_the_originals() {
        let base = std::env::temp_dir().join(format!("mvpn-hook-{}", uuid::Uuid::new_v4()));
        let run = base.join("0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0");
        std::fs::create_dir_all(&run).unwrap();
        let (m, store) = crate::macos::dns::tests::mem_manager(base.join("db/dns"));
        let log = Log::at(base.join("c.log"));
        let mut vars: Vec<(String, String)> = vec![("dev".into(), "utun9".into())];
        for i in 0..=crate::macos::dns_legacy::MAX_DOMAINS {
            vars.push((format!("foreign_option_{}", i + 1), format!("dhcp-option DOMAIN d{i}.corp.example")));
        }
        vars.push((format!("foreign_option_{}", vars.len()), "dhcp-option DNS 10.0.0.53".into()));
        let e = HookEnv::from_lookup(move |k| vars.iter().find(|(a, _)| a == k).map(|(_, b)| b.clone()));
        up(&e, &run, &log, Some(&m));
        assert!(store.dict("Setup:/Network/Service/S1/DNS").is_none());
        assert!(std::fs::read_to_string(base.join("c.log")).unwrap().contains("exceed the limits"));
        down(&run, &log, Some(&m), None);
        assert!(store.keys("^State:/Network/(Service/macvpn-|MacVPN)").is_empty());
        fsx::remove_rf(&base);
    }

    fn env_options(e: &HookEnv) -> (Vec<String>, Vec<String>) {
        e.options()
    }

    #[test]
    fn only_allowlisted_names_are_read() {
        let asked = std::cell::RefCell::new(Vec::new());
        let _ = HookEnv::from_lookup(|k| {
            asked.borrow_mut().push(k.to_string());
            None
        });
        let mut a = asked.into_inner();
        a.sort();
        assert_eq!(
            a,
            vec![
                "dev",
                "dns_search_domain_1",
                "dns_server_1_address_1",
                "dns_vars_file",
                "foreign_option_1",
                "ifconfig_local",
                "route_ipv6_network_1",
                "route_network_1",
                "script_type",
            ]
        );
    }

    #[test]
    fn backup_lines_never_glob() {
        assert_eq!(
            parse_backup_line("Wi-Fi\t1.1.1.1 8.8.8.8 \t*"),
            Some(("Wi-Fi".into(), vec!["1.1.1.1".into(), "8.8.8.8".into()], vec!["*".into()]))
        );
        assert_eq!(
            parse_backup_line("svc\tEmpty\tEmpty"),
            Some(("svc".into(), vec!["Empty".into()], vec!["Empty".into()]))
        );
        assert_eq!(parse_backup_line("svc\t\tEmpty"), Some(("svc".into(), vec!["Empty".into()], vec![])));
        assert_eq!(parse_backup_line(""), None);
    }

    #[test]
    fn up_and_down_go_through_the_dns_manager() {
        let base = std::env::temp_dir().join(format!("mvpn-hook-{}", uuid::Uuid::new_v4()));
        let run = base.join("0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0");
        std::fs::create_dir_all(&run).unwrap();
        let (m, store) = crate::macos::dns::tests::mem_manager(base.join("db/dns"));
        let log = Log::at(base.join("c.log"));
        let e = env(&[
            ("dev", "utun9"),
            ("foreign_option_1", "dhcp-option DNS 10.0.0.53"),
            ("foreign_option_2", "dhcp-option DOMAIN corp.example"),
        ]);
        up(&e, &run, &log, Some(&m));
        let setup = store.dict("Setup:/Network/Service/S1/DNS").unwrap();
        assert_eq!(crate::macos::dns_store::list_of(&setup, "ServerAddresses"), ["10.0.0.53"]);
        assert!(!run.join("dns-backup").exists(), "nothing persistent in the run directory");
        down(&run, &log, Some(&m), None);
        assert!(store.dict("Setup:/Network/Service/S1/DNS").is_none());
        // Without a manager (not root, not a run directory of the caller): nothing changes.
        up(&e, &run, &log, None);
        assert!(store.dict("Setup:/Network/Service/S1/DNS").is_none());
        assert!(std::fs::read_to_string(base.join("c.log")).unwrap().contains("not running as root: DNS not changed"));
        fsx::remove_rf(&base);
    }

    #[test]
    fn dns6_and_domain_search_are_accepted() {
        let e = env(&[
            ("foreign_option_1", "dhcp-option DNS6 fd00::53"),
            ("foreign_option_2", "dhcp-option DOMAIN-SEARCH corp.example"),
            ("foreign_option_3", "dhcp-option DNS6 fd00::53;x"),
            ("foreign_option_4", "dhcp-option DOMAIN-SEARCH -x"),
        ]);
        assert_eq!(e.options(), (vec!["fd00::53".into()], vec!["corp.example".into()]));
    }

    #[test]
    fn routes_are_read_strictly() {
        let e = env(&[
            ("route_network_1", "10.1.0.0"),
            ("route_netmask_1", "255.255.0.0"),
            ("route_network_2", "10.2.0.0"),
            ("route_netmask_2", "255.0.255.0"),
            ("route_network_3", "x;y"),
            ("route_netmask_3", "255.255.255.0"),
            ("route_ipv6_network_1", "fd00:1::/64"),
            ("route_ipv6_network_2", "fd00::1"),
        ]);
        let r: Vec<String> = e.routes().iter().map(|p| format!("{}/{}", p.addr, p.len)).collect();
        assert_eq!(r, ["10.1.0.0/16", "fd00:1::/64"]);
    }

    fn temp_run() -> (PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!("mvpn-hook-{}", uuid::Uuid::new_v4()));
        let run = base.join("0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0");
        std::fs::create_dir_all(&run).unwrap();
        (base, run)
    }

    #[test]
    fn up_without_pushed_dns_uses_own_servers() {
        use macvpn_core::dns_settings::DnsRequest;
        let (base, run) = temp_run();
        let (m, store) = crate::macos::dns::tests::mem_manager(base.join("db/dns"));
        crate::macos::dns_session::write_request(
            &run,
            &DnsRequest { servers: vec!["10.0.0.53".into()], ..Default::default() },
        )
        .unwrap();
        let log = Log::at(base.join("c.log"));
        up(&env(&[("dev", "utun9")]), &run, &log, Some(&m));
        let setup = store.dict("Setup:/Network/Service/S1/DNS").unwrap();
        assert_eq!(crate::macos::dns_store::list_of(&setup, "ServerAddresses"), ["10.0.0.53"]);
        assert!(std::fs::read_to_string(base.join("c.log")).unwrap().contains("the server sent no DNS"));
        fsx::remove_rf(&base);
    }

    #[test]
    fn up_with_override_ignores_pushed() {
        use macvpn_core::dns_settings::DnsRequest;
        let (base, run) = temp_run();
        let (m, store) = crate::macos::dns::tests::mem_manager(base.join("db/dns"));
        let own = DnsRequest { servers: vec!["10.0.0.53".into()], override_vpn: true, ..Default::default() };
        crate::macos::dns_session::write_request(&run, &own).unwrap();
        let e = env(&[("dev", "utun9"), ("foreign_option_1", "dhcp-option DNS 10.8.0.1")]);
        up(&e, &run, &Log::none(), Some(&m));
        let setup = store.dict("Setup:/Network/Service/S1/DNS").unwrap();
        assert_eq!(crate::macos::dns_store::list_of(&setup, "ServerAddresses"), ["10.0.0.53"]);
        fsx::remove_rf(&base);
    }

    fn dns_env() -> Vec<(&'static str, &'static str)> {
        vec![
            ("dns_search_domain_1", "corp.example"),
            ("dns_server_1_address_1", "10.8.0.9"),
            ("dns_server_1_transport", "DoT"),
            ("dns_server_2_address_1", "10.8.0.1"),
            ("dns_server_2_address_2", "fd00::53"),
            ("dns_server_2_resolve_domain_1", "svc.example"),
            ("dns_server_2_resolve_domain_2", "bad domain"),
            ("dns_server_3_address_1", "10.8.0.3"),
        ]
    }

    #[test]
    fn first_compatible_profile() {
        let e = env(&dns_env());
        let (servers, search, resolve) = e.dns.compatible();
        assert_eq!(servers, ["10.8.0.1", "fd00::53"], "the DoT profile is skipped");
        assert_eq!(search, ["corp.example"]);
        assert_eq!(resolve, ["svc.example"]);
        let mut v = dns_env();
        v.push(("dns_server_2_port_1", "5353"));
        assert_eq!(env(&v).dns.compatible().0, ["10.8.0.3"], "another port is skipped too");
    }

    #[test]
    fn resolve_domains_reach_the_match_entry() {
        let (base, run) = temp_run();
        let (m, store) = crate::macos::dns::tests::mem_manager(base.join("db/dns"));
        let mut v = dns_env();
        v.push(("script_type", "dns-up"));
        dns_up(&env(&v), &run, &Log::none());
        // `--up` then runs without DNS foreign options (OpenVPN removed them).
        up(&env(&[("dev", "utun9")]), &run, &Log::none(), Some(&m));
        let id = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";
        let matched = store.dict(&crate::macos::dns_plan::entry_key(id, "-match")).unwrap();
        assert_eq!(crate::macos::dns_store::list_of(&matched, "SupplementalMatchDomains"), ["svc.example"]);
        fsx::remove_rf(&base);
    }

    #[test]
    fn dns_vars_file_strict() {
        let (base, _) = temp_run();
        let f = base.join("vars");
        std::fs::write(&f, "dns_server_1_address_1=10.8.0.1\ndns_search_domain_1=$(touch /tmp/x)\n").unwrap();
        let vars = read_dns_vars_file(&f).unwrap();
        assert_eq!(vars["dns_search_domain_1"], "$(touch /tmp/x)", "kept literal");
        let d = DnsVars::from_lookup(&|k| vars.get(k).cloned());
        assert_eq!(d.compatible(), (vec!["10.8.0.1".into()], vec![], vec![]), "an invalid domain is dropped");
        std::fs::write(&f, "PATH=/tmp\n").unwrap();
        assert!(read_dns_vars_file(&f).is_none(), "an unknown name refuses the file");
        std::fs::write(&f, "dns_server_1_address_1=1\ndns_server_1_address_1=2\n").unwrap();
        assert!(read_dns_vars_file(&f).is_none(), "a repeated name too");
        std::fs::write(&f, "x".repeat(70 * 1024)).unwrap();
        assert!(read_dns_vars_file(&f).is_none(), "oversize");
        let link = base.join("link");
        std::fs::write(&f, "dns_server_1_address_1=10.8.0.1\n").unwrap();
        std::os::unix::fs::symlink(&f, &link).unwrap();
        assert!(read_dns_vars_file(&link).is_none(), "never through a symlink");
        assert!(is_dns_var_name("dns_server_12_resolve_domain_3") && !is_dns_var_name("dns_server_x_dnssec"));
        fsx::remove_rf(&base);
    }

    #[test]
    fn tunnel_devices() {
        assert!(is_tunnel_dev("utun9") && is_tunnel_dev("ppp0"));
        assert!(!is_tunnel_dev("utun1;x") && !is_tunnel_dev("en0") && !is_tunnel_dev("ppp"));
    }
}
