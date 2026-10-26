//! `mvpn hook ovpn-dns <run-dir> <log> [openvpn's extra arguments…]`: the OpenVPN `--up` / `--down` hook (root),
//! also used for SSTP (mvpn passes the DNS servers from the pppd log in OpenVPN form). Successor of `ovpn-dns`.
//!
//! The hook runs as root with the environment OpenVPN gives it, which includes the config's `setenv` lines (the
//! validator forbids the dangerous names; this is defence in depth). Only the variables OpenVPN sets for the hook
//! and the hook uses are read: `script_type`, `dev`, `ifconfig_local`, `foreign_option_N`; nothing else of the
//! environment is consulted, and `networksetup` runs with an explicit minimal environment. Server-sent values are
//! never evaluated: strict format checks only. The DNS servers go to every network service through the DNS manager
//! ([`crate::macos::dns`]), which keeps the originals in its persistent ledger and restores them when the last
//! connection holding DNS goes `down` (a `<run>/dns-backup` of an older root layer is still restored).
//!
//! `script_type=check` prints the accepted DNS / DOMAIN values (tests); `check-env` prints the names of the
//! variables the hook acts on (tests).

use crate::macos::dns::{Dns, Manager, NetworkSetup, is_search_domain};
use crate::macos::fsx;
use crate::macos::log::Log;
use crate::macos::paths::{is_dir, is_file, is_symlink};
use std::path::{Path, PathBuf};

/// The allowlisted environment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HookEnv {
    pub script_type: String,
    pub dev: String,
    pub ifconfig_local: String,
    /// `foreign_option_1`, `foreign_option_2`, … up to the first missing one.
    pub foreign: Vec<String>,
}

impl HookEnv {
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> HookEnv {
        let mut foreign = Vec::new();
        while let Some(o) = get(&format!("foreign_option_{}", foreign.len() + 1)) {
            foreign.push(o);
        }
        HookEnv {
            script_type: get("script_type").unwrap_or_default(),
            dev: get("dev").unwrap_or_default(),
            ifconfig_local: get("ifconfig_local").unwrap_or_default(),
            foreign,
        }
    }

    fn from_env() -> HookEnv {
        Self::from_lookup(|k| std::env::var_os(k).map(|v| v.to_string_lossy().into_owned()))
    }

    /// `parse_options`: the accepted DNS servers and search domains.
    pub fn options(&self) -> (Vec<String>, Vec<String>) {
        let mut dns = Vec::new();
        let mut doms = Vec::new();
        for o in &self.foreign {
            if let Some(v) = o.strip_prefix("dhcp-option DNS ") {
                if is_dns(v) {
                    dns.push(v.to_string());
                }
            } else if let Some(v) = o.strip_prefix("dhcp-option DOMAIN ")
                && is_search_domain(v)
            {
                doms.push(v.to_string());
            }
        }
        (dns, doms)
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

/// The DNS manager of the hook: only as root (the fixed ledger and `/usr/sbin/networksetup`). The hook reads no
/// other environment, so not as root (tests, or an openvpn that dropped its privileges) it never changes DNS.
fn hook_manager() -> Option<Manager> {
    (crate::macos::sys::geteuid() == 0).then(|| {
        Manager::new(
            PathBuf::from(crate::macos::paths::DNS_BASE),
            Box::new(NetworkSetup { program: PathBuf::from(crate::macos::paths::NETWORKSETUP) }),
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
            // The variables the hook acts on: the allowlisted ones present, and the fixed PATH / LC_ALL of its
            // children. Nothing else of the environment is read.
            let mut present: Vec<String> = Vec::new();
            if !env.script_type.is_empty() {
                present.push("script_type".into());
            }
            if !env.dev.is_empty() {
                present.push("dev".into());
            }
            if !env.ifconfig_local.is_empty() {
                present.push("ifconfig_local".into());
            }
            for i in 0..env.foreign.len() {
                present.push(format!("foreign_option_{}", i + 1));
            }
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
        "up" => up(env, &run, &log, hook_manager().as_ref()),
        "down" => down(&run, &log, hook_manager().as_ref()),
        _ => {}
    }
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
    let (servers, domains) = env.options();
    if servers.is_empty() {
        log.step(&tr("the server sent no DNS", &[]));
        return;
    }
    match (m, run_id(run)) {
        // Every network service gets the DNS; the originals are kept in the DNS manager's persistent ledger.
        (Some(m), Some(id)) => m.acquire(&id, &Dns { servers, domains }, log),
        _ => log.step(&tr("not running as root: DNS not changed", &[])),
    }
}

fn down(run: &Path, log: &Log, m: Option<&Manager>) {
    let Some(m) = m else { return };
    if let Some(id) = run_id(run) {
        m.release(&id, log);
    }
    // A connection set up by a root layer before the ledger: its own backup.
    let backup = run.join("dns-backup");
    if is_file(&backup) && !is_symlink(&backup) {
        m.restore_legacy(&backup, log);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        use crate::macos::dns::tests::{FakeNet, dns};
        let base = std::env::temp_dir().join(format!("mvpn-hook-{}", uuid::Uuid::new_v4()));
        let run = base.join("0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0");
        std::fs::create_dir_all(&run).unwrap();
        let net = FakeNet::with(&[("Wi-Fi", &["192.168.1.1"], &["lan.example.com"])]);
        let m = Manager::new(base.join("db/dns"), Box::new(net.clone()));
        let log = Log::at(base.join("c.log"));
        let mut vars: Vec<(String, String)> = vec![("dev".into(), "utun9".into())];
        for i in 0..=crate::macos::dns::MAX_DOMAINS {
            vars.push((format!("foreign_option_{}", i + 1), format!("dhcp-option DOMAIN d{i}.corp.example")));
        }
        vars.push((format!("foreign_option_{}", vars.len()), "dhcp-option DNS 10.0.0.53".into()));
        let e = HookEnv::from_lookup(move |k| vars.iter().find(|(a, _)| a == k).map(|(_, b)| b.clone()));
        up(&e, &run, &log, Some(&m));
        assert_eq!(net.of("Wi-Fi"), dns(&["192.168.1.1"], &["lan.example.com"]));
        assert!(std::fs::read_to_string(base.join("c.log")).unwrap().contains("exceed the limits"));
        down(&run, &log, Some(&m));
        assert_eq!(net.of("Wi-Fi"), dns(&["192.168.1.1"], &["lan.example.com"]));
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
        assert_eq!(a, vec!["dev", "foreign_option_1", "ifconfig_local", "script_type"]);
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
        use crate::macos::dns::tests::{FakeNet, dns};
        let base = std::env::temp_dir().join(format!("mvpn-hook-{}", uuid::Uuid::new_v4()));
        let run = base.join("0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0");
        std::fs::create_dir_all(&run).unwrap();
        let net = FakeNet::with(&[("Wi-Fi", &["192.168.1.1"], &[])]);
        let m = Manager::new(base.join("db/dns"), Box::new(net.clone()));
        let log = Log::at(base.join("c.log"));
        let e = env(&[
            ("dev", "utun9"),
            ("foreign_option_1", "dhcp-option DNS 10.0.0.53"),
            ("foreign_option_2", "dhcp-option DOMAIN corp.example"),
        ]);
        up(&e, &run, &log, Some(&m));
        assert_eq!(net.of("Wi-Fi"), dns(&["10.0.0.53"], &["corp.example"]));
        assert!(!run.join("dns-backup").exists(), "the originals live in the ledger, not in the run directory");
        down(&run, &log, Some(&m));
        assert_eq!(net.of("Wi-Fi"), dns(&["192.168.1.1"], &[]));
        // Not as root (no manager): nothing changes.
        up(&e, &run, &log, None);
        assert_eq!(net.of("Wi-Fi"), dns(&["192.168.1.1"], &[]));
        assert!(std::fs::read_to_string(base.join("c.log")).unwrap().contains("not running as root: DNS not changed"));
        fsx::remove_rf(&base);
    }

    #[test]
    fn tunnel_devices() {
        assert!(is_tunnel_dev("utun9") && is_tunnel_dev("ppp0"));
        assert!(!is_tunnel_dev("utun1;x") && !is_tunnel_dev("en0") && !is_tunnel_dev("ppp"));
    }
}
