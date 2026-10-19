//! `mvpn hook ovpn-dns <run-dir> <log> [openvpn's extra arguments…]`: the OpenVPN `--up` / `--down` hook (root),
//! also used for SSTP (mvpn passes the DNS servers from the pppd log in OpenVPN form). Successor of `ovpn-dns`.
//!
//! The hook runs as root with the environment OpenVPN gives it, which includes the config's `setenv` lines (the
//! validator forbids the dangerous names; this is defence in depth). Only the variables OpenVPN sets for the hook
//! and the hook uses are read: `script_type`, `dev`, `ifconfig_local`, `foreign_option_N`; nothing else of the
//! environment is consulted, and `networksetup` runs with an explicit minimal environment. Server-sent values are
//! never evaluated: strict format checks only. The DNS servers go to every network service (like wg-quick) and are
//! restored at `down` from `<run>/dns-backup`.
//!
//! `script_type=check` prints the accepted DNS / DOMAIN values (tests); `check-env` prints the names of the
//! variables the hook acts on (tests).

use crate::exec::{Cmd, EnvMode};
use crate::fsx;
use crate::paths::{is_dir, is_file, is_symlink};
use std::path::{Path, PathBuf};
use std::process::Stdio;

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
                && is_domain(v)
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

/// Hex digits and colons, at least one hex digit, at least two colons.
pub fn is_ipv6(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| b.is_ascii_hexdigit() || b == b':')
        && s.bytes().any(|b| b.is_ascii_hexdigit())
        && s.bytes().filter(|&b| b == b':').count() >= 2
}

pub fn is_dns(s: &str) -> bool {
    is_ipv4(s) || is_ipv6(s)
}

/// `^[A-Za-z0-9][A-Za-z0-9.-]*$`
pub fn is_domain(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b[0].is_ascii_alphanumeric()
        && b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-'))
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

/// `networksetup` with the minimal environment.
fn networksetup<I, S>(args: I) -> Cmd
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    Cmd::new("/usr/sbin/networksetup").args(args)
}

fn ns_output(args: &[&str]) -> String {
    crate::exec::capture(&networksetup(args), EnvMode::Minimal, 1 << 20)
        .map(|(_, o)| String::from_utf8_lossy(&o).into_owned())
        .unwrap_or_default()
}

fn ns_run(args: &[String]) {
    let _ = networksetup(args).command(EnvMode::Minimal).stdin(Stdio::null()).status();
}

/// `cur=$(… | tr '\n' ' ')`, "There aren't any …" → `Empty`.
fn current_list(flag: &str, svc: &str) -> String {
    let joined = ns_output(&[flag, svc]).replace('\n', " ");
    if joined.contains("aren't any") { "Empty".into() } else { joined }
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
        && crate::log::read_range(&lang_file, 0, 3).is_some_and(|d| {
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
    let write_log = |s: &str| {
        let _ = fsx::append(&log, format!("{s}\n").as_bytes());
    };
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
        "up" => up(env, &run, &write_log),
        "down" => down(&run, &write_log),
        _ => {}
    }
}

fn up(env: &HookEnv, run: &Path, log: &dyn Fn(&str)) {
    use crate::ctx::tr;
    if is_tunnel_dev(&env.dev) {
        let _ = fsx::write_line(&run.join("iface"), &env.dev);
    } else {
        log(&format!("▶ [mvpn] {}", tr("unexpected interface name, not recorded", &[])));
    }
    if is_ipv4(&env.ifconfig_local) {
        let _ = fsx::write_line(&run.join("ip"), &env.ifconfig_local);
    }
    let (dns, doms) = env.options();
    if dns.is_empty() {
        log(&format!("▶ [mvpn] {}", tr("the server sent no DNS", &[])));
        return;
    }
    // An existing backup (a reconnect without down) is kept: otherwise the VPN's DNS would be saved as original.
    let backup_path = run.join("dns-backup");
    let backup = !is_file(&backup_path);
    if backup {
        let _ = fsx::write_file(&backup_path, b"", 0o600);
    }
    let services = ns_output(&["-listallnetworkservices"]);
    for svc in services.lines().skip(1) {
        let svc = svc.strip_prefix('*').unwrap_or(svc);
        if backup {
            let cur = current_list("-getdnsservers", svc);
            let curs = current_list("-getsearchdomains", svc);
            let _ = fsx::append(&backup_path, format!("{svc}\t{cur}\t{curs}\n").as_bytes());
        }
        log(&format!("$ networksetup -setdnsservers \"{svc}\" {}", dns.join(" ")));
        let mut a = vec!["-setdnsservers".to_string(), svc.to_string()];
        a.extend(dns.iter().cloned());
        ns_run(&a);
        if !doms.is_empty() {
            log(&format!("$ networksetup -setsearchdomains \"{svc}\" {}", doms.join(" ")));
            let mut a = vec!["-setsearchdomains".to_string(), svc.to_string()];
            a.extend(doms.iter().cloned());
            ns_run(&a);
        }
    }
}

fn down(run: &Path, log: &dyn Fn(&str)) {
    let backup_path = run.join("dns-backup");
    if !is_file(&backup_path) {
        return;
    }
    let data = std::fs::read(&backup_path).unwrap_or_default();
    for line in String::from_utf8_lossy(&data).lines() {
        let Some((svc, dns, doms)) = parse_backup_line(line) else { continue };
        log(&format!("$ networksetup -setdnsservers \"{svc}\" {}", dns.join(" ")));
        let mut a = vec!["-setdnsservers".to_string(), svc.clone()];
        a.extend(dns);
        ns_run(&a);
        let mut a = vec!["-setsearchdomains".to_string(), svc];
        a.extend(doms);
        ns_run(&a);
    }
    fsx::remove_file(&backup_path);
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
    fn tunnel_devices() {
        assert!(is_tunnel_dev("utun9") && is_tunnel_dev("ppp0"));
        assert!(!is_tunnel_dev("utun1;x") && !is_tunnel_dev("en0") && !is_tunnel_dev("ppp"));
    }
}
