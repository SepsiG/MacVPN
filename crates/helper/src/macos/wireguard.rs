//! WireGuard through Homebrew `wg-quick` (bash 4+, `wireguard-go`). The interface is named `mv<first 8 hex
//! digits of the id>`; wg-quick records the real `utunN` in `/var/run/wireguard/<iface>.name`.
//!
//! DNS is not left to wg-quick: it would keep the original DNS only in the memory of its background route monitor
//! and restore it asynchronously (unlogged) when that process ends. The `DNS =` lines are taken out of the conf
//! wg-quick gets, and the helper's DNS manager ([`crate::macos::dns`]) sets them after `wg-quick up` and gives
//! them up after `wg-quick down`, like OpenVPN's.

use crate::macos::ctx::{Ctx, R, tr};
use crate::macos::dns::{Dns, is_search_domain, log_over_limits};
use crate::macos::exec::Cmd;
use crate::macos::fsx;
use crate::macos::hook_dns::is_dns;
use crate::macos::paths::is_dir;

/// `wg_iface`: `mv` + the first 8 hex digits of the id, lower case.
pub fn iface_name(id: &str) -> String {
    let hex: String = id.chars().filter(|c| *c != '-').take(8).collect::<String>().to_ascii_lowercase();
    format!("mv{hex}")
}

/// `^mv[0-9a-f]{8}$`
pub fn is_iface(s: &str) -> bool {
    s.len() == 10 && s.starts_with("mv") && s[2..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `^utun[0-9]+$`
pub fn is_utun(s: &str) -> bool {
    s.strip_prefix("utun").is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// The conf for wg-quick without the `DNS =` lines of `[Interface]`, and their values: addresses are servers,
/// the rest search domains (wg-quick's own split). The config was validated before (`dns` values are addresses
/// or host names); a value of neither form is dropped.
pub fn strip_dns(conf: &str) -> (String, Dns) {
    let mut out = String::with_capacity(conf.len());
    let mut dns = Dns::default();
    let mut interface = false;
    for line in conf.split_inclusive('\n') {
        let stripped = line.split('#').next().unwrap_or_default();
        let (key, value) = stripped.split_once('=').unwrap_or((stripped, ""));
        let key = key.trim_matches([' ', '\t', '\r', '\n']);
        if key.starts_with('[') {
            interface = key.eq_ignore_ascii_case("[interface]");
        }
        if interface && key.eq_ignore_ascii_case("dns") && stripped.contains('=') {
            for v in value.split([',', ' ', '\t', '\r', '\n']).filter(|v| !v.is_empty()) {
                if is_dns(v) {
                    dns.servers.push(v.to_string());
                } else if is_search_domain(v.trim_end_matches('.')) {
                    dns.domains.push(v.trim_end_matches('.').to_string());
                }
            }
            continue;
        }
        out.push_str(line);
    }
    (out, dns)
}

/// `up_wireguard`
pub fn up(ctx: &mut Ctx) -> R {
    let Some(wgq) = ctx.find_tool("wg-quick") else {
        return Err(ctx.die(tr("wg-quick not found (brew install wireguard-tools)", &[])));
    };
    let Some(bash4) = ctx.find_tool("bash") else {
        return Err(ctx.die(tr("bash 4+ not found (brew install bash)", &[])));
    };
    if ctx.find_tool("wireguard-go").is_none() {
        return Err(ctx.die(tr("wireguard-go not found (brew install wireguard-tools)", &[])));
    }
    let run = ctx.run().to_path_buf();
    let iface = iface_name(&ctx.id);
    let conf = run.join(format!("{iface}.conf"));
    let mut dns = Dns::default();
    if let Ok(d) = std::fs::read(run.join("config")) {
        let (text, found) = strip_dns(&String::from_utf8_lossy(&d));
        let _ = fsx::write_file(&conf, text.as_bytes(), 0o600);
        dns = found;
    }
    let _ = fsx::write_line(&run.join("iface"), &iface);
    // wg-quick calls wg and wireguard-go from PATH: the brew bin is needed (system directories first).
    ctx.brew_path = true;
    ctx.wg_debug_env = ctx.a.debug;
    let cmd = Cmd::new(&bash4).arg(&wgq).arg("up").arg(&conf);
    if !ctx.run_direct(&cmd)? {
        if !ctx.dry() {
            fsx::remove_rf(&run);
        }
        return Err(ctx.die(tr("wg-quick up failed (details in the log)", &[])));
    }
    if ctx.a.debug {
        let wg = ctx.find_tool("wg").unwrap_or_default();
        ctx.run_logged(&Cmd::new(wg).arg("show").arg(&iface))?;
    }
    if !dns.servers.is_empty() && !ctx.dry() {
        // The DNS manager's limits (M-2): an oversized list is refused whole, the original DNS stays.
        if dns.within_limits() {
            ctx.dns_set(&dns);
        } else {
            log_over_limits(&dns, &ctx.log);
        }
    }
    Ok(())
}

/// `down_wireguard`
pub fn down(ctx: &mut Ctx) -> R<bool> {
    if !is_dir(ctx.run()) {
        ctx.no_running();
        return Ok(true);
    }
    let Some(wgq) = ctx.find_tool("wg-quick") else {
        return Err(ctx.die(tr("wg-quick not found", &[])));
    };
    let Some(bash4) = ctx.find_tool("bash") else {
        return Err(ctx.die(tr("bash 4+ not found", &[])));
    };
    let saved = fsx::read_trim(&ctx.run().join("iface"));
    let iface = saved.filter(|s| is_iface(s)).unwrap_or_else(|| iface_name(&ctx.id));
    ctx.brew_path = true;
    let conf = ctx.run().join(format!("{iface}.conf"));
    let ok = ctx.run_direct(&Cmd::new(&bash4).arg(&wgq).arg("down").arg(&conf))?;
    if ok && !ctx.dry() {
        ctx.dns_restore();
    }
    Ok(ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_names() {
        assert_eq!(iface_name("0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0"), "mv0f1e2d3c");
        assert!(is_iface("mv12345678") && !is_iface("mv1234567") && !is_iface("mv1234567G"));
        assert!(is_utun("utun12") && !is_utun("utun") && !is_utun("utun1x"));
    }

    #[test]
    fn dns_lines_are_taken_out_of_the_conf_for_wg_quick() {
        let conf = "[Interface]\nPrivateKey = k\nDNS = 10.0.0.53, fd00::53 # resolvers\ndns=corp.example,b.corp.example.\n\
                    Address = 10.0.0.2/32\n\n[Peer]\nPublicKey = p\nEndpoint = vpn.example.com:51820\n";
        let (out, dns) = strip_dns(conf);
        assert_eq!(
            out,
            "[Interface]\nPrivateKey = k\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = p\nEndpoint = vpn.example.com:51820\n"
        );
        assert_eq!(dns.servers, vec!["10.0.0.53", "fd00::53"]);
        assert_eq!(dns.domains, vec!["corp.example", "b.corp.example"]);
        let (same, none) = strip_dns("[Interface]\nPrivateKey = k\n# DNS = 1.1.1.1\n");
        assert_eq!(same, "[Interface]\nPrivateKey = k\n# DNS = 1.1.1.1\n");
        assert!(none.servers.is_empty() && none.domains.is_empty());
    }

    #[test]
    fn an_oversized_dns_line_is_over_the_managers_limits() {
        use crate::macos::dns::{MAX_DOMAINS, MAX_SERVERS};
        let doms: Vec<String> = (0..=MAX_DOMAINS).map(|i| format!("d{i}.corp.example")).collect();
        let conf = format!("[Interface]\nDNS = 10.0.0.53, {}\n", doms.join(", "));
        let (out, d) = strip_dns(&conf);
        assert_eq!(out, "[Interface]\n", "taken out of the conf for wg-quick in any case");
        assert_eq!(d.domains.len(), MAX_DOMAINS + 1);
        assert!(!d.within_limits());
        let srv: Vec<String> = (0..=MAX_SERVERS).map(|i| format!("10.0.0.{}", i + 1)).collect();
        assert!(!strip_dns(&format!("[Interface]\nDNS = {}\n", srv.join(","))).1.within_limits());
        assert!(strip_dns("[Interface]\nDNS = 10.0.0.53, corp.example\n").1.within_limits());
    }
}
