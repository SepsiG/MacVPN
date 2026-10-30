//! SSTP through NetworkManager: `network-manager-sstp` (its service starts pppd with sstpc as the pty; LinVPN L-b,
//! Task 9).
//!
//! The validator runs first (an invalid config is its error, [`Unsupported::invalid`]); the validated `.sstp`
//! config is then read with `SSTPConfig::parse`. The `vpn.data` keys are pinned against `src/nm-sstp-service.c`'s
//! `valid_properties[]` and `shared/nm-service-defines.h` of network-manager-sstp **1.3.2** (Ubuntu 26.04
//! `network-manager-sstp 1.3.2-1build6`): `gateway` (`host`, `host:port`, IPv6 in brackets; the string goes
//! into sstpc's command line, so only the validator's host characters reach it), `user`, `password-flags`,
//! `connection-type = password`, `ca-cert` (sstpc `--ca-cert`; absent: the system CAs), `ignore-cert-warn`
//! (sstpc `--cert-warn`), `tls-ext` (sstpc `--tls-ext`, SNI, as macOS starts it), `refuse-pap`, `refuse-chap`,
//! `refuse-mschap`, `refuse-eap` (MS-CHAPv2 only, as macOS's pppd options). The secret is `password`.
//!
//! `cert = ca` writes the inline CA as the runtime file `sstp-ca.pem`; `cert = insecure` is allowed with a
//! warning (as on macOS); `route_all = no` → `never-default`; `peer_dns = no` → `ignore-auto-dns` (NM honours it
//! exactly, resolved point 16's DNS note). A split tunnel carries the `user.data` mark of the class-based route
//! (`classful_route_section`).

use super::{Input, NmPlan, NmValue, RuntimeFile, SERVICE_SSTP, SecretItem, SecretKey, SecretValue, Unsupported, dns};
use crate::l10n;
use crate::models::SecretField;
use crate::validators::sstp::DEFAULT_PORT;
use crate::validators::{CertMode, ConfigValidator, SSTPConfig, SSTPValidator};
use std::collections::BTreeMap;
use std::net::Ipv6Addr;
use zeroize::Zeroizing;

/// The runtime file of `cert = ca`.
pub const CA_FILE: &str = "sstp-ca.pem";

/// The plan of an `.sstp` config.
pub fn plan(input: &Input) -> Result<NmPlan, Unsupported> {
    let text = crate::swift_str::string_from_utf8_data(input.config.to_vec())
        .ok_or_else(|| Unsupported::invalid(vec![l10n::tr("The config is not UTF-8 text", &[])]))?;
    let issues = SSTPValidator.validate(&text);
    if !issues.is_empty() {
        return Err(Unsupported::invalid(issues.iter().map(|i| i.display()).collect()));
    }
    let c = SSTPConfig::parse(&text);

    let host = if c.server.parse::<Ipv6Addr>().is_ok() { format!("[{}]", c.server) } else { c.server.clone() };
    let gateway = if c.port == DEFAULT_PORT { host } else { format!("{host}:{}", c.port) };
    let mut data = BTreeMap::new();
    data.insert("gateway".to_string(), gateway);
    data.insert("user".to_string(), c.user.clone());
    data.insert("connection-type".to_string(), "password".to_string());
    data.insert("password-flags".to_string(), input.caps.secret_mode.flags().to_string());
    data.insert("tls-ext".to_string(), "yes".to_string());
    for refuse in ["refuse-pap", "refuse-chap", "refuse-mschap", "refuse-eap"] {
        data.insert(refuse.to_string(), "yes".to_string());
    }
    let mut files = Vec::new();
    let mut warnings = Vec::new();
    match c.cert {
        CertMode::System => {}
        CertMode::Ca => {
            let pem = format!("{}\n", c.ca_pem);
            files.push(RuntimeFile { name: CA_FILE.into(), data: Zeroizing::new(pem.into_bytes()) });
            data.insert("ca-cert".to_string(), super::linux_path(input.runtime_dir, &[CA_FILE]));
        }
        CertMode::Insecure => {
            data.insert("ignore-cert-warn".to_string(), "yes".to_string());
            warnings.push(l10n::tr("Without verification the server's certificate is not checked.", &[]));
        }
    }

    let mut settings = super::Settings::new();
    settings
        .insert("connection".into(), super::connection_section(input.connection, input.uid, input.user, "vpn", None));
    settings.insert("vpn".into(), super::vpn_section(SERVICE_SSTP, Some(&c.user), data));
    let full = c.route_all;
    let mut ipv4 = if c.peer_dns { dns::section_extras(full, &[]) } else { BTreeMap::new() };
    let mut ipv6 = BTreeMap::new();
    for section in [&mut ipv4, &mut ipv6] {
        section.insert("method".into(), NmValue::Str("auto".into()));
        section.insert("never-default".into(), NmValue::Bool(!full));
        if !c.peer_dns {
            section.insert("ignore-auto-dns".into(), NmValue::Bool(true));
        }
    }
    settings.insert("ipv4".into(), ipv4);
    settings.insert("ipv6".into(), ipv6);
    if !full {
        // The split tunnel's class-based route (Windows' and macOS' PPP), added by the dispatcher script.
        settings.insert("user".into(), super::classful_route_section());
    }

    Ok(NmPlan {
        kind: input.connection.kind,
        service_type: Some(SERVICE_SSTP),
        settings,
        secrets: vec![SecretItem {
            setting: "vpn",
            key: SecretKey::Plain("password".into()),
            value: SecretValue::Field(SecretField::Password),
        }],
        files,
        iface: None,
        summary: None,
        warnings,
    })
}
