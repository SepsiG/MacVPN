//! IKEv2 (strongSwan) through NetworkManager: `network-manager-strongswan`, whose service is charon-nm (LinVPN
//! L-b, Task 9).
//!
//! The validator runs first (an invalid config is its error, [`Unsupported::invalid`]). Then the first connection
//! and its first child (the ones macOS initiates, and `ras::ikev2` translates for Windows) are read with the
//! validator's own scanner. The reader ([`Swan`], [`read`]) is a copy of the private one in `ras/ikev2.rs`: the
//! duplication is the price of not touching WinVPN's code.
//!
//! The `vpn.data` keys, `method` values and list syntax are pinned against `src/charon-nm/nm/nm_service.c` of
//! strongSwan **6.0.4** (Ubuntu 26.04 `strongswan 6.0.4-1ubuntu3.2`; the NM plugin is `network-manager-strongswan
//! 1.6.4-1`): `address`, `server-port`, `method` (`eap`, `psk`, `key`; charon-nm also knows `cert`, `agent`,
//! `smartcard`, `eap-tls`), `user`, `local-identity`, `remote-identity`, `certificate` (the gateway or CA
//! certificate; absent: charon-nm's CA directory), `usercert`, `userkey`, `virtual`, `encap`, `ipcomp`,
//! `proposal` + `ike` + `esp`, `local-ts`, `remote-ts`. Lists (`ike`, `esp`, `local-ts`, `remote-ts`) are
//! **semicolon**-separated there (`enumerator_create_token(…, ";", "")`), not comma-separated as in swanctl.
//! The one secret is `password`: the EAP password, the PSK (`method = psk`), or the private key's passphrase
//! (`method = key`; 6.0.4 has no `userkey-password` yet). charon-nm's PSK side is `psk` on both ends, the others
//! authenticate the server by certificate (`pubkey`). Without `remote-ts` charon-nm proposes `0.0.0.0/0` and
//! `::/0`: a full tunnel.
//!
//! Certificates (resolved point 18) come from LinVPN's credential folder `Caps::swanctl_dir`
//! (`$XDG_DATA_HOME/LinVPN/swanctl/{x509,x509ca,private}`): `certs = <file>` → `usercert = <dir>/x509/<file>`,
//! `userkey = <dir>/private/<stem>.key`; `cacerts = <file>` → `certificate = <dir>/x509ca/<file>`; none named and
//! exactly one file in `x509ca` → that one; otherwise charon-nm's system CAs and a warning. A key-signing config
//! without `certs` uses the client certificate imported in the app ([`ImportedCert`], client credential audit G4):
//! `usercert` / `userkey` name its two 0600 runtime files ([`CLIENT_CERT_FILE`], [`CLIENT_KEY_FILE`]) in the
//! connection's 0700 runtime directory, which the engine removes at disconnect. PEM only: charon-nm cannot load a
//! PKCS#12 file as `usercert`, so the app and the engine convert one first (`openssl pkcs12`).

use super::{
    ImportedCert, Input, NmPlan, NmValue, RuntimeFile, SERVICE_STRONGSWAN, SecretItem, SecretKey, SecretValue,
    Unsupported, dns,
};
use crate::client_cert::{ClientCert, Form};
use crate::l10n::{self, Arg};
use crate::models::SecretField;
use crate::netaddr::IpPrefix;
use crate::swift_str::ascii_lowercased;
use crate::validators::strongswan::{Context, Section, Visit};
use crate::validators::{ConfigValidator, StrongSwanValidator};
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::path::Path;

/// The keys of the first connection, its first `local` / `remote` sections and its first child (a repeated key:
/// the last value, as strongSwan reads it). Values are the items joined with a space. (Copy of `ras::ikev2`.)
#[derive(Default)]
struct Swan {
    connection: Option<String>,
    child: Option<String>,
    conn: HashMap<String, String>,
    local_sections: Vec<String>,
    local: HashMap<String, String>,
    remote_sections: Vec<String>,
    remote: HashMap<String, String>,
    child_keys: HashMap<String, String>,
}

/// The first connection and its first child, read from the sections (copy of `ras::ikev2::read`).
fn read(text: &str) -> Swan {
    let mut swan = Swan::default();
    StrongSwanValidator::visit(text, &mut |path: &[Section], event: Visit<'_>| {
        if path.len() < 2 || path[0].context != Context::Connections || path[1].context != Context::Conn {
            return;
        }
        let connection = swan.connection.get_or_insert_with(|| path[1].name.clone());
        if path[1].name != *connection {
            return;
        }
        let first_section = |names: &mut Vec<String>, name: &str| {
            if !names.iter().any(|n| n == name) {
                names.push(name.to_string());
            }
            names[0] == name
        };
        let in_child = path.len() == 4 && path[2].context == Context::Children && path[3].context == Context::Child;
        match event {
            Visit::Open => match path.len() {
                3 if path[2].context == Context::Local => {
                    first_section(&mut swan.local_sections, &path[2].name);
                }
                3 if path[2].context == Context::Remote => {
                    first_section(&mut swan.remote_sections, &path[2].name);
                }
                4 if in_child => {
                    swan.child.get_or_insert_with(|| path[3].name.clone());
                }
                _ => {}
            },
            Visit::Key(key, items) => {
                let value = items.join(" ");
                match path.len() {
                    2 => {
                        swan.conn.insert(key.to_string(), value);
                    }
                    3 if path[2].context == Context::Local => {
                        if first_section(&mut swan.local_sections, &path[2].name) {
                            swan.local.insert(key.to_string(), value);
                        }
                    }
                    3 if path[2].context == Context::Remote => {
                        if first_section(&mut swan.remote_sections, &path[2].name) {
                            swan.remote.insert(key.to_string(), value);
                        }
                    }
                    4 if in_child && swan.child.as_deref() == Some(path[3].name.as_str()) => {
                        swan.child_keys.insert(key.to_string(), value);
                    }
                    _ => {}
                }
            }
        }
    });
    swan
}

/// At most this many characters of a config value are quoted in a reason.
const MAX_QUOTED_CHARS: usize = 60;

/// "Not supported on Linux: `key = value`".
pub(crate) fn not_supported(key: &str, value: &str) -> String {
    let value = value.trim();
    let quoted = if value.chars().count() <= MAX_QUOTED_CHARS {
        value.to_string()
    } else {
        value.chars().take(MAX_QUOTED_CHARS).collect::<String>() + "…"
    };
    l10n::tr("Not supported on Linux: %@", &[Arg::Str(&format!("{key} = {quoted}"))])
}

/// A proposal list as charon-nm takes it. `default` (strongSwan's own list) cannot be named to charon-nm: then the
/// key is left out, so charon-nm's defaults apply.
fn proposals(value: Option<&String>) -> Option<Vec<&str>> {
    value.map(|v| list(v)).filter(|items| !items.is_empty() && !items.contains(&"default"))
}

/// The items of a swanctl list (`a, b` or `a,b`).
fn list(value: &str) -> Vec<&str> {
    value.split(',').map(str::trim).filter(|v| !v.is_empty()).collect()
}

/// The method charon-nm runs, from the local and remote `auth`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Method {
    Eap,
    Psk,
    Key,
}

impl Method {
    fn data(self) -> &'static str {
        match self {
            Method::Eap => "eap",
            Method::Psk => "psk",
            Method::Key => "key",
        }
    }
}

/// The plan of a `swanctl.conf`.
pub fn plan(input: &Input) -> Result<NmPlan, Unsupported> {
    let text = crate::swift_str::string_from_utf8_data(input.config.to_vec())
        .ok_or_else(|| Unsupported::invalid(vec![l10n::tr("The config is not UTF-8 text", &[])]))?;
    let issues = StrongSwanValidator.validate(&text);
    if !issues.is_empty() {
        return Err(Unsupported::invalid(issues.iter().map(|i| i.display()).collect()));
    }
    let swan = read(&text);
    if swan.connection.is_none() {
        return Err(Unsupported::invalid(vec![l10n::tr("Missing connections block", &[])]));
    }
    let caps = input.caps;
    let mut reasons = Vec::new();
    let mut warnings = Vec::new();
    let mut data: BTreeMap<String, String> = BTreeMap::new();
    let mut files = Vec::new();

    // The child's traffic selectors first: the split-tunnel reason leads when the plugin is too old.
    let remote_ts = selectors(&swan.child_keys, "remote_ts", &mut reasons);
    let local_ts = selectors(&swan.child_keys, "local_ts", &mut reasons);
    let full = remote_ts
        .as_ref()
        .is_none_or(|ts| ts.iter().any(|p| IpPrefix::parse(p).is_some_and(|p| p.len == 0 && p.addr.is_ipv4())));
    if !full && let Some(ts) = &remote_ts {
        if caps.strongswan_remote_ts {
            data.insert("remote-ts".into(), ts.join(";"));
        } else {
            reasons.push(l10n::tr(
                "Not supported on Linux by the installed network-manager-strongswan: %@ (a split tunnel needs a newer version)",
                &[Arg::Str(&format!("remote_ts = {}", ts.join(", ")))],
            ));
        }
    }
    if let Some(ts) = &local_ts {
        if caps.strongswan_remote_ts {
            data.insert("local-ts".into(), ts.join(";"));
        } else {
            reasons.push(not_supported("local_ts", &ts.join(", ")));
        }
    }

    match swan.conn.get("version").map(|v| v.trim()) {
        None | Some("0") | Some("2") => {}
        Some(other) => reasons.push(not_supported("version", other)),
    }
    let addrs = swan.conn.get("remote_addrs").map_or("", String::as_str);
    match list(addrs).as_slice() {
        [] => reasons.push(l10n::tr(
            "On Linux the server address is required: set remote_addrs to the server's name or address.",
            &[],
        )),
        [host] => {
            let range =
                host.split_once('-').is_some_and(|(a, b)| a.parse::<IpAddr>().is_ok() && b.parse::<IpAddr>().is_ok());
            if host.contains('/') || host.starts_with('%') || host.contains(' ') || range {
                reasons.push(not_supported("remote_addrs", addrs));
            } else {
                data.insert("address".into(), host.to_string());
            }
        }
        _ => reasons.push(l10n::tr("Not supported on Linux: more than one remote address", &[])),
    }
    if let Some(port) = swan.conn.get("remote_port").map(|p| p.trim())
        && port != "500"
    {
        data.insert("server-port".into(), port.to_string());
    }
    if swan.conn.get("vips").is_some_and(|v| !list(v).is_empty()) {
        data.insert("virtual".into(), "yes".into());
    }
    if swan.conn.get("encap").is_some_and(|v| ascii_lowercased(v.trim()) == "yes") {
        data.insert("encap".into(), "yes".into());
    }
    if swan.child_keys.get("ipcomp").is_some_and(|v| ascii_lowercased(v.trim()) == "yes") {
        data.insert("ipcomp".into(), "yes".into());
    }
    if let Some(mode) = swan.child_keys.get("mode")
        && ascii_lowercased(mode.trim()) != "tunnel"
    {
        reasons.push(not_supported("mode", mode));
    }
    let ike = proposals(swan.conn.get("proposals"));
    let esp = proposals(swan.child_keys.get("esp_proposals"));
    if ike.is_some() || esp.is_some() {
        data.insert("proposal".into(), "yes".into());
    }
    if let Some(ike) = ike {
        data.insert("ike".into(), ike.join(";"));
    }
    if let Some(esp) = esp {
        data.insert("esp".into(), esp.join(";"));
    }

    // Authentication: one round each way; charon-nm pairs EAP and a client key with a server certificate, and a
    // PSK with a PSK.
    if swan.local_sections.len() > 1 || swan.remote_sections.len() > 1 {
        reasons.push(l10n::tr("Not supported on Linux: more than one authentication round", &[]));
    }
    let local_auth = swan.local.get("auth").map_or("pubkey", |v| v.trim());
    let remote_auth = swan.remote.get("auth").map_or("pubkey", |v| v.trim());
    let method = match ascii_lowercased(local_auth).as_str() {
        "eap-mschapv2" | "eap" => Some(Method::Eap),
        "psk" => Some(Method::Psk),
        "pubkey" => Some(Method::Key),
        _ => {
            reasons.push(not_supported("local auth", local_auth));
            None
        }
    };
    if let Some(method) = method {
        let wanted = if method == Method::Psk { "psk" } else { "pubkey" };
        if ascii_lowercased(remote_auth) != wanted {
            reasons.push(not_supported("remote auth", remote_auth));
        }
        data.insert("method".into(), method.data().into());
    }

    let id = |v: Option<&String>| v.map(|v| v.trim().to_string()).filter(|v| !v.is_empty() && !v.starts_with('%'));
    let local_id = id(swan.local.get("id"));
    let user = match method {
        Some(Method::Eap) => id(swan.local.get("eap_id")).or_else(|| local_id.clone()),
        _ => local_id.clone(),
    };
    if let Some(user) = &user {
        data.insert("user".into(), user.clone());
    }
    if let Some(local_id) = local_id.filter(|l| Some(l) != user.as_ref()) {
        data.insert("local-identity".into(), local_id);
    }
    if let Some(remote_id) = id(swan.remote.get("id")) {
        data.insert("remote-identity".into(), remote_id);
    }

    // Certificates from LinVPN's credential folder (resolved point 18).
    let dir = caps.swanctl_dir.as_deref();
    if method == Some(Method::Key) {
        match (swan.local.get("certs").map(|v| list(v)), dir) {
            (Some(certs), Some(dir)) if certs.len() == 1 => {
                let cert = super::linux_path(dir, &["x509", certs[0]]);
                let stem = Path::new(certs[0]).file_stem().map(|s| s.to_string_lossy().into_owned());
                data.insert("usercert".into(), cert);
                if let Some(stem) = stem {
                    let key = super::linux_path(dir, &["private", &format!("{stem}.key")]);
                    data.insert("userkey".into(), key);
                }
            }
            (Some(certs), Some(_)) if certs.len() > 1 => {
                reasons.push(not_supported("certs", &certs.join(", ")));
            }
            (Some(certs), None) if !certs.is_empty() => {
                reasons.push(l10n::tr("LinVPN's strongSwan credential folder is not available", &[]));
            }
            _ => imported_cert(input, &mut data, &mut files, &mut reasons),
        }
    }
    if method.is_some() && method != Some(Method::Psk) {
        let named = swan.remote.get("cacerts").or_else(|| swan.remote.get("cacert")).map(|v| list(v));
        match (named, dir) {
            (Some(cas), Some(dir)) if cas.len() == 1 => {
                data.insert("certificate".into(), super::linux_path(dir, &["x509ca", cas[0]]));
            }
            (Some(cas), _) if cas.len() > 1 => reasons.push(not_supported("cacerts", &cas.join(", "))),
            (Some(cas), None) if !cas.is_empty() => {
                reasons.push(l10n::tr("LinVPN's strongSwan credential folder is not available", &[]));
            }
            (_, Some(dir)) if caps.swanctl_ca_files.len() == 1 => {
                let ca = super::linux_path(dir, &["x509ca", &caps.swanctl_ca_files[0]]);
                data.insert("certificate".into(), ca);
            }
            _ => warnings.push(l10n::tr(
                "No CA certificate is named and LinVPN's strongSwan folder (x509ca) does not hold exactly one: the system's CA certificates check the server.",
                &[],
            )),
        }
    }

    if !reasons.is_empty() {
        return Err(Unsupported::linux(reasons));
    }
    let Some(method) = method else { return Err(Unsupported::linux(reasons)) };
    data.insert("password-flags".into(), caps.secret_mode.flags().to_string());
    let field = match method {
        Method::Eap => SecretField::Password,
        Method::Psk => SecretField::Psk,
        Method::Key => SecretField::KeyPassword,
    };
    let secrets =
        vec![SecretItem { setting: "vpn", key: SecretKey::Plain("password".into()), value: SecretValue::Field(field) }];

    let mut settings = super::Settings::new();
    settings
        .insert("connection".into(), super::connection_section(input.connection, input.uid, input.user, "vpn", None));
    settings.insert("vpn".into(), super::vpn_section(SERVICE_STRONGSWAN, None, data));
    let mut ipv4 = dns::section_extras(full, &[]);
    ipv4.insert("method".into(), NmValue::Str("auto".into()));
    ipv4.insert("never-default".into(), NmValue::Bool(!full));
    settings.insert("ipv4".into(), ipv4);
    let mut ipv6 = BTreeMap::new();
    ipv6.insert("method".into(), NmValue::Str("auto".into()));
    ipv6.insert("never-default".into(), NmValue::Bool(!full));
    settings.insert("ipv6".into(), ipv6);

    Ok(NmPlan {
        kind: input.connection.kind,
        service_type: Some(SERVICE_STRONGSWAN),
        settings,
        secrets,
        files,
        iface: None,
        summary: None,
        warnings,
    })
}

/// The runtime files of the client certificate imported in the app (client credential audit G4).
pub const CLIENT_CERT_FILE: &str = "client-cert.pem";
pub const CLIENT_KEY_FILE: &str = "client-key.pem";

/// A key-signing config that names no `certs` of its own: the client certificate imported in the app (as macOS'
/// root layer 12 uses it for the `auth = pubkey` rounds without `certs`). charon-nm reads `usercert` / `userkey`
/// as files, so the certificate (PEM) and its key (its PEM block as imported, encrypted or not) become two private
/// runtime files; the key's passphrase stays the `password` secret. charon-nm loads `usercert` as an X.509
/// certificate only: LinVPN converts a PKCS#12 file to PEM at import, and one restored from a Mac at connect (the
/// engine, before planning), so only the editor's notes see the PKCS#12 form ([`ImportedCert::Known`]).
fn imported_cert(
    input: &Input,
    data: &mut BTreeMap<String, String>,
    files: &mut Vec<RuntimeFile>,
    reasons: &mut Vec<String>,
) {
    match (input.client_cert, input.client_cert.form()) {
        (_, None) => reasons.push(l10n::tr(
            "On Linux a client certificate is needed: import it with Import Client Certificate…, or set certs to its file in LinVPN's strongSwan folder (x509).",
            &[],
        )),
        // The engine converts a PKCS#12 file (one restored from a Mac) to PEM before planning; unconverted it
        // cannot be used.
        (ImportedCert::Cert(_), Some(Form::Pkcs12)) => reasons.push(pkcs12_not_supported()),
        (_, Some(_)) => {
            data.insert("usercert".into(), super::linux_path(input.runtime_dir, &[CLIENT_CERT_FILE]));
            data.insert("userkey".into(), super::linux_path(input.runtime_dir, &[CLIENT_KEY_FILE]));
            if let ImportedCert::Cert(ClientCert::Pem { cert, key, .. }) = input.client_cert {
                let cert_pem = crate::x509::to_pem(cert).into_bytes();
                files.push(RuntimeFile { name: CLIENT_CERT_FILE.into(), data: cert_pem.into() });
                files.push(RuntimeFile { name: CLIENT_KEY_FILE.into(), data: key.as_bytes().to_vec().into() });
            }
        }
    }
}

/// The localized reason (and import refusal) for a PKCS#12 client certificate on Linux.
pub fn pkcs12_not_supported() -> String {
    l10n::tr(
        "On Linux strongSwan's NetworkManager plugin cannot open a PKCS#12 file: import the client certificate and its private key as PEM files.",
        &[],
    )
}

/// A child's traffic selectors as charon-nm takes them (CIDR prefixes). `None`: absent or only `dynamic`. A
/// selector with a protocol or port, or a range, is a reason.
fn selectors(keys: &HashMap<String, String>, key: &str, reasons: &mut Vec<String>) -> Option<Vec<String>> {
    let value = keys.get(key)?;
    let mut out = Vec::new();
    for item in list(value) {
        if item == "dynamic" {
            continue;
        }
        match IpPrefix::parse(item) {
            Some(_) => out.push(item.to_string()),
            None => {
                reasons.push(not_supported(key, item));
                return None;
            }
        }
    }
    (!out.is_empty()).then_some(out)
}
