//! The certificates a connection's config carries (client-credential audit G3) and whether its private key needs
//! a password (G6): what the editor's "Certificates" section shows, the connection row's expiry warning, and the
//! "Private key password" field and prompt.
//!
//! - OpenVPN: `<cert>` (the client certificate, then its chain), `<ca>`, `<extra-certs>` (PEM) and the
//!   certificates a `<pkcs12>` stores unencrypted ([`crate::pkcs12`]: those OpenSSL encrypts need the password
//!   and are not shown).
//! - SSTP: the custom CA (`ca_pem`).
//! - IKEv2 (strongSwan): the certificates are files outside the config; the app reads them where it can
//!   ([`swanctl_files`] names them).
//!
//! Everything here only reads and shows: no signature or chain is checked.

use crate::models::VPNKind;
use crate::pkcs12;
use crate::validators::{OpenVPNValidator, SSTPConfig};
use crate::x509::{self, Certificate};

/// What a certificate is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The certificate the client authenticates with.
    Client,
    /// A CA the client trusts (or a CA in a chain).
    Ca,
    /// Another certificate of the chain (an intermediate in `<cert>` or `<extra-certs>`).
    Chain,
}

/// One certificate of a config, with where it comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigCertificate {
    pub role: Role,
    /// `<cert>`, `<ca>`, `<extra-certs>`, `<pkcs12>`, the SSTP CA (`ca`), or a swanctl file name.
    pub source: String,
    pub certificate: Certificate,
}

/// The certificates of a config.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigCertificates {
    pub certificates: Vec<ConfigCertificate>,
    /// A `<pkcs12>` whose certificates are encrypted (they need its password): the section says so.
    pub pkcs12_encrypted: bool,
}

impl ConfigCertificates {
    /// The earliest `notAfter` (Unix seconds) of the certificates, for the expiry warning.
    pub fn earliest_expiry(&self) -> Option<i64> {
        self.certificates.iter().map(|c| c.certificate.not_after).min()
    }
}

/// The certificates of `config` (a connection of `kind`).
pub fn of_config(kind: VPNKind, config: &str) -> ConfigCertificates {
    match kind {
        VPNKind::Openvpn => openvpn(config),
        VPNKind::Sstp => {
            let pem = SSTPConfig::parse(config).ca_pem;
            ConfigCertificates {
                certificates: x509::pem_certificates(&pem)
                    .into_iter()
                    .map(|certificate| ConfigCertificate { role: Role::Ca, source: "ca".into(), certificate })
                    .collect(),
                pkcs12_encrypted: false,
            }
        }
        VPNKind::Wireguard | VPNKind::Strongswan | VPNKind::L2tp | VPNKind::Cisco => ConfigCertificates::default(),
    }
}

fn openvpn(config: &str) -> ConfigCertificates {
    let outline = OpenVPNValidator::outline(config);
    let mut out = ConfigCertificates::default();
    for (block, text) in &outline.data {
        let source = format!("<{block}>");
        match block.as_str() {
            "cert" => {
                for (i, certificate) in x509::pem_certificates(text).into_iter().enumerate() {
                    let role = if i == 0 { Role::Client } else { Role::Chain };
                    out.certificates.push(ConfigCertificate { role, source: source.clone(), certificate });
                }
            }
            "ca" | "extra-certs" => {
                let role = if block == "ca" { Role::Ca } else { Role::Chain };
                for certificate in x509::pem_certificates(text) {
                    out.certificates.push(ConfigCertificate { role, source: source.clone(), certificate });
                }
            }
            "pkcs12" => {
                let Some(summary) = pkcs12::read_base64(text) else { continue };
                out.pkcs12_encrypted |= summary.encrypted_parts > 0 && summary.certificates.is_empty();
                let mut client_seen = false;
                for certificate in summary.certificates {
                    let role = if certificate.ca {
                        Role::Ca
                    } else if !client_seen {
                        client_seen = true;
                        Role::Client
                    } else {
                        Role::Chain
                    };
                    out.certificates.push(ConfigCertificate { role, source: source.clone(), certificate });
                }
            }
            _ => {}
        }
    }
    // The client certificate first, then the chain, then the CAs (stable within each).
    out.certificates.sort_by_key(|c| match c.role {
        Role::Client => 0,
        Role::Chain => 1,
        Role::Ca => 2,
    });
    out
}

/// The private key of an OpenVPN config needs a password: an encrypted PEM `<key>`, or a `<pkcs12>` that does not
/// open with an empty password (OpenVPN tries that first), or one that cannot be checked.
pub fn openvpn_key_needs_password(config: &str) -> bool {
    let outline = OpenVPNValidator::outline(config);
    if crate::importer::contains_encrypted_key(&outline.key) {
        return true;
    }
    outline
        .data
        .iter()
        .filter(|(block, _)| block == "pkcs12")
        .any(|(_, text)| pkcs12::read_base64(text).is_none_or(|s| s.needs_password()))
}

/// A `<pkcs12>` of the OpenVPN config is readable and does not open with an empty password (the import says to
/// enter its password; an unreadable one is only asked for at connect).
pub fn openvpn_pkcs12_protected(config: &str) -> bool {
    OpenVPNValidator::outline(config)
        .data
        .iter()
        .filter(|(block, _)| block == "pkcs12")
        .any(|(_, text)| pkcs12::read_base64(text).is_some_and(|s| s.password == pkcs12::Password::Needed))
}

/// The certificate files a strongSwan config names (`certs`, `cacerts` of its `local…` / `remote…` sections), as
/// `(is_ca, file name)` in config order, without duplicates. Only plain file names (swanctl looks them up in its
/// `x509` / `x509ca` folders); anything with a path is left out.
pub fn swanctl_files(config: &str) -> Vec<(bool, String)> {
    let mut out: Vec<(bool, String)> = Vec::new();
    for line in config.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let Some((key, value)) = line.split_once('=') else { continue };
        let is_ca = match key.trim() {
            "certs" => false,
            "cacerts" => true,
            _ => continue,
        };
        for name in value.split(',') {
            let name = name.trim().trim_matches('"').trim();
            let plain = !name.is_empty()
                && name.len() <= 255
                && !name.starts_with('.')
                && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | '+'));
            if plain && !out.iter().any(|(ca, n)| *ca == is_ca && n == name) {
                out.push((is_ca, name.to_string()));
            }
        }
    }
    out
}

/// The certificates of swanctl files the app could read: `(is_ca, file name, contents)` (PEM or DER).
pub fn of_swanctl_files(files: &[(bool, String, Vec<u8>)]) -> ConfigCertificates {
    let mut out = ConfigCertificates::default();
    for (is_ca, name, data) in files {
        let text = String::from_utf8_lossy(data);
        let mut certificates = x509::pem_certificates(&text);
        if certificates.is_empty()
            && let Some(c) = x509::parse_der(data)
        {
            certificates.push(c);
        }
        for certificate in certificates {
            let role = if *is_ca { Role::Ca } else { Role::Client };
            out.certificates.push(ConfigCertificate { role, source: name.clone(), certificate });
        }
    }
    out
}
