//! **Trust This CA in Windows…** (WinVPN 2c Task 12), the pure part: the first certificate of a PEM text (an SSTP
//! config's `<ca>` block, or a PEM file the user picked for IKEv2) read for the confirmation an administrator sees
//! before the computer trusts it: the subject, the validity and the SHA-256 fingerprint, plus the SHA-1 thumbprint
//! Windows' certificate stores are searched by. Only a CA certificate (basicConstraints `cA = TRUE`) that is valid
//! now is accepted.
//!
//! The PEM is untrusted text (a team catalog or an imported file can carry it): it is read by the core's strict,
//! bounded DER reader ([`macvpn_core::x509`]: definite lengths of at most four bytes, every element inside its
//! parent, nothing after the certificate; every text cut and freed of control characters, invisible format
//! characters shown escaped). Nothing here decides trust: Windows checks the certificate itself when the elevated
//! step (`win::admin_steps`) adds it and whenever a VPN uses it.

use macvpn_core::l10n;
use macvpn_core::x509;
use macvpn_platform_api::CaSummary;

/// A CA certificate ready to be trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaCert {
    /// The certificate (DER), exactly as the elevated step adds it.
    pub der: Vec<u8>,
    pub summary: CaSummary,
    /// The SHA-1 thumbprint (Windows' `CERT_SHA1_HASH_PROP_ID`): the key the store check searches by. Not a
    /// security decision: a match only says the store holds this exact certificate.
    pub sha1: [u8; 20],
}

/// The warning of the confirmation. WinVPN adds the CA for server and client authentication only (M-1 of the 2.0.0
/// security review): never for code signing.
pub fn warning() -> String {
    l10n::tr(
        "Every program on this PC will trust server and client certificates from this CA (not software it signs).",
        &[],
    )
}

fn no_certificate() -> String {
    l10n::tr("The text contains no readable certificate.", &[])
}

fn not_a_ca() -> String {
    l10n::tr("This certificate is not a CA certificate.", &[])
}

fn not_valid_now() -> String {
    l10n::tr("This CA certificate has expired or is not valid yet.", &[])
}

/// The first certificate of `pem` as a CA certificate valid at `now` (Unix seconds), or why it cannot be trusted.
pub fn read(pem: &str, now: i64) -> Result<CaCert, String> {
    let der = x509::first_pem_der(pem).ok_or_else(no_certificate)?;
    read_der(&der, now)
}

/// The certificate `der` as a CA certificate valid at `now` (Unix seconds), or why it cannot be trusted: the checks
/// of [`read`], again in the elevated step on the file WinVPN staged.
pub fn read_der(der: &[u8], now: i64) -> Result<CaCert, String> {
    let cert = x509::parse_der(der).ok_or_else(no_certificate)?;
    if !cert.ca {
        return Err(not_a_ca());
    }
    if now < cert.not_before || now > cert.not_after {
        return Err(not_valid_now());
    }
    Ok(CaCert {
        summary: CaSummary {
            subject: cert.subject,
            not_before: cert.not_before,
            not_after: cert.not_after,
            sha256: cert.sha256,
        },
        sha1: cert.sha1,
        der: cert.der,
    })
}

/// SHA-1 of `data` (the core's; kept here for the callers of this module).
pub fn sha1(data: &[u8]) -> [u8; 20] {
    x509::sha1(data)
}
