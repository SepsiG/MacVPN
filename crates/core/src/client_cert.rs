//! **Import Client Certificate…** of an IKEv2 (strongSwan) connection (client credential audit G4): a PKCS#12 file,
//! or PEM text with the client certificate and its private key (one file or several), checked strictly and kept as
//! one vault secret ([`crate::models::SecretField::ClientCert`]). At connect the app sends it to the root layer in
//! the `up` frame (`x509=` + `private=`, or `pkcs12=`, base64); the root layer writes it into the connection's
//! root-only run directory, where `swanctl --load-all` reads it (root layer 12). Nothing is written into a folder
//! of the user.
//!
//! - **PEM:** every block is decoded (strict base64, the `END` label matching the `BEGIN` one) and checked:
//!   `CERTIFICATE` (a DER `Certificate`: `tbsCertificate`, `signatureAlgorithm`, `signatureValue`, nothing after
//!   it), exactly one private key (`PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`, or OpenSSL's traditional `RSA PRIVATE
//!   KEY` / `EC PRIVATE KEY`, plain or with `Proc-Type: 4,ENCRYPTED` and `DEK-Info`), and `EC PARAMETERS` (skipped).
//!   Any other block is refused; text outside the blocks (OpenSSL's "Bag Attributes") is ignored. The client
//!   certificate is the only one that is not a CA (basicConstraints `cA`); other certificates (the CA, the chain)
//!   are not kept, and the import says how many were left out. Only the certificate (DER) and the key (its block
//!   re-encoded) are kept.
//! - **PKCS#12:** a DER (or BER) `PFX` with version 3 whose `authSafe` is PKCS#7 `data` or `signedData`. It is kept
//!   as it is: no PKCS#12 code exists here (no new crypto crate), swanctl opens it with the key password.
//!
//! The DER reader is bounded: definite lengths of at most four bytes (the PKCS#12 outer layers may also be
//! indefinite, as Windows writes them), every element inside its parent. Messages never quote the input. Key
//! material is held in [`Zeroizing`] buffers and has no `Debug` output.

use crate::l10n;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The largest file read (certificates, keys and PKCS#12 files of a client are a few kilobytes).
pub const MAX_FILE_BYTES: usize = 16 * 1024;
/// At most this many files in one import (a certificate, a key, a chain file).
pub const MAX_FILES: usize = 4;
/// At most this many PEM blocks in all.
const MAX_BLOCKS: usize = 32;

/// How the credential was imported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Form {
    Pem,
    Pkcs12,
}

/// A checked client credential.
#[derive(Clone, PartialEq, Eq)]
pub enum ClientCert {
    /// The client certificate (DER) and its private key (one PEM block, re-encoded).
    Pem { cert: Vec<u8>, key: Zeroizing<String>, encrypted: bool },
    /// A PKCS#12 file as it was.
    Pkcs12 { der: Zeroizing<Vec<u8>> },
}

impl std::fmt::Debug for ClientCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientCert")
            .field("form", &self.form())
            .field("needs_password", &self.needs_password())
            .finish()
    }
}

/// What the editor shows (public facts only).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub form: Form,
    /// SHA-256 of the certificate (PEM) or of the PKCS#12 file, upper-case hex pairs with colons.
    pub sha256: String,
    /// The key is encrypted (always for PKCS#12): the connection needs the private key password.
    pub needs_password: bool,
    /// PEM: the client certificate (DER; public), for the editor's "Certificates" section. Not in the JSON.
    #[serde(skip)]
    pub certificate: Option<Vec<u8>>,
}

/// [`import`]'s result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Imported {
    pub cert: ClientCert,
    /// Certificates of the PEM text that were not kept (the CA, the chain).
    pub ignored_certificates: usize,
}

const PEM_PREFIX: &str = "pem:";
const PKCS12_PREFIX: &str = "p12:";

fn unreadable() -> String {
    l10n::tr("Choose a PKCS#12 file (.p12, .pfx) or a PEM certificate with its private key.", &[])
}

/// Checks the chosen files (each at most [`MAX_FILE_BYTES`], at most [`MAX_FILES`]): one PKCS#12 file, or PEM text
/// files that together hold the client certificate and exactly one private key.
pub fn import(files: &[&[u8]]) -> Result<Imported, String> {
    if files.is_empty() || files.len() > MAX_FILES {
        return Err(unreadable());
    }
    if files.iter().any(|f| f.len() > MAX_FILE_BYTES) {
        return Err(l10n::tr("A client certificate file may be 16 KB at most.", &[]));
    }
    if files.iter().any(|f| f.first() == Some(&0x30)) {
        if files.len() != 1 {
            return Err(l10n::tr("Import a PKCS#12 file on its own.", &[]));
        }
        let der = files[0];
        if !is_pkcs12(der) {
            return Err(l10n::tr("The PKCS#12 file is damaged.", &[]));
        }
        return Ok(Imported {
            cert: ClientCert::Pkcs12 { der: Zeroizing::new(der.to_vec()) },
            ignored_certificates: 0,
        });
    }
    let mut blocks = Vec::new();
    for f in files {
        let text = std::str::from_utf8(f).map_err(|_| unreadable())?;
        if text.contains('\0') {
            return Err(unreadable());
        }
        blocks.extend(pem_blocks(text).ok_or_else(damaged_pem)?);
        if blocks.len() > MAX_BLOCKS {
            return Err(damaged_pem());
        }
    }
    from_blocks(blocks)
}

fn damaged_pem() -> String {
    l10n::tr("The PEM text is damaged or holds a block that is not a certificate or a private key.", &[])
}

fn from_blocks(blocks: Vec<Block>) -> Result<Imported, String> {
    let mut certs: Vec<(Vec<u8>, bool)> = Vec::new();
    let mut keys: Vec<(String, bool)> = Vec::new();
    for b in blocks {
        match b.label.as_str() {
            "CERTIFICATE" => {
                let is_ca = certificate(&b.data).ok_or_else(damaged_pem)?;
                certs.push((b.data.to_vec(), is_ca));
            }
            "PRIVATE KEY" | "ENCRYPTED PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY" => {
                let encrypted = key_block(&b).ok_or_else(damaged_pem)?;
                keys.push((b.encode(), encrypted));
            }
            "EC PARAMETERS" => {
                whole(&b.data).ok_or_else(damaged_pem)?;
            }
            _ => return Err(damaged_pem()),
        }
    }
    if certs.is_empty() {
        return Err(l10n::tr("The PEM text holds no certificate.", &[]));
    }
    if keys.is_empty() {
        return Err(l10n::tr("The PEM text holds no private key.", &[]));
    }
    if keys.len() > 1 {
        return Err(l10n::tr("The PEM text holds more than one private key.", &[]));
    }
    let clients: Vec<usize> = (0..certs.len()).filter(|&i| !certs[i].1).collect();
    let leaf = match (clients.as_slice(), certs.len()) {
        ([one], _) => *one,
        ([], 1) => 0,
        _ => {
            return Err(l10n::tr(
                "The PEM text holds more than one client certificate: choose the certificate that belongs to the key.",
                &[],
            ));
        }
    };
    let ignored_certificates = certs.len() - 1;
    let (key, encrypted) = keys.remove(0);
    let cert = certs.swap_remove(leaf).0;
    Ok(Imported { cert: ClientCert::Pem { cert, key: Zeroizing::new(key), encrypted }, ignored_certificates })
}

impl ClientCert {
    pub fn form(&self) -> Form {
        match self {
            ClientCert::Pem { .. } => Form::Pem,
            ClientCert::Pkcs12 { .. } => Form::Pkcs12,
        }
    }

    /// The connection needs the private key password: an encrypted PEM key, or any PKCS#12 file (its password
    /// may be empty, but it cannot be known without opening it).
    pub fn needs_password(&self) -> bool {
        match self {
            ClientCert::Pem { encrypted, .. } => *encrypted,
            ClientCert::Pkcs12 { .. } => true,
        }
    }

    pub fn summary(&self) -> Summary {
        let digest = match self {
            ClientCert::Pem { cert, .. } => Sha256::digest(cert),
            ClientCert::Pkcs12 { der } => Sha256::digest(der.as_slice()),
        };
        let sha256 = digest.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(":");
        let certificate = match self {
            ClientCert::Pem { cert, .. } => Some(cert.clone()),
            ClientCert::Pkcs12 { .. } => None,
        };
        Summary { form: self.form(), sha256, needs_password: self.needs_password(), certificate }
    }

    /// The vault value: one line (`pem:<certificate>:<key block>` or `p12:<file>`, each part base64).
    pub fn stored(&self) -> Zeroizing<String> {
        match self {
            ClientCert::Pem { cert, key, .. } => {
                let key64 = Zeroizing::new(STANDARD.encode(key.as_bytes()));
                Zeroizing::new(format!("{PEM_PREFIX}{}:{}", STANDARD.encode(cert), key64.as_str()))
            }
            ClientCert::Pkcs12 { der } => Zeroizing::new(format!("{PKCS12_PREFIX}{}", STANDARD.encode(der.as_slice()))),
        }
    }

    /// A vault value of [`Self::stored`], checked again as on import. `None`: not one.
    pub fn from_stored(value: &str) -> Option<ClientCert> {
        if let Some(rest) = value.strip_prefix(PKCS12_PREFIX) {
            let der = Zeroizing::new(STANDARD.decode(rest).ok()?);
            return (der.len() <= MAX_FILE_BYTES && is_pkcs12(&der)).then_some(ClientCert::Pkcs12 { der });
        }
        let (cert64, key64) = value.strip_prefix(PEM_PREFIX)?.split_once(':')?;
        let cert = STANDARD.decode(cert64).ok()?;
        let key = Zeroizing::new(STANDARD.decode(key64).ok()?);
        if cert.len() > MAX_FILE_BYTES || key.len() > MAX_FILE_BYTES {
            return None;
        }
        let key_text = std::str::from_utf8(&key).ok()?;
        let blocks = pem_blocks(key_text)?;
        let [block] = blocks.as_slice() else { return None };
        if block.label == "CERTIFICATE" || block.label == "EC PARAMETERS" {
            return None;
        }
        let encrypted = key_block(block)?;
        certificate(&cert)?;
        Some(ClientCert::Pem { cert, key: Zeroizing::new(block.encode()), encrypted })
    }

    /// The `up` frame's lines (root layer 12): `x509=` and `private=`, or `pkcs12=`, each base64, each ending in
    /// `\n`.
    pub fn frame_lines(&self) -> Zeroizing<String> {
        match self {
            ClientCert::Pem { cert, key, .. } => {
                let key64 = Zeroizing::new(STANDARD.encode(key.as_bytes()));
                Zeroizing::new(format!("x509={}\nprivate={}\n", STANDARD.encode(cert), key64.as_str()))
            }
            ClientCert::Pkcs12 { der } => Zeroizing::new(format!("pkcs12={}\n", STANDARD.encode(der.as_slice()))),
        }
    }
}

/// The frame lines of a stored value (an unreadable one: none).
pub fn frame_lines_of_stored(value: &str) -> Zeroizing<String> {
    ClientCert::from_stored(value).map(|c| c.frame_lines()).unwrap_or_default()
}

// MARK: - PEM

/// One PEM block.
struct Block {
    label: String,
    /// `Proc-Type` and `DEK-Info` (a traditional encrypted key only).
    headers: Vec<(String, String)>,
    data: Zeroizing<Vec<u8>>,
}

impl Block {
    /// The block in its canonical form (64 base64 characters a line).
    fn encode(&self) -> String {
        let body = Zeroizing::new(STANDARD.encode(self.data.as_slice()));
        let mut out = format!("-----BEGIN {}-----\n", self.label);
        for (k, v) in &self.headers {
            out.push_str(&format!("{k}: {v}\n"));
        }
        if !self.headers.is_empty() {
            out.push('\n');
        }
        for chunk in body.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
            out.push('\n');
        }
        out.push_str(&format!("-----END {}-----\n", self.label));
        out
    }
}

fn is_label(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b' ')
}

/// The blocks of a PEM text. `None`: a broken block (no matching `END`, bad base64, a stray `-----` line).
fn pem_blocks(text: &str) -> Option<Vec<Block>> {
    let mut blocks = Vec::new();
    let mut lines = text.split('\n').map(|l| l.trim_end_matches(['\r', ' ', '\t']));
    while let Some(line) = lines.next() {
        let line = line.trim_start();
        if !line.starts_with("-----") {
            continue;
        }
        let label = line.strip_prefix("-----BEGIN ")?.strip_suffix("-----")?;
        if !is_label(label) {
            return None;
        }
        let end = format!("-----END {label}-----");
        let mut headers = Vec::new();
        let mut body = Zeroizing::new(String::new());
        let mut in_headers = true;
        let mut closed = false;
        for line in lines.by_ref() {
            let line = line.trim_start();
            if line == end {
                closed = true;
                break;
            }
            if in_headers && let Some((k, v)) = line.split_once(':') {
                if headers.len() >= 2 {
                    return None;
                }
                headers.push((k.trim().to_string(), v.trim().to_string()));
                continue;
            }
            if in_headers && line.is_empty() && !headers.is_empty() {
                in_headers = false;
                continue;
            }
            in_headers = false;
            if line.is_empty() || !line.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=')) {
                return None;
            }
            body.push_str(line);
        }
        if !closed || body.is_empty() {
            return None;
        }
        let data = Zeroizing::new(STANDARD.decode(body.as_bytes()).ok()?);
        blocks.push(Block { label: label.to_string(), headers, data });
        if blocks.len() > MAX_BLOCKS {
            return None;
        }
    }
    Some(blocks)
}

/// A private key block: `Some(encrypted)` when well-formed.
fn key_block(b: &Block) -> Option<bool> {
    match b.label.as_str() {
        "PRIVATE KEY" | "ENCRYPTED PRIVATE KEY" => {
            (b.headers.is_empty() && whole(&b.data).is_some_and(|(t, _)| t == 0x30)).then_some(b.label.starts_with('E'))
        }
        "RSA PRIVATE KEY" | "EC PRIVATE KEY" => {
            if b.headers.is_empty() {
                return whole(&b.data).is_some_and(|(t, _)| t == 0x30).then_some(false);
            }
            let [(p, pv), (d, dv)] = b.headers.as_slice() else { return None };
            let dek = dv.split_once(',').filter(|(alg, iv)| {
                !alg.is_empty()
                    && alg.len() <= 32
                    && alg.bytes().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'-')
                    && (16..=64).contains(&iv.len())
                    && iv.len().is_multiple_of(2)
                    && iv.bytes().all(|c| c.is_ascii_hexdigit())
            });
            (p == "Proc-Type" && pv == "4,ENCRYPTED" && d == "DEK-Info" && dek.is_some() && b.data.len() >= 16)
                .then_some(true)
        }
        _ => None,
    }
}

// MARK: - DER

/// One element of `data`: (tag, content, rest). Definite lengths only (at most four length bytes, minimal).
fn element(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (tag, len, header) = header(data)?;
    let len = len?;
    let rest = &data[header..];
    (rest.len() >= len).then(|| (tag, &rest[..len], &rest[len..]))
}

/// The tag, the length (`None`: indefinite) and the header's length.
fn header(data: &[u8]) -> Option<(u8, Option<usize>, usize)> {
    let (&tag, rest) = data.split_first()?;
    if tag & 0x1F == 0x1F {
        return None;
    }
    let (&first, rest) = rest.split_first()?;
    if first < 0x80 {
        return Some((tag, Some(usize::from(first)), 2));
    }
    if first == 0x80 {
        return Some((tag, None, 2));
    }
    let n = usize::from(first & 0x7F);
    if n > 4 || rest.len() < n || rest[0] == 0 {
        return None;
    }
    let len = rest[..n].iter().fold(0usize, |a, &b| (a << 8) | usize::from(b));
    (len >= 0x80).then_some((tag, Some(len), 2 + n))
}

/// `data` is exactly one element: its tag and content.
fn whole(data: &[u8]) -> Option<(u8, &[u8])> {
    let (tag, content, rest) = element(data)?;
    rest.is_empty().then_some((tag, content))
}

/// An X.509 `Certificate` (nothing after it): `Some(is_ca)`.
fn certificate(der: &[u8]) -> Option<bool> {
    let (0x30, cert) = whole(der)? else { return None };
    let (0x30, tbs, rest) = element(cert)? else { return None };
    let (0x30, _, rest) = element(rest)? else { return None };
    let (0x03, _, rest) = element(rest)? else { return None };
    if !rest.is_empty() {
        return None;
    }
    let mut rest = tbs;
    if rest.first() == Some(&0xA0) {
        rest = element(rest)?.2;
    }
    // serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo.
    for wanted in [0x02, 0x30, 0x30, 0x30, 0x30, 0x30] {
        let (tag, _, next) = element(rest)?;
        if tag != wanted {
            return None;
        }
        rest = next;
    }
    let mut is_ca = false;
    while !rest.is_empty() {
        let (tag, content, next) = element(rest)?;
        rest = next;
        match tag {
            0x81 | 0x82 => {}
            0xA3 => is_ca = basic_constraints_ca(content)?,
            _ => return None,
        }
    }
    Some(is_ca)
}

/// `[3] Extensions`: whether basicConstraints says `cA = TRUE`.
fn basic_constraints_ca(explicit: &[u8]) -> Option<bool> {
    const BASIC_CONSTRAINTS: [u8; 3] = [0x55, 0x1D, 0x13];
    let (0x30, mut list) = whole(explicit)? else { return None };
    let mut ca = false;
    while !list.is_empty() {
        let (0x30, ext, next) = element(list)? else { return None };
        list = next;
        let (0x06, oid, mut rest) = element(ext)? else { return None };
        if rest.first() == Some(&0x01) {
            rest = element(rest)?.2;
        }
        let (0x04, value) = whole(rest)? else { return None };
        if oid == BASIC_CONSTRAINTS {
            let (0x30, bc) = whole(value)? else { return None };
            if let Some((0x01, flag, _)) = element(bc) {
                ca = flag.first().is_some_and(|&b| b != 0);
            }
        }
    }
    Some(ca)
}

/// A PKCS#12 `PFX`: version 3 and an `authSafe` of PKCS#7 `data` or `signedData`; a definite outer length must be
/// the whole file, an indefinite one must end the file with its end-of-contents.
fn is_pkcs12(der: &[u8]) -> bool {
    const DATA: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01];
    const SIGNED: [u8; 9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02];
    let Some((0x30, len, h)) = header(der) else { return false };
    let body = match len {
        Some(len) if h + len == der.len() => &der[h..],
        None if der.len() >= h + 2 && der.ends_with(&[0, 0]) => &der[h..der.len() - 2],
        _ => return false,
    };
    let Some((0x02, [3], rest)) = element(body) else { return false };
    let Some((0x30, _, h)) = header(rest) else { return false };
    matches!(element(&rest[h..]), Some((0x06, oid, _)) if oid == DATA || oid == SIGNED)
}

/// Synthetic inputs for tests across the workspace (structurally valid, cryptographically meaningless).
#[doc(hidden)]
pub mod fixtures {
    use super::{Block, Zeroizing};

    /// A minimal DER element.
    pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        let n = content.len();
        if n < 0x80 {
            v.push(n as u8);
        } else if n < 0x100 {
            v.extend([0x81, n as u8]);
        } else {
            v.extend([0x82, (n >> 8) as u8, n as u8]);
        }
        v.extend_from_slice(content);
        v
    }

    pub fn cert(ca: bool) -> Vec<u8> {
        let name = tlv(0x30, &tlv(0x31, &tlv(0x30, &[tlv(0x06, &[0x55, 4, 3]), tlv(0x0C, b"lab")].concat())));
        let alg = tlv(0x30, &tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 4, 3, 2]));
        let validity = tlv(0x30, &[tlv(0x17, b"260101000000Z"), tlv(0x17, b"300101000000Z")].concat());
        let spki = tlv(0x30, &[alg.clone(), tlv(0x03, &[0, 4, 1, 2])].concat());
        let mut tbs =
            [tlv(0xA0, &tlv(0x02, &[2])), tlv(0x02, &[1]), alg.clone(), name.clone(), validity, name, spki].concat();
        if ca {
            let bc = tlv(0x30, &tlv(0x01, &[0xFF]));
            let ext = tlv(0x30, &[tlv(0x06, &[0x55, 0x1D, 0x13]), tlv(0x01, &[0xFF]), tlv(0x04, &bc)].concat());
            tbs.extend(tlv(0xA3, &tlv(0x30, &ext)));
        }
        tlv(0x30, &[tlv(0x30, &tbs), alg, tlv(0x03, &[0, 1, 2, 3])].concat())
    }

    pub fn pem(label: &str, data: &[u8]) -> String {
        Block { label: label.into(), headers: vec![], data: Zeroizing::new(data.to_vec()) }.encode()
    }

    pub fn pkcs8() -> Vec<u8> {
        tlv(0x30, &[tlv(0x02, &[0]), tlv(0x30, &tlv(0x06, &[1, 2])), tlv(0x04, &[9; 40])].concat())
    }

    pub fn p12() -> Vec<u8> {
        let auth = tlv(0x30, &[tlv(0x06, &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 1, 7, 1]), tlv(0xA0, &[4, 0])].concat());
        tlv(0x30, &[tlv(0x02, &[3]), auth, tlv(0x30, &[])].concat())
    }

    /// A client certificate and its unencrypted key, as one PEM text.
    pub fn pem_pair() -> String {
        format!("{}{}", pem("CERTIFICATE", &cert(false)), pem("PRIVATE KEY", &pkcs8()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use fixtures::*;

    #[test]
    fn a_pem_certificate_and_key_are_kept_without_the_ca() {
        let text = format!(
            "Bag Attributes\n    localKeyID: 01\n{}{}{}",
            pem("CERTIFICATE", &cert(true)),
            pem("CERTIFICATE", &cert(false)),
            pem("PRIVATE KEY", &pkcs8())
        );
        let i = import(&[text.as_bytes()]).unwrap();
        assert_eq!(i.ignored_certificates, 1);
        let ClientCert::Pem { cert: c, key, encrypted } = &i.cert else { panic!() };
        assert_eq!(c, &cert(false));
        assert_eq!(key.as_str(), pem("PRIVATE KEY", &pkcs8()));
        assert!(!encrypted && !i.cert.needs_password());
        // Two files (the key separately, CRLF line ends) give the same.
        let crlf = pem("PRIVATE KEY", &pkcs8()).replace('\n', "\r\n");
        let two = import(&[pem("CERTIFICATE", &cert(false)).as_bytes(), crlf.as_bytes()]).unwrap();
        assert_eq!(two.cert, i.cert);
        assert_eq!(two.ignored_certificates, 0);
    }

    #[test]
    fn the_stored_value_is_one_line_and_reads_back() {
        let i = import(&[format!("{}{}", pem("CERTIFICATE", &cert(false)), pem("PRIVATE KEY", &pkcs8())).as_bytes()])
            .unwrap();
        let stored = i.cert.stored();
        assert!(stored.starts_with("pem:") && !stored.contains('\n'));
        assert_eq!(ClientCert::from_stored(&stored), Some(i.cert.clone()));
        let lines = i.cert.frame_lines();
        assert!(lines.starts_with("x509=") && lines.contains("\nprivate=") && lines.ends_with('\n'));
        assert_eq!(lines.matches('\n').count(), 2);
        let p = import(&[&p12()]).unwrap().cert;
        assert_eq!(ClientCert::from_stored(&p.stored()), Some(p.clone()));
        assert!(p.frame_lines().starts_with("pkcs12=") && p.needs_password());
        for bad in ["", "pem:", "pem:AAAA", "p12:!!", "x:abc", "p12:MAA="] {
            assert_eq!(ClientCert::from_stored(bad), None, "{bad}");
        }
        assert!(frame_lines_of_stored("junk").is_empty());
    }

    #[test]
    fn encrypted_keys_need_the_password() {
        let enc = pem("ENCRYPTED PRIVATE KEY", &pkcs8());
        let i = import(&[format!("{}{enc}", pem("CERTIFICATE", &cert(false))).as_bytes()]).unwrap();
        assert!(i.cert.needs_password());
        let traditional = format!(
            "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00112233445566778899AABBCCDDEEFF\n\n{}\n-----END RSA PRIVATE KEY-----\n",
            STANDARD.encode([7u8; 48])
        );
        let i = import(&[format!("{}{traditional}", pem("CERTIFICATE", &cert(false))).as_bytes()]).unwrap();
        assert!(i.cert.needs_password());
        let ClientCert::Pem { key, .. } = &i.cert else { panic!() };
        assert!(key.contains("Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,"));
        assert_eq!(ClientCert::from_stored(&i.cert.stored()), Some(i.cert.clone()));
        // A bad DEK-Info or an unknown header is refused.
        for bad in ["DEK-Info: AES-256-CBC,0011", "DEK-Info: aes;cbc,00112233445566778899AABBCCDDEEFF", "X-Other: 1"] {
            let t = traditional.replace("DEK-Info: AES-256-CBC,00112233445566778899AABBCCDDEEFF", bad);
            assert!(import(&[format!("{}{t}", pem("CERTIFICATE", &cert(false))).as_bytes()]).is_err(), "{bad}");
        }
    }

    #[test]
    fn broken_or_incomplete_pem_is_refused() {
        let c = pem("CERTIFICATE", &cert(false));
        let k = pem("PRIVATE KEY", &pkcs8());
        let cases = [
            c.clone(),                                                                       // no key
            k.clone(),                                                                       // no certificate
            format!("{c}{k}{k}"),                                                            // two keys
            format!("{}{}{k}", pem("CERTIFICATE", &cert(false)), c),                         // two client certificates
            format!("{c}{}", k.replace("-----END PRIVATE KEY", "-----END RSA PRIVATE KEY")), // wrong END
            format!("{c}{}", k.replace("-----END PRIVATE KEY-----\n", "")),                  // unclosed
            format!("{c}{k}{}", pem("PUBLIC KEY", &pkcs8())),                                // other block
            format!("{c}{}", pem("PRIVATE KEY", &[pkcs8(), vec![0]].concat())),              // trailing byte
            format!("{}{k}", pem("CERTIFICATE", &cert(false)[..20])),                        // truncated certificate
            format!("{c}{}", k.replacen('M', "*", 1)),                                       // bad base64
            format!("{c}{k}-----\n"),                                                        // stray dashes
        ];
        for (n, text) in cases.iter().enumerate() {
            assert!(import(&[text.as_bytes()]).is_err(), "case {n}");
        }
        assert!(import(&[]).is_err());
        assert!(import(&[b"\xff\xfe"]).is_err());
        assert!(import(&[&vec![b'a'; MAX_FILE_BYTES + 1]]).is_err());
        assert!(import(&[b"a", b"b", b"c", b"d", b"e"]).is_err());
    }

    #[test]
    fn ec_parameters_are_skipped() {
        let params = pem("EC PARAMETERS", &tlv(0x06, &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 3, 1, 7]));
        let ec = pem("EC PRIVATE KEY", &pkcs8());
        let i = import(&[format!("{params}{ec}{}", pem("CERTIFICATE", &cert(false))).as_bytes()]).unwrap();
        assert!(!i.cert.needs_password());
    }

    #[test]
    fn pkcs12_is_checked_and_kept_alone() {
        let p = p12();
        assert!(matches!(import(&[&p]).unwrap().cert, ClientCert::Pkcs12 { .. }));
        // BER with indefinite outer lengths (as Windows writes them).
        let mut ber = vec![0x30, 0x80];
        ber.extend_from_slice(&p[2..]);
        ber.extend([0, 0]);
        assert!(import(&[&ber]).is_ok());
        let mut v2 = p.clone();
        v2[4] = 2;
        for bad in [v2, [p.clone(), vec![0]].concat(), p[..p.len() - 1].to_vec(), cert(false)] {
            assert!(import(&[&bad]).is_err());
        }
        assert!(import(&[&p, pem("CERTIFICATE", &cert(false)).as_bytes()]).is_err(), "alone");
        let s = import(&[&p]).unwrap().cert.summary();
        assert_eq!(s.form, Form::Pkcs12);
        assert_eq!(s.sha256.len(), 32 * 3 - 1);
    }

    #[test]
    fn debug_shows_no_key_material() {
        let i = import(&[format!("{}{}", pem("CERTIFICATE", &cert(false)), pem("PRIVATE KEY", &pkcs8())).as_bytes()])
            .unwrap();
        let d = format!("{:?}", i);
        assert!(!d.contains("BEGIN") && !d.contains("CQkJ"), "{d}");
    }
}
