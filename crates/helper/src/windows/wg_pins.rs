//! The pinned wireguard-nt SDK (`scripts/pins/wireguard-nt.txt`): its version, the zip's and each bundled DLL's
//! SHA-256 and the DLLs' Authenticode signer: its name and the key of the CA that issued its certificate.
//! `scripts/fetch-wireguard-nt.sh` checks the download against the same file at build time; the service compares the
//! `wireguard.dll` it is about to load with [`dll_sha256`] of its own architecture (`sys/wgdll.rs`), and every DLL
//! it loads, bundled or downloaded, with the signer's name and CA keys (M-1 of the 2.0.0 security review).
//! `docs/RELEASING.md` ("Signer pins") says how to update the CA keys when the publisher's certificate changes.

use std::sync::LazyLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireGuardNtPins {
    pub version: String,
    /// On `https://download.wireguard.com/wireguard-nt/`.
    pub zip_url: String,
    pub zip_sha256: String,
    pub dll_amd64_sha256: String,
    pub dll_arm64_sha256: String,
    /// The simple name of the DLLs' Authenticode signer (checked at build time).
    pub signer: String,
    /// The SPKI SHA-256 of the CAs that may have issued the signer's certificate, comma-separated (see
    /// [`signer_cas`](Self::signer_cas)).
    pub signer_ca_spki_sha256: String,
}

impl WireGuardNtPins {
    /// The pinned CA keys: a DLL's signer certificate must chain through one of them
    /// (`macvpn_winsys::trust::Signer::is_pinned`).
    pub fn signer_cas(&self) -> Vec<&str> {
        self.signer_ca_spki_sha256.split(',').collect()
    }
}

const KEYS: [&str; 7] =
    ["version", "zip_url", "zip_sha256", "dll_amd64_sha256", "dll_arm64_sha256", "signer", "signer_ca_spki_sha256"];

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A comma-separated list of SHA-256 hashes (64 lower-case hex digits each), at least one, no spaces.
pub fn is_sha256_list(s: &str) -> bool {
    s.split(',').all(is_sha256_hex)
}

/// `key<TAB>value` lines and `#` comments; every key exactly once, nothing else, no empty value; the hashes 64
/// lower-case hex digits; the zip on `download.wireguard.com` over HTTPS.
pub fn parse(text: &str) -> Result<WireGuardNtPins, String> {
    let mut values: [Option<String>; KEYS.len()] = Default::default();
    for (n, line) in text.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once('\t').ok_or_else(|| format!("line {}: no tab", n + 1))?;
        let i = KEYS.iter().position(|k| *k == key).ok_or_else(|| format!("line {}: unknown key {key}", n + 1))?;
        if value.is_empty() || value.trim() != value || value.contains('\t') || value.chars().any(char::is_control) {
            return Err(format!("line {}: bad value for {key}", n + 1));
        }
        if key == "signer_ca_spki_sha256" {
            if !is_sha256_list(value) {
                return Err(format!("line {}: {key} is not a comma-separated list of SHA-256 hashes", n + 1));
            }
        } else if key.ends_with("sha256") && !is_sha256_hex(value) {
            return Err(format!("line {}: {key} is not 64 lower-case hex digits", n + 1));
        }
        if key == "zip_url" && !value.starts_with("https://download.wireguard.com/wireguard-nt/") {
            return Err(format!("line {}: zip_url is not on https://download.wireguard.com/wireguard-nt/", n + 1));
        }
        if values[i].replace(value.to_owned()).is_some() {
            return Err(format!("line {}: {key} twice", n + 1));
        }
    }
    let mut it = values.into_iter().zip(KEYS).map(|(v, k)| v.ok_or_else(|| format!("missing {k}")));
    let mut next = || it.next().expect("one value per key");
    Ok(WireGuardNtPins {
        version: next()?,
        zip_url: next()?,
        zip_sha256: next()?,
        dll_amd64_sha256: next()?,
        dll_arm64_sha256: next()?,
        signer: next()?,
        signer_ca_spki_sha256: next()?,
    })
}

/// The pins compiled into the service.
pub static PINS: LazyLock<WireGuardNtPins> =
    LazyLock::new(|| parse(include_str!("../../../../scripts/pins/wireguard-nt.txt")).expect("valid pins"));

/// The pinned SHA-256 of `wireguard.dll` for a Rust architecture name (`std::env::consts::ARCH`): `x86_64` (the
/// SDK's `amd64`) and `aarch64` (`arm64`); `None` for any other (WinVPN ships no other service).
pub fn dll_sha256(arch: &str) -> Option<&'static str> {
    match arch {
        "x86_64" => Some(&PINS.dll_amd64_sha256),
        "aarch64" => Some(&PINS.dll_arm64_sha256),
        _ => None,
    }
}
