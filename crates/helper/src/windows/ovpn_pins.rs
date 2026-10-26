//! The pinned OpenVPN Community installer (`scripts/pins/openvpn.txt`): version policy, the Authenticode signer of
//! `openvpn.exe` and the MSIs, the MSIs' URLs, SHA-256 and feature lists (decision 4, amended 2026-10-22:
//! `openvpn.exe`, DCO, TAP-Windows6; no Wintun). The app's copy (`crates/platform-win/src/pure/openvpn_pins.rs`) is generated from the same
//! file by [`render_rust`] (`crates/helper/tests/ovpn_windows.rs`), so both sides use the same values.

use std::sync::LazyLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenVpnPins {
    /// The pinned MSIs' OpenVPN version (System Status recommends at least this one).
    pub version: String,
    /// The oldest `openvpn.exe` the service runs (2.6.0: DCO on Windows).
    pub min_version: String,
    /// The simple name of the Authenticode signer of the MSIs and of `openvpn.exe`.
    pub signer: String,
    /// The SPKI SHA-256 of the CAs that may have issued the signer's certificate, comma-separated (M-1 of the 2.0.0
    /// security review; [`signer_cas`](Self::signer_cas)).
    pub signer_ca_spki_sha256: String,
    /// The service name of OpenVPN's Interactive Service (`openvpnserv.exe`, part of the core `OpenVPN` feature):
    /// WinVPN disables it after an install WinVPN made (decision 4 of the 2b plan, Task 17).
    pub interactive_service: String,
    pub msi_x64_url: String,
    pub msi_x64_sha256: String,
    /// The `ADDLOCAL` list for the x64 MSI.
    pub msi_x64_features: String,
    pub msi_arm64_url: String,
    pub msi_arm64_sha256: String,
    /// The `ADDLOCAL` list for the ARM64 MSI.
    pub msi_arm64_features: String,
}

impl OpenVpnPins {
    /// The pinned CA keys: the signer certificate of an MSI or of `openvpn.exe` must chain through one of them
    /// (`macvpn_winsys::trust::Signer::is_pinned`).
    pub fn signer_cas(&self) -> Vec<&str> {
        self.signer_ca_spki_sha256.split(',').collect()
    }
}

const KEYS: [&str; 11] = [
    "version",
    "min_version",
    "signer",
    "signer_ca_spki_sha256",
    "interactive_service",
    "msi_x64_url",
    "msi_x64_sha256",
    "msi_x64_features",
    "msi_arm64_url",
    "msi_arm64_sha256",
    "msi_arm64_features",
];

/// `key<TAB>value` lines and `#` comments; every key of [`OpenVpnPins`] exactly once, nothing else, no empty value.
pub fn parse(text: &str) -> Result<OpenVpnPins, String> {
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
        if key == "signer_ca_spki_sha256" && !crate::windows::wg_pins::is_sha256_list(value) {
            return Err(format!("line {}: {key} is not a comma-separated list of SHA-256 hashes", n + 1));
        }
        if values[i].replace(value.to_owned()).is_some() {
            return Err(format!("line {}: {key} twice", n + 1));
        }
    }
    let mut it = values.into_iter().zip(KEYS).map(|(v, k)| v.ok_or_else(|| format!("missing {k}")));
    let mut next = || it.next().expect("one value per key");
    Ok(OpenVpnPins {
        version: next()?,
        min_version: next()?,
        signer: next()?,
        signer_ca_spki_sha256: next()?,
        interactive_service: next()?,
        msi_x64_url: next()?,
        msi_x64_sha256: next()?,
        msi_x64_features: next()?,
        msi_arm64_url: next()?,
        msi_arm64_sha256: next()?,
        msi_arm64_features: next()?,
    })
}

/// The pins compiled into the service.
pub static PINS: LazyLock<OpenVpnPins> =
    LazyLock::new(|| parse(include_str!("../../../../scripts/pins/openvpn.txt")).expect("valid pins"));

/// The app's copy: one `pub const` per field, laid out as `rustfmt` keeps it.
pub fn render_rust(p: &OpenVpnPins) -> String {
    let mut out = String::from(
        "//! Generated from scripts/pins/openvpn.txt by crates/helper/tests/ovpn_windows.rs (WINVPN_WRITE_PINS=1); do not edit.\n",
    );
    for (name, value) in [
        ("OPENVPN_VERSION", &p.version),
        ("OPENVPN_MIN", &p.min_version),
        ("OPENVPN_SIGNER", &p.signer),
        ("OPENVPN_SIGNER_CA_SPKI_SHA256", &p.signer_ca_spki_sha256),
        ("OPENVPN_INTERACTIVE_SERVICE", &p.interactive_service),
        ("OPENVPN_MSI_X64_URL", &p.msi_x64_url),
        ("OPENVPN_MSI_X64_SHA256", &p.msi_x64_sha256),
        ("OPENVPN_MSI_X64_FEATURES", &p.msi_x64_features),
        ("OPENVPN_MSI_ARM64_URL", &p.msi_arm64_url),
        ("OPENVPN_MSI_ARM64_SHA256", &p.msi_arm64_sha256),
        ("OPENVPN_MSI_ARM64_FEATURES", &p.msi_arm64_features),
    ] {
        let one_line = format!("pub const {name}: &str = {value:?};");
        if one_line.chars().count() <= 120 {
            out.push_str(&format!("\n{one_line}\n"));
        } else {
            out.push_str(&format!("\npub const {name}: &str =\n    {value:?};\n"));
        }
    }
    out
}
