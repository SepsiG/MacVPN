//! The product identity: the name, the OS, the app ID, the repository and the paths derived from them (spec 3).
//!
//! Storage identifiers (Keychain services, the preferences domain, the LaunchAgent label, socket names, the
//! helper's paths) are not identity: they stay literals inside the platform crates, because renaming them would
//! orphan users' data.

use macvpn_core::TargetOs;
use macvpn_core::l10n::TextPlatform;
use macvpn_core::update::SignatureDomain;
use std::path::{Path, PathBuf};

/// One product of the workspace (MacVPN, WinVPN, LinVPN).
#[derive(Debug, PartialEq, Eq)]
pub struct Product {
    /// `MacVPN` / `WinVPN` / `LinVPN`; also the data directory's name.
    pub name: &'static str,
    pub os: TargetOs,
    /// `local.macvpn` / `local.winvpn` / `local.linvpn` (Windows: also the AppUserModelID).
    pub app_id: &'static str,
    /// The one GitHub repository of every product (spec 2): the Help fallback and the asset checks.
    pub repo: &'static str,
    /// The user guide's file stem: `docs/<stem>.<lang>.md`.
    pub user_guide_stem: &'static str,
    /// The update signature's domain (`UpdateSignature::message_for`): MacVPN's message names no asset, WinVPN's
    /// names the MSI, LinVPN's the `.deb`, so a signature of one product or architecture never verifies for another.
    pub signature_domain: SignatureDomain,
}

pub const MACVPN: Product = Product {
    name: "MacVPN",
    os: TargetOs::MacOs,
    app_id: "local.macvpn",
    repo: "SepsiG/MacVPN",
    user_guide_stem: "user-guide",
    signature_domain: SignatureDomain::MacVpnV1,
};

pub const WINVPN: Product = Product {
    name: "WinVPN",
    os: TargetOs::Windows,
    app_id: "local.winvpn",
    repo: "SepsiG/MacVPN",
    user_guide_stem: "winvpn-user-guide",
    signature_domain: SignatureDomain::WinVpnV1,
};

pub const LINVPN: Product = Product {
    name: "LinVPN",
    os: TargetOs::Linux,
    app_id: "local.linvpn",
    repo: "SepsiG/MacVPN",
    user_guide_stem: "linvpn-user-guide",
    signature_domain: SignatureDomain::LinVpnV1,
};

impl Product {
    /// `<app-data root>/<name>`: the platform gives the root (macOS: `<home>/Library/Application Support`).
    pub fn data_dir(&self, app_data_root: &Path) -> PathBuf {
        app_data_root.join(self.name)
    }

    /// The release asset of `version` for this machine: MacVPN `MacVPN-<version>.dmg` (one universal image);
    /// WinVPN `WinVPN-<version>-x64.msi` / `-arm64.msi` by `arch` (`std::env::consts::ARCH`); LinVPN
    /// `linvpn_<version>_amd64.deb` / `_arm64.deb`: the package name, not the product name, as Debian names
    /// packages. `None`: no asset for this architecture.
    pub fn update_asset(&self, version: &str, arch: &str) -> Option<String> {
        match self.os {
            TargetOs::MacOs => Some(format!("{}-{version}.dmg", self.name)),
            TargetOs::Windows => {
                let arch = match arch {
                    "x86_64" => "x64",
                    "aarch64" => "arm64",
                    _ => return None,
                };
                Some(format!("{}-{version}-{arch}.msi", self.name))
            }
            TargetOs::Linux => {
                let arch = match arch {
                    "x86_64" => "amd64",
                    "aarch64" => "arm64",
                    _ => return None,
                };
                Some(format!("linvpn_{version}_{arch}.deb"))
            }
        }
    }

    /// The OS and product the texts are worded for (installed with `l10n::set_text_platform` at launch).
    pub fn text_platform(&self) -> TextPlatform {
        TextPlatform { os: self.os, product: self.name }
    }
}
