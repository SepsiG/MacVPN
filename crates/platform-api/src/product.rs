//! The product identity: the name, the OS, the app ID, the repository and the paths derived from them (spec 3).
//!
//! Storage identifiers (Keychain services, the preferences domain, the LaunchAgent label, socket names, the
//! helper's paths) are not identity: they stay literals inside the platform crates, because renaming them would
//! orphan users' data.

use macvpn_core::TargetOs;
use macvpn_core::l10n::TextPlatform;
use std::path::{Path, PathBuf};

/// One product of the workspace (MacVPN, WinVPN).
#[derive(Debug, PartialEq, Eq)]
pub struct Product {
    /// `MacVPN` / `WinVPN`; also the data directory's name.
    pub name: &'static str,
    pub os: TargetOs,
    /// `local.macvpn` / `local.winvpn` (Windows: also the AppUserModelID).
    pub app_id: &'static str,
    /// The one GitHub repository of every product (spec 2): the Help fallback and the asset checks.
    pub repo: &'static str,
    /// The user guide's file stem: `docs/<stem>.<lang>.md`.
    pub user_guide_stem: &'static str,
}

pub const MACVPN: Product = Product {
    name: "MacVPN",
    os: TargetOs::MacOs,
    app_id: "local.macvpn",
    repo: "SepsiG/MacVPN",
    user_guide_stem: "user-guide",
};

pub const WINVPN: Product = Product {
    name: "WinVPN",
    os: TargetOs::Windows,
    app_id: "local.winvpn",
    repo: "SepsiG/MacVPN",
    user_guide_stem: "winvpn-user-guide",
};

impl Product {
    /// `<app-data root>/<name>`: the platform gives the root (macOS: `<home>/Library/Application Support`).
    pub fn data_dir(&self, app_data_root: &Path) -> PathBuf {
        app_data_root.join(self.name)
    }

    /// The release asset of `version` for this machine: MacVPN `MacVPN-<version>.dmg` (one universal image);
    /// WinVPN `WinVPN-<version>-x64.msi` / `-arm64.msi` by `arch` (`std::env::consts::ARCH`). `None`: no asset
    /// for this architecture.
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
            TargetOs::Linux => None,
        }
    }

    /// The OS and product the texts are worded for (installed with `l10n::set_text_platform` at launch).
    pub fn text_platform(&self) -> TextPlatform {
        TextPlatform { os: self.os, product: self.name }
    }
}
