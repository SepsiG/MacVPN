//! The product identities: the data directory, the update asset and the text platform.

use macvpn_core::TargetOs;
use macvpn_core::l10n::TextPlatform;
use macvpn_core::update::SignatureDomain;
use macvpn_platform_api::{MACVPN, WINVPN};
use std::path::{Path, PathBuf};

#[test]
fn data_dir_is_the_product_name_under_the_app_data_root() {
    assert_eq!(
        MACVPN.data_dir(Path::new("/Users/x/Library/Application Support")),
        PathBuf::from("/Users/x/Library/Application Support/MacVPN")
    );
    assert_eq!(WINVPN.data_dir(Path::new("/appdata")), PathBuf::from("/appdata/WinVPN"));
}

/// The callers pass `MACVPN` and `<home>/Library/Application Support` (Task 10): the paths are the 1.4.0 ones byte
/// for byte (`store::application_support_directory(home)`, `store::default_base_dir(home)`).
// Unix only: the bytes are the macOS paths, and `Path::join` writes a backslash on Windows.
#[cfg(unix)]
#[test]
fn macvpn_paths_are_the_1_4_0_paths() {
    let home = Path::new("/Users/someone");
    let data_dir = MACVPN.data_dir(&home.join("Library/Application Support"));
    assert_eq!(data_dir.as_os_str().as_encoded_bytes(), b"/Users/someone/Library/Application Support/MacVPN");
    assert_eq!(
        macvpn_core::store::ConnectionStore::default_base_dir(&data_dir).as_os_str().as_encoded_bytes(),
        b"/Users/someone/Library/Application Support/MacVPN/connections"
    );
}

#[test]
fn macvpn_has_one_universal_disk_image() {
    assert_eq!(MACVPN.update_asset("1.5.0", "aarch64").as_deref(), Some("MacVPN-1.5.0.dmg"));
    assert_eq!(MACVPN.update_asset("1.5.0", "x86_64").as_deref(), Some("MacVPN-1.5.0.dmg"));
}

#[test]
fn winvpn_has_one_installer_per_architecture() {
    assert_eq!(WINVPN.update_asset("1.5.0", "x86_64").as_deref(), Some("WinVPN-1.5.0-x64.msi"));
    assert_eq!(WINVPN.update_asset("1.5.0", "aarch64").as_deref(), Some("WinVPN-1.5.0-arm64.msi"));
    assert_eq!(WINVPN.update_asset("1.5.0", "riscv64"), None);
}

#[test]
fn identity_values() {
    assert_eq!(MACVPN.name, "MacVPN");
    assert_eq!(MACVPN.os, TargetOs::MacOs);
    assert_eq!(MACVPN.app_id, "local.macvpn");
    assert_eq!(MACVPN.repo, "SepsiG/MacVPN");
    assert_eq!(MACVPN.user_guide_stem, "user-guide");
    assert_eq!(WINVPN.name, "WinVPN");
    assert_eq!(WINVPN.os, TargetOs::Windows);
    assert_eq!(WINVPN.app_id, "local.winvpn");
    assert_eq!(WINVPN.repo, "SepsiG/MacVPN");
    assert_eq!(WINVPN.user_guide_stem, "winvpn-user-guide");
}

#[test]
fn text_platform() {
    assert_eq!(MACVPN.text_platform(), TextPlatform::MACOS);
    assert_eq!(WINVPN.text_platform(), TextPlatform { os: TargetOs::Windows, product: "WinVPN" });
}

#[test]
fn each_product_has_its_signature_domain() {
    assert_eq!(MACVPN.signature_domain, SignatureDomain::MacVpnV1);
    assert_eq!(WINVPN.signature_domain, SignatureDomain::WinVpnV1);
}
