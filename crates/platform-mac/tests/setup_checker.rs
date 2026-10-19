//! Port of `SetupCheckerTests.swift`.

use macvpn_core::l10n::AppLanguage;
use macvpn_core::models::VPNKind;
use macvpn_platform_mac::command::CommandResult;
use macvpn_platform_mac::setup_checker::{SetupChecker, SetupReport};
use macvpn_platform_mac::testing::MockCommandRunner;
use std::collections::HashSet;
use std::path::PathBuf;

fn check(existing: &[String], sudo_ok: bool, installed: Option<&str>, bundled: Option<&str>) -> SetupReport {
    // `--lang` comes from the fixed language, not the machine's locale.
    AppLanguage::set_thread_override(Some(AppLanguage::En));
    let mock = MockCommandRunner::new();
    mock.respond(
        "/usr/bin/sudo -n /usr/local/libexec/macvpn/mvpn version --lang en",
        CommandResult::new(if sudo_ok { 0 } else { 1 }, installed.unwrap_or(""), ""),
    );
    let existing: HashSet<String> = existing.iter().cloned().collect();
    let installed = installed.map(str::to_string);
    let bundled = bundled.map(str::to_string);
    let checker = SetupChecker::with_io(
        &mock,
        |p| existing.contains(p),
        |p| match p {
            "/usr/local/libexec/macvpn/VERSION" => installed.clone(),
            "/bundle/VERSION" => bundled.clone(),
            _ => None,
        },
        Some(PathBuf::from("/bundle")),
    );
    checker.check()
}

fn root_binaries() -> Vec<String> {
    SetupChecker::ROOT_EXECUTABLES.iter().map(|f| format!("/usr/local/libexec/macvpn/{f}")).collect()
}

#[test]
fn nothing_installed() {
    let r = check(&[], false, None, Some("1"));
    assert_eq!(r.brew_prefix, None);
    assert!(!r.root_ok());
    assert!(!r.is_complete());
    assert!(!r.is_available(VPNKind::Openvpn));
    assert!(r.is_available(VPNKind::L2tp));
    assert!(r.is_available(VPNKind::Cisco));
}

#[test]
fn partial_tools() {
    let mut existing = vec!["/opt/homebrew/bin/brew".to_string(), "/opt/homebrew/sbin/openvpn".to_string()];
    existing.extend(root_binaries());
    let r = check(&existing, true, Some("1\n"), Some("1\n"));
    assert_eq!(r.brew_prefix.as_deref(), Some("/opt/homebrew"));
    assert!(r.root_ok());
    assert!(r.is_available(VPNKind::Openvpn));
    assert!(!r.is_available(VPNKind::Wireguard));
    assert_eq!(r.missing_tools, ["wg", "wg-quick", "wireguard-go", "bash", "swanctl", "charon", "sstpc"]);
    assert!(!r.is_complete());
}

#[test]
fn intel_prefix_and_complete() {
    let mut existing: Vec<String> = vec!["/usr/local/bin/brew".into()];
    for (_, tools) in SetupChecker::REQUIRED_TOOLS {
        for t in tools {
            existing.push(SetupChecker::candidates(t, "/usr/local")[0].clone());
        }
    }
    existing.extend(root_binaries());
    let r = check(&existing, true, Some("8"), Some("8"));
    assert_eq!(r.brew_prefix.as_deref(), Some("/usr/local"));
    assert!(r.missing_tools.is_empty());
    assert!(r.is_complete());
    assert!(VPNKind::ALL.iter().all(|k| r.is_available(*k)));
}

/// Even with a matching VERSION a reinstall is needed when the root binary is missing (an interrupted install).
#[test]
fn missing_root_binary_needs_reinstall() {
    // Root layers 7 and 8 are a single binary (the Swift layer 6 had four executables).
    assert_eq!(SetupChecker::ROOT_EXECUTABLES, ["mvpn"]);
    let r = check(&["/opt/homebrew/bin/brew".to_string()], true, Some("8"), Some("8"));
    assert_eq!(r.missing_root_files, ["mvpn"]);
    assert!(!r.root_ok());
    let none = check(&[], false, None, Some("8"));
    assert!(none.missing_root_files.is_empty(), "an uninstalled layer does not show missing files");
}

#[test]
fn version_mismatch_needs_reinstall() {
    // An installed layer 7 cannot read the config on stdin: the app requires the bundled 8.
    let r = check(&root_binaries(), true, Some("7"), Some("8"));
    assert!(!r.root_ok());
    let r = check(&root_binaries(), true, Some("6"), Some("8"));
    assert!(!r.root_ok());
}

#[test]
fn sudo_failure_is_not_ok() {
    let r = check(&root_binaries(), false, Some("8"), Some("8"));
    assert!(!r.sudo_works);
    assert!(!r.root_ok());
}

#[test]
fn charon_candidates() {
    assert!(
        SetupChecker::candidates("charon", "/opt/homebrew")
            .contains(&"/opt/homebrew/opt/strongswan/libexec/ipsec/charon".to_string())
    );
    assert_eq!(SetupChecker::candidates("wg", "/usr/local"), ["/usr/local/bin/wg", "/usr/local/sbin/wg"]);
    assert_eq!(SetupChecker::BREW_PACKAGES, ["openvpn", "wireguard-tools", "strongswan", "sstp-client", "bash"]);
}
