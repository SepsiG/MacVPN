//! Port of `SetupCheckerTests.swift`.
#![cfg(target_os = "macos")]

use macvpn_core::l10n::AppLanguage;
use macvpn_core::models::VPNKind;
use macvpn_platform_api::OutdatedPackage;
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
    assert_eq!(r.package_manager, None);
    // The report carries the checker's tool table (platform-api's `SetupReport::is_available` reads it).
    assert_eq!(r.required_tools, &SetupChecker::REQUIRED_TOOLS[..]);
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
    assert_eq!(r.package_manager.as_deref(), Some("/opt/homebrew"));
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
    assert_eq!(r.package_manager.as_deref(), Some("/usr/local"));
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

const OUTDATED: &str =
    "/opt/homebrew/bin/brew outdated --json=v2 --formula openvpn wireguard-tools strongswan sstp-client bash";

fn green() -> SetupReport {
    SetupReport {
        package_manager: Some("/opt/homebrew".into()),
        required_tools: &SetupChecker::REQUIRED_TOOLS,
        ..SetupReport::unknown()
    }
}

/// With every tool there, `brew outdated` (never a real brew: the mock answers) fills the outdated formulae; its
/// exit status 1 (brew's answer when a named formula is outdated) does not matter.
#[test]
fn outdated_formulae_are_checked_when_the_tools_are_green() {
    let mock = MockCommandRunner::new();
    mock.respond(
        OUTDATED,
        CommandResult::new(
            1,
            r#"{"formulae":[{"name":"openvpn","installed_versions":["2.6.8"],"current_version":"2.6.9","pinned":false,"pinned_version":null}],"casks":[]}"#,
            "",
        ),
    );
    let mut report = green();
    SetupChecker::check_outdated(&mut report, &mock);
    assert_eq!(mock.calls().len(), 1);
    assert_eq!(mock.calls()[0].command_line(), OUTDATED);
    assert_eq!(
        report.outdated_packages,
        [OutdatedPackage { name: "openvpn".into(), installed: "2.6.8".into(), available: "2.6.9".into() }]
    );
    // An update never makes the report incomplete or a kind unavailable.
    let mut complete = report.clone();
    complete.installed_root_version = Some("8".into());
    complete.bundled_root_version = Some("8".into());
    complete.sudo_works = true;
    assert!(complete.is_complete());
    assert!(complete.is_available(VPNKind::Openvpn));
}

/// A missing tool or a missing Homebrew: no `brew outdated` at all (and an earlier answer is cleared).
#[test]
fn outdated_formulae_are_not_checked_when_something_is_missing() {
    let stale = vec![OutdatedPackage { name: "bash".into(), installed: "5.2".into(), available: "5.3".into() }];
    let mock = MockCommandRunner::new();
    let mut missing = SetupReport { missing_tools: vec!["sstpc".into()], outdated_packages: stale.clone(), ..green() };
    SetupChecker::check_outdated(&mut missing, &mock);
    let mut no_brew = SetupReport { outdated_packages: stale, ..SetupReport::unknown() };
    SetupChecker::check_outdated(&mut no_brew, &mock);
    assert!(mock.calls().is_empty());
    assert!(missing.outdated_packages.is_empty() && no_brew.outdated_packages.is_empty());
}

/// An answer that is not the JSON (an error, a timeout's empty output) is unknown: nothing to update, no error.
#[test]
fn an_unreadable_outdated_answer_offers_nothing() {
    for stdout in ["", "Error: something", "{\"formulae\": 3}", "[]"] {
        let mock = MockCommandRunner::new();
        mock.respond(OUTDATED, CommandResult::new(1, stdout, "Error"));
        let mut report = green();
        SetupChecker::check_outdated(&mut report, &mock);
        assert!(report.outdated_packages.is_empty(), "{stdout}");
    }
    let mut report = green();
    SetupChecker::check_outdated(&mut report, &Failing);
    assert!(report.outdated_packages.is_empty());
}

struct Failing;

impl macvpn_platform_mac::command::CommandRunner for Failing {
    fn run(
        &self,
        _: &str,
        _: &[String],
        _: Option<&str>,
    ) -> Result<CommandResult, macvpn_platform_mac::command::CommandError> {
        Err(macvpn_platform_mac::command::CommandError::TimedOut("brew".into()))
    }
}

/// Homebrew is found at its fixed prefixes only (Apple silicon first), never through `PATH`.
#[test]
fn brew_prefix_is_found_at_the_fixed_prefixes() {
    let found = |present: &'static [&'static str]| SetupChecker::find_brew_prefix(|p| present.contains(&p));
    assert_eq!(found(&["/opt/homebrew/bin/brew", "/usr/local/bin/brew"]).as_deref(), Some("/opt/homebrew"));
    assert_eq!(found(&["/usr/local/bin/brew"]).as_deref(), Some("/usr/local"));
    assert_eq!(found(&["/home/linuxbrew/.linuxbrew/bin/brew", "/usr/bin/brew"]), None);
}
