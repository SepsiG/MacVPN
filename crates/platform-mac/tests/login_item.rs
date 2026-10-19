//! Port of `LoginItemTests.swift` and `LaunchAgentLoginItemTests.swift`. Always with a temporary directory and a
//! mock service: the real `~/Library/LaunchAgents` and the real login item are never touched.

mod common;

use common::{Scratch, mode};
use macvpn_core::l10n::{self, AppLanguage};
use macvpn_core::plist_xml::{PlistValue, to_xml};
use macvpn_platform_mac::login_item::{
    FallbackLoginItemService, LaunchAgentError, LaunchAgentLoginItem, LoginItemController, LoginItemLocation,
    LoginItemNote, LoginItemService, LoginItemState, LoginItemStatus,
};
use macvpn_platform_mac::testing::MockLoginItemService;
use std::collections::BTreeMap;
use std::path::Path;

use LoginItemLocation as Loc;
use LoginItemStatus as St;

fn state(is_on: bool, can_toggle: bool, note: Option<LoginItemNote>, shows: bool) -> LoginItemState {
    LoginItemState::new(is_on, can_toggle, note, shows)
}

fn controller(service: &MockLoginItemService, location: Loc) -> LoginItemController {
    LoginItemController::new(Box::new(service.clone()), Box::new(move || location))
}

// MARK: State → UI

#[test]
fn state_mapping_from_applications() {
    assert_eq!(LoginItemState::make(St::Enabled, Loc::Applications), state(true, true, None, false));
    assert_eq!(LoginItemState::make(St::NotRegistered, Loc::Applications), state(false, true, None, false));
    assert_eq!(
        LoginItemState::make(St::RequiresApproval, Loc::Applications),
        state(true, true, Some(LoginItemNote::RequiresApproval), true)
    );
    // An ad-hoc signed build: SMAppService says NotFound, but the app is in place → off, clickable.
    assert_eq!(LoginItemState::make(St::NotFound, Loc::Applications), state(false, true, None, false));
    assert_eq!(
        LoginItemState::make(St::EnabledViaLaunchAgent, Loc::Applications),
        state(true, true, Some(LoginItemNote::LaunchAgent), false)
    );
}

#[test]
fn bad_location_disables_turning_on_but_allows_turning_off() {
    assert_eq!(
        LoginItemState::make(St::NotRegistered, Loc::NotInApplications),
        state(false, false, Some(LoginItemNote::NotInApplications), false)
    );
    assert_eq!(
        LoginItemState::make(St::NotRegistered, Loc::Translocated),
        state(false, false, Some(LoginItemNote::Translocated), false)
    );
    assert_eq!(
        LoginItemState::make(St::NotFound, Loc::Translocated),
        state(false, false, Some(LoginItemNote::Translocated), false)
    );
    assert_eq!(
        LoginItemState::make(St::NotFound, Loc::NotInApplications),
        state(false, false, Some(LoginItemNote::NotInApplications), false)
    );
    assert_eq!(
        LoginItemState::make(St::EnabledViaLaunchAgent, Loc::Translocated),
        state(true, true, Some(LoginItemNote::Translocated), false)
    );
    // Already registered (e.g. the app runs from elsewhere now): it can still be turned off.
    assert_eq!(
        LoginItemState::make(St::Enabled, Loc::NotInApplications),
        state(true, true, Some(LoginItemNote::NotInApplications), false)
    );
}

#[test]
fn controller_reads_status_from_service() {
    let service = MockLoginItemService::new(St::NotRegistered);
    let mut c = controller(&service, Loc::Applications);
    assert!(!c.state().is_on);
    service.set_status(St::Enabled); // e.g. turned on in System Settings
    assert!(!c.state().is_on);
    c.refresh();
    assert!(c.state().is_on);
    service.set_status(St::RequiresApproval);
    c.refresh();
    assert_eq!(c.state().note, Some(LoginItemNote::RequiresApproval));
}

// MARK: Default

#[test]
fn default_is_off_and_nothing_is_registered_automatically() {
    const { assert!(!LoginItemController::DEFAULT_ENABLED) };
    let service = MockLoginItemService::new(St::NotRegistered);
    let mut c = controller(&service, Loc::Applications);
    c.refresh();
    assert!(service.calls().is_empty());
    assert!(!c.state().is_on);
}

// MARK: Switch

#[test]
fn toggle_calls_register_and_unregister() {
    let service = MockLoginItemService::new(St::NotRegistered);
    let mut c = controller(&service, Loc::Applications);
    c.set_enabled(true).unwrap();
    assert_eq!(service.calls(), ["register"]);
    assert_eq!(c.status(), St::Enabled);
    c.set_enabled(false).unwrap();
    assert_eq!(service.calls(), ["register", "unregister"]);
    assert_eq!(c.status(), St::NotRegistered);
}

#[test]
fn toggle_to_current_value_is_no_op() {
    let service = MockLoginItemService::new(St::Enabled);
    controller(&service, Loc::Applications).set_enabled(true).unwrap();
    assert!(service.calls().is_empty());
}

#[test]
fn register_needing_approval_shows_note() {
    let service = MockLoginItemService::new(St::NotRegistered);
    service.0.borrow_mut().status_after_register = St::RequiresApproval;
    let mut c = controller(&service, Loc::Applications);
    c.set_enabled(true).unwrap();
    assert_eq!(c.state().note, Some(LoginItemNote::RequiresApproval));
    assert!(c.state().shows_open_settings);
    c.open_system_settings();
    assert_eq!(service.calls(), ["register", "openSettings"]);
}

#[test]
fn disabled_toggle_does_not_register() {
    let service = MockLoginItemService::new(St::NotRegistered);
    controller(&service, Loc::Translocated).set_enabled(true).unwrap();
    let not_found = MockLoginItemService::new(St::NotFound);
    controller(&not_found, Loc::NotInApplications).set_enabled(true).unwrap();
    assert!(service.calls().is_empty());
    assert!(not_found.calls().is_empty());
}

#[test]
fn not_found_from_applications_can_be_turned_on() {
    let service = MockLoginItemService::new(St::NotFound);
    let mut c = controller(&service, Loc::Applications);
    c.set_enabled(true).unwrap();
    assert_eq!(service.calls(), ["register"]);
    assert!(c.state().is_on);
}

#[test]
fn register_error_surfaces_and_state_is_reread() {
    let service = MockLoginItemService::new(St::NotRegistered);
    service.0.borrow_mut().register_error = true;
    let mut c = controller(&service, Loc::Applications);
    assert_eq!(c.set_enabled(true).unwrap_err().to_string(), "Operation not permitted");
    assert!(!c.state().is_on);
}

#[test]
fn unregister_error_surfaces() {
    let service = MockLoginItemService::new(St::Enabled);
    service.0.borrow_mut().unregister_error = true;
    let mut c = controller(&service, Loc::Applications);
    assert!(c.set_enabled(false).is_err());
    assert!(c.state().is_on);
}

// MARK: Uninstall

#[test]
fn uninstall_unregisters_when_registered() {
    for status in [St::Enabled, St::RequiresApproval] {
        let service = MockLoginItemService::new(status);
        let mut c = controller(&service, Loc::Applications);
        assert!(c.unregister_if_registered().unwrap());
        assert_eq!(service.calls(), ["unregister"]);
        assert_eq!(c.status(), St::NotRegistered);
    }
}

#[test]
fn uninstall_skips_when_not_registered() {
    for status in [St::NotRegistered, St::NotFound] {
        let service = MockLoginItemService::new(status);
        assert!(!controller(&service, Loc::Applications).unregister_if_registered().unwrap());
        assert!(service.calls().is_empty());
    }
}

#[test]
fn uninstall_unregister_error_surfaces() {
    let service = MockLoginItemService::new(St::Enabled);
    service.0.borrow_mut().unregister_error = true;
    assert!(controller(&service, Loc::Applications).unregister_if_registered().is_err());
}

// MARK: Location

#[test]
fn location_check() {
    let check = |p: &str| LoginItemLocation::check(p, "/Users/anna");
    assert_eq!(check("/Applications/MacVPN.app"), Loc::Applications);
    assert_eq!(check("/Applications/Utilities/MacVPN.app"), Loc::Applications);
    assert_eq!(check("/applications/MacVPN.app"), Loc::Applications);
    assert_eq!(check("/Users/anna/Applications/MacVPN.app"), Loc::Applications);
    assert_eq!(check("/Users/anna/Applications/../Applications/MacVPN.app"), Loc::Applications);
    assert_eq!(check("/Applications/MacVPN.app/"), Loc::Applications);
    assert_eq!(check("/Volumes/MacVPN/MacVPN.app"), Loc::NotInApplications);
    assert_eq!(check("/Users/anna/Downloads/MacVPN.app"), Loc::NotInApplications);
    assert_eq!(check("/Users/bob/Applications/MacVPN.app"), Loc::NotInApplications);
    assert_eq!(check("/ApplicationsOld/MacVPN.app"), Loc::NotInApplications);
    assert_eq!(check("/Applications/../tmp/MacVPN.app"), Loc::NotInApplications);
    assert_eq!(check("/Applications"), Loc::NotInApplications);
    assert_eq!(check("/Users/anna/dev/macvpn/.build/debug"), Loc::NotInApplications);
    assert_eq!(check("/private/var/folders/x/T/AppTranslocation/1234-ABCD/d/MacVPN.app"), Loc::Translocated);
    assert_eq!(LoginItemLocation::check("/Users/anna/Applications/MacVPN.app", ""), Loc::NotInApplications);
    // The current location resolves symlinks.
    let dir = Scratch::new("macvpn-loc");
    let real = dir.join("Applications/MacVPN.app");
    std::fs::create_dir_all(&real).unwrap();
    let link = dir.join("Elsewhere.app");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let home = std::fs::canonicalize(dir.path()).unwrap();
    assert_eq!(LoginItemLocation::current(&link, &home), Loc::Applications);
}

// MARK: Texts

#[test]
fn notes_are_localized() {
    let notes = [
        LoginItemNote::RequiresApproval,
        LoginItemNote::LaunchAgent,
        LoginItemNote::NotInApplications,
        LoginItemNote::Translocated,
    ];
    let english: Vec<String> = l10n::with_language(AppLanguage::En, || notes.iter().map(|n| n.message()).collect());
    assert_eq!(english[0], "Approve MacVPN in System Settings → General → Login Items.");
    assert_eq!(english[1], "Enabled via a login LaunchAgent (applies at next login).");
    l10n::with_language(AppLanguage::Hu, || {
        for (note, en) in notes.iter().zip(&english) {
            assert_eq!(Some(note.message().as_str()), l10n::hungarian(en), "no Hungarian: {en}");
        }
        assert_eq!(
            LoginItemNote::RequiresApproval.message(),
            "Engedélyezd a MacVPN-t a Rendszerbeállítások → Általános → Bejelentkezési elemek alatt."
        );
    });
}

// MARK: - LaunchAgent fallback

struct AgentDir {
    _scratch: Scratch,
    agent: LaunchAgentLoginItem,
}

fn agent_dir() -> AgentDir {
    let scratch = Scratch::unborn("macvpn-launchagent");
    let agent = LaunchAgentLoginItem::in_directory(scratch.join("LaunchAgents"));
    AgentDir { _scratch: scratch, agent }
}

fn read_plist(path: &Path) -> plist::Dictionary {
    plist::Value::from_file(path).unwrap().into_dictionary().unwrap()
}

fn write_plist(agent: &LaunchAgentLoginItem, label: &str, args: &[&str]) {
    std::fs::create_dir_all(&agent.directory).unwrap();
    let mut d = BTreeMap::new();
    d.insert("Label".to_string(), PlistValue::String(label.into()));
    d.insert(
        "ProgramArguments".to_string(),
        PlistValue::Array(args.iter().map(|a| PlistValue::String(a.to_string())).collect()),
    );
    std::fs::write(agent.plist_path(), to_xml(&PlistValue::Dictionary(d))).unwrap();
}

fn fallback(primary: &MockLoginItemService, agent: &LaunchAgentLoginItem) -> FallbackLoginItemService {
    FallbackLoginItemService::new(Box::new(primary.clone()), agent.clone())
}

#[test]
fn launch_agent_defaults() {
    assert_eq!(LaunchAgentLoginItem::DEFAULT_LABEL, "local.macvpn.launcher");
    assert_eq!(LaunchAgentLoginItem::DEFAULT_BUNDLE_IDENTIFIER, "local.macvpn");
    let real = LaunchAgentLoginItem::new(Path::new("/Users/anna"));
    assert_eq!(real.directory, Path::new("/Users/anna/Library/LaunchAgents"));
    assert_eq!(real.plist_path().file_name().unwrap(), "local.macvpn.launcher.plist");
}

/// Byte-identical to Swift's `PropertyListSerialization` XML output.
#[test]
fn plist_data_matches_swift() {
    let d = agent_dir();
    assert_eq!(
        String::from_utf8(d.agent.plist_data()).unwrap(),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n\t<key>Label</key>\n\t<string>local.macvpn.launcher</string>\n\t<key>LimitLoadToSessionType</key>\n\t<string>Aqua</string>\n\t<key>ProgramArguments</key>\n\t<array>\n\t\t<string>/usr/bin/open</string>\n\t\t<string>-b</string>\n\t\t<string>local.macvpn</string>\n\t</array>\n\t<key>RunAtLoad</key>\n\t<true/>\n</dict>\n</plist>\n"
    );
}

#[test]
fn install_writes_expected_plist_with_mode_0644() {
    let d = agent_dir();
    assert!(!d.agent.is_installed());
    d.agent.install().unwrap();
    let plist = read_plist(&d.agent.plist_path());
    assert_eq!(plist.get("Label").and_then(|v| v.as_string()), Some("local.macvpn.launcher"));
    let args: Vec<&str> =
        plist.get("ProgramArguments").unwrap().as_array().unwrap().iter().map(|v| v.as_string().unwrap()).collect();
    assert_eq!(args, ["/usr/bin/open", "-b", "local.macvpn"]);
    assert_eq!(plist.get("RunAtLoad").and_then(|v| v.as_boolean()), Some(true));
    assert_eq!(plist.get("LimitLoadToSessionType").and_then(|v| v.as_string()), Some("Aqua"));
    assert_eq!(mode(&d.agent.plist_path()), 0o644);
    assert!(std::fs::symlink_metadata(d.agent.plist_path()).unwrap().file_type().is_file());
    assert!(d.agent.is_installed());
    // No temp file is left.
    let names: Vec<String> = std::fs::read_dir(&d.agent.directory)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["local.macvpn.launcher.plist"]);
    // Rewriting (overwriting) works too.
    d.agent.install().unwrap();
    assert!(d.agent.is_installed());
}

#[test]
fn install_refuses_symlink() {
    let d = agent_dir();
    std::fs::create_dir_all(&d.agent.directory).unwrap();
    let target = d.agent.directory.parent().unwrap().join("target.plist");
    std::fs::write(&target, "keep").unwrap();
    std::os::unix::fs::symlink(&target, d.agent.plist_path()).unwrap();
    let e = d.agent.install().unwrap_err();
    assert_eq!(
        e.downcast_ref::<LaunchAgentError>(),
        Some(&LaunchAgentError::NotRegularFile(d.agent.plist_path().to_string_lossy().into_owned()))
    );
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
    assert_eq!(std::fs::read_link(d.agent.plist_path()).unwrap(), target);
    assert!(!d.agent.is_installed());
}

#[test]
fn symlink_to_valid_plist_is_not_installed_and_not_removed() {
    let d = agent_dir();
    let real = LaunchAgentLoginItem::in_directory(d.agent.directory.parent().unwrap().to_path_buf());
    real.install().unwrap();
    std::fs::create_dir_all(&d.agent.directory).unwrap();
    std::os::unix::fs::symlink(real.plist_path(), d.agent.plist_path()).unwrap();
    assert!(!d.agent.is_installed());
    assert!(!d.agent.remove().unwrap());
    assert!(real.is_installed());
}

#[test]
fn status_detection_checks_label_and_arguments() {
    let d = agent_dir();
    assert!(!d.agent.is_installed());
    write_plist(&d.agent, "local.macvpn.launcher", &["/usr/bin/open", "-b", "local.macvpn"]);
    assert!(d.agent.is_installed());
    write_plist(&d.agent, "local.macvpn.launcher", &["/tmp/evil"]);
    assert!(!d.agent.is_installed());
    write_plist(&d.agent, "com.example.other", &["/usr/bin/open", "-b", "local.macvpn"]);
    assert!(!d.agent.is_installed());
    std::fs::write(d.agent.plist_path(), "not a plist").unwrap();
    assert!(!d.agent.is_installed());
    // A binary plist (e.g. converted by a tool) is read too.
    write_plist(&d.agent, "local.macvpn.launcher", &["/usr/bin/open", "-b", "local.macvpn"]);
    assert!(
        std::process::Command::new("/usr/bin/plutil")
            .args(["-convert", "binary1"])
            .arg(d.agent.plist_path())
            .status()
            .unwrap()
            .success()
    );
    assert!(d.agent.is_installed());
}

#[test]
fn remove_deletes_only_our_label() {
    let d = agent_dir();
    assert!(!d.agent.remove().unwrap()); // nothing to delete
    write_plist(&d.agent, "com.example.other", &["/bin/true"]);
    assert!(!d.agent.remove().unwrap());
    assert!(d.agent.plist_path().exists());
    // Our label with old arguments: deleted.
    write_plist(&d.agent, "local.macvpn.launcher", &["/old/path"]);
    assert!(d.agent.remove().unwrap());
    assert!(!d.agent.plist_path().exists());
}

// MARK: Combined service

#[test]
fn register_falls_back_when_smappservice_fails() {
    let d = agent_dir();
    let primary = MockLoginItemService::new(St::NotFound);
    primary.0.borrow_mut().register_error = true;
    let service = fallback(&primary, &d.agent);
    assert_eq!(service.status(), St::NotFound);
    service.register().unwrap();
    assert_eq!(primary.calls(), ["register"]);
    assert!(d.agent.is_installed());
    assert_eq!(service.status(), St::EnabledViaLaunchAgent);
}

#[test]
fn register_falls_back_when_status_stays_not_found() {
    let d = agent_dir();
    let primary = MockLoginItemService::new(St::NotFound);
    primary.0.borrow_mut().status_after_register = St::NotFound;
    let service = fallback(&primary, &d.agent);
    service.register().unwrap();
    assert!(d.agent.is_installed());
    assert_eq!(service.status(), St::EnabledViaLaunchAgent);
}

#[test]
fn register_via_smappservice_does_not_write_plist_and_removes_stale_one() {
    let d = agent_dir();
    let primary = MockLoginItemService::new(St::NotRegistered);
    let service = fallback(&primary, &d.agent);
    service.register().unwrap();
    assert_eq!(service.status(), St::Enabled);
    assert!(!d.agent.plist_path().exists());

    d.agent.install().unwrap();
    let approval = MockLoginItemService::new(St::NotRegistered);
    approval.0.borrow_mut().status_after_register = St::RequiresApproval;
    fallback(&approval, &d.agent).register().unwrap();
    assert!(!d.agent.is_installed());
}

#[test]
fn register_fallback_error_surfaces() {
    let d = agent_dir();
    let primary = MockLoginItemService::new(St::NotFound);
    primary.0.borrow_mut().register_error = true;
    std::fs::create_dir_all(&d.agent.directory).unwrap();
    std::os::unix::fs::symlink("/dev/null", d.agent.plist_path()).unwrap();
    let mut c = LoginItemController::new(Box::new(fallback(&primary, &d.agent)), Box::new(|| Loc::Applications));
    assert!(c.set_enabled(true).is_err());
    assert!(!c.state().is_on);
}

#[test]
fn status_from_plist() {
    let d = agent_dir();
    let primary = MockLoginItemService::new(St::NotRegistered);
    let service = fallback(&primary, &d.agent);
    assert_eq!(service.status(), St::NotRegistered);
    d.agent.install().unwrap();
    assert_eq!(service.status(), St::EnabledViaLaunchAgent);
    primary.set_status(St::RequiresApproval); // SMAppService's state wins (the approval button is needed)
    assert_eq!(service.status(), St::RequiresApproval);
}

#[test]
fn unregister_removes_both_and_ignores_smappservice_error() {
    let d = agent_dir();
    let primary = MockLoginItemService::new(St::NotFound);
    primary.0.borrow_mut().unregister_error = true;
    let service = fallback(&primary, &d.agent);
    d.agent.install().unwrap();
    service.unregister().unwrap();
    assert_eq!(primary.calls(), ["unregister"]);
    assert!(!d.agent.plist_path().exists());
    assert_eq!(service.status(), St::NotFound);
}

#[test]
fn unregister_surfaces_error_when_smappservice_stays_enabled() {
    let d = agent_dir();
    let primary = MockLoginItemService::new(St::Enabled);
    primary.0.borrow_mut().unregister_error = true;
    assert!(fallback(&primary, &d.agent).unregister().is_err());
}

#[test]
fn unregister_leaves_foreign_plist_alone() {
    let d = agent_dir();
    let primary = MockLoginItemService::new(St::NotRegistered);
    write_plist(&d.agent, "com.example.other", &["/bin/true"]);
    fallback(&primary, &d.agent).unregister().unwrap();
    assert!(d.agent.plist_path().exists());
}

#[test]
fn toggle_on_and_off_through_controller() {
    let d = agent_dir();
    let primary = MockLoginItemService::new(St::NotFound);
    primary.0.borrow_mut().status_after_register = St::NotFound;
    let mut c = LoginItemController::new(Box::new(fallback(&primary, &d.agent)), Box::new(|| Loc::Applications));
    assert_eq!(c.state(), state(false, true, None, false));
    c.set_enabled(true).unwrap();
    assert_eq!(c.state(), state(true, true, Some(LoginItemNote::LaunchAgent), false));
    c.set_enabled(false).unwrap();
    assert!(!d.agent.is_installed());
    assert!(!c.state().is_on);
}

#[test]
fn uninstall_removes_plist() {
    let d = agent_dir();
    let primary = MockLoginItemService::new(St::NotFound);
    let mut c = LoginItemController::new(Box::new(fallback(&primary, &d.agent)), Box::new(|| Loc::Applications));
    d.agent.install().unwrap();
    c.refresh();
    assert!(c.unregister_if_registered().unwrap());
    assert!(!d.agent.plist_path().exists());
    assert_eq!(c.status(), St::NotRegistered);
}

#[test]
fn error_messages_are_localized() {
    let e = LaunchAgentError::NotRegularFile("/x.plist".into());
    assert_eq!(
        l10n::with_language(AppLanguage::En, || e.to_string()),
        "Refusing to write /x.plist: it is a symbolic link or not a regular file."
    );
    assert_eq!(
        l10n::with_language(AppLanguage::Hu, || e.to_string()),
        "A(z) /x.plist nem írható: szimbolikus link vagy nem szabályos fájl."
    );
    for key in [
        "Could not write %@: %@",
        "Could not remove %@: %@",
        "Enabled via a login LaunchAgent (applies at next login).",
    ] {
        assert!(l10n::hungarian(key).is_some(), "{key}");
    }
    assert_eq!(
        l10n::with_language(AppLanguage::En, || LaunchAgentError::WriteFailed("/p".into(), libc_eacces()).to_string()),
        "Could not write /p: Permission denied"
    );
}

fn libc_eacces() -> i32 {
    13
}
