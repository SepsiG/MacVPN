//! The System Status window without a UI (the Swift `SetupView`, `BrewInstaller` and `AppModel.uninstall`): the
//! row texts in both languages, the up-front notice before reinstalling the root layer, the `brew install`
//! output, and the uninstall order with its final message.

mod common;

use common::*;
use macvpn_app_core::connections::ConnectionsModel;
use macvpn_app_core::deps::{SecretField, SecretReader, SystemVpn};
use macvpn_app_core::editor::EditorDeps;
use macvpn_app_core::migration::{LegacyKeychain, LegacyRead};
use macvpn_app_core::setup::*;
use macvpn_core::l10n::{AppLanguage, with_language};
use macvpn_core::models::{Connection, NativeSettings, VPNKind};
use macvpn_core::vault::{KeyStore, MemoryKeyStore};
use std::cell::RefCell;
use std::sync::{Arc, Mutex};

fn facts() -> SetupFacts {
    SetupFacts {
        brew_prefix: Some("/opt/homebrew".into()),
        missing_tools: vec![],
        installed_root_version: Some("8".into()),
        bundled_root_version: Some("8".into()),
        root_ok: true,
        missing_root_files: vec![],
    }
}

const NOTICE: &str = "Updating the system component will disconnect active VPN connections.";

#[test]
fn root_detail_cases() {
    with_language(AppLanguage::En, || {
        assert_eq!(root_detail(&facts()), "Installed (version 8)");
        let old = SetupFacts { installed_root_version: Some("7".into()), root_ok: false, ..facts() };
        assert_eq!(root_detail(&old), "Update required (7 → 8). Asks for the admin password once.");
        let partial = SetupFacts { missing_root_files: vec!["mvpn".into()], root_ok: false, ..facts() };
        assert_eq!(
            root_detail(&partial),
            "Incomplete installation (missing: mvpn). Reinstall: asks for the admin password once."
        );
        let none = SetupFacts { installed_root_version: None, root_ok: false, ..facts() };
        assert!(root_detail(&none).starts_with("Asks for the admin password once: installs the scripts"));
        let no_bundle = SetupFacts { bundled_root_version: None, root_ok: false, ..facts() };
        assert_eq!(root_detail(&no_bundle), "Update required (8 → ?). Asks for the admin password once.");
    });
    with_language(AppLanguage::Hu, || {
        assert_eq!(root_detail(&facts()), "Telepítve (verzió 8)");
    });
}

#[test]
fn rows_and_the_upgrade_notice() {
    with_language(AppLanguage::En, || {
        let brew = BrewRun::default();
        let ops = SetupOps::default();
        let unchecked = SetupView::build(None, &brew, &ops, NOTICE.into());
        assert!(!unchecked.checked && unchecked.homebrew.is_none() && !unchecked.can_install_tools);

        let ok = SetupView::build(Some(&facts()), &brew, &ops, NOTICE.into());
        assert_eq!(ok.homebrew.as_ref().map(|r| (r.ok, r.detail.as_str())), Some((true, "/opt/homebrew")));
        assert_eq!(ok.tools.as_ref().map(|r| r.detail.as_str()), Some("All tools are installed"));
        assert_eq!(ok.upgrade_notice, None, "nothing to install");

        let missing = SetupFacts {
            brew_prefix: None,
            missing_tools: vec!["openvpn".into(), "sstpc".into()],
            installed_root_version: Some("7".into()),
            root_ok: false,
            ..facts()
        };
        let view = SetupView::build(Some(&missing), &brew, &ops, NOTICE.into());
        let homebrew = view.homebrew.unwrap();
        assert!(!homebrew.ok && homebrew.detail.starts_with("Not installed. The installer runs in Terminal"));
        assert_eq!(view.tools.unwrap().detail, "Missing: openvpn, sstpc");
        assert!(!view.can_install_tools, "no Homebrew");
        assert_eq!(view.upgrade_notice.as_deref(), Some(NOTICE), "an older root layer is installed");

        let fresh = SetupFacts { installed_root_version: None, root_ok: false, ..facts() };
        assert_eq!(SetupView::build(Some(&fresh), &brew, &ops, NOTICE.into()).upgrade_notice, None);

        let mut running = BrewRun::default();
        running.start();
        assert!(!SetupView::build(Some(&facts()), &running, &ops, NOTICE.into()).can_install_tools);
    });
}

#[test]
fn brew_run_output() {
    let mut run = BrewRun::default();
    assert!(run.start());
    assert!(!run.start(), "one at a time");
    run.append("$ brew install openvpn\n");
    run.append("==> Pouring\n");
    run.finish();
    assert!(!run.running);
    assert_eq!(run.finished, 1);
    assert_eq!(run.output, "$ brew install openvpn\n==> Pouring\n");
    assert!(run.start());
    assert_eq!(run.output, "", "a new run starts over");
    let line = format!("{}\n", "é".repeat(100));
    for _ in 0..(MAX_BREW_OUTPUT / line.len() + 50) {
        run.append(&line);
    }
    run.append("\n✓ Done.\n");
    assert!(run.output.len() <= MAX_BREW_OUTPUT);
    assert!(run.output.starts_with('é'), "whole lines only");
    assert!(run.output.ends_with("✓ Done.\n"));
}

#[derive(Default)]
struct Recorder {
    calls: RefCell<Vec<&'static str>>,
    helper_error: Option<String>,
    login_item_error: bool,
}

impl UninstallSystem for Recorder {
    fn uninstall_helper(&self) -> Result<(), String> {
        self.calls.borrow_mut().push("helper");
        self.helper_error.clone().map_or(Ok(()), Err)
    }
    fn stop_polling(&self) {
        self.calls.borrow_mut().push("stopPolling");
    }
    fn unregister_login_item(&self) -> Result<(), String> {
        self.calls.borrow_mut().push("loginItem");
        if self.login_item_error { Err("no".into()) } else { Ok(()) }
    }
    fn remove_stale_login_entries(&self) -> Result<(), String> {
        self.calls.borrow_mut().push("staleLoginEntries");
        Ok(())
    }
    fn remove_user_files(&self) {
        self.calls.borrow_mut().push("userFiles");
    }
}

/// The old service's Keychain items (`local.macvpn.secrets`), as the uninstall deletes them.
#[derive(Default)]
struct OldItems(Mutex<Vec<(String, SecretField)>>);

impl LegacyKeychain for OldItems {
    fn items(&self) -> Vec<(String, SecretField)> {
        self.0.lock().unwrap().clone()
    }
    fn read(&self, _: &str, _: SecretField) -> LegacyRead {
        LegacyRead::Missing
    }
    fn delete(&self, account: &str, field: SecretField) {
        self.0.lock().unwrap().retain(|(a, f)| !(a == account && *f == field));
    }
}

/// The vault key in the key store and two old Keychain items.
fn stores() -> (MemoryKeyStore, OldItems) {
    let key_store = MemoryKeyStore::new();
    key_store.set(&[7; 32]).unwrap();
    let old = OldItems::default();
    old.0.lock().unwrap().push(("A1111111-2222-4333-8444-555555555555".into(), SecretField::Password));
    old.0.lock().unwrap().push(("SVC-9".into(), SecretField::Psk));
    (key_store, old)
}

struct Setup {
    fx: Fixture,
    manager: Arc<macvpn_app_core::ConnectionManager>,
    model: ConnectionsModel,
    native: Connection,
}

fn setup() -> Setup {
    let fx = Fixture::new(AppLanguage::En);
    let mut native = Connection::new("Home", VPNKind::L2tp);
    native.native =
        Some(NativeSettings { server: "vpn.example.com".into(), account: "bob".into(), ..Default::default() });
    native.native_service_name = Some("Home".into());
    fx.store.save(&native, None).unwrap();
    fx.secrets.set("pw", &native.id, SecretField::Password);
    fx.native.set_list(Ok(vec![SystemVpn::new("SVC-1", "Home", "L2TP", "Connected")]));
    let manager = fx.manager();
    manager.refresh();
    let model = ConnectionsModel::new(EditorDeps {
        manager: manager.clone(),
        store: fx.store.clone(),
        secrets: fx.secrets.clone(),
        secret_writer: fx.secrets.clone(),
        profiles: Arc::new(MobileconfigProfiles::default()),
        clock: clock_at(0.0),
    });
    Setup { fx, manager, model, native }
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn a_failed_root_uninstall_stops_everything() {
    let s = setup();
    let (key_store, old) = stores();
    let system = Recorder { helper_error: Some("Uninstall cancelled".into()), ..Default::default() };
    let failure = uninstall(
        &s.manager,
        &s.model,
        s.fx.secrets.as_ref(),
        &system,
        UserDataStores { key_store: &key_store, legacy_keychain: &old },
        UninstallChoice { remove_user_data: true },
    )
    .unwrap_err();
    assert_eq!((failure.title.as_str(), failure.message.as_str()), ("Uninstall failed", "Uninstall cancelled"));
    assert_eq!(*system.calls.borrow(), ["helper"]);
    assert!(s.fx.native.stops().is_empty());
    assert_eq!(s.fx.secrets.get(&s.native.id, SecretField::Password).as_deref(), Some("pw"));
    assert!(key_store.exists().unwrap() && old.items().len() == 2);
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn uninstall_order_and_final_message() {
    let s = setup();
    assert!(s.manager.state(&macvpn_core::models::uuid_string(&s.native.id)).is_active());
    let (key_store, old) = stores();
    let system = Recorder::default();
    let done = uninstall(
        &s.manager,
        &s.model,
        s.fx.secrets.as_ref(),
        &system,
        UserDataStores { key_store: &key_store, legacy_keychain: &old },
        UninstallChoice { remove_user_data: false },
    )
    .unwrap();
    assert_eq!(*system.calls.borrow(), ["helper", "stopPolling", "loginItem", "staleLoginEntries"]);
    assert_eq!(s.fx.native.stops(), ["SVC-1"], "the active native connection is disconnected");
    assert_eq!(s.fx.secrets.get(&s.native.id, SecretField::Password).as_deref(), Some("pw"), "user data kept");
    assert!(key_store.exists().unwrap() && old.items().len() == 2, "the keys are kept too");
    assert_eq!(done.title, "MacVPN has been uninstalled");
    assert!(done.message.starts_with("You can now drag the app to the Trash."));
    assert!(done.message.contains("L2TP / Cisco profiles"), "{}", done.message);
    assert!(!done.message.contains("login items"));
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn uninstall_with_user_data_and_a_login_item_left() {
    let s = setup();
    let (key_store, old) = stores();
    let system = Recorder { login_item_error: true, ..Default::default() };
    let done = uninstall(
        &s.manager,
        &s.model,
        s.fx.secrets.as_ref(),
        &system,
        UserDataStores { key_store: &key_store, legacy_keychain: &old },
        UninstallChoice { remove_user_data: true },
    )
    .unwrap();
    assert_eq!(*system.calls.borrow(), ["helper", "stopPolling", "loginItem", "staleLoginEntries", "userFiles"]);
    assert_eq!(s.fx.secrets.count(&s.native.id), 0);
    // The vault key (`local.macvpn.vault`) and every item of the old service (also in the legacy read-only mode)
    // go with the vault file: no orphaned key is left.
    assert!(!key_store.exists().unwrap());
    assert!(old.items().is_empty());
    assert!(done.message.ends_with(
        "MacVPN could not be removed from the login items. You can remove it in System Settings → General → Login Items."
    ));
}
