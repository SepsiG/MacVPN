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
use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

fn facts() -> SetupFacts {
    SetupFacts {
        brew_prefix: Some("/opt/homebrew".into()),
        missing_tools: vec![],
        installed_root_version: Some("8".into()),
        bundled_root_version: Some("8".into()),
        root_ok: true,
        missing_root_files: vec![],
        outdated: vec![],
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

/// A green tools row with outdated formulae keeps its mark, lists each update and offers "Update"; nothing else
/// changes, and without an update the JSON has no `toolsAction` (MacVPN's view model is unchanged).
#[test]
fn outdated_formulae_offer_an_update_on_the_green_tools_row() {
    use macvpn_platform_api::setup::OutdatedPackage;
    let pkg = |n: &str, i: &str, a: &str| OutdatedPackage { name: n.into(), installed: i.into(), available: a.into() };
    let (brew, ops) = (BrewRun::default(), SetupOps::default());
    with_language(AppLanguage::En, || {
        let plain = SetupView::build(Some(&facts()), &brew, &ops, NOTICE.into());
        assert_eq!(plain.tools_action, None);
        assert!(!serde_json::to_string(&plain).unwrap().contains("toolsAction"));

        let outdated =
            SetupFacts { outdated: vec![pkg("openvpn", "2.6.8", "2.6.14"), pkg("bash", "5.2", "5.3")], ..facts() };
        let view = SetupView::build(Some(&outdated), &brew, &ops, NOTICE.into());
        let tools = view.tools.as_ref().unwrap();
        assert!(tools.ok, "an update keeps the row green");
        assert_eq!(tools.detail, "openvpn: Update available: 2.6.8 → 2.6.14; bash: Update available: 5.2 → 5.3");
        assert_eq!(view.tools_action, Some("update"));
        assert!(view.can_install_tools);
        assert!(serde_json::to_string(&view).unwrap().contains("\"toolsAction\":\"update\""));
        // While it runs the button is disabled (the same `brew_running` as "Install").
        let mut running = BrewRun::default();
        running.start();
        assert!(!SetupView::build(Some(&outdated), &running, &ops, NOTICE.into()).can_install_tools);
        // A missing tool wins: "Install" (which brings the newest versions anyway), no update offer.
        let missing = SetupFacts { missing_tools: vec!["sstpc".into()], ..outdated.clone() };
        let view = SetupView::build(Some(&missing), &brew, &ops, NOTICE.into());
        assert_eq!((view.tools_action, view.tools.unwrap().detail.as_str()), (None, "Missing: sstpc"));
        // The engine rows (WinVPN) and the engine note take the offer away with the row.
        let view = SetupView::build(Some(&outdated), &brew, &ops, NOTICE.into());
        assert_eq!(view.clone().with_engine_note(Some("Later.".into())).tools_action, None);
    });
    with_language(AppLanguage::Hu, || {
        let outdated = SetupFacts { outdated: vec![pkg("openvpn", "2.6.8", "2.6.14")], ..facts() };
        assert_eq!(tools_detail(&outdated), "openvpn: Frissítés elérhető: 2.6.8 → 2.6.14");
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
    /// WinVPN: the app removes itself from the account; the helper (the MSI's service) disconnects nothing.
    account_cleanup: bool,
    /// The profiles whose removals `remove_user_files` counts (they must come before the files).
    profiles: Option<Arc<MobileconfigProfiles>>,
    removed_before_files: Cell<Option<usize>>,
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
        if let Some(p) = &self.profiles {
            self.removed_before_files.set(Some(p.removed.lock().unwrap().len()));
        }
    }
    fn helper_disconnects(&self) -> bool {
        !self.account_cleanup
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
    profiles: Arc<MobileconfigProfiles>,
    /// A WireGuard connection, connected through the helper when made by [`setup_with_wireguard`].
    wireguard: Option<Connection>,
}

fn setup() -> Setup {
    setup_with(false, false)
}

/// The connected L2TP connection and a connected WireGuard one; `removes`: the platform removes native profiles
/// itself (WinVPN's RAS engine).
fn setup_with_wireguard(removes: bool) -> Setup {
    setup_with(true, removes)
}

fn setup_with(wireguard: bool, removes: bool) -> Setup {
    let fx = Fixture::new(AppLanguage::En);
    let mut native = Connection::new("Home", VPNKind::L2tp);
    native.native =
        Some(NativeSettings { server: "vpn.example.com".into(), account: "bob".into(), ..Default::default() });
    native.native_service_name = Some("Home".into());
    fx.store.save(&native, None).unwrap();
    fx.secrets.set("pw", &native.id, SecretField::Password);
    fx.native.set_list(Ok(vec![SystemVpn::new("SVC-1", "Home", "L2TP", "Connected")]));
    let wireguard = wireguard.then(|| {
        let c = Connection::new("WG", VPNKind::Wireguard);
        fx.store.save(&c, Some("[Interface]")).unwrap();
        fx.helper.respond(
            "status",
            Ok(&format!(
                r#"[{{"id":"{}","kind":"wireguard","state":"connected","iface":null,"ip":null,"since":null}}]"#,
                macvpn_core::models::uuid_string(&c.id)
            )),
        );
        c
    });
    let manager = fx.manager();
    manager.refresh();
    let profiles = Arc::new(MobileconfigProfiles::default());
    profiles.removes.store(removes, std::sync::atomic::Ordering::SeqCst);
    let model = ConnectionsModel::new(EditorDeps {
        manager: manager.clone(),
        store: fx.store.clone(),
        secrets: fx.secrets.clone(),
        secret_writer: fx.secrets.clone(),
        profiles: profiles.clone(),
        clock: clock_at(0.0),
    });
    Setup { fx, manager, model, native, profiles, wireguard }
}

#[test]
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
    // macOS: the profiles stay for System Settings (the platform does not remove them).
    assert!(s.profiles.removed.lock().unwrap().is_empty());
    assert!(s.profiles.reconciled.lock().unwrap().is_empty());
}

/// macOS: the root layer's uninstall script takes the helper's connections down; the app disconnects only the
/// native ones (unchanged).
#[test]
fn macos_leaves_the_helper_connections_to_the_root_layer() {
    let s = setup_with_wireguard(false);
    let wg = s.wireguard.clone().unwrap();
    assert!(s.manager.state(&macvpn_core::models::uuid_string(&wg.id)).is_active());
    let (key_store, old) = stores();
    let system = Recorder::default();
    uninstall(
        &s.manager,
        &s.model,
        s.fx.secrets.as_ref(),
        &system,
        UserDataStores { key_store: &key_store, legacy_keychain: &old },
        UninstallChoice { remove_user_data: true },
    )
    .unwrap();
    assert!(!s.fx.helper.lines().contains(&down_line(VPNKind::Wireguard, &wg.id)));
    assert_eq!(s.fx.native.stops(), ["SVC-1"]);
    assert!(s.profiles.removed.lock().unwrap().is_empty());
}

/// WinVPN (G-9): "Remove WinVPN from This Account…" disconnects every connection (the MSI's service is not
/// uninstalled, so nothing else takes them down), deletes every connection's Windows VPN entry and its PSK, then
/// sweeps any `WinVPN-<UUID>` entry left (a locked vault lists only the active connections); the user's data and
/// the keys stay without "Also delete user data", and no "remove the profiles yourself" line is added.
#[test]
fn uninstall_removes_every_native_entry() {
    let s = setup_with_wireguard(true);
    let wg = s.wireguard.clone().unwrap();
    assert!(s.manager.state(&macvpn_core::models::uuid_string(&wg.id)).is_active());
    let (key_store, old) = stores();
    let system = Recorder { account_cleanup: true, ..Default::default() };
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
    assert_eq!(s.fx.native.stops(), ["SVC-1"]);
    assert!(s.fx.helper.lines().contains(&down_line(VPNKind::Wireguard, &wg.id)), "{:?}", s.fx.helper.lines());
    let removed: HashSet<_> = s.profiles.removed.lock().unwrap().iter().copied().collect();
    assert_eq!(removed, HashSet::from([s.native.id, wg.id]));
    assert_eq!(*s.profiles.reconciled.lock().unwrap(), [HashSet::new()], "every leftover entry is swept");
    assert_eq!(s.fx.secrets.get(&s.native.id, SecretField::Password).as_deref(), Some("pw"), "user data kept");
    assert!(key_store.exists().unwrap() && old.items().len() == 2, "the keys are kept too");
    assert!(!done.message.contains("L2TP / Cisco profiles"), "{}", done.message);
}

/// WinVPN (G-9) with "Also delete user data": the vault key (`local.winvpn.vault` in Credential Manager) and the
/// secrets go, and the Windows VPN entries are removed before the data folder (their PSKs are in Windows' store,
/// not in the folder).
#[test]
fn uninstall_with_user_data_deletes_the_vault_key() {
    let s = setup_with_wireguard(true);
    let (key_store, old) = stores();
    let system = Recorder { account_cleanup: true, profiles: Some(s.profiles.clone()), ..Default::default() };
    uninstall(
        &s.manager,
        &s.model,
        s.fx.secrets.as_ref(),
        &system,
        UserDataStores { key_store: &key_store, legacy_keychain: &old },
        UninstallChoice { remove_user_data: true },
    )
    .unwrap();
    assert_eq!(*system.calls.borrow(), ["helper", "stopPolling", "loginItem", "staleLoginEntries", "userFiles"]);
    assert_eq!(system.removed_before_files.get(), Some(2), "the entries go before the data folder");
    assert_eq!(s.fx.secrets.count(&s.native.id), 0);
    assert!(!key_store.exists().unwrap());
    assert!(old.items().is_empty());
}

#[test]
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

#[test]
fn an_engine_note_replaces_the_rows_and_stays_out_of_the_json_on_macos() {
    let facts = SetupFacts::default();
    let plain = SetupView::build(Some(&facts), &BrewRun::default(), &SetupOps::default(), String::new());
    let json = serde_json::to_string(&plain).unwrap();
    assert!(!json.contains("engineNote"), "absent when None: the 1.4 view-model JSON is unchanged");
    let noted = plain.with_engine_note(Some("Later.".into()));
    assert_eq!(noted.engine_note.as_deref(), Some("Later."));
    assert!(noted.homebrew.is_none() && noted.tools.is_none() && noted.root.is_none());
    assert!(!noted.can_install_tools);
    assert!(serde_json::to_string(&noted).unwrap().contains("\"engineNote\":\"Later.\""));
}

/// Where the app is uninstalled through the system (WinVPN: the MSI, in Settings → Apps), System Status shows that
/// note and a button to the system's page instead of its own "Uninstall"; absent from the JSON on macOS.
#[test]
fn a_system_uninstall_note_replaces_the_uninstall_and_stays_out_of_the_json_on_macos() {
    let plain =
        SetupView::build(Some(&SetupFacts::default()), &BrewRun::default(), &SetupOps::default(), String::new());
    assert!(!serde_json::to_string(&plain).unwrap().contains("systemUninstall"));
    assert_eq!(plain.clone().with_system_uninstall(None), plain);
    let noted = plain.with_system_uninstall(Some("Use Settings.".into()));
    assert_eq!(noted.system_uninstall.as_deref(), Some("Use Settings."));
    assert!(serde_json::to_string(&noted).unwrap().contains("\"systemUninstall\":\"Use Settings.\""));
}

/// WinVPN (G-9): next to the system uninstall note, "Remove WinVPN from This Account…" (the in-app clean-up);
/// absent from the JSON on macOS.
#[test]
fn an_account_cleanup_is_offered_only_where_the_platform_has_one() {
    let plain =
        SetupView::build(Some(&SetupFacts::default()), &BrewRun::default(), &SetupOps::default(), String::new());
    assert!(!serde_json::to_string(&plain).unwrap().contains("accountCleanup"));
    assert_eq!(plain.clone().with_account_cleanup(false), plain);
    let offered = plain.with_account_cleanup(true);
    assert!(offered.account_cleanup);
    assert!(serde_json::to_string(&offered).unwrap().contains("\"accountCleanup\":true"));
}

/// WinVPN 2b: the service, OpenVPN and WireGuard rows replace the Homebrew, tools and root rows; the OpenVPN row's
/// action enables "Install" (the installer's output keeps its box); absent from the JSON on macOS.
#[test]
fn engine_rows_replace_the_rows_and_stay_out_of_the_json_on_macos() {
    use macvpn_platform_api::setup::{EngineReport, EngineRow};
    let facts = SetupFacts::default();
    let brew = BrewRun { output: "Installing OpenVPN…\n".into(), running: false, finished: 0 };
    let plain = SetupView::build(Some(&facts), &brew, &SetupOps::default(), "Notice.".into());
    assert!(!serde_json::to_string(&plain).unwrap().contains("\"engine\""), "absent when None");
    assert_eq!(plain.clone().with_engine(None, Some("Later.".into())), plain, "no report: unchanged");
    let row = |ok: bool, detail: &str, action: Option<&'static str>| EngineRow {
        ok,
        usable: ok,
        detail: detail.into(),
        action,
    };
    let report = EngineReport {
        service: row(true, "Running (version 1)", None),
        openvpn: row(false, "Not installed", Some("install")),
        wireguard: row(true, "wireguard-nt 1.1.0", None),
    };
    let view = plain.clone().with_engine(Some(&report), Some("Later.".into()));
    assert!(view.homebrew.is_none() && view.tools.is_none() && view.root.is_none() && view.upgrade_notice.is_none());
    assert_eq!(view.brew_output, "Installing OpenVPN…\n");
    assert!(view.can_install_tools);
    let engine = view.engine.as_ref().unwrap();
    assert_eq!(engine.service, CheckRow { ok: true, detail: "Running (version 1)".into() });
    assert_eq!(engine.openvpn, CheckRow { ok: false, detail: "Not installed".into() });
    assert_eq!(engine.wireguard, CheckRow { ok: true, detail: "wireguard-nt 1.1.0".into() });
    assert_eq!(engine.openvpn_action, Some("install"));
    assert_eq!(engine.later_note, "Later.");
    let json = serde_json::to_value(&view).unwrap();
    assert_eq!(json["engine"]["openvpnAction"], "install");
    assert_eq!(json["engine"]["laterNote"], "Later.");
    assert_eq!(json["engine"]["service"]["ok"], true);
    // No action: no button, and the action is absent from the JSON.
    let ready = EngineReport { openvpn: row(true, "2.6.14", None), ..report.clone() };
    let view = plain.clone().with_engine(Some(&ready), None);
    assert!(!view.can_install_tools);
    assert_eq!(view.engine.as_ref().unwrap().later_note, "");
    assert!(serde_json::to_value(&view).unwrap()["engine"].get("openvpnAction").is_none());
    assert!(serde_json::to_value(&view).unwrap()["engine"].get("wireguardAction").is_none());
    // The WireGuard row's "Update" (fix4) enables the button on its own.
    let wg = EngineReport {
        wireguard: row(true, "wireguard-nt 1.1.0 Update available: 1.1.0 → 1.2.0", Some("update")),
        ..ready.clone()
    };
    let view = plain.clone().with_engine(Some(&wg), None);
    assert!(view.can_install_tools);
    assert_eq!(view.engine.as_ref().unwrap().wireguard_action, Some("update"));
    assert_eq!(serde_json::to_value(&view).unwrap()["engine"]["wireguardAction"], "update");
    // While the installer runs its button is disabled.
    let running = BrewRun { running: true, ..brew };
    let view =
        SetupView::build(Some(&facts), &running, &SetupOps::default(), String::new()).with_engine(Some(&report), None);
    assert!(!view.can_install_tools && view.brew_running);
}

/// WinVPN 2c Task 11: the Windows VPN client row, with the service's rows or with the engine note (the native
/// VPNs need no service); absent from the JSON on macOS.
#[test]
fn the_windows_vpn_client_row_is_shown_with_or_without_the_service() {
    use macvpn_platform_api::setup::EngineRow;
    let plain =
        SetupView::build(Some(&SetupFacts::default()), &BrewRun::default(), &SetupOps::default(), String::new());
    assert!(!serde_json::to_string(&plain).unwrap().contains("\"ras\""), "absent when None");
    assert_eq!(plain.clone().with_ras(None), plain);
    let row =
        EngineRow { ok: false, usable: false, detail: "The Windows service SstpSvc is disabled.".into(), action: None };
    let view = plain.with_engine_note(Some("No service.".into())).with_ras(Some(&row));
    assert_eq!(view.ras, Some(CheckRow { ok: false, detail: "The Windows service SstpSvc is disabled.".into() }));
    assert_eq!(view.engine_note.as_deref(), Some("No service."));
    let json = serde_json::to_value(&view).unwrap();
    assert_eq!(json["ras"]["ok"], false);
    assert_eq!(json["ras"]["detail"], "The Windows service SstpSvc is disabled.");
}

/// LinVPN (L-b Task 12): the NetworkManager row and one row per kind replace the Homebrew, tools and root rows; a
/// row with "install" carries its packages and enables the button; absent from the JSON on macOS and Windows.
#[test]
fn networkmanager_rows_replace_the_rows_and_stay_out_of_the_json_elsewhere() {
    use macvpn_platform_api::setup::{EngineRow, NmReport};
    let facts = SetupFacts::default();
    let brew = BrewRun { output: "Installing…\n".into(), running: false, finished: 0 };
    let plain = SetupView::build(Some(&facts), &brew, &SetupOps::default(), "Notice.".into());
    assert!(!serde_json::to_string(&plain).unwrap().contains("\"nm\""), "absent when None");
    assert_eq!(plain.clone().with_nm(None), plain, "no report: unchanged");
    let row = |ok: bool, detail: &str, action: Option<&'static str>| EngineRow {
        ok,
        usable: ok,
        detail: detail.into(),
        action,
    };
    let report = NmReport {
        networkmanager: row(true, "NetworkManager 1.54.3", None),
        kinds: vec![
            (VPNKind::Wireguard, row(true, "Built in", None), String::new()),
            (VPNKind::Sstp, row(false, "Not installed", Some("install")), "network-manager-sstp".into()),
        ],
        openvpn_push_visible: false,
    };
    let view = plain.clone().with_nm(Some(&report));
    assert!(view.homebrew.is_none() && view.tools.is_none() && view.root.is_none() && view.upgrade_notice.is_none());
    assert_eq!(view.tools_action, None);
    assert_eq!(view.brew_output, "Installing…\n");
    assert!(view.can_install_tools);
    let nm = view.nm.as_ref().unwrap();
    assert_eq!(nm.networkmanager, CheckRow { ok: true, detail: "NetworkManager 1.54.3".into() });
    assert_eq!(nm.kinds.len(), 2);
    assert_eq!(nm.kinds[1].kind, "sstp");
    assert_eq!(nm.kinds[1].row, CheckRow { ok: false, detail: "Not installed".into() });
    assert_eq!(nm.kinds[1].packages, "network-manager-sstp");
    assert_eq!(nm.kinds[1].action, Some("install"));
    let json = serde_json::to_value(&view).unwrap();
    assert_eq!(json["nm"]["networkmanager"]["ok"], true);
    assert_eq!(json["nm"]["kinds"][0]["kind"], "wireguard");
    assert!(json["nm"]["kinds"][0].get("action").is_none(), "no action: absent");
    assert_eq!(json["nm"]["kinds"][1]["action"], "install");
    assert_eq!(json["nm"]["kinds"][1]["packages"], "network-manager-sstp");
    assert!(json["nm"]["kinds"][0].get("pushVisible").is_none(), "only OpenVPN's row has it");
    // OpenVPN's row says whether NetworkManager sees the server's redirect-gateway (absent when not).
    let openvpn = NmReport {
        kinds: vec![(VPNKind::Openvpn, row(true, "OpenVPN 2.7.0", None), "network-manager-openvpn".into())],
        openvpn_push_visible: true,
        ..report.clone()
    };
    let json = serde_json::to_value(plain.clone().with_nm(Some(&openvpn))).unwrap();
    assert_eq!(json["nm"]["kinds"][0]["pushVisible"], true);
    let old = NmReport { openvpn_push_visible: false, ..openvpn.clone() };
    let json = serde_json::to_value(plain.clone().with_nm(Some(&old))).unwrap();
    assert!(json["nm"]["kinds"][0].get("pushVisible").is_none());
    // Nothing to install: no button; while an install runs the button is disabled.
    let ready = NmReport { kinds: vec![report.kinds[0].clone()], ..report.clone() };
    assert!(!plain.clone().with_nm(Some(&ready)).can_install_tools);
    let running = BrewRun { running: true, ..brew };
    let view = SetupView::build(Some(&facts), &running, &SetupOps::default(), String::new()).with_nm(Some(&report));
    assert!(!view.can_install_tools && view.brew_running);
}
