//! The System Status window without a UI (the Swift `SetupView`, `BrewInstaller` and `AppModel.uninstall`): the
//! row texts in both languages, the up-front notice before reinstalling the root layer, the `brew install`
//! output, and the uninstall order with its final message.

mod common;

use common::*;
use macvpn_app_core::connections::ConnectionsModel;
use macvpn_app_core::deps::{SecretField, SecretReader, SystemService};
use macvpn_app_core::editor::EditorDeps;
use macvpn_app_core::setup::*;
use macvpn_core::l10n::{AppLanguage, with_language};
use macvpn_core::models::{Connection, NativeSettings, VPNKind};
use std::cell::RefCell;
use std::sync::Arc;

fn facts() -> SetupFacts {
    SetupFacts {
        brew_prefix: Some("/opt/homebrew".into()),
        missing_tools: vec![],
        installed_root_version: Some("7".into()),
        bundled_root_version: Some("7".into()),
        root_ok: true,
        missing_root_files: vec![],
    }
}

const NOTICE: &str = "Updating the system component will disconnect active VPN connections.";

#[test]
fn root_detail_cases() {
    with_language(AppLanguage::En, || {
        assert_eq!(root_detail(&facts()), "Installed (version 7)");
        let old = SetupFacts { installed_root_version: Some("6".into()), root_ok: false, ..facts() };
        assert_eq!(root_detail(&old), "Update required (6 → 7). Asks for the admin password once.");
        let partial = SetupFacts { missing_root_files: vec!["mvpn".into()], root_ok: false, ..facts() };
        assert_eq!(
            root_detail(&partial),
            "Incomplete installation (missing: mvpn). Reinstall: asks for the admin password once."
        );
        let none = SetupFacts { installed_root_version: None, root_ok: false, ..facts() };
        assert!(root_detail(&none).starts_with("Asks for the admin password once: installs the scripts"));
        let no_bundle = SetupFacts { bundled_root_version: None, root_ok: false, ..facts() };
        assert_eq!(root_detail(&no_bundle), "Update required (7 → ?). Asks for the admin password once.");
    });
    with_language(AppLanguage::Hu, || {
        assert_eq!(root_detail(&facts()), "Telepítve (verzió 7)");
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
            installed_root_version: Some("6".into()),
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
    root_error: Option<String>,
    login_item_error: bool,
}

impl UninstallSystem for Recorder {
    fn uninstall_root(&self) -> Result<(), String> {
        self.calls.borrow_mut().push("root");
        self.root_error.clone().map_or(Ok(()), Err)
    }
    fn stop_polling(&self) {
        self.calls.borrow_mut().push("stopPolling");
    }
    fn unregister_login_item(&self) -> Result<(), String> {
        self.calls.borrow_mut().push("loginItem");
        if self.login_item_error { Err("no".into()) } else { Ok(()) }
    }
    fn remove_launch_agent(&self) -> Result<(), String> {
        self.calls.borrow_mut().push("launchAgent");
        Ok(())
    }
    fn remove_user_files(&self) {
        self.calls.borrow_mut().push("userFiles");
    }
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
    fx.native.set_list(Ok(vec![SystemService::new("SVC-1", "Home", "L2TP", "Connected")]));
    let manager = fx.manager();
    manager.refresh();
    let model = ConnectionsModel::new(EditorDeps {
        manager: manager.clone(),
        store: fx.store.clone(),
        secrets: fx.secrets.clone(),
        secret_writer: fx.secrets.clone(),
        profiles: Arc::new(MockProfiles::default()),
        clock: clock_at(0.0),
    });
    Setup { fx, manager, model, native }
}

#[test]
fn a_failed_root_uninstall_stops_everything() {
    let s = setup();
    let system = Recorder { root_error: Some("Uninstall cancelled".into()), ..Default::default() };
    let failure =
        uninstall(&s.manager, &s.model, s.fx.secrets.as_ref(), &system, UninstallChoice { remove_user_data: true })
            .unwrap_err();
    assert_eq!((failure.title.as_str(), failure.message.as_str()), ("Uninstall failed", "Uninstall cancelled"));
    assert_eq!(*system.calls.borrow(), ["root"]);
    assert!(s.fx.native.stops().is_empty());
    assert_eq!(s.fx.secrets.get(&s.native.id, SecretField::Password).as_deref(), Some("pw"));
}

#[test]
fn uninstall_order_and_final_message() {
    let s = setup();
    assert!(s.manager.state(&macvpn_core::models::uuid_string(&s.native.id)).is_active());
    let system = Recorder::default();
    let done =
        uninstall(&s.manager, &s.model, s.fx.secrets.as_ref(), &system, UninstallChoice { remove_user_data: false })
            .unwrap();
    assert_eq!(*system.calls.borrow(), ["root", "stopPolling", "loginItem", "launchAgent"]);
    assert_eq!(s.fx.native.stops(), ["SVC-1"], "the active native connection is disconnected");
    assert_eq!(s.fx.secrets.get(&s.native.id, SecretField::Password).as_deref(), Some("pw"), "user data kept");
    assert_eq!(done.title, "MacVPN has been uninstalled");
    assert!(done.message.starts_with("You can now drag the app to the Trash."));
    assert!(done.message.contains("L2TP / Cisco profiles"), "{}", done.message);
    assert!(!done.message.contains("login items"));
}

#[test]
fn uninstall_with_user_data_and_a_login_item_left() {
    let s = setup();
    let system = Recorder { login_item_error: true, ..Default::default() };
    let done =
        uninstall(&s.manager, &s.model, s.fx.secrets.as_ref(), &system, UninstallChoice { remove_user_data: true })
            .unwrap();
    assert_eq!(*system.calls.borrow(), ["root", "stopPolling", "loginItem", "launchAgent", "userFiles"]);
    assert_eq!(s.fx.secrets.count(&s.native.id), 0);
    assert!(done.message.ends_with(
        "MacVPN could not be removed from the login items. You can remove it in System Settings → General → Login Items."
    ));
}
