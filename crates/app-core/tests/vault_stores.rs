//! The vault-backed stores and the locked state (plan B Task 11, spec 2.3): every store round-trips through the
//! vault while it is unlocked and fails as specified while it is locked; Lock now keeps only a redacted record of
//! the active connections; the editors, the import, the export and the delete refuse; the view model shows no
//! name; the legacy read-only mode reads the 1.1 storage and refuses every write.

mod common;

use common::{MobileconfigProfiles, MockHelper, MockNative, TempDir, clock_at, up_line};
use macvpn_app_core::connections::ConnectionsModel;
use macvpn_app_core::control::{FileRegistryStore, RegistryStore};
use macvpn_app_core::deps::{
    ConnectionRepository, FolderOp, FolderOpResult, FolderStore, RankingPersistence, SecretField, SecretReader,
    SecretWriter, SystemOTPPersistence, SystemVpn,
};
use macvpn_app_core::editor::EditorDeps;
use macvpn_app_core::folders::VaultFolders;
use macvpn_app_core::import_export;
use macvpn_app_core::shared_credentials::SharedCredentials;
use macvpn_app_core::vault::{VaultLifecycle, VaultState};
use macvpn_app_core::vault_stores::{
    ReadOnly, VaultConnections, VaultRanking, VaultRegistry, VaultSecrets, VaultSystemOtp, locked_message,
    read_only_message,
};
use macvpn_app_core::view_model::VaultView;
use macvpn_app_core::{ConnectionItem, ConnectionManager, Dependencies, ViewModel};
use macvpn_core::control::registry::{PairedClient, Registry};
use macvpn_core::date::Date;
use macvpn_core::l10n::AppLanguage;
use macvpn_core::models::{Connection, OTPSeparator, OTPSetting, VPNKind, uuid_string};
use macvpn_core::ranking::{ConnectionRanking, ConnectionRankingStore};
use macvpn_core::store::ConnectionStore;
use macvpn_core::system_otp::SystemOTPStore;
use macvpn_core::vault::{FixedEntropy, KdfParams, MemoryKeyStore};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;
use zeroize::Zeroizing;

const PASSWORD: &str = "correct horse battery";
const SVC: &str = "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4";
const CONFIG: &str = "client\nremote vpn.example.com 1194\n";

struct Fixture {
    tmp: TempDir,
    vault: Arc<VaultLifecycle>,
    connections: Arc<VaultConnections>,
    secrets: Arc<VaultSecrets>,
    ranking: Arc<VaultRanking>,
    otp: Arc<VaultSystemOtp>,
    registry: Arc<VaultRegistry>,
    folders: Arc<VaultFolders>,
    helper: Arc<MockHelper>,
    native: Arc<MockNative>,
}

impl Fixture {
    fn new() -> Fixture {
        AppLanguage::set_thread_override(Some(AppLanguage::En));
        let tmp = TempDir::new();
        let vault = Arc::new(VaultLifecycle::new(
            tmp.path().join("MacVPN"),
            Arc::new(MemoryKeyStore::new()),
            Arc::new(FixedEntropy::new(11)),
            KdfParams::insecure_for_tests(),
        ));
        vault.set_logger(|_| {});
        vault.create(Zeroizing::new(PASSWORD.into()), false).unwrap();
        Fixture {
            connections: Arc::new(VaultConnections::new(vault.clone())),
            secrets: Arc::new(VaultSecrets::new(vault.clone())),
            ranking: Arc::new(VaultRanking::new(vault.clone())),
            otp: Arc::new(VaultSystemOtp::new(vault.clone())),
            registry: Arc::new(VaultRegistry::new(vault.clone())),
            folders: Arc::new(VaultFolders::new(vault.clone())),
            helper: Arc::new(MockHelper::default()),
            native: Arc::new(MockNative::default()),
            vault,
            tmp,
        }
    }

    fn deps(&self) -> Dependencies {
        let mut deps =
            Dependencies::new(self.connections.clone(), self.secrets.clone(), self.helper.clone(), self.native.clone());
        deps.ranking_store = Some(self.ranking.clone());
        deps.system_otp_store = Some(self.otp.clone());
        deps.secret_writer = Some(self.secrets.clone());
        deps.folders = Some(self.folders.clone());
        deps
    }

    fn manager(&self) -> Arc<ConnectionManager> {
        let m = ConnectionManager::new(self.deps());
        m.reload();
        m
    }

    fn model(&self, manager: &Arc<ConnectionManager>) -> ConnectionsModel {
        ConnectionsModel::new(EditorDeps {
            manager: manager.clone(),
            store: self.connections.clone(),
            secrets: self.secrets.clone(),
            secret_writer: self.secrets.clone(),
            profiles: Arc::new(MobileconfigProfiles::default()),
            clock: clock_at(1_000_000.0),
        })
    }

    fn add(&self, name: &str, kind: VPNKind) -> Connection {
        let c = connection(name, kind);
        self.connections.save(&c, Some(CONFIG)).unwrap();
        c
    }

    fn unlock(&self) {
        self.vault.unlock_with_password(Zeroizing::new(PASSWORD.into()), Instant::now()).unwrap();
    }
}

/// A connection created at a whole second (the stored dates have no fraction).
fn connection(name: &str, kind: VPNKind) -> Connection {
    Connection::with_id(Uuid::new_v4(), name, kind, Date::from_time_interval_since_1970(1_800_000_000.0))
}

fn locked_error(e: &std::io::Error) -> bool {
    e.kind() == ErrorKind::PermissionDenied && e.to_string() == locked_message()
}

fn client(name: &str) -> PairedClient {
    PairedClient::new(
        Uuid::new_v4(),
        name.into(),
        "token",
        "/Applications/Remote.app".into(),
        vec![],
        Date::from_time_interval_since_1970(1_800_000_000.0),
    )
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn each_store_round_trips_while_unlocked() {
    let f = Fixture::new();
    let c = f.add("Office", VPNKind::Openvpn);
    assert_eq!(f.connections.list().unwrap(), std::slice::from_ref(&c));
    assert_eq!(f.connections.load_config(&c.id).unwrap(), CONFIG);
    assert_eq!(f.connections.load_config_wiped(&c.id).unwrap().as_str(), CONFIG);
    f.secrets.set("s3cret", &c.id, SecretField::Password);
    assert_eq!(f.secrets.get(&c.id, SecretField::Password).as_deref(), Some("s3cret"));
    let mut ranking = ConnectionRanking::default();
    ranking.pin(&uuid_string(&c.id));
    f.ranking.save(&ranking).unwrap();
    assert!(f.ranking.load().is_pinned(&uuid_string(&c.id)));
    let otp = HashMap::from([(SVC.to_string(), OTPSetting::new(true, OTPSeparator::None))]);
    f.otp.save(&otp).unwrap();
    assert_eq!(f.otp.load(), otp);
    let mut registry = Registry::new();
    registry.add(client("Remote Desktop"));
    f.registry.save(&registry).unwrap();
    assert_eq!(f.registry.load().unwrap().clients(), registry.clients());
    f.connections.delete(&c.id).unwrap();
    assert!(f.connections.list().unwrap().is_empty());
    assert_eq!(f.secrets.get(&c.id, SecretField::Password), None, "the secrets go with the connection");
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn each_store_fails_as_specified_while_locked() {
    let f = Fixture::new();
    let c = f.add("Office", VPNKind::Openvpn);
    f.secrets.set("s3cret", &c.id, SecretField::Password);
    let mut registry = Registry::new();
    registry.add(client("Remote Desktop"));
    f.registry.save(&registry).unwrap();
    f.vault.lock();
    assert!(locked_error(&f.connections.list().unwrap_err()));
    assert!(locked_error(&f.connections.load_config(&c.id).unwrap_err()));
    assert!(locked_error(&f.connections.load_config_wiped(&c.id).unwrap_err()));
    assert!(locked_error(&f.connections.save(&c, None).unwrap_err()));
    assert!(locked_error(&f.connections.delete(&c.id).unwrap_err()));
    // Secrets: reads give nothing, writes are dropped (no error in the trait).
    assert_eq!(f.secrets.get(&c.id, SecretField::Password), None);
    f.secrets.set("other", &c.id, SecretField::Password);
    f.secrets.remove_all();
    // Ranking and OTP: empty loads, failing saves.
    assert_eq!(f.ranking.load(), ConnectionRanking::default());
    assert!(locked_error(&f.ranking.save(&ConnectionRanking::default()).unwrap_err()));
    assert!(f.otp.load().is_empty());
    assert!(locked_error(&f.otp.save(&HashMap::new()).unwrap_err()));
    // The registry: a load fails (never an empty registry that a save would write over the real one).
    assert!(locked_error(&f.registry.load().unwrap_err()));
    assert!(locked_error(&f.registry.save(&Registry::new()).unwrap_err()));
    // Unlocked again: nothing was lost or overwritten.
    f.unlock();
    assert_eq!(f.secrets.get(&c.id, SecretField::Password).as_deref(), Some("s3cret"));
    assert_eq!(f.registry.load().unwrap().clients().len(), 1);
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn lock_keeps_a_redacted_active_connection_and_unlock_brings_the_names_back() {
    let f = Fixture::new();
    let up = f.add("Office", VPNKind::Openvpn);
    let idle = f.add("Home", VPNKind::Wireguard);
    let key = uuid_string(&up.id);
    f.helper.respond(
        "status",
        Ok(&format!(r#"[{{"id":"{key}","kind":"openvpn","state":"connected","iface":"utun4","ip":"10.8.0.2"}}]"#)),
    );
    f.native.set_list(Ok(vec![SystemVpn::new(SVC, "Corp", "IKEv2", "Disconnected")]));
    let m = f.manager();
    m.pin(&key);
    m.set_system_otp(OTPSetting::new(true, OTPSeparator::None), SVC);
    m.refresh();
    assert!(m.state(&key).is_connected());

    f.vault.lock();
    m.enter_locked();
    assert!(m.is_locked());
    let kept = m.connections();
    assert_eq!(kept.len(), 1);
    assert_eq!((kept[0].id, kept[0].kind, kept[0].name.as_str()), (up.id, VPNKind::Openvpn, ""));
    assert!(m.ranking().pinned().is_empty() && m.system_otp().is_empty());
    // The poll keeps the state; nothing new connects; pinning is ignored.
    m.refresh();
    assert!(m.state(&key).is_connected());
    m.connect(&idle, false);
    assert!(!m.state(&uuid_string(&idle.id)).is_active());
    assert!(!f.helper.lines().iter().any(|l| l == &up_line(VPNKind::Wireguard, &idle.id)));
    m.pin(SVC);
    assert!(!m.is_pinned(SVC));
    // A reload while still locked changes nothing.
    m.reload();
    assert!(m.is_locked());
    // Quit: the active one is disconnected.
    m.disconnect_all();
    assert!(f.helper.lines().iter().any(|l| l.starts_with("down ")), "{:?}", f.helper.lines());

    f.unlock();
    m.reload();
    assert!(!m.is_locked());
    let mut names: Vec<String> = m.connections().into_iter().map(|c| c.name).collect();
    names.sort();
    assert_eq!(names, ["Home", "Office"]);
    assert!(m.is_pinned(&key), "the ranking is read again");
    assert!(m.system_otp_setting(SVC).enabled, "the OTP settings are read again");
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn a_manager_built_while_locked_reads_the_ranking_at_the_first_reload() {
    let f = Fixture::new();
    let c = f.add("Office", VPNKind::Openvpn);
    let mut ranking = ConnectionRanking::default();
    ranking.pin(&uuid_string(&c.id));
    f.ranking.save(&ranking).unwrap();
    f.vault.lock();
    let m = ConnectionManager::new(f.deps());
    m.enter_locked();
    m.reload();
    assert!(m.connections().is_empty());
    f.unlock();
    m.reload();
    assert!(m.is_pinned(&uuid_string(&c.id)));
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn the_editors_import_export_and_delete_refuse_while_locked() {
    let f = Fixture::new();
    let c = f.add("Office", VPNKind::Openvpn);
    let key = uuid_string(&c.id);
    let m = f.manager();
    let model = f.model(&m);
    model.open_editor(&key).unwrap();
    f.vault.lock();
    m.enter_locked();
    model.vault_locked();
    assert!(model.draft_fields().is_empty(), "the drafts are dropped");
    let locked = locked_message();
    assert_eq!(model.open_editor(&key).unwrap_err(), locked);
    assert_eq!(model.create(VPNKind::Openvpn).unwrap_err(), locked);
    let report = model.import_paths(&[f.tmp.path().join("x.ovpn")]);
    assert_eq!(report.errors, std::slice::from_ref(&locked));
    assert!(model.delete(&c.id).is_none());
    assert_eq!(import_export::export_warning(model.deps(), &c).unwrap_err(), locked);
    assert_eq!(import_export::export_plan(model.deps(), &c, false).unwrap_err(), locked);
    f.unlock();
    m.reload();
    assert!(model.open_editor(&key).is_ok());
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn the_view_model_while_locked_contains_no_name() {
    let f = Fixture::new();
    let up = f.add("Seeded Office", VPNKind::Openvpn);
    f.add("Seeded Home", VPNKind::Wireguard);
    let key = uuid_string(&up.id);
    f.helper.respond("status", Ok(&format!(r#"[{{"id":"{key}","kind":"openvpn","state":"connected"}}]"#)));
    f.native.set_list(Ok(vec![SystemVpn::new(SVC, "Seeded Corp", "IKEv2", "Disconnected")]));
    let m = f.manager();
    m.refresh();
    let unlocked = ViewModel::build(&m.snapshot(), "en", |_| true, Vec::new(), true);
    assert!(serde_json::to_string(&unlocked).unwrap().contains("Seeded Office"));

    f.vault.lock();
    m.enter_locked();
    m.refresh();
    let mut vm = ViewModel::build(&m.snapshot(), "en", |_| true, Vec::new(), true);
    // A prompt still listed (review 1.2.0 M2): no credential prompt is sent, an MFA prompt without its name.
    vm.credential_prompts.push(macvpn_app_core::credential_prompt::CredentialPromptView {
        id: 1,
        connection_id: key.clone(),
        connection_name: "Seeded Office".into(),
        fields: vec!["password"],
        username: Some("seeded-user".into()),
        message: None,
        deadline: 0.0,
        credential_name: Some("Seeded Credential".into()),
        used_by: Some(2),
        team: Some("Seeded Team".into()),
        team_source: Some("seeded.example.com".into()),
        server: Some("seeded-vpn.example.com".into()),
    });
    vm.prompts.push(macvpn_app_core::prompt::PromptView {
        id: 2,
        connection_id: key.clone(),
        connection_name: "Seeded Office".into(),
        kind: "code",
        text: None,
        echo: false,
        from_server: false,
        url: None,
        host: None,
        deadline: 0.0,
    });
    vm.apply_vault(VaultView::build(&f.vault.state(), false, false, 0));
    assert!(vm.credential_prompts.is_empty());
    assert_eq!(vm.prompts.len(), 1);
    let json = serde_json::to_string(&vm).unwrap();
    for name in ["Seeded Office", "Seeded Home", "Seeded Corp", "Seeded Credential", "seeded-user"] {
        assert!(!json.contains(name), "{name} in {json}");
    }
    assert!(vm.rows.is_empty());
    assert_eq!((vm.vault.state, vm.vault.active_count), ("locked", 1));
    assert!(!vm.vault.show_lock_now, "nothing to lock");
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn lock_drops_the_folders_and_the_credentials_and_unlock_brings_them_back() {
    let f = Fixture::new();
    let c = f.add("Seeded Office", VPNKind::Openvpn);
    let key = uuid_string(&c.id);
    let FolderOpResult::Created(work) =
        f.folders.apply(FolderOp::Create { parent: None, name: "Secret Folder".into() }).unwrap()
    else {
        panic!("not created")
    };
    f.folders.apply(FolderOp::MoveItem { key: key.clone(), folder: Some(work) }).unwrap();
    let m = f.manager();
    assert_eq!(m.folders().len(), 1);
    assert!(m.placement(&key).is_some());
    let shared = SharedCredentials::new(f.vault.clone());
    shared.create("Secret Credential", "alice", None).unwrap();
    let unlocked_credentials = shared.view();
    assert!(unlocked_credentials.available && unlocked_credentials.items.len() == 1);

    f.vault.lock();
    m.enter_locked();
    assert!(m.folders().is_empty() && m.placement(&key).is_none());
    // A reload while still locked reads nothing back.
    m.reload();
    assert!(m.folders().is_empty());
    let mut vm = ViewModel::build(&m.snapshot(), "en", |_| true, Vec::new(), true);
    // Even a stale view of the credentials is not sent while locked.
    vm.credentials = unlocked_credentials;
    vm.apply_vault(VaultView::build(&f.vault.state(), false, false, 0));
    let json = serde_json::to_string(&vm).unwrap();
    for name in ["Secret Folder", "Secret Credential", "alice"] {
        assert!(!json.contains(name), "{name} in {json}");
    }
    assert!(vm.tree.is_empty() && vm.palette.is_empty() && !vm.folders_enabled);
    assert!(!vm.credentials.available && vm.credentials.items.is_empty());

    f.unlock();
    m.reload();
    assert_eq!(m.folders().len(), 1);
    assert_eq!(m.placement(&key).and_then(|p| p.folder), Some(work));
    let vm = ViewModel::build(&m.snapshot(), "en", |_| true, Vec::new(), true);
    assert!(serde_json::to_string(&vm).unwrap().contains("Secret Folder"));
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn reload_all_reads_what_a_restore_wrote() {
    let f = Fixture::new();
    let c = f.add("Office", VPNKind::Openvpn);
    let key = uuid_string(&c.id);
    let m = f.manager();
    assert!(!m.is_pinned(&key));
    // A restore writes the vault behind the manager's back.
    let mut ranking = ConnectionRanking::default();
    ranking.pin(&key);
    f.ranking.save(&ranking).unwrap();
    f.folders.apply(FolderOp::Create { parent: None, name: "Restored".into() }).unwrap();
    m.reload();
    assert!(!m.is_pinned(&key), "an ordinary reload keeps the ranking it has");
    m.reload_all();
    assert!(m.is_pinned(&key));
    assert_eq!(m.folders().len(), 1);
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn the_legacy_mode_offers_no_folder_editing() {
    let f = Fixture::new();
    let m = f.manager();
    let mut vm = ViewModel::build(&m.snapshot(), "en", |_| true, Vec::new(), true);
    assert!(vm.folders_enabled && vm.folders_note.is_none());
    vm.apply_vault(VaultView::build(&VaultState::LegacyReadOnly { error: String::new() }, false, false, 0));
    assert!(!vm.folders_enabled);
    assert_eq!(vm.folders_note.as_deref(), Some("Folders can be made once your data is in the vault."));
}

#[test]
fn show_lock_now_follows_auto_unlock_and_the_preference() {
    let unlocked = VaultState::Unlocked;
    assert!(VaultView::build(&unlocked, false, false, 0).show_lock_now, "auto-unlock off");
    assert!(VaultView::build(&unlocked, true, true, 0).show_lock_now, "on, with the preference");
    assert!(!VaultView::build(&unlocked, true, false, 0).show_lock_now, "on, without the preference");
    for state in [VaultState::Locked, VaultState::NotCreated, VaultState::LegacyReadOnly { error: "x".into() }] {
        assert!(!VaultView::build(&state, false, true, 0).show_lock_now, "{state:?}");
    }
    let legacy = VaultView::build(&VaultState::LegacyReadOnly { error: "the migration failed".into() }, true, false, 0);
    assert_eq!((legacy.state, legacy.legacy_error.as_deref()), ("legacyReadOnly", Some("the migration failed")));
    assert!(!legacy.hides_data());
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn the_legacy_mode_reads_the_old_storage_and_refuses_writes() {
    AppLanguage::set_thread_override(Some(AppLanguage::En));
    let tmp = TempDir::new();
    let support = tmp.path().join("MacVPN");
    // The 1.1 data.
    let old_store = Arc::new(ConnectionStore::new(support.join("connections")));
    let c = connection("Old Office", VPNKind::Openvpn);
    old_store.save(&c, Some(CONFIG)).unwrap();
    let old_ranking = ConnectionRankingStore::new(ConnectionRankingStore::default_path(&support));
    let mut ranking = ConnectionRanking::default();
    ranking.pin(&uuid_string(&c.id));
    old_ranking.save(&ranking).unwrap();
    let old_otp = SystemOTPStore::new(SystemOTPStore::default_path(&support));
    let mut registry = Registry::new();
    registry.add(client("Remote Desktop"));
    registry.save(&support).unwrap();

    let vault = Arc::new(VaultLifecycle::new(
        support.clone(),
        Arc::new(MemoryKeyStore::new()),
        Arc::new(FixedEntropy::new(2)),
        KdfParams::insecure_for_tests(),
    ));
    vault.set_logger(|_| {});
    vault.set_legacy_read_only(Some("the migration failed".into()));
    let connections = VaultConnections::new(vault.clone()).with_legacy(Arc::new(ReadOnly(old_store.clone())));
    let ranking_store = VaultRanking::new(vault.clone()).with_legacy(Arc::new(ReadOnly(Arc::new(old_ranking))));
    let otp_store = VaultSystemOtp::new(vault.clone()).with_legacy(Arc::new(ReadOnly(Arc::new(old_otp))));
    let registry_store = VaultRegistry::new(vault.clone())
        .with_legacy(Arc::new(ReadOnly(Arc::new(FileRegistryStore { dir: support.clone() }))));

    assert_eq!(connections.list().unwrap(), std::slice::from_ref(&c));
    assert_eq!(connections.load_config(&c.id).unwrap(), CONFIG);
    assert!(ranking_store.load().is_pinned(&uuid_string(&c.id)));
    assert_eq!(registry_store.load().unwrap().clients().len(), 1);
    let read_only = |e: std::io::Error| e.kind() == ErrorKind::PermissionDenied && e.to_string() == read_only_message();
    assert!(read_only(connections.save(&c, None).unwrap_err()));
    assert!(read_only(connections.delete(&c.id).unwrap_err()));
    assert!(read_only(ranking_store.save(&ConnectionRanking::default()).unwrap_err()));
    assert!(read_only(otp_store.save(&HashMap::new()).unwrap_err()));
    assert!(read_only(registry_store.save(&Registry::new()).unwrap_err()));
    // The old files are untouched.
    assert_eq!(old_store.list().unwrap(), std::slice::from_ref(&c));
    // The manager runs from them.
    let m = ConnectionManager::new(Dependencies::new(
        Arc::new(connections),
        Arc::new(VaultSecrets::new(vault.clone())),
        Arc::new(MockHelper::default()),
        Arc::new(MockNative::default()),
    ));
    m.reload();
    assert!(matches!(m.item(&uuid_string(&c.id)), Some(ConnectionItem::Managed(found)) if found.name == "Old Office"));
    // The migration succeeded later: the vault (empty here) is used.
    vault.set_legacy_read_only(None);
    assert!(registry_store.load().is_err(), "no vault yet: locked");
}
