//! Shared credentials in the app (plan B Task 18, spec 3a): the vault-backed secret store resolves links, so the
//! connect path (root stdin, `SCNetworkConnectionStart` options) gets the credential's username and password and
//! the item's own other secrets; the orchestration over the vault lifecycle (CRUD, restricted delete,
//! copy-into-connections, "Create from connection…", the import's match by name).

mod common;

use common::{MobileconfigProfiles, MockHelper, MockNative, TempDir, clock_at};
use macvpn_app_core::deps::{SecretField, SecretReader, SecretWriter, SystemVpn};
use macvpn_app_core::editor::{self, EditorDeps};
use macvpn_app_core::shared_credentials::{DeleteCredentialError, ImportLink, SharedCredentials, prompt_credential};
use macvpn_app_core::vault::VaultLifecycle;
use macvpn_app_core::vault_stores::VaultSecrets;
use macvpn_app_core::{ConnectionManager, Dependencies};
use macvpn_core::credentials::{CredentialAnswer, CredentialField, CredentialPrompt, CredentialValues};
use macvpn_core::l10n::AppLanguage;
use macvpn_core::models::{Connection, CredentialRef, NativeSettings, OTPSetting, Secrets, VPNKind, uuid_string};
use macvpn_core::native::{ENT_IPSEC, ENT_PPP, IPSEC_SHARED_SECRET, PPP_AUTH_NAME, PPP_AUTH_PASSWORD};
use macvpn_core::store::ConnectionStore;
use macvpn_core::vault::{FixedEntropy, KdfParams, MemoryKeyStore};
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use zeroize::Zeroizing;

const SVC: &str = "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4";

struct Fixture {
    _tmp: TempDir,
    vault: Arc<VaultLifecycle>,
    log: Arc<Mutex<Vec<String>>>,
    store: Arc<ConnectionStore>,
    helper: Arc<MockHelper>,
    native: Arc<MockNative>,
    secrets: Arc<VaultSecrets>,
    creds: SharedCredentials,
}

impl Fixture {
    fn new() -> Fixture {
        AppLanguage::set_thread_override(Some(AppLanguage::En));
        let tmp = TempDir::new();
        let vault = Arc::new(VaultLifecycle::new(
            tmp.path().join("MacVPN"),
            Arc::new(MemoryKeyStore::new()),
            Arc::new(FixedEntropy::new(3)),
            KdfParams::insecure_for_tests(),
        ));
        let log = Arc::new(Mutex::new(Vec::new()));
        let sink = log.clone();
        vault.set_logger(move |line| sink.lock().unwrap().push(line.to_string()));
        vault.create(Zeroizing::new("correct horse battery".into()), false).unwrap();
        Fixture {
            store: Arc::new(ConnectionStore::new(tmp.path().join("connections"))),
            helper: Arc::new(MockHelper::default()),
            native: Arc::new(MockNative::default()),
            secrets: Arc::new(VaultSecrets::new(vault.clone())),
            creds: SharedCredentials::new(vault.clone()),
            vault,
            log,
            _tmp: tmp,
        }
    }

    fn manager(&self) -> Arc<ConnectionManager> {
        let deps =
            Dependencies::new(self.store.clone(), self.secrets.clone(), self.helper.clone(), self.native.clone());
        let m = ConnectionManager::new(deps);
        m.reload();
        m
    }

    fn openvpn(&self, name: &str) -> Connection {
        let c = Connection::new(name, VPNKind::Openvpn);
        self.store.save(&c, Some("client\nremote vpn.example.com 1194\nauth-user-pass\n")).unwrap();
        c
    }

    /// The stdin of the last `mvpn up` of `c`.
    fn connect_stdin(&self, c: &Connection) -> String {
        self.helper.respond("status", Ok("[]"));
        let m = self.manager();
        m.connect(c, false);
        let key = uuid_string(&c.id);
        let up = self.helper.calls().into_iter().rev().find(|call| call.line.contains(&key)).expect("up call");
        up.stdin.unwrap_or_default()
    }
}

fn pw(s: &str) -> Option<Zeroizing<String>> {
    Some(Zeroizing::new(s.to_string()))
}

#[test]
fn a_linked_connection_connects_with_the_credentials_username_and_password() {
    let f = Fixture::new();
    let c = f.openvpn("Office");
    f.secrets.set("own-user", &c.id, SecretField::Username);
    f.secrets.set("own-pass", &c.id, SecretField::Password);
    f.secrets.set("keypass", &c.id, SecretField::KeyPassword);
    let cred = f.creds.create("Office AD", "alice", pw("shared")).unwrap();
    f.creds.link(&uuid_string(&c.id), Some(cred)).unwrap();

    let secrets = f.secrets.secrets(&c.id);
    assert_eq!(secrets.username.as_deref(), Some("alice"));
    assert_eq!(secrets.password.as_deref(), Some("shared"));
    assert_eq!(secrets.key_password.as_deref(), Some("keypass"), "other secrets stay per connection");
    assert_eq!(f.connect_stdin(&c), "username=alice\npassword=shared\nkeypass=keypass\n");

    // Unlink: its own values again, which the link deleted.
    f.creds.link(&uuid_string(&c.id), None).unwrap();
    let secrets = f.secrets.secrets(&c.id);
    assert_eq!((secrets.username, secrets.password), (None, None));
    assert_eq!(secrets.key_password.as_deref(), Some("keypass"));
}

#[test]
fn a_linked_native_connection_passes_the_credential_as_auth_name_and_keeps_its_psk() {
    let f = Fixture::new();
    let mut c = Connection::new("Office L2TP", VPNKind::L2tp);
    c.native_service_name = Some("Office L2TP".into());
    c.native = Some(NativeSettings { server: "vpn.example.com".into(), account: "bob".into(), ..Default::default() });
    f.store.save(&c, None).unwrap();
    f.helper.respond("status", Ok("[]"));
    f.native.set_list(Ok(vec![SystemVpn::new(SVC, "Office L2TP", "L2TP", "Disconnected")]));
    f.native.set_address(SVC, Some("vpn.example.com"));
    f.secrets.set("own-psk", &c.id, SecretField::Psk);
    let cred = f.creds.create("Office L2TP user", "alice", pw("shared")).unwrap();
    f.creds.link(&uuid_string(&c.id), Some(cred)).unwrap();

    f.manager().connect(&c, false);
    let start = f.native.starts().pop().expect("a native start");
    let options = start.options.expect("start options");
    assert_eq!(options[ENT_PPP][PPP_AUTH_NAME], "alice");
    assert_eq!(options[ENT_PPP][PPP_AUTH_PASSWORD], "shared");
    assert_eq!(options[ENT_IPSEC][IPSEC_SHARED_SECRET], "own-psk");
}

#[test]
fn a_credential_without_a_password_is_asked_for_and_saved_into_the_credential() {
    let f = Fixture::new();
    let one = f.openvpn("One");
    let two = f.openvpn("Two");
    let cred = f.creds.create("Office AD", "alice", None).unwrap();
    for c in [&one, &two] {
        f.creds.link(&uuid_string(&c.id), Some(cred)).unwrap();
    }
    // No password: the 1.1 required-fields check (`credentials::missing` over `secrets()`) sees it as missing,
    // and the prompt names the credential.
    let secrets = f.secrets.secrets(&one.id);
    assert_eq!(secrets.username.as_deref(), Some("alice"));
    assert_eq!(secrets.password, None);
    let named = CredentialRef { name: "Office AD".into(), used_by: 2, ..Default::default() };
    assert_eq!(f.secrets.credential_for(&one.id), Some(named.clone()));
    assert_eq!(prompt_credential(f.secrets.as_ref(), &one.id, &[SecretField::Password]), Some(named.clone()));
    assert_eq!(prompt_credential(f.secrets.as_ref(), &one.id, &[SecretField::KeyPassword]), None);
    // The user name of a linked credential (an empty one) is the credential's too (final review 1.2.0 L3).
    assert_eq!(prompt_credential(f.secrets.as_ref(), &one.id, &[SecretField::Username]), Some(named.clone()));
    let own = f.openvpn("Own");
    assert_eq!(f.secrets.credential_for(&own.id), None);
    assert_eq!(prompt_credential(f.secrets.as_ref(), &own.id, &[SecretField::Password]), None);

    // "Save" of the prompt (and a re-prompt after a sign-in failure) writes through `save_prompted`: into the
    // credential, so the second linked connection connects with it and needs no prompt.
    f.secrets.save_prompted("typed", &one.id, SecretField::Password);
    assert!(f.creds.list().unwrap()[0].credential.has_password);
    assert_eq!(f.secrets.secrets(&two.id).password.as_deref(), Some("typed"));
    assert_eq!(f.connect_stdin(&two), "username=alice\npassword=typed\n");
    f.secrets.save_prompted("retyped", &two.id, SecretField::Password);
    assert_eq!(f.secrets.secrets(&one.id).password.as_deref(), Some("retyped"));
}

/// The manager end to end: the prompt for a linked credential without a password names the credential, its
/// "Save" goes into the credential (through `save_prompted`), and the second linked connection asks nothing.
#[test]
fn the_prompt_names_the_credential_and_its_save_updates_it() {
    let f = Fixture::new();
    let one = f.openvpn("One");
    let two = f.openvpn("Two");
    let cred = f.creds.create("Office AD", "alice", None).unwrap();
    for c in [&one, &two] {
        f.creds.link(&uuid_string(&c.id), Some(cred)).unwrap();
    }
    let mut deps = Dependencies::new(f.store.clone(), f.secrets.clone(), f.helper.clone(), f.native.clone());
    deps.secret_writer = Some(f.secrets.clone());
    let m = ConnectionManager::new(deps);
    m.reload();
    let prompts = Arc::new(Mutex::new(Vec::new()));
    let seen = prompts.clone();
    m.set_credential_handler(move |prompt: CredentialPrompt| {
        let fields = prompt.fields.clone();
        seen.lock().unwrap().push(prompt);
        let mut values = CredentialValues::default();
        for field in fields {
            values.set(field, Zeroizing::new("typed".to_string()));
        }
        CredentialAnswer::Provided { values, save: true }
    });
    let connected = |c: &Connection| {
        format!(
            r#"[{{"id":"{}","kind":"openvpn","state":"connected","iface":null,"ip":null,"since":null}}]"#,
            uuid_string(&c.id)
        )
    };
    f.helper.respond("status", Ok(&connected(&one)));
    m.connect(&one, false);
    m.flush_saves();
    {
        let prompts = prompts.lock().unwrap();
        assert_eq!(prompts.len(), 1);
        assert_eq!(prompts[0].fields, [CredentialField::Password]);
        assert_eq!(
            prompts[0].credential,
            Some(CredentialRef { name: "Office AD".into(), used_by: 2, ..Default::default() })
        );
    }
    assert!(f.creds.list().unwrap()[0].credential.has_password, "saved into the credential");
    assert_eq!(f.secrets.secrets(&two.id).password.as_deref(), Some("typed"));
    f.helper.respond("status", Ok(&connected(&two)));
    m.connect(&two, false);
    assert_eq!(prompts.lock().unwrap().len(), 1, "the second linked connection asks nothing");

    // A connection with its own fields: no credential named.
    let own = f.openvpn("Own");
    m.reload();
    f.helper.respond("status", Ok(&connected(&own)));
    m.connect(&own, false);
    m.flush_saves();
    let prompts = prompts.lock().unwrap();
    assert_eq!(prompts.len(), 2);
    assert_eq!(prompts[1].credential, None);
}

#[test]
fn delete_while_linked_lists_the_items_and_copy_into_connections_unlinks_them() {
    let f = Fixture::new();
    let one = f.openvpn("One");
    let cred = f.creds.create("Office AD", "alice", pw("shared")).unwrap();
    f.creds.link(&uuid_string(&one.id), Some(cred)).unwrap();
    f.creds.link(SVC, Some(cred)).unwrap();

    let mut expected = vec![uuid_string(&one.id), SVC.to_string()];
    expected.sort();
    match f.creds.delete(cred, false) {
        Err(DeleteCredentialError::InUse(items)) => assert_eq!(items, expected),
        other => panic!("expected InUse, got {other:?}"),
    }
    assert_eq!(f.creds.list().unwrap().len(), 1);
    assert_eq!(f.creds.list().unwrap()[0].used_by, 2);

    f.creds.delete(cred, true).unwrap();
    assert!(f.creds.list().unwrap().is_empty());
    for id in [one.id, Uuid::parse_str(SVC).unwrap()] {
        let s = f.secrets.secrets(&id);
        assert_eq!((s.username.as_deref(), s.password.as_deref()), (Some("alice"), Some("shared")));
        assert_eq!(f.creds.credential_of(&uuid_string(&id)).unwrap(), None);
    }
    // An unused credential is deleted without copying.
    let unused = f.creds.create("Unused", "u", None).unwrap();
    f.creds.delete(unused, false).unwrap();
    assert!(f.creds.list().unwrap().is_empty());
}

#[test]
fn create_from_connection_links_the_chosen_matches() {
    let f = Fixture::new();
    let source = f.openvpn("Source");
    let same = f.openvpn("Same");
    let different = f.openvpn("Different");
    for (c, pass) in [(&source, "pw"), (&same, "pw"), (&different, "other")] {
        f.secrets.set("alice", &c.id, SecretField::Username);
        f.secrets.set(pass, &c.id, SecretField::Password);
    }
    let key = uuid_string(&source.id);
    assert_eq!(f.creds.matching_items(&key).unwrap(), vec![uuid_string(&same.id)]);
    let cred = f.creds.create_from_connection(&key, "Office AD", &[uuid_string(&same.id)]).unwrap();
    assert_eq!(f.creds.credential_of(&uuid_string(&same.id)).unwrap(), Some(cred));
    assert_eq!(f.creds.credential_of(&uuid_string(&different.id)).unwrap(), None);
    assert_eq!(f.secrets.secrets(&same.id).password.as_deref(), Some("pw"));
    assert_eq!(f.creds.list().unwrap()[0].used_by, 2);
}

/// Review M3: an imported file never links itself to a shared credential. A matching name only asks, naming the
/// server the file would send the shared password to; the default is the connection's own fields.
#[test]
fn import_never_links_by_itself_and_asks_with_the_remote_host() {
    let f = Fixture::new();
    let cred = f.creds.create("Office AD", "alice", pw("pw")).unwrap();
    // Another connection to the same server is already linked: still no automatic link.
    let linked = f.openvpn("Linked");
    f.creds.link(&uuid_string(&linked.id), Some(cred)).unwrap();
    let a = f.openvpn("A");
    let key = uuid_string(&a.id);
    let config = "client\nremote attacker.example 443\nauth-user-pass\n";
    assert_eq!(
        f.creds.link_imported(Some("Office AD"), VPNKind::Openvpn, config).unwrap(),
        ImportLink::Ask { credential: cred, name: "Office AD".into(), remote: Some("attacker.example".into()) }
    );
    let same_server = "client\nremote vpn.example.com 1194\nauth-user-pass\n";
    assert!(matches!(
        f.creds.link_imported(Some("Office AD"), VPNKind::Openvpn, same_server).unwrap(),
        ImportLink::Ask { remote: Some(ref r), .. } if r == "vpn.example.com"
    ));
    assert_eq!(f.creds.credential_of(&key).unwrap(), None, "asking links nothing");
    assert_eq!(f.secrets.secrets(&a.id).password, None);
    assert_eq!(f.creds.list().unwrap()[0].used_by, 1);
    // No server in the config: still asked, without a host.
    assert!(matches!(
        f.creds.link_imported(Some("Office AD"), VPNKind::Openvpn, "client\n").unwrap(),
        ImportLink::Ask { remote: None, .. }
    ));
    // The user's yes goes through `link`.
    f.creds.link(&key, Some(cred)).unwrap();
    assert_eq!(f.creds.credential_of(&key).unwrap(), Some(cred));

    assert_eq!(
        f.creds.link_imported(Some("office ad"), VPNKind::Openvpn, config).unwrap(),
        ImportLink::Unknown { name: "office ad".into(), remote: Some("attacker.example".into()) }
    );
    assert_eq!(f.creds.link_imported(None, VPNKind::Openvpn, config).unwrap(), ImportLink::Own);
}

/// Review M4: an editor's write (`SecretWriter::set`) to a linked connection never changes the shared credential
/// the other connections use; only the credential prompt's `save_prompted` does.
#[test]
fn an_editor_write_to_a_linked_item_is_refused_and_logged_without_the_value() {
    let f = Fixture::new();
    let one = f.openvpn("One");
    let two = f.openvpn("Two");
    let cred = f.creds.create("Office AD", "alice", pw("shared")).unwrap();
    for c in [&one, &two] {
        f.creds.link(&uuid_string(&c.id), Some(cred)).unwrap();
    }
    f.secrets.set("CanaryUser", &one.id, SecretField::Username);
    f.secrets.set("CanaryPass", &one.id, SecretField::Password);
    let s = f.secrets.secrets(&two.id);
    assert_eq!((s.username.as_deref(), s.password.as_deref()), (Some("alice"), Some("shared")));
    let log = f.log.lock().unwrap().join("\n");
    assert!(log.contains("the item uses a shared credential"), "{log}");
    assert!(!log.contains("Canary"), "no value in the log");
    // The other fields are still the item's own.
    f.secrets.set("psk", &one.id, SecretField::Psk);
    assert_eq!(f.secrets.secrets(&one.id).psk.as_deref(), Some("psk"));
    assert_eq!(f.secrets.secrets(&two.id).psk, None);
}

#[test]
fn the_editors_refuse_a_typed_username_or_password_for_a_linked_connection() {
    let f = Fixture::new();
    let one = f.openvpn("One");
    let two = f.openvpn("Two");
    let cred = f.creds.create("Office AD", "alice", pw("shared")).unwrap();
    for c in [&one, &two] {
        f.creds.link(&uuid_string(&c.id), Some(cred)).unwrap();
    }
    let deps = EditorDeps {
        manager: f.manager(),
        store: f.store.clone(),
        secrets: f.secrets.clone(),
        secret_writer: f.secrets.clone(),
        profiles: Arc::new(MobileconfigProfiles::default()),
        clock: clock_at(1_000_000.0),
    };
    let config = "client\nremote vpn.example.com 1194\nauth-user-pass\n";
    let typed = Secrets { password: Some("typed".into()), ..Secrets::default() };
    let issues = editor::save_text(&deps, &one, "One", config, &typed, &BTreeSet::new(), None);
    assert_eq!(issues.len(), 1);
    assert!(issues[0].message.contains("Office AD"), "{:?}", issues[0].message);
    assert_eq!(f.secrets.secrets(&two.id).password.as_deref(), Some("shared"));
    // A linked editor sends `None` for both (or an empty value): saved, the credential untouched.
    let untouched = Secrets { username: Some(String::new()), key_password: Some("kp".into()), ..Secrets::default() };
    assert!(editor::save_text(&deps, &one, "One renamed", config, &untouched, &BTreeSet::new(), None).is_empty());
    assert_eq!(f.secrets.secrets(&one.id).key_password.as_deref(), Some("kp"));
    let s = f.secrets.secrets(&two.id);
    assert_eq!((s.username.as_deref(), s.password.as_deref()), (Some("alice"), Some("shared")));

    // A system VPN linked to the credential: a typed password is refused, a PSK is its own.
    f.creds.link(SVC, Some(cred)).unwrap();
    let service = SystemVpn::new(SVC, "Office L2TP", "L2TP", "Disconnected");
    let error = editor::save_system_secrets(&deps, &service, Some("psk"), Some("typed"), OTPSetting::default());
    assert!(error.is_some_and(|e| e.contains("Office AD")));
    assert_eq!(editor::save_system_secrets(&deps, &service, Some("psk"), None, OTPSetting::default()), None);
    let svc = Uuid::parse_str(SVC).unwrap();
    assert_eq!(f.secrets.secrets(&svc).psk.as_deref(), Some("psk"));
    assert_eq!(f.secrets.secrets(&svc).password.as_deref(), Some("shared"));

    // A linked native connection: the form's account name goes into the profile only, never into the credential.
    let mut native = Connection::new("Office L2TP", VPNKind::L2tp);
    native.native =
        Some(NativeSettings { server: "vpn.example.com".into(), account: "bob".into(), ..Default::default() });
    f.store.save(&native, None).unwrap();
    f.creds.link(&uuid_string(&native.id), Some(cred)).unwrap();
    let settings = native.native.clone().unwrap();
    let error =
        editor::save_native(&deps, &native, "Office L2TP", &settings, Some("typed"), None, OTPSetting::default());
    assert!(error.is_some_and(|e| e.contains("Office AD")));
    assert_eq!(
        editor::save_native(&deps, &native, "Office L2TP", &settings, None, Some("psk"), OTPSetting::default()),
        None
    );
    let s = f.secrets.secrets(&native.id);
    assert_eq!(
        (s.username.as_deref(), s.password.as_deref(), s.psk.as_deref()),
        (Some("alice"), Some("shared"), Some("psk"))
    );
    assert_eq!(f.creds.list().unwrap()[0].credential.username, "alice");
}

#[test]
fn names_are_unique() {
    let f = Fixture::new();
    f.creds.create("Office AD", "alice", None).unwrap();
    assert!(f.creds.create("Office AD", "bob", None).is_err());
    let other = f.creds.create("Other", "bob", None).unwrap();
    assert!(f.creds.update(other, Some("Office AD"), None, None).is_err());
    f.creds.update(other, Some("Renamed"), Some("bobby"), Some(pw("x"))).unwrap();
    let list = f.creds.list().unwrap();
    assert_eq!(list.iter().map(|c| c.credential.name.as_str()).collect::<Vec<_>>(), ["Office AD", "Renamed"]);
    assert!(list[1].credential.has_password);
}

#[test]
fn locked_reads_nothing_and_writes_fail_with_a_log_line_only() {
    let f = Fixture::new();
    let c = f.openvpn("Office");
    let cred = f.creds.create("Office AD", "alice", pw("CanaryShared")).unwrap();
    f.creds.link(&uuid_string(&c.id), Some(cred)).unwrap();
    f.vault.lock();
    assert_eq!(f.secrets.get(&c.id, SecretField::Username), None);
    assert_eq!(f.secrets.credential_for(&c.id), None);
    assert!(f.creds.list().is_err());
    f.secrets.set("CanaryTyped", &c.id, SecretField::Password);
    let log = f.log.lock().unwrap().join("\n");
    assert!(log.contains("not saved"), "{log}");
    assert!(!log.contains("Canary"), "no secret in the log");
}

#[test]
fn forgetting_an_items_secrets_also_unlinks_it() {
    let f = Fixture::new();
    let c = f.openvpn("Office");
    f.secrets.set("psk", &c.id, SecretField::Psk);
    let cred = f.creds.create("Office AD", "alice", pw("pw")).unwrap();
    f.creds.link(&uuid_string(&c.id), Some(cred)).unwrap();
    f.secrets.delete_all(&c.id);
    assert_eq!(f.secrets.secrets(&c.id), Default::default());
    assert_eq!(f.creds.credential_of(&uuid_string(&c.id)).unwrap(), None);
    assert_eq!(f.creds.list().unwrap()[0].used_by, 0);
    // Removing every secret (uninstall with the user data) takes the credentials too.
    f.secrets.remove_all();
    assert!(f.creds.list().unwrap().is_empty());
}

/// WinVPN 2c Task 12 (Cisco IPsec on Windows, option A): **Make an L2TP/IPsec Copy** makes a new L2TP connection in
/// the same folder with the same server, account, `send_all_traffic`, OTP setting, PSK and password (or the same
/// shared-credential link); the group name is dropped; the original stays as it was.
#[test]
fn l2tp_copy_keeps_server_account_and_secrets() {
    use macvpn_app_core::deps::{ConnectionRepository, FolderOp, FolderOpResult, FolderStore};
    use macvpn_app_core::folders::VaultFolders;
    use macvpn_app_core::vault_stores::VaultConnections;
    use macvpn_core::models::OTPSeparator;

    let f = Fixture::new();
    let store = Arc::new(VaultConnections::new(f.vault.clone()));
    let folders = Arc::new(VaultFolders::new(f.vault.clone()));
    let mut deps = Dependencies::new(store.clone(), f.secrets.clone(), f.helper.clone(), f.native.clone());
    deps.folders = Some(folders.clone());
    let manager = ConnectionManager::new(deps);
    let profiles = Arc::new(MobileconfigProfiles::default());
    let ed = EditorDeps {
        manager: manager.clone(),
        store: store.clone(),
        secrets: f.secrets.clone(),
        secret_writer: f.secrets.clone(),
        profiles: profiles.clone(),
        clock: clock_at(1_000_000.0),
    };

    let mut cisco = Connection::new("Office", VPNKind::Cisco);
    cisco.native = Some(NativeSettings {
        server: "vpn.example.com".into(),
        account: "bob".into(),
        group_name: "staff".into(),
        send_all_traffic: true,
    });
    cisco.native_service_name = Some("Office".into());
    cisco.otp = OTPSetting::new(true, OTPSeparator::Comma);
    store.save(&cisco, None).unwrap();
    f.secrets.set("bob", &cisco.id, SecretField::Username);
    f.secrets.set("own-pass", &cisco.id, SecretField::Password);
    f.secrets.set("the-psk", &cisco.id, SecretField::Psk);
    let FolderOpResult::Created(work) = folders.apply(FolderOp::Create { parent: None, name: "Work".into() }).unwrap()
    else {
        panic!("no folder")
    };
    folders.apply(FolderOp::MoveItem { key: uuid_string(&cisco.id), folder: Some(work) }).unwrap();
    manager.reload();
    manager.reload_folders();

    let copy = editor::l2tp_copy_of(&ed, &cisco, Some(&f.creds)).unwrap();
    assert_eq!(copy.install_error, None);
    let c = manager.connections().into_iter().find(|c| c.id == copy.id).expect("the copy is listed");
    assert_eq!((c.kind, c.name.as_str()), (VPNKind::L2tp, "Office (L2TP)"));
    assert_eq!(
        c.native,
        Some(NativeSettings {
            server: "vpn.example.com".into(),
            account: "bob".into(),
            group_name: String::new(),
            send_all_traffic: true,
        })
    );
    assert_eq!(c.native_service_name.as_deref(), Some("Office (L2TP)"));
    assert_eq!(c.otp, cisco.otp);
    let s = f.secrets.secrets(&copy.id);
    assert_eq!(
        (s.username.as_deref(), s.password.as_deref(), s.psk.as_deref()),
        (Some("bob"), Some("own-pass"), Some("the-psk"))
    );
    assert_eq!(manager.placement(&uuid_string(&copy.id)).and_then(|p| p.folder), Some(work));
    // The copy's profile is installed as a save would (WinVPN: its RAS entry is written).
    let installs = profiles.installs.lock().unwrap().clone();
    assert_eq!(installs.iter().map(|i| i.0).collect::<Vec<_>>(), [copy.id]);
    // The original is untouched.
    let original = manager.connections().into_iter().find(|c| c.id == cisco.id).unwrap();
    assert_eq!((original.kind, &original.native, &original.name), (VPNKind::Cisco, &cisco.native, &cisco.name));
    let s = f.secrets.secrets(&cisco.id);
    assert_eq!((s.password.as_deref(), s.psk.as_deref()), (Some("own-pass"), Some("the-psk")));

    // A linked Cisco connection: the copy is linked to the same credential, its PSK is its own.
    let cred = f.creds.create("Office AD", "alice", pw("shared")).unwrap();
    let mut linked = Connection::new("Branch", VPNKind::Cisco);
    linked.native = Some(NativeSettings { server: "192.0.2.10".into(), account: "alice".into(), ..Default::default() });
    store.save(&linked, None).unwrap();
    f.creds.link(&uuid_string(&linked.id), Some(cred)).unwrap();
    f.secrets.set("branch-psk", &linked.id, SecretField::Psk);
    manager.reload();
    let copy = editor::l2tp_copy_of(&ed, &linked, Some(&f.creds)).unwrap();
    assert_eq!(f.creds.credential_of(&uuid_string(&copy.id)).unwrap(), Some(cred));
    let s = f.secrets.secrets(&copy.id);
    assert_eq!(
        (s.username.as_deref(), s.password.as_deref(), s.psk.as_deref()),
        (Some("alice"), Some("shared"), Some("branch-psk"))
    );
    let copied = manager.connections().into_iter().find(|c| c.id == copy.id).unwrap();
    assert_eq!(copied.native.as_ref().map(|n| n.server.as_str()), Some("192.0.2.10"));
    assert_eq!(manager.placement(&uuid_string(&copy.id)).and_then(|p| p.folder), None);

    // Only a Cisco IPsec connection is copied.
    let l2tp = manager.connections().into_iter().find(|c| c.kind == VPNKind::L2tp).unwrap();
    assert!(editor::l2tp_copy_of(&ed, &l2tp, Some(&f.creds)).is_err());
}
