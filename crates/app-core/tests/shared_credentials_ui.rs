//! Shared credentials in the Connections window (plan B Task 19, spec 3a): the Credentials section's list and
//! actions (the restricted delete with "Copy into each connection", "Create from connection…"), the editors'
//! selector (a linked editor shows and writes no username or password), the export's `credentialName` and the
//! import's question (never an automatic link), and the locked state.

mod common;

use common::{MockNative, MockProfiles, MockRoot, TempDir, clock_at};
use macvpn_app_core::connections::ConnectionsModel;
use macvpn_app_core::deps::{FolderOp, FolderOpResult, SecretField, SecretReader, SecretWriter};
use macvpn_app_core::editor::{EditorDeps, EditorFields};
use macvpn_app_core::folders::VaultFolders;
use macvpn_app_core::import_export;
use macvpn_app_core::questions::{QuestionBroker, QuestionView};
use macvpn_app_core::shared_credentials::{self, CredentialsView, SharedCredentials};
use macvpn_app_core::vault::VaultLifecycle;
use macvpn_app_core::vault_stores::VaultSecrets;
use macvpn_app_core::{ConnectionManager, Dependencies};
use macvpn_core::l10n::AppLanguage;
use macvpn_core::models::{Connection, VPNKind, uuid_string};
use macvpn_core::store::ConnectionStore;
use macvpn_core::vault::{FixedEntropy, KdfParams, MemoryKeyStore};
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;
use zeroize::Zeroizing;

const CONFIG: &str = "client\nremote vpn.example.com 1194\nauth-user-pass\n";

struct Fixture {
    tmp: TempDir,
    vault: Arc<VaultLifecycle>,
    store: Arc<ConnectionStore>,
    secrets: Arc<VaultSecrets>,
    creds: SharedCredentials,
    model: Arc<ConnectionsModel>,
}

impl Fixture {
    fn new() -> Fixture {
        AppLanguage::set_thread_override(Some(AppLanguage::En));
        let tmp = TempDir::new();
        let vault = Arc::new(VaultLifecycle::new(
            tmp.path().join("MacVPN"),
            Arc::new(MemoryKeyStore::new()),
            Arc::new(FixedEntropy::new(5)),
            KdfParams::insecure_for_tests(),
        ));
        vault.set_logger(|_| {});
        vault.create(Zeroizing::new("correct horse battery".into()), false).unwrap();
        let store = Arc::new(ConnectionStore::new(tmp.path().join("connections")));
        let secrets = Arc::new(VaultSecrets::new(vault.clone()));
        let mut deps = Dependencies::new(
            store.clone(),
            secrets.clone(),
            Arc::new(MockRoot::default()),
            Arc::new(MockNative::default()),
        );
        deps.folders = Some(Arc::new(VaultFolders::new(vault.clone())));
        let manager = ConnectionManager::new(deps);
        let model = Arc::new(ConnectionsModel::new(EditorDeps {
            manager,
            store: store.clone(),
            secrets: secrets.clone(),
            secret_writer: secrets.clone(),
            profiles: Arc::new(MockProfiles::default()),
            clock: clock_at(1_000_000.0),
        }));
        let creds = SharedCredentials::new(vault.clone());
        model.set_shared_credentials(creds.clone());
        Fixture { tmp, vault, store, secrets, creds, model }
    }

    fn openvpn(&self, name: &str, user: Option<(&str, &str)>) -> Connection {
        let c = Connection::new(name, VPNKind::Openvpn);
        self.store.save(&c, Some(CONFIG)).unwrap();
        if let Some((u, p)) = user {
            self.secrets.set(u, &c.id, SecretField::Username);
            self.secrets.set(p, &c.id, SecretField::Password);
        }
        self.model.deps().manager.reload();
        c
    }

    fn key(c: &Connection) -> String {
        uuid_string(&c.id)
    }

    fn credential(&self, name: &str) -> Uuid {
        self.creds.list().unwrap().into_iter().find(|s| s.credential.name == name).unwrap().credential.id
    }

    /// Imports `text` as `file` on a worker; returns the question it asks (if any) and the join handle.
    fn import(
        &self,
        file: &str,
        text: &str,
    ) -> (Option<QuestionView>, std::thread::JoinHandle<import_export::ImportReport>) {
        let path = self.tmp.path().join(file);
        std::fs::write(&path, text).unwrap();
        let model = self.model.clone();
        let worker = std::thread::spawn(move || {
            AppLanguage::set_thread_override(Some(AppLanguage::En));
            model.import_paths(&[path])
        });
        (wait_for_question(self.model.questions(), &worker), worker)
    }

    fn imported(&self) -> Connection {
        // From the store: the question comes before the manager reloads.
        self.store.list().unwrap().into_iter().find(|c| c.name == "office-import").expect("imported")
    }
}

fn wait_for_question(questions: &QuestionBroker, worker: &std::thread::JoinHandle<impl Sized>) -> Option<QuestionView> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some(q) = questions.current() {
            return Some(q);
        }
        if worker.is_finished() {
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    None
}

fn pw(s: &str) -> Option<Zeroizing<String>> {
    Some(Zeroizing::new(s.to_string()))
}

#[test]
fn the_section_lists_credentials_with_their_use_count_and_never_a_password() {
    let f = Fixture::new();
    let one = f.openvpn("One", None);
    f.model.add_credential("Office AD", "alice", pw("CanaryPassword")).unwrap();
    f.model.add_credential("Lab", "", None).unwrap();
    f.model.link_credential(&Fixture::key(&one), Some(f.credential("Office AD"))).unwrap();
    let view = f.model.credentials_view();
    assert!(view.available && view.message.is_none());
    let rows: Vec<(&str, &str, bool, usize)> =
        view.items.iter().map(|c| (c.name.as_str(), c.username.as_str(), c.has_password, c.used_by)).collect();
    assert_eq!(rows, [("Lab", "", false, 0), ("Office AD", "alice", true, 1)]);
    let json = serde_json::to_string(&view).unwrap();
    assert!(!json.contains("CanaryPassword"), "{json}");
    assert!(json.contains("\"usedBy\":1") && json.contains("\"hasPassword\":true"), "{json}");
}

#[test]
fn add_edit_and_rename_check_the_name_and_the_values() {
    let f = Fixture::new();
    f.model.add_credential("Office AD", "alice", None).unwrap();
    let duplicate = f.model.add_credential(" Office AD ", "bob", None).unwrap_err();
    assert_eq!(duplicate, "A credential named Office AD already exists.");
    assert!(f.model.add_credential("", "bob", None).unwrap_err().contains("1 to 64 characters"));
    assert!(f.model.add_credential("Bad", "a\nb", None).unwrap_err().contains("user name"));
    assert!(f.model.add_credential("Bad", "bob", pw("a\u{7}")).unwrap_err().contains("password"));
    let id = f.credential("Office AD");
    // Edit: the password replaced; rename to its own name is fine, to another's is not.
    f.model.edit_credential(id, Some("Office AD"), Some("alice2"), pw("secret")).unwrap();
    f.model.add_credential("Other", "x", None).unwrap();
    assert!(f.model.edit_credential(id, Some("Other"), None, None).is_err());
    f.model.edit_credential(id, Some("Renamed"), None, None).unwrap();
    let c = f.creds.list().unwrap().into_iter().find(|s| s.credential.id == id).unwrap().credential;
    assert_eq!((c.name.as_str(), c.username.as_str(), c.has_password), ("Renamed", "alice2", true));
    // `Some("")` removes the password, `None` keeps it.
    f.model.edit_credential(id, None, None, None).unwrap();
    assert!(f.creds.list().unwrap().iter().any(|s| s.credential.id == id && s.credential.has_password));
    f.model.edit_credential(id, None, None, pw("")).unwrap();
    assert!(f.creds.list().unwrap().iter().any(|s| s.credential.id == id && !s.credential.has_password));
}

#[test]
fn delete_of_a_used_credential_names_the_connections_and_copies_into_each() {
    let f = Fixture::new();
    let one = f.openvpn("Office VPN", None);
    let two = f.openvpn("Branch VPN", None);
    f.model.add_credential("Office AD", "alice", pw("shared")).unwrap();
    let id = f.credential("Office AD");
    for c in [&one, &two] {
        f.model.link_credential(&Fixture::key(c), Some(id)).unwrap();
    }
    let mut names = f.model.delete_credential(id, false).unwrap().expect("in use");
    names.sort();
    assert_eq!(names, ["Branch VPN", "Office VPN"]);
    assert_eq!(f.creds.list().unwrap().len(), 1, "nothing deleted");
    assert_eq!(f.model.delete_credential(id, true).unwrap(), None);
    assert!(f.creds.list().unwrap().is_empty());
    for c in [&one, &two] {
        let s = f.secrets.secrets(&c.id);
        assert_eq!((s.username.as_deref(), s.password.as_deref()), (Some("alice"), Some("shared")));
        assert!(f.secrets.credential_for(&c.id).is_none());
    }
    // An unused one goes at once.
    f.model.add_credential("Unused", "u", None).unwrap();
    assert_eq!(f.model.delete_credential(f.credential("Unused"), false).unwrap(), None);
}

#[test]
fn a_linked_editor_shows_no_username_and_saves_none() {
    let f = Fixture::new();
    let one = f.openvpn("One", Some(("own-user", "own-pass")));
    let two = f.openvpn("Two", None);
    let key = Fixture::key(&one);
    f.model.add_credential("Office AD", "alice", pw("shared")).unwrap();
    let id = f.credential("Office AD");
    f.model.link_credential(&Fixture::key(&two), Some(id)).unwrap();

    // Open before linking, with an unsaved rename: linking keeps the rename and hides the own fields.
    let view = f.model.open_editor(&key).unwrap();
    assert_eq!(view.credential, None);
    let EditorFields::Text(mut fields) = view.fields else { panic!("text editor") };
    assert_eq!(fields.username, "own-user");
    fields.name = "One renamed".into();
    f.model.update_editor(&key, EditorFields::Text(fields)).unwrap();
    f.model.link_credential(&key, Some(id)).unwrap();
    let view = f.model.open_editor(&key).unwrap();
    assert_eq!(view.credential.as_deref(), Some("Office AD"));
    let EditorFields::Text(fields) = &view.fields else { panic!("text editor") };
    assert_eq!((fields.username.as_str(), fields.password.as_deref()), ("", None));
    assert_eq!(fields.name, "One renamed");
    assert!(view.dirty, "the rename is still unsaved");
    let json = serde_json::to_string(&view).unwrap();
    assert!(!json.contains("alice") && !json.contains("shared") && !json.contains("own-"), "{json}");

    // A typed username is refused and nothing changes; without one the save goes through.
    let mut typed = fields.clone();
    typed.username = "mallory".into();
    let saved = f.model.save_editor(&key, EditorFields::Text(typed)).unwrap();
    assert!(saved.issues.iter().any(|i| i.contains("Office AD")), "{:?}", saved.issues);
    let mut clean = fields.clone();
    clean.username = String::new();
    let saved = f.model.save_editor(&key, EditorFields::Text(clean)).unwrap();
    assert!(saved.issues.is_empty(), "{:?}", saved.issues);
    for c in [&one, &two] {
        let s = f.secrets.secrets(&c.id);
        assert_eq!((s.username.as_deref(), s.password.as_deref()), (Some("alice"), Some("shared")));
    }

    // Back to its own fields: shown again, empty (linking deleted them).
    f.model.link_credential(&key, None).unwrap();
    let view = f.model.open_editor(&key).unwrap();
    assert_eq!(view.credential, None);
    let EditorFields::Text(fields) = &view.fields else { panic!("text editor") };
    assert_eq!(fields.username, "");
    assert!(!view.has_stored_secret.password);
}

#[test]
fn create_from_connection_links_the_ticked_matches_only() {
    let f = Fixture::new();
    let source = f.openvpn("Source", Some(("alice", "same")));
    let same = f.openvpn("Same", Some(("alice", "same")));
    let also = f.openvpn("Also", Some(("alice", "same")));
    let _other = f.openvpn("Other", Some(("alice", "different")));
    let matches = f.model.credential_matches(&Fixture::key(&source)).unwrap();
    assert_eq!(matches.iter().map(|(_, n)| n.as_str()).collect::<Vec<_>>(), ["Also", "Same"]);
    let link = vec![Fixture::key(&same)];
    f.model.credential_from_connection(&Fixture::key(&source), "Office AD", &link).unwrap();
    assert_eq!(f.secrets.credential_for(&source.id).map(|c| (c.name, c.used_by)), Some(("Office AD".into(), 2)));
    assert!(f.secrets.credential_for(&same.id).is_some());
    assert!(f.secrets.credential_for(&also.id).is_none(), "unticked");
    // Again from a linked connection, or from one without a user name: refused with a message.
    assert!(f.model.credential_from_connection(&Fixture::key(&source), "Again", &[]).unwrap_err().contains("already"));
    let empty = f.openvpn("Empty", None);
    assert!(f.model.credential_from_connection(&Fixture::key(&empty), "Empty", &[]).unwrap_err().contains("no stored"));
    // A connection that is not a match cannot be smuggled in.
    let bad = vec![Fixture::key(&_other)];
    assert!(f.model.credential_from_connection(&Fixture::key(&also), "Also AD", &bad).is_err());
    assert!(f.secrets.credential_for(&also.id).is_none());
}

#[test]
fn export_names_the_credential_and_never_a_value() {
    let f = Fixture::new();
    let one = f.openvpn("One", Some(("alice", "CanaryShared")));
    let plan = import_export::export_plan(f.model.deps(), &one, false).unwrap();
    assert_eq!(String::from_utf8(plan.data).unwrap(), CONFIG, "no line without metadata");
    f.model.credential_from_connection(&Fixture::key(&one), "Office \"AD\"", &[]).unwrap();
    let text = String::from_utf8(import_export::export_plan(f.model.deps(), &one, false).unwrap().data).unwrap();
    assert_eq!(text, format!("# macvpn-meta: {{\"credentialName\":\"Office \\\"AD\\\"\"}}\n{CONFIG}"));
    assert!(!text.contains("alice") && !text.contains("CanaryShared"));
}

#[test]
fn one_meta_line_carries_the_folder_and_the_credential_both_ways() {
    let f = Fixture::new();
    let one = f.openvpn("One", Some(("alice", "CanaryShared")));
    f.model.credential_from_connection(&Fixture::key(&one), "Office AD", &[]).unwrap();
    let manager = &f.model.deps().manager;
    let store = manager.folder_store().unwrap();
    let created = |parent, name: &str| match store.apply(FolderOp::Create { parent, name: name.into() }).unwrap() {
        FolderOpResult::Created(id) => id,
        other => panic!("{other:?}"),
    };
    let work = created(None, "Work");
    let clients = created(Some(work), "Clients");
    store.apply(FolderOp::MoveItem { key: Fixture::key(&one), folder: Some(clients) }).unwrap();
    manager.reload_folders();
    let text = String::from_utf8(import_export::export_plan(f.model.deps(), &one, false).unwrap().data).unwrap();
    assert_eq!(
        text,
        format!("# macvpn-meta: {{\"credentialName\":\"Office AD\",\"folder\":[\"Work\",\"Clients\"]}}\n{CONFIG}")
    );
    assert!(!text.contains("alice") && !text.contains("CanaryShared"));

    // The import reads the line once: it asks about the credential and lands in the same folder.
    let (question, worker) = f.import("office-import.ovpn", &text);
    let q = question.expect("the import asks");
    assert!(f.model.questions().answer(q.id, true));
    let report = worker.join().unwrap();
    assert!(report.errors.is_empty(), "{:?}", report.errors);
    let imported = f.imported();
    assert_eq!(f.secrets.credential_for(&imported.id).map(|c| c.name), Some("Office AD".into()));
    assert_eq!(manager.folder_path(&Fixture::key(&imported)), Some(vec!["Work".to_string(), "Clients".to_string()]));
    assert_eq!(f.store.load_config(&imported.id).unwrap(), CONFIG, "the meta line is not stored");
}

#[test]
fn import_asks_before_using_a_credential_of_the_same_name() {
    let f = Fixture::new();
    f.model.add_credential("Office AD", "alice", pw("shared")).unwrap();
    let file = format!("# macvpn-meta: {{\"credentialName\":\"Office AD\"}}\n{CONFIG}");

    // The default answer: the connection's own fields, nothing linked.
    let (question, worker) = f.import("office-import.ovpn", &file);
    let q = question.expect("the import asks");
    assert_eq!(q.title, "Use the shared credential 'Office AD' for this connection to vpn.example.com?");
    assert_eq!((q.yes.as_str(), q.no.as_str()), ("Use Shared Credential", "Use Own Fields"));
    assert!(q.options.is_empty());
    let imported = f.imported();
    assert!(f.secrets.credential_for(&imported.id).is_none(), "nothing linked before the answer");
    assert!(f.model.questions().answer(q.id, false));
    worker.join().unwrap();
    assert!(f.secrets.credential_for(&imported.id).is_none());
    let stored = f.store.load_config(&imported.id).unwrap();
    assert_eq!(stored, CONFIG, "the meta line is not stored");
    f.model.delete(&imported.id);

    // Yes: linked.
    let (question, worker) = f.import("office-import.ovpn", &file);
    let q = question.expect("the import asks");
    assert!(f.model.questions().answer(q.id, true));
    worker.join().unwrap();
    assert_eq!(f.secrets.credential_for(&f.imported().id).map(|c| c.name), Some("Office AD".into()));
}

#[test]
fn import_of_an_unknown_name_offers_the_credentials_or_the_own_fields() {
    let f = Fixture::new();
    let file = format!("# macvpn-meta: {{\"credentialName\":\"Head Office\"}}\n{CONFIG}");
    // No credential at all: a note, no question.
    let (question, worker) = f.import("office-import.ovpn", &file);
    assert!(question.is_none());
    let report = worker.join().unwrap();
    assert!(report.notes.iter().any(|n| n.contains("no shared credential named 'Head Office'")), "{report:?}");
    f.model.delete(&f.imported().id);

    f.model.add_credential("Office AD", "alice", pw("shared")).unwrap();
    f.model.add_credential("Lab", "lab", None).unwrap();
    let (question, worker) = f.import("office-import.ovpn", &file);
    let q = question.expect("the pick");
    assert_eq!(q.title, "There is no shared credential named 'Head Office'");
    // As the Ask path (final review 1.2.0 L4): the server the password goes to, and trust the file first.
    assert!(q.message.contains("vpn.example.com"), "{}", q.message);
    assert!(q.message.contains("only if you trust the file"), "{}", q.message);
    assert_eq!(q.options, ["Lab", "Office AD"]);
    assert!(!f.model.questions().answer_choice(q.id, Some(2)), "not an option");
    assert!(f.model.questions().answer_choice(q.id, Some(1)));
    worker.join().unwrap();
    assert_eq!(f.secrets.credential_for(&f.imported().id).map(|c| c.name), Some("Office AD".into()));
}

#[test]
fn without_a_vault_or_locked_the_section_says_so() {
    let f = Fixture::new();
    let one = f.openvpn("One", Some(("alice", "x")));
    f.vault.lock();
    assert_eq!(f.model.credentials_view(), CredentialsView::locked());
    let locked = shared_credentials::locked_message();
    assert_eq!(f.model.add_credential("Office AD", "alice", None).unwrap_err(), locked);
    assert_eq!(f.model.link_credential(&Fixture::key(&one), Some(Uuid::new_v4())).unwrap_err(), locked);

    // An app without a vault (until Task 14 wires it): the same answers.
    let deps = f.model.deps().clone();
    let bare = ConnectionsModel::new(deps);
    assert_eq!(bare.credentials_view(), CredentialsView::locked());
    assert_eq!(bare.delete_credential(Uuid::new_v4(), false).unwrap_err(), locked);
}

#[test]
fn a_choice_question_takes_an_option_or_none() {
    let broker = Arc::new(QuestionBroker::new());
    let asking = broker.clone();
    let worker = std::thread::spawn(move || {
        asking.ask_choice("t".into(), "m".into(), vec!["A".into(), "B".into()], "Use".into(), "No".into())
    });
    let q = wait_for_question(&broker, &worker).unwrap();
    assert_eq!(q.options, ["A", "B"]);
    assert!(!broker.answer_choice(q.id + 1, Some(0)));
    assert!(broker.answer_choice(q.id, Some(1)));
    assert_eq!(worker.join().unwrap(), Some(1));
    // A yes / no question takes 0 or none only; the window closing is a no.
    let asking = broker.clone();
    let worker = std::thread::spawn(move || asking.ask("t".into(), "m".into(), "Y".into(), "N".into()));
    let q = wait_for_question(&broker, &worker).unwrap();
    assert!(!broker.answer_choice(q.id, Some(1)));
    broker.cancel();
    assert!(!worker.join().unwrap());
}
