//! Team catalog connections at connect time (plan Task 13, spec 6 and 8): credential slots filled through the 1.1
//! credential prompt, team secrets, the SSTP and native per-user fields, the risky-directive acknowledgement, the
//! read-only editors, "Install profile" for native connections, the duplicate and the control API's ids.

mod catalog_support;
mod common;

use catalog_support::*;
use common::{MobileconfigProfiles, clock_at, up_line};
use macvpn_app_core::connections::ConnectionsModel;
use macvpn_app_core::credential_prompt::CredentialBroker;
use macvpn_app_core::deps::{ConnectionRepository, SecretReader, SystemVpn};
use macvpn_app_core::editor::{EditorDeps, EditorFields};
use macvpn_app_core::manager::ConnectionItem;
use macvpn_app_core::vault_stores::VaultConnections;
use macvpn_core::catalog::payload::{CatalogConnection, CatalogPayload};
use macvpn_core::control::protocol::is_uuid_shaped;
use macvpn_core::control::registry::{PairedClient, Registry};
use macvpn_core::credentials::{CredentialAnswer, CredentialField, CredentialPrompt, CredentialValues};
use macvpn_core::date::Date;
use macvpn_core::l10n::AppLanguage;
use macvpn_core::mfa::PromptDeadline;
use macvpn_core::models::{Connection, CredentialRef, NativeSettings, SecretField, VPNKind, uuid_string};
use macvpn_core::native::{ENT_IPSEC, ENT_PPP, IPSEC_SHARED_SECRET, PPP_AUTH_NAME, PPP_AUTH_PASSWORD};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use uuid::Uuid;
use zeroize::Zeroizing;

const SVC: &str = "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4";
const SVC2: &str = "5F0C2E31-9A64-4C1B-8E77-0D2B6A3F9E10";
const RISKY: &str = "client\ndev tun\nproto udp\nremote vpn.example.com 1194\nnobind\nauth-user-pass\nuser nobody\n";
const SSTP: &str = "server=vpn.example.com\nport=443\nuser=placeholder\ncert=system\nroute_all=yes\npeer_dns=yes\n";

/// The catalog fixture with a recording credential handler and the Connections window over the same manager.
struct Connect {
    f: CatalogFixture,
    p: Publisher,
    prompts: Arc<Mutex<Vec<CredentialPrompt>>>,
    /// The values the handler answers with (`None`: cancel).
    answer: Arc<Mutex<Option<(String, String)>>>,
    profiles: Arc<MobileconfigProfiles>,
    window: ConnectionsModel,
    clock: Arc<macvpn_app_core::deps::ManualClock>,
}

impl Connect {
    fn new() -> Connect {
        AppLanguage::set_thread_override(Some(AppLanguage::En));
        let f = CatalogFixture::new();
        let prompts = Arc::new(Mutex::new(Vec::new()));
        let answer = Arc::new(Mutex::new(Some(("alice".to_string(), "Secret123".to_string()))));
        let (seen, typed) = (prompts.clone(), answer.clone());
        f.manager.set_credential_handler(move |prompt: CredentialPrompt| {
            let fields = prompt.fields.clone();
            seen.lock().unwrap().push(prompt);
            let Some((user, password)) = typed.lock().unwrap().clone() else { return CredentialAnswer::Cancelled };
            let mut values = CredentialValues::default();
            for field in fields {
                let value = match field {
                    CredentialField::Username => user.clone(),
                    CredentialField::Password => password.clone(),
                    CredentialField::Psk => "typed-psk".into(),
                    CredentialField::KeyPassword => "typed-key".into(),
                };
                values.set(field, Zeroizing::new(value));
            }
            CredentialAnswer::Provided { values, save: true }
        });
        let profiles = Arc::new(MobileconfigProfiles::default());
        let clock = clock_at(1_000_000.0);
        let window = ConnectionsModel::new(EditorDeps {
            manager: f.manager.clone(),
            store: Arc::new(VaultConnections::new(f.vault.clone())),
            secrets: f.secrets.clone(),
            secret_writer: f.secrets.clone(),
            profiles: profiles.clone(),
            clock: clock.clone(),
        });
        Connect { f, p: Publisher::new(), prompts, answer, profiles, window, clock }
    }

    fn subscribe(&self, payload: &CatalogPayload) {
        self.f.fetcher.serve(self.p.seal(1, payload));
        let input = macvpn_app_core::catalog::SubscribeInput {
            source: macvpn_core::catalog::source::CatalogSource::File(share_file("acme.macvpncatalog")),
            team_key: macvpn_core::catalog::keys::TeamKey::from_bytes(self.p.team.as_bytes()).unwrap(),
            fingerprint: self.p.admin.public().fingerprint(),
            bearer: None,
            catalog_id: None,
            min_version: None,
        };
        let (_, pending) = self.f.service.preview(input).unwrap();
        self.f.service.confirm(pending).unwrap();
    }

    fn publish(&self, version: u64, payload: &CatalogPayload) {
        self.f.fetcher.serve(self.p.seal(version, payload));
        let result = self.f.service.refresh(catalog_id(), macvpn_app_core::catalog_schedule::RefreshTrigger::Manual);
        assert!(matches!(result, macvpn_app_core::catalog::RefreshResult::Applied(_)), "{result:?}");
    }

    fn item(&self, n: u128) -> Connection {
        match self.f.manager.item(&key(n)) {
            Some(ConnectionItem::Managed(c)) => c,
            other => panic!("no catalog connection {n}: {other:?}"),
        }
    }

    /// Connects catalog connection `n` with the root reporting it up, and waits for the prompt's "Save".
    fn connect(&self, n: u128) {
        let c = self.item(n);
        self.f.helper.respond("status", Ok(&connected(&key(n), c.kind)));
        self.f.manager.connect(&c, false);
        self.f.manager.flush_saves();
    }

    /// A refresh lists the services (the app calls the window after every manager change), a while later.
    fn services_seen(&self) {
        self.clock.advance(10.0);
        self.f.manager.refresh();
        self.window.system_services_changed();
    }

    fn prompts(&self) -> Vec<CredentialPrompt> {
        self.prompts.lock().unwrap().clone()
    }

    fn last_up(&self, n: u128) -> common::Call {
        let line = up_line(self.item(n).kind, &local(n));
        self.f.helper.calls().into_iter().rfind(|c| c.line.starts_with(&line)).expect("an up call")
    }

    fn slot(&self) -> macvpn_core::vault::SharedCredential {
        let credentials = self.f.vault.with_read(|v| v.credentials()).unwrap();
        credentials.into_iter().find(|c| c.name == "Office AD").expect("the slot credential")
    }
}

fn connected(key: &str, kind: VPNKind) -> String {
    format!(
        r#"[{{"id":"{key}","kind":"{}","state":"connected","iface":null,"ip":null,"since":null}}]"#,
        kind.raw_value()
    )
}

fn with_slot(mut c: CatalogConnection) -> CatalogConnection {
    c.slot = Some(uid(200));
    c
}

fn sstp(n: u128, name: &str) -> CatalogConnection {
    let mut c = with_slot(connection(n, name));
    c.kind = VPNKind::Sstp;
    c.config = Zeroizing::new(SSTP.into());
    c
}

fn l2tp(n: u128, name: &str, server: &str) -> CatalogConnection {
    let mut c = with_slot(connection(n, name));
    c.kind = VPNKind::L2tp;
    c.config = Zeroizing::new(String::new());
    c.native = Some(NativeSettings { server: server.into(), send_all_traffic: true, ..Default::default() });
    c.secret_refs.insert(SecretField::Psk, uid(300));
    c
}

fn catalog(connections: Vec<CatalogConnection>) -> CatalogPayload {
    let mut p = payload(&[]);
    p.connections = connections;
    p.shared_secrets.insert(uid(300), Zeroizing::new("team-psk".into()));
    p
}

fn wait_until(what: &str, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ok() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

// MARK: - credential slots

#[test]
fn an_unfilled_slot_asks_for_both_names_the_slot_and_the_catalog_and_save_fills_it() {
    let t = Connect::new();
    t.subscribe(&payload(&[(1, "One"), (2, "Two")]));
    let slot = t.slot();
    assert_eq!((slot.username.as_str(), slot.has_password), ("", false), "an unfilled slot");

    t.connect(1);
    let prompts = t.prompts();
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].fields, [CredentialField::Username, CredentialField::Password]);
    let short = t.p.admin.public().fingerprint().to_text()[..9].to_string();
    assert_eq!(
        prompts[0].credential,
        Some(CredentialRef {
            name: "Office AD".into(),
            used_by: 2,
            team: Some("Acme VPN".into()),
            team_source: Some(short),
            server: Some("vpn.example.com".into()),
        })
    );
    assert_eq!(t.last_up(1).stdin.as_deref(), Some("username=alice\npassword=Secret123\n"));
    let slot = t.slot();
    assert_eq!((slot.username.as_str(), slot.has_password), ("alice", true), "\"Save in vault\" filled the slot");
    assert!(t.f.service.view()[0].slots[0].filled);

    // The second connection on the same slot connects without a prompt.
    t.connect(2);
    assert_eq!(t.prompts().len(), 1);
    assert_eq!(t.last_up(2).stdin.as_deref(), Some("username=alice\npassword=Secret123\n"));
}

#[test]
fn a_sign_in_failure_re_prompts_once_for_the_slot() {
    let t = Connect::new();
    t.subscribe(&payload(&[(1, "One")]));
    let line = up_line(VPNKind::Openvpn, &local(1));
    t.f.helper.respond_once(&line, Err("Authentication failed (AUTH_FAILED)"));
    t.connect(1);
    let prompts = t.prompts();
    assert_eq!(prompts.len(), 2);
    assert!(!prompts[0].retry);
    assert!(prompts[1].retry);
    assert_eq!(prompts[1].credential.as_ref().and_then(|c| c.team.as_deref()), Some("Acme VPN"));
    assert_eq!(t.slot().username, "alice");
}

#[test]
fn a_personal_link_or_an_own_login_is_not_named_as_a_team_slot() {
    let t = Connect::new();
    t.subscribe(&payload(&[(1, "One")]));
    // The user links the catalog connection to a credential of their own: no team in the prompt.
    let own = t.f.vault.with(|v| v.create_credential("Mine", "bob", None)).unwrap();
    t.f.vault.with(|v| v.link(&key(1), own)).unwrap();
    assert_eq!(
        t.f.secrets.credential_for(&local(1)),
        Some(CredentialRef { name: "Mine".into(), used_by: 1, ..Default::default() })
    );
}

#[test]
fn the_prompt_window_shows_the_team_catalog() {
    let broker = Arc::new(CredentialBroker::new());
    let prompt = CredentialPrompt {
        connection_id: "K".into(),
        connection_name: "One".into(),
        kind: VPNKind::Openvpn,
        fields: vec![CredentialField::Username, CredentialField::Password],
        username: None,
        retry: false,
        deadline: PromptDeadline::new(Date::now()),
        credential: Some(CredentialRef {
            name: "Office AD".into(),
            used_by: 2,
            team: Some("Acme VPN".into()),
            team_source: Some("ABCD-1234".into()),
            server: Some("vpn.example.com".into()),
        }),
    };
    let b = broker.clone();
    let waiter = std::thread::spawn(move || b.present(prompt, Date::now()));
    wait_until("the prompt", || !broker.pending().is_empty());
    let view = broker.pending().remove(0);
    assert_eq!(view.credential_name.as_deref(), Some("Office AD"));
    assert_eq!(view.team.as_deref(), Some("Acme VPN"));
    let json = serde_json::to_value(&view).unwrap();
    assert_eq!(json["team"], "Acme VPN");
    assert_eq!(json["teamSource"], "ABCD-1234", "the catalog's source next to its name");
    assert_eq!(json["server"], "vpn.example.com", "the server the password goes to");
    broker.dismiss("K");
    assert!(matches!(waiter.join().unwrap(), CredentialAnswer::Cancelled));
}

#[test]
fn an_https_slot_names_the_source_host_and_the_update_notice_names_moved_servers() {
    let t = Connect::new();
    t.subscribe(&catalog(vec![l2tp(1, "Office L2TP", "vpn.example.com"), sstp(2, "Office SSTP")]));
    t.f.vault
        .with(|v| {
            v.update_subscription_state(catalog_id(), |r| {
                r.source = macvpn_core::catalog::source::CatalogSource::Https(
                    macvpn_core::catalog::source::HttpsUrl::parse("https://catalogs.example.org/acme?sig=x").unwrap(),
                )
            })
        })
        .unwrap();
    let r = t.f.secrets.credential_for(&local(1)).unwrap();
    assert_eq!(r.team_source.as_deref(), Some("catalogs.example.org"));
    assert_eq!(r.server.as_deref(), Some("vpn.example.com"));
    assert_eq!(t.f.secrets.credential_for(&local(2)).unwrap().server.as_deref(), Some("vpn.example.com"));

    t.publish(2, &catalog(vec![l2tp(1, "Office L2TP", "vpn2.example.com"), sstp(2, "Office SSTP")]));
    assert_eq!(
        t.f.notices().last().unwrap(),
        "Team catalog “Acme VPN” updated: 1 changed. Server changed: Office L2TP"
    );
}

// MARK: - team secrets and per-user fields

#[test]
fn a_team_psk_is_not_asked_and_reaches_the_start_options_with_the_slot_username() {
    let t = Connect::new();
    t.subscribe(&catalog(vec![l2tp(1, "Office L2TP", "vpn.example.com")]));
    t.f.native.set_list(Ok(vec![SystemVpn::new(SVC, "Office L2TP", "L2TP", "Disconnected")]));
    t.f.native.set_address(SVC, Some("vpn.example.com"));
    t.f.manager.reload();

    t.f.manager.connect(&t.item(1), false);
    let prompts = t.prompts();
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].fields, [CredentialField::Username, CredentialField::Password], "the PSK is the team's");
    let options = t.f.native.starts().pop().expect("a native start").options.expect("start options");
    assert_eq!(options[ENT_PPP][PPP_AUTH_NAME], "alice");
    assert_eq!(options[ENT_PPP][PPP_AUTH_PASSWORD], "Secret123");
    assert_eq!(options[ENT_IPSEC][IPSEC_SHARED_SECRET], "team-psk");
}

#[test]
fn the_team_profile_has_no_account_and_the_team_psk() {
    let t = Connect::new();
    t.subscribe(&catalog(vec![l2tp(1, "Office L2TP", "vpn.example.com")]));
    t.window.install_team_profile(&key(1)).unwrap();
    let installs = t.profiles.installs.lock().unwrap().clone();
    assert_eq!(installs.len(), 1);
    let (id, profile, _, existed) = &installs[0];
    assert_eq!(*id, local(1));
    assert!(!existed);
    let after = &profile[profile.find("<key>AuthName</key>").expect("an AuthName") + "<key>AuthName</key>".len()..];
    let value = after.trim_start();
    assert!(value.starts_with("<string></string>") || value.starts_with("<string/>"), "{profile}");
    assert!(profile.contains("dGVhbS1wc2s="), "the team PSK (base64) is in the profile");
    // A personal connection has no team profile to install.
    let own = t.f.vault.with(|v| {
        let c = Connection::new("Own", VPNKind::Openvpn);
        v.save_connection(&c, Some(OPENVPN))?;
        Ok(c)
    });
    t.f.manager.reload();
    assert!(t.window.install_team_profile(&uuid_string(&own.unwrap().id)).is_err());
}

#[test]
fn sstp_gets_the_slot_username_in_memory_and_the_stored_config_stays() {
    let t = Connect::new();
    t.subscribe(&catalog(vec![sstp(1, "Office SSTP")]));
    t.connect(1);
    let prompts = t.prompts();
    assert_eq!(prompts.len(), 1);
    assert_eq!(prompts[0].fields, [CredentialField::Username, CredentialField::Password], "the slot's user name too");
    let config = String::from_utf8(t.last_up(1).config.unwrap()).unwrap();
    assert!(config.contains("user=alice\n"), "{config}");
    assert!(!config.contains("placeholder"));
    let stored = t.f.vault.with_read(|v| v.config(&local(1))).unwrap();
    assert!(stored.contains("user=placeholder\n"), "the stored config is unchanged");

    // Filled: no prompt, the same substitution.
    t.connect(1);
    assert_eq!(t.prompts().len(), 1);
    assert!(String::from_utf8(t.last_up(1).config.unwrap()).unwrap().contains("user=alice\n"));
}

#[test]
fn an_sstp_slot_username_the_config_cannot_carry_is_refused() {
    let t = Connect::new();
    t.subscribe(&catalog(vec![sstp(1, "Office SSTP")]));
    *t.answer.lock().unwrap() = Some(("OFFICE\\alice".into(), "Secret123".into()));
    t.connect(1);
    assert!(t.f.helper.calls().iter().all(|c| !c.line.starts_with("up ")), "nothing reached the root layer");
    match t.f.manager.state(&key(1)) {
        macvpn_core::models::ConnectionState::Failed(reason) => {
            assert!(reason.contains("Invalid user name"), "{reason}")
        }
        other => panic!("expected a failure, got {other:?}"),
    }
    assert_eq!(t.slot().username, "", "nothing saved");
}

// MARK: - risky directives

#[test]
fn a_config_change_clears_the_acknowledgement_and_the_read_only_editor_ticks_it_again() {
    let t = Connect::new();
    let mut c = connection(1, "Risky");
    c.config = Zeroizing::new(RISKY.into());
    let mut v1 = catalog(vec![c.clone()]);
    v1.connections[0].slot = None;
    t.subscribe(&v1);
    *t.answer.lock().unwrap() = Some(("alice".into(), "pw".into()));

    t.connect(1);
    assert!(t.f.helper.calls().iter().all(|c| !c.line.starts_with("up ")));
    assert!(
        matches!(t.f.manager.state(&key(1)), macvpn_core::models::ConnectionState::Failed(r) if r.contains("Risky settings"))
    );

    // The read-only editor keeps the risky checkbox: ticking it saves only the acknowledgement.
    let view = t.window.open_editor(&key(1)).unwrap();
    assert_eq!(view.read_only.as_deref(), Some("Managed by the team catalog “Acme VPN”"));
    let EditorFields::Text(mut fields) = view.fields else { panic!("a text editor") };
    fields.acknowledged = view.risky.iter().map(|r| r.directive.clone()).collect();
    let saved = t.window.save_editor(&key(1), EditorFields::Text(fields)).unwrap();
    assert!(saved.issues.is_empty(), "{:?}", saved.issues);
    assert!(!saved.dirty);
    assert_eq!(t.item(1).acknowledged_risky_directives, ["user"]);
    t.connect(1);
    assert!(t.last_up(1).line.ends_with("--accept-risky user"), "{}", t.last_up(1).line);

    // v2 renames only: the acknowledgement stays. v3 changes the config: asked again.
    let mut v2 = v1.clone();
    v2.connections[0].name = "Risky renamed".into();
    t.publish(2, &v2);
    assert_eq!(t.item(1).acknowledged_risky_directives, ["user"]);
    let mut v3 = v2.clone();
    v3.connections[0].config.push_str("verb 3\n");
    t.publish(3, &v3);
    assert!(t.item(1).acknowledged_risky_directives.is_empty());
    let ups = t.f.helper.lines().iter().filter(|l| l.starts_with("up ")).count();
    t.connect(1);
    assert_eq!(t.f.helper.lines().iter().filter(|l| l.starts_with("up ")).count(), ups, "refused until ticked again");
}

#[test]
fn a_stale_editor_cannot_acknowledge_a_newer_catalog_config() {
    let t = Connect::new();
    let mut c = connection(1, "Risky");
    c.config = Zeroizing::new(RISKY.into());
    c.slot = None;
    let v1 = catalog(vec![c]);
    t.subscribe(&v1);

    // The editor is opened on v1 ...
    let view = t.window.open_editor(&key(1)).unwrap();
    let EditorFields::Text(mut fields) = view.fields else { panic!("a text editor") };
    fields.acknowledged = view.risky.iter().map(|r| r.directive.clone()).collect();
    // ... the catalog publishes v2 with another risky directive meanwhile ...
    let mut v2 = v1.clone();
    v2.connections[0].config.push_str("group nogroup\n");
    t.publish(2, &v2);
    // ... and ticking the box of the stale editor is refused: v2 stays unacknowledged.
    let saved = t.window.save_editor(&key(1), EditorFields::Text(fields)).unwrap();
    assert_eq!(saved.issues, ["The team catalog changed this connection; review it again"]);
    assert!(t.item(1).acknowledged_risky_directives.is_empty());
    assert!(t.f.vault.with_read(|v| v.config(&local(1))).unwrap().contains("group nogroup"));
}

#[test]
fn an_apply_reloads_the_open_editor_of_a_changed_catalog_connection() {
    let t = Connect::new();
    let mut c = connection(1, "Risky");
    c.config = Zeroizing::new(RISKY.into());
    c.slot = None;
    let v1 = catalog(vec![c]);
    t.subscribe(&v1);
    t.window.open_editor(&key(1)).unwrap();
    let mut v2 = v1.clone();
    v2.connections[0].config.push_str("verb 3\n");
    t.publish(2, &v2);
    // The app calls this after every manager change (an apply reloads the manager).
    t.window.system_services_changed();
    let view = t.window.open_editor(&key(1)).unwrap();
    let EditorFields::Text(fields) = view.fields else { panic!("a text editor") };
    assert!(fields.text.ends_with("verb 3\n"), "the editor shows v2");
    assert!(!view.dirty);
}

/// A store whose catalog read fails (a vault error reads as "not a catalog connection"): the writes still go to the
/// vault, which refuses them for catalog rows.
struct BlindStore(VaultConnections);

impl ConnectionRepository for BlindStore {
    fn list(&self) -> std::io::Result<Vec<Connection>> {
        self.0.list()
    }
    fn save(&self, connection: &Connection, config: Option<&str>) -> std::io::Result<()> {
        self.0.save(connection, config)
    }
    fn load_config(&self, id: &Uuid) -> std::io::Result<String> {
        self.0.load_config(id)
    }
    fn delete(&self, id: &Uuid) -> std::io::Result<()> {
        self.0.delete(id)
    }
}

#[test]
fn a_refused_delete_keeps_the_secrets_and_the_slot_link() {
    let t = Connect::new();
    t.subscribe(&catalog(vec![l2tp(1, "Office L2TP", "vpn.example.com")]));
    t.f.vault.with(|v| v.set_item_secret(&key(1), SecretField::KeyPassword, "own")).ok();
    let window = ConnectionsModel::new(EditorDeps {
        manager: t.f.manager.clone(),
        store: Arc::new(BlindStore(VaultConnections::new(t.f.vault.clone()))),
        secrets: t.f.secrets.clone(),
        secret_writer: t.f.secrets.clone(),
        profiles: t.profiles.clone(),
        clock: clock_at(1_000_000.0),
    });
    assert!(window.delete(&local(1)).is_none(), "the vault refused the delete");
    assert_eq!(t.f.connection_names(), ["Office L2TP"]);
    assert!(t.f.secrets.credential_for(&local(1)).is_some(), "still linked to its slot");
    assert_eq!(t.f.secrets.get(&local(1), SecretField::Psk).as_deref(), Some("team-psk"), "the team PSK stays");
}

// MARK: - read-only editors

#[test]
fn the_editors_refuse_every_other_change_to_a_catalog_connection() {
    let t = Connect::new();
    t.subscribe(&payload(&[(1, "One")]));
    let view = t.window.open_editor(&key(1)).unwrap();
    let EditorFields::Text(mut fields) = view.fields else { panic!("a text editor") };
    fields.name = "Renamed".into();
    fields.text.push_str("verb 3\n");
    let saved = t.window.save_editor(&key(1), EditorFields::Text(fields)).unwrap();
    assert_eq!(saved.issues, ["Managed by the team catalog “Acme VPN”"]);
    assert_eq!(t.item(1).name, "One");
    assert_eq!(t.f.vault.with_read(|v| v.config(&local(1))).unwrap().as_str(), OPENVPN);

    // The store itself refuses with a readable text.
    let store = VaultConnections::new(t.f.vault.clone());
    let mut c = t.item(1);
    c.name = "Renamed".into();
    let e = store.save(&c, None).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(e.to_string().contains("team catalog"), "{e}");

    // Delete from the Connections window: refused, the slot link and the item stay.
    assert!(t.window.delete(&local(1)).is_none());
    assert_eq!(t.f.connection_names(), ["One"]);
    assert!(t.f.secrets.credential_for(&local(1)).is_some(), "still linked to its slot");
}

#[test]
fn a_duplicate_is_an_editable_personal_connection_on_the_same_slot() {
    let t = Connect::new();
    t.subscribe(&payload(&[(1, "One")]));
    t.connect(1);
    let copy = t.f.service.duplicate(local(1), "One (mine)").unwrap();
    let copy_key = uuid_string(&copy);
    let view = t.window.open_editor(&copy_key).unwrap();
    assert_eq!(view.read_only, None);
    let EditorFields::Text(mut fields) = view.fields else { panic!("a text editor") };
    fields.text.push_str("verb 3\n");
    let saved = t.window.save_editor(&copy_key, EditorFields::Text(fields)).unwrap();
    assert!(saved.issues.is_empty(), "{:?}", saved.issues);
    assert!(t.f.vault.with_read(|v| v.config(&copy)).unwrap().ends_with("verb 3\n"));
    // The copy uses the filled slot credential: no prompt.
    let c = match t.f.manager.item(&copy_key) {
        Some(ConnectionItem::Managed(c)) => c,
        other => panic!("{other:?}"),
    };
    t.f.helper.respond("status", Ok(&connected(&copy_key, VPNKind::Openvpn)));
    t.f.manager.connect(&c, false);
    assert_eq!(t.prompts().len(), 1);
    assert_eq!(t.f.secrets.credential_for(&copy).map(|r| r.team), Some(None), "a personal copy is not a team item");
}

// MARK: - native profiles

#[test]
fn an_outdated_profile_offers_the_reinstall_before_connecting() {
    let t = Connect::new();
    t.subscribe(&catalog(vec![l2tp(1, "Office L2TP", "vpn.example.com")]));
    t.f.native.set_list(Ok(vec![SystemVpn::new(SVC, "Office L2TP", "L2TP", "Disconnected")]));
    t.f.native.set_address(SVC, Some("vpn2.example.com"));
    t.publish(2, &catalog(vec![l2tp(1, "Office L2TP", "vpn2.example.com")]));
    assert!(t.f.service.badges()[&key(1)].profile_outdated);

    t.f.manager.connect(&t.item(1), false);
    assert!(t.f.native.starts().is_empty());
    match t.f.manager.state(&key(1)) {
        macvpn_core::models::ConnectionState::Failed(reason) => {
            assert_eq!(reason, "The team catalog changed this connection: reinstall its profile")
        }
        other => panic!("expected the reinstall offer, got {other:?}"),
    }

    t.window.install_team_profile(&key(1)).unwrap();
    assert!(t.profiles.installs.lock().unwrap()[0].1.contains("vpn2.example.com"));
    assert!(t.f.service.badges()[&key(1)].profile_outdated, "staged only: not installed yet");
    // macOS replaces the service with the approved profile's.
    t.f.native.set_list(Ok(vec![SystemVpn::new(SVC2, "Office L2TP", "L2TP", "Disconnected")]));
    t.f.native.set_address(SVC2, Some("vpn2.example.com"));
    t.services_seen();
    assert!(!t.f.service.badges()[&key(1)].profile_outdated, "reinstalled");
    t.f.manager.connect(&t.item(1), false);
    assert_eq!(t.f.native.starts().len(), 1);
}

/// WinVPN 2c Task 13: where installing needs no approval, the app installs a catalog's native profiles after each
/// apply (the `after_apply` hook): an added L2TP connection is ready at once, a moved server is reinstalled and its
/// "reinstall its profile" mark cleared without a click, and "Install profile" clears it at once too.
#[test]
fn without_approval_an_apply_installs_and_clears_the_mark() {
    let t = Arc::new(Connect::new());
    t.profiles.silent.store(true, std::sync::atomic::Ordering::SeqCst);
    let weak = Arc::downgrade(&t);
    t.f.service.set_after_apply(move || {
        if let Some(t) = weak.upgrade() {
            t.window.install_native_profiles();
        }
    });
    t.subscribe(&catalog(vec![l2tp(1, "Office L2TP", "vpn.example.com")]));
    {
        let installs = t.profiles.installs.lock().unwrap();
        assert_eq!(installs.len(), 1, "added: installed");
        assert_eq!(installs[0].0, local(1));
        assert!(installs[0].1.contains("vpn.example.com"));
    }
    t.publish(2, &catalog(vec![l2tp(1, "Office L2TP", "vpn2.example.com")]));
    assert!(t.profiles.installs.lock().unwrap()[1].1.contains("vpn2.example.com"));
    assert!(!t.f.service.badges()[&key(1)].profile_outdated, "installed: no approval to wait for");

    // "Install profile" (a mark left by a failed install) clears it at once.
    *t.profiles.fail.lock().unwrap() = Some("busy".into());
    t.publish(3, &catalog(vec![l2tp(1, "Office L2TP", "vpn3.example.com")]));
    assert!(t.f.service.badges()[&key(1)].profile_outdated);
    *t.profiles.fail.lock().unwrap() = None;
    t.window.install_team_profile(&key(1)).unwrap();
    assert!(!t.f.service.badges()[&key(1)].profile_outdated);
    t.f.manager.connect(&t.item(1), false);
    assert!(
        !matches!(t.f.manager.state(&key(1)), macvpn_core::models::ConnectionState::Failed(r) if r == "The team catalog changed this connection: reinstall its profile")
    );
}

/// The catalog moved the server; the old profile (old server) is installed.
fn outdated_l2tp(t: &Connect) {
    t.subscribe(&catalog(vec![l2tp(1, "Office L2TP", "vpn.example.com")]));
    t.f.native.set_list(Ok(vec![SystemVpn::new(SVC, "Office L2TP", "L2TP", "Disconnected")]));
    t.f.native.set_address(SVC, Some("vpn.example.com"));
    t.publish(2, &catalog(vec![l2tp(1, "Office L2TP", "vpn2.example.com")]));
    t.f.manager.reload();
    assert!(t.f.service.badges()[&key(1)].profile_outdated);
}

#[test]
fn a_cancelled_profile_install_keeps_the_connect_blocked() {
    let t = Connect::new();
    outdated_l2tp(&t);
    t.window.install_team_profile(&key(1)).unwrap();
    // The user cancels in System Settings: the old service stays as it was.
    t.services_seen();
    t.services_seen();
    assert!(t.f.service.badges()[&key(1)].profile_outdated);
    t.f.manager.connect(&t.item(1), false);
    assert!(t.f.native.starts().is_empty());
    assert!(matches!(t.f.manager.state(&key(1)),
        macvpn_core::models::ConnectionState::Failed(r) if r == "The team catalog changed this connection: reinstall its profile"));
}

#[test]
fn an_installed_profile_clears_the_mark_once_its_new_server_shows() {
    let t = Connect::new();
    outdated_l2tp(&t);
    t.window.install_team_profile(&key(1)).unwrap();
    // The same service, now with the new server (the profile replaced it in place).
    t.f.native.set_address(SVC, Some("vpn2.example.com"));
    t.services_seen();
    assert!(!t.f.service.badges()[&key(1)].profile_outdated);
}

#[test]
fn an_apply_racing_the_install_keeps_its_new_mark() {
    let t = Connect::new();
    outdated_l2tp(&t);
    t.window.install_team_profile(&key(1)).unwrap();
    // v3 moves the server again before the v2 profile is approved.
    t.publish(3, &catalog(vec![l2tp(1, "Office L2TP", "vpn3.example.com")]));
    t.f.native.set_address(SVC, Some("vpn2.example.com"));
    t.services_seen();
    assert!(t.f.service.badges()[&key(1)].profile_outdated, "the v2 profile does not clear the v3 mark");
}

#[test]
fn the_native_service_binding_of_a_catalog_connection_is_kept() {
    let t = Connect::new();
    t.subscribe(&catalog(vec![l2tp(1, "Office L2TP", "vpn.example.com")]));
    t.f.native.set_list(Ok(vec![SystemVpn::new(SVC, "Office L2TP", "L2TP", "Disconnected")]));
    t.f.native.set_address(SVC, Some("vpn.example.com"));
    t.f.manager.refresh();
    t.f.manager.reload();
    assert_eq!(t.item(1).native_service_id.as_deref(), Some(SVC), "bound, and saved in the vault");

    // Another system VPN with the same name is not hidden as the catalog connection's.
    t.f.native.set_list(Ok(vec![
        SystemVpn::new(SVC, "Office L2TP", "L2TP", "Disconnected"),
        SystemVpn::new(SVC2, "Office L2TP", "L2TP", "Disconnected"),
    ]));
    t.f.native.set_address(SVC2, Some("evil.example.net"));
    t.f.manager.refresh();
    let listed: Vec<String> = t.f.manager.system_services().into_iter().map(|s| s.id).collect();
    assert_eq!(listed, [SVC2]);
}

// MARK: - control API

#[test]
fn the_control_api_sees_catalog_connections_by_their_namespaced_ids() {
    let t = Connect::new();
    t.subscribe(&payload(&[(1, "One")]));
    let k = key(1);
    assert!(is_uuid_shaped(&k));
    assert_eq!(k, k.to_uppercase(), "upper case, as the allowlist stores ids");
    let client = PairedClient::new(Uuid::new_v4(), "Client".into(), "t", "/x".into(), vec![k.clone()], Date::now());
    assert!(Registry::is_allowed(&client, &k));
    assert!(!Registry::is_allowed(&client, &k.to_lowercase()));
    // `up` goes through the manager's item by that key, like any other connection.
    assert!(matches!(t.f.manager.item(&k), Some(ConnectionItem::Managed(c)) if c.id == local(1)));
    t.connect(1);
    assert_eq!(t.last_up(1).line, up_line(VPNKind::Openvpn, &local(1)));
}

#[test]
fn i_installed_it_clears_the_mark_of_a_staged_profile_only() {
    let t = Connect::new();
    outdated_l2tp(&t);
    // Nothing staged yet: refused, the mark stays.
    assert_eq!(t.window.confirm_team_profile_installed(&key(1)).unwrap_err(), "Install the profile first.");
    assert!(t.f.service.badges()[&key(1)].profile_outdated);
    // Staged; macOS cannot show the change (same service, same server): the user confirms.
    t.window.install_team_profile(&key(1)).unwrap();
    t.services_seen();
    assert!(t.f.service.badges()[&key(1)].profile_outdated);
    t.window.confirm_team_profile_installed(&key(1)).unwrap();
    assert!(!t.f.service.badges()[&key(1)].profile_outdated);
    // Once only: the staged profile was used up.
    assert_eq!(t.window.confirm_team_profile_installed(&key(1)).unwrap_err(), "Install the profile first.");
}

#[test]
fn i_installed_it_after_a_newer_apply_keeps_the_mark() {
    let t = Connect::new();
    outdated_l2tp(&t);
    t.window.install_team_profile(&key(1)).unwrap();
    t.publish(3, &catalog(vec![l2tp(1, "Office L2TP", "vpn3.example.com")]));
    assert_eq!(
        t.window.confirm_team_profile_installed(&key(1)).unwrap_err(),
        "The team catalog changed this connection; review it again"
    );
    assert!(t.f.service.badges()[&key(1)].profile_outdated);
}
