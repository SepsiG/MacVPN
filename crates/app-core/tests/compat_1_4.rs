//! The 1.4.0 compatibility fixtures (platform-neutral refactor, Task 1): what "no behaviour change" means for every
//! serialized format, frozen on the unchanged 1.4.0 code. Every later task keeps these tests green **without
//! editing the fixture files** (the one allowed edit is the `dmg` → `package` field name in `release-parsed.txt`,
//! done visibly in Task 10).
//!
//! The fixtures are in `tests/fixtures/compat-1.4.0/`. They were written once by the ignored test
//! [`write_compat_fixtures`]:
//!
//! ```text
//! cargo test -p macvpn-app-core --test compat_1_4 -- --ignored write_compat_fixtures
//! ```
//!
//! which refuses to overwrite an existing file. Every input is fixed: `FixedEntropy::new(0x01)`,
//! `KdfParams::insecure_for_tests()`, the date 1 790 000 000 s after 1970, the password `fixture-password-1`, the
//! server `vpn.example.com`, the user `alice`, the secret `fixture-secret`. The normal tests rebuild each fixture,
//! compare it byte for byte, and open the committed file again with the current code (round trip).
//!
//! `mvpn-usage.txt` and `mvpn-version.txt` (the root layer's output) are checked by `scripts/test-root.sh`, since a
//! test here cannot run another crate's binary.

mod catalog_support;
mod common;

use catalog_support::FakeFetcher;
use common::{MockHelper, MockNative, TempDir};
use macvpn_app_core::app::{MemoryPreferences, PreferenceStore};
use macvpn_app_core::catalog::{CatalogDeps, CatalogService, SubscribeInput};
use macvpn_app_core::deps::{ManualClock, SystemVpn};
use macvpn_app_core::folders::VaultFolders;
use macvpn_app_core::shared_credentials::SharedCredentials;
use macvpn_app_core::updates::{ReleaseSource, UpdateController, UpdateSource};
use macvpn_app_core::vault::VaultLifecycle;
use macvpn_app_core::vault_stores::{VaultConnections, VaultRanking, VaultSecrets, VaultSystemOtp};
use macvpn_app_core::view_model::{ControlView, VaultView};
use macvpn_app_core::{ConnectionManager, Dependencies, ViewModel};
use macvpn_core::catalog::format::{CatalogHeaderInput, OpenRequest, Trust, open_catalog, seal_catalog};
use macvpn_core::catalog::keys::{AdminKey, TeamKey};
use macvpn_core::catalog::payload::{
    CatalogConnection, CatalogFolder, CatalogPayload, CredentialSlot, PAYLOAD_VERSION, encode_payload,
};
use macvpn_core::catalog::source::{CatalogSource, HttpsUrl};
use macvpn_core::control::registry::{PairedClient, Registry};
use macvpn_core::date::Date;
use macvpn_core::exporter;
use macvpn_core::importer::ExportMeta;
use macvpn_core::l10n::AppLanguage;
use macvpn_core::models::{Connection, NativeSettings, OTPSeparator, OTPSetting, SecretField, VPNKind, uuid_string};
use macvpn_core::ranking::{ConnectionRanking, ConnectionRankingStore, UsageStats};
use macvpn_core::store::ConnectionStore;
use macvpn_core::system_otp::SystemOTPStore;
use macvpn_core::update::{Release, UpdateChecker};
use macvpn_core::vault::backup::{self, BackupConnection, BackupCredential, BackupPayload, BackupPreferences};
use macvpn_core::vault::{Dek, FixedEntropy, FolderColor, FolderNode, KdfParams, MemoryKeyStore, SystemItem, Vault};
use macvpn_platform_api::MACVPN;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroizing;

// MARK: - the fixed inputs

const PASSWORD: &str = "fixture-password-1";
const SERVER: &str = "vpn.example.com";
const USER: &str = "alice";
const SECRET: &str = "fixture-secret";
/// The version the fixtures were made with (a fixed input, not the running build's version).
const APP_VERSION: &str = "1.4.0";
/// The system VPN (an scutil service ID).
const SYSTEM_VPN: &str = "8F1C2D3E-0000-4000-8000-000000000001";
const GITHUB_REPO: &str = "SepsiG/MacVPN";
const GITHUB_REPO_ID: i64 = 1_422_472_799;

const OPENVPN_CONFIG: &str =
    "client\ndev tun\nproto udp\nremote vpn.example.com 1194\nnobind\nauth-user-pass\nverb 3\n";
const WIREGUARD_CONFIG: &str = "[Interface]\nPrivateKey = AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=\n\
                                Address = 10.0.0.2/32\n\n[Peer]\n\
                                PublicKey = ISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0+P0A=\n\
                                Endpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0\n";

fn entropy() -> FixedEntropy {
    FixedEntropy::new(0x01)
}

fn kdf() -> KdfParams {
    KdfParams::insecure_for_tests()
}

/// 1 790 000 000 s after 1970 (2026-09-21T14:13:20Z).
fn fixed_date() -> Date {
    Date::from_time_interval_since_1970(1_790_000_000.0)
}

fn id(n: u128) -> Uuid {
    Uuid::from_u128(0xC0DE_0000_0000_4000_8000_0000_0000_0000 + n)
}

fn openvpn_id() -> Uuid {
    id(0x01)
}
fn wireguard_id() -> Uuid {
    id(0x02)
}
fn l2tp_id() -> Uuid {
    id(0x03)
}
fn work_folder() -> Uuid {
    id(0x10)
}
fn remote_folder() -> Uuid {
    id(0x11)
}
fn credential_id() -> Uuid {
    id(0x20)
}
fn client_id() -> Uuid {
    id(0x30)
}
fn catalog_id() -> Uuid {
    id(0x40)
}

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_string())
}

// MARK: - the connections

fn openvpn() -> Connection {
    let mut c = Connection::with_id(openvpn_id(), "Office OpenVPN", VPNKind::Openvpn, fixed_date());
    c.otp = OTPSetting::new(true, OTPSeparator::Colon);
    c
}

fn wireguard() -> Connection {
    Connection::with_id(wireguard_id(), "Home WireGuard", VPNKind::Wireguard, fixed_date())
}

fn l2tp() -> Connection {
    let mut c = Connection::with_id(l2tp_id(), "Branch L2TP", VPNKind::L2tp, fixed_date());
    c.native_service_name = Some("Branch L2TP".into());
    c.native = Some(NativeSettings {
        server: SERVER.into(),
        account: USER.into(),
        group_name: String::new(),
        send_all_traffic: true,
    });
    c
}

fn folders() -> Vec<FolderNode> {
    vec![
        FolderNode {
            id: work_folder(),
            parent: None,
            name: "Work".into(),
            color: Some(FolderColor::Blue),
            position: 0,
            collapsed: false,
        },
        FolderNode {
            id: remote_folder(),
            parent: Some(work_folder()),
            name: "Remote".into(),
            color: Some(FolderColor::Green),
            position: 0,
            collapsed: true,
        },
    ]
}

fn ranking() -> ConnectionRanking {
    let usage = |score: f64| UsageStats { score, last_updated: fixed_date() };
    ConnectionRanking::new(
        vec![uuid_string(&wireguard_id())],
        HashMap::from([(uuid_string(&openvpn_id()), usage(2.5)), (SYSTEM_VPN.to_string(), usage(1.0))]),
    )
}

fn system_otp() -> HashMap<String, OTPSetting> {
    HashMap::from([(SYSTEM_VPN.to_string(), OTPSetting::new(true, OTPSeparator::Comma))])
}

fn paired_client() -> PairedClient {
    PairedClient::new(
        client_id(),
        "Acme Remote".into(),
        "fixture-control-token",
        "/Applications/Acme Remote.app/Contents/MacOS/Acme Remote".into(),
        vec![uuid_string(&openvpn_id()), SYSTEM_VPN.into()],
        fixed_date(),
    )
}

fn registry() -> Registry {
    let mut r = Registry::new();
    r.add(paired_client());
    r
}

/// One OpenVPN, one WireGuard and one L2TP connection, a two-level folder tree with colours, a shared credential
/// linked to the OpenVPN connection, a pin, a ranking, two preferences and a system VPN's placement. (The paired
/// control client is in the vault, never in a backup.)
fn backup_payload() -> BackupPayload {
    let prefs = BackupPreferences { auto_check: true, control_api_enabled: true, ..BackupPreferences::default() };
    let mut p = BackupPayload::empty(fixed_date(), APP_VERSION, prefs);
    // Sorted by name, as `backup::collect` sorts them.
    p.connections = vec![
        BackupConnection {
            connection: l2tp(),
            config: z(""),
            folder_id: None,
            color: Some(FolderColor::Red),
            position: 0,
            secrets: vec![(SecretField::Password, z(SECRET)), (SecretField::Psk, z(SECRET))],
        },
        BackupConnection {
            connection: wireguard(),
            config: z(WIREGUARD_CONFIG),
            folder_id: Some(work_folder()),
            color: None,
            position: 0,
            secrets: Vec::new(),
        },
        BackupConnection {
            connection: openvpn(),
            config: z(OPENVPN_CONFIG),
            folder_id: Some(remote_folder()),
            color: None,
            position: 0,
            secrets: Vec::new(),
        },
    ];
    p.system_secrets = BTreeMap::from([(SYSTEM_VPN.to_string(), vec![(SecretField::Psk, z(SECRET))])]);
    p.folders = folders();
    p.credentials = vec![BackupCredential {
        id: credential_id(),
        name: "Office Login".into(),
        username: z(USER),
        password: Some(z(SECRET)),
        created: fixed_date(),
        updated: fixed_date(),
    }];
    p.credential_links = vec![(uuid_string(&openvpn_id()), credential_id())];
    p.system_items = vec![SystemItem {
        service_id: SYSTEM_VPN.into(),
        folder_id: Some(work_folder()),
        color: Some(FolderColor::Orange),
        position: 1,
        missing_since: None,
    }];
    p.system_otp = system_otp();
    p.ranking = ranking();
    p
}

// MARK: - the team catalog

/// The publisher's signing key and the team key (from `FixedEntropy`), as used for `catalog.macvpncatalog`.
fn catalog_keys(e: &FixedEntropy) -> (AdminKey, TeamKey) {
    (AdminKey::from_seed(&[7; 32]).unwrap(), TeamKey::generate(e).unwrap())
}

/// Two connections, a folder, a credential slot and a team PSK.
fn catalog_payload() -> CatalogPayload {
    let slot = id(0x42);
    let psk = id(0x43);
    let folder = id(0x41);
    CatalogPayload {
        version: PAYLOAD_VERSION,
        folders: vec![CatalogFolder {
            id: folder,
            parent: None,
            name: "Team".into(),
            color: Some(FolderColor::Purple),
            position: 0,
        }],
        connections: vec![
            CatalogConnection {
                id: id(0x44),
                name: "Team OpenVPN".into(),
                kind: VPNKind::Openvpn,
                folder: Some(folder),
                color: None,
                config: z(OPENVPN_CONFIG),
                native: None,
                otp: OTPSetting::default(),
                slot: Some(slot),
                secret_refs: BTreeMap::new(),
            },
            CatalogConnection {
                id: id(0x45),
                name: "Team L2TP".into(),
                kind: VPNKind::L2tp,
                folder: Some(folder),
                color: Some(FolderColor::Teal),
                config: z(""),
                native: Some(NativeSettings { server: SERVER.into(), ..NativeSettings::default() }),
                otp: OTPSetting::new(true, OTPSeparator::None),
                slot: Some(slot),
                secret_refs: BTreeMap::from([(SecretField::Psk, psk)]),
            },
        ],
        credential_slots: vec![CredentialSlot { id: slot, name: "Team Login".into() }],
        shared_secrets: BTreeMap::from([(psk, z(SECRET))]),
    }
}

fn sealed_catalog() -> (Vec<u8>, AdminKey, TeamKey) {
    let e = entropy();
    let (admin, team) = catalog_keys(&e);
    let bytes = seal_catalog(
        CatalogHeaderInput {
            catalog_id: catalog_id(),
            name: "Acme VPN".into(),
            version: 1,
            created: fixed_date(),
            successor_key: None,
        },
        &catalog_payload(),
        &team,
        &admin,
        &e,
    )
    .unwrap();
    (bytes, admin, team)
}

fn open_fixture_catalog(bytes: &[u8], admin: &AdminKey, team: &TeamKey) -> CatalogPayload {
    let trust = Trust { pinned: admin.public().fingerprint(), publisher_key: None, successor: None };
    let req = OpenRequest { trust: &trust, catalog_id: Some(catalog_id()), applied_version: None, team_key: team };
    open_catalog(bytes, &req).unwrap().payload
}

// MARK: - the update check

fn release_json() -> Vec<u8> {
    let asset = |name: &str| {
        serde_json::json!({
            "name": name,
            "browser_download_url": format!("https://github.com/{GITHUB_REPO}/releases/download/v1.4.0/{name}"),
        })
    };
    let json = serde_json::json!({
        "tag_name": "v1.4.0",
        "name": "MacVPN 1.4.0",
        "body": "## What's new\n- The team catalog file has its own slot.",
        "html_url": format!("https://github.com/{GITHUB_REPO}/releases/tag/v1.4.0"),
        "draft": false,
        "prerelease": false,
        "published_at": "2026-09-21T21:33:20Z",
        "assets": [asset("MacVPN-1.4.0.dmg"), asset("MacVPN-1.4.0.dmg.sha256"), asset("MacVPN-1.4.0.dmg.sig")],
    });
    let mut out = serde_json::to_vec_pretty(&json).unwrap();
    out.push(b'\n');
    out
}

fn parsed_release(json: &[u8]) -> Release {
    UpdateChecker::parse_release(json, GITHUB_REPO, &|v| MACVPN.update_asset(v, std::env::consts::ARCH)).unwrap()
}

/// The release the update source answers with (the view model's pending offer).
struct FixedRelease(Release);

impl ReleaseSource for FixedRelease {
    fn latest_release(&self, _repo_id: i64, _repo: &str) -> Result<Release, String> {
        Ok(self.0.clone())
    }
}

// MARK: - the vault dump

/// A logical dump of the vault: the schema (`sqlite_master`, by name) and every table's rows ordered by the
/// primary key, each value as its SQL literal (`quote()`: BLOBs as `X'hex'`). SQLCipher's file bytes are random by
/// design; this is what must stay equal. The vault's creation time is the only value normalized.
fn vault_dump(vault: &Vault) -> Vec<u8> {
    let conn = vault.connection();
    let mut schema = Vec::new();
    let mut stmt = conn.prepare("SELECT type, name, tbl_name, sql FROM sqlite_master ORDER BY name").unwrap();
    let rows = stmt
        .query_map([], |r| {
            Ok(serde_json::json!({
                "type": r.get::<_, String>(0)?,
                "name": r.get::<_, String>(1)?,
                "table": r.get::<_, String>(2)?,
                "sql": r.get::<_, Option<String>>(3)?,
            }))
        })
        .unwrap();
    for row in rows {
        schema.push(row.unwrap());
    }
    let mut stmt = conn.prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").unwrap();
    let tables: Vec<String> = stmt.query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect();
    let mut dump = serde_json::Map::new();
    for table in tables {
        let mut stmt = conn.prepare("SELECT name, pk FROM pragma_table_info(?1) ORDER BY cid").unwrap();
        let columns: Vec<(String, i64)> =
            stmt.query_map([&table], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().map(Result::unwrap).collect();
        let mut keys: Vec<&(String, i64)> = columns.iter().filter(|(_, pk)| *pk > 0).collect();
        keys.sort_by_key(|(_, pk)| *pk);
        let order = if keys.is_empty() {
            columns.iter().map(|(c, _)| format!("\"{c}\"")).collect::<Vec<_>>().join(", ")
        } else {
            keys.iter().map(|(c, _)| format!("\"{c}\"")).collect::<Vec<_>>().join(", ")
        };
        let select = columns.iter().map(|(c, _)| format!("quote(\"{c}\")")).collect::<Vec<_>>().join(", ");
        let mut stmt = conn.prepare(&format!("SELECT {select} FROM \"{table}\" ORDER BY {order}")).unwrap();
        let width = columns.len();
        let rows: Vec<Vec<String>> = stmt
            .query_map([], |r| (0..width).map(|i| r.get::<_, String>(i)).collect())
            .unwrap()
            .map(Result::unwrap)
            .map(|mut row: Vec<String>| {
                if table == "meta" && row.first().map(String::as_str) == Some("'created'") {
                    row[1] = "'@CREATED@'".into();
                }
                row
            })
            .collect();
        dump.insert(
            table,
            serde_json::json!({ "columns": columns.iter().map(|(c, _)| c).collect::<Vec<_>>(), "rows": rows }),
        );
    }
    let mut out = serde_json::to_vec_pretty(&serde_json::json!({ "schema": schema, "tables": dump })).unwrap();
    out.push(b'\n');
    out
}

/// A vault filled with the backup's content (restored through the repositories) and the paired client.
fn filled_vault(dir: &Path) -> Vault {
    fs::create_dir_all(dir).unwrap();
    let dek = Dek::generate(&entropy()).unwrap();
    let mut vault = Vault::create(dir, &dek).unwrap();
    backup::replace(&mut vault, &backup_payload()).unwrap();
    vault.save_control_clients(&registry().client_values()).unwrap();
    vault
}

// MARK: - the view model

/// The view model as the app's publisher builds it (`AppState::view_model` in `app/src-tauri/src/state.rs`), over
/// app-core types only: the backup's content in an unlocked vault, the OpenVPN connection connected, the system VPN
/// "Office VPN", the "Remote" folder collapsed, a pending update offer, one team catalog subscription and the
/// control API on with one paired client.
fn view_model_json() -> Vec<u8> {
    AppLanguage::set_thread_override(Some(AppLanguage::En));
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path()).unwrap();
    let vault = Arc::new(VaultLifecycle::new(
        tmp.path().join("MacVPN"),
        Arc::new(MemoryKeyStore::new()),
        Arc::new(entropy()),
        kdf(),
    ));
    vault.create(z(PASSWORD), false).unwrap();
    vault.with(|v| backup::replace(v, &backup_payload())).unwrap();
    vault.with(|v| v.save_control_clients(&registry().client_values())).unwrap();

    // The app's wiring (`build_state` in `app/src-tauri/src/main.rs`) with the root and the system VPNs mocked.
    let helper = Arc::new(MockHelper::default());
    helper.respond(
        "status",
        Ok(&format!(
            r#"[{{"id":"{}","kind":"openvpn","state":"connected","iface":"utun4","ip":"10.0.0.2","since":1790000000}}]"#,
            uuid_string(&openvpn_id())
        )),
    );
    let native = Arc::new(MockNative::default());
    native.set_list(Ok(vec![SystemVpn::new(SYSTEM_VPN, "Office VPN", "L2TP", "Connected")]));
    let secrets = Arc::new(VaultSecrets::new(vault.clone()));
    let mut deps =
        Dependencies::new(Arc::new(VaultConnections::new(vault.clone())), secrets.clone(), helper.clone(), native);
    deps.ranking_store = Some(Arc::new(VaultRanking::new(vault.clone())));
    deps.system_otp_store = Some(Arc::new(VaultSystemOtp::new(vault.clone())));
    deps.secret_writer = Some(secrets);
    deps.folders = Some(Arc::new(VaultFolders::new(vault.clone())));
    let clock = Arc::new(ManualClock::new(fixed_date()));
    deps.clock = clock.clone();
    let manager = ConnectionManager::new(deps);
    manager.reload();

    // One team catalog subscription (the fixture catalog, over HTTPS).
    let fetcher = Arc::new(FakeFetcher::default());
    let (bytes, admin, team) = sealed_catalog();
    fetcher.serve(bytes);
    let catalogs = CatalogService::new(CatalogDeps {
        vault: vault.clone(),
        https: fetcher.clone(),
        file: fetcher,
        manager: manager.clone(),
        clock: clock.clone(),
    });
    catalogs.attach();
    let (_, pending) = catalogs
        .preview(SubscribeInput {
            source: CatalogSource::Https(HttpsUrl::parse("https://vpn.example.com/team.macvpncatalog").unwrap()),
            team_key: team,
            fingerprint: admin.public().fingerprint(),
            bearer: None,
            catalog_id: Some(catalog_id()),
            min_version: None,
        })
        .unwrap();
    catalogs.confirm(pending).unwrap();
    manager.reload();
    manager.refresh();

    // A pending update offer: the fixture release, offered to an older running version.
    let prefs = Arc::new(MemoryPreferences::new());
    prefs.set_bool("controlAPIEnabled", true);
    let updates = UpdateController::new(
        Some(UpdateSource { repo_id: GITHUB_REPO_ID, repo: GITHUB_REPO.into() }),
        "1.3.0",
        prefs.clone(),
        Arc::new(FixedRelease(parsed_release(&release_json()))),
        clock,
    );
    assert!(updates.check(), "the fixture release is offered");

    // `AppState::view_model`, step by step.
    let mut vm = ViewModel::build(&manager.snapshot(), AppLanguage::En.raw_value(), |_| true, Vec::new(), true);
    vm.set_server_hosts(&manager.server_hosts());
    vm.update = updates.view();
    let clients = Registry::from_client_values(&vault.with_read(|v| v.control_clients()).unwrap()).unwrap();
    vm.control = ControlView::build(
        prefs.bool("controlAPIEnabled").unwrap_or(false),
        true,
        None,
        clients.clients(),
        &HashMap::new(),
        Vec::new(),
    );
    vm.credentials = SharedCredentials::new(vault.clone()).view();
    vm.backup_available = true;
    // `CatalogApp::fill` (the publishing side has nothing here).
    vm.catalogs = catalogs.view();
    vm.set_catalog_badges(&catalogs.badges());
    vm.apply_vault(VaultView::build(&vault.state(), vault.auto_unlock(), false, 0));
    // The running build's version is not part of the format.
    vm.app_version = "@VERSION@";
    let mut text = serde_json::to_string_pretty(&vm).unwrap();
    // The catalog slot's credential gets a random id when the subscription is applied (by design).
    let random: Vec<String> = vault
        .with_read(|v| v.credentials())
        .unwrap()
        .into_iter()
        .map(|c| uuid_string(&c.id))
        .filter(|c| *c != uuid_string(&credential_id()))
        .collect();
    assert_eq!(random.len(), 1, "one slot credential");
    text = text.replace(&random[0], "@SLOT-CREDENTIAL@");
    text.push('\n');
    text.into_bytes()
}

// MARK: - the fixtures

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/compat-1.4.0")
}

fn read_fixture(name: &str) -> Vec<u8> {
    let path = fixtures_dir().join(name);
    fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn pretty(value: &serde_json::Value) -> Vec<u8> {
    let mut out = serde_json::to_vec_pretty(value).unwrap();
    out.push(b'\n');
    out
}

fn backup_files() -> Vec<(&'static str, Vec<u8>)> {
    let payload = backup_payload();
    let sealed = backup::seal(&payload, PASSWORD, kdf(), &entropy()).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&backup::payload_json(&payload).unwrap()).unwrap();
    vec![("backup.macvpnbackup", sealed), ("backup-payload.json", pretty(&json))]
}

fn catalog_files() -> Vec<(&'static str, Vec<u8>)> {
    let (bytes, admin, team) = sealed_catalog();
    let opened = open_fixture_catalog(&bytes, &admin, &team);
    let json: serde_json::Value = serde_json::from_slice(&encode_payload(&opened).unwrap()).unwrap();
    vec![("catalog.macvpncatalog", bytes), ("catalog-payload.json", pretty(&json))]
}

fn export_files() -> Vec<(&'static str, Vec<u8>)> {
    let tmp = TempDir::new();
    let store = ConnectionStore::new(tmp.path().join("connections"));
    for c in [openvpn(), l2tp()] {
        store.save(&c, if c.kind.is_native() { None } else { Some(OPENVPN_CONFIG) }).unwrap();
    }
    let config = exporter::export(&openvpn(), &store).unwrap();
    let meta =
        ExportMeta { folder: Some(vec!["Work".into(), "Remote".into()]), credential_name: Some("Office Login".into()) };
    vec![
        ("export-openvpn.ovpn", exporter::with_meta(&config, &meta)),
        ("export-l2tp.mobileconfig", exporter::export(&l2tp(), &store).unwrap()),
    ]
}

fn store_files() -> Vec<(&'static str, Vec<u8>)> {
    let tmp = TempDir::new();
    let store = ConnectionStore::new(tmp.path().join("connections"));
    store.save(&openvpn(), Some(OPENVPN_CONFIG)).unwrap();
    let order = ConnectionRankingStore::new(tmp.path().join("connection-order.json"));
    order.save(&ranking()).unwrap();
    let otp = SystemOTPStore::new(tmp.path().join("system-otp.json"));
    otp.save(&system_otp()).unwrap();
    registry().save(tmp.path()).unwrap();
    vec![
        ("meta.json", fs::read(store.meta_path(&openvpn_id())).unwrap()),
        ("connection-order.json", fs::read(&order.path).unwrap()),
        ("system-otp.json", fs::read(&otp.path).unwrap()),
        ("control-clients.json", fs::read(Registry::path(tmp.path())).unwrap()),
    ]
}

fn vault_files() -> Vec<(&'static str, Vec<u8>)> {
    let tmp = TempDir::new();
    let vault = filled_vault(&tmp.path().join("vault"));
    vec![("vault-dump.json", vault_dump(&vault))]
}

fn release_files() -> Vec<(&'static str, Vec<u8>)> {
    let json = release_json();
    let parsed = format!("{:#?}\n", parsed_release(&json));
    vec![("release.json", json), ("release-parsed.txt", parsed.into_bytes())]
}

fn all_fixtures() -> Vec<(&'static str, Vec<u8>)> {
    let mut all = Vec::new();
    all.extend(backup_files());
    all.extend(catalog_files());
    all.extend(export_files());
    all.extend(store_files());
    all.extend(vault_files());
    all.push(("view-model.json", view_model_json()));
    all.extend(release_files());
    all
}

/// Each generated file must equal its committed fixture byte for byte.
fn assert_same(files: &[(&'static str, Vec<u8>)]) {
    for (name, bytes) in files {
        let expected = read_fixture(name);
        if *bytes != expected {
            panic!(
                "{name} differs from the 1.4.0 fixture (tests/fixtures/compat-1.4.0/{name}); a serialized format changed.\n\
                 now:\n{}",
                String::from_utf8_lossy(bytes)
            );
        }
    }
}

/// Writes the fixtures once; never overwrites one.
#[test]
#[ignore = "writes the 1.4.0 fixtures; run once on 1.4.0"]
fn write_compat_fixtures() {
    let dir = fixtures_dir();
    fs::create_dir_all(&dir).unwrap();
    for (name, bytes) in all_fixtures() {
        let path = dir.join(name);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap_or_else(|e| panic!("refusing to overwrite {}: {e}", path.display()));
        std::io::Write::write_all(&mut file, &bytes).unwrap();
    }
}

// MARK: - the checks

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn backup_matches_and_opens() {
    assert_same(&backup_files());
    let payload = backup::open(&read_fixture("backup.macvpnbackup"), PASSWORD).unwrap();
    assert_eq!(payload, backup_payload());
    let json: serde_json::Value = serde_json::from_slice(&backup::payload_json(&payload).unwrap()).unwrap();
    assert_eq!(pretty(&json), read_fixture("backup-payload.json"));
    // Restored and collected again, the vault gives the same payload.
    let tmp = TempDir::new();
    let vault = filled_vault(&tmp.path().join("vault"));
    let prefs = payload.preferences;
    assert_eq!(backup::collect(&vault, prefs, fixed_date(), APP_VERSION).unwrap(), payload);
}

#[test]
fn catalog_matches_and_opens() {
    assert_same(&catalog_files());
    let (_, admin, team) = sealed_catalog();
    let opened = open_fixture_catalog(&read_fixture("catalog.macvpncatalog"), &admin, &team);
    assert_eq!(opened, catalog_payload());
    let json: serde_json::Value = serde_json::from_slice(&encode_payload(&opened).unwrap()).unwrap();
    assert_eq!(pretty(&json), read_fixture("catalog-payload.json"));
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn exports_match_and_import() {
    assert_same(&export_files());
    // The exported config imports again: its metadata line, then the config itself.
    let ovpn = String::from_utf8(read_fixture("export-openvpn.ovpn")).unwrap();
    let (meta, config) = macvpn_core::importer::take_export_meta(&ovpn);
    let meta = meta.expect("the metadata line");
    assert_eq!(config, OPENVPN_CONFIG);
    assert_eq!(meta.folder, Some(vec!["Work".to_string(), "Remote".to_string()]));
    assert_eq!(meta.credential_name.as_deref(), Some("Office Login"));
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path()).unwrap();
    let prepared = macvpn_core::importer::prepare("Office OpenVPN.ovpn", config, tmp.path()).unwrap();
    assert_eq!((prepared.kind, prepared.config.as_str()), (VPNKind::Openvpn, OPENVPN_CONFIG));
    assert!(prepared.issues.is_empty(), "{:?}", prepared.issues);
    // The profile is never imported by MacVPN (the system installs it): it stays the same plist.
    let profile = String::from_utf8(read_fixture("export-l2tp.mobileconfig")).unwrap();
    assert!(profile.starts_with("<?xml") && profile.contains(&format!("<string>{SERVER}</string>")));
    assert!(!profile.contains(USER) && !profile.contains(SECRET), "a personal value in the exported profile");
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn store_files_match_and_load() {
    assert_same(&store_files());
    let tmp = TempDir::new();
    let dir = tmp.path().join("connections").join(uuid_string(&openvpn_id()));
    fs::create_dir_all(&dir).unwrap();
    for name in ["meta.json", "connection-order.json", "system-otp.json", "control-clients.json"] {
        let target = if name == "meta.json" { dir.join(name) } else { tmp.path().join(name) };
        fs::write(target, read_fixture(name)).unwrap();
    }
    fs::write(dir.join("config.ovpn"), OPENVPN_CONFIG).unwrap();
    let listed = ConnectionStore::new(tmp.path().join("connections")).list().unwrap();
    assert_eq!(listed, vec![openvpn()]);
    assert_eq!(ConnectionRankingStore::new(tmp.path().join("connection-order.json")).load(), ranking());
    assert_eq!(SystemOTPStore::new(tmp.path().join("system-otp.json")).load(), system_otp());
    assert_eq!(Registry::load(tmp.path()).unwrap().clients(), registry().clients());
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn vault_dump_matches() {
    assert_same(&vault_files());
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn view_model_matches() {
    assert_same(&[("view-model.json", view_model_json())]);
}

#[test]
fn release_matches_and_parses() {
    assert_same(&release_files());
    let parsed = parsed_release(&read_fixture("release.json"));
    assert_eq!(format!("{parsed:#?}\n").into_bytes(), read_fixture("release-parsed.txt"));
}

/// The fixtures hold no value of a real system: no home directory and no host name but the example server (and
/// GitHub, where the release assets live, and Apple's plist DTD).
#[test]
fn fixtures_contain_no_real_system_values() {
    let allowed = ["vpn.example.com", "github.com", "www.apple.com"];
    let host =
        regex::Regex::new(r"(?i)\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|hu|de|eu|local|lan|internal|corp)\b").unwrap();
    // The encrypted files' contents are checked through their decrypted payloads (and configs, base64 there).
    let backup = backup_payload();
    let catalog = catalog_payload();
    let mut texts: Vec<(String, String)> = Vec::new();
    for entry in fs::read_dir(fixtures_dir()).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let bytes = fs::read(&path).unwrap();
        if let Ok(text) = String::from_utf8(bytes) {
            texts.push((name, text));
        }
    }
    for c in &backup.connections {
        texts.push((format!("backup config {}", c.connection.name), c.config.to_string()));
    }
    for c in &catalog.connections {
        texts.push((format!("catalog config {}", c.name), c.config.to_string()));
    }
    assert!(texts.iter().any(|(n, _)| n == "view-model.json"), "the fixtures are missing");
    for (name, text) in &texts {
        assert!(!text.contains("/Users/"), "{name} contains a home directory");
        assert!(!text.contains("/private/var/") && !text.contains("/var/folders/"), "{name} has a temp path");
        for m in host.find_iter(text) {
            let found = m.as_str().to_ascii_lowercase();
            // Reverse-DNS identifiers (com.apple.…, local.macvpn.…) are not host names.
            if found.starts_with("com.") || found.starts_with("local.") {
                continue;
            }
            assert!(allowed.contains(&found.as_str()), "{name} names the host {found}");
        }
    }
}
