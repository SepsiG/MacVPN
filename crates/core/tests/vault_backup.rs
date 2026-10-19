//! The full backup (plan B Task 20, spec 3b): the sealed container, the JSON payload collected from the vault, and
//! the restore planner (merge with each conflict mode, replace, a fresh restore).

mod common;

use common::{TempDir, mode};
use macvpn_core::date::Date;
use macvpn_core::models::{Connection, OTPSeparator, OTPSetting, SecretField, VPNKind, uuid_string};
use macvpn_core::ranking::{ConnectionRanking, UsageStats};
use macvpn_core::vault::backup::{
    self, BackupConnection, BackupCredential, BackupError, BackupPayload, BackupPreferences, Collection, ConflictMode,
    HEADER_LEN, InvalidBackup, MAX_BACKUP_BYTES, MAX_ITEMS, MAX_KDF, MAX_PLAINTEXT_BYTES, RestorePlan,
};
use macvpn_core::vault::{
    Dek, FixedEntropy, FolderColor, FolderNode, KdfParams, SystemItem, Vault, VaultError, validate_credential_name,
};
use serde_json::json;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use zeroize::Zeroizing;

const PASSWORD: &str = "correct horse battery";

fn dek() -> Dek {
    Dek::generate(&FixedEntropy::new(20)).unwrap()
}

fn new_vault(tmp: &TempDir, name: &str) -> Vault {
    fs::create_dir_all(tmp.path()).unwrap();
    Vault::create(&tmp.path().join(name), &dek()).unwrap()
}

fn date(s: &str) -> Date {
    Date::parse_iso8601(s).unwrap()
}

fn now() -> Date {
    date("2026-10-19T12:00:00Z")
}

fn id(n: u128) -> Uuid {
    Uuid::from_u128(0x1000_0000_0000_4000_8000_0000_0000_0000 + n)
}

fn z(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_string())
}

fn connection(uuid: Uuid, name: &str) -> Connection {
    Connection::with_id(uuid, name, VPNKind::Openvpn, date("2026-10-01T08:00:00Z"))
}

fn prefs() -> BackupPreferences {
    BackupPreferences {
        auto_check: true,
        delay_24h: false,
        launch_at_login: true,
        control_api_enabled: true,
        auto_unlock: false,
    }
}

fn kdf() -> KdfParams {
    KdfParams::insecure_for_tests()
}

fn add_credential(vault: &mut Vault, uuid: Uuid, name: &str, username: &str, password: Option<&str>) {
    vault
        .transaction(|tx| {
            tx.execute(
                "INSERT INTO credentials(id, name, username, password, created, updated) VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
                (uuid_string(&uuid), name, username, password.map(str::as_bytes), "2026-10-02T08:00:00Z"),
            )?;
            Ok(())
        })
        .unwrap();
}

fn link(vault: &mut Vault, item: &str, credential: Uuid) {
    vault
        .transaction(|tx| {
            tx.execute(
                "INSERT INTO credential_links(item_id, credential_id) VALUES (?1, ?2)
                 ON CONFLICT(item_id) DO UPDATE SET credential_id = excluded.credential_id",
                (item, uuid_string(&credential)),
            )?;
            Ok(())
        })
        .unwrap();
}

fn credential_rows(vault: &Vault) -> Vec<(String, String, String, Option<String>)> {
    let mut stmt =
        vault.connection().prepare("SELECT id, name, username, password FROM credentials ORDER BY name").unwrap();
    stmt.query_map([], |r| {
        let password: Option<Vec<u8>> = r.get(3)?;
        Ok((r.get(0)?, r.get(1)?, r.get(2)?, password.map(|p| String::from_utf8(p).unwrap())))
    })
    .unwrap()
    .collect::<Result<_, _>>()
    .unwrap()
}

fn links(vault: &Vault) -> BTreeMap<String, String> {
    let mut stmt = vault.connection().prepare("SELECT item_id, credential_id FROM credential_links").unwrap();
    stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().collect::<Result<_, _>>().unwrap()
}

fn credential_id_named(vault: &Vault, name: &str) -> String {
    vault.connection().query_row("SELECT id FROM credentials WHERE name = ?1", [name], |r| r.get(0)).unwrap()
}

fn named(vault: &Vault, name: &str) -> Connection {
    let all = vault.connections().unwrap();
    all.iter().find(|c| c.connection.name == name).unwrap_or_else(|| panic!("no {name}")).connection.clone()
}

fn folder_named<'a>(folders: &'a [FolderNode], name: &str) -> &'a FolderNode {
    folders.iter().find(|f| f.name == name).unwrap_or_else(|| panic!("no folder {name}"))
}

fn secret(vault: &Vault, item: &str, field: SecretField) -> Option<String> {
    vault.secret(item, field).unwrap().map(|s| s.to_string())
}

fn client(id: &str) -> serde_json::Value {
    json!({ "id": id, "name": "Remote Desktop", "tokenHash": "ab" })
}

fn usage(score: f64) -> UsageStats {
    UsageStats { score, last_updated: date("2026-10-18T10:00:00Z") }
}

/// Every table filled: two folders (one nested), two connections with secrets, a linked shared credential, a
/// credential without a password, a system VPN with a placement, secrets, a link and an OTP setting, the ranking
/// with a pin, and a paired control client (which the backup leaves out).
fn filled_vault(tmp: &TempDir, name: &str) -> Vault {
    let mut vault = new_vault(tmp, name);
    let work = vault.create_folder(None, "Work").unwrap();
    let sub = vault.create_folder(Some(work), "Sub").unwrap();
    vault.set_folder_color(work, Some(FolderColor::Blue)).unwrap();
    vault.set_collapsed(sub, true).unwrap();
    let alpha = connection(id(1), "Canary Alpha");
    vault.save_connection(&alpha, Some("remote canary-alpha.example 1194\n")).unwrap();
    vault.set_item_folder(&uuid_string(&alpha.id), Some(sub)).unwrap();
    vault.set_item_color(&uuid_string(&alpha.id), Some(FolderColor::Red)).unwrap();
    vault.set_secret(&uuid_string(&alpha.id), SecretField::KeyPassword, "alpha-keypass").unwrap();
    let mut beta = Connection::with_id(id(2), "Beta", VPNKind::L2tp, date("2026-10-01T09:00:00Z"));
    beta.native_service_name = Some("Beta".into());
    vault.save_connection(&beta, Some("")).unwrap();
    vault.set_secret(&uuid_string(&beta.id), SecretField::Username, "beta-user").unwrap();
    vault.set_secret(&uuid_string(&beta.id), SecretField::Password, "beta-pass").unwrap();
    vault.set_secret(&uuid_string(&beta.id), SecretField::Psk, "beta-psk").unwrap();
    add_credential(&mut vault, id(100), "Office AD", "ad-user", Some("ad-pass"));
    add_credential(&mut vault, id(101), "No Password", "np-user", None);
    link(&mut vault, &uuid_string(&alpha.id), id(100));
    vault.set_item_folder("SYSTEM-SERVICE-1", Some(work)).unwrap();
    // Linked: its username and password are the credential's, its PSK its own.
    vault.set_secret("SYSTEM-SERVICE-1", SecretField::Psk, "system-psk").unwrap();
    link(&mut vault, "SYSTEM-SERVICE-1", id(101));
    let otp = HashMap::from([("SYSTEM-SERVICE-1".to_string(), OTPSetting::new(true, OTPSeparator::None))]);
    vault.save_system_otp_map(&otp).unwrap();
    let ranking = ConnectionRanking::new(
        vec![uuid_string(&beta.id)],
        HashMap::from([(uuid_string(&alpha.id), usage(3.5)), ("SYSTEM-SERVICE-1".to_string(), usage(1.0))]),
    );
    vault.save_ranking(&ranking).unwrap();
    vault.save_control_clients(&[client("client-1")]).unwrap();
    vault
}

fn collect(vault: &Vault) -> BackupPayload {
    backup::collect(vault, prefs(), now(), "1.2.0").unwrap()
}

fn sealed(payload: &BackupPayload) -> Vec<u8> {
    backup::seal(payload, PASSWORD, kdf(), &FixedEntropy::new(5)).unwrap()
}

// MARK: - collect

#[test]
fn collect_takes_everything_but_the_paired_clients() {
    let tmp = TempDir::new();
    let vault = filled_vault(&tmp, "a");
    let p = collect(&vault);
    assert_eq!(p.version, 1);
    assert_eq!(p.created, now());
    assert_eq!(p.app_version, "1.2.0");
    assert_eq!(p.preferences, prefs());
    assert_eq!(p.folders.len(), 2);
    let work = folder_named(&p.folders, "Work");
    let sub = folder_named(&p.folders, "Sub");
    assert_eq!(work.color, Some(FolderColor::Blue));
    assert_eq!(sub.parent, Some(work.id));
    assert!(sub.collapsed);

    let names: Vec<&str> = p.connections.iter().map(|c| c.connection.name.as_str()).collect();
    assert_eq!(names, ["Beta", "Canary Alpha"]);
    let alpha = &p.connections[1];
    assert_eq!(alpha.config.as_str(), "remote canary-alpha.example 1194\n");
    assert_eq!(alpha.folder_id, Some(sub.id));
    assert_eq!(alpha.color, Some(FolderColor::Red));
    assert_eq!(alpha.secrets, vec![(SecretField::KeyPassword, z("alpha-keypass"))]);
    let beta = &p.connections[0];
    assert_eq!(beta.connection.kind, VPNKind::L2tp);
    assert_eq!(
        beta.secrets,
        vec![
            (SecretField::Username, z("beta-user")),
            (SecretField::Password, z("beta-pass")),
            (SecretField::Psk, z("beta-psk")),
        ]
    );

    assert_eq!(p.system_secrets.len(), 1);
    assert_eq!(p.system_secrets["SYSTEM-SERVICE-1"], vec![(SecretField::Psk, z("system-psk"))]);
    assert_eq!(p.credentials.len(), 2);
    assert_eq!(p.credentials[0].name, "No Password");
    assert_eq!(p.credentials[0].password, None);
    assert_eq!(p.credentials[1].name, "Office AD");
    assert_eq!(p.credentials[1].username.as_str(), "ad-user");
    assert_eq!(p.credentials[1].password.as_deref().map(String::as_str), Some("ad-pass"));
    assert_eq!(p.credentials[1].created, date("2026-10-02T08:00:00Z"));
    assert_eq!(p.credential_links, vec![(uuid_string(&id(1)), id(100)), ("SYSTEM-SERVICE-1".to_string(), id(101))]);
    assert_eq!(p.system_items.len(), 1);
    assert_eq!(p.system_items[0].service_id, "SYSTEM-SERVICE-1");
    assert_eq!(p.system_items[0].folder_id, Some(work.id));
    assert!(p.system_otp["SYSTEM-SERVICE-1"].enabled);
    assert_eq!(p.ranking.pinned(), [uuid_string(&id(2))]);
    assert_eq!(p.ranking.usage().len(), 2);
}

#[test]
fn debug_output_of_a_payload_shows_no_secret() {
    let tmp = TempDir::new();
    let vault = filled_vault(&tmp, "a");
    let text = format!("{:?}", collect(&vault));
    for secret in ["canary-alpha", "alpha-keypass", "beta-pass", "beta-psk", "ad-pass", "ad-user", "system-psk"] {
        assert!(!text.contains(secret), "{secret} in {text}");
    }
}

// MARK: - the container

#[test]
fn seal_and_open_round_trip_a_full_payload() {
    let tmp = TempDir::new();
    let vault = filled_vault(&tmp, "a");
    let payload = collect(&vault);
    let bytes = sealed(&payload);
    let back = backup::open(&bytes, PASSWORD).unwrap();
    assert_eq!(back, payload);
}

#[test]
fn the_header_holds_the_format_and_the_kdf_parameters() {
    let payload = BackupPayload::empty(now(), "1.2.0", prefs());
    let bytes = sealed(&payload);
    assert_eq!(HEADER_LEN, 64);
    assert_eq!(&bytes[..8], b"MVPNBKUP");
    assert_eq!(&bytes[8..10], &[0, 1]);
    assert_eq!(bytes[10], 1);
    assert_eq!(bytes[11], 0);
    let p = kdf();
    assert_eq!(&bytes[12..16], &p.m_kib.to_be_bytes());
    assert_eq!(&bytes[16..20], &p.t.to_be_bytes());
    assert_eq!(&bytes[20..24], &p.p.to_be_bytes());
    // A fresh salt and nonce every time.
    let again = backup::seal(&payload, PASSWORD, kdf(), &FixedEntropy::new(6)).unwrap();
    assert_ne!(&bytes[24..64], &again[24..64]);
    assert!(bytes.len() > HEADER_LEN + 16);
}

#[test]
fn production_kdf_parameters_are_never_lowered() {
    let payload = BackupPayload::empty(now(), "1.2.0", prefs());
    let weak = KdfParams { m_kib: 8, t: 1, p: 1 };
    let bytes = backup::seal(&payload, PASSWORD, weak, &FixedEntropy::new(5)).unwrap();
    let d = KdfParams::DEFAULT;
    assert_eq!(&bytes[12..24], [d.m_kib.to_be_bytes(), d.t.to_be_bytes(), d.p.to_be_bytes()].concat());
    assert!(backup::open(&bytes, PASSWORD).is_ok());
}

fn assert_cannot_open(bytes: &[u8], password: &str, what: &str) {
    match backup::open(bytes, password) {
        Err(BackupError::CannotOpen) => {}
        other => panic!("{what}: {other:?}"),
    }
}

#[test]
fn a_wrong_password_or_any_damage_is_the_same_generic_error() {
    let payload = BackupPayload::empty(now(), "1.2.0", prefs());
    let bytes = sealed(&payload);
    assert_cannot_open(&bytes, "wrong password!", "wrong password");
    assert_cannot_open(&bytes, "", "empty password");
    // Every header byte except the format (which says "newer") and the KDF cost fields' high bytes, which would
    // only make the KDF slower.
    for i in (0..8).chain(10..12).chain([15, 19, 23]).chain(24..HEADER_LEN) {
        let mut damaged = bytes.clone();
        damaged[i] ^= 0x01;
        assert_cannot_open(&damaged, PASSWORD, &format!("header byte {i}"));
    }
    for i in [HEADER_LEN, HEADER_LEN + 1, bytes.len() / 2, bytes.len() - 17, bytes.len() - 1] {
        let mut damaged = bytes.clone();
        damaged[i] ^= 0x80;
        assert_cannot_open(&damaged, PASSWORD, &format!("payload byte {i}"));
    }
    for len in [0, 7, 8, 40, HEADER_LEN - 1, HEADER_LEN, HEADER_LEN + 15, HEADER_LEN + 16, bytes.len() - 1] {
        assert_cannot_open(&bytes[..len], PASSWORD, &format!("truncated to {len}"));
    }
    let mut longer = bytes.clone();
    longer.push(0);
    assert_cannot_open(&longer, PASSWORD, "a trailing byte");
}

#[test]
fn an_unknown_kdf_or_impossible_parameters_cannot_open() {
    let bytes = sealed(&BackupPayload::empty(now(), "1.2.0", prefs()));
    let mut kdf_id = bytes.clone();
    kdf_id[10] = 2;
    assert_cannot_open(&kdf_id, PASSWORD, "kdf id 2");
    let mut huge = bytes.clone();
    huge[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_cannot_open(&huge, PASSWORD, "m_kib above the ceiling");
    let mut zero_lanes = bytes;
    zero_lanes[20..24].copy_from_slice(&0u32.to_be_bytes());
    assert_cannot_open(&zero_lanes, PASSWORD, "p = 0");
}

#[test]
fn a_newer_format_is_refused_as_newer() {
    let mut bytes = sealed(&BackupPayload::empty(now(), "1.2.0", prefs()));
    bytes[8..10].copy_from_slice(&2u16.to_be_bytes());
    assert!(matches!(backup::open(&bytes, PASSWORD), Err(BackupError::NewerVersion(2))));
    // Even with a wrong password: the format is checked before anything else.
    assert!(matches!(backup::open(&bytes, "wrong password!"), Err(BackupError::NewerVersion(2))));
    bytes[8..10].copy_from_slice(&0u16.to_be_bytes());
    assert_cannot_open(&bytes, PASSWORD, "format 0");
}

#[test]
fn a_newer_payload_version_is_refused_as_newer() {
    let mut payload = BackupPayload::empty(now(), "9.0.0", prefs());
    payload.version = 2;
    let bytes = sealed(&payload);
    assert!(matches!(backup::open(&bytes, PASSWORD), Err(BackupError::NewerVersion(2))));
    payload.version = 0;
    assert_cannot_open(&sealed(&payload), PASSWORD, "payload version 0");
}

#[test]
fn a_file_over_the_cap_is_too_large() {
    assert_eq!(MAX_PLAINTEXT_BYTES, 64 * 1024 * 1024);
    assert_eq!(MAX_BACKUP_BYTES, HEADER_LEN + MAX_PLAINTEXT_BYTES + 16);
    let bytes = vec![0u8; MAX_BACKUP_BYTES + 1];
    assert!(matches!(backup::open(&bytes, PASSWORD), Err(BackupError::TooLarge)));
}

#[test]
fn the_sealed_bytes_hold_no_plaintext() {
    let tmp = TempDir::new();
    let vault = filled_vault(&tmp, "a");
    let bytes = sealed(&collect(&vault));
    for canary in ["Canary Alpha", "canary-alpha", "beta-pass", "ad-pass", "Office AD", "SYSTEM-SERVICE-1"] {
        assert!(!contains(&bytes, canary.as_bytes()), "{canary}");
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

// MARK: - write_backup

#[test]
fn write_backup_creates_a_0600_file() {
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path()).unwrap();
    let path = tmp.path().join("MacVPN-backup-2026-10-19.macvpnbackup");
    backup::write_backup(&path, b"sealed bytes").unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"sealed bytes");
    assert_eq!(mode(&path), 0o600);
    let names: Vec<_> = fs::read_dir(tmp.path()).unwrap().flatten().map(|e| e.file_name()).collect();
    assert_eq!(names.len(), 1);
}

#[test]
fn a_failed_write_leaves_no_partial_file() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = TempDir::new();
    let dir = tmp.path().join("read-only");
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o500)).unwrap();
    let result = backup::write_backup(&dir.join("b.macvpnbackup"), b"sealed bytes");
    let left: Vec<_> = fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name()).collect();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(result, Err(BackupError::Io(_))), "{result:?}");
    assert!(left.is_empty(), "{left:?}");
}

/// Runs `collect` + `seal` + `write_backup` in a child process whose `TMPDIR` is a scratch directory (the test
/// process cannot change its own environment without `unsafe`), then scans every file in the scratch directory and
/// in the target directory for the canary connection name and config line.
#[test]
fn no_plaintext_reaches_a_temporary_file() {
    const CHILD: &str = "MACVPN_BACKUP_TEMP_CHILD";
    if let Some(target) = std::env::var_os(CHILD) {
        let target = PathBuf::from(target);
        let tmp = TempDir(target.join("vault-home"));
        let vault = filled_vault(&tmp, "a");
        let bytes = sealed(&collect(&vault));
        vault.close();
        drop(tmp);
        backup::write_backup(&target.join("out").join("backup.macvpnbackup"), &bytes).unwrap();
        return;
    }
    let tmp = TempDir::new();
    let scratch = tmp.path().join("tmpdir");
    let target = tmp.path().join("target");
    fs::create_dir_all(&scratch).unwrap();
    fs::create_dir_all(target.join("out")).unwrap();
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["no_plaintext_reaches_a_temporary_file", "--exact", "--test-threads=1"])
        .env(CHILD, &target)
        .env("TMPDIR", &scratch)
        .status()
        .unwrap();
    assert!(status.success());
    let sealed_file = target.join("out").join("backup.macvpnbackup");
    assert!(sealed_file.is_file());
    let mut scanned = 0;
    for root in [&scratch, &target] {
        for file in files_under(root) {
            let bytes = fs::read(&file).unwrap();
            scanned += 1;
            for canary in ["Canary Alpha", "remote canary-alpha.example 1194"] {
                assert!(!contains(&bytes, canary.as_bytes()), "{canary} in {}", file.display());
            }
        }
    }
    assert!(scanned >= 1);
}

fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if entry.file_type().unwrap().is_dir() {
            out.extend(files_under(&path));
        } else {
            out.push(path);
        }
    }
    out
}

// MARK: - restore

/// The vault a merge goes into: folder `Work` (the backup's id), connection `Alpha` (the backup's id, other config
/// and password, linked to `Office AD`), `Zulu` (not in the backup), credential `Office AD` (the backup's id, other
/// values) and `Lab` (the backup's name under another id), a pin and a paired client.
fn existing_vault(tmp: &TempDir) -> Vault {
    let mut vault = new_vault(tmp, "existing");
    vault
        .transaction(|tx| {
            tx.execute(
                "INSERT INTO folders(id, parent_id, name, color, position, collapsed) VALUES (?1, NULL, 'Work', NULL, 0, 0)",
                [uuid_string(&id(10))],
            )?;
            Ok(())
        })
        .unwrap();
    vault.save_connection(&connection(id(1), "Alpha"), Some("remote old-alpha\n")).unwrap();
    vault.set_item_folder(&uuid_string(&id(1)), Some(id(10))).unwrap();
    vault.set_secret(&uuid_string(&id(1)), SecretField::KeyPassword, "old-keypass").unwrap();
    vault.save_connection(&connection(id(9), "Zulu"), Some("remote zulu\n")).unwrap();
    add_credential(&mut vault, id(100), "Office AD", "old-user", Some("old-pass"));
    add_credential(&mut vault, id(199), "Lab", "old-lab-user", None);
    link(&mut vault, &uuid_string(&id(1)), id(100));
    vault.save_ranking(&ConnectionRanking::new(vec![uuid_string(&id(1))], HashMap::new())).unwrap();
    vault.save_control_clients(&[client("client-1")]).unwrap();
    vault
}

fn backup_connection(uuid: Uuid, name: &str, config: &str, folder: Option<Uuid>) -> BackupConnection {
    BackupConnection {
        connection: connection(uuid, name),
        config: z(config),
        folder_id: folder,
        color: None,
        position: 0,
        secrets: vec![(SecretField::KeyPassword, z(&format!("{name}-keypass")))],
    }
}

fn credential(uuid: Uuid, name: &str, username: &str, password: Option<&str>) -> BackupCredential {
    BackupCredential {
        id: uuid,
        name: name.into(),
        username: z(username),
        password: password.map(z),
        created: date("2026-10-03T08:00:00Z"),
        updated: date("2026-10-04T08:00:00Z"),
    }
}

/// `Work` (conflict, renamed and coloured) with `Sub` (new) in it; `Alpha` (conflict) in `Sub` with a new config,
/// `Beta` (new) in `Work`; `Office AD` (id conflict), `Lab` (name conflict), `Fresh` (new); Alpha → Office AD,
/// Beta → Lab; a system VPN in `Sub` with a secret, a link to Fresh and an OTP setting; a pin on Beta.
fn incoming() -> BackupPayload {
    let mut p = BackupPayload::empty(now(), "1.2.0", prefs());
    p.folders = vec![
        FolderNode {
            id: id(10),
            parent: None,
            name: "Work (renamed)".into(),
            color: Some(FolderColor::Blue),
            position: 0,
            collapsed: false,
        },
        FolderNode { id: id(11), parent: Some(id(10)), name: "Sub".into(), color: None, position: 0, collapsed: true },
    ];
    p.connections = vec![
        backup_connection(id(1), "Alpha", "remote new-alpha\n", Some(id(11))),
        backup_connection(id(2), "Beta", "remote beta\n", Some(id(10))),
    ];
    p.credentials = vec![
        credential(id(100), "Office AD", "new-user", Some("new-pass")),
        credential(id(101), "Lab", "lab-user", Some("lab-pass")),
        credential(id(102), "Fresh", "fresh-user", None),
    ];
    p.credential_links =
        vec![(uuid_string(&id(1)), id(100)), (uuid_string(&id(2)), id(101)), ("SYSTEM-SERVICE-1".into(), id(102))];
    p.system_items = vec![SystemItem {
        service_id: "SYSTEM-SERVICE-1".into(),
        folder_id: Some(id(11)),
        color: Some(FolderColor::Green),
        position: 0,
        missing_since: None,
    }];
    p.system_secrets = BTreeMap::from([("SYSTEM-SERVICE-1".to_string(), vec![(SecretField::Psk, z("sys-psk"))])]);
    p.system_otp = HashMap::from([("SYSTEM-SERVICE-1".to_string(), OTPSetting::new(true, OTPSeparator::None))]);
    p.ranking = ConnectionRanking::new(vec![uuid_string(&id(2))], HashMap::from([(uuid_string(&id(1)), usage(9.0))]));
    p
}

fn assert_common_merge_result(vault: &Vault) {
    // Zulu, the paired client and the new items are there whatever the mode.
    assert_eq!(named(vault, "Zulu").id, id(9));
    assert_eq!(vault.control_clients().unwrap(), vec![client("client-1")]);
    let beta = named(vault, "Beta");
    assert_eq!(vault.config(&beta.id).unwrap().as_str(), "remote beta\n");
    assert_eq!(secret(vault, &uuid_string(&beta.id), SecretField::KeyPassword).as_deref(), Some("Beta-keypass"));
    let sub = folder_named(&vault.folders().unwrap(), "Sub").clone();
    assert!(sub.collapsed);
    let system = vault.system_items().unwrap();
    assert_eq!(system.len(), 1);
    assert_eq!(system[0].folder_id, Some(sub.id));
    assert_eq!(secret(vault, "SYSTEM-SERVICE-1", SecretField::Psk).as_deref(), Some("sys-psk"));
    assert!(vault.system_otp_map().unwrap()["SYSTEM-SERVICE-1"].enabled);
    let fresh = credential_id_named(vault, "Fresh");
    assert_eq!(links(vault).get("SYSTEM-SERVICE-1"), Some(&fresh));
    // The existing pin first, then the backup's.
    assert_eq!(vault.ranking().unwrap().pinned(), [uuid_string(&id(1)), uuid_string(&id(2))]);
}

#[test]
fn plan_restore_counts_new_items_conflicts_and_what_replace_loses() {
    let tmp = TempDir::new();
    let vault = existing_vault(&tmp);
    let plan = backup::plan_restore(&vault, &incoming()).unwrap();
    // Added: Beta, Sub, Fresh. Conflicts: Alpha, Work, Office AD (id), Lab (name). Lost on replace: Zulu and the
    // existing Lab (its id is not in the backup).
    assert_eq!(plan, RestorePlan { added: 3, conflicts: 4, lost_on_replace: 2, acknowledged_risky: Vec::new() });
    let empty = new_vault(&tmp, "empty");
    assert_eq!(
        backup::plan_restore(&empty, &incoming()).unwrap(),
        RestorePlan { added: 7, conflicts: 0, lost_on_replace: 0, acknowledged_risky: Vec::new() }
    );
}

#[test]
fn merge_overwrite_takes_the_backup_copy_of_every_conflict() {
    let tmp = TempDir::new();
    let mut vault = existing_vault(&tmp);
    backup::merge(&mut vault, &incoming(), ConflictMode::Overwrite).unwrap();
    assert_common_merge_result(&vault);
    assert_eq!(vault.connection_count().unwrap(), 3);
    let alpha = &uuid_string(&id(1));
    assert_eq!(vault.config(&id(1)).unwrap().as_str(), "remote new-alpha\n");
    assert_eq!(secret(&vault, alpha, SecretField::KeyPassword).as_deref(), Some("Alpha-keypass"));
    let folders = vault.folders().unwrap();
    assert_eq!(folders.len(), 2);
    let work = folder_named(&folders, "Work (renamed)");
    assert_eq!(work.id, id(10));
    assert_eq!(work.color, Some(FolderColor::Blue));
    let stored = vault.connections().unwrap();
    let stored_alpha = stored.iter().find(|c| c.connection.id == id(1)).unwrap();
    assert_eq!(stored_alpha.folder_id, Some(id(11)));
    // Office AD overwritten by id, Lab by name (the existing id stays, the backup's links follow it).
    assert_eq!(
        credential_rows(&vault),
        vec![
            (uuid_string(&id(102)), "Fresh".into(), "fresh-user".into(), None),
            (uuid_string(&id(199)), "Lab".into(), "lab-user".into(), Some("lab-pass".into())),
            (uuid_string(&id(100)), "Office AD".into(), "new-user".into(), Some("new-pass".into())),
        ]
    );
    let l = links(&vault);
    assert_eq!(l[alpha], uuid_string(&id(100)));
    assert_eq!(l[&uuid_string(&id(2))], uuid_string(&id(199)));
    assert_eq!(vault.ranking().unwrap().usage()[alpha].score, 9.0);
}

#[test]
fn merge_keep_existing_only_adds_what_is_missing() {
    let tmp = TempDir::new();
    let mut vault = existing_vault(&tmp);
    backup::merge(&mut vault, &incoming(), ConflictMode::KeepExisting).unwrap();
    assert_common_merge_result(&vault);
    assert_eq!(vault.connection_count().unwrap(), 3);
    let alpha = &uuid_string(&id(1));
    assert_eq!(vault.config(&id(1)).unwrap().as_str(), "remote old-alpha\n");
    assert_eq!(secret(&vault, alpha, SecretField::KeyPassword).as_deref(), Some("old-keypass"));
    let stored = vault.connections().unwrap();
    assert_eq!(stored.iter().find(|c| c.connection.id == id(1)).unwrap().folder_id, Some(id(10)));
    let folders = vault.folders().unwrap();
    assert_eq!(folders.len(), 2);
    assert_eq!(folder_named(&folders, "Work").color, None);
    assert_eq!(folder_named(&folders, "Sub").parent, Some(id(10)));
    assert_eq!(
        credential_rows(&vault),
        vec![
            (uuid_string(&id(102)), "Fresh".into(), "fresh-user".into(), None),
            (uuid_string(&id(199)), "Lab".into(), "old-lab-user".into(), None),
            (uuid_string(&id(100)), "Office AD".into(), "old-user".into(), Some("old-pass".into())),
        ]
    );
    let l = links(&vault);
    assert_eq!(l[alpha], uuid_string(&id(100)));
    // Beta's link to the backup's Lab follows the existing Lab of that name.
    assert_eq!(l[&uuid_string(&id(2))], uuid_string(&id(199)));
    // Alpha had no usage entry: the backup's is added (an existing one would have been kept).
    assert_eq!(vault.ranking().unwrap().usage()[alpha].score, 9.0);
}

#[test]
fn merge_keep_both_copies_each_conflict_under_a_new_id() {
    let tmp = TempDir::new();
    let mut vault = existing_vault(&tmp);
    backup::merge(&mut vault, &incoming(), ConflictMode::KeepBoth).unwrap();
    assert_common_merge_result(&vault);
    assert_eq!(vault.connection_count().unwrap(), 4);
    // The original is untouched.
    let alpha = &uuid_string(&id(1));
    assert_eq!(vault.config(&id(1)).unwrap().as_str(), "remote old-alpha\n");
    assert_eq!(secret(&vault, alpha, SecretField::KeyPassword).as_deref(), Some("old-keypass"));
    // The copy: new id, suffix, the backup's config and secrets, in the copy of Work's Sub.
    let copy = named(&vault, "Alpha (backup)");
    assert_ne!(copy.id, id(1));
    let copy_key = uuid_string(&copy.id);
    assert_eq!(vault.config(&copy.id).unwrap().as_str(), "remote new-alpha\n");
    assert_eq!(secret(&vault, &copy_key, SecretField::KeyPassword).as_deref(), Some("Alpha-keypass"));
    let folders = vault.folders().unwrap();
    assert_eq!(folders.len(), 3);
    let work = folder_named(&folders, "Work");
    let work_copy = folder_named(&folders, "Work (renamed) (backup)");
    assert_eq!(work.id, id(10));
    assert_ne!(work_copy.id, id(10));
    assert_eq!(work_copy.color, Some(FolderColor::Blue));
    // Sub had no conflict, but its parent was copied: it follows the copy.
    assert_eq!(folder_named(&folders, "Sub").parent, Some(work_copy.id));
    let stored = vault.connections().unwrap();
    assert_eq!(stored.iter().find(|c| c.connection.id == copy.id).unwrap().folder_id, Some(id(11)));
    assert_eq!(stored.iter().find(|c| c.connection.name == "Beta").unwrap().folder_id, Some(work_copy.id));
    // Credentials: both conflicts copied with a suffix; the copies' links follow.
    let names: Vec<String> = credential_rows(&vault).into_iter().map(|r| r.1).collect();
    assert_eq!(names, ["Fresh", "Lab", "Lab (backup)", "Office AD", "Office AD (backup)"]);
    let l = links(&vault);
    assert_eq!(l[alpha], uuid_string(&id(100)));
    assert_eq!(l[&copy_key], credential_id_named(&vault, "Office AD (backup)"));
    assert_eq!(l[&uuid_string(&id(2))], credential_id_named(&vault, "Lab (backup)"));
    // The originals keep their values.
    assert!(credential_rows(&vault).contains(&(
        uuid_string(&id(100)),
        "Office AD".into(),
        "old-user".into(),
        Some("old-pass".into())
    )));

    // Again: the names are taken, so the next copies count up.
    backup::merge(&mut vault, &incoming(), ConflictMode::KeepBoth).unwrap();
    assert_eq!(named(&vault, "Alpha (backup 2)").kind, VPNKind::Openvpn);
    assert!(credential_rows(&vault).iter().any(|r| r.1 == "Office AD (backup 2)"));
}

#[test]
fn keep_both_unbinds_a_native_copy_from_the_installed_service() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp, "v");
    let mut native = Connection::with_id(id(5), "Office L2TP", VPNKind::L2tp, now());
    native.native_service_name = Some("Office L2TP".into());
    native.native_service_id = Some("SERVICE-OF-THE-ORIGINAL".into());
    vault.save_connection(&native, Some("")).unwrap();
    let mut p = BackupPayload::empty(now(), "1.2.0", prefs());
    p.connections = vec![BackupConnection {
        connection: native.clone(),
        config: z(""),
        folder_id: None,
        color: None,
        position: 0,
        secrets: vec![(SecretField::Psk, z("psk"))],
    }];
    backup::merge(&mut vault, &p, ConflictMode::KeepBoth).unwrap();
    let copy = named(&vault, "Office L2TP (backup)");
    assert_eq!(copy.native_service_name.as_deref(), Some("Office L2TP (backup)"));
    assert_eq!(copy.native_service_id, None);
    assert_eq!(named(&vault, "Office L2TP").native_service_id.as_deref(), Some("SERVICE-OF-THE-ORIGINAL"));
}

#[test]
fn replace_clears_everything_but_the_paired_clients() {
    let tmp = TempDir::new();
    let mut vault = existing_vault(&tmp);
    let payload = incoming();
    assert_eq!(backup::plan_restore(&vault, &payload).unwrap().lost_on_replace, 2);
    backup::replace(&mut vault, &payload).unwrap();
    assert_eq!(vault.control_clients().unwrap(), vec![client("client-1")]);
    assert_eq!(vault.connection_count().unwrap(), 2);
    assert!(vault.connections().unwrap().iter().all(|c| c.connection.name != "Zulu"));
    assert_eq!(vault.config(&id(1)).unwrap().as_str(), "remote new-alpha\n");
    let names: Vec<String> = credential_rows(&vault).into_iter().map(|r| r.1).collect();
    assert_eq!(names, ["Fresh", "Lab", "Office AD"]);
    assert_eq!(credential_id_named(&vault, "Lab"), uuid_string(&id(101)));
    assert_eq!(vault.ranking().unwrap().pinned(), [uuid_string(&id(2))]);
    let again = backup::collect(&vault, prefs(), now(), "1.2.0").unwrap();
    assert_eq!(again.connections.len(), 2);
    assert_eq!(again.folders, payload.folders);
}

#[test]
fn a_fresh_restore_reproduces_the_backed_up_vault() {
    let tmp = TempDir::new();
    let source = filled_vault(&tmp, "source");
    let original = collect(&source);
    let opened = backup::open(&sealed(&original), PASSWORD).unwrap();
    let mut fresh = new_vault(&tmp, "fresh");
    backup::replace(&mut fresh, &opened).unwrap();
    assert_eq!(collect(&fresh), original);
    // The paired client of the source is not carried over.
    assert!(fresh.control_clients().unwrap().is_empty());
}

#[test]
fn a_failing_restore_changes_nothing() {
    let tmp = TempDir::new();
    let mut vault = existing_vault(&tmp);
    let before = collect(&vault);
    let mut bad = incoming();
    // A folder cycle in the backup: a typed error (review L5), not "the vault is damaged".
    bad.folders[0].parent = Some(id(11));
    let tree = |r: Result<(), VaultError>| matches!(r, Err(VaultError::InvalidBackup(InvalidBackup::FolderTree)));
    assert!(tree(backup::merge(&mut vault, &bad, ConflictMode::Overwrite)));
    assert!(tree(backup::replace(&mut vault, &bad)));
    assert_eq!(collect(&vault), before);
    assert_eq!(vault.control_clients().unwrap(), vec![client("client-1")]);
}

#[test]
fn system_items_unknown_on_this_mac_get_the_retention_timestamp() {
    let mut p = BackupPayload::empty(now(), "1.2.0", prefs());
    let item = |service: &str, missing: Option<Date>| SystemItem {
        service_id: service.into(),
        folder_id: None,
        color: None,
        position: 0,
        missing_since: missing,
    };
    p.system_items = vec![
        item("HERE", Some(date("2026-09-01T00:00:00Z"))),
        item("GONE", None),
        item("GONE-EARLIER", Some(date("2026-10-10T00:00:00Z"))),
    ];
    let known: HashSet<String> = HashSet::from(["HERE".to_string()]);
    backup::mark_missing_system_items(&mut p, &known, now());
    assert_eq!(p.system_items[0].missing_since, None);
    assert_eq!(p.system_items[1].missing_since, Some(now()));
    assert_eq!(p.system_items[2].missing_since, Some(date("2026-10-10T00:00:00Z")));
}

// MARK: - review fixes: untrusted payloads (M1, LM1, LM2)

/// A payload that differs from a valid one in exactly one place, and the kind of refusal it must get.
fn crafted() -> Vec<(&'static str, BackupPayload, InvalidBackup)> {
    let base = || {
        let mut p = BackupPayload::empty(now(), "1.2.0", prefs());
        p.credentials = vec![credential(id(100), "Office AD", "alice", Some("pw"))];
        p.folders = vec![FolderNode {
            id: id(10),
            parent: None,
            name: "Work".into(),
            color: None,
            position: 0,
            collapsed: false,
        }];
        p
    };
    let mut out = Vec::new();
    let mut case = |what: &'static str, kind: InvalidBackup, f: &dyn Fn(&mut BackupPayload)| {
        let mut p = base();
        f(&mut p);
        out.push((what, p, kind));
    };
    // The reviewer's PoC values.
    case(
        "an escape sequence, a line break, bidi and 300 characters in a credential name",
        InvalidBackup::CredentialName,
        &|p| {
            p.credentials[0].name = format!("\u{1b}[31mEvil\n{}\u{202e}", "x".repeat(300));
        },
    );
    case("NUL and CRLF in a credential username", InvalidBackup::CredentialUsername, &|p| {
        p.credentials[0].username = z("user\u{0}\r\nX");
    });
    case("line breaks and 10 000 bytes in a credential password", InvalidBackup::CredentialPassword, &|p| {
        p.credentials[0].password = Some(z(&"p\n".repeat(5000)));
    });
    case("a line break and 500 characters in a folder name", InvalidBackup::FolderName, &|p| {
        p.folders[0].name = format!("bad\n{}", "y".repeat(500));
    });
    case("NUL in a linked item id", InvalidBackup::ItemId, &|p| {
        p.credential_links.push(("weird\u{0}item".into(), id(100)));
    });
    // The other limits.
    case("65 characters in a credential name", InvalidBackup::CredentialName, &|p| {
        p.credentials[0].name = "n".repeat(65)
    });
    case("a credential name not in its stored (trimmed) form", InvalidBackup::CredentialName, &|p| {
        p.credentials[0].name = " Office AD ".into();
    });
    case("257 bytes in a credential username", InvalidBackup::CredentialUsername, &|p| {
        p.credentials[0].username = z(&"u".repeat(257));
    });
    case("1025 bytes in a credential password", InvalidBackup::CredentialPassword, &|p| {
        p.credentials[0].password = Some(z(&"p".repeat(1025)));
    });
    case("an empty folder name", InvalidBackup::FolderName, &|p| p.folders[0].name = "   ".into());
    case("a folder whose parent is not in the backup", InvalidBackup::FolderTree, &|p| {
        p.folders[0].parent = Some(id(77))
    });
    case("two credentials with one name", InvalidBackup::Duplicate, &|p| {
        p.credentials.push(credential(id(101), "Office AD", "bob", None));
    });
    case("two folders with one id", InvalidBackup::Duplicate, &|p| {
        let again = p.folders[0].clone();
        p.folders.push(again);
    });
    case("a line break in a connection's secret", InvalidBackup::Secret, &|p| {
        let mut c = backup_connection(id(1), "Alpha", "remote a\n", None);
        c.secrets = vec![(SecretField::Password, z("pw\nusername=evil"))];
        p.connections.push(c);
    });
    case("a control character in a system VPN's secret", InvalidBackup::Secret, &|p| {
        p.system_secrets.insert("SVC-1".into(), vec![(SecretField::Psk, z("psk\u{85}"))]);
    });
    case("a secret over 64 KiB", InvalidBackup::Secret, &|p| {
        p.system_secrets.insert("SVC-1".into(), vec![(SecretField::Psk, z(&"k".repeat(64 * 1024 + 1)))]);
    });
    case("a control character in a system secret's item id", InvalidBackup::ItemId, &|p| {
        p.system_secrets.insert("SVC\n1".into(), vec![(SecretField::Psk, z("psk"))]);
    });
    case("an empty system item service ID", InvalidBackup::ItemId, &|p| {
        p.system_items.push(SystemItem {
            service_id: String::new(),
            folder_id: None,
            color: None,
            position: 0,
            missing_since: None,
        });
    });
    case("a control character in a system OTP key", InvalidBackup::ItemId, &|p| {
        p.system_otp.insert("SVC\u{7f}".into(), OTPSetting::new(true, OTPSeparator::None));
    });
    case("a 257-byte pin", InvalidBackup::ItemId, &|p| {
        p.ranking = ConnectionRanking::new(vec!["x".repeat(257)], HashMap::new());
    });
    case("an escape sequence in the app version", InvalidBackup::AppVersion, &|p| {
        p.app_version = "1.2\u{1b}[2J".into()
    });
    case("more pins than the cap", InvalidBackup::TooMany(Collection::Pins), &|p| {
        p.ranking = ConnectionRanking::new((0..=MAX_ITEMS).map(|i| format!("PIN-{i}")).collect(), HashMap::new())
    });
    case("more links than the cap", InvalidBackup::TooMany(Collection::CredentialLinks), &|p| {
        p.credential_links = (0..=MAX_ITEMS).map(|i| (format!("ITEM-{i}"), id(100))).collect();
    });
    out
}

#[test]
fn a_crafted_payload_is_refused_on_seal_open_merge_and_replace() {
    let tmp = TempDir::new();
    let mut vault = existing_vault(&tmp);
    let before = collect(&vault);
    for (what, payload, kind) in crafted() {
        assert_eq!(backup::validate(&payload), Err(kind), "{what}");
        assert_eq!(
            backup::seal(&payload, PASSWORD, kdf(), &FixedEntropy::new(5)),
            Err(BackupError::Invalid(kind)),
            "{what}"
        );
        // A file crafted by someone who knows the password.
        let bytes = backup::seal_unchecked(&payload, PASSWORD, kdf(), &FixedEntropy::new(5)).unwrap();
        assert_eq!(backup::open(&bytes, PASSWORD), Err(BackupError::Invalid(kind)), "{what}");
        // And a payload handed to the restore directly.
        for mode in [ConflictMode::Overwrite, ConflictMode::KeepExisting, ConflictMode::KeepBoth] {
            let result = backup::merge(&mut vault, &payload, mode);
            assert!(matches!(result, Err(VaultError::InvalidBackup(k)) if k == kind), "{what} {mode:?}: {result:?}");
        }
        let result = backup::replace(&mut vault, &payload);
        assert!(matches!(result, Err(VaultError::InvalidBackup(k)) if k == kind), "{what} replace: {result:?}");
        // The error names the kind only.
        let text = format!("{} {:?}", BackupError::Invalid(kind), BackupError::Invalid(kind));
        assert!(!text.contains("Evil") && !text.contains("user\u{0}") && !text.contains("weird"), "{text}");
    }
    assert_eq!(collect(&vault), before, "nothing was written");
}

#[test]
fn every_crafted_case_differs_from_a_valid_payload_in_that_place_only() {
    // The base payload of `crafted` is itself valid and restorable, so each refusal above is for its one change.
    let tmp = TempDir::new();
    let mut p = BackupPayload::empty(now(), "1.2.0", prefs());
    p.credentials = vec![credential(id(100), "Office AD", "alice", Some("pw"))];
    p.folders =
        vec![FolderNode { id: id(10), parent: None, name: "Work".into(), color: None, position: 0, collapsed: false }];
    assert_eq!(backup::validate(&p), Ok(()));
    let mut vault = new_vault(&tmp, "v");
    backup::merge(&mut vault, &p, ConflictMode::Overwrite).unwrap();
    // Exactly at the caps is fine.
    p.ranking = ConnectionRanking::new((0..MAX_ITEMS).map(|i| format!("PIN-{i}")).collect(), HashMap::new());
    p.credentials[0].name = "n".repeat(64);
    p.credentials[0].username = z(&"u".repeat(256));
    p.credentials[0].password = Some(z(&"p".repeat(1024)));
    assert_eq!(backup::validate(&p), Ok(()));
}

#[test]
fn keep_both_credential_names_never_exceed_64_characters() {
    let tmp = TempDir::new();
    let mut vault = new_vault(&tmp, "v");
    let long = "n".repeat(64);
    let existing = vault.create_credential(&long, "u", None).unwrap();
    let mut p = BackupPayload::empty(now(), "1.2.0", prefs());
    p.credentials = vec![credential(existing, &long, "u", None)];
    for _ in 0..3 {
        backup::merge(&mut vault, &p, ConflictMode::KeepBoth).unwrap();
    }
    let names: Vec<String> = vault.credentials().unwrap().into_iter().map(|c| c.name).collect();
    assert_eq!(names.len(), 4);
    assert_eq!(names.iter().collect::<HashSet<_>>().len(), 4, "{names:?}");
    for name in &names {
        assert!(name.chars().count() <= 64, "{name}");
        assert_eq!(validate_credential_name(name).unwrap(), *name);
    }
    assert!(names.contains(&format!("{} (backup)", "n".repeat(55))));
    assert!(names.contains(&format!("{} (backup 3)", "n".repeat(53))));
    // A restored credential can still be edited like any other.
    let copy = vault.credentials().unwrap().into_iter().find(|c| c.name.ends_with("(backup)")).unwrap();
    vault.update_credential(copy.id, None, Some("ok"), None).unwrap();
}

#[test]
fn a_header_above_the_backup_kdf_ceiling_cannot_open_and_the_kdf_never_runs() {
    let bytes = sealed(&BackupPayload::empty(now(), "1.2.0", prefs()));
    let with = |m_kib: u32, t: u32, p: u32| {
        let mut b = bytes.clone();
        b[12..16].copy_from_slice(&m_kib.to_be_bytes());
        b[16..20].copy_from_slice(&t.to_be_bytes());
        b[20..24].copy_from_slice(&p.to_be_bytes());
        b
    };
    // Each within the vault's own ceiling (1 GiB, 256, 16) but above the backup's: running the KDF with any of
    // them would take far longer than the bound below.
    for (m, t, p) in
        [(MAX_KDF.m_kib + 1, 3, 1), (256 * 1024, MAX_KDF.t + 1, 1), (1024 * 1024, 256, 16), (65536, 3, MAX_KDF.p + 1)]
    {
        let started = std::time::Instant::now();
        assert_cannot_open(&with(m, t, p), PASSWORD, &format!("m={m} t={t} p={p}"));
        assert!(started.elapsed() < std::time::Duration::from_secs(2), "the KDF ran for m={m} t={t} p={p}");
    }
    assert_eq!(MAX_KDF, KdfParams { m_kib: 256 * 1024, t: 64, p: 4 });
    // Sealing above the ceiling is refused too (the file could not be opened).
    let above = KdfParams { m_kib: 65536, t: MAX_KDF.t + 1, p: 1 };
    assert!(matches!(
        backup::seal(&BackupPayload::empty(now(), "1.2.0", prefs()), PASSWORD, above, &FixedEntropy::new(5)),
        Err(BackupError::Io(_))
    ));
}

#[test]
fn read_backup_file_reads_only_a_regular_file_within_the_cap() {
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path()).unwrap();
    let bytes = sealed(&BackupPayload::empty(now(), "1.2.0", prefs()));
    let file = tmp.path().join("b.macvpnbackup");
    backup::write_backup(&file, &bytes).unwrap();
    assert_eq!(backup::read_backup_file(&file).unwrap(), bytes);

    let link = tmp.path().join("link.macvpnbackup");
    std::os::unix::fs::symlink(&file, &link).unwrap();
    assert!(matches!(backup::read_backup_file(&link), Err(BackupError::Io(_))), "a symlink is not followed");
    assert!(matches!(backup::read_backup_file(tmp.path()), Err(BackupError::Io(_))), "a directory");
    let fifo = tmp.path().join("fifo.macvpnbackup");
    assert!(std::process::Command::new("/usr/bin/mkfifo").arg(&fifo).status().unwrap().success());
    assert!(matches!(backup::read_backup_file(&fifo), Err(BackupError::Io(_))), "a FIFO, without blocking");
    assert!(matches!(backup::read_backup_file(&tmp.path().join("missing")), Err(BackupError::Io(_))));

    // A (sparse) file one byte over the cap.
    let big = tmp.path().join("big.macvpnbackup");
    fs::File::create(&big).unwrap().set_len(MAX_BACKUP_BYTES as u64 + 1).unwrap();
    assert_eq!(backup::read_backup_file(&big), Err(BackupError::TooLarge));
}

// MARK: - review fixes: the link invariant (M2)

fn own_login(vault: &Vault, item: &str) -> (Option<String>, Option<String>) {
    (secret(vault, item, SecretField::Username), secret(vault, item, SecretField::Password))
}

#[test]
fn a_restored_link_leaves_the_item_no_own_username_or_password() {
    // The PoC: a system VPN with its own username and password **and** a link, and a connection likewise.
    let mut p = BackupPayload::empty(now(), "1.2.0", prefs());
    p.credentials = vec![credential(id(100), "Office AD", "alice", Some("shared"))];
    p.system_secrets = BTreeMap::from([(
        "SVC-1".to_string(),
        vec![(SecretField::Username, z("own")), (SecretField::Password, z("ownpw")), (SecretField::Psk, z("psk"))],
    )]);
    let mut c = backup_connection(id(1), "Alpha", "remote a\n", None);
    c.secrets = vec![(SecretField::Username, z("own")), (SecretField::Password, z("ownpw"))];
    p.connections = vec![c];
    p.credential_links = vec![(uuid_string(&id(1)), id(100)), ("SVC-1".into(), id(100))];
    for restore in ["replace", "Overwrite", "KeepExisting", "KeepBoth"] {
        let tmp = TempDir::new();
        let mut vault = new_vault(&tmp, "v");
        match restore {
            "replace" => backup::replace(&mut vault, &p).unwrap(),
            "Overwrite" => backup::merge(&mut vault, &p, ConflictMode::Overwrite).unwrap(),
            "KeepExisting" => backup::merge(&mut vault, &p, ConflictMode::KeepExisting).unwrap(),
            _ => backup::merge(&mut vault, &p, ConflictMode::KeepBoth).unwrap(),
        }
        for item in ["SVC-1".to_string(), uuid_string(&id(1))] {
            assert_eq!(vault.credential_of(&item).unwrap(), Some(id(100)), "{restore} {item}");
            assert_eq!(own_login(&vault, &item), (None, None), "{restore} {item}");
            assert_eq!(vault.resolved_secret(&item, SecretField::Password).unwrap().unwrap().as_str(), "shared");
        }
        assert_eq!(secret(&vault, "SVC-1", SecretField::Psk).as_deref(), Some("psk"), "{restore}: the PSK stays");
    }
}

#[test]
fn an_overwrite_merge_onto_an_already_linked_system_vpn_keeps_the_invariant() {
    // The vault: SVC-1 linked to a shared credential. The backup (made while SVC-1 used its own fields): SVC-1's
    // own username and password, no link.
    let setup = |tmp: &TempDir| {
        let mut vault = new_vault(tmp, "v");
        let shared = vault.create_credential("Office AD", "alice", Some("shared")).unwrap();
        vault.link("SVC-1", shared).unwrap();
        vault.link("SVC-2", shared).unwrap();
        (vault, shared)
    };
    let mut p = BackupPayload::empty(now(), "1.2.0", prefs());
    p.system_secrets = BTreeMap::from([(
        "SVC-1".to_string(),
        vec![(SecretField::Username, z("own")), (SecretField::Password, z("ownpw"))],
    )]);

    // Overwrite: the backup's copy (own fields, no link) replaces the item's secrets and link together.
    let tmp = TempDir::new();
    let (mut vault, shared) = setup(&tmp);
    backup::merge(&mut vault, &p, ConflictMode::Overwrite).unwrap();
    assert_eq!(vault.credential_of("SVC-1").unwrap(), None);
    assert_eq!(own_login(&vault, "SVC-1"), (Some("own".into()), Some("ownpw".into())));
    // The shared credential and its other item are untouched.
    assert_eq!(vault.credential_of("SVC-2").unwrap(), Some(shared));
    assert_eq!(vault.credential_password(shared).unwrap().unwrap().as_str(), "shared");

    // Overwrite with a backup that also links SVC-1: linked, and no own username or password survives.
    let tmp = TempDir::new();
    let (mut vault, shared) = setup(&tmp);
    let mut linked = p.clone();
    linked.credentials = vec![credential(shared, "Office AD", "alice", Some("shared"))];
    linked.credential_links = vec![("SVC-1".into(), shared)];
    backup::merge(&mut vault, &linked, ConflictMode::Overwrite).unwrap();
    assert_eq!(vault.credential_of("SVC-1").unwrap(), Some(shared));
    assert_eq!(own_login(&vault, "SVC-1"), (None, None));

    // Keep existing: the link stays, and the backup's own fields are not added next to it.
    for mode in [ConflictMode::KeepExisting, ConflictMode::KeepBoth] {
        let tmp = TempDir::new();
        let (mut vault, shared) = setup(&tmp);
        backup::merge(&mut vault, &p, mode).unwrap();
        assert_eq!(vault.credential_of("SVC-1").unwrap(), Some(shared), "{mode:?}");
        assert_eq!(own_login(&vault, "SVC-1"), (None, None), "{mode:?}");
    }
}

#[test]
fn without_overwrite_a_link_is_not_added_to_an_item_with_its_own_login() {
    let mut p = BackupPayload::empty(now(), "1.2.0", prefs());
    p.credentials = vec![credential(id(100), "Office AD", "alice", Some("shared"))];
    p.credential_links = vec![("SVC-1".into(), id(100))];
    let setup = |tmp: &TempDir| {
        let mut vault = new_vault(tmp, "v");
        vault.set_secret("SVC-1", SecretField::Username, "mine").unwrap();
        vault.set_secret("SVC-1", SecretField::Password, "minepw").unwrap();
        vault
    };
    for mode in [ConflictMode::KeepExisting, ConflictMode::KeepBoth] {
        let tmp = TempDir::new();
        let mut vault = setup(&tmp);
        backup::merge(&mut vault, &p, mode).unwrap();
        assert_eq!(vault.credential_of("SVC-1").unwrap(), None, "{mode:?}");
        assert_eq!(own_login(&vault, "SVC-1"), (Some("mine".into()), Some("minepw".into())), "{mode:?}");
    }
    let tmp = TempDir::new();
    let mut vault = setup(&tmp);
    backup::merge(&mut vault, &p, ConflictMode::Overwrite).unwrap();
    assert_eq!(vault.credential_of("SVC-1").unwrap(), Some(id(100)));
    assert_eq!(own_login(&vault, "SVC-1"), (None, None));
}

// MARK: - review fixes: acknowledged risky directives (LM3)

fn risky(uuid: Uuid, name: &str, config: &str) -> BackupConnection {
    let mut c = backup_connection(uuid, name, config, None);
    c.connection.acknowledged_risky_directives = vec!["up".into()];
    c
}

fn acknowledged(vault: &Vault, name: &str) -> Vec<String> {
    named(vault, name).acknowledged_risky_directives
}

#[test]
fn a_merge_keeps_acknowledged_risky_directives_only_for_the_same_connection_and_config() {
    let setup = |tmp: &TempDir| {
        let mut vault = new_vault(tmp, "v");
        let mut same = connection(id(1), "Same");
        same.acknowledged_risky_directives = vec!["up".into()];
        vault.save_connection(&same, Some("remote a\nup /x\n")).unwrap();
        vault.save_connection(&connection(id(2), "Changed"), Some("remote b\n")).unwrap();
        vault
    };
    let mut p = BackupPayload::empty(now(), "1.2.0", prefs());
    p.connections = vec![
        risky(id(1), "Same", "remote a\nup /x\n"),
        risky(id(2), "Changed", "remote b\nup /evil\n"),
        risky(id(3), "New", "remote c\nup /evil\n"),
    ];

    let tmp = TempDir::new();
    let mut vault = setup(&tmp);
    backup::merge(&mut vault, &p, ConflictMode::Overwrite).unwrap();
    assert_eq!(acknowledged(&vault, "Same"), ["up"]);
    assert!(acknowledged(&vault, "Changed").is_empty(), "another config: the editor asks again");
    assert!(acknowledged(&vault, "New").is_empty(), "a new connection: the editor asks again");

    let tmp = TempDir::new();
    let mut vault = setup(&tmp);
    backup::merge(&mut vault, &p, ConflictMode::KeepBoth).unwrap();
    assert_eq!(acknowledged(&vault, "Same (backup)"), ["up"]);
    assert!(acknowledged(&vault, "Changed (backup)").is_empty());
    assert!(acknowledged(&vault, "New").is_empty());

    // Replace (and a fresh restore) keeps them all, and the plan lists them for the restore window.
    let tmp = TempDir::new();
    let mut vault = setup(&tmp);
    let plan = backup::plan_restore(&vault, &p).unwrap();
    assert_eq!(plan.acknowledged_risky, ["Same", "Changed", "New"]);
    backup::replace(&mut vault, &p).unwrap();
    for name in ["Same", "Changed", "New"] {
        assert_eq!(acknowledged(&vault, name), ["up"], "{name}");
    }
}
