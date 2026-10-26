//! The vault repositories for the ranking and pins, the system OTP settings, the system-VPN placement and the
//! paired control clients (plan B Task 8). Every write goes through the vault's transaction API.

mod common;

use common::TempDir;
use macvpn_core::date::Date;
use macvpn_core::models::{OTPSeparator, OTPSetting, uuid_string};
use macvpn_core::ranking::{ConnectionRanking, ConnectionRankingStore, UsageStats};
use macvpn_core::swift_json;
use macvpn_core::system_otp::SystemOTPStore;
use macvpn_core::vault::{Dek, FixedEntropy, FolderColor, SystemItem, Vault, VaultError};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

fn dek() -> Dek {
    Dek::generate(&FixedEntropy::new(8)).unwrap()
}

fn new_vault(tmp: &TempDir) -> (PathBuf, Vault) {
    fs::create_dir_all(tmp.path()).unwrap();
    let dir = tmp.path().join("MacVPN");
    let vault = Vault::create(&dir, &dek()).unwrap();
    (dir, vault)
}

fn reopen(dir: &Path, vault: Vault) -> Vault {
    vault.close();
    Vault::open(dir, &dek()).unwrap()
}

/// Marks the database as written by a newer MacVPN and reopens it: read-only.
fn reopen_as_newer(dir: &Path, mut vault: Vault) -> Vault {
    vault
        .transaction(|tx| {
            tx.execute_batch(
                "UPDATE meta SET value = '99' WHERE key = 'schema_version';
                 UPDATE meta SET value = '99' WHERE key = 'min_app_schema';",
            )?;
            Ok(())
        })
        .unwrap();
    vault.close();
    let vault = Vault::open(dir, &dek()).unwrap();
    assert!(vault.is_read_only());
    vault
}

fn assert_newer<T: std::fmt::Debug>(r: Result<T, VaultError>) {
    assert!(matches!(r, Err(VaultError::NewerSchema { db: 99, app: 2 })), "{r:?}");
}

fn date(s: &str) -> Date {
    Date::parse_iso8601(s).unwrap()
}

fn swift_fixture(dir: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/swift").join(dir).join(name)
}

fn rows(vault: &Vault, sql: &str) -> Vec<(String, String)> {
    let mut stmt = vault.connection().prepare(sql).unwrap();
    stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).unwrap().map(Result::unwrap).collect()
}

// --- Ranking and pins -------------------------------------------------------------------------------------------

fn sample_ranking() -> ConnectionRanking {
    let mut usage = HashMap::new();
    usage.insert(
        "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0".to_string(),
        UsageStats { score: 2.718_281_828_459_1, last_updated: date("2026-10-01T12:34:56Z") },
    );
    usage.insert("SERVICE-ID-1".to_string(), UsageStats { score: 0.1, last_updated: date("2025-01-02T03:04:05Z") });
    usage.insert("pinned-unused".to_string(), UsageStats { score: 1.0, last_updated: date("2026-10-19T00:00:00Z") });
    ConnectionRanking::new(vec!["SERVICE-ID-1".into(), "pinned-unused".into(), "never-used".into()], usage)
}

#[test]
fn ranking_round_trips_with_pin_order_scores_and_dates() {
    let tmp = TempDir::new();
    let (dir, mut vault) = new_vault(&tmp);
    assert_eq!(vault.ranking().unwrap(), ConnectionRanking::default(), "an empty vault has an empty ranking");
    let ranking = sample_ranking();
    vault.save_ranking(&ranking).unwrap();
    let vault = reopen(&dir, vault);
    let back = vault.ranking().unwrap();
    assert_eq!(back, ranking);
    assert_eq!(back.pinned(), ["SERVICE-ID-1", "pinned-unused", "never-used"]);
    assert_eq!(back.usage()["SERVICE-ID-1"].last_updated, date("2025-01-02T03:04:05Z"));
    assert_eq!(
        rows(&vault, "SELECT id, CAST(position AS TEXT) FROM pins ORDER BY position"),
        [("SERVICE-ID-1", "0"), ("pinned-unused", "1"), ("never-used", "2")]
            .map(|(a, b)| (a.to_string(), b.to_string()))
    );
}

#[test]
fn a_ranking_row_is_the_usage_entry_of_connection_order_json() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    vault.save_ranking(&sample_ranking()).unwrap();
    let whole = sample_ranking().to_json().unwrap();
    for (id, json) in rows(&vault, "SELECT id, json FROM ranking") {
        // The exact text the file writer produces for this entry (numbers compared as text, not as JSON values,
        // where `1` and `1.0` differ).
        assert_eq!(json, swift_json::to_compact_sorted(&whole["usage"][&id]).unwrap(), "{id}");
    }
}

#[test]
fn the_swift_written_ranking_files_survive_the_vault_byte_for_byte() {
    for name in ["recorded.json", "numbers.json", "empty.json"] {
        let path = swift_fixture("connection-order", name);
        let text = fs::read_to_string(&path).unwrap();
        let ranking = ConnectionRankingStore::new(&path).load();
        let tmp = TempDir::new();
        let (_dir, mut vault) = new_vault(&tmp);
        vault.save_ranking(&ranking).unwrap();
        let back = vault.ranking().unwrap();
        assert_eq!(back, ranking, "{name}");
        assert_eq!(swift_json::to_pretty_sorted(&back.to_json().unwrap()).unwrap(), text, "{name}");
    }
}

#[test]
fn saving_the_ranking_replaces_both_tables() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    vault.save_ranking(&sample_ranking()).unwrap();
    let smaller = ConnectionRanking::new(
        vec!["only".into()],
        HashMap::from([("only".to_string(), UsageStats { score: 3.0, last_updated: date("2026-10-19T08:00:00Z") })]),
    );
    vault.save_ranking(&smaller).unwrap();
    assert_eq!(vault.ranking().unwrap(), smaller);
    assert_eq!(rows(&vault, "SELECT id, json FROM ranking").len(), 1);
    assert_eq!(rows(&vault, "SELECT id, CAST(position AS TEXT) FROM pins").len(), 1);
}

#[test]
fn a_ranking_with_a_non_finite_score_is_refused_and_nothing_changes() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    vault.save_ranking(&sample_ranking()).unwrap();
    let bad = ConnectionRanking::new(
        vec![],
        HashMap::from([("x".to_string(), UsageStats { score: f64::NAN, last_updated: date("2026-10-19T08:00:00Z") })]),
    );
    assert!(vault.save_ranking(&bad).is_err());
    assert_eq!(vault.ranking().unwrap(), sample_ranking());
}

#[test]
fn an_undecodable_ranking_row_is_skipped() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    vault.save_ranking(&sample_ranking()).unwrap();
    vault
        .transaction(|tx| {
            tx.execute("INSERT INTO ranking(id, json) VALUES ('broken', '{\"score\":\"high\"}')", ())?;
            tx.execute("INSERT INTO ranking(id, json) VALUES ('garbage', 'not json')", ())?;
            Ok(())
        })
        .unwrap();
    assert_eq!(vault.ranking().unwrap(), sample_ranking());
}

#[test]
fn ranking_writes_are_refused_on_a_newer_database() {
    let tmp = TempDir::new();
    let (dir, mut vault) = new_vault(&tmp);
    vault.save_ranking(&sample_ranking()).unwrap();
    let mut vault = reopen_as_newer(&dir, vault);
    assert_eq!(vault.ranking().unwrap(), sample_ranking());
    assert_newer(vault.save_ranking(&ConnectionRanking::default()));
    assert_eq!(vault.ranking().unwrap(), sample_ranking());
}

// --- System OTP -------------------------------------------------------------------------------------------------

fn sample_otp() -> HashMap<String, OTPSetting> {
    HashMap::from([
        ("SERVICE-A".to_string(), OTPSetting::new(true, OTPSeparator::None)),
        ("SERVICE-B".to_string(), OTPSetting::new(true, OTPSeparator::Comma)),
    ])
}

#[test]
fn system_otp_round_trips() {
    let tmp = TempDir::new();
    let (dir, mut vault) = new_vault(&tmp);
    assert!(vault.system_otp_map().unwrap().is_empty());
    vault.save_system_otp_map(&sample_otp()).unwrap();
    let vault = reopen(&dir, vault);
    assert_eq!(vault.system_otp_map().unwrap(), sample_otp());
    for (id, json) in rows(&vault, "SELECT service_id, json FROM system_otp") {
        assert_eq!(json, swift_json::to_compact_sorted(&sample_otp()[&id].to_json()).unwrap());
    }
}

#[test]
fn system_otp_keeps_only_enabled_entries_and_replaces_the_table() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    vault.save_system_otp_map(&sample_otp()).unwrap();
    let mut map = HashMap::from([("SERVICE-C".to_string(), OTPSetting::new(true, OTPSeparator::None))]);
    map.insert("SERVICE-OFF".to_string(), OTPSetting::new(false, OTPSeparator::None));
    vault.save_system_otp_map(&map).unwrap();
    map.remove("SERVICE-OFF");
    assert_eq!(vault.system_otp_map().unwrap(), map, "like system-otp.json: disabled entries are not stored");
}

#[test]
fn the_swift_written_system_otp_file_survives_the_vault() {
    let path = swift_fixture("system-otp", "saved.json");
    let map = SystemOTPStore::new(&path).load();
    assert!(!map.is_empty());
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    vault.save_system_otp_map(&map).unwrap();
    assert_eq!(vault.system_otp_map().unwrap(), map);
}

#[test]
fn system_otp_writes_are_refused_on_a_newer_database() {
    let tmp = TempDir::new();
    let (dir, mut vault) = new_vault(&tmp);
    vault.save_system_otp_map(&sample_otp()).unwrap();
    let mut vault = reopen_as_newer(&dir, vault);
    assert_eq!(vault.system_otp_map().unwrap(), sample_otp());
    assert_newer(vault.save_system_otp_map(&HashMap::new()));
}

// --- System items -----------------------------------------------------------------------------------------------

fn item(service_id: &str) -> SystemItem {
    SystemItem { service_id: service_id.into(), folder_id: None, color: None, position: 0, missing_since: None }
}

#[test]
fn system_items_upsert_and_delete() {
    let tmp = TempDir::new();
    let (dir, mut vault) = new_vault(&tmp);
    assert!(vault.system_items().unwrap().is_empty());
    let folder = Uuid::new_v4();
    let a = SystemItem { folder_id: Some(folder), color: Some(FolderColor::Indigo), position: 3, ..item("SERVICE-A") };
    let b = item("SERVICE-B");
    vault.save_system_item(&a).unwrap();
    vault.save_system_item(&b).unwrap();
    let mut vault = reopen(&dir, vault);
    assert_eq!(vault.system_items().unwrap(), [a.clone(), b.clone()]);
    let folder_column: String = vault
        .connection()
        .query_row("SELECT folder_id FROM system_items WHERE service_id = 'SERVICE-A'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(folder_column, uuid_string(&folder));

    // Upsert: the same service ID replaces the row.
    let moved = SystemItem { folder_id: None, color: None, position: 0, ..a.clone() };
    vault.save_system_item(&moved).unwrap();
    assert_eq!(vault.system_items().unwrap(), [moved, b.clone()]);

    vault.delete_system_item("SERVICE-A").unwrap();
    assert_eq!(vault.system_items().unwrap(), [b]);
    vault.delete_system_item("SERVICE-A").unwrap();
}

#[test]
fn missing_since_is_stored_and_cleared() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    let gone = SystemItem { missing_since: Some(date("2026-10-01T09:30:00Z")), ..item("SERVICE-GONE") };
    vault.save_system_item(&gone).unwrap();
    assert_eq!(vault.system_items().unwrap(), std::slice::from_ref(&gone));
    let stored: String =
        vault.connection().query_row("SELECT missing_since FROM system_items", [], |r| r.get(0)).unwrap();
    assert_eq!(stored, "2026-10-01T09:30:00Z");
    // It reappeared.
    let back = SystemItem { missing_since: None, ..gone };
    vault.save_system_item(&back).unwrap();
    assert_eq!(vault.system_items().unwrap(), [back]);
}

#[test]
fn unknown_stored_values_of_a_system_item_read_as_none() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    vault
        .transaction(|tx| {
            tx.execute(
                "INSERT INTO system_items(service_id, folder_id, color, position, missing_since)
                 VALUES ('S', 'not-a-uuid', 'mauve', 4, 'yesterday')",
                (),
            )?;
            Ok(())
        })
        .unwrap();
    assert_eq!(vault.system_items().unwrap(), [SystemItem { position: 4, ..item("S") }]);
}

#[test]
fn system_item_writes_are_refused_on_a_newer_database() {
    let tmp = TempDir::new();
    let (dir, mut vault) = new_vault(&tmp);
    vault.save_system_item(&item("SERVICE-A")).unwrap();
    let mut vault = reopen_as_newer(&dir, vault);
    assert_eq!(vault.system_items().unwrap(), [item("SERVICE-A")]);
    assert_newer(vault.save_system_item(&item("SERVICE-B")));
    assert_newer(vault.delete_system_item("SERVICE-A"));
    assert_eq!(vault.system_items().unwrap(), [item("SERVICE-A")]);
}

// --- Control clients --------------------------------------------------------------------------------------------

/// The shape `PairedClient::to_json` writes into `control-clients.json` (the control API).
fn client(id: &str, name: &str) -> Value {
    json!({
        "id": id,
        "name": name,
        "tokenSha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
        "executable": "/Applications/Example.app/Contents/MacOS/Example",
        "allowed": ["0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0", "SERVICE-ID-1"],
        "created": "2026-10-19T08:00:00Z",
        "lastUsed": "2026-10-19T09:00:00Z"
    })
}

#[test]
fn control_clients_round_trip_in_order() {
    let tmp = TempDir::new();
    let (dir, mut vault) = new_vault(&tmp);
    assert!(vault.control_clients().unwrap().is_empty());
    let clients = vec![
        client("E2B1A5C4-0000-4000-8000-000000000002", "Second"),
        client("11111111-0000-4000-8000-000000000001", "First"),
    ];
    vault.save_control_clients(&clients).unwrap();
    let mut vault = reopen(&dir, vault);
    assert_eq!(vault.control_clients().unwrap(), clients, "the registry's order is kept");
    let stored = rows(&vault, "SELECT id, json FROM control_clients ORDER BY rowid");
    assert_eq!(stored[0].0, "E2B1A5C4-0000-4000-8000-000000000002");
    assert_eq!(stored[0].1, swift_json::to_compact_sorted(&clients[0]).unwrap());

    // Saving replaces the table.
    vault.save_control_clients(&clients[1..]).unwrap();
    assert_eq!(vault.control_clients().unwrap(), &clients[1..]);
    vault.save_control_clients(&[]).unwrap();
    assert!(vault.control_clients().unwrap().is_empty());
}

#[test]
fn a_control_client_without_an_id_is_refused_and_nothing_changes() {
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    let kept = vec![client("11111111-0000-4000-8000-000000000001", "First")];
    vault.save_control_clients(&kept).unwrap();
    let r = vault.save_control_clients(&[client("A", "ok"), json!({"name": "no id"})]);
    assert!(matches!(r, Err(VaultError::Constraint(_))), "{r:?}");
    assert_eq!(vault.control_clients().unwrap(), kept);
}

#[test]
fn an_unreadable_control_client_row_is_an_error_not_an_empty_registry() {
    // An empty registry would be saved over the real one at the next change and unpair every client.
    let tmp = TempDir::new();
    let (_dir, mut vault) = new_vault(&tmp);
    vault
        .transaction(|tx| {
            tx.execute("INSERT INTO control_clients(id, json) VALUES ('X', 'not json')", ())?;
            Ok(())
        })
        .unwrap();
    let r = vault.control_clients();
    assert!(matches!(r, Err(VaultError::Corrupt(_))), "{r:?}");
}

#[test]
fn control_client_writes_are_refused_on_a_newer_database() {
    let tmp = TempDir::new();
    let (dir, mut vault) = new_vault(&tmp);
    let clients = vec![client("11111111-0000-4000-8000-000000000001", "First")];
    vault.save_control_clients(&clients).unwrap();
    let mut vault = reopen_as_newer(&dir, vault);
    assert_eq!(vault.control_clients().unwrap(), clients);
    assert_newer(vault.save_control_clients(&[]));
    assert_eq!(vault.control_clients().unwrap(), clients);
}
