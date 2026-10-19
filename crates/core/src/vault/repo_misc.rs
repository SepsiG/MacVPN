//! The smaller tables (spec 2.4): `ranking` and `pins` (today's `connection-order.json`), `system_otp`
//! (`system-otp.json`), `system_items` (the placement of the system VPNs) and `control_clients`
//! (`control-clients.json`).
//!
//! The JSON columns hold exactly the pieces of today's files, written with the Swift-compatible writer
//! (`swift_json::to_compact_sorted`) and read back with the existing model decoders, so nothing about the formats
//! changes. Every write runs in [`Vault::transaction`] (a database of a newer MacVPN refuses it with
//! [`VaultError::NewerSchema`]); the `save_*` methods of whole collections replace their tables in one transaction.

use super::color::FolderColor;
use super::db::{Tx, Vault, VaultError};
use crate::date::Date;
use crate::models::{OTPSetting, parse_uuid, uuid_string};
use crate::ranking::ConnectionRanking;
use crate::swift_json;
use serde_json::{Map, Value};
use std::collections::HashMap;
use uuid::Uuid;

/// Where a system VPN (scutil service ID) sits in the list. `missing_since` is set while the service is not
/// installed, so its placement is kept for 30 days (spec 5).
#[derive(Debug, Clone, PartialEq)]
pub struct SystemItem {
    pub service_id: String,
    pub folder_id: Option<Uuid>,
    pub color: Option<FolderColor>,
    pub position: i64,
    pub missing_since: Option<Date>,
}

fn encode(value: &Value) -> Result<String, VaultError> {
    swift_json::to_compact_sorted(value).map_err(VaultError::Constraint)
}

impl Vault {
    /// The pins (in pin order) and the usage scores. A usage row this build cannot decode is skipped (losing a
    /// score only changes the order, as an unreadable `connection-order.json` does today).
    pub fn ranking(&self) -> Result<ConnectionRanking, VaultError> {
        let conn = self.connection();
        let pinned = {
            let mut stmt = conn.prepare("SELECT id FROM pins ORDER BY position, rowid")?;
            stmt.query_map([], |r| r.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()?
        };
        let mut usage = HashMap::new();
        let mut stmt = conn.prepare("SELECT id, json FROM ranking ORDER BY rowid")?;
        for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
            let (id, json) = row?;
            let Ok(entry) = swift_json::parse(json.as_bytes()) else { continue };
            // The entry is decoded by the ranking's own decoder, wrapped as a one-entry `connection-order.json`.
            let mut one = Map::new();
            one.insert(id.clone(), entry);
            let mut file = Map::new();
            file.insert("pinned".into(), Value::Array(Vec::new()));
            file.insert("usage".into(), Value::Object(one));
            if let Some(stats) =
                ConnectionRanking::from_json(&Value::Object(file)).ok().and_then(|r| r.usage().get(&id).copied())
            {
                usage.insert(id, stats);
            }
        }
        Ok(ConnectionRanking::new(pinned, usage))
    }

    /// Replaces the `ranking` and `pins` tables: one row per usage entry (its JSON as in `connection-order.json`),
    /// and the pins with `position` 0..n. A non-finite score is refused (as the file writer refuses it).
    pub fn save_ranking(&mut self, r: &ConnectionRanking) -> Result<(), VaultError> {
        self.transaction(|tx| tx.save_ranking(r))
    }

    /// The system VPNs' OTP settings by service ID. A row this build cannot decode is skipped.
    pub fn system_otp_map(&self) -> Result<HashMap<String, OTPSetting>, VaultError> {
        let mut stmt = self.connection().prepare("SELECT service_id, json FROM system_otp")?;
        let mut out = HashMap::new();
        for row in stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))? {
            let (id, json) = row?;
            let Ok(value) = swift_json::parse(json.as_bytes()) else { continue };
            if let Ok(setting) = OTPSetting::from_json(&value) {
                out.insert(id, setting);
            }
        }
        Ok(out)
    }

    /// Replaces the `system_otp` table. Only the enabled entries are stored, as in `system-otp.json`.
    pub fn save_system_otp_map(&mut self, map: &HashMap<String, OTPSetting>) -> Result<(), VaultError> {
        self.transaction(|tx| tx.save_system_otp_map(map))
    }

    /// Every stored system-VPN placement, by service ID. A folder ID, colour or date this build cannot read
    /// (written by a newer version) reads as `None`.
    pub fn system_items(&self) -> Result<Vec<SystemItem>, VaultError> {
        let mut stmt = self.connection().prepare(
            "SELECT service_id, folder_id, color, position, missing_since FROM system_items ORDER BY service_id",
        )?;
        let rows = stmt.query_map([], |r| {
            let folder: Option<String> = r.get(1)?;
            let color: Option<String> = r.get(2)?;
            let missing: Option<String> = r.get(4)?;
            Ok(SystemItem {
                service_id: r.get(0)?,
                folder_id: folder.as_deref().and_then(parse_uuid),
                color: color.as_deref().and_then(FolderColor::parse),
                position: r.get(3)?,
                missing_since: missing.as_deref().and_then(Date::parse_iso8601),
            })
        })?;
        Ok(rows.collect::<Result<Vec<_>, _>>()?)
    }

    /// Inserts or replaces the placement of one system VPN.
    pub fn save_system_item(&mut self, item: &SystemItem) -> Result<(), VaultError> {
        self.transaction(|tx| {
            tx.execute(
                "INSERT INTO system_items(service_id, folder_id, color, position, missing_since)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(service_id) DO UPDATE SET
                     folder_id = excluded.folder_id,
                     color = excluded.color,
                     position = excluded.position,
                     missing_since = excluded.missing_since",
                (
                    &item.service_id,
                    item.folder_id.as_ref().map(uuid_string),
                    item.color.map(FolderColor::as_str),
                    item.position,
                    item.missing_since.map(Date::iso8601),
                ),
            )?;
            Ok(())
        })
    }

    /// Removes the placement of one system VPN (deleting a missing one is not an error).
    pub fn delete_system_item(&mut self, service_id: &str) -> Result<(), VaultError> {
        self.transaction(|tx| {
            tx.execute("DELETE FROM system_items WHERE service_id = ?1", [service_id])?;
            Ok(())
        })
    }

    /// The paired control-API clients, in the order they were saved: each the JSON object the registry writes
    /// for one client (`PairedClient::to_json`, with the token's SHA-256, never the token). A row that is not JSON
    /// is an error, not a skipped client: an incomplete registry would be saved back over the real one at the
    /// next change and silently unpair clients.
    pub fn control_clients(&self) -> Result<Vec<Value>, VaultError> {
        let mut stmt = self.connection().prepare("SELECT json FROM control_clients ORDER BY rowid")?;
        let mut out = Vec::new();
        for row in stmt.query_map([], |r| r.get::<_, String>(0))? {
            let json = row?;
            let value = swift_json::parse(json.as_bytes())
                .map_err(|_| VaultError::Corrupt("a paired control client is not valid JSON".into()))?;
            out.push(value);
        }
        Ok(out)
    }

    /// Replaces the `control_clients` table, keeping the order. Each client must be a JSON object with a string
    /// `id` (the row key).
    pub fn save_control_clients(&mut self, clients: &[Value]) -> Result<(), VaultError> {
        self.transaction(|tx| tx.save_control_clients(clients))
    }
}

/// The same writes inside a caller's transaction, so several of them commit together (the migration).
impl Tx<'_> {
    /// [`Vault::save_ranking`] inside this transaction.
    pub fn save_ranking(&self, r: &ConnectionRanking) -> Result<(), VaultError> {
        let whole = r.to_json().map_err(VaultError::Constraint)?;
        let mut entries = Vec::new();
        if let Some(usage) = whole.get("usage").and_then(Value::as_object) {
            for (id, entry) in usage {
                entries.push((id.clone(), encode(entry)?));
            }
        }
        self.execute("DELETE FROM ranking", ())?;
        self.execute("DELETE FROM pins", ())?;
        for (id, json) in &entries {
            self.execute("INSERT INTO ranking(id, json) VALUES (?1, ?2)", (id, json))?;
        }
        for (position, id) in r.pinned().iter().enumerate() {
            self.execute("INSERT INTO pins(id, position) VALUES (?1, ?2)", (id, position as i64))?;
        }
        Ok(())
    }

    /// [`Vault::save_system_otp_map`] inside this transaction.
    pub fn save_system_otp_map(&self, map: &HashMap<String, OTPSetting>) -> Result<(), VaultError> {
        let rows: Vec<(&String, String)> = map
            .iter()
            .filter(|(_, s)| s.enabled)
            .map(|(id, s)| Ok((id, encode(&s.to_json())?)))
            .collect::<Result<_, VaultError>>()?;
        self.execute("DELETE FROM system_otp", ())?;
        for (id, json) in &rows {
            self.execute("INSERT INTO system_otp(service_id, json) VALUES (?1, ?2)", (id, json))?;
        }
        Ok(())
    }

    /// [`Vault::save_control_clients`] inside this transaction.
    pub fn save_control_clients(&self, clients: &[Value]) -> Result<(), VaultError> {
        let rows: Vec<(&str, String)> = clients
            .iter()
            .map(|c| {
                let id = c
                    .get("id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| VaultError::Constraint("a paired control client has no id".into()))?;
                Ok((id, encode(c)?))
            })
            .collect::<Result<_, VaultError>>()?;
        self.execute("DELETE FROM control_clients", ())?;
        for (id, json) in &rows {
            self.execute("INSERT INTO control_clients(id, json) VALUES (?1, ?2)", (id, json))?;
        }
        Ok(())
    }
}
