//! The root layer's `mvpn status` JSON (port of `RootStatus` in `MvpnClient.swift`).

use crate::date::Date;
use crate::l10n;
use crate::models::{ConnectionState, parse_uuid};
use crate::swift_json;
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq)]
pub struct RootStatus {
    pub id: Uuid,
    pub kind: String,
    pub state: String,
    pub iface: Option<String>,
    pub ip: Option<String>,
    /// Unix time.
    pub since: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusParseError;

impl std::fmt::Display for StatusParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid mvpn status JSON")
    }
}

impl std::error::Error for StatusParseError {}

impl RootStatus {
    pub fn connection_state(&self) -> ConnectionState {
        match self.state.as_str() {
            "connected" => ConnectionState::Connected {
                ip: self.ip.clone(),
                since: self.since.map(Date::from_time_interval_since_1970),
            },
            "connecting" => ConnectionState::Connecting,
            _ => ConnectionState::Failed(l10n::tr("The connection dropped", &[])),
        }
    }

    fn from_json(v: &Value) -> Option<RootStatus> {
        let obj = v.as_object()?;
        let string = |key: &str| obj.get(key).and_then(Value::as_str).map(str::to_string);
        let optional_string = |key: &str| -> Option<Option<String>> {
            match obj.get(key) {
                None | Some(Value::Null) => Some(None),
                Some(v) => v.as_str().map(|s| Some(s.to_string())),
            }
        };
        let since = match obj.get("since") {
            None | Some(Value::Null) => None,
            Some(v) => Some(v.as_f64()?),
        };
        Some(RootStatus {
            id: obj.get("id")?.as_str().and_then(parse_uuid)?,
            kind: string("kind")?,
            state: string("state")?,
            iface: optional_string("iface")?,
            ip: optional_string("ip")?,
            since,
        })
    }
}

/// `MvpnClient.parseStatus`: a JSON array of status objects; any malformed entry fails the whole parse.
pub fn parse_status(json: &str) -> Result<Vec<RootStatus>, StatusParseError> {
    let value = swift_json::parse(json.as_bytes()).map_err(|_| StatusParseError)?;
    value.as_array().ok_or(StatusParseError)?.iter().map(|v| RootStatus::from_json(v).ok_or(StatusParseError)).collect()
}
