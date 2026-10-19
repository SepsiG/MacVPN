//! The system VPNs' (scutil service ID) "code appended to the password" settings:
//! `~/Library/Application Support/MacVPN/system-otp.json` (0600, atomic write). Not secret, not exported.
//! Port of `SystemOTPStore` (`MFA.swift`).

use crate::models::OTPSetting;
use crate::store::{ensure_private_parent, write_private};
use crate::swift_json;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct SystemOTPStore {
    pub path: PathBuf,
}

impl SystemOTPStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        SystemOTPStore { path: path.into() }
    }

    /// `<application support>/system-otp.json`.
    pub fn default_path(application_support: &Path) -> PathBuf {
        application_support.join("system-otp.json")
    }

    /// A missing or invalid file (any entry of the wrong shape): empty.
    pub fn load(&self) -> HashMap<String, OTPSetting> {
        let Ok(data) = std::fs::read(&self.path) else { return HashMap::new() };
        let Ok(Value::Object(obj)) = swift_json::parse(&data) else { return HashMap::new() };
        let mut out = HashMap::new();
        for (key, v) in obj {
            match OTPSetting::from_json(&v) {
                Ok(s) => {
                    out.insert(key, s);
                }
                Err(_) => return HashMap::new(),
            }
        }
        out
    }

    /// Only the enabled entries are written.
    pub fn save(&self, map: &HashMap<String, OTPSetting>) -> io::Result<()> {
        ensure_private_parent(&self.path)?;
        let mut obj = Map::new();
        for (key, setting) in map.iter().filter(|(_, s)| s.enabled) {
            obj.insert(key.clone(), setting.to_json());
        }
        let json = swift_json::to_pretty_sorted(&Value::Object(obj)).map_err(io::Error::other)?;
        write_private(json.as_bytes(), &self.path)
    }
}
