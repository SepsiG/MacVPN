//! The native (L2TP / Cisco IPsec) `.mobileconfig` profile (port of `MobileconfigGenerator.swift`).

use crate::l10n;
use crate::models::{Connection, NativeSettings, VPNKind, uuid_string};
use crate::plist_xml::{PlistValue, to_xml};
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MobileconfigError {
    NotNative,
    Validation(String),
    /// `PropertyListSerialization` cannot write a string with U+0000.
    InvalidCharacter,
}

impl MobileconfigError {
    pub fn message(&self) -> String {
        match self {
            MobileconfigError::NotNative => {
                l10n::tr("A profile can only be generated for L2TP and Cisco IPsec connections", &[])
            }
            MobileconfigError::Validation(m) => m.clone(),
            MobileconfigError::InvalidCharacter => {
                "The data couldn’t be written because it isn’t in the correct format.".into()
            }
        }
    }
}

impl std::fmt::Display for MobileconfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message())
    }
}

impl std::error::Error for MobileconfigError {}

fn s(v: &str) -> PlistValue {
    PlistValue::String(v.to_string())
}

fn dict(entries: Vec<(&str, PlistValue)>) -> PlistValue {
    PlistValue::Dictionary(entries.into_iter().map(|(k, v)| (k.to_string(), v)).collect::<BTreeMap<_, _>>())
}

/// The fixed PayloadIdentifier makes a reinstall replace the earlier profile. No password in the profile: MacVPN
/// passes it in-process when connecting (`NativeStartOptions`); started from System Settings, macOS asks. The PSK
/// is included, otherwise the service is unusable from there.
pub fn generate(connection: &Connection, psk: &str) -> Result<Vec<u8>, MobileconfigError> {
    if !connection.kind.is_native() {
        return Err(MobileconfigError::NotNative);
    }
    let settings = connection.native.clone().unwrap_or_default();
    let has_nul = [&connection.name, &settings.server, &settings.account].iter().any(|s| s.contains('\0'))
        || (connection.kind == VPNKind::Cisco && settings.group_name.contains('\0'));
    let NativeSettings { server, account, group_name, send_all_traffic } = settings;
    let identifier = format!("macvpn.{}", uuid_string(&connection.id));
    let mut vpn = vec![
        ("PayloadType", s("com.apple.vpn.managed")),
        ("PayloadIdentifier", s(&format!("{identifier}.vpn"))),
        ("PayloadUUID", s(&inner_uuid(&connection.id))),
        ("PayloadVersion", PlistValue::Integer(1)),
        ("PayloadDisplayName", s(&connection.name)),
        ("UserDefinedName", s(&connection.name)),
        ("IPv4", dict(vec![("OverridePrimary", PlistValue::Integer(i64::from(send_all_traffic)))])),
    ];
    match connection.kind {
        VPNKind::L2tp => {
            vpn.push(("VPNType", s("L2TP")));
            vpn.push(("PPP", dict(vec![("CommRemoteAddress", s(&server)), ("AuthName", s(&account))])));
            vpn.push((
                "IPSec",
                dict(vec![
                    ("AuthenticationMethod", s("SharedSecret")),
                    ("SharedSecret", PlistValue::Data(psk.as_bytes().to_vec())),
                ]),
            ));
        }
        VPNKind::Cisco => {
            vpn.push(("VPNType", s("IPSec")));
            if group_name.is_empty() {
                return Err(MobileconfigError::Validation(l10n::tr("Cisco IPsec requires a group name", &[])));
            }
            vpn.push((
                "IPSec",
                dict(vec![
                    ("RemoteAddress", s(&server)),
                    ("AuthenticationMethod", s("SharedSecret")),
                    ("SharedSecret", PlistValue::Data(psk.as_bytes().to_vec())),
                    ("LocalIdentifier", s(&group_name)),
                    ("LocalIdentifierType", s("KeyID")),
                    ("XAuthEnabled", PlistValue::Integer(1)),
                    ("XAuthName", s(&account)),
                    ("PromptForVPNPIN", PlistValue::Boolean(false)),
                ]),
            ));
        }
        _ => return Err(MobileconfigError::NotNative),
    }
    if has_nul {
        return Err(MobileconfigError::InvalidCharacter);
    }
    let root = dict(vec![
        ("PayloadType", s("Configuration")),
        ("PayloadIdentifier", s(&identifier)),
        ("PayloadUUID", s(&uuid_string(&connection.id))),
        ("PayloadVersion", PlistValue::Integer(1)),
        ("PayloadDisplayName", s(&format!("MacVPN – {}", connection.name))),
        ("PayloadContent", PlistValue::Array(vec![dict(vpn)])),
    ]);
    Ok(to_xml(&root))
}

/// The inner PayloadUUID, derived deterministically from the connection ID.
pub fn inner_uuid(id: &Uuid) -> String {
    let mut bytes = *id.as_bytes();
    bytes[0] ^= 0xFF;
    bytes[15] ^= 0xA5;
    uuid_string(&Uuid::from_bytes(bytes))
}
