//! The non-interactive polkit pre-check before every NM write (spike L0-1's rule; R1).
use std::collections::HashMap;
use zbus::blocking::Connection;
use zbus::zvariant::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authorization {
    /// Both actions authorized without a challenge.
    Authorized,
    /// polkit would ask (an SSH session, a locked-down system): LinVPN never asks.
    NeedsPrompt,
    Denied,
    /// polkit could not be asked (no system bus, no polkitd): fail closed.
    Unknown(String),
}

pub const ACTIONS: [&str; 2] =
    ["org.freedesktop.NetworkManager.settings.modify.own", "org.freedesktop.NetworkManager.network-control"];

const AUTHORITY: &str = "org.freedesktop.PolicyKit1";
const AUTHORITY_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const AUTHORITY_IFACE: &str = "org.freedesktop.PolicyKit1.Authority";

/// Asks polkit, for this connection's own unique name (`system-bus-name`, the subject NetworkManager checks), whether
/// both [`ACTIONS`] are allowed without a password. Flags 0 (never `AllowUserInteraction`) on a message without
/// the interactive-authorization flag: polkit answers at once and shows nothing. Only "authorized, no challenge" for
/// both is [`Authorization::Authorized`]; anything else refuses (R9).
pub fn check_nm_write(bus: &Connection) -> Authorization {
    let Some(name) = bus.unique_name().map(|n| n.to_string()) else {
        return Authorization::Unknown("the bus connection has no unique name".into());
    };
    for action in ACTIONS {
        match check(bus, &name, action) {
            Ok((true, false)) => {}
            Ok((_, true)) => return Authorization::NeedsPrompt,
            Ok((false, false)) => return Authorization::Denied,
            Err(e) => return Authorization::Unknown(e.to_string()),
        }
    }
    Authorization::Authorized
}

/// `(is_authorized, is_challenge)` of one action.
fn check(bus: &Connection, name: &str, action: &str) -> zbus::Result<(bool, bool)> {
    let subject = ("system-bus-name", HashMap::from([("name", Value::from(name))]));
    let details: HashMap<&str, &str> = HashMap::new();
    let reply = bus.call_method(
        Some(AUTHORITY),
        AUTHORITY_PATH,
        Some(AUTHORITY_IFACE),
        "CheckAuthorization",
        &(subject, action, details, 0u32, ""),
    )?;
    let (authorized, challenge, _details): (bool, bool, HashMap<String, String>) = reply.body().deserialize()?;
    Ok((authorized, challenge))
}
