//! One session-bus and one system-bus connection per process, opened on first use (never at construction: the
//! sandbox and the tests open none unless they call a D-Bus service). `zbus::blocking::Connection` is cheap to
//! clone (shared).

use std::sync::{Mutex, PoisonError};
use zbus::blocking::Connection;

static SESSION: Mutex<Option<Connection>> = Mutex::new(None);
static SYSTEM: Mutex<Option<Connection>> = Mutex::new(None);

fn get(slot: &Mutex<Option<Connection>>, open: fn() -> zbus::Result<Connection>) -> zbus::Result<Connection> {
    let mut guard = slot.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(c) = guard.as_ref() {
        return Ok(c.clone());
    }
    let c = open()?;
    *guard = Some(c.clone());
    Ok(c)
}

/// The user's session bus (`DBUS_SESSION_BUS_ADDRESS`).
pub fn session() -> zbus::Result<Connection> {
    get(&SESSION, Connection::session)
}

/// The system bus.
pub fn system() -> zbus::Result<Connection> {
    get(&SYSTEM, Connection::system)
}
