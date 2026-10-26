//! The control API's lease table: which client sessions hold which connection up.
//!
//! Rules (spec section 6):
//! - The first lease on a connection that is down starts it; the connection then belongs to its lease holders
//!   and goes down when the last lease ends (`down`, socket close, crash, revoke).
//! - A connection that was already up without a lease is "pre-existing": no lease end ever brings it down.
//! - A manual disconnect by the user, or the connection dropping, ends every lease on it at once; the holders are
//!   told. Auto-reconnect (2.0) never brings back a connection started for leases (the app marks the lease's
//!   connect for its planner); a pre-existing one follows the user's "Reconnect Automatically" without a lease.
//!
//! The table only decides; the server performs the returned [`LeaseAction`].
//!
//! # The server's side of the contract
//!
//! An entry is removed only by its last release, [`LeaseTable::on_user_disconnect`] or [`LeaseTable::on_dropped`],
//! and [`LeaseTable::acquire`] on an existing entry never asks for a connect. So the server must:
//! - call [`LeaseTable::on_dropped`] on **every** transition of a leased key to `Failed` or `Disconnected` that is
//!   not a user disconnect, including a connect that fails synchronously (the `connect` call returned an error
//!   right after a [`LeaseAction::Connect`]). Otherwise the stale entry keeps the key "up" in the table, and a
//!   later `up` gets no `Connect`;
//! - answer `busy` *before* calling `acquire` when the key is not leased and its state is `Connecting`,
//!   `Disconnecting` or `AwaitingAuth`. `acquire` only sees `is_active`, which is true for all three (and for
//!   `Disconnecting` too), so it would otherwise record a connection that is on its way down as pre-existing.

use std::collections::{BTreeMap, BTreeSet};

/// One client socket connection.
pub type SessionId = u64;

/// What the server has to do after a table change.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LeaseAction {
    None,
    Connect,
    Disconnect,
}

#[derive(Debug, Clone, Default)]
struct Entry {
    holders: BTreeSet<SessionId>,
    /// Up before the first lease: never disconnected by a lease end.
    preexisting: bool,
}

/// Keyed by the connection key (`ConnectionItem::id()`). An entry exists only while it has holders.
#[derive(Debug, Clone, Default)]
pub struct LeaseTable {
    entries: BTreeMap<String, Entry>,
}

impl LeaseTable {
    pub fn new() -> Self {
        LeaseTable::default()
    }

    /// `session` takes a lease on `key`; `is_active` is the connection's current `ConnectionState::is_active()`.
    /// The first holder of a down connection must connect it; acquiring again is a no-op.
    ///
    /// Preconditions (see the module docs): the server has already answered `busy` for an unleased key that is
    /// `Connecting`, `Disconnecting` or `AwaitingAuth`, and it calls [`Self::on_dropped`] whenever a leased key
    /// fails or goes down (a synchronous connect error too), so an existing entry always means the connection
    /// is up or coming up.
    pub fn acquire(&mut self, key: &str, session: SessionId, is_active: bool) -> LeaseAction {
        if let Some(entry) = self.entries.get_mut(key) {
            entry.holders.insert(session);
            return LeaseAction::None;
        }
        self.entries.insert(key.to_string(), Entry { holders: BTreeSet::from([session]), preexisting: is_active });
        if is_active { LeaseAction::None } else { LeaseAction::Connect }
    }

    /// `session` ends its lease on `key`. The last holder of a connection it started must disconnect it.
    pub fn release(&mut self, key: &str, session: SessionId) -> LeaseAction {
        let Some(entry) = self.entries.get_mut(key) else { return LeaseAction::None };
        if !entry.holders.remove(&session) || !entry.holders.is_empty() {
            return LeaseAction::None;
        }
        let preexisting = entry.preexisting;
        self.entries.remove(key);
        if preexisting { LeaseAction::None } else { LeaseAction::Disconnect }
    }

    /// Ends every lease of `session` (its socket closed or its client was revoked), in key order.
    pub fn release_session(&mut self, session: SessionId) -> Vec<(String, LeaseAction)> {
        let keys: Vec<String> =
            self.entries.iter().filter(|(_, e)| e.holders.contains(&session)).map(|(k, _)| k.clone()).collect();
        keys.into_iter()
            .map(|key| {
                let action = self.release(&key, session);
                (key, action)
            })
            .collect()
    }

    /// The user disconnected `key` by hand: the user wins. Every lease on it ends without an action; returns the
    /// sessions to notify.
    pub fn on_user_disconnect(&mut self, key: &str) -> Vec<SessionId> {
        self.entries.remove(key).map(|e| e.holders.into_iter().collect()).unwrap_or_default()
    }

    /// `key` dropped (failed or went down by itself): like a manual disconnect, the holders are notified and the
    /// leases end (no lease is taken again on its own).
    pub fn on_dropped(&mut self, key: &str) -> Vec<SessionId> {
        self.on_user_disconnect(key)
    }

    /// In ascending order.
    pub fn holders_of(&self, key: &str) -> Vec<SessionId> {
        self.entries.get(key).map(|e| e.holders.iter().copied().collect()).unwrap_or_default()
    }

    pub fn is_leased(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }
}
