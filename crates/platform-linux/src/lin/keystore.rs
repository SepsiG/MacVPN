//! The vault's auto-unlock key (DEK) in the Secret Service (`org.freedesktop.secrets`: gnome-keyring), the
//! counterpart of the macOS Keychain item and the Windows credential. One item in the default collection, label
//! "LinVPN vault key", attributes `application = local.linvpn`, `kind = vault-key` (storage identifiers: literals).
//!
//! Protocol (Secret Service API 0.2): `OpenSession("plain")`; `SearchItems(attributes)` → unlocked / locked paths;
//! a locked item is unlocked with `Unlock` and, when a prompt is returned, the system's own prompt
//! (`Prompt.Prompt("")`, then the `Completed` signal, at most 120 s; dismissed → `Unavailable`); `GetSecret`;
//! `CreateItem(properties, secret, replace = true)` in the collection the alias `default` names; `Item.Delete`.
//! `SearchItems` searches every collection, but `replace` replaces only inside one: so `delete` removes every match in
//! every collection (locked ones unlocked first), searching again until none is left, and `set` does the same before
//! it writes. A copy left in another keyring (the default changed since) never outlives "turn auto-unlock off".
//! The `plain` session sends the DEK unencrypted over the session bus, which only this user's processes reach (the
//! same-user boundary every platform's key store has; LinVPN plan, "Resolved points"). Every copy is `Zeroizing`.
//! No session bus or no service: `Unavailable` (the vault then asks for the master password).

use macvpn_core::vault::{KeyStore, KeyStoreError};
use std::collections::HashMap;
use std::sync::mpsc;
use std::time::Duration;
use zbus::blocking::{Connection, Proxy};
use zbus::proxy::CacheProperties;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zeroize::Zeroizing;

const PATH: &str = "/org/freedesktop/secrets";
const SERVICE: &str = "org.freedesktop.secrets";
const LABEL: &str = "LinVPN vault key";
const APPLICATION: &str = "local.linvpn";
const KIND: &str = "vault-key";
const PROMPT_WAIT: Duration = Duration::from_secs(120);
/// `delete`'s search-and-delete rounds before it gives up (a service that keeps reporting deleted items).
const DELETE_ROUNDS: usize = 8;

type Secret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

/// The Secret Service [`KeyStore`]. Opens a `plain` session per operation and closes it again.
pub struct SecretServiceKeyStore {
    service: String,
    application: String,
    bus: fn() -> zbus::Result<Connection>,
}

fn unavailable(e: impl std::fmt::Display) -> KeyStoreError {
    KeyStoreError::Unavailable(format!("Secret Service: {e}"))
}

impl SecretServiceKeyStore {
    /// The user's Secret Service on the process' session bus.
    pub fn production() -> SecretServiceKeyStore {
        SecretServiceKeyStore {
            service: SERVICE.into(),
            application: APPLICATION.into(),
            bus: crate::lin::bus::session,
        }
    }

    /// Tests: a unique application attribute, on the test's session bus (a fake service).
    #[doc(hidden)]
    pub fn for_tests(application: &str) -> SecretServiceKeyStore {
        Self::for_tests_at(SERVICE, application)
    }

    /// Tests: another bus name for the service (one nobody owns: `Unavailable`).
    #[doc(hidden)]
    pub fn for_tests_at(service: &str, application: &str) -> SecretServiceKeyStore {
        SecretServiceKeyStore { service: service.into(), application: application.into(), bus: Connection::session }
    }

    /// Desktop tests: the real keyring of the logged-in user, a unique application attribute.
    #[doc(hidden)]
    pub fn for_real_tests(application: &str) -> SecretServiceKeyStore {
        Self::for_tests(application)
    }

    fn attributes(&self) -> HashMap<&str, &str> {
        HashMap::from([("application", self.application.as_str()), ("kind", KIND)])
    }

    /// A proxy without the property cache (no `GetAll` and no signal match on creation).
    fn proxy(&self, bus: &Connection, path: &str, interface: &'static str) -> Result<Proxy<'static>, KeyStoreError> {
        zbus::blocking::proxy::Builder::<Proxy<'static>>::new(bus)
            .destination(self.service.clone())
            .and_then(|b| b.path(path.to_owned()))
            .and_then(|b| b.interface(interface))
            .map(|b| b.cache_properties(CacheProperties::No))
            .and_then(|b| b.build())
            .map_err(unavailable)
    }

    fn search(&self, bus: &Connection) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>), KeyStoreError> {
        let service = self.proxy(bus, PATH, "org.freedesktop.Secret.Service")?;
        service.call("SearchItems", &(self.attributes(),)).map_err(unavailable)
    }

    fn connect(&self) -> Result<(Connection, OwnedObjectPath), KeyStoreError> {
        let bus = (self.bus)().map_err(unavailable)?;
        let service = self.proxy(&bus, PATH, "org.freedesktop.Secret.Service")?;
        let (_, session): (OwnedValue, OwnedObjectPath) =
            service.call("OpenSession", &("plain", Value::from(""))).map_err(unavailable)?;
        Ok((bus, session))
    }

    fn close(&self, bus: &Connection, session: &OwnedObjectPath) {
        if let Ok(p) = self.proxy(bus, session.as_str(), "org.freedesktop.Secret.Session") {
            let _: Result<(), _> = p.call("Close", &());
        }
    }

    /// The item's path, unlocked first if it is locked; `None`: no item.
    fn find(&self, bus: &Connection) -> Result<Option<OwnedObjectPath>, KeyStoreError> {
        let (unlocked, locked) = self.search(bus)?;
        if let Some(path) = unlocked.into_iter().next() {
            return Ok(Some(path));
        }
        let Some(path) = locked.into_iter().next() else { return Ok(None) };
        let service = self.proxy(bus, PATH, "org.freedesktop.Secret.Service")?;
        let (done, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) =
            service.call("Unlock", &(vec![path.clone()],)).map_err(unavailable)?;
        if done.contains(&path) {
            return Ok(Some(path));
        }
        self.run_prompt(bus, &prompt)?;
        Ok(Some(path))
    }

    /// Every matching item of every collection, the locked ones unlocked first (one `Unlock`, at most one prompt).
    fn find_all(&self, bus: &Connection) -> Result<Vec<OwnedObjectPath>, KeyStoreError> {
        let (mut items, locked) = self.search(bus)?;
        if !locked.is_empty() {
            let service = self.proxy(bus, PATH, "org.freedesktop.Secret.Service")?;
            let (_, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) =
                service.call("Unlock", &(locked.clone(),)).map_err(unavailable)?;
            self.run_prompt(bus, &prompt)?;
            items.extend(locked);
        }
        Ok(items)
    }

    /// Deletes every matching item of every collection, searching again until none is left.
    fn delete_all(&self, bus: &Connection) -> Result<(), KeyStoreError> {
        for _ in 0..DELETE_ROUNDS {
            let items = self.find_all(bus)?;
            if items.is_empty() {
                return Ok(());
            }
            for path in items {
                let item = self.proxy(bus, path.as_str(), "org.freedesktop.Secret.Item")?;
                let prompt: OwnedObjectPath = item.call("Delete", &()).map_err(unavailable)?;
                self.run_prompt(bus, &prompt)?;
            }
        }
        Err(KeyStoreError::Unavailable("the keyring still holds the vault key".into()))
    }

    /// The system's prompt: `Prompt("")`, then `Completed(dismissed, result)`; `/` means no prompt is needed.
    fn run_prompt(&self, bus: &Connection, prompt: &OwnedObjectPath) -> Result<(), KeyStoreError> {
        if prompt.as_str() == "/" {
            return Ok(());
        }
        let p = self.proxy(bus, prompt.as_str(), "org.freedesktop.Secret.Prompt")?;
        let signals = p.receive_signal("Completed").map_err(unavailable)?;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            if let Some(message) = signals.into_iter().next() {
                let dismissed = message.body().deserialize::<(bool, OwnedValue)>().map(|(d, _)| d).unwrap_or(true);
                let _ = tx.send(dismissed);
            }
        });
        p.call::<_, _, ()>("Prompt", &("",)).map_err(unavailable)?;
        match rx.recv_timeout(PROMPT_WAIT) {
            Ok(false) => Ok(()),
            Ok(true) => Err(KeyStoreError::Unavailable("the keyring was not unlocked".into())),
            Err(_) => {
                let _: Result<(), _> = p.call("Dismiss", &());
                Err(KeyStoreError::Unavailable("the keyring prompt timed out".into()))
            }
        }
    }
}

impl KeyStore for SecretServiceKeyStore {
    fn get(&self) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
        let (bus, session) = self.connect()?;
        let result = (|| {
            let Some(path) = self.find(&bus)? else { return Ok(None) };
            let item = self.proxy(&bus, path.as_str(), "org.freedesktop.Secret.Item")?;
            // Straight into the tuple: the only copies are the reply message and this `Zeroizing` value.
            let (_, parameters, value, _): Secret = item.call("GetSecret", &(&session,)).map_err(unavailable)?;
            drop(Zeroizing::new(parameters));
            Ok(Some(Zeroizing::new(value)))
        })();
        self.close(&bus, &session);
        result
    }

    /// Searching never prompts: a locked item counts as existing.
    fn exists(&self) -> Result<bool, KeyStoreError> {
        let bus = (self.bus)().map_err(unavailable)?;
        let (unlocked, locked) = self.search(&bus)?;
        Ok(!unlocked.is_empty() || !locked.is_empty())
    }

    fn set(&self, key: &[u8]) -> Result<(), KeyStoreError> {
        let (bus, session) = self.connect()?;
        let result = (|| {
            // No copy elsewhere (another keyring, an old item): the one written below is the only one.
            self.delete_all(&bus)?;
            let service = self.proxy(&bus, PATH, "org.freedesktop.Secret.Service")?;
            let collection: OwnedObjectPath = service.call("ReadAlias", &("default",)).map_err(unavailable)?;
            if collection.as_str() == "/" {
                return Err(KeyStoreError::Unavailable("no default keyring".into()));
            }
            let c = self.proxy(&bus, collection.as_str(), "org.freedesktop.Secret.Collection")?;
            let properties: HashMap<&str, Value> = HashMap::from([
                ("org.freedesktop.Secret.Item.Label", Value::from(LABEL)),
                ("org.freedesktop.Secret.Item.Attributes", Value::from(self.attributes())),
            ]);
            let value = Zeroizing::new(key.to_vec());
            let secret = (&session, Vec::<u8>::new(), value.as_slice(), "application/octet-stream");
            let (_, prompt): (OwnedObjectPath, OwnedObjectPath) =
                c.call("CreateItem", &(properties, secret, true)).map_err(unavailable)?;
            self.run_prompt(&bus, &prompt)
        })();
        self.close(&bus, &session);
        result
    }

    /// Every copy, in every collection.
    fn delete(&self) -> Result<(), KeyStoreError> {
        let bus = (self.bus)().map_err(unavailable)?;
        self.delete_all(&bus)
    }
}
