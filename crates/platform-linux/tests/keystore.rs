//! The Secret Service key store against an in-process fake of the few Secret Service calls it makes, served on the
//! private session bus of `dbus-run-session` (CI and `lin-remote.sh test` run every test under one). One test runs
//! against the real keyring at the desktop (`desktop:`, ignored everywhere).
#![cfg(target_os = "linux")]

use macvpn_core::vault::{KeyStore, KeyStoreError};
use macvpn_platform_linux::SecretServiceKeyStore;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use zbus::blocking::Connection;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};

type Secret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

const LOGIN: &str = "/org/freedesktop/secrets/collection/login";
const OTHER: &str = "/org/freedesktop/secrets/collection/other";

/// One item: its collection, attributes, secret, and whether it is locked (per item, so tests running in parallel
/// never lock each other's items).
struct Stored {
    collection: String,
    attributes: HashMap<String, String>,
    secret: Vec<u8>,
    locked: bool,
}

#[derive(Default)]
struct Store {
    /// item path → item
    items: HashMap<String, Stored>,
    next: u32,
}

struct Service(Arc<Mutex<Store>>);
/// A collection: the store and its object path (`login`, the default; `other`, a second keyring).
struct Collection(Arc<Mutex<Store>>, String);
struct Item(Arc<Mutex<Store>>, String);
struct Session;

fn path(p: &str) -> OwnedObjectPath {
    OwnedObjectPath::try_from(p).unwrap()
}

#[zbus::interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    fn open_session(&self, algorithm: String, _input: OwnedValue) -> zbus::fdo::Result<(OwnedValue, OwnedObjectPath)> {
        assert_eq!(algorithm, "plain");
        Ok((OwnedValue::try_from(Value::from("")).unwrap(), path("/org/freedesktop/secrets/session/s1")))
    }
    /// Every matching item of every collection, as the real service does.
    fn search_items(&self, attributes: HashMap<String, String>) -> (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) {
        let store = self.0.lock().unwrap();
        let (mut unlocked, mut locked) = (vec![], vec![]);
        for (p, item) in &store.items {
            if attributes.iter().all(|(k, v)| item.attributes.get(k) == Some(v)) {
                if item.locked { locked.push(path(p)) } else { unlocked.push(path(p)) }
            }
        }
        (unlocked, locked)
    }
    fn unlock(&self, objects: Vec<OwnedObjectPath>) -> (Vec<OwnedObjectPath>, OwnedObjectPath) {
        let mut store = self.0.lock().unwrap();
        for o in &objects {
            if let Some(item) = store.items.get_mut(o.as_str()) {
                item.locked = false;
            }
        }
        (objects, path("/"))
    }
    fn read_alias(&self, name: String) -> OwnedObjectPath {
        assert_eq!(name, "default");
        path(LOGIN)
    }
}

#[zbus::interface(name = "org.freedesktop.Secret.Collection")]
impl Collection {
    /// `replace` replaces an item with the same attributes in this collection only, as the real service does.
    async fn create_item(
        &self,
        properties: HashMap<String, OwnedValue>,
        secret: Secret,
        replace: bool,
        #[zbus(object_server)] server: &zbus::ObjectServer,
    ) -> zbus::fdo::Result<(OwnedObjectPath, OwnedObjectPath)> {
        assert!(replace);
        let attrs: HashMap<String, String> =
            HashMap::try_from(properties["org.freedesktop.Secret.Item.Attributes"].try_clone().unwrap()).unwrap();
        let item_path = insert(&self.0, &self.1, attrs, secret.2, false, true);
        server.at(item_path.as_str(), Item(self.0.clone(), item_path.clone())).await?;
        Ok((path(&item_path), path("/")))
    }
}

/// A new item in `collection` (with `replace`, an item there with the same attributes is replaced); its path.
fn insert(
    store: &Mutex<Store>,
    collection: &str,
    attrs: HashMap<String, String>,
    secret: Vec<u8>,
    locked: bool,
    replace: bool,
) -> String {
    let mut store = store.lock().unwrap();
    if replace {
        store.items.retain(|_, i| !(i.collection == collection && i.attributes == attrs));
    }
    store.next += 1;
    let item_path = format!("{collection}/i{}", store.next);
    let stored = Stored { collection: collection.into(), attributes: attrs, secret, locked };
    store.items.insert(item_path.clone(), stored);
    item_path
}

#[zbus::interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    fn get_secret(&self, session: OwnedObjectPath) -> zbus::fdo::Result<Secret> {
        let store = self.0.lock().unwrap();
        let item = store.items.get(&self.1).ok_or_else(|| zbus::fdo::Error::UnknownObject(self.1.clone()))?;
        if item.locked {
            return Err(zbus::fdo::Error::AccessDenied("locked".into()));
        }
        Ok((session, vec![], item.secret.clone(), "application/octet-stream".into()))
    }
    /// A locked item cannot be deleted (as gnome-keyring's `IsLocked`).
    fn delete(&self) -> zbus::fdo::Result<OwnedObjectPath> {
        let mut store = self.0.lock().unwrap();
        match store.items.get(&self.1) {
            Some(item) if item.locked => Err(zbus::fdo::Error::AccessDenied("locked".into())),
            Some(_) => {
                store.items.remove(&self.1);
                Ok(path("/"))
            }
            None => Err(zbus::fdo::Error::UnknownObject(self.1.clone())),
        }
    }
}

#[zbus::interface(name = "org.freedesktop.Secret.Session")]
impl Session {
    fn close(&self) {}
}

fn fake_bus() -> &'static (Connection, Arc<Mutex<Store>>) {
    static FAKE: OnceLock<(Connection, Arc<Mutex<Store>>)> = OnceLock::new();
    FAKE.get_or_init(|| {
        let store = Arc::new(Mutex::new(Store::default()));
        let conn = zbus::blocking::connection::Builder::session()
            .unwrap()
            .name("org.freedesktop.secrets")
            .unwrap()
            .serve_at("/org/freedesktop/secrets", Service(store.clone()))
            .unwrap()
            .serve_at(LOGIN, Collection(store.clone(), LOGIN.into()))
            .unwrap()
            .serve_at(OTHER, Collection(store.clone(), OTHER.into()))
            .unwrap()
            .serve_at("/org/freedesktop/secrets/session/s1", Session)
            .unwrap()
            .build()
            .expect("a session bus: run the tests under dbus-run-session");
        (conn, store)
    })
}

fn fake() -> Arc<Mutex<Store>> {
    fake_bus().1.clone()
}

/// An item put straight into `collection` (another keyring, an old copy; never replacing one), served on the bus
/// like a real one.
fn plant(collection: &str, application: &str, secret: &[u8], locked: bool) -> String {
    let (conn, store) = fake_bus();
    let attrs =
        HashMap::from([("application".to_string(), application.to_string()), ("kind".into(), "vault-key".into())]);
    let item_path = insert(store, collection, attrs, secret.to_vec(), locked, false);
    conn.object_server().at(item_path.as_str(), Item(store.clone(), item_path.clone())).unwrap();
    item_path
}

/// The items of `application`: (collection, secret).
fn items_of(application: &str) -> Vec<(String, Vec<u8>)> {
    let store = fake();
    let store = store.lock().unwrap();
    store
        .items
        .values()
        .filter(|i| i.attributes.get("application").map(String::as_str) == Some(application))
        .map(|i| (i.collection.clone(), i.secret.clone()))
        .collect()
}

fn store_for_test() -> SecretServiceKeyStore {
    store_and_application().0
}

fn store_and_application() -> (SecretServiceKeyStore, String) {
    fake();
    let application = format!("local.linvpn.test.{}", uuid::Uuid::new_v4());
    (SecretServiceKeyStore::for_tests(&application), application)
}

#[test]
fn set_get_exists_delete() {
    let ks = store_for_test();
    assert!(!ks.exists().unwrap());
    assert!(ks.get().unwrap().is_none());
    ks.set(&[7u8; 32]).unwrap();
    assert!(ks.exists().unwrap());
    assert_eq!(ks.get().unwrap().unwrap().as_slice(), &[7u8; 32]);
    ks.set(&[9u8; 32]).unwrap();
    assert_eq!(ks.get().unwrap().unwrap().as_slice(), &[9u8; 32], "replaced, not a second item");
    ks.delete().unwrap();
    assert!(!ks.exists().unwrap());
    ks.delete().unwrap(); // deleting nothing is fine
}

#[test]
fn a_locked_collection_is_unlocked_first() {
    let (ks, application) = store_and_application();
    ks.set(&[3u8; 32]).unwrap();
    for item in fake().lock().unwrap().items.values_mut() {
        if item.attributes.get("application") == Some(&application) {
            item.locked = true;
        }
    }
    assert_eq!(ks.get().unwrap().unwrap().as_slice(), &[3u8; 32]);
    ks.delete().unwrap();
    assert!(items_of(&application).is_empty());
}

/// LA-3: a copy in another keyring (the default changed after auto-unlock was turned on) is deleted too, also when
/// it is locked: turning auto-unlock off leaves no copy of the key at rest.
#[test]
fn delete_removes_every_copy_in_every_collection() {
    let (ks, application) = store_and_application();
    ks.set(&[1u8; 32]).unwrap();
    plant(OTHER, &application, &[2u8; 32], false);
    plant(OTHER, &application, &[3u8; 32], true);
    plant(LOGIN, &application, &[4u8; 32], true);
    assert_eq!(items_of(&application).len(), 4);
    ks.delete().unwrap();
    assert!(items_of(&application).is_empty(), "{:?}", items_of(&application));
    assert!(!ks.exists().unwrap());
}

/// LA-3: `set` leaves exactly one item, in the default collection, with the new key: no stale copy elsewhere that
/// `get` could return first or `delete` could miss.
#[test]
fn set_leaves_no_stale_copy_elsewhere() {
    let (ks, application) = store_and_application();
    plant(OTHER, &application, &[2u8; 32], false);
    plant(OTHER, &application, &[3u8; 32], true);
    ks.set(&[9u8; 32]).unwrap();
    assert_eq!(items_of(&application), [(LOGIN.to_string(), vec![9u8; 32])]);
    assert_eq!(ks.get().unwrap().unwrap().as_slice(), &[9u8; 32]);
    ks.delete().unwrap();
}

#[test]
fn the_attributes_are_ours_only() {
    let ks = store_for_test();
    ks.set(&[1u8; 32]).unwrap();
    let store = fake();
    let store = store.lock().unwrap();
    let ours: Vec<_> = store
        .items
        .values()
        .map(|i| &i.attributes)
        .filter(|a| a.get("kind").map(String::as_str) == Some("vault-key"))
        .collect();
    assert!(!ours.is_empty());
    assert!(ours.iter().all(|a| a.len() == 2 && a["application"].starts_with("local.linvpn")));
}

#[test]
fn no_service_is_unavailable() {
    // A bus name nobody owns (and nothing can activate): the error is `Unavailable`, never a panic.
    let ks = SecretServiceKeyStore::for_tests_at("org.example.NoSuchSecrets", "local.linvpn.test.none");
    assert!(matches!(ks.get(), Err(KeyStoreError::Unavailable(_))));
    assert!(matches!(ks.exists(), Err(KeyStoreError::Unavailable(_))));
}

/// At the desktop (CP-desktop login): the real gnome-keyring, a unique test item, deleted again.
#[test]
#[ignore = "desktop: the real Secret Service (gnome-keyring)"]
fn desktop_the_real_keyring_round_trip() {
    let ks = SecretServiceKeyStore::for_real_tests(&format!("local.linvpn.test.{}", uuid::Uuid::new_v4()));
    ks.set(&[5u8; 32]).unwrap();
    assert_eq!(ks.get().unwrap().unwrap().as_slice(), &[5u8; 32]);
    ks.delete().unwrap();
    assert!(!ks.exists().unwrap());
}
