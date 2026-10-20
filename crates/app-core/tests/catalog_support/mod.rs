//! Shared by the team catalog tests: a vault-backed connection repository, a publisher that seals catalogs, a fake
//! fetcher, and a fixture with the catalog service over the in-memory vault, the mock root and the mock native
//! controller. The manager uses the app's own vault stores (`VaultConnections`, `VaultSecrets`).
#![allow(dead_code)]

use crate::common::{MemorySecrets, MockNative, MockRoot, TempDir};
use macvpn_app_core::catalog::{CatalogDeps, CatalogService};
use macvpn_app_core::deps::{CatalogFetcher, ConnectionRepository, FetchOutcome, FetchRequest, ManualClock};
use macvpn_app_core::notify::NotificationContent;
use macvpn_app_core::vault::VaultLifecycle;
use macvpn_app_core::vault_stores::{VaultConnections, VaultSecrets};
use macvpn_app_core::{ConnectionManager, Dependencies};
use macvpn_core::catalog::fetch::content_hash;
use macvpn_core::catalog::format::{CatalogError, CatalogHeaderInput, seal_catalog};
use macvpn_core::catalog::ids::{CatalogItemKind, local_id};
use macvpn_core::catalog::keys::{AdminKey, PublisherKey, TeamKey};
use macvpn_core::catalog::payload::{CatalogConnection, CatalogPayload, CredentialSlot, PAYLOAD_VERSION};
use macvpn_core::date::Date;
use macvpn_core::models::{Connection, VPNKind, uuid_string};
use macvpn_core::vault::{FixedEntropy, KdfParams, MemoryKeyStore, SourceValidators, VaultError};
use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use zeroize::Zeroizing;

pub const OPENVPN: &str = "client\ndev tun\nproto udp\nremote vpn.example.com 1194\nnobind\nauth-user-pass\n";
pub const MASTER: &str = "correct horse battery";

/// The manager's connections from the vault.
pub struct VaultRepo(pub Arc<VaultLifecycle>);

fn io_error(e: VaultError) -> io::Error {
    io::Error::other(e.to_string())
}

impl ConnectionRepository for VaultRepo {
    fn list(&self) -> io::Result<Vec<Connection>> {
        self.0.with_read(|v| v.connections()).map(|l| l.into_iter().map(|s| s.connection).collect()).map_err(io_error)
    }

    fn save(&self, connection: &Connection, config: Option<&str>) -> io::Result<()> {
        self.0.with(|v| v.save_connection(connection, config)).map_err(io_error)
    }

    fn load_config(&self, id: &Uuid) -> io::Result<String> {
        self.0.with_read(|v| v.config(id)).map(|c| c.as_str().to_string()).map_err(io_error)
    }

    fn delete(&self, id: &Uuid) -> io::Result<()> {
        self.0.with(|v| v.delete_connection(id)).map_err(io_error)
    }
}

pub fn uid(n: u128) -> Uuid {
    Uuid::from_u128(0x3000_0000_0000_4000_8000_0000_0000_0000 + n)
}

pub fn catalog_id() -> Uuid {
    uid(0xCA7)
}

/// The local id of catalog connection `n`.
pub fn local(n: u128) -> Uuid {
    local_id(catalog_id(), CatalogItemKind::Connection, uid(n))
}

pub fn key(n: u128) -> String {
    uuid_string(&local(n))
}

pub fn connection(n: u128, name: &str) -> CatalogConnection {
    CatalogConnection {
        id: uid(n),
        name: name.into(),
        kind: VPNKind::Openvpn,
        folder: None,
        color: None,
        config: Zeroizing::new(OPENVPN.into()),
        native: None,
        otp: Default::default(),
        slot: None,
        secret_refs: BTreeMap::new(),
    }
}

/// Connections `ns`, all on slot 200 ("Office AD").
pub fn payload(ns: &[(u128, &str)]) -> CatalogPayload {
    CatalogPayload {
        version: PAYLOAD_VERSION,
        folders: Vec::new(),
        connections: ns
            .iter()
            .map(|(n, name)| {
                let mut c = connection(*n, name);
                c.slot = Some(uid(200));
                c
            })
            .collect(),
        credential_slots: vec![CredentialSlot { id: uid(200), name: "Office AD".into() }],
        shared_secrets: BTreeMap::new(),
    }
}

/// The admin side: an admin key, the team key, the catalog id.
pub struct Publisher {
    pub admin: AdminKey,
    pub team: TeamKey,
    pub name: String,
}

impl Publisher {
    pub fn new() -> Publisher {
        Publisher {
            admin: AdminKey::generate(&FixedEntropy::new(9)).unwrap(),
            team: TeamKey::generate(&FixedEntropy::new(1)).unwrap(),
            name: "Acme VPN".into(),
        }
    }

    pub fn seal(&self, version: u64, payload: &CatalogPayload) -> Vec<u8> {
        self.seal_with(version, payload, &self.admin, &self.team, None)
    }

    pub fn seal_with(
        &self,
        version: u64,
        payload: &CatalogPayload,
        admin: &AdminKey,
        team: &TeamKey,
        successor: Option<PublisherKey>,
    ) -> Vec<u8> {
        seal_catalog(
            CatalogHeaderInput {
                catalog_id: catalog_id(),
                name: self.name.clone(),
                version,
                created: Date::parse_iso8601("2026-10-19T08:00:00Z").unwrap(),
                successor_key: successor,
            },
            payload,
            team,
            admin,
            &FixedEntropy::new(version),
        )
        .unwrap()
    }
}

/// Serves one file, like a share: `NotModified` when the content hash equals the stored one.
#[derive(Default)]
pub struct FakeFetcher {
    on_fetch: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
    served: Mutex<Option<Result<Vec<u8>, CatalogError>>>,
    calls: Mutex<usize>,
    bearers: Mutex<Vec<Option<String>>>,
}

impl FakeFetcher {
    pub fn serve(&self, bytes: Vec<u8>) {
        *self.served.lock().unwrap() = Some(Ok(bytes));
    }

    pub fn fail(&self, e: CatalogError) {
        *self.served.lock().unwrap() = Some(Err(e));
    }

    /// Runs during every fetch (to lock the vault mid-refresh).
    pub fn set_on_fetch(&self, f: impl Fn() + Send + Sync + 'static) {
        *self.on_fetch.lock().unwrap() = Some(Box::new(f));
    }

    pub fn calls(&self) -> usize {
        *self.calls.lock().unwrap()
    }

    pub fn bearers(&self) -> Vec<Option<String>> {
        self.bearers.lock().unwrap().clone()
    }
}

impl CatalogFetcher for FakeFetcher {
    fn fetch(&self, req: &FetchRequest) -> Result<FetchOutcome, CatalogError> {
        *self.calls.lock().unwrap() += 1;
        if let Some(f) = self.on_fetch.lock().unwrap().as_ref() {
            f();
        }
        self.bearers.lock().unwrap().push(req.bearer.map(str::to_string));
        let served = self.served.lock().unwrap().clone().unwrap_or(Err(CatalogError::Unavailable("none".into())))?;
        let hash = content_hash(&served);
        if req.previous.content_hash == Some(hash) {
            return Ok(FetchOutcome::NotModified);
        }
        Ok(FetchOutcome::Fetched {
            bytes: served,
            validators: SourceValidators { content_hash: Some(hash), ..Default::default() },
        })
    }
}

pub struct CatalogFixture {
    pub tmp: TempDir,
    pub vault: Arc<VaultLifecycle>,
    pub root: Arc<MockRoot>,
    pub native: Arc<MockNative>,
    pub secrets: Arc<VaultSecrets>,
    pub manager: Arc<ConnectionManager>,
    pub fetcher: Arc<FakeFetcher>,
    pub service: Arc<CatalogService>,
    pub clock: Arc<ManualClock>,
    pub notices: Arc<Mutex<Vec<NotificationContent>>>,
    pub log: Arc<Mutex<Vec<String>>>,
    pub forgotten: Arc<Mutex<Vec<String>>>,
}

impl CatalogFixture {
    pub fn new() -> CatalogFixture {
        let tmp = TempDir::new();
        std::fs::create_dir_all(tmp.path()).unwrap();
        let vault = Arc::new(VaultLifecycle::new(
            tmp.path().join("MacVPN"),
            Arc::new(MemoryKeyStore::new()),
            Arc::new(FixedEntropy::new(3)),
            KdfParams::insecure_for_tests(),
        ));
        let log = Arc::new(Mutex::new(Vec::new()));
        let sink = log.clone();
        vault.set_logger(move |line| sink.lock().unwrap().push(line.to_string()));
        vault.create(Zeroizing::new(MASTER.into()), false).unwrap();
        let root = Arc::new(MockRoot::default());
        root.respond("status", Ok("[]"));
        let secrets = Arc::new(VaultSecrets::new(vault.clone()));
        let native = Arc::new(MockNative::default());
        let mut deps = Dependencies::new(
            Arc::new(VaultConnections::new(vault.clone())),
            secrets.clone(),
            root.clone(),
            native.clone(),
        );
        deps.secret_writer = Some(secrets.clone());
        let clock = Arc::new(ManualClock::new(Date::parse_iso8601("2026-10-19T09:00:00Z").unwrap()));
        deps.clock = clock.clone();
        let manager = ConnectionManager::new(deps);
        manager.reload();
        let fetcher = Arc::new(FakeFetcher::default());
        let service = CatalogService::new(CatalogDeps {
            vault: vault.clone(),
            https: fetcher.clone(),
            file: fetcher.clone(),
            manager: manager.clone(),
            clock: clock.clone(),
        });
        let notices = Arc::new(Mutex::new(Vec::new()));
        let sink = notices.clone();
        service.set_notifier(move |n| sink.lock().unwrap().push(n));
        let sink = log.clone();
        service.set_logger(move |line| sink.lock().unwrap().push(line.to_string()));
        let forgotten = Arc::new(Mutex::new(Vec::new()));
        let sink = forgotten.clone();
        service.set_forget_keys(move |keys| {
            sink.lock().unwrap().extend(keys.iter().cloned());
            Ok(())
        });
        service.attach();
        let _ = MemorySecrets::default();
        CatalogFixture { tmp, vault, root, native, secrets, manager, fetcher, service, clock, notices, log, forgotten }
    }

    pub fn notices(&self) -> Vec<String> {
        self.notices.lock().unwrap().iter().map(|n| n.body.clone()).collect()
    }

    pub fn connection_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.manager.connections().into_iter().map(|c| c.name).collect();
        names.sort();
        names
    }
}
