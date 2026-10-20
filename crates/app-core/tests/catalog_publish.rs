//! Publishing (plan Task 14, spec 7): admin keys, the backup key kept offline, publish with the automatic version,
//! the team key shown once and rotated, the 0644 file, the subscription string behind the master password, the
//! "changed since the last publish" badge, and a subscriber following a promoted backup key.

mod catalog_support;
mod common;

use catalog_support::{CatalogFixture, MASTER, OPENVPN};
use common::TempDir;
use macvpn_app_core::catalog::{RefreshResult, SubscribeInput};
use macvpn_app_core::catalog_publish::{PublishError, PublishInput, PublishResult, Publisher, PublisherDeps};
use macvpn_app_core::catalog_schedule::RefreshTrigger;
use macvpn_app_core::deps::ManualClock;
use macvpn_app_core::vault::VaultLifecycle;
use macvpn_core::catalog::format::{CatalogError, OpenRequest, OpenedCatalog, Trust, open_catalog};
use macvpn_core::catalog::keys::{Fingerprint, TeamKey};
use macvpn_core::catalog::selection::PublishSelection;
use macvpn_core::catalog::source::CatalogSource;
use macvpn_core::catalog::subscription::parse_subscription;
use macvpn_core::date::Date;
use macvpn_core::models::{Connection, VPNKind, uuid_string};
use macvpn_core::vault::{AdminKeyRole, FixedEntropy, KdfParams, MemoryKeyStore};
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use zeroize::Zeroizing;

const KEY_FILE_PASSWORD: &str = "offline admin key password";

fn id(n: u128) -> Uuid {
    Uuid::from_u128(0x5000_0000_0000_4000_8000_0000_0000_0000 + n)
}

struct Admin {
    tmp: TempDir,
    vault: Arc<VaultLifecycle>,
    publisher: Publisher,
    log: Arc<Mutex<Vec<String>>>,
    office: Uuid,
    lab: Uuid,
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn admin() -> Admin {
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path().join("out")).unwrap();
    let vault = Arc::new(VaultLifecycle::new(
        tmp.path().join("MacVPN"),
        Arc::new(MemoryKeyStore::new()),
        Arc::new(FixedEntropy::new(31)),
        KdfParams::insecure_for_tests(),
    ));
    vault.create(Zeroizing::new(MASTER.into()), false).unwrap();
    let created = Date::parse_iso8601("2026-10-19T08:00:00Z").unwrap();
    let (office, lab) = vault
        .with(|v| {
            for (n, name) in [(1, "Office"), (2, "Lab")] {
                v.save_connection(&Connection::with_id(id(n), name, VPNKind::Openvpn, created), Some(OPENVPN))?;
            }
            Ok((id(1), id(2)))
        })
        .unwrap();
    let publisher = Publisher::new(PublisherDeps {
        vault: vault.clone(),
        entropy: Arc::new(FixedEntropy::new(77)),
        kdf: KdfParams::insecure_for_tests(),
        clock: Arc::new(ManualClock::new(Date::parse_iso8601("2026-10-19T09:00:00Z").unwrap())),
    });
    let log = Arc::new(Mutex::new(Vec::new()));
    let sink = log.clone();
    publisher.set_logger(move |line| sink.lock().unwrap().push(line.to_string()));
    Admin { tmp, vault, publisher, log, office, lab }
}

impl Admin {
    fn path(&self, name: &str) -> PathBuf {
        self.tmp.path().join("out").join(name)
    }

    fn selection(&self) -> PublishSelection {
        PublishSelection { connections: BTreeSet::from([self.office, self.lab]), ..Default::default() }
    }

    fn publish(&self, catalog_id: Option<Uuid>, file: &str) -> Result<PublishResult, PublishError> {
        self.publisher.publish(PublishInput {
            catalog_id,
            name: "Acme VPN".into(),
            selection: self.selection(),
            path: self.path(file),
        })
    }

    fn fingerprint(&self, role: AdminKeyRole) -> Fingerprint {
        self.publisher.admin_keys().unwrap().into_iter().find(|k| k.role == role).unwrap().fingerprint
    }

    fn log_text(&self) -> String {
        self.log.lock().unwrap().join("\n")
    }
}

fn open(path: &Path, team: &TeamKey, pinned: Fingerprint) -> Result<OpenedCatalog, CatalogError> {
    let bytes = fs::read(path).unwrap();
    open_catalog(
        &bytes,
        &OpenRequest {
            trust: &Trust { pinned, publisher_key: None, successor: None },
            catalog_id: None,
            applied_version: None,
            team_key: team,
        },
    )
}

fn team(result: &PublishResult) -> TeamKey {
    TeamKey::parse(result.new_team_key.as_ref().expect("a new team key")).unwrap()
}

#[test]
fn publishing_twice_gives_versions_1_and_2_with_the_same_ids() {
    let a = admin();
    assert_eq!(a.publish(None, "acme.macvpncatalog").unwrap_err(), PublishError::NoAdminKey);
    let primary = a.publisher.generate_admin_key(AdminKeyRole::Primary).unwrap();
    assert_eq!(a.fingerprint(AdminKeyRole::Primary), primary);
    assert!(a.publisher.generate_admin_key(AdminKeyRole::Primary).is_err(), "never replaced silently");

    let first = a.publish(None, "acme.macvpncatalog").unwrap();
    assert_eq!((first.version, first.fingerprint), (1, primary));
    let key = team(&first);
    let debug = format!("{first:?}");
    assert!(!debug.contains(first.new_team_key.as_ref().unwrap().as_str()), "the team key is redacted");
    let path = a.path("acme.macvpncatalog");
    assert_eq!(mode(&path), 0o644, "meant to be served");
    let opened = open(&path, &key, primary).unwrap();
    assert_eq!((opened.header.catalog_id, opened.header.version), (first.catalog_id, 1));
    assert_eq!(opened.header.name, "Acme VPN");
    assert_eq!(opened.header.successor_key, None);
    let ids: BTreeSet<Uuid> = opened.payload.connections.iter().map(|c| c.id).collect();
    assert_eq!(ids, BTreeSet::from([a.office, a.lab]));

    let second = a.publish(Some(first.catalog_id), "acme.macvpncatalog").unwrap();
    assert_eq!((second.catalog_id, second.version), (first.catalog_id, 2));
    assert!(second.new_team_key.is_none(), "shown once");
    let opened = open(&path, &key, primary).unwrap();
    assert_eq!(opened.header.version, 2);
    assert_eq!(opened.payload.connections.iter().map(|c| c.id).collect::<BTreeSet<_>>(), ids);

    let views = a.publisher.publications().unwrap();
    assert_eq!(views.len(), 1);
    assert_eq!((views[0].version, views[0].changed), (2, 0));
    assert_eq!(views[0].file_name.as_deref(), Some("acme.macvpncatalog"));
    let log = a.log_text();
    assert!(log.contains("published v1") && log.contains("published v2"), "{log}");
    assert!(log.contains("admin key generated"));
    assert!(!log.contains(first.new_team_key.as_ref().unwrap().as_str()));
    assert!(!log.contains("remote vpn.example.com"));

    // An unknown publication.
    assert_eq!(a.publish(Some(id(999)), "x.macvpncatalog").unwrap_err(), PublishError::UnknownPublication);
}

#[test]
fn a_failed_write_leaves_the_version_unchanged() {
    let a = admin();
    a.publisher.generate_admin_key(AdminKeyRole::Primary).unwrap();
    let locked = a.tmp.path().join("locked");
    fs::create_dir_all(&locked).unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o555)).unwrap();
    let input = |catalog_id| PublishInput {
        catalog_id,
        name: "Acme VPN".into(),
        selection: a.selection(),
        path: locked.join("acme.macvpncatalog"),
    };
    assert!(matches!(a.publisher.publish(input(None)), Err(PublishError::Write(_))));
    assert!(a.publisher.publications().unwrap().is_empty(), "nothing stored, no team key kept");

    let first = a.publish(None, "acme.macvpncatalog").unwrap();
    assert!(matches!(a.publisher.publish(input(Some(first.catalog_id))), Err(PublishError::Write(_))));
    assert_eq!(a.publisher.publications().unwrap()[0].version, 1);
    assert!(a.publisher.rotate_team_key(first.catalog_id, &locked.join("acme.macvpncatalog")).is_err());
    let key = team(&first);
    let opened = open(&a.path("acme.macvpncatalog"), &key, a.fingerprint(AdminKeyRole::Primary)).unwrap();
    assert_eq!(opened.header.version, 1, "the old file and its team key still work");
    let next = a.publish(Some(first.catalog_id), "acme.macvpncatalog").unwrap();
    assert_eq!(next.version, 2);
    open(&a.path("acme.macvpncatalog"), &key, a.fingerprint(AdminKeyRole::Primary)).unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn an_invalid_name_or_selection_is_refused_before_anything_is_written() {
    let a = admin();
    a.publisher.generate_admin_key(AdminKeyRole::Primary).unwrap();
    let bad_name = a.publisher.publish(PublishInput {
        catalog_id: None,
        name: "  ".into(),
        selection: a.selection(),
        path: a.path("x.macvpncatalog"),
    });
    assert_eq!(bad_name.unwrap_err(), PublishError::InvalidName);
    let empty = a.publisher.publish(PublishInput {
        catalog_id: None,
        name: "Acme VPN".into(),
        selection: PublishSelection::default(),
        path: a.path("x.macvpncatalog"),
    });
    assert_eq!(empty.unwrap_err(), PublishError::Empty);
    assert!(!a.path("x.macvpncatalog").exists());
    let preview = a.publisher.preview(&a.selection()).unwrap();
    assert_eq!(preview.payload_counts, (0, 2, 0, 0));
}

#[test]
fn rotating_the_team_key_locks_out_the_old_key() {
    let a = admin();
    let primary = a.publisher.generate_admin_key(AdminKeyRole::Primary).unwrap();
    let first = a.publish(None, "acme.macvpncatalog").unwrap();
    let old = team(&first);
    let rotated = a.publisher.rotate_team_key(first.catalog_id, &a.path("acme.macvpncatalog")).unwrap();
    assert_eq!((rotated.catalog_id, rotated.version), (first.catalog_id, 2));
    let new = team(&rotated);
    assert_ne!(new.as_bytes(), old.as_bytes());
    assert_eq!(open(&a.path("acme.macvpncatalog"), &old, primary).unwrap_err(), CatalogError::WrongTeamKey);
    assert_eq!(open(&a.path("acme.macvpncatalog"), &new, primary).unwrap().header.version, 2);
    // The next publish keeps the new key.
    a.publish(Some(first.catalog_id), "acme.macvpncatalog").unwrap();
    assert_eq!(open(&a.path("acme.macvpncatalog"), &new, primary).unwrap().header.version, 3);
    assert!(a.log_text().contains("team key rotated"));
    assert!(!a.log_text().contains(rotated.new_team_key.as_ref().unwrap().as_str()));
}

#[test]
fn the_subscription_string_needs_the_master_password() {
    let a = admin();
    let primary = a.publisher.generate_admin_key(AdminKeyRole::Primary).unwrap();
    let first = a.publish(None, "acme.macvpncatalog").unwrap();
    let source = CatalogSource::File(PathBuf::from("/Volumes/Share/team/acme.macvpncatalog"));
    let text =
        a.publisher.subscription_string(first.catalog_id, Zeroizing::new(MASTER.into()), source.clone()).unwrap();
    let parsed = parse_subscription(&text).unwrap();
    assert_eq!(parsed.team_key.as_bytes(), team(&first).as_bytes());
    assert_eq!(parsed.fingerprint, primary);
    assert_eq!((parsed.catalog_id, parsed.min_version), (Some(first.catalog_id), Some(1)));
    assert!(!a.log_text().contains(text.as_str()));
    // A wrong password (the vault's retry delay applies to the next attempt).
    let wrong = a.publisher.subscription_string(first.catalog_id, Zeroizing::new("not the password".into()), source);
    assert!(matches!(wrong, Err(PublishError::WrongPassword)));
}

#[test]
fn the_badge_shows_when_a_published_connection_changed() {
    let a = admin();
    a.publisher.generate_admin_key(AdminKeyRole::Primary).unwrap();
    let first = a.publish(None, "acme.macvpncatalog").unwrap();
    let badges = a.publisher.published_badges().unwrap();
    let office = &badges[&uuid_string(&a.office)];
    assert_eq!(office.len(), 1);
    assert_eq!((office[0].name.as_str(), office[0].version, office[0].changed), ("Acme VPN", 1, false));

    a.vault
        .with(|v| {
            let c = v.connections()?.into_iter().find(|c| c.connection.id == a.office).unwrap().connection;
            v.save_connection(&c, Some(&format!("{OPENVPN}verb 3\n")))
        })
        .unwrap();
    let badges = a.publisher.published_badges().unwrap();
    assert!(badges[&uuid_string(&a.office)][0].changed);
    assert!(!badges[&uuid_string(&a.lab)][0].changed);
    assert_eq!(a.publisher.publications().unwrap()[0].changed, 1);

    a.publish(Some(first.catalog_id), "acme.macvpncatalog").unwrap();
    assert!(!a.publisher.published_badges().unwrap()[&uuid_string(&a.office)][0].changed);
    a.publisher.forget(first.catalog_id).unwrap();
    assert!(a.publisher.published_badges().unwrap().is_empty());
    assert!(a.path("acme.macvpncatalog").exists(), "forgetting keeps the file");
}

#[test]
fn the_backup_key_is_announced_kept_offline_promoted_and_followed_by_a_subscriber() {
    let a = admin();
    let primary = a.publisher.generate_admin_key(AdminKeyRole::Primary).unwrap();
    let backup = a.publisher.generate_admin_key(AdminKeyRole::Backup).unwrap();
    let first = a.publish(None, "acme.macvpncatalog").unwrap();
    let key = team(&first);
    let catalog = a.path("acme.macvpncatalog");
    assert_eq!(open(&catalog, &key, primary).unwrap().header.successor_key.map(|k| k.fingerprint()), Some(backup));

    // The subscriber.
    let f = CatalogFixture::new();
    f.fetcher.serve(fs::read(&catalog).unwrap());
    let (_, pending) = f
        .service
        .preview(SubscribeInput {
            source: CatalogSource::File(PathBuf::from("/Volumes/Share/team/acme.macvpncatalog")),
            team_key: TeamKey::from_bytes(key.as_bytes()).unwrap(),
            fingerprint: primary,
            bearer: None,
            catalog_id: Some(first.catalog_id),
            min_version: Some(1),
        })
        .unwrap();
    f.service.confirm(pending).unwrap();
    assert_eq!(f.connection_names(), ["Lab", "Office"]);

    // Export with "remove from this Mac": refused paths keep the key; a short password is refused.
    let locked = a.tmp.path().join("locked");
    fs::create_dir_all(&locked).unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o555)).unwrap();
    let pw = || Zeroizing::new(KEY_FILE_PASSWORD.to_string());
    assert!(matches!(
        a.publisher.export_backup_key(&a.path("b.macvpnadminkey"), Zeroizing::new("short".into()), true),
        Err(PublishError::WeakPassword(_))
    ));
    assert!(a.publisher.export_backup_key(&locked.join("b.macvpnadminkey"), pw(), true).is_err());
    assert!(a.vault.with_read(|v| v.admin_key(AdminKeyRole::Backup)).unwrap().is_some(), "not removed");
    let key_file = a.path("Acme backup.macvpnadminkey");
    a.publisher.export_backup_key(&key_file, pw(), true).unwrap();
    assert_eq!(mode(&key_file), 0o600);
    assert!(a.vault.with_read(|v| v.admin_key(AdminKeyRole::Backup)).unwrap().is_none(), "removed after the write");
    let keys = a.publisher.admin_keys().unwrap();
    assert!(keys.iter().any(|k| k.role == AdminKeyRole::Backup && k.offline && k.fingerprint == backup));
    assert!(a.publisher.promote_backup_key().is_err(), "an offline key must be imported first");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();

    // v2 still announces the offline key; the subscriber stores it.
    a.publish(Some(first.catalog_id), "acme.macvpncatalog").unwrap();
    assert_eq!(open(&catalog, &key, primary).unwrap().header.successor_key.map(|k| k.fingerprint()), Some(backup));
    f.fetcher.serve(fs::read(&catalog).unwrap());
    assert!(matches!(f.service.refresh(first.catalog_id, RefreshTrigger::Manual), RefreshResult::Applied(_)));
    let record = f.vault.with_read(|v| v.subscription(first.catalog_id)).unwrap().unwrap();
    assert_eq!(record.successor_key.map(|k| k.fingerprint()), Some(backup));

    // Import (a wrong password first), promote, publish: signed by the backup key, and the subscriber follows.
    assert!(matches!(
        a.publisher.import_admin_key(&key_file, Zeroizing::new("wrong password!".into())),
        Err(PublishError::CannotOpen)
    ));
    assert_eq!(a.publisher.import_admin_key(&key_file, pw()).unwrap(), backup);
    assert_eq!(a.publisher.promote_backup_key().unwrap(), backup);
    let keys = a.publisher.admin_keys().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!((keys[0].role, keys[0].fingerprint), (AdminKeyRole::Primary, backup));
    let third = a.publish(Some(first.catalog_id), "acme.macvpncatalog").unwrap();
    assert_eq!(third.fingerprint, backup);
    let opened = open(&catalog, &key, backup).unwrap();
    assert_eq!(opened.header.successor_key, None);
    f.fetcher.serve(fs::read(&catalog).unwrap());
    assert!(matches!(f.service.refresh(first.catalog_id, RefreshTrigger::Manual), RefreshResult::Applied(_)));
    let record = f.vault.with_read(|v| v.subscription(first.catalog_id)).unwrap().unwrap();
    assert_eq!((record.pinned, record.applied_version), (backup, Some(3)));
    let log = a.log_text();
    assert!(log.contains("admin key imported") && log.contains("admin key promoted"), "{log}");
    assert!(!log.contains(KEY_FILE_PASSWORD));
}

#[test]
fn the_preview_warns_when_a_publish_would_drop_an_announced_successor() {
    let a = admin();
    a.publisher.generate_admin_key(AdminKeyRole::Primary).unwrap();
    let backup = a.publisher.generate_admin_key(AdminKeyRole::Backup).unwrap();
    a.publish(None, "acme.macvpncatalog").unwrap();
    assert!(a.publisher.preview(&a.selection()).unwrap().successor_dropped_in.is_empty());
    // The backup key is deleted: the next version of "Acme VPN" would no longer announce it.
    a.vault.with(|v| v.delete_admin_key(&backup)).unwrap();
    assert_eq!(a.publisher.preview(&a.selection()).unwrap().successor_dropped_in, ["Acme VPN"]);
}

#[test]
fn promoting_the_announced_successor_does_not_warn() {
    let a = admin();
    a.publisher.generate_admin_key(AdminKeyRole::Primary).unwrap();
    a.publisher.generate_admin_key(AdminKeyRole::Backup).unwrap();
    a.publish(None, "acme.macvpncatalog").unwrap();
    a.publisher.promote_backup_key().unwrap();
    assert!(a.publisher.preview(&a.selection()).unwrap().successor_dropped_in.is_empty());
}

#[test]
fn the_version_and_a_new_team_key_are_reserved_before_the_file_is_written() {
    let a = admin();
    let primary = a.publisher.generate_admin_key(AdminKeyRole::Primary).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let (vault, sink) = (a.vault.clone(), seen.clone());
    a.publisher.set_before_write(move || {
        let stored = vault.with_read(|v| {
            let p = v.publications()?;
            let key = match p.first() {
                Some(p) => Some(v.publication_team_key(p.catalog_id)?.as_bytes().to_vec()),
                None => None,
            };
            Ok(p.first().map(|p| (p.version, key)))
        });
        sink.lock().unwrap().push(stored.unwrap());
    });
    let first = a.publish(None, "acme.macvpncatalog").unwrap();
    let rotated = a.publisher.rotate_team_key(first.catalog_id, &a.path("acme.macvpncatalog")).unwrap();
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen[0], Some((1, Some(team(&first).as_bytes().to_vec()))), "v1 and its team key, before the write");
    assert_eq!(
        seen[1],
        Some((2, Some(team(&rotated).as_bytes().to_vec()))),
        "v2 and the rotated key, before the write"
    );
    // Whatever happens after the write, the file's version is never published again.
    let next = a.publish(Some(first.catalog_id), "acme.macvpncatalog").unwrap();
    assert_eq!(next.version, 3);
    assert_eq!(open(&a.path("acme.macvpncatalog"), &team(&rotated), primary).unwrap().header.version, 3);
}

#[test]
fn rotating_the_team_key_needs_a_reviewed_publish_of_any_change() {
    let a = admin();
    let primary = a.publisher.generate_admin_key(AdminKeyRole::Primary).unwrap();
    let first = a.publish(None, "acme.macvpncatalog").unwrap();
    a.vault
        .with(|v| {
            let c = v.connections()?.into_iter().find(|c| c.connection.id == a.office).unwrap().connection;
            v.save_connection(&c, Some(&format!("{OPENVPN}verb 3\n")))
        })
        .unwrap();
    // The rotation would republish the changed connection without its review: refused, nothing written.
    let refused = a.publisher.rotate_team_key(first.catalog_id, &a.path("acme.macvpncatalog"));
    assert_eq!(refused.unwrap_err(), PublishError::ReviewFirst);
    assert_eq!(open(&a.path("acme.macvpncatalog"), &team(&first), primary).unwrap().header.version, 1);
    assert_eq!(a.publisher.publications().unwrap()[0].version, 1);
    // After a publish with the review, the rotation goes through.
    a.publish(Some(first.catalog_id), "acme.macvpncatalog").unwrap();
    let rotated = a.publisher.rotate_team_key(first.catalog_id, &a.path("acme.macvpncatalog")).unwrap();
    assert_eq!(rotated.version, 3);
}

#[test]
fn the_backup_seed_is_removed_only_after_the_written_file_opens_with_the_password() {
    let a = admin();
    a.publisher.generate_admin_key(AdminKeyRole::Primary).unwrap();
    a.publisher.generate_admin_key(AdminKeyRole::Backup).unwrap();
    // The file is damaged right after it was written (a full disk, a sync tool, a swapped file).
    a.publisher.set_after_key_write(|path| {
        let mut bytes = fs::read(path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x55;
        fs::write(path, bytes).unwrap();
    });
    let pw = || Zeroizing::new(KEY_FILE_PASSWORD.to_string());
    let result = a.publisher.export_backup_key(&a.path("b.macvpnadminkey"), pw(), true);
    assert!(result.is_err(), "{result:?}");
    assert!(a.vault.with_read(|v| v.admin_key(AdminKeyRole::Backup)).unwrap().is_some(), "the seed stays");
    assert!(a.publisher.admin_keys().unwrap().iter().all(|k| !k.offline));
}
