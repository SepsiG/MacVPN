//! The backup and restore orchestration (plan B Task 21) over a real vault in a temp directory and fakes for the
//! preferences and the profile installer: backup with an own or the master password, open (a wrong password and a
//! damaged file give one message, a newer file its own), merge with each conflict mode, replace with the counted
//! confirmation, the first-run restore, the preferences applied one by one (the control API never ticked by
//! default), the native profiles reinstalled one at a time, and the window ownership of a staged restore.

mod common;

use common::TempDir;
use macvpn_app_core::backup::{
    BackupService, PasswordSource, Preference, PreferencePort, RestoreChoice, check_backup_password, default_file_name,
    parse_choice, preference_choices,
};
use macvpn_app_core::deps::{NativeProfile, NativeProfiles};
use macvpn_app_core::vault::VaultLifecycle;
use macvpn_core::date::Date;
use macvpn_core::l10n::{AppLanguage, with_language};
use macvpn_core::mobileconfig;
use macvpn_core::models::{Connection, NativeSettings, SecretField, VPNKind, uuid_string};
use macvpn_core::vault::backup::{BackupPreferences, ConflictMode};
use macvpn_core::vault::{FixedEntropy, KdfParams, MemoryKeyStore};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use zeroize::Zeroizing;

const MASTER: &str = "correct horse battery";
const BACKUP_PW: &str = "backup password 42";
const WINDOW: &str = "restore";

fn pw(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_string())
}

fn id(n: u128) -> Uuid {
    Uuid::from_u128(0x2000_0000_0000_4000_8000_0000_0000_0000 + n)
}

fn now() -> Date {
    Date::parse_iso8601("2026-10-19T12:00:00Z").unwrap()
}

#[derive(Default)]
struct FakePrefs {
    current: Mutex<BackupPreferences>,
    applied: Mutex<Vec<(Preference, bool)>>,
    fail: Mutex<Option<Preference>>,
    /// How often the master password confirmation for automatic unlock was asked for.
    confirms: Mutex<usize>,
}

impl PreferencePort for FakePrefs {
    fn current(&self) -> BackupPreferences {
        *self.current.lock().unwrap()
    }

    fn apply(&self, preference: Preference, on: bool) -> Result<(), String> {
        if *self.fail.lock().unwrap() == Some(preference) {
            return Err("refused".into());
        }
        self.applied.lock().unwrap().push((preference, on));
        let mut c = self.current.lock().unwrap();
        match preference {
            Preference::AutoCheck => c.auto_check = on,
            Preference::Delay24h => c.delay_24h = on,
            Preference::LaunchAtLogin => c.launch_at_login = on,
            Preference::ControlApi => c.control_api_enabled = on,
            Preference::AutoUnlock => c.auto_unlock = on,
        }
        Ok(())
    }

    fn confirm_auto_unlock(&self) -> Result<(), String> {
        *self.confirms.lock().unwrap() += 1;
        Ok(())
    }
}

/// An installed profile: the connection, the profile bytes, the file name, whether the service existed.
type Installed = (Uuid, Vec<u8>, String, bool);

#[derive(Default)]
struct FakeInstaller {
    installed: Mutex<Vec<Installed>>,
    /// WinVPN: no approval step, and Cisco IPsec refused (option A).
    windows: bool,
}

const CISCO_REFUSED: &str = "Cisco IPsec is not supported by Windows.";

impl NativeProfiles for FakeInstaller {
    fn build(&self, connection: &Connection, psk: &str) -> Result<NativeProfile, String> {
        common::MobileconfigProfiles::default().build(connection, psk)
    }

    fn install(&self, id: &Uuid, profile: &[u8], file_name: &str, service_existed: bool) -> Result<(), String> {
        if self.windows && String::from_utf8_lossy(profile).contains("XAuth") {
            return Err(CISCO_REFUSED.into());
        }
        self.installed.lock().unwrap().push((*id, profile.to_vec(), file_name.to_string(), service_existed));
        Ok(())
    }

    fn needs_approval(&self) -> bool {
        !self.windows
    }
}

struct Fixture {
    _tmp: TempDir,
    service: BackupService,
    prefs: FakePrefs,
}

impl Fixture {
    /// A vault (created and unlocked unless `create` is false) with its backup service.
    fn new(create: bool) -> Fixture {
        let tmp = TempDir::new();
        let vault = Arc::new(VaultLifecycle::new(
            tmp.path().join("MacVPN"),
            Arc::new(MemoryKeyStore::new()),
            Arc::new(FixedEntropy::new(3)),
            KdfParams::insecure_for_tests(),
        ));
        vault.set_logger(|_| {});
        if create {
            vault.create(pw(MASTER), false).unwrap();
        }
        let service =
            BackupService::new(vault, Arc::new(FixedEntropy::new(9)), KdfParams::insecure_for_tests(), "1.2.0");
        Fixture { _tmp: tmp, service, prefs: FakePrefs::default() }
    }

    fn save(&self, c: &Connection, config: &str) {
        self.service.vault().with(|v| v.save_connection(c, Some(config))).unwrap();
    }

    fn names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .service
            .vault()
            .with_read(|v| Ok(v.connections()?.into_iter().map(|s| s.connection.name).collect()))
            .unwrap();
        names.sort();
        names
    }

    fn backup(&self, prefs: BackupPreferences) -> Vec<u8> {
        self.service.make(pw(MASTER), PasswordSource::Own(pw(BACKUP_PW)), prefs, now()).unwrap()
    }

    fn open(&self, bytes: &[u8]) -> macvpn_app_core::backup::RestoreSummary {
        self.service.open(WINDOW, bytes, pw(BACKUP_PW), false).unwrap()
    }

    fn apply(&self, choice: RestoreChoice) -> Result<macvpn_app_core::backup::RestoreOutcome, String> {
        self.service.apply(WINDOW, choice, &HashSet::new(), now(), &self.prefs)
    }
}

fn openvpn(n: u128, name: &str) -> Connection {
    Connection::with_id(id(n), name, VPNKind::Openvpn, now())
}

fn l2tp(n: u128, name: &str) -> Connection {
    let mut c = Connection::with_id(id(n), name, VPNKind::L2tp, now());
    c.native = Some(NativeSettings {
        server: "l2tp.example.com".into(),
        account: "bob".into(),
        group_name: String::new(),
        send_all_traffic: true,
    });
    c.native_service_name = Some(name.into());
    c
}

const OVPN: &str = "client\ndev tun\nremote vpn.example.com 1194\n";

fn en<T>(f: impl FnOnce() -> T) -> T {
    with_language(AppLanguage::En, f)
}

#[test]
fn file_name_password_rule_and_choices() {
    assert_eq!(default_file_name("MacVPN", "2026-10-19"), "MacVPN-backup-2026-10-19.macvpnbackup");
    // The product's name: WinVPN's backups are named after WinVPN (the format and extension are shared).
    assert_eq!(default_file_name("WinVPN", "2026-10-19"), "WinVPN-backup-2026-10-19.macvpnbackup");
    en(|| {
        assert_eq!(
            check_backup_password("short"),
            Err("The backup password must be at least 10 characters long".to_string())
        );
    });
    assert!(check_backup_password("ten chars!").is_ok());
    assert_eq!(parse_choice("merge", Some("overwrite"), None), Ok(RestoreChoice::Merge(ConflictMode::Overwrite)));
    assert_eq!(parse_choice("merge", Some("keepExisting"), None), Ok(RestoreChoice::Merge(ConflictMode::KeepExisting)));
    assert_eq!(parse_choice("merge", Some("keepBoth"), None), Ok(RestoreChoice::Merge(ConflictMode::KeepBoth)));
    assert_eq!(parse_choice("replace", None, Some(3)), Ok(RestoreChoice::Replace { expected_lost: 3 }));
    for (mode, conflict, lost) in [
        ("merge", None, None),
        ("merge", Some("both"), None),
        ("merge", Some("overwrite"), Some(1)),
        ("replace", None, None),
        ("replace", Some("overwrite"), Some(1)),
        ("wipe", None, Some(1)),
    ] {
        assert!(parse_choice(mode, conflict, lost).is_err(), "{mode} {conflict:?} {lost:?}");
    }
    for p in Preference::ALL {
        let raw = serde_json::to_value(p).unwrap();
        assert_eq!(Preference::parse(raw.as_str().unwrap()), Ok(p));
    }
    assert!(Preference::parse("controlAPI").is_err());
}

#[test]
fn a_short_own_password_and_a_wrong_master_password_are_refused() {
    let f = Fixture::new(true);
    en(|| {
        assert_eq!(
            f.service.make(pw(MASTER), PasswordSource::Own(pw("short")), BackupPreferences::default(), now()),
            Err("The backup password must be at least 10 characters long".to_string())
        );
        assert_eq!(
            f.service.make(pw("not the master pw"), PasswordSource::Master, BackupPreferences::default(), now()),
            Err("The master password is not correct.".to_string())
        );
    });
    // An own backup password does not replace the master password's check (with the unlock delay).
    std::thread::sleep(std::time::Duration::from_millis(1100));
    en(|| {
        assert_eq!(
            f.service.make(
                pw("not the master pw"),
                PasswordSource::Own(pw(BACKUP_PW)),
                BackupPreferences::default(),
                now()
            ),
            Err("The master password is not correct.".to_string())
        );
        assert!(
            f.service
                .make(pw(MASTER), PasswordSource::Own(pw(BACKUP_PW)), BackupPreferences::default(), now())
                .unwrap_err()
                .starts_with("Wait "),
            "the unlock delay applies"
        );
    });
    // The master password: the backup opens with it.
    f.save(&openvpn(1, "Office"), OVPN);
    std::thread::sleep(std::time::Duration::from_millis(2100));
    let bytes = f.service.make(pw(MASTER), PasswordSource::Master, BackupPreferences::default(), now()).unwrap();
    let summary = f.service.open(WINDOW, &bytes, pw(MASTER), false).unwrap();
    assert_eq!((summary.connections, summary.conflicts, summary.added), (1, 1, 0));
}

#[test]
fn a_wrong_password_a_damaged_file_and_a_newer_file() {
    let f = Fixture::new(true);
    f.save(&openvpn(1, "Office"), OVPN);
    let bytes = f.backup(BackupPreferences::default());
    en(|| {
        let generic = "The backup cannot be opened. The password is wrong, or the file is damaged.".to_string();
        assert_eq!(f.service.open(WINDOW, &bytes, pw("wrong password!"), false), Err(generic.clone()));
        let mut damaged = bytes.clone();
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        assert_eq!(f.service.open(WINDOW, &damaged, pw(BACKUP_PW), false), Err(generic.clone()));
        assert_eq!(f.service.open(WINDOW, &bytes[..100], pw(BACKUP_PW), false), Err(generic));
        let mut newer = bytes.clone();
        newer[8..10].copy_from_slice(&2u16.to_be_bytes());
        assert_eq!(
            f.service.open(WINDOW, &newer, pw(BACKUP_PW), false),
            Err("This backup was made by a newer MacVPN. Update MacVPN to restore it.".to_string())
        );
    });
    assert!(!f.service.has_staged(WINDOW));
}

#[test]
fn merge_with_each_mode() {
    for (mode, expected) in [
        (ConflictMode::Overwrite, vec!["Office", "Old site"]),
        (ConflictMode::KeepExisting, vec!["Office renamed", "Old site"]),
        (ConflictMode::KeepBoth, vec!["Office (backup)", "Office renamed", "Old site"]),
    ] {
        let f = Fixture::new(true);
        f.save(&openvpn(1, "Office"), OVPN);
        f.save(&openvpn(2, "Old site"), OVPN);
        let bytes = f.backup(BackupPreferences::default());
        f.save(&openvpn(1, "Office renamed"), OVPN);
        f.service.vault().with(|v| v.delete_connection(&id(2))).unwrap();
        let summary = f.open(&bytes);
        assert_eq!((summary.added, summary.conflicts, summary.lost_on_replace), (1, 1, 0), "{mode:?}");
        assert!(!summary.fresh);
        let outcome = f.apply(RestoreChoice::Merge(mode)).unwrap();
        assert!(outcome.skipped_catalog_items.is_empty(), "no team catalog here");
        assert_eq!(f.names(), expected, "{mode:?}");
        // The staged backup is used up.
        assert!(!f.service.has_staged(WINDOW));
        assert!(f.apply(RestoreChoice::Merge(mode)).is_err());
    }
}

#[test]
fn replace_names_the_lost_count_and_refuses_a_stale_one() {
    let f = Fixture::new(true);
    f.save(&openvpn(1, "Office"), OVPN);
    let bytes = f.backup(BackupPreferences::default());
    f.save(&openvpn(3, "Added later"), OVPN);
    f.save(&openvpn(4, "Added later too"), OVPN);
    let summary = f.open(&bytes);
    assert_eq!(summary.lost_on_replace, 2);
    // The vault changed after the summary (or the window sent another number): refused, nothing changed, and the
    // backup stays open for another try.
    en(|| {
        assert_eq!(
            f.apply(RestoreChoice::Replace { expected_lost: 1 }),
            Err("The vault changed since the summary. Review the restore again.".to_string())
        );
    });
    assert_eq!(f.names(), ["Added later", "Added later too", "Office"]);
    assert!(f.service.has_staged(WINDOW));
    f.apply(RestoreChoice::Replace { expected_lost: 2 }).unwrap();
    assert_eq!(f.names(), ["Office"]);
}

/// "Replace everything" names what it takes from the publisher side too: an admin key the backup replaces with its
/// own counts in the number the confirmation sends; one the backup has nothing for stays.
#[test]
fn replace_names_the_admin_keys_it_replaces() {
    use macvpn_core::catalog::keys::AdminKey;
    use macvpn_core::vault::AdminKeyRole;
    let admin = |seed| AdminKey::generate(&FixedEntropy::new(seed)).unwrap();
    let f = Fixture::new(true);
    f.save(&openvpn(1, "Office"), OVPN);
    f.service.vault().with(|v| v.save_admin_key(&admin(1), AdminKeyRole::Primary, now())).unwrap();
    let bytes = f.backup(BackupPreferences::default());
    f.service
        .vault()
        .with(|v| {
            v.delete_admin_key(&admin(1).public().fingerprint())?;
            v.save_admin_key(&admin(2), AdminKeyRole::Primary, now())?;
            v.save_admin_key(&admin(3), AdminKeyRole::Backup, now())
        })
        .unwrap();
    let summary = f.open(&bytes);
    assert_eq!(summary.lost_on_replace, 0);
    assert_eq!(summary.lost_admin_keys, ["primary"]);
    assert!(summary.lost_subscriptions.is_empty() && summary.lost_publications.is_empty());
    assert_eq!(summary.lost_total, 1);
    en(|| assert!(f.apply(RestoreChoice::Replace { expected_lost: 0 }).is_err(), "the items alone are stale"));
    f.apply(RestoreChoice::Replace { expected_lost: 1 }).unwrap();
    let keys = f.service.vault().with_read(|v| v.admin_keys()).unwrap();
    let public = |role| keys.iter().find(|k| k.role == role).map(|k| k.public);
    assert_eq!(public(AdminKeyRole::Primary), Some(admin(1).public()), "the backup's");
    assert_eq!(public(AdminKeyRole::Backup), Some(admin(3).public()), "not in the backup: kept");
}

#[test]
fn acknowledged_risky_directives_are_listed_before_the_restore() {
    let f = Fixture::new(true);
    let mut risky = openvpn(1, "Risky");
    risky.acknowledged_risky_directives = vec!["up".into()];
    f.save(&risky, "client\nscript-security 2\nup /bin/true\n");
    f.save(&openvpn(2, "Plain"), OVPN);
    let bytes = f.backup(BackupPreferences::default());
    assert_eq!(f.open(&bytes).acknowledged_risky, ["Risky"]);
}

#[test]
fn only_the_window_that_opened_it_restores() {
    let f = Fixture::new(true);
    f.save(&openvpn(1, "Office"), OVPN);
    let bytes = f.backup(BackupPreferences::default());
    f.open(&bytes);
    assert!(
        f.service
            .apply("backup", RestoreChoice::Merge(ConflictMode::Overwrite), &HashSet::new(), now(), &f.prefs)
            .is_err()
    );
    // Not as a fresh restore either.
    assert!(f.service.apply_fresh(WINDOW, &HashSet::new(), now(), &f.prefs).is_err());
    assert!(f.service.has_staged(WINDOW));
    f.service.discard("backup");
    assert!(f.service.has_staged(WINDOW));
    f.service.discard(WINDOW);
    assert!(!f.service.has_staged(WINDOW));
}

#[test]
fn a_locked_vault_neither_backs_up_nor_restores() {
    let f = Fixture::new(true);
    let bytes = f.backup(BackupPreferences::default());
    f.service.vault().lock();
    assert!(!f.service.available());
    en(|| {
        let locked = Err("The vault is locked. Unlock it first.".to_string());
        assert_eq!(
            f.service.make(pw(MASTER), PasswordSource::Own(pw(BACKUP_PW)), BackupPreferences::default(), now()),
            locked
        );
        assert_eq!(
            f.service.open(WINDOW, &bytes, pw(BACKUP_PW), false).map(|_| ()),
            locked.clone().map(|_: Vec<u8>| ())
        );
    });
}

#[test]
fn preferences_are_applied_only_when_ticked() {
    let backed_up = BackupPreferences {
        auto_check: false,
        delay_24h: true,
        launch_at_login: true,
        control_api_enabled: true,
        auto_unlock: true,
    };
    let current = BackupPreferences { auto_check: true, delay_24h: true, ..BackupPreferences::default() };
    let choices = preference_choices(&backed_up, &current);
    let ticked: Vec<(Preference, bool)> = choices.iter().map(|c| (c.key, c.ticked)).collect();
    assert_eq!(
        ticked,
        [
            (Preference::AutoCheck, true),
            (Preference::Delay24h, false),
            (Preference::LaunchAtLogin, true),
            // Differs, but never ticked by default.
            (Preference::ControlApi, false),
            (Preference::AutoUnlock, true),
        ]
    );

    let f = Fixture::new(true);
    *f.prefs.current.lock().unwrap() = current;
    f.save(&openvpn(1, "Office"), OVPN);
    let bytes = f.backup(backed_up);
    f.open(&bytes);
    let outcome = f.apply(RestoreChoice::Merge(ConflictMode::Overwrite)).unwrap();
    assert_eq!(outcome.preferences, choices);
    // Nothing is applied by the restore itself.
    assert!(f.prefs.applied.lock().unwrap().is_empty());
    // The window names the keys; the values are the backup's. Automatic unlock is never turned on by the restore:
    // the master password confirms it (the app opens its window), and the row says so.
    *f.prefs.fail.lock().unwrap() = Some(Preference::Delay24h);
    let failures = en(|| {
        f.service
            .apply_preferences(
                WINDOW,
                &[Preference::LaunchAtLogin, Preference::AutoUnlock, Preference::LaunchAtLogin, Preference::Delay24h],
                &f.prefs,
            )
            .unwrap()
    });
    let keys: Vec<Preference> = failures.iter().map(|f| f.key).collect();
    assert_eq!(keys, [Preference::AutoUnlock, Preference::Delay24h]);
    assert_eq!(
        failures[0].message,
        "Enter your master password in the window that opened to turn on automatic unlock."
    );
    assert_eq!(*f.prefs.applied.lock().unwrap(), [(Preference::LaunchAtLogin, true)]);
    assert_eq!(*f.prefs.confirms.lock().unwrap(), 1);
    // Another window: refused.
    assert!(f.service.apply_preferences("backup", &[Preference::AutoCheck], &f.prefs).is_err());
}

#[test]
fn native_profiles_are_reinstalled_one_by_one() {
    let f = Fixture::new(true);
    let native = l2tp(5, "Branch L2TP");
    f.save(&native, "");
    let key = uuid_string(&native.id);
    f.service.vault().with(|v| v.set_secret(&key, SecretField::Psk, "shared-psk-123")).unwrap();
    f.service.vault().with(|v| v.set_secret(&key, SecretField::Password, "user-pass-456")).unwrap();
    f.save(&openvpn(1, "Office"), OVPN);
    let bytes = f.backup(BackupPreferences::default());
    let summary = f.open(&bytes);
    assert_eq!(summary.native_profiles, 1);
    let outcome = f.apply(RestoreChoice::Replace { expected_lost: 0 }).unwrap();
    assert_eq!(outcome.native_profiles.len(), 1);
    assert_eq!(outcome.native_profiles[0].name, "Branch L2TP");
    assert!(!outcome.native_profiles[0].installed);

    let installer = FakeInstaller::default();
    assert!(f.service.reinstall_profile(WINDOW, &uuid_string(&id(1)), &installer, |_| false).is_err());
    let list = f.service.reinstall_profile(WINDOW, &key, &installer, |_| true).unwrap();
    assert!(list[0].installed);
    let installed = installer.installed.lock().unwrap();
    assert_eq!(installed.len(), 1);
    let (iid, data, file, existed) = &installed[0];
    assert_eq!(*iid, native.id);
    assert!(file.ends_with(".mobileconfig"), "{file}");
    assert!(*existed);
    // As the editor makes it: the PSK in the profile (`mobileconfig::generate`), never the password.
    let stored = f
        .service
        .vault()
        .with_read(|v| Ok(v.connections()?.into_iter().find(|s| s.connection.id == native.id).unwrap().connection))
        .unwrap();
    assert_eq!(*data, mobileconfig::generate(&stored, "shared-psk-123").unwrap());
    assert!(!String::from_utf8_lossy(data).contains("user-pass-456"));
}

/// WinVPN 2c Task 13: where installing needs no approval, the restore's native profiles are all installed at once
/// (as macOS installs them one by one); Cisco IPsec's refusal is the row's note, not a failure of the restore. Where
/// the user approves each (macOS) nothing is installed by itself.
#[test]
fn without_approval_every_restored_native_profile_is_installed() {
    let f = Fixture::new(true);
    let branch = l2tp(5, "Branch L2TP");
    f.save(&branch, "");
    let mut cisco = l2tp(6, "Office Cisco");
    cisco.kind = VPNKind::Cisco;
    cisco.native.as_mut().unwrap().group_name = "staff".into();
    f.save(&cisco, "");
    f.service.vault().with(|v| v.set_secret(&uuid_string(&branch.id), SecretField::Psk, "shared-psk-123")).unwrap();
    let bytes = f.backup(BackupPreferences::default());
    f.open(&bytes);
    let outcome = f.apply(RestoreChoice::Replace { expected_lost: 0 }).unwrap();
    assert_eq!(outcome.native_profiles.len(), 2);

    let macos = FakeInstaller::default();
    let list = f.service.install_profiles_without_approval(WINDOW, &macos, |_| false).unwrap();
    assert!(list.iter().all(|n| !n.installed && n.note.is_none()));
    assert!(macos.installed.lock().unwrap().is_empty(), "macOS: the user approves each");
    let json = serde_json::to_value(&list).unwrap();
    assert!(json[0].get("note").is_none(), "macOS: absent");

    let windows = FakeInstaller { windows: true, ..FakeInstaller::default() };
    assert!(f.service.install_profiles_without_approval("other", &windows, |_| false).is_err());
    let list = f.service.install_profiles_without_approval(WINDOW, &windows, |_| false).unwrap();
    let by_name = |name: &str| list.iter().find(|n| n.name == name).unwrap().clone();
    assert!(by_name("Branch L2TP").installed);
    assert_eq!(by_name("Branch L2TP").note, None);
    assert!(!by_name("Office Cisco").installed);
    assert_eq!(by_name("Office Cisco").note.as_deref(), Some(CISCO_REFUSED));
    let installed = windows.installed.lock().unwrap();
    assert_eq!(installed.len(), 1);
    assert_eq!(installed[0].0, branch.id);
    assert_eq!(f.names(), ["Branch L2TP", "Office Cisco"], "the restore stands");
}

#[test]
fn fresh_restore_into_the_new_vault() {
    // The source Mac.
    let source = Fixture::new(true);
    let mut risky = openvpn(1, "Risky");
    risky.acknowledged_risky_directives = vec!["up".into()];
    source.save(&risky, "client\nscript-security 2\nup /bin/true\n");
    source.save(&openvpn(2, "Office"), OVPN);
    let bytes = source.backup(BackupPreferences { launch_at_login: true, ..BackupPreferences::default() });

    // The new Mac: no vault yet. The file opens before the vault exists.
    let f = Fixture::new(false);
    let summary = f.service.open("vault-create", &bytes, pw(BACKUP_PW), true).unwrap();
    assert!(summary.fresh);
    assert_eq!((summary.added, summary.conflicts, summary.lost_on_replace), (2, 0, 0));
    assert_eq!(summary.acknowledged_risky, ["Risky"]);
    // Not before the vault exists.
    assert!(f.service.apply_fresh("vault-create", &HashSet::new(), now(), &f.prefs).is_err());
    assert!(f.service.has_staged("vault-create"));
    // The create steps, then the restore.
    f.service.vault().create(pw(MASTER), true).unwrap();
    // The ordinary restore is not the fresh one.
    assert!(
        f.service
            .apply("vault-create", RestoreChoice::Replace { expected_lost: 0 }, &HashSet::new(), now(), &f.prefs)
            .is_err()
    );
    let outcome = f.service.apply_fresh("vault-create", &HashSet::new(), now(), &f.prefs).unwrap();
    assert_eq!(f.names(), ["Office", "Risky"]);
    // A replace keeps the acknowledgements.
    let kept = f
        .service
        .vault()
        .with_read(|v| Ok(v.connections()?.into_iter().find(|s| s.connection.id == id(1)).unwrap()))
        .unwrap();
    assert_eq!(kept.connection.acknowledged_risky_directives, ["up"]);
    assert!(outcome.preferences.iter().any(|p| p.key == Preference::LaunchAtLogin && p.ticked));

    // A vault with data is not a fresh target.
    en(|| {
        assert_eq!(
            f.service.open("vault-create", &bytes, pw(BACKUP_PW), true),
            Err("A restore from the first-run window needs a new, empty vault.".to_string())
        );
    });
}

#[test]
fn fresh_restore_in_place_of_the_migration() {
    let source = Fixture::new(true);
    source.save(&openvpn(2, "Office"), OVPN);
    let bytes = source.backup(BackupPreferences::default());
    // 1.1 data waits for the migration: the app reads it read-only, no vault yet.
    let f = Fixture::new(false);
    f.service.vault().set_legacy_read_only(Some(String::new()));
    assert!(f.service.open("vault-create", &bytes, pw(BACKUP_PW), true).unwrap().fresh);
    f.service.vault().create(pw(MASTER), false).unwrap();
    f.service.apply_fresh("vault-create", &HashSet::new(), now(), &f.prefs).unwrap();
    assert_eq!(f.names(), ["Office"]);
    // A locked vault is not a fresh target.
    f.service.vault().lock();
    en(|| {
        assert_eq!(
            f.service.open("vault-create", &bytes, pw(BACKUP_PW), true),
            Err("A restore from the first-run window needs a new, empty vault.".to_string())
        );
    });
}
