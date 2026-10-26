//! Native L2TP / Cisco profile secrets with the vault (plan B Task 12, spec 2.6, vault spike report D).
//!
//! The decision until the manual test D.3 passes: the PSK stays in the generated profile (macOS owns it), while
//! MacVPN's own copies of the PSK and the password live in the vault and are passed at start through the
//! `SCNetworkConnectionStart` user options. The password is never in a profile.
//!
//! The secret store here is a small adapter over the vault lifecycle, standing in for the app's vault-backed
//! `SecretReader` / `SecretWriter`. Fakes only: no profile is installed, nothing connects, no Keychain is used.

mod common;

use common::*;
use macvpn_app_core::deps::{SecretField, SecretReader, SecretWriter, SystemVpn};
use macvpn_app_core::editor::{self, EditorDeps};
use macvpn_app_core::vault::VaultLifecycle;
use macvpn_app_core::{ConnectionManager, Dependencies};
use macvpn_core::l10n::AppLanguage;
use macvpn_core::models::{Connection, NativeSettings, OTPSetting, VPNKind, uuid_string};
use macvpn_core::vault::{FixedEntropy, KdfParams, MemoryKeyStore};
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroizing;

const L2TP_SERVICE: &str = "38B51E6D-5D77-4ABE-BFDF-B0E5DE45B1C4";
const CISCO_SERVICE: &str = "052ED352-624D-4F75-BD84-D3E278CFD84F";

/// The secrets table of an unlocked vault, keyed like the 1.1 Keychain accounts (the managed connection's UUID,
/// or a system VPN's service ID).
struct VaultBacked(Arc<VaultLifecycle>);

impl SecretReader for VaultBacked {
    fn get(&self, id: &Uuid, field: SecretField) -> Option<String> {
        self.0.with(|v| v.secret(&uuid_string(id), field)).ok().flatten().map(|s| s.to_string())
    }
}

impl SecretWriter for VaultBacked {
    fn set(&self, value: &str, id: &Uuid, field: SecretField) {
        self.0.with(|v| v.set_secret(&uuid_string(id), field, value)).unwrap();
    }

    fn delete_all(&self, id: &Uuid) {
        self.0.with(|v| v.delete_secrets(&uuid_string(id))).unwrap();
    }

    fn remove_all(&self) {
        self.0.with(|v| v.delete_all_secrets()).unwrap();
    }
}

struct Setup {
    fx: Fixture,
    vault: Arc<VaultLifecycle>,
    secrets: Arc<VaultBacked>,
}

impl Setup {
    fn new() -> Setup {
        let fx = Fixture::new(AppLanguage::En);
        let vault = Arc::new(VaultLifecycle::new(
            fx.dir.path().join("vault"),
            Arc::new(MemoryKeyStore::new()),
            Arc::new(FixedEntropy::new(7)),
            KdfParams::insecure_for_tests(),
        ));
        vault.create(Zeroizing::new("correct horse battery".into()), false).unwrap();
        let secrets = Arc::new(VaultBacked(vault.clone()));
        Setup { fx, vault, secrets }
    }

    fn manager(&self) -> Arc<ConnectionManager> {
        let deps = Dependencies::new(
            self.fx.store.clone(),
            self.secrets.clone(),
            self.fx.helper.clone(),
            self.fx.native.clone(),
        );
        self.fx.manager_with(deps)
    }

    fn editor_deps(&self, manager: Arc<ConnectionManager>, profiles: Arc<MobileconfigProfiles>) -> EditorDeps {
        EditorDeps {
            manager,
            store: self.fx.store.clone(),
            secrets: self.secrets.clone(),
            secret_writer: self.secrets.clone(),
            profiles,
            clock: clock_at(1_000_000.0),
        }
    }

    /// A raw read of the vault's secrets table.
    fn stored(&self, item: &str, field: SecretField) -> Option<String> {
        self.vault.with(|v| v.secret(item, field)).unwrap().map(|s| s.to_string())
    }

    fn native_connection(&self, name: &str, kind: VPNKind, service_id: &str) -> Connection {
        let mut c = Connection::new(name, kind);
        c.native = Some(NativeSettings {
            server: "vpn.example.com".into(),
            account: "bob".into(),
            group_name: "staff".into(),
            send_all_traffic: true,
        });
        c.native_service_name = Some(name.into());
        c.native_service_id = Some(service_id.into());
        self.fx.store.save(&c, None).unwrap();
        c
    }
}

fn option<'a>(start: &'a Start, entity: &str, key: &str) -> Option<&'a str> {
    start.options.as_ref()?.get(entity)?.get(key).map(String::as_str)
}

/// A managed L2TP and Cisco connection start with the PSK, the account name and the password from the vault.
#[test]
fn managed_native_start_passes_the_vault_secrets() {
    let s = Setup::new();
    let l2tp = s.native_connection("Office L2TP", VPNKind::L2tp, L2TP_SERVICE);
    let cisco = s.native_connection("Office Cisco", VPNKind::Cisco, CISCO_SERVICE);
    for (c, psk, password) in [(&l2tp, "l2tp-psk", "l2tp-pw"), (&cisco, "cisco-psk", "cisco-pw")] {
        s.secrets.set("bob", &c.id, SecretField::Username);
        s.secrets.set(psk, &c.id, SecretField::Psk);
        s.secrets.set(password, &c.id, SecretField::Password);
    }
    s.fx.native.set_list(Ok(vec![
        SystemVpn::new(L2TP_SERVICE, "Office L2TP", "L2TP", "Disconnected"),
        SystemVpn::new(CISCO_SERVICE, "Office Cisco", "Cisco IPsec", "Disconnected"),
    ]));
    let m = s.manager();
    m.connect(&l2tp, false);
    m.connect(&cisco, false);

    let starts = s.fx.native.starts();
    assert_eq!(starts.len(), 2);
    assert_eq!(starts[0].service_id, L2TP_SERVICE);
    assert_eq!(option(&starts[0], "IPSec", "SharedSecret"), Some("l2tp-psk"));
    assert_eq!(option(&starts[0], "PPP", "AuthName"), Some("bob"));
    assert_eq!(option(&starts[0], "PPP", "AuthPassword"), Some("l2tp-pw"));
    assert_eq!(starts[1].service_id, CISCO_SERVICE);
    assert_eq!(option(&starts[1], "IPSec", "SharedSecret"), Some("cisco-psk"));
    assert_eq!(option(&starts[1], "IPSec", "XAuthName"), Some("bob"));
    assert_eq!(option(&starts[1], "IPSec", "XAuthPassword"), Some("cisco-pw"));
}

/// A system VPN's PSK and password are vault rows keyed by its service ID, and are passed at start.
#[test]
fn system_vpn_start_passes_the_vault_secrets() {
    let s = Setup::new();
    let service = SystemVpn::new(L2TP_SERVICE, "Office L2TP", "L2TP", "Disconnected");
    let id = service.secret_id().unwrap();
    s.secrets.set("system-psk", &id, SecretField::Psk);
    s.secrets.set("system-pw", &id, SecretField::Password);
    assert_eq!(s.stored(L2TP_SERVICE, SecretField::Psk).as_deref(), Some("system-psk"));
    s.fx.native.set_list(Ok(vec![service.clone()]));
    let m = s.manager();

    let secrets = m.system_secrets(&service);
    assert_eq!((secrets.psk.as_deref(), secrets.password.as_deref()), (Some("system-psk"), Some("system-pw")));
    m.connect_system(&service);
    let start = s.fx.native.starts().into_iter().next().expect("a start");
    assert_eq!(option(&start, "IPSec", "SharedSecret"), Some("system-psk"));
    assert_eq!(option(&start, "PPP", "AuthPassword"), Some("system-pw"));
}

/// The system-VPN editor saves into the vault and "Forget" clears the vault rows.
#[test]
fn system_vpn_editor_saves_and_forgets_in_the_vault() {
    let s = Setup::new();
    let service = SystemVpn::new(CISCO_SERVICE, "Office Cisco", "Cisco IPsec", "Disconnected");
    let profiles = Arc::new(MobileconfigProfiles::default());
    let deps = s.editor_deps(s.manager(), profiles);
    assert_eq!(
        editor::save_system_secrets(&deps, &service, Some("cisco-psk"), Some("cisco-pw"), OTPSetting::default()),
        None
    );
    assert_eq!(s.stored(CISCO_SERVICE, SecretField::Psk).as_deref(), Some("cisco-psk"));
    assert_eq!(s.stored(CISCO_SERVICE, SecretField::Password).as_deref(), Some("cisco-pw"));
    editor::forget_system_secrets(&deps, &service);
    assert_eq!(s.stored(CISCO_SERVICE, SecretField::Psk), None);
    assert_eq!(s.stored(CISCO_SERVICE, SecretField::Password), None);
}

/// Saving a native connection: the profile embeds the PSK (the "PSK stays in the profile" branch) but never the
/// password; MacVPN's copies of both go into the vault. A later save without a new PSK embeds the vault's copy.
#[test]
fn native_save_keeps_the_psk_in_the_profile_and_both_secrets_in_the_vault() {
    let s = Setup::new();
    let c = s.native_connection("Office L2TP", VPNKind::L2tp, L2TP_SERVICE);
    let profiles = Arc::new(MobileconfigProfiles::default());
    let deps = s.editor_deps(s.manager(), profiles.clone());
    let settings = c.native.clone().unwrap();

    let error = editor::save_native(
        &deps,
        &c,
        "Office L2TP",
        &settings,
        Some("secret-pw"),
        Some("office-psk"),
        OTPSetting::default(),
    );
    assert_eq!(error, None);
    let key = uuid_string(&c.id);
    assert_eq!(s.stored(&key, SecretField::Psk).as_deref(), Some("office-psk"));
    assert_eq!(s.stored(&key, SecretField::Password).as_deref(), Some("secret-pw"));
    assert_eq!(s.stored(&key, SecretField::Username).as_deref(), Some("bob"));
    let profile = profiles.installs.lock().unwrap()[0].1.clone();
    assert!(profile.contains("<key>SharedSecret</key>"), "{profile}");
    assert!(profile.contains("b2ZmaWNlLXBzaw=="), "the PSK (base64) is in the profile: {profile}");
    assert!(!profile.contains("Password") && !profile.contains("secret-pw"), "{profile}");

    // Password and PSK kept (`None`): the profile gets the vault's PSK.
    s.secrets.set("kept-psk", &c.id, SecretField::Psk);
    assert_eq!(editor::save_native(&deps, &c, "Office L2TP", &settings, None, None, OTPSetting::default()), None);
    let profile = profiles.installs.lock().unwrap()[1].1.clone();
    assert!(profile.contains("a2VwdC1wc2s="), "{profile}");
    assert!(!profile.contains("secret-pw"), "{profile}");
    assert_eq!(s.stored(&key, SecretField::Password).as_deref(), Some("secret-pw"));
}
