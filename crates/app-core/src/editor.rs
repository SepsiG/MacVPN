//! The Connections window's editors without a UI (port of `TextConfigDraft`, `NativeConfigDraft`,
//! `SSTPConfigDraft`, `SystemSecretsDraft` and the save handlers of the Swift `AppModel`: `saveText`, `saveSSTP`,
//! `saveOTP`, `saveNative`, `saveSystemSecrets`, `forgetSystemSecrets`).
//!
//! The web view sends the whole field set of an editor after every change ([`EditorFields`], bounded and
//! validated by serde and [`EditorFields::validate`]); the draft keeps it next to the loaded original, so dirty
//! tracking, the live risky-directive panel and the "save all" of the unsaved-changes question work without the
//! UI. Saving goes through the same validation as the Swift app (validators, `Secrets.inputError`, the SSTP
//! password rule, the risky acknowledgement).
//!
//! Stored secrets (passwords, PSKs, the private key password) never reach the web view: a secret field is
//! `None` ("keep the stored value") unless the user typed a new value or removed the stored one (`Some("")`), and
//! the view only says which fields have a stored value ([`StoredSecrets`]). Saving with an untouched field keeps
//! the Keychain item as it is.
//!
//! Shared credentials (spec 3a): the username and password of a connection linked to a credential are the
//! credential's and are never written from an editor. A linked editor (Task 19) sends `None` for those fields;
//! a non-empty value is refused with a message ([`EditorDeps::linked_credential_error`]) before anything is
//! saved, and the secret store refuses it as well (`SecretWriter::set`). The credential itself changes only in
//! the Credentials section or through the credential prompt's "Save" (`SecretWriter::save_prompted`).

use crate::deps::{Clock, ConnectionRepository, NativeProfiles, SecretField, SecretReader, SecretWriter, SystemVpn};
use crate::manager::ConnectionManager;
use macvpn_core::l10n::{self, Arg};
use macvpn_core::mfa;
use macvpn_core::models::{
    Connection, NativeSettings, OTPSeparator, OTPSetting, Secrets, VPNKind, ValidationIssue, uuid_string,
};
use macvpn_core::validators::openvpn::OpenVPNValidator;
use macvpn_core::validators::sstp::{CertMode, SSTPConfig};
use macvpn_core::vault::Entropy;
use macvpn_core::wireguard_keys::{self, KeyLine};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroizing;

/// The largest config text an editor accepts (the root layer's limit too).
pub const MAX_CONFIG_BYTES: usize = 1_048_576;
/// Any other text field (name, server, user name, passwords, PSK).
pub const MAX_FIELD_BYTES: usize = 64 * 1024;
/// The acknowledged risky directive names.
pub const MAX_ACKNOWLEDGED: usize = 512;
const MAX_DIRECTIVE_BYTES: usize = 128;

// MARK: - Fields

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Separator {
    #[default]
    None,
    Comma,
    Colon,
}

/// "Ask for a one-time code at connect and append it to the password" (the Swift `OTPSettingFields`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OtpFields {
    pub enabled: bool,
    pub separator: Separator,
}

impl From<OTPSetting> for OtpFields {
    fn from(s: OTPSetting) -> Self {
        let separator = match s.separator {
            OTPSeparator::None => Separator::None,
            OTPSeparator::Comma => Separator::Comma,
            OTPSeparator::Colon => Separator::Colon,
        };
        OtpFields { enabled: s.enabled, separator }
    }
}

impl From<OtpFields> for OTPSetting {
    fn from(f: OtpFields) -> Self {
        let separator = match f.separator {
            Separator::None => OTPSeparator::None,
            Separator::Comma => OTPSeparator::Comma,
            Separator::Colon => OTPSeparator::Colon,
        };
        OTPSetting::new(f.enabled, separator)
    }
}

/// A secret field as the editor sends it: `None` keeps the stored value (the field was not touched), `Some(v)`
/// stores `v` (`Some("")`: "Remove saved password", deletes the Keychain item).
pub type SecretInput = Option<String>;

/// OpenVPN, WireGuard and strongSwan: the config text and the Keychain secrets.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TextFields {
    pub name: String,
    pub text: String,
    /// Not a secret: shown as stored.
    pub username: String,
    pub password: SecretInput,
    pub psk: SecretInput,
    pub key_password: SecretInput,
    /// The acknowledged risky directives (OpenVPN). The checkbox is ticked when every current risky directive is
    /// in it; ticking it stores exactly the current set.
    pub acknowledged: BTreeSet<String>,
    pub otp: OtpFields,
}

/// L2TP / Cisco IPsec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeFields {
    pub name: String,
    pub server: String,
    pub account: String,
    pub group_name: String,
    pub send_all_traffic: bool,
    pub password: SecretInput,
    pub psk: SecretInput,
    pub otp: OtpFields,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Cert {
    #[default]
    System,
    Ca,
    Insecure,
}

/// SSTP: the config as a form (`SSTPConfig`) and the password.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SstpFields {
    pub name: String,
    pub server: String,
    pub port: i64,
    pub user: String,
    pub cert: Cert,
    pub route_all: bool,
    pub peer_dns: bool,
    pub ca_pem: String,
    pub password: SecretInput,
    pub otp: OtpFields,
}

/// A system VPN's PSK / password kept in MacVPN's keychain (L2TP / Cisco IPsec) and its OTP setting.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SystemFields {
    pub psk: SecretInput,
    pub password: SecretInput,
    pub otp: OtpFields,
}

/// Which secret fields have a value in the Keychain (the editor shows them empty, "Saved — type to replace").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredSecrets {
    pub password: bool,
    pub psk: bool,
    pub key_password: bool,
}

impl StoredSecrets {
    fn read(secrets: &Secrets) -> Self {
        let has = |v: &Option<String>| v.as_deref().is_some_and(|v| !v.is_empty());
        StoredSecrets {
            password: has(&secrets.password),
            psk: has(&secrets.psk),
            key_password: has(&secrets.key_password),
        }
    }

    /// After a save: a written field is stored if it was not empty; a kept field stays as it was.
    fn after_save(&mut self, password: &SecretInput, psk: &SecretInput, key_password: &SecretInput) {
        for (flag, input) in
            [(&mut self.password, password), (&mut self.psk, psk), (&mut self.key_password, key_password)]
        {
            if let Some(value) = input {
                *flag = !value.is_empty();
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum EditorFields {
    Text(TextFields),
    Native(NativeFields),
    Sstp(SstpFields),
    System(SystemFields),
}

fn too_long(s: &str, limit: usize) -> bool {
    s.len() > limit
}

impl EditorFields {
    /// Size limits (the config text and the CA PEM 1 MB, other fields 64 KB) and the directive names.
    pub fn validate(&self) -> Result<(), String> {
        let short = |fields: &[&str]| fields.iter().all(|f| !too_long(f, MAX_FIELD_BYTES));
        fn secret(f: &SecretInput) -> &str {
            f.as_deref().unwrap_or("")
        }
        let ok = match self {
            EditorFields::Text(f) => {
                !too_long(&f.text, MAX_CONFIG_BYTES)
                    && short(&[&f.name, &f.username, secret(&f.password), secret(&f.psk), secret(&f.key_password)])
                    && f.acknowledged.len() <= MAX_ACKNOWLEDGED
                    && f.acknowledged.iter().all(|d| {
                        !d.is_empty()
                            && d.len() <= MAX_DIRECTIVE_BYTES
                            && d.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                    })
            }
            EditorFields::Native(f) => {
                short(&[&f.name, &f.server, &f.account, &f.group_name, secret(&f.password), secret(&f.psk)])
            }
            EditorFields::Sstp(f) => {
                !too_long(&f.ca_pem, MAX_CONFIG_BYTES) && short(&[&f.name, &f.server, &f.user, secret(&f.password)])
            }
            EditorFields::System(f) => short(&[secret(&f.psk), secret(&f.password)]),
        };
        if ok { Ok(()) } else { Err("invalid editor fields".into()) }
    }

    /// The fields with every secret input back to `None` (keep the stored value).
    pub fn without_secret_inputs(&self) -> EditorFields {
        let mut fields = self.clone();
        match &mut fields {
            EditorFields::Text(f) => {
                f.password = None;
                f.psk = None;
                f.key_password = None;
            }
            EditorFields::Native(f) => {
                f.password = None;
                f.psk = None;
            }
            EditorFields::Sstp(f) => f.password = None,
            EditorFields::System(f) => {
                f.password = None;
                f.psk = None;
            }
        }
        fields
    }

    fn same_type(&self, other: &EditorFields) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

impl SstpFields {
    pub(crate) fn config(&self) -> SSTPConfig {
        SSTPConfig {
            server: self.server.clone(),
            port: self.port,
            user: self.user.clone(),
            cert: match self.cert {
                Cert::System => CertMode::System,
                Cert::Ca => CertMode::Ca,
                Cert::Insecure => CertMode::Insecure,
            },
            route_all: self.route_all,
            peer_dns: self.peer_dns,
            ca_pem: self.ca_pem.clone(),
        }
    }
}

// MARK: - Dependencies

/// What the editors, the import and the delete need from the app.
#[derive(Clone)]
pub struct EditorDeps {
    pub manager: Arc<ConnectionManager>,
    pub store: Arc<dyn ConnectionRepository>,
    pub secrets: Arc<dyn SecretReader>,
    pub secret_writer: Arc<dyn SecretWriter>,
    pub profiles: Arc<dyn NativeProfiles>,
    pub clock: Arc<dyn Clock>,
}

impl EditorDeps {
    /// The connection as the manager knows it now (the editor's copy may be older), else the given one.
    fn current(&self, c: &Connection) -> Connection {
        self.manager.connections().into_iter().find(|x| x.id == c.id).unwrap_or_else(|| c.clone())
    }

    /// The message for a save that would write the username or password of a connection linked to a shared
    /// credential (a non-empty value; an empty one is a no-op there). `None`: fine.
    fn linked_credential_error(&self, id: &Uuid, s: &Secrets) -> Option<String> {
        let typed = |v: &Option<String>| v.as_deref().is_some_and(|v| !v.is_empty());
        if !typed(&s.username) && !typed(&s.password) {
            return None;
        }
        let credential = self.secrets.credential_for(id)?;
        Some(l10n::tr(
            "This connection uses the shared credential %@. Change its user name and password in the Credentials section.",
            &[Arg::Str(&credential.name)],
        ))
    }

    /// Writes the given fields (an empty value deletes the item); a `None` field keeps its stored value.
    fn store_secrets(&self, s: &Secrets, id: &Uuid) {
        let w = &self.secret_writer;
        for (value, field) in [
            (&s.username, SecretField::Username),
            (&s.password, SecretField::Password),
            (&s.psk, SecretField::Psk),
            (&s.key_password, SecretField::KeyPassword),
        ] {
            if let Some(value) = value {
                w.set(value, id, field);
            }
        }
    }
}

// MARK: - Save handlers (the Swift `AppModel`)

/// The list of problems; empty = saved. OpenVPN: `acknowledged` is the set acknowledged in the editor; every risky
/// directive of the config must be in it, and exactly the config's risky set is stored (a risky directive added
/// later needs a new acknowledgement). A `None` field of `secrets` keeps its stored value.
pub fn save_text(
    deps: &EditorDeps,
    c: &Connection,
    name: &str,
    config: &str,
    secrets: &Secrets,
    acknowledged: &BTreeSet<String>,
    otp: Option<OTPSetting>,
) -> Vec<ValidationIssue> {
    let mut issues;
    let mut risky_names = Vec::new();
    if c.kind == VPNKind::Openvpn {
        let acknowledged: HashSet<String> = acknowledged.iter().cloned().collect();
        let result = OpenVPNValidator.validate_full(config, &acknowledged);
        issues = result.issues.clone();
        risky_names = result.risky_names();
        if !result.unacknowledged.is_empty() {
            issues.push(ValidationIssue::new(
                0,
                l10n::tr(
                    "Acknowledge the risky settings (tick the checkbox) before saving: %@",
                    &[Arg::Str(&result.unacknowledged.join(", "))],
                ),
            ));
        }
    } else {
        issues = macvpn_core::validators::validator(c.kind).map(|v| v.validate(config)).unwrap_or_default();
    }
    if let Some(error) = secrets.input_error() {
        issues.push(ValidationIssue::new(0, error));
    }
    if let Some(error) = deps.linked_credential_error(&c.id, secrets) {
        issues.push(ValidationIssue::new(0, error));
    }
    if !issues.is_empty() {
        return issues;
    }
    let mut updated = deps.current(c);
    updated.name = name.to_string();
    updated.acknowledged_risky_directives = risky_names;
    if let Some(otp) = otp {
        updated.otp = otp;
    }
    if let Err(e) = deps.store.save(&updated, Some(config)) {
        return vec![ValidationIssue::new(0, e.to_string())];
    }
    deps.store_secrets(secrets, &c.id);
    deps.manager.reload();
    Vec::new()
}

/// The SSTP form: the config serialized and validated, the password to the Keychain. Empty = saved. `password`
/// `None` keeps the stored one (it still has to follow the password rule, as every SSTP save checks it).
pub fn save_sstp(
    deps: &EditorDeps,
    c: &Connection,
    name: &str,
    config: &SSTPConfig,
    password: Option<&str>,
    otp: OTPSetting,
) -> Vec<ValidationIssue> {
    let effective = match password {
        Some(p) => p.to_string(),
        None => deps.secrets.get(&c.id, SecretField::Password).unwrap_or_default(),
    };
    if !SSTPConfig::is_acceptable_password(&effective) {
        return vec![ValidationIssue::new(0, SSTPConfig::password_rule_message())];
    }
    // As the Swift `Secrets(password:)`: the other fields are cleared.
    let secrets = Secrets {
        username: Some(String::new()),
        password: password.map(str::to_string),
        psk: Some(String::new()),
        key_password: Some(String::new()),
        ..Secrets::default()
    };
    save_text(deps, c, name, &config.serialized(), &secrets, &BTreeSet::new(), Some(otp))
}

/// Only the "code after the password" setting changed: `meta.json` is saved (no new profile for a native
/// connection).
pub fn save_otp(deps: &EditorDeps, c: &Connection, otp: OTPSetting) -> Option<String> {
    let mut updated = deps.current(c);
    updated.otp = otp;
    if let Err(e) = deps.store.save(&updated, None) {
        return Some(e.to_string());
    }
    deps.manager.reload();
    None
}

/// Native save: the profile (without the password, with the PSK) goes to a fresh private temp directory, is
/// opened from there, and is deleted once the service is listed by `scutil --nc list` (at the latest on the
/// next launch). `password` / `psk` `None`: the stored value is kept (the stored PSK goes into the profile).
/// MacVPN's copies of both go to the secret store (the vault); see `mobileconfig`'s module docs.
pub fn save_native(
    deps: &EditorDeps,
    c: &Connection,
    name: &str,
    settings: &NativeSettings,
    password: Option<&str>,
    psk: Option<&str>,
    otp: OTPSetting,
) -> Option<String> {
    if settings.server.is_empty() || settings.account.is_empty() {
        return Some(l10n::tr("Server and account name are required", &[]));
    }
    // A linked connection's account name is the profile's only: the stored username is the credential's.
    let linked = deps.secrets.credential_for(&c.id).is_some();
    let secrets = Secrets {
        username: (!linked).then(|| settings.account.clone()),
        password: password.map(str::to_string),
        psk: psk.map(str::to_string),
        key_password: Some(String::new()),
        ..Secrets::default()
    };
    if let Some(error) = secrets.input_error() {
        return Some(error);
    }
    if let Some(error) = deps.linked_credential_error(&c.id, &secrets) {
        return Some(error);
    }
    let profile_psk = match psk {
        Some(psk) => psk.to_string(),
        None => deps.secrets.get(&c.id, SecretField::Psk).unwrap_or_default(),
    };
    let mut updated = deps.current(c);
    updated.name = name.to_string();
    updated.native = Some(settings.clone());
    updated.native_service_name = Some(name.to_string());
    updated.otp = otp;
    let service_existed = deps.manager.installed_native_ids().contains(&c.id);
    let profile = match deps.profiles.build(&updated, &profile_psk) {
        Ok(profile) => profile,
        Err(e) => return Some(e),
    };
    if let Err(e) = deps.store.save(&updated, None) {
        return Some(e.to_string());
    }
    deps.store_secrets(&secrets, &c.id);
    deps.manager.reload();
    deps.profiles.install(&c.id, &profile.data, &profile.file_name, service_existed).err()
}

/// The PSK / password of a system VPN in MacVPN's secret store (L2TP / Cisco IPsec with a UUID service ID only). An
/// empty field deletes the item, a `None` field keeps it. `None`: saved; otherwise the error.
pub fn save_system_secrets(
    deps: &EditorDeps,
    s: &SystemVpn,
    psk: Option<&str>,
    password: Option<&str>,
    otp: OTPSetting,
) -> Option<String> {
    let (true, Some(id)) = (s.supports_stored_secrets(), s.secret_id()) else {
        return Some(l10n::tr("The editor is no longer available", &[]));
    };
    let secrets =
        Secrets { password: password.map(str::to_string), psk: psk.map(str::to_string), ..Secrets::default() };
    if let Some(error) = secrets.input_error() {
        return Some(error);
    }
    if let Some(error) = deps.linked_credential_error(&id, &secrets) {
        return Some(error);
    }
    if let Some(psk) = psk {
        deps.secret_writer.set(psk, &id, SecretField::Psk);
    }
    if let Some(password) = password {
        deps.secret_writer.set(password, &id, SecretField::Password);
    }
    deps.manager.set_system_otp(otp, &s.id);
    None
}

pub fn forget_system_secrets(deps: &EditorDeps, s: &SystemVpn) {
    let Some(id) = s.secret_id() else { return };
    deps.secret_writer.delete_all(&id);
    deps.manager.set_system_otp(OTPSetting::default(), &s.id);
}

// MARK: - Make an L2TP/IPsec Copy (WinVPN 2c, Cisco IPsec on Windows: option A)

/// The new connection of [`l2tp_copy_of`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L2tpCopy {
    pub id: Uuid,
    /// The copy is saved, but its profile could not be installed (the editor shows it, as after a save).
    pub install_error: Option<String>,
}

/// The longest connection name (the vault's and the catalogs' limit).
const MAX_NAME_CHARACTERS: usize = 128;

/// "<name> (L2TP)", the name cut so that the whole stays within the name limit.
fn l2tp_copy_name(name: &str) -> String {
    const SUFFIX: &str = " (L2TP)";
    let base: String = name.chars().take(MAX_NAME_CHARACTERS - SUFFIX.chars().count()).collect();
    format!("{}{SUFFIX}", base.trim_end())
}

/// **Make an L2TP/IPsec Copy** of a Cisco IPsec connection (Windows has no Cisco IPsec client): a new L2TP/IPsec
/// connection "<name> (L2TP)" in the same folder, with the same server, account, "send all traffic" and OTP
/// setting, the vault's PSK and password copied (a connection linked to a shared credential: the copy is linked
/// to the same credential, `credentials` must then be given), the group name dropped. Its profile is built and
/// installed as a save does (WinVPN: the RAS entry is written). The original is not changed.
pub fn l2tp_copy_of(
    deps: &EditorDeps,
    original: &Connection,
    credentials: Option<&crate::shared_credentials::SharedCredentials>,
) -> Result<L2tpCopy, String> {
    let original = deps.current(original);
    let (VPNKind::Cisco, Some(settings)) = (original.kind, original.native.as_ref()) else {
        return Err(l10n::tr("The editor is no longer available", &[]));
    };
    let source_key = uuid_string(&original.id);
    let credential = match credentials {
        Some(c) => c.credential_of(&source_key).map_err(|e| crate::shared_credentials::error_message(&e))?,
        None if deps.secrets.credential_for(&original.id).is_some() => {
            return Err(crate::shared_credentials::locked_message());
        }
        None => None,
    };
    let name = l2tp_copy_name(&original.name);
    let mut copy = Connection::new(name.clone(), VPNKind::L2tp);
    copy.native = Some(NativeSettings { group_name: String::new(), ..settings.clone() });
    copy.native_service_name = Some(name);
    copy.otp = original.otp;
    deps.store.save(&copy, None).map_err(|e| e.to_string())?;
    let key = uuid_string(&copy.id);
    if let (Some(credential), Some(credentials)) = (credential, credentials)
        && let Err(e) = credentials.link(&key, Some(credential))
    {
        let _ = deps.store.delete(&copy.id);
        return Err(crate::shared_credentials::error_message(&e));
    }
    let psk = deps.secrets.get(&original.id, SecretField::Psk).unwrap_or_default();
    let own = credential.is_none();
    let secrets = Secrets {
        username: own.then(|| deps.secrets.get(&original.id, SecretField::Username)).flatten(),
        password: own.then(|| deps.secrets.get(&original.id, SecretField::Password)).flatten(),
        psk: Some(psk.clone()),
        ..Secrets::default()
    };
    deps.store_secrets(&secrets, &copy.id);
    if let (Some(store), Some(folder)) =
        (deps.manager.folder_store(), deps.manager.placement(&source_key).and_then(|p| p.folder))
    {
        // A folder the copy cannot go into (a team catalog's): it stays at the root.
        let _ = store.apply(crate::deps::FolderOp::MoveItem { key, folder: Some(folder) });
    }
    deps.manager.reload();
    deps.manager.reload_folders();
    let install_error = match deps.profiles.build(&copy, &psk) {
        Ok(profile) => deps.profiles.install(&copy.id, &profile.data, &profile.file_name, false).err(),
        Err(e) => Some(e),
    };
    Ok(L2tpCopy { id: copy.id, install_error })
}

// MARK: - Drafts

/// What an editor edits.
#[derive(Debug, Clone, PartialEq)]
pub enum Target {
    Connection(Connection),
    System(SystemVpn),
}

/// One editor's state (the Swift `…Draft` objects).
#[derive(Debug, Clone)]
pub struct Draft {
    pub target: Target,
    pub original: EditorFields,
    pub fields: EditorFields,
    /// The validation problems shown in red (text and SSTP editors).
    pub issues: Vec<String>,
    /// The native / system editor's error.
    pub error: Option<String>,
    /// The native / system editor saved successfully.
    pub saved: bool,
    /// The text / SSTP editor's last successful save (Unix seconds).
    pub saved_at: Option<f64>,
    /// The SSTP CA file could not be used.
    pub import_error: Option<String>,
    /// Which secret fields have a Keychain value (never the values themselves).
    pub stored: StoredSecrets,
    /// System VPN: the service is no longer listed by macOS (the editor is read-only until it returns).
    pub removed: bool,
    /// The shared credential the connection's username and password come from (its name; spec 3a). While it is
    /// set, the editor hides its own username and password fields and never writes them.
    pub credential: Option<String>,
    /// "Managed by the team catalog “…”" (team catalog spec 6): the config, name and the other settings are
    /// read-only; only the risky-directive acknowledgement is saved.
    pub read_only: Option<String>,
}

/// The read-only reason of a team catalog's connection.
fn read_only_reason(deps: &EditorDeps, target: &Target) -> Option<String> {
    let Target::Connection(c) = target else { return None };
    let team = deps.store.team_managed(&c.id)?;
    Some(l10n::tr("Managed by the team catalog “%@”", &[Arg::Str(&team.catalog)]))
}

/// An editor's shared-credential state ([`Draft::link_state`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkState {
    /// The linked credential's name.
    pub credential: Option<String>,
    pub stored_password: bool,
    /// The own username (empty while linked).
    pub username: String,
}

/// The vault item of an editor's target: the managed connection's id or the system VPN's service ID.
pub fn secret_item(target: &Target) -> Option<Uuid> {
    match target {
        Target::Connection(c) => Some(c.id),
        Target::System(s) => s.secret_id(),
    }
}

impl Draft {
    /// The fields as stored now (the Swift `load`). `import_issues`: the import's validation problems, shown once.
    pub fn load(deps: &EditorDeps, target: Target, import_issues: Vec<ValidationIssue>) -> Draft {
        let credential = secret_item(&target).and_then(|id| deps.secrets.credential_for(&id)).map(|c| c.name);
        let linked = credential.is_some();
        let read_only = read_only_reason(deps, &target);
        let (fields, stored) = match &target {
            Target::Connection(c) => {
                let stored = StoredSecrets::read(&deps.secrets.secrets(&c.id));
                // A linked connection's username is the credential's: never shown in (or sent back from) its editor.
                let username = || {
                    if linked {
                        String::new()
                    } else {
                        deps.secrets.get(&c.id, SecretField::Username).unwrap_or_default()
                    }
                };
                let text = || deps.store.load_config(&c.id).unwrap_or_default();
                let fields = if c.kind.is_native() {
                    let settings = c.native.clone().unwrap_or_default();
                    EditorFields::Native(NativeFields {
                        name: c.name.clone(),
                        server: settings.server,
                        account: settings.account,
                        group_name: settings.group_name,
                        send_all_traffic: settings.send_all_traffic,
                        password: None,
                        psk: None,
                        otp: c.otp.into(),
                    })
                } else if c.kind == VPNKind::Sstp {
                    let config = SSTPConfig::parse(&text());
                    EditorFields::Sstp(SstpFields {
                        name: c.name.clone(),
                        server: config.server,
                        port: config.port,
                        user: config.user,
                        cert: match config.cert {
                            CertMode::System => Cert::System,
                            CertMode::Ca => Cert::Ca,
                            CertMode::Insecure => Cert::Insecure,
                        },
                        route_all: config.route_all,
                        peer_dns: config.peer_dns,
                        ca_pem: config.ca_pem,
                        password: None,
                        otp: c.otp.into(),
                    })
                } else {
                    EditorFields::Text(TextFields {
                        name: c.name.clone(),
                        text: text(),
                        username: username(),
                        password: None,
                        psk: None,
                        key_password: None,
                        acknowledged: c.acknowledged_risky_directives.iter().cloned().collect(),
                        otp: c.otp.into(),
                    })
                };
                (fields, stored)
            }
            Target::System(s) => {
                let stored = StoredSecrets::read(&deps.manager.system_secrets(s));
                let fields = EditorFields::System(SystemFields {
                    psk: None,
                    password: None,
                    otp: deps.manager.system_otp_setting(&s.id).into(),
                });
                (fields, stored)
            }
        };
        // The text editor shows the issues with their line numbers, the SSTP form the same way after an import.
        let issues = import_issues.iter().map(ValidationIssue::display).collect();
        Draft {
            target,
            original: fields.clone(),
            fields,
            issues,
            error: None,
            saved: false,
            saved_at: None,
            import_error: None,
            stored,
            removed: false,
            credential,
            read_only,
        }
    }

    /// The link state of `target` as stored now (read without any lock of the caller held).
    pub fn link_state(deps: &EditorDeps, target: &Target) -> Option<LinkState> {
        let id = secret_item(target)?;
        let credential = deps.secrets.credential_for(&id).map(|c| c.name);
        let secrets = match target {
            Target::Connection(_) => deps.secrets.secrets(&id),
            Target::System(s) => deps.manager.system_secrets(s),
        };
        let username = if credential.is_some() {
            String::new()
        } else {
            deps.secrets.get(&id, SecretField::Username).unwrap_or_default()
        };
        Some(LinkState { credential, stored_password: StoredSecrets::read(&secrets).password, username })
    }

    /// The connection was linked to a shared credential or unlinked (the editor's selector, "Copy into each
    /// connection", "Create from connection…"): the link state and the stored-password flag follow, and the
    /// username and password fields go back to "stored" in the edited and in the original fields, so the other
    /// edits stay and the draft does not turn dirty.
    pub fn apply_link_state(&mut self, state: LinkState) {
        self.credential = state.credential;
        self.stored.password = state.stored_password;
        for fields in [&mut self.fields, &mut self.original] {
            match fields {
                EditorFields::Text(f) => {
                    f.username = state.username.clone();
                    f.password = None;
                }
                EditorFields::Native(f) => f.password = None,
                EditorFields::Sstp(f) => f.password = None,
                EditorFields::System(f) => f.password = None,
            }
        }
    }

    pub fn is_dirty(&self) -> bool {
        self.fields != self.original
    }

    /// Replaces the fields with the editor's (same editor type only).
    pub fn update(&mut self, fields: EditorFields) -> Result<(), String> {
        fields.validate()?;
        if !self.fields.same_type(&fields) {
            return Err("wrong editor type".into());
        }
        self.fields = fields;
        Ok(())
    }

    /// The kind of the connection, if it is one.
    pub fn kind(&self) -> Option<VPNKind> {
        match &self.target {
            Target::Connection(c) => Some(c.kind),
            Target::System(_) => None,
        }
    }

    /// The config's risky directives, live (OpenVPN only).
    pub fn risky(&self) -> Vec<RiskyView> {
        match (&self.fields, self.kind()) {
            (EditorFields::Text(f), Some(VPNKind::Openvpn)) => OpenVPNValidator
                .validate_full(&f.text, &HashSet::new())
                .risky
                .into_iter()
                .map(|r| RiskyView { line: r.line, reason: r.reason(), directive: r.directive })
                .collect(),
            _ => Vec::new(),
        }
    }

    fn risky_names(risky: &[RiskyView]) -> BTreeSet<String> {
        risky.iter().map(|r| r.directive.clone()).collect()
    }

    /// "I acknowledge these settings…": ticked when every current risky directive is acknowledged (so a newly
    /// added risky directive un-ticks it).
    pub fn acknowledges_risk(&self, risky: &[RiskyView]) -> bool {
        match &self.fields {
            EditorFields::Text(f) => !risky.is_empty() && Self::risky_names(risky).is_subset(&f.acknowledged),
            _ => false,
        }
    }

    /// A team catalog's connection (spec 6): only the risky-directive acknowledgement of an OpenVPN config is saved
    /// (the subscriber's own, through [`ConnectionRepository::set_acknowledged_risky`]); any other change is refused
    /// with the read-only text.
    fn save_read_only(&mut self, deps: &EditorDeps, reason: String) -> bool {
        let (Target::Connection(c), EditorFields::Text(f), EditorFields::Text(o)) =
            (&self.target, &self.fields, &self.original)
        else {
            self.issues = vec![reason.clone()];
            self.error = Some(reason);
            return false;
        };
        let only_acknowledged = TextFields { acknowledged: o.acknowledged.clone(), ..f.clone() } == *o;
        if !only_acknowledged || c.kind != VPNKind::Openvpn {
            self.issues = vec![reason];
            return false;
        }
        let risky = self.risky();
        let acknowledged = if self.acknowledges_risk(&risky) { Self::risky_names(&risky) } else { BTreeSet::new() };
        let names: Vec<String> = acknowledged.iter().cloned().collect();
        // The config the user reviewed: the vault refuses the acknowledgement if the catalog changed it since.
        if let Err(e) = deps.store.set_acknowledged_risky(&c.id, &o.text, &names) {
            self.issues = vec![e.to_string()];
            return false;
        }
        deps.manager.reload();
        self.issues.clear();
        let mut saved = f.clone();
        saved.acknowledged = acknowledged;
        self.adopt_saved(EditorFields::Text(saved));
        self.saved_at = Some(deps.clock.now().time_interval_since_1970());
        true
    }

    /// Saves the fields (the Swift drafts' `save()`). True: saved.
    pub fn save(&mut self, deps: &EditorDeps) -> bool {
        if let Some(reason) = self.read_only.clone() {
            return self.save_read_only(deps, reason);
        }
        let fields = self.fields.clone();
        match (&self.target, &fields) {
            (Target::Connection(c), EditorFields::Text(f)) => {
                let risky = self.risky();
                let acknowledged =
                    if self.acknowledges_risk(&risky) { Self::risky_names(&risky) } else { BTreeSet::new() };
                // Only OpenVPN has a private key password; the other kinds clear it (as the Swift save).
                let key_password =
                    if c.kind == VPNKind::Openvpn { f.key_password.clone() } else { Some(String::new()) };
                // A linked editor sends no username (an empty one); a typed one is refused by `save_text`.
                let linked = self.credential.is_some();
                let secrets = Secrets {
                    username: (!linked || !f.username.is_empty()).then(|| f.username.clone()),
                    password: f.password.clone(),
                    psk: f.psk.clone(),
                    key_password: key_password.clone(),
                    ..Secrets::default()
                };
                let issues = save_text(deps, c, &f.name, &f.text, &secrets, &acknowledged, Some(f.otp.into()));
                self.issues = issues.iter().map(ValidationIssue::display).collect();
                let ok = issues.is_empty();
                if ok {
                    self.stored.after_save(&f.password, &f.psk, &key_password);
                    // The editor's fields follow: the stored acknowledgement is exactly the current risky set, and
                    // the secrets are stored (the fields show them as saved, empty).
                    let mut saved = f.clone();
                    saved.acknowledged = acknowledged;
                    self.adopt_saved(EditorFields::Text(saved));
                }
                self.saved_at = ok.then(|| deps.clock.now().time_interval_since_1970());
                ok
            }
            (Target::Connection(c), EditorFields::Sstp(f)) => {
                let issues = save_sstp(deps, c, &f.name, &f.config(), f.password.as_deref(), f.otp.into());
                // As the Swift form: the messages without line numbers.
                self.issues = issues.into_iter().map(|i| i.message).collect();
                let ok = self.issues.is_empty();
                if ok {
                    self.stored.after_save(&f.password, &Some(String::new()), &Some(String::new()));
                    self.adopt_saved(fields.clone());
                }
                self.saved_at = ok.then(|| deps.clock.now().time_interval_since_1970());
                ok
            }
            (Target::Connection(c), EditorFields::Native(f)) => {
                let only_otp = match &self.original {
                    EditorFields::Native(o) => NativeFields { otp: o.otp, ..f.clone() } == *o,
                    _ => false,
                };
                self.error = if only_otp {
                    // Only the code setting changed: no new profile (and no new approval).
                    save_otp(deps, c, f.otp.into())
                } else {
                    let settings = NativeSettings {
                        server: f.server.clone(),
                        account: f.account.clone(),
                        group_name: f.group_name.clone(),
                        send_all_traffic: f.send_all_traffic,
                    };
                    save_native(deps, c, &f.name, &settings, f.password.as_deref(), f.psk.as_deref(), f.otp.into())
                };
                self.saved = self.error.is_none();
                if self.saved {
                    if !only_otp {
                        self.stored.after_save(&f.password, &f.psk, &Some(String::new()));
                    }
                    self.adopt_saved(fields.clone());
                }
                self.saved
            }
            (Target::System(s), EditorFields::System(f)) => {
                self.error = save_system_secrets(deps, s, f.psk.as_deref(), f.password.as_deref(), f.otp.into());
                self.saved = self.error.is_none();
                if self.saved {
                    self.stored.after_save(&f.password, &f.psk, &None);
                    self.adopt_saved(fields.clone());
                }
                self.saved
            }
            _ => {
                self.error = Some(l10n::tr("The editor is no longer available", &[]));
                false
            }
        }
    }

    /// The saved fields become the original and the editor's fields, with the secret fields back to "stored"
    /// (`None`): a saved secret is never sent back to the web view.
    fn adopt_saved(&mut self, saved: EditorFields) {
        let saved = saved.without_secret_inputs();
        self.original = saved.clone();
        self.fields = saved;
    }

    /// `None` = saved; otherwise the message for the "Saving failed" list (the Swift `saveReportingError`).
    pub fn save_reporting_error(&mut self, deps: &EditorDeps) -> Option<String> {
        if self.save(deps) {
            return None;
        }
        Some(match &self.fields {
            EditorFields::Text(_) | EditorFields::Sstp(_) => self.issues.join("\n"),
            EditorFields::Native(_) => self.error.clone().unwrap_or_else(|| l10n::tr("Unknown error", &[])),
            EditorFields::System(_) => {
                self.error.clone().unwrap_or_else(|| l10n::tr("The editor is no longer available", &[]))
            }
        })
    }

    /// "Forget saved secrets" (system VPN).
    pub fn forget(&mut self, deps: &EditorDeps) {
        let Target::System(s) = &self.target else { return };
        forget_system_secrets(deps, s);
        self.error = None;
        self.original = EditorFields::System(SystemFields::default());
        self.fields = self.original.clone();
        self.stored = StoredSecrets::default();
        self.saved = false;
    }

    /// The certificate(s) of a chosen CA file into the SSTP config (the Swift `importCA`).
    pub fn import_ca(&mut self, text: Option<&str>) {
        let EditorFields::Sstp(f) = &mut self.fields else { return };
        match text.and_then(SSTPConfig::extract_certificates) {
            Some(pem) => {
                self.import_error = None;
                f.ca_pem = pem;
            }
            None => {
                self.import_error = Some(l10n::tr(
                    "The file contains no PEM certificate (-----BEGIN CERTIFICATE-----). Convert a binary (DER) .cer file to PEM first.",
                    &[],
                ));
            }
        }
    }

    /// The WireGuard key panel (a WireGuard connection's text editor only): the config's `[Interface]
    /// PrivateKey`, the public key derived from it (live, from the draft's text), and the only peer's
    /// `PresharedKey`.
    fn wireguard_keys(&self) -> Option<WireGuardKeysView> {
        let (EditorFields::Text(f), Some(VPNKind::Wireguard)) = (&self.fields, self.kind()) else { return None };
        let keys = wireguard_keys::read(&f.text);
        let public_key = keys.private_key.as_deref().and_then(|k| wireguard_keys::public_key(k));
        Some(WireGuardKeysView {
            private_key: keys.private_key.as_deref().map(|k| k.to_string()),
            public_key,
            peers: keys.peers,
            preshared_key: keys.preshared_key.as_deref().map(|k| k.to_string()),
        })
    }

    /// "Generate Key Pair" / "Generate Preshared Key": a new key from `entropy` (the OS CSPRNG) into the draft's
    /// config text (the line replaced, or added). The key is never logged; the editor shows it as any typed edit
    /// (unsaved until "Save"). Refused for a read-only or removed editor and for anything but WireGuard.
    pub fn generate_wireguard_key(&mut self, which: KeyLine, entropy: &dyn Entropy) -> Result<(), String> {
        if let Some(reason) = &self.read_only {
            return Err(reason.clone());
        }
        if self.removed || self.kind() != Some(VPNKind::Wireguard) {
            return Err("not a WireGuard editor".into());
        }
        let EditorFields::Text(f) = &mut self.fields else { return Err("not a WireGuard editor".into()) };
        let fill = |buf: &mut [u8]| entropy.fill(buf);
        let key = match which {
            KeyLine::PrivateKey => wireguard_keys::generate_private_key(fill),
            KeyLine::PresharedKey => wireguard_keys::generate_preshared_key(fill),
        }
        .map_err(|e| e.to_string())?;
        let text = wireguard_keys::set(&f.text, which, &key).ok_or("the config needs exactly one [Peer]")?;
        if too_long(&text, MAX_CONFIG_BYTES) {
            return Err("invalid editor fields".into());
        }
        f.text = text;
        Ok(())
    }

    /// The draft's current private key or preshared key, for the secret clipboard ("Copy").
    pub fn wireguard_secret(&self, which: KeyLine) -> Option<Zeroizing<String>> {
        let (EditorFields::Text(f), Some(VPNKind::Wireguard)) = (&self.fields, self.kind()) else { return None };
        let keys = wireguard_keys::read(&f.text);
        match which {
            KeyLine::PrivateKey => keys.private_key,
            KeyLine::PresharedKey => keys.preshared_key,
        }
    }

    /// The editor's view for the UI.
    pub fn view(&self, id: &str) -> EditorView {
        let risky = self.risky();
        let acknowledges_risk = self.acknowledges_risk(&risky);
        let (static_challenge, cert_count, password_rule) = match &self.fields {
            EditorFields::Text(f) => {
                (self.kind() == Some(VPNKind::Openvpn) && mfa::static_challenge(&f.text).is_some(), 0, None)
            }
            // Only a typed password is checked live (a stored one is checked when saving).
            EditorFields::Sstp(f) => (
                false,
                SSTPConfig::certificate_count(&f.ca_pem),
                f.password
                    .as_deref()
                    .is_some_and(|p| !SSTPConfig::is_acceptable_password(p))
                    .then(SSTPConfig::password_rule_message),
            ),
            _ => (false, 0, None),
        };
        EditorView {
            id: id.to_string(),
            kind: self.kind().map_or("system", VPNKind::raw_value),
            fields: self.fields.clone(),
            dirty: self.is_dirty(),
            issues: self.issues.clone(),
            error: self.error.clone(),
            saved: self.saved,
            saved_at: self.saved_at,
            risky,
            acknowledges_risk,
            static_challenge,
            cert_count,
            password_rule,
            import_error: self.import_error.clone(),
            has_stored: matches!(&self.original, EditorFields::System(o)
                if self.stored.password || self.stored.psk || o.otp != OtpFields::default()),
            has_stored_secret: self.stored,
            removed: self.removed,
            credential: self.credential.clone(),
            read_only: self.read_only.clone(),
            wireguard: self.wireguard_keys(),
            platform: None,
        }
    }
}

/// A risky directive of the config (the yellow panel's row).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskyView {
    pub line: i64,
    pub directive: String,
    pub reason: String,
}

/// An editor as the UI shows it.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EditorView {
    /// The connection's UUID string or the system VPN's service ID.
    pub id: String,
    /// The connection's kind (`openvpn`, …) or `system`.
    pub kind: &'static str,
    pub fields: EditorFields,
    /// "Unsaved changes".
    pub dirty: bool,
    pub issues: Vec<String>,
    pub error: Option<String>,
    pub saved: bool,
    /// Unix seconds of the last successful save of a text / SSTP editor ("Saved: …").
    pub saved_at: Option<f64>,
    pub risky: Vec<RiskyView>,
    pub acknowledges_risk: bool,
    /// OpenVPN `static-challenge`: the code is asked for at connect (no OTP setting).
    pub static_challenge: bool,
    /// SSTP: the number of CA certificates.
    pub cert_count: usize,
    /// SSTP: the password breaks the pppd-safe rule (the message).
    pub password_rule: Option<String>,
    /// SSTP: the chosen CA file had no PEM certificate.
    pub import_error: Option<String>,
    /// System VPN: something is stored ("Forget saved secrets").
    pub has_stored: bool,
    /// Which secret fields have a stored value: the field is shown empty ("Saved — type to replace"), the value
    /// itself never leaves the backend.
    pub has_stored_secret: StoredSecrets,
    /// System VPN: removed from macOS; the editor is read-only ("This VPN was removed from macOS").
    pub removed: bool,
    /// The shared credential (its name) the username and password come from: the selector shows "Use
    /// credential: <name>" and the own username and password fields are hidden. `None`: its own fields.
    pub credential: Option<String>,
    /// A team catalog's connection: "Managed by the team catalog “…”". The editor is read-only except for the
    /// risky settings' checkbox.
    pub read_only: Option<String>,
    /// WireGuard: the key panel (the private key, its public key, the only peer's preshared key). Absent from the
    /// JSON for the other kinds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wireguard: Option<WireGuardKeysView>,
    /// What the platform says about these settings (WinVPN 2c: Windows' reasons, the IKEv2 summary, the CA trust,
    /// the L2TP copy, the system VPN's PSK note); set by the Connections window
    /// ([`crate::connections::ConnectionsModel::set_native_platform`]). Absent from the JSON when `None` (MacVPN).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<EditorPlatformView>,
}

/// [`EditorView::wireguard`]: the keys of the draft's config text. The private and preshared keys are the values
/// the config text (also in the view) holds; the public key is derived here, never in the web view.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WireGuardKeysView {
    /// The `[Interface] PrivateKey` value as written; `None`: no line or an empty value.
    pub private_key: Option<String>,
    /// The public key of `private_key`; `None`: no private key, or not a valid one ("Invalid private key").
    pub public_key: Option<String>,
    /// The number of `[Peer]` sections ("Generate Preshared Key" needs exactly one).
    pub peers: usize,
    /// The only peer's `PresharedKey`; `None`: none, or not exactly one peer.
    pub preshared_key: Option<String>,
}

/// Without the key values (a view printed for a test failure or a debug line never shows them).
impl std::fmt::Debug for WireGuardKeysView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireGuardKeysView")
            .field("private_key", &self.private_key.as_ref().map(|_| "<redacted>"))
            .field("public_key", &self.public_key)
            .field("peers", &self.peers)
            .field("preshared_key", &self.preshared_key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// [`EditorView::platform`]: the platform's notes on the editor's draft (`PlatformNotes`), plus whether the system
/// trusts the SSTP custom CA and the system VPN's PSK note.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EditorPlatformView {
    /// Why the platform cannot connect these settings (the yellow note; saving still works).
    pub reasons: Vec<String>,
    /// One line on what the platform makes of the settings (grey).
    pub summary: Option<String>,
    /// Settings the platform ignores (grey notes; the connection still runs).
    pub warnings: Vec<String>,
    /// SSTP: why "No verification" cannot be chosen (its title; the option is disabled).
    pub insecure_cert: Option<String>,
    /// The editor offers **Trust This CA in Windows…**.
    pub trust_ca: bool,
    /// SSTP with a custom CA: whether the system trusts it ("Trusted by Windows"); `None`: unknown or no CA.
    pub ca_trusted: Option<bool>,
    /// The editor offers **Make an L2TP/IPsec Copy** (Cisco IPsec).
    pub l2tp_copy: bool,
    /// L2TP / Cisco: saving needs no approval step ("Save", no "approve the profile" note).
    pub no_install_step: bool,
    /// System VPN: the note under the PSK (Windows keeps it for that VPN too).
    pub psk_note: Option<String>,
}

/// The editor key of a connection.
pub fn key(c: &Connection) -> String {
    uuid_string(&c.id)
}
