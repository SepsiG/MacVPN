//! Launch at login (port of `LoginItem.swift`, `LaunchAgentLoginItem.swift` and the app's
//! `SMAppServiceLoginItem.swift`). The actual state always comes from the system, never from a saved switch.

use crate::native_vpn::BoxError;
use crate::temp_dir::{standardize, strerror};
use macvpn_core::l10n::{self, Arg};
use macvpn_core::plist_xml::{PlistValue, to_xml};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// `SMAppService.Status`, plus our LaunchAgent fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginItemStatus {
    Enabled,
    NotRegistered,
    RequiresApproval,
    NotFound,
    /// `SMAppService` is not registered (typically `.notFound` for an ad-hoc signed build), but our per-user
    /// LaunchAgent (`~/Library/LaunchAgents/local.macvpn.launcher.plist`) exists with the expected contents.
    EnabledViaLaunchAgent,
}

/// The system's login item service (`SMAppService.mainApp` in production).
pub trait LoginItemService {
    fn status(&self) -> LoginItemStatus;
    fn register(&self) -> Result<(), BoxError>;
    fn unregister(&self) -> Result<(), BoxError>;
    fn open_system_settings_login_items(&self);
}

/// Where the app runs from. From a DMG, the Downloads folder or App Translocation the registration is fragile
/// (the system would remember a temporary path), so only the Applications folders are allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginItemLocation {
    Applications,
    NotInApplications,
    Translocated,
}

impl LoginItemLocation {
    /// `/Applications` or `~/Applications` (subfolders too) is fine. Case-insensitive (APFS is by default). The
    /// caller resolves symlinks.
    pub fn check(bundle_path: &str, home_directory: &str) -> LoginItemLocation {
        let path = standardize_string(bundle_path);
        if path.contains("/AppTranslocation/") {
            return LoginItemLocation::Translocated;
        }
        if path_extension(&path).to_lowercase() != "app" {
            return LoginItemLocation::NotInApplications;
        }
        let home = standardize_string(home_directory);
        let mut roots = vec!["/Applications".to_string()];
        if home.starts_with('/') && home != "/" {
            roots.push(format!("{}/Applications", home.trim_end_matches('/')));
        }
        let lowered = path.to_lowercase();
        if roots.iter().any(|r| lowered.starts_with(&format!("{}/", r.to_lowercase()))) {
            LoginItemLocation::Applications
        } else {
            LoginItemLocation::NotInApplications
        }
    }

    /// The running app's location (symlinks resolved).
    pub fn current(bundle_path: &Path, home_directory: &Path) -> LoginItemLocation {
        let resolved = fs::canonicalize(bundle_path).unwrap_or_else(|_| bundle_path.to_path_buf());
        Self::check(&resolved.to_string_lossy(), &home_directory.to_string_lossy())
    }
}

/// `NSString.standardizingPath` for our inputs (absolute paths: `.`, `..`, duplicate and trailing slashes).
fn standardize_string(path: &str) -> String {
    if path.is_empty() {
        return String::new();
    }
    standardize(Path::new(path)).to_string_lossy().into_owned()
}

/// `NSString.pathExtension`.
fn path_extension(path: &str) -> &str {
    let name = path.rsplit('/').next().unwrap_or("");
    match name.rfind('.') {
        Some(i) if i > 0 => &name[i + 1..],
        _ => "",
    }
}

/// The note under the switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginItemNote {
    RequiresApproval,
    /// Turned on with the LaunchAgent fallback (applies from the next login).
    LaunchAgent,
    NotInApplications,
    Translocated,
}

impl LoginItemNote {
    pub fn message(self) -> String {
        let key = match self {
            LoginItemNote::RequiresApproval => "Approve MacVPN in System Settings → General → Login Items.",
            LoginItemNote::LaunchAgent => "Enabled via a login LaunchAgent (applies at next login).",
            LoginItemNote::NotInApplications => {
                "Launch at login is available only when MacVPN runs from the Applications folder. Drag the app there first."
            }
            LoginItemNote::Translocated => {
                "macOS is running MacVPN from a temporary location. Move the app to the Applications folder and open it from there."
            }
        };
        l10n::tr(key, &[])
    }
}

/// What the UI shows: the switch, whether it can be clicked, the note and the "Login Items" button.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginItemState {
    pub is_on: bool,
    pub can_toggle: bool,
    pub note: Option<LoginItemNote>,
    pub shows_open_settings: bool,
}

impl LoginItemState {
    pub fn new(is_on: bool, can_toggle: bool, note: Option<LoginItemNote>, shows_open_settings: bool) -> Self {
        LoginItemState { is_on, can_toggle, note, shows_open_settings }
    }

    /// - `Enabled` → on; `NotRegistered` → off.
    /// - `RequiresApproval` → on (registered, waiting for approval; can be turned off) + note and button.
    /// - `NotFound` → like `NotRegistered`: an ad-hoc signed build gets it even from the right place. Turning it
    ///   on falls back to the LaunchAgent ([`FallbackLoginItemService`]).
    /// - `EnabledViaLaunchAgent` → on, with a note (applies from the next login).
    /// - From a wrong place it cannot be turned on; if already registered it can be turned off (never stuck).
    pub fn make(status: LoginItemStatus, location: LoginItemLocation) -> LoginItemState {
        let location_note = match location {
            LoginItemLocation::Applications => None,
            LoginItemLocation::NotInApplications => Some(LoginItemNote::NotInApplications),
            LoginItemLocation::Translocated => Some(LoginItemNote::Translocated),
        };
        match status {
            LoginItemStatus::Enabled => LoginItemState::new(true, true, location_note, false),
            LoginItemStatus::RequiresApproval => {
                LoginItemState::new(true, true, Some(LoginItemNote::RequiresApproval), true)
            }
            LoginItemStatus::EnabledViaLaunchAgent => {
                LoginItemState::new(true, true, location_note.or(Some(LoginItemNote::LaunchAgent)), false)
            }
            LoginItemStatus::NotRegistered | LoginItemStatus::NotFound => {
                LoginItemState::new(false, location_note.is_none(), location_note, false)
            }
        }
    }
}

/// The login item's state and actions. Off by default for a new user: the app never registers by itself, only
/// from the switch.
pub struct LoginItemController {
    status: LoginItemStatus,
    location: LoginItemLocation,
    service: Box<dyn LoginItemService>,
    locate: Box<dyn Fn() -> LoginItemLocation>,
}

impl LoginItemController {
    /// The default of a new install: no launch at login (no automatic registration).
    pub const DEFAULT_ENABLED: bool = false;

    pub fn new(service: Box<dyn LoginItemService>, locate: Box<dyn Fn() -> LoginItemLocation>) -> Self {
        let status = service.status();
        let location = locate();
        LoginItemController { status, location, service, locate }
    }

    pub fn status(&self) -> LoginItemStatus {
        self.status
    }

    pub fn location(&self) -> LoginItemLocation {
        self.location
    }

    pub fn state(&self) -> LoginItemState {
        LoginItemState::make(self.status, self.location)
    }

    /// Re-reads the system state (menu open, the System Status window, after a switch).
    pub fn refresh(&mut self) {
        self.status = self.service.status();
        self.location = (self.locate)();
    }

    /// The switch: on → `register()`, off → `unregister()`. The error is returned (the UI shows it); the state is
    /// re-read in every case. Nothing happens if the switch cannot be clicked.
    pub fn set_enabled(&mut self, on: bool) -> Result<(), BoxError> {
        let result = self.toggle(on);
        self.refresh();
        result
    }

    fn toggle(&self, on: bool) -> Result<(), BoxError> {
        let current = self.state();
        if on == current.is_on {
            return Ok(());
        }
        if on {
            if !current.can_toggle {
                return Ok(());
            }
            self.service.register()
        } else {
            self.service.unregister()
        }
    }

    /// On uninstall: unregisters if registered (on, waiting for approval or via the LaunchAgent), so no orphan
    /// login item is left. True if there was something to remove.
    pub fn unregister_if_registered(&mut self) -> Result<bool, BoxError> {
        let result = match self.service.status() {
            LoginItemStatus::Enabled | LoginItemStatus::RequiresApproval | LoginItemStatus::EnabledViaLaunchAgent => {
                self.service.unregister().map(|_| true)
            }
            LoginItemStatus::NotRegistered | LoginItemStatus::NotFound => Ok(false),
        };
        self.refresh();
        result
    }

    pub fn open_system_settings(&self) {
        self.service.open_system_settings_login_items();
    }
}

// MARK: - LaunchAgent fallback

/// Launch at login without code signing: a per-user LaunchAgent (`~/Library/LaunchAgents/local.macvpn.launcher.plist`).
/// `ProgramArguments` is `/usr/bin/open -b local.macvpn`: it launches by bundle identifier, so there is no path in
/// it and it keeps working after the app is moved. No `launchctl bootstrap`: launchd picks it up at next login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchAgentLoginItem {
    pub directory: PathBuf,
    pub label: String,
    pub bundle_identifier: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchAgentError {
    NotRegularFile(String),
    WriteFailed(String, i32),
    RemoveFailed(String, i32),
}

impl std::fmt::Display for LaunchAgentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let reason = |code: &i32| strerror(&io::Error::from_raw_os_error(*code));
        let text = match self {
            LaunchAgentError::NotRegularFile(path) => {
                l10n::tr("Refusing to write %@: it is a symbolic link or not a regular file.", &[Arg::Str(path)])
            }
            LaunchAgentError::WriteFailed(path, code) => {
                l10n::tr("Could not write %@: %@", &[Arg::Str(path), Arg::Str(&reason(code))])
            }
            LaunchAgentError::RemoveFailed(path, code) => {
                l10n::tr("Could not remove %@: %@", &[Arg::Str(path), Arg::Str(&reason(code))])
            }
        };
        f.write_str(&text)
    }
}

impl std::error::Error for LaunchAgentError {}

fn errno_of(e: &io::Error) -> i32 {
    e.raw_os_error().unwrap_or(libc::EIO)
}

impl LaunchAgentLoginItem {
    pub const DEFAULT_LABEL: &'static str = "local.macvpn.launcher";
    pub const DEFAULT_BUNDLE_IDENTIFIER: &'static str = "local.macvpn";

    /// The real agent in the user's `~/Library/LaunchAgents`.
    pub fn new(home: &Path) -> Self {
        Self::in_directory(Self::default_directory(home))
    }

    /// Tests pass a temporary directory.
    pub fn in_directory(directory: PathBuf) -> Self {
        Self::with(directory, Self::DEFAULT_LABEL, Self::DEFAULT_BUNDLE_IDENTIFIER)
    }

    pub fn with(directory: PathBuf, label: &str, bundle_identifier: &str) -> Self {
        LaunchAgentLoginItem { directory, label: label.to_string(), bundle_identifier: bundle_identifier.to_string() }
    }

    pub fn default_directory(home: &Path) -> PathBuf {
        home.join("Library/LaunchAgents")
    }

    pub fn plist_path(&self) -> PathBuf {
        self.directory.join(format!("{}.plist", self.label))
    }

    pub fn program_arguments(&self) -> Vec<String> {
        vec!["/usr/bin/open".into(), "-b".into(), self.bundle_identifier.clone()]
    }

    /// The property list written.
    pub fn plist_contents(&self) -> PlistValue {
        let mut d = BTreeMap::new();
        d.insert("Label".to_string(), PlistValue::String(self.label.clone()));
        d.insert(
            "ProgramArguments".to_string(),
            PlistValue::Array(self.program_arguments().into_iter().map(PlistValue::String).collect()),
        );
        d.insert("RunAtLoad".to_string(), PlistValue::Boolean(true));
        d.insert("LimitLoadToSessionType".to_string(), PlistValue::String("Aqua".into()));
        PlistValue::Dictionary(d)
    }

    /// `PropertyListSerialization` XML, byte-identical to the Swift app's.
    pub fn plist_data(&self) -> Vec<u8> {
        to_xml(&self.plist_contents())
    }

    /// On: the plist is a regular file (not a symlink) with the expected `Label` and `ProgramArguments`.
    pub fn is_installed(&self) -> bool {
        let Some(plist) = self.read_own_plist() else { return false };
        let Some(dict) = plist.as_dictionary() else { return false };
        let label = dict.get("Label").and_then(plist::Value::as_string);
        let args: Option<Vec<&str>> = dict
            .get("ProgramArguments")
            .and_then(plist::Value::as_array)
            .and_then(|a| a.iter().map(plist::Value::as_string).collect());
        label == Some(self.label.as_str())
            && args.is_some_and(|a| a.iter().copied().eq(self.program_arguments().iter().map(String::as_str)))
    }

    /// Reads the plist with O_NOFOLLOW; `None` if missing, a symlink, not a regular file or not a property list.
    fn read_own_plist(&self) -> Option<plist::Value> {
        let path = self.plist_path();
        if !is_regular_file(&path) {
            return None;
        }
        let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(&path).ok()?;
        let mut data = Vec::new();
        file.take(1 << 16).read_to_end(&mut data).ok()?;
        plist::Value::from_reader(io::Cursor::new(data)).ok()
    }

    /// Writes the plist atomically (temp file O_EXCL | O_NOFOLLOW, 0644, fsync, rename). Never overwrites a
    /// symlink or a non-regular file. Creates the LaunchAgents directory if missing.
    pub fn install(&self) -> Result<(), BoxError> {
        let path = self.plist_path();
        let path_str = path.to_string_lossy().into_owned();
        if exists(&path) && !is_regular_file(&path) {
            return Err(Box::new(LaunchAgentError::NotRegularFile(path_str)));
        }
        fs::DirBuilder::new().recursive(true).mode(0o755).create(&self.directory)?;
        let data = self.plist_data();
        let tmp = self.directory.join(format!(
            ".{}.plist.tmp-{}",
            self.label,
            macvpn_core::models::uuid_string(&uuid::Uuid::new_v4())
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)
            .map_err(|e| LaunchAgentError::WriteFailed(path_str.clone(), errno_of(&e)))?;
        let result = (|| -> Result<(), BoxError> {
            // Neither narrowed nor widened by the umask: LaunchAgents are 0644.
            file.set_permissions(fs::Permissions::from_mode(0o644))
                .map_err(|e| LaunchAgentError::WriteFailed(path_str.clone(), errno_of(&e)))?;
            file.write_all(&data)?;
            file.sync_all().map_err(|e| LaunchAgentError::WriteFailed(path_str.clone(), errno_of(&e)))?;
            // Replaced by a symlink meanwhile? The rename would replace the link itself, but we refuse instead.
            if exists(&path) && !is_regular_file(&path) {
                return Err(Box::new(LaunchAgentError::NotRegularFile(path_str.clone())));
            }
            fs::rename(&tmp, &path).map_err(|e| LaunchAgentError::WriteFailed(path_str.clone(), errno_of(&e)))?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result
    }

    /// Deletes the plist, but only a regular file with our `Label` (a foreign one is left alone). True if deleted.
    pub fn remove(&self) -> Result<bool, BoxError> {
        let Some(plist) = self.read_own_plist() else { return Ok(false) };
        let ours = plist.as_dictionary().and_then(|d| d.get("Label")).and_then(plist::Value::as_string)
            == Some(self.label.as_str());
        if !ours {
            return Ok(false);
        }
        match fs::remove_file(self.plist_path()) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(Box::new(LaunchAgentError::RemoveFailed(
                self.plist_path().to_string_lossy().into_owned(),
                errno_of(&e),
            ))),
        }
    }
}

fn is_regular_file(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_file())
}

fn exists(path: &Path) -> bool {
    fs::symlink_metadata(path).is_ok()
}

/// [`LoginItemService`] in two layers: first `SMAppService` (`primary`); if that does not work (it fails, or it
/// is still `NotFound` after registering), the per-user LaunchAgent.
pub struct FallbackLoginItemService {
    primary: Box<dyn LoginItemService>,
    pub launch_agent: LaunchAgentLoginItem,
}

impl FallbackLoginItemService {
    pub fn new(primary: Box<dyn LoginItemService>, launch_agent: LaunchAgentLoginItem) -> Self {
        FallbackLoginItemService { primary, launch_agent }
    }
}

impl LoginItemService for FallbackLoginItemService {
    /// `SMAppService`'s `Enabled` / `RequiresApproval` wins; otherwise `EnabledViaLaunchAgent` if the agent exists;
    /// otherwise `SMAppService`'s state (`NotRegistered` / `NotFound`).
    fn status(&self) -> LoginItemStatus {
        let primary = self.primary.status();
        match primary {
            LoginItemStatus::Enabled | LoginItemStatus::RequiresApproval | LoginItemStatus::EnabledViaLaunchAgent => {
                primary
            }
            LoginItemStatus::NotRegistered | LoginItemStatus::NotFound => {
                if self.launch_agent.is_installed() {
                    LoginItemStatus::EnabledViaLaunchAgent
                } else {
                    primary
                }
            }
        }
    }

    fn register(&self) -> Result<(), BoxError> {
        // An ad-hoc signed build: SMAppService fails, the fallback follows.
        if self.primary.register().is_ok() {
            match self.primary.status() {
                LoginItemStatus::Enabled
                | LoginItemStatus::RequiresApproval
                | LoginItemStatus::EnabledViaLaunchAgent => {
                    // Done the normal way: an earlier fallback agent must not launch the app a second time.
                    let _ = self.launch_agent.remove();
                    return Ok(());
                }
                LoginItemStatus::NotRegistered | LoginItemStatus::NotFound => {}
            }
        }
        self.launch_agent.install()
    }

    /// Removes both. `SMAppService`'s error is swallowed unless it stayed registered (otherwise the switch would
    /// silently stay on).
    fn unregister(&self) -> Result<(), BoxError> {
        let primary_error = self.primary.unregister().err();
        self.launch_agent.remove()?;
        if let Some(e) = primary_error
            && matches!(self.primary.status(), LoginItemStatus::Enabled | LoginItemStatus::RequiresApproval)
        {
            return Err(e);
        }
        Ok(())
    }

    fn open_system_settings_login_items(&self) {
        self.primary.open_system_settings_login_items();
    }
}

/// The production [`LoginItemService`]: `SMAppService.mainApp` (macOS 13+).
#[derive(Debug, Default, Clone, Copy)]
pub struct SMAppServiceLoginItem;

impl LoginItemService for SMAppServiceLoginItem {
    fn status(&self) -> LoginItemStatus {
        crate::smappservice_ffi::status()
    }

    fn register(&self) -> Result<(), BoxError> {
        crate::smappservice_ffi::register().map_err(|m| Box::new(crate::temp_dir::MessageError(m)) as BoxError)
    }

    fn unregister(&self) -> Result<(), BoxError> {
        crate::smappservice_ffi::unregister().map_err(|m| Box::new(crate::temp_dir::MessageError(m)) as BoxError)
    }

    fn open_system_settings_login_items(&self) {
        crate::smappservice_ffi::open_system_settings_login_items();
    }
}
