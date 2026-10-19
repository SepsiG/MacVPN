//! The System Status window without a UI (port of `SetupView.swift`, `BrewInstaller.swift` and the setup parts
//! of the Swift `AppModel`: `checkSetup`, `installRoot`, `uninstall`): the three check rows with their texts, the
//! live `brew install` output (owned by the app, so it survives closing the window), the root layer's install
//! state and its up-front notice, and the uninstall sequence with its final message.

use crate::connections::ConnectionsModel;
use crate::deps::SecretWriter;
use crate::manager::ConnectionManager;
use crate::migration::LegacyKeychain;
use crate::updates::Notice;
use macvpn_core::l10n::{self, Arg};
use macvpn_core::models::uuid_string;
use macvpn_core::vault::KeyStore;
use serde::Serialize;

/// What the system check found (the platform's `SetupReport`, mapped by the app).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SetupFacts {
    pub brew_prefix: Option<String>,
    /// In the checker's order.
    pub missing_tools: Vec<String>,
    pub installed_root_version: Option<String>,
    pub bundled_root_version: Option<String>,
    /// Installed, the bundled version, complete, and `sudo -n mvpn` works.
    pub root_ok: bool,
    pub missing_root_files: Vec<String>,
}

/// One row: green or red, and its detail line. The row's action is shown only when it is not ok.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckRow {
    pub ok: bool,
    pub detail: String,
}

/// The System Status window.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetupView {
    /// The first check has finished (before it the rows are not shown as failed).
    pub checked: bool,
    pub homebrew: Option<CheckRow>,
    pub tools: Option<CheckRow>,
    pub root: Option<CheckRow>,
    /// "Install" of the tools can be used: Homebrew is there and no install runs.
    pub can_install_tools: bool,
    /// The `brew install` output (header, live chunks, the result line).
    pub brew_output: String,
    pub brew_running: bool,
    /// "Authorize" runs (the administrator prompt is up).
    pub installing_root: bool,
    /// The root layer could not be installed (the localized error).
    pub install_error: Option<String>,
    /// Shown before "Authorize" when a root layer is installed: the install takes its connections down.
    pub upgrade_notice: Option<String>,
    pub uninstalling: bool,
}

/// The Swift `SetupView.rootDetail`.
pub fn root_detail(f: &SetupFacts) -> String {
    if f.root_ok {
        return l10n::tr("Installed (version %@)", &[Arg::Str(f.installed_root_version.as_deref().unwrap_or("?"))]);
    }
    if let Some(installed) = &f.installed_root_version
        && Some(installed) != f.bundled_root_version.as_ref()
    {
        return l10n::tr(
            "Update required (%@ → %@). Asks for the admin password once.",
            &[Arg::Str(installed), Arg::Str(f.bundled_root_version.as_deref().unwrap_or("?"))],
        );
    }
    if f.installed_root_version.is_some() && !f.missing_root_files.is_empty() {
        return l10n::tr(
            "Incomplete installation (missing: %@). Reinstall: asks for the admin password once.",
            &[Arg::Str(&f.missing_root_files.join(", "))],
        );
    }
    l10n::tr(
        "Asks for the admin password once: installs the scripts in /usr/local/libexec/macvpn and the /etc/sudoers.d/macvpn rule.",
        &[],
    )
}

/// The app-side state of the window's operations.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SetupOps {
    pub installing_root: bool,
    pub install_error: Option<String>,
    pub uninstalling: bool,
}

impl SetupView {
    /// `facts`: `None` until the first check finished. `upgrade_notice`: the platform's text ("Updating the system
    /// component will disconnect active VPN connections."), shown when a root layer is installed but needs
    /// installing again (another version, incomplete, or `sudo` does not work).
    pub fn build(facts: Option<&SetupFacts>, brew: &BrewRun, ops: &SetupOps, upgrade_notice: String) -> SetupView {
        let row = |ok: bool, detail: String| Some(CheckRow { ok, detail });
        let (homebrew, tools, root, notice) = match facts {
            Some(f) => (
                row(
                    f.brew_prefix.is_some(),
                    f.brew_prefix.clone().unwrap_or_else(|| {
                        l10n::tr(
                            "Not installed. The installer runs in Terminal and asks for an administrator password.",
                            &[],
                        )
                    }),
                ),
                row(
                    f.missing_tools.is_empty(),
                    if f.missing_tools.is_empty() {
                        l10n::tr("All tools are installed", &[])
                    } else {
                        l10n::tr("Missing: %@", &[Arg::Str(&f.missing_tools.join(", "))])
                    },
                ),
                row(f.root_ok, root_detail(f)),
                (f.installed_root_version.is_some() && !f.root_ok).then_some(upgrade_notice),
            ),
            None => (None, None, None, None),
        };
        SetupView {
            checked: facts.is_some(),
            can_install_tools: facts.is_some_and(|f| f.brew_prefix.is_some()) && !brew.running,
            homebrew,
            tools,
            root,
            brew_output: brew.output.clone(),
            brew_running: brew.running,
            installing_root: ops.installing_root,
            install_error: ops.install_error.clone(),
            upgrade_notice: notice,
            uninstalling: ops.uninstalling,
        }
    }
}

// MARK: - brew install

/// The kept `brew install` output (the start is dropped beyond this; the result line is always kept).
pub const MAX_BREW_OUTPUT: usize = 256 * 1024;

/// The `brew install` run (the Swift `BrewInstaller`): one at a time; the output grows while it runs; finishing
/// counts up (the app checks the system again then, even if the window was closed meanwhile).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BrewRun {
    pub output: String,
    pub running: bool,
    pub finished: u64,
}

impl BrewRun {
    /// False if a run is going on already. The output starts over.
    pub fn start(&mut self) -> bool {
        if self.running {
            return false;
        }
        self.running = true;
        self.output.clear();
        true
    }

    pub fn append(&mut self, text: &str) {
        self.output.push_str(text);
        if self.output.len() > MAX_BREW_OUTPUT {
            let mut cut = self.output.len() - MAX_BREW_OUTPUT;
            while !self.output.is_char_boundary(cut) {
                cut += 1;
            }
            // From the next line on, so the window does not start with half a line.
            if let Some(newline) = self.output[cut..].find('\n') {
                cut += newline + 1;
            }
            self.output.drain(..cut);
        }
    }

    /// The run ended (its last line was appended).
    pub fn finish(&mut self) {
        self.running = false;
        self.finished += 1;
    }
}

// MARK: - Uninstall

/// The system steps of the uninstall (the app implements them over the platform layer; the sandbox fakes the
/// root and login item steps).
pub trait UninstallSystem {
    /// The root layer with one administrator prompt (its own script takes the root connections down first).
    fn uninstall_root(&self) -> Result<(), String>;
    /// The status poller stops (nothing is left to poll).
    fn stop_polling(&self);
    /// `SMAppService` / LaunchAgent: unregistered if registered.
    fn unregister_login_item(&self) -> Result<(), String>;
    /// A LaunchAgent with our label but stale content is removed too (a foreign plist is left alone).
    fn remove_launch_agent(&self) -> Result<(), String>;
    /// `~/Library/Application Support/MacVPN`, the update cache and the app's preferences.
    fn remove_user_files(&self);
}

/// The keys the user data has outside its files: the vault key's key-store item (`local.macvpn.vault`, for the
/// automatic unlock) and the old service's Keychain items (`local.macvpn.secrets`, left by a 1.1 install that was
/// never migrated, or by a migration that could not delete them).
pub struct UserDataStores<'a> {
    pub key_store: &'a dyn KeyStore,
    pub legacy_keychain: &'a dyn LegacyKeychain,
}

/// The answer to the confirmation (Uninstall with or without "Also delete user data").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UninstallChoice {
    pub remove_user_data: bool,
}

/// The Swift `AppModel.uninstall` after the confirmation. The root layer goes first (its script disconnects the
/// root connections); if that fails, nothing else happens (`Err`: the "Uninstall failed" alert, then the system is
/// checked again). Then the active native connections are disconnected, polling stops, the login item is
/// unregistered, and with `remove_user_data` the saved secrets, the vault key, the old Keychain items, the unsaved
/// edits and the user files go. `Ok`:
/// the final message ("MacVPN has been uninstalled"; the window's button quits).
pub fn uninstall(
    manager: &ConnectionManager,
    connections: &ConnectionsModel,
    secrets: &dyn SecretWriter,
    system: &dyn UninstallSystem,
    stores: UserDataStores<'_>,
    choice: UninstallChoice,
) -> Result<Notice, Notice> {
    if let Err(message) = system.uninstall_root() {
        return Err(Notice { title: l10n::tr("Uninstall failed", &[]), message });
    }
    let all = manager.connections();
    for c in all.iter().filter(|c| c.kind.is_native()) {
        if manager.state(&uuid_string(&c.id)).is_active() {
            manager.disconnect(c);
        }
    }
    system.stop_polling();
    let had_native = all.iter().any(|c| c.kind.is_native());
    // No orphaned login item.
    let mut login_item_left = system.unregister_login_item().is_err();
    login_item_left |= system.remove_launch_agent().is_err();
    if choice.remove_user_data {
        for c in &all {
            manager.forget_saves(&c.id);
            secrets.delete_all(&c.id);
        }
        secrets.remove_all();
        // Also in the legacy read-only mode (where the stores write nothing): the old items are deleted one by one.
        for (account, field) in stores.legacy_keychain.items() {
            stores.legacy_keychain.delete(&account, field);
        }
        // The vault file goes with the files below; its key must not stay behind.
        let _ = stores.key_store.delete();
        connections.discard_unsaved();
        system.remove_user_files();
    }
    let mut message = l10n::tr(
        "You can now drag the app to the Trash. The Homebrew packages were kept (brew uninstall openvpn wireguard-tools strongswan sstp-client).",
        &[],
    );
    if had_native {
        message.push_str("\n\n");
        message.push_str(&l10n::tr(
            "You can remove the L2TP / Cisco profiles in System Settings → General → Device Management.",
            &[],
        ));
    }
    if login_item_left {
        message.push_str("\n\n");
        message.push_str(&l10n::tr(
            "MacVPN could not be removed from the login items. You can remove it in System Settings → General → Login Items.",
            &[],
        ));
    }
    Ok(Notice { title: l10n::tr("MacVPN has been uninstalled", &[]), message })
}
