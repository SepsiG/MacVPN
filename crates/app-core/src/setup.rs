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
use macvpn_core::models::{VPNKind, uuid_string};
use macvpn_core::vault::KeyStore;
use macvpn_platform_api::setup::{EngineReport, EngineRow, NmReport, OutdatedPackage};
use serde::Serialize;
use std::collections::HashSet;

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
    /// The Homebrew formulae with a newer version (checked only when no tool is missing; empty when unknown).
    pub outdated: Vec<OutdatedPackage>,
}

/// One row: green or red, and its detail line. The row's action is shown only when it is not ok.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckRow {
    pub ok: bool,
    pub detail: String,
}

impl From<&EngineRow> for CheckRow {
    fn from(row: &EngineRow) -> CheckRow {
        CheckRow { ok: row.ok, detail: row.detail.clone() }
    }
}

/// System Status' engine rows (WinVPN); absent from the JSON on macOS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineRowsView {
    pub service: CheckRow,
    pub openvpn: CheckRow,
    pub wireguard: CheckRow,
    /// "install" / "repair" / "update" / none: the OpenVPN row's button.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub openvpn_action: Option<&'static str>,
    /// "update" / none: the WireGuard row's button (the WinVPN Service updates wireguard-nt itself).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wireguard_action: Option<&'static str>,
    /// The note under the rows (`SystemSetup::later_note`): empty since WinVPN 2.0 (the native Windows VPNs ship).
    pub later_note: String,
}

/// System Status' NetworkManager rows (LinVPN, L-b); absent from the JSON on macOS and Windows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NmRowsView {
    pub networkmanager: CheckRow,
    /// One row per kind, in the platform's order.
    pub kinds: Vec<NmKindRow>,
}

/// One kind's row under NetworkManager: the plugin it needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NmKindRow {
    /// The kind's raw value (`"l2tp"`): the Install button sends it to `setup_install_tools`.
    pub kind: &'static str,
    pub row: CheckRow,
    /// The package(s) the Install button asks PackageKit for (space-separated; empty for WireGuard).
    pub packages: String,
    /// `"install"` / none: the row's button.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<&'static str>,
    /// OpenVPN's row: NetworkManager sees the server's `redirect-gateway` (OpenVPN 2.7 or later), for the editor's
    /// "Server decides" help text. Absent when false.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub push_visible: bool,
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
    /// `"update"`: the tools row is green but a formula has a newer version, and the row offers "Update" (`brew
    /// upgrade`, through the same command as "Install"). Absent from the JSON otherwise (MacVPN's view model is
    /// unchanged without an update).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools_action: Option<&'static str>,
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
    /// The platform's note when it has no VPN engine yet (WinVPN 2a); the rows are then not shown. Absent from the
    /// JSON when `None`, so MacVPN's view model stays byte-identical.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_note: Option<String>,
    /// The app is uninstalled through the system (WinVPN: Settings → Apps): this note and a button to the system's
    /// page replace the "Uninstall" button. Absent from the JSON when `None` (MacVPN's view model is unchanged).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_uninstall: Option<String>,
    /// The app removes itself from the user's account before the system uninstall (WinVPN: "Remove WinVPN from
    /// This Account…", `SystemSetup::account_cleanup`). Absent from the JSON when `false` (MacVPN's view model is
    /// unchanged).
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub account_cleanup: bool,
    /// The WinVPN Service, OpenVPN and WireGuard rows (WinVPN 2b), shown instead of the Homebrew, tools and root
    /// rows. Absent from the JSON when `None` (MacVPN's view model is unchanged).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine: Option<EngineRowsView>,
    /// The Windows VPN client row (WinVPN 2c: L2TP/IPsec, IKEv2 and SSTP through Windows' own client), shown under
    /// the engine rows, also without the WinVPN Service. Absent from the JSON when `None` (MacVPN).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ras: Option<CheckRow>,
    /// The NetworkManager and plugin rows (LinVPN, L-b), shown instead of the Homebrew, tools and root rows. Absent
    /// from the JSON when `None` (MacVPN and WinVPN).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nm: Option<NmRowsView>,
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

/// The tools row's detail: what is missing, or that all are installed, or (green, with an update) each outdated
/// formula with its versions ("openvpn: Update available: 2.6.8 → 2.6.9").
pub fn tools_detail(f: &SetupFacts) -> String {
    if !f.missing_tools.is_empty() {
        return l10n::tr("Missing: %@", &[Arg::Str(&f.missing_tools.join(", "))]);
    }
    if f.brew_prefix.is_none() || f.outdated.is_empty() {
        return l10n::tr("All tools are installed", &[]);
    }
    f.outdated
        .iter()
        .map(|p| {
            let update = l10n::tr("Update available: %@ → %@", &[Arg::Str(&p.installed), Arg::Str(&p.available)]);
            format!("{}: {update}", p.name)
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// The app-side state of the window's operations.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SetupOps {
    pub installing_root: bool,
    pub install_error: Option<String>,
    pub uninstalling: bool,
}

impl SetupView {
    /// The view with the platform's engine note: the Homebrew, tools and helper rows (and their actions) are
    /// replaced by it. `None` returns the view unchanged.
    pub fn with_engine_note(mut self, note: Option<String>) -> SetupView {
        if note.is_some() {
            self.homebrew = None;
            self.tools = None;
            self.root = None;
            self.can_install_tools = false;
            self.tools_action = None;
            self.upgrade_notice = None;
            self.engine_note = note;
        }
        self
    }

    /// The view with the service's engine rows (`SetupReport::engine`): they replace the Homebrew, tools and root
    /// rows and the root layer's notice; the installer's output (`brew_output`, `brew_running`) stays, as OpenVPN's
    /// installer writes there, and "Install" of the tools is the OpenVPN row's action. `later_note`: the line under
    /// the rows (`SystemSetup::later_note`). `None` returns the view unchanged.
    pub fn with_engine(mut self, report: Option<&EngineReport>, later_note: Option<String>) -> SetupView {
        let Some(report) = report else { return self };
        self.homebrew = None;
        self.tools = None;
        self.root = None;
        self.upgrade_notice = None;
        self.tools_action = None;
        self.can_install_tools =
            (report.openvpn.action.is_some() || report.wireguard.action.is_some()) && !self.brew_running;
        self.engine = Some(EngineRowsView {
            service: (&report.service).into(),
            openvpn: (&report.openvpn).into(),
            wireguard: (&report.wireguard).into(),
            openvpn_action: report.openvpn.action,
            wireguard_action: report.wireguard.action,
            later_note: later_note.unwrap_or_default(),
        });
        self
    }

    /// The view with LinVPN's NetworkManager rows (`SetupReport::nm`): they replace the Homebrew, tools and root
    /// rows and the root layer's notice; the installer's output stays (PackageKit's progress is written there), and
    /// "Install" can be used when a row offers it and no install runs. `None` returns the view unchanged.
    pub fn with_nm(mut self, report: Option<&NmReport>) -> SetupView {
        let Some(report) = report else { return self };
        self.homebrew = None;
        self.tools = None;
        self.root = None;
        self.upgrade_notice = None;
        self.tools_action = None;
        self.can_install_tools = report.kinds.iter().any(|(_, r, _)| r.action.is_some()) && !self.brew_running;
        self.nm = Some(NmRowsView {
            networkmanager: (&report.networkmanager).into(),
            kinds: report
                .kinds
                .iter()
                .map(|(kind, row, packages)| NmKindRow {
                    kind: kind.raw_value(),
                    row: row.into(),
                    packages: packages.clone(),
                    action: row.action,
                    push_visible: *kind == VPNKind::Openvpn && report.openvpn_push_visible,
                })
                .collect(),
        });
        self
    }

    /// The platform's Windows VPN client row (`SetupReport::ras`). `None` returns the view unchanged.
    pub fn with_ras(mut self, row: Option<&EngineRow>) -> SetupView {
        if let Some(row) = row {
            self.ras = Some(row.into());
        }
        self
    }

    /// The platform's note that the app is uninstalled through the system (`SystemSetup::system_uninstall_note`):
    /// the window shows it instead of its own "Uninstall". `None` returns the view unchanged.
    pub fn with_system_uninstall(mut self, note: Option<String>) -> SetupView {
        self.system_uninstall = note;
        self
    }

    /// The platform's in-app clean-up before the system uninstall (`SystemSetup::account_cleanup`).
    pub fn with_account_cleanup(mut self, offered: bool) -> SetupView {
        self.account_cleanup = offered;
        self
    }

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
                row(f.missing_tools.is_empty(), tools_detail(f)),
                row(f.root_ok, root_detail(f)),
                (f.installed_root_version.is_some() && !f.root_ok).then_some(upgrade_notice),
            ),
            None => (None, None, None, None),
        };
        SetupView {
            checked: facts.is_some(),
            can_install_tools: facts.is_some_and(|f| f.brew_prefix.is_some()) && !brew.running,
            tools_action: facts
                .is_some_and(|f| f.brew_prefix.is_some() && f.missing_tools.is_empty() && !f.outdated.is_empty())
                .then_some("update"),
            homebrew,
            tools,
            root,
            brew_output: brew.output.clone(),
            brew_running: brew.running,
            installing_root: ops.installing_root,
            install_error: ops.install_error.clone(),
            upgrade_notice: notice,
            uninstalling: ops.uninstalling,
            engine_note: None,
            system_uninstall: None,
            account_cleanup: false,
            engine: None,
            ras: None,
            nm: None,
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
    /// The privileged helper (on macOS the root layer, with one administrator prompt; its own script takes the
    /// root connections down first).
    fn uninstall_helper(&self) -> Result<(), String>;
    /// The status poller stops (nothing is left to poll).
    fn stop_polling(&self);
    /// `SMAppService` / LaunchAgent: unregistered if registered.
    fn unregister_login_item(&self) -> Result<(), String>;
    /// Stale login entries of the app are removed too (on macOS a LaunchAgent with our label but stale content; a
    /// foreign plist is left alone).
    fn remove_stale_login_entries(&self) -> Result<(), String>;
    /// The app's data directory (`Product::data_dir`), the update cache and the app's preferences.
    fn remove_user_files(&self);
    /// [`Self::uninstall_helper`] took the helper's connections down (macOS: the root layer's script). `false`
    /// (WinVPN: the WinVPN Service is the MSI's and stays): the app disconnects every active connection itself.
    fn helper_disconnects(&self) -> bool {
        true
    }
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
/// checked again). Then the active native connections are disconnected (every active connection where the helper
/// disconnects none: WinVPN), polling stops, the login item is unregistered, where the platform removes native
/// profiles itself (WinVPN: the RAS entries and the PSKs Windows keeps for them) every connection's profile is
/// removed and the leftovers swept, and with `remove_user_data` the saved secrets, the vault key, the old Keychain
/// items, the unsaved edits and the user files go. `Ok`: the final message ("MacVPN has been uninstalled"; on
/// WinVPN "… removed from this account"; the window's button quits).
pub fn uninstall(
    manager: &ConnectionManager,
    connections: &ConnectionsModel,
    secrets: &dyn SecretWriter,
    system: &dyn UninstallSystem,
    stores: UserDataStores<'_>,
    choice: UninstallChoice,
) -> Result<Notice, Notice> {
    if let Err(message) = system.uninstall_helper() {
        return Err(Notice { title: l10n::tr("Uninstall failed", &[]), message });
    }
    let all = manager.connections();
    let helper_disconnects = system.helper_disconnects();
    for c in all.iter().filter(|c| c.kind.is_native() || !helper_disconnects) {
        if manager.state(&uuid_string(&c.id)).is_active() {
            manager.disconnect(c);
        }
    }
    system.stop_polling();
    let had_native = all.iter().any(|c| c.kind.is_native());
    // No orphaned login item.
    let mut login_item_left = system.unregister_login_item().is_err();
    login_item_left |= system.remove_stale_login_entries().is_err();
    // WinVPN: its Windows VPN entries and their PSKs (in Windows' own store, outside the data folder), before the
    // folder goes. Then every `WinVPN-<UUID>` entry left (a locked vault lists only the active connections): no
    // connection is kept. Never anything else (the platform removes only its own entries).
    let profiles = &connections.deps().profiles;
    let removes_profiles = profiles.removes_profiles();
    if removes_profiles {
        for c in &all {
            profiles.remove(&c.id);
        }
        profiles.reconcile(&HashSet::new());
    }
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
    if had_native && !removes_profiles {
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
