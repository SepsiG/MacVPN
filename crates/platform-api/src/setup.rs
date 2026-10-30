//! The system status check and the installers of the tools and the privileged helper.

use crate::PlatformError;
use macvpn_core::l10n;
use macvpn_core::models::VPNKind;
use std::path::Path;

/// What the system check found.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SetupReport {
    /// The package manager's location (macOS: the Homebrew prefix); `None`: not installed.
    pub package_manager: Option<String>,
    /// The tools each helper-run kind needs, in the checker's order (the platform's table; macOS:
    /// `SetupChecker::REQUIRED_TOOLS`). A kind without an entry needs no tool.
    pub required_tools: &'static [(VPNKind, &'static [&'static str])],
    /// In the order of [`Self::required_tools`].
    pub missing_tools: Vec<String>,
    pub installed_root_version: Option<String>,
    pub bundled_root_version: Option<String>,
    pub sudo_works: bool,
    /// Missing executables of the installed root layer (an interrupted install): a reinstall is needed.
    pub missing_root_files: Vec<String>,
    /// The platform has no VPN engine yet (WinVPN 2a): the short, localized answer to every connect ("The VPN
    /// engine comes in a later version of WinVPN."). No kind is available then, and nothing is missing that the user
    /// could install. `None` (macOS): the fields above decide.
    pub engine_missing: Option<String>,
    /// The WinVPN Service's engine (WinVPN 2b): the service, OpenVPN and WireGuard rows, which decide whether
    /// OpenVPN and WireGuard can start. `None` (macOS): the fields above decide.
    pub engine: Option<EngineReport>,
    /// The kinds this platform offers only in a later version, with the localized reason (WinVPN 2b had the native
    /// VPNs here). Empty on macOS, and on Windows since 2.0.
    pub later_kinds: Vec<(VPNKind, String)>,
    /// The packages of the package manager that have a newer version (macOS: the Homebrew formulae of
    /// `SetupChecker::BREW_PACKAGES` that `brew outdated` lists, pinned ones left out), checked only when nothing is
    /// missing. Empty when none is outdated or it is unknown (the check failed or timed out). Never makes the report
    /// incomplete: the tools stay usable. Empty on Windows (the engine rows carry OpenVPN's update).
    pub outdated_packages: Vec<OutdatedPackage>,
    /// The Windows VPN client (RAS; WinVPN 2c): it runs L2TP/IPsec, IKEv2 and SSTP connections and the system VPNs
    /// in the user's own process, so its row (not the WinVPN Service's [`Self::engine_missing`]) decides whether
    /// they can start. `None` (macOS): the fields above decide.
    pub ras: Option<EngineRow>,
    /// The kinds this platform keeps (editable, exported, backed up) but cannot connect, with the localized reason
    /// (WinVPN 2c: Cisco IPsec). Empty on macOS.
    pub ras_unsupported_kinds: Vec<(VPNKind, String)>,
    /// LinVPN's engine (L-b): NetworkManager and the plugin each kind needs, which decide every kind and the system
    /// VPNs. `None` on macOS and Windows.
    pub nm: Option<NmReport>,
}

/// A package with a newer version (macOS: an outdated Homebrew formula).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OutdatedPackage {
    pub name: String,
    pub installed: String,
    pub available: String,
}

/// One row of the engine (Windows): green or red, its detail, and the action the row offers when it is red or an
/// update exists (`"install"` / `"repair"` / `"update"`; only OpenVPN has one).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EngineRow {
    /// Green: nothing to install or repair.
    pub ok: bool,
    /// Connections can start (OpenVPN: `openvpn.exe` passed its checks and at least one driver exists; a missing
    /// driver refuses only the connections that need it, with its own message).
    pub usable: bool,
    /// The row's localized detail line.
    pub detail: String,
    pub action: Option<&'static str>,
}

/// LinVPN's engine (L-b): NetworkManager and the plugin each kind needs (spec 4, resolved point 17).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NmReport {
    /// NetworkManager itself (on the bus, version ≥ 1.36: `AddAndActivateConnection2`).
    pub networkmanager: EngineRow,
    /// One row per kind, with the package(s) its Install button asks PackageKit for (space-separated; empty for
    /// WireGuard, built into NM).
    pub kinds: Vec<(VPNKind, EngineRow, String)>,
    /// The system's OpenVPN is 2.7 or later: NetworkManager sees the server's `redirect-gateway` (the editor's
    /// "Server decides" help text; L-b resolved point 7).
    pub openvpn_push_visible: bool,
}

impl NmReport {
    /// The row of `kind`; `None`: the report has none (the kind cannot start).
    pub fn row(&self, kind: VPNKind) -> Option<&EngineRow> {
        self.kinds.iter().find(|(k, _, _)| *k == kind).map(|(_, r, _)| r)
    }
}

/// The name of what a kind needs on Linux, as System Status and the row's "Not installed: …" name it.
fn plugin_name(kind: VPNKind) -> String {
    l10n::tr(
        match kind {
            VPNKind::L2tp => "NetworkManager L2TP plugin",
            VPNKind::Strongswan => "NetworkManager strongSwan plugin",
            VPNKind::Cisco => "NetworkManager vpnc plugin",
            VPNKind::Sstp => "NetworkManager SSTP plugin",
            VPNKind::Openvpn => "LinVPN OpenVPN service",
            VPNKind::Wireguard => "WireGuard (NetworkManager)",
        },
        &[],
    )
}

/// The WinVPN Service's engine as System Status shows it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EngineReport {
    pub service: EngineRow,
    pub openvpn: EngineRow,
    pub wireguard: EngineRow,
}

impl SetupReport {
    pub fn unknown() -> Self {
        Self::default()
    }

    pub fn root_ok(&self) -> bool {
        self.sudo_works
            && self.installed_root_version.is_some()
            && self.installed_root_version == self.bundled_root_version
            && self.missing_root_files.is_empty()
    }

    /// The reason a kind is not offered on this platform yet (WinVPN: the native VPNs, 2c).
    pub fn later_reason(&self, kind: VPNKind) -> Option<&str> {
        self.later_kinds.iter().find(|(k, _)| *k == kind).map(|(_, r)| r.as_str())
    }

    /// The reason the platform cannot connect a kind it keeps (WinVPN 2c: Cisco IPsec).
    pub fn ras_unsupported_reason(&self, kind: VPNKind) -> Option<&str> {
        self.ras_unsupported_kinds.iter().find(|(k, _)| *k == kind).map(|(_, r)| r.as_str())
    }

    /// The RAS row when it runs `kind` (L2TP/IPsec, IKEv2, SSTP; WinVPN 2c). `None` on macOS.
    fn ras_row(&self, kind: VPNKind) -> Option<&EngineRow> {
        matches!(kind, VPNKind::L2tp | VPNKind::Strongswan | VPNKind::Sstp).then_some(self.ras.as_ref()).flatten()
    }

    /// Nothing is missing that the user could install (the popover's System Status tile has no "!" mark, and the
    /// window does not open by itself at launch). Without the engine (WinVPN: the WinVPN Service the MSI installs
    /// is missing or unusable) it is not complete, though the RAS kinds still connect; with the service's engine
    /// every row must be green, except an OpenVPN that is only not installed (WinVPN 2.0: an optional engine; its
    /// row stays red with "Install", its connections greyed); a RAS row (WinVPN 2c) must be green too.
    pub fn is_complete(&self) -> bool {
        if let Some(nm) = &self.nm {
            return nm.networkmanager.ok && nm.kinds.iter().all(|(_, r, _)| r.ok);
        }
        let ras_ok = self.ras.as_ref().is_none_or(|r| r.ok);
        if self.engine_missing.is_some() {
            return false;
        }
        if let Some(e) = &self.engine {
            let openvpn_ok = e.openvpn.ok || (e.openvpn.action == Some("install") && !e.openvpn.usable);
            return e.service.ok && openvpn_ok && e.wireguard.ok && ras_ok;
        }
        self.package_manager.is_some() && self.missing_tools.is_empty() && self.root_ok() && ras_ok
    }

    /// A connection of `kind` can start (without an engine none can, nor a kind that comes later or that the
    /// platform cannot connect; the RAS row decides the kinds it runs, the service's engine rows the others).
    pub fn is_available(&self, kind: VPNKind) -> bool {
        if self.ras_unsupported_reason(kind).is_some() || self.later_reason(kind).is_some() {
            return false;
        }
        if let Some(nm) = &self.nm {
            return nm.networkmanager.usable && nm.row(kind).is_some_and(|r| r.usable);
        }
        if let Some(ras) = self.ras_row(kind) {
            return ras.usable;
        }
        if self.engine_missing.is_some() {
            return false;
        }
        if let Some(e) = &self.engine {
            return match kind {
                VPNKind::Openvpn => e.service.usable && e.openvpn.usable,
                VPNKind::Wireguard => e.service.usable && e.wireguard.usable,
                _ => false,
            };
        }
        if kind.is_native() {
            return true;
        }
        if !self.root_ok() || self.package_manager.is_none() {
            return false;
        }
        let needed = self.required_tools.iter().find(|(k, _)| *k == kind).map(|(_, t)| *t).unwrap_or(&[]);
        needed.iter().all(|t| !self.missing_tools.iter().any(|m| m == t))
    }
}

/// An engine a kind needs that is not usable: its name, and whether it is installed (then it needs a repair or an
/// update: "Not ready") or not ("Not installed").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingEngine {
    pub name: String,
    pub installed: bool,
}

impl MissingEngine {
    /// The row's localized label: "Not installed: <name>" or "Not ready: <name>".
    pub fn label(&self) -> String {
        l10n::tr(if self.installed { "Not ready: %@" } else { "Not installed: %@" }, &[l10n::Arg::Str(&self.name)])
    }
}

/// The name of a helper-run kind's tools on macOS (the Homebrew packages as System Status lists them).
fn tool_package(kind: VPNKind) -> &'static str {
    match kind {
        VPNKind::Openvpn => "OpenVPN",
        VPNKind::Wireguard => "WireGuard tools",
        VPNKind::Strongswan => "strongSwan",
        VPNKind::Sstp => "sstp-client",
        VPNKind::L2tp | VPNKind::Cisco => "",
    }
}

impl SetupReport {
    /// The engine `kind` lacks. `None` when it is available, or when the reason is not an engine
    /// ([`Self::engine_missing`], a later kind).
    pub fn missing_engine(&self, kind: VPNKind) -> Option<MissingEngine> {
        if self.is_available(kind) || self.later_reason(kind).is_some() || self.ras_unsupported_reason(kind).is_some() {
            return None;
        }
        let missing = |name: &str, installed: bool| Some(MissingEngine { name: name.to_string(), installed });
        // LinVPN: NetworkManager first (a system service: "Not installed"), then the kind's plugin; only a row that
        // offers "install" lacks its package, any other red row needs a repair ("Not ready").
        if let Some(nm) = &self.nm {
            if !nm.networkmanager.usable {
                return missing("NetworkManager", false);
            }
            let row = nm.row(kind);
            return missing(&plugin_name(kind), row.is_some_and(|r| r.action != Some("install")));
        }
        // The Windows VPN client is part of Windows: never "Not installed", only "Not ready" (a Windows service it
        // needs is disabled).
        if self.ras_row(kind).is_some() {
            return missing(&l10n::tr("Windows VPN client", &[]), true);
        }
        if self.engine_missing.is_some() {
            return None;
        }
        if let Some(e) = &self.engine {
            if !e.service.usable {
                return missing(&l10n::tr("WinVPN Service", &[]), true);
            }
            let (name, row) = match kind {
                VPNKind::Openvpn => ("OpenVPN Community", &e.openvpn),
                VPNKind::Wireguard => ("WireGuard", &e.wireguard),
                _ => return None,
            };
            // Only a row that offers "install" lacks the program; any other red row needs a repair or an update.
            return missing(name, row.action != Some("install"));
        }
        if kind.is_native() {
            return None;
        }
        if self.package_manager.is_none() {
            return missing("Homebrew", false);
        }
        if !self.root_ok() {
            let title = l10n::tr("Permissions (root scripts + sudoers)", &[]);
            return missing(&title, self.installed_root_version.is_some());
        }
        let needed = self.required_tools.iter().find(|(k, _)| *k == kind).map(|(_, t)| *t).unwrap_or(&[]);
        let absent: Vec<&str> = needed.iter().copied().filter(|t| self.missing_tools.iter().any(|m| m == t)).collect();
        // Only bash missing (WireGuard's wg-quick needs Homebrew's bash): name it.
        let name = if absent == ["bash"] { "bash" } else { tool_package(kind) };
        missing(name, false)
    }

    /// `None`: a connection of `kind` can start. Otherwise the row's localized label, from the first source that
    /// applies: the reason the platform cannot connect it, the engine-missing text (not for the kinds the RAS row
    /// runs), the later text, "Not installed: …" / "Not ready: …".
    pub fn unavailable_text(&self, kind: VPNKind) -> Option<String> {
        if self.is_available(kind) {
            return None;
        }
        if let Some(reason) = self.start_refusal(Some(kind)) {
            return Some(reason);
        }
        let engine = self.missing_engine(kind);
        let engine = engine.unwrap_or_else(|| MissingEngine { name: kind.display_name().to_string(), installed: true });
        Some(engine.label())
    }

    /// Why a start is refused outright (the `connect` command, the control API's `up`: failed with this text, not
    /// "set up first"): the reason the platform cannot connect the kind, the engine-missing text (except for the
    /// kinds the RAS row runs and, with a RAS row, the system VPNs: they need no WinVPN Service), the later text.
    /// `kind` `None`: a system VPN. `None`: the setup check ([`Self::is_available`]) decides.
    pub fn start_refusal(&self, kind: Option<VPNKind>) -> Option<String> {
        let Some(kind) = kind else {
            // LinVPN: a system VPN starts through NetworkManager.
            if let Some(nm) = &self.nm {
                return (!nm.networkmanager.usable).then(|| nm.networkmanager.detail.clone());
            }
            return self.engine_missing.clone().filter(|_| self.needs_service(None));
        };
        if let Some(reason) = self.ras_unsupported_reason(kind) {
            return Some(reason.to_string());
        }
        if self.needs_service(Some(kind))
            && let Some(reason) = &self.engine_missing
        {
            return Some(reason.clone());
        }
        self.later_reason(kind).map(str::to_string)
    }

    /// A start of `kind` (`None`: a system VPN) needs the platform's engine, so [`Self::engine_missing`] concerns
    /// it: every start without a RAS row (macOS, WinVPN before 2c); with one, only the kinds the WinVPN Service
    /// runs (not the RAS kinds, the system VPNs, or a kind the platform cannot connect at all). LinVPN (`nm`): no
    /// kind needs a service (NetworkManager's rows decide).
    pub fn needs_service(&self, kind: Option<VPNKind>) -> bool {
        if self.nm.is_some() {
            return false;
        }
        match kind {
            None => self.ras.is_none(),
            Some(kind) => self.ras_row(kind).is_none() && self.ras_unsupported_reason(kind).is_none(),
        }
    }
}

/// The localized lines the package-manager bootstrap script prints (macOS: `BrewBootstrap::script`'s arguments).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapTexts {
    pub start: String,
    pub done: String,
    pub failed: String,
}

/// How [`SystemSetup::update_package_index`] ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageIndexUpdate {
    /// Nothing to update: no package manager (Homebrew is absent), the sandbox, or a platform without one.
    Unavailable,
    /// Another package-manager command of the app is running (an install or upgrade): skipped this time.
    Busy,
    Updated,
    /// Offline, an error or the time limit: the message for the log.
    Failed(String),
}

/// The System Status window's checks and installs.
pub trait SystemSetup: Send + Sync {
    /// `bundled_helper_dir`: the helper shipped with the app (its VERSION is compared with the installed one).
    fn check(&self, bundled_helper_dir: Option<&Path>) -> SetupReport;
    /// Installs the package manager in a terminal window (macOS: Homebrew's installer; `parent` holds the
    /// script's private directory).
    fn install_package_manager(
        &self,
        texts: &BootstrapTexts,
        parent: &Path,
        sandbox: bool,
    ) -> Result<(), PlatformError>;
    /// Installs the missing tools of `report`, streaming the installer's output (with its header and footer
    /// lines) to `output` as it comes; blocking. The output is the user-facing text of the System Status window.
    fn install_tools(&self, report: &SetupReport, output: &mut dyn FnMut(&str)) -> Result<(), PlatformError>;
    /// Installs the privileged helper from `source_dir` for `user` (asks for the administrator's approval).
    fn install_helper(&self, source_dir: &Path, user: &str) -> Result<(), PlatformError>;
    fn uninstall_helper(&self, user: &str) -> Result<(), PlatformError>;
    /// The note that upgrading the helper disconnects the running VPNs.
    fn helper_upgrade_notice(&self) -> String;
    /// A note that replaces the System Status rows while this platform has no VPN engine (WinVPN in 2a: "The VPN
    /// engine comes in a later version of WinVPN. …", localized). `None`: the rows are shown (macOS).
    fn engine_note(&self) -> Option<String> {
        None
    }
    /// The note under the engine rows (WinVPN 2b had one: the native VPNs came later). `None`: no note (macOS, and
    /// WinVPN since 2.0).
    fn later_note(&self) -> Option<String> {
        None
    }
    /// The app is uninstalled through the system, not by the app (WinVPN: the MSI, in Settings → Apps; LinVPN: the
    /// package, `apt remove linvpn`): the localized note System Status shows, with a button to
    /// [`Self::open_system_uninstall`] (WinVPN; LinVPN has no page to open), instead of its own "Uninstall" button.
    /// `None` (macOS): the app's own uninstall.
    fn system_uninstall_note(&self) -> Option<String> {
        None
    }
    /// Opens the system's page for uninstalling apps (WinVPN: Settings → Apps → Installed apps). Nothing where
    /// [`Self::system_uninstall_note`] is `None`.
    fn open_system_uninstall(&self) {}
    /// Next to [`Self::system_uninstall_note`], the app removes itself from the user's account first (WinVPN:
    /// "Remove WinVPN from This Account…": every connection disconnected, launch at login, its Windows VPN entries
    /// with their PSKs, optionally the user data; then [`Self::open_system_uninstall`]). [`Self::uninstall_helper`]
    /// then removes nothing (the service belongs to the system's uninstaller) and disconnects nothing. `false`
    /// (macOS): the app's own uninstall, whose helper uninstall takes its connections down.
    fn account_cleanup(&self) -> bool {
        false
    }
    /// Refreshes the package manager's own index in the background, as the user, so the outdated check sees the
    /// newest versions (macOS: `brew update`, at most once a day; the caller schedules it). Blocking, with a time
    /// limit; never while another package-manager command of the app runs. Windows has no index: `Updated` with a
    /// usable WinVPN Service, so the app's next check asks winget and the service again. Default: nothing.
    fn update_package_index(&self) -> PackageIndexUpdate {
        PackageIndexUpdate::Unavailable
    }
    /// What [`Self::update_package_index`] runs, for the app's log line when it fails (not localized; macOS:
    /// `brew update`).
    fn package_index_task(&self) -> &'static str {
        "brew update"
    }
}
