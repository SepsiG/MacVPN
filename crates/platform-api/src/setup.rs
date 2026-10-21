//! The system status check and the installers of the tools and the privileged helper.

use crate::PlatformError;
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

    pub fn is_complete(&self) -> bool {
        self.package_manager.is_some() && self.missing_tools.is_empty() && self.root_ok()
    }

    pub fn is_available(&self, kind: VPNKind) -> bool {
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

/// The localized lines the package-manager bootstrap script prints (macOS: `BrewBootstrap::script`'s arguments).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapTexts {
    pub start: String,
    pub done: String,
    pub failed: String,
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
}
