//! The system status check (port of `SetupChecker.swift`): Homebrew, the VPN tools, the root layer's VERSION
//! against the bundled one, and whether `sudo -n mvpn` works.

use crate::command::CommandRunner;
use crate::mvpn_client::{INSTALL_DIR, MvpnClient};
use macvpn_core::l10n::AppLanguage;
use macvpn_core::models::VPNKind;
use macvpn_core::swift_str;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SetupReport {
    pub brew_prefix: Option<String>,
    /// In the order of [`SetupChecker::REQUIRED_TOOLS`].
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
        self.brew_prefix.is_some() && self.missing_tools.is_empty() && self.root_ok()
    }

    pub fn is_available(&self, kind: VPNKind) -> bool {
        if kind.is_native() {
            return true;
        }
        if !self.root_ok() || self.brew_prefix.is_none() {
            return false;
        }
        let needed = SetupChecker::REQUIRED_TOOLS.iter().find(|(k, _)| *k == kind).map(|(_, t)| *t).unwrap_or(&[]);
        needed.iter().all(|t| !self.missing_tools.iter().any(|m| m == t))
    }
}

type ReadFile<'a> = Box<dyn Fn(&str) -> Option<String> + 'a>;

pub struct SetupChecker<'a> {
    runner: &'a dyn CommandRunner,
    file_exists: Box<dyn Fn(&str) -> bool + 'a>,
    read_file: ReadFile<'a>,
    bundled_root_dir: Option<PathBuf>,
}

impl<'a> SetupChecker<'a> {
    pub const REQUIRED_TOOLS: [(VPNKind, &'static [&'static str]); 4] = [
        (VPNKind::Openvpn, &["openvpn"]),
        (VPNKind::Wireguard, &["wg", "wg-quick", "wireguard-go", "bash"]),
        (VPNKind::Strongswan, &["swanctl", "charon"]),
        (VPNKind::Sstp, &["sstpc"]),
    ];
    pub const BREW_PACKAGES: [&'static str; 5] = ["openvpn", "wireguard-tools", "strongswan", "sstp-client", "bash"];
    pub const BREW_PREFIXES: [&'static str; 2] = ["/opt/homebrew", "/usr/local"];
    /// The root layer's executables ([`crate::root_installer::ROOT_FILES`] without VERSION). Root layer 7 is a
    /// single binary.
    pub const ROOT_EXECUTABLES: [&'static str; 1] = ["mvpn"];

    /// The real checker: executable-file test and UTF-8 file reads on the real file system.
    pub fn new(runner: &'a dyn CommandRunner, bundled_root_dir: Option<PathBuf>) -> Self {
        Self::with_io(
            runner,
            |p| crate::sys::is_executable_file(Path::new(p)),
            |p| std::fs::read(p).ok().and_then(|d| String::from_utf8(d).ok()),
            bundled_root_dir,
        )
    }

    pub fn with_io(
        runner: &'a dyn CommandRunner,
        file_exists: impl Fn(&str) -> bool + 'a,
        read_file: impl Fn(&str) -> Option<String> + 'a,
        bundled_root_dir: Option<PathBuf>,
    ) -> Self {
        SetupChecker { runner, file_exists: Box::new(file_exists), read_file: Box::new(read_file), bundled_root_dir }
    }

    /// Mirrors `mvpn`'s find_tool / find_charon paths.
    pub fn candidates(tool: &str, prefix: &str) -> Vec<String> {
        if tool == "charon" {
            return vec![
                format!("{prefix}/opt/strongswan/libexec/ipsec/charon"),
                format!("{prefix}/opt/strongswan/libexec/charon"),
            ];
        }
        vec![format!("{prefix}/bin/{tool}"), format!("{prefix}/sbin/{tool}")]
    }

    pub fn check(&self) -> SetupReport {
        let prefix =
            Self::BREW_PREFIXES.iter().find(|p| (self.file_exists)(&format!("{p}/bin/brew"))).map(|p| p.to_string());
        let mut missing: Vec<String> = Vec::new();
        for (_, tools) in Self::REQUIRED_TOOLS {
            for tool in tools {
                if missing.iter().any(|m| m == tool) {
                    continue;
                }
                let found =
                    prefix.as_ref().is_some_and(|p| Self::candidates(tool, p).iter().any(|c| (self.file_exists)(c)));
                if !found {
                    missing.push(tool.to_string());
                }
            }
        }
        let trim =
            |s: Option<String>| s.map(|s| s.trim_matches(swift_str::is_foundation_whitespace_or_newline).to_string());
        let installed = trim((self.read_file)(&format!("{INSTALL_DIR}/VERSION")));
        let bundled =
            trim(self.bundled_root_dir.as_ref().and_then(|d| (self.read_file)(&d.join("VERSION").to_string_lossy())));
        let sudo = self
            .runner
            .run("/usr/bin/sudo", &MvpnClient::sudo_arguments(&["version".to_string()], AppLanguage::current()), None)
            .is_ok_and(|r| r.exit_code == 0);
        // The root executables, checked even with a matching VERSION (against an interrupted install).
        let missing_root = if installed.is_none() {
            Vec::new()
        } else {
            Self::ROOT_EXECUTABLES
                .iter()
                .filter(|f| !(self.file_exists)(&format!("{INSTALL_DIR}/{f}")))
                .map(|f| f.to_string())
                .collect()
        };
        SetupReport {
            brew_prefix: prefix,
            missing_tools: missing,
            installed_root_version: installed,
            bundled_root_version: bundled,
            sudo_works: sudo,
            missing_root_files: missing_root,
        }
    }
}
