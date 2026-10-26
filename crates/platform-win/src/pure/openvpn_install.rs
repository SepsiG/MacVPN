//! Installing OpenVPN Community for WinVPN (2b plan, Task 17; decision 4: `openvpn.exe`, DCO and TAP-Windows6;
//! OpenVPN's Interactive Service disabled after an install WinVPN made): the fixed command lines, which path an
//! action takes, the elevated step's arguments and exit code, and the texts. Nothing here runs anything.
//!
//! **The elevated step.** One UAC confirmation per install where the path allows it: WinVPN starts its own
//! installed `WinVPN.exe` elevated with [`STEP_ARG`] ([`step_parameters`]); that process trusts nothing the
//! unelevated app did. It takes only a plain local drive path ([`parse_step`]: no UNC, security review L-3), notes
//! whether OpenVPN is installed before anything runs (security review L-2), copies the MSI into a new folder only
//! administrators can change (`C:\ProgramData\WinVPN\installer\<random>`, security review L-1) and checks the
//! copy (SHA-256 for the pinned MSI, Authenticode signer, and its database: [`msi_properties_ok`]), runs
//! `%SystemRoot%\System32\msiexec.exe` with [`msiexec_parameters`] on the copy, deletes it, then disables, stops
//! and checks OpenVPN's Interactive Service when [`disable_interactive`] says so, writes the marker, and exits with
//! [`StepResult`] encoded ([`StepResult::code`]). After a winget install (winget asks for its own elevation) the same step runs
//! without an MSI ([`Step::Interactive`]) only when the Interactive Service must be disabled.

use crate::pure::openvpn_pins as pins;
use macvpn_core::l10n::{self, Arg};
use macvpn_core::service_proto::{OpenVpnFacts, Version};
use std::path::Path;

/// msiexec's or winget's exit code, as System Status reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Done,
    DoneRestartNeeded,
    Cancelled,
    Failed(u32),
}

/// msiexec and winget exit codes; 1602 is `ERROR_INSTALL_USEREXIT`, 1223 `ERROR_CANCELLED` (UAC declined).
pub fn outcome(code: u32) -> Outcome {
    match code {
        0 => Outcome::Done,
        3010 => Outcome::DoneRestartNeeded,
        1602 | 1223 => Outcome::Cancelled,
        c => Outcome::Failed(c),
    }
}

/// An exit code as the user reads it: small ones (msiexec's) in decimal, winget's HRESULTs in hex.
pub fn code_text(code: u32) -> String {
    if code < 0x1_0000 { code.to_string() } else { format!("0x{code:08X}") }
}

/// The OpenVPN row's action (`EngineRow::action` of `pure::engine::report`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Install,
    Repair,
    Update,
}

impl Action {
    pub fn parse(s: &str) -> Option<Action> {
        match s {
            "install" => Some(Action::Install),
            "repair" => Some(Action::Repair),
            "update" => Some(Action::Update),
            _ => None,
        }
    }
}

/// How an action starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum First {
    /// `winget install` (`update: false`) or `winget upgrade`, then the pinned MSI if a driver is still missing.
    Winget { update: bool },
    /// The pinned MSI directly.
    Msi,
    /// Nothing WinVPN can do; the text says what the user can.
    Refuse(String),
}

/// The path of `action`. `installed`: the installed `openvpn.exe`'s version (`None`: not installed or unknown);
/// `pinned`: `OPENVPN_VERSION`. "Repair" of the pinned version is a maintenance install of the pinned MSI (it adds
/// the missing features); of another version it needs winget's `upgrade` (the pinned MSI cannot change another
/// version's features), and without winget the user adds the drivers in Settings.
pub fn first_step(action: Action, installed: Option<&str>, pinned: &str, has_winget: bool) -> First {
    let same = matches!((installed.and_then(Version::parse), Version::parse(pinned)), (Some(a), Some(b)) if a == b);
    match (action, has_winget) {
        (Action::Repair, _) if same => First::Msi,
        (Action::Repair, true) => First::Winget { update: true },
        (Action::Repair, false) => First::Refuse(add_drivers_in_settings()),
        (Action::Install, true) => First::Winget { update: false },
        (Action::Update, true) => First::Winget { update: true },
        (Action::Install | Action::Update, false) => First::Msi,
    }
}

/// Both data-channel drivers WinVPN uses are installed (decision 4: DCO and TAP-Windows6).
pub fn drivers_complete(facts: &OpenVpnFacts) -> bool {
    facts.dco.is_some() && facts.tap_windows6.is_some()
}

/// Decision 4 (amended 2026-10-22): OpenVPN's Interactive Service is disabled only on an installation WinVPN made:
/// OpenVPN was absent before this install, or WinVPN's marker (`HKLM\SOFTWARE\WinVPN`, `OpenVpnInstalledByWinVpn`
/// = 1) says an earlier install was WinVPN's. A user's own installation (which the OpenVPN GUI may need) is never
/// touched.
pub fn disable_interactive(absent_before: bool, marker: bool) -> bool {
    absent_before || marker
}

/// The machine key and value of WinVPN's marker (written only by the elevated step).
pub const MARKER_KEY: &str = r"SOFTWARE\WinVPN";
pub const MARKER_VALUE: &str = "OpenVpnInstalledByWinVpn";
/// Where OpenVPN records `openvpn.exe` (the service's detection reads the same value).
pub const OPENVPN_KEY: &str = r"SOFTWARE\OpenVPN";
pub const OPENVPN_EXE_VALUE: &str = "exe_path";

/// OpenVPN Community's winget package (decision 4, amended 2026-10-24: winget installs and updates to its newest
/// version; nothing on the winget path names a version).
pub const WINGET_ID: &str = "OpenVPNTechnologies.OpenVPN";

pub fn winget_args(update: bool, features: &str) -> Vec<String> {
    let mut a: Vec<String> = [
        if update { "upgrade" } else { "install" },
        "--id",
        WINGET_ID,
        "--exact",
        "--source",
        "winget",
        "--scope",
        "machine",
        "--silent",
        "--accept-package-agreements",
        "--accept-source-agreements",
        "--disable-interactivity",
        "--override",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    a.push(format!("/qn /norestart ADDLOCAL={features}"));
    a
}

/// A feature list is `[A-Za-z0-9._,]` only (the pins file; never user input).
fn valid_features(f: &str) -> bool {
    !f.is_empty() && f.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b','))
}

/// A path that can be written in double quotes on a command line that `CommandLineToArgvW` (or msiexec) splits,
/// and that the elevated step may open: a plain absolute path on a local drive letter
/// ([`crate::pure::update::is_plain_windows_path`]: valid Unicode, no `"`, no control character, never ending in `\`
/// (which would escape the closing quote), and never UNC: security review L-3).
fn quotable(path: &Path) -> Option<&str> {
    let p = path.to_str()?;
    crate::pure::update::is_plain_windows_path(p).then_some(p)
}

/// `msiexec`'s parameters (one string, which msiexec parses itself): the path must be quotable, so it cannot end
/// the quoting.
pub fn msiexec_parameters(msi: &Path, features: &str) -> Option<String> {
    let p = quotable(msi)?;
    if !valid_features(features) {
        return None;
    }
    Some(format!(r#"/i "{p}" /qb! /norestart ADDLOCAL={features}"#))
}

/// The pinned MSI of a CPU architecture (`std::env::consts::ARCH`): URL, SHA-256, features.
pub fn pinned_msi(arch: &str) -> Option<(&'static str, &'static str, &'static str)> {
    match arch {
        "x86_64" => Some((pins::OPENVPN_MSI_X64_URL, pins::OPENVPN_MSI_X64_SHA256, pins::OPENVPN_MSI_X64_FEATURES)),
        "aarch64" => {
            Some((pins::OPENVPN_MSI_ARM64_URL, pins::OPENVPN_MSI_ARM64_SHA256, pins::OPENVPN_MSI_ARM64_FEATURES))
        }
        _ => None,
    }
}

/// An official MSI the elevated step may run without a pin: its file name is an official MSI name for `arch`
/// ([`parse_msi_name`]) whose OpenVPN version is at least the pin's (never older than what WinVPN pins).
pub fn official_msi_name_ok(path: &Path, arch: &str, pinned: &str) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else { return false };
    matches!((parse_msi_name(name, arch), Version::parse(pinned)), (Some((v, _)), Some(p)) if v >= p)
}

/// The file name of a pinned URL (its last segment), when it is a plain `….msi` name.
pub fn msi_file_name(url: &str) -> Option<&str> {
    let name = url.rsplit('/').next()?;
    let ok = name.len() > 4
        && name.ends_with(".msi")
        && name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    ok.then_some(name)
}

/// OpenVPN Community MSIs' `Manufacturer` (the `Property` table; read 2026-10-25 from 2.6.15 and 2.7.8).
pub const OPENVPN_MSI_MANUFACTURER: &str = "OpenVPN, Inc.";

/// The `UpgradeCode` of OpenVPN Community's MSIs for a CPU architecture (`std::env::consts::ARCH`): the same for
/// every release of one architecture (2.6.15 and 2.7.8 amd64 share it), so it is what the MSI's major upgrade
/// matches. Read on the Windows test machine (2026-10-25) from OpenVPN-2.7.8-I001-amd64.msi and -arm64.msi.
pub fn openvpn_upgrade_code(arch: &str) -> Option<&'static str> {
    match arch {
        "x86_64" => Some("{461BDF86-D389-4471-BF36-99806B64C127}"),
        "aarch64" => Some("{1E8C4DDC-9E93-4AE2-9495-DF86821EAA3A}"),
        _ => None,
    }
}

/// What an MSI's database says it installs (`props`: its `Property` table as (name, value) rows), checked in the
/// elevated step on the copy it installs (security review L-2: the file name proves nothing): exactly one each of
/// `ProductName` (`OpenVPN`, or `OpenVPN <version…>` as 2.6 had it), `Manufacturer`
/// ([`OPENVPN_MSI_MANUFACTURER`]), `UpgradeCode` (this architecture's, [`openvpn_upgrade_code`]) and
/// `ProductVersion` (`2.7.801` = OpenVPN 2.7.8 I001, [`openvpn_version_of_winget`]) not older than `pinned`. The
/// OpenVPN version, or `None`.
pub fn msi_properties_ok(props: &[(String, String)], arch: &str, pinned: &str) -> Option<Version> {
    let one = |name: &str| {
        let mut values = props.iter().filter(|(k, _)| k == name).map(|(_, v)| v.as_str());
        match (values.next(), values.next()) {
            (Some(v), None) => Some(v),
            _ => None,
        }
    };
    let product = one("ProductName")?;
    let named = product == "OpenVPN"
        || product.strip_prefix("OpenVPN ").is_some_and(|r| r.starts_with(|c: char| c.is_ascii_digit()));
    let upgrade = openvpn_upgrade_code(arch)?;
    if !named || one("Manufacturer")? != OPENVPN_MSI_MANUFACTURER || !one("UpgradeCode")?.eq_ignore_ascii_case(upgrade)
    {
        return None;
    }
    let version = openvpn_version_of_winget(one("ProductVersion")?)?;
    (version >= Version::parse(pinned)?).then_some(version)
}

/// The pinned MSI may follow (a failed winget, drivers still missing) only when it is not older than the installed
/// OpenVPN (`installed`: `None` when there is none or its version is unknown): it never downgrades a newer
/// installation winget made.
pub fn msi_fallback_allowed(installed: Option<&str>, pinned: &str) -> bool {
    match (installed.map(Version::parse), Version::parse(pinned)) {
        (None, Some(_)) => true,
        (Some(Some(i)), Some(p)) => i <= p,
        _ => false,
    }
}

// MARK: - The newest official MSI (2b plan, "As built (fix4)")

/// OpenVPN's official Community download page: it links the newest release's MSIs (`OpenVPN-<version>-I<build>-
/// <amd64|arm64|x86>.msi` on `swupdate.openvpn.org`, with a GnuPG `.asc` each). The page is fetched only from
/// [`OFFICIAL_PAGE_HOSTS`] (`/community-downloads/` redirects to `/community/` there).
pub const OFFICIAL_PAGE: &str = "https://openvpn.net/community-downloads/";
pub const OFFICIAL_PAGE_HOSTS: &[&str] = &["openvpn.net"];
/// The hosts an official MSI is downloaded from (`swupdate.openvpn.org` redirects to `.net`).
pub const OFFICIAL_MSI_HOSTS: &[&str] = &["swupdate.openvpn.org", "swupdate.openvpn.net"];
/// The largest page read (about 200 KB on 2026-10-24) and curl's time limit for it.
pub const OFFICIAL_PAGE_MAX_BYTES: u64 = 4 << 20;
pub const OFFICIAL_PAGE_SECS: f64 = 30.0;
/// Every MSI link the page is searched for starts so.
const MSI_PREFIX: &str = "https://swupdate.openvpn.org/community/releases/";

/// An official OpenVPN Community MSI: its OpenVPN version, the installer build (`I002` = 2) and its URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfficialMsi {
    pub version: Version,
    pub installer: u16,
    pub url: String,
}

/// The MSI file name's architecture for a Rust architecture name.
pub fn msi_arch(arch: &str) -> Option<&'static str> {
    match arch {
        "x86_64" => Some("amd64"),
        "aarch64" => Some("arm64"),
        _ => None,
    }
}

/// `OpenVPN-<major.minor.patch>-I<1–4 digits>-<arch>.msi` exactly: the version and the installer build.
pub fn parse_msi_name(name: &str, arch: &str) -> Option<(Version, u16)> {
    let rest = name.strip_prefix("OpenVPN-")?.strip_suffix(&format!("-{}.msi", msi_arch(arch)?))?;
    let (version, build) = rest.split_once("-I")?;
    if build.is_empty() || build.len() > 4 || !build.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((Version::parse(version)?, build.parse().ok()?))
}

/// The newest MSI for `arch` the page links (highest version, then installer build); `None` when it links none.
/// A link counts only as `https://swupdate.openvpn.org/community/releases/<name>` with a [`parse_msi_name`] name,
/// ended by a character that cannot continue a URL's file name (so `….msi.asc` is not an MSI).
pub fn parse_official_page(html: &str, arch: &str) -> Option<OfficialMsi> {
    let mut best: Option<OfficialMsi> = None;
    let mut rest = html;
    while let Some(at) = rest.find(MSI_PREFIX) {
        rest = &rest[at + MSI_PREFIX.len()..];
        let end =
            rest.find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))).unwrap_or(rest.len());
        let name = &rest[..end];
        if let Some((version, installer)) = parse_msi_name(name, arch)
            && best.as_ref().is_none_or(|b| (version, installer) > (b.version, b.installer))
        {
            best = Some(OfficialMsi { version, installer, url: format!("{MSI_PREFIX}{name}") });
        }
    }
    best
}

/// The pinned MSI of `arch` as an [`OfficialMsi`] (its URL names its version and build).
pub fn pinned_official(arch: &str) -> Option<OfficialMsi> {
    let (url, _, _) = pinned_msi(arch)?;
    let (version, installer) = parse_msi_name(url.strip_prefix(MSI_PREFIX)?, arch)?;
    Some(OfficialMsi { version, installer, url: url.to_string() })
}

/// Which MSI the MSI path installs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MsiPick {
    /// The pinned MSI (SHA-256 and signer; the offline and bootstrap fallback).
    Pinned(OfficialMsi),
    /// The newest official MSI found at runtime (HTTPS from OpenVPN's hosts and the Authenticode signer).
    Official(OfficialMsi),
}

impl MsiPick {
    pub fn msi(&self) -> &OfficialMsi {
        match self {
            MsiPick::Pinned(m) | MsiPick::Official(m) => m,
        }
    }
}

/// The official MSI only when it is a newer OpenVPN than the pin (decision 4 as amended 2026-10-24, fix4: always
/// the newest); for the pin's own version the hash-pinned MSI is used (the same OpenVPN with a stronger check).
/// Nothing found (offline, the page changed) = the pin, never an error.
pub fn pick_msi(discovered: Option<OfficialMsi>, pinned: OfficialMsi) -> MsiPick {
    match discovered {
        Some(d) if d.version > pinned.version => MsiPick::Official(d),
        _ => MsiPick::Pinned(pinned),
    }
}

// MARK: - The update check (System Status' OpenVPN row; decision 4 as amended 2026-10-24)

/// Where an update comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    /// `winget upgrade` (Task 17's winget path).
    Winget,
    /// The pinned MSI (Task 17's MSI path: one UAC prompt; the MSI's major upgrade replaces any older OpenVPN
    /// Community MSI installation, winget's included: the same `UpgradeCode`).
    Msi,
}

/// Whether a newer OpenVPN Community than the installed one is available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Upgrade {
    /// Not asked, or no reliable answer (winget failed, timed out or printed something unexpected). Never an error
    /// row: the row stays as the service's facts make it, without "Update".
    Unknown,
    /// Nothing newer.
    None,
    /// A newer version: as the user reads it (`shown`, `2.7.8`), as OpenVPN's version (`version`, for choosing),
    /// and where it comes from.
    Available { shown: String, version: Version, via: Via },
}

/// How long System Status waits for winget's answer before it counts as [`Upgrade::Unknown`].
pub const WINGET_CHECK_SECS: u64 = 30;

/// The largest winget output the check reads (its table of one package is a few hundred bytes).
pub const WINGET_CHECK_MAX_BYTES: usize = 64 << 10;

/// `winget list` of OpenVPN's package, only when winget has an upgrade for it (read-only: nothing is installed).
/// `--source winget` keeps the msstore source and its agreement text out; `--disable-interactivity` never waits for
/// input.
pub fn winget_check_args() -> Vec<String> {
    [
        "list",
        "--id",
        WINGET_ID,
        "--exact",
        "--source",
        "winget",
        "--upgrade-available",
        "--disable-interactivity",
        "--accept-source-agreements",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// `APPINSTALLER_CLI_ERROR_NO_APPLICATIONS_FOUND`: winget found no installed package that matches.
pub const WINGET_NO_APPLICATIONS_FOUND: u32 = 0x8A15_0014;

/// The answer of [`winget_check_args`]'s `winget list`. winget's table is localized (headers, messages, the
/// package name) and column-aligned, so only what does not change with the language is read: the exit code, and
/// the row whose whitespace-separated tokens contain [`WINGET_ID`] exactly; after the ID come the installed
/// version, the available version and (without `--source`) the source. Captured on Windows 11 with winget
/// 1.29.380: no upgrade = exit 0 (or `0x8A150014`) with one message line and no table; an upgrade = a header
/// line, a line of dashes and one row per package.
///
/// - another exit code → [`Upgrade::Unknown`];
/// - the ID's row with an available version winget's way (`2.7.801`, [`openvpn_version_of_winget`]) →
///   [`Upgrade::Available`]; an ID row without one → `Unknown`;
/// - no ID row but a table (a line of dashes: the row was truncated or is another package's) → `Unknown`;
/// - no table at all → [`Upgrade::None`].
///
/// `installed` (the service's `openvpn.exe` version) only shapes the text: when winget's newer package maps to
/// the same OpenVPN version (a rebuilt installer, `2.7.701` → `2.7.702`), winget's own version is shown.
pub fn parse_winget_check(code: u32, output: &str, installed: Version) -> Upgrade {
    if code != 0 && code != WINGET_NO_APPLICATIONS_FOUND {
        return Upgrade::Unknown;
    }
    let mut table = false;
    for line in output.split(['\r', '\n']) {
        let line = line.trim();
        if line.len() >= 3 && line.chars().all(|c| c == '-' || c == '\u{2500}') {
            table = true;
            continue;
        }
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let Some(at) = tokens.iter().position(|t| *t == WINGET_ID) else { continue };
        let Some(available) = tokens.get(at + 2) else { return Upgrade::Unknown };
        return match openvpn_version_of_winget(available) {
            Some(v) if v > installed => Upgrade::Available { shown: v.to_string(), version: v, via: Via::Winget },
            Some(v) => Upgrade::Available { shown: (*available).to_string(), version: v, via: Via::Winget },
            None => Upgrade::Unknown,
        };
    }
    if table { Upgrade::Unknown } else { Upgrade::None }
}

/// OpenVPN's version from its winget package version: winget lists the MSI's `ProductVersion`, whose third part is
/// the patch level times 100 plus the installer build (`2.7.701` = 2.7.7 I001, `2.6.2302` = 2.6.23 I002,
/// `2.7.017` = 2.7.0 I017; `winget show --versions`, 2026-10-24); a third part of one or two digits is taken as
/// the patch level itself. `None` when it is not `major.minor.patch`.
pub fn openvpn_version_of_winget(s: &str) -> Option<Version> {
    let Version(major, minor, build) = Version::parse(s)?;
    let digits = s.rsplit('.').next().map_or(0, str::len);
    Some(Version(major, minor, if digits >= 3 { build / 100 } else { build }))
}

/// The update System Status offers: the newest of winget's offer (`winget`: [`parse_winget_check`]'s answer, or
/// [`Upgrade::None`] without winget) and the pinned MSI when it is newer than `installed` (decision 4 as amended
/// 2026-10-24: always the newest OpenVPN). winget's offer wins when it is at least the pin's version; the pin wins
/// over an older (or same-version rebuilt) winget offer, over "nothing newer" and over "unknown". Without a newer
/// pin, winget's answer stands. The pin is never offered when it is not newer than the installed version (no
/// downgrade).
pub fn choose_update(winget: &Upgrade, installed: Version, pinned: &str) -> Upgrade {
    let pin = Version::parse(pinned).filter(|p| *p > installed);
    match (winget, pin) {
        (Upgrade::Available { version, .. }, Some(p)) if *version >= p => winget.clone(),
        (_, Some(p)) => Upgrade::Available { shown: p.to_string(), version: p, via: Via::Msi },
        (_, None) => winget.clone(),
    }
}

/// How "Update" starts, from the update System Status offered ([`choose_update`], asked again when the action
/// runs): the pinned MSI when that is the newest, else winget's `upgrade` when winget exists, else the pinned MSI.
pub fn update_first(choice: &Upgrade, has_winget: bool) -> First {
    match choice {
        Upgrade::Available { via: Via::Msi, .. } => First::Msi,
        _ if has_winget => First::Winget { update: true },
        _ => First::Msi,
    }
}

// MARK: - The elevated step

/// The first argument of `WinVPN.exe` in the elevated step (no other mode of the app takes it).
pub const STEP_ARG: &str = "--winvpn-openvpn-step";

/// What the elevated step does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Checks and installs the pinned MSI at this path. Whether OpenVPN was absent before is the elevated
    /// process' own finding (it looks before msiexec runs), never an argument (security review L-2).
    Msi { path: String },
    /// After winget installed or updated OpenVPN: only the Interactive Service. `absent_before`: OpenVPN was
    /// absent before winget ran (the elevated process comes after winget, so it cannot see that itself; the
    /// argument can only make WinVPN disable OpenVPN's Interactive Service, never install anything).
    Interactive { absent_before: bool },
    /// Checks and installs a newest official MSI at this path (fix4): no pin, so the elevated process requires its
    /// name to be an official MSI name of this machine's architecture, its database to name OpenVPN Community not
    /// older than the pin ([`msi_properties_ok`]), and its Authenticode signer to be the pinned signer.
    OfficialMsi { path: String },
}

/// The parameters of the elevated `WinVPN.exe` (after [`STEP_ARG`]); `None` for a path that cannot be quoted.
pub fn step_parameters(step: &Step) -> Option<String> {
    match step {
        Step::Msi { path } => Some(format!(r#"{STEP_ARG} msi "{}""#, quotable(Path::new(path))?)),
        Step::Interactive { absent_before } => Some(format!("{STEP_ARG} interactive {}", before(*absent_before))),
        Step::OfficialMsi { path } => Some(format!(r#"{STEP_ARG} msi-official "{}""#, quotable(Path::new(path))?)),
    }
}

fn before(absent: bool) -> &'static str {
    if absent { "absent" } else { "present" }
}

fn parse_before(s: &str) -> Option<bool> {
    match s {
        "absent" => Some(true),
        "present" => Some(false),
        _ => None,
    }
}

/// The step from `WinVPN.exe`'s arguments (without the program name); `None` when they are not exactly a step's.
/// An MSI path must be a plain local drive path ([`quotable`]) before anything opens it: a UNC path would make the
/// elevated process log on to another machine with the administrator's token (security review L-3). The elevated
/// process checks the file itself again; nothing else is read from the arguments.
pub fn parse_step(args: &[String]) -> Option<Step> {
    match args {
        [first, mode, path] if first == STEP_ARG && mode == "msi" => {
            Some(Step::Msi { path: quotable(Path::new(path))?.to_string() })
        }
        [first, mode, before] if first == STEP_ARG && mode == "interactive" => {
            Some(Step::Interactive { absent_before: parse_before(before)? })
        }
        [first, mode, path] if first == STEP_ARG && mode == "msi-official" => {
            Some(Step::OfficialMsi { path: quotable(Path::new(path))?.to_string() })
        }
        _ => None,
    }
}

/// What the elevated step did with the Interactive Service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Interactive {
    /// Not WinVPN's installation (or the install did not succeed): not touched.
    Untouched,
    /// Disabled and stopped, checked, and the marker written.
    Disabled,
    /// Disabling, stopping or the check failed (the marker is written when it could be).
    NotDisabled,
    /// Disabled and stopped, but the marker could not be written.
    MarkerNotWritten,
}

/// Why the elevated step did not get to run msiexec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepError {
    /// The arguments were not a step's.
    Arguments,
    /// The MSI's SHA-256 or signer did not match the pins (checked again elevated).
    NotVerified,
    /// msiexec could not be started.
    NoMsiexec,
    /// The MSI's database does not name OpenVPN Community at or above the pin ([`msi_properties_ok`]).
    NotOpenVpn,
    /// The MSI could not be copied into the admin-only folder it is installed from.
    NotStaged,
}

/// The elevated step's result, carried in its exit code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StepResult {
    /// msiexec's exit code, when it ran.
    pub msi: Option<u32>,
    pub interactive: Interactive,
    pub error: Option<StepError>,
}

/// Bit 29: the application bit of a Win32 error code, so a step code is never a system or msiexec code (and an
/// exit code without it is not the step's: a crash, `ERROR_CANCELLED` from UAC).
const STEP_BIT: u32 = 1 << 29;
const MSI_RAN: u32 = 1 << 16;
/// Every bit a step code may have.
const STEP_BITS: u32 = STEP_BIT | 0x0077_FFFF;

impl StepResult {
    /// The exit code: bit 29, msiexec's code in bits 0–15 with bit 16 when it ran, the Interactive Service in bits
    /// 17–18, the error in bits 20–22.
    pub fn code(&self) -> u32 {
        let msi = self.msi.map_or(0, |c| MSI_RAN | (c & 0xFFFF));
        let interactive = match self.interactive {
            Interactive::Untouched => 0,
            Interactive::Disabled => 1,
            Interactive::NotDisabled => 2,
            Interactive::MarkerNotWritten => 3,
        };
        let error = match self.error {
            None => 0,
            Some(StepError::Arguments) => 1,
            Some(StepError::NotVerified) => 2,
            Some(StepError::NoMsiexec) => 3,
            Some(StepError::NotOpenVpn) => 4,
            Some(StepError::NotStaged) => 5,
        };
        STEP_BIT | msi | (interactive << 17) | (error << 20)
    }

    /// The result of an exit code; `None` when it is not a step's code.
    pub fn from_code(code: u32) -> Option<StepResult> {
        if code & !STEP_BITS != 0 || code & STEP_BIT == 0 {
            return None;
        }
        let msi = (code & MSI_RAN != 0).then_some(code & 0xFFFF);
        if msi.is_none() && code & 0xFFFF != 0 {
            return None;
        }
        let interactive = match (code >> 17) & 3 {
            0 => Interactive::Untouched,
            1 => Interactive::Disabled,
            2 => Interactive::NotDisabled,
            _ => Interactive::MarkerNotWritten,
        };
        let error = match (code >> 20) & 7 {
            0 => None,
            1 => Some(StepError::Arguments),
            2 => Some(StepError::NotVerified),
            3 => Some(StepError::NoMsiexec),
            4 => Some(StepError::NotOpenVpn),
            5 => Some(StepError::NotStaged),
            _ => return None,
        };
        Some(StepResult { msi, interactive, error })
    }
}

// MARK: - Texts (the literals are the l10n keys)

pub fn installing(version: &str) -> String {
    l10n::tr("Installing OpenVPN Community %@…", &[Arg::Str(version)])
}

/// The winget path's first line: it installs winget's newest OpenVPN, whatever version WinVPN pins.
pub fn installing_with_winget() -> String {
    l10n::tr("Installing the newest OpenVPN Community with winget…", &[])
}

pub fn winget_failed(code: u32) -> String {
    l10n::tr("winget could not install OpenVPN (%@); trying the official installer.", &[Arg::Str(&code_text(code))])
}

pub fn winget_missed_drivers() -> String {
    l10n::tr("winget did not install every OpenVPN driver; adding them with the official installer.", &[])
}

pub fn add_drivers_in_settings() -> String {
    l10n::tr("Add the DCO and TAP-Windows6 drivers in Settings → Apps → Installed apps → OpenVPN → Modify.", &[])
}

pub fn not_signed_by(signer: &str) -> String {
    l10n::tr("The OpenVPN installer is not signed by %@.", &[Arg::Str(signer)])
}

/// The MSI's database names another product, architecture or an older OpenVPN than `pinned`.
pub fn not_openvpn(pinned: &str) -> String {
    l10n::tr("The OpenVPN installer is not OpenVPN Community %@ or newer.", &[Arg::Str(pinned)])
}

pub fn download_failed(reason: &str) -> String {
    l10n::tr("The OpenVPN installer could not be downloaded: %@", &[Arg::Str(reason)])
}

pub fn installer_failed(code: u32) -> String {
    l10n::tr("The OpenVPN installer failed (%@).", &[Arg::Str(&code_text(code))])
}

pub fn installer_not_started() -> String {
    l10n::tr("The OpenVPN installer could not be started.", &[])
}

pub fn only_installed_winvpn() -> String {
    l10n::tr("Only a WinVPN installed in Program Files can install OpenVPN Community.", &[])
}

pub fn installed() -> String {
    l10n::tr("OpenVPN Community is installed.", &[])
}

pub fn restart_needed() -> String {
    l10n::tr("Restart Windows to finish.", &[])
}

pub fn cancelled() -> String {
    l10n::tr("Cancelled", &[])
}

pub fn interactive_not_disabled() -> String {
    l10n::tr("OpenVPN's Interactive Service could not be disabled.", &[])
}

pub fn marker_not_written() -> String {
    l10n::tr("WinVPN could not record that it installed OpenVPN Community.", &[])
}

/// The texts after the elevated step: `Ok(lines for the output)` when the install succeeded (whatever happened to
/// the Interactive Service: WinVPN works with it running), else `Err(the failure)`.
pub fn after_step(result: &StepResult) -> Result<Vec<String>, String> {
    if let Some(e) = result.error {
        return Err(match e {
            StepError::NotVerified => not_signed_by(pins::OPENVPN_SIGNER),
            StepError::NotOpenVpn => not_openvpn(pins::OPENVPN_VERSION),
            StepError::Arguments | StepError::NoMsiexec | StepError::NotStaged => installer_not_started(),
        });
    }
    let mut lines = Vec::new();
    let restart = match result.msi.map(outcome) {
        None | Some(Outcome::Done) => false,
        Some(Outcome::DoneRestartNeeded) => true,
        Some(Outcome::Cancelled) => return Err(cancelled()),
        Some(Outcome::Failed(c)) => return Err(installer_failed(c)),
    };
    match result.interactive {
        Interactive::Untouched | Interactive::Disabled => {}
        Interactive::NotDisabled => lines.push(interactive_not_disabled()),
        Interactive::MarkerNotWritten => lines.push(marker_not_written()),
    }
    if result.msi.is_some() {
        lines.push(installed());
    }
    if restart {
        lines.push(restart_needed());
    }
    Ok(lines)
}

/// winget's output for System Status: its progress spinner (`-\|/`), bars and blank lines dropped, each `\r`
/// segment a line of its own; `None` when nothing is left.
pub fn winget_line(raw: &str) -> Option<String> {
    let last = raw.split('\r').map(str::trim).rfind(|s| !s.is_empty())?;
    let noise = |c: char| matches!(c, '-' | '\\' | '|' | '/' | ' ' | '█' | '▒' | '\u{8}');
    if last.chars().all(noise) {
        return None;
    }
    Some(last.chars().filter(|c| !c.is_control()).collect())
}
