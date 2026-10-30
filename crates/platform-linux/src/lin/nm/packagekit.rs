//! Installs packages through PackageKit's system D-Bus API (the system's own password prompt: polkit's
//! `org.freedesktop.packagekit.package-install`, asked by PackageKit itself; LinVPN never runs `pkexec` or `apt`).
//!
//! Only the fixed names of [`plugins::PACKAGES`] (resolved point 17) ever reach the bus: any other name is refused
//! before the first call. One transaction per role, as PackageKit requires: `Resolve` (not installed, newest, this
//! architecture) turns the names into package ids, a name it does not find is looked up once more among the
//! installed packages (already there: nothing to do), then `InstallPackages` with `ONLY_TRUSTED` installs the rest.
//! The bus is the caller's: the system bus in the app, the private session bus of `dbus-run-session` in the tests.

use crate::pure::nm::plugins;
use macvpn_core::l10n::{self, Arg};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use zbus::blocking::Connection;
use zbus::blocking::proxy::{Builder, Proxy};
use zbus::proxy::CacheProperties;
use zbus::zvariant::OwnedObjectPath;

const DEST: &str = "org.freedesktop.PackageKit";
const PATH: &str = "/org/freedesktop/PackageKit";
const INTERFACE: &str = "org.freedesktop.PackageKit";
const TRANSACTION: &str = "org.freedesktop.PackageKit.Transaction";

// PackageKit's enums (`pk-enum.h`; checked against PackageKitGlib-1.0 on Ubuntu 26.04). A filter or transaction flag
// bitfield sets bit `1 << value`.
/// `PK_FILTER_ENUM_INSTALLED`.
pub const FILTER_INSTALLED: u64 = 1 << 2;
/// `PK_FILTER_ENUM_NOT_INSTALLED`.
pub const FILTER_NOT_INSTALLED: u64 = 1 << 3;
/// `PK_FILTER_ENUM_NEWEST`.
pub const FILTER_NEWEST: u64 = 1 << 16;
/// `PK_FILTER_ENUM_ARCH`.
pub const FILTER_ARCH: u64 = 1 << 18;
/// `PK_TRANSACTION_FLAG_ENUM_ONLY_TRUSTED`.
pub const TRANSACTION_FLAG_ONLY_TRUSTED: u64 = 1 << 1;
/// `PK_EXIT_ENUM_SUCCESS`.
pub const EXIT_SUCCESS: u32 = 1;
/// `PK_EXIT_ENUM_CANCELLED`.
pub const EXIT_CANCELLED: u32 = 3;
/// `PK_ERROR_ENUM_TRANSACTION_CANCELLED`.
pub const ERROR_TRANSACTION_CANCELLED: u32 = 17;
/// `PK_ERROR_ENUM_NOT_AUTHORIZED`.
pub const ERROR_NOT_AUTHORIZED: u32 = 48;

/// How long a transaction may take before LinVPN gives up on it (and asks PackageKit to cancel it).
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// `Resolve` (PackageKit may refresh its cache first).
    pub resolve: Duration,
    /// `InstallPackages`, the password prompt and the download included.
    pub install: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { resolve: Duration::from_secs(5 * 60), install: Duration::from_secs(30 * 60) }
    }
}

/// What one transaction reported.
#[derive(Default)]
struct Outcome {
    /// `Package` signals: the package ids.
    packages: Vec<String>,
    /// The first `ErrorCode`.
    error: Option<(u32, String)>,
    /// `Finished`'s exit; `None`: the transaction went away without finishing.
    exit: Option<u32>,
    /// No `Finished` within the transaction's limit (in minutes, for the message).
    timed_out: Option<u64>,
}

fn unavailable(e: &zbus::Error) -> String {
    l10n::tr("PackageKit is not available: %@", &[Arg::Str(&e.to_string())])
}

/// PackageKit's details as one short line (its text, never ours to trust for layout).
fn one_line(details: &str) -> String {
    let line: String = details.chars().map(|c| if c.is_control() { ' ' } else { c }).take(300).collect();
    line.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A failed transaction's message.
fn failure(outcome: &Outcome) -> String {
    if let Some(minutes) = outcome.timed_out {
        return l10n::tr(
            "PackageKit did not finish the installation within %@ minutes. Try again later, or install the packages with the system's software tool.",
            &[Arg::Str(&minutes.to_string())],
        );
    }
    match &outcome.error {
        Some((ERROR_NOT_AUTHORIZED, _)) => l10n::tr("The installation was not authorized.", &[]),
        Some((ERROR_TRANSACTION_CANCELLED, _)) => l10n::tr("The installation was cancelled.", &[]),
        None if outcome.exit == Some(EXIT_CANCELLED) => l10n::tr("The installation was cancelled.", &[]),
        Some((_, details)) => l10n::tr("The installation failed: %@", &[Arg::Str(&one_line(details))]),
        None => l10n::tr("The installation failed: %@", &[Arg::Str(&format!("exit {:?}", outcome.exit))]),
    }
}

fn proxy<'a>(bus: &Connection, path: OwnedObjectPath, interface: &'a str) -> zbus::Result<Proxy<'a>> {
    Builder::new(bus).destination(DEST)?.path(path)?.interface(interface)?.cache_properties(CacheProperties::No).build()
}

/// One transaction: `CreateTransaction`, the signals subscribed to, `start` (the transaction's one role), then the
/// signals until `Finished` (or `Destroy`), for at most `limit`: then the transaction is cancelled (best effort) and
/// the outcome says it timed out.
fn transaction(
    bus: &Connection,
    limit: Duration,
    start: impl FnOnce(&Proxy<'_>) -> zbus::Result<()>,
) -> zbus::Result<Outcome> {
    let manager = proxy(bus, OwnedObjectPath::try_from(PATH)?, INTERFACE)?;
    let path: OwnedObjectPath = manager.call("CreateTransaction", &())?;
    let tx = proxy(bus, path, TRANSACTION)?;
    let signals = tx.receive_all_signals()?;
    start(&tx)?;
    // The blocking signal iterator has no timeout: a thread forwards the signals (it ends with the transaction's
    // `Finished`/`Destroy`, which the cancel below brings, or when this side stops listening).
    let (sender, received) = mpsc::channel();
    std::thread::Builder::new()
        .name("linvpn-packagekit".into())
        .spawn(move || {
            for message in signals {
                if sender.send(message).is_err() {
                    break;
                }
            }
        })
        .map_err(|e| zbus::Error::Failure(e.to_string()))?;
    let deadline = Instant::now() + limit;
    let mut outcome = Outcome::default();
    loop {
        let message = match received.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(m) => m,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let _ = tx.call::<_, _, ()>("Cancel", &());
                outcome.timed_out = Some(u64::try_from(limit.as_millis().div_ceil(60_000)).unwrap_or(u64::MAX).max(1));
                break;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        };
        let header = message.header();
        if header.interface().map(|i| i.as_str()) != Some(TRANSACTION) {
            continue;
        }
        match header.member().map(|m| m.as_str()) {
            Some("Package") => {
                if let Ok((_info, id, _summary)) = message.body().deserialize::<(u32, String, String)>() {
                    outcome.packages.push(id);
                }
            }
            Some("ErrorCode") => {
                if let Ok(error) = message.body().deserialize::<(u32, String)>() {
                    outcome.error.get_or_insert(error);
                }
            }
            Some("Finished") => {
                outcome.exit = message.body().deserialize::<(u32, u32)>().ok().map(|(exit, _runtime)| exit);
                break;
            }
            Some("Destroy") => break,
            _ => {}
        }
    }
    Ok(outcome)
}

/// The package ids `Resolve` gives for `names` with `filter` (the first id of each name; ids of other names are
/// ignored).
fn resolve(bus: &Connection, limit: Duration, filter: u64, names: &[&str]) -> Result<Vec<(String, String)>, String> {
    let outcome =
        transaction(bus, limit, |tx| tx.call::<_, _, ()>("Resolve", &(filter, names))).map_err(|e| unavailable(&e))?;
    if outcome.exit != Some(EXIT_SUCCESS) {
        return Err(failure(&outcome));
    }
    let mut found: Vec<(String, String)> = Vec::new();
    for id in outcome.packages {
        let valid = id.len() <= 512 && !id.chars().any(char::is_control);
        let Some(name) = id.split(';').next().filter(|n| valid && names.contains(n)) else { continue };
        if !found.iter().any(|(n, _)| n == name) {
            found.push((name.to_string(), id.clone()));
        }
    }
    Ok(found)
}

/// Installs `packages` (each one of [`plugins::PACKAGES`]) through PackageKit on `bus`, reporting human lines to
/// `output`. PackageKit asks for the administrator password itself (the system's prompt).
pub fn install(bus: &Connection, packages: &[&str], output: &mut dyn FnMut(&str)) -> Result<(), String> {
    install_within(bus, packages, Limits::default(), output)
}

/// [`install`] with other time limits (the tests').
pub fn install_within(
    bus: &Connection,
    packages: &[&str],
    limits: Limits,
    output: &mut dyn FnMut(&str),
) -> Result<(), String> {
    if let Some(bad) = packages.iter().find(|p| !plugins::is_installable(p)) {
        return Err(l10n::tr("%@ is not a package LinVPN installs.", &[Arg::Str(bad)]));
    }
    let mut names: Vec<&str> = Vec::new();
    for p in packages {
        if !names.contains(p) {
            names.push(p);
        }
    }
    if names.is_empty() {
        return Ok(());
    }
    let found = resolve(bus, limits.resolve, FILTER_NOT_INSTALLED | FILTER_NEWEST | FILTER_ARCH, &names)?;
    let missing: Vec<&str> = names.iter().copied().filter(|n| !found.iter().any(|(f, _)| f == n)).collect();
    if !missing.is_empty() {
        let installed = resolve(bus, limits.resolve, FILTER_INSTALLED, &missing)?;
        let unknown: Vec<&str> = missing.iter().copied().filter(|n| !installed.iter().any(|(f, _)| f == n)).collect();
        if !unknown.is_empty() {
            let names = unknown.join(", ");
            return Err(l10n::tr("%@ was not found in the system's package sources.", &[Arg::Str(&names)]));
        }
    }
    if found.is_empty() {
        output(&l10n::tr("Done.", &[]));
        return Ok(());
    }
    let shown: Vec<&str> = found.iter().map(|(n, _)| n.as_str()).collect();
    output(&l10n::tr("Installing %@…", &[Arg::Str(&shown.join(", "))]));
    let ids: Vec<&str> = found.iter().map(|(_, id)| id.as_str()).collect();
    let outcome = transaction(bus, limits.install, |tx| {
        tx.call::<_, _, ()>("SetHints", &(vec!["interactive=true"],))?;
        tx.call::<_, _, ()>("InstallPackages", &(TRANSACTION_FLAG_ONLY_TRUSTED, &ids))
    })
    .map_err(|e| unavailable(&e))?;
    if outcome.exit == Some(EXIT_SUCCESS) && outcome.error.is_none() {
        output(&l10n::tr("Done.", &[]));
        return Ok(());
    }
    Err(failure(&outcome))
}
