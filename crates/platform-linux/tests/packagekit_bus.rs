//! `lin::nm::packagekit::install` against a fake `org.freedesktop.PackageKit` on the test's own session bus (run
//! under `dbus-run-session`: nothing reaches the system's PackageKit, nothing is installed, no prompt).
#![cfg(target_os = "linux")]

use macvpn_platform_linux::lin_for_tests::nm::packagekit::{
    ERROR_NOT_AUTHORIZED, ERROR_TRANSACTION_CANCELLED, FILTER_ARCH, FILTER_INSTALLED, FILTER_NEWEST,
    FILTER_NOT_INSTALLED, Limits, TRANSACTION_FLAG_ONLY_TRUSTED, install, install_within,
};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};
use zbus::object_server::SignalEmitter;
use zbus::zvariant::OwnedObjectPath;

const DEST: &str = "org.freedesktop.PackageKit";

#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    Resolve(u64, Vec<String>),
    Hints(Vec<String>),
    Install(u64, Vec<String>),
    Cancel,
}

#[derive(Default)]
struct State {
    /// The packages the fake's sources have, and whether each is installed.
    known: Vec<(&'static str, bool)>,
    /// `InstallPackages` ends with this `ErrorCode` (else success).
    install_error: Option<u32>,
    /// `InstallPackages` never finishes (until `Cancel`).
    install_hangs: bool,
    calls: Vec<Call>,
}

type Shared = Arc<Mutex<State>>;

fn lock(state: &Shared) -> MutexGuard<'_, State> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

struct Manager {
    state: Shared,
    next: AtomicU32,
}

#[zbus::interface(name = "org.freedesktop.PackageKit")]
impl Manager {
    async fn create_transaction(
        &self,
        #[zbus(object_server)] server: &zbus::ObjectServer,
    ) -> zbus::fdo::Result<OwnedObjectPath> {
        let n = self.next.fetch_add(1, Ordering::SeqCst);
        let path =
            OwnedObjectPath::try_from(format!("/{n}_tx")).map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        server.at(&path, Transaction { state: self.state.clone(), used: false }).await?;
        Ok(path)
    }
}

struct Transaction {
    state: Shared,
    /// PackageKit runs one role per transaction.
    used: bool,
}

impl Transaction {
    fn role(&mut self) -> zbus::fdo::Result<()> {
        if std::mem::replace(&mut self.used, true) {
            return Err(zbus::fdo::Error::Failed("the transaction already ran".into()));
        }
        Ok(())
    }
}

#[zbus::interface(name = "org.freedesktop.PackageKit.Transaction")]
impl Transaction {
    fn set_hints(&mut self, hints: Vec<String>) {
        lock(&self.state).calls.push(Call::Hints(hints));
    }

    async fn resolve(
        &mut self,
        filter: u64,
        packages: Vec<String>,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> zbus::fdo::Result<()> {
        self.role()?;
        let hits: Vec<(u32, String)> =
            {
                let mut state = lock(&self.state);
                state.calls.push(Call::Resolve(filter, packages.clone()));
                packages
                    .iter()
                    .filter_map(|p| state.known.iter().find(|(k, _)| k == p))
                    .filter(|(_, installed)| {
                        if *installed { filter & FILTER_INSTALLED != 0 } else { filter & FILTER_NOT_INSTALLED != 0 }
                    })
                    .map(|(name, installed)| (if *installed { 1 } else { 2 }, format!("{name};1.0-1;amd64;resolute")))
                    .collect()
            };
        for (info, id) in hits {
            Self::package(&emitter, info, &id, "summary").await?;
        }
        Self::finished(&emitter, 1, 5).await?;
        Ok(())
    }

    async fn install_packages(
        &mut self,
        transaction_flags: u64,
        package_ids: Vec<String>,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> zbus::fdo::Result<()> {
        self.role()?;
        let error = {
            let mut state = lock(&self.state);
            state.calls.push(Call::Install(transaction_flags, package_ids.clone()));
            state.install_error
        };
        for id in &package_ids {
            Self::item_progress(&emitter, id, 0, 50).await?;
        }
        if lock(&self.state).install_hangs {
            return Ok(());
        }
        match error {
            None => Self::finished(&emitter, 1, 10).await?,
            Some(code) => {
                Self::error_code(&emitter, code, "the fake's details").await?;
                Self::finished(&emitter, 2, 10).await?;
            }
        }
        Ok(())
    }

    async fn cancel(&mut self, #[zbus(signal_emitter)] emitter: SignalEmitter<'_>) -> zbus::fdo::Result<()> {
        lock(&self.state).calls.push(Call::Cancel);
        Self::error_code(&emitter, 17, "cancelled").await?;
        Self::finished(&emitter, 3, 10).await?;
        Ok(())
    }

    #[zbus(signal)]
    async fn package(emitter: &SignalEmitter<'_>, info: u32, package_id: &str, summary: &str) -> zbus::Result<()>;
    #[zbus(signal)]
    async fn item_progress(emitter: &SignalEmitter<'_>, id: &str, status: u32, percentage: u32) -> zbus::Result<()>;
    #[zbus(signal)]
    async fn error_code(emitter: &SignalEmitter<'_>, code: u32, details: &str) -> zbus::Result<()>;
    #[zbus(signal)]
    async fn finished(emitter: &SignalEmitter<'_>, exit: u32, runtime: u32) -> zbus::Result<()>;
}

/// One fake for the whole test binary (the name is the bus's), each test under [`serial`] with its own state.
fn fake() -> &'static Shared {
    static FAKE: OnceLock<(zbus::blocking::Connection, Shared)> = OnceLock::new();
    &FAKE
        .get_or_init(|| {
            let state = Shared::default();
            let manager = Manager { state: state.clone(), next: AtomicU32::new(1) };
            let server = zbus::blocking::connection::Builder::session()
                .unwrap()
                .name(DEST)
                .unwrap()
                .serve_at("/org/freedesktop/PackageKit", manager)
                .unwrap()
                .build()
                .expect("a private session bus (run under dbus-run-session)");
            (server, state)
        })
        .1
}

fn serial() -> MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A fresh fake state; returns the client's bus.
fn setup(known: &[(&'static str, bool)], install_error: Option<u32>) -> zbus::blocking::Connection {
    *lock(fake()) = State { known: known.to_vec(), install_error, install_hangs: false, calls: Vec::new() };
    zbus::blocking::Connection::session().unwrap()
}

fn calls() -> Vec<Call> {
    lock(fake()).calls.clone()
}

fn run(bus: &zbus::blocking::Connection, packages: &[&str]) -> (Result<(), String>, Vec<String>) {
    let mut out = Vec::new();
    let result = install(bus, packages, &mut |line| out.push(line.to_string()));
    (result, out)
}

const RESOLVE_FILTER: u64 = 8 | 65536 | 262144;

#[test]
fn pins_packagekits_bitfields() {
    // pk-enum.h: NOT_INSTALLED = 3, NEWEST = 16, ARCH = 18, INSTALLED = 2; ONLY_TRUSTED = 1 (bit = 1 << value).
    assert_eq!(FILTER_NOT_INSTALLED | FILTER_NEWEST | FILTER_ARCH, RESOLVE_FILTER);
    assert_eq!(FILTER_INSTALLED, 4);
    assert_eq!(TRANSACTION_FLAG_ONLY_TRUSTED, 2);
    assert_eq!((ERROR_NOT_AUTHORIZED, ERROR_TRANSACTION_CANCELLED), (48, 17));
}

#[test]
fn installs_the_resolved_package_with_only_trusted() {
    let _serial = serial();
    let bus = setup(&[("network-manager-sstp", false)], None);
    let (result, out) = run(&bus, &["network-manager-sstp"]);
    assert_eq!(result, Ok(()));
    assert_eq!(out, ["Installing network-manager-sstp…", "Done."]);
    assert_eq!(
        calls(),
        [
            Call::Resolve(RESOLVE_FILTER, vec!["network-manager-sstp".into()]),
            Call::Hints(vec!["interactive=true".into()]),
            Call::Install(2, vec!["network-manager-sstp;1.0-1;amd64;resolute".into()]),
        ]
    );
}

#[test]
fn installs_two_packages_in_one_transaction() {
    let _serial = serial();
    let bus = setup(&[("network-manager-strongswan", false), ("libcharon-extauth-plugins", false)], None);
    let (result, out) = run(&bus, &["network-manager-strongswan", "libcharon-extauth-plugins"]);
    assert_eq!(result, Ok(()));
    assert_eq!(out, ["Installing network-manager-strongswan, libcharon-extauth-plugins…", "Done."]);
    let installs: Vec<Call> = calls().into_iter().filter(|c| matches!(c, Call::Install(..))).collect();
    assert_eq!(
        installs,
        [Call::Install(
            2,
            vec![
                "network-manager-strongswan;1.0-1;amd64;resolute".into(),
                "libcharon-extauth-plugins;1.0-1;amd64;resolute".into()
            ]
        )]
    );
}

#[test]
fn a_package_the_sources_do_not_have_is_not_found() {
    let _serial = serial();
    let bus = setup(&[("network-manager-sstp", false)], None);
    let (result, out) = run(&bus, &["network-manager-l2tp"]);
    assert_eq!(result, Err("network-manager-l2tp was not found in the system's package sources.".into()));
    assert!(out.is_empty());
    assert_eq!(
        calls(),
        [
            Call::Resolve(RESOLVE_FILTER, vec!["network-manager-l2tp".into()]),
            Call::Resolve(4, vec!["network-manager-l2tp".into()]),
        ],
        "no install"
    );
}

#[test]
fn an_installed_package_is_skipped() {
    let _serial = serial();
    let bus = setup(&[("network-manager-sstp", true)], None);
    let (result, out) = run(&bus, &["network-manager-sstp"]);
    assert_eq!(result, Ok(()));
    assert_eq!(out, ["Done."]);
    assert!(!calls().iter().any(|c| matches!(c, Call::Install(..))));
}

#[test]
fn a_refused_prompt_is_not_authorized() {
    let _serial = serial();
    let bus = setup(&[("network-manager-sstp", false)], Some(ERROR_NOT_AUTHORIZED));
    let (result, out) = run(&bus, &["network-manager-sstp"]);
    assert_eq!(result, Err("The installation was not authorized.".into()));
    assert_eq!(out, ["Installing network-manager-sstp…"]);
}

#[test]
fn a_cancelled_prompt_is_cancelled() {
    let _serial = serial();
    let bus = setup(&[("network-manager-sstp", false)], Some(ERROR_TRANSACTION_CANCELLED));
    let (result, _) = run(&bus, &["network-manager-sstp"]);
    assert_eq!(result, Err("The installation was cancelled.".into()));
}

#[test]
fn another_error_shows_packagekits_details() {
    let _serial = serial();
    let bus = setup(&[("network-manager-sstp", false)], Some(13));
    let (result, _) = run(&bus, &["network-manager-sstp"]);
    assert_eq!(result, Err("The installation failed: the fake's details".into()));
}

#[test]
fn a_name_outside_the_fixed_list_never_reaches_the_bus() {
    let _serial = serial();
    let bus = setup(&[("network-manager-foo", false), ("network-manager-sstp", false)], None);
    for bad in [&["network-manager-foo"][..], &["network-manager-sstp", "sudo"], &["network-manager-sstp;1;amd64;x"]] {
        let (result, out) = run(&bus, bad);
        let name = bad.iter().find(|p| **p != "network-manager-sstp").unwrap();
        assert_eq!(result, Err(format!("{name} is not a package LinVPN installs.")));
        assert!(out.is_empty());
    }
    assert!(calls().is_empty(), "nothing was asked: {:?}", calls());
}

#[test]
fn an_installation_that_never_finishes_times_out_and_is_cancelled() {
    let _one = serial();
    let bus = setup(&[("network-manager-l2tp", false)], None);
    lock(fake()).install_hangs = true;
    let limits = Limits { resolve: Duration::from_secs(10), install: Duration::from_millis(400) };
    let start = Instant::now();
    let mut out = Vec::new();
    let result = install_within(&bus, &["network-manager-l2tp"], limits, &mut |l| out.push(l.to_string()));
    assert!(start.elapsed() < Duration::from_secs(10), "the wait ends at the limit");
    let err = result.unwrap_err();
    assert!(err.contains("did not finish the installation within 1 minutes"), "{err}");
    assert_eq!(calls().last(), Some(&Call::Cancel), "PackageKit is asked to cancel it");
}
