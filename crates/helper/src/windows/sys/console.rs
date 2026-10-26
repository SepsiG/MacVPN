//! `mvpn console --pipe \\.\pipe\WinVPN-test-<…> --data <dir> [--fake-engine | --fake-openvpn] [--existing-data]
//! [--wireguard-dll <absolute path>] [--wireguard-updates <absolute dir>] [--wireguard-floor <version>]`: the service's
//! server as the current (non-SYSTEM) user, for the tests. Debug builds only (`sys/mod.rs` compiles this module only
//! with `debug_assertions`; the MSI's gate checks the release binary has no `console`). The pipe is
//! `Endpoint::ServiceForTests` (owned by this user, never by SYSTEM: winsys refuses it in a LocalSystem process, and
//! so does this mode), and only a `WinVPN-test-` name, so a client that trusts SYSTEM never reaches it. The data
//! directory must be new (created private) unless `--existing-data`, which checks an existing one as the service
//! does (a directory with inherited permissions is degraded). Prints `ready` once listening; stops when stdin
//! closes. `--fake-openvpn`: the real OpenVPN engine, but its `openvpn.exe` is this binary (`fake_openvpn`, which
//! skips the trust checks: debug builds only), with both drivers. `--wireguard-dll` loads that `wireguard.dll`
//! (still only the pinned bytes) instead of the one next to the exe, without the service's admin-only folder check.
//! wireguard-nt updates never go online here: `--wireguard-updates <dir>` serves the listing and zips from `dir`
//! (`fetch::Fixtures`), without it every download fails; `--wireguard-floor <version>` replaces the bundled pin's
//! version as the one a download must be above (the real 1.1 DLL then stands for a newer one).

use super::detect::Ready;
use super::fetch::{Fetcher, Fixtures, Offline};
use super::openvpn::OpenVpnEngine;
use super::service_log::ServiceLog;
use super::{data_dir, job, real_host, server};
use crate::windows::service::{Engine, EngineState, Service, UpRequest};
use crate::windows::wg_update::NtVersion;
use macvpn_winsys::file::Protection;
use macvpn_winsys::pipe::{Endpoint, Listener};
use macvpn_winsys::sid::Sid;
use std::collections::HashSet;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

const TEST_PIPE_PREFIX: &str = r"\\.\pipe\WinVPN-test-";

struct Options {
    pipe: String,
    data: PathBuf,
    fake_engine: bool,
    fake_openvpn: bool,
    existing_data: bool,
    wireguard_dll: Option<PathBuf>,
    wireguard_updates: Option<PathBuf>,
    wireguard_floor: Option<NtVersion>,
}

/// The console's fixtures directory for wireguard-nt updates (`Some(None)`: the console runs, without fixtures).
static UPDATES: OnceLock<Option<PathBuf>> = OnceLock::new();

/// In the console: its fetcher (fixtures or offline); `None` outside the console.
pub(crate) fn fetcher() -> Option<Box<dyn Fetcher>> {
    UPDATES.get().map(|dir| -> Box<dyn Fetcher> {
        match dir {
            Some(d) => Box::new(Fixtures(d.clone())),
            None => Box::new(Offline),
        }
    })
}

impl Options {
    fn parse(args: &[String]) -> Option<Options> {
        let (mut pipe, mut data, mut fake_engine, mut fake_openvpn, mut existing_data) =
            (None, None, false, false, false);
        let (mut wireguard_dll, mut wireguard_updates, mut wireguard_floor) = (None, None, None);
        let mut it = args.iter();
        while let Some(a) = it.next() {
            match a.as_str() {
                "--pipe" if pipe.is_none() => pipe = Some(it.next()?.clone()),
                "--data" if data.is_none() => data = Some(PathBuf::from(it.next()?)),
                "--fake-engine" if !fake_openvpn => fake_engine = true,
                "--fake-openvpn" if !fake_engine => fake_openvpn = true,
                "--existing-data" => existing_data = true,
                "--wireguard-dll" if wireguard_dll.is_none() => wireguard_dll = Some(PathBuf::from(it.next()?)),
                "--wireguard-updates" if wireguard_updates.is_none() => {
                    wireguard_updates = Some(PathBuf::from(it.next()?)).filter(|p| p.is_absolute());
                    wireguard_updates.as_ref()?;
                }
                "--wireguard-floor" if wireguard_floor.is_none() => {
                    wireguard_floor = Some(NtVersion::parse(it.next()?)?)
                }
                _ => return None,
            }
        }
        let pipe = pipe.filter(|p| p.strip_prefix(TEST_PIPE_PREFIX).is_some_and(|rest| !rest.is_empty()))?;
        let wireguard_dll = match wireguard_dll {
            Some(p) if !p.is_absolute() => return None,
            p => p,
        };
        Some(Options {
            pipe,
            data: data.filter(|d| d.is_absolute())?,
            fake_engine,
            fake_openvpn,
            existing_data,
            wireguard_dll,
            wireguard_updates,
            wireguard_floor,
        })
    }
}

pub fn main(args: &[String]) -> i32 {
    let Some(o) = Options::parse(args) else {
        eprintln!(
            r"usage: mvpn console --pipe \\.\pipe\WinVPN-test-<name> --data <absolute dir> [--fake-engine | --fake-openvpn] [--existing-data] [--wireguard-dll <absolute path>] [--wireguard-updates <absolute dir>] [--wireguard-floor <version>]"
        );
        return 2;
    };
    let Ok(me) = Sid::current_user() else { return 2 };
    if me == Sid::local_system() {
        eprintln!("the console is not for LocalSystem");
        return 2;
    }
    if !o.existing_data && std::fs::symlink_metadata(&o.data).is_ok() {
        eprintln!("the data directory exists (use --existing-data)");
        return 2;
    }
    // As the service; a test runner's own job may refuse it, which does not matter here.
    let _ = job::contain_self();
    if let Some(dll) = o.wireguard_dll {
        super::wireguard::use_console_dll(dll);
    }
    if let Some(floor) = o.wireguard_floor {
        super::wireguard::use_console_floor(floor);
    }
    let _ = UPDATES.set(o.wireguard_updates);
    let data = data_dir::open_at(&o.data, Protection::Private, &[me]).map(Arc::new);
    let log = ServiceLog::none();
    let fake = if o.fake_engine {
        let (a, b): (Box<dyn Engine>, Box<dyn Engine>) =
            (Box::new(FakeEngine::default()), Box::new(FakeEngine::default()));
        Some((a, b))
    } else if let (true, Ok(d)) = (o.fake_openvpn, &data) {
        let (_, wireguard) = super::engines(d, &log);
        let openvpn: Box<dyn Engine> =
            Box::new(OpenVpnEngine::with_detector(d.clone(), log.clone(), Box::new(fake_ready)));
        Some((openvpn, wireguard))
    } else {
        None
    };
    let service = Arc::new(Service::new(real_host(data.clone(), &log, fake)));
    let listener = match Listener::bind_endpoint(&o.pipe, Endpoint::ServiceForTests) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cannot serve the pipe: {e}");
            return 1;
        }
    };
    let mut out = std::io::stdout();
    if writeln!(out, "ready").and_then(|()| out.flush()).is_err() {
        return 1;
    }
    let stop = Arc::new(AtomicBool::new(false));
    let watch = stop.clone();
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut std::io::stdin().lock().take(u64::MAX), &mut std::io::sink());
        watch.store(true, Ordering::SeqCst);
    });
    server::serve(listener, service.clone(), &stop, |l| eprintln!("{l}"));
    service.shutdown();
    if let Ok(d) = &data {
        d.sweep_runs();
    }
    0
}

/// `--fake-openvpn`: this binary is the `openvpn.exe`, with both drivers.
fn fake_ready() -> Result<Ready, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    Ok(Ready { exe, dco: true, tap_windows6: true })
}

/// Both kinds in `--fake-engine`: `up` logs two lines (one with the password, which the log masks) and connects at
/// once; `state` is connected with a fixed interface and address; `down` forgets.
#[derive(Default)]
struct FakeEngine(Mutex<HashSet<String>>);

impl Engine for FakeEngine {
    fn up(&self, req: &UpRequest<'_>) -> Result<(), String> {
        req.log.line("fake engine: starting");
        req.log.line(&format!("fake engine: password {}", String::from_utf8_lossy(&req.secrets.pass)));
        self.0.lock().unwrap_or_else(PoisonError::into_inner).insert(req.id.to_string());
        Ok(())
    }
    fn down(&self, id: &str) -> Result<(), String> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).remove(id);
        Ok(())
    }
    fn state(&self, id: &str) -> Option<EngineState> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).contains(id).then(|| EngineState {
            state: "connected",
            iface: format!("WinVPN{}", id.get(..8).unwrap_or_default().to_ascii_lowercase()),
            ip: "10.0.0.2".into(),
            since: None,
        })
    }
}
