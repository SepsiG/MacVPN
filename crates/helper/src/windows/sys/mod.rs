//! The WinVPN Service on Windows: `WinVPNService.exe service` under the SCM; in debug builds also
//! `mvpn.exe console …` for the tests. Everything that calls Win32 for the service lives below this module.

#[cfg(debug_assertions)]
mod console;
mod data_dir;
mod detect;
mod diag;
#[cfg(debug_assertions)]
mod fake_openvpn;
mod fetch;
mod host;
mod iphlp;
mod job;
mod mgmt;
mod openvpn;
mod server;
mod service_log;
mod session;
mod tcp_owner;
mod wgdll;
mod wireguard;

use crate::shared::mask::Masker;
use crate::windows::logs::FileLogStore;
use crate::windows::service::{Engine, EngineState, Host, LogSink, LogStore, UpRequest};
use macvpn_core::models::VPNKind;
use macvpn_core::service_proto::{EngineFacts, LogSlice, OpenVpnFacts, SERVICE_VERSION, WireGuardFacts};
use std::sync::Arc;

pub fn main(argv: &[String]) -> i32 {
    // Before anything loads a DLL: no application directory, no current directory, no PATH in the DLL search.
    macvpn_winsys::dll::harden_process_search();
    match argv.get(1).map(String::as_str) {
        Some("service") if argv.len() == 2 => host::run(),
        #[cfg(debug_assertions)]
        Some("console") => console::main(&argv[2..]),
        // The installed OpenVPN as `engine` reports it (tests/openvpn_installed.rs).
        #[cfg(debug_assertions)]
        Some("console-detect") if argv.len() == 2 => {
            println!("{}", detect::detect().0.to_json());
            0
        }
        // The console's `--fake-openvpn` runs this binary as `openvpn.exe` (its argv starts with `--config`).
        #[cfg(debug_assertions)]
        Some("--config") => fake_openvpn::main(&argv[1..]),
        _ => 2,
    }
}

/// An engine that cannot run (OpenVPN missing, wireguard.dll refused, the data directory unsafe): every `up`
/// answers its reason.
pub(crate) struct Unavailable(pub String);

impl Engine for Unavailable {
    fn up(&self, _req: &UpRequest<'_>) -> Result<(), String> {
        Err(self.0.clone())
    }
    fn down(&self, _id: &str) -> Result<(), String> {
        Ok(())
    }
    fn state(&self, _id: &str) -> Option<EngineState> {
        None
    }
}

/// The logs of a degraded service: none (it has no safe folder to write them to, and it connects nothing).
pub(crate) struct NoLogs;

struct NoSink;

impl LogSink for NoSink {
    fn line(&self, _text: &str) {}
}

impl LogStore for NoLogs {
    fn open(&self, _id: &str, _masker: Masker) -> Box<dyn LogSink> {
        Box::new(NoSink)
    }
    fn read(&self, _id: &str, _offset: u64, _max: usize) -> Option<LogSlice> {
        None
    }
    fn remove(&self, _id: &str) {}
}

/// The real environment of the service (and of the console).
pub(crate) struct RealHost {
    pub openvpn: Box<dyn Engine>,
    pub wireguard: Box<dyn Engine>,
    pub logs: Box<dyn LogStore>,
    pub problem: Option<String>,
    pub facts: Box<dyn Fn() -> (OpenVpnFacts, WireGuardFacts) + Send + Sync>,
}

impl Host for RealHost {
    fn engine(&self, kind: VPNKind) -> Option<&dyn Engine> {
        match kind {
            VPNKind::Openvpn => Some(&*self.openvpn),
            VPNKind::Wireguard => Some(&*self.wireguard),
            _ => None,
        }
    }
    fn facts(&self) -> EngineFacts {
        let (openvpn, wireguard) = (self.facts)();
        EngineFacts { service_version: SERVICE_VERSION, problem: self.problem.clone(), openvpn, wireguard }
    }
    fn logs(&self) -> &dyn LogStore {
        &*self.logs
    }
    fn problem(&self) -> Option<String> {
        self.problem.clone()
    }
    fn snapshot(&self, server: Option<&str>) -> Option<crate::windows::diagnostics::Snapshot> {
        Some(diag::snapshot(server))
    }
    /// `GetLocalTime`: the machine's local time, as the app's own log lines write it.
    fn local_timestamp(&self) -> String {
        let mut t = windows_sys::Win32::Foundation::SYSTEMTIME::default();
        // SAFETY: a valid out-pointer to a plain struct; the call cannot fail.
        unsafe { windows_sys::Win32::System::SystemInformation::GetLocalTime(&mut t) };
        format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond)
    }
}

/// The host over the data directory's outcome: with a safe directory its engines and logs; without one (`problem`)
/// unavailable engines with the reason and no logs. `fake`: the console's fake engines instead of `engines`.
pub(crate) fn real_host(
    data: Result<Arc<data_dir::DataDir>, String>,
    log: &service_log::ServiceLog,
    fake: Option<(Box<dyn Engine>, Box<dyn Engine>)>,
) -> RealHost {
    match data {
        Ok(d) => {
            let (openvpn, wireguard) = fake.unwrap_or_else(|| engines(&d, log));
            let logs = Box::new(FileLogStore::new(d.logs.clone()));
            RealHost { openvpn, wireguard, logs, problem: None, facts: facts_fn(Some(d)) }
        }
        Err(problem) => RealHost {
            openvpn: Box::new(Unavailable(problem.clone())),
            wireguard: Box::new(Unavailable(problem.clone())),
            logs: Box::new(NoLogs),
            problem: Some(problem),
            facts: facts_fn(None),
        },
    }
}

/// The two engines over a ready data directory (Tasks 13 and 14 each replace their `Unavailable` line).
pub(crate) fn engines(
    data: &Arc<data_dir::DataDir>,
    log: &service_log::ServiceLog,
) -> (Box<dyn Engine>, Box<dyn Engine>) {
    let wireguard = wireguard::WireGuardEngine::new(Some(data.clone()), log, fetcher());
    (Box::new(openvpn::OpenVpnEngine::new(data.clone(), log.clone())), Box::new(wireguard))
}

/// How the service downloads engine updates: System32's curl; the console never goes online (its fixtures or
/// nothing).
fn fetcher() -> Box<dyn fetch::Fetcher> {
    #[cfg(debug_assertions)]
    if let Some(f) = console::fetcher() {
        return f;
    }
    Box::new(fetch::CurlFetcher)
}

/// What `engine` reports about OpenVPN and WireGuard (Tasks 13 and 14 each replace their half).
pub(crate) fn facts_fn(
    data: Option<Arc<data_dir::DataDir>>,
) -> Box<dyn Fn() -> (OpenVpnFacts, WireGuardFacts) + Send + Sync> {
    let _ = data;
    Box::new(|| (detect::detect().0, wireguard::facts()))
}
