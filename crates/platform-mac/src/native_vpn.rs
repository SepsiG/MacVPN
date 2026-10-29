//! Native (scutil-listed) VPN services (port of `NativeVPN.swift`): the `scutil --nc list` / `--nc show`
//! parsers and the start/stop driver. Starting never goes through `scutil` (secrets must never reach argv).

use crate::command::{CommandError, CommandRunner};
use crate::mvpn_client::MvpnError;
use macvpn_core::l10n::{self, Arg};
use macvpn_core::models::{ConnectionState, Secrets, parse_uuid};
use macvpn_core::native::{NativeKind, NativeStartOptions, start_options};
use macvpn_core::swift_str;
use regex::Regex;
use std::sync::LazyLock;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemVPNService {
    pub id: String,
    pub name: String,
    pub type_label: String,
    pub status: String,
}

impl SystemVPNService {
    /// MacVPN keychain key for this service's PSK/password. scutil service IDs are UUIDs; `None` if this one is not.
    pub fn secret_id(&self) -> Option<Uuid> {
        parse_uuid(&self.id)
    }

    /// The PSK/password can be stored in MacVPN and passed when starting (L2TP and Cisco IPsec only).
    pub fn supports_stored_secrets(&self) -> bool {
        self.secret_id().is_some() && NativeKind::from_type_label(&self.type_label).is_some()
    }

    pub fn connection_state(&self) -> ConnectionState {
        match self.status.as_str() {
            "Connected" => ConnectionState::Connected { ip: None, since: None },
            "Connecting" => ConnectionState::Connecting,
            "Disconnecting" => ConnectionState::Disconnecting,
            _ => ConnectionState::Disconnected,
        }
    }
}

pub struct ScutilParser;

static LIST_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^\*?\s*\(([^)]+)\)\s+([0-9A-Fa-f-]{36})\s+.*?"(.*)"\s+\[([^\]]+)\]\s*$"#).expect("valid regex")
});

impl ScutilParser {
    pub fn parse_list(output: &str) -> Vec<SystemVPNService> {
        output
            .split('\n')
            .filter_map(|line| {
                let m = LIST_LINE.captures(line)?;
                let type_label = Self::type_label(&m[4])?;
                Some(SystemVPNService {
                    id: m[2].to_string(),
                    name: m[3].to_string(),
                    type_label: type_label.to_string(),
                    status: m[1].to_string(),
                })
            })
            .collect()
    }

    /// The server address from `scutil --nc show <id>` (`CommRemoteAddress` for L2TP, `RemoteAddress` for IPsec).
    pub fn remote_address(output: &str) -> Option<String> {
        for line in output.split('\n') {
            let parts: Vec<&str> = swift_str::split(line, ":", 1, true)
                .into_iter()
                .map(|p| p.trim_matches(swift_str::is_foundation_whitespace))
                .collect();
            if parts.len() != 2
                || !(parts[0] == "CommRemoteAddress" || parts[0] == "RemoteAddress")
                || parts[1].is_empty()
            {
                continue;
            }
            return Some(parts[1].to_string());
        }
        None
    }

    /// `None`: not a VPN (for example a modem).
    pub fn type_label(raw: &str) -> Option<&'static str> {
        match raw {
            "PPP:L2TP" => Some("L2TP"),
            "IPSec" => Some("Cisco IPsec"),
            "IKEv2" => Some("IKEv2"),
            "VPN:com.wireguard.macos" => Some("WireGuard (app)"),
            "VPN:net.tunnelblick.tunnelblick" => Some("OpenVPN (app)"),
            _ if raw.starts_with("VPN:") => Some("VPN"),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeDriverError {
    Open(String),
    Start(String),
    Stop(String),
}

impl std::fmt::Display for NativeDriverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            NativeDriverError::Open(d) => l10n::tr("Cannot open the VPN service: %@", &[Arg::Str(d)]),
            NativeDriverError::Start(d) => l10n::tr("Cannot start the VPN service: %@", &[Arg::Str(d)]),
            NativeDriverError::Stop(d) => l10n::tr("Cannot stop the VPN service: %@", &[Arg::Str(d)]),
        };
        f.write_str(&text)
    }
}

impl std::error::Error for NativeDriverError {}

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Starts and stops a native VPN service. Behind a trait so tests never touch a real VPN.
pub trait NativeConnectionDriver: Send + Sync {
    fn start(&self, service_id: &str, options: Option<&NativeStartOptions>, linger: bool) -> Result<(), BoxError>;
    fn stop(&self, service_id: &str) -> Result<(), BoxError>;
}

/// In-process `SCNetworkConnection`. Unlike `scutil --nc start`, it can pass the PSK/password as user options
/// (an L2TP PSK in the System keychain is otherwise not found: "L2TP: incorrect user shared secret found").
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemConfigurationDriver;

impl From<crate::sc_ffi::Failure> for NativeDriverError {
    fn from(f: crate::sc_ffi::Failure) -> Self {
        match f {
            crate::sc_ffi::Failure::Open(d) => NativeDriverError::Open(d),
            crate::sc_ffi::Failure::Start(d) => NativeDriverError::Start(d),
            crate::sc_ffi::Failure::Stop(d) => NativeDriverError::Stop(d),
        }
    }
}

impl NativeConnectionDriver for SystemConfigurationDriver {
    fn start(&self, service_id: &str, options: Option<&NativeStartOptions>, linger: bool) -> Result<(), BoxError> {
        crate::sc_ffi::start(service_id, options, linger).map_err(|f| Box::new(NativeDriverError::from(f)) as BoxError)
    }

    fn stop(&self, service_id: &str) -> Result<(), BoxError> {
        crate::sc_ffi::stop(service_id).map_err(|f| Box::new(NativeDriverError::from(f)) as BoxError)
    }
}

#[derive(Debug)]
pub enum NativeError {
    Command(CommandError),
    Mvpn(MvpnError),
    Driver(BoxError),
}

impl std::fmt::Display for NativeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NativeError::Command(e) => e.fmt(f),
            NativeError::Mvpn(e) => e.fmt(f),
            NativeError::Driver(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for NativeError {}

pub struct NativeVPNController<R: CommandRunner, D: NativeConnectionDriver> {
    runner: R,
    driver: D,
}

impl<R: CommandRunner, D: NativeConnectionDriver> NativeVPNController<R, D> {
    /// The started connection outlives this process: the VPN keeps running after MacVPN quits ("keep running").
    pub const LINGER: bool = true;

    /// No default driver: tests must never reach the real [`SystemConfigurationDriver`] by accident.
    pub fn new(runner: R, driver: D) -> Self {
        NativeVPNController { runner, driver }
    }

    pub fn runner(&self) -> &R {
        &self.runner
    }

    pub fn driver(&self) -> &D {
        &self.driver
    }

    pub fn list(&self) -> Result<Vec<SystemVPNService>, NativeError> {
        let result =
            self.runner.run("/usr/sbin/scutil", &["--nc".into(), "list".into()], None).map_err(NativeError::Command)?;
        if result.exit_code != 0 {
            let message = format!("{}{}", result.stderr, result.stdout);
            let message = message.trim_matches(swift_str::is_foundation_whitespace_or_newline);
            return Err(NativeError::Mvpn(MvpnError::Failed(if message.is_empty() {
                l10n::tr("scutil error (exit code: %d)", &[Arg::Int(i64::from(result.exit_code))])
            } else {
                message.to_string()
            })));
        }
        Ok(ScutilParser::parse_list(&result.stdout))
    }

    /// The service's server address (`scutil --nc show`); `None` if it cannot be read.
    pub fn remote_address(&self, service_id: &str) -> Option<String> {
        let result =
            self.runner.run("/usr/sbin/scutil", &["--nc".into(), "show".into(), service_id.into()], None).ok()?;
        if result.exit_code != 0 {
            return None;
        }
        ScutilParser::remote_address(&result.stdout)
    }

    /// `kind` `None` or no secrets: started with the stored configuration only.
    pub fn start(&self, service_id: &str, kind: Option<NativeKind>, secrets: &Secrets) -> Result<(), NativeError> {
        let options = kind.and_then(|k| start_options(k, secrets));
        self.driver.start(service_id, options.as_ref(), Self::LINGER).map_err(NativeError::Driver)
    }

    pub fn stop(&self, service_id: &str) -> Result<(), NativeError> {
        self.driver.stop(service_id).map_err(NativeError::Driver)
    }
}

// MARK: - Live traffic and the address

/// A property list value copied out of `SCNetworkConnectionCopyStatistics` / `…CopyExtendedStatus` (`sc_ffi`).
#[derive(Debug, Clone, PartialEq)]
pub enum Plist {
    Dict(Vec<(String, Plist)>),
    Array(Vec<Plist>),
    Num(i64),
    Str(String),
    Other,
}

impl Plist {
    pub fn get(&self, key: &str) -> Option<&Plist> {
        match self {
            Plist::Dict(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    fn num(&self) -> Option<u64> {
        match self {
            Plist::Num(n) => u64::try_from(*n).ok(),
            _ => None,
        }
    }

    fn str(&self) -> Option<&str> {
        match self {
            Plist::Str(s) => Some(s),
            _ => None,
        }
    }
}

/// The byte counters (received, sent) in a service's statistics: `BytesIn` / `BytesOut` of its `PPP` or `IPSec`
/// (or other) section. `None`: none there.
pub fn statistics_counters(stats: &Plist) -> Option<(u64, u64)> {
    let Plist::Dict(sections) = stats else { return None };
    let pick = |d: &Plist| Some((d.get("BytesIn")?.num()?, d.get("BytesOut")?.num()?));
    ["PPP", "IPSec", "IPsec", "VPN"]
        .iter()
        .filter_map(|k| stats.get(k))
        .chain(sections.iter().map(|(_, v)| v))
        .find_map(pick)
}

/// The tunnel's IPv4 address (the first of `IPv4.Addresses`) in a service's extended status.
pub fn extended_address(ext: &Plist) -> Option<String> {
    let Some(Plist::Array(addresses)) = ext.get("IPv4")?.get("Addresses") else { return None };
    addresses.iter().filter_map(Plist::str).find(|a| a.parse::<std::net::Ipv4Addr>().is_ok()).map(str::to_string)
}

/// The tunnel interface (`IPv4.InterfaceName`, `ppp0` / `ipsec0`) in a service's extended status.
pub fn extended_interface(ext: &Plist) -> Option<String> {
    ext.get("IPv4")?.get("InterfaceName")?.str().filter(|n| crate::if_counters::is_tunnel_name(n)).map(str::to_string)
}
