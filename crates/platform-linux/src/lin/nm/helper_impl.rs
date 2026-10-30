//! `HelperClient` of the NetworkManager engine: OpenVPN, WireGuard, IKEv2 and SSTP (resolved point 1; L-b Task 21).
//!
//! `up` plans the given config and activates it through [`Engine::activate`] (returning once NM accepted the
//! activation, as `mvpn up` returns once the tunnel process runs); `status` reports the runs NM still has
//! (`connected` / `connecting`); a failed or vanished run disappears from `status` once its reason is in the
//! connection's log, so app-core's failure notifications read it there. Liveness (resolved point 15): WireGuard
//! always, OpenVPN while not reconnecting, report the tunnel's counters; OpenVPN reconnecting (NM's VPN state after
//! having been activated) reports `Liveness::OpenVpn`. Traffic (resolved point 16): the sysfs counters of the tunnel
//! interface. IKEv2 reports the counters of charon-nm's XFRM interface (strongSwan 6: `nm-xfrm-*`, holding the
//! virtual IP, user-readable in sysfs) and, with an older policy-based charon-nm (no interface), its IPsec SAs'
//! counters from `linvpn-xfrmd` ([`crate::lin::nm::xfrmd_client`]), for both: `Liveness::Counters` with no
//! keepalive, so an idle tunnel (IKE's DPD and NAT keepalives go outside the SAs and the interface, so nothing moves)
//! is never dead, and one that keeps sending into a tunnel that brings nothing back for `COUNTER_SILENCE` is.

use crate::lin::nm::agent::{Agent, Expect};
use crate::lin::nm::client::{NmClient, WatchGuard};
use crate::lin::nm::connlog::{ConnLog, Pump};
use crate::lin::nm::engine::{Engine, RunView};
use crate::lin::nm::files::RuntimeFiles;
use crate::lin::nm::sysfs;
use crate::lin::nm::xfrmd_client;
use crate::pure::nm::state::VpnState;
use macvpn_core::date::Date;
use macvpn_core::fsx::FileOwner;
use macvpn_core::l10n::{self, Arg};
use macvpn_core::liveness::Liveness;
use macvpn_core::mfa::{AuthResponseKind, MFAError, is_valid_code};
use macvpn_core::models::{Connection, Secrets, VPNKind};
use macvpn_core::nm_plan::Caps;
use macvpn_core::status::RootStatus;
use macvpn_core::xfrmd::Target;
use macvpn_platform_api::{CounterWidth, HelperClient, HelperTunnel, TrafficReading, traffic};
use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, PoisonError, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;
use zeroize::Zeroizing;

/// The tunnel counter source: `(rx_bytes, tx_bytes)` of an interface.
pub type CounterSource = Box<dyn Fn(&str) -> Option<(u64, u64)> + Send + Sync>;

/// The tunnel interfaces holding an IPv4 address (`sysfs::tunnel_ifaces_for` in production).
pub type IfaceSource = Box<dyn Fn(&str) -> Vec<String> + Send + Sync>;

/// The IKEv2 counter source: `(rx_bytes, tx_bytes)` of a connection's IPsec SAs (`linvpn-xfrmd` in production).
pub type XfrmSource = Box<dyn Fn(&Target) -> Option<(u64, u64)> + Send + Sync>;

/// The helper kinds' part of the engine's state.
pub struct HelperState {
    pub(crate) client: OnceLock<NmClient>,
    pub(crate) agent: OnceLock<Agent>,
    /// Serializes the first creation of the client, the agent and the watcher.
    pub(crate) init: Mutex<()>,
    /// Shared with the watcher's thread.
    pub(crate) runs: Arc<Mutex<Runs>>,
    /// `WatchGuard` is `Send` only: behind a mutex.
    pub(crate) watch: Mutex<Option<WatchGuard>>,
    pub(crate) counters: RwLock<CounterSource>,
    pub(crate) xfrm: RwLock<XfrmSource>,
    pub(crate) tunnel_ifaces: RwLock<IfaceSource>,
    pub(crate) caps: Mutex<Option<(Instant, Caps)>>,
    /// The journal pump's `linvpn-logd` socket: `None` is the installed one (production); the tests name their own,
    /// so a run's log never depends on the host's journal.
    pub(crate) logd_socket: RwLock<Option<std::path::PathBuf>>,
    /// The adoption of the connections an earlier process left up ran (`Engine::adopt`); held while it runs, so
    /// no start, stop or status comes in between.
    pub(crate) adopted: Mutex<bool>,
}

impl Default for HelperState {
    fn default() -> HelperState {
        HelperState {
            client: OnceLock::new(),
            agent: OnceLock::new(),
            init: Mutex::new(()),
            runs: Arc::new(Mutex::new(Runs::default())),
            watch: Mutex::new(None),
            counters: RwLock::new(Box::new(sysfs::counters)),
            xfrm: RwLock::new(Box::new(|t| xfrmd_client::counters(t).map(|c| (c.rx, c.tx)))),
            tunnel_ifaces: RwLock::new(Box::new(sysfs::tunnel_ifaces_for)),
            caps: Mutex::new(None),
            logd_socket: RwLock::new(None),
            adopted: Mutex::new(false),
        }
    }
}

#[derive(Default)]
pub struct Runs {
    pub by_id: HashMap<Uuid, Run>,
    /// `VpnStateChanged` of an active path no run has yet: `(path, state, reason)`.
    pub orphans: VecDeque<(String, VpnState, u32)>,
}

/// One activation LinVPN started (or adopted from an earlier process). Dropping it removes its runtime files, makes
/// the agent forget its secrets and lets the journal pump run out.
pub struct Run {
    pub kind: VPNKind,
    pub nm_uuid: String,
    pub active_path: String,
    /// LinVPN's interface name (WireGuard, OpenVPN).
    pub iface: Option<String>,
    pub keepalive: u32,
    /// Unix seconds.
    pub since: f64,
    pub was_activated: bool,
    pub reconnecting_since: Option<u64>,
    pub last_reason: Option<u32>,
    /// The reason line is in the log.
    pub ended: bool,
    /// NM stopped reporting the run (it waits for its reason).
    pub gone_since: Option<Instant>,
    pub ip: Option<String>,
    /// "Connected" went into the log before NM had the address (WireGuard, IKEv2): it follows once known.
    pub ip_unlogged: bool,
    pub files: Option<RuntimeFiles>,
    pub expect: Option<Expect>,
    pub log: ConnLog,
    pub pump: Option<Pump>,
    /// Adopted without the connection's secrets: its journal lines are masked only once app-core hands them over
    /// ([`HelperClient::set_log_secrets`]).
    pub log_secrets_missing: bool,
}

fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

impl Run {
    /// NM says activated: logs "Connected" when it was not (first time, or back from reconnecting), with the IPv4
    /// address, or, when NM has none yet (WireGuard and IKEv2 get it after the activation), "Connected" now and the
    /// address in a line of its own at the first call that knows it.
    pub(crate) fn connected(&mut self, ip: Option<String>) {
        if ip.is_some() {
            self.ip = ip;
        }
        if !self.was_activated || self.reconnecting_since.is_some() {
            match self.ip.clone() {
                Some(ip) => self.log.line(&l10n::tr("Connected, IPv4 %@", &[Arg::Str(&ip)])),
                None => self.log.line(&l10n::tr("Connected (IPv4 address not known yet)", &[])),
            }
            self.ip_unlogged = self.ip.is_none();
        } else if self.ip_unlogged
            && let Some(ip) = self.ip.clone()
        {
            self.log.line(&l10n::tr("IPv4 address: %@", &[Arg::Str(&ip)]));
            self.ip_unlogged = false;
        }
        self.was_activated = true;
        self.reconnecting_since = None;
    }

    /// NM says not activated (yet or again): after having been activated, the run reconnects.
    pub(crate) fn not_connected(&mut self) {
        if self.was_activated && self.reconnecting_since.is_none() {
            self.reconnecting_since = Some(unix_secs());
            self.log.line(&l10n::tr("Reconnecting (NetworkManager)", &[]));
        }
    }

    pub(crate) fn view(&self, id: Uuid, state: &'static str) -> RunView {
        RunView {
            id,
            kind: self.kind,
            nm_uuid: self.nm_uuid.clone(),
            state,
            iface: self.iface.clone(),
            ip: self.ip.clone(),
            since: self.since,
            reconnecting_since: self.reconnecting_since,
            keepalive: self.keepalive,
        }
    }
}

/// The kinds `HelperClient` runs (L2TP and Cisco are `NativeController`'s).
fn is_helper_kind(kind: VPNKind) -> bool {
    !kind.is_native()
}

fn no_code_asked() -> String {
    l10n::tr("No code is being asked for.", &[])
}

impl Engine {
    /// The run's NM UUID, or the derived one (no run: nothing pending there).
    fn nm_uuid_of(&self, id: &Uuid) -> String {
        let runs = self.helper.runs.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        runs.by_id
            .get(id)
            .map(|r| r.nm_uuid.clone())
            .unwrap_or_else(|| macvpn_core::nm_plan::names::nm_uuid(self.uid, id).to_string())
    }

    /// A connected run's liveness facts (resolved point 15).
    pub fn liveness_of(&self, id: &Uuid) -> Option<Liveness> {
        let (kind, iface, reconnecting_since, keepalive) = {
            let runs = self.helper.runs.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let run = runs.by_id.get(id).filter(|r| r.was_activated && r.gone_since.is_none())?;
            (run.kind, run.iface.clone(), run.reconnecting_since, run.keepalive)
        };
        match kind {
            VPNKind::Openvpn if reconnecting_since.is_some() => Some(Liveness::OpenVpn { reconnecting_since }),
            VPNKind::Wireguard | VPNKind::Openvpn => {
                let (rx, tx) = self.counters_of(iface.as_deref()?)?;
                let keepalive =
                    if kind == VPNKind::Wireguard { u16::try_from(keepalive).unwrap_or(u16::MAX) } else { 0 };
                Some(Liveness::Counters { rx, tx, keepalive })
            }
            // Nothing of IKE's own (DPD, NAT keepalives) passes the SAs or charon-nm's XFRM interface: keepalive 0,
            // and an idle tunnel stays still. The interface's counters when there is one, else the SAs'.
            VPNKind::Strongswan => {
                let (rx, tx) = match self.traffic_iface(id) {
                    Some((iface, _)) => self.counters_of(&iface)?,
                    None => self.xfrm_counters_of(&Target::Linvpn(*id))?,
                };
                Some(Liveness::Counters { rx, tx, keepalive: 0 })
            }
            _ => None,
        }
    }

    /// The IPsec SA counters of an IKEv2 connection (`linvpn-xfrmd` in production).
    pub fn xfrm_counters_of(&self, target: &Target) -> Option<(u64, u64)> {
        (self.helper.xfrm.read().unwrap_or_else(PoisonError::into_inner))(target)
    }

    /// Tests only: the journal pump asks the `linvpn-logd` at `socket` (a missing one: no journal lines).
    #[doc(hidden)]
    pub fn set_logd_socket_for_tests(&self, socket: std::path::PathBuf) {
        *self.helper.logd_socket.write().unwrap_or_else(PoisonError::into_inner) = Some(socket);
    }

    /// Tests only: replaces the IKEv2 counter source (no `linvpn-xfrmd` in the tests).
    #[doc(hidden)]
    pub fn set_xfrm_for_tests(&self, f: XfrmSource) {
        *self.helper.xfrm.write().unwrap_or_else(PoisonError::into_inner) = f;
    }

    /// A connected run's tunnel counters (resolved point 16; IKEv2: charon-nm's XFRM interface's, else its SAs').
    pub fn traffic_of(&self, id: &Uuid) -> Option<TrafficReading> {
        let ikev2_since = {
            let runs = self.helper.runs.lock().unwrap_or_else(PoisonError::into_inner);
            let run = runs.by_id.get(id).filter(|r| r.was_activated && r.gone_since.is_none())?;
            (run.kind == VPNKind::Strongswan).then_some(run.since)
        };
        if let Some(since) = ikev2_since.filter(|_| self.traffic_iface(id).is_none()) {
            let (rx, tx) = self.xfrm_counters_of(&Target::Linvpn(*id))?;
            return Some(TrafficReading {
                // No interface index: the run's start alone names its SAs' generation.
                generation: traffic::generation(&[0, since.to_bits()]),
                rx,
                tx,
                width: CounterWidth::Bits64,
                from_zero: true,
            });
        }
        let (iface, since) = self.traffic_iface(id)?;
        let (rx, tx) = self.counters_of(&iface)?;
        let ifindex = sysfs::ifindex(&iface).unwrap_or(0);
        Some(TrafficReading {
            generation: traffic::generation(&[u64::from(ifindex), since.to_bits()]),
            rx,
            tx,
            width: CounterWidth::Bits64,
            from_zero: true,
        })
    }
}

impl HelperClient for Engine {
    fn status(&self) -> Result<Vec<RootStatus>, String> {
        Ok(self
            .try_runs()?
            .into_iter()
            .filter(|r| is_helper_kind(r.kind))
            .map(|r| RootStatus {
                id: r.id,
                kind: r.kind.raw_value().to_string(),
                state: r.state.to_string(),
                iface: r.iface,
                ip: r.ip,
                since: Some(r.since),
            })
            .collect())
    }

    fn up(
        &self,
        kind: VPNKind,
        id: &Uuid,
        config: &[u8],
        secrets: &Secrets,
        debug: bool,
        accept_risky: &[String],
    ) -> Result<(), String> {
        if !is_helper_kind(kind) {
            return Err(l10n::tr("This kind of connection is not started this way on Linux.", &[]));
        }
        // NM's `connection.id` is shown only in the desktop's network menu.
        let mut connection = Connection::with_id(*id, format!("LinVPN {}", kind.display_name()), kind, Date::now());
        let mut acknowledged = accept_risky.to_vec();
        acknowledged.sort();
        acknowledged.dedup();
        connection.acknowledged_risky_directives = acknowledged;
        self.activate(*id, &connection, config, secrets, debug)
    }

    fn down(&self, _kind: VPNKind, id: &Uuid) -> Result<(), String> {
        self.deactivate(id)
    }

    fn wants_log_secrets(&self, id: &Uuid) -> bool {
        let runs = self.helper.runs.lock().unwrap_or_else(PoisonError::into_inner);
        runs.by_id.get(id).is_some_and(|r| r.log_secrets_missing)
    }

    fn set_log_secrets(&self, id: &Uuid, secrets: &Secrets) {
        let mut runs = self.helper.runs.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(run) = runs.by_id.get_mut(id) else { return };
        if let Some(pump) = &run.pump {
            pump.add_secrets(secrets);
        }
        run.log_secrets_missing = false;
    }

    fn respond(&self, id: &Uuid, kind: AuthResponseKind, response: &str) -> Result<(), String> {
        let Some(agent) = self.helper.agent.get() else { return Err(no_code_asked()) };
        let nm_uuid = self.nm_uuid_of(id);
        match kind {
            AuthResponseKind::Crv1 | AuthResponseKind::Static => {
                if !is_valid_code(response, true) {
                    return Err(MFAError::InvalidCode.message());
                }
                if agent.respond(&nm_uuid, Zeroizing::new(response.to_string())) {
                    Ok(())
                } else {
                    Err(no_code_asked())
                }
            }
            AuthResponseKind::Cancel => {
                agent.cancel(&nm_uuid);
                Ok(())
            }
            // No web confirmation through NetworkManager.
            AuthResponseKind::WebauthAck => Err(no_code_asked()),
        }
    }

    fn log_path(&self, id: &Uuid) -> Option<PathBuf> {
        Some(self.log_file(id))
    }

    fn clear_log(&self, id: &Uuid, note: &str) -> Result<(), String> {
        // SAFETY: getuid has no arguments and cannot fail.
        let owner = FileOwner::from_uid(unsafe { libc::getuid() });
        macvpn_core::log::clear_file(&self.log_file(id), &owner, Some(note)).map(|_| ()).map_err(|e| e.to_string())
    }

    fn liveness(&self, id: &Uuid) -> Option<Liveness> {
        self.liveness_of(id)
    }

    fn traffic(&self, tunnel: &HelperTunnel<'_>) -> Option<TrafficReading> {
        self.traffic_of(tunnel.id)
    }
}
