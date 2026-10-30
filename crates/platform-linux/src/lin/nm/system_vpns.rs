//! The user's own NetworkManager VPN and WireGuard profiles as system VPNs (resolved point 14; L-b Task 22):
//! the profiles the user can see (`pure::nm::system_vpn::is_listed`), never one LinVPN made, read-only (LinVPN
//! never edits or deletes them). Each is listed with its NM UUID as id, its `connection.id` as name and its state
//! from NM's active connections. [`watch`] reports their changes (`SystemVpnWatch`).

use crate::lin::nm::client::{ActiveInfo, NmClient, NmEvent, ProfileInfo};
use crate::lin::nm::engine::Engine;
use crate::lin::nm::sysfs;
use crate::pure::nm::system_vpn::{self, is_linvpn_made, is_listed, type_label};
use macvpn_core::l10n;
use macvpn_platform_api::{CounterWidth, SystemVpn, TrafficReading, traffic};
use std::io;
use std::sync::{Mutex, PoisonError};

pub(crate) fn nm_unavailable() -> String {
    l10n::tr("NetworkManager is not running.", &[])
}

/// No such system VPN (deleted in NM, or not the user's).
pub(crate) fn not_found() -> String {
    l10n::tr("NetworkManager has no VPN with this ID that this user may use.", &[])
}

impl Engine {
    /// The NM client without registering the agent (listing and watching need none).
    pub(crate) fn nm_client(&self) -> Result<&NmClient, String> {
        if let Some(c) = self.helper.client.get() {
            return Ok(c);
        }
        let _init = self.helper.init.lock().unwrap_or_else(PoisonError::into_inner);
        if self.helper.client.get().is_none() {
            let bus = (self.bus)().map_err(|_| nm_unavailable())?;
            let _ = self.helper.client.set(NmClient::new(bus));
        }
        self.helper.client.get().ok_or_else(nm_unavailable)
    }

    /// Whether a saved profile is one of this user's system VPNs.
    pub(crate) fn is_system_vpn(&self, p: &ProfileInfo) -> bool {
        is_listed(&p.nm_type, &p.permissions, p.flags, &self.user, is_linvpn_made(&p.uuid, &p.id))
    }

    /// The system VPN with NM UUID `uuid`.
    pub(crate) fn system_profile(&self, uuid: &str) -> Result<ProfileInfo, String> {
        let client = self.nm_client()?;
        let profiles = client.profiles().map_err(|e| e.message())?;
        profiles.into_iter().find(|p| p.uuid == uuid && self.is_system_vpn(p)).ok_or_else(not_found)
    }
}

/// The most advanced state of `uuid`'s active connections (a re-activation can briefly overlap the old one).
fn status_of(uuid: &str, active: &[ActiveInfo]) -> &'static str {
    const ORDER: [&str; 4] = ["Connected", "Disconnecting", "Connecting", "Disconnected"];
    active
        .iter()
        .filter(|a| a.uuid == uuid)
        .map(|a| system_vpn::status(a.state, a.vpn_state))
        .min_by_key(|s| ORDER.iter().position(|o| o == s))
        .unwrap_or("Disconnected")
}

/// The connected active connection of `uuid`.
pub(crate) fn connected<'a>(uuid: &str, active: &'a [ActiveInfo]) -> Option<&'a ActiveInfo> {
    active.iter().find(|a| a.uuid == uuid && system_vpn::status(a.state, a.vpn_state) == "Connected")
}

/// The user's system VPNs with their states. `active`: NM's active connections (read once by the caller).
pub fn list_with(engine: &Engine, active: &[ActiveInfo]) -> Result<Vec<SystemVpn>, String> {
    let client = engine.nm_client()?;
    let profiles = client.profiles().map_err(|e| e.message())?;
    Ok(profiles
        .iter()
        .filter(|p| engine.is_system_vpn(p))
        .map(|p| {
            SystemVpn::new(
                &p.uuid,
                &p.id,
                type_label(&p.nm_type, p.service_type.as_deref()),
                status_of(&p.uuid, active),
            )
        })
        .collect())
}

/// [`list_with`] reading NM's active connections itself.
pub fn list(engine: &Engine) -> Result<Vec<SystemVpn>, String> {
    let active = engine.nm_client()?.active().map_err(|e| e.message())?;
    list_with(engine, &active)
}

/// The tunnel counters of a connected system VPN: WireGuard's own interface, a PPP / tun plugin's interface holding
/// its address, charon-nm's XFRM interface holding it (IKEv2, strongSwan 6); IKEv2 without one (an older,
/// policy-based charon-nm) its IPsec SAs' from `linvpn-xfrmd`, which answers only for a profile that is for every
/// user (`macvpn_core::xfrmd`).
pub fn traffic_of(engine: &Engine, a: &ActiveInfo) -> Option<TrafficReading> {
    let ikev2 = a.service_type.as_deref() == Some(macvpn_core::nm_plan::SERVICE_STRONGSWAN);
    let iface = if a.nm_type == "wireguard" {
        a.ip_iface.clone()?
    } else if let Some(iface) = a.ip4.as_deref().and_then(|ip| engine.vpn_iface_for(ikev2, ip)) {
        iface
    } else if ikev2 {
        let uuid = uuid::Uuid::parse_str(&a.uuid).ok()?;
        let (rx, tx) = engine.xfrm_counters_of(&macvpn_core::xfrmd::Target::System(uuid))?;
        let mut parts = vec![0];
        parts.extend(a.path.bytes().map(u64::from));
        return Some(TrafficReading {
            generation: traffic::generation(&parts),
            rx,
            tx,
            width: CounterWidth::Bits64,
            from_zero: true,
        });
    } else {
        return None;
    };
    let (rx, tx) = engine.counters_of(&iface)?;
    let ifindex = sysfs::ifindex(&iface).unwrap_or(0);
    // NM numbers each activation's object path anew: a new activation is a new generation.
    let mut parts = vec![u64::from(ifindex)];
    parts.extend(a.path.bytes().map(u64::from));
    Some(TrafficReading {
        generation: traffic::generation(&parts),
        rx,
        tx,
        width: CounterWidth::Bits64,
        from_zero: true,
    })
}

/// Calls `on_change` when NM's profiles or active connections change (a system VPN added, edited, removed,
/// connecting, connected or gone). Its own bus connection; dropping the box stops it. In the sandbox nothing is
/// watched.
pub fn watch(engine: &Engine, on_change: Box<dyn Fn() + Send>) -> io::Result<Box<dyn Send>> {
    if engine.sandbox {
        return Ok(Box::new(()));
    }
    let bus = (engine.bus)().map_err(io::Error::other)?;
    let client = NmClient::new(bus);
    let on_change = Mutex::new(on_change);
    let guard = client
        .watch(Box::new(move |event| {
            if matches!(
                event,
                NmEvent::ProfilesChanged
                    | NmEvent::ActiveChanged
                    | NmEvent::ActiveState { .. }
                    | NmEvent::VpnState { .. }
            ) {
                (on_change.lock().unwrap_or_else(PoisonError::into_inner))();
            }
        }))
        .map_err(io::Error::other)?;
    Ok(Box::new((guard, client)))
}
