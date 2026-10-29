//! Live traffic: the readings of [`crate::pure::traffic`], from `GetIfEntry2` (the service's adapters) and
//! `RasGetConnectionStatistics` (RAS connections). All of them run as the user; none asks the service.

use crate::pure::traffic::{Lookup, RasGenerations, interface_reading, lookup};
use macvpn_platform_api::{HelperTunnel, TrafficReading};
use macvpn_winsys::net;
use macvpn_winsys::ras as wras;
use std::sync::{LazyLock, Mutex, PoisonError};

/// The RAS handles' generations (handle values are the process's).
static RAS: LazyLock<Mutex<RasGenerations>> = LazyLock::new(|| Mutex::new(RasGenerations::default()));

/// A service tunnel's reading (WireGuard by its adapter's alias, OpenVPN by the adapter holding its address).
pub(crate) fn service_reading(tunnel: &HelperTunnel<'_>) -> Option<TrafficReading> {
    let how = lookup(tunnel.kind, tunnel.iface, tunnel.ip)?;
    let luid = match &how {
        Lookup::Alias(alias) => net::luid_of_alias(alias).ok()??,
        Lookup::Address(ip) => net::luid_of_address(*ip).ok()??,
    };
    let c = net::if_counters(luid).ok()??;
    Some(interface_reading(&how, c.index, tunnel.since, c.rx, c.tx))
}

/// A RAS connection's reading.
pub(crate) fn ras_reading(handle: wras::Handle) -> Option<TrafficReading> {
    let s = wras::statistics(handle).ok()?;
    Some(RAS.lock().unwrap_or_else(PoisonError::into_inner).reading(handle.value(), s.rx, s.tx, s.duration_ms))
}
