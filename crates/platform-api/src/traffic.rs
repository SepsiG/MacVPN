//! Live traffic (maintainer request 2026-10-29): what a platform reads of a running tunnel's byte counters. The
//! totals and the rates are app-core's (`macvpn_app_core::traffic`); a platform only reads counters, cheaply and
//! without administrator rights or the root layer:
//!
//! - an interface's counters (macOS `sysctl` `NET_RT_IFLIST2`, 64-bit `if_data64`; Windows `GetIfEntry2`);
//! - a RAS connection's statistics (Windows `RasGetConnectionStatistics`, 32-bit).

use macvpn_core::models::VPNKind;
use uuid::Uuid;

/// How wide a counter is: a 32-bit counter wraps at 2³², which is not a restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterWidth {
    Bits32,
    Bits64,
}

/// One reading of a tunnel's counters (bytes since the counters started).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrafficReading {
    /// Which counters these are: another value means other counters that started from zero or from their own
    /// value (a recreated interface, another RAS connection, another run of the engine).
    pub generation: u64,
    /// Received (download).
    pub rx: u64,
    /// Sent (upload).
    pub tx: u64,
    pub width: CounterWidth,
    /// The counters started with this tunnel (an interface or a RAS connection made for it): its first reading
    /// counts whole. `false`: they belong to something older (a persistent adapter), only what comes after the
    /// first reading counts.
    pub from_zero: bool,
}

/// What the helper reported about a running tunnel of a managed helper kind (`mvpn status` / the WinVPN Service's
/// `status`, or the in-app RAS engine on Windows).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct HelperTunnel<'a> {
    pub id: &'a Uuid,
    pub kind: VPNKind,
    /// The tunnel interface's name (macOS `utun7`, `ppp0`; WinVPN: the WireGuard adapter's alias), if reported.
    pub iface: Option<&'a str>,
    /// The tunnel's address, if reported.
    pub ip: Option<&'a str>,
    /// When the engine's run started (Unix seconds), if reported.
    pub since: Option<f64>,
}

/// A stable 64-bit mix of a counter's identity parts (an interface index and the run's start), for
/// [`TrafficReading::generation`].
pub fn generation(parts: &[u64]) -> u64 {
    // FNV-1a over the parts' little-endian bytes: stable across runs and platforms (no random hasher seed).
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for p in parts {
        for b in p.to_le_bytes() {
            h ^= u64::from(b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    }
    h
}
