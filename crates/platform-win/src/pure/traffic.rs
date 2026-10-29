//! Live traffic on Windows: which counters a tunnel's reading comes from, and their generations.
//!
//! - **WireGuard** (the service's adapter, one per connection, created at connect): the adapter's `GetIfEntry2`
//!   counters, found by the alias the service reports; they start with the tunnel.
//! - **OpenVPN**: the service's `traffic <id>` (OpenVPN's own management `>BYTECOUNT`, counted from the
//!   `openvpn.exe` start: one generation per process run, a reconnect inside it keeps counting). Only when the
//!   service gives none (an older service answers its usage error): the counters of the DCO / TAP adapter that holds
//!   the reported tunnel address; that adapter is installed once and reused, so only what comes after the first
//!   reading counts.
//! - **RAS** (IKEv2, SSTP, L2TP, and the system VPNs): `RasGetConnectionStatistics` of the RAS connection, 32-bit,
//!   counted from its dial. A handle value may come back for a later connection: its connected time starting again
//!   makes a new generation ([`RasGenerations`]).

use macvpn_core::models::VPNKind;
use macvpn_platform_api::traffic::generation;
use macvpn_platform_api::{CounterWidth, TrafficReading};
use std::collections::HashMap;

/// How a service tunnel's interface is found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lookup {
    /// By the adapter alias the service reported (WireGuard).
    Alias(String),
    /// By the tunnel address the service reported (OpenVPN, whose adapter the service does not name).
    Address(std::net::IpAddr),
}

/// Where a service tunnel's counters are read; `None`: nowhere (nothing reported, another kind).
pub fn lookup(kind: VPNKind, iface: Option<&str>, ip: Option<&str>) -> Option<Lookup> {
    match kind {
        VPNKind::Wireguard => iface.filter(|i| is_alias(i)).map(|i| Lookup::Alias(i.to_string())),
        VPNKind::Openvpn => ip.and_then(|ip| ip.parse().ok()).map(Lookup::Address),
        _ => None,
    }
}

/// An alias as the service reports one (letters, digits and `-`, as its `status` checks).
fn is_alias(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// A service tunnel's reading of interface `index`'s counters. `since`: the run's start the service reported.
pub fn interface_reading(lookup: &Lookup, index: u32, since: Option<f64>, rx: u64, tx: u64) -> TrafficReading {
    let since = since.map_or(0, |s| s.max(0.0) as u64);
    TrafficReading {
        generation: generation(&[u64::from(index), since]),
        rx,
        tx,
        width: CounterWidth::Bits64,
        // The WireGuard adapter is made for the tunnel; OpenVPN's is reused.
        from_zero: matches!(lookup, Lookup::Alias(_)),
    }
}

/// A reading of the service's `traffic` answer (OpenVPN's `>BYTECOUNT` of one process run).
pub fn service_count_reading(b: &macvpn_core::traffic::ByteCount) -> TrafficReading {
    // Tagged apart from the adapter readings' generations (the fallback), so a switch between the two is a new one.
    const BYTECOUNT: u64 = 0x4259_5445_434f_554e;
    TrafficReading {
        generation: generation(&[BYTECOUNT, b.run]),
        rx: b.rx,
        tx: b.tx,
        width: CounterWidth::Bits64,
        from_zero: true,
    }
}

/// The generations of RAS connections by handle value (kept for the app's run: a few entries, and a handle that
/// comes back must still be told apart from its earlier connection).
#[derive(Debug, Default)]
pub struct RasGenerations {
    /// handle → (epoch, the connected time last read in ms).
    seen: HashMap<usize, (u64, u32)>,
}

impl RasGenerations {
    /// The reading of RAS connection `handle` with its statistics.
    pub fn reading(&mut self, handle: usize, rx: u32, tx: u32, duration_ms: u32) -> TrafficReading {
        let entry = self.seen.entry(handle).or_insert((0, duration_ms));
        if duration_ms < entry.1 {
            // Connected for less time than before: another connection got the handle.
            entry.0 += 1;
        }
        entry.1 = duration_ms;
        TrafficReading {
            generation: generation(&[handle as u64, entry.0]),
            rx: u64::from(rx),
            tx: u64::from(tx),
            width: CounterWidth::Bits32,
            from_zero: true,
        }
    }
}
