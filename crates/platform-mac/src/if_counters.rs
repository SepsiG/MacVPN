//! Live traffic: an interface's 64-bit byte counters (`sysctl` `NET_RT_IFLIST2` for one interface index, the
//! `if_data64` of its `RTM_IFINFO2` message, as `netstat -ib` reads them). No root needed, no process started.
//! The calls are in [`crate::sys`]; the answer is parsed here in safe Rust, at the fields' offsets in libc's
//! `if_msghdr2` / `if_data64`.

use crate::sys;
use macvpn_platform_api::traffic::generation;
use macvpn_platform_api::{CounterWidth, HelperTunnel, TrafficReading};
use std::mem::offset_of;

/// An interface's counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IfCounters {
    pub index: u32,
    pub rx: u64,
    pub tx: u64,
}

/// A tunnel interface name as the root layer reports it (`utun7`, `ppp0`, `ipsec0`): letters then digits.
pub fn is_tunnel_name(name: &str) -> bool {
    let digits = name.trim_start_matches(|c: char| c.is_ascii_lowercase());
    name.len() <= 15 && digits.len() < name.len() && !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

/// The counters of the interface `name`; `None`: no such interface, or the system did not answer.
pub fn read(name: &str) -> Option<IfCounters> {
    if !is_tunnel_name(name) {
        return None;
    }
    let index = sys::if_index(name);
    if index == 0 {
        return None;
    }
    let buf = sys::iflist2(index)?;
    parse(&buf, index)
}

/// The `RTM_IFINFO2` message of interface `index` in a `NET_RT_IFLIST2` answer.
pub fn parse(buf: &[u8], index: u32) -> Option<IfCounters> {
    const HEADER: usize = std::mem::size_of::<libc::if_msghdr2>();
    const INDEX: usize = offset_of!(libc::if_msghdr2, ifm_index);
    const DATA: usize = offset_of!(libc::if_msghdr2, ifm_data);
    const RX: usize = DATA + offset_of!(libc::if_data64, ifi_ibytes);
    const TX: usize = DATA + offset_of!(libc::if_data64, ifi_obytes);
    let u16_at = |m: &[u8], at: usize| u16::from_ne_bytes([m[at], m[at + 1]]);
    let u64_at = |m: &[u8], at: usize| u64::from_ne_bytes(m[at..at + 8].try_into().unwrap_or([0; 8]));
    let mut at = 0usize;
    while at + 4 <= buf.len() {
        let len = usize::from(u16_at(buf, at));
        if len < 4 || at + len > buf.len() {
            return None;
        }
        let m = &buf[at..at + len];
        if i32::from(m[3]) == libc::RTM_IFINFO2 && len >= HEADER && u32::from(u16_at(m, INDEX)) == index {
            return Some(IfCounters { index, rx: u64_at(m, RX), tx: u64_at(m, TX) });
        }
        at += len;
    }
    None
}

/// The reading of a root-layer tunnel whose interface was reported: its counters started with the interface
/// (every macOS engine makes its own `utun` / `ppp` per run). The generation is the interface index and the run's
/// start.
pub fn helper_reading(tunnel: &HelperTunnel<'_>) -> Option<TrafficReading> {
    let c = read(tunnel.iface?)?;
    let since = tunnel.since.map_or(0, |s| s.max(0.0) as u64);
    Some(TrafficReading {
        generation: generation(&[u64::from(c.index), since]),
        rx: c.rx,
        tx: c.tx,
        width: CounterWidth::Bits64,
        from_zero: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tunnel_names() {
        for ok in ["utun7", "ppp0", "ipsec12", "lo0"] {
            assert!(is_tunnel_name(ok), "{ok}");
        }
        for bad in ["", "utun", "7", "utun7a", "UTUN7", "utun-1", "../x0", "abcdefghijklmn12"] {
            assert!(!is_tunnel_name(bad), "{bad}");
        }
    }

    #[test]
    fn the_loopback_counts_what_it_carries() {
        let before = read("lo0").expect("lo0 is always there");
        assert!(before.index > 0);
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let target = socket.local_addr().unwrap();
        for _ in 0..20 {
            socket.send_to(&[0u8; 1000], target).unwrap();
        }
        let after = read("lo0").unwrap();
        assert!(after.tx >= before.tx + 20_000, "{before:?} → {after:?}");
        assert!(after.rx >= before.rx + 20_000, "{before:?} → {after:?}");
        assert_eq!(read("utun999"), None);
    }

    #[test]
    fn a_truncated_answer_reads_nothing() {
        assert_eq!(parse(&[], 1), None);
        assert_eq!(parse(&[200, 0, 5, 18], 1), None);
        assert_eq!(parse(&[2, 0, 5, 18], 1), None);
    }
}
