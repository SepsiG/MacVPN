//! The tunnel's counters and interfaces from `/sys/class/net` and `getifaddrs` (user-readable; spike L0-3).
//! Every interface name is checked ([`valid_iface_name`]) before a path is built from it.

use crate::pure::nm::iface::{is_tunnel_type, valid_iface_name};
use std::ffi::CStr;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::str::FromStr;

/// `/sys/class/net/<iface>/<attr>` as a trimmed decimal number.
fn number<T: FromStr>(iface: &str, attr: &str) -> Option<T> {
    if !valid_iface_name(iface) {
        return None;
    }
    let path = PathBuf::from("/sys/class/net").join(iface).join(attr);
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// `(rx_bytes, tx_bytes)`.
pub fn counters(iface: &str) -> Option<(u64, u64)> {
    Some((number(iface, "statistics/rx_bytes")?, number(iface, "statistics/tx_bytes")?))
}

pub fn ifindex(iface: &str) -> Option<u32> {
    number(iface, "ifindex")
}

/// The tunnel interface (tun / WireGuard / PPP / XFRM: never a physical one) that holds `ipv4`.
pub fn tunnel_iface_for(ipv4: &str) -> Option<String> {
    tunnel_ifaces_for(ipv4).into_iter().next()
}

/// Every tunnel interface that holds `ipv4`, in the system's order (charon-nm's virtual IP is on `lo` too, which
/// is no tunnel).
pub fn tunnel_ifaces_for(ipv4: &str) -> Vec<String> {
    let Ok(want) = ipv4.parse::<Ipv4Addr>() else { return Vec::new() };
    ifaces_with(want).into_iter().filter(|name| number::<u32>(name, "type").is_some_and(is_tunnel_type)).collect()
}

/// The names of the interfaces that hold `want` (`getifaddrs`), in the system's order.
fn ifaces_with(want: Ipv4Addr) -> Vec<String> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: `head` is a valid out-pointer for the call; on success it owns a list freed below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Vec::new();
    }
    let mut names = Vec::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is a node of the list `getifaddrs` returned, valid until `freeifaddrs`.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;
        if ifa.ifa_addr.is_null() || ifa.ifa_name.is_null() {
            continue;
        }
        // SAFETY: `ifa_addr` is non-null and points to a `sockaddr` of the list.
        if i32::from(unsafe { (*ifa.ifa_addr).sa_family }) != libc::AF_INET {
            continue;
        }
        // SAFETY: an `AF_INET` address of `getifaddrs` is a `sockaddr_in`.
        let sin = unsafe { &*ifa.ifa_addr.cast::<libc::sockaddr_in>() };
        if Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)) != want {
            continue;
        }
        // SAFETY: `ifa_name` is non-null and NUL-terminated, valid until `freeifaddrs`.
        if let Ok(name) = unsafe { CStr::from_ptr(ifa.ifa_name) }.to_str() {
            names.push(name.to_owned());
        }
    }
    // SAFETY: `head` came from a successful `getifaddrs` and is freed once; no reference into it outlives this.
    unsafe { libc::freeifaddrs(head) };
    names
}
