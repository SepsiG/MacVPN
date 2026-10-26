//! IP prefixes (`10.20.30.0/24`, `fd00::/64`): parsing, masking, containment and overlap. Pure; no OS calls.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A network prefix, always stored with the host bits cleared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IpPrefix {
    pub addr: IpAddr,
    pub len: u8,
}

fn bits(addr: &IpAddr) -> (u128, u8) {
    match addr {
        IpAddr::V4(a) => (u128::from(u32::from(*a)), 32),
        IpAddr::V6(a) => (u128::from(*a), 128),
    }
}

fn mask(len: u8, width: u8) -> u128 {
    if len == 0 { 0 } else { (!0u128 << (width - len)) & if width == 32 { u128::from(u32::MAX) } else { !0u128 } }
}

impl IpPrefix {
    /// `addr/len` or a bare address (a host prefix). Strict: no spaces, no host names, `len` in range.
    pub fn parse(text: &str) -> Option<IpPrefix> {
        let (addr, len) = match text.split_once('/') {
            Some((a, l)) => (a, Some(l)),
            None => (text, None),
        };
        let addr: IpAddr = addr.parse().ok()?;
        let width = bits(&addr).1;
        let len = match len {
            None => width,
            Some(l) if !l.is_empty() && l.bytes().all(|b| b.is_ascii_digit()) && l.len() <= 3 => l.parse().ok()?,
            Some(_) => return None,
        };
        IpPrefix::new(addr, len)
    }

    /// The prefix `addr/len` with the host bits cleared; `None` when `len` is too long.
    pub fn new(addr: IpAddr, len: u8) -> Option<IpPrefix> {
        let (value, width) = bits(&addr);
        if len > width {
            return None;
        }
        let net = value & mask(len, width);
        let addr = if width == 32 { IpAddr::V4(Ipv4Addr::from(net as u32)) } else { IpAddr::V6(Ipv6Addr::from(net)) };
        Some(IpPrefix { addr, len })
    }

    /// OpenVPN's `route <network> <netmask>`: a contiguous mask only.
    pub fn from_mask(addr: Ipv4Addr, netmask: Ipv4Addr) -> Option<IpPrefix> {
        let m = u32::from(netmask);
        let len = m.leading_ones();
        if m.checked_shl(len).unwrap_or(0) != 0 {
            return None;
        }
        IpPrefix::new(IpAddr::V4(addr), len as u8)
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        let (net, width) = bits(&self.addr);
        let (value, other) = bits(ip);
        width == other && value & mask(self.len, width) == net
    }

    pub fn overlaps(&self, other: &IpPrefix) -> bool {
        self.contains(&other.addr) || other.contains(&self.addr)
    }

    /// `0.0.0.0/0`, `::/0` and the `def1` halves (`0.0.0.0/1`, `128.0.0.0/1`, `::/1`, `8000::/1`).
    pub fn is_default_route(&self) -> bool {
        self.len <= 1
    }
}
