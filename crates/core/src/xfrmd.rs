//! linvpn-xfrmd's protocol, XFRM netlink parser, SA selection and authorization (LinVPN: IKEv2 traffic and
//! liveness).
//!
//! NetworkManager's strongSwan plugin (charon-nm) makes no network interface: IKEv2 is policy-based XFRM, so the
//! only byte counters of such a tunnel are its IPsec SAs' (`struct xfrm_lifetime_cur` of each SA). Reading XFRM
//! state needs `CAP_NET_ADMIN`, so a small socket-activated service (`linvpn-xfrmd`, helper crate) reads them for
//! the user; this module is its pure half, tested on every OS. The server and the client only move bytes.
//!
//! ```text
//! request:  linvpn-xfrmd-v1 linvpn <LinVPN connection UUID>\n      (≤ MAX_REQUEST bytes)
//!           linvpn-xfrmd-v1 system <NetworkManager connection UUID>\n
//! response: T <rx bytes> <tx bytes>\n    or    N\n                  (≤ MAX_RESPONSE bytes)
//! ```
//!
//! **Ownership** ([`authorize`]): the caller is its `SO_PEERCRED` uid. A `linvpn` target's NetworkManager UUID is
//! derived from that uid and the named connection ([`crate::nm_plan::names::nm_uuid`], as `linvpn-logd` does), so a
//! caller only reaches its own LinVPN connections. A `system` target (the user's own NM profile, a "system VPN")
//! counts only when NetworkManager shows the service its settings and they say the profile is a strongSwan VPN
//! **for every user** (empty `connection.permissions`): NM hides a user-restricted profile's settings from the
//! service's own (dynamic) user and exposes no "activated by" uid, so whose such a profile is cannot be decided
//! safely, and it is refused. A system-wide profile's counters are what every local user can already read for the
//! interface-based kinds (`/sys/class/net/*/statistics` is world-readable). In both cases the connection must be
//! an activated NM VPN (`Type` `vpn`, state activated, VPN state activated) with at least one address, and no
//! *other* active connection may hold any of its addresses (fail closed on an ambiguous address; NM's `loopback`
//! connection does not count: charon-nm installs the virtual IP on `lo`, so NM shows it there too).
//!
//! **Which SAs** ([`counters`]): NM's addresses of the connection (its `Ip4Config` / `Ip6Config`, set by NM from
//! charon-nm's virtual IP; never chosen by the caller) select the XFRM policies whose selector is exactly that
//! address (outbound: source /32 or /128; inbound: destination), and their templates' `(reqid, outer destination,
//! outer source when named, protocol)` select the SAs: outbound SAs give `tx`, inbound SAs `rx`, summed (a rekey's
//! old and new SA both). An SA with a selector of its own must name that address too. A template with reqid 0
//! ("any") selects nothing. Only ESP and AH SAs count (IPComp would count twice). Without an SA in each direction
//! the answer is `N`, and also when a selected SA fits another tunnel's template as well (the system's charon and
//! charon-nm both number reqids from 1: toward the same gateway their tunnel-mode SAs cannot be told apart).
//!
//! **What leaves the service**: two sums, nothing else (no SPI, no address, no key; the dump's key attributes are
//! skipped, never read, and the server wipes its receive buffers). The parser ([`DumpParser`]) is defensive: every
//! length is checked against its container, a kernel error, a foreign sequence number, an unexpected message type
//! or more than [`MAX_ENTRIES`] entries fail the dump. The struct offsets are Linux's on 64-bit targets (x86_64,
//! aarch64: `struct xfrm_usersa_info` is 224 bytes; checked against `<linux/xfrm.h>` on the target).

use crate::models::parse_uuid;
use crate::nm_plan::{SERVICE_STRONGSWAN, names};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use uuid::Uuid;

pub const MAGIC: &str = "linvpn-xfrmd-v1";
/// The longest request, newline included.
pub const MAX_REQUEST: usize = 128;
/// The longest response, newline included.
pub const MAX_RESPONSE: usize = 64;
/// The most SAs or policies one dump may hold.
pub const MAX_ENTRIES: usize = 16_384;
/// The most templates one policy may carry (the kernel's `XFRM_MAX_DEPTH` is 6).
pub const MAX_TMPLS: usize = 16;

/// Which connection the caller asks about.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Target {
    /// A LinVPN connection id (not the NM UUID): the server derives the NM UUID from the caller's uid.
    Linvpn(Uuid),
    /// A system VPN's NM connection UUID.
    System(Uuid),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Request {
    pub target: Target,
}

impl Request {
    pub fn encode(&self) -> String {
        let (kind, id) = match &self.target {
            Target::Linvpn(id) => ("linvpn", id),
            Target::System(id) => ("system", id),
        };
        format!("{MAGIC} {kind} {}\n", id.hyphenated())
    }

    /// Strict: exactly the form [`Request::encode`] writes (lower-case hyphenated UUID, one `\n`), or `None`.
    pub fn parse(s: &str) -> Option<Request> {
        if s.len() > MAX_REQUEST {
            return None;
        }
        let body = s.strip_suffix('\n')?;
        let mut it = body.split(' ');
        let (magic, kind, id) = (it.next()?, it.next()?, it.next()?);
        if magic != MAGIC || it.next().is_some() {
            return None;
        }
        let id = parse_uuid(id).filter(|u| u.hyphenated().to_string() == id)?;
        let target = match kind {
            "linvpn" => Target::Linvpn(id),
            "system" => Target::System(id),
            _ => return None,
        };
        Some(Request { target })
    }
}

/// Bytes through the connection's SAs: `rx` received (inbound SAs), `tx` sent (outbound SAs).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Counters {
    pub rx: u64,
    pub tx: u64,
}

/// The server's answer: the counters, or nothing (refused, not found, no SA yet, an error: all the same `N`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Response {
    Counters(Counters),
    Unavailable,
}

impl Response {
    pub fn encode(&self) -> String {
        match self {
            Response::Counters(c) => format!("T {} {}\n", c.rx, c.tx),
            Response::Unavailable => "N\n".into(),
        }
    }

    /// Strict, or `None`.
    pub fn parse(s: &str) -> Option<Response> {
        if s.len() > MAX_RESPONSE {
            return None;
        }
        if s == "N\n" {
            return Some(Response::Unavailable);
        }
        let mut it = s.strip_suffix('\n')?.strip_prefix("T ")?.split(' ');
        let (rx, tx) = (parse_dec(it.next()?)?, parse_dec(it.next()?)?);
        if it.next().is_some() {
            return None;
        }
        Some(Response::Counters(Counters { rx, tx }))
    }
}

/// ASCII decimal, no sign, no leading zero (but `0`), fits u64.
fn parse_dec(s: &str) -> Option<u64> {
    if s.is_empty() || s.len() > 20 || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0')) {
        return None;
    }
    s.parse().ok()
}

// ---- netlink ----

/// The netlink protocol of XFRM (`NETLINK_XFRM`).
pub const NETLINK_XFRM: i32 = 6;
const NLMSG_HDRLEN: usize = 16;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_DUMP: u16 = 0x300;
const XFRM_MSG_NEWSA: u16 = 16;
const XFRM_MSG_GETSA: u16 = 18;
const XFRM_MSG_NEWPOLICY: u16 = 19;
const XFRM_MSG_GETPOLICY: u16 = 21;
const XFRMA_TMPL: u16 = 5;
/// `NLA_F_NESTED | NLA_F_NET_BYTEORDER`.
const NLA_TYPE_MASK: u16 = !0xC000;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
pub const IPPROTO_ESP: u8 = 50;
pub const IPPROTO_AH: u8 = 51;
pub const XFRM_POLICY_IN: u8 = 0;
pub const XFRM_POLICY_OUT: u8 = 1;
pub const XFRM_POLICY_FWD: u8 = 2;

/// `struct xfrm_usersa_info` (64-bit layout; its `sel` at 0, laid out as the policy's).
mod sa_info {
    pub const SIZE: usize = 224;
    pub const SEL_DADDR: usize = 0;
    pub const SEL_SADDR: usize = 16;
    pub const SEL_FAMILY: usize = 40;
    pub const SEL_PREFIXLEN_D: usize = 42;
    pub const SEL_PREFIXLEN_S: usize = 43;
    /// `saddr` (the SA's outer source).
    pub const SADDR: usize = 80;
    /// `id.daddr`, `id.proto`.
    pub const DADDR: usize = 56;
    pub const PROTO: usize = 76;
    /// `curlft.bytes`, `curlft.packets`.
    pub const BYTES: usize = 160;
    pub const PACKETS: usize = 168;
    pub const REQID: usize = 208;
    pub const FAMILY: usize = 212;
}

/// `struct xfrm_userpolicy_info` (64-bit layout; its `sel` at 0).
mod policy_info {
    pub const SIZE: usize = 168;
    pub const SEL_DADDR: usize = 0;
    pub const SEL_SADDR: usize = 16;
    pub const SEL_FAMILY: usize = 40;
    pub const SEL_PREFIXLEN_D: usize = 42;
    pub const SEL_PREFIXLEN_S: usize = 43;
    pub const DIR: usize = 160;
}

/// `struct xfrm_user_tmpl`.
mod tmpl_info {
    pub const SIZE: usize = 64;
    pub const DADDR: usize = 0;
    pub const PROTO: usize = 20;
    pub const FAMILY: usize = 24;
    pub const SADDR: usize = 28;
    pub const REQID: usize = 44;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DumpKind {
    Sas,
    Policies,
}

impl DumpKind {
    fn get(self) -> u16 {
        match self {
            DumpKind::Sas => XFRM_MSG_GETSA,
            DumpKind::Policies => XFRM_MSG_GETPOLICY,
        }
    }

    fn reply(self) -> u16 {
        match self {
            DumpKind::Sas => XFRM_MSG_NEWSA,
            DumpKind::Policies => XFRM_MSG_NEWPOLICY,
        }
    }
}

/// The dump request: a bare `nlmsghdr` (`XFRM_MSG_GETSA` / `XFRM_MSG_GETPOLICY`, `NLM_F_REQUEST | NLM_F_DUMP`),
/// no attributes. Built from constants only: nothing the caller sent reaches the netlink socket.
pub fn dump_request(kind: DumpKind, seq: u32) -> [u8; NLMSG_HDRLEN] {
    let mut m = [0u8; NLMSG_HDRLEN];
    m[0..4].copy_from_slice(&(NLMSG_HDRLEN as u32).to_ne_bytes());
    m[4..6].copy_from_slice(&kind.get().to_ne_bytes());
    m[6..8].copy_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    m[8..12].copy_from_slice(&seq.to_ne_bytes());
    m
}

/// One SA's counts (its outer addresses, protocol and reqid say which tunnel and direction it is).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sa {
    pub daddr: IpAddr,
    /// The outer source (`saddr`).
    pub saddr: IpAddr,
    /// Its selector, `None` when empty (tunnel mode: strongSwan leaves it unset) or of an unknown family.
    pub sel: Option<Selector>,
    pub proto: u8,
    pub reqid: u32,
    pub bytes: u64,
    pub packets: u64,
}

/// An SA's traffic selector (`struct xfrm_selector`'s addresses and prefixes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selector {
    pub src: IpAddr,
    pub prefix_src: u8,
    pub dst: IpAddr,
    pub prefix_dst: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tmpl {
    pub daddr: IpAddr,
    /// The outer source; `None` when unspecified (all zero: any).
    pub saddr: Option<IpAddr>,
    pub proto: u8,
    pub reqid: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub dir: u8,
    pub src: IpAddr,
    pub prefix_src: u8,
    pub dst: IpAddr,
    pub prefix_dst: u8,
    pub tmpls: Vec<Tmpl>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DumpError {
    /// The kernel answered an error (its errno, positive: 1 = `EPERM` without `CAP_NET_ADMIN`).
    Kernel(i32),
    /// A length, type or sequence number that does not fit.
    Malformed,
    /// More than [`MAX_ENTRIES`] entries.
    TooLarge,
}

/// One dump's parser: feed it each datagram the socket returns until [`DumpParser::is_done`].
#[derive(Debug)]
pub struct DumpParser {
    kind: DumpKind,
    seq: u32,
    done: bool,
    sas: Vec<Sa>,
    policies: Vec<Policy>,
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_ne_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// An `xfrm_address_t` of `family`; `None` for another family.
fn addr_at(b: &[u8], at: usize, family: u16) -> Option<IpAddr> {
    match family {
        AF_INET => {
            let o: [u8; 4] = b.get(at..at + 4)?.try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(o)))
        }
        AF_INET6 => {
            let o: [u8; 16] = b.get(at..at + 16)?.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(o)))
        }
        _ => None,
    }
}

fn align4(n: usize) -> usize {
    n.saturating_add(3) & !3
}

impl DumpParser {
    pub fn new(kind: DumpKind, seq: u32) -> DumpParser {
        DumpParser { kind, seq, done: false, sas: Vec::new(), policies: Vec::new() }
    }

    pub fn is_done(&self) -> bool {
        self.done
    }

    pub fn sas(&self) -> &[Sa] {
        &self.sas
    }

    pub fn policies(&self) -> &[Policy] {
        &self.policies
    }

    pub fn into_parts(self) -> (Vec<Sa>, Vec<Policy>) {
        (self.sas, self.policies)
    }

    /// One datagram. After the dump's end (`NLMSG_DONE`) anything more is ignored.
    pub fn feed(&mut self, datagram: &[u8]) -> Result<(), DumpError> {
        let mut rest = datagram;
        while !self.done && !rest.is_empty() {
            let len = u32_at(rest, 0).ok_or(DumpError::Malformed)? as usize;
            if len < NLMSG_HDRLEN || len > rest.len() {
                return Err(DumpError::Malformed);
            }
            let kind = u16_at(rest, 4).ok_or(DumpError::Malformed)?;
            let seq = u32_at(rest, 8).ok_or(DumpError::Malformed)?;
            let payload = &rest[NLMSG_HDRLEN..len];
            if seq != self.seq {
                return Err(DumpError::Malformed);
            }
            match kind {
                NLMSG_ERROR => {
                    let errno = u32_at(payload, 0).ok_or(DumpError::Malformed)? as i32;
                    // 0 would be an acknowledgement: a dump never sends one.
                    return Err(if errno < 0 {
                        DumpError::Kernel(errno.saturating_neg())
                    } else {
                        DumpError::Malformed
                    });
                }
                NLMSG_DONE => {
                    if let Some(e) = u32_at(payload, 0).map(|e| e as i32)
                        && e < 0
                    {
                        return Err(DumpError::Kernel(e.saturating_neg()));
                    }
                    self.done = true;
                }
                k if k == self.kind.reply() => {
                    if self.sas.len() + self.policies.len() >= MAX_ENTRIES {
                        return Err(DumpError::TooLarge);
                    }
                    match self.kind {
                        DumpKind::Sas => {
                            if let Some(sa) = parse_sa(payload)? {
                                self.sas.push(sa);
                            }
                        }
                        DumpKind::Policies => {
                            if let Some(p) = parse_policy(payload)? {
                                self.policies.push(p);
                            }
                        }
                    }
                }
                _ => return Err(DumpError::Malformed),
            }
            rest = rest.get(align4(len)..).unwrap_or(&[]);
        }
        Ok(())
    }
}

/// The fixed struct only (the attributes after it, keys among them, are never read). `Ok(None)`: a family this
/// parser does not know (skipped).
fn parse_sa(p: &[u8]) -> Result<Option<Sa>, DumpError> {
    if p.len() < sa_info::SIZE {
        return Err(DumpError::Malformed);
    }
    let m = DumpError::Malformed;
    let family = u16_at(p, sa_info::FAMILY).ok_or(m)?;
    let Some(daddr) = addr_at(p, sa_info::DADDR, family) else { return Ok(None) };
    let saddr = addr_at(p, sa_info::SADDR, family).ok_or(m)?;
    let sel_family = u16_at(p, sa_info::SEL_FAMILY).ok_or(m)?;
    let sel = match (addr_at(p, sa_info::SEL_SADDR, sel_family), addr_at(p, sa_info::SEL_DADDR, sel_family)) {
        (Some(src), Some(dst)) if p[sa_info::SEL_PREFIXLEN_S] != 0 || p[sa_info::SEL_PREFIXLEN_D] != 0 => {
            Some(Selector {
                src,
                prefix_src: p[sa_info::SEL_PREFIXLEN_S],
                dst,
                prefix_dst: p[sa_info::SEL_PREFIXLEN_D],
            })
        }
        _ => None,
    };
    Ok(Some(Sa {
        daddr,
        saddr,
        sel,
        proto: p[sa_info::PROTO],
        reqid: u32_at(p, sa_info::REQID).ok_or(m)?,
        bytes: u64_at(p, sa_info::BYTES).ok_or(m)?,
        packets: u64_at(p, sa_info::PACKETS).ok_or(m)?,
    }))
}

fn parse_policy(p: &[u8]) -> Result<Option<Policy>, DumpError> {
    let m = DumpError::Malformed;
    if p.len() < policy_info::SIZE {
        return Err(m);
    }
    let family = u16_at(p, policy_info::SEL_FAMILY).ok_or(m)?;
    let mut tmpls = Vec::new();
    let mut attrs = &p[align4(policy_info::SIZE).min(p.len())..];
    while !attrs.is_empty() {
        let len = u16_at(attrs, 0).ok_or(m)? as usize;
        let kind = u16_at(attrs, 2).ok_or(m)? & NLA_TYPE_MASK;
        if len < 4 || len > attrs.len() {
            return Err(m);
        }
        if kind == XFRMA_TMPL {
            let data = &attrs[4..len];
            if !data.len().is_multiple_of(tmpl_info::SIZE) || data.len() / tmpl_info::SIZE > MAX_TMPLS {
                return Err(m);
            }
            for t in data.as_chunks::<{ tmpl_info::SIZE }>().0 {
                let tf = u16_at(t, tmpl_info::FAMILY).ok_or(m)?;
                if let Some(daddr) = addr_at(t, tmpl_info::DADDR, tf) {
                    let saddr = addr_at(t, tmpl_info::SADDR, tf).filter(|a| !a.is_unspecified());
                    tmpls.push(Tmpl {
                        daddr,
                        saddr,
                        proto: t[tmpl_info::PROTO],
                        reqid: u32_at(t, tmpl_info::REQID).ok_or(m)?,
                    });
                }
            }
        }
        attrs = attrs.get(align4(len)..).unwrap_or(&[]);
    }
    let (Some(dst), Some(src)) =
        (addr_at(p, policy_info::SEL_DADDR, family), addr_at(p, policy_info::SEL_SADDR, family))
    else {
        return Ok(None);
    };
    Ok(Some(Policy {
        dir: p[policy_info::DIR],
        src,
        prefix_src: p[policy_info::SEL_PREFIXLEN_S],
        dst,
        prefix_dst: p[policy_info::SEL_PREFIXLEN_D],
        tmpls,
    }))
}

// ---- selection ----

fn full_prefix(a: &IpAddr) -> u8 {
    if a.is_ipv4() { 32 } else { 128 }
}

fn is_ipsec(proto: u8) -> bool {
    proto == IPPROTO_ESP || proto == IPPROTO_AH
}

/// Whether `sa` is one `t` describes: reqid, protocol and outer destination, and the outer source when the
/// template names one.
fn tmpl_matches(t: &Tmpl, sa: &Sa) -> bool {
    t.reqid == sa.reqid && t.proto == sa.proto && t.daddr == sa.daddr && t.saddr.is_none_or(|a| a == sa.saddr)
}

/// An SA's own selector, when it has one, must be the connection's address too (outbound: its source; inbound:
/// its destination).
fn selector_fits(sa: &Sa, inner: &[IpAddr], outbound: bool) -> bool {
    let Some(sel) = sa.sel else { return true };
    let (addr, prefix) = if outbound { (sel.src, sel.prefix_src) } else { (sel.dst, sel.prefix_dst) };
    prefix == full_prefix(&addr) && inner.contains(&addr)
}

/// The connection's counters: see the module docs. `None` without an SA in each direction, and `None` when an SA
/// of the connection is also described by another tunnel's template (two IKE daemons, say the system's charon and
/// charon-nm, may use the same reqid toward the same gateway from the same address: such an SA cannot be told apart,
/// so nothing is counted rather than another tunnel's bytes).
pub fn counters(inner: &[IpAddr], policies: &[Policy], sas: &[Sa]) -> Option<Counters> {
    let mut out_tmpls = Vec::new();
    let mut in_tmpls = Vec::new();
    let mut foreign = Vec::new();
    for p in policies {
        let usable = p.tmpls.iter().filter(|t| t.reqid != 0 && is_ipsec(t.proto));
        let own_out = p.prefix_src == full_prefix(&p.src) && inner.contains(&p.src);
        let own_in = p.prefix_dst == full_prefix(&p.dst) && inner.contains(&p.dst);
        match p.dir {
            XFRM_POLICY_OUT if own_out => out_tmpls.extend(usable),
            XFRM_POLICY_IN if own_in => in_tmpls.extend(usable),
            // The connection's forward policy repeats its inbound templates.
            XFRM_POLICY_FWD if own_in => {}
            _ => foreign.extend(usable),
        }
    }
    let (mut rx, mut tx, mut seen_in, mut seen_out) = (0u64, 0u64, false, false);
    for s in sas.iter().filter(|s| is_ipsec(s.proto)) {
        let out = out_tmpls.iter().any(|t| tmpl_matches(t, s)) && selector_fits(s, inner, true);
        let inb = !out && in_tmpls.iter().any(|t| tmpl_matches(t, s)) && selector_fits(s, inner, false);
        if !(out || inb) {
            continue;
        }
        if foreign.iter().any(|t| tmpl_matches(t, s)) {
            return None;
        }
        if out {
            tx = tx.saturating_add(s.bytes);
            seen_out = true;
        } else {
            rx = rx.saturating_add(s.bytes);
            seen_in = true;
        }
    }
    (seen_in && seen_out).then_some(Counters { rx, tx })
}

// ---- authorization ----

/// The `Type` of NM's active connection for the loopback device.
pub const NM_TYPE_LOOPBACK: &str = "loopback";
/// NM's `NM_ACTIVE_CONNECTION_STATE_ACTIVATED`.
pub const ACTIVE_ACTIVATED: u32 = 2;
/// NM's `NM_VPN_CONNECTION_STATE_ACTIVATED`.
pub const VPN_ACTIVATED: u32 = 5;

/// One NM active connection as the server read it (properties every user may read).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveFacts {
    pub uuid: String,
    /// Its settings object path (`Connection`).
    pub connection: String,
    pub nm_type: String,
    pub vpn: bool,
    pub state: u32,
    pub vpn_state: Option<u32>,
    /// Its `Ip4Config` and `Ip6Config` addresses.
    pub addresses: Vec<IpAddr>,
}

/// A profile's settings as NM showed them to the server (`GetSettings`; `None` when NM refused).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileFacts {
    pub permissions: Vec<String>,
    pub service_type: Option<String>,
}

/// The NM UUID a target names for `uid`.
pub fn nm_uuid(target: &Target, uid: u32) -> String {
    match target {
        Target::Linvpn(id) => names::nm_uuid(uid, id).hyphenated().to_string(),
        Target::System(u) => u.hyphenated().to_string(),
    }
}

/// The addresses whose SAs `uid` may read for `target` (see the module docs), or `None`. `profile` reads a settings
/// object path's profile (only asked for `system` targets).
pub fn authorize(
    target: &Target,
    uid: u32,
    actives: &[ActiveFacts],
    profile: &dyn Fn(&str) -> Option<ProfileFacts>,
) -> Option<Vec<IpAddr>> {
    let want = nm_uuid(target, uid);
    let mine: Vec<&ActiveFacts> = actives
        .iter()
        .filter(|a| {
            a.uuid == want
                && a.nm_type == "vpn"
                && a.vpn
                && a.state == ACTIVE_ACTIVATED
                && a.vpn_state == Some(VPN_ACTIVATED)
        })
        .collect();
    if mine.is_empty() {
        return None;
    }
    if matches!(target, Target::System(_)) {
        for a in &mine {
            let p = profile(&a.connection)?;
            if !p.permissions.is_empty() || p.service_type.as_deref() != Some(SERVICE_STRONGSWAN) {
                return None;
            }
        }
    }
    let mut addresses: Vec<IpAddr> = Vec::new();
    for a in &mine {
        for ip in &a.addresses {
            if !addresses.contains(ip) {
                addresses.push(*ip);
            }
        }
    }
    if addresses.is_empty() {
        return None;
    }
    // NM's own loopback connection (NM ≥ 1.42 manages `lo`) shows the virtual IP charon-nm installs on `lo`: the same
    // address on the host, not another holder.
    let shared = actives
        .iter()
        .filter(|a| a.uuid != want && a.nm_type != NM_TYPE_LOOPBACK)
        .any(|a| a.addresses.iter().any(|ip| addresses.contains(ip)));
    (!shared).then_some(addresses)
}
