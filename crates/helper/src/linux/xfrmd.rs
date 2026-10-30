//! `linvpn-xfrmd`, LinVPN's IKEv2 traffic counter reader: the byte counters of the IPsec SAs of the caller's own
//! IKEv2 connection (NetworkManager's strongSwan plugin makes no interface, so XFRM is the only place they exist).
//!
//! A service of its own, not a second query of `linvpn-logd`: it needs what logd must never have, the host's
//! network namespace (XFRM state is per namespace; logd runs with `PrivateNetwork=yes`), `CAP_NET_ADMIN` (the kernel
//! answers even a read-only XFRM dump only with it), `AF_NETLINK` and the system bus; and logd needs what this one
//! must never have, the `systemd-journal` group. Kept apart, each holds only its own privilege.
//!
//! systemd starts one instance per connection (`linvpn-xfrmd.socket`, `Accept=yes`) with the accepted socket on fd
//! 0, as a dynamic user whose only capability is `CAP_NET_ADMIN` (ambient and bounding set), never root. One instance
//! answers exactly one request and exits:
//!
//! 1. the caller's uid from `SO_PEERCRED` (fail closed: no credentials, no answer);
//! 2. one request ([`macvpn_core::xfrmd::Request`], at most `MAX_REQUEST` bytes, within [`READ_TIMEOUT`]); anything
//!    else gets `N` and nothing is read;
//! 3. NetworkManager's active connections from the system bus (read-only properties; for a system VPN also
//!    `GetSettings` of its profile, which NM shows only when the profile is for every user) and
//!    [`macvpn_core::xfrmd::authorize`]: the caller's own connection's addresses, or `N` (no netlink dump at all);
//! 4. one `XFRM_MSG_GETPOLICY` and one `XFRM_MSG_GETSA` dump (fixed requests built from constants: nothing the caller
//!    sent reaches the netlink socket; never a write), the receive buffers wiped after parsing, and
//!    [`macvpn_core::xfrmd::counters`]: two sums, `T <rx> <tx>`, or `N`.
//!
//! It logs only `uid=<n> answer=<T|N>` (or the error kind) to stderr, the service's journal: never the request.

use std::io::{self, ErrorKind, Read, Write};
use std::net::{IpAddr, Shutdown};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::str::FromStr;
use std::time::{Duration, Instant};

use macvpn_core::xfrmd::{
    self, ActiveFacts, Counters, DumpKind, DumpParser, Policy, ProfileFacts, Request, Response, Sa,
};
use zeroize::Zeroizing;

use crate::linux::logd;

/// How long the caller may take to send its request.
pub const READ_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the caller may take to read the response.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// How long one D-Bus call to NetworkManager may take.
pub const NM_TIMEOUT: Duration = Duration::from_secs(3);
/// How long one netlink dump may take.
pub const DUMP_TIMEOUT: Duration = Duration::from_secs(3);
/// The most bytes one dump may take in all.
pub const DUMP_CAP: usize = 32 * 1024 * 1024;
/// One receive buffer (a dump datagram is at most a few pages).
const RECV_BUFFER: usize = 64 * 1024;

/// NetworkManager as the server sees it: production reads the system bus ([`NmBus`]); the tests answer with facts.
pub trait Nm {
    /// Every active connection.
    fn actives(&self) -> io::Result<Vec<ActiveFacts>>;
    /// A profile's settings by its object path, `None` when NM refuses to show them.
    fn profile(&self, path: &str) -> Option<ProfileFacts>;
}

/// The kernel's XFRM state: production dumps it over netlink ([`Netlink`]); the tests answer with entries.
pub trait Xfrm {
    fn dump(&self) -> io::Result<(Vec<Policy>, Vec<Sa>)>;
}

/// What one request ended with (for the log line).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Counters,
    Unavailable,
}

/// One request on `stream` from `uid`. A request not complete within [`READ_TIMEOUT`] is closed unanswered
/// (`TimedOut`); an invalid one, a refusal or a failure gets `N`.
pub fn serve(stream: UnixStream, uid: u32, nm: &dyn Nm, xfrm: &dyn Xfrm) -> io::Result<Outcome> {
    serve_within(stream, uid, nm, xfrm, READ_TIMEOUT)
}

/// [`serve`] with another read timeout (the tests').
pub fn serve_within(
    mut stream: UnixStream,
    uid: u32,
    nm: &dyn Nm,
    xfrm: &dyn Xfrm,
    read_timeout: Duration,
) -> io::Result<Outcome> {
    let request = match read_request(&mut stream, read_timeout) {
        Ok(r) => r,
        Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
            let _ = stream.shutdown(Shutdown::Both);
            return Err(io::Error::new(ErrorKind::TimedOut, "no request in time"));
        }
        Err(_) => None,
    };
    let counters = request.and_then(|r| lookup(&r, uid, nm, xfrm));
    let response = counters.map_or(Response::Unavailable, Response::Counters);
    answer(&mut stream, &response)?;
    Ok(if counters.is_some() { Outcome::Counters } else { Outcome::Unavailable })
}

/// Authorization first; the netlink dump only for an authorized connection.
fn lookup(request: &Request, uid: u32, nm: &dyn Nm, xfrm: &dyn Xfrm) -> Option<Counters> {
    let actives = nm.actives().ok()?;
    let inner = xfrmd::authorize(&request.target, uid, &actives, &|path| nm.profile(path))?;
    let (policies, sas) = xfrm.dump().ok()?;
    xfrmd::counters(&inner, &policies, &sas)
}

/// The request bytes up to the first `\n` (at most `MAX_REQUEST` in all), parsed strictly; `Ok(None)` for anything
/// that is not one valid request.
fn read_request(stream: &mut UnixStream, timeout: Duration) -> io::Result<Option<Request>> {
    let deadline = Instant::now() + timeout;
    let mut buf = Vec::with_capacity(xfrmd::MAX_REQUEST + 1);
    let mut chunk = [0u8; xfrmd::MAX_REQUEST + 1];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(ErrorKind::TimedOut, "request timeout"));
        }
        stream.set_read_timeout(Some(left))?;
        let room = xfrmd::MAX_REQUEST + 1 - buf.len();
        let n = match stream.read(&mut chunk[..room]) {
            Ok(n) => n,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > xfrmd::MAX_REQUEST {
            return Ok(None);
        }
        if buf.contains(&b'\n') {
            return Ok(std::str::from_utf8(&buf).ok().and_then(Request::parse));
        }
    }
}

fn answer(stream: &mut UnixStream, response: &Response) -> io::Result<()> {
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    stream.write_all(response.encode().as_bytes())?;
    stream.flush()?;
    let _ = stream.shutdown(Shutdown::Write);
    logd::drain(stream);
    Ok(())
}

// ---- NetworkManager over the system bus ----

const NM_DEST: &str = "org.freedesktop.NetworkManager";
const NM_ROOT: &str = "/org/freedesktop/NetworkManager";
const IF_NM: &str = "org.freedesktop.NetworkManager";
const IF_ACTIVE: &str = "org.freedesktop.NetworkManager.Connection.Active";
const IF_VPN: &str = "org.freedesktop.NetworkManager.VPN.Connection";
const IF_IP4: &str = "org.freedesktop.NetworkManager.IP4Config";
const IF_IP6: &str = "org.freedesktop.NetworkManager.IP6Config";
const IF_PROFILE: &str = "org.freedesktop.NetworkManager.Settings.Connection";
const IF_PROPERTIES: &str = "org.freedesktop.DBus.Properties";
/// The most active connections read.
const MAX_ACTIVES: usize = 256;

/// NetworkManager on the system bus: property reads (`Get`) and `GetSettings`, nothing else.
pub struct NmBus {
    bus: zbus::blocking::Connection,
}

type Settings = std::collections::HashMap<String, std::collections::HashMap<String, zbus::zvariant::OwnedValue>>;

impl NmBus {
    pub fn system() -> io::Result<NmBus> {
        let bus = zbus::blocking::connection::Builder::system()
            .and_then(|b| b.method_timeout(NM_TIMEOUT).build())
            .map_err(io::Error::other)?;
        Ok(NmBus { bus })
    }

    fn get<T: TryFrom<zbus::zvariant::OwnedValue>>(&self, path: &str, iface: &str, name: &str) -> io::Result<T> {
        let path = zbus::zvariant::ObjectPath::try_from(path).map_err(io::Error::other)?;
        let reply = self
            .bus
            .call_method(Some(NM_DEST), path, Some(IF_PROPERTIES), "Get", &(iface, name))
            .map_err(io::Error::other)?;
        let v: zbus::zvariant::OwnedValue = reply.body().deserialize().map_err(io::Error::other)?;
        T::try_from(v).map_err(|_| io::Error::new(ErrorKind::InvalidData, "unexpected property type"))
    }

    /// The `address` entries of an `IP4Config` / `IP6Config` object's `AddressData` (`aa{sv}`).
    fn addresses(&self, config: &str, iface: &str) -> Vec<IpAddr> {
        if config == "/" {
            return Vec::new();
        }
        let Ok(v) = self.get::<zbus::zvariant::OwnedValue>(config, iface, "AddressData") else { return Vec::new() };
        let list =
            Vec::<std::collections::HashMap<String, zbus::zvariant::OwnedValue>>::try_from(v).unwrap_or_default();
        list.iter()
            .filter_map(|d| d.get("address")?.try_clone().ok())
            .filter_map(|v| String::try_from(v).ok())
            .filter_map(|s| IpAddr::from_str(&s).ok())
            .collect()
    }

    fn active(&self, path: &str) -> io::Result<ActiveFacts> {
        use zbus::zvariant::OwnedObjectPath;
        let vpn: bool = self.get(path, IF_ACTIVE, "Vpn")?;
        // A missing IP configuration is no address (and so never a match), not a failure.
        let mut addresses = Vec::new();
        for (property, iface) in [("Ip4Config", IF_IP4), ("Ip6Config", IF_IP6)] {
            if let Ok(config) = self.get::<OwnedObjectPath>(path, IF_ACTIVE, property) {
                addresses.extend(self.addresses(config.as_str(), iface));
            }
        }
        Ok(ActiveFacts {
            uuid: self.get(path, IF_ACTIVE, "Uuid")?,
            connection: self.get::<OwnedObjectPath>(path, IF_ACTIVE, "Connection")?.as_str().to_string(),
            nm_type: self.get(path, IF_ACTIVE, "Type")?,
            vpn,
            state: self.get(path, IF_ACTIVE, "State")?,
            vpn_state: if vpn { self.get(path, IF_VPN, "VpnState").ok() } else { None },
            addresses,
        })
    }
}

impl Nm for NmBus {
    fn actives(&self) -> io::Result<Vec<ActiveFacts>> {
        let paths: Vec<zbus::zvariant::OwnedObjectPath> = self.get(NM_ROOT, IF_NM, "ActiveConnections")?;
        // One that vanished between the list and its properties is left out.
        Ok(paths.iter().take(MAX_ACTIVES).filter_map(|p| self.active(p.as_str()).ok()).collect())
    }

    fn profile(&self, path: &str) -> Option<ProfileFacts> {
        let path = zbus::zvariant::ObjectPath::try_from(path).ok()?;
        let reply = self.bus.call_method(Some(NM_DEST), path, Some(IF_PROFILE), "GetSettings", &()).ok()?;
        let settings: Settings = reply.body().deserialize().ok()?;
        let value = |setting: &str, key: &str| settings.get(setting)?.get(key)?.try_clone().ok();
        Some(ProfileFacts {
            permissions: value("connection", "permissions")
                .and_then(|v| Vec::<String>::try_from(v).ok())
                .unwrap_or_default(),
            service_type: value("vpn", "service-type").and_then(|v| String::try_from(v).ok()),
        })
    }
}

impl crate::linux::logd::ActiveVpns for NmBus {
    /// linvpn-logd's reading: every listed active connection's `Vpn`, `State` and `Uuid`, strictly (a connection
    /// that vanished between the list and its properties fails the reading too: logd then has none).
    fn active_vpns(&self) -> io::Result<Vec<String>> {
        let paths: Vec<zbus::zvariant::OwnedObjectPath> = self.get(NM_ROOT, IF_NM, "ActiveConnections")?;
        if paths.len() > macvpn_core::logd::MAX_OBSERVED {
            return Err(io::Error::other("too many active connections"));
        }
        let mut out = Vec::new();
        for p in &paths {
            if !self.get::<bool>(p.as_str(), IF_ACTIVE, "Vpn")? {
                continue;
            }
            // NM_ACTIVE_CONNECTION_STATE_DEACTIVATED (4): gone, only not yet removed from the list.
            if self.get::<u32>(p.as_str(), IF_ACTIVE, "State")? == 4 {
                continue;
            }
            out.push(self.get::<String>(p.as_str(), IF_ACTIVE, "Uuid")?);
        }
        Ok(out)
    }
}

// ---- XFRM over netlink ----

/// The kernel's XFRM state through a `NETLINK_XFRM` socket: two dumps, read-only.
#[derive(Clone, Debug)]
pub struct Netlink {
    pub timeout: Duration,
    pub cap: usize,
}

impl Default for Netlink {
    fn default() -> Self {
        Netlink { timeout: DUMP_TIMEOUT, cap: DUMP_CAP }
    }
}

impl Xfrm for Netlink {
    fn dump(&self) -> io::Result<(Vec<Policy>, Vec<Sa>)> {
        let socket = netlink_socket()?;
        let seq = std::process::id().wrapping_shl(8);
        let (_, policies) = self.dump_one(&socket, DumpKind::Policies, seq)?.into_parts();
        let (sas, _) = self.dump_one(&socket, DumpKind::Sas, seq.wrapping_add(1))?.into_parts();
        Ok((policies, sas))
    }
}

impl Netlink {
    fn dump_one(&self, socket: &OwnedFd, kind: DumpKind, seq: u32) -> io::Result<DumpParser> {
        let deadline = Instant::now() + self.timeout;
        send_to_kernel(socket.as_fd(), &xfrmd::dump_request(kind, seq))?;
        let mut parser = DumpParser::new(kind, seq);
        // Wiped when dropped: a dump carries the SAs' keys (never parsed, but they pass through this buffer).
        let mut buf = Zeroizing::new(vec![0u8; RECV_BUFFER]);
        let mut total = 0usize;
        while !parser.is_done() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(io::Error::new(ErrorKind::TimedOut, "netlink dump timed out"));
            }
            let n = recv_from_kernel(socket.as_fd(), &mut buf, left)?;
            total = total.saturating_add(n);
            if total > self.cap {
                return Err(io::Error::new(ErrorKind::InvalidData, "netlink dump too large"));
            }
            let fed = parser.feed(&buf[..n]);
            buf[..n].fill(0);
            fed.map_err(|e| match e {
                xfrmd::DumpError::Kernel(errno) => io::Error::from_raw_os_error(errno),
                other => io::Error::new(ErrorKind::InvalidData, format!("netlink dump: {other:?}")),
            })?;
        }
        Ok(parser)
    }
}

#[allow(unsafe_code)]
fn netlink_socket() -> io::Result<OwnedFd> {
    // SAFETY: plain socket(2) with constant arguments; the result is checked before it is owned.
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, xfrmd::NETLINK_XFRM) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh descriptor nobody else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The kernel's address: pid 0, no groups.
fn kernel_address() -> libc::sockaddr_nl {
    let mut a = zeroed_sockaddr_nl();
    a.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    a
}

#[allow(unsafe_code)]
fn zeroed_sockaddr_nl() -> libc::sockaddr_nl {
    // SAFETY: sockaddr_nl is plain old data; all zeroes is a valid value (it has private padding fields).
    unsafe { std::mem::zeroed() }
}

#[allow(unsafe_code)]
fn send_to_kernel(fd: BorrowedFd<'_>, message: &[u8]) -> io::Result<()> {
    let to = kernel_address();
    loop {
        // SAFETY: `message` and `to` are valid for the call, their lengths passed with them.
        let n = unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                message.as_ptr().cast(),
                message.len(),
                0,
                (&raw const to).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        if n as usize != message.len() {
            return Err(io::Error::new(ErrorKind::WriteZero, "netlink request cut short"));
        }
        return Ok(());
    }
}

/// One datagram from the kernel (`nl_pid` 0) within `timeout`; a datagram larger than `buf` is an error, never a
/// cut one; one from another sender is dropped.
#[allow(unsafe_code)]
fn recv_from_kernel(fd: BorrowedFd<'_>, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
    let tv = libc::timeval {
        tv_sec: timeout.as_secs().min(60) as libc::time_t,
        tv_usec: timeout.subsec_micros().max(1) as libc::suseconds_t,
    };
    // SAFETY: `tv` is valid for the call, its size passed with it.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&raw const tv).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    loop {
        let mut from = zeroed_sockaddr_nl();
        let mut from_len = std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        // SAFETY: `buf`, `from` and `from_len` are valid for the call; MSG_TRUNC makes the result the datagram's
        // real length, so a cut datagram is detected below and never parsed.
        let n = unsafe {
            libc::recvfrom(
                fd.as_raw_fd(),
                buf.as_mut_ptr().cast(),
                buf.len(),
                libc::MSG_TRUNC,
                (&raw mut from).cast(),
                &mut from_len,
            )
        };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        let n = n as usize;
        if n > buf.len() {
            buf.fill(0);
            return Err(io::Error::new(ErrorKind::InvalidData, "netlink datagram larger than the buffer"));
        }
        if from_len as usize != std::mem::size_of::<libc::sockaddr_nl>()
            || from.nl_family != libc::AF_NETLINK as libc::sa_family_t
            || from.nl_pid != 0
        {
            buf[..n].fill(0);
            continue;
        }
        return Ok(n);
    }
}

/// The binary's entry: fd 0 must be the accepted `AF_UNIX` stream socket (else exit 2). Exit 0 after an answer,
/// 1 on a failure (no peer credentials: no answer at all).
#[allow(unsafe_code)]
pub fn main() -> i32 {
    // SAFETY: fd 0 is borrowed only for the two getsockopt calls.
    let fd0 = unsafe { BorrowedFd::borrow_raw(0) };
    if let Err(e) = logd::check_unix_stream(fd0) {
        eprintln!("linvpn-xfrmd: stdin is not the accepted socket ({:?})", e.kind());
        return 2;
    }
    // SAFETY: fd 0 is open and a socket (checked above), and nothing else in this process uses it: std's stdin
    // handle is never touched, so the stream becomes its only owner.
    let stream = UnixStream::from(unsafe { OwnedFd::from_raw_fd(0) });
    let uid = match logd::peer_uid(&stream) {
        Ok(uid) => uid,
        Err(e) => {
            eprintln!("linvpn-xfrmd: no peer credentials ({:?})", e.kind());
            return 1;
        }
    };
    let nm: Box<dyn Nm> = match NmBus::system() {
        Ok(nm) => Box::new(nm),
        Err(_) => Box::new(NoNm),
    };
    match serve(stream, uid, nm.as_ref(), &Netlink::default()) {
        Ok(Outcome::Counters) => {
            eprintln!("uid={uid} answer=T");
            0
        }
        Ok(Outcome::Unavailable) => {
            eprintln!("uid={uid} answer=N");
            0
        }
        Err(e) => {
            eprintln!("uid={uid} error={:?}", e.kind());
            1
        }
    }
}

/// No system bus: nothing is authorized (the answer is `N`).
struct NoNm;

impl Nm for NoNm {
    fn actives(&self) -> io::Result<Vec<ActiveFacts>> {
        Err(io::Error::new(ErrorKind::NotConnected, "no system bus"))
    }

    fn profile(&self, _: &str) -> Option<ProfileFacts> {
        None
    }
}
