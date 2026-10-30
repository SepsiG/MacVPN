//! `linvpn-xfrmd`'s server: one request per connection, the caller's uid from `SO_PEERCRED`, NetworkManager's facts
//! deciding which connection is the caller's before any XFRM dump, two sums out. Against a fake NetworkManager and
//! fake XFRM state, the unprivileged kernel (which refuses the dump) and the binary itself.
#![cfg(target_os = "linux")]

use std::cell::Cell;
use std::io::{ErrorKind, Read, Write};
use std::net::IpAddr;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use macvpn_core::nm_plan::names;
use macvpn_core::xfrmd::{self, ActiveFacts, Policy, ProfileFacts, Request, Response, Sa, Target, Tmpl};
use macvpn_helper::linux::xfrmd::{self as server, Netlink, Nm, Outcome, Xfrm};
use uuid::Uuid;

const ID: &str = "0b5f7c1e-2d3a-4b5c-8d6e-7f8091a2b3c4";
const SYS: &str = "7a5d0e6c-9b8f-4c2e-8db4-5e6f708192a3";
const SWAN: &str = "org.freedesktop.NetworkManager.strongswan";
const INNER: &str = "198.51.100.77";
const GW: &str = "203.0.113.1";
const LOCAL: &str = "198.51.100.20";

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn active(uuid: &str, path: &str) -> ActiveFacts {
    ActiveFacts {
        uuid: uuid.into(),
        connection: path.into(),
        nm_type: "vpn".into(),
        vpn: true,
        state: 2,
        vpn_state: Some(5),
        addresses: vec![ip(INNER)],
    }
}

struct FakeNm {
    actives: Vec<ActiveFacts>,
    /// The profile NM shows for `/profile/system` (others: refused).
    system: Option<ProfileFacts>,
    calls: Cell<usize>,
    fail: bool,
}

impl FakeNm {
    fn own(uid: u32) -> FakeNm {
        let uuid = names::nm_uuid(uid, &Uuid::parse_str(ID).unwrap()).to_string();
        FakeNm { actives: vec![active(&uuid, "/profile/own")], system: None, calls: Cell::new(0), fail: false }
    }
}

impl Nm for FakeNm {
    fn actives(&self) -> std::io::Result<Vec<ActiveFacts>> {
        self.calls.set(self.calls.get() + 1);
        if self.fail { Err(std::io::Error::other("no bus")) } else { Ok(self.actives.clone()) }
    }
    fn profile(&self, path: &str) -> Option<ProfileFacts> {
        (path == "/profile/system").then(|| self.system.clone()).flatten()
    }
}

struct FakeXfrm {
    dumps: Cell<usize>,
    fail: bool,
}

impl FakeXfrm {
    fn new() -> FakeXfrm {
        FakeXfrm { dumps: Cell::new(0), fail: false }
    }
}

impl Xfrm for FakeXfrm {
    fn dump(&self) -> std::io::Result<(Vec<Policy>, Vec<Sa>)> {
        self.dumps.set(self.dumps.get() + 1);
        if self.fail {
            return Err(std::io::Error::from_raw_os_error(libc::EPERM));
        }
        let t = |d: &str| vec![Tmpl { daddr: ip(d), saddr: None, proto: 50, reqid: 7 }];
        Ok((
            vec![
                Policy { dir: 1, src: ip(INNER), prefix_src: 32, dst: ip("0.0.0.0"), prefix_dst: 0, tmpls: t(GW) },
                Policy { dir: 0, src: ip("0.0.0.0"), prefix_src: 0, dst: ip(INNER), prefix_dst: 32, tmpls: t(LOCAL) },
            ],
            vec![
                Sa { daddr: ip(GW), saddr: ip(LOCAL), sel: None, proto: 50, reqid: 7, bytes: 300, packets: 3 },
                Sa { daddr: ip(LOCAL), saddr: ip(GW), sel: None, proto: 50, reqid: 7, bytes: 9000, packets: 9 },
            ],
        ))
    }
}

fn request(target: Target) -> String {
    Request { target }.encode()
}

fn linvpn() -> Target {
    Target::Linvpn(Uuid::parse_str(ID).unwrap())
}

/// Serves `send` (then half-closes) from `uid`; the raw answer and the server's result.
fn exchange(send: &[u8], uid: u32, nm: &FakeNm, xfrm: &FakeXfrm) -> (String, std::io::Result<Outcome>) {
    let (mut client, srv) = UnixStream::pair().unwrap();
    client.write_all(send).unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();
    let result = server::serve(srv, uid, nm, xfrm);
    let mut out = String::new();
    client.read_to_string(&mut out).unwrap();
    (out, result)
}

#[test]
fn the_callers_own_ikev2_connection_gets_its_sa_counters() {
    let (nm, x) = (FakeNm::own(1001), FakeXfrm::new());
    let (out, result) = exchange(request(linvpn()).as_bytes(), 1001, &nm, &x);
    assert_eq!(out, "T 9000 300\n");
    assert_eq!(result.unwrap(), Outcome::Counters);
    assert_eq!(Response::parse(&out), Some(Response::Counters(xfrmd::Counters { rx: 9000, tx: 300 })));
}

#[test]
fn another_uid_gets_nothing_and_no_dump_is_made() {
    let (nm, x) = (FakeNm::own(1001), FakeXfrm::new());
    let (out, result) = exchange(request(linvpn()).as_bytes(), 1002, &nm, &x);
    assert_eq!(out, "N\n");
    assert_eq!(result.unwrap(), Outcome::Unavailable);
    assert_eq!(x.dumps.get(), 0, "the kernel is asked only for an authorized connection");
}

#[test]
fn a_bad_request_gets_n_and_asks_nobody() {
    let valid = request(linvpn());
    let oversized = format!("{}\n", "x".repeat(xfrmd::MAX_REQUEST + 10));
    let mut not_utf8 = valid.clone().into_bytes();
    not_utf8[20] = 0xff;
    for bad in
        [b"".to_vec(), b"hello\n".to_vec(), valid.trim_end().as_bytes().to_vec(), oversized.into_bytes(), not_utf8]
    {
        let (nm, x) = (FakeNm::own(1001), FakeXfrm::new());
        let (out, _) = exchange(&bad, 1001, &nm, &x);
        assert_eq!(out, "N\n", "{bad:?}");
        assert_eq!((nm.calls.get(), x.dumps.get()), (0, 0));
    }
}

#[test]
fn nm_or_kernel_failures_get_n() {
    let mut nm = FakeNm::own(1001);
    nm.fail = true;
    let x = FakeXfrm::new();
    assert_eq!(exchange(request(linvpn()).as_bytes(), 1001, &nm, &x).0, "N\n");
    assert_eq!(x.dumps.get(), 0);
    let nm = FakeNm::own(1001);
    let x = FakeXfrm { dumps: Cell::new(0), fail: true };
    assert_eq!(exchange(request(linvpn()).as_bytes(), 1001, &nm, &x).0, "N\n");
}

#[test]
fn a_system_vpn_counts_only_when_its_profile_is_for_every_user() {
    let target = Target::System(Uuid::parse_str(SYS).unwrap());
    let mut nm = FakeNm {
        actives: vec![active(SYS, "/profile/system")],
        system: Some(ProfileFacts { permissions: vec![], service_type: Some(SWAN.into()) }),
        calls: Cell::new(0),
        fail: false,
    };
    let x = FakeXfrm::new();
    assert_eq!(exchange(request(target.clone()).as_bytes(), 1001, &nm, &x).0, "T 9000 300\n");
    nm.system = Some(ProfileFacts { permissions: vec!["user:alice".into()], service_type: Some(SWAN.into()) });
    assert_eq!(exchange(request(target.clone()).as_bytes(), 1001, &nm, &x).0, "N\n");
    nm.system = None;
    assert_eq!(exchange(request(target).as_bytes(), 1001, &nm, &x).0, "N\n");
    assert_eq!(x.dumps.get(), 1);
}

#[test]
fn a_request_that_never_ends_is_closed_after_the_timeout() {
    let (nm, x) = (FakeNm::own(1001), FakeXfrm::new());
    let (mut client, srv) = UnixStream::pair().unwrap();
    client.write_all(b"linvpn-xfrmd-v1 linvpn").unwrap();
    let start = Instant::now();
    let err = server::serve_within(srv, 1001, &nm, &x, Duration::from_millis(300)).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::TimedOut);
    assert!(start.elapsed() < Duration::from_secs(3));
    let mut out = String::new();
    client.read_to_string(&mut out).unwrap();
    assert_eq!(out, "", "closed unanswered");
}

#[test]
fn without_cap_net_admin_the_kernel_refuses_the_dump() {
    // The tests run unprivileged (the VM's linvpn-dev, CI's runner): the kernel's EPERM must be an error, never an
    // empty dump read as "no SA".
    #[allow(unsafe_code)]
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        return;
    }
    let err = Netlink::default().dump().unwrap_err();
    assert_eq!(err.raw_os_error(), Some(libc::EPERM), "{err:?}");
}

#[test]
#[ignore = "lab: needs CAP_NET_ADMIN (sudo -E) and an IKEv2 tunnel up through charon-nm"]
fn lab_a_real_xfrm_dump_parses() {
    let (policies, sas) = Netlink::default().dump().expect("the dump (run as root)");
    eprintln!("{} policies, {} SAs", policies.len(), sas.len());
    assert!(policies.iter().any(|p| !p.tmpls.is_empty()), "an IKEv2 tunnel's policies with templates");
    assert!(sas.iter().any(|s| s.proto == 50 && s.reqid != 0), "an ESP SA with a reqid");
}

// ---- the binary ----

fn run_binary(stdin: Stdio) -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_linvpn-xfrmd"))
        .stdin(stdin)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

#[test]
fn the_binary_refuses_a_stdin_that_is_not_a_socket() {
    let out = run_binary(Stdio::piped()).wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(run_binary(Stdio::null()).wait_with_output().unwrap().status.code(), Some(2));
}

#[test]
fn the_binary_answers_n_for_a_connection_that_is_not_up() {
    // A random LinVPN id: no active connection of this uid has its derived UUID, so the answer is N whether or not
    // there is a system bus (read-only property reads only), and no netlink dump is made.
    let (mut client, srv) = UnixStream::pair().unwrap();
    let child = run_binary(Stdio::from(OwnedFd::from(srv)));
    client.write_all(request(Target::Linvpn(Uuid::new_v4())).as_bytes()).unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let mut out = String::new();
    client.read_to_string(&mut out).unwrap();
    let done = child.wait_with_output().unwrap();
    assert_eq!(out, "N\n");
    let stderr = String::from_utf8_lossy(&done.stderr);
    assert_eq!(done.status.code(), Some(0), "{stderr}");
    let ours = std::fs::metadata("/proc/self").unwrap().uid();
    assert_eq!(stderr.trim_end(), format!("uid={ours} answer=N"));
}
