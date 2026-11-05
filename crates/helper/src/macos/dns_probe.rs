//! The DNS probe (root layer 15): does the VPN's DNS resolve internet names? One `A` query for `apple.com`
//! (`dns_wire`) to each of at most the first [`MAX_SERVERS`] VPN servers, through the routing table exactly as the
//! resolver's own queries go, until one resolves it. The Automatic mode falls back on the answer (see `dns_plan`).
//!
//! Bounded: one UDP socket per server, `connect()`ed to `<server>:53` so only that peer's datagrams are read, at
//! most 2 sends, [`TIMEOUT`] per send; answers with another ID or another question are ignored until the deadline.
//! No crate is added and nothing is cached. In test mode no socket is ever opened: `MVPN_DNS_PROBE=ok|fail` is the
//! result, and without it the probe is not run.

use crate::macos::dns_plan::Probe;
use crate::macos::paths::Settings;
use macvpn_core::dns_wire::{self, Answer, PROBE_NAME, TYPE_A};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

pub const TIMEOUT: Duration = Duration::from_millis(1500);
/// At most this many servers are asked (macOS's resolver uses the first 3 too).
pub const MAX_SERVERS: usize = 3;
/// Two sends per server: one lost datagram does not count as a broken DNS.
const SENDS: u32 = 2;

/// The answer of one server to the probe; `None`: no usable answer (silent, unreachable, only garbage).
pub fn probe_server(addr: SocketAddr, timeout: Duration) -> Option<Answer> {
    let local: IpAddr = if addr.is_ipv4() { Ipv4Addr::UNSPECIFIED.into() } else { Ipv6Addr::UNSPECIFIED.into() };
    let sock = UdpSocket::bind(SocketAddr::new(local, 0)).ok()?;
    sock.connect(addr).ok()?;
    let id = u16::from_be_bytes(uuid::Uuid::new_v4().as_bytes()[..2].try_into().ok()?);
    let query = dns_wire::query(id, PROBE_NAME, TYPE_A);
    let mut buf = [0u8; 1500];
    for _ in 0..SENDS {
        if sock.send(&query).is_err() {
            return None;
        }
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() || sock.set_read_timeout(Some(left)).is_err() {
                break;
            }
            match sock.recv(&mut buf) {
                Ok(n) => match dns_wire::parse_answer(&buf[..n], &query) {
                    Answer::Mismatch | Answer::Malformed => continue,
                    a => return Some(a),
                },
                // An ICMP unreachable came back: no DNS there.
                Err(e) if e.kind() == ErrorKind::ConnectionRefused => return None,
                Err(_) => break,
            }
        }
    }
    None
}

/// The log word of one server's result.
fn word(a: Option<Answer>) -> String {
    match a {
        None => "no answer".into(),
        Some(Answer::Resolved) => "resolved".into(),
        Some(Answer::NoRecursion) => "no recursion".into(),
        Some(Answer::Empty) => "no address".into(),
        Some(Answer::NxDomain) => "NXDOMAIN".into(),
        Some(Answer::ServFail) => "SERVFAIL".into(),
        Some(Answer::Refused) => "REFUSED".into(),
        Some(Answer::OtherRcode(r)) => format!("rcode {r}"),
        Some(Answer::Mismatch | Answer::Malformed) => "malformed".into(),
    }
}

/// Asks `addrs` in order until one resolves; the result and the log detail (`<server>: <result>; …`).
pub fn probe_addrs(addrs: &[SocketAddr], timeout: Duration) -> (Probe, String) {
    let mut detail = Vec::new();
    for addr in addrs.iter().take(MAX_SERVERS) {
        let a = probe_server(*addr, timeout);
        detail.push(format!("{}: {}", addr.ip(), word(a)));
        if a == Some(Answer::Resolved) {
            return (Probe::Ok, detail.join("; "));
        }
    }
    if detail.is_empty() { (Probe::NotRun, String::new()) } else { (Probe::Failed, detail.join("; ")) }
}

/// The probe of `servers` (the effective VPN servers, IP literals): in test mode only `MVPN_DNS_PROBE` (`ok`,
/// `fail`; `slow-ok` / `slow-fail` take a second, as a real probe takes its time).
pub fn probe(s: &Settings, servers: &[String]) -> (Probe, String) {
    if s.test_mode {
        let mut v = s.dns_probe.as_deref();
        if let Some(rest) = v.and_then(|v| v.strip_prefix("slow-")) {
            std::thread::sleep(Duration::from_secs(1));
            v = Some(rest);
        }
        return match v {
            Some("ok") => (Probe::Ok, "test: ok".into()),
            Some("fail") => (Probe::Failed, "test: fail".into()),
            _ => (Probe::NotRun, String::new()),
        };
    }
    let addrs: Vec<SocketAddr> =
        servers.iter().filter_map(|v| v.parse::<IpAddr>().ok()).map(|ip| SocketAddr::new(ip, 53)).collect();
    probe_addrs(&addrs, TIMEOUT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone, Copy)]
    enum Behaviour {
        /// One A record.
        Resolve,
        /// RCODE 5.
        Refuse,
        /// Never answers.
        Silent,
        /// First an answer with another ID, then the right one.
        WrongIdFirst,
    }

    /// The answer to `q` with `rcode` and, when `a`, one A record.
    fn reply(q: &[u8], rcode: u8, a: bool) -> Vec<u8> {
        let mut r = q[0..2].to_vec();
        r.extend_from_slice(&[0x81, 0x80 | rcode, 0, 1, 0, u8::from(a), 0, 0, 0, 0]);
        r.extend_from_slice(&q[12..]);
        if a {
            r.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 17, 253, 144, 10]);
        }
        r
    }

    /// A fake DNS server on 127.0.0.1; returns its address and the count of queries it got.
    fn server(b: Behaviour) -> (SocketAddr, Arc<AtomicUsize>) {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = sock.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            while let Ok((n, from)) = sock.recv_from(&mut buf) {
                c.fetch_add(1, Ordering::SeqCst);
                let q = &buf[..n];
                let out = match b {
                    Behaviour::Resolve => vec![reply(q, 0, true)],
                    Behaviour::Refuse => vec![reply(q, 5, false)],
                    Behaviour::Silent => vec![],
                    Behaviour::WrongIdFirst => {
                        let mut wrong = reply(q, 0, true);
                        wrong[0] ^= 0xFF;
                        vec![wrong, reply(q, 0, true)]
                    }
                };
                for o in out {
                    let _ = sock.send_to(&o, from);
                }
            }
        });
        (addr, count)
    }

    const T: Duration = Duration::from_millis(300);

    #[test]
    fn resolves_against_a_fake_recursive_server() {
        let (addr, _) = server(Behaviour::Resolve);
        assert_eq!(probe_server(addr, T), Some(Answer::Resolved));
        let (p, detail) = probe_addrs(&[addr], T);
        assert_eq!(p, Probe::Ok);
        assert!(detail.ends_with("resolved"), "{detail}");
    }

    #[test]
    fn refused_server_fails() {
        let (addr, _) = server(Behaviour::Refuse);
        assert_eq!(probe_addrs(&[addr], T).0, Probe::Failed);
    }

    #[test]
    fn silent_server_times_out_within_bound() {
        let (addr, count) = server(Behaviour::Silent);
        let start = Instant::now();
        assert_eq!(probe_server(addr, T), None);
        assert!(start.elapsed() <= 2 * T + Duration::from_millis(500), "{:?}", start.elapsed());
        assert_eq!(count.load(Ordering::SeqCst), 2, "two sends");
    }

    #[test]
    fn wrong_id_is_ignored_then_right_answer_counts() {
        let (addr, _) = server(Behaviour::WrongIdFirst);
        assert_eq!(probe_server(addr, T), Some(Answer::Resolved));
    }

    #[test]
    fn first_good_server_wins_and_at_most_three_are_asked() {
        let (bad1, c1) = server(Behaviour::Refuse);
        let (good, c2) = server(Behaviour::Resolve);
        let (never, c3) = server(Behaviour::Resolve);
        assert_eq!(probe_addrs(&[bad1, good, never], T).0, Probe::Ok);
        assert_eq!(c1.load(Ordering::SeqCst), 1);
        assert_eq!(c2.load(Ordering::SeqCst), 1);
        assert_eq!(c3.load(Ordering::SeqCst), 0, "the first good one wins");
        let refusing: Vec<(SocketAddr, Arc<AtomicUsize>)> = (0..4).map(|_| server(Behaviour::Refuse)).collect();
        let addrs: Vec<SocketAddr> = refusing.iter().map(|(a, _)| *a).collect();
        assert_eq!(probe_addrs(&addrs, T).0, Probe::Failed);
        assert_eq!(refusing[3].1.load(Ordering::SeqCst), 0, "at most three are asked");
        assert_eq!(probe_addrs(&[], T).0, Probe::NotRun);
    }

    #[test]
    fn test_mode_never_opens_a_socket() {
        let mut s = Settings::resolve(true, Default::default(), String::new());
        assert_eq!(probe(&s, &["127.0.0.1".into()]).0, Probe::NotRun);
        s.dns_probe = Some("ok".into());
        assert_eq!(probe(&s, &[]).0, Probe::Ok);
        s.dns_probe = Some("fail".into());
        assert_eq!(probe(&s, &[]).0, Probe::Failed);
    }
}
