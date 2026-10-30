//! linvpn-xfrmd's pure half: the wire format, the XFRM netlink dump parser (fixtures crafted as bytes, with
//! bounds and mutation tests), the SA selection and the authorization against NetworkManager's facts.
use macvpn_core::nm_plan::names;
use macvpn_core::xfrmd::{
    self, ActiveFacts, Counters, DumpError, DumpKind, DumpParser, Policy, ProfileFacts, Request, Response, Sa,
    Selector, Target, Tmpl,
};
use std::net::IpAddr;
use uuid::Uuid;

const ID: &str = "0b5f7c1e-2d3a-4b5c-8d6e-7f8091a2b3c4";
const SYS: &str = "7a5d0e6c-9b8f-4c2e-8db4-5e6f708192a3";
const SWAN: &str = "org.freedesktop.NetworkManager.strongswan";
const SEQ: u32 = 0x4c56_0001;

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

// ---- the wire format ----

#[test]
fn a_request_round_trips_and_strict_parsing_refuses_anything_else() {
    for target in [Target::Linvpn(Uuid::parse_str(ID).unwrap()), Target::System(Uuid::parse_str(SYS).unwrap())] {
        let r = Request { target };
        assert_eq!(Request::parse(&r.encode()), Some(r.clone()));
    }
    assert_eq!(
        Request { target: Target::Linvpn(Uuid::parse_str(ID).unwrap()) }.encode(),
        format!("linvpn-xfrmd-v1 linvpn {ID}\n")
    );
    let long = format!("linvpn-xfrmd-v1 linvpn {ID}{}\n", " ".repeat(200));
    for bad in [
        String::new(),
        "linvpn-xfrmd-v1\n".into(),
        format!("linvpn-xfrmd-v1 linvpn {ID}"),
        format!("linvpn-xfrmd-v2 linvpn {ID}\n"),
        format!("linvpn-xfrmd-v1 other {ID}\n"),
        format!("linvpn-xfrmd-v1 linvpn {}\n", ID.to_uppercase()),
        format!("linvpn-xfrmd-v1 linvpn {}\n", ID.replace('-', "")),
        format!("linvpn-xfrmd-v1  linvpn {ID}\n"),
        format!("linvpn-xfrmd-v1 linvpn {ID} \n"),
        format!("linvpn-xfrmd-v1 linvpn {ID}\n\n"),
        format!("linvpn-xfrmd-v1 linvpn {ID}\r\n"),
        format!("linvpn-xfrmd-v1 system {ID}\nlinvpn-xfrmd-v1 system {SYS}\n"),
        long,
    ] {
        assert_eq!(Request::parse(&bad), None, "{bad:?}");
    }
}

#[test]
fn a_response_round_trips_and_strict_parsing_refuses_anything_else() {
    for r in [
        Response::Counters(Counters { rx: 0, tx: 0 }),
        Response::Counters(Counters { rx: u64::MAX, tx: 7 }),
        Response::Unavailable,
    ] {
        assert_eq!(Response::parse(&r.encode()), Some(r));
    }
    assert_eq!(Response::Counters(Counters { rx: 12, tx: 34 }).encode(), "T 12 34\n");
    assert_eq!(Response::Unavailable.encode(), "N\n");
    for bad in [
        "",
        "N",
        "N\n\n",
        "T 1\n",
        "T 1 2 3\n",
        "T 01 2\n",
        "T -1 2\n",
        "T 1 18446744073709551616\n",
        "T  1 2\n",
        "X\n",
    ] {
        assert_eq!(Response::parse(bad), None, "{bad:?}");
    }
}

// ---- netlink fixtures ----

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const ESP: u8 = 50;

fn nlmsg(kind: u16, flags: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
    let len = 16 + payload.len();
    let mut m = Vec::new();
    m.extend_from_slice(&(len as u32).to_ne_bytes());
    m.extend_from_slice(&kind.to_ne_bytes());
    m.extend_from_slice(&flags.to_ne_bytes());
    m.extend_from_slice(&seq.to_ne_bytes());
    m.extend_from_slice(&4242u32.to_ne_bytes());
    m.extend_from_slice(payload);
    while m.len() % 4 != 0 {
        m.push(0);
    }
    m
}

fn put_addr(buf: &mut [u8], at: usize, a: IpAddr) {
    match a {
        IpAddr::V4(v) => buf[at..at + 4].copy_from_slice(&v.octets()),
        IpAddr::V6(v) => buf[at..at + 16].copy_from_slice(&v.octets()),
    }
}

fn family(a: IpAddr) -> u16 {
    if a.is_ipv4() { AF_INET } else { AF_INET6 }
}

/// `struct xfrm_usersa_info` (224 bytes on 64-bit) with a fake key attribute after it.
fn sa(daddr: &str, proto: u8, reqid: u32, bytes: u64, packets: u64) -> Vec<u8> {
    let d = ip(daddr);
    let mut p = vec![0xEEu8; 224];
    p[..56].fill(0);
    p[56..80].fill(0);
    put_addr(&mut p, 56, d);
    p[80..96].fill(0);
    put_addr(&mut p, 80, if d.is_ipv4() { ip("192.0.2.9") } else { ip("2001:db8::9") });
    p[72..76].copy_from_slice(&0x1234_5678u32.to_be_bytes()); // spi
    p[76] = proto;
    p[160..168].copy_from_slice(&bytes.to_ne_bytes());
    p[168..176].copy_from_slice(&packets.to_ne_bytes());
    p[208..212].copy_from_slice(&reqid.to_ne_bytes());
    p[212..214].copy_from_slice(&family(d).to_ne_bytes());
    // XFRMA_ALG_CRYPT (2) with key-ish bytes: must be skipped, never read.
    let mut attr = Vec::new();
    attr.extend_from_slice(&(4u16 + 68).to_ne_bytes());
    attr.extend_from_slice(&2u16.to_ne_bytes());
    attr.extend_from_slice(&[0xAB; 68]);
    p.extend_from_slice(&attr);
    p
}

/// `struct xfrm_userpolicy_info` (168 bytes) + `XFRMA_TMPL` with `struct xfrm_user_tmpl` (64 bytes each).
fn policy(dir: u8, src: &str, plen_s: u8, dst: &str, plen_d: u8, tmpls: &[(&str, u8, u32)]) -> Vec<u8> {
    let (s, d) = (ip(src), ip(dst));
    let mut p = vec![0u8; 168];
    put_addr(&mut p, 0, d);
    put_addr(&mut p, 16, s);
    p[40..42].copy_from_slice(&family(s).to_ne_bytes());
    p[42] = plen_d;
    p[43] = plen_s;
    p[160] = dir;
    if !tmpls.is_empty() {
        let mut data = Vec::new();
        for (daddr, proto, reqid) in tmpls {
            let mut t = vec![0u8; 64];
            let a = ip(daddr);
            put_addr(&mut t, 0, a);
            t[20] = *proto;
            t[24..26].copy_from_slice(&family(a).to_ne_bytes());
            t[44..48].copy_from_slice(&reqid.to_ne_bytes());
            t[48] = 1; // tunnel
            data.extend_from_slice(&t);
        }
        p.extend_from_slice(&(4 + data.len() as u16).to_ne_bytes());
        p.extend_from_slice(&5u16.to_ne_bytes());
        p.extend_from_slice(&data);
    }
    p
}

fn done(seq: u32) -> Vec<u8> {
    nlmsg(3, 2, seq, &0i32.to_ne_bytes())
}

fn sa_dump() -> Vec<u8> {
    let mut d = nlmsg(16, 2, SEQ, &sa("203.0.113.1", ESP, 7, 1000, 10));
    d.extend(nlmsg(16, 2, SEQ, &sa("198.51.100.20", ESP, 7, 5000, 50)));
    d.extend(nlmsg(16, 2, SEQ, &sa("2001:db8::1", ESP, 9, 3, 1)));
    d.extend(done(SEQ));
    d
}

fn parse(kind: DumpKind, datagrams: &[&[u8]]) -> Result<DumpParser, DumpError> {
    let mut p = DumpParser::new(kind, SEQ);
    for d in datagrams {
        p.feed(d)?;
    }
    Ok(p)
}

#[test]
fn the_dump_request_is_a_bare_header() {
    let r = xfrmd::dump_request(DumpKind::Sas, SEQ);
    assert_eq!(r.len(), 16);
    assert_eq!(u32::from_ne_bytes(r[0..4].try_into().unwrap()), 16);
    assert_eq!(u16::from_ne_bytes(r[4..6].try_into().unwrap()), 18, "XFRM_MSG_GETSA");
    assert_eq!(u16::from_ne_bytes(r[6..8].try_into().unwrap()), 0x301, "NLM_F_REQUEST | NLM_F_DUMP");
    assert_eq!(u32::from_ne_bytes(r[8..12].try_into().unwrap()), SEQ);
    assert_eq!(u16::from_ne_bytes(xfrmd::dump_request(DumpKind::Policies, 1)[4..6].try_into().unwrap()), 21);
}

#[test]
fn an_sa_dump_parses_into_counts_without_keys() {
    let p = parse(DumpKind::Sas, &[&sa_dump()]).unwrap();
    assert!(p.is_done());
    assert_eq!(
        p.sas(),
        &[
            Sa {
                daddr: ip("203.0.113.1"),
                saddr: ip("192.0.2.9"),
                sel: None,
                proto: ESP,
                reqid: 7,
                bytes: 1000,
                packets: 10
            },
            Sa {
                daddr: ip("198.51.100.20"),
                saddr: ip("192.0.2.9"),
                sel: None,
                proto: ESP,
                reqid: 7,
                bytes: 5000,
                packets: 50
            },
            Sa {
                daddr: ip("2001:db8::1"),
                saddr: ip("2001:db8::9"),
                sel: None,
                proto: ESP,
                reqid: 9,
                bytes: 3,
                packets: 1
            },
        ]
    );
}

#[test]
fn a_dump_may_come_in_several_datagrams_and_ends_at_done() {
    let a = nlmsg(16, 2, SEQ, &sa("203.0.113.1", ESP, 7, 1, 1));
    let b = [nlmsg(16, 2, SEQ, &sa("203.0.113.2", ESP, 7, 2, 1)), done(SEQ)].concat();
    let mut p = DumpParser::new(DumpKind::Sas, SEQ);
    p.feed(&a).unwrap();
    assert!(!p.is_done());
    p.feed(&b).unwrap();
    assert!(p.is_done());
    assert_eq!(p.sas().len(), 2);
    // Nothing after the end counts.
    p.feed(&nlmsg(16, 2, SEQ, &sa("203.0.113.3", ESP, 7, 3, 1))).unwrap();
    assert_eq!(p.sas().len(), 2);
}

#[test]
fn a_policy_dump_parses_selectors_and_templates() {
    let d = [
        nlmsg(19, 2, SEQ, &policy(1, "198.51.100.77", 32, "0.0.0.0", 0, &[("203.0.113.1", ESP, 7)])),
        nlmsg(19, 2, SEQ, &policy(0, "0.0.0.0", 0, "198.51.100.77", 32, &[("198.51.100.20", ESP, 7)])),
        nlmsg(19, 2, SEQ, &policy(3, "0.0.0.0", 0, "0.0.0.0", 0, &[])),
        done(SEQ),
    ]
    .concat();
    let p = parse(DumpKind::Policies, &[&d]).unwrap();
    assert_eq!(
        p.policies()[0],
        Policy {
            dir: 1,
            src: ip("198.51.100.77"),
            prefix_src: 32,
            dst: ip("0.0.0.0"),
            prefix_dst: 0,
            tmpls: vec![Tmpl { daddr: ip("203.0.113.1"), saddr: None, proto: ESP, reqid: 7 }],
        }
    );
    assert_eq!(p.policies()[1].dir, 0);
    assert!(p.policies()[2].tmpls.is_empty());
}

#[test]
fn kernel_errors_and_foreign_messages_fail_the_dump() {
    let eperm = nlmsg(2, 0, SEQ, &[(-1i32).to_ne_bytes().as_slice(), &[0u8; 16]].concat());
    assert_eq!(parse(DumpKind::Sas, &[&eperm]).err(), Some(DumpError::Kernel(1)));
    let done_err = nlmsg(3, 2, SEQ, &(-105i32).to_ne_bytes());
    assert_eq!(parse(DumpKind::Sas, &[&done_err]).err(), Some(DumpError::Kernel(105)));
    let ack = nlmsg(2, 0, SEQ, &[0i32.to_ne_bytes().as_slice(), &[0u8; 16]].concat());
    assert!(parse(DumpKind::Sas, &[&ack]).is_err());
    let other_seq = nlmsg(16, 2, SEQ + 1, &sa("203.0.113.1", ESP, 7, 1, 1));
    assert_eq!(parse(DumpKind::Sas, &[&other_seq]).err(), Some(DumpError::Malformed));
    let policy_in_sa_dump = nlmsg(19, 2, SEQ, &policy(1, "203.0.113.51", 32, "0.0.0.0", 0, &[]));
    assert_eq!(parse(DumpKind::Sas, &[&policy_in_sa_dump]).err(), Some(DumpError::Malformed));
}

#[test]
fn malformed_lengths_are_refused() {
    let good = nlmsg(16, 2, SEQ, &sa("203.0.113.1", ESP, 7, 1, 1));
    // A header shorter than 16, a length below the header, beyond the datagram, an SA shorter than its struct.
    assert!(parse(DumpKind::Sas, &[&good[..10]]).is_err());
    let mut small = good.clone();
    small[0..4].copy_from_slice(&8u32.to_ne_bytes());
    assert!(parse(DumpKind::Sas, &[&small]).is_err());
    let mut long = good.clone();
    long[0..4].copy_from_slice(&(good.len() as u32 + 4).to_ne_bytes());
    assert!(parse(DumpKind::Sas, &[&long]).is_err());
    let short_sa = nlmsg(16, 2, SEQ, &sa("203.0.113.1", ESP, 7, 1, 1)[..200]);
    assert!(parse(DumpKind::Sas, &[&short_sa]).is_err());
    // A template attribute that is not whole templates, an attribute shorter than its header or past the message.
    let mut p = policy(1, "203.0.113.51", 32, "0.0.0.0", 0, &[("203.0.113.1", ESP, 7)]);
    p[168..170].copy_from_slice(&(4u16 + 60).to_ne_bytes());
    assert!(parse(DumpKind::Policies, &[&nlmsg(19, 2, SEQ, &p)]).is_err());
    p[168..170].copy_from_slice(&2u16.to_ne_bytes());
    assert!(parse(DumpKind::Policies, &[&nlmsg(19, 2, SEQ, &p)]).is_err());
    p[168..170].copy_from_slice(&(4u16 + 128).to_ne_bytes());
    assert!(parse(DumpKind::Policies, &[&nlmsg(19, 2, SEQ, &p)]).is_err());
}

#[test]
fn unknown_address_families_are_skipped_not_misread() {
    let mut s = sa("203.0.113.1", ESP, 7, 1, 1);
    s[212..214].copy_from_slice(&17u16.to_ne_bytes());
    let p = parse(DumpKind::Sas, &[&[nlmsg(16, 2, SEQ, &s), done(SEQ)].concat()]).unwrap();
    assert!(p.is_done() && p.sas().is_empty());
}

#[test]
fn too_many_entries_fail_the_dump() {
    let one = nlmsg(16, 2, SEQ, &sa("203.0.113.1", ESP, 7, 1, 1));
    let mut p = DumpParser::new(DumpKind::Sas, SEQ);
    let mut result = Ok(());
    for _ in 0..=xfrmd::MAX_ENTRIES {
        result = p.feed(&one);
        if result.is_err() {
            break;
        }
    }
    assert_eq!(result, Err(DumpError::TooLarge));
}

/// xorshift64*: deterministic, no dependency.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

#[test]
fn truncated_and_mutated_dumps_never_panic() {
    let pol = [
        nlmsg(
            19,
            2,
            SEQ,
            &policy(1, "198.51.100.77", 32, "0.0.0.0", 0, &[("203.0.113.1", ESP, 7), ("203.0.113.9", ESP, 8)]),
        ),
        done(SEQ),
    ]
    .concat();
    let sas = sa_dump();
    for (kind, base) in [(DumpKind::Sas, &sas), (DumpKind::Policies, &pol)] {
        for cut in 0..base.len() {
            let _ = parse(kind, &[&base[..cut]]);
        }
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        for _ in 0..20_000 {
            let mut m = base.clone();
            for _ in 0..1 + rng.next() % 6 {
                let at = (rng.next() as usize) % m.len();
                m[at] = rng.next() as u8;
            }
            let cut = (rng.next() as usize) % (m.len() + 1);
            let _ = parse(kind, &[&m[..cut], &m[cut..]]);
        }
    }
}

// ---- which SAs are the connection's ----

const INNER: &str = "198.51.100.77";
const GW: &str = "203.0.113.1";
const LOCAL: &str = "198.51.100.20";

fn own_policies() -> Vec<Policy> {
    let t = |d: &str, reqid| vec![Tmpl { daddr: ip(d), saddr: None, proto: ESP, reqid }];
    vec![
        Policy { dir: 1, src: ip(INNER), prefix_src: 32, dst: ip("0.0.0.0"), prefix_dst: 0, tmpls: t(GW, 7) },
        Policy { dir: 0, src: ip("0.0.0.0"), prefix_src: 0, dst: ip(INNER), prefix_dst: 32, tmpls: t(LOCAL, 7) },
        Policy { dir: 2, src: ip("0.0.0.0"), prefix_src: 0, dst: ip(INNER), prefix_dst: 32, tmpls: t(LOCAL, 7) },
        // Another tunnel on the machine (another user's, or another connection).
        Policy { dir: 1, src: ip("198.51.100.78"), prefix_src: 32, dst: ip("0.0.0.0"), prefix_dst: 0, tmpls: t(GW, 8) },
        Policy {
            dir: 0,
            src: ip("0.0.0.0"),
            prefix_src: 0,
            dst: ip("198.51.100.78"),
            prefix_dst: 32,
            tmpls: t(LOCAL, 8),
        },
    ]
}

fn own_sas() -> Vec<Sa> {
    vec![
        Sa { daddr: ip(GW), saddr: ip(LOCAL), sel: None, proto: ESP, reqid: 7, bytes: 300, packets: 3 },
        Sa { daddr: ip(LOCAL), saddr: ip(GW), sel: None, proto: ESP, reqid: 7, bytes: 9000, packets: 9 },
        Sa { daddr: ip(GW), saddr: ip(LOCAL), sel: None, proto: ESP, reqid: 8, bytes: 1, packets: 1 },
        Sa { daddr: ip(LOCAL), saddr: ip(GW), sel: None, proto: ESP, reqid: 8, bytes: 2, packets: 1 },
    ]
}

#[test]
fn the_connections_sas_are_found_through_its_policies_and_summed_per_direction() {
    let c = xfrmd::counters(&[ip(INNER)], &own_policies(), &own_sas());
    assert_eq!(c, Some(Counters { rx: 9000, tx: 300 }));
    // A rekey's overlap: both SAs of a direction count.
    let mut sas = own_sas();
    sas.push(Sa { daddr: ip(GW), saddr: ip(LOCAL), sel: None, proto: ESP, reqid: 7, bytes: 5, packets: 1 });
    sas.push(Sa { daddr: ip(LOCAL), saddr: ip(GW), sel: None, proto: ESP, reqid: 7, bytes: 6, packets: 1 });
    assert_eq!(xfrmd::counters(&[ip(INNER)], &own_policies(), &sas), Some(Counters { rx: 9006, tx: 305 }));
}

#[test]
fn nothing_is_returned_without_policies_or_without_both_directions() {
    assert_eq!(xfrmd::counters(&[ip("198.51.100.99")], &own_policies(), &own_sas()), None);
    assert_eq!(xfrmd::counters(&[], &own_policies(), &own_sas()), None);
    let sas: Vec<Sa> = own_sas().into_iter().filter(|s| s.daddr != ip(LOCAL)).collect();
    assert_eq!(xfrmd::counters(&[ip(INNER)], &own_policies(), &sas), None, "no inbound SA");
    assert_eq!(xfrmd::counters(&[ip(INNER)], &own_policies(), &[]), None);
}

#[test]
fn wide_selectors_zero_reqids_and_other_protocols_do_not_match() {
    let wide = |prefix| {
        vec![
            Policy {
                dir: 1,
                src: ip(INNER),
                prefix_src: prefix,
                dst: ip("0.0.0.0"),
                prefix_dst: 0,
                tmpls: vec![Tmpl { daddr: ip(GW), saddr: None, proto: ESP, reqid: 7 }],
            },
            Policy {
                dir: 0,
                src: ip("0.0.0.0"),
                prefix_src: 0,
                dst: ip(INNER),
                prefix_dst: prefix,
                tmpls: vec![Tmpl { daddr: ip(LOCAL), saddr: None, proto: ESP, reqid: 7 }],
            },
        ]
    };
    assert_eq!(xfrmd::counters(&[ip(INNER)], &wide(24), &own_sas()), None, "a /24 selector is not the address");
    assert!(xfrmd::counters(&[ip(INNER)], &wide(32), &own_sas()).is_some());
    let zero: Vec<Policy> = own_policies()
        .into_iter()
        .map(|mut p| {
            p.tmpls.iter_mut().for_each(|t| t.reqid = 0);
            p
        })
        .collect();
    assert_eq!(xfrmd::counters(&[ip(INNER)], &zero, &own_sas()), None, "reqid 0 matches any SA: never");
    let ipcomp: Vec<Sa> = own_sas().into_iter().map(|s| Sa { proto: 108, ..s }).collect();
    assert_eq!(xfrmd::counters(&[ip(INNER)], &own_policies(), &ipcomp), None);
}

#[test]
fn ipv6_inner_addresses_work_and_counts_saturate() {
    let inner = ip("fd00:99::2");
    let t = |d: &str| vec![Tmpl { daddr: ip(d), saddr: None, proto: ESP, reqid: 3 }];
    let pols = vec![
        Policy { dir: 1, src: inner, prefix_src: 128, dst: ip("::"), prefix_dst: 0, tmpls: t(GW) },
        Policy { dir: 0, src: ip("::"), prefix_src: 0, dst: inner, prefix_dst: 128, tmpls: t(LOCAL) },
    ];
    let sas = vec![
        Sa { daddr: ip(GW), saddr: ip(LOCAL), sel: None, proto: ESP, reqid: 3, bytes: u64::MAX, packets: 1 },
        Sa { daddr: ip(GW), saddr: ip(LOCAL), sel: None, proto: ESP, reqid: 3, bytes: 5, packets: 1 },
        Sa { daddr: ip(LOCAL), saddr: ip(GW), sel: None, proto: ESP, reqid: 3, bytes: 1, packets: 1 },
    ];
    assert_eq!(xfrmd::counters(&[inner], &pols, &sas), Some(Counters { rx: 1, tx: u64::MAX }));
}

/// Outbound/inbound policies of `inner` whose templates name both outer addresses.
fn tunnel(inner: &str, reqid: u32) -> Vec<Policy> {
    let t = |s: &str, d: &str| vec![Tmpl { daddr: ip(d), saddr: Some(ip(s)), proto: ESP, reqid }];
    vec![
        Policy { dir: 1, src: ip(inner), prefix_src: 32, dst: ip("0.0.0.0"), prefix_dst: 0, tmpls: t(LOCAL, GW) },
        Policy { dir: 0, src: ip("0.0.0.0"), prefix_src: 0, dst: ip(inner), prefix_dst: 32, tmpls: t(GW, LOCAL) },
        Policy { dir: 2, src: ip("0.0.0.0"), prefix_src: 0, dst: ip(inner), prefix_dst: 32, tmpls: t(GW, LOCAL) },
    ]
}

fn esp(saddr: &str, daddr: &str, reqid: u32, bytes: u64) -> Sa {
    Sa { daddr: ip(daddr), saddr: ip(saddr), sel: None, proto: ESP, reqid, bytes, packets: 1 }
}

#[test]
fn the_sas_outer_source_must_be_the_templates() {
    let sas = vec![esp(LOCAL, GW, 7, 300), esp(GW, LOCAL, 7, 9000), esp("198.51.100.30", GW, 7, 55)];
    assert_eq!(
        xfrmd::counters(&[ip(INNER)], &tunnel(INNER, 7), &sas),
        Some(Counters { rx: 9000, tx: 300 }),
        "an SA from another local address with the same reqid toward the same gateway is not the connection's"
    );
}

#[test]
fn an_sas_own_selector_must_be_the_connections_address() {
    let mut sas = vec![esp(LOCAL, GW, 7, 300), esp(GW, LOCAL, 7, 9000)];
    let other = Selector { src: ip("100.64.0.5"), prefix_src: 32, dst: ip("0.0.0.0"), prefix_dst: 0 };
    sas.push(Sa { sel: Some(other), ..esp(LOCAL, GW, 7, 4000) });
    let own = Selector { src: ip(INNER), prefix_src: 32, dst: ip("0.0.0.0"), prefix_dst: 0 };
    sas.push(Sa { sel: Some(own), ..esp(LOCAL, GW, 7, 5) });
    assert_eq!(xfrmd::counters(&[ip(INNER)], &tunnel(INNER, 7), &sas), Some(Counters { rx: 9000, tx: 305 }));
}

#[test]
fn another_daemons_tunnel_with_the_same_reqid_gateway_and_source_counts_nothing() {
    // The system's charon and charon-nm both number from reqid 1: same reqid, same gateway, same local address.
    let mut policies = tunnel(INNER, 1);
    policies.extend(tunnel("100.64.0.5", 1));
    let sas = vec![esp(LOCAL, GW, 1, 300), esp(GW, LOCAL, 1, 9000), esp(LOCAL, GW, 1, 7), esp(GW, LOCAL, 1, 8)];
    assert_eq!(xfrmd::counters(&[ip(INNER)], &policies, &sas), None, "the SAs cannot be told apart: nothing");
    // A different reqid on the other tunnel: no ambiguity.
    let mut policies = tunnel(INNER, 1);
    policies.extend(tunnel("100.64.0.5", 2));
    let sas = vec![esp(LOCAL, GW, 1, 300), esp(GW, LOCAL, 1, 9000), esp(LOCAL, GW, 2, 7), esp(GW, LOCAL, 2, 8)];
    assert_eq!(xfrmd::counters(&[ip(INNER)], &policies, &sas), Some(Counters { rx: 9000, tx: 300 }));
}

#[test]
fn an_sas_selector_and_a_templates_source_are_parsed() {
    let mut raw = sa("203.0.113.1", ESP, 7, 1, 1);
    put_addr(&mut raw, 16, ip("100.64.0.5"));
    raw[40..42].copy_from_slice(&AF_INET.to_ne_bytes());
    raw[43] = 32;
    let p = parse(DumpKind::Sas, &[&[nlmsg(16, 2, SEQ, &raw), done(SEQ)].concat()]).unwrap();
    assert_eq!(
        p.sas()[0].sel,
        Some(Selector { src: ip("100.64.0.5"), prefix_src: 32, dst: ip("0.0.0.0"), prefix_dst: 0 })
    );
    assert_eq!(p.sas()[0].saddr, ip("192.0.2.9"));
    let mut pol = policy(1, "198.51.100.77", 32, "0.0.0.0", 0, &[("203.0.113.1", ESP, 7)]);
    put_addr(&mut pol, 168 + 4 + 28, ip(LOCAL));
    let p = parse(DumpKind::Policies, &[&[nlmsg(19, 2, SEQ, &pol), done(SEQ)].concat()]).unwrap();
    assert_eq!(p.policies()[0].tmpls[0].saddr, Some(ip(LOCAL)));
}

// ---- authorization ----

fn active(uuid: &str, addrs: &[&str]) -> ActiveFacts {
    ActiveFacts {
        uuid: uuid.into(),
        connection: format!("/org/freedesktop/NetworkManager/Settings/{}", &uuid[..4]),
        nm_type: "vpn".into(),
        vpn: true,
        state: 2,
        vpn_state: Some(5),
        addresses: addrs.iter().map(|a| ip(a)).collect(),
    }
}

fn own_uuid(uid: u32) -> String {
    names::nm_uuid(uid, &Uuid::parse_str(ID).unwrap()).to_string()
}

fn linvpn() -> Target {
    Target::Linvpn(Uuid::parse_str(ID).unwrap())
}

fn system() -> Target {
    Target::System(Uuid::parse_str(SYS).unwrap())
}

fn no_profile(_: &str) -> Option<ProfileFacts> {
    None
}

#[test]
fn a_users_own_linvpn_connection_is_found_by_its_derived_uuid() {
    let actives = vec![active(&own_uuid(1000), &[INNER]), active(&own_uuid(1001), &["198.51.100.78"])];
    assert_eq!(xfrmd::authorize(&linvpn(), 1000, &actives, &no_profile), Some(vec![ip(INNER)]));
    assert_eq!(xfrmd::authorize(&linvpn(), 1001, &actives, &no_profile), Some(vec![ip("198.51.100.78")]));
    // Another uid derives another UUID: nothing.
    assert_eq!(xfrmd::authorize(&linvpn(), 1002, &actives, &no_profile), None);
}

#[test]
fn only_an_activated_vpn_with_an_address_counts() {
    let uuid = own_uuid(1000);
    for change in [
        (|a: &mut ActiveFacts| a.state = 1) as fn(&mut ActiveFacts),
        |a| a.vpn_state = Some(4),
        |a| a.vpn_state = None,
        |a| a.vpn = false,
        |a| a.nm_type = "wireguard".into(),
        |a| a.addresses.clear(),
    ] {
        let mut a = active(&uuid, &[INNER]);
        change(&mut a);
        assert_eq!(xfrmd::authorize(&linvpn(), 1000, &[a], &no_profile), None);
    }
}

#[test]
fn an_address_another_active_connection_also_holds_is_refused() {
    let actives = vec![active(&own_uuid(1000), &[INNER]), active(SYS, &["203.0.113.50", INNER])];
    assert_eq!(xfrmd::authorize(&linvpn(), 1000, &actives, &no_profile), None);
    // A re-activation of the same profile overlapping briefly is the same connection.
    let actives = vec![active(&own_uuid(1000), &[INNER]), active(&own_uuid(1000), &[INNER])];
    assert_eq!(xfrmd::authorize(&linvpn(), 1000, &actives, &no_profile), Some(vec![ip(INNER)]));
}

/// charon-nm installs the virtual IP on `lo`, and NM 1.54 manages `lo` as an active connection of type `loopback`
/// whose `Ip4Config` then shows it too (L-b lab, 2026-10-30): that is the same address on the host, not another
/// tunnel holding it. Another device's connection or another VPN holding it still makes it ambiguous.
#[test]
fn the_virtual_ip_on_nms_loopback_connection_is_not_another_holder() {
    let mut lo = active("75c578b6-9706-4175-a370-b06a4c6a29ab", &[INNER, "127.0.0.1"]);
    (lo.nm_type, lo.vpn, lo.vpn_state) = ("loopback".into(), false, None);
    let actives = vec![active(&own_uuid(1000), &[INNER]), lo.clone()];
    assert_eq!(xfrmd::authorize(&linvpn(), 1000, &actives, &no_profile), Some(vec![ip(INNER)]));
    let mut eth = lo;
    eth.nm_type = "802-3-ethernet".into();
    let actives = vec![active(&own_uuid(1000), &[INNER]), eth];
    assert_eq!(xfrmd::authorize(&linvpn(), 1000, &actives, &no_profile), None);
}

#[test]
fn a_system_vpn_counts_only_when_it_is_a_strongswan_profile_for_every_user() {
    let actives = vec![active(SYS, &[INNER])];
    let profile = |perms: &'static [&'static str], service: &'static str| {
        move |_: &str| {
            Some(ProfileFacts {
                permissions: perms.iter().map(|p| p.to_string()).collect(),
                service_type: Some(service.into()),
            })
        }
    };
    assert_eq!(xfrmd::authorize(&system(), 1000, &actives, &profile(&[], SWAN)), Some(vec![ip(INNER)]));
    // Restricted to users: the service cannot see whose; refused.
    assert_eq!(xfrmd::authorize(&system(), 1000, &actives, &profile(&["user:alice"], SWAN)), None);
    assert_eq!(
        xfrmd::authorize(&system(), 1000, &actives, &profile(&[], "org.freedesktop.NetworkManager.openvpn")),
        None
    );
    // NM refused to show the profile (it belongs to other users): refused.
    assert_eq!(xfrmd::authorize(&system(), 1000, &actives, &no_profile), None);
    // A LinVPN connection is never reached as a "system" one: its profile is never readable by the service.
    assert_eq!(
        xfrmd::authorize(
            &Target::System(Uuid::parse_str(&own_uuid(1000)).unwrap()),
            1001,
            &[active(&own_uuid(1000), &[INNER])],
            &no_profile
        ),
        None
    );
}
