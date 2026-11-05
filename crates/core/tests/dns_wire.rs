//! The probe's DNS query and answer parser (root layer 15).
use macvpn_core::dns_wire::{Answer, PROBE_NAME, TYPE_A, parse_answer, query};

const ID: u16 = 0xBEEF;

fn q() -> Vec<u8> {
    query(ID, PROBE_NAME, TYPE_A)
}

/// A response header for `q()`: flags byte 1 (`QR` + extra), flags byte 2 (`RA` + rcode), answer count; then the
/// echoed question.
fn resp(f1: u8, f2: u8, ancount: u16) -> Vec<u8> {
    let q = q();
    let mut r = q[0..2].to_vec();
    r.extend_from_slice(&[0x80 | 0x01 | f1, f2]);
    r.extend_from_slice(&[0, 1]);
    r.extend_from_slice(&ancount.to_be_bytes());
    r.extend_from_slice(&[0, 0, 0, 0]);
    r.extend_from_slice(&q[12..]);
    r
}

/// One record: name bytes, type, class IN, TTL 60, rdata.
fn rr(r: &mut Vec<u8>, name: &[u8], t: u16, rdata: &[u8]) {
    r.extend_from_slice(name);
    r.extend_from_slice(&t.to_be_bytes());
    r.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
    r.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    r.extend_from_slice(rdata);
}

#[test]
fn query_bytes_for_apple_com() {
    let mut want = vec![0xBE, 0xEF, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 5];
    want.extend_from_slice(b"apple");
    want.push(3);
    want.extend_from_slice(b"com");
    want.extend_from_slice(&[0, 0, 1, 0, 1]);
    assert_eq!(q(), want);
}

#[test]
fn resolved_with_a_record() {
    let mut r = resp(0, 0x80, 1);
    rr(&mut r, &[0xC0, 0x0C], 1, &[17, 253, 144, 10]);
    assert_eq!(parse_answer(&r, &q()), Answer::Resolved);
    assert!(Answer::Resolved.ok());
}

#[test]
fn resolved_through_cname_compression() {
    let mut r = resp(0, 0x80, 2);
    // apple.com CNAME www.apple.com (www + pointer to offset 12), then www.apple.com A (pointer to the CNAME data).
    let cname_data_at = r.len() + 2 + 10;
    rr(&mut r, &[0xC0, 0x0C], 5, &[3, b'w', b'w', b'w', 0xC0, 0x0C]);
    rr(&mut r, &[0xC0, cname_data_at as u8], 1, &[1, 2, 3, 4]);
    assert_eq!(parse_answer(&r, &q()), Answer::Resolved);
}

#[test]
fn truncated_noerror_counts_as_resolved() {
    assert_eq!(parse_answer(&resp(0x02, 0x80, 0), &q()), Answer::Resolved);
    assert_eq!(parse_answer(&resp(0x02, 0x83, 0), &q()), Answer::NxDomain, "TC does not hide an error");
}

#[test]
fn nxdomain_servfail_refused() {
    assert_eq!(parse_answer(&resp(0, 0x83, 0), &q()), Answer::NxDomain);
    assert_eq!(parse_answer(&resp(0, 0x82, 0), &q()), Answer::ServFail);
    assert_eq!(parse_answer(&resp(0, 0x05, 0), &q()), Answer::Refused);
    assert_eq!(parse_answer(&resp(0, 0x04, 0), &q()), Answer::OtherRcode(4));
    assert!(!Answer::Refused.ok());
}

#[test]
fn noerror_without_answer_and_ra0_is_no_recursion() {
    assert_eq!(parse_answer(&resp(0, 0x00, 0), &q()), Answer::NoRecursion);
    assert_eq!(parse_answer(&resp(0, 0x80, 0), &q()), Answer::Empty);
    // Only a CNAME, no address: not resolved.
    let mut r = resp(0, 0x00, 1);
    rr(&mut r, &[0xC0, 0x0C], 5, &[0xC0, 0x0C]);
    assert_eq!(parse_answer(&r, &q()), Answer::NoRecursion);
}

#[test]
fn wrong_id_is_mismatch() {
    let mut r = resp(0, 0x80, 0);
    r[1] ^= 1;
    assert_eq!(parse_answer(&r, &q()), Answer::Mismatch);
}

#[test]
fn not_a_response_is_malformed() {
    let mut r = resp(0, 0x80, 0);
    r[2] &= 0x7F;
    assert_eq!(parse_answer(&r, &q()), Answer::Malformed);
    let mut r = resp(0, 0x80, 0);
    r[2] |= 0x10; // opcode 2
    assert_eq!(parse_answer(&r, &q()), Answer::Malformed);
    assert_eq!(parse_answer(&[0xBE, 0xEF, 0x81], &q()), Answer::Malformed);
    let mut r = resp(0, 0x80, 0);
    r[5] = 2; // QDCOUNT 2
    assert_eq!(parse_answer(&r, &q()), Answer::Malformed);
}

#[test]
fn question_must_echo() {
    let mut r = resp(0, 0x80, 1);
    r[13] = b'b'; // "bpple"
    rr(&mut r, &[0xC0, 0x0C], 1, &[1, 2, 3, 4]);
    assert_eq!(parse_answer(&r, &q()), Answer::Mismatch);
    let short = &resp(0, 0x80, 0)[..20];
    assert_eq!(parse_answer(short, &q()), Answer::Mismatch);
}

#[test]
fn pointer_loop_is_malformed() {
    // A name of 200 one-byte labels never ends within 128 steps.
    let mut r = resp(0, 0x80, 1);
    let mut name = Vec::new();
    for _ in 0..200 {
        name.extend_from_slice(&[1, b'a']);
    }
    name.push(0);
    rr(&mut r, &name, 1, &[1, 2, 3, 4]);
    assert_eq!(parse_answer(&r, &q()), Answer::Malformed);
    // A reserved label type (0x40) is malformed too.
    let mut r = resp(0, 0x80, 1);
    rr(&mut r, &[0x40, 0], 1, &[1, 2, 3, 4]);
    assert_eq!(parse_answer(&r, &q()), Answer::Malformed);
}

#[test]
fn short_and_overlong_rdata_are_malformed() {
    let mut r = resp(0, 0x80, 1);
    rr(&mut r, &[0xC0, 0x0C], 1, &[1, 2, 3]);
    assert_eq!(parse_answer(&r, &q()), Answer::Malformed, "A with 3 bytes");
    let mut r = resp(0, 0x80, 1);
    rr(&mut r, &[0xC0, 0x0C], 1, &[1, 2, 3, 4]);
    r.truncate(r.len() - 2);
    assert_eq!(parse_answer(&r, &q()), Answer::Malformed, "rdlength beyond the packet");
    let mut r = resp(0, 0x80, 2);
    rr(&mut r, &[0xC0, 0x0C], 1, &[1, 2, 3, 4]);
    assert_eq!(parse_answer(&r, &q()), Answer::Malformed, "ANCOUNT beyond the packet");
}
