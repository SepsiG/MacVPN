//! One DNS query and the reading of its answer, for the root layer's probe "does the VPN's DNS resolve internet
//! names?" (root layer 15): an `A` question for `apple.com` with recursion desired. Pure and bounded: the answer is
//! read, never trusted (the ID and the question must echo ours, every length is checked, compression pointers are
//! skipped, not followed, and a name ends within 128 labels).

/// The public name the probe asks for (maintainer decision: fixed, not configurable).
pub const PROBE_NAME: &str = "apple.com";
pub const TYPE_A: u16 = 1;
const CLASS_IN: u16 = 1;
/// The header's length (RFC 1035 4.1.1).
const HEADER: usize = 12;
/// The most labels (or pointers) a name may take before it counts as malformed (a pointer loop, a crafted packet).
const MAX_LABELS: usize = 128;

/// What one answer says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// At least one `A` record (or `TC` with `NOERROR`: the name exists, the answer did not fit).
    Resolved,
    /// `NOERROR` without an address and without recursion available: a DNS that serves only its own zones.
    NoRecursion,
    /// `NOERROR` without an address, recursion available.
    Empty,
    NxDomain,
    ServFail,
    Refused,
    OtherRcode(u8),
    /// Not the answer to our question (another ID or another question): ignored by the caller.
    Mismatch,
    Malformed,
}

impl Answer {
    pub fn ok(self) -> bool {
        self == Answer::Resolved
    }
}

/// The query bytes: `id`, flags with `RD`, one question `name` / `qtype` / `IN`. `name` is a plain dotted name
/// of short ASCII labels (the probe's own constant).
pub fn query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(18 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]); // RD
    q.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // QDCOUNT 1
    for label in name.split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&CLASS_IN.to_be_bytes());
    q
}

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

/// The index after a (possibly compressed) name; bounded, no pointer is followed (only skipped).
fn skip_name(b: &[u8], mut i: usize) -> Option<usize> {
    for _ in 0..MAX_LABELS {
        let len = *b.get(i)? as usize;
        match len & 0xC0 {
            0x00 if len == 0 => return Some(i + 1),
            0x00 => i += 1 + len,
            0xC0 => {
                b.get(i + 1)?;
                return Some(i + 2);
            }
            _ => return None,
        }
    }
    None
}

/// Reads `resp` as the answer to `query` (the bytes we sent).
pub fn parse_answer(resp: &[u8], query: &[u8]) -> Answer {
    if resp.len() < HEADER || query.len() < HEADER {
        return Answer::Malformed;
    }
    if resp[0..2] != query[0..2] {
        return Answer::Mismatch;
    }
    let (f1, f2) = (resp[2], resp[3]);
    // QR set, opcode QUERY.
    if f1 & 0x80 == 0 || (f1 >> 3) & 0x0F != 0 {
        return Answer::Malformed;
    }
    if u16_at(resp, 4) != Some(1) {
        return Answer::Malformed;
    }
    // The question section must echo ours byte for byte.
    let qend = query.len();
    if resp.get(HEADER..qend) != Some(&query[HEADER..]) {
        return Answer::Mismatch;
    }
    let tc = f1 & 0x02 != 0;
    let ra = f2 & 0x80 != 0;
    match f2 & 0x0F {
        0 => {}
        2 => return Answer::ServFail,
        3 => return Answer::NxDomain,
        5 => return Answer::Refused,
        r => return Answer::OtherRcode(r),
    }
    if tc {
        return Answer::Resolved;
    }
    let Some(ancount) = u16_at(resp, 6) else { return Answer::Malformed };
    let mut i = qend;
    let mut a = 0;
    for _ in 0..ancount {
        let Some(j) = skip_name(resp, i) else { return Answer::Malformed };
        let (Some(t), Some(c), Some(len)) = (u16_at(resp, j), u16_at(resp, j + 2), u16_at(resp, j + 8)) else {
            return Answer::Malformed;
        };
        let end = j + 10 + len as usize;
        if end > resp.len() {
            return Answer::Malformed;
        }
        if t == TYPE_A && c == CLASS_IN {
            if len != 4 {
                return Answer::Malformed;
            }
            a += 1;
        }
        i = end;
    }
    if a > 0 {
        Answer::Resolved
    } else if !ra {
        Answer::NoRecursion
    } else {
        Answer::Empty
    }
}
