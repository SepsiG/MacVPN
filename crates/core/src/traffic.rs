//! The byte counters the privileged side reports for the live traffic (maintainer request 2026-10-29), where the
//! app cannot read them itself:
//!
//! - the WinVPN Service's `traffic <id>` on its pipe: OpenVPN's own management `>BYTECOUNT`, which counts from the
//!   start of the `openvpn` process (a reconnect inside the process keeps counting);
//! - the macOS root layer's `mvpn traffic <id>` (root layer 11): strongSwan's CHILD_SA counters
//!   (`swanctl --list-sas`), one line per CHILD_SA of the connection; a rekey makes a new CHILD_SA with fresh
//!   counters, so the app sums them over their IDs ([`ChildSums`]).
//!
//! ```text
//! bytes <rx> <tx> <run>\n      rx / tx: bytes received / sent; run: the Unix second the openvpn process started
//! strongswan <n>\n             n = 0 … MAX_CHILDREN CHILD_SAs, then n lines:
//! child <id> <rx> <tx>\n       id: charon's unique CHILD_SA number (never an SPI); rx / tx: bytes in / out
//! ```
//!
//! Numbers are ASCII decimal without sign or leading zero (but `0`), at most 20 digits, fitting a `u64`. Anything
//! else, also a longer answer than [`MAX_BYTES`], is refused (`None`). An older service answers its usage error: the
//! app then has no data (never an error).

/// The command on the service's pipe.
pub const TRAFFIC: &str = "traffic";
/// The longest `bytes` answer accepted.
pub const MAX_BYTES: usize = 128;
/// The most CHILD_SAs reported (more are left out).
pub const MAX_CHILDREN: usize = 64;
/// The longest `strongswan` answer accepted.
pub const MAX_CHILDREN_BYTES: usize = 8 * 1024;

/// The counters of one engine run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteCount {
    pub rx: u64,
    pub tx: u64,
    /// The run's start (Unix seconds): another value is another process, whose counters started from zero.
    pub run: u64,
}

fn number(s: &str) -> Option<u64> {
    let ok = !s.is_empty()
        && s.len() <= 20
        && s.bytes().all(|b| b.is_ascii_digit())
        && (s.len() == 1 || !s.starts_with('0'));
    if ok { s.parse().ok() } else { None }
}

impl ByteCount {
    pub fn encode(&self) -> String {
        format!("bytes {} {} {}\n", self.rx, self.tx, self.run)
    }

    /// Exactly the format above.
    pub fn parse(data: &[u8]) -> Option<ByteCount> {
        if data.len() > MAX_BYTES {
            return None;
        }
        let line = std::str::from_utf8(data).ok()?.strip_suffix('\n')?;
        let ["bytes", rx, tx, run] = line.split(' ').collect::<Vec<_>>()[..] else { return None };
        Some(ByteCount { rx: number(rx)?, tx: number(tx)?, run: number(run)? })
    }

    /// OpenVPN's `>BYTECOUNT:<in>,<out>` management line (`\r` allowed at the end); `None` for anything else.
    /// `run`: the process's start.
    pub fn from_management(line: &str, run: u64) -> Option<ByteCount> {
        let rest = line.strip_suffix('\r').unwrap_or(line).strip_prefix(">BYTECOUNT:")?;
        let (rx, tx) = rest.split_once(',')?;
        Some(ByteCount { rx: number(rx)?, tx: number(tx)?, run })
    }
}

/// One CHILD_SA's counters (`mvpn traffic <id>` of a strongSwan connection).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChildCount {
    /// charon's unique CHILD_SA number (a rekey gets a new one).
    pub id: u64,
    pub rx: u64,
    pub tx: u64,
}

/// The `strongswan <n>` answer (at most [`MAX_CHILDREN`] CHILD_SAs).
pub fn encode_children(children: &[ChildCount]) -> String {
    let children = &children[..children.len().min(MAX_CHILDREN)];
    let mut out = format!("strongswan {}\n", children.len());
    for c in children {
        out.push_str(&format!("child {} {} {}\n", c.id, c.rx, c.tx));
    }
    out
}

/// Exactly the `strongswan <n>` format.
pub fn parse_children(data: &[u8]) -> Option<Vec<ChildCount>> {
    if data.len() > MAX_CHILDREN_BYTES {
        return None;
    }
    let body = std::str::from_utf8(data).ok()?.strip_suffix('\n')?;
    let mut lines = body.split('\n');
    let ["strongswan", n] = lines.next()?.split(' ').collect::<Vec<_>>()[..] else { return None };
    let n = usize::try_from(number(n)?).ok().filter(|n| *n <= MAX_CHILDREN)?;
    let mut out = Vec::with_capacity(n);
    for line in lines {
        let ["child", id, rx, tx] = line.split(' ').collect::<Vec<_>>()[..] else { return None };
        out.push(ChildCount { id: number(id)?, rx: number(rx)?, tx: number(tx)? });
    }
    (out.len() == n).then_some(out)
}

/// A connection's traffic summed over its CHILD_SAs: a CHILD_SA seen before adds what it grew by, a new one (or one
/// whose counters went down: charon restarted and reused the number) adds its counters whole, and one that is gone
/// (rekeyed away) keeps what it added. The sums never go down.
#[derive(Debug, Default, Clone)]
pub struct ChildSums {
    seen: std::collections::HashMap<u64, (u64, u64)>,
    rx: u64,
    tx: u64,
}

impl ChildSums {
    /// The sums (received, sent) after this reading.
    pub fn update(&mut self, children: &[ChildCount]) -> (u64, u64) {
        let mut next = std::collections::HashMap::with_capacity(children.len());
        for c in children {
            let (rx, tx) = match self.seen.get(&c.id) {
                Some(&(rx0, tx0)) if c.rx >= rx0 && c.tx >= tx0 => (c.rx - rx0, c.tx - tx0),
                _ => (c.rx, c.tx),
            };
            self.rx = self.rx.saturating_add(rx);
            self.tx = self.tx.saturating_add(tx);
            next.insert(c.id, (c.rx, c.tx));
        }
        self.seen = next;
        (self.rx, self.tx)
    }
}
