//! Asks `linvpn-xfrmd` (`/run/linvpn-xfrmd.sock`) for the IPsec SA byte counters of one of this user's IKEv2
//! connections (charon-nm makes no interface, so there are no sysfs counters).
//!
//! One request, one response per connection (`macvpn_core::xfrmd`'s wire format): the server identifies us by
//! `SO_PEERCRED` and answers only for our own connection. Any failure (no service, a refusal, a timeout, a malformed
//! answer) is `None`: the app then shows no traffic and detects nothing, as before. A reading younger than
//! [`REUSE`] is reused, so a status poll's traffic and liveness questions start one service instance, not two.

use macvpn_core::xfrmd::{Counters, MAX_RESPONSE, Request, Response, Target};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

pub const SOCKET: &str = "/run/linvpn-xfrmd.sock";
/// How long one query may take in all (connect, request, the whole answer).
pub const TIMEOUT: Duration = Duration::from_secs(3);
/// How long a reading is reused.
pub const REUSE: Duration = Duration::from_millis(500);

/// The recent readings: when each request was answered, and with what.
type Recent = HashMap<Request, (Instant, Option<Counters>)>;

/// The installed `linvpn-xfrmd`'s counters of `target`: its socket must be a socket owned by root (systemd made
/// it), else it is not ours.
pub fn counters(target: &Target) -> Option<Counters> {
    static RECENT: Mutex<Option<Recent>> = Mutex::new(None);
    let request = Request { target: target.clone() };
    {
        let mut recent = RECENT.lock().unwrap_or_else(PoisonError::into_inner);
        let map = recent.get_or_insert_with(HashMap::new);
        map.retain(|_, (at, _)| at.elapsed() < REUSE);
        if let Some((_, c)) = map.get(&request) {
            return *c;
        }
    }
    let path = Path::new(SOCKET);
    let c = match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() && m.uid() == 0 => query_within(path, &request, TIMEOUT).ok().flatten(),
        _ => None,
    };
    RECENT
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get_or_insert_with(HashMap::new)
        .insert(request, (Instant::now(), c));
    c
}

/// One query of the server at `socket` within `timeout`: `Ok(None)` for its `N`.
#[doc(hidden)]
pub fn query_within(socket: &Path, request: &Request, timeout: Duration) -> io::Result<Option<Counters>> {
    let deadline = Instant::now() + timeout;
    let left = || {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "linvpn-xfrmd timed out"))
    };
    let mut stream = UnixStream::connect(socket)?;
    stream.set_write_timeout(Some(left()?))?;
    stream.write_all(request.encode().as_bytes())?;
    let _ = stream.shutdown(Shutdown::Write);
    let mut data = Vec::with_capacity(MAX_RESPONSE + 1);
    let mut chunk = [0u8; MAX_RESPONSE + 1];
    loop {
        stream.set_read_timeout(Some(left()?))?;
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                data.extend_from_slice(&chunk[..n]);
                if data.len() > MAX_RESPONSE {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "answer too long"));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    let text = std::str::from_utf8(&data).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "not UTF-8"))?;
    match Response::parse(text) {
        Some(Response::Counters(c)) => Ok(Some(c)),
        Some(Response::Unavailable) => Ok(None),
        None => Err(io::Error::new(io::ErrorKind::InvalidData, "malformed answer")),
    }
}
