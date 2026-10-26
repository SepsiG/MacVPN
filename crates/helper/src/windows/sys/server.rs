//! The accept loop of the service's pipe: one thread per client, which first identifies its client (a client that
//! opened without SQOS gets up to 2 s to write, `pipe::FIRST_WRITE_WAIT`): the loop itself never waits for a client,
//! so a silent one cannot hold up other users' requests (security review L-4). At most [`MAX_UNIDENTIFIED`]
//! clients are being identified at a time; more are closed at once. A client whose identity cannot be read is
//! closed unanswered (fail closed). Each client sends one request within [`REQUEST_TIMEOUT`] (in total, not per
//! read) and gets one answer; at most [`MAX_IN_FLIGHT_PER_SID`] requests of one user are handled at a time.

use crate::shared::l10n::tr;
use crate::windows::service::{Caller, Host, Service};
use macvpn_core::service_proto::{self as proto, ProtoError, Response};
use macvpn_winsys::pipe::{Listener, PipeStream};
use std::collections::HashMap;
use std::io::{self, Read};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_IN_FLIGHT_PER_SID: usize = 8;
/// Clients connected but not identified yet, across all users.
pub const MAX_UNIDENTIFIED: usize = 16;

type InFlight = Arc<Mutex<HashMap<String, usize>>>;

/// One place among the clients being identified, given back on drop.
struct Unidentified(Arc<AtomicUsize>);

impl Unidentified {
    fn take(count: &Arc<AtomicUsize>) -> Option<Unidentified> {
        let mut n = count.load(Ordering::SeqCst);
        loop {
            if n >= MAX_UNIDENTIFIED {
                return None;
            }
            match count.compare_exchange(n, n + 1, Ordering::SeqCst, Ordering::SeqCst) {
                Ok(_) => return Some(Unidentified(count.clone())),
                Err(now) => n = now,
            }
        }
    }
}

impl Drop for Unidentified {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Serves until `stop` is set (checked every 250 ms). `log` gets fixed texts and error kinds only.
pub fn serve<H: Host + 'static>(
    listener: Listener,
    service: Arc<Service<H>>,
    stop: &AtomicBool,
    log: impl Fn(&str) + Send + Sync + 'static,
) {
    let in_flight: InFlight = Arc::default();
    let unidentified = Arc::new(AtomicUsize::new(0));
    let log = Arc::new(log);
    while !stop.load(Ordering::SeqCst) {
        match listener.accept_unidentified(Duration::from_millis(250)) {
            Ok(None) => {}
            Ok(Some(stream)) => {
                // Too many clients not identified yet: closed unanswered.
                let Some(place) = Unidentified::take(&unidentified) else {
                    drop(stream);
                    continue;
                };
                let (service, in_flight, thread_log) = (service.clone(), in_flight.clone(), log.clone());
                let spawned = std::thread::Builder::new().name("winvpn-request".into()).spawn(move || {
                    let peer = stream.identify();
                    drop(place);
                    match peer {
                        Ok(peer) => handle(stream, peer.sid.to_string(), &service, &in_flight, &*thread_log),
                        // Not identifiable (anonymous impersonation only, silent, or gone): closed unanswered.
                        Err(_) => drop(stream),
                    }
                });
                if spawned.is_err() {
                    log("cannot start a request thread");
                }
            }
            Err(e) => {
                log(&format!("accept failed: {:?}", e.kind()));
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

/// One request slot of a SID, given back on drop (also if the handler panics).
struct Slot<'a> {
    map: &'a Mutex<HashMap<String, usize>>,
    sid: &'a str,
}

impl<'a> Slot<'a> {
    fn take(map: &'a Mutex<HashMap<String, usize>>, sid: &'a str) -> Option<Slot<'a>> {
        let mut m = map.lock().unwrap_or_else(PoisonError::into_inner);
        let n = m.entry(sid.to_string()).or_default();
        if *n >= MAX_IN_FLIGHT_PER_SID {
            return None;
        }
        *n += 1;
        Some(Slot { map, sid })
    }
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        let mut m = self.map.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(n) = m.get_mut(self.sid) {
            *n -= 1;
            if *n == 0 {
                m.remove(self.sid);
            }
        }
    }
}

/// Reads from the pipe until a fixed instant: each read waits only for the time left.
struct Deadline<'a> {
    stream: &'a PipeStream,
    until: Instant,
}

impl Read for Deadline<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::from(io::ErrorKind::TimedOut));
        }
        self.stream.set_read_timeout(Some(left))?;
        self.stream.read_some(buf)
    }
}

fn handle<H: Host>(
    mut stream: PipeStream,
    sid: String,
    service: &Service<H>,
    in_flight: &Mutex<HashMap<String, usize>>,
    log: &dyn Fn(&str),
) {
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    let Some(_slot) = Slot::take(in_flight, &sid) else {
        let _ = proto::write_response(&mut stream, &Response::fail(1, &tr("Too many requests", &[])));
        return;
    };
    let read = proto::read_request(&mut Deadline { stream: &stream, until: Instant::now() + REQUEST_TIMEOUT });
    let answer = match read {
        // The request, with its secrets, is dropped (zeroed) at the end of this arm, before the answer is written.
        Ok(req) => service.handle(&Caller { sid: sid.clone() }, &req),
        Err(ProtoError::TooLarge) => Response::fail(2, &tr("The config is too large (1 MB at most)", &[])),
        Err(_) => Response::fail(2, &tr("Invalid input", &[])),
    };
    if let Err(e) = proto::write_response(&mut stream, &answer) {
        log(&format!("answer not delivered: {:?}", e.kind()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_most_max_unidentified_clients_wait_at_a_time() {
        let count = Arc::new(AtomicUsize::new(0));
        let mut places: Vec<Unidentified> =
            (0..MAX_UNIDENTIFIED).map(|_| Unidentified::take(&count).unwrap()).collect();
        assert!(Unidentified::take(&count).is_none());
        places.pop();
        assert_eq!(count.load(Ordering::SeqCst), MAX_UNIDENTIFIED - 1);
        places.push(Unidentified::take(&count).expect("a place again"));
        drop(places);
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }
}
