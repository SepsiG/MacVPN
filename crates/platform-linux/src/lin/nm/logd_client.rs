//! Asks `linvpn-logd` (`/run/linvpn-logd.sock`) for the journal lines of one of this user's connections.
//!
//! One request, one response per connection (`macvpn_core::logd`'s wire format): the server derives the
//! NetworkManager UUID from our `SO_PEERCRED` uid, so we can only ever get our own connections' lines. The answer is
//! read to its end within [`TIMEOUT`], at most `MAX_RESPONSE` bytes, and parsed strictly (fail closed).

use macvpn_core::logd::{MAX_RESPONSE, Request, Response};
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

pub const SOCKET: &str = "/run/linvpn-logd.sock";
/// How long one query may take in all (connect, request, the whole answer).
pub const TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogdError {
    /// No socket, or nobody listens on it (`linvpn-logd` is not installed or its socket is stopped).
    Unavailable,
    /// The answer is longer than `MAX_RESPONSE`.
    TooLarge,
    /// The answer is not a valid response.
    Malformed,
    /// No complete answer within the time.
    Timeout,
    /// Another I/O error (its kind).
    Io(String),
}

/// The installed `linvpn-logd`: its socket must be a socket owned by root (systemd made it), else it is not ours.
pub fn query(request: &Request) -> Result<Response, LogdError> {
    let path = Path::new(SOCKET);
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() && m.uid() == 0 => query_at(path, request),
        _ => Err(LogdError::Unavailable),
    }
}

/// How long the engine waits for [`mark`] before it activates anyway.
pub const MARK_TIMEOUT: Duration = Duration::from_secs(3);

/// One query right before an activation, whose answer is not needed: `linvpn-logd` reads NetworkManager's active
/// VPN connections and records the reading, which shows every earlier connection that is gone by now as gone
/// before this activation (NetworkManager logs no end line for a finished VPN at its default level; without such a
/// reading the new connection's plugin lines would be withheld as possibly another's). `socket`: `None` for the
/// installed server. Any failure is ignored (the plugin lines may then be withheld).
pub fn mark(socket: Option<&Path>, connection: uuid::Uuid) {
    let since_usec = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_micros()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    let request = Request { connection, since_usec, cursor: None };
    let _ = match socket {
        Some(p) => query_within(p, &request, MARK_TIMEOUT),
        None => match std::fs::symlink_metadata(SOCKET) {
            Ok(m) if m.file_type().is_socket() && m.uid() == 0 => {
                query_within(Path::new(SOCKET), &request, MARK_TIMEOUT)
            }
            _ => Err(LogdError::Unavailable),
        },
    };
}

/// One query of the server at `socket`, within [`TIMEOUT`].
pub fn query_at(socket: &Path, request: &Request) -> Result<Response, LogdError> {
    query_within(socket, request, TIMEOUT)
}

/// [`query_at`] with another time limit (the tests').
#[doc(hidden)]
pub fn query_within(socket: &Path, request: &Request, timeout: Duration) -> Result<Response, LogdError> {
    let deadline = Instant::now() + timeout;
    let mut stream = UnixStream::connect(socket).map_err(|e| match e.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => LogdError::Unavailable,
        _ => io_error(&e),
    })?;
    let left = || deadline.checked_duration_since(Instant::now()).filter(|d| !d.is_zero()).ok_or(LogdError::Timeout);
    stream.set_write_timeout(Some(left()?)).map_err(|e| io_error(&e))?;
    stream.write_all(request.encode().as_bytes()).map_err(|e| io_error(&e))?;
    let _ = stream.shutdown(Shutdown::Write);

    let mut data = Vec::with_capacity(64 * 1024);
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        stream.set_read_timeout(Some(left()?)).map_err(|e| io_error(&e))?;
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if data.len() + n > MAX_RESPONSE {
                    return Err(LogdError::TooLarge);
                }
                data.extend_from_slice(&chunk[..n]);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(io_error(&e)),
        }
    }
    let text = std::str::from_utf8(&data).map_err(|_| LogdError::Malformed)?;
    Response::parse(text).ok_or(LogdError::Malformed)
}

fn io_error(e: &io::Error) -> LogdError {
    match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => LogdError::Timeout,
        kind => LogdError::Io(format!("{kind:?}")),
    }
}
