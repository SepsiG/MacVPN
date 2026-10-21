//! The control-API transport (spec `2026-10-19-control-api-design.md`): the endpoint, its client streams with
//! the peer identity, and the entropy. app-core's `ControlServer` runs over it; the platform implements it (macOS:
//! a Unix socket; Windows: a named pipe).

use std::fmt;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerUser {
    Uid(u32),
    Sid(String),
}

/// `uid 501` / `sid S-1-5-…`: the form of the audit log lines (`uid …` as in 1.4).
impl fmt::Display for PeerUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerUser::Uid(uid) => write!(f, "uid {uid}"),
            PeerUser::Sid(sid) => write!(f, "sid {sid}"),
        }
    }
}

/// The process on the other end of a client connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerIdentity {
    pub user: PeerUser,
    /// `user` is this process's user.
    pub same_user: bool,
    pub pid: i32,
    /// The executable path, `None` if it could not be read (or is not UTF-8): such a peer cannot pair or
    /// authenticate.
    pub executable: Option<String>,
}

/// One client connection. Clones share the underlying connection (like `UnixStream::try_clone`).
pub trait ControlStream: Read + Write + Send + Sync {
    fn try_clone(&self) -> io::Result<Box<dyn ControlStream>>;
    fn shutdown(&self, how: Shutdown) -> io::Result<()>;
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    /// Still connected, without blocking and without consuming data the reader needs (the pairing reply waits
    /// for it; the connection is closed after the pairing anyway, so a byte read here is not missed).
    fn peer_connected(&self) -> bool;
}

/// What one [`ControlListener::accept`] produced.
pub enum Accepted {
    /// A client (a blocking stream); `peer` failed when its identity could not be read.
    Client { stream: Box<dyn ControlStream>, peer: io::Result<PeerIdentity> },
    /// Nothing within the poll interval (the accept thread checks the stop flag).
    Idle,
}

/// The bound endpoint's accepting side.
pub trait ControlListener: Send {
    /// Waits at most about `poll` for a client.
    fn accept(&self, poll: Duration) -> io::Result<Accepted>;
}

/// A bound control endpoint.
pub struct BoundEndpoint {
    pub listener: Box<dyn ControlListener>,
    /// For the "listening on …" log line (macOS: the socket path, displayed as in 1.4).
    pub display: String,
    /// Removed by app-core's `ControlServer::stop` (macOS: the socket file; a named pipe: `None`).
    pub socket_file: Option<PathBuf>,
    /// The platform's single-instance lock (`control_socket::ControlListener`). app-core's `ControlServer::stop`
    /// drops it last, after the socket is removed and the clients are gone, so a new instance never binds while
    /// this one still serves.
    pub guard: Box<dyn Send + Sync>,
}

/// The endpoint, the peer identity and the entropy (the platform layer).
///
/// Every method is required: `prepare_dir` has no default, so a platform cannot silently skip its own checks (on
/// macOS: the directory's owner is this user). A transport without it does not compile:
///
/// ```compile_fail
/// use std::{io, path::Path};
/// use macvpn_platform_api::{BoundEndpoint, ControlTransport};
///
/// struct NoPrepare;
/// impl ControlTransport for NoPrepare {
///     fn bind(&self, _dir: &Path) -> io::Result<BoundEndpoint> { Err(io::ErrorKind::Unsupported.into()) }
///     fn random_32(&self) -> io::Result<[u8; 32]> { Err(io::ErrorKind::Unsupported.into()) }
///     fn is_already_closed(&self, _e: &io::Error) -> bool { false }
/// }
/// ```
pub trait ControlTransport: Send + Sync {
    /// Prepares the private directory and binds the endpoint in it (macOS: `<dir>/macvpn.sock`; another
    /// instance: `AddrInUse`).
    fn bind(&self, dir: &Path) -> io::Result<BoundEndpoint>;
    /// 32 bytes from the system CSPRNG.
    fn random_32(&self) -> io::Result<[u8; 32]>;
    /// The client connected and closed at once (macOS: `EINVAL` / `ENOTCONN` / `ECONNRESET`; macOS answers a
    /// socket option on such a socket with `EINVAL`): a probe that said nothing, not worth a log line.
    fn is_already_closed(&self, e: &io::Error) -> bool;
    /// Prepares the endpoint's private directory as `bind` does (the app keeps its control audit file there):
    /// created if missing, a real directory of this user, owner-only. No default: each platform checks the owner
    /// its own way (core's `fsx::ensure_private_dir` alone does not).
    fn prepare_dir(&self, dir: &Path) -> io::Result<()>;
}

// MARK: - Options
