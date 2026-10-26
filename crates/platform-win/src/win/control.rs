//! The control API's endpoint on Windows: `\\.\pipe\WinVPN-control-<SID>` (see `macvpn_winsys::pipe` for the DACL,
//! the identity and the I/O).

use macvpn_core::fsx::{self, FileOwner};
use macvpn_platform_api::{
    Accepted, BoundEndpoint, ControlListener, ControlStream, ControlTransport, PeerIdentity, PeerUser,
};
use macvpn_winsys::pipe::{self, Listener, NetworkLogons, PipeStream};
use macvpn_winsys::sid::Sid;
use std::io::{self, ErrorKind, Read, Write};
use std::net::Shutdown;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// The pipe name's prefix (a storage identifier: clients find WinVPN by it).
pub(crate) const CONTROL_PIPE_PREFIX: &str = "WinVPN-control";

pub(crate) struct PipeTransport {
    name: String,
    /// `Deny` in production: only this user's local (desktop) logons may connect.
    network: NetworkLogons,
}

impl PipeTransport {
    /// `\\.\pipe\WinVPN-control-<this user's SID>`, closed to this user's network logons.
    pub(crate) fn for_user() -> io::Result<PipeTransport> {
        Ok(PipeTransport { name: pipe::user_pipe_name(CONTROL_PIPE_PREFIX)?, network: NetworkLogons::Deny })
    }

    /// Tests only (`control_transport_for_tests`): another name, and the choice of network logons (the tests run
    /// over SSH).
    pub(crate) fn with_name(name: &str, network: NetworkLogons) -> PipeTransport {
        PipeTransport { name: name.to_string(), network }
    }
}

struct PipeListener(Arc<Listener>);

struct Stream(PipeStream);

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read_some(buf)
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write_some(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl ControlStream for Stream {
    fn try_clone(&self) -> io::Result<Box<dyn ControlStream>> {
        Ok(Box::new(Stream(self.0.try_clone())))
    }

    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.0.shutdown(how)
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.0.set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.0.set_write_timeout(timeout)
    }

    /// A zero-length `PeekNamedPipe`: nothing is consumed (stricter than the macOS one-byte peek).
    fn peer_connected(&self) -> bool {
        self.0.peer_connected()
    }
}

/// The peer as the server sees it. `same_user` compares SIDs; a SID that cannot be read fails the accept (the
/// server closes such a client).
fn identity(peer: pipe::Peer) -> io::Result<PeerIdentity> {
    let me = Sid::current_user()?;
    Ok(PeerIdentity {
        same_user: peer.sid == me,
        user: PeerUser::Sid(peer.sid.to_string()),
        pid: i32::try_from(peer.pid).unwrap_or(-1),
        executable: peer.image.and_then(|p| p.into_os_string().into_string().ok()),
    })
}

impl ControlListener for PipeListener {
    fn accept(&self, poll: Duration) -> io::Result<Accepted> {
        Ok(match self.0.accept(poll)? {
            None => Accepted::Idle,
            Some((stream, peer)) => {
                Accepted::Client { stream: Box::new(Stream(stream)), peer: peer.and_then(identity) }
            }
        })
    }
}

impl ControlTransport for PipeTransport {
    fn bind(&self, dir: &Path) -> io::Result<BoundEndpoint> {
        self.prepare_dir(dir)?;
        let listener = Arc::new(Listener::bind_with(&self.name, self.network)?);
        Ok(BoundEndpoint {
            listener: Box::new(PipeListener(listener.clone())),
            display: self.name.clone(),
            socket_file: None,
            // The first instance is the single-instance lock: the name stays ours until the server drops this last.
            guard: Box::new(listener),
        })
    }

    /// `BCryptGenRandom` (the system-preferred RNG), as the platform's entropy.
    fn random_32(&self) -> io::Result<[u8; 32]> {
        let mut bytes = [0u8; 32];
        macvpn_winsys::random::fill(&mut bytes)?;
        Ok(bytes)
    }

    /// ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED: a client that connected and left at once.
    fn is_already_closed(&self, e: &io::Error) -> bool {
        e.kind() == ErrorKind::BrokenPipe
            || e.kind() == ErrorKind::NotConnected
            || matches!(e.raw_os_error(), Some(109 | 232 | 233))
    }

    /// The directory (the audit file's home) is a real, private directory of this user.
    fn prepare_dir(&self, dir: &Path) -> io::Result<()> {
        let owner = fsx::ensure_private_dir(dir)?;
        if owner != FileOwner::current_user()? {
            return Err(io::Error::new(ErrorKind::PermissionDenied, format!("{} is not this user's", dir.display())));
        }
        Ok(())
    }
}
