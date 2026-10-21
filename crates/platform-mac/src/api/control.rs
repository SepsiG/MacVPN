//! The control API's transport on macOS (moved from the app in 1.5): the Unix socket of [`crate::control_socket`]
//! as platform-api's [`ControlTransport`].

use crate::control_socket;
use macvpn_platform_api::{
    Accepted, BoundEndpoint, ControlListener, ControlStream, ControlTransport, PeerIdentity, PeerUser,
};
use std::io::{self, ErrorKind, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

/// The platform socket (`control_socket`): `<dir>/macvpn.sock`, guarded by the instance lock.
pub struct Transport;

impl ControlTransport for Transport {
    fn bind(&self, dir: &Path) -> io::Result<BoundEndpoint> {
        let bound = control_socket::bind(dir)?;
        let listener = UnixControlListener::new(bound.listener().try_clone()?)?;
        let path = control_socket::socket_path(dir);
        // The `ControlListener` (with the instance lock) is the guard the server drops last.
        Ok(BoundEndpoint {
            listener: Box::new(listener),
            display: path.display().to_string(),
            socket_file: Some(path),
            guard: Box::new(bound),
        })
    }

    fn random_32(&self) -> io::Result<[u8; 32]> {
        control_socket::random_32()
    }

    fn is_already_closed(&self, e: &io::Error) -> bool {
        control_socket::is_already_closed(e)
    }

    /// `control_socket::prepare_dir` (the owner checked against `getuid()` before the mode is tightened).
    fn prepare_dir(&self, dir: &Path) -> io::Result<()> {
        control_socket::prepare_dir(dir)
    }
}

/// The bound Unix socket, non-blocking so the accept thread can see the stop flag.
pub struct UnixControlListener(UnixListener);

impl UnixControlListener {
    fn new(listener: UnixListener) -> io::Result<UnixControlListener> {
        listener.set_nonblocking(true)?;
        Ok(UnixControlListener(listener))
    }
}

impl ControlListener for UnixControlListener {
    fn accept(&self, poll: Duration) -> io::Result<Accepted> {
        let stream = match self.0.accept() {
            Ok((stream, _)) => stream,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(poll);
                return Ok(Accepted::Idle);
            }
            Err(e) => return Err(e),
        };
        // The listener is non-blocking; the client's stream must not be (BSD sockets inherit the flag). A client
        // whose flag cannot be cleared is dropped without a word.
        if stream.set_nonblocking(false).is_err() {
            return Ok(Accepted::Idle);
        }
        let peer = control_socket::peer(&stream).map(|peer| PeerIdentity {
            user: PeerUser::Uid(peer.uid),
            same_user: control_socket::same_user(peer.uid),
            pid: peer.pid,
            executable: peer.executable.and_then(|p| p.into_os_string().into_string().ok()),
        });
        Ok(Accepted::Client { stream: Box::new(UnixControlStream(stream)), peer })
    }
}

/// One client's Unix socket.
pub struct UnixControlStream(UnixStream);

impl Read for UnixControlStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for UnixControlStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl ControlStream for UnixControlStream {
    fn try_clone(&self) -> io::Result<Box<dyn ControlStream>> {
        Ok(Box::new(UnixControlStream(self.0.try_clone()?)))
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

    /// Peeks without blocking: the reader is the pairing's own thread, and the connection is closed after the
    /// pairing anyway, so a byte read here is not missed.
    fn peer_connected(&self) -> bool {
        if self.0.set_nonblocking(true).is_err() {
            return false;
        }
        let mut byte = [0u8; 1];
        let alive = match (&self.0).read(&mut byte) {
            Ok(0) => false,
            Ok(_) => true,
            Err(e) => e.kind() == ErrorKind::WouldBlock,
        };
        self.0.set_nonblocking(false).is_ok() && alive
    }
}
