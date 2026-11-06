//! The control API's Unix-socket transport as platform-api's types (moved from platform-mac's `api/control.rs`,
//! LinVPN plan Task 10): the non-blocking listener, one client's stream, and [`endpoint`], which turns a bound
//! [`ControlListener`](crate::control_socket::ControlListener) into a [`BoundEndpoint`]. Shared by macOS and Linux.

use crate::control_socket;
use macvpn_platform_api::{
    Accepted, BoundEndpoint, ControlListener, ControlStream, ListenerWaker, PeerIdentity, PeerUser,
};
use std::fs::File;
use std::io::{self, ErrorKind, Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// The bound socket as platform-api's endpoint: the non-blocking listener, the path as the log line shows it, the
/// socket file the server removes at stop, and the lock as the guard it drops last.
pub fn endpoint(bound: control_socket::ControlListener, path: PathBuf) -> io::Result<BoundEndpoint> {
    let listener = UnixControlListener::new(bound.listener().try_clone()?)?;
    Ok(BoundEndpoint {
        listener: Box::new(listener),
        display: path.display().to_string(),
        socket_file: Some(path),
        guard: Box::new(bound),
    })
}

/// The bound Unix socket (non-blocking: a client that left between `poll` and `accept` does not block) and the
/// wake pipe: `accept` sleeps in `poll(2)` on both, so it wakes only for a client or the stop. The waker writes one
/// byte that nobody reads, so every later `accept` returns at once too.
pub struct UnixControlListener {
    listener: UnixListener,
    wake_read: OwnedFd,
    wake_write: Arc<File>,
}

impl UnixControlListener {
    fn new(listener: UnixListener) -> io::Result<UnixControlListener> {
        listener.set_nonblocking(true)?;
        let (wake_read, wake_write) = wake_pipe()?;
        Ok(UnixControlListener { listener, wake_read, wake_write: Arc::new(File::from(wake_write)) })
    }
}

/// A close-on-exec pipe whose write end does not block (a full pipe is woken already).
fn wake_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a two-element array, as `pipe` requires.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `pipe` succeeded, so both descriptors are new and owned by nobody else.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    for (fd, status) in [(&read, 0), (&write, libc::O_NONBLOCK)] {
        // SAFETY: plain `fcntl` calls on a descriptor owned here.
        let ok = unsafe {
            libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) == 0
                && (status == 0 || libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, status) == 0)
        };
        if !ok {
            return Err(io::Error::last_os_error());
        }
    }
    Ok((read, write))
}

/// `poll(2)`'s timeout for `poll`, in milliseconds (at most `c_int::MAX`).
fn timeout_ms(poll: Duration) -> libc::c_int {
    libc::c_int::try_from(poll.as_millis()).unwrap_or(libc::c_int::MAX)
}

impl ControlListener for UnixControlListener {
    fn accept(&self, poll: Duration) -> io::Result<Accepted> {
        let mut fds = [
            libc::pollfd { fd: self.listener.as_raw_fd(), events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: self.wake_read.as_raw_fd(), events: libc::POLLIN, revents: 0 },
        ];
        // SAFETY: `fds` is a valid array of `fds.len()` pollfd entries.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms(poll)) };
        if n < 0 {
            let e = io::Error::last_os_error();
            return if e.kind() == ErrorKind::Interrupted { Ok(Accepted::Idle) } else { Err(e) };
        }
        if n == 0 || fds[1].revents != 0 {
            return Ok(Accepted::Idle);
        }
        let stream = match self.listener.accept() {
            Ok((stream, _)) => stream,
            Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(Accepted::Idle),
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

    fn waker(&self) -> io::Result<ListenerWaker> {
        let write = self.wake_write.clone();
        // A full pipe (`WouldBlock`) is woken already; nothing else can fail on a pipe whose read end is open.
        Ok(Box::new(move || {
            let _ = (&*write).write(&[1]);
        }))
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    /// A listener in its own directory (short: the socket path limit).
    fn listener() -> (UnixControlListener, PathBuf) {
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("mvpn-acc-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        (UnixControlListener::new(UnixListener::bind(dir.join("s")).unwrap()).unwrap(), dir)
    }

    #[test]
    fn an_accept_without_a_client_sleeps_until_its_waker_runs() {
        let (l, dir) = listener();
        let wake = l.waker().unwrap();
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            wake();
        });
        let start = Instant::now();
        assert!(matches!(l.accept(Duration::from_secs(30)).unwrap(), Accepted::Idle));
        let waited = start.elapsed();
        assert!(waited >= Duration::from_millis(90) && waited < Duration::from_secs(5), "{waited:?}");
        t.join().unwrap();
        // Woken stays woken: the stop is never missed.
        let start = Instant::now();
        assert!(matches!(l.accept(Duration::from_secs(30)).unwrap(), Accepted::Idle));
        assert!(start.elapsed() < Duration::from_secs(1));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn an_accept_returns_idle_after_its_poll_and_takes_a_client() {
        let (l, dir) = listener();
        assert!(matches!(l.accept(Duration::from_millis(20)).unwrap(), Accepted::Idle));
        let _client = UnixStream::connect(dir.join("s")).unwrap();
        assert!(matches!(l.accept(Duration::from_secs(30)).unwrap(), Accepted::Client { .. }));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
