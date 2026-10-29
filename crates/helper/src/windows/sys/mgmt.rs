//! The management connection over loopback TCP (OpenVPN on Windows has no Unix sockets). Only after the socket
//! that accepted the connection is shown to belong to the `openvpn.exe` this run started is the password sent
//! ([`super::tcp_owner::peer_pid`]): a process that bound the port first never gets it (nor, after it, the user's
//! credentials). Then the stream goes to the shared bridge with a 250 ms read timeout (the bridge's poll).
//!
//! A connection that reached anything else is closed without a byte sent and tried again until the deadline:
//! while `openvpn.exe` is still starting, a connect to its port can even reach itself (a TCP self-connect: Windows
//! gave the connecting socket the port it connects to as its own ephemeral port, and with nobody listening the two
//! ends of one socket meet), and a listener of another process may hold the port. OpenVPN listens again after a
//! client goes away, so dropping a connection never loses the interface.
//!
//! OpenVPN's login texts (2.7.8 `manage.c`: `man_prompt`, `man_check_password`): the prompt `ENTER PASSWORD:`
//! without a line end, then `SUCCESS: password is correct` or `ERROR: bad password` (lines end in `\r\n`).

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const PROMPT: &[u8] = b"ENTER PASSWORD:";
const SUCCESS: &[u8] = b"SUCCESS: password is correct";
/// The pause between two tries.
const RETRY: Duration = Duration::from_millis(200);
/// The error of a management port that, up to the deadline, was answered only by another process (or by a socket
/// whose owner could not be found): the caller may start OpenVPN again on another port.
pub const NOT_OPENVPNS: &str = "the management port is not openvpn's";

/// What a connection to the management port reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reached {
    /// The socket of the `openvpn.exe` this run started: the only one the password goes to.
    Openvpn,
    /// The connecting socket itself (its local and remote ends are the same): nobody listens yet.
    Itself,
    /// Another process, or an owner that cannot be found (fail closed).
    Other,
}

/// `ends`: the connection's (local, peer) address, `None` when either is unknown; `owner`: the PID of the socket
/// at the peer end.
fn judge(ends: Option<(SocketAddr, SocketAddr)>, owner: Option<u32>, openvpn_pid: u32) -> Reached {
    match ends {
        Some((local, peer)) if local == peer => Reached::Itself,
        Some(_) if owner == Some(openvpn_pid) => Reached::Openvpn,
        _ => Reached::Other,
    }
}

/// Connects to `127.0.0.1:port` within `deadline` (`gone` says the process ended: no more tries), checks that the
/// accepting socket is `openvpn_pid`'s, logs in with `password`.
pub fn connect(
    port: u16,
    openvpn_pid: u32,
    password: &[u8],
    deadline: Instant,
    gone: &dyn Fn() -> bool,
) -> io::Result<TcpStream> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    // A plain (blocking) connect: each try ends refused or established. A connect with a short timeout would
    // abandon a try whose SYN Windows still retries (a refused loopback connect takes about 2 s there); once
    // OpenVPN listens, that orphan is the connection it accepts, and it serves one client at a time.
    connect_with(&mut || TcpStream::connect(addr), openvpn_pid, password, deadline, gone, super::tcp_owner::peer_pid)
}

/// The tries of [`connect`] with `dial` making each connection and `owner` finding the PID of its other end.
fn connect_with(
    dial: &mut dyn FnMut() -> io::Result<TcpStream>,
    openvpn_pid: u32,
    password: &[u8],
    deadline: Instant,
    gone: &dyn Fn() -> bool,
    owner: fn(&TcpStream) -> Option<u32>,
) -> io::Result<TcpStream> {
    // A try that reached another process wins over a later refusal as the reason (the caller may move the port).
    let mut squatted = false;
    loop {
        let error = match dial() {
            Ok(stream) => {
                let ends = stream.local_addr().ok().zip(stream.peer_addr().ok());
                match judge(ends, owner(&stream), openvpn_pid) {
                    Reached::Openvpn => return login(stream, password),
                    // Closed here, nothing sent: anyone else gets nothing.
                    Reached::Itself => io::Error::new(
                        io::ErrorKind::ConnectionRefused,
                        "the management connection reached itself (openvpn was not listening)",
                    ),
                    Reached::Other => {
                        squatted = true;
                        io::Error::new(io::ErrorKind::AddrInUse, NOT_OPENVPNS)
                    }
                }
            }
            Err(e) => e,
        };
        if Instant::now() >= deadline || gone() {
            return Err(if squatted { io::Error::new(io::ErrorKind::AddrInUse, NOT_OPENVPNS) } else { error });
        }
        std::thread::sleep(RETRY);
    }
}

/// The login on a stream already shown to be `openvpn.exe`'s.
fn login(stream: TcpStream, password: &[u8]) -> io::Result<TcpStream> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut prompt = [0u8; PROMPT.len()];
    (&stream).read_exact(&mut prompt)?;
    if prompt != PROMPT {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "no management password prompt"));
    }
    let mut line = Zeroizing::new(Vec::with_capacity(password.len() + 1));
    line.extend_from_slice(password);
    line.push(b'\n');
    (&stream).write_all(&line)?;
    let mut answer = Vec::new();
    let mut byte = [0u8; 1];
    while answer.len() < 256 && (&stream).read(&mut byte)? == 1 && byte[0] != b'\n' {
        answer.push(byte[0]);
    }
    if !answer.starts_with(SUCCESS) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "the management password was refused"));
    }
    stream.set_read_timeout(Some(Duration::from_millis(250)))?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::mpsc;

    /// A management server in this process: it prompts, reads one line, answers `reply`, and reports what it got.
    fn server(reply: &'static [u8]) -> (u16, mpsc::Receiver<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let _ = s.write_all(PROMPT);
            let mut got = Vec::new();
            let mut byte = [0u8; 1];
            while let Ok(1) = s.read(&mut byte) {
                got.push(byte[0]);
                if byte[0] == b'\n' {
                    let _ = s.write_all(reply);
                    break;
                }
            }
            let _ = tx.send(got);
            std::thread::sleep(Duration::from_millis(300));
        });
        (port, rx)
    }

    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(3)
    }

    /// A TCP self-connect, as a connect to a port nobody listens on can get by chance: a socket bound to a free
    /// loopback port and connected to that same port (Windows completes it as a simultaneous open).
    #[allow(unsafe_code)]
    fn self_connected() -> TcpStream {
        use std::os::windows::io::FromRawSocket;
        use windows_sys::Win32::Networking::WinSock::{
            AF_INET, INVALID_SOCKET, IPPROTO_TCP, SOCK_STREAM, SOCKADDR, SOCKADDR_IN, bind, closesocket, connect,
            socket,
        };
        // Initializes Winsock for this process (std does it on first use).
        drop(TcpListener::bind("127.0.0.1:0").unwrap());
        for _ in 0..20 {
            let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
            // SAFETY: plain Winsock calls on a socket this function owns; `addr` outlives the calls that read it.
            unsafe {
                let s = socket(i32::from(AF_INET), SOCK_STREAM, IPPROTO_TCP);
                assert_ne!(s, INVALID_SOCKET);
                let mut addr: SOCKADDR_IN = std::mem::zeroed();
                addr.sin_family = AF_INET;
                addr.sin_port = port.to_be();
                addr.sin_addr.S_un.S_addr = u32::from_ne_bytes([127, 0, 0, 1]);
                let (p, len) = ((&raw const addr).cast::<SOCKADDR>(), size_of::<SOCKADDR_IN>() as i32);
                if bind(s, p, len) == 0 && connect(s, p, len) == 0 {
                    return TcpStream::from_raw_socket(s as u64);
                }
                closesocket(s);
            }
        }
        panic!("no self-connect")
    }

    #[test]
    fn the_password_goes_only_to_the_process_that_was_started() {
        let me = std::process::id();
        // Our own server: the owner check passes, the password is sent once, the login succeeds.
        let (port, rx) = server(b"SUCCESS: password is correct\r\n");
        let s = connect(port, me, b"0123abcd", soon(), &|| false).unwrap();
        assert_eq!(s.read_timeout().unwrap(), Some(Duration::from_millis(250)));
        assert_eq!(rx.recv().unwrap(), b"0123abcd\n");
        // A listener of "another process" (the PID does not match): tried until the deadline, not one byte is sent.
        let (port, rx) = server(b"SUCCESS: password is correct\r\n");
        let started = Instant::now();
        let until = Instant::now() + Duration::from_millis(700);
        let e = connect(port, me.wrapping_add(4), b"0123abcd", until, &|| false).unwrap_err();
        assert_eq!((e.kind(), e.to_string().as_str()), (io::ErrorKind::AddrInUse, NOT_OPENVPNS));
        assert!(started.elapsed() >= Duration::from_millis(600), "retried, not failed at once");
        assert_eq!(rx.recv().unwrap(), b"", "the password never reached the squatter");
        // An owner that cannot be determined is refused the same way.
        let (port, rx) = server(b"SUCCESS: password is correct\r\n");
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let e = connect_with(&mut || TcpStream::connect(addr), me, b"0123abcd", Instant::now(), &|| false, |_| None)
            .unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::AddrInUse);
        assert_eq!(rx.recv().unwrap(), b"");
    }

    #[test]
    fn a_refused_password_or_another_protocol_fails() {
        let me = std::process::id();
        let (port, _rx) = server(b"ERROR: bad password\r\n");
        assert_eq!(connect(port, me, b"x", soon(), &|| false).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        // No listener at all: fails at the deadline (or at once when the process is gone).
        let free = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let started = Instant::now();
        assert!(connect(free, me, b"x", Instant::now() + Duration::from_secs(10), &|| true).is_err());
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn what_a_connection_reached_decides_whether_the_password_goes() {
        let a = SocketAddr::from(([127, 0, 0, 1], 50000));
        let b = SocketAddr::from(([127, 0, 0, 1], 40000));
        assert_eq!(judge(Some((a, b)), Some(7), 7), Reached::Openvpn);
        // A self-connect is never OpenVPN, whatever the table says.
        assert_eq!(judge(Some((a, a)), Some(7), 7), Reached::Itself);
        assert_eq!(judge(Some((a, a)), None, 7), Reached::Itself);
        assert_eq!(judge(Some((a, b)), Some(8), 7), Reached::Other);
        assert_eq!(judge(Some((a, b)), None, 7), Reached::Other);
        assert_eq!(judge(None, Some(7), 7), Reached::Other);
    }

    #[test]
    fn a_self_connect_is_retried_and_gets_nothing() {
        let me = std::process::id();
        let s = self_connected();
        assert_eq!(s.local_addr().unwrap(), s.peer_addr().unwrap());
        // Its other end is this process (the old check refused the whole connect here).
        assert_eq!(super::super::tcp_owner::peer_pid(&s), Some(me));
        // A self-connect first, then OpenVPN listens: the login goes to OpenVPN, once.
        let (port, rx) = server(b"SUCCESS: password is correct\r\n");
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let mut first = Some(s);
        let mut dial = || match first.take() {
            Some(s) => Ok(s),
            None => TcpStream::connect(addr),
        };
        let owner = super::super::tcp_owner::peer_pid;
        connect_with(&mut dial, me, b"0123abcd", soon(), &|| false, owner).unwrap();
        assert_eq!(rx.recv().unwrap(), b"0123abcd\n");
        // Only self-connects up to the deadline: an error, and the socket never saw the password (it would read it
        // back itself).
        let s = self_connected();
        let probe = s.try_clone().unwrap();
        let mut once = Some(s);
        let mut dial = || once.take().map_or_else(|| Err(io::ErrorKind::ConnectionRefused.into()), Ok);
        let e = connect_with(&mut dial, me, b"0123abcd", Instant::now(), &|| false, owner).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused);
        probe.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        let mut buf = [0u8; 16];
        assert!(!matches!((&probe).read(&mut buf), Ok(n) if n > 0), "nothing was written to it");
    }
}
