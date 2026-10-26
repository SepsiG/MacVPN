//! The management connection over loopback TCP (OpenVPN on Windows has no Unix sockets). Only after the socket
//! that accepted the connection is shown to belong to the `openvpn.exe` this run started is the password sent
//! ([`super::tcp_owner::peer_pid`]): a process that bound the port first never gets it (nor, after it, the user's
//! credentials). Then the stream goes to the shared bridge with a 250 ms read timeout (the bridge's poll).
//!
//! OpenVPN's login texts (2.7.8 `manage.c`: `man_prompt`, `man_check_password`): the prompt `ENTER PASSWORD:`
//! without a line end, then `SUCCESS: password is correct` or `ERROR: bad password` (lines end in `\r\n`).

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const PROMPT: &[u8] = b"ENTER PASSWORD:";
const SUCCESS: &[u8] = b"SUCCESS: password is correct";

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
    let stream = loop {
        match TcpStream::connect(addr) {
            Ok(s) => break s,
            Err(_) if Instant::now() < deadline && !gone() => std::thread::sleep(Duration::from_millis(200)),
            Err(e) => return Err(e),
        }
    };
    login(stream, openvpn_pid, password, super::tcp_owner::peer_pid)
}

/// The login on a connected stream; `owner` finds the PID of the stream's other end.
fn login(
    stream: TcpStream,
    openvpn_pid: u32,
    password: &[u8],
    owner: fn(&TcpStream) -> Option<u32>,
) -> io::Result<TcpStream> {
    // The listener we reached must be our child's: anyone else gets nothing.
    if owner(&stream) != Some(openvpn_pid) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "the management port is not openvpn's"));
    }
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

    #[test]
    fn the_password_goes_only_to_the_process_that_was_started() {
        let me = std::process::id();
        // Our own server: the owner check passes, the password is sent once, the login succeeds.
        let (port, rx) = server(b"SUCCESS: password is correct\r\n");
        let s = connect(port, me, b"0123abcd", soon(), &|| false).unwrap();
        assert_eq!(s.read_timeout().unwrap(), Some(Duration::from_millis(250)));
        assert_eq!(rx.recv().unwrap(), b"0123abcd\n");
        // A listener of "another process" (the PID does not match): not one byte is sent.
        let (port, rx) = server(b"SUCCESS: password is correct\r\n");
        let e = connect(port, me.wrapping_add(4), b"0123abcd", soon(), &|| false).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(rx.recv().unwrap(), b"", "the password never reached the squatter");
        // An owner that cannot be determined is refused the same way.
        let (port, rx) = server(b"SUCCESS: password is correct\r\n");
        let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let e = login(stream, me, b"0123abcd", |_| None).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
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
}
