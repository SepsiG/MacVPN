//! One WinVPN per user and session: a named mutex (`Local\WinVPN-instance-<SID>`, private DACL, owned by this user)
//! decides; a second launch forwards its files (or an empty list: "show yourself") over
//! `\\.\pipe\WinVPN-open-<SID>-<session>` and exits.
//!
//! The pipe is the control pipe's kind (`macvpn_winsys::pipe`: a protected DACL for this user and SYSTEM, network
//! logons denied, remote clients rejected, the first instance only). The receiver hears only peers of this user in
//! this session, reads at most [`forward::MAX_BYTES`], and drops a malformed message as a whole; the sender talks
//! only to a server of this user (`pipe::connect` checks the server's SID before sending). Every path then goes
//! through the same import confirmation as a double-click.

use crate::pure::{forward, instance};
use macvpn_winsys::mutex;
use macvpn_winsys::pipe::{self, Listener, NetworkLogons};
use macvpn_winsys::sid::Sid;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED;
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Threading::GetCurrentProcessId;

/// How long a second launch waits for the first one's pipe (it may still be starting) and for a busy pipe.
const CONNECT: Duration = Duration::from_secs(5);
/// How long the receiver waits for one launch's whole message (one deadline, however the bytes trickle in).
const READ: Duration = Duration::from_secs(2);

pub enum Claim {
    /// This is the running instance: keep the guard for the process's life and call [`InstanceGuard::listen`].
    First(InstanceGuard),
    /// Another instance got the files (or the request to show itself): exit.
    Forwarded,
}

pub struct InstanceGuard {
    _mutex: mutex::NamedMutex,
    pipe_name: String,
}

/// The Remote Desktop session of a process.
fn session_of(pid: u32) -> io::Result<u32> {
    let mut id = 0u32;
    // SAFETY: a valid out pointer.
    if unsafe { ProcessIdToSessionId(pid, &mut id) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(id)
}

/// Claims the instance; a second one forwards `paths` (absolute file arguments) and returns `Forwarded`. Errors
/// fail closed: the caller does not start a second instance (a mutex or pipe of another user under our name, a
/// first instance that does not answer, paths the message cannot carry). The mutex is created with a private DACL
/// (this user and SYSTEM, owner this user); an existing one counts as WinVPN's only when this user owns it: a mutex
/// another user created first, or one this user cannot open, is [`instance::squatted`] (review L3).
pub fn claim(paths: &[PathBuf]) -> io::Result<Claim> {
    let sid = Sid::current_user()?;
    // SAFETY: plain call.
    let session = session_of(unsafe { GetCurrentProcessId() })?;
    let mutex = mutex::create_private(&format!("Local\\WinVPN-instance-{sid}"))
        .map_err(|e| if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) { instance::squatted() } else { e })?;
    let pipe_name = format!(r"\\.\pipe\WinVPN-open-{sid}-{session}");
    let Some(owner) = &mutex.existing_owner else {
        return Ok(Claim::First(InstanceGuard { _mutex: mutex, pipe_name }));
    };
    instance::existing_mutex(*owner == sid)?;
    let message = forward::encode(paths).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let stream = connect_retrying(&pipe_name)?;
    stream.set_write_timeout(Some(CONNECT))?;
    (&stream).write_all(&message)?;
    stream.shutdown(Shutdown::Both)?;
    Ok(Claim::Forwarded)
}

/// Tells the user why WinVPN does not start (a GUI app has no console for `claim`'s error): a modal message box
/// with [`instance::failure_message`]. Returns when the user closed it.
pub fn show_claim_failure(e: &io::Error) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MB_SETFOREGROUND, MessageBoxW};
    let wide = |s: &str| -> Vec<u16> { s.encode_utf16().filter(|&c| c != 0).chain(Some(0)).collect() };
    let (text, caption) = (wide(&instance::failure_message(e)), wide("WinVPN"));
    // SAFETY: NUL-terminated strings that outlive the call; no owner window.
    unsafe {
        MessageBoxW(std::ptr::null_mut(), text.as_ptr(), caption.as_ptr(), MB_OK | MB_ICONERROR | MB_SETFOREGROUND)
    };
}

/// The first instance may still be starting (its pipe not listening yet): `NotFound` is retried until [`CONNECT`].
fn connect_retrying(name: &str) -> io::Result<pipe::PipeStream> {
    let deadline = Instant::now() + CONNECT;
    loop {
        match pipe::connect(name, CONNECT) {
            Err(e) if e.kind() == io::ErrorKind::NotFound && Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(100));
            }
            other => return other,
        }
    }
}

impl InstanceGuard {
    /// Serves the forwarding pipe on its own thread; `on_open` gets each launch's paths (empty: show yourself).
    /// Only peers of this user in this session are heard. A pipe name taken already (a squatter) is `AddrInUse`.
    pub fn listen(&self, on_open: Box<dyn Fn(Vec<PathBuf>) + Send>) -> io::Result<()> {
        self.listen_with(on_open, NetworkLogons::Deny)
    }

    /// Tests only: an SSH session is a network logon, which [`InstanceGuard::listen`] refuses.
    #[doc(hidden)]
    pub fn listen_allowing_network_logons_for_tests(
        &self,
        on_open: Box<dyn Fn(Vec<PathBuf>) + Send>,
    ) -> io::Result<()> {
        self.listen_with(on_open, NetworkLogons::Allow)
    }

    fn listen_with(&self, on_open: Box<dyn Fn(Vec<PathBuf>) + Send>, network: NetworkLogons) -> io::Result<()> {
        let listener = Listener::bind_with(&self.pipe_name, network)?;
        let me = Sid::current_user()?;
        // SAFETY: plain call.
        let session = session_of(unsafe { GetCurrentProcessId() })?;
        std::thread::Builder::new()
            .name("winvpn-open-files".into())
            .spawn(move || serve(&listener, &me, session, on_open))?;
        Ok(())
    }
}

/// The receiver's loop: one launch at a time, each for at most [`READ`].
fn serve(listener: &Listener, me: &Sid, session: u32, on_open: Box<dyn Fn(Vec<PathBuf>) + Send>) {
    loop {
        let (stream, peer) = match listener.accept(Duration::from_millis(500)) {
            Ok(Some(client)) => client,
            Ok(None) => continue,
            Err(_) => {
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
        };
        let heard = peer.is_ok_and(|p| p.sid == *me && session_of(p.pid).is_ok_and(|s| s == session));
        if heard && let Some(paths) = read_message(&stream, Instant::now() + READ) {
            on_open(paths);
        }
        let _ = stream.shutdown(Shutdown::Both);
    }
}

/// One launch's message, at most [`forward::MAX_BYTES`] (more is dropped as a whole); `None` if it did not end
/// (the sender closing its end) by `deadline`. The deadline is for the whole message: each read waits only for what
/// is left of it, so a sender that drips a byte now and then cannot hold the receiver (review L2).
fn read_message(stream: &pipe::PipeStream, deadline: Instant) -> Option<Vec<PathBuf>> {
    let mut data = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        stream.set_read_timeout(Some(left)).ok()?;
        let want = (forward::MAX_BYTES + 1 - data.len()).min(buf.len());
        match (&*stream).read(&mut buf[..want]) {
            Ok(0) => break,
            Ok(n) => {
                data.extend_from_slice(&buf[..n]);
                if data.len() > forward::MAX_BYTES {
                    break;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => return None,
        }
    }
    Some(forward::decode(&data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn unique_name() -> String {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        format!(r"\\.\pipe\winvpn-open-unit-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst))
    }

    /// A sender that drips one byte every 1.5 s is closed after [`READ`] in total (not 2 s per byte), and the next
    /// launch is served right after it (review L2). Network logons are admitted: the tests run over SSH.
    #[test]
    fn a_dripping_sender_is_closed_after_the_deadline_and_the_next_one_is_served() {
        let name = unique_name();
        let listener = Listener::bind_with(&name, NetworkLogons::Allow).unwrap();
        let me = Sid::current_user().unwrap();
        // SAFETY: plain call.
        let session = session_of(unsafe { GetCurrentProcessId() }).unwrap();
        let (tx, rx) = mpsc::channel();
        let tx = std::sync::Mutex::new(tx);
        std::thread::spawn(move || {
            serve(&listener, &me, session, Box::new(move |p| tx.lock().unwrap().send(p).unwrap()))
        });
        let started = Instant::now();
        let dripper_name = name.clone();
        let dripper = std::thread::spawn(move || {
            let stream = pipe::connect(&dripper_name, CONNECT).unwrap();
            stream.set_write_timeout(Some(Duration::from_secs(1))).unwrap();
            // Until the receiver closes the pipe: then a write fails.
            for _ in 0..20 {
                if (&stream).write_all(b"C").is_err() {
                    return Instant::now();
                }
                std::thread::sleep(Duration::from_millis(1500));
            }
            panic!("the receiver never closed the pipe");
        });
        std::thread::sleep(Duration::from_millis(100));
        let file = std::env::temp_dir().join("next.ovpn");
        let next = pipe::connect(&name, CONNECT).unwrap();
        (&next).write_all(&forward::encode(std::slice::from_ref(&file)).unwrap()).unwrap();
        next.shutdown(Shutdown::Both).unwrap();
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), vec![file]);
        let served = started.elapsed();
        assert!(served < Duration::from_millis(3500), "the next launch waited {served:?}");
        let closed = dripper.join().unwrap().duration_since(started);
        // Closed at READ (2 s); the dripper notices on its next write, at most 1.5 s later.
        assert!(closed < Duration::from_millis(3700), "closed after {closed:?}");
    }

    /// A message ends with the sender closing its end; more than [`forward::MAX_BYTES`] is dropped as a whole.
    #[test]
    fn read_message_reads_to_the_end_and_caps_the_size() {
        let name = unique_name();
        let listener = Listener::bind_with(&name, NetworkLogons::Allow).unwrap();
        let file = std::env::temp_dir().join("a.ovpn");
        let message = forward::encode(std::slice::from_ref(&file)).unwrap();
        let send = |bytes: Vec<u8>| {
            let name = name.clone();
            std::thread::spawn(move || {
                let s = pipe::connect(&name, CONNECT).unwrap();
                let _ = (&s).write_all(&bytes);
                let _ = s.shutdown(Shutdown::Both);
            })
        };
        let accept = || loop {
            if let Some((s, _)) = listener.accept(Duration::from_secs(5)).unwrap() {
                break s;
            }
        };
        let sender = send(message);
        let stream = accept();
        assert_eq!(read_message(&stream, Instant::now() + READ), Some(vec![file]));
        sender.join().unwrap();
        let sender = send(vec![b'/'; forward::MAX_BYTES + 10]);
        let stream = accept();
        assert_eq!(read_message(&stream, Instant::now() + READ), Some(Vec::new()));
        drop(stream);
        sender.join().unwrap();
    }
}
