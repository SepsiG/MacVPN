//! A PKCS#12 client certificate (IKEv2, client credential audit G4) converted to the PEM form with the system's
//! `/usr/bin/openssl pkcs12` (OpenSSL 3): strongSwan's NetworkManager plugin loads `usercert` as an X.509 certificate
//! only. Used at import (the vault keeps the PEM form) and at connect for a PKCS#12 file restored from a Mac.
//!
//! - **The password** goes to openssl through a pipe on fd 3 (`-passin fd:3`, and `-passout fd:3`, whose second line
//!   openssl reads for the output key), written before the child starts: never in the argv or the environment.
//! - **The file** is written to openssl's stdin from memory; **the output** is read from its stdout (no file on
//!   disk), capped at [`MAX_OUTPUT`]; the child is killed after [`TIMEOUT`].
//! - **The key keeps the file's password** (`-aes256`): it is stored encrypted, as an encrypted PEM key is, and its
//!   password stays the connection's "Private key password". A file with an empty password gives an unencrypted key
//!   (`-noenc`), as an unencrypted PEM key is stored.
//! - **Legacy files** (RC2 / 3DES, older macOS and Windows exports) fail with OpenSSL 3's default provider: the
//!   conversion is tried again with `-legacy`.
//! - **The output** is checked like an imported PEM file ([`client_cert::import`]); only the client certificate
//!   (`-clcerts`) and its key are read.
//! - The environment is `PATH=/usr/bin:/bin` and `LC_ALL=C` only.

use macvpn_core::client_cert::{self, Imported};
use macvpn_core::l10n;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub const OPENSSL: &str = "/usr/bin/openssl";
/// The most stdout (or stderr) read: a client certificate and its key are a few kilobytes.
pub const MAX_OUTPUT: usize = 64 * 1024;
/// The longest an openssl run may take.
pub const TIMEOUT: Duration = Duration::from_secs(20);
/// The longest password passed (a password is a line of a pipe).
const MAX_PASSWORD: usize = 1024;

/// What one openssl run gave.
struct Run {
    ok: bool,
    stdout: Zeroizing<Vec<u8>>,
    stderr: String,
}

fn missing_openssl() -> String {
    l10n::tr("Reading a PKCS#12 file needs the openssl package: install openssl, then try again.", &[])
}

fn wrong_password() -> String {
    l10n::tr("The PKCS#12 password is wrong.", &[])
}

fn unreadable() -> String {
    l10n::tr("openssl could not read the PKCS#12 file.", &[])
}

/// `der` (a PKCS#12 file) and its password → the checked PEM form (client certificate + key).
pub fn convert(der: &[u8], password: &str) -> Result<Imported, String> {
    convert_with(OPENSSL, der, password)
}

/// [`convert`] with another openssl (tests).
pub fn convert_with(openssl: &str, der: &[u8], password: &str) -> Result<Imported, String> {
    if !std::path::Path::new(openssl).exists() {
        return Err(missing_openssl());
    }
    if password.len() > MAX_PASSWORD || password.contains(['\n', '\r', '\0']) {
        return Err(wrong_password());
    }
    let first = run(openssl, der, password, false).map_err(|_| unreadable())?;
    let run = if first.ok {
        first
    } else {
        let legacy = run(openssl, der, password, true).map_err(|_| unreadable())?;
        if !legacy.ok {
            let text = format!("{}\n{}", first.stderr, legacy.stderr);
            return Err(if is_wrong_password(&text) { wrong_password() } else { unreadable() });
        }
        legacy
    };
    let imported = client_cert::import(&[run.stdout.as_slice()]).map_err(|_| unreadable())?;
    if imported.cert.form() != client_cert::Form::Pem {
        return Err(unreadable());
    }
    Ok(imported)
}

/// openssl's words for a password that does not open the file.
fn is_wrong_password(stderr: &str) -> bool {
    let s = stderr.to_ascii_lowercase();
    s.contains("mac verify error") || s.contains("invalid password") || s.contains("bad decrypt")
}

/// The argv (no secret in it).
pub fn arguments(encrypt: bool, legacy: bool) -> Vec<&'static str> {
    let mut args = vec!["pkcs12", "-clcerts", "-passin", "fd:3"];
    if encrypt {
        args.extend(["-passout", "fd:3", "-aes256"]);
    } else {
        args.push("-noenc");
    }
    if legacy {
        args.push("-legacy");
    }
    args
}

/// `fd` moved to a descriptor ≥ 3 (close-on-exec): when this process runs with a standard stream closed, `pipe2` may
/// return 0, 1 or 2, which the child's stdio set-up overwrites before `pre_exec` copies it to 3 (openssl would then
/// read its password from the wrong file).
fn above_stdio(fd: OwnedFd) -> io::Result<OwnedFd> {
    if fd.as_raw_fd() >= 3 {
        return Ok(fd);
    }
    // SAFETY: `fd` is open and owned here; F_DUPFD_CLOEXEC returns a new descriptor or -1.
    let new = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if new < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `new` is a fresh descriptor this function owns; the old one closes when `fd` drops.
    Ok(unsafe { OwnedFd::from_raw_fd(new) })
}

fn run(openssl: &str, der: &[u8], password: &str, legacy: bool) -> io::Result<Run> {
    let encrypt = !password.is_empty();
    // The password pipe: both lines written before the child starts (a few bytes: within the pipe's buffer).
    let mut fds = [0; 2];
    // SAFETY: `fds` is a valid array of two ints for pipe2 to fill.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: pipe2 returned two new descriptors this function owns.
    let (read_end, write_end) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    {
        let mut w = std::fs::File::from(write_end);
        let lines = Zeroizing::new(if encrypt { format!("{password}\n{password}\n") } else { "\n".to_string() });
        w.write_all(lines.as_bytes())?;
    }
    let read_end = above_stdio(read_end)?;
    let raw = read_end.as_raw_fd();
    let mut command = Command::new(openssl);
    command
        .args(arguments(encrypt, legacy))
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: only async-signal-safe calls (dup2, fcntl) between fork and exec.
    unsafe {
        command.pre_exec(move || {
            if raw == 3 {
                let flags = libc::fcntl(3, libc::F_GETFD);
                if flags < 0 || libc::fcntl(3, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(io::Error::last_os_error());
                }
            } else if libc::dup2(raw, 3) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    drop(read_end);
    let mut stdin = child.stdin.take();
    let input = Zeroizing::new(der.to_vec());
    let writer = std::thread::spawn(move || {
        if let Some(pipe) = stdin.as_mut() {
            let _ = pipe.write_all(&input);
        }
    });
    let read_capped = |mut r: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut out = Zeroizing::new(Vec::new());
            let _ = r.by_ref().take(MAX_OUTPUT as u64 + 1).read_to_end(&mut out);
            let _ = io::copy(&mut r, &mut io::sink());
            out
        })
    };
    let out = child.stdout.take().map(|s| read_capped(Box::new(s)));
    let err = child.stderr.take().map(|s| read_capped(Box::new(s)));
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if start.elapsed() > TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let _ = writer.join();
    let stdout = out.and_then(|h| h.join().ok()).unwrap_or_default();
    let stderr = err.and_then(|h| h.join().ok()).unwrap_or_default();
    let ok = status.is_some_and(|s| s.success()) && stdout.len() <= MAX_OUTPUT;
    Ok(Run { ok, stdout, stderr: String::from_utf8_lossy(&stderr).into_owned() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_secret_is_in_the_argv() {
        for (encrypt, legacy) in [(true, false), (true, true), (false, false)] {
            let args = arguments(encrypt, legacy);
            assert!(args.contains(&"fd:3"));
            assert!(args.iter().all(|a| !a.contains("pass:") && !a.contains("env:")));
            assert_eq!(args.contains(&"-legacy"), legacy);
            assert_eq!(args.contains(&"-noenc"), !encrypt);
        }
    }

    #[test]
    fn a_pipe_end_at_descriptor_0_is_moved_above_stdio_and_stays_close_on_exec() {
        let mut fds = [0; 2];
        // SAFETY: plain descriptor calls on descriptors this test owns; fd 0 is restored before the end.
        unsafe {
            assert_eq!(libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC), 0);
            let saved = libc::dup(0);
            assert!(saved >= 0);
            // The pipe's read end where `pipe2` would put it with stdin closed.
            assert_eq!(libc::dup2(fds[0], 0), 0);
            libc::close(fds[0]);
            let moved = above_stdio(OwnedFd::from_raw_fd(0)).unwrap();
            libc::dup2(saved, 0);
            libc::close(saved);
            assert!(moved.as_raw_fd() >= 3);
            assert!(libc::fcntl(moved.as_raw_fd(), libc::F_GETFD) & libc::FD_CLOEXEC != 0);
            let mut w = std::fs::File::from(OwnedFd::from_raw_fd(fds[1]));
            w.write_all(b"pw\n").unwrap();
            drop(w);
            let mut got = String::new();
            std::fs::File::from(moved).read_to_string(&mut got).unwrap();
            assert_eq!(got, "pw\n", "the moved descriptor is the same pipe");
        }
    }

    #[test]
    fn a_missing_openssl_names_the_package() {
        let err = convert_with("/nonexistent/openssl", b"x", "pw").unwrap_err();
        assert!(err.contains("openssl"), "{err}");
    }
}
