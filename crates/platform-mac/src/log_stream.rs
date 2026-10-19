//! A long-running child whose output is delivered line by line (the process part of the Swift
//! `NativeLogCollector`: `/usr/bin/log stream --style compact --predicate …` during a native debug connect).
//!
//! stdout and stderr share one pipe; a reader thread splits it into lines (an unterminated tail longer than
//! 64 KB is passed on as a line) and reports the end of the output once the child is reaped. `stop` sends
//! SIGTERM, then SIGKILL after two seconds; dropping the handle stops the child too.

use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

/// `log stream`'s path; nothing else is ever started by this module in the app.
pub const LOG_EXECUTABLE: &str = "/usr/bin/log";
const MAX_PARTIAL: usize = 64 * 1024;

pub struct LineStream {
    child: Arc<Mutex<Option<Child>>>,
}

impl LineStream {
    /// Starts `executable arguments…` (no stdin, the app's environment). `on_lines` gets each batch of complete
    /// lines in order; `on_exit` is called once after the output ended and the child was reaped (whether it
    /// stopped on its own or was stopped).
    pub fn spawn(
        executable: &str,
        arguments: &[&str],
        mut on_lines: impl FnMut(Vec<String>) + Send + 'static,
        on_exit: impl FnOnce() + Send + 'static,
    ) -> std::io::Result<LineStream> {
        let (mut reader, writer) = std::io::pipe()?;
        let mut command = Command::new(executable);
        crate::sys::close_inherited_fds(&mut command);
        let spawned = command.args(arguments).stdin(Stdio::null()).stdout(writer.try_clone()?).stderr(writer).spawn();
        // The command holds the parent's copies of the write end: dropped, so the read sees EOF.
        drop(command);
        let child = Arc::new(Mutex::new(Some(spawned?)));
        let reaped = child.clone();
        std::thread::Builder::new().name("macvpn-log-stream".into()).spawn(move || {
            let mut buffer = [0u8; 8192];
            let mut pending: Vec<u8> = Vec::new();
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        pending.extend_from_slice(&buffer[..n]);
                        let lines = take_lines(&mut pending);
                        if !lines.is_empty() {
                            on_lines(lines);
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
            if !pending.is_empty() {
                on_lines(vec![String::from_utf8_lossy(&pending).into_owned()]);
            }
            if let Some(mut child) = reaped.lock().unwrap_or_else(PoisonError::into_inner).take() {
                let _ = child.kill();
                let _ = child.wait();
            }
            on_exit();
        })?;
        Ok(LineStream { child })
    }

    /// SIGTERM, then SIGKILL if it is still running after two seconds (on a helper thread; returns at once).
    pub fn stop(&self) {
        {
            // Signalled under the lock: the reader thread reaps under it too, so the pid cannot be reused here.
            let guard = self.child.lock().unwrap_or_else(PoisonError::into_inner);
            let Some(child) = guard.as_ref() else { return };
            crate::sys::kill(child.id() as i32, crate::sys::SIGTERM);
        }
        let child = self.child.clone();
        let _ = std::thread::Builder::new().name("macvpn-log-stream-kill".into()).spawn(move || {
            std::thread::sleep(Duration::from_secs(2));
            if let Some(child) = child.lock().unwrap_or_else(PoisonError::into_inner).as_mut()
                && child.try_wait().ok().flatten().is_none()
            {
                let _ = child.kill();
            }
        });
    }
}

impl Drop for LineStream {
    fn drop(&mut self) {
        self.stop();
    }
}

/// The complete lines at the start of `pending` (removed from it); an unterminated tail over 64 KB too.
pub fn take_lines(pending: &mut Vec<u8>) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(last) = pending.iter().rposition(|&b| b == b'\n') {
        let text = String::from_utf8_lossy(&pending[..last]).into_owned();
        lines.extend(text.split('\n').map(|l| l.strip_suffix('\r').unwrap_or(l).to_string()));
        pending.drain(..=last);
    }
    if pending.len() > MAX_PARTIAL {
        let cut = macvpn_core::log::complete_utf8_prefix(pending);
        lines.push(String::from_utf8_lossy(&pending[..cut]).into_owned());
        pending.drain(..cut);
    }
    lines
}
