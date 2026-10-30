//! One LinVPN per user and session: the first launch owns the bus name (`RequestName` with `DO_NOT_QUEUE`) and
//! serves `local.linvpn.Instance1.Open(aay files)` at `/local/linvpn/Instance`; a later launch calls `Open` with its
//! absolute file arguments (none: "show yourself") and exits. Files that arrive before the app listens wait in a
//! queue. `--after-update` (the updater's relaunch) waits up to 20 s for the old process to release the name.

use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};
use zbus::blocking::Connection;
use zbus::fdo::{RequestNameFlags, RequestNameReply};

/// Gets the files of every forwarded launch (empty: "show yourself"), on zbus' thread.
pub type Listener = Box<dyn Fn(Vec<PathBuf>) + Send + Sync>;

#[derive(Default)]
struct Inbox {
    listener: Option<Listener>,
    queued: Vec<Vec<PathBuf>>,
}

struct Instance(Arc<Mutex<Inbox>>);

#[zbus::interface(name = "local.linvpn.Instance1")]
impl Instance {
    fn open(&self, files: Vec<Vec<u8>>) {
        let paths: Vec<PathBuf> = files
            .into_iter()
            .map(|b| PathBuf::from(std::ffi::OsString::from_vec(b)))
            .filter(|p| p.is_absolute())
            .collect();
        let mut inbox = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        match &inbox.listener {
            Some(listen) => listen(paths),
            None => inbox.queued.push(paths),
        }
    }
}

pub enum Claim {
    First(InstanceGuard),
    Forwarded,
}

/// Keeps the name (and the connection serving `Open`) for the process' life.
pub struct InstanceGuard {
    _bus: Connection,
    inbox: Arc<Mutex<Inbox>>,
}

impl InstanceGuard {
    /// From now on `on_open` gets every forwarded launch (the queued ones first).
    pub fn listen(&self, on_open: Listener) {
        let mut inbox = self.inbox.lock().unwrap_or_else(PoisonError::into_inner);
        for paths in inbox.queued.drain(..) {
            on_open(paths);
        }
        inbox.listener = Some(on_open);
    }
}

const PATH: &str = "/local/linvpn/Instance";
const INTERFACE: &str = "local.linvpn.Instance1";

/// Over the process' shared session connection.
pub fn claim(name: &str, files: &[PathBuf], wait_for_release: bool) -> zbus::Result<Claim> {
    claim_on(crate::lin::bus::session()?, name, files, wait_for_release)
}

/// Over `bus` (the tests: a fresh connection per simulated process).
pub fn claim_on(bus: Connection, name: &str, files: &[PathBuf], wait_for_release: bool) -> zbus::Result<Claim> {
    let inbox = Arc::new(Mutex::new(Inbox::default()));
    // Served before the name is requested, so no `Open` that arrives right after is lost.
    bus.object_server().at(PATH, Instance(inbox.clone()))?;
    let deadline = Instant::now() + if wait_for_release { Duration::from_secs(20) } else { Duration::ZERO };
    loop {
        // zbus reports `Exists` (another process owns the name) as `Err(NameTaken)`.
        match bus.request_name_with_flags(name, RequestNameFlags::DoNotQueue.into()) {
            Ok(RequestNameReply::PrimaryOwner | RequestNameReply::AlreadyOwner) => {
                return Ok(Claim::First(InstanceGuard { _bus: bus, inbox }));
            }
            Ok(_) | Err(zbus::Error::NameTaken) => {}
            Err(e) => return Err(e),
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    // Not the owner: this process serves nothing.
    let _ = bus.object_server().remove::<Instance, _>(PATH);
    let owner = zbus::blocking::Proxy::new(&bus, name, PATH, INTERFACE)?;
    let bytes: Vec<Vec<u8>> = files.iter().map(|p| p.as_os_str().as_bytes().to_vec()).collect();
    owner.call::<_, _, ()>("Open", &(bytes,))?;
    Ok(Claim::Forwarded)
}
