//! Named pipes. The server: [`Listener::bind`] (first instance; a name in use is `AddrInUse`), [`Listener::accept`]
//! (waits at most a poll interval; the client's SID from identification-level impersonation, its PID and image
//! path). The client: [`connect`] (identification-level only; refuses a server of another user). Both sides use
//! [`PipeStream`]: overlapped I/O with one event per operation, exact timeouts, clones, shutdown.
//!
//! The WinVPN Service's endpoint ([`Endpoint::Service`]: owner SYSTEM, interactive users may read and write data
//! but never create an instance or change the DACL) and its client ([`connect_with`] + [`ServerTrust::LocalSystem`]:
//! opens with [`SERVICE_CLIENT_ACCESS`] and refuses a pipe not owned by SYSTEM before it sends anything).
//!
//! Only local pipes (`\\.\pipe\<name>`, the name without `\` or `/`) are accepted on either side.

use crate::security::{Ace, Acl, Descriptor};
use crate::sid::Sid;
use crate::util::{check, wide};
use std::ffi::{OsStr, OsString};
use std::io::{self, ErrorKind, Read, Write};
use std::net::Shutdown;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock, TryLockError};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_CANNOT_IMPERSONATE, ERROR_IO_PENDING, ERROR_NO_DATA,
    ERROR_OPERATION_ABORTED, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED, GENERIC_READ,
    GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::{RevertToSelf, TOKEN_QUERY};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ALL_ACCESS, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ,
    FILE_WRITE_DATA, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, READ_CONTROL, ReadFile, SECURITY_IDENTIFICATION,
    SECURITY_SQOS_PRESENT, WriteFile,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
    ImpersonateNamedPipeClient, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT, PeekNamedPipe, WaitNamedPipeW,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentThread, INFINITE, OpenProcess, OpenProcessToken, OpenThreadToken, PROCESS_NAME_WIN32,
    PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW, WaitForSingleObject,
};

const BUFFER: u32 = 64 * 1024;
const LOCAL_PREFIX: &str = r"\\.\pipe\";

/// The message of the `PermissionDenied` error [`connect`] returns for a server that is not (provably) this user.
pub const NOT_THIS_USER: &str = "the pipe is not served by this user";

pub use crate::file::AceSummary;

/// What a client of the service endpoint may do: read, write data, read the security descriptor (`READ_CONTROL`,
/// to check the owner), synchronize. Not `FILE_APPEND_DATA` (= [`FILE_CREATE_PIPE_INSTANCE`]: a rogue instance of
/// the service's name), not [`WRITE_DAC`] / [`WRITE_OWNER`]. Clients open with exactly this (not `GENERIC_WRITE`,
/// which maps to `FILE_APPEND_DATA` too and would be denied).
pub const SERVICE_CLIENT_ACCESS: u32 = FILE_GENERIC_READ | FILE_WRITE_DATA;
/// The right to create another instance of a pipe name (the same bit as `FILE_APPEND_DATA`).
pub const FILE_CREATE_PIPE_INSTANCE: u32 = windows_sys::Win32::Storage::FileSystem::FILE_CREATE_PIPE_INSTANCE;
pub const WRITE_DAC: u32 = windows_sys::Win32::Storage::FileSystem::WRITE_DAC;
pub const WRITE_OWNER: u32 = windows_sys::Win32::Storage::FileSystem::WRITE_OWNER;
/// The message of the `PermissionDenied` error for a service pipe not owned by SYSTEM.
pub const NOT_THE_SERVICE: &str = "the pipe is not served by the WinVPN Service";
/// How long [`dacl_of_name`] waits for a free instance.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// How long [`Listener::accept`] waits for the first bytes of a client that cannot be impersonated before it has
/// written (see [`peer_of`]).
pub const FIRST_WRITE_WAIT: Duration = Duration::from_secs(2);

/// Which descriptor a listener's instances get.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endpoint {
    /// A per-user pipe (the control API, the single-instance pipe): [`Listener::bind_with`]'s descriptor.
    User(NetworkLogons),
    /// The WinVPN Service: owner SYSTEM (the process must run as LocalSystem, else `PermissionDenied`); protected
    /// DACL: deny NETWORK (all), allow SYSTEM (all), allow INTERACTIVE [`SERVICE_CLIENT_ACCESS`].
    Service,
    /// The test-mode service: owner = this user, who also gets all access (to create instances); SYSTEM all;
    /// INTERACTIVE [`SERVICE_CLIENT_ACCESS`]; network logons allowed (the tests run over SSH). Refused
    /// (`PermissionDenied`) in a LocalSystem process: a pipe owned by SYSTEM always has the production DACL, so a
    /// client trusting SYSTEM never reaches a test endpoint.
    ServiceForTests,
}

/// Whom a client trusts to serve the pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerTrust {
    /// The server process runs as this user ([`connect`]'s rule).
    SameUser,
    /// The pipe object is owned by `NT AUTHORITY\SYSTEM`; opened with [`SERVICE_CLIENT_ACCESS`].
    LocalSystem,
}

/// `\\.\pipe\<prefix>-<this user's SID>`.
pub fn user_pipe_name(prefix: &str) -> io::Result<String> {
    let name = format!(r"{LOCAL_PREFIX}{prefix}-{}", Sid::current_user()?);
    local_name(&name)?;
    Ok(name)
}

/// The NUL-terminated UTF-16 name of a local pipe; anything else (a remote server, a file, a name with a path
/// separator that the path normalization would act on) is `InvalidInput`.
fn local_name(name: &str) -> io::Result<Vec<u16>> {
    let invalid = || io::Error::new(ErrorKind::InvalidInput, r"not a local pipe name (\\.\pipe\<name>)");
    let rest = name.strip_prefix(LOCAL_PREFIX).ok_or_else(invalid)?;
    if rest.is_empty() || rest == "." || rest == ".." || rest.contains(['\\', '/']) || rest.len() > 240 {
        return Err(invalid());
    }
    wide(OsStr::new(name))
}

/// The process on the other end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub sid: Sid,
    pub pid: u32,
    /// `None` if the image path could not be read.
    pub image: Option<PathBuf>,
}

/// Takes ownership of a handle a system call just returned (`null` and `INVALID_HANDLE_VALUE` are its last error).
fn owned(handle: HANDLE) -> io::Result<OwnedHandle> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a valid handle a system call just returned; nobody else owns it, the OwnedHandle closes it once.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

/// An unnamed manual-reset event, not signalled.
fn event() -> io::Result<OwnedHandle> {
    // SAFETY: no security attributes and no name (null pointers are allowed); the handle is owned by the result.
    owned(unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) })
}

/// Milliseconds for a wait, rounded up: at least 1 (a `Duration` below 1 ms still waits), never `INFINITE`.
fn millis(d: Duration) -> u32 {
    d.as_nanos().div_ceil(1_000_000).clamp(1, u128::from(INFINITE - 1)) as u32
}

/// Waits for `event` until it is signalled or, with a deadline, until the deadline has passed on the monotonic
/// clock. A Windows wait can come back up to a timer tick before its timeout, so a wait that times out early waits
/// again for the rest: `WAIT_TIMEOUT` only once `Instant::now() >= deadline`, never before.
fn wait_until(event: HANDLE, deadline: Option<Instant>) -> u32 {
    loop {
        let ms = match deadline {
            None => INFINITE,
            Some(deadline) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return WAIT_TIMEOUT;
                }
                millis(left)
            }
        };
        // SAFETY: the caller passes an event handle that stays open across the call.
        let waited = unsafe { WaitForSingleObject(event, ms) };
        if waited != WAIT_TIMEOUT || deadline.is_none() {
            return waited;
        }
    }
}

fn zeroed_overlapped(event: &OwnedHandle) -> Box<OVERLAPPED> {
    // SAFETY: OVERLAPPED is plain data (integers, a union of integers/pointer, a handle); all zero is valid.
    let mut ov: Box<OVERLAPPED> = Box::new(unsafe { std::mem::zeroed() });
    ov.hEvent = event.as_raw_handle();
    ov
}

/// Whether processes of this user in a network logon session (`NT AUTHORITY\NETWORK` in the token: an SSH or
/// WinRM session, a network share's logon) may open the pipe. Clients on other machines are rejected either way
/// (`PIPE_REJECT_REMOTE_CLIENTS`), and other users either way (the DACL admits only this user and SYSTEM).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkLogons {
    /// A deny ACE for `NT AUTHORITY\NETWORK` first: only this user's local (interactive, service, batch) logons.
    /// What [`Listener::bind`] uses.
    Deny,
    /// No deny ACE: this user's processes in any logon session on this machine.
    Allow,
}

/// The pipe's descriptor: owner = this user; protected DACL: (deny NETWORK, allow OWNER RIGHTS `READ_CONTROL`,)
/// allow this user (all access, needed to create further instances) and SYSTEM.
///
/// The OWNER RIGHTS entry (review L1) replaces the owner's implicit `READ_CONTROL | WRITE_DAC` by `READ_CONTROL`
/// alone, so nothing grants a logon of this user `WRITE_DAC` but the user's own entry, which the deny comes before:
/// a network logon of the owner can never rewrite the DACL. (Windows 11's access check already lets the deny win
/// over the implicit owner rights, as `a_network_logon_cannot_rewrite_the_default_pipes_dacl` shows without the entry
/// too; the entry makes the DACL say so instead of relying on that order.) The user's own entry still grants the
/// local logons everything.
fn descriptor(network: NetworkLogons) -> io::Result<Box<Descriptor>> {
    let (user, system, network_sid) = (Sid::current_user()?, Sid::local_system(), Sid::network());
    let owner_rights = Sid::owner_rights();
    let allow = [Ace::Allow(&user, FILE_ALL_ACCESS), Ace::Allow(&system, FILE_ALL_ACCESS)];
    let acl = match network {
        NetworkLogons::Deny => {
            let [a, b] = allow;
            Acl::new(&[Ace::Deny(&network_sid, FILE_ALL_ACCESS), Ace::Allow(&owner_rights, READ_CONTROL), a, b], 0)?
        }
        NetworkLogons::Allow => Acl::new(&allow, 0)?,
    };
    Descriptor::new(user, acl)
}

/// The service endpoint's DACL (spec 4.1) with `owner` as the descriptor's owner: SYSTEM in production
/// ([`Endpoint::Service`]); the unit tests pass this user to check the shape on a real pipe without being SYSTEM.
fn service_descriptor(owner: Sid) -> io::Result<Box<Descriptor>> {
    let (system, interactive, network) = (Sid::local_system(), Sid::interactive(), Sid::network());
    let acl = Acl::new(
        &[
            Ace::Deny(&network, FILE_ALL_ACCESS),
            Ace::Allow(&system, FILE_ALL_ACCESS),
            Ace::Allow(&interactive, SERVICE_CLIENT_ACCESS),
        ],
        0,
    )?;
    Descriptor::new(owner, acl)
}

fn endpoint_descriptor(endpoint: Endpoint) -> io::Result<Box<Descriptor>> {
    match endpoint {
        Endpoint::User(network) => descriptor(network),
        Endpoint::Service => {
            let system = Sid::local_system();
            // Fail closed: only SYSTEM can make SYSTEM the owner, and a pipe of another owner is no service pipe.
            if Sid::current_user()? != system {
                return Err(io::Error::new(ErrorKind::PermissionDenied, "the service endpoint needs LocalSystem"));
            }
            service_descriptor(system)
        }
        Endpoint::ServiceForTests => {
            let (user, system, interactive) = (Sid::current_user()?, Sid::local_system(), Sid::interactive());
            if user == system {
                return Err(io::Error::new(ErrorKind::PermissionDenied, "the test endpoint is not for LocalSystem"));
            }
            let acl = Acl::new(
                &[
                    Ace::Allow(&user, FILE_ALL_ACCESS),
                    Ace::Allow(&system, FILE_ALL_ACCESS),
                    Ace::Allow(&interactive, SERVICE_CLIENT_ACCESS),
                ],
                0,
            )?;
            Descriptor::new(user, acl)
        }
    }
}

fn create_instance(name: &[u16], d: &Descriptor, first: bool) -> io::Result<OwnedHandle> {
    let open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | if first { FILE_FLAG_FIRST_PIPE_INSTANCE } else { 0 };
    let pipe_mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
    // SAFETY: `name` is NUL-terminated; the attributes point into `d`, alive across the call.
    let h = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            open_mode,
            pipe_mode,
            PIPE_UNLIMITED_INSTANCES,
            BUFFER,
            BUFFER,
            0,
            d.attributes(),
        )
    };
    owned(h)
}

/// One pipe instance waiting for its client.
struct Pending {
    pipe: Option<OwnedHandle>,
    /// `hEvent` of the OVERLAPPED; dropped after `Drop::drop` has waited for the operation.
    _event: OwnedHandle,
    overlapped: Box<OVERLAPPED>,
    connected: bool,
}

/// How often [`Pending::start`] takes the instance back from a client that connected and closed again before the
/// connect started (`ERROR_NO_DATA`), before it gives up.
const GONE_CLIENTS: usize = 16;

impl Pending {
    fn start(pipe: OwnedHandle) -> io::Result<Pending> {
        let ev = event()?;
        let mut overlapped = zeroed_overlapped(&ev);
        let mut gone = 0;
        let connected = loop {
            // SAFETY: the pipe handle is open; the OVERLAPPED is boxed (a stable address) and its event alive, and
            // both outlive the operation: `Drop` cancels it and waits for its completion before they are freed.
            let ok = unsafe { ConnectNamedPipe(pipe.as_raw_handle(), &mut *overlapped) };
            if ok != 0 {
                break true;
            }
            // SAFETY: no preconditions.
            match unsafe { GetLastError() } {
                ERROR_IO_PENDING => break false,
                ERROR_PIPE_CONNECTED => break true,
                // A client opened the instance and closed it again between CreateNamedPipeW and this call (review
                // I8): disconnect its end and wait for the next client on the same instance, so the name stays ours.
                // No operation is in flight (the connect failed at once).
                ERROR_NO_DATA if gone < GONE_CLIENTS => {
                    gone += 1;
                    // SAFETY: the pipe handle is open; a failure shows in the next ConnectNamedPipe.
                    unsafe { DisconnectNamedPipe(pipe.as_raw_handle()) };
                }
                // The pipe and the event are closed by their OwnedHandles; no operation is in flight.
                e => return Err(io::Error::from_raw_os_error(e as i32)),
            }
        };
        Ok(Pending { pipe: Some(pipe), _event: ev, overlapped, connected })
    }
}

impl Drop for Pending {
    /// A connect still in flight is cancelled and waited for, so the kernel is done with the OVERLAPPED before the
    /// box and the event are freed (the pipe handle closes after this, as a field).
    fn drop(&mut self) {
        if let (Some(pipe), false) = (&self.pipe, self.connected) {
            let mut n = 0u32;
            // SAFETY: the handle and the OVERLAPPED are alive; cancelling an operation that already completed is
            // harmless (ERROR_NOT_FOUND), and the blocking GetOverlappedResult returns once the kernel released
            // the OVERLAPPED (its result, success or ERROR_OPERATION_ABORTED, does not matter here).
            unsafe {
                CancelIoEx(pipe.as_raw_handle(), &*self.overlapped);
                GetOverlappedResult(pipe.as_raw_handle(), &*self.overlapped, &mut n, 1);
            }
        }
    }
}

/// The server side of a pipe name. Dropping it closes the instance that waits for a client; connected streams
/// stay usable.
pub struct Listener {
    name: Vec<u16>,
    descriptor: Box<Descriptor>,
    pending: Mutex<Option<Pending>>,
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listener").field("name", &String::from_utf16_lossy(&self.name)).finish_non_exhaustive()
    }
}

// SAFETY: the raw pointers inside (the descriptor's SID/ACL pointers, the OVERLAPPED's event handle) point into heap
// memory and handles this Listener owns; nothing is tied to a thread (an overlapped ConnectNamedPipe is not
// cancelled when its thread exits), and the pending instance is only touched under the Mutex. The control server
// moves the listener to its accept thread (`ControlListener: Send`).
unsafe impl Send for Listener {}
// SAFETY: as above; every method takes `&self` and serializes through the Mutex (the descriptor is read-only).
unsafe impl Sync for Listener {}

impl Listener {
    /// Creates the first instance of `name` (`FILE_FLAG_FIRST_PIPE_INSTANCE`). A name that exists already (another
    /// server, or a squatter) is `AddrInUse`.
    pub fn bind(name: &str) -> io::Result<Listener> {
        Listener::bind_with(name, NetworkLogons::Deny)
    }

    /// [`Listener::bind`] with the choice of [`NetworkLogons`].
    pub fn bind_with(name: &str, network: NetworkLogons) -> io::Result<Listener> {
        Listener::bind_endpoint(name, Endpoint::User(network))
    }

    /// [`Listener::bind`] with the descriptor of `endpoint`. [`Endpoint::Service`] outside LocalSystem is
    /// `PermissionDenied` (nothing is created).
    pub fn bind_endpoint(name: &str, endpoint: Endpoint) -> io::Result<Listener> {
        let wide_name = local_name(name)?;
        Listener::bind_descriptor(wide_name, endpoint_descriptor(endpoint)?)
    }

    fn bind_descriptor(wide_name: Vec<u16>, descriptor: Box<Descriptor>) -> io::Result<Listener> {
        let first =
            create_instance(&wide_name, &descriptor, true).map_err(|e| match e.raw_os_error().map(|c| c as u32) {
                Some(ERROR_ACCESS_DENIED | ERROR_PIPE_BUSY) => {
                    io::Error::new(ErrorKind::AddrInUse, "the pipe name is in use")
                }
                _ => e,
            })?;
        let pending = Pending::start(first)?;
        Ok(Listener { name: wide_name, descriptor, pending: Mutex::new(Some(pending)) })
    }

    /// The DACL of the instance waiting for a client, as (allow, SID string) in order (tests and the security
    /// review).
    pub fn dacl_summary(&self) -> io::Result<Vec<(bool, String)>> {
        Ok(self.dacl_masks()?.into_iter().map(|a| (a.allow, a.sid)).collect())
    }

    /// The DACL of the instance waiting for a client, every ACE with its mask, in order (tests and the security
    /// review).
    pub fn dacl_masks(&self) -> io::Result<Vec<AceSummary>> {
        self.with_waiting_instance(|pipe| crate::file::dacl_aces(pipe.as_raw_handle(), true))
    }

    fn with_waiting_instance<T>(&self, f: impl FnOnce(&OwnedHandle) -> io::Result<T>) -> io::Result<T> {
        let mut slot = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.is_none() {
            *slot = Some(self.next_instance()?);
        }
        f(slot.as_ref().and_then(|p| p.pipe.as_ref()).expect("a pending instance has its pipe"))
    }

    fn next_instance(&self) -> io::Result<Pending> {
        Pending::start(create_instance(&self.name, &self.descriptor, false)?)
    }

    /// Waits at most `poll` for a client: `Ok(None)` when none came. The next instance is created before the
    /// connected one is handed out (or a failed one closed), so the name never disappears while the listener
    /// lives. The peer is `Err` when the client cannot be identified (it allowed less than identification-level
    /// impersonation, or it is gone): the caller closes such a client. Identifying a client that opened without
    /// SQOS can wait up to [`FIRST_WRITE_WAIT`] here; a server of many users accepts with
    /// [`Listener::accept_unidentified`] and identifies on the client's own thread.
    pub fn accept(&self, poll: Duration) -> io::Result<Option<(PipeStream, io::Result<Peer>)>> {
        Ok(self.accept_unidentified(poll)?.map(|stream| {
            let peer = stream.identify();
            (stream, peer)
        }))
    }

    /// [`Listener::accept`] without identifying the client: the stream returns as soon as a client connected, and
    /// the caller calls [`PipeStream::identify`] (which may wait up to [`FIRST_WRITE_WAIT`] for a client that
    /// opened without SQOS) off the accept loop, so a silent client never holds up the next ones (security review
    /// L-4). Nothing may be answered before the client is identified.
    pub fn accept_unidentified(&self, poll: Duration) -> io::Result<Option<PipeStream>> {
        let mut slot = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.is_none() {
            *slot = Some(self.next_instance()?);
        }
        let pending = slot.as_mut().expect("just filled");
        if !pending.connected {
            // SAFETY: the event belongs to the pending operation and is alive.
            match unsafe { WaitForSingleObject(pending.overlapped.hEvent, millis(poll)) } {
                WAIT_OBJECT_0 => {}
                WAIT_TIMEOUT => return Ok(None),
                _ => return Err(io::Error::last_os_error()),
            }
            let pipe = pending.pipe.as_ref().expect("a pending instance has its pipe").as_raw_handle();
            let mut n = 0u32;
            // SAFETY: the operation has completed (its event is signalled); the OVERLAPPED is alive.
            if unsafe { GetOverlappedResult(pipe, &*pending.overlapped, &mut n, 0) } == 0 {
                // The connect failed (the client left at once): replace the instance, then close the old one.
                let next = self.next_instance();
                let failed = slot.take();
                *slot = next.ok();
                drop(failed);
                return Ok(None);
            }
            pending.connected = true;
        }
        let next = self.next_instance();
        let mut done = slot.take().expect("a connected instance");
        let pipe = done.pipe.take().expect("its pipe");
        drop(done);
        // A failed next instance is retried by the next call; this client is served either way.
        *slot = next.ok();
        Ok(Some(PipeStream::new(pipe)))
    }
}

/// The client's process (the pid) and user (the SID, read on the second try when the first is `None`).
fn peer_of(pipe: HANDLE, sid: io::Result<Sid>) -> io::Result<Peer> {
    let mut pid = 0u32;
    // SAFETY: a connected server instance; `pid` is a valid out pointer.
    check(unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) })?;
    let sid = sid?;
    Ok(Peer { sid, pid, image: process_image(pid).ok() })
}

fn cannot_impersonate(r: &io::Result<Sid>) -> bool {
    matches!(r, Err(e) if e.raw_os_error() == Some(ERROR_CANNOT_IMPERSONATE as i32))
}

/// How many bytes the client has written within `wait` (0: none; a zero-length peek, nothing is consumed).
fn first_write(pipe: HANDLE, wait: Duration) -> u32 {
    let deadline = Instant::now() + wait;
    loop {
        let mut available = 0u32;
        // SAFETY: a connected server instance; a zero-length peek with a null buffer and only the "available" out
        // pointer, which is valid.
        let ok = unsafe {
            PeekNamedPipe(pipe, std::ptr::null_mut(), 0, std::ptr::null_mut(), &mut available, std::ptr::null_mut())
        };
        if ok == 0 || available > 0 || Instant::now() >= deadline {
            return if ok == 0 { 0 } else { available };
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Ends any impersonation of this thread; if that fails, the process aborts: it must never keep running as the
/// client.
fn revert_or_abort() {
    // SAFETY: no preconditions; reverting a thread that does not impersonate succeeds and does nothing.
    if unsafe { RevertToSelf() } == 0 {
        std::process::abort();
    }
}

/// The client's user, from identification-level impersonation. A client that allows only anonymous
/// impersonation has no readable token (`ERROR_CANT_OPEN_ANONYMOUS`): an error, never a default.
fn client_sid(pipe: HANDLE) -> io::Result<Sid> {
    // SAFETY: a connected server instance. The impersonation is ended right below on every path.
    let impersonated = unsafe { ImpersonateNamedPipeClient(pipe) };
    let impersonate_error = io::Error::last_os_error();
    if impersonated == 0 {
        revert_or_abort();
        return Err(impersonate_error);
    }
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: the pseudo handle of this thread needs no closing; `token` is a valid out pointer. `OpenAsSelf` =
    // TRUE: the access check uses the process's own context, not the client's.
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) };
    let open_error = io::Error::last_os_error();
    revert_or_abort();
    if opened == 0 {
        return Err(open_error);
    }
    let token = owned(token)?;
    Sid::of_token(token.as_handle())
}

fn open_process(pid: u32) -> io::Result<OwnedHandle> {
    // SAFETY: no pointers; the handle is owned by the result.
    owned(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) })
}

/// The full Win32 path of a process's executable.
pub fn process_image(pid: u32) -> io::Result<PathBuf> {
    let process = open_process(pid)?;
    let mut buf = vec![0u16; 32_768];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` holds `len` u16s; the call writes at most that many and sets `len` to the count written
    // (without the NUL).
    check(unsafe {
        QueryFullProcessImageNameW(process.as_raw_handle(), PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len)
    })?;
    let len = (len as usize).min(buf.len());
    Ok(PathBuf::from(OsString::from_wide(&buf[..len])))
}

/// The user a process runs as.
pub fn process_user(pid: u32) -> io::Result<Sid> {
    let process = open_process(pid)?;
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: an open process handle and a valid out pointer.
    check(unsafe { OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut token) })?;
    let token = owned(token)?;
    Sid::of_token(token.as_handle())
}

/// Connects as a client with identification-level impersonation only (`SECURITY_SQOS_PRESENT |
/// SECURITY_IDENTIFICATION`: the server can read who we are, never act as us), and refuses a server process of
/// another user, or one whose user cannot be read, with `PermissionDenied` ([`NOT_THIS_USER`]) before anything
/// is sent: a squatter can identify the client (its SID, groups and privileges, at identification level) but
/// never act as it, and it never gets to read what the client sends. `NotFound`: no such pipe. `TimedOut`: every
/// instance stayed busy until `timeout`. `InvalidInput`: not a local pipe name.
pub fn connect(name: &str, timeout: Duration) -> io::Result<PipeStream> {
    let pipe = open_client(&local_name(name)?, GENERIC_READ | GENERIC_WRITE, timeout)?;
    let not_this_user = || io::Error::new(ErrorKind::PermissionDenied, NOT_THIS_USER);
    let mut pid = 0u32;
    // SAFETY: a connected client handle; a valid out pointer.
    check(unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut pid) }).map_err(|_| not_this_user())?;
    let server = process_user(pid).map_err(|_| not_this_user())?;
    if server != Sid::current_user()? {
        return Err(not_this_user());
    }
    Ok(PipeStream::new(pipe))
}

/// [`connect`] with the choice of [`ServerTrust`]. With [`ServerTrust::LocalSystem`] the pipe is opened with
/// [`SERVICE_CLIENT_ACCESS`] (identification-level impersonation only, as [`connect`]) and the pipe object's owner
/// is read from the handle: anything but `NT AUTHORITY\SYSTEM`, or an owner that cannot be read, is
/// `PermissionDenied` ([`NOT_THE_SERVICE`]) before a byte is sent. Only SYSTEM (or a holder of
/// `SeRestorePrivilege`) can create an object owned by SYSTEM, so a squatter that took the name first never
/// receives a request; and the service's DACL lets no one else add an instance to the name.
pub fn connect_with(name: &str, timeout: Duration, trust: ServerTrust) -> io::Result<PipeStream> {
    match trust {
        ServerTrust::SameUser => connect(name, timeout),
        ServerTrust::LocalSystem => connect_owned_by(name, timeout, &Sid::local_system()),
    }
}

/// The service client with the expected owner as a parameter: SYSTEM in production; the unit tests pass this user
/// to run the whole path (access mask, owner read, I/O) without being SYSTEM.
fn connect_owned_by(name: &str, timeout: Duration, expected: &Sid) -> io::Result<PipeStream> {
    let pipe = open_client(&local_name(name)?, SERVICE_CLIENT_ACCESS, timeout)?;
    check_owner(crate::file::kernel_object_owner(pipe.as_handle()), expected)?;
    Ok(PipeStream::new(pipe))
}

/// The client's trust decision: `Ok` only for an owner that was read and is `expected`; a read failure or any
/// other owner is `PermissionDenied` ([`NOT_THE_SERVICE`]), never a default.
fn check_owner(owner: io::Result<Sid>, expected: &Sid) -> io::Result<()> {
    match owner {
        Ok(owner) if owner == *expected => Ok(()),
        _ => Err(io::Error::new(ErrorKind::PermissionDenied, NOT_THE_SERVICE)),
    }
}

/// The DACL of a pipe name, every ACE with its mask (the admin test of the installed service). Opens the name
/// with `READ_CONTROL` only and identification-level impersonation: this takes one instance as a client for the
/// moment of the read, which the server sees as a client that sends nothing and leaves.
pub fn dacl_of_name(name: &str) -> io::Result<Vec<AceSummary>> {
    let pipe = open_client(&local_name(name)?, READ_CONTROL, PROBE_TIMEOUT)?;
    crate::file::dacl_aces(pipe.as_raw_handle(), true)
}

/// Opens the client end of a local pipe with `access` and identification-level impersonation only, waiting until
/// `timeout` while every instance is busy. `NotFound`: no such pipe. `TimedOut`: still busy at the deadline.
fn open_client(wide_name: &[u16], access: u32, timeout: Duration) -> io::Result<OwnedHandle> {
    let deadline = Instant::now() + timeout;
    loop {
        // SAFETY: `wide_name` is NUL-terminated; no security attributes, no template.
        let h = unsafe {
            CreateFileW(
                wide_name.as_ptr(),
                access,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                std::ptr::null_mut(),
            )
        };
        if h != INVALID_HANDLE_VALUE {
            return owned(h);
        }
        // SAFETY: no preconditions.
        let error = unsafe { GetLastError() };
        if error != ERROR_PIPE_BUSY {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::from(ErrorKind::TimedOut));
        }
        // SAFETY: `wide_name` is NUL-terminated. The result does not matter: the loop tries again until the
        // deadline.
        unsafe { WaitNamedPipeW(wide_name.as_ptr(), millis(left)) };
    }
}

/// One end of a connected pipe. Clones share the handle, the timeouts and the shutdown state (like
/// `UnixStream::try_clone`).
#[derive(Clone)]
pub struct PipeStream(Arc<Inner>);

impl std::fmt::Debug for PipeStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let open = self.0.handle.read().unwrap_or_else(PoisonError::into_inner).is_some();
        f.debug_struct("PipeStream").field("open", &open).finish_non_exhaustive()
    }
}

struct Inner {
    /// `None` once shut down. Operations hold it shared for their whole duration; the close holds it exclusive,
    /// so a closed handle value is never used again.
    handle: RwLock<Option<OwnedHandle>>,
    read_timeout: Mutex<Option<Duration>>,
    write_timeout: Mutex<Option<Duration>>,
    read_shut: AtomicBool,
    /// The addresses of the OVERLAPPEDs of the reads in flight, for `shutdown(Read)`. A read registers itself
    /// under this lock after checking `read_shut`, and `shutdown(Read)` cancels under it after setting `read_shut`,
    /// so a read is either never started or cancelled; an entry is removed before its OVERLAPPED is freed.
    pending_reads: Mutex<Vec<usize>>,
    /// What [`PipeStream::identify`] had to read before the client could be impersonated; the next reads return it
    /// first.
    unread: Mutex<Vec<u8>>,
}

fn is_closed(e: &io::Error) -> bool {
    matches!(e.raw_os_error().map(|c| c as u32), Some(ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED | ERROR_NO_DATA))
}

fn is_aborted(e: &io::Error) -> bool {
    e.raw_os_error() == Some(ERROR_OPERATION_ABORTED as i32)
}

impl PipeStream {
    fn new(handle: OwnedHandle) -> PipeStream {
        PipeStream(Arc::new(Inner {
            handle: RwLock::new(Some(handle)),
            read_timeout: Mutex::new(None),
            write_timeout: Mutex::new(None),
            read_shut: AtomicBool::new(false),
            pending_reads: Mutex::new(Vec::new()),
            unread: Mutex::new(Vec::new()),
        }))
    }

    /// The server's view of its client. A client that opened the pipe without `SECURITY_SQOS_PRESENT` (Node's
    /// `net.connect`, most runtimes) can only be impersonated once the server has read from the pipe
    /// (`ERROR_CANNOT_IMPERSONATE` before). Such a client gets [`FIRST_WRITE_WAIT`] to write its first bytes, which
    /// are read, kept and returned by the next reads (nothing is lost), and it is identified then. A client that
    /// stays silent stays unidentified (the caller closes it). Found by the Windows smoke run (the control API's
    /// Node test client). Call it once, before anything else reads the stream ([`Listener::accept_unidentified`]).
    pub fn identify(&self) -> io::Result<Peer> {
        let guard = self.0.handle.read().unwrap_or_else(PoisonError::into_inner);
        let h =
            guard.as_ref().map(AsRawHandle::as_raw_handle).ok_or_else(|| io::Error::from(ErrorKind::NotConnected))?;
        let first = client_sid(h);
        if !cannot_impersonate(&first) {
            return peer_of(h, first);
        }
        let available = first_write(h, FIRST_WRITE_WAIT);
        drop(guard);
        if available == 0 {
            return Err(first.expect_err("checked above"));
        }
        let mut buf = vec![0u8; (available as usize).min(BUFFER as usize)];
        let n = self.read_some(&mut buf)?;
        buf.truncate(n);
        *self.0.unread.lock().unwrap_or_else(PoisonError::into_inner) = buf;
        let guard = self.0.handle.read().unwrap_or_else(PoisonError::into_inner);
        let h =
            guard.as_ref().map(AsRawHandle::as_raw_handle).ok_or_else(|| io::Error::from(ErrorKind::NotConnected))?;
        peer_of(h, client_sid(h))
    }

    pub fn try_clone(&self) -> PipeStream {
        self.clone()
    }

    /// `None`: no timeout. `Some(Duration::ZERO)` is `InvalidInput`, as for sockets.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        if timeout == Some(Duration::ZERO) {
            return Err(io::Error::from(ErrorKind::InvalidInput));
        }
        *self.0.read_timeout.lock().unwrap_or_else(PoisonError::into_inner) = timeout;
        Ok(())
    }

    /// `None`: no timeout. `Some(Duration::ZERO)` is `InvalidInput`, as for sockets.
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        if timeout == Some(Duration::ZERO) {
            return Err(io::Error::from(ErrorKind::InvalidInput));
        }
        *self.0.write_timeout.lock().unwrap_or_else(PoisonError::into_inner) = timeout;
        Ok(())
    }

    /// `Ok(0)` at the end: the peer closed, or this side shut reading down. A timeout is `TimedOut`; data that
    /// arrived while the timed-out read was being cancelled is returned, not dropped.
    pub fn read_some(&self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.0.read_shut.load(Ordering::SeqCst) {
            return Ok(0);
        }
        {
            let mut unread = self.0.unread.lock().unwrap_or_else(PoisonError::into_inner);
            if !unread.is_empty() {
                let n = buf.len().min(unread.len());
                buf[..n].copy_from_slice(&unread[..n]);
                unread.drain(..n);
                return Ok(n);
            }
        }
        let guard = self.0.handle.read().unwrap_or_else(PoisonError::into_inner);
        let Some(h) = guard.as_ref().map(AsRawHandle::as_raw_handle) else { return Ok(0) };
        let timeout = *self.0.read_timeout.lock().unwrap_or_else(PoisonError::into_inner);
        let len = buf.len().min(u32::MAX as usize) as u32;
        let ptr = buf.as_mut_ptr();
        let track = Track { list: &self.0.pending_reads, shut: &self.0.read_shut };
        // SAFETY: `h` is open (the read guard is held across the operation); `buf` is valid for writes of `len`
        // bytes and stays borrowed until `overlapped` returns, which is after the kernel finished with it.
        let result =
            overlapped(h, timeout, Some(track), |ov| unsafe { ReadFile(h, ptr, len, std::ptr::null_mut(), ov) });
        match result {
            Ok(Some(n)) => Ok(n as usize),
            // Shut down before the read started.
            Ok(None) => Ok(0),
            Err(e) if is_closed(&e) => Ok(0),
            Err(e) if is_aborted(&e) && self.0.read_shut.load(Ordering::SeqCst) => Ok(0),
            Err(e) => Err(e),
        }
    }

    /// A closed pipe (the peer's or ours) is `BrokenPipe`. A timeout is `TimedOut`.
    pub fn write_some(&self, buf: &[u8]) -> io::Result<usize> {
        let guard = self.0.handle.read().unwrap_or_else(PoisonError::into_inner);
        let Some(h) = guard.as_ref().map(AsRawHandle::as_raw_handle) else {
            return Err(io::Error::from(ErrorKind::BrokenPipe));
        };
        if buf.is_empty() {
            return Ok(0);
        }
        let timeout = *self.0.write_timeout.lock().unwrap_or_else(PoisonError::into_inner);
        let len = buf.len().min(u32::MAX as usize) as u32;
        // SAFETY: `h` is open (the read guard is held across the operation); `buf` is valid for reads of `len`
        // bytes and stays borrowed until `overlapped` returns, which is after the kernel finished with it.
        let result =
            overlapped(h, timeout, None, |ov| unsafe { WriteFile(h, buf.as_ptr(), len, std::ptr::null_mut(), ov) });
        match result {
            Ok(n) => Ok(n.unwrap_or(0) as usize),
            Err(e) if is_closed(&e) => Err(io::Error::new(ErrorKind::BrokenPipe, e)),
            // Cancelled by `shutdown(Write | Both)`.
            Err(e) if is_aborted(&e) && self.0.handle_closing() => Err(io::Error::new(ErrorKind::BrokenPipe, e)),
            Err(e) => Err(e),
        }
    }

    /// `Read`: reads return `Ok(0)` from now on (a blocked read too). `Write` and `Both`: also every operation in
    /// flight ends and the handle is closed (not disconnected: the peer still reads what was sent, then the end);
    /// a pipe has no half-close, so `Write` is `Both`.
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.0.read_shut.store(true, Ordering::SeqCst);
        if how == Shutdown::Read {
            let guard = self.0.handle.read().unwrap_or_else(PoisonError::into_inner);
            if let Some(h) = guard.as_ref() {
                let reads = self.0.pending_reads.lock().unwrap_or_else(PoisonError::into_inner);
                for &ov in reads.iter() {
                    // SAFETY: the handle is open (guard held); each OVERLAPPED in the list is alive (an entry is
                    // removed under this lock before its OVERLAPPED is freed); cancelling an operation that has
                    // completed already is harmless (ERROR_NOT_FOUND).
                    unsafe { CancelIoEx(h.as_raw_handle(), ov as *const OVERLAPPED) };
                }
            }
            return Ok(());
        }
        loop {
            if let Some(h) = self.0.handle.read().unwrap_or_else(PoisonError::into_inner).as_ref() {
                // SAFETY: the handle is open (guard held); a null OVERLAPPED cancels every operation on the handle
                // from any thread; each operation then waits for its own cancellation and releases the guard.
                unsafe { CancelIoEx(h.as_raw_handle(), std::ptr::null()) };
            }
            match self.0.handle.try_write() {
                Ok(mut guard) => {
                    guard.take();
                    return Ok(());
                }
                // An operation started after the cancel: cancel again (it is at most a few microseconds old).
                Err(TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(1)),
                Err(TryLockError::Poisoned(p)) => {
                    p.into_inner().take();
                    return Ok(());
                }
            }
        }
    }

    /// Still connected, without blocking and without consuming data.
    pub fn peer_connected(&self) -> bool {
        let guard = self.0.handle.read().unwrap_or_else(PoisonError::into_inner);
        let Some(h) = guard.as_ref() else { return false };
        let mut available = 0u32;
        // SAFETY: the handle is open (guard held); a zero-length peek with a null buffer and only the "available"
        // out pointer, which is valid.
        unsafe {
            PeekNamedPipe(
                h.as_raw_handle(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            ) != 0
        }
    }
}

impl Inner {
    /// `shutdown(Write | Both)` has started (reads are shut and a close is coming).
    fn handle_closing(&self) -> bool {
        self.read_shut.load(Ordering::SeqCst)
    }
}

/// How a read registers itself for `shutdown(Read)`.
struct Track<'a> {
    list: &'a Mutex<Vec<usize>>,
    shut: &'a AtomicBool,
}

/// One overlapped operation with its own event, waited for at most `timeout`. A timed-out operation is cancelled
/// and waited for (the kernel must be done with the buffer and the OVERLAPPED); if it completed in that race its
/// result counts. `Ok(None)`: a tracked read that was not started because reading is shut down.
fn overlapped(
    h: HANDLE,
    timeout: Option<Duration>,
    track: Option<Track<'_>>,
    start: impl FnOnce(*mut OVERLAPPED) -> windows_sys::core::BOOL,
) -> io::Result<Option<u32>> {
    // Before the operation starts: the timeout counts from here, so the operation never gets less than it.
    let deadline = timeout.map(|t| Instant::now() + t);
    let ev = event()?;
    let mut ov = zeroed_overlapped(&ev);
    let ptr: *mut OVERLAPPED = &mut *ov;
    // Registration and start under the tracking lock: `shutdown(Read)` either sees this read or is seen by it.
    let started = {
        let mut list = track.as_ref().map(|t| t.list.lock().unwrap_or_else(PoisonError::into_inner));
        if let (Some(t), Some(list)) = (&track, list.as_mut()) {
            if t.shut.load(Ordering::SeqCst) {
                return Ok(None);
            }
            list.push(ptr as usize);
        }
        let ok = start(ptr);
        // SAFETY: no preconditions; read right after the call that set it.
        let error = if ok != 0 { 0 } else { unsafe { GetLastError() } };
        (ok, error)
    };
    let finish = |wait: bool| -> io::Result<u32> {
        let mut n = 0u32;
        // SAFETY: `ptr` is alive (boxed in `ov`, dropped after this function's last use of it); `wait` blocks
        // until the kernel is done with the operation.
        check(unsafe { GetOverlappedResult(h, ptr, &mut n, i32::from(wait)) }).map(|()| n)
    };
    let result = match started {
        (ok, _) if ok != 0 => finish(true),
        (_, error) if error != ERROR_IO_PENDING => Err(io::Error::from_raw_os_error(error as i32)),
        _ => {
            // The event belongs to this operation and is alive until the end of this function.
            match wait_until(ev.as_raw_handle(), deadline) {
                WAIT_OBJECT_0 => finish(true),
                waited => {
                    // SAFETY: `h` is open (the caller holds its guard); cancels only this operation.
                    unsafe { CancelIoEx(h, ptr) };
                    match finish(true) {
                        Ok(n) => Ok(n),
                        Err(e) if waited == WAIT_TIMEOUT && is_aborted(&e) => Err(io::Error::from(ErrorKind::TimedOut)),
                        Err(e) => Err(e),
                    }
                }
            }
        }
    };
    if let Some(t) = &track {
        t.list.lock().unwrap_or_else(PoisonError::into_inner).retain(|&p| p != ptr as usize);
    }
    // Only now, with the operation finished and unregistered, are the OVERLAPPED and its event freed.
    drop(ov);
    drop(ev);
    result.map(Some)
}

impl Read for &PipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_some(buf)
    }
}

impl Write for &PipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_some(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for PipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_some(buf)
    }
}

impl Write for PipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_some(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The pipe's DACL as (allow, SID string) in order (tests and the security review).
pub fn dacl_summary(stream: &PipeStream) -> io::Result<Vec<(bool, String)>> {
    let guard = stream.0.handle.read().unwrap_or_else(PoisonError::into_inner);
    let h = guard.as_ref().ok_or_else(|| io::Error::from(ErrorKind::NotConnected))?;
    crate::file::dacl_entries(h.as_raw_handle(), true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::{
        GetTokenInformation, SECURITY_IMPERSONATION_LEVEL, SecurityIdentification, TokenImpersonationLevel,
    };

    /// A client that opens the first instance and closes it before the connect starts makes `ConnectNamedPipe`
    /// fail with `ERROR_NO_DATA`; the instance is taken back and serves the next client (review I8).
    #[test]
    fn a_client_gone_before_the_connect_does_not_fail_the_bind() {
        let name = format!(r"\\.\pipe\winsys-unit-gone-{}", std::process::id());
        let wide_name = local_name(&name).unwrap();
        let d = descriptor(NetworkLogons::Allow).unwrap();
        let first = create_instance(&wide_name, &d, true).unwrap();
        drop(std::fs::OpenOptions::new().read(true).write(true).open(&name).expect("the instance is free"));
        let pending = Pending::start(first).expect("ERROR_NO_DATA is taken back");
        let listener = Listener { name: wide_name, descriptor: d, pending: Mutex::new(Some(pending)) };
        let client_name = name.clone();
        let client = std::thread::spawn(move || connect(&client_name, Duration::from_secs(5)).unwrap());
        let (mut server, _) = listener.accept(Duration::from_secs(5)).unwrap().expect("the next client");
        let mut client = client.join().unwrap();
        client.write_all(b"x").unwrap();
        let mut byte = [0u8; 1];
        server.read_exact(&mut byte).unwrap();
        assert_eq!(&byte, b"x");
    }

    #[test]
    fn local_names_only() {
        assert!(local_name(r"\\.\pipe\WinVPN-control-S-1-5-21-1").is_ok());
        for bad in [r"\\.\pipe\", r"\\.\pipe\a\b", r"\\.\pipe\a/b", r"\\.\pipe\..", r"\\srv\pipe\a", r"\\?\pipe\a", "a"]
        {
            assert_eq!(local_name(bad).unwrap_err().kind(), ErrorKind::InvalidInput, "{bad}");
        }
        assert_eq!(local_name("\\\\.\\pipe\\a\0b").unwrap_err().kind(), ErrorKind::InvalidInput);
    }

    /// The impersonation level the server gets from its client.
    fn impersonation_level(server: &PipeStream) -> SECURITY_IMPERSONATION_LEVEL {
        let guard = server.0.handle.read().unwrap();
        let pipe = guard.as_ref().unwrap().as_raw_handle();
        // SAFETY: a connected server instance; reverted right after the token is opened (abort if that fails).
        check(unsafe { ImpersonateNamedPipeClient(pipe) }).unwrap();
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: valid out pointer; the pseudo handle needs no closing.
        let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) };
        revert_or_abort();
        check(opened).unwrap();
        let token = owned(token).unwrap();
        let mut level: SECURITY_IMPERSONATION_LEVEL = 0;
        let mut len = 0u32;
        // SAFETY: an open token; `level` is valid for writes of its size.
        check(unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenImpersonationLevel,
                (&mut level as *mut SECURITY_IMPERSONATION_LEVEL).cast(),
                size_of::<SECURITY_IMPERSONATION_LEVEL>() as u32,
                &mut len,
            )
        })
        .unwrap();
        level
    }

    /// [`connect`] lets the server identify it and nothing more: the impersonation token the server gets is at
    /// identification level, so a server cannot act as the client.
    #[test]
    fn connect_allows_identification_only() {
        let name = format!(r"\\.\pipe\winsys-unit-{}", std::process::id());
        let listener = Listener::bind_with(&name, NetworkLogons::Allow).unwrap();
        let client = std::thread::spawn(move || connect(&name, Duration::from_secs(5)).unwrap());
        let (server, _) = listener.accept(Duration::from_secs(5)).unwrap().expect("the client");
        let _client = client.join().unwrap();
        assert_eq!(impersonation_level(&server), SecurityIdentification);
    }

    fn unit_name(what: &str) -> String {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        format!(r"\\.\pipe\winsys-unit-{what}-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst))
    }

    /// Whether this process's token has `NT AUTHORITY\NETWORK` (S-1-5-2): an SSH session has, a desktop session not.
    fn in_network_logon() -> bool {
        let out = std::process::Command::new("whoami").args(["/groups", "/fo", "csv", "/nh"]).output().unwrap();
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stdout).contains("\"S-1-5-2\"")
    }

    fn ace(allow: bool, sid: &Sid, mask: u32) -> AceSummary {
        AceSummary { allow, sid: sid.to_string(), mask, flags: 0 }
    }

    /// The client's trust decision fails closed: an unreadable owner and every owner but the expected one are
    /// refused with the same error.
    #[test]
    fn the_owner_check_fails_closed() {
        let (system, me) = (Sid::local_system(), Sid::current_user().unwrap());
        assert!(check_owner(Ok(system.clone()), &system).is_ok());
        for owner in [Ok(me.clone()), Ok(Sid::builtin_administrators()), Err(io::Error::from(ErrorKind::Other))] {
            let e = check_owner(owner, &system).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::PermissionDenied);
            assert_eq!(e.to_string(), NOT_THE_SERVICE);
        }
    }

    #[test]
    fn the_client_mask_is_read_and_write_data_only() {
        assert_eq!(SERVICE_CLIENT_ACCESS, 0x0012_008B);
        assert_eq!(FILE_CREATE_PIPE_INSTANCE, windows_sys::Win32::Storage::FileSystem::FILE_APPEND_DATA);
        assert_eq!(SERVICE_CLIENT_ACCESS & (FILE_CREATE_PIPE_INSTANCE | WRITE_DAC | WRITE_OWNER), 0);
        assert_ne!(SERVICE_CLIENT_ACCESS & READ_CONTROL, 0, "the client reads the owner");
    }

    /// The production descriptor exactly as spec 4.1 and the plan say: owner SYSTEM; deny NETWORK; allow SYSTEM
    /// all; allow INTERACTIVE the client mask; nothing inherited, nothing else.
    #[test]
    fn the_service_descriptor_has_the_spec_shape() {
        let (system, interactive, network) = (Sid::local_system(), Sid::interactive(), Sid::network());
        let d = service_descriptor(system.clone()).unwrap();
        assert_eq!(d.owner(), &system);
        assert_eq!(
            crate::file::descriptor_aces(&d).unwrap(),
            [
                ace(false, &network, FILE_ALL_ACCESS),
                ace(true, &system, FILE_ALL_ACCESS),
                ace(true, &interactive, SERVICE_CLIENT_ACCESS),
            ]
        );
    }

    /// The production shape on a real pipe, with this user as a test-only owner (a standard user cannot make SYSTEM
    /// the owner): the kernel keeps owner and DACL as given. Over SSH (a network logon) the deny wins even for the
    /// owner; in a desktop session INTERACTIVE's grant alone lets the service client open and talk.
    #[test]
    fn the_service_shape_on_a_real_pipe() {
        let (me, system, interactive, network) =
            (Sid::current_user().unwrap(), Sid::local_system(), Sid::interactive(), Sid::network());
        let name = unit_name("service-shape");
        let listener =
            Listener::bind_descriptor(local_name(&name).unwrap(), service_descriptor(me.clone()).unwrap()).unwrap();
        let owner = listener.with_waiting_instance(|p| crate::file::kernel_object_owner(p.as_handle())).unwrap();
        assert_eq!(owner, me);
        assert_eq!(
            listener.dacl_masks().unwrap(),
            [
                ace(false, &network, FILE_ALL_ACCESS),
                ace(true, &system, FILE_ALL_ACCESS),
                ace(true, &interactive, SERVICE_CLIENT_ACCESS),
            ]
        );
        let opened = connect_owned_by(&name, Duration::from_secs(2), &me);
        if in_network_logon() {
            assert_eq!(opened.unwrap_err().kind(), ErrorKind::PermissionDenied);
        } else {
            let client = opened.expect("INTERACTIVE may open with the client mask");
            let (server, peer) = listener.accept(Duration::from_secs(5)).unwrap().expect("the client");
            assert_eq!(peer.unwrap().sid, me);
            (&client).write_all(b"x").unwrap();
            let mut byte = [0u8; 1];
            (&server).read_exact(&mut byte).unwrap();
            assert_eq!(&byte, b"x");
        }
    }

    /// Whoever holds exactly the client grant (here this user, standing in for INTERACTIVE, with OWNER RIGHTS
    /// taking away the owner's implicit `WRITE_DAC`) can open with the client mask, talk and be identified, but
    /// cannot add an instance to the name (a rogue server) nor open with `GENERIC_WRITE`.
    #[test]
    fn the_client_grant_opens_and_talks_but_never_creates_an_instance() {
        let me = Sid::current_user().unwrap();
        let name = unit_name("client-grant");
        let wide_name = local_name(&name).unwrap();
        let acl =
            Acl::new(&[Ace::Allow(&Sid::owner_rights(), READ_CONTROL), Ace::Allow(&me, SERVICE_CLIENT_ACCESS)], 0)
                .unwrap();
        let listener = Listener::bind_descriptor(wide_name.clone(), Descriptor::new(me.clone(), acl).unwrap()).unwrap();
        let rogue =
            create_instance(&wide_name, &Descriptor::new(me.clone(), Acl::new(&[], 0).unwrap()).unwrap(), false);
        assert_eq!(rogue.unwrap_err().raw_os_error(), Some(ERROR_ACCESS_DENIED as i32));
        let generic_write = std::fs::OpenOptions::new().read(true).write(true).open(&name).unwrap_err();
        assert_eq!(generic_write.kind(), ErrorKind::PermissionDenied);
        let client_name = name.clone();
        let expected = me.clone();
        let client = std::thread::spawn(move || connect_owned_by(&client_name, Duration::from_secs(5), &expected));
        let (server, peer) = listener.accept(Duration::from_secs(5)).unwrap().expect("the client");
        let client = client.join().unwrap().expect("the client mask is enough");
        assert_eq!(peer.unwrap().sid, me);
        assert_eq!(impersonation_level(&server), SecurityIdentification);
        (&client).write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        (&server).read_exact(&mut buf).unwrap();
        (&server).write_all(&buf).unwrap();
        (&client).read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
    }

    /// The service client refuses a pipe whose owner is not the expected one, before it sends anything: the server
    /// reads the end of the stream, never a byte.
    #[test]
    fn the_service_client_refuses_another_owner_before_sending() {
        let name = unit_name("other-owner");
        let listener = Listener::bind_endpoint(&name, Endpoint::ServiceForTests).unwrap();
        let client_name = name.clone();
        let client = std::thread::spawn(move || {
            connect_owned_by(&client_name, Duration::from_secs(5), &Sid::builtin_administrators())
        });
        let (server, _) = listener.accept(Duration::from_secs(5)).unwrap().expect("the client");
        let e = client.join().unwrap().unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PermissionDenied);
        assert_eq!(e.to_string(), NOT_THE_SERVICE);
        server.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = [0u8; 1];
        assert_eq!((&server).read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn dacl_of_name_reads_the_pipes_dacl() {
        let name = unit_name("dacl-of-name");
        let listener = Listener::bind_endpoint(&name, Endpoint::ServiceForTests).unwrap();
        let expected = listener.dacl_masks().unwrap();
        assert_eq!(dacl_of_name(&name).unwrap(), expected);
    }
}
