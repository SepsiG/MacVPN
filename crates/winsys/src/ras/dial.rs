//! Dialling (`RasDialW` with a `RasDialFunc2` callback), hanging up, the connection list and status, the tunnel's
//! IPv4 address, Windows' error texts and Windows' own sign-in dialog (`RasDialDlgW`).
//!
//! Dial, status, list and hang-up work only in an interactive logon session (see the module docs).

use super::entry::entry_name;
use super::{
    ERROR_INVALID_HANDLE, ERROR_NO_CONNECTION, Error, Phonebook, Result, field_text, fill, guid_bytes, rc, wipe,
};
use crate::dll::Library;
use std::collections::HashMap;
use std::ffi::c_void;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use windows_sys::Win32::NetworkManagement::Rras::{
    HRASCONN, PROJECTION_INFO_TYPE_IKEv2, PROJECTION_INFO_TYPE_PPP, RAS_PROJECTION_INFO, RAS_STATS, RASAPIVERSION_601,
    RASCONNSTATE, RASCONNSTATUSW, RASCONNW, RASCS_Connected, RASDIALDLG, RASDIALPARAMSW, RasDialW, RasEnumConnectionsW,
    RasGetConnectStatusW, RasGetConnectionStatistics, RasGetEntryDialParamsW, RasGetErrorStringW,
    RasGetProjectionInfoEx, RasHangUpW,
};
use windows_sys::core::{BOOL, PCWSTR};

/// `ERROR_BUFFER_TOO_SMALL`
const ERROR_BUFFER_TOO_SMALL: u32 = 603;
/// At most this many connections are listed.
const MAX_CONNECTIONS: usize = 256;
/// `RasDialW`'s notifier type of a `RasDialFunc2`.
const NOTIFIER_RASDIALFUNC2: u32 = 2;
/// How often [`hang_up`] asks whether the handle is released (Microsoft: poll `RasGetConnectStatus`).
const HANG_UP_POLL: Duration = Duration::from_millis(50);

/// A RAS connection handle (`HRASCONN`). Valid until the connection is hung up and released.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Handle(usize);

impl Handle {
    fn raw(self) -> HRASCONN {
        self.0 as HRASCONN
    }

    /// The handle's value (for logs and maps).
    pub fn value(self) -> usize {
        self.0
    }
}

/// The credentials of one dial: given to `RasDialW` only (nothing is stored in Windows). The caller keeps the
/// strings in its own wiped storage; the `RASDIALPARAMSW` they are copied into is wiped right after the call.
#[derive(Clone, Copy, Default)]
pub struct DialParams<'a> {
    pub user: &'a str,
    pub password: &'a str,
    pub domain: &'a str,
}

impl<'a> DialParams<'a> {
    /// A user name and a password, no domain.
    pub fn user(user: &'a str, password: &'a str) -> DialParams<'a> {
        DialParams { user, password, domain: "" }
    }
}

impl std::fmt::Debug for DialParams<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DialParams")
            .field("user", &self.user)
            .field("password", &if self.password.is_empty() { "" } else { "<set>" })
            .field("domain", &self.domain)
            .finish()
    }
}

/// What the dial callback reports (on a RAS thread).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialEvent {
    /// A `RASCONNSTATE` step (`RASCS_*`; `RASCS_Disconnected` without an error too).
    State(u32),
    /// `RASCS_Connected`: the last event of a successful dial.
    Connected,
    /// The dial failed (a RAS, Win32 or HRESULT code): the last event. The handle must still be hung up.
    Failed { code: u32 },
}

type Callback = dyn Fn(DialEvent) + Send + Sync;

struct Registration {
    callback: Box<Callback>,
    /// The dial's handle once `RasDialW` returned it (0 before): events of another handle are dropped.
    handle: AtomicUsize,
}

/// The live dials' callbacks by `dwCallbackId`: the callback finds its closure here, so a late event of a dial
/// whose [`Dial`] was dropped finds nothing and is dropped.
fn dials() -> &'static Mutex<HashMap<usize, Arc<Registration>>> {
    static DIALS: OnceLock<Mutex<HashMap<usize, Arc<Registration>>>> = OnceLock::new();
    DIALS.get_or_init(Default::default)
}

fn registration(id: usize) -> Option<Arc<Registration>> {
    dials().lock().unwrap_or_else(|e| e.into_inner()).get(&id).cloned()
}

/// The `RasDialFunc2` of every dial. Never calls back into RAS (Microsoft: no `RasHangUp` from the callback).
unsafe extern "system" fn on_dial(
    callback_id: usize,
    _sub_entry: u32,
    hrasconn: HRASCONN,
    _message: u32,
    state: RASCONNSTATE,
    error: u32,
    _extended_error: u32,
) -> u32 {
    if let Some(reg) = registration(callback_id) {
        let known = reg.handle.load(Ordering::SeqCst);
        if known == 0 || known == hrasconn as usize {
            let event = if error != 0 {
                DialEvent::Failed { code: error }
            } else if state == RASCS_Connected {
                DialEvent::Connected
            } else {
                DialEvent::State(state as u32)
            };
            // A panic must not unwind into Windows' thread.
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (reg.callback)(event)));
        }
    }
    1 // keep sending callbacks
}

/// A `RASDIALPARAMSW` on the heap, wiped on drop (it holds the password). `packed(4)` on 64-bit: its fields are
/// only written through raw pointers.
struct DialBuffer(Box<RASDIALPARAMSW>);

impl DialBuffer {
    fn ptr(&mut self) -> *mut RASDIALPARAMSW {
        &mut *self.0
    }

    /// A zeroed structure with `dwSize` and the entry name set.
    fn for_entry(name: &str) -> Result<DialBuffer> {
        entry_name(name)?;
        let mut buf = DialBuffer(Box::<RASDIALPARAMSW>::default());
        let p = buf.ptr();
        // SAFETY: `p` is the boxed structure; `addr_of_mut!` takes field addresses without references (packed
        // fields), and every write is unaligned-safe (`write_unaligned` / `fill`) and inside its field.
        unsafe {
            std::ptr::addr_of_mut!((*p).dwSize).write_unaligned(std::mem::size_of::<RASDIALPARAMSW>() as u32);
            fill(std::ptr::addr_of_mut!((*p).szEntryName).cast(), 257, name, "the entry name")?;
        }
        Ok(buf)
    }

    /// Fills the structure with what Windows saved for its entry in `book` (`RasGetEntryDialParamsW`); whether a
    /// password was saved.
    fn load_saved(&mut self, book: &Phonebook) -> Result<bool> {
        let mut password: BOOL = 0;
        // SAFETY: the phonebook path is NUL-terminated (or null) and alive across the call; `self` is a complete
        // RASDIALPARAMSW with `dwSize` and `szEntryName` set; `password` receives a BOOL.
        let code = unsafe { RasGetEntryDialParamsW(book.as_pcwstr(), self.ptr(), &mut password) };
        rc("RasGetEntryDialParamsW", code)?;
        Ok(password != 0)
    }
}

impl Drop for DialBuffer {
    fn drop(&mut self) {
        let p = self.ptr();
        // SAFETY: `p` points to the whole boxed structure, valid for writes of its size.
        unsafe { wipe(p.cast(), std::mem::size_of::<RASDIALPARAMSW>()) };
    }
}

/// A dial in progress or done. Dropping it stops delivering its events; the connection itself stays (RasMan owns
/// it): hang it up first when it should end.
#[derive(Debug)]
pub struct Dial {
    id: usize,
    handle: Handle,
}

impl Dial {
    pub fn handle(&self) -> Handle {
        self.handle
    }

    /// [`hang_up`] of this dial's connection.
    pub fn hang_up_and_wait(&self, timeout: Duration) -> Result<()> {
        hang_up(self.handle, timeout)
    }
}

impl Drop for Dial {
    fn drop(&mut self) {
        dials().lock().unwrap_or_else(|e| e.into_inner()).remove(&self.id);
    }
}

/// Dials the entry `name` of `book` asynchronously; `on_event` receives the dial's steps on a RAS thread (keep it
/// short, never call RAS from it). `Err` when `RasDialW` refuses at once (any handle it gave is hung up).
pub fn dial(
    book: &Phonebook,
    name: &str,
    params: &DialParams<'_>,
    on_event: impl Fn(DialEvent) + Send + Sync + 'static,
) -> Result<Dial> {
    let mut buf = DialBuffer::for_entry(name)?;
    let p = buf.ptr();
    // SAFETY: `p` is the boxed structure; `addr_of_mut!` takes field addresses without references (packed
    // fields), and every write is unaligned-safe (`fill`) and inside its field.
    unsafe {
        fill(std::ptr::addr_of_mut!((*p).szUserName).cast(), 257, params.user, "the user name")?;
        fill(std::ptr::addr_of_mut!((*p).szPassword).cast(), 257, params.password, "the password")?;
        fill(std::ptr::addr_of_mut!((*p).szDomain).cast(), 16, params.domain, "the domain")?;
    }
    start(book, buf, on_event)
}

/// What Windows saved for signing in to an entry (`RasGetEntryDialParamsW`; the user's own entries: what they
/// typed and let Windows remember). The password itself never leaves winsys.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Saved {
    pub user: String,
    pub domain: String,
    /// Windows has a saved password for the entry.
    pub password: bool,
}

/// What Windows saved for signing in to the entry `name` of `book` (nothing is changed). The saved password is
/// wiped at once; only whether there is one is returned.
pub fn saved_credentials(book: &Phonebook, name: &str) -> Result<Saved> {
    let mut buf = DialBuffer::for_entry(name)?;
    let password = buf.load_saved(book)?;
    let p = buf.ptr();
    // SAFETY: `p` is the boxed, initialised structure; the arrays are copied out unaligned (packed fields).
    let (user, domain) = unsafe {
        (std::ptr::addr_of!((*p).szUserName).read_unaligned(), std::ptr::addr_of!((*p).szDomain).read_unaligned())
    };
    Ok(Saved { user: field_text(&user), domain: field_text(&domain), password })
}

/// Dials the entry `name` of `book` with what Windows saved for it ([`saved_credentials`]): the saved user name and
/// domain, and `password` when given, else Windows' saved password (passed to `RasDialW` as Windows returned it;
/// it never leaves winsys). `Ok(None)`: no `password` given and Windows saved none (nothing was dialled). As
/// [`dial`] otherwise.
pub fn dial_saved(
    book: &Phonebook,
    name: &str,
    password: Option<&str>,
    on_event: impl Fn(DialEvent) + Send + Sync + 'static,
) -> Result<Option<Dial>> {
    let mut buf = DialBuffer::for_entry(name)?;
    let saved = buf.load_saved(book)?;
    match password {
        Some(password) => {
            let p = buf.ptr();
            // SAFETY: as in `dial`: an unaligned-safe write inside the field.
            unsafe { fill(std::ptr::addr_of_mut!((*p).szPassword).cast(), 257, password, "the password")? };
        }
        None if !saved => return Ok(None),
        None => {}
    }
    start(book, buf, on_event).map(Some)
}

/// `RasDialW` with the filled `buf` (its callback ID is set here); `buf` is wiped right after the call.
fn start(book: &Phonebook, mut buf: DialBuffer, on_event: impl Fn(DialEvent) + Send + Sync + 'static) -> Result<Dial> {
    static NEXT_ID: AtomicUsize = AtomicUsize::new(1);
    let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
    let p = buf.ptr();
    // SAFETY: an unaligned write of a field of the boxed structure.
    unsafe { std::ptr::addr_of_mut!((*p).dwCallbackId).write_unaligned(id) };
    let reg = Arc::new(Registration { callback: Box::new(on_event), handle: AtomicUsize::new(0) });
    dials().lock().unwrap_or_else(|e| e.into_inner()).insert(id, reg.clone());
    let mut dial = Dial { id, handle: Handle(0) };
    let mut h: HRASCONN = std::ptr::null_mut();
    let callback: unsafe extern "system" fn(usize, u32, HRASCONN, u32, RASCONNSTATE, u32, u32) -> u32 = on_dial;
    // SAFETY: no extensions; the phonebook path is NUL-terminated (or null) and alive across the call; `p` is a
    // complete RASDIALPARAMSW with `dwSize` set; `callback` is a RasDialFunc2 (notifier type 2) that stays valid
    // for the whole process; `h` receives the handle.
    let code = unsafe {
        RasDialW(std::ptr::null(), book.as_pcwstr(), p, NOTIFIER_RASDIALFUNC2, callback as *const c_void, &mut h)
    };
    drop(buf);
    if code != 0 {
        if !h.is_null() {
            // SAFETY: a handle RasDialW returned; Microsoft: hang up even after a failed RasDial.
            unsafe { RasHangUpW(h) };
        }
        return Err(Error::Call { call: "RasDialW", code });
    }
    reg.handle.store(h as usize, Ordering::SeqCst);
    dial.handle = Handle(h as usize);
    Ok(dial)
}

/// Hangs up a connection (`RasHangUpW`) and waits until Windows released its handle (`RasGetConnectStatusW`
/// answers `ERROR_INVALID_HANDLE`, polled every 50 ms as Microsoft requires before a new dial). A connection
/// that is already gone is fine. `Error::Timeout` when the handle is still valid after `timeout`.
pub fn hang_up(handle: Handle, timeout: Duration) -> Result<()> {
    // SAFETY: RasHangUpW validates the handle itself (an invalid one: ERROR_INVALID_HANDLE).
    let code = unsafe { RasHangUpW(handle.raw()) };
    if ![0, ERROR_NO_CONNECTION, ERROR_INVALID_HANDLE].contains(&code) {
        return Err(Error::Call { call: "RasHangUpW", code });
    }
    let start = Instant::now();
    loop {
        if raw_status(handle).err() == Some(ERROR_INVALID_HANDLE) {
            return Ok(());
        }
        if start.elapsed() >= timeout {
            return Err(Error::Timeout);
        }
        std::thread::sleep(HANG_UP_POLL);
    }
}

/// A RAS connection of this logon session (`RasEnumConnectionsW`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conn {
    pub handle: Handle,
    pub entry: String,
    /// The phonebook path exactly as the dialler passed it (compare without regard to letter case).
    pub phonebook: PathBuf,
    pub device_type: String,
    pub device_name: String,
    /// The entry's `guidId`, RFC 4122 byte order.
    pub entry_guid: [u8; 16],
}

/// The RAS connections of this logon session (a network logon sees none of its own).
pub fn connections() -> Result<Vec<Conn>> {
    let item = std::mem::size_of::<RASCONNW>();
    let mut buf: Vec<RASCONNW> = vec![RASCONNW::default(); 8];
    loop {
        // A place assignment, no reference to the packed field.
        buf[0].dwSize = item as u32;
        let mut bytes = (buf.len() * item) as u32;
        let mut count: u32 = 0;
        // SAFETY: `buf` is `bytes` bytes of RASCONNW with the first `dwSize` set.
        let code = unsafe { RasEnumConnectionsW(buf.as_mut_ptr(), &mut bytes, &mut count) };
        if code == ERROR_BUFFER_TOO_SMALL {
            let needed = (bytes as usize).div_ceil(item);
            if needed <= buf.len() || needed > MAX_CONNECTIONS {
                return Err(Error::Call { call: "RasEnumConnectionsW", code });
            }
            buf = vec![RASCONNW::default(); needed];
            continue;
        }
        rc("RasEnumConnectionsW", code)?;
        let count = (count as usize).min(buf.len());
        return Ok(buf[..count]
            .iter()
            .map(|c| {
                // Copies out of the packed structure (no references to its fields).
                let (handle, entry, phonebook) = (c.hrasconn, c.szEntryName, c.szPhonebook);
                let (device_type, device_name, guid) = (c.szDeviceType, c.szDeviceName, c.guidEntry);
                Conn {
                    handle: Handle(handle as usize),
                    entry: field_text(&entry),
                    phonebook: PathBuf::from(field_text(&phonebook)),
                    device_type: field_text(&device_type),
                    device_name: field_text(&device_name),
                    entry_guid: guid_bytes(&guid),
                }
            })
            .collect());
    }
}

/// A connection's state (`RasGetConnectStatusW`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// `RASCONNSTATE` (`RASCS_Connected` = 0x2000, `RASCS_Disconnected` = 0x2001).
    pub state: u32,
    /// The error that ended the dial or the connection (0: none).
    pub error: u32,
    pub device_name: String,
}

/// The state of `handle` (`Error::Call` with `ERROR_INVALID_HANDLE` once it is released).
pub fn status(handle: Handle) -> Result<Status> {
    raw_status(handle).map_err(|code| Error::Call { call: "RasGetConnectStatusW", code })
}

fn raw_status(handle: Handle) -> std::result::Result<Status, u32> {
    let mut s = Box::<RASCONNSTATUSW>::default();
    s.dwSize = std::mem::size_of::<RASCONNSTATUSW>() as u32;
    // SAFETY: `s` is a writable RASCONNSTATUSW with `dwSize` set; the call validates the handle.
    let code = unsafe { RasGetConnectStatusW(handle.raw(), &mut *s) };
    if code != 0 {
        return Err(code);
    }
    Ok(Status { state: s.rasconnstate as u32, error: s.dwError, device_name: field_text(&s.szDeviceName) })
}

/// A connection's statistics (`RasGetConnectionStatistics`), counted from its dial on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stats {
    /// Bytes received (32-bit: wraps at 4 GiB).
    pub rx: u32,
    /// Bytes sent (32-bit).
    pub tx: u32,
    /// How long it has been connected, in milliseconds.
    pub duration_ms: u32,
}

/// The statistics of `handle`.
pub fn statistics(handle: Handle) -> Result<Stats> {
    let mut s = RAS_STATS { dwSize: std::mem::size_of::<RAS_STATS>() as u32, ..Default::default() };
    // SAFETY: `s` is a writable RAS_STATS with `dwSize` set; the call validates the handle and keeps nothing.
    let code = unsafe { RasGetConnectionStatistics(handle.raw(), &mut s) };
    rc("RasGetConnectionStatistics", code)?;
    Ok(Stats { rx: s.dwBytesRcved, tx: s.dwBytesXmited, duration_ms: s.dwConnectDuration })
}

/// The tunnel's IPv4 address of a connected connection (`RasGetProjectionInfoEx`, PPP or IKEv2), `None` when IPv4
/// was not negotiated.
pub fn ipv4(handle: Handle) -> Result<Option<Ipv4Addr>> {
    let size = std::mem::size_of::<RAS_PROJECTION_INFO>();
    let mut buf = vec![0u64; size.div_ceil(8)];
    loop {
        let info = buf.as_mut_ptr().cast::<RAS_PROJECTION_INFO>();
        // SAFETY: `buf` is zeroed, 8-byte aligned and holds at least one RAS_PROJECTION_INFO.
        unsafe { (*info).version = RASAPIVERSION_601 };
        let mut bytes = (buf.len() * 8) as u32;
        // SAFETY: `info` is writable for `bytes` bytes; the call validates the handle.
        let code = unsafe { RasGetProjectionInfoEx(handle.raw(), info, &mut bytes) };
        if code == ERROR_BUFFER_TOO_SMALL && (bytes as usize) > buf.len() * 8 && bytes < 65536 {
            buf = vec![0u64; (bytes as usize).div_ceil(8)];
            continue;
        }
        rc("RasGetProjectionInfoEx", code)?;
        // SAFETY: the call filled the structure; the union member read is the one `type` names, copied by value
        // (the IKEv2 member is packed).
        let addr = unsafe {
            match (*info).r#type {
                t if t == PROJECTION_INFO_TYPE_PPP => (*info).Anonymous.ppp.ipv4Address.S_un.S_addr,
                t if t == PROJECTION_INFO_TYPE_IKEv2 => {
                    let a = (*info).Anonymous.ikev2.ipv4Address;
                    a.S_un.S_addr
                }
                _ => 0,
            }
        };
        // S_addr holds the address in network byte order: its bytes in memory order are the octets.
        return Ok(Some(Ipv4Addr::from(addr.to_ne_bytes())).filter(|a| !a.is_unspecified()));
    }
}

/// Windows' text for a RAS, Win32 or HRESULT code, in Windows' display language (`RasGetErrorStringW`, else the
/// system message table); never empty.
pub fn error_text(code: u32) -> String {
    let mut buf = [0u16; 512];
    // SAFETY: `buf` is writable for its length, which is passed.
    let r = unsafe { RasGetErrorStringW(code, buf.as_mut_ptr(), buf.len() as u32) };
    let text = if r == 0 { field_text(&buf) } else { String::new() };
    let text = if text.trim().is_empty() {
        let os = std::io::Error::from_raw_os_error(code as i32).to_string();
        // std appends " (os error N)".
        os.rsplit_once(" (os error ").map_or(os.clone(), |(t, _)| t.to_string())
    } else {
        text
    };
    let text = text.trim().to_string();
    if text.is_empty() { format!("error {code}") } else { text }
}

/// Windows' own dial dialog for the entry `name` (`RasDialDlgW` from `rasdlg.dll`, loaded from System32 when
/// needed; no owner window): the user signs in and connects in Windows' window. Blocks until it closes (call it
/// on a worker thread). `Ok(true)`: connected; `Ok(false)`: the user cancelled.
pub fn dial_dlg(book: &Phonebook, name: &str) -> Result<bool> {
    let wname = entry_name(name)?;
    let lib = Library::system32("rasdlg.dll").map_err(|e| Error::invalid(format!("rasdlg.dll: {e}")))?;
    let f = lib.symbol(c"RasDialDlgW").map_err(|e| Error::invalid(format!("RasDialDlgW: {e}")))?;
    type RasDialDlgW = unsafe extern "system" fn(PCWSTR, PCWSTR, PCWSTR, *mut RASDIALDLG) -> BOOL;
    // SAFETY: the export RasDialDlgW has exactly this signature (ras.h / rasdlg.h); `lib` outlives the call.
    let f: RasDialDlgW = unsafe { std::mem::transmute::<*const c_void, RasDialDlgW>(f) };
    let mut info = RASDIALDLG { dwSize: std::mem::size_of::<RASDIALDLG>() as u32, ..RASDIALDLG::default() };
    // SAFETY: the strings are NUL-terminated (or null: the phonebook, the phone number) and alive across the call;
    // `info` is a writable RASDIALDLG with `dwSize` set and no owner window.
    let ok = unsafe { f(book.as_pcwstr(), wname.as_ptr(), std::ptr::null(), &mut info) };
    let error = info.dwError;
    match (ok != 0, error) {
        (true, _) => Ok(true),
        (false, 0) => Ok(false),
        (false, code) => Err(Error::Call { call: "RasDialDlgW", code }),
    }
}
