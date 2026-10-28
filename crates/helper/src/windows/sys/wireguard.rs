//! The WireGuard engine (wireguard-nt): one adapter per connection, named and identified only from a hash of the
//! connection ID (`wg_nt::adapter_name` / `adapter_guid`), configured only from the validated config's plan
//! (`wg_plan::parse` runs the validator itself) and the endpoints the service resolved for it. Its addresses, routes,
//! interface metric, MTU and DNS are set through IP Helper on that adapter's own LUID. The adapter handle is owned
//! by an [`Adapter`] that closes it on drop, and closing deletes the adapter with everything set on it: every
//! failure after the adapter exists drops it (fail closed), `down` drops it, and so does the end of the process
//! (wireguard-nt ties the adapter's life to its handle). Keys live only in the plan and the configuration block,
//! both zeroized on drop, and are never logged.
//!
//! **Which `wireguard.dll`** (2b plan, "As built (fix4)"): at engine start, and again after an update, the service
//! loads the highest version that passes every check of `wgdll` (signer and machine at every load): its own download
//! in `C:\ProgramData\WinVPN\engines\wireguard-nt\wireguard.dll` when that is above the bundled one, else the
//! bundled one next to the exe (pinned by SHA-256; the fallback). **Updates** ([`WireGuardEngine::update`]): the
//! service itself finds the newest version on the official listing, downloads the SDK zip with System32's curl into
//! that admin-only directory, takes only `bin\<arch>\wireguard.dll` out of it, checks it as a download above every
//! version it has, and swaps it in only while no WireGuard connection is up (an `up` holds [`GATE`] for reading, the
//! swap needs it for writing): the DLL holds the driver. Every temporary file is deleted on every path. Nothing of
//! the request reaches any of this: the app can only ask "check" or "update".

use super::data_dir::DataDir;
use super::fetch::Fetcher;
use super::iphlp;
use super::service_log::ServiceLog;
use super::wgdll::{self, ADAPTER_STATE_DOWN, ADAPTER_STATE_UP, AdapterHandle, Trust, WgDll};
use crate::shared::l10n::tr;
use crate::windows::diagnostics::PeerStatus;
use crate::windows::service::{self, Engine, EngineState, UpRequest, UpdateRefusal};
use crate::windows::wg_plan::{self, Endpoint, Plan};
use crate::windows::wg_update::{self, CheckCache, Listed, NtVersion};
use crate::windows::{wg_nt, wg_pins};
use macvpn_core::service_proto::{EngineUpdate, WireGuardFacts};
use std::collections::HashMap;
use std::io::{self, Read};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError, RwLock};
use std::time::Duration;
use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_MORE_DATA};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
};
use windows_sys::core::GUID;
use zeroize::Zeroizing;

/// The interface metric of every WinVPN adapter (below Windows' automatic metrics, so its routes and DNS win).
const METRIC: u32 = 5;
/// The tunnel type wireguard-nt records for our adapters.
const TUNNEL_TYPE: &str = "WinVPN";
/// How long one endpoint's name resolution may take.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);
/// The longest wireguard-nt log message kept (UTF-16 units).
const LOG_MESSAGE_MAX: usize = 512;

/// The engine directory's name below the data directory's `engines`.
const ENGINE_DIR: &str = "wireguard-nt";
/// The downloaded DLL's name there, and the temporary files of an update (removed on every path).
const DOWNLOADED: &str = "wireguard.dll";
const NEW_DLL: &str = "wireguard.new";
const ZIP: &str = "download.zip";
const LISTING: &str = "listing.html";

/// The loaded DLL (or why none is), shared by the engine and `engine`'s facts. `None`: not loaded yet, or being
/// swapped by an update.
static DLL: Mutex<Option<Result<Arc<WgDll>, String>>> = Mutex::new(None);
/// Held for reading by every `up` (from before it takes the DLL until its adapter is recorded), for writing by the
/// swap of an update: the DLL is never replaced while an adapter is being made.
static GATE: RwLock<()> = RwLock::new(());
/// Where wireguard-nt's own messages go.
static LOG: OnceLock<ServiceLog> = OnceLock::new();
/// The console's `--wireguard-dll` (tests): used instead of the service's own folder, without the admin-only check.
#[cfg(debug_assertions)]
static CONSOLE_DLL: OnceLock<PathBuf> = OnceLock::new();
/// The console's `--wireguard-floor` (tests): the version a download must be above instead of the bundled pin's,
/// so the real (and only) signed DLL can stand for a newer one.
#[cfg(debug_assertions)]
static CONSOLE_FLOOR: OnceLock<NtVersion> = OnceLock::new();

/// The console's `--wireguard-dll` (before the engines are made).
#[cfg(debug_assertions)]
pub(crate) fn use_console_dll(path: PathBuf) {
    let _ = CONSOLE_DLL.set(path);
}

/// The console's `--wireguard-floor` (before the engines are made).
#[cfg(debug_assertions)]
pub(crate) fn use_console_floor(version: NtVersion) {
    let _ = CONSOLE_FLOOR.set(version);
}

/// The bundled DLL's version: the pin's (`scripts/pins/wireguard-nt.txt`), or the console's floor.
fn bundled_version() -> NtVersion {
    #[cfg(debug_assertions)]
    if let Some(v) = CONSOLE_FLOOR.get() {
        return *v;
    }
    NtVersion::parse(&wg_pins::PINS.version).expect("the pinned version parses")
}

/// `<folder of the service's exe>\wireguard.dll`, checked to be admin-only; the console's path instead when given.
fn dll_source() -> io::Result<(PathBuf, bool)> {
    #[cfg(debug_assertions)]
    if let Some(p) = CONSOLE_DLL.get() {
        return Ok((p.clone(), false));
    }
    Ok((std::env::current_exe()?.with_file_name("wireguard.dll"), true))
}

/// wireguard-nt's messages (adapter management; no keys) into the service log, with their level.
unsafe extern "system" fn logger(level: i32, _timestamp: u64, message: *const u16) {
    if message.is_null() {
        return;
    }
    let mut units = Vec::new();
    for i in 0..LOG_MESSAGE_MAX {
        // SAFETY: wireguard-nt passes a NUL-terminated string; reading stops at its NUL (or the cap).
        let u = unsafe { *message.add(i) };
        if u == 0 {
            break;
        }
        units.push(u);
    }
    let text = String::from_utf16_lossy(&units);
    let level = match level {
        0 => "info",
        1 => "warning",
        _ => "error",
    };
    if let Some(log) = LOG.get() {
        let _ = std::panic::catch_unwind(|| log.line(&format!("wireguard-nt {level}: {text}")));
    }
}

fn dll_state() -> MutexGuard<'static, Option<Result<Arc<WgDll>, String>>> {
    DLL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The downloaded DLL, when the data directory has one the service made: its path (the directory checked now) and
/// file version.
fn downloaded(data: Option<&DataDir>) -> Option<(PathBuf, NtVersion)> {
    let data = data?;
    let path = data.engine_dir(ENGINE_DIR).ok()?.join(DOWNLOADED);
    if !data.is_own_file(&path).unwrap_or(false) {
        return None;
    }
    let version = macvpn_winsys::version::file_version(&path).ok()?;
    Some((path, NtVersion::from_file_version(version)))
}

/// Loads the highest version that passes its checks (the download when it is above the bundled DLL, else the
/// bundled one), sets wireguard-nt's logger and records it. A refused download is logged; the bundled DLL is used.
fn load_best(data: Option<&DataDir>, log: &ServiceLog) -> Result<Arc<WgDll>, String> {
    let _ = LOG.set(log.clone());
    let bundled = bundled_version();
    let mut loaded = None;
    if let Some((path, version)) = downloaded(data)
        && wg_update::use_downloaded(bundled, Some(version))
    {
        match wgdll::load(&path, Trust::Downloaded { above: bundled }) {
            Ok(dll) => loaded = Some(dll),
            Err(why) => log.line(&format!("downloaded wireguard.dll {version} refused: {why}; using the bundled one")),
        }
    }
    let loaded = match loaded {
        Some(dll) => Ok(dll),
        None => dll_source()
            .map_err(|e| format!("no path ({:?})", e.kind()))
            .and_then(|(path, admin_only_folder)| wgdll::load(&path, Trust::Bundled { admin_only_folder })),
    };
    let result = match loaded {
        Ok(dll) => {
            // SAFETY: `logger` matches WIREGUARD_LOGGER_CALLBACK and lives for the whole process.
            unsafe { (dll.set_logger)(Some(logger)) };
            let from = if dll.downloaded { "downloaded" } else { "bundled" };
            log.line(&format!("wireguard.dll {} loaded ({from})", dll.version));
            Ok(Arc::new(dll))
        }
        Err(why) => {
            log.line(&format!("wireguard.dll refused: {why}"));
            Err(tr("wireguard.dll does not match its pinned version. Repair WinVPN.", &[]))
        }
    };
    *dll_state() = Some(result.clone());
    result
}

/// The loaded DLL, loading it first when nothing is (yet, or after a failed swap).
fn current(data: Option<&DataDir>, log: &ServiceLog) -> Result<Arc<WgDll>, String> {
    let now = dll_state().clone();
    match now {
        Some(r) => r,
        None => load_best(data, log),
    }
}

/// What `engine` reports: the DLL's version once loaded, or why it was refused (nothing before the engine exists).
pub(crate) fn facts() -> WireGuardFacts {
    match dll_state().as_ref() {
        Some(Ok(dll)) => WireGuardFacts { dll_version: Some(dll.version.clone()), problem: None },
        Some(Err(why)) => WireGuardFacts { dll_version: None, problem: Some(why.clone()) },
        None => WireGuardFacts { dll_version: None, problem: None },
    }
}

/// Deletes a file of the engine directory (missing is fine; a link is removed itself, never followed).
fn remove(path: &Path) {
    let _ = std::fs::remove_file(path);
}

/// Whether this process may create adapters at all (an elevated token, or LocalSystem). Asked before wireguard-nt
/// is, so a standard user's console never makes it try to install its driver.
fn may_create_adapters() -> bool {
    macvpn_winsys::sid::this_process_is_elevated()
        || macvpn_winsys::sid::Sid::current_user().is_ok_and(|me| me == macvpn_winsys::sid::Sid::local_system())
}

/// One wireguard-nt adapter, deleted (with its addresses, routes and DNS) when dropped. It keeps its DLL loaded.
struct Adapter {
    handle: AdapterHandle,
    dll: Arc<WgDll>,
}

// SAFETY: a wireguard-nt adapter handle may be used and closed from any thread (the DLL serializes per adapter);
// the engine's map hands it to one thread at a time.
unsafe impl Send for Adapter {}

impl Adapter {
    fn create(dll: Arc<WgDll>, name: &str, guid: [u8; 16]) -> io::Result<Adapter> {
        let uuid = uuid::Uuid::from_bytes(guid);
        let (data1, data2, data3, data4) = uuid.as_fields();
        let guid = GUID { data1, data2, data3, data4: *data4 };
        let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let tunnel_type: Vec<u16> = TUNNEL_TYPE.encode_utf16().chain(Some(0)).collect();
        // SAFETY: both strings are NUL-terminated and, like `guid`, live across the call.
        let handle = unsafe { (dll.create)(name.as_ptr(), tunnel_type.as_ptr(), &guid) };
        if handle.is_null() { Err(io::Error::last_os_error()) } else { Ok(Adapter { handle, dll }) }
    }

    /// `WireGuardSetConfiguration` with the block copied into 8-byte aligned memory (the structs are `ALIGNED(8)`),
    /// zeroized on drop like the block.
    fn set_config(&self, block: &[u8]) -> io::Result<()> {
        let bytes = u32::try_from(block.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let mut aligned = Zeroizing::new(vec![0u64; block.len().div_ceil(8)]);
        for (word, chunk) in aligned.iter_mut().zip(block.chunks(8)) {
            let mut b = [0u8; 8];
            b[..chunk.len()].copy_from_slice(chunk);
            *word = u64::from_ne_bytes(b);
        }
        // SAFETY: `aligned` holds `bytes` bytes of the configuration and lives across the call; the handle is ours.
        let ok = unsafe { (self.dll.set_config)(self.handle, aligned.as_ptr().cast(), bytes) } != 0;
        if ok { Ok(()) } else { Err(io::Error::last_os_error()) }
    }

    /// `WireGuardGetConfiguration` into 8-byte aligned, zeroized memory (it holds the private and preshared keys),
    /// grown once to the size the DLL asks for; at most `wg_nt::MAX_BYTES`. Returned as zeroized bytes.
    fn get_config(&self) -> io::Result<Zeroizing<Vec<u8>>> {
        let mut bytes: u32 = 4096;
        for _ in 0..2 {
            let mut words = Zeroizing::new(vec![0u64; (bytes as usize).div_ceil(8)]);
            let mut size = (words.len() * 8) as u32;
            // SAFETY: `words` is writable for `size` bytes, 8-byte aligned, and lives across the call; the handle is
            // ours; `size` is a valid out pointer (the needed size when the buffer is too small).
            let ok = unsafe { (self.dll.get_config)(self.handle, words.as_mut_ptr().cast(), &mut size) } != 0;
            if ok {
                let len = (size as usize).min(words.len() * 8);
                let mut out = Zeroizing::new(Vec::with_capacity(words.len() * 8));
                for w in words.iter() {
                    out.extend_from_slice(&w.to_ne_bytes());
                }
                out.truncate(len);
                return Ok(out);
            }
            let e = io::Error::last_os_error();
            if e.raw_os_error() != Some(ERROR_MORE_DATA as i32) || size as usize > wg_nt::MAX_BYTES || size <= bytes {
                return Err(e);
            }
            bytes = size;
        }
        Err(io::Error::from_raw_os_error(ERROR_MORE_DATA as i32))
    }

    fn luid(&self) -> NET_LUID_LH {
        let mut luid = NET_LUID_LH { Value: 0 };
        // SAFETY: the handle is ours; `luid` is writable.
        unsafe { (self.dll.luid)(self.handle, &mut luid) };
        luid
    }

    fn set_state(&self, state: i32) -> io::Result<()> {
        // SAFETY: the handle is ours.
        let ok = unsafe { (self.dll.set_state)(self.handle, state) } != 0;
        if ok { Ok(()) } else { Err(io::Error::last_os_error()) }
    }
}

impl Drop for Adapter {
    fn drop(&mut self) {
        // SAFETY: the handle came from WireGuardCreateAdapter and is closed exactly once, here.
        unsafe { (self.dll.close)(self.handle) };
    }
}

struct Run {
    adapter: Adapter,
    name: String,
    since: u64,
    address: Option<IpAddr>,
}

pub(crate) struct WireGuardEngine {
    runs: Mutex<HashMap<String, Run>>,
    /// The data directory (the downloads; `None`: no updates, the bundled DLL only).
    data: Option<Arc<DataDir>>,
    log: ServiceLog,
    fetcher: Box<dyn Fetcher>,
    /// The last check's answer (reused for `wg_update::CHECK_CACHE_SECS`).
    checked: Mutex<Option<CheckCache<EngineUpdate>>>,
    /// Held while an update runs (a second one is refused, not queued).
    updating: Mutex<()>,
}

/// Why an update step failed: the detail for the service log, the localized message for the user.
struct Failure {
    detail: String,
    message: String,
}

fn failed(detail: impl Into<String>, message: String) -> Failure {
    Failure { detail: detail.into(), message }
}

fn not_checked() -> String {
    tr("wireguard-nt could not be checked for updates.", &[])
}

fn not_downloaded() -> String {
    tr("The newest wireguard-nt could not be downloaded.", &[])
}

fn not_verified() -> String {
    tr(
        "The downloaded wireguard-nt did not pass its checks (signer WireGuard LLC, version, processor); nothing was changed.",
        &[],
    )
}

/// Reads a file of the engine directory deny-write, without following a reparse point, at most `max` bytes.
fn read_engine_file(path: &Path, max: u64) -> io::Result<Vec<u8>> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || meta.len() > max {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not a plain file of a plausible size"));
    }
    let mut bytes = Vec::new();
    (&file).take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "too large"));
    }
    Ok(bytes)
}

impl WireGuardEngine {
    /// The engine over the process' `wireguard.dll` (the highest valid version, loaded now if nothing is yet);
    /// leftovers of an interrupted update, and a download that is not above the bundled DLL, are removed first.
    pub(crate) fn new(data: Option<Arc<DataDir>>, log: &ServiceLog, fetcher: Box<dyn Fetcher>) -> WireGuardEngine {
        if dll_state().is_none()
            && let Some(dir) = data.as_deref().and_then(|d| d.engine_dir(ENGINE_DIR).ok())
        {
            for name in [NEW_DLL, ZIP, LISTING] {
                remove(&dir.join(name));
            }
            if let Some((path, version)) = downloaded(data.as_deref())
                && !wg_update::use_downloaded(bundled_version(), Some(version))
            {
                log.line(&format!("downloaded wireguard.dll {version} is not above the bundled one: removed"));
                remove(&path);
            }
        }
        let _ = current(data.as_deref(), log);
        WireGuardEngine {
            runs: Mutex::new(HashMap::new()),
            data,
            log: log.clone(),
            fetcher,
            checked: Mutex::new(None),
            updating: Mutex::new(()),
        }
    }

    /// Every version the service has: the bundled one (the pin), the downloaded file and the loaded DLL.
    fn versions(&self) -> Vec<NtVersion> {
        let mut have = vec![bundled_version()];
        have.extend(downloaded(self.data.as_deref()).map(|(_, v)| v));
        if let Some(Ok(dll)) = dll_state().as_ref() {
            have.push(dll.nt_version);
        }
        have
    }

    /// The engine directory, checked now.
    fn engine_dir(&self) -> Result<PathBuf, Failure> {
        let data = self.data.as_deref().ok_or_else(|| failed("no data directory", not_checked()))?;
        data.engine_dir(ENGINE_DIR).map_err(|e| failed(format!("the engine directory ({:?})", e.kind()), not_checked()))
    }

    /// The newest version on the official listing (fetched into the engine directory, read, deleted).
    fn discover(&self, dir: &Path) -> Result<Listed, Failure> {
        let file = dir.join(LISTING);
        remove(&file);
        let fetched = self
            .fetcher
            .fetch(wg_update::LISTING_URL, &file, wg_update::LISTING_MAX_BYTES, wg_update::LISTING_MAX_TIME)
            .map_err(|e| failed(format!("the listing: {e}"), not_checked()))
            .and_then(|()| {
                read_engine_file(&file, wg_update::LISTING_MAX_BYTES)
                    .map_err(|e| failed(format!("the listing ({:?})", e.kind()), not_checked()))
            });
        remove(&file);
        let html = String::from_utf8_lossy(&fetched?).into_owned();
        wg_update::parse_listing(&html).ok_or_else(|| failed("the listing names no wireguard-nt zip", not_checked()))
    }

    fn check(&self) -> Result<EngineUpdate, Failure> {
        let dir = self.engine_dir()?;
        let listed = self.discover(&dir)?;
        let installed = match dll_state().as_ref() {
            Some(Ok(dll)) => Some(dll.version.clone()),
            _ => None,
        };
        let available = wg_update::is_newer(listed.version, &self.versions()).then(|| listed.version.to_string());
        Ok(EngineUpdate { installed, available })
    }

    /// Downloads the zip of `listed`, takes this machine's DLL out of it, writes it as `wireguard.new` and checks it
    /// as a download above every version the service has. `Ok`: the checked file and its version. Every temporary
    /// file is gone on failure.
    fn fetch_checked(&self, dir: &Path, listed: &Listed) -> Result<(PathBuf, NtVersion), Failure> {
        let data = self.data.as_deref().ok_or_else(|| failed("no data directory", not_downloaded()))?;
        let url = wg_update::zip_url(listed).ok_or_else(|| failed("no zip URL", not_downloaded()))?;
        let member = wg_update::dll_member(std::env::consts::ARCH)
            .ok_or_else(|| failed("no DLL for this architecture", not_verified()))?;
        let zip_file = dir.join(ZIP);
        remove(&zip_file);
        let zip = self
            .fetcher
            .fetch(&url, &zip_file, wg_update::ZIP_MAX_BYTES, wg_update::ZIP_MAX_TIME)
            .map_err(|e| failed(format!("{url}: {e}"), not_downloaded()))
            .and_then(|()| {
                read_engine_file(&zip_file, wg_update::ZIP_MAX_BYTES)
                    .map_err(|e| failed(format!("the zip ({:?})", e.kind()), not_downloaded()))
            });
        remove(&zip_file);
        let inflate = |d: &[u8], limit: usize| miniz_oxide::inflate::decompress_to_vec_with_limit(d, limit).ok();
        let bytes = wg_update::extract(&zip?, member, wg_update::DLL_MAX_BYTES, inflate)
            .map_err(|e| failed(e.to_string(), not_verified()))?;
        let new = data
            .write_engine_file(dir, NEW_DLL, &bytes)
            .map_err(|e| failed(format!("cannot write {NEW_DLL} ({:?})", e.kind()), not_downloaded()))?;
        let above = self.versions().into_iter().max().unwrap_or_else(bundled_version);
        let checked = wgdll::inspect(&new, Trust::Downloaded { above }).and_then(|v| {
            if wg_update::matches_listed(v, listed) {
                Ok(v)
            } else {
                Err(format!("its version {v} is not the listed {}", listed.text))
            }
        });
        match checked {
            Ok(v) => Ok((new, v)),
            Err(why) => {
                remove(&new);
                Err(failed(why, not_verified()))
            }
        }
    }

    /// Replaces the downloaded DLL with `new` and loads the highest valid version again, only while no WireGuard
    /// adapter exists or is being made. `Ok`: the version now loaded.
    fn swap(&self, dir: &Path, new: &Path) -> Result<String, UpdateRefusal> {
        let busy = || UpdateRefusal::Busy(service::wireguard_busy());
        let Ok(_gate) = GATE.try_write() else { return Err(busy()) };
        if !self.runs().is_empty() {
            return Err(busy());
        }
        // No adapter holds the DLL now: dropping the last reference unloads it, so the file can be replaced.
        *dll_state() = None;
        let renamed = std::fs::rename(new, dir.join(DOWNLOADED));
        let loaded = load_best(self.data.as_deref(), &self.log);
        if let Err(e) = renamed {
            self.log.line(&format!("wireguard-nt update: cannot replace {DOWNLOADED} ({:?})", e.kind()));
        }
        match loaded {
            Ok(dll) => Ok(dll.version.clone()),
            Err(m) => Err(UpdateRefusal::Failed(m)),
        }
    }

    fn runs(&self) -> std::sync::MutexGuard<'_, HashMap<String, Run>> {
        self.runs.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// `host:port` resolved once (the system's order, the first address), on a helper thread, within the timeout.
fn resolve_host(host: &str, port: u16) -> Result<SocketAddr, String> {
    let (tx, rx) = std::sync::mpsc::channel();
    let name = host.to_owned();
    std::thread::spawn(move || {
        let _ = tx.send((name.as_str(), port).to_socket_addrs().ok().and_then(|mut it| it.next()));
    });
    match rx.recv_timeout(RESOLVE_TIMEOUT) {
        Ok(Some(addr)) => Ok(addr),
        _ => Err(tr("Cannot resolve %@", &[host])),
    }
}

/// One entry per peer, as `wg_nt::encode` needs them.
fn resolve(plan: &Plan) -> Result<Vec<Option<SocketAddr>>, String> {
    plan.peers
        .iter()
        .map(|p| match &p.endpoint {
            None => Ok(None),
            Some(Endpoint::Addr(a)) => Ok(Some(*a)),
            Some(Endpoint::Host(host, port)) => resolve_host(host, *port).map(Some),
        })
        .collect()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

impl Engine for WireGuardEngine {
    fn up(&self, req: &UpRequest<'_>) -> Result<(), String> {
        // Held until the adapter is recorded (or the `up` failed): no update swaps the DLL meanwhile.
        let _gate = GATE.read().unwrap_or_else(PoisonError::into_inner);
        let dll = current(self.data.as_deref(), &self.log)?;
        let text = std::str::from_utf8(req.config).map_err(|_| tr("Invalid value: %@", &["config"]))?;
        let plan = wg_plan::parse(text)?;
        let (Some(name), Some(guid)) = (wg_nt::adapter_name(req.id), wg_nt::adapter_guid(req.id)) else {
            return Err(tr("Invalid ID", &[]));
        };
        let resolved = resolve(&plan)?;
        let block = wg_nt::encode(&plan, &resolved)?;
        // A previous run of this ID goes first (the service normally did that already).
        self.down(req.id)?;
        let cannot_create = |e: io::Error| {
            let message = tr("Cannot create the WireGuard adapter (%@)", &[&e.to_string()]);
            req.log.line(&message);
            message
        };
        if self.runs().values().any(|r| r.name == name) {
            return Err(cannot_create(io::Error::from_raw_os_error(ERROR_ALREADY_EXISTS as i32)));
        }
        if !may_create_adapters() {
            return Err(cannot_create(io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32)));
        }
        let adapter = Adapter::create(dll, &name, guid).map_err(cannot_create)?;
        req.log.line(&format!("adapter {name} created"));
        // From here every `?` drops `adapter`: the adapter and all set on it are deleted.
        let step = |what: &str, e: io::Error| {
            let message = tr("Cannot configure the WireGuard adapter: %@ (%@)", &[what, &e.to_string()]);
            req.log.line(&message);
            message
        };
        adapter.set_config(&block).map_err(|e| step("configuration", e))?;
        drop(block);
        let luid = adapter.luid();
        for a in &plan.addresses {
            iphlp::add_address(luid, a).map_err(|e| step("address", e))?;
        }
        req.log.line(&format!("addresses set ({})", plan.addresses.len()));
        let routes = plan.routes();
        for r in &routes {
            iphlp::add_route(luid, r).map_err(|e| step("route", e))?;
        }
        req.log.line(&format!("routes set ({})", routes.len()));
        for family in [AF_INET, AF_INET6] {
            if plan.addresses.iter().any(|a| iphlp::family(&a.addr()) == family) {
                iphlp::set_interface(luid, family, METRIC, plan.mtu).map_err(|e| step("interface", e))?;
            }
        }
        // Both families every time, empty values clearing what an earlier session of this connection left in the
        // registry under the adapter's (stable) GUID.
        let dns = wg_nt::dns_lists(&plan);
        let guid = iphlp::guid_of(luid).map_err(|e| step("DNS", e))?;
        for call in wg_nt::dns_calls(&dns) {
            let sets = !call.servers.is_empty() || call.search.as_deref().is_some_and(|s| !s.is_empty());
            match iphlp::set_dns(guid, call.ipv6, &call.servers, call.search.as_deref()) {
                Err(e) if sets => return Err(step("DNS", e)),
                Err(e) => req.log.line(&format!("DNS clear ({}): {e}", if call.ipv6 { "IPv6" } else { "IPv4" })),
                Ok(()) => {}
            }
        }
        if dns.v4.is_some() || dns.v6.is_some() {
            req.log.line("DNS set");
        }
        adapter.set_state(ADAPTER_STATE_UP).map_err(|e| step("state", e))?;
        req.log.line("up");
        let address = plan.addresses.first().map(|a| a.addr());
        self.runs().insert(req.id.to_string(), Run { adapter, name, since: unix_now(), address });
        Ok(())
    }

    fn down(&self, id: &str) -> Result<(), String> {
        // Taken out of the map first; dropping the run closes (deletes) the adapter.
        let run = self.runs().remove(id);
        if let Some(run) = run {
            let _ = run.adapter.set_state(ADAPTER_STATE_DOWN);
        }
        Ok(())
    }

    fn state(&self, id: &str) -> Option<EngineState> {
        self.runs().get(id).map(|r| EngineState {
            state: "connected",
            iface: r.name.clone(),
            ip: r.address.map(|a| a.to_string()).unwrap_or_default(),
            since: Some(r.since),
        })
    }

    /// Asks the official listing (at most once a minute; answers are reused) whether a version above every one the
    /// service has exists.
    fn peer_status(&self, id: &str) -> Option<(String, Vec<PeerStatus>)> {
        let runs = self.runs();
        let run = runs.get(id)?;
        match run.adapter.get_config() {
            Ok(block) => Some((run.name.clone(), wg_nt::peer_status(&block))),
            Err(e) => {
                self.log.line(&format!("wireguard-nt: peer status of {} not read: {e}", run.name));
                None
            }
        }
    }

    /// Dead-tunnel detection: the peers' handshake, counters and keepalive (no key). Polled: an error is not logged.
    fn liveness(&self, id: &str) -> Option<macvpn_core::liveness::Liveness> {
        let runs = self.runs();
        let block = runs.get(id)?.adapter.get_config().ok()?;
        Some(wg_nt::liveness(&block))
    }

    fn update_check(&self) -> Result<EngineUpdate, String> {
        let now = unix_now();
        let mut cache = self.checked.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(answer) = CheckCache::fresh(&cache, now) {
            return Ok(answer);
        }
        match self.check() {
            Ok(answer) => {
                *cache = Some(CheckCache { at: now, answer: answer.clone() });
                Ok(answer)
            }
            Err(f) => {
                self.log.line(&format!("wireguard-nt check: {}", f.detail));
                Err(f.message)
            }
        }
    }

    /// The newest wireguard-nt, asked again now, downloaded, checked and loaded (see the module docs).
    fn update(&self) -> Result<EngineUpdate, UpdateRefusal> {
        let Ok(_one) = self.updating.try_lock() else {
            return Err(UpdateRefusal::Busy(tr("An update of wireguard-nt is already running.", &[])));
        };
        if !self.runs().is_empty() {
            return Err(UpdateRefusal::Busy(service::wireguard_busy()));
        }
        let log_failure = |f: Failure| {
            self.log.line(&format!("wireguard-nt update: {}", f.detail));
            UpdateRefusal::Failed(f.message)
        };
        let dir = self.engine_dir().map_err(log_failure)?;
        let listed = self.discover(&dir).map_err(log_failure)?;
        if !wg_update::is_newer(listed.version, &self.versions()) {
            return Err(UpdateRefusal::Failed(tr("No newer wireguard-nt is available.", &[])));
        }
        let (new, version) = self.fetch_checked(&dir, &listed).map_err(log_failure)?;
        self.log.line(&format!("wireguard-nt update: {version} downloaded and checked"));
        let swapped = self.swap(&dir, &new);
        remove(&new);
        *self.checked.lock().unwrap_or_else(PoisonError::into_inner) = None;
        let loaded = swapped?;
        if loaded != version.to_string() {
            self.log.line(&format!("wireguard-nt update: {version} was not loaded ({loaded} is)"));
            return Err(UpdateRefusal::Failed(tr(
                "The new wireguard-nt could not be loaded; WinVPN keeps using wireguard-nt %@.",
                &[loaded.as_str()],
            )));
        }
        Ok(EngineUpdate { installed: Some(loaded), available: None })
    }
}
