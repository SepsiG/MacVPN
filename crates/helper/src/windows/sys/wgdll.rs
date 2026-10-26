//! `wireguard.dll` (wireguard-nt; `scripts/pins/wireguard-nt.txt` pins the bundled one): loaded by absolute path
//! only after it passed every check, at every load (2b plan, Task 14; "As built (fix4)"):
//!
//! - **The bundled DLL** (next to the service's exe): its SHA-256 is the pin compiled into the service for this
//!   architecture, and it lies in an admin-only folder (`acl_check::is_admin_only`: the install folder; the
//!   console's `--wireguard-dll` (tests) skips that one check).
//! - **A downloaded DLL** (the service's own wireguard-nt update, in its admin-only data directory, which the caller
//!   checks): no pin (the maintainer's choice, 2026-10-24: wireguard-nt updates without a WinVPN release); its file
//!   version must be above the version it replaces.
//! - **Both:** a plain file (no reparse point) of at most `wg_update::DLL_MAX_BYTES`; a DLL for this machine (PE
//!   header: AMD64 or ARM64); a valid Authenticode signature whose signer is the pinned `WireGuard LLC` **and**
//!   chains through a pinned CA key (`signer_ca_spki_sha256`: M-1 of the 2.0.0 security review; a "WireGuard LLC"
//!   certificate from a root an operator or a TLS-inspection product added to the machine is refused, and the
//!   service log names the chain's keys; the bundled DLL stays in use).
//!
//! The file is held open with share mode `FILE_SHARE_READ` (no writer, no rename, no delete) from before it is read
//! until the loader has mapped it, so the bytes checked are the bytes loaded. The process' DLL search was restricted
//! first (`harden_process_search` in `sys::main`); `Library::load` resolves the DLL's own imports from its folder and
//! System32 only. The function pointers' types follow `wireguard.h`.

use crate::windows::wg_pins;
use crate::windows::wg_update::{self, NtVersion};
use macvpn_core::update::sha256_hex;
use macvpn_winsys::dll::Library;
use std::ffi::c_void;
use std::fs::File;
use std::io::Read;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
};
use windows_sys::core::{BOOL, GUID};

/// `WIREGUARD_ADAPTER_HANDLE`.
pub type AdapterHandle = *mut c_void;
/// `WIREGUARD_LOGGER_CALLBACK`: level (`WIREGUARD_LOGGER_LEVEL`), timestamp (100 ns since 1601), NUL-terminated text.
pub type LoggerCallback = unsafe extern "system" fn(level: i32, timestamp: u64, message: *const u16);
/// `WIREGUARD_ADAPTER_STATE_DOWN` / `_UP`.
pub const ADAPTER_STATE_DOWN: i32 = 0;
pub const ADAPTER_STATE_UP: i32 = 1;

type CreateAdapter =
    unsafe extern "system" fn(name: *const u16, tunnel_type: *const u16, guid: *const GUID) -> AdapterHandle;
type CloseAdapter = unsafe extern "system" fn(adapter: AdapterHandle);
type GetAdapterLuid = unsafe extern "system" fn(adapter: AdapterHandle, luid: *mut NET_LUID_LH);
type SetConfiguration = unsafe extern "system" fn(adapter: AdapterHandle, config: *const c_void, bytes: u32) -> BOOL;
type SetAdapterState = unsafe extern "system" fn(adapter: AdapterHandle, state: i32) -> BOOL;
type SetLogger = unsafe extern "system" fn(logger: Option<LoggerCallback>);
type GetConfiguration = unsafe extern "system" fn(adapter: AdapterHandle, config: *mut c_void, bytes: *mut u32) -> BOOL;

/// The loaded DLL and the functions the engine calls (valid while `_lib` lives: the struct owns both).
pub struct WgDll {
    _lib: Library,
    /// The DLL's file version (`1.1.0`, as System Status shows it).
    pub version: String,
    pub nt_version: NtVersion,
    /// It is the service's own download, not the bundled DLL.
    pub downloaded: bool,
    pub create: CreateAdapter,
    pub close: CloseAdapter,
    pub luid: GetAdapterLuid,
    pub set_config: SetConfiguration,
    pub set_state: SetAdapterState,
    pub set_logger: SetLogger,
    /// Debug mode's peer status (G-6).
    pub get_config: GetConfiguration,
}

/// Why a `wireguard.dll` was refused (fixed words for the service log; the user sees one localized message).
pub type Refusal = String;

/// Which checks a `wireguard.dll` must pass besides the common ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    /// The bundled DLL: the pinned SHA-256; `admin_only_folder`: the service's own copy (not the console's).
    Bundled { admin_only_folder: bool },
    /// The service's download: a file version above `above`.
    Downloaded { above: NtVersion },
}

/// Opens `path` deny-write and runs every check of `trust`; the handle keeps the file as checked.
fn open_checked(path: &Path, trust: Trust) -> Result<(File, NtVersion), Refusal> {
    if let Trust::Bundled { admin_only_folder: true } = trust {
        match macvpn_winsys::acl_check::is_admin_only(path) {
            Ok(true) => {}
            Ok(false) => return Err("its folder is not admin-only".into()),
            Err(e) => return Err(format!("its folder cannot be checked ({:?})", e.kind())),
        }
    }
    // Held until the DLL is mapped: nobody can write, rename or delete it in between.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|e| format!("cannot open it ({:?})", e.kind()))?;
    let meta = file.metadata().map_err(|e| format!("cannot read its metadata ({:?})", e.kind()))?;
    let max = wg_update::DLL_MAX_BYTES;
    if !meta.is_file() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || meta.len() > max {
        return Err("not a plain file of a plausible size".into());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
    (&file).take(max + 1).read_to_end(&mut bytes).map_err(|e| format!("cannot read it ({:?})", e.kind()))?;
    if let Trust::Bundled { .. } = trust {
        let pin = wg_pins::dll_sha256(std::env::consts::ARCH).ok_or("no pinned wireguard.dll for this architecture")?;
        if sha256_hex(&bytes) != pin {
            return Err("its SHA-256 is not the pinned one".into());
        }
    }
    let machine = wg_update::machine_of(std::env::consts::ARCH).ok_or("no wireguard.dll for this architecture")?;
    if wg_update::pe_dll_machine(&bytes) != Some(machine) {
        return Err("it is not a DLL for this machine".into());
    }
    match macvpn_winsys::trust::verify_signature(path) {
        Ok(signer) if signer.is_pinned(&wg_pins::PINS.signer, &wg_pins::PINS.signer_cas()) => {}
        Ok(signer) if signer.subject == wg_pins::PINS.signer => {
            return Err(format!(
                "it is signed by {:?} but not under a pinned CA (its chain's key SHA-256: {}; pinned: {}); a WinVPN \
                 release must add the new CA key to scripts/pins/wireguard-nt.txt",
                signer.subject,
                signer.chain_spki_sha256.join(", "),
                wg_pins::PINS.signer_ca_spki_sha256
            ));
        }
        Ok(signer) => return Err(format!("it is signed by {:?}, not by the pinned signer", signer.subject)),
        Err(e) => return Err(format!("its Authenticode signature is not valid ({e})")),
    }
    let version = macvpn_winsys::version::file_version(path)
        .map(NtVersion::from_file_version)
        .map_err(|e| format!("cannot read its version ({:?})", e.kind()))?;
    if let Trust::Downloaded { above } = trust
        && version <= above
    {
        return Err(format!("its version {version} is not above {above}"));
    }
    Ok((file, version))
}

/// Every check of [`load`] without loading: the version of a DLL that passed them.
pub fn inspect(path: &Path, trust: Trust) -> Result<NtVersion, Refusal> {
    open_checked(path, trust).map(|(_, version)| version)
}

/// Loads `path` (a plain absolute path) after every check of `trust`.
pub fn load(path: &Path, trust: Trust) -> Result<WgDll, Refusal> {
    let (file, nt_version) = open_checked(path, trust)?;
    let lib = Library::load(path).map_err(|e| format!("cannot load it ({e})"))?;
    drop(file);
    let sym = |name: &std::ffi::CStr| lib.symbol(name).map_err(|_| format!("it has no {}", name.to_string_lossy()));
    let (create, close, luid, set_config, set_state, set_logger, get_config) = (
        sym(c"WireGuardCreateAdapter")?,
        sym(c"WireGuardCloseAdapter")?,
        sym(c"WireGuardGetAdapterLUID")?,
        sym(c"WireGuardSetConfiguration")?,
        sym(c"WireGuardSetAdapterState")?,
        sym(c"WireGuardSetLogger")?,
        sym(c"WireGuardGetConfiguration")?,
    );
    // SAFETY (each transmute): a non-null export of a checked wireguard.dll (1.1's API, unchanged since 0.10), whose prototype in its
    // wireguard.h is the type it becomes: WIREGUARD_CREATE_ADAPTER_FUNC (LPCWSTR, LPCWSTR, const GUID*) ->
    // WIREGUARD_ADAPTER_HANDLE; WIREGUARD_CLOSE_ADAPTER_FUNC (WIREGUARD_ADAPTER_HANDLE) -> VOID;
    // WIREGUARD_GET_ADAPTER_LUID_FUNC (WIREGUARD_ADAPTER_HANDLE, NET_LUID*) -> VOID;
    // WIREGUARD_SET_CONFIGURATION_FUNC (WIREGUARD_ADAPTER_HANDLE, const WIREGUARD_INTERFACE*, DWORD) -> BOOL;
    // WIREGUARD_SET_ADAPTER_STATE_FUNC (WIREGUARD_ADAPTER_HANDLE, WIREGUARD_ADAPTER_STATE) -> BOOL;
    // WIREGUARD_SET_LOGGER_FUNC (WIREGUARD_LOGGER_CALLBACK) -> VOID; WIREGUARD_GET_CONFIGURATION_FUNC
    // (WIREGUARD_ADAPTER_HANDLE, WIREGUARD_INTERFACE*, DWORD*) -> BOOL; all WINAPI ("system"). The pointers stay
    // valid while `_lib` (moved into the same struct) is loaded.
    unsafe {
        Ok(WgDll {
            version: nt_version.to_string(),
            nt_version,
            downloaded: matches!(trust, Trust::Downloaded { .. }),
            create: std::mem::transmute::<*const c_void, CreateAdapter>(create),
            close: std::mem::transmute::<*const c_void, CloseAdapter>(close),
            luid: std::mem::transmute::<*const c_void, GetAdapterLuid>(luid),
            set_config: std::mem::transmute::<*const c_void, SetConfiguration>(set_config),
            set_state: std::mem::transmute::<*const c_void, SetAdapterState>(set_state),
            set_logger: std::mem::transmute::<*const c_void, SetLogger>(set_logger),
            get_config: std::mem::transmute::<*const c_void, GetConfiguration>(get_config),
            _lib: lib,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The console's bundled DLL (no admin-only folder check).
    const CONSOLE: Trust = Trust::Bundled { admin_only_folder: false };

    fn v(s: &str) -> NtVersion {
        NtVersion::parse(s).unwrap()
    }

    /// The SDK's other DLLs (`bin\<arch>\wireguard.dll`), as `scripts/fetch-wireguard-nt.sh` leaves them.
    fn sdk_dll(arch: &str) -> std::path::PathBuf {
        pinned_dll().parent().unwrap().parent().unwrap().join(arch).join("wireguard.dll")
    }

    /// The pinned DLL as `scripts/fetch-wireguard-nt.sh` leaves it (a plain drive path).
    fn pinned_dll() -> std::path::PathBuf {
        let arch = if cfg!(target_arch = "aarch64") { "arm64" } else { "amd64" };
        let p =
            Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(r"..\..\target\wireguard-nt\bin\{arch}\wireguard.dll"));
        let p = std::fs::canonicalize(&p)
            .unwrap_or_else(|e| panic!("{}: {e} (run scripts/fetch-wireguard-nt.sh first)", p.display()));
        std::path::PathBuf::from(p.to_str().unwrap().strip_prefix(r"\\?\").unwrap().to_owned())
    }

    fn scratch_copy(bytes: &[u8]) -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("winvpn-wgdll-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        let file = dir.join("wireguard.dll");
        std::fs::write(&file, bytes).unwrap();
        (dir, file)
    }

    #[test]
    fn the_pinned_dll_loads_and_reports_its_version() {
        // Loading wireguard.dll installs nothing (only creating an adapter would install the driver).
        let dll = load(&pinned_dll(), CONSOLE).unwrap();
        assert_eq!(dll.version, "1.1.0");
    }

    #[test]
    fn only_the_pinned_bytes_from_an_admin_only_folder_load() {
        let bytes = std::fs::read(pinned_dll()).unwrap();
        // The pinned bytes in a folder this user can write: refused for the service, allowed for the console.
        let (dir, copy) = scratch_copy(&bytes);
        assert_eq!(
            load(&copy, Trust::Bundled { admin_only_folder: true }).err().as_deref(),
            Some("its folder is not admin-only")
        );
        drop(load(&copy, CONSOLE).unwrap());
        // One byte more: refused before it is loaded, so the file stays deletable (not mapped).
        let mut tampered = bytes.clone();
        tampered.push(0);
        std::fs::write(&copy, &tampered).unwrap();
        assert_eq!(load(&copy, CONSOLE).err().as_deref(), Some("its SHA-256 is not the pinned one"));
        std::fs::remove_file(&copy).unwrap();
        // Another signed DLL (System32's version.dll): refused by its hash.
        let other = Path::new(r"C:\Windows\System32\version.dll");
        assert_eq!(load(other, CONSOLE).err().as_deref(), Some("its SHA-256 is not the pinned one"));
        // A file another process holds open for writing cannot be pinned: refused.
        std::fs::write(&copy, &bytes).unwrap();
        let writer = std::fs::OpenOptions::new().write(true).open(&copy).unwrap();
        assert!(load(&copy, CONSOLE).err().unwrap().starts_with("cannot open it"));
        drop(writer);
        // Relative and missing paths.
        assert!(load(Path::new("wireguard.dll"), CONSOLE).is_err());
        assert!(load(&dir.join("missing.dll"), CONSOLE).err().unwrap().starts_with("cannot open it"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_loaded_dll_keeps_its_file_pinned() {
        // While the loader maps it nobody may replace it; once loaded, Windows itself refuses writes to a mapped image.
        let bytes = std::fs::read(pinned_dll()).unwrap();
        let (dir, copy) = scratch_copy(&bytes);
        let dll = load(&copy, CONSOLE).unwrap();
        assert!(std::fs::OpenOptions::new().write(true).open(&copy).is_err());
        drop(dll);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_downloaded_dll_needs_the_signer_this_machine_and_a_higher_version() {
        let bytes = std::fs::read(pinned_dll()).unwrap();
        let (dir, copy) = scratch_copy(&bytes);
        // The real 1.1 DLL counts as a download above 1.0, never above itself (no pin is asked for).
        assert_eq!(inspect(&copy, Trust::Downloaded { above: v("1.0") }), Ok(v("1.1")));
        let dll = load(&copy, Trust::Downloaded { above: v("1.0") }).unwrap();
        assert!(dll.downloaded && dll.version == "1.1.0");
        drop(dll);
        assert_eq!(
            inspect(&copy, Trust::Downloaded { above: v("1.1") }).err().as_deref(),
            Some("its version 1.1.0 is not above 1.1.0")
        );
        // One byte changed in the middle: the Authenticode hash no longer matches.
        let mut tampered = bytes.clone();
        let mid = tampered.len() / 2;
        tampered[mid] ^= 0xFF;
        std::fs::write(&copy, &tampered).unwrap();
        let why = inspect(&copy, Trust::Downloaded { above: v("1.0") }).unwrap_err();
        assert!(why.starts_with("its Authenticode signature is not valid"), "{why}");
        // A validly signed DLL of another signer (Microsoft's version.dll).
        let why =
            inspect(Path::new(r"C:\Windows\System32\version.dll"), Trust::Downloaded { above: v("0.1") }).unwrap_err();
        assert!(why.contains("not by the pinned signer"), "{why}");
        // WireGuard LLC's DLLs for the other machines of the SDK.
        let other = if cfg!(target_arch = "aarch64") { "amd64" } else { "arm64" };
        for arch in [other, "x86"] {
            let why = inspect(&sdk_dll(arch), Trust::Downloaded { above: v("1.0") }).unwrap_err();
            assert_eq!(why, "it is not a DLL for this machine", "{arch}");
        }
        // Unsigned bytes that only look like a DLL.
        std::fs::write(&copy, b"MZ not a dll").unwrap();
        assert!(inspect(&copy, Trust::Downloaded { above: v("0.1") }).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_sdk_zip_yields_the_pinned_dll() {
        // `scripts/fetch-wireguard-nt.sh` keeps the pinned zip as target\wireguard-nt.zip.
        let zip = std::fs::read(pinned_dll().parent().unwrap().join(r"..\..\..\wireguard-nt.zip")).unwrap();
        let member = wg_update::dll_member(std::env::consts::ARCH).unwrap();
        let inflate = |data: &[u8], limit: usize| miniz_oxide::inflate::decompress_to_vec_with_limit(data, limit).ok();
        let dll = wg_update::extract(&zip, member, wg_update::DLL_MAX_BYTES, inflate).unwrap();
        assert_eq!(sha256_hex(&dll), wg_pins::dll_sha256(std::env::consts::ARCH).unwrap());
        assert_eq!(wg_update::pe_dll_machine(&dll), wg_update::machine_of(std::env::consts::ARCH));
    }
}
