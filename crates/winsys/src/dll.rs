//! DLLs only from System32 and from where the caller says.
//!
//! [`harden_process_search`] removes the application directory, the current directory and `PATH` from the process'
//! DLL search: `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` (every later `LoadLibrary*` without search
//! flags, including the system's own delay loads, searches System32 only) and `SetDllDirectoryW("")` (no current
//! directory in the legacy search either). [`Library::load`] takes a plain absolute path only and resolves the
//! DLL's own imports from its folder and System32 (`LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR |
//! LOAD_LIBRARY_SEARCH_SYSTEM32`). Whether the file at that path is the right one (its SHA-256, an admin-only
//! folder) is the caller's check, made before loading. [`Library::system32`] loads a Windows DLL by its bare name
//! from System32 only (for one that is needed rarely, such as `rasdlg.dll`).

use crate::util::{plain_absolute, wide, wide_path};
use std::ffi::{CStr, c_void};
use std::io;
use std::path::Path;
use windows_sys::Win32::Foundation::{FreeLibrary, HMODULE};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32, LoadLibraryExW,
    SetDefaultDllDirectories, SetDllDirectoryW,
};

/// Restricts the process' DLL search to System32. Call it first thing in `main`. Both calls exist and succeed on
/// every supported Windows (10 and later); if either fails the process aborts: it must not go on with an unsafe
/// DLL search.
pub fn harden_process_search() {
    // SAFETY: plain flags; no pointers.
    let ok = unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) } != 0;
    let empty = [0u16];
    // SAFETY: `empty` is a NUL-terminated (empty) string that lives across the call.
    let ok = ok && unsafe { SetDllDirectoryW(empty.as_ptr()) } != 0;
    if !ok {
        eprintln!("cannot restrict the DLL search path: {}", io::Error::last_os_error());
        std::process::abort();
    }
}

/// A loaded DLL, freed (`FreeLibrary`) on drop.
#[derive(Debug)]
pub struct Library(HMODULE);

// SAFETY: a module handle is valid process-wide and on any thread; `FreeLibrary` and `GetProcAddress` may be called
// from any thread.
unsafe impl Send for Library {}
// SAFETY: as above; `symbol` only reads the module's export table, which the loader synchronizes.
unsafe impl Sync for Library {}

impl Library {
    /// Loads the DLL at `path` (a plain absolute path; a bare name or relative path is refused before any search).
    pub fn load(path: &Path) -> io::Result<Library> {
        plain_absolute(path)?;
        let name = wide_path(path)?;
        // SAFETY: `name` is NUL-terminated and lives across the call; no file handle (must be null).
        let module = unsafe {
            LoadLibraryExW(
                name.as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if module.is_null() { Err(io::Error::last_os_error()) } else { Ok(Library(module)) }
    }

    /// Loads the system DLL `name` (a bare file name such as `rasdlg.dll`) from System32 only
    /// (`LOAD_LIBRARY_SEARCH_SYSTEM32`): for system DLLs loaded only when a rarely used call needs them.
    pub fn system32(name: &str) -> io::Result<Library> {
        if name.is_empty() || name.contains(['\\', '/', ':']) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "a bare DLL file name is required"));
        }
        let name = wide(std::ffi::OsStr::new(name))?;
        // SAFETY: `name` is NUL-terminated and lives across the call; no file handle (must be null).
        let module = unsafe { LoadLibraryExW(name.as_ptr(), std::ptr::null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
        if module.is_null() { Err(io::Error::last_os_error()) } else { Ok(Library(module)) }
    }

    /// The address of the export `name`. Calling it (with the right signature) is the caller's `unsafe`; the
    /// address is valid while this `Library` lives.
    pub fn symbol(&self, name: &CStr) -> io::Result<*const c_void> {
        // SAFETY: the module is loaded (owned by `self`); `name` is NUL-terminated and lives across the call.
        match unsafe { GetProcAddress(self.0, name.as_ptr().cast()) } {
            Some(f) => Ok(f as *const c_void),
            None => Err(io::Error::last_os_error()),
        }
    }
}

impl Drop for Library {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful LoadLibraryExW and is freed exactly once, here.
        unsafe { FreeLibrary(self.0) };
    }
}
