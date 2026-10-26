//! An MSI package's `Property` table, read through the Windows Installer database API (read-only: nothing is
//! installed, no UI, no Windows Installer service). WinVPN's elevated OpenVPN step checks what the package says it
//! installs (`ProductName`, `ProductVersion`, `UpgradeCode`, `Manufacturer`) instead of trusting its file name.

use crate::util::wide_path;
use std::io;
use std::path::Path;
use windows_sys::Win32::Foundation::{ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS};
use windows_sys::Win32::System::ApplicationInstallationAndServicing::{
    MSIDBOPEN_CREATE, MSIDBOPEN_READONLY, MSIHANDLE, MsiCloseHandle, MsiCreateRecord, MsiDatabaseCommit,
    MsiDatabaseImportW, MsiDatabaseOpenViewW, MsiOpenDatabaseW, MsiRecordGetStringW, MsiRecordSetStringW,
    MsiViewExecute, MsiViewFetch,
};

/// At most this many rows are read (OpenVPN's MSIs have about 40 properties).
const MAX_ROWS: usize = 4096;
/// The longest value read, in UTF-16 units.
const MAX_VALUE_UNITS: u32 = 64 * 1024;

/// An MSI handle, closed on drop.
struct Handle(MSIHANDLE);

impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: a handle an Msi* call returned and nothing else closes.
            unsafe { MsiCloseHandle(self.0) };
        }
    }
}

fn rc(what: &str, code: u32) -> io::Result<()> {
    if code == ERROR_SUCCESS { Ok(()) } else { Err(io::Error::other(format!("{what} failed ({code})"))) }
}

fn wide_str(s: &str) -> io::Result<Vec<u16>> {
    wide_path(Path::new(s))
}

fn open(path: &Path, persist: windows_sys::core::PCWSTR) -> io::Result<Handle> {
    let name = wide_path(path)?;
    let mut db: MSIHANDLE = 0;
    // SAFETY: `name` is NUL-terminated and alive across the call; `persist` is one of the MSIDBOPEN_* constants (a
    // small integer in a pointer, as the API defines them); `db` is a valid out pointer.
    rc("MsiOpenDatabaseW", unsafe { MsiOpenDatabaseW(name.as_ptr(), persist, &mut db) })?;
    Ok(Handle(db))
}

fn view(db: &Handle, query: &str, params: Option<&Handle>) -> io::Result<Handle> {
    let q = wide_str(query)?;
    let mut v: MSIHANDLE = 0;
    // SAFETY: an open database handle; `q` is NUL-terminated and alive across the call; `v` is a valid out pointer.
    rc("MsiDatabaseOpenViewW", unsafe { MsiDatabaseOpenViewW(db.0, q.as_ptr(), &mut v) })?;
    let v = Handle(v);
    // SAFETY: an open view handle; the record handle is 0 or an open record.
    rc("MsiViewExecute", unsafe { MsiViewExecute(v.0, params.map_or(0, |p| p.0)) })?;
    Ok(v)
}

/// One string field of a record (1-based).
fn field(record: &Handle, index: u32) -> io::Result<String> {
    let mut buf = vec![0u16; 256];
    loop {
        let mut len = buf.len() as u32;
        // SAFETY: an open record handle; `buf` is valid for writes of `len` units (`len` counts the NUL).
        let code = unsafe { MsiRecordGetStringW(record.0, index, buf.as_mut_ptr(), &mut len) };
        match code {
            ERROR_SUCCESS => return Ok(String::from_utf16_lossy(&buf[..len as usize])),
            ERROR_MORE_DATA if len < MAX_VALUE_UNITS => buf.resize(len as usize + 1, 0),
            _ => return rc("MsiRecordGetStringW", code).map(|_| String::new()),
        }
    }
}

/// Every row of the package's `Property` table as (name, value), in the table's order. The package is opened
/// read-only (`MSIDBOPEN_READONLY`); a file that is not an MSI database is an error.
pub fn properties(path: &Path) -> io::Result<Vec<(String, String)>> {
    let db = open(path, MSIDBOPEN_READONLY)?;
    let v = view(&db, "SELECT `Property`, `Value` FROM `Property`", None)?;
    let mut rows = Vec::new();
    loop {
        let mut r: MSIHANDLE = 0;
        // SAFETY: an executed view handle; `r` is a valid out pointer.
        let code = unsafe { MsiViewFetch(v.0, &mut r) };
        if code == ERROR_NO_MORE_ITEMS {
            return Ok(rows);
        }
        rc("MsiViewFetch", code)?;
        let r = Handle(r);
        if rows.len() >= MAX_ROWS {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "too many properties"));
        }
        rows.push((field(&r, 1)?, field(&r, 2)?));
    }
}

/// Tests only: a new MSI database at `path` (it must not exist) with only a `Property` table holding `rows`, its
/// strings stored in the ANSI code page `codepage` (as a real package states its own). Without one
/// the database is code-page neutral and Windows Installer stores its strings in the machine's ANSI code page, so
/// what survives depends on the machine (`ű` and `ő` become `u` and `o` under 1252). No privilege needed; nothing
/// is installed.
#[doc(hidden)]
pub fn create_for_tests(path: &Path, codepage: u16, rows: &[(&str, &str)]) -> io::Result<()> {
    let db = open(path, MSIDBOPEN_CREATE)?;
    set_codepage(&db, path, codepage)?;
    view(
        &db,
        "CREATE TABLE `Property` (`Property` CHAR(72) NOT NULL, `Value` LONGCHAR NOT NULL LOCALIZABLE \
         PRIMARY KEY `Property`)",
        None,
    )?;
    for (name, value) in rows {
        // SAFETY: plain call; returns 0 on failure.
        let record = Handle(unsafe { MsiCreateRecord(2) });
        if record.0 == 0 {
            return Err(io::Error::other("MsiCreateRecord failed"));
        }
        for (i, s) in [(1, name), (2, value)] {
            let w = wide_str(s)?;
            // SAFETY: an open record handle; `w` is NUL-terminated and alive across the call.
            rc("MsiRecordSetStringW", unsafe { MsiRecordSetStringW(record.0, i, w.as_ptr()) })?;
        }
        view(&db, "INSERT INTO `Property` (`Property`, `Value`) VALUES (?, ?)", Some(&record))?;
    }
    // SAFETY: an open database handle.
    rc("MsiDatabaseCommit", unsafe { MsiDatabaseCommit(db.0) })
}

/// Sets the code page of a new, empty database: the `_ForceCodepage` import (an `.idt` file of two empty lines and
/// `<codepage>\t_ForceCodepage`), written next to the database and removed again.
fn set_codepage(db: &Handle, path: &Path, codepage: u16) -> io::Result<()> {
    let dir = path.parent().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no folder"))?;
    let name = format!("winvpn-codepage-{}.idt", std::process::id());
    let idt = dir.join(&name);
    std::fs::write(&idt, format!("\r\n\r\n{codepage}\t_ForceCodepage\r\n"))?;
    let (folder, file) = (wide_path(dir)?, wide_str(&name)?);
    // SAFETY: an open database handle; both strings are NUL-terminated and alive across the call.
    let code = unsafe { MsiDatabaseImportW(db.0, folder.as_ptr(), file.as_ptr()) };
    let _ = std::fs::remove_file(&idt);
    rc("MsiDatabaseImportW", code)
}
