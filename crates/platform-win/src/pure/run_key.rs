//! Launch at login: the `HKCU\…\Run` value and Settings' StartupApproved switch.

use std::path::Path;

/// The Run value's data: the quoted executable path (Windows splits an unquoted path with spaces at the first
/// space and could start `C:\Program.exe`).
pub fn command(exe: &Path) -> String {
    format!("\"{}\"", exe.display())
}

/// Whether `exe` can be registered: absolute, UTF-8, no quote (it would end the quoting) and no control character.
pub fn usable(exe: &Path) -> bool {
    exe.is_absolute() && exe.to_str().is_some_and(|s| !s.contains('"') && !s.chars().any(char::is_control))
}

/// `…\Explorer\StartupApproved\Run\<name>`: a 12-byte value whose first byte is 2 (enabled) or 3 (disabled by the
/// user in Settings or Task Manager). An odd first byte means disabled; a missing value means enabled.
pub fn disabled_in_settings(value: &[u8]) -> bool {
    value.first().is_some_and(|b| b & 1 == 1)
}
