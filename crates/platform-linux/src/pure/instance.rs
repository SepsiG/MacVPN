//! The single-instance name on the session bus: `local.linvpn.Instance`; a sandbox owns
//! `local.linvpn.Sandbox.h<16 hex digits of SHA-256(the sandbox path)>`, so a smoke run never meets an installed
//! LinVPN. And the files of a launch: its absolute arguments (`linvpn %F`); options and relative paths are not files.

use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub fn bus_name(sandbox: Option<&Path>) -> String {
    match sandbox {
        None => "local.linvpn.Instance".into(),
        Some(p) => {
            // On Unix the encoded bytes are the path's raw bytes (and the module still compiles on every OS).
            let digest = Sha256::digest(p.as_os_str().as_encoded_bytes());
            let hex: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
            format!("local.linvpn.Sandbox.h{hex}")
        }
    }
}

pub fn launch_files(args: impl IntoIterator<Item = OsString>) -> Vec<PathBuf> {
    args.into_iter().map(PathBuf::from).filter(|p| p.is_absolute()).collect()
}
