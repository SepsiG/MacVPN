//! `mvpn console` (the service's server as the current user, debug builds only) for the tests: start it on a fresh
//! test pipe and data directory, call it over the pipe, stop it and remove the directory on drop.

use macvpn_core::service_proto::{self as proto, Response};
use macvpn_winsys::pipe::{self, ServerTrust};
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

pub struct Console {
    pub child: Child,
    pub pipe: String,
    pub data: std::path::PathBuf,
}

pub fn test_pipe() -> String {
    format!(r"\\.\pipe\WinVPN-test-{}", uuid::Uuid::new_v4())
}

/// Starts `mvpn console` and waits for its `ready` line.
pub fn spawn(args: &[&str]) -> Child {
    let mut child = Command::new(env!("CARGO_BIN_EXE_mvpn"))
        .arg("console")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut first = String::new();
    BufReader::new(child.stdout.as_mut().unwrap()).read_line(&mut first).unwrap();
    assert_eq!(first.trim(), "ready");
    child
}

impl Console {
    /// With the fake engines (`fake`) or the real ones.
    pub fn start(fake: bool) -> Console {
        Console::start_with(if fake { &["--fake-engine"] } else { &[] })
    }

    /// With more console options (`--fake-engine`, `--wireguard-dll <path>`).
    pub fn start_with(extra_args: &[&str]) -> Console {
        let pipe = test_pipe();
        let data = std::env::temp_dir().join(format!("winvpn-console-{}", uuid::Uuid::new_v4()));
        let mut args = vec!["--pipe", &pipe, "--data", data.to_str().unwrap()];
        args.extend_from_slice(extra_args);
        let child = spawn(&args);
        Console { child, pipe, data }
    }

    pub fn call(&self, args: &[&str], body: &[u8]) -> Response {
        let mut s = pipe::connect_with(&self.pipe, Duration::from_secs(5), ServerTrust::SameUser).unwrap();
        proto::write_request(&mut s, args, body).unwrap();
        proto::read_response(&mut s).unwrap()
    }
}

impl Drop for Console {
    fn drop(&mut self) {
        drop(self.child.stdin.take()); // closing stdin stops the console
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.data);
    }
}

/// The root layer 8 frame of a config without secrets.
pub fn framed(config: &str) -> Vec<u8> {
    format!("config {}\n{config}", config.len()).into_bytes()
}

/// The pinned `wireguard.dll` of this architecture as `scripts/fetch-wireguard-nt.sh` leaves it.
pub fn wireguard_dll() -> std::path::PathBuf {
    let arch = if cfg!(target_arch = "aarch64") { "arm64" } else { "amd64" };
    let dll = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!(r"..\..\target\wireguard-nt\bin\{arch}\wireguard.dll"));
    let dll = std::fs::canonicalize(&dll)
        .unwrap_or_else(|e| panic!("{}: {e} (run scripts/fetch-wireguard-nt.sh first)", dll.display()));
    // `canonicalize` gives `\\?\C:\…`; the service takes plain drive paths only.
    std::path::PathBuf::from(dll.to_str().unwrap().strip_prefix(r"\\?\").unwrap().to_owned())
}
