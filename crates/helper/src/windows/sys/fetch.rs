//! The WinVPN Service's downloads (2b plan, "As built (fix4)": wireguard-nt updates): System32's `curl.exe` with a
//! fixed argv (`wg_update::curl_args`: HTTPS only, no redirects, TLS 1.2+, size and time caps), an environment of
//! `SystemRoot` and `PATH=<System32>` only (the 2b curl runner's rule), no window, no stdin; the service's job
//! object takes it down with the service. Only the service's own fixed URLs are fetched, into files of its admin-only
//! data directory; nothing of a request reaches the argv. The service cannot use the app's curl layer (that crate
//! brings the vault, which the service must not link), so this is the service's own small runner.

use crate::windows::wg_update;
use std::io::Read;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// `CREATE_NO_WINDOW` (winbase.h).
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// The runner's margin over curl's own `--max-time`.
const MARGIN: Duration = Duration::from_secs(30);

/// Fetches one of the service's fixed URLs into `output` (a path the caller chose and removes).
pub(crate) trait Fetcher: Send + Sync {
    fn fetch(&self, url: &str, output: &Path, max_bytes: u64, max_time: u64) -> Result<(), String>;
}

/// System32's curl.
pub(crate) struct CurlFetcher;

impl Fetcher for CurlFetcher {
    fn fetch(&self, url: &str, output: &Path, max_bytes: u64, max_time: u64) -> Result<(), String> {
        let system32 = macvpn_winsys::known::system32().map_err(|e| format!("no System32 ({:?})", e.kind()))?;
        let windows = macvpn_winsys::known::windows_dir().map_err(|e| format!("no Windows folder ({:?})", e.kind()))?;
        let out = output.to_str().ok_or("the output path is not Unicode")?;
        let mut child = Command::new(system32.join("curl.exe"))
            .args(wg_update::curl_args(url, out, max_bytes, max_time))
            .env_clear()
            .env("SystemRoot", &windows)
            .env("PATH", &system32)
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("curl did not start ({:?})", e.kind()))?;
        let (stdout, stderr) = (child.stdout.take(), child.stderr.take());
        let out_reader = std::thread::spawn(move || read_capped(stdout));
        let err_reader = std::thread::spawn(move || read_capped(stderr));
        let deadline = Instant::now() + Duration::from_secs(max_time) + MARGIN;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
                Ok(None) => break Err("curl timed out".to_string()),
                Err(e) => break Err(format!("curl could not be watched ({:?})", e.kind())),
            }
        };
        if status.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let status = status?;
        let http = out_reader.join().unwrap_or_default();
        let message = err_reader.join().unwrap_or_default();
        match (status.code(), http.trim()) {
            (Some(0), "200") => Ok(()),
            (Some(0), code) => Err(format!("HTTP {code}")),
            (code, _) => Err(format!("curl failed ({code:?}): {}", message.trim())),
        }
    }
}

/// The first 4 KiB of a pipe as text (curl prints the status code and at most an error line); the rest is drained.
fn read_capped(pipe: Option<impl Read>) -> String {
    let mut kept = Vec::new();
    if let Some(mut p) = pipe {
        let _ = p.by_ref().take(4096).read_to_end(&mut kept);
        let _ = std::io::copy(&mut p, &mut std::io::sink());
    }
    String::from_utf8_lossy(&kept).into_owned()
}

/// The console's fetcher when it has no fixtures: the console never goes online (the tests stay offline).
#[cfg(debug_assertions)]
pub(crate) struct Offline;

#[cfg(debug_assertions)]
impl Fetcher for Offline {
    fn fetch(&self, _url: &str, _output: &Path, _max_bytes: u64, _max_time: u64) -> Result<(), String> {
        Err("offline (console)".into())
    }
}

/// The console's `--wireguard-updates <dir>` (tests): the listing is `<dir>\listing.html`, a zip
/// `<dir>\wireguard-nt-<version>.zip`; any other URL, a missing file or one above `max_bytes` fails.
#[cfg(debug_assertions)]
pub(crate) struct Fixtures(pub std::path::PathBuf);

#[cfg(debug_assertions)]
impl Fetcher for Fixtures {
    fn fetch(&self, url: &str, output: &Path, max_bytes: u64, _max_time: u64) -> Result<(), String> {
        let name = match url.strip_prefix(wg_update::LISTING_URL) {
            Some("") => "listing.html",
            Some(zip) if zip.starts_with("wireguard-nt-") && zip.ends_with(".zip") && !zip.contains(['/', '\\']) => zip,
            _ => return Err(format!("not a fixture URL: {url}")),
        };
        let bytes = std::fs::read(self.0.join(name)).map_err(|e| format!("{name}: {:?}", e.kind()))?;
        if bytes.len() as u64 > max_bytes {
            return Err("above --max-filesize".into());
        }
        std::fs::write(output, bytes).map_err(|e| format!("cannot write ({:?})", e.kind()))
    }
}
