//! The command line of `openvpn.exe` in the WinVPN Service: only the run directory (a UUID below the service's
//! data directory), a port number, the chosen driver and fixed words. The management options come after the
//! config, so they override the same directives of the config (which the Windows tier forbids anyway). No `--log`:
//! stdout and stderr go to the service, which masks them into the connection log.
//!
//! Portable (no `cfg`): tested on every OS. Paths below the run directory are joined with `\` whatever the host,
//! because they are Windows paths for a Windows process.

use std::ffi::OsString;
use std::path::Path;

pub use macvpn_core::service_proto::Version;

/// The data-channel driver of one connection (decision 4 of the 2b plan, amended 2026-10-22: OpenVPN 2.7.8 with
/// DCO and TAP-Windows6; no Wintun, which OpenVPN 2.7 removed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Driver {
    Dco,
    TapWindows6,
}

impl Driver {
    /// The options that select the driver. OpenVPN 2.7 ignores `--windows-driver` (a deprecation warning; DCO
    /// unless disabled, else TAP-Windows6: `options.c` of 2.7.8), so the driver is chosen through DCO itself: nothing
    /// for DCO (the default since 2.6.0), `--disable-dco` for TAP-Windows6. 2.6.x picks the same driver for both.
    pub fn args(self) -> &'static [&'static str] {
        match self {
            Driver::Dco => &[],
            Driver::TapWindows6 => &["--disable-dco"],
        }
    }

    /// The driver's name in messages and System Status.
    pub fn name(self) -> &'static str {
        match self {
            Driver::Dco => "OpenVPN DCO",
            Driver::TapWindows6 => "TAP-Windows6",
        }
    }
}

/// The data ciphers ovpn-dco-win runs (OpenVPN 2.7.8 `dco_win.c`, `dco_get_supported_ciphers`; CHACHA20-POLY1305
/// only from Windows 11 on — on Windows 10 OpenVPN disables DCO itself and falls back to TAP-Windows6).
const DCO_CIPHERS: [&str; 4] = ["AES-128-GCM", "AES-192-GCM", "AES-256-GCM", "CHACHA20-POLY1305"];

/// The driver for a validated config, by the rules of the pinned OpenVPN (2.7.8 `dco.c`: `dco_check_option`,
/// `dco_check_option_ce`, `dco_check_startup_option`; the same client-side rules as 2.6.23):
/// - TAP-Windows6 for a layer-2 device (`dev tap…`, `dev-type tap`);
/// - TAP-Windows6 for what DCO cannot run: any compression context (`comp-lzo` in any form, `compress` other than
///   `compress migrate` — `compress stub-v2` too), `allow-compression` other than `no`, a `cipher` /
///   `data-ciphers` / `data-ciphers-fallback` / `ncp-ciphers` list with a cipher outside [`DCO_CIPHERS`] (an
///   optional `?` marker ignored), `fragment`, `http-proxy`, `socks-proxy`, a static `secret` (no TLS),
///   `disable-dco`;
/// - DCO otherwise.
///
/// Reads the directives the validator accepted: top level and `<connection>` blocks, skipping comments and inline
/// blocks, `setenv opt <d>` counted as `<d>`. Never reads `windows-driver` (forbidden on Windows). A wrong guess
/// towards DCO is not fatal: OpenVPN then disables DCO itself and uses TAP-Windows6.
pub fn choose_driver(config: &str) -> Driver {
    let mut in_block: Option<String> = None;
    for raw in config.lines() {
        let line = raw.trim();
        if let Some(tag) = &in_block {
            if line.eq_ignore_ascii_case(&format!("</{tag}>")) {
                in_block = None;
            }
            continue;
        }
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(tag) = line.strip_prefix('<').and_then(|t| t.strip_suffix('>')) {
            if !tag.starts_with('/') && !tag.eq_ignore_ascii_case("connection") {
                in_block = Some(tag.to_ascii_lowercase());
            }
            continue;
        }
        let mut words = line.split_whitespace().map(|w| w.trim_matches(|c| c == '"' || c == '\''));
        let mut d = words.next().unwrap_or_default().trim_start_matches("--").to_ascii_lowercase();
        if d == "setenv" && words.next().is_some_and(|w| w.eq_ignore_ascii_case("opt")) {
            d = words.next().unwrap_or_default().to_ascii_lowercase();
        }
        let first = words.next().unwrap_or_default();
        let no_dco = match d.as_str() {
            "dev" => first.to_ascii_lowercase().starts_with("tap"),
            "dev-type" => first.eq_ignore_ascii_case("tap"),
            "comp-lzo" | "fragment" | "secret" | "disable-dco" | "http-proxy" | "socks-proxy" => true,
            "compress" => !first.eq_ignore_ascii_case("migrate"),
            "allow-compression" => !first.eq_ignore_ascii_case("no"),
            "cipher" | "data-ciphers" | "data-ciphers-fallback" | "ncp-ciphers" => !first
                .split(':')
                .all(|c| DCO_CIPHERS.iter().any(|d| d.eq_ignore_ascii_case(c.strip_prefix('?').unwrap_or(c)))),
            _ => false,
        };
        if no_dco {
            return Driver::TapWindows6;
        }
    }
    Driver::Dco
}

/// `<run>\<name>`: a fixed file name in the run directory, as a Windows path.
fn in_run(run: &Path, name: &str) -> OsString {
    let mut p = run.as_os_str().to_os_string();
    p.push("\\");
    p.push(name);
    p
}

/// The argv after `openvpn.exe`. `user_pass`: credentials go through the management bridge; `keypass`: the private
/// key's password file (`<run>\askpass`); `debug`: verbosity 5 instead of 3.
pub fn argv(run: &Path, port: u16, driver: Driver, debug: bool, user_pass: bool, keypass: bool) -> Vec<OsString> {
    let word = |s: &str| OsString::from(s);
    let mut a = vec![word("--config"), in_run(run, "config.ovpn")];
    a.extend(["--script-security", "1"].into_iter().chain(driver.args().iter().copied()).map(word));
    // After the config, so the config's own `verb` / `mute` cannot raise the volume; at most 20 consecutive messages
    // of one kind (e.g. "write UDPv4: Network is unreachable" while offline), the connection log has a cap too.
    a.extend(["--verb", if debug { "5" } else { "3" }, "--mute", "20"].map(word));
    a.extend([word("--management"), word("127.0.0.1"), OsString::from(port.to_string()), in_run(run, "mgmt.pw")]);
    a.extend(
        [
            "--management-hold",
            "--management-query-passwords",
            "--auth-retry",
            "interact",
            "--setenv",
            "IV_SSO",
            "openurl,webauth,crtext",
        ]
        .map(word),
    );
    if user_pass {
        a.push(word("--auth-user-pass"));
    }
    if keypass {
        a.extend([word("--askpass"), in_run(run, "askpass")]);
    }
    a
}
