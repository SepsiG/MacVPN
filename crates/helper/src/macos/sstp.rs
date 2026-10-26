//! SSTP through Homebrew `sstp-client` (sstpc) and the macOS `/usr/sbin/pppd`:
//!
//! ```text
//! sstpc --log-stderr --log-level <2|4> --tls-ext --save-server-route [--ca-cert <run>/ca.pem | --cert-warn]
//!       --user <user> --password <password> <host>:<port>
//!       -- logfile <run>/pppd.log require-mschap-v2 refuse-pap refuse-chap refuse-mschap refuse-eap noauth nodetach
//!          [usepeerdns] [defaultroute] [debug]
//! ```
//!
//! The password is on sstpc's command line (the brew sstpc only starts that way and computes the MPPE keys for the
//! crypto binding itself; it blanks its own argv after reading). The log and the dry-run output show `***`;
//! sstpc's output goes through a long-running masker that reads the secrets once from a root 0600 file and
//! deletes it. The password must not contain `"`, `\` or a control character (sstpc writes it unescaped into a
//! pppd option file). Interface, address and DNS come only from the root-only `pppd.log`, with anchored patterns.
//! Routes for "all traffic" are two `/1` routes; DNS goes through the shared DNS hook.

use crate::macos::ctx::{Ctx, Exit, R, tr};
use crate::macos::exec::{Cmd, EnvMode};
use crate::macos::fsx;
use crate::macos::log::flush_root_log;
use crate::macos::paths::{is_dir, is_file, is_symlink};
use crate::macos::procs;
use regex::bytes::Regex;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::LazyLock;

/// The validated, normalized parameters (checked again here as defence in depth).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SstpParams {
    pub host: String,
    pub port: String,
    pub user: String,
    pub cert: String,
    pub route_all: String,
    pub peer_dns: String,
}

impl SstpParams {
    pub fn from_lines(lines: &[String]) -> Option<SstpParams> {
        let get = |i: usize| lines.get(i).cloned().unwrap_or_default();
        let p =
            SstpParams { host: get(0), port: get(1), user: get(2), cert: get(3), route_all: get(4), peer_dns: get(5) };
        p.valid().then_some(p)
    }

    fn valid(&self) -> bool {
        let h = self.host.as_bytes();
        let host_ok = !h.is_empty()
            && (h[0].is_ascii_alphanumeric() || matches!(h[0], b'.' | b':'))
            && h.iter().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b':' | b'-'));
        let port_ok = (1..=5).contains(&self.port.len()) && self.port.bytes().all(|b| b.is_ascii_digit());
        let u = self.user.as_bytes();
        let user_ok = !u.is_empty()
            && (u[0].is_ascii_alphanumeric() || matches!(u[0], b'.' | b'_' | b'@' | b'+'))
            && u.iter().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'@' | b'+' | b'-'));
        host_ok
            && port_ok
            && user_ok
            && matches!(self.cert.as_str(), "system" | "ca" | "insecure")
            && matches!(self.route_all.as_str(), "yes" | "no")
            && matches!(self.peer_dns.as_str(), "yes" | "no")
    }

    /// `host:port`, an IPv6 host in brackets.
    pub fn target(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// `sstp_load_params`
pub fn load_params(ctx: &mut Ctx) -> Option<SstpParams> {
    let p = crate::macos::validate::sstp_params(&ctx.run().join("config")).and_then(|l| SstpParams::from_lines(&l))?;
    ctx.sstp = Some(p.clone());
    Some(p)
}

/// The SSTP password rule (the Swift `SSTPConfig.isAcceptablePassword` mirror, byte-level: no `"`, `\` or
/// control character; the C1 range is filtered by the app).
pub fn password_ok(pw: &[u8]) -> bool {
    !pw.iter().any(|&b| b == b'"' || b == b'\\' || b < 0x20 || b == 0x7F)
}

pub fn sstp_alive(pid: &str) -> bool {
    procs::alive_as(pid, "sstpc")
}

pub fn pppd_alive(pid: &str) -> bool {
    procs::alive_as(pid, "pppd")
}

/// Does the interface exist? In test mode `MVPN_TEST_IFACE_OK=1` says yes (the fake sstpc makes no ppp).
pub fn iface_up(ctx_test: bool, iface_ok: bool, iface: &str) -> bool {
    if ctx_test && iface_ok {
        return true;
    }
    crate::macos::exec::quiet(&Cmd::new("/sbin/ifconfig").arg(iface), EnvMode::Minimal)
}

const PPPD_TS: &str = r"([A-Z][a-z]{2} [A-Z][a-z]{2} +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4} : )?";
static IFACE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!(r"(?-u)^{PPPD_TS}Using interface (ppp[0-9]+)$")).expect("valid"));
static IP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(r"(?-u)^{PPPD_TS}local +IP address ([0-9]{{1,3}}(\.[0-9]{{1,3}}){{3}})$")).expect("valid")
});
static DNS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(r"(?-u)^{PPPD_TS}(primary|secondary) +DNS address ([0-9A-Fa-f:.]+)$")).expect("valid")
});

/// One field of the pppd log, every match in order (`iface`, `ip`, `dns`): an optional pppd timestamp, nothing
/// else before the anchored text.
pub fn pppd_fields(data: &[u8], field: &str) -> Vec<String> {
    let (re, group) = match field {
        "iface" => (&*IFACE_RE, 2),
        "ip" => (&*IP_RE, 2),
        _ => (&*DNS_RE, 3),
    };
    crate::shared::mask::lines(data)
        .filter_map(|l| {
            re.captures(l).and_then(|c| c.get(group)).map(|m| String::from_utf8_lossy(m.as_bytes()).into_owned())
        })
        .collect()
}

fn pppd_log_fields(run: &Path, field: &str) -> Vec<String> {
    let f = run.join("pppd.log");
    if !is_file(&f) || is_symlink(&f) {
        return Vec::new();
    }
    pppd_fields(&crate::macos::log::read_range(&f, 0, 16 << 20).unwrap_or_default(), field)
}

fn flush_pppd(ctx: &Ctx) {
    flush_root_log(&ctx.log, &ctx.run().join("pppd.log"), "[pppd] ", false, &ctx.masker());
}

/// `ensure_ppp_options`: sstpc/pppd read `/etc/ppp/options`; if missing it is created empty (root, 644) and a
/// marker (`$LIBEXEC/.created-ppp-options`) lets the uninstaller remove it later.
fn ensure_ppp_options(ctx: &Ctx) -> R {
    let p = &ctx.s.ppp_options;
    if crate::macos::paths::exists(p) || is_symlink(p) {
        return Ok(());
    }
    let shown = p.display().to_string();
    ctx.log.step(&tr("creating %@ (required by sstpc/pppd)", &[&shown]));
    ctx.log.cmd(&format!("touch {shown} && chmod 644 {shown}"));
    if ctx.dry() {
        ctx.say(&format!("DRY: touch {shown}"));
        return Ok(());
    }
    let made = p.parent().is_none_or(|d| std::fs::create_dir_all(d).is_ok())
        && fsx::write_file(p, b"", 0o644).is_ok()
        && fsx::chmod(p, 0o644).is_ok();
    if !made {
        return Err(ctx.die(tr("Cannot create %@", &[&shown])));
    }
    if !ctx.s.test_mode {
        let _ = std::os::unix::fs::lchown(p, Some(0), Some(0));
    }
    let marker = ctx.s.libexec.join(".created-ppp-options");
    ctx.log.cmd(&format!("touch {}", marker.display()));
    let _ = fsx::write_file(&marker, b"", 0o600);
    Ok(())
}

/// `start_sstpc`: sstpc in the background, its output through the masker into the log; the password shown as
/// `***`. The masker runs from this binary (`mvpn mask-stream <id>`) and outlives this process.
fn start_sstpc(ctx: &Ctx, cmd: &Cmd) -> R {
    ctx.log.cmd(&format!("{} &", cmd.display()));
    if ctx.dry() {
        ctx.say(&format!("DRY: {}", cmd.display()));
        return Ok(());
    }
    let run = ctx.run().to_path_buf();
    let mut mask = zeroize::Zeroizing::new(ctx.secrets.pass.to_vec());
    mask.push(b'\n');
    if !ctx.secrets.otp.is_empty() {
        mask.extend_from_slice(&ctx.secrets.otp);
        mask.push(b'\n');
    }
    let _ = fsx::write_file(&run.join("mask"), &mask, 0o600);
    let _ = fsx::chmod(&run.join("mask"), 0o600);
    let Ok((reader, writer)) = std::io::pipe() else { return Ok(()) };
    let Ok(writer2) = writer.try_clone() else { return Ok(()) };
    let out = ctx.log.file().map(Stdio::from).unwrap_or_else(Stdio::null);
    let masker = Cmd::new(ctx.s.self_binary()).args(["mask-stream", &ctx.id]);
    if let Err(e) = masker.command(ctx.env_mode()).stdin(Stdio::from(reader)).stdout(out).stderr(Stdio::null()).spawn()
    {
        ctx.log.line(&format!("mask-stream: {e}"));
        return Ok(());
    }
    let child = cmd
        .command(ctx.env_mode())
        .stdin(Stdio::null())
        .stdout(Stdio::from(writer))
        .stderr(Stdio::from(writer2))
        .spawn();
    match child {
        Ok(c) => {
            let _ = fsx::write_line(&run.join("pid"), &c.id().to_string());
        }
        Err(e) => ctx.log.line(&format!("{}: {e}", cmd.shown)),
    }
    Ok(())
}

/// `up_sstp`
pub fn up(ctx: &mut Ctx) -> R {
    let Some(sstpc) = ctx.find_tool("sstpc") else {
        return Err(ctx.die(tr("sstpc not found (brew install sstp-client)", &[])));
    };
    if !crate::macos::exec::is_executable(&ctx.s.pppd) {
        return Err(ctx.die(tr("pppd not found: %@", &[&ctx.s.pppd.display().to_string()])));
    }
    let Some(p) = load_params(ctx) else {
        return Err(ctx.die(tr("Invalid SSTP parameters", &[])));
    };
    if ctx.secrets.pass.is_empty() {
        return Err(ctx.die(tr("SSTP needs a password (set it in the connection settings)", &[])));
    }
    if !password_ok(&ctx.secrets.pass) {
        return Err(
            ctx.die(tr("The SSTP password must not contain quotation marks, backslashes or control characters", &[]))
        );
    }
    ensure_ppp_options(ctx)?;
    let run = ctx.run().to_path_buf();
    let lvl = if ctx.a.debug { "4" } else { "2" };
    let mut args: Vec<Vec<u8>> = ["--log-stderr", "--log-level", lvl, "--tls-ext", "--save-server-route"]
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();
    match p.cert.as_str() {
        "ca" => {
            let Some(pem) = crate::macos::validate::sstp_ca(&run.join("config")) else {
                return Err(ctx.die(tr("The CA certificate block is missing or invalid", &[])));
            };
            let ca = run.join("ca.pem");
            let _ = fsx::write_file(&ca, format!("{pem}\n").as_bytes(), 0o600);
            let _ = fsx::chmod(&ca, 0o600);
            ctx.log.step(&tr("CA certificate written: %@/ca.pem", &[&run.display().to_string()]));
            args.push(b"--ca-cert".to_vec());
            args.push(ca.display().to_string().into_bytes());
        }
        "insecure" => {
            ctx.log.step(&tr("WARNING: server certificate verification is off (--cert-warn)", &[]));
            args.push(b"--cert-warn".to_vec());
        }
        _ => {}
    }
    let plog = run.join("pppd.log");
    let mut tail: Vec<String> = vec![
        "--user".into(),
        p.user.clone(),
        "--password".into(),
        "\0".into(),
        p.target(),
        "--".into(),
        "logfile".into(),
        plog.display().to_string(),
    ];
    tail.extend(
        ["require-mschap-v2", "refuse-pap", "refuse-chap", "refuse-mschap", "refuse-eap", "noauth", "nodetach"]
            .map(String::from),
    );
    if p.peer_dns == "yes" {
        tail.push("usepeerdns".into());
    }
    if p.route_all == "yes" {
        tail.push("defaultroute".into());
    }
    if ctx.a.debug {
        tail.push("debug".into());
    }
    let mut shown: Vec<String> = args.iter().map(|a| String::from_utf8_lossy(a).into_owned()).collect();
    for t in &tail {
        if t == "\0" {
            shown.push("***".into());
            args.push(ctx.secrets.pass.to_vec());
        } else {
            shown.push(t.clone());
            args.push(t.clone().into_bytes());
        }
    }
    let _ = fsx::write_line(&run.join("route_all"), &p.route_all);
    if !ctx.dry() {
        fsx::remove_file(&plog);
        let _ = fsx::write_file(&plog, b"", 0o600);
        let _ = fsx::chmod(&plog, 0o600);
    }
    let offset = ctx.log.path().and_then(fsx::size).unwrap_or(0);
    let mut cmd = Cmd::new(&sstpc);
    {
        use std::os::unix::ffi::OsStrExt;
        cmd.args = args.iter().map(|a| std::ffi::OsStr::from_bytes(a).to_os_string()).collect();
    }
    cmd.shown_args = Some(shown);
    start_sstpc(ctx, &cmd)?;
    if ctx.dry() {
        return Ok(());
    }
    wait_connected(ctx, offset, &p)
}

fn wait_connected(ctx: &mut Ctx, offset: u64, p: &SstpParams) -> R {
    let run = ctx.run().to_path_buf();
    let mut iface = String::new();
    for _ in 0..ctx.s.up_timeout {
        if !crate::macos::exec::sleep_ms(1000, true) {
            ctx.check_term()?;
        }
        let pid = fsx::cat(&run.join("pid"));
        flush_pppd(ctx);
        let new = ctx.log.path().and_then(|l| crate::macos::log::read_range(l, offset, u64::MAX)).unwrap_or_default();
        // Errors may come from sstpc's output and the pppd log: they can only cause a failure, never success.
        if crate::shared::mask::find(&new, b"certificate verification failed").is_some()
            || crate::shared::mask::find(&new, b"certificate did not match").is_some()
        {
            return Err(fail(
                ctx,
                tr("Server certificate error (see the log; check the certificate mode or the CA file)", &[]),
            ));
        }
        let lower = new.to_ascii_lowercase();
        if crate::shared::mask::find(&lower, b"authentication failed").is_some()
            || crate::shared::mask::find(&lower, b"e=691").is_some()
        {
            return Err(fail(ctx, tr("Authentication failed (wrong user name or password)", &[])));
        }
        if iface.is_empty() {
            iface = pppd_log_fields(&run, "iface").into_iter().next().unwrap_or_default();
        }
        let ip = pppd_log_fields(&run, "ip").into_iter().last().unwrap_or_default();
        if !iface.is_empty() && !ip.is_empty() && iface_up(ctx.s.test_mode, ctx.s.test.iface_ok, &iface) {
            return connected(ctx, &iface, &ip, p);
        }
        if !pid.is_empty() && !sstp_alive(&pid) {
            let last = crate::shared::mask::lines(&new)
                .filter(|l| !l.starts_with(b"$") && !l.iter().all(|b| b.is_ascii_whitespace()))
                .last()
                .map(|l| String::from_utf8_lossy(l).into_owned())
                .unwrap_or_default();
            return Err(fail(ctx, format!("{} {last}", tr("sstpc exited:", &[]))));
        }
    }
    let t = ctx.s.up_timeout.to_string();
    Err(fail(ctx, tr("Timed out: the connection was not established within %@ s", &[&t])))
}

/// `sstp_connected`: record the interface, set the routes and DNS (DNS only from pppd.log too).
fn connected(ctx: &mut Ctx, iface: &str, ip: &str, p: &SstpParams) -> R {
    let run = ctx.run().to_path_buf();
    fsx::remove_file(&run.join("mask"));
    let _ = fsx::write_line(&run.join("iface"), iface);
    if is_ipv4_shape(ip) {
        let _ = fsx::write_line(&run.join("ip"), ip);
    }
    let pid = fsx::cat(&run.join("pid"));
    if let Some(ppid) = pppd_children(&pid).into_iter().next() {
        let _ = fsx::write_line(&run.join("pppd-pid"), &ppid);
    }
    if p.route_all == "yes" {
        let route = |net: &str| Cmd::new(&ctx.s.route).args(["-n", "add", "-net", net, "-interface", iface]);
        let ok = ctx.run_logged(&route("0.0.0.0/1"))? && ctx.run_logged(&route("128.0.0.0/1"))?;
        if !ok {
            return Err(fail(ctx, tr("Setting the routes failed", &[])));
        }
    }
    if p.peer_dns == "yes" {
        let dns = pppd_log_fields(&run, "dns");
        let log = ctx.log.path().map(Path::to_path_buf).unwrap_or_default();
        ctx.log.cmd(&format!(
            "{} hook ovpn-dns {} {} (DNS: {})",
            ctx.s.hook_program().display(),
            run.display(),
            log.display(),
            dns.len()
        ));
        // The bash `env -i script_type=up dev=… ifconfig_local=… foreign_option_N=…`.
        let mut cmd = Cmd::new(ctx.s.hook_program())
            .args(["hook", "ovpn-dns"])
            .arg(&run)
            .arg(&log)
            .env("script_type", "up")
            .env("dev", iface)
            .env("ifconfig_local", ip);
        for (i, d) in dns.iter().enumerate() {
            cmd = cmd.env(format!("foreign_option_{}", i + 1), format!("dhcp-option DNS {d}"));
        }
        let _ = cmd.command(EnvMode::Empty).stdin(Stdio::null()).status();
    }
    // A final copy of the pppd log (the loop may have copied a partly written log).
    flush_pppd(ctx);
    Ok(())
}

/// `^([0-9]{1,3}\.){3}[0-9]{1,3}$`
fn is_ipv4_shape(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 4 && parts.iter().all(|p| (1..=3).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()))
}

/// `fail_sstp`
fn fail(ctx: &Ctx, msg: String) -> Exit {
    let _ = cleanup(ctx);
    if !ctx.dry() {
        fsx::remove_rf(ctx.run());
    }
    ctx.die(msg)
}

/// sstpc's pppd children (only while sstpc runs; the parent pid ties them to it).
fn pppd_children(sstpc: &str) -> Vec<String> {
    if !sstp_alive(sstpc) {
        return Vec::new();
    }
    procs::pgrep(&["-P", sstpc, "-x", "pppd"])
}

/// The recorded pppd pid is ours only if sstpc runs and this process is its child.
fn trusted_pppd(sstpc: &str, pppd: &str) -> bool {
    sstp_alive(sstpc) && pppd_alive(pppd) && procs::ppid(pppd).as_deref() == Some(sstpc)
}

/// `sweep_sstp_tmp`: removes sstpc's own unescaped password option files (`sstp-pppd.XXXXXX`): exactly that name,
/// a regular file (not a symlink), owned by root (the caller in test mode), not newer than this connection's start.
fn sweep_tmp(ctx: &Ctx) {
    let started = ctx.run().join("started");
    let Some(limit) = (if is_file(&started) { fsx::mtime_ns(&started) } else { None }) else { return };
    let owner = if ctx.s.test_mode { crate::macos::sys::geteuid() } else { 0 };
    for dir in &ctx.s.sstp_tmp_dirs {
        if !is_dir(dir) || is_symlink(dir) {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(dir) else { continue };
        for e in entries.filter_map(Result::ok) {
            let name = e.file_name();
            let name = name.as_encoded_bytes();
            if name.len() != 16 || !name.starts_with(b"sstp-pppd.") {
                continue;
            }
            let path: PathBuf = e.path();
            let Ok(m) = std::fs::symlink_metadata(&path) else { continue };
            let mtime = i128::from(m.mtime()) * 1_000_000_000 + i128::from(m.mtime_nsec());
            if m.file_type().is_file() && m.uid() == owner && mtime <= limit {
                ctx.log.cmd(&format!("rm -f {}", path.display()));
                fsx::remove_file(&path);
            }
        }
    }
}

/// `cleanup_sstp`: `true` if neither sstpc nor its pppd is left running.
pub fn cleanup(ctx: &Ctx) -> bool {
    if ctx.dry() {
        return true;
    }
    let run = ctx.run().to_path_buf();
    let pid = fsx::cat(&run.join("pid"));
    let recorded = fsx::cat(&run.join("pppd-pid"));
    let mut ppids = Vec::new();
    if trusted_pppd(&pid, &recorded) {
        ppids.push(recorded);
    }
    ppids.extend(pppd_children(&pid));
    // pppd first (orderly LCP shutdown), then sstpc (it removes the --save-server-route route).
    for p in &ppids {
        if pppd_alive(p) {
            ctx.log.cmd(&format!("kill {p}"));
            procs::signal(p, crate::macos::sys::SIGTERM);
        }
    }
    if sstp_alive(&pid) {
        ctx.log.cmd(&format!("kill {pid}"));
        procs::signal(&pid, crate::macos::sys::SIGTERM);
    }
    for _ in 0..10 {
        if !sstp_alive(&pid) {
            break;
        }
        crate::macos::exec::sleep_ms(1000, false);
    }
    if sstp_alive(&pid) {
        ctx.log.cmd(&format!("kill -9 {pid}"));
        procs::signal(&pid, crate::macos::sys::SIGKILL);
        crate::macos::exec::sleep_ms(1000, false);
    }
    for p in &ppids {
        if pppd_alive(p) {
            ctx.log.cmd(&format!("kill -9 {p}"));
            procs::signal(p, crate::macos::sys::SIGKILL);
        }
    }
    let ok = !sstp_alive(&pid);
    // The /1 routes (route_all); errors do not matter (they go away with the interface anyway).
    let iface = fsx::cat(&run.join("iface"));
    let ppp = iface.strip_prefix("ppp").is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
    if fsx::cat(&run.join("route_all")) == "yes" && ppp {
        for net in ["0.0.0.0/1", "128.0.0.0/1"] {
            let cmd = Cmd::new(&ctx.s.route).args(["-n", "delete", "-net", net, "-interface", &iface]);
            ctx.log.cmd(&cmd.display());
            let _ = crate::macos::exec::quiet(&cmd, ctx.env_mode());
        }
    }
    ctx.dns_restore();
    flush_pppd(ctx);
    fsx::remove_file(&run.join("mask"));
    fsx::remove_file(&run.join("ca.pem"));
    sweep_tmp(ctx);
    ok
}

/// `down_sstp`
pub fn down(ctx: &mut Ctx) -> R<bool> {
    if !is_dir(ctx.run()) {
        ctx.no_running();
        return Ok(true);
    }
    Ok(cleanup(ctx))
}

/// Reads the secrets of a mask file: one per line, at most 4 KB, a regular file that is not a symlink.
fn read_mask_file(path: &std::path::Path) -> Option<crate::shared::mask::Masker> {
    let data = fsx::read_private(path, 4096)?;
    let data = zeroize::Zeroizing::new(data);
    Some(crate::shared::mask::from_mask_file(&data))
}

/// `mvpn mask-stream <id>` (internal): reads the secrets of `$RUN_BASE/<id>/mask` once, deletes the file, then
/// masks stdin into stdout (the user's log) line by line until EOF, keeping the log under its cap. Not reachable
/// through sudo (see `main`).
pub fn mask_stream(s: &crate::macos::paths::Settings, id: &str) -> i32 {
    if !crate::shared::cli::is_uuid(id) {
        return 2;
    }
    let path = s.run_dir(id).join("mask");
    let masker = read_mask_file(&path).unwrap_or_default();
    fsx::remove_file(&path);
    // stdout is the user's log (opened with O_APPEND): it is rolled before a line would take it over its cap, as
    // sstpc and pppd run (and write) for the whole session.
    // pppd's own log (pppd also writes its lines here, through sstpc) is cut to its cap too, also when the app does
    // not poll the status.
    let log = s.log_file(id);
    let pppd_log = s.run_dir(id).join("pppd.log");
    let lock = s.run_base.join(format!(".{id}.lock"));
    let mut out = std::io::stdout().lock();
    masker.stream_lines(std::io::stdin().lock(), crate::shared::mask::MAX_LINE, |l| {
        crate::macos::log::make_room(&log, s.log_max, l.len() as u64);
        if fsx::size(&pppd_log).is_some_and(|n| n > crate::macos::log::ROOT_LOG_MAX)
            && crate::macos::lock::try_take(&lock)
        {
            crate::macos::log::flush_root_log(
                &crate::macos::log::Log::capped(log.clone(), s.log_max),
                &pppd_log,
                "[pppd] ",
                true,
                &crate::shared::mask::Masker::default(),
            );
            crate::macos::lock::release_try(&lock);
        }
        std::io::Write::write_all(&mut out, l).and_then(|_| std::io::Write::flush(&mut out)).is_ok()
    });
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pppd_fields_are_anchored() {
        let log = b"Fri Oct 16 22:58:59 2026 : evil Using interface ppp7\n\
Fri Oct 16 22:58:59 2026 : Using interface ppp9\n\
Fri Oct 16 22:58:59 2026 : local  IP address 10.0.0.7\n\
Fri Oct 16 22:58:59 2026 : remote IP address 10.0.0.1\n\
Fri Oct 16 22:58:59 2026 : primary   DNS address 10.0.0.53\n\
secondary DNS address 10.0.0.54\n\
primary   DNS address 6.6.6.7 x\n";
        assert_eq!(pppd_fields(log, "iface"), vec!["ppp9"]);
        assert_eq!(pppd_fields(log, "ip"), vec!["10.0.0.7"]);
        assert_eq!(pppd_fields(log, "dns"), vec!["10.0.0.53", "10.0.0.54"]);
        assert!(pppd_fields(b"[pppd] Using interface ppp6\n", "iface").is_empty());
    }

    #[test]
    fn params_and_password() {
        let l = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let p = SstpParams::from_lines(&l(&["vpn.example.com", "443", "bob@corp", "system", "yes", "no"])).unwrap();
        assert_eq!(p.target(), "vpn.example.com:443");
        let v6 = SstpParams::from_lines(&l(&["fd00::1", "443", "bob", "ca", "no", "no"])).unwrap();
        assert_eq!(v6.target(), "[fd00::1]:443");
        assert!(SstpParams::from_lines(&l(&["-x", "443", "bob", "ca", "no", "no"])).is_none());
        assert!(SstpParams::from_lines(&l(&["a", "443", "bob", "weird", "no", "no"])).is_none());
        assert!(password_ok(b"Sup3rSstp!pw") && password_ok("ÁrvíZ".as_bytes()));
        assert!(!password_ok(b"a\"b") && !password_ok(b"a\\b") && !password_ok(b"a\tb") && !password_ok(b"a\x7f"));
    }
}
