//! OpenVPN up/down, and the `mvpn` side of the MFA management bridge (spec 10f).
//!
//! OpenVPN always starts with a management interface (a unix socket in the root 0700 run directory) whose only client
//! is the root-side bridge (`mvpn-mgmt`, see [`crate::macos::mgmt_bridge`]). The user name and password go through the
//! bridge (`$RUN/mgmt-creds`, root 0600, read once and deleted). Whether the connection is up is decided only from the
//! root-only `$RUN/openvpn.log`.

use crate::macos::ctx::{Ctx, Exit, R, tr};
use crate::macos::exec::Cmd;
use crate::macos::fsx;
use crate::macos::log::{self, flush_root_log};
use crate::macos::paths::{is_dir, is_file, is_symlink};
use crate::macos::procs;
use crate::shared::bridge::valid_status;
use std::path::{Path, PathBuf};

/// Is the recorded openvpn still running under that name (pid reuse)?
pub fn ovpn_alive(pid: &str) -> bool {
    procs::alive_as(pid, "openvpn")
}

/// The bridge's process name (its `argv[0]`): `ps` shows it, so a recycled pid is not mistaken for the bridge.
pub const BRIDGE_NAME: &str = "mvpn-mgmt";

/// Is the bridge alive (a running, non-zombie process named `mvpn-mgmt`)?
pub fn mgmt_alive(pid: &str) -> bool {
    procs::alive_as(pid, BRIDGE_NAME)
}

/// `mgmt_status`: the bridge's root-only state for `mvpn` (strict format).
pub fn mgmt_status(run: &Path) -> Option<String> {
    let f = run.join("mgmt-status");
    if !is_file(&f) || is_symlink(&f) {
        return None;
    }
    let data = log::read_range(&f, 0, 64)?;
    let first = data.split(|&b| b == b'\n').next().unwrap_or_default();
    let s = std::str::from_utf8(first).ok()?;
    valid_status(s).then(|| s.to_string())
}

/// `fail_openvpn`: stop the process, restore DNS, remove the run directory, exit.
fn fail(ctx: &Ctx, msg: String) -> Exit {
    let _ = cleanup(ctx);
    if !ctx.dry() {
        fsx::remove_rf(ctx.run());
    }
    ctx.die(msg)
}

/// `mgmt_fail`: a final bridge state → a failed up with its message.
fn mgmt_fail(ctx: &Ctx, st: Option<&str>) -> R {
    let key = match st {
        Some("failed") => "Authentication failed",
        Some("cancelled") => "Authentication cancelled",
        Some("timeout") => "Timed out waiting for authentication",
        _ => return Ok(()),
    };
    Err(fail(ctx, tr(key, &[])))
}

/// `prepare_ui`: the state directory (`/var/run/macvpn-ui`, root 755): the user can read their own 0600
/// `<id>.json` there but cannot place a symlink or another file. A symlink or non-directory is replaced.
fn prepare_ui(ctx: &Ctx) -> R {
    if ctx.dry() {
        return Ok(());
    }
    let ui = &ctx.s.ui_base;
    if is_symlink(ui) || (crate::macos::paths::exists(ui) && !is_dir(ui)) {
        fsx::remove_file(ui);
    }
    let made = std::fs::create_dir_all(ui).is_ok() && !is_symlink(ui) && fsx::chmod(ui, 0o755).is_ok();
    if !made {
        return Err(fail(ctx, tr("Cannot create: %@", &[&ui.display().to_string()])));
    }
    if !ctx.s.test_mode {
        let _ = std::os::unix::fs::lchown(ui, Some(0), Some(0));
    }
    fsx::remove_file(&ui.join(format!("{}.json", ctx.id)));
    Ok(())
}

/// `start_mgmt`: the bridge in the background (stdin `/dev/null`, output – event lines without secrets – into the
/// log). Its argv holds no secret.
fn start_mgmt(ctx: &Ctx) -> R {
    let Some(user) = ctx.user() else {
        return Err(fail(ctx, tr("Unknown user", &[])));
    };
    let mut cmd = Cmd::new(&ctx.s.mgmt).args([
        "--id".to_string(),
        ctx.id.clone(),
        "--run".into(),
        ctx.run().display().to_string(),
        "--ui".into(),
        ctx.s.ui_base.display().to_string(),
        "--uid".into(),
        user.uid.to_string(),
        "--gid".into(),
        user.gid.to_string(),
        "--max-wait".into(),
        ctx.s.mfa_max.to_string(),
    ]);
    cmd.arg0 = Some(BRIDGE_NAME.into());
    cmd.shown = BRIDGE_NAME.into();
    if let Some(pid) = ctx.run_bg(&cmd)? {
        let _ = fsx::write_line(&ctx.run().join("mgmt.pid"), &pid.to_string());
    }
    Ok(())
}

/// `stop_mgmt`
fn stop_mgmt(ctx: &Ctx) {
    let pid = fsx::cat(&ctx.run().join("mgmt.pid"));
    if !mgmt_alive(&pid) {
        return;
    }
    ctx.log.cmd(&format!("kill {pid}"));
    procs::signal(&pid, crate::macos::sys::SIGTERM);
    for _ in 0..10 {
        if !mgmt_alive(&pid) {
            break;
        }
        crate::macos::exec::sleep_ms(200, false);
    }
    if mgmt_alive(&pid) {
        procs::signal(&pid, crate::macos::sys::SIGKILL);
    }
}

/// `up_openvpn`
pub fn up(ctx: &mut Ctx) -> R {
    let Some(ovpn) = ctx.find_tool("openvpn") else {
        return Err(ctx.die(tr("openvpn not found (brew install openvpn)", &[])));
    };
    let verb = if ctx.a.debug { "5" } else { "3" };
    if !ctx.dry() && !crate::macos::exec::is_executable(&ctx.s.mgmt) {
        return Err(ctx.die(tr(
            "mvpn-mgmt not found: %@ (reinstall the root layer in System Status)",
            &[&ctx.s.mgmt.display().to_string()],
        )));
    }
    let run = ctx.run().to_path_buf();
    let olog = run.join("openvpn.log");
    let log_path = ctx.log.path().map(|p| p.display().to_string()).unwrap_or_default();
    let hook = format!("{} hook ovpn-dns {} {}", ctx.s.hook_program().display(), run.display(), log_path);
    // The management options come after the config, so they override the same directives of the config (which
    // the validator forbids anyway).
    let mut args: Vec<String> = vec![
        "--config".into(),
        run.join("config").display().to_string(),
        "--script-security".into(),
        "2".into(),
        "--up".into(),
        hook.clone(),
        "--down".into(),
        hook,
        "--writepid".into(),
        run.join("pid").display().to_string(),
        "--log-append".into(),
        olog.display().to_string(),
        "--daemon".into(),
        format!("mvpn-{}", ctx.id),
        // At most 20 consecutive messages of one kind (e.g. "write UDPv4: Network is unreachable" while offline).
        "--mute".into(),
        "20".into(),
        "--verb".into(),
        verb.into(),
        "--management".into(),
        run.join("mgmt.sock").display().to_string(),
        "unix".into(),
        "--management-client-user".into(),
        "root".into(),
        "--management-hold".into(),
        "--management-query-passwords".into(),
        "--auth-retry".into(),
        "interact".into(),
        "--setenv".into(),
        "IV_SSO".into(),
        "openurl,webauth,crtext".into(),
    ];
    // User name and password go through the bridge (root 0600 file, deleted by the bridge right after reading).
    if !ctx.secrets.user.is_empty() || !ctx.secrets.pass.is_empty() {
        let mut creds = zeroize::Zeroizing::new(Vec::new());
        creds.extend_from_slice(b"username=");
        creds.extend_from_slice(&ctx.secrets.user);
        creds.extend_from_slice(b"\npassword=");
        creds.extend_from_slice(&ctx.secrets.pass);
        creds.extend_from_slice(if ctx.secrets.packed { b"\npacked=1\n" } else { b"\npacked=0\n" });
        let _ = fsx::write_file(&run.join("mgmt-creds"), &creds, 0o600);
        let _ = fsx::chmod(&run.join("mgmt-creds"), 0o600);
        args.push("--auth-user-pass".into());
    }
    // The private key's password: a root 0600 file until `down` (a reconnect may need it again).
    if !ctx.secrets.keypass.is_empty() {
        let mut kp = zeroize::Zeroizing::new(ctx.secrets.keypass.to_vec());
        kp.push(b'\n');
        let _ = fsx::write_file(&run.join("askpass"), &kp, 0o600);
        let _ = fsx::chmod(&run.join("askpass"), 0o600);
        args.push("--askpass".into());
        args.push(run.join("askpass").display().to_string());
    }
    if !ctx.dry() {
        fsx::remove_file(&olog);
        fsx::remove_file(&PathBuf::from(format!("{}.off", olog.display())));
        let _ = fsx::write_file(&olog, b"", 0o600);
        let _ = fsx::chmod(&olog, 0o600);
    }
    prepare_ui(ctx)?;
    // Relative paths of the config resolve against the root-only run directory.
    if !is_dir(&run) {
        return Err(fail(ctx, tr("Cannot enter the run directory", &[])));
    }
    let mut cmd = Cmd::new(&ovpn).args(&args);
    cmd.cwd = Some(run.clone());
    if !ctx.run_direct(&cmd)? {
        return Err(fail(ctx, tr("Starting openvpn failed", &[])));
    }
    start_mgmt(ctx)?;
    if ctx.dry() {
        return Ok(());
    }
    wait_connected(ctx, &olog)
}

/// The wait for `Initialization Sequence Completed`. While the bridge waits for authentication (`wait <unix time>`
/// in the root-only mgmt-status) the deadline moves (+15 s for the server), at most to `UP_TIMEOUT + MFA_MAX`.
fn wait_connected(ctx: &Ctx, olog: &Path) -> R {
    let run = ctx.run().to_path_buf();
    let masker = ctx.masker();
    let started = crate::macos::exec::now();
    let base = started + ctx.s.up_timeout as i64;
    let mut deadline = base;
    let hard = base + ctx.s.mfa_max as i64;
    loop {
        if !crate::macos::exec::sleep_ms(1000, true) {
            ctx.check_term()?;
        }
        flush_root_log(&ctx.log, olog, "", false, &masker);
        if log::ovpn_done_file(olog) {
            return Ok(());
        }
        let st = mgmt_status(&run);
        mgmt_fail(ctx, st.as_deref())?;
        if let Some(w) = st.as_deref().and_then(|s| s.strip_prefix("wait ")).and_then(|n| n.parse::<i64>().ok()) {
            deadline = deadline.max(w + 15).min(hard);
        }
        // A dynamic challenge (AUTH_FAILED,CRV1:…) and AUTH_FAILED,TEMP are not final.
        if log::ovpn_auth_failed_file(olog) {
            return Err(fail(ctx, tr("Authentication failed (AUTH_FAILED)", &[])));
        }
        // Without the bridge openvpn would wait forever in the hold / password state.
        if !mgmt_alive(&fsx::cat(&run.join("mgmt.pid"))) {
            mgmt_fail(ctx, mgmt_status(&run).as_deref())?;
            return Err(fail(ctx, tr("The management bridge stopped (details in the log)", &[])));
        }
        if is_file(&run.join("pid")) && !ovpn_alive(&fsx::cat(&run.join("pid"))) {
            mgmt_fail(ctx, mgmt_status(&run).as_deref())?;
            let last = masker.line(&log::ovpn_last_line_file(olog));
            return Err(fail(ctx, format!("{} {}", tr("openvpn exited:", &[]), String::from_utf8_lossy(&last))));
        }
        if crate::macos::exec::now() >= deadline {
            break;
        }
    }
    if deadline > base {
        return Err(fail(ctx, tr("Timed out waiting for authentication", &[])));
    }
    let t = ctx.s.up_timeout.to_string();
    Err(fail(ctx, tr("Timed out: the connection was not established within %@ s", &[&t])))
}

/// `cleanup_openvpn`: `Ok(true)` if no openvpn is left running.
pub fn cleanup(ctx: &Ctx) -> bool {
    if ctx.dry() {
        return true;
    }
    let run = ctx.run().to_path_buf();
    let pid = fsx::cat(&run.join("pid"));
    let mut ok = true;
    if ovpn_alive(&pid) {
        ctx.log.cmd(&format!("kill {pid}"));
        procs::signal(&pid, crate::macos::sys::SIGTERM);
        for _ in 0..10 {
            if !ovpn_alive(&pid) {
                break;
            }
            crate::macos::exec::sleep_ms(1000, false);
        }
        if ovpn_alive(&pid) {
            ctx.log.cmd(&format!("kill -9 {pid}"));
            procs::signal(&pid, crate::macos::sys::SIGKILL);
            crate::macos::exec::sleep_ms(1000, false);
        }
        ok = !ovpn_alive(&pid);
    }
    // If the down hook did not run (e.g. kill -9), DNS is restored here.
    ctx.dns_restore();
    flush_root_log(&ctx.log, &run.join("openvpn.log"), "", false, &ctx.masker());
    stop_mgmt(ctx);
    for f in ["auth", "askpass", "mgmt-creds", "mgmt-resp", "mgmt-status"] {
        fsx::remove_file(&run.join(f));
    }
    fsx::remove_file(&ctx.s.ui_base.join(format!("{}.json", ctx.id)));
    ok
}

/// `down_openvpn`
pub fn down(ctx: &mut Ctx) -> R<bool> {
    if !is_dir(ctx.run()) {
        ctx.no_running();
        return Ok(true);
    }
    Ok(cleanup(ctx))
}
