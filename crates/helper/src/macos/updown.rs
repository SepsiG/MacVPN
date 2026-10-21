//! `mvpn up|down <kind> <id>`: the flow around the per-kind code — validation of the arguments, test-mode guard,
//! the framed stdin of `up` (config and secrets, see [`crate::shared::framing`]), log, lock, the previous run, the
//! config written into the run directory and validated, debug snapshots, and the cleanup on every exit.

use crate::macos::ctx::{Ctx, Exit, R, tr};
use crate::macos::exec::{Cmd, EnvMode};
use crate::macos::fsx;
use crate::macos::paths::{is_dir, is_symlink};
use crate::macos::{lock, log, openvpn, run_dir, sstp, status, strongswan, validate, wireguard};
use crate::shared::cli::{is_kind, is_uuid};
use crate::shared::framing;

/// Runs `f` like a bash subshell `( … )`: changes to the run directory, the kind and the exported tool settings
/// do not leak back; a `die` inside only ends `f`.
fn subshell<T>(ctx: &mut Ctx, f: impl FnOnce(&mut Ctx) -> R<T>) -> R<T> {
    let saved = (ctx.run.clone(), ctx.kind.clone(), ctx.brew_path, ctx.wg_debug_env, ctx.sstp.clone());
    let r = f(ctx);
    (ctx.run, ctx.kind, ctx.brew_path, ctx.wg_debug_env, ctx.sstp) = saved;
    r
}

fn up_kind(ctx: &mut Ctx) -> R {
    match ctx.kind.as_str() {
        "openvpn" => openvpn::up(ctx),
        "wireguard" => wireguard::up(ctx),
        "strongswan" => strongswan::up(ctx),
        _ => sstp::up(ctx),
    }
}

/// `down_<kind>`: `Ok(true)` = exit 0, `Ok(false)` = exit 1 (a tracked process still runs).
fn down_kind(ctx: &mut Ctx) -> R<bool> {
    match ctx.kind.as_str() {
        "openvpn" => openvpn::down(ctx),
        "wireguard" => wireguard::down(ctx),
        "strongswan" => strongswan::down(ctx),
        _ => sstp::down(ctx),
    }
}

/// The exit status of a subshell-run `down_<kind>`.
fn down_status(r: R<bool>) -> R<bool> {
    match r {
        Ok(ok) => Ok(ok),
        Err(Exit(143)) if crate::macos::sys::terminated() => Err(Exit(143)),
        Err(_) => Ok(false),
    }
}

/// `server_of`: the server name for the debug snapshot. OpenVPN: the first top-level or `<connection>` `remote`
/// (inline blocks such as `<auth-user-pass>` are skipped, so a password line never reaches the log).
fn server_of(ctx: &mut Ctx) -> String {
    let text = std::fs::read(ctx.run().join("config")).unwrap_or_default();
    let lines = || crate::shared::mask::lines(&text).map(|l| String::from_utf8_lossy(l).into_owned());
    match ctx.kind.as_str() {
        "openvpn" => {
            let mut block = String::new();
            for l in lines() {
                let t = l.to_ascii_lowercase();
                let t = t.trim_start_matches([' ', '\t']).trim_end_matches([' ', '\t', '\r']).to_string();
                if !block.is_empty() {
                    if t == format!("</{block}>") {
                        block.clear();
                    }
                    continue;
                }
                if t.len() > 2
                    && t.starts_with('<')
                    && t.ends_with('>')
                    && t[1..t.len() - 1].bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                    && t != "<connection>"
                {
                    block = t[1..t.len() - 1].to_string();
                    continue;
                }
                let mut fields = l.split([' ', '\t']).filter(|f| !f.is_empty());
                if fields.next().is_some_and(|f| f.eq_ignore_ascii_case("remote")) {
                    return fields.next().unwrap_or_default().to_string();
                }
            }
            String::new()
        }
        "wireguard" => {
            for l in lines() {
                let mut parts = l.split('=');
                let key = parts.next().unwrap_or_default();
                if key.trim_matches([' ', '\t']).eq_ignore_ascii_case("endpoint") {
                    let v: String =
                        parts.next().unwrap_or_default().chars().filter(|c| *c != ' ' && *c != '\t').collect();
                    return strip_port(&v);
                }
            }
            String::new()
        }
        "strongswan" => {
            for l in lines() {
                let mut parts = l.split('=');
                if parts.next().unwrap_or_default().contains("remote_addrs") {
                    let v: String =
                        parts.next().unwrap_or_default().chars().filter(|c| *c != ' ' && *c != '\t').collect();
                    return v.split(',').next().unwrap_or_default().to_string();
                }
            }
            String::new()
        }
        _ => {
            // The validated host, not a scan of the config (because of the <ca> block).
            if ctx.sstp.is_none() {
                sstp::load_params(ctx);
            }
            ctx.sstp.as_ref().map(|p| p.host.clone()).unwrap_or_default()
        }
    }
}

/// `sub(/:[0-9]+$/, "")`
fn strip_port(v: &str) -> String {
    if let Some(i) = v.rfind(':') {
        let port = &v[i + 1..];
        if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) {
            return v[..i].to_string();
        }
    }
    v.to_string()
}

/// `snapshot`: diagnostics in the log with `--debug`.
fn snapshot(ctx: &mut Ctx, label: &str) -> R {
    if !ctx.a.debug {
        return Ok(());
    }
    ctx.log.step(&format!("{} ({label})", tr("diagnostics", &[])));
    let server = server_of(ctx);
    if !server.is_empty() && server.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b':' | b'-')) {
        ctx.run_logged(&Cmd::system("/usr/bin/dscacheutil").args(["-q", "host", "-a", "name", &server]))?;
    }
    ctx.run_logged(&Cmd::system("/usr/sbin/netstat").args(["-rn", "-f", "inet"]))?;
    ctx.log.cmd("scutil --dns | head -40");
    if !ctx.dry()
        && let Some((_, out)) =
            crate::macos::exec::capture_merged(&Cmd::new("/usr/sbin/scutil").arg("--dns"), EnvMode::Minimal, 1 << 20)
    {
        let head: Vec<&[u8]> = crate::shared::mask::lines(&out).take(40).collect();
        let mut data = head.join(&b'\n');
        if !data.is_empty() {
            data.push(b'\n');
        }
        ctx.log.bytes(&data);
    }
    ctx.run_logged(&Cmd::system("/sbin/ifconfig").arg("-l"))?;
    Ok(())
}

/// `tracked_alive`: a process of the run directory still runs.
fn tracked_alive(ctx: &Ctx) -> bool {
    status::one(&ctx.s, ctx.run()).state != "failed"
}

/// `do_down`: the kind comes from the run directory (allowlist), not the command line, so a down of the wrong
/// kind does not leave a connection running. The run directory is only removed if the teardown worked or nothing
/// tracked runs any more; otherwise it stays (a later down can find the processes) and the exit is an error.
fn do_down(ctx: &mut Ctx) -> R {
    let run = ctx.s.run_dir(&ctx.id);
    ctx.run = Some(run.clone());
    if !is_dir(&run) || is_symlink(&run) {
        ctx.no_running();
        ctx.log.step(&tr("connection closed", &[]));
        return Ok(());
    }
    let k = fsx::cat(&run.join("kind"));
    if !is_kind(&k) {
        ctx.log.step(&tr("no valid type in the run directory, cleanup only", &[]));
        if !ctx.dry() {
            fsx::remove_rf(&run);
        }
        return Ok(());
    }
    if k != ctx.kind {
        ctx.log.step(&tr(
            "kind mismatch: command line %@, running connection %@ – closing the running kind",
            &[&ctx.kind.clone(), &k],
        ));
    }
    ctx.kind = k;
    let ok = down_status(subshell(ctx, down_kind))?;
    if ctx.dry() {
        ctx.log.step(&tr("connection closed", &[]));
        return Ok(());
    }
    if ok || !tracked_alive(ctx) {
        fsx::remove_rf(&run);
        ctx.log.step(&tr("connection closed", &[]));
        return Ok(());
    }
    Err(ctx.die(tr("Disconnect failed, the connection is still running (the run directory is kept)", &[])))
}

/// `cleanup_failed_up`: a failed or interrupted up after `prepare_run` tears the half-built connection down,
/// restores DNS and removes the run directory.
fn cleanup_failed_up(ctx: &mut Ctx) {
    if ctx.a.cmd != "up" || ctx.up_done || ctx.dry() {
        return;
    }
    let Some(run) = ctx.run.clone() else { return };
    if run != ctx.s.run_dir(&ctx.id) || !is_dir(&run) || is_symlink(&run) {
        return;
    }
    ctx.log.step(&tr("cleaning up after the failed connection attempt", &[]));
    let quiet = ctx.quiet;
    ctx.quiet = true;
    let _ = subshell(ctx, down_kind);
    ctx.dns_restore();
    ctx.quiet = quiet;
    fsx::remove_rf(&run);
}

/// `on_exit`
fn on_exit(ctx: &mut Ctx) {
    cleanup_failed_up(ctx);
    if ctx.dry()
        && let Some(run) = &ctx.run
        && run.file_name().is_some_and(|n| n.to_string_lossy().starts_with(&format!("{}.dryrun.", ctx.id)))
        && run.parent() == Some(ctx.s.run_base.as_path())
    {
        fsx::remove_rf(run);
    }
    lock::release(ctx);
}

fn header(ctx: &Ctx, what: &str) {
    let debug = if what == "up" && ctx.a.debug { " (debug)" } else { "" };
    ctx.log.line(&format!(
        "═══ {} {what} {} {}{debug} ═══",
        crate::macos::sys::local_timestamp(crate::macos::exec::now()),
        ctx.kind,
        ctx.id
    ));
}

fn up(ctx: &mut Ctx, input: Result<framing::Framed, framing::FrameError>) -> R {
    header(ctx, "up");
    let config = match input {
        Ok((config, s)) => {
            ctx.secrets = s;
            config
        }
        Err(e) => return Err(ctx.die(e.message())),
    };
    // Validated first: a bad new config must not tear down a working connection of this id.
    validate::validate_config(ctx, &config)?;
    // A run directory left for this id (e.g. a connection never taken down) is closed first, otherwise the copy
    // would delete its pid / iface files and the process would be orphaned. A crashed openvpn (dead pid) gets
    // its DNS restored from dns-backup this way.
    if !ctx.dry() && is_dir(&ctx.s.run_dir(&ctx.id)) {
        ctx.log.step(&tr("closing the previous run", &[]));
        if let Err(e) = subshell(ctx, do_down) {
            if e == Exit(143) && crate::macos::sys::terminated() {
                return Err(e);
            }
            return Err(ctx.die(tr("Cannot close the previous connection", &[])));
        }
    }
    ctx.check_term()?;
    run_dir::prepare(ctx, &config)?;
    drop(config);
    ctx.check_term()?;
    snapshot(ctx, &tr("before", &[]))?;
    up_kind(ctx)?;
    ctx.up_done = true;
    snapshot(ctx, &tr("after", &[]))?;
    ctx.log.step(&tr("connection established", &[]));
    Ok(())
}

fn body(ctx: &mut Ctx, input: Option<Result<framing::Framed, framing::FrameError>>) -> R {
    ctx.log = log::open(
        &ctx.s.log_base.clone(),
        &ctx.id.clone(),
        (ctx.a.cmd == "up").then_some(ctx.s.log_max),
        ctx.owner_uid(),
    );
    ctx.check_term()?;
    lock::acquire(ctx)?;
    if let Some(input) = input {
        up(ctx, input)
    } else {
        header(ctx, "down");
        do_down(ctx)
    }
}

/// `mvpn up|down …`; returns the exit code.
pub fn main(ctx: &mut Ctx) -> i32 {
    if !is_kind(&ctx.kind) {
        return ctx.die(tr("Unknown type: %@", &[&ctx.kind.clone()])).0;
    }
    if !is_uuid(&ctx.id) {
        return ctx.die(tr("Invalid ID", &[])).0;
    }
    if !ctx.a.accept_risky_valid() {
        return ctx.die(tr("Invalid --accept-risky value", &[])).0;
    }
    if ctx.s.test_mode && !ctx.dry() {
        // In test mode (not root) the real up/down runs only on explicit request and with a fake brew directory,
        // so no real VPN tool is ever started.
        let brew = ctx.s.test.brew.is_some();
        let allowed = (ctx.a.cmd == "down" && ctx.s.test.allow_down && brew)
            || (ctx.a.cmd == "up" && ctx.s.test.allow_up && brew);
        if !allowed {
            return ctx.die(tr("Root privileges required (or --dry-run)", &[])).0;
        }
    }
    // `up` reads its whole stdin at once, before waiting for the lock, so the caller's write never blocks on it.
    let input = (ctx.a.cmd == "up").then(|| crate::macos::read_framed_stdin(true));
    crate::macos::sys::install_sigterm_flag();
    let r = body(ctx, input);
    on_exit(ctx);
    match r {
        Ok(()) => 0,
        Err(Exit(code)) => code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_stripping() {
        assert_eq!(strip_port("vpn.example.com:51820"), "vpn.example.com");
        assert_eq!(strip_port("vpn.example.com"), "vpn.example.com");
        assert_eq!(strip_port("[fd00::1]:51820"), "[fd00::1]");
    }
}
