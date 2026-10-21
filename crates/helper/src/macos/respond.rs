//! `mvpn respond openvpn <id>`: the user's answer (a code, the web login acknowledged, cancel) for the bridge.
//!
//! stdin: `kind=crv1|static|webauth-ack|cancel` and `response=<value>` (at most 256 bytes, no control character,
//! at most two lines of 300 bytes). The answer is read straight from stdin into memory and written only into the
//! root-only run directory (`mgmt-resp`, 0600, atomic rename); no temporary file elsewhere. No lock (the `up`
//! holds it while waiting for authentication). The value never reaches the log, only its kind.

use crate::macos::ctx::{Ctx, R, tr};
use crate::macos::fsx;
use crate::macos::openvpn::mgmt_alive;
use crate::macos::paths::{is_dir, is_symlink};
use crate::shared::respond::{STDIN_MAX, parse};
use std::io::Read;
use zeroize::Zeroizing;

/// `do_respond`
pub fn run(ctx: &mut Ctx) -> R {
    let run = ctx.s.run_dir(&ctx.id);
    ctx.run = Some(run.clone());
    ctx.log = crate::macos::log::open(&ctx.s.log_base, &ctx.id, None, ctx.owner_uid());
    let waiting = is_dir(&run)
        && !is_symlink(&run)
        && fsx::cat(&run.join("kind")) == "openvpn"
        && mgmt_alive(&fsx::cat(&run.join("mgmt.pid")));
    if !waiting {
        return Err(ctx.die(tr("No connection is waiting for authentication", &[])));
    }
    if crate::macos::sys::stdin_is_tty() {
        return Err(ctx.die(tr("Invalid response", &[])));
    }
    let mut data = Zeroizing::new(Vec::new());
    let _ = std::io::stdin().lock().take(STDIN_MAX + 1).read_to_end(&mut data);
    let (kind, response) = match parse(&data) {
        Ok(v) => v,
        Err(key) => return Err(ctx.die(tr(key, &[]))),
    };
    let mut content = Zeroizing::new(format!("kind={kind}\nresponse=").into_bytes());
    content.extend_from_slice(&response);
    content.push(b'\n');
    let tmp = run.join(format!(".mgmt-resp.{}", std::process::id()));
    let written = fsx::write_file(&tmp, &content, 0o600).is_ok()
        && fsx::chmod(&tmp, 0o600).is_ok()
        && std::fs::rename(&tmp, run.join("mgmt-resp")).is_ok();
    if !written {
        fsx::remove_file(&tmp);
        return Err(ctx.die(tr("Cannot pass the response", &[])));
    }
    ctx.log.step(&tr("authentication response passed to the management bridge (kind: %@)", &[&kind]));
    Ok(())
}
