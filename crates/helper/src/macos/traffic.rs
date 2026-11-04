//! `mvpn traffic <id>` (root layer 11): a running strongSwan connection's CHILD_SA byte counters for the app's live
//! traffic, in the format of [`macvpn_core::traffic`] (`strongswan <n>` + `child <id> <rx> <tx>` lines). The app
//! passes only the connection ID (a UUID); the root layer maps it to its own run directory and the connection name it
//! recorded there, and asks `swanctl --list-sas --ike <name>`. Only numbers leave it: never an SPI, an ID, an address
//! or a name.
//!
//! The other kinds' counters the app reads itself (the interface `status` reports): exit 1 without output, as for an
//! unknown ID, a connection that is not up, or swanctl not answering.

use crate::macos::ctx::Ctx;
use crate::macos::fsx;
use crate::macos::liveness::canonical_id;
use crate::macos::paths::{is_dir, is_symlink};

/// What `mvpn traffic <id>` prints on stdout, with its exit code (the ID is the CLI's second positional). Shared by
/// the command line and `mvpn serve` (see `serve`), so both answer exactly the same.
pub fn answer(ctx: &Ctx) -> (i32, String) {
    let Some(id) = canonical_id(&ctx.kind) else {
        return (ctx.die(crate::macos::ctx::tr("Invalid ID", &[])).0, String::new());
    };
    let run = ctx.s.run_base.join(&id);
    if !is_dir(&run) || is_symlink(&run) || fsx::cat(&run.join("kind")) != "strongswan" {
        return (1, String::new());
    }
    let conn = fsx::cat(&run.join("conn"));
    if !crate::macos::strongswan::is_name(&conn) {
        return (1, String::new());
    }
    let Some(swanctl) = crate::macos::status::find_swanctl(&ctx.s) else { return (1, String::new()) };
    match crate::macos::strongswan::list_sas(&swanctl, &conn, crate::macos::status::mode(&ctx.s)) {
        Some(l) if l.state == Some("connected") => (0, macvpn_core::traffic::encode_children(&l.children)),
        _ => (1, String::new()),
    }
}

/// `mvpn traffic <id>`.
pub fn main(ctx: &Ctx) -> i32 {
    let (code, out) = answer(ctx);
    crate::macos::out_raw(&out);
    code
}
