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
use crate::macos::paths::{is_dir, is_symlink};
use crate::shared::cli::is_uuid;
use macvpn_core::models::{parse_uuid, uuid_string};

/// `mvpn traffic <id>` (the ID is the CLI's second positional).
pub fn main(ctx: &Ctx) -> i32 {
    let raw = ctx.kind.as_str();
    let Some(id) = parse_uuid(raw).filter(|_| is_uuid(raw)).map(|u| uuid_string(&u)) else {
        return ctx.die(crate::macos::ctx::tr("Invalid ID", &[])).0;
    };
    let run = ctx.s.run_base.join(&id);
    if !is_dir(&run) || is_symlink(&run) || fsx::cat(&run.join("kind")) != "strongswan" {
        return 1;
    }
    let conn = fsx::cat(&run.join("conn"));
    if !crate::macos::strongswan::is_name(&conn) {
        return 1;
    }
    let Some(swanctl) = crate::macos::status::find_swanctl(&ctx.s) else { return 1 };
    match crate::macos::strongswan::list_sas(&swanctl, &conn, crate::macos::status::mode(&ctx.s)) {
        Some(l) if l.state == Some("connected") => {
            crate::macos::out_raw(&macvpn_core::traffic::encode_children(&l.children));
            0
        }
        _ => 1,
    }
}
