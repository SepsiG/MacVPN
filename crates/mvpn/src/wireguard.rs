//! WireGuard through Homebrew `wg-quick` (bash 4+, `wireguard-go`). The interface is named `mv<first 8 hex
//! digits of the id>`; wg-quick records the real `utunN` in `/var/run/wireguard/<iface>.name`.

use crate::ctx::{Ctx, R, tr};
use crate::exec::Cmd;
use crate::fsx;
use crate::paths::is_dir;

/// `wg_iface`: `mv` + the first 8 hex digits of the id, lower case.
pub fn iface_name(id: &str) -> String {
    let hex: String = id.chars().filter(|c| *c != '-').take(8).collect::<String>().to_ascii_lowercase();
    format!("mv{hex}")
}

/// `^mv[0-9a-f]{8}$`
pub fn is_iface(s: &str) -> bool {
    s.len() == 10 && s.starts_with("mv") && s[2..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `^utun[0-9]+$`
pub fn is_utun(s: &str) -> bool {
    s.strip_prefix("utun").is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// `up_wireguard`
pub fn up(ctx: &mut Ctx) -> R {
    let Some(wgq) = ctx.find_tool("wg-quick") else {
        return Err(ctx.die(tr("wg-quick not found (brew install wireguard-tools)", &[])));
    };
    let Some(bash4) = ctx.find_tool("bash") else {
        return Err(ctx.die(tr("bash 4+ not found (brew install bash)", &[])));
    };
    if ctx.find_tool("wireguard-go").is_none() {
        return Err(ctx.die(tr("wireguard-go not found (brew install wireguard-tools)", &[])));
    }
    let run = ctx.run().to_path_buf();
    let iface = iface_name(&ctx.id);
    let conf = run.join(format!("{iface}.conf"));
    let _ = std::fs::read(run.join("config")).map(|d| fsx::write_file(&conf, &d, 0o600));
    let _ = fsx::write_line(&run.join("iface"), &iface);
    // wg-quick calls wg and wireguard-go from PATH: the brew bin is needed (system directories first).
    ctx.brew_path = true;
    ctx.wg_debug_env = ctx.a.debug;
    let cmd = Cmd::new(&bash4).arg(&wgq).arg("up").arg(&conf);
    if !ctx.run_direct(&cmd)? {
        if !ctx.dry() {
            fsx::remove_rf(&run);
        }
        return Err(ctx.die(tr("wg-quick up failed (details in the log)", &[])));
    }
    if ctx.a.debug {
        let wg = ctx.find_tool("wg").unwrap_or_default();
        ctx.run_logged(&Cmd::new(wg).arg("show").arg(&iface))?;
    }
    Ok(())
}

/// `down_wireguard`
pub fn down(ctx: &mut Ctx) -> R<bool> {
    if !is_dir(ctx.run()) {
        ctx.no_running();
        return Ok(true);
    }
    let Some(wgq) = ctx.find_tool("wg-quick") else {
        return Err(ctx.die(tr("wg-quick not found", &[])));
    };
    let Some(bash4) = ctx.find_tool("bash") else {
        return Err(ctx.die(tr("bash 4+ not found", &[])));
    };
    let saved = fsx::read_trim(&ctx.run().join("iface"));
    let iface = saved.filter(|s| is_iface(s)).unwrap_or_else(|| iface_name(&ctx.id));
    ctx.brew_path = true;
    let conf = ctx.run().join(format!("{iface}.conf"));
    ctx.run_direct(&Cmd::new(&bash4).arg(&wgq).arg("down").arg(&conf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_names() {
        assert_eq!(iface_name("0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0"), "mv0f1e2d3c");
        assert!(is_iface("mv12345678") && !is_iface("mv1234567") && !is_iface("mv1234567G"));
        assert!(is_utun("utun12") && !is_utun("utun") && !is_utun("utun1x"));
    }
}
