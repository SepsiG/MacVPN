//! `mvpn liveness <id>` (root layer 10): a running tunnel's liveness facts for the app's dead-tunnel detection, in
//! the format of [`macvpn_core::liveness`]. The app passes only the connection ID (a UUID); the root layer maps it to
//! its own run directory and interface. Only times and counters leave it: never a key, an address, an interface name
//! or a path.
//!
//! - WireGuard: `wg show <utun> dump` (the utun wg-quick recorded for the connection's `mv…` interface). The dump
//!   holds the private and preshared keys: only the numbers are taken, and the buffer is zeroed.
//! - OpenVPN: the run file `tunnel` the management bridge writes (`up` | `reconnecting <t>`); none yet (not
//!   connected, or a bridge of root layer 9 still running): nothing to report.
//! - Anything else, an unknown ID or no answer: exit 1 without output (the app decides nothing).

use crate::macos::ctx::Ctx;
use crate::macos::exec::{Cmd, EnvMode};
use crate::macos::fsx;
use crate::macos::paths::{is_dir, is_file, is_symlink};
use crate::macos::wireguard::{is_iface, is_utun};
use crate::shared::cli::is_uuid;
use macvpn_core::liveness::{Liveness, MAX_PEERS, WgPeer};
use macvpn_core::models::{parse_uuid, uuid_string};
use std::path::Path;
use zeroize::Zeroize;

/// The longest `wg show dump` read (64 peers fit many times over).
const DUMP_MAX: usize = 1 << 20;

/// The peers of a `wg show <iface> dump` (tab-separated: the interface line first, then per peer `public-key
/// preshared-key endpoint allowed-ips latest-handshake transfer-rx transfer-tx persistent-keepalive`). `None`: not
/// that format. Only the numbers and whether an endpoint is set are kept.
pub fn parse_dump(dump: &[u8]) -> Option<Vec<WgPeer>> {
    let text = std::str::from_utf8(dump).ok()?;
    let mut lines = text.lines();
    if lines.next()?.split('\t').count() != 4 {
        return None;
    }
    let num = |s: &str| -> Option<u64> {
        (!s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit())).then(|| s.parse().ok()).flatten()
    };
    let mut peers = Vec::new();
    for line in lines.filter(|l| !l.is_empty()) {
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() != 8 {
            return None;
        }
        let handshake = num(f[4])?;
        let keepalive = if f[7] == "off" { 0 } else { u16::try_from(num(f[7])?).ok()? };
        if peers.len() < MAX_PEERS {
            peers.push(WgPeer {
                last_handshake: (handshake != 0).then_some(handshake),
                rx: num(f[5])?,
                tx: num(f[6])?,
                keepalive,
                endpoint: f[2] != "(none)",
            });
        }
    }
    Some(peers)
}

/// The OpenVPN run file `tunnel`: `up` | `reconnecting <digits>`.
pub fn parse_tunnel(data: &[u8]) -> Option<Liveness> {
    let text = std::str::from_utf8(data).ok()?;
    let line = text.strip_suffix('\n').unwrap_or(text);
    if line == "up" {
        return Some(Liveness::OpenVpn { reconnecting_since: None });
    }
    let t = line.strip_prefix("reconnecting ")?;
    let ok = !t.is_empty() && t.len() <= 20 && t.bytes().all(|b| b.is_ascii_digit());
    ok.then(|| t.parse().ok()).flatten().map(|t| Liveness::OpenVpn { reconnecting_since: Some(t) })
}

fn wireguard(ctx: &Ctx, run: &Path) -> Option<Liveness> {
    let iface = fsx::read_trim(&run.join("iface")).filter(|s| is_iface(s))?;
    let utun = fsx::cat(&ctx.s.wg_run.join(format!("{iface}.name")));
    if !is_utun(&utun) {
        return None;
    }
    let wg = ctx.find_tool("wg")?;
    let mode = if ctx.s.test_mode { EnvMode::Inherit } else { EnvMode::Minimal };
    let (ok, mut out) = crate::macos::exec::capture(&Cmd::new(wg).arg("show").arg(&utun).arg("dump"), mode, DUMP_MAX)?;
    let peers = if ok { parse_dump(&out) } else { None };
    out.zeroize();
    peers.map(Liveness::WireGuard)
}

fn openvpn(run: &Path) -> Option<Liveness> {
    let f = run.join("tunnel");
    if !is_file(&f) || is_symlink(&f) {
        return None;
    }
    parse_tunnel(&fsx::read_private(&f, 64)?)
}

/// `mvpn liveness <id>` (the ID is the CLI's second positional).
pub fn main(ctx: &Ctx) -> i32 {
    let raw = ctx.kind.as_str();
    let Some(id) = parse_uuid(raw).filter(|_| is_uuid(raw)).map(|u| uuid_string(&u)) else {
        return ctx.die(crate::macos::ctx::tr("Invalid ID", &[])).0;
    };
    let run = ctx.s.run_base.join(&id);
    if !is_dir(&run) || is_symlink(&run) {
        return 1;
    }
    let facts = match fsx::cat(&run.join("kind")).as_str() {
        "wireguard" => wireguard(ctx, &run),
        "openvpn" => openvpn(&run),
        _ => None,
    };
    match facts {
        Some(l) => {
            crate::macos::out_raw(&l.encode());
            0
        }
        None => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_dump_gives_only_the_numbers() {
        let dump = "cHJpdmF0ZQ==\tcHVibGlj\t51820\toff\n\
                    cGVlcg==\tcHNr\t203.0.113.7:51820\t0.0.0.0/0\t1800000000\t1024\t2048\t25\n\
                    b3RoZXI=\t(none)\t(none)\t10.0.0.0/8\t0\t0\t0\toff\n";
        let peers = parse_dump(dump.as_bytes()).unwrap();
        assert_eq!(
            peers,
            [
                WgPeer { last_handshake: Some(1_800_000_000), rx: 1024, tx: 2048, keepalive: 25, endpoint: true },
                WgPeer { last_handshake: None, rx: 0, tx: 0, keepalive: 0, endpoint: false },
            ]
        );
        let out = Liveness::WireGuard(peers).encode();
        for secret in ["cHJpdmF0ZQ", "cHVibGlj", "cGVlcg", "cHNr", "203.0.113.7", "0.0.0.0/0"] {
            assert!(!out.contains(secret), "{out}");
        }
        assert_eq!(parse_dump(b"k\tp\t1\toff\n"), Some(vec![]));
    }

    #[test]
    fn anything_else_is_refused() {
        for bad in [
            "",
            "k\tp\t1\n",
            "k\tp\t1\toff\npeer\tpsk\t(none)\t0/0\t1\t2\t3\n",
            "k\tp\t1\toff\npeer\tpsk\t(none)\t0/0\t-1\t2\t3\toff\n",
            "k\tp\t1\toff\npeer\tpsk\t(none)\t0/0\t1\t2\t3\t70000\n",
            "k\tp\t1\toff\npeer\tpsk\t(none)\t0/0\tx\t2\t3\toff\n",
        ] {
            assert_eq!(parse_dump(bad.as_bytes()), None, "{bad:?}");
        }
    }

    #[test]
    fn the_tunnel_file() {
        assert_eq!(parse_tunnel(b"up\n"), Some(Liveness::OpenVpn { reconnecting_since: None }));
        assert_eq!(
            parse_tunnel(b"reconnecting 1800000000\n"),
            Some(Liveness::OpenVpn { reconnecting_since: Some(1_800_000_000) })
        );
        for bad in [&b""[..], b"down\n", b"reconnecting\n", b"reconnecting -1\n", b"reconnecting 1 2\n", b"UP\n"] {
            assert_eq!(parse_tunnel(bad), None, "{bad:?}");
        }
    }
}
