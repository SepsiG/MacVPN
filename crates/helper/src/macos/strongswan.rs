//! strongSwan (IKEv2) through Homebrew `swanctl` + `charon`. The secrets go into a `secrets {}` block of the
//! root-only config copy (escaped); `charon` is only started if no root `charon` from the expected binary runs.

use crate::macos::ctx::{Ctx, R, tr};
use crate::macos::exec::{Cmd, EnvMode};
use crate::macos::fsx;
use crate::macos::paths::is_dir;
use crate::macos::procs;
use std::path::Path;

/// `^[A-Za-z0-9_.-]+$`
pub fn is_name(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// `swan_escape`: `\` → `\\`, `"` → `\"`.
pub fn escape(v: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() + 8);
    for &b in v {
        if b == b'\\' || b == b'"' {
            out.push(b'\\');
        }
        out.push(b);
    }
    out
}

/// The `secrets {}` block appended to the config copy.
pub fn secrets_block(user: &[u8], pass: &[u8], psk: &[u8]) -> zeroize::Zeroizing<Vec<u8>> {
    let mut b = zeroize::Zeroizing::new(b"secrets {\n".to_vec());
    if !psk.is_empty() {
        b.extend_from_slice(b"  ike-macvpn {\n    secret = \"");
        b.extend_from_slice(&escape(psk));
        b.extend_from_slice(b"\"\n  }\n");
    }
    if !pass.is_empty() {
        b.extend_from_slice(b"  eap-macvpn {\n    id = \"");
        b.extend_from_slice(&escape(user));
        b.extend_from_slice(b"\"\n    secret = \"");
        b.extend_from_slice(&escape(pass));
        b.extend_from_slice(b"\"\n  }\n");
    }
    b.extend_from_slice(b"}\n");
    b
}

/// A failed EAP sign-in in swanctl / charon output: `EAP_FAILURE`, or `EAP method … failed` on one line.
pub fn is_eap_failure(out: &[u8]) -> bool {
    crate::shared::mask::lines(out).any(|l| {
        crate::shared::mask::find(l, b"EAP_FAILURE").is_some()
            || crate::shared::mask::find(l, b"EAP method ")
                .is_some_and(|i| crate::shared::mask::find(&l[i + b"EAP method ".len()..], b" failed").is_some())
    })
}

/// `charon_pids`: root-owned `charon` processes (`pgrep -U 0 -x charon`) started from the expected binary (the
/// `ps` comm is the start path). Another user's or another path's `charon` is not ours.
pub fn charon_pids(charon: &Path) -> Vec<String> {
    let path = charon.display().to_string();
    let real = std::fs::canonicalize(charon).ok().map(|p| p.display().to_string());
    procs::pgrep(&["-U", "0", "-x", "charon"])
        .into_iter()
        .filter(|p| procs::comm(p).is_some_and(|c| c == path || real.as_deref() == Some(c.as_str())))
        .collect()
}

/// `up_strongswan`
pub fn up(ctx: &mut Ctx) -> R {
    let Some(swanctl) = ctx.find_tool("swanctl") else {
        return Err(ctx.die(tr("swanctl not found (brew install strongswan)", &[])));
    };
    let Some(charon) = ctx.find_charon() else {
        return Err(ctx.die(tr("charon not found (brew install strongswan)", &[])));
    };
    let run = ctx.run().to_path_buf();
    let (conn, child) = crate::macos::validate::swan_names(&run.join("config")).unwrap_or_default();
    if !is_name(&conn) {
        return Err(ctx.die(tr("No connection name found", &[])));
    }
    if !is_name(&child) {
        return Err(ctx.die(tr("No child name found", &[])));
    }
    let _ = fsx::write_line(&run.join("conn"), &conn);
    if !ctx.secrets.psk.is_empty() || !ctx.secrets.pass.is_empty() {
        let block = secrets_block(&ctx.secrets.user, &ctx.secrets.pass, &ctx.secrets.psk);
        let _ = fsx::append(&run.join("config"), &block);
        ctx.log.step(&tr("secrets block added (masked)", &[]));
    }
    // charon does not daemonize: started in the background, without the caller's pipes.
    if ctx.dry() || charon_pids(&charon).is_empty() {
        ctx.run_bg(&Cmd::new(&charon))?;
        if !ctx.dry() {
            for _ in 0..10 {
                if crate::macos::exec::quiet(&Cmd::new(&swanctl).arg("--stats"), ctx.env_mode()) {
                    break;
                }
                ctx.sleep_ms(500)?;
            }
        }
    }
    let config = run.join("config");
    if !ctx.run_logged(&Cmd::new(&swanctl).arg("--load-all").arg("--file").arg(&config))? {
        if !ctx.dry() {
            fsx::remove_rf(&run);
        }
        return Err(ctx.die(tr("swanctl --load-all failed", &[])));
    }
    let lvl = if ctx.a.debug { "2" } else { "1" };
    let initiate = Cmd::new(&swanctl).args(["--initiate", "--child", &child, "--timeout", "30", "--loglevel", lvl]);
    // The EAP verdict comes from swanctl's own (masked) output stream, not from the user-writable log.
    let (initiated, eap) = ctx.run_logged_scan(&initiate, is_eap_failure)?;
    if !initiated {
        ctx.run_logged(&Cmd::new(&swanctl).args(["--terminate", "--ike", &conn, "--timeout", "5"]))?;
        if !ctx.dry() {
            fsx::remove_rf(&run);
        }
        if eap {
            return Err(ctx.die(tr("Authentication failed (EAP)", &[])));
        }
        return Err(ctx.die(tr("IKE negotiation failed (details in the log)", &[])));
    }
    Ok(())
}

/// `down_strongswan`: charon is only stopped if no other strongSwan connection runs.
pub fn down(ctx: &mut Ctx) -> R<bool> {
    if !is_dir(ctx.run()) {
        ctx.no_running();
        return Ok(true);
    }
    let Some(swanctl) = ctx.find_tool("swanctl") else {
        return Err(ctx.die(tr("swanctl not found", &[])));
    };
    let conn = fsx::cat(&ctx.run().join("conn"));
    if is_name(&conn) {
        ctx.run_logged(&Cmd::new(&swanctl).args(["--terminate", "--ike", &conn, "--timeout", "10"]))?;
    }
    if others_running(ctx) == 0
        && !ctx.dry()
        && let Some(charon) = ctx.find_charon()
    {
        for p in charon_pids(&charon) {
            ctx.log.cmd(&format!("kill {p}"));
            procs::signal(&p, crate::macos::sys::SIGTERM);
        }
    }
    Ok(true)
}

/// Other run directories whose `kind` is strongswan (`grep -lx strongswan $RUN_BASE/*/kind`, this one excluded).
fn others_running(ctx: &Ctx) -> usize {
    let Ok(entries) = std::fs::read_dir(&ctx.s.run_base) else { return 0 };
    entries
        .filter_map(Result::ok)
        .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
        .filter(|e| e.path() != ctx.run())
        .filter(|e| {
            std::fs::read(e.path().join("kind"))
                .map(|d| d.split(|&b| b == b'\n').any(|l| l == b"strongswan"))
                .unwrap_or(false)
        })
        .count()
}

/// Whether swanctl reports the IKE SA (`status`): `Some("connected")`, `Some("connecting")` or `None`.
pub fn sa_state(swanctl: &Path, conn: &str, mode: EnvMode) -> Option<&'static str> {
    let (_, out) = crate::macos::exec::capture(&Cmd::new(swanctl).args(["--list-sas", "--ike", conn]), mode, 1 << 20)?;
    if crate::shared::mask::find(&out, b"ESTABLISHED").is_some() {
        Some("connected")
    } else if crate::shared::mask::find(&out, b"CONNECTING").is_some() {
        Some("connecting")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_block_is_escaped() {
        let b = secrets_block(b"al\"ice", b"p\\w", b"k\"y");
        assert_eq!(
            String::from_utf8(b.to_vec()).unwrap(),
            "secrets {\n  ike-macvpn {\n    secret = \"k\\\"y\"\n  }\n  eap-macvpn {\n    id = \"al\\\"ice\"\n    secret = \"p\\\\w\"\n  }\n}\n"
        );
        assert_eq!(
            secrets_block(b"", b"", b"psk").to_vec(),
            b"secrets {\n  ike-macvpn {\n    secret = \"psk\"\n  }\n}\n".to_vec()
        );
    }

    #[test]
    fn eap_failures() {
        assert!(is_eap_failure(b"[IKE] received EAP_FAILURE, EAP authentication failed\n"));
        assert!(is_eap_failure(b"x\n[IKE] EAP method EAP_MSCHAPV2 failed for peer 10.0.0.1\ny\n"));
        assert!(is_eap_failure(b"EAP method EAP_PEAP (id 0x02) failed"));
        assert!(!is_eap_failure(b"[IKE] establishing CHILD_SA office-net failed\n"));
        assert!(!is_eap_failure(b"EAP method\n failed\n"));
        assert!(!is_eap_failure(b"initiate failed: establishing CHILD_SA 'office-net' failed\n"));
        assert!(!is_eap_failure(b""));
    }

    #[test]
    fn names() {
        assert!(is_name("office-net") && is_name("a.b_c") && !is_name("a b") && !is_name(""));
    }
}
