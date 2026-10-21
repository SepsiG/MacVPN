//! Config validation with the core validators (the single source of the rules), in-process for `up`, and the
//! `validate` subcommand that replaces the old `mvpn-validate` binary. Since root layer 8 it takes the config on
//! stdin, framed like `up`'s but without secret lines (`config <len>\n<len bytes>`, nothing after; see
//! [`crate::shared::framing`]); it opens no file:
//!
//! ```text
//! mvpn validate [--lang en|hu] <openvpn|wireguard|strongswan|sstp> [--accept-risky a,b]
//!                                         → issues on stdout, one per line; exit 1 if any, 2 on a usage error
//!                                           or a refused stdin (its message on stdout)
//! mvpn validate [--lang en|hu] --swan-names   → connection and child name (two lines); exit 1 if none
//! mvpn validate [--lang en|hu] --sstp-params  → the validated SSTP parameters, one per line
//! mvpn validate [--lang en|hu] --sstp-ca      → the validated config's <ca> PEM block
//! ```

use crate::macos::ctx::{Ctx, Exit, R, tr};
use crate::macos::fsx;
use crate::shared::validate::{issues, risky_set, run};
use macvpn_core::l10n::AppLanguage;
use macvpn_core::models::VPNKind;
use macvpn_core::validators::{SSTPValidator, StrongSwanValidator};
use std::collections::HashSet;
use std::path::Path;
use zeroize::Zeroizing;

/// A run file's text (lossy UTF-8, like the Swift `String(decoding:as:)`), zeroed on drop: the config may hold
/// private keys.
fn read_text(p: &Path) -> Option<Zeroizing<String>> {
    let data = std::fs::read(p).ok()?;
    Some(Zeroizing::new(match String::from_utf8(data) {
        Ok(text) => text,
        Err(e) => {
            let raw = Zeroizing::new(e.into_bytes());
            String::from_utf8_lossy(&raw).into_owned()
        }
    }))
}

/// `validate_config` (in-process; the bash ran `mvpn-validate`), on the framed config in memory. `up` runs it
/// before anything else changes (the previous run is closed only for a valid config), and writes exactly these
/// bytes into the run directory afterwards.
pub fn validate_config(ctx: &Ctx, config: &[u8]) -> R {
    let mut acknowledged = HashSet::new();
    if ctx.kind == "openvpn" && !ctx.a.accept_risky.is_empty() {
        acknowledged = risky_set(&ctx.a.accept_risky);
        ctx.log.step(&format!("{} {}", tr("acknowledged risky directives:", &[]), ctx.a.accept_risky));
    }
    let Ok(text) = std::str::from_utf8(config) else {
        // The framing already refuses non-UTF-8; kept so this function never validates a lossy copy.
        return Err(ctx.die(tr("Invalid input", &[])));
    };
    let found = VPNKind::from_raw_value(&ctx.kind).and_then(|k| issues(k, text, &acknowledged));
    let found = found.unwrap_or_else(|| vec![tr("Unknown type: %@", &[&ctx.kind])]);
    if !found.is_empty() {
        for l in &found {
            ctx.log.line(&format!("✗ {l}"));
        }
        if let Some(run) = &ctx.run {
            fsx::remove_rf(run);
        }
        if !ctx.quiet {
            err!("{}\n{}", tr("Invalid config:", &[]), found.join("\n"));
        }
        return Err(Exit(1));
    }
    ctx.log.step(&tr("config is valid", &[]));
    Ok(())
}

/// The first connection and child name of a strongSwan config.
pub fn swan_names(p: &Path) -> Option<(String, String)> {
    StrongSwanValidator::names(&read_text(p)?)
}

/// The validated SSTP parameters (host, port, user, cert, route_all, peer_dns).
pub fn sstp_params(p: &Path) -> Option<Vec<String>> {
    SSTPValidator::parameters(&read_text(p)?)
}

/// The `<ca>` PEM block of a valid SSTP config.
pub fn sstp_ca(p: &Path) -> Option<String> {
    SSTPValidator::ca_pem(&read_text(p)?)
}

/// `mvpn validate …` (the old `mvpn-validate`); returns the exit code.
pub fn main(argv: &[String]) -> i32 {
    let mut args: Vec<String> = argv.to_vec();
    let mut lang = AppLanguage::En;
    if let Some(i) = args.iter().position(|a| a == "--lang") {
        lang = args.get(i + 1).map(|v| AppLanguage::from_argument(v)).unwrap_or(AppLanguage::En);
        let end = (i + 2).min(args.len());
        args.drain(i..end);
    }
    AppLanguage::set_override(Some(lang));
    let (code, out) = run(&args, || crate::macos::read_framed_stdin(false));
    crate::macos::out_raw(&out);
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    const WG: &str = "[Interface]\nPrivateKey = bWFjdnBuLXRlc3QtcHJpdmF0ZS1rZXktMzJieXRlcyE=\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = bWFjdnBuLXRlc3QtcHVibGljLS1rZXktMzJieXRlcyE=\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.com:51820\n";

    #[test]
    fn the_up_check_runs_on_memory_without_a_run_directory() {
        use crate::macos::paths::Settings;
        use crate::macos::testmode::TestEnv;
        use crate::shared::cli::Args;
        let a = Args { cmd: "up".into(), kind: "wireguard".into(), ..Args::default() };
        let mut c = Ctx::new(Settings::resolve(true, TestEnv::default(), String::new()), a);
        c.quiet = true;
        assert!(validate_config(&c, WG.as_bytes()).is_ok());
        assert_eq!(validate_config(&c, WG.replace("Address", "PostUp = x\nAddress").as_bytes()), Err(Exit(1)));
        assert_eq!(validate_config(&c, b"\xff"), Err(Exit(1)));
        assert!(c.run.is_none());
    }
}
