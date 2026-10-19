//! Config validation with the core validators (the single source of the rules), in-process for `up`, and the
//! `validate` subcommand that replaces the old `mvpn-validate` binary. Since root layer 8 it takes the config on
//! stdin, framed like `up`'s but without secret lines (`config <len>\n<len bytes>`, nothing after; see
//! [`crate::secrets`]); it opens no file:
//!
//! ```text
//! mvpn validate [--lang en|hu] <openvpn|wireguard|strongswan|sstp> [--accept-risky a,b]
//!                                         → issues on stdout, one per line; exit 1 if any, 2 on a usage error
//!                                           or a refused stdin (its message on stdout)
//! mvpn validate [--lang en|hu] --swan-names   → connection and child name (two lines); exit 1 if none
//! mvpn validate [--lang en|hu] --sstp-params  → the validated SSTP parameters, one per line
//! mvpn validate [--lang en|hu] --sstp-ca      → the validated config's <ca> PEM block
//! ```

use crate::cli::is_valid_risky_list;
use crate::ctx::{Ctx, Exit, R, tr};
use crate::fsx;
use crate::secrets::{FrameError, Framed};
use macvpn_core::l10n::AppLanguage;
use macvpn_core::models::VPNKind;
use macvpn_core::validators::{self, OpenVPNValidator, SSTPValidator, StrongSwanValidator};
use std::collections::HashSet;
use std::path::Path;
use zeroize::Zeroizing;

/// The issues of a config text (displayed lines, in the current language).
pub fn issues(kind: VPNKind, text: &str, acknowledged: &HashSet<String>) -> Option<Vec<String>> {
    let v = validators::validator(kind)?;
    let list = if kind == VPNKind::Openvpn {
        OpenVPNValidator.validate_full(text, acknowledged).all_issues()
    } else {
        v.validate(text)
    };
    Some(list.iter().map(|i| i.display()).collect())
}

fn risky_set(list: &str) -> HashSet<String> {
    list.split(',').filter(|s| !s.is_empty()).map(String::from).collect()
}

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
    let (code, out) = run(&args, || crate::secrets::read_framed_stdin(false));
    crate::out_raw(&out);
    code
}

/// The `validate` subcommand without `--lang`: the exit code and the stdout text. `input` reads the framed config
/// (only once the arguments are valid).
fn run(argv: &[String], input: impl FnOnce() -> Result<Framed, FrameError>) -> (i32, String) {
    let mut args: Vec<String> = argv.to_vec();
    let mut acknowledged = HashSet::new();
    if let Some(i) = args.iter().position(|a| a == "--accept-risky") {
        let value = args.get(i + 1).cloned().unwrap_or_default();
        if !is_valid_risky_list(&value) {
            return (2, format!("{}\n", tr("Invalid --accept-risky value", &[])));
        }
        acknowledged = risky_set(&value);
        let end = (i + 2).min(args.len());
        args.drain(i..end);
    }
    let usage = || {
        tr(
            "Usage: mvpn validate [--lang en|hu] <openvpn|wireguard|strongswan|sstp> [--accept-risky names] | --swan-names | --sstp-params | --sstp-ca (the config on stdin: config <length>, a newline, the config)",
            &[],
        )
    };
    let [mode] = args.as_slice() else { return (2, format!("{}\n", usage())) };
    let kind = match mode.as_str() {
        "--swan-names" | "--sstp-params" | "--sstp-ca" => None,
        k => match VPNKind::from_raw_value(k).filter(|kind| validators::validator(*kind).is_some()) {
            Some(kind) => Some(kind),
            None => return (2, format!("{}\n", tr("Unknown type: %@", &[k]))),
        },
    };
    let config = match input() {
        Ok((config, _)) => config,
        Err(e) => return (2, format!("{}\n", e.message())),
    };
    // Borrowed, no copy of the config (the framing already checked UTF-8).
    let Ok(text) = std::str::from_utf8(&config) else {
        return (2, format!("{}\n", FrameError::Invalid.message()));
    };
    let lines = |list: Vec<String>| list.iter().map(|l| format!("{l}\n")).collect::<String>();
    match (mode.as_str(), kind) {
        ("--swan-names", _) => match StrongSwanValidator::names(text) {
            Some((c, ch)) => (0, format!("{c}\n{ch}\n")),
            None => (1, String::new()),
        },
        ("--sstp-params", _) => match SSTPValidator::parameters(text) {
            Some(p) => (0, lines(p)),
            None => (1, String::new()),
        },
        ("--sstp-ca", _) => match SSTPValidator::ca_pem(text) {
            Some(pem) => (0, format!("{pem}\n")),
            None => (1, String::new()),
        },
        (_, Some(kind)) => {
            let list = issues(kind, text, &acknowledged).unwrap_or_default();
            (i32::from(!list.is_empty()), lines(list))
        }
        (_, None) => (2, format!("{}\n", usage())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secrets::parse_framed;

    fn framed(config: &str) -> Vec<u8> {
        format!("config {}\n{config}", config.len()).into_bytes()
    }

    fn call(args: &[&str], stdin: &[u8]) -> (i32, String) {
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        run(&args, || parse_framed(stdin, false))
    }

    const SWAN: &str = "connections {\n  office {\n    remote_addrs = vpn.example.com\n    children {\n      office-net {\n        remote_ts = 0.0.0.0/0\n      }\n    }\n  }\n}\n";
    const WG: &str = "[Interface]\nPrivateKey = bWFjdnBuLXRlc3QtcHJpdmF0ZS1rZXktMzJieXRlcyE=\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = bWFjdnBuLXRlc3QtcHVibGljLS1rZXktMzJieXRlcyE=\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.com:51820\n";

    #[test]
    fn validates_the_config_from_stdin() {
        assert_eq!(call(&["wireguard"], &framed(WG)), (0, String::new()));
        let (code, out) = call(&["wireguard"], &framed(&WG.replace("Address", "PostUp = x\nAddress")));
        assert_eq!(code, 1);
        assert!(!out.is_empty());
        assert_eq!(call(&["--swan-names"], &framed(SWAN)), (0, "office\noffice-net\n".into()));
        let ovpn = "client\ndev tun\nremote vpn.example.com 1194\nuser nobody\n";
        assert_eq!(call(&["openvpn"], &framed(ovpn)).0, 1);
        assert_eq!(call(&["openvpn", "--accept-risky", "user"], &framed(ovpn)), (0, String::new()));
    }

    #[test]
    fn a_refused_stdin_is_a_usage_error() {
        for bad in [&b""[..], b"config 5\nab", b"config 01\nx", b"config 1048577\n"] {
            assert_eq!(call(&["wireguard"], bad).0, 2, "{:?}", String::from_utf8_lossy(bad));
        }
        let mut with_secret = framed(WG);
        with_secret.extend_from_slice(b"password=x\n");
        assert_eq!(call(&["wireguard"], &with_secret).0, 2);
        assert_eq!(call(&["--sstp-ca"], b"config 3\na\0b").0, 2);
    }

    #[test]
    fn the_file_argument_is_gone() {
        assert_eq!(call(&["wireguard", "/etc/hosts"], &framed(WG)).0, 2);
        assert_eq!(call(&["--swan-names", "/etc/hosts"], &framed(SWAN)).0, 2);
        assert_eq!(call(&[], &framed(WG)).0, 2);
        assert_eq!(call(&["pptp"], &framed(WG)).0, 2);
        assert_eq!(call(&["openvpn", "--accept-risky", "a b"], &framed(WG)).0, 2);
    }

    #[test]
    fn the_up_check_runs_on_memory_without_a_run_directory() {
        use crate::cli::Args;
        use crate::paths::Settings;
        use crate::testmode::TestEnv;
        let a = Args { cmd: "up".into(), kind: "wireguard".into(), ..Args::default() };
        let mut c = Ctx::new(Settings::resolve(true, TestEnv::default(), String::new()), a);
        c.quiet = true;
        assert!(validate_config(&c, WG.as_bytes()).is_ok());
        assert_eq!(validate_config(&c, WG.replace("Address", "PostUp = x\nAddress").as_bytes()), Err(Exit(1)));
        assert_eq!(validate_config(&c, b"\xff"), Err(Exit(1)));
        assert!(c.run.is_none());
    }

    #[test]
    fn stdin_is_not_read_on_a_usage_error() {
        let args = vec!["nonsense".to_string()];
        let (code, _) = run(&args, || panic!("stdin read"));
        assert_eq!(code, 2);
    }
}
