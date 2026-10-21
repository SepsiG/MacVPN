//! The `validate` subcommand's logic (the old `mvpn-validate`) over core's validators, the single source of the
//! rules: the dispatch by kind and mode, on a framed config already in memory (see [`crate::shared::framing`]).
//! The backend reads stdin and prints the result (`macos::validate`).

use crate::shared::cli::is_valid_risky_list;
use crate::shared::framing::{FrameError, Framed};
use crate::shared::l10n::tr;
use macvpn_core::models::VPNKind;
use macvpn_core::validators::{self, OpenVPNValidator, SSTPValidator, StrongSwanValidator};
use std::collections::HashSet;

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

/// The names of an `--accept-risky` list.
pub fn risky_set(list: &str) -> HashSet<String> {
    list.split(',').filter(|s| !s.is_empty()).map(String::from).collect()
}

/// The `validate` subcommand without `--lang`: the exit code and the stdout text. `input` reads the framed config
/// (only once the arguments are valid).
pub fn run(argv: &[String], input: impl FnOnce() -> Result<Framed, FrameError>) -> (i32, String) {
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
    use crate::shared::framing::parse_framed;

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
    fn stdin_is_not_read_on_a_usage_error() {
        let args = vec!["nonsense".to_string()];
        let (code, _) = run(&args, || panic!("stdin read"));
        assert_eq!(code, 2);
    }
}
