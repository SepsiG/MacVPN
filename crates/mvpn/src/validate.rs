//! Config validation with the core validators (the single source of the rules), in-process for `up`, and the
//! `validate` subcommand that replaces the old `mvpn-validate` binary:
//!
//! ```text
//! mvpn validate [--lang en|hu] <openvpn|wireguard|strongswan|sstp> <file> [--accept-risky a,b]
//!                                         → issues on stdout, one per line; exit 1 if any, 2 on a usage error
//! mvpn validate [--lang en|hu] --swan-names <file>   → connection and child name (two lines); exit 1 if none
//! mvpn validate [--lang en|hu] --sstp-params <file>  → the validated SSTP parameters, one per line
//! mvpn validate [--lang en|hu] --sstp-ca <file>      → the validated config's <ca> PEM block
//! ```

use crate::cli::is_valid_risky_list;
use crate::ctx::{Ctx, Exit, R, tr};
use crate::fsx;
use macvpn_core::l10n::AppLanguage;
use macvpn_core::models::VPNKind;
use macvpn_core::validators::{self, OpenVPNValidator, SSTPValidator, StrongSwanValidator};
use std::collections::HashSet;
use std::path::Path;

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

/// The validated config's text (lossy UTF-8, like the Swift `String(decoding:as:)`).
fn read_text(p: &Path) -> Option<String> {
    std::fs::read(p).ok().map(|d| String::from_utf8_lossy(&d).into_owned())
}

/// `validate_config` (in-process; the bash ran `mvpn-validate`).
pub fn validate_config(ctx: &Ctx) -> R {
    let run = ctx.run().to_path_buf();
    let mut acknowledged = HashSet::new();
    if ctx.kind == "openvpn" && !ctx.a.accept_risky.is_empty() {
        acknowledged = risky_set(&ctx.a.accept_risky);
        ctx.log.step(&format!("{} {}", tr("acknowledged risky directives:", &[]), ctx.a.accept_risky));
    }
    let kind = VPNKind::from_raw_value(&ctx.kind);
    let found = match (kind, read_text(&run.join("config"))) {
        (Some(k), Some(text)) => issues(k, &text, &acknowledged),
        (_, None) => Some(vec![tr("Cannot read the file: %@", &[&run.join("config").display().to_string()])]),
        (None, _) => None,
    };
    let found = found.unwrap_or_else(|| vec![tr("Unknown type: %@", &[&ctx.kind])]);
    if !found.is_empty() {
        for l in &found {
            ctx.log.line(&format!("✗ {l}"));
        }
        fsx::remove_rf(&run);
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
    let mut acknowledged = HashSet::new();
    if let Some(i) = args.iter().position(|a| a == "--accept-risky") {
        let value = args.get(i + 1).cloned().unwrap_or_default();
        if !is_valid_risky_list(&value) {
            out!("{}", tr("Invalid --accept-risky value", &[]));
            return 2;
        }
        acknowledged = risky_set(&value);
        let end = (i + 2).min(args.len());
        args.drain(i..end);
    }
    if args.len() != 2 {
        out!(
            "{}",
            tr(
                "Usage: mvpn-validate [--lang en|hu] <openvpn|wireguard|strongswan|sstp> <file> [--accept-risky names] | --swan-names <file> | --sstp-params <file> | --sstp-ca <file>",
                &[]
            )
        );
        return 2;
    }
    let path = Path::new(&args[1]);
    let read = || {
        let text = read_text(path);
        if text.is_none() {
            out!("{}", tr("Cannot read the file: %@", &[&args[1]]));
        }
        text
    };
    match args[0].as_str() {
        "--swan-names" => match read() {
            None => 2,
            Some(text) => match StrongSwanValidator::names(&text) {
                Some((c, ch)) => {
                    out!("{c}\n{ch}");
                    0
                }
                None => 1,
            },
        },
        "--sstp-params" => match read() {
            None => 2,
            Some(text) => match SSTPValidator::parameters(&text) {
                Some(p) => {
                    for l in p {
                        out!("{l}");
                    }
                    0
                }
                None => 1,
            },
        },
        "--sstp-ca" => match read() {
            None => 2,
            Some(text) => match SSTPValidator::ca_pem(&text) {
                Some(pem) => {
                    out!("{pem}");
                    0
                }
                None => 1,
            },
        },
        k => {
            let Some(kind) = VPNKind::from_raw_value(k).filter(|kind| validators::validator(*kind).is_some()) else {
                out!("{}", tr("Unknown type: %@", &[k]));
                return 2;
            };
            let Some(text) = read() else { return 2 };
            let list = issues(kind, &text, &acknowledged).unwrap_or_default();
            for l in &list {
                out!("{l}");
            }
            i32::from(!list.is_empty())
        }
    }
}
