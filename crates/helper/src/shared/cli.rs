//! The command line of the `up` / `down` / `status` / `version` / `respond` family, parsed exactly like the bash
//! `mvpn`: the flags may stand anywhere, `--lang` / `--accept-risky` take the next argument, the first three other
//! arguments are the command, the kind and the id.

use macvpn_core::l10n::AppLanguage;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Args {
    pub cmd: String,
    pub kind: String,
    pub id: String,
    pub debug: bool,
    pub dry_run: bool,
    /// `--lang` value (`hu` gives Hungarian, anything else English).
    pub lang_hu: bool,
    /// `--accept-risky` was given (its value may be empty or missing: then it is invalid).
    pub accept_risky_set: bool,
    pub accept_risky: String,
}

impl Args {
    pub fn parse(argv: &[String]) -> Args {
        let mut a = Args::default();
        let mut lang = String::from("en");
        let mut positional = Vec::new();
        let mut expect_lang = false;
        let mut expect_risky = false;
        for arg in argv {
            if expect_lang {
                lang = arg.clone();
                expect_lang = false;
                continue;
            }
            if expect_risky {
                a.accept_risky = arg.clone();
                expect_risky = false;
                continue;
            }
            match arg.as_str() {
                "--accept-risky" => {
                    a.accept_risky_set = true;
                    expect_risky = true;
                }
                "--debug" => a.debug = true,
                "--dry-run" => a.dry_run = true,
                "--lang" => expect_lang = true,
                s if s.starts_with("--lang=") => lang = s["--lang=".len()..].to_string(),
                _ => positional.push(arg.clone()),
            }
        }
        a.lang_hu = lang == "hu";
        let mut it = positional.into_iter();
        a.cmd = it.next().unwrap_or_default();
        a.kind = it.next().unwrap_or_default();
        a.id = it.next().unwrap_or_default();
        a
    }

    pub fn language(&self) -> AppLanguage {
        if self.lang_hu { AppLanguage::Hu } else { AppLanguage::En }
    }

    /// `^[a-z0-9-]+(,[a-z0-9-]+)*$`, at most 4096 bytes (only checked when the flag was given).
    pub fn accept_risky_valid(&self) -> bool {
        !self.accept_risky_set || is_valid_risky_list(&self.accept_risky)
    }
}

/// The format of an `--accept-risky` list (what the names mean is up to the validator).
pub fn is_valid_risky_list(v: &str) -> bool {
    v.len() <= 4096
        && !v.is_empty()
        && v.split(',')
            .all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
}

/// `^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`
pub fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter()
            .enumerate()
            .all(|(i, c)| if matches!(i, 8 | 13 | 18 | 23) { *c == b'-' } else { c.is_ascii_hexdigit() })
}

/// The kinds the root layer runs.
pub fn is_kind(s: &str) -> bool {
    matches!(s, "openvpn" | "wireguard" | "strongswan" | "sstp")
}

/// `^[A-Za-z_][A-Za-z0-9_.-]*$`
pub fn is_user_name(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(v: &[&str]) -> Args {
        Args::parse(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn flags_anywhere() {
        let a = p(&["--debug", "up", "--lang", "hu", "openvpn", "--dry-run", "ID", "extra", "--accept-risky", "a,b"]);
        assert_eq!((a.cmd.as_str(), a.kind.as_str(), a.id.as_str()), ("up", "openvpn", "ID"));
        assert!(a.debug && a.dry_run && a.lang_hu && a.accept_risky_set);
        assert_eq!(a.accept_risky, "a,b");
        assert!(p(&["version", "--lang=hu"]).lang_hu);
        assert!(!p(&["version", "--lang", "de"]).lang_hu);
        assert!(!p(&["version", "--lang"]).lang_hu);
    }

    #[test]
    fn accept_risky_format() {
        for ok in ["user", "group,user", "future-option", "a1-b"] {
            assert!(is_valid_risky_list(ok), "{ok}");
        }
        for bad in ["User", "a,,b", ",a", "a;b", "a b", "../x", "", "a,"] {
            assert!(!is_valid_risky_list(bad), "{bad}");
        }
        assert!(!is_valid_risky_list(&"a".repeat(4097)));
        assert!(is_valid_risky_list(&"a".repeat(4096)));
        let missing = p(&["up", "openvpn", "x", "--accept-risky"]);
        assert!(missing.accept_risky_set && !missing.accept_risky_valid());
        assert!(p(&["up"]).accept_risky_valid());
    }

    #[test]
    fn ids_kinds_users() {
        assert!(is_uuid("0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0"));
        assert!(is_uuid("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"));
        assert!(!is_uuid("../../etc"));
        assert!(!is_uuid("0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0\n"));
        assert!(is_kind("sstp") && !is_kind("pptp") && !is_kind("l2tp"));
        assert!(is_user_name("bob") && is_user_name("_x.y-z") && !is_user_name("1x") && !is_user_name("a b"));
    }
}
