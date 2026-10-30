//! The config text with its inline secrets masked (client-credential audit G1): what the editor shows while
//! "Show secrets" is off, so a screen share, a screenshot or someone looking over the shoulder does not see them.
//!
//! The masked text is only ever shown, never edited or saved: the editor keeps the real text in its draft, shows
//! the masked text read-only, and lets the user edit only with the secrets shown. Each masked line keeps its line
//! (the line numbers of the validation problems still match) and its indentation; the secret itself becomes
//! [`MASK`], whatever its length.
//!
//! What is masked follows the export's key material ([`crate::exporter::secret_material`]):
//! - OpenVPN: the lines inside `<key>`, `<pkcs12>`, `<tls-auth>`, `<tls-crypt>`, `<tls-crypt-v2>`, `<secret>`,
//!   `<auth-user-pass>` and `<http-proxy-user-pass>` (an unclosed block to the end of the text);
//! - WireGuard: the values of `PrivateKey` and `PresharedKey`;
//! - strongSwan: a top-level `secrets { … }` section, except its braces, its section names and its comments.

use crate::exporter::{self, OPENVPN_SECRET_BLOCKS};
use crate::models::VPNKind;
use crate::swift_str;

/// What a masked secret shows.
pub const MASK: &str = "••••••••••••••••";

/// The config with its secrets masked; `None`: there is nothing to mask (the text is shown as it is).
pub fn masked(kind: VPNKind, text: &str) -> Option<String> {
    let lines: Vec<&str> = text.split('\n').collect();
    let out: Vec<String> = match kind {
        VPNKind::Openvpn => openvpn(&lines),
        VPNKind::Wireguard => lines.iter().map(|line| wireguard(line)).collect(),
        VPNKind::Strongswan => strongswan(&lines),
        VPNKind::Sstp | VPNKind::L2tp | VPNKind::Cisco => return None,
    };
    let joined = out.join("\n");
    (joined != text).then_some(joined)
}

/// `line` with everything after its indentation masked (a blank line stays as it is; a trailing `\r` stays).
fn mask_line(line: &str) -> String {
    let (body, cr) = match line.strip_suffix('\r') {
        Some(body) => (body, "\r"),
        None => (line, ""),
    };
    if body.trim().is_empty() {
        return line.to_string();
    }
    let indent = &body[..body.len() - body.trim_start().len()];
    format!("{indent}{MASK}{cr}")
}

fn openvpn(lines: &[&str]) -> Vec<String> {
    let mut out = Vec::with_capacity(lines.len());
    let mut inside: Option<String> = None;
    for line in lines {
        if let Some(tag) = &inside {
            let closing = format!("</{tag}>");
            if swift_str::eq(
                &line.trim_matches(swift_str::is_foundation_whitespace_or_newline).to_lowercase(),
                &closing,
            ) {
                inside = None;
                out.push(line.to_string());
            } else {
                out.push(mask_line(line));
            }
            continue;
        }
        if let Some(tag) = exporter::openvpn_block_tag(line)
            && OPENVPN_SECRET_BLOCKS.contains(&tag.as_str())
        {
            inside = Some(tag);
        }
        out.push(line.to_string());
    }
    out
}

/// A `PrivateKey = …` / `PresharedKey = …` line with its value masked.
fn wireguard(line: &str) -> String {
    if exporter::wireguard_secret_key(line, true).is_none() {
        return line.to_string();
    }
    let Some(eq) = line.find('=') else { return line.to_string() };
    let value = &line[eq + 1..];
    let lead = &value[..value.len() - value.trim_start().len()];
    let cr = if line.ends_with('\r') { "\r" } else { "" };
    format!("{}{lead}{MASK}{cr}", &line[..=eq])
}

fn strongswan(lines: &[&str]) -> Vec<String> {
    let inside = exporter::strongswan_secret_lines(lines);
    let mut out = Vec::with_capacity(lines.len());
    let mut previous = false;
    for (line, &secret) in lines.iter().zip(&inside) {
        // A section's first line (a section may follow right after another one).
        let first = secret
            && (!previous
                || line.trim_start().strip_prefix("secrets").is_some_and(|r| r.trim_start().starts_with('{')));
        previous = secret;
        if !secret {
            out.push(line.to_string());
        } else if first {
            // `secrets {` stays; anything after its brace on the same line is masked.
            let Some(brace) = line.find('{') else {
                out.push(mask_line(line));
                continue;
            };
            let rest = &line[brace + 1..];
            if structural(rest) {
                out.push(line.to_string());
            } else {
                out.push(format!("{} {MASK}{}", &line[..=brace], if line.ends_with('\r') { "\r" } else { "" }));
            }
        } else if structural(line) {
            out.push(line.to_string());
        } else {
            out.push(mask_line(line));
        }
    }
    out
}

/// A line of a `secrets` section that holds no value: blank, a comment, a closing brace, or a section opening
/// (`ike-office {`).
fn structural(line: &str) -> bool {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') || t == "}" {
        return true;
    }
    match t.strip_suffix('{') {
        Some(name) => {
            let name = name.trim_end();
            !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
        }
        None => false,
    }
}
