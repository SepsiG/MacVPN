//! OpenVPN's "Send all traffic over VPN" (LinVPN decisions 7 and 8, resolved point 4): stored in the config itself,
//! so it syncs through backups, exports and catalogs and means the same to every OpenVPN. Only top-level directive
//! lines are read or written (never a block's content or a comment); the line ends of the text are kept.

use crate::swift_str::trim_space_tab;
use crate::validators::OpenVPNValidator;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Routing {
    /// No routing line: the server's push decides (default; macOS' behaviour).
    ServerDecides,
    /// `redirect-gateway` (without `!ipv4`).
    Always,
    /// `pull-filter ignore "redirect-gateway"` or `route-nopull`.
    Never,
}

/// The text Never writes.
pub const NEVER_LINE: &str = "pull-filter ignore \"redirect-gateway\"";

/// What one top-level line says about routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineKind {
    /// `redirect-gateway …`: `all` = without `!ipv4`; `ipv6` = with the `ipv6` flag.
    Redirect { all: bool, ipv6: bool },
    /// `route-nopull` or `pull-filter ignore "redirect-gateway"`.
    Never,
}

/// The routing meaning of a directive's tokens (name already lower-cased by the caller).
fn kind_of(tokens: &[String]) -> Option<LineKind> {
    match tokens.first()?.as_str() {
        "redirect-gateway" => {
            let flags = &tokens[1..];
            Some(LineKind::Redirect {
                all: !flags.iter().any(|f| f == "!ipv4"),
                ipv6: flags.iter().any(|f| f == "ipv6"),
            })
        }
        "route-nopull" => Some(LineKind::Never),
        "pull-filter" if tokens.len() == 3 && tokens[1] == "ignore" && tokens[2] == "redirect-gateway" => {
            Some(LineKind::Never)
        }
        _ => None,
    }
}

/// Every top-level line of `text` as `(byte range including its line end, routing kind)`. Blocks
/// (`<tag>…</tag>`, `<connection>…</connection>`) and comments are skipped, as the validator reads them.
fn lines(text: &str) -> Vec<(std::ops::Range<usize>, Option<LineKind>)> {
    let mut out = Vec::new();
    // A data block (its content skipped) and a `<connection>` block (which may hold a data block itself).
    let mut in_block = false;
    let mut in_connection = false;
    let mut start = 0;
    while start < text.len() {
        let end = text[start..].find('\n').map_or(text.len(), |i| start + i + 1);
        let raw = text[start..end].trim_end_matches('\n');
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        let line = trim_space_tab(raw);
        let mut kind = None;
        if in_block {
            if line.starts_with("</") {
                in_block = false;
            }
        } else if in_connection {
            if line.starts_with("</") {
                in_connection = false;
            } else if is_open_tag(line) {
                in_block = true;
            }
        } else if is_open_tag(line) {
            if line.eq_ignore_ascii_case("<connection>") {
                in_connection = true;
            } else {
                in_block = true;
            }
        } else if !line.is_empty() && !line.starts_with('#') && !line.starts_with(';') {
            kind = directive_tokens(line).as_deref().and_then(kind_of);
        }
        out.push((start..end, kind));
        start = end;
    }
    out
}

fn is_open_tag(line: &str) -> bool {
    line.len() > 2
        && line.starts_with('<')
        && line.ends_with('>')
        && line[1..line.len() - 1].bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// The line's tokens with the directive name normalized (lower-case, no `--`); `None` for a line OpenVPN's
/// tokenizer (as the validator mirrors it) rejects.
fn directive_tokens(line: &str) -> Option<Vec<String>> {
    let mut tokens: Vec<String> = OpenVPNValidator::tokenize(line)?.into_iter().map(|t| t.text).collect();
    let name = OpenVPNValidator::directive_name(tokens.first()?)?;
    tokens[0] = name;
    Some(tokens)
}

/// What the config says (the last routing line wins, as OpenVPN applies options in order).
pub fn read(text: &str) -> Routing {
    let mut routing = Routing::ServerDecides;
    for (_, kind) in lines(text) {
        match kind {
            Some(LineKind::Redirect { all: true, .. }) => routing = Routing::Always,
            Some(LineKind::Redirect { all: false, .. }) => routing = Routing::ServerDecides,
            Some(LineKind::Never) => routing = Routing::Never,
            None => {}
        }
    }
    routing
}

/// The text with exactly `routing`'s line: every routing line removed, then `redirect-gateway def1` (plus ` ipv6`
/// when a removed `redirect-gateway` line had it) or `pull-filter ignore "redirect-gateway"` appended at the end
/// (after a trailing newline is ensured). `ServerDecides` only removes. Unchanged text if it already says so.
pub fn write(text: &str, routing: Routing) -> String {
    if read(text) == routing {
        return text.to_string();
    }
    let newline = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut out = String::with_capacity(text.len() + 48);
    let mut ipv6 = false;
    for (range, kind) in lines(text) {
        match kind {
            Some(LineKind::Redirect { ipv6: v6, .. }) => ipv6 |= v6,
            Some(LineKind::Never) => {}
            None => out.push_str(&text[range]),
        }
    }
    let line = match routing {
        Routing::ServerDecides => return out,
        Routing::Always if ipv6 => "redirect-gateway def1 ipv6",
        Routing::Always => "redirect-gateway def1",
        Routing::Never => NEVER_LINE,
    };
    if !out.is_empty() && !out.ends_with('\n') {
        out.push_str(newline);
    }
    out.push_str(line);
    out.push_str(newline);
    out
}
