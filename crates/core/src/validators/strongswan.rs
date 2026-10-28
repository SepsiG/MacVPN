//! Default-deny strongSwan (`swanctl.conf`) validation (port of `StrongSwanValidator`). The root layer runs it for
//! validation and for `--swan-names`. Per-section key allowlists based on the installed `swanctl.conf(5)`
//! (connections, local/remote, children, secrets, pools, authorities).
//!
//! Per line: control character -> error; any `\` (0x5C) -> "Character not allowed: \"; an odd number of `"` in
//! the line -> "Unbalanced quote (multi-line strings are not allowed)" (the rest of the line is skipped); the
//! comment cut off quote-aware (`#` starts a comment only outside `"`, no escapes); a trimmed empty line skipped.
//! The rest follows the strongSwan settings syntax: `name {` opens a section, `}` closes, `name = value` is a key
//! (the value runs to the end of the line or the next `}`, `"…"` may quote). For sections and keys:
//! - `include` (as a key or a section) -> "Forbidden: include"; `updown`, `file`, `crl_uris`, `ocsp_uris` ->
//!   "Forbidden key";
//! - the section type does not allow such a subsection/key -> "Section/Key not allowed" (the name only for a known
//!   keyword);
//! - the values of `certs`, `cacerts`, `pubkeys`, `cacert` may only be plain file name lists (no `/`, `..`,
//!   leading `.`): swanctl reads these from its own x509/pubkey directories; no `file:` URI in any value;
//! - a standalone `=` or an unquoted `{` in a value -> "Invalid line" (suspected key smuggling).
//!
//! At most one message per line. A section open at the end -> "Unclosed section"; an unexpected `}` -> error.
//! A `connections` section with a `children` section in it is required.

use super::{ConfigValidator, control_character_message, has_control_character, matches, numbered_lines};
use crate::l10n::{self, Arg};
use crate::models::ValidationIssue;
use crate::swift_str::{self, ascii_lowercased, trim_space_tab};
use regex::Regex;
use std::collections::HashSet;
use std::sync::LazyLock;

/// Section types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Context {
    Root,
    Connections,
    Conn,
    Local,
    Remote,
    Certificate,
    Children,
    Child,
    Secrets,
    SharedSecret,
    PrivateKeySecret,
    TokenSecret,
    Pools,
    Pool,
    Authorities,
    Authority,
    /// Inside a section that is not allowed: already an error, only the braces and the forbidden names are tracked.
    Rejected,
}

const CONN_KEYS: &[&str] = &[
    "version",
    "local_addrs",
    "remote_addrs",
    "local_port",
    "remote_port",
    "proposals",
    "vips",
    "aggressive",
    "pull",
    "dscp",
    "encap",
    "mobike",
    "dpd_delay",
    "dpd_timeout",
    "fragmentation",
    "childless",
    "send_certreq",
    "send_cert",
    "ocsp",
    "ppk_id",
    "ppk_required",
    "keyingtries",
    "unique",
    "reauth_time",
    "rekey_time",
    "over_time",
    "rand_time",
    "pools",
    "if_id_in",
    "if_id_out",
    "mediation",
    "mediated_by",
    "mediation_peer",
];
const LOCAL_KEYS: &[&str] = &["round", "certs", "pubkeys", "auth", "id", "eap_id", "aaa_id", "xauth_id"];
const REMOTE_KEYS: &[&str] =
    &["round", "id", "eap_id", "groups", "cert_policy", "certs", "cacerts", "ca_id", "pubkeys", "revocation", "auth"];
const CERTIFICATE_KEYS: &[&str] = &["handle", "slot", "module"];
const CHILD_KEYS: &[&str] = &[
    "ah_proposals",
    "esp_proposals",
    "sha256_96",
    "local_ts",
    "remote_ts",
    "rekey_time",
    "life_time",
    "rand_time",
    "rekey_bytes",
    "life_bytes",
    "rand_bytes",
    "rekey_packets",
    "life_packets",
    "rand_packets",
    "hostaccess",
    "mode",
    "policies",
    "policies_fwd_out",
    "dpd_action",
    "ipcomp",
    "inactivity",
    "reqid",
    "priority",
    "interface",
    "mark_in",
    "mark_in_sa",
    "mark_out",
    "set_mark_in",
    "set_mark_out",
    "if_id_in",
    "if_id_out",
    "label",
    "label_mode",
    "tfc_padding",
    "replay_window",
    "per_cpu_sas",
    "hw_offload",
    "copy_df",
    "copy_ecn",
    "copy_dscp",
    "icmp",
    "start_action",
    "close_action",
];
const TOKEN_KEYS: &[&str] = &["handle", "slot", "module", "pin"];
const POOL_KEYS: &[&str] =
    &["addrs", "dns", "nbns", "dhcp", "netmask", "server", "subnet", "split_include", "split_exclude"];
const AUTHORITY_KEYS: &[&str] = &["cacert", "handle", "slot", "module", "cert_uri_base"];
/// Keys referring to a file root opens: only a file name (relative to swanctl's own directories).
const FILE_NAME_KEYS: &[&str] = &["certs", "cacerts", "pubkeys", "cacert"];
/// Forbidden keys (in any section; as a section name too): command execution, arbitrary file, network URI.
pub const FORBIDDEN_KEYS: &[&str] = &["updown", "file", "crl_uris", "ocsp_uris"];
const SECTION_KEYWORDS: &[&str] = &["connections", "children", "secrets", "pools", "authorities", "local", "remote"];
const NAME_PATTERN: &str = "^[A-Za-z0-9_.-]+$";

/// The names a message may quote (known keywords only, never the config's free text).
static KNOWN_NAMES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    let mut s: HashSet<&'static str> = HashSet::new();
    for list in
        [CONN_KEYS, LOCAL_KEYS, REMOTE_KEYS, CERTIFICATE_KEYS, CHILD_KEYS, TOKEN_KEYS, POOL_KEYS, AUTHORITY_KEYS]
    {
        s.extend(list.iter().copied());
    }
    s.extend(SECTION_KEYWORDS.iter().copied());
    s.extend(["secret", "id"]);
    s
});

fn subsection(name: &str, context: Context) -> Option<Context> {
    let starts = |p: &str| swift_str::has_prefix(name, p);
    match context {
        Context::Root => match name {
            "connections" => Some(Context::Connections),
            "secrets" => Some(Context::Secrets),
            "pools" => Some(Context::Pools),
            "authorities" => Some(Context::Authorities),
            _ => None,
        },
        Context::Connections => Some(Context::Conn),
        Context::Conn => {
            if name == "children" {
                Some(Context::Children)
            } else if starts("local") {
                Some(Context::Local)
            } else if starts("remote") {
                Some(Context::Remote)
            } else {
                None
            }
        }
        Context::Local => starts("cert").then_some(Context::Certificate),
        Context::Remote => (starts("cert") || starts("cacert")).then_some(Context::Certificate),
        Context::Children => Some(Context::Child),
        Context::Secrets => {
            if ["eap", "xauth", "ntlm", "ike", "ppk"].iter().any(|p| starts(p)) {
                Some(Context::SharedSecret)
            } else if ["private", "rsa", "ecdsa", "pkcs8", "pkcs12"].iter().any(|p| starts(p)) {
                Some(Context::PrivateKeySecret)
            } else {
                starts("token").then_some(Context::TokenSecret)
            }
        }
        Context::Pools => Some(Context::Pool),
        Context::Authorities => Some(Context::Authority),
        Context::Certificate
        | Context::Child
        | Context::SharedSecret
        | Context::PrivateKeySecret
        | Context::TokenSecret
        | Context::Pool
        | Context::Authority
        | Context::Rejected => None,
    }
}

fn allows(key: &str, context: Context) -> bool {
    match context {
        Context::Conn => CONN_KEYS.contains(&key),
        Context::Local => LOCAL_KEYS.contains(&key),
        Context::Remote => REMOTE_KEYS.contains(&key),
        Context::Certificate => CERTIFICATE_KEYS.contains(&key),
        Context::Child => CHILD_KEYS.contains(&key),
        Context::SharedSecret => key == "secret" || swift_str::has_prefix(key, "id"),
        Context::PrivateKeySecret => key == "secret",
        Context::TokenSecret => TOKEN_KEYS.contains(&key),
        Context::Pool => POOL_KEYS.contains(&key) || matches(key, "^[0-9]{1,5}$"),
        Context::Authority => AUTHORITY_KEYS.contains(&key),
        Context::Root
        | Context::Connections
        | Context::Children
        | Context::Secrets
        | Context::Pools
        | Context::Authorities
        | Context::Rejected => false,
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct StrongSwanValidator;

impl ConfigValidator for StrongSwanValidator {
    fn validate(&self, text: &str) -> Vec<ValidationIssue> {
        let mut issues = Vec::new();
        let mut stack: Vec<Section> = Vec::new();
        let (mut has_connections, mut has_children) = (false, false);
        for (line_no, raw_line) in numbered_lines(text) {
            if has_control_character(raw_line) {
                issues.push(ValidationIssue::new(line_no, control_character_message()));
                continue;
            }
            if raw_line.as_bytes().contains(&0x5C) {
                issues.push(ValidationIssue::new(line_no, l10n::tr("Character not allowed: \\", &[])));
                continue;
            }
            if raw_line.bytes().filter(|&b| b == 0x22).count() % 2 != 0 {
                issues.push(ValidationIssue::new(
                    line_no,
                    l10n::tr("Unbalanced quote (multi-line strings are not allowed)", &[]),
                ));
                continue;
            }
            let line = strip_comment(raw_line);
            if line.is_empty() {
                continue;
            }
            let mut scanner = LineScanner { bytes: line.as_bytes(), line: line_no, i: 0, error: None, on_key: None };
            scanner.run(&mut stack, &mut has_connections, &mut has_children);
            if let Some(message) = scanner.error {
                issues.push(ValidationIssue::new(line_no, message));
            }
        }
        for open in stack.iter().rev() {
            issues.push(ValidationIssue::new(open.line, l10n::tr("Unclosed section", &[])));
        }
        if !has_connections {
            issues.push(ValidationIssue::new(0, l10n::tr("Missing connections block", &[])));
        }
        if !has_children {
            issues.push(ValidationIssue::new(0, l10n::tr("Missing children block", &[])));
        }
        issues
    }
}

/// An open section: its type, the line that opened it and its name (`connections`, a connection's name,
/// `local-1`, …).
pub(crate) struct Section {
    pub(crate) context: Context,
    pub(crate) line: i64,
    pub(crate) name: String,
}

/// What the scanner reports to a visitor, with the open sections (innermost last).
pub(crate) enum Visit<'v> {
    /// The innermost section was just opened (an allowed one; rejected sections are not reported).
    Open,
    /// An accepted `key = value` of the innermost section: the key and the value items.
    Key(&'v str, &'v [String]),
}

/// See [`LineScanner::on_key`].
type KeyVisitor<'a> = dyn FnMut(&[Section], Visit<'_>) + 'a;

/// Byte-level processing of one line (comment removed, even quotes, no backslash); the first error is kept.
struct LineScanner<'a> {
    bytes: &'a [u8],
    line: i64,
    i: usize,
    error: Option<String>,
    /// Called with every allowed section opened and every accepted `key = value`.
    on_key: Option<&'a mut KeyVisitor<'a>>,
}

impl LineScanner<'_> {
    fn fail(&mut self, message: String) {
        if self.error.is_none() {
            self.error = Some(message);
        }
    }

    fn current(&self) -> Option<u8> {
        self.bytes.get(self.i).copied()
    }

    fn skip_space(&mut self) {
        while let Some(c) = self.current()
            && (c == 0x20 || c == 0x09)
        {
            self.i += 1;
        }
    }

    fn is_delimiter(c: u8) -> bool {
        c == 0x20 || c == 0x09 || c == 0x7B || c == 0x7D || c == 0x3D || c == 0x22
    }

    fn text(&self, start: usize, end: usize) -> String {
        String::from_utf8_lossy(&self.bytes[start..end]).into_owned()
    }

    fn run(&mut self, stack: &mut Vec<Section>, has_connections: &mut bool, has_children: &mut bool) {
        loop {
            self.skip_space();
            let Some(c) = self.current() else { return };
            if c == 0x7D {
                // }
                self.i += 1;
                if stack.pop().is_none() {
                    self.fail(l10n::tr("Unexpected closing brace", &[]));
                }
                continue;
            }
            let start = self.i;
            while let Some(c) = self.current()
                && !Self::is_delimiter(c)
            {
                self.i += 1;
            }
            let name = self.text(start, self.i);
            let lower = ascii_lowercased(&name);
            self.skip_space();
            let context = stack.last().map_or(Context::Root, |s| s.context);
            let forbidden_message = if swift_str::eq(&lower, "include") {
                Some(l10n::tr("Forbidden: include", &[]))
            } else if FORBIDDEN_KEYS.iter().any(|k| swift_str::eq(k, &lower)) {
                Some(l10n::tr("Forbidden key: %@", &[Arg::Str(&lower)]))
            } else {
                None
            };
            let next = self.current();
            if name.is_empty() || !matches(&name, NAME_PATTERN) || !matches!(next, Some(0x7B) | Some(0x3D)) {
                self.fail(forbidden_message.unwrap_or_else(|| l10n::tr("Invalid line", &[])));
                self.recover(stack);
                return;
            }
            self.i += 1;
            if next == Some(0x7B) {
                // {
                let mut sub = Context::Rejected;
                if let Some(m) = forbidden_message {
                    self.fail(m);
                } else if matches!(context, Context::Connections | Context::Children) && name.starts_with('-') {
                    // A connection / child name is passed to `swanctl --initiate`: no option-like name.
                    self.fail(l10n::tr("A connection or child name must not start with \"-\"", &[]));
                } else if let Some(s) = subsection(&name, context) {
                    sub = s;
                    if s == Context::Connections {
                        *has_connections = true;
                    }
                    if s == Context::Children {
                        *has_children = true;
                    }
                } else if context != Context::Rejected {
                    self.fail(if KNOWN_NAMES.contains(name.as_str()) {
                        l10n::tr("Section not allowed: %@", &[Arg::Str(&name)])
                    } else {
                        l10n::tr("Section not allowed", &[])
                    });
                }
                stack.push(Section { context: sub, line: self.line, name });
                if sub != Context::Rejected
                    && let Some(on_key) = self.on_key.as_mut()
                {
                    on_key(stack, Visit::Open);
                }
                continue;
            }
            // name = value
            let mut key_ok = false;
            if let Some(m) = forbidden_message {
                self.fail(m);
            } else if context != Context::Rejected {
                if allows(&name, context) {
                    key_ok = true;
                } else {
                    self.fail(if KNOWN_NAMES.contains(name.as_str()) {
                        l10n::tr("Key not allowed: %@", &[Arg::Str(&name)])
                    } else {
                        l10n::tr("Key not allowed", &[])
                    });
                }
            }
            let Some(items) = self.read_value() else {
                self.fail(l10n::tr("Invalid line", &[]));
                self.recover(stack);
                return;
            };
            if key_ok && let Some(on_key) = self.on_key.as_mut() {
                on_key(stack, Visit::Key(&name, &items));
            }
            if items.iter().any(|item| swift_str::contains(&ascii_lowercased(item), "file:")) {
                self.fail(l10n::tr("Forbidden: file: URI", &[]));
            } else if key_ok && FILE_NAME_KEYS.contains(&name.as_str()) {
                let joined = items.join(" ");
                let names = swift_str::split(&joined, ",", usize::MAX, false);
                let ok = names
                    .into_iter()
                    .map(trim_space_tab)
                    .all(|n| matches(n, "^[A-Za-z0-9_+@][A-Za-z0-9_.+@-]*$") && !swift_str::contains(n, ".."));
                if !ok {
                    self.fail(l10n::tr("Only a file name is allowed, no path: %@", &[Arg::Str(&name)]));
                }
            }
        }
    }

    /// The value after `=`, to the end of the line or the next (unquoted) `}`. `None`: a standalone `=` or an
    /// unquoted `{` in the value (suspicious, so an error).
    fn read_value(&mut self) -> Option<Vec<String>> {
        let mut items = Vec::new();
        loop {
            self.skip_space();
            let c = match self.current() {
                None | Some(0x7D) => return Some(items),
                Some(c) => c,
            };
            if c == 0x22 {
                self.i += 1;
                let start = self.i;
                while let Some(q) = self.current()
                    && q != 0x22
                {
                    self.i += 1;
                }
                items.push(self.text(start, self.i));
                self.i += 1;
                continue;
            }
            let start = self.i;
            while let Some(q) = self.current()
                && q != 0x20
                && q != 0x09
                && q != 0x7D
                && q != 0x22
            {
                self.i += 1;
            }
            let word = self.text(start, self.i);
            if word == "=" || swift_str::has_prefix(&word, "=") || swift_str::contains(&word, "{") {
                return None;
            }
            items.push(word);
        }
    }

    /// After an error only the braces are tracked in the rest of the line (outside quotes), so the structure does
    /// not slip.
    fn recover(&mut self, stack: &mut Vec<Section>) {
        let mut in_quote = false;
        while let Some(c) = self.current() {
            self.i += 1;
            if c == 0x22 {
                in_quote = !in_quote;
            }
            if in_quote {
                continue;
            }
            if c == 0x7B {
                stack.push(Section { context: Context::Rejected, line: self.line, name: String::new() });
            }
            if c == 0x7D {
                stack.pop();
            }
        }
    }
}

impl StrongSwanValidator {
    /// The `auth` values of the connections' `local…` sections (comments removed, parsed like
    /// [`ConfigValidator::validate`]; keys in rejected sections are skipped).
    pub(crate) fn local_auth_values(text: &str) -> Vec<String> {
        let mut values = Vec::new();
        Self::visit(text, &mut |path: &[Section], event: Visit<'_>| {
            if let Visit::Key("auth", items) = event
                && path.last().is_some_and(|s| s.context == Context::Local)
            {
                values.push(items.join(" "));
            }
        });
        values
    }

    /// Calls `visit` with every allowed section opened and every accepted `key = value` of the text, parsed like
    /// [`ConfigValidator::validate`] (comments removed; lines with an error, rejected sections and their keys are
    /// skipped). Meant for an already validated text.
    pub(crate) fn visit(text: &str, visit: &mut dyn FnMut(&[Section], Visit<'_>)) {
        let mut stack: Vec<Section> = Vec::new();
        let (mut has_connections, mut has_children) = (false, false);
        let mut forward = |path: &[Section], event: Visit<'_>| visit(path, event);
        for (line_no, raw_line) in numbered_lines(text) {
            if has_control_character(raw_line)
                || raw_line.as_bytes().contains(&0x5C)
                || raw_line.bytes().filter(|&b| b == 0x22).count() % 2 != 0
            {
                continue;
            }
            let line = strip_comment(raw_line);
            if line.is_empty() {
                continue;
            }
            let mut scanner =
                LineScanner { bytes: line.as_bytes(), line: line_no, i: 0, error: None, on_key: Some(&mut forward) };
            scanner.run(&mut stack, &mut has_connections, &mut has_children);
        }
    }

    /// `<section>.<name>` of every named section directly under `connections`, `secrets`, `pools` and
    /// `authorities`, in order (parsed like [`Self::visit`]). These names are global in charon: two configs loaded
    /// together must not share one (strongSwan's settings parser merges sections of the same name).
    pub fn section_names(text: &str) -> Vec<String> {
        let mut names = Vec::new();
        Self::visit(text, &mut |path: &[Section], event: Visit<'_>| {
            if let (Visit::Open, [top, named]) = (event, path)
                && matches!(
                    top.context,
                    Context::Connections | Context::Secrets | Context::Pools | Context::Authorities
                )
            {
                names.push(format!("{}.{}", top.name, named.name));
            }
        });
        names
    }

    /// The remote identities of connection `conn` (sorted, unique) if each of its `remote…` sections names one
    /// concrete identity (one value, no `*`, no `%…`, no subnet or address range); empty otherwise. charon looks a
    /// secret up with the configured remote id (or the one the peer sent, which must match it), so a secret may
    /// be bound to exactly these ids; with a wildcard or no id it is looked up with `%any` or a pattern.
    pub fn remote_ids(text: &str, conn: &str) -> Vec<String> {
        static RANGE: LazyLock<Regex> =
            LazyLock::new(|| Regex::new("^[0-9A-Fa-f:.]+-[0-9A-Fa-f:.]+$").expect("valid pattern"));
        let concrete = |v: &str| {
            !v.is_empty() && !v.contains('*') && !v.starts_with('%') && !v.contains('/') && !RANGE.is_match(v)
        };
        let mut rounds: Vec<Option<String>> = Vec::new();
        Self::visit(text, &mut |path: &[Section], event: Visit<'_>| {
            let [_, c, r] = path else { return };
            if c.context != Context::Conn || c.name != conn || r.context != Context::Remote {
                return;
            }
            match event {
                Visit::Open => rounds.push(None),
                Visit::Key("id", items) => {
                    if let Some(last) = rounds.last_mut() {
                        *last = match items {
                            [one] if concrete(one) => Some(one.clone()),
                            _ => None,
                        };
                    }
                }
                Visit::Key(..) => {}
            }
        });
        if rounds.is_empty() || rounds.iter().any(Option::is_none) {
            return Vec::new();
        }
        let mut ids: Vec<String> = rounds.into_iter().flatten().collect();
        ids.sort();
        ids.dedup();
        ids
    }

    /// Whether connection `conn` sets `key` itself (a key directly in its section, parsed like [`Self::visit`]).
    pub fn conn_sets(text: &str, conn: &str, key: &str) -> bool {
        let mut found = false;
        Self::visit(text, &mut |path: &[Section], event: Visit<'_>| {
            if let ([_, c], Visit::Key(k, _)) = (path, event)
                && c.context == Context::Conn
                && c.name == conn
                && k == key
            {
                found = true;
            }
        });
        found
    }

    /// The first connection and the first child name (for `swanctl --initiate --child`).
    pub fn names(text: &str) -> Option<(String, String)> {
        static HEADER: LazyLock<Regex> =
            LazyLock::new(|| Regex::new("^([A-Za-z0-9_.-]+)[ \\t]*\\{").expect("valid pattern"));
        let (mut in_connections, mut in_children) = (false, false);
        let (mut connection, mut child): (Option<String>, Option<String>) = (None, None);
        for (_, raw_line) in numbered_lines(text) {
            let line = strip_comment(raw_line);
            if matches(&line, "^connections[ \\t]*\\{") {
                in_connections = true;
                continue;
            }
            if matches(&line, "^children[ \\t]*\\{") {
                in_children = true;
                continue;
            }
            // NSRegularExpression: scalar-based, not Character-based.
            let Some(caps) = HEADER.captures(&line) else { continue };
            let name = caps[1].to_string();
            if in_connections && connection.is_none() {
                connection = Some(name.clone());
            }
            if in_children && child.is_none() {
                child = Some(name);
            }
        }
        let (connection, child) = (connection?, child?);
        // Never hand an option-like name to `swanctl --initiate --child`.
        if connection.starts_with('-') || child.starts_with('-') {
            return None;
        }
        Some((connection, child))
    }
}

/// `#` starts a comment only outside quotes (`"`). No escapes.
pub(crate) fn strip_comment(line: &str) -> String {
    let mut in_quote = false;
    let mut out: Vec<u8> = Vec::new();
    for &byte in line.as_bytes() {
        if byte == 0x22 {
            in_quote = !in_quote;
        }
        if byte == 0x23 && !in_quote {
            break;
        }
        out.push(byte);
    }
    trim_space_tab(&String::from_utf8_lossy(&out)).to_string()
}
