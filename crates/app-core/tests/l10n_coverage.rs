//! Every text the Rust side translates is in the EN/HU table (`crates/core/l10n/strings.json`) with a Hungarian
//! text, across the whole workspace: the core, the root helper, the platform layer, the app logic and the Tauri
//! shell. A missing key would silently stay English. The web UI's own texts are checked by `app/ui`'s `npm test`
//! (`l10n.test.ts`).
//!
//! A literal key (`tr("…")`, `tr_in(lang, "…")`, `tr1("…", …)`, also an `if … { "A" } else { "B" }` argument) is
//! checked directly. A key passed through a variable must be listed in [`VARIABLE_KEYS`] with the place its
//! literals come from, so a new one cannot slip through unchecked.

use macvpn_core::l10n;
use regex::Regex;
use std::path::{Path, PathBuf};

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

fn rust_sources() -> Vec<PathBuf> {
    let root = workspace();
    let mut dirs: Vec<PathBuf> =
        ["crates/core/src", "crates/mvpn/src", "crates/platform-mac/src", "crates/app-core/src", "app/src-tauri/src"]
            .iter()
            .map(|d| root.join(d))
            .collect();
    let mut files = Vec::new();
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

fn unescape(literal: &str) -> String {
    literal.replace("\\n", "\n").replace("\\\"", "\"").replace("\\\\", "\\")
}

/// The literals in `text` (Rust string literals without raw strings, which the call sites do not use).
fn literals(text: &str) -> Vec<String> {
    let re = Regex::new(r#""((?:[^"\\]|\\.)*)""#).unwrap();
    re.captures_iter(text).map(|c| unescape(&c[1])).collect()
}

/// The literals a `match` evaluates to (`… => "…"`, `… => Ok("…")`, `… => { "…" }`), not its patterns.
fn arm_values(text: &str) -> Vec<String> {
    let re = Regex::new(r#"=>\s*(?:Ok\(|\{)?\s*"((?:[^"\\]|\\.)*)""#).unwrap();
    re.captures_iter(text).map(|c| unescape(&c[1])).collect()
}

/// The text of a call's key argument: from after `(` to the first top-level `,` (or `)`), with nested brackets.
fn key_argument(source: &str, open: usize, skip_first: bool) -> &str {
    let bytes = source.as_bytes();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut start = open + 1;
    let mut skipped = !skip_first;
    let mut i = open + 1;
    while i < bytes.len() {
        let c = bytes[i];
        if in_string {
            if c == b'\\' {
                i += 1;
            } else if c == b'"' {
                in_string = false;
            }
        } else {
            match c {
                b'"' => in_string = true,
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' if depth > 0 => depth -= 1,
                b')' => return &source[start..i],
                b',' if depth == 0 => {
                    if skipped {
                        return &source[start..i];
                    }
                    skipped = true;
                    start = i + 1;
                }
                _ => {}
            }
        }
        i += 1;
    }
    &source[start..]
}

/// Keys passed through a variable: (file name, variable) → where the literals are taken from.
enum KeySource {
    /// The body of this function in the same file.
    Function(&'static str),
    /// The literal given as this function's last argument at its call sites in the same file.
    CallArgument(&'static str),
    /// The `match` that assigns the variable just before the call (in the same function).
    MatchBefore,
    /// The file's `&str` constants and `Err("…")` literals (the keys handed around as `&'static str`).
    Constants,
    /// A wrapper's definition: its callers pass literals, checked as calls of the wrapper.
    Wrapper,
}

const VARIABLE_KEYS: &[(&str, &str, KeySource)] = &[
    ("commands.rs", "title", KeySource::Function("window_title")),
    ("backup.rs", "title", KeySource::Function("window_title")),
    ("system.rs", "prefix", KeySource::CallArgument("installer_message")),
    ("login_item.rs", "key", KeySource::MatchBefore),
    ("update_installer.rs", "key", KeySource::MatchBefore),
    ("openvpn.rs", "key", KeySource::MatchBefore),
    ("respond.rs", "key", KeySource::Constants),
    ("openvpn.rs", "self.reason_key", KeySource::Constants),
    ("temp_dir.rs", "key", KeySource::Wrapper),
    ("l10n.rs", "key", KeySource::Wrapper),
    ("ctx.rs", "key", KeySource::Wrapper),
];

fn function_body<'a>(source: &'a str, name: &str) -> &'a str {
    let start = source.find(&format!("fn {name}(")).unwrap_or_else(|| panic!("no fn {name}"));
    let open = start + source[start..].find('{').unwrap();
    let mut depth = 0;
    for (i, c) in source[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[open..open + i];
                }
            }
            _ => {}
        }
    }
    &source[open..]
}

fn variable_keys(file: &str, source: &str, variable: &str, at: usize) -> Option<Vec<String>> {
    let (_, _, how) = VARIABLE_KEYS.iter().find(|(f, v, _)| *f == file && *v == variable)?;
    Some(match how {
        KeySource::Function(name) => arm_values(function_body(source, name)),
        KeySource::CallArgument(name) => {
            let re = Regex::new(&format!(r#"\b{name}\([^()"]*,\s*"((?:[^"\\]|\\.)*)"\s*\)"#)).unwrap();
            re.captures_iter(source).map(|c| unescape(&c[1])).collect()
        }
        KeySource::MatchBefore => {
            let start = source[..at].rfind(&format!("let {variable} = match")).expect("no match before the call");
            arm_values(&source[start..at])
        }
        KeySource::Constants => {
            // Not the regex patterns (`…_PATTERN`).
            let re = Regex::new(r#"(?:const ([A-Z_0-9]+): &str =\s*|Err\()"((?:[^"\\]|\\.)*)""#).unwrap();
            re.captures_iter(source)
                .filter(|c| c.get(1).is_none_or(|n| !n.as_str().ends_with("PATTERN")))
                .map(|c| unescape(&c[2]))
                .collect()
        }
        KeySource::Wrapper => Vec::new(),
    })
}

#[test]
fn every_rust_text_is_in_the_table() {
    let call = Regex::new(r"\b(tr|tr_in|tr1)\(").unwrap();
    let ident = Regex::new(r"^\s*([a-z_][a-z0-9_.]*)\s*$").unwrap();
    let mut checked = 0;
    let mut missing = Vec::new();
    let mut unknown = Vec::new();
    for path in rust_sources() {
        let source = std::fs::read_to_string(&path).unwrap();
        let file = path.file_name().unwrap().to_string_lossy().into_owned();
        for m in call.find_iter(&source) {
            let before = &source[..m.start()];
            // Definitions (`fn tr(`) and comments are not calls.
            let line = &before[before.rfind('\n').map_or(0, |i| i + 1)..];
            if before.trim_end().ends_with("fn") || line.trim_start().starts_with("//") {
                continue;
            }
            let name = m.as_str().trim_end_matches('(');
            let argument = key_argument(&source, m.end() - 1, name == "tr_in");
            let keys = if argument.contains('"') {
                literals(argument)
            } else if let Some(c) = ident.captures(argument) {
                match variable_keys(&file, &source, &c[1], m.start()) {
                    Some(keys) => keys,
                    None => {
                        unknown.push(format!("{}: {}({}…)", path.display(), name, argument.trim()));
                        continue;
                    }
                }
            } else {
                unknown.push(format!("{}: {}({}…)", path.display(), name, argument.trim()));
                continue;
            };
            for key in keys {
                checked += 1;
                if l10n::hungarian(&key).is_none() {
                    missing.push(format!("{}: {key:?}", path.display()));
                }
            }
        }
    }
    assert!(unknown.is_empty(), "keys through a variable, add them to VARIABLE_KEYS: {unknown:#?}");
    assert!(missing.is_empty(), "no Hungarian text: {missing:#?}");
    assert!(checked > 300, "only {checked} keys found");
}
