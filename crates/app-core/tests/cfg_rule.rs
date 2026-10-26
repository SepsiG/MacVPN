//! The platform rule of spec 3, enforced on the source (plan Task 16):
//!
//! - An OS `cfg` (`cfg(target_os …)`, `cfg(unix)`, `cfg(windows)`, their `not(…)`, `any(…)` and `all(…)`
//!   combinations, `cfg_attr(…)` and `cfg!(…)` with one of them, or `target_os =` anywhere in code) appears in
//!   production code only in `crates/core/src/fsx/`, `crates/platform-mac/`, `crates/platform-win/`,
//!   `crates/winsys/`, `crates/helper/src/{macos,windows}/`, the helper's binary entry `crates/helper/src/main.rs` and
//!   `app/src-tauri/src/platform/`. A `cfg` whose predicate is a macro metavariable (`cfg($m)`) counts as one,
//!   because the scan cannot see what it expands to; so do `#[path = …]` and `include!(…)`, which pull in code
//!   from places the scan does not read.
//! - `unsafe`, and an `allow`/`expect`/`warn` of the `unsafe_code` lint, appear only in `crates/platform-mac`,
//!   `crates/platform-win`, `crates/winsys` and `crates/helper`.
//!
//! Scanned: `crates/*/src` and `app/src-tauri/src`. Comments and string literals are not code. Tests are outside the
//! cfg rule (see the plan's "Resolved points"): an item under `#[cfg(test)]` (the unit test module) is skipped for
//! it, but not for `unsafe`. `#[cfg(debug_assertions)]`, `cfg(test)`, `cfg(feature = …)` and `cfg!(dev)` are not OS
//! `cfg`s.

use std::fs;
use std::path::{Path, PathBuf};

const CFG_ALLOWED: &[&str] = &[
    "crates/core/src/fsx/",
    "crates/platform-mac/",
    "crates/platform-win/",
    "crates/winsys/",
    "crates/helper/src/macos/",
    "crates/helper/src/windows/",
    "crates/helper/src/main.rs",
    "app/src-tauri/src/platform/",
];

const UNSAFE_ALLOWED: &[&str] = &["crates/platform-mac/", "crates/platform-win/", "crates/winsys/", "crates/helper/"];

/// The words that make a `cfg` predicate an OS one.
const OS_WORDS: &[&str] = &["target_os", "unix", "windows", "target_family", "target_vendor", "target_env"];

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

/// Every `.rs` file below the scanned roots, as (path relative to the workspace with `/`, text).
fn sources() -> Vec<(String, String)> {
    let root = workspace();
    let mut dirs = vec![root.join("app/src-tauri/src")];
    for entry in fs::read_dir(root.join("crates")).unwrap() {
        let src = entry.unwrap().path().join("src");
        if src.is_dir() {
            dirs.push(src);
        }
    }
    let mut files = Vec::new();
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let rel = path.strip_prefix(&root).unwrap();
                let rel = rel.components().map(|c| c.as_os_str().to_string_lossy()).collect::<Vec<_>>().join("/");
                files.push((rel, fs::read_to_string(&path).unwrap()));
            }
        }
    }
    files.sort();
    assert!(files.len() > 50, "the scan found only {} files", files.len());
    files
}

/// The code with every comment and every string and character literal blanked out (newlines kept, so the line
/// numbers stay right).
fn code_only(text: &str) -> Vec<char> {
    let s: Vec<char> = text.chars().collect();
    let mut out = s.clone();
    let blank = |out: &mut Vec<char>, from: usize, to: usize| {
        for c in &mut out[from..to] {
            if *c != '\n' {
                *c = ' ';
            }
        }
    };
    let mut i = 0;
    while i < s.len() {
        let next = s.get(i + 1).copied();
        if s[i] == '/' && next == Some('/') {
            let end = s[i..].iter().position(|&c| c == '\n').map_or(s.len(), |p| i + p);
            blank(&mut out, i, end);
            i = end;
        } else if s[i] == '/' && next == Some('*') {
            let (mut depth, mut j) = (1, i + 2);
            while j < s.len() && depth > 0 {
                if s[j] == '/' && s.get(j + 1) == Some(&'*') {
                    depth += 1;
                    j += 2;
                } else if s[j] == '*' && s.get(j + 1) == Some(&'/') {
                    depth -= 1;
                    j += 2;
                } else {
                    j += 1;
                }
            }
            blank(&mut out, i, j);
            i = j;
        } else if raw_string_start(&s, i) {
            // A raw string: r"…", r#"…"#, also with a `b` or `c` prefix (br"…", br#"…"#, cr"…").
            let mut j = i + 1;
            let mut hashes = 0;
            while s.get(j) == Some(&'#') {
                hashes += 1;
                j += 1;
            }
            if s.get(j) != Some(&'"') {
                i += 1;
                continue;
            }
            j += 1;
            loop {
                if j >= s.len() {
                    break;
                }
                if s[j] == '"' && (0..hashes).all(|k| s.get(j + 1 + k) == Some(&'#')) {
                    j += 1 + hashes;
                    break;
                }
                j += 1;
            }
            blank(&mut out, i + 1, j);
            i = j;
        } else if s[i] == '"' {
            let mut j = i + 1;
            while j < s.len() && s[j] != '"' {
                j += if s[j] == '\\' { 2 } else { 1 };
            }
            blank(&mut out, i, (j + 1).min(s.len()));
            i = j + 1;
        } else if s[i] == '\'' {
            // A character literal ('x', '\n', '\u{1F600}'); otherwise a lifetime or a label.
            if next == Some('\\') {
                let end = s[i + 2..].iter().position(|&c| c == '\'').map_or(s.len(), |p| i + 2 + p + 1);
                blank(&mut out, i, end);
                i = end;
            } else if s.get(i + 2) == Some(&'\'') {
                blank(&mut out, i, i + 3);
                i += 3;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    out
}

/// Whether the `r` at `i` starts a raw string literal (`r"`, `r#`), alone or after a `b`/`c` prefix. A raw
/// identifier (`r#type`) passes here and is told apart by the caller (no `"` after the hashes).
fn raw_string_start(s: &[char], i: usize) -> bool {
    let next = s.get(i + 1).copied();
    if s[i] != 'r' || (next != Some('"') && next != Some('#')) {
        return false;
    }
    let before = i.checked_sub(1).map(|p| s[p]);
    !ident_char(before) || (matches!(before, Some('b' | 'c')) && !ident_char(i.checked_sub(2).map(|p| s[p])))
}

fn ident_char(c: Option<char>) -> bool {
    c.is_some_and(|c| c.is_alphanumeric() || c == '_')
}

/// Whether `word` occurs in `text` as a whole identifier.
fn has_word(text: &str, word: &str) -> bool {
    text.match_indices(word).any(|(at, _)| {
        !ident_char(text[..at].chars().next_back()) && !ident_char(text[at + word.len()..].chars().next())
    })
}

/// The index just past the bracket that closes the one at `open` (`(`/`)` or `{`/`}`).
fn close_of(code: &[char], open: usize) -> usize {
    let (o, c) = (code[open], if code[open] == '(' { ')' } else { '}' });
    let mut depth = 0;
    for (k, &ch) in code.iter().enumerate().skip(open) {
        if ch == o {
            depth += 1;
        } else if ch == c {
            depth -= 1;
            if depth == 0 {
                return k + 1;
            }
        }
    }
    code.len()
}

/// Blanks every item under `#[cfg(test)]` (outer attribute): up to its `;`, or its balanced `{…}` block.
fn without_test_items(code: &mut [char]) {
    let squeezed = |from: usize, to: usize, code: &[char]| -> String {
        code[from..to].iter().filter(|c| !c.is_whitespace()).collect()
    };
    let mut i = 0;
    while i < code.len() {
        if code[i] == '#' && code.get(i + 1) == Some(&'[') {
            let end = close_of_square(code, i + 1);
            if squeezed(i, end, code) == "#[cfg(test)]" {
                let mut j = end;
                while j < code.len() && code[j] != '{' && code[j] != ';' {
                    j += 1;
                }
                let stop = if code.get(j) == Some(&'{') { close_of(code, j) } else { (j + 1).min(code.len()) };
                for c in &mut code[i..stop] {
                    if *c != '\n' {
                        *c = ' ';
                    }
                }
                i = stop;
                continue;
            }
        }
        i += 1;
    }
}

fn close_of_square(code: &[char], open: usize) -> usize {
    let mut depth = 0;
    for (k, &ch) in code.iter().enumerate().skip(open) {
        if ch == '[' {
            depth += 1;
        } else if ch == ']' {
            depth -= 1;
            if depth == 0 {
                return k + 1;
            }
        }
    }
    code.len()
}

/// Every attribute (`#[…]`, `#![…]`) of the code: (its start, its text without whitespace).
fn attributes(code: &[char]) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    let mut i = 0;
    while i < code.len() {
        if code[i] == '#' {
            let mut j = i + 1;
            if code.get(j) == Some(&'!') {
                j += 1;
            }
            while j < code.len() && code[j].is_whitespace() {
                j += 1;
            }
            if code.get(j) == Some(&'[') {
                let end = close_of_square(code, j);
                found.push((i, code[i..end].iter().filter(|c| !c.is_whitespace()).collect()));
                i = end;
                continue;
            }
        }
        i += 1;
    }
    found
}

fn line_of(code: &[char], at: usize) -> usize {
    code[..at].iter().filter(|&&c| c == '\n').count() + 1
}

/// The OS `cfg`s of one file's code: (line, the `cfg…(…)` text without whitespace).
fn os_cfgs(text: &str) -> Vec<(usize, String)> {
    let mut code = code_only(text);
    without_test_items(&mut code);
    let mut found = Vec::new();
    let mut i = 0;
    while i + 3 <= code.len() {
        let starts_cfg = code[i..].starts_with(&['c', 'f', 'g']) && !ident_char(i.checked_sub(1).map(|p| code[p]));
        if !starts_cfg {
            i += 1;
            continue;
        }
        let mut j = i + 3;
        for suffix in [&['!'][..], &['_', 'a', 't', 't', 'r'][..]] {
            if code[j..].starts_with(suffix) {
                j += suffix.len();
            }
        }
        while j < code.len() && code[j].is_whitespace() {
            j += 1;
        }
        if code.get(j) != Some(&'(') {
            i += 1;
            continue;
        }
        let end = close_of(&code, j);
        let predicate: String = code[i..end].iter().filter(|c| !c.is_whitespace()).collect();
        if OS_WORDS.iter().any(|w| has_word(&predicate, w)) || predicate.contains('$') {
            found.push((line_of(&code, i), predicate));
        }
        i = end;
    }
    // `target_os =` outside a cfg (in a `#[cfg_attr]` the loop above already found it).
    let flat: String = code.iter().collect();
    for (at, _) in flat.match_indices("target_os") {
        let rest = flat[at + "target_os".len()..].trim_start();
        let line = flat[..at].matches('\n').count() + 1;
        if rest.starts_with('=') && !found.iter().any(|(l, _)| *l == line) {
            found.push((line, "target_os =".into()));
        }
    }
    // Code from elsewhere: `#[path = …]` (also inside a `cfg_attr`) and `include!(…)`.
    for (at, attr) in attributes(&code) {
        let attr = attr.replacen("#!", "#", 1);
        if attr.starts_with("#[path=") || (attr.starts_with("#[cfg_attr(") && attr.contains(",path=")) {
            found.push((line_of(&code, at), attr));
        }
    }
    for (at, _) in flat.match_indices("include") {
        if ident_char(flat[..at].chars().next_back()) {
            continue;
        }
        let rest = flat[at + "include".len()..].trim_start();
        if let Some(rest) = rest.strip_prefix('!')
            && rest.trim_start().starts_with(['(', '[', '{'])
        {
            found.push((flat[..at].matches('\n').count() + 1, "include!".into()));
        }
    }
    found.sort();
    found
}

/// The lines with `unsafe` code, or with an attribute that lowers the `unsafe_code` lint (`allow`, `expect`,
/// `warn`; `deny` and `forbid` are fine).
fn unsafe_lines(text: &str) -> Vec<usize> {
    let code = code_only(text);
    let flat: String = code.iter().collect();
    let mut lines: Vec<usize> =
        flat.lines().enumerate().filter(|(_, l)| has_word(l, "unsafe")).map(|(n, _)| n + 1).collect();
    for (at, attr) in attributes(&code) {
        let lowers = ["allow(", "expect(", "warn("].iter().any(|l| attr.contains(l));
        if lowers && has_word(&attr, "unsafe_code") {
            lines.push(line_of(&code, at));
        }
    }
    lines.sort();
    lines.dedup();
    lines
}

#[test]
fn os_cfgs_only_in_the_platform_places() {
    let mut bad = Vec::new();
    for (path, text) in sources() {
        if CFG_ALLOWED.iter().any(|p| path.starts_with(p)) {
            continue;
        }
        for (line, _) in os_cfgs(&text) {
            bad.push(format!("{path}:{line}: {}", text.lines().nth(line - 1).unwrap_or("").trim()));
        }
    }
    assert!(
        bad.is_empty(),
        "an OS cfg (or a `cfg($…)`, `#[path]`, `include!`) outside fsx, the platform crates, the helper's backends and \
         the app's platform module:\n{}",
        bad.join("\n")
    );
}

#[test]
fn unsafe_only_in_the_platform_crates_and_the_helper() {
    let mut bad = Vec::new();
    for (path, text) in sources() {
        if UNSAFE_ALLOWED.iter().any(|p| path.starts_with(p)) {
            continue;
        }
        for line in unsafe_lines(&text) {
            bad.push(format!("{path}:{line}: {}", text.lines().nth(line - 1).unwrap_or("").trim()));
        }
    }
    assert!(
        bad.is_empty(),
        "`unsafe` (or an allowed `unsafe_code` lint) outside platform-mac, platform-win and the helper:\n{}",
        bad.join("\n")
    );
}

/// The scanner itself: what counts as an OS cfg and what does not.
#[test]
fn the_scanner_finds_os_cfgs_and_nothing_else() {
    let found = |text: &str| os_cfgs(text).into_iter().map(|(l, _)| l).collect::<Vec<_>>();
    assert_eq!(found("#[cfg(target_os = \"macos\")]\nfn a() {}\n"), [1]);
    assert_eq!(found("fn a() {}\n#[cfg(unix)]\nfn b() {}"), [2]);
    assert_eq!(found("#[cfg(not( windows ))]\nmod w;"), [1]);
    assert_eq!(found("#[cfg(all(debug_assertions, target_os = \"macos\"))]\nmod s;"), [1]);
    assert_eq!(found("#[cfg_attr(windows, ignore)]\nfn t() {}"), [1]);
    assert_eq!(found("fn a() -> bool { cfg!(unix) }"), [1]);
    assert_eq!(found("#[cfg(target_family = \"unix\")]\nfn a() {}"), [1]);
    assert_eq!(found("const X: bool = cfg!(any(test, target_os = \"windows\"));"), [1]);
    // Not OS cfgs, or not code.
    assert!(found("#[cfg(test)]\nmod tests {\n    #[cfg(unix)]\n    fn t() { let s = \"}\"; }\n}\n").is_empty());
    assert!(found("#[cfg(any(test, feature = \"test-support\"))]\nfn a() {}").is_empty());
    assert!(found("#[cfg(debug_assertions)]\nfn a() { is_allowed(cfg!(dev)) }").is_empty());
    assert!(found("// #[cfg(unix)]\n/// cfg(windows)\n/* cfg(target_os = \"macos\") */ fn a() {}").is_empty());
    assert!(found("const S: &str = \"#[cfg(unix)]\"; const R: &str = r#\"cfg(windows)\"#;").is_empty());
    assert!(found("fn unix_time() {} fn windows_count() {} struct cfgx;").is_empty());
    assert!(found("fn f<'a>(x: &'a str) -> char { '\"' } #[cfg(feature = \"x\")] fn g() {}").is_empty());
    // A test item ends where it ends: the code after the test module is scanned again.
    assert_eq!(found("#[cfg(test)]\nmod tests {\n}\n#[cfg(windows)]\nfn w() {}"), [4]);
}

/// The scanner's former blind spots (Task 20, L1): each one is found now.
#[test]
fn the_scanner_sees_through_byte_and_c_raw_strings() {
    let found = |text: &str| os_cfgs(text).into_iter().map(|(l, _)| l).collect::<Vec<_>>();
    // `br"\"` ends at its second quote; read as a normal string it would hide the cfg up to the next quote.
    assert_eq!(found("const B: &[u8] = br\"\\\";\n#[cfg(unix)]\nfn a() {}\nconst C: &[u8] = b\"x\";"), [2]);
    assert_eq!(found("const B: &[u8] = br#\"\\\"#;\n#[cfg(unix)]\nfn a() {}\nconst C: &str = \"x\";"), [2]);
    assert_eq!(found("const C: &core::ffi::CStr = cr\"\\\";\n#[cfg(windows)]\nfn a() {}\nconst S: &str = \"x\";"), [2]);
    // Still not code: the raw strings' contents, and a raw identifier is not a raw string.
    assert!(found("const B: &[u8] = br#\"cfg(unix)\"#; const R: &str = r\"cfg(windows)\";").is_empty());
    assert!(found("fn r#type() {} fn br() {} const X: &str = \"cfg\";").is_empty());
}

#[test]
fn the_scanner_finds_path_attributes_and_include() {
    let found = |text: &str| os_cfgs(text).into_iter().map(|(l, _)| l).collect::<Vec<_>>();
    assert_eq!(found("fn a() {}\n#[path = \"macos_impl.rs\"]\nmod imp;"), [2]);
    assert_eq!(found("#[cfg_attr(feature = \"x\", path = \"other.rs\")]\nmod imp;"), [1]);
    assert_eq!(found("fn a() {}\ninclude!(\"generated.rs\");"), [2]);
    assert_eq!(found("include ! { \"generated.rs\" }"), [1]);
    // The data macros and other words are fine.
    assert!(found("const T: &str = include_str!(\"t.txt\"); const B: &[u8] = include_bytes!(\"b\");").is_empty());
    assert!(found("fn include(path: &str) {} fn f() { include(\"x\"); let path = 1; }").is_empty());
}

#[test]
fn the_scanner_finds_macro_metavariable_cfgs() {
    let found = |text: &str| os_cfgs(text).into_iter().map(|(l, _)| l).collect::<Vec<_>>();
    let text = "macro_rules! on {\n    ($p:meta, $i:item) => {\n        #[cfg($p)]\n        $i\n    };\n}\n";
    assert_eq!(found(text), [3]);
    assert_eq!(found("macro_rules! b { ($p:meta) => { cfg!($p) }; }"), [1]);
    assert_eq!(found("macro_rules! b { ($v:literal) => { cfg!(target_os = $v) }; }"), [1]);
}

#[test]
fn the_scanner_finds_target_env_and_target_family() {
    let found = |text: &str| os_cfgs(text).into_iter().map(|(l, _)| l).collect::<Vec<_>>();
    assert_eq!(found("#[cfg(target_env = \"msvc\")]\nfn a() {}"), [1]);
    assert_eq!(found("fn a() -> bool { cfg!(target_family = \"windows\") }"), [1]);
    assert_eq!(found("#[cfg(not(target_env = \"gnu\"))]\nfn a() {}"), [1]);
}

#[test]
fn the_scanner_finds_a_lowered_unsafe_code_lint() {
    assert_eq!(unsafe_lines("#![allow(unsafe_code)]\nfn a() {}"), [1]);
    assert_eq!(unsafe_lines("fn a() {}\n#[expect(unsafe_code, reason = \"x\")]\nmod m;"), [2]);
    assert_eq!(unsafe_lines("#[allow(dead_code, unsafe_code)]\nfn a() {}"), [1]);
    assert_eq!(unsafe_lines("#[warn(unsafe_code)]\nfn a() {}"), [1]);
    assert_eq!(unsafe_lines("#[cfg_attr(test, allow(unsafe_code))]\nfn a() {}"), [1]);
    // Raising it is fine.
    assert!(unsafe_lines("#![forbid(unsafe_code)]\n#[deny(unsafe_code)]\nfn a() {}").is_empty());
}

#[test]
fn the_scanner_finds_unsafe_code_only() {
    assert_eq!(unsafe_lines("fn a() {}\nunsafe fn b() {}\nfn c() { unsafe { b() } }"), [2, 3]);
    assert!(
        unsafe_lines("#![forbid(unsafe_code)]\n// unsafe\nfn is_unsafe_text_char() {} const S: &str = \"unsafe\";")
            .is_empty()
    );
}

#[test]
fn the_allow_lists_are_exactly_the_platform_places() {
    assert_eq!(
        CFG_ALLOWED,
        [
            "crates/core/src/fsx/",
            "crates/platform-mac/",
            "crates/platform-win/",
            "crates/winsys/",
            "crates/helper/src/macos/",
            "crates/helper/src/windows/",
            "crates/helper/src/main.rs",
            "app/src-tauri/src/platform/",
        ]
    );
    assert_eq!(UNSAFE_ALLOWED, ["crates/platform-mac/", "crates/platform-win/", "crates/winsys/", "crates/helper/"]);
}
