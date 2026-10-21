//! The helper and the app agree on the MFA state directory (Task 10).
//!
//! The helper writes `<UI_BASE>/<id>.json`, the app reads `<UI_STATE_DIR>/<id>.json`. The two crates must not
//! depend on each other, so the test reads both constants from the source text: `UI_BASE` anywhere below
//! `crates/helper/src` (wherever the helper's modules live), `UI_STATE_DIR` in `crates/platform-mac/src/mvpn_client.rs`.

use std::path::{Path, PathBuf};

/// The string literals of every `const <name>: &str = "…";` in `text`.
fn literal(text: &str, name: &str) -> Vec<String> {
    let needle = format!("const {name}: &str = \"");
    text.match_indices(&needle)
        .filter_map(|(at, _)| {
            let rest = &text[at + needle.len()..];
            rest.find('"').map(|end| rest[..end].to_string())
        })
        .collect()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn ui_state_directory_is_the_same_literal() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();

    let mut files = Vec::new();
    rust_files(&crates.join("helper/src"), &mut files);
    files.sort();
    let helper: Vec<String> =
        files.iter().flat_map(|f| literal(&std::fs::read_to_string(f).unwrap(), "UI_BASE")).collect();
    assert_eq!(helper.len(), 1, "one UI_BASE in crates/helper/src: {helper:?}");

    let client = std::fs::read_to_string(crates.join("platform-mac/src/mvpn_client.rs")).unwrap();
    let app = literal(&client, "UI_STATE_DIR");
    assert_eq!(app.len(), 1, "one UI_STATE_DIR in crates/platform-mac/src/mvpn_client.rs: {app:?}");

    assert_eq!(helper[0], app[0]);
    assert_eq!(app[0], "/var/run/macvpn-ui");
}
