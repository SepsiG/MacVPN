//! The MacVPN helper (the root layer, binary `mvpn`): the shared protocol logic ([`shared`]: the command line,
//! the framed stdin, masking, the `respond` answer, the status JSON, the validation dispatch and the
//! management-bridge state machine) and one backend per operating system ([`macos`]: everything that runs today;
//! [`windows`]: phase 1 refuses). `src/main.rs` picks the backend.

pub mod macos;
pub mod shared;
pub mod windows;

#[cfg(test)]
mod tests {
    use std::path::Path;

    fn sources(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                sources(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }

    /// Every literal message key passed to `tr` in the helper (every backend) has a Hungarian translation.
    #[test]
    fn every_call_site_has_a_translation() {
        let mut files = Vec::new();
        sources(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut files);
        let call = regex::Regex::new(r#"\btr\(\s*"((?:[^"\\]|\\.)*)""#).unwrap();
        let mut found = 0;
        for path in files {
            let text = std::fs::read_to_string(path).unwrap();
            for c in call.captures_iter(&text) {
                let key = c[1].replace("\\\"", "\"");
                assert!(macvpn_core::l10n::hungarian(&key).is_some(), "{key}");
                found += 1;
            }
        }
        assert!(found > 80, "{found}");
    }
}
