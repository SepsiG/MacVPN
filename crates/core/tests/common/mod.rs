//! Test helpers.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

/// A unique directory under the system temp dir, removed on drop. Never the user's Application Support.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new() -> TempDir {
        let p = std::env::temp_dir().join(format!("macvpn-core-test-{}", uuid::Uuid::new_v4()));
        TempDir(p)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

/// The repository root (for `Tests/Fixtures` and `docs`).
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..").canonicalize().unwrap()
}

use macvpn_core::l10n::AppLanguage;
use macvpn_core::models::ValidationIssue;
use macvpn_core::validators::{ConfigValidator, OpenVPNValidator, StrongSwanValidator, WireGuardValidator};

/// Fixes the language of the current test thread (Swift: `AppLanguage.override` in `setUp`).
pub fn lang(language: AppLanguage) {
    AppLanguage::set_thread_override(Some(language));
}

pub fn ovpn_all(text: &str) -> Vec<ValidationIssue> {
    OpenVPNValidator.validate(text)
}

pub fn wg_all(text: &str) -> Vec<ValidationIssue> {
    WireGuardValidator.validate(text)
}

pub fn swan_all(text: &str) -> Vec<ValidationIssue> {
    StrongSwanValidator.validate(text)
}

pub fn lines(issues: &[ValidationIssue]) -> Vec<i64> {
    issues.iter().map(|i| i.line).collect()
}

pub fn messages(issues: &[ValidationIssue]) -> Vec<String> {
    issues.iter().map(|i| i.message.clone()).collect()
}

pub fn set(names: &[&str]) -> std::collections::HashSet<String> {
    names.iter().map(|s| s.to_string()).collect()
}

/// Swift's `"""` literal: the common indentation removed, no trailing newline.
pub fn dedent(s: &str) -> String {
    let lines: Vec<&str> = s.strip_prefix('\n').unwrap_or(s).lines().collect();
    let indent =
        lines.iter().filter(|l| !l.trim().is_empty()).map(|l| l.len() - l.trim_start().len()).min().unwrap_or(0);
    let body: Vec<&str> = lines.iter().map(|l| if l.len() >= indent { &l[indent..] } else { l.trim_start() }).collect();
    body.join("\n").trim_end_matches([' ', '\n']).to_string()
}
