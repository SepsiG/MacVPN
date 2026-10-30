//! Config export in its original format (port of `ConfigExporter.swift`). The password and PSK stored in the
//! Keychain are not included (for SSTP the user name is part of the config); key material and credentials inline
//! in the config are handled by `secret_material` / `strip_secrets`.

use crate::fsx::{self, Access, Follow};
use crate::importer::{self, ExportMeta};
use crate::l10n::{self, Arg};
use crate::mobileconfig::{self, MobileconfigError};
use crate::models::{Connection, VPNKind, uuid_string};
use crate::store::ConnectionStore;
use crate::swift_str;
use regex::Regex;
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::LazyLock;
use uuid::Uuid;

/// The export file name. Every `/` and `:` becomes `-`. Deliberately stricter than Swift: Foundation's
/// `replacingOccurrences` skips a `/` or `:` that a combining mark follows; nothing depends on that quirk.
pub fn file_name(c: &Connection) -> String {
    let replaced = c.name.replace(['/', ':'], "-");
    let mut safe = replaced.trim_matches(swift_str::is_foundation_whitespace_or_newline).to_string();
    if safe.is_empty() {
        safe = "MacVPN".into();
    }
    match c.kind {
        VPNKind::Openvpn => format!("{safe}.ovpn"),
        VPNKind::Wireguard => format!("{safe}.conf"),
        VPNKind::Strongswan => format!("{safe}.swanctl.conf"),
        VPNKind::Sstp => format!("{safe}.sstp"),
        VPNKind::L2tp | VPNKind::Cisco => format!("{safe}.mobileconfig"),
    }
}

#[derive(Debug)]
pub enum ExportError {
    Io(std::io::Error),
    Profile(MobileconfigError),
}

impl std::fmt::Display for ExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExportError::Io(e) => write!(f, "{e}"),
            ExportError::Profile(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ExportError {}

/// The exported bytes. A native profile leaves the account name empty (personal, the recipient fills in theirs)
/// and has no PSK.
pub fn export(c: &Connection, store: &ConnectionStore) -> Result<Vec<u8>, ExportError> {
    if c.kind.is_native() {
        let mut copy = c.clone();
        if let Some(native) = copy.native.as_mut() {
            native.account = String::new();
        }
        return mobileconfig::generate(&copy, "").map_err(ExportError::Profile);
    }
    store.load_config(&c.id).map(String::into_bytes).map_err(ExportError::Io)
}

/// The metadata line for an exported text config (`importer::take_export_meta` reads it back), with a line
/// break; `None` when there is nothing to carry. Keys in sorted order, values JSON-escaped.
pub fn meta_line(meta: &ExportMeta) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(name) = &meta.credential_name {
        parts.push(format!("\"credentialName\":{}", serde_json::Value::from(name.as_str())));
    }
    if let Some(folder) = &meta.folder {
        let path: Vec<serde_json::Value> = folder.iter().map(|f| serde_json::Value::from(f.as_str())).collect();
        parts.push(format!("\"folder\":{}", serde_json::Value::Array(path)));
    }
    if parts.is_empty() {
        return None;
    }
    Some(format!("{}{{{}}}\n", importer::EXPORT_META_PREFIX, parts.join(",")))
}

/// The exported text config with the metadata line on top (unchanged when there is none).
pub fn with_meta(config: &[u8], meta: &ExportMeta) -> Vec<u8> {
    match meta_line(meta) {
        Some(line) => [line.as_bytes(), config].concat(),
        None => config.to_vec(),
    }
}

/// A write error with a user-facing message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteError {
    pub message: String,
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for WriteError {}

/// Creates the export with 0600 from the start: a temp file in the target folder (`O_EXCL`, no symlink followed),
/// an fsync, then an atomic rename and an fsync of the folder. An existing file's permissions are not inherited.
pub fn write(data: &[u8], path: &Path) -> Result<(), WriteError> {
    write_with_access(data, path, Access::Private)
}

/// [`write`] with another final access (a team catalog is written [`Access::Shared`], 0644: it is meant to be
/// served, and it is encrypted and signed). The temp file is created private (0600) and gets `access` explicitly
/// (not through the umask) before the rename.
///
/// The access is set on the open descriptor (`fchmod`), never by path: in a shared or group-writable folder someone
/// could swap the temp name for a symlink to one of the user's files, and a chmod by path would follow it. Before
/// the rename the temp name must still be the written file (same file identity, not a symlink), else nothing is
/// published; where the platform cannot tell the identity ([`fsx::file_id`] is `None`), nothing is published.
pub fn write_with_access(data: &[u8], path: &Path, access: Access) -> Result<(), WriteError> {
    write_with_access_raced(data, path, access, &|_| {})
}

/// [`write_with_access`] with a hook that runs on the temp file's path after it was written, before its access is
/// set and it is renamed: tests swap the temp file there to check that a race cannot redirect the chmod or the
/// rename.
#[doc(hidden)]
pub fn write_with_access_raced(
    data: &[u8],
    path: &Path,
    access: Access,
    race: &dyn Fn(&Path),
) -> Result<(), WriteError> {
    let display = path.to_string_lossy().into_owned();
    let cannot_write = || WriteError { message: l10n::tr("Cannot write: %@", &[Arg::Str(&display)]) };
    let dir = path.parent().unwrap_or(Path::new("."));
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let tmp = dir.join(format!(".{name}.{}.tmp", uuid_string(&Uuid::new_v4())));
    let mut file = fsx::create_new(&tmp, Access::Private).map_err(|_| cannot_write())?;
    let mut ours = true;
    let result = (|| {
        file.write_all(data).map_err(|_| cannot_write())?;
        file.sync_all().map_err(|_| cannot_write())?;
        race(&tmp);
        fsx::set_access(&file, access)
            .map_err(|_| WriteError { message: l10n::tr("Cannot set the permissions: %@", &[Arg::Str(&display)]) })?;
        let written = fsx::stat(&file).map_err(|_| cannot_write())?;
        let named = fsx::stat_path(&tmp, Follow::No).map_err(|_| cannot_write())?;
        let same_file = matches!((fsx::file_id(&named), fsx::file_id(&written)), (Some(a), Some(b)) if a == b);
        if !named.file_type().is_file() || !same_file {
            ours = false;
            return Err(cannot_write());
        }
        drop(file);
        fs::rename(&tmp, path).map_err(|_| cannot_write())
    })();
    if result.is_err() {
        // Only our own temp file is removed (a swapped-in name is someone else's).
        if ours {
            let _ = fs::remove_file(&tmp);
        }
        return result;
    }
    // Durability of the rename; if the directory cannot be opened, the write still succeeded.
    fsx::sync_dir(dir);
    result
}

// MARK: - Key material

/// The OpenVPN inline blocks holding a private / static key or credentials (user name + password).
/// `<http-proxy-user-pass>` may be inside a `<connection>` block: detection is per line, so it is found there too.
pub const OPENVPN_SECRET_BLOCKS: [&str; 8] =
    ["key", "tls-auth", "tls-crypt", "tls-crypt-v2", "secret", "pkcs12", "auth-user-pass", "http-proxy-user-pass"];
pub const WIREGUARD_SECRET_KEYS: [&str; 2] = ["PrivateKey", "PresharedKey"];
/// The OpenVPN key blocks every client of a server shares (the server's `tls-auth` / `tls-crypt` key, made with
/// `openvpn --genkey` on the server): not personal, and a copy cannot connect without them, so "Export Without
/// Keys" keeps them (client-credential audit G10). `tls-crypt-v2` is different: each client has its own key.
pub const OPENVPN_SHARED_BLOCKS: [&str; 2] = ["tls-auth", "tls-crypt"];

/// The names of the key material in the config (e.g. `<key>`, `PrivateKey`, `secrets`), for the warning. Empty:
/// nothing to strip. A native export has no secrets anyway.
pub fn secret_material(config: &str, kind: VPNKind) -> Vec<String> {
    let lines: Vec<&str> = config.split('\n').collect();
    match kind {
        VPNKind::Openvpn => {
            let opened: BTreeSet<String> = lines.iter().filter_map(|l| openvpn_block_tag(l)).collect();
            OPENVPN_SECRET_BLOCKS.iter().filter(|b| opened.contains(**b)).map(|b| format!("<{b}>")).collect()
        }
        VPNKind::Wireguard => {
            let keys: BTreeSet<&str> = lines.iter().filter_map(|l| wireguard_secret_key(l, true)).collect();
            WIREGUARD_SECRET_KEYS.iter().filter(|k| keys.contains(**k)).map(|k| k.to_string()).collect()
        }
        VPNKind::Strongswan => {
            if strongswan_strip(&lines).1 {
                vec!["secrets".into()]
            } else {
                vec![]
            }
        }
        VPNKind::Sstp | VPNKind::L2tp | VPNKind::Cisco => vec![],
    }
}

/// The key material of [`secret_material`] that is personal: everything but the shared OpenVPN TLS keys
/// ([`OPENVPN_SHARED_BLOCKS`]). Empty: nothing for "Export Without Keys" to strip.
pub fn personal_material(config: &str, kind: VPNKind) -> Vec<String> {
    let shared = shared_material(config, kind);
    secret_material(config, kind).into_iter().filter(|m| !shared.contains(m)).collect()
}

/// The shared OpenVPN TLS keys of the config (`<tls-auth>`, `<tls-crypt>`), which "Export Without Keys" keeps.
pub fn shared_material(config: &str, kind: VPNKind) -> Vec<String> {
    if kind != VPNKind::Openvpn {
        return Vec::new();
    }
    let opened: BTreeSet<String> = config.split('\n').filter_map(openvpn_block_tag).collect();
    OPENVPN_SHARED_BLOCKS.iter().filter(|b| opened.contains(**b)).map(|b| format!("<{b}>")).collect()
}

/// The config without personal key material ("Export Without Keys"): the OpenVPN client key, PKCS#12,
/// `tls-crypt-v2` client key, static key and inline credentials removed (the shared `tls-auth` / `tls-crypt` key
/// stays: [`OPENVPN_SHARED_BLOCKS`]), WireGuard key values emptied (the structure stays, the recipient fills in
/// theirs), the strongSwan `secrets` section removed.
pub fn strip_secrets(config: &str, kind: VPNKind) -> String {
    let lines: Vec<&str> = config.split('\n').collect();
    match kind {
        VPNKind::Openvpn => {
            let mut out: Vec<&str> = Vec::new();
            let mut skipping: Option<String> = None;
            for line in &lines {
                if let Some(tag) = &skipping {
                    if swift_str::eq(
                        &line.trim_matches(swift_str::is_foundation_whitespace_or_newline).to_lowercase(),
                        &format!("</{tag}>"),
                    ) {
                        skipping = None;
                    }
                    continue;
                }
                if let Some(tag) = openvpn_block_tag(line)
                    && !OPENVPN_SHARED_BLOCKS.contains(&tag.as_str())
                {
                    skipping = Some(tag);
                    continue;
                }
                out.push(line);
            }
            // An unclosed block: everything to the end was dropped; keep the final newline.
            if skipping.is_some() && swift_str::has_suffix(config, "\n") && out.last() != Some(&"") {
                out.push("");
            }
            out.join("\n")
        }
        VPNKind::Wireguard => lines
            .iter()
            .map(|line| wireguard_secret_key(line, false).map(|k| format!("{k} =")).unwrap_or_else(|| line.to_string()))
            .collect::<Vec<_>>()
            .join("\n"),
        VPNKind::Strongswan => strongswan_strip(&lines).0.join("\n"),
        VPNKind::Sstp | VPNKind::L2tp | VPNKind::Cisco => config.to_string(),
    }
}

/// The opening tag (lower-cased) of an OpenVPN block holding a key, otherwise `None`.
pub(crate) fn openvpn_block_tag(line: &str) -> Option<String> {
    let t = line.trim_matches(swift_str::is_foundation_whitespace_or_newline).to_lowercase();
    if !swift_str::has_prefix(&t, "<") || !swift_str::has_suffix(&t, ">") || swift_str::has_prefix(&t, "</") {
        return None;
    }
    let characters = swift_str::characters(&t);
    if characters.len() < 2 {
        return None;
    }
    let tag: String = characters[1..characters.len() - 1].concat();
    OPENVPN_SECRET_BLOCKS.iter().any(|b| swift_str::eq(b, &tag)).then_some(tag)
}

/// The key (canonical spelling) of a `PrivateKey = …` / `PresharedKey = …` line, otherwise `None`.
/// `require_value`: a line with an empty value (an already stripped key) does not count.
pub(crate) fn wireguard_secret_key(line: &str, require_value: bool) -> Option<&'static str> {
    let eq = swift_str::first_index(line, "=")?;
    if require_value
        && line[eq + swift_str::char_len_at(line, eq)..]
            .trim_matches(swift_str::is_foundation_whitespace_or_newline)
            .is_empty()
    {
        return None;
    }
    let key = line[..eq].trim_matches(swift_str::is_foundation_whitespace).to_lowercase();
    WIREGUARD_SECRET_KEYS.iter().copied().find(|k| swift_str::eq(&k.to_lowercase(), &key))
}

/// Removes the top-level `secrets { … }` section(s).
fn strongswan_strip<'a>(lines: &[&'a str]) -> (Vec<&'a str>, bool) {
    let inside = strongswan_secret_lines(lines);
    let out = lines.iter().zip(&inside).filter(|(_, inside)| !**inside).map(|(line, _)| *line).collect();
    (out, inside.contains(&true))
}

/// Per line: it belongs to a top-level `secrets { … }` section (its first and last line included). Braces are
/// counted outside quotes and `#` comments.
pub(crate) fn strongswan_secret_lines(lines: &[&str]) -> Vec<bool> {
    static SECRETS: LazyLock<Regex> = LazyLock::new(|| Regex::new("^\\s*secrets\\s*\\{").expect("valid pattern"));
    let mut out = Vec::with_capacity(lines.len());
    let mut depth = 0i64;
    let mut skipping = false;
    for line in lines {
        let start_depth = depth;
        let mut in_quote = false;
        for ch in swift_str::characters(line) {
            if in_quote {
                if ch == "\"" {
                    in_quote = false;
                }
                continue;
            }
            if ch == "#" {
                break;
            }
            if ch == "\"" {
                in_quote = true;
            } else if ch == "{" {
                depth += 1;
            } else if ch == "}" {
                depth = i64::max(0, depth - 1);
            }
        }
        if !skipping && start_depth == 0 && swift_str::matches(line, &SECRETS) {
            skipping = true;
        }
        out.push(skipping);
        if skipping && depth == 0 {
            skipping = false;
        }
    }
    out
}
