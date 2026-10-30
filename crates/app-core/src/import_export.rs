//! Import and export orchestration (port of the Swift `AppModel.importFile` / `importFiles` / `export`): reading a
//! chosen or dropped file, saving the connection even with validation problems (fixed in the editor), the
//! credential-file confirmation, the report notes, and the export's key-material warning and save-panel text.

use crate::deps::SecretField;
use crate::editor::EditorDeps;
use macvpn_core::exporter;
use macvpn_core::fsx::{self, Follow, OpenFor};
use macvpn_core::importer::{self, ExportMeta};
use macvpn_core::l10n::{self, Arg};
use macvpn_core::models::{Connection, VPNKind, ValidationIssue, uuid_string};
use serde::Serialize;
use std::io::Read;
use std::path::Path;
use uuid::Uuid;
use zeroize::Zeroizing;

/// The largest file read for an import (the editor's config limit).
pub const MAX_IMPORT_BYTES: u64 = 1_048_576;

/// The result of an import: errors (files not imported) and information (inlined files, validation problems).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportReport {
    pub errors: Vec<String>,
    pub notes: Vec<String>,
}

impl ImportReport {
    pub fn is_empty(&self) -> bool {
        self.errors.is_empty() && self.notes.is_empty()
    }

    pub fn message(&self) -> String {
        self.errors.iter().chain(&self.notes).cloned().collect::<Vec<_>>().join("\n")
    }

    /// "Import" or, with errors, "Import Error" (the alert's title).
    pub fn title(&self) -> String {
        l10n::tr(if self.errors.is_empty() { "Import" } else { "Import Error" }, &[])
    }

    pub fn merge(&mut self, other: ImportReport) {
        self.errors.extend(other.errors);
        self.notes.extend(other.notes);
    }
}

/// A file's bytes for **Import Client Certificate…** (a PKCS#12 file is binary), opened and checked as
/// [`read_import_file`] does. At most `max + 1` bytes are read: a larger file comes back with `max + 1` bytes, so
/// the caller's size check says it is too large. `None`: cannot be read.
pub fn read_import_bytes(path: &Path, max: usize) -> Option<Zeroizing<Vec<u8>>> {
    if !std::fs::metadata(path).ok()?.is_file() {
        return None;
    }
    let (file, _) = fsx::open_regular(path, OpenFor::Read, Follow::Yes, true).ok()?;
    let mut data = Zeroizing::new(Vec::with_capacity(max + 1));
    file.take(max as u64 + 1).read_to_end(&mut data).ok()?;
    Some(data)
}

/// The file's text (UTF-8, at most [`MAX_IMPORT_BYTES`]): a regular file, opened once and checked on the open
/// descriptor. `None`: cannot be read. Every file the user picks or drops (import, the SSTP CA) comes through here.
///
/// The path must name a regular file before it is opened (`stat`: a FIFO, a device or a directory is never opened,
/// as an open alone can have effects). It is then opened with `O_NONBLOCK` (a file swapped for a FIFO meanwhile
/// never blocks the open) and `O_NOCTTY` (a swapped-in terminal never becomes the controlling one), the descriptor
/// is checked again (`fstat`: a regular file) and only then switched back to blocking reads (`fsx::open_regular`),
/// and the size is checked (at most 1 MB). Symlinks
/// are followed as before (a link to a regular file imports that file; a link to a FIFO is refused by the same
/// checks).
pub fn read_import_file(path: &Path) -> Option<String> {
    if !std::fs::metadata(path).ok()?.is_file() {
        return None;
    }
    let (file, meta) = fsx::open_regular(path, OpenFor::Read, Follow::Yes, true).ok()?;
    if meta.len() > MAX_IMPORT_BYTES {
        return None;
    }
    let mut data = Vec::new();
    file.take(MAX_IMPORT_BYTES + 1).read_to_end(&mut data).ok()?;
    if data.len() as u64 > MAX_IMPORT_BYTES {
        return None;
    }
    String::from_utf8(data).ok()
}

/// The credential-file question: "Use the credentials from … for this connection?" (true: Use).
pub fn credential_question(files: &[String], config: &str) -> (String, String) {
    let list = files.join(", ");
    (
        l10n::tr("Use the credentials from %@ for this connection?", &[Arg::Str(&list)]),
        l10n::tr(
            "%@ refers to these files. If you choose Use, their user name, password or private key password is stored in the vault for this connection. The files are never copied into the config.",
            &[Arg::Str(config)],
        ),
    )
}

/// What one imported file produced.
pub struct ImportedFile {
    pub report: ImportReport,
    /// The new connection and its validation problems (shown once by the editor).
    pub imported: Option<(Uuid, Vec<ValidationIssue>)>,
    /// The exported `credentialName` of the `# macvpn-meta` line, with the kind and the stored config: the caller
    /// asks whether to use that shared credential (`SharedCredentials::link_imported`); nothing is linked here.
    pub credential: Option<ImportedCredentialName>,
}

/// An imported config's `credentialName` (spec 3a: only ever offered, never linked by the file itself).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedCredentialName {
    pub name: String,
    pub kind: VPNKind,
    /// The stored config (without the metadata line): where the import question reads the server from.
    pub config: String,
}

/// Imports one file. The config is saved even with validation problems (fixable in the editor). `confirm` asks
/// whether the credentials of the referenced secret files may be stored (`files`, `config file name`): their
/// secrets only reach the Keychain after the user agreed, never the config. `gate` refuses a kind that cannot be
/// added (its engine is missing: the reason), after the file's kind is known and before anything is saved.
pub fn import_file(
    deps: &EditorDeps,
    path: &Path,
    gate: &dyn Fn(VPNKind) -> Option<String>,
    confirm: &mut dyn FnMut(&[String], &str) -> bool,
) -> ImportedFile {
    let file = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let fail = |message: String| ImportedFile {
        report: ImportReport { errors: vec![format!("{file}: {message}")], notes: vec![] },
        imported: None,
        credential: None,
    };
    let Some(content) = read_import_file(path) else { return fail(l10n::tr("Cannot read the file", &[])) };
    let base = path.parent().unwrap_or(Path::new("/"));
    // A valid `# macvpn-meta` line (an export of MacVPN 1.2) is split off here: not part of the stored config.
    let prepared = match importer::prepare(&file, &content, base) {
        Ok(prepared) => prepared,
        Err(e) => return fail(e.message()),
    };
    if let Some(reason) = gate(prepared.kind) {
        return fail(reason);
    }
    let name = path.file_stem().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let c = Connection::new(name, prepared.kind);
    if let Err(e) = deps.store.save(&c, Some(&prepared.config)) {
        return fail(e.to_string());
    }
    // The exported folder path: the missing folders are recreated; an older export lands at the root.
    let folder = prepared.meta.as_ref().and_then(|m| m.folder.as_deref());
    let placed = crate::folders::place_imported(&deps.manager, &c.id, folder);
    let creds = &prepared.credentials;
    let candidates = creds.candidate_files();
    let use_credentials = !candidates.is_empty() && confirm(&candidates, &file);
    if use_credentials {
        let w = &deps.secret_writer;
        if let Some(user) = &creds.username {
            w.set(user, &c.id, SecretField::Username);
        }
        if let Some(pass) = &creds.password {
            w.set(pass, &c.id, SecretField::Password);
        }
        if let Some(key_pass) = &creds.key_password {
            w.set(key_pass, &c.id, SecretField::KeyPassword);
        }
    }
    let mut report = ImportReport::default();
    let mut note = |text: String| report.notes.push(format!("{file}: {text}"));
    if let Err(e) = placed {
        note(l10n::tr("Imported to the top level: the folder could not be created (%@)", &[Arg::Str(&e.to_string())]));
    }
    if !prepared.inlined_files.is_empty() {
        note(l10n::tr("Imported, inlined: %@", &[Arg::Str(&prepared.inlined_files.join(", "))]));
    }
    if !prepared.issues.is_empty() {
        note(l10n::tr("Imported, but the config has problems. Fix them in the editor (red list).", &[]));
    }
    if use_credentials && let Some(source) = &creds.credentials_file {
        note(l10n::tr(
            "The username and password from %@ are stored in the vault; the file is not copied into the config.",
            &[Arg::Str(source)],
        ));
    }
    if use_credentials && let Some(source) = &creds.key_password_file {
        note(l10n::tr("The private key password from %@ is stored in the vault.", &[Arg::Str(source)]));
    }
    if !use_credentials && !candidates.is_empty() {
        note(l10n::tr(
            "The credentials in %@ were not used. Enter them in the editor if needed.",
            &[Arg::Str(&candidates.join(", "))],
        ));
    }
    for unread in &creds.unread_files {
        note(l10n::tr(
            "%@ was not read (missing, outside the config's folder, larger than 1 KB, or not in the expected form). Enter the credentials in the editor.",
            &[Arg::Str(unread)],
        ));
    }
    if prepared.has_encrypted_key && !(use_credentials && creds.key_password.is_some()) {
        note(l10n::tr(
            "The private key is encrypted: enter its password in the Private key password field before connecting.",
            &[],
        ));
    }
    if !prepared.risky.is_empty() {
        let names: std::collections::BTreeSet<&str> = prepared.risky.iter().map(|r| r.directive.as_str()).collect();
        let list = names.into_iter().collect::<Vec<_>>().join(", ");
        note(l10n::tr(
            "Imported. It contains risky settings (%@): review them in the editor’s yellow panel and tick the checkbox before connecting.",
            &[Arg::Str(&list)],
        ));
    }
    let credential = prepared
        .meta
        .as_ref()
        .and_then(|m| m.credential_name.clone())
        .map(|name| ImportedCredentialName { name, kind: prepared.kind, config: prepared.config.clone() });
    ImportedFile { report, imported: Some((c.id, prepared.issues)), credential }
}

// MARK: - Export

/// The warning before an export with key material: "Export Without Keys" / "Export With Keys" / "Cancel".
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportWarning {
    pub title: String,
    pub message: String,
}

/// The export's bytes as text (the core exporter; a native profile is generated).
fn exported_text(deps: &EditorDeps, c: &Connection) -> Result<String, String> {
    let data = if c.kind.is_native() {
        // As `exporter::export`: the account name left empty (the recipient fills in theirs), no PSK.
        let mut copy = c.clone();
        if let Some(native) = copy.native.as_mut() {
            native.account = String::new();
        }
        macvpn_core::mobileconfig::generate(&copy, "").map_err(|e| e.message())?
    } else {
        deps.store.load_config(&c.id).map(String::into_bytes).map_err(|e| e.to_string())?
    };
    Ok(String::from_utf8_lossy(&data).into_owned())
}

/// `None`: no personal key material, export at once (a shared OpenVPN `tls-auth` / `tls-crypt` key alone is
/// exported either way: [`exporter::OPENVPN_SHARED_BLOCKS`]); otherwise the question to ask first.
pub fn export_warning(deps: &EditorDeps, c: &Connection) -> Result<Option<ExportWarning>, String> {
    if deps.manager.is_locked() {
        return Err(crate::vault_stores::locked_message());
    }
    let text = exported_text(deps, c)?;
    let personal = exporter::personal_material(&text, c.kind);
    if personal.is_empty() {
        return Ok(None);
    }
    let mut message = l10n::tr(
        "It contains: %@. Anyone who has these keys can connect as you. Export them only if the recipient needs them, and keep the file in a trusted place.",
        &[Arg::Str(&personal.join(", "))],
    );
    let shared = exporter::shared_material(&text, c.kind);
    if !shared.is_empty() {
        message.push(' ');
        message.push_str(&l10n::tr(
            "Export Without Keys keeps %@: every user of the server has the same key, and the copy cannot connect without it.",
            &[Arg::Str(&shared.join(", "))],
        ));
    }
    Ok(Some(ExportWarning { title: l10n::tr("The config contains private keys or credentials", &[]), message }))
}

/// What the save panel shows and what is written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportPlan {
    pub data: Vec<u8>,
    pub file_name: String,
    /// The panel's message: decided by the data actually written (if key material stayed in, it says so).
    pub message: String,
}

/// The export's metadata line (`# macvpn-meta: …`): the folder path of a connection in a folder and the name of
/// the shared credential it uses (spec 3, 3a). Never a secret: the line has only those names.
pub fn export_meta(deps: &EditorDeps, c: &Connection) -> ExportMeta {
    ExportMeta {
        folder: deps.manager.folder_path(&uuid_string(&c.id)),
        credential_name: deps.secrets.credential_for(&c.id).map(|credential| credential.name),
    }
}

/// The export (`with_keys` false: the key material stripped). The Keychain's passwords and PSK are never in it.
/// A text config starts with the metadata line when there is something to carry (`folder`, `credentialName`); a
/// native profile carries none (the importer refuses it anyway).
pub fn export_plan(deps: &EditorDeps, c: &Connection, with_keys: bool) -> Result<ExportPlan, String> {
    if deps.manager.is_locked() {
        return Err(crate::vault_stores::locked_message());
    }
    let mut text = exported_text(deps, c)?;
    if !with_keys && !exporter::personal_material(&text, c.kind).is_empty() {
        text = exporter::strip_secrets(&text, c.kind);
    }
    let included = exporter::secret_material(&text, c.kind);
    let shared = exporter::shared_material(&text, c.kind);
    let message = if included.is_empty() {
        l10n::tr("Passwords and the PSK are not included in the export.", &[])
    } else if exporter::personal_material(&text, c.kind).is_empty() {
        // Only the server's shared TLS key stays in (G10 of the client-credential audit).
        l10n::tr(
            "Your private keys and credentials are not included. The shared TLS key (%@) is: every user of the server has the same one, and the copy needs it to connect. Passwords and the PSK stored in the vault are not included.",
            &[Arg::Str(&shared.join(", "))],
        )
    } else {
        l10n::tr(
            "The export INCLUDES the private keys and credentials from the config (%@). Passwords and the PSK stored in the vault are not included.",
            &[Arg::Str(&included.join(", "))],
        )
    };
    let data = if c.kind.is_native() {
        text.into_bytes()
    } else {
        exporter::with_meta(text.as_bytes(), &export_meta(deps, c))
    };
    Ok(ExportPlan { data, file_name: exporter::file_name(c), message })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    use std::time::{Duration, Instant};

    struct Dir(std::path::PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn temp_dir() -> Dir {
        let dir = std::env::temp_dir().join(format!("macvpn-import-read-{}", Uuid::new_v4()));
        std::fs::create_dir(&dir).unwrap();
        Dir(dir)
    }
    #[cfg(unix)]
    fn mkfifo(path: &Path) {
        let status = std::process::Command::new("/usr/bin/mkfifo").arg("-m").arg("600").arg(path).status().unwrap();
        assert!(status.success(), "mkfifo");
    }
    /// Runs the read on a thread and fails the test (instead of hanging it) when it does not return in 2 s.
    fn read_quickly(path: &Path) -> Option<String> {
        let path = path.to_path_buf();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(read_import_file(&path));
        });
        let start = Instant::now();
        let result = rx.recv_timeout(Duration::from_secs(2)).expect("read_import_file blocked");
        assert!(start.elapsed() < Duration::from_secs(2));
        result
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_is_refused_without_blocking() {
        let dir = temp_dir();
        let fifo = dir.0.join("pipe.ovpn");
        mkfifo(&fifo);
        assert_eq!(read_quickly(&fifo), None);
    }

    /// A FIFO is not even opened: a writer waiting in its blocking `open` would be released by any reader (and a
    /// device's open can have side effects), so the path's type is checked first.
    #[cfg(unix)]
    #[test]
    fn a_fifo_is_never_opened() {
        let dir = temp_dir();
        let fifo = dir.0.join("pipe.ovpn");
        mkfifo(&fifo);
        let (tx, rx) = std::sync::mpsc::channel();
        let writer_path = fifo.clone();
        std::thread::spawn(move || {
            // Blocks until a reader opens the FIFO.
            let opened = std::fs::OpenOptions::new().write(true).open(&writer_path).is_ok();
            let _ = tx.send(opened);
        });
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(read_quickly(&fifo), None);
        assert!(rx.recv_timeout(Duration::from_millis(300)).is_err(), "read_import_file opened the FIFO");
        // Release the writer.
        drop(std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open(&fifo).unwrap());
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)), Ok(true));
    }

    #[test]
    fn a_directory_is_refused() {
        let dir = temp_dir();
        assert_eq!(read_quickly(&dir.0), None);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_to_a_fifo_is_refused_without_blocking() {
        let dir = temp_dir();
        let fifo = dir.0.join("pipe");
        mkfifo(&fifo);
        let link = dir.0.join("link.ovpn");
        std::os::unix::fs::symlink(&fifo, &link).unwrap();
        assert_eq!(read_quickly(&link), None);
    }

    #[cfg(unix)]
    #[test]
    fn a_device_is_refused() {
        assert_eq!(read_quickly(Path::new("/dev/zero")), None);
        assert_eq!(read_quickly(Path::new("/dev/null")), None);
    }

    #[cfg(unix)]
    #[test]
    fn a_regular_file_and_a_symlink_to_one_are_read() {
        let dir = temp_dir();
        let file = dir.0.join("office.ovpn");
        std::fs::write(&file, "client\n").unwrap();
        assert_eq!(read_quickly(&file).as_deref(), Some("client\n"));
        let link = dir.0.join("link.ovpn");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert_eq!(read_quickly(&link).as_deref(), Some("client\n"));
    }

    #[test]
    fn the_size_cap_holds() {
        let dir = temp_dir();
        let file = dir.0.join("big.ovpn");
        std::fs::write(&file, vec![b'a'; MAX_IMPORT_BYTES as usize]).unwrap();
        assert_eq!(read_quickly(&file).map(|s| s.len()), Some(MAX_IMPORT_BYTES as usize));
        std::fs::write(&file, vec![b'a'; MAX_IMPORT_BYTES as usize + 1]).unwrap();
        assert_eq!(read_quickly(&file), None);
    }
}
