//! The vault database (spec 2.1): `vault.db`, SQLCipher 4 keyed with the raw DEK, so SQLCipher's own KDF is not
//! used and neither the schema nor the row counts are visible without the key.
//!
//! Open sequence: `PRAGMA key = "x'<hex>'"` first (the statement text lives in a `Zeroizing` buffer), then
//! `cipher_compatibility = 4`, `foreign_keys = ON`, `journal_mode = WAL`, `secure_delete = ON`,
//! `temp_store = MEMORY`, then a read of `sqlite_master`; a wrong key fails there with `SQLITE_NOTADB`, which is
//! reported as [`VaultError::WrongKey`].
//!
//! Schema versioning (spec 2.4): `meta.schema_version` and `meta.min_app_schema` are compared with this build's
//! [`CURRENT_SCHEMA`](super::CURRENT_SCHEMA) on open.
//! - Older database: a byte copy of the still-encrypted file goes to `vault.db.bak-v<old>` (0600, after a WAL
//!   checkpoint; the last two backups are kept), then every step `v → v+1` runs in order in its own savepoint
//!   inside one transaction that also writes the new versions, so a failure rolls everything back and the database
//!   stays at the old version (the backup is kept, the error is [`VaultError::MigrationFailed`]).
//! - Equal: normal.
//! - Newer (or `min_app_schema` above this build): opened read-only (`SQLITE_OPEN_READONLY` + `query_only`) when
//!   every table and column this build knows can still be read; every write is refused with
//!   [`VaultError::NewerSchema`]. When it cannot be read, opening fails with the same error. A migration is never
//!   needed to read an older database, and an older build never writes to a newer one.
//!
//! Files: the directory is a real directory (no symlink) owned by the user and 0700; `vault.db` is created by us
//! first (`create_new`, 0600, `O_NOFOLLOW`) and only then opened by SQLite, which gives the `-wal` and `-shm` files
//! the main file's mode, so no umask change is needed. `open` refuses a `vault.db` that is not a regular 0600 file
//! of the user.

use super::backup::InvalidBackup;
use super::keys::Dek;
use super::schema::{MIGRATIONS, Migration};
use super::tree::TreeError;
use crate::date::Date;
use crate::store::write_private;
use rusqlite::config::DbConfig;
use rusqlite::{Connection, ErrorCode, OpenFlags, OptionalExtension, TransactionBehavior};
use std::fmt;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, ErrorKind};
use std::ops::Deref;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub const VAULT_FILE: &str = "vault.db";
/// `vault.db.bak-v<old version>`, written before a migration.
const BACKUP_PREFIX: &str = "vault.db.bak-v";
/// How many pre-migration backups are kept.
const BACKUPS_KEPT: usize = 2;

/// What went wrong with the vault. No variant carries key material or row contents.
#[derive(Debug)]
pub enum VaultError {
    /// The vault is locked (no open database).
    Locked,
    /// The key does not open the database (or the file is not a vault at all; SQLCipher cannot tell).
    WrongKey,
    Corrupt(String),
    /// Written by a newer MacVPN (`db`) than this build knows (`app`): read-only, or not readable at all. The UI
    /// says "This data was saved by a newer MacVPN — update the app to make changes".
    NewerSchema {
        db: u32,
        app: u32,
    },
    /// A schema migration `from → to` failed and was rolled back; the database is still at `from` and the
    /// pre-migration backup is kept.
    MigrationFailed {
        from: u32,
        to: u32,
        detail: String,
    },
    /// A constraint failed (foreign key, unique, not null).
    Constraint(String),
    /// A folder edit was refused (a cycle, an unknown folder, an invalid name).
    Tree(TreeError),
    /// A username or password write to an item linked to a shared credential through the editors' path
    /// ([`Vault::set_item_secret`]): the shared credential is changed in the Credentials section (or by the
    /// credential prompt's "Save"), never by editing one connection.
    LinkedToCredential,
    /// A backup payload a restore refuses (which part, never its value).
    InvalidBackup(InvalidBackup),
    Io(io::Error),
    Sql(String),
    /// The 1.1 data waits for its migration (the app's legacy read-only mode): the new vault takes no write but the
    /// migration's own (and a first-run restore's), so nothing can block the migration.
    ReadOnly,
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::Locked => f.write_str("the vault is locked"),
            VaultError::WrongKey => f.write_str("the key does not open the vault"),
            VaultError::Corrupt(detail) => write!(f, "the vault is damaged ({detail})"),
            VaultError::NewerSchema { db, app } => write!(
                f,
                "this data was saved by a newer MacVPN (vault schema {db}, this app knows {app}); update the app to make changes"
            ),
            VaultError::MigrationFailed { from, to, detail } => write!(
                f,
                "updating the vault from schema {from} to {to} failed and was undone; the vault is unchanged and a backup was kept ({detail})"
            ),
            VaultError::Constraint(detail) => write!(f, "vault constraint failed ({detail})"),
            VaultError::Tree(e) => e.fmt(f),
            VaultError::LinkedToCredential => {
                f.write_str("the user name and password of this item come from a shared credential")
            }
            VaultError::InvalidBackup(e) => e.fmt(f),
            VaultError::Io(e) => write!(f, "vault file error: {e}"),
            VaultError::Sql(detail) => write!(f, "vault database error ({detail})"),
            VaultError::ReadOnly => f.write_str("the vault is read-only until the migration of the old data finishes"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<TreeError> for VaultError {
    fn from(e: TreeError) -> Self {
        VaultError::Tree(e)
    }
}

impl From<io::Error> for VaultError {
    fn from(e: io::Error) -> Self {
        VaultError::Io(e)
    }
}

impl From<rusqlite::Error> for VaultError {
    fn from(e: rusqlite::Error) -> Self {
        match &e {
            rusqlite::Error::SqliteFailure(failure, message) => match failure.code {
                ErrorCode::ConstraintViolation => {
                    VaultError::Constraint(message.clone().unwrap_or_else(|| e.to_string()))
                }
                ErrorCode::NotADatabase | ErrorCode::DatabaseCorrupt => VaultError::Corrupt(e.to_string()),
                _ => VaultError::Sql(e.to_string()),
            },
            _ => VaultError::Sql(e.to_string()),
        }
    }
}

/// During the open sequence `SQLITE_NOTADB` means the key is wrong.
fn keyed(e: rusqlite::Error) -> VaultError {
    if e.sqlite_error_code() == Some(ErrorCode::NotADatabase) { VaultError::WrongKey } else { e.into() }
}

/// A write transaction ([`Vault::transaction`]); dereferences to the connection for statements.
pub struct Tx<'a>(rusqlite::Transaction<'a>);

impl Deref for Tx<'_> {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        &self.0
    }
}

/// An open, unlocked vault.
pub struct Vault {
    conn: Connection,
    /// The stored schema version.
    schema: u32,
    /// `Some(app schema)` when the database is newer than this build: opened read-only.
    read_only_for: Option<u32>,
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault").finish_non_exhaustive()
    }
}

impl Vault {
    /// Creates `<dir>/vault.db` (the directory 0700 if missing) with schema v1. Fails if the file exists.
    pub fn create(dir: &Path, dek: &Dek) -> Result<Vault, VaultError> {
        let dir_uid = prepare_dir(dir)?;
        let path = dir.join(VAULT_FILE);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)?;
        // The new file belongs to this process's user: the directory must too.
        let own_uid = file.metadata()?.uid();
        drop(file);
        let result = (|| {
            if dir_uid != own_uid {
                return Err(not_ours(dir));
            }
            let mut conn = connect(&path, dek, Access::ReadWrite)?;
            migrate(&mut conn, MIGRATIONS, 0)?;
            Ok(Vault { conn, schema: latest(MIGRATIONS), read_only_for: None })
        })();
        if result.is_err() {
            for suffix in ["", "-wal", "-shm", "-journal"] {
                let _ = fs::remove_file(sidecar(&path, suffix));
            }
        }
        result
    }

    /// Opens an existing vault and brings its schema up to date.
    pub fn open(dir: &Path, dek: &Dek) -> Result<Vault, VaultError> {
        Self::open_with_migrations(dir, dek, MIGRATIONS)
    }

    /// The migrations of this build.
    pub fn migrations() -> &'static [Migration] {
        MIGRATIONS
    }

    /// [`Vault::open`] with another migration list (tests of the runner).
    #[doc(hidden)]
    pub fn open_with_migrations(dir: &Path, dek: &Dek, migrations: &[Migration]) -> Result<Vault, VaultError> {
        // No `getuid` without `unsafe` here: the file and the directory must have the same owner, the directory is
        // ours to the extent that we could create or open it 0700, and the file must be 0600.
        let dir_uid = prepare_dir(dir)?;
        let path = dir.join(VAULT_FILE);
        let meta = fs::symlink_metadata(&path)?;
        if !meta.file_type().is_file() || meta.uid() != dir_uid || meta.mode() & 0o7777 != 0o600 {
            return Err(VaultError::Io(io::Error::new(
                ErrorKind::PermissionDenied,
                format!("{} must be a regular 0600 file of this user", path.display()),
            )));
        }
        let app = latest(migrations);
        // The versions are read without changing anything (no journal-mode switch, no write).
        let (db, min_app) = {
            let probe = connect(&path, dek, Access::Probe)?;
            stored_versions(&probe)?
        };
        if db > app || min_app > app {
            let conn = connect(&path, dek, Access::ReadOnly)?;
            if !readable(&conn, migrations) {
                return Err(VaultError::NewerSchema { db, app });
            }
            return Ok(Vault { conn, schema: db, read_only_for: Some(app) });
        }
        let mut conn = connect(&path, dek, Access::ReadWrite)?;
        if db < app {
            if db > 0 {
                backup(&conn, &path, db)?;
            }
            migrate(&mut conn, migrations, db)?;
        }
        Ok(Vault { conn, schema: app, read_only_for: None })
    }

    /// Whether the database was written by a newer MacVPN and is open read-only.
    pub fn is_read_only(&self) -> bool {
        self.read_only_for.is_some()
    }

    /// The database's schema version.
    pub fn schema_version(&self) -> u32 {
        self.schema
    }

    /// Runs `f` in one `BEGIN IMMEDIATE` transaction: committed if `f` succeeds, rolled back otherwise. Every write
    /// goes through here, so a read-only (newer) database refuses all of them with [`VaultError::NewerSchema`].
    pub fn transaction<R>(&mut self, f: impl FnOnce(&Tx<'_>) -> Result<R, VaultError>) -> Result<R, VaultError> {
        if let Some(app) = self.read_only_for {
            return Err(VaultError::NewerSchema { db: self.schema, app });
        }
        let tx = Tx(self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?);
        let result = f(&tx)?;
        tx.0.commit()?;
        Ok(result)
    }

    /// Closes the database (checkpointing the WAL).
    pub fn close(self) {
        let _ = self.conn.close();
    }

    /// The raw connection, for reads in tests and in the repositories.
    #[doc(hidden)]
    pub fn connection(&self) -> &Connection {
        &self.conn
    }
}

/// Opens the file with SQLite and runs the key and pragma sequence. SQLite gets the canonical path because
/// `SQLITE_OPEN_NOFOLLOW` refuses a symlink anywhere in the path (`/var` → `/private/var`, a symlinked home); the
/// directory itself was already checked not to be a symlink, and the file is not followed if it is one.
fn connect(path: &Path, dek: &Dek, access: Access) -> Result<Connection, VaultError> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let name = path.file_name().ok_or_else(|| io::Error::from(ErrorKind::InvalidInput))?;
    let path = fs::canonicalize(dir)?.join(name);
    let mode =
        if access == Access::ReadOnly { OpenFlags::SQLITE_OPEN_READ_ONLY } else { OpenFlags::SQLITE_OPEN_READ_WRITE };
    let flags = mode | OpenFlags::SQLITE_OPEN_NO_MUTEX | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let conn = Connection::open_with_flags(&path, flags)?;
    if access != Access::ReadWrite {
        // Closing must not checkpoint a hot WAL into the main file of a database this build may not write
        // (security review M3).
        conn.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)?;
    }
    // Wipe SQLCipher's freed memory (key material included) before the key is set.
    conn.execute_batch("PRAGMA cipher_memory_security = ON;")?;
    {
        let hex = dek.hex();
        let mut sql = Zeroizing::new(String::with_capacity(hex.len() + 24));
        sql.push_str("PRAGMA key = \"x'");
        sql.push_str(&hex);
        sql.push_str("'\";");
        // A fixed message: SQLite's own error text could quote the statement, and with it the key.
        conn.execute_batch(&sql).map_err(|e| match keyed(e) {
            VaultError::WrongKey => VaultError::WrongKey,
            _ => VaultError::Sql("setting the vault key failed".into()),
        })?;
    }
    conn.execute_batch("PRAGMA cipher_compatibility = 4; PRAGMA foreign_keys = ON;").map_err(keyed)?;
    if access == Access::ReadWrite {
        let journal: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0)).map_err(keyed)?;
        if !journal.eq_ignore_ascii_case("wal") {
            return Err(VaultError::Sql(format!("journal_mode is {journal}, not wal")));
        }
    }
    conn.execute_batch("PRAGMA secure_delete = ON; PRAGMA temp_store = MEMORY;").map_err(keyed)?;
    if access != Access::ReadWrite {
        conn.execute_batch("PRAGMA query_only = ON;").map_err(keyed)?;
    }
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get::<_, i64>(0)).map_err(keyed)?;
    Ok(conn)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    /// The normal connection: read-write, WAL.
    ReadWrite,
    /// Reads the versions before deciding; opened read-write (a read-only open of a WAL database needs its `-shm`)
    /// but with `query_only`, without the journal-mode switch and with `SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE` (no
    /// checkpoint of a hot WAL on close), so it writes nothing to the main file.
    Probe,
    /// A database of a newer MacVPN: `SQLITE_OPEN_READONLY`, `query_only` and no checkpoint on close.
    ReadOnly,
}

fn latest(migrations: &[Migration]) -> u32 {
    migrations.iter().map(|m| m.version).max().unwrap_or(0)
}

/// `(schema_version, min_app_schema)`; `(0, 0)` for a database without a schema yet. A missing `min_app_schema`
/// (none of this build's databases lack it) counts as the schema version.
fn stored_versions(conn: &Connection) -> Result<(u32, u32), VaultError> {
    let has_meta: i64 =
        conn.query_row("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'meta'", [], |r| r.get(0))?;
    if has_meta == 0 {
        return Ok((0, 0));
    }
    let read = |key: &str| -> Result<Option<u32>, VaultError> {
        let value: Option<Option<String>> =
            conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0)).optional()?;
        match value {
            None => Ok(None),
            Some(v) => v
                .and_then(|v| v.parse::<u32>().ok())
                .map(Some)
                .ok_or_else(|| VaultError::Corrupt(format!("invalid {key}"))),
        }
    };
    let version = read("schema_version")?.ok_or_else(|| VaultError::Corrupt("missing schema_version".into()))?;
    let min_app = read("min_app_schema")?.unwrap_or(version);
    Ok((version, min_app))
}

/// Whether every table and column of this build's schema can be read from `conn`: the schema is built from the
/// migrations in a scratch in-memory database, and each of its tables must exist in `conn` with (at least) the same
/// columns (compared through `PRAGMA table_info`, not a `SELECT`, where SQLite would read an unknown double-quoted
/// column name as a string literal).
fn readable(conn: &Connection, migrations: &[Migration]) -> bool {
    fn columns(c: &Connection, table: &str) -> Option<Vec<String>> {
        let mut stmt = c.prepare("SELECT name FROM pragma_table_info(?1)").ok()?;
        let rows = stmt.query_map([table], |r| r.get::<_, String>(0)).ok()?;
        rows.collect::<Result<Vec<_>, _>>().ok()
    }
    let Ok(scratch) = Connection::open_in_memory() else { return false };
    if migrations.iter().flat_map(|m| m.statements.iter()).any(|s| scratch.execute_batch(s).is_err()) {
        return false;
    }
    let tables: Option<Vec<String>> = scratch
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
        .ok()
        .and_then(|mut stmt| stmt.query_map([], |r| r.get::<_, String>(0)).ok()?.collect::<Result<_, _>>().ok());
    let Some(tables) = tables else { return false };
    tables.iter().all(|table| match (columns(&scratch, table), columns(conn, table)) {
        (Some(wanted), Some(have)) => wanted.iter().all(|c| have.contains(c)),
        _ => false,
    })
}

/// Byte copy of the still-encrypted database to `vault.db.bak-v<version>` (0600, atomic), after a WAL checkpoint
/// so the main file is complete; then only the newest [`BACKUPS_KEPT`] backups are kept.
fn backup(conn: &Connection, path: &Path, version: u32) -> Result<(), VaultError> {
    let (busy, _, _): (i64, i64, i64) =
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
    if busy != 0 {
        return Err(VaultError::Sql("the vault is busy; the pre-migration backup could not be made".into()));
    }
    let dir = path.parent().unwrap_or(Path::new("."));
    let bytes = fs::read(path)?;
    write_private(&bytes, &dir.join(format!("{BACKUP_PREFIX}{version}")))?;
    let mut existing: Vec<(u32, PathBuf)> = fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let v = name.strip_prefix(BACKUP_PREFIX)?.parse::<u32>().ok()?;
            Some((v, e.path()))
        })
        .collect();
    existing.sort_by_key(|e| std::cmp::Reverse(e.0));
    for (_, old) in existing.into_iter().skip(BACKUPS_KEPT) {
        fs::remove_file(old)?;
    }
    Ok(())
}

/// Applies every migration newer than `current` in order, each step in its own savepoint, all inside one
/// transaction that also writes `schema_version` and `min_app_schema` (and, for a new database, `created`): either
/// every step is applied or none is.
fn migrate(conn: &mut Connection, migrations: &[Migration], current: u32) -> Result<(), VaultError> {
    let mut steps: Vec<&Migration> = migrations.iter().filter(|m| m.version > current).collect();
    steps.sort_by_key(|m| m.version);
    let Some(target) = steps.last().map(|m| m.version) else { return Ok(()) };
    let failed = |e: rusqlite::Error| VaultError::MigrationFailed { from: current, to: target, detail: e.to_string() };
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(failed)?;
    for step in &steps {
        let savepoint = format!("migrate_v{}", step.version);
        tx.execute_batch(&format!("SAVEPOINT {savepoint}")).map_err(failed)?;
        for statement in step.statements {
            tx.execute_batch(statement).map_err(failed)?;
        }
        tx.execute_batch(&format!("RELEASE {savepoint}")).map_err(failed)?;
    }
    let set = "INSERT INTO meta(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value";
    tx.execute(set, ["schema_version", &target.to_string()]).map_err(failed)?;
    // An older build must never write to this database: the lowest app schema that may write it is this one.
    tx.execute(set, ["min_app_schema", &target.to_string()]).map_err(failed)?;
    if current == 0 {
        tx.execute("INSERT OR IGNORE INTO meta(key, value) VALUES ('created', ?1)", [Date::now().iso8601()])
            .map_err(failed)?;
    }
    tx.commit().map_err(failed)?;
    Ok(())
}

fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

fn not_ours(dir: &Path) -> VaultError {
    VaultError::Io(io::Error::new(ErrorKind::PermissionDenied, format!("{} is not owned by this user", dir.display())))
}

/// Creates `dir` (0700) if missing, refuses anything but a real directory (a symlink included), tightens its mode
/// to 0700, and returns its owner.
fn prepare_dir(dir: &Path) -> io::Result<u32> {
    if let Some(parent) = dir.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    match DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let not_a_dir = || io::Error::new(ErrorKind::NotADirectory, format!("{} is not a real directory", dir.display()));
    if !fs::symlink_metadata(dir)?.file_type().is_dir() {
        return Err(not_a_dir());
    }
    let handle = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY)
        .open(dir)
        .map_err(|e| if e.raw_os_error() == Some(libc::ELOOP) { not_a_dir() } else { e })?;
    let meta = handle.metadata()?;
    if !meta.file_type().is_dir() {
        return Err(not_a_dir());
    }
    if meta.mode() & 0o7777 != 0o700 {
        handle.set_permissions(fs::Permissions::from_mode(0o700))?;
    }
    Ok(meta.uid())
}
