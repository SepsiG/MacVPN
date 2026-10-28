//! strongSwan (IKEv2) through Homebrew `swanctl` + `charon`. The secrets go into a `secrets {}` block of the
//! root-only config copy (escaped, named after the connection id, bound to the connection's remote ids); the CA /
//! certificates / keys of Homebrew's `etc/swanctl` are copied next to it (see [`stage_creds`]), because `swanctl
//! --load-all --file` reads them only there; `charon` is only started if no root `charon` from the expected binary
//! runs.
//!
//! Several strongSwan connections share one charon, and `swanctl --load-all --file F` (strongSwan 6 `load_conns.c`,
//! `load_creds.c`, `load_pools.c`, `load_authorities.c`) unloads every connection, private key, shared secret, pool
//! and authority charon holds that F does not name. So every load names all active connections: F is the
//! concatenation of their run configs ([`combined`], a transient root-only file), built and loaded under one lock
//! ([`crate::macos::lock::acquire_shared`]); charon's settings parser merges the repeated top-level sections. The
//! names under `connections` / `secrets` / `pools` / `authorities` must therefore differ between the connections
//! ([`first_collision`]), and two generated secrets charon could not tell apart ([`Owner::ambiguous`]) are refused.
//! Down reloads the other active connections, which unloads this one's connection and secrets.

use crate::macos::ctx::{Ctx, R, tr};
use crate::macos::exec::{Cmd, EnvMode};
use crate::macos::fsx;
use crate::macos::paths::is_dir;
use crate::macos::procs;
use macvpn_core::validators::StrongSwanValidator;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// `^[A-Za-z0-9_.-]+$`
pub fn is_name(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

/// `swan_escape`: `\` → `\\`, `"` → `\"`.
pub fn escape(v: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() + 8);
    for &b in v {
        if b == b'\\' || b == b'"' {
            out.push(b'\\');
        }
        out.push(b);
    }
    out
}

/// Appends ` {key} = "{escaped value}"` lines for `ids` (`id-r1`, `id-r2`, …: swanctl takes every key starting
/// with `id` as an owner).
fn owner_lines(b: &mut Vec<u8>, ids: &[String]) {
    for (i, id) in ids.iter().enumerate() {
        b.extend_from_slice(format!("    id-r{} = \"", i + 1).as_bytes());
        b.extend_from_slice(&escape(id.as_bytes()));
        b.extend_from_slice(b"\"\n");
    }
}

/// The `secrets {}` block appended to the config copy: `ike-mvpn-<id>` (the PSK) and `eap-mvpn-<id>` (the EAP
/// user and password), unique per connection, each bound to `remote_ids` ([`StrongSwanValidator::remote_ids`];
/// none: the PSK is charon's `%any`, as before).
pub fn secrets_block(id: &str, user: &[u8], pass: &[u8], psk: &[u8], remote_ids: &[String]) -> Zeroizing<Vec<u8>> {
    let mut b = Zeroizing::new(b"secrets {\n".to_vec());
    if !psk.is_empty() {
        b.extend_from_slice(format!("  ike-mvpn-{id} {{\n    secret = \"").as_bytes());
        b.extend_from_slice(&escape(psk));
        b.extend_from_slice(b"\"\n");
        owner_lines(&mut b, remote_ids);
        b.extend_from_slice(b"  }\n");
    }
    if !pass.is_empty() {
        b.extend_from_slice(format!("  eap-mvpn-{id} {{\n    id = \"").as_bytes());
        b.extend_from_slice(&escape(user));
        b.extend_from_slice(b"\"\n    secret = \"");
        b.extend_from_slice(&escape(pass));
        b.extend_from_slice(b"\"\n");
        owner_lines(&mut b, remote_ids);
        b.extend_from_slice(b"  }\n");
    }
    b.extend_from_slice(b"}\n");
    b
}

/// Who a generated secret belongs to (its owners), kept in `<run>/owners` so a later connection can tell whether
/// charon could confuse their secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Owner {
    /// The PSK, bound to these remote ids (none: `%any`).
    Ike(Vec<String>),
    /// The EAP secret of this user, bound to these remote ids too.
    Eap(Vec<u8>, Vec<String>),
}

impl Owner {
    /// charon (`credential_manager.c` `get_shared`, `mem_cred.c` `has_owner`) takes the secret whose owners match
    /// the remote id best, then the local id; on a tie the first one found. Two PSKs tie if neither is bound or they
    /// share a remote id (a bound PSK beats `%any` for its own id, and does not match another one); two EAP secrets
    /// of the same user (a perfect local match each) tie unless both are bound to different remote ids.
    pub fn ambiguous(&self, other: &Owner) -> bool {
        let shared = |a: &[String], b: &[String]| a.iter().any(|x| b.contains(x));
        match (self, other) {
            (Owner::Ike(a), Owner::Ike(b)) => (a.is_empty() && b.is_empty()) || shared(a, b),
            (Owner::Eap(u, a), Owner::Eap(v, b)) => u == v && (a.is_empty() || b.is_empty() || shared(a, b)),
            _ => false,
        }
    }
}

/// `<run>/owners`: one line per secret, the type and the hex fields separated by tabs.
pub fn owners_text(owners: &[Owner]) -> String {
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let mut out = String::new();
    for o in owners {
        let (kind, user, ids) = match o {
            Owner::Ike(ids) => ("ike", None, ids),
            Owner::Eap(u, ids) => ("eap", Some(u), ids),
        };
        out.push_str(kind);
        for f in user.map(|u| hex(u)).into_iter().chain(ids.iter().map(|i| hex(i.as_bytes()))) {
            out.push('\t');
            out.push_str(&f);
        }
        out.push('\n');
    }
    out
}

/// Reads [`owners_text`]; unknown or malformed lines are skipped.
pub fn parse_owners(text: &str) -> Vec<Owner> {
    let unhex = |f: &str| -> Option<Vec<u8>> {
        if !f.len().is_multiple_of(2) {
            return None;
        }
        (0..f.len()).step_by(2).map(|i| u8::from_str_radix(f.get(i..i + 2)?, 16).ok()).collect()
    };
    let id = |f: &str| unhex(f).and_then(|b| String::from_utf8(b).ok());
    text.lines()
        .filter_map(|l| {
            let mut f = l.split('\t');
            match f.next()? {
                "ike" => Some(Owner::Ike(f.map(id).collect::<Option<_>>()?)),
                "eap" => {
                    let user = unhex(f.next()?)?;
                    Some(Owner::Eap(user, f.map(id).collect::<Option<_>>()?))
                }
                _ => None,
            }
        })
        .collect()
}

/// The first of `own`'s section names ([`StrongSwanValidator::section_names`]) that `other` uses too.
pub fn first_collision(own: &[String], other: &[String]) -> Option<String> {
    own.iter().find(|n| other.contains(n)).cloned()
}

/// The load file: the configs one after the other (each ending in a newline).
pub fn combined(configs: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::new());
    for c in configs {
        out.extend_from_slice(c);
        out.push(b'\n');
    }
    out
}

/// Dead peer detection when the config has none (2026-10-28): swanctl's `dpd_delay` defaults to 0 (off), so a dead
/// server leaves the IKE SA `ESTABLISHED` until its next rekeying. With [`DEFAULT_DPD_DELAY`] charon sends an
/// INFORMATIONAL exchange after that long without traffic from the peer; IKEv2 has no `dpd_timeout` (it is IKEv1's):
/// an unanswered exchange ends after charon's retransmissions (about 165 s by default), the IKE SA is deleted and the
/// child follows its `dpd_action` (default `clear`), so the connection drops and the app reconnects it. A config's
/// own `dpd_delay` (also `0s`) is kept.
pub const DEFAULT_DPD_DELAY: &str = "30s";

/// The section appended to the run copy of the config when connection `conn` sets no `dpd_delay` (`None`: it sets
/// one). strongSwan's settings parser merges sections of the same name, so this only adds the key.
pub fn default_dpd_block(config: &str, conn: &str) -> Option<String> {
    if StrongSwanValidator::conn_sets(config, conn, "dpd_delay") {
        return None;
    }
    Some(format!("\nconnections {{\n  {conn} {{\n    dpd_delay = {DEFAULT_DPD_DELAY}\n  }}\n}}\n"))
}

/// The run directories of the other active strongSwan connections, sorted: `kind` strongswan, a `conn` file
/// (written under the lock just before the load) and no `unloaded` mark (written under the lock by down).
pub fn active_others(run_base: &Path, me: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(run_base) else { return Vec::new() };
    let mut dirs: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
        .map(|e| e.path())
        .filter(|p| p != me && is_real_dir(p))
        .filter(|p| fsx::cat(&p.join("kind")) == "strongswan")
        .filter(|p| p.join("conn").is_file() && !p.join("unloaded").exists())
        .collect();
    dirs.sort();
    dirs
}

/// The credential directories `swanctl --load-all` reads (strongSwan `swanctl.h`, `load_creds.c`). With `--file`
/// swanctl looks for them, and for the files `certs` / `cacerts` / `pubkeys` / `cacert` name, next to that file
/// (`swanctl_dir = dirname(--file)`), not in Homebrew's `etc/swanctl`; and it unloads every private key and shared
/// secret charon holds that it did not load itself. So they are copied into the run directory (see
/// [`stage_creds`]).
pub const CRED_DIRS: [&str; 12] = [
    "x509", "x509ca", "x509ocsp", "x509aa", "x509ac", "x509crl", "pubkey", "private", "rsa", "ecdsa", "pkcs8", "pkcs12",
];
/// A credential file larger than this is skipped (certificates, keys and PKCS#12 containers are a few KB).
pub const CRED_FILE_MAX: u64 = 1 << 20;
/// At most this many credential files are copied (all directories together).
pub const CRED_FILES_MAX: usize = 256;

/// What [`stage_creds`] did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Staged {
    pub copied: usize,
    pub skipped: usize,
}

/// strongSwan's own credential directory in the Homebrew prefix (the formula's `SWANCTLDIR`, `#{etc}/swanctl`).
pub fn cred_source(brew: &Path) -> std::path::PathBuf {
    brew.join("etc/swanctl")
}

/// A real directory: not a symlink, not following one.
fn is_real_dir(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_dir())
}

/// The owner of a credential file or directory may be root, the owner of the Homebrew prefix (Apple silicon:
/// `/opt/homebrew` is the user's), or the owner of `<prefix>/etc` (Intel: `/usr/local` is root's, its `etc` the
/// Homebrew user's; only root or the prefix owner can have made it). Anyone else is refused.
fn trusted_owner(uid: u32, prefix: u32, etc: u32) -> bool {
    uid == 0 || uid == prefix || uid == etc
}

/// Opens a directory: the prefix by path (its last component never a symlink), the rest one name at a time.
fn open_dir(p: &Path) -> Option<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(p)
        .ok()
}

/// A plain regular file of `dir` (no symlink followed, a single link, a trusted owner, at most
/// [`CRED_FILE_MAX`] bytes), read whole through the descriptor that was checked.
fn read_cred(dir: &std::fs::File, name: &std::ffi::OsStr, trusted: &dyn Fn(u32) -> bool) -> Option<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    let mut f = crate::macos::sys::open_at(dir, name, false).ok()?;
    let m = f.metadata().ok()?;
    if !m.file_type().is_file() || m.nlink() != 1 || !trusted(m.uid()) || m.len() > CRED_FILE_MAX {
        return None;
    }
    let mut data = Vec::with_capacity(m.len() as usize);
    (&mut f).take(CRED_FILE_MAX + 1).read_to_end(&mut data).ok()?;
    (data.len() as u64 <= CRED_FILE_MAX).then_some(data)
}

/// Copies the credentials of Homebrew's `etc/swanctl` (under the prefix `brew`) into `run`, where `swanctl
/// --load-all --file <run>/config` reads them: for each of [`CRED_DIRS`] that is a real directory there,
/// `<run>/<dir>` (0700, new) with a copy (0600, new) of each regular file whose name is a plain file name
/// (`[A-Za-z0-9_.-]`, no leading `.`, the validator's rule for `certs = …`), at most [`CRED_FILE_MAX`] bytes,
/// [`CRED_FILES_MAX`] files in all; nothing else of the source (`swanctl.conf`, other directories) is read.
///
/// Root reads a directory the Homebrew user controls, so (L-7): every level (`<prefix>`, `etc`, `swanctl`, the
/// credential directory, the file) is opened through its parent's descriptor with `O_NOFOLLOW` (a symlink anywhere
/// is not followed, and a swap after a check has no effect); a file must have a single link (no hard link to a
/// file elsewhere) and every directory and file a trusted owner ([`trusted_owner`]). What is refused is skipped.
/// The run directory is removed at down, so the copies (private keys too) live only while the connection does.
pub fn stage_creds(brew: &Path, run: &Path) -> std::io::Result<Staged> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};
    let mut n = Staged::default();
    let Some(prefix) = open_dir(brew) else { return Ok(n) };
    let Some(prefix_uid) = prefix.metadata().ok().map(|m| m.uid()) else { return Ok(n) };
    let Ok(etc) = crate::macos::sys::open_at(&prefix, "etc".as_ref(), true) else { return Ok(n) };
    let Some(etc_uid) = etc.metadata().ok().map(|m| m.uid()) else { return Ok(n) };
    let trusted = |uid: u32| trusted_owner(uid, prefix_uid, etc_uid);
    let owned = |f: &std::fs::File| f.metadata().is_ok_and(|m| m.file_type().is_dir() && trusted(m.uid()));
    let Ok(src) = crate::macos::sys::open_at(&etc, "swanctl".as_ref(), true) else { return Ok(n) };
    if !owned(&src) {
        return Ok(n);
    }
    for dir in CRED_DIRS {
        let Ok(from) = crate::macos::sys::open_at(&src, dir.as_ref(), true) else { continue };
        if !owned(&from) {
            continue;
        }
        let Ok(mut names) = crate::macos::sys::list_dir(&from) else { continue };
        names.sort();
        let to = run.join(dir);
        std::fs::DirBuilder::new().mode(0o700).create(&to)?;
        fsx::chmod(&to, 0o700)?;
        for name in names {
            let plain = name.to_str().is_some_and(|s| is_name(s) && !s.starts_with('.'));
            let data = if plain && n.copied < CRED_FILES_MAX {
                read_cred(&from, &name, &trusted).map(zeroize::Zeroizing::new)
            } else {
                None
            };
            let Some(data) = data else {
                n.skipped += 1;
                continue;
            };
            let dst = to.join(&name);
            fsx::create_new(&dst, &data, 0o600)?;
            fsx::chmod(&dst, 0o600)?;
            n.copied += 1;
        }
    }
    Ok(n)
}

/// `swanctl --load-all --noprompt --file <file>`: the root layer never waits for a key password on a terminal (an
/// encrypted key that has no configured secret is skipped by swanctl).
pub fn load_all_cmd(swanctl: &Path, file: &Path) -> Cmd {
    Cmd::new(swanctl).args(["--load-all", "--noprompt", "--file"]).arg(file)
}

/// `swanctl --initiate --child <child> --ike <conn>`: the child of this connection's own IKE config (another
/// active connection may have a child of the same name).
pub fn initiate_cmd(swanctl: &Path, conn: &str, child: &str, lvl: &str) -> Cmd {
    Cmd::new(swanctl).args(["--initiate", "--child", child, "--ike", conn, "--timeout", "30", "--loglevel", lvl])
}

/// The largest run config read back for a load (the config and the secrets block).
const LOAD_PART_MAX: u64 = crate::macos::paths::SRC_MAX + (64 << 10);

/// Loads `configs` (run directories; their `config`) as one file `<run>/load.conf` (0600, removed right after),
/// next to this run's credential copies. `false`: not written or swanctl failed.
fn load_together(ctx: &Ctx, swanctl: &Path, configs: &[PathBuf]) -> R<bool> {
    let run = ctx.run().to_path_buf();
    let file = run.join("load.conf");
    if ctx.dry() {
        return ctx.run_logged(&load_all_cmd(swanctl, &file));
    }
    let mut parts = Vec::new();
    for d in configs {
        // A config that cannot be read (its connection is going away) is left out.
        if let Some(c) = fsx::read_private(&d.join("config"), LOAD_PART_MAX) {
            parts.push(Zeroizing::new(c));
        }
    }
    let data = combined(&parts.iter().map(|p| p.as_slice()).collect::<Vec<_>>());
    fsx::remove_file(&file);
    if fsx::create_new(&file, &data, 0o600).is_err() {
        fsx::remove_file(&file);
        return Ok(false);
    }
    let ok = ctx.run_logged(&load_all_cmd(swanctl, &file));
    fsx::remove_file(&file);
    ok
}

/// The section names of a run's config (see [`StrongSwanValidator::section_names`]).
fn run_section_names(run: &Path) -> Vec<String> {
    fsx::read_private(&run.join("config"), LOAD_PART_MAX)
        .map(Zeroizing::new)
        .map(|c| StrongSwanValidator::section_names(&String::from_utf8_lossy(&c)))
        .unwrap_or_default()
}

/// A failed EAP sign-in in swanctl / charon output: `EAP_FAILURE`, or `EAP method … failed` on one line.
pub fn is_eap_failure(out: &[u8]) -> bool {
    crate::shared::mask::lines(out).any(|l| {
        crate::shared::mask::find(l, b"EAP_FAILURE").is_some()
            || crate::shared::mask::find(l, b"EAP method ")
                .is_some_and(|i| crate::shared::mask::find(&l[i + b"EAP method ".len()..], b" failed").is_some())
    })
}

/// `charon_pids`: root-owned `charon` processes (`pgrep -U 0 -x charon`) started from the expected binary (the
/// `ps` comm is the start path). Another user's or another path's `charon` is not ours.
pub fn charon_pids(charon: &Path) -> Vec<String> {
    let path = charon.display().to_string();
    let real = std::fs::canonicalize(charon).ok().map(|p| p.display().to_string());
    procs::pgrep(&["-U", "0", "-x", "charon"])
        .into_iter()
        .filter(|p| procs::comm(p).is_some_and(|c| c == path || real.as_deref() == Some(c.as_str())))
        .collect()
}

/// `up_strongswan`
pub fn up(ctx: &mut Ctx) -> R {
    let Some(swanctl) = ctx.find_tool("swanctl") else {
        return Err(ctx.die(tr("swanctl not found (brew install strongswan)", &[])));
    };
    let Some(charon) = ctx.find_charon() else {
        return Err(ctx.die(tr("charon not found (brew install strongswan)", &[])));
    };
    let run = ctx.run().to_path_buf();
    let (conn, child) = crate::macos::validate::swan_names(&run.join("config")).unwrap_or_default();
    if !is_name(&conn) {
        return Err(ctx.die(tr("No connection name found", &[])));
    }
    if !is_name(&child) {
        return Err(ctx.die(tr("No child name found", &[])));
    }
    let own_names = run_section_names(&run);
    // Dead peer detection unless the config sets its own (the user's config, validated; read back from the run copy).
    if let Some(text) = fsx::read_private(&run.join("config"), LOAD_PART_MAX).map(Zeroizing::new)
        && let Some(block) = default_dpd_block(&String::from_utf8_lossy(&text), &conn)
    {
        let _ = fsx::append(&run.join("config"), block.as_bytes());
        ctx.log.step(&tr("dead peer detection added (dpd_delay = %@)", &[DEFAULT_DPD_DELAY]));
    }
    let mut owners = Vec::new();
    if !ctx.secrets.psk.is_empty() || !ctx.secrets.pass.is_empty() {
        let text = fsx::read_private(&run.join("config"), LOAD_PART_MAX).map(Zeroizing::new).unwrap_or_default();
        let ids = StrongSwanValidator::remote_ids(&String::from_utf8_lossy(&text), &conn);
        if !ctx.secrets.psk.is_empty() {
            owners.push(Owner::Ike(ids.clone()));
        }
        if !ctx.secrets.pass.is_empty() {
            owners.push(Owner::Eap(ctx.secrets.user.to_vec(), ids.clone()));
        }
        let block = secrets_block(&ctx.id, &ctx.secrets.user, &ctx.secrets.pass, &ctx.secrets.psk, &ids);
        let _ = fsx::append(&run.join("config"), &block);
        let _ = fsx::write_file(&run.join("owners"), owners_text(&owners).as_bytes(), 0o600);
        ctx.log.step(&tr("secrets block added (masked)", &[]));
    }
    // charon does not daemonize: started in the background, without the caller's pipes.
    if ctx.dry() || charon_pids(&charon).is_empty() {
        ctx.run_bg(&Cmd::new(&charon))?;
        if !ctx.dry() {
            for _ in 0..10 {
                if crate::macos::exec::quiet(&Cmd::new(&swanctl).arg("--stats"), ctx.env_mode()) {
                    break;
                }
                ctx.sleep_ms(500)?;
            }
        }
    }
    // The CA / certificates / keys go next to the config, where `--load-all --file` reads them.
    if !ctx.dry()
        && let Some(brew) = ctx.s.brew.clone()
    {
        let src = cred_source(&brew);
        match stage_creds(&brew, &run) {
            Ok(n) => ctx.log.step(&tr(
                "strongSwan credentials copied from %@: %@ (skipped: %@)",
                &[&src.display().to_string(), &n.copied.to_string(), &n.skipped.to_string()],
            )),
            Err(_) => {
                fsx::remove_rf(&run);
                return Err(ctx.die(tr("Cannot create: %@", &[&run.display().to_string()])));
            }
        }
    }
    {
        // What charon holds is shared: checked and loaded under one lock, with every active connection.
        let _guard = if ctx.dry() { None } else { Some(crate::macos::lock::acquire_shared(ctx, "strongswan")?) };
        let others = if ctx.dry() { Vec::new() } else { active_others(&ctx.s.run_base, &run) };
        for o in &others {
            if let Some(name) = first_collision(&own_names, &run_section_names(o)) {
                fsx::remove_rf(&run);
                return Err(ctx.die(tr("Another active strongSwan connection already defines %@", &[&name])));
            }
            let theirs = parse_owners(&fsx::read_trim(&o.join("owners")).unwrap_or_default());
            if owners.iter().any(|m| theirs.iter().any(|t| m.ambiguous(t))) {
                fsx::remove_rf(&run);
                return Err(ctx.die(tr(
                    "Another active strongSwan connection already has a secret for the same identities (set a different remote id)",
                    &[],
                )));
            }
        }
        // From here on this connection is active (its `conn`): down terminates it and the next load includes it.
        let _ = fsx::write_line(&run.join("conn"), &conn);
        let mut configs = others;
        configs.push(run.clone());
        if !load_together(ctx, &swanctl, &configs)? {
            if !ctx.dry() {
                fsx::remove_rf(&run);
            }
            return Err(ctx.die(tr("swanctl --load-all failed", &[])));
        }
    }
    let lvl = if ctx.a.debug { "2" } else { "1" };
    let initiate = initiate_cmd(&swanctl, &conn, &child, lvl);
    // The EAP verdict comes from swanctl's own (masked) output stream, not from the user-writable log.
    let (initiated, eap) = ctx.run_logged_scan(&initiate, is_eap_failure)?;
    if !initiated {
        ctx.run_logged(&Cmd::new(&swanctl).args(["--terminate", "--ike", &conn, "--timeout", "5"]))?;
        if !ctx.dry() {
            unload(ctx, &swanctl)?;
            fsx::remove_rf(&run);
        }
        if eap {
            return Err(ctx.die(tr("Authentication failed (EAP)", &[])));
        }
        return Err(ctx.die(tr("IKE negotiation failed (details in the log)", &[])));
    }
    Ok(())
}

/// Marks this connection `unloaded` and reloads the other active ones, which unloads its connection, secrets and
/// keys from charon (nothing to do without others: charon is stopped then). Under the shared lock.
fn unload(ctx: &Ctx, swanctl: &Path) -> R {
    let _guard = crate::macos::lock::acquire_shared(ctx, "strongswan")?;
    let run = ctx.run().to_path_buf();
    let _ = fsx::write_file(&run.join("unloaded"), b"", 0o600);
    let others = active_others(&ctx.s.run_base, &run);
    if !others.is_empty() && run.join("conn").is_file() {
        ctx.log.step(&tr("reloading the other strongSwan connections", &[]));
        let _ = load_together(ctx, swanctl, &others)?;
    }
    Ok(())
}

/// `down_strongswan`: charon is only stopped if no other strongSwan connection runs.
pub fn down(ctx: &mut Ctx) -> R<bool> {
    if !is_dir(ctx.run()) {
        ctx.no_running();
        return Ok(true);
    }
    let Some(swanctl) = ctx.find_tool("swanctl") else {
        return Err(ctx.die(tr("swanctl not found", &[])));
    };
    let conn = fsx::cat(&ctx.run().join("conn"));
    if is_name(&conn) {
        ctx.run_logged(&Cmd::new(&swanctl).args(["--terminate", "--ike", &conn, "--timeout", "10"]))?;
    }
    if !ctx.dry() {
        unload(ctx, &swanctl)?;
    }
    if others_running(ctx) == 0
        && !ctx.dry()
        && let Some(charon) = ctx.find_charon()
    {
        for p in charon_pids(&charon) {
            ctx.log.cmd(&format!("kill {p}"));
            procs::signal(&p, crate::macos::sys::SIGTERM);
        }
    }
    Ok(true)
}

/// Other run directories whose `kind` is strongswan (`grep -lx strongswan $RUN_BASE/*/kind`, this one excluded).
fn others_running(ctx: &Ctx) -> usize {
    let Ok(entries) = std::fs::read_dir(&ctx.s.run_base) else { return 0 };
    entries
        .filter_map(Result::ok)
        .filter(|e| !e.file_name().to_string_lossy().starts_with('.'))
        .filter(|e| e.path() != ctx.run())
        .filter(|e| {
            std::fs::read(e.path().join("kind"))
                .map(|d| d.split(|&b| b == b'\n').any(|l| l == b"strongswan"))
                .unwrap_or(false)
        })
        .count()
}

/// Whether swanctl reports the IKE SA (`status`): `Some("connected")`, `Some("connecting")` or `None`.
pub fn sa_state(swanctl: &Path, conn: &str, mode: EnvMode) -> Option<&'static str> {
    let (_, out) = crate::macos::exec::capture(&Cmd::new(swanctl).args(["--list-sas", "--ike", conn]), mode, 1 << 20)?;
    if crate::shared::mask::find(&out, b"ESTABLISHED").is_some() {
        Some("connected")
    } else if crate::shared::mask::find(&out, b"CONNECTING").is_some() {
        Some("connecting")
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "6C7B5599-9608-4703-8F4D-10114DDD4B26";

    #[test]
    fn secrets_block_is_escaped_and_named_after_the_connection() {
        let b = secrets_block(ID, b"al\"ice", b"p\\w", b"k\"y", &[]);
        assert_eq!(
            String::from_utf8(b.to_vec()).unwrap(),
            format!(
                "secrets {{\n  ike-mvpn-{ID} {{\n    secret = \"k\\\"y\"\n  }}\n  eap-mvpn-{ID} {{\n    id = \"al\\\"ice\"\n    secret = \"p\\\\w\"\n  }}\n}}\n"
            )
        );
        assert_eq!(
            secrets_block(ID, b"", b"", b"psk", &[]).to_vec(),
            format!("secrets {{\n  ike-mvpn-{ID} {{\n    secret = \"psk\"\n  }}\n}}\n").into_bytes()
        );
    }

    #[test]
    fn secrets_are_bound_to_the_concrete_remote_ids() {
        let ids = ["lab.example".to_string(), "C=CH, CN=vpn".to_string()];
        let b = secrets_block(ID, b"labuser", b"pw", b"psk", &ids);
        assert_eq!(
            String::from_utf8(b.to_vec()).unwrap(),
            format!(
                "secrets {{\n  ike-mvpn-{ID} {{\n    secret = \"psk\"\n    id-r1 = \"lab.example\"\n    id-r2 = \"C=CH, CN=vpn\"\n  }}\n  eap-mvpn-{ID} {{\n    id = \"labuser\"\n    secret = \"pw\"\n    id-r1 = \"lab.example\"\n    id-r2 = \"C=CH, CN=vpn\"\n  }}\n}}\n"
            )
        );
    }

    #[test]
    fn owners_round_trip_through_the_run_file() {
        let o = vec![
            Owner::Ike(vec!["lab.example".into(), "C=CH, CN=vpn".into()]),
            Owner::Eap(b"lab\tuser \xff".to_vec(), vec![]),
        ];
        assert_eq!(parse_owners(&owners_text(&o)), o);
        assert_eq!(parse_owners(""), []);
        assert_eq!(parse_owners("bogus\nike\n"), [Owner::Ike(vec![])]);
    }

    #[test]
    fn two_secrets_are_ambiguous_when_charon_would_rank_them_equal() {
        let ike = |ids: &[&str]| Owner::Ike(ids.iter().map(|s| s.to_string()).collect());
        let eap =
            |u: &str, ids: &[&str]| Owner::Eap(u.as_bytes().to_vec(), ids.iter().map(|s| s.to_string()).collect());
        // credential_manager get_shared: the remote match first, then the local one; ties keep the first found.
        assert!(ike(&[]).ambiguous(&ike(&[])));
        assert!(ike(&["a"]).ambiguous(&ike(&["a"])));
        assert!(ike(&["a", "b"]).ambiguous(&ike(&["b"])));
        assert!(!ike(&["a"]).ambiguous(&ike(&["b"])));
        assert!(!ike(&["a"]).ambiguous(&ike(&[])));
        assert!(!ike(&[]).ambiguous(&ike(&["a"])));
        assert!(eap("u", &[]).ambiguous(&eap("u", &[])));
        assert!(eap("u", &["a"]).ambiguous(&eap("u", &[])));
        assert!(eap("u", &["a"]).ambiguous(&eap("u", &["a"])));
        assert!(!eap("u", &["a"]).ambiguous(&eap("u", &["b"])));
        assert!(!eap("u", &[]).ambiguous(&eap("v", &[])));
        assert!(!ike(&[]).ambiguous(&eap("u", &[])));
    }

    #[test]
    fn dead_peer_detection_is_added_only_when_the_config_has_none() {
        let without = "connections {\n  lab {\n    remote_addrs = vpn.example\n    children {\n      net {\n        dpd_action = clear\n      }\n    }\n  }\n}\n";
        let block = default_dpd_block(without, "lab").unwrap();
        assert_eq!(block, "\nconnections {\n  lab {\n    dpd_delay = 30s\n  }\n}\n");
        let merged = format!("{without}{block}");
        use macvpn_core::validators::ConfigValidator;
        assert!(StrongSwanValidator.validate(&merged).is_empty(), "the appended section is a valid config");
        assert!(StrongSwanValidator::conn_sets(&merged, "lab", "dpd_delay"));
        assert_eq!(StrongSwanValidator::names(&merged), Some(("lab".into(), "net".into())), "the names stay");
        let own = without.replace("remote_addrs = vpn.example", "remote_addrs = vpn.example\n    dpd_delay = 0s");
        assert_eq!(default_dpd_block(&own, "lab"), None, "the config's own value stays");
        // Another connection's or a child's key does not count.
        let other = format!(
            "{without}connections {{\n  other {{\n    dpd_delay = 10s\n    children {{\n      x {{\n      }}\n    }}\n  }}\n}}\n"
        );
        assert!(default_dpd_block(&other, "lab").is_some());
    }

    #[test]
    fn the_load_file_holds_every_config_in_order() {
        let c = combined(&[b"a {\n}".as_slice(), b"b {\n}\n".as_slice()]);
        assert_eq!(c.as_slice(), b"a {\n}\nb {\n}\n\n");
    }

    #[test]
    fn a_shared_name_is_a_collision() {
        let own = ["connections.a".to_string(), "secrets.ike-mvpn-1".to_string()];
        assert_eq!(first_collision(&own, &["pools.p".into(), "connections.a".into()]), Some("connections.a".into()));
        assert_eq!(first_collision(&own, &["connections.b".into()]), None);
    }

    #[test]
    fn the_active_others_are_loaded_strongswan_runs_but_this_one() {
        let base = tmp();
        let mk = |name: &str, kind: &str, conn: bool, unloaded: bool| {
            let d = base.join(name);
            std::fs::create_dir(&d).unwrap();
            std::fs::write(d.join("kind"), format!("{kind}\n")).unwrap();
            if conn {
                std::fs::write(d.join("conn"), "x\n").unwrap();
            }
            if unloaded {
                std::fs::write(d.join("unloaded"), "").unwrap();
            }
            d
        };
        let me = mk("me", "strongswan", true, false);
        let b = mk("b", "strongswan", true, false);
        let a = mk("a", "strongswan", true, false);
        mk("c", "openvpn", true, false);
        mk("d", "strongswan", false, false);
        mk("e", "strongswan", true, true);
        mk(".x.lock", "strongswan", true, false);
        assert_eq!(active_others(&base, &me), [a, b]);
        assert_eq!(active_others(&base.join("nonexistent"), &me), Vec::<std::path::PathBuf>::new());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn initiate_names_the_ike_config_of_the_child() {
        let c = initiate_cmd(Path::new("/s/swanctl"), "lab-eap", "net", "1");
        assert_eq!(c.display(), "/s/swanctl --initiate --child net --ike lab-eap --timeout 30 --loglevel 1");
    }

    #[test]
    fn eap_failures() {
        assert!(is_eap_failure(b"[IKE] received EAP_FAILURE, EAP authentication failed\n"));
        assert!(is_eap_failure(b"x\n[IKE] EAP method EAP_MSCHAPV2 failed for peer 10.0.0.1\ny\n"));
        assert!(is_eap_failure(b"EAP method EAP_PEAP (id 0x02) failed"));
        assert!(!is_eap_failure(b"[IKE] establishing CHILD_SA office-net failed\n"));
        assert!(!is_eap_failure(b"EAP method\n failed\n"));
        assert!(!is_eap_failure(b"initiate failed: establishing CHILD_SA 'office-net' failed\n"));
        assert!(!is_eap_failure(b""));
    }

    fn tmp() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("mvpn-swan-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&p).unwrap();
        p
    }

    fn mode(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn the_credential_directories_are_swanctls_own() {
        // strongSwan 6 swanctl.h / load_creds.c: every directory `--load-all` reads next to its `--file`.
        assert_eq!(
            CRED_DIRS,
            [
                "x509", "x509ca", "x509ocsp", "x509aa", "x509ac", "x509crl", "pubkey", "private", "rsa", "ecdsa",
                "pkcs8", "pkcs12"
            ]
        );
    }

    /// A fake Homebrew prefix with `etc/swanctl`: (prefix, swanctl directory).
    fn brew() -> (PathBuf, PathBuf) {
        let b = tmp();
        let src = cred_source(&b);
        std::fs::create_dir_all(&src).unwrap();
        (b, src)
    }

    #[test]
    fn credentials_are_copied_next_to_the_config_root_only() {
        let ((b, src), run) = (brew(), tmp());
        for d in ["x509ca", "x509", "private", "pkcs12"] {
            std::fs::create_dir(src.join(d)).unwrap();
        }
        std::fs::write(src.join("x509ca/ca.pem"), b"CA").unwrap();
        std::fs::write(src.join("x509/client.pem"), b"CERT").unwrap();
        std::fs::write(src.join("private/client.key"), b"KEY").unwrap();
        std::fs::write(src.join("pkcs12/c.p12"), b"P12").unwrap();
        let n = stage_creds(&b, &run).unwrap();
        assert_eq!(n, Staged { copied: 4, skipped: 0 });
        for (d, f, data) in [
            ("x509ca", "ca.pem", &b"CA"[..]),
            ("x509", "client.pem", b"CERT"),
            ("private", "client.key", b"KEY"),
            ("pkcs12", "c.p12", b"P12"),
        ] {
            assert_eq!(mode(&run.join(d)), 0o700, "{d}");
            assert_eq!(mode(&run.join(d).join(f)), 0o600, "{d}/{f}");
            assert_eq!(std::fs::read(run.join(d).join(f)).unwrap(), data);
        }
        // Directories that are missing in the source are not created.
        assert!(!run.join("x509crl").exists() && !run.join("rsa").exists());
        let _ = std::fs::remove_dir_all(&b);
        let _ = std::fs::remove_dir_all(&run);
    }

    #[test]
    fn only_plain_regular_files_of_the_known_directories_are_copied() {
        let ((b, src), run, outside) = (brew(), tmp(), tmp());
        std::fs::write(outside.join("secret"), b"OUT").unwrap();
        std::fs::create_dir(src.join("private")).unwrap();
        std::fs::create_dir(src.join("other")).unwrap();
        std::fs::write(src.join("other/x.pem"), b"X").unwrap();
        std::fs::write(src.join("swanctl.conf"), b"connections {}").unwrap();
        std::os::unix::fs::symlink(outside.join("secret"), src.join("private/link.key")).unwrap();
        std::fs::write(src.join("private/.hidden.key"), b"H").unwrap();
        std::fs::write(src.join("private/sp ace.key"), b"S").unwrap();
        std::fs::create_dir(src.join("private/sub")).unwrap();
        std::fs::write(src.join("private/big.key"), vec![b'k'; CRED_FILE_MAX as usize + 1]).unwrap();
        std::fs::write(src.join("private/ok.key"), b"OK").unwrap();
        // A symlinked credential directory is not followed.
        std::os::unix::fs::symlink(&outside, src.join("x509ca")).unwrap();
        let n = stage_creds(&b, &run).unwrap();
        assert_eq!(n, Staged { copied: 1, skipped: 5 });
        let mut names: Vec<_> =
            std::fs::read_dir(run.join("private")).unwrap().map(|e| e.unwrap().file_name()).collect();
        names.sort();
        assert_eq!(names, ["ok.key"]);
        assert!(!run.join("x509ca").exists() && !run.join("other").exists() && !run.join("swanctl.conf").exists());
        for p in [&b, &run, &outside] {
            let _ = std::fs::remove_dir_all(p);
        }
    }

    #[test]
    fn a_hard_linked_credential_is_refused() {
        // L-7: a hard link into `x509/` could name a root-only file elsewhere on the volume.
        let ((b, src), run, outside) = (brew(), tmp(), tmp());
        std::fs::create_dir(src.join("x509")).unwrap();
        std::fs::write(outside.join("root-only"), b"SECRET").unwrap();
        std::fs::hard_link(outside.join("root-only"), src.join("x509/hard.pem")).unwrap();
        std::fs::write(src.join("x509/ok.pem"), b"OK").unwrap();
        assert_eq!(stage_creds(&b, &run).unwrap(), Staged { copied: 1, skipped: 1 });
        assert!(!run.join("x509/hard.pem").exists() && run.join("x509/ok.pem").exists());
        for p in [&b, &run, &outside] {
            let _ = std::fs::remove_dir_all(p);
        }
    }

    #[test]
    fn a_symlink_in_any_directory_component_is_not_followed() {
        // L-7: `etc` or `etc/swanctl` swapped for a symlink (e.g. to /var/db) copies nothing.
        let ((b, src), run) = (brew(), tmp());
        std::fs::create_dir(src.join("x509ca")).unwrap();
        std::fs::write(src.join("x509ca/ca.pem"), b"CA").unwrap();
        let other = tmp();
        std::os::unix::fs::symlink(b.join("etc"), other.join("etc")).unwrap();
        assert_eq!(stage_creds(&other, &run).unwrap(), Staged::default(), "etc is a symlink");
        let third = tmp();
        std::fs::create_dir(third.join("etc")).unwrap();
        std::os::unix::fs::symlink(&src, third.join("etc/swanctl")).unwrap();
        assert_eq!(stage_creds(&third, &run).unwrap(), Staged::default(), "etc/swanctl is a symlink");
        let link = tmp().join("brew");
        std::os::unix::fs::symlink(&b, &link).unwrap();
        assert_eq!(stage_creds(&link, &run).unwrap(), Staged::default(), "the prefix is a symlink");
        assert!(!run.join("x509ca").exists());
        assert_eq!(stage_creds(&b, &run).unwrap(), Staged { copied: 1, skipped: 0 }, "control");
        for p in [&b, &run, &other, &third, &link.parent().unwrap().to_path_buf()] {
            let _ = std::fs::remove_dir_all(p);
        }
    }

    #[test]
    fn only_root_or_the_prefix_owner_is_trusted() {
        // Apple silicon: the prefix and `etc` belong to the user; Intel: `/usr/local` is root's, `etc` the user's.
        assert!(trusted_owner(501, 501, 501) && trusted_owner(0, 501, 501));
        assert!(trusted_owner(501, 0, 501) && trusted_owner(0, 0, 501));
        assert!(!trusted_owner(502, 501, 501) && !trusted_owner(502, 0, 501));
    }

    #[test]
    fn a_missing_or_symlinked_source_copies_nothing() {
        let (run, real) = (tmp(), tmp());
        assert_eq!(stage_creds(&run.join("nonexistent"), &run).unwrap(), Staged::default());
        std::fs::create_dir_all(real.join("etc/swanctl/x509ca")).unwrap();
        std::fs::write(real.join("etc/swanctl/x509ca/ca.pem"), b"CA").unwrap();
        let link = run.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(stage_creds(&link, &run).unwrap(), Staged::default());
        assert!(!run.join("x509ca").exists());
        let _ = std::fs::remove_dir_all(&run);
        let _ = std::fs::remove_dir_all(&real);
    }

    #[test]
    fn at_most_cred_files_max_files_are_copied() {
        let ((b, src), run) = (brew(), tmp());
        std::fs::create_dir(src.join("x509ca")).unwrap();
        for i in 0..CRED_FILES_MAX + 2 {
            std::fs::write(src.join(format!("x509ca/ca{i:04}.pem")), b"CA").unwrap();
        }
        assert_eq!(stage_creds(&b, &run).unwrap(), Staged { copied: CRED_FILES_MAX, skipped: 2 });
        let _ = std::fs::remove_dir_all(&b);
        let _ = std::fs::remove_dir_all(&run);
    }

    #[test]
    fn an_existing_target_is_an_error() {
        let ((b, src), run) = (brew(), tmp());
        std::fs::create_dir(src.join("x509ca")).unwrap();
        std::fs::write(src.join("x509ca/ca.pem"), b"CA").unwrap();
        std::os::unix::fs::symlink("/nonexistent", run.join("x509ca")).unwrap();
        assert!(stage_creds(&b, &run).is_err());
        let _ = std::fs::remove_dir_all(&b);
        let _ = std::fs::remove_dir_all(&run);
    }

    #[test]
    fn load_all_never_prompts_and_names_the_run_config() {
        let c = load_all_cmd(Path::new("/opt/homebrew/bin/swanctl"), Path::new("/var/run/macvpn/x/config"));
        assert_eq!(c.display(), "/opt/homebrew/bin/swanctl --load-all --noprompt --file /var/run/macvpn/x/config");
    }

    #[test]
    fn the_source_is_homebrews_swanctl_directory() {
        assert_eq!(cred_source(Path::new("/opt/homebrew")), Path::new("/opt/homebrew/etc/swanctl"));
        assert_eq!(cred_source(Path::new("/usr/local")), Path::new("/usr/local/etc/swanctl"));
    }

    #[test]
    fn names() {
        assert!(is_name("office-net") && is_name("a.b_c") && !is_name("a b") && !is_name(""));
    }
}
