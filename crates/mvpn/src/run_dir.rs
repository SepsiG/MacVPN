//! The run directory (`/var/run/macvpn/<id>`, root 0700) and the copy of the config into it.
//!
//! The source config is read with the user's rights (`sudo -n -u <user> /bin/cat --`), the copy is created by
//! root in the root-only directory: a symlink / hardlink swap (TOCTOU) can at most bring in a file the user could
//! read anyway. The symlink, owner and link-count checks stay as defence in depth. From here on only the copy is
//! used. A dry-run gets its own `<id>.dryrun.XXXXXX` directory (removed at exit), so it never touches a live one.

use crate::cli::is_user_name;
use crate::ctx::{Ctx, R, tr};
use crate::exec::{self, Cmd};
use crate::fsx;
use crate::paths::{SRC_MAX, is_file, is_symlink};
use std::io::Read;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;

/// `resolve_src_base`: `<home>/Library/Application Support/MacVPN/connections` of the target user.
pub fn resolve_src_base(ctx: &mut Ctx) -> R {
    if ctx.s.src_base.is_some() {
        return Ok(());
    }
    if !is_user_name(&ctx.s.target_user) {
        return Err(ctx.die(tr("Invalid user", &[])));
    }
    let home = crate::sys::user_by_name(&ctx.s.target_user).map(|u| u.home).filter(|h| !h.is_empty());
    let Some(home) = home else {
        return Err(ctx.die(tr("The user's home directory was not found", &[])));
    };
    ctx.s.src_base = Some(PathBuf::from(home).join("Library/Application Support/MacVPN/connections"));
    Ok(())
}

/// `mktemp -d <base>/<id>.dryrun.XXXXXX` (0700, created atomically).
fn make_dry_dir(base: &Path, id: &str) -> Option<PathBuf> {
    for _ in 0..100 {
        let suffix: String = uuid::Uuid::new_v4().simple().to_string().chars().take(6).collect();
        let p = base.join(format!("{id}.dryrun.{suffix}"));
        if std::fs::DirBuilder::new().mode(0o700).create(&p).is_ok() {
            return Some(p);
        }
    }
    None
}

/// Removes the run directory and stops with `msg`.
fn fail(ctx: &Ctx, run: &Path, msg: String) -> crate::ctx::Exit {
    fsx::remove_rf(run);
    ctx.die(msg)
}

/// `prepare_run`
pub fn prepare(ctx: &mut Ctx) -> R {
    let src_base = ctx.s.src_base.clone().unwrap_or_default();
    let conn_dir = src_base.join(&ctx.id);
    let src = conn_dir.join("config");
    if !is_user_name(&ctx.s.target_user) {
        return Err(ctx.die(tr("Invalid user", &[])));
    }
    if is_symlink(&conn_dir) {
        return Err(ctx.die(tr("The connection directory must not be a symlink", &[])));
    }
    if is_symlink(&src) {
        return Err(ctx.die(tr("The config must not be a symlink", &[])));
    }
    if !is_file(&src) {
        return Err(ctx.die(tr("Config not found", &[])));
    }
    let Some(user) = ctx.user() else {
        return Err(ctx.die(tr("Unknown user", &[])));
    };
    let Some(owner) = fsx::owner_and_links(&src) else {
        return Err(ctx.die(tr("Cannot read the config", &[])));
    };
    if owner != (user.uid, 1) {
        return Err(ctx.die(tr("The owner or link count of the config is wrong", &[])));
    }
    let _ = std::fs::create_dir_all(&ctx.s.run_base);
    let _ = fsx::chmod(&ctx.s.run_base, 0o700);
    let run = if ctx.dry() {
        match make_dry_dir(&ctx.s.run_base, &ctx.id) {
            Some(p) => p,
            None => return Err(ctx.die(tr("Cannot create the dry-run directory", &[]))),
        }
    } else {
        let run = ctx.s.run_dir(&ctx.id);
        fsx::remove_rf(&run);
        if std::fs::DirBuilder::new().mode(0o700).create(&run).is_err() {
            return Err(ctx.die(tr("Cannot create: %@", &[&run.display().to_string()])));
        }
        run
    };
    ctx.run = Some(run.clone());

    let cat = if ctx.s.test_mode {
        Cmd::new("/bin/cat").arg("--").arg(&src)
    } else {
        Cmd::new("/usr/bin/sudo").args(["-n", "-u", &ctx.s.target_user, "/bin/cat", "--"]).arg(&src)
    };
    let dest = run.join("config");
    let copied = copy_as_user(&cat, ctx.env_mode(), &dest);
    if is_symlink(&dest) {
        return Err(fail(ctx, &run, tr("The config must not be a symlink", &[])));
    }
    if !is_file(&dest) {
        return Err(fail(ctx, &run, tr("The config is not a regular file", &[])));
    }
    if fsx::size(&dest).unwrap_or(u64::MAX) > SRC_MAX {
        return Err(fail(ctx, &run, tr("The config is too large (1 MB at most)", &[])));
    }
    if !copied {
        return Err(fail(ctx, &run, tr("Copying the config failed", &[])));
    }
    let _ = fsx::write_line(&run.join("kind"), &ctx.kind);
    let _ = fsx::write_line(&run.join("lang"), if ctx.a.lang_hu { "hu" } else { "en" });
    let _ = fsx::write_line(&run.join("started"), &exec::now().to_string());
    ctx.log.step(&tr("config copied: %@/config", &[&run.display().to_string()]));
    Ok(())
}

/// Runs the reader, keeps at most `SRC_MAX + 1` bytes of its output in `dest` (created new, 0600); `true` if the
/// reader succeeded.
fn copy_as_user(cat: &Cmd, mode: exec::EnvMode, dest: &Path) -> bool {
    let child = cat.command(mode).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn();
    let mut data = Vec::new();
    let mut ok = false;
    if let Ok(mut child) = child {
        if let Some(out) = child.stdout.take() {
            let _ = out.take(SRC_MAX + 1).read_to_end(&mut data);
        }
        ok = child.wait().is_ok_and(|s| s.success());
    }
    let _ = fsx::write_file(dest, &data, 0o600);
    ok
}
