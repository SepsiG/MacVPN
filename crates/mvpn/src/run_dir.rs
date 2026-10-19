//! The run directory (`/var/run/macvpn/<id>`, root 0700) and the config written into it.
//!
//! Since root layer 8 the config arrives on stdin (see [`crate::secrets`]): the root layer opens no user file, so
//! there is no source path a symlink, hardlink or owner trick could redirect. The bytes go straight from memory
//! into `run/config` (0600, created new, never through a symlink) in the freshly created root-only directory;
//! from here on only that copy is used. A dry-run gets its own `<id>.dryrun.XXXXXX` directory (removed at exit),
//! so it never touches a live one.

use crate::ctx::{Ctx, R, tr};
use crate::exec;
use crate::fsx;
use crate::paths::SRC_MAX;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

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

/// `prepare_run`: a new run directory with `config` written from `config` (already framed and size-checked).
pub fn prepare(ctx: &mut Ctx, config: &[u8]) -> R {
    // The connection's user (`SUDO_USER`) must exist: the log and the MFA files are handed to it.
    if ctx.user().is_none() {
        return Err(ctx.die(tr("Unknown user", &[])));
    }
    // The framing guarantees both; checked again because this is the only writer of `run/config`.
    if config.is_empty() {
        return Err(ctx.die(tr("Config not provided", &[])));
    }
    if config.len() as u64 > SRC_MAX {
        return Err(ctx.die(tr("The config is too large (1 MB at most)", &[])));
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
    if fsx::create_new(&run.join("config"), config, 0o600).is_err() {
        return Err(fail(ctx, &run, tr("Cannot write the config", &[])));
    }
    let _ = fsx::write_line(&run.join("kind"), &ctx.kind);
    let _ = fsx::write_line(&run.join("lang"), if ctx.a.lang_hu { "hu" } else { "en" });
    let _ = fsx::write_line(&run.join("started"), &exec::now().to_string());
    ctx.log.step(&tr("config written: %@/config", &[&run.display().to_string()]));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Args;
    use crate::paths::Settings;
    use crate::testmode::TestEnv;
    use std::os::unix::fs::PermissionsExt;

    fn ctx(base: &Path, dry: bool) -> Ctx {
        let t = TestEnv { run_base: Some(base.display().to_string()), ..TestEnv::default() };
        let a = Args {
            cmd: "up".into(),
            kind: "openvpn".into(),
            id: "0F6B2C1E-6F1D-4C35-9C47-2B1A3E5D7F90".into(),
            dry_run: dry,
            ..Args::default()
        };
        Ctx::new(Settings::resolve(true, t, String::new()), a)
    }

    fn tmp() -> PathBuf {
        std::env::temp_dir().join(format!("mvpn-run-{}", uuid::Uuid::new_v4()))
    }

    #[test]
    fn writes_the_config_from_memory_into_a_private_directory() {
        let base = tmp();
        let mut c = ctx(&base, false);
        prepare(&mut c, b"client\nremote a 1\n").unwrap();
        let run = c.run().to_path_buf();
        assert_eq!(run, base.join(&c.id));
        assert_eq!(std::fs::read(run.join("config")).unwrap(), b"client\nremote a 1\n");
        assert_eq!(std::fs::metadata(&run).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(std::fs::metadata(run.join("config")).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(fsx::cat(&run.join("kind")), "openvpn");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_dry_run_gets_its_own_directory() {
        let base = tmp();
        let mut c = ctx(&base, true);
        prepare(&mut c, b"x").unwrap();
        let name = c.run().file_name().unwrap().to_string_lossy().into_owned();
        assert!(name.starts_with(&format!("{}.dryrun.", c.id)), "{name}");
        assert_eq!(std::fs::read(c.run().join("config")).unwrap(), b"x");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn refuses_an_empty_or_oversize_config_without_a_run_directory() {
        let base = tmp();
        let mut c = ctx(&base, false);
        assert!(prepare(&mut c, b"").is_err());
        assert!(prepare(&mut c, &vec![b'#'; SRC_MAX as usize + 1]).is_err());
        assert!(c.run.is_none() && !base.join(&c.id).exists());
        let _ = std::fs::remove_dir_all(&base);
    }
}
