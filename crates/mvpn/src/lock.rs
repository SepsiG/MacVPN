//! The per-connection lock: `up` and `down` of one id never run at the same time (atomic `mkdir`).
//!
//! The lock directory holds the owner's pid. A lock is stale (SIGKILL, crash) if the pid no longer runs, or if it
//! has no pid file and is older than 60 s (the gap between `mkdir` and writing the pid), or if it is older than
//! 10 minutes (pid reuse; no operation takes that long). Removing a stale lock is serialized by a second lock
//! (`.reap`) and the staleness is checked again under it, so two waiters never remove each other's fresh lock.

use crate::ctx::{Ctx, R, tr};
use crate::exec;
use crate::fsx;
use crate::procs;
use crate::testmode::is_digits;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub struct Lock {
    pub path: Option<PathBuf>,
    pub held: bool,
}

/// Seconds since the lock's modification (`stat -f %m`; a missing lock counts as just made).
fn age(p: &Path) -> i64 {
    let now = exec::now();
    now - fsx::mtime_secs(p).unwrap_or(now)
}

/// `lock_is_stale`
pub fn is_stale(lock: &Path) -> bool {
    if !crate::paths::is_dir(lock) {
        return false;
    }
    let a = age(lock);
    if a > 600 {
        return true;
    }
    let pid = fsx::cat(&lock.join("pid"));
    if is_digits(&pid) {
        return !procs::exists(&pid);
    }
    a > 60
}

/// `reap_stale_lock`
fn reap(ctx: &Ctx, lock: &Path) {
    let reap = PathBuf::from(format!("{}.reap", lock.display()));
    if std::fs::create_dir(&reap).is_err() {
        if age(&reap) > 60 {
            fsx::remove_rf(&reap);
        }
        return;
    }
    if is_stale(lock) {
        let pid = crate::fsx::read_trim(&lock.join("pid")).unwrap_or_else(|| "-".into());
        ctx.log.step(&format!("{} (pid: {pid})", tr("stale lock removed", &[])));
        fsx::remove_rf(lock);
    }
    let _ = std::fs::remove_dir(&reap);
}

/// `acquire_lock`: up to `lock_tries` × 0.5 s. A root dry-run takes no lock (it touches nothing shared).
pub fn acquire(ctx: &mut Ctx) -> R {
    if ctx.dry() && !ctx.s.test_mode {
        return Ok(());
    }
    let _ = std::fs::create_dir_all(&ctx.s.run_base);
    let _ = fsx::chmod(&ctx.s.run_base, 0o700);
    let lock = ctx.s.run_base.join(format!(".{}.lock", ctx.id));
    ctx.lock.path = Some(lock.clone());
    for _ in 0..ctx.s.lock_tries {
        if std::fs::create_dir(&lock).is_ok() {
            ctx.lock.held = true;
            let _ = fsx::write_line(&lock.join("pid"), &std::process::id().to_string());
            return Ok(());
        }
        if is_stale(&lock) {
            reap(ctx, &lock);
            continue;
        }
        ctx.sleep_ms(500)?;
    }
    Err(ctx
        .die(tr("Another operation is already running on this connection (lock: %@)", &[&lock.display().to_string()])))
}

/// `release_lock`: only our own lock (pid check).
pub fn release(ctx: &mut Ctx) {
    if !ctx.lock.held {
        return;
    }
    if let Some(lock) = &ctx.lock.path
        && fsx::cat(&lock.join("pid")) == std::process::id().to_string()
    {
        fsx::remove_rf(lock);
    }
    ctx.lock.held = false;
}

/// The status-time lock: a single non-blocking attempt; `true` if taken (then [`release_try`] it).
pub fn try_take(lock: &Path) -> bool {
    if std::fs::create_dir(lock).is_err() {
        return false;
    }
    let _ = fsx::write_line(&lock.join("pid"), &std::process::id().to_string());
    true
}

pub fn release_try(lock: &Path) {
    if fsx::cat(&lock.join("pid")) == std::process::id().to_string() {
        fsx::remove_rf(lock);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staleness() {
        let d = std::env::temp_dir().join(format!("mvpn-lock-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&d).unwrap();
        let lock = d.join(".x.lock");
        assert!(!is_stale(&lock));
        std::fs::create_dir(&lock).unwrap();
        assert!(!is_stale(&lock), "fresh lock without pid");
        fsx::write_line(&lock.join("pid"), &std::process::id().to_string()).unwrap();
        assert!(!is_stale(&lock), "live pid");
        fsx::write_line(&lock.join("pid"), "999999").unwrap();
        assert!(is_stale(&lock), "dead pid");
        fsx::remove_rf(&d);
    }
}
