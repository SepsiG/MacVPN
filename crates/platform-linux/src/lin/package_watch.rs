//! The installed LinVPN restarts itself after its package is upgraded from outside the app (`pure::package_watch`):
//! a thread reads the `.deb`'s marker every 3 s; once it names another version, and nothing holds the app (`busy`:
//! unsaved changes in the editor, the in-app update installing), the updater's notice and relaunch
//! (`LinUpdater::restart_after_package`), then `quit` (no quit questions; the tunnels stay up). Once only.

use super::updater;
use crate::pure::package_watch::{self as pw, MARKER, POLL};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Starts the watch for the installed LinVPN, running `running` with the user's `home`.
pub fn watch_package_upgrade(
    home: PathBuf,
    running: String,
    busy: Box<dyn Fn() -> bool + Send>,
    quit: Box<dyn FnOnce() + Send>,
) {
    let restart = Box::new(move |version: &str| updater::installed().restart_after_package(&home, version));
    spawn(PathBuf::from(MARKER), POLL, running, busy, restart, quit);
}

fn spawn(
    marker: PathBuf,
    poll: Duration,
    running: String,
    busy: Box<dyn Fn() -> bool + Send>,
    restart: Box<dyn FnOnce(&str) + Send>,
    quit: Box<dyn FnOnce() + Send>,
) {
    // Read before the thread starts: what the marker holds now is the baseline, whatever the thread sees later.
    let at_start = pw::read_marker(&marker);
    let started = std::thread::Builder::new()
        .name("linvpn-package-watch".into())
        .spawn(move || run(&marker, at_start, poll, &running, busy.as_ref(), restart, quit));
    if let Err(e) = started {
        eprintln!("LinVPN: the package watch could not start: {e}");
    }
}

/// The watch's loop (`at_start`: the marker when the watch began); returns after the restart.
fn run(
    marker: &Path,
    at_start: Option<String>,
    poll: Duration,
    running: &str,
    busy: &dyn Fn() -> bool,
    restart: Box<dyn FnOnce(&str) + Send>,
    quit: Box<dyn FnOnce() + Send>,
) {
    loop {
        std::thread::sleep(poll);
        let Some(version) = pw::upgraded_to(running, at_start.as_deref(), pw::read_marker(marker).as_deref()) else {
            continue;
        };
        if busy() {
            continue;
        }
        eprintln!("LinVPN: the package is now {version} (running {running}): restarting");
        restart(&version);
        quit();
        return;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, mpsc};
    use std::time::Instant;

    const TICK: Duration = Duration::from_millis(10);

    struct Watch {
        dir: PathBuf,
        marker: PathBuf,
        busy: Arc<AtomicBool>,
        restarted: Arc<Mutex<Vec<String>>>,
        quit: mpsc::Receiver<()>,
    }

    /// A watch of a temp marker holding `initial` (none: missing), the app running 2.1.0.
    fn watch(initial: Option<&str>) -> Watch {
        let dir = std::env::temp_dir().join(format!("linvpn-package-watch-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("package-version");
        if let Some(text) = initial {
            std::fs::write(&marker, text).unwrap();
        }
        let busy = Arc::new(AtomicBool::new(false));
        let restarted = Arc::new(Mutex::new(Vec::new()));
        let (tx, quit) = mpsc::channel();
        let (b, r) = (busy.clone(), restarted.clone());
        spawn(
            marker.clone(),
            TICK,
            "2.1.0".into(),
            Box::new(move || b.load(Ordering::SeqCst)),
            Box::new(move |v| r.lock().unwrap().push(v.to_string())),
            Box::new(move || tx.send(()).unwrap()),
        );
        Watch { dir, marker, busy, restarted, quit }
    }

    impl Watch {
        fn set(&self, text: &str) {
            let tmp = self.dir.join("tmp");
            std::fs::write(&tmp, text).unwrap();
            std::fs::rename(&tmp, &self.marker).unwrap();
        }

        fn quits(&self) -> bool {
            self.quit.recv_timeout(Duration::from_secs(5)).is_ok()
        }

        fn stays(&self) -> bool {
            std::thread::sleep(TICK * 20);
            self.quit.try_recv().is_err() && self.restarted.lock().unwrap().is_empty()
        }
    }

    impl Drop for Watch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn an_upgrade_restarts_once() {
        let w = watch(Some("2.1.0\n"));
        assert!(w.stays());
        w.set("2.2.0\n");
        assert!(w.quits());
        assert_eq!(*w.restarted.lock().unwrap(), ["2.2.0"]);
        w.set("2.3.0\n");
        std::thread::sleep(TICK * 20);
        assert_eq!(*w.restarted.lock().unwrap(), ["2.2.0"], "the thread has ended");
    }

    #[test]
    fn a_downgrade_restarts_too() {
        let w = watch(Some("2.1.0\n"));
        w.set("2.0.9\n");
        assert!(w.quits());
        assert_eq!(*w.restarted.lock().unwrap(), ["2.0.9"]);
    }

    #[test]
    fn no_marker_waits_for_one() {
        let w = watch(None);
        assert!(w.stays());
        w.set("2.2.0\n");
        assert!(w.quits());
    }

    #[test]
    fn a_marker_that_differed_at_start_waits_for_a_change() {
        let w = watch(Some("2.2.0\n"));
        assert!(w.stays());
        w.set("garbage");
        assert!(w.stays());
        w.set("2.3.0");
        assert!(w.quits());
        assert_eq!(*w.restarted.lock().unwrap(), ["2.3.0"]);
    }

    #[test]
    fn busy_holds_the_restart_until_it_ends() {
        let w = watch(Some("2.1.0\n"));
        w.busy.store(true, Ordering::SeqCst);
        w.set("2.2.0\n");
        assert!(w.stays());
        let since = Instant::now();
        w.busy.store(false, Ordering::SeqCst);
        assert!(w.quits());
        assert!(since.elapsed() < Duration::from_secs(5));
        assert_eq!(*w.restarted.lock().unwrap(), ["2.2.0"]);
    }
}
