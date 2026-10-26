//! Files opened from Finder (a double click, "Open With → MacVPN", or a drop on the app's icon): which flow each
//! file goes to, and the queue that holds them while the vault is not open yet.
//!
//! - **Untrusted input.** An opened file is handled exactly like a file dropped on the Connections window: the
//!   VPN configs go through the import (`ConnectionsModel::import_paths`, with every check and question of a manual
//!   import), a team catalog file only preselects the "Add team catalog" dialog's file source (the user still
//!   enters the team key and the fingerprint, and ticks the comparison). Nothing here reads a file, and nothing
//!   here connects.
//! - **Only paths, only in memory.** The queue keeps paths (never contents), at most [`MAX_QUEUED`], and only until
//!   the vault opens or its window is closed. No path leaves the backend: the window gets a file name at most.
//! - **The flows** ([`flow`]): `.macvpncatalog` → the add dialog; `.macvpnadminkey` and `.macvpnbackup` → refused
//!   (they are opened from their own panels only); anything else → the import, which detects the kind by the
//!   extension and the content and refuses what it cannot import (a `.mobileconfig` among them), as for a drop.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use macvpn_core::catalog::{admin_file, format as catalog_format};
use macvpn_core::importer::path_extension;
use macvpn_core::l10n::{self, Arg};
use macvpn_core::vault::backup;

/// At most this many paths wait for the vault (the rest of a larger open is dropped).
pub const MAX_QUEUED: usize = 32;
/// At most this many files are imported per open (as for a drop or the open panel).
pub const MAX_IMPORTED: usize = 64;
/// At most this many paths of one open are looked at (a flood of paths is cut before it is sorted).
pub const MAX_SORTED: usize = MAX_IMPORTED * 4;
/// At most this many refused files are named in the report; the rest is a count ([`Batch::refused_more`]).
pub const MAX_REFUSED: usize = 8;
/// At most this many downloaded files are named in the confirmation; the rest is a count.
pub const MAX_NAMED_DOWNLOADS: usize = 10;

/// Where an opened file goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenFlow {
    /// The import of the Connections window (VPN configs; the import itself refuses what it cannot read).
    Import,
    /// The "Add team catalog" dialog with the file as its source.
    Catalog,
    /// Never opened from Finder (admin key files and backups have their own panels).
    Refused,
}

/// The flow of a file, by its extension (case-insensitive, as the importer reads it).
pub fn flow(path: &Path) -> OpenFlow {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let extension = path_extension(&name).to_lowercase();
    if extension == catalog_format::EXTENSION {
        OpenFlow::Catalog
    } else if extension == admin_file::EXTENSION || extension == backup::EXTENSION {
        OpenFlow::Refused
    } else {
        OpenFlow::Import
    }
}

/// Why a file was not opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// An admin key file or a backup: opened from its panel only.
    PanelOnly,
    /// A second team catalog file in the same open: the add dialog takes one.
    OneCatalog,
}

/// What one open does, sorted by flow.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Batch {
    /// The files to import, in the order they came (at most [`MAX_IMPORTED`]).
    pub imports: Vec<PathBuf>,
    /// The team catalog file for the add dialog (the first one).
    pub catalog: Option<PathBuf>,
    /// The refused files: their names (never the path) and why; at most [`MAX_REFUSED`].
    pub refused: Vec<(String, Refusal)>,
    /// How many more files were refused than [`Self::refused`] names.
    pub refused_more: usize,
}

impl Batch {
    pub fn is_empty(&self) -> bool {
        self.imports.is_empty() && self.catalog.is_none() && self.refused.is_empty() && self.refused_more == 0
    }

    /// Sorts the paths of an open: only absolute ones, each once, only the first [`MAX_SORTED`] looked at.
    pub fn sort(paths: impl IntoIterator<Item = PathBuf>) -> Batch {
        let mut batch = Batch::default();
        let mut seen: HashSet<PathBuf> = HashSet::new();
        for path in paths.into_iter().take(MAX_SORTED) {
            if !path.is_absolute() || !seen.insert(path.clone()) {
                continue;
            }
            match flow(&path) {
                OpenFlow::Import => {
                    if batch.imports.len() < MAX_IMPORTED {
                        batch.imports.push(path);
                    }
                }
                OpenFlow::Catalog if batch.catalog.is_none() => batch.catalog = Some(path),
                OpenFlow::Catalog => batch.refuse(file_name(&path), Refusal::OneCatalog),
                OpenFlow::Refused => batch.refuse(file_name(&path), Refusal::PanelOnly),
            }
        }
        batch
    }

    fn refuse(&mut self, name: String, why: Refusal) {
        if self.refused.len() < MAX_REFUSED {
            self.refused.push((name, why));
        } else {
            self.refused_more += 1;
        }
    }

    /// Adds a later open to this one (they run together): its imports after these (each once, up to
    /// [`MAX_IMPORTED`]), its catalog file in place of this one's (the latest open wins, as the add dialog shows
    /// one), its refusals (capped).
    pub fn merge(&mut self, other: Batch) {
        let seen: HashSet<PathBuf> = self.imports.iter().cloned().collect();
        let room = MAX_IMPORTED.saturating_sub(self.imports.len());
        self.imports.extend(other.imports.into_iter().filter(|p| !seen.contains(p)).take(room));
        if other.catalog.is_some() {
            self.catalog = other.catalog;
        }
        for (name, why) in other.refused {
            self.refuse(name, why);
        }
        self.refused_more += other.refused_more;
    }
}

/// The opens waiting for the one worker that runs them: a worker is started for the first submitted batch, and the
/// batches submitted while it runs are merged and run next by the same worker.
#[derive(Debug, Default)]
pub struct WorkQueue {
    batch: Option<Batch>,
    running: bool,
}

impl WorkQueue {
    /// Adds a batch. True: no worker is running, the caller starts one (which calls [`Self::next_batch`] until `None`).
    pub fn submit(&mut self, batch: Batch) -> bool {
        if batch.is_empty() {
            return false;
        }
        match &mut self.batch {
            Some(waiting) => waiting.merge(batch),
            None => self.batch = Some(batch),
        }
        !std::mem::replace(&mut self.running, true)
    }

    /// The worker's next batch; `None`: nothing waits, the worker ends (a later submit starts a new one).
    pub fn next_batch(&mut self) -> Option<Batch> {
        let next = self.batch.take();
        self.running = next.is_some();
        next
    }

    /// The worker could not be started: the batch is dropped, the next submit tries again.
    pub fn failed(&mut self) {
        self.batch = None;
        self.running = false;
    }
}

/// The confirmation for downloaded files (title, message): "Import N downloaded file(s)?", their names (at most
/// [`MAX_NAMED_DOWNLOADS`], the rest as a count) and "Only import files you trust."
pub fn downloaded_question(names: &[String]) -> (String, String) {
    let title = if names.len() == 1 {
        l10n::tr("Import the downloaded file?", &[])
    } else {
        l10n::tr("Import %lld downloaded files?", &[Arg::Int(names.len() as i64)])
    };
    let mut list = names.iter().take(MAX_NAMED_DOWNLOADS).cloned().collect::<Vec<_>>().join(", ");
    if names.len() > MAX_NAMED_DOWNLOADS {
        list.push(' ');
        list.push_str(&l10n::tr("and %lld more", &[Arg::Int((names.len() - MAX_NAMED_DOWNLOADS) as i64)]));
    }
    (title, format!("{list}\n\n{}", l10n::tr("Only import files you trust.", &[])))
}

/// The files to import after the downloaded ones were confirmed: a file that carries the quarantine mark
/// (`quarantined`: downloaded from the internet, saved by a browser, mail or AirDrop) is imported only if the user
/// agrees, all of them with one question (`ask`, with [`downloaded_question`]). Files without the mark are imported
/// without a question; with none marked, nothing is asked. The order is kept.
pub fn confirm_downloaded(
    imports: Vec<PathBuf>,
    quarantined: impl Fn(&Path) -> bool,
    ask: impl FnOnce(String, String) -> bool,
) -> Vec<PathBuf> {
    let marked: Vec<bool> = imports.iter().map(|p| quarantined(p)).collect();
    if !marked.contains(&true) {
        return imports;
    }
    let names: Vec<String> = imports.iter().zip(&marked).filter(|(_, m)| **m).map(|(p, _)| file_name(p)).collect();
    let (title, message) = downloaded_question(&names);
    let confirmed = ask(title, message);
    imports.into_iter().zip(marked).filter(|(_, m)| confirmed || !m).map(|(p, _)| p).collect()
}

/// The file's name (what a report may show).
pub fn file_name(path: &Path) -> String {
    path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

/// What happens to an open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Received {
    /// The vault is open: run it now.
    Run(Batch),
    /// Kept until the vault opens. `show_vault`: the unlock (or create) window is to be shown now (before the
    /// launch decided the vault's state, the launch shows it). `dropped`: paths over [`MAX_QUEUED`].
    Queued { show_vault: bool, dropped: usize },
}

/// The opens waiting for the vault, and whether the launch has decided the vault's state yet.
#[derive(Debug, Default)]
pub struct OpenQueue {
    paths: Vec<PathBuf>,
    /// [`Self::paths`] as a set (each path once, without a linear search).
    seen: HashSet<PathBuf>,
    launched: bool,
}

impl OpenQueue {
    /// An open from Finder. `vault_ready`: the vault is open and no create window is in progress.
    pub fn receive(&mut self, paths: impl IntoIterator<Item = PathBuf>, vault_ready: bool) -> Received {
        if self.launched && vault_ready {
            // Anything still waiting goes first (an unlock and an open can cross).
            let waiting = self.take();
            return Received::Run(Batch::sort(waiting.into_iter().chain(paths)));
        }
        // The window is shown for the first open that waits only (a flood of opens shows it once).
        let first = self.paths.is_empty();
        let dropped = self.push(paths);
        Received::Queued { show_vault: self.launched && first && !self.paths.is_empty(), dropped }
    }

    /// Queues absolute paths (each once) up to [`MAX_QUEUED`]; returns how many were dropped (only the first
    /// [`MAX_SORTED`] paths are looked at; the rest count as dropped).
    fn push(&mut self, paths: impl IntoIterator<Item = PathBuf>) -> usize {
        let mut dropped = 0;
        let mut paths = paths.into_iter();
        for path in paths.by_ref().take(MAX_SORTED) {
            if !path.is_absolute() || self.seen.contains(&path) {
                continue;
            }
            if self.paths.len() < MAX_QUEUED {
                self.seen.insert(path.clone());
                self.paths.push(path);
            } else {
                dropped += 1;
            }
        }
        dropped + paths.count()
    }

    fn take(&mut self) -> Vec<PathBuf> {
        self.seen.clear();
        std::mem::take(&mut self.paths)
    }

    /// The launch decided the vault's state (its window, if any, is shown): what waits runs now if the vault is
    /// ready.
    pub fn launched(&mut self, vault_ready: bool) -> Option<Batch> {
        self.launched = true;
        self.flush(vault_ready)
    }

    /// The vault opened (an unlock, a closed create window): what waits runs now.
    pub fn flush(&mut self, vault_ready: bool) -> Option<Batch> {
        if !self.launched || !vault_ready || self.paths.is_empty() {
            return None;
        }
        Some(Batch::sort(self.take()))
    }

    /// The unlock or create window was closed without opening the vault: what waits is dropped. Returns how many.
    pub fn cancel(&mut self) -> usize {
        self.take().len()
    }

    pub fn len(&self) -> usize {
        self.paths.len()
    }

    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }
}

/// What a launch without files does while the app already runs (WinVPN started again from the Start menu, a
/// shortcut or Explorer: the second instance forwards an empty list). macOS has no such launch: a click on the Dock
/// icon (`Reopen`) brings the open windows forward and opens none, and stays so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShowYourself {
    /// A real window (Connections, System Status, Update, Backup, Restore) is open: they come forward.
    BringForward,
    /// Only the tray runs and the vault is open: the Connections window opens (otherwise the launch would show
    /// nothing at all).
    Connections,
    /// Only the tray runs and the vault is closed (locked, not created, or its create window in progress): its
    /// unlock or create window comes forward, as for an opened file.
    Vault,
}

/// The decision of [`ShowYourself`]. `real_window_open`: one of the real windows exists (shown or minimized);
/// `vault_ready`: the vault is open and no create window is in progress.
pub fn show_yourself(real_window_open: bool, vault_ready: bool) -> ShowYourself {
    match (real_window_open, vault_ready) {
        (true, _) => ShowYourself::BringForward,
        (false, true) => ShowYourself::Connections,
        (false, false) => ShowYourself::Vault,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A second launch without files never ends with nothing visible: an open window comes forward, else the
    /// Connections window opens, or the vault's window while the vault is closed.
    #[test]
    fn a_launch_without_files_always_shows_a_window() {
        assert_eq!(show_yourself(true, true), ShowYourself::BringForward);
        assert_eq!(show_yourself(true, false), ShowYourself::BringForward);
        assert_eq!(show_yourself(false, true), ShowYourself::Connections);
        assert_eq!(show_yourself(false, false), ShowYourself::Vault);
    }

    /// An absolute path on every OS (`/s/a.ovpn` is not absolute on Windows, and the queue takes absolute paths only).
    fn p(s: &str) -> PathBuf {
        std::env::temp_dir().join(s.trim_start_matches('/'))
    }

    #[test]
    fn extensions_choose_the_flow() {
        for import in [
            "/a/x.ovpn",
            "/a/x.OVPN",
            "/a/x.sstp",
            "/a/wg0.conf",
            "/a/x.swanctl.conf",
            "/a/x.mobileconfig",
            "/a/noext",
            "/a/.ovpn",
        ] {
            assert_eq!(flow(Path::new(import)), OpenFlow::Import, "{import}");
        }
        assert_eq!(flow(Path::new("/a/team.macvpncatalog")), OpenFlow::Catalog);
        assert_eq!(flow(Path::new("/a/team.MacVPNCatalog")), OpenFlow::Catalog);
        assert_eq!(flow(Path::new("/a/k.macvpnadminkey")), OpenFlow::Refused);
        assert_eq!(flow(Path::new("/a/b.macvpnbackup")), OpenFlow::Refused);
    }

    #[test]
    fn a_batch_sorts_by_flow_and_keeps_only_names_of_refused_files() {
        let batch = Batch::sort([
            p("/s/one.ovpn"),
            p("/s/team.macvpncatalog"),
            p("/s/second.macvpncatalog"),
            p("/secret-dir/k.macvpnadminkey"),
            PathBuf::from("relative.ovpn"),
            p("/s/one.ovpn"),
            p("/s/two.sstp"),
        ]);
        assert_eq!(batch.imports, [p("/s/one.ovpn"), p("/s/two.sstp")]);
        assert_eq!(batch.catalog, Some(p("/s/team.macvpncatalog")));
        assert_eq!(
            batch.refused,
            [
                ("second.macvpncatalog".to_string(), Refusal::OneCatalog),
                ("k.macvpnadminkey".into(), Refusal::PanelOnly)
            ]
        );
        assert!(!format!("{:?}", batch.refused).contains("secret-dir"));
    }

    #[test]
    fn a_batch_imports_at_most_the_import_limit() {
        let batch = Batch::sort((0..100).map(|i| p(&format!("/s/{i}.ovpn"))));
        assert_eq!(batch.imports.len(), MAX_IMPORTED);
    }

    #[test]
    fn opens_wait_while_locked_and_run_after_the_unlock() {
        let mut queue = OpenQueue::default();
        assert_eq!(queue.launched(false), None);
        assert_eq!(queue.receive([p("/s/a.ovpn")], false), Received::Queued { show_vault: true, dropped: 0 });
        // The window was shown for the first open that waits; a second one does not show it again.
        assert_eq!(
            queue.receive([p("/s/b.ovpn"), p("/s/a.ovpn")], false),
            Received::Queued { show_vault: false, dropped: 0 }
        );
        assert_eq!(queue.len(), 2);
        // Still locked: nothing runs.
        assert_eq!(queue.flush(false), None);
        let batch = queue.flush(true).expect("runs after the unlock");
        assert_eq!(batch.imports, [p("/s/a.ovpn"), p("/s/b.ovpn")]);
        assert!(queue.is_empty());
        assert_eq!(queue.flush(true), None);
    }

    #[test]
    fn opens_before_the_launch_wait_without_showing_a_window() {
        let mut queue = OpenQueue::default();
        // The vault may even be open already: the launch has not run its steps.
        assert_eq!(queue.receive([p("/s/a.ovpn")], true), Received::Queued { show_vault: false, dropped: 0 });
        assert_eq!(queue.flush(true), None);
        let batch = queue.launched(true).expect("runs once launched");
        assert_eq!(batch.imports, [p("/s/a.ovpn")]);
    }

    #[test]
    fn an_open_with_the_vault_ready_runs_with_what_waited() {
        let mut queue = OpenQueue::default();
        queue.launched(false);
        queue.receive([p("/s/a.ovpn")], false);
        match queue.receive([p("/s/t.macvpncatalog")], true) {
            Received::Run(batch) => {
                assert_eq!(batch.imports, [p("/s/a.ovpn")]);
                assert_eq!(batch.catalog, Some(p("/s/t.macvpncatalog")));
            }
            other => panic!("{other:?}"),
        }
        assert!(queue.is_empty());
    }

    #[test]
    fn a_cancelled_unlock_drops_the_queue() {
        let mut queue = OpenQueue::default();
        queue.launched(false);
        queue.receive([p("/s/a.ovpn"), p("/s/t.macvpncatalog")], false);
        assert_eq!(queue.cancel(), 2);
        assert_eq!(queue.flush(true), None);
    }

    #[test]
    fn the_queue_is_capped() {
        let mut queue = OpenQueue::default();
        queue.launched(false);
        let many: Vec<PathBuf> = (0..40).map(|i| p(&format!("/s/{i}.ovpn"))).collect();
        assert_eq!(queue.receive(many, false), Received::Queued { show_vault: true, dropped: 40 - MAX_QUEUED });
        assert_eq!(queue.len(), MAX_QUEUED);
        assert_eq!(queue.receive([p("/s/more.ovpn")], false), Received::Queued { show_vault: false, dropped: 1 });
        // Relative paths are never queued.
        let mut other = OpenQueue::default();
        other.receive([PathBuf::from("x.ovpn")], false);
        assert!(other.is_empty());
    }

    #[test]
    fn a_catalog_file_goes_to_the_add_dialog_after_the_unlock() {
        let mut queue = OpenQueue::default();
        queue.launched(false);
        queue.receive([p("/s/team.macvpncatalog")], false);
        let batch = queue.flush(true).unwrap();
        assert_eq!(batch.catalog, Some(p("/s/team.macvpncatalog")));
        assert!(batch.imports.is_empty() && batch.refused.is_empty());
    }

    #[test]
    fn a_flood_of_paths_is_cut_before_it_is_sorted() {
        // Far more paths than looked at: only the first MAX_SORTED count, the imports are capped.
        let batch = Batch::sort((0..100_000).map(|i| p(&format!("/s/{i}.ovpn"))));
        assert_eq!(batch.imports.len(), MAX_IMPORTED);
        // A catalog file after the cut is never seen.
        let late = (0..MAX_SORTED).map(|i| p(&format!("/s/{i}.ovpn"))).chain([p("/s/t.macvpncatalog")]);
        assert_eq!(Batch::sort(late).catalog, None);
        // Duplicates are dropped (each path once), however many there are.
        let dup = Batch::sort(std::iter::repeat_n(p("/s/a.ovpn"), MAX_SORTED));
        assert_eq!(dup.imports, [p("/s/a.ovpn")]);
    }

    #[test]
    fn refusals_are_capped_and_counted() {
        let batch = Batch::sort((0..50).map(|i| p(&format!("/s/{i}.macvpnbackup"))));
        assert_eq!(batch.refused.len(), MAX_REFUSED);
        assert_eq!(batch.refused_more, 50 - MAX_REFUSED);
        assert!(!batch.is_empty());
        let only_more = Batch { refused_more: 1, ..Batch::default() };
        assert!(!only_more.is_empty());
    }

    #[test]
    fn batches_merge_with_the_caps() {
        let mut a = Batch::sort([p("/s/a.ovpn"), p("/s/one.macvpncatalog"), p("/s/k.macvpnadminkey")]);
        let b = Batch::sort([p("/s/a.ovpn"), p("/s/b.ovpn"), p("/s/two.macvpncatalog")]);
        a.merge(b);
        assert_eq!(a.imports, [p("/s/a.ovpn"), p("/s/b.ovpn")]);
        assert_eq!(a.catalog, Some(p("/s/two.macvpncatalog")), "the latest open's catalog file");
        assert_eq!(a.refused.len(), 1);
        let mut full = Batch::sort((0..MAX_IMPORTED).map(|i| p(&format!("/s/{i}.ovpn"))));
        full.merge(Batch::sort((0..20).map(|i| p(&format!("/t/{i}.macvpnbackup")))));
        full.merge(Batch::sort([p("/t/extra.ovpn")]));
        assert_eq!(full.imports.len(), MAX_IMPORTED);
        assert_eq!((full.refused.len(), full.refused_more), (MAX_REFUSED, 20 - MAX_REFUSED));
    }

    #[test]
    fn one_worker_runs_the_opens_that_arrive_while_it_works() {
        let mut work = WorkQueue::default();
        assert!(!work.submit(Batch::default()), "nothing to run");
        assert!(work.submit(Batch::sort([p("/s/a.ovpn")])), "the first open starts the worker");
        assert!(!work.submit(Batch::sort([p("/s/b.ovpn")])), "the worker runs");
        assert!(!work.submit(Batch::sort([p("/s/c.ovpn")])));
        assert_eq!(work.next_batch().unwrap().imports, [p("/s/a.ovpn"), p("/s/b.ovpn"), p("/s/c.ovpn")]);
        assert!(!work.submit(Batch::sort([p("/s/d.ovpn")])), "still the same worker");
        assert_eq!(work.next_batch().unwrap().imports, [p("/s/d.ovpn")]);
        assert_eq!(work.next_batch(), None, "the worker ends");
        assert!(work.submit(Batch::sort([p("/s/e.ovpn")])), "a new worker");
        work.failed();
        assert!(work.submit(Batch::sort([p("/s/f.ovpn")])), "after a failed start, the next submit starts one");
    }

    #[test]
    fn the_vault_window_is_shown_for_the_first_waiting_open_only() {
        let mut queue = OpenQueue::default();
        queue.launched(false);
        assert_eq!(queue.receive([p("/s/a.ovpn")], false), Received::Queued { show_vault: true, dropped: 0 });
        for i in 0..100 {
            let r = queue.receive([p(&format!("/s/{i}.ovpn"))], false);
            assert!(matches!(r, Received::Queued { show_vault: false, .. }), "{r:?}");
        }
        // Cancelled: the next open shows it again.
        queue.cancel();
        assert_eq!(queue.receive([p("/s/a.ovpn")], false), Received::Queued { show_vault: true, dropped: 0 });
        // Nothing kept (a relative path): nothing to show.
        let mut other = OpenQueue::default();
        other.launched(false);
        assert_eq!(other.receive([PathBuf::from("x.ovpn")], false), Received::Queued { show_vault: false, dropped: 0 });
        // A flood counts what was not looked at as dropped.
        let mut flood = OpenQueue::default();
        flood.launched(false);
        let r = flood.receive((0..10_000).map(|i| p(&format!("/s/{i}.ovpn"))), false);
        assert_eq!(r, Received::Queued { show_vault: true, dropped: 10_000 - MAX_QUEUED });
    }

    fn quarantined(p: &Path) -> bool {
        p.to_string_lossy().contains("Downloads")
    }

    #[test]
    fn local_files_import_without_a_question() {
        let files = vec![p("/Users/me/Documents/a.ovpn"), p("/Users/me/Desktop/b.sstp")];
        let kept = confirm_downloaded(files.clone(), quarantined, |_, _| panic!("asked"));
        assert_eq!(kept, files);
    }

    #[test]
    fn downloaded_files_are_confirmed_once() {
        let files =
            vec![p("/Users/me/Downloads/a.ovpn"), p("/Users/me/Documents/local.ovpn"), p("/Users/me/Downloads/b.sstp")];
        macvpn_core::l10n::AppLanguage::set_thread_override(Some(macvpn_core::l10n::AppLanguage::En));
        let mut asked = 0;
        let kept = confirm_downloaded(files.clone(), quarantined, |title, message| {
            asked += 1;
            assert_eq!(title, "Import 2 downloaded files?");
            assert!(message.contains("a.ovpn, b.sstp"), "{message}");
            assert!(message.contains("Only import files you trust."), "{message}");
            assert!(!message.contains("/Users") && !message.contains("local.ovpn"), "{message}");
            true
        });
        assert_eq!(asked, 1);
        assert_eq!(kept, files, "Import: every file, in order");
        // Cancel: the downloaded ones are not imported, the local one still is.
        let kept = confirm_downloaded(files, quarantined, |_, _| false);
        assert_eq!(kept, [p("/Users/me/Documents/local.ovpn")]);
    }

    #[test]
    fn the_downloaded_question_names_a_few_files() {
        macvpn_core::l10n::AppLanguage::set_thread_override(Some(macvpn_core::l10n::AppLanguage::En));
        let (title, _) = downloaded_question(&["a.ovpn".to_string()]);
        assert_eq!(title, "Import the downloaded file?");
        let names: Vec<String> = (0..15).map(|i| format!("f{i}.ovpn")).collect();
        let (title, message) = downloaded_question(&names);
        assert_eq!(title, "Import 15 downloaded files?");
        assert!(message.contains("f9.ovpn") && !message.contains("f10.ovpn"), "{message}");
        assert!(message.contains("and 5 more"), "{message}");
    }
}
