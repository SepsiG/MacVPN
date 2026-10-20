//! The file source of team catalogs (spec 4, plan Task 10): a path on a network share or in a synced folder.
//!
//! - The opening rules are core's `read_catalog_file` (`O_NOFOLLOW` on the last component, a regular file only, the
//!   8 MB cap, the "unavailable" errnos of spike decision B2).
//! - The read runs on a worker thread with [`FILE_READ_TIMEOUT`] (decision B2): an unplugged SMB server can block
//!   `open` and `read` for minutes. A read that does not finish in time is [`CatalogError::Unavailable`]; its thread
//!   is left to finish on its own and is counted ([`FileCatalogFetcher::hung_reads`]), and while it runs, a new fetch
//!   of the same path returns `Unavailable` at once instead of starting another thread (at most one hung read per
//!   path).
//! - Change detection (decision B1): always read, and compare the SHA-256 of the content with the stored
//!   `content_hash`; no `fstat` shortcut.
//!
//! Nothing here logs; a file source is named by its file name only.

use crate::deps::{CatalogFetcher, FetchOutcome, FetchRequest};
use macvpn_core::catalog::fetch::content_hash;
use macvpn_core::catalog::format::CatalogError;
use macvpn_core::catalog::source::{CatalogSource, read_catalog_file};
use macvpn_core::vault::SourceValidators;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::time::Duration;

/// How long one read of a file source may take (spike decision B2).
pub const FILE_READ_TIMEOUT: Duration = Duration::from_secs(20);

type Reader = dyn Fn(&Path) -> Result<Vec<u8>, CatalogError> + Send + Sync;

/// The file source (see the module docs).
pub struct FileCatalogFetcher {
    timeout: Duration,
    reader: Arc<Reader>,
    /// The paths with a read in progress (on time or hung).
    running: Arc<Mutex<HashSet<PathBuf>>>,
    /// Reads past their timeout that have not finished yet.
    hung: Arc<AtomicUsize>,
}

impl Default for FileCatalogFetcher {
    fn default() -> Self {
        Self::new()
    }
}

fn file_name(path: &Path) -> String {
    path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

impl FileCatalogFetcher {
    /// `read_catalog_file` with [`FILE_READ_TIMEOUT`].
    pub fn new() -> Self {
        Self::build(FILE_READ_TIMEOUT, Arc::new(read_catalog_file))
    }

    /// Another reader and timeout: a reader that blocks, for the timeout tests.
    #[cfg(feature = "test-support")]
    pub fn with_reader(
        timeout: Duration,
        reader: impl Fn(&Path) -> Result<Vec<u8>, CatalogError> + Send + Sync + 'static,
    ) -> Self {
        Self::build(timeout, Arc::new(reader))
    }

    fn build(timeout: Duration, reader: Arc<Reader>) -> Self {
        FileCatalogFetcher {
            timeout,
            reader,
            running: Arc::new(Mutex::new(HashSet::new())),
            hung: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// The reads that passed their timeout and are still blocked.
    pub fn hung_reads(&self) -> usize {
        self.hung.load(Ordering::SeqCst)
    }

    /// Reads `path` on a worker thread, at most `timeout`.
    fn read(&self, path: &Path) -> Result<Vec<u8>, CatalogError> {
        let unavailable = || CatalogError::Unavailable(file_name(path));
        if !self.running.lock().unwrap_or_else(PoisonError::into_inner).insert(path.to_path_buf()) {
            return Err(unavailable());
        }
        let (tx, rx) = mpsc::channel();
        // Set by whichever side gets there first: the worker when it finished, or the caller when it stopped
        // waiting. The worker that finds it set was counted as hung and counts itself out; the caller that finds
        // it set takes the result after all.
        let settled = Arc::new(Mutex::new(false));
        let worker = Worker {
            running: self.running.clone(),
            hung: self.hung.clone(),
            settled: settled.clone(),
            path: path.to_path_buf(),
            tx,
            result: None,
        };
        let reader = self.reader.clone();
        let spawned = std::thread::Builder::new().name("macvpn-catalog-file".into()).spawn(move || {
            // A panicking reader drops `worker` without a result: the bookkeeping still runs.
            let result = reader(&worker.path);
            worker.finish(result);
        });
        if spawned.is_err() {
            // The closure (and its worker) was dropped: the path is free again.
            return Err(CatalogError::Io("cannot read the team catalog file".into()));
        }
        match rx.recv_timeout(self.timeout) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err(CatalogError::Io("cannot read the team catalog file".into()))
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let mut done = settled.lock().unwrap_or_else(PoisonError::into_inner);
                if *done {
                    // Finished just now: take its result after all.
                    drop(done);
                    return rx
                        .recv()
                        .unwrap_or_else(|_| Err(CatalogError::Io("cannot read the team catalog file".into())));
                }
                *done = true;
                self.hung.fetch_add(1, Ordering::SeqCst);
                Err(unavailable())
            }
        }
    }
}

/// The worker's side of one read. Its `Drop` does the bookkeeping (free the path, count a hung read out, hand
/// over the result), so it also runs when the reader panics.
struct Worker {
    running: Arc<Mutex<HashSet<PathBuf>>>,
    hung: Arc<AtomicUsize>,
    settled: Arc<Mutex<bool>>,
    path: PathBuf,
    tx: mpsc::Sender<Result<Vec<u8>, CatalogError>>,
    result: Option<Result<Vec<u8>, CatalogError>>,
}

impl Worker {
    /// Hands the result over (through `Drop`).
    fn finish(mut self, result: Result<Vec<u8>, CatalogError>) {
        self.result = Some(result);
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let mut done = self.settled.lock().unwrap_or_else(PoisonError::into_inner);
        if *done {
            self.hung.fetch_sub(1, Ordering::SeqCst);
        }
        self.running.lock().unwrap_or_else(PoisonError::into_inner).remove(&self.path);
        *done = true;
        drop(done);
        if let Some(result) = self.result.take() {
            let _ = self.tx.send(result);
        }
    }
}

impl CatalogFetcher for FileCatalogFetcher {
    fn fetch(&self, req: &FetchRequest) -> Result<FetchOutcome, CatalogError> {
        let CatalogSource::File(path) = req.source else {
            return Err(CatalogError::Io("not a file source".into()));
        };
        let bytes = self.read(path)?;
        let hash = content_hash(&bytes);
        if req.previous.content_hash == Some(hash) {
            return Ok(FetchOutcome::NotModified);
        }
        Ok(FetchOutcome::Fetched {
            bytes,
            validators: SourceValidators { content_hash: Some(hash), ..Default::default() },
        })
    }
}
