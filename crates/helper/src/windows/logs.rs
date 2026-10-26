//! The connection logs of the service: `<dir>\<ID>.log`, one per connection, replaced at each `up` (a new
//! generation), masked line by line, at most [`LOG_MAX`] each. A log that reaches its cap during a session (OpenVPN
//! runs for days and its stdout comes here) is rolled: it becomes `<ID>.log.1` (one generation kept, replaced), a new
//! `<ID>.log` starts with a line naming it, and the generation changes, so the app's tail starts over. The directory
//! is the service's private `logs` folder (Task 12 creates it SYSTEM-only); names come only from canonical UUIDs.

use crate::shared::mask::Masker;
use crate::windows::service::{LogSink, LogStore};
use macvpn_core::service_proto::LogSlice;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

pub const LOG_MAX: u64 = 8 * 1024 * 1024;

pub struct FileLogStore {
    shared: Arc<Shared>,
    max: u64,
}

struct Shared {
    dir: PathBuf,
    next_generation: AtomicU64,
    generations: Mutex<HashMap<String, u64>>,
}

impl FileLogStore {
    pub fn new(dir: PathBuf) -> FileLogStore {
        FileLogStore::with_max(dir, LOG_MAX)
    }

    /// A store whose logs roll at `max` bytes (the tests).
    pub fn with_max(dir: PathBuf, max: u64) -> FileLogStore {
        // Generations only need to differ within one service run and from 0 (no log).
        let seed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(1, |d| d.as_secs() << 16);
        let shared = Shared { dir, next_generation: AtomicU64::new(seed.max(1)), generations: Mutex::default() };
        FileLogStore { shared: Arc::new(shared), max: max.max(1) }
    }

    fn path(&self, id: &str) -> Option<PathBuf> {
        self.shared.path(id)
    }
}

impl Shared {
    fn path(&self, id: &str) -> Option<PathBuf> {
        crate::shared::cli::is_uuid(id).then(|| self.dir.join(format!("{}.log", id.to_ascii_uppercase())))
    }

    /// A new generation for `id`'s log.
    fn new_generation(&self, id: &str) -> u64 {
        let generation = self.next_generation.fetch_add(1, Ordering::SeqCst);
        self.generations.lock().unwrap_or_else(PoisonError::into_inner).insert(id.to_ascii_uppercase(), generation);
        generation
    }
}

/// `<ID>.log.1`
fn rotated(path: &std::path::Path) -> PathBuf {
    path.with_extension("log.1")
}

struct FileSink {
    shared: Arc<Shared>,
    id: String,
    max: u64,
    state: Mutex<SinkState>,
    masker: Masker,
}

struct SinkState {
    file: Option<File>,
    written: u64,
    generation: u64,
}

impl FileSink {
    /// Still this sink's log (a newer `up` or a remove replaces it: then this sink stops writing).
    fn current(&self, st: &SinkState) -> bool {
        self.shared.generations.lock().unwrap_or_else(PoisonError::into_inner).get(&self.id) == Some(&st.generation)
    }

    /// The log is full: it becomes `<ID>.log.1` and a new generation starts.
    fn roll(&self, st: &mut SinkState) -> bool {
        st.file = None;
        let Some(path) = self.shared.path(&self.id) else { return false };
        let old = rotated(&path);
        let _ = std::fs::rename(&path, &old);
        st.file = OpenOptions::new().write(true).create(true).truncate(true).open(&path).ok();
        st.generation = self.shared.new_generation(&self.id);
        st.written = 0;
        let name = old.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let note = format!(
            "[WinVPN] {}\n",
            crate::shared::l10n::tr("The log reached its size limit; its earlier part is in %@", &[&name])
        );
        if let Some(f) = st.file.as_mut()
            && f.write_all(note.as_bytes()).is_ok()
        {
            st.written = note.len() as u64;
        }
        st.file.is_some()
    }
}

impl LogSink for FileSink {
    fn line(&self, text: &str) {
        let mut st = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if st.file.is_none() || !self.current(&st) {
            st.file = None;
            return;
        }
        // Masked before it is cut, so a cut never leaves part of a secret.
        let mut line = self.masker.line(text.as_bytes());
        line.truncate(crate::shared::mask::MAX_LINE);
        line.push(b'\n');
        if st.written + line.len() as u64 > self.max && !self.roll(&mut st) {
            return;
        }
        if let Some(f) = st.file.as_mut()
            && f.write_all(&line).is_ok()
        {
            st.written += line.len() as u64;
        }
    }
}

impl LogStore for FileLogStore {
    fn open(&self, id: &str, masker: Masker) -> Box<dyn LogSink> {
        let path = self.path(id);
        let file = path.as_ref().and_then(|p| OpenOptions::new().write(true).create(true).truncate(true).open(p).ok());
        if let Some(p) = &path {
            // The previous connection's rolled part is not this connection's.
            let _ = std::fs::remove_file(rotated(p));
        }
        let generation = self.shared.new_generation(id);
        let state = SinkState { file, written: 0, generation };
        Box::new(FileSink {
            shared: self.shared.clone(),
            id: id.to_ascii_uppercase(),
            max: self.max,
            state: Mutex::new(state),
            masker,
        })
    }

    fn read(&self, id: &str, offset: u64, max: usize) -> Option<LogSlice> {
        let generation =
            *self.shared.generations.lock().unwrap_or_else(PoisonError::into_inner).get(&id.to_ascii_uppercase())?;
        let mut f = File::open(self.path(id)?).ok()?;
        let size = f.seek(SeekFrom::End(0)).ok()?;
        let start = offset.min(size);
        f.seek(SeekFrom::Start(start)).ok()?;
        let mut data = Vec::new();
        f.take(max as u64).read_to_end(&mut data).ok()?;
        // A line written between the seek and the read must not make the slice claim more than `size`.
        data.truncate(usize::try_from(size - start).unwrap_or(usize::MAX));
        Some(LogSlice { generation, size, start, data })
    }

    fn remove(&self, id: &str) {
        self.shared.generations.lock().unwrap_or_else(PoisonError::into_inner).remove(&id.to_ascii_uppercase());
        if let Some(p) = self.path(id) {
            let _ = std::fs::remove_file(rotated(&p));
            let _ = std::fs::remove_file(p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";

    fn len(p: &std::path::Path) -> u64 {
        std::fs::metadata(p).map(|m| m.len()).unwrap_or(0)
    }

    #[test]
    fn a_long_session_rolls_the_log_and_keeps_the_newest_lines() {
        let dir = std::env::temp_dir().join(format!("winvpn-logs-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = FileLogStore::with_max(dir.clone(), 400);
        let path = dir.join(format!("{ID}.log"));
        let sink = store.open(ID, Masker::default());
        let first = store.read(ID, 0, 10).unwrap().generation;
        for i in 0..200 {
            sink.line(&format!("write UDPv4: Network is unreachable (fd=5,code=51) #{i}"));
            assert!(len(&path) <= 400 && len(&rotated(&path)) <= 400, "after {i}");
        }
        let live = std::fs::read_to_string(&path).unwrap();
        assert!(live.starts_with("[WinVPN] ") && live.contains(&format!("{ID}.log.1")), "{live}");
        assert!(live.ends_with("#199\n"), "the newest line is kept");
        assert!(std::fs::read_to_string(rotated(&path)).unwrap().contains("Network is unreachable"));
        let slice = store.read(ID, 0, 1 << 20).unwrap();
        assert_ne!(slice.generation, first, "a roll is a new log for the app's tail");
        assert_eq!(slice.size, len(&path));
        // A new `up` replaces both; the old sink then stops instead of rolling the new log away.
        let fresh = store.open(ID, Masker::default());
        assert!(!rotated(&path).exists());
        for _ in 0..50 {
            sink.line("old connection's line, long enough to fill the log quickly ...........");
        }
        fresh.line("new connection");
        assert!(!rotated(&path).exists());
        assert!(std::fs::read_to_string(&path).unwrap().ends_with("new connection\n"));
        store.remove(ID);
        assert!(!path.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
