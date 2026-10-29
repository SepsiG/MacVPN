//! The user's own Windows VPNs as system VPNs (`scutil --nc list` on macOS): the entries of Windows' default
//! phonebooks (the user's `%APPDATA%\…\Pbk\rasphone.pbk` and the all-users one), each with its status from the
//! RAS connection list, connected and disconnected from WinVPN.
//!
//! **Read-only:** WinVPN never writes, renames or deletes these entries, and never changes what Windows keeps for
//! them. The one thing it may add: the L2TP pre-shared key the user stored for it in WinVPN (Windows has no
//! per-dial PSK, as macOS passes it per start), written with `RasSetCredentialsW` just before dialling **only when
//! Windows has no PSK saved for that entry** (`pure::system_vpn::store_psk`); a PSK Windows has is used as it is.
//!
//! A start uses WinVPN's stored password (with the OTP code) and Windows' saved user name, else Windows' saved
//! credentials, else Windows' own sign-in window (`RasDialDlgW`, on a worker thread): `pure::system_vpn::how_to_start`.
//! The status is polled by the manager (the RAS connection notification is only a hint: the RAS spike).

use crate::pure::ras_errors::{self, ErrorContext};
use crate::pure::system_vpn::{
    self, EntryKind, SavedSignIn, Start, connection_status, how_to_start, is_connection_of, same_phonebook,
};
use macvpn_core::models::Secrets;
use macvpn_core::native::NativeKind;
use macvpn_core::ras as core_ras;
use macvpn_platform_api::{NativeController, SystemVpn};
use macvpn_winsys::ras::{self, Auth, Entry, Phonebook, Strategy};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// At most this many system entries are listed (a phonebook is user-writable: bounded work per poll).
const MAX_ENTRIES: usize = 256;
/// How long a hang-up waits for Windows to release the connection.
const HANG_UP_WAIT: Duration = Duration::from_secs(10);

/// Where the system entries come from.
enum Source {
    /// Windows' default phonebooks (`RasEnumEntriesW(NULL, NULL)`).
    Windows,
    /// Tests: these phonebook files stand in for the default ones.
    Books(Vec<PathBuf>),
}

/// One system entry, read.
struct Found {
    id: String,
    book: Phonebook,
    book_path: String,
    entry: Entry,
}

/// The user's own Windows VPNs.
pub(crate) struct SystemVpns {
    source: Source,
    /// WinVPN's private phonebook: its entries are never system VPNs.
    private: Option<PathBuf>,
    /// WinVPN's dials of system VPNs (by ID) until they end: a failed dial's handle is hung up (Microsoft: also
    /// after a failure), and a stop during the dial has the handle before the connection list shows it.
    dials: Arc<Mutex<HashMap<String, ras::Dial>>>,
    /// The IDs whose Windows sign-in window is open (one window per VPN).
    dialogs: Arc<Mutex<HashSet<String>>>,
}

impl SystemVpns {
    /// Windows' default phonebooks; `private` is WinVPN's own phonebook (skipped).
    pub(crate) fn new(private: Option<PathBuf>) -> SystemVpns {
        SystemVpns::with_source(Source::Windows, private)
    }

    /// Tests: `books` stand in for Windows' default phonebooks.
    pub(crate) fn for_test(books: Vec<PathBuf>, private: Option<PathBuf>) -> SystemVpns {
        SystemVpns::with_source(Source::Books(books), private)
    }

    fn with_source(source: Source, private: Option<PathBuf>) -> SystemVpns {
        SystemVpns { source, private, dials: Arc::default(), dialogs: Arc::default() }
    }

    /// The entries with their phonebook path, the private phonebook's left out, bounded.
    fn names(&self) -> Result<Vec<(String, PathBuf)>, String> {
        let listed = match &self.source {
            Source::Windows => ras::system_entries().map_err(|e| e.to_string())?,
            Source::Books(books) => {
                let mut all = Vec::new();
                for path in books {
                    let book = Phonebook::at(path).map_err(|e| e.to_string())?;
                    all.extend(book.entries().map_err(|e| e.to_string())?);
                }
                all
            }
        };
        let private = self.private.as_ref().map(|p| p.to_string_lossy().into_owned());
        Ok(listed
            .into_iter()
            .filter(|e| private.as_deref().is_none_or(|p| !same_phonebook(&e.phonebook.to_string_lossy(), p)))
            .take(MAX_ENTRIES)
            .map(|e| (e.name, e.phonebook))
            .collect())
    }

    /// Every system entry, read (an entry that cannot be read is left out: it may be mid-edit in Settings).
    fn entries(&self) -> Result<Vec<Found>, String> {
        let mut found: Vec<Found> = Vec::new();
        for (name, path) in self.names()? {
            let Ok(book) = Phonebook::at(&path) else { continue };
            let Ok(entry) = book.read(&name) else { continue };
            let id = system_vpn::system_id(entry.guid, &entry.name);
            if found.iter().any(|f| f.id == id) {
                continue;
            }
            found.push(Found { id, book_path: path.to_string_lossy().into_owned(), book, entry });
        }
        Ok(found)
    }

    fn find(&self, id: &str) -> Result<Found, String> {
        self.entries()?.into_iter().find(|f| f.id == id).ok_or_else(gone)
    }

    /// The RAS connection of `f`, if any.
    fn connection(f: &Found, conns: &[ras::Conn]) -> Option<ras::Conn> {
        conns
            .iter()
            .find(|c| {
                is_connection_of(
                    (&c.entry, &c.phonebook.to_string_lossy(), c.entry_guid),
                    (&f.entry.name, &f.book_path, f.entry.guid),
                )
            })
            .cloned()
    }

    /// The system VPNs with their status.
    pub(crate) fn list(&self) -> Result<Vec<SystemVpn>, String> {
        let found = self.entries()?;
        // Over SSH (a network logon) the list is empty; a failure means "no connection known".
        let conns = ras::connections().unwrap_or_default();
        Ok(found
            .iter()
            .map(|f| {
                let status = match SystemVpns::connection(f, &conns) {
                    Some(c) => ras::status(c.handle).map_or("Disconnected", |s| connection_status(s.state, s.error)),
                    None => "Disconnected",
                };
                SystemVpn::new(&f.id, &f.entry.name, system_vpn::type_label(kind(f.entry.strategy)), status)
            })
            .collect())
    }

    /// The tunnel's IPv4 address of the VPN's RAS connection, if it is connected.
    pub(crate) fn address(&self, id: &str) -> Option<String> {
        let f = self.find(id).ok()?;
        let conn = SystemVpns::connection(&f, &ras::connections().ok()?)?;
        ras::ipv4(conn.handle).ok().flatten().map(|a| a.to_string())
    }

    /// Live traffic of the VPN's RAS connection, if it is connected.
    pub(crate) fn traffic(&self, id: &str) -> Option<macvpn_platform_api::TrafficReading> {
        let f = self.find(id).ok()?;
        let conn = SystemVpns::connection(&f, &ras::connections().ok()?)?;
        super::traffic::ras_reading(conn.handle)
    }

    /// The entry's server (`szLocalPhoneNumber`).
    pub(crate) fn remote_address(&self, id: &str) -> Option<String> {
        self.find(id).ok().map(|f| f.entry.server).filter(|s| !s.is_empty())
    }

    /// Connects the system VPN `id` (see the module docs). A VPN that is already connected or connecting, or whose
    /// sign-in window is open, is left as it is.
    pub(crate) fn start(&self, id: &str, kind: Option<NativeKind>, secrets: &Secrets) -> Result<(), String> {
        let f = self.find(id)?;
        if SystemVpns::connection(&f, &ras::connections().unwrap_or_default()).is_some()
            || self.dialogs.lock().unwrap_or_else(|e| e.into_inner()).contains(id)
        {
            return Ok(());
        }
        // A dial of ours that is no longer a connection (it failed or ended): release its handle before the next.
        let stale = self.dials.lock().unwrap_or_else(|e| e.into_inner()).remove(id);
        if let Some(stale) = stale {
            let _ = stale.hang_up_and_wait(HANG_UP_WAIT);
        }
        let name = f.entry.name.clone();
        let refused = |e: ras::Error| explain(&f.entry, e);
        if kind == Some(NativeKind::L2tp) {
            provide_psk(&f.book, &f.entry, non_empty(&secrets.psk)).map_err(refused)?;
        }
        let saved = ras::saved_credentials(&f.book, &name).map_err(refused)?;
        let needs_password = !matches!(f.entry.auth, Auth::MachineCertificate);
        let stored = non_empty(&secrets.password);
        let how = how_to_start(
            needs_password,
            stored.is_some(),
            SavedSignIn { user: !saved.user.is_empty(), password: saved.password },
        );
        let dial = match how {
            Start::Dialog => return self.open_dialog(id, f.book, name),
            // A computer certificate: no user name or password.
            Start::Saved if !needs_password => {
                Some(ras::dial(&f.book, &name, &ras::DialParams::default(), self.on_event(id)).map_err(refused)?)
            }
            Start::Params => ras::dial_saved(&f.book, &name, stored, self.on_event(id)).map_err(refused)?,
            Start::Saved => ras::dial_saved(&f.book, &name, None, self.on_event(id)).map_err(refused)?,
        };
        match dial {
            Some(dial) => {
                self.dials.lock().unwrap_or_else(|e| e.into_inner()).insert(id.to_string(), dial);
                Ok(())
            }
            // Windows' saved password went away in between: its window asks.
            None => self.open_dialog(id, f.book, name),
        }
    }

    /// The dial callback: a failed dial's handle is hung up off the RAS thread (never from the callback), and the
    /// dial is forgotten once it ended.
    fn on_event(&self, id: &str) -> impl Fn(ras::DialEvent) + Send + Sync + 'static {
        let dials = Arc::downgrade(&self.dials);
        let id = id.to_string();
        move |event| {
            if let ras::DialEvent::Failed { .. } = event {
                let (dials, id) = (dials.clone(), id.clone());
                std::thread::spawn(move || {
                    let Some(dials) = dials.upgrade() else { return };
                    let dial = dials.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
                    if let Some(dial) = dial {
                        let _ = dial.hang_up_and_wait(HANG_UP_WAIT);
                    }
                });
            }
        }
    }

    /// Windows' sign-in window for the entry, on a worker thread (it blocks until the user closes it).
    fn open_dialog(&self, id: &str, book: Phonebook, name: String) -> Result<(), String> {
        if !self.dialogs.lock().unwrap_or_else(|e| e.into_inner()).insert(id.to_string()) {
            return Ok(());
        }
        let dialogs = self.dialogs.clone();
        let id = id.to_string();
        std::thread::Builder::new()
            .name("ras-dial-dialog".into())
            .spawn(move || {
                let _ = ras::dial_dlg(&book, &name);
                dialogs.lock().unwrap_or_else(|e| e.into_inner()).remove(&id);
            })
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Disconnects the system VPN `id`: its RAS connection (or WinVPN's dial still in progress) is hung up. A VPN
    /// that is not connected is fine.
    pub(crate) fn stop(&self, id: &str) -> Result<(), String> {
        let dial = self.dials.lock().unwrap_or_else(|e| e.into_inner()).remove(id);
        let conn = self.find(id).ok().and_then(|f| SystemVpns::connection(&f, &ras::connections().unwrap_or_default()));
        let handle = conn.map(|c| c.handle).or(dial.as_ref().map(ras::Dial::handle));
        match handle {
            Some(h) => ras::hang_up(h, HANG_UP_WAIT).map_err(|e| e.to_string()),
            None => Ok(()),
        }
    }
}

/// The text of a refused start: WinVPN's explanation of a Windows code, else the error.
fn explain(entry: &Entry, e: ras::Error) -> String {
    let (Some(code), Some(strategy)) = (e.code(), core_strategy(entry.strategy)) else { return e.to_string() };
    let auth = match entry.auth {
        Auth::MsChapV2 { psk } => core_ras::Auth::MsChapV2 { psk },
        Auth::EapMsChapV2 => core_ras::Auth::EapMsChapV2,
        Auth::MachineCertificate => core_ras::Auth::MachineCertificate,
    };
    let context = ErrorContext { strategy, auth, sstp_custom_ca: false, policy: None };
    ras_errors::explain(code, &context).text
}

fn core_strategy(s: Strategy) -> Option<core_ras::Strategy> {
    match s {
        Strategy::L2tp => Some(core_ras::Strategy::L2tp),
        Strategy::Sstp => Some(core_ras::Strategy::Sstp),
        Strategy::Ikev2 => Some(core_ras::Strategy::Ikev2),
        Strategy::Other(_) => None,
    }
}

fn kind(s: Strategy) -> EntryKind {
    match s {
        Strategy::L2tp => EntryKind::L2tp,
        Strategy::Sstp => EntryKind::Sstp,
        Strategy::Ikev2 => EntryKind::Ikev2,
        Strategy::Other(_) => EntryKind::Other,
    }
}

/// The PSK the user stored in WinVPN for this L2TP PSK entry, into Windows' RAS credential store, only when
/// Windows has none for it (never overwritten). Whether it was written.
pub(crate) fn provide_psk(book: &Phonebook, entry: &Entry, stored: Option<&str>) -> Result<bool, ras::Error> {
    let l2tp_psk = entry.strategy == Strategy::L2tp && matches!(entry.auth, Auth::MsChapV2 { psk: true });
    if !l2tp_psk || stored.is_none() {
        return Ok(false);
    }
    let windows_has = ras::has_psk(book, &entry.name)?;
    match (system_vpn::store_psk(l2tp_psk, stored.is_some(), windows_has), stored) {
        (true, Some(psk)) => ras::set_psk(book, &entry.name, psk).map(|()| true),
        _ => Ok(false),
    }
}

fn non_empty(s: &Option<String>) -> Option<&str> {
    s.as_deref().filter(|v| !v.is_empty())
}

fn gone() -> String {
    macvpn_core::l10n::tr(
        "This Windows VPN no longer exists. It may have been removed in Settings → Network & internet → VPN.",
        &[],
    )
}

/// The system VPNs alone as a native controller (tests; the platform's controller is the RAS engine, which lists
/// its managed entries first and hands every other ID to these).
impl NativeController for SystemVpns {
    fn list(&self) -> Result<Vec<SystemVpn>, String> {
        SystemVpns::list(self)
    }

    fn remote_address(&self, service_id: &str) -> Option<String> {
        SystemVpns::remote_address(self, service_id)
    }

    fn start(&self, service_id: &str, kind: Option<NativeKind>, secrets: &Secrets) -> Result<(), String> {
        SystemVpns::start(self, service_id, kind, secrets)
    }

    fn stop(&self, service_id: &str) -> Result<(), String> {
        SystemVpns::stop(self, service_id)
    }
}
