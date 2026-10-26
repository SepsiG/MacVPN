//! The `RasEngine` (WinVPN 2c, Task 8): L2TP, IKEv2 and SSTP through RAS entries in WinVPN's private phonebook
//! (`%LOCALAPPDATA%\WinVPN\ras\WinVPN.pbk`), dialled with `RasDialW` in the app's own process (the user's
//! context; no WinVPN Service, no administrator).
//!
//! - **L2TP** keeps the macOS model (`NativeController` + `NativeProfiles`): Save writes the entry (`install`, no
//!   approval step) and the connection's profile (`<UUID>.ras`: its plan, no secret); a connect rewrites the entry
//!   from that profile, stores the PSK in Windows' RAS credential store and dials.
//! - **IKEv2 and SSTP** keep the helper model (`HelperClient`, routed by [`RasHelper`]): each `up` writes the entry
//!   from the config it is given, then dials.
//! - Every entry is named `WinVPN-<UUID>` (`macvpn_core::ras::names`); the engine writes, dials and deletes no
//!   other name. Secrets are used at dial time only: the password (with the OTP code the manager appended) goes
//!   into `RASDIALPARAMSW` (wiped by winsys after the call), the PSK into the RAS credential store at each connect
//!   (cleared before the entry is deleted). Nothing secret is in the phonebook, the profile or the log.
//! - `up` and `start` return once the dial is connected or failed (G-5: a rejected sign-in comes back as the
//!   sign-in failure text, so the manager asks for the credentials once more, as macOS' helper `up` does).
//! - Every dial state, warning, error and (in debug mode) the entry's settings go to the connection's masked log
//!   (`logs\ras\<UUID>.log`), which the Log tab tails (G-2).
//! - Connections survive a relaunch (RasMan owns them): the engine finds them with `RasEnumConnectionsW` by this
//!   phonebook's path (compared without regard to letter case) and the entry name.

use super::ras_paths::{RasLog, RasPaths};
use super::service_client::ServiceClient;
use super::system;
use super::system_vpns::SystemVpns;
use crate::pure::ras_connect as rc;
use crate::pure::ras_errors::ErrorContext;
use crate::pure::ras_log::{self, LogMasker};
use crate::pure::ras_state::{self, DialEvent, DialState, rascs};
use crate::pure::ras_sweep;
use crate::pure::texts;
use macvpn_core::l10n::{self, Arg};
use macvpn_core::log::{FileLogSource, LogSource};
use macvpn_core::mfa::AuthResponseKind;
use macvpn_core::models::{Connection, Secrets, VPNKind};
use macvpn_core::native::NativeKind;
use macvpn_core::ras::policy::{DhGroup, EspCipher, EspIntegrity, IkeCipher, IkeIntegrity};
use macvpn_core::ras::{Auth, DefaultRoute, RasEntryPlan, Strategy, WindowsPolicy, names};
use macvpn_core::status::RootStatus;
use macvpn_platform_api::{HelperClient, NativeController, NativeProfile, NativeProfiles, NativeSupport, SystemVpn};
use macvpn_winsys::ras as wras;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, channel};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// How long `up` / `start` wait for the dial's outcome. A silent L2TP server fails after about 65 s (789), SSTP
/// after 21 s, IKEv2 after 5 s (the RAS spike); a server that keeps answering slowly is cut here.
const DIAL_WAIT: Duration = Duration::from_secs(150);
/// A hang-up waits this long for Windows to release the handle.
const HANG_UP_WAIT: Duration = Duration::from_secs(10);
/// After a failed dial the handle is released (Microsoft: hang up even after a failure); a short wait.
const FAILED_HANG_UP_WAIT: Duration = Duration::from_secs(5);
/// `ERROR_PORT_NOT_AVAILABLE` (633) right after a hang-up: the WAN Miniport is still busy. One retry after this.
const BUSY_RETRY_AFTER: Duration = Duration::from_secs(2);
const DEVICE_BUSY: u32 = crate::pure::ras_errors::codes::PORT_NOT_AVAILABLE;
/// `ERROR_INTERACTIVE_MODE`: Windows paused the dial for input WinVPN cannot give.
const INTERACTIVE_MODE: u32 = 703;

fn now() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64())
}

fn local_now() -> String {
    system::local_time(now()).map(rc::timestamp).unwrap_or_default()
}

/// The engine of the process (one per process: `WinPlatform` shares it). `Err`: its folders could not be made
/// safe; every action answers why.
pub(crate) struct RasEngine {
    ready: Result<Arc<Inner>, String>,
    /// The user's own Windows VPNs (Task 9): listed after the managed entries; every ID that is not a
    /// `WinVPN-<UUID>` entry name is theirs.
    system: SystemVpns,
}

struct Inner {
    paths: RasPaths,
    book: wras::Phonebook,
    /// The phonebook path as `RASCONNW.szPhonebook` reports it for our dials, lower case.
    book_key: String,
    slots: Mutex<HashMap<Uuid, Slot>>,
    /// Signalled whenever a slot changes (the waits of `up` / `start`).
    changed: Condvar,
    /// Each entry's strategy (the list's type label), read once per name.
    strategies: Mutex<HashMap<String, Strategy>>,
}

/// One connection's dial: its state, its handle, the live dial (its callback registration) and its log.
struct Slot {
    kind: VPNKind,
    dial: ras_state::Dial,
    handle: Option<wras::Handle>,
    live: Option<wras::Dial>,
    log: Arc<RasLog>,
    masker: Arc<LogMasker>,
    attempt: u64,
}

impl Slot {
    fn is_busy(&self) -> bool {
        matches!(self.dial.state(), DialState::Dialling { .. } | DialState::HangingUp)
    }

    /// Applies `event`, writes its lines (masked; an error's as error lines) and returns nothing.
    fn apply(&mut self, event: DialEvent) {
        let error = matches!(event, DialEvent::Error { .. });
        let lines = self.dial.apply(event);
        let lines: Vec<String> = lines
            .iter()
            .map(|l| {
                let l = self.masker.line(l);
                if error { rc::error_line(&l) } else { l }
            })
            .collect();
        self.log.lines(&lines);
    }
}

/// How a dial ended for `up` / `start`.
enum Outcome {
    Connected,
    Failed(String),
    /// Hung up by WinVPN meanwhile (the user's disconnect): not an error.
    Cancelled,
    TimedOut,
}

static ATTEMPTS: AtomicU64 = AtomicU64::new(1);

impl RasEngine {
    /// The engine over WinVPN's data directory `data` (`%LOCALAPPDATA%\WinVPN`); its folders are made (private)
    /// here. `None`: no data directory could be found.
    pub(crate) fn open(data: Option<&Path>) -> RasEngine {
        let private = data.map(|d| d.join(names::PHONEBOOK_DIR).join(names::PHONEBOOK_FILE));
        RasEngine::with_system(data, SystemVpns::new(private))
    }

    /// [`Self::open`] with `system` as the user's own Windows VPNs (tests: temp phonebooks, or none).
    pub(crate) fn with_system(data: Option<&Path>, system: SystemVpns) -> RasEngine {
        let ready = match data {
            Some(data) => Inner::open(data).map(Arc::new),
            None => Err(texts::data_folder_missing()),
        };
        RasEngine { ready, system }
    }

    fn inner(&self) -> Result<&Arc<Inner>, String> {
        self.ready.as_ref().map_err(Clone::clone)
    }

    /// The phonebook's path (tests).
    pub(crate) fn phonebook_path(&self) -> Option<std::path::PathBuf> {
        self.inner().ok().map(|i| i.paths.phonebook())
    }

    /// The connection's log path (tests).
    pub(crate) fn log_path(&self, id: &Uuid) -> Option<std::path::PathBuf> {
        self.inner().ok().map(|i| i.paths.log(id))
    }

    /// IKEv2 / SSTP `up`: the plan from `config`, the entry, the dial; returns once it is connected or failed.
    pub(crate) fn up(
        &self,
        kind: VPNKind,
        id: &Uuid,
        config: &[u8],
        secrets: &Secrets,
        debug: bool,
    ) -> Result<(), String> {
        let inner = self.inner()?;
        let plan = rc::helper_plan(kind, config)?;
        inner.connect(id, kind, &plan, config, secrets, debug)
    }

    pub(crate) fn down(&self, id: &Uuid) -> Result<(), String> {
        self.inner()?.disconnect(id)
    }

    /// The IKEv2 and SSTP connections' states, as the root layer reports them.
    pub(crate) fn root_statuses(&self) -> Vec<RootStatus> {
        let Ok(inner) = self.inner() else { return Vec::new() };
        inner.refresh();
        let slots = inner.lock();
        slots
            .iter()
            .filter(|(_, s)| rc::is_helper_kind(s.kind))
            .filter_map(|(id, s)| s.dial.state().root_status(*id, s.kind))
            .collect()
    }

    /// The connection has a RAS log (it was dialled through this engine at least once).
    pub(crate) fn has_log(&self, id: &Uuid) -> bool {
        self.inner().is_ok_and(|i| i.paths.log(id).is_file())
    }

    fn log_source_of(&self, id: &Uuid) -> Option<Box<dyn LogSource>> {
        let inner = self.inner().ok()?;
        Some(Box::new(FileLogSource { path: inner.paths.log(id) }))
    }

    /// Hangs up every WinVPN RAS connection of this user (the logoff, `WM_ENDSESSION`).
    pub(crate) fn hang_up_all(&self) {
        let Ok(inner) = self.inner() else { return };
        inner.refresh();
        let ids: Vec<Uuid> = inner.lock().keys().copied().collect();
        for id in ids {
            let _ = inner.disconnect(&id);
        }
    }
}

impl Inner {
    fn open(data: &Path) -> Result<Inner, String> {
        let paths = RasPaths::prepare(data)?;
        let path = paths.phonebook();
        let book = wras::Phonebook::at(&path).map_err(|e| e.to_string())?;
        Ok(Inner {
            book_key: path.to_string_lossy().to_lowercase(),
            paths,
            book,
            slots: Mutex::default(),
            changed: Condvar::new(),
            strategies: Mutex::default(),
        })
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<Uuid, Slot>> {
        self.slots.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Applies `event` to the slot of `id` if `attempt` is still its dial; wakes the waits.
    fn apply(&self, id: &Uuid, attempt: u64, event: DialEvent) {
        let mut slots = self.lock();
        if let Some(slot) = slots.get_mut(id).filter(|s| s.attempt == attempt) {
            slot.apply(event);
        }
        drop(slots);
        self.changed.notify_all();
    }

    fn is_ours(&self, phonebook: &Path) -> bool {
        phonebook.to_string_lossy().to_lowercase() == self.book_key
    }

    /// Writes the entry `name` from `plan` (the whole entry, its EAP data and its policy keys).
    fn write_entry(&self, name: &str, plan: &RasEntryPlan) -> Result<(), String> {
        let entry = entry_for(name, plan)?;
        self.book.write(&entry).map_err(|e| {
            let text = e.to_string();
            l10n::tr("The Windows VPN entry could not be written: %@", &[Arg::Str(&text)])
        })?;
        self.strategies.lock().unwrap_or_else(PoisonError::into_inner).insert(name.to_string(), plan.strategy);
        Ok(())
    }

    /// Writes the entry, stores the PSK, dials and waits for the outcome.
    fn connect(
        self: &Arc<Self>,
        id: &Uuid,
        kind: VPNKind,
        plan: &RasEntryPlan,
        config: &[u8],
        secrets: &Secrets,
        debug: bool,
    ) -> Result<(), String> {
        let name = names::entry_name(id);
        self.refresh();
        {
            let slots = self.lock();
            if let Some(slot) = slots.get(id) {
                match slot.dial.state() {
                    DialState::Dialling { .. } | DialState::HangingUp => {
                        return Err(l10n::tr("This connection is already connecting.", &[]));
                    }
                    DialState::Connected { .. } => return Ok(()),
                    DialState::Idle | DialState::Failed { .. } => {}
                }
            }
        }
        let log = Arc::new(RasLog::create(self.paths.log(id)));
        let masker = Arc::new(LogMasker::new(secrets));
        let mut first = vec![rc::header(&local_now(), kind, id, debug)];
        first.extend(plan.warnings.iter().cloned());
        if debug {
            first.extend(ras_log::entry_dump(plan));
        }
        log.lines(&masker.lines(&first));
        let fail = |text: String| {
            log.lines(&[rc::error_line(&masker.line(&text))]);
            Err(text)
        };
        let psk = match rc::dial_psk(plan, secrets) {
            Ok(psk) => psk,
            Err(e) => return fail(e),
        };
        let user = rc::dial_user(plan, secrets);
        let password = rc::dial_password(plan, secrets);
        if let Err(e) = self.write_entry(&name, plan) {
            return fail(e);
        }
        if let Some(psk) = psk
            && let Err(e) = wras::set_psk(&self.book, &name, psk)
        {
            let text = e.to_string();
            return fail(l10n::tr("The Windows VPN entry could not be written: %@", &[Arg::Str(&text)]));
        }

        let attempt = ATTEMPTS.fetch_add(1, Ordering::SeqCst);
        let context = rc::error_context(plan, config);
        let mut slot = Slot {
            kind,
            dial: ras_state::Dial::new(&plan.server, context),
            handle: None,
            live: None,
            log,
            masker,
            attempt,
        };
        slot.apply(DialEvent::Started);
        let previous = self.lock().insert(*id, slot);
        drop(previous);

        let (tx, rx) = channel::<wras::DialEvent>();
        let params = wras::DialParams::user(&user, &password);
        let dial = |tx: std::sync::mpsc::Sender<wras::DialEvent>| {
            wras::dial(&self.book, &name, &params, move |event| {
                let _ = tx.send(event);
            })
        };
        let dialled = match dial(tx.clone()) {
            Err(e) if e.code() == Some(DEVICE_BUSY) => {
                std::thread::sleep(BUSY_RETRY_AFTER);
                dial(tx)
            }
            other => {
                drop(tx);
                other
            }
        };
        drop(password);
        let live = match dialled {
            Ok(live) => live,
            Err(e) => {
                match e.code() {
                    Some(code) => {
                        let windows_text = wras::error_text(code);
                        self.apply(id, attempt, DialEvent::Error { code, at: now(), windows_text });
                        self.apply(id, attempt, DialEvent::Ended);
                    }
                    None => {
                        let text = e.to_string();
                        self.with_slot(id, attempt, |s| {
                            s.log.lines(&[rc::error_line(&s.masker.line(&text))]);
                            s.dial = ras_state::Dial::new(&plan.server, rc::error_context(plan, config));
                        });
                        self.changed.notify_all();
                        return Err(text);
                    }
                }
                return Err(self.failure_text(id, attempt).unwrap_or_else(|| e.to_string()));
            }
        };
        let handle = live.handle();
        // The user may have disconnected while `RasDialW` ran: the new connection is hung up at once.
        let hang_up_now = self
            .with_slot(id, attempt, |s| {
                s.handle = Some(handle);
                s.live = Some(live);
                matches!(s.dial.state(), DialState::HangingUp)
            })
            .unwrap_or(true);
        if hang_up_now {
            let _ = wras::hang_up(handle, HANG_UP_WAIT);
            let live = self.with_slot(id, attempt, |s| {
                s.apply(DialEvent::Ended);
                s.handle = None;
                s.live.take()
            });
            drop(live);
            self.changed.notify_all();
            return Ok(());
        }
        let follower = self.clone();
        let id_copy = *id;
        let _ = std::thread::Builder::new()
            .name("winvpn-ras-dial".into())
            .spawn(move || follower.follow(id_copy, attempt, handle, rx));

        match self.wait(id, attempt, DIAL_WAIT) {
            Outcome::Connected | Outcome::Cancelled => Ok(()),
            Outcome::Failed(text) => Err(text),
            Outcome::TimedOut => {
                let _ = self.disconnect(id);
                let text = l10n::tr("Timed out", &[]);
                self.with_slot(id, attempt, |s| s.log.lines(&[rc::error_line(&text)]));
                Err(text)
            }
        }
    }

    fn with_slot<T>(&self, id: &Uuid, attempt: u64, f: impl FnOnce(&mut Slot) -> T) -> Option<T> {
        let mut slots = self.lock();
        slots.get_mut(id).filter(|s| s.attempt == attempt).map(f)
    }

    fn failure_text(&self, id: &Uuid, attempt: u64) -> Option<String> {
        self.with_slot(id, attempt, |s| s.dial.failure().map(|f| f.text)).flatten()
    }

    /// The dial's events (from the RAS callback thread, through `rx`), on its own thread: the address after a
    /// connect, Windows' text and the release of the handle after a failure (no RAS call runs in the callback).
    fn follow(&self, id: Uuid, attempt: u64, handle: wras::Handle, rx: Receiver<wras::DialEvent>) {
        for event in rx {
            match event {
                wras::DialEvent::State(state) if (rascs::INTERACTIVE..rascs::CONNECTED).contains(&state) => {
                    // Paused for input (EAP UI, a password change, …): WinVPN cannot answer; the dial fails.
                    self.apply(&id, attempt, DialEvent::Step(state));
                    let windows_text = wras::error_text(INTERACTIVE_MODE);
                    self.apply(&id, attempt, DialEvent::Error { code: INTERACTIVE_MODE, at: now(), windows_text });
                    self.end_failed(&id, attempt, handle);
                    return;
                }
                wras::DialEvent::State(state) => self.apply(&id, attempt, DialEvent::Step(state)),
                wras::DialEvent::Connected => {
                    let ipv4 = wras::ipv4(handle).ok().flatten().map(|a| a.to_string());
                    // The secrets are no longer needed for masking: later lines are WinVPN's and Windows' texts.
                    self.with_slot(&id, attempt, |s| s.masker = Arc::new(LogMasker::default()));
                    self.apply(&id, attempt, DialEvent::Connected { ipv4, at: now() });
                }
                wras::DialEvent::Failed { code } => {
                    let windows_text = wras::error_text(code);
                    self.apply(&id, attempt, DialEvent::Error { code, at: now(), windows_text });
                    self.end_failed(&id, attempt, handle);
                    return;
                }
            }
        }
    }

    /// After a failure: the handle is released (unless WinVPN's own hang-up does it), the dial ends.
    fn end_failed(&self, id: &Uuid, attempt: u64, handle: wras::Handle) {
        let ours = self.with_slot(id, attempt, |s| !matches!(s.dial.state(), DialState::HangingUp)).unwrap_or(false);
        if ours {
            let _ = wras::hang_up(handle, FAILED_HANG_UP_WAIT);
        }
        let live = self.with_slot(id, attempt, |s| {
            s.apply(DialEvent::Ended);
            s.handle = None;
            s.masker = Arc::new(LogMasker::default());
            s.live.take()
        });
        drop(live);
        self.changed.notify_all();
    }

    fn wait(&self, id: &Uuid, attempt: u64, limit: Duration) -> Outcome {
        let deadline = Instant::now() + limit;
        let mut slots = self.lock();
        loop {
            let Some(slot) = slots.get(id).filter(|s| s.attempt == attempt) else { return Outcome::Cancelled };
            match slot.dial.state() {
                DialState::Connected { .. } => return Outcome::Connected,
                DialState::Failed { .. } => {
                    return Outcome::Failed(slot.dial.failure().map(|f| f.text).unwrap_or_default());
                }
                DialState::Idle => return Outcome::Cancelled,
                DialState::Dialling { .. } | DialState::HangingUp => {}
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Outcome::TimedOut;
            }
            slots = self.changed.wait_timeout(slots, left).unwrap_or_else(PoisonError::into_inner).0;
        }
    }

    /// Hangs up the connection (`RasHangUpW`, then waits until Windows released it). Nothing to do: `Ok`.
    fn disconnect(&self, id: &Uuid) -> Result<(), String> {
        self.refresh();
        let target = {
            let mut slots = self.lock();
            let Some(slot) = slots.get_mut(id) else { return Ok(()) };
            let active = matches!(slot.dial.state(), DialState::Dialling { .. } | DialState::Connected { .. });
            if !active {
                return Ok(());
            }
            slot.apply(DialEvent::HangUp);
            (slot.handle, slot.attempt)
        };
        self.changed.notify_all();
        let (handle, attempt) = target;
        let result = match handle {
            Some(handle) => wras::hang_up(handle, HANG_UP_WAIT),
            // `RasDialW` has not returned yet: `connect` hangs the new handle up itself.
            None => Ok(()),
        };
        let live = self.with_slot(id, attempt, |s| {
            if handle.is_some() {
                s.apply(DialEvent::Ended);
                s.handle = None;
            }
            s.live.take()
        });
        drop(live);
        self.changed.notify_all();
        result.map_err(|e| match e {
            wras::Error::Timeout => l10n::tr("Timed out", &[]),
            other => other.to_string(),
        })
    }

    /// Follows the system's view: connections of this phonebook WinVPN does not know yet (dialled before a
    /// relaunch) are taken over; a connected one that is gone dropped. A failed listing changes nothing (and a
    /// network logon lists none of its own: its dials never connect anyway).
    fn refresh(&self) {
        let Ok(conns) = wras::connections() else { return };
        let ours: Vec<(Uuid, wras::Handle)> = conns
            .iter()
            .filter(|c| self.is_ours(&c.phonebook))
            .filter_map(|c| names::connection_id(&c.entry).map(|id| (id, c.handle)))
            .collect();
        let unknown: Vec<(Uuid, wras::Handle)> = {
            let mut slots = self.lock();
            for slot in slots.values_mut() {
                let present = slot.handle.is_some_and(|h| ours.iter().any(|(_, o)| *o == h));
                if matches!(slot.dial.state(), DialState::Connected { .. }) && !present {
                    // Closed by the server or the network.
                    slot.apply(DialEvent::Ended);
                    slot.handle = None;
                    slot.live = None;
                }
            }
            ours.iter()
                .filter(|(id, h)| !slots.get(id).is_some_and(|s| s.handle == Some(*h) || s.is_busy()))
                .copied()
                .collect()
        };
        for (id, handle) in unknown {
            self.adopt(id, handle);
        }
        self.changed.notify_all();
    }

    /// A connection of this phonebook dialled by an earlier run (or found before its own callback): its slot.
    fn adopt(&self, id: Uuid, handle: wras::Handle) {
        let name = names::entry_name(&id);
        let Ok(entry) = self.book.read(&name) else { return };
        let Some(strategy) = core_strategy(entry.strategy) else { return };
        let Ok(status) = wras::status(handle) else { return };
        let context = ErrorContext { strategy, auth: core_auth(entry.auth), sstp_custom_ca: false, policy: None };
        let mut dial = ras_state::Dial::new(&entry.server, context);
        dial.apply(DialEvent::Started);
        if status.state == rascs::CONNECTED {
            let ipv4 = wras::ipv4(handle).ok().flatten().map(|a| a.to_string());
            dial.apply(DialEvent::Connected { ipv4, at: now() });
        } else if status.error == 0 {
            dial.apply(DialEvent::Step(status.state));
        } else {
            return;
        }
        let slot = Slot {
            kind: rc::kind_of(strategy),
            dial,
            handle: Some(handle),
            live: None,
            log: Arc::new(RasLog::append_to(self.paths.log(&id))),
            masker: Arc::new(LogMasker::default()),
            attempt: ATTEMPTS.fetch_add(1, Ordering::SeqCst),
        };
        self.lock().insert(id, slot);
    }

    fn strategy_of(&self, name: &str) -> Option<Strategy> {
        if let Some(s) = self.strategies.lock().unwrap_or_else(PoisonError::into_inner).get(name) {
            return Some(*s);
        }
        let strategy = core_strategy(self.book.read(name).ok()?.strategy)?;
        self.strategies.lock().unwrap_or_else(PoisonError::into_inner).insert(name.to_string(), strategy);
        Some(strategy)
    }

    /// The managed entries of the phonebook, each with its state.
    fn list(&self) -> Result<Vec<SystemVpn>, String> {
        self.refresh();
        let entries = self.book.entries().map_err(|e| e.to_string())?;
        let slots = self.lock();
        let mut out = Vec::new();
        for e in entries {
            let Some(id) = names::connection_id(&e.name) else { continue };
            let Some(strategy) = self.strategy_of(&e.name) else { continue };
            let status = slots.get(&id).map_or("Disconnected", |s| s.dial.state().system_status());
            out.push(SystemVpn::new(&e.name, &e.name, rc::type_label(strategy), status));
        }
        Ok(out)
    }

    /// Task 13: removes what WinVPN keeps for connections not in `known` (the open vault's): each orphaned
    /// `WinVPN-<UUID>` entry with its stored PSK, profile and logs ([`Self::remove`]), then the profile and log files
    /// left without an entry. Only WinVPN's own names are chosen (`pure::ras_sweep`); every other entry or file
    /// stays. A phonebook that cannot be listed leaves the entries for the next sweep.
    fn reconcile(&self, known: &HashSet<Uuid>) {
        if let Ok(entries) = self.book.names() {
            for id in ras_sweep::orphan_entries(entries.iter().map(String::as_str), known) {
                self.remove(&id);
            }
        }
        let files = self.paths.file_names();
        for id in ras_sweep::orphan_files(files.iter().map(String::as_str), known) {
            self.paths.forget(&id);
        }
    }

    /// Deletes the connection's entry, its stored PSK, its profile and its logs.
    fn remove(&self, id: &Uuid) {
        let _ = self.disconnect(id);
        let name = names::entry_name(id);
        let _ = wras::clear_psk(&self.book, &name);
        let _ = self.book.delete(&name);
        self.strategies.lock().unwrap_or_else(PoisonError::into_inner).remove(&name);
        let slot = self.lock().remove(id);
        drop(slot);
        self.paths.forget(id);
    }
}

/// `winsys`' entry of a plan (the policy numbers are `winsys`'; the mapping is here, as Task 5 left it).
fn entry_for(name: &str, plan: &RasEntryPlan) -> Result<wras::Entry, String> {
    let strategy = match plan.strategy {
        Strategy::L2tp => wras::Strategy::L2tp,
        Strategy::Sstp => wras::Strategy::Sstp,
        Strategy::Ikev2 => wras::Strategy::Ikev2,
    };
    let auth = match plan.auth {
        Auth::MsChapV2 { psk } => wras::Auth::MsChapV2 { psk },
        Auth::EapMsChapV2 => wras::Auth::EapMsChapV2,
        Auth::MachineCertificate => wras::Auth::MachineCertificate,
        // No entry form Windows dials with (the RAS spike); `plan_ikev2` never produces it.
        Auth::Ikev2Psk => return Err(l10n::tr("Not supported on Windows: %@", &[Arg::Str("local auth = psk")])),
    };
    let (v4, v6) = match plan.default_route {
        DefaultRoute::None => (false, false),
        DefaultRoute::Ipv4 => (true, false),
        DefaultRoute::Both => (true, true),
    };
    Ok(wras::Entry {
        name: name.to_string(),
        strategy,
        server: plan.server.clone(),
        auth,
        default_gateway_v4: v4,
        default_gateway_v6: v6,
        ts_as_routes: plan.ts_as_routes,
        // winsys: always on for L2TP and SSTP (the switch is IKEv2's).
        ike_fragmentation: plan.strategy != Strategy::Ikev2 || plan.ike_fragmentation,
        interface_metric: plan.interface_metric,
        policy: plan.policy.as_ref().map(ipsec_policy),
        guid: None,
    })
}

/// `core::ras::WindowsPolicy` (named algorithms) → `winsys`' `IpsecPolicy` (the VpnClient numbers).
pub(crate) fn ipsec_policy(p: &WindowsPolicy) -> wras::IpsecPolicy {
    let dh = |g: DhGroup| match g {
        DhGroup::Group2 => wras::DhGroup::Group2,
        DhGroup::Group14 => wras::DhGroup::Group14,
        DhGroup::Group24 => wras::DhGroup::Group24,
        DhGroup::Ecp256 => wras::DhGroup::Ecp256,
        DhGroup::Ecp384 => wras::DhGroup::Ecp384,
    };
    let pfs = |g: Option<DhGroup>| match g {
        None => wras::PfsGroup::None,
        Some(DhGroup::Group2) => wras::PfsGroup::Pfs2,
        Some(DhGroup::Group14) => wras::PfsGroup::Pfs2048,
        Some(DhGroup::Group24) => wras::PfsGroup::Pfs24,
        Some(DhGroup::Ecp256) => wras::PfsGroup::Ecp256,
        Some(DhGroup::Ecp384) => wras::PfsGroup::Ecp384,
    };
    wras::IpsecPolicy {
        integrity: match p.ike_integrity {
            IkeIntegrity::Sha1 => wras::Integrity::Sha1,
            IkeIntegrity::Sha256 => wras::Integrity::Sha256,
            IkeIntegrity::Sha384 => wras::Integrity::Sha384,
        },
        encryption: match p.ike_cipher {
            IkeCipher::Aes128 => wras::Encryption::Aes128,
            IkeCipher::Aes192 => wras::Encryption::Aes192,
            IkeCipher::Aes256 => wras::Encryption::Aes256,
            IkeCipher::TripleDes => wras::Encryption::Des3,
            IkeCipher::Aes128Gcm16 => wras::Encryption::GcmAes128,
            IkeCipher::Aes256Gcm16 => wras::Encryption::GcmAes256,
        },
        dh_group: dh(p.dh_group),
        cipher_transform: match p.esp_cipher {
            EspCipher::Aes128 => wras::CipherTransform::Aes128,
            EspCipher::Aes192 => wras::CipherTransform::Aes192,
            EspCipher::Aes256 => wras::CipherTransform::Aes256,
            EspCipher::TripleDes => wras::CipherTransform::Des3,
            EspCipher::Aes128Gcm16 => wras::CipherTransform::GcmAes128,
            EspCipher::Aes192Gcm16 => wras::CipherTransform::GcmAes192,
            EspCipher::Aes256Gcm16 => wras::CipherTransform::GcmAes256,
        },
        auth_transform: match p.esp_integrity {
            EspIntegrity::Sha196 => wras::AuthTransform::Sha196,
            EspIntegrity::Sha256128 => wras::AuthTransform::Sha256128,
            EspIntegrity::Gcm128 => wras::AuthTransform::GcmAes128,
            EspIntegrity::Gcm192 => wras::AuthTransform::GcmAes192,
            EspIntegrity::Gcm256 => wras::AuthTransform::GcmAes256,
        },
        pfs_group: pfs(p.pfs),
    }
}

fn core_strategy(s: wras::Strategy) -> Option<Strategy> {
    match s {
        wras::Strategy::L2tp => Some(Strategy::L2tp),
        wras::Strategy::Sstp => Some(Strategy::Sstp),
        wras::Strategy::Ikev2 => Some(Strategy::Ikev2),
        wras::Strategy::Other(_) => None,
    }
}

fn core_auth(a: wras::Auth) -> Auth {
    match a {
        wras::Auth::MsChapV2 { psk } => Auth::MsChapV2 { psk },
        wras::Auth::EapMsChapV2 => Auth::EapMsChapV2,
        wras::Auth::MachineCertificate => Auth::MachineCertificate,
    }
}

// MARK: - The platform traits

impl NativeController for RasEngine {
    /// WinVPN's own entries (`WinVPN-<UUID>`), each with its state, then the user's own Windows VPNs (Task 9:
    /// their GUIDs as IDs). An engine whose folders are unsafe lists no managed entry (its actions say why).
    fn list(&self) -> Result<Vec<SystemVpn>, String> {
        let mut out = match self.inner() {
            Ok(inner) => inner.list()?,
            Err(_) => Vec::new(),
        };
        out.extend(self.system.list()?);
        Ok(out)
    }

    fn remote_address(&self, service_id: &str) -> Option<String> {
        if names::connection_id(service_id).is_none() {
            return self.system.remote_address(service_id);
        }
        Some(self.inner().ok()?.book.read(service_id).ok()?.server)
    }

    /// A managed L2TP entry: rewritten from its saved profile, its PSK stored, dialled; returns once connected or
    /// failed (the failure's text: what to do).
    fn start(&self, service_id: &str, kind: Option<NativeKind>, secrets: &Secrets) -> Result<(), String> {
        let Some(id) = names::connection_id(service_id) else { return self.system.start(service_id, kind, secrets) };
        let inner = self.inner()?;
        let plan = rc::decode_profile(&inner.paths.read_profile(&id)?)?;
        inner.connect(&id, VPNKind::L2tp, &plan, b"", secrets, false)
    }

    fn stop(&self, service_id: &str) -> Result<(), String> {
        let Some(id) = names::connection_id(service_id) else { return self.system.stop(service_id) };
        self.inner()?.disconnect(&id)
    }

    fn managed_service_id(&self, connection: &Uuid) -> Option<String> {
        Some(names::entry_name(connection))
    }

    /// G-2: the RAS log (written at every connect, debug or not).
    fn log_source(&self, connection: &Uuid) -> Option<Box<dyn LogSource>> {
        self.log_source_of(connection)
    }
}

impl NativeProfiles for RasEngine {
    /// The connection's profile: its L2TP plan (no secret; the PSK is stored in Windows at each connect), or the
    /// reasons Windows cannot run it, which [`Self::install`] answers (Cisco IPsec: the connection is still saved).
    fn build(&self, connection: &Connection, _psk: &str) -> Result<NativeProfile, String> {
        let plan = rc::profile_plan(connection);
        Ok(NativeProfile { data: rc::encode_profile(&plan), file_name: format!("{}.ras", connection.id) })
    }

    /// Writes the entry `WinVPN-<UUID>` and the saved profile: no approval step on Windows. An unchanged profile
    /// whose entry exists is left as it is (an unlock or a catalog apply installs every L2TP profile again; a
    /// connect rewrites the entry anyway).
    fn install(&self, id: &Uuid, profile: &[u8], _file_name: &str, _service_existed: bool) -> Result<(), String> {
        let inner = self.inner()?;
        let plan = rc::decode_profile(profile)?;
        let name = names::entry_name(id);
        if inner.paths.read_profile(id).is_ok_and(|saved| saved == profile) && inner.book.read(&name).is_ok() {
            return Ok(());
        }
        inner.write_entry(&name, &plan)?;
        inner.paths.write_profile(id, profile).map_err(|e| {
            let text = e.to_string();
            l10n::tr("The Windows VPN entry could not be written: %@", &[Arg::Str(&text)])
        })
    }

    fn remove(&self, id: &Uuid) {
        if let Ok(inner) = self.inner() {
            inner.remove(id);
        }
    }

    /// Task 13: called with the open vault's connections only (after an unlock or a restore).
    fn reconcile(&self, known: &HashSet<Uuid>) {
        if let Ok(inner) = self.inner() {
            inner.reconcile(known);
        }
    }

    fn removes_profiles(&self) -> bool {
        true
    }

    fn needs_approval(&self) -> bool {
        false
    }
}

impl NativeSupport for RasEngine {
    fn unsupported_reason(&self, connection: &Connection, config: &[u8]) -> Option<String> {
        rc::unsupported_reason(connection, config)
    }

    fn editor_notes(&self, connection: &Connection, config: &[u8]) -> macvpn_platform_api::PlatformNotes {
        crate::pure::ras_editor::editor_notes(connection, config)
    }

    fn system_psk_note(&self) -> Option<String> {
        Some(crate::pure::ras_editor::system_psk_note())
    }
}

/// The app's `HelperClient` on Windows: IKEv2 and SSTP go to the [`RasEngine`] (in this process), OpenVPN and
/// WireGuard to the WinVPN Service. A missing service does not hide the RAS connections' states.
pub(crate) struct RasHelper {
    pub(crate) service: ServiceClient,
    pub(crate) ras: Arc<RasEngine>,
}

impl HelperClient for RasHelper {
    fn status(&self) -> Result<Vec<RootStatus>, String> {
        let ras = self.ras.root_statuses();
        match self.service.status() {
            Ok(mut all) => {
                all.extend(ras);
                Ok(all)
            }
            Err(e) if ras.is_empty() => Err(e),
            Err(_) => Ok(ras),
        }
    }

    fn up(
        &self,
        kind: VPNKind,
        id: &Uuid,
        config: &[u8],
        secrets: &Secrets,
        debug: bool,
        accept_risky: &[String],
    ) -> Result<(), String> {
        if rc::is_helper_kind(kind) {
            self.ras.up(kind, id, config, secrets, debug)
        } else {
            self.service.up(kind, id, config, secrets, debug, accept_risky)
        }
    }

    fn down(&self, kind: VPNKind, id: &Uuid) -> Result<(), String> {
        if rc::is_helper_kind(kind) { self.ras.down(id) } else { self.service.down(kind, id) }
    }

    fn respond(&self, id: &Uuid, kind: AuthResponseKind, response: &str) -> Result<(), String> {
        self.service.respond(id, kind, response)
    }

    /// The RAS log when the connection has one (IKEv2, SSTP, and L2TP for the failure notifications), else the
    /// service's.
    fn log_source(&self, id: &Uuid) -> Option<Box<dyn LogSource>> {
        if self.ras.has_log(id) { self.ras.log_source_of(id) } else { self.service.log_source(id) }
    }
}
