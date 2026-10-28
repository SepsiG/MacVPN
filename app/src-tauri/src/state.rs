//! The shared app state and the view-model publisher.

use macvpn_app_core::app::{Poller, PreferenceStore};
use macvpn_app_core::connections::ConnectionsModel;
use macvpn_app_core::credential_prompt::{CredentialBroker, CredentialPromptView};
use macvpn_app_core::deps::HelperClient;
use macvpn_app_core::live::LiveReload;
use macvpn_app_core::logs::{LogFeed, NativeLogs};
use macvpn_app_core::notify::PromptTracker;
use macvpn_app_core::prompt::PromptBroker;
use macvpn_app_core::quit::{QuitGuard, QuitStep, lease_holders_note};
use macvpn_app_core::setup::{BrewRun, SetupFacts, SetupOps, SetupView};
use macvpn_app_core::updates::UpdateController;
use macvpn_app_core::{ConnectionManager, LoginItemView, ViewModel};
use macvpn_core::l10n::AppLanguage;
use macvpn_platform_api::{NativeProfiles, SetupReport};
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Condvar, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, PhysicalPosition, PhysicalSize};

use crate::platform::Environment;

pub struct AppState {
    pub manager: Arc<ConnectionManager>,
    /// The manager's helper (a smoke run's stand-in in a smoke run): the connection logs are read through it, never
    /// through the platform's own (`platform::get()`), which would ask the real root helper or WinVPN Service.
    pub helper: Arc<dyn HelperClient>,
    pub broker: Arc<PromptBroker>,
    /// The credential prompts (`cred-<id>` windows).
    pub credential_broker: Arc<CredentialBroker>,
    pub poller: Arc<Poller>,
    /// The live system VPN list: the watcher's notifications, debounced, wake the poller.
    pub live: Arc<LiveReload>,
    /// The system VPN change watcher (not in the sandbox; `None` if it could not start). Dropping it stops it.
    pub watcher: Mutex<Option<Box<dyn Send>>>,
    /// A trusted watcher runs: the poll fallback keeps its idle pace with a window open.
    pub live_trusted: AtomicBool,
    pub publisher: Arc<Publisher>,
    pub setup: RwLock<SetupReport>,
    /// The first system check finished (the System Status rows are shown).
    pub setup_checked: AtomicBool,
    /// When the popover or the Connections window last started a background check (`system::recheck_if_incomplete`).
    pub setup_rechecked: Mutex<Option<Instant>>,
    /// `brew install` (owned here, so it survives closing the System Status window).
    pub brew: Mutex<BrewRun>,
    /// The System Status window's root install / uninstall state.
    pub setup_ops: Mutex<SetupOps>,
    /// The uninstaller finished: its final message's Quit may quit.
    pub uninstalled: AtomicBool,
    pub updates: Arc<UpdateController>,
    /// The app's preferences (the Swift `UserDefaults`).
    pub prefs: Arc<dyn PreferenceStore>,
    /// The last read launch-at-login state (`None` until read).
    pub login_item: RwLock<Option<LoginItemView>>,
    /// The Connections window: selection, editors, unsaved changes, import, delete.
    pub connections: Arc<ConnectionsModel>,
    /// The native debug log collections (`log stream`).
    pub native_logs: Arc<NativeLogs>,
    /// The native profiles (their staged files wait for their service).
    pub native_profiles: Arc<dyn NativeProfiles>,
    /// The Log tab being shown, with its subscription number (events of an older one are ignored by the UI).
    pub log_feed: Mutex<Option<(u64, LogFeed)>>,
    pub log_generation: AtomicU64,
    /// The log poller thread runs.
    pub log_poller: AtomicBool,
    /// An open / save panel is shown (one at a time).
    pub dialog_open: AtomicBool,
    pub env: Environment,
    /// Every quit path's questions (unsaved changes, active connections).
    pub quit: Arc<QuitGuard>,
    /// The open MFA prompts already shown (their windows and notifications).
    pub prompt_tracker: Mutex<PromptTracker>,
    /// The open credential prompts already shown (their windows and notifications).
    pub credential_tracker: Mutex<PromptTracker<CredentialPromptView>>,
    /// The tray icon's last known place (the popover is anchored below it).
    pub tray_anchor: Mutex<Option<(PhysicalPosition<f64>, PhysicalSize<f64>)>>,
    /// When the popover was last hidden because it lost the focus (a click on the tray icon does that first).
    pub hidden_on_blur: Mutex<Option<Instant>>,
    /// The local control API: the setting, the server, the pairing broker.
    pub control: crate::control::ControlApp,
    /// The pairing windows shown.
    pub pairing_windows: crate::pairing::PairingWindows,
    /// The vault: its lifecycle, the 1.1 storage, the create window's steps, the vault windows' input locks.
    pub vault: crate::vault::VaultApp,
    /// The full backup and restore (once the vault is attached).
    pub backup: crate::backup::BackupApp,
    /// The team catalogs: the subscriptions, the publishing side, the refresh scheduler.
    pub catalog: crate::catalog::CatalogApp,
    /// Files opened from Finder waiting for the vault, and their outcome for the Connections window (paths stay
    /// here; never in the view model).
    pub open_files: crate::open_files::OpenFilesApp,
    /// The last state seen per managed connection, for the "connected" / "reconnected" notices.
    pub notices: Mutex<macvpn_app_core::connection_notices::NoticeTracker>,
    /// Auto-reconnect (decision 4): the planner, its driver's events and the network watcher.
    pub reconnect: crate::reconnect::Reconnect,
}

impl AppState {
    /// Quitting: the status poller, the live reload, the watchers and the team catalog scheduler stop (the
    /// scheduler is joined).
    pub fn stop_polling(&self) {
        self.catalog.stop_scheduler();
        // A copied recovery key, team key or subscription string leaves the pasteboard (if still there).
        crate::clipboard::clear_secret();
        self.poller.stop();
        self.live.stop();
        // Dropping the watcher stops it (and joins its thread).
        drop(self.watcher.lock().unwrap_or_else(PoisonError::into_inner).take());
        self.reconnect.stop();
    }

    /// Re-reads launch at login from the system (menu open, after the switch) and publishes it.
    pub fn refresh_login_item(self: &Arc<Self>) {
        let state = self.clone();
        tauri::async_runtime::spawn_blocking(move || {
            let view = crate::platform::login_items(&state.env).state();
            *state.login_item.write().unwrap_or_else(PoisonError::into_inner) = Some(view);
            state.publisher.mark();
        });
    }

    pub fn view_model(&self) -> ViewModel {
        // A snapshot: no guard of `setup` is held across the other locks taken below (the control server's among
        // them, whose `up` reads the setup too; with a queued writer that was a deadlock).
        let setup = self.setup.read().unwrap_or_else(PoisonError::into_inner).clone();
        let snapshot = self.manager.snapshot();
        let mut vm = ViewModel::build(
            &snapshot,
            AppLanguage::current().raw_value(),
            |kind| setup.is_available(kind),
            self.broker.pending(),
            setup.is_complete(),
        );
        // Without a VPN engine (WinVPN: no usable WinVPN Service) every row that needs it says so (the native kinds
        // and the system VPNs run without the service).
        vm.set_engine_missing_where(setup.engine_missing.as_deref(), &|kind| setup.needs_service(kind));
        // The kinds that come later (WinVPN: the native VPNs) say so on their rows.
        vm.set_later_kinds(&setup.later_kinds);
        // The connections the platform cannot connect with their settings (WinVPN 2c; read at the last reload, no
        // config is read here; none on macOS).
        vm.set_unsupported(&self.manager.unsupported_reasons());
        // Rows whose engine is missing (only once the check ran: unknown is not missing).
        if self.setup_checked.load(std::sync::atomic::Ordering::SeqCst) {
            vm.set_unavailable_kinds(&|kind| {
                setup.unavailable_text(kind).map(|text| (text, setup.missing_engine(kind).is_some()))
            });
        }
        // A failure whose text names an administrator step offers its button (WinVPN 2c: allow L2TP behind NAT,
        // trust the SSTP CA; none on macOS).
        let admin = crate::platform::get().admin_steps();
        vm.set_admin_actions(&|reason| admin.offered_action(reason));
        // The configs' server hosts for the search, as the last reload read them (no config is read here).
        vm.set_server_hosts(&self.manager.server_hosts());
        vm.update = self.updates.view();
        vm.login_item = self.login_item.read().unwrap_or_else(PoisonError::into_inner).clone();
        vm.appearance = Some(macvpn_app_core::appearance::Appearance::load(self.prefs.as_ref()).raw_value());
        vm.connection_notifications = crate::notifications::notices_possible(self)
            .then(|| macvpn_app_core::connection_notices::enabled(self.prefs.as_ref()));
        // "Reconnect Automatically" per managed connection (default on).
        vm.set_auto_reconnect(&|id| {
            macvpn_core::models::parse_uuid(id)
                .is_some_and(|u| macvpn_app_core::reconnect::is_enabled(self.prefs.as_ref(), &u))
        });
        // The connections with no physical network under them (the network loss rule): "Waiting for network…" in
        // their rows and the tray, never "connected".
        vm.set_waiting_for_network(&self.reconnect.waiting_for_network());
        // Dead-tunnel detection: OpenVPN restarting itself is "Reconnecting…" (never "connected"), a tunnel found
        // dead and disconnected is "Not responding".
        vm.set_reconnecting(&self.reconnect.reconnecting());
        vm.set_not_responding(&self.reconnect.not_responding());
        // The slow tier: "Retrying in … min" on a down row.
        vm.set_retrying(&self.reconnect.slow_retries());
        vm.manage = self.connections.view();
        let facts = self.setup_checked.load(std::sync::atomic::Ordering::SeqCst).then(|| setup_facts(&setup));
        vm.setup = SetupView::build(
            facts.as_ref(),
            &self.brew.lock().unwrap_or_else(PoisonError::into_inner),
            &self.setup_ops.lock().unwrap_or_else(PoisonError::into_inner),
            crate::platform::get().setup().helper_upgrade_notice(),
        )
        // Without a usable engine (WinVPN: no service, another version, degraded) its reason replaces the rows;
        // macOS has neither.
        .with_engine_note(crate::platform::get().setup().engine_note().or_else(|| setup.engine_missing.clone()))
        .with_engine(setup.engine.as_ref(), crate::platform::get().setup().later_note())
        // The Windows VPN client row (WinVPN 2c), also while the service is missing; none on macOS.
        .with_ras(setup.ras.as_ref())
        .with_system_uninstall(crate::platform::get().setup().system_uninstall_note())
        .with_account_cleanup(crate::platform::get().setup().account_cleanup());
        vm.quit = self.quit.question();
        // The control API: the "Held by" labels, the quit question's note, the Paired apps section, the pairings.
        vm.set_holders(&self.control.holders());
        if vm.quit.is_some_and(|q| q.step == QuitStep::ActiveConnections) {
            vm.quit_note = lease_holders_note(&self.control.holder_names());
        }
        vm.control = self.control.view(self.prefs.bool(crate::control::ENABLED_KEY).unwrap_or(false));
        vm.pairings = self.control.pairing.pending();
        vm.credential_prompts = self.credential_broker.pending();
        vm.credentials = self.connections.credentials_view();
        vm.backup_available = self.backup.available();
        // The team catalogs, their badges and the publishing side (empty while locked).
        self.catalog.fill(&mut vm);
        // Last: while locked (or before the vault exists) the rows and paired apps are removed again.
        let (vault, setup) = self.vault.view(self.prefs.bool(crate::vault::SHOW_LOCK_NOW_KEY).unwrap_or(false));
        vm.apply_vault(vault);
        vm.vault_setup = setup;
        vm
    }

    /// Notifications are posted only from a real app bundle (as in the Swift app).
    pub fn notifications_enabled(&self) -> bool {
        self.env.bundle.is_some() && !self.env.sandbox
    }
}

/// The platform's report as the System Status window's facts.
pub fn setup_facts(r: &SetupReport) -> SetupFacts {
    SetupFacts {
        brew_prefix: r.package_manager.clone(),
        missing_tools: r.missing_tools.clone(),
        installed_root_version: r.installed_root_version.clone(),
        bundled_root_version: r.bundled_root_version.clone(),
        root_ok: r.root_ok(),
        missing_root_files: r.missing_root_files.clone(),
        outdated: r.outdated_packages.clone(),
    }
}

/// Coalesces "something changed" notifications from any thread and publishes the latest view model (event
/// `view-model`) and tray icon from one thread, so an older state never overtakes a newer one.
#[derive(Default)]
pub struct Publisher {
    dirty: Mutex<bool>,
    signal: Condvar,
}

/// Changes within this window are published together.
const COALESCE: Duration = Duration::from_millis(30);

impl Publisher {
    pub fn mark(&self) {
        *self.dirty.lock().unwrap_or_else(PoisonError::into_inner) = true;
        self.signal.notify_one();
    }

    fn wait(&self) {
        let mut dirty = self.dirty.lock().unwrap_or_else(PoisonError::into_inner);
        while !*dirty {
            dirty = self.signal.wait(dirty).unwrap_or_else(PoisonError::into_inner);
        }
        drop(dirty);
        std::thread::sleep(COALESCE);
        *self.dirty.lock().unwrap_or_else(PoisonError::into_inner) = false;
    }

    pub fn spawn(app: AppHandle, state: Arc<AppState>) {
        let publisher = state.publisher.clone();
        std::thread::Builder::new()
            .name("macvpn-publish".into())
            .spawn(move || {
                let mut tray = None;
                loop {
                    publisher.wait();
                    let vm = state.view_model();
                    let shown = (vm.tray, vm.tray.tooltip());
                    if tray.as_ref() != Some(&shown) {
                        crate::tray::set_icon(&app, shown.0, shown.1.as_deref());
                        tray = Some(shown);
                    }
                    // New prompts get a window (and a notification), closed ones lose theirs.
                    crate::prompts::sync(&app, &state, &vm.prompts);
                    crate::pairing::sync(&app, &state, &vm.pairings);
                    crate::credentials::sync(&app, &state, &vm.credential_prompts);
                    let _ = app.emit("view-model", &vm);
                }
            })
            .expect("publisher thread");
    }
}
