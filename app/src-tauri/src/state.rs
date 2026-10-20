//! The shared app state and the view-model publisher.

use macvpn_app_core::app::{Poller, PreferenceStore};
use macvpn_app_core::connections::ConnectionsModel;
use macvpn_app_core::credential_prompt::{CredentialBroker, CredentialPromptView};
use macvpn_app_core::live::LiveReload;
use macvpn_app_core::logs::{LogFeed, NativeLogs};
use macvpn_app_core::notify::PromptTracker;
use macvpn_app_core::prompt::PromptBroker;
use macvpn_app_core::quit::{QuitGuard, QuitStep, lease_holders_note};
use macvpn_app_core::setup::{BrewRun, SetupFacts, SetupOps, SetupView};
use macvpn_app_core::updates::UpdateController;
use macvpn_app_core::{ConnectionManager, LoginItemView, ViewModel};
use macvpn_core::l10n::AppLanguage;
use macvpn_platform_mac::profile_staging::StagedProfiles;
use macvpn_platform_mac::root_installer::upgrade_disconnect_notice;
use macvpn_platform_mac::sc_watch::SystemVpnWatcher;
use macvpn_platform_mac::setup_checker::SetupReport;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Condvar, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, PhysicalPosition, PhysicalSize};

use crate::platform::Environment;

pub struct AppState {
    pub manager: Arc<ConnectionManager>,
    pub broker: Arc<PromptBroker>,
    /// The credential prompts (`cred-<id>` windows).
    pub credential_broker: Arc<CredentialBroker>,
    pub poller: Arc<Poller>,
    /// The live system VPN list: the watcher's notifications, debounced, wake the poller.
    pub live: Arc<LiveReload>,
    /// The system VPN change watcher (not in the sandbox; `None` if it could not start).
    pub watcher: Mutex<Option<SystemVpnWatcher>>,
    /// A trusted watcher runs: the poll fallback keeps its idle pace with a window open.
    pub live_trusted: AtomicBool,
    pub publisher: Arc<Publisher>,
    pub setup: RwLock<SetupReport>,
    /// The first system check finished (the System Status rows are shown).
    pub setup_checked: AtomicBool,
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
    /// The staged native profiles waiting for their service.
    pub staged_profiles: Arc<Mutex<StagedProfiles>>,
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
}

impl AppState {
    /// Quitting: the status poller, the live reload, the watcher and the team catalog scheduler stop (the
    /// scheduler is joined).
    pub fn stop_polling(&self) {
        self.catalog.stop_scheduler();
        // A copied recovery key, team key or subscription string leaves the pasteboard (if still there).
        crate::clipboard::clear_secret();
        self.poller.stop();
        self.live.stop();
        if let Some(watcher) = self.watcher.lock().unwrap_or_else(PoisonError::into_inner).take() {
            watcher.stop();
        }
    }

    /// Re-reads launch at login from the system (menu open, after the switch) and publishes it.
    pub fn refresh_login_item(self: &Arc<Self>) {
        let state = self.clone();
        tauri::async_runtime::spawn_blocking(move || {
            let view = crate::platform::login_item_view(crate::platform::login_items(&state.env).state());
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
        // The configs' server hosts for the search, as the last reload read them (no config is read here).
        vm.set_server_hosts(&self.manager.server_hosts());
        vm.update = self.updates.view();
        vm.login_item = self.login_item.read().unwrap_or_else(PoisonError::into_inner).clone();
        vm.manage = self.connections.view();
        let facts = self.setup_checked.load(std::sync::atomic::Ordering::SeqCst).then(|| setup_facts(&setup));
        vm.setup = SetupView::build(
            facts.as_ref(),
            &self.brew.lock().unwrap_or_else(PoisonError::into_inner),
            &self.setup_ops.lock().unwrap_or_else(PoisonError::into_inner),
            upgrade_disconnect_notice(),
        );
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
        brew_prefix: r.brew_prefix.clone(),
        missing_tools: r.missing_tools.clone(),
        installed_root_version: r.installed_root_version.clone(),
        bundled_root_version: r.bundled_root_version.clone(),
        root_ok: r.root_ok(),
        missing_root_files: r.missing_root_files.clone(),
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
                    if tray != Some(vm.tray) {
                        tray = Some(vm.tray);
                        crate::tray::set_icon(&app, vm.tray);
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
