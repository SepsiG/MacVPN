//! The shared app state and the view-model publisher.

use macvpn_app_core::app::{Poller, PreferenceStore};
use macvpn_app_core::connections::ConnectionsModel;
use macvpn_app_core::logs::{LogFeed, NativeLogs};
use macvpn_app_core::notify::PromptTracker;
use macvpn_app_core::prompt::PromptBroker;
use macvpn_app_core::quit::QuitGuard;
use macvpn_app_core::setup::{BrewRun, SetupFacts, SetupOps, SetupView};
use macvpn_app_core::updates::UpdateController;
use macvpn_app_core::{ConnectionManager, LoginItemView, ViewModel};
use macvpn_core::l10n::AppLanguage;
use macvpn_platform_mac::profile_staging::StagedProfiles;
use macvpn_platform_mac::root_installer::upgrade_disconnect_notice;
use macvpn_platform_mac::setup_checker::SetupReport;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Condvar, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, PhysicalPosition, PhysicalSize};

use crate::platform::Environment;

pub struct AppState {
    pub manager: Arc<ConnectionManager>,
    pub broker: Arc<PromptBroker>,
    pub poller: Arc<Poller>,
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
    /// The tray icon's last known place (the popover is anchored below it).
    pub tray_anchor: Mutex<Option<(PhysicalPosition<f64>, PhysicalSize<f64>)>>,
    /// When the popover was last hidden because it lost the focus (a click on the tray icon does that first).
    pub hidden_on_blur: Mutex<Option<Instant>>,
}

impl AppState {
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
        let setup = self.setup.read().unwrap_or_else(PoisonError::into_inner);
        let mut vm = ViewModel::build(
            &self.manager.snapshot(),
            AppLanguage::current().raw_value(),
            |kind| setup.is_available(kind),
            self.broker.pending(),
            setup.is_complete(),
        );
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
                    let _ = app.emit("view-model", &vm);
                }
            })
            .expect("publisher thread");
    }
}
