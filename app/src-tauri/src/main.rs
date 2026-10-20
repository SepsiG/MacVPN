//! MacVPN: the menu bar app (Tauri 2 shell). The logic lives in `macvpn-app-core` (connection manager, view
//! model, orchestration) over the macOS implementations in `macvpn-platform-mac`; this crate wires them to the
//! tray icon, the menu popover and the windows.
//!
//! Threads: the main thread runs the event loop only. The launch steps after the first three, the status poller,
//! the view-model publisher and every connect / disconnect run on their own threads or the blocking pool,
//! because the platform calls are synchronous.

mod backup;
mod catalog;
mod clipboard;
mod commands;
mod control;
mod credentials;
mod dialogs;
mod dock;
mod fit;
mod folders;
mod manage;
mod navigation;
mod notifications;
mod pairing;
mod platform;
mod prompts;
mod shared_credentials;
#[cfg(debug_assertions)]
mod smoke;
mod state;
mod system;
mod tray;
mod update_window;
mod vault;

use macvpn_app_core::app::{LAUNCH_SEQUENCE, LaunchStep, MemoryPreferences, POLL_TICK, Poller, PreferenceStore};
use macvpn_app_core::backup::BackupService;
use macvpn_app_core::catalog::{CatalogDeps, CatalogService};
use macvpn_app_core::catalog_file::FileCatalogFetcher;
use macvpn_app_core::catalog_publish::{Publisher as CatalogPublisher, PublisherDeps};
use macvpn_app_core::connections::ConnectionsModel;
use macvpn_app_core::control::FileRegistryStore;
use macvpn_app_core::credential_prompt::CredentialBroker;
use macvpn_app_core::deps::{SecretReader, SystemClock};
use macvpn_app_core::editor::EditorDeps;
use macvpn_app_core::folders::VaultFolders;
use macvpn_app_core::live::{LiveReload, WATCHER_TRUSTED};
use macvpn_app_core::logs::{NativeLogCollector, NativeLogs};
use macvpn_app_core::migration::{LegacyKeychain, LegacySources};
use macvpn_app_core::prompt::PromptBroker;
use macvpn_app_core::quit::{QuitAction, QuitGuard, QuitOrigin};
use macvpn_app_core::shared_credentials::SharedCredentials;
use macvpn_app_core::updates::UpdateController;
use macvpn_app_core::vault::VaultLifecycle;
use macvpn_app_core::vault_stores::{
    ReadOnly, VaultConnections, VaultRanking, VaultRegistry, VaultSecrets, VaultSystemOtp,
};
use macvpn_app_core::{ConnectionManager, Dependencies};
use macvpn_core::date::Date;
use macvpn_core::l10n;
use macvpn_core::ranking::ConnectionRankingStore;
use macvpn_core::store::ConnectionStore;
use macvpn_core::system_otp::SystemOTPStore;
use macvpn_core::vault::{Entropy, KdfParams, KeyStore, MemoryKeyStore, VAULT_FILE};
use macvpn_platform_mac::app_hooks::{self, TerminateReply};
use macvpn_platform_mac::legacy_store::KeychainLegacy;
use macvpn_platform_mac::profile_staging::{self, StagedProfiles};
use macvpn_platform_mac::secrets::{InMemoryKeychain, KeychainSecretStore};
use macvpn_platform_mac::setup_checker::SetupReport;
use macvpn_platform_mac::vault_keys::{KeychainKeyStore, SystemEntropy};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use tauri::menu::{MenuBuilder, MenuItemBuilder, SubmenuBuilder};
use tauri::{AppHandle, Emitter, Manager, RunEvent, WindowEvent};

use macvpn_platform_mac::http::CurlHttpClient;
use macvpn_platform_mac::preferences::CFPreferencesStore;
use platform::{
    AuthStateFiles, Environment, GitHubReleases, Keychain, LogStreams, Native, Preferences, ProfileFiles, Root,
    SharedKeychain,
};
use state::{AppState, Publisher};

/// Every store the app uses, backed by the vault; the 1.1 storage is the migration's source and, in the legacy
/// read-only mode, the stores' fallback.
struct Storage {
    vault: Arc<VaultLifecycle>,
    legacy: Arc<LegacySources>,
    entropy: Arc<dyn Entropy>,
    connections: Arc<VaultConnections>,
    secrets: Arc<VaultSecrets>,
    ranking: Arc<VaultRanking>,
    system_otp: Arc<VaultSystemOtp>,
    registry: Arc<VaultRegistry>,
}

/// The auto-unlock key store, the old Keychain items (as the migration and as the read-only mode read them) and the
/// one-time move of the older service's items.
type Platform = (Arc<dyn KeyStore>, Arc<dyn LegacyKeychain>, Arc<dyn SecretReader>, Box<dyn FnOnce() + Send>);

/// The storage and the one-time move of the Keychain items of the older service (`macvpn`), before anything is
/// read. The sandbox keeps the old Keychain items and the auto-unlock key in memory (never the real Keychain).
fn storage(env: &Environment, legacy_store: Arc<ConnectionStore>) -> (Storage, Box<dyn FnOnce() + Send>) {
    let support = env.application_support();
    let entropy: Arc<dyn Entropy> = Arc::new(SystemEntropy);
    let (keystore, keychain, legacy_secrets, migrate): Platform = if env.sandbox {
        let memory = Arc::new(InMemoryKeychain::new());
        #[cfg(debug_assertions)]
        smoke::seed_legacy_keychain(env, &memory);
        (
            Arc::new(MemoryKeyStore::new()),
            Arc::new(KeychainLegacy::new(KeychainSecretStore::new(SharedKeychain(memory.clone())))),
            Arc::new(Keychain(KeychainSecretStore::new(SharedKeychain(memory)))),
            Box::new(|| {}),
        )
    } else {
        (
            Arc::new(KeychainKeyStore::new()),
            Arc::new(KeychainLegacy::system()),
            Arc::new(Keychain(KeychainSecretStore::system())),
            Box::new(|| {
                KeychainSecretStore::system().migrate_legacy_items();
            }),
        )
    };
    let vault = Arc::new(VaultLifecycle::new(support.clone(), keystore, entropy.clone(), KdfParams::DEFAULT));
    let legacy = Arc::new(LegacySources::new(support.clone(), keychain));
    let storage = Storage {
        connections: Arc::new(VaultConnections::new(vault.clone()).with_legacy(Arc::new(ReadOnly(legacy_store)))),
        secrets: Arc::new(VaultSecrets::new(vault.clone()).with_legacy(Arc::new(ReadOnly(legacy_secrets)))),
        ranking: Arc::new(VaultRanking::new(vault.clone()).with_legacy(Arc::new(ReadOnly(Arc::new(
            ConnectionRankingStore::new(ConnectionRankingStore::default_path(&support)),
        ))))),
        system_otp: Arc::new(
            VaultSystemOtp::new(vault.clone())
                .with_legacy(Arc::new(ReadOnly(Arc::new(SystemOTPStore::new(SystemOTPStore::default_path(&support)))))),
        ),
        registry: Arc::new(
            VaultRegistry::new(vault.clone())
                .with_legacy(Arc::new(ReadOnly(Arc::new(FileRegistryStore { dir: support.clone() })))),
        ),
        vault,
        legacy,
        entropy,
    };
    (storage, migrate)
}

fn build_state(env: Environment, storage: Storage) -> Arc<AppState> {
    let support = env.application_support();
    let root: Arc<dyn macvpn_app_core::deps::RootClient> = Arc::new(Root::new());
    // The smoke run never reaches the root helper: its connects go to a stand-in (debug builds only).
    #[cfg(debug_assertions)]
    let root = smoke::fake_root(&env).unwrap_or(root);
    let native: Arc<dyn macvpn_app_core::deps::NativeController> = Arc::new(Native::new());
    // The smoke run's system VPN list is a stand-in the driver changes (debug builds only).
    #[cfg(debug_assertions)]
    let native = smoke::fake_native(&env).unwrap_or(native);
    let mut deps = Dependencies::new(storage.connections.clone(), storage.secrets.clone(), root, native);
    deps.ranking_store = Some(storage.ranking.clone());
    deps.system_otp_store = Some(storage.system_otp.clone());
    deps.auth_state = Arc::new(AuthStateFiles { uid: macvpn_platform_mac::system::user_id() });
    // "Save in vault" of the credential prompt writes to the same store as the editors.
    deps.secret_writer = Some(storage.secrets.clone());
    // Folders and colours live in the vault (dropped while it is locked).
    deps.folders = Some(Arc::new(VaultFolders::new(storage.vault.clone())));
    // The Swift app's UserDefaults domain; the sandbox keeps them in memory.
    let prefs: Arc<dyn PreferenceStore> =
        if env.sandbox { Arc::new(MemoryPreferences::new()) } else { Arc::new(Preferences(CFPreferencesStore::app())) };
    let updates = Arc::new(UpdateController::new(
        env.update_source(),
        env!("CARGO_PKG_VERSION"),
        prefs.clone(),
        Arc::new(GitHubReleases(CurlHttpClient::default())),
        Arc::new(SystemClock),
    ));
    let manager = ConnectionManager::new(deps);
    let staged_profiles = Arc::new(Mutex::new(StagedProfiles::default()));
    let profiles = ProfileFiles {
        parent: env.staging_parent().unwrap_or_else(std::env::temp_dir),
        staged: staged_profiles.clone(),
        open: !env.sandbox,
    };
    let connections = Arc::new(ConnectionsModel::new(EditorDeps {
        manager: manager.clone(),
        store: storage.connections.clone(),
        secrets: storage.secrets.clone(),
        secret_writer: storage.secrets.clone(),
        profiles: Arc::new(profiles),
        clock: Arc::new(SystemClock),
    }));
    // The shared credentials live in the vault (the section answers "locked" while it is locked).
    connections.set_shared_credentials(SharedCredentials::new(storage.vault.clone()));
    let native_logs = Arc::new(NativeLogs::new(Box::new(|| {
        NativeLogCollector::new(
            Arc::new(LogStreams),
            Arc::new(|date: Date| {
                macvpn_platform_mac::system::local_date_time(
                    date.time_interval_since_1970(),
                    l10n::AppLanguage::current(),
                )
            }),
            Arc::new(SystemClock),
            std::time::Duration::from_secs_f64(macvpn_app_core::logs::NATIVE_LOG_MAX_SECONDS),
        )
    })));
    // The full backup and restore work on the vault (the service answers "locked" while it is not open).
    let backup = backup::BackupApp::default();
    backup.attach(Arc::new(BackupService::new(
        storage.vault.clone(),
        storage.entropy.clone(),
        KdfParams::DEFAULT,
        macvpn_core::VERSION,
    )));
    // Team catalogs (spec 5–7): the HTTPS source through curl (refused in the sandbox), the file source with its
    // read timeout, the publishing side on the same vault.
    let https = catalog::https_fetcher(env.sandbox);
    let catalog_service = CatalogService::new(CatalogDeps {
        vault: storage.vault.clone(),
        https,
        file: Arc::new(FileCatalogFetcher::new()),
        manager: manager.clone(),
        clock: Arc::new(SystemClock),
    });
    let catalog_publisher = Arc::new(CatalogPublisher::new(PublisherDeps {
        vault: storage.vault.clone(),
        entropy: storage.entropy.clone(),
        kdf: KdfParams::DEFAULT,
        clock: Arc::new(SystemClock),
    }));
    let catalog = catalog::CatalogApp::new(catalog_service, catalog_publisher, storage.vault.clone(), env.sandbox);
    Arc::new(AppState {
        catalog,
        updates,
        login_item: RwLock::new(None),
        connections,
        native_logs,
        staged_profiles,
        log_feed: Mutex::new(None),
        log_generation: AtomicU64::new(0),
        log_poller: AtomicBool::new(false),
        dialog_open: AtomicBool::new(false),
        manager,
        broker: Arc::new(PromptBroker::new()),
        credential_broker: Arc::new(CredentialBroker::new()),
        poller: Arc::new(Poller::new()),
        live: Arc::new(LiveReload::new()),
        watcher: Mutex::new(None),
        live_trusted: AtomicBool::new(false),
        publisher: Arc::new(Publisher::default()),
        setup: RwLock::new(SetupReport::unknown()),
        setup_checked: AtomicBool::new(false),
        brew: Mutex::default(),
        setup_ops: Mutex::default(),
        uninstalled: AtomicBool::new(false),
        prefs,
        env,
        quit: Arc::new(QuitGuard::new()),
        prompt_tracker: Mutex::default(),
        credential_tracker: Mutex::default(),
        tray_anchor: Mutex::new(None),
        hidden_on_blur: Mutex::new(None),
        control: control::ControlApp::new(&support, storage.registry.clone(), support.join(VAULT_FILE)),
        vault: vault::VaultApp::new(storage.vault, storage.legacy, storage.entropy),
        pairing_windows: pairing::PairingWindows::default(),
        backup,
    })
}

/// Hooks the manager and the prompt broker to the UI.
fn connect_hooks(app: &AppHandle, state: &Arc<AppState>) {
    // After every manager change (a refresh among them): the Connections window learns which system VPNs are
    // gone (a removed one's editor turns read-only).
    let publisher = state.publisher.clone();
    let connections = state.connections.clone();
    state.manager.set_on_change(move || {
        connections.system_services_changed();
        publisher.mark();
    });
    let publisher = state.publisher.clone();
    state.broker.set_on_change(move || publisher.mark());
    let publisher = state.publisher.clone();
    state.updates.set_on_change(move || publisher.mark());
    let publisher = state.publisher.clone();
    state.connections.set_on_change(move || publisher.mark());
    let publisher = state.publisher.clone();
    state.quit.set_on_change(move || publisher.mark());
    let publisher = state.publisher.clone();
    state.control.pairing.set_on_change(move || publisher.mark());
    // The control API's manager listeners, once (a started server plugs its notifier into the relay).
    state.control.attach(&state.manager);
    // The team catalogs: notifications, the log, the allowlist pruning, the pending removals' listener.
    catalog::connect_hooks(state);
    // A staged native profile is deleted once its service is listed (the Swift `stagedProfiles.servicesSeen`).
    let staged = state.staged_profiles.clone();
    state.manager.set_on_native_services_seen(move |ids| {
        staged.lock().unwrap_or_else(PoisonError::into_inner).services_seen(ids);
    });
    let broker = state.broker.clone();
    state.manager.set_prompt_handler(move |prompt| broker.present(prompt, Date::now()));
    let broker = state.broker.clone();
    state.manager.set_dismiss_prompt(move |key| broker.dismiss(key));
    let publisher = state.publisher.clone();
    state.credential_broker.set_on_change(move || publisher.mark());
    let broker = state.credential_broker.clone();
    state.manager.set_credential_handler(move |prompt| broker.present(prompt, Date::now()));
    let broker = state.credential_broker.clone();
    state.manager.set_dismiss_credentials(move |key| broker.dismiss(key));
    // Failures and drops: a notification (bundle only; generic text) and the UI event.
    let handle = app.clone();
    let notifying = state.clone();
    state.manager.set_on_event(move |event| {
        notifications::event(&notifying, &event);
        let _ = handle.emit("connection-event", event);
    });
}

/// The steps after the Swift `AppModel.init` part (reload, setup check, …, polling), off the main thread.
fn run_late_launch_step(app: &AppHandle, state: &Arc<AppState>, step: LaunchStep) {
    match step {
        LaunchStep::OpenVault => vault::launch(app, state),
        LaunchStep::ReloadConnections => {
            state.manager.reload();
            start_live_list(state);
        }
        LaunchStep::CheckSetup => {
            state.refresh_login_item();
            let complete = system::check(state).is_complete();
            if !complete {
                // As the Swift app: the System Status window opens at launch when something is missing.
                let _ = commands::open(app, "setup");
            }
        }
        // Bundle only (UNUserNotificationCenter needs a bundle identifier).
        LaunchStep::RequestNotificationAuthorization => notifications::start(app, state),
        // Bundle only (the Swift `launchHousekeeping`): the leftovers of an interrupted update, the previous
        // update's notice.
        LaunchStep::UpdateHousekeeping => update_window::launch_housekeeping(app, state),
        // Only from a bundle with the update source in Info.plist (otherwise `run_scheduler` returns at once).
        LaunchStep::StartUpdateScheduler => {
            if state.updates.enabled() {
                let updates = state.updates.clone();
                std::thread::Builder::new()
                    .name("macvpn-updates".into())
                    .spawn(move || {
                        updates.run_scheduler(|wake| {
                            std::thread::sleep(wake);
                            true
                        })
                    })
                    .expect("update scheduler thread");
            }
        }
        LaunchStep::StartPolling => {
            let state = state.clone();
            std::thread::Builder::new()
                .name("macvpn-poll".into())
                .spawn(move || {
                    let manager = state.manager.clone();
                    state.poller.run(
                        || manager.refresh(),
                        || manager.has_active(),
                        window_open,
                        || state.live_trusted.load(Ordering::SeqCst),
                        &SystemClock,
                        || state.poller.wait(POLL_TICK),
                    );
                })
                .expect("poller thread");
        }
        // The team catalog scheduler: a launch round, then every 30 s it checks what is due; the wake hook and
        // `vault::after_unlock` ask it for a round, and it skips its rounds while the vault is locked. The handle is
        // kept and joined at quit (`AppState::stop_polling`).
        LaunchStep::StartCatalogRefresh => state.catalog.start_scheduler(),
        LaunchStep::MigrateKeychain | LaunchStep::SweepStagedProfiles | LaunchStep::RemoveLegacyProfiles => {}
    }
}

/// The live system VPN list: the debounced reload thread (it wakes the poller) and, outside the sandbox, the
/// SystemConfiguration watcher feeding it. Without a watcher (it failed, or the sandbox) the poll fallback's
/// faster pace with a window open keeps the list current; the smoke run triggers the reload itself.
fn start_live_list(state: &Arc<AppState>) {
    let live = state.live.clone();
    let poller = state.poller.clone();
    std::thread::Builder::new()
        .name("macvpn-live".into())
        .spawn(move || live.run(|| poller.wake()))
        .expect("live reload thread");
    if state.env.sandbox {
        return;
    }
    let live = state.live.clone();
    match macvpn_platform_mac::sc_watch::SystemVpnWatcher::start(move || live.trigger()) {
        Ok(watcher) => {
            *state.watcher.lock().unwrap_or_else(PoisonError::into_inner) = Some(watcher);
            state.live_trusted.store(WATCHER_TRUSTED, Ordering::SeqCst);
        }
        Err(e) => eprintln!("MacVPN: the system VPN watcher did not start ({e}); polling instead"),
    }
}

/// A MacVPN window is shown (Connections, System Status, Update – visible and not minimized – or the menu
/// popover): the poll fallback's faster pace. Read from flags kept on the main thread, no round trip to it.
fn window_open() -> bool {
    dock::windows_shown() || tray::menu_shown()
}

/// `applicationShouldTerminate:` (logout, restart, shutdown, a quit Apple Event): the same quit questions. With
/// nothing to ask the app terminates at once; otherwise AppKit waits ("later") until the questions are answered
/// (the reply comes from `commands::handle_quit` / `commands::terminate`); macOS cancels a logout that waits too
/// long, as with the Swift app.
fn system_terminate_request(app: &AppHandle) -> TerminateReply {
    let Some(state) = app.try_state::<Arc<AppState>>() else { return TerminateReply::Now };
    let state = state.inner().clone();
    let unsaved = state.connections.has_unsaved_changes();
    match state.quit.request(QuitOrigin::System, unsaved, state.manager.has_active()).0 {
        QuitAction::Finished { proceed: true, .. } => {
            if state.control.is_running() {
                // The control server stops first (its clients get `app_quitting`), off the main thread; then the
                // waiting system gets its yes (`commands::terminate`).
                state.quit.set_system_waiting();
                let app = app.clone();
                std::thread::spawn(move || commands::terminate(&app, &state));
                return TerminateReply::Later;
            }
            state.quit.confirm();
            state.stop_polling();
            TerminateReply::Now
        }
        QuitAction::Finished { proceed: false, .. } => TerminateReply::Cancel,
        action @ (QuitAction::Ask(_) | QuitAction::Joined(_)) => {
            state.quit.set_system_waiting();
            let app = app.clone();
            std::thread::spawn(move || commands::handle_quit(&app, &state, action));
            TerminateReply::Later
        }
    }
}

/// Cmd+Q goes through the quit question; the Edit items keep text editing shortcuts working in the windows.
fn install_menu(app: &AppHandle) -> tauri::Result<()> {
    let quit = MenuItemBuilder::with_id("quit", l10n::tr("Quit MacVPN", &[])).accelerator("CmdOrCtrl+Q").build(app)?;
    let app_menu = SubmenuBuilder::new(app, "MacVPN").item(&quit).build()?;
    let edit = SubmenuBuilder::new(app, "Edit")
        .undo()
        .redo()
        .separator()
        .cut()
        .copy()
        .paste()
        .select_all()
        .separator()
        .close_window()
        .build()?;
    app.set_menu(MenuBuilder::new(app).items(&[&app_menu, &edit]).build()?)?;
    app.on_menu_event(|app, event| {
        if event.id() == "quit"
            && let Some(state) = app.try_state::<Arc<AppState>>()
        {
            commands::request_quit(app, &state, QuitOrigin::Menu);
        }
    });
    Ok(())
}

fn main() {
    macvpn_platform_mac::install_core_hooks();
    let env = match Environment::detect() {
        Ok(env) => env,
        Err(e) => {
            eprintln!("MacVPN: {e}");
            std::process::exit(1);
        }
    };
    // The 1.1 connection store: only the migration's source and the legacy read-only mode's fallback.
    let store = Arc::new(ConnectionStore::new(env.connections_dir()));
    let (storage, migrate) = storage(&env, store.clone());
    // The Swift `AppModel.init` part, before anything else (and before any secret is read): the Keychain
    // migration, the sweep of the native profiles staged by the previous run, and the legacy profile removal.
    let mut migrate = Some(migrate);
    for step in &LAUNCH_SEQUENCE[..3] {
        match step {
            LaunchStep::MigrateKeychain => {
                if let Some(migrate) = migrate.take() {
                    migrate();
                }
            }
            LaunchStep::SweepStagedProfiles => {
                if let Some(parent) = env.staging_parent() {
                    profile_staging::sweep(&parent);
                }
            }
            LaunchStep::RemoveLegacyProfiles => {
                store.remove_legacy_profiles();
            }
            _ => unreachable!("the first three launch steps"),
        }
    }
    let state = build_state(env, storage);

    let app = tauri::Builder::default()
        .manage(state.clone())
        .invoke_handler(tauri::generate_handler![
            commands::get_view_model,
            commands::connect,
            commands::disconnect,
            commands::pin,
            commands::unpin,
            commands::move_pinned,
            commands::open_window,
            commands::close_window,
            commands::set_menu_height,
            commands::quit,
            commands::check_for_updates,
            commands::set_update_option,
            commands::set_launch_at_login,
            commands::open_login_items_settings,
            commands::open_user_guide,
            manage::select_connection,
            manage::resolve_unsaved,
            manage::take_tab_request,
            manage::editor_open,
            manage::editor_update,
            manage::editor_save,
            manage::editor_forget,
            manage::editor_choose_ca,
            manage::create_connection,
            manage::import_files,
            manage::answer_question,
            manage::export_check,
            manage::export_connection,
            manage::delete_connection,
            manage::log_subscribe,
            manage::log_copy,
            manage::log_save,
            system::setup_check,
            system::setup_install_homebrew,
            system::setup_install_tools,
            system::setup_install_root,
            system::setup_uninstall,
            system::quit_after_uninstall,
            update_window::update_install,
            update_window::update_open_page,
            update_window::update_dismiss_notice,
            prompts::answer_prompt,
            prompts::prompt_ready,
            credentials::answer_credentials,
            credentials::credentials_ready,
            pairing::pairing_answer,
            pairing::pairing_ready,
            fit::fit_window,
            control::control_set_enabled,
            control::control_set_allowed,
            control::control_revoke,
            control::control_audit_save,
            vault::vault_ready,
            vault::vault_setup_step,
            vault::vault_create,
            vault::vault_confirm_recovery,
            vault::vault_open_restore,
            vault::vault_unlock,
            vault::vault_recover,
            vault::vault_close,
            vault::vault_change_password,
            vault::vault_enable_auto_unlock,
            vault::vault_new_recovery_key,
            vault::vault_confirm_new_key,
            vault::vault_show,
            vault::vault_lock_now,
            vault::vault_auto_unlock_off,
            vault::vault_set_show_lock_now,
            vault::vault_copy_recovery_key,
            folders::folder_create,
            folders::folder_rename,
            folders::folder_set_color,
            folders::folder_set_collapsed,
            folders::folder_move,
            folders::folder_delete,
            folders::item_move,
            folders::item_set_color,
            shared_credentials::credential_create,
            shared_credentials::credential_update,
            shared_credentials::credential_delete,
            shared_credentials::credential_link,
            shared_credentials::credential_matches,
            shared_credentials::credential_from_connection,
            shared_credentials::answer_question_choice,
            backup::backup_show_window,
            backup::backup_close_window,
            backup::backup_choose_destination,
            backup::backup_save,
            backup::restore_choose_file,
            backup::restore_open,
            backup::restore_apply,
            backup::restore_fresh_apply,
            backup::restore_apply_preferences,
            backup::restore_reinstall_profile,
            backup::restore_discard,
            catalog::catalog_parse_subscription,
            catalog::catalog_choose_file_source,
            catalog::catalog_preview,
            catalog::catalog_confirm,
            catalog::catalog_discard,
            catalog::catalog_refresh,
            catalog::catalog_refresh_all,
            catalog::catalog_update_source,
            catalog::catalog_update_team_key,
            catalog::catalog_update_bearer,
            catalog::catalog_unsubscribe,
            catalog::catalog_duplicate,
            catalog::catalog_install_profile,
            catalog::catalog_profile_installed,
            catalog::admin_key_generate,
            catalog::admin_key_export,
            catalog::admin_key_choose_file,
            catalog::admin_key_import,
            catalog::admin_key_promote,
            catalog::publish_preview,
            catalog::publish_catalog,
            catalog::publication_rotate_team_key,
            catalog::publication_copy_subscription,
            catalog::publication_forget,
            catalog::catalog_copy_team_key,
        ])
        .on_window_event(|window, event| {
            if let WindowEvent::Destroyed = event {
                fit::forget(window.label());
            }
            // The last real window gone: the Dock icon goes too.
            if let WindowEvent::Destroyed = event
                && dock::counts(window.label())
            {
                dock::sync(window.app_handle());
            }
            // Shown, hidden, minimized or restored: the poll fallback's "a window is open" (main thread here).
            if dock::counts(window.label()) {
                dock::track_shown(window.app_handle());
            }
            if window.label() == manage::MANAGE_WINDOW {
                manage::on_window_event(window, event);
                return;
            }
            if prompts::is_prompt_window(window.label()) {
                prompts::on_window_event(window, event);
                return;
            }
            if credentials::is_credential_window(window.label()) {
                credentials::on_window_event(window, event);
                return;
            }
            if vault::is_vault_window(window.label()) {
                vault::on_window_event(window, event);
                return;
            }
            if backup::is_backup_window(window.label()) {
                backup::on_window_event(window, event);
                return;
            }
            if pairing::is_pairing_window(window.label()) {
                pairing::on_window_event(window, event);
                return;
            }
            if window.label() == update_window::UPDATE_WINDOW {
                if let WindowEvent::Destroyed = event
                    && let Some(state) = window.app_handle().try_state::<Arc<AppState>>()
                {
                    update_window::window_destroyed(window.app_handle(), &state);
                }
                return;
            }
            if window.label() != tray::MENU_WINDOW {
                return;
            }
            match event {
                WindowEvent::Focused(false) => tray::hide_on_blur(window.app_handle()),
                // The popover is never closed (Cmd+W), only hidden.
                WindowEvent::CloseRequested { api, .. } => {
                    api.prevent_close();
                    tray::hide_menu(window.app_handle());
                }
                _ => {}
            }
        })
        .setup(move |app| {
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);
            let handle = app.handle().clone();
            // A system quit goes through the quit questions too (tao does not implement this delegate method).
            let terminating = handle.clone();
            if !app_hooks::install_terminate_handler(move || system_terminate_request(&terminating)) {
                eprintln!("MacVPN: applicationShouldTerminate could not be installed");
            }
            // A woken Mac refreshes at once (the Swift `didWakeNotification`), the team catalogs too.
            let poller = state.poller.clone();
            let catalogs = state.catalog.service.clone();
            app_hooks::observe_wake(move || {
                poller.wake();
                catalogs.wake();
            });
            install_menu(&handle)?;
            tray::create_menu_window(&handle)?;
            tray::create(&handle)?;
            connect_hooks(&handle, &state);
            Publisher::spawn(handle.clone(), state.clone());
            #[cfg(debug_assertions)]
            smoke::start(&handle, &state);
            std::thread::Builder::new().name("macvpn-launch".into()).spawn(move || {
                for step in &LAUNCH_SEQUENCE[3..] {
                    run_late_launch_step(&handle, &state, *step);
                }
                // The control API, once the connections and the system status are known.
                control::launch(&state);
            })?;
            Ok(())
        })
        .build(tauri::generate_context!())
        .unwrap_or_else(|e| {
            eprintln!("MacVPN: {e}");
            std::process::exit(1);
        });

    app.run(|app, event| match event {
        // Closing the last window does not quit a menu bar app; only `app.exit` (the quit flow) does.
        RunEvent::ExitRequested { code: None, api, .. } => api.prevent_exit(),
        // A click on the Dock icon (shown while a window is open): that window comes forward; nothing opens.
        #[cfg(target_os = "macos")]
        RunEvent::Reopen { .. } => dock::reopen(app),
        _ => {}
    });
}
