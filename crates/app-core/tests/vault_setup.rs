//! The create window's steps, the launch decision and the unlock reply (plan B Task 14): fakes only
//! (`MemoryKeyStore`, `FixedEntropy`, the insecure test KDF parameters).

mod common;

use common::TempDir;
use macvpn_app_core::migration::MigrationReport;
use macvpn_app_core::vault::{UnlockError, VaultLifecycle, VaultState};
use macvpn_app_core::vault_setup::{
    KeyConfirmation, LaunchDecision, SetupAction, SetupStep, UnlockReply, VaultSetup, launch_decision,
    parse_setup_action,
};
use macvpn_core::l10n::AppLanguage;
use macvpn_core::vault::{FixedEntropy, KdfParams, KeyStore, MemoryKeyStore, RecoveryKey};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

fn key() -> RecoveryKey {
    RecoveryKey::generate(&FixedEntropy::new(4)).unwrap()
}

/// A setup at `Confirm` for group 3, with the key's group 3.
fn at_confirm(migrating: bool) -> (VaultSetup, String) {
    let mut setup = VaultSetup::new(migrating, 4);
    setup.act(SetupAction::Continue).unwrap();
    setup.may_create().unwrap();
    let k = key();
    let group = k.group(3).to_string();
    setup.created(k, 3);
    assert_eq!(setup.step(), SetupStep::RecoveryKey);
    assert!(!setup.may_close(), "the key is shown");
    setup.act(SetupAction::Saved).unwrap();
    assert_eq!(setup.view().group, Some(3));
    (setup, group)
}

#[test]
fn the_steps_without_migration() {
    AppLanguage::set_thread_override(Some(AppLanguage::En));
    let mut setup = VaultSetup::new(false, 0);
    assert_eq!(setup.view().step, "intro");
    assert!(setup.may_create().is_err(), "no create before the password step");
    assert!(setup.act(SetupAction::Saved).is_err());
    setup.act(SetupAction::Continue).unwrap();
    setup.act(SetupAction::Back).unwrap();
    assert_eq!(setup.step(), SetupStep::Intro);
    let (mut setup, group) = at_confirm(false);
    setup.confirm(3, &group.to_lowercase()).unwrap();
    assert_eq!(setup.step(), SetupStep::Done);
    assert!(setup.may_close());
}

#[test]
fn the_confirm_step_rejects_a_wrong_group() {
    AppLanguage::set_thread_override(Some(AppLanguage::En));
    let (mut setup, group) = at_confirm(true);
    // Another group index, or the wrong text: refused, the step stays.
    assert!(setup.confirm(2, &group).is_err());
    let wrong = if group == "AAAA" { "BBBB" } else { "AAAA" };
    let message = setup.confirm(3, wrong).unwrap_err();
    assert_eq!(message, "This is not group 4 of your recovery key");
    assert_eq!(setup.step(), SetupStep::Confirm);
    assert_eq!(setup.view().message.as_deref(), Some(message.as_str()));
    // There is no way back to the key (shown once); the right group still works.
    assert!(setup.act(SetupAction::Saved).is_err());
    setup.confirm(3, &format!(" {} ", group.replace('0', "o"))).unwrap();
    assert_eq!(setup.step(), SetupStep::Migrating);
    assert!(!setup.may_close(), "no close during the migration");
}

#[test]
fn a_failed_migration_retries_from_the_password() {
    AppLanguage::set_thread_override(Some(AppLanguage::En));
    let (mut setup, group) = at_confirm(true);
    setup.confirm(3, &group).unwrap();
    setup.migrated(Err("the migration failed (read): denied".into()));
    assert_eq!(setup.step(), SetupStep::Failed);
    assert_eq!(setup.view().message.as_deref(), Some("the migration failed (read): denied"));
    assert!(setup.may_close());
    setup.act(SetupAction::Retry).unwrap();
    assert_eq!(setup.step(), SetupStep::Password);
    let k = key();
    let group = k.group(0).to_string();
    setup.created(k, 6);
    setup.act(SetupAction::Saved).unwrap();
    setup.confirm(0, &group).unwrap();
    setup.migrated(Ok(MigrationReport {
        connections: 3,
        secrets: 2,
        skipped: vec!["x".into()],
        ..MigrationReport::default()
    }));
    let view = setup.view();
    assert_eq!((view.step, view.connections, view.secrets, view.skipped), ("verified", 3, 2, 1));
    setup.act(SetupAction::Finish).unwrap();
    assert_eq!(setup.step(), SetupStep::Done);
}

#[test]
fn restore_is_offered_only_at_the_intro() {
    let mut setup = VaultSetup::new(false, 0);
    assert!(!setup.view().can_restore);
    setup.set_can_restore(true);
    assert!(setup.view().can_restore);
    setup.act(SetupAction::Continue).unwrap();
    assert!(!setup.view().can_restore);
}

#[test]
fn a_restore_replaces_the_migration_until_given_up() {
    AppLanguage::set_thread_override(Some(AppLanguage::En));
    let mut setup = VaultSetup::new(true, 4);
    setup.set_can_restore(true);
    setup.set_restoring();
    setup.act(SetupAction::Continue).unwrap();
    let view = setup.view();
    assert!(view.restoring && !view.migrating && !view.can_restore);
    // Back at the intro: the migration again.
    setup.act(SetupAction::Back).unwrap();
    let view = setup.view();
    assert!(!view.restoring && view.migrating && view.can_restore);
    // Restoring through the recovery key check: Confirm leads to Done (the window restores then), no migration.
    setup.set_restoring();
    setup.act(SetupAction::Continue).unwrap();
    let k = key();
    let group = k.group(2).to_string();
    setup.created(k, 2);
    setup.act(SetupAction::Saved).unwrap();
    setup.confirm(2, &group).unwrap();
    assert_eq!(setup.step(), SetupStep::Done);
    assert!(setup.restoring() && !setup.migrating());
}

#[test]
fn retry_into_a_kept_vault_runs_the_migration_again() {
    let (mut setup, group) = at_confirm(true);
    assert!(setup.retry_migration().is_err(), "only after a failure");
    setup.confirm(3, &group).unwrap();
    assert_eq!(setup.step(), SetupStep::Migrating);
    setup.migrated(Err("the vault could not be removed".into()));
    assert_eq!(setup.step(), SetupStep::Failed);
    setup.retry_migration().unwrap();
    assert_eq!(setup.step(), SetupStep::Migrating);
    assert!(setup.view().message.is_none());
}

#[test]
fn a_migration_left_from_an_earlier_run_is_shown_until_it_ends() {
    let mut setup = VaultSetup::resuming(2);
    let view = setup.view();
    assert_eq!((view.step, view.migrating, view.keychain_items), ("migrating", true, 2));
    assert!(!setup.may_close());
    setup.migrated(Ok(MigrationReport { resumed: true, ..Default::default() }));
    assert_eq!(setup.step(), SetupStep::Done);
    let mut failed = VaultSetup::resuming(0);
    failed.failed("the Keychain item could not be deleted".into(), false);
    assert_eq!(failed.step(), SetupStep::Failed);
    let view = failed.view();
    assert_eq!(view.message.as_deref(), Some("the Keychain item could not be deleted"));
    // The window says what happened: an earlier run's vault was kept, nothing was removed.
    assert!(view.resumed && !view.vault_removed);
}

#[test]
fn a_failure_says_whether_the_new_vault_was_removed() {
    let (mut setup, group) = at_confirm(true);
    setup.confirm(3, &group).unwrap();
    setup.failed("the import failed".into(), true);
    let view = setup.view();
    assert!(view.vault_removed && !view.resumed);
    let (mut kept, group) = at_confirm(true);
    kept.confirm(3, &group).unwrap();
    kept.failed("the old files could not be deleted".into(), false);
    assert!(!kept.view().vault_removed);
}

/// Final review 1.2.0 L5 and L6: the first-run restore is written only after the key check of a restoring setup;
/// Lock Now waits while the create window is past its password step.
#[test]
fn the_fresh_restore_and_lock_now_wait_for_their_step() {
    let mut setup = VaultSetup::new(false, 0);
    assert!(setup.may_restore_fresh().is_err(), "not restoring");
    assert!(!setup.blocks_lock());
    setup.set_can_restore(true);
    setup.set_restoring();
    setup.act(SetupAction::Continue).unwrap();
    assert!(setup.may_restore_fresh().is_err(), "at the password step");
    assert!(!setup.blocks_lock(), "nothing created yet");
    let k = key();
    let group = k.group(1).to_string();
    setup.created(k, 1);
    assert!(setup.blocks_lock() && setup.may_restore_fresh().is_err());
    setup.act(SetupAction::Saved).unwrap();
    assert!(setup.blocks_lock());
    setup.confirm(1, &group).unwrap();
    assert_eq!(setup.step(), SetupStep::Done);
    setup.may_restore_fresh().unwrap();
    assert!(setup.blocks_lock(), "the restore is still to be written");

    let (mut migrating, group) = at_confirm(true);
    assert!(migrating.blocks_lock());
    migrating.confirm(3, &group).unwrap();
    assert!(migrating.blocks_lock(), "migrating");
    migrating.migrated(Ok(MigrationReport { connections: 1, ..Default::default() }));
    assert!(migrating.blocks_lock(), "the old data is deleted after Continue");
    migrating.act(SetupAction::Finish).unwrap();
    assert!(!migrating.blocks_lock() && migrating.may_restore_fresh().is_err());
}

#[test]
fn actions_parse() {
    for (raw, action) in [
        ("continue", SetupAction::Continue),
        ("back", SetupAction::Back),
        ("saved", SetupAction::Saved),
        ("retry", SetupAction::Retry),
        ("finish", SetupAction::Finish),
    ] {
        assert_eq!(parse_setup_action(raw), Ok(action));
    }
    assert!(parse_setup_action("create").is_err());
    assert!(parse_setup_action("showKey").is_err());
}

fn lifecycle(tmp: &TempDir, store: Arc<MemoryKeyStore>) -> VaultLifecycle {
    let v = VaultLifecycle::new(
        tmp.path().join("MacVPN"),
        store,
        Arc::new(FixedEntropy::new(1)),
        KdfParams::insecure_for_tests(),
    );
    v.set_logger(|_| {});
    v
}

#[test]
#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]
fn the_launch_decision_for_the_three_cases() {
    // No vault, no old data: a fresh start.
    let tmp = TempDir::new();
    let v = lifecycle(&tmp, Arc::new(MemoryKeyStore::new()));
    assert_eq!(launch_decision(&v, || false), LaunchDecision::Create { migrating: false });
    assert_eq!(v.state(), VaultState::NotCreated);
    // No vault, old data: migration mode, the app reads the old storage meanwhile.
    let tmp = TempDir::new();
    let v = lifecycle(&tmp, Arc::new(MemoryKeyStore::new()));
    assert_eq!(launch_decision(&v, || true), LaunchDecision::Create { migrating: true });
    assert!(matches!(v.state(), VaultState::LegacyReadOnly { .. }));
    // A vault with the key-store item: unlocked; without it: the unlock window.
    let tmp = TempDir::new();
    let store = Arc::new(MemoryKeyStore::new());
    lifecycle(&tmp, store.clone()).create(Zeroizing::new("correct horse battery".into()), true).unwrap();
    let v = lifecycle(&tmp, store.clone());
    assert_eq!(launch_decision(&v, || panic!("not asked")), LaunchDecision::Unlocked);
    store.delete().unwrap();
    let v = lifecycle(&tmp, store);
    assert_eq!(launch_decision(&v, || panic!("not asked")), LaunchDecision::Unlock);
    assert_eq!(v.state(), VaultState::Locked);
}

#[test]
fn unlock_replies_carry_no_secret() {
    AppLanguage::set_thread_override(Some(AppLanguage::En));
    assert_eq!(UnlockReply::from_result(Ok(())), UnlockReply::ok());
    let wrong = UnlockReply::from_result(Err(UnlockError::Wrong { retry_after: Duration::from_secs(2) }));
    assert_eq!((wrong.error, wrong.retry_after_ms), (Some("wrong"), Some(2000)));
    assert_eq!(wrong.message.as_deref(), Some("Wrong password or recovery key"));
    let soon = UnlockReply::from_result(Err(UnlockError::TooSoon { retry_after: Duration::from_millis(1500) }));
    assert_eq!((soon.error, soon.retry_after_ms), (Some("tooSoon"), Some(1500)));
    assert_eq!(UnlockReply::from_result(Err(UnlockError::Corrupt)).error, Some("corrupt"));
    assert_eq!(UnlockReply::from_result(Err(UnlockError::NewerSchema)).error, Some("newer"));
    AppLanguage::set_thread_override(Some(AppLanguage::Hu));
    let hu = UnlockReply::from_result(Err(UnlockError::Wrong { retry_after: Duration::from_secs(1) }));
    assert_ne!(hu.message.as_deref(), Some("Wrong password or recovery key"));
}

#[test]
fn a_new_key_is_confirmed_by_one_group() {
    AppLanguage::set_thread_override(Some(AppLanguage::En));
    let k = key();
    let group = k.group(5).to_string();
    let check = KeyConfirmation::new(k, 11);
    assert_eq!(check.group(), 5);
    assert!(check.check(4, &group).is_err(), "another group index");
    assert_eq!(check.check(5, "zzzz").unwrap_err(), "This is not group 6 of your recovery key");
    assert!(check.check(5, &group.to_lowercase()).is_ok());
}
