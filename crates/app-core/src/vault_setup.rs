//! The vault windows' logic without a UI (plan B Task 14, spec 2.3 and 2.7): the create window's steps
//! ([`VaultSetup`]), the launch decision ([`launch_decision`]), the one-second input lock of the vault windows
//! ([`InputLock`]) and the unlock reply ([`UnlockReply`]).
//!
//! # The create window
//!
//! `Intro` (what the vault is; in migration mode "macOS may ask several times — choose Always Allow — this happens
//! only once" with the number of Keychain items) → `Password` (the master password twice, the strength hint, at
//! least 10 characters, "Unlock automatically", on by default) → `RecoveryKey` (shown once, with Copy and "I saved
//! it") → `Confirm` (retype one randomly chosen group, compared case-insensitively) → in migration mode
//! `Migrating` → `Verified` (the counts, and the reminder where backup lives) → `Done`. A failed migration is
//! `Failed { message }`; Retry goes back to `Password` (the failed migration removed the new vault, so a new one is
//! created). Without migration `Confirm` leads to `Done` at once.
//!
//! The recovery key crosses IPC once, as the reply to `vault_create`; it is held here (wiped on drop) only until the
//! confirmation and is never part of [`VaultSetupView`]. The restore branch of Task 21 hooks in at `Intro`
//! ([`VaultSetupView::can_restore`]).

use crate::migration::MigrationReport;
use crate::vault::{AutoUnlock, UnlockError, VaultLifecycle};
use macvpn_core::l10n::{self, Arg};
use macvpn_core::vault::RecoveryKey;
use serde::Serialize;
use std::time::{Duration, Instant};

/// The number of groups of a recovery key.
pub const RECOVERY_GROUPS: usize = 6;
/// The vault windows refuse input for this long after they were shown and their page was ready.
pub const INPUT_LOCK: Duration = Duration::from_secs(1);

/// Where the create window is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupStep {
    Intro,
    Password,
    RecoveryKey,
    Confirm,
    Migrating,
    Verified,
    Done,
    Failed,
}

impl SetupStep {
    pub fn as_str(self) -> &'static str {
        match self {
            SetupStep::Intro => "intro",
            SetupStep::Password => "password",
            SetupStep::RecoveryKey => "recoveryKey",
            SetupStep::Confirm => "confirm",
            SetupStep::Migrating => "migrating",
            SetupStep::Verified => "verified",
            SetupStep::Done => "done",
            SetupStep::Failed => "failed",
        }
    }
}

/// A navigation of the create window (`vault_setup_step`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupAction {
    /// Intro → Password.
    Continue,
    /// Password → Intro.
    Back,
    /// RecoveryKey → Confirm ("I saved it"; the window forgets the key then, it is shown only once).
    Saved,
    /// Failed → Password.
    Retry,
    /// Verified → Done.
    Finish,
}

pub fn parse_setup_action(raw: &str) -> Result<SetupAction, String> {
    match raw {
        "continue" => Ok(SetupAction::Continue),
        "back" => Ok(SetupAction::Back),
        "saved" => Ok(SetupAction::Saved),
        "retry" => Ok(SetupAction::Retry),
        "finish" => Ok(SetupAction::Finish),
        _ => Err("invalid action".into()),
    }
}

/// The create window's part of the view model. Never a password or the recovery key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultSetupView {
    pub step: &'static str,
    /// The 1.1 data is migrated after the vault is created.
    pub migrating: bool,
    /// The Keychain items the migration reads ("macOS may ask N times").
    pub keychain_items: usize,
    /// `Confirm`: the group to retype (0-based; the window shows it 1-based).
    pub group: Option<usize>,
    /// `Failed`: why; `Confirm`: the last typed group did not match.
    pub message: Option<String>,
    /// `Verified` / `Done` after a migration: what was moved.
    pub connections: usize,
    pub secrets: usize,
    pub skipped: usize,
    /// "Restore from backup…" is offered at `Intro` (Task 21 turns it on).
    pub can_restore: bool,
    /// A fresh restore from a backup runs instead of the migration (chosen at `Intro`): after `Confirm` the window
    /// restores the backup into the new vault.
    pub restoring: bool,
    /// A migration left from an earlier run (shown at launch, [`VaultSetup::resuming`]).
    pub resumed: bool,
    /// `Failed`: the new vault was removed and the old data is used read-only (otherwise the vault was kept).
    pub vault_removed: bool,
}

/// The create window's state.
pub struct VaultSetup {
    migrating: bool,
    /// The 1.1 data was found at launch (`migrating` again when a restore is given up at `Password`).
    legacy: bool,
    restoring: bool,
    resumed: bool,
    vault_removed: bool,
    keychain_items: usize,
    step: SetupStep,
    /// Held from `vault_create` until the confirmation (wiped on drop); never in the view.
    key: Option<RecoveryKey>,
    group: usize,
    message: Option<String>,
    report: Option<MigrationReport>,
    can_restore: bool,
}

impl std::fmt::Debug for VaultSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultSetup")
            .field("step", &self.step)
            .field("migrating", &self.migrating)
            .finish_non_exhaustive()
    }
}

/// A transition that does not fit the current step.
fn wrong_step() -> String {
    "not at this step".into()
}

/// A typed group as the key shows it: upper case; `O` reads as `0`, `I` and `L` as `1`; spaces and `-` dropped.
pub fn normalize_group(typed: &str) -> String {
    typed
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        })
        .collect()
}

/// Whether `typed` is group `group` of `key` (normalized, case-insensitive); the error is the message to show.
fn check_group(key: Option<&RecoveryKey>, group: usize, typed: &str) -> Result<(), String> {
    let expected = key.map(|k| k.group(group)).unwrap_or("");
    let typed = normalize_group(typed);
    // The same work whatever the input (the key is wiped right after; this only guards against typos).
    let matches = !expected.is_empty()
        && typed.len() == expected.len()
        && typed.bytes().zip(expected.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0;
    if matches {
        Ok(())
    } else {
        Err(l10n::tr("This is not group %lld of your recovery key", &[Arg::Int(group as i64 + 1)]))
    }
}

/// A new recovery key (Task 15, `vault-recovery`) waiting for its "retype group N" check: held (wiped on drop)
/// until the check passes or the window closes.
pub struct KeyConfirmation {
    key: RecoveryKey,
    group: usize,
}

impl KeyConfirmation {
    pub fn new(key: RecoveryKey, group: usize) -> Self {
        KeyConfirmation { key, group: group % RECOVERY_GROUPS }
    }

    pub fn group(&self) -> usize {
        self.group
    }

    /// The key, to save once the check passed ([`crate::vault::VaultLifecycle::save_recovery_key`]).
    pub fn key(&self) -> &RecoveryKey {
        &self.key
    }

    /// The asked `group` and its text; the error is the message to show.
    pub fn check(&self, group: usize, typed: &str) -> Result<(), String> {
        if group != self.group {
            return Err(wrong_step());
        }
        check_group(Some(&self.key), self.group, typed)
    }
}

impl VaultSetup {
    pub fn new(migrating: bool, keychain_items: usize) -> Self {
        VaultSetup {
            migrating,
            legacy: migrating,
            restoring: false,
            resumed: false,
            vault_removed: false,
            keychain_items,
            step: SetupStep::Intro,
            key: None,
            group: 0,
            message: None,
            report: None,
            can_restore: false,
        }
    }

    /// A migration left from an earlier run (the deletion of the old data, or a verified import to finish), shown
    /// at launch: the window starts at `Migrating` (it explains the Keychain prompts) and ends at `Done` or `Failed`.
    pub fn resuming(keychain_items: usize) -> Self {
        let mut setup = VaultSetup::new(true, keychain_items);
        setup.step = SetupStep::Migrating;
        setup.resumed = true;
        setup
    }

    pub fn step(&self) -> SetupStep {
        self.step
    }

    pub fn migrating(&self) -> bool {
        self.migrating
    }

    /// Offers "Restore from backup…" at `Intro` (Task 21).
    pub fn set_can_restore(&mut self, on: bool) {
        self.can_restore = on;
    }

    /// A fresh restore from a backup (Task 21) instead of the migration: `Confirm` then leads to `Done`, and the
    /// restore applies its payload into the new vault (nothing of the 1.1 storage is migrated).
    pub fn set_restoring(&mut self) {
        self.migrating = false;
        self.restoring = true;
    }

    /// A fresh restore runs (see [`Self::set_restoring`]).
    pub fn restoring(&self) -> bool {
        self.restoring
    }

    pub fn view(&self) -> VaultSetupView {
        let report = self.report.as_ref();
        VaultSetupView {
            step: self.step.as_str(),
            migrating: self.migrating,
            keychain_items: self.keychain_items,
            group: (self.step == SetupStep::Confirm).then_some(self.group),
            message: self.message.clone(),
            connections: report.map_or(0, |r| r.connections),
            secrets: report.map_or(0, |r| r.secrets),
            skipped: report.map_or(0, |r| r.skipped.len()),
            can_restore: self.can_restore && self.step == SetupStep::Intro,
            restoring: self.restoring,
            resumed: self.resumed,
            vault_removed: self.step == SetupStep::Failed && self.vault_removed,
        }
    }

    /// The window's navigation buttons.
    pub fn act(&mut self, action: SetupAction) -> Result<(), String> {
        self.step = match (self.step, action) {
            (SetupStep::Intro, SetupAction::Continue) => SetupStep::Password,
            (SetupStep::Password, SetupAction::Back) => {
                // Back at the intro the restore is given up: the migration (if any) is the way again.
                self.restoring = false;
                self.migrating = self.legacy;
                SetupStep::Intro
            }
            (SetupStep::RecoveryKey, SetupAction::Saved) => SetupStep::Confirm,
            (SetupStep::Failed, SetupAction::Retry) => SetupStep::Password,
            (SetupStep::Verified, SetupAction::Finish) => SetupStep::Done,
            _ => return Err(wrong_step()),
        };
        self.message = None;
        Ok(())
    }

    /// The first-run restore may be written: a restoring setup after its recovery key check (`Done`).
    pub fn may_restore_fresh(&self) -> Result<(), String> {
        if self.restoring && self.step == SetupStep::Done { Ok(()) } else { Err(wrong_step()) }
    }

    /// Lock Now waits: the window is past its password step (the new vault exists) and not finished yet (the key
    /// shown or checked, the migration running or waiting for Continue, the restore not written).
    pub fn blocks_lock(&self) -> bool {
        matches!(self.step, SetupStep::RecoveryKey | SetupStep::Confirm | SetupStep::Migrating | SetupStep::Verified)
            || (self.restoring && self.step == SetupStep::Done)
    }

    /// Only at `Password`: `vault_create` may run now.
    pub fn may_create(&self) -> Result<(), String> {
        if self.step == SetupStep::Password { Ok(()) } else { Err(wrong_step()) }
    }

    /// The vault was created: its key is shown once; `group` (0..6) is the one to retype.
    pub fn created(&mut self, key: RecoveryKey, group: usize) {
        self.key = Some(key);
        self.group = group % RECOVERY_GROUPS;
        self.step = SetupStep::RecoveryKey;
        self.message = None;
    }

    /// `Confirm`: the typed `group` must be the asked one and match the key (case-insensitively). Right: the key is
    /// dropped, and the next step is `Migrating` (migration mode) or `Done`. Wrong: the step stays, with a message.
    pub fn confirm(&mut self, group: usize, typed: &str) -> Result<(), String> {
        if self.step != SetupStep::Confirm || group != self.group {
            return Err(wrong_step());
        }
        if let Err(message) = check_group(self.key.as_ref(), self.group, typed) {
            self.message = Some(message.clone());
            return Err(message);
        }
        self.key = None;
        self.message = None;
        self.step = if self.migrating { SetupStep::Migrating } else { SetupStep::Done };
        Ok(())
    }

    /// Retry when the failed migration kept its vault (it could not be removed): the migration runs again into it
    /// (`Failed` → `Migrating`; a new vault cannot be created next to it).
    pub fn retry_migration(&mut self) -> Result<(), String> {
        if self.step != SetupStep::Failed || !self.migrating {
            return Err(wrong_step());
        }
        self.message = None;
        self.step = SetupStep::Migrating;
        Ok(())
    }

    /// The migration failed (`Migrating` only); `vault_removed`: the new vault was removed and the app uses the old
    /// data read-only (the migration's `legacy_read_only`), otherwise the vault was kept.
    pub fn failed(&mut self, message: String, vault_removed: bool) {
        if self.step != SetupStep::Migrating {
            return;
        }
        self.vault_removed = vault_removed;
        self.message = Some(message);
        self.step = SetupStep::Failed;
    }

    /// The migration ended (`Migrating` only). An error here means the new vault was removed (see [`Self::failed`]).
    pub fn migrated(&mut self, result: Result<MigrationReport, String>) {
        if self.step != SetupStep::Migrating {
            return;
        }
        match result {
            Ok(report) => {
                self.message = None;
                // Only the deletion was left, or nothing to do: nothing new to report.
                let verified = !report.resumed && !report.vault_had_data;
                self.step = if verified { SetupStep::Verified } else { SetupStep::Done };
                self.report = Some(report);
            }
            Err(message) => {
                let removed = !self.resumed;
                self.failed(message, removed);
            }
        }
    }

    /// The window may close: done, or nothing created yet (closing the window then leaves the app as it is).
    pub fn may_close(&self) -> bool {
        !matches!(self.step, SetupStep::Migrating | SetupStep::RecoveryKey | SetupStep::Confirm)
    }
}

// MARK: - Launch

/// What the app does with the vault at launch (after the Keychain move, before the connections are read).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchDecision {
    /// Opened (auto-unlock): the normal launch.
    Unlocked,
    /// The vault exists, the key store gave no usable key: the menu is locked and `vault-unlock` opens.
    Unlock,
    /// No vault: `vault-create` opens. `migrating`: the 1.1 data is there; meanwhile the app runs from it,
    /// read-only.
    Create { migrating: bool },
}

/// The launch decision. `has_legacy_data` is asked only when there is no vault. With legacy data the lifecycle
/// enters the legacy read-only mode (the stores read the 1.1 storage until the migration succeeds).
pub fn launch_decision(vault: &VaultLifecycle, has_legacy_data: impl FnOnce() -> bool) -> LaunchDecision {
    match vault.try_auto_unlock() {
        AutoUnlock::Unlocked => LaunchDecision::Unlocked,
        AutoUnlock::NeedsPassword => LaunchDecision::Unlock,
        AutoUnlock::NotCreated => {
            let migrating = has_legacy_data();
            if migrating {
                vault.set_legacy_read_only(Some(String::new()));
            }
            LaunchDecision::Create { migrating }
        }
    }
}

// MARK: - Input lock

/// The one-second input lock of a vault window: counted from the later of the window being ordered on screen
/// (`shown`) and its page being ready (`loaded`), like the prompt windows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InputLock {
    shown: Option<Instant>,
    loaded: Option<Instant>,
}

impl InputLock {
    pub fn mark_shown(&mut self, now: Instant) {
        self.shown = Some(now);
    }

    pub fn mark_loaded(&mut self, now: Instant) {
        self.loaded = Some(now);
    }

    /// Input is taken: both happened, at least [`INPUT_LOCK`] ago.
    pub fn armed(&self, now: Instant) -> bool {
        match (self.shown, self.loaded) {
            (Some(shown), Some(loaded)) => now >= shown.max(loaded) + INPUT_LOCK,
            _ => false,
        }
    }

    /// `Err("too early")` while not armed (the UI shows "Not ready yet").
    pub fn check(&self, now: Instant) -> Result<(), String> {
        if self.armed(now) { Ok(()) } else { Err("too early".into()) }
    }
}

// MARK: - Unlock reply

/// The reply of `vault_unlock` / `vault_recover` (and the Task 15 password checks): never any part of a secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockReply {
    pub ok: bool,
    /// `wrong`, `tooSoon`, `corrupt`, `newer`, `invalid` or `error`.
    pub error: Option<&'static str>,
    /// Wrong / too soon: the next attempt is taken after this many milliseconds (the countdown).
    pub retry_after_ms: Option<u64>,
    /// The localized text to show.
    pub message: Option<String>,
}

impl UnlockReply {
    pub fn ok() -> UnlockReply {
        UnlockReply { ok: true, error: None, retry_after_ms: None, message: None }
    }

    /// A refused input (a password that breaks the rules, a malformed recovery key): `message` is shown.
    pub fn invalid(message: String) -> UnlockReply {
        UnlockReply { ok: false, error: Some("invalid"), retry_after_ms: None, message: Some(message) }
    }

    pub fn from_result(result: Result<(), UnlockError>) -> UnlockReply {
        let Err(e) = result else { return UnlockReply::ok() };
        let millis = |d: Duration| Some(u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        let (error, retry_after_ms, message) = match e {
            UnlockError::Wrong { retry_after } => {
                ("wrong", millis(retry_after), l10n::tr("Wrong password or recovery key", &[]))
            }
            UnlockError::TooSoon { retry_after } => {
                ("tooSoon", millis(retry_after), l10n::tr("Wait a moment before the next attempt", &[]))
            }
            UnlockError::Corrupt => ("corrupt", None, l10n::tr("The vault is damaged and cannot be opened", &[])),
            UnlockError::NewerSchema => {
                ("newer", None, l10n::tr("This vault was saved by a newer MacVPN. Update MacVPN to open it.", &[]))
            }
            UnlockError::Io(detail) => ("error", None, detail),
        };
        UnlockReply { ok: false, error: Some(error), retry_after_ms, message: Some(message) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use macvpn_core::vault::FixedEntropy;

    fn key() -> RecoveryKey {
        RecoveryKey::generate(&FixedEntropy::new(9)).unwrap()
    }

    #[test]
    fn groups_are_normalized_like_the_key() {
        assert_eq!(normalize_group(" ab-c d "), "ABCD");
        assert_eq!(normalize_group("oil0"), "0110");
    }

    #[test]
    fn the_input_lock_counts_from_the_later_signal() {
        let t0 = Instant::now();
        let mut lock = InputLock::default();
        assert!(!lock.armed(t0 + Duration::from_secs(10)));
        lock.mark_shown(t0);
        assert!(!lock.armed(t0 + Duration::from_secs(10)), "not loaded yet");
        lock.mark_loaded(t0 + Duration::from_millis(500));
        assert!(!lock.armed(t0 + Duration::from_millis(1400)));
        assert!(lock.armed(t0 + Duration::from_millis(1500)));
        assert_eq!(lock.check(t0), Err("too early".to_string()));
    }

    #[test]
    fn the_key_is_never_in_the_view() {
        let mut setup = VaultSetup::new(false, 0);
        setup.act(SetupAction::Continue).unwrap();
        let k = key();
        let text = k.as_str().to_string();
        setup.created(k, 2);
        let view = format!("{:?} {:?}", setup.view(), setup);
        assert!(!view.contains(&text) && !view.contains(&text[..4]), "{view}");
    }
}
