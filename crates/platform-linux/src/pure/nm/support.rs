//! The pure half of the engine's `NativeSupport` (resolved point 5; L-b Task 22): why Linux cannot run a
//! connection and the editor's notes, both from `nm_plan` alone, so every OS tests them.

use macvpn_core::nm_plan::{self, Input};
use macvpn_platform_api::PlatformNotes;

/// Why Linux cannot run these settings (`nm_plan`'s Linux reasons, one per line); `None` when it can, and when the
/// config itself is invalid (the validator says that).
pub fn unsupported_reason(input: &Input) -> Option<String> {
    nm_plan::plan(input).err().filter(|u| !u.invalid_config).map(|u| u.to_string())
}

/// The editor's notes: the Linux reasons, the plan's summary and warnings; L2TP and Cisco are saved without an
/// install step (their plan record is written at once, resolved point 2).
pub fn editor_notes(input: &Input) -> PlatformNotes {
    let mut notes = PlatformNotes { no_install_step: input.connection.kind.is_native(), ..PlatformNotes::default() };
    match nm_plan::plan(input) {
        Ok(plan) => {
            notes.summary = plan.summary;
            notes.warnings = plan.warnings;
        }
        Err(u) if !u.invalid_config => notes.reasons = u.reasons,
        Err(_) => {}
    }
    notes
}
