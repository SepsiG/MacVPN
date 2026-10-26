//! The calling window's check of the commands that change the machine (an administrator step, an install, an
//! uninstall) or delete data (security review 2.0.0 part 2, I2). Each main window has its own capability file
//! (`capabilities/menu.json`, `manage.json`, `setup.json`, `update.json`) granting only the commands its UI uses;
//! these commands also answer only the window that offers them, as the vault, backup, catalog and shared-credential
//! commands do. A web view that somehow ran foreign script still could not trust a CA or uninstall the app from the
//! menu popover or the Update window.

use tauri::Window;

/// The message of a refused call (never shown: the UI only calls a command from its own window).
pub const REFUSED: &str = "not available in this window";

/// `Ok` when `window` is `allowed` (or, in a debug build's smoke run, one of the smoke driver's extra callers).
pub fn only(window: &Window, command: &str, allowed: &str) -> Result<(), String> {
    if permits(window.label(), command, allowed) { Ok(()) } else { Err(REFUSED.into()) }
}

fn permits(label: &str, command: &str, allowed: &str) -> bool {
    label == allowed || smoke_permits(label, command)
}

/// The smoke run (debug builds, `MACVPN_SMOKE_DIR` in the sandbox) drives `quit.js` in the Connections window,
/// which starts "Download and Install" itself; nothing else, and never in a release build.
#[cfg(debug_assertions)]
fn smoke_permits(label: &str, command: &str) -> bool {
    crate::platform::smoke::permits(label, command)
}

#[cfg(not(debug_assertions))]
fn smoke_permits(_label: &str, _command: &str) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::permits;

    #[test]
    fn only_the_offering_window_may_call() {
        assert!(permits("manage", "ras_trust_ca", "manage"));
        assert!(permits("setup", "setup_uninstall", "setup"));
        assert!(permits("update", "update_install", "update"));
        for label in ["menu", "setup", "update", "prompt-1", "cred-1", "pair-1", "vault-create", "backup", "", "Manage"]
        {
            assert!(!permits(label, "ras_trust_ca", "manage"), "{label}");
            assert!(!permits(label, "ras_allow_l2tp_nat", "manage"), "{label}");
        }
        for label in ["menu", "manage", "update", "prompt-1", "setup-2", "SETUP"] {
            assert!(!permits(label, "setup_uninstall", "setup"), "{label}");
        }
        // No smoke run in the unit tests: the Connections window may not start an update.
        assert!(!permits("manage", "update_install", "update"));
    }
}
