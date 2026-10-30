//! The localized texts of LinVPN's "not yet" state: L-a had no VPN engine; since L-b only the sandbox (debug
//! builds, `MACVPN_SANDBOX_HOME`) answers with them, where the NetworkManager engine is never asked.

use macvpn_core::l10n;

/// The sandbox's answer to every start.
pub fn not_yet() -> String {
    l10n::tr("Connecting comes in a later version of LinVPN.", &[])
}

/// A connect refused because another user's NetworkManager profile holds this connection's derived UUID (a squat:
/// NM refuses a second profile with the UUID, and LinVPN never deletes a profile that is not its own).
pub fn uuid_squatted() -> String {
    l10n::tr(
        "Another user's NetworkManager connection uses this connection's ID. Ask them to remove it, or remove this connection and add it again.",
        &[],
    )
}

/// NetworkManager refused LinVPN's secret agent: another process of this user (a second LinVPN, a test run) has
/// registered one with LinVPN's identifier already (NM allows one per identifier and user).
pub fn agent_already_registered() -> String {
    l10n::tr(
        "Another LinVPN (or a LinVPN test) is already registered with NetworkManager for this user. Quit it and try again.",
        &[],
    )
}

/// NetworkManager's refusal of a second agent with the same identifier for the same user (`RegisterWithCapabilities`:
/// `org.freedesktop.NetworkManager.AgentManager.PermissionDenied`, "An agent with this ID is already registered for
/// this user.").
pub fn is_agent_already_registered(error_name: &str, message: &str) -> bool {
    error_name == "org.freedesktop.NetworkManager.AgentManager.PermissionDenied"
        && message.contains("already registered")
}

/// System Status' note in the sandbox, in place of the NetworkManager rows.
pub fn engine_note() -> String {
    l10n::tr(
        "Connecting comes in a later version of LinVPN: its engines arrive with NetworkManager support. You can already create, import, edit, export and back up connections.",
        &[],
    )
}

/// System Status' note in place of "Uninstall": LinVPN is removed as a package (it has no root helper of its own to
/// uninstall, so the app's own uninstall is refused with this note).
pub fn uninstall_note() -> String {
    l10n::tr("To remove LinVPN, run “apt remove linvpn” as an administrator.", &[])
}
