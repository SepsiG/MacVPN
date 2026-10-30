use macvpn_core::TargetOs;
use macvpn_core::l10n::{AppLanguage, TextPlatform, with_language};
use macvpn_platform_linux::pure::texts;

const LINUX: TextPlatform = TextPlatform { os: TargetOs::Linux, product: "LinVPN" };

#[test]
fn a_second_agent_of_the_user_is_explained_in_both_languages() {
    macvpn_core::l10n::set_text_platform(LINUX);
    assert!(
        with_language(AppLanguage::En, texts::agent_already_registered)
            .starts_with("Another LinVPN (or a LinVPN test)")
    );
    assert!(with_language(AppLanguage::Hu, texts::agent_already_registered).starts_with("Ehhez a felhasználóhoz már"));
}

#[test]
fn only_nms_duplicate_agent_refusal_is_the_second_agent() {
    let denied = "org.freedesktop.NetworkManager.AgentManager.PermissionDenied";
    assert!(texts::is_agent_already_registered(denied, "An agent with this ID is already registered for this user."));
    assert!(!texts::is_agent_already_registered(denied, "Unable to determine UID of request."));
    assert!(!texts::is_agent_already_registered("org.freedesktop.DBus.Error.ServiceUnknown", "already registered"));
}

#[test]
fn a_squatted_uuid_is_explained_in_both_languages() {
    macvpn_core::l10n::set_text_platform(LINUX);
    assert!(
        with_language(AppLanguage::En, texts::uuid_squatted).starts_with("Another user's NetworkManager connection")
    );
    assert!(with_language(AppLanguage::Hu, texts::uuid_squatted).starts_with("Egy másik felhasználó NetworkManager"));
}

#[test]
fn not_yet_in_both_languages() {
    macvpn_core::l10n::set_text_platform(LINUX);
    assert_eq!(with_language(AppLanguage::En, texts::not_yet), "Connecting comes in a later version of LinVPN.");
    assert_eq!(
        with_language(AppLanguage::Hu, texts::not_yet),
        "A kapcsolódás a LinVPN egy későbbi verziójában érkezik."
    );
    assert!(
        with_language(AppLanguage::En, texts::engine_note)
            .starts_with("Connecting comes in a later version of LinVPN: ")
    );
    assert!(
        with_language(AppLanguage::Hu, texts::engine_note)
            .starts_with("A kapcsolódás a LinVPN egy későbbi verziójában érkezik: ")
    );
    assert_eq!(
        with_language(AppLanguage::En, texts::uninstall_note),
        "To remove LinVPN, run “apt remove linvpn” as an administrator."
    );
    assert_eq!(
        with_language(AppLanguage::Hu, texts::uninstall_note),
        "A LinVPN eltávolításához futtasd rendszergazdaként: „apt remove linvpn”."
    );
}
