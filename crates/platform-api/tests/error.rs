//! `PlatformError`'s messages.

use macvpn_core::l10n::AppLanguage;
use macvpn_platform_api::PlatformError;

fn in_language(language: AppLanguage, error: &PlatformError) -> String {
    AppLanguage::set_thread_override(Some(language));
    let message = error.message();
    AppLanguage::set_thread_override(None);
    message
}

#[test]
fn unsupported_is_the_localized_text_without_the_callers_value() {
    let error = PlatformError::Unsupported { what: "native VPN" };
    let en = in_language(AppLanguage::En, &error);
    let hu = in_language(AppLanguage::Hu, &error);
    assert_eq!(en, "Not available on this system yet");
    assert_eq!(hu, "Ezen a rendszeren még nem érhető el");
    assert!(!en.contains("native VPN") && !hu.contains("native VPN"));
}

#[test]
fn failed_carries_its_message() {
    let error = PlatformError::Failed("Something went wrong".into());
    assert_eq!(error.message(), "Something went wrong");
    assert_eq!(error.to_string(), "Something went wrong");
    assert_eq!(String::from(error), "Something went wrong");
}

#[test]
fn into_string_is_the_message() {
    AppLanguage::set_thread_override(Some(AppLanguage::En));
    let s: String = PlatformError::Unsupported { what: "clipboard" }.into();
    AppLanguage::set_thread_override(None);
    assert_eq!(s, "Not available on this system yet");
}
