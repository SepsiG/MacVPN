use macvpn_platform_linux::pure::languages::preferred_languages;
use std::collections::HashMap;

fn langs(pairs: &[(&str, &str)]) -> Vec<String> {
    let map: HashMap<&str, &str> = pairs.iter().copied().collect();
    preferred_languages(|k| map.get(k).map(|v| v.to_string()))
}

#[test]
fn language_list_first_then_the_locale_variables() {
    assert_eq!(langs(&[("LANGUAGE", "hu:en_GB:en"), ("LANG", "de_DE.UTF-8")]), ["hu", "en-GB", "en"]);
    assert_eq!(langs(&[("LC_ALL", "hu_HU.UTF-8"), ("LANG", "en_US.UTF-8")]), ["hu-HU"]);
    assert_eq!(langs(&[("LC_MESSAGES", "hu_HU@euro"), ("LANG", "en_US.UTF-8")]), ["hu-HU"]);
    assert_eq!(langs(&[("LANG", "en_US.UTF-8")]), ["en-US"]);
}

#[test]
fn c_posix_and_empty_mean_nothing() {
    assert!(langs(&[("LANG", "C.UTF-8")]).is_empty());
    assert!(langs(&[("LANG", "POSIX")]).is_empty());
    assert!(langs(&[("LANGUAGE", ""), ("LANG", "")]).is_empty());
    // LANGUAGE is ignored when the locale is C (gettext's rule).
    assert!(langs(&[("LANGUAGE", "hu"), ("LC_ALL", "C")]).is_empty());
}
