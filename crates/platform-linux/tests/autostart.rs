use macvpn_platform_linux::pure::autostart::{State, desktop_file, state_of};

#[test]
fn our_file_is_on() {
    let text = desktop_file();
    assert!(text.starts_with("[Desktop Entry]\n"));
    assert!(text.contains("\nExec=/usr/bin/linvpn\n"));
    assert!(text.contains("\nX-GNOME-Autostart-enabled=true\n"));
    assert_eq!(state_of(Some(&text)), State::On);
}

#[test]
fn missing_or_turned_off_elsewhere() {
    assert_eq!(state_of(None), State::Off);
    let hidden = desktop_file().replace("X-GNOME-Autostart-enabled=true", "Hidden=true");
    assert_eq!(state_of(Some(&hidden)), State::TurnedOffElsewhere);
    let disabled = desktop_file().replace("X-GNOME-Autostart-enabled=true", "X-GNOME-Autostart-enabled=false");
    assert_eq!(state_of(Some(&disabled)), State::TurnedOffElsewhere);
    // Keys in other groups do not count.
    let other = format!("{}\n[Desktop Action x]\nHidden=true\n", desktop_file());
    assert_eq!(state_of(Some(&other)), State::On);
}

#[cfg(target_os = "linux")]
#[test]
fn toggling_writes_and_removes_the_file() {
    use macvpn_platform_api::LoginItems;
    use macvpn_platform_linux::AutostartItem;
    let dir = std::env::temp_dir().join(format!("linvpn-autostart-{}", uuid::Uuid::new_v4()));
    let mut item = AutostartItem { file: dir.join("autostart/linvpn.desktop"), installed: true };
    assert!(!item.state().is_on);
    item.set_enabled(true).unwrap();
    assert!(item.state().is_on);
    assert_eq!(std::fs::read_to_string(&item.file).unwrap(), macvpn_platform_linux::pure::autostart::desktop_file());
    // Turned off by another tool: off with a note; the switch rewrites the whole file.
    std::fs::write(&item.file, macvpn_platform_linux::pure::autostart::desktop_file() + "Hidden=true\n").unwrap();
    let view = item.state();
    assert!(!view.is_on && view.can_toggle);
    assert_eq!(view.note.as_deref(), Some("Turned off by another app."));
    let hu = macvpn_core::l10n::with_language(macvpn_core::l10n::AppLanguage::Hu, || item.state().note);
    assert_eq!(hu.as_deref(), Some("Egy másik alkalmazás kikapcsolta."));
    item.set_enabled(true).unwrap();
    assert!(item.state().is_on);
    item.set_enabled(false).unwrap();
    assert!(!item.file.exists());
    assert!(!item.unregister_if_registered().unwrap());
    let dev = AutostartItem { file: dir.join("x.desktop"), installed: false };
    assert!(!dev.state().can_toggle);
    let hu = macvpn_core::l10n::with_language(macvpn_core::l10n::AppLanguage::Hu, || dev.state().note);
    assert_eq!(hu.as_deref(), Some("Az automatikus indítás akkor érhető el, ha a LinVPN a csomagjából van telepítve."));
    let _ = std::fs::remove_dir_all(&dir);
}

/// The sandbox's item and a development build's (a test binary is not `/usr/bin/linvpn`) write nothing, so the
/// real `~/.config/autostart` is never touched.
#[cfg(target_os = "linux")]
#[test]
fn the_sandbox_and_a_development_build_write_nothing() {
    use macvpn_platform_api::Platform;
    use macvpn_platform_linux::LinPlatform;
    let dir = std::env::temp_dir().join(format!("linvpn-autostart-{}", uuid::Uuid::new_v4()));
    let sandbox = LinPlatform::new(true);
    let mut item = sandbox.login_items(&dir, None, true);
    assert!(!item.state().can_toggle);
    assert!(item.set_enabled(true).is_err());
    assert!(!dir.exists());
    let real = LinPlatform::new(false);
    let mut item = real.login_items(&dir, None, false);
    assert!(!item.state().can_toggle);
    assert!(item.set_enabled(true).is_err());
    assert!(!dir.exists());
}
