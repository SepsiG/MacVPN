//! The portal against the real desktop session (`scripts/lin-remote.sh desktop`, at a checkpoint): a read only, no
//! dialog.
#![cfg(target_os = "linux")]

#[test]
#[ignore = "desktop: the portal's color-scheme"]
fn desktop_the_color_scheme_reads() {
    let dark = macvpn_platform_linux::portal_system_dark_for_tests();
    println!("the portal's color-scheme: {dark:?} (Some(true) dark, Some(false) light, None no preference)");
}
