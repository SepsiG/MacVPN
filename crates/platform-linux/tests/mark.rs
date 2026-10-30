use macvpn_platform_linux::pure::mark::{XattrRead, is_marked};

#[test]
fn the_origin_attribute_decides_and_unknowns_fail_closed() {
    assert!(is_marked(XattrRead::Present));
    assert!(!is_marked(XattrRead::Absent));
    assert!(!is_marked(XattrRead::NotSupported));
    assert!(!is_marked(XattrRead::NoFile));
    assert!(is_marked(XattrRead::Error(libc_eacces())));
}

fn libc_eacces() -> i32 {
    13
}

#[cfg(target_os = "linux")]
#[test]
fn a_downloaded_file_is_marked() {
    use macvpn_platform_api::Platform;
    let p = macvpn_platform_linux::LinPlatform::new(true);
    let dir = std::env::temp_dir().join(format!("linvpn-mark-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    let f = dir.join("a.ovpn");
    std::fs::write(&f, "client\n").unwrap();
    assert!(!p.download_mark().is_marked(&f));
    let set = std::process::Command::new("setfattr")
        .args(["-n", "user.xdg.origin.url", "-v", "https://example.com/a.ovpn"])
        .arg(&f)
        .status();
    match set {
        Ok(s) if s.success() => assert!(p.download_mark().is_marked(&f)),
        _ => eprintln!("skipped the marked case: setfattr or user xattrs unavailable here"),
    }
    assert!(!p.download_mark().is_marked(&dir.join("missing.ovpn")));
    std::fs::remove_dir_all(&dir).unwrap();
}
