use macvpn_core::deb_update::{self, Fields, StepArgs, StepError};
use std::path::PathBuf;

#[test]
fn asset_names() {
    assert_eq!(deb_update::deb_arch("x86_64"), Some("amd64"));
    assert_eq!(deb_update::deb_arch("aarch64"), Some("arm64"));
    assert_eq!(deb_update::deb_arch("riscv64"), None);
    assert_eq!(deb_update::asset("2.1.0", "amd64"), "linvpn_2.1.0_amd64.deb");
}

#[test]
fn dpkg_deb_fields() {
    let out = "Package: linvpn\nVersion: 2.1.0\nArchitecture: amd64\n";
    assert_eq!(
        deb_update::parse_fields(out),
        Some(Fields { package: "linvpn".into(), version: "2.1.0".into(), architecture: "amd64".into() })
    );
    assert_eq!(deb_update::parse_fields("Package: linvpn\nVersion: 2.1.0\n"), None);
    assert_eq!(
        deb_update::parse_fields("Package: linvpn\nPackage: other\nVersion: 2.1.0\nArchitecture: amd64\n"),
        None
    );
}

#[test]
fn version_order() {
    assert!(deb_update::is_newer("2.1.0", None));
    assert!(deb_update::is_newer("2.1.0", Some("2.0.5")));
    assert!(deb_update::is_newer("2.10.0", Some("2.9.9")));
    assert!(!deb_update::is_newer("2.0.5", Some("2.0.5")));
    assert!(!deb_update::is_newer("2.0.4", Some("2.0.5")));
    assert!(!deb_update::is_newer("2.1", Some("2.0.5")));
    assert!(!deb_update::is_newer("2.1.0", Some("garbage")));
}

#[test]
fn the_package_must_be_ours_this_architecture_the_signed_version_and_newer() {
    let ok = Fields { package: "linvpn".into(), version: "2.1.0".into(), architecture: "amd64".into() };
    assert_eq!(deb_update::check(&ok, "2.1.0", "amd64", Some("2.0.5")), Ok(()));
    let other = Fields { package: "evil".into(), ..ok.clone() };
    assert_eq!(deb_update::check(&other, "2.1.0", "amd64", None), Err(StepError::WrongPackage));
    assert_eq!(deb_update::check(&ok, "2.1.0", "arm64", None), Err(StepError::WrongArchitecture));
    assert_eq!(deb_update::check(&ok, "2.1.1", "amd64", None), Err(StepError::WrongVersion));
    assert_eq!(deb_update::check(&ok, "2.1.0", "amd64", Some("2.1.0")), Err(StepError::NotNewer));
}

#[test]
fn nothing_installed_is_refused_never_a_free_pass() {
    // The root step ships inside the installed `linvpn`: "not installed" can only mean something is wrong (LA-2).
    let ok = Fields { package: "linvpn".into(), version: "2.1.0".into(), architecture: "amd64".into() };
    assert_eq!(deb_update::check(&ok, "2.1.0", "amd64", None), Err(StepError::NotInstalled));
    assert_eq!(StepError::NotInstalled.code(), 20);
    assert_eq!(StepError::from_code(20), Some(StepError::NotInstalled));
}

#[test]
fn dpkg_querys_status_and_version() {
    assert_eq!(deb_update::parse_installed("installed 2.0.5"), Ok(Some("2.0.5".into())));
    assert_eq!(deb_update::parse_installed("installed 2.0.5\n"), Ok(Some("2.0.5".into())));
    for gone in ["config-files 2.0.5", "not-installed ", "not-installed", "half-installed 2.0.5", "unpacked 2.0.5"] {
        assert_eq!(deb_update::parse_installed(gone), Ok(None), "{gone:?}");
    }
    for garbage in ["", "installed", "installed ", "2.0.5", "installed 2.0.5 extra", "installed 2.0.5\ninstalled 2.0.6"]
    {
        assert_eq!(deb_update::parse_installed(garbage), Err(StepError::ToolFailed), "{garbage:?}");
    }
}

#[test]
fn the_existing_exit_codes_stay() {
    let expected = [
        (StepError::BadArguments, 10),
        (StepError::NotRoot, 11),
        (StepError::UnsafeFile, 12),
        (StepError::BadSignature, 13),
        (StepError::WrongPackage, 14),
        (StepError::WrongArchitecture, 15),
        (StepError::WrongVersion, 16),
        (StepError::NotNewer, 17),
        (StepError::ToolFailed, 18),
        (StepError::InstallFailed, 19),
        (StepError::NotInstalled, 20),
    ];
    assert_eq!(StepError::ALL.len(), expected.len());
    for (e, code) in expected {
        assert_eq!(e.code(), code, "{e:?}");
    }
}

#[test]
fn step_arguments_exactly() {
    let args: Vec<String> = [
        "--deb",
        "/home/a/.cache/LinVPN/updates/linvpn_2.1.0_amd64.deb",
        "--sig",
        "/home/a/.cache/LinVPN/updates/linvpn_2.1.0_amd64.deb.sig",
        "--version",
        "2.1.0",
        "--asset",
        "linvpn_2.1.0_amd64.deb",
    ]
    .map(String::from)
    .to_vec();
    assert_eq!(
        deb_update::parse_step_args(&args),
        Some(StepArgs {
            deb: PathBuf::from("/home/a/.cache/LinVPN/updates/linvpn_2.1.0_amd64.deb"),
            sig: PathBuf::from("/home/a/.cache/LinVPN/updates/linvpn_2.1.0_amd64.deb.sig"),
            version: "2.1.0".into(),
            asset: "linvpn_2.1.0_amd64.deb".into(),
        })
    );
    assert_eq!(deb_update::parse_step_args(&args[..7]), None);
    let mut relative = args.clone();
    relative[1] = "linvpn.deb".into();
    assert_eq!(deb_update::parse_step_args(&relative), None);
    for not_unix_absolute in [r"C:\\linvpn.deb", r"\\server\\linvpn.deb", "./linvpn.deb", ""] {
        let mut other = args.clone();
        other[3] = not_unix_absolute.into();
        assert_eq!(deb_update::parse_step_args(&other), None, "{not_unix_absolute:?}");
    }
    let mut extra = args.clone();
    extra.push("--force".into());
    assert_eq!(deb_update::parse_step_args(&extra), None);
}

#[test]
fn exit_codes_are_distinct_and_never_pkexecs() {
    let codes: Vec<i32> = StepError::ALL.iter().map(|e| e.code()).collect();
    let mut unique = codes.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), codes.len());
    assert!(codes.iter().all(|c| (10..=40).contains(c)), "never 0, 126 or 127 (pkexec's own)");
}
