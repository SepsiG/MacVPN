//! WinVPN's update check without the network (every OS): the update source an installed WinVPN names, and the
//! `releases/latest` answer read with WinVPN's MSI for this machine. A fake HTTP client plays GitHub.

use macvpn_core::update::UpdateChecker;
use macvpn_platform_api::WINVPN;
use macvpn_platform_api::curl::http::{HttpClient, HttpError, HttpResponse};
use macvpn_platform_win::pure::update_check::{self as uc, UPDATE_REPO_ID};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[test]
fn an_installed_winvpn_names_the_one_repository_by_id_and_name() {
    let info = uc::update_info();
    assert_eq!(UpdateChecker::source_from_info(Some(&info)), Some((UPDATE_REPO_ID, "SepsiG/MacVPN".to_string())));
    assert_eq!(UPDATE_REPO_ID, 1_422_472_799);
}

#[test]
fn the_update_source_matches_the_info_plist() {
    let plist =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../app/src-tauri/Info.plist")).unwrap();
    assert!(plist.contains(&format!("<string>{}</string>", WINVPN.repo)));
    assert!(plist.contains(&format!("<string>{UPDATE_REPO_ID}</string>")));
}

struct FakeGitHub {
    status: i64,
    body: String,
    asked: Mutex<Vec<String>>,
}

impl HttpClient for FakeGitHub {
    fn get(&self, url: &str) -> Result<HttpResponse, HttpError> {
        self.asked.lock().unwrap().push(url.to_string());
        Ok(HttpResponse::new(self.status, self.body.as_bytes()))
    }

    fn download(&self, _url: &str) -> Result<(PathBuf, i64), HttpError> {
        unreachable!("the check never downloads")
    }
}

fn release_json(tag: &str, assets: &[&str]) -> String {
    let assets: Vec<String> = assets
        .iter()
        .map(|name| {
            format!(
                r#"{{"name":"{name}","browser_download_url":"https://github.com/SepsiG/MacVPN/releases/download/{tag}/{name}"}}"#
            )
        })
        .collect();
    format!(
        r#"{{"tag_name":"{tag}","name":"WinVPN {tag}","body":"","html_url":"https://github.com/SepsiG/MacVPN/releases/tag/{tag}","published_at":"2026-10-01T10:00:00Z","assets":[{}]}}"#,
        assets.join(",")
    )
}

#[test]
fn the_check_asks_github_by_repository_id_and_takes_this_machines_msi() {
    let body = release_json(
        "v1.6.0",
        &[
            "MacVPN-1.6.0.dmg",
            "WinVPN-1.6.0-x64.msi",
            "WinVPN-1.6.0-x64.msi.sha256",
            "WinVPN-1.6.0-x64.msi.sig",
            "WinVPN-1.6.0-arm64.msi",
            "WinVPN-1.6.0-arm64.msi.sha256",
            "WinVPN-1.6.0-arm64.msi.sig",
        ],
    );
    let github = FakeGitHub { status: 200, body, asked: Mutex::default() };
    let release = uc::latest_release(&github, UPDATE_REPO_ID, "SepsiG/MacVPN", "x86_64").unwrap();
    assert_eq!(*github.asked.lock().unwrap(), ["https://api.github.com/repositories/1422472799/releases/latest"]);
    assert_eq!(release.version, "1.6.0");
    assert!(release.package.url.ends_with("/WinVPN-1.6.0-x64.msi"), "{}", release.package.url);

    let arm = uc::latest_release(&github, UPDATE_REPO_ID, "SepsiG/MacVPN", "aarch64").unwrap();
    assert!(arm.package.url.ends_with("/WinVPN-1.6.0-arm64.msi"), "{}", arm.package.url);
}

#[test]
fn a_failed_answer_is_a_message_not_a_release() {
    let github = FakeGitHub { status: 404, body: String::new(), asked: Mutex::default() };
    assert!(uc::latest_release(&github, UPDATE_REPO_ID, "SepsiG/MacVPN", "x86_64").is_err());
    let no_msi =
        FakeGitHub { status: 200, body: release_json("v1.6.0", &["MacVPN-1.6.0.dmg"]), asked: Mutex::default() };
    assert!(uc::latest_release(&no_msi, UPDATE_REPO_ID, "SepsiG/MacVPN", "x86_64").is_err());
}

#[test]
fn an_unsigned_release_of_this_machine_has_no_signature() {
    let arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        _ => "x64",
    };
    let msi = format!("WinVPN-1.6.0-{arch}.msi");
    let sha = format!("{msi}.sha256");
    let github = FakeGitHub { status: 200, body: release_json("v1.6.0", &[&msi, &sha]), asked: Mutex::default() };
    let release = uc::latest_release(&github, UPDATE_REPO_ID, "SepsiG/MacVPN", std::env::consts::ARCH).unwrap();
    assert_eq!(*github.asked.lock().unwrap(), ["https://api.github.com/repositories/1422472799/releases/latest"]);
    assert_eq!(release.package.name, msi);
    assert!(release.signature.is_none());
}
