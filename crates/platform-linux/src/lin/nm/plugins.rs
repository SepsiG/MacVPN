//! Which NM VPN plugins are installed (`/usr/lib/NetworkManager/VPN/*.name`, `/etc/NetworkManager/VPN`), LinVPN's
//! own OpenVPN service, OpenVPN's version, NM's version: the facts of System Status' NetworkManager rows. Read-only,
//! as the user; [`crate::pure::nm::plugins::report`] makes the rows.

use crate::lin::command::LinCommandRunner;
use crate::pure::nm::plugins::{self, Facts};
use macvpn_core::nm_plan::SERVICE_OPENVPN;
use macvpn_platform_api::curl::CommandRunner;
use std::fs;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Where NM looks for the plugins' `.name` files.
const NAME_DIRS: [&str; 2] = ["usr/lib/NetworkManager/VPN", "etc/NetworkManager/VPN"];
/// A larger `.name` file is not one (skipped).
const NAME_FILE_CAP: u64 = 64 * 1024;
/// LinVPN's OpenVPN service (Task 4): its `.name` file and its two programs.
const LINVPN_NAME_FILE: &str = "usr/lib/NetworkManager/VPN/nm-linvpn-openvpn-service.name";
const LINVPN_PROGRAMS: [&str; 2] =
    ["usr/lib/linvpn/nm-openvpn-service", "usr/lib/linvpn/nm-openvpn-service-openvpn-helper"];
/// strongSwan's EAP-MSCHAPv2 plugin (Ubuntu 26.04: `/usr/lib/ipsec/plugins`; the multiarch folders elsewhere).
const EAP_MSCHAPV2: [&str; 3] = [
    "usr/lib/ipsec/plugins/libstrongswan-eap-mschapv2.so",
    "usr/lib/x86_64-linux-gnu/ipsec/plugins/libstrongswan-eap-mschapv2.so",
    "usr/lib/aarch64-linux-gnu/ipsec/plugins/libstrongswan-eap-mschapv2.so",
];
/// strongSwan's EAP-Identity plugin, in the same folders.
const EAP_IDENTITY: [&str; 3] = [
    "usr/lib/ipsec/plugins/libstrongswan-eap-identity.so",
    "usr/lib/x86_64-linux-gnu/ipsec/plugins/libstrongswan-eap-identity.so",
    "usr/lib/aarch64-linux-gnu/ipsec/plugins/libstrongswan-eap-identity.so",
];
const OPENVPN: &str = "/usr/sbin/openvpn";
/// `openvpn --version` gets this long.
const OPENVPN_TIMEOUT_SECS: f64 = 2.0;

/// The facts of this system (`nm_version`: NM's `Version` property, `None` when NM is not on the bus).
pub fn facts(nm_version: Option<String>) -> Facts {
    let mut facts = facts_under(Path::new("/"), nm_version);
    facts.openvpn_version = openvpn_version();
    facts
}

/// The file facts under `root` (`/`, or a test's folder); `openvpn_version` stays `None`.
pub(crate) fn facts_under(root: &Path, nm_version: Option<String>) -> Facts {
    let mut services: Vec<String> =
        NAME_DIRS.iter().flat_map(|dir| name_files(&root.join(dir))).filter_map(|f| service_in(&f)).collect();
    services.sort();
    services.dedup();
    let linvpn_openvpn = service_in(&root.join(LINVPN_NAME_FILE)).as_deref() == Some(SERVICE_OPENVPN)
        && LINVPN_PROGRAMS.iter().all(|p| root_owned_program(&root.join(p)));
    let eap_mschapv2 = EAP_MSCHAPV2.iter().any(|p| root.join(p).is_file());
    let eap_identity = EAP_IDENTITY.iter().any(|p| root.join(p).is_file());
    Facts { nm_version, services, linvpn_openvpn, openvpn_version: None, eap_mschapv2, eap_identity }
}

/// The `*.name` files of `dir` (none if it cannot be read).
fn name_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else { return Vec::new() };
    entries.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|e| e == "name")).collect()
}

/// The `service=` of a `.name` file: a regular file of at most 64 KiB, else `None`.
fn service_in(path: &Path) -> Option<String> {
    let file = fs::File::open(path).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > NAME_FILE_CAP {
        return None;
    }
    let mut text = String::new();
    file.take(NAME_FILE_CAP + 1).read_to_string(&mut text).ok()?;
    plugins::service_of(&text)
}

/// A regular, executable file owned by root that neither group nor others can write (R9: NM runs it as root, so
/// anything else is not LinVPN's service). A symlink is not followed.
fn root_owned_program(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .is_ok_and(|m| m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0 && m.mode() & 0o111 != 0)
}

/// `openvpn --version`'s version, run as the user with `LC_ALL=C` and a 2 s limit (its exit code is not looked at:
/// OpenVPN 2.6 exits 1 after printing it).
fn openvpn_version() -> Option<String> {
    let runner = LinCommandRunner::new(OPENVPN_TIMEOUT_SECS);
    let result = runner.run(OPENVPN, &["--version".to_string()], None).ok()?;
    plugins::openvpn_version(&result.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn write(root: &Path, rel: &str, text: &str, mode: u32) {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, text).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn root(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("linvpn-plugins-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn name_files_of_both_folders_give_the_services() {
        let dir = root("names");
        write(
            &dir,
            "usr/lib/NetworkManager/VPN/nm-l2tp-service.name",
            "[VPN Connection]\nservice=org.freedesktop.NetworkManager.l2tp\n",
            0o644,
        );
        write(
            &dir,
            "etc/NetworkManager/VPN/nm-vpnc-service.name",
            "service=org.freedesktop.NetworkManager.vpnc\n",
            0o644,
        );
        write(&dir, "etc/NetworkManager/VPN/again.name", "service=org.freedesktop.NetworkManager.l2tp\n", 0o644);
        write(
            &dir,
            "usr/lib/NetworkManager/VPN/not-a-name-file.conf",
            "service=org.freedesktop.NetworkManager.sstp\n",
            0o644,
        );
        let big = format!("service=org.freedesktop.NetworkManager.sstp\n{}", "#".repeat(70 * 1024));
        write(&dir, "usr/lib/NetworkManager/VPN/big.name", &big, 0o644);
        write(&dir, "usr/lib/ipsec/plugins/libstrongswan-eap-mschapv2.so", "", 0o644);
        write(&dir, "usr/lib/x86_64-linux-gnu/ipsec/plugins/libstrongswan-eap-identity.so", "", 0o644);
        let f = facts_under(&dir, Some("1.54.3".into()));
        assert_eq!(f.services, ["org.freedesktop.NetworkManager.l2tp", "org.freedesktop.NetworkManager.vpnc"]);
        assert_eq!(f.nm_version.as_deref(), Some("1.54.3"));
        assert!(f.eap_mschapv2);
        assert!(f.eap_identity);
        assert!(!f.linvpn_openvpn);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn linvpns_service_owned_by_the_user_is_not_ours() {
        let dir = root("linvpn");
        write(&dir, LINVPN_NAME_FILE, "service=org.freedesktop.NetworkManager.linvpn-openvpn\n", 0o644);
        for p in LINVPN_PROGRAMS {
            write(&dir, p, "#!/bin/sh\n", 0o755);
        }
        let f = facts_under(&dir, None);
        assert!(f.services.iter().any(|s| s == SERVICE_OPENVPN));
        // The test runs as a user: the files are not root's, so fail closed (R9).
        assert_ne!(fs::metadata(&dir).unwrap().uid(), 0, "run the tests as a user");
        assert!(!f.linvpn_openvpn);
        assert!(!f.eap_mschapv2);
        assert!(!f.eap_identity);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn only_a_root_owned_executable_counts() {
        // `/usr/bin/env` may be a symlink (Ubuntu 26.04: to the Rust coreutils), which does not count itself.
        let env = fs::canonicalize("/usr/bin/env").unwrap();
        assert!(root_owned_program(&env), "{env:?}");
        if fs::symlink_metadata("/usr/bin/env").unwrap().file_type().is_symlink() {
            assert!(!root_owned_program(Path::new("/usr/bin/env")), "a symlink is not followed");
        }
        assert!(!root_owned_program(Path::new("/etc/passwd")), "not executable");
        assert!(!root_owned_program(Path::new("/nonexistent/linvpn")));
    }
}
