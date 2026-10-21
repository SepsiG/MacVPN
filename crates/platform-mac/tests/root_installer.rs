//! Port of `RootInstallerTests.swift` (`RootInstallerTests`, `RootUninstallerTests`, `RootInstallerTempTests`).
//! Root layer 7 (and 8, the config-on-stdin layer) installs the single `mvpn` + `VERSION` and removes the earlier
//! layers' files.
#![cfg(target_os = "macos")]

mod common;

use common::{Scratch, assert_bash_syntax, chmod, getuid, mode, run_bash_file_merged};
use macvpn_core::l10n::AppLanguage;
use macvpn_platform_mac::brew::shell_quote;
use macvpn_platform_mac::command::CommandResult;
use macvpn_platform_mac::root_installer::{
    OBSOLETE_ROOT_FILES, ROOT_FILES, ROOT_INSTALL_TIMEOUT, ROOT_SHELL, apple_script, file_hashes, install_script,
    install_with, root_install_runner, sudoers_lines, uninstall_script, uninstall_with, untrusted_mvpn_message,
};
use macvpn_platform_mac::testing::{FixedRunner, MockCommandRunner};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

/// The owner part of the installed-`mvpn` trust check; the sandboxes let the testing user count as root.
const MVPN_OWNER_CHECK: &str = r#"[ "$(stat -f %u "$MVPN")" != 0 ]"#;

fn fake_hashes() -> BTreeMap<String, String> {
    ROOT_FILES.iter().map(|n| (n.to_string(), "a".repeat(64))).collect()
}

fn lang(l: AppLanguage) {
    AppLanguage::set_thread_override(Some(l));
}

#[test]
fn script_contents() {
    lang(AppLanguage::En);
    let s =
        install_script(Path::new("/Applications/MacVPN.app/Contents/Resources/root"), "alice", &fake_hashes()).unwrap();
    let a64 = "a".repeat(64);
    assert!(s.contains(&format!("stage '/Applications/MacVPN.app/Contents/Resources/root/mvpn' mvpn {a64}")));
    assert!(s.contains("install -o root -g wheel -m 755 \"$STAGE/mvpn\" \"$DIR/mvpn\""));
    assert!(s.contains("install -o root -g wheel -m 644 \"$STAGE/VERSION\" \"$DIR/VERSION\""));
    assert!(s.contains("DIR=/usr/local/libexec/macvpn"));
    assert!(s.contains("'alice ALL=(root) NOPASSWD: /usr/local/libexec/macvpn/mvpn'"));
    // Layer 7: no separate validator, bridge or DNS hook any more; their files are removed.
    for old in ["mvpn-validate", "mvpn-mgmt", "ovpn-dns"] {
        assert!(!s.contains(&format!("\"$STAGE/{old}\"")), "{old}");
    }
    assert!(s.contains("rm -f -- \"$DIR/ovpn-dns\" \"$DIR/mvpn-validate\" \"$DIR/mvpn-mgmt\"\n"));
    assert!(s.contains("visudo -c -f"));
    assert!(s.contains("install -o root -g wheel -m 440"));
    assert!(s.starts_with("#!/bin/bash\nset -euo pipefail\n"));
    assert!(s.contains("shasum -a 256"));
    // Every file is verified before anything is installed.
    let last_stage = s.find("stage '/Applications/MacVPN.app/Contents/Resources/root/VERSION'").unwrap();
    let first_install = s.find("install -o root").unwrap();
    assert!(last_stage < first_install);
    // The old files go only after the new binary is in place.
    assert!(s.find("\"$DIR/VERSION\"").unwrap() < s.find("rm -f --").unwrap());
    assert_bash_syntax(&s);
}

#[test]
fn script_requires_all_hashes() {
    for name in ROOT_FILES {
        let mut hashes = fake_hashes();
        hashes.remove(name);
        assert!(install_script(Path::new("/x"), "bob", &hashes).is_err(), "{name}");
        hashes.insert(name.to_string(), "not-a-hash".into());
        assert!(install_script(Path::new("/x"), "bob", &hashes).is_err(), "{name}");
        hashes.insert(name.to_string(), "A".repeat(64));
        assert!(install_script(Path::new("/x"), "bob", &hashes).is_err(), "upper case: {name}");
    }
}

#[test]
fn file_hashes_of_the_root_files() {
    let dir = make_root_source();
    let hashes = file_hashes(dir.path()).unwrap();
    assert_eq!(hashes["VERSION"], "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a"); // "4"
    assert_eq!(hashes.keys().cloned().collect::<Vec<_>>(), ["VERSION", "mvpn"]);
    std::fs::remove_file(dir.join("mvpn")).unwrap();
    assert!(file_hashes(dir.path()).is_err());
}

/// The sudoers lines pass the real `visudo -c` (no root needed).
#[test]
fn sudoers_lines_pass_visudo() {
    let lines = sudoers_lines("alice");
    assert_eq!(
        lines,
        [
            "alice ALL=(root) NOPASSWD: /usr/local/libexec/macvpn/mvpn",
            "Defaults!/usr/local/libexec/macvpn/mvpn env_reset, !env_keep",
            "Defaults!/usr/local/libexec/macvpn/mvpn env_delete += \"LANG LANGUAGE LC_* CHARSET\"",
        ]
    );
    let dir = Scratch::new("macvpn-sudoers");
    let path = dir.join("sudoers");
    std::fs::write(&path, lines.join("\n") + "\n").unwrap();
    let out = Command::new("/usr/sbin/visudo").arg("-c").arg("-f").arg(&path).output().unwrap();
    assert!(out.status.success(), "{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
}

/// The two root files in a temporary directory (VERSION is "4").
fn make_root_source() -> Scratch {
    let dir = Scratch::new("macvpn-rootsrc");
    for name in ROOT_FILES {
        let content = if name == "VERSION" { "4".to_string() } else { format!("#!/bin/bash\n# {name}\n") };
        std::fs::write(dir.join(name), content).unwrap();
    }
    dir
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ParentState {
    Safe,
    Writable,
    ForeignOwner,
    Symlink,
}

/// The installer script in a sandbox (not as root): the system paths point into the sandbox, setting the root
/// owner (`-o root -g wheel`, `chown`) is dropped / becomes `echo CHOWN`. For `Safe` / `Writable` the testing user
/// counts as "root" (uid swap in the owner check), for `ForeignOwner` not. Our own `macvpn` directory exists with
/// 0777 (the script fixes it), and holds the files of a layer 6 install.
fn run_install_sandbox(tamper: bool, parent: ParentState) -> (i32, String, Scratch) {
    run_install_sandbox_with(tamper, parent, None)
}

/// An installed older layer in the sandbox (`version`; the layer 6 files are there too): a fake old `mvpn` that
/// records each call together with the state of the files at that moment, and (optionally) run directories of
/// active connections.
struct OldLayer<'a> {
    run_dirs: bool,
    failing_id: Option<&'a str>,
    version: &'a str,
}

const GOOD_ID: &str = "11111111-2222-3333-4444-555555555555";
const OTHER_ID: &str = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE";

fn run_install_sandbox_with(tamper: bool, parent: ParentState, old: Option<OldLayer>) -> (i32, String, Scratch) {
    run_install_sandbox_full(tamper, parent, old, false)
}

/// `via_osascript`: run the exact osascript command line (inline script), only without administrator rights.
fn run_install_sandbox_full(
    tamper: bool,
    parent: ParentState,
    old: Option<OldLayer>,
    via_osascript: bool,
) -> (i32, String, Scratch) {
    let src = make_root_source();
    let root = Scratch::new("macvpn-install");
    for d in ["usr", "var/run", "var/log", "etc/sudoers.d"] {
        std::fs::create_dir_all(root.join(d)).unwrap();
    }
    let local = root.join("usr/local");
    if parent == ParentState::Symlink {
        std::os::unix::fs::symlink(std::env::temp_dir(), &local).unwrap();
    } else {
        let own = local.join("libexec/macvpn");
        std::fs::create_dir_all(&own).unwrap();
        for old in OBSOLETE_ROOT_FILES {
            std::fs::write(own.join(old), "#!/bin/bash\n").unwrap();
        }
        if let Some(old) = &old {
            std::fs::write(own.join("VERSION"), old.version).unwrap();
            let calls = root.join("calls");
            std::fs::write(
                own.join("mvpn"),
                format!(
                    "#!/bin/bash\nD=$(/usr/bin/dirname \"$0\")\necho \"$SUDO_USER $* | VERSION=$(cat \"$D/VERSION\") ovpn-dns=$([ -e \"$D/ovpn-dns\" ] && echo yes || echo no) sudoers=$([ -e {sudoers} ] && echo yes || echo no)\" >> {calls}\n[ \"$3\" = \"{fail}\" ] && exit 1\nexit 0\n",
                    sudoers = shell_quote(&root.join("etc/sudoers.d/macvpn").to_string_lossy()),
                    calls = shell_quote(&calls.to_string_lossy()),
                    fail = old.failing_id.unwrap_or("-"),
                ),
            )
            .unwrap();
            chmod(&own.join("mvpn"), 0o755);
            if old.run_dirs {
                let run = root.join("var/run/macvpn");
                for (dir, kind) in [
                    (GOOD_ID, "openvpn"),
                    (OTHER_ID, "wireguard"),
                    ("notauuid", "openvpn"),
                    ("99999999-2222-3333-4444-555555555555", "evil;rm"),
                ] {
                    std::fs::create_dir_all(run.join(dir)).unwrap();
                    std::fs::write(run.join(dir).join("kind"), format!("{kind}\n")).unwrap();
                }
            }
        }
        chmod(&local, if parent == ParentState::Writable { 0o777 } else { 0o755 });
        chmod(&local.join("libexec"), 0o755);
        chmod(&own, 0o777);
    }
    let hashes = file_hashes(src.path()).unwrap();
    if tamper {
        std::fs::write(src.join("mvpn"), "#!/bin/bash\nid\n").unwrap();
    }
    let r = root.path().to_string_lossy().into_owned();
    let uid = if parent == ParentState::ForeignOwner { 0 } else { getuid() };
    let script = install_script(src.path(), "bob", &hashes)
        .unwrap()
        .replace("-o root -g wheel ", "")
        .replace(r#"chown root:wheel "$1""#, r#"echo CHOWN "$1""#)
        .replace("/usr/local", &format!("{r}/usr/local"))
        .replace("/var/run/", &format!("{r}/var/run/"))
        .replace("/var/log/", &format!("{r}/var/log/"))
        .replace("/etc/sudoers.d/", &format!("{r}/etc/sudoers.d/"))
        .replace(r#"[ "$(stat -f %u "$1")" != 0 ]"#, &format!(r#"[ "$(stat -f %u "$1")" != {uid} ]"#))
        .replace(MVPN_OWNER_CHECK, &MVPN_OWNER_CHECK.replace("!= 0", &format!("!= {uid}")));
    if via_osascript {
        let (ok, stdout, stderr) = run_apple_script_unprivileged(&script);
        return (if ok { 0 } else { 1 }, stdout + &stderr, root);
    }
    let path = root.join("install.sh");
    std::fs::write(&path, script).unwrap();
    let (status, output) = run_bash_file_merged(&path);
    (status, output, root)
}

#[test]
fn install_sandbox_verifies_and_installs() {
    lang(AppLanguage::En);
    let (status, output, root) = run_install_sandbox(false, ParentState::Safe);
    assert_eq!(status, 0, "{output}");
    let dir = root.join("usr/local/libexec/macvpn");
    assert_eq!(std::fs::read_to_string(dir.join("VERSION")).unwrap(), "4");
    assert!(macvpn_platform_mac_is_executable(&dir.join("mvpn")));
    // The earlier layers' files are gone.
    for old in OBSOLETE_ROOT_FILES {
        assert!(!dir.join(old).exists(), "{old}");
    }
    // Only our own (0777) macvpn directory is fixed; the parents are not touched.
    assert_eq!(output.matches("CHOWN").count(), 1, "{output}");
    assert!(output.contains(&format!("CHOWN {}\n", dir.display())), "{output}");
    assert_eq!(mode(&dir) & 0o022, 0);
    let sudoers = std::fs::read_to_string(root.join("etc/sudoers.d/macvpn")).unwrap();
    assert!(sudoers.contains("env_reset, !env_keep"), "{sudoers}");
    assert!(sudoers.contains("bob ALL=(root) NOPASSWD:"), "{sudoers}");
    // The staging directory is deleted.
    let leftovers: Vec<String> = std::fs::read_dir(root.join("var/run"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(!leftovers.iter().any(|n| n.starts_with("macvpn-install.")), "{leftovers:?}");
}

fn macvpn_platform_mac_is_executable(p: &Path) -> bool {
    mode(p) & 0o111 != 0
}

fn recorded_calls(root: &Scratch) -> Vec<String> {
    let mut calls: Vec<String> =
        std::fs::read_to_string(root.join("calls")).unwrap_or_default().lines().map(str::to_string).collect();
    calls.sort();
    calls
}

/// The running connections are taken down with the old `mvpn`, while the old layer is still complete (its
/// VERSION, its ovpn-dns, no new sudoers yet), and only then is anything replaced.
#[test]
fn install_takes_connections_down_with_the_old_layer_first() {
    lang(AppLanguage::Hu);
    let (status, output, root) = run_install_sandbox_with(
        false,
        ParentState::Safe,
        Some(OldLayer { run_dirs: true, failing_id: None, version: "6" }),
    );
    assert_eq!(status, 0, "{output}");
    assert_eq!(
        recorded_calls(&root),
        [
            format!("bob down openvpn {GOOD_ID} --lang hu | VERSION=6 ovpn-dns=yes sudoers=no"),
            format!("bob down wireguard {OTHER_ID} --lang hu | VERSION=6 ovpn-dns=yes sudoers=no"),
        ]
    );
    let dir = root.join("usr/local/libexec/macvpn");
    assert_eq!(std::fs::read_to_string(dir.join("VERSION")).unwrap(), "4");
    assert_eq!(std::fs::read_to_string(dir.join("mvpn")).unwrap(), "#!/bin/bash\n# mvpn\n");
    assert!(!dir.join("ovpn-dns").exists());
    // In the script: the loop comes after the verified staging and before the first replacement.
    let s = install_script(Path::new("/x"), "bob", &fake_hashes()).unwrap();
    let down = s.find("\"$MVPN\" down \"$kind\" \"$id\"").unwrap();
    assert!(s.find("stage '/x/VERSION'").unwrap() < down);
    assert!(down < s.find("if [ -n \"$FAILED\" ]; then").unwrap());
    assert!(
        s.find("if [ -n \"$FAILED\" ]; then").unwrap()
            < s.find("install -o root -g wheel -m 755 \"$STAGE/mvpn\"").unwrap()
    );
    assert!(s.contains("MVPN='/usr/local/libexec/macvpn/mvpn'\nRUN_BASE=/var/run/macvpn\n"));
    assert!(s.contains(
        r#"[[ "$id" =~ ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$ ]] || continue"#
    ));
    assert!(s.contains("case \"$kind\" in openvpn|wireguard|strongswan|sstp) ;; *) continue ;; esac"));
}

/// 7 → 8 (root 8 takes the config on stdin): the running connections are taken down with the installed layer 7
/// (`down` reads no config, so the old layer can do it), then the bundled layer replaces it.
#[test]
fn upgrade_from_layer_7_takes_connections_down_with_it() {
    lang(AppLanguage::En);
    let (status, output, root) = run_install_sandbox_with(
        false,
        ParentState::Safe,
        Some(OldLayer { run_dirs: true, failing_id: None, version: "7" }),
    );
    assert_eq!(status, 0, "{output}");
    assert_eq!(
        recorded_calls(&root),
        [
            format!("bob down openvpn {GOOD_ID} --lang en | VERSION=7 ovpn-dns=yes sudoers=no"),
            format!("bob down wireguard {OTHER_ID} --lang en | VERSION=7 ovpn-dns=yes sudoers=no"),
        ]
    );
    let dir = root.join("usr/local/libexec/macvpn");
    assert_eq!(std::fs::read_to_string(dir.join("VERSION")).unwrap(), "4", "the bundled (sandbox) VERSION");
    assert_eq!(std::fs::read_to_string(dir.join("mvpn")).unwrap(), "#!/bin/bash\n# mvpn\n");
}

/// A connection the old layer cannot take down: nothing is replaced, and the app shows a localized error.
#[test]
fn install_aborts_when_a_connection_cannot_be_disconnected() {
    for (l, line, message) in [
        (AppLanguage::En, "Could not disconnect:", "A connection could not be disconnected, installation cancelled."),
        (AppLanguage::Hu, "Nem bontható kapcsolat:", "Egy kapcsolat nem bontható, a telepítés megszakítva."),
    ] {
        lang(l);
        let (status, output, root) = run_install_sandbox_with(
            false,
            ParentState::Safe,
            Some(OldLayer { run_dirs: true, failing_id: Some(OTHER_ID), version: "6" }),
        );
        assert_eq!(status, 1, "{output}");
        assert!(output.contains(&format!("{line} {OTHER_ID}")), "{output}");
        assert_eq!(recorded_calls(&root).len(), 2, "both are tried");
        let dir = root.join("usr/local/libexec/macvpn");
        assert_eq!(std::fs::read_to_string(dir.join("VERSION")).unwrap(), "6", "the old layer stays");
        assert!(std::fs::read_to_string(dir.join("mvpn")).unwrap().contains("SUDO_USER"));
        for old in OBSOLETE_ROOT_FILES {
            assert!(dir.join(old).exists(), "{old}");
        }
        assert!(!root.join("etc/sudoers.d/macvpn").exists());

        // The same stderr through osascript becomes the localized message.
        let failing = FixedRunner(CommandResult::new(1, "", &format!("0:120: execution error: {line} {OTHER_ID} (1)")));
        let src = make_root_source();
        let msg = install_with(src.path(), "bob", &failing).unwrap_err().to_string();
        assert!(msg.starts_with(message), "{msg}");
        assert!(msg.contains(OTHER_ID), "{msg}");
    }
}

/// No run directories (or no old layer at all): the old `mvpn` is never called, the install goes on.
#[test]
fn install_without_running_connections_calls_nothing() {
    lang(AppLanguage::En);
    let (status, output, root) = run_install_sandbox_with(
        false,
        ParentState::Safe,
        Some(OldLayer { run_dirs: false, failing_id: None, version: "6" }),
    );
    assert_eq!(status, 0, "{output}");
    assert!(recorded_calls(&root).is_empty());
    assert_eq!(std::fs::read_to_string(root.join("usr/local/libexec/macvpn/VERSION")).unwrap(), "4");
    // A first install (no old mvpn): nothing to call either.
    let (status, output, root) = run_install_sandbox(false, ParentState::Safe);
    assert_eq!(status, 0, "{output}");
    assert!(recorded_calls(&root).is_empty());
}

#[test]
fn upgrade_notice_is_localized() {
    use macvpn_platform_mac::root_installer::upgrade_disconnect_notice;
    lang(AppLanguage::En);
    assert_eq!(upgrade_disconnect_notice(), "Updating the system component will disconnect active VPN connections.");
    lang(AppLanguage::Hu);
    assert_eq!(upgrade_disconnect_notice(), "A rendszerkomponens frissítése bontja az aktív VPN-kapcsolatokat.");
}

#[test]
fn install_script_creates_missing_parents_root_owned() {
    lang(AppLanguage::En);
    let s = install_script(Path::new("/x"), "bob", &fake_hashes()).unwrap();
    assert!(s.contains(r#"install -d -o root -g wheel -m 755 "$1""#));
    assert!(s.contains("check_dir /usr/local '"));
    assert!(s.contains("check_dir /usr/local/libexec '"));
    assert!(s.contains(r#"check_dir "$DIR" """#));
}

#[test]
fn install_sandbox_refuses_unsafe_parents() {
    for (state, l) in [
        (ParentState::Writable, AppLanguage::En),
        (ParentState::ForeignOwner, AppLanguage::En),
        (ParentState::Writable, AppLanguage::Hu),
    ] {
        lang(l);
        let (status, output, root) = run_install_sandbox(false, state);
        let local = format!("{}/usr/local", root.path().display());
        assert_eq!(status, 1, "{output}");
        assert!(!output.contains("CHOWN"), "{output}");
        if l == AppLanguage::En {
            assert!(output.contains(&format!("Installation cancelled: {local} is not owned by root or is writable by other users, so anything running as that user could replace the MacVPN root scripts.")), "{output}");
            assert!(
                output.contains(&format!(
                    "sudo chown root:wheel {local} && sudo chmod go-w {local} (on Intel Macs this may affect Homebrew)"
                )),
                "{output}"
            );
        } else {
            assert!(
                output.contains(&format!("A telepítés megszakítva: a(z) {local} nem a root tulajdona")),
                "{output}"
            );
            assert!(output.contains("(Intel Macen ez érintheti a Homebrew-t)"), "{output}");
        }
        assert!(!Path::new(&format!("{local}/libexec/macvpn/mvpn")).exists());
        // Nothing removed either.
        assert!(Path::new(&format!("{local}/libexec/macvpn/mvpn-mgmt")).exists());
        assert!(!root.join("etc/sudoers.d/macvpn").exists());
        assert_eq!(
            mode(Path::new(&local)),
            if state == ParentState::Writable { 0o777 } else { 0o755 },
            "the parent is untouched"
        );
    }
}

#[test]
fn install_sandbox_rejects_tampered_file() {
    lang(AppLanguage::En);
    let (status, output, root) = run_install_sandbox(true, ParentState::Safe);
    assert_eq!(status, 1, "{output}");
    assert!(output.contains("Integrity check failed, installation cancelled: mvpn"), "{output}");
    assert!(!root.join("usr/local/libexec/macvpn/mvpn").exists());
    assert!(root.join("usr/local/libexec/macvpn/mvpn-mgmt").exists(), "the old layer stays usable");
    assert!(!root.join("etc/sudoers.d/macvpn").exists());
}

#[test]
fn install_sandbox_rejects_symlink_parent() {
    lang(AppLanguage::En);
    let (status, output, root) = run_install_sandbox(false, ParentState::Symlink);
    assert_eq!(status, 1, "{output}");
    assert!(
        output.contains(&format!("Unsafe directory, installation cancelled: {}/usr/local", root.path().display())),
        "{output}"
    );
}

#[test]
fn rejects_bad_user() {
    assert!(install_script(Path::new("/x"), "bob ALL=(ALL) ALL", &fake_hashes()).is_err());
    assert!(install_script(Path::new("/x"), "", &fake_hashes()).is_err());
    assert!(install_script(Path::new("/x"), "1bob", &fake_hashes()).is_err());
}

#[test]
fn apple_script_quotes_path() {
    // The root shell starts with an empty environment: BASH_ENV & co. of the app never reach it.
    let out = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(format!("{}-c 'echo \"[$BASH_ENV][$PATH][$LC_ALL]\"'", ROOT_SHELL))
        .env("BASH_ENV", "/tmp/evil")
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout), "[][/usr/bin:/bin:/usr/sbin:/sbin][C]\n");
    // The script text goes inline as an AppleScript string literal; the shell gets it single-quoted.
    assert_eq!(
        apple_script("echo \"a\\b\" 'c'\n\tx"),
        r#"do shell script "/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C /bin/bash -c " & quoted form of "echo \"a\\b\" 'c'\n\tx" with administrator privileges"#
    );
}

/// The exact AppleScript osascript gets, run without `with administrator privileges` (never as root): the text
/// survives the AppleScript literal and `quoted form of` byte for byte.
fn run_apple_script_unprivileged(script: &str) -> (bool, String, String) {
    let source = apple_script(script);
    let unprivileged = source.strip_suffix(" with administrator privileges").expect("admin suffix");
    let out = Command::new("/usr/bin/osascript").arg("-e").arg(unprivileged).output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn inline_script_round_trips_through_osascript() {
    let tricky =
        "#!/bin/bash\nprintf '%s|' \"a'b\" 'c\"d' 'e\\f' \"$PATH\" \"${BASH_ENV-unset}\" 'ű😀'\nprintf 'tab\\there'\n";
    let (ok, stdout, stderr) = run_apple_script_unprivileged(tricky);
    assert!(ok, "{stderr}");
    assert_eq!(stdout.trim_end(), "a'b|c\"d|e\\f|/usr/bin:/bin:/usr/sbin:/sbin|unset|ű😀|tab\there");
}

#[test]
fn install_passes_the_script_inline() {
    lang(AppLanguage::En);
    let runner = MockCommandRunner::new();
    let src = make_root_source();
    install_with(src.path(), "bob", &runner).unwrap();
    let call = &runner.calls()[0];
    assert_eq!(call.executable, "/usr/bin/osascript");
    assert_eq!(call.arguments.len(), 2);
    assert_eq!(call.arguments[0], "-e");
    let hashes = file_hashes(src.path()).unwrap();
    assert_eq!(call.arguments[1], apple_script(&install_script(src.path(), "bob", &hashes).unwrap()));
    assert!(call.arguments[1].contains("/bin/bash -c \" & quoted form of \"#!/bin/bash\\nset -euo pipefail\\n"));
    assert!(!call.arguments[1].contains("install.sh"), "no script file");
}

#[test]
fn install_failure_and_cancel_messages() {
    lang(AppLanguage::En);
    let src = make_root_source();
    let cancelled = FixedRunner(CommandResult::new(1, "", "execution error: User canceled. (-128)\n"));
    assert_eq!(install_with(src.path(), "bob", &cancelled).unwrap_err().to_string(), "Installation cancelled");
    let failed = FixedRunner(CommandResult::new(1, "", "0:1: execution error: visudo: parse error (1)\n"));
    assert_eq!(
        install_with(src.path(), "bob", &failed).unwrap_err().to_string(),
        "Installation error: 0:1: execution error: visudo: parse error (1)"
    );
}

// MARK: - Uninstaller

#[test]
fn uninstall_script_contents() {
    lang(AppLanguage::Hu);
    let s = uninstall_script("alice").unwrap();
    assert!(s.starts_with("#!/bin/bash\n"));
    // Taking down the running connections from the kind file, with a checked uuid and kind.
    assert!(s.contains("MVPN='/usr/local/libexec/macvpn/mvpn'"));
    assert!(s.contains("\"$RUN_BASE\"/*/"));
    assert!(s.contains(
        r#"[[ "$id" =~ ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$ ]] || continue"#
    ));
    assert!(s.contains("case \"$kind\" in openvpn|wireguard|strongswan|sstp) ;; *) continue ;; esac"));
    assert!(s.contains("if ! SUDO_USER='alice' \"$MVPN\" down \"$kind\" \"$id\" --lang hu </dev/null; then"));
    assert!(s.contains("FAILED=\"$FAILED $id\""));
    // A failed take-down exits before anything is deleted.
    let guard = s.find("if [ -n \"$FAILED\" ]; then").unwrap();
    let exit = guard + s[guard..].find("exit 1").unwrap();
    let first_rm = s.find("/bin/rm").unwrap();
    assert!(exit < first_rm);
    assert!(s.contains("echo 'Nem bontható kapcsolat:'\"$FAILED\" >&2"));
    // Deletion: after the take-down.
    let down = s.find("down \"$kind\"").unwrap();
    for path in
        ["/etc/sudoers.d/macvpn", "/usr/local/libexec/macvpn /var/run/macvpn /var/run/macvpn-ui /var/log/macvpn"]
    {
        assert!(s[down..].contains(path), "{path}");
    }
    assert!(s.contains("/bin/rm -f /etc/sudoers.d/macvpn"));
    assert!(s.contains("/bin/rm -rf /usr/local/libexec/macvpn /var/run/macvpn /var/run/macvpn-ui /var/log/macvpn"));
}

#[test]
fn uninstall_script_rejects_bad_user() {
    assert!(uninstall_script("x' ; rm -rf / ; '").is_err());
}

#[test]
fn uninstall_script_syntax() {
    assert_bash_syntax(&uninstall_script("bob").unwrap());
}

#[test]
fn uninstall_runs_via_osascript_and_cleans_up() {
    lang(AppLanguage::Hu);
    let runner = MockCommandRunner::new();
    uninstall_with("bob", &runner).unwrap();
    let call = &runner.calls()[0];
    assert_eq!(call.executable, "/usr/bin/osascript");
    let script = call.arguments.last().unwrap();
    assert!(script.ends_with("with administrator privileges"));
    assert_eq!(script, &apple_script(&uninstall_script("bob").unwrap()));
}

/// The script in a sandbox: a fake mvpn, a run directory, the deletions turned into `echo RM`.
fn run_uninstall_sandbox(
    failing_id: Option<&str>,
    ppp_marker: bool,
    ppp_content: Option<&str>,
) -> (i32, String, Vec<String>) {
    run_uninstall_sandbox_with(failing_id, ppp_marker, ppp_content, MvpnState::Trusted)
}

/// The installed `mvpn` in the sandbox: as installed, or in a state that must not be run as root.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum MvpnState {
    Trusted,
    Symlink,
    GroupWritable,
    WorldWritable,
    ForeignOwner,
}

fn run_uninstall_sandbox_with(
    failing_id: Option<&str>,
    ppp_marker: bool,
    ppp_content: Option<&str>,
    state: MvpnState,
) -> (i32, String, Vec<String>) {
    let root = Scratch::new("macvpn-uninstall");
    let run = root.join("run");
    let good = "11111111-2222-3333-4444-555555555555";
    let other = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE";
    for (dir, kind) in [
        (good, "openvpn"),
        (other, "wireguard"),
        ("notauuid", "openvpn"),
        ("99999999-2222-3333-4444-555555555555", "evil;rm"),
    ] {
        std::fs::create_dir_all(run.join(dir)).unwrap();
        std::fs::write(run.join(dir).join("kind"), format!("{kind}\n")).unwrap();
    }
    let ppp_options = root.join("ppp-options");
    let marker = root.join(".created-ppp-options");
    if let Some(content) = ppp_content {
        std::fs::write(&ppp_options, content).unwrap();
    }
    if ppp_marker {
        std::fs::write(&marker, "").unwrap();
    }
    let calls = root.join("calls");
    let mvpn = root.join("mvpn");
    std::fs::write(
        &mvpn,
        format!(
            "#!/bin/bash\necho \"$SUDO_USER $*\" >> {}\n[ \"$3\" = \"{}\" ] && exit 1\nexit 0\n",
            shell_quote(&calls.to_string_lossy()),
            failing_id.unwrap_or("-")
        ),
    )
    .unwrap();
    chmod(&mvpn, 0o755);
    let mvpn = match state {
        MvpnState::Symlink => {
            let link = root.join("mvpn-link");
            std::os::unix::fs::symlink(&mvpn, &link).unwrap();
            link
        }
        MvpnState::GroupWritable => {
            chmod(&mvpn, 0o775);
            mvpn
        }
        MvpnState::WorldWritable => {
            chmod(&mvpn, 0o757);
            mvpn
        }
        MvpnState::Trusted | MvpnState::ForeignOwner => mvpn,
    };
    let owner = if state == MvpnState::ForeignOwner { 0 } else { getuid() };
    let q = |p: &Path| shell_quote(&p.to_string_lossy());
    let script = uninstall_script("bob")
        .unwrap()
        .replace(MVPN_OWNER_CHECK, &MVPN_OWNER_CHECK.replace("!= 0", &format!("!= {owner}")))
        .replace("MVPN='/usr/local/libexec/macvpn/mvpn'", &format!("MVPN={}", q(&mvpn)))
        .replace("RUN_BASE=/var/run/macvpn", &format!("RUN_BASE={}", q(&run)))
        .replace("PPP_OPTIONS=/etc/ppp/options", &format!("PPP_OPTIONS={}", q(&ppp_options)))
        .replace("PPP_MARKER=/usr/local/libexec/macvpn/.created-ppp-options", &format!("PPP_MARKER={}", q(&marker)))
        .replace("/bin/rm", "echo RM");
    let path = root.join("u.sh");
    std::fs::write(&path, script).unwrap();
    let (status, output) = run_bash_file_merged(&path);
    let mut mvpn_calls: Vec<String> =
        std::fs::read_to_string(&calls).unwrap_or_default().lines().map(str::to_string).collect();
    mvpn_calls.sort();
    (status, output, mvpn_calls)
}

#[test]
fn uninstall_sandbox_success() {
    lang(AppLanguage::Hu);
    let (status, output, calls) = run_uninstall_sandbox(None, false, None);
    assert_eq!(status, 0, "{output}");
    assert_eq!(
        calls,
        [
            "bob down openvpn 11111111-2222-3333-4444-555555555555 --lang hu",
            "bob down wireguard AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE --lang hu"
        ]
    );
    assert!(output.contains("RM -f /etc/sudoers.d/macvpn"), "{output}");
    assert!(
        output.contains("RM -rf /usr/local/libexec/macvpn /var/run/macvpn /var/run/macvpn-ui /var/log/macvpn"),
        "{output}"
    );
}

/// /etc/ppp/options is deleted only with mvpn's marker, and only when empty.
#[test]
fn uninstall_ppp_options() {
    lang(AppLanguage::Hu);
    let (status, output, _) = run_uninstall_sandbox(None, true, Some(""));
    assert_eq!(status, 0, "{output}");
    assert!(output.contains("RM -f ") && output.contains("/ppp-options\n"), "{output}");
    for (marker, content) in [(false, Some("")), (true, Some("lock\n")), (true, None), (false, None)] {
        let (status, output, _) = run_uninstall_sandbox(None, marker, content);
        assert_eq!(status, 0, "{output}");
        assert!(!output.contains("ppp-options"), "{marker} {content:?}: {output}");
    }
    let s = uninstall_script("bob").unwrap();
    assert!(s.contains("PPP_OPTIONS=/etc/ppp/options"));
    assert!(s.contains("PPP_MARKER=/usr/local/libexec/macvpn/.created-ppp-options"));
    // The marker is in the root directory: deleting it (rm -rf on the directory) comes only after the ppp check.
    assert!(s.find("/bin/rm -f \"$PPP_OPTIONS\"").unwrap() < s.find("/bin/rm -rf /usr/local/libexec/macvpn").unwrap());
}

#[test]
fn uninstall_sandbox_failed_down_keeps_root_layer() {
    lang(AppLanguage::Hu);
    let (status, output, calls) = run_uninstall_sandbox(Some("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"), false, None);
    assert_eq!(status, 1);
    assert_eq!(calls.len(), 2);
    assert!(output.contains("Nem bontható kapcsolat: AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"), "{output}");
    assert!(!output.contains("RM"), "{output}");
}

#[test]
fn uninstall_down_failure_message() {
    lang(AppLanguage::Hu);
    let failing = FixedRunner(CommandResult::new(
        1,
        "",
        "0:120: execution error: Nem bontható kapcsolat: AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE (1)",
    ));
    let msg = uninstall_with("bob", &failing).unwrap_err().to_string();
    assert!(msg.starts_with("Egy kapcsolat nem bontható, az eltávolítás megszakítva"), "{msg}");
    assert!(msg.contains("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"), "{msg}");
}

#[test]
fn uninstall_cancelled() {
    lang(AppLanguage::Hu);
    let failing = FixedRunner(CommandResult::new(1, "", "execution error: User canceled. (-128)"));
    assert_eq!(uninstall_with("bob", &failing).unwrap_err().to_string(), "Az eltávolítás megszakítva");
}

/// An installed `mvpn` that is a symlink, group/world writable or not root's is never run as root: the down loop
/// is skipped with a message (here the testing user stands in for root, so "foreign" means uid 0's check fails).
#[test]
fn untrusted_installed_mvpn_is_not_executed() {
    for state in [MvpnState::Symlink, MvpnState::GroupWritable, MvpnState::WorldWritable, MvpnState::ForeignOwner] {
        lang(AppLanguage::En);
        let (status, output, calls) = run_uninstall_sandbox_with(None, false, None, state);
        assert!(calls.is_empty(), "{state:?}: {calls:?}");
        assert!(output.contains(&untrusted_mvpn_message()), "{state:?}: {output}");
        assert_eq!(status, 0, "{state:?}: {output}");
    }
    assert_eq!(
        untrusted_mvpn_message(),
        "The installed mvpn is not a protected root file, so running connections were not disconnected:"
    );
    lang(AppLanguage::Hu);
    assert!(untrusted_mvpn_message().starts_with("A telepített mvpn nem védett root fájl"));
    // The trusted one is run.
    let (status, output, calls) = run_uninstall_sandbox_with(None, false, None, MvpnState::Trusted);
    assert_eq!((status, calls.len()), (0, 2), "{output}");
    assert!(!output.contains("nem védett"), "{output}");
    // The check in the script: symlink, regular file, owner, mode.
    let s = install_script(Path::new("/x"), "bob", &fake_hashes()).unwrap();
    assert!(s.contains(r#"if [ -L "$MVPN" ] || [ ! -f "$MVPN" ] || [ "$(stat -f %u "$MVPN")" != 0 ] || [ $(( 0$(stat -f %Lp "$MVPN") & 022 )) != 0 ]; then"#));
}

/// The sudoers candidate is written inside the root-owned staging directory, not in a shared temp dir.
#[test]
fn sudoers_temp_file_is_in_the_staging_directory() {
    let s = install_script(Path::new("/x"), "bob", &fake_hashes()).unwrap();
    assert!(s.contains("TMP=$(mktemp \"$STAGE/sudoers.XXXXXX\")\n"));
    assert!(!s.contains("TMP=$(mktemp)"));
    assert!(s.find("STAGE=$(mktemp -d /var/run/macvpn-install.XXXXXX)").unwrap() < s.find("TMP=$(mktemp").unwrap());
}

/// The administrator run has its own, generous time limit (password prompt + every `mvpn down`).
#[test]
fn root_install_timeout() {
    assert_eq!(ROOT_INSTALL_TIMEOUT, 900.0);
    const { assert!(ROOT_INSTALL_TIMEOUT > macvpn_platform_mac::command::RunnerTimeouts::STANDARD) };
    assert_eq!(root_install_runner().timeout, ROOT_INSTALL_TIMEOUT);
}

/// The sandbox install through the real osascript command line (without admin rights): same results.
#[test]
fn install_sandbox_via_osascript_command_line() {
    lang(AppLanguage::En);
    let (status, output, root) = run_install_sandbox_full(
        false,
        ParentState::Safe,
        Some(OldLayer { run_dirs: true, failing_id: None, version: "6" }),
        true,
    );
    assert_eq!(status, 0, "{output}");
    assert_eq!(recorded_calls(&root).len(), 2);
    let dir = root.join("usr/local/libexec/macvpn");
    assert_eq!(std::fs::read_to_string(dir.join("VERSION")).unwrap(), "4");
    assert!(!dir.join("ovpn-dns").exists());
    assert!(std::fs::read_to_string(root.join("etc/sudoers.d/macvpn")).unwrap().contains("bob ALL=(root) NOPASSWD:"));
    let (status, output, root) = run_install_sandbox_full(true, ParentState::Safe, None, true);
    assert_eq!(status, 1, "{output}");
    assert!(output.contains("Integrity check failed, installation cancelled: mvpn"), "{output}");
    assert!(!root.join("usr/local/libexec/macvpn/mvpn").exists());
}
