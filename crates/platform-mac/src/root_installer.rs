//! Installing and uninstalling the root layer (port of `RootInstaller.swift`), with one administrator prompt
//! (`osascript … with administrator privileges`).
//!
//! Root layer 7 is a single binary: the installer copies `mvpn` and `VERSION`, and removes the files of the
//! earlier layers (`ovpn-dns`, `mvpn-validate`, `mvpn-mgmt`); the uninstaller removes the whole directory.

use crate::brew::shell_quote;
use crate::command::{CommandError, CommandRunner, ProcessCommandRunner};
use crate::mvpn_client::{EXECUTABLE, INSTALL_DIR, LOG_DIR};
use crate::temp_dir::MessageError;
use macvpn_core::l10n::{self, AppLanguage, Arg};
use macvpn_core::mfa::AuthUIState;
use macvpn_core::swift_str;
use macvpn_core::update::sha256_hex;
use regex::Regex;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::LazyLock;

/// The root files to install (from the bundle's `Resources/root`).
pub const ROOT_FILES: [&str; 2] = ["mvpn", "VERSION"];
/// The executables of root layers 1–6, replaced by the single `mvpn`; the installer deletes them.
pub const OBSOLETE_ROOT_FILES: [&str; 3] = ["ovpn-dns", "mvpn-validate", "mvpn-mgmt"];

#[derive(Debug)]
pub enum InstallError {
    Message(String),
    Command(CommandError),
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstallError::Message(m) => f.write_str(m),
            InstallError::Command(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for InstallError {}

impl From<MessageError> for InstallError {
    fn from(e: MessageError) -> Self {
        InstallError::Message(e.0)
    }
}

static USER_NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z_][A-Za-z0-9_.-]*$").expect("valid regex"));
static SHA256_HEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9a-f]{64}$").expect("valid regex"));

/// The SHA-256 (lower-case hex) of the root files, computed right before the installer script is generated.
pub fn file_hashes(source_dir: &Path) -> Result<BTreeMap<String, String>, InstallError> {
    let mut hashes = BTreeMap::new();
    for name in ROOT_FILES {
        let path = source_dir.join(name);
        let data = std::fs::read(&path).map_err(|_| {
            InstallError::Message(l10n::tr("Cannot read the file: %@", &[Arg::Str(&path.to_string_lossy())]))
        })?;
        hashes.insert(name.to_string(), sha256_hex(&data));
    }
    Ok(hashes)
}

/// The sudoers lines. Defaults for `mvpn`: a clean environment (`env_reset`), none of the user's variables (LANG,
/// LC_* etc.) kept (`!env_keep`), and deleted even without env_reset (`env_delete`).
pub fn sudoers_lines(user: &str) -> Vec<String> {
    vec![
        format!("{user} ALL=(root) NOPASSWD: {EXECUTABLE}"),
        format!("Defaults!{EXECUTABLE} env_reset, !env_keep"),
        format!("Defaults!{EXECUTABLE} env_delete += \"LANG LANGUAGE LC_* CHARSET\""),
    ]
}

fn check_user(user: &str) -> Result<(), InstallError> {
    if USER_NAME.is_match(user) {
        Ok(())
    } else {
        Err(InstallError::Message(l10n::tr("Invalid user name: %@", &[Arg::Str(user)])))
    }
}

/// The installer script (runs as root, `osascript … with administrator privileges`).
/// 1. `/usr/local`, `/usr/local/libexec`, `/usr/local/libexec/macvpn`: a symlink or not a directory → abort;
///    missing → created root-owned. If either parent is not root-owned or is group/world writable → abort with
///    manual fix instructions (never rewritten: on Intel Macs it may be Homebrew's); our own `macvpn` directory is
///    fixed with `chown root:wheel` + `chmod go-w`.
/// 2. The source files are copied into a root-owned staging directory and installed (from there) only if their
///    SHA-256 matches `hashes` (computed by the app right before writing the script), so the user-writable source
///    cannot be swapped unnoticed between writing the script and the root run.
/// 3. The running connections are taken down with the installed (old) `mvpn`, exactly as the uninstaller does;
///    if any fails, the install stops before anything is replaced.
/// 4. The new files are installed, the files of the earlier layers are removed.
/// 5. sudoers: checked with `visudo -c -f`, then put in place.
pub fn install_script(
    source_dir: &Path,
    user: &str,
    hashes: &BTreeMap<String, String>,
) -> Result<String, InstallError> {
    check_user(user)?;
    let integrity = l10n::tr("Integrity check failed, installation cancelled:", &[]);
    let mut stage_lines = Vec::new();
    for name in ROOT_FILES {
        match hashes.get(name) {
            Some(hash) if SHA256_HEX.is_match(hash) => stage_lines
                .push(format!("stage {} {name} {hash}", shell_quote(&source_dir.join(name).to_string_lossy()))),
            _ => return Err(InstallError::Message(format!("{integrity} {name}"))),
        }
    }
    // The parents are never rewritten (on Intel Macs /usr/local/libexec may be Homebrew's): if they are not
    // root-owned or are group/world writable, the install stops with manual instructions. Only our own directory
    // is fixed.
    let parent_checks = ["/usr/local", "/usr/local/libexec"]
        .iter()
        .map(|d| {
            format!(
                "check_dir {d} {}",
                shell_quote(&l10n::tr(
                    "Installation cancelled: %@ is not owned by root or is writable by other users, so anything running as that user could replace the MacVPN root scripts. Fix it in Terminal, then try again: sudo chown root:wheel %@ && sudo chmod go-w %@ (on Intel Macs this may affect Homebrew).",
                    &[Arg::Str(d), Arg::Str(d), Arg::Str(d)],
                ))
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let sudoers = sudoers_lines(user).iter().map(|l| shell_quote(l)).collect::<Vec<_>>().join(" ");
    let obsolete = OBSOLETE_ROOT_FILES.iter().map(|f| format!("\"$DIR/{f}\"")).collect::<Vec<_>>().join(" ");
    let unsafe_message = shell_quote(&l10n::tr("Unsafe directory, installation cancelled:", &[]));
    let integrity = shell_quote(&integrity);
    let stage_lines = stage_lines.join("\n");
    let mvpn = shell_quote(EXECUTABLE);
    let down_loop = down_loop(user);
    let marker = shell_quote(&disconnect_failure_marker());
    Ok(format!(
        r#"#!/bin/bash
set -euo pipefail
export PATH=/usr/bin:/bin:/usr/sbin:/sbin
export LC_ALL=C
DIR={INSTALL_DIR}
TMP=""
STAGE=""
trap 'rm -rf "$STAGE" "$TMP"' EXIT
unsafe_dir() {{ [ "$(stat -f %u "$1")" != 0 ] || [ $(( 0$(stat -f %Lp "$1") & 022 )) != 0 ]; }}
check_dir() {{ # <könyvtár> <üzenet, ha nem root tulajdonú vagy group/world írható szülő>
  if [ -L "$1" ] || {{ [ -e "$1" ] && [ ! -d "$1" ]; }}; then
    echo {unsafe_message} "$1" >&2
    exit 1
  fi
  if [ ! -d "$1" ]; then
    install -d -o root -g wheel -m 755 "$1"
  elif unsafe_dir "$1"; then
    if [ -z "$2" ]; then
      chown root:wheel "$1"
      chmod go-w "$1"
    else
      echo "$2" >&2
      exit 1
    fi
  fi
}}
{parent_checks}
check_dir "$DIR" ""
STAGE=$(mktemp -d /var/run/macvpn-install.XXXXXX)
stage() {{
  cp -- "$1" "$STAGE/$2"
  if [ "$(shasum -a 256 "$STAGE/$2" | awk '{{print $1}}')" != "$3" ]; then
    echo {integrity} "$2" >&2
    exit 1
  fi
}}
{stage_lines}
# A futó kapcsolatokat a még telepített (régi) mvpn bontja, mielőtt bármit cserélnénk: így a régi réteg
# takarítása (pl. az ovpn-dns DNS-visszaállítása) a saját fájljaival fut le. Sikertelen bontásnál nincs csere.
MVPN={mvpn}
RUN_BASE=/var/run/macvpn
{down_loop}if [ -n "$FAILED" ]; then
  echo {marker}"$FAILED" >&2
  exit 1
fi
install -o root -g wheel -m 755 "$STAGE/mvpn" "$DIR/mvpn"
install -o root -g wheel -m 644 "$STAGE/VERSION" "$DIR/VERSION"
rm -f -- {obsolete}
install -d -o root -g wheel -m 755 {LOG_DIR}
install -d -o root -g wheel -m 700 /var/run/macvpn
TMP=$(mktemp "$STAGE/sudoers.XXXXXX")
printf '%s\n' {sudoers} > "$TMP"
visudo -c -f "$TMP"
install -o root -g wheel -m 440 "$TMP" /etc/sudoers.d/macvpn
"#
    ))
}

/// The command root runs: bash with a cleared environment (`env -i`), so nothing of the app's environment
/// (`BASH_ENV`, `ENV`, `SHELLOPTS`, `PS4`, …) reaches a root shell.
pub const ROOT_SHELL: &str = "/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin LC_ALL=C /bin/bash ";

/// `do shell script "<ROOT_SHELL>-c " & quoted form of "<script>" with administrator privileges`: the script text
/// goes inline (no script file a user process could swap before root runs it). `quoted form of` single-quotes it
/// for `/bin/sh`; here it only has to be a correct AppleScript string literal.
pub fn apple_script(script: &str) -> String {
    format!(
        "do shell script \"{ROOT_SHELL}-c \" & quoted form of {} with administrator privileges",
        apple_script_string(script)
    )
}

/// An AppleScript string literal: `\` and `"` escaped, line breaks and tabs as `\n`, `\r`, `\t`.
pub fn apple_script_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The time limit of the administrator run: the password prompt (the user may take a while) plus taking down
/// every running connection (each `mvpn down` may wait for its lock) and the install itself.
pub const ROOT_INSTALL_TIMEOUT: f64 = 15.0 * 60.0;

/// The runner for [`install`] and [`uninstall`]: [`ROOT_INSTALL_TIMEOUT`].
pub fn root_install_runner() -> ProcessCommandRunner {
    ProcessCommandRunner::new(ROOT_INSTALL_TIMEOUT)
}

/// The current user's login name (Foundation `NSUserName()`), from the user database.
pub fn current_user_name() -> Option<String> {
    crate::sys::user_by_uid(crate::sys::getuid()).map(|u| u.name)
}

/// Installs the root layer and the sudoers rule with one administrator prompt. Running connections are taken
/// down first (the UI tells the user beforehand: [`upgrade_disconnect_notice`]).
pub fn install(source_dir: &Path, user: &str) -> Result<(), InstallError> {
    install_with(source_dir, user, &root_install_runner())
}

/// [`install`] with an explicit runner (tests).
pub fn install_with(source_dir: &Path, user: &str, runner: &dyn CommandRunner) -> Result<(), InstallError> {
    let hashes = file_hashes(source_dir)?;
    let failure = l10n::tr("Installation error", &[]);
    let script = install_script(source_dir, user, &hashes)?;
    match run_privileged(&script, runner, &l10n::tr("Installation cancelled", &[]), &failure) {
        Err(InstallError::Message(m)) if m.contains(&disconnect_failure_marker()) => {
            let detail = m.replace(&format!("{failure}: "), "");
            Err(InstallError::Message(l10n::tr(
                "A connection could not be disconnected, installation cancelled.\n\n%@",
                &[Arg::Str(&detail)],
            )))
        }
        other => other,
    }
}

/// What the UI shows before installing or updating the root layer: active connections will be disconnected.
pub fn upgrade_disconnect_notice() -> String {
    l10n::tr("Updating the system component will disconnect active VPN connections.", &[])
}

/// Takes down every running connection with the installed `mvpn` (from `/var/run/macvpn/<uuid>/kind`, after
/// checking the uuid and the kind); collects the failed ids in `FAILED`. Expects `MVPN` and `RUN_BASE`. Shared
/// by the uninstaller and the installer (which stops the connections with the old layer before replacing it).
fn down_loop(user: &str) -> String {
    let user_q = shell_quote(user);
    let lang = AppLanguage::current().raw_value();
    let untrusted = shell_quote(&untrusted_mvpn_message());
    format!(
        r#"FAILED=""
if [ -d "$RUN_BASE" ] && [ ! -L "$RUN_BASE" ] && {{ [ -x "$MVPN" ] || [ -L "$MVPN" ]; }}; then
  # Only a protected binary runs as root: a regular file (not a symlink), owned by root, not group/world writable.
  if [ -L "$MVPN" ] || [ ! -f "$MVPN" ] || [ "$(stat -f %u "$MVPN")" != 0 ] || [ $(( 0$(stat -f %Lp "$MVPN") & 022 )) != 0 ]; then
    echo {untrusted} "$MVPN" >&2
  else
    for d in "$RUN_BASE"/*/; do
      d="${{d%/}}"
      [ -L "$d" ] && continue
      id=$(/usr/bin/basename "$d")
      [[ "$id" =~ ^[0-9A-Fa-f]{{8}}-[0-9A-Fa-f]{{4}}-[0-9A-Fa-f]{{4}}-[0-9A-Fa-f]{{4}}-[0-9A-Fa-f]{{12}}$ ]] || continue
      [ -f "$d/kind" ] && [ ! -L "$d/kind" ] || continue
      kind=$(/usr/bin/head -c 32 "$d/kind")
      case "$kind" in openvpn|wireguard|strongswan|sstp) ;; *) continue ;; esac
      if ! SUDO_USER={user_q} "$MVPN" down "$kind" "$id" --lang {lang} </dev/null; then
        FAILED="$FAILED $id"
      fi
    done
  fi
fi
"#
    )
}

/// The message (stderr) when the installed `mvpn` is not trusted to run as root: the down loop is skipped.
pub fn untrusted_mvpn_message() -> String {
    l10n::tr("The installed mvpn is not a protected root file, so running connections were not disconnected:", &[])
}

/// The uninstaller script. First every running connection is taken down (from `/var/run/macvpn/<uuid>/kind`,
/// after checking the uuid and the kind), then the root layer is deleted. The user is needed for the log file's
/// owner (`mvpn` reads it from `SUDO_USER`; the osascript admin run does not set it).
pub fn uninstall_script(user: &str) -> Result<String, InstallError> {
    check_user(user)?;
    let mvpn = shell_quote(EXECUTABLE);
    let down_loop = down_loop(user);
    let marker = shell_quote(&disconnect_failure_marker());
    let ui_dir = AuthUIState::DEFAULT_DIRECTORY;
    Ok(format!(
        r#"#!/bin/bash
set -uo pipefail
MVPN={mvpn}
RUN_BASE=/var/run/macvpn
PPP_OPTIONS=/etc/ppp/options
PPP_MARKER={INSTALL_DIR}/.created-ppp-options
{down_loop}# Ha bármelyik kapcsolat nem bontható, a root réteg marad (a mvpn kell a későbbi bontáshoz).
if [ -n "$FAILED" ]; then
  echo {marker}"$FAILED" >&2
  exit 1
fi
# A /etc/ppp/options-t csak akkor töröljük, ha a mvpn hozta létre (jelölő), és azóta is üres.
if [ -f "$PPP_MARKER" ] && [ ! -L "$PPP_MARKER" ] && [ -f "$PPP_OPTIONS" ] && [ ! -L "$PPP_OPTIONS" ] && [ ! -s "$PPP_OPTIONS" ]; then
  /bin/rm -f "$PPP_OPTIONS"
fi
/bin/rm -f /etc/sudoers.d/macvpn
/bin/rm -rf {INSTALL_DIR} /var/run/macvpn {ui_dir} {LOG_DIR}
"#
    ))
}

/// The installer and the uninstaller mark connections that could not be taken down with this (localized) prefix on stderr.
pub fn disconnect_failure_marker() -> String {
    l10n::tr("Could not disconnect:", &[])
}

/// Takes down the running connections and removes the root layer with one administrator prompt.
pub fn uninstall(user: &str) -> Result<(), InstallError> {
    uninstall_with(user, &root_install_runner())
}

/// [`uninstall`] with an explicit runner (tests).
pub fn uninstall_with(user: &str, runner: &dyn CommandRunner) -> Result<(), InstallError> {
    let failure = l10n::tr("Uninstall error", &[]);
    match run_privileged(&uninstall_script(user)?, runner, &l10n::tr("Uninstall cancelled", &[]), &failure) {
        Err(InstallError::Message(m)) if m.contains(&disconnect_failure_marker()) => {
            let detail = m.replace(&format!("{failure}: "), "");
            Err(InstallError::Message(l10n::tr(
                "A connection could not be disconnected, uninstall cancelled.\n\n%@",
                &[Arg::Str(&detail)],
            )))
        }
        other => other,
    }
}

/// Runs the script (inline, see [`apple_script`]) with one `osascript … with administrator privileges` call.
pub fn run_privileged(
    script: &str,
    runner: &dyn CommandRunner,
    cancelled: &str,
    failure: &str,
) -> Result<(), InstallError> {
    let result = runner
        .run("/usr/bin/osascript", &["-e".to_string(), apple_script(script)], None)
        .map_err(InstallError::Command)?;
    if result.exit_code != 0 {
        let msg = result.stderr.trim_matches(swift_str::is_foundation_whitespace_or_newline);
        return Err(InstallError::Message(if msg.contains("-128") {
            cancelled.to_string()
        } else {
            format!("{failure}: {msg}")
        }));
    }
    Ok(())
}
