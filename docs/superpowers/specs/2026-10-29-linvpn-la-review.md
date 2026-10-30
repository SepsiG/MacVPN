# LinVPN L-a: independent security review

Date: 2026-10-29. Reviewer: an independent agent that did not write the code (plan Task 26). Review only: nothing was
changed in the reviewed code.

## Scope

The range runs from the plan's first commit, `9c1bd6a` ("docs(plan): LinVPN L0 (spikes) and L-a (foundations)"), to
the `develop` tip `adc34d2`. The yardsticks were the spec `docs/superpowers/specs/2026-10-29-linvpn-design.md`
(sections 7 and 8, decisions 1–8) and the "Resolved points" of `docs/superpowers/plans/2026-10-29-linvpn-l0-la.md`.

- **The root step:** `crates/helper/src/linux/` (`install_update.rs`, `main_install_update.rs`) and
  `crates/core/src/deb_update.rs`. Also read were `UpdateSignature::message_for` / `verify_for` in
  `crates/core/src/update.rs` and the tests in `crates/helper/tests/install_update.rs`.
- **The polkit action:** `packaging/linux/local.linvpn.update.policy`.
- **`crates/platform-linux/src/lin/`:**
  - `updater.rs` and `curl_runner.rs`, with `pure/update.rs` and `pure/update_check.rs`;
  - `keystore.rs`, `control.rs`, `instance.rs` (with `pure/instance.rs`), `clipboard.rs`;
  - `xattr.rs` (with `pure/mark.rs` and its caller `app/src-tauri/src/open_files.rs`);
  - `tray.rs`, `notify.rs` and `shell.rs`.
- **`crates/unixsys/`:** `control_socket.rs`, `transport.rs` and `random.rs`.
- **The overlay's input region:** `app/src-tauri/src/platform/linux.rs` and `pure/placement.rs::card_input_rect`.
- **Packaging:**
  - `scripts/build-deb.sh` and `scripts/bundle-baseline/linvpn-deb-files.txt`;
  - `packaging/linux/*`: the desktop entry, the MIME XML, the polkit action, the copyright file, and
    `nm-linvpn-openvpn/*.conf` (L-b, checked only against upstream's bus policy).
- **The VM harness:** `scripts/lin-remote.sh` and `scripts/lin-smoke.sh`.
- **CI and release:** the Linux additions to `.github/workflows/ci.yml` and `.github/workflows/release.yml` (gated
  by `LINVPN_DEB_IN_RELEASE`), and the `.deb` additions to `scripts/sign-release.sh`.

## Method

- Read the code and its tests directly, not the implementers' commit messages.
- For every root-reachable input, traced who controls it:
  - the arguments;
  - the caller's files;
  - `PKEXEC_UID`;
  - the inherited process state;
  - the output of the dpkg/apt tools.
- Checked the order of checks in the root step against spec 7: signature, package, architecture, version, no
  downgrade.
- For each local-boundary component, asked whether another local user (not the same uid) can reach it:
  - the control socket;
  - the session-bus instance name;
  - the Secret Service item;
  - the clipboard;
  - notifications.
- Same-user attacks were rated only where the plan does not already accept the same-user boundary, or where a
  same-user process can turn an administrator's password prompt into more than the plan intends.
- Checked the scripts for path escape, quoting, and anything that leaves the Mac.
- No code was run and no VM was contacted. Each finding below has a concrete failure scenario; style points and
  speculation without a scenario are left out.

Severity scale:
- **Critical:** any local user gets root, or the signature is bypassed.
- **High:** another local user reaches LinVPN's secrets or controls, or a downgrade is possible without a precondition.
- **Medium:** the same, behind a realistic precondition.
- **Low:** defence in depth with a concrete but constrained scenario.
- **Info:** a note or a residual risk.

## Findings

| ID | Severity | File:line | Issue | Scenario | Suggested fix |
|---|---|---|---|---|---|
| LA-1 | Low | `crates/helper/src/linux/install_update.rs:54`, `:79`, `:93-100` | The root step checks the size of the caller's `.deb` (512 MB) and `.sig` (1 KB) with `fstat` when it opens them, but then reads both to EOF with no limit (`read` loop into the root copy; `read_to_string` for the signature). The caller owns both files and can keep writing to them. | A same-user process waits for the user to approve a LinVPN update prompt. It passes a `.deb` path that it keeps appending to, for example from a `/dev/zero` writer. The root step copies without end into `/var/cache/linvpn-update/<hex>/` and fills `/var` down to root's reserved blocks; with the signature file, it fills root's memory instead. apt, journald and the login manager then fail system-wide until the step is killed. The signature check rejects the result only after EOF, which never comes. | Read through `source.take(MAX_DEB + 1)` and refuse when more than `MAX_DEB` bytes arrive, as the app side's `copy_hashed` (`pure/update.rs:169-190`) already does. Read the signature through `take(MAX_SIGNATURE_FILE_SIZE + 1)` the same way. Add a test with a file that grows after it is opened. |
| LA-2 | Low | `crates/helper/src/linux/install_update.rs:157-160`; `crates/core/src/deb_update.rs:54-59` | "No downgrade" fails open. `installed` returns `None` both when `dpkg-query` fails (non-zero exit, spawn error) and when `linvpn` is not installed; `is_newer(_, None)` then accepts any signed version. The step itself ships in the `linvpn` package, so in practice `None` can only mean a failure. | Make `dpkg-query` fail while `apt-get` still works, for example through a transient error, a tight resource limit the caller sets before `pkexec` (rlimits survive pkexec), or a dpkg database `dpkg-query -W` cannot parse. The step then installs an older signed release over a newer one: a downgrade to a version with a known, already-fixed flaw. Spec 7 and spec 8 ("never downgrades") forbid this. | Make `installed` return `Result<Option<String>, StepError>`: a tool failure is `ToolFailed`, and only "the package is unknown or not installed" (shown by `${db:Status-Status}`) is `None`. Better still, since the step only exists inside an installed `linvpn`, refuse `None` outright (`NotNewer`). Add a test where `installed` reports a failure. |
| LA-3 | Low | `crates/platform-linux/src/lin/keystore.rs:105-119`, `:173-185`, `:192-198` | The DEK item is found by attributes across every collection; `find` takes the first unlocked match. `set` writes into whichever collection the alias `default` names at that moment (`replace = true` only replaces inside that collection), and `delete` removes only the first match. | The user turns on auto-unlock, which stores the DEK in the "Login" keyring. Later they make another keyring the default, or a migration does; turning auto-unlock off and on again then writes a second DEK item there. When the user turns auto-unlock off, or resets the vault, `delete` removes one item and the other copy of the DEK stays at rest in the keyring. This is contrary to the user's choice, and `exists()` keeps reporting `true`. A stale item can also be returned by `get` before the current one. | `delete` loops over every unlocked and locked match until `SearchItems` returns none. `set` first deletes matches outside the target collection, or searches through `Collection.SearchItems` on the default collection only. Add a fake-service test with two collections. |
| LA-4 | Low | `scripts/lin-remote.sh:43`, `:88-94` | `LINVPN_REMOTE_DIR` is checked with `^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$`, which accepts the segments `.` and `..`. `sync` then runs `git init`, `git checkout --force` and `git clean -q -fdx` in `~/$REMOTE_DIR`. The plan's rule that remote paths cannot escape the checkout is not met (`put` and `fetch` refuse `..`; `REMOTE_DIR` does not). | An operator sets `LINVPN_REMOTE_DIR=.` (or `work/..`) for a "fresh" run, intending to clean. `sync` makes `linvpn-dev`'s home a git work tree and `git clean -fdx` deletes everything untracked in it: `~/.ssh/authorized_keys` (the harness locks itself out), `~/.cargo`, `~/.rustup`, the desktop session's config and the keyring. `../x` writes outside the home. `scripts/win-remote.sh:33` has the same pattern; it predates L-a. | Use the same rule as `put`: refuse any `.` or `..` segment (`(^|/)\.{1,2}(/|$)`), and keep the leading `~/` with a fixed prefix such as `linvpn-work*`. Add the negative cases to `scripts/test-lin-remote.sh`. |
| LA-5 | Low | `scripts/lin-remote.sh:30-32`, `:68`, `:89`, `:205`, `:212` | The SSH and scp options do not turn off forwarding, so the maintainer's `~/.ssh/config` decides. A `Host *` block with `ForwardAgent yes` (common), or `ForwardX11`, applies to the VM connection. | The VM runs freshly synced, unreviewed builds, `npm ci` and cargo build scripts as `linvpn-dev`; any process there, or anyone with root on the VM, can then use the Mac's forwarded ssh-agent while a job is being followed. The SSH keys never leave the Mac, but they can be used from the VM, for example to push to GitHub with the maintainer's key. The script header promises "Nothing secret is sent", which this does not keep. | Add `-o ForwardAgent=no -o ForwardX11=no -o ClearAllForwardings=yes` to `SSH_OPTS`; scp ignores the first two and accepts them. Do the same in `win-remote.sh`. |
| LA-6 | Info | `crates/helper/src/linux/install_update.rs:42-57` | `open_callers` checks the parent folder with a path-based `lstat`, then opens the full path again by name. Only the last component is opened with `O_NOFOLLOW`, and the open has no `O_NONBLOCK`. | A same-user process swaps a parent folder for a symlink between the check and the open. This gains nothing: the opened file must still be a regular file owned by the caller with one link, so root reads nothing the caller could not. A FIFO at the path makes the root step block in `open` until the user kills the prompt, which is a denial of service against the user's own update. | Open the parent with `O_DIRECTORY \| O_NOFOLLOW`, `fstat` it, then `openat(dirfd, name, O_RDONLY \| O_NOFOLLOW \| O_NONBLOCK \| O_CLOEXEC)` and clear `O_NONBLOCK` after the `is_file` check. |
| LA-7 | Info | `crates/helper/src/linux/install_update.rs:126-173` | pkexec clears the environment but passes on the caller's `umask` and resource limits. The step runs `dpkg-deb` and `apt-get` (and through it `dpkg`, triggers and `apt`'s cache rebuild) with them. | A user with `umask 077` updates. Files apt or a trigger creates outside the package's own tar modes, such as the regenerated `/var/cache/apt/*.bin`, `mime.cache` and `icon-theme.cache`, can come out root-only, which breaks other users' desktops until the next normal `apt`. A caller-set `RLIMIT_FSIZE` or `RLIMIT_NOFILE` can make apt fail half-way. This is not an escalation. | At the start of `main`, as root: `umask(0o022)`, and reset `RLIMIT_FSIZE`, `RLIMIT_NOFILE` and `RLIMIT_CORE` to sane values, as `sudo` does. |
| LA-8 | Info | `crates/platform-linux/src/pure/update.rs:83`; `crates/platform-linux/src/lin/updater.rs:154-163` | pkexec's 127 means "not authorized *or an error occurred*", which includes a missing program. It is mapped to `Cancelled` with no message. | `/usr/libexec/linvpn/linvpn-install-update` or the polkit action is missing, for example because of a broken install or because the action file was removed. Every "Update" silently does nothing, and the user is never told that updates (and their security fixes) cannot install. | Before running pkexec, check that `STEP` and the action file exist. If they do not, show `HelperFailed`. Map 127 to `Cancelled` only when both are present. |
| LA-9 | Info | `crates/helper/src/linux/install_update.rs:114`; `packaging/linux/local.linvpn.update.policy:12` | "No downgrade" compares only with the installed version, not with the latest release, and the polkit message names no version. | A same-user process asks for the prompt itself (`pkexec … --version 2.2.0`) with a genuine signed but superseded release, while 2.3.0, which fixes a flaw in 2.2.0, is out. A user who approves gets 2.2.0, not the fix. The app only offers `releases/latest`, so this needs a same-user attacker and an approved prompt. | Accepted residual risk; record it. Optionally the app could show the version it is about to install right before the prompt, so a prompt nobody asked for stands out. |
| LA-10 | Info | `crates/unixsys/src/control_socket.rs:303-318` | On Linux, `SO_PEERCRED`'s pid is the connecting process, but `/proc/<pid>/exe` is read at accept time. | A same-user process connects, forks a child that keeps the socket, then `exec`s a binary the user has paired. The server records the paired executable while the child holds the connection. The pin is therefore not a boundary: it is the same limit as macOS's `LOCAL_PEERPID` and is documented ("never the only check"), and the pairing token is still required. Another uid is refused by `same_user`, `crates/app-core/src/control.rs:880`. | No change for L-a. Keep relying on the token. Optionally also compare `/proc/<pid>/stat`'s start time before and after reading `exe`. |
| LA-11 | Info | `crates/platform-linux/src/pure/mark.rs:17`; `app/src-tauri/src/open_files.rs:244-249` | On Linux the download mark (`user.xdg.origin.url`) exists only when the downloading program sets it. Archive extractors, `curl`/`wget`, mail clients and some browsers or versions do not set it, and unmarked files import without the confirmation. | A `.ovpn` or `.macvpncatalog` taken out of a downloaded zip, or saved from a mail attachment, and opened by double-click is imported straight away. Importing never connects, so the impact is a rogue entry in the list. | Accepted limitation (the plan's "Download mark"); document it in the user guide. Optionally, a file under `~/Downloads` or `$XDG_DOWNLOAD_DIR` counts as marked. |

Points checked and found sound, so not findings:

- **The root step's order:** it refuses a mismatched asset before it opens any file. It copies into a fresh random
  0700 folder under a root-owned 0700 parent (`create_new`, `O_NOFOLLOW`) and hashes while copying. It verifies the
  `linvpn-update-v1` signature on that copy (asset, version, SHA-256; `verify_strict`; the embedded keys only). Only
  then does it run `dpkg-deb --field` on the copy: package, architecture, signed version, newer. `apt-get` runs last,
  on the copy. The copy's name cannot traverse, because the asset must equal `linvpn_<version>_<arch>.deb` and
  `message_for` limits the version to `[0-9]{1,9}` (×3).
- **The tools:** absolute paths, `env_clear`, a fixed `PATH`, `LC_ALL=C`, `DEBIAN_FRONTEND=noninteractive`, stdin
  from `/dev/null`, and the deb path passed as one argv element (no shell).
- **Exit codes:** 10–19, never 0, 126 or 127. `PKEXEC_UID` is required, and pkexec's cleared environment means the
  caller cannot forge it.
- **The polkit action:** `auth_admin` for any, inactive and active sessions (no `_keep`); `exec.path` names only the
  step; no `allow_gui`.
- **The `.deb`:** no maintainer scripts; the control archive is exactly `control` and `md5sums`. Every file is
  root:root, and the modes are pinned by the baseline (no setuid, 0755 for binaries, 0644 for data). The binaries in
  the package are the gated ones. The root step links only libc, libm, libgcc_s and the loader. The desktop entry
  uses `%F` and claims exactly `.ovpn`, `.sstp` and `.macvpncatalog`; `.conf` and backups are deliberately not
  claimed.
- **The control socket:** it needs `$XDG_RUNTIME_DIR` to be owned by the uid and 0700, and creates
  `linvpn/control` 0700 checked through an `O_NOFOLLOW` descriptor. The `flock` comes before the stale-socket unlink,
  and the unlink happens only for this uid's socket. The bind runs under umask 077 and is then set to 0600. Over-long
  paths are refused, and peers of another uid are refused.
- **The instance name:** only the user's own session bus can reach it. Only absolute paths are forwarded, and the
  download-mark rule still applies to them.
- **The clipboard:** it sets the `x-kde-passwordManagerHint=secret` target, and `clear_if_unchanged` clears only
  this app's own secret.
- **Notifications:** no secret in the body, and clicks are taken only from `org.freedesktop.Notifications`.
- **The overlay:** its input region is the card's rectangle, re-applied on every `size-allocate` and clamped to the
  window, so a click outside the card passes through to the window below and never reaches LinVPN.
- **The updater:** a 0700 updates folder with 0600 files, canonical github.com URLs only, and curl with `-q`, a
  fixed environment and a private temp folder. It runs `pkexec` and the relaunch by absolute path.
- **CI and release:** `build-linux` has read-only permissions, no secrets and no cache, and checks that the tag is
  on `main`. The release job takes the `.deb`s only when `LINVPN_DEB_IN_RELEASE == 'true'`, and then requires both
  architectures, `sha256sum -c` and build provenance. `sign-release.sh` signs exactly the two `.deb` names under
  `linvpn-update-v1`, both or neither.
- **The NM OpenVPN service's bus policy (L-b):** only root may own or call
  `org.freedesktop.NetworkManager.linvpn-openvpn*`, the same as upstream.

## Summary

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 0 |
| Medium | 0 |
| Low | 5 (LA-1 … LA-5) |
| Info | 6 (LA-6 … LA-11) |

No local privilege escalation and no signature bypass was found. The root update step does what spec 7 and the
"Resolved points" ask: it re-verifies a signed, root-owned copy, then checks package, architecture and version before
`apt-get`. Every path into it needs an administrator's password per run. No other local user can reach the control
socket, the instance name or the keyring item.

The findings that matter before L-a ships:

- **LA-2:** "no downgrade" fails open when `dpkg-query` fails. This is a one-line change to the spec's guarantee.
- **LA-1:** the root step's reads are not bounded, so it can be made to fill `/var` or root's memory.
- **LA-3:** a copy of the vault key can survive "turn off auto-unlock" when there are several keyrings.

The two harness findings protect the maintainer's machine and the VM, not users:

- **LA-4:** `LINVPN_REMOTE_DIR=.` wipes the VM home.
- **LA-5:** agent forwarding is not turned off.

## Resolution

Fixed on branch `la-fix` in commit `a2ba972` (each fix test first); the Info findings without a code change carry a
decision.

| ID | Resolution |
|---|---|
| LA-1 | Fixed (`a2ba972`). The root step reads the `.deb` through `take(512 MiB + 1)` (`copy_hashed`, refused as `UnsafeFile` beyond the limit) and the `.sig` through `take(1 KiB + 1)` (`read_signature`, refused as `BadSignature`). Tests: an endless reader (`io::repeat`) is cut off at the limit for both; exactly the limit passes. |
| LA-2 | Fixed (`a2ba972`). "No downgrade" fails closed: `Env::installed` is `Result<Option<String>, StepError>`; `dpkg-query` not starting or exiting other than 0/1, or unparsable output, is `ToolFailed` (18); exit 1 (no such package) or a status other than `installed` (`deb_update::parse_installed` of `${db:Status-Status} ${Version}`) is the new refusal `NotInstalled` (20), since the step ships inside `linvpn`. `deb_update::check` refuses `None`. Codes 10–19 unchanged (pinned by a test); the list is in `docs/architecture.md`, "The update chain and the `.deb`". |
| LA-3 | Fixed (`a2ba972`). `delete` unlocks (one `Unlock`) and deletes every match in every collection, searching again until none is left (at most 8 rounds, then `Unavailable`); `set` does the same before `CreateItem`, so exactly one item remains, in the default collection. The fake Secret Service now has two collections, per-item locks, and refuses deleting or reading a locked item; tests: copies in another collection (locked and unlocked) are all deleted, and `set` leaves one item with the new key. |
| LA-4 | Fixed (`a2ba972`). `LINVPN_REMOTE_DIR` and `WINVPN_REMOTE_DIR` must be one folder name, `^[A-Za-z0-9_-][A-Za-z0-9._-]*$`: never empty (set but empty no longer falls back to the default), absolute, nested, `.`, `..` or hidden (`.ssh`). Self-tests in `scripts/test-lin-remote.sh` and `scripts/test-win-remote.sh` (15 refused, several accepted). `scripts/win-smoke.sh` goes through `win-remote.sh`, so it is covered. |
| LA-5 | Fixed (`a2ba972`). Both scripts' `SSH_OPTS` (used by every `ssh` and `scp` call) add `-o ForwardAgent=no -o ForwardX11=no -o ClearAllForwardings=yes`; the self-tests check the options and that every call uses `SSH_OPTS`. |
| LA-6 | Accepted residual risk: a parent-folder swap gains the caller nothing (the opened file must still be its own regular single-link file), and a FIFO only blocks the user's own update until they cancel. |
| LA-7 | Fixed (`a2ba972`). `main` calls `harden_process` first: umask 022, `RLIMIT_CORE` 0, `RLIMIT_FSIZE` unlimited, `RLIMIT_NOFILE` at least 1024. The tools already ran with `env_clear` and a fixed `PATH`/`LC_ALL` (unchanged). Test: after `harden_process` the umask is 022 and the limits are as stated. |
| LA-8 | Fixed (`a2ba972`). Before any download or prompt the updater checks that the root step (a regular, executable file) and the polkit action file are installed, and checks again after pkexec's 127; a missing one is `HelperFailed` with its path (the existing text "Cannot start the installer helper script: %@", so no new strings). 127 with both in place stays `Cancelled`. Tests: missing step, missing action, step not executable, step removed while pkexec ran. |
| LA-9 | Accepted residual risk: it needs a same-user attacker and an approved administrator prompt, and installs only a genuine signed LinVPN release newer than the installed one; showing the version before the prompt is left as an option for later. |
| LA-10 | Accepted residual risk: the executable pin is documented as never the only check; the pairing token stays required and other uids are refused. |
| LA-11 | Accepted residual risk: unmarked downloads import without the confirmation, and importing never connects; the limitation goes into the Linux user guide with L-b's documentation. |
