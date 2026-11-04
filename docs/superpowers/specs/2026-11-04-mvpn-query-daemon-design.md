# Read-only root query daemon (macOS, root layer 13) – design

Date: 2026-11-04. Status: approved by the maintainer ("rendben mehet").

## Why

With a tunnel up, the app asks the root layer for the connections' state every 3 s (10 s while no window is
shown, since 2.1.6) and for liveness every 30 s. Each question is `sudo -n /usr/local/libexec/macvpn/mvpn …`: a new
`sudo` and `mvpn` process, PAM, a group lookup (logged by the system as a performance impact) and some 30 lines in
the unified log. Measured on 2026-11-04: MacVPN 7–13 wake-ups/s with OpenVPN up, 6–10 with WireGuard (3 without a
tunnel), and one `sudo` every 2.8–3.75 s. Goal: the read-only questions without `sudo`, same answers, no new
privilege for anyone.

## Design

### `mvpn serve` (root, launchd)

- A new internal subcommand of the existing `mvpn` binary, run only by launchd from
  `/Library/LaunchDaemons/<bundle-id>.mvpn-query.plist`. Not reachable through the sudoers rule (the existing
  internal-subcommand guard in `crates/helper/src/macos/mod.rs` covers it).
- Socket activation: launchd owns the listening socket `/var/run/macvpn-query.sock` (`SockPathOwner` = the
  installing user's uid, `SockPathGroup` = 0, `SockPathMode` = 0600), so only that user and root can connect. The
  daemon takes it with `launch_activate_socket`, serves connections one at a time and exits after 60 s without a
  connection (launchd starts it again on the next one).
- Every connection: `getpeereid` must give the installed user's uid (passed in the plist's arguments, checked to
  be a plain number ≥ 501 at install) or root; otherwise the connection is closed without an answer.
- Request: one line, at most 128 bytes, read with a 2 s timeout: `status`, `liveness <UUID>` or `traffic <UUID>`
  (the same validation as the CLI's arguments). Anything else: closed. Response: the exit code as a decimal line,
  then exactly what the CLI prints on stdout for that command (same code path, `status::render` with its
  housekeeping included), written with a 2 s timeout; the connection then closes.
- Nothing is changed by it beyond what `mvpn status` already does (the log housekeeping); no secrets are in the
  answers (they are what the user's `sudo mvpn status` prints today).

### Installer / uninstaller (`crates/platform-mac/src/root_installer.rs`)

- Same single administrator prompt. Install: write the plist (root:wheel 0644, from a template with the uid),
  `launchctl bootout` an old one, `launchctl bootstrap system <plist>`. Uninstall: `bootout`, remove plist and
  socket.
- Root layer `VERSION` 13 (the app offers the update as for every root layer change).

### App (`crates/platform-mac/src/mvpn_client.rs`)

- `status`, `liveness`, `traffic` first try the socket (connect + 2 s timeouts, the same parsing of the answer);
  on any failure (no socket: an older root layer, the daemon not loaded, a timeout, a malformed answer) the
  existing `sudo -n` path runs, so nothing gets worse than today. Everything that changes state stays on `sudo`.

### `mvpn-mgmt` relay

- The management stream's read timeout is 250 ms only while the bridge waits for the user's answer (an MFA or
  web-auth prompt, a deadline pending); otherwise 2 s. The loop's other duties (run directory still trusted,
  housekeeping every 30 s) keep working at that pace. Shared bridge code: the stream gets an optional "idle
  timeout" hook, implemented for the macOS Unix stream; Windows keeps its behaviour.

## Out of scope

Linux (NetworkManager, no sudo polling) and Windows (the WinVPN Service already answers over its pipe).

## Tests

- Unit: request parsing and validation, the peer check, the answer framing, the client's fallback decision.
- Integration (no launchd): `mvpn serve` on a socket in a temp dir via a test-only entry, answering `status`.
- Installer script tests (`crates/platform-mac/tests/root_installer.rs`) for the plist and launchctl steps.
- The macOS smoke run; live on the maintainer's Mac: install root layer 13 (admin password), then measure
  wake-ups and `sudo` count with OpenVPN and WireGuard up.
