# MacVPN – Local control API – design

**Date:** 2026-10-19
**Status:** design approved in conversation; written spec awaiting review
**Base:** MacVPN 1.0.0 (Rust/Tauri). The main spec (`2026-10-16-macvpn-design.md`) and its security rules (section 3) still apply.

## 1. Goal

Let another local program owned by the same user (first client: the maintainer's own **Remote Desktop** app, written in Rust and ad-hoc signed) do three things:

- list the VPN connections it is allowed to use,
- bring one of them up,
- bring it down again.

The VPN stays up only while the client's session needs it.

Not goals:

- remote (network) access
- other users on the Mac
- reading or changing configs or secrets
- creating or importing connections
- handling MFA in the client
- Windows or Linux (the transport is kept replaceable, see section 9)

## 2. Approach

The running MacVPN menu bar app serves a **Unix domain socket**. Messages are **newline-delimited JSON**. A client holds a **lease** on a connection for as long as its socket connection stays open.

These alternatives were rejected:

- **Localhost HTTP:** any local user or process can reach a TCP port, and browsers can be driven against it (DNS rebinding, CSRF).
- **XPC/launchd:** it only adds value with Developer ID code signing, and the client is ad-hoc signed.

## 3. Turning it on

- Setting: **"Allow other apps to control VPNs"** (HU: „Más appok vezérelhetik a VPN-eket”). It is **off by default** and lives in the Connections window, in a new **"Paired apps"** (HU: „Párosított appok”) section.
- While the setting is off, the socket does not exist. Turning the setting off closes every client connection. Leases end as described in section 6.

## 4. Transport and access control

- **Path:** `~/Library/Application Support/MacVPN/control/macvpn.sock`.
  - The `control/` directory is created with mode 0700 and must be owned by the user.
  - `lstat` must report a real directory, not a symlink. Otherwise the app refuses to serve and shows an error in the Setup window.
- **Stale socket:** a leftover `macvpn.sock` is removed only if `lstat` shows that it is a socket owned by the user. It is bound with umask 077 and then `chmod 0600`.
- **Single instance:** if `connect()` to an existing socket succeeds, another MacVPN is serving. The app does not take over.
- **Peer check on every accept:**
  - `getpeereid()` must return the app's own uid. Otherwise the connection is closed immediately.
  - The peer PID (`LOCAL_PEERPID`) and its executable path (`proc_pidpath`) are read for pairing and the audit log. The path is used to pin a client (section 5), never as the only check.
- **Limits:**
  - at most 8 concurrent client connections
  - lines of at most 4 KB
  - `hello` or `pair` must arrive within 5 s
  - at most 20 requests per second per connection
  
  If a limit is exceeded, the connection is closed.

## 5. Pairing and authentication

### Pairing

1. The client sends `{"op":"pair","name":"Remote Desktop"}`. `name` is 1–64 printable characters, sanitized like the MFA texts (`AuthText.sanitize`). Only one pairing can be pending at a time; other attempts get `busy`.
2. MacVPN shows a pairing window. It never steals focus. Its input is locked for 1 s, the same as the MFA prompts, and there is no default button. The window shows:
   - the name the client gave, marked as self-reported,
   - the **executable path** from `proc_pidpath`, which the window treats as the authoritative identity,
   - checkboxes for the connections to allow, none selected by default.
3. If the user approves:
   - MacVPN generates a 32-byte random token (`getentropy`), base64url-encoded.
   - It sends the token to the client once: `{"ok":true,"token":"…","client_id":"<uuid>"}`.
   - It stores only `SHA-256(token)`, the client id, the name, the pinned executable path, the allowed connection ids and the creation time. These go in `control-clients.json` (0600, atomic write, same rules as the other stores).
4. If the user rejects, or the window times out after 2 min: `{"ok":false,"error":"denied"}`. After 3 rejections, pairing is refused for 10 min.

The client stores the token in its own Keychain item. It must not store it in a plain file.

### Authentication

- Every connection first sends `{"op":"hello","token":"…"}`.
- MacVPN accepts it only if all of these hold:
  - the hash matches (constant-time compare),
  - the pairing has not been revoked,
  - the peer's executable path equals the pinned path.
- **Failure:**
  - the reply is a generic `unauthorized`, sent after a 1 s delay,
  - then the connection is closed,
  - the attempt is written to the log.
- **Changed executable path** (for example a dev build in another folder): the same `unauthorized`. The Paired apps list shows "path changed", and the user re-pairs.

### Paired apps list

For each paired client the list shows:

- name and path
- allowed connections, editable
- last used
- **Revoke**

Revoking closes that client's open connections at once.

## 6. Protocol

Each request is one JSON object per line and carries an `id` chosen by the client. Each reply echoes that `id`. Unsolicited events have no `id`. Requests are parsed strictly (`deny_unknown_fields`), and connection ids must be UUIDs.

| Request | Reply / effect |
|---|---|
| `{"id":1,"op":"list"}` | `{"id":1,"ok":true,"connections":[{"id":"<uuid>","name":"…","kind":"openvpn","state":"disconnected"}]}`. Only the client's allowed connections, in MacVPN's order. Never configs, usernames or secrets. |
| `{"id":2,"op":"up","connection":"<uuid>"}` | Takes a lease and starts the connection if it is down. The client gets progress events `{"event":"state","connection":"…","state":"connecting"\|"waiting_for_mfa"\|"waiting_for_credentials"\|"connected"}`, then the final reply `{"id":2,"ok":true,"state":"connected"}` or `{"id":2,"ok":false,"error":"…"}`. |
| `{"id":3,"op":"down","connection":"<uuid>"}` | Releases this socket's lease. See the lease rules below for when the VPN actually stops. |
| `{"id":4,"op":"status"}` | Subscribes to state events for the allowed connections, e.g. the VPN dropping. |

The protocol version is sent in `hello`'s reply: `{"ok":true,"api":1}`. Unknown ops get `unsupported`.

**Forward compatibility.** Later releases may add `state` values and `error` codes to API v1 without raising the version. A client must treat an unknown `state` as "in progress" and an unknown `error` code as `failed`. The first additions, `waiting_for_credentials` and `credentials_cancelled`, ship in the same release as API v1 (1.1.0): MacVPN's credential prompt is open, or the user cancelled it (see `2026-10-19-vault-folders-design.md`, section 4).

### Lease rules

- Each running connection has a set of lease holders.
- MacVPN brings the connection down when the last lease ends: through `down`, the socket closing, the client crashing, or a revoke.
- A connection that was **already up without a lease**, because the user or another path started it, is never brought down by a lease ending. In that case `up` only reports `connected`.
- If the user disconnects a leased connection by hand in the menu, the user wins. Lease holders get a `disconnected` event, and MacVPN does not reconnect on its own.
- The menu and the Connections window show "held by Remote Desktop" next to a leased connection.
- **Quitting MacVPN:** the quit guard already asks about connections that are up. It names the leasing clients too. Quitting ends all leases and closes the socket.
- **Sleep and wake:** sockets stay open. If the VPN drops, holders get the event, and reconnecting is up to the client.

### Errors

These are generic codes, never raw tool output:

- `unauthorized`, `not_allowed` (not in the allowlist), `unknown_connection`, `busy` (the connection is changing state), `setup_required` (brew or the root layer is missing)
- `mfa_cancelled`, `mfa_timeout`, `credentials_cancelled` (the credential prompt was cancelled or expired), `failed` (a localized short reason, such as in the MacVPN notification)
- `app_quitting`, `disabled`, `unsupported`, `bad_request`

## 7. MFA and secrets

- Starting a connection goes through exactly the same path as a manual connect:
  - the `ConnectionManager` op, token and epoch,
  - the root layer through `sudo -n`,
  - the Keychain,
  - the MFA prompts in MacVPN's own windows.
- The client only sees `waiting_for_mfa` and `waiting_for_credentials`. It never sends or receives codes, passwords or configs.
- Risky-directive acknowledgement and every validator still apply. A connection that needs an acknowledgement it does not have fails with `failed`, the same as a manual connect.

## 8. Audit

These events are recorded, with the client name and path:

- pairing requests and their results,
- hello failures,
- every `up` and `down`,
- lease ends,
- server starts, stops and start failures (with the raw OS error, which the UI does not show).

They go to three places:

- **The debug log** (stderr), prefixed `MacVPN (Control API):`.
- **The Activity list** of the Paired apps section: the latest 100 lines of this session. It has a "Save…" action that saves the audit file through the native save panel (0600; the web view never names a path).
- **The audit file** `~/Library/Application Support/MacVPN/control/audit.log`:
  - 0600, in the 0700 control directory (checked like the socket's), never opened through a symlink;
  - one ISO 8601 timestamped line per event, appended by a background thread;
  - rotated before it would pass 256 KB to `audit.log.1`, and only that one old file is kept.

Tokens are never logged.

The Paired apps list's "path changed" flag (section 5) is kept in memory only. After a restart it appears again with the next failed `hello` from the other path.

### Accepted limitations

Malware already running as the same user is not fully stopped by any of the checks above. It could:

- replace a user-writable client binary at the pinned path, or
- drive the client.

The design limits what such malware gains:

- only the allowlisted connections,
- only up and down,
- no secrets.

Every action is visible in the menu and the log. This matches MacVPN's existing threat model, where brew binaries are user-writable.

## 9. Code layout

- **`crates/core/src/control/`** (platform-independent, `#![forbid(unsafe_code)]`):
  - the protocol types and strict parser,
  - the client registry (hashing, allowlist, pinning, rate limits),
  - the lease table (holders, "pre-existing" flag, release decisions),
  - the error mapping.
  
  Pure logic, fully unit-tested.
- **`crates/platform-mac/src/control_socket.rs`:**
  - the socket directory checks, bind and accept,
  - `getpeereid`, `LOCAL_PEERPID`, `proc_pidpath`,
  - `getentropy`.
  
  This is the one module with FFI. A later Windows or Linux port replaces it with a named pipe or abstract socket.
- **`crates/app-core`:** the server loop on its own threads. It dispatches to `ConnectionManager`, forwards state events and drives the quit-guard integration.
- **Tauri:**
  - the pairing window, which works like the MFA prompt windows: own capability, label check, input lock,
  - the Paired apps section,
  - the "held by" labels,
  - the setting.
  
  New IPC commands are added to the allowlist and the capability test.
- **`examples/macvpn-control-client/`:** a minimal Rust client (std only) that the Remote Desktop app can copy. It does pair (keeping the token in its Keychain), hello, list, up and down, and shows how to hold the socket open for the session.
- **`docs/control-api.md`** (EN) and **`docs/control-api.hu.md`** (HU): the protocol, the security model, an integration how-to, and the error codes.

## 10. Testing

- **Core unit tests:**
  - parser limits and malformed or unknown input,
  - token hashing and constant-time compare,
  - allowlist enforcement,
  - path pinning,
  - pairing rate limits,
  - lease rules: last holder, pre-existing connection, manual disconnect, revoke, quit.
- **platform-mac tests in a temp directory:**
  - refusing a symlinked or foreign-owned `control/`,
  - removing a stale socket only when it is safe,
  - permissions are 0600,
  - two-instance detection,
  - a peer with another uid can't be simulated without root, so the check is covered by a unit-tested pure function on the `getpeereid` result.
- **Integration tests (app-core with mocked VPN runners):** a real socket and the example client. They walk through the full flow: pair, hello, list, up, socket drop, down. Then: a revoked client, a wrong path, and a client killed mid-connect.
- **Smoke test:** the sandboxed app, with pairing approved through a smoke hook (debug builds only, like the existing hooks; the release gate also checks for this hook's marker).
- **Manual checklist:** pairing the real Remote Desktop app, then up and down with an OpenVPN connection that has MFA, then quitting Remote Desktop and checking that the VPN goes down.

## 11. Release

The release is 1.1.0, with no root layer change (root VERSION stays 7). It goes through the existing signed-update path.
