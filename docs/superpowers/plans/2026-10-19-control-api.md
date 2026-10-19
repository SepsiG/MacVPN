# MacVPN local control API – implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax. The spec is `docs/superpowers/specs/2026-10-19-control-api-design.md`; where this plan and the spec disagree, the spec wins. Follow the existing patterns of the crate you work in (look at a neighbouring module first).

**Goal:** another local program of the same user (first client: the maintainer's Rust "Remote Desktop" app) can pair with MacVPN, list its allowed connections, and hold a connection up through a socket lease (release 1.1.0).

**Architecture:**
- **Pure logic:** protocol, client registry and lease table in `crates/core/src/control/`.
- **FFI:** socket and peer identity in `crates/platform-mac/src/control_socket.rs`.
- **Server:** `crates/app-core/src/control.rs`. It runs on its own threads, drives `ConnectionManager`, and calls back into the UI for pairing.
- **UI:** a Tauri pairing window plus a "Paired apps" section.

**Tech:**
- Rust 1.99.1 (pinned), `std::os::unix::net`, `libc` (already a dependency), `sha2`, `serde`/`serde_json` (strict), `uuid`.
- Tauri 2, Svelte + TS.
- No new crates, unless the subagent shows that one is needed and the reviewer agrees.

**Rules for every task:**
- TDD.
- `cargo fmt --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --locked` must be green before each commit.
- No `unsafe` outside `platform-mac`.
- Never log tokens. Never put a token in argv or env.
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- The maintainer's forbidden company name never enters the repo.

**Key ids:** `ConnectionItem::id()` (the managed connection's UUID string, or the scutil service ID of a system VPN) is the connection key everywhere in the API.
- The allowlist may hold both kinds of key.
- Validation: a key is accepted only if it is a UUID-shaped string (36 chars, hex and dashes) **and** it is currently in `manager.ordered_items()`.

---

## Task 1: core – protocol types and parser

**Files:** create `crates/core/src/control/mod.rs` and `crates/core/src/control/protocol.rs`; modify `crates/core/src/lib.rs` (`pub mod control;`).

- [ ] Define the requests, all with `#[serde(deny_unknown_fields, tag = "op", rename_all = "snake_case")]`:
  ```rust
  pub const API_VERSION: u32 = 1;
  pub const MAX_LINE: usize = 4096;
  pub enum Request {
      Pair { id: Option<u64>, name: String },
      Hello { id: Option<u64>, token: String },
      List { id: u64 },
      Up { id: u64, connection: String },
      Down { id: u64, connection: String },
      Status { id: u64 },
  }
  pub enum ErrorCode {
      Unauthorized, NotAllowed, UnknownConnection, Busy, SetupRequired,
      MfaCancelled, MfaTimeout, Failed, AppQuitting, Disabled,
      Unsupported, BadRequest, Denied,
  }
  pub enum WireState { Disconnected, Connecting, WaitingForMfa, Connected, Disconnecting, Failed }
  ```
- [ ] `pub fn parse_line(bytes: &[u8]) -> Result<Request, ErrorCode>`:
  - A line longer than `MAX_LINE`, invalid UTF-8, an unknown op or unknown fields → `BadRequest`. An unknown `op` value alone → `Unsupported`.
  - `name`: 1–64 chars after `macvpn_core::mfa` sanitize (the `AuthText.sanitize` port), no control chars.
  - `token`: exactly 43 chars of base64url without padding.
  - `connection`: UUID-shaped.
- [ ] Reply builders. Each returns one `String` that ends in `\n`; `serde_json` handles the escaping.
  - `reply_ok(id, extra: serde_json::Map)`
  - `reply_err(id, ErrorCode, message: Option<&str>)`
  - `event_state(key, WireState, reason: Option<&str>)`
- [ ] `pub fn wire_state(&ConnectionState) -> WireState`. `AwaitingAuth(_)` maps to `WaitingForMfa`.
- [ ] Tests:
  - each op parses
  - an unknown field is rejected
  - an unknown op → `Unsupported`
  - 4097 bytes → `BadRequest`
  - bad UTF-8
  - a bad UUID
  - a token of the wrong length or alphabet
  - `name` with a control character or RTL override (Cf) is sanitized or rejected
  - replies round-trip through `serde_json`
  - a name containing `"` and `\n` stays on one line
- [ ] Commit: `feat(core): control API protocol`.

## Task 2: core – client registry

**Files:** create `crates/core/src/control/registry.rs`. Look at `crates/core/src/store.rs` for the atomic 0600 write helpers and reuse them.

- [ ] Data, persisted as JSON in `control-clients.json` under the app support directory:
  ```rust
  pub struct PairedClient {
      pub id: Uuid, pub name: String, pub token_sha256: String /* hex */,
      pub executable: String, pub allowed: Vec<String>,
      pub created: Date, pub last_used: Option<Date>,
  }
  pub struct Registry { clients: Vec<PairedClient>, /* + rejection window */ }
  ```
- [ ] Functions:
  - `Registry::load(dir) / save(dir)`: 0600, atomic, and a missing file means an empty registry. A corrupt file also means an empty registry, and the corrupt file is renamed to `.bad`, following the existing store's pattern.
  - `pub fn new_token(entropy: [u8; 32]) -> String`: base64url, no padding. Entropy is passed in, so the function is testable.
  - `pub fn authenticate(&self, token: &str, executable: &str) -> Result<&PairedClient, ErrorCode>`:
    - Hash the token and compare against every client in constant time. Use a hand-written XOR fold over the 32 bytes with no early exit, and run it for every client.
    - The executable path must match exactly, otherwise `Unauthorized`.
  - `add`, `revoke(id)`, `set_allowed(id, Vec<String>)`, `touch(id, now)`.
  - `is_allowed(client, key)`.
- [ ] Pairing rate limit:
  - `record_rejection(now)` keeps the timestamps of the last 3 rejections.
  - `pairing_blocked(now)` returns true while 3 rejections fall inside 10 min and the newest one is less than 10 min old.
  - These live in memory only.
- [ ] Tests:
  - authenticate succeeds with the right token and path
  - a wrong token → `Unauthorized`
  - a wrong path → `Unauthorized`
  - after `revoke` → `Unauthorized`
  - the allowlist is enforced
  - the token is 43 chars and differs for different entropy
  - save then load round-trips
  - the file mode is 0600
  - a corrupt file → empty registry plus `.bad`
  - the rate limit with a fake clock
- [ ] Commit: `feat(core): paired client registry`.

## Task 3: core – lease table

**Files:** create `crates/core/src/control/lease.rs`.

- [ ] Types:
  ```rust
  pub type SessionId = u64;
  pub struct LeaseTable { /* key -> Entry { holders: BTreeSet<SessionId>, preexisting: bool } */ }
  pub enum LeaseAction { None, Connect, Disconnect }
  ```
- [ ] `acquire(key, session, is_active: bool) -> LeaseAction`:
  - First holder and the connection is not active: `Connect`.
  - First holder and the connection is active: `preexisting = true`, `None`.
  - Otherwise: `None`.
- [ ] `release(key, session) -> LeaseAction`: if this was the last holder and the connection is not `preexisting`: `Disconnect`; otherwise `None`.
- [ ] `release_session(session) -> Vec<(String, LeaseAction)>`: used when a socket closes or a client is revoked.
- [ ] `on_user_disconnect(key) -> Vec<SessionId>`: drops the entry and returns the sessions to notify, so the user wins.
- [ ] `on_dropped(key)`: same as above; the holders get the event, and there is no reconnect.
- [ ] `holders_of(key) -> Vec<SessionId>` and `is_leased(key)`.
- [ ] Tests:
  - one holder: up then socket close → Disconnect
  - two holders: the first release → None, the second → Disconnect
  - pre-existing connection: release → None
  - manual disconnect clears the entry, and a later release → None
  - drop
  - revoke releases all of a session's keys
  - the same session acquiring twice is idempotent
- [ ] Commit: `feat(core): control API lease table`.

## Task 4: platform-mac – control socket

**Files:** create `crates/platform-mac/src/control_socket.rs`; export it in `crates/platform-mac/src/lib.rs`.

- [ ] `pub fn prepare_dir(dir: &Path) -> io::Result<()>`:
  - Create the directory with mode 0700 if it is missing.
  - Then `lstat`: it must be a real directory, owned by `getuid()`, mode 0700. If the mode is looser, fix it with `chmod`; if it is a symlink or has another owner, return an error.
- [ ] `pub fn bind(dir: &Path) -> io::Result<UnixListener>`:
  - If `macvpn.sock` exists, `connect()` to it first. If that succeeds, return `AddrInUse` (another instance).
  - Otherwise, if `lstat` shows a socket owned by us, unlink it. Anything else → error.
  - Bind with the process umask temporarily set to 0o077 (restore it afterwards), then `chmod 0600`.
- [ ] `pub struct Peer { pub uid: u32, pub pid: i32, pub executable: Option<String> }` and `pub fn peer(stream: &UnixStream) -> io::Result<Peer>`, using:
  - `libc::getpeereid`
  - `getsockopt(SOL_LOCAL, LOCAL_PEERPID)`
  - `libc::proc_pidpath` (buffer `PROC_PIDPATHINFO_MAXSIZE`)
- [ ] `pub fn same_user(peer_uid: u32) -> bool`: pure, compares with `getuid()`.
- [ ] `pub fn random_32() -> io::Result<[u8; 32]>`: `libc::getentropy`.
- [ ] Each FFI call is documented and kept small, like `sys.rs`. Every fd is close-on-exec, the same way the crate already does it.
- [ ] Tests, in a temp dir (use the crate's `testing.rs` helpers):
  - a symlinked dir is refused
  - mode 0755 is tightened to 0700
  - the socket is 0600
  - a stale socket is replaced
  - a regular file in place of the socket → error
  - with a live listener, a second bind → `AddrInUse`
  - `peer()` on a `UnixStream::pair()` returns our uid and pid, and the executable equals `std::env::current_exe()` after canonicalizing
  - `random_32` returns different values
- [ ] Commit: `feat(platform-mac): control socket and peer identity`.

## Task 5: app-core – control server

**Files:** create `crates/app-core/src/control.rs`; modify `crates/app-core/src/lib.rs`, `crates/app-core/src/manager.rs` (an event fan-out, see below), and `crates/app-core/src/quit.rs` (lease names in the quit question).

- [ ] Event fan-out:
  - The manager has a single `set_on_change` hook today, and the Tauri publisher uses it (`app/src-tauri/src/main.rs:150`).
  - Add `pub fn add_state_listener(&self, f: impl Fn(&str, &ConnectionState) + Send + Sync + 'static)`. Call it for every key whose state changes, in the same place the change is published.
  - Also add a hook for a **user-initiated** disconnect, so that it differs from a lease release. Reuse the existing disconnect path with a `cause` flag rather than writing a second path.
- [ ] Trait seams, for tests:
  ```rust
  pub trait ControlHost: Send + Sync {
      fn items(&self) -> Vec<ConnectionItem>;
      fn state(&self, key: &str) -> ConnectionState;
      fn connect(&self, key: &str) -> Result<(), ErrorCode>;      // Managed → manager.connect(c,false); System → connect_system
      fn disconnect(&self, key: &str);
      fn setup_ready(&self) -> bool;
      fn ask_pairing(&self, req: PairingRequest) -> PairingAnswer; // blocks; UI implements it
      fn log(&self, line: String);                                  // "Control API" source
  }
  pub struct PairingRequest { pub name: String, pub executable: String, pub items: Vec<(String,String)> }
  pub enum PairingAnswer { Approved(Vec<String>), Denied, TimedOut }
  ```
- [ ] `ControlServer`:
  - `start(dir, host) -> Result<Self, …>` / `stop()`. The setting toggle calls these.
  - An accept thread, plus one thread per client. At most 8 clients; the 9th is accepted and closed at once.
  - A client must send `pair` or `hello` within 5 s (read timeout).
  - Requests are limited to 20/s with a token bucket; going over closes the connection.
- [ ] Per-client flow:
  - Run the peer check. A different uid is closed at once.
  - `pair`:
    - If a pairing is already pending → `busy`. If `pairing_blocked` → `denied`.
    - Otherwise `ask_pairing`. On `Approved(keys)`: create the token from `random_32`, add the client, save, and reply `{ok, token, client_id}`, then close.
    - On `Denied`/`TimedOut`: `record_rejection`, then `denied`.
  - `hello`:
    - Authenticate. On failure, sleep 1 s, send `unauthorized`, close, and log the attempt (without the token).
    - On success: `{ok, api:1}`, `touch`, save.
  - `list`: the client's allowed items that still exist, in `ordered_items()` order, as `{id,name,kind,state}`. `kind` is `openvpn|wireguard|strongswan|l2tp|cisco|sstp|system`.
  - `up`:
    - Check the allowlist (`not_allowed`), existence (`unknown_connection`) and setup (`setup_required`).
    - If the state is `Connecting`/`Disconnecting` and no lease is held → `busy`.
    - `acquire`, and call `connect` if the action says so.
    - Then forward state events for that key to this client until it becomes `Connected` (`{ok, state:"connected"}`) or `Failed(reason)` (`{ok:false, error:"failed", message: reason}`). The lease is released when the result is `Failed`.
    - An MFA cancel or timeout maps to `mfa_cancelled`/`mfa_timeout` if the manager's failure reason identifies it. Use the existing `auth_timeout_reason()`, and add a cancelled-reason helper next to it if one is missing.
  - `down`: `release` → `disconnect` if needed → `{ok}`.
  - `status`: subscribe; afterwards every state change of an allowed key is sent as an event.
  - Socket EOF or error → `release_session`, then disconnect where needed and log.
  - User disconnect → `on_user_disconnect`, then a `disconnected` event to the holders.
  - Revoke → close that client's sockets, which goes through the EOF path.
  - `stop()` → close everything (leases end) and unlink the socket.
- [ ] Quit integration: `quit.rs` names the leasing clients in the existing "connections are up" question. A test asserts that the text includes the client name. Add the l10n keys EN+HU to `crates/core/l10n/strings.json`.
- [ ] Tests, with a fake `ControlHost` driven by a scripted state machine and a real socket in a temp dir:
  - pair approved → token works in `hello`
  - pair denied ×3 → blocked
  - wrong token → `unauthorized` after ≥1 s
  - another path → `unauthorized`
  - `list` filters to the allowlist
  - `up` → connecting → waiting_for_mfa → connected
  - client EOF → `disconnect` called
  - two clients → disconnect only after both close
  - pre-existing connection → no disconnect
  - user disconnect → event, then no reconnect
  - revoke closes the socket and disconnects
  - 9th client refused
  - silent client closed after 5 s (use a configurable timeout in tests)
  - flood closed
  - `stop()` removes the socket
- [ ] Commit: `feat(app-core): local control server with socket leases`.

## Task 6: Tauri – setting, pairing window, Paired apps, "held by"

**Files:**
- `app/src-tauri/src/control.rs` (new): implements `ControlHost` on top of `AppState` and starts/stops the server from the setting.
- `app/src-tauri/src/prompts.rs` (pairing window): reuse the MFA prompt window pattern, which means its own label prefix `pair-*`, a label check in its commands, `mark_shown`/`prompt_ready` input lock, no focus steal, no default button.
- `app/src-tauri/src/commands.rs` + `build.rs` `COMMANDS` + `app/src-tauri/capabilities/*.json`: the new commands. The capability test at `commands.rs:455` must stay green.
- `app/ui/src/lib/…`: the pairing view and the Paired apps section in the Connections window. Add a "held by <name>" label to the menu rows and the list rows.
- `crates/app-core/src/view_model.rs`: the setting flag, the paired clients (id, name, path, allowed keys, last used, path-changed flag) and the lease holder names per key. **No tokens or hashes in the view model.**
- `crates/core/l10n/strings.json`: all new labels in EN+HU. The l10n coverage test must pass.

Steps:
- [ ] The setting "Allow other apps to control VPNs" / „Más appok vezérelhetik a VPN-eket”. It is stored in preferences the same way as the existing toggles, default off. Turning it on calls `ControlServer::start`; a failure (bad dir, another instance) is shown in the Setup/status area.
- [ ] Pairing window:
  - It shows the name, labelled "self-reported" / „a program saját megnevezése”.
  - It shows the executable path in full, in monospace.
  - Connection checkboxes, none selected.
  - "Allow" is enabled only when at least one connection is ticked.
  - Window close counts as Denied. A 2 min timeout counts as TimedOut.
  - Commands: `pairing_answer(id, allowed: Vec<String>)` and `pairing_ready(id)`. Both accept only the window's own id (label check). `allowed` is checked against the request's item list.
- [ ] Paired apps commands: `control_set_enabled(bool)`, `control_set_allowed(client_id, keys)` and `control_revoke(client_id)`. Validate the UUIDs and keys exactly like the existing commands do.
- [ ] Tests:
  - a unit test for each command's validation
  - the capability and command-list test
  - the l10n coverage test
  - `npm test`: a view test that the pairing view renders the path and leaves the button disabled until a connection is ticked
- [ ] Smoke test: extend `scripts/smoke/` with a debug-only hook (`MACVPN_SMOKE_*`, already gated by the release check) that approves the pairing. Then run the example client from Task 7 in the sandbox: pair, list, `up` against the fake runner, close, and check the disconnect. Run it with `SMOKE_LANG=en` and `SMOKE_LANG=hu`.
- [ ] Commit: `feat(app): pairing, paired apps and lease labels`.

## Task 7: example client and docs

**Files:** create `examples/macvpn-control-client/` (a workspace member, std + serde_json only) with `src/main.rs` and a README; create `docs/control-api.md` (EN) and `docs/control-api.hu.md` (HU); link both from README.md and the user guides.

- [ ] Client CLI:
  - `pair <name>`: prints the token **once** to stdout, so the integrator can put it in the Keychain.
  - `list`
  - `hold <connection-id>`: sends `up` and keeps the socket open until Ctrl-C or stdin EOF, printing the events.
  - The token comes from env `MACVPN_TOKEN` or stdin, so it is never in argv.
- [ ] Docs:
  - what the feature does
  - turning it on
  - pairing
  - the security model, including the accepted limitations
  - every request, reply and event with examples
  - error codes
  - lease rules
  - how-to: integrate a Rust app, store the token in the Keychain, and tie the socket lifetime to the remote session
  - troubleshooting: path changed after a rebuild → re-pair
- [ ] An integration test runs the example client against `ControlServer` with the fake host.
- [ ] Commit: `docs: control API guide and example client`.

## Task 8: version, manual checklist, review, release 1.1.0

- [ ] Version 1.1.0 in `tauri.conf.json`, `Cargo.toml` `[workspace.package]` and `app/ui/package.json` (plus the lock files). The root VERSION stays 7.
- [ ] `docs/manual-test-checklist.md`: a control API section that pairs the real Remote Desktop app and checks:
  - an OpenVPN up with MFA
  - quitting Remote Desktop brings the VPN down
  - a pre-existing connection stays up
  - revoking cuts the client off
  - after the setting is turned off, the socket is gone
- [ ] Run everything: fmt, clippy, `cargo test`, `scripts/test-root.sh`, npm test and build, smoke EN/HU, and `scripts/build-dmg.sh` with the release gate.
- [ ] An independent security review of the control API (spec sections 4–8), the new IPC commands and the windows. Fix until approved.
- [ ] Release: same flow as 1.0.0. That flow is: the user tests the DMG, the `public` sync commit, the `main` push (main only, never the working branches), the CI, the `v1.1.0` tag, the draft check against a local build, and the signing by the user.
