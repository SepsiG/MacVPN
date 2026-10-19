# MacVPN 1.1 credential prompt and live system-VPN list – implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax. The spec is `docs/superpowers/specs/2026-10-19-vault-folders-design.md`, sections 4 and 5 only; where this plan and the spec disagree, the spec wins. Follow the existing patterns of the crate you work in (look at a neighbouring module first).

**Goal:** before connecting, MacVPN asks in a modal for a username, password, PSK or key password that is required but not stored, can save it, and re-prompts once after a sign-in failure. Adding, changing or deleting a system VPN in macOS shows up in MacVPN at once (release 1.1.0, together with the control API).

**Base:** branch `control-api` (worktree `../macvpn-control`) after Tasks 1–7 of `docs/superpowers/plans/2026-10-19-control-api.md` (that plan is on the `control-api` branch) are merged. Work on a new branch `credential-prompt` from `control-api`, and merge it back into `control-api` before that plan's Task 8 (the 1.1.0 release), which this plan's Task 12 extends.

**Architecture:**
- **Pure logic:** the required-fields computation, the credential prompt's request/answer types and the sign-in-failure classifier in `crates/core/src/credentials.rs`.
- **Broker:** `crates/app-core/src/credential_prompt.rs`, a copy of the MFA `PromptBroker` pattern (`crates/app-core/src/prompt.rs`) for the credential window.
- **Manager:** `crates/app-core/src/manager.rs` asks through a new blocking hook before it calls the root layer or `SCNetworkConnection`, saves after success, and re-prompts once.
- **Control API:** a new state `waiting_for_credentials` and error `credentials_cancelled` in `crates/core/src/control/protocol.rs`, mapped in `crates/app-core/src/control.rs`.
- **Live list:** a watcher in `crates/platform-mac/src/sc_watch.rs` (source chosen by the Task 1 spike), a debouncer in `crates/app-core/src/live.rs` that wakes the existing `Poller`, and a "removed from macOS" read-only state for open system-VPN editors.
- **UI:** a `cred-<id>` Tauri window (`app/src-tauri/src/credentials.rs`, `app/ui/src/lib/CredentialPrompt.svelte`), and the live list in the menu and the Connections window.

**Tech:**
- Rust 1.99.1 (pinned), `zeroize` (already used by `mvpn`; add it to `macvpn-core` and `macvpn-app-core`), `core-foundation` / `core-foundation-sys` (already in `platform-mac`), `serde`/`serde_json`.
- Tauri 2, Svelte + TS.
- No other new crates, unless the subagent shows that one is needed and the reviewer agrees.

**Rules for every task:**
- TDD: write the failing test first.
- `cargo fmt --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --locked` must be green before each commit. For UI work also `cd app/ui && npm test && npm run build`.
- No `unsafe` outside `platform-mac` and `mvpn`.
- Never log a username, password, PSK, key password or code; never put one in argv or env. Typed secrets live in `zeroize` buffers and are wiped when the connect ends.
- Root `VERSION` stays 7 in this plan: no change to `crates/mvpn`.
- Every new user-facing string goes into `crates/core/l10n/strings.json` in EN and HU, with the right `scope`; the l10n coverage tests must pass.
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- The maintainer's forbidden company name never enters the repo (code, tests, fixtures, docs, commit messages).

**Key facts from the current code (read before starting):**
- `ConnectionManager::connect` (`manager.rs`) runs `connect_native` (L2TP/Cisco, `SCNetworkConnection`) or `connect_root` (`sudo -n mvpn up`, secrets on stdin through `Secrets::stdin_payload`). Both read `self.deps.secrets.secrets(&c.id)` and then call `code_secrets` (the MFA static challenge / "code after the password"). `connect_system` does the same for an unmanaged system VPN with stored secrets.
- A cancelled code prompt ends through `abandon_connect` as `Disconnected` with no event; `auth_cancelled_reason()` / `auth_timeout_reason()` mark the failures the control server maps to `mfa_cancelled` / `mfa_timeout` (`control.rs`, `resolve_pending`).
- `mvpn` failures reach the app as the last stderr line, in the language passed with `--lang` (`mvpn_client.rs`, `check`). The sign-in failures are the l10n keys `Authentication failed (AUTH_FAILED)` (`openvpn.rs`), `Authentication failed` (the MFA bridge's final state, `openvpn.rs` `mgmt_fail`) and `Authentication failed (wrong user name or password)` (`sstp.rs`). strongSwan has no separate EAP message in root layer 7 (only `IKE negotiation failed (details in the log)`).
- The SSTP user name is the config's `user=` line (required by `SSTPValidator`); `mvpn up sstp` ignores `username=` on stdin. The native (L2TP/Cisco) account is `NativeSettings::account` in the meta and is mirrored into the `Username` secret by the editor; `native::start_options` already passes `AuthName` / `XAuthName` at start.
- `importer::contains_encrypted_key(config)` detects an encrypted OpenVPN key. `exporter::OPENVPN_SECRET_BLOCKS` includes the inline `<auth-user-pass>` block.
- The status `Poller` (`crates/app-core/src/app.rs`) already refreshes every 3 s with an active connection and every 30 s otherwise, and `Poller::wake()` forces an immediate `ConnectionManager::refresh()`, which calls `NativeController::list()` (`scutil --nc list`).

---

## Task 1: spike – change notifications and native sign-in failures

**Goal:** decide, on real macOS 14 and 15 (the maintainer's Mac plus one other or a VM), which notification source reports system-VPN add/change/delete, and whether a native L2TP / Cisco IPsec sign-in failure can be told apart from other failures. No production code is merged from this task.

**Files:** create `crates/platform-mac/examples/sc_watch_spike.rs` (a throwaway, deleted again in Task 8) and `docs/superpowers/spikes/2026-10-19-live-system-list.md` (the findings; kept).

- [ ] Write the example with three candidate sources, each on its own thread with a `CFRunLoop`, printing a timestamped line per callback (never any secret, never the service's password):
  - **A:** `SCPreferencesCreate` + `SCPreferencesSetCallback` + `SCPreferencesScheduleWithRunLoop`, callback flags `kSCPreferencesNotificationCommit | kSCPreferencesNotificationApply`.
  - **B:** `SCDynamicStoreCreate` with `SCDynamicStoreSetNotificationKeys(nil, patterns)` for `Setup:/Network/Service/[^/]+` and `Setup:/Network/Service/[^/]+/(PPP|IPSec|VPN|Interface)`, plus `SCDynamicStoreCreateRunLoopSource`.
  - **C:** the poll baseline: `scutil --nc list` every second, printing a diff.
- [ ] Try each on: add, rename and delete an L2TP and an IKEv2 service in System Settings → VPN; install and remove a MacVPN-generated `.mobileconfig`; connect and disconnect a system VPN (state changes should *not* be required, but note whether they fire).
- [ ] Native sign-in failure: with a test L2TP and a test Cisco IPsec server (or a deliberately wrong password against a real one), record what `SCNetworkConnectionGetStatus` and `SCNetworkConnectionCopyExtendedStatus` return after a wrong password, a wrong PSK and an unreachable server (the `PPP` → `LastCause` and `IPSec` → `LastCause`/`Status` keys).
- [ ] Go/no-go criteria, written into the findings file with the raw observations:
  - **A source is chosen** if it fires for every add, rename and delete above within 2 s, 10 out of 10 times, on both macOS versions, and does not fire more than once per second while idle for 10 minutes. Prefer A over B if both pass.
  - **If neither passes:** the poll fallback (spec section 5): `scutil --nc list` every 5 s while a MacVPN window is open, every 30 s otherwise. Task 8 then implements only the poll change.
  - **Native sign-in failure is detectable** if a wrong password and a wrong PSK each give a `LastCause` value that an unreachable server never gives, on both versions. Then Task 5 implements the native re-prompt. Otherwise the native re-prompt is out of 1.1 (the spike file says so, and the user guide does not promise it).
- [ ] Commit: `docs(spike): system VPN change notifications and native sign-in failures` (the example and the findings).

## Task 2: core – required fields, prompt types, sign-in failure classifier

**Files:** create `crates/core/src/credentials.rs`; modify `crates/core/src/lib.rs` (`pub mod credentials;`), `crates/core/Cargo.toml` (`zeroize`), `crates/core/src/models.rs` (`AuthWaitKind::Credentials`). Tests in `crates/core/tests/credentials.rs`, using the existing fixtures under `Tests/Fixtures/` and the importer templates (`importer::template`).

- [ ] Types:
  ```rust
  #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
  pub enum CredentialField { Username, Password, Psk, KeyPassword }

  /// Which fields a connect needs, before looking at what is stored.
  #[derive(Debug, Clone, Default, PartialEq, Eq)]
  pub struct RequiredFields { pub fields: BTreeSet<CredentialField> }

  /// Typed values from the prompt; wiped on drop.
  #[derive(Default)]
  pub struct CredentialValues {
      pub username: Option<Zeroizing<String>>,
      pub password: Option<Zeroizing<String>>,
      pub psk: Option<Zeroizing<String>>,
      pub key_password: Option<Zeroizing<String>>,
  }

  pub struct CredentialPrompt {
      pub connection_id: String,
      pub connection_name: String,
      /// Only the fields to ask for, in display order.
      pub fields: Vec<CredentialField>,
      /// Pre-filled when one is stored (not a secret: the editor shows it too).
      pub username: Option<String>,
      /// The re-prompt after a sign-in failure ("Sign-in failed — check the username and password").
      pub retry: bool,
      pub deadline: PromptDeadline,
  }

  pub enum CredentialAnswer { Provided { values: CredentialValues, save: bool }, Cancelled }
  ```
  `CredentialValues` has a hand-written `Debug` that prints only which fields are set. `AuthWaitKind` gets a third variant `Credentials`.
- [ ] `pub fn required_fields(kind: VPNKind, config: Option<&str>) -> RequiredFields`:
  - **OpenVPN:** `Username` + `Password` when the config has an `auth-user-pass` directive with no file argument and no inline `<auth-user-pass>` block; `KeyPassword` when `importer::contains_encrypted_key(config)`. Reuse the OpenVPN tokenizer of `validators/openvpn.rs` (comments, quoting, inline blocks); do not write a second line parser.
  - **L2TP:** `Username`, `Password`, `Psk`.
  - **Cisco IPsec:** `Username`, `Password`, `Psk`. MacVPN generates Cisco profiles with `AuthenticationMethod = SharedSecret` only (`mobileconfig.rs`), so the spec's "PSK or certificate" is always PSK for a managed connection.
  - **IKEv2 (`Strongswan`):** `Username` + `Password` when a `local` section has `auth = eap…` (reuse `validators/strongswan.rs`'s `strip_comment` and section parsing); otherwise none.
  - **SSTP:** `Password` only. The user name is the config's `user=` line, which the validator requires.
  - **WireGuard:** none. `config` `None` (unreadable) → the kind's fixed fields only (OpenVPN and IKEv2: none, the root layer decides).
- [ ] `pub fn missing(required: &RequiredFields, stored: &Secrets) -> Vec<CredentialField>`: a field is missing when its stored value is `None` or empty. Display order: Username, Password, Psk, KeyPassword.
- [ ] `pub fn apply(values: &CredentialValues, base: &Secrets) -> Secrets`: the typed values override the stored ones field by field.
- [ ] `pub fn validate_values(values: &CredentialValues, fields: &[CredentialField]) -> Result<(), String>`: every asked field non-empty, at most 1024 bytes, and the same character rule as `Secrets::input_error` (no line breaks or control characters). The SSTP password additionally passes `SSTPValidator`'s password rule (find it via `password_rule` in `editor.rs`).
- [ ] `pub fn is_sign_in_failure(message: &str) -> bool`: true when the last non-empty line of `message`, trimmed, equals one of the three `mvpn` keys listed in "Key facts" in English or their `l10n::hungarian` translation. Nothing else matches (substring matches are not enough).
- [ ] `pub fn sign_in_failed_text() -> String`: `l10n::tr("Sign-in failed — check the username and password", &[])`.
- [ ] Tests:
  - OpenVPN: the `importer::template(Openvpn)` (bare `auth-user-pass`) → Username+Password; the same with an inline `<auth-user-pass>` block → none; `auth-user-pass` commented out with `#` and with `;` → none; every `Tests/Fixtures/mikrotik/*.ovpn` fixture gives the expected set (write the expectation per file); an encrypted PEM key (`-----BEGIN ENCRYPTED PRIVATE KEY-----`) → KeyPassword; a PKCS#12 that `contains_encrypted_key` flags → KeyPassword.
  - IKEv2: the template (`auth = eap-mschapv2`) → Username+Password; `auth = pubkey` → none; `auth = eap` inside a comment → none.
  - L2TP, Cisco → Username+Password+Psk; SSTP → Password; WireGuard → none.
  - `missing`: an empty stored string counts as missing; a stored username is not asked.
  - `apply` keeps the stored fields that were not typed.
  - `validate_values`: empty, a `\n`, U+2028 and 1025 bytes are rejected.
  - `is_sign_in_failure`: each key in EN and HU, also after a preceding stderr line; `IKE negotiation failed (details in the log)`, `Authentication cancelled` and a message that merely contains "Authentication failed" in the middle → false.
  - `CredentialValues`' `Debug` never contains the value.
- [ ] Commit: `feat(core): required credential fields and the credential prompt types`.

## Task 3: app-core – credential prompt broker

**Files:** create `crates/app-core/src/credential_prompt.rs`; modify `crates/app-core/src/lib.rs`, `crates/app-core/src/notify.rs` (window label helpers), `crates/app-core/Cargo.toml` (`zeroize`). Model it line by line on `crates/app-core/src/prompt.rs` (`PromptBroker`) and `crates/app-core/src/pairing.rs` (`PairingBroker`).

- [ ] View (no secret in it; part of the view model):
  ```rust
  #[derive(Debug, Clone, PartialEq, Serialize)]
  #[serde(rename_all = "camelCase")]
  pub struct CredentialPromptView {
      pub id: u64,
      pub connection_id: String,
      pub connection_name: String,
      /// `username`, `password`, `psk`, `keyPassword`.
      pub fields: Vec<&'static str>,
      pub username: Option<String>,
      /// The localized "Sign-in failed …" line, only on a re-prompt.
      pub message: Option<String>,
      pub deadline: f64,
  }
  ```
- [ ] `pub enum RawCredentialAnswer { Connect { values: CredentialValues, save: bool }, Cancel }`: an answer from the window before the broker's checks.
- [ ] `CredentialBroker`:
  - `present(&self, prompt: CredentialPrompt, now: Date) -> CredentialAnswer`: blocks until answered, dismissed or expired; at most one open prompt per connection (a new one cancels the previous one).
  - `answer_checked(&self, id: u64, answer: RawCredentialAnswer, now: Instant) -> Result<(), String>`: the prompt must be open; only Cancel is taken before `ARM_DELAY` (1 s) has passed since the later of `mark_shown` and `mark_loaded`; a `Provided` answer must name exactly the prompt's fields and pass `credentials::validate_values`.
  - `mark_shown`, `mark_loaded`, `dismiss(connection_id)`, `pending() -> Vec<CredentialPromptView>`, `prompt_for_connection`, `set_on_change`.
  - Expiry: the prompt's `PromptDeadline` (2 minutes, the MFA value). An expired prompt answers `Cancelled` (see "Resolved" at the end).
- [ ] `pub fn parse_credential_answer(action: &str, values: BTreeMap<String, String>, save: bool) -> Result<RawCredentialAnswer, String>`: `action` is `connect` or `cancel`; keys only from the four field names; `cancel` must carry no values. The strings are moved into `Zeroizing` at once.
- [ ] `notify.rs`: `credential_window_label(id) -> String` (`cred-<id>`) and `credential_id_of_label(&str) -> Option<u64>`, with the same digit checks as `prompt_id_of_label`. Generalize `PromptTracker` to be generic over the view (or add a second tracker with the same logic) so opened/closed credential prompts produce window open/close and notification changes.
- [ ] Tests (fake clock and `Instant`s, like `prompt.rs`' tests):
  - present → answer → the caller gets the values; the view never contains them (serialize the view and search for the typed value)
  - Connect within the first second → refused; Cancel within the first second → taken
  - shown but not loaded → not armed; loaded but not shown → not armed
  - a missing field, an extra field, an unknown key and an empty value → refused
  - a second prompt for the same connection cancels the first
  - `dismiss` → `Cancelled`; deadline → `Cancelled`
  - label helpers: `cred-12` ↔ 12; `cred-`, `cred-x`, `prompt-1`, 20 digits → `None`
- [ ] Commit: `feat(app-core): credential prompt broker`.

## Task 4: app-core – the credential flow in the manager

**Files:** modify `crates/app-core/src/manager.rs`, `crates/app-core/src/deps.rs`; tests in `crates/app-core/tests/credential_prompt.rs` with the mocks of `crates/app-core/tests/common/mod.rs` (extend `MockRoot` so a scripted `up` can fail with a given message, and `MemorySecrets` so writes are recorded).

- [ ] Dependencies:
  - `Dependencies` gets `pub secret_writer: Option<Arc<dyn SecretWriter>>` (`None` in `Dependencies::new`; the Tauri app sets it to the same Keychain store as the editors).
  - A new hook `pub type CredentialHandler = Arc<dyn Fn(CredentialPrompt) -> CredentialAnswer + Send + Sync>` with `set_credential_handler`, and `set_dismiss_credentials(Fn(&str))`, stored in `Hooks` like `prompt_handler` / `dismiss_prompt`. Without a handler there is no prompt and the connect goes on with the stored secrets exactly as today, so the existing manager tests and headless uses keep their behaviour.
- [ ] `fn ask_credentials(&self, key, name, fields, username, retry) -> Option<CredentialValues>`: sets `AwaitingAuth(AuthWait { kind: AuthWaitKind::Credentials, deadline })` before calling the handler (same locking rules as `ask`: never hold the mutex while the handler runs), clears it afterwards, and on `Cancelled` inserts the key into a new `credentials_cancelled: HashSet<String>` in `Inner`.
- [ ] `fn credential_secrets(&self, key: &str, name: &str, item: &Uuid, kind: VPNKind, config: Option<&str>, native_account: Option<&str>, base: Secrets, retry: bool) -> Result<Option<(Secrets, Option<PendingSave>)>, String>`, called in `connect_root`, `connect_native` and `connect_system` right after the stored secrets are read and **before** `code_secrets`, so the MFA code is asked after the credentials:
  - Required fields: `credentials::required_fields(kind, config)`. For a managed native connection, a stored `native.account` counts as the username. For a system VPN (`connect_system`) there is **no** pre-connect prompt, because MacVPN cannot know whether macOS holds the secrets in the profile (see "Resolved"); only the re-prompt applies, and only if Task 1 found native sign-in failures detectable.
  - `retry == false`: ask only for `credentials::missing(…)`; nothing missing → no prompt. `retry == true`: ask for every required field except `Psk`/`KeyPassword` that is stored, with the stored username pre-filled.
  - `None` (cancelled) → the caller ends like a cancelled code prompt: `abandon_connect` (state `Disconnected`, no `ConnectionEvent`, no notification).
  - `PendingSave { id: Uuid, values: CredentialValues, native_account: Option<String> }` is returned only when `save` was ticked.
- [ ] Save after success, never before: `Inner` gets `pending_saves: HashMap<String, PendingSave>`. In `settle_successes` (the first transition to `Connected` of a user-started connect), take the entry and, outside the lock, write each value with `SecretWriter::set` (and for a native connection with a typed username, save `native.account` through `deps.store.save(&c, None)` and reload). On `Failed`, `Disconnected` or a new connect the entry is dropped (and so zeroized). A failing write is logged without the value and does not change the connection state.
- [ ] Re-prompt once (root kinds): in `connect_root`, when `deps.root.up` returns `Err(msg)` with `credentials::is_sign_in_failure(&msg)`, the connect has not been re-prompted yet, the key's epoch is still the token, and the kind has required credential fields, then ask again with `retry = true` and run `code_secrets` and `up` once more. A second failure, or a failure that is not a sign-in failure, ends as `Failed(msg)` exactly as today. The re-prompt does not loop.
- [ ] Native re-prompt (only if Task 1 said "detectable"): add `fn last_sign_in_failure(&self, service_id: &str) -> bool` to `NativeController` with a default `false`. When `refresh` ends an `AwaitingNative` op as failed and this returns true for a connect that has not been re-prompted, the manager emits a new `ConnectionEvent::SignInFailed { connection_id, name }` instead of `Failed`; the app reacts by calling `ConnectionManager::reconnect_after_sign_in_failure(key)`, which runs the connect again with `retry = true`. Otherwise skip this step and note it in the commit message.
- [ ] Zeroize: typed values only live in `CredentialValues` (`Zeroizing`). After `deps.root.up` / `deps.native.start` returns, the merged `Secrets` built from them is wiped: add `zeroize` support to `models::Secrets` (`impl Zeroize`, and `Drop` that zeroizes, if the compiler accepts it everywhere; otherwise call `zeroize()` explicitly at the end of each connect path).
- [ ] Tests:
  - OpenVPN with bare `auth-user-pass` and nothing stored → the handler gets `[username, password]`; the answer reaches `MockRoot.up`'s `Secrets`; nothing is written yet; after the scripted refresh reports `connected`, the writer has both values
  - "Save" not ticked → nothing is ever written
  - username stored, password not → only `[password]`, username pre-filled
  - everything stored → no prompt
  - Cancel → state `Disconnected`, no `ConnectionEvent`, `up` never called, nothing written
  - while the handler blocks, `state(key)` is `AwaitingAuth` with kind `Credentials`
  - static challenge config + missing password → the credential prompt comes first, then the code prompt
  - WireGuard / IKEv2 with `auth = pubkey` → no prompt
  - L2TP managed with empty PSK → `[psk]`; the typed PSK reaches `MockNative.start`
  - system VPN with nothing stored → no prompt
  - `up` fails with `Authentication failed (AUTH_FAILED)` → one re-prompt with `retry = true`, a second `up`; a second failure → `Failed` with that message and no third prompt
  - `up` fails with `IKE negotiation failed (details in the log)` → no re-prompt
  - a re-prompt cancelled → `Disconnected`, no notification
  - the user disconnects while the prompt is open → the prompt is dismissed (`dismiss_credentials` called) and no `up` follows
  - a failed connect after "Save" → nothing written
  - (if native re-prompt is implemented) a native sign-in failure → `SignInFailed` event, `reconnect_after_sign_in_failure` asks with `retry = true`
- [ ] Commit: `feat(app-core): ask for missing credentials before connecting`.

## Task 5: control API – `waiting_for_credentials` and `credentials_cancelled`

**Files:** modify `crates/core/src/control/protocol.rs`, `crates/app-core/src/control.rs`, `docs/control-api.md` and `docs/control-api.hu.md` (from control-api Task 7), `examples/macvpn-control-client/src/main.rs` if it matches state strings; tests in `crates/core/tests/control_protocol.rs` and `crates/app-core/tests/control_server.rs`.

- [ ] Protocol, API version stays `1`:
  - `WireState::WaitingForCredentials` → `"waiting_for_credentials"`; `wire_state` maps `AwaitingAuth(AuthWait { kind: Credentials, .. })` to it, and the other `AwaitingAuth` kinds to `WaitingForMfa` as before.
  - `ErrorCode::CredentialsCancelled` → `"credentials_cancelled"`.
- [ ] Server: `Pending` gets `saw_credentials: bool` next to `saw_mfa` (set on `WaitingForCredentials`). A `Disconnected` that the user did not cause ends the pending `up` with `credentials_cancelled` when the **last** wait seen was for credentials, `mfa_cancelled` when it was for MFA, `failed` otherwise. A `Failed` still maps through `auth_timeout_reason` / `auth_cancelled_reason` as today.
- [ ] Compatibility, written into both control-API docs:
  - Both values are additions to API v1 and ship in the same release as the API (1.1.0).
  - Clients must treat an unknown `state` value as "in progress" and an unknown `error` code as `failed`; future v1 additions follow the same rule. Say so in the protocol section, and handle it that way in the example client.
- [ ] Tests:
  - `wire_state` for each `AuthWaitKind`
  - the new strings round-trip in `event_state` / `reply_err`
  - server with the fake host: `up` → `connecting` → `waiting_for_credentials` → connected
  - `up` → `waiting_for_credentials` → `disconnected` → `credentials_cancelled`
  - credentials then MFA, MFA cancelled → `mfa_cancelled`
  - the lease is released after `credentials_cancelled` (no leftover holder)
  - the example client prints an unknown state without failing
- [ ] Commit: `feat(control): waiting_for_credentials and credentials_cancelled`.

## Task 6: Tauri – the credential window

**Files:**
- create `app/src-tauri/src/credentials.rs` (window open/close sync, commands, close = cancel), modelled on `app/src-tauri/src/prompts.rs`
- modify `app/src-tauri/src/main.rs` (`connect_hooks`: `set_credential_handler` → `CredentialBroker::present`, `set_dismiss_credentials`, the publisher on broker change, `secret_writer` in `Dependencies`; if Task 4 added `SignInFailed`, spawn `reconnect_after_sign_in_failure` off the main thread in the event hook), `app/src-tauri/src/state.rs` (`credential_broker`, `credential_tracker`), `app/src-tauri/src/notifications.rs` ("Credentials needed" notification, click focuses the window, removed when the prompt closes)
- `app/src-tauri/build.rs` `COMMANDS`: `answer_credentials`, `credentials_ready`; create `app/src-tauri/capabilities/credentials.json` (windows `cred-*`: `core:event:allow-listen/unlisten`, `allow-get-view-model`, `allow-answer-credentials`, `allow-credentials-ready`, nothing else); the capability test in `commands.rs` must stay green
- `crates/app-core/src/view_model.rs`: `credential_prompts: Vec<CredentialPromptView>`
- create `app/ui/src/lib/CredentialPrompt.svelte` and `app/ui/src/lib/credentials.ts` (+ `credentials.test.ts`); route `cred-` in `app/ui/src/App.svelte`; use the 1.1 card tokens of `app.css` and `Icon.svelte`
- `crates/core/l10n/strings.json`: the window strings (title "Credentials needed", field labels, "Save in vault" — in 1.1 the label is "Save" with the hint "Stored in the macOS Keychain"; see "Resolved", Connect, Cancel, the retry line) in EN+HU

Steps:
- [ ] Window rules, the same as the MFA window: label `cred-<id>`, `always_on_top`, `visible(false)` + `focused(false)` then `order_front_regardless` (no focus steal, no app activation), `mark_shown` on the main thread, `credentials_ready` → `mark_loaded`, the 1 s input lock in the broker, **no default button** (Return in a field does nothing; Connect needs a click or Space on the focused button), the close button = Cancel, the window closes when the prompt ends.
- [ ] Contents: the connection name; on a re-prompt the "Sign-in failed — check the username and password" line; only the asked fields (username as text, pre-filled; the others as password inputs); the "Save" checkbox, ticked by default; Connect (enabled once every field is non-empty) and Cancel.
- [ ] Commands:
  - `answer_credentials(window, id, action, values: BTreeMap<String,String>, save: bool)`: label check (`credential_id_of_label(window.label()) == Some(id)`), then `parse_credential_answer`, then `answer_checked`. Never log `values`.
  - `credentials_ready(window, id)`: label check, `mark_loaded`.
- [ ] The UI clears its input values from the DOM and its state right after sending the answer.
- [ ] Tests:
  - Rust unit tests for the label check and the argument validation of both commands
  - the capability/command list test and the l10n coverage test
  - `credentials.test.ts`: field ordering, the Connect enablement rule, the label parser
  - `npm test` view test: the window renders only the asked fields, the username is pre-filled, Connect is disabled until every field has a value, and there is no `type="submit"` button and no `autofocus`
- [ ] Commit: `feat(app): credential prompt window`.

## Task 7: core + platform-mac – the system-VPN watcher (per the spike)

**Files:** create `crates/platform-mac/src/sc_watch.rs`; modify `crates/platform-mac/src/sc_ffi.rs` (the FFI declarations, documented and kept small like the existing ones), `crates/platform-mac/src/lib.rs`. **Skip this task** if Task 1 chose the poll fallback.

- [ ] API:
  ```rust
  /// Calls `on_change` (on the watcher's own thread) when the system's network service setup changes.
  pub struct SystemVpnWatcher { /* thread, CFRunLoop handle */ }
  impl SystemVpnWatcher {
      pub fn start(on_change: impl Fn() + Send + 'static) -> io::Result<SystemVpnWatcher>;
      /// Stops the run loop and joins the thread.
      pub fn stop(self);
  }
  ```
  The source is the one Task 1 chose (SCPreferences callback or SCDynamicStore keys). The callback does nothing but call `on_change`; no listing happens on the watcher thread.
- [ ] `start` fails cleanly (an `io::Error`, no panic) when the SC call returns NULL / false; the app then uses the poll fallback (Task 8).
- [ ] Tests:
  - `start` then `stop` returns within 1 s and leaks no thread (start/stop 50 times in a loop)
  - `on_change` panicking does not abort the process (catch it on the watcher thread)
  - an `#[ignore]`d manual test documented in the spike file: run it, add a VPN in System Settings, see the callback
- [ ] Commit: `feat(platform-mac): system VPN change watcher`.

## Task 8: app-core + Tauri – debounced reload, poll fallback, removed editors

**Files:** create `crates/app-core/src/live.rs`; modify `crates/app-core/src/app.rs` (`poll_interval`), `crates/app-core/src/connections.rs`, `crates/app-core/src/editor.rs` (`EditorView`), `crates/app-core/src/view_model.rs`, `app/src-tauri/src/main.rs`, `app/src-tauri/src/state.rs`; delete `crates/platform-mac/examples/sc_watch_spike.rs`.

- [ ] Debouncer (pure, fake clock):
  ```rust
  pub const LIVE_DEBOUNCE: Duration = Duration::from_millis(500);
  pub struct Debouncer { /* last trigger, armed */ }
  impl Debouncer {
      pub fn trigger(&mut self, now: Instant);
      /// `true` once, `LIVE_DEBOUNCE` after the last trigger of a burst.
      pub fn take_due(&mut self, now: Instant) -> bool;
  }
  ```
  A small thread in the app (`macvpn-live`) waits on a condvar, and once `take_due` fires it calls `Poller::wake()`, which runs a full `ConnectionManager::refresh()` (that already re-lists the system services and rebinds the managed native ones).
- [ ] Poll fallback: `poll_interval(has_active: bool, window_open: bool, live: bool) -> f64`:
  - `live == true` (a watcher runs): unchanged, 3 s active / 30 s idle.
  - `live == false`: 3 s active; otherwise 5 s while a MacVPN window (menu popover, Connections, System Status, Update) is open, else 30 s.
  - `Poller::run` takes the two new closures. The app tracks "a window is open" from the existing window events (`dock.rs` already counts the regular windows; reuse that and add the popover's visibility).
- [ ] Removed system VPNs:
  - `ConnectionsModel::services_changed(&self, present: &HashSet<String>)`, called after each refresh (from the manager's `set_on_change` path in the app): every draft whose key is a system-VPN service ID that is no longer listed gets `removed = true`; if it is listed again with the same ID, `removed = false`.
  - `EditorView` gets `pub removed: bool`. `update_editor`, `save_editor` and `forget_secrets` on a removed draft return `Err` with `l10n::tr("This VPN was removed from macOS", &[])`.
  - `ManageView` gets `pub selected_removed: bool`: the selection is kept when the selected system VPN disappears, so its detail stays visible.
  - Its stored secrets are **not** deleted automatically (the service may return; folder placement retention is a 1.2 feature).
- [ ] Wire-up in `main.rs`: start `SystemVpnWatcher` after `ReloadConnections` (not in the sandbox; the smoke test drives a fake source, Task 10); if `start` fails, log once and run with `live = false`. Stop it on quit.
- [ ] Tests:
  - debouncer: 1 trigger → due after 500 ms, not before; 10 triggers 100 ms apart → exactly one due, 500 ms after the last; triggers after a due → a second due
  - `poll_interval` table for all 8 combinations
  - `Poller::run` with a fake clock and `live = false`, window open → refresh every 5 s
  - a refresh where the open system editor's service vanished → `removed`, save refused with the message, `selected_removed` true; it comes back → editable again, the typed draft kept
  - a managed connection's draft is never marked removed by this path
- [ ] Commit: `feat(app): live system VPN list`.

## Task 9: UI – live list and read-only editor

**Files:** `app/ui/src/lib/manage/SystemDetail.svelte`, `app/ui/src/lib/manage/EditorHost.svelte` (or wherever the system editor's form is), `app/ui/src/lib/manage/Sidebar.svelte`, `app/ui/src/lib/Menu.svelte`; tests next to them.

- [ ] The menu and the Connections list already re-render from the view model; check that a row added or removed by a refresh appears or disappears without reopening the window or the popover, and that the selection of a vanished row is kept (the detail stays) only while `selectedRemoved` is true.
- [ ] A removed editor shows a banner "This VPN was removed from macOS" in the card style, disables every input and the Save / Forget buttons, and keeps the Log tab readable.
- [ ] Tests: a view test with a view model where `removed = true` → banner shown, inputs disabled; a row list update keeps the scroll position and the selection.
- [ ] Commit: `ui: live system VPN list and the removed-VPN editor`.

## Task 10: smoke tests

**Files:** `app/src-tauri/src/smoke.rs`, `scripts/smoke-manage.sh`, new `scripts/smoke/credentials.js`, `scripts/smoke/live.js`.

- [ ] Credential prompt:
  - Seed an OpenVPN connection `CRED` (new fixed UUID, e.g. `a1111111-2222-4333-8444-555555555555`) with a bare `auth-user-pass` config and no secrets.
  - The smoke driver connects it; `credentials.js` runs in the `cred-*` window: it checks that exactly the username and password fields are shown, waits until the inputs accept input (the 1 s lock), types `smoke-user` / a fixed test password, leaves "Save" ticked and clicks Connect.
  - `FakeRoot::up` logs `up <id> username=set password=set` (never the values). Then the state is connected, and the in-memory secret store holds both values (checked through `SecretReader`, logged as `saved=yes`).
  - A second connect of the same connection shows no prompt.
  - A third seeded connection whose `FakeRoot::up` fails with `Authentication failed (AUTH_FAILED)` once shows the re-prompt with the retry line; `credentials.js` answers Cancel; the state ends `disconnected` and no failure notification event is emitted.
- [ ] Live list:
  - Add a smoke-only `FakeNative` (debug builds only, like `FakeRoot`) whose service list the driver can change, and drive `Debouncer::trigger` directly in place of the real watcher.
  - `live.js` (Connections window): opens a fake L2TP system VPN's editor, the driver removes that service, the script waits for the banner and the disabled inputs, the driver adds a new service, the script waits for its row. The menu shows the new row too.
- [ ] `scripts/smoke-manage.sh` checks the new `MacVPN smoke: …` lines; run with `SMOKE_LANG=en` and `SMOKE_LANG=hu` (the window texts are checked in both languages).
- [ ] The release gate in `scripts/build-dmg.sh` still finds no `MACVPN_SMOKE` in the release binary.
- [ ] Commit: `test(smoke): credential prompt and live system list`.

## Task 11: docs

**Files:** `docs/user-guide.en.md`, `docs/user-guide.hu.md`, `docs/how-to.en.md`, `docs/how-to.hu.md`, `docs/manual-test-checklist.md` (Hungarian, like the rest of that file), `README.md` (feature list).

- [ ] User guide: the credential prompt (when it appears, "Save", the one re-prompt, Cancel), and that system VPNs update live. In 1.1 "Save" stores into the macOS Keychain; the 1.2 vault changes that.
- [ ] How-to: "Connect without storing the password" (untick Save).
- [ ] Manual checklist, a 1.1 section:
  - OpenVPN with `auth-user-pass` and no stored password against a real server: prompt, Connect, Save → next connect without a prompt
  - a wrong password → one re-prompt with the message → a right one connects; a second wrong one fails with the normal notification
  - Cancel → no notification
  - the prompt does not steal focus while typing in another app; Return does not submit
  - delete a system VPN in System Settings while the menu is open → the row disappears within about a second; with its editor open → the banner and read-only form
  - add a VPN in System Settings with the Connections window open → it appears
  - (if implemented) L2TP with a wrong password → re-prompt
- [ ] Commit: `docs: credential prompt and live system list`.

## Task 12: review and release 1.1.0

This task runs **together with** Task 8 of `docs/superpowers/plans/2026-10-19-control-api.md` (branch `control-api`): 1.1.0 ships the control API, the card UI, the Dock icon, the credential prompt and the live system list in one release. Do not run that Task 8 separately.

- [ ] Merge `credential-prompt` into `control-api` (no fast-forward), then do control-api Task 8's version bump (1.1.0 in `tauri.conf.json`, `Cargo.toml` `[workspace.package]`, `app/ui/package.json` and the lock files). Root `VERSION` stays 7.
- [ ] Run everything: fmt, clippy, `cargo test`, `scripts/test-root.sh`, `npm test` and `npm run build`, smoke EN/HU, `scripts/build-dmg.sh` with the release gate.
- [ ] Independent security review of this plan's work in addition to the control API review of control-api Task 8:
  - typed secrets: never in the view model, logs, argv, env, or the webview after the answer; zeroized after the connect; saved only after success and only with "Save"
  - the `cred-*` capability grants nothing else; the label check on both commands
  - the 1 s lock, no focus steal, no default button
  - the watcher thread cannot be driven to a busy loop; the debounce bounds the refresh rate
  - control API: no new information leaks (a client sees only `waiting_for_credentials`)
  Fix until approved.
- [ ] The manual checklist (control-api Task 8's section and this plan's Task 11 section) on the DMG.
- [ ] Release: the same flow as in control-api Task 8 (the user tests the DMG, the `public` sync commit, the `main` push — main only, never the working branches —, CI, the `v1.1.0` tag, the draft check against a local build, the signing by the user).

---

## Resolved points (spec ambiguities and how this plan settles them)

- **System VPNs get no pre-connect prompt.** For an unmanaged system VPN MacVPN cannot tell whether macOS keeps the password and PSK in the profile, so asking up front would nag for secrets macOS already has. They only get the sign-in-failure re-prompt, and only if Task 1 shows that a native sign-in failure is detectable.
- **SSTP asks only for the password.** The SSTP user name is the config's `user=` line (required by the validator, and the root layer ignores a stdin user name).
- **IKEv2 EAP sign-in failures do not re-prompt in 1.1.** Root layer 7 has no distinct EAP failure message, and 1.1 does not change the root layer. Plan `2026-10-19-vault-folders.md` adds the message with root VERSION 8.
- **Save happens after the connection comes up.** "Save" stores the typed values only once the connect reached `connected`, so a wrong password is never stored, and a failed attempt leaves the store as it was.
- **"Save in vault" in 1.1.** There is no vault in 1.1. The checkbox is labelled "Save", with the hint "Stored in the macOS Keychain", and writes through the existing `SecretWriter`. In 1.2 the label becomes "Save in vault", and the same code path writes to the vault through the same trait.
- **Expiry.** The credential prompt uses the MFA prompt's 2-minute deadline. An expired prompt counts as Cancel (no notification, `credentials_cancelled` for the control API), because the user did nothing wrong and there is no server deadline.
- **Re-prompt fields.** The re-prompt asks again for the username and password (username pre-filled); a stored PSK or key password is not asked again.
- **Cisco "PSK or certificate".** MacVPN-generated Cisco profiles always use a shared secret, so the PSK is required for managed Cisco connections.
- **API v1 compatibility.** The new state and error code ship in the same release as API v1. The protocol docs add the rule that clients treat unknown states as "in progress" and unknown error codes as `failed`.
- **Live reload.** It wakes the existing poller (a full refresh), so there is one refresh path with its epoch rules, and no second system-list code path.
