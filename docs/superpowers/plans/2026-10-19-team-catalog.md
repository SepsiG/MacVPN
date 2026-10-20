# MacVPN 1.3 team catalog (shared connections) – implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax. The spec is `docs/superpowers/specs/2026-10-19-team-catalog-design.md` (all sections). It builds on `docs/superpowers/specs/2026-10-19-vault-folders-design.md` (the version with the review updates in sections 3a and 3b) and on plan B, `docs/superpowers/plans/2026-10-19-vault-folders.md`. Where this plan and the spec disagree, the spec wins. Follow the existing patterns of the crate you work in (look at a neighbouring module first).

**Goal:** an administrator publishes a set of connections, their folder tree, named credential slots and, optionally, team secrets as one signed and encrypted `<name>.macvpncatalog` file. Every subscribed MacVPN fetches it from an HTTPS URL or a file path, verifies it against the pinned publisher key, decrypts it with the team key, validates it like an import and applies additions, changes and removals in one transaction. Each user keeps their own usernames, passwords, OTP secrets, pins, ranking and collapsed folders. Release 1.3.0.

**Base:** the released 1.2.0 (`vault` merged with `control-api`, see plan B and `docs/superpowers/plans/2026-10-19-credential-prompt-live-system.md`). Work on a new branch `catalog` from that point. The root layer does not change (root `VERSION` stays 8).

**Architecture:**
- **Core (`crates/core/src/catalog/`, behind the existing cargo feature `vault`):** the key types (team key, admin signing key, publisher key, fingerprint), the catalog payload and its validation, the file format (seal, sign, open with the ordered checks), the subscription string and the source rules, the pure apply/diff planner and the pure publish builder. The vault gets schema v2 with the catalog tables, the repositories, the read-only guard for catalog-owned rows, and backup payload v2. All platform-independent and without `unsafe`.
- **platform-mac:** `CurlCatalogFetcher`, the HTTPS source on top of the existing curl client (`http.rs`): conditional GET, the bearer token on curl's stdin, hop-by-hop redirects, the 8 MB cap.
- **app-core:** `FileCatalogFetcher` (the file source with a read timeout), `CatalogService` (subscribe, refresh, verify, apply, unsubscribe, pending removals, notifications), the refresh schedule with back-off, the connect-time integration of credential slots, and `Publisher` (admin keys, publish, team-key rotation).
- **Tauri / UI:** the "Team catalogs" section, the "Add team catalog…" dialog, the "Team" badges and read-only editors, the admin key page, the publish wizard and the publications list, all on the 1.1 card design.

**Tech:**
- Rust 1.99.1 (pinned).
- No new crates. Ed25519 signing uses `ed25519-dalek =3.0.0`, already a core dependency for update signatures (`update.rs`, `UpdateSignature`); its default features include `zeroize`, and `SigningKey::from_bytes` needs no `rand` (the 32 seed bytes come from `vault::Entropy`). Encryption is the vault's `chacha20poly1305 =0.11.0` (XChaCha20-Poly1305). Hashing is the existing `sha2`. Deterministic item ids use `uuid`'s `Builder::from_custom_bytes` (UUID v8), so no new `uuid` feature is needed.
- The catalog code is compiled only with `macvpn-core/vault`, which `mvpn` never enables; the release gate (Task 22) checks that the root binary contains no catalog code.
- Tauri 2, Svelte + TS. No other new crates unless the subagent shows a need and the reviewer agrees.

**Rules for every task:**
- TDD: write the failing test first.
- `cargo fmt --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `CI=1 cargo test --workspace --locked` green before each commit. For UI work also `cd app/ui && npm test && npm run build`. Root-layer work is not expected; if a task touches `mvpn`, also `scripts/test-root.sh`.
- No `unsafe` outside `platform-mac` and `mvpn`.
- Never log, and never put in argv or env: a team key, an admin signing key, a bearer token, a subscription string, a catalog payload or any config or secret in it, a backup or admin-key-file password, or the master password. The catalog service logs only events: subscribed, refreshed (not modified / applied vN: a added, c changed, r removed), refused (the error kind, never a value), unsubscribed, published vN, team key rotated, admin key generated / imported / promoted. A URL is logged without its query string; a file source by its file name only.
- Key material lives only in `Zeroizing` buffers, with a redacted `Debug`. The team key, the admin keys, the bearer token and the subscription string are never in the view model or in webview storage. They cross IPC only as typed input, and the team key once more when it is shown at creation.
- Every new user-facing string goes into `crates/core/l10n/strings.json` in EN and HU (right `scope`). The l10n coverage tests (`crates/app-core/tests/l10n_coverage.rs`, the `mvpn` call-site test, `npm test`) must pass.
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- The maintainer's forbidden company name never enters the repo (code, tests, fixtures, docs, commit messages). Use neutral examples such as "Office AD", "Acme VPN" and `vpn.example.com`.

**Key facts from the current code (read before starting):**
- **Vault crypto (`crates/core/src/vault/keys.rs`):** `KdfParams` (floor 64 MiB / t ≥ 3, ceiling 1 GiB / t ≤ 256 / p ≤ 16, `DEFAULT = { m_kib: 65536, t: 32, p: 1 }`, `strengthened()` never lowers, `insecure_for_tests()` only with core's `test-support` feature), `derive_kek` (Argon2id), the XChaCha20-Poly1305 wrap with a fresh 24-byte nonce and a constant AAD, `Dek` with a redacted `Debug`. Randomness comes only through `vault::Entropy` (`entropy.rs`; `FixedEntropy` for known-answer tests, `platform-mac::SystemEntropy` with `getentropy` in production).
- **Recovery key (`vault/recovery.rs`):** hand-written Crockford base32 (alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`), case-insensitive, `O`→`0`, `I`/`L`→`1`, `-` and spaces ignored, 6 groups of 4 = 24 symbols = 120 bits. The encoder and decoder are private to that file today.
- **Backup (`vault/backup.rs`):** the 64-byte header (`MVPNBKUP`, format, KDF id, parameters, salt, nonce) authenticated as AAD; one generic `BackupError::CannotOpen` for every wrong password, damaged byte, truncation or unknown KDF; `NewerVersion` checked first; `MAX_KDF` ceiling checked before the KDF runs; the payload is JSON in a right-sized `Zeroizing` buffer, secrets base64 inside it, the `serde_json::Value` trees wiped (`WipedValue`, `Counter`, both private); `validate` treats the payload as untrusted (name rules in stored form, `check_username`/`check_password`/`check_item`, `mfa::has_control` for secrets, `MAX_ITEMS`, no duplicates, folders form a tree); `read_backup_file` (`O_NOFOLLOW | O_NONBLOCK`, regular file only, `take(cap + 1)`); `write_backup` via `exporter::write` (temp file, `O_EXCL|O_NOFOLLOW`, 0600, fsync, rename, fsync of the directory, partial file removed). `PAYLOAD_VERSION` is 1 and the payload-migration list (`MIGRATIONS`) is empty. Restore: `plan_restore`, `merge(ConflictMode)`, `replace`; a merge drops restored acknowledged risky directives unless the same connection exists with the same config.
- **Update signing (`crates/core/src/update.rs`, `UpdateSignature`):** a domain-separated message (`"macvpn-update-v1\n…"`), `VerifyingKey::from_bytes`, `verify_strict`, two embedded keys (primary and backup). Only verification exists in the app; signing is `scripts/sign-release.sh` (OpenSSL).
- **Vault database (`vault/db.rs`, `vault/schema.rs`):** SQLCipher, `CURRENT_SCHEMA = 1`, `MIGRATIONS` appended, never edited; an older database is backed up and migrated in one transaction; a newer one opens read-only (`NewerSchema`). Every write goes through `Vault::transaction`. `VaultError` has `Locked`, `Constraint`, `LinkedToCredential`, `InvalidBackup`, `Tree`, `NewerSchema`, … Connection rows: `connections(id, kind, meta_json = Connection::to_json(), config, folder_id, color, position)`; `delete_connection` also drops the item's secrets, credential link, ranking entry and pin; `forget_item` drops secrets and link.
- **Folders (`vault/tree.rs`, `repo_folders.rs`):** `FolderNode`, `FolderTree::new` rejects cycles and dangling parents, `item_color(own, folder)` returns `(colour, ColorSource)`, `validate_folder_name` (1–64 characters through `mfa::clean_name`), `FolderColor` with 12 palette names.
- **Shared credentials (`vault/repo_credentials.rs`, `app-core/src/shared_credentials.rs`):** `credentials(id, name UNIQUE, username, password NULL)`, `credential_links(item_id → credential_id, ON DELETE RESTRICT)`. `resolved_secret` returns the credential's username/password for a linked item; `save_prompted_secret` (the credential prompt's "Save" and re-prompt) writes into the linked credential; `set_item_secret` (editors, import) refuses a username/password of a linked item (`LinkedToCredential`). `validate_credential_name`, `check_username` (≤ 256 bytes), `check_password` (≤ 1024 bytes), `check_item`. `prompt_credential` builds the `CredentialRef { name, used_by }` the prompt shows.
- **Credential prompt (1.1, `crates/core/src/credentials.rs`, `app-core/src/credential_prompt.rs`):** `required_fields(kind, config)` (OpenVPN: bare `auth-user-pass` without an inline `<auth-user-pass>` block → username + password, an encrypted `<key>` → key password; strongSwan EAP → username + password; L2TP/Cisco → username, password, PSK; SSTP → password only, the user name is the config's `user=` line; WireGuard → none). `missing()` treats an empty stored value as missing. `CredentialBroker::present` shows the modal; the control API reports `waiting_for_credentials` / `credentials_cancelled`.
- **Importer and validators:** `importer::prepare` runs `OpenVPNValidator.validate_full` (blocking `issues` plus `risky: Vec<RiskyFinding>`) or `validators::validator(kind).validate`. `ConnectionManager::unacknowledged_risk_reason` refuses a connect until `Connection::acknowledged_risky_directives` covers the risky findings. `importer::remote_host(kind, config)` gives the server for display. `import_export::read_import_file` follows symlinks (it is for files the user picks) and uses `clear_nonblocking` to read a regular file after an `O_NONBLOCK` open.
- **HTTP (`crates/platform-mac/src/http.rs`):** `CurlHttpClient` runs `/usr/bin/curl` (8.7.1 with SecureTransport on macOS 26, so the system trust store) through `CommandRunner` with `environment()` (only `PATH`, `HOME`, `LANG`), `base_arguments` (`-q`, `--proto =https`, `--max-redirs 0`, timeouts, user agent), follows redirects itself hop by hop in a private temp directory, and accepts only `UpdateURLPolicy` hosts. `CommandRunner::run(executable, args, stdin: Option<&str>)` and `run_bytes` exist; stdin is written by the non-blocking `ProcessCommandRunner`.
- **Control API (`crates/core/src/control/`, `app-core/src/control.rs`):** connection keys are UUID-shaped (`is_uuid_shaped`), case-sensitive, upper-case as written by `uuid_string`; a client's allowlist is an exact-match list (`Registry::is_allowed`). Deleting a connection does **not** prune allowlists today. `list` uses `ConnectionManager::ordered_items()`.
- **Manager hooks:** `ConnectionManager::add_state_listener(key, state)`, `set_on_event`, `connections()`, `state(key)`, `disconnect(c)`, `reload()`. `ConnectionEvent` covers `Failed` and `Dropped`. The app already observes wake from sleep (`platform-mac::app_hooks::observe_wake`) and has a `Poller` with `wake()` (`app-core/src/app.rs`) and the update scheduler's `run_scheduler(sleep)` pattern (`updates.rs`). Launch order is `LAUNCH_SEQUENCE` with an order test.
- **Smoke:** `scripts/smoke-manage.sh` starts the built app with `MACVPN_SANDBOX_HOME=<dir>` and `MACVPN_SMOKE_DIR=scripts/smoke`; flows are JS files reporting `MacVPN smoke: …` lines.
- `docs/manual-test-checklist.md` is written in Hungarian; keep that.

---

## Task 1: spike – conditional GET with curl, file-source change detection, Ed25519 signing and rotation, two sandboxes

**Goal:** settle the open technical questions before production code. Findings go into `docs/superpowers/spikes/2026-10-19-catalog-spike.md` (kept). Probes run outside the repository (scratch crate or shell scripts); only the report is committed.

**Outcome (done 2026-10-19, see the spike report):** A and C were run automatically (a local HTTPS server on 127.0.0.1 with a throwaway CA passed through `--cacert`; no external host). B and D were decided from documentation, the code and local APFS tests; the provider and two-app checks are listed in the report's "Manual checks" section for the maintainer.

**Part A – curl (automated where possible):**
- [x] With `/usr/bin/curl` and the exact `CurlHttpClient::base_arguments` plus the additions below, against a local HTTPS server with a certificate trusted in a **test** keychain (or a public test host such as an object store you control), record:
  - `--config -` together with `-q` (which must stay the first argument): a `header = "Authorization: Bearer <token>"` line on stdin is sent, and `ps -ww -o args` during the request shows no token.
  - `--dump-header <file>` with `--max-redirs 0`: exactly one response block per hop; `ETag` and `Last-Modified` parse from it (case-insensitive names, CRLF line ends).
  - `--header 'If-None-Match: <etag>'` and `--header 'If-Modified-Since: <date>'` give `304` with an empty body.
  - `--max-filesize 8388608`: the exit code (63) both with a `Content-Length` above the cap and with a chunked body that grows past it (8.7.1 is expected to abort mid-transfer; if it does not, the reader's `take(cap + 1)` still stops it, so record the transferred size).
  - A `301` to an `http://` URL: `--proto =https` makes the next hop fail even if it is requested; our own hop check refuses it first.
- [x] **Decision A1:** conditional GET through our own `If-None-Match` / `If-Modified-Since` headers and `--dump-header` (expected), or curl's `--etag-compare/--etag-save` files. The default is our own headers, because the validators live in the vault, not in files.
  - **Decided: our own headers + `--dump-header`.** One response block per hop with `--max-redirs 0`; header names arrive in any case and lines end in CRLF. A `304` creates **no** `--output` file (a `302` with an empty body creates an empty one): the `--write-out` status decides, a missing body file reads as empty. `--max-filesize 8388608` → exit 63 both for a large `Content-Length` (no body written) and for a chunked body (aborted at exactly 8 388 608 bytes). A `301` to `http://` is reported by `--write-out` and refused by our hop check; with `-L` curl itself fails with exit 1 (`--proto =https`).
- [x] **Decision A2:** the token travels only on stdin via `--config -`. If `-q` and `--config -` conflict, the fallback is a 0600 config file in the request's private temp directory, deleted after the request (`temp_dir.rs`).
  - **Decided: stdin via `--config -`, `-q` stays first; no conflict, no fallback file.** The token was received by the server and occurred 0 times in `ps -ww -o args`.

**Part B – file sources (maintainer's Mac, manual):**
- [ ] (manual, see the spike report's "Manual checks") For each of: an SMB share (mounted, then the server unplugged), an NFS or AFP share if available, iCloud Drive (a file evicted with "Remove Download"), OneDrive and Dropbox (online-only files), record:
  - whether `fstat` `(dev, ino, size, mtime_ns)` changes when the publisher replaces the file (atomic rename by `exporter::write`) and when only the content changes in place
  - whether `open(O_NOFOLLOW | O_NONBLOCK)` of an evicted or online-only file returns at once, blocks while it downloads, or fails (and with which errno)
  - how long `open` and `read` block on an unplugged SMB server (expect tens of seconds or more)
  - the errno of a missing share (`ENOENT` for an unmounted `/Volumes/<name>`, others)
- [x] **Decision B1:** change detection. Default: always read the file (it is at most 8 MB) and compare its SHA-256 with the last applied content hash; the `fstat` stamp is only a shortcut when it proves reliable on every tested provider. Record which providers allow the shortcut; if any does not, the shortcut is not used at all.
  - **Decided: always read and compare the SHA-256; no `fstat` shortcut on any provider.** Local APFS already shows a same-size in-place change with a preserved `mtime` that leaves `(dev, ino, size, mtime_ns)` unchanged, and the File Provider clouds may set server times.
- [x] **Decision B2:** the read timeout of `FileCatalogFetcher` (default 20 s, on a worker thread, see Task 10) and which errnos mean "unavailable" rather than "error".
  - **Decided: 20 s.** Unavailable: `ENOENT`, `ENOTDIR`, `ENXIO`, `EIO`, `EHOSTDOWN`, `EHOSTUNREACH`, `ENETDOWN`, `ENETUNREACH`, `ENETRESET`, `ECONNABORTED`, `ECONNRESET`, `ECONNREFUSED`, `ENOTCONN`, `ETIMEDOUT`, `ESTALE`, `EDEADLK` (a dataless cloud file that is not materialized), `EAGAIN`. `ELOOP` and a non-regular file (FIFO, directory: the `O_NONBLOCK` open of both succeeds, `fstat` decides) → `Io("not a regular file")`; any other errno → `Io`.

**Part C – Ed25519 signing and rotation (automated):**
- [x] With `ed25519-dalek =3.0.0` (the workspace version, default features): `SigningKey::from_bytes(&[u8; 32])` from 32 `FixedEntropy` bytes, sign and `verify_strict`; check that `SigningKey` zeroizes on drop (the `zeroize` feature) and that no `rand` crate enters `Cargo.lock`.
- [x] Check that a signature made by OpenSSL 3 (`pkeyutl -sign -rawin`, as `scripts/sign-release.sh` does) over the same bytes verifies, so a catalog could later be signed offline the same way.
- [x] **Decision C:** the successor-key scheme of Task 4 (the header field `successor_key`, covered by the catalog signature) is confirmed, or replaced by a separately signed announcement if the review finds a weakness.
  - **Decided: confirmed.** `SigningKey::from_bytes` needs no `rand` (none in `Cargo.lock`), `SigningKey` is `ZeroizeOnDrop`, OpenSSL 3 `pkeyutl -sign -rawin` gives a byte-identical signature. **Correction:** `VerifyingKey::from_bytes` accepts small-order keys, so `PublisherKey::from_bytes` also refuses `is_weak()` keys (Task 2). Rules for Tasks 4/11/14: store an announced successor only from a catalog that passed every check; once a catalog signed by the successor is applied, re-pin to it and stop accepting the old key; a later catalog of the current key may replace the announced successor.

**Part D – two sandboxes:**
- [ ] (manual, optional) Run two built apps at once with different `MACVPN_SANDBOX_HOME` values; record whether a single-instance lock, a shared Keychain service name or the control socket path collide.
- [x] **Decision D:** the smoke run of Task 19 uses the two sandboxes **sequentially** (A publishes, quits; B subscribes, quits; A publishes v2; B refreshes), unless both instances run cleanly side by side.
  - **Decided: sequential.** No single-instance lock, and the sandbox keeps data, Keychain and preferences apart, but both instances share the `local.macvpn` webview data store and the menu bar; the control API socket is not in this base yet.
- [x] Commit: `docs(spike): catalog fetch, file sources, Ed25519 signing, two sandboxes`.

## Task 2: core – key text, team key, admin keys and fingerprints

**Files:** create `crates/core/src/vault/crockford.rs` (moved out of `recovery.rs`), `crates/core/src/catalog/mod.rs`, `catalog/keys.rs`; modify `crates/core/src/vault/recovery.rs` (use `crockford`), `crates/core/src/vault/mod.rs`, `crates/core/src/lib.rs` (`#[cfg(feature = "vault")] pub mod catalog;`). Tests in `crates/core/tests/catalog_keys.rs` (`required-features = ["vault"]` in `crates/core/Cargo.toml`).

- [ ] Move the Crockford encoder/decoder (`ALPHABET`, `symbol_value`, bit packing) into `vault/crockford.rs` as `pub(crate)` functions over byte slices (`encode(bytes, symbols) -> Zeroizing<String>`, `decode(symbols) -> Option<Zeroizing<Vec<u8>>>`, `normalize(input) -> Result<Zeroizing<Vec<u8>>, CrockfordError>` for the parse rules). `recovery.rs` keeps its public API; its existing tests must pass unchanged.
- [ ] Types:
  ```rust
  // catalog/keys.rs
  pub const TEAM_KEY_PREFIX: &str = "TEAM-";
  pub const KEY_FINGERPRINT_DOMAIN: &[u8] = b"macvpn-catalog-key-v1\n";
  const TEAM_KEY_CHECK_DOMAIN: &[u8] = b"macvpn-team-key-v1\n";

  /// 256 random bits. No Clone, redacted Debug, wiped on drop.
  pub struct TeamKey(Zeroizing<[u8; 32]>);
  pub enum TeamKeyError { WrongLength, InvalidCharacter, Typo }
  impl TeamKey {
      pub fn generate(e: &dyn Entropy) -> io::Result<TeamKey>;
      pub fn parse(input: &str) -> Result<TeamKey, TeamKeyError>;
      pub fn to_text(&self) -> Zeroizing<String>;   // "TEAM-XXXX-…" : 13 groups of key symbols + 1 check group
      pub fn group(&self, index: usize) -> Zeroizing<String>; // for the "retype one group" confirmation
      pub fn as_bytes(&self) -> &[u8; 32];
      pub fn from_bytes(bytes: &[u8]) -> Option<TeamKey>;     // from the vault
  }

  /// An Ed25519 signing key (the admin key). No Clone, redacted Debug, wiped on drop.
  pub struct AdminKey(ed25519_dalek::SigningKey);
  impl AdminKey {
      pub fn generate(e: &dyn Entropy) -> io::Result<AdminKey>;
      pub fn from_seed(seed: &[u8]) -> Option<AdminKey>;      // exactly 32 bytes
      pub fn seed(&self) -> Zeroizing<[u8; 32]>;
      pub fn public(&self) -> PublisherKey;
      pub fn sign(&self, message: &[u8]) -> [u8; 64];
  }

  #[derive(Clone, Copy, PartialEq, Eq, Hash)]
  pub struct PublisherKey([u8; 32]);
  impl PublisherKey {
      pub fn from_bytes(bytes: &[u8]) -> Option<PublisherKey>; // 32 bytes, VerifyingKey::from_bytes accepts it, not is_weak() (spike C)
      pub fn as_bytes(&self) -> &[u8; 32];
      pub fn fingerprint(&self) -> Fingerprint;
      pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> bool; // verify_strict
  }

  /// SHA-256(KEY_FINGERPRINT_DOMAIN ‖ public key), first 16 bytes; shown as 8 groups of 4 upper-case hex digits.
  #[derive(Clone, Copy, PartialEq, Eq, Hash)]
  pub struct Fingerprint([u8; 16]);
  pub enum FingerprintError { WrongLength, InvalidCharacter }
  impl Fingerprint {
      pub fn parse(input: &str) -> Result<Fingerprint, FingerprintError>; // case-insensitive, spaces and '-' ignored, 32 hex digits
      pub fn to_text(&self) -> String;                                      // "ABCD-1234-…" (8 groups)
  }
  ```
  - Team key text: the 32 bytes as 52 Crockford symbols (the 4 padding bits must decode as zero, otherwise `InvalidCharacter`), then a check group of 4 symbols = the first 20 bits of `SHA-256(TEAM_KEY_CHECK_DOMAIN ‖ key)`. `parse` strips an optional `TEAM-` prefix (case-insensitive), ignores `-` and white space, applies the `O`/`I`/`L` substitutions, requires exactly 56 symbols (`WrongLength`), and a wrong check group is `Typo` (so a mistyped key is told apart from a wrong key without any decryption).
  - Fingerprint: the full 32-byte public key always travels in the catalog header; the 16-byte fingerprint is only what users compare and pin.
- [ ] Tests:
  - team key: generate → `to_text` → `parse` round-trips; the text matches `^TEAM(-[0-9A-HJKMNP-TV-Z]{4}){14}$`; lower case, spaces, missing prefix, `O`/`I`/`L` accepted; 55 and 57 symbols → `WrongLength`; one changed symbol → `Typo`; `U` → `InvalidCharacter`; non-zero padding bits → `InvalidCharacter`; two generations differ
  - a known-answer vector with `FixedEntropy` for the team-key text and for an admin key's public key and fingerprint
  - admin key: sign → `PublisherKey::verify` true; a flipped message byte, signature byte or another key → false; a small-order public key is refused by `from_bytes`
  - fingerprint: `to_text` format, `parse` round-trip with lower case and spaces, 31 and 33 digits refused
  - `Debug` of `TeamKey` and `AdminKey` shows no key bytes
  - the recovery-key tests still pass (the Crockford move)
- [ ] Commit: `feat(core): team key, admin signing key and fingerprints`.

## Task 3: core – the catalog payload and its validation

**Files:** create `crates/core/src/catalog/payload.rs`, `crates/core/src/vault/wiped_json.rs` (move `WipedValue` and `Counter` out of `backup.rs`, `pub(crate)`); modify `vault/backup.rs` to use them. Tests in `crates/core/tests/catalog_payload.rs`.

- [ ] Types:
  ```rust
  pub const PAYLOAD_VERSION: u32 = 1;
  pub const MAX_CATALOG_CONNECTIONS: usize = 2000;
  pub const MAX_CATALOG_FOLDERS: usize = 1000;
  pub const MAX_CREDENTIAL_SLOTS: usize = 200;
  pub const MAX_SHARED_SECRETS: usize = 2000;
  pub const MAX_CATALOG_CONFIG_BYTES: usize = 1_048_576;   // the editor's and the root layer's config limit

  pub struct CatalogFolder { pub id: Uuid, pub parent: Option<Uuid>, pub name: String, pub color: Option<FolderColor>, pub position: i64 }
  pub struct CredentialSlot { pub id: Uuid, pub name: String }
  pub struct CatalogConnection {
      pub id: Uuid, pub name: String, pub kind: VPNKind,
      pub folder: Option<Uuid>, pub color: Option<FolderColor>,
      pub config: Zeroizing<String>,                 // empty for L2TP/Cisco
      pub native: Option<NativeSettings>,           // L2TP/Cisco only; `account` always empty
      pub otp: OTPSetting,
      pub slot: Option<Uuid>,
      pub secret_refs: BTreeMap<SecretField, Uuid>, // only Psk and KeyPassword
  }
  pub struct CatalogPayload {
      pub version: u32,
      pub folders: Vec<CatalogFolder>,
      pub connections: Vec<CatalogConnection>,
      pub credential_slots: Vec<CredentialSlot>,
      pub shared_secrets: BTreeMap<Uuid, Zeroizing<String>>,
  }
  pub enum InvalidCatalog {
      TooMany(CatalogCollection), Duplicate, FolderName, FolderTree, UnknownFolder, ConnectionName,
      UnknownSlot, UnknownSecret, SecretField, Secret, SlotName, ConfigTooLarge,
      Config { connection: Uuid },  // blocking validator issues; the UI resolves the name from the payload
      InlineCredentials { connection: Uuid }, NativeSettings { connection: Uuid }, Malformed,
  }
  pub fn encode_payload(p: &CatalogPayload) -> Result<Zeroizing<Vec<u8>>, InvalidCatalog>;
  pub fn decode_payload(plaintext: &[u8]) -> Result<CatalogPayload, InvalidCatalog>;
  pub fn validate_payload(p: &CatalogPayload) -> Result<CatalogFindings, InvalidCatalog>;
  pub struct CatalogFindings { pub risky: BTreeMap<Uuid, Vec<RiskyFinding>> }
  pub enum PersonalField { SstpUser, NativeAccount, WireGuardPrivateKey, OpenVpnInlineKey }
  pub fn personal_fields(c: &CatalogConnection) -> Vec<PersonalField>;
  ```
- [ ] JSON: built and parsed exactly like the backup payload (a right-sized `Zeroizing` buffer through `Counter`, `WipedValue` trees, configs and secret values base64 inside the JSON). Unknown top-level keys are refused (`Malformed`), as are duplicate keys (read the objects with a duplicate check; `serde_json::Value` keeps the last). A payload `version` above `PAYLOAD_VERSION` is `CatalogError::NewerFormat` at the format layer (Task 4).
- [ ] `validate_payload` (a catalog is untrusted input, like a backup):
  - caps per collection; connection and folder ids unique; slot and secret ids unique
  - folder names in stored form (`validate_folder_name`), the folders form a tree (`FolderTree::new`), every `folder` / `parent` reference exists
  - connection names through `mfa::clean_name(name, MAX_CONNECTION_NAME_CHARACTERS)` in stored form (`MAX_CONNECTION_NAME_CHARACTERS = 128`, a new constant in `payload.rs`; the editors have no name rule of their own today, so the catalog defines it)
  - slot names through `validate_credential_name` in stored form; every `slot` reference exists
  - `secret_refs` only `Psk` and `KeyPassword` (`SecretField`), each target exists; every shared secret passes the backup's secret rule (`mfa::has_control` false, ≤ 64 KiB)
  - each config ≤ `MAX_CATALOG_CONFIG_BYTES`, no NUL; OpenVPN through `OpenVPNValidator.validate_full`, the others through `validators::validator(kind)`: any blocking issue → `Config { connection }`; the risky findings are returned in `CatalogFindings` (they are acknowledged by each subscriber, never by the catalog)
  - OpenVPN with an inline `<auth-user-pass>` block → `InlineCredentials` (a catalog never carries a user's password)
  - L2TP/Cisco: `native` present with a non-empty `account` → `NativeSettings`; the server and group name through the native editor's rules
  - the whole payload is refused on the first problem; the error carries ids, never values
- [ ] `personal_fields` (used by the publish review, Task 14): an SSTP `user=` value, a native `account`, a WireGuard `PrivateKey`, an OpenVPN inline `<key>`.
- [ ] Tests:
  - round-trip encode/decode of a payload with every kind, nested folders, slots and secrets
  - each `InvalidCatalog` variant with a minimal crafted payload
  - an OpenVPN config with a risky directive validates and reports the finding
  - a duplicate JSON key and an unknown top-level key → `Malformed`
  - `Debug` of a payload shows no config or secret text
  - the backup tests still pass (the `WipedValue` move)
- [ ] Commit: `feat(core): catalog payload and validation`.

## Task 4: core – the catalog file format

**Files:** create `crates/core/src/catalog/format.rs`; tests in `crates/core/tests/catalog_format.rs`.

- [ ] Container, version 1 (integers big-endian):
  ```
  magic         8   b"MVPNCAT1"
  header_len    4   1 ..= MAX_HEADER_BYTES (16 KiB)
  header        …   UTF-8 JSON, header_len bytes
  sealed        …   XChaCha20-Poly1305(team key, header.nonce, payload JSON, AAD = AAD_DOMAIN ‖ magic ‖ header_len ‖ header), tag last
  signature    64   Ed25519 over SIGNATURE_DOMAIN ‖ magic ‖ header_len ‖ header ‖ sealed
  ```
  ```rust
  pub const MAGIC: &[u8; 8] = b"MVPNCAT1";
  pub const FORMAT: u32 = 1;
  pub const SIGNATURE_DOMAIN: &[u8] = b"macvpn-catalog-v1\n";
  pub const AAD_DOMAIN: &[u8] = b"macvpn-catalog-v1|payload\n";
  pub const MAX_CATALOG_BYTES: usize = 8 * 1024 * 1024;
  pub const MAX_HEADER_BYTES: usize = 16 * 1024;
  pub const EXTENSION: &str = "macvpncatalog";

  pub struct CatalogHeader {
      pub format: u32, pub catalog_id: Uuid, pub name: String, pub version: u64, pub created: Date,
      pub publisher_key: PublisherKey, pub publisher_key_id: Fingerprint,
      pub successor_key: Option<PublisherKey>,
      pub kdf: String /* "none" */, pub enc: String /* "xchacha20poly1305" */, pub nonce: [u8; 24],
  }
  pub struct Trust { pub pinned: Fingerprint, pub publisher_key: Option<PublisherKey>, pub successor: Option<PublisherKey> }
  pub struct OpenRequest<'a> { pub trust: &'a Trust, pub catalog_id: Option<Uuid>, pub applied_version: Option<u64>, pub team_key: &'a TeamKey }
  pub struct OpenedCatalog { pub header: CatalogHeader, pub payload: CatalogPayload, pub findings: CatalogFindings, pub signed_by_successor: bool, pub content_hash: [u8; 32] }
  pub enum CatalogError {
      NotACatalog, Truncated, TooLarge, NewerFormat(u32), BadHeader,
      UnknownPublisher, BadSignature, WrongCatalog, SameVersion, Rollback { applied: u64, offered: u64 },
      WrongTeamKey, Invalid(InvalidCatalog), Unavailable(String), Io(String),
  }
  /// The fieldless form stored in a subscription's status (`CatalogError::kind()`).
  pub enum CatalogErrorKind { NotACatalog, Truncated, TooLarge, NewerFormat, BadHeader, UnknownPublisher, BadSignature,
                              WrongCatalog, WrongTeamKey, Invalid, Io }
  pub fn seal_catalog(header: CatalogHeaderInput, payload: &CatalogPayload, team_key: &TeamKey, admin: &AdminKey, e: &dyn Entropy) -> Result<Vec<u8>, CatalogError>;
  pub fn peek_header(bytes: &[u8]) -> Result<CatalogHeader, CatalogError>;   // framing + header only, no trust
  pub fn open_catalog(bytes: &[u8], req: &OpenRequest) -> Result<OpenedCatalog, CatalogError>;
  ```
- [ ] Header JSON: strict (duplicate or unknown keys → `BadHeader`), except that `format` is read first from a plain parse: above `FORMAT` → `NewerFormat`. `name` through `validate_credential_name`'s character rule (1–64 characters, no control characters); `kdf` must be `"none"`, `enc` `"xchacha20poly1305"`; `publisher_key_id` must equal `publisher_key.fingerprint()`; `successor_key`, when present, must differ from `publisher_key`.
- [ ] `open_catalog` runs the spec's order exactly, and each step only after the previous one passed:
  1. framing: shorter than `8 + 4 + 1 + 16 + 64` or a bad `header_len` → `Truncated`; wrong magic → `NotACatalog`; over `MAX_CATALOG_BYTES` → `TooLarge` (checked before anything else is parsed)
  2. header parse → `BadHeader` / `NewerFormat`
  3. trust: the header's key must be the pinned one (`publisher_key_id == trust.pinned`, and equal to `trust.publisher_key` once that is known) **or** `trust.successor`; otherwise `UnknownPublisher`. Then the signature (`verify_strict`) → `BadSignature`
  4. `catalog_id` equal to `req.catalog_id` when set → `WrongCatalog`
  5. version: equal to `applied_version` → `SameVersion`; lower → `Rollback { applied, offered }`
  6. decrypt with the team key (AAD as above) → `WrongTeamKey` (after a good signature, a failure here can only be the key)
  7. `decode_payload` + `validate_payload` → `Invalid(…)`; a payload `version` above 1 → `NewerFormat`
  `content_hash` is SHA-256 of the whole file (the file source's change check, Task 10).
- [ ] `seal_catalog` validates the payload first (a catalog that no subscriber could apply is never written), takes a fresh nonce from `Entropy`, and signs with the admin key. `CatalogHeaderInput` has everything but `format`, `kdf`, `enc` and `nonce`.
- [ ] Error messages (`Display` and the l10n texts) never contain a value from the file except the two version numbers of `Rollback`.
- [ ] Tests:
  - round-trip seal/open with a fresh trust (`publisher_key: None`), and with the key known
  - a wrong team key → `WrongTeamKey`; a wrong pinned fingerprint → `UnknownPublisher`; a flipped byte in the header, the sealed payload or the signature → `BadSignature`; a truncated file at every cut point of a small catalog → `Truncated` or `BadSignature`, never a panic and never `WrongTeamKey`
  - the distinct variants are distinct, and none of their messages contains the catalog name, a connection name or config text (string search)
  - `SameVersion` for equal, `Rollback` for lower, accepted for higher
  - `WrongCatalog` for another `catalog_id`
  - size cap: a file of `MAX_CATALOG_BYTES + 1` → `TooLarge` without parsing
  - `format: 2` → `NewerFormat(2)`; `kdf: "argon2id"` → `BadHeader`
  - successor: a catalog signed by the key announced in `trust.successor` opens with `signed_by_successor = true`; one signed by an unannounced key → `UnknownPublisher`
  - a proptest over random bytes and random mutations of a valid file: no panic, no allocation beyond the cap
- [ ] Commit: `feat(core): signed and encrypted catalog file format`.

## Task 5: core – the subscription string and the source rules

**Files:** create `crates/core/src/catalog/subscription.rs`, `crates/core/src/catalog/source.rs`; tests in `crates/core/tests/catalog_subscription.rs` and `crates/core/tests/catalog_source.rs`.

- [ ] Sources:
  ```rust
  pub enum CatalogSource { Https(HttpsUrl), File(PathBuf) }
  pub struct HttpsUrl { /* canonical text */ }
  pub enum SourceError { NotHttps, BadUrl, UserInfo, Fragment, TooLong, NotAbsolute, BadPath }
  impl HttpsUrl {
      pub fn parse(input: &str) -> Result<HttpsUrl, SourceError>;
      pub fn as_str(&self) -> &str;          // canonical, handed to curl after `--`
      pub fn origin(&self) -> (String, u16); // host (lower case, punycode), port (443 default)
      pub fn redacted(&self) -> String;      // without the query, for logs and the UI
      pub fn redirect_target(&self, location: &str) -> Result<HttpsUrl, SourceError>; // relative or absolute, https only
  }
  pub fn parse_file_source(input: &str) -> Result<PathBuf, SourceError>; // absolute, no NUL, ≤ 1024 bytes, `~/` expanded by the caller
  pub fn read_catalog_file(path: &Path) -> Result<Vec<u8>, CatalogError>;
  ```
  - `HttpsUrl`: `https://` only; a host that is an ASCII LDH name (a Unicode name converted with `idna::domain_to_ascii`), an IPv4 literal or a bracketed IPv6 literal; optional port 1–65535; no user info; no fragment; path and query printable ASCII (`0x21..0x7e`); at most 2048 bytes. Built on `macvpn_core::url::parse`, the same parser `canonical_redirect_url` uses, but without the update host allowlist.
  - `read_catalog_file`: `O_NOFOLLOW | O_NONBLOCK` (the last component is never a symlink, a FIFO never blocks the open), `fstat` on the descriptor: a regular file only, at most `MAX_CATALOG_BYTES` (else `TooLarge`), then read through `take(MAX_CATALOG_BYTES + 1)`. `ENOENT`, `ENOTDIR`, `EHOSTDOWN`, `ETIMEDOUT`, `ENETUNREACH` and the other errnos recorded in Task 1 B2 → `CatalogError::Unavailable(<file name>)`; a symlink (`ELOOP`), a non-regular file → `Io("not a regular file")`. Same structure as `backup::read_backup_file`.
- [ ] Subscription string:
  ```rust
  pub const SUBSCRIPTION_PREFIX: &str = "macvpn-sub:";
  pub const MAX_SUBSCRIPTION_CHARS: usize = 4096;
  pub struct SubscriptionString { pub source: CatalogSource, pub team_key: TeamKey, pub fingerprint: Fingerprint }
  pub enum SubscriptionError { NotASubscription, TooLong, Malformed, NewerVersion(u32), Source(SourceError), TeamKey(TeamKeyError), Fingerprint(FingerprintError) }
  pub fn parse_subscription(input: &str) -> Result<SubscriptionString, SubscriptionError>;
  pub fn format_subscription(s: &SubscriptionString) -> Zeroizing<String>;
  ```
  - `macvpn-sub:` + base64url (no padding) of `{"v":1,"source":{"https":"…"}|{"file":"…"},"teamKey":"TEAM-…","fingerprint":"XXXX-…"}`. Leading and trailing white space is trimmed; anything else around it is refused. Strict JSON (duplicate or unknown keys → `Malformed`); `v` above 1 → `NewerVersion`.
  - The decoded bytes, the intermediate JSON and the formatted string are wiped (`Zeroizing`, `WipedValue`).
  - The bearer token is **not** part of the string (see "Resolved points").
- [ ] Tests:
  - URL: accepted forms (default port, explicit port, IPv4, `[::1]`, IDN → punycode, query kept); refused forms (`http://`, `ftp://`, user info, fragment, control character, space, 2049 bytes, empty host); `redacted` drops the query; `redirect_target` resolves `/x`, `../x` and absolute targets and refuses `http://`
  - file source: relative path refused; NUL refused
  - `read_catalog_file` refuses a symlink, a directory and a FIFO (without blocking; a 2 s guard as in `import_export`'s `read_quickly` test), an oversized file (sparse file of 8 MiB + 1) → `TooLarge`; a missing file → `Unavailable`
  - subscription: round-trip; a pasted string with surrounding white space and line breaks inside the base64 (copied from mail) → refused (`Malformed`), documenting that the UI strips nothing but the outer white space; wrong prefix; 4097 characters; a wrong check group in the team key → `TeamKey(Typo)`; `v: 2` → `NewerVersion(2)`
  - `Debug` of `SubscriptionString` shows the source and the fingerprint only
- [ ] Commit: `feat(core): subscription string and catalog sources`.

## Task 6: core – vault schema v2 and the catalog repositories

**Files:** modify `crates/core/src/vault/schema.rs` (`CURRENT_SCHEMA = 2`, migration v2), `vault/db.rs` (`VaultError::CatalogManaged`), `vault/repo_connections.rs`, `repo_folders.rs`, `repo_credentials.rs` (the read-only guard); create `crates/core/src/vault/repo_catalog.rs`, `crates/core/src/catalog/ids.rs`, `crates/core/src/catalog/selection.rs`. Tests in `crates/core/tests/vault_catalog.rs` and an extension of `crates/core/tests/vault_db.rs` (migration v1 → v2).

- [ ] Migration v2 (additive only, so a 1.2 app can still read a v2 database read-only):
  ```sql
  CREATE TABLE catalog_subscriptions(
      catalog_id TEXT PRIMARY KEY,
      json TEXT NOT NULL,            -- name, source, pinned fingerprint, applied_version, reapply, status, validators, timestamps, failures, root_folder_id
      team_key BLOB NOT NULL,
      bearer BLOB NULL,
      publisher_key BLOB NULL,       -- 32 bytes once the first catalog was verified
      successor_key BLOB NULL);
  CREATE TABLE catalog_items(
      local_id TEXT PRIMARY KEY,     -- the connections.id or folders.id it owns
      catalog_id TEXT NOT NULL REFERENCES catalog_subscriptions(catalog_id) ON DELETE CASCADE,
      item_id TEXT NOT NULL,
      kind TEXT NOT NULL CHECK(kind IN ('root','folder','connection')),
      color TEXT NULL,               -- the publisher's colour (connections; folders keep theirs in folders.color)
      slot_id TEXT NULL,
      provided_secrets TEXT NOT NULL DEFAULT '',  -- comma list of SecretField raw values set by the catalog
      config_hash TEXT NULL,         -- SHA-256 of config + native settings, for "changed" and the risky acknowledgement rule
      meta_hash TEXT NULL,           -- SHA-256 of name, folder, colour, OTP setting, slot and secret refs
      pending_removal INTEGER NOT NULL DEFAULT 0,
      profile_outdated INTEGER NOT NULL DEFAULT 0,
      UNIQUE(catalog_id, item_id, kind));
  CREATE TABLE catalog_slots(
      catalog_id TEXT NOT NULL REFERENCES catalog_subscriptions(catalog_id) ON DELETE CASCADE,
      slot_id TEXT NOT NULL,
      name TEXT NOT NULL,
      credential_id TEXT NULL REFERENCES credentials(id) ON DELETE SET NULL,
      PRIMARY KEY(catalog_id, slot_id));
  CREATE TABLE catalog_admin_keys(
      key_id TEXT PRIMARY KEY,       -- the fingerprint text
      role TEXT NOT NULL CHECK(role IN ('primary','backup')),
      seed BLOB NOT NULL,
      created TEXT NOT NULL);
  CREATE TABLE catalog_publications(
      catalog_id TEXT PRIMARY KEY,
      json TEXT NOT NULL,            -- name, version, selection, included secrets, slots, item hashes, last path, last published
      team_key BLOB NOT NULL);
  ```
  `min_app_schema` stays 1, but it does not matter for 1.2: a 1.2 build opens any database whose `schema_version` is above its own read-only, whatever `min_app_schema` says, so it reads a v2 vault and never writes it. That is safe (pinned by `a_v2_database_opens_in_a_1_2_build_and_reads_every_v1_table`). See "Resolved points".
- [ ] `catalog/ids.rs`:
  ```rust
  /// UUID v8 from SHA-256("macvpn-catalog-item-v1\n" ‖ kind ‖ "\n" ‖ catalog_id ‖ "\n" ‖ item_id): stable across
  /// versions and devices, UUID-shaped for the control API, never equal for two catalogs.
  pub fn local_id(catalog_id: Uuid, kind: CatalogItemKind, item_id: Uuid) -> Uuid;
  pub fn root_folder_id(catalog_id: Uuid) -> Uuid; // local_id(catalog_id, Root, catalog_id)
  pub enum CatalogItemKind { Root, Folder, Connection }
  ```
- [ ] Repository (`repo_catalog.rs`) on `Vault`, every write in one transaction:
  ```rust
  pub struct SubscriptionRecord { pub catalog_id: Uuid, pub name: String, pub source: CatalogSource, pub pinned: Fingerprint,
      pub applied_version: Option<u64>, pub reapply: bool, pub status: SubscriptionStatus, pub validators: SourceValidators,
      pub last_attempt: Option<Date>, pub last_success: Option<Date>, pub failures: u32, pub has_bearer: bool,
      pub publisher_key: Option<PublisherKey>, pub successor_key: Option<PublisherKey>, pub added: Date }
  pub enum SubscriptionStatus { Ok, NotModified, Unavailable, Failed(CatalogErrorKind), RollbackRefused { offered: u64 }, TeamKeyChanged }
  pub struct SourceValidators { pub etag: Option<String>, pub last_modified: Option<String>, pub content_hash: Option<[u8; 32]> }
  pub enum AdminKeyRole { Primary, Backup }
  pub struct AdminKeyRecord { pub role: AdminKeyRole, pub public: PublisherKey, pub fingerprint: Fingerprint, pub created: Date }
  pub struct PublicationRecord { pub catalog_id: Uuid, pub name: String, pub version: u64, pub selection: PublishSelection,
      pub secret_ids: BTreeMap<(Uuid, SecretField), Uuid>, pub item_hashes: BTreeMap<Uuid, String>,
      pub last_path: Option<PathBuf>, pub last_published: Option<Date> }
  // catalog/selection.rs (plain data, created in this task, used by Task 14):
  pub struct PublishSelection { pub folders: BTreeSet<Uuid>, pub connections: BTreeSet<Uuid>,
                                pub secrets: BTreeSet<(Uuid, SecretField)>, pub slots: BTreeSet<Uuid> /* publisher credential ids */ }
  pub fn subscriptions(&self) -> Result<Vec<SubscriptionRecord>, VaultError>;
  pub fn subscription_secrets(&self, id: Uuid) -> Result<(TeamKey, Option<Zeroizing<String>>), VaultError>;
  pub fn add_subscription(&mut self, record: &SubscriptionRecord, team_key: &TeamKey, bearer: Option<&str>) -> Result<(), VaultError>; // creates the root folder too
  pub fn update_subscription_state(&mut self, id: Uuid, f: impl FnOnce(&mut SubscriptionRecord)) -> Result<(), VaultError>;
  pub fn set_subscription_team_key(&mut self, id: Uuid, key: &TeamKey) -> Result<(), VaultError>;
  pub fn set_subscription_bearer(&mut self, id: Uuid, bearer: Option<&str>) -> Result<(), VaultError>;
  pub fn local_catalog(&self, id: Uuid) -> Result<LocalCatalog, VaultError>;    // the planner's input (Task 7)
  pub fn catalog_owner(&self, local_id: &str) -> Result<Option<CatalogOwnership>, VaultError>;
  pub fn admin_keys(&self) -> Result<Vec<AdminKeyRecord>, VaultError>;          // never the seed
  pub fn admin_key(&self, role: AdminKeyRole) -> Result<Option<AdminKey>, VaultError>;
  pub fn save_admin_key(&mut self, key: &AdminKey, role: AdminKeyRole, created: Date) -> Result<(), VaultError>;
  pub fn delete_admin_key(&mut self, key_id: &Fingerprint) -> Result<(), VaultError>;
  pub fn promote_backup_key(&mut self) -> Result<(), VaultError>;              // backup → primary, old primary deleted
  pub fn publications(&self) -> Result<Vec<PublicationRecord>, VaultError>;
  pub fn publication_team_key(&self, id: Uuid) -> Result<TeamKey, VaultError>;
  pub fn save_publication(&mut self, p: &PublicationRecord, team_key: Option<&TeamKey>) -> Result<(), VaultError>;
  pub fn delete_publication(&mut self, id: Uuid) -> Result<(), VaultError>;
  ```
  - The bearer token is checked as an RFC 6750 `b64token` (`[A-Za-z0-9._~+/-]+=*`, 1–4096 bytes); anything else → `Constraint`.
  - `CatalogOwnership { catalog_id, catalog_name, kind, slot_id, provided_secrets, pending_removal, profile_outdated }`.
- [ ] Read-only guard (spec 6): the generic write paths refuse catalog-owned rows with the new `VaultError::CatalogManaged`:
  - `save_connection` (name, config, meta), `delete_connection`, `set_item_folder` for a catalog connection, and moving a personal item **into** a catalog folder
  - `create_folder` under a catalog folder, `rename_folder`, `set_folder_color`, `move_folder`, `delete_folder` of a catalog folder or root
  - `set_item_secret` / `save_prompted_secret` of a field listed in `provided_secrets`
  - still allowed on catalog items: `set_collapsed`, `set_item_color` (the local override), pins and ranking, own secrets that the catalog does not provide, the credential link and `save_prompted_secret` of username/password, and the new `set_acknowledged_risky(id, &[String])`, which only changes `acknowledged_risky_directives` in `meta_json`
  - the catalog executor (Task 7) writes through a separate `Tx` path that bypasses the guard
- [ ] Tests:
  - migration v1 → v2 on a v1 database with data: tables created, `schema_version` 2, the data intact, the `.bak-v1` copy made
  - a v2 database opened by the v1 schema list (simulating 1.2) opens read-only and reads every v1 table, and the file is unchanged afterwards
  - subscription round-trip; team key and bearer stored only in the BLOB columns (scan `json` for the key text and the token: absent)
  - `local_id`: deterministic, differs per catalog, per kind and per item, is UUID-shaped (`is_uuid_shaped` on `uuid_string`)
  - every guarded write on a catalog row → `CatalogManaged`; every allowed write works
  - admin keys: save, list without seeds, load, promote, delete
  - publications: round-trip, the team key only in its column
  - deleting a subscription cascades `catalog_items` and `catalog_slots` rows (the owned connections are removed by the executor, Task 7, not by the cascade)
- [ ] Commit: `feat(core): vault schema v2 with catalog subscriptions, items and admin keys`.

## Task 7: core – the apply/diff planner and its executor

**Files:** create `crates/core/src/catalog/planner.rs` (pure) and `crates/core/src/vault/catalog_apply.rs` (the executor); tests in `crates/core/tests/catalog_planner.rs` and `crates/core/tests/vault_catalog_apply.rs`.

- [ ] Pure planner:
  ```rust
  pub struct LocalItem { pub local_id: Uuid, pub item_id: Uuid, pub kind: CatalogItemKind, pub config_hash: Option<String>,
                         pub meta_hash: String, pub pending_removal: bool, pub slot_id: Option<Uuid>, pub provided: BTreeSet<SecretField> }
  pub struct LocalCatalog { pub catalog_id: Uuid, pub name: String, pub root_folder: Uuid, pub items: Vec<LocalItem>,
                            pub slots: BTreeMap<Uuid, (String, Option<Uuid> /* credential */)> }
  pub enum CatalogOp {
      RenameRoot { name: String },
      UpsertFolder { local_id: Uuid, parent: Uuid, name: String, color: Option<FolderColor>, position: i64 },
      RemoveFolder { local_id: Uuid },
      AddConnection { local_id: Uuid, item: Uuid },          // the payload entry is looked up by item id
      UpdateConnection { local_id: Uuid, item: Uuid, config_changed: bool, native_changed: bool },
      MarkPendingRemoval { local_id: Uuid, folder_to: Uuid }, // up: kept, moved to the catalog root
      RemoveConnection { local_id: Uuid },
      SetProvidedSecret { local_id: Uuid, field: SecretField, secret: Uuid },
      ClearProvidedSecret { local_id: Uuid, field: SecretField },
      UpsertSlot { slot: Uuid, name: String },
      RemoveSlot { slot: Uuid },
      LinkSlot { local_id: Uuid, slot: Uuid },
      UnlinkSlot { local_id: Uuid },
  }
  pub struct ApplySummary { pub added: usize, pub changed: usize, pub removed: usize, pub deferred: usize }
  pub struct ApplyPlan { pub ops: Vec<CatalogOp>, pub summary: ApplySummary }
  pub fn plan_apply(old: &LocalCatalog, new_name: &str, new: &CatalogPayload, active: &HashSet<Uuid>) -> ApplyPlan;
  pub fn plan_unsubscribe(old: &LocalCatalog) -> ApplyPlan;            // every item RemoveConnection / RemoveFolder, slots RemoveSlot
  pub fn plan_pending(old: &LocalCatalog, active: &HashSet<Uuid>) -> ApplyPlan; // pending removals that are no longer active
  ```
  - Ops are ordered so every reference exists when it is used: root rename, folders parents-first, slots, connections, secrets, links; removals of connections before folders, folders children-first.
  - "Changed" means a different `meta_hash` (name, folder, colour, OTP setting, slot, secret refs) or `config_hash`; an unchanged item yields no op.
  - A connection removed from the catalog that is in `active` → `MarkPendingRemoval` (counted in `deferred` and in `removed`); otherwise `RemoveConnection`. A folder that disappears is removed even if it held a pending-removal connection, because that connection was moved to the root.
  - An active connection that changes is updated at once: its tunnel already has its config (the root layer took it on stdin at connect), so the new config takes effect at the next connect. `native_changed` on L2TP/Cisco sets `profile_outdated`.
- [ ] Executor:
  ```rust
  pub struct ApplyContext<'a> { pub catalog_id: Uuid, pub payload: &'a CatalogPayload, pub now: Date }
  impl Vault {
      pub fn apply_catalog(&mut self, plan: &ApplyPlan, ctx: &ApplyContext, record: &SubscriptionRecord) -> Result<Vec<Uuid>, VaultError>; // returns removed connection ids
      pub fn unsubscribe_catalog(&mut self, catalog_id: Uuid, plan: &ApplyPlan) -> Result<UnsubscribeReport, VaultError>;
      pub fn duplicate_catalog_connection(&mut self, local_id: Uuid, name: &str) -> Result<Uuid, VaultError>;
  }
  pub struct UnsubscribeReport { pub removed_connections: Vec<Uuid>, pub kept_credentials: Vec<String> }
  ```
  - One transaction for the whole plan **and** the new `SubscriptionRecord` (version, validators, status): either everything or nothing.
  - `AddConnection` / `UpdateConnection` write `connections` with `meta_json = Connection::to_json()` built from the payload entry, keeping the local fields: `created_at` (new: `now`), `native_service_name` / `native_service_id` (the local binding), and `acknowledged_risky_directives` **only if** the stored `config_hash` equals the new one (otherwise cleared, so the subscriber is asked again). `connections.color` (the local override) is kept; the publisher's colour goes to `catalog_items.color`.
  - The effective colour of a catalog connection is: local override, else the publisher's colour, else the folder's (the manager passes `override.or(publisher)` as `own` to `FolderTree::item_color`).
  - `SetProvidedSecret` writes the shared secret's value as the item's own secret and records the field in `provided_secrets`; `ClearProvidedSecret` deletes the value too, so a team secret never lingers after the publisher stops including it.
  - Slots (spec 6, credential slots): `UpsertSlot` creates the `catalog_slots` row. `LinkSlot` links the connection to the slot's credential; when the slot has no credential yet, the executor creates one named after the slot (`validate_credential_name`; if the name is taken by another credential, suffix " (<catalog name>)", then " (<catalog name> 2)", …) with an empty username and no password, and stores its id in `catalog_slots.credential_id`. A connection that already has its own username or password (`items_with_own_login`) is **not** linked. `RemoveSlot` deletes the row; the credential stays if it was filled in (a non-empty username or a password) or is linked elsewhere, otherwise it is deleted.
  - `RemoveConnection` uses the same clean-up as `delete_connection` (secrets, link, ranking, pin) and deletes the `catalog_items` row.
  - `unsubscribe_catalog`: runs `plan_unsubscribe`'s ops, deletes the root folder and the subscription row; filled slot credentials are kept as normal shared credentials (listed in the report), unfilled ones are deleted. Refused while any of the catalog's connections is active (the app disconnects first, Task 11).
  - `duplicate_catalog_connection` (spec 6, "Duplicate as personal connection"): a new random UUID, the given name, the same config and kind, at the vault root, no catalog row; the item's own secrets and provided secrets copied as its own; the same credential link; `acknowledged_risky_directives` cleared; OTP setting copied.
- [ ] Tests (planner, pure):
  - add, change (config only; name only; folder move; colour; slot; secret refs), remove, unchanged → no op
  - a connection that is up when it changes → updated, summary `changed`; when it is removed → `MarkPendingRemoval`, `deferred` 1; `plan_pending` later removes it once it is no longer active
  - several catalogs: two `LocalCatalog`s with the same item ids give disjoint local ids; applying one never touches the other
  - namespacing: `local_id` of the same item differs between catalogs
  - unsubscribe: every item and slot removed
  - op order: parents before children on add, children before parents on remove
- [ ] Tests (executor, vault):
  - apply v1 → rows, folders under the catalog root with the publisher's colours, links to new empty slot credentials
  - apply v2 with a config change → the acknowledged risky directives cleared; with only a name change → kept
  - local colour override and collapse state survive an apply; pins and ranking survive; a removed connection's pin and ranking entry are gone
  - a provided PSK is written, refused to the editor path (`CatalogManaged`), and deleted when no longer provided
  - a slot whose name is taken by a personal credential gets the suffixed name; a connection with its own login is not linked
  - a failure injected in the middle of a plan leaves the vault unchanged (the record's version too)
  - unsubscribe keeps a filled slot credential and deletes an unfilled one; refuses while active
  - duplicate: independent editable copy, saving it works, the catalog item is unchanged
- [ ] Commit: `feat(core): catalog apply planner and executor`.

## Task 8: core – backup payload v2 (subscriptions, admin keys, publications)

**Files:** modify `crates/core/src/vault/backup.rs`; tests in `crates/core/tests/vault_backup.rs`.

- [ ] `PAYLOAD_VERSION = 2`, with the first entry of `MIGRATIONS` (v1 → v2: empty catalog collections). New fields:
  ```rust
  pub struct BackupSubscription { pub record: SubscriptionRecord, pub team_key: TeamKey, pub bearer: Option<Zeroizing<String>>,
                                  pub slots: Vec<(Uuid /* slot */, String /* name */, Option<Uuid> /* credential */)> }
  pub struct BackupAdminKey { pub role: AdminKeyRole, pub seed: Zeroizing<[u8; 32]>, pub created: Date }
  pub struct BackupPublication { pub record: PublicationRecord, pub team_key: TeamKey }
  // BackupPayload gains: subscriptions, admin_keys, publications
  ```
  - `collect` excludes every catalog-owned connection and folder (they come back from the source) but keeps their user state: the items' own secrets go into `system_secrets` keyed by the local id, and their pins and ranking stay in `ranking`. The slot credentials are ordinary credentials and are included.
  - Restored subscriptions get `reapply = true` and keep `applied_version` as the rollback floor: the next refresh accepts the same version once (Task 11) and re-creates the items with the same deterministic ids, so the restored secrets, pins and links attach again.
  - `validate` adds: subscriptions' names and sources (Task 5 rules), bearer token rule, at most `MAX_ITEMS` per new collection, admin keys at most one per role, publication versions ≥ 1, no duplicate catalog ids.
  - `merge`: a subscription or publication with an existing `catalog_id` follows the `ConflictMode` (Overwrite, KeepExisting; KeepBoth behaves as KeepExisting, since one catalog cannot be subscribed twice), and the result's `applied_version` / publication `version` is the **maximum** of both, never lower. Admin keys: a backup key for a role that already holds a different key → the conflict mode (Overwrite replaces, the others keep). `replace` takes the backup's.
- [ ] The UI wording of "What the backup contains" (Task 18) lists the team catalog subscriptions and the admin keys.
- [ ] Tests:
  - round-trip with subscriptions, admin keys and publications; their key material is only in the sealed file
  - a v1 payload opens and migrates (empty catalog collections)
  - `collect` leaves catalog-owned connections and folders out, keeps their own secrets and pins
  - merge never lowers `applied_version` or a publication's `version` (both directions)
  - a crafted payload with two primary admin keys, a bad bearer token, an `http://` source → `Invalid`
  - restore then apply of the same catalog version (`reapply`) re-creates the items with the restored secrets attached
- [ ] Commit: `feat(core): team catalogs and admin keys in the full backup`.

## Task 9: platform-mac – the HTTPS catalog fetcher

**Files:** create `crates/platform-mac/src/catalog_http.rs`; modify `crates/platform-mac/src/http.rs` (share `environment`, `runner`, `with_private_directory`, `parse_trailer`, `remove_output`; `base_arguments` takes the user agent), `crates/platform-mac/src/lib.rs`, `crates/app-core/src/deps.rs` (the trait). Tests in `crates/platform-mac/tests/catalog_http.rs` with a fake `CommandRunner` that plays curl.

- [ ] Trait in `app-core/src/deps.rs` (implemented here and by `FileCatalogFetcher`, Task 10):
  ```rust
  pub struct FetchRequest<'a> { pub source: &'a CatalogSource, pub bearer: Option<&'a str>, pub previous: &'a SourceValidators }
  pub enum FetchOutcome { NotModified, Fetched { bytes: Vec<u8>, validators: SourceValidators } }
  pub trait CatalogFetcher: Send + Sync {
      fn fetch(&self, req: &FetchRequest) -> Result<FetchOutcome, CatalogError>; // Unavailable for transport failures
  }
  ```
- [ ] `CurlCatalogFetcher`:
  - Arguments: `base_arguments` with user agent `MacVPN-Catalog/<version>`, `--max-time 60`, `--max-filesize 8388608`, `--dump-header <dir>/headers`, `--write-out '%{http_code} %{redirect_url}'`, `--output <dir>/body`, `--header 'If-None-Match: <etag>'` and `--header 'If-Modified-Since: <date>'` from `previous` (each re-checked: ≤ 256 bytes, printable ASCII, no `"`-less quoting tricks: only `0x21..0x7e` and space), then `--` and the canonical URL.
  - The bearer token (Task 1 A2) goes on stdin as `--config -` with the line `header = "Authorization: Bearer <token>"`; the token was checked against the `b64token` rule (Task 6), so it needs no escaping. Never in argv, never in env, never in a log line.
  - Redirects: followed hop by hop (at most 5), each target through `HttpsUrl::redirect_target` (https only, else `CatalogError::Io("redirect to a non-HTTPS address")`). The token is sent only while the hop's `origin()` equals the subscription URL's origin; a cross-origin hop is requested without it.
  - `304` → `NotModified`. `200` → the body read through `take(MAX_CATALOG_BYTES + 1)` (over → `TooLarge`), `ETag` / `Last-Modified` parsed from the final hop's headers. curl exit 63 → `TooLarge`. `401`/`403` → `Io("access denied (check the access token)")`; other statuses → `Io("HTTP <status>")`. curl transport failures (6, 7, 28, 35, 60, …) → `Unavailable("<host>")`, except certificate errors (60) → `Io("certificate not trusted")`.
  - The private temp directory is removed after every request (`with_private_directory`).
- [ ] Tests (fake runner reading the argument list and writing `headers` / `body` / the trailer as curl would):
  - the argument list: `-q` first, `--proto =https`, `--max-redirs 0`, the conditional headers, `--` before the URL; the token appears **only** in the runner's stdin, never in the arguments or the environment
  - `200` with `ETag` and `Last-Modified` (mixed-case header names, CRLF) → `Fetched` with the validators
  - `304` → `NotModified`
  - a redirect to `https://` same origin (token sent again), to another origin (token not sent), to `http://` (refused, no request made), 6 redirects (refused)
  - exit 63 and an 8 MiB + 1 body → `TooLarge`
  - `401` → access denied; exit 6 → `Unavailable`; exit 60 → certificate
  - the temp directory is gone after success and after each failure
  - one `#[ignore]` live test against `MACVPN_CATALOG_TEST_URL` (run by hand, documented in the spike report)
- [ ] Resolved by the core review (Tasks 2–5): the bearer token is stripped on every hop whose `HttpsUrl::origin()` differs from the subscription URL's origin (exact equality of host and port), and at most 5 hops are followed.
- [ ] Commit: `feat(platform-mac): HTTPS catalog fetcher`.

## Task 10: app-core – the file source

**Files:** create `crates/app-core/src/catalog_file.rs`; tests in `crates/app-core/tests/catalog_file.rs`.

- [ ] `FileCatalogFetcher` implements `CatalogFetcher` for `CatalogSource::File`:
  - The read runs on a worker thread with the timeout from Task 1 B2 (default 20 s). A read that does not finish → `Unavailable(<file name>)`; the thread is left to finish on its own and is counted, and while a previous read of the same path is still running, a new fetch returns `Unavailable` at once instead of starting another thread (at most one hung read per path).
  - `read_catalog_file` (Task 5) does the opening rules. Change detection per decision B1: by default the SHA-256 of the bytes against `previous.content_hash` → `NotModified` when equal; the `fstat` shortcut only if the spike allowed it.
  - A missing share is `Unavailable`, never `Io`, so the service shows "unavailable" without an error notification (spec 4).
- [ ] Tests:
  - a regular file → `Fetched` with its hash; the same content again → `NotModified`; a replaced file with new content → `Fetched`
  - a symlink as last component, a FIFO, an oversized file → refused (the FIFO without blocking)
  - a path under a missing directory → `Unavailable`
  - a read that blocks (a test hook replacing the reader with one that sleeps) → `Unavailable` after the timeout; a second fetch during the hang returns at once
- [ ] Resolved by the core review (Tasks 2–5): `FileCatalogFetcher` owns the 20 s read timeout; `read_catalog_file` itself has none (it clears `O_NONBLOCK` after the regular-file check, so a slow share blocks the worker thread, not the caller).
- [ ] Commit: `feat(app-core): file source for team catalogs`.

## Task 11: app-core – the catalog service: subscribe, refresh, apply, unsubscribe

**Files:** create `crates/app-core/src/catalog.rs`; modify `crates/app-core/src/vault_stores.rs` (a `VaultCatalogs` store over `VaultLifecycle`), `crates/app-core/src/manager.rs` (catalog ownership in `ConnectionItem` views, effective colour), `crates/app-core/src/view_model.rs`, `crates/app-core/src/control.rs` (`forget_keys`). Tests in `crates/app-core/tests/catalog_service.rs` with fakes (`FakeFetcher`, `MockRoot`, the in-memory vault from `tests/common`).

- [ ] API:
  ```rust
  pub struct SubscribeInput { pub source: CatalogSource, pub team_key: TeamKey, pub fingerprint: Fingerprint, pub bearer: Option<Zeroizing<String>> }
  pub struct CatalogPreview { pub catalog_id: Uuid, pub name: String, pub version: u64, pub fingerprint: Fingerprint,
                              pub connections: usize, pub folders: usize, pub slots: Vec<String>, pub risky: usize, pub team_secrets: usize }
  pub enum RefreshResult { NotModified, Applied(ApplySummary), Unchanged, Refused(CatalogError) }
  pub struct CatalogService { /* vault, fetchers (https, file), manager, control, notifier, clock, entropy, Mutex<state> */ }
  impl CatalogService {
      pub fn preview(&self, input: &SubscribeInput) -> Result<(CatalogPreview, PendingSubscription), CatalogError>;
      pub fn confirm(&self, pending: PendingSubscription) -> Result<ApplySummary, CatalogError>;
      pub fn refresh(&self, catalog_id: Uuid, trigger: RefreshTrigger) -> RefreshResult;
      pub fn refresh_all(&self, trigger: RefreshTrigger) -> Vec<(Uuid, RefreshResult)>;
      pub fn update_subscription(&self, catalog_id: Uuid, change: SubscriptionChange) -> Result<(), VaultError>; // team key, bearer, source
      pub fn unsubscribe(&self, catalog_id: Uuid) -> Result<UnsubscribeReport, CatalogError>;
      pub fn duplicate(&self, local_id: Uuid) -> Result<Uuid, VaultError>;
      pub fn process_pending_removals(&self);
      pub fn view(&self) -> Vec<SubscriptionView>;
  }
  ```
- [ ] Subscribe (spec 5): `preview` fetches with the given source and bearer, opens with `Trust { pinned: fingerprint, publisher_key: None, successor: None }`, no `catalog_id`, no `applied_version`; the first download must match the fingerprint (`UnknownPublisher` otherwise: "The catalog is signed by a different key than the fingerprint you entered."). There is no trust on first use: the fingerprint field is required. An already subscribed `catalog_id` → refused ("You are already subscribed to this catalog."). `confirm` stores the subscription (the publisher key now pinned in full), creates the root folder named after the catalog and applies in the same transaction. `PendingSubscription` holds the opened catalog and the secrets in `Zeroizing` and is dropped after 10 minutes.
- [ ] Refresh: fetch with the stored validators → `NotModified` updates `last_attempt`/`last_success` only. `Fetched` → `open_catalog` with the stored trust, `catalog_id`, `applied_version` and team key. With `reapply` set (after a restore), the service passes `applied_version: None` and checks the floor itself right after `open_catalog`: `offered < applied_version` is handled as `Rollback`, an equal version is applied once and clears `reapply`; then `plan_apply` with the manager's active ids and `apply_catalog` (one transaction with the new record); then `manager.reload()`.
  - `SameVersion` → status `Ok`, validators updated (a re-uploaded identical version), no notification.
  - `Rollback` → status `RollbackRefused { offered }`, the items untouched, one notification per offered version: "Team catalog “%@” offered an older version (v%d after v%d) and was not applied."
  - `WrongTeamKey` → status `TeamKeyChanged`, one notification: "The team key of “%@” has changed. Ask your administrator for the new key."
  - `UnknownPublisher` / `BadSignature` / `Invalid` / other → status `Failed(kind)`, one notification when the status changes, never per attempt.
  - `Unavailable` → status `Unavailable`, no notification.
  - Successor keys (spec 7): a verified catalog whose header announces `successor_key` stores it; a catalog signed by the stored successor re-pins: `pinned` and `publisher_key` become the successor, `successor_key` becomes the new header's announcement (or none). Logged as "publisher key rotated", and the subscription view shows the new fingerprint.
  - After a successful apply with changes: one notification, "Team catalog “%@” updated: 2 added, 3 changed, 1 removed", listing only the non-zero parts (spec 6).
- [ ] Unsubscribe (spec 6): the active catalog connections are disconnected first (`manager.disconnect`, waiting up to 15 s for each to leave the active states); then `unsubscribe_catalog`; then `ControlService::forget_keys(&ids)` removes the removed ids from every paired client's allowlist; then `manager.reload()`.
- [ ] Removal of a connection that was up: `apply_catalog` marks it; `process_pending_removals` runs from a `manager.add_state_listener` hook whenever a pending item leaves the active states, and once at launch; it applies `plan_pending` and prunes the allowlists the same way.
- [ ] `ControlService::forget_keys(keys)` (new): removes the keys from every client's allowlist and saves once. Removals and unsubscribe call it, so a later re-subscribe (same deterministic ids) never re-grants access silently.
- [ ] Manager and view model:
  - `ConnectionItem` views get `catalog: Option<CatalogBadge { catalog_id, name, pending_removal, profile_outdated }>`; the tree rows of the catalog root get `team: true`.
  - The Connections window's editor view model gets `read_only: Option<String>` ("Managed by the team catalog “%@”") for catalog items, and the editors' save commands are refused with that text (the vault refuses too, `CatalogManaged`).
  - The control API sees catalog connections like any other (spec 8): `list`, `up`, `down` and the allowlist use the namespaced local ids; no protocol change.
- [ ] Tests:
  - subscribe with the right fingerprint → items appear; with a wrong fingerprint → `UnknownPublisher`, nothing stored; twice → refused
  - refresh: 304 → no change; v2 → applied, notification text with only non-zero parts; same version → no notification; older version → refused, notification once, items unchanged
  - a wrong team key after a rotation → `TeamKeyChanged`; `update_subscription` with the new key → next refresh applies
  - the successor flow: v3 announces S; v4 signed by S applies and re-pins; v5 signed by the old key after that → `UnknownPublisher`
  - a connection that is up when removed stays listed with `pending_removal`, then disappears after the fake root reports it down; its allowlist entry is gone
  - unsubscribe with one connection up: it is disconnected first; filled slot credential kept; allowlists pruned
  - a restored subscription (`reapply`) applies the same version once
  - the control API `list` (fake host) includes catalog connections with their local ids
  - no log line contains the team key text, the token, a config line or a subscription string (capture the app log in the test)
- [ ] Resolved by the core review (Tasks 2–5):
  - A successor key is stored only from a catalog that was fully opened **and** applied (never from `peek_header`, never from a refused or merely fetched file).
  - When a catalog signed by the stored successor is applied: re-pin (`pinned` and `publisher_key` become the successor) and clear `successor_key` (or replace it with the new header's announcement), in the same transaction as the apply.
  - Reapply after a restore opens with the floor `applied_version - 1` (so the same version opens once and a lower one is still `Rollback`), never with `None`.
  - The subscription string's optional `catalogId` and `minVersion` (`SubscriptionString::catalog_id` / `min_version`) are the first download's `OpenRequest::catalog_id` and rollback floor (`applied_version: min_version - 1`).
  - `peek_header` returns an `UnverifiedHeader` that offers only `display_name()`: never prefill, compare or store its fingerprint, key or catalog id.
  - A successor rotation is not compromise recovery: whoever holds a leaked admin key can announce their own successor. After a compromise the publisher creates a new catalog (new admin key, new team key) and every subscriber re-subscribes with the new fingerprint; the UI and the manual say so.
- [ ] Commit: `feat(app-core): team catalog subscriptions`.

## Task 12: app-core – the refresh schedule, back-off and triggers

**Files:** create `crates/app-core/src/catalog_schedule.rs` (pure); modify `crates/app-core/src/catalog.rs` (`run_scheduler`), `crates/app-core/src/app.rs` (`LaunchStep::StartCatalogRefresh` after `StartUpdateScheduler`), `app/src-tauri/src/main.rs` (the wake hook also wakes the catalog scheduler). Tests in `crates/app-core/tests/catalog_schedule.rs` and the `LAUNCH_SEQUENCE` order test.

- [ ] Pure schedule:
  ```rust
  pub const REFRESH_INTERVAL: Duration = Duration::from_secs(15 * 60);
  pub const BACKOFF_START: Duration = Duration::from_secs(60);
  pub const BACKOFF_MAX: Duration = Duration::from_secs(60 * 60);
  pub enum RefreshTrigger { Launch, Timer, Wake, Unlock, Manual }
  /// Next attempt: REFRESH_INTERVAL after the last attempt while healthy; after n ≥ 1 consecutive failures
  /// (Unavailable or Failed) min(BACKOFF_START · 2^(n−1), BACKOFF_MAX), plus a jitter of up to 10 % (injected).
  pub fn next_attempt(last_attempt: Option<Instant>, failures: u32, jitter: f64) -> Option<Instant>;
  pub fn is_due(trigger: RefreshTrigger, next: Option<Instant>, now: Instant) -> bool;
  ```
  - `Launch` and `Unlock` refresh every subscription once (the vault must be unlocked; while locked nothing runs). `Wake` refreshes every subscription once, whatever the back-off (spec 4: on wake), and the failure count keeps counting. `Manual` ("Refresh now") always runs and is the only trigger the UI waits for. `Timer` respects `next_attempt`.
  - A `RollbackRefused` or `TeamKeyChanged` subscription is refreshed on the normal 15-minute schedule (it is not a transport failure).
- [ ] `CatalogService::run_scheduler(sleep)`: one thread, the `Poller`/`run_scheduler` pattern of `updates.rs`, waking every 30 s to check `is_due`; subscriptions are refreshed one after another (each fetch has its own timeout, Task 9/10), and a manual refresh of one catalog runs in the caller's background task, not on the scheduler thread.
- [ ] Tests:
  - healthy: due 15 min after the last attempt
  - back-off: 1, 2, 4, 8, 16, 32, 60, 60 min for n = 1…8; reset after a success
  - wake runs despite back-off; manual always runs; timer does not run inside the back-off
  - locked vault: no fetch at all (count the fake fetcher's calls)
  - the launch order test includes `StartCatalogRefresh` after the vault unlock decision and after `StartUpdateScheduler`
- [ ] Commit: `feat(app-core): team catalog refresh schedule with back-off`.

## Task 13: app-core – catalog connections at connect time

**Files:** modify `crates/app-core/src/manager.rs` (`connect_root`, the native start path), `crates/app-core/src/shared_credentials.rs` (`prompt_credential`), `crates/core/src/credentials.rs` (`CredentialRef`), `crates/app-core/src/credential_prompt.rs` (`CredentialPromptView`), `app/ui/src/lib/CredentialPrompt.svelte`, `crates/app-core/src/connections.rs` (native profile install for catalog items). Tests in `crates/app-core/tests/catalog_connect.rs`.

- [ ] Credential slots at first use (spec 6): a catalog connection linked to an unfilled slot credential has an empty username and no password, so `missing()` asks for both. `CredentialRef` gains `team: Option<String>` (the catalog name); `prompt_credential` fills it from `catalog_owner`. The prompt reads "Office AD (team catalog “Acme VPN”) — enter your user name and password", with both fields, and "Save in vault" saves them into the slot credential through `save_prompted_secret` (the 1.2 path). A second connection using the same slot then connects without a prompt. A sign-in failure re-prompts once, as in 1.1.
- [ ] Per-user fields of SSTP and native connections (see "Resolved points"):
  - SSTP: when a catalog SSTP connection is linked to a slot credential with a non-empty username, `connect_root` replaces the config's `user=` value with that username in memory (`SSTPConfig::parse` → set `user` → `serialized()`) before the config goes to the root layer. The stored config is not changed.
  - L2TP/Cisco: the payload never carries `native.account`; the profile is generated with an empty account and the slot's username is passed as `AuthName`/`XAuthName` at start (`native::start_options` already takes it from `secrets.username`).
  - A catalog native connection without an installed profile shows "Install profile" (the existing `ProfileInstaller` flow); `profile_outdated` shows "The team catalog changed this connection: reinstall its profile", and the next connect offers the reinstall first.
- [ ] Risky directives: `unacknowledged_risk_reason` works unchanged (the catalog item's `acknowledged_risky_directives` is the subscriber's own); the read-only editor keeps the yellow panel's checkbox active and saves through `set_acknowledged_risky`.
- [ ] Tests:
  - an OpenVPN catalog connection with `auth-user-pass` and an unfilled slot → the prompt carries the slot name and the catalog name; Save → the credential is filled; the second connection with the same slot connects without a prompt
  - SSTP: the root layer receives the slot username in `user=`; the stored config is unchanged
  - L2TP: the start options carry the slot username; the generated profile has no account
  - a config change in v2 clears the acknowledgement: the connect is refused until the user ticks it again
  - `profile_outdated` → the connect offers the reinstall
- [ ] Commit: `feat(app-core): credential slots and per-user fields for team connections`.

## Task 14: core and app-core – publishing and admin keys

**Files:** create `crates/core/src/catalog/publish.rs` (pure), `crates/core/src/catalog/admin_file.rs`, `crates/core/src/vault/sealed.rs` (the password-sealed container shared with `backup.rs`), `crates/app-core/src/catalog_publish.rs`; modify `crates/core/src/vault/backup.rs` (use `sealed.rs`), `crates/core/src/exporter.rs` (`write_with_mode`). Tests in `crates/core/tests/catalog_publish.rs`, `crates/core/tests/catalog_admin_file.rs`, `crates/app-core/tests/catalog_publish.rs`.

- [ ] `vault/sealed.rs`: extract the backup container's header, Argon2id key derivation with `MAX_KDF`, XChaCha20-Poly1305 with the header as AAD, and the single `CannotOpen` error into `seal_with_password(magic: &[u8; 8], format: u16, plaintext: &[u8], password: &str, kdf, e)` and `open_with_password(bytes, magic, format, password, max_len)`. `backup.rs` calls them; all backup tests (`CannotOpen` equality, the KDF ceiling before the KDF runs, `NewerVersion` first) pass unchanged.
- [ ] Admin key file (spec 7, the backup admin key kept offline): `<name>.macvpnadminkey`, magic `MVPNAKEY`, format 1, sealed with a password of at least 10 characters (`check_password_rules`); payload JSON `{"version":1,"role":"backup","seed":"<base64>","created":"…"}` in `Zeroizing` buffers. `export_admin_key(key, role, password, kdf, e) -> Vec<u8>`, `import_admin_key(bytes, password) -> (AdminKey, AdminKeyRole)`, `read_admin_key_file(path)` (same rules as `read_backup_file`, cap 64 KiB). Written 0600 with `exporter::write`.
- [ ] Pure publish builder:
  ```rust
  // PublishSelection: catalog/selection.rs (Task 6)
  pub struct PublishPreview { pub payload_counts: (usize, usize, usize, usize), pub personal: Vec<(Uuid, PersonalField)>,
                              pub available_secrets: Vec<(Uuid, SecretField)>, pub available_slots: Vec<(Uuid, String, usize)>,
                              pub refused: Vec<(Uuid, InvalidCatalog)> }
  pub fn preview(vault: &Vault, sel: &PublishSelection) -> Result<PublishPreview, VaultError>;
  pub fn build_payload(vault: &Vault, sel: &PublishSelection, prior: Option<&PublicationRecord>) -> Result<(CatalogPayload, PublicationRecord), PublishError>;
  pub fn item_hashes(vault: &Vault, sel: &PublishSelection) -> Result<BTreeMap<Uuid, String>, VaultError>;
  pub fn changed_since_publish(vault: &Vault, p: &PublicationRecord) -> Result<BTreeSet<Uuid>, VaultError>;
  ```
  - Selection (spec 7 step 1): a selected folder includes its whole subtree; a selected connection whose folder is not selected is placed at the catalog root. Item ids are the publisher's own folder and connection UUIDs (stable across publishes). System VPNs and catalog connections the publisher itself subscribes to cannot be selected.
  - Secrets (step 2): only stored PSKs and key passwords of selected connections are offered; none is included unless ticked. A shared secret keeps its id across publishes (`PublicationRecord.secret_ids`, a random UUID per (connection, field)).
  - Slots (step 3): every shared credential linked to a selected connection is offered as a slot with the credential's id and name; never its username or password. An unticked slot leaves its connections without one (each subscriber's prompt asks per connection).
  - Refusals before writing: configs with an inline `<auth-user-pass>` block, blocking validator issues, native connections whose `account` would be needed (always stripped). `personal` lists the fields of `personal_fields` for the review step; WireGuard private keys need an explicit acknowledgement in the wizard ("Everyone with this catalog uses the same WireGuard key").
  - `item_hashes` covers what the catalog carries (name, folder path, colour, config, native settings, OTP setting, slot, included secret refs); `changed_since_publish` compares them with `PublicationRecord.item_hashes` for the "published in catalog X (v12)" badge (spec 7, admin side).
- [ ] `Publisher` (app-core):
  ```rust
  impl Publisher {
      pub fn admin_keys(&self) -> Result<Vec<AdminKeyRecord>, VaultError>;              // fingerprints and roles only
      pub fn generate_admin_key(&self, role: AdminKeyRole) -> Result<Fingerprint, VaultError>;
      pub fn export_backup_key(&self, path: &Path, password: Zeroizing<String>, remove_after: bool) -> Result<(), PublishError>;
      pub fn import_admin_key(&self, path: &Path, password: Zeroizing<String>) -> Result<Fingerprint, PublishError>;
      pub fn promote_backup_key(&self) -> Result<Fingerprint, VaultError>;
      pub fn preview(&self, sel: &PublishSelection) -> Result<PublishPreview, VaultError>;
      pub fn publish(&self, input: PublishInput) -> Result<PublishResult, PublishError>;   // new or existing publication
      pub fn rotate_team_key(&self, catalog_id: Uuid, path: &Path) -> Result<PublishResult, PublishError>;
      pub fn subscription_string(&self, catalog_id: Uuid, master_password: Zeroizing<String>, source: CatalogSource) -> Result<Zeroizing<String>, PublishError>;
      pub fn forget(&self, catalog_id: Uuid) -> Result<(), VaultError>;
  }
  pub struct PublishResult { pub catalog_id: Uuid, pub version: u64, pub fingerprint: Fingerprint, pub new_team_key: Option<Zeroizing<String>> }
  ```
  - `publish` (spec 7 step 4): requires a primary admin key; the first publish of a catalog generates the `catalog_id` and the team key (returned once in `new_team_key`); every publish takes `version = previous + 1` (1 for a new one), builds the payload, seals and signs it (`seal_catalog`), announces the backup admin key as `successor_key` when one exists, writes the file with `exporter::write_with_mode(bytes, path, 0o644)` (the file is meant to be served; it is encrypted), and only then saves the `PublicationRecord` (version, selection, secret ids, item hashes, path, time). A write failure leaves the version unchanged. MacVPN uploads nothing.
  - `rotate_team_key` (spec 7): a new team key, published at once as the next version to the publication's last path (the save panel confirms it), and returned once. The UI says that rotating is the only way to revoke access to a catalog someone already has.
  - `promote_backup_key`: the backup key becomes the primary, the old primary is deleted. The next publish is signed by it; subscribers that saw the announcement accept it (Task 11). The view suggests generating a new backup key.
  - `subscription_string`: needs the master password (checked by `VaultLifecycle`, no copy kept), and the UI copies the result to the clipboard without showing it (see "Resolved points").
- [ ] Tests:
  - `sealed.rs` round-trip and the backup suite unchanged
  - admin key file: round-trip; wrong password and a flipped byte → the same `CannotOpen`; a backup with `remove_after` deletes it from the vault only after the file is written
  - builder: subtree selection; a connection outside the selected folders lands at the root; secrets only when ticked; slots carry no username or password (scan the payload JSON); refusals listed; system VPNs not selectable
  - publish twice → versions 1 and 2, the same `catalog_id` and item ids; the file opens with the team key and the fingerprint (`open_catalog`)
  - a write into a read-only directory → error, version unchanged
  - with a backup key: the header announces it; after `promote_backup_key` the next file is signed by it and a subscriber (Task 11's service over fakes) follows the rotation
  - `changed_since_publish`: unchanged after publish; a config edit marks the connection
  - rotate: the old team key gives `WrongTeamKey` on the new file
- [ ] Resolved by the core review (Tasks 2–5): besides `personal_fields` (an inline `<key>` or `<pkcs12>` is `OpenVpnInlineKey`), the publish review lists the other inline team secrets of a selected config for an explicit tick each: a WireGuard `PresharedKey`, OpenVPN `<tls-auth>`, `<tls-crypt>`, `<tls-crypt-v2>` and `<secret>` blocks. Inline `<auth-user-pass>` / `<http-proxy-user-pass>` blocks and a strongSwan `secrets { … }` section are refused (`InlineCredentials`); a team PSK goes through `secretRefs`.
- [ ] Commit: `feat: publish team catalogs and manage admin keys`.

## Task 15: Tauri – commands, capabilities and wiring

**Files:** create `app/src-tauri/src/catalog.rs`; modify `app/src-tauri/src/main.rs` (`build_state`: `CatalogService` with `CurlCatalogFetcher` and `FileCatalogFetcher`, `Publisher`; the sandbox uses the same fetchers with sandbox paths, and an HTTPS source is refused in the sandbox with "HTTPS sources are not available in the sandbox"), `app/src-tauri/src/state.rs`, `app/src-tauri/build.rs`, `app/src-tauri/capabilities/main.json`, `app/src-tauri/src/dialogs.rs` (save panel for `.macvpncatalog` and `.macvpnadminkey`, open panel for a file source and an admin key file).

- [ ] Commands, all with the window label check, all input validated in Rust (ids UUID-shaped and existing, names through their rules, sources through Task 5, team key through `TeamKey::parse`, fingerprint through `Fingerprint::parse`, token through the `b64token` rule, passwords into `Zeroizing` at once, never logged):
  - subscriber: `catalog_parse_subscription(text) -> { source, fingerprint }` (the team key is checked but never echoed), `catalog_preview(input) -> CatalogPreview` (keeps the pending subscription in the state under a random id), `catalog_confirm(pendingId)`, `catalog_refresh(catalogId?)`, `catalog_update(catalogId, teamKey?, token?, clearToken, source?)`, `catalog_unsubscribe(catalogId)`, `catalog_duplicate(itemId, name)`, `catalog_set_acknowledged_risky(itemId, directives)`
  - publisher: `admin_key_generate(role)`, `admin_key_export(path, password, removeAfter)`, `admin_key_import(path, password)`, `admin_key_promote()`, `publish_preview(selection)`, `publish_catalog(input)`, `publication_rotate_team_key(catalogId, path)`, `publication_copy_subscription(catalogId, masterPassword, source)` (copies to the pasteboard in Rust and returns nothing), `publication_forget(catalogId)`
- [ ] `new_team_key` is returned only by `publish_catalog` / `publication_rotate_team_key` and never stored in the state or the view model.
- [ ] View model: `catalogs: Vec<SubscriptionView { id, name, source (redacted), fingerprint, version, status, lastRefresh, lastSuccess, error, hasToken, slots: [{ name, filled, credentialName }] }>`, `publishing: { adminKeys: [{ role, fingerprint, created }], publications: [{ id, name, version, lastPublished, path, changed: usize }] }`.
- [ ] Wake: the existing `observe_wake` callback also calls `CatalogService::wake()`.
- [ ] Tests:
  - the capability/command list test; the label check
  - each command's validation (bad UUID, bad team key, `http://` source, bad token, short password)
  - `catalog_parse_subscription` output never contains the team key (serialize and search)
  - the view model contains no team key, token or subscription string (serialize and search)
- [ ] Commit: `feat(app): team catalog commands and wiring`.

## Task 16: UI – team catalogs for subscribers

**Files:** create `app/ui/src/lib/catalog/TeamCatalogs.svelte`, `AddCatalog.svelte`, `CatalogDetail.svelte`, `TeamBadge.svelte`, `subscription.ts` (+ test), `status.ts` (+ test); modify `app/ui/src/lib/manage/Sidebar.svelte` (the section and the badges), `Detail.svelte` / `EditorHost.svelte` / `TextEditor.svelte` / `NativeForm.svelte` / `SstpForm.svelte` (read-only mode), `app/ui/src/lib/folders/FolderRow.svelte`, `app/ui/src/lib/MenuRow.svelte`, `crates/core/l10n/strings.json`.

- [ ] "Team catalogs" section in the Manage window (spec 9): each subscription with name, source (redacted), status, last refresh, version, the publisher fingerprint, and the error text; actions Refresh now, Edit (team key, access token, source), Unsubscribe.
- [ ] "Add team catalog…" (spec 5): a paste field for the subscription string, which fills the source and the fingerprint and keeps the team key out of the DOM after parsing; or the three fields (source: URL or "Choose file…", team key, fingerprint as 8 groups) plus an optional access token. "Check" runs `catalog_preview` and shows the catalog name, version, fingerprint ("Compare it with what your administrator sent you"), counts, the credential slots and the number of connections with risky settings; "Subscribe" confirms. No path without a fingerprint.
- [ ] Team badges: the catalog root folder row and each catalog item carry a "Team" badge (menu and Manage); a pending removal shows "Removed from the team catalog — disappears after you disconnect".
- [ ] Read-only editors (spec 6): name, folder, colour (the publisher's) and config are disabled with the note "Managed by the team catalog “%@”"; enabled are the local colour override ("Use team colour" clears it), pin, connect/disconnect, the risky-settings checkbox, the user's own secret fields that the catalog does not provide (a provided one shows "Provided by the team catalog"), and "Duplicate as personal connection…" (asks for a name, default "<name> (personal)").
- [ ] Edit source (review L3): when the new source is on another origin (another host or port, or a file), `CatalogService::update_subscription` drops the stored access token, so the dialog asks for a new one there ("The access token is not sent to a new address. Enter the token for it, if it needs one.") and shows the subscription without a token until then.
- [ ] Credential slots in the catalog detail: each slot with "Filled in" or "You will be asked when you connect", and "Edit in Credentials" (it is an ordinary shared credential).
- [ ] Unsubscribe dialog: names the catalog and the number of connections, says active ones are disconnected first and that filled-in credentials are kept.
- [ ] The UI clears the team key, the token and the pasted string from the DOM and component state once sent.
- [ ] Tests:
  - `subscription.ts`: fingerprint formatting while typing (8 groups), team key formatting (`TEAM-` + groups), the paste detection of `macvpn-sub:`
  - `status.ts`: each status → its text and severity
  - view tests: the add dialog cannot subscribe without a fingerprint; the read-only editor disables the right fields; the badge and the pending-removal note
  - the l10n coverage test
- [ ] Commit: `ui: team catalogs for subscribers`.

## Task 17: UI – publishing for administrators

**Files:** create `app/ui/src/lib/catalog/Publishing.svelte`, `AdminKeys.svelte`, `PublishWizard.svelte`, `Publications.svelte`, `TeamKeyReveal.svelte`, `wizard.ts` (+ test); modify `app/ui/src/lib/manage/Sidebar.svelte` ("Publishing" section, and the "published in catalog X (v12)" badge on source connections), `crates/core/l10n/strings.json`.

- [ ] Admin key page (spec 7): "Generate admin key" (shows the fingerprint in 8 groups with Copy); "Generate backup admin key" with "Export backup key…" (save panel, password twice, minimum 10 characters, "Remove the backup key from this Mac after export"); "Import admin key…"; "Switch to the backup key" with an explanation that subscribers who refreshed since the backup key was created follow automatically, others must re-subscribe.
- [ ] Publish wizard ("Publish catalog…"), steps (spec 7):
  1. Choose folders and connections (the tree with checkboxes; system VPNs and subscribed team connections are not offered).
  2. Secrets: each stored PSK and key password of the selection, all unticked; ticking one says "Everyone with the team key can read this secret".
  3. Credential slots: the linked shared credentials, ticked by default, "without user names or passwords".
  4. Review: the refusals (fix them first), the personal fields of `personal_fields` (WireGuard needs a tick), the counts.
  5. Name (new catalog only) and the file (save panel, default `<name>.macvpncatalog`; "MacVPN does not upload anything: put the file on your web server or share").
  6. Done: version N written; for a new catalog the team key is shown **once** (`TeamKeyReveal`: Copy, "I saved it", then retype one group), and "Copy subscription string" (asks for the source URL or path the team will use).
- [ ] Publications list: name, version, last published, file, "N changed since last publish", actions Publish new version (the wizard with the saved selection), Rotate team key (with the revoke explanation, then the new key shown once), Copy subscription string (master password, then copied, never shown), Forget.
- [ ] Source connections show "Published in “%@” (v%d)" and, when changed, "changed since the last publish".
- [ ] Tests:
  - `wizard.ts`: step transitions, the subtree selection, the WireGuard acknowledgement gate, the retype check of a team key group
  - view tests: the team key is gone from the DOM after "I saved it"; the rotate dialog's revoke text; the copy action shows no string
  - the l10n coverage test
- [ ] Commit: `ui: publish team catalogs`.

## Task 18: l10n sweep and documentation

**Files:** `crates/core/l10n/strings.json`, `scripts/check-l10n.sh`, `docs/user-guide.en.md`, `docs/user-guide.hu.md`, `docs/how-to.en.md`, `docs/how-to.hu.md`, `README.md`, `docs/control-api.md` / `.hu.md`.

- [ ] Run the l10n coverage tests and `scripts/check-l10n.sh`; a native HU review pass over every string added in this plan with consistent terms: team catalog = „csapatkatalógus”, team key = „csapatkulcs”, publisher = „közzétevő”, publish = „közzététel”, subscribe / subscription = „feliratkozás”, admin key = „adminisztrátori aláírókulcs”, backup admin key = „tartalék aláírókulcs”, fingerprint = „ujjlenyomat”, credential slot = „közös belépési adat helye”, access token = „hozzáférési token”. Settle them in Task 16 (the first UI task) and keep them.
- [ ] User guide (EN/HU): team catalogs for users (subscribing, the fingerprint check, what is read-only, credential slots, updates and removals, unsubscribing); publishing for admins (admin key, backup key, the wizard, team secrets, rotating the team key as the only revocation, file and HTTPS hosting); the security notes of spec 8; what the full backup now contains.
- [ ] How-to (EN/HU): "Share VPN connections with your team", "Host a catalog on a web server or a file share", "Remove a team member's access (rotate the team key)", "Move the admin key to a new Mac".
- [ ] `docs/control-api.md` / `.hu.md`: one paragraph that team catalog connections appear like any other, with stable ids per catalog, and that removing or unsubscribing removes them from every allowlist.
- [ ] Commit: `docs: team catalogs`.

## Task 19: smoke tests with two sandboxes

**Files:** `app/src-tauri/src/smoke.rs`, `scripts/smoke-manage.sh` (a `--catalog` mode), new `scripts/smoke/catalog-publish.js`, `catalog-subscribe.js`, `catalog-update.js`.

- [ ] Per Task 1 D, two sandbox homes `A` and `B` and a shared directory `share/` under the run's temp directory; the runs are sequential unless the spike showed parallel instances work:
  1. **A, publish v1:** seed two OpenVPN connections (one with `auth-user-pass`, linked to a shared credential `Smoke Cred`) in a folder `Smoke Team` with a colour; generate the admin key; publish to `share/smoke.macvpncatalog` with the slot and no secrets; the flow reports the fingerprint and the subscription string through the smoke channel (the smoke runner only, never the app log).
  2. **B, subscribe:** paste the subscription string (file source `share/smoke.macvpncatalog`); check the preview's fingerprint; subscribe; check the root folder `smoke` with the Team badge, the nested `Smoke Team` folder with the colour, two read-only items; connect the `auth-user-pass` one with the fake root → the prompt names the slot and the catalog; Save; connect again without a prompt.
  3. **A, publish v2:** rename one connection, remove the other, add a third.
  4. **B, update:** Refresh now → "updated: 1 added, 1 changed, 1 removed"; the removed one was connected before the refresh → it stays with the pending-removal note until disconnected, then disappears.
  5. **B, rollback:** copy the v1 file over the v2 file; Refresh now → the rollback warning, the items unchanged.
  6. **B, unsubscribe:** the items are gone; `Smoke Cred`'s slot credential is still in Credentials.
- [ ] Every step runs with `SMOKE_LANG=en` and `SMOKE_LANG=hu` and reports through `MacVPN smoke: …` lines checked by `smoke-manage.sh`. The script also checks that `share/smoke.macvpncatalog` contains neither a connection name nor a config line in clear, and that neither sandbox's log contains the team key text.
- [ ] Commit: `test(smoke): publish and subscribe a team catalog across two sandboxes`.

## Task 20: manual checklist

**Files:** `docs/manual-test-checklist.md` (Hungarian, like the rest of the file).

- [ ] A 1.3.0 section, two real Macs (A: admin, B: user), a file share and an HTTPS host:
  - A: admin key, backup key exported to a file and removed from the Mac; publish a catalog with an OpenVPN, an L2TP and an SSTP connection, a slot and a team PSK to the SMB share and to the HTTPS host (with an access token on the host).
  - B: subscribe through the subscription string (share), compare the fingerprint by phone; fill the slot at the first connect; the L2TP profile install asks for approval once; the SSTP connection uses the slot's user name.
  - B: a second subscription through HTTPS with the token; `ps` during a refresh shows no token; the web server log shows `304` on unchanged refreshes.
  - Unplug the share server: B shows "unavailable", no error notification storm, the menu stays responsive; plug it back: the next refresh works.
  - Sleep B for 20 minutes, publish on A meanwhile, wake B: the update arrives without "Refresh now".
  - Publish v3 with a removed connection while B is connected to it: it stays up, disappears after disconnecting.
  - Rotate the team key on A: B shows "team key changed"; enter the new key; it updates.
  - Import the backup key on A, switch to it, publish: B follows without re-subscribing.
  - Restore a full backup of B on a fresh user account: the subscription comes back and the next refresh re-creates the items with the filled-in slot.
  - The control API on B: a paired app sees the team connection; unsubscribing removes it from the allowlist.
- [ ] Commit: `docs: 1.3.0 manual checklist`.

## Task 21: independent security review

- [ ] A reviewer who did not write the code reviews against spec sections 3, 4, 5, 7 and 8 and the rules above, at least:
  - the file format: the order of checks, the signature domain and coverage (magic, length, header, sealed payload), header-as-AAD, nonce freshness, the distinct but non-leaky errors, the size caps before parsing, the proptest
  - rollback: the per-subscription floor, `reapply` after a restore, the backup merge never lowering a version
  - keys: team key and admin key entropy (`Entropy` only), zeroization, redacted `Debug`, no key in logs, argv, env, the view model or webview storage; the admin key file's password container; the successor-key rule (an announcement is accepted only from a verified, newer catalog)
  - sources: the URL canonicalization, https-only redirects, the token never sent cross-origin and never in argv (check with `ps` in a test run), curl's environment, the 8 MB cap mid-transfer; the file source's `O_NOFOLLOW`, FIFO, oversize and hang handling
  - validation: every catalog config through the validators, risky acknowledgement per subscriber and cleared on a config change, no inline credentials, slot credentials never auto-linked to a personal credential by name, team secrets written only for ticked fields and deleted when withdrawn
  - the read-only guard on every write path; namespaced ids; the allowlist pruning
  - the publish flow: no user credential in a catalog (scan a published file's payload in a test), the team key shown once, the subscription string copied without display
  - every new IPC command and the capability file (label checks, input validation)
- [ ] Fix until approved; each fix with a test.
- [ ] Commit(s): `fix: security review findings` (as many as needed).

## Task 22: release 1.3.0

- [ ] Version 1.3.0 in `tauri.conf.json`, `Cargo.toml` `[workspace.package]`, `app/ui/package.json` and the lock files. Root `VERSION` stays 8.
- [ ] `scripts/build-dmg.sh`: the release gate also fails if the `mvpn` binary contains `MVPNCAT1` or `macvpn-catalog-v1` (`grep -a` on both slices), next to the existing SQLCipher checks.
- [ ] No document types are registered for `.macvpncatalog` or `.macvpnadminkey`; `Info.plist` does not change (see "Resolved points"). *(1.3.0 only; after 1.3.0 `.macvpncatalog` became a document type, see "Resolved points" → File types.)*
- [ ] Run everything: fmt, clippy, `CI=1 cargo test`, `npm test` and `npm run build`, smoke EN/HU including the catalog mode, `scripts/build-dmg.sh` with the release gate, CI green.
- [ ] The manual checklist (Task 20) on the DMG.
- [ ] Release: the same flow as 1.2.0 (the user tests the DMG, the `public` sync commit, the `main` push, the CI, the `v1.3.0` tag, the draft check against a local build, the signing by the user). The release notes say that team catalogs need every member on 1.3.0, that the vault schema moves to v2 on first launch (a backup copy is made, and 1.2 can still read it), and that MacVPN never uploads a catalog.

---

## Spec coverage (self-review)

| Spec | Requirement | Task |
|---|---|---|
| 1 | each user keeps credentials, pins, ranking, collapse | 7 (apply keeps them), 13 |
| 1 | no shared database file, no server | (design; nothing built) |
| 2 | catalog file with connections, folder tree, colours, slots, optional secrets | 3, 4 |
| 2 | publisher with an Ed25519 admin key in the vault | 2, 6, 14 |
| 2 | subscriber stores source, pinned fingerprint, team key in the vault | 6, 11 |
| 3 | format: magic, len-prefixed header, sealed payload, signature over domain ‖ header ‖ payload | 4 |
| 3 | team key 256 bits, Crockford text `TEAM-…`, no KDF | 2, 4 |
| 3 | order: signature, monotonic version, decrypt, validators + risky acknowledgement | 4, 7, 13 |
| 3 | 8 MB limit | 4, 5, 9, 10 |
| 4 | HTTPS: system trust, bearer token in the vault, conditional GET, https-only redirects | 6, 9 |
| 4 | file: `O_NOFOLLOW`, regular file, 8 MB, missing share = unavailable | 5, 10 |
| 4 | refresh at launch, every 15 min, on wake, Refresh now, back-off | 12, 15 |
| 5 | "Add team catalog…" with source, team key, fingerprint; no TOFU | 11, 16 |
| 5 | subscription string `macvpn-sub:<base64url JSON>` | 5, 16 |
| 6 | root folder per catalog, Team badge, publisher's tree and colours | 7, 11, 16 |
| 6 | read-only config, name, folder, colour; local pin, ranking, collapse, colour override, slots, connect, duplicate | 6, 7, 11, 16 |
| 6 | slots map to shared credentials by slot id; first-use prompt; saved in the user's vault | 7, 13 |
| 6 | one-transaction apply; up connections stay up; removal after disconnect; notification text | 7, 11 |
| 6 | unsubscribe: confirm, disconnect first, keep filled credentials | 7, 11, 16 |
| 6 | several catalogs, namespaced ids | 6, 7 |
| 7 | generate admin key, export in full backup, fingerprint shown, backup key, successor announcement | 2, 4, 8, 11, 14, 17 |
| 7 | publish wizard steps 1–4, version auto-increment, no upload | 14, 17 |
| 7 | team key generated on first publish and shown once; rotate; revoke text | 14, 17 |
| 7 | admin side: source connections editable; "published in catalog X (v12)" badge | 14, 17 |
| 8 | team key vs signature threat model, rollback warning, validators, secrets never logged | 4, 11, 18, 21 |
| 8 | control API treats catalog connections like any other; allowlist with namespaced ids | 6, 11, 18 |
| 9 | code layout: core catalog, platform-mac HTTP only, app-core service + publishing, UI | 2–17 |
| 10 | format, planner, sources, smoke, manual, security review tests | 3–5, 7, 9, 10, 19, 20, 21 |

---

## Resolved points (spec ambiguities and how this plan settles them)

- **Team key text (spec 3 says "the same 6×4 Crockford format as the recovery key").** 6×4 symbols hold only 120 bits, and the team key has 256. The plan keeps the recovery key's alphabet, grouping and parse rules but uses 13 groups for the key plus one check group: `TEAM-` + 14 groups of 4. The check group tells a typo apart from a wrong key without any decryption.
- **What exactly is signed.** Spec 3 writes `"macvpn-catalog-v1\n" || header || sealed payload`. The plan signs the domain followed by every file byte before the signature (magic, header length, header, sealed payload), so where the header ends is never ambiguous. The full publisher key travels in the header; users compare and pin only its 128-bit fingerprint.
- **"Successor key, signed by the current key".** The announcement is a header field, and the header is covered by the catalog's signature, so the current key signs it. It is accepted only from a catalog that passed every check and was newer than the last applied one. The "backup admin key" is that pre-announced successor. It can be kept offline in a password-sealed `.macvpnadminkey` file, and "Switch to the backup key" promotes it. A subscriber that never saw the announcement must re-subscribe.
- **Distinct but non-leaky errors.** Every failure has its own variant (`NotACatalog`, `Truncated`, `TooLarge`, `NewerFormat`, `BadHeader`, `UnknownPublisher`, `BadSignature`, `WrongCatalog`, `SameVersion`, `Rollback`, `WrongTeamKey`, `Invalid`). A message carries no value from the file except the two version numbers of a rollback. Because the signature is checked before decryption, `WrongTeamKey` can only mean a wrong or rotated key, and the UI says so.
- **An equal version.** It is ignored silently (re-uploading the same file is normal). Only a lower version is refused with a warning. After a backup restore, the same version is accepted once (`reapply`), because the catalog-owned items are not in the backup.
- **Namespaced ids.** Local ids are UUID v8 values derived from (catalog id, kind, item id) with a domain-separated SHA-256. They are UUID-shaped, as the control API and the existing tables require, stable across versions and Macs, and never equal across catalogs. Since a re-subscribe gives the same ids, removals and unsubscribe prune those ids from every paired client's allowlist. Deleting a personal connection keeps today's behaviour.
- **"Read-only" enforcement.** The vault refuses every generic write to catalog-owned rows (`CatalogManaged`). Only the catalog executor writes them. The risky-directive acknowledgement, the colour override, collapse, pins, ranking and the user's own secrets stay writable.
- **Colour override.** The publisher's colour is stored apart (`catalog_items.color`), and the local override in `connections.color`. The effective colour is the override, else the publisher's colour, else the folder's. "Use team colour" clears the override. Catalog folders' colours are the publisher's and are not overridable.
- **Changed and removed connections that are up.** The config in the vault is updated at once; the running tunnel is unaffected because the root layer took its config on stdin at connect, so the new config simply applies at the next connect. A removed connection that is up is moved to the catalog root, marked "removed", and deleted when it leaves the active states. Native profiles whose settings changed are flagged for reinstall.
- **Risky directives.** A catalog never carries an acknowledgement. Each subscriber acknowledges in the read-only editor's yellow panel. The acknowledgement survives an update only when the config is byte-identical, the same rule as the backup merge.
- **Credential slots.** At first apply each slot gets a new shared credential named after the slot (suffixed with the catalog name if the name is taken), with an empty user name and no password. The 1.1/1.2 prompt asks for both at first connect and saves them there. A slot is never linked to an existing personal credential by name: the 1.2 review (M3) forbids automatic links. A connection with its own stored login is not linked. Unfilled slot credentials are removed with the subscription; filled ones are kept.
- **Per-user fields in configs.** L2TP/Cisco never publish `account`, and the slot user name is passed at start. For SSTP, the user name lives in the config (`user=`), so a catalog SSTP connection with a filled slot gets the slot's user name substituted in memory at connect. OpenVPN configs with an inline `<auth-user-pass>` block are refused at publish and at apply. A shared WireGuard private key needs an explicit acknowledgement by the admin.
- **Which secrets can be shared.** Only PSKs and key passwords, each ticked one by one. User names and passwords travel only as slots, without values. A team secret withdrawn in a later version is deleted on the subscriber.
- **Bearer token.** It is not part of the subscription string: spec 5 lists only the source, the team key and the fingerprint, and a token is often per user. It is entered in the add dialog, stored in the vault, sent on curl's stdin, and never sent to another origin after a redirect.
- **Conditional GET.** MacVPN sends its own `If-None-Match` / `If-Modified-Since` headers from validators stored in the vault, and reads the response headers with `--dump-header` (Task 1 A1). For file sources, the default change check is the SHA-256 of the file. An `fstat` shortcut is used only if the spike shows it is reliable on every tested provider.
- **Back-off.** While healthy, a refresh runs 15 minutes after the last one. After n consecutive failures, the next attempt waits min(1 min · 2ⁿ⁻¹, 60 min), with up to 10 % jitter. Wake and "Refresh now" always run. Failures update the status without notifying; only status changes notify (rollback, team key changed, signature or validation problems).
- **The team key "shown once".** The publisher must keep it to publish later versions, so it is stored in the vault. Its text is displayed only at creation and at rotation. Later, "Copy subscription string" asks for the master password and puts the string on the clipboard without displaying it.
- **The catalog file's mode.** It is written 0644, not 0600 like backups, because it is meant to be served or shared. It is encrypted and signed.
- **Vault schema v2 and 1.2.** The new tables are additive and `min_app_schema` stays 1. A 1.2 build opens any newer `schema_version` read-only, whatever `min_app_schema` says, so it reads a v2 vault (every v1 table) and never writes it. That is safe: no 1.2 write can touch a catalog-owned row. The test `a_v2_database_opens_in_a_1_2_build_and_reads_every_v1_table` pins it.
- **What the full backup contains.** Subscriptions (with team keys and tokens), slot bindings, admin keys and publications are added in payload v2. The catalog-owned connections and folders are left out, because they come back from the source, but the user's own secrets, pins and ranking for them are kept. A merge never lowers an applied or published version.
- **Selection rules for publishing.** A selected folder brings its subtree. A selected connection outside the selected folders goes to the catalog root. System VPNs and connections from other team catalogs cannot be published. Item ids are the publisher's own UUIDs, so they stay stable across publishes.
- **HTTPS hosts.** Any host is allowed (not the update allowlist), but only over `https://` with the system trust store, with no user info and with a canonical URL handed to curl after `--`. The sandbox refuses HTTPS sources, so smoke tests use the file source and HTTPS is covered by the fake-curl tests and the manual checklist.
- **File types.** 1.3.0 does not register `.macvpncatalog` or `.macvpnadminkey` as document types. A catalog is added through the subscription string or the add dialog, which keeps the fingerprint step mandatory.
  - **Revised after 1.3.0 (at the user's request):** `.macvpncatalog` is now a document type (exported UTI `local.macvpn.catalog`, Owner). Double-clicking it opens the add dialog with the file preselected as the file source; the fingerprint step stays mandatory (the user enters the team key and the fingerprint, checks the preview and ticks "fingerprint matches"). `.macvpnadminkey` and `.macvpnbackup` stay panel-only (no document type). See spec 5 and `app/src-tauri/src/open_files.rs`.
