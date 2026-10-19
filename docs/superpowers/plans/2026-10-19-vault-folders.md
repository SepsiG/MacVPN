# MacVPN 1.2 encrypted vault, folders, shared credentials and full backup – implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax. The spec is `docs/superpowers/specs/2026-10-19-vault-folders-design.md`, sections 2, 3, 3a and 3b (plus the security notes in 6, the layout in 7 and the tests in 8); where this plan and the spec disagree, the spec wins. Follow the existing patterns of the crate you work in (look at a neighbouring module first).

**Goal:** every piece of MacVPN user data lives in one encrypted SQLite vault unlocked by a master password (cached in the Keychain for auto-unlock), connections can be grouped in nested coloured folders, a username + password can be shared by many connections, and everything can be backed up into one encrypted file and restored. The root layer takes configs on stdin (root `VERSION` 8). Release 1.2.0.

**Base:** the released 1.1.0 (`control-api` merged with `credential-prompt`, see `docs/superpowers/plans/2026-10-19-credential-prompt-live-system.md`). Work on a new branch `vault` from that point.

**Architecture:**
- **Core (`crates/core/src/vault/`, behind the cargo feature `vault`):** the key hierarchy, the recovery-key format, the `KeyStore` and `Entropy` traits, the database (schema, migrations, repositories), the folder tree and colour inheritance, shared credentials and the backup format. All platform-independent and without `unsafe`.
- **platform-mac:** the Keychain `KeyStore`, the `getentropy` `Entropy`, the legacy Keychain reader for the migration.
- **app-core:** the vault lifecycle (create, unlock, auto-unlock, lock now, change password, recovery), vault-backed implementations of the existing store traits (`ConnectionRepository`, `SecretReader`, `SecretWriter`, `RankingPersistence`, `SystemOTPPersistence`, the control-API registry), the migration orchestrator, folders, shared credentials and backup/restore orchestration.
- **mvpn:** config on stdin with length framing, root `VERSION` 8.
- **Tauri / UI:** the vault windows (`vault-*`), the menu's locked state, the folder tree and colours, the Credentials section, backup and restore, all on the 1.1 card design.

**Tech:**
- Rust 1.99.1 (pinned).
- New crates, all in `macvpn-core` behind the `vault` feature (versions pinned by the Task 1 spike, `docs/superpowers/spikes/2026-10-19-vault-spike.md`, "Recommended Cargo setup"):
  - `rusqlite =0.40.2` with `bundled-sqlcipher` (SQLCipher 4.14.0, CommonCrypto on macOS), as a `cfg(target_os = "macos")` dependency. The spike result is **go**, so the sealed-columns fallback is not used. The vendored-OpenSSL line for other platforms is added only with a Linux/Windows port.
  - `argon2 =0.6.0` and `chacha20poly1305 =0.11.0` (RustCrypto, pure Rust), both `default-features = false, features = ["alloc", "zeroize"]` (no `getrandom`; randomness comes from `Entropy`).
  - `zeroize` (already used by `mvpn`; plan A adds it to core and app-core).
- `macvpn-app-core` enables `macvpn-core/vault`. **`mvpn` never does:** the root binary must not link SQLite or the vault code, and the release gate (Task 26) checks that.
- Tauri 2, Svelte + TS. No other new crates unless the subagent shows a need and the reviewer agrees.

**Rules for every task:**
- TDD: write the failing test first.
- `cargo fmt --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `cargo test --workspace --locked` green before each commit. For UI work also `cd app/ui && npm test && npm run build`. For `mvpn` work also `scripts/test-root.sh`.
- No `unsafe` outside `platform-mac` and `mvpn`.
- Never log, and never put in argv or env: the master password, the recovery key, the DEK, a KEK, a backup password, a VPN secret, or a config. The vault logs only events: created, unlocked, locked, migrated, wrong password, attempt counts.
- Key material lives only in `Zeroizing` buffers. The master password and the recovery key are never in the view model or in webview storage.
- Every new user-facing string goes into `crates/core/l10n/strings.json` in EN and HU (right `scope`). The l10n coverage tests (`crates/app-core/tests/l10n_coverage.rs`, the `mvpn` call-site test, `npm test`) must pass.
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- The maintainer's forbidden company name never enters the repo (code, tests, fixtures, docs, commit messages). Use neutral examples such as "Office AD".

**Key facts from the current code (read before starting):**
- Storage today:
  - `ConnectionStore` (`crates/core/src/store.rs`): `connections/<UUID>/{meta.json,config}` under `~/Library/Application Support/MacVPN`, written by `write_private` (0600, atomic, `O_NOFOLLOW`).
  - `ConnectionRankingStore` (`ranking.rs`): `connection-order.json`. `SystemOTPStore` (`system_otp.rs`): `system-otp.json`. The control-API `Registry` (`control/registry.rs`): `control-clients.json`, through `Registry::load(dir)` / `save(dir)`, called from `app/src-tauri/src/control.rs` and the server (`ControlOptions`).
  - Secrets: `KeychainSecretStore` (`platform-mac/src/secrets.rs`), service `local.macvpn.secrets`, account `<UUID>.<field>` (`username`, `password`, `psk`, `keypass`). The account key is the managed connection's UUID **or** a system VPN's service ID. The legacy service `macvpn` is moved over at launch by `migrate_legacy_items` (`LaunchStep::MigrateKeychain`).
- The app reads and writes through traits in `crates/app-core/src/deps.rs`: `ConnectionRepository`, `SecretReader`, `SecretWriter`, `RankingPersistence`, `SystemOTPPersistence`. The manager (`Dependencies`) and the editors (`EditorDeps`) are built in `app/src-tauri/src/main.rs` (`build_state`); the sandbox swaps in `InMemoryKeychain`.
- The root layer today copies the config itself with `sudo -n -u <user> /bin/cat` (`crates/mvpn/src/run_dir.rs`, `prepare` / `copy_as_user`); secrets come on stdin as `key=value` lines (`crates/mvpn/src/secrets.rs`, `STDIN_MAX` 64 KiB); the config limit is `SRC_MAX` (1 MB, `paths.rs`). `mvpn validate <kind> <file>` and `--swan-names|--sstp-params|--sstp-ca <file>` read a file path; the `up` path calls the same functions on `run/config` directly. `VERSION` is 7 (`crates/mvpn/VERSION`, test `version_is_7`).
- The app requires the bundled root version: "Update required (7 → 8)" appears when the installed `VERSION` differs from the bundled one (`crates/app-core/src/setup.rs`, `platform-mac/src/setup_checker.rs`); the installer is `platform-mac/src/root_installer.rs` (tests in `crates/platform-mac/tests/root_installer.rs`).
- Native L2TP/Cisco profiles are generated by `mobileconfig::generate`, which puts the **PSK** into the profile (`SharedSecret`), but not the password. `native::start_options` passes `AuthName`/`XAuthName`, the password and the PSK at start through `SCNetworkConnection` user options.
- The per-connection export (`exporter::export`) writes only the config text, or a `.mobileconfig` for native kinds (which the importer refuses). There is no separate exported metadata today.
- Ordering: `ConnectionRanking::order` = pinned (pin order) → score (14-day half-life) → localized name → key. `ConnectionManager::ordered_items()` is also the control API's `list` order.
- `docs/manual-test-checklist.md` is written in Hungarian; keep that.

---

## Task 1: spike – SQLCipher universal build, Keychain DEK item, Argon2id cost, native profile secrets

**Goal:** settle the four open technical questions before any production code. The findings go into `docs/superpowers/spikes/2026-10-19-vault-spike.md` (kept); the throwaway code (a `crates/vault-spike` workspace member or an `examples/` file) is removed again in Task 6. Commit the findings and the spike code together.

**Status (2026-10-19): done**, see `docs/superpowers/spikes/2026-10-19-vault-spike.md`. The probes ran outside the repository, so only the report was committed and Task 6 has no spike code to delete. The decisions:
- **A – go.** `rusqlite =0.40.2` + `bundled-sqlcipher` gives SQLCipher 4.14.0 with `cipher_provider = commoncrypto` on both slices (x86_64 checked under Rosetta). It links only Security, CoreFoundation and libSystem. A wrong key gives `SQLITE_NOTADB`. There is no plaintext in the db or the `-wal`. The build costs about 10 s per target and about 1.9 MB per slice.
  - CommonCrypto is chosen only when no `OPENSSL_DIR` / `OPENSSL_LIB_DIR` / `OPENSSL_INCLUDE_DIR` is set. These variables are not tracked for rebuilds, and an exported `OPENSSL_DIR` silently links the Homebrew libcrypto dylib. That is why the provider gates in Task 6 and Task 26 were added.
  - Still open:
    - the real `build-dmg.sh` and CI `dmg` run with the crate linked. Task 6's CI run is the check.
    - the Linux `cargo check`, which is information only.
- **B:**
  - The Keychain item is written with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. It is accepted without an entitlement, but the file-based login keychain drops it (there is no `pdmn`).
  - The effective protection is the keychain's lock state plus the item ACL, bound to the ad-hoc cdhash. Each update with a new cdhash gives one prompt for the single item.
  - Still open: the prompt count and the login-password field in the dialog, verified by hand (spike report B.4).
- **C:** `KdfParams::DEFAULT = { m_kib: 65536, t: 32, p: 1 }`. It takes 0.66 s on an M5. t = 3 takes only 60 ms. No Intel Mac was available.
- **D:**
  - The PSK is honoured when it is passed in the `SCNetworkConnectionStart` user options. This has been field-tested since 0.1.3.
  - Whether a profile without `SharedSecret` installs and works from System Settings needs the manual test in the spike report, D.3. Until that passes, Task 12 takes the "PSK stays in the profile" branch.

**Part A – SQLCipher (automated):**
- [ ] Add a throwaway crate depending on `rusqlite` (latest) with `features = ["bundled-sqlcipher"]` for macOS and `bundled-sqlcipher-vendored-openssl` for other targets (`[target.'cfg(…)'.dependencies]`).
- [ ] Prove, and record the evidence:
  - `cargo build --release --target aarch64-apple-darwin` and `--target x86_64-apple-darwin` both work from a clean `target/`, and `lipo -create` gives a universal binary.
  - `PRAGMA cipher_provider` returns `commoncrypto` and `PRAGMA cipher_version` a 4.x value on both slices (run the x86_64 slice under Rosetta).
  - `otool -L` lists only system libraries (Security.framework and libSystem); `nm` shows no OpenSSL symbols.
  - A database created with a raw key (`PRAGMA key = "x'<64 hex>'"`) reopens with the same key, fails with `SQLITE_NOTADB` with another key, and a `hexdump` of the file shows neither the `SQLite format 3` header nor a known canary string.
  - `scripts/build-dmg.sh` (with the spike crate linked into the app temporarily) and the CI `dmg` job on `macos-15` are green. Record the added build time and binary size.
  - `cargo check` on `ubuntu-latest` with the vendored-OpenSSL feature (one manual CI run) compiles. It is not a release gate; record the result.
- [ ] **Go:** every point above holds. **No-go:** any macOS point fails and cannot be fixed with a build flag in an hour of work. Then Task 6 uses the fallback: plain SQLite (`rusqlite` `bundled`) with every payload column sealed by XChaCha20-Poly1305; the key hierarchy does not change.

**Part B – the Keychain item for the DEK (maintainer's Mac, manual):**
- [ ] With a small ad-hoc-signed, hardened-runtime test app (same signing as `build-dmg.sh`, no entitlements), create a generic password item (service `local.macvpn.vault-spike`, account `dek`) with `kSecAttrAccessible = kSecAttrAccessibleWhenUnlockedThisDeviceOnly` in the login keychain.
- [ ] Record:
  - whether the attribute is accepted and kept without the data-protection keychain (`kSecUseDataProtectionKeychain` needs an entitlement we do not have)
  - that another ad-hoc binary is prompted
  - how many prompts appear after re-signing the same app (expected: one, "Always Allow")
  - that reading while the screen is locked fails or blocks as documented
- [ ] **Decision:** the attribute set used by Task 5 (`WhenUnlockedThisDeviceOnly` if kept, otherwise `WhenUnlocked`, the spec's minimum), written into the findings.

**Part C – Argon2id cost:**
- [ ] Measure `Argon2id(m=64 MiB, t=3, p=1)` on Apple Silicon (release build) and natively on an Intel Mac if available (Rosetta is not representative; note it if no Intel Mac is available).
- [ ] **Decision:** keep `t = 3` if Apple Silicon takes 0.5–1 s; otherwise pick the `t` (`m` stays 64 MiB) that lands in that window. Task 4 uses this as `KdfParams::DEFAULT`. **Result: t = 32** (spike report C).

**Part D – native L2TP/Cisco profile secrets (maintainer's Mac, manual, spec 2.6):**
- [ ] Install a MacVPN-generated L2TP and Cisco profile and inspect the System keychain (`security dump-keychain /Library/Keychains/System.keychain`, names only, never `-d`): where the PSK lands and under which item.
- [ ] Generate test profiles **without** `SharedSecret` and connect through MacVPN (PSK passed by `start_options`) and through System Settings.
- [ ] **Decision rule:**
  - If the profile without a PSK connects through MacVPN **and** System Settings still works (macOS asks for the secret), Task 12 generates profiles without the PSK, and the vault holds the only copy.
  - Otherwise the PSK stays in the profile, because macOS owns those profiles. MacVPN's own copy moves into the vault and is still passed at start.
  - The password is never in the profile today; it moves into the vault in both cases.
- [ ] Commit: `docs(spike): SQLCipher build, Keychain DEK item, Argon2id cost, native profile secrets`.

## Task 2: mvpn – config on stdin, root VERSION 8

**Files:** `crates/mvpn/src/secrets.rs`, `run_dir.rs`, `updown.rs`, `validate.rs`, `main.rs` (usage text, `version_is_8`), `paths.rs` / `testmode.rs` (remove `src_base` / `MVPN_SRC_BASE`), `strongswan.rs` (EAP failure message), `crates/mvpn/VERSION` (`8`), `crates/core/l10n/strings.json` (scope `mvpn`), `scripts/test-root.sh`.

- [ ] Stdin protocol for `up` (and `validate`):
  ```
  config <len>\n<len bytes of config><secret lines as today: username=…\n password=…\n …>
  ```
  - `<len>`: ASCII decimal, 1–7 digits, no sign, no leading zero, `1 ≤ len ≤ SRC_MAX` (1 MB). Anything else → `Invalid input`. Too big → the existing `The config is too large (1 MB at most)`, refused before reading the body.
  - The body is read into a `Zeroizing<Vec<u8>>` (the config may hold private keys). Fewer than `len` bytes → `The config is incomplete` (new key). A NUL byte → `The config must not contain NUL bytes` (new key). It must be UTF-8, as today's validators already require.
  - After the body, the rest is parsed **strictly**: only complete lines of the known keys (`username=`, `password=`, `psk=`, `keypass=`, `otp=`, `challenge=packed`). Any other line, or an unterminated last line → `Invalid input`. This is how a length mismatch (a `len` shorter than the real config) is caught.
  - The total stdin cap becomes `SRC_MAX + 64 KiB + 16`.
  - No `config` header on `up` → `Config not provided` (new key). `down`, `respond` and `status` read no config.
- [ ] `Secrets::read_framed() -> Result<(Zeroizing<Vec<u8>>, Secrets), FrameError>` and a pure `parse_framed(&[u8])`, both tested; the old lenient `parse` stays only for `respond`'s use, if any. Check this first and delete it if nothing else uses it.
- [ ] `run_dir::prepare(ctx, config: &[u8])` writes `run/config` (0600, created new in the 0700 run directory) from memory. Remove `resolve_src_base`, `copy_as_user`, the `sudo -u <user> cat` call, and the source-file symlink, owner and link-count checks: the root layer no longer opens any user file. Validation of the copy stays exactly as today (`validate::validate_config`).
- [ ] `mvpn validate [--lang en|hu] <openvpn|wireguard|strongswan|sstp> [--accept-risky a,b]` and `mvpn validate [--lang] --swan-names|--sstp-params|--sstp-ca` read the framed config from stdin (no secret lines; anything after the body → `Invalid input`). The `<file>` argument is removed.
- [ ] strongSwan EAP sign-in failure: when `swanctl --initiate` fails and its output or the connection log contains `EAP_FAILURE` or `EAP method … failed`, `mvpn` reports `Authentication failed (EAP)` (new key) instead of `IKE negotiation failed (details in the log)`. The app's classifier gets this key in Task 3.
- [ ] `VERSION` = 8, test `version_is_8`, usage strings updated.
- [ ] `scripts/test-root.sh`:
  - `new_conn` keeps the config under `$T/cfg/<id>` (test data only, never read by `mvpn`). A new `feed <id>` helper prints `config <bytes>\n` + the file. Count bytes with `wc -c` under `LC_ALL=C`, never `${#var}`.
  - Every `printf 'username=…' | … up …` becomes `{ feed "$ID"; printf 'username=…'; } | … up …`, and every validator call pipes `feed`.
  - `EXPECT_VERSION=8`.
  - The source-config cases ("symlink config", "symlink kapcsolat-könyvtár", owner and link count) are replaced by "a file at the old path is ignored" (a config left under the old directory, `up` without a header → `Config not provided`).
  - New cases, each checking the exit code, the message, that no run directory is left, and that no secret or config line reaches the log:
    - a truncated stream (len 100, 50 bytes sent)
    - a length mismatch (len shorter than the config, so config lines arrive as "secret lines")
    - an oversize config (len 1048577)
    - an embedded NUL
    - a bad header (`config -1`, `config 01`, `config 1x`, no newline)
    - a secret line before the header
    - `validate` with stdin for each kind and each `--swan-names|--sstp-params|--sstp-ca`
    - strongSwan EAP failure through a fake `swanctl` mode `eapfail`
  - `MVPN_IMPL=bash` (the Swift-era reference) cannot speak the new protocol: remove that branch from the harness. The `legacy/swift` files stay for the `bash_messages_are_in_the_table` test.
  - All remaining existing cases stay green.
- [ ] Unit tests in `secrets.rs` for `parse_framed`, covering every error above plus a config containing `password=` lines that must **not** be taken as secrets.
- [ ] Commit: `feat(mvpn): config on stdin, root layer 8`.

## Task 3: app – send the config on stdin, require root 8

**Files:** `crates/app-core/src/deps.rs` (`RootClient::up`), `crates/app-core/src/manager.rs` (`connect_root`), `crates/platform-mac/src/mvpn_client.rs`, `app/src-tauri/src/platform.rs`, `app/src-tauri/src/smoke.rs` (`FakeRoot`), `app/src-tauri/src/control.rs` test doubles, `crates/app-core/tests/common/mod.rs` (`MockRoot`), `crates/platform-mac/tests/root_installer.rs`, `crates/core/src/credentials.rs` (classifier, from plan A).

- [ ] `RootClient::up(&self, kind, id, config: &[u8], secrets: &Secrets, debug, accept_risky)`. `connect_root` always loads the config through `deps.store.load_config` (today only OpenVPN does); an unreadable config fails the connect with the existing `Config not found` text, without calling `mvpn`.
- [ ] `MvpnClient::up` builds the stdin as `config <len>\n` + config bytes + `secrets.stdin_payload()`, in one `Zeroizing<Vec<u8>>`. `CommandRunner::run` takes `stdin: Option<&str>` today: add a bytes variant (`run_bytes`) rather than forcing UTF-8, and make sure the buffer is wiped after the write.
- [ ] The installer and setup-checker tests move from layer 7 to 8 (bundled `VERSION` "8"; the "Update required (7 → 8)" text appears with an installed 7).
- [ ] `credentials::is_sign_in_failure` also accepts `Authentication failed (EAP)` (EN/HU), so IKEv2 EAP gets the plan-A re-prompt.
- [ ] Tests:
  - `up_arguments` unchanged
  - the stdin bytes for a config with `password=` lines and a UTF-8 name are `config <exact byte length>\n…`
  - the secrets are never in the arguments
  - `MockRoot` receives the config
  - an unreadable config → `Failed`, no `up` call
  - root installer: 7 → 8 upgrade path
  - the classifier accepts the EAP key
- [ ] Commit: `feat(app): send configs to the root layer on stdin`.

## Task 4: core – key hierarchy and recovery key

**Files:** create `crates/core/src/vault/mod.rs`, `vault/entropy.rs`, `vault/keys.rs`, `vault/recovery.rs`; modify `crates/core/src/lib.rs` (`#[cfg(feature = "vault")] pub mod vault;`), `crates/core/Cargo.toml` (`[features] vault = ["dep:argon2", "dep:chacha20poly1305", "dep:rusqlite"]`, the deps optional), `crates/app-core/Cargo.toml` (`macvpn-core = { …, features = ["vault"] }`). Tests in `crates/core/tests/vault_keys.rs` with `required-features = ["vault"]`.

- [ ] Types and functions:
  ```rust
  // entropy.rs
  pub trait Entropy: Send + Sync { fn fill(&self, buf: &mut [u8]) -> io::Result<()>; }
  /// Deterministic, for tests (a counter-based stream); `#[doc(hidden)]`.
  pub struct FixedEntropy { /* seed */ }

  // keys.rs
  pub const KEYS_FILE: &str = "vault.keys";
  pub const AAD_PASSWORD: &[u8] = b"macvpn-vault-v1|pw";
  pub const AAD_RECOVERY: &[u8] = b"macvpn-vault-v1|rc";
  pub const MIN_PASSWORD_CHARS: usize = 10;
  #[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
  pub struct KdfParams { pub m_kib: u32, pub t: u32, pub p: u32 }
  impl KdfParams { pub const DEFAULT: KdfParams = KdfParams { m_kib: 65536, t: 32, p: 1 }; } // Task 1 C
  pub struct Dek(Zeroizing<[u8; 32]>);            // no Debug value, no Clone
  pub struct Slot { pub kdf: KdfParams, pub salt: [u8; 16], pub nonce: [u8; 24], pub wrapped: Vec<u8> } // per-slot KDF (review M1)
  pub struct KeyFile { pub version: u32, pub password: Slot, pub recovery: Slot }
  pub enum KeyError { Wrong, Corrupt, UnsupportedVersion(u32), Io(io::Error) }
  pub fn derive_kek(secret: &[u8], salt: &[u8; 16], kdf: KdfParams) -> Zeroizing<[u8; 32]>;
  impl Dek { pub fn generate(e: &dyn Entropy) -> io::Result<Dek>; pub fn as_bytes(&self) -> &[u8; 32]; pub fn hex(&self) -> Zeroizing<String>; }
  impl KeyFile {
      pub fn create(dek: &Dek, password: &str, recovery: &RecoveryKey, kdf: KdfParams, e: &dyn Entropy) -> io::Result<KeyFile>;
      pub fn unlock_password(&self, password: &str) -> Result<Dek, KeyError>;
      pub fn unlock_recovery(&self, key: &RecoveryKey) -> Result<Dek, KeyError>;
      pub fn set_password(&mut self, dek: &Dek, new_password: &str, e: &dyn Entropy) -> io::Result<()>;
      pub fn set_recovery(&mut self, dek: &Dek, key: &RecoveryKey, e: &dyn Entropy) -> io::Result<()>;
      pub fn load(dir: &Path) -> Result<KeyFile, KeyError>;
      pub fn save(&self, dir: &Path) -> io::Result<()>;   // JSON, base64 fields, store::write_private (0600, atomic)
  }
  pub fn check_password_rules(password: &str) -> Result<(), String>; // ≥ 10 characters (grapheme count)

  // recovery.rs
  pub struct RecoveryKey(Zeroizing<String>);      // canonical "XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
  impl RecoveryKey {
      pub fn generate(e: &dyn Entropy) -> io::Result<RecoveryKey>; // 15 random bytes = 120 bits → 24 Crockford chars
      pub fn parse(input: &str) -> Result<RecoveryKey, RecoveryKeyError>;
      pub fn as_str(&self) -> &str;
      pub fn group(&self, index: usize) -> &str;   // 0..6, for the "retype one group" check
  }
  ```
  - The Crockford base32 encoder/decoder is hand-written (alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ`). `parse` is case-insensitive, maps `O`→`0` and `I`/`L`→`1`, ignores `-` and spaces, and requires exactly 24 symbols.
  - The secret fed to Argon2id for the recovery slot is the decoded 15 bytes, not the text.
  - The wrap is XChaCha20-Poly1305 with a fresh 24-byte nonce per wrap, and the slot's AAD constant.
  - `vault.keys` JSON: `{"version":1,"password":{"kdf":{"m_kib":…,"t":…,"p":…},"salt":"…","nonce":"…","wrapped":"…"},"recovery":{…}}`. A higher `version` → `UnsupportedVersion`, malformed → `Corrupt`.
  - KDF bounds (security review M1): parameters below the floor (64 MiB, t ≥ 3) or above the ceiling (1 GiB, t ≤ 256, p ≤ 16) → `Corrupt` on load, refused by `create`. New wraps use `KdfParams::strengthened()` = the slot's parameters raised to at least `DEFAULT`. `KdfParams::insecure_for_tests()` exists only with core's `test-support` feature (enabled by core's dev-dependency on itself; app-core tests that need it enable it the same way), and only that exact value bypasses the floor.
- [ ] Tests:
  - known-answer vectors: fix the `FixedEntropy` seed, a password and the DEK, and assert the exact `wrapped` bytes, so a dependency upgrade that changes the output is caught. Use the tiny `KdfParams::insecure_for_tests()` (`{ m_kib: 64, t: 1, p: 1 }`, `test-support`) in tests to keep them fast, and one `#[ignore]` test with `DEFAULT` that also prints the timing.
  - unwrap with the right password / recovery key returns the same DEK
  - a wrong password and a wrong recovery key both → `KeyError::Wrong`, the same variant whether the slot or the AAD is wrong (swap the slots in the file: still `Wrong`, never something that tells which part failed)
  - a flipped byte in `wrapped`, `nonce` or `salt` → `Wrong`
  - `set_password` → the old password fails, the new one works, the recovery slot is untouched and the DEK is the same
  - `set_recovery` → the old recovery key fails
  - recovery key format: 6 groups of 4, only alphabet characters; `parse` round-trips with lower case, spaces, `O`/`I`/`L` substitutions; 23 or 25 symbols and `U` are rejected; two generations differ
  - file: mode 0600 after `save`; load(save(x)) == x; version 2 → `UnsupportedVersion`; garbage → `Corrupt`
  - `check_password_rules`: 9 characters rejected, 10 accepted, 10 emoji (grapheme clusters) accepted
  - `Debug` of `Dek`, `RecoveryKey` and `KeyFile` shows no key bytes
- [ ] Commit: `feat(core): vault key hierarchy and recovery key`.

## Task 5: KeyStore and Entropy – trait in core, Keychain and getentropy in platform-mac

**Files:** create `crates/core/src/vault/keystore.rs`; modify `crates/platform-mac/src/keychain_ffi.rs` (a write with an accessibility attribute), create `crates/platform-mac/src/vault_keys.rs`; modify `crates/platform-mac/Cargo.toml` (`macvpn-core` with `vault`) and `lib.rs`. Reuse `control_socket::random_32`'s `getentropy` call (move it to a shared `sys` helper).

- [ ] Core:
  ```rust
  pub enum KeyStoreError { Unavailable(String), Denied, Io(String) }
  pub trait KeyStore: Send + Sync {
      fn get(&self) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError>;
      fn set(&self, key: &[u8]) -> Result<(), KeyStoreError>;
      fn delete(&self) -> Result<(), KeyStoreError>;
  }
  pub struct MemoryKeyStore { /* Mutex<Option<Zeroizing<Vec<u8>>>>, fail flags for tests */ }
  ```
- [ ] platform-mac:
  - `KeychainKeyStore` (service `local.macvpn.vault`, account `dek`), with the accessibility attribute decided in Task 1 B: `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, in the default (login) keychain, **without** `kSecUseDataProtectionKeychain`. `get` first reads with `kSecUseAuthenticationUIFail`; only if that fails with `errSecInteractionNotAllowed` / `errSecAuthFailed` does it do one read that may show the macOS prompt. `get` maps `errSecItemNotFound` → `Ok(None)`, a user cancel / auth failure → `Denied`, anything else → `Unavailable`. Nothing is logged except the OSStatus number.
  - `SystemEntropy` implementing `Entropy` with `getentropy` in chunks of at most 256 bytes.
- [ ] Linux (libsecret) and Windows (DPAPI) implementations are **not** part of this plan (spec 2.3). The trait is shaped so they can follow.
- [ ] Tests:
  - `MemoryKeyStore` set/get/delete, injected failures
  - `SystemEntropy` fills 1, 256, 257 and 4096 bytes; two fills differ
  - `KeychainKeyStore` against the real Keychain only in an `#[ignore]`d test with a test service name (CI never touches the Keychain); the query dictionary is built by a pure function and unit-tested (service, account, class, accessibility)
- [ ] Commit: `feat(platform-mac): Keychain key store and system entropy for the vault`.

## Task 6: core – the vault database and schema

**Files:** create `crates/core/src/vault/db.rs` and `vault/schema.rs`. Task 1 A was a go, so there is no `vault/seal.rs` and no fallback mode, and there is no spike code to delete. Tests in `crates/core/tests/vault_db.rs`. Dependencies exactly as in the spike report's "Recommended Cargo setup".

- [ ] API:
  ```rust
  pub const VAULT_FILE: &str = "vault.db";
  pub const CURRENT_SCHEMA: u32 = 1;
  pub enum VaultError { Locked, WrongKey, Corrupt(String), NewerSchema { db: u32, app: u32 },
                        MigrationFailed { from: u32, to: u32, detail: String }, Constraint(String), Io(io::Error), Sql(String) }
  pub struct Vault { conn: rusqlite::Connection, /* + Sealer in fallback mode */ }
  impl Vault {
      /// `dir` is created 0700 if missing (checked with lstat like `control_socket::prepare_dir`: a real
      /// directory, our uid, 0700, no symlink); the file is created 0600.
      pub fn create(dir: &Path, dek: &Dek) -> Result<Vault, VaultError>;
      pub fn open(dir: &Path, dek: &Dek) -> Result<Vault, VaultError>;
      pub fn transaction<R>(&mut self, f: impl FnOnce(&Tx) -> Result<R, VaultError>) -> Result<R, VaultError>; // the only write path
      pub fn is_read_only(&self) -> bool;     // a newer database (see "Schema versioning")
      pub fn schema_version(&self) -> u32;
      pub fn close(self);
  }
  ```
- [ ] Open sequence: `PRAGMA key = "x'<hex>'"` as the very first statement (the hex string is built in a `Zeroizing<String>` and dropped right after); then `PRAGMA cipher_compatibility = 4`, `foreign_keys = ON`, `journal_mode = WAL`, `secure_delete = ON`, `temp_store = MEMORY`; then `SELECT count(*) FROM sqlite_master` (a wrong key fails here → `WrongKey`). `create` makes the database file itself first (`OpenOptions` `create_new`, mode 0600, `O_NOFOLLOW`) and only then opens it with SQLite: SQLite gives the `-wal` and `-shm` files the main file's mode, so they are 0600 too, without touching the process umask (which would need `unsafe` in core and races with other threads). `open` refuses a file that is not 0600 or not ours.
- [ ] Schema v1: exactly the spec 2.4 tables, plus these columns:
  - `system_items.missing_since TEXT NULL`: 30-day placement retention (spec 5); used by Task 16.
  - `connections.credential_id`: **not** added. Links are in `credential_links`.
  - `meta` rows: `schema_version`, `created`.
- [ ] Schema versioning (spec 2.4, "Schema versioning"; added on the user's request during Task 6):
  - `meta.schema_version` and `meta.min_app_schema` (the lowest app schema that may write the database), compared with `CURRENT_SCHEMA` on open.
  - **Older:** `PRAGMA wal_checkpoint(TRUNCATE)`, then a byte copy of the encrypted file to `vault.db.bak-v<old>` (0600, atomic; only the last 2 kept). Then the migration runner: an ordered list of `Migration { version, statements }`, each step v→v+1 in its own savepoint inside one `BEGIN IMMEDIATE` transaction, which also writes `schema_version` and `min_app_schema`. Any failure rolls everything back → `MigrationFailed { from, to, detail }`; the database stays at the old version and the backup is kept.
  - **Equal:** normal.
  - **Newer** (or `min_app_schema > CURRENT_SCHEMA`): the versions are read first without writing; then the database is opened with `SQLITE_OPEN_READONLY` + `PRAGMA query_only = ON` if every table and column of this build's schema exists (checked against the migrations applied to a scratch in-memory database, via `pragma_table_info`). `transaction` (every write path goes through it) returns `NewerSchema { db, app }`. Not readable → opening fails with `NewerSchema { db, app }`.
  - A migration must never be needed to read an older database; an older app never writes to a newer one.
- [ ] Fallback mode (only on no-go): `rusqlite` `bundled`, and `Sealer` (XChaCha20-Poly1305, key = SHA-256(`"macvpn-seal-v1"` ‖ DEK), AAD = `"<table>|<column>|<row key>"`, random nonce, stored as `nonce ‖ ciphertext`) applied to every payload column: `meta_json`, `config`, `secrets.value`, `folders.name/color`, `credentials.name/username/password`, `system_otp.json`, `ranking.json`, `control_clients.json`, `connections.color`, `system_items.color`. Ids and `position`s stay in the clear. `credentials.name UNIQUE` is enforced in code (decrypt the names), not by SQL. Keep the same repository API, so no later task depends on the mode.
- [ ] Tests:
  - create → open with the same DEK works; a different DEK → `WrongKey`
  - `dir` and file modes 0700 / 0600; `-wal` / `-shm` 0600; a symlinked `dir` is refused
  - no plaintext: insert a connection named `GrepCanaryName` with config line `remote canary.example.com 1194`, close, and scan the raw bytes of `vault.db`, `-wal` and `-shm` for both strings and for `SQLite format 3` (SQLCipher mode) → none found
  - crash in the middle of a transaction: a child process (re-exec of the test binary with an env flag) inserts 1000 rows in one transaction and calls `std::process::abort()` before commit; the parent reopens: `PRAGMA integrity_check` = `ok` (and `PRAGMA cipher_integrity_check` returns no rows in SQLCipher mode), zero rows from the aborted transaction
  - migration v1→v2 with a test-only fake v2 migration: applied once, `vault.db.bak-v1` created (0600, encrypted, still opens as v1); v1→v3 in one run
  - a failing step (after a succeeding one) leaves v1 intact, nothing of either step, and the backup present → `MigrationFailed`
  - a newer database opens read-only: reads work, `transaction` returns `NewerSchema { db, app }`, the raw connection cannot write, the file is unchanged; a newer database with a renamed known column → `NewerSchema` on open
  - backup rotation keeps the last 2
  - foreign keys are on (`PRAGMA foreign_keys` = 1); `secure_delete` = 1
  - `#[cfg(target_os = "macos")]`: `PRAGMA cipher_provider` = `commoncrypto` and `PRAGMA cipher_version` starts with `4.` (catches an OpenSSL build in `cargo test`, see the spike report A.1)
- [ ] This is the first commit that links `rusqlite`: its CI run (the `rust` and `dmg` jobs) is the outstanding confirmation of Task 1 A. Record the CI result in the spike report.
- [ ] Commit: `feat(core): encrypted vault database and schema`.

## Task 7: core – repositories: connections and secrets

**Files:** create `crates/core/src/vault/repo_connections.rs` and `crates/core/src/vault/color.rs`; tests in `crates/core/tests/vault_connections.rs`.

- [ ] `vault/color.rs` (used by every later task):
  ```rust
  pub enum FolderColor { Red, Orange, Amber, Yellow, Lime, Green, Teal, Cyan, Blue, Indigo, Purple, Pink }
  impl FolderColor { pub const ALL: [FolderColor; 12]; pub fn as_str(self) -> &'static str; pub fn parse(s: &str) -> Option<FolderColor>; }
  ```
  Stored as the lower-case name in the `color` columns.

- [ ] Methods on `Vault` (each write in a transaction):
  ```rust
  pub struct StoredConnection { pub connection: Connection, pub folder_id: Option<Uuid>, pub color: Option<FolderColor>, pub position: i64 }
  pub fn connections(&self) -> Result<Vec<StoredConnection>, VaultError>;
  pub fn save_connection(&mut self, c: &Connection, config: Option<&str>) -> Result<(), VaultError>; // None keeps the stored config; a new row gets position = max+1 in its folder
  pub fn config(&self, id: &Uuid) -> Result<Zeroizing<String>, VaultError>;
  pub fn delete_connection(&mut self, id: &Uuid) -> Result<(), VaultError>;   // also its secrets, credential link, ranking entry, pin
  pub fn secret(&self, item: &str, field: SecretField) -> Result<Option<Zeroizing<String>>, VaultError>;
  pub fn set_secret(&mut self, item: &str, field: SecretField, value: &str) -> Result<(), VaultError>; // "" deletes
  pub fn delete_secrets(&mut self, item: &str) -> Result<(), VaultError>;
  pub fn delete_all_secrets(&mut self) -> Result<(), VaultError>;
  ```
  - `item` is the connection's UUID string **or** a system VPN's service ID, like the Keychain account today.
  - `SecretField` moves from `app-core/deps.rs` into `macvpn_core::models` (re-exported from `deps.rs` so callers keep compiling), with the raw values `username|password|psk|keypass`.
  - `meta_json` is exactly `Connection::to_json()`, so it stays compatible with the Swift-era `meta.json` and the export (`Connection::from_json` reads it back).
- [ ] Tests:
  - save → list round-trips every `Connection` field, using the Swift compatibility fixtures in `crates/core/tests/fixtures/swift/decoded/meta/` that decode successfully
  - `save_connection(c, None)` keeps the config
  - delete cascades to secrets, link, ranking and pin
  - `set_secret("")` deletes; secrets keyed by a service ID work
  - a config with a 1 MB inline block round-trips
  - `meta_json` of a saved row equals `to_json()` byte for byte
  - the colour palette round-trips through `as_str`/`parse`; an unknown stored colour reads as `None`
- [ ] Commit: `feat(core): vault repositories for connections and secrets`.

## Task 8: core – repositories: ranking, pins, system OTP, system items, control clients

**Files:** create `crates/core/src/vault/repo_misc.rs`; modify `crates/core/src/control/registry.rs` (a `RegistryStore` trait); tests in `crates/core/tests/vault_misc.rs` and `crates/core/tests/control_registry.rs`.

- [ ] Ranking: `fn ranking(&self) -> Result<ConnectionRanking, VaultError>` and `fn save_ranking(&mut self, r: &ConnectionRanking)`. Each usage entry is one `ranking` row (`id`, the entry's JSON as in `connection-order.json`); `pins` holds the pin order (`position` 0..n). Saving replaces both tables in one transaction.
- [ ] System OTP: `system_otp_map()` / `save_system_otp_map(&HashMap<String, OTPSetting>)` (rows of `OTPSetting::to_json`).
- [ ] System items:
  ```rust
  pub struct SystemItem { pub service_id: String, pub folder_id: Option<Uuid>, pub color: Option<FolderColor>, pub position: i64, pub missing_since: Option<Date> }
  pub fn system_items(&self) -> Result<Vec<SystemItem>, VaultError>;
  pub fn save_system_item(&mut self, item: &SystemItem) -> Result<(), VaultError>;
  pub fn delete_system_item(&mut self, service_id: &str) -> Result<(), VaultError>;
  ```
- [ ] Control clients:
  - Add to `control/registry.rs`: `pub trait RegistryStore: Send + Sync { fn load(&self) -> Result<Registry, RegistryError>; fn save(&self, r: &Registry) -> io::Result<()>; }`, plus `FileRegistryStore { dir }` with today's file behaviour (including the `.bad` rename).
  - Change `ControlOptions` (`crates/app-core/src/control.rs`) and `app/src-tauri/src/control.rs` to take `Arc<dyn RegistryStore>`; behaviour unchanged.
  - The vault side: `control_clients()` / `save_control_clients(&[PairedClient])`, one row per client (`id`, JSON).
- [ ] Tests:
  - ranking round-trip, including the pin order and the scores' dates
  - system OTP round-trip
  - system item upsert, delete, `missing_since`
  - control clients round-trip
  - `FileRegistryStore` passes the existing registry tests unchanged
- [ ] Commit: `feat(core): vault repositories for order, OTP, system items and paired clients`.

## Task 9: core – folder tree, colours and ordering

**Files:** create `crates/core/src/vault/tree.rs` (pure) and `vault/repo_folders.rs`; tests in `crates/core/tests/vault_tree.rs`.

- [ ] Pure types (`FolderColor` is from Task 7):
  ```rust
  pub struct FolderNode { pub id: Uuid, pub parent: Option<Uuid>, pub name: String, pub color: Option<FolderColor>, pub position: i64, pub collapsed: bool }
  pub enum ColorSource { Own, Inherited(Uuid), None }
  pub enum TreeError { Cycle, UnknownFolder(Uuid), InvalidName }
  pub struct FolderTree { /* by id, children by parent */ }
  impl FolderTree {
      pub fn new(folders: Vec<FolderNode>) -> Result<FolderTree, TreeError>;       // rejects cycles and dangling parents
      pub fn check_move(&self, folder: Uuid, new_parent: Option<Uuid>) -> Result<(), TreeError>; // not itself or a descendant
      pub fn folder_color(&self, folder: Uuid) -> (Option<FolderColor>, ColorSource);
      pub fn item_color(&self, own: Option<FolderColor>, folder: Option<Uuid>) -> (Option<FolderColor>, ColorSource);
      pub fn path(&self, folder: Uuid) -> Vec<String>;                              // root → leaf names, for export
      pub fn descendants(&self, folder: Uuid) -> Vec<Uuid>;
      pub fn depth(&self, folder: Uuid) -> usize;
  }
  pub enum TreeEntry { Folder { id: Uuid, depth: usize }, Item { key: String, depth: usize } }
  /// Per folder (and the root): subfolders by `position` (then name), then the items in
  /// `ConnectionRanking::order` (pinned in pin order, then score, then name).
  pub fn order_tree(tree: &FolderTree, items: &[(String, Option<Uuid>)], ranking: &ConnectionRanking, now: Date, name: impl Fn(&str) -> String) -> Vec<TreeEntry>;
  pub fn validate_folder_name(name: &str) -> Result<String, TreeError>;  // trimmed, 1–64 characters, no control characters (reuse the mfa sanitizer)
  ```
- [ ] Folder repository on `Vault`:
  - `folders()`
  - `create_folder(parent, name) -> Uuid` (position = last)
  - `rename_folder`, `set_folder_color`, `set_collapsed`
  - `move_folder(id, new_parent, position)`: runs `FolderTree::check_move` first, inside the transaction, and renumbers the siblings
  - `delete_folder(id, DeleteMode)` with `pub enum DeleteMode { MoveContentsUp, DeleteContents }`:
    - `MoveContentsUp` re-parents the direct subfolders and items to the deleted folder's parent before deleting.
    - `DeleteContents` relies on `ON DELETE CASCADE` for subfolders and returns the managed connection ids to delete, so the app deletes them through its normal path (profiles, secrets). System VPNs in it always move to the root.
  - `set_item_folder(key, folder)` and `set_item_color(key, color)`: a managed key updates `connections`, a system key upserts `system_items`.
- [ ] Tests:
  - colour inheritance: own; parent; grandparent through an uncoloured parent; none; an override on a connection; clearing the override ("Use folder colour") → inherited again
  - a cycle is rejected: move a folder under itself, under its child, under its grandchild; `new` with a cyclic input → `Cycle`
  - delete with `MoveContentsUp`: the children land in the parent at the end; at the root too
  - delete with `DeleteContents`: cascade of subfolders; the returned ids include connections of nested subfolders; system VPNs are moved to the root
  - `ON DELETE SET NULL` for a connection whose folder vanished through a direct SQL delete
  - ordering: subfolders before items; subfolders by position; pinned first (in pin order) inside a folder; then by score; the root behaves the same; depth 5 works
  - `path` for export
- [ ] Commit: `feat(core): folder tree, colours and ordering`.

## Task 10: app-core – vault lifecycle

**Files:** create `crates/app-core/src/vault.rs`; tests in `crates/app-core/tests/vault_lifecycle.rs` (temp dirs, `MemoryKeyStore`, `FixedEntropy`, small `KdfParams`).

- [ ] API:
  ```rust
  pub enum VaultState { NotCreated, Locked, Unlocked, LegacyReadOnly { error: String } }
  pub enum UnlockError { Wrong { retry_after: Duration }, TooSoon { retry_after: Duration }, Corrupt, NewerSchema, Io(String) }
  pub enum AutoUnlock { Unlocked, NeedsPassword, NotCreated }
  pub struct VaultLifecycle { /* dir, keystore, entropy, kdf, Mutex<Inner { vault: Option<Vault>, dek: Option<Dek>, failures: u32, not_before: Option<Instant> }>, listeners */ }
  impl VaultLifecycle {
      pub fn new(dir: PathBuf, keystore: Arc<dyn KeyStore>, entropy: Arc<dyn Entropy>, kdf: KdfParams) -> Self;
      pub fn state(&self) -> VaultState;
      pub fn create(&self, password: Zeroizing<String>, auto_unlock: bool) -> Result<RecoveryKey, VaultError>;
      pub fn try_auto_unlock(&self) -> AutoUnlock;
      pub fn unlock_with_password(&self, password: Zeroizing<String>, now: Instant) -> Result<(), UnlockError>;
      pub fn reset_with_recovery(&self, key: &RecoveryKey, new_password: Zeroizing<String>, now: Instant) -> Result<(), UnlockError>;
      pub fn lock(&self);
      pub fn change_password(&self, current: Zeroizing<String>, new: Zeroizing<String>) -> Result<(), UnlockError>;
      pub fn new_recovery_key(&self, password: Zeroizing<String>) -> Result<RecoveryKey, UnlockError>;
      pub fn set_auto_unlock(&self, on: bool) -> Result<(), VaultError>;   // on: KeyStore::set(DEK); off: KeyStore::delete
      pub fn auto_unlock(&self) -> bool;                                    // the KeyStore item exists
      pub fn with<R>(&self, f: impl FnOnce(&mut Vault) -> Result<R, VaultError>) -> Result<R, VaultError>; // Locked → VaultError::Locked
      pub fn add_listener(&self, f: impl Fn(VaultState) + Send + Sync + 'static);
  }
  ```
- [ ] Rules:
  - `create` writes `vault.keys` first, then `vault.db`; a failure removes both. With `auto_unlock`, the DEK goes to the `KeyStore`.
  - `try_auto_unlock`: the `KeyStore` item missing, `Denied` or `Unavailable` → `NeedsPassword` (the unlock window). An item that does not open the database (a stale key) → `NeedsPassword`, and the item is **not** deleted automatically.
  - Wrong attempts: the delay after the n-th consecutive failure is `min(2^(n-1), 30)` seconds (1, 2, 4, 8, 16, 30, 30, …). There is no lockout. An attempt before `not_before` → `TooSoon` without running Argon2id. Success resets the count.
  - Wrong password and wrong recovery key give the same `Wrong` error.
  - `lock`: closes the database, drops (zeroizes) the DEK, and keeps the `KeyStore` item. Running VPNs are not touched (that is the manager's side, Task 11).
  - `reset_with_recovery` opens the recovery slot, sets a new password slot, saves `vault.keys`, and unlocks. If auto-unlock is on, the `KeyStore` item is rewritten (same DEK).
  - `change_password` requires the current password and changes only the password slot (the database is not re-encrypted). `new_recovery_key` requires the password and invalidates the old key.
  - Log lines (through the existing app log, source "Vault"): `created`, `unlocked (password|recovery key|auto)`, `locked`, `wrong password (attempt n)`. Never any key material.
- [ ] Tests:
  - create → state `Unlocked`; recovery key returned; `vault.keys` and `vault.db` exist with modes 0600; auto-unlock item present
  - a new instance → `try_auto_unlock` → `Unlocked`; with the item deleted → `NeedsPassword`
  - wrong password ×3 → delays 1, 2, 4 s (fake `Instant`s); an attempt inside the delay → `TooSoon` and Argon2id is not called (count the calls through a test hook); the right password then works and resets the count
  - lock → `with` → `Locked`; the KeyStore item still exists; unlock again
  - change password: the old one fails, the new one works, the data is still there
  - new recovery key: the old one fails, the new one resets the password
  - `set_auto_unlock(false)` deletes the item; `true` writes it
  - a failure injected into `create` after `vault.keys` → neither file is left
  - `KeyStore` returning `Denied` → `NeedsPassword`, no crash
- [ ] Commit: `feat(app-core): vault lifecycle`.

## Task 11: app-core – vault-backed stores and the locked state

**Files:** create `crates/app-core/src/vault_stores.rs`; modify `crates/app-core/src/manager.rs`, `crates/app-core/src/connections.rs`, `crates/app-core/src/import_export.rs`, `crates/app-core/src/control.rs`, `crates/core/src/control/protocol.rs`, `crates/app-core/src/view_model.rs`, `crates/app-core/src/quit.rs`; tests in `crates/app-core/tests/vault_stores.rs`.

- [ ] Implementations over `Arc<VaultLifecycle>`:
  - `VaultConnections: ConnectionRepository`. Locked → `io::Error` of kind `PermissionDenied` with the message `l10n::tr("The vault is locked", &[])`.
  - `VaultSecrets: SecretReader + SecretWriter`. Locked → `get` returns `None`, writes fail silently with a log line (the trait has no error today; keep it that way), `remove_all` clears the table.
  - `VaultRanking: RankingPersistence`, `VaultSystemOtp: SystemOTPPersistence`, `VaultRegistry: RegistryStore`.
  - `ReadOnly<T>` wrappers for the legacy stores, for the migration-failed mode (Task 13): every write fails with "MacVPN is using the old storage in read-only mode until the migration succeeds".
- [ ] The credential prompt (plan A) now saves into the vault through the same `SecretWriter`; its checkbox label becomes "Save in vault" (the 1.1 label "Save" and its Keychain hint are removed from the window and from `strings.json`).
- [ ] Locked state across the app:
  - `ConnectionManager::enter_locked(&self)`: keeps only what is needed to keep polling and to disconnect the **active** connections (id, kind, bound native service ID; the name is replaced by an empty string), drops every other connection, and clears the system-OTP map and the ranking from memory. `reload()` after unlock restores everything. Connect is refused while locked (a `Failed` with "The vault is locked" is **not** used; the menu simply offers no connect).
  - `ConnectionsModel`: every editor, import, export and delete returns `Err("The vault is locked")`; the drafts are dropped on lock.
  - View model: `vault: VaultView { state: "notCreated"|"locked"|"unlocked"|"legacyReadOnly", auto_unlock: bool, show_lock_now: bool, active_count: usize }`. While locked, `rows` contains no names (the menu shows the "Unlock…" row and "N connections active" only).
  - The quit question while locked names no connection, only the count.
- [ ] Control API, still API v1:
  - `ErrorCode::Locked` → `"locked"`.
  - While locked, `pair`, `hello`, `list`, `up` and `status` reply `locked`. `down` still works for an already authenticated session, because it releases a lease and reads nothing from the vault.
  - Existing sessions and leases are kept across a lock.
  - `docs/control-api.md` / `.hu.md` list the new code under the compatibility rule from plan A.
- [ ] Tests:
  - each store round-trips while unlocked and fails as specified while locked
  - lock with one active connection → `connections()` holds one redacted entry, the poll keeps its state, `disconnect_all` stops it; unlock → names back
  - editors refuse while locked
  - control server with the fake host: `locked` for `hello` and `up`, `down` OK for an existing lease; after unlock `hello` works
  - the view model while locked contains none of the seeded names (serialize and search)
- [ ] Commit: `feat(app-core): vault-backed stores and the locked state`.

## Task 12: native profile secrets (per the Task 1 D finding)

**Files:** `crates/core/src/mobileconfig.rs`, `crates/app-core/src/editor.rs` (the native save path), `crates/platform-mac/src/native_vpn.rs` if needed; tests next to them.

- [ ] **If the finding is "PSK must stay in the profile":** no code change in `mobileconfig.rs`. Document in `mobileconfig.rs`' module docs and in the security section of the user guide that macOS keeps the PSK of MacVPN-installed native profiles in the System keychain as part of the profile, while MacVPN's own copies (PSK and password, for the editor and the start options) live in the vault. Add a test that `generate` still embeds `SharedSecret`, to guard the decision.
- [ ] **If the finding is "PSK can be passed only at start":** `generate(connection, psk)` becomes `generate(connection)` with no `SharedSecret`, `AuthenticationMethod = SharedSecret` kept. The editor no longer needs the PSK to build the profile. The start options keep passing it. Existing installed profiles keep their PSK until they are reinstalled: the Connections window shows a one-time "Reinstall to remove the PSK from the profile" note per native connection. Tests: the generated plist has no `SharedSecret`; the start options still include the PSK.
- [ ] In both cases: no MacVPN Keychain item for native secrets remains after the migration (Task 13 moves them); `system_secrets` / `connect_native` read them from the vault through `SecretReader`.
- [ ] Commit: `feat: native profile secrets per the vault spike`.

## Task 13: migration from 1.1 storage

**Files:** create `crates/app-core/src/migration.rs`, `crates/platform-mac/src/legacy_store.rs` (the Keychain listing); tests in `crates/app-core/tests/migration.rs` with fixture data directories under `crates/app-core/tests/fixtures/migration/{swift-era,1.0}/` (build them from the existing Swift fixtures) and an in-memory Keychain (`InMemoryKeychain`).

- [ ] Sources:
  ```rust
  pub struct LegacySources {
      pub support_dir: PathBuf,                       // ~/Library/Application Support/MacVPN
      pub store: Arc<ConnectionStore>,
      pub keychain: Arc<dyn LegacyKeychain>,          // list + read + delete of local.macvpn.secrets items
      pub ranking: ConnectionRankingStore,
      pub system_otp: SystemOTPStore,
      pub registry: FileRegistryStore,
  }
  pub trait LegacyKeychain: Send + Sync {
      fn items(&self) -> Vec<(String /* item id */, SecretField)>;
      fn read(&self, item: &str, field: SecretField) -> Option<Zeroizing<String>>;
      fn delete(&self, item: &str, field: SecretField);
  }
  pub enum MigrationStep { Read, Import, Verify, DeleteFiles, DeleteKeychain, Marker }
  pub struct MigrationReport { pub connections: usize, pub secrets: usize, pub system_otp: usize, pub clients: usize, pub skipped: Vec<String> }
  pub enum MigrationError { Failed { step: MigrationStep, message: String } }
  pub fn has_legacy_data(src: &LegacySources) -> bool;
  pub fn keychain_item_count(src: &LegacySources) -> usize;   // for the "macOS may ask N times" text
  pub fn migrate(vault: &VaultLifecycle, src: &LegacySources) -> Result<MigrationReport, MigrationError>;
  // test-only (`test-support`): migrate_for_tests(vault, src, fail_at: Option<MigrationStep>, after_import)
  pub const MARKER: &str = "migrated-to-vault";
  ```
  `platform-mac::legacy_store::KeychainLegacy` implements `LegacyKeychain` over `KeychainSecretStore` / `KeychainBackend::accounts`. Run `migrate_legacy_items` (the old `macvpn` service) first, as today's launch does.
- [ ] Steps, in order:
  1. **Read** everything into memory (`Zeroizing` for configs and secrets). A connection directory whose `meta.json` does not decode is reported in `skipped` and left on disk.
  2. **Import**: one vault transaction for the connections (meta + config), every Keychain item (managed and system-VPN ids), the ranking and pins, the system OTP map and the paired clients.
  3. **Verify**: read every record back from the vault and compare it with the in-memory source (meta JSON equal, config bytes equal, each secret equal, ranking equal, OTP equal, clients equal). Any mismatch fails the step.
  4. **Delete files** only after verification: for each `connections/<UUID>/{meta.json,config}`, `connection-order.json`, `system-otp.json` and `control-clients.json`, overwrite the file with zeros of the same length, `fsync`, then unlink; then remove the empty directories. A helper `store::shred_file(path)` is added to core and tested.
  5. **Delete Keychain** items (`local.macvpn.secrets`), each one.
  6. Write the **marker** file (0600) in the support directory.
- [ ] On any failure before step 4, nothing is deleted: the vault is closed and its two files are removed, and the app runs in `LegacyReadOnly` (the legacy stores wrapped in `ReadOnly`) until the user retries. A failure in step 4 or 5 leaves the vault (verified and complete) in use, and records the leftovers so a later launch finishes the deletion; the marker is written only after both deletions are done.
- [ ] The migration logs counts only.
- [ ] Tests:
  - the Swift-era fixture and the 1.0 fixture each migrate fully; the report counts match; a system-VPN secret (service-ID key) is migrated
  - verification catches a tampered vault row (inject through a test hook between import and verify)
  - `fail_at` for each step: before `DeleteFiles` → every legacy file and Keychain item still exists byte for byte, and no vault files remain; at `DeleteKeychain` → the files are gone, the Keychain items still exist, no marker, and a second run finishes the job
  - shredded files: the file content is zeroed before unlink (a test hook observes the write)
  - a corrupt `meta.json` is skipped and left in place
  - `has_legacy_data` false on an empty directory
- [ ] Commit: `feat(app-core): migrate 1.1 storage into the vault`.

## Task 14: vault windows – create, unlock, recovery; app wiring

**Files:**
- create `app/src-tauri/src/vault.rs` (windows, commands, the launch decision) and `crates/app-core/src/vault_setup.rs` (the create flow's state machine, pure)
- modify `app/src-tauri/src/main.rs` (`build_state`: the vault-backed stores replace `ConnectionStore`, `Keychain`, the ranking, OTP and registry files; the sandbox uses `MemoryKeyStore` and its sandbox home), `app/src-tauri/src/state.rs`, `app/src-tauri/build.rs`, create `app/src-tauri/capabilities/vault.json` (`vault-*` windows, only the vault commands, `get_view_model` and events)
- create `app/ui/src/lib/vault/CreateVault.svelte`, `Unlock.svelte`, `RecoveryKey.svelte`, `strength.ts` (+ test), `recovery.ts` (+ test); route `vault-` in `App.svelte`
- `crates/core/l10n/strings.json`

Steps:
- **Notes from Task 13 (review):**
  - Run `migration::migrate` **right after `create`, before any store writes to the vault.** A failed migration removes only a vault still marked `created_for_migration`; the first write through `VaultLifecycle::with` ends the mark, and then a failure keeps the vault (`legacy_read_only()` is false). Reads go through `with_read`.
  - The unlock calls take the caller's clock: always pass `Instant::now()`.
  - Build the Keychain side with `platform-mac::legacy_store::KeychainLegacy::system()` and the sources with `LegacySources::new(support_dir, …)`; `migrate(vault, src)` also finishes a pending deletion (`migration-cleanup`) on a later launch.
- [ ] Launch decision, after `MigrateKeychain` and before `ReloadConnections`. Update `LaunchStep` and its order test:
  - Vault present: `try_auto_unlock`. `Unlocked` → normal launch. `NeedsPassword` → the menu is in the locked state and `vault-unlock` opens.
  - No vault, legacy data present → `vault-create` opens in migration mode, while the app runs in `LegacyReadOnly`.
  - No vault, no legacy data → `vault-create` opens for a fresh start.
- [ ] `VaultSetup` steps:
  - `Intro { migrating: bool, keychain_items: usize }`: explains the vault, and in migration mode says "macOS may ask several times — choose Always Allow — this happens only once" with the count.
  - `Password`: the master password twice; the strength hint; minimum 10 characters; the auto-unlock checkbox, on by default.
  - `RecoveryKey { key }`: shown once, with Copy and "I saved it".
  - `Confirm { group: usize }`: retype a randomly chosen group, compared case-insensitively.
  - `Migrating`, then `Verified`, then `Done`. On a failure: `Failed { message }` with Retry.
  The Task 21 restore branch hooks in at `Intro`.
- [ ] Commands, all with a label check on the `vault-*` window:
  - `vault_create(password, autoUnlock) -> { recoveryKey }`. The only time the key crosses IPC; it is never put in the view model.
  - `vault_confirm_recovery(group, typed)`, `vault_migrate()`, `vault_unlock(password)`, `vault_recover(recoveryKey, newPassword)`, `vault_ready()`.
  - Passwords arrive as `String`, move into `Zeroizing` at once, and are never logged.
- [ ] Window rules: the same as the prompt windows (no focus steal at launch, `order_front_regardless`, the 1 s input lock through `mark_shown`/`ready`, no default button), and the window cannot be closed while a migration runs. The unlock window shows the growing delay as a countdown and disables Unlock meanwhile. "Use recovery key" switches the unlock window to the recovery form (recovery key + new password twice).
- [ ] The UI clears every password and the recovery key from the DOM and from its component state once sent or once the window moves on.
- [ ] Tests:
  - `VaultSetup` transitions, including Retry after a failure and the confirm step rejecting a wrong group
  - the launch decision for the three cases (unit test over fakes)
  - the capability/command list test; the label check
  - `strength.ts` (weak / fair / strong cases, with no claim that weak blocks)
  - `recovery.ts` (formatting while typing, normalisation)
  - a view test: the recovery key is shown once and is gone after "I saved it"
  - the l10n coverage test
- [ ] Commit: `feat(app): create, unlock and recover the vault`.

## Task 15: settings, Lock now, the locked menu, change password, new recovery key

**Files:** `app/src-tauri/src/vault.rs`, `app/src-tauri/src/commands.rs`, `app/src-tauri/build.rs`, `app/src-tauri/capabilities/main.json` (the settings commands for the menu / Connections window) and `vault.json`, `app/ui/src/lib/Menu.svelte`, `app/ui/src/lib/vault/ChangePassword.svelte`, the settings area of the menu, `crates/app-core/src/view_model.rs`, `crates/core/l10n/strings.json`.

- [ ] Settings:
  - "Unlock automatically" (default on). Turning it off deletes the Keychain item, after a confirmation that every launch will ask for the master password. Turning it on asks for the master password in `vault-password` (mode `confirm`) and stores the DEK.
  - "Show Lock now" (preference `vaultShowLockNow`, default off).
  - "Change master password…" and "New recovery key…".
- [ ] "Lock now" in the menu, shown when auto-unlock is off or "Show Lock now" is on. It calls `VaultLifecycle::lock` and then `ConnectionManager::enter_locked`. Running VPNs stay up.
- [ ] Locked menu: one "Unlock…" row (opens `vault-unlock`), a line "N connections active" if any, Quit; no names, no switches, no settings that read the vault.
- [ ] `vault-password` window modes: `change` (current + new twice) and `confirm` (one password). `vault-recovery` window: password, then the new key shown once and confirmed by retyping a group, like the create flow.
- [ ] Tests:
  - view model: `show_lock_now` logic (auto-unlock off → shown; on + pref → shown; on without pref → hidden)
  - the commands' validation and label checks
  - a view test of the locked menu (no names in the DOM)
  - the l10n coverage test
- [ ] Commit: `feat(app): vault settings, Lock now and the locked menu`.

## Task 16: folders in app-core – model, commands, export and import metadata

**Files:** create `crates/app-core/src/folders.rs`; modify `crates/app-core/src/manager.rs` (folder data and `ordered_tree`), `crates/app-core/src/view_model.rs`, `crates/app-core/src/connections.rs` (delete paths), `crates/app-core/src/import_export.rs`, `crates/core/src/exporter.rs`, `crates/core/src/importer.rs`; `app/src-tauri/src/commands.rs`, `build.rs`, `capabilities/main.json`.

- [ ] A new trait in `crates/app-core/src/deps.rs`, implemented by `VaultFolders` in `vault_stores.rs` (locked → errors like the other vault stores) and by an in-memory fake in `tests/common/mod.rs`:
  ```rust
  pub struct Placement { pub key: String, pub folder: Option<Uuid>, pub color: Option<FolderColor> }
  pub trait FolderStore: Send + Sync {
      fn folders(&self) -> io::Result<Vec<FolderNode>>;
      fn placements(&self) -> io::Result<Vec<Placement>>;          // managed connections and system items
      fn system_items(&self) -> io::Result<Vec<SystemItem>>;
      fn apply(&self, op: FolderOp) -> io::Result<FolderOpResult>; // create, rename, colour, collapse, move, delete, item move/colour, retention
  }
  ```
  `Dependencies` gets `pub folders: Option<Arc<dyn FolderStore>>` (`None`: everything at the root, as in 1.1).
- [ ] Manager:
  - Holds `folders: Vec<FolderNode>` and the placements (connections' `folder_id`/`color` from `StoredConnection`, system VPNs from `system_items`), loaded in `reload()`.
  - `pub fn ordered_tree(&self) -> Vec<TreeEntry>`.
  - `ordered_items()` (the flat order, used by the control API's `list`) is unchanged.
- [ ] System-VPN placements (spec 5, 30-day retention): after each refresh, a placed service that is not listed gets `missing_since = now` (if it is unset); one that is listed again gets it cleared; rows with `missing_since` older than 30 days are deleted. A pure function `fn retention(items, listed, now) -> Vec<SystemItemChange>`.
- [ ] View model:
  - `tree: Vec<TreeRowView>`, where `TreeRowView` is `Folder { id, name, depth, color, colorSource, collapsed, activeCount, hasConnected }` or `Item { id, depth, color, colorSource }` (the item's other fields stay in `rows`).
  - `depth` is the real depth; the UI caps the indentation at 3 levels.
  - `activeCount` / `hasConnected` count the active connections in the folder and all its descendants.
- [ ] Commands:
  - `folder_create(parent?, name)`, `folder_rename(id, name)`, `folder_set_color(id, color?)`, `folder_set_collapsed(id, collapsed)`, `folder_move(id, parent?, position)`, `folder_delete(id, mode: "moveUp"|"deleteContents")`, `item_move(key, folder?)`, `item_set_color(key, color?)`.
  - Validation: UUID-shaped ids that exist; a colour from the palette or null; the name through `validate_folder_name`.
  - `deleteContents` deletes the returned managed connections through `ConnectionsModel::delete` one by one, which keeps today's profile and secret clean-up, and it is refused while any of them is active.
- [ ] Export / import metadata. There is no separate metadata file today, so the folder path is carried in the exported text config (see "Resolved"):
  - Export of a text config (OpenVPN, WireGuard, strongSwan, SSTP) prepends one comment line `# macvpn-meta: {"folder":["Work","Clients"]}` (JSON, keys optional) when the connection is in a folder. All four config formats accept `#` comments (checked in their validators). Native `.mobileconfig` exports carry nothing (the importer refuses them anyway).
  - `importer`: a first line starting with `# macvpn-meta: ` is parsed (strict JSON, at most 4 KiB, unknown keys ignored), removed from the stored config, and returned as `ExportMeta { folder: Option<Vec<String>>, credential_name: Option<String> }`. An invalid line is left in the config as an ordinary comment.
  - Import recreates the missing folders of the path (by name, under the same parents) and places the connection; no line → the root.
- [ ] Tests:
  - the tree order end to end with seeded folders, pins and usage
  - retention: missing → `missing_since` set; back within 30 days → kept and cleared; after 30 days → removed
  - each command's validation; moving a folder into its descendant → error
  - `deleteContents` refused with an active connection
  - export adds the line only with a folder; import strips it, recreates `Work/Clients`, and an older export without the line lands at the root
  - a malformed meta line stays as a comment
  - the line never contains a secret (the JSON has only the two keys)
- [ ] Commit: `feat(app-core): folders and colours`.

## Task 17: folders and colours in the UI

**Files:** `app/ui/src/app.css` (12 colour tokens for light and dark: `--folder-red` … `--folder-pink`), `app/ui/src/lib/Icon.svelte` (folder icons), create `app/ui/src/lib/folders/FolderRow.svelte`, `ColorPicker.svelte`, `tree.ts` (+ test), `dnd.ts` (+ test); modify `app/ui/src/lib/Menu.svelte`, `MenuRow.svelte`, `app/ui/src/lib/manage/Sidebar.svelte` (becomes the tree), `app/ui/src/lib/manage/Modal.svelte` use; `crates/core/l10n/strings.json`.

- [ ] Menu:
  - Folder rows are collapsible, with a coloured folder icon and the active count.
  - A collapsed folder that contains a connected item shows a green dot plus the count.
  - Indentation is capped visually at 3 levels.
  - The collapsed state is saved through `folder_set_collapsed`.
- [ ] Connections window tree:
  - Drag and drop to move items and folders, and to reorder folders. `dnd.ts` computes the drop target and refuses a drop into a descendant before calling the backend.
  - Context menu: New folder, Rename (inline), Colour (the picker with 12 swatches and "None"; on an item also "Use folder colour", shown only when it has its own colour), Delete.
  - Delete folder asks "Move its contents to the parent folder" (default) or "Delete the connections too". The second option needs an extra confirmation that names how many connections will be deleted.
  - An item with its own colour shows a small override marker.
- [ ] Colours must keep text contrast ≥ 4.5:1 on the card background in both modes. Check each token in a test against the light and dark card backgrounds from `app.css`.
- [ ] Tests:
  - `tree.ts`: indentation cap, the counts, the green dot rule
  - `dnd.ts`: drop targets, descendant refusal
  - the contrast test
  - view tests: the colour picker; the delete dialog's two-step confirmation
  - the l10n coverage test
- [ ] Commit: `ui: folders, colours and drag and drop`.

## Task 18: shared credentials – core and app-core

**Files:** create `crates/core/src/vault/repo_credentials.rs`; modify `crates/app-core/src/vault_stores.rs` (`VaultSecrets` resolves links), `crates/app-core/src/deps.rs` (`SecretReader::credential_for`), `crates/app-core/src/manager.rs` (the prompt naming the credential), `crates/core/src/credentials.rs` (`CredentialPrompt` gains the credential fields); tests in `crates/core/tests/vault_credentials.rs` and `crates/app-core/tests/shared_credentials.rs`.

- [ ] Repository:
  ```rust
  pub struct SharedCredential { pub id: Uuid, pub name: String, pub username: String, pub has_password: bool, pub created: Date, pub updated: Date }
  pub struct CredentialInUse { pub items: Vec<String> }
  pub fn credentials(&self) -> Result<Vec<SharedCredential>, VaultError>;
  pub fn credential_usage(&self) -> Result<HashMap<Uuid, usize>, VaultError>;
  pub fn create_credential(&mut self, name: &str, username: &str, password: Option<&str>) -> Result<Uuid, VaultError>; // name unique → Constraint
  pub fn update_credential(&mut self, id: Uuid, name: Option<&str>, username: Option<&str>, password: Option<Option<&str>>) -> Result<(), VaultError>;
  pub fn credential_password(&self, id: Uuid) -> Result<Option<Zeroizing<String>>, VaultError>;
  pub fn delete_credential(&mut self, id: Uuid) -> Result<(), Result<CredentialInUse, VaultError>>; // RESTRICT when linked
  pub fn link(&mut self, item: &str, credential: Uuid) -> Result<(), VaultError>;     // deletes the item's own username/password in the same transaction
  pub fn unlink(&mut self, item: &str) -> Result<(), VaultError>;
  pub fn credential_of(&self, item: &str) -> Result<Option<Uuid>, VaultError>;
  pub fn copy_into_connections(&mut self, credential: Uuid) -> Result<(), VaultError>; // writes username/password into each linked item, unlinks all, deletes the credential
  ```
- [ ] Resolution at connect time, transparent to the manager:
  - `VaultSecrets::get(item, Username|Password)` returns the linked credential's values when the item is linked; PSK, key password and OTP stay per connection.
  - Two separate writes (review M4). `SecretWriter::save_prompted` (`Vault::save_prompted_secret`) is only for "Save" in the credential prompt and the sign-in failure re-prompt: on a linked item it writes the credential's username or password (spec 3a). `SecretWriter::set` (`Vault::set_item_secret`), used by the editors and the import, refuses a non-empty username or password of a linked item with `VaultError::LinkedToCredential`; nothing changes and the refusal is logged without the value. An empty value there is a no-op, and the PSK and the key password are always the item's own.
  - A linked native connection: the credential's username is passed as `AuthName`/`XAuthName` (already done by `start_options` from `secrets.username`).
- [ ] `pub struct CredentialRef { pub name: String, pub used_by: usize }` in `crates/core/src/credentials.rs` (next to `CredentialPrompt`), and `SecretReader::credential_for(&self, item: &str) -> Option<CredentialRef>` (default `None`). When the linked credential has no password, `CredentialPrompt` carries `credential: Option<CredentialRef>`, and the window says "Password for Office AD — used by 4 connections". `CredentialPromptView` (plan A, `credential_prompt.rs`) gains `credential_name: Option<String>` and `used_by: Option<usize>`, and `CredentialPrompt.svelte` shows that line instead of the connection's own fields heading. A sign-in failure re-prompts once as in 1.1, and a saved new password updates the credential.
- [ ] "Create from connection…" helper, pure over the vault: `fn matching_items(vault, item) -> Vec<String>` returns the other items whose own username **and** password equal this one's. The comparison runs on `Zeroizing` values in memory and returns only ids. Then `create_credential` + `link` for the chosen ones in one transaction.
- [ ] Tests:
  - link → the manager's `secrets()` returns the credential's username/password and the item's own PSK
  - unlink → its own values again (empty, since link deleted them)
  - delete while linked → `CredentialInUse` listing the items
  - `copy_into_connections` → every item has its own copy, no links, the credential is gone
  - a linked credential with no password → required fields include `Password` and the prompt carries the name and the use count; "Save" → the credential's password is set, and a second linked connection connects without a prompt
  - a sign-in failure re-prompt saves into the credential
  - `matching_items` finds exact matches only (same user, different password → not matched)
  - names are unique
  - the API never sees a credential (control `list` output unchanged)
- [ ] Commit: `feat: shared credentials`.

## Task 19: shared credentials – UI, editors, export and import

**Files:** create `app/src-tauri/src/shared_credentials.rs` (commands); modify `app/src-tauri/build.rs`, `capabilities/main.json`; create `app/ui/src/lib/manage/Credentials.svelte`, `CredentialSelector.svelte`; modify the editors that have username/password fields (`TextEditor.svelte` hosts for OpenVPN `auth-user-pass` and IKEv2 EAP, `NativeForm.svelte` for L2TP/Cisco, `SstpForm.svelte`, `SystemDetail.svelte`), `crates/app-core/src/editor.rs` (`EditorFields.credential: Option<String>`), `crates/app-core/src/import_export.rs`, `crates/core/src/importer.rs` / `exporter.rs` (the `credentialName` key of the meta line from Task 16), `crates/core/l10n/strings.json` (HU section title „Hitelesítő adatok”).

- [ ] Credentials section in the Connections window:
  - The list shows each credential's name, username and "used by N".
  - Actions: Add, Edit, Rename, Delete.
  - The password field follows the existing `SecretField.svelte` pattern ("Saved — type to replace"); the password never reaches the webview.
  - Delete of a used credential asks "Copy into each connection" or Cancel, listing the connections' names.
- [ ] Editor selector for the editors with username/password: "Own username and password" (default) or "Use credential: <name>". Choosing a credential hides the own fields and, after a confirmation, deletes the connection's own stored username and password (through `link`). The SSTP selector covers the password only (its user name is in the config; see plan A).
- [ ] A linked editor sends `None` for the username and password fields. The save handlers (`save_text`, `save_sstp`, `save_native`, `save_system_secrets`) refuse a typed value with "This connection uses the shared credential %@. Change its user name and password in the Credentials section." before anything is saved, and `SecretWriter::set` refuses it as well. `save_native` keeps a linked connection's account name in the profile only. The credential prompt's "Save" and re-prompt call `SecretWriter::save_prompted`, never `set`.
- [ ] "Create from connection…": pick a connection, type a name; then a list of the other connections with the same username and password (names only), all ticked, and "Link".
- [ ] Export / import: the meta line carries `credentialName` when the connection is linked. On import, nothing is linked automatically (review M3). `SharedCredentials::link_imported(credential_name, kind, config)` only reads the vault:
  - A credential with that exact name gives `ImportLink::Ask { credential, name, remote }`, where `remote` is `importer::remote_host(kind, config)`. The import question asks "Use the shared credential '<name>' for this connection to <remote>?". The default answer is "Use the connection's own fields". Only a yes calls `link`.
  - An unknown name gives `ImportLink::Unknown { name }`: the existing import question (`ManageView.question`) offers the credentials to pick from, or "Use the connection's own fields".
  - There is no automatic link, not even when another connection linked to the same credential has the same remote host. A config can list several servers and fall back to another one, so the same-host check is too easy to get wrong.
  - `take_export_meta` puts every folder path component through the folder-name rule and the credential name through the credential-name rule (`mfa::clean_name`). An invalid name makes the whole line an ordinary comment.
- [ ] Commands, validated like the existing ones (UUIDs, name 1–64 chars sanitized, username ≤ 256 bytes without control characters, password through the secret rules):
  - `credential_create`, `credential_update`, `credential_delete(id, copyInto: bool)`
  - `credential_link(item, credential?)`
  - `credential_from_connection(item, name, link: Vec<String>)`
- [ ] Tests:
  - command validation and the capability test
  - editor view model: `credential` set → the username/password fields are not in `EditorFields` output
  - import with a matching name → the question with the remote host (default: own fields), nothing linked until the user says yes; with an unknown name → the question to pick a credential
  - a linked editor: a typed username or password is refused, and the shared credential is unchanged
  - a view test: Delete of a used credential shows the copy-into question with the names
  - the l10n coverage test
- [ ] Commit: `ui: shared credentials`.

## Task 20: core – the backup format and the restore planner

**Files:** create `crates/core/src/vault/backup.rs`; tests in `crates/core/tests/vault_backup.rs`.

- [ ] Container, version 1 (all integers big-endian), a 64-byte header followed by the ciphertext:
  ```
  magic        8  b"MVPNBKUP"
  format       2  1
  kdf          1  1 = Argon2id
  reserved     1  0
  m_kib        4
  t            4
  p            4
  salt        16
  nonce       24
  ciphertext   …  XChaCha20-Poly1305(key = Argon2id(backup password, salt, params), nonce, payload, AAD = the 64 header bytes)
  ```
- [ ] The payload is JSON, decided here instead of a SQLite image: no plain database file can ever touch the disk, and it is easy to version. It is serialized into a `Zeroizing<Vec<u8>>`:
  ```rust
  pub struct BackupPayload {
      pub version: u32,                       // payload schema, 1
      pub created: Date, pub app_version: String,
      pub connections: Vec<BackupConnection>, // meta JSON, config, folder_id, color, position, secrets {field: value}
      pub folders: Vec<FolderNode>,
      pub credentials: Vec<BackupCredential>, // with password
      pub credential_links: Vec<(String, Uuid)>,
      pub system_items: Vec<SystemItem>,
      pub system_otp: HashMap<String, OTPSetting>,
      pub ranking: ConnectionRanking,         // usage + pins
      pub preferences: BackupPreferences,     // auto_check, delay_24h, launch_at_login, control_api_enabled, auto_unlock
  }
  ```
  Paired control clients, the DEK, the recovery key and the logs are **not** in it.
- [ ] Functions:
  - `pub fn collect(vault: &Vault, prefs: BackupPreferences, now: Date, app_version: &str) -> Result<BackupPayload, VaultError>`
  - `pub fn seal(payload: &BackupPayload, password: &str, kdf: KdfParams, e: &dyn Entropy) -> Result<Vec<u8>, BackupError>`
  - `pub fn open(bytes: &[u8], password: &str) -> Result<BackupPayload, BackupError>` with `pub enum BackupError { CannotOpen, NewerVersion(u16), TooLarge, Io(String) }`:
    - A wrong password, a tampered header, a tampered payload, a truncated file and an unknown `kdf` id all give `CannotOpen`. One generic error, so the caller cannot tell which part was wrong.
    - A `format` above 1, or a payload `version` above 1, gives `NewerVersion`.
    - A file over `MAX_BACKUP_BYTES` (the 64-byte header, `MAX_PLAINTEXT_BYTES` = 64 MiB and the tag) gives `TooLarge`.
    - KDF parameters above the backup ceiling `MAX_KDF` (m ≤ 256 MiB, t ≤ 64, p ≤ 4) give `CannotOpen` before the KDF runs (review LM1). `seal` refuses parameters above it.
    - The opened payload goes through `validate` (review M1, LM2). A refused payload is `BackupError::Invalid(InvalidBackup)`, which names the kind of problem and never a value. `validate` checks:
      - credential names (`validate_credential_name`, in their stored form), usernames (`check_username`) and passwords (`check_password`)
      - folder names (`validate_folder_name`) and that the folders form a tree
      - every item id (`check_item`)
      - the control-character rule of `Secrets::input_error`, and at most 64 KiB, for every secret
      - no duplicate ids or credential names
      - at most `MAX_ITEMS` (10 000) connections, folders, credentials, links, pins, usage entries, system items, system secrets and OTP settings
    - `seal` runs the same `validate`, so a backup that could not be restored is refused when it is made. With `test-support`, `seal_unchecked` builds the crafted files for the tests.
    - An older payload version is migrated (the hook exists, with no older versions yet).
  - `pub fn read_backup_file(path: &Path) -> Result<Vec<u8>, BackupError>` (review LM2): `O_NOFOLLOW | O_NONBLOCK`, a regular file only, read through `take(MAX_BACKUP_BYTES + 1)`. Task 21 reads backups only through this, never with `fs::read`.
  - `pub fn write_backup(path: &Path, bytes: &[u8]) -> Result<(), BackupError>`: atomic (temp file in the same directory, `O_EXCL|O_NOFOLLOW`, 0600, fsync, rename); on any error the partial file is removed. `exporter::write` already does the temp file, `O_EXCL|O_NOFOLLOW`, 0600, rename and clean-up; add the missing `fsync` (file and directory) there and reuse it.
- [ ] Restore planner, pure:
  ```rust
  pub enum ConflictMode { Overwrite, KeepExisting, KeepBoth }
  pub struct RestorePlan { pub added: usize, pub conflicts: usize, pub lost_on_replace: usize, pub acknowledged_risky: Vec<String> }
  pub fn plan_restore(vault: &Vault, payload: &BackupPayload) -> Result<RestorePlan, VaultError>;
  pub fn merge(vault: &mut Vault, payload: &BackupPayload, mode: ConflictMode) -> Result<(), VaultError>;   // one transaction
  pub fn replace(vault: &mut Vault, payload: &BackupPayload) -> Result<(), VaultError>;                     // one transaction
  ```
  - A conflict is a connection, folder or credential id that already exists, or a credential **name** that exists under another id. One mode applies to all conflicts.
  - `KeepBoth` gives the backup copy a new id and the suffix " (backup)" (then " (backup 2)", … while the name is still taken), and re-points that copy's links, secrets and placements.
  - `replace` clears every table except `control_clients` and `meta` (the paired clients belong to this Mac).
  - System items whose service is unknown on this Mac get `missing_since = now` (the 30-day retention).
  - `merge` and `replace` `validate` the payload again before writing anything, and refuse it with `VaultError::InvalidBackup`. "Keep both" credential names are shortened to fit 64 characters with the suffix. The suffixes are handed out per base name from sets, not by probing from 1 each time. Pins are de-duplicated with a set.
  - The link invariant (review M2): every restored link goes through `Tx::link`, and at the end no linked item has its own username or password. With Overwrite, a system VPN's secrets and its link are replaced together. Without Overwrite, a link is not added to an item that has its own username or password.
  - Acknowledged risky directives (review LM3): a merge drops them from every restored connection, unless the same connection already exists with the same config. `replace` keeps them, and `RestorePlan::acknowledged_risky` names those connections.
  - A folder cycle after a merge is `VaultError::Tree(TreeError::Cycle)`. A backup whose own folders are not a tree is `InvalidBackup::FolderTree`. Neither is reported as "Corrupt".
- [ ] Tests:
  - round-trip seal/open of a full payload
  - wrong password, a flipped header byte, a flipped payload byte and a truncated file → all exactly `CannotOpen`
  - format 2 → `NewerVersion`
  - merge with each mode, checked on connections, folders, credentials (by id and by name), secrets and links
  - every case of the security review's PoC, and each other validation rule, is refused on seal, open, merge (every mode) and replace, and the vault is unchanged
  - "Keep both" of a 64-character credential name stays valid
  - a restored link leaves no own username or password, also for an Overwrite merge onto an already linked system VPN
  - acknowledged risky directives after merge and replace
  - a header above the KDF ceiling cannot be opened, and the KDF never runs
  - `read_backup_file` refuses a symlink, a directory, a FIFO (without blocking) and an oversized file
  - replace keeps the paired clients and reports the lost count
  - no plaintext temp file: run `collect` + `seal` + `write_backup` with `TMPDIR` pointed at a scratch dir, scan every file created in the scratch dir and the target dir for a canary connection name and config line, and find none outside the sealed file (which itself must not contain them)
  - the written file is 0600; a write into a read-only directory leaves no partial file
- [ ] Commit: `feat(core): encrypted full backup format`.

## Task 21: backup and restore in the app

**Files:** create `crates/app-core/src/backup.rs` (orchestration), `app/src-tauri/src/backup.rs` (windows `vault-backup` / `vault-restore`, the native save/open panels through `dialogs.rs`), `app/ui/src/lib/vault/Backup.svelte`, `Restore.svelte`; modify `crates/app-core/src/vault_setup.rs` ("Restore from backup…" at `Intro`, the "Back up everything…" button at the migration's reminder step), the menu settings and the Connections window ("Back up everything…", "Restore from backup…"), `app/src-tauri/build.rs`, `capabilities/vault.json`, `crates/core/l10n/strings.json`.

- [ ] `backup::open` and `backup::seal` run Argon2id with up to `MAX_KDF` (seconds). Call them off the main thread, and never block the UI on them. Read the file with `backup::read_backup_file`, never with `fs::read`.
- [ ] Backup:
  - The default file name is `MacVPN-backup-<YYYY-MM-DD>.macvpnbackup`, chosen in the native save panel.
  - The backup password is entered twice, with the strength hint and a minimum of 10 characters. "Use my master password" appears only after an explicit confirmation step, and then the master password is checked against the vault (no second copy is kept).
  - The window shows "Anyone with this file and its password can read all your VPN credentials".
  - The password is never stored.
- [ ] Restore on a fresh install, from `vault-create` → "Restore from backup…":
  1. Pick the file, enter the backup password.
  2. Set a new master password and save and confirm a new recovery key (the normal create steps).
  3. `replace` into the empty vault, in one transaction.
- [ ] Restore into an existing vault, from the settings: the file and the password, then the plan's numbers and the choice:
  - **Merge**, with the single conflict question (Overwrite / Keep existing / Keep both).
  - **Replace everything**, with a confirmation naming `lost_on_replace` and a "Back up the current state first" button.
- [ ] Before a merge or replace, the restore window lists `RestorePlan::acknowledged_risky`: a replace (and a fresh restore) keeps those connections' acknowledged risky directives, while a merge drops them unless the connection already exists with the same config.
- [ ] After a restore:
  - Preferences are never applied silently. The window lists each backed-up preference (auto-update, the 24 h delay, launch at login through the login item service, the control API switch, auto-unlock), and the user confirms each one. The control API is unticked by default, whatever the backup says.
  - `manager.reload()`
  - the native profiles listed with "Reinstall N native profiles", which installs them one after another through the existing `ProfileInstaller` (macOS asks for approval per profile; see "Resolved")
  - a missing tool or root layer shows in System Status as usual
- [ ] The migration's reminder step gets its "Back up everything…" button here (Task 14 shipped the step without it).
- [ ] Tests:
  - orchestration over fakes: the preferences restored; a merge with each mode; replace; a wrong password → the generic message; a newer file → "This backup was made by a newer MacVPN. Update MacVPN to restore it."
  - the command validation and the capability test
  - view tests: the warning text; the "Use my master password" confirmation step
  - the l10n coverage test
- [ ] Commit: `feat(app): full backup and restore`.

## Task 22: l10n sweep and documentation

**Files:** `crates/core/l10n/strings.json`, `scripts/check-l10n.sh`, `docs/user-guide.en.md`, `docs/user-guide.hu.md`, `docs/how-to.en.md`, `docs/how-to.hu.md`, `README.md`, `docs/control-api.md` / `.hu.md` (the `locked` code, if not done in Task 11).

- [ ] Run the l10n coverage tests and `scripts/check-l10n.sh`; a native HU review pass over every string added in this plan (consistent terms: vault = „széf”, master password = „mesterjelszó”, recovery key = „helyreállítási kulcs”, folder = „mappa”, credentials = „hitelesítő adatok”). Settle the terms once in the first task that adds them, and keep them.
- [ ] User guide (EN/HU):
  - the vault: what it protects, auto-unlock, Lock now, the recovery key and what happens without it
  - the migration (the Keychain prompts, once)
  - folders and colours
  - shared credentials
  - backup and restore
  - the security notes (spec 6)
- [ ] How-to (EN/HU): "Move MacVPN to a new Mac", "Reset a forgotten master password with the recovery key", "Share one password across connections".
- [ ] Commit: `docs: vault, folders, shared credentials and backup`.

## Task 23: smoke tests

**Files:** `app/src-tauri/src/smoke.rs`, `scripts/smoke-manage.sh`, new `scripts/smoke/vault-create.js`, `vault-unlock.js`, `folders.js`, `backup.js`; the existing scripts adapted to the vault.

- [ ] The sandbox uses `MemoryKeyStore`, a vault in the sandbox home, and the in-memory legacy Keychain. `smoke-manage.sh` keeps seeding the 1.1 file layout, which now becomes **migration input**: the run checks that the seeded connections, a seeded secret and a seeded `connection-order.json` arrive in the vault and that the seeded files are gone afterwards.
- [ ] Flows, each run with `SMOKE_LANG=en` and `SMOKE_LANG=hu`:
  - **create**: `vault-create.js` waits for the input lock, types the master password twice, reads the recovery key from the window, confirms the asked group, waits for "Done" (the migration ran)
  - **lock / unlock**: the driver locks; the menu shows no seeded name; `vault-unlock.js` types a wrong password (the countdown appears), then the right one
  - **recovery**: lock again; "Use recovery key", the saved key + a new password; then lock and unlock with the new password
  - **folders**: `folders.js` creates `Smoke A`, nests `Smoke B` in it, sets a colour, moves a connection into `Smoke B` (through the same calls the drop handler makes), checks the inherited colour on the row, deletes `Smoke A` with "move up", and checks that `Smoke B` and the connection are at the root
  - **credential prompt**: the 1.1 flow (`credentials.js`), now checking that "Save" wrote into the vault
  - **shared credential**: create `Smoke Cred` without a password, link two seeded OpenVPN connections, connect one → the prompt names the credential and "used by 2"; Save → the second connects without a prompt
  - **live list**: the 1.1 fake system-service change
  - **backup**: back up into the sandbox `tmp`, change a name, restore with Merge / Overwrite, check the name is back; check the backup file is 0600 and contains no seeded name in clear
- [ ] Every flow reports through `MacVPN smoke: …` lines checked by `smoke-manage.sh`. The release gate still holds.
- [ ] Commit: `test(smoke): vault, folders, shared credentials and backup`.

## Task 24: manual checklist

**Files:** `docs/manual-test-checklist.md` (Hungarian, like the rest of the file).

- [ ] A 1.2.0 section:
  - **Real migration on the maintainer's data:** first a full copy of `~/Library/Application Support/MacVPN` and an export of the `local.macvpn.secrets` items. Then install 1.2.0, create the vault, count the Keychain prompts (one per old item at most, and "Always Allow"), and check that every connection connects, the order and pins are unchanged, the system-VPN OTP settings are kept, and the paired Remote Desktop app still works. Check that the old files and items are gone and the marker exists.
  - **After the next update** (install a 1.2.1 test build over it): at most one Keychain prompt for the vault item.
  - Auto-unlock off → the unlock window at launch; wrong password delays; Lock now with a VPN up (it stays up, the menu shows no names, the Remote Desktop app gets `locked`).
  - Recovery key reset; change the password; a new recovery key invalidates the old one.
  - Folders: nesting 5 deep, colours in light and dark mode, drag and drop, delete with both options.
  - Shared credential across an OpenVPN and an L2TP connection; delete with "Copy into each connection".
  - Backup on this Mac, restore on a second Mac or a fresh user account (native profiles reinstall, preferences restored), Merge with each mode, Replace.
  - Delete a system VPN in System Settings while the menu is open (it disappears; its folder placement returns if it comes back with the same ID within 30 days).
  - Root layer 8: "Update required (7 → 8)" after the update, one admin prompt, then every kind connects; `ls ~/Library/Application\ Support/MacVPN` shows only `vault.db`, `vault.keys` and the marker (plus logs, if any).
  - `strings` / `grep` on `vault.db`: no connection name in clear.
- [ ] Commit: `docs: 1.2.0 manual checklist`.

## Task 25: independent security review

- [ ] A reviewer who did not write the code reviews against spec sections 2, 3a, 3b and 6 and the rules above, at least:
  - the key hierarchy: KDF parameters, nonce uniqueness, the AADs, zeroization, no key in `Debug`, logs, argv, env or the view model
  - the Keychain item attributes (Task 1 B decision) and what happens after an ad-hoc re-sign
  - lock: the DEK is wiped, the manager's redaction, the control API `locked` behaviour
  - SQLCipher pragmas and modes (or the sealing in fallback mode); the plaintext scan
  - the migration's deletion only after verification; shredding; failure paths
  - root layer 8: the stdin framing parser (fuzz it: `cargo fuzz` or a proptest over random inputs, with no panic and no over-read), that `mvpn` opens no user file any more, and the `test-root.sh` new cases
  - backup: the generic error, the header as AAD, the atomic write, no plaintext temp file, password handling, restore merge correctness
  - shared credentials: the password never in the webview, the restricted delete
  - every new IPC command and capability file (label checks, input validation)
- [ ] Fix until approved; each fix with a test.
- [ ] Commit(s): `fix: security review findings` (as many as needed).

## Task 26: release 1.2.0

- [ ] Version 1.2.0 in `tauri.conf.json`, `Cargo.toml` `[workspace.package]`, `app/ui/package.json` and the lock files. Root `VERSION` 8 (done in Task 2).
- [ ] `scripts/build-dmg.sh`:
  - The release gate also fails if the `mvpn` binary contains `sqlcipher` or `SQLite format` (the vault code must not reach the root layer). `grep -a` both slices.
  - The SQLCipher provider gate (spike report A.5):
    - At the top of the script, `unset OPENSSL_DIR OPENSSL_LIB_DIR OPENSSL_INCLUDE_DIR` and their `AARCH64_APPLE_DARWIN_` / `X86_64_APPLE_DARWIN_` prefixed forms.
    - After the app build, check the app binary:
      - `otool -L` lists no `libcrypto`, `libssl` or `openssl`
      - `grep -a -c commoncrypto` is ≥ 1
      - `grep -a -i openssl` finds nothing
  - Update the comment that lists `Contents/Resources/root` (`VERSION` 8).
  - Add SQLCipher's licence notice (BSD-style) to the bundled licences, wherever the third-party notices live today (check `README.md`; create `THIRD-PARTY-NOTICES.md` if there is none).
- [ ] Run everything: fmt, clippy, `cargo test`, `scripts/test-root.sh`, `npm test` and `npm run build`, smoke EN/HU, `scripts/build-dmg.sh` with the release gate, CI green.
- [ ] The manual checklist (Task 24) on the DMG.
- [ ] Release: the same flow as 1.1.0. That flow is: the user tests the DMG, the `public` sync commit, the `main` push (main only, never the working branches), the CI, the `v1.2.0` tag, the draft check against a local build, and the signing by the user. The release notes say that the first launch creates the vault and migrates, that macOS may ask for Keychain access several times once, and that the root layer update asks for the admin password once.

---

## Resolved points (spec ambiguities and how this plan settles them)

- **Where the vault code lives.** The spec puts it in `crates/core`, but `mvpn` (root) depends on core. The vault is therefore behind a `vault` cargo feature that only `app-core` / `platform-mac` enable, and the release gate checks that the root binary has no SQLite in it.
- **Randomness in core.** The spec says `getentropy`, but core has no `unsafe`. Core uses an `Entropy` trait; `platform-mac` implements it with `getentropy`, and tests use a deterministic stream (so known-answer vectors are possible).
- **`mvpn validate --config-path`.** The current form is a positional `<file>` argument (`mvpn validate <kind> <file>`); that is what is removed. All validate modes read the framed config from stdin.
- **Length mismatch.** The secret lines after the config body are parsed strictly in the framed protocol, so a `len` that is too short is detected (the leftover config lines are not valid secret lines); too long is "incomplete".
- **The bash reference in `test-root.sh`** cannot speak the new protocol and is removed from the harness; the Swift-era files stay for the message-table test.
- **IKEv2 re-prompt.** Root layer 8 adds `Authentication failed (EAP)`, so the plan-A re-prompt now covers IKEv2 EAP too.
- **System-VPN placement retention** needs a timestamp the spec's schema does not have: `system_items.missing_since` is added.
- **"Exported metadata"** does not exist today (an export is the bare config or a `.mobileconfig`). Folder path and `credentialName` travel as one `# macvpn-meta: {json}` comment line at the top of exported text configs; `.mobileconfig` exports carry none (they cannot be imported anyway).
- **`connections.position`.** Items are ordered by pins and ranking as today (spec 3, "Ordering"), so manual reordering by drag and drop applies to folders and to the pin order, and dropping an item only changes its folder. The column is written (append order in the folder) for a stable schema, and is not used for display.
- **Lock now and running VPNs.** The manager keeps only a redacted record (id, kind, bound service ID) of the active connections so polling and quit-time disconnect still work; names, the ranking and the OTP map are dropped from memory.
- **Control API while locked.** Everything that needs the vault answers `locked`. `down` still works for an already authenticated session, so a client can always release its lease.
- **Wrong-attempt delay.** 1 s, doubling, capped at 30 s, in memory only; never a lockout.
- **"Export all" in the migration window.** This is the full backup of section 3b. The button is added in Task 21; until then the step only reminds the user where backup lives.
- **Backup payload.** JSON, sealed as a whole (no SQLite image), so no plain database file can exist even briefly.
- **Replace keeps paired clients.** They are bound to executables on this Mac and are not in the backup, so "Replace everything" keeps them.
- **Reinstalling native profiles after a restore.** The existing `ProfileInstaller` opens each profile for approval separately. The plan reinstalls them one after another from one button, instead of building a combined profile, which would break the per-connection identifiers that make a reinstall replace the old profile.
- **Recovery key entropy.** 120 bits = 15 bytes = 24 Crockford symbols, exactly six groups of four.
- **Native profile secrets** follow the Task 1 D decision rule. The password is never in a profile; the PSK stays in the profile unless starting from System Settings still works without it. Spike result: the start-option PSK works; the System Settings case awaits the manual test (spike report D.3), so the default is "PSK stays in the profile".
- **Argon2id cost (spec 2.2 says t=3).** On Apple Silicon t=3 takes 60 ms, far below the 0.5–1 s target. Per Task 1 C the default is `m=64 MiB, t=32, p=1` (0.66 s on an M5). The parameters are stored in `vault.keys`, so they can change later.
- **Keychain "data-protection class" (spec 2.3).** Without a real signing identity the item lives in the file-based login keychain, which does not keep an accessibility class. The item is still written with `WhenUnlockedThisDeviceOnly`, but the docs (Task 22) and the security review (Task 25) describe the real protection: the login keychain's lock state plus an ACL bound to the app's cdhash. "ThisDeviceOnly" is not enforced, because Time Machine backs up the login keychain, encrypted.
- **SQLCipher crypto provider.** CommonCrypto is used only when no `OPENSSL_*` variable is set (spike report A.1). Tasks 6 and 26 add the guards.
