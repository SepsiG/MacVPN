# Vault spike (1.2.0, plan B Task 1) – findings

Date: 2026-10-19. Machine: Apple M5 (arm64), 16 GB, macOS 27.0.1, Xcode SDK of that release, Rust 1.99.1.
The probes lived outside the repository (a scratch directory); only this report is committed, so Task 6 has no
spike code to delete. Spec: `docs/superpowers/specs/2026-10-19-vault-folders-design.md` section 2. Plan:
`docs/superpowers/plans/2026-10-19-vault-folders.md` Task 1.

## Summary of decisions

| Part | Decision |
|------|----------|
| A | **Go: SQLCipher.** `rusqlite =0.40.2` with `bundled-sqlcipher` builds SQLCipher 4.14.0 (SQLite 3.51.3) with the CommonCrypto provider on both macOS targets, links only Security, CoreFoundation and libSystem, and passes every check. The XChaCha20 fallback is not needed. Two build gates are required (see A.5). |
| B | Pass `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (accepted), but know that the file-based login keychain **does not store or enforce it**. The real protection is the login keychain's lock state plus the item ACL, which is bound to the app's ad-hoc cdhash. Every update that changes the binary triggers one access prompt for the single DEK item. The prompt count and the dialog itself need one manual check on the login keychain. |
| C | **Argon2id m = 64 MiB, p = 1, t = 32** (about 0.66 s on the M5). The spec's t = 3 takes only 60 ms on this Mac. |
| D | The PSK can be passed at start through `SCNetworkConnectionStart` user options. MacVPN already does this and has been field-tested since 0.1.3. Whether a profile **without** `SharedSecret` still works from System Settings cannot be settled without a real test. Until the manual test below passes, Task 12 takes the "PSK stays in the profile" branch. |

## A. SQLCipher via rusqlite, CommonCrypto on macOS

### A.1 How the provider is selected (code reading)

`libsqlite3-sys 0.38.2` `build.rs`, `bundled-sqlcipher` branch:

- The bundled C source is `sqlcipher/sqlite3.c`: SQLCipher `4.14.0 community`, SQLite `3.51.3`. Compiled with `-DSQLITE_HAS_CODEC -DSQLITE_TEMP_STORE=2 -DSQLITE_EXTRA_INIT=sqlcipher_extra_init …`.
- The provider is chosen in this order:
  1. The feature `bundled-sqlcipher-vendored-openssl` → OpenSSL from `openssl-src`, linked statically.
  2. `OPENSSL_LIB_DIR` + `OPENSSL_INCLUDE_DIR`, or `OPENSSL_DIR`, is set → the system **libcrypto dylib** at that path. The build script also checks the target-prefixed forms, such as `AARCH64_APPLE_DARWIN_OPENSSL_DIR`.
  3. Otherwise, if both host and target contain `apple` → `-DSQLCIPHER_CRYPTO_CC`, linking `framework=Security` and `framework=CoreFoundation`. **This is the path MacVPN wants.**
  4. Otherwise → `-lcrypto`.
- There is no feature that forces CommonCrypto. It is the default only when no OpenSSL variable is set.
- The build script does **not** emit `rerun-if-env-changed` for the `OPENSSL_*` variables. Setting or clearing them does not rebuild a cached `libsqlite3-sys`.
- Verified: with `OPENSSL_DIR=/opt/homebrew/opt/openssl@4` exported, the arm64 build linked `/opt/homebrew/opt/openssl@4/lib/libcrypto.4.dylib` and reported `cipher_provider=openssl`. Without it, the build used CommonCrypto.
- Consequence: build-dmg.sh and CI must make sure no `OPENSSL_*` variable leaks in, and the release gate must check the result (A.5).

### A.2 Universal build and runtime checks (tiny test binary)

The test binary's `main` opens a database with a raw key and checks the following:

- `PRAGMA cipher_provider`, `cipher_version`, `sqlite_version()`
- WAL mode, `secure_delete`, a `secrets` table with a canary string
- a reopen with the same key, a reopen with another key, and a reopen with no key
- the open sequence from Task 6: `cipher_compatibility = 4`, `foreign_keys`, `journal_mode = WAL`, `secure_delete`, `temp_store = MEMORY`, then `integrity_check` and `cipher_integrity_check`
- a scan of the `-wal` file before any checkpoint

| Check | Result |
|-------|--------|
| `cargo build --release --target aarch64-apple-darwin`, clean `target/` | OK, 14.6 s total |
| `cargo build --release --target x86_64-apple-darwin` (cross-compiled on arm64) | OK, 14.4 s total |
| `lipo -create` | `x86_64 arm64`, 4.69 MB (2.34 + 2.33 MB) |
| arm64 slice | `cipher_provider=commoncrypto`, `cipher_version=4.14.0 community`, `sqlite=3.51.3` |
| x86_64 slice under Rosetta (`arch -x86_64`) | identical output |
| `otool -L` (both slices) | only `Security.framework`, `CoreFoundation.framework` and `libSystem.B.dylib` |
| `nm` (both slices), `grep -i 'openssl\|EVP_\|libcrypto'` | 0 symbols. The undefined crypto imports are `CCCryptorCreate/Update/Final/Release`, `CCHmacInit/Update/Final`, `CCKeyDerivationPBKDF` and `SecRandomCopyBytes`. |
| Raw key `PRAGMA key = "x'<64 hex>'"` → reopen with the same key | OK, canary read back |
| Another key | `SqliteFailure` code `NotADatabase` (extended 26), "file is not a database", on the first `SELECT … FROM sqlite_master` |
| No key | "file is not a database" |
| File bytes (`grep -a`, hex search) | no `SQLite format 3` header, no canary, no `CREATE TABLE` / `secrets`. The first 16 bytes are random (the salt). A plain-SQLite control file made with the same insert contains both the header and the canary, so the scan does detect them. |
| `-wal` before checkpoint (8 KiB) | no canary; `-shm` has none either |
| Task 6 open sequence | all pragmas accepted, `integrity_check = ok`, `cipher_integrity_check` returned 0 rows |
| Ad-hoc signature with the hardened runtime (`codesign --force --sign - --options runtime`, as in build-dmg.sh) | `codesign --verify --strict` OK; both slices run |

### A.3 Build-time and size cost

- **Build time:**
  - `cargo build --timings`: the `libsqlite3-sys` build script, which compiles `sqlite3.c`, takes **10.2 s per target** on the M5. Plain `bundled` SQLite takes about the same (a clean total of 12.0 s, against 14.6 s for SQLCipher).
  - The build script runs in parallel with the other crates. In the app build (two targets) it adds at most about 20 s of wall time to a clean build, and nothing to an incremental one.
- **Binary size:**
  - About **+1.9 MB per slice** (+3.8 MB universal) against a binary without SQLite. That is about 11 % of today's 34.5 MB universal `MacVPN` binary.
  - SQLCipher costs about +40 KB per slice over plain bundled SQLite.
- **Verdict:** acceptable.

### A.4 build-dmg.sh and the CI `dmg` job (feasibility, by reading)

- **build-dmg.sh:**
  - It runs `tauri build --target universal-apple-darwin`, which runs cargo once per target and then `lipo`. That is the same thing as the manual two-target build plus `lipo` above.
  - On each target run, `HOST` (aarch64-apple-darwin) and `TARGET` both contain `apple`, so CommonCrypto is selected for both slices.
  - The x86_64 slice is cross-compiled through `cc` with `clang -arch x86_64` against the Xcode SDK. This worked locally without extra flags.
  - The ad-hoc signature with the hardened runtime and no entitlements needs no change: CommonCrypto and Security are system frameworks, so library validation is satisfied.
- **CI (`.github/workflows/ci.yml`, `release.yml`):**
  - Every job runs on `macos-15` with Xcode, and nothing needs installing (no perl/make, no OpenSSL).
  - The jobs do not set any `OPENSSL_*` variable. I could not confirm whether the runner image exports one, so the gate in A.5 is mandatory.
  - The `rust` job (`clippy --workspace --all-targets`, `cargo test --workspace`) compiles SQLCipher once for the host. This adds about 10 s.
- **Not run:**
  - the real `scripts/build-dmg.sh` with the vault crate linked in
  - the GitHub `dmg` job

  Per the brief, the real app was not changed. Task 6 is the first commit that links `rusqlite`. Its CI run (`rust` job plus `dmg` job) is the confirmation, and the gate in A.5 makes a wrong provider fail loudly.
- **Task 6, local result (2026-10-19):** with the vault crates linked (core `vault` feature through app-core and platform-mac), the real `scripts/build-dmg.sh` passed with the A.5 gates. The arm64 slice of `MacVPN` contains SQLCipher with `commoncrypto`; the x86_64 slice has the unused SQLCipher code dead-stripped until the app opens the vault (Task 14), so the gate requires CommonCrypto only where SQLCipher is linked until Task 26 makes it mandatory. Neither slice links or contains OpenSSL; `mvpn` contains no `sqlcipher` / `SQLite format`. The gate matches the lower-case `"openssl"` (SQLCipher's provider name) case-sensitively, because the app's own texts mention "Homebrew's OpenSSL". A universal release build of the `vault_db` test binary passed all its tests on arm64 and on x86_64 under Rosetta (`cipher_provider = commoncrypto`); the same binary built with `OPENSSL_DIR=/opt/homebrew/opt/openssl@4` linked `libcrypto.4.dylib`, contained `"openssl"` and failed `sqlcipher_uses_commoncrypto`, so both the gate and the test catch a wrong provider. The CI `rust` and `dmg` jobs are still to be confirmed on the first push.

### A.5 Required build gates (go/no-go conditions for later tasks)

1. **The provider gate**, in `scripts/build-dmg.sh` after the app is built, on the universal `Contents/MacOS/MacVPN`:
   - `otool -L` must not list any `libcrypto` or `libssl`. Test with `grep -Ei 'libcrypto|libssl|openssl'` and die if anything matches.
   - `LC_ALL=C grep -a -c commoncrypto` must be ≥ 1. The string is present only when SQLCipher is compiled with `SQLCIPHER_CRYPTO_CC`: the test binary had 2 matches, and the OpenSSL build had 0.
   - `LC_ALL=C grep -a -i -q openssl` must find nothing. The CommonCrypto test binary had 0 matches, and the OpenSSL build had 4.
2. **Unset leaking variables.** At the top of build-dmg.sh, `unset OPENSSL_DIR OPENSSL_LIB_DIR OPENSSL_INCLUDE_DIR` and their `AARCH64_APPLE_DARWIN_` / `X86_64_APPLE_DARWIN_` prefixed forms. This matters because the variables are not tracked for rebuilds (A.1). Homebrew's `openssl@4` is installed on the maintainer's Mac, so this is a real risk there.
3. **The root-layer gate** (already planned for Task 26): `mvpn` contains no `sqlcipher` and no `SQLite format`. Verified as a usable marker: the SQLCipher test binary contains `SQLite format 3` (3 hits), and a hello-world binary contains none.
4. Optionally, a test in core (`#[cfg(target_os = "macos")]`) that asserts `PRAGMA cipher_provider = 'commoncrypto'`. It catches a wrong provider in `cargo test` already, not only in the DMG build. Recommended for Task 6.

### A.6 Linux / Windows (information only, not a gate)

- The target-specific feature split works under resolver 3:
  ```toml
  [target.'cfg(target_os = "macos")'.dependencies]
  rusqlite = { version = "=0.40.2", features = ["bundled-sqlcipher"] }
  [target.'cfg(not(target_os = "macos"))'.dependencies]
  rusqlite = { version = "=0.40.2", features = ["bundled-sqlcipher-vendored-openssl"] }
  ```
  - `cargo tree --target aarch64-apple-darwin` shows **no** `openssl-sys`. The features are not unified across targets.
  - `--target x86_64-unknown-linux-gnu` pulls `openssl-sys 0.9.117` (MIT) and `openssl-src 300.6.1+3.6.3` (OpenSSL 3.6.3, Apache-2.0). That build needs `perl` and `make` on the builder.
- Not compiled here: no Linux target or runner was available, and the brief excluded CI pushes. The one-off `cargo check` on `ubuntu-latest` from the plan is still open. It is not a release gate.
- **Recommendation:** do not add the `cfg(not(macos))` line before a Linux/Windows port exists. Even unused, it puts `openssl-sys` / `openssl-src` into `Cargo.lock`. Add it together with the libsecret / DPAPI `KeyStore`.

### A.7 Crates and versions (Part A)

New in the dependency tree on macOS (`cargo metadata --filter-platform aarch64-apple-darwin`):

| Crate | Version | Licence | Note |
|-------|---------|---------|------|
| rusqlite | 0.40.2 | MIT | |
| libsqlite3-sys | 0.38.2 | MIT | bundles SQLCipher 4.14.0 (BSD-3-Clause, Zetetic LLC) + SQLite 3.51.3 (public domain) |
| hashlink | 0.12.2 | MIT OR Apache-2.0 | |
| fallible-iterator | 0.3.0 | MIT/Apache-2.0 | |
| fallible-streaming-iterator | 0.1.9 | MIT/Apache-2.0 | |
| hashbrown | 0.17.1 | MIT OR Apache-2.0 | already in the workspace lock |
| foldhash | 0.2.0 | Zlib | already in the workspace lock |
| bitflags, smallvec | 2.13.2, 1.16.3 | MIT OR Apache-2.0 | already in the workspace lock |
| cc, pkg-config, vcpkg, find-msvc-tools, shlex (build) | 1.9.0 (≥ 1.2.27 needed; the lock's 1.8.0 works), 0.3.34, 0.2.15, 0.1.15, 2.0.1 | MIT OR Apache-2.0 | build-time only |

- `cargo tree` shows nothing unexpected.
- `sqlite-wasm-rs 0.5.5` appears in `Cargo.lock` only: it is a wasm32-only dependency of `libsqlite3-sys`, and it is never compiled or linked for macOS.
- **Licence obligation:** SQLCipher's BSD-3-Clause requires its copyright notice in the distributed app. This is already listed in Task 26.

### A.8 Fallback prototype (measured anyway; not needed)

Plain `rusqlite` `bundled` plus XChaCha20-Poly1305 (`chacha20poly1305 0.11.0`) per column, release build on the M5:

- **AEAD seal:**
  - 0.43 µs for 32 B
  - 1.17 µs for 1 KiB (0.87 GB/s)
  - 59 µs for 64 KiB
  - 0.96 ms for 1 MiB (≈ 1.1 GB/s)
- **Workload:** 300 connections, each with a 4 KiB config and meta, and 1200 secrets, written in one transaction and then read back with every row opened:

| | write | read all |
|---|---|---|
| plain | 3.5 ms | 0.11 ms |
| sealed | 5.4 ms | 1.41 ms |

- The file grows by 3 % (nonce + tag per value).
- **Verdict:** the fallback is cheap to run but costs more code: `credentials.name UNIQUE` has to be enforced in code, and ids, row counts and the schema stay visible. SQLCipher is preferred.

## B. The Keychain DEK item

### B.1 Method (no real keychain item touched)

- **The probe:** a small Swift binary using `SecItemAdd` / `SecItemCopyMatching` / `SecItemDelete`, the same API as `crates/platform-mac/src/keychain_ffi.rs`.
- **Signing:** ad-hoc with the hardened runtime and no entitlements, like build-dmg.sh: `codesign --force --sign - --options runtime --identifier local.macvpn.vault-spike`.
- **The temporary keychain:**
  - All writes went to a keychain made with `security create-keychain -p <throwaway>` in the scratch directory.
  - The probe addressed it explicitly: `kSecUseKeychain` for the add, `kSecMatchSearchList = [that keychain]` for reads and deletes.
  - `SecKeychainSetUserInteractionAllowed(false)` and `kSecUseAuthenticationUIFail` were set, so no dialog appeared.
- **The search list:** it was not changed. `security list-keychains -d user` was identical before and after: `openvpn.keychain-db`, `login.keychain-db`.
- **Cleanup:** the temporary keychain was deleted afterwards.
- **The data-protection check:** the only call that touched the user's keychains was a read-only `SecItemCopyMatching` for a random, nonexistent service with `kSecUseDataProtectionKeychain = true`.

### B.2 Results

| Question | Result |
|----------|--------|
| `SecItemAdd` with `kSecAttrAccessible = kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, no data-protection keychain, no entitlement | **Accepted** (`errSecSuccess`) |
| Is the attribute kept? | **No.** The returned and the re-read attributes are `acct, cdat, class, labl, mdat, svce`, with no `pdmn`. File-based keychains (login keychain, a temporary keychain) have no accessibility class. They silently drop it. The existing `keychain_ffi::write`, which passes `AfterFirstUnlockThisDeviceOnly`, behaves the same way. |
| Read by the creating binary | OK, 32 bytes, no prompt |
| Read by **another** ad-hoc binary (same bytes, different identifier → different cdhash), with UI disallowed | `-25293 errSecAuthFailed`, so with UI allowed a prompt appears |
| **"Update"**: rebuilt binary (new cdhash), same path, same identifier, re-signed ad-hoc | `-25293`: an access prompt. The ACL trusts only the old cdhash. |
| Identical bytes re-signed again (same cdhash) | read OK, no prompt |
| The same bytes re-signed **without** the hardened runtime (different cdhash) | `-25293`: a prompt |
| Keychain locked (`security lock-keychain`), UI disallowed | data read `-25293`. The attributes (service, account, label) stay readable while locked, and only the secret is protected. |
| The item's ACL (`security dump-keychain -a`, temporary keychain) | `decrypt` is allowed only for `…/probeA` with `requirement: cdhash H"443bb2…"`; `change_acl` has an empty application list. Ad-hoc code has no Team ID, so its designated requirement is just the cdhash. |
| Data-protection keychain (read-only lookup, nonexistent item, no entitlement) | `-25300 errSecItemNotFound`, not `-34018 errSecMissingEntitlement`. Lookups are therefore not refused outright. Whether an **add** would work was not tested, because a successful add would write into the user's real data-protection keychain. Not needed for the decision. |

### B.3 Decision for Task 5

- **Attributes:**
  - Write the item in the login keychain (the default keychain, as today) with: class generic password, service `local.macvpn.vault`, account `dek`, label `MacVPN vault key`, and `kSecAttrAccessible = kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.
  - The attribute is harmless and documents the intent. It starts to apply automatically if the item ever moves to the data-protection keychain, which needs a real signing identity. Do **not** set `kSecUseDataProtectionKeychain`.
- **The security text** (spec 2.3, Task 22 docs, and the Task 25 review) must state what is actually enforced:
  - The DEK is readable by the MacVPN binary whose cdhash is in the item's ACL, while the login keychain is unlocked. The login keychain normally stays unlocked for the whole login session, including the lock screen.
  - Any other binary gets a macOS access prompt.
  - "ThisDeviceOnly" is **not** enforced: the item lives in `~/Library/Keychains/login.keychain-db`, which a Time Machine backup copies, encrypted with the login password.
  - The spec's "data-protection class 'when unlocked'" wording should be read with this in mind.
- **The read path:**
  - At launch, read **without UI first** (`kSecUseAuthenticationUIFail`). On `errSecInteractionNotAllowed` / `errSecAuthFailed`, the app knows a prompt is coming. It can then do one normal read with UI, which shows the macOS dialog, or fall back to the unlock window.
  - Map a user cancel (`errSecUserCanceled` −128) or a denial (`errSecAuthFailed` −25293) to `Denied`. Task 5 already plans this.
- **Prompt count:** one item, so after each update with a new cdhash, macOS shows **one** prompt on the first launch. Today MacVPN shows one prompt per stored secret, so this is an improvement.
  - "Always Allow" adds the new cdhash to the ACL, and there are no further prompts.
  - "Allow" asks again on every launch.

### B.4 Manual verification needed (login keychain, maintainer)

The prompt itself, and whether "Always Allow" on the login keychain also asks for the login password, can only be seen with the real login keychain and a person clicking. Steps:

1. Build the probe. Use the source in the appendix, with `kSecUseKeychain` / `kSecMatchSearchList` removed so that it uses the default keychain, and the service `local.macvpn.vault-spike`.
2. Sign it: `codesign --force --sign - --options runtime --identifier local.macvpn.vault-spike probe`.
3. Run `./probe add`, then `./probe read`. Expect no dialog.
4. Change one string in the source, rebuild, re-sign as in step 2 (same path), and run `./probe readui`.
   - Count the dialogs and note whether a password field is shown.
   - Click "Always Allow", then run `./probe readui` again. Expect 0 dialogs.
5. Lock the screen for a minute, unlock it, and run `./probe read`. Expect success, because the login keychain stays unlocked. Optionally, run `security lock-keychain ~/Library/Keychains/login.keychain-db` and then `./probe readui`: expect a keychain-password dialog.
6. Clean up: `security delete-generic-password -s local.macvpn.vault-spike -a dek`.
7. Record the counts in this file.

Expected: one dialog in step 4, which may ask for the login password, and none afterwards. If the result differs, only the release-notes wording in Task 26 changes. The design does not change.

## C. Argon2id cost

- **Crate:** `argon2 =0.6.0` (RustCrypto) with `default-features = false, features = ["alloc", "zeroize"]`, which avoids `getrandom` / `password-hash`, so core keeps its `Entropy` trait. Call: `Argon2::new(Argon2id, V0x13, Params::new(65536, t, 1, Some(32)))` and then `hash_password_into`.
- **Build:** release.
- **Load:** the system load average was 4–10 during the runs because other builds were running. The medians below are typical, and the minima are close to an idle machine.
- **Correctness:** for t = 1 and t = 3, the output is byte-identical to the reference C implementation (`argon2` CLI 20190702: `-id -m 16 -p 1 -l 32`): `375a25b4…e52b` and `c5a11ba7…04f2`.

| t (m = 64 MiB, p = 1) | M5 arm64 median | Rosetta x86_64 (not representative) |
|---|---|---|
| 1 | 19 ms | – |
| 2 | 39 ms | – |
| 3 | 60 ms | 112 ms |
| 4 | 81 ms | – |
| 5 | 105 ms | – |
| 6 | 130 ms | – |
| 8 | 167–192 ms | 368 ms |
| 16 | 353–372 ms | – |
| 24 | 494–517 ms | 1191 ms |
| 28 | 576–609 ms | – |
| 32 | **660–677 ms** (one 759 ms outlier) | (≈ 1.5 s extrapolated) |

- **Throughput:** about 20.7 ms per pass over 64 MiB.
- **For reference, m = 256 MiB:** t = 3 takes 351 ms and t = 6 takes 540 ms.
- **Decision:** `KdfParams::DEFAULT = { m_kib: 65536, t: 32, p: 1 }`.
  - t = 24 sits right on the 0.5 s floor on this Mac.
  - t = 32 lands in the middle of the 0.5–1 s window and leaves headroom for older Apple Silicon. An M1 is expected at about 1.0–1.2 s.
- **Intel:** no Intel Mac was available. The Rosetta numbers overstate native Intel cost, but expect 1–1.5 s on older Intel Macs. That is acceptable for an operation that runs only when auto-unlock is off, or on create, change password and recovery.
- **The parameters are stored in `vault.keys`**, so they can be raised later without migration. The spec's `t=3` is superseded.

## D. Native L2TP/Cisco profile secrets

### D.1 Where the secrets are today (code reading)

- **The profile** (`crates/core/src/mobileconfig.rs::generate(connection, psk)`):
  - The `IPSec` dictionary carries `AuthenticationMethod = SharedSecret` and `SharedSecret = <PSK bytes>` (plist `Data`) for both L2TP and Cisco.
  - It carries **no password**: no `PPP.AuthPassword` and no `IPSec.XAuthPassword`. Only `AuthName` / `XAuthName` (the account name), and `PromptForVPNPIN = false` for Cisco.
  - The export path calls the same generator with an empty PSK, so an exported `.mobileconfig` has an empty `SharedSecret` (see `crates/core/tests/exporter.rs`).
- **Staging** (`crates/platform-mac/src/profile_staging.rs`):
  - The profile file (which contains the PSK) is written 0600 into a fresh 0700 `mkdtemp` directory.
  - It is opened for approval in System Settings and deleted once the service shows up in `scutil --nc list`, after 600 s for a re-saved profile, or at the next launch (the sweep).
- **Once the profile is installed:**
  - macOS turns the VPN payload into a SystemConfiguration service in `/Library/Preferences/SystemConfiguration/preferences.plist`.
  - Per Apple's SC schema (`SCSchemaDefinitions.h`: `kSCPropNetIPSecSharedSecret` + `kSCPropNetIPSecSharedSecretEncryption = "Keychain"`), the PSK is not kept in the plist. It is kept as an item in the **System keychain** (`/Library/Keychains/System.keychain`), and the service refers to it.
  - The exact item name (expected: the service ID with an `.SS` suffix, kind "IPSec Shared Secret") was **not observed**: no profile was installed. Step D.3.2 records it.
- **MacVPN's own copies:**
  - The PSK, username and password live in the login keychain, `local.macvpn.secrets`, accounts `<UUID>.{username,password,psk}`.
  - For system VPNs the account key is the service ID instead of the UUID.
- **At start** (`crates/core/src/native.rs::start_options` → `platform-mac/src/sc_ffi.rs` → `SCNetworkConnectionStart(conn, userOptions, linger=true)`), MacVPN passes the following, in process, never in argv:
  - L2TP: `IPSec.SharedSecret`, `PPP.AuthName`, `PPP.AuthPassword`
  - Cisco: `IPSec.SharedSecret`, `IPSec.XAuthName`, `IPSec.XAuthPassword`

### D.2 Can the PSK be supplied only at start?

- **For MacVPN-started connections: yes.** The evidence:
  - Commit `0740ba5` (0.1.3) moved native starts from `scutil --nc start` to `SCNetworkConnectionStart` with user options. The reason was that pppd could not read an L2TP PSK from the System keychain ("L2TP: incorrect user shared secret found").
  - The manual checklist (`docs/manual-test-checklist.md`, the `Office L2TP` system-VPN lines) verifies that a PSK saved only in MacVPN and passed in the options connects.
  - The user-options PSK therefore overrides or replaces the stored one in practice.
  - Apple's header (`SCNetworkConnection.h`) warns that "not all options can be overridden … inappropriate options will be ignored". The field result shows that `IPSec.SharedSecret` is honoured.
- **For System Settings-started connections: unknown.**
  - Apple's VPN payload treats `SharedSecret` as optional.
  - macOS shows a prompt for a missing XAuth or PPP password. Whether it also prompts for a missing **shared secret**, or the connection just fails, cannot be decided from the documentation or headers.
  - Whether a profile with `AuthenticationMethod = SharedSecret` but no `SharedSecret` installs at all is also open.
- **Decision until the manual test passes:**
  - Task 12 takes the **"PSK stays in the profile"** branch, with the guard test that `generate` still embeds `SharedSecret`.
  - MacVPN's copies (PSK and password) move into the vault and are still passed at start.
  - The password stays out of the profile in both branches.
- If D.3 shows that the profile without a PSK installs, connects through MacVPN, and works from System Settings (macOS asks for the secret), Task 12 switches to the "PSK only at start" branch.

### D.3 Manual test (maintainer's Mac, needs a reachable L2TP and Cisco test server)

No profile was installed and nothing was connected in this spike.

1. **Baseline:**
   - Create an L2TP connection in MacVPN 1.0/1.1 with a PSK, approve the profile, and connect from MacVPN. Note the service ID from `scutil --nc list`.
   - Run `sudo security dump-keychain /Library/Keychains/System.keychain | grep -E '"svce"|"acct"|"labl"|"desc"'` (names only, **never `-d`**) and record which item holds the PSK: its account, service, label and kind.
   - Run `sudo /usr/libexec/PlistBuddy -c "Print :NetworkServices:<serviceID>:IPSec" /Library/Preferences/SystemConfiguration/preferences.plist` and record the `SharedSecret` / `SharedSecretEncryption` values. These should be a reference, not the secret.
   - Repeat for Cisco IPsec.
2. **Profile without a PSK:**
   - Export the connection (Connections → Export), which gives an empty `SharedSecret`.
   - Make a copy with the key removed entirely: `/usr/libexec/PlistBuddy -c "Delete :PayloadContent:0:IPSec:SharedSecret" test.mobileconfig`.
   - Install each variant by double-clicking it and approving it in System Settings. Record whether installation succeeds, and repeat the System-keychain listing from step 1.
3. **Start through MacVPN:**
   - The installed service appears as a system VPN, or as the bound managed connection.
   - Save the PSK (and password) in MacVPN's Connections window for it, then connect from the menu.
   - Expect it to connect, with no `incorrect user shared secret` in `log show --last 5m --predicate 'process == "racoon" OR process == "pppd"'`.
4. **Start through System Settings** → VPN → the service → Connect. Record whether macOS asks for the shared secret, fails with an error (which one), or connects.
5. Clean up: remove the test profiles in System Settings → Profiles.
6. **Apply the rule:**
   - If steps 3 and 4 work for both kinds, Task 12 uses "PSK only at start".
   - Otherwise it uses "PSK stays in the profile", which is the current default.

## Recommended Cargo setup (Task 4–6)

`crates/core/Cargo.toml`, all optional behind `vault`:

```toml
[features]
vault = ["dep:rusqlite", "dep:argon2", "dep:chacha20poly1305", "dep:zeroize"]

[dependencies]
argon2 = { version = "=0.6.0", default-features = false, features = ["alloc", "zeroize"], optional = true }
chacha20poly1305 = { version = "=0.11.0", default-features = false, features = ["alloc", "zeroize"], optional = true }
zeroize = { version = "1.9.1", optional = true }   # 1.9.1 is already in Cargo.lock

[target.'cfg(target_os = "macos")'.dependencies]
rusqlite = { version = "=0.40.2", features = ["bundled-sqlcipher"], optional = true }
# Linux/Windows (later, with their KeyStore): rusqlite = { version = "=0.40.2", features = ["bundled-sqlcipher-vendored-openssl"], optional = true }
```

- **No `getrandom`:** with these feature sets the tree has no `getrandom` / `rand_core`. Randomness comes from the `Entropy` trait.
- **The RustCrypto API changed in this generation:**
  - `aead 0.6`, `hybrid-array`: `XNonce::from_slice` is deprecated; use `XNonce::try_from(&bytes[..24])`. A key is built with `XChaCha20Poly1305::new(&key.into())`.
  - `chacha20poly1305 0.11` uses `aead::Payload { msg, aad }` for AAD.
- **The crypto crates and their licences:**

  | Crate | Version | Licence |
  |-------|---------|---------|
  | argon2 | 0.6.0 | MIT OR Apache-2.0 |
  | blake2 | 0.11.0 | MIT OR Apache-2.0 |
  | base64ct | 1.8.3 | Apache-2.0 OR MIT |
  | digest | 0.11.3 | MIT OR Apache-2.0 |
  | block-buffer | 0.12.1 | MIT OR Apache-2.0 |
  | crypto-common | 0.2.2 | MIT OR Apache-2.0 |
  | hybrid-array | 0.4.15 | MIT OR Apache-2.0 |
  | typenum | 1.20.1 | MIT OR Apache-2.0 |
  | ctutils | 0.4.3 | Apache-2.0 OR MIT |
  | cmov | 0.5.4 | Apache-2.0 OR MIT |
  | chacha20poly1305 | 0.11.0 | Apache-2.0 OR MIT |
  | aead | 0.6.1 | MIT OR Apache-2.0 |
  | inout | 0.2.4 | MIT OR Apache-2.0 |
  | chacha20 | 0.10.2 | MIT OR Apache-2.0 |
  | cipher | 0.5.2 | MIT OR Apache-2.0 |
  | poly1305 | 0.9.1 | Apache-2.0 OR MIT |
  | universal-hash | 0.6.1 | MIT OR Apache-2.0 |
  | cfg-if | 1.0.5 | MIT OR Apache-2.0 |

  `cargo tree` shows nothing unexpected.

## Appendix: the Keychain probe (Swift, for B.4)

The full source, with modes `add | read | readui | attrs | dpcheck | delete`, was kept in the spike's scratch directory. The essential calls:

```swift
// add
SecItemAdd([kSecClass: kSecClassGenericPassword, kSecAttrService: "local.macvpn.vault-spike",
            kSecAttrAccount: "dek", kSecValueData: Data(32 random bytes),
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecReturnAttributes: true /*, kSecUseKeychain: tempKeychain */] as CFDictionary, &out)
// read without UI (mode "read"); mode "readui" omits the next key and does not call SecKeychainSetUserInteractionAllowed(false)
SecItemCopyMatching([kSecClass: kSecClassGenericPassword, kSecAttrService: "local.macvpn.vault-spike",
                     kSecAttrAccount: "dek", kSecReturnData: true, kSecMatchLimit: kSecMatchLimitOne,
                     kSecUseAuthenticationUI: kSecUseAuthenticationUIFail
                     /*, kSecMatchSearchList: [tempKeychain] */] as CFDictionary, &out)
```
