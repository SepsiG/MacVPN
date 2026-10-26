# MacVPN 1.5 platform-neutral refactor (cross-platform phase 1) – implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Steps use checkbox (`- [ ]`) syntax. The spec is `docs/superpowers/specs/2026-10-20-cross-platform-winvpn-design.md` (sections 3, 5, 6, 7 and the phase 1 definition in section 9). Every earlier spec still applies unchanged. Where this plan and the spec disagree, the spec wins. Follow the existing patterns of the crate you work in (look at a neighbouring module first).

**Goal:** restructure the workspace so one app can serve several operating systems, without changing MacVPN. MacVPN 1.5.0 behaves exactly as 1.4.0: the same windows, texts, files, Keychain items, Info.plist, root layer (`mvpn`, VERSION 8, same install path and protocol), vault, backup, export, team catalog and view-model formats. The only user-visible change is none on macOS; wording becomes per-OS through l10n variants, and on macOS it reads exactly as before. In addition, the whole workspace compiles with `cargo check` for `x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc` against a stub Windows platform that answers "not supported" everywhere. Release 1.5.0 (macOS only).

**Base:** the released 1.4.0 (`develop` at `4b9404d`). Work on a new branch `neutral` from that point. The root layer does not change (root `VERSION` stays 8).

**Architecture (spec 3):**
- **`crates/core`** stays the shared logic. Its Unix-only file operations move behind one module, `macvpn_core::fsx` (Unix now; Windows compile-checked and fail-closed where it needs ACLs). It gets `TargetOs`, the per-OS OpenVPN platform tier and per-OS l10n variants. macOS paths and product names leave core: the functions take them as parameters.
- **`crates/platform-api`** (new, `macvpn-platform-api`): the traits every platform implements and the shared types, including `Product` (identity and paths). It depends on core only. Traits that already fit move here from app-core and are re-exported from their old app-core paths; core's own traits (`KeyStore`, `Entropy`, `LegacyKeychain`, `CatalogFetcher`) stay in core and are re-exported.
- **`crates/app-core`** depends on platform-api for the system-facing traits. macOS concepts get neutral names (`SystemService` → `SystemVpn`, `RootClient` → `HelperClient`, `ProfileInstaller` → `NativeProfiles`). The control server runs over a generic stream (`ControlStream`), not `UnixStream`.
- **`crates/platform-mac`** implements platform-api (`MacPlatform`); the adapters that live in `app/src-tauri/src/platform.rs` today move here. The whole crate is `#![cfg(target_os = "macos")]`, so a Windows check sees an empty crate.
- **`crates/platform-win`** (new, `macvpn-platform-win`): the stub `WinPlatform`; every call returns `PlatformError::Unsupported`. It compiles on every OS.
- **`crates/helper`** (was `crates/mvpn`, package `macvpn-helper`, binary still `mvpn`): a library with the shared logic (CLI, framing, masking, validation dispatch, response parsing, status JSON, the management-bridge state machine) and the backends `macos` (everything that runs today) and `windows` (phase 1: a `main` that refuses).
- **`app/src-tauri`**: one `platform` module (`app/src-tauri/src/platform/`) chooses the platform crate with `cfg(target_os)`; the rest of the app uses only platform-api traits through it.
- **`app/ui`**: one UI; `tr()` picks the per-OS variant; the OS and product come from a new read-only command `get_platform`.

**Rule (spec 3):** `cfg(target_os)` / `cfg(unix)` / `cfg(windows)` appear in production code only in `app/src-tauri/src/platform/`, in `crates/core/src/fsx/`, inside `crates/platform-*` and inside `crates/helper/src/{macos,windows}/` plus the helper's binary entry `crates/helper/src/main.rs`. A source-scan test enforces it (Task 16). Tests, `examples/` and build scripts are outside the rule (see "Resolved points").

**Tech:**
- Rust 1.99.1 (pinned), edition 2024, Tauri 2.12, Svelte + TS.
- No new crates in the macOS binaries. The only new third-party crate in `Cargo.lock` is what `rusqlite`'s `bundled-sqlcipher-vendored-openssl` pulls for Windows targets (`openssl-src`, `openssl-sys`), decided in Task 2; a `cargo tree` check proves it never reaches a macOS target.
- The `platform-win` stub has no dependencies besides core and platform-api (no `windows-sys` in phase 1).

**Rules for every task:**
- TDD: write the failing test first. For a pure move or rename, the "failing test" is the compatibility test of Task 1 or an existing test that must still pass; say which in the commit message body.
- `cargo fmt --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `CI=1 cargo test --workspace --locked` and `CI=1 cargo test --workspace --locked --release` green before each commit. For UI work also `cd app/ui && npm test && npm run build`. If a task touches the helper (`crates/mvpn` / `crates/helper`), also `scripts/test-root.sh`. From Task 16 on, also `scripts/check-windows.sh`.
- No `unsafe` outside `crates/platform-mac`, `crates/platform-win` and `crates/helper`. In particular none in core, app-core, platform-api or the app crate (the workspace lint `unsafe_code = "deny"` stays; only those three crates may `#![allow]` it per module, as `platform-mac` and `mvpn` do today).
- Never log, and never put in argv or env: a password, a PSK, a key password, an OTP, a recovery key, the master password, a vault key, a team key, an admin key, a bearer token, a subscription string, a control-API token, or a config's content. A refactor never adds a log line with a value; moved log lines keep their exact text.
- Serialized formats are frozen: the vault schema and its JSON columns, the backup payload, the per-connection export, the team catalog file, `control-clients.json`, `connection-order.json`, `system-otp.json`, `meta.json`, the view-model JSON and every IPC payload. A renamed Rust field keeps its wire name with `#[serde(rename = "…")]`. The Task 1 fixtures prove it.
- Every new user-facing string goes into `crates/core/l10n/strings.json` in EN and HU (right `scope`). The l10n coverage tests (`crates/app-core/tests/l10n_coverage.rs`, the helper's call-site test, `npm test`) must pass.
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- The maintainer's forbidden company name never enters the repo (code, tests, fixtures, docs, commit messages). Use neutral examples such as "Office VPN", "Acme VPN" and `vpn.example.com`.

**Parallel execution.** Tasks in the same wave touch disjoint files except where the task says "shared with". Run each parallel task in its own worktree (superpowers:using-git-worktrees) from the tip of the previous wave, and merge the wave in task order; the next wave starts from the merged tip. A wave is done when the merged tip passes every check in the rules above.

| Wave | Tasks (parallel within a wave) | Needs |
|---|---|---|
| 0 | 1 baseline fixtures ∥ 2 Windows toolchain spike | – |
| 1 | 3 TargetOs + validator tiers ∥ 4 `fsx` ∥ 5 control transport ∥ 6 l10n variants ∥ 7 helper rename ∥ 8 neutral naming | 1 (2 only informs 16) |
| 2 | 9 platform-api ∥ 10 identity parameters + Tauri per-OS config ∥ 11 helper split | wave 1 (11 needs only 7) |
| 3 | 12 platform-mac implements platform-api ∥ 13 platform-win stub | 9, 10 |
| 4 | 14 app: platform module + first half of the call sites | 12 |
| 5 | 15 app: second half + UI platform wiring | 14, 6 |
| 6 | 16 Windows compile of the whole workspace | 2, 11, 13, 15 |
| 7 | 17 CI Windows job ∥ 18 version 1.5.0 and docs | 16 |
| 8 | 19 verification against 1.4.0 → 20 independent review → 21 release | 17, 18 |

**Key facts from the current code (read before starting):**
- **Workspace:** members `crates/core`, `crates/platform-mac`, `crates/mvpn`, `crates/app-core`, `app/src-tauri`, `examples/macvpn-control-client`; `[workspace.lints.rust] unsafe_code = "deny"`. Dependency graph: `platform-mac → core(vault)`, `app-core → core(vault)`, `mvpn → core` (never `vault`; the `scripts/build-dmg.sh` gate checks that `mvpn` links no SQLite and no catalog code), `macvpn-app → app-core, core, platform-mac`. app-core does **not** depend on platform-mac; the adapters between them are in `app/src-tauri/src/platform.rs` (`Root`, `Native`, `Keychain`, `SharedKeychain`, `ProfileFiles`, `LogStreams`, `AuthStateFiles`, `Preferences`, `GitHubReleases`, `SandboxLoginItem`, `login_items`, `Environment`).
- **`cfg(target_os)` today:** `crates/core/Cargo.toml` (rusqlite only for macOS), `crates/core/tests/vault_db.rs:236`, `app/src-tauri/src/main.rs` (activation policy at setup; `RunEvent::Reopen` and `RunEvent::Opened` arms), `app/src-tauri/src/dock.rs` (`apply`).
- **rusqlite:** `[target.'cfg(target_os = "macos")'.dependencies] rusqlite = { version = "=0.40.2", features = ["bundled-sqlcipher"], optional = true }`; the `vault` feature names `dep:rusqlite`. The comment there says Windows/Linux add `bundled-sqlcipher-vendored-openssl` "together with their KeyStore, not before". `scripts/third-party-notices.mjs` reads `cargo metadata --filter-platform` for the two macOS targets only.
- **Unix file APIs in core** (`OpenOptionsExt`, `PermissionsExt`, `MetadataExt`, `DirBuilderExt`, `libc::O_*`, errno constants; core calls no libc function, only constants): `store.rs` (`save` 0700 dirs; `write_private` temp `create_new` 0600 + `O_NOFOLLOW`, fsync, rename, directory fsync; `shred_file` `O_NOFOLLOW|O_NONBLOCK` + `nlink`; `ensure_private_parent`), `exporter.rs` (`write_with_mode_raced`: temp 0600 `O_NOFOLLOW`, `set_permissions(mode)`, dev/ino check after the rename), `importer.rs` (referenced files: `O_NOFOLLOW|O_NONBLOCK`), `log.rs` (inode of the open log), `mfa.rs` (`AuthUIState::read`: `O_NOFOLLOW|O_NONBLOCK`, regular, `uid == expected`, ≤ 8192), `catalog/source.rs` (`read_catalog_file`: `O_NOFOLLOW|O_NONBLOCK`, the "unavailable" errno list, `ELOOP`, `clear_nonblocking` through a `UnixStream`), `vault/keys.rs` (`vault.keys`: `O_NOFOLLOW`, owner == directory owner), `vault/sealed.rs` (user-picked sealed files), `vault/db.rs` (`create_new` 0600 `O_NOFOLLOW`, owner check, `mode & 0o7777 == 0o600`, `prepare_dir`: 0700, `O_NOFOLLOW|O_DIRECTORY`, chmod 0700, returns the uid), `vault/backup.rs` and `catalog/admin_file.rs` (through `sealed`/`exporter`).
- **Unix file APIs in app-core:** `import_export.rs` (`O_NONBLOCK|O_NOCTTY`, `clear_nonblocking`), `vault.rs` (`DirBuilder` 0700), `control.rs` (`UnixListener`/`UnixStream`, `libc::EINVAL|ENOTCONN|ECONNRESET` in `already_closed`). In the app crate: `control.rs` (the audit file: a hard-coded `O_NOFOLLOW = 0x0100`, 0600) and `smoke.rs` (mode checks).
- **Control server (`crates/app-core/src/control.rs`):** `ControlTransport { bind(dir) -> BoundSocket { listener: UnixListener, path, guard }, peer(&UnixStream) -> PeerIdentity { uid: u32, same_user, pid: i32, executable }, random_32() }`. The server uses on a stream: `try_clone`, `shutdown(Both|Read)`, `set_read_timeout`, `set_write_timeout`, `set_nonblocking` (accept loop, and `peer_connected`'s one-byte peek), `read`, `write_all`; on the listener: `set_nonblocking(true)`, `accept`. The app implements the transport in `app/src-tauri/src/control.rs` over `platform-mac::control_socket` (`bind`, `peer` with `getpeereid` + `LOCAL_PEERPID` + `proc_pidpath`, `same_user`, `random_32`). The app-core tests use their own Unix-socket transport (`crates/app-core/tests/control_support/mod.rs`). Log texts such as `closed a connection from another user (uid {}, pid {})` and `listening on {}` are part of the audit log and must not change.
- **l10n:** one table `crates/core/l10n/strings.json` (`{comment, sourceLanguage, strings, version}`; each entry `{hu, scope}`, the key is the English text; 1114 entries). Core: `tr`, `tr_in`, `hungarian`, `table()`, `Entry { key, hu, scope }`. UI: `app/ui/src/lib/l10n-core.ts` (`translate(table, language, key, args)` uses only `scope == "app"`) and `l10n.svelte.ts`. 80 entries name a macOS term (Keychain, Finder, Mac, macOS, Homebrew/brew, System Settings, Login Items, LaunchAgent, Applications folder, Device Management/Profiles, scutil, sudo, Dock, menu bar); 73 entries contain "MacVPN". Coverage: `crates/app-core/tests/l10n_coverage.rs` scans `crates/core/src`, `crates/mvpn/src`, `crates/platform-mac/src`, `crates/app-core/src`, `app/src-tauri/src`; `scripts/check-l10n.sh`; `app/ui/src/lib/l10n.test.ts`.
- **OpenVPN tiers (`crates/core/src/validators/openvpn.rs`):** `pub struct OpenVPNValidator;` (unit struct, used as a value in `importer.rs`, `catalog/payload.rs`, `validators::validator`), `RISKY_REASONS` (one static table), `REASON_PLATFORM = "Not supported on macOS (Windows or Linux only)"` for `win-sys`, `service`, `cryptoapicert`, `allow-nonadmin`, `setcon`, `msg-channel`, `rdns-internal`, `dhcp-internal`. The root layer runs the same validator. Tests in `crates/core/tests/openvpn_tiers.rs`, `validator_arguments.rs`.
- **Identity in core:** `store::application_support_directory(home)` = `home/Library/Application Support/MacVPN`, `store::default_base_dir(home)`, `store::remove_user_data` refuses a directory not named `MacVPN`; `mfa::AuthUIState::DEFAULT_DIRECTORY = "/var/run/macvpn-ui"` (shared by the root layer's `paths::UI_BASE` and the app's `AuthStateFiles`); `update::UpdateChecker::parse_release` hard-codes `MacVPN-{version}.dmg` (+ `.sha256`, `.sig`); `update::UserGuide::FALLBACK_REPO = "SepsiG/MacVPN"`; the update signature message (`macvpn-update-v1\n<version>\n<sha256>\n`) names no asset and does not change. The update source (`MacVPNUpdateRepo`, `MacVPNUpdateRepoID`) is read from the bundle's Info.plist (`platform-mac::system::bundle_info`).
- **Identity elsewhere (storage identifiers, never renamed):** Keychain services `local.macvpn.vault` (account `dek`) and `local.macvpn.secrets`, the preferences domain `local.macvpn`, the LaunchAgent label `local.macvpn.launcher`, the control socket `macvpn.sock` / `macvpn.lock`, the root paths `/usr/local/libexec/macvpn`, `/var/run/macvpn`, `/var/log/macvpn`, `/etc/sudoers.d/macvpn`, the exported UTIs `local.macvpn.*`.
- **Tauri config:** one `app/src-tauri/tauri.conf.json` (`productName`/`mainBinaryName` `MacVPN`, `identifier` `local.macvpn`, `macOSPrivateApi`, `bundle.targets ["app"]`, the icon list with `icon.icns`, `bundle.macOS.minimumSystemVersion 14.0`) plus `app/src-tauri/Info.plist` (merged by the bundler). Tauri 2 merges `tauri.<platform>.conf.json` (JSON merge patch) over the base. There is no `icons/icon.ico`. `scripts/build-dmg.sh` checks the Info.plist key by key and the three version numbers.
- **The root layer (`crates/mvpn`, 23 modules, bin only):** `cli`, `mask` are pure; `secrets` (framing; needs `ctx::tr` and `paths::SRC_MAX`), `respond::parse`, `status::render` (JSON), `validate`, `lock`, `mgmt_bridge` (a `Bridge` state machine over a `UnixStream`) mix pure logic with macOS I/O; `ctx`, `exec`, `sys` (the `unsafe` libc calls), `paths`, `procs`, `run_dir`, `fsx` (the root layer's own file helpers), `openvpn`, `wireguard`, `strongswan`, `sstp`, `updown`, `hook_dns`, `testmode`, `log` are macOS. `scripts/test-root.sh` builds `-p mvpn`, reads `crates/mvpn/VERSION` (8), greps `crates/mvpn/src/strongswan.rs` and `crates/mvpn/src/*.rs`, and runs `cargo test -p mvpn -- hook_dns::tests::backup_lines_never_glob`; `scripts/build-dmg.sh` builds `-p mvpn` for both targets and reads `crates/mvpn/VERSION`; `scripts/check-l10n.sh` runs `cargo test -p mvpn -- call_site`.
- **The app crate's direct platform-mac calls (20 files):** `main.rs` (12: `install_core_hooks`, `app_hooks`, `KeychainLegacy`, `profile_staging`, `InMemoryKeychain`, `KeychainSecretStore`, `SetupReport`, `KeychainKeyStore`, `SystemEntropy`, `CurlHttpClient`, `CFPreferencesStore`, `system::user_id`, `system::local_date_time`, `sc_watch::SystemVpnWatcher`), `platform.rs` (17), `smoke.rs` (13, debug only), `state.rs` (4), `system.rs` (7: brew, root installer, setup checker, update installer, login item), `update_window.rs` (4), `control.rs` (3), `dialogs.rs` (3), `clipboard.rs`, `notifications.rs`, `tray.rs`, `prompts.rs`, `backup.rs` (2 each), `catalog.rs`, `commands.rs`, `credentials.rs`, `fit.rs`, `manage.rs`, `open_files.rs`, `pairing.rs`, `vault.rs` (1 each). Window functions take the raw `NSWindow` (`*mut c_void` from `WebviewWindow::ns_window()`).
- **UI shortcuts:** `EditorHost.svelte` (Cmd+S: `event.metaKey`), `manage/Sidebar.svelte` (Cmd+F), "Option-click a switch: debug mode" (`altKey`).
- **Smoke:** `scripts/smoke-manage.sh` with `SMOKE_LANG=en|hu`, `MACVPN_SANDBOX_HOME`, flows in `scripts/smoke/`; the driver is `app/src-tauri/src/smoke.rs` (`#[cfg(debug_assertions)]`).
- **CI (`.github/workflows/ci.yml`):** jobs `rust`, `node`, `dmg` on `macos-15`; `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1` with `persist-credentials: false`, `actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0` with `node-version: "26.8.2"` and `package-manager-cache: false`; the toolchain step reads `channel` from `rust-toolchain.toml` and installs exactly that version.
- `docs/manual-test-checklist.md` is written in Hungarian; keep that.

---

## Task 1: baseline – the 1.4.0 compatibility fixtures and the bundle baseline

**Goal:** freeze what "no behaviour change" means before anything moves. Every later task must keep these green without editing the fixtures. Written and committed on the unchanged 1.4.0 code.

**Files:** create `crates/app-core/tests/compat_1_4.rs`, `crates/app-core/tests/fixtures/compat-1.4.0/` (the fixture files below), `scripts/bundle-baseline.sh`, `scripts/bundle-baseline/1.4.0/` (`Info.plist.xml`, `bundle-files.txt`, `otool-L.txt`, `entitlements.txt`, `tauri-config.json`), `scripts/l10n-baseline.mjs`, `scripts/bundle-baseline/1.4.0/l10n-macos.json`.

- [ ] Fixtures, each produced by an `#[ignore]` test `write_compat_fixtures` (run once with `cargo test -p macvpn-app-core --test compat_1_4 -- --ignored write_compat_fixtures`; it refuses to overwrite an existing file) and checked by a normal test that compares bytes. All inputs are fixed: `FixedEntropy` (seeded 0x01…), `KdfParams::insecure_for_tests()`, a fixed `Date` (1 790 000 000 s after 1970, through the constructor the existing tests use), the password `fixture-password-1`, the server `vpn.example.com`, user names `alice`, secrets `fixture-secret`.
  - `backup.macvpnbackup`: `backup::seal(&payload, …)` of a payload with one OpenVPN, one WireGuard, one L2TP connection, a folder tree of two levels with colours, a shared credential linked to the OpenVPN connection, a pin, a ranking, two preferences, a system-VPN placement and a paired control client. The test also opens it with `backup::open` and compares `backup::payload_json` with `backup-payload.json`.
  - `catalog.macvpncatalog`: `seal_catalog` of a catalog with two connections, a folder, a credential slot and a team PSK, signed by an `AdminKey::from_seed([7; 32])`, team key from `FixedEntropy`; plus `open_catalog` → `catalog-payload.json` (the decrypted payload JSON).
  - `export-openvpn.ovpn` and `export-l2tp.mobileconfig`: `exporter::with_meta` / `exporter::export` of the same connections.
  - `meta.json`, `connection-order.json`, `system-otp.json`, `control-clients.json`: `ConnectionStore::save`, `ConnectionRankingStore::save`, `SystemOTPStore::save`, `Registry::save` into a temp directory, then read back as bytes.
  - `vault-dump.json`: a vault created in a temp directory and filled through the repositories with the backup's content, then dumped logically (`SELECT sql FROM sqlite_master ORDER BY name` and every table's rows ordered by primary key, BLOBs as hex). The file bytes of SQLCipher are random by design; the dump is what must stay equal.
  - `view-model.json`: `serde_json::to_string_pretty(&ViewModel)` for a fixed state: the connections above, one connected (`ConnectionState::Connected { ip: Some("10.0.0.2"), since: Some(fixed date) }`), one system VPN (`SystemService::new("8F1C2D3E-0000-4000-8000-000000000001", "Office VPN", "L2TP", "Connected")`), a folder collapsed, a pending update offer, the vault unlocked, one team catalog subscription, the control API on with one client; built through the same `ViewModel::build…` path the publisher uses (find it in `app/src-tauri/src/state.rs`, reproduce it in the test over app-core types only).
  - `release.json` + `release-parsed.txt`: a GitHub `releases/latest` sample with `MacVPN-1.4.0.dmg`, `.sha256`, `.sig`; the `Debug` of `UpdateChecker::parse_release`'s result.
  - `mvpn-usage.txt`, `mvpn-version.txt`: the output (stdout and stderr, and the exit code on the last line) of the debug `mvpn` with no arguments and with `version`. A test in app-core cannot run another crate's binary (`CARGO_BIN_EXE_*` exists only inside the binary's own crate), so these two are written once by hand from `target/debug/mvpn` and checked by `scripts/test-root.sh` (next step).
- [ ] `scripts/test-root.sh`: two new checks comparing `"$MVPN"` (no arguments, stderr+stdout) and `"$MVPN" version` with `crates/app-core/tests/fixtures/compat-1.4.0/mvpn-usage.txt` and `mvpn-version.txt`.
- [ ] `scripts/l10n-baseline.mjs`: writes or checks (`--check`) `scripts/bundle-baseline/1.4.0/l10n-macos.json`, the resolved EN and HU text of every key as the macOS app shows it today (EN = key, HU = `hu`). From Task 6 on it resolves through the new lookup with `os = "macos"` and must give identical output.
- [ ] `scripts/bundle-baseline.sh <app>`: writes (`--write`) or compares (default) for a built `MacVPN.app`: `plutil -convert xml1 -o - Contents/Info.plist` with the three version values replaced by `@VERSION@`; `find . -type f -o -type l | sort` with sizes; `otool -L` of `Contents/MacOS/MacVPN` and of `Contents/Resources/root/mvpn` per architecture (`lipo -thin`); `codesign -d --entitlements :- `; the merged Tauri config (`node -e` merge-patch of `tauri.conf.json` and, when present, `tauri.macos.conf.json`) as `tauri-config.json` with the version normalized. Run it with `--write` on a `scripts/build-dmg.sh` build of 1.4.0 and commit the baseline.
- [ ] Tests (all pass on 1.4.0 now):
  - each fixture above compares byte for byte, and each fixture file is opened again by the current code (round trip)
  - the fixtures contain no value of a real system (grep in the test: no `/Users/`, no host name other than `vpn.example.com`)
- [ ] Commit: `test: 1.4.0 compatibility fixtures and bundle baseline`.

## Task 2: spike – checking the workspace for Windows from macOS and on windows-latest

**Goal:** settle how Task 16 verifies the Windows targets, and which dependencies need per-OS care. Findings go into `docs/superpowers/spikes/2026-10-20-windows-check-spike.md` (kept). Probes run in a scratch clone outside the repository; only the report is committed.

- [x] On the maintainer's Mac: `rustup target add x86_64-pc-windows-msvc aarch64-pc-windows-msvc` (toolchain 1.99.1), then record for each target:
  - `cargo check --target <t> -p macvpn-core` (no `vault`): expected to pass once `libc` constants are behind `fsx` (record today's errors as the to-do list for Task 4).
  - `cargo check --target <t> -p macvpn-core --features vault` with a scratch `[target.'cfg(windows)'.dependencies] rusqlite = { version = "=0.40.2", features = ["bundled-sqlcipher-vendored-openssl"], optional = true }`: the C build of SQLCipher and OpenSSL needs an MSVC-compatible compiler. Record the failure without one, then retry with `cargo xwin check` (`cargo install --locked cargo-xwin`, `brew install llvm`, `XWIN_ACCEPT_LICENSE=1` set by the maintainer after reading the licence): pass or fail, time, disk use.
  - `cargo check --target <t> -p macvpn-app` (Tauri): `tauri-build`'s Windows resource step without and with `cargo xwin`; whether it needs `icons/icon.ico`.
  - `cargo check --target <t> -p mvpn` and `-p macvpn-control-client`: the errors (Unix-only APIs) as the to-do list for Tasks 11 and 16.
  - **Result (`docs/superpowers/spikes/2026-10-20-windows-check-spike.md` sections 2–3):** `openssl-src` builds MSVC targets only on a Windows host (`nmake.exe` through the Windows registry, a Windows Perl), so `cargo xwin` cannot help and was not installed; the Tauri resource needs `icons/icon.ico` and then `rc.exe`/`llvm-rc`. The error lists for Tasks 4, 11, 12, 16 are in the report.
- [ ] (pending: the probe is `docs/superpowers/spikes/2026-10-20-windows-check-spike.workflow.yml`, run by the maintainer on a throwaway branch; results go into the report's section 6) On GitHub's `windows-latest` (a throwaway branch in a fork or a manual `workflow_dispatch` run of a scratch workflow, deleted afterwards): `cargo check --workspace --all-targets --target x86_64-pc-windows-msvc` and `--target aarch64-pc-windows-msvc` with the scratch rusqlite line; record whether `openssl-src` needs NASM or Perl beyond the image (Strawberry Perl ships with the image), the build time with and without the Cargo cache, and whether the ARM64 C cross-compile works with the image's MSVC ARM64 tools.
- [x] `cargo tree --locked --target aarch64-apple-darwin -e features -i openssl-sys` and the same for `x86_64-apple-darwin`: must print nothing with the scratch line in place (resolver 3 does not unify target-specific features across targets). `node scripts/third-party-notices.mjs --check` must still pass. **Result:** `cargo tree` prints nothing, but the notices check fails (it lists `openssl-sys`: `cargo metadata --filter-platform` unifies features across targets); Task 16 changes the script.
- [x] `rustup show` cost of listing the two Windows targets in `rust-toolchain.toml`: the extra download on a fresh macOS runner (rustup installs the listed targets). **Result:** rustup 1.29 installs them on the first `cargo` call; about 45 MB download, 235 MB on disk per macOS job (Task 17).
- [x] **Decision A (local check):** default `scripts/check-windows.sh` runs `cargo check` for the crates without C dependencies on both targets (`macvpn-core` without `vault`, `macvpn-platform-api`, `macvpn-platform-win`, `macvpn-helper`, `macvpn-control-client`) always, and `cargo xwin check --workspace --all-targets` for both targets when `cargo-xwin` is installed (otherwise it says that CI covers the rest and exits 0). Replace this default only if the spike shows `cargo xwin` cannot build SQLCipher/OpenSSL or the Tauri resources; then the full check is CI-only and the script says so. **Decided: replaced** (`cargo xwin` cannot build OpenSSL for MSVC from macOS, nor the resource without `llvm-rc`): the full check is CI-only. The local list is `macvpn-core` without `vault`, `macvpn-helper`, `macvpn-control-client`; `macvpn-platform-api` and `macvpn-platform-win` only if they stay off core's `vault` feature (by default they are CI-only, because the re-exported vault traits need `vault`).
- [x] **Decision B (SQLCipher on Windows):** default: add the Windows rusqlite line in Task 16 now (spec 7 chose `bundled-sqlcipher-vendored-openssl`), because app-core needs `vault` and its tests run on Windows CI. The comment in `crates/core/Cargo.toml` is updated. Replace only if windows-latest cannot build it; the fallback is a Windows `cargo check` only (no Windows `cargo test` of app-core) with `rusqlite` features `["sqlcipher"]` (linking skipped by `check`), recorded as a phase 2 item. **Decided: default kept**, confirmed by the windows-latest probe when it runs; it adds only `openssl-src`/`openssl-sys` to `Cargo.lock`. Task 17 sets `OPENSSL_SRC_PERL` to Strawberry Perl unless the probe shows Git Bash's Perl works.
- [x] **Decision C (NASM):** default: none (the spike records whether `openssl-src` builds without it on the image). If it needs NASM, CI installs it with `choco install nasm --no-progress` (Chocolatey is on the image; no new third-party action). **Decided: none**: `openssl-src` uses NASM only when it is on the PATH and otherwise configures `no-asm`.
- [ ] Commit: `docs(spike): checking the workspace for Windows`.

## Task 3: core – `TargetOs` and the per-OS OpenVPN platform tier

**Files:** create `crates/core/src/target_os.rs`; modify `crates/core/src/lib.rs`, `crates/core/src/validators/openvpn.rs`, `crates/core/l10n/strings.json` (shared with Task 6: add entries only), `docs/openvpn-directives.md`. Tests in `crates/core/tests/openvpn_tiers.rs` and a new `crates/core/tests/target_os.rs`.

- [x] Types:
  ```rust
  // target_os.rs (no cfg attributes: the host comes from std::env::consts::OS, a compile-time constant)
  #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
  pub enum TargetOs { MacOs, Windows, Linux }
  impl TargetOs {
      pub const ALL: [TargetOs; 3];
      pub fn host() -> TargetOs;                 // "macos" → MacOs, "windows" → Windows, anything else → Linux
      pub fn as_str(self) -> &'static str;       // "macos" | "windows" | "linux" (the l10n variant key)
      pub fn parse(s: &str) -> Option<TargetOs>;
  }

  // validators/openvpn.rs
  pub const REASON_PLATFORM: &str = "Not supported on macOS (Windows or Linux only)"; // unchanged
  pub const REASON_PLATFORM_WINDOWS: &str = "Not supported on Windows (Linux only)";
  pub const REASON_SERVICE_OWNED: &str = "Set by the VPN service itself, not by a connection's config";
  /// The platform tier: directives this OS refuses or that need an acknowledgement here, with the reason.
  pub fn platform_reasons(os: TargetOs) -> &'static HashMap<&'static str, &'static str>;
  impl OpenVPNValidator {
      pub fn tier_for(os: TargetOs, directive: &str) -> OpenVPNTier;
      pub fn validate_full_for(&self, os: TargetOs, config: &str, acknowledged: &HashSet<String>) -> OpenVPNValidation;
  }
  ```
  - `RISKY_REASONS` keeps every entry except the eight platform ones; the lookup consults `RISKY_REASONS`, then `platform_reasons(os)`. `OpenVPNValidator` stays a unit struct, and its existing methods (`validate_full`, `tier`, `ConfigValidator::validate`) use `TargetOs::host()`, so no caller changes.
  - `platform_reasons(MacOs)` = the eight directives with `REASON_PLATFORM` (today's table). `platform_reasons(Windows)`: `setcon` → `REASON_PLATFORM_WINDOWS`; `service`, `msg-channel`, `win-sys`, `allow-nonadmin`, `rdns-internal`, `dhcp-internal` → `REASON_SERVICE_OWNED` (the WinVPN Service sets them; a user config must not); `cryptoapicert` is absent, so it falls through to the normal argument checks (add an `ARGUMENT_SPECS` entry `cryptoapicert` with one argument of the `SELECT:`/`THUMB:`/`SUBJ:`/`ISSUER:` forms that is active only for Windows: `argument_spec_for(os, directive)` returns `None` for it on macOS and Linux, so on macOS it stays exactly `REASON_PLATFORM`). `platform_reasons(Linux)` = the macOS table with `setcon` removed (phase 4 revisits it). The Windows table is a draft that the phase 2 security review confirms; phase 1 only ships the macOS one.
- [x] Two new strings (EN/HU, scope `core`; Task 6 adds the third new string of wave 1, `Not available on this system yet`): `Not supported on Windows (Linux only)` → „Windowson nem támogatott (csak Linuxon)”; `Set by the VPN service itself, not by a connection's config` → „Ezt maga a VPN-szolgáltatás állítja be, nem a kapcsolat konfigurációja”.
- [x] `docs/openvpn-directives.md`: the platform tier per OS (a table with the three columns).
- [x] Tests:
  - `TargetOs::host()` is `MacOs` on the macOS CI; `as_str`/`parse` round-trip; `parse("Windows")` is `None` (exact)
  - golden: for every directive in `RISKY_REASONS ∪ platform_reasons(MacOs) ∪ FORBIDDEN ∪ ARGUMENT_SPECS` keys, `tier_for(MacOs, d)` equals the 1.4.0 `tier(d)` (the expected list is generated once on 1.4.0 into `crates/core/tests/fixtures/openvpn-tiers-1.4.0.txt` in this task's first commit, before the change)
  - Windows: `win-sys` risky with `REASON_SERVICE_OWNED`, `setcon` risky with `REASON_PLATFORM_WINDOWS`, `cryptoapicert "THUMB:aa bb"` safe, `cryptoapicert "x"` an argument error; Linux: `setcon` not in the platform tier
  - `validate_full` equals `validate_full_for(TargetOs::host(), …)` for the existing tier test corpus
  - the l10n coverage test passes (the new reason keys are found as constants: add both to `VARIABLE_KEYS` in `l10n_coverage.rs`, shared with Task 6, next to `REASON_PLATFORM`)
- [x] Commit: `feat(core): TargetOs and a per-OS OpenVPN platform tier`.

## Task 4: core and app-core – `fsx`, the safe file operations

**Files:** create `crates/core/src/fsx/mod.rs`, `fsx/unix.rs`, `fsx/windows.rs`; modify `crates/core/src/{lib.rs, store.rs, exporter.rs, importer.rs, log.rs, mfa.rs}`, `crates/core/src/catalog/source.rs`, `crates/core/src/vault/{keys.rs, sealed.rs, db.rs}`, `crates/app-core/src/{import_export.rs, vault.rs}`, `crates/core/Cargo.toml` and `crates/app-core/Cargo.toml` (`libc` becomes `[target.'cfg(unix)'.dependencies]` in core; app-core keeps `libc` until Task 5 removes its last use). Tests in a new `crates/core/tests/fsx.rs` plus the existing ones.

- [x] API (the only module of core with `cfg`; `mod.rs` holds the portable types and dispatches to `unix.rs` / `windows.rs`):
  ```rust
  /// Who may read a file or directory we create.
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub enum Access { Private, Shared }          // Unix: files 0600/0644, directories 0700/0755

  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub enum Follow { No, Yes }                   // No: the last component is never a symlink (O_NOFOLLOW)

  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub enum OpenFor { Read, Write }

  /// Opaque owner identity (Unix: the uid).
  #[derive(Debug, Clone, PartialEq, Eq)]
  pub struct FileOwner(/* private */);
  /// Opaque file identity (Unix: (dev, ino)).
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub struct FileId(/* private */);

  pub fn create_private_dir_all(dir: &Path) -> io::Result<()>;              // DirBuilder recursive 0700 + set 0700
  pub fn ensure_private_dir(dir: &Path) -> io::Result<FileOwner>;           // db.rs prepare_dir, byte for byte
  pub fn create_new(path: &Path, access: Access) -> io::Result<File>;       // write, create_new, mode, O_NOFOLLOW
  pub fn create_new_rw(path: &Path, access: Access) -> io::Result<File>;    // db.rs: read + write
  /// Opens with O_NONBLOCK (never hangs on a FIFO), fstat on the descriptor, refuses anything but a regular file
  /// (`not_regular_file()`), then clears O_NONBLOCK. `noctty`: also O_NOCTTY (import_export).
  pub fn open_regular(path: &Path, open: OpenFor, follow: Follow, noctty: bool) -> io::Result<(File, Metadata)>;
  pub fn open_append(path: &Path, access: Access) -> io::Result<File>;      // append, create, mode, O_NOFOLLOW (app audit file)
  pub fn set_access(file: &File, access: Access) -> io::Result<()>;
  pub fn has_access(meta: &Metadata, access: Access) -> bool;               // mode & 0o7777 == 0o600 / 0o700
  pub fn owner(meta: &Metadata) -> io::Result<FileOwner>;
  pub fn file_id(meta: &Metadata) -> Option<FileId>;
  pub fn hard_links(meta: &Metadata) -> u64;                                // shred_file
  pub fn sync_dir(dir: &Path);                                              // best effort, as today
  /// Temp file in the same directory (create_new, O_NOFOLLOW, `access`), write, fsync, rename, sync_dir; the temp
  /// file is removed on any error. store::write_private's exact steps.
  pub fn atomic_write(path: &Path, data: &[u8], access: Access) -> io::Result<()>;
  pub fn not_regular_file() -> io::Error;                                   // InvalidInput "not a regular file"
  pub fn is_unavailable(e: &io::Error) -> bool;                             // source.rs's errno list
  pub fn is_symlink_refused(e: &io::Error) -> bool;                         // ELOOP
  ```
- [x] Call-site mapping (each must keep its flags, order of checks and error kinds exactly; the reviewer of Task 20 checks this table against the diff):

  | Call site | Today | After |
  |---|---|---|
  | `store.rs` `ConnectionStore::save`, `ensure_private_parent`; `app-core vault.rs` | `DirBuilder` 0700 (+ `set_permissions` 0700 in `save`) | `create_private_dir_all` (`ensure_private_parent` keeps its "only if missing" check) |
  | `store.rs` `write_private` | temp `create_new` 0600 `O_NOFOLLOW`, fsync, rename, dir fsync | `atomic_write(path, data, Private)`; `write_private` stays as a thin wrapper |
  | `store.rs` `shred_file` | `O_NOFOLLOW|O_NONBLOCK` write, regular check, `nlink` | `open_regular(path, Write, Follow::No, false)` + `hard_links` |
  | `exporter.rs` `write_with_mode_raced` | temp 0600 `O_NOFOLLOW`, `set_permissions(mode)`, dev/ino check | `create_new(…, Private)`, `set_access(file, access)`, `file_id` compare; the public `write_with_mode(data, path, mode: u32)` becomes `write_with_access(data, path, Access)`; callers pass `Private` (0600) or `Shared` (0644, the catalog file) |
  | `importer.rs` referenced files, `vault/sealed.rs`, `vault/backup.rs::read_backup_file`, `catalog/admin_file.rs` | `O_NOFOLLOW|O_NONBLOCK`, regular, `take(cap + 1)` | `open_regular(path, Read, Follow::No, false)` |
  | `catalog/source.rs` `read_catalog_file` | same + the errno list + `ELOOP` + `clear_nonblocking` via `UnixStream` | `open_regular` + `is_unavailable` + `is_symlink_refused`; the private `clear_nonblocking` is deleted (now inside `open_regular`) |
  | `app-core import_export.rs` | `O_NONBLOCK|O_NOCTTY` (follows symlinks: user-picked), `clear_nonblocking` | `open_regular(path, Read, Follow::Yes, true)` |
  | `mfa.rs` `AuthUIState::read` | `O_NOFOLLOW|O_NONBLOCK`, regular, `uid == expected`, ≤ 8192 | `open_regular` + `owner(meta)? == expected` (the parameter becomes `expected: &FileOwner`; `FileOwner::from_uid(u32)` exists on Unix only and is called from the platform layer) |
  | `vault/keys.rs` | `O_NOFOLLOW`, regular, owner == directory owner | `open_regular` + `owner` |
  | `vault/db.rs` `create_with_migrations` / `open_with_migrations` / `prepare_dir` | see key facts | `ensure_private_dir`, `create_new_rw(…, Private)`, `owner`, `has_access(meta, Private)` |
  | `log.rs` | `MetadataExt::ino` | `file_id` |

- [x] Windows implementation (`fsx/windows.rs`, compiled and clippy-clean on the Windows targets from Task 16 on, no `unsafe`): `Follow::No` → `std::os::windows::fs::OpenOptionsExt::custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)` and refuse a handle whose `file_attributes()` has `FILE_ATTRIBUTE_REPARSE_POINT` (`is_symlink_refused` recognizes that refusal); `create_new`, `open_append`, `atomic_write` (rename replaces), `sync_dir` (no-op), `hard_links` (1), `file_id` (`None`: stable std has no file index) are real; `is_unavailable` maps `ERROR_FILE_NOT_FOUND`, `ERROR_PATH_NOT_FOUND`, `ERROR_NOT_READY`, `ERROR_BAD_NETPATH`, `ERROR_NETNAME_DELETED`, `ERROR_BAD_NET_NAME`, `ERROR_SEM_TIMEOUT`, `ERROR_NETWORK_UNREACHABLE` (as raw numbers with named constants). **Fail closed** where an ACL or an owner is needed: `Access::Private` in `create_new`/`set_access`/`create_private_dir_all`/`ensure_private_dir`, `owner`, `has_access` return `io::ErrorKind::Unsupported` ("private files on Windows need the platform layer (phase 2)"); `Access::Shared` works. Phase 2 replaces these.
- [x] Tests (`crates/core/tests/fsx.rs`, Unix assertions under `#[cfg(unix)]`):
  - `create_new` Private → mode 0600, Shared → 0644; refuses an existing file and a symlink at the path
  - `create_private_dir_all` → 0700 on every created level the old code made 0700 (only the leaf for `save`'s extra `set_permissions`: keep both behaviours, test both)
  - `ensure_private_dir`: a symlink to a directory → `NotADirectory`; a 0755 directory is changed to 0700; returns the owner of a fresh directory == `owner` of a fresh file
  - `open_regular`: a FIFO is refused without hanging (with a 2 s watchdog thread), a directory is refused, a symlink is refused with `Follow::No` (`is_symlink_refused`) and followed with `Follow::Yes`; the returned file reads in blocking mode
  - `atomic_write`: no temp file is left after a failed rename (target is a directory); the content is complete
  - `is_unavailable` for `ENOENT`, `ETIMEDOUT`, `EDEADLK`; not for `EACCES`
  - every existing test of `store`, `exporter`, `importer`, `mfa`, `catalog_source`, `vault_*`, `migration`, `vault_lifecycle`, `import_export` passes unchanged; Task 1's fixtures pass
- [x] Commit: `refactor(core): fsx, the safe file operations behind one module`.

## Task 5: app-core – the control-API transport over generic streams

**Files:** modify `crates/app-core/src/control.rs`, `crates/app-core/Cargo.toml` (drop `libc`), `crates/platform-mac/src/control_socket.rs` (`is_already_closed` only), `crates/app-core/tests/control_support/mod.rs`, `crates/app-core/tests/control_server.rs`, `crates/app-core/tests/control_example_client.rs`, `app/src-tauri/src/control.rs` (the `Transport` impl only; shared with Task 8, which renames `SystemService` in other hunks).

- [x] Types (in `app-core::control` for now; Task 9 moves them to platform-api and re-exports them here):
  ```rust
  /// One client connection. Clones share the underlying connection (like `UnixStream::try_clone`).
  pub trait ControlStream: Read + Write + Send + Sync {
      fn try_clone(&self) -> io::Result<Box<dyn ControlStream>>;
      fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()>;
      fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
      fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
      /// Still connected, without blocking and without consuming data the reader needs (today's `peer_connected`).
      fn peer_connected(&self) -> bool;
  }
  pub enum Accepted {
      /// A client; `peer` failed when its identity could not be read.
      Client { stream: Box<dyn ControlStream>, peer: io::Result<PeerIdentity> },
      /// Nothing within the poll interval (the accept thread checks the stop flag).
      Idle,
  }
  pub trait ControlListener: Send {
      fn accept(&self, poll: Duration) -> io::Result<Accepted>;
  }
  #[derive(Debug, Clone, PartialEq, Eq)]
  pub enum PeerUser { Uid(u32), Sid(String) }       // Display: "uid 501" / "sid S-1-5-…"
  pub struct PeerIdentity { pub user: PeerUser, pub same_user: bool, pub pid: i32, pub executable: Option<String> }
  pub struct BoundEndpoint {
      pub listener: Box<dyn ControlListener>,
      /// For the "listening on …" log line (macOS: the socket path, displayed as today).
      pub display: String,
      /// Removed by `ControlServer::stop` (macOS: the socket file; a named pipe: `None`).
      pub socket_file: Option<PathBuf>,
      pub guard: Box<dyn Send + Sync>,
  }
  pub trait ControlTransport: Send + Sync {
      fn bind(&self, dir: &Path) -> io::Result<BoundEndpoint>;
      fn random_32(&self) -> io::Result<[u8; 32]>;
      /// The client connected and closed at once (macOS: EINVAL / ENOTCONN / ECONNRESET): no log line.
      fn is_already_closed(&self, e: &io::Error) -> bool;
  }
  ```
  - `BoundSocket` and `ControlTransport::peer` are removed; the accept loop calls `listener.accept(limits.accept_poll)` (the platform listener does the non-blocking accept and sleeps for the poll, clears `O_NONBLOCK` on the client, and identifies the peer); `already_closed` becomes `transport.is_already_closed`. `ControlServer::socket_path()` becomes `endpoint() -> &str` plus `socket_file() -> Option<&Path>`; update its one caller.
  - Every log line keeps its text: `closed a connection from another user ({user}, pid {pid})` where `PeerUser::Uid(501)` displays as `uid 501`.
  - The macOS implementation lives in the app crate for now (platform-mac does not depend on app-core, and the orphan rule forbids implementing app-core's trait for `std`'s `UnixStream` anywhere but app-core): `app/src-tauri/src/control.rs` gets the newtypes `UnixControlStream(UnixStream)` (`peer_connected` is today's peek, moved verbatim) and `UnixControlListener` (wraps the bound `UnixListener`, `set_nonblocking(true)` once; `accept` → `set_nonblocking(false)` on the client → `control_socket::peer` → `PeerIdentity`), and `Transport::is_already_closed`, which calls a new plain function `control_socket::is_already_closed(e: &io::Error) -> bool` in platform-mac (the three errnos; the app crate has no `libc`). Task 12 moves the whole transport into platform-mac, where the traits are then platform-api's. The app-core test transports are newtypes in `tests/control_support` too.
- [x] Test transports: `control_support` keeps its Unix-socket transport (now `#[cfg(unix)]` in the test file) and gains `LoopbackTransport` over `TcpListener::bind("127.0.0.1:0")` (`PeerUser::Uid(0)`, `same_user: true`, executable from a test-configured string), which runs on every OS. `control_server.rs` runs its whole suite over both transports (a macro or a generic fn per test); `control_example_client.rs` stays Unix-only.
- [x] Tests:
  - the existing control server suite, unchanged in its assertions, over both transports
  - `peer_connected` false after the client closes, true while it waits (Unix socket and loopback)
  - a peer of another user (fake transport returning `same_user: false`) → the exact 1.4.0 log line, no session
  - `stop` removes `socket_file` when `Some`, nothing when `None`
  - `cargo tree -p macvpn-app-core` no longer lists `libc` as a direct dependency (checked by `grep` in the task, not a test)
- [x] Commit: `refactor(app-core): the control API over generic streams`.

## Task 6: core and UI – per-OS l10n variants and the product name

**Files:** modify `crates/core/src/l10n.rs`, `crates/core/l10n/strings.json` (shared with Task 3), `crates/app-core/tests/l10n_coverage.rs` (shared with Tasks 3 and 7), `scripts/check-l10n.sh`, `scripts/l10n-baseline.mjs`, `app/ui/src/lib/l10n-core.ts`, `app/ui/src/lib/l10n.svelte.ts`, `app/ui/src/lib/l10n.test.ts`, `app/ui/src/lib/manage/EditorHost.svelte`, `app/ui/src/lib/manage/Sidebar.svelte`, new `app/ui/src/lib/keys.ts` + `keys.test.ts`. Tests in `crates/core/tests/l10n.rs`.

- [x] **Format.** An entry may have two optional fields (the key stays the macOS English text, so no call site changes):
  ```json
  "If macOS asks for access to the Keychain, choose Always Allow.": {
    "hu": "Ha a macOS hozzáférést kér a Kulcskarikához, válaszd a Mindig engedélyezem gombot.",
    "scope": "app",
    "only": ["macos"]
  },
  "Enter the master password. Its key is then kept in the macOS Keychain, and MacVPN opens without asking.": {
    "hu": "…", "scope": "app",
    "variants": { "windows": { "en": "Enter the master password. Its key is then kept in the Windows Credential Manager, and MacVPN opens without asking.", "hu": "…" } }
  }
  ```
  - `variants.<os>` (`windows` or `linux`): the text on that OS, both `en` and `hu`. `only`: the OSes whose code paths show the string (no variant needed; on another OS it is never shown). Neither: the same text everywhere.
  - **Product name:** on an OS whose product is not MacVPN, every resolved text (base or variant, EN and HU) has `MacVPN` replaced by the product name, except entries with `only: ["macos"]`. Hungarian suffixes stay correct (both names end in "VPN"). On macOS nothing is replaced.
- [x] Core API (no `cfg`; the platform installs the values at launch, the defaults are the macOS ones so every existing test is unchanged):
  ```rust
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub struct TextPlatform { pub os: TargetOs, pub product: &'static str }
  impl TextPlatform { pub const MACOS: TextPlatform = TextPlatform { os: TargetOs::MacOs, product: "MacVPN" }; }
  pub fn set_text_platform(p: TextPlatform);          // once, at launch (platform layer); default MACOS
  pub fn text_platform() -> TextPlatform;
  pub fn tr_for(p: TextPlatform, language: AppLanguage, key: &str, args: &[Arg<'_>]) -> String;
  // tr / tr_in = tr_for(text_platform(), …)
  pub struct Entry { pub key: String, pub hu: String, pub scope: String,
                     pub only: Vec<TargetOs>, pub variants: BTreeMap<TargetOs, (String, String)> }
  ```
- [x] UI: `translate(table, language, platform, key, args)` with `platform: { os: 'macos' | 'windows' | 'linux'; product: string }`; `i18n` gains `platform` (`$state`, default `{ os: 'macos', product: 'MacVPN' }`) and `setPlatform(p)`; `tr()` passes it. Task 15 fills it from `get_platform`. `keys.ts`: `isPrimaryShortcut(event, key)` (macOS: `metaKey` and no `ctrlKey`; Windows/Linux: `ctrlKey` and no `metaKey`; never `altKey`/`shiftKey`) used by the Cmd+S and Cmd+F handlers; the macOS behaviour is identical.
- [x] One new string for the later tasks (so the wave-2 tasks need not add it in parallel): `Not available on this system yet` → „Ezen a rendszeren még nem érhető el” (scope `platform`), used by `PlatformError::Unsupported` (Task 9), the helper's Windows `main` (Task 11) and the stub (Task 13); list it in `VARIABLE_KEYS` until Task 9 adds its call site.
- [x] **Classification of the macOS-specific strings.** The coverage test's term list (below) finds them; each gets `only: ["macos"]` or a `windows` variant. Rule: `only: ["macos"]` for Homebrew, the root layer and sudoers, scutil, LaunchAgent/SMAppService, `/usr/local/libexec`, Device Management / profiles, Gatekeeper/quarantine/Applications folder, the 1.1 Keychain migration, and every `mvpn`-scope message of the macOS backend (`brew install …`, `charon`, `wg-quick`, `sstpc`). A `windows` variant for shared features whose wording names a macOS facility: Keychain → Credential Manager („Hitelesítőadat-kezelő”), Finder → File Explorer („Fájlkezelő”), "this Mac" → "this PC" („ez a számítógép”, with the right case: „ezen a számítógépen”, „erről a számítógépről”), System Settings → Settings („Gépház”), Login Items → Startup apps („Indítási alkalmazások”), menu bar → notification area („értesítési terület”), Dock → taskbar („tálca”), `Option-click` → `Alt-click` („Alt+kattintás”). `REASON_PLATFORM` gets no variant (the validator returns the Windows reasons of Task 3 on Windows). Record the full list with its classification in the task's commit message body.
- [x] Tests:
  - core: `tr_for(MACOS, En|Hu, k)` equals the 1.4.0 text for **every** key (`scripts/l10n-baseline.mjs --check` against Task 1's `l10n-macos.json`, and the same check in Rust over `table()`)
  - core: a `windows` variant is returned on Windows in both languages; an entry without a variant gives the base text with `MacVPN` → `WinVPN`; an `only: ["macos"]` entry is never substituted; `%@`/`%d`/`%lld` sequences of every variant equal those of its base (count and kinds, also positional)
  - coverage (`l10n_coverage.rs`, new test `macos_terms_are_classified`): every key or HU text matching `\b(Keychain|Kulcskarika|Finder|Mac|macOS|Homebrew|brew|System Settings|Rendszerbeállítások|Login Items|LaunchAgent|Applications|Device Management|scutil|sudo|sudoers|Dock|menu bar|menüsor|Option-click|Gatekeeper)\b` has `only` or a `windows` variant; `only` and `variants` never both name the same OS; a variant has both `en` and `hu`
  - UI (`l10n.test.ts`): the same three resolution rules; `keys.test.ts`: Cmd+S on macOS, Ctrl+S on Windows, Ctrl+S on macOS is not the shortcut
  - every existing l10n test, `scripts/check-l10n.sh`, `npm test`
- [x] Commit: `feat(l10n): per-OS text variants and the product name`.

## Task 7: helper – move `crates/mvpn` to `crates/helper` (no code change)

**Files:** `git mv crates/mvpn crates/helper`; modify `crates/helper/Cargo.toml` (package `macvpn-helper`, `[[bin]] name = "mvpn"`, `path = "src/main.rs"`), `Cargo.toml` (members), `Cargo.lock`, `scripts/test-root.sh`, `scripts/build-dmg.sh`, `scripts/check-l10n.sh`, `crates/app-core/tests/l10n_coverage.rs` (the source directory list; shared with Task 6), `README.md`, `app/README.md`, `docs/RELEASING.md` (paths only), `.github/workflows/*.yml` (only if they name `-p mvpn`).

- [x] Every `-p mvpn` becomes `-p macvpn-helper`; every `crates/mvpn/` becomes `crates/helper/`; the built binary is still `target/<profile>/mvpn` and `target/<triple>/release/mvpn`, so the DMG layout (`Contents/Resources/root/mvpn`, `VERSION`) and the install path (`/usr/local/libexec/macvpn/mvpn`) do not change. `crates/helper/VERSION` stays `8`.
- [x] Tests:
  - `scripts/test-root.sh` passes (including Task 1's usage and version checks)
  - `cargo test -p macvpn-helper` passes; `scripts/check-l10n.sh` passes
  - `scripts/build-dmg.sh` produces the same `Contents/Resources/root/` file list (`scripts/bundle-baseline.sh` on the built app shows no difference other than the binary hashes)
  - `grep -rn 'crates/mvpn\|-p mvpn' --exclude-dir=target --exclude-dir=node_modules --exclude-dir=superpowers .` prints nothing
- [x] Commit: `refactor: crates/mvpn becomes crates/helper (macvpn-helper, binary mvpn)`.

## Task 8: app-core and core – neutral names

**Files:** `crates/app-core/src/{deps.rs, manager.rs, editor.rs, connections.rs, backup.rs, setup.rs, logs.rs, lib.rs}` and every app-core test using the renamed items, `app/src-tauri/src/{platform.rs, main.rs, catalog.rs, control.rs, smoke.rs, state.rs, system.rs}` (renames only; shared with Task 5 in `control.rs`), `crates/core/src/models.rs` (doc comments).

- [x] Renames (the old names are not kept as aliases: one name per concept):
  | Old | New |
  |---|---|
  | `deps::SystemService` | `deps::SystemVpn` (same fields; the doc names the labels every platform must produce: `type_label` ∈ `L2TP`, `Cisco IPsec`, `IKEv2`, `WireGuard (app)`, `OpenVPN (app)`, `VPN`; `status` ∈ `Connected`, `Connecting`, `Disconnecting`, `Disconnected`) |
  | `deps::RootClient`, `Dependencies::root` | `deps::HelperClient`, `Dependencies::helper` |
  | `deps::ProfileInstaller` (`install(id, profile, file_name, service_existed)`) | `deps::NativeProfiles` with `build(&self, connection: &Connection, psk: &str) -> Result<NativeProfile, String>` and the same `install`; `pub struct NativeProfile { pub data: Zeroizing<Vec<u8>>, pub file_name: String }` |
  | direct `macvpn_core::mobileconfig::generate` in `editor.rs`, `connections.rs`, `backup.rs` | `deps.profiles.build(…)` (the app's implementation calls `mobileconfig::generate` and `exporter::file_name`, exactly as today; app-core tests use `tests/common`'s `MobileconfigProfiles` that does the same) |
  | identifiers containing `mobileconfig` in app-core | `native_profile` (wire names unchanged) |
  | `setup::UninstallSystem::uninstall_root`, `remove_launch_agent` | `uninstall_helper`, `remove_stale_login_entries` |
  | `logs::PREDICATE` and the `$ log stream …` header line | `LogStreamSpawner::command_line(&self) -> String` (the macOS implementation returns today's exact text) |
- [x] Unchanged on purpose: `NativeController`, `AuthStateReader`, `PreferenceStore`, `ReleaseSource`, `LogStreamSpawner`, the IPC command names, `SetupFacts` and every view-model field (the UI reads them), the vault's `system_items` table, `LegacyKeychain` (a macOS-only legacy source, see "Resolved points"), `core::mobileconfig` (a file format, also the L2TP/Cisco export).
- [x] Every serde field of a renamed Rust field keeps its JSON name (`#[serde(rename = "…")]`).
- [x] Tests: all existing tests with the new names; Task 1's `view-model.json`, `backup*.json` and `vault-dump.json` unchanged; a test that `NativeProfiles::build` of the app's implementation gives byte-identical data to `mobileconfig::generate` for an L2TP and a Cisco connection.
- [x] Commit: `refactor(app-core): neutral names for system VPNs, the helper and native profiles`.

## Task 9: platform-api – the platform traits, shared types and `Product`

**Files:** create `crates/platform-api/{Cargo.toml, src/lib.rs, src/product.rs, src/error.rs, src/helper.rs, src/native_vpn.rs, src/control.rs, src/system.rs, src/setup.rs, src/login_item.rs, src/updates.rs, src/ui.rs, src/prefs.rs, src/logs.rs, src/debug.rs}`; modify `Cargo.toml` (member), `crates/app-core/Cargo.toml` (dependency), `crates/app-core/src/{deps.rs, control.rs, app.rs, updates.rs, logs.rs, setup.rs, view_model.rs, lib.rs}` (the moved items become `pub use macvpn_platform_api::…`). Tests in `crates/platform-api/tests/product.rs` and `tests/error.rs`.

- [x] `Cargo.toml`: `macvpn-platform-api`, depends on `macvpn-core` (with `vault`, for the re-exported `KeyStore`/`Entropy`/`LegacyKeychain`), `serde`, `uuid`, `zeroize`; `[lints] workspace = true`; no `unsafe`.
- [x] Moved from app-core (re-exported at the old paths, so app-core's callers and tests do not change): `HelperClient`, `NativeController`, `SystemVpn`, `NativeProfiles`, `NativeProfile`, `AuthStateReader`, `NoAuthState`, `PreferenceStore`, `ReleaseSource`, `UpdateSource`, `LogStreamSpawner`, `StreamHandle`, `LoginItemView`, and Task 5's `ControlTransport`, `ControlListener`, `ControlStream`, `Accepted`, `PeerIdentity`, `PeerUser`, `BoundEndpoint`. Re-exported from core: `TargetOs`, `KeyStore`, `Entropy`, `LegacyKeychain`, `CatalogFetcher`. Stay in app-core (implemented by the app, not by a platform): `ConnectionRepository`, `SecretReader`, `SecretWriter`, `FolderStore`, `RankingPersistence`, `SystemOTPPersistence`, `Clock`, `ControlHost`, `RegistryStore`, `PreferencePort`, `UninstallSystem`, `TrackedPrompt`.
- [x] `Product` (`product.rs`):
  ```rust
  #[derive(Debug)]
  pub struct Product {
      pub name: &'static str,             // "MacVPN" / "WinVPN"; also the data directory's name
      pub os: TargetOs,
      pub app_id: &'static str,           // "local.macvpn" / "local.winvpn" (Windows: also the AppUserModelID)
      pub repo: &'static str,             // "SepsiG/MacVPN" (one repo, spec 2): Help fallback and asset checks
      pub user_guide_stem: &'static str,  // "user-guide" / "winvpn-user-guide" → docs/<stem>.<lang>.md
  }
  pub const MACVPN: Product; pub const WINVPN: Product;
  impl Product {
      /// `<app-data root>/<name>`: the platform gives the root (macOS: `<home>/Library/Application Support`).
      pub fn data_dir(&self, app_data_root: &Path) -> PathBuf;
      /// MacVPN: `MacVPN-<version>.dmg`; WinVPN: `WinVPN-<version>-x64.msi` / `-arm64.msi` by `arch`
      /// (`std::env::consts::ARCH`: `x86_64` → `x64`, `aarch64` → `arm64`; other → `None`).
      pub fn update_asset(&self, version: &str, arch: &str) -> Option<String>;
      pub fn text_platform(&self) -> macvpn_core::l10n::TextPlatform;
  }
  ```
- [x] `PlatformError` (`error.rs`): `Unsupported { what: &'static str }` (message: the l10n key `Not available on this system yet`, added by Task 6) and `Failed(String)` (an already localized message); `message() -> String`; `From<PlatformError> for String`.
- [x] New traits (signatures mirror today's platform-mac functions so Task 12 is a move, not a rewrite):
  ```rust
  pub trait SystemInfo: Send + Sync {
      fn home_directory(&self) -> Option<PathBuf>;
      fn app_data_root(&self, home: &Path) -> PathBuf;
      fn user_owner(&self) -> macvpn_core::fsx::FileOwner;            // AuthStateFiles' expected owner
      fn temporary_directory(&self) -> Result<PathBuf, PlatformError>;
      fn local_date(&self, unix: f64) -> String;
      fn local_date_time(&self, unix: f64, language: AppLanguage) -> String;
      fn app_location(&self) -> Option<PathBuf>;                       // the running bundle (macOS `.app`)
      fn bundled_helper_dir(&self, app: &Path) -> Option<PathBuf>;
      fn update_info(&self, app: &Path) -> Option<macvpn_core::update::Info>;
  }
  pub trait Shell: Send + Sync {
      fn open_path(&self, path: &Path) -> Result<(), PlatformError>;   // absolute paths only
      fn open_url(&self, url: &str) -> Result<(), PlatformError>;      // callers validate first (is_safe_github_url)
      fn open_native_profile_settings(&self);
      fn copy_text(&self, text: &str) -> Result<(), PlatformError>;
  }
  /// The localized lines the package-manager bootstrap script prints (today's `BrewBootstrap::script` arguments).
  pub struct BootstrapTexts { pub start: String, pub done: String, pub failed: String }
  pub trait SystemSetup: Send + Sync {
      fn check(&self, bundled_helper_dir: Option<&Path>) -> SetupReport;   // SetupReport moves here; field brew_prefix → package_manager
      fn install_package_manager(&self, texts: &BootstrapTexts, parent: &Path, sandbox: bool) -> Result<(), PlatformError>;
      fn install_tools(&self, report: &SetupReport) -> Result<(), PlatformError>;
      fn install_helper(&self, source_dir: &Path, user: &str) -> Result<(), PlatformError>;
      fn uninstall_helper(&self, user: &str) -> Result<(), PlatformError>;
      fn helper_upgrade_notice(&self) -> String;
  }
  pub trait LoginItems { fn state(&self) -> LoginItemView; fn set_enabled(&mut self, on: bool) -> Result<(), PlatformError>;
                         fn unregister_if_registered(&mut self) -> Result<bool, PlatformError>; fn open_settings(&self);
                         fn remove_stale_entries(&self) -> Result<(), PlatformError>; }
  pub enum UpdateOutcome { HelperLaunched, Cancelled }               // moved from platform-mac
  pub trait Updater: Send + Sync {
      /// Download, verify (SHA-256 + Ed25519), install, relaunch, in the one allowed order (today's
      /// `update_installer::install_update` over the real `UpdateInstaller`); `stage` gets the localized step text;
      /// `confirm_quit` is the quit questions. The error is the localized message.
      fn install(&self, release: &Release, app: &Path, home: &Path, stage: &dyn Fn(String),
                 confirm_quit: Box<dyn FnOnce() -> bool + '_>) -> Result<UpdateOutcome, String>;
      /// Today's `update_installer::launch_housekeeping(app, cache, home, noticed)` with the cache directory derived
      /// from `home` inside the platform: (the removed leftovers, the previous run's `(run id, message)` notice).
      fn launch_housekeeping(&self, app: &Path, home: &Path, noticed: Option<&str>) -> (Vec<PathBuf>, Option<(String, String)>);
  }
  pub struct NativeWindow(pub *mut core::ffi::c_void);              // NSWindow / HWND; never dereferenced outside a platform crate
  pub trait WindowChrome: Send + Sync {
      fn popover_corner_radius(&self) -> f64;
      fn round_corners(&self, w: NativeWindow, radius: f64) -> bool;
      fn fit_viewport(&self, w: NativeWindow, width: f64, viewport: f64, center: bool) -> Option<f64>;
      fn order_front_regardless(&self, w: NativeWindow);
  }
  pub trait FilePanels: Send + Sync {
      fn choose_files(&self, parent: NativeWindow, multiple: bool, done: Box<dyn FnOnce(Vec<PathBuf>)>);
      fn choose_save_path(&self, parent: NativeWindow, suggested: &str, done: Box<dyn FnOnce(Option<PathBuf>)>);
  }
  pub trait Notifier: Send + Sync {
      fn start(&self, on_click: Box<dyn Fn(BTreeMap<String, String>) + Send + Sync>);
      fn post(&self, identifier: &str, title: &str, body: &str, user_info: (&str, &str));
      fn remove_delivered(&self, identifier: &str);
  }
  pub struct ClipboardMark(pub isize);
  pub trait SecretClipboard: Send + Sync {
      fn write_secret(&self, text: &str) -> Result<ClipboardMark, PlatformError>;
      fn clear_if_unchanged(&self, mark: ClipboardMark) -> bool;
  }
  pub enum TerminateReply { Now, Later, Cancel }
  pub trait AppLifecycle: Send + Sync {
      fn install_terminate_handler(&self, handler: Box<dyn Fn() -> TerminateReply + Send + Sync>) -> bool;
      fn reply_to_terminate(&self, terminate: bool);
      fn observe_wake(&self, on_wake: Box<dyn Fn() + Send + Sync>);
  }
  pub trait DownloadMark: Send + Sync { fn is_marked(&self, path: &Path) -> bool; }
  pub trait SystemVpnWatch: Send + Sync {
      fn start(&self, on_change: Box<dyn Fn() + Send>) -> io::Result<Box<dyn Send>>;  // dropping the box stops it
  }
  /// One handle per platform crate; the app's `platform` module returns `&'static dyn Platform`.
  pub trait Platform: Send + Sync {
      fn product(&self) -> &'static Product;
      fn install_core_hooks(&self);                                    // collation, preferred languages, text platform
      fn system(&self) -> &dyn SystemInfo;
      fn shell(&self) -> &dyn Shell;
      fn setup(&self) -> &dyn SystemSetup;
      fn updater(&self) -> &dyn Updater;
      fn windows(&self) -> &dyn WindowChrome;
      fn file_panels(&self) -> &dyn FilePanels;
      fn notifier(&self) -> &dyn Notifier;
      fn clipboard(&self) -> &dyn SecretClipboard;
      fn lifecycle(&self) -> &dyn AppLifecycle;
      fn download_mark(&self) -> &dyn DownloadMark;
      fn system_vpn_watch(&self) -> &dyn SystemVpnWatch;
      fn control_transport(&self) -> Arc<dyn ControlTransport>;
      fn helper_client(&self) -> Arc<dyn HelperClient>;
      fn native_controller(&self) -> Arc<dyn NativeController>;
      fn native_profiles(&self, staging: &Path, open: bool) -> Arc<dyn NativeProfiles>;
      fn auth_state(&self) -> Arc<dyn AuthStateReader>;
      fn log_streams(&self) -> Arc<dyn LogStreamSpawner>;
      fn release_source(&self) -> Arc<dyn ReleaseSource>;
      fn https_catalog_fetcher(&self) -> Arc<dyn CatalogFetcher>;
      fn key_store(&self) -> Arc<dyn KeyStore>;
      fn entropy(&self) -> Arc<dyn Entropy>;
      fn legacy_keychain(&self) -> Arc<dyn LegacyKeychain>;
      /// The 1.1 secrets as the legacy read-only mode reads them (macOS: `KeychainSecretStore`; the sandbox shares
      /// one memory keychain with `legacy_keychain`, as `main.rs::storage` does today).
      fn legacy_secrets(&self) -> Arc<dyn LegacySecrets>;
      /// The one-time move of the older service's Keychain items (`KeychainSecretStore::migrate_legacy_items`;
      /// a no-op in the sandbox and on other platforms).
      fn migrate_legacy_service(&self);
      fn preferences(&self) -> Arc<dyn PreferenceStore>;
      fn login_items(&self, home: &Path, app: Option<&Path>, sandbox: bool) -> Box<dyn LoginItems>;
  }
  ```
  `LegacySecrets` (`helper.rs`): `pub trait LegacySecrets: Send + Sync { fn get(&self, id: &Uuid, field: SecretField) -> Option<String>; }`; app-core gets `struct LegacySecretReader(pub Arc<dyn LegacySecrets>)` implementing `SecretReader` (the `ReadOnly` wrapper of `main.rs` keeps wrapping it), so the legacy read path calls exactly what `Keychain(KeychainSecretStore::system())` calls today.
  `debug.rs` (only with `debug_assertions`): `pub trait SmokeHooks { fn force_appearance(&self, dark: bool) -> bool; fn window_shape(&self, w: NativeWindow) -> Option<WindowShape>; fn window_number(&self, w: NativeWindow) -> Option<isize>; fn activation_policy_is_regular(&self) -> Option<bool>; fn seed_legacy_keychain(&self, items: &[(String, String, Vec<u8>)]); }` (`WindowShape` moves here from `window_shape.rs`; `seed_legacy_keychain` writes `(service, account, data)` into the sandbox's memory keychain, replacing `smoke::seed_legacy_keychain`'s direct access) — implemented by platform-mac; the stub returns `false`/`None` and seeds nothing. The sandbox update run (`smoke::SandboxUpdate`, an `UpdateSteps` fake) stays inside the smoke module, which calls platform-mac's `install_update` directly (Task 14).
- [x] Tests:
  - `MACVPN.data_dir(Path::new("/Users/x/Library/Application Support"))` = `/Users/x/Library/Application Support/MacVPN`; `MACVPN.update_asset("1.5.0", "aarch64")` = `MacVPN-1.5.0.dmg` (also for `x86_64`); `WINVPN.update_asset("1.5.0", "x86_64")` = `WinVPN-1.5.0-x64.msi`, `aarch64` → `-arm64.msi`, `riscv64` → `None`; `MACVPN.text_platform() == TextPlatform::MACOS`
  - `PlatformError::Unsupported` message in EN and HU; no value of the caller appears in it
  - app-core compiles and all its tests pass through the re-exports (no test file edited in this task)
- [x] Commit: `feat: platform-api, the platform traits and the product identity`.

## Task 10: core – identity as parameters; Tauri per-OS config

**Files:** modify `crates/core/src/{store.rs, update.rs, mfa.rs, system_otp.rs (docs)}`, their callers in `crates/app-core/src/{migration.rs, setup.rs, app.rs, updates.rs}`, `crates/platform-mac/src/{update_installer.rs, system.rs}`, `app/src-tauri/src/platform.rs` (callers only; Task 12 moves them); create `app/src-tauri/tauri.macos.conf.json`, `app/src-tauri/tauri.windows.conf.json`; modify `app/src-tauri/tauri.conf.json`, `scripts/build-dmg.sh` (if it reads a moved key). Tests in `crates/core/tests/{store.rs, update.rs, mfa.rs}` and `app/src-tauri/tests/tauri_config.rs` (new; reads the JSON files only).

- [x] Core signatures:
  - `store::application_support_directory(home)` and `store::default_base_dir(home)` are removed; `ConnectionStore::default_base_dir(data_dir: &Path) -> PathBuf` (`data_dir/connections`); `store::remove_user_data(dir, expected_name: &str)`.
  - `UpdateChecker::parse_release(data, repo, asset: &str)` and `release_from_response(status, data, repo, asset_for: &dyn Fn(&str) -> Option<String>)`: the caller passes `|v| product.update_asset(v, ARCH)`; the `.sha256`/`.sig` names stay `<asset>.sha256`/`<asset>.sig`; `Release::dmg` is renamed `Release::package` (not serialized: checked).
  - `UserGuide::url(repo: Option<&str>, fallback_repo: &str, stem: &str, preferred)`; `app-core::app::user_guide_url` passes `MACVPN.repo` and `MACVPN.user_guide_stem` until Task 14 passes the selected product.
  - `mfa::AuthUIState::path(dir: &Path, id)` and `read(path, expected: &FileOwner)`; `DEFAULT_DIRECTORY` moves to `platform-mac::mvpn_client::UI_STATE_DIR` (same literal `/var/run/macvpn-ui`); the helper keeps its own `paths::UI_BASE`. A test in `crates/helper/tests/paths_agree.rs` reads `crates/platform-mac/src/mvpn_client.rs` as text and asserts both literals are equal (the two crates must not depend on each other).
  - Doc comments that name `~/Library/Application Support/MacVPN` say "the app's data directory (`Product::data_dir`)".
- [x] Until Task 12, the callers pass `macvpn_platform_api::MACVPN` and `home.join("Library/Application Support")`; the resulting paths are byte-identical (test).
- [x] Tauri config: `tauri.conf.json` keeps everything shared (and the macOS identity as the default: `productName`, `mainBinaryName`, `identifier`, the version, the windows, the CSP, the capabilities); `tauri.macos.conf.json` takes `app.macOSPrivateApi`, `bundle.targets ["app"]`, `bundle.icon` (with `icon.icns`) and `bundle.macOS`; `tauri.windows.conf.json`: `productName` and `mainBinaryName` `WinVPN`, `identifier` `local.winvpn`, `bundle.targets ["msi"]`, `bundle.icon` (`icons/32x32.png`, `icons/128x128.png`, `icons/icon.ico`; the `.ico` is added in Task 16), `bundle.windows { "webviewInstallMode": { "type": "downloadBootstrapper" } }` (phase 2 revisits it).
- [x] Tests:
  - `tauri_config.rs`: JSON merge patch (RFC 7396, implemented in the test, 20 lines) of base + `tauri.macos.conf.json` equals Task 1's `tauri-config.json` with the version normalized; base + windows has `productName` `WinVPN` and no `macOS` key; `scripts/build-dmg.sh`'s version checks still find the version in `tauri.conf.json`
  - `ConnectionStore::default_base_dir(&MACVPN.data_dir(&home.join("Library/Application Support")))` equals the 1.4.0 `default_base_dir(home)` (literal path in the test)
  - `parse_release` with Task 1's `release.json` and the MacVPN asset gives Task 1's `release-parsed.txt` (after the `dmg` → `package` rename in the expected text, done in this commit's first step together with the fixture's one-line change, reviewed as the only allowed fixture edit)
  - `remove_user_data` refuses a directory not named `expected_name`
  - `scripts/build-dmg.sh` + `scripts/bundle-baseline.sh`: no difference in `Info.plist.xml` and `tauri-config.json`
- [x] Commit: `refactor(core): product identity as parameters; per-OS Tauri config`.

## Task 11: helper – shared logic and the macOS backend

**Files:** in `crates/helper/`: create `src/lib.rs`, `src/shared/{mod.rs, cli.rs, mask.rs, framing.rs, respond.rs, status_json.rs, validate.rs, bridge.rs, l10n.rs, limits.rs}`, `src/macos/mod.rs` (the remaining modules moved under it: `ctx`, `exec`, `sys`, `paths`, `procs`, `run_dir`, `fsx`, `lock`, `log`, `openvpn`, `wireguard`, `strongswan`, `sstp`, `updown`, `hook_dns`, `testmode`, and the I/O halves of `status`, `respond`, `validate`, `mgmt_bridge`, plus `macos::main`), `src/windows/mod.rs`; `src/main.rs` becomes the selector; modify `Cargo.toml` (`[lib] name = "macvpn_helper"`, `libc` under `[target.'cfg(unix)'.dependencies]`), `scripts/test-root.sh` (source paths and the `hook_dns` test path), `scripts/check-l10n.sh` (unchanged filter `call_site`, check it still matches), `crates/app-core/tests/l10n_coverage.rs` (still scans `crates/helper/src` recursively: verify).

- [x] Shared (no `cfg`, no `unsafe`, no process or file I/O; compiled on every OS):
  - `cli` and `mask`: moved unchanged.
  - `framing` (was `secrets`' frame half): `Framed`, `FrameError`, `parse_framed`, `read_framed<R: Read>`, `Secrets` parsing; `SRC_MAX` and `STDIN_MAX` from `limits`; messages through `shared::l10n::tr` (was `ctx::tr`, same keys).
  - `respond::parse`; `status_json::render(states: &[StatusLine]) -> String` (the JSON half of `status::render`; `StatusLine` holds what `status::one` computes); `validate::run_framed(kind, framed, accept_risky) -> Result<(), Vec<ValidationIssue>>` (the dispatch over core's validators; the I/O half stays in `macos::validate`).
  - `bridge`: the management-bridge state machine as `Bridge<S: Read + Write>` with a `BridgeFiles` trait for its state/response files; `macos::mgmt_bridge` supplies the `UnixStream` and the file implementation (the root-owned directories and `O_NOFOLLOW` reads, unchanged).
- [x] `src/main.rs`: `#[cfg(target_os = "macos")] fn main() { std::process::exit(macvpn_helper::macos::main()) }`, `#[cfg(windows)] fn main() { std::process::exit(macvpn_helper::windows::main()) }`, and a `#[cfg(not(any(…)))]` `main` that does the same as Windows (Linux is phase 4). `windows::main` prints `tr("Not available on this system yet")` to stderr and returns 1. The `argv[0] == "mvpn-mgmt"` dispatch stays in `macos::main`.
- [x] The macOS backend keeps every behaviour: the usage text, the exit codes, the log lines, the environment allowlists, the `MVPN_*` test-mode hooks (non-root only), VERSION 8.
- [x] Tests:
  - every existing unit test, moved with its module (the module paths in `scripts/test-root.sh` updated: `macos::hook_dns::tests::backup_lines_never_glob`)
  - shared: `parse_framed` corpus (moved), `respond::parse` corpus (moved), `status_json::render` of three fixed `StatusLine`s equals the string 1.4.0's `status::render` printed for the same state (captured into the test in this task's first commit), `Bridge` over an in-memory duplex stream: the CRV1, static-challenge and web-auth exchanges of the existing tests
  - `scripts/test-root.sh` passes, including the usage/version byte checks of Task 1
  - `cargo check -p macvpn-helper --target x86_64-pc-windows-msvc` passes (with the target installed; otherwise Task 16 covers it)
- [x] Commit: `refactor(helper): shared protocol logic and a macOS backend`.

## Task 12: platform-mac – implements platform-api

**Files:** modify `crates/platform-mac/Cargo.toml` (depend on `macvpn-platform-api`; every macOS-only dependency — `block2`, `core-foundation`, `core-foundation-sys`, `objc2*`, `oslog`, `security-framework-sys`, `plist` — moves to `[target.'cfg(target_os = "macos")'.dependencies]`), `crates/platform-mac/src/lib.rs` (`#![cfg(target_os = "macos")]` at the top, `pub mod api;`), create `crates/platform-mac/src/api.rs` (and `api/` submodules if it grows past ~600 lines), modify `setup_checker.rs` (`SetupReport` from platform-api), `control_socket.rs`, `native_vpn.rs`, `mvpn_client.rs`, `login_item.rs`, `update_installer.rs`; every file under `crates/platform-mac/tests/` gets `#![cfg(target_os = "macos")]`. Move out of `app/src-tauri/src/platform.rs`: `Root`, `Native`, `Keychain`, `SharedKeychain`, `ProfileFiles`, `open_file`/`open_path`, `open_profiles_settings`, `copy_to_pasteboard`, `LogStreams`, `AuthStateFiles`, `Preferences`, `GitHubReleases`, `SandboxLoginItem`, `login_items`, `login_item_view`, `open_github_url`, and the control `Transport` of `app/src-tauri/src/control.rs`. Until Task 14 switches the app to `MacPlatform`, the app's `platform.rs` and `control.rs` import these from `macvpn_platform_mac::api` (thin `pub use`), so the app builds and behaves the same after this task.

- [x] `pub struct MacPlatform { sandbox: bool, … }`, `MacPlatform::new(sandbox: bool)`, `impl Platform for MacPlatform`; each accessor wraps the existing code (no behaviour change): `product()` → `&MACVPN`; `install_core_hooks()` = today's `install_core_hooks()` + `l10n::set_text_platform(MACVPN.text_platform())`; `system()` over `system.rs` + `temp_dir.rs`; `setup()` over `setup_checker`, `brew`, `root_installer`; `updater()` over `update_installer::install_update` (the DMG steps stay private to platform-mac; `UpdateSteps` stays a platform-mac trait used by its tests and the smoke run); `windows()` over `window_fit`, `window_shape`, `app_hooks::order_front_regardless`; `file_panels()` over `dialogs`; `notifier()` over `notifications`; `clipboard()` over `pasteboard`; `lifecycle()` over `app_hooks`; `download_mark()` over `quarantine`; `system_vpn_watch()` over `sc_watch`; `control_transport()` = Task 5's Unix implementation (moved from the app); `helper_client()` = `Root` (the three runners); `native_profiles(staging, open)` = `ProfileFiles` + `build` via `mobileconfig::generate`; `auth_state()` = `AuthStateFiles` with `UI_STATE_DIR` and the user's `FileOwner`; `log_streams()` = `LogStreams` (with `command_line()` from Task 8); `release_source()` = `GitHubReleases` with `release_from_response(…, &|v| MACVPN.update_asset(v, std::env::consts::ARCH))`; `https_catalog_fetcher()` = `CurlCatalogFetcher::default()`; `key_store()`/`legacy_keychain()`/`preferences()` honour `sandbox` exactly as `main.rs::storage` and `build_state` do today (memory stores in the sandbox); `login_items(…)` = today's `login_items(env)`; `SmokeHooks` over `app_hooks::force_appearance`, `window_shape::{shape, number}`, `activation_policy_is_regular`.
- [x] platform-mac switches to platform-api's `SetupReport` (defined in Task 9) and deletes its own; `brew_prefix` → `package_manager` (the checker fills it with the Homebrew prefix exactly as before); the app's uses (`state.rs::setup_facts`, the `control.rs` tests) are updated in this task.
- [x] Tests:
  - the moved app tests (`bundle_detection`, `keychain_fields_map_to_the_platform_store`) now in `crates/platform-mac/tests/api.rs`
  - `MacPlatform::new(true)`: `key_store()` is a memory store, `preferences()` is memory, `login_items(…).set_enabled(true)` fails with the sandbox message; `new(false)`: `release_source()` refuses a release without the MacVPN DMG asset (fake HTTP client through the existing `HttpClient` seam)
  - `native_profiles(…).build(l2tp)` equals `mobileconfig::generate` (from Task 8)
  - every existing platform-mac test passes (CI=1 skips the real Keychain tests as before)
- [x] Commit: `refactor(platform-mac): implement platform-api`.

## Task 13: platform-win – the stub platform

**Files:** create `crates/platform-win/{Cargo.toml, src/lib.rs, tests/stub.rs}`; modify `Cargo.toml` (member).

- [x] `macvpn-platform-win`, depends on `macvpn-core` (with `vault`) and `macvpn-platform-api` only; compiles on every OS (no `cfg`, no `unsafe`, no `windows-sys` in phase 1), so the macOS clippy and tests cover it.
- [x] `pub struct WinPlatform`, `impl Platform for WinPlatform`: `product()` → `&WINVPN`; `install_core_hooks()` sets only the text platform; every fallible call returns `PlatformError::Unsupported { what }` (`what` names the facility, e.g. `"native VPN"`); infallible calls are inert (`is_marked` → `false`, `round_corners` → `false`, `fit_viewport` → `None`, `post` does nothing, `observe_wake` stores nothing); `helper_client()`/`native_controller()` return objects whose every method returns the localized unsupported message; `key_store()` returns a store whose `load` gives `Ok(None)` and whose `store` fails (fail closed: no auto-unlock); `entropy()` fails (`io::ErrorKind::Unsupported`), so no vault can be created by mistake; `preferences()` is an in-memory store; `control_transport().bind` fails `Unsupported`; `https_catalog_fetcher()` fails every fetch with the unsupported message.
- [x] Tests: every `Platform` accessor is called once and either returns the documented inert value or `Unsupported` (one test per trait); `entropy().fill` fails; `key_store().store` fails; `product().name == "WinVPN"`; no method panics.
- [x] Commit: `feat(platform-win): the stub Windows platform`.

## Task 14: app – the platform module and the first half of the call sites

**Files:** create `app/src-tauri/src/platform/{mod.rs, macos.rs, windows.rs, environment.rs}`; delete `app/src-tauri/src/platform.rs` (its remaining content moves into `environment.rs`); `git mv app/src-tauri/src/smoke.rs app/src-tauri/src/platform/smoke.rs` (declared in `platform/mod.rs` as `#[cfg(all(debug_assertions, target_os = "macos"))] pub mod smoke;`, with facade functions `platform::smoke_*` — `fake_root`, `fake_native`, `setup_report`, `seed_legacy_keychain`, `start`, `update_install` — that forward to it on macOS and return `None`/do nothing elsewhere; every `#[cfg(debug_assertions)] smoke::…` call in the app becomes a `#[cfg(debug_assertions)] platform::smoke_…` call); modify `app/src-tauri/Cargo.toml` (`macvpn-platform-api`; `[target.'cfg(target_os = "macos")'.dependencies] macvpn-platform-mac`; `[target.'cfg(windows)'.dependencies] macvpn-platform-win`), `main.rs`, `state.rs`, `system.rs`, `update_window.rs`, `control.rs`, `manage.rs`, `catalog.rs`, `backup.rs`, `dock.rs`.

- [x] `platform/mod.rs` — the only `cfg(target_os)` of the app:
  ```rust
  #[cfg(target_os = "macos")] mod macos;   #[cfg(target_os = "macos")] use macos as selected;
  #[cfg(not(target_os = "macos"))] mod windows; #[cfg(not(target_os = "macos"))] use windows as selected;
  mod environment; pub use environment::Environment;
  /// Created once in `main` (sandbox decided by `Environment::detect`).
  pub fn init(sandbox: bool) -> &'static dyn Platform;
  pub fn get() -> &'static dyn Platform;                      // after init
  pub fn native_window(w: &tauri::WebviewWindow) -> Option<NativeWindow>;   // ns_window() / hwnd()
  pub fn configure_app(app: &mut tauri::App);                 // macOS: ActivationPolicy::Accessory
  pub fn set_window_presence(app: &AppHandle, shown: bool);   // macOS: Regular / Accessory (dock.rs's apply)
  pub fn on_run_event(app: &AppHandle, event: &tauri::RunEvent); // macOS: Reopen → dock::reopen, Opened → open_files::opened
  pub fn supported() -> Result<(), String>;                   // macOS: Ok; Windows: Err("WinVPN is not available yet") → main exits 1
  ```
  `macos.rs` creates `MacPlatform`; `windows.rs` creates `WinPlatform` and implements the Tauri glue as no-ops (`hwnd()` for `native_window`).
- [x] `Environment` (`environment.rs`): the same fields and rules (`MACVPN_SANDBOX_HOME`, debug only), built from `platform::get().system()` and `product()`: `application_support()` → `product.data_dir(system.app_data_root(&home))`; `connections_dir()` → `ConnectionStore::default_base_dir(&application_support())`; `staging_parent`, `bundled_root_dir`, `update_source`, `repo` as today through the traits.
- [x] `main.rs`: `platform::supported()` first; `platform::init(env.sandbox)`; `install_core_hooks` through the platform; `storage()` and `build_state()` take their key store, entropy, legacy keychain, legacy secrets (`LegacySecretReader`), the one-time `migrate_legacy_service`, helper client, native controller, preferences, release source, profiles, log streams, auth state and the system VPN watcher from the platform (the sandbox's shared memory keychain is a platform-mac detail of `MacPlatform::new(true)`); the activation policy and the two `RunEvent` arms go through `configure_app` and `on_run_event`; `dock.rs`'s `apply` calls `platform::set_window_presence`. `state.rs`, `system.rs`, `update_window.rs`, `control.rs` (the `Transport` struct is deleted: `platform::get().control_transport()`), `manage.rs` (`MvpnClient::log_path` → `HelperClient::log_path(&self, id: &Uuid) -> Option<PathBuf>`, a default method returning `None` added to the trait in this task; platform-mac returns today's path), `update_window.rs` (`Updater::install` / `launch_housekeeping`; the sandbox branch calls `platform::smoke_update_install`), `catalog.rs`, `backup.rs` (`local_date`) use only platform-api.
- [x] Tests:
  - `grep -rn 'macvpn_platform_mac' app/src-tauri/src --include=*.rs` lists only `platform/macos.rs`, `platform/smoke.rs` and the second-half files of Task 15
  - the app crate's unit tests; Task 1's fixtures; `SMOKE_LANG=en scripts/smoke-manage.sh` and `SMOKE_LANG=hu scripts/smoke-manage.sh` pass
- [x] Commit: `refactor(app): one platform module; launch, state, system, updates, control on platform-api`.

## Task 15: app – the second half of the call sites and the UI's platform

**Files:** modify `app/src-tauri/src/{notifications.rs, clipboard.rs, dialogs.rs, fit.rs, tray.rs, prompts.rs, pairing.rs, credentials.rs, vault.rs, commands.rs, open_files.rs}`; `app/src-tauri/build.rs` (command `get_platform`), every file in `app/src-tauri/capabilities/` (`allow-get-platform`), `app/ui/src/lib/api.ts`, `app/ui/src/main.ts`.

- [x] Window code passes `platform::native_window(&w)` to `WindowChrome`/`FilePanels`; `clipboard.rs`'s `Board` trait is replaced by `SecretClipboard`; notifications, the terminate reply (`commands.rs`), `order_front_regardless` (credentials, pairing, prompts, vault) and the download mark (`open_files.rs`) go through the platform; `prompts.rs`'s `ProcessCommandRunner` use becomes `Shell::open_url`/`open_path` (whichever it is today: keep the exact executable and arguments inside platform-mac).
- [x] `get_platform` (read-only, no input): returns `PlatformView { os: "macos", product_name: "MacVPN" }` (`#[serde(rename_all = "camelCase")]`) from `platform::get().product()`. Added to `COMMANDS` and to every capability file whose window calls `tr()` (all seven). `main.ts` awaits it before mounting and calls `setPlatform`; on an error it keeps the macOS default.
- [x] Tests:
  - `grep -rn 'macvpn_platform_mac' app/src-tauri/src` lists only `platform/macos.rs` and `platform/smoke.rs`
  - the capability test (each window's capability grants exactly its commands) includes `allow-get-platform`
  - UI: `api.test`/`l10n.test` for `setPlatform` from a `get_platform` reply; a reply with an unknown `os` keeps `macos`
  - Task 1's `view-model.json` unchanged (the platform is not in the view model)
  - smoke EN/HU pass; `scripts/l10n-baseline.mjs --check` passes
- [x] Commit: `refactor(app): every platform call through platform-api; the UI learns its platform`.

## Task 16: Windows – the whole workspace compiles for both Windows targets

**Files:** `rust-toolchain.toml` (targets), `crates/core/Cargo.toml` (Windows rusqlite per Task 2 B, the updated comment), `Cargo.lock`, `scripts/third-party-notices.mjs`, `app/src-tauri/icons/icon.ico` (generated from `icon.png` with `npx tauri icon` into a temp directory; only the `.ico` is committed), `examples/macvpn-control-client/src/{lib.rs, main.rs}`, test files that use Unix-only APIs, new `scripts/check-windows.sh`, new `crates/app-core/tests/cfg_rule.rs`.

- [x] `rust-toolchain.toml`: `targets = ["aarch64-apple-darwin", "x86_64-apple-darwin", "x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc"]`.
- [x] Dependencies that need per-OS care (each moved to a target table, none removed): core `libc` → `cfg(unix)` (Task 4); core `rusqlite` → `bundled-sqlcipher` on macOS, `bundled-sqlcipher-vendored-openssl` on Windows (Task 2 B), nothing on Linux yet; platform-mac's `block2`, `core-foundation*`, `objc2*`, `oslog`, `security-framework-sys`, `plist` → `cfg(target_os = "macos")` (Task 12); helper `libc` → `cfg(unix)` (Task 11); app `macvpn-platform-mac` / `macvpn-platform-win` per target (Task 14); `tauri`'s `macos-private-api` stays off (it is off today); the dev-dependency `plist` of core is portable (pure Rust) and stays.
- [x] Fix every Windows compile error found by `scripts/check-windows.sh` (Task 2's to-do lists): only by moving code behind `fsx`, the platform module, the helper backends or the platform crates — never by a new `cfg` elsewhere in production code.
- [x] Tests that use `std::os::unix`, `libc` or Unix paths: `#[cfg(unix)]` on the test function or, for a file that is Unix-only as a whole (`crates/platform-mac/tests/*` already done in Task 12, `crates/app-core/tests/control_example_client.rs`, `crates/core/tests/vault_db.rs`'s macOS test), `#![cfg(unix)]` at the top.
- [x] `examples/macvpn-control-client`: its Unix-socket transport under `#[cfg(unix)]`; on Windows `Client::connect` returns `io::ErrorKind::Unsupported` ("the named pipe client comes with WinVPN"). The README notes it.
- [x] `scripts/check-windows.sh` (per Task 2 A): installs nothing; checks `rustup target list --installed`; runs the always-on `cargo check --locked --target <t> -p …` list for both targets, with `--all-targets`, also with `--release`; then says that the vault, platform-api, platform-win, app-core and the app are checked by CI (windows-latest); no `cargo xwin` branch (Task 2 A); exits non-zero on any failure.
- [x] `scripts/third-party-notices.mjs` (Task 2 B): the crate set per macOS target comes from `cargo tree --locked -e normal --target <t> -p macvpn-app -p mvpn --prefix none -f '{p}'` (resolver 3 per-target features), `cargo metadata` only for licences and paths; the committed notices file does not change. *(Done differently: the `cargo tree` set is 19 crates smaller than the committed file, which lists what `cargo metadata`'s cross-target feature unification adds (`chrono`, `schemars`, …, none of them linked). To keep the file unchanged, the script keeps the `cargo metadata` walk and drops the crates that only the Windows targets' `cargo tree` has (`openssl-sys`). Whether to shrink the file to the `cargo tree` set is left to the maintainer.)*
- [x] `cfg_rule.rs`: scans `crates/*/src` and `app/src-tauri/src` for `cfg(target_os`, `cfg(unix`, `cfg(windows`, `cfg(not(unix`, `cfg(not(windows`, `cfg(any(` / `cfg(all(` containing one of them, and `cfg!(`/`target_os =` in code; allowed only in `crates/core/src/fsx/`, `crates/platform-mac/`, `crates/platform-win/`, `crates/helper/src/macos/`, `crates/helper/src/windows/`, `crates/helper/src/main.rs`, `app/src-tauri/src/platform/`. It also asserts `unsafe` appears only in `crates/platform-mac`, `crates/platform-win`, `crates/helper`.
- [x] Tests / checks:
  - `scripts/check-windows.sh` passes on the maintainer's Mac (the always-on part at least)
  - `cargo tree --locked --target aarch64-apple-darwin -i openssl-sys` and `--target x86_64-apple-darwin` print nothing; `node scripts/third-party-notices.mjs --check` passes
  - `cfg_rule.rs` passes and fails on a planted `#[cfg(target_os = "macos")]` in `crates/app-core/src/lib.rs` (try it locally, do not commit it)
  - all macOS checks of the rules block; `scripts/build-dmg.sh` release gate (no OpenSSL in the app)
- [x] Commit: `build: the workspace compiles for Windows x64 and ARM64`.

## Task 17: CI – a Windows job

**Files:** `.github/workflows/ci.yml`, `.github/workflows/release.yml` (toolchain targets only); the test files that fail on the first Windows run because they create private files or a vault (the `cfg_attr` below).

- [x] New job `windows` on `windows-latest`, `defaults.run.shell: bash` (Git Bash on the image), `permissions` inherited (`contents: read`):
  ```yaml
  windows:
    runs-on: windows-latest
    defaults:
      run:
        shell: bash
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - name: Rust toolchain (both Windows targets)
        run: |
          RUST_VERSION=$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml)
          [[ "$RUST_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "rust-toolchain.toml: channel must be an exact version"; exit 1; }
          rustup toolchain install "$RUST_VERSION" --profile minimal -c clippy,rustfmt -t x86_64-pc-windows-msvc,aarch64-pc-windows-msvc
          [ "$(rustc --version | cut -d' ' -f2)" = "$RUST_VERSION" ] || { echo "rustc is not $RUST_VERSION"; exit 1; }
      - name: cargo fmt
        run: cargo fmt --all --check
      - name: cargo clippy (x64)
        run: cargo clippy --workspace --all-targets --locked --target x86_64-pc-windows-msvc -- -D warnings
      - name: cargo check (ARM64, debug and release)
        run: |
          cargo check --workspace --all-targets --locked --target aarch64-pc-windows-msvc
          cargo check --workspace --all-targets --locked --release --target aarch64-pc-windows-msvc
      - name: cargo test (platform-independent crates)
        run: CI=1 cargo test --locked --target x86_64-pc-windows-msvc -p macvpn-core -p macvpn-app-core -p macvpn-platform-api -p macvpn-platform-win -p macvpn-helper --lib --tests
  windows-node:
    runs-on: windows-latest
    defaults:
      run:
        shell: bash
        working-directory: app/ui
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0
        with:
          node-version: "26.8.2"
          package-manager-cache: false
      - run: npm ci --no-audit --no-fund
      - run: npm test
  ```
  - Per Task 2: a `git config --global core.autocrlf false` step before the checkout (a CRLF checkout breaks the toolchain `sed` and the byte-compared fixtures); `env: OPENSSL_SRC_PERL: C:\Strawberry\perl\bin\perl.exe` on the job unless the probe showed Git Bash's Perl works.
  - Per Task 2 C, a `choco install nasm --no-progress` step before clippy if needed. Per Task 2 B fallback, the test step drops `-p macvpn-app-core` and the vault tests, and the plan's resolved point is updated.
  - The Windows test run uses a `#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]` on every test that creates a private file or a vault (they fail closed by design, Task 4); a step prints the count of ignored tests (`cargo test … -- --list --ignored | grep -c ': test'`) so phase 2 can drive it to zero.
  - *(Done: the `core.autocrlf false` step comes first in both Windows jobs (in `windows-node` with `working-directory: .`, since `app/ui` does not exist before the checkout); `OPENSSL_SRC_PERL` is set on the `windows` job, because the probe has not run yet and the spike expects Git Bash's MSYS Perl to be refused; no NASM step (Decision C: `openssl-src` configures `no-asm` without it). The ignored-test count step lists into `$RUNNER_TEMP` and tolerates zero; it also counts the tests ignored on every OS (`write_compat_fixtures` and the other plain `#[ignore]`s). The tests to ignore were found by running the five crates on macOS with core's `fsx/unix.rs` temporarily answering like `fsx/windows.rs` (private files, private directories, owners, `has_access(Private)`, `file_id`, `hard_links`): 542 attributes (core 181, app-core 361, of which 44 are entries of the `over_both!` list in `control_server.rs`, so they apply to the loopback tests on Windows); platform-api, platform-win and the helper need none. A second run with the importer's path resolution failing as it will on Windows (`importer::read_inline_data` joins and prefix-checks `/`-separated strings, so no referenced file is ever inlined on a `\\?\C:\…` path) gave 24 more in `crates/core/tests/importer.rs`, ignored with "the importer resolves file paths as Unix strings: phase 2" (a phase 2 importer fix, not an ACL one). A third run with `TargetOs::host()` answering Windows changed nothing but `host_is_the_compile_target`. Three tests that are Unix by nature became `#[cfg(unix)]`: platform-api `macvpn_paths_are_the_1_4_0_paths` (byte paths), core `shred_file_refuses_a_directory_and_a_fifo` (`/usr/bin/mkfifo`) and `sign_release_uses_the_embedded_keys` (`/bin/bash`). The macOS test counts are unchanged.)*
- [x] The macOS jobs (`rust`, `node`, `dmg`) are unchanged except that the toolchain steps of `rust` and `dmg`, and of `.github/workflows/release.yml`, pass all four targets in `-t`: rustup installs the targets listed in `rust-toolchain.toml` anyway (Task 2), so the download happens in the toolchain step.
- [x] Check: push the branch; the four jobs are green; the Windows job time is recorded in the PR description. Done 2026-10-21 on a temporary, squashed `ci/windows` branch (approved once by the maintainer; branch and runs deleted afterwards; no PR). Three rounds: (1) Windows clippy x64 and ARM64 check (vendored OpenSSL + SQLCipher C builds) passed at once; tests failed in `open_files` (`/s/…` is not absolute on Windows) and the UI clipboard rule (`\\` separators); (2) one failure: a server close reaches a Windows TCP client as `ConnectionAborted` (WSAECONNABORTED), now accepted by `expect_closed`; (3) all five jobs green. Times of the green run: `windows` 35 min (no cache), `windows-node` 38 s, `rust` 7 min, `dmg` 15 min, `node` 33 s. Ignored tests on Windows: 567 (incl. the few ignored on every OS); phase 2 drives the private-file ones to zero. The Windows test step runs with `--no-fail-fast`.
- [x] Commit: `ci: a Windows job (check, clippy, platform-independent tests, UI tests)`.

## Task 18: version 1.5.0 and the developer documentation

**Files:** `app/src-tauri/tauri.conf.json`, `Cargo.toml` (`[workspace.package] version = "1.5.0"`), `Cargo.lock`, `app/ui/package.json`, `app/ui/package-lock.json`, `README.md` (EN/HU Development sections, "What's new in 1.5" / „Újdonságok az 1.5-ben”), `app/README.md`, new `docs/architecture.md`, `docs/RELEASING.md`, `crates/core/src/l10n.rs` (no change; the `comment` field of `strings.json` documents `only` and `variants`).

- [x] Version 1.5.0 in the three places (`cargo check` updates `Cargo.lock`, `npm install --package-lock-only` the UI lock). `crates/helper/VERSION` stays 8.
- [x] `docs/architecture.md` (English): the crate graph (a text diagram as in spec 3), what lives where (core, fsx, platform-api, platform-mac, platform-win, helper shared/macos/windows, app-core, the app's platform module, the UI), the `cfg` and `unsafe` rules and their tests, `Product` and the per-OS Tauri config, the l10n variant rules (`only`, `variants`, the product-name substitution, the glossary of Task 6), the control transport, how to add a platform (the checklist phase 2 follows), the Windows checks (`scripts/check-windows.sh`, CI).
- [x] `README.md` Development (EN/HU) and `app/README.md`: the new crate paths, `scripts/check-windows.sh`, the note that the full Windows check is CI-only (Task 2).
- [x] `docs/RELEASING.md`: `crates/helper/VERSION`; the release checklist gains: CI Windows job green, `scripts/check-windows.sh`, `scripts/bundle-baseline.sh` compared with the previous release, `scripts/l10n-baseline.mjs --check` (macOS texts unchanged unless a release says so). The release notes of 1.5.0: "internal restructuring for WinVPN; no change for MacVPN users; root layer unchanged (no Authorize needed)".
- [x] `README.md` "What's new in 1.5" (EN/HU): one line each ("Under the hood: prepared for a Windows version; MacVPN works exactly as before.").
- [x] Commit: `docs: 1.5.0, architecture and developer notes`. *(Also, at the maintainer's request: the `1.5.0` section of `docs/manual-test-checklist.md` (smoke EN/HU, the update from 1.4.1 without an admin password, the bundle and l10n baselines); Task 19 extends it with the full manual list.)*

## Task 19: verification against 1.4.0

**Files:** `docs/manual-test-checklist.md` (Hungarian, a 1.5.0 section).

- [x] Automated, on the merged branch:
  - every check of the rules block, `scripts/test-root.sh`, `scripts/check-windows.sh`, `scripts/check-l10n.sh`, `scripts/l10n-baseline.mjs --check`
  - Task 1's fixtures (no fixture file changed since Task 1 except the one `release-parsed.txt` line of Task 10: `git diff <task-1-commit> -- crates/app-core/tests/fixtures/compat-1.4.0` shows only that)
  - `scripts/build-dmg.sh`, then `scripts/bundle-baseline.sh dist/MacVPN.app`: `Info.plist.xml`, `tauri-config.json`, `entitlements.txt` identical; `bundle-files.txt` identical in names; `otool-L.txt` identical (no new framework or dylib linked)
  - `SMOKE_LANG=en` and `SMOKE_LANG=hu scripts/smoke-manage.sh`, including the catalog mode
  - `cargo tree --locked --target aarch64-apple-darwin -e normal -p macvpn-app` compared with 1.4.0's: the only new packages are `macvpn-platform-api` (and `macvpn-helper` for the root binary's tree)
- [x] Manual (1.5.0 section of the checklist, on a Mac with 1.4.0 installed and a real vault): install the 1.5.0 DMG over 1.4.0 through the updater (a locally signed test release, as for 1.4.0); the vault opens with auto-unlock (same Keychain item); every connection type connects (the root layer is not reinstalled: System Status shows root 8 current); a system VPN starts and stops; the live list follows a change in System Settings; notifications, the tray popover, Cmd+S / Cmd+F, Option-click debug mode; a backup made by 1.4.0 restores in 1.5.0 and a backup made by 1.5.0 restores in 1.4.0; a 1.4.0 team catalog refreshes; the control-API example client pairs and holds a lease; Finder "Open With" for `.ovpn`, `.sstp`, `.conf`, `.macvpncatalog`; launch at login; Uninstall (with and without user data) in a test account.
- [x] Commit: `docs: 1.5.0 manual checklist`.

## Task 20: independent review

- [x] A reviewer who did not write the code reviews the whole branch against spec 3, 5, 6, 7, 9 (phase 1) and this plan's rules, at least:
  - **No behaviour change:** the fsx mapping table of Task 4 against the diff (flags, order of checks, error kinds, modes, what follows a symlink); the control transport (same-user check, peer identity, the `peer_connected` peek, every audit line's text, the accept poll); the helper (usage, exit codes, environment allowlists, test-mode gating on euid, VERSION 8, `test-root.sh`); the l10n baseline; Task 1's fixtures; the bundle baseline
  - **Fail closed on Windows:** `fsx` private files, `WinPlatform`'s key store, entropy, control transport and fetchers; the app's `platform::supported()` gate; the helper's Windows `main`
  - **Rules:** the `cfg` and `unsafe` scan (`cfg_rule.rs`) and its allow-list; no `unsafe` moved into core, app-core, platform-api or the app; `NativeWindow` pointers are never dereferenced outside platform crates
  - **Secrets:** no new log line, argv or env value carries a secret; the moved code keeps zeroization (`Zeroizing` in `NativeProfile`, the framing, the clipboard)
  - **Dependencies:** openssl only for Windows targets; no new crate in the macOS binaries; the notices check
  - **IPC:** `get_platform` takes no input and returns no secret; its capability entries
  - **The Windows OpenVPN tier draft** (Task 3) is marked as a draft for the phase 2 review and inactive on macOS
- [x] Fix until approved; each fix with a test. Verdict: **approve after fixes; no macOS behaviour change found.** Fixed: M1 (docs: the update signature binds the bytes, not the product or asset name; corrected here, in `docs/architecture.md` and the spec, with the phase 2 blocker recorded), L1 (`cfg_rule.rs`: `br"…"`/`cr"…"` raw strings, `target_env`, `cfg($…)`, `#[path]`, `include!`, a lowered `unsafe_code` lint; one self-test each), L2 (Windows `fsx::hard_links` is `u64::MAX`, so `shred_file` only unlinks), L3 (`ControlTransport::prepare_dir` is required; a `compile_fail` doctest), L4 (docs: the importer's Windows path issue in "Adding a platform" and the spec). Phase 2 items: M1's code fix (a WinVPN signature domain with the asset name, before the first signed WinVPN asset), the real Windows link count and owner checks behind `hard_links` / `prepare_dir` (L2/L3 follow-ups), the importer's Windows paths (L4).
- [x] Commit(s): `fix: review findings` (as many as needed).

## Task 21: release 1.5.0

- [x] Everything green: the rules block, CI (all jobs), Task 19's automated list on the final commit.
- [x] `scripts/build-dmg.sh` with the release gate; the user tests the DMG (Task 19's manual list).
- [x] Release: the same flow as 1.4.0 (`docs/RELEASING.md`: the `public` sync commit, the `main` push, CI, the `v1.5.0` tag, the draft check against a local build, the offline signing by the user). Only `MacVPN-1.5.0.dmg` (+ `.sha256`, `.sig`) is published; no Windows asset. The release notes say there is no visible change and no Authorize step.
  *(Released 2026-10-21: main `5cd5189` (CI all five jobs green, incl. the Windows jobs), tag `v1.5.0`, the draft DMG compared with the local build, signed by the maintainer and the signature verified against the primary key. The maintainer tested the DMG over 1.4.1.)*

---

## Spec coverage (self-review)

| Spec | Requirement | Task |
|---|---|---|
| 3 | `core`: Unix-only file operations behind `fsx` (Unix now; Windows reparse-point handling, ACLs fail closed until phase 2) | 4 |
| 3 | `app-core`: the control-API transport becomes a trait; neutral names (`SystemService` → `SystemVpn`, mobileconfig → native profile) | 5, 8 |
| 3 | `platform-api`: key store, notifications, tray/popover, file panels, native VPN, helper client, login item, updater, clipboard, download mark, setup/dependency checker, product identity and paths | 9 |
| 3 | `platform-mac` implements platform-api | 12 |
| 3 | `platform-win` implements platform-api (phase 1: stub) | 13 |
| 3 | `helper`: renamed crate, binary name and install path kept; shared CLI/protocol, framing, masking, validation, locks, management bridge; `macos` backend | 7, 11 |
| 3 | `app/src-tauri`: one `platform` module chooses the crate; the rest uses platform-api | 14, 15 |
| 3 | `app/ui`: OS-specific wording from per-OS l10n variants | 6, 15 |
| 3 | Product identity: name, app id, icons, data directory, update asset name, help URLs; per-OS Tauri config files; `Product` in platform-api | 9, 10, 14, 16 (icon) |
| 3 | `cfg(target_os)` only in the platform selection, `fsx`, platform and helper backends | 16 (`cfg_rule.rs`), 20 |
| 5 | Data formats the same on every OS | 1, 8, 19 |
| 5 | `REASON_PLATFORM` per OS | 3 |
| 6 | Platform flags for the UI; primary modifier Cmd/Ctrl | 6 (`keys.ts`), 15 (`get_platform`) |
| 6 | System font stack per OS | (phase 2: the macOS stack is unchanged; see "Resolved points") |
| 7 | `rust-toolchain.toml` Windows targets | 16 |
| 7 | SQLCipher on Windows with vendored OpenSSL; provider gate | 2, 16 (macOS gate unchanged; the Windows gate is phase 2's `build-msi.ps1`) |
| 7 | CI `windows-latest` job; macOS jobs unchanged | 17 |
| 8 | Unit tests on all OSes in CI; helper tests split into shared and backend cases | 11, 17 |
| 9 | Phase 1: release 1.5.0, macOS only, behaviour unchanged, every test green, Windows `cargo check` with a stub | 1, 16, 19, 21 |

---

## Resolved points (ambiguities and how this plan settles them)

- **Where the existing traits go.** Traits a platform implements move to platform-api and are re-exported from their old app-core paths (no churn in callers and tests). Traits the app implements over its own state (`ControlHost`, `RegistryStore`, `PreferencePort`, `UninstallSystem`, `TrackedPrompt`, the stores) stay in app-core. Core's own traits (`KeyStore`, `Entropy`, `LegacyKeychain`, `CatalogFetcher`) stay in core, because core's vault and catalog code call them; platform-api re-exports them.
- **One `Platform` handle.** The app reaches every platform service through `&'static dyn Platform` from its `platform` module, created once in `main`. Free functions in platform-mac stay as the implementation, wrapped by `MacPlatform`. Tauri-specific glue (the activation policy, `RunEvent::Reopen`/`Opened`, `ns_window`/`hwnd`) stays in the app's platform module, because platform-api does not depend on Tauri.
- **`TargetOs` without `cfg`.** `TargetOs::host()` reads `std::env::consts::OS`, a compile-time constant, so core needs no `cfg` attribute for it. The validator uses the host directly (security rules must not depend on a launch-time setting). The l10n platform is installed at launch, with the macOS default, because the product name is identity, not a property of the compile target.
- **The Windows OpenVPN tier.** Phase 1 ships only the macOS tier, unchanged. The Windows and Linux tables exist so that the mechanism is tested; they are drafts for the phase 2 security review. `cryptoapicert` becomes a checked, allowed directive on Windows; the service-owned Windows directives need an acknowledgement; `setcon` is refused on Windows.
- **The `cfg` rule's scope.** It applies to production code. Tests may use `#[cfg(unix)]` for Unix-only assertions. Cargo manifests use target-specific dependency tables. The helper's `main.rs` selects its backend with `cfg`. `examples/macvpn-control-client` is a client template for other apps, outside the rule; its Unix transport is `#[cfg(unix)]` and its Windows client comes with phase 2. `#[cfg(debug_assertions)]` is not an OS `cfg`.
- **`fsx` on Windows in phase 1.** Opening without following reparse points, atomic replace and the "unavailable" errors are real. Anything that needs an owner check or an owner-only ACL fails closed with `Unsupported`, because core may not contain `unsafe` and stable std has no ACL API. Phase 2 adds the ACL and owner implementation through the platform layer. Tests that need private files are ignored on Windows and counted in CI. The helper keeps its own root-side `fsx` in its macOS backend: it handles root-owned paths with explicit modes, a different job.
- **`file_id` on Windows.** Stable std has no file index, so `file_id` is `None` on Windows. The exporter's post-rename identity check therefore fails closed on Windows until phase 2.
- **Control transport shape.** The listener identifies the peer at accept time (`Accepted::Client { stream, peer }`), so a platform with a different identity model (a named pipe and a token SID) needs no stream downcast. `PeerUser::Uid(n)` displays as `uid n`, so every audit line keeps its 1.4.0 text. The app-core suite also runs over a TCP loopback test transport, so it runs on Windows CI.
- **Per-OS l10n.** The key stays the macOS English text, so no call site changes and the macOS output is byte-identical (`scripts/l10n-baseline.mjs`). `variants.<os>` carries both languages; `only` marks texts that only one OS's code paths show. "MacVPN" is replaced by the product name on other OSes, except in `only: ["macos"]` texts. Hungarian suffixes stay valid because both names end in "VPN". The UI learns the OS and product from `get_platform`, a new read-only command, so the view-model JSON stays byte-identical.
- **Which macOS texts get a Windows variant now.** Shared features whose wording names a macOS facility get one, using the Task 6 glossary. macOS-only flows (Homebrew, the root layer and sudoers, profiles and Device Management, LaunchAgent, Gatekeeper, the 1.1 migration, the macOS backend's messages) are marked `only: ["macos"]`. Their Windows counterparts are new strings in phase 2.
- **Storage identifiers are not identity.** The Keychain services `local.macvpn.vault` and `local.macvpn.secrets`, the preferences domain, the LaunchAgent label, the socket names, the root paths and the UTIs are literals in platform-mac (or the helper). They never derive from `Product`, because renaming them would orphan users' data.
- **Product values.** WinVPN's identifier is `local.winvpn` (also its AppUserModelID, so toasts work in phase 2). The data directory is `<platform app-data root>/<product name>`, so `%APPDATA%\WinVPN` comes from the platform's known-folder lookup in phase 2. The update asset is `WinVPN-<version>-x64.msi` or `-arm64.msi`, and the repo is the same `SepsiG/MacVPN` (spec 2). WinVPN's user guide stem is `winvpn-user-guide`, written in phase 2. The icons are MacVPN's until phase 2; only `icon.ico` is added, because the Windows resource build needs it.
- **The update signature.** The signed message contains the version and the SHA-256, not the product or the asset name, and it stays `macvpn-update-v1` in phase 1. What it binds: the signature covers exactly those bytes, so it cannot be reused for a different file (other bytes, other hash). What it does not bind: the asset's name. A signed file renamed to another asset of the same version (a WinVPN MSI as another product's asset, or the x64 MSI as the arm64 one) still verifies, because both products share one repo, one version line and the same keys. In 1.5.0 this cannot run anything: phase 1 signs no WinVPN asset, and on macOS a non-DMG file fails at the mount. Only the asset name of `parse_release` becomes a parameter. **Phase 2 blocker** (Task 20, M1): before the first signed WinVPN asset, keep `macvpn-update-v1` byte for byte for MacVPN and give WinVPN its own domain that includes the asset name (e.g. `winvpn-update-v1\n<asset>\n<version>\n<sha256>\n`, or separate keys); tests: MacVPN rejects a WinVPN-domain signature, WinVPN rejects the x64 signature for the arm64 asset.
- **`Release::dmg` → `Release::package`.** The field is not serialized. Its rename changes one line of the `Debug` fixture, and that is the only allowed fixture edit, done visibly in Task 10.
- **Native profiles.** `NativeProfiles::build` hides the profile format behind the platform. macOS builds the same `.mobileconfig` bytes as before. `core::mobileconfig` stays in core: it is a pure file format and is also the per-connection export of L2TP and Cisco connections, which stays `.mobileconfig` on every OS in phase 1 (data portability). Phase 2 decides whether WinVPN also exports RAS entries.
- **`LegacyKeychain` keeps its name.** It reads the 1.1 Keychain items, which exist only on macOS. The Windows stub returns an empty source.
- **`SetupReport.brew_prefix` → `package_manager`.** It is a Rust-only field. The view model's `SetupFacts` keep their wire names, and the System Status window on macOS is unchanged.
- **SQLCipher on Windows now, not with the Windows key store.** The comment in `crates/core/Cargo.toml` deferred it to keep `openssl-src` out of `Cargo.lock`. The Windows check and the Windows app-core tests need the vault, so it is added in phase 1, gated to Windows targets. The macOS release gate (no OpenSSL, CommonCrypto provider) and `cargo tree` prove that the macOS binaries are unaffected. The Windows provider gate belongs to phase 2's `build-msi.ps1`.
- **Checking Windows from macOS.** The C dependencies (SQLCipher, OpenSSL, Tauri's Windows resources) need an MSVC-compatible toolchain. `cargo xwin` cannot provide it for this workspace (Task 2: vendored OpenSSL builds for MSVC only on a Windows host). `scripts/check-windows.sh` checks the crates without C dependencies, and CI's `windows-latest` job is the full check.
- **The smoke run** is a macOS debug-build driver. It moves under the app's platform module (`platform/smoke.rs`, macOS and debug only), and the app reaches it through no-op facades elsewhere. The Windows smoke run is phase 2.
- **Fonts (spec 6).** The UI already uses the system font stack through CSS. Adding `"Segoe UI Variable"` to that stack is a phase 2 UI change, since it cannot change anything on macOS and cannot be verified until WinVPN runs.
- **The `get_platform` command on Windows** returns `windows`/`WinVPN`. The Windows app exits at `platform::supported()` before any window opens in phase 1, so this is never shown yet.
- **Helper test layout (spec 8).** Phase 1 splits the Rust unit tests into shared and macOS cases (Task 11). `scripts/test-root.sh` stays the macOS backend's black-box test. The Windows harness is phase 2.
