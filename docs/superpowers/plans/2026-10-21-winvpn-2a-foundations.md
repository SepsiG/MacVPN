# WinVPN phase 2a – foundations: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. The spec is `docs/superpowers/specs/2026-10-20-cross-platform-winvpn-design.md` (sections 3, 4.3, 5, 6, 7, 8 and its "Phase 2 blockers"). Every earlier spec (vault, control API, team catalog) still applies unchanged, on Windows too. Where this plan and the spec disagree, the spec wins, except where "Resolved points" below says why the plan deviates. Follow the existing patterns of the crate you work in (read a neighbouring module first). The phase 1 plan (`docs/superpowers/plans/2026-10-20-platform-neutral-refactor.md`) is the reference for rigor.

**Goal:** a testable, unsigned WinVPN MSI (x64 and ARM64) that installs, launches, creates and unlocks the vault (auto-unlock key in Credential Manager), shows the notification-area icon, the popover and every window, imports, edits, exports, backs up and restores connections, subscribes to file-based team catalogs and pairs control-API clients over a named pipe, but connects no VPN yet: the helper and native controllers answer "The VPN engine comes in a later version of WinVPN" and System Status says so. MacVPN behaviour stays exactly as in 1.5.0.

**Architecture:** a new low-level binding crate `crates/winsys` (`macvpn-winsys`, Windows-only, the one new home of `unsafe` besides the platform crates and the helper) wraps the few Win32 calls that core's `fsx` and the platform both need (SIDs, security descriptors, file identity, randomness, named pipes). Core's `fsx` gets a portable `Stat` type so owner, ACL, identity and link checks work from an open handle on Windows and stay byte-for-byte the same `fstat`/`lstat` calls on Unix. `crates/platform-win` turns from a stub into the real Windows platform (Credential Manager, known folders, DWM, COM file dialogs, WinRT toasts, clipboard formats, Run key, a hidden lifecycle window, the control pipe, single instance), with its pure logic in modules that also compile and test on macOS. The app's `platform/windows.rs` wires it to Tauri; the MSI is Tauri's WiX bundle plus one WiX fragment.

**Tech Stack:** Rust 1.99.1 (pinned in `rust-toolchain.toml`), edition 2024, Tauri 2.12 (WiX 3 MSI bundler), `windows-sys =0.61.2` and `windows =0.62.2` (both already in `Cargo.lock` through Tauri: no new crate in the lock file), Svelte + TS, bash (Git Bash on Windows), Node 26.8.2.

---

## Decisions of the maintainer (2026-10-21)

1. **Auto-unlock on Windows: on by default**, as on macOS. The Windows user guide says exactly what it protects against (other users, a stolen disk) and what not (malware running as the same user: Credential Manager has no per-app ACL). It can be switched off in the settings. (Task 9, Task 18.)
2. **Data directory: `%LOCALAPPDATA%\WinVPN`**, not the spec's `%APPDATA%` (see Resolved points; the spec is updated).
3. **MSIs on 1.x release drafts: only from 2.0.0.** The release workflow builds both MSIs on every tag but attaches them only when the repository variable `WINVPN_MSI_IN_RELEASE` is `true` (unset until 2.0.0); CI keeps them as workflow artifacts. (Task 17.)
4. **HTTPS team catalogs and the update check on Windows: 2b.** In 2a, file-based catalog sources work fully and an HTTPS source shows "Not available on this system yet". (Task 9.)
5. **Version of 2a builds: stays `1.5.0`** (decided by the coordinator); the WiX `UpgradeCode` is fixed from now on.
6. **The Windows test machine** (set up 2026-10-21): Windows 11 x64 VM on the maintainer's LAN (its address is not in the repository: `WINVPN_SSH`), standard (non-admin) account `winvpn-dev`, medium integrity; key `~/.ssh/winvpn_dev`, host key pinned in `~/.ssh/winvpn_known_hosts` (no alias in `~/.ssh/config`). Installed: Git (Git Bash), Strawberry Perl, Visual Studio 18 C++ tools (x64 + ARM64), rustup and Node 26.8.2 (user level). The checkout is `C:\Users\winvpn-dev\src\macvpn` (`core.autocrlf false`). OpenSSH's `DefaultShell` is **not** changed (that needs admin): `scripts/win-remote.sh` runs `"C:\Program Files\Git\bin\bash.exe" -lc '…'` explicitly. Admin-only steps (MSI install, later the service) are run by the maintainer.

---

**Rules for every task:**
- TDD: write the failing test first. For a pure refactor the "failing test" is an existing test that must stay green (name it in the commit message body). Tests that need Windows are written on the Mac, compile-checked with `scripts/check-windows.sh` where possible, and run on the Windows machine with `scripts/win-remote.sh` (Task 1); the step says which.
- Before each commit, on the Mac: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `CI=1 cargo test --workspace --locked`, `scripts/check-windows.sh`. For UI work also `cd app/ui && npm test && npm run build`. If a task touches `crates/helper`, also `MVPN_IMPL=rust scripts/test-root.sh`.
- Before each commit of a task that touches Windows code, on the Windows machine: `scripts/win-remote.sh test` (the CI windows job's set) and `scripts/win-remote.sh run 'cargo clippy --workspace --all-targets --locked --target x86_64-pc-windows-msvc -- -D warnings'`.
- **MacVPN unchanged:** every phase 1 baseline stays green without edits: `cargo test -p macvpn-app-core --test compat_1_4`, `node scripts/l10n-baseline.mjs --check`, `app/src-tauri/tests/tauri_config.rs`, `MVPN_IMPL=rust scripts/test-root.sh`, `node scripts/third-party-notices.mjs --check`, `cargo tree --locked --target aarch64-apple-darwin -i openssl-sys` (prints nothing) and the same for `x86_64-apple-darwin`, no Windows crate in a macOS binary (a new check from Task 3 on): `cargo tree --locked -e normal --target aarch64-apple-darwin -p macvpn-app -p macvpn-helper --prefix none | grep -E '^(windows|macvpn-winsys)'` prints nothing, and the same for `x86_64-apple-darwin` (`-i windows-sys` alone is ambiguous: the lockfile has two versions). Task 19 adds `scripts/bundle-baseline.sh dist/MacVPN.app`.
- **The cfg/unsafe rule** (`crates/app-core/tests/cfg_rule.rs`): OS `cfg` only in `crates/core/src/fsx/`, `crates/platform-mac/`, `crates/platform-win/`, `crates/winsys/`, the helper backends and `app/src-tauri/src/platform/`; `unsafe` only in `crates/platform-mac/`, `crates/platform-win/`, `crates/winsys/` and `crates/helper/`. Core, app-core, platform-api and the app crate stay free of `unsafe`. Task 3 is the only task that edits the allow-lists.
- **Dependencies:** every Windows dependency is a `[target.'cfg(windows)'.dependencies]` entry pinned exactly (`=x.y.z`), already in `Cargo.lock` (`windows-sys =0.61.2`, `windows =0.62.2`) unless the task says otherwise, and listed in the Windows notices (Task 16). No new crate reaches a macOS binary.
- **Secrets:** never log, and never put in argv, env, a window title or a toast: a password, a PSK, a key password, an OTP, a recovery key, the master password, a vault key (DEK), a team key, an admin key, a bearer token, a subscription string, a control-API token, or a config's content. Zeroize every buffer that held one (`Zeroizing`), including the Credential Manager blob copy.
- **Fail closed:** when a Windows check cannot be completed (an ACL that cannot be read, a token that cannot be opened, a reparse tag that cannot be read), the operation is refused, never assumed safe.
- Serialized formats are frozen (vault, backup, export, catalog, `control-clients.json`, `connection-order.json`, `system-otp.json`, `meta.json`, view-model JSON, IPC payloads). A new view-model field is `#[serde(skip_serializing_if = …)]` and absent on macOS, so the compat fixtures stay byte-identical.
- Every new user-facing string goes into `crates/core/l10n/strings.json` in EN and HU with the right `scope`; a Windows-only text has `"only": ["windows"]`. Tasks that add strings only add entries (shared file: merge conflicts are resolved by keeping both entries, sorted).
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Never push.
- The maintainer's forbidden company name never enters the repo. Use "Office VPN", "Acme VPN", `vpn.example.com`.
- Never touch the real Keychain or `~/Library/Application Support/MacVPN` on the Mac; tests on Windows use their own temp directories and uniquely named test credentials (`local.winvpn.test.<uuid>`), which they delete.

**Parallel execution.** Tasks in the same wave touch disjoint files except where a task says "shared with". Run each parallel task in its own worktree (superpowers:using-git-worktrees) from the tip of the previous wave; merge in task order; the next wave starts from the merged tip. A wave is done when the merged tip passes every check above on the Mac and `scripts/win-remote.sh test` on Windows. Each worktree syncs into its own remote directory on the Windows machine (`WINVPN_REMOTE_DIR=winvpn-work-<task>`), so parallel tasks never overwrite each other's checkout. Shared files within a wave: `crates/core/l10n/strings.json` (entries only), `crates/platform-win/{Cargo.toml, src/lib.rs, src/win/mod.rs, src/win/platform.rs}` (Tasks 12 and 13: each adds its own lines), the control test files (Tasks 10 and 11: 11 deletes ignore lines, 10 adds the pipe kind).

| Wave | Tasks (parallel within a wave) | Needs |
|---|---|---|
| 0 | 1 Windows test harness ∥ 2 update signature bound to product and asset ∥ 3 `winsys`: SIDs, security descriptors, file identity, randomness | – (3 is run on Windows through 1) |
| 1 | 4 `fsx::Stat` (portable, Unix byte-identical) ∥ 5 importer paths ∥ 6 `winsys::pipe` ∥ 7 platform-api additions | 4: 3; 5: none; 6: 3; 7: none |
| 2 | 8 `fsx` on Windows for real ∥ 9 platform-win foundations | 8: 3, 4; 9: 3, 4, 7 |
| 3 | 10 the control API over the named pipe ∥ 11 the Windows ignores go ∥ 12 platform-win UI services ∥ 13 platform-win lifecycle, login item, single instance | 10: 6, 8, 9; 11: 5, 8; 12: 9; 13: 9, 6 |
| 4 | 14 the app on Windows ∥ 15 texts for Windows | 14: 10, 12, 13; 15: 9, 12, 13 |
| 5 | 16 the MSI and its release gates | 14, 15 |
| 6 | 17 CI and release workflow ∥ 18 documentation | 17: 11, 16; 18: 14, 16 |
| 7 | 19 verification (MacVPN baselines, the MSI on the Windows machine) → 20 independent review | 17, 18 |

**Key facts from the current code (read before starting):**
- **Workspace:** members `crates/{core,platform-api,platform-mac,platform-win,helper,app-core}`, `app/src-tauri`, `examples/macvpn-control-client`; version `1.5.0`; `[workspace.lints.rust] unsafe_code = "deny"`. `Cargo.lock` already has `windows-sys 0.61.2` and `windows 0.62.2` (Tauri's), `windows-sys 0.45.0`, `getrandom 0.3.4/0.4.3`, `winreg 0.56.0`.
- **`fsx` today** (`crates/core/src/fsx/{mod.rs,unix.rs,windows.rs}`): `owner(&Metadata)`, `has_access(&Metadata, Access)`, `file_id(&Metadata) -> Option<FileId>`, `hard_links(&Metadata) -> u64` take a `std::fs::Metadata`, which on Windows carries no owner, ACL, file index or link count in stable std. `windows.rs` fails closed: `Access::Private`, `owner`, `ensure_private_dir`, `create_private_dir_all` return `Unsupported`; `file_id` is `None`; `hard_links` is `u64::MAX` (so `store::shred_file` never overwrites on Windows). `OwnerId`/`FileIdent` are `Infallible` there. Callers of the `&Metadata` functions: `mfa.rs:621` (`AuthUIState::read`), `vault/keys.rs:307-309` (`fs::metadata(dir)` follows symlinks; the file's from `open_regular`), `vault/db.rs:196` (`file.metadata()`), `vault/db.rs:231-232` (`fs::symlink_metadata(&path)`), `exporter.rs:147-149` (`file.metadata()` vs `fs::symlink_metadata(&tmp)`), `log.rs:127` (`file.metadata()`), `store.rs:167` (`open_regular`'s metadata), tests in `crates/core/tests/fsx.rs` (Unix only) and `app/src-tauri/src/control.rs:795-796`.
- **Windows ignores:** 542 tests carry `#[cfg_attr(windows, ignore = "private files on Windows: phase 2")]`, 24 carry `… "the importer resolves file paths as Unix strings: phase 2"` (`crates/core/tests/importer.rs`), and 2 in `crates/core/tests/store.rs` carry `… "shred_file skips the overwrite on Windows until it reads the real hard link count: phase 2"` (multi-line `cfg_attr`). One `cfg_attr(windows, ignore …)` in `crates/app-core/src/vault.rs` (a unit test). CI's windows job prints the ignored count (`.github/workflows/ci.yml`, step "Tests ignored on Windows").
- **Importer:** `read_inline_data(path: &str, base: &str)` (`crates/core/src/importer.rs:550`) joins with `format!("{base}/{path}")`, canonicalizes, and compares `resolved` with `base + "/"` as text; `inline_openvpn_files` canonicalizes the base to a `String`; `lexically_escapes` splits on `/` only.
- **Update signature** (`crates/core/src/update.rs:505-560`): `UpdateSignature::{DOMAIN = "macvpn-update-v1", message(version, sha), verify(version, sha, sig, keys), verify_trusted}`; callers: `crates/platform-mac/src/update_installer.rs:179` and tests in `crates/core/tests/update.rs` and `crates/platform-mac/tests/update_installer.rs`. `scripts/sign-release.sh` signs only `MacVPN-<v>.dmg`; `scripts/test-sign-release.sh` (Hungarian output) and `crates/core/tests/update.rs::sign_release_dry_run_matches_app` drive its `--dry-run --dmg`.
- **platform-api:** `Platform` (one accessor per facility), `PlatformError::{Unsupported{what}, Failed(String)}`, `Product { name, os, app_id, repo, user_guide_stem }` with `MACVPN` and `WINVPN` (`app_id` `local.winvpn`, also the AppUserModelID), `ControlTransport { bind, random_32, is_already_closed, prepare_dir }`, `BoundEndpoint { listener, display, socket_file, guard }`, `Accepted::{Client{stream, peer}, Idle}`, `ControlStream { try_clone, shutdown, set_read_timeout, set_write_timeout, peer_connected }`, `PeerUser::{Uid, Sid}` (displays `sid S-1-5-…`), `MemoryPreferences`, `SystemSetup`, `WindowChrome`, `FilePanels` (`done` is `Box<dyn FnOnce…>`, not `Send`: called on the main thread), `Notifier`, `SecretClipboard` + `ClipboardMark(isize)`, `AppLifecycle` + `TerminateReply::{Now, Later, Cancel}`, `LoginItems` + `LoginItemView`.
- **platform-win today:** a stub `WinPlatform` (unit struct) without `cfg`, `unsafe` or `windows-sys`, tested on every OS by `crates/platform-win/tests/stub.rs`. The app picks it for every non-macOS target (`[target.'cfg(not(target_os = "macos"))'.dependencies]` in `app/src-tauri/Cargo.toml`; `app/src-tauri/src/platform/windows.rs`, whose `supported()` returns `Err("WinVPN is not available yet")`).
- **The app:** `main.rs` calls `platform::supported()` first, then `platform::init(sandbox)`, `install_core_hooks`, `Environment::detect`; setup calls `platform::configure_app`, `lifecycle.install_terminate_handler`, `observe_wake`, `tray::create_menu_window`, `tray::create`; `app.run` forwards other run events to `platform::on_run_event`. `tray.rs` places the popover **below** the icon (`y = icon.y + icon.height + 2`) and uses template icons (`icon_as_template(true)`, black + alpha). `open_files::opened(app, &[Url])` is the shared handler for files opened from the system. `dock::reopen(app)` brings a window forward.
- **The app menu:** `main.rs::install_menu` sets an app menu (Quit with `CmdOrCtrl+Q`, Edit); the tray tooltip is the literal `"MacVPN"` in `tray.rs::create`.
- **Tauri config:** `tauri.conf.json` (MacVPN identity, the `menu` window with `"title": "MacVPN"`, `"copyright": "MacVPN"`), `tauri.windows.conf.json` (`WinVPN`, `local.winvpn`, `msi`, icons with `icons/icon.ico`, WebView2 `downloadBootstrapper`). JSON merge patch replaces arrays whole. `app/src-tauri/tests/tauri_config.rs` checks base + macOS against 1.4.0.
- **CI** (`.github/workflows/ci.yml`): macOS jobs `rust`, `node`, `dmg`; Windows jobs `windows` (fmt, clippy x64, check ARM64 debug+release, tests of `macvpn-core macvpn-app-core macvpn-platform-api macvpn-platform-win macvpn-helper` with `--lib --tests`, the ignored count) and `windows-node` (npm test); `OPENSSL_SRC_PERL: C:\Strawberry\perl\bin\perl.exe`; LF checkout (`git config --global core.autocrlf false`). `scripts/check-windows.sh` (Mac) checks `macvpn-core` (no vault), `macvpn-helper`, `macvpn-control-client` for both Windows targets.
- **Release** (`.github/workflows/release.yml`): job `build` (macos-15, tests, DMG, `.sha256`, artifact `dmg`) and job `release` (ubuntu, no checkout, `gh release create … --draft`).
- **Gates of `scripts/build-dmg.sh`:** no `setInspectable`, `developerExtrasEnabled`, `MACVPN_SANDBOX_HOME`, `MACVPN_SMOKE` in the release binary; SQLCipher with the CommonCrypto provider and no OpenSSL; `THIRD-PARTY-NOTICES.txt` checked by `node scripts/third-party-notices.mjs --check`; exact resource list.
- **Texts:** `crates/core/l10n/strings.json` entries `{hu, scope, variants?: {windows: {en, hu}}, only?: ["macos"|"windows"|"linux"]}`; "MacVPN" is replaced by the product name except in texts whose `only` excludes the OS. The Windows glossary is in `docs/architecture.md` ("Texts per OS").
- **The smoke driver** (`app/src-tauri/src/platform/smoke.rs`, 1796 lines) is AppKit-specific (window numbers, `screencapture`, activation policy).
- `docs/manual-test-checklist.md` and `scripts/test-sign-release.sh` are Hungarian; keep that.

---

## Resolved points (where the spec leaves a choice open, and where this plan deviates)

- **Where `unsafe` for core's Windows file calls lives: a new crate `crates/winsys`.** Core may not contain `unsafe` (rule above) and stable std reads no owner, ACL, file index or link count on Windows. The spec says "ACLs through the platform layer", but core cannot depend on `platform-win` (platform-win depends on core: a cycle). So the Win32 calls core needs go into `macvpn-winsys`, a crate with one dependency (`windows-sys`), no knowledge of core, `#![cfg(windows)]` as a whole (an empty crate elsewhere), and safe functions only in its public API. Core depends on it only under `[target.'cfg(windows)'.dependencies]`. platform-win, app-core's tests and the example client use the same functions, so there is one audited implementation of each Win32 call. `cfg_rule.rs` adds `crates/winsys/` to both allow-lists; nothing else is added.
- **`fsx` checks come from a handle, through `fsx::Stat`.** `owner`, `has_access`, `file_id` and `hard_links` take `&fsx::Stat` instead of `&Metadata`. `Stat` derefs to `Metadata` (so `meta.len()`, `meta.file_type()` keep working) and on Windows also carries what was read from the open handle (owner SID, the DACL's shape, the 128-bit file id, the link count, the reparse tag). On Unix `fsx::stat(&file)` is `file.metadata()` (`fstat`), `fsx::stat_path(p, Follow::No)` is `fs::symlink_metadata` (`lstat`) and `Follow::Yes` is `fs::metadata` (`stat`): every Unix call site makes exactly the syscall it made before. `open_regular` returns `(File, Stat)`.
- **The private ACL: the user and SYSTEM, not Administrators.** `Access::Private` is a protected DACL (no inherited ACEs) with exactly two ACCESS_ALLOWED ACEs, `FILE_ALL_ACCESS` for the current user and for `NT AUTHORITY\SYSTEM`, and the owner set explicitly to the current user's SID (an elevated token would otherwise make `BUILTIN\Administrators` the owner). Directories carry the same two ACEs with `OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE`, so the files SQLite creates beside the vault (`-wal`, `-shm`) are private too. SYSTEM is the trusted computing base (it can read anything through backup privileges anyway); granting it keeps Defender, VSS and backup tools working. Administrators are left out, like the admin group under a Unix 0600: an elevated process can still take ownership, but only deliberately, and the counterpart of macOS (root can read too) holds. `has_access(Private)` is true only for exactly that shape (the counterpart of `mode & 0o7777 == 0o600`). `Access::Shared` means "the folder's normal permissions": the DACL is not protected (inherits from the parent); `has_access(Shared)` is true exactly then. *As built (Task 8):* `Access::Shared` is a protected DACL too, not inherited permissions: the user and SYSTEM with full access and `BUILTIN\Users` with read (`macvpn_winsys::file::Protection::Shared`), the intended equivalent of 0644 (0755 for a directory); `has_access(Shared)` is true for exactly that shape.
- **Reparse points.** `Follow::No` refuses **name-surrogate** reparse points (symlinks, junctions, mount points: `IsReparseTagNameSurrogate`, bit `0x20000000` of the tag) with `is_symlink_refused`. Non-surrogate reparse points (OneDrive / Cloud Files placeholders, deduplicated or WOF-compressed files) are regular files: a user who imports an `.ovpn` from a OneDrive folder must not be refused. For such a file `open_regular` reopens without `FILE_FLAG_OPEN_REPARSE_POINT` (which hydrates a placeholder) and checks that the second handle has the same volume and 128-bit file id as the first (no swap in between); a Cloud Files provider or network error while hydrating (`macvpn_winsys::file::is_cloud_unavailable`) counts as `is_unavailable`. The private data directory and its files are always created by us, never reparse points; `ensure_private_dir` refuses a reparse point as the leaf (`NotADirectory`), like a symlink on Unix.
- **Alternate data streams.** On Windows a referenced file path in an imported config whose file name contains `:` (an alternate data stream, `ca.crt:hidden`) is refused as `MissingFile` (`fsx::names_a_stream`, always `false` on Unix, so macOS keeps accepting `:` in names).
- **`sync_dir` on Windows** stays a no-op: NTFS journals the rename's metadata; `FlushFileBuffers` on a directory handle needs write access to the directory and gives nothing more.
- **The importer** joins with `Path` (`base.join(path)`, or the path itself when it `has_root()` or has a drive prefix) and checks `resolved.starts_with(&base) && resolved != base` component-wise on canonical paths (`\\?\C:\…` on both sides on Windows). On Unix this accepts and refuses exactly the same inputs as the text check (canonical paths have no `.`/`..` or doubled `/`; `base` itself, the one difference, was refused by the text check and is refused explicitly). Non-UTF-8 canonical paths stay refused. `lexically_escapes` splits on `fsx::is_separator` (`/` on Unix; `/` and `\` on Windows).
- **The update signature domain.** MacVPN keeps `macvpn-update-v1\n<version>\n<sha256>\n` byte for byte. WinVPN uses `winvpn-update-v1\n<asset>\n<version>\n<sha256>\n` with the asset's file name, which must be exactly `WinVPN-<version>-x64.msi` or `WinVPN-<version>-arm64.msi` (anything else: no message, no verification). Same keys (spec: "or separate keys" was the alternative; one key pair keeps the maintainer's offline process unchanged, and the domain separation makes cross-product and cross-arch reuse impossible). `Product` names its `signature_domain`. The WinVPN updater itself (download, verify, `msiexec`) is 2b; 2a only makes the signing and verification ready, so the first signed WinVPN asset is already bound. *2b note (review I7):* the WinVPN updater must verify with `UpdateSignature::verify_trusted_for(product.signature_domain, asset, version, sha256, signature)`, passing the exact file name of the asset it downloaded (`WinVPN-<version>-x64.msi` or `…-arm64.msi`, the one for this machine's architecture); never `verify_trusted` (MacVPN's domain), and never with `SignatureDomain::MacVpnV1`, which ignores the asset, so a signature of the other architecture's MSI would pass.
- **The control pipe** is `\\.\pipe\WinVPN-control-<user SID>` (not `\\.\pipe\WinVPN`, which spec 4.1 reserves for the 2b service). Its DACL is protected: deny `NT AUTHORITY\NETWORK`, allow `FILE_ALL_ACCESS` to the current user (needed to create further instances) and to SYSTEM; owner = the user. Created with `PIPE_REJECT_REMOTE_CLIENTS`, the first instance with `FILE_FLAG_FIRST_PIPE_INSTANCE` (a name already taken, by another WinVPN of this user or by a squatter, is `AddrInUse`: the control API then stays off and says so, as on macOS). The peer: `GetNamedPipeClientProcessId`, the client's SID from `ImpersonateNamedPipeClient` + `OpenThreadToken` (then `RevertToSelf`; if reverting fails the process aborts: it must never keep running as the client), the image path from `QueryFullProcessImageNameW`. A client that allows less than identification-level impersonation cannot be identified and is closed (fail closed). Clients (the example client) open the pipe with `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` and refuse a server whose process token is not their own user (`GetNamedPipeServerProcessId`), so a squatter never receives a bearer token (*review I1:* it can still identify the client while it connects, its SID, groups and privileges at identification level, but it can never act as the client and receives no data). `display` is the pipe name; `socket_file` is `None`; the guard is the first instance.
- **Pipe I/O.** Overlapped I/O with one event per operation, so reads and writes on clones run concurrently and every timeout is exact. A timed-out read cancels only itself (`CancelIoEx` with its `OVERLAPPED`), then waits for the cancellation; data that arrived in the race is returned, not dropped. `shutdown(Read)` makes reads return `Ok(0)`; `shutdown(Both|Write)` cancels pending I/O and closes the handle (not `DisconnectNamedPipe`, which would discard data the peer has not read yet), after the in-flight operations have finished (an `RwLock` around the handle: operations hold it shared, the close holds it exclusive), so a stale handle value is never reused. `peer_connected` is `PeekNamedPipe` with a zero-length buffer.
- **app-core's control tests on Windows** get a `Kind::Pipe` test transport over `macvpn-winsys::pipe` (a dev-dependency under `cfg(windows)`; winsys is a binding crate, not a platform crate, so app-core still never depends on a platform crate). It keeps the suite's fake peer identity (the suite tests the server's decisions); the real peer identity is tested in `crates/winsys/tests/pipe.rs` and `crates/platform-win/tests/control_pipe.rs`.
- **The example client's Windows transport** depends on `macvpn-winsys` under `cfg(windows)`: verifying the server's user needs Win32 calls, and one audited pipe implementation beats a copy. Its README says what to copy with it. `Client::connect(path)` takes the pipe name as the path; `macvpn_control_client::default_endpoint()` returns it.
- **Key store.** A generic credential `local.winvpn.vault`, user name `dek` (literals in platform-win, never derived from `Product`), `CRED_PERSIST_LOCAL_MACHINE` (the DEK never roams to other machines with a roaming profile; another machine falls back to the password, which is the safe direction). `exists()` reads the credential (Windows never prompts). Errors map: `ERROR_NOT_FOUND` → none; `ERROR_NO_SUCH_LOGON_SESSION` → `Unavailable`. The blob copy is zeroized. Entropy and `random_32`: `BCryptGenRandom(BCRYPT_USE_SYSTEM_PREFERRED_RNG)`. The legacy keychain and legacy secrets are empty (macOS-only history).
- **Preferences: a JSON file in the private data directory, not the registry.** `%LOCALAPPDATA%\WinVPN\preferences.json` (private ACL, `fsx::atomic_write`), implemented once as `FilePreferences` in platform-api (portable, tested on macOS too; macOS keeps `CFPreferences`). One place for all user data (removed with it, backed up with it), the same safe-write code as every other store, no registry code to audit. A corrupt file reads as empty and is replaced on the next write.
- **Data directory:** `%LOCALAPPDATA%\WinVPN` (maintainer's decision 2026-10-21, replacing the spec's `%APPDATA%`), from `SHGetKnownFolderPath(FOLDERID_LocalAppData)`; home is `FOLDERID_Profile`. Not the roaming profile: a roaming sync could copy the SQLite vault while it is open, and the vault key in Credential Manager is per machine anyway; moving to another PC goes through the full backup. The sandbox (`MACVPN_SANDBOX_HOME`, debug builds) keeps `<sandbox>/AppData/Local/WinVPN`, memory key store and memory preferences.
- **What answers "not yet" in 2a, and how it looks.** `HelperClient::status` → `Ok(vec![])` (nothing runs), `up`/`down`/`respond` → the localized "The VPN engine comes in a later version of WinVPN." `NativeController::list` → `Ok(vec![])` (no system VPNs listed, no error loop), `start`/`stop` → the same message. `NativeProfiles::build` → `Ok` with an empty profile (so an L2TP / IKEv2 connection can be created, edited and saved), `install` → `Err(` the same message `)` (the editor shows it after saving). `SystemVpnWatch::start` → `Ok` with an inert guard. `SystemSetup::engine_note()` (new, default `None`) → `Some(` "The VPN engine comes in a later version of WinVPN. You can already create, import, edit, export and back up connections." `)`; System Status shows that note instead of the Homebrew / tools / helper rows. HTTPS catalog fetch, the release source and the updater stay `Unsupported` (question 2). The log stream stays `Unsupported`.
- **Single instance and opened files.** A named mutex `Local\WinVPN-instance-<SID>` (per session) decides; a second instance forwards its absolute file arguments (or an empty list: "show yourself") over `\\.\pipe\WinVPN-open-<SID>-<session id>` (same DACL rules as the control pipe, same-user peers only, at most 64 KiB, UTF-8 lines) and exits 0. The first instance hands them to `open_files::opened` (as `file://` URLs), or, for an empty list, brings the open real windows forward (`dock::reopen`); with none open it opens the Connections window, or the vault's unlock/create window while the vault is closed (`open_files::show_yourself`, so a second launch always shows something; macOS' Dock `Reopen` is unchanged). Same trust as macOS's `RunEvent::Opened` (any same-user app can `open -a MacVPN`); the Mark-of-the-Web check still applies to every file.
- **Mark of the Web:** `<path>:Zone.Identifier` read through std (`File::open` on the stream name; no `unsafe`), at most 4 KiB. `ZoneId` ≥ 3 (Internet, Restricted) → marked; 0–2 → not marked; no stream (`NotFound`) → not marked; a missing file → not marked; anything else unreadable or unparsable → marked (fail closed, as the trait says).
- **No app menu on Windows.** macOS' app menu (Quit, Edit) would become a menu bar inside every WinVPN window; on Windows the app installs none (`platform::uses_app_menu()`): WebView2 keeps the native text shortcuts (Ctrl+C/V/X/A/Z), and Quit is in the popover. The tray tooltip is the product's name (`MacVPN` on macOS, as before).
- **Window presence.** Windows shows a taskbar button for every visible window except those with `skipTaskbar` (the popover), so `set_window_presence` stays a no-op and WinVPN has no taskbar button while only the tray runs.
- **Tray.** The popover opens **above** the icon when the icon is in the lower half of its monitor (Windows' taskbar), below it otherwise (macOS' menu bar): one pure function `popover_position` in `tray.rs`, whose macOS result is unchanged (tested). The tray icons are the same PNGs tinted at runtime: `WindowChrome::tray_tint()` (new, default `None` = template image) returns white on a dark taskbar and black on a light one (`HKCU\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize\SystemUsesLightTheme`), read again whenever the icon is set or the popover opens.
- **Rounded corners.** `DwmSetWindowAttribute(DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND)`: Windows 11 rounds (radius 8, `popover_corner_radius() = 8.0`); on Windows 10 the call fails and `round_corners` returns `false` (square corners, accepted).
- **File panels.** `IFileOpenDialog` / `IFileSaveDialog` (COM, `windows` crate) shown from a message posted to platform-win's own hidden message window, so `choose_files` returns at once (as the trait promises) and the modal loop never runs inside a caller's lock; `done` (not `Send`) is kept in a main-thread `thread_local!` queue.
- **Notifications.** WinRT toasts (`Windows.UI.Notifications`, `windows` crate) with the AppUserModelID `local.winvpn`, set for the process (`SetCurrentProcessExplicitAppUserModelID`) and on the MSI's Start-menu shortcut (`System.AppUserModel.ID`; the MSI gate checks it). Tag = the notification identifier (≤ 64 characters; longer identifiers are hashed to 32 hex digits), so `remove_delivered` works. Clicks arrive through the `Activated` event while WinVPN runs; a click after quit only starts WinVPN (no deep action; accepted for 2a).
- **Secret clipboard.** `CF_UNICODETEXT` plus the registered formats `ExcludeClipboardContentFromMonitorProcessing` (empty), `CanIncludeInClipboardHistory` (DWORD 0) and `CanUploadToCloudClipboard` (DWORD 0); `ClipboardMark` is `GetClipboardSequenceNumber()` after the write; `clear_if_unchanged` empties only if the sequence number is still the mark.
- **Quit and logoff.** platform-win's hidden **top-level** lifecycle window (message-only windows get no `WM_QUERYENDSESSION`) answers `WM_QUERYENDSESSION` with the handler: `Now` → TRUE; `Cancel` → FALSE; `Later` → FALSE plus `ShutdownBlockReasonCreate` (localized "Closing WinVPN…"), and `reply_to_terminate(true)` destroys the reason and lets the app exit. `WM_POWERBROADCAST` / `PBT_APMRESUMEAUTOMATIC` drives `observe_wake`.
- **Launch at login:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, value `WinVPN` = `"<exe path>"` (quoted). The Settings switch (Startup apps) writes `…\Explorer\StartupApproved\Run\WinVPN` (a 12-byte binary; first byte `2` enabled, `3` disabled); a disabled entry shows the note "Turned off in Settings → Apps → Startup." and the "Open Startup apps settings…" button (`ms-settings:startupapps`). The sandbox uses a no-op item.
- **Fonts (spec 6):** `--font` gets `"Segoe UI Variable Text", "Segoe UI"` after the Apple fonts, and `--mono` gets `Consolas` before `monospace`: the first available family wins, so macOS renders exactly as before.
- **`platform-win` layout.** No crate-level `cfg`: the pure logic (zone parsing, Run-key values, toast XML, date formatting, the "not yet" texts, the popover-independent bits) lives in `src/pure/` and compiles and tests on every OS (the macOS CI covers it); everything that calls Win32 is under `src/win/` behind `#[cfg(windows)]` in `lib.rs`. `WinPlatform` exists only on Windows. The app selects platform-win for `cfg(windows)` only; any other non-macOS target hits a `compile_error!` naming phase 4 (no Linux build exists today).
- **The MSI script is bash (`scripts/build-msi.sh`), not `build-msi.ps1`.** CI's Windows jobs and the maintainer's Windows machine both run Git Bash already; one shell keeps the gates readable next to `build-dmg.sh` and lets `scripts/win-remote.sh` drive it. Spec 7's gates are kept (the `wireguard.dll` gate arrives with WireGuard in 2b).
- **Windows notices.** `scripts/third-party-notices.mjs --os windows` writes `THIRD-PARTY-NOTICES.windows.txt` (the crates linked for the two Windows targets, the SQLCipher and OpenSSL notices, the UI's JS packages); the MSI installs it as `THIRD-PARTY-NOTICES.txt`. The macOS file is untouched.
- **Authenticode:** the build script signs only when `WINVPN_SIGN_THUMBPRINT` is set (`signtool sign /sha1 … /fd sha256 /tr <RFC 3161 URL> /td sha256` on `WinVPN.exe` before bundling and on the MSI after); unset by default, in CI and in the release workflow.
- **The smoke run on Windows is deferred to 2b.** The driver is AppKit-specific (window numbers, `screencapture`, the activation policy), and an SSH session on the Windows machine has no interactive desktop for WebView2. Porting it is worth it when connecting works (2b); 2a's UI is covered by the manual checklist (Task 18) and the unit tests.
- **Windows test harness.** `scripts/win-remote.sh` syncs `HEAD` plus uncommitted tracked changes (`git stash create`) as a git bundle over `scp`, checks it out in `~/<WINVPN_REMOTE_DIR>` on the Windows machine, and runs commands there in Git Bash. It never needs admin rights; admin-only steps (installing the MSI, later the service) are the maintainer's, listed in the manual checklist.
- **ARM64** is built and `cargo check`ed (debug and release) but not run (no ARM64 machine); the MSI is checked for contents only.

---
## Task 1: the Windows test harness

**Goal:** every later task can run its Windows tests on the maintainer's Windows 11 x64 machine from the Mac with one command, as a standard user, without admin rights and without touching the Mac's real data.

**Files:**
- Create: `scripts/win-remote.sh`
- Modify: `docs/architecture.md` (section "Checking Windows": a subsection "The Windows test machine")
- Modify: `.github/workflows/ci.yml` (only the existing "Bash syntax check" covers the new script; no edit needed, verify)

- [x] **Step 1: One-time setup on the Windows machine (the maintainer, documented, not automated)**

Write this into `docs/architecture.md` under "Checking Windows" as a new subsection "The Windows test machine":

```markdown
### The Windows test machine

The coordinator reaches a Windows 11 x64 machine over SSH as a **standard user** (no admin rights). The machine has
rustup (the toolchain comes from `rust-toolchain.toml` on the first `cargo` call), Visual Studio Build Tools (the C++
workload with the x64 and ARM64 compilers), Git for Windows (Git Bash), Strawberry Perl and Node 26.8.2.

Setup (done 2026-10-21): the standard account `winvpn-dev` has a key-only `authorized_keys` entry for the
Mac's `~/.ssh/winvpn_dev`; the host key is pinned in `~/.ssh/winvpn_known_hosts`. Nothing in `~/.ssh/config` and
no change to OpenSSH's `DefaultShell` (that needs an administrator): the script starts Git Bash explicitly
(`C:\Program Files\Git\bin\bash.exe -lc …`) for every remote command.

`scripts/win-remote.sh` then syncs the working tree (HEAD plus uncommitted changes of tracked files; `git add -N`
a new file first) and runs commands there:

    scripts/win-remote.sh test                      # the CI windows job's test set
    scripts/win-remote.sh ignored                   # the tests ignored on Windows
    scripts/win-remote.sh run 'cargo test --locked -p macvpn-winsys'
    scripts/win-remote.sh run 'scripts/build-msi.sh'
    scripts/win-remote.sh fetch dist/windows ./dist/windows

Steps that need an administrator (installing the MSI, from 2b the service) are the maintainer's; they are in
`docs/manual-test-checklist.md`. Several worktrees use separate remote checkouts: `WINVPN_REMOTE_DIR=winvpn-work-<name>`.
```

- [x] **Step 2: Write `scripts/win-remote.sh`**

```bash
#!/bin/bash
# Runs the working tree on the Windows test machine over SSH (docs/architecture.md, "The Windows test machine").
#
#   scripts/win-remote.sh sync                       copy HEAD + uncommitted changes of tracked files there
#   scripts/win-remote.sh run 'COMMAND'              sync, then COMMAND in the remote checkout (Git Bash)
#   scripts/win-remote.sh test [EXTRA CARGO ARGS]    sync, then the CI windows job's test set
#   scripts/win-remote.sh ignored                    sync, then list the tests ignored on Windows
#   scripts/win-remote.sh fetch REMOTE_PATH LOCAL_DIR   copy a build product back (relative to the checkout)
#
# Environment: WINVPN_SSH (ssh destination user@host, required), WINVPN_REMOTE_DIR (default "winvpn-work",
# relative to the remote home). The remote account is a standard user: nothing here needs administrator rights.
# Nothing secret is sent: the bundle holds only the repository's tracked content.
set -euo pipefail
cd "$(dirname "$0")/.."

SSH_DEST="${WINVPN_SSH:?set WINVPN_SSH=user@host of the Windows test machine}"
SSH_OPTS=(-o BatchMode=yes -o IdentitiesOnly=yes -i "$HOME/.ssh/winvpn_dev" -o UserKnownHostsFile="$HOME/.ssh/winvpn_known_hosts")
GIT_BASH='"C:\Program Files\Git\bin\bash.exe"'
REMOTE_DIR="${WINVPN_REMOTE_DIR:-winvpn-work}"
[[ "$REMOTE_DIR" =~ ^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$ ]] || { echo "WINVPN_REMOTE_DIR: letters, digits, . _ - and /"; exit 1; }
REF=refs/winvpn/sync
PACKAGES=(-p macvpn-core -p macvpn-app-core -p macvpn-platform-api -p macvpn-platform-win -p macvpn-helper -p macvpn-winsys -p macvpn-control-client)

WORK="$(mktemp -d "${TMPDIR:-/tmp}/winvpn-remote.XXXXXXXX")"
cleanup() { rm -rf "${WORK:?}"; git update-ref -d "$REF" 2>/dev/null || true; }
trap cleanup EXIT

die() { echo "error: $*" >&2; exit 1; }
# The remote default shell is cmd.exe (OpenSSH's default; not changed): every command runs in Git Bash explicitly.
# The command is passed base64-encoded so neither cmd.exe nor bash re-quotes it.
remote() {
  local b64
  b64="$(printf '%s' "$*" | base64 | tr -d '\n')"
  ssh "${SSH_OPTS[@]}" "$SSH_DEST" "$GIT_BASH -lc \"echo $b64 | base64 -d | bash\""
}
# The remote shell is Git Bash: one login shell per command, the checkout as the working directory, the Perl that
# openssl-src needs (the CI job's OPENSSL_SRC_PERL).
in_checkout() {
  remote "cd ~/'$REMOTE_DIR' && export OPENSSL_SRC_PERL='C:\\Strawberry\\perl\\bin\\perl.exe' CI=1 && $1"
}

sync() {
  local rev
  rev="$(git stash create)"
  rev="${rev:-$(git rev-parse HEAD)}"
  git update-ref "$REF" "$rev"
  git bundle create "$WORK/sync.bundle" "$REF" >/dev/null 2>&1 || die "git bundle failed"
  remote "mkdir -p ~/'$REMOTE_DIR' && cd ~/'$REMOTE_DIR' && { [ -d .git ] || git init -q; } && git config core.autocrlf false"
  scp -q "${SSH_OPTS[@]}" "$WORK/sync.bundle" "$SSH_DEST:$REMOTE_DIR/.sync.bundle"
  in_checkout "git fetch -q .sync.bundle '$REF' && git checkout -q --force --detach FETCH_HEAD \
    && git clean -q -fdx -e /target -e node_modules -e /dist && rm -f .sync.bundle && git log -1 --format='synced %h %s'"
}

[ $# -ge 1 ] || { sed -n '4,9p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
case "$1" in
  sync) sync ;;
  run)
    [ $# -eq 2 ] || die "run needs exactly one quoted command"
    sync
    in_checkout "$2"
    ;;
  test)
    shift
    sync
    in_checkout "cargo test --locked --target x86_64-pc-windows-msvc ${PACKAGES[*]} --lib --tests --no-fail-fast $*"
    ;;
  ignored)
    sync
    in_checkout "cargo test --locked --target x86_64-pc-windows-msvc ${PACKAGES[*]} --lib --tests -- --list --ignored 2>/dev/null | grep ': test\$' | sort"
    ;;
  fetch)
    [ $# -eq 3 ] || die "fetch needs REMOTE_PATH LOCAL_DIR"
    [[ "$2" =~ ^[A-Za-z0-9._/-]+$ ]] || die "REMOTE_PATH: letters, digits, . _ / - only"
    mkdir -p "$3"
    scp -q -r "${SSH_OPTS[@]}" "$SSH_DEST:$REMOTE_DIR/$2" "$3/"
    ;;
  *) die "unknown command: $1" ;;
esac
```

*As built (2026-10-21), the committed script differs from the listing above where the first runs showed it had to:* the snapshot is a commit of a copied index after `git add -u` (`git stash create` refuses a file added with `git add -N`); the sync ref is `refs/winvpn/sync-<pid>` (refs are shared by all worktrees); `git clean` runs with `MSYS_NO_PATHCONV=1` (Git Bash turns `/target` into `C:/Program Files/Git/target`, so `-x` would delete the build cache); remote commands run with `ssh -n`, `set -o pipefail` and stdin from `/dev/null`; `PACKAGES` leaves out a crate that does not exist yet (`macvpn-winsys` before Task 3); `fetch` refuses `..`.

- [x] **Step 3: Check the script locally**

Run: `bash -n scripts/win-remote.sh && chmod +x scripts/win-remote.sh && scripts/win-remote.sh; echo "exit $?"`
Expected: the usage text (lines 4–9 of the header) and `exit 1`.

Run: `perl -ne 'print "$ARGV:$.: $_" if /\$[A-Za-z_][A-Za-z0-9_]*[\x80-\xff]/' scripts/win-remote.sh`
Expected: no output (the CI rule about `$VAR` before non-ASCII text).

- [x] **Step 4: First real run (needs question 4 answered and the one-time setup done)**

Run: `scripts/win-remote.sh test`
Expected: `synced <hash> docs(plan)…`, then the current Windows test result: everything passes, the 568 marked tests are ignored. Record the run time in the commit message body. If the machine is not ready yet, commit anyway and mark this step as pending in the plan; Tasks 3, 6, 8–14 cannot finish without it.

- [x] **Step 5: Commit**

```bash
git add scripts/win-remote.sh docs/architecture.md
git commit -m "build: run the working tree on the Windows test machine" -m "scripts/win-remote.sh syncs HEAD plus uncommitted tracked changes as a git bundle and runs the CI windows job's test set there, as a standard user." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

## Task 2: the update signature bound to product and asset (phase 2 blocker M1)

**Goal:** MacVPN's signed message stays `macvpn-update-v1\n<version>\n<sha256>\n` byte for byte; WinVPN's is `winvpn-update-v1\n<asset>\n<version>\n<sha256>\n`; a signature of one product or architecture never verifies for another; `scripts/sign-release.sh` signs every asset of a release with its product's message.

**Files:**
- Modify: `crates/core/src/update.rs:495-560` (the `UpdateSignature` section)
- Modify: `crates/platform-api/src/product.rs`, `crates/platform-api/tests/product.rs`
- Modify: `scripts/sign-release.sh`, `scripts/test-sign-release.sh`
- Test: `crates/core/tests/update.rs`

- [x] **Step 1: Write the failing tests** (append to `crates/core/tests/update.rs`, next to `message_format_is_exact`)

```rust
use macvpn_core::update::SignatureDomain;

const X64: &str = "WinVPN-0.2.2-x64.msi";
const ARM64: &str = "WinVPN-0.2.2-arm64.msi";

fn sign_for(k: &SigningKey, domain: SignatureDomain, asset: &str, version: &str, digest: &str) -> String {
    let message = UpdateSignature::message_for(domain, asset, version, digest).unwrap();
    swift_base64::encode(&k.sign(&message).to_bytes()) + "\n"
}

#[test]
fn macvpn_message_is_unchanged_whatever_the_asset() {
    let expected = format!("macvpn-update-v1\n0.2.2\n{DIGEST}\n").into_bytes();
    assert_eq!(UpdateSignature::message("0.2.2", DIGEST), Some(expected.clone()));
    for asset in ["MacVPN-0.2.2.dmg", "", X64] {
        assert_eq!(UpdateSignature::message_for(SignatureDomain::MacVpnV1, asset, "0.2.2", DIGEST), Some(expected.clone()));
    }
}

#[test]
fn winvpn_message_names_the_asset() {
    assert_eq!(
        UpdateSignature::message_for(SignatureDomain::WinVpnV1, X64, "0.2.2", DIGEST),
        Some(format!("winvpn-update-v1\n{X64}\n0.2.2\n{DIGEST}\n").into_bytes())
    );
    assert_eq!(
        UpdateSignature::message_for(SignatureDomain::WinVpnV1, ARM64, "0.2.2", DIGEST),
        Some(format!("winvpn-update-v1\n{ARM64}\n0.2.2\n{DIGEST}\n").into_bytes())
    );
}

#[test]
fn winvpn_message_refuses_any_other_asset_name() {
    for asset in [
        "",
        "MacVPN-0.2.2.dmg",
        "WinVPN-0.2.3-x64.msi",
        "WinVPN-0.2.2-x86.msi",
        "winvpn-0.2.2-x64.msi",
        "WinVPN-0.2.2-x64.msi\n",
        "WinVPN-0.2.2-x64.MSI",
        "../WinVPN-0.2.2-x64.msi",
    ] {
        assert_eq!(UpdateSignature::message_for(SignatureDomain::WinVpnV1, asset, "0.2.2", DIGEST), None, "{asset:?}");
    }
    assert_eq!(UpdateSignature::message_for(SignatureDomain::WinVpnV1, X64, "0.2", DIGEST), None);
    assert_eq!(UpdateSignature::message_for(SignatureDomain::WinVpnV1, X64, "0.2.2", &DIGEST[..63]), None);
}

#[test]
fn macvpn_rejects_a_winvpn_signature() {
    let sig = sign_for(&key(1), SignatureDomain::WinVpnV1, X64, "0.2.2", DIGEST);
    assert!(!UpdateSignature::verify("0.2.2", DIGEST, &sig, &keys()));
    assert!(!UpdateSignature::verify_for(SignatureDomain::MacVpnV1, "MacVPN-0.2.2.dmg", "0.2.2", DIGEST, &sig, &keys()));
}

#[test]
fn winvpn_rejects_a_macvpn_signature() {
    let sig = sign(&key(1), "0.2.2", DIGEST);
    assert!(!UpdateSignature::verify_for(SignatureDomain::WinVpnV1, X64, "0.2.2", DIGEST, &sig, &keys()));
}

#[test]
fn winvpn_rejects_the_x64_signature_for_the_arm64_asset() {
    let sig = sign_for(&key(1), SignatureDomain::WinVpnV1, X64, "0.2.2", DIGEST);
    assert!(UpdateSignature::verify_for(SignatureDomain::WinVpnV1, X64, "0.2.2", DIGEST, &sig, &keys()));
    assert!(!UpdateSignature::verify_for(SignatureDomain::WinVpnV1, ARM64, "0.2.2", DIGEST, &sig, &keys()));
}

#[test]
fn winvpn_signature_is_bound_to_version_and_hash() {
    let sig = sign_for(&key(2), SignatureDomain::WinVpnV1, ARM64, "0.2.2", DIGEST);
    assert!(UpdateSignature::verify_for(SignatureDomain::WinVpnV1, ARM64, "0.2.2", DIGEST, &sig, &keys()));
    let other = format!("{}0", &DIGEST[..63]);
    assert!(!UpdateSignature::verify_for(SignatureDomain::WinVpnV1, ARM64, "0.2.2", &other, &sig, &keys()));
    assert!(!UpdateSignature::verify_for(SignatureDomain::WinVpnV1, "WinVPN-0.2.3-arm64.msi", "0.2.3", DIGEST, &sig, &keys()));
}
```

- [x] **Step 2: Run them to see them fail**

Run: `cargo test --locked -p macvpn-core --test update`
Expected: FAIL to compile: `cannot find type SignatureDomain in module update`, `no function message_for`, `no function verify_for`.

- [x] **Step 3: Implement** (replace the `UpdateSignature` block in `crates/core/src/update.rs`; the doc comment keeps its first paragraphs and gains the domain paragraph)

```rust
/// Which product's update a signature is for (the first line of the signed message).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureDomain {
    /// MacVPN: `macvpn-update-v1\n<version>\n<sha256>\n`, byte for byte as every MacVPN since 0.2.2 checks it.
    MacVpnV1,
    /// WinVPN: `winvpn-update-v1\n<asset>\n<version>\n<sha256>\n`; the asset is the file name
    /// `WinVPN-<version>-x64.msi` or `WinVPN-<version>-arm64.msi`, so a signature binds the product, the
    /// architecture and the version as well as the bytes.
    WinVpnV1,
}

/// The releases' offline Ed25519 signature.
///
/// The maintainer signs every release asset's SHA-256 with an offline key independent of GitHub
/// (`scripts/sign-release.sh`); the signature is the `<asset>.sig` asset. The app installs only if the signature is
/// valid with one of the embedded public keys, so a compromised GitHub account (or CI) cannot publish an update.
///
/// The signed message, byte for byte, by [`SignatureDomain`]: MacVPN `"macvpn-update-v1\n" + version + "\n" +
/// lower-case sha256 hex + "\n"`; WinVPN `"winvpn-update-v1\n" + asset + "\n" + version + "\n" + sha256 + "\n"`.
/// The version is without `v` (e.g. `0.2.2`). Plain Ed25519 (OpenSSL 3: `pkeyutl -sign -rawin`). The `.sig` is one
/// line: the 64-byte signature in base64, with a trailing newline.
pub struct UpdateSignature;

impl UpdateSignature {
    /// The primary key (in the maintainer's login Keychain). Raw 32 bytes, base64.
    pub const PRIMARY_PUBLIC_KEY_BASE64: &'static str = "KfHXY5gQkjMA3e8bx8rIuPQ4x3zCuSJoMo3PYcMgbFk=";
    /// The backup key (offline, in a password manager), for losing or compromising the primary.
    pub const BACKUP_PUBLIC_KEY_BASE64: &'static str = "QUFfsn9koh06k4EX9lNPognIvQ84/Ox6lgZhShvVrmI=";
    /// The largest `.sig` asset (the real one: 88 characters + newline).
    pub const MAX_SIGNATURE_FILE_SIZE: usize = 1024;
    pub const DOMAIN: &'static str = "macvpn-update-v1";
    pub const WINVPN_DOMAIN: &'static str = "winvpn-update-v1";

    /// The embedded, trusted keys (primary, backup), raw 32 bytes each.
    pub fn trusted_keys() -> Vec<[u8; 32]> {
        [Self::PRIMARY_PUBLIC_KEY_BASE64, Self::BACKUP_PUBLIC_KEY_BASE64]
            .iter()
            .filter_map(|b64| swift_base64::decode(b64)?.try_into().ok())
            .filter(|k: &[u8; 32]| VerifyingKey::from_bytes(k).is_ok())
            .collect()
    }

    /// MacVPN's signed message. `None` if the version is not `X.Y.Z`, or the hash is not 64 lower-case hex digits.
    pub fn message(version: &str, sha256_hex: &str) -> Option<Vec<u8>> {
        Self::message_for(SignatureDomain::MacVpnV1, "", version, sha256_hex)
    }

    /// The signed message of `domain`. MacVPN ignores `asset` (its message has none); WinVPN requires exactly
    /// `WinVPN-<version>-x64.msi` or `WinVPN-<version>-arm64.msi`. `None`: not a message any signature may cover.
    pub fn message_for(domain: SignatureDomain, asset: &str, version: &str, sha256_hex: &str) -> Option<Vec<u8>> {
        if !crate::validators::matches(version, "^[0-9]{1,9}\\.[0-9]{1,9}\\.[0-9]{1,9}$")
            || sha256_hex.len() != 64
            || !sha256_hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return None;
        }
        match domain {
            SignatureDomain::MacVpnV1 => Some(format!("{}\n{version}\n{sha256_hex}\n", Self::DOMAIN).into_bytes()),
            SignatureDomain::WinVpnV1 => {
                let allowed = [format!("WinVPN-{version}-x64.msi"), format!("WinVPN-{version}-arm64.msi")];
                if !allowed.iter().any(|a| a == asset) {
                    return None;
                }
                Some(format!("{}\n{asset}\n{version}\n{sha256_hex}\n", Self::WINVPN_DOMAIN).into_bytes())
            }
        }
    }

    /// MacVPN's verification ([`Self::verify_for`] with [`SignatureDomain::MacVpnV1`]).
    pub fn verify(version: &str, sha256_hex: &str, signature_base64: &str, public_keys: &[[u8; 32]]) -> bool {
        Self::verify_for(SignatureDomain::MacVpnV1, "", version, sha256_hex, signature_base64, public_keys)
    }

    /// Verification is strict (`verify_strict`: also rejects small-order keys and non-canonical points), which
    /// every signature made by `scripts/sign-release.sh` passes.
    ///
    /// True if `signature_base64` (the `.sig` content) is a valid Ed25519 signature of `domain`'s message for
    /// `asset`, `version` and `sha256_hex` with any of `public_keys`. Pure: no network, no file. The hash is the
    /// locally computed SHA-256.
    pub fn verify_for(
        domain: SignatureDomain,
        asset: &str,
        version: &str,
        sha256_hex: &str,
        signature_base64: &str,
        public_keys: &[[u8; 32]],
    ) -> bool {
        if signature_base64.len() > Self::MAX_SIGNATURE_FILE_SIZE {
            return false;
        }
        let Some(message) = Self::message_for(domain, asset, version, sha256_hex) else { return false };
        // One line; a trailing newline (and space) is fine, an inner space or more lines are not.
        let trimmed = signature_base64.trim_matches(swift_str::is_foundation_whitespace_or_newline);
        if trimmed.is_empty() || trimmed.chars().any(char::is_whitespace) {
            return false;
        }
        let Some(bytes) = swift_base64::decode(trimmed) else { return false };
        let Ok(bytes) = <[u8; 64]>::try_from(bytes.as_slice()) else { return false };
        let signature = Signature::from_bytes(&bytes);
        public_keys
            .iter()
            .any(|k| VerifyingKey::from_bytes(k).is_ok_and(|key| key.verify_strict(&message, &signature).is_ok()))
    }

    /// [`Self::verify`] with the embedded keys.
    pub fn verify_trusted(version: &str, sha256_hex: &str, signature_base64: &str) -> bool {
        Self::verify(version, sha256_hex, signature_base64, &Self::trusted_keys())
    }

    /// [`Self::verify_for`] with the embedded keys (the WinVPN updater, 2b).
    pub fn verify_trusted_for(
        domain: SignatureDomain,
        asset: &str,
        version: &str,
        sha256_hex: &str,
        signature_base64: &str,
    ) -> bool {
        Self::verify_for(domain, asset, version, sha256_hex, signature_base64, &Self::trusted_keys())
    }
}
```

- [x] **Step 4: Run the tests**

Run: `cargo test --locked -p macvpn-core --test update && cargo test --locked -p macvpn-platform-mac --test update_installer`
Expected: PASS (the old tests too: `message_format_is_exact`, `signature_valid`, `openssl_rawin_signature_verifies`, the installer's).

- [x] **Step 5: The product names its domain** (failing test first, in `crates/platform-api/tests/product.rs`)

```rust
use macvpn_core::update::SignatureDomain;

#[test]
fn each_product_has_its_signature_domain() {
    assert_eq!(MACVPN.signature_domain, SignatureDomain::MacVpnV1);
    assert_eq!(WINVPN.signature_domain, SignatureDomain::WinVpnV1);
}
```

Run: `cargo test --locked -p macvpn-platform-api --test product` → FAIL (`no field signature_domain`). Then add to `Product` in `crates/platform-api/src/product.rs`:

```rust
    /// The update signature's domain (`UpdateSignature::message_for`): MacVPN's message names no asset, WinVPN's
    /// names the MSI, so a signature of one product or architecture never verifies for another.
    pub signature_domain: macvpn_core::update::SignatureDomain,
```

and `signature_domain: SignatureDomain::MacVpnV1,` in `MACVPN`, `signature_domain: SignatureDomain::WinVpnV1,` in `WINVPN` (import `macvpn_core::update::SignatureDomain`). Run again → PASS.

- [x] **Step 6: `scripts/sign-release.sh` signs every asset with its product's message**

Changes (keep everything else byte for byte):
1. Header comment: replace the "signs" paragraph by

```bash
# CI (release.yml) only creates a *draft* release with MacVPN-X.Y.Z.dmg (and, when WinVPN is released,
# WinVPN-X.Y.Z-x64.msi and WinVPN-X.Y.Z-arm64.msi), each with its .sha256; it never holds the signing key. This
# script downloads them, checks each SHA-256 locally, signs each asset with its product's message:
#   MacVPN-X.Y.Z.dmg           "macvpn-update-v1\n" + X.Y.Z + "\n" + sha256hex + "\n"
#   WinVPN-X.Y.Z-<arch>.msi    "winvpn-update-v1\n" + asset name + "\n" + X.Y.Z + "\n" + sha256hex + "\n"
# with Ed25519 (OpenSSL 3, pkeyutl -rawin), verifies each signature against the public keys embedded in the app
# (parsed from the Rust core, crates/core/src/update.rs, UpdateSignature::PRIMARY_/BACKUP_PUBLIC_KEY_BASE64; the same
# keys as in every app since 0.2.2), uploads the .sig files and publishes the release.
```

and the usage line `#   scripts/sign-release.sh --dry-run (--dmg FILE | --msi FILE --arch x64|arm64) [--backup-key FILE] vX.Y.Z`.

2. Constants and options:

```bash
SIG_DOMAIN="macvpn-update-v1"
WIN_SIG_DOMAIN="winvpn-update-v1"
```

```bash
DRY_MSI=""
DRY_ARCH=""
# in the option loop:
    --msi) [ $# -ge 2 ] || die "--msi needs a file"; DRY_MSI="$2"; shift ;;
    --arch) [ $# -ge 2 ] || die "--arch needs x64 or arm64"; DRY_ARCH="$2"; shift ;;
```

3. Arguments: replace the `DMG_NAME`/`SUM_NAME`/`SIG_NAME` block and the dry-run checks by

```bash
VERSION="${TAG#v}"
DMG_NAME="MacVPN-$VERSION.dmg"
MSI_NAMES=("WinVPN-$VERSION-x64.msi" "WinVPN-$VERSION-arm64.msi")
if [ "$DRY_RUN" = 1 ]; then
  [ "$REPUBLISH" = 0 ] || die "--republish-sig cannot be combined with --dry-run"
  if [ -n "$DRY_DMG" ]; then
    [ -z "$DRY_MSI" ] || die "--dmg and --msi cannot be combined"
    [ -f "$DRY_DMG" ] || die "not a file: $DRY_DMG"
    DRY_FILE="$DRY_DMG"; DRY_ASSET="$DMG_NAME"
  elif [ -n "$DRY_MSI" ]; then
    [ -f "$DRY_MSI" ] || die "not a file: $DRY_MSI"
    [[ "$DRY_ARCH" =~ ^(x64|arm64)$ ]] || die "--msi needs --arch x64 or --arch arm64"
    DRY_FILE="$DRY_MSI"; DRY_ASSET="WinVPN-$VERSION-$DRY_ARCH.msi"
  else
    die "--dry-run needs --dmg FILE or --msi FILE --arch ARCH"
  fi
else
  [ -z "$DRY_DMG$DRY_MSI$DRY_ARCH" ] || die "--dmg, --msi and --arch are only for --dry-run"
fi
```

4. Helpers: `sign_message` and `write_message` take the asset:

```bash
# Writes the signed message of asset $1 with hash $2 to $WORK/message.
write_message() {
  case "$1" in
    "$DMG_NAME") printf '%s\n%s\n%s\n' "$SIG_DOMAIN" "$VERSION" "$2" ;;
    "WinVPN-$VERSION-x64.msi"|"WinVPN-$VERSION-arm64.msi") printf '%s\n%s\n%s\n%s\n' "$WIN_SIG_DOMAIN" "$1" "$VERSION" "$2" ;;
    *) die "no signature domain for the asset $1" ;;
  esac >"$WORK/message"
}

sign_message() { # $1 = asset name; writes $WORK/$1.sig
  local sig_name="$1.sig"
  rm -f "${WORK:?}/signature.bin"
  # (the two signing branches unchanged)
  ...
  [ "$(wc -c <"$WORK/signature.bin" | tr -d ' ')" = 64 ] || die "the signature is not 64 bytes"
  printf '%s\n' "$(base64 <"$WORK/signature.bin" | tr -d '\n')" >"$WORK/$sig_name"
  [ "$(wc -c <"$WORK/$sig_name" | tr -d ' ')" -le 1024 ] || die "the .sig file is larger than 1 KB"
}
```

5. Dry run:

```bash
if [ "$DRY_RUN" = 1 ]; then
  HASH="$(local_sha256 "$DRY_FILE")"
  echo "SHA-256 ($DRY_FILE as $DRY_ASSET): $HASH"
  write_message "$DRY_ASSET" "$HASH"
  sign_message "$DRY_ASSET"
  verify_signature
  echo "signature: $(cat "$WORK/$DRY_ASSET.sig")"
  echo "Dry run: nothing was uploaded or published."
  exit 0
fi
```

6. The GitHub part: build the asset list, check each, sign each, upload each:

```bash
ASSETS=("$DMG_NAME")
MSI_COUNT=0
for name in "${MSI_NAMES[@]}"; do
  [ -n "$(asset_field "$name" url)" ] && MSI_COUNT=$((MSI_COUNT + 1))
done
case "$MSI_COUNT" in
  0) ;;
  2) ASSETS+=("${MSI_NAMES[@]}") ;;
  *) die "the release has only one of ${MSI_NAMES[*]}: both or neither" ;;
esac

# Parallel arrays, not `declare -A`: the maintainer runs this with macOS' /bin/bash 3.2.
HASH_LIST=()
for name in "${ASSETS[@]}"; do
  echo "Downloading $name and $name.sha256…"
  download_asset "$name"
  download_asset "$name.sha256"
  HASH="$(local_sha256 "$WORK/$name")"
  EXPECTED="$(awk -v n="$name" '$2 == n || $2 == "*" n {print tolower($1)}' "$WORK/$name.sha256" | head -n 1)"
  [[ "$EXPECTED" =~ ^[0-9a-f]{64}$ ]] || die "cannot parse $name.sha256"
  [ "$HASH" = "$EXPECTED" ] || die "SHA-256 mismatch for $name: local $HASH, $name.sha256 says $EXPECTED"
  HASH_LIST+=("$HASH")
  echo "  $name: $HASH"
done
echo "Compare these with the 'SHA-256' steps of the release workflow log before signing."
read -r -p "Sign and publish $TAG (${#ASSETS[@]} assets)? [y/N] " ANSWER
[[ "$ANSWER" =~ ^[yY]$ ]] || die "cancelled"

for i in "${!ASSETS[@]}"; do
  write_message "${ASSETS[$i]}" "${HASH_LIST[$i]}"
  sign_message "${ASSETS[$i]}"
  verify_signature
done
for name in "${ASSETS[@]}"; do
  SIG_NAME="$name.sig"
  OLD_SIG_ID="$(asset_field "$SIG_NAME" id)"
  if [ -n "$OLD_SIG_ID" ]; then
    [[ "$OLD_SIG_ID" =~ ^[0-9]+$ ]] || die "unexpected asset id: $OLD_SIG_ID"
    echo "Deleting the existing $SIG_NAME (asset $OLD_SIG_ID)"
    api -X DELETE "$REPO_API/releases/assets/$OLD_SIG_ID" >/dev/null
  fi
  echo "Uploading ${SIG_NAME}…"
  UPLOAD_URL="https://uploads.github.com/repos/$FULL_NAME/releases/$RELEASE_ID/assets?name=$SIG_NAME"
  api -X POST -H "Content-Type: application/octet-stream" --data-binary @"$WORK/$SIG_NAME" "$UPLOAD_URL" >"$WORK/upload.json"
  [ "$(jq -r '.size' "$WORK/upload.json")" = "$(wc -c <"$WORK/$SIG_NAME" | tr -d ' ')" ] || die "upload size mismatch: $SIG_NAME"
done
```

The old single-DMG download, hash, prompt, sign and upload block is removed (this block replaces it); the "Publishing" part after it is unchanged.

- [x] **Step 7: Extend the script test** (`scripts/test-sign-release.sh`, after the DMG checks; keep the Hungarian messages)

```bash
head -c 100000 /dev/urandom >"$T/winvpn.msi"
MHASH="$(shasum -a 256 "$T/winvpn.msi" | awk '{print $1}')"
if OUT="$("$SCRIPT" --dry-run --msi "$T/winvpn.msi" --arch arm64 --backup-key "$T/throwaway.pem" v9.8.7 </dev/null 2>&1)"; then
  ok "msi dry-run lefut"
else
  nok "msi dry-run lefut"; echo "$OUT"
fi
MSIG="$(sed -n 's/^signature: //p' <<<"$OUT")"
printf 'winvpn-update-v1\nWinVPN-9.8.7-arm64.msi\n9.8.7\n%s\n' "$MHASH" >"$T/mmessage"
printf %s "$MSIG" | base64 -d >"$T/msig.bin"
check "az msi aláírása a WinVPN-üzenetre érvényes" \
  "$OPENSSL" pkeyutl -verify -pubin -inkey "$T/throwaway.pub.pem" -rawin -in "$T/mmessage" -sigfile "$T/msig.bin" -out /dev/null
printf 'winvpn-update-v1\nWinVPN-9.8.7-x64.msi\n9.8.7\n%s\n' "$MHASH" >"$T/mmessage2"
if "$OPENSSL" pkeyutl -verify -pubin -inkey "$T/throwaway.pub.pem" -rawin -in "$T/mmessage2" -sigfile "$T/msig.bin" >/dev/null 2>&1; then
  nok "az arm64 aláírás az x64 fájlra nem érvényes"
else
  ok "az arm64 aláírás az x64 fájlra nem érvényes"
fi
expect_fail "--msi --arch nélkül" "$SCRIPT" --dry-run --msi "$T/winvpn.msi" --backup-key "$T/throwaway.pem" v9.8.7
expect_fail "--msi rossz arch" "$SCRIPT" --dry-run --msi "$T/winvpn.msi" --arch x86 --backup-key "$T/throwaway.pem" v9.8.7
expect_fail "--dmg és --msi együtt" "$SCRIPT" --dry-run --dmg "$T/MacVPN-9.8.7.dmg" --msi "$T/winvpn.msi" --arch x64 --backup-key "$T/throwaway.pem" v9.8.7
```

And in `crates/core/tests/update.rs` a Rust counterpart of `sign_release_dry_run_matches_app` for the MSI (`--msi <file> --arch x64`, then `UpdateSignature::verify_for(SignatureDomain::WinVpnV1, "WinVPN-0.2.2-x64.msi", "0.2.2", &local, &sig, &[public])` is true and the same with `"WinVPN-0.2.2-arm64.msi"` is false), named `sign_release_dry_run_msi_matches_app`.

- [x] **Step 8: Run everything touched**

Run: `scripts/test-sign-release.sh && cargo test --locked -p macvpn-core --test update && cargo test --locked -p macvpn-platform-api`
Expected: `# N ok, 0 hiba`, all Rust tests PASS.

- [x] **Step 9: Commit**

```bash
git add crates/core/src/update.rs crates/core/tests/update.rs crates/platform-api/src/product.rs crates/platform-api/tests/product.rs scripts/sign-release.sh scripts/test-sign-release.sh
git commit -m "feat(update): bind WinVPN signatures to the product and the asset" -m "MacVPN keeps macvpn-update-v1 byte for byte. WinVPN signs winvpn-update-v1, the MSI's name, the version and the hash, so a signature of one product or architecture never verifies for another (phase 2 blocker M1). sign-release.sh signs every asset with its product's message." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

## Task 3: `crates/winsys` – SIDs, security descriptors, file identity, randomness

**Goal:** one small crate holds the Win32 calls core's `fsx` and the Windows platform need, behind safe functions, and the cfg/unsafe rule admits it (and nothing else new).

**Files:**
- Create: `crates/winsys/Cargo.toml`, `crates/winsys/src/{lib.rs, util.rs, sid.rs, security.rs, file.rs, random.rs}`, `crates/winsys/tests/winsys.rs`
- Modify: `Cargo.toml` (workspace members), `Cargo.lock` (the new path crate only), `crates/app-core/tests/cfg_rule.rs:21-31`, `scripts/check-windows.sh`, `.github/workflows/ci.yml` (add `-p macvpn-winsys` to the windows test and ignored-count steps)

- [x] **Step 1: The cfg rule admits `crates/winsys/` (failing test first)**

In `crates/app-core/tests/cfg_rule.rs` add a test:

```rust
#[test]
fn the_allow_lists_are_exactly_the_platform_places() {
    assert_eq!(
        CFG_ALLOWED,
        [
            "crates/core/src/fsx/",
            "crates/platform-mac/",
            "crates/platform-win/",
            "crates/winsys/",
            "crates/helper/src/macos/",
            "crates/helper/src/windows/",
            "crates/helper/src/main.rs",
            "app/src-tauri/src/platform/",
        ]
    );
    assert_eq!(UNSAFE_ALLOWED, ["crates/platform-mac/", "crates/platform-win/", "crates/winsys/", "crates/helper/"]);
}
```

Run: `cargo test --locked -p macvpn-app-core --test cfg_rule`
Expected: FAIL (`crates/winsys/` missing). Then add `"crates/winsys/",` after `"crates/platform-win/",` in both constants and update the module doc's two bullet lists the same way. Run again: PASS.

- [x] **Step 2: The crate skeleton**

`crates/winsys/Cargo.toml`:

```toml
[package]
name = "macvpn-winsys"
description = "The Win32 calls MacVPN's core and Windows platform share: SIDs, security descriptors, file identity, randomness, named pipes"
version.workspace = true
edition.workspace = true
license.workspace = true
publish.workspace = true
rust-version.workspace = true

[lib]
name = "macvpn_winsys"

[lints]
workspace = true

# Windows only (the whole crate is `#![cfg(windows)]`): an empty crate on every other target. windows-sys is the
# version Tauri already brings (no new crate in Cargo.lock), pinned exactly.
[target.'cfg(windows)'.dependencies]
windows-sys = { version = "=0.61.2", features = [
    "Win32_Foundation",
    "Win32_Security",
    "Win32_Security_Authorization",
    "Win32_Security_Cryptography",
    "Win32_Storage_FileSystem",
    "Win32_System_IO",
    "Win32_System_Pipes",
    "Win32_System_Threading",
] }
```

`crates/winsys/src/lib.rs`:

```rust
//! The few Win32 calls that MacVPN's core (`fsx`) and the Windows platform both need, behind safe functions:
//! SIDs, security descriptors (the private and shared DACLs), what an open handle says about its file (owner, DACL
//! shape, 128-bit id, link count, reparse tag), the system CSPRNG and, from Task 6, named pipes.
//!
//! Its own crate because core may not contain `unsafe` and cannot depend on `macvpn-platform-win` (which depends on
//! core). It depends on nothing but `windows-sys` and knows nothing of MacVPN. Windows only: on every other target
//! this crate is empty. Every `unsafe` block says why it is sound.

#![cfg(windows)]
// The crate exists to make these calls (crates/app-core/tests/cfg_rule.rs lists it).
#![allow(unsafe_code)]

pub mod file;
pub mod random;
pub mod sid;
mod security;
mod util;
```

Add `"crates/winsys"` to the workspace `members` (after `"crates/platform-win"`), run `cargo metadata --format-version 1 >/dev/null` to update `Cargo.lock`, and check: `git diff Cargo.lock` shows only the new `macvpn-winsys` package (no new registry crate).

`crates/winsys/src/util.rs`:

```rust
use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::core::BOOL;

/// A NUL-terminated UTF-16 copy; an interior NUL is refused (it would cut the path short).
pub(crate) fn wide(s: &OsStr) -> io::Result<Vec<u16>> {
    let mut w: Vec<u16> = s.encode_wide().collect();
    if w.contains(&0) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "a NUL character in a path or name"));
    }
    w.push(0);
    Ok(w)
}

pub(crate) fn wide_path(p: &Path) -> io::Result<Vec<u16>> {
    wide(p.as_os_str())
}

/// `Err(last OS error)` for a FALSE result.
pub(crate) fn check(ok: BOOL) -> io::Result<()> {
    if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

/// Memory the system allocated with `LocalAlloc` (security descriptors from `GetSecurityInfo`).
pub(crate) struct LocalBox(pub(crate) *mut core::ffi::c_void);

impl Drop for LocalBox {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from a system call documented to allocate with LocalAlloc; freed once.
            unsafe { LocalFree(self.0) };
        }
    }
}
```

- [x] **Step 3: Write the failing tests** (`crates/winsys/tests/winsys.rs`)

```rust
//! macvpn-winsys on a real Windows file system (Windows only; the crate is empty elsewhere).

#![cfg(windows)]

use macvpn_winsys::file::{self, Disposition, Open, Protection};
use macvpn_winsys::{random, sid::Sid};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

/// A fresh directory under the user's temp directory, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Scratch {
        static N: AtomicU32 = AtomicU32::new(0);
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let dir = std::env::temp_dir()
            .join(format!("winsys-test-{}-{nanos}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
        fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn new_file(path: &Path, protection: Option<Protection>) -> fs::File {
    file::open(path, Open { protection, ..Open::create_new() }).unwrap()
}

#[test]
fn well_known_sids_have_their_string_form() {
    assert_eq!(Sid::local_system().to_string(), "S-1-5-18");
    assert_eq!(Sid::network().to_string(), "S-1-5-2");
    assert_eq!(Sid::builtin_users().to_string(), "S-1-5-32-545");
}

#[test]
fn the_current_user_is_a_user_sid() {
    let me = Sid::current_user().unwrap();
    let s = me.to_string();
    assert!(s.starts_with("S-1-5-21-") || s.starts_with("S-1-12-1-"), "{s}");
    assert_ne!(me, Sid::local_system());
    assert_eq!(me, Sid::current_user().unwrap());
}

#[test]
fn randomness_fills_and_differs() {
    let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
    random::fill(&mut a).unwrap();
    random::fill(&mut b).unwrap();
    assert_ne!(a, [0u8; 64]);
    assert_ne!(a, b);
    random::fill(&mut []).unwrap();
}

#[test]
fn a_private_file_is_owned_by_the_user_and_readable_by_the_user_and_system_only() {
    let tmp = Scratch::new();
    let f = new_file(&tmp.0.join("p"), Some(Protection::Private));
    let info = file::info(&f).unwrap();
    assert_eq!(info.owner, Sid::current_user().unwrap());
    assert_eq!(info.protection, Some(Protection::Private));
    assert_eq!(info.links, 1);
    assert_eq!(info.reparse_tag, None);
}

#[test]
fn a_shared_file_adds_read_for_users() {
    let tmp = Scratch::new();
    let f = new_file(&tmp.0.join("s"), Some(Protection::Shared));
    assert_eq!(file::info(&f).unwrap().protection, Some(Protection::Shared));
}

#[test]
fn an_inheriting_file_has_neither_shape() {
    let tmp = Scratch::new();
    let f = new_file(&tmp.0.join("i"), None);
    assert_eq!(file::info(&f).unwrap().protection, None);
}

#[test]
fn create_new_refuses_an_existing_file() {
    let tmp = Scratch::new();
    let path = tmp.0.join("x");
    drop(new_file(&path, Some(Protection::Private)));
    let err = file::open(&path, Open { protection: Some(Protection::Private), ..Open::create_new() }).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
}

#[test]
fn protection_can_be_changed_on_the_handle() {
    let tmp = Scratch::new();
    let f = new_file(&tmp.0.join("c"), Some(Protection::Private));
    file::set_protection(&f, Protection::Shared, false).unwrap();
    assert_eq!(file::info(&f).unwrap().protection, Some(Protection::Shared));
    file::set_protection(&f, Protection::Private, false).unwrap();
    assert_eq!(file::info(&f).unwrap().protection, Some(Protection::Private));
}

#[test]
fn hard_links_and_identity() {
    let tmp = Scratch::new();
    let (a, b, c) = (tmp.0.join("a"), tmp.0.join("b"), tmp.0.join("c"));
    let mut fa = new_file(&a, None);
    fa.write_all(b"data").unwrap();
    drop(new_file(&c, None));
    fs::hard_link(&a, &b).unwrap();
    let ia = file::info(&fs::File::open(&a).unwrap()).unwrap();
    let ib = file::info(&fs::File::open(&b).unwrap()).unwrap();
    let ic = file::info(&fs::File::open(&c).unwrap()).unwrap();
    assert_eq!((ia.links, ib.links), (2, 2));
    assert_eq!((ia.volume, ia.id), (ib.volume, ib.id));
    assert_ne!(ia.id, ic.id);
}

#[test]
fn a_private_directory_passes_its_protection_to_new_files() {
    let tmp = Scratch::new();
    let dir = tmp.0.join("d");
    file::create_dir(&dir, Some(Protection::Private)).unwrap();
    let handle = file::open_dir(&dir, false).unwrap();
    let info = file::info(&handle).unwrap();
    assert_eq!(info.protection, Some(Protection::Private));
    // A file created inside without its own descriptor (as SQLite creates its -wal file) gets only the inherited
    // user and SYSTEM entries: not "Private" by shape (not protected), but nobody else is in its DACL.
    let inner = new_file(&dir.join("inner"), None);
    assert!(file::grants_only_owner_and_system(&inner).unwrap());
}

#[test]
fn a_junction_is_seen_as_a_name_surrogate_reparse_point() {
    let tmp = Scratch::new();
    let target = tmp.0.join("target");
    fs::create_dir(&target).unwrap();
    let link = tmp.0.join("link");
    let status = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(&link)
        .arg(&target)
        .status()
        .unwrap();
    assert!(status.success());
    let handle = file::open_dir(&link, false).unwrap();
    let tag = file::info(&handle).unwrap().reparse_tag.expect("a reparse point");
    assert!(file::is_name_surrogate(tag));
    let followed = file::open_dir(&link, true).unwrap();
    assert_eq!(file::info(&followed).unwrap().reparse_tag, None);
}

#[test]
fn reparse_tag_classes() {
    assert!(file::is_name_surrogate(0xA000_000C)); // IO_REPARSE_TAG_SYMLINK
    assert!(file::is_name_surrogate(0xA000_0003)); // IO_REPARSE_TAG_MOUNT_POINT (junction)
    assert!(!file::is_name_surrogate(0x9000_601A)); // a Cloud Files placeholder (OneDrive)
    assert!(!file::is_name_surrogate(0x8000_0013)); // IO_REPARSE_TAG_DEDUP
}
```

- [x] **Step 4: Run them to see them fail**

Run: `scripts/check-windows.sh` after adding `-p macvpn-winsys` to its `PACKAGES` (and to the "OK:" line) — Expected: FAIL to compile (`file`, `random`, `sid` modules are missing).

- [x] **Step 5: `sid.rs`**

```rust
//! Security identifiers.

use crate::util::check;
use std::fmt;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Security::{
    CreateWellKnownSid, GetLengthSid, GetTokenInformation, IsValidSid, PSID, SECURITY_MAX_SID_SIZE, TOKEN_QUERY,
    TOKEN_USER, TokenUser, WELL_KNOWN_SID_TYPE, WinBuiltinUsersSid, WinLocalSystemSid, WinNetworkSid,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// A SID as owned bytes. Built only from SIDs the system produced, so it is always valid.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Sid(Vec<u8>);

impl Sid {
    /// The user this process runs as (the process token's `TokenUser`), read once.
    pub fn current_user() -> io::Result<Sid> {
        static USER: OnceLock<Sid> = OnceLock::new();
        if let Some(sid) = USER.get() {
            return Ok(sid.clone());
        }
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: GetCurrentProcess returns a pseudo handle that needs no closing; `token` is a valid out pointer.
        check(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) })?;
        // SAFETY: OpenProcessToken succeeded, so `token` is a new handle we own.
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let sid = Sid::of_token(token.as_raw_handle())?;
        Ok(USER.get_or_init(|| sid).clone())
    }

    /// The user of an access token opened with `TOKEN_QUERY`.
    pub fn of_token(token: HANDLE) -> io::Result<Sid> {
        let mut len = 0u32;
        // SAFETY: a size query: a null buffer of length 0 is allowed; `len` is a valid out pointer.
        unsafe { GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len) };
        if len == 0 {
            return Err(io::Error::last_os_error());
        }
        // u64 elements: the buffer is aligned for TOKEN_USER.
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        // SAFETY: the buffer has at least `len` bytes, as the size query asked.
        check(unsafe { GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len) })?;
        // SAFETY: the system wrote a TOKEN_USER at the start of the aligned buffer; its SID points into the buffer,
        // which lives until the copy below is made.
        unsafe {
            let user = &*(buf.as_ptr() as *const TOKEN_USER);
            Sid::from_psid(user.User.Sid)
        }
    }

    /// Copies a SID.
    ///
    /// # Safety
    /// `psid` is null or points to memory that holds a SID for the duration of the call.
    pub(crate) unsafe fn from_psid(psid: PSID) -> io::Result<Sid> {
        // SAFETY: by the caller's contract; IsValidSid checks the structure before GetLengthSid reads it.
        unsafe {
            if psid.is_null() || IsValidSid(psid) == 0 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "not a valid SID"));
            }
            let len = GetLengthSid(psid) as usize;
            Ok(Sid(std::slice::from_raw_parts(psid as *const u8, len).to_vec()))
        }
    }

    /// `NT AUTHORITY\SYSTEM` (S-1-5-18).
    pub fn local_system() -> Sid {
        well_known(WinLocalSystemSid)
    }

    /// `NT AUTHORITY\NETWORK` (S-1-5-2): every logon over the network.
    pub fn network() -> Sid {
        well_known(WinNetworkSid)
    }

    /// `BUILTIN\Users` (S-1-5-32-545).
    pub fn builtin_users() -> Sid {
        well_known(WinBuiltinUsersSid)
    }

    /// For the security APIs, which take a non-const pointer but do not write through it.
    pub(crate) fn as_psid(&self) -> PSID {
        self.0.as_ptr().cast_mut().cast()
    }

    pub(crate) fn byte_len(&self) -> usize {
        self.0.len()
    }
}

fn well_known(kind: WELL_KNOWN_SID_TYPE) -> Sid {
    let mut buf = vec![0u8; SECURITY_MAX_SID_SIZE as usize];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` has room for any SID (SECURITY_MAX_SID_SIZE); these kinds need no domain SID.
    let ok = unsafe { CreateWellKnownSid(kind, std::ptr::null_mut(), buf.as_mut_ptr().cast(), &mut len) };
    assert!(ok != 0, "CreateWellKnownSid({kind}) cannot fail for a domain-less SID");
    buf.truncate(len as usize);
    Sid(buf)
}

/// The standard string form (`S-1-5-21-…`), computed from the bytes (MS-DTYP 2.4.2.1): revision, the 48-bit
/// identifier authority (in hex as `0x…` when it does not fit 32 bits), then each sub-authority.
impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        let authority = b[2..8].iter().fold(0u64, |acc, &x| (acc << 8) | u64::from(x));
        if authority >> 32 == 0 {
            write!(f, "S-{}-{authority}", b[0])?;
        } else {
            write!(f, "S-{}-0x{authority:012X}", b[0])?;
        }
        for i in 0..usize::from(b[1]) {
            let at = 8 + 4 * i;
            write!(f, "-{}", u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]))?;
        }
        Ok(())
    }
}

impl fmt::Debug for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
```

- [x] **Step 6: `random.rs`**

```rust
//! The system CSPRNG.

use std::io;
use windows_sys::Win32::Security::Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom};

/// Fills the whole buffer from the system-preferred RNG, or fails (never a partial fill reported as success).
pub fn fill(buf: &mut [u8]) -> io::Result<()> {
    for chunk in buf.chunks_mut(u32::MAX as usize) {
        // SAFETY: `chunk` is valid for writes of `chunk.len()` bytes; no algorithm handle with this flag.
        let status = unsafe {
            BCryptGenRandom(std::ptr::null_mut(), chunk.as_mut_ptr(), chunk.len() as u32, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
        };
        if status != 0 {
            return Err(io::Error::other(format!("BCryptGenRandom failed (NTSTATUS {status:#010x})")));
        }
    }
    Ok(())
}
```

- [x] **Step 7: `security.rs`** (the descriptors; crate-internal, also used by the pipes of Task 6)

```rust
//! Absolute security descriptors with an explicit owner and a protected DACL.

use crate::sid::Sid;
use crate::util::check;
use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_FLAGS, ACL, ACL_REVISION, AddAccessAllowedAceEx, AddAccessDeniedAceEx,
    InitializeAcl, InitializeSecurityDescriptor, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
    SetSecurityDescriptorControl, SetSecurityDescriptorDacl, SetSecurityDescriptorOwner,
};

/// `SECURITY_DESCRIPTOR_REVISION` (winnt.h); defined here so the crate needs no `Win32_System_SystemServices`.
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;

pub(crate) enum Ace<'a> {
    Allow(&'a Sid, u32),
    Deny(&'a Sid, u32),
}

/// An ACL in a u32-aligned buffer.
pub(crate) struct Acl(Vec<u32>);

impl Acl {
    pub(crate) fn new(aces: &[Ace<'_>], flags: ACE_FLAGS) -> io::Result<Acl> {
        let ace_size = |sid: &Sid| size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>() + sid.byte_len();
        let size = size_of::<ACL>()
            + aces.iter().map(|a| match a { Ace::Allow(s, _) | Ace::Deny(s, _) => ace_size(s) }).sum::<usize>();
        let mut buf = vec![0u32; size.div_ceil(4)];
        let acl = buf.as_mut_ptr() as *mut ACL;
        // SAFETY: `buf` is u32-aligned and `size` bytes long, enough for the header and every ACE added below.
        unsafe {
            check(InitializeAcl(acl, (buf.len() * 4) as u32, ACL_REVISION))?;
            for ace in aces {
                match ace {
                    Ace::Allow(sid, mask) => check(AddAccessAllowedAceEx(acl, ACL_REVISION, flags, *mask, sid.as_psid()))?,
                    Ace::Deny(sid, mask) => check(AddAccessDeniedAceEx(acl, ACL_REVISION, flags, *mask, sid.as_psid()))?,
                }
            }
        }
        Ok(Acl(buf))
    }

    pub(crate) fn as_ptr(&self) -> *mut ACL {
        self.0.as_ptr().cast_mut().cast()
    }
}

/// An absolute security descriptor: owner + protected DACL. Owns everything it points to.
pub(crate) struct Descriptor {
    sd: Box<SECURITY_DESCRIPTOR>,
    _owner: Sid,
    acl: Acl,
    attributes: SECURITY_ATTRIBUTES,
}

impl Descriptor {
    pub(crate) fn new(owner: Sid, acl: Acl) -> io::Result<Box<Descriptor>> {
        // SAFETY: SECURITY_DESCRIPTOR is plain data; InitializeSecurityDescriptor sets it up below.
        let sd: Box<SECURITY_DESCRIPTOR> = Box::new(unsafe { std::mem::zeroed() });
        let mut d = Box::new(Descriptor {
            sd,
            _owner: owner,
            acl,
            // SAFETY: plain data, filled in below.
            attributes: unsafe { std::mem::zeroed() },
        });
        let psd = (&mut *d.sd as *mut SECURITY_DESCRIPTOR).cast::<c_void>();
        // SAFETY: `psd` points to the boxed descriptor; the owner SID and the ACL it records live in the same box,
        // so the pointers stay valid as long as the Descriptor (never moved out of its Box).
        unsafe {
            check(InitializeSecurityDescriptor(psd, SECURITY_DESCRIPTOR_REVISION))?;
            check(SetSecurityDescriptorOwner(psd, d._owner.as_psid(), 0))?;
            check(SetSecurityDescriptorDacl(psd, 1, d.acl.as_ptr(), 0))?;
            check(SetSecurityDescriptorControl(psd, SE_DACL_PROTECTED, SE_DACL_PROTECTED))?;
        }
        d.attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: psd,
            bInheritHandle: 0,
        };
        Ok(d)
    }

    /// For `CreateFileW`, `CreateDirectoryW`, `CreateNamedPipeW`.
    pub(crate) fn attributes(&self) -> *const SECURITY_ATTRIBUTES {
        &self.attributes
    }

    pub(crate) fn acl(&self) -> *mut ACL {
        self.acl.as_ptr()
    }
}
```

- [x] **Step 8: `file.rs`**

```rust
//! Files and directories with an explicit owner and DACL, and what an open handle says about its file.

use crate::security::{Ace, Acl, Descriptor};
use crate::sid::Sid;
use crate::util::{LocalBox, check, wide_path};
use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT, SetSecurityInfo};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, GetAce,
    GetSecurityDescriptorControl, INHERITED_ACE, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ALL_ACCESS, FILE_APPEND_DATA,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_ID_INFO,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_ATTRIBUTES,
    FileAttributeTagInfo, FileIdInfo, GetFileInformationByHandle, GetFileInformationByHandleEx, OPEN_ALWAYS,
    OPEN_EXISTING, READ_CONTROL, SYNCHRONIZE, WRITE_DAC,
};

/// The two DACL shapes MacVPN creates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    /// Protected (nothing inherited): the owner and SYSTEM, full access; nobody else (Unix 0600 / 0700).
    Private,
    /// Protected: the owner and SYSTEM full access, `BUILTIN\Users` read (Unix 0644 / 0755).
    Shared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Fails with `AlreadyExists` when anything (a file, a link) has the name.
    CreateNew,
    OpenOrCreate,
    OpenExisting,
}

/// How [`open`] opens or creates a file.
#[derive(Debug, Clone, Copy)]
pub struct Open {
    pub read: bool,
    pub write: bool,
    /// Writes always go to the end (`FILE_APPEND_DATA` without `FILE_WRITE_DATA`).
    pub append: bool,
    pub disposition: Disposition,
    /// The DACL of a newly created file (owner = this user); `None`: the folder's inherited permissions.
    pub protection: Option<Protection>,
    /// Open a reparse point itself, never its target.
    pub no_follow: bool,
}

impl Open {
    /// Write, create new, private, never through a reparse point: `fsx::create_new`'s defaults.
    pub fn create_new() -> Open {
        Open {
            read: false,
            write: true,
            append: false,
            disposition: Disposition::CreateNew,
            protection: Some(Protection::Private),
            no_follow: true,
        }
    }
}

/// What an open handle says about its file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    pub owner: Sid,
    /// The DACL's shape: one of MacVPN's, or `None` (inherited or anything else).
    pub protection: Option<Protection>,
    pub volume: u64,
    /// The 128-bit file id (ReFS needs all of it; NTFS uses the low 64 bits).
    pub id: [u8; 16],
    pub links: u32,
    pub attributes: u32,
    /// The reparse tag when the handle is a reparse point (opened with `no_follow`).
    pub reparse_tag: Option<u32>,
}

fn descriptor(protection: Protection, dir: bool) -> io::Result<Box<Descriptor>> {
    let (owner, system) = (Sid::current_user()?, Sid::local_system());
    let flags = if dir { OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE } else { 0 };
    let acl = match protection {
        Protection::Private => Acl::new(&[Ace::Allow(&owner, FILE_ALL_ACCESS), Ace::Allow(&system, FILE_ALL_ACCESS)], flags)?,
        Protection::Shared => {
            let users = Sid::builtin_users();
            Acl::new(
                &[
                    Ace::Allow(&owner, FILE_ALL_ACCESS),
                    Ace::Allow(&system, FILE_ALL_ACCESS),
                    Ace::Allow(&users, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE),
                ],
                flags,
            )?
        }
    };
    Descriptor::new(owner, acl)
}

fn handle_to_file(handle: HANDLE) -> io::Result<File> {
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a valid handle that CreateFileW just returned and nobody else owns.
    Ok(File::from(unsafe { OwnedHandle::from_raw_handle(handle) }))
}

/// Opens or creates `path` as `o` says. Every handle also has `READ_CONTROL` and `FILE_READ_ATTRIBUTES` (for
/// [`info`]) and, for a writable one, `WRITE_DAC` (for [`set_protection`]). Sharing as std's default (read, write,
/// delete), so renames over the file keep working.
pub fn open(path: &Path, o: Open) -> io::Result<File> {
    let name = wide_path(path)?;
    let mut access = READ_CONTROL | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
    if o.read {
        access |= FILE_GENERIC_READ;
    }
    if o.append {
        access |= FILE_APPEND_DATA | FILE_WRITE_ATTRIBUTES | WRITE_DAC;
    } else if o.write {
        access |= FILE_GENERIC_WRITE | WRITE_DAC;
    }
    let disposition = match o.disposition {
        Disposition::CreateNew => CREATE_NEW,
        Disposition::OpenOrCreate => OPEN_ALWAYS,
        Disposition::OpenExisting => OPEN_EXISTING,
    };
    let flags = FILE_ATTRIBUTE_NORMAL | if o.no_follow { FILE_FLAG_OPEN_REPARSE_POINT } else { 0 };
    let sd = o.protection.map(|p| descriptor(p, false)).transpose()?;
    let sa = sd.as_ref().map_or(std::ptr::null(), |d| d.attributes());
    // SAFETY: `name` is NUL-terminated; `sa` is null or points into `sd`, alive across the call.
    let handle = unsafe {
        CreateFileW(name.as_ptr(), access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, sa, disposition, flags, std::ptr::null_mut())
    };
    handle_to_file(handle)
}

/// Creates one directory (not its parents) with `protection` (inheritable to what is created inside), or with
/// the parent's inherited permissions for `None`.
pub fn create_dir(path: &Path, protection: Option<Protection>) -> io::Result<()> {
    let name = wide_path(path)?;
    let sd = protection.map(|p| descriptor(p, true)).transpose()?;
    let sa = sd.as_ref().map_or(std::ptr::null(), |d| d.attributes());
    // SAFETY: as in `open`.
    check(unsafe { CreateDirectoryW(name.as_ptr(), sa) })
}

/// Opens a directory (or any file) for its metadata and DACL: `READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES`,
/// with backup semantics (needed for directories; no privilege is used). `follow`: `false` opens a reparse point
/// itself.
pub fn open_dir(path: &Path, follow: bool) -> io::Result<File> {
    open_for_metadata(path, follow, READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES)
}

/// Like [`open_dir`] without `WRITE_DAC`: for reading only (`fsx::stat_path`).
pub fn open_metadata(path: &Path, follow: bool) -> io::Result<File> {
    open_for_metadata(path, follow, READ_CONTROL | FILE_READ_ATTRIBUTES)
}

fn open_for_metadata(path: &Path, follow: bool, access: u32) -> io::Result<File> {
    let name = wide_path(path)?;
    let flags = FILE_FLAG_BACKUP_SEMANTICS | if follow { 0 } else { FILE_FLAG_OPEN_REPARSE_POINT };
    // SAFETY: as in `open`; no security attributes (nothing is created).
    let handle = unsafe {
        CreateFileW(name.as_ptr(), access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, std::ptr::null(), OPEN_EXISTING, flags, std::ptr::null_mut())
    };
    handle_to_file(handle)
}

/// Owner, DACL shape, identity, link count, attributes and reparse tag of an open file. The handle needs
/// `READ_CONTROL` (every handle std opens for reading or writing has it).
pub fn info(file: &File) -> io::Result<Info> {
    let h = file.as_raw_handle();
    let (owner, protection) = owner_and_protection(h)?;
    // SAFETY: plain data structs the calls fill in; the sizes passed are theirs.
    let mut basic: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    check(unsafe { GetFileInformationByHandle(h, &mut basic) })?;
    let mut id_info: FILE_ID_INFO = unsafe { std::mem::zeroed() };
    let (volume, id) = if unsafe {
        GetFileInformationByHandleEx(h, FileIdInfo, (&mut id_info as *mut FILE_ID_INFO).cast(), size_of::<FILE_ID_INFO>() as u32)
    } != 0
    {
        (id_info.VolumeSerialNumber, id_info.FileId.Identifier)
    } else {
        // FAT and some network file systems have no 128-bit id: the 64-bit index of the basic information.
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&((u64::from(basic.nFileIndexHigh) << 32) | u64::from(basic.nFileIndexLow)).to_le_bytes());
        (u64::from(basic.dwVolumeSerialNumber), id)
    };
    let reparse_tag = if basic.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        let mut tag: FILE_ATTRIBUTE_TAG_INFO = unsafe { std::mem::zeroed() };
        check(unsafe {
            GetFileInformationByHandleEx(h, FileAttributeTagInfo, (&mut tag as *mut FILE_ATTRIBUTE_TAG_INFO).cast(), size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32)
        })?;
        Some(tag.ReparseTag)
    } else {
        None
    };
    Ok(Info { owner, protection, volume, id, links: basic.nNumberOfLinks, attributes: basic.dwFileAttributes, reparse_tag })
}

/// Whether every ACE of the file's DACL is an allow ACE for its owner or SYSTEM (inherited ones included): the
/// test for files that others (SQLite) create inside a private directory.
pub fn grants_only_owner_and_system(file: &File) -> io::Result<bool> {
    with_security(file.as_raw_handle(), |owner, dacl, _control| {
        let system = Sid::local_system();
        // SAFETY: `dacl` comes from GetSecurityInfo and lives while `with_security` holds the descriptor.
        let aces = unsafe { aces(dacl)? };
        Ok(!dacl.is_null() && aces.iter().all(|(allow, sid, _, _)| *allow && (sid == owner || *sid == system)))
    })
}

/// Sets the DACL of an open file or directory to `protection` (protected, nothing inherited). The handle needs
/// `WRITE_DAC` (files from [`open`] with write or append; directories from [`open_dir`]). The owner is not changed.
pub fn set_protection(file: &File, protection: Protection, dir: bool) -> io::Result<()> {
    let d = descriptor(protection, dir)?;
    // SAFETY: the handle is valid; the ACL lives in `d` across the call; owner and SACL are not set.
    let err = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            d.acl(),
            std::ptr::null(),
        )
    };
    if err != 0 { Err(io::Error::from_raw_os_error(err as i32)) } else { Ok(()) }
}

/// Name-surrogate reparse points point at another name (symlinks, junctions, mount points); the others (Cloud Files
/// placeholders, dedup, WOF compression) are the file itself.
pub fn is_name_surrogate(tag: u32) -> bool {
    tag & 0x2000_0000 != 0
}

/// Runs `f` with the owner, the DACL (possibly null) and the control bits of `h`'s security descriptor.
fn with_security<T>(h: HANDLE, f: impl FnOnce(&Sid, *const ACL, u16) -> io::Result<T>) -> io::Result<T> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: valid out pointers; on success `sd` is LocalAlloc'ed and `owner`/`dacl` point into it.
    let err = unsafe {
        GetSecurityInfo(h, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &mut owner, std::ptr::null_mut(), &mut dacl, std::ptr::null_mut(), &mut sd)
    };
    if err != 0 {
        return Err(io::Error::from_raw_os_error(err as i32));
    }
    let _sd = LocalBox(sd);
    // SAFETY: `owner` points into `sd`, alive until `_sd` drops at the end of this function.
    let owner = unsafe { Sid::from_psid(owner)? };
    let (mut control, mut revision) = (0u16, 0u32);
    // SAFETY: `sd` is a valid descriptor.
    check(unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut revision) })?;
    f(&owner, dacl, control)
}

fn owner_and_protection(h: HANDLE) -> io::Result<(Sid, Option<Protection>)> {
    with_security(h, |owner, dacl, control| {
        if dacl.is_null() || control & SE_DACL_PROTECTED == 0 {
            return Ok((owner.clone(), None));
        }
        // SAFETY: `dacl` is valid while `with_security` holds the descriptor.
        let aces = unsafe { aces(dacl)? };
        let system = Sid::local_system();
        let users = Sid::builtin_users();
        let explicit = aces.iter().all(|(allow, _, _, flags)| *allow && flags & INHERITED_ACE as u8 == 0);
        let has = |sid: &Sid, mask: u32| aces.iter().any(|(_, s, m, _)| s == sid && *m == mask);
        let shape = if !explicit {
            None
        } else if aces.len() == 2 && has(owner, FILE_ALL_ACCESS) && has(&system, FILE_ALL_ACCESS) {
            Some(Protection::Private)
        } else if aces.len() == 3
            && has(owner, FILE_ALL_ACCESS)
            && has(&system, FILE_ALL_ACCESS)
            && has(&users, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE)
        {
            Some(Protection::Shared)
        } else {
            None
        };
        Ok((owner.clone(), shape))
    })
}

/// Every ACE of a DACL as (allow, SID, mask, flags); an ACE of any other type counts as a deny (never "allow").
///
/// # Safety
/// `dacl` is null or a valid ACL that stays alive during the call.
unsafe fn aces(dacl: *const ACL) -> io::Result<Vec<(bool, Sid, u32, u8)>> {
    if dacl.is_null() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    // SAFETY: by the contract; GetAce bounds-checks the index against AceCount.
    unsafe {
        for i in 0..u32::from((*dacl).AceCount) {
            let mut ace: *mut c_void = std::ptr::null_mut();
            check(GetAce(dacl, i, &mut ace))?;
            let header = &*(ace as *const ACE_HEADER);
            let allowed = &*(ace as *const ACCESS_ALLOWED_ACE);
            let sid = Sid::from_psid((&allowed.SidStart as *const u32).cast_mut().cast())?;
            // ACCESS_ALLOWED_ACE_TYPE is 0, ACCESS_DENIED_ACE_TYPE 1; both have this layout.
            out.push((header.AceType == 0, sid, allowed.Mask, header.AceFlags));
        }
    }
    Ok(out)
}
```

The code reads ACEs of non-allow, non-deny types (object ACEs) with the allow layout only to get a SID; such an ACE makes the shape `None` because `header.AceType != 0` and the shape requires every ACE to be an allow ACE.

- [x] **Step 9: Compile on the Mac, test on Windows**

Run: `scripts/check-windows.sh`
Expected: `OK: …` including `macvpn-winsys` for both targets, debug and release.

Run: `scripts/win-remote.sh run 'cargo test --locked -p macvpn-winsys'`
Expected: every test in `crates/winsys/tests/winsys.rs` PASSES.

Run (Mac), for both macOS targets: `cargo tree --locked -e normal --target aarch64-apple-darwin -p macvpn-app -p macvpn-helper --prefix none | grep -E '^(windows|macvpn-winsys)'` (prints nothing)
Expected: `error: package ID specification \`windows-sys\` did not match any packages` or no output for both (no macOS binary links it).

- [x] **Step 10: CI lists the crate**

In `.github/workflows/ci.yml`, job `windows`: add `-p macvpn-winsys` to both `cargo test` lines (the test step and the ignored-count step).

- [x] **Step 11: Commit**

```bash
git add Cargo.toml Cargo.lock crates/winsys crates/app-core/tests/cfg_rule.rs scripts/check-windows.sh .github/workflows/ci.yml
git commit -m "feat(winsys): SIDs, private and shared DACLs, file identity and randomness on Windows" -m "A small binding crate for the Win32 calls core's fsx and the Windows platform share; core cannot hold unsafe and cannot depend on platform-win. The cfg/unsafe rule admits crates/winsys/." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

## Task 4: `fsx::Stat` – checks from a handle (portable; Unix byte-identical)

**Goal:** `owner`, `has_access`, `file_id` and `hard_links` take an `fsx::Stat`, which Windows can fill from an open handle (Task 8). On Unix every call site makes exactly the syscall it made before. Windows stays fail-closed in this task.

**Files:**
- Modify: `crates/core/src/fsx/{mod.rs, unix.rs, windows.rs}`, `crates/core/Cargo.toml` (`[target.'cfg(windows)'.dependencies] macvpn-winsys = { path = "../winsys" }`, for the owner constructors below)
- Modify: `crates/core/src/{mfa.rs, exporter.rs, log.rs, store.rs}`, `crates/core/src/vault/{keys.rs, db.rs}` (and any other compile error the type change shows: `catalog/source.rs`, `vault/sealed.rs`, `importer.rs`, `crates/app-core/src/import_export.rs` use `open_regular`'s metadata through `Deref` and should need no change)
- Modify: `app/src-tauri/src/control.rs:795-796` (test)
- Test: `crates/core/tests/fsx.rs`

- [x] **Step 1: Write the failing tests** (`crates/core/tests/fsx.rs`, Unix; update the existing calls as listed in Step 3 first only where they no longer compile after Step 3 – here only add)

```rust
#[test]
fn stat_path_follows_only_when_asked() {
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path()).unwrap();
    let real = tmp.path().join("real");
    fs::write(&real, b"x").unwrap();
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert!(fsx::stat_path(&link, Follow::No).unwrap().file_type().is_symlink());
    let followed = fsx::stat_path(&link, Follow::Yes).unwrap();
    assert!(followed.file_type().is_file());
    assert_eq!(followed.ino(), fs::metadata(&real).unwrap().ino());
}

#[test]
fn stat_of_an_open_file_is_its_fstat() {
    let tmp = TempDir::new();
    fs::create_dir_all(tmp.path()).unwrap();
    let path = tmp.path().join("f");
    fs::write(&path, b"abc").unwrap();
    let file = fs::File::open(&path).unwrap();
    let stat = fsx::stat(&file).unwrap();
    assert_eq!(stat.len(), 3);
    assert_eq!(stat.ino(), file.metadata().unwrap().ino());
    assert_eq!(fsx::owner(&stat).unwrap(), FileOwner::from_uid(stat.uid()));
    assert_eq!(fsx::hard_links(&stat), 1);
}
```

Run: `cargo test --locked -p macvpn-core --test fsx`
Expected: FAIL to compile (`no function stat_path`, `no function stat`).

- [x] **Step 2: The portable API** (`crates/core/src/fsx/mod.rs`; replace the four `&Metadata` functions and `open_regular`'s return type)

```rust
/// What the system says about a file: its [`Metadata`] (`Stat` derefs to it) plus, where the platform reads them
/// from an open handle (Windows), the owner, the access shape, the identity and the link count.
#[derive(Debug, Clone)]
pub struct Stat {
    meta: Metadata,
    extra: imp::Extra,
}

impl std::ops::Deref for Stat {
    type Target = Metadata;
    fn deref(&self) -> &Metadata {
        &self.meta
    }
}

/// The open file's [`Stat`] (Unix: `fstat`).
pub fn stat(file: &File) -> io::Result<Stat> {
    imp::stat(file)
}

/// The [`Stat`] of the file at `path` (Unix: `lstat` for [`Follow::No`], `stat` for [`Follow::Yes`]).
pub fn stat_path(path: &Path, follow: Follow) -> io::Result<Stat> {
    imp::stat_path(path, follow)
}

/// Opens with `O_NONBLOCK` (never hangs on a FIFO), checks the open descriptor (`fstat`) and refuses anything but
/// a regular file ([`not_regular_file`]), then clears `O_NONBLOCK`. `follow`: [`Follow::No`] refuses a symlink as
/// the last component ([`is_symlink_refused`]). `noctty`: also `O_NOCTTY`. Returns the file and its [`Stat`].
pub fn open_regular(path: &Path, open: OpenFor, follow: Follow, noctty: bool) -> io::Result<(File, Stat)> {
    imp::open_regular(path, open, follow, noctty)
}

/// Whether the permissions are exactly `access` (Unix: `mode & 0o7777` is 0600 / 0644 for a file, 0700 / 0755 for
/// a directory; Windows: the DACL shape, see `macvpn_winsys::file::Protection`).
pub fn has_access(stat: &Stat, access: Access) -> bool {
    imp::has_access(stat, access)
}

/// The owner of a file.
pub fn owner(stat: &Stat) -> io::Result<FileOwner> {
    imp::owner(stat).map(FileOwner)
}

/// The identity of a file; `None` where the platform cannot tell.
pub fn file_id(stat: &Stat) -> Option<FileId> {
    imp::file_id(stat).map(FileId)
}

/// The number of hard links, never less than the real one: where the platform cannot tell it is `u64::MAX`, so a
/// caller that acts only on a single link (`store::shred_file`) fails closed.
pub fn hard_links(stat: &Stat) -> u64 {
    imp::hard_links(stat)
}
```

`Stat` is built only inside `fsx` (`Stat { meta, extra }` in `unix.rs`/`windows.rs`; child modules see the private fields).

The Windows owner constructors (in `mod.rs`, next to `from_uid`):

```rust
impl FileOwner {
    /// The owner with this SID string (`S-1-5-21-…`).
    #[cfg(windows)]
    pub fn from_sid(sid: String) -> FileOwner {
        FileOwner(sid)
    }

    /// The user this process runs as (Windows knows it without the platform layer).
    #[cfg(windows)]
    pub fn current_user() -> io::Result<FileOwner> {
        macvpn_winsys::sid::Sid::current_user().map(|s| FileOwner(s.to_string()))
    }
}
```

(`owner()` stays `Err(Unsupported)` on Windows until Task 8, so no comparison can succeed yet: fail closed.)

- [x] **Step 3: Unix: the same syscalls** (`crates/core/src/fsx/unix.rs`)

```rust
use super::Stat;

/// Unix needs nothing beyond the metadata.
pub(super) type Extra = ();

pub(super) fn stat(file: &File) -> io::Result<Stat> {
    Ok(Stat { meta: file.metadata()?, extra: () })
}

pub(super) fn stat_path(path: &Path, follow: Follow) -> io::Result<Stat> {
    let meta = match follow {
        Follow::No => fs::symlink_metadata(path)?,
        Follow::Yes => fs::metadata(path)?,
    };
    Ok(Stat { meta, extra: () })
}
```

`open_regular` returns `Ok((clear_nonblocking(file)?, Stat { meta, extra: () }))`; `has_access`, `owner`, `file_id`, `hard_links` take `stat: &Stat` and read `stat.meta` exactly as before (`stat.meta.mode()`, `stat.meta.uid()`, `(stat.meta.dev(), stat.meta.ino())`, `stat.meta.nlink()`); `ensure_private_dir` is unchanged.

Windows (`crates/core/src/fsx/windows.rs`), still fail-closed in this task, but the owner type becomes the SID string so the platform can name the user now (Task 9 needs it before Task 8 lands):

```rust
use super::Stat;

/// The owner's SID in its string form (`S-1-5-21-…`).
pub(super) type OwnerId = String;
/// Filled from the open handle from Task 8 on; empty until then.
pub(super) type Extra = ();

pub(super) fn stat(file: &File) -> io::Result<Stat> {
    Ok(Stat { meta: file.metadata()?, extra: () })
}

pub(super) fn stat_path(path: &Path, follow: Follow) -> io::Result<Stat> {
    let meta = match follow {
        Follow::No => std::fs::symlink_metadata(path)?,
        Follow::Yes => std::fs::metadata(path)?,
    };
    Ok(Stat { meta, extra: () })
}
```

with `open_regular` returning `Stat { meta, extra: () }` and the four check functions taking `&Stat` (same fail-closed bodies).

- [x] **Step 4: The call sites** (each makes the same syscall as before on Unix)

| File | Before | After |
|---|---|---|
| `vault/keys.rs:307` | `fsx::owner(&fs::metadata(dir).map_err(KeyError::Io)?)` | `fsx::owner(&fsx::stat_path(dir, Follow::Yes).map_err(KeyError::Io)?)` |
| `vault/db.rs:196` | `fsx::owner(&file.metadata()?)?` | `fsx::owner(&fsx::stat(&file)?)?` |
| `vault/db.rs:231` | `let meta = fs::symlink_metadata(&path)?;` | `let meta = fsx::stat_path(&path, fsx::Follow::No)?;` |
| `exporter.rs:147` | `file.metadata()` | `fsx::stat(&file)` |
| `exporter.rs:148` | `fs::symlink_metadata(&tmp)` | `fsx::stat_path(&tmp, fsx::Follow::No)` (import `Follow`) |
| `log.rs:127` | `file.metadata().ok().and_then(\|m\| fsx::file_id(&m))` | `fsx::stat(&file).ok().and_then(\|s\| fsx::file_id(&s))` |
| `mfa.rs:621`, `store.rs:167`, `keys.rs:309` | `open_regular`'s metadata | unchanged (it is a `Stat` now) |
| `app/src-tauri/src/control.rs:795-796` (test) | `fsx::has_access(&fs::metadata(&path).unwrap(), …)` | `fsx::has_access(&fsx::stat_path(&path, Follow::Yes).unwrap(), …)` |
| `crates/core/tests/fsx.rs` | `fsx::has_access(&fs::metadata(x).unwrap(), …)`, `fsx::owner(&fs::metadata(x).unwrap())`, `fsx::hard_links(&meta)` with `meta` from `fs::metadata`, `fsx::file_id(&fs::metadata(x).unwrap())`, `fsx::file_id(&File::open(x).unwrap().metadata().unwrap())` | `fsx::stat_path(x, Follow::Yes)` resp. `fsx::stat(&File::open(x).unwrap())` |

- [x] **Step 5: Run everything**

Run: `cargo fmt --all && cargo clippy --workspace --all-targets --locked -- -D warnings && CI=1 cargo test --workspace --locked && scripts/check-windows.sh && cargo test --locked -p macvpn-app-core --test compat_1_4`
Expected: all PASS, including the two new tests; `compat_1_4` unchanged.

- [x] **Step 6: Commit**

```bash
git add crates/core/src crates/core/tests/fsx.rs app/src-tauri/src/control.rs
git commit -m "refactor(fsx): owner, access, identity and links from an fsx::Stat" -m "Windows reads these from an open handle; on Unix each call site keeps its fstat / lstat / stat. The existing fsx, vault, exporter, mfa and store tests guard the behaviour." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

## Task 5: importer paths on Windows (phase 2 blocker)

**Goal:** referenced files of an imported OpenVPN config resolve on Windows (`\\?\C:\…` canonical paths, `\` separators, drive letters) with the same refusals as on macOS; macOS accepts and refuses exactly what it did; the 24 importer ignores go.

**Files:**
- Modify: `crates/core/src/importer.rs:428-579, 607-624`
- Modify: `crates/core/src/fsx/{mod.rs, unix.rs, windows.rs}` (two small helpers; shared with Task 4 if run in the same wave: add only)
- Test: `crates/core/tests/importer.rs`

- [x] **Step 1: Write the failing tests** (`crates/core/tests/importer.rs`; the `Env` helper is the file's existing one)

```rust
/// The importer's decisions on Unix, pinned: every case keeps what the text-based check of 1.5.0 decided.
#[test]
#[cfg(unix)]
fn unix_decisions_are_unchanged() {
    let env = Env::new();
    env.put("ca.crt", CERT);
    fs::create_dir_all(env.dir.join("sub")).unwrap();
    env.put("sub/ca.crt", CERT);
    env.put("a:b.crt", CERT); // a colon is an ordinary file name character on Unix
    let base = env.dir.display().to_string();
    for ok in ["ca.crt", "./ca.crt", "sub/../ca.crt", "sub//ca.crt", "a:b.crt", &format!("{base}/ca.crt"), &format!("{base}/sub/ca.crt")] {
        assert!(env.inline(&format!("ca {ok}\n")).is_ok(), "{ok}");
    }
    env.rejected("ca ../x.crt", ConfigImportError::OutsideBaseDirectory("../x.crt".into()));
    env.rejected("ca /etc/hosts", ConfigImportError::OutsideBaseDirectory("/etc/hosts".into()));
    env.rejected("ca missing.crt", ConfigImportError::MissingFile("missing.crt".into()));
    env.rejected("ca .", ConfigImportError::OutsideBaseDirectory(".".into()));
    env.rejected(&format!("ca {base}"), ConfigImportError::OutsideBaseDirectory(base.clone()));
    assert!(!lexically_escapes("a\\..\\..\\b"), "a backslash is a name character on Unix");
}

#[test]
#[cfg(windows)]
fn windows_paths_resolve_like_unix_ones() {
    let env = Env::new();
    env.put("ca.crt", CERT);
    fs::create_dir_all(env.dir.join("sub")).unwrap();
    env.put("sub/ca.crt", CERT);
    let base = env.dir.display().to_string();
    for ok in ["ca.crt", "sub\\ca.crt", "sub/ca.crt", ".\\sub\\..\\ca.crt", &format!("{base}\\ca.crt"), &format!("{base}/sub/ca.crt")] {
        assert!(env.inline(&format!("ca \"{ok}\"\n")).is_ok(), "{ok}");
    }
    env.rejected("ca ..\\x.crt", ConfigImportError::OutsideBaseDirectory("..\\x.crt".into()));
    env.rejected("ca C:\\Windows\\win.ini", ConfigImportError::OutsideBaseDirectory("C:\\Windows\\win.ini".into()));
    env.rejected("ca ca.crt:hidden", ConfigImportError::MissingFile("ca.crt:hidden".into()));
    env.rejected("ca \\\\localhost\\c$\\x.crt", ConfigImportError::MissingFile("\\\\localhost\\c$\\x.crt".into()));
    assert!(lexically_escapes("a\\..\\..\\b"));
    assert!(!lexically_escapes("C:\\x\\..\\..\\y"), "absolute: checked after resolving");
}
```

(If `Env::rejected` / `Env::inline` take the config differently, follow the file's helpers; `lexically_escapes` is `macvpn_core::importer::lexically_escapes`. The UNC case: `\\localhost\c$` needs admin rights to exist; for a standard user it does not resolve, so it is `MissingFile` – the point is that it is never read. If the test machine's account can reach it, the expected error is `OutsideBaseDirectory`; assert `matches!(…, MissingFile(_) | OutsideBaseDirectory(_))` for that one case.)

Run (Mac): `cargo test --locked -p macvpn-core --test importer unix_decisions_are_unchanged`
Expected: PASS already for everything but `ca .` and `ca <base>` if the text check answered differently: record the outcome. The text check refuses `.` and `<base>` (the canonical path equals the base, which lacks the trailing `/`), so this test pins that.

Run: `scripts/win-remote.sh run 'cargo test --locked -p macvpn-core --test importer windows_paths_resolve_like_unix_ones'`
Expected: FAIL (`MissingFile("sub\\ca.crt")` or `OutsideBaseDirectory`).

- [x] **Step 2: Two fsx helpers** (`crates/core/src/fsx/mod.rs`)

```rust
/// Whether `c` separates path components in a path a user typed (Unix: `/`; Windows: `/` and `\`).
pub fn is_separator(c: char) -> bool {
    imp::is_separator(c)
}

/// Whether a referenced path names an alternate data stream (Windows: a component with `:` after the drive).
/// Always `false` on Unix, where `:` is an ordinary file name character.
pub fn names_a_stream(path: &Path) -> bool {
    imp::names_a_stream(path)
}
```

`unix.rs`:

```rust
pub(super) fn is_separator(c: char) -> bool {
    c == '/'
}

pub(super) fn names_a_stream(_path: &Path) -> bool {
    false
}
```

`windows.rs`:

```rust
pub(super) fn is_separator(c: char) -> bool {
    c == '/' || c == '\\'
}

/// A `Normal` component with a `:` (the drive is a `Prefix` component, so `C:\x` is not a stream).
pub(super) fn names_a_stream(path: &Path) -> bool {
    path.components().any(|c| matches!(c, std::path::Component::Normal(s) if s.to_string_lossy().contains(':')))
}
```

- [x] **Step 3: The importer** (`crates/core/src/importer.rs`)

```rust
pub fn inline_openvpn_files(content: &str, base_directory: &Path) -> Result<InlineResult, ConfigImportError> {
    // A canonical, UTF-8 base (as before: a base that is not UTF-8 counts as missing).
    let base = std::fs::canonicalize(base_directory)
        .ok()
        .filter(|p| p.to_str().is_some())
        .ok_or_else(|| ConfigImportError::MissingFile(base_directory.to_string_lossy().into_owned()))?;
    // … unchanged, with `&base` now a `&Path` …
}

fn read_credential_lines(path: &str, base: &Path) -> Option<Vec<String>> { /* unchanged body */ }
fn read_inline_file(path: &str, base: &Path, directive: &str) -> Result<String, ConfigImportError> { /* unchanged body */ }

/// Absolute for the importer: a root (`/x`, `\x`) or a drive / UNC prefix (`C:x`, `C:\x`, `\\server\share`).
/// Such a path is not joined to the base; the containment check below decides.
fn is_absolute_reference(path: &Path) -> bool {
    path.has_root() || matches!(path.components().next(), Some(std::path::Component::Prefix(_)))
}

fn read_inline_data(path: &str, base: &Path) -> Result<Vec<u8>, ConfigImportError> {
    let missing = || ConfigImportError::MissingFile(path.to_string());
    // `realpath` takes a C string: it ends at the first NUL (kept on every OS).
    let referenced = Path::new(path.split('\0').next().unwrap_or_default());
    if fsx::names_a_stream(referenced) {
        return Err(missing());
    }
    let joined = if is_absolute_reference(referenced) { referenced.to_path_buf() } else { base.join(referenced) };
    let Some(resolved) = std::fs::canonicalize(&joined).ok().filter(|p| p.to_str().is_some()) else {
        // Missing: if it already points outside textually, say that.
        return Err(if lexically_escapes(path) {
            ConfigImportError::OutsideBaseDirectory(path.to_string())
        } else {
            missing()
        });
    };
    // Component-wise containment on canonical paths. The base itself is outside (the old text check compared
    // with `base + "/"`); only the root as the base contains itself, as `"/"` did.
    let inside = resolved.starts_with(base) && (resolved != base || base.parent().is_none());
    if !inside {
        return Err(ConfigImportError::OutsideBaseDirectory(path.to_string()));
    }
    // Not a regular file (or unreadable): missing.
    let (file, meta) = fsx::open_regular(&resolved, OpenFor::Read, Follow::No, false).map_err(|_| missing())?;
    if meta.len() > MAX_INLINE_FILE_SIZE as u64 {
        return Err(ConfigImportError::FileTooLarge(path.to_string()));
    }
    let mut data = Vec::new();
    let _ = file.take(MAX_INLINE_FILE_SIZE as u64 + 1).read_to_end(&mut data);
    if data.len() > MAX_INLINE_FILE_SIZE {
        return Err(ConfigImportError::FileTooLarge(path.to_string()));
    }
    Ok(data)
}

/// A relative path that gets above the starting folder with `..` (an absolute path is checked by realpath).
/// Components are split on `fsx::is_separator` (`/`; on Windows also `\`).
pub fn lexically_escapes(path: &str) -> bool {
    if is_absolute_reference(Path::new(path)) {
        return false;
    }
    let normalized: String = path.chars().map(|c| if fsx::is_separator(c) { '/' } else { c }).collect();
    let mut depth = 0i64;
    for part in swift_str::split(&normalized, "/", usize::MAX, true) {
        if swift_str::eq(part, "..") {
            depth -= 1;
        } else if !swift_str::eq(part, ".") {
            depth += 1;
        }
        if depth < 0 {
            return true;
        }
    }
    false
}
```

On Unix `is_absolute_reference(Path::new(p))` is `p.starts_with('/')` (no prefixes exist), `fsx::is_separator` is `/` only (the `map` is the identity), and `base.join(p)` for a relative `p` is the old `format!("{base}/{p}")`.

- [x] **Step 4: Remove the 24 importer ignores**

Run: `grep -n 'the importer resolves file paths as Unix strings' crates/core/tests/importer.rs | wc -l` → `24`. Delete each `#[cfg_attr(windows, ignore = "the importer resolves file paths as Unix strings: phase 2")]` line (`sed -i '' '/the importer resolves file paths as Unix strings: phase 2/d' crates/core/tests/importer.rs`), then the grep prints `0`.

- [x] **Step 5: Run the tests on both systems**

Run: `CI=1 cargo test --locked -p macvpn-core --test importer && cargo test --locked -p macvpn-app-core --test compat_1_4`
Expected: PASS (macOS).

Run: `scripts/win-remote.sh run 'cargo test --locked -p macvpn-core --test importer'`
Expected: PASS, `0 ignored` for the importer file (tests that also need private files are not in this file). A test that fails only because a fixture uses `/` inside a *config line's absolute path* (e.g. `format!("{}/ca.crt", env.dir.display())`) is fine on Windows (`/` is a separator there); a test that fails because it builds an absolute Unix path such as `/etc/hosts` keeps its Unix meaning only under `#[cfg(unix)]`: give it a Windows twin with `C:\Windows\win.ini` instead of ignoring it.

- [x] **Step 6: Commit**

```bash
git add crates/core/src/importer.rs crates/core/src/fsx crates/core/tests/importer.rs
git commit -m "fix(importer): resolve referenced files with Path joins and component-wise containment" -m "Windows canonical paths are \\\\?\\C:\\…, so the text prefix check refused every referenced file there. On Unix the decisions are the same (pinned by unix_decisions_are_unchanged). Alternate data streams are refused on Windows. The 24 Windows ignores of the importer tests are gone." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

## Task 6: `winsys::pipe` – named pipes with identity, timeouts and clean shutdown

**Goal:** the server side (bind once per name, accept with a poll interval, the client's SID, PID and image path) and the client side (identification-only impersonation, the server must be the same user) over one stream type with exact timeouts, clones and shutdown.

**Files:**
- Create: `crates/winsys/src/pipe.rs`, `crates/winsys/tests/pipe.rs`
- Modify: `crates/winsys/src/lib.rs` (`pub mod pipe;`), `crates/winsys/src/file.rs` (`with_security` takes the object type; see Step 3)

- [x] **Step 1: Write the failing tests** (`crates/winsys/tests/pipe.rs`)

```rust
//! Named pipes on a real Windows system.

#![cfg(windows)]

use macvpn_winsys::pipe::{self, Listener, PipeStream};
use macvpn_winsys::sid::Sid;
use std::io::{ErrorKind, Read, Write};
use std::net::Shutdown;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;
use std::time::{Duration, Instant};

fn unique_name() -> String {
    static N: AtomicU32 = AtomicU32::new(0);
    format!(r"\\.\pipe\winsys-test-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst))
}

/// A connected pair: (server side, client side, the server's view of the peer).
fn pair() -> (Listener, PipeStream, PipeStream, pipe::Peer) {
    let name = unique_name();
    let listener = Listener::bind(&name).unwrap();
    let client_name = name.clone();
    let client = thread::spawn(move || pipe::connect(&client_name, Duration::from_secs(5)).unwrap());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some((server, peer)) = listener.accept(Duration::from_millis(50)).unwrap() {
            return (listener, server, client.join().unwrap(), peer.unwrap());
        }
        assert!(Instant::now() < deadline, "no client within 5 s");
    }
}

#[test]
fn the_peer_is_this_process_and_user() {
    let (_l, _s, _c, peer) = pair();
    assert_eq!(peer.sid, Sid::current_user().unwrap());
    assert_eq!(peer.pid, std::process::id());
    let exe = std::env::current_exe().unwrap();
    let image = peer.image.expect("the image path");
    assert!(image.to_string_lossy().eq_ignore_ascii_case(&exe.to_string_lossy()), "{image:?} vs {exe:?}");
}

#[test]
fn a_second_bind_of_the_same_name_is_addr_in_use() {
    let name = unique_name();
    let _first = Listener::bind(&name).unwrap();
    assert_eq!(Listener::bind(&name).err().unwrap().kind(), ErrorKind::AddrInUse);
}

#[test]
fn accept_without_a_client_is_idle_after_the_poll() {
    let listener = Listener::bind(&unique_name()).unwrap();
    let start = Instant::now();
    assert!(listener.accept(Duration::from_millis(100)).unwrap().is_none());
    assert!(start.elapsed() >= Duration::from_millis(90));
}

#[test]
fn bytes_flow_both_ways_and_clones_share_the_stream() {
    let (_l, server, client, _) = pair();
    (&client).write_all(b"hello\n").unwrap();
    let mut buf = [0u8; 6];
    (&server).read_exact(&mut buf).unwrap();
    assert_eq!(&buf, b"hello\n");
    let clone = server.try_clone();
    (&clone).write_all(b"ok").unwrap();
    let mut two = [0u8; 2];
    (&client).read_exact(&mut two).unwrap();
    assert_eq!(&two, b"ok");
}

#[test]
fn a_read_times_out_exactly() {
    let (_l, server, _client, _) = pair();
    server.set_read_timeout(Some(Duration::from_millis(150))).unwrap();
    let start = Instant::now();
    let err = (&server).read(&mut [0u8; 1]).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::TimedOut);
    assert!(start.elapsed() < Duration::from_secs(2));
    assert_eq!(server.set_read_timeout(Some(Duration::ZERO)).unwrap_err().kind(), ErrorKind::InvalidInput);
}

#[test]
fn shutdown_read_ends_a_blocked_read() {
    let (_l, server, _client, _) = pair();
    let reader = server.try_clone();
    let blocked = thread::spawn(move || (&reader).read(&mut [0u8; 8]).unwrap());
    thread::sleep(Duration::from_millis(100));
    server.shutdown(Shutdown::Read).unwrap();
    assert_eq!(blocked.join().unwrap(), 0);
}

#[test]
fn the_client_closing_is_eof_for_the_server_and_data_sent_before_survives() {
    let (_l, server, client, _) = pair();
    (&server).write_all(b"bye").unwrap();
    server.shutdown(Shutdown::Both).unwrap();
    let mut got = Vec::new();
    (&client).read_to_end(&mut got).unwrap();
    assert_eq!(got, b"bye");
    client.shutdown(Shutdown::Both).unwrap();
    assert!(!client.peer_connected());
}

#[test]
fn peer_connected_follows_the_other_end() {
    let (_l, server, client, _) = pair();
    assert!(server.peer_connected());
    client.shutdown(Shutdown::Both).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while server.peer_connected() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn connecting_to_a_missing_pipe_is_not_found() {
    assert_eq!(pipe::connect(&unique_name(), Duration::from_millis(200)).unwrap_err().kind(), ErrorKind::NotFound);
}

#[test]
fn an_anonymous_client_cannot_be_identified() {
    use std::os::windows::fs::OpenOptionsExt;
    let name = unique_name();
    let listener = Listener::bind(&name).unwrap();
    // SECURITY_ANONYMOUS: std adds SECURITY_SQOS_PRESENT to the flags it is given.
    let _anon = std::fs::OpenOptions::new().read(true).write(true).security_qos_flags(0).open(&name).unwrap();
    let (_server, peer) = listener.accept(Duration::from_secs(2)).unwrap().expect("the client");
    assert!(peer.is_err());
}

#[test]
fn the_pipe_denies_the_network_and_admits_only_the_user_and_system() {
    let (_l, server, _c, _) = pair();
    let user = Sid::current_user().unwrap().to_string();
    assert_eq!(
        pipe::dacl_summary(&server).unwrap(),
        [(false, "S-1-5-2".to_string()), (true, user), (true, "S-1-5-18".to_string())]
    );
}

#[test]
fn user_pipe_names_carry_the_sid() {
    let name = pipe::user_pipe_name("WinVPN-control").unwrap();
    assert_eq!(name, format!(r"\\.\pipe\WinVPN-control-{}", Sid::current_user().unwrap()));
}
```

Run: `scripts/check-windows.sh` → FAIL to compile (no `pipe` module).

- [x] **Step 2: `pipe.rs`**

```rust
//! Named pipes. The server: [`Listener::bind`] (first instance; a name in use is `AddrInUse`), [`Listener::accept`]
//! (waits at most a poll interval; the client's SID from identification-level impersonation, its PID and image
//! path). The client: [`connect`] (identification-level only; refuses a server of another user). Both sides use
//! [`PipeStream`]: overlapped I/O with one event per operation, exact timeouts, clones, shutdown.

use crate::security::{Ace, Acl, Descriptor};
use crate::sid::Sid;
use crate::util::{check, wide};
use std::ffi::{OsStr, OsString};
use std::io::{self, ErrorKind, Read, Write};
use std::net::Shutdown;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_NO_DATA, ERROR_OPERATION_ABORTED,
    ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED, GENERIC_READ, GENERIC_WRITE, GetLastError,
    HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::{RevertToSelf, TOKEN_QUERY};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ALL_ACCESS, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
    PIPE_ACCESS_DUPLEX, ReadFile, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, WriteFile,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
    ImpersonateNamedPipeClient, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT, PeekNamedPipe, WaitNamedPipeW,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentThread, INFINITE, OpenProcess, OpenProcessToken, OpenThreadToken,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW, WaitForSingleObject,
};

const BUFFER: u32 = 64 * 1024;

/// `\\.\pipe\<prefix>-<this user's SID>`.
pub fn user_pipe_name(prefix: &str) -> io::Result<String> {
    Ok(format!(r"\\.\pipe\{prefix}-{}", Sid::current_user()?))
}

/// The process on the other end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub sid: Sid,
    pub pid: u32,
    /// `None` if the image path could not be read.
    pub image: Option<PathBuf>,
}

fn owned(handle: HANDLE) -> io::Result<OwnedHandle> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a valid handle a system call just returned; nobody else owns it.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

fn event() -> io::Result<OwnedHandle> {
    // SAFETY: an unnamed manual-reset event, initially not signalled.
    owned(unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) })
}

fn millis(d: Duration) -> u32 {
    d.as_millis().clamp(1, u128::from(INFINITE - 1)) as u32
}

/// The pipe's descriptor: owner = this user; protected DACL: deny NETWORK, allow this user (all access, needed to
/// create further instances) and SYSTEM.
fn descriptor() -> io::Result<Box<Descriptor>> {
    let (user, system, network) = (Sid::current_user()?, Sid::local_system(), Sid::network());
    let acl = Acl::new(
        &[Ace::Deny(&network, FILE_ALL_ACCESS), Ace::Allow(&user, FILE_ALL_ACCESS), Ace::Allow(&system, FILE_ALL_ACCESS)],
        0,
    )?;
    Descriptor::new(user, acl)
}

fn create_instance(name: &[u16], d: &Descriptor, first: bool) -> io::Result<OwnedHandle> {
    let open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | if first { FILE_FLAG_FIRST_PIPE_INSTANCE } else { 0 };
    let pipe_mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
    // SAFETY: `name` is NUL-terminated; the attributes point into `d`, alive across the call.
    let h = unsafe {
        CreateNamedPipeW(name.as_ptr(), open_mode, pipe_mode, PIPE_UNLIMITED_INSTANCES, BUFFER, BUFFER, 0, d.attributes())
    };
    owned(h)
}

/// One pipe instance waiting for its client.
struct Pending {
    pipe: Option<OwnedHandle>,
    _event: OwnedHandle,
    overlapped: Box<OVERLAPPED>,
    connected: bool,
}

impl Pending {
    fn start(pipe: OwnedHandle) -> io::Result<Pending> {
        let ev = event()?;
        // SAFETY: OVERLAPPED is plain data.
        let mut overlapped: Box<OVERLAPPED> = Box::new(unsafe { std::mem::zeroed() });
        overlapped.hEvent = ev.as_raw_handle();
        // SAFETY: the OVERLAPPED is boxed (a stable address) and outlives the operation: Drop waits for it.
        let ok = unsafe { ConnectNamedPipe(pipe.as_raw_handle(), &mut *overlapped) };
        let connected = if ok != 0 {
            true
        } else {
            // SAFETY: plain call.
            match unsafe { GetLastError() } {
                ERROR_IO_PENDING => false,
                ERROR_PIPE_CONNECTED => true,
                e => return Err(io::Error::from_raw_os_error(e as i32)),
            }
        };
        Ok(Pending { pipe: Some(pipe), _event: ev, overlapped, connected })
    }
}

impl Drop for Pending {
    /// A connect still in flight is cancelled and waited for, so the kernel is done with the OVERLAPPED.
    fn drop(&mut self) {
        if let (Some(pipe), false) = (&self.pipe, self.connected) {
            let mut n = 0u32;
            // SAFETY: the handle and the OVERLAPPED are alive; waiting makes sure the kernel releases the latter.
            unsafe {
                CancelIoEx(pipe.as_raw_handle(), &*self.overlapped);
                GetOverlappedResult(pipe.as_raw_handle(), &*self.overlapped, &mut n, 1);
            }
        }
    }
}

/// The server side of a pipe name.
pub struct Listener {
    name: Vec<u16>,
    descriptor: Box<Descriptor>,
    pending: Mutex<Option<Pending>>,
}

// SAFETY: the raw pointers inside (the descriptor's SID/ACL pointers, the OVERLAPPED's event handle) point into
// heap memory and handles this Listener owns; nothing is tied to a thread, and the pending instance is only touched
// under the Mutex. The control server moves the listener to its accept thread (`ControlListener: Send`).
unsafe impl Send for Listener {}
// SAFETY: as above; every method takes `&self` and serializes through the Mutex (the descriptor is read-only).
unsafe impl Sync for Listener {}

impl Listener {
    /// Creates the first instance of `name`. A name that exists already (another server, or a squatter) is
    /// `AddrInUse`.
    pub fn bind(name: &str) -> io::Result<Listener> {
        let wide_name = wide(OsStr::new(name))?;
        let descriptor = descriptor()?;
        let first = create_instance(&wide_name, &descriptor, true).map_err(|e| {
            match e.raw_os_error().map(|c| c as u32) {
                Some(ERROR_ACCESS_DENIED) | Some(ERROR_PIPE_BUSY) => io::Error::new(ErrorKind::AddrInUse, "the pipe name is in use"),
                _ => e,
            }
        })?;
        let pending = Pending::start(first)?;
        Ok(Listener { name: wide_name, descriptor, pending: Mutex::new(Some(pending)) })
    }

    /// Waits at most `poll` for a client: `Ok(None)` when none came (or one came and went at once). The next
    /// instance is created before the client is returned, so the name never disappears while serving.
    pub fn accept(&self, poll: Duration) -> io::Result<Option<(PipeStream, io::Result<Peer>)>> {
        let mut slot = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        if slot.is_none() {
            *slot = Some(Pending::start(create_instance(&self.name, &self.descriptor, false)?)?);
        }
        let pending = slot.as_mut().expect("just filled");
        if !pending.connected {
            let pipe = pending.pipe.as_ref().expect("a pending instance has its pipe").as_raw_handle();
            // SAFETY: the event belongs to the pending operation.
            match unsafe { WaitForSingleObject(pending.overlapped.hEvent, millis(poll)) } {
                WAIT_OBJECT_0 => {}
                WAIT_TIMEOUT => return Ok(None),
                _ => return Err(io::Error::last_os_error()),
            }
            let mut n = 0u32;
            // SAFETY: the operation has completed (its event is signalled).
            if unsafe { GetOverlappedResult(pipe, &*pending.overlapped, &mut n, 0) } == 0 {
                // The client left before we accepted: drop this instance; the next call starts a new one.
                *slot = None;
                return Ok(None);
            }
            pending.connected = true;
        }
        let mut done = slot.take().expect("connected instance");
        let pipe = done.pipe.take().expect("its pipe");
        drop(done);
        *slot = Pending::start(create_instance(&self.name, &self.descriptor, false)?).ok();
        let peer = peer_of(pipe.as_raw_handle());
        Ok(Some((PipeStream::new(pipe), peer)))
    }
}

fn peer_of(pipe: HANDLE) -> io::Result<Peer> {
    let mut pid = 0u32;
    // SAFETY: a connected server instance; `pid` is a valid out pointer.
    check(unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) })?;
    Ok(Peer { sid: client_sid(pipe)?, pid, image: process_image(pid).ok() })
}

/// The client's user, from identification-level impersonation. The thread reverts at once; if it cannot, the
/// process aborts: it must never keep running as the client.
fn client_sid(pipe: HANDLE) -> io::Result<Sid> {
    // SAFETY: a connected server instance. The impersonation is ended below on every path.
    check(unsafe { ImpersonateNamedPipeClient(pipe) })?;
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: valid out pointer; `OpenAsSelf` = TRUE (the access check uses the process's own context).
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) };
    let open_error = io::Error::last_os_error();
    // SAFETY: plain call.
    if unsafe { RevertToSelf() } == 0 {
        std::process::abort();
    }
    if opened == 0 {
        return Err(open_error);
    }
    let token = owned(token)?;
    Sid::of_token(token.as_raw_handle())
}

fn open_process(pid: u32) -> io::Result<OwnedHandle> {
    // SAFETY: plain call; the handle is owned by the result.
    owned(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) })
}

/// The full Win32 path of a process's executable.
pub fn process_image(pid: u32) -> io::Result<PathBuf> {
    let process = open_process(pid)?;
    let mut buf = vec![0u16; 32_768];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` holds `len` u16s; the call writes at most that many and updates `len`.
    check(unsafe { QueryFullProcessImageNameW(process.as_raw_handle(), PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len) })?;
    Ok(PathBuf::from(OsString::from_wide(&buf[..len as usize])))
}

/// The user a process runs as.
pub fn process_user(pid: u32) -> io::Result<Sid> {
    let process = open_process(pid)?;
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: valid process handle and out pointer.
    check(unsafe { OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut token) })?;
    let token = owned(token)?;
    Sid::of_token(token.as_raw_handle())
}

/// Connects as a client with identification-level impersonation only, and refuses a server process of another
/// user (`PermissionDenied`): a squatter never gets to read what the client sends. `NotFound`: no such pipe.
pub fn connect(name: &str, timeout: Duration) -> io::Result<PipeStream> {
    let wide_name = wide(OsStr::new(name))?;
    let deadline = Instant::now() + timeout;
    loop {
        // SAFETY: `wide_name` is NUL-terminated; no security attributes.
        let h = unsafe {
            CreateFileW(
                wide_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                std::ptr::null_mut(),
            )
        };
        if h != INVALID_HANDLE_VALUE {
            let pipe = owned(h)?;
            let mut pid = 0u32;
            // SAFETY: a connected client handle; valid out pointer.
            check(unsafe { GetNamedPipeServerProcessId(pipe.as_raw_handle(), &mut pid) })?;
            if process_user(pid)? != Sid::current_user()? {
                return Err(io::Error::new(ErrorKind::PermissionDenied, "the pipe is served by another user"));
            }
            return Ok(PipeStream::new(pipe));
        }
        // SAFETY: plain call.
        let error = unsafe { GetLastError() };
        if error != ERROR_PIPE_BUSY {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::from(ErrorKind::TimedOut));
        }
        // SAFETY: as above. The result does not matter: the loop tries again until the deadline.
        unsafe { WaitNamedPipeW(wide_name.as_ptr(), millis(left)) };
    }
}

/// One end of a connected pipe. Clones share the handle, the timeouts and the shutdown state (like
/// `UnixStream::try_clone`).
#[derive(Clone)]
pub struct PipeStream(Arc<Inner>);

struct Inner {
    /// `None` once shut down. Operations hold it shared for their whole duration; the close holds it exclusive,
    /// so a closed handle value is never used again.
    handle: RwLock<Option<OwnedHandle>>,
    read_timeout: Mutex<Option<Duration>>,
    write_timeout: Mutex<Option<Duration>>,
    read_shut: AtomicBool,
    /// The address of the OVERLAPPED of the read in flight (0: none), for `shutdown(Read)`.
    pending_read: Mutex<usize>,
}

fn is_closed(e: &io::Error) -> bool {
    matches!(e.raw_os_error().map(|c| c as u32), Some(ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED | ERROR_NO_DATA))
}

impl PipeStream {
    fn new(handle: OwnedHandle) -> PipeStream {
        PipeStream(Arc::new(Inner {
            handle: RwLock::new(Some(handle)),
            read_timeout: Mutex::new(None),
            write_timeout: Mutex::new(None),
            read_shut: AtomicBool::new(false),
            pending_read: Mutex::new(0),
        }))
    }

    pub fn try_clone(&self) -> PipeStream {
        self.clone()
    }

    /// `Some(Duration::ZERO)` is `InvalidInput`, as for sockets.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        if timeout == Some(Duration::ZERO) {
            return Err(io::Error::from(ErrorKind::InvalidInput));
        }
        *self.0.read_timeout.lock().unwrap_or_else(PoisonError::into_inner) = timeout;
        Ok(())
    }

    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        if timeout == Some(Duration::ZERO) {
            return Err(io::Error::from(ErrorKind::InvalidInput));
        }
        *self.0.write_timeout.lock().unwrap_or_else(PoisonError::into_inner) = timeout;
        Ok(())
    }

    /// `Ok(0)` at the end: the peer closed, or this side shut reading down. A timeout is `TimedOut`.
    pub fn read_some(&self, buf: &mut [u8]) -> io::Result<usize> {
        if self.0.read_shut.load(Ordering::SeqCst) {
            return Ok(0);
        }
        let guard = self.0.handle.read().unwrap_or_else(PoisonError::into_inner);
        let Some(h) = guard.as_ref().map(AsRawHandle::as_raw_handle) else { return Ok(0) };
        let timeout = *self.0.read_timeout.lock().unwrap_or_else(PoisonError::into_inner);
        let len = buf.len().min(u32::MAX as usize) as u32;
        let ptr = buf.as_mut_ptr();
        // SAFETY: `buf` stays borrowed until `overlapped` returns, which is after the kernel finished with it.
        let result = overlapped(h, timeout, Some(&self.0.pending_read), |ov| unsafe {
            ReadFile(h, ptr, len, std::ptr::null_mut(), ov)
        });
        match result {
            Ok(n) => Ok(n as usize),
            Err(e) if is_closed(&e) => Ok(0),
            Err(e)
                if e.raw_os_error() == Some(ERROR_OPERATION_ABORTED as i32) && self.0.read_shut.load(Ordering::SeqCst) =>
            {
                Ok(0)
            }
            Err(e) => Err(e),
        }
    }

    /// A closed pipe is `BrokenPipe`. A timeout is `TimedOut`.
    pub fn write_some(&self, buf: &[u8]) -> io::Result<usize> {
        let guard = self.0.handle.read().unwrap_or_else(PoisonError::into_inner);
        let Some(h) = guard.as_ref().map(AsRawHandle::as_raw_handle) else {
            return Err(io::Error::from(ErrorKind::BrokenPipe));
        };
        let timeout = *self.0.write_timeout.lock().unwrap_or_else(PoisonError::into_inner);
        let len = buf.len().min(u32::MAX as usize) as u32;
        // SAFETY: as in `read_some`.
        let result = overlapped(h, timeout, None, |ov| unsafe { WriteFile(h, buf.as_ptr(), len, std::ptr::null_mut(), ov) });
        match result {
            Ok(n) => Ok(n as usize),
            Err(e) if is_closed(&e) => Err(io::Error::new(ErrorKind::BrokenPipe, e)),
            Err(e) => Err(e),
        }
    }

    /// `Read`: reads return `Ok(0)` from now on (a blocked read too). `Write` and `Both`: also every operation in
    /// flight ends and the handle is closed (the peer then reads what was sent, then the end); a pipe has no
    /// half-close, so `Write` is `Both`.
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.0.read_shut.store(true, Ordering::SeqCst);
        if how == Shutdown::Read {
            let pending = *self.0.pending_read.lock().unwrap_or_else(PoisonError::into_inner);
            if pending != 0
                && let Some(h) = self.0.handle.read().unwrap_or_else(PoisonError::into_inner).as_ref()
            {
                // SAFETY: cancelling an OVERLAPPED that already completed is harmless (ERROR_NOT_FOUND).
                unsafe { CancelIoEx(h.as_raw_handle(), pending as *const OVERLAPPED) };
            }
            return Ok(());
        }
        loop {
            if let Some(h) = self.0.handle.read().unwrap_or_else(PoisonError::into_inner).as_ref() {
                // SAFETY: cancels every operation on the handle; each waits for its own cancellation.
                unsafe { CancelIoEx(h.as_raw_handle(), std::ptr::null()) };
            }
            match self.0.handle.try_write() {
                Ok(mut guard) => {
                    guard.take();
                    return Ok(());
                }
                // An operation started after the cancel: cancel again (it is at most a few microseconds old).
                Err(std::sync::TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(1)),
                Err(std::sync::TryLockError::Poisoned(p)) => {
                    p.into_inner().take();
                    return Ok(());
                }
            }
        }
    }

    /// Still connected, without blocking and without consuming data.
    pub fn peer_connected(&self) -> bool {
        let guard = self.0.handle.read().unwrap_or_else(PoisonError::into_inner);
        let Some(h) = guard.as_ref() else { return false };
        let mut available = 0u32;
        // SAFETY: a zero-length peek with only the "available" out pointer.
        unsafe {
            PeekNamedPipe(h.as_raw_handle(), std::ptr::null_mut(), 0, std::ptr::null_mut(), &mut available, std::ptr::null_mut())
                != 0
        }
    }
}

/// One overlapped operation with its own event, waited for at most `timeout`. A timed-out operation is cancelled
/// and waited for (the kernel must be done with the OVERLAPPED); if it completed in that race its result counts.
fn overlapped(
    h: HANDLE,
    timeout: Option<Duration>,
    track: Option<&Mutex<usize>>,
    start: impl FnOnce(*mut OVERLAPPED) -> windows_sys::core::BOOL,
) -> io::Result<u32> {
    let ev = event()?;
    // SAFETY: OVERLAPPED is plain data.
    let mut ov: Box<OVERLAPPED> = Box::new(unsafe { std::mem::zeroed() });
    ov.hEvent = ev.as_raw_handle();
    let ptr: *mut OVERLAPPED = &mut *ov;
    if let Some(t) = track {
        *t.lock().unwrap_or_else(PoisonError::into_inner) = ptr as usize;
    }
    let finish = |wait: bool| -> io::Result<u32> {
        let mut n = 0u32;
        // SAFETY: `ptr` is alive (boxed, dropped after this function); `wait` blocks until the kernel is done.
        check(unsafe { GetOverlappedResult(h, ptr, &mut n, i32::from(wait)) }).map(|()| n)
    };
    let result = if start(ptr) != 0 {
        finish(true)
    } else {
        // SAFETY: plain call.
        let error = unsafe { GetLastError() };
        if error != ERROR_IO_PENDING {
            Err(io::Error::from_raw_os_error(error as i32))
        } else {
            // SAFETY: the event belongs to this operation.
            match unsafe { WaitForSingleObject(ev.as_raw_handle(), timeout.map_or(INFINITE, millis)) } {
                WAIT_OBJECT_0 => finish(true),
                waited => {
                    // SAFETY: cancels only this operation.
                    unsafe { CancelIoEx(h, ptr) };
                    match finish(true) {
                        Ok(n) => Ok(n),
                        Err(e) if waited == WAIT_TIMEOUT && e.raw_os_error() == Some(ERROR_OPERATION_ABORTED as i32) => {
                            Err(io::Error::from(ErrorKind::TimedOut))
                        }
                        Err(e) => Err(e),
                    }
                }
            }
        }
    };
    if let Some(t) = track {
        *t.lock().unwrap_or_else(PoisonError::into_inner) = 0;
    }
    drop(ov);
    result
}

impl Read for &PipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_some(buf)
    }
}

impl Write for &PipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_some(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for PipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_some(buf)
    }
}

impl Write for PipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_some(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The pipe's DACL as (allow, SID string) in order (tests and the security review).
pub fn dacl_summary(stream: &PipeStream) -> io::Result<Vec<(bool, String)>> {
    let guard = stream.0.handle.read().unwrap_or_else(PoisonError::into_inner);
    let h = guard.as_ref().ok_or_else(|| io::Error::from(ErrorKind::NotConnected))?;
    crate::file::dacl_entries(h.as_raw_handle(), true)
}
```

- [x] **Step 3: `file.rs` reads a kernel object's DACL too**

Change `with_security(h, f)` to `with_security(h, kernel_object: bool, f)` passing `SE_KERNEL_OBJECT` instead of `SE_FILE_OBJECT` when `kernel_object` is true (named pipe handles are kernel objects for the security API), update its two callers with `false`, and add:

```rust
/// Every ACE of the handle's DACL as (allow, SID string), in order.
pub(crate) fn dacl_entries(h: HANDLE, kernel_object: bool) -> io::Result<Vec<(bool, String)>> {
    with_security(h, kernel_object, |_owner, dacl, _control| {
        // SAFETY: `dacl` is valid while `with_security` holds the descriptor.
        Ok(unsafe { aces(dacl)? }.into_iter().map(|(allow, sid, _, _)| (allow, sid.to_string())).collect())
    })
}
```

(`aces` reports an ACCESS_DENIED ACE as `allow = false`, since its type is 1.)

- [x] **Step 4: Run the tests on Windows**

Run: `scripts/check-windows.sh && scripts/win-remote.sh run 'cargo test --locked -p macvpn-winsys --test pipe -- --test-threads=4'`
Expected: every test PASSES. Then run it ten times in a row to catch races: `scripts/win-remote.sh run 'for i in 1 2 3 4 5 6 7 8 9 10; do cargo test --locked -q -p macvpn-winsys --test pipe || exit 1; done'` → PASS ten times.

- [x] **Step 5: Commit**

```bash
git add crates/winsys
git commit -m "feat(winsys): named pipes with the peer's identity, exact timeouts and clean shutdown" -m "Server: first-instance bind (a taken name is AddrInUse), accept with a poll interval, the client's SID through identification-level impersonation (abort if RevertToSelf fails), PID and image path; DACL: deny NETWORK, allow the user and SYSTEM; remote clients rejected. Client: identification-only, refuses a server of another user." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

## Task 7: platform-api and app-core additions (portable, macOS unchanged)

**Goal:** the few portable pieces WinVPN needs: a file-backed `PreferenceStore`, the System Status engine note, the tray tint, all with defaults that leave macOS exactly as it is.

**Files:**
- Modify: `crates/platform-api/src/prefs.rs`, `crates/platform-api/src/lib.rs` (re-export `FilePreferences`), `crates/platform-api/src/setup.rs`, `crates/platform-api/src/ui.rs`, `crates/platform-api/Cargo.toml` (`serde_json` if not yet a dependency: use the workspace's exact version `1.0.154`)
- Modify: `crates/app-core/src/setup.rs` (`SetupView::engine_note`, `with_engine_note`)
- Test: `crates/platform-api/tests/file_preferences.rs`, `crates/app-core/tests/system_status.rs`

- [x] **Step 1: Write the failing tests**

`crates/platform-api/tests/file_preferences.rs`:

```rust
//! FilePreferences: the JSON preference file in the private data directory (WinVPN).

use macvpn_core::date::Date;
use macvpn_platform_api::{FilePreferences, PreferenceStore};
use std::fs;
use std::path::PathBuf;

fn scratch() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("file-prefs-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
#[cfg_attr(not(unix), ignore = "needs fsx private files (Task 8 removes this on Windows)")]
fn values_survive_a_new_store_and_keep_their_types() {
    let dir = scratch();
    let path = dir.join("preferences.json");
    let prefs = FilePreferences::new(path.clone());
    prefs.set_bool("autoUpdate", true);
    prefs.set_string("language", "hu");
    prefs.set_date("lastCheck", Date::from_time_interval_since_1970(1_790_000_000.5));
    let again = FilePreferences::new(path.clone());
    assert_eq!(again.bool("autoUpdate"), Some(true));
    assert_eq!(again.string("language").as_deref(), Some("hu"));
    assert_eq!(again.date("lastCheck").map(|d| d.time_interval_since_1970()), Some(1_790_000_000.5));
    assert_eq!(again.bool("language"), None, "a string is not a bool");
    assert_eq!(again.string("missing"), None);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
#[cfg_attr(not(unix), ignore = "needs fsx private files (Task 8 removes this on Windows)")]
fn the_file_is_private_and_remove_all_empties_it() {
    let dir = scratch();
    let path = dir.join("preferences.json");
    let prefs = FilePreferences::new(path.clone());
    prefs.set_bool("x", true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o7777, 0o600);
    }
    // Windows: Task 8 adds `fsx::has_access(&fsx::stat_path(&path, Follow::No).unwrap(), Access::Private)` here.
    prefs.remove_all();
    assert_eq!(FilePreferences::new(path).bool("x"), None);
    fs::remove_dir_all(dir).unwrap();
}

#[test]
#[cfg_attr(not(unix), ignore = "needs fsx private files (Task 8 removes this on Windows)")]
fn a_corrupt_or_missing_file_reads_as_empty_and_is_replaced_on_write() {
    let dir = scratch();
    let path = dir.join("preferences.json");
    assert_eq!(FilePreferences::new(path.clone()).bool("x"), None);
    fs::write(&path, b"{not json").unwrap();
    let prefs = FilePreferences::new(path.clone());
    assert_eq!(prefs.bool("x"), None);
    prefs.set_bool("x", false);
    assert_eq!(FilePreferences::new(path).bool("x"), Some(false));
    fs::remove_dir_all(dir).unwrap();
}
```

In `crates/app-core/tests/system_status.rs`:

```rust
#[test]
fn an_engine_note_replaces_the_rows_and_stays_out_of_the_json_on_macos() {
    let facts = SetupFacts::default();
    let plain = SetupView::build(Some(&facts), &BrewRun::default(), &SetupOps::default(), String::new());
    let json = serde_json::to_string(&plain).unwrap();
    assert!(!json.contains("engineNote"), "absent when None: the 1.4 view-model JSON is unchanged");
    let noted = plain.with_engine_note(Some("Later.".into()));
    assert_eq!(noted.engine_note.as_deref(), Some("Later."));
    assert!(noted.homebrew.is_none() && noted.tools.is_none() && noted.root.is_none());
    assert!(!noted.can_install_tools);
    assert!(serde_json::to_string(&noted).unwrap().contains("\"engineNote\":\"Later.\""));
}
```

(Use the file's existing imports; add `BrewRun`, `SetupOps`, `SetupFacts` from `macvpn_app_core::setup` if missing.)

Run: `cargo test --locked -p macvpn-platform-api --test file_preferences; cargo test --locked -p macvpn-app-core --test system_status`
Expected: FAIL to compile (`FilePreferences`, `with_engine_note`, `engine_note` missing).

- [x] **Step 2: `FilePreferences`** (append to `crates/platform-api/src/prefs.rs`)

```rust
/// A [`PreferenceStore`] in one JSON file (WinVPN: `%LOCALAPPDATA%\WinVPN\preferences.json`), private (`fsx::Access::
/// Private`, written with `fsx::atomic_write`), read once and kept in memory. A missing or corrupt file reads as
/// empty and is replaced by the next write. Write errors are ignored like `CFPreferences`' (the value stays in
/// memory for this run). Format: `{"version":1,"values":{"key":{"bool":true}|{"string":"…"}|{"date":<seconds
/// since 1970>}}}`.
#[derive(Debug)]
pub struct FilePreferences {
    path: std::path::PathBuf,
    values: Mutex<Option<HashMap<String, PreferenceValue>>>,
}

impl FilePreferences {
    pub fn new(path: std::path::PathBuf) -> Self {
        FilePreferences { path, values: Mutex::new(None) }
    }

    fn with<T>(&self, f: impl FnOnce(&mut HashMap<String, PreferenceValue>) -> T) -> T {
        let mut guard = self.values.lock().unwrap_or_else(PoisonError::into_inner);
        let values = guard.get_or_insert_with(|| self.load());
        f(values)
    }

    fn load(&self) -> HashMap<String, PreferenceValue> {
        let Ok((mut file, meta)) = macvpn_core::fsx::open_regular(
            &self.path,
            macvpn_core::fsx::OpenFor::Read,
            macvpn_core::fsx::Follow::No,
            false,
        ) else {
            return HashMap::new();
        };
        if meta.len() > 1024 * 1024 {
            return HashMap::new();
        }
        let mut data = Vec::new();
        if std::io::Read::read_to_end(&mut file, &mut data).is_err() {
            return HashMap::new();
        }
        let Ok(json) = serde_json::from_slice::<serde_json::Value>(&data) else { return HashMap::new() };
        let mut out = HashMap::new();
        if json.get("version").and_then(serde_json::Value::as_u64) != Some(1) {
            return out;
        }
        for (key, value) in json.get("values").and_then(serde_json::Value::as_object).into_iter().flatten() {
            let parsed = if let Some(b) = value.get("bool").and_then(serde_json::Value::as_bool) {
                Some(PreferenceValue::Bool(b))
            } else if let Some(s) = value.get("string").and_then(serde_json::Value::as_str) {
                Some(PreferenceValue::String(s.to_string()))
            } else {
                value.get("date").and_then(serde_json::Value::as_f64).map(|d| PreferenceValue::Date(Date::from_time_interval_since_1970(d)))
            };
            if let Some(v) = parsed {
                out.insert(key.clone(), v);
            }
        }
        out
    }

    fn save(&self, values: &HashMap<String, PreferenceValue>) {
        let mut map = serde_json::Map::new();
        let mut keys: Vec<&String> = values.keys().collect();
        keys.sort();
        for key in keys {
            let v = match &values[key] {
                PreferenceValue::Bool(b) => serde_json::json!({ "bool": b }),
                PreferenceValue::String(s) => serde_json::json!({ "string": s }),
                PreferenceValue::Date(d) => serde_json::json!({ "date": d.time_interval_since_1970() }),
            };
            map.insert(key.clone(), v);
        }
        let json = serde_json::json!({ "version": 1, "values": map });
        let Ok(bytes) = serde_json::to_vec_pretty(&json) else { return };
        if let Some(parent) = self.path.parent() {
            let _ = macvpn_core::fsx::create_missing_private_dirs(parent);
        }
        let _ = macvpn_core::fsx::atomic_write(&self.path, &bytes, macvpn_core::fsx::Access::Private);
    }

    fn put(&self, key: &str, value: PreferenceValue) {
        self.with(|values| {
            values.insert(key.to_string(), value);
            self.save(values);
        });
    }

    fn get(&self, key: &str) -> Option<PreferenceValue> {
        self.with(|values| values.get(key).cloned())
    }
}

impl PreferenceStore for FilePreferences {
    fn bool(&self, key: &str) -> Option<bool> {
        match self.get(key)? {
            PreferenceValue::Bool(b) => Some(b),
            _ => None,
        }
    }

    fn set_bool(&self, key: &str, value: bool) {
        self.put(key, PreferenceValue::Bool(value));
    }

    fn date(&self, key: &str) -> Option<Date> {
        match self.get(key)? {
            PreferenceValue::Date(d) => Some(d),
            _ => None,
        }
    }

    fn set_date(&self, key: &str, value: Date) {
        self.put(key, PreferenceValue::Date(value));
    }

    fn string(&self, key: &str) -> Option<String> {
        match self.get(key)? {
            PreferenceValue::String(s) => Some(s),
            _ => None,
        }
    }

    fn set_string(&self, key: &str, value: &str) {
        self.put(key, PreferenceValue::String(value.to_string()));
    }

    fn remove_all(&self) {
        self.with(|values| {
            values.clear();
            self.save(values);
        });
    }
}
```

Re-export in `lib.rs`: `pub use prefs::{FilePreferences, MemoryPreferences, PreferenceStore};`. Add `uuid` to platform-api's `[dev-dependencies]` if the test needs it (same version as `[dependencies]`).

- [x] **Step 3: The two trait defaults**

`crates/platform-api/src/setup.rs`, in `SystemSetup`:

```rust
    /// A note that replaces the System Status rows while this platform has no VPN engine (WinVPN in 2a: "The VPN
    /// engine comes in a later version of WinVPN. …", localized). `None`: the rows are shown (macOS).
    fn engine_note(&self) -> Option<String> {
        None
    }
```

`crates/platform-api/src/ui.rs`, in `WindowChrome`:

```rust
    /// The colour the tray icon is drawn in: `None` keeps the template image (the system tints it: macOS);
    /// `Some(rgb)` recolours its opaque pixels (Windows: white on a dark taskbar, black on a light one).
    fn tray_tint(&self) -> Option<[u8; 3]> {
        None
    }
```

- [x] **Step 4: `SetupView::engine_note`** (`crates/app-core/src/setup.rs`)

Add the field (last in the struct, so the existing field order of the JSON is unchanged):

```rust
    /// The platform's note when it has no VPN engine yet (WinVPN 2a); the rows are then not shown. Absent from the
    /// JSON when `None`, so MacVPN's view model stays byte-identical.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_note: Option<String>,
```

and in `impl SetupView`:

```rust
    /// The view with the platform's engine note: the Homebrew, tools and helper rows (and their actions) are
    /// replaced by it. `None` returns the view unchanged.
    pub fn with_engine_note(mut self, note: Option<String>) -> SetupView {
        if note.is_some() {
            self.homebrew = None;
            self.tools = None;
            self.root = None;
            self.can_install_tools = false;
            self.upgrade_notice = None;
            self.engine_note = note;
        }
        self
    }
```

`SetupView::build` sets `engine_note: None`.

- [x] **Step 5: Run the tests**

Run: `cargo test --locked -p macvpn-platform-api && cargo test --locked -p macvpn-app-core --test system_status --test compat_1_4 --test view_model`
Expected: PASS; `compat_1_4` unchanged (the field is skipped).

- [x] **Step 6: Commit**

```bash
git add crates/platform-api crates/app-core/src/setup.rs crates/app-core/tests/system_status.rs
git commit -m "feat(platform-api): FilePreferences, the engine note and the tray tint" -m "Portable pieces for WinVPN with defaults that keep macOS as it is: the view model's engineNote is absent when None (compat_1_4 unchanged)." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

## Task 8: `fsx` on Windows for real

**Goal:** `Access::Private`, `owner`, `has_access`, `ensure_private_dir`, `create_private_dir_all`, `create_missing_private_dirs`, `file_id` and `hard_links` work on Windows through `macvpn-winsys`, with the reparse-point policy of "Resolved points"; core still has no `unsafe`.

**Files:**
- Modify: `crates/core/Cargo.toml` (`[target.'cfg(windows)'.dev-dependencies] macvpn-winsys`), `crates/core/src/fsx/{mod.rs, windows.rs}`, `crates/winsys/src/file.rs` (`is_cloud_unavailable`)
- Create: `crates/core/tests/fsx_windows.rs`
- Modify: `crates/core/tests/store.rs` (the two shred ignores go), `crates/platform-api/tests/file_preferences.rs` (its three `cfg_attr(not(unix), ignore …)` go)

- [x] **Step 1: Write the failing tests** (`crates/core/tests/fsx_windows.rs`)

```rust
//! `macvpn_core::fsx` on Windows: the counterparts of `tests/fsx.rs`'s Unix assertions.

#![cfg(windows)]

use macvpn_core::fsx::{self, Access, FileOwner, Follow, OpenFor};
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Scratch {
        let dir = std::env::temp_dir().join(format!("fsx-win-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn junction(link: &Path, target: &Path) {
    assert!(Command::new("cmd").args(["/C", "mklink", "/J"]).arg(link).arg(target).status().unwrap().success());
}

fn me() -> FileOwner {
    FileOwner::current_user().unwrap()
}

#[test]
fn create_new_private_is_owned_by_me_and_private() {
    let tmp = Scratch::new();
    let path = tmp.0.join("p");
    let file = fsx::create_new(&path, Access::Private).unwrap();
    let stat = fsx::stat(&file).unwrap();
    assert!(fsx::has_access(&stat, Access::Private));
    assert!(!fsx::has_access(&stat, Access::Shared));
    assert_eq!(fsx::owner(&stat).unwrap(), me());
    let by_path = fsx::stat_path(&path, Follow::No).unwrap();
    assert!(fsx::has_access(&by_path, Access::Private));
}

#[test]
fn set_access_switches_between_the_shapes() {
    let tmp = Scratch::new();
    let file = fsx::create_new(&tmp.0.join("s"), Access::Private).unwrap();
    fsx::set_access(&file, Access::Shared).unwrap();
    assert!(fsx::has_access(&fsx::stat(&file).unwrap(), Access::Shared));
    fsx::set_access(&file, Access::Private).unwrap();
    assert!(fsx::has_access(&fsx::stat(&file).unwrap(), Access::Private));
}

#[test]
fn a_plain_file_has_neither_shape() {
    let tmp = Scratch::new();
    let path = tmp.0.join("plain");
    fs::write(&path, b"x").unwrap();
    let stat = fsx::stat_path(&path, Follow::No).unwrap();
    assert!(!fsx::has_access(&stat, Access::Private));
    assert!(!fsx::has_access(&stat, Access::Shared));
}

#[test]
fn create_private_dir_all_makes_every_level_private() {
    let tmp = Scratch::new();
    let leaf = tmp.0.join("a").join("b").join("c");
    fsx::create_private_dir_all(&leaf).unwrap();
    for dir in [tmp.0.join("a"), tmp.0.join("a").join("b"), leaf.clone()] {
        assert!(fsx::has_access(&fsx::stat_path(&dir, Follow::No).unwrap(), Access::Private), "{dir:?}");
    }
}

#[test]
fn ensure_private_dir_tightens_and_returns_the_owner() {
    let tmp = Scratch::new();
    let dir = tmp.0.join("d");
    fs::create_dir(&dir).unwrap(); // inherited permissions
    assert!(!fsx::has_access(&fsx::stat_path(&dir, Follow::No).unwrap(), Access::Private));
    assert_eq!(fsx::ensure_private_dir(&dir).unwrap(), me());
    assert!(fsx::has_access(&fsx::stat_path(&dir, Follow::No).unwrap(), Access::Private));
}

#[test]
fn ensure_private_dir_refuses_a_junction_and_a_file() {
    let tmp = Scratch::new();
    let real = tmp.0.join("real");
    fs::create_dir(&real).unwrap();
    let link = tmp.0.join("link");
    junction(&link, &real);
    assert_eq!(fsx::ensure_private_dir(&link).unwrap_err().kind(), ErrorKind::NotADirectory);
    let file = tmp.0.join("file");
    fs::write(&file, b"x").unwrap();
    assert_eq!(fsx::ensure_private_dir(&file).unwrap_err().kind(), ErrorKind::NotADirectory);
}

#[test]
fn files_sqlite_creates_inside_a_private_dir_inherit_user_and_system_only() {
    let tmp = Scratch::new();
    let dir = tmp.0.join("vault");
    fsx::ensure_private_dir(&dir).unwrap();
    fs::write(dir.join("vault.db-wal"), b"x").unwrap();
    let handle = fs::File::open(dir.join("vault.db-wal")).unwrap();
    assert!(macvpn_winsys::file::grants_only_owner_and_system(&handle).unwrap());
}

#[test]
fn open_regular_refuses_a_directory_and_a_symlink() {
    let tmp = Scratch::new();
    let err = fsx::open_regular(&tmp.0, OpenFor::Read, Follow::No, false).unwrap_err();
    assert!(fsx::is_not_regular_file(&err), "{err:?}");
    let target = tmp.0.join("t");
    fs::write(&target, b"x").unwrap();
    let link = tmp.0.join("l");
    match std::os::windows::fs::symlink_file(&target, &link) {
        // ERROR_PRIVILEGE_NOT_HELD: symlinks need Developer Mode or an administrator.
        Err(e) if e.raw_os_error() == Some(1314) => eprintln!("skipped: no symlink privilege"),
        Err(e) => panic!("{e}"),
        Ok(()) => {
            let err = fsx::open_regular(&link, OpenFor::Read, Follow::No, false).unwrap_err();
            assert!(fsx::is_symlink_refused(&err), "{err:?}");
            assert!(fsx::open_regular(&link, OpenFor::Read, Follow::Yes, false).is_ok());
        }
    }
}

#[test]
fn hard_links_and_file_ids_are_real() {
    let tmp = Scratch::new();
    let (a, b, c) = (tmp.0.join("a"), tmp.0.join("b"), tmp.0.join("c"));
    fsx::create_new(&a, Access::Private).unwrap().write_all(b"a").unwrap();
    fs::write(&c, b"c").unwrap();
    let (_, single) = fsx::open_regular(&a, OpenFor::Read, Follow::No, false).unwrap();
    assert_eq!(fsx::hard_links(&single), 1);
    fs::hard_link(&a, &b).unwrap();
    let (_, shared) = fsx::open_regular(&a, OpenFor::Read, Follow::No, false).unwrap();
    assert_eq!(fsx::hard_links(&shared), 2);
    let id = |p: &Path| fsx::file_id(&fsx::stat_path(p, Follow::No).unwrap()).unwrap();
    assert_eq!(id(&a), id(&b));
    assert_ne!(id(&a), id(&c));
}

#[test]
fn atomic_write_private_leaves_a_private_file() {
    let tmp = Scratch::new();
    let path = tmp.0.join("x.json");
    fsx::atomic_write(&path, b"{}", Access::Private).unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"{}");
    assert!(fsx::has_access(&fsx::stat_path(&path, Follow::No).unwrap(), Access::Private));
    fsx::atomic_write(&path, b"{\"a\":1}", Access::Private).unwrap();
    assert_eq!(fs::read(&path).unwrap(), b"{\"a\":1}");
}

#[test]
fn open_append_creates_private_and_refuses_a_junction_target() {
    let tmp = Scratch::new();
    let path = tmp.0.join("audit.log");
    let mut f = fsx::open_append(&path, Access::Private).unwrap();
    f.write_all(b"one\n").unwrap();
    assert!(fsx::has_access(&fsx::stat(&f).unwrap(), Access::Private));
}
```

Add `uuid` (core already has it as a dependency; tests can use it) and `macvpn-winsys` as a `[target.'cfg(windows)'.dev-dependencies]` of core.

Run: `scripts/win-remote.sh run 'cargo test --locked -p macvpn-core --test fsx_windows'`
Expected: FAIL (`FileOwner::current_user` missing; then `Unsupported` errors).

- [x] **Step 2: `winsys::file::is_cloud_unavailable`**

```rust
/// The Cloud Files (OneDrive placeholder) errors that mean "cannot be reached right now".
pub fn is_cloud_unavailable(code: i32) -> bool {
    use windows_sys::Win32::Foundation::{
        ERROR_CLOUD_FILE_IN_USE, ERROR_CLOUD_FILE_NETWORK_UNAVAILABLE, ERROR_CLOUD_FILE_PROVIDER_NOT_RUNNING,
        ERROR_CLOUD_FILE_PROVIDER_TERMINATED, ERROR_CLOUD_FILE_REQUEST_TIMEOUT, ERROR_CLOUD_FILE_UNSUCCESSFUL,
    };
    [
        ERROR_CLOUD_FILE_PROVIDER_NOT_RUNNING,
        ERROR_CLOUD_FILE_NETWORK_UNAVAILABLE,
        ERROR_CLOUD_FILE_UNSUCCESSFUL,
        ERROR_CLOUD_FILE_REQUEST_TIMEOUT,
        ERROR_CLOUD_FILE_PROVIDER_TERMINATED,
        ERROR_CLOUD_FILE_IN_USE,
    ]
    .iter()
    .any(|&c| c as i32 == code)
}
```

- [x] **Step 3: `fsx/mod.rs`'s module doc**

The owner constructors exist since Task 4. Update the module doc of `mod.rs` (the Windows sentence) to: "On Windows the owner, the private and shared DACLs, the identity and the link count are read from the open handle through `macvpn-winsys`; a check that cannot be completed fails closed."

- [x] **Step 4: `fsx/windows.rs`** (the whole file)

```rust
//! `fsx` on Windows. The owner (a SID string), the DACL shape, the 128-bit file id and the link count come from the
//! open handle through `macvpn-winsys` (core holds no `unsafe`). `Access::Private` is the protected DACL "this user
//! and SYSTEM", `Access::Shared` adds read for `BUILTIN\Users` (`macvpn_winsys::file::Protection`).
//!
//! Reparse points: `Follow::No` refuses name surrogates (symlinks, junctions); other reparse points (Cloud Files
//! placeholders, dedup) are the file itself and are reopened normally, checked to be the same file. Whatever cannot
//! be read fails closed: no owner, no access, no identity, `u64::MAX` links.

use super::{Access, Follow, OpenFor, Stat, not_regular_file};
use macvpn_winsys::file::{self as wfile, Disposition, Info, Open, Protection};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::path::Path;

pub(super) type OwnerId = String;
pub(super) type FileIdent = (u64, [u8; 16]);
/// What the handle said (`None`: it could not be read; every check then fails closed).
pub(super) type Extra = Option<Info>;

const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
const ERROR_ACCESS_DENIED: i32 = 5;

// The Win32 errors that mean "the file or its share cannot be reached right now".
const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_PATH_NOT_FOUND: i32 = 3;
const ERROR_NOT_READY: i32 = 21;
const ERROR_BAD_NETPATH: i32 = 53;
const ERROR_NETNAME_DELETED: i32 = 64;
const ERROR_BAD_NET_NAME: i32 = 67;
const ERROR_SEM_TIMEOUT: i32 = 121;
const ERROR_NETWORK_UNREACHABLE: i32 = 1231;

fn protection(access: Access) -> Protection {
    match access {
        Access::Private => Protection::Private,
        Access::Shared => Protection::Shared,
    }
}

/// The refusal of a reparse point by `Follow::No` (recognized by [`is_symlink_refused`]).
struct SymlinkRefused;

impl fmt::Display for SymlinkRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the path is a symbolic link or another reparse point")
    }
}

impl fmt::Debug for SymlinkRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for SymlinkRefused {}

fn symlink_refused() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, SymlinkRefused)
}

fn not_a_dir(dir: &Path) -> io::Error {
    io::Error::new(io::ErrorKind::NotADirectory, format!("{} is not a real directory", dir.display()))
}

pub(super) fn stat(file: &File) -> io::Result<Stat> {
    Ok(Stat { meta: file.metadata()?, extra: wfile::info(file).ok() })
}

pub(super) fn stat_path(path: &Path, follow: Follow) -> io::Result<Stat> {
    let handle = wfile::open_metadata(path, follow == Follow::Yes)?;
    Ok(Stat { meta: handle.metadata()?, extra: wfile::info(&handle).ok() })
}

pub(super) fn create_missing_private_dirs(dir: &Path) -> io::Result<()> {
    if dir.as_os_str().is_empty() || dir.is_dir() {
        return Ok(());
    }
    if let Some(parent) = dir.parent() {
        create_missing_private_dirs(parent)?;
    }
    match wfile::create_dir(dir, Some(Protection::Private)) {
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists && dir.is_dir() => Ok(()),
        other => other,
    }
}

pub(super) fn create_private_dir_all(dir: &Path) -> io::Result<()> {
    create_missing_private_dirs(dir)?;
    let handle = wfile::open_dir(dir, true)?;
    wfile::set_protection(&handle, Protection::Private, true)
}

pub(super) fn ensure_private_dir(dir: &Path) -> io::Result<OwnerId> {
    if let Some(parent) = dir.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    match wfile::create_dir(dir, Some(Protection::Private)) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    let handle = wfile::open_dir(dir, false).map_err(|e| {
        // A file (not a directory) at the name answers ERROR_ACCESS_DENIED or ERROR_DIRECTORY here.
        if fs::symlink_metadata(dir).is_ok_and(|m| !m.is_dir()) { not_a_dir(dir) } else { e }
    })?;
    let info = wfile::info(&handle)?;
    if info.reparse_tag.is_some() || info.attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(not_a_dir(dir));
    }
    if info.protection != Some(Protection::Private) {
        wfile::set_protection(&handle, Protection::Private, true)?;
    }
    Ok(info.owner.to_string())
}

pub(super) fn create_new(path: &Path, access: Access, read: bool) -> io::Result<File> {
    wfile::open(
        path,
        Open { read, write: true, append: false, disposition: Disposition::CreateNew, protection: Some(protection(access)), no_follow: true },
    )
}

pub(super) fn open_regular(path: &Path, open: OpenFor, follow: Follow, _noctty: bool) -> io::Result<(File, Stat)> {
    let options = |reparse: bool| {
        let mut o = OpenOptions::new();
        match open {
            OpenFor::Read => o.read(true),
            OpenFor::Write => o.write(true),
        };
        if reparse {
            o.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        o
    };
    let file = options(follow == Follow::No).open(path).map_err(|e| {
        // A directory cannot be opened as a file (ERROR_ACCESS_DENIED): the Unix "not a regular file".
        if e.raw_os_error() == Some(ERROR_ACCESS_DENIED) && fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()) {
            not_regular_file()
        } else {
            e
        }
    })?;
    let info = wfile::info(&file)?;
    let (file, info) = match info.reparse_tag {
        Some(tag) if follow == Follow::No && wfile::is_name_surrogate(tag) => return Err(symlink_refused()),
        Some(_) if follow == Follow::No => {
            // A placeholder (or another non-surrogate reparse point) is the file itself: open it normally (which
            // hydrates a placeholder) and make sure it is still the same file.
            let again = options(false).open(path)?;
            let again_info = wfile::info(&again)?;
            if (again_info.volume, again_info.id) != (info.volume, info.id) {
                return Err(symlink_refused());
            }
            (again, again_info)
        }
        _ => (file, info),
    };
    let meta = file.metadata()?;
    if !meta.file_type().is_file() {
        return Err(not_regular_file());
    }
    Ok((file, Stat { meta, extra: Some(info) }))
}

pub(super) fn open_append(path: &Path, access: Access) -> io::Result<File> {
    let file = wfile::open(
        path,
        Open { read: false, write: false, append: true, disposition: Disposition::OpenOrCreate, protection: Some(protection(access)), no_follow: true },
    )?;
    let info = wfile::info(&file)?;
    if info.reparse_tag.is_some_and(wfile::is_name_surrogate) {
        return Err(symlink_refused());
    }
    if !file.metadata()?.file_type().is_file() {
        return Err(not_regular_file());
    }
    Ok(file)
}

pub(super) fn set_access(file: &File, access: Access) -> io::Result<()> {
    wfile::set_protection(file, protection(access), file.metadata()?.is_dir())
}

pub(super) fn has_access(stat: &Stat, access: Access) -> bool {
    stat.extra.as_ref().is_some_and(|i| i.protection == Some(protection(access)))
}

pub(super) fn owner(stat: &Stat) -> io::Result<OwnerId> {
    stat.extra
        .as_ref()
        .map(|i| i.owner.to_string())
        .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "the file's owner could not be read"))
}

pub(super) fn file_id(stat: &Stat) -> Option<FileIdent> {
    stat.extra.as_ref().map(|i| (i.volume, i.id))
}

/// `u64::MAX` when unknown: `store::shred_file` then only unlinks (fail closed).
pub(super) fn hard_links(stat: &Stat) -> u64 {
    stat.extra.as_ref().map_or(u64::MAX, |i| u64::from(i.links))
}

/// NTFS journals the rename's metadata; flushing a directory handle needs write access to it and gives nothing
/// more.
pub(super) fn sync_dir(_dir: &Path) {}

pub(super) fn is_unavailable(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(
            ERROR_FILE_NOT_FOUND
                | ERROR_PATH_NOT_FOUND
                | ERROR_NOT_READY
                | ERROR_BAD_NETPATH
                | ERROR_NETNAME_DELETED
                | ERROR_BAD_NET_NAME
                | ERROR_SEM_TIMEOUT
                | ERROR_NETWORK_UNREACHABLE
        )
    ) || e.raw_os_error().is_some_and(wfile::is_cloud_unavailable)
}

pub(super) fn is_symlink_refused(e: &io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.is::<SymlinkRefused>())
}

pub(super) fn is_separator(c: char) -> bool {
    c == '/' || c == '\\'
}

/// A `Normal` component with a `:` (the drive is a `Prefix` component, so `C:\x` is not a stream).
pub(super) fn names_a_stream(path: &Path) -> bool {
    path.components().any(|c| matches!(c, std::path::Component::Normal(s) if s.to_string_lossy().contains(':')))
}
```

- [x] **Step 5: Remove the ignores this task makes pass**

In `crates/core/tests/store.rs` delete the two four-line `#[cfg_attr(windows, ignore = "shred_file skips the overwrite on Windows until it reads the real hard link count: phase 2")]` blocks; in `crates/platform-api/tests/file_preferences.rs` delete the three `#[cfg_attr(not(unix), ignore = …)]` lines and replace the comment "Windows: Task 8 adds …" by

```rust
    #[cfg(windows)]
    {
        use macvpn_core::fsx::{self, Access, Follow};
        assert!(fsx::has_access(&fsx::stat_path(&path, Follow::No).unwrap(), Access::Private));
    }
```

- [x] **Step 6: Run on both systems**

Run (Mac): `CI=1 cargo test --workspace --locked && scripts/check-windows.sh`
Expected: PASS (nothing changed for Unix).

Run: `scripts/win-remote.sh run 'cargo test --locked -p macvpn-core --test fsx_windows --test store && cargo test --locked -p macvpn-platform-api'`
Expected: PASS, including `shred_file_zeroes_the_contents_before_unlinking` and `shred_file_handles_large_and_empty_files_and_a_missing_one`.

- [x] **Step 7: Commit**

```bash
git add crates/core crates/winsys/src/file.rs crates/platform-api/tests/file_preferences.rs Cargo.lock
git commit -m "feat(fsx): private files, owners, identities and link counts on Windows" -m "Through macvpn-winsys: a protected DACL for this user and SYSTEM (inheritable on directories), the owner SID, the 128-bit file id and the link count from the open handle. Follow::No refuses name-surrogate reparse points; Cloud Files placeholders are reopened and checked to be the same file. The shred overwrite tests run on Windows again." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

## Task 9: platform-win foundations

**Goal:** `WinPlatform::new(sandbox)` replaces the stub: known folders, the user's owner, dates, the shell, entropy, the Credential Manager key store, file preferences, the Mark of the Web, and the clear "not yet" answers of the VPN parts. Pure logic compiles and is tested on macOS too.

**Files:**
- Modify: `crates/platform-win/Cargo.toml`, `crates/platform-win/src/lib.rs`
- Create: `crates/platform-win/src/pure/{mod.rs, texts.rs, zone.rs, dates.rs}`, `crates/platform-win/src/win/{mod.rs, platform.rs, system.rs, shell.rs, keystore.rs, not_yet.rs}`
- Delete: `crates/platform-win/tests/stub.rs`
- Create: `crates/platform-win/tests/pure.rs` (every OS), `crates/platform-win/tests/windows.rs` (`#![cfg(windows)]`)
- Modify: `crates/core/l10n/strings.json` (new Windows-only entries; shared: add only)

- [x] **Step 1: The crate layout** (its own commit)

`crates/platform-win/Cargo.toml`:

```toml
[package]
name = "macvpn-platform-win"
description = "MacVPN platform layer for Windows (WinVPN)"
version.workspace = true
edition.workspace = true
license.workspace = true
publish.workspace = true
rust-version.workspace = true

[lib]
name = "macvpn_platform_win"

[lints]
workspace = true

# `pure` compiles on every OS (tested on macOS too); `win` only on Windows.
[dependencies]
# `vault` for the `KeyStore`, `Entropy` and `LegacyKeychain` it returns.
macvpn-core = { path = "../core", features = ["vault"] }
macvpn-platform-api = { path = "../platform-api" }
uuid = "1.26.1"
zeroize = "1.9.1"

[target.'cfg(windows)'.dependencies]
macvpn-winsys = { path = "../winsys" }
# The version Tauri already brings (no new crate in Cargo.lock), pinned exactly.
windows-sys = { version = "=0.61.2", features = [
    "Win32_Foundation",
    "Win32_Globalization",
    "Win32_Security",
    "Win32_Security_Credentials",
    "Win32_Storage_FileSystem",
    "Win32_System_Com",
    "Win32_System_Registry",
    "Win32_System_Time",
    "Win32_UI_Shell",
    "Win32_UI_WindowsAndMessaging",
] }
```

`crates/platform-win/src/lib.rs`:

```rust
//! The Windows platform (WinVPN), phase 2a: everything but the VPN engine (the WinVPN Service, OpenVPN and
//! WireGuard come in 2b, native RAS VPNs in 2c; until then those parts answer "The VPN engine comes in a later
//! version of WinVPN.").
//!
//! `pure`: the logic without system calls (texts, the Mark-of-the-Web parser, date formats, …), compiled and tested
//! on every OS. `win`: the Windows implementation (Win32 through `windows-sys` and `macvpn-winsys`), Windows only.
//! The storage identifiers (the credential `local.winvpn.vault`, the Run value `WinVPN`, the pipe names) are
//! literals here and never derive from `Product`.

pub mod pure;

#[cfg(windows)]
#[allow(unsafe_code)]
mod win;

#[cfg(windows)]
pub use win::platform::WinPlatform;
```

`src/pure/mod.rs`: `pub mod dates; pub mod texts; pub mod zone;` and `src/win/mod.rs`: `pub(crate) mod keystore; pub(crate) mod locale; pub(crate) mod not_yet; pub mod platform; pub(crate) mod registry; pub(crate) mod shell; pub(crate) mod system;`. Delete `tests/stub.rs`. In `app/src-tauri/Cargo.toml` change the target table to `[target.'cfg(windows)'.dependencies]` and in `app/src-tauri/src/platform/mod.rs` replace the two `cfg(not(target_os = "macos"))` selections by `cfg(windows)` and add:

```rust
#[cfg(not(any(target_os = "macos", windows)))]
compile_error!("no platform layer for this operating system yet (Linux is phase 4)");
```

(the `facades` module's `not(target_os = "macos")` stays: it means "not the macOS smoke driver"). Until Step 6 lands, `win::platform` holds the old stub's code moved verbatim (`pub struct WinPlatform;` with every impl), so the app still builds; the app's `platform/windows.rs` keeps `static PLATFORM: WinPlatform = WinPlatform;` until Task 14.

Run: `cargo clippy --workspace --all-targets --locked -- -D warnings && scripts/check-windows.sh` (Mac) and `scripts/win-remote.sh run 'cargo clippy --workspace --all-targets --locked --target x86_64-pc-windows-msvc -- -D warnings'`
Expected: PASS. Commit: `git add -A crates/platform-win app/src-tauri/Cargo.toml app/src-tauri/src/platform/mod.rs Cargo.lock && git commit -m "refactor(platform-win): pure and Windows modules" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"`.

- [x] **Step 2: Write the failing pure tests** (`crates/platform-win/tests/pure.rs`, every OS)

```rust
//! platform-win's pure logic (compiled and tested on every OS).

use macvpn_core::l10n::{self, AppLanguage};
use macvpn_platform_win::pure::{dates, texts, zone};
use std::fs;

#[test]
fn zone_ids_three_and_up_are_downloads() {
    assert!(zone::marks_download(b"[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://example.com/\r\n"));
    assert!(zone::marks_download(b"[ZoneTransfer]\nZoneId=4\n"));
    assert!(!zone::marks_download(b"[ZoneTransfer]\r\nZoneId=0\r\n"));
    assert!(!zone::marks_download(b"[ZoneTransfer]\r\nZoneId=2\r\n"));
    assert!(!zone::marks_download(b"[zonetransfer]\r\n zoneid = 1 \r\n"));
}

#[test]
fn an_unreadable_zone_stream_is_a_download() {
    assert!(zone::marks_download(b""));
    assert!(zone::marks_download(b"[ZoneTransfer]\r\nZoneId=x\r\n"));
    assert!(zone::marks_download(b"[Other]\r\nZoneId=0\r\n"));
    assert!(zone::marks_download(&[0xff, 0xfe, 0xff]));
}

#[test]
fn a_utf16_zone_stream_is_read() {
    let text: Vec<u8> = "\u{feff}[ZoneTransfer]\r\nZoneId=1\r\n".encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert!(!zone::marks_download(&text));
}

/// On Unix the stream name is an ordinary file name, so the reader is tested here too.
#[test]
fn the_mark_is_read_from_the_stream_next_to_the_file() {
    let dir = std::env::temp_dir().join(format!("zone-{}", uuid::Uuid::new_v4()));
    fs::create_dir_all(&dir).unwrap();
    let file = dir.join("a.ovpn");
    assert!(!zone::is_marked(&file), "a missing file is not marked");
    fs::write(&file, b"client\n").unwrap();
    assert!(!zone::is_marked(&file), "no stream: not marked");
    fs::write(dir.join("a.ovpn:Zone.Identifier"), b"[ZoneTransfer]\r\nZoneId=3\r\n").unwrap();
    assert!(zone::is_marked(&file));
    fs::write(dir.join("a.ovpn:Zone.Identifier"), vec![b'x'; 5000]).unwrap();
    assert!(zone::is_marked(&file), "too large: fail closed");
    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn dates_have_the_macos_formats() {
    assert_eq!(dates::date((2026, 10, 18)), "2026-10-18");
    assert_eq!(dates::date_time((2026, 10, 18, 14, 3, 5), AppLanguage::Hu), "2026. 10. 18. 14:03:05");
    assert_eq!(dates::date_time((2026, 10, 18, 14, 3, 5), AppLanguage::En), "10/18/2026, 2:03:05\u{202f}PM");
    assert_eq!(dates::date_time((2026, 1, 2, 0, 7, 9), AppLanguage::En), "1/2/2026, 12:07:09\u{202f}AM");
}

#[test]
fn the_not_yet_texts_are_translated() {
    l10n::with_language(AppLanguage::Hu, || {
        assert_ne!(texts::engine_later(), "The VPN engine comes in a later version of WinVPN.");
        assert!(texts::engine_note().contains("WinVPN"));
    });
}
```

Add `uuid` to `[dev-dependencies]` (`uuid = { version = "1.26.1", features = ["v4"] }`).

Run: `cargo test --locked -p macvpn-platform-win --test pure`
Expected: FAIL to compile (modules empty).

- [x] **Step 3: The pure modules**

`src/pure/zone.rs`:

```rust
//! The Mark of the Web: the `Zone.Identifier` alternate data stream a browser writes next to a download.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// The largest stream read (real ones are a few hundred bytes).
const MAX_STREAM: u64 = 4096;

/// Whether a `Zone.Identifier` stream's content marks a download: `ZoneId` 3 (Internet) or 4 (Restricted) in the
/// `[ZoneTransfer]` section. 0–2 (this computer, intranet, trusted) are not. Anything unreadable is marked.
pub fn marks_download(content: &[u8]) -> bool {
    let text = if content.starts_with(&[0xff, 0xfe]) {
        let units: Vec<u16> = content[2..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        match String::from_utf16(&units) {
            Ok(t) => t,
            Err(_) => return true,
        }
    } else {
        match std::str::from_utf8(content) {
            Ok(t) => t.trim_start_matches('\u{feff}').to_string(),
            Err(_) => return true,
        }
    };
    let (mut in_section, mut zone) = (false, None);
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            in_section = line.trim_start_matches('\u{feff}').eq_ignore_ascii_case("[ZoneTransfer]");
        } else if in_section
            && let Some((key, value)) = line.split_once('=')
            && key.trim().eq_ignore_ascii_case("ZoneId")
        {
            zone = Some(value.trim().parse::<u32>().unwrap_or(u32::MAX));
        }
    }
    zone.is_none_or(|z| z >= 3)
}

/// The `DownloadMark` of WinVPN: marked when the file's stream says so or cannot be read; a missing file and a file
/// without the stream are not marked.
pub fn is_marked(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return false,
        Err(_) => return true,
        Ok(_) => {}
    }
    let mut stream = path.as_os_str().to_owned();
    stream.push(":Zone.Identifier");
    match File::open(&stream) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => false,
        Err(_) => true,
        Ok(file) => {
            let mut data = Vec::new();
            match file.take(MAX_STREAM + 1).read_to_end(&mut data) {
                Ok(_) if data.len() as u64 <= MAX_STREAM => marks_download(&data),
                _ => true,
            }
        }
    }
}
```

`src/pure/dates.rs`:

```rust
//! The local date formats of the UI, the same as MacVPN's (`platform-mac::system::local_date_time`).

use macvpn_core::l10n::AppLanguage;

pub fn date((y, mo, d): (i32, u32, u32)) -> String {
    format!("{y:04}-{mo:02}-{d:02}")
}

/// `10/18/2026, 2:03:05 PM` (English, a narrow no-break space before AM/PM) and `2026. 10. 18. 14:03:05` (Hungarian).
pub fn date_time((y, mo, d, h, mi, s): (i32, u32, u32, u32, u32, u32), language: AppLanguage) -> String {
    match language {
        AppLanguage::Hu => format!("{y}. {mo:02}. {d:02}. {h:02}:{mi:02}:{s:02}"),
        AppLanguage::En => {
            let (h12, suffix) = match h {
                0 => (12, "AM"),
                1..=11 => (h, "AM"),
                12 => (12, "PM"),
                _ => (h - 12, "PM"),
            };
            format!("{mo}/{d}/{y}, {h12}:{mi:02}:{s:02}\u{202f}{suffix}")
        }
    }
}
```

`src/pure/texts.rs`:

```rust
//! The texts of what WinVPN 2a cannot do yet (the literals are the l10n keys).

use macvpn_core::l10n;

/// A connect, disconnect or MFA answer.
pub fn engine_later() -> String {
    l10n::tr("The VPN engine comes in a later version of WinVPN.", &[])
}

/// System Status.
pub fn engine_note() -> String {
    l10n::tr(
        "The VPN engine comes in a later version of WinVPN. You can already create, import, edit, export and back up connections.",
        &[],
    )
}
```

`crates/core/l10n/strings.json` (add, sorted with the other keys):

```json
    "The VPN engine comes in a later version of WinVPN.": {
      "hu": "A VPN-motor a WinVPN egy későbbi verziójában érkezik.",
      "scope": "platform",
      "only": ["windows"]
    },
    "The VPN engine comes in a later version of WinVPN. You can already create, import, edit, export and back up connections.": {
      "hu": "A VPN-motor a WinVPN egy későbbi verziójában érkezik. Kapcsolatokat már most is létrehozhatsz, importálhatsz, szerkeszthetsz, exportálhatsz és menthetsz.",
      "scope": "app",
      "only": ["windows"]
    },
```

(Format the `only` arrays as the file does: one element per line.)

Run: `cargo test --locked -p macvpn-platform-win --test pure && cargo test --locked -p macvpn-app-core --test l10n_coverage && node scripts/l10n-baseline.mjs --check`
Expected: PASS; the macOS baseline is unchanged (Windows-only entries are not part of it: if the script lists every key, extend it to skip entries whose `only` excludes `macos`, and say so in the commit).

- [x] **Step 4: Write the failing Windows tests** (`crates/platform-win/tests/windows.rs`)

```rust
//! WinPlatform on a real Windows system. Nothing here touches the user's real data: the key store test uses its own
//! uniquely named credential and deletes it.

#![cfg(windows)]

use macvpn_core::fsx::FileOwner;
use macvpn_core::models::{Secrets, VPNKind};
use macvpn_core::vault::KeyStore;
use macvpn_platform_api::{Platform, PlatformError, WINVPN};
use macvpn_platform_win::WinPlatform;
use std::path::Path;
use uuid::Uuid;

fn platform() -> WinPlatform {
    WinPlatform::new(true)
}

#[test]
fn identity_and_folders() {
    let p = WinPlatform::new(false);
    assert_eq!(p.product(), &WINVPN);
    let home = p.system().home_directory().expect("a profile folder");
    assert!(home.is_absolute());
    let root = p.system().app_data_root(&home);
    assert!(root.ends_with("AppData\\Local") || root.ends_with("AppData/Local"), "{root:?}");
    assert_eq!(p.system().user_owner().unwrap(), FileOwner::current_user().unwrap());
    assert!(p.system().temporary_directory().unwrap().is_absolute());
}

#[test]
fn the_sandbox_keeps_its_data_under_the_sandbox_home() {
    let p = platform();
    let home = Path::new(r"C:\sandbox-home");
    assert_eq!(p.system().app_data_root(home), home.join("AppData").join("Local"));
}

#[test]
fn entropy_is_real() {
    let mut a = [0u8; 32];
    platform().entropy().fill(&mut a).unwrap();
    assert_ne!(a, [0u8; 32]);
}

#[test]
fn the_credential_key_store_round_trips_and_deletes() {
    let store = macvpn_platform_win::credential_key_store_for_tests(&format!("local.winvpn.test.{}", Uuid::new_v4()));
    assert!(store.get().unwrap().is_none());
    assert!(!store.exists().unwrap());
    store.set(&[7u8; 32]).unwrap();
    assert!(store.exists().unwrap());
    assert_eq!(store.get().unwrap().as_deref().map(|k| k.to_vec()), Some(vec![7u8; 32]));
    store.set(&[9u8; 32]).unwrap();
    assert_eq!(store.get().unwrap().as_deref().map(|k| k.to_vec()), Some(vec![9u8; 32]));
    store.delete().unwrap();
    assert!(store.get().unwrap().is_none());
    store.delete().unwrap();
}

#[test]
fn the_sandbox_key_store_never_reaches_credential_manager() {
    let p = platform();
    let store = p.key_store();
    store.set(&[1u8; 32]).unwrap();
    assert!(store.exists().unwrap());
    // A fresh real store does not see the sandbox's item.
    assert!(!macvpn_platform_win::credential_key_store_for_tests("local.winvpn.vault.sandbox-check").exists().unwrap());
}

#[test]
fn the_vpn_parts_say_later_and_list_nothing() {
    let p = platform();
    macvpn_core::l10n::with_language(macvpn_core::l10n::AppLanguage::En, || {
        let later = "The VPN engine comes in a later version of WinVPN.";
        assert!(p.helper_client().status().unwrap().is_empty());
        assert_eq!(p.helper_client().up(VPNKind::Openvpn, &Uuid::new_v4(), b"", &Secrets::default(), false, &[]).unwrap_err(), later);
        assert!(p.native_controller().list().unwrap().is_empty());
        assert_eq!(p.native_controller().start("x", None, &Secrets::default()).unwrap_err(), later);
        assert!(p.setup().engine_note().unwrap().starts_with(later));
        let profiles = p.native_profiles(Path::new(r"C:\unused"), false);
        assert_eq!(profiles.install(&Uuid::new_v4(), b"", "x", false).unwrap_err(), later);
    });
}

#[test]
fn https_catalogs_and_updates_are_not_available_yet() {
    let p = platform();
    assert!(p.release_source().latest_release(1, "SepsiG/MacVPN").is_err());
    assert!(matches!(p.shell().open_url("http://example.com"), Err(PlatformError::Failed(_)) | Err(PlatformError::Unsupported { .. })));
}
```

`credential_key_store_for_tests(target)` is a `#[doc(hidden)] pub fn` in `lib.rs` (Windows only) returning `Box<dyn KeyStore>` over `win::keystore::CredentialKeyStore::new(target, "dek")`.

Run: `scripts/win-remote.sh run 'cargo test --locked -p macvpn-platform-win --test windows'`
Expected: FAIL to compile (`WinPlatform::new` missing).

- [x] **Step 5: `win/keystore.rs`**

```rust
//! The vault key in Credential Manager: one generic credential, DPAPI-protected for this user, never roaming.

use macvpn_core::vault::{KeyStore, KeyStoreError};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows_sys::Win32::Foundation::{ERROR_NO_SUCH_LOGON_SESSION, ERROR_NOT_FOUND, GetLastError};
use windows_sys::Win32::Security::Credentials::{
    CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW, CredFree, CredReadW, CredWriteW,
};
use zeroize::{Zeroize, Zeroizing};

/// The production credential: target `local.winvpn.vault`, user name `dek` (storage identifiers: literals).
pub(crate) const VAULT_TARGET: &str = "local.winvpn.vault";
pub(crate) const VAULT_USER: &str = "dek";
/// Credential Manager's limit for a generic credential's blob (CRED_MAX_CREDENTIAL_BLOB_SIZE).
const MAX_BLOB: usize = 5 * 512;

pub(crate) struct CredentialKeyStore {
    target: Vec<u16>,
    user: Vec<u16>,
}

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

/// The error of a failed call (status codes only, never key material).
fn failure(code: u32) -> KeyStoreError {
    if code == ERROR_NO_SUCH_LOGON_SESSION {
        KeyStoreError::Unavailable(format!("no logon session ({code})"))
    } else {
        KeyStoreError::Io(format!("Credential Manager error {code}"))
    }
}

/// The credential CredReadW returned: its blob is wiped before CredFree.
struct Read(*mut CREDENTIALW);

impl Drop for Read {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from a successful CredReadW and is freed exactly once; the blob pointer and size
        // are the system's.
        unsafe {
            let c = &*self.0;
            if !c.CredentialBlob.is_null() {
                std::slice::from_raw_parts_mut(c.CredentialBlob, c.CredentialBlobSize as usize).zeroize();
            }
            CredFree(self.0.cast());
        }
    }
}

impl CredentialKeyStore {
    pub(crate) fn new(target: &str, user: &str) -> Self {
        CredentialKeyStore { target: wide(target), user: wide(user) }
    }

    fn read(&self) -> Result<Option<Read>, KeyStoreError> {
        let mut cred: *mut CREDENTIALW = std::ptr::null_mut();
        // SAFETY: `target` is NUL-terminated; `cred` is a valid out pointer.
        if unsafe { CredReadW(self.target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut cred) } == 0 {
            // SAFETY: plain call.
            let code = unsafe { GetLastError() };
            return if code == ERROR_NOT_FOUND { Ok(None) } else { Err(failure(code)) };
        }
        Ok(Some(Read(cred)))
    }
}

impl KeyStore for CredentialKeyStore {
    fn get(&self) -> Result<Option<Zeroizing<Vec<u8>>>, KeyStoreError> {
        let Some(read) = self.read()? else { return Ok(None) };
        // SAFETY: a successful read: the blob pointer and size describe the system's buffer, alive until `read`
        // drops.
        let key = unsafe {
            let c = &*read.0;
            if c.CredentialBlob.is_null() {
                return Ok(None);
            }
            Zeroizing::new(std::slice::from_raw_parts(c.CredentialBlob, c.CredentialBlobSize as usize).to_vec())
        };
        Ok(Some(key))
    }

    fn exists(&self) -> Result<bool, KeyStoreError> {
        Ok(self.read()?.is_some())
    }

    fn set(&self, key: &[u8]) -> Result<(), KeyStoreError> {
        if key.is_empty() || key.len() > MAX_BLOB {
            return Err(KeyStoreError::Io("invalid key length".into()));
        }
        let mut blob = Zeroizing::new(key.to_vec());
        // SAFETY: CREDENTIALW is plain data; every pointer set below outlives the CredWriteW call.
        let mut cred: CREDENTIALW = unsafe { std::mem::zeroed() };
        cred.Type = CRED_TYPE_GENERIC;
        cred.TargetName = self.target.as_ptr().cast_mut();
        cred.UserName = self.user.as_ptr().cast_mut();
        cred.CredentialBlobSize = blob.len() as u32;
        cred.CredentialBlob = blob.as_mut_ptr();
        cred.Persist = CRED_PERSIST_LOCAL_MACHINE;
        // SAFETY: see above; CredWriteW copies the blob.
        if unsafe { CredWriteW(&cred, 0) } == 0 {
            // SAFETY: plain call.
            return Err(failure(unsafe { GetLastError() }));
        }
        Ok(())
    }

    fn delete(&self) -> Result<(), KeyStoreError> {
        // SAFETY: `target` is NUL-terminated.
        if unsafe { CredDeleteW(self.target.as_ptr(), CRED_TYPE_GENERIC, 0) } == 0 {
            // SAFETY: plain call.
            let code = unsafe { GetLastError() };
            if code != ERROR_NOT_FOUND {
                return Err(failure(code));
            }
        }
        Ok(())
    }
}
```

- [x] **Step 6: `win/system.rs`, `win/shell.rs`, `win/not_yet.rs`, `win/platform.rs`**

`win/system.rs`:

```rust
//! Known folders, the user and the local time.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use windows_sys::Win32::Foundation::{FILETIME, SYSTEMTIME};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::Time::{FileTimeToSystemTime, SystemTimeToTzSpecificLocalTime};
use windows_sys::Win32::UI::Shell::{FOLDERID_Profile, FOLDERID_LocalAppData, KF_FLAG_DEFAULT, SHGetKnownFolderPath};
use windows_sys::core::GUID;

fn known_folder(id: &GUID) -> Option<PathBuf> {
    let mut path: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: valid GUID and out pointer; on success the string is CoTaskMemAlloc'ed and freed below.
    let hr = unsafe { SHGetKnownFolderPath(id, KF_FLAG_DEFAULT as _, std::ptr::null_mut(), &mut path) };
    let result = if hr >= 0 && !path.is_null() {
        // SAFETY: a NUL-terminated wide string from the system.
        let len = unsafe { (0..).take_while(|&i| *path.add(i) != 0).count() };
        // SAFETY: `len` u16s are readable.
        Some(PathBuf::from(OsString::from_wide(unsafe { std::slice::from_raw_parts(path, len) })))
    } else {
        None
    };
    // SAFETY: CoTaskMemFree accepts null.
    unsafe { CoTaskMemFree(path.cast()) };
    result
}

pub(crate) fn profile() -> Option<PathBuf> {
    known_folder(&FOLDERID_Profile)
}

pub(crate) fn local_app_data() -> Option<PathBuf> {
    known_folder(&FOLDERID_LocalAppData)
}

/// The local (y, m, d, h, mi, s) of a Unix time; `None` before 1601 or past the system's range.
pub(crate) fn local_time(unix: f64) -> Option<(i32, u32, u32, u32, u32, u32)> {
    if !unix.is_finite() {
        return None;
    }
    // 100 ns ticks since 1601-01-01.
    let ticks = (unix.floor() as i64).checked_add(11_644_473_600)?.checked_mul(10_000_000)?;
    let ticks = u64::try_from(ticks).ok()?;
    let ft = FILETIME { dwLowDateTime: ticks as u32, dwHighDateTime: (ticks >> 32) as u32 };
    // SAFETY: plain data structs; the calls fill `utc` and `local`.
    let (mut utc, mut local): (SYSTEMTIME, SYSTEMTIME) = unsafe { (std::mem::zeroed(), std::mem::zeroed()) };
    if unsafe { FileTimeToSystemTime(&ft, &mut utc) } == 0
        || unsafe { SystemTimeToTzSpecificLocalTime(std::ptr::null(), &utc, &mut local) } == 0
    {
        return None;
    }
    Some((
        i32::from(local.wYear),
        u32::from(local.wMonth),
        u32::from(local.wDay),
        u32::from(local.wHour),
        u32::from(local.wMinute),
        u32::from(local.wSecond),
    ))
}
```

`win/shell.rs`:

```rust
//! Opening folders, URLs and Settings pages with the shell. Never a file: on Windows "open" runs an executable.

use macvpn_platform_api::PlatformError;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(Some(0)).collect()
}

fn shell_open(target: &OsStr) -> Result<(), PlatformError> {
    let (verb, target) = (wide(OsStr::new("open")), wide(target));
    // SAFETY: NUL-terminated strings, no parameters or directory, no owner window.
    let result = unsafe {
        ShellExecuteW(std::ptr::null_mut(), verb.as_ptr(), target.as_ptr(), std::ptr::null(), std::ptr::null(), SW_SHOWNORMAL)
    };
    // Values above 32 mean success.
    if result as usize > 32 { Ok(()) } else { Err(PlatformError::Failed(format!("ShellExecute failed ({})", result as usize))) }
}

/// Absolute directories only (Explorer opens them); a file is refused.
pub(crate) fn open_directory(path: &Path) -> Result<(), PlatformError> {
    if !path.is_absolute() || !std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()) {
        return Err(PlatformError::Failed("refused path".into()));
    }
    shell_open(path.as_os_str())
}

/// `https://` URLs only (the caller validated it already).
pub(crate) fn open_https(url: &str) -> Result<(), PlatformError> {
    if !url.starts_with("https://") || url.chars().any(|c| c.is_whitespace() || c == '"') {
        return Err(PlatformError::Failed("refused URL".into()));
    }
    shell_open(OsStr::new(url))
}

/// A fixed `ms-settings:` page.
pub(crate) fn open_settings(page: &'static str) {
    debug_assert!(page.starts_with("ms-settings:"));
    let _ = shell_open(OsStr::new(page));
}
```

`win/not_yet.rs`:

```rust
//! The VPN parts of WinVPN 2a: nothing runs, nothing is listed, every action says the engine comes later.

use crate::pure::texts;
use macvpn_core::mfa::AuthResponseKind;
use macvpn_core::models::{Connection, Secrets, VPNKind};
use macvpn_core::native::NativeKind;
use macvpn_core::status::RootStatus;
use macvpn_platform_api::{HelperClient, NativeController, NativeProfile, NativeProfiles, SystemVpn};
use uuid::Uuid;
use zeroize::Zeroizing;

pub(crate) struct NoEngine;

impl HelperClient for NoEngine {
    /// Nothing runs.
    fn status(&self) -> Result<Vec<RootStatus>, String> {
        Ok(Vec::new())
    }

    fn up(&self, _: VPNKind, _: &Uuid, _: &[u8], _: &Secrets, _: bool, _: &[String]) -> Result<(), String> {
        Err(texts::engine_later())
    }

    fn down(&self, _: VPNKind, _: &Uuid) -> Result<(), String> {
        Err(texts::engine_later())
    }

    fn respond(&self, _: &Uuid, _: AuthResponseKind, _: &str) -> Result<(), String> {
        Err(texts::engine_later())
    }
}

impl NativeController for NoEngine {
    /// No system VPN is listed (no error, so no error loop in the poller).
    fn list(&self) -> Result<Vec<SystemVpn>, String> {
        Ok(Vec::new())
    }

    fn remote_address(&self, _: &str) -> Option<String> {
        None
    }

    fn start(&self, _: &str, _: Option<NativeKind>, _: &Secrets) -> Result<(), String> {
        Err(texts::engine_later())
    }

    fn stop(&self, _: &str) -> Result<(), String> {
        Err(texts::engine_later())
    }
}

impl NativeProfiles for NoEngine {
    /// An empty profile: the connection can be created, edited and saved.
    fn build(&self, connection: &Connection, _psk: &str) -> Result<NativeProfile, String> {
        Ok(NativeProfile { data: Zeroizing::new(Vec::new()), file_name: format!("{}.pending", connection.id) })
    }

    /// Nothing is installed; the editor shows this after saving.
    fn install(&self, _: &Uuid, _: &[u8], _: &str, _: bool) -> Result<(), String> {
        Err(texts::engine_later())
    }
}
```

`win/locale.rs`:

```rust
//! The user's UI languages and the locale-aware comparison of connection names (core's hooks).

use macvpn_core::{collation, l10n};
use std::cmp::Ordering;
use windows_sys::Win32::Globalization::{
    CSTR_EQUAL, CSTR_GREATER_THAN, CSTR_LESS_THAN, CompareStringEx, GetUserPreferredUILanguages,
    LINGUISTIC_IGNORECASE, LOCALE_NAME_USER_DEFAULT, MUI_LANGUAGE_NAME,
};

pub(crate) fn install() {
    l10n::AppLanguage::set_preferred_languages(preferred_languages());
    collation::set_localized_compare(Some(compare));
}

/// `GetUserPreferredUILanguages` as BCP 47 names (`hu-HU`, `en-US`), most preferred first.
fn preferred_languages() -> Vec<String> {
    let (mut count, mut len) = (0u32, 0u32);
    // SAFETY: a size query with a null buffer.
    if unsafe { GetUserPreferredUILanguages(MUI_LANGUAGE_NAME, &mut count, std::ptr::null_mut(), &mut len) } == 0 {
        return Vec::new();
    }
    let mut buf = vec![0u16; len as usize];
    // SAFETY: `buf` holds `len` u16s as the size query asked.
    if unsafe { GetUserPreferredUILanguages(MUI_LANGUAGE_NAME, &mut count, buf.as_mut_ptr(), &mut len) } == 0 {
        return Vec::new();
    }
    // A double-NUL-terminated list of NUL-terminated names.
    buf.split(|&c| c == 0).filter(|s| !s.is_empty()).map(String::from_utf16_lossy).collect()
}

/// Swift's `localizedCaseInsensitiveCompare` on Windows: the user's locale, case-insensitive.
fn compare(a: &str, b: &str) -> Ordering {
    let (wa, wb): (Vec<u16>, Vec<u16>) = (a.encode_utf16().collect(), b.encode_utf16().collect());
    // SAFETY: explicit lengths; no NUL termination needed.
    let r = unsafe {
        CompareStringEx(
            LOCALE_NAME_USER_DEFAULT,
            LINGUISTIC_IGNORECASE,
            wa.as_ptr(),
            wa.len() as i32,
            wb.as_ptr(),
            wb.len() as i32,
            std::ptr::null(),
            std::ptr::null(),
            0,
        )
    };
    match r {
        CSTR_LESS_THAN => Ordering::Less,
        CSTR_GREATER_THAN => Ordering::Greater,
        CSTR_EQUAL => Ordering::Equal,
        _ => collation::default_compare(a, b),
    }
}
```

(`collation::default_compare` is core's fallback; if it is private, make it `pub` – it has no OS dependency.)

`win/registry.rs` (shared by Tasks 12 and 13):

```rust
//! The few `HKEY_CURRENT_USER` values WinVPN reads and writes.

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows_sys::Win32::System::Registry::{
    HKEY_CURRENT_USER, REG_BINARY, REG_SZ, RRF_RT_REG_BINARY, RRF_RT_REG_DWORD, RRF_RT_REG_SZ, RegDeleteKeyValueW,
    RegGetValueW, RegSetKeyValueW,
};

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

fn read(subkey: &str, value: &str, flags: u32) -> Option<Vec<u8>> {
    let (k, v) = (wide(subkey), wide(value));
    let mut len = 0u32;
    // SAFETY: a size query (null data pointer).
    if unsafe { RegGetValueW(HKEY_CURRENT_USER, k.as_ptr(), v.as_ptr(), flags, std::ptr::null_mut(), std::ptr::null_mut(), &mut len) } != 0 {
        return None;
    }
    let mut buf = vec![0u8; len as usize];
    // SAFETY: `buf` holds `len` bytes.
    if unsafe { RegGetValueW(HKEY_CURRENT_USER, k.as_ptr(), v.as_ptr(), flags, std::ptr::null_mut(), buf.as_mut_ptr().cast(), &mut len) } != 0 {
        return None;
    }
    buf.truncate(len as usize);
    Some(buf)
}

pub(crate) fn read_dword(subkey: &str, value: &str) -> Option<u32> {
    read(subkey, value, RRF_RT_REG_DWORD).and_then(|b| Some(u32::from_le_bytes(b.get(..4)?.try_into().ok()?)))
}

pub(crate) fn read_string(subkey: &str, value: &str) -> Option<String> {
    let bytes = read(subkey, value, RRF_RT_REG_SZ)?;
    let units: Vec<u16> = bytes.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    Some(String::from_utf16_lossy(units.split(|&c| c == 0).next().unwrap_or_default()))
}

pub(crate) fn read_binary(subkey: &str, value: &str) -> Option<Vec<u8>> {
    read(subkey, value, RRF_RT_REG_BINARY)
}

pub(crate) fn write_string(subkey: &str, value: &str, data: &str) -> io::Result<()> {
    let (k, v, d) = (wide(subkey), wide(value), wide(data));
    // SAFETY: NUL-terminated strings; the size includes the terminating NUL, as REG_SZ requires.
    let err = unsafe { RegSetKeyValueW(HKEY_CURRENT_USER, k.as_ptr(), v.as_ptr(), REG_SZ, d.as_ptr().cast(), (d.len() * 2) as u32) };
    if err == 0 { Ok(()) } else { Err(io::Error::from_raw_os_error(err as i32)) }
}

pub(crate) fn write_binary(subkey: &str, value: &str, data: &[u8]) -> io::Result<()> {
    let (k, v) = (wide(subkey), wide(value));
    // SAFETY: `data` is valid for its length.
    let err = unsafe { RegSetKeyValueW(HKEY_CURRENT_USER, k.as_ptr(), v.as_ptr(), REG_BINARY, data.as_ptr().cast(), data.len() as u32) };
    if err == 0 { Ok(()) } else { Err(io::Error::from_raw_os_error(err as i32)) }
}

/// A missing value (or key) is not an error.
pub(crate) fn delete_value(subkey: &str, value: &str) -> io::Result<()> {
    let (k, v) = (wide(subkey), wide(value));
    // SAFETY: NUL-terminated strings.
    let err = unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, k.as_ptr(), v.as_ptr()) };
    if err == 0 || err == ERROR_FILE_NOT_FOUND { Ok(()) } else { Err(io::Error::from_raw_os_error(err as i32)) }
}
```

Add a registry round trip to `tests/windows.rs` through a `#[doc(hidden)] pub fn registry_round_trip_for_tests() -> bool` in `lib.rs` that writes, reads and deletes `Software\WinVPN-test-<uuid>` / `x` (string and binary) and returns whether every step matched.

`win/platform.rs`: `pub struct WinPlatform { sandbox: Option<Sandbox> }` with `struct Sandbox { key_store: Arc<MemoryKeyStore>, preferences: Arc<MemoryPreferences> }`, and:

```rust
impl WinPlatform {
    /// `sandbox` (debug builds, `MACVPN_SANDBOX_HOME`): memory key store and preferences, data under the sandbox
    /// home; never Credential Manager.
    pub fn new(sandbox: bool) -> WinPlatform {
        WinPlatform {
            sandbox: sandbox.then(|| Sandbox {
                key_store: Arc::new(MemoryKeyStore::new()),
                preferences: Arc::new(MemoryPreferences::new()),
            }),
        }
    }

    pub fn is_sandbox(&self) -> bool {
        self.sandbox.is_some()
    }
}
```

and the `Platform` accessors (the ones not listed keep the moved stub's inert behaviour, which Tasks 10, 12 and 13 replace):

| Accessor | 2a behaviour |
|---|---|
| `product` | `&WINVPN` |
| `install_core_hooks` | `locale::install()` (the preferred UI languages and the locale-aware name comparison), then `l10n::set_text_platform(WINVPN.text_platform())` |
| `system().home_directory` | `system::profile()` |
| `system().app_data_root(home)` | sandbox: `home/AppData/Local`; else `system::local_app_data()` or, if that fails, `home/AppData/Local` |
| `system().user_owner` | `FileOwner::current_user()` mapped to `PlatformError::Failed` |
| `system().user_name` | `None` (only the helper installer uses it: 2b) |
| `system().temporary_directory` | `Ok(std::env::temp_dir())` |
| `system().local_date` / `local_date_time` | `pure::dates` over `system::local_time` (empty string when `None`) |
| `system().app_location` | the directory of `std::env::current_exe()` when the file name is `WinVPN.exe` (an installed or bundled build), else `None` |
| `system().bundled_helper_dir`, `update_info` | `None` (2b) |
| `shell()` | `open_path` → `shell::open_directory`; `open_url` → `shell::open_https`; `open_native_profile_settings` → `shell::open_settings("ms-settings:network-vpn")`; `copy_text` → `Unsupported` until Task 12 |
| `setup()` | `check` → `SetupReport::unknown()`; installers → `Unsupported`; `helper_upgrade_notice` → `texts::engine_later()`; `engine_note` → `Some(texts::engine_note())` |
| `helper_client`, `native_controller`, `native_profiles` | `Arc::new(NoEngine)` |
| `system_vpn_watch().start` | `Ok(Box::new(()))` (nothing to watch) |
| `download_mark().is_marked` | `pure::zone::is_marked` |
| `entropy()` | an `Entropy` over `macvpn_winsys::random::fill` |
| `key_store()` | sandbox: its `MemoryKeyStore`; else `CredentialKeyStore::new(VAULT_TARGET, VAULT_USER)` |
| `legacy_keychain`, `legacy_secrets` | empty (as the stub) |
| `preferences()` | sandbox: its `MemoryPreferences`; else `FilePreferences::new(<local app data>/WinVPN/preferences.json)` (the product's `data_dir` of `app_data_root`) |
| `release_source`, `https_catalog_fetcher`, `log_streams` | as the stub (`Unsupported` / `CatalogError::Unavailable`) – question 2 |
| `updater` | as the stub (`Unsupported`), `cache_directory` `None` |

- [x] **Step 7: Run on both systems**

Run (Mac): `cargo test --locked -p macvpn-platform-win && cargo clippy --workspace --all-targets --locked -- -D warnings && scripts/check-windows.sh`
Run: `scripts/win-remote.sh run 'cargo test --locked -p macvpn-platform-win'`
Expected: PASS on both. Then on Windows, `cmdkey /list | grep -c local.winvpn.test` prints `0` (the test deleted its credential).

- [x] **Step 8: Commit**

```bash
git add crates/platform-win crates/core/l10n/strings.json app/src-tauri Cargo.lock
git commit -m "feat(platform-win): known folders, Credential Manager key, file preferences, Mark of the Web" -m "WinPlatform::new(sandbox) replaces the stub. The vault key is a generic credential (DPAPI, this user, never roaming); the sandbox keeps it in memory. The VPN parts list nothing and answer that the engine comes in a later version; System Status shows the engine note." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

## Task 10: the control API over the named pipe

**Goal:** WinVPN's control API listens on `\\.\pipe\WinVPN-control-<SID>`; the whole app-core control suite and the example client run over a real pipe on Windows; the example client verifies the server's user.

**Files:**
- Create: `crates/platform-win/src/win/control.rs`, `crates/platform-win/tests/control_pipe.rs`
- Modify: `crates/platform-win/src/win/{mod.rs, platform.rs}` (`control_transport()`, `entropy()` share the pipe transport's randomness)
- Modify: `crates/app-core/tests/control_support/mod.rs`, `crates/app-core/tests/control_server.rs`, `crates/app-core/tests/control_example_client.rs`, `crates/app-core/Cargo.toml` (`[target.'cfg(windows)'.dev-dependencies] macvpn-winsys = { path = "../winsys" }`)
- Modify: `examples/macvpn-control-client/{Cargo.toml, src/lib.rs, src/main.rs, README.md}`

- [x] **Step 1: Write the failing transport test** (`crates/platform-win/tests/control_pipe.rs`)

```rust
//! The control transport over the named pipe (Windows).

#![cfg(windows)]

use macvpn_core::fsx::{self, Access, Follow};
use macvpn_platform_api::{Accepted, ControlTransport, PeerUser};
use macvpn_platform_win::control_transport_for_tests;
use std::io::{ErrorKind, Write};
use std::time::Duration;

#[test]
fn bind_accept_and_the_peer() {
    let dir = std::env::temp_dir().join(format!("control-{}", uuid::Uuid::new_v4()));
    let name = format!(r"\\.\pipe\WinVPN-control-test-{}", uuid::Uuid::new_v4());
    let transport = control_transport_for_tests(&name);
    let bound = transport.bind(&dir).unwrap();
    assert_eq!(bound.display, name);
    assert_eq!(bound.socket_file, None);
    assert!(fsx::has_access(&fsx::stat_path(&dir, Follow::No).unwrap(), Access::Private), "the directory is private");
    assert_eq!(transport.bind(&dir).err().unwrap().kind(), ErrorKind::AddrInUse);
    assert_ne!(transport.random_32().unwrap(), [0u8; 32]);

    let client = std::thread::spawn({
        let name = name.clone();
        move || {
            let s = macvpn_winsys::pipe::connect(&name, Duration::from_secs(5)).unwrap();
            (&s).write_all(b"{}\n").unwrap();
            s
        }
    });
    let accepted = loop {
        if let Accepted::Client { stream, peer } = bound.listener.accept(Duration::from_millis(100)).unwrap() {
            break (stream, peer.unwrap());
        }
    };
    let (_stream, peer) = accepted;
    let me = macvpn_winsys::sid::Sid::current_user().unwrap().to_string();
    assert_eq!(peer.user, PeerUser::Sid(me));
    assert!(peer.same_user);
    assert_eq!(peer.pid, std::process::id() as i32);
    let exe = std::env::current_exe().unwrap().to_string_lossy().to_lowercase();
    assert_eq!(peer.executable.map(|e| e.to_lowercase()), Some(exe));
    drop(client.join().unwrap());
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn closed_pipe_errors_are_already_closed() {
    let transport = control_transport_for_tests(r"\\.\pipe\unused");
    assert!(transport.is_already_closed(&std::io::Error::from(ErrorKind::BrokenPipe)));
    assert!(transport.is_already_closed(&std::io::Error::from_raw_os_error(233)));
    assert!(!transport.is_already_closed(&std::io::Error::from(ErrorKind::TimedOut)));
}
```

Run: `scripts/win-remote.sh run 'cargo test --locked -p macvpn-platform-win --test control_pipe'`
Expected: FAIL to compile (`control_transport_for_tests` missing).

- [x] **Step 2: `win/control.rs`**

```rust
//! The control API's endpoint on Windows: `\\.\pipe\WinVPN-control-<SID>` (see macvpn_winsys::pipe for the DACL,
//! the identity and the I/O).

use macvpn_core::fsx::{self, FileOwner};
use macvpn_platform_api::{Accepted, BoundEndpoint, ControlListener, ControlStream, ControlTransport, PeerIdentity, PeerUser};
use macvpn_winsys::pipe::{self, Listener, PipeStream};
use macvpn_winsys::sid::Sid;
use std::io::{self, ErrorKind, Read, Write};
use std::net::Shutdown;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// The pipe name's prefix (a storage identifier: clients find WinVPN by it).
pub(crate) const CONTROL_PIPE_PREFIX: &str = "WinVPN-control";

pub(crate) struct PipeTransport {
    name: String,
}

impl PipeTransport {
    pub(crate) fn for_user() -> io::Result<PipeTransport> {
        Ok(PipeTransport { name: pipe::user_pipe_name(CONTROL_PIPE_PREFIX)? })
    }

    pub(crate) fn with_name(name: &str) -> PipeTransport {
        PipeTransport { name: name.to_string() }
    }
}

struct PipeListener(Arc<Listener>);

struct Stream(PipeStream);

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read_some(buf)
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write_some(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl ControlStream for Stream {
    fn try_clone(&self) -> io::Result<Box<dyn ControlStream>> {
        Ok(Box::new(Stream(self.0.try_clone())))
    }

    fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.0.shutdown(how)
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.0.set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.0.set_write_timeout(timeout)
    }

    fn peer_connected(&self) -> bool {
        self.0.peer_connected()
    }
}

fn identity(peer: pipe::Peer) -> io::Result<PeerIdentity> {
    let me = Sid::current_user()?;
    Ok(PeerIdentity {
        same_user: peer.sid == me,
        user: PeerUser::Sid(peer.sid.to_string()),
        pid: i32::try_from(peer.pid).unwrap_or(-1),
        executable: peer.image.and_then(|p| p.into_os_string().into_string().ok()),
    })
}

impl ControlListener for PipeListener {
    fn accept(&self, poll: Duration) -> io::Result<Accepted> {
        Ok(match self.0.accept(poll)? {
            None => Accepted::Idle,
            Some((stream, peer)) => Accepted::Client { stream: Box::new(Stream(stream)), peer: peer.and_then(identity) },
        })
    }
}

impl ControlTransport for PipeTransport {
    fn bind(&self, dir: &Path) -> io::Result<BoundEndpoint> {
        self.prepare_dir(dir)?;
        let listener = Arc::new(Listener::bind(&self.name)?);
        Ok(BoundEndpoint {
            listener: Box::new(PipeListener(listener.clone())),
            display: self.name.clone(),
            socket_file: None,
            // The first instance is the single-instance lock: the name stays ours until the server drops this last.
            guard: Box::new(listener),
        })
    }

    fn random_32(&self) -> io::Result<[u8; 32]> {
        let mut bytes = [0u8; 32];
        macvpn_winsys::random::fill(&mut bytes)?;
        Ok(bytes)
    }

    /// ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED: a client that connected and left at once.
    fn is_already_closed(&self, e: &io::Error) -> bool {
        e.kind() == ErrorKind::BrokenPipe || e.kind() == ErrorKind::NotConnected || matches!(e.raw_os_error(), Some(109 | 232 | 233))
    }

    /// The directory (the audit file's home) is a real, private directory of this user.
    fn prepare_dir(&self, dir: &Path) -> io::Result<()> {
        let owner = fsx::ensure_private_dir(dir)?;
        if owner != FileOwner::current_user()? {
            return Err(io::Error::new(ErrorKind::PermissionDenied, format!("{} is not this user's", dir.display())));
        }
        Ok(())
    }
}
```

`platform.rs`: `fn control_transport(&self) -> Arc<dyn ControlTransport>` returns `Arc::new(PipeTransport::for_user())` or, if the SID cannot be read, the old stub transport (binds nothing: fail closed). `lib.rs`: `#[cfg(windows)] #[doc(hidden)] pub fn control_transport_for_tests(name: &str) -> std::sync::Arc<dyn macvpn_platform_api::ControlTransport> { std::sync::Arc::new(win::control::PipeTransport::with_name(name)) }`. Add `macvpn-winsys` and `uuid` (`features = ["v4"]`) to platform-win's Windows dev-dependencies.

Run: `scripts/win-remote.sh run 'cargo test --locked -p macvpn-platform-win --test control_pipe'`
Expected: PASS.

- [x] **Step 3: app-core's suite over a real pipe**

In `crates/app-core/tests/control_support/mod.rs`:
1. `Kind::Pipe` (doc: "A real named pipe (Windows only); the peer identity is the fake one, as for the other kinds.").
2. `FakeTransport` gets `pipe_name: Mutex<Option<String>>`.
3. `bind`'s match gets:

```rust
            #[cfg(windows)]
            Kind::Pipe => {
                let name = format!(r"\\.\pipe\macvpn-test-{}", uuid::Uuid::new_v4());
                let listener = macvpn_winsys::pipe::Listener::bind(&name)?;
                *self.pipe_name.lock().unwrap() = Some(name.clone());
                Ok(BoundEndpoint {
                    listener: Box::new(PipeTestListener { listener, peer, uid }),
                    display: name,
                    socket_file: None,
                    guard: Box::new(()),
                })
            }
            #[cfg(not(windows))]
            Kind::Pipe => Err(io::Error::from(ErrorKind::Unsupported)),
```

4. A `PipeTestListener` like `LoopbackListener`, whose `accept` maps `listener.accept(poll)?` to `Accepted::Idle` / `Accepted::Client { stream: Box::new(PipeWrap(stream)), peer: Ok(peer.identity(uid)) }` (the fake identity; the real peer of the pipe is ignored here), and `PipeWrap` through the file's existing stream-wrapping macro over `macvpn_winsys::pipe::PipeStream` (its `try_clone` returns the clone in `Ok`, `shutdown`, the timeouts and `peer_connected` delegate).
5. The suite's client connect helper (`grep -n 'TcpStream::connect\|UnixStream::connect' crates/app-core/tests/control_support/mod.rs`) gets a `Kind::Pipe` arm: `macvpn_winsys::pipe::connect(&name, Duration::from_secs(5))` wrapped like the others.
6. `is_already_closed` also accepts `ErrorKind::BrokenPipe` and the raw codes 109/232/233.
7. The list of kinds the server suite runs over (`grep -n 'Kind::Loopback' crates/app-core/tests/control_server.rs`) gets `Kind::Pipe` under `cfg!(windows)` (e.g. `fn kinds() -> Vec<Kind>`: Unix `[Unix, Loopback]`, Windows `[Loopback, Pipe]`).
8. `peer_user(Kind::Pipe)` is `"uid 0"` (the fake identity's uid, like Loopback).

In `crates/app-core/tests/control_example_client.rs`: the harness that starts the server for the example client uses `Kind::Unix` on Unix and `Kind::Pipe` on Windows, and passes the pipe name as the client's path.

Run: `scripts/win-remote.sh run 'cargo test --locked -p macvpn-app-core --test control_server --test control_example_client'`
Expected: the Pipe runs PASS (the tests that still carry a "private files" ignore stay ignored until Task 11 – run them now with `-- --include-ignored` to see them pass already, and note any failure for Task 11).

- [x] **Step 4: The example client's Windows transport**

`examples/macvpn-control-client/Cargo.toml`:

```toml
# std + serde_json only on Unix, so the client is easy to copy. On Windows the named pipe needs Win32 calls (the
# server's user must be checked before a token is sent): macvpn-winsys, see the README.
[target.'cfg(windows)'.dependencies]
macvpn-winsys = { path = "../../crates/winsys" }
```

`src/lib.rs`, replace the `#[cfg(not(unix))] mod transport` by:

```rust
/// On Windows: WinVPN's named pipe, `\\.\pipe\WinVPN-control-<your SID>` ([`default_endpoint`]). The client asks for
/// identification-level impersonation only and refuses a pipe served by another user, so a squatter never sees a
/// token.
#[cfg(windows)]
mod transport {
    use macvpn_winsys::pipe::{self, PipeStream};
    use std::io::{self, ErrorKind, Read, Write};
    use std::net::Shutdown;
    use std::path::Path;
    use std::time::Duration;

    pub(crate) struct Stream(PipeStream);

    pub(crate) fn connect(path: &Path) -> io::Result<Stream> {
        let name = path.to_str().ok_or_else(|| io::Error::from(ErrorKind::InvalidInput))?;
        pipe::connect(name, Duration::from_secs(5)).map(Stream)
    }

    impl Stream {
        pub(crate) fn try_clone(&self) -> io::Result<Stream> {
            Ok(Stream(self.0.try_clone()))
        }

        pub(crate) fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            self.0.set_read_timeout(timeout)
        }

        pub(crate) fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            self.0.set_write_timeout(timeout)
        }

        pub(crate) fn shutdown(&self, how: Shutdown) -> io::Result<()> {
            self.0.shutdown(how)
        }
    }

    impl Read for Stream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read_some(buf)
        }
    }

    impl Write for Stream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write_some(buf)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
}

/// WinVPN's control endpoint for this user (the pipe name, used as the path of [`Client::connect`]).
#[cfg(windows)]
pub fn default_endpoint() -> std::io::Result<std::path::PathBuf> {
    macvpn_winsys::pipe::user_pipe_name("WinVPN-control").map(std::path::PathBuf::from)
}
```

(Keep the old `#[cfg(not(unix))]` stub only for targets that are neither Unix nor Windows: change its cfg to `#[cfg(not(any(unix, windows)))]`.) If `Closer` or `Client` call other `Stream` methods, add them the same way. `src/main.rs`: on Windows, the default path is `default_endpoint()`; `README.md`: a "Windows" section: the pipe name, the identification-only connection, the server-user check, and that `crates/winsys/src/{pipe.rs, sid.rs, security.rs, util.rs}` must be copied along (or depended on).

Run: `scripts/check-windows.sh && scripts/win-remote.sh run 'cargo test --locked -p macvpn-control-client -p macvpn-app-core --test control_example_client -- --include-ignored'`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add crates/platform-win crates/app-core/tests crates/app-core/Cargo.toml examples/macvpn-control-client Cargo.lock
git commit -m "feat(control): the control API over a per-user named pipe on Windows" -m "\\\\.\\pipe\\WinVPN-control-<SID>: protected DACL (no NETWORK; the user and SYSTEM), remote clients rejected, the first instance as the single-instance lock, the peer's SID through identification-level impersonation. The app-core server suite and the example client run over a real pipe on Windows; the example client refuses a server of another user." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

## Task 11: the Windows ignores go

**Goal:** no test is ignored on Windows only. The list of ignored tests is the same on macOS and Windows, and CI enforces it.

**Files:**
- Modify: every test file with `cfg_attr(windows, ignore = "private files on Windows: phase 2")` (542 marks, list in "Key facts") and `crates/app-core/src/vault.rs` (one unit-test mark)
- Create: `scripts/check-ignored.sh`, `scripts/ignored-everywhere.txt`
- Modify: production code where a test exposes a real Windows bug (one commit per bug, each with its regression test)

- [x] **Step 1: Write the gate first** (`scripts/check-ignored.sh`)

```bash
#!/bin/bash
# No test may be ignored on one OS only: the ignored tests of the workspace's test set must be exactly
# scripts/ignored-everywhere.txt (the tests ignored on every OS, e.g. the fixture writers).
#
#   scripts/check-ignored.sh [CARGO ARGS...]            compare (e.g. --target x86_64-pc-windows-msvc)
#   scripts/check-ignored.sh --write [CARGO ARGS...]    rewrite the list (only when a test is ignored everywhere)
set -euo pipefail
cd "$(dirname "$0")/.."
WRITE=0
if [ "${1:-}" = --write ]; then WRITE=1; shift; fi
PACKAGES=(-p macvpn-core -p macvpn-app-core -p macvpn-platform-api -p macvpn-platform-win -p macvpn-helper -p macvpn-winsys -p macvpn-control-client)
LIST="$(CI=1 cargo test --locked "$@" "${PACKAGES[@]}" --lib --tests -- --list --ignored 2>/dev/null | sed -n 's/: test$//p' | LC_ALL=C sort)"
if [ "$WRITE" = 1 ]; then
  printf '%s\n' "$LIST" >scripts/ignored-everywhere.txt
  echo "wrote scripts/ignored-everywhere.txt ($(grep -c . scripts/ignored-everywhere.txt) tests)"
  exit 0
fi
if ! diff -u scripts/ignored-everywhere.txt <(printf '%s\n' "$LIST"); then
  echo "FAIL: the ignored tests differ from scripts/ignored-everywhere.txt (a test is ignored on this OS only, or the list is stale)"
  exit 1
fi
if grep -rnE 'cfg_attr\((windows|not\(unix\)|not\(target_os = "macos"\)), *ignore' crates app examples --include='*.rs' | grep -v 'crates/app-core/tests/cfg_rule.rs'; then
  echo "FAIL: an OS-specific ignore is left in the sources"
  exit 1
fi
echo "OK: $(grep -c . scripts/ignored-everywhere.txt) ignored tests, the same on every OS"
```

Run (Mac): `chmod +x scripts/check-ignored.sh && scripts/check-ignored.sh --write && cat scripts/ignored-everywhere.txt`
Expected: the tests ignored on macOS today (fixture writers such as `write_compat_fixtures`, and whatever else carries a plain `#[ignore]`); review the list: every entry must be a plain `#[ignore]` (not OS-specific). Then `scripts/check-ignored.sh` → `FAIL: an OS-specific ignore is left in the sources` (the marks are still there).

*As done:* the script compares the ignored tests with the list's entries **that are built on this OS** (`--list` of all tests, intersected with the list), because a test that exists on one OS only and is ignored there (`winsys/tests/pipe.rs::another_user_is_refused_both_ways`, a manual check that needs a second account) can never appear on the other; `--write` keeps the entries not built here. The list: `another_user_is_refused_both_ways`, `default_parameters_timing`, `write_compat_fixtures`. Before: 544 tests ignored on Windows (542 marks + 2 plain; Tasks 5 and 8 had already removed 31), 3 after (the list). The one production bug: every vault write overflowed the stack on Windows (SQLCipher's memory security + its stderr log, `VirtualLock` quota): `fix(core): SQLCipher's log no longer recurses on Windows`.

- [x] **Step 2: Remove the marks**

Run: `grep -rln 'cfg_attr(windows, ignore = "private files on Windows: phase 2")' crates app | xargs sed -i '' '/cfg_attr(windows, ignore = "private files on Windows: phase 2")/d'`
Then: `grep -rn 'cfg_attr(windows, ignore' crates app examples --include='*.rs' | grep -v cfg_rule.rs` → no output; `cargo fmt --all --check` → PASS (the marks were whole lines).

- [x] **Step 3: Run the whole set on Windows and sort the failures**

Run: `scripts/win-remote.sh test 2>&1 | tee /tmp/win-tests.txt | tail -50; grep -E '^test .* FAILED$|^---- ' /tmp/win-tests.txt | sort | uniq > /tmp/win-failures.txt; wc -l /tmp/win-failures.txt`
Expected: some failures. For each, use superpowers:systematic-debugging. The known Windows differences, and what to do:

| Symptom | Cause | Fix |
|---|---|---|
| `PermissionDenied` / `os error 5` on `fs::rename` over a file, or on `remove_file` | the target is still open in this process (Windows refuses to replace or delete an open file unless it was opened with delete sharing) | production code: close (drop) the handle before the rename/remove; regression test that reproduces the order |
| `os error 32` (sharing violation) | two handles to the same file, one without sharing (often SQLite's journal while the test copies the file) | close the vault before copying in the test (a test bug), or open with the sharing std uses by default |
| an assertion on a path string with `/` | the test builds expected text with `/` | build it with `Path::join` / `display()` in the test |
| a byte-compared fixture differs by `\r\n` | a checkout with CRLF | the harness and CI check out with `core.autocrlf false`; if a file is generated at test time with `\n` and compared with a text from `include_str!`, keep both LF |
| a test asserts Unix modes (`0o600`) | genuinely Unix-only | `#[cfg(unix)]` on that test, and a Windows twin asserting `fsx::has_access(…, Access::Private)` where the behaviour matters |
| timing (a 2 s budget missed) | slower file system on Windows (Defender scans) | raise the budget only in the test, with a comment, never in production |

Never re-add an ignore. If a failure needs a design decision (not a bug), stop and ask the maintainer.

- [x] **Step 4: One commit per production bug**

For each production fix: the failing test (already there), the fix, `scripts/win-remote.sh test` for the affected crate, the Mac checks, then

```bash
git add <the files>
git commit -m "fix(<crate>): <what Windows exposed>" -m "<cause, and why macOS was not affected>" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

- [x] **Step 5: The gate passes on both systems**

Run (Mac): `scripts/check-ignored.sh`
Run: `scripts/win-remote.sh run 'scripts/check-ignored.sh --target x86_64-pc-windows-msvc'`
Expected: `OK: N ignored tests, the same on every OS` on both, the same N. And `scripts/win-remote.sh test` → `0 failed`.

- [x] **Step 6: CI**

In `.github/workflows/ci.yml`: job `rust` gets a step `- name: Ignored tests are the same on every OS` / `run: scripts/check-ignored.sh`; job `windows` replaces the step "Tests ignored on Windows (private files, phase 2 drives this to zero)" by `- name: Ignored tests are the same on every OS` / `run: scripts/check-ignored.sh --target x86_64-pc-windows-msvc`.

- [x] **Step 7: Commit**

```bash
git add -A crates app scripts/check-ignored.sh scripts/ignored-everywhere.txt .github/workflows/ci.yml
git commit -m "test: no test is ignored on Windows only any more" -m "The 543 private-file marks are gone (fsx is real on Windows since the previous commits). scripts/check-ignored.sh keeps the ignored list identical on every OS; both CI test jobs run it." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

## Task 12: platform-win UI services – window chrome, file panels, toasts, clipboard

**Goal:** rounded popover corners (Windows 11), window fitting and bringing to front, the tray tint, native open/save dialogs that return at once, toast notifications with clicks and removal, and the secret clipboard.

**Files:**
- Modify: `crates/platform-win/Cargo.toml` (features; the `windows` crate), `crates/platform-win/src/win/{mod.rs, platform.rs}`
- Create: `crates/platform-win/src/win/{chrome.rs, msgwin.rs, panels.rs, toast.rs, clipboard.rs}`, `crates/platform-win/src/pure/toast.rs`
- Test: `crates/platform-win/tests/pure.rs` (toast XML, tags), `crates/platform-win/tests/windows.rs` (clipboard, tint)
- Modify: `crates/core/l10n/strings.json` (none expected; add only if a new text appears)

- [x] **Step 1: Dependencies**

Add to platform-win's `windows-sys` features: `"Win32_Graphics_Dwm"`, `"Win32_Graphics_Gdi"`, `"Win32_System_DataExchange"`, `"Win32_System_LibraryLoader"`, `"Win32_System_Memory"`, `"Win32_System_Ole"`, `"Win32_System_Threading"`, `"Win32_UI_HiDpi"`. And:

```toml
# WinRT toasts and the COM file dialogs; the version Tauri already brings (no new crate in Cargo.lock).
windows = { version = "=0.62.2", features = [
    "Data_Xml_Dom",
    "Foundation",
    "UI_Notifications",
    "Win32_Foundation",
    "Win32_System_Com",
    "Win32_UI_Shell",
    "Win32_UI_Shell_Common",
] }
```

Run: `cargo metadata --format-version 1 >/dev/null && git diff --stat Cargo.lock` → no new `[[package]]` entry (only dependency lists of `macvpn-platform-win` change).

- [x] **Step 2: Write the failing pure tests** (append to `crates/platform-win/tests/pure.rs`)

```rust
use macvpn_platform_win::pure::toast;

#[test]
fn toast_xml_escapes_everything() {
    let xml = toast::xml("Office <VPN> & \"more\"", "it's 'connected'");
    assert_eq!(
        xml,
        "<toast><visual><binding template=\"ToastGeneric\"><text>Office &lt;VPN&gt; &amp; &quot;more&quot;</text>\
         <text>it&apos;s &apos;connected&apos;</text></binding></visual></toast>"
    );
}

#[test]
fn toast_tags_fit_the_64_character_limit() {
    assert_eq!(toast::tag("auth-1234"), "auth-1234");
    let long = "x".repeat(100);
    let t = toast::tag(&long);
    assert_eq!(t.len(), 32);
    assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(t, toast::tag(&long), "stable");
}
```

Run: `cargo test --locked -p macvpn-platform-win --test pure` → FAIL (no `toast` module).

- [x] **Step 3: `pure/toast.rs`**

```rust
//! The toast's XML and tag (pure; the WinRT calls are in `win/toast.rs`).

/// The five XML entities.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// A generic toast with a title and a body.
pub fn xml(title: &str, body: &str) -> String {
    format!(
        "<toast><visual><binding template=\"ToastGeneric\"><text>{}</text><text>{}</text></binding></visual></toast>",
        escape(title),
        escape(body)
    )
}

/// The toast's tag (at most 64 characters): the identifier, or the first 32 hex digits of its SHA-256.
pub fn tag(identifier: &str) -> String {
    if identifier.len() <= 64 {
        identifier.to_string()
    } else {
        macvpn_core::update::sha256_hex(identifier.as_bytes())[..32].to_string()
    }
}
```

(Add `pub mod toast;` to `pure/mod.rs`; `sha256_hex` is core's public helper used by the updater.) Run the pure tests → PASS.

- [x] **Step 4: `win/msgwin.rs`** (a main-thread message-only window that runs posted jobs later)

```rust
//! A message-only window on the main thread: jobs posted to it run later, from the event loop, on the main thread
//! (the file panels: their modal loop must not run inside a caller's lock, and their callbacks are not `Send`).

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Threading::GetCurrentThreadId;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, HWND_MESSAGE, PostMessageW, RegisterClassExW, WM_APP, WNDCLASSEXW,
};

const WM_RUN: u32 = WM_APP + 1;
static MAIN_THREAD: OnceLock<u32> = OnceLock::new();

thread_local! {
    static JOBS: RefCell<VecDeque<Box<dyn FnOnce()>>> = RefCell::new(VecDeque::new());
    static WINDOW: Cell<HWND> = const { Cell::new(std::ptr::null_mut()) };
}

/// Records the calling thread as the main thread (`WinPlatform::new`, from `main`).
pub(crate) fn remember_main_thread() {
    // SAFETY: plain call.
    let _ = MAIN_THREAD.set(unsafe { GetCurrentThreadId() });
}

pub(crate) fn on_main_thread() -> bool {
    // SAFETY: plain call.
    MAIN_THREAD.get().is_some_and(|&id| id == unsafe { GetCurrentThreadId() })
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    if msg == WM_RUN {
        if let Some(job) = JOBS.with(|j| j.borrow_mut().pop_front()) {
            job();
        }
        return 0;
    }
    // SAFETY: the default handling of every other message.
    unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
}

fn window() -> Option<HWND> {
    let existing = WINDOW.with(Cell::get);
    if !existing.is_null() {
        return Some(existing);
    }
    let class: Vec<u16> = "WinVPNMessages\0".encode_utf16().collect();
    // SAFETY: a class with this module's instance and our window procedure; registering twice fails harmlessly.
    let hwnd = unsafe {
        let instance = GetModuleHandleW(std::ptr::null());
        let mut wc: WNDCLASSEXW = std::mem::zeroed();
        wc.cbSize = std::mem::size_of::<WNDCLASSEXW>() as u32;
        wc.lpfnWndProc = Some(wndproc);
        wc.hInstance = instance;
        wc.lpszClassName = class.as_ptr();
        RegisterClassExW(&wc);
        CreateWindowExW(0, class.as_ptr(), std::ptr::null(), 0, 0, 0, 0, 0, HWND_MESSAGE, std::ptr::null_mut(), instance, std::ptr::null())
    };
    if hwnd.is_null() {
        return None;
    }
    WINDOW.with(|w| w.set(hwnd));
    Some(hwnd)
}

/// Runs `job` later on the main thread; `false` (and `job` dropped) when not called on the main thread or the
/// window cannot be made.
pub(crate) fn post(job: Box<dyn FnOnce()>) -> bool {
    if !on_main_thread() {
        return false;
    }
    let Some(hwnd) = window() else { return false };
    JOBS.with(|j| j.borrow_mut().push_back(job));
    // SAFETY: our own window, on its thread.
    if unsafe { PostMessageW(hwnd, WM_RUN, 0, 0) } == 0 {
        JOBS.with(|j| j.borrow_mut().pop_back());
        return false;
    }
    true
}
```

`WinPlatform::new` calls `msgwin::remember_main_thread()` and (Step 7) sets the AppUserModelID.

- [x] **Step 5: `win/panels.rs`** (COM dialogs, shown from a posted job)

```rust
//! IFileOpenDialog / IFileSaveDialog, owned by the parent window, shown from the message window's queue.

use super::msgwin;
use macvpn_platform_api::{FilePanels, NativeWindow};
use std::path::PathBuf;
use windows::Win32::Foundation::{ERROR_CANCELLED, HWND};
use windows::Win32::System::Com::{CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx, CoTaskMemFree};
use windows::Win32::UI::Shell::{
    FOS_ALLOWMULTISELECT, FOS_FILEMUSTEXIST, FOS_FORCEFILESYSTEM, FOS_NOREADONLYRETURN, FOS_OVERWRITEPROMPT,
    FileOpenDialog, FileSaveDialog, IFileOpenDialog, IFileSaveDialog, IShellItem, SIGDN_FILESYSPATH,
};
use windows::core::{HRESULT, HSTRING};

fn cancelled(e: &windows::core::Error) -> bool {
    e.code() == HRESULT::from_win32(ERROR_CANCELLED.0)
}

fn path_of(item: &IShellItem) -> windows::core::Result<PathBuf> {
    // SAFETY: GetDisplayName returns a CoTaskMemAlloc'ed string, freed after the copy.
    unsafe {
        let name = item.GetDisplayName(SIGDN_FILESYSPATH)?;
        let path = PathBuf::from(name.to_string().map_err(|_| windows::core::Error::from(HRESULT(-1)))?);
        CoTaskMemFree(Some(name.0 as *const _));
        Ok(path)
    }
}

fn open(owner: HWND, multiple: bool) -> windows::core::Result<Vec<PathBuf>> {
    // SAFETY: COM on the main (STA) thread; a second initialization is harmless (S_FALSE / RPC_E_CHANGED_MODE).
    unsafe {
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let dialog: IFileOpenDialog = CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER)?;
        let mut options = dialog.GetOptions()? | FOS_FORCEFILESYSTEM | FOS_FILEMUSTEXIST;
        if multiple {
            options |= FOS_ALLOWMULTISELECT;
        }
        dialog.SetOptions(options)?;
        match dialog.Show(Some(owner)) {
            Err(e) if cancelled(&e) => return Ok(Vec::new()),
            other => other?,
        }
        let items = dialog.GetResults()?;
        (0..items.GetCount()?).map(|i| path_of(&items.GetItemAt(i)?)).collect()
    }
}

fn save(owner: HWND, suggested: &str, message: Option<&str>) -> windows::core::Result<Option<PathBuf>> {
    // SAFETY: as in `open`.
    unsafe {
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let dialog: IFileSaveDialog = CoCreateInstance(&FileSaveDialog, None, CLSCTX_INPROC_SERVER)?;
        dialog.SetOptions(dialog.GetOptions()? | FOS_FORCEFILESYSTEM | FOS_OVERWRITEPROMPT | FOS_NOREADONLYRETURN)?;
        dialog.SetFileName(&HSTRING::from(suggested))?;
        if let Some(message) = message {
            dialog.SetTitle(&HSTRING::from(message))?;
        }
        match dialog.Show(Some(owner)) {
            Err(e) if cancelled(&e) => return Ok(None),
            other => other?,
        }
        Ok(Some(path_of(&dialog.GetResult()?)?))
    }
}

pub(crate) struct Panels;

impl FilePanels for Panels {
    fn choose_files(&self, parent: NativeWindow, multiple: bool, done: Box<dyn FnOnce(Vec<PathBuf>)>) {
        let owner = HWND(parent.0);
        // `done` moves into the job; if the job cannot be posted it is dropped unrun, so call it here instead.
        let slot = std::rc::Rc::new(std::cell::RefCell::new(Some(done)));
        let job_slot = slot.clone();
        let posted = msgwin::post(Box::new(move || {
            if let Some(done) = job_slot.borrow_mut().take() {
                done(open(owner, multiple).unwrap_or_default());
            }
        }));
        if !posted && let Some(done) = slot.borrow_mut().take() {
            done(Vec::new());
        }
    }

    fn choose_save_path(&self, parent: NativeWindow, suggested: &str, message: Option<&str>, done: Box<dyn FnOnce(Option<PathBuf>)>) {
        let owner = HWND(parent.0);
        let (suggested, message) = (suggested.to_string(), message.map(str::to_string));
        let slot = std::rc::Rc::new(std::cell::RefCell::new(Some(done)));
        let job_slot = slot.clone();
        let posted = msgwin::post(Box::new(move || {
            if let Some(done) = job_slot.borrow_mut().take() {
                done(save(owner, &suggested, message.as_deref()).ok().flatten());
            }
        }));
        if !posted && let Some(done) = slot.borrow_mut().take() {
            done(None);
        }
    }
}
```

- [x] **Step 6: `win/chrome.rs`**

```rust
//! Window shape and placement, and the tray icon's colour.

use super::registry;
use macvpn_platform_api::{NativeWindow, WindowChrome};
use std::mem::size_of;
use windows_sys::Win32::Foundation::{HWND, RECT};
use windows_sys::Win32::Graphics::Dwm::{DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND, DwmSetWindowAttribute};
use windows_sys::Win32::Graphics::Gdi::{GetMonitorInfoW, MONITOR_DEFAULTTONEAREST, MONITORINFO, MonitorFromWindow};
use windows_sys::Win32::UI::HiDpi::{AdjustWindowRectExForDpi, GetDpiForWindow};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GWL_EXSTYLE, GWL_STYLE, GetWindowLongPtrW, GetWindowRect, HWND_NOTOPMOST, HWND_TOPMOST, SW_SHOWNORMAL,
    SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER, SWP_SHOWWINDOW, SetForegroundWindow, SetWindowPos, ShowWindow,
};

const PERSONALIZE: &str = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize";

pub(crate) struct Chrome;

fn hwnd(w: NativeWindow) -> Option<HWND> {
    (!w.0.is_null()).then_some(w.0 as HWND)
}

impl WindowChrome for Chrome {
    /// Windows 11's window corner radius.
    fn popover_corner_radius(&self) -> f64 {
        8.0
    }

    /// Windows 11 rounds through DWM; Windows 10 has no rounded corners (`false`).
    fn round_corners(&self, w: NativeWindow, _radius: f64) -> bool {
        let Some(h) = hwnd(w) else { return false };
        let preference = DWMWCP_ROUND;
        // SAFETY: a valid window and a 4-byte attribute value.
        let hr = unsafe {
            DwmSetWindowAttribute(h, DWMWA_WINDOW_CORNER_PREFERENCE as u32, (&preference as *const i32).cast(), size_of::<i32>() as u32)
        };
        hr >= 0
    }

    /// The client area becomes `width` × `viewport` (logical pixels, scaled by the window's DPI), at most the
    /// monitor's work area; returns the logical client height set.
    fn fit_viewport(&self, w: NativeWindow, width: f64, viewport: f64, center: bool) -> Option<f64> {
        let h = hwnd(w)?;
        // SAFETY: a valid window; plain data out parameters.
        unsafe {
            let dpi = GetDpiForWindow(h);
            if dpi == 0 {
                return None;
            }
            let scale = f64::from(dpi) / 96.0;
            let (client_w, client_h) = ((width * scale).round() as i32, (viewport * scale).round() as i32);
            let mut frame = RECT { left: 0, top: 0, right: client_w, bottom: client_h };
            let style = GetWindowLongPtrW(h, GWL_STYLE) as u32;
            let ex_style = GetWindowLongPtrW(h, GWL_EXSTYLE) as u32;
            if AdjustWindowRectExForDpi(&mut frame, style, 0, ex_style, dpi) == 0 {
                return None;
            }
            let (outer_w, outer_h) = (frame.right - frame.left, frame.bottom - frame.top);
            let mut info: MONITORINFO = std::mem::zeroed();
            info.cbSize = size_of::<MONITORINFO>() as u32;
            if GetMonitorInfoW(MonitorFromWindow(h, MONITOR_DEFAULTTONEAREST), &mut info) == 0 {
                return None;
            }
            let work = info.rcWork;
            let height = outer_h.min(work.bottom - work.top);
            let mut current = RECT { left: 0, top: 0, right: 0, bottom: 0 };
            GetWindowRect(h, &mut current);
            let (x, y) = if center {
                (work.left + ((work.right - work.left) - outer_w) / 2, work.top + ((work.bottom - work.top) - height) / 2)
            } else {
                (current.left, current.top.clamp(work.top, (work.bottom - height).max(work.top)))
            };
            if SetWindowPos(h, std::ptr::null_mut(), x, y, outer_w, height, SWP_NOZORDER | SWP_NOACTIVATE) == 0 {
                return None;
            }
            Some(f64::from(height - (outer_h - client_h)) / scale)
        }
    }

    fn order_front_regardless(&self, w: NativeWindow) {
        let Some(h) = hwnd(w) else { return };
        // SAFETY: a valid window; the topmost toggle brings it above other apps without keeping it there.
        unsafe {
            ShowWindow(h, SW_SHOWNORMAL);
            SetWindowPos(h, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
            SetWindowPos(h, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW);
            SetForegroundWindow(h);
        }
    }

    /// White on a dark taskbar (the default), black on a light one.
    fn tray_tint(&self) -> Option<[u8; 3]> {
        Some(if registry::read_dword(PERSONALIZE, "SystemUsesLightTheme") == Some(1) { [0, 0, 0] } else { [255, 255, 255] })
    }
}
```

- [x] **Step 7: `win/toast.rs`** (and the AppUserModelID)

```rust
//! Toast notifications (WinRT) under the AppUserModelID `local.winvpn`.

use crate::pure::toast;
use macvpn_platform_api::Notifier;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use windows::Data::Xml::Dom::XmlDocument;
use windows::Foundation::TypedEventHandler;
use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};
use windows::Win32::UI::Shell::SetCurrentProcessExplicitAppUserModelID;
use windows::core::{HSTRING, IInspectable};

/// The AppUserModelID (`Product::app_id`; also on the MSI's Start-menu shortcut).
pub(crate) const APP_ID: &str = "local.winvpn";
const GROUP: &str = "WinVPN";

type OnClick = Arc<dyn Fn(BTreeMap<String, String>) + Send + Sync>;

#[derive(Default)]
pub(crate) struct Toasts {
    on_click: Arc<Mutex<Option<OnClick>>>,
}

/// Before any window exists (`WinPlatform::new`).
pub(crate) fn set_app_id() {
    // SAFETY: a constant string; fails only with an invalid ID.
    let _ = unsafe { SetCurrentProcessExplicitAppUserModelID(&HSTRING::from(APP_ID)) };
}

impl Toasts {
    fn show(&self, identifier: &str, title: &str, body: &str, user_info: (&str, &str)) -> windows::core::Result<()> {
        let doc = XmlDocument::new()?;
        doc.LoadXml(&HSTRING::from(toast::xml(title, body)))?;
        let notification = ToastNotification::CreateToastNotification(&doc)?;
        notification.SetTag(&HSTRING::from(toast::tag(identifier)))?;
        notification.SetGroup(&HSTRING::from(GROUP))?;
        let on_click = self.on_click.clone();
        let info = BTreeMap::from([(user_info.0.to_string(), user_info.1.to_string())]);
        notification.Activated(&TypedEventHandler::<ToastNotification, IInspectable>::new(move |_, _| {
            if let Some(f) = on_click.lock().unwrap_or_else(PoisonError::into_inner).clone() {
                f(info.clone());
            }
            Ok(())
        }))?;
        ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(APP_ID))?.Show(&notification)
    }
}

impl Notifier for Toasts {
    /// The click callback runs on a WinRT thread pool thread (the app's handler hops to the main thread itself,
    /// as for macOS' delegate callbacks).
    fn start(&self, on_click: Box<dyn Fn(BTreeMap<String, String>) + Send + Sync>) {
        *self.on_click.lock().unwrap_or_else(PoisonError::into_inner) = Some(Arc::from(on_click));
    }

    /// Errors (no Start-menu shortcut in a development run, notifications turned off) are ignored, as on macOS.
    fn post(&self, identifier: &str, title: &str, body: &str, user_info: (&str, &str)) {
        let _ = self.show(identifier, title, body, user_info);
    }

    fn remove_delivered(&self, identifier: &str) {
        if let Ok(history) = ToastNotificationManager::History() {
            let _ = history.RemoveGroupedTagWithId(&HSTRING::from(toast::tag(identifier)), &HSTRING::from(GROUP), &HSTRING::from(APP_ID));
        }
    }
}
```

Check `app/src-tauri/src/notifications.rs` (`start`'s callback): if it touches windows directly, wrap its body in `app.run_on_main_thread`; on macOS the callback already arrives on the main thread, so this is a no-op change there.

- [x] **Step 8: `win/clipboard.rs`**

```rust
//! The clipboard: plain text, and secrets kept out of clipboard history, cloud sync and clipboard monitors.

use macvpn_platform_api::{ClipboardMark, PlatformError, SecretClipboard};
use std::time::Duration;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardSequenceNumber, OpenClipboard, RegisterClipboardFormatW, SetClipboardData,
};
use windows_sys::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalFree, GlobalLock, GlobalUnlock};
use windows_sys::Win32::System::Ole::CF_UNICODETEXT;
use zeroize::Zeroize;

fn failed(what: &str) -> PlatformError {
    PlatformError::Failed(format!("clipboard: {what}"))
}

/// The clipboard is open while this lives (another app may hold it briefly: retried for about 100 ms).
struct Open;

impl Open {
    fn new() -> Result<Open, PlatformError> {
        for _ in 0..10 {
            // SAFETY: no owner window (the clipboard is then owned by no window, which is allowed).
            if unsafe { OpenClipboard(std::ptr::null_mut()) } != 0 {
                return Ok(Open);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Err(failed("busy"))
    }
}

impl Drop for Open {
    fn drop(&mut self) {
        // SAFETY: we opened it.
        unsafe { CloseClipboard() };
    }
}

/// Puts `bytes` on the open clipboard under `format`; the clipboard owns the memory on success.
fn set(format: u32, bytes: &[u8]) -> Result<(), PlatformError> {
    // SAFETY: a movable block of `max(len, 1)` bytes, filled while locked, handed to the clipboard (or freed).
    unsafe {
        let mem = GlobalAlloc(GMEM_MOVEABLE, bytes.len().max(1));
        if mem.is_null() {
            return Err(failed("out of memory"));
        }
        let p = GlobalLock(mem) as *mut u8;
        if p.is_null() {
            GlobalFree(mem);
            return Err(failed("lock"));
        }
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len());
        GlobalUnlock(mem);
        if SetClipboardData(format, mem as HANDLE).is_null() {
            GlobalFree(mem);
            return Err(failed("set"));
        }
    }
    Ok(())
}

fn registered(name: &str) -> u32 {
    let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    // SAFETY: a NUL-terminated name.
    unsafe { RegisterClipboardFormatW(wide.as_ptr()) }
}

/// Writes `text`; a secret also gets the three exclusion formats. Returns the clipboard's sequence number after it.
pub(crate) fn write(text: &str, secret: bool) -> Result<u32, PlatformError> {
    let mut bytes: Vec<u8> = text.encode_utf16().chain(Some(0)).flat_map(u16::to_le_bytes).collect();
    let result = (|| {
        let _open = Open::new()?;
        // SAFETY: the clipboard is open.
        if unsafe { EmptyClipboard() } == 0 {
            return Err(failed("empty"));
        }
        if secret {
            set(registered("ExcludeClipboardContentFromMonitorProcessing"), &[0])?;
            set(registered("CanIncludeInClipboardHistory"), &0u32.to_le_bytes())?;
            set(registered("CanUploadToCloudClipboard"), &0u32.to_le_bytes())?;
        }
        set(CF_UNICODETEXT as u32, &bytes)
    })();
    bytes.zeroize();
    result?;
    // SAFETY: plain call.
    Ok(unsafe { GetClipboardSequenceNumber() })
}

pub(crate) struct Clipboard;

impl SecretClipboard for Clipboard {
    fn write_secret(&self, text: &str) -> Result<ClipboardMark, PlatformError> {
        write(text, true).map(|seq| ClipboardMark(seq as isize))
    }

    /// Empties the clipboard only if nothing was copied since `mark`.
    fn clear_if_unchanged(&self, mark: ClipboardMark) -> bool {
        // SAFETY: plain call.
        if unsafe { GetClipboardSequenceNumber() } as isize != mark.0 {
            return false;
        }
        let Ok(_open) = Open::new() else { return false };
        // SAFETY: the clipboard is open.
        unsafe { EmptyClipboard() != 0 }
    }
}
```

`Shell::copy_text` → `clipboard::write(text, false).map(|_| ())`.

- [x] **Step 9: Wire them into `WinPlatform`** (`windows()` → `&Chrome`, `file_panels()` → `&Panels`, `notifier()` → the platform's `Toasts` field, `clipboard()` → `&Clipboard`; `WinPlatform::new` calls `msgwin::remember_main_thread()` and `toast::set_app_id()`), then add the Windows tests:

```rust
#[test]
fn the_secret_clipboard_clears_only_its_own_text() {
    let p = platform();
    let mark = p.clipboard().write_secret("fixture-secret").unwrap();
    assert!(p.clipboard().clear_if_unchanged(mark));
    let mark = p.clipboard().write_secret("fixture-secret").unwrap();
    p.shell().copy_text("the user's own text").unwrap();
    assert!(!p.clipboard().clear_if_unchanged(mark));
}

#[test]
fn the_tray_tint_is_black_or_white() {
    let tint = platform().windows().tray_tint().unwrap();
    assert!(tint == [0, 0, 0] || tint == [255, 255, 255]);
}
```

Run: `scripts/win-remote.sh run 'cargo test --locked -p macvpn-platform-win -- --test-threads=1'` (the clipboard is global: one test thread)
Expected: PASS. The panels, chrome and toasts are verified in the manual checklist (they need a desktop session).

- [x] **Step 10: Commit**

```bash
git add crates/platform-win Cargo.lock app/src-tauri/src/notifications.rs
git commit -m "feat(platform-win): window chrome, file dialogs, toasts and the secret clipboard" -m "DWM rounded corners (Windows 11), DPI-aware fitting, COM open/save dialogs posted to a main-thread message window, WinRT toasts under local.winvpn with tags for removal, and secrets on the clipboard excluded from history, cloud sync and monitors." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

## Task 13: platform-win lifecycle, launch at login and single instance

**Goal:** logoff and shutdown go through the quit questions, a resume wakes the poller, "Launch at login" is a Run value that respects Settings → Startup apps, and a second launch hands its files to the running WinVPN.

**Files:**
- Create: `crates/platform-win/src/win/{lifecycle.rs, login_item.rs, instance.rs}`, `crates/platform-win/src/pure/{run_key.rs, forward.rs}`
- Modify: `crates/platform-win/src/{lib.rs, pure/mod.rs, win/mod.rs, win/platform.rs}`, `crates/platform-win/Cargo.toml` (feature `"Win32_System_Power"`, `"Win32_System_RemoteDesktop"`, `"Win32_System_Shutdown"`)
- Modify: `crates/core/l10n/strings.json` (two Windows-only texts)
- Test: `crates/platform-win/tests/pure.rs`, `crates/platform-win/tests/windows.rs`

- [x] **Step 1: Write the failing pure tests**

```rust
use macvpn_platform_win::pure::{forward, run_key};
use std::path::{Path, PathBuf};

#[test]
fn the_run_value_quotes_the_executable() {
    assert_eq!(run_key::command(Path::new(r"C:\Program Files\WinVPN\WinVPN.exe")), "\"C:\\Program Files\\WinVPN\\WinVPN.exe\"");
}

#[test]
fn startup_approved_odd_first_byte_is_disabled() {
    assert!(!run_key::disabled_in_settings(&[2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    assert!(run_key::disabled_in_settings(&[3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    assert!(!run_key::disabled_in_settings(&[]));
}

#[test]
fn forwarded_paths_round_trip_and_only_absolute_ones_count() {
    let paths = if cfg!(windows) {
        vec![PathBuf::from(r"C:\Users\a\Downloads\office.ovpn"), PathBuf::from(r"C:\x\team.macvpncatalog")]
    } else {
        vec![PathBuf::from("/Users/a/office.ovpn"), PathBuf::from("/x/team.macvpncatalog")]
    };
    let bytes = forward::encode(&paths).unwrap();
    assert_eq!(forward::decode(&bytes), paths);
    assert_eq!(forward::decode(b"relative.ovpn\n"), Vec::<PathBuf>::new());
    assert_eq!(forward::decode(b""), Vec::<PathBuf>::new(), "empty: show the running app");
    assert_eq!(forward::decode(&vec![b'/'; forward::MAX_BYTES + 1]), Vec::<PathBuf>::new(), "too large: nothing");
    assert!(forward::encode(&[PathBuf::from("a\nb")]).is_err());
}
```

Run: `cargo test --locked -p macvpn-platform-win --test pure` → FAIL.

- [x] **Step 2: The pure modules**

`pure/run_key.rs`:

```rust
//! Launch at login: the `HKCU\…\Run` value and Settings' StartupApproved switch.

use std::path::Path;

/// The Run value's data: the quoted executable path.
pub fn command(exe: &Path) -> String {
    format!("\"{}\"", exe.display())
}

/// `…\Explorer\StartupApproved\Run\<name>`: a 12-byte value whose first byte is 2 (enabled) or 3 (disabled by the
/// user in Settings or Task Manager). An odd first byte means disabled; a missing value means enabled.
pub fn disabled_in_settings(value: &[u8]) -> bool {
    value.first().is_some_and(|b| b & 1 == 1)
}
```

`pure/forward.rs`:

```rust
//! The files a second launch hands to the running instance: absolute paths, one per line, UTF-8, at most 64 KiB.
//! An empty message means "show yourself".

use std::path::{Path, PathBuf};

pub const MAX_BYTES: usize = 64 * 1024;

pub fn encode(paths: &[PathBuf]) -> Result<Vec<u8>, &'static str> {
    let mut out = String::new();
    for p in paths {
        let s = p.to_str().ok_or("a path that is not UTF-8")?;
        if s.contains(['\n', '\r', '\0']) {
            return Err("a line break in a path");
        }
        out.push_str(s);
        out.push('\n');
    }
    if out.len() > MAX_BYTES {
        return Err("too many paths");
    }
    Ok(out.into_bytes())
}

/// Absolute paths only; anything malformed or too large is dropped as a whole.
pub fn decode(bytes: &[u8]) -> Vec<PathBuf> {
    if bytes.len() > MAX_BYTES {
        return Vec::new();
    }
    let Ok(text) = std::str::from_utf8(bytes) else { return Vec::new() };
    text.lines().filter(|l| !l.is_empty() && Path::new(l).is_absolute()).map(PathBuf::from).collect()
}
```

Run the pure tests → PASS.

- [x] **Step 3: `win/lifecycle.rs`** (a hidden top-level window: message-only windows get no `WM_QUERYENDSESSION`)

```rust
//! Logoff/shutdown (`WM_QUERYENDSESSION`) and resume (`WM_POWERBROADCAST`), through a hidden top-level window.

use crate::pure::texts;
use macvpn_platform_api::{AppLifecycle, TerminateReply};
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::sync::{Mutex, OnceLock, PoisonError};
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Power::PBT_APMRESUMEAUTOMATIC;
use windows_sys::Win32::System::Shutdown::{ShutdownBlockReasonCreate, ShutdownBlockReasonDestroy};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, RegisterClassExW, WM_POWERBROADCAST, WM_QUERYENDSESSION, WNDCLASSEXW, WS_EX_TOOLWINDOW,
};

type Handler = Box<dyn Fn() -> TerminateReply + Send + Sync>;
static HANDLER: OnceLock<Handler> = OnceLock::new();
static WAKE: Mutex<Vec<Box<dyn Fn() + Send + Sync>>> = Mutex::new(Vec::new());
static WINDOW: AtomicPtr<core::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());
static BLOCKING: AtomicBool = AtomicBool::new(false);

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_QUERYENDSESSION => match HANDLER.get().map_or(TerminateReply::Now, |h| h()) {
            TerminateReply::Now => 1,
            TerminateReply::Cancel => 0,
            TerminateReply::Later => {
                let reason: Vec<u16> = texts::closing().encode_utf16().chain(Some(0)).collect();
                // SAFETY: our window; a NUL-terminated reason.
                unsafe { ShutdownBlockReasonCreate(hwnd, reason.as_ptr()) };
                BLOCKING.store(true, Ordering::SeqCst);
                0
            }
        },
        WM_POWERBROADCAST if wparam == PBT_APMRESUMEAUTOMATIC as usize => {
            for f in WAKE.lock().unwrap_or_else(PoisonError::into_inner).iter() {
                f();
            }
            1
        }
        // SAFETY: the default handling of every other message.
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

/// The hidden window, created once on the calling (main) thread.
fn ensure_window() -> bool {
    if !WINDOW.load(Ordering::SeqCst).is_null() {
        return true;
    }
    let class: Vec<u16> = "WinVPNLifecycle\0".encode_utf16().collect();
    // SAFETY: a never-shown tool window (no taskbar button) with our window procedure.
    let hwnd = unsafe {
        let instance = GetModuleHandleW(std::ptr::null());
        let mut wc: WNDCLASSEXW = std::mem::zeroed();
        wc.cbSize = std::mem::size_of::<WNDCLASSEXW>() as u32;
        wc.lpfnWndProc = Some(wndproc);
        wc.hInstance = instance;
        wc.lpszClassName = class.as_ptr();
        RegisterClassExW(&wc);
        CreateWindowExW(WS_EX_TOOLWINDOW, class.as_ptr(), std::ptr::null(), 0, 0, 0, 0, 0, std::ptr::null_mut(), std::ptr::null_mut(), instance, std::ptr::null())
    };
    if hwnd.is_null() {
        return false;
    }
    WINDOW.store(hwnd, Ordering::SeqCst);
    true
}

pub(crate) struct Lifecycle;

impl AppLifecycle for Lifecycle {
    fn install_terminate_handler(&self, handler: Box<dyn Fn() -> TerminateReply + Send + Sync>) -> bool {
        HANDLER.set(handler).is_ok() && ensure_window()
    }

    /// After a `Later`: the block reason goes; `true` ends the process (the quit flow is done, as AppKit's
    /// terminate after `replyToApplicationShouldTerminate:YES`).
    fn reply_to_terminate(&self, terminate: bool) {
        let hwnd = WINDOW.load(Ordering::SeqCst);
        if BLOCKING.swap(false, Ordering::SeqCst) && !hwnd.is_null() {
            // SAFETY: our window.
            unsafe { ShutdownBlockReasonDestroy(hwnd) };
        }
        if terminate {
            std::process::exit(0);
        }
    }

    fn observe_wake(&self, on_wake: Box<dyn Fn() + Send + Sync>) {
        WAKE.lock().unwrap_or_else(PoisonError::into_inner).push(on_wake);
        ensure_window();
    }
}
```

`pure/texts.rs` gets `pub fn closing() -> String { l10n::tr("Closing WinVPN…", &[]) }` and `pub fn startup_disabled() -> String { l10n::tr("Turned off in Settings → Apps → Startup.", &[]) }`; `strings.json` (scope `platform`, `only` `["windows"]`): „A WinVPN bezárása…” and „Kikapcsolva: Gépház → Alkalmazások → Indítás.”

- [x] **Step 4: `win/login_item.rs`**

```rust
//! Launch at login: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WinVPN`.

use super::{registry, shell};
use crate::pure::{run_key, texts};
use macvpn_platform_api::{LoginItemView, LoginItems, PlatformError};
use std::path::PathBuf;

const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const APPROVED: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
/// The value's name (a storage identifier).
const VALUE: &str = "WinVPN";

pub(crate) struct RunKeyItem {
    pub(crate) exe: PathBuf,
}

impl RunKeyItem {
    fn registered(&self) -> bool {
        registry::read_string(RUN, VALUE).is_some_and(|v| v.eq_ignore_ascii_case(&run_key::command(&self.exe)))
    }

    fn disabled(&self) -> bool {
        registry::read_binary(APPROVED, VALUE).is_some_and(|b| run_key::disabled_in_settings(&b))
    }
}

impl LoginItems for RunKeyItem {
    fn state(&self) -> LoginItemView {
        let (registered, disabled) = (self.registered(), self.disabled());
        LoginItemView {
            is_on: registered && !disabled,
            can_toggle: true,
            note: (registered && disabled).then(texts::startup_disabled),
            shows_open_settings: registered && disabled,
        }
    }

    /// On: the Run value, and the Settings switch back on (the user asked for it here). Off: the value goes.
    fn set_enabled(&mut self, on: bool) -> Result<(), PlatformError> {
        let result = if on {
            registry::write_string(RUN, VALUE, &run_key::command(&self.exe)).and_then(|()| registry::delete_value(APPROVED, VALUE))
        } else {
            registry::delete_value(RUN, VALUE)
        };
        result.map_err(|e| PlatformError::Failed(e.to_string()))
    }

    fn unregister_if_registered(&mut self) -> Result<bool, PlatformError> {
        if registry::read_string(RUN, VALUE).is_none() {
            return Ok(false);
        }
        registry::delete_value(RUN, VALUE).map_err(|e| PlatformError::Failed(e.to_string()))?;
        Ok(true)
    }

    fn open_settings(&self) {
        shell::open_settings("ms-settings:startupapps");
    }

    fn remove_stale_entries(&self) -> Result<(), PlatformError> {
        Ok(())
    }
}
```

`Platform::login_items(home, app, sandbox)`: sandbox or `app == None` → the old inert item (`can_toggle: false`); else `RunKeyItem { exe: app.join("WinVPN.exe") }`.

- [x] **Step 5: `win/instance.rs`**

```rust
//! One WinVPN per user and session: a named mutex decides; a second launch forwards its files over a pipe.

use crate::pure::forward;
use macvpn_winsys::pipe::{self, Listener};
use macvpn_winsys::sid::Sid;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::path::PathBuf;
use std::time::Duration;
use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError};
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Threading::{CreateMutexW, GetCurrentProcessId};

pub enum Claim {
    /// This is the running instance: keep the guard for the process's life and call `listen`.
    First(InstanceGuard),
    /// Another instance got the files (or the request to show itself): exit.
    Forwarded,
}

pub struct InstanceGuard {
    _mutex: OwnedHandle,
    pipe_name: String,
}

fn session() -> u32 {
    let mut id = 0u32;
    // SAFETY: valid out pointer.
    unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut id) };
    id
}

/// Claims the instance; a second one forwards `paths` (absolute file arguments) and returns `Forwarded`.
pub fn claim(paths: &[PathBuf]) -> io::Result<Claim> {
    let sid = Sid::current_user()?;
    let mutex_name: Vec<u16> = format!("Local\\WinVPN-instance-{sid}").encode_utf16().chain(Some(0)).collect();
    // SAFETY: an unowned named mutex; the handle is owned below.
    let handle = unsafe { CreateMutexW(std::ptr::null(), 0, mutex_name.as_ptr()) };
    // SAFETY: plain call, right after CreateMutexW.
    let already = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
    if handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a valid handle we own.
    let mutex = unsafe { OwnedHandle::from_raw_handle(handle) };
    let pipe_name = format!(r"\\.\pipe\WinVPN-open-{sid}-{}", session());
    if !already {
        return Ok(Claim::First(InstanceGuard { _mutex: mutex, pipe_name }));
    }
    let message = forward::encode(paths).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let stream = connect_retrying(&pipe_name)?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    (&stream).write_all(&message)?;
    stream.shutdown(Shutdown::Both)?;
    Ok(Claim::Forwarded)
}

/// The first instance may still be starting (its pipe not listening yet): `NotFound` is retried for up to 5 s.
fn connect_retrying(name: &str) -> io::Result<pipe::PipeStream> {
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        match pipe::connect(name, Duration::from_secs(5)) {
            Err(e) if e.kind() == io::ErrorKind::NotFound && std::time::Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(100));
            }
            other => return other,
        }
    }
}

impl InstanceGuard {
    /// Serves the forwarding pipe on its own thread; `on_open` gets each launch's paths (empty: show yourself).
    /// Only peers of this user are heard.
    pub fn listen(&self, on_open: Box<dyn Fn(Vec<PathBuf>) + Send>) -> io::Result<()> {
        let listener = Listener::bind(&self.pipe_name)?;
        let me = Sid::current_user()?;
        std::thread::Builder::new().name("winvpn-open-files".into()).spawn(move || {
            loop {
                let Ok(Some((stream, peer))) = listener.accept(Duration::from_millis(500)) else { continue };
                if !peer.is_ok_and(|p| p.sid == me) {
                    continue;
                }
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let mut data = Vec::new();
                if (&stream).take(forward::MAX_BYTES as u64 + 1).read_to_end(&mut data).is_ok() {
                    on_open(forward::decode(&data));
                }
            }
        })?;
        Ok(())
    }
}
```

`lib.rs` re-exports `win::instance::{claim, Claim, InstanceGuard}` on Windows.

- [x] **Step 6: Windows tests** (append to `tests/windows.rs`)

```rust
#[test]
fn the_run_key_item_round_trips_and_honours_settings() {
    // Uses a throwaway exe path; the value name is WinVPN's, so the test restores what it found.
    let before = macvpn_platform_win::run_value_for_tests();
    let mut item = macvpn_platform_win::run_key_item_for_tests(std::path::Path::new(r"C:\WinVPN-test\WinVPN.exe"));
    item.set_enabled(true).unwrap();
    assert!(item.state().is_on);
    item.set_enabled(false).unwrap();
    assert!(!item.state().is_on);
    assert!(!item.unregister_if_registered().unwrap());
    macvpn_platform_win::restore_run_value_for_tests(before);
}

#[test]
fn a_second_claim_forwards_to_the_first() {
    use macvpn_platform_win::{Claim, claim};
    use std::sync::mpsc;
    let Claim::First(guard) = claim(&[]).unwrap() else { panic!("another WinVPN runs for this user: close it first") };
    let (tx, rx) = mpsc::channel();
    let tx = std::sync::Mutex::new(tx);
    guard.listen(Box::new(move |paths| tx.lock().unwrap().send(paths).unwrap())).unwrap();
    let file = std::env::temp_dir().join("forwarded.ovpn");
    assert!(matches!(claim(&[file.clone()]).unwrap(), Claim::Forwarded));
    assert_eq!(rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap(), vec![file]);
}
```

(`run_value_for_tests` / `restore_run_value_for_tests` / `run_key_item_for_tests` are `#[doc(hidden)]` helpers in `lib.rs` over `win::registry` and `RunKeyItem`.) Note: `claim` in a test process: the mutex is per user and session, so the test fails if WinVPN itself runs in that session on the test machine – the assertion message says so.

Run: `scripts/win-remote.sh run 'cargo test --locked -p macvpn-platform-win -- --test-threads=1'`
Expected: PASS. Logoff and resume are in the manual checklist.

- [x] **Step 7: Commit**

```bash
git add crates/platform-win crates/core/l10n/strings.json Cargo.lock
git commit -m "feat(platform-win): logoff and resume, launch at login, one instance per user" -m "A hidden top-level window answers WM_QUERYENDSESSION with the quit questions (a block reason while they run) and turns a resume into a wake. Launch at login is the HKCU Run value and follows the Startup apps switch. A second launch forwards its files over a per-user, per-session pipe." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

## Task 14: the app on Windows

**Goal:** the Tauri app runs as WinVPN: `supported()` is `Ok`, one instance per user, files from Explorer and from a second launch are imported, the popover sits above the taskbar icon with a tinted icon and rounded corners, no macOS menu bar appears in the windows, System Status shows the engine note, the MSI registers the file types. MacVPN is unchanged.

**Files:**
- Modify: `app/src-tauri/src/platform/{mod.rs, macos.rs, windows.rs}`, `app/src-tauri/src/main.rs`, `app/src-tauri/src/tray.rs`, `app/src-tauri/src/state.rs` (the setup view), `app/src-tauri/src/open_files.rs` (tests: `#[cfg(target_os = "macos")]` on the two Info.plist tests)
- Modify: `app/src-tauri/tauri.windows.conf.json`; create `app/src-tauri/wix/file-associations.wxs`
- Modify: `app/src-tauri/tests/tauri_config.rs`
- Modify: `app/ui/src/lib/api.ts`, `app/ui/src/lib/Setup.svelte`, `app/ui/src/app.css`

- [x] **Step 1: Write the failing tray placement test** (`app/src-tauri/src/tray.rs`, in `mod tests`)

```rust
    use tauri::{PhysicalPosition, PhysicalSize};

    fn monitor() -> Option<(PhysicalPosition<i32>, PhysicalSize<u32>)> {
        Some((PhysicalPosition::new(0, 0), PhysicalSize::new(2560, 1600)))
    }

    #[test]
    fn below_a_menu_bar_icon_exactly_as_before() {
        let icon = (PhysicalPosition::new(2000.0, 0.0), PhysicalSize::new(44.0, 48.0));
        // The 1.5 formula: x = centre − width/2 (kept on the monitor), y = icon bottom + 2.
        assert_eq!(popover_position(icon, (660.0, 720.0), monitor()), (1692, 50));
        assert_eq!(popover_position(icon, (660.0, 720.0), None), (1692, 50));
    }

    #[test]
    fn above_a_taskbar_icon_and_kept_on_the_screen() {
        let icon = (PhysicalPosition::new(2400.0, 1552.0), PhysicalSize::new(48.0, 48.0));
        assert_eq!(popover_position(icon, (660.0, 720.0), monitor()), (1892, 830));
    }
```

Run: `cargo test --locked -p macvpn-app tray` → FAIL (`popover_position` missing).

- [x] **Step 2: `popover_position` and its use**

```rust
/// Where the popover goes (physical pixels): centred on the icon and kept 8 px inside the monitor horizontally;
/// below the icon when it is in the upper half of its monitor (the macOS menu bar: the 1.5 formula, unchanged), above
/// it otherwise (the Windows taskbar).
pub fn popover_position(
    icon: (PhysicalPosition<f64>, PhysicalSize<f64>),
    window: (f64, f64),
    monitor: Option<(PhysicalPosition<i32>, PhysicalSize<u32>)>,
) -> (i32, i32) {
    let (position, size) = icon;
    let (width, height) = window;
    let mut x = position.x + size.width / 2.0 - width / 2.0;
    let mut y = position.y + size.height + 2.0;
    if let Some((origin, extent)) = monitor {
        let left = f64::from(origin.x) + 8.0;
        let right = f64::from(origin.x) + f64::from(extent.width) - width - 8.0;
        x = x.clamp(left, right.max(left));
        let middle = f64::from(origin.y) + f64::from(extent.height) / 2.0;
        if position.y > middle {
            y = (position.y - height - 2.0).max(f64::from(origin.y) + 8.0);
        }
    }
    (x.round() as i32, y.round() as i32)
}
```

In `show_menu`, replace the inline computation by:

```rust
    if let (Some((position, size)), Ok(window_size)) = (anchor, window.outer_size()) {
        let monitor = app.monitor_from_point(position.x, position.y).ok().flatten().map(|m| (*m.position(), *m.size()));
        let (x, y) = popover_position(
            (position, size),
            (f64::from(window_size.width), f64::from(window_size.height)),
            monitor,
        );
        let _ = window.set_position(PhysicalPosition::new(x, y));
    }
```

(The anchor's types are `PhysicalPosition<f64>` / `PhysicalSize<f64>` from `remember_anchor`; adjust the tuple types to them.) Run the tray tests → PASS.

- [x] **Step 3: The tint and the tooltip**

```rust
/// The icon in the platform's colour: a template image (the system tints it: macOS), or recoloured opaque pixels
/// (Windows' notification area has no template images).
fn image(icon: TrayIcon) -> Option<Image<'static>> {
    let bytes = match icon {
        TrayIcon::Idle => IDLE,
        TrayIcon::Active => ACTIVE,
        TrayIcon::Failure => FAILURE,
        TrayIcon::Auth => AUTH,
    };
    let image = Image::from_bytes(bytes).ok()?;
    match platform::get().windows().tray_tint() {
        None => Some(image),
        Some(rgb) => Some(Image::new_owned(tinted(image.rgba(), rgb), image.width(), image.height())),
    }
}

/// Every pixel takes `rgb`; the alpha (the shape) stays.
fn tinted(rgba: &[u8], rgb: [u8; 3]) -> Vec<u8> {
    rgba.chunks_exact(4).flat_map(|p| [rgb[0], rgb[1], rgb[2], p[3]]).collect()
}
```

`create` and `set_icon` use `icon_as_template(platform::get().windows().tray_tint().is_none())` and `.tooltip(platform::get().product().name)`. Test (`mod tests`): `tinted(&[0, 0, 0, 255, 0, 0, 0, 0], [255, 255, 255]) == [255, 255, 255, 255, 255, 255, 255, 0]`.

- [x] **Step 4: The platform module's Windows glue**

`app/src-tauri/src/platform/mod.rs`, two new facades (doc comments as for the others):

```rust
/// Before Tauri starts: `false` when another instance of this product runs for this user and got this launch's
/// files (`main` then exits 0). macOS: always `true` (LaunchServices keeps one instance).
pub fn claim_instance() -> bool {
    selected::claim_instance()
}

/// Whether the app installs its own menu (macOS: the app menu bar with Quit and Edit; Windows: none, the windows
/// keep their native text shortcuts and Quit is in the popover).
pub fn uses_app_menu() -> bool {
    selected::uses_app_menu()
}
```

`macos.rs`: `pub fn claim_instance() -> bool { true }`, `pub fn uses_app_menu() -> bool { true }`.

`windows.rs` (the whole file):

```rust
//! Windows: `WinPlatform` (`macvpn-platform-win`) and the Tauri glue: the `HWND`, one instance per user (a second
//! launch forwards its files), the files of this launch, no app menu, no Dock-like presence (Windows shows a taskbar
//! button for each real window by itself).

use macvpn_platform_api::{NativeWindow, Platform};
use macvpn_platform_win::{Claim, InstanceGuard, WinPlatform, claim};
use std::path::PathBuf;
use std::sync::OnceLock;
use tauri::{AppHandle, Url};

static PLATFORM: OnceLock<WinPlatform> = OnceLock::new();
static INSTANCE: OnceLock<InstanceGuard> = OnceLock::new();

pub fn init(sandbox: bool) -> &'static dyn Platform {
    PLATFORM.get_or_init(|| WinPlatform::new(sandbox))
}

pub fn get() -> Option<&'static dyn Platform> {
    PLATFORM.get().map(|p| p as &'static dyn Platform)
}

pub fn native_window(w: &tauri::WebviewWindow) -> Option<NativeWindow> {
    w.hwnd().ok().map(|hwnd| NativeWindow(hwnd.0))
}

/// The absolute file arguments of this launch (Explorer passes `"%1"`).
fn launch_files() -> Vec<PathBuf> {
    std::env::args_os().skip(1).map(PathBuf::from).filter(|p| p.is_absolute()).collect()
}

fn urls(paths: &[PathBuf]) -> Vec<Url> {
    paths.iter().filter_map(|p| Url::from_file_path(p).ok()).collect()
}

pub fn claim_instance() -> bool {
    match claim(&launch_files()) {
        Ok(Claim::First(guard)) => {
            let _ = INSTANCE.set(guard);
            true
        }
        Ok(Claim::Forwarded) => false,
        // Fail open for the launch itself (the user sees WinVPN), never for the files: they stay with this instance.
        Err(e) => {
            eprintln!("WinVPN: single instance: {e}");
            true
        }
    }
}

/// At setup: this launch's files go through the same handler as macOS' `RunEvent::Opened` (queued behind the
/// setup, so the open-files state is attached first); later launches arrive through the forwarding pipe.
pub fn configure_app(app: &mut tauri::App) {
    let handle = app.handle().clone();
    let files = urls(&launch_files());
    if !files.is_empty() {
        let h = handle.clone();
        let _ = handle.run_on_main_thread(move || crate::open_files::opened(&h, &files));
    }
    if let Some(guard) = INSTANCE.get() {
        let h = handle.clone();
        let listening = guard.listen(Box::new(move |paths| {
            let target = h.clone();
            let _ = h.run_on_main_thread(move || {
                if paths.is_empty() {
                    crate::dock::reopen(&target);
                } else {
                    crate::open_files::opened(&target, &urls(&paths));
                }
            });
        }));
        if let Err(e) = listening {
            eprintln!("WinVPN: the open-files pipe: {e}");
        }
    }
}

pub fn set_window_presence(_app: &AppHandle, _shown: bool) {}

pub fn on_run_event(_app: &AppHandle, _event: &tauri::RunEvent) {}

pub fn supported() -> Result<(), String> {
    Ok(())
}

pub fn uses_app_menu() -> bool {
    false
}
```

`main.rs`: after `platform.install_core_hooks();` add

```rust
    // Another instance of this product runs for this user: it got this launch's files.
    if !platform::claim_instance() {
        std::process::exit(0);
    }
```

and in setup replace `install_menu(&handle)?;` by `if platform::uses_app_menu() { install_menu(&handle)?; }`.

`state.rs`: where `vm.setup = SetupView::build(…)`, append `.with_engine_note(crate::platform::get().setup().engine_note())`.

`open_files.rs` tests: `#[cfg(target_os = "macos")]` on `info_plist`, `vpn_config_types_are_not_safe_download_types` and `handler_ranks_claim_only_the_own_type` (they read the macOS Info.plist with `/usr/bin/plutil`).

- [x] **Step 5: The Windows Tauri config and the `.conf` association** (failing test first, in `app/src-tauri/tests/tauri_config.rs`)

```rust
/// Base + Windows: WinVPN's identity, the same windows as MacVPN's but titled WinVPN, the default associations of
/// .ovpn, .sstp and .macvpncatalog (no .conf: that one is "Open with" only, through the WiX fragment).
#[test]
fn the_windows_config_is_winvpn() {
    let merged = merged_config("tauri.windows.conf.json");
    assert_eq!(merged["productName"], "WinVPN");
    assert_eq!(merged["mainBinaryName"], "WinVPN");
    assert_eq!(merged["identifier"], "local.winvpn");
    assert_eq!(merged["bundle"]["copyright"], "WinVPN");
    let base = config("tauri.conf.json");
    let (mut ours, mut theirs) = (merged["app"]["windows"].clone(), base["app"]["windows"].clone());
    ours[0]["title"] = "".into();
    theirs[0]["title"] = "".into();
    assert_eq!(ours, theirs, "the same windows apart from the title");
    assert_eq!(merged["app"]["windows"][0]["title"], "WinVPN");
    let exts: Vec<String> = merged["bundle"]["fileAssociations"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|a| a["ext"].as_array().unwrap().iter().map(|e| e.as_str().unwrap().to_string()))
        .collect();
    assert_eq!(exts, ["ovpn", "sstp", "macvpncatalog"]);
    let wix = &merged["bundle"]["windows"]["wix"];
    assert_eq!(wix["fragmentPaths"][0], "wix/file-associations.wxs");
    assert_eq!(wix["componentRefs"][0], "WinVPNConfOpenWith");
    let upgrade = wix["upgradeCode"].as_str().unwrap();
    assert_eq!(upgrade.len(), 36, "a fixed GUID: MSI upgrades find the installed WinVPN by it");
    let fragment = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("wix/file-associations.wxs")).unwrap();
    assert!(fragment.contains(r"Software\Classes\.conf\OpenWithProgids"));
    assert!(!fragment.contains("<Extension"), ".conf never becomes WinVPN's by default");
}
```

(`merged_config(name)` / `config(name)`: the merge-patch helpers the file already uses for the macOS check; add `merged_config` taking the OS file name if it is hard-coded to macOS.)

Run: `cargo test --locked -p macvpn-app --test tauri_config` → FAIL. Then `app/src-tauri/tauri.windows.conf.json`:

```json
{
  "productName": "WinVPN",
  "mainBinaryName": "WinVPN",
  "identifier": "local.winvpn",
  "app": {
    "windows": [
      {
        "label": "menu",
        "create": false,
        "title": "WinVPN",
        "url": "index.html",
        "width": 330,
        "height": 360,
        "resizable": false,
        "maximizable": false,
        "minimizable": false,
        "decorations": false,
        "visible": false,
        "alwaysOnTop": true,
        "skipTaskbar": true,
        "visibleOnAllWorkspaces": true,
        "acceptFirstMouse": true,
        "shadow": true,
        "focus": true
      }
    ]
  },
  "bundle": {
    "targets": ["msi"],
    "copyright": "WinVPN",
    "icon": ["icons/32x32.png", "icons/128x128.png", "icons/icon.ico"],
    "fileAssociations": [
      { "ext": ["ovpn"], "name": "OpenVPN configuration", "description": "OpenVPN configuration", "role": "Viewer" },
      { "ext": ["sstp"], "name": "SSTP connection", "description": "SSTP connection", "role": "Viewer" },
      { "ext": ["macvpncatalog"], "name": "Team catalog", "description": "MacVPN / WinVPN team catalog", "role": "Editor" }
    ],
    "windows": {
      "webviewInstallMode": { "type": "downloadBootstrapper" },
      "wix": {
        "upgradeCode": "72446277-03C5-4DBB-AC44-49785F029CF8",
        "fragmentPaths": ["wix/file-associations.wxs"],
        "componentRefs": ["WinVPNConfOpenWith"]
      }
    }
  }
}
```

(The `menu` window entry is copied from `tauri.conf.json` with only the title changed: merge patch replaces arrays whole; the test above keeps them in step.) `app/src-tauri/wix/file-associations.wxs`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<!-- .conf (WireGuard, strongSwan) is "Open with" only: WinVPN never becomes its default app (as the macOS
     Alternate rank). .ovpn, .sstp and .macvpncatalog come from tauri.windows.conf.json's fileAssociations. -->
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Fragment>
    <DirectoryRef Id="INSTALLDIR">
      <Component Id="WinVPNConfOpenWith" Guid="91CB152A-A2D5-4E75-AD31-77AB3A835A7A">
        <RegistryValue Root="HKLM" Key="Software\Classes\WinVPN.conf" Value="VPN configuration" Type="string" KeyPath="yes" />
        <RegistryValue Root="HKLM" Key="Software\Classes\WinVPN.conf\shell\open\command" Value="&quot;[INSTALLDIR]WinVPN.exe&quot; &quot;%1&quot;" Type="string" />
        <RegistryValue Root="HKLM" Key="Software\Classes\.conf\OpenWithProgids" Name="WinVPN.conf" Value="" Type="string" />
      </Component>
    </DirectoryRef>
  </Fragment>
</Wix>
```

Run the config test → PASS; `cargo test --locked -p macvpn-app --test tauri_config` also keeps the macOS check green.

- [x] **Step 6: The UI**

`app/ui/src/lib/api.ts`, in `SetupView`: `engineNote?: string;` (optional: absent on macOS). `Setup.svelte`, before the rows block (`{#if setup?.homebrew && setup.tools && setup.root}`):

```svelte
    {#if setup?.engineNote}
      <p class="engine-note">{setup.engineNote}</p>
    {:else if setup?.homebrew && setup.tools && setup.root}
```

(close the new `{#if}` where the old one closes; style `.engine-note` like the window's other notes). `app.css`:

```css
  --font: -apple-system, BlinkMacSystemFont, 'SF Pro Text', 'Helvetica Neue', 'Segoe UI Variable Text', 'Segoe UI', sans-serif;
  --mono: ui-monospace, 'SF Mono', SFMono-Regular, Menlo, Consolas, monospace;
```

Run: `cd app/ui && npm test && npm run build`
Expected: PASS (svelte-check accepts the optional field).

- [x] **Step 7: Run everything on both systems**

Run (Mac): `cargo test --locked -p macvpn-app && CI=1 cargo test --workspace --locked && cargo test --locked -p macvpn-app-core --test compat_1_4 && node scripts/l10n-baseline.mjs --check`
Run: `scripts/win-remote.sh run 'cargo test --locked --target x86_64-pc-windows-msvc -p macvpn-app && cargo build --locked -p macvpn-app'`
Expected: PASS. On the Windows machine (the maintainer, at the desktop): `target\debug\macvpn-app.exe` with `MACVPN_SANDBOX_HOME=%TEMP%\winvpn-sandbox` and the Vite dev server (`cd app/ui && npm run dev`) starts, shows the tray icon (white on a dark taskbar), opens the popover above it; Manage, Vault and System Status windows open; System Status shows the engine note.

- [x] **Step 8: Commit**

```bash
git add app crates/platform-win
git commit -m "feat(app): WinVPN runs on Windows" -m "One instance per user (a second launch forwards its files), files from Explorer through the shared open-files handler, the popover above the taskbar icon, a tinted tray icon, no macOS menu bar, the engine note in System Status, the MSI's file types (.conf as Open with only). macOS: the same popover position (tested), template icons, the same menu." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

## Task 15: texts for Windows

**Goal:** no Windows text names a macOS facility; WinVPN's own texts exist in EN and HU; the macOS texts stay byte-identical.

**Files:**
- Modify: `crates/app-core/tests/l10n_coverage.rs`, `crates/core/l10n/strings.json`
- Modify: `scripts/l10n-baseline.mjs` (an optional `--os windows` dump for the review, not a gate)
- Test: `app/ui/src/lib/l10n.test.ts`

- [x] **Step 1: Write the failing test** (`crates/app-core/tests/l10n_coverage.rs`)

```rust
/// What WinVPN shows: every text resolved for Windows (variant, else base, product name replaced), in both
/// languages, names no macOS facility, unless the text is never shown on Windows (`only` without "windows").
#[test]
fn no_macos_term_reaches_windows() {
    use macvpn_core::TargetOs;
    use macvpn_core::l10n::{self, AppLanguage, TextPlatform};
    let windows = TextPlatform { os: TargetOs::Windows, product: "WinVPN" };
    let mut offenders = Vec::new();
    for entry in l10n::table() {
        if !entry.shown_on(TargetOs::Windows) {
            continue;
        }
        for language in [AppLanguage::En, AppLanguage::Hu] {
            let text = l10n::resolve_for(&entry.key, language, windows);
            for term in MACOS_TERMS {
                if contains_term(&text, term) {
                    offenders.push(format!("{term}: {text}"));
                }
            }
        }
    }
    assert!(offenders.is_empty(), "macOS terms in Windows texts:\n{}", offenders.join("\n"));
}
```

`MACOS_TERMS` and `contains_term` are the list and matcher `macos_terms_are_classified` already uses (move them to module level if they are local; add the Hungarian forms if the list has only English ones: „Kulcskarika”, „Finder”, „Mac”, „Rendszerbeállítások”, „Dock”, „menüsor”, „Option”). `entry.shown_on(os)` and `l10n::resolve_for(key, language, platform)`: use the functions `tr_for` already uses; if they are private, expose them `#[doc(hidden)] pub`.

Run: `cargo test --locked -p macvpn-app-core --test l10n_coverage no_macos_term_reaches_windows`
Expected: FAIL or PASS – a FAIL lists the texts to fix.

- [x] **Step 2: Fix every offender**

For each listed text: either a `variants.windows` (`en` and `hu`, the glossary of `docs/architecture.md`; the same format specifiers as the base), or `only: ["macos"]` if the code path that shows it never runs on Windows (Homebrew, the root layer, Device Management, LaunchAgent, Gatekeeper, the 1.1 Keychain migration). Rerun until PASS.

- [x] **Step 3: The UI side**

In `app/ui/src/lib/l10n.test.ts`, the same check over `scope == "app"` entries with `translate(table, language, key, args, { os: 'windows', productName: 'WinVPN' })` (the platform parameter `tr()` already passes). Run: `cd app/ui && npm test` → PASS.

- [x] **Step 4: The macOS texts are unchanged**

Run: `node scripts/l10n-baseline.mjs --check && cargo test --locked -p macvpn-core --test l10n`
Expected: PASS. Then `node scripts/l10n-baseline.mjs --os windows > /tmp/l10n-windows.json` (add the flag: prints the Windows resolution of every key shown on Windows, EN and HU, sorted; no file is committed) and attach a skim of it to Task 20's review.

- [x] **Step 5: Commit**

```bash
git add crates/core/l10n/strings.json crates/app-core/tests/l10n_coverage.rs app/ui/src/lib/l10n.test.ts scripts/l10n-baseline.mjs crates/core/src/l10n.rs
git commit -m "feat(l10n): every Windows text speaks Windows" -m "A test resolves every text for WinVPN in English and Hungarian and refuses macOS facility names; the offenders got Windows variants or only: macos. The macOS baseline is unchanged." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

## Task 16: the MSI and its release gates

**Goal:** `scripts/build-msi.sh` builds `dist/windows/WinVPN-<version>-x64.msi` and `-arm64.msi` with their `.sha256`, unsigned, after gates that mirror `build-dmg.sh`'s.

**Files:**
- Create: `scripts/build-msi.sh`, `scripts/pe-imports.mjs`, `scripts/bundle-baseline/winvpn-msi-files.txt`, `THIRD-PARTY-NOTICES.windows.txt`
- Modify: `scripts/third-party-notices.mjs` (`--os windows`), `app/src-tauri/tauri.windows.conf.json` (`bundle.resources`), `.gitignore` (`dist/windows/`)

- [x] **Step 1: Windows notices** (failing check first)

Run: `node scripts/third-party-notices.mjs --os windows --check`
Expected: FAIL (`unknown option` or the missing file).

Change `scripts/third-party-notices.mjs`: parse `--os macos|windows` (default `macos`, so every existing call is unchanged); `TARGETS`/`OTHER_TARGETS` swap for `windows`; `OUT` is `THIRD-PARTY-NOTICES.windows.txt` for `windows`; `ROOT_PACKAGES` for `windows` is `['macvpn-app']` (no helper ships in the 2a MSI); for `windows` also print OpenSSL's own licence (`openssl-src`'s `openssl/LICENSE.txt` from the registry source) next to the SQLCipher notice, since the vendored OpenSSL is linked into `WinVPN.exe`. Then `node scripts/third-party-notices.mjs --os windows` writes the file, and `node scripts/third-party-notices.mjs --check` (macOS) still passes unchanged.

Check: `grep -c '^windows-sys 0.61.2\|^windows 0.62.2\|^openssl-src' THIRD-PARTY-NOTICES.windows.txt` ≥ 3, and `grep -n 'macvpn-winsys\|macvpn-platform-win' THIRD-PARTY-NOTICES.windows.txt` prints nothing (workspace crates are not third-party).

In `tauri.windows.conf.json`, `bundle`: `"resources": { "../../THIRD-PARTY-NOTICES.windows.txt": "THIRD-PARTY-NOTICES.txt" }`.

- [x] **Step 2: `scripts/pe-imports.mjs`**

```js
#!/usr/bin/env node
// Prints the DLLs a PE file (exe or dll) imports, normal and delay-loaded, lower-case, sorted, one per line.
// No dependencies: the release gate of scripts/build-msi.sh checks that no crypto or SQLite DLL is imported.
import { readFileSync } from 'node:fs';

const buf = readFileSync(process.argv[2]);
const pe = buf.readUInt32LE(0x3c);
if (buf.toString('latin1', pe, pe + 4) !== 'PE\0\0') throw new Error('not a PE file');
const coff = pe + 4;
const sectionCount = buf.readUInt16LE(coff + 2);
const optionalSize = buf.readUInt16LE(coff + 16);
const optional = coff + 20;
const directories = optional + (buf.readUInt16LE(optional) === 0x20b ? 112 : 96);
const sections = optional + optionalSize;

function offset(rva) {
  for (let i = 0; i < sectionCount; i++) {
    const s = sections + i * 40;
    const va = buf.readUInt32LE(s + 12);
    const size = Math.max(buf.readUInt32LE(s + 8), buf.readUInt32LE(s + 16));
    if (rva >= va && rva < va + size) return rva - va + buf.readUInt32LE(s + 20);
  }
  throw new Error(`RVA ${rva} is outside every section`);
}

function cstring(at) {
  let end = at;
  while (buf[end] !== 0) end++;
  return buf.toString('latin1', at, end);
}

const names = new Set();
const imports = buf.readUInt32LE(directories + 1 * 8);
if (imports) {
  for (let d = offset(imports); buf.readUInt32LE(d + 12) !== 0; d += 20) names.add(cstring(offset(buf.readUInt32LE(d + 12))).toLowerCase());
}
const delayed = buf.readUInt32LE(directories + 13 * 8);
if (delayed) {
  for (let d = offset(delayed); buf.readUInt32LE(d + 4) !== 0; d += 32) names.add(cstring(offset(buf.readUInt32LE(d + 4))).toLowerCase());
}
console.log([...names].sort().join('\n'));
```

Check it later on the built exe: its output contains `kernel32.dll` and `webview2loader.dll` or `ole32.dll`, and no `libcrypto*`, `libssl*`, `sqlite*`.

- [x] **Step 3: `scripts/build-msi.sh`**

```bash
#!/bin/bash
# Builds the unsigned WinVPN MSIs on Windows (Git Bash), the counterpart of build-dmg.sh (spec 7):
#   1. the three version numbers agree; no build-changing variable leaks in; THIRD-PARTY-NOTICES.windows.txt current
#   2. the UI, then per architecture: `tauri build --bundles msi` for the target
#   3. release gates on WinVPN.exe: no debug-only code (MACVPN_SANDBOX_HOME, MACVPN_SMOKE); SQLCipher with the
#      vendored OpenSSL 3, statically linked (no crypto or SQLite DLL imported, no CommonCrypto provider)
#   4. the MSI: renamed to the update asset name, its files exactly scripts/bundle-baseline/winvpn-msi-files.txt
#      (an administrative extraction), the notices inside equal to the committed file, the Start-menu shortcut
#      carrying the AppUserModelID local.winvpn, the fixed UpgradeCode; .sha256 next to it
# Authenticode only when WINVPN_SIGN_THUMBPRINT (and WINVPN_SIGN_TIMESTAMP_URL) are set: off by default and in CI.
#
#   scripts/build-msi.sh [--arch x64|arm64|both] [--write-baseline]
set -euo pipefail
cd "$(dirname "$0")/.."

die() { echo "error: $*" >&2; exit 1; }
step() { echo; echo "==> $*"; }

[ "$(uname -o 2>/dev/null)" = Msys ] || die "run this in Git Bash on Windows"
ARCHES=(x64 arm64)
WRITE_BASELINE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --arch) [ $# -ge 2 ] || die "--arch needs x64, arm64 or both"
            case "$2" in x64|arm64) ARCHES=("$2") ;; both) ;; *) die "--arch needs x64, arm64 or both" ;; esac; shift ;;
    --write-baseline) WRITE_BASELINE=1 ;;
    *) die "unknown option: $1" ;;
  esac
  shift
done

step "versions"
VERSION="$(node -p "require('./app/src-tauri/tauri.conf.json').version")"
CARGO_VERSION="$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -n 1)"
UI_VERSION="$(node -p "require('./app/ui/package.json').version")"
[ "$VERSION" = "$CARGO_VERSION" ] && [ "$VERSION" = "$UI_VERSION" ] \
  || die "versions differ: tauri.conf.json $VERSION, Cargo.toml $CARGO_VERSION, app/ui/package.json $UI_VERSION"
echo "  $VERSION"

step "environment"
for v in MACVPN_SANDBOX_HOME MACVPN_SMOKE_DIR RUSTFLAGS CARGO_ENCODED_RUSTFLAGS OPENSSL_DIR OPENSSL_LIB_DIR \
         OPENSSL_INCLUDE_DIR OPENSSL_STATIC OPENSSL_NO_VENDOR SQLCIPHER_LIB_DIR SQLCIPHER_INCLUDE_DIR; do
  [ -z "${!v:-}" ] || die "$v is set: unset it for a release build"
done
export OPENSSL_SRC_PERL="${OPENSSL_SRC_PERL:-C:\\Strawberry\\perl\\bin\\perl.exe}"

step "THIRD-PARTY-NOTICES.windows.txt"
node scripts/third-party-notices.mjs --os windows --check || die "THIRD-PARTY-NOTICES.windows.txt is out of date (node scripts/third-party-notices.mjs --os windows)"

SIGN_CONFIG=()
if [ -n "${WINVPN_SIGN_THUMBPRINT:-}" ]; then
  [[ "$WINVPN_SIGN_THUMBPRINT" =~ ^[0-9A-Fa-f]{40}$ ]] || die "WINVPN_SIGN_THUMBPRINT: 40 hex digits"
  [[ "${WINVPN_SIGN_TIMESTAMP_URL:-}" =~ ^https?://[A-Za-z0-9./_-]+$ ]] || die "WINVPN_SIGN_TIMESTAMP_URL is needed for signing"
  SIGN_CONFIG=(--config "{\"bundle\":{\"windows\":{\"certificateThumbprint\":\"$WINVPN_SIGN_THUMBPRINT\",\"digestAlgorithm\":\"sha256\",\"timestampUrl\":\"$WINVPN_SIGN_TIMESTAMP_URL\"}}}")
  echo "Authenticode: on ($WINVPN_SIGN_THUMBPRINT)"
else
  echo "Authenticode: off (unsigned build)"
fi

step "UI"
(cd app/ui && npm ci --no-audit --no-fund && npm run build)

OUT=dist/windows
rm -rf "$OUT"
mkdir -p "$OUT"
for arch in "${ARCHES[@]}"; do
  case "$arch" in
    x64) TARGET=x86_64-pc-windows-msvc ;;
    arm64) TARGET=aarch64-pc-windows-msvc ;;
  esac
  step "build $arch ($TARGET)"
  (cd app/ui && npx --no-install tauri build --ci --target "$TARGET" --bundles msi "${SIGN_CONFIG[@]}")
  # The Tauri CLI writes the binary under mainBinaryName next to cargo's macvpn-app.exe.
  EXE="target/$TARGET/release/WinVPN.exe"
  [ -f "$EXE" ] || die "$EXE is missing"

  step "release gate: no debug-only code ($arch)"
  for marker in MACVPN_SANDBOX_HOME MACVPN_SMOKE; do
    if LC_ALL=C grep -a -q -F "$marker" "$EXE"; then die "the release binary contains '$marker'"; fi
  done

  step "release gate: SQLCipher with the vendored OpenSSL, linked statically ($arch)"
  LC_ALL=C grep -a -q -F 'SQLite format' "$EXE" || die "$EXE contains no SQLCipher"
  LC_ALL=C grep -a -q -E 'OpenSSL 3\.[0-9]+\.[0-9]+' "$EXE" || die "$EXE contains no vendored OpenSSL 3"
  if LC_ALL=C grep -a -q -F commoncrypto "$EXE"; then die "$EXE names the CommonCrypto provider"; fi
  node scripts/pe-imports.mjs "$EXE" >"$OUT/imports-$arch.txt"
  if grep -E '^(libcrypto|libssl|sqlite|sqlcipher)' "$OUT/imports-$arch.txt"; then die "$EXE imports a crypto or SQLite DLL"; fi

  step "MSI ($arch)"
  shopt -s nullglob
  BUILT=(target/"$TARGET"/release/bundle/msi/WinVPN_"$VERSION"_*.msi)
  shopt -u nullglob
  [ ${#BUILT[@]} -eq 1 ] || die "expected one MSI for $arch, found ${#BUILT[@]}"
  MSI="$OUT/WinVPN-$VERSION-$arch.msi"
  cp "${BUILT[0]}" "$MSI"
  WXS="$(ls target/"$TARGET"/release/wix/*/main.wxs)"
  grep -q 'System.AppUserModel.ID' "$WXS" && grep -q 'local.winvpn' "$WXS" \
    || die "the Start-menu shortcut has no AppUserModelID local.winvpn (toasts would not show): use a custom WiX template"
  UPGRADE="$(node -p "require('./app/src-tauri/tauri.windows.conf.json').bundle.windows.wix.upgradeCode")"
  grep -qi "UpgradeCode=\"$UPGRADE\"" "$WXS" || die "the MSI's UpgradeCode is not $UPGRADE"

  step "MSI contents ($arch)"
  EXTRACT="$OUT/extract-$arch"
  MSYS2_ARG_CONV_EXCL='*' msiexec /a "$(cygpath -w "$MSI")" /qn TARGETDIR="$(cygpath -w "$PWD/$EXTRACT")"
  (cd "$EXTRACT" && find . -type f ! -name '*.msi' | sed 's|^\./||' | LC_ALL=C sort) >"$OUT/files-$arch.txt"
  if [ "$WRITE_BASELINE" = 1 ] && [ "$arch" = x64 ]; then
    cp "$OUT/files-$arch.txt" scripts/bundle-baseline/winvpn-msi-files.txt
    echo "  wrote scripts/bundle-baseline/winvpn-msi-files.txt: review it before committing"
  fi
  diff -u scripts/bundle-baseline/winvpn-msi-files.txt "$OUT/files-$arch.txt" || die "unexpected files in the $arch MSI"
  NOTICES="$(grep -m 1 'THIRD-PARTY-NOTICES.txt$' "$OUT/files-$arch.txt")" || die "the MSI has no THIRD-PARTY-NOTICES.txt"
  cmp -s "$EXTRACT/$NOTICES" THIRD-PARTY-NOTICES.windows.txt || die "the MSI's notices differ from THIRD-PARTY-NOTICES.windows.txt"
  rm -rf "$EXTRACT"

  (cd "$OUT" && sha256sum "WinVPN-$VERSION-$arch.msi" >"WinVPN-$VERSION-$arch.msi.sha256")
  cat "$OUT/WinVPN-$VERSION-$arch.msi.sha256"
done
echo
echo "OK: $(ls "$OUT"/*.msi | tr '\n' ' ')"
```

(`npx --no-install tauri` runs the pinned `@tauri-apps/cli` from `app/ui/node_modules`; if the project runs the CLI through `npm run tauri`, use `npm run tauri -- build …` instead, as `build-dmg.sh` does.)

- [x] **Step 4: First build and the baseline**

Run: `bash -n scripts/build-msi.sh && scripts/win-remote.sh run 'scripts/build-msi.sh --arch x64 --write-baseline' && scripts/win-remote.sh fetch scripts/bundle-baseline/winvpn-msi-files.txt ./scripts/bundle-baseline`
Expected: the gates pass; the baseline lists exactly the installed `WinVPN.exe` and `THIRD-PARTY-NOTICES.txt` under the program-files folder (for example `PFiles64/WinVPN/WinVPN.exe`, `PFiles64/WinVPN/THIRD-PARTY-NOTICES.txt`). Anything else (a `.pdb`, a stray DLL) is a finding: fix the bundle, not the baseline. If `msiexec /a` needs elevation on the standard account, note it: the step then runs in CI (the runner is an administrator) and the maintainer's machine skips it with `WINVPN_SKIP_MSI_EXTRACT=1` (add that switch, which prints "SKIPPED: MSI contents" and never applies in CI).

If the AppUserModelID gate fails, copy Tauri 2.12's `main.wxs` template into `app/src-tauri/wix/main.wxs`, add `<ShortcutProperty Key="System.AppUserModel.ID" Value="{{bundle_id}}"/>` inside the Start-menu `<Shortcut>`, set `bundle.windows.wix.template` to it, and say so in the commit.

Then: `scripts/win-remote.sh run 'scripts/build-msi.sh'` → both MSIs and `.sha256`; `scripts/win-remote.sh fetch dist/windows ./dist` for the maintainer's install test (Task 19).

**As built (2026-10-21):** Tauri 2.12's own template already carries `System.AppUserModel.ID` = `local.winvpn` on the Start-menu shortcut, so no custom template. `msiexec /a` cannot run on the test machine (an OpenSSH session with key authentication cannot reach the Windows Installer service: error 1601), and for the same reason light.exe's ICE validation fails there (LGHT0217). So the contents gate unpacks the MSI with WiX's `dark.exe -x` and places the files by the File, Component and Directory tables (no service, works everywhere, CI too; `WINVPN_SKIP_MSI_EXTRACT` is not needed), and `WINVPN_WIX_NO_ICE=1` (refused when `CI` is set) re-links the MSI from Tauri's objects with `light.exe -sval` where the service is unreachable; CI validates. The MSI's tables are read with `scripts/msi-query.ps1` (the Windows Installer COM object, read-only, no service) instead of grepping `main.wxs`: ProductName, ProductVersion, UpgradeCode, the shortcut and its AppUserModelID, the Extension/Verb rows of `.ovpn`, `.sstp`, `.macvpncatalog`, the `.conf` Registry rows (Open with only). candle.exe, light.exe and dark.exe are checked against pinned SHA-256s (WiX 3.14.1.8722, which the Tauri CLI downloads and checks itself). The binary's PE machine is checked per architecture. The ARM64 cross build (vendored OpenSSL included) works on the test machine.

- [x] **Step 5: Commit**

```bash
git add scripts/build-msi.sh scripts/pe-imports.mjs scripts/bundle-baseline/winvpn-msi-files.txt scripts/third-party-notices.mjs THIRD-PARTY-NOTICES.windows.txt app/src-tauri/tauri.windows.conf.json app/src-tauri/wix .gitignore
git commit -m "build: the WinVPN MSIs with release gates" -m "scripts/build-msi.sh builds x64 and ARM64 MSIs named as the update assets, with build-dmg.sh's gates for Windows: no debug-only code, SQLCipher with the statically linked vendored OpenSSL 3, the exact MSI contents, the notices, the AppUserModelID shortcut and the fixed UpgradeCode. Authenticode only when a thumbprint is given (off by default)." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

## Task 17: CI and the release workflow

**Goal:** CI builds both MSIs on every push and keeps them as artifacts; the release workflow builds them on Windows and attaches them to the draft only when `WINVPN_MSI_IN_RELEASE` is `true` (question 3). The macOS jobs are unchanged except for the new ignored-tests gate (Task 11).

**Files:**
- Modify: `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `docs/RELEASING.md`

- [x] **Step 1: CI** (`.github/workflows/ci.yml`)

In job `windows`: add `-p macvpn-app` to the test step. Add a job:

```yaml
  msi:
    runs-on: windows-latest
    defaults:
      run:
        shell: bash
    env:
      OPENSSL_SRC_PERL: C:\Strawberry\perl\bin\perl.exe
    steps:
      - name: Check out with LF line endings
        run: git config --global core.autocrlf false
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0
        with:
          node-version: "26.8.2"
          # No automatic cache: release builds must not restore a cache written elsewhere.
          package-manager-cache: false
      - name: Rust toolchain (both Windows targets)
        run: |
          RUST_VERSION=$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml)
          [[ "$RUST_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "rust-toolchain.toml: channel must be an exact version"; exit 1; }
          rustup toolchain install "$RUST_VERSION" --profile minimal -t x86_64-pc-windows-msvc,aarch64-pc-windows-msvc
          [ "$(rustc --version | cut -d' ' -f2)" = "$RUST_VERSION" ] || { echo "rustc is not $RUST_VERSION"; exit 1; }
      - name: MSIs (x64, ARM64) with the release gates
        run: scripts/build-msi.sh
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2
        with:
          name: winvpn-msi
          path: |
            dist/windows/WinVPN-*.msi
            dist/windows/WinVPN-*.msi.sha256
          if-no-files-found: error
          retention-days: 7
```

Check: `node -e "require('js-yaml')" 2>/dev/null` is not needed; validate with `ruby -ryaml -e 'YAML.load_file(".github/workflows/ci.yml")'` (Ruby ships with macOS) → no error.

- [x] **Step 2: Release** (`.github/workflows/release.yml`)

A job `build-windows` (same `permissions: contents: read`, `runs-on: windows-latest`, `shell: bash`, the `OPENSSL_SRC_PERL` env), with the steps of `build` adapted: the tag check, checkout with `fetch-depth: 0`, "the tagged commit is on main", the version check (`node -p` instead of `plutil`), node, the toolchain (both Windows targets), the tests (`cargo test --locked --target x86_64-pc-windows-msvc` over the CI package set plus `-p macvpn-app`, then `scripts/check-ignored.sh --target x86_64-pc-windows-msvc`), `scripts/build-msi.sh`, a `SHA-256` step that prints `dist/windows/*.sha256`, and an upload of artifact `msi` (`dist/windows/WinVPN-*.msi`, `.sha256`). Keep the Hungarian step names style of the file.

The `release` job: `needs: [build, build-windows]`; a second `actions/download-artifact` (same pinned SHA) of `msi` into `dist` guarded by `if: vars.WINVPN_MSI_IN_RELEASE == 'true'`; in the `Release` step:

```bash
          FILES=(dist/MacVPN-*.dmg dist/MacVPN-*.dmg.sha256)
          (cd dist && shasum -a 256 -c MacVPN-*.dmg.sha256)
          if [ "${WINVPN_MSI_IN_RELEASE:-}" = true ]; then
            (cd dist && sha256sum -c WinVPN-*.msi.sha256)
            FILES+=(dist/WinVPN-*.msi dist/WinVPN-*.msi.sha256)
          fi
          gh release create "$GITHUB_REF_NAME" "${FILES[@]}" … (the existing flags)
```

with `WINVPN_MSI_IN_RELEASE: ${{ vars.WINVPN_MSI_IN_RELEASE }}` in the step's `env`, and the notes extended (EN/HU): the WinVPN MSIs are not Authenticode-signed (SmartScreen warns once: "More info" → "Run anyway"), they are installed by an administrator, and updates are protected by the same offline Ed25519 signatures (`WinVPN-X.Y.Z-<arch>.msi.sig`).

- [x] **Step 3: `docs/RELEASING.md`**

A section "WinVPN": the variable `WINVPN_MSI_IN_RELEASE` (unset until 2.0.0), what `sign-release.sh` signs (both MSIs with `winvpn-update-v1` and the asset name; both or neither), and that the Authenticode switch (`WINVPN_SIGN_THUMBPRINT`, `WINVPN_SIGN_TIMESTAMP_URL`) is off.

- [x] **Step 4: Commit and push nothing**

```bash
git add .github/workflows/ci.yml .github/workflows/release.yml docs/RELEASING.md
git commit -m "ci: build the WinVPN MSIs; release them behind WINVPN_MSI_IN_RELEASE" -m "CI keeps both MSIs as artifacts. The release workflow builds and tests on Windows too and attaches the MSIs to the draft only when the repository variable is true." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

The workflows run when the maintainer pushes (never from this plan). Ask the maintainer to push the branch to a fork or run the workflow once, and record the result in Task 19.

**As built (2026-10-21):** not run on GitHub yet (nothing is pushed from this plan; the first run is the maintainer's, its result goes into Task 19); the YAML is checked with PyYAML and Ruby, and the Release step's script was run locally with a stub `gh`. Adaptations: the CI `windows` test step (and the release's Windows tests) also take `-p macvpn-control-client`, the set `scripts/win-remote.sh test` and `scripts/check-ignored.sh` already use; the `msi` job and `build-windows` refuse a set `WINVPN_WIX_NO_ICE` themselves too, and `build-windows` refuses `WINVPN_SIGN_THUMBPRINT`; both print the `.sha256` files in a "SHA-256" step; `build-windows` sets `core.autocrlf false` before its checkout, runs `setup-node` before the version check (`node -p`), checks that both MSIs and `.sha256` exist, and has no update-source step (the Windows update check is 2b). The `release` job runs with `if: !cancelled() && needs.build.result == 'success' && (needs.build-windows.result == 'success' || vars.WINVPN_MSI_IN_RELEASE != 'true')`: while the variable is unset a failed Windows build does not hold back the MacVPN draft (exactly as before), and the WinVPN paragraph is added to the notes only when the MSIs are attached (the 1.x notes stay byte-identical); with the variable `true` the step requires both MSIs (sign-release.sh: both or neither).

## Task 18: documentation

**Goal:** WinVPN users have their guide, developers have the updated map, and the maintainer has a Hungarian manual checklist for Windows.

**Files:**
- Create: `docs/winvpn-user-guide.en.md`, `docs/winvpn-user-guide.hu.md`, `docs/manual-test-checklist-winvpn.md`
- Modify: `README.md`, `docs/architecture.md`, `docs/superpowers/specs/2026-10-20-cross-platform-winvpn-design.md` (only the "Phase 2 blockers" note: both marked done, with the commits)

- [x] **Step 1: The user guides** (the stem `winvpn-user-guide` is `WINVPN.user_guide_stem`; `UserGuide::url` links them)

Start from `docs/user-guide.en.md` / `.hu.md` and keep the structure and the shared sections word for word where the wording does not differ (connections, import, editing, folders, credentials, vault, backup, team catalogs, control API). Change with the glossary (Keychain → Credential Manager, Finder → File Explorer, this Mac → this PC, System Settings → Settings, Login Items → Startup apps, menu bar → notification area, Dock → taskbar, Option-click → Alt-click). Drop the macOS-only sections (Homebrew, the root layer, Device Management profiles, Gatekeeper). Add:
- **Installing:** the MSI (`WinVPN-<version>-x64.msi` or `-arm64.msi`), an administrator installs it; SmartScreen warns once because the installer is not Authenticode-signed ("More info" → "Run anyway"); WebView2 is downloaded if missing.
- **This version (preview):** WinVPN cannot connect yet; "The VPN engine comes in a later version of WinVPN." What works.
- **Auto-unlock:** the key is in Credential Manager (`local.winvpn.vault`), protected for your Windows account; it protects against other users and a stolen disk, not against software running as you; how to turn it off (question 1's wording).
- **Files from the internet:** WinVPN asks before importing a file Windows marked as downloaded.
- **Launch at login, notifications, the tray icon** (and "Show hidden icons" to pin it).
The Hungarian guide in the same structure, Hungarian throughout (the glossary's Hungarian terms).

- [x] **Step 2: `docs/manual-test-checklist-winvpn.md`** (Hungarian, the style of `docs/manual-test-checklist.md`: a checkbox per check, the expected result after "→")

Sections and checks (each a checkbox line):
1. **Telepítés** (rendszergazda): az x64 MSI telepítése tiszta Windows 11-en → SmartScreen egyszer figyelmeztet; Start menüben „WinVPN”; `C:\Program Files\WinVPN\WinVPN.exe` és `THIRD-PARTY-NOTICES.txt`; újratelepítés (ugyanaz a verzió) → javítás, nem második példány; eltávolítás → a program eltűnik, a `%LOCALAPPDATA%\WinVPN` megmarad.
2. **Első indítás és trezor:** a tálca értesítési területén megjelenik az ikon (sötét tálcán fehér, világoson fekete; témaváltás után a következő ikonfrissítéskor); a popover az ikon fölött, lekerekítve (Win11); trezor létrehozása, helyreállítási kulcs; `cmdkey /list` → `local.winvpn.vault` szerepel; kilépés és újraindítás → automatikus feloldás; automatikus feloldás ki → a hitelesítő adat eltűnik, indításkor jelszót kér; `icacls %LOCALAPPDATA%\WinVPN` → csak a felhasználó és a SYSTEM.
3. **Kapcsolatok:** `.ovpn` importálása mellékelt fájlokkal (`ca.crt`, `sub\client.key`) → beolvasva; `..\` hivatkozás → elutasítva; OneDrive-mappából importálás (csak online fájl) → letöltődik és beolvasódik; L2TP kapcsolat létrehozása és mentése → mentve, utána „A VPN-motor a WinVPN egy későbbi verziójában érkezik.”; kapcsolódás bármelyikre → ugyanez az üzenet; exportálás.
4. **Mentés és visszaállítás:** teljes mentés WinVPN-ből; egy MacVPN-mentés visszaállítása WinVPN-ben → kapcsolatok, mappák, hitelesítő adatok átjönnek; egy WinVPN-mentés visszaállítása MacVPN-ben (Macen).
5. **Csapatkatalógus:** fájlos forrás feliratkozás, frissítés; HTTPS-forrás → „Ezen a rendszeren még nem érhető el” (2b-ig).
6. **Vezérlő API:** a példakliens (`macvpn-control-client` Windows-build) párosítása → párosító ablak, a kliens útvonala látszik; `list`; egy másik felhasználó (második fiók) kliense → nem csatlakozhat.
7. **Fájltársítások:** dupla kattintás `.ovpn`-re és `.macvpncatalog`-ra → WinVPN megnyitja (ha fut: a futó példány); `.conf` → csak a „Társítás” listában; letöltött `.ovpn` (Mark of the Web) → megerősítést kér.
8. **Rendszer:** értesítések (kapcsolat-esemény helyett egy katalógus-értesítés); vágólapra másolt titok → nem jelenik meg a Win+V előzményekben; bejelentkezéskor indítás be → `HKCU\…\Run\WinVPN`; Gépház → Alkalmazások → Indítás alatt kikapcsolva → WinVPN megjegyzést mutat; kijelentkezés nyitott, nem mentett szerkesztővel → a kilépési kérdés megjelenik, a Windows vár; alvás és ébredés → a lista frissül.
9. **ARM64:** az arm64 MSI telepítése ARM64 gépen, ha elérhető (különben jelöld: nem tesztelt).

- [x] **Step 3: README and architecture**

`README.md`: a short "WinVPN (preview)" section: what 2a does and does not do, the MSI names, the build (`scripts/build-msi.sh` on Windows), the link to the WinVPN user guide. `docs/architecture.md`: `crates/winsys` in the crate list and the dependency graph (core → winsys on Windows; platform-win → winsys); platform-win's real layout (`pure`/`win`); the rule table's allow-lists (with `crates/winsys/`) and the new `scripts/check-ignored.sh` row; `fsx::Stat`; the control pipe; "Checking Windows" (Task 1's subsection, `build-msi.sh`); "Adding a platform" steps 4, 11 and 12 marked done for Windows with a pointer to this plan.

Spec: in "Phase 2 blockers", append to each item "Done in 2a (`<commit>`)."

*As built (2026-10-21):* the Windows checklist is the section "WinVPN 2a" at the top of `docs/manual-test-checklist.md` (one Hungarian checklist file, which `docs/architecture.md` already named for the admin-only steps), not a separate `manual-test-checklist-winvpn.md`; Task 19 Step 3 uses that section. It covers the plan's nine areas plus every desktop-only check the tasks reported (the Credential Manager round trip in an interactive logon, the pipe refusing a second account and SSH, single instance, logoff, sleep, Startup apps, the tray tint and popover, no menu bar, Ctrl shortcuts, file dialogs, toasts, the clipboard formats, the Mark of the Web, the file associations, MSI repair and uninstall, `icacls`). The guides describe the code as it is, including where it differs from this plan: on Windows only L2TP and Cisco IPsec reach the "engine later" answer (the other types are "Missing tool": `SetupReport::is_available` is false for a non-native kind while `check` returns `SetupReport::unknown()`; the control API answers `setup_required` for them); System Status opens at every launch with a "!" mark; Help opens the MacVPN guide (`user_guide_url` uses `MACVPN`); the in-app uninstall fails ("no user name"); `Access::Shared` is a protected DACL with `BUILTIN\Users` read, not the folder's inherited permissions; the backup's default name stays `MacVPN-backup-<date>.macvpnbackup`. `docs/RELEASING.md` is left to Task 17 (same wave, its file).

*Fixed after Task 18 (branch `a2-fix1`), the guides and the checklist updated with them:* every VPN type shows the engine answer instead of "Missing tool" (`SetupReport::engine_missing`, set by platform-win's `check`: no kind is available, the rows carry it as `unavailableReason`, the `connect` command refuses with it, and the control API's `up` answers `failed` with it as the message, through `ControlHost::engine_missing`, never `setup_required`); System Status is not incomplete without an engine (`is_complete`), so it no longer opens by itself and its tile has no "!"; Help opens the running product's guide (`user_guide_url` takes the `Product`); the in-app uninstall is replaced on Windows by a note and "Open Installed Apps…" (`ms-settings:appsfeatures`; `SystemSetup::system_uninstall_note` / `open_system_uninstall`, `SetupView::system_uninstall`), and `setup_uninstall` refuses there; the backup's default name is `<product>-backup-<date>.macvpnbackup` (`WinVPN-backup-…` on Windows, MacVPN unchanged); `scripts/win-remote.sh msi` runs `build-msi.sh` without `CI` and with `WINVPN_WIX_NO_ICE=1` (checked by `scripts/test-win-remote.sh`). `Access::Shared` being a protected DACL (user and SYSTEM full, `BUILTIN\Users` read) is the intended equivalent of 0644, not a gap (see Resolved points). Two more, found by installing the MSI: the navigation guard allowed only `tauri://localhost`, so every window was blank on Windows (the app origin is now per OS, `navigation::app_origin()` by `Product::os`: `https://tauri.localhost` on Windows, where every window uses `useHttpsScheme` and the CSP's `connect-src` allows `https://ipc.localhost`); and a console window opened with WinVPN (`windows_subsystem = "windows"` in release builds; `build-msi.sh` checks the PE subsystem).

- [x] **Step 4: Check and commit**

Run: `grep -rniE 'alpha.?vet' docs README.md` → no output. `node scripts/l10n-baseline.mjs --check` → PASS (docs do not change texts).

```bash
git add docs README.md
git commit -m "docs: WinVPN user guide, Windows manual checklist, architecture for 2a" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

## Task 19: verification

**Goal:** proof that MacVPN is unchanged and that the WinVPN MSI does what the goal says, on the maintainer's machines.


  *Maintainer's desktop run (2026-10-21):* `cargo test -p macvpn-platform-win --test windows -- --test-threads=1` as `winvpn-dev` in an interactive logon (`runas`): 19 passed, 0 failed, 0 ignored — incl. the real Credential Manager round trip (`the_credential_key_store_round_trips_and_deletes`), the single-instance forwarding and the secret clipboard. The first MSI install showed blank white windows and a console window (fixed in the follow-up: the Windows app origin `https://tauri.localhost` in the navigation guard, and the GUI subsystem).


  *GitHub CI (2026-10-21, temporary squashed `ci/windows` branch, approved by the maintainer; branch and runs deleted afterwards):* round 1 failed in three places that only the hosted runner shows (the icacls test read the built-in Administrator as the SDDL alias `LA`; the pipe auth timeout could fire up to a timer tick early — a real bug; the MSI gate compared against Tauri's restored, unpatched exe). Round 2 after the fixes: all six jobs green — `rust` 9 min, `dmg` 12 min, `node` 27 s, `windows-node` 29 s, `windows` 39 min, `msi` 30 min (both MSIs, ICE validation on, every gate).

- [x] **Step 1: MacVPN** (on the Mac)

Run, and record each result in the commit body:
```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
CI=1 cargo test --workspace --locked && CI=1 cargo test --workspace --locked --release
cargo test --locked -p macvpn-app-core --test compat_1_4
node scripts/l10n-baseline.mjs --check
node scripts/third-party-notices.mjs --check
MVPN_IMPL=rust scripts/test-root.sh
scripts/test-sign-release.sh
scripts/check-windows.sh
scripts/check-ignored.sh
cargo tree --locked --target aarch64-apple-darwin -i openssl-sys; cargo tree --locked --target x86_64-apple-darwin -i openssl-sys
cargo tree --locked -e normal --target aarch64-apple-darwin -p macvpn-app -p macvpn-helper --prefix none | grep -E '^(windows|macvpn-winsys)'; cargo tree --locked -e normal --target x86_64-apple-darwin -p macvpn-app -p macvpn-helper --prefix none | grep -E '^(windows|macvpn-winsys)'
(cd app/ui && npm test && npm run build)
scripts/build-dmg.sh && scripts/bundle-baseline.sh dist/MacVPN.app
```
Expected: all green; the four `cargo tree` lines print nothing; `bundle-baseline.sh` reports no difference except what the phase 1 baseline already normalizes (a new difference is a stop: find out why before going on).

- [x] **Step 2: Windows, automated** (the test machine)

Run: `scripts/win-remote.sh test && scripts/win-remote.sh run 'scripts/check-ignored.sh --target x86_64-pc-windows-msvc && cargo clippy --workspace --all-targets --locked --target x86_64-pc-windows-msvc -- -D warnings && cargo check --workspace --all-targets --locked --target aarch64-pc-windows-msvc && scripts/build-msi.sh' && scripts/win-remote.sh fetch dist/windows ./dist`
Expected: all green; two MSIs and two `.sha256` in `dist/windows/`.

*As done (2026-10-21, Steps 1–2 automated, at `33312b9`):*
  - **Mac** (Rust 1.99.1): `cargo fmt --check` and workspace clippy `-D warnings` clean; `CI=1 cargo test --workspace --locked` 1964 passed, 0 failed, 6 ignored, `--release` 1962 passed (the two sandbox tests are debug-only), 0 failed, 6 ignored; `compat_1_4` 8 passed and `git diff v1.5.0 -- crates/app-core/tests/fixtures/compat-1.4.0 scripts/bundle-baseline/1.4.0` empty; `l10n-baseline.mjs --check`: 1114 keys identical, 9 new; `third-party-notices.mjs --check` up to date (needs `npm ci` in `app/ui` first) and `git diff v1.5.0 -- THIRD-PARTY-NOTICES.txt` empty, the Windows notices up to date too; `scripts/check-l10n.sh`, `MVPN_IMPL=rust scripts/test-root.sh` (412 pass), `scripts/test-sign-release.sh` (31 ok), `scripts/check-windows.sh`, `scripts/check-ignored.sh` (2 here + 1 not built on macOS) all green; the four `cargo tree` lines print nothing; `app/ui`: `npm ci`, `npm test` 167 pass, `npm run build`; `scripts/build-dmg.sh` and `scripts/bundle-baseline.sh dist/MacVPN.app`: identical (only the two binary sizes).
  - **The 2a bundle against a local v1.5.0 build** (temporary worktree at `v1.5.0`, removed): Info.plist byte-identical; entitlements of the app and of `mvpn` identical; codesign flags `0x10002(adhoc,runtime)` on both binaries (only the CodeDirectory size/hash count of the larger app binary differs); the bundle's file list identical; root `VERSION` 8 in both; `THIRD-PARTY-NOTICES.txt` byte-identical; `otool -L` identical for both binaries and both architectures; `_CodeSignature/CodeResources` differs only in `mvpn`'s hash. `mvpn`'s string literals per architecture (build paths normalized, covered by substrings of at least 12 characters): nothing of 1.5.0 is missing; the only new literal text is the 9 new entries of the embedded `crates/core/l10n/strings.json` (`l10n::STRINGS_JSON`, the Windows-only texts: the VPN engine note, Installed apps, Startup apps, closing WinVPN, the mapped network drive), the rest is the linker packing short literals differently.
  - **Smoke:** `SMOKE_LANG=en` and `SMOKE_LANG=hu scripts/smoke-manage.sh` could not pass here: the Mac's display was locked for the whole run, and `manage.js` gave no result (EN also hit the 480 s limit). A debug build of `v1.5.0` fails the same way under the same locked display, so it is the environment, not 2a; every other smoke section that ran passed (vault, folders, shared, backup, catalog, open, publish, control, live, credentials, prompt, setup, update, dock, quit). **Rerun both with the display unlocked.**
  - **Windows** (the test VM, Windows 11 build 10.0.26300.9711, standard account, `WINVPN_REMOTE_DIR=winvpn-work-t19`, deleted afterwards): `scripts/win-remote.sh test` 1558 passed, 0 failed, 3 ignored (`write_compat_fixtures`, `default_parameters_timing`, `another_user_is_refused_both_ways`, exactly `scripts/ignored-everywhere.txt`); `ignored` lists the same three; `check-ignored.sh --target x86_64-pc-windows-msvc` OK; clippy x64 `-D warnings` clean; `cargo check` ARM64 clean; `scripts/win-remote.sh msi --arch both` (`WINVPN_WIX_NO_ICE=1`: ICE validation only on CI) passed every gate; fetched to `dist/windows/`: `WinVPN-1.5.0-x64.msi` SHA-256 `2786a311940599e1e7ffb76ccf623371eac2bf6136fdbe59d0d2da6b801a056c`, `WinVPN-1.5.0-arm64.msi` SHA-256 `7b6a93ccd8c2a0ac3690275c7db69d0ee7e3137f578b83c2dd85654e8f9cc0b6` (both match their `.sha256`). Dry signing of both MSIs with a throwaway Ed25519 key (Step 3): the signature verifies ("not an embedded key"), nothing uploaded.
  - Step 3 is the maintainer's: 73 items of the "WinVPN 2a" checklist section are still unchecked.

- [ ] **Step 3: Windows, manual** (the maintainer, as administrator for the install)

Hand `dist/windows/WinVPN-<version>-x64.msi` and the "WinVPN 2a" section of `docs/manual-test-checklist.md` to the maintainer; every unchecked item is a finding with its fix task. Also a dry signing: `scripts/sign-release.sh --dry-run --msi dist/windows/WinVPN-<version>-x64.msi --arch x64 --backup-key <throwaway.pem> v<version>` → the signature verifies with the throwaway key.

- [ ] **Step 4: Record**

Tick the plan's checkboxes for the tasks done; commit `docs(plan): 2a verified` with the results (which checks, which machine, Windows build number, the checklist outcome) in the body.

  *Smoke (2026-10-22, at 38bc107, display unlocked):* `SMOKE_LANG=en` and `SMOKE_LANG=hu scripts/smoke-manage.sh` both passed on the first run (the earlier failures were only the locked display).

## Task 20: independent review

**Goal:** a reviewer who did not write the code checks the security-relevant parts before 2b builds on them.


  *Review input from Task 5 (2026-10-21):* a symlink **inside** the import folder that points to a UNC target is still followed by `canonicalize` (the text containment check then sees the `\\?\UNC\…` result as outside, but the SMB connection, and so NTLM, has already happened during canonicalization). macOS has the analogous gap for symlinks to network mounts. Creating such a symlink on Windows needs `SeCreateSymbolicLinkPrivilege` or Developer Mode. Decide: refuse any reparse point in the reference chain before canonicalizing, or accept and document.


  *Review input from Task 11 (2026-10-21):* `crates/core/src/vault/db.rs` now runs `PRAGMA cipher_log = device` once per process (`route_sqlcipher_log`) to stop a stack overflow on Windows (SQLCipher's stderr warning about a failed `VirtualLock` allocated and failed again, recursively). Verify that on macOS this is exactly SQLCipher's default (no log target change, no secret ever logged), and that `cipher_memory_security` stays on.


  *Review input from Task 16 (2026-10-21):* on Windows `control_server::pipe::a_silent_client_is_closed_after_the_auth_timeout` failed once (elapsed < 300 ms, control_server.rs:744) and passed 5 reruns: a timing flake (Windows timer resolution / timeout rounding?). Make it deterministic or widen the lower bound with a justification.

- [ ] **Step 1: Request it** (superpowers:requesting-code-review), with this focus list:
  - `crates/winsys`: every `unsafe` block's soundness note; the OVERLAPPED lifetimes (no free before completion; cancellation waited for); `RevertToSelf` failure aborts; handle ownership (`OwnedHandle` everywhere, no double close); the `Send`/`Sync` impls of `Listener`.
  - The DACL shapes: `Private` exactly user + SYSTEM, protected, owner set explicitly; `has_access` fails closed on anything else (inherited ACEs, a deny ACE, an extra allow).
  - `fsx` on Windows: reparse policy (name surrogates refused, placeholders reopened and compared by 128-bit id), `ensure_private_dir` on a junction and on another user's directory, `hard_links` fail-closed, the shred path.
  - The control pipe: first-instance bind, squatting (another user creating the name first), remote rejection, NETWORK deny, identification-level impersonation, `same_user` from the token (not the PID), the example client's server-user check.
  - The forwarding pipe: same-user peers only, 64 KiB cap, absolute paths only, the Mark-of-the-Web path still applied.
  - Credential Manager: blob zeroized, never logged, `LOCAL_MACHINE` persistence, sandbox isolation.
  - The clipboard formats; toasts never carry a secret (grep every `notifier().post` call's arguments).
  - The update signature domains (`message_for` refuses any asset name but the two exact ones) and `sign-release.sh`'s asset handling (both MSIs or neither).
  - The importer on Windows: `\\?\` canonical containment, UNC and drive-relative paths, alternate data streams.
  - The MSI gates: what they prove and what they cannot (no Authenticode yet).
  - MacVPN unchanged: the call-site table of Task 4, the popover formula of Task 14, the menu, the tray icons.
- [x] **Step 2:** fix each finding in its own commit (with a test where it is code), rerun Task 19 Steps 1–2, and record the review result and the fixes in a commit `docs(plan): 2a review` (body: the findings and their commits).
  *Fixed (2026-10-21, branch `a2-fix4`), one commit each, `fix: review findings – …`:* **M1** (a symlink or junction inside the import folder pointing at a UNC path leaked NTLM while canonicalizing): `fsx::canonicalize_reference` refuses on Windows a reference not lexically below the folder before any file system call, then refuses every name-surrogate reparse point below the folder (whatever its target), then canonicalizes and checks the result for a stream (I2); macOS keeps following (accepted, docs/architecture.md); this also settles the Task 5 review input. **L1** OWNER RIGHTS (`READ_CONTROL`) ACE after the pipes' NETWORK deny (the test machine already denied WRITE_DAC to the owner's network logon without it: defence in depth). **L2** one total 2 s deadline per forwarded message. **L3** the single-instance mutex has a private DACL; a foreign-owned or unopenable one is "squatted", not "running"; every claim failure shows a localized message box (EN/HU). **L4** `build-msi.sh` checks the WiX tools before `tauri build` when they exist (`--check-tools`, `scripts/test-build-msi.sh`). **I1** the squatter wording (it can identify the client, never act as it or receive data). **I3** the clipboard's owner is the main thread's message window. **I4** the Windows guide's pagefile note. **I6** folders open with the `explore` verb (`ShellExecuteExW`, no error UI). **I7** the 2b updater note in the resolved point on the signature domain. **I8** `ConnectNamedPipe`'s ERROR_NO_DATA is taken back on the same instance. **I9** `check-ignored.sh` covers `-p macvpn-app` and every OS-specific ignore form (`scripts/test-check-ignored.sh`). **I10** the `cipher_log` pragma's status row must be `"0"` (the Task 11 input: on macOS `device` is SQLCipher's default target, `cipher_memory_security` stays on). The Task 16 timing flake was not part of this round. Verified: every Mac gate (fmt, clippy, tests debug and release, check-windows, check-ignored, compat_1_4, cfg_rule, l10n, bash -n, the script tests, the UI) and on Windows the test set with `-p macvpn-app` (1679 passed, 0 failed, 3 ignored everywhere), Windows clippy, `check-ignored.sh`, and the x64 MSI (SHA-256 `e4486083360d78002895ff31a47ba2d91332596be26c021d017b186f1e0056b8`). The macOS smoke could not run: the Mac's display was locked, and it stopped the same way on the base commit.

---

## Spec coverage (self-review)

| Spec / brief | Requirement | Task |
|---|---|---|
| Blocker M1 | MacVPN `macvpn-update-v1` byte for byte; WinVPN domain with the asset; sign-release signs each asset with its product's message; cross-product and cross-arch rejection tested | 2 |
| Blocker (importer) | `Path` joins, `\\?\` containment, macOS byte-for-byte; the 24 importer ignores removed | 5 |
| Spec 3 (fsx), brief 2 | private files/dirs through ACLs (user + SYSTEM, justified), `owner`/`has_access`/`ensure_private_dir`/`create_private_dir_all`, real link count and file id, reparse policy incl. OneDrive, unsafe placement justified, cfg_rule allow-lists | 3, 4, 8 |
| Brief 2 | the `private files` ignores and the two shred ignores removed; ignored count = tests ignored on every OS (CI gate) | 8, 11 |
| Spec 4.3 (vault key), brief 4 | Credential Manager generic credential (DPAPI, current user); entropy via `BCryptGenRandom`; legacy keychain empty; sandbox in memory | 3, 9 |
| Spec 4.3 (control transport), brief 5 | named pipe per user SID, DACL user + SYSTEM (+ NETWORK deny), `PIPE_REJECT_REMOTE_CLIENTS`, token SID + image path, example client's Windows transport, tests on Windows | 6, 10 |
| Spec 4.3 (tray, window presence) | notification-area icon, borderless rounded popover, taskbar presence | 12, 14 |
| Spec 4.3 (notifications) | toasts with an AppUserModelID | 12, 16 (shortcut gate) |
| Spec 4.3 (file panels) | `IFileOpenDialog` / `IFileSaveDialog` | 12 |
| Spec 4.3 (clipboard) | the three exclusion formats | 12 |
| Spec 4.3 (download mark) | Mark of the Web | 9 |
| Spec 4.3 (file associations) | `.ovpn`, `.sstp`, `.macvpncatalog` default; `.conf` Open with only; single instance | 13, 14 |
| Spec 4.3 (quit and logout) | `WM_QUERYENDSESSION` / end session | 13 |
| Spec 4.3 (launch at login) | per-user Run key | 13 |
| Brief 6 | `supported()` Ok, preferences store (decided: JSON file), data dir `%LOCALAPPDATA%\WinVPN`, System Status engine note, window chrome via DWM | 7, 9, 14 |
| Spec 6 | Windows fonts; Ctrl shortcuts (phase 1); per-OS texts | 14, 15 |
| Spec 7, brief 7 | WiX MSIs x64 + ARM64; build script with gates (no smoke markers, SQLCipher provider on Windows, notices, MSI contents); CI artifacts; release workflow; Authenticode present but off | 16, 17 |
| Spec 7 | the `wireguard.dll` gate | 2b (WireGuard arrives there) |
| Spec 8, brief 8 | unit tests on Windows; the Windows machine over SSH as a standard user; sync and run; smoke run decided | 1, 11; smoke deferred (Resolved points) |
| Spec 8 | helper protocol tests on Windows, service harness | 2b |
| Brief 9 | user guide variants, README/architecture, Hungarian manual checklist | 18 |
| Spec 9 (phase 2) | service, OpenVPN, WireGuard (2b); native RAS VPNs (2c); release 2.0.0 after review | out of 2a scope by the maintainer's split |
| Constraints | MacVPN unchanged (compat, bundle, l10n, test-root); cfg/unsafe rule; no new crate in macOS binaries; exact pins and notices; no secret logged; fail closed | Rules, 3, 16, 19, 20 |
