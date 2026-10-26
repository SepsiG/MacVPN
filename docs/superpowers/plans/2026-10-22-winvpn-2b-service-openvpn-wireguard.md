# WinVPN phase 2b – the WinVPN Service, OpenVPN and WireGuard: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. The spec is `docs/superpowers/specs/2026-10-20-cross-platform-winvpn-design.md` (sections 4.1, 4.3, 4.4, 5, 7, 8, 9). Every earlier spec (vault, control API, team catalog) and every rule and "As built" note of the 2a plan (`docs/superpowers/plans/2026-10-21-winvpn-2a-foundations.md`) still applies. Where this plan and the spec disagree, the spec wins, except where "Resolved points" below says why the plan deviates. Follow the existing patterns of the crate you work in (read a neighbouring module first). The 2a plan is the reference for rigor and style.

**Goal:** an unsigned WinVPN MSI (x64 and ARM64) whose WinVPN Service (LocalSystem, `\\.\pipe\WinVPN`) connects OpenVPN (OpenVPN Community 2.7 with the DCO and TAP-Windows6 drivers, installed from System Status; the service picks the driver per connection) and WireGuard (the bundled wireguard-nt), with MFA prompts and the live log as on macOS; System Status shows the service, OpenVPN and WireGuard rows; WinVPN updates itself from signed MSIs, subscribes to HTTPS team catalogs, and has a Windows smoke run. Native RAS VPNs (L2TP, Cisco IPsec, IKEv2, SSTP, strongSwan translated) stay on a "later" answer (2c). MacVPN behaviour stays exactly as in 1.5.0.

**Architecture:** the service is the existing helper crate (`crates/helper`, binary `mvpn`) with a real `windows` backend: its request handling (the root layer's CLI, framing, validation, masking, status JSON and management bridge from `shared`) is pure and tested on every OS (`src/windows/*.rs`); everything that calls Win32 (the service control dispatcher, the pipe server, `openvpn.exe` in a job object, wireguard-nt, IP Helper) is under `src/windows/sys/` behind `cfg(windows)`. The app and the service speak one length-delimited envelope (`macvpn_core::service_proto`) around the root layer 8 frame. New Win32 calls the service and the app both need (the service pipe's DACL and its client trust, Authenticode, file versions, admin-only paths, safe DLL loading) go into `macvpn-winsys`. The app side is `platform-win`'s `ServiceClient` behind the existing `HelperClient` trait.

**Tech Stack:** Rust 1.99.1 (pinned), edition 2024, Tauri 2.12 (WiX 3 MSI), `windows-sys =0.61.2` / `windows =0.62.2` (already in `Cargo.lock`: only new *features*, no new crate), wireguard-nt 1.1 (`wireguard.dll`, prebuilt and signed by WireGuard LLC; decision 6, amended 2026-10-22 from 0.10.1), OpenVPN Community 2.6.x (DCO), Windows' own `curl.exe` (System32), Svelte + TS, bash (Git Bash on Windows), Node 26.8.2.

---

## Decisions of the maintainer (2026-10-22)

1. **Updates: a UAC prompt from the app** runs `msiexec` (`ShellExecuteExW` with `runas` on `%SystemRoot%\System32\msiexec.exe`; a standard user needs an administrator's credentials, as for the first install). The service never installs WinVPN updates. Task 18.
2. **Logoff: the service takes down the connections of a user whose session logs off** (`SERVICE_CONTROL_SESSIONCHANGE` / `WTS_SESSION_LOGOFF`); locking the screen or switching users keeps them. Task 12.
3. **`cryptoapicert` is refused on Windows** in 2b: `openvpn.exe` runs as SYSTEM, so a certificate selector would reach the computer's certificate store, not the user's (a user could make the service sign with the machine's key). A per-user signing bridge (management-external-key) may come later. Task 2.
4. **OpenVPN Community is installed with its two data-channel drivers** *(amended 2026-10-22; the original read "all three data-channel drivers: DCO, TAP-Windows6 and Wintun" with OpenVPN 2.6)*: **OpenVPN Community 2.7.8** (the current release; the maintainer chose it over 2.6.23), `openvpn.exe` with its libraries, the **DCO** and **TAP-Windows6** drivers; **no Wintun** (OpenVPN 2.7 removed it), **no** OpenVPN GUI and **no** `OpenVPN.Service` feature; OpenVPN's **Interactive Service is disabled** when WinVPN installs OpenVPN (below). So configurations DCO cannot run (compression, non-AEAD ciphers, `fragment`, static keys, proxies, `dev tap`) still connect, over TAP-Windows6: the service chooses the driver per connection from the validated configuration (Task 10, `ovpn_args::choose_driver`), never from a `windows-driver` directive (which stays forbidden; OpenVPN 2.7 ignores it anyway). Through winget first (with the same `ADDLOCAL` via `--override`, falling back to the pinned MSI when the drivers are not both there afterwards), the pinned MSI otherwise. An existing OpenVPN installation is used as it is (a missing driver is offered as "Repair"; a Wintun driver an older installation brought is neither used nor reported); uninstalling WinVPN leaves OpenVPN and its drivers installed. Tasks 2, 10, 13, 16, 17, 21, 22.
   **Amended 2026-10-24 (the maintainer: "always run the newest OpenVPN, and if there is an update, it can be updated"):** winget installs and updates to the newest OpenVPN in winget (at CP2 that was 2.7.7, below the 2.7.8 pin: wanted); nothing on the winget path names a version. The pinned MSI is the fallback without winget (and when winget left a driver missing, never as a downgrade of a newer installation), and its pin is raised to the newest OpenVPN at each WinVPN release (`docs/RELEASING.md`). System Status offers "Update" on the green row with the newest of winget's offer (asked read-only) and the pin: the pinned MSI when it is newer than both the installed version and winget's offer (or winget has nothing or does not answer), winget when its offer is at least the pin's version (coordinator, 2026-10-24). The service's checks (signer, admin-only path, `min_version` 2.6.0) are unchanged: any signed version from 2.6.0 on is used. Task 17's "As built (fix3)".
   **Amended again 2026-10-24 (fix4; the maintainer: "nem akarok mindig új kiadást csinálni, ha frissülnek a vpnek" — the engines must always be the newest, without a new WinVPN release):** the second candidate of "Update" is no longer the pin but **the newest official OpenVPN Community MSI found at runtime** on OpenVPN's download page (`https://openvpn.net/community-downloads/`, fetched from `openvpn.net` only; MSIs from `swupdate.openvpn.org`/`.net` only), verified by HTTPS and its Authenticode signer `OpenVPN Inc.` (checked by the app, and again by the elevated step, which also requires an official MSI name of this machine not older than the pin); the GnuPG `.asc` is not checked at runtime (no OpenPGP/RSA code in the workspace; Task 17's "As built (fix4)"). The pinned 2.7.8 MSI stays the **minimum and the offline/bootstrap fallback** (a page that cannot be read or names nothing newer = the pin, never an error row; for the pin's own version the hash-pinned MSI is used); the pin need not be raised at each release any more (`docs/RELEASING.md`). Never a downgrade.
   **Effect of the amendment** (the task texts below are updated; where one still says otherwise, this wins): the pins are 2.7.8-I001 with `ADDLOCAL=OpenVPN,Drivers,Drivers.OvpnDco,Drivers.TAPWindows6` on both architectures (Task 10's "Re-pinned" note); `Driver` has two variants and the argv selects TAP-Windows6 with `--disable-dco` instead of `--windows-driver` (2.7 ignores that option); `OpenVpnFacts` has no `wintun` field. **Task 13:** the facts list DCO and TAP-Windows6 only (registry keys `ovpn-dco`, `tap0901`); the one retry after a DCO incompatibility uses TAP-Windows6; there is no Wintun mapping. **Task 15 (and CP1):** the MSI is unchanged; the maintainer installs the 2.7.8 MSI by hand with the two-driver `ADDLOCAL`, and CP1's driver configs are DCO and TAP-Windows6 (a config DCO cannot run gets TAP-Windows6 too). **Task 16:** the OpenVPN row lists DCO and TAP-Windows6 only. **Task 17:** the feature lists, the "every driver" check after winget and the "add the drivers" message name DCO and TAP-Windows6 only. **Task 21:** `ci-install-openvpn.sh` checks the `ovpn-dco` and `tap0901` driver services; the CI end-to-end test's second connection is a TAP-Windows6 one (`admin_a_tap_windows6_connection_comes_up_through_the_service`: a non-AEAD cipher → `--disable-dco`). **Task 22:** the guide and the "WinVPN 2b" checklist name DCO and TAP-Windows6 only (`pnputil /enum-drivers`: ovpn-dco, tap0901).
   **The OpenVPN Interactive Service (amended 2026-10-22):** `OpenVPNServiceInteractive` (`openvpnserv.exe`) is a component of the core `OpenVPN` feature itself, so `ADDLOCAL` cannot leave it out, and the MSI installs it with start type automatic and starts it. WinVPN does not use it (the WinVPN Service runs `openvpn.exe` as SYSTEM itself), and it is a second SYSTEM service with a pipe every local user can open that makes privileged network changes for OpenVPN processes: surface WinVPN does not need. So **after an OpenVPN install or update that WinVPN started** (Task 17, either path), WinVPN sets that service to **disabled** and **stops** it, in the same elevated step as the install where possible (one UAC confirmation), then **checks** it (`QueryServiceConfigW`: start type `SERVICE_DISABLED`; `QueryServiceStatus`: `SERVICE_STOPPED`; a failed check is a precise message in System Status' output, not silence). WinVPN **never touches it on an OpenVPN installation it did not make** (installed before, by hand or by another tool: that user may use the OpenVPN GUI, which needs it): WinVPN records its own install in an admin-only machine value written by the elevated step (`HKLM\SOFTWARE\WinVPN`, `OpenVpnInstalledByWinVpn` = 1) and repeats the disabling only after its own later updates and repairs of that installation (an MSI upgrade re-registers the service as automatic). The service name is pinned (`interactive_service` in `scripts/pins/openvpn.txt`, `OPENVPN_INTERACTIVE_SERVICE`). Tasks 10, 17, 21, 22.
5. **ARM64: built, gated and shipped untested on hardware**, as in 2a (the ARM64 MSI carries the ARM64 service and the ARM64 `wireguard.dll`; the checklist marks it "nem tesztelt" until an ARM64 machine exists). Tasks 15, 23.
6. **wireguard-nt 1.1** *(2026-10-22, during Task 14)*: WinVPN bundles the official wireguard-nt **1.1** (`wireguard-nt-1.1.zip`, the release the official WireGuard for Windows pins since 2026-05-07), not 0.10.1. Where a task text below still says 0.10.1, 1.1 wins: the pins are in `scripts/pins/wireguard-nt.txt`; 1.1's `WIREGUARD_ALLOWED_IP` has a `Flags` field (offset 20, in 0.10.1's padding; WinVPN always writes 0 = add) and `WIREGUARD_PEER_UPDATE` is named `WIREGUARD_PEER_UPDATE_ONLY` (never set); the sizes 80/136/24 and the API are unchanged. The service reports the DLL's file version (`1.1.0`). Task 14.
   **Amended 2026-10-24 (fix4; the maintainer's choice: engine updates without a WinVPN release, runtime updating of wireguard-nt rather than release-bundled updates):** the **WinVPN Service** updates wireguard-nt itself at runtime: on the app's request ("check" / "update", nothing else of the request is used) it reads the official listing `https://download.wireguard.com/wireguard-nt/`, downloads the newest `wireguard-nt-<v>.zip` with System32's curl into its admin-only `C:\ProgramData\WinVPN\engines\wireguard-nt\`, takes only `bin\<arch>\wireguard.dll` out of it and keeps it only when its Authenticode signature is Valid with signer `WireGuard LLC`, it is a DLL for this machine and its version is above every version the service has; it is applied only while no WireGuard connection is up. At engine start and after an update the service loads the highest valid version of {the bundled DLL, its download}, re-checking the signer at every load; the bundled DLL (still pinned by SHA-256) is the minimum and the fallback. **Trust trade-off, accepted by the maintainer:** a downloaded DLL is trusted on its publisher's Authenticode signature (WireGuard LLC, through the Windows root store) instead of a hash pinned by a WinVPN release; upstream publishes no signature or manifest for the SDK zips (checked 2026-10-24), so there is nothing stronger to check. Task 17's "As built (fix4)" (with the threat notes for Task 24).

---

**Test strategy from 2026-10-22 (the maintainer's decision, overrides the per-task gate lists below):** each task runs only the tests of the crates it touches (`cargo test -p <crate> [--test <name>]`) and clippy on those crates, without a `--release` test run; on Windows only its own test binaries (`scripts/win-remote.sh run '…'`). The coordinator runs the full gate (workspace debug + release, `scripts/test-root.sh`, the full Windows set, the check scripts) once per wave on the merged tip. VM remote dirs are persistent warm slots (`winvpn-work-slot1..3`), not deleted after each task. The macOS smoke runs only with the maintainer's OK.

**Rules for every task** (the 2a rules, plus the service's):
- TDD: write the failing test first. For a pure refactor the "failing test" is an existing test that must stay green (name it in the commit message body). Windows tests are written on the Mac, compile-checked with `scripts/check-windows.sh`, and run on the Windows machine with `scripts/win-remote.sh` (as the standard user `winvpn-dev`); the step says which.
- Before each commit, on the Mac: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`, `CI=1 cargo test --workspace --locked`, `scripts/check-windows.sh`, `scripts/check-ignored.sh`. For UI work also `cd app/ui && npm test && npm run build`. If a task touches `crates/helper`, also `MVPN_IMPL=rust scripts/test-root.sh` (the macOS root layer must not change).
- Before each commit of a task that touches Windows code: `scripts/win-remote.sh test` and `scripts/win-remote.sh run 'cargo clippy --workspace --all-targets --locked --target x86_64-pc-windows-msvc -- -D warnings'`. At most **3** tasks build on the Windows machine at the same time (about 30 GB free; each checkout's `target/` takes 6–8 GB): each worktree uses its own `WINVPN_REMOTE_DIR=winvpn-work-<task>`, deleted (`scripts/win-remote.sh run 'cd ~ && rm -rf winvpn-work-<task>'` from another checkout) when the task is merged.
- **MacVPN unchanged:** every 2a baseline stays green without edits: `cargo test -p macvpn-app-core --test compat_1_4`, `node scripts/l10n-baseline.mjs --check`, `app/src-tauri/tests/tauri_config.rs`, `MVPN_IMPL=rust scripts/test-root.sh`, `node scripts/third-party-notices.mjs --check`, the four `cargo tree` lines of the 2a rules (no `openssl-sys`, no `windows*` / `macvpn-winsys` in `macvpn-app` or `macvpn-helper` for the two macOS targets), and (Task 23) `scripts/bundle-baseline.sh dist/MacVPN.app`.
- **The cfg/unsafe rule** (`crates/app-core/tests/cfg_rule.rs`) is unchanged: the helper's Windows code lives in `crates/helper/src/windows/` (already an allowed place for OS `cfg`; `unsafe` is allowed in `crates/helper/`). `crates/helper/src/shared/` keeps no `cfg`, no `unsafe` and no I/O. No task edits the allow-lists.
- **Dependencies:** no new crate in `Cargo.lock`. Windows-only dependencies are `[target.'cfg(windows)'.dependencies]` entries pinned exactly (`windows-sys = "=0.61.2"`; new *features* of it are fine). The helper never gets the `vault` feature of core (the `scripts/build-msi.sh` gate of Task 15 checks the service binary links no SQLite).
- **The service is a privileged attack surface.** Every rule here is checked by the review (Task 24):
  - **Fail closed:** a check that cannot be completed (a token, an owner, a DACL, a signature, a hash, a registry value that cannot be read) refuses the operation; never a default.
  - **Caller identity per request:** the caller's SID comes from the pipe (identification-level impersonation), never from the request bytes or the client's PID. A connection belongs to the SID that brought it up; only that SID can take it down, answer its MFA prompt, read its log or see it in `status`.
  - **No command injection:** no shell, ever (`cmd.exe`, PowerShell, `ShellExecute` with a document); every child process is started by its absolute path with an argv built only from validated values (UUIDs, validator-checked configs written to files, numbers). `std::process::Command` on Windows quotes each argument itself; no argument is built by string concatenation of user text.
  - **No path traversal:** the service writes only below its data directory (`C:\ProgramData\WinVPN`), only to names it builds from a UUID, and opens nothing a request names. It never follows a reparse point in its data directory.
  - **Secrets** (passwords, PSKs, key passwords, OTPs, private keys, the management password, a config's content) live only in memory, in the pipe, and in the SYSTEM-only run directory where the root layer kept them on macOS (the config file `openvpn.exe` reads); they are `Zeroizing`, never logged (every log line goes through `Masker` and `log_safe`), never in argv, env, the Event Log or a window title.
  - **DLLs** load only from the install directory or System32: the service calls `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` and `SetDllDirectoryW("")` first thing, and loads `wireguard.dll` by its absolute path with `LoadLibraryExW(…, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32)` after checking its SHA-256 against the build-time pin.
  - **Every downloaded or bundled binary is pinned** *(amended 2026-10-24, fix4: a `wireguard.dll` the service downloads itself and a newest official OpenVPN MSI are trusted on their Authenticode signer, not a pin — decisions 4 and 6 as amended)*: `wireguard.dll` by SHA-256 and Authenticode signer at build time and by SHA-256 at load time; the OpenVPN MSI by SHA-256 and Authenticode signer before it runs; `openvpn.exe` by Authenticode signer and an admin-only path before every start; WinVPN MSIs by the Ed25519 update signature (`verify_trusted_for`).
- **Admin-only and desktop-only steps:** the Windows machine is reached over SSH as the standard user `winvpn-dev`: no desktop, no Credential Manager session, no UAC, no service install, no driver. Such code is designed so that as much as possible runs as a standard user (pure logic on every OS; the service's request handling in a debug-only console mode over a test pipe; read-only Win32 calls), and the rest is (a) an admin test set marked `#[ignore = "admin: …"]`, listed in `scripts/ignored-everywhere.txt`, run by CI's `windows-admin` job (GitHub's runners are administrators, Task 21) and by the maintainer in an elevated Git Bash, and (b) a precise Hungarian checklist item in the "WinVPN 2b" section of `docs/manual-test-checklist.md` (Task 22). A task that changes user-visible behaviour ends its wave with a fresh MSI for the maintainer's checkpoint.
- **GitHub CI** Windows jobs (`windows`, `windows-node`, `msi`, from Task 21 `windows-admin`) run only on a temporary squashed branch the maintainer approves each time; nothing in this plan pushes.
- Serialized formats are frozen (vault, backup, export, catalog, view-model JSON, IPC payloads). New view-model fields are `#[serde(skip_serializing_if = …)]` and absent on macOS, so the compat fixtures stay byte-identical. The pipe protocol (Task 1) is new and versioned (`SERVICE_VERSION`).
- Every new user-facing string goes into `crates/core/l10n/strings.json` in EN and HU with the right `scope`; Windows-only texts have `"only": ["windows"]`. Tasks that add strings only add entries (merge conflicts: keep both, sorted).
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Never push. The maintainer's forbidden company name never enters the repo (use "Office VPN", "Acme VPN", `vpn.example.com`); the Windows machine's address never enters the repo (`WINVPN_SSH` only).
- Never touch the real Keychain or `~/Library/Application Support/MacVPN` on the Mac. Tests on Windows use their own temp directories, pipe names `WinVPN-test-<uuid>`, adapter names `WinVPN-test-<8 hex>`, and delete what they create.

**Parallel execution.** As in 2a: tasks of one wave touch disjoint files except where a task says "shared with"; each runs in its own worktree from the previous wave's merged tip; merge in task order; a wave is done when the merged tip passes every check above on the Mac and `scripts/win-remote.sh test` on Windows. Shared files: `crates/core/l10n/strings.json` (entries only); `crates/helper/Cargo.toml` (Tasks 12–14 each add their own `windows-sys` features: keep the union, sorted); `crates/helper/src/windows/sys/mod.rs` (Tasks 13 and 14 each add one `mod` line and one line in `engines()`); `crates/winsys/Cargo.toml` (Tasks 3 and 4: union of features); `scripts/ignored-everywhere.txt` (entries only, sorted).

| Wave | Tasks (∥ = parallel) | Needs | Maintainer checkpoint |
|---|---|---|---|
| 0 | 1 the service protocol ∥ 2 the Windows validator tiers ∥ 3 `winsys`: the service pipe ∥ 4 `winsys`: Authenticode, versions, admin-only paths, DLLs ∥ 5 the portable curl layer ∥ 6 `LogSource` ∥ 7 helper shared moves | – (3, 4 run on Windows) | – |
| 1 | 8 the service core (pure) ∥ 9 WireGuard, pure parts ∥ 10 OpenVPN, pure parts ∥ 11 System Status engine rows | 8: 1, 7; 9: 2; 10: 2; 11: 1 | – |
| 2 | 12 the service host ∥ 13 the OpenVPN engine ∥ 14 the WireGuard engine | 12: 3, 8; 13: 4, 7, 8, 10; 14: 4, 8, 9 | – |
| 3 | 15 the MSI with the service ∥ 16 the app's service client | 15: 12, 13, 14; 16: 1, 6, 11, 12 | **CP1**: MSI with the service, OpenVPN installed by hand, connect OpenVPN and WireGuard, admin test set |
| 4 | 17 OpenVPN install from System Status ∥ 18 the Windows updater ∥ 19 HTTPS catalogs and the update check | 17: 4, 10, 16; 18: 5, 15, 16; 19: 5 | **CP2**: one-click OpenVPN install, update to a newer MSI, HTTPS catalog |
| 5 | 20 the Windows smoke run ∥ 21 CI and release (with the `windows-admin` job) | 20: 16–19; 21: 15, 20 | – |
| 6 | 22 documentation and the "WinVPN 2b" checklist → 23 verification → 24 independent security review | 22: all; 23: 22; 24: 23 | **CP3**: the full "WinVPN 2b" checklist on the final MSI |

**Key facts from the current code (read before starting):**
- **Helper** (`crates/helper`, package `macvpn-helper`, binary `mvpn`, `crates/helper/VERSION` = 8): `src/shared/` = `cli` (`Args::parse`, `is_uuid`, `is_kind` – `openvpn|wireguard|strongswan|sstp`, `is_valid_risky_list`), `framing` (`parse_framed(data, secrets) -> Result<(Zeroizing<Vec<u8>>, Secrets), FrameError>`, `read_framed`, `Secrets { user, pass, psk, keypass, otp, packed }`, `Secrets::masker()`), `limits` (`SRC_MAX` 1 MiB, `SECRETS_MAX` 64 KiB, `STDIN_MAX`), `mask` (`Masker::{new, add, line, text, stream_lines}`, `mask::lines`), `respond::parse(body)`, `status_json::{StatusLine, render}`, `validate::{issues, risky_set, run}`, `bridge::{BridgeArgs, BridgeFiles, Bridge}` (the bridge uses only `id` and `max_wait` of `BridgeArgs`; `Bridge::run` expects the stream to time out reads every ~250 ms), `l10n::tr`. `src/macos/log.rs` has the OpenVPN log predicates (`log_safe`, `ovpn_real_lines`, `ovpn_done`, the `DONE`/`ECHO`/`AUTH_NOT_FINAL` regexes). `src/windows/mod.rs` prints "Not available on this system yet" and exits 1; `src/main.rs` calls it on Windows and Linux. `lib.rs` has `pub mod macos; pub mod shared; pub mod windows;` and a test that every `tr("…")` key has a Hungarian translation.
- **core:** `l10n::with_language(lang, f)` (a thread override: the service handles requests on several threads), `l10n::tr`, `status::{RootStatus, parse_status}` (states `connected` / `connecting` / anything else = failed), `mfa::AuthUIState::parse(&[u8])`, `management::{ManagementCredentials { username, password, packed }, ManagementResponse::parse}`, `log::{LogTailer, LogLine, INITIAL_WINDOW = 256 KiB, MAX_READ_BYTES = 1 MiB, MAX_PARTIAL_BYTES}`, `update::{UpdateSignature::verify_trusted_for(domain, asset, version, sha256, sig), SignatureDomain::WinVpnV1, UpdateURLPolicy, parse_checksum, sha256_of_file}`, `validators::openvpn::{platform_reasons, PLATFORM_WINDOWS (draft), WINDOWS_ARGUMENT_SPECS (cryptoapicert), FORBIDDEN, OpenVPNValidator::tier_for(os, d)}`, `validators::wireguard::{INTERFACE_KEYS (incl. fwmark, table), PEER_KEYS}`, `TargetOs::host()`.
- **platform-api:** `HelperClient { status, up, down, respond, log_path (default None) }`, `AuthStateReader`, `SystemSetup { check, install_package_manager, install_tools(report, output), install_helper, uninstall_helper, helper_upgrade_notice, engine_note, system_uninstall_note, open_system_uninstall }`, `SetupReport { package_manager, required_tools, missing_tools, installed_root_version, bundled_root_version, sudo_works, missing_root_files, engine_missing }` with `is_complete`, `is_available(kind)`, `Updater { install, launch_housekeeping, cache_directory }`, `ReleaseSource`, `SystemInfo::{update_info, bundled_helper_dir, user_name}`.
- **platform-win:** `src/pure/` (portable; `texts::{engine_later, engine_note, …}`), `src/win/` (Windows); `not_yet::NoEngine` answers every VPN call; `platform.rs` returns `Inert` for the updater, release source, HTTPS catalog fetcher and log stream, `SystemSetup::check` returns `SetupReport { engine_missing: Some(engine_later), .. }`, `update_info` / `bundled_helper_dir` / `user_name` are `None`.
- **winsys:** `pipe::{Listener::{bind, bind_with}, NetworkLogons, connect (same-user server only), PipeStream, Peer, process_user, process_image}`, private `security::{Ace, Acl, Descriptor}`, `sid::Sid::{current_user, of_token, parse, local_system, network, owner_rights, builtin_users}`, `file::{info, dacl_entries (pub(crate)), kernel_object_owner (pub(crate)), …}`, `random::fill`, `mutex::create_private`. `connect` opens with `GENERIC_READ | GENERIC_WRITE`.
- **platform-mac's curl layer:** `http.rs` (`HttpClient`, `CurlHttpClient` with `/usr/bin/curl`, `base_arguments`, `parse_trailer`, the redirect loop, `canonical_redirect_url`, `with_private_directory`) and `catalog_http.rs` (`CurlCatalogFetcher`: conditional GET, `--dump-header`, the bearer token on stdin via `--config -`, `--max-filesize`), over `command::CommandRunner { run, run_bytes }`.
- **app:** `app/src-tauri/src/manage.rs::log_subscribe` builds `LogFeed::new(&c, helper_client().log_path(&c.id).unwrap_or_default(), …)`; `state.rs` builds the setup view with `.with_engine_note(setup().engine_note())`; `app/ui/src/lib/Setup.svelte` renders `homebrew`, `tools`, `root` rows or `engineNote`.
- **MSI:** `scripts/build-msi.sh` (gates, `--config` JSON overrides to `tauri build`, `dark.exe -x` contents vs `scripts/bundle-baseline/winvpn-msi-files.txt`, `scripts/msi-query.ps1` for tables, `WINVPN_WIX_NO_ICE=1` over SSH); `tauri.windows.conf.json` has `bundle.windows.wix.{upgradeCode, fragmentPaths: ["wix/file-associations.wxs"], componentRefs}`.

---

## Resolved points (where the spec leaves a choice open, and where this plan deviates)

- **The service is the helper crate's Windows backend.** Spec 3 says "Backends: `macos` … and `windows` (service: OpenVPN, wireguard-nt, DNS)". The binary stays `mvpn.exe` (one crate, one `[[bin]]`); the MSI installs it as `C:\Program Files\WinVPN\WinVPNService.exe` (WiX `File/@Name`), service name `WinVPN`, display name "WinVPN Service", `LocalSystem`, automatic start, command line `"…\WinVPNService.exe" service`. Its request handling reuses `shared` unchanged (CLI, framing, validation, masking, status JSON, the management bridge) — no second implementation of any rule.
- **The wire format is an envelope around the root layer 8 frame** (`macvpn_core::service_proto`). A pipe has no half-close, so the root layer's "stdin until EOF" cannot mark the end of the secrets: each request is `winvpn 1\n`, `args <n>\n`, `n` lines of one argument each (`[A-Za-z0-9,._=-]`, 1–4096 bytes, at most 16 arguments: the `mvpn` command line), `body <len>\n` and exactly `len` bytes (at most `STDIN_MAX`: the root layer 8 frame for `up`, the `respond` body, empty otherwise). The answer is `winvpn 1\n`, `exit <code>\n`, `stdout <len>\n<bytes>`, `stderr <len>\n<bytes>` (each at most 2 MiB). One request per pipe connection, like one `mvpn` process per call. Strict parsing (no leading zeros, no extra bytes), refused before the body is read when a length is too large. The body is read into one `Zeroizing` buffer allocated at its final size.
- **The commands** are the `mvpn` commands (`version`, `status`, `up`, `down`, `respond`) with the same arguments and exit codes, plus three that replace macOS' user-readable files: `auth-state <id>` (the bridge's `AuthUIState` JSON, which macOS writes to `/var/run/macvpn-ui/<id>.json`), `log <id> <offset>` (a slice of the connection's masked log, which macOS keeps in `/var/log/macvpn/<id>.log`), and `engine` (the service version, the data directory's state, OpenVPN's and WireGuard's facts as JSON for System Status). `validate` is not offered over the pipe (the app validates in process with the same core validators). `strongswan` and `sstp` answer "Not available on this system yet" (native RAS in 2c).
- **The service pipe** `\\.\pipe\WinVPN`: created by the service as SYSTEM with `FILE_FLAG_FIRST_PIPE_INSTANCE`, `PIPE_REJECT_REMOTE_CLIENTS`, owner `SYSTEM`, protected DACL: deny `NT AUTHORITY\NETWORK` (all), allow `SYSTEM` (all), allow `NT AUTHORITY\INTERACTIVE` `FILE_GENERIC_READ | FILE_WRITE_DATA` — **not** `FILE_APPEND_DATA` (= `FILE_CREATE_PIPE_INSTANCE`: a user could otherwise add a rogue instance of the service's own name) and not `WRITE_DAC`/`WRITE_OWNER`. Clients therefore open with `FILE_GENERIC_READ | FILE_WRITE_DATA` (not `GENERIC_WRITE`, which maps to `FILE_APPEND_DATA` and would be denied) and `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION`. **Client trust:** before sending a byte the client reads the pipe object's owner from its handle (`READ_CONTROL` is in `FILE_GENERIC_READ`) and refuses anything not owned by `S-1-5-18`. A standard user cannot create an object owned by SYSTEM (that needs `SeRestorePrivilege`), so a squatter that created `\\.\pipe\WinVPN` before the service never receives a config or a secret; the service, finding the name taken, retries every 5 s and logs it; the app says "The WinVPN Service is not reachable." (spec 4.1 names the DACL; the create-instance right, the client's access mask and the owner check are this plan's additions.)
- **The test-mode service.** `mvpn.exe console --pipe <name> --data <dir> [--fake-engine]` exists only in debug builds (`cfg(debug_assertions)`; the Task 15 gate checks the release binary has no `console` / `--fake-engine` strings) and only when the process is not LocalSystem: it runs the same request handler over a pipe owned by the current user (DACL: the user, SYSTEM, INTERACTIVE as above; network logons allowed so SSH tests reach it), with the data directory a private temp directory, and either the real engines (which fail without admin rights, tested as failures) or a fake engine (scripted states, a fake management server on loopback for MFA). Clients in tests trust a pipe owned by the current user (`ServerTrust::SameUser`). This is how `scripts/win-remote.sh test` covers the protocol, the framing, ownership, limits, status, MFA answers and logs as the standard user.
- **Caller identity and ownership.** The service reads each client's SID (`ImpersonateNamedPipeClient` + `OpenThreadToken` at identification level, `RevertToSelf` or abort: `winsys::pipe` as in 2a) once per connection. An `up` records `id → (SID, kind)`; `down`, `respond`, `auth-state` and `log` by another SID answer "Invalid ID" (the same text as an unknown ID: no oracle); `status` lists only the caller's connections; an `up` of an ID another SID owns is refused. Limits: 8 connections per SID, 32 in total, 8 requests in flight per SID (further connections wait for a pipe instance), 5 s to send a request. Ownership is in memory: the service's children are in a job object that kills them when the service stops, so nothing outlives it.
- **Logoff** (decision 2): the service registers for `SERVICE_ACCEPT_SESSIONCHANGE`; on `WTS_SESSION_LOGOFF` it takes down every connection whose owner SID has no other interactive session left (`WTSEnumerateSessionsW` + `WTSQueryUserToken` for each, compared by SID).
- **The data directory** `C:\ProgramData\WinVPN` (`FOLDERID_ProgramData`): `run\<id>\` (per connection: `config.ovpn`, `mgmt.pw`), `logs\<id>.log` (masked, rotated at 1 MiB), `service.log` (the service's own events, rotated at 1 MiB; never a secret). Any user can create folders in `C:\ProgramData`, so a user could create `WinVPN` before the service does: at start the service opens it without following reparse points and requires a real directory owned by SYSTEM or Administrators with a protected DACL granting exactly SYSTEM and Administrators full access (nothing else). If it does not exist, the service creates it with that descriptor. If it exists in any other shape the service does not repair it (it may already contain links planted by the squatter): it runs **degraded**, answering `version` and `engine` (with the problem: "The folder C:\ProgramData\WinVPN has unsafe permissions. An administrator must delete it, then restart the WinVPN Service.") and refusing `up` with the same text. Below it, every directory and file is created by the service with the same descriptor and opened with `FILE_FLAG_OPEN_REPARSE_POINT`, refusing name-surrogate reparse points (fail closed). Uninstall leaves the folder: Windows Installer runs as SYSTEM and would delete through a junction a user planted there, and the service removes its run directories at every stop, so only masked logs remain; the guide says how an administrator deletes it.
- **OpenVPN runs as SYSTEM, directly.** The service starts `openvpn.exe` itself (not through OpenVPN's Interactive Service), so OpenVPN sets its adapter's (DCO or TAP-Windows6) addresses, routes and DNS itself (it is privileged) — the service has no DNS hook for OpenVPN ("DNS on its own adapters": the only adapters whose DNS the service sets are its WireGuard adapters). The argv is fixed and built only from the run directory, a port number, the chosen driver and fixed words: exactly the list in Task 10 (`ovpn_args::argv`; no `--machine-readable-output`, which would change the log lines `log_safe` and `ovpn_done` were written for), with stdout/stderr piped to the service, which masks and writes them to the connection log and decides "connected" with the shared `ovpn_done` predicate (`Initialization Sequence Completed`), as on macOS.
- **The management interface is TCP on loopback** (OpenVPN on Windows has no Unix sockets). Any local process can connect to `127.0.0.1:<port>`, so: the port is chosen at random in 49152–65535 and checked free; a random 32-byte password (hex) is written to `<run>\mgmt.pw` (SYSTEM-only) and passed as the management password file; the service connects, then checks with `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_CONNECTIONS)` that the listening end of its connection is owned by the PID of the `openvpn.exe` it started (a process that bound the port first would otherwise receive the password and the user's credentials); only then does it send the password and hand the stream to the shared `Bridge`. Only one management client exists at a time, so a local process that connects first can only make the `up` fail (it cannot log in without the password). The credentials go to the bridge in memory (no `mgmt-creds` file: the bridge runs as a thread of the service).
- **OpenVPN's trust before every start:** `openvpn.exe`'s path comes from `HKLM\SOFTWARE\OpenVPN\exe_path` (64-bit view), must be absolute, must be admin-only writable (the file and every ancestor directory: owner SYSTEM, Administrators or TrustedInstaller; no allow ACE granting a write, delete, `WRITE_DAC` or `WRITE_OWNER` right to anyone else), must carry a valid Authenticode signature whose signer's simple name is the pinned `OPENVPN_SIGNER` (recorded in Task 10 from the pinned MSI's binaries with `Get-AuthenticodeSignature`), and its file version must be at least `OPENVPN_MIN` (2.6.0: DCO on Windows). A missing or failing check is a precise `engine` fact and refuses `up`. The two drivers are detected separately (each driver service's key under `HKLM\SYSTEM\CurrentControlSet\Services` — `ovpn-dco`, `tap0901` — present with `Start` ≠ 4, and the version of its `.sys` file); a connection whose chosen driver is missing is refused with "This connection needs the %@ driver. Repair OpenVPN Community in System Status." The drivers are kernel-mode code: Windows itself refuses to load one that is not signed for the kernel, so the service adds no signer check for them; what WinVPN installs is pinned through the MSI's SHA-256 (or winget's manifest hash).
- **The OpenVPN validator's Windows tier is stricter than the phase 1 draft.** The draft made `win-sys`, `service`, `msg-channel`, `allow-nonadmin`, `rdns-internal`, `dhcp-internal` RISKY (acknowledgeable). As SYSTEM, `win-sys <dir>` makes OpenVPN run `<dir>\system32\route.exe` / `netsh.exe` (code execution as SYSTEM for any user who acknowledges a warning), `msg-channel` / `service` hand OpenVPN an event or pipe handle, and `allow-nonadmin` changes a TAP adapter's permissions so any user could open it (TAP-Windows6 is installed now: decision 4). So on Windows these are **FORBIDDEN** (not acknowledgeable), with the reason "Set by the WinVPN Service itself, never by a configuration". `windows-driver` is FORBIDDEN on Windows too (the service chooses the driver); `cryptoapicert` is FORBIDDEN on Windows with "Certificates from the Windows certificate store are not supported by WinVPN" (decision 3); `setcon` stays refused (Linux only); `dev-node` stays FORBIDDEN on every OS (it would let a configuration pick an adapter by name, for example another user's TAP adapter). macOS and Linux tables are unchanged byte for byte (tests pin them).
- **What TAP-Windows6 makes work again (decision 4), and why each is acceptable.** Nothing new becomes SAFE in the validator: these directives are SAFE in the shared table already (as on macOS); with DCO alone they would only have failed at connect time. Now: `comp-lzo` / `compress` / `allow-compression` (compression; the shared tier keeps them SAFE as on macOS — the VORACLE risk of compressing before encryption is the server's configuration choice, the user guide names it) → TAP-Windows6; `cipher` / `data-ciphers` without an AEAD cipher (`AES-*-GCM`, `CHACHA20-POLY1305`) → TAP-Windows6; `fragment`, `http-proxy`, `socks-proxy` → TAP-Windows6; `secret` (a static key) → TAP-Windows6; `disable-dco` → TAP-Windows6; `dev tap` / `dev-type tap` / `dev tapN` → TAP-Windows6 (layer 2: DCO is layer 3 only). `tap-sleep`, `ip-win32`, `route-method`, `dhcp-*` stay SAFE (OpenVPN's own TAP handling). The choice is the service's (`ovpn_args::choose_driver` over the validated config), passed after the config as nothing (DCO, OpenVPN's default) or `--disable-dco` (TAP-Windows6; OpenVPN 2.7 ignores `--windows-driver`, amended 2026-10-22), never read from a directive.
- **DCO and pushed options.** A server can push an option DCO cannot run (compression, a non-AEAD cipher); the config does not show it. When a DCO attempt ends before `Initialization Sequence Completed` and its log has OpenVPN's DCO-incompatibility line (matched by `ovpn_log::dco_incompatible`, Task 10), the service retries the same `up` once with TAP-Windows6 and logs why; any other failure is not retried.
- **WireGuard on Windows** accepts the macOS key set except `FwMark` (no Windows equivalent: refused "Not supported on Windows") and `Table` (only `auto` and `off`; `off` = no routes). Endpoints with a host name are resolved by the service once at `up` (A and AAAA; the first address of the system's order), like `wg-quick`.
- **wireguard-nt.** *(Amended 2026-10-22, decision 6: 1.1 instead of 0.10.1.)* The official prebuilt `wireguard.dll` 0.10.1 (`wireguard-nt-0.10.1.zip` from `download.wireguard.com`), per architecture (`amd64`, `arm64`), pinned in `scripts/pins/wireguard-nt.txt` by the zip's SHA-256 and each DLL's SHA-256, checked at build time with the hash and the Authenticode signer (`WireGuard LLC`), and at load time by the service against the same SHA-256 compiled in (`build.rs` of the helper reads the pin file; a mismatch refuses WireGuard). The service is its only loader. Adapters are named `WinVPN-<first 8 hex of the id>`, tunnel type `WinVPN`, GUID derived from the connection ID (stable, so Windows does not accumulate network profiles). Addresses: `CreateUnicastIpAddressEntry`; routes: `CreateIpForwardEntry2` for each AllowedIPs prefix (unless `Table = off`); DNS: `SetInterfaceDnsSettings` (servers and search domains) on the adapter's GUID; interface metric 5 (so the tunnel's DNS wins); MTU (`SetIpInterfaceEntry`) when `MTU` is given. Closing the adapter handle deletes the adapter and with it its addresses, routes and DNS. wireguard-nt keeps the tunnel's own UDP traffic off the tunnel (the driver binds to the best route that is not its own interface), so `AllowedIPs = 0.0.0.0/0` needs no endpoint exclusion route; the manual checklist checks a full tunnel. No kill switch (parity with macOS' `wg-quick`).
- **The service version** is `macvpn_core::service_proto::SERVICE_VERSION` (1), separate from the macOS root layer's `VERSION` (8, unchanged). The service reports it (`version`, `engine`); the app compares it with the same constant: equal = ok; anything else (or no service) = the engine-missing state with "The WinVPN Service is missing or from another WinVPN version. Repair WinVPN: Settings → Apps → Installed apps → WinVPN → Modify → Repair." The MSI installs and upgrades both together, so a mismatch means a broken install.
- **The engine-missing state** (2a's `SetupReport::engine_missing`) is now set only when the service is absent, unreachable, from another version or degraded. Otherwise `SetupReport::engine` (new, `None` on macOS) carries the service, OpenVPN and WireGuard facts; `is_available(Openvpn)` needs a usable OpenVPN, `is_available(Wireguard)` a loaded `wireguard.dll`; every native kind (L2TP, Cisco, IKEv2 via strongSwan, SSTP) is unavailable with "Native Windows VPNs come in a later version of WinVPN." (`SetupReport::later_kinds`). System Status shows three rows (WinVPN Service, OpenVPN Community, WireGuard) instead of 2a's engine note, and a note line about native VPNs.
- **The live log and MFA without user-readable files.** `HelperClient` gets `log_source(id) -> Option<Box<dyn LogSource>>` (default: a file source over `log_path`, so macOS reads `/var/log/macvpn/<id>.log` exactly as before); `LogTailer` reads through a `LogSource` (core) with the same windows, resets and partial-line rules. On Windows the source asks the service (`log <id> <offset>`). The MFA state comes from `auth-state <id>`, parsed with the same `AuthUIState::parse` (and its 8 KiB limit) as the file on macOS.
- **The HTTP client on Windows is Windows' own `curl.exe`** (`%SystemRoot%\System32\curl.exe`, located with `GetSystemDirectoryW`, never `PATH`), driven by the same code as macOS' `/usr/bin/curl`. The redirect policy, the canonical URLs, the size caps, the conditional GET, the token-only-to-its-origin rule and the bearer token on stdin are security logic; one implementation of them (moved from platform-mac into `macvpn_platform_api::curl`, macOS' argv pinned byte for byte by a golden test written before the move) beats a second one over WinHTTP. Windows' curl (8.x on 22H2+, Schannel, the system trust store) supports every flag used; the Windows flavour adds `--ssl-revoke-best-effort` (Schannel otherwise fails when a CRL server is unreachable, but still refuses a revoked certificate) and an environment of only `SystemRoot` (Winsock needs it) and `PATH=%SystemRoot%\System32`. WinHTTP would bring the system proxy, but macOS' curl ignores proxies too (parity), and it would mean new `unsafe` code for every request.
- **The Windows updater** (decision 1): `check` and `download` as on macOS (the curl layer); verification: the `.sha256` asset, then `UpdateSignature::verify_trusted_for(WINVPN.signature_domain, asset, version, sha256, sig)` with `asset` = `WINVPN.update_asset(version, std::env::consts::ARCH)` (`WinVPN-<v>-x64.msi` or `-arm64.msi`), never `verify_trusted` (2a review I7). The verified MSI is kept open with share mode `FILE_SHARE_READ` only (no write, no delete, no rename while `msiexec` reads it) in `%LOCALAPPDATA%\WinVPN\updates\` (private ACL); install: the quit questions, then `ShellExecuteExW(runas, %SystemRoot%\System32\msiexec.exe, /i "<msi>" /qb! /norestart /l*v "<log>")`, waiting for it; exit 0 or 3010 = done, 1602 = cancelled by the user (UAC declined), anything else = the localized failure with the log path. The MSI's own `ServiceControl` stops the old service and starts the new one. WinVPN must not hold `WinVPN.exe` while the installer replaces it, so it starts a relauncher (a copy of itself in the private updates folder, run with `--relaunch-after <msiexec PID> --target <WinVPN.exe>`: it waits for `msiexec`, records the outcome for the next launch and starts the new `WinVPN.exe`) and quits. Same-user malware could hijack any UAC prompt the user approves; the deny-write handle is defence in depth, not a boundary (the threat model of 2a's question 1).
- **OpenVPN Community install** (spec 4.4; decision 4): offered by System Status when OpenVPN is missing ("Install"), when a driver is missing ("Repair"), and when the installed version is below `OPENVPN_RECOMMENDED` (the pinned MSI's version: "Update"). `<features>` = the MSI's features for `openvpn.exe`, DCO and TAP-Windows6 (and their parents), recorded in `scripts/pins/openvpn.txt` (Task 10). Order: (1) winget, when `winget.exe` exists at `%LOCALAPPDATA%\Microsoft\WindowsApps\winget.exe`: `winget install|upgrade --id OpenVPNTechnologies.OpenVPN --exact --source winget --scope machine --silent --accept-package-agreements --accept-source-agreements --disable-interactivity --override "/qn /norestart ADDLOCAL=<features>"`, run as the user (winget asks for elevation itself; it checks the installer's hash from its manifest). `--override` replaces winget's installer arguments with ours, and the OpenVPN package's installer is the same MSI, so the feature set is the same as the pinned path; but winget cannot report which features were installed, and a manifest can change its installer type — so after winget returns, System Status asks the service again, and if either driver is still missing it goes on with (2). (2) The pinned MSI (`OPENVPN_MSI_URL_X64` / `_ARM64`) downloaded with the curl layer, its SHA-256 = the pin and its Authenticode signer = `OPENVPN_SIGNER`, then `ShellExecuteExW(runas, msiexec.exe, /i "<msi>" /qb! /norestart ADDLOCAL=<features>)` with the deny-write handle held: on a machine with the same OpenVPN version this is a maintenance install that adds the missing features. "Repair" when the installed version differs from the pin goes through winget (`upgrade`); without winget the row says "Add the DCO and TAP-Windows6 drivers in Settings → Apps → Installed apps → OpenVPN → Modify." The service's own trust check of `openvpn.exe` (above) is what makes either source safe to use. After either path succeeds on an installation WinVPN made, the Interactive Service is disabled, stopped and checked (decision 4, "The OpenVPN Interactive Service"). The output lines stream into System Status (2a's `install_tools(report, output)`, which macOS uses for `brew install`).
- **The Windows smoke run** is a scheduled task in the interactive session of `winvpn-dev`: `scripts/win-smoke.sh` (run on the Mac) syncs, builds the debug app on the Windows machine, writes a one-shot task `WinVPN-smoke-<pid>` with `schtasks /Create /SC ONCE /ST 00:00 /IT /RU winvpn-dev /TR "<Git Bash> -lc 'cd ~/<dir> && scripts/smoke-manage.sh'"` (`/IT`: runs only in the logged-on desktop session, no password stored; a standard user may create it for itself), runs it with `schtasks /Run`, waits for its result file, prints the log, and deletes the task. It needs `winvpn-dev` logged on at the VM's console (the session may be locked or disconnected); without a session it fails with "no interactive session of winvpn-dev: log on at the VM's console". The smoke driver is split into a portable part (scripts, the fake helper, the mock reports, waiting, `eval`) and the macOS-only part (window numbers, `screencapture`, the Dock, the activation policy); the Windows run covers every section except Dock, shapes and screenshots.
- **Admin tests in CI.** GitHub's Windows runners run as administrators: a `windows-admin` job (Task 21) installs the pinned OpenVPN MSI and the freshly built WinVPN MSI with `msiexec /qn`, checks the service, and runs the admin test set (`-- --ignored admin_`), including an end-to-end OpenVPN connect through the service to a local `openvpn.exe` server on loopback with a throwaway PKI made by Git's `openssl.exe` at test time, and a WireGuard adapter up/down. The maintainer runs the same set on the VM in an elevated Git Bash (checklist).
- **Risks of decision 4.** More kernel drivers means more attack surface: TAP-Windows6 is a Microsoft-signed driver maintained by OpenVPN, installed by OpenVPN's own MSI, and loaded only for the connections that need it; WinVPN never talks to it itself. TAP-Windows6 adapters persist in Network Connections after a disconnect and after WinVPN is uninstalled (they belong to OpenVPN); a TAP adapter opened by a SYSTEM `openvpn.exe` carries that user's tunnel, and `allow-nonadmin` (which would let other users open it) stays forbidden. Configurations that need TAP-Windows6 run slower than DCO and some (compression) are weaker; the validator keeps them SAFE as on macOS, and the guide says why.
- **What stays as it is:** the native RAS VPNs (2c); the WireGuard and OpenVPN drivers stay installed when WinVPN is uninstalled (both are shared with the official clients); no Authenticode signing of WinVPN by default (2a); version of 2b builds stays `1.5.0` (2a's decision 5).

---
## File structure

Created (C) or modified (M); the task that owns each file.

| File | What it is | Task |
|---|---|---|
| C `crates/core/src/service_proto.rs`, `crates/core/tests/service_proto.rs` | the pipe envelope, the commands' shared types (`EngineFacts`, `LogSlice`), `SERVICE_VERSION`, `PIPE_NAME` | 1 |
| M `crates/core/src/validators/{openvpn,wireguard}.rs`, `crates/core/tests/{openvpn_tiers,validators}.rs`, `docs/openvpn-directives.md` | the Windows tiers | 2 |
| M `crates/winsys/src/{pipe,sid,file}.rs`, `crates/winsys/tests/service_pipe.rs` | the service endpoint: DACL, `ServerTrust`, client access mask | 3 |
| C `crates/winsys/src/{trust,version,acl_check,dll}.rs`, `crates/winsys/tests/trust.rs` | Authenticode signer, file version, admin-only paths, safe DLL loading | 4 |
| C `crates/platform-api/src/curl/{mod,http,catalog}.rs`; M `crates/platform-mac/src/{http,catalog_http,command}.rs`; C `crates/platform-mac/tests/curl_argv.rs` | the curl layer shared by macOS and Windows | 5 |
| M `crates/core/src/log.rs`, `crates/platform-api/src/helper.rs`, `crates/app-core/src/logs.rs`, `app/src-tauri/src/manage.rs` | `LogSource`, `HelperClient::log_source` | 6 |
| C `crates/helper/src/shared/ovpn_log.rs`; M `crates/helper/src/macos/log.rs`, `crates/helper/src/shared/{mod,bridge}.rs` | the OpenVPN log predicates and the in-process bridge arguments | 7 |
| C `crates/helper/src/windows/{service,logs}.rs`, `crates/helper/tests/service_core.rs`; M `crates/helper/src/shared/limits.rs` | the request handler and the connection logs (pure) | 8 |
| C `crates/helper/src/windows/{wg_nt,wg_plan}.rs`, `crates/helper/tests/wg_windows.rs` | wireguard-nt's configuration bytes and the IP plan (pure) | 9 |
| C `crates/helper/src/windows/{ovpn_args,ovpn_pins}.rs`, `crates/helper/tests/ovpn_windows.rs`, `scripts/pins/openvpn.txt`, `crates/platform-win/src/pure/openvpn_pins.rs` (generated); M `crates/core/src/service_proto.rs` (`Version`) | OpenVPN's argv, the version policy, the pins | 10 |
| M `crates/platform-api/src/setup.rs`, `crates/app-core/src/setup.rs`, `app/src-tauri/src/state.rs`, `app/ui/src/lib/{Setup.svelte,api.ts}`, `crates/core/l10n/strings.json` | System Status' engine rows | 11 |
| C `crates/helper/src/windows/sys/{mod,host,server,data_dir,session,console,service_log,job}.rs`, `crates/winsys/src/known.rs`, `crates/helper/tests/{service_pipe,service_admin}.rs`; M `crates/helper/src/windows/mod.rs`, `crates/helper/Cargo.toml`, `crates/winsys/src/file.rs` | the service host | 12 |
| C `crates/helper/src/windows/bridge_state.rs`, `crates/helper/src/windows/sys/{openvpn,detect,mgmt,tcp_owner,adapters}.rs`, `crates/helper/tests/{bridge_state,openvpn_installed}.rs` | the OpenVPN engine | 13 |
| C `crates/helper/src/windows/wg_pins.rs`, `crates/helper/src/windows/sys/{wireguard,wgdll,iphlp}.rs`, `crates/helper/tests/{wireguard_admin.rs,common/console.rs}`, `scripts/pins/wireguard-nt.txt`, `scripts/fetch-wireguard-nt.sh`, `scripts/wg-nt-layout.c` | the WireGuard engine | 14 |
| C `app/src-tauri/wix/service.wxs.in`, `scripts/notices/wireguard-nt-LICENSE.txt`; M `scripts/build-msi.sh`, `scripts/bundle-baseline/winvpn-msi-files.txt`, `scripts/third-party-notices.mjs`, `THIRD-PARTY-NOTICES.windows.txt`, `scripts/test-build-msi.sh` | the MSI with the service | 15 |
| C `crates/core/src/helper_args.rs`, `crates/platform-win/src/win/service_client.rs`, `crates/platform-win/src/pure/engine.rs`, `crates/platform-win/tests/service_client.rs`; M `crates/platform-mac/src/mvpn_client.rs`, `crates/platform-win/src/win/{platform,not_yet}.rs`, `crates/platform-win/src/pure/texts.rs` | the app's service client | 16 |
| C `crates/platform-win/src/win/{elevate,openvpn_install,curl_runner}.rs`, `crates/platform-win/src/pure/openvpn_install.rs`, `crates/platform-api/tests/curl_pinned.rs`, `crates/platform-win/tests/openvpn_install.rs`; M `crates/platform-api/src/curl/http.rs` | OpenVPN install from System Status | 17 |
| C `crates/platform-win/src/win/updater.rs`, `crates/platform-win/src/pure/update.rs`, `crates/platform-win/tests/update.rs`; M `app/src-tauri/src/{main.rs,platform/windows.rs}` | the Windows updater, its relauncher, the release source | 18 |
| M `crates/platform-win/src/win/platform.rs` (fetcher), C `crates/platform-win/tests/curl.rs` | HTTPS team catalogs and the update check | 19 |
| C `app/src-tauri/src/platform/smoke/{mod,macos}.rs` (from `smoke.rs`), `scripts/win-smoke.sh`, `scripts/test-win-smoke.sh`; M `scripts/smoke-manage.sh`, `scripts/win-remote.sh` (`run-nosync`) | the Windows smoke run | 20 |
| M `.github/workflows/{ci,release}.yml`, `docs/RELEASING.md`; C `crates/helper/tests/openvpn_e2e.rs`, `scripts/ci-install-openvpn.sh` | CI, the admin job, release | 21 |
| M `docs/{architecture,winvpn-user-guide.en,winvpn-user-guide.hu,manual-test-checklist}.md`, `README.md`, the spec | documentation | 22 |

---

## Task 1: the service protocol (`macvpn_core::service_proto`)

**Goal:** one strict, portable codec for the pipe between the app and the WinVPN Service, plus the shared types of the three Windows-only commands. Used by the service (Task 8) and the app (Task 16); tested on every OS.

**Files:**
- Create: `crates/core/src/service_proto.rs`, `crates/core/tests/service_proto.rs`
- Modify: `crates/core/src/lib.rs` (`pub mod service_proto;`, sorted after `pub mod native;`… keep the existing alphabetical order: between `ranking` and `status`)

- [x] **Step 1: Write the failing tests** (`crates/core/tests/service_proto.rs`)

```rust
//! The WinVPN Service's pipe envelope (see `macvpn_core::service_proto`).

use macvpn_core::service_proto::{
    self as proto, EngineFacts, LogSlice, OpenVpnFacts, ProtoError, Request, Response, WireGuardFacts,
};

fn request_bytes(args: &[&str], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    proto::write_request(&mut out, args, body).unwrap();
    out
}

#[test]
fn a_request_round_trips() {
    let body = b"config 7\nclient\n\npassword=x\n";
    let bytes = request_bytes(&["up", "openvpn", "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0", "--lang", "hu"], body);
    assert!(bytes.starts_with(b"winvpn 1\nargs 5\nup\nopenvpn\n"));
    let Request { args, body: got } = proto::read_request(&mut bytes.as_slice()).unwrap();
    assert_eq!(args, ["up", "openvpn", "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0", "--lang", "hu"]);
    assert_eq!(got.as_slice(), body);
}

#[test]
fn a_response_round_trips() {
    let r = Response { code: 1, stdout: b"[]\n".to_vec(), stderr: "Érvénytelen azonosító\n".as_bytes().to_vec() };
    let mut out = Vec::new();
    proto::write_response(&mut out, &r).unwrap();
    assert!(out.starts_with(b"winvpn 1\nexit 1\nstdout 3\n[]\nstderr "));
    assert_eq!(proto::read_response(&mut out.as_slice()).unwrap(), r);
    let negative = Response { code: -1, stdout: vec![], stderr: vec![] };
    let mut out = Vec::new();
    proto::write_response(&mut out, &negative).unwrap();
    assert_eq!(proto::read_response(&mut out.as_slice()).unwrap(), negative);
}

#[test]
fn arguments_are_restricted() {
    for bad in ["", "a b", "a\nb", "ä", "a;b", "../x", "a\\b", "\"x\""] {
        assert!(!proto::is_valid_arg(bad), "{bad:?}");
        let mut sink = Vec::new();
        assert!(proto::write_request(&mut sink, &[bad], b"").is_err(), "{bad:?}");
    }
    for good in ["up", "--accept-risky", "a,b-c", "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0", "--lang=hu", "12345"] {
        assert!(proto::is_valid_arg(good), "{good}");
    }
    assert!(!proto::is_valid_arg(&"a".repeat(proto::ARG_MAX + 1)));
    let many: Vec<&str> = std::iter::repeat_n("x", proto::MAX_ARGS + 1).collect();
    assert!(proto::write_request(&mut Vec::new(), &many, b"").is_err());
}

#[test]
fn malformed_requests_are_refused() {
    let cases: &[&[u8]] = &[
        b"",
        b"winvpn 2\nargs 0\nbody 0\n",
        b"winvpn 1\nargs 01\nx\nbody 0\n",
        b"winvpn 1\nargs 1\nx\nbody 1\n",
        b"winvpn 1\nargs 1\nx y\nbody 0\n",
        b"winvpn 1\nargs 17\n",
        b"winvpn 1\nargs 0\nbody 0\nextra",
        b"winvpn 1\r\nargs 0\nbody 0\n",
        b"winvpn 1\nargs 0\nbody -1\n",
        b"winvpn 1\nargs 0\nbody 99999999999\n",
    ];
    for c in cases {
        assert!(proto::read_request(&mut &c[..]).is_err(), "{:?}", String::from_utf8_lossy(c));
    }
}

#[test]
fn an_oversized_body_is_refused_before_it_is_read() {
    let header = format!("winvpn 1\nargs 0\nbody {}\n", proto::BODY_MAX + 1);
    let mut src = std::io::Cursor::new(header.into_bytes()).chain(std::io::repeat(b'#'));
    assert_eq!(proto::read_request(&mut src).err(), Some(ProtoError::TooLarge));
}

#[test]
fn trailing_bytes_after_the_body_are_not_read() {
    // One request per connection: the reader stops after the body (the server then answers).
    let mut bytes = request_bytes(&["status"], b"");
    bytes.extend_from_slice(b"junk");
    let mut slice = bytes.as_slice();
    assert!(proto::read_request(&mut slice).is_ok());
    assert_eq!(slice, b"junk");
}

#[test]
fn engine_facts_round_trip_as_json() {
    let facts = EngineFacts {
        service_version: proto::SERVICE_VERSION,
        problem: None,
        openvpn: OpenVpnFacts {
            version: Some("2.6.14".into()),
            path: Some(r"C:\Program Files\OpenVPN\bin\openvpn.exe".into()),
            dco: Some("2.6.1".into()),
            wintun: Some("0.14.1".into()),
            tap_windows6: Some("9.27.0".into()),
            problem: None,
        },
        wireguard: WireGuardFacts { dll_version: Some("0.10.1".into()), problem: None },
    };
    let json = facts.to_json();
    assert_eq!(EngineFacts::parse(json.as_bytes()), Some(facts));
    assert_eq!(EngineFacts::parse(b"{}"), None);
    assert_eq!(EngineFacts::parse(&vec![b' '; proto::FACTS_MAX + 1]), None);
}

#[test]
fn log_slices_round_trip() {
    let s = LogSlice { generation: 7, size: 300, start: 290, data: b"0123456789".to_vec() };
    let bytes = s.encode();
    assert_eq!(&bytes[..12], b"7 300 290\n01");
    assert_eq!(LogSlice::parse(&bytes), Some(s));
    for bad in [&b""[..], b"7 300\nx", b"x 1 1\n", b"1 1 2\n", b"1 5 0\n123456", b"01 1 0\nx"] {
        assert_eq!(LogSlice::parse(bad), None, "{:?}", String::from_utf8_lossy(bad));
    }
}
```

`std::io::Read::chain` needs `use std::io::Read;` at the top; add it.

- [x] **Step 2: Run the tests to verify they fail**

Run: `cargo test --locked -p macvpn-core --test service_proto`
Expected: FAIL to compile with "unresolved import `macvpn_core::service_proto`".

- [x] **Step 3: Implement** (`crates/core/src/service_proto.rs`)

```rust
//! The pipe between WinVPN and the WinVPN Service (`\\.\pipe\WinVPN`): one request per connection, length-
//! delimited, strict. The body of an `up` is the root layer 8 frame (`config <len>\n…` and the secret lines), of a
//! `respond` the answer lines; the service parses them with the helper's shared code. A pipe has no half-close, so
//! the envelope carries the body's length where the macOS root layer reads stdin to its end.
//!
//! ```text
//! request:  winvpn 1\n args <n>\n <arg>\n × n  body <len>\n <len bytes>
//! response: winvpn 1\n exit <code>\n stdout <len>\n <bytes> stderr <len>\n <bytes>
//! ```
//!
//! Numbers are ASCII decimal without sign (the exit code may have a `-`) or leading zero; an argument is 1–4096
//! bytes of `[A-Za-z0-9,._=-]`, at most 16 of them; the body is at most [`BODY_MAX`] bytes (refused before it is
//! read), each output at most [`OUTPUT_MAX`]. Platform-independent: no I/O but the given reader and writer.

use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use zeroize::Zeroizing;

/// The service's endpoint.
pub const PIPE_NAME: &str = r"\\.\pipe\WinVPN";
/// The protocol and service version: the app requires exactly this one (the MSI installs both together).
pub const SERVICE_VERSION: u32 = 1;
pub const MAGIC: &[u8] = b"winvpn 1\n";
pub const ARG_MAX: usize = 4096;
pub const MAX_ARGS: usize = 16;
/// The helper's `STDIN_MAX` (1 MiB config + 64 KiB secrets + 16); the helper asserts the two are equal.
pub const BODY_MAX: u64 = 1_048_576 + 65_536 + 16;
pub const OUTPUT_MAX: u64 = 2 * 1024 * 1024;
/// The longest `engine` answer.
pub const FACTS_MAX: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtoError {
    /// Not this protocol, a malformed line or number, or bytes where none may be.
    Invalid,
    /// A length above its limit (nothing more was read).
    TooLarge,
    /// The stream ended early or failed.
    Io(io::ErrorKind),
}

impl From<io::Error> for ProtoError {
    fn from(e: io::Error) -> Self {
        ProtoError::Io(e.kind())
    }
}

/// A request as the service receives it. The body may hold secrets: zeroed on drop.
#[derive(Debug)]
pub struct Request {
    pub args: Vec<String>,
    pub body: Zeroizing<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Response {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Response {
    pub fn ok(stdout: impl Into<Vec<u8>>) -> Response {
        Response { code: 0, stdout: stdout.into(), stderr: Vec::new() }
    }

    /// `code` with `message` and a line end on stderr (the `mvpn` `die`).
    pub fn fail(code: i32, message: &str) -> Response {
        Response { code, stdout: Vec::new(), stderr: format!("{message}\n").into_bytes() }
    }
}

pub fn is_valid_arg(a: &str) -> bool {
    !a.is_empty()
        && a.len() <= ARG_MAX
        && a.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b',' | b'.' | b'_' | b'=' | b'-'))
}

fn invalid_input() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "not a valid service request")
}

pub fn write_request(w: &mut impl Write, args: &[&str], body: &[u8]) -> io::Result<()> {
    if args.len() > MAX_ARGS || !args.iter().all(|a| is_valid_arg(a)) || body.len() as u64 > BODY_MAX {
        return Err(invalid_input());
    }
    let mut head = Vec::with_capacity(64 + args.iter().map(|a| a.len() + 1).sum::<usize>());
    head.extend_from_slice(MAGIC);
    head.extend_from_slice(format!("args {}\n", args.len()).as_bytes());
    for a in args {
        head.extend_from_slice(a.as_bytes());
        head.push(b'\n');
    }
    head.extend_from_slice(format!("body {}\n", body.len()).as_bytes());
    w.write_all(&head)?;
    w.write_all(body)?;
    w.flush()
}

pub fn write_response(w: &mut impl Write, r: &Response) -> io::Result<()> {
    if r.stdout.len() as u64 > OUTPUT_MAX || r.stderr.len() as u64 > OUTPUT_MAX {
        return Err(invalid_input());
    }
    w.write_all(MAGIC)?;
    w.write_all(format!("exit {}\nstdout {}\n", r.code, r.stdout.len()).as_bytes())?;
    w.write_all(&r.stdout)?;
    w.write_all(format!("stderr {}\n", r.stderr.len()).as_bytes())?;
    w.write_all(&r.stderr)?;
    w.flush()
}

/// One line of at most `max` bytes before its `\n`, read a byte at a time (nothing after the line is consumed).
fn read_line(r: &mut impl Read, max: usize) -> Result<Vec<u8>, ProtoError> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match r.read(&mut byte) {
            Ok(0) => return Err(ProtoError::Io(io::ErrorKind::UnexpectedEof)),
            Ok(_) if byte[0] == b'\n' => return Ok(line),
            Ok(_) if line.len() == max => return Err(ProtoError::Invalid),
            Ok(_) => line.push(byte[0]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
}

/// `<word> <number>`: digits only, no leading zero (but `0` itself), at most 12 digits.
fn number_line(line: &[u8], word: &str, signed: bool) -> Result<i64, ProtoError> {
    let rest = line.strip_prefix(word.as_bytes()).and_then(|r| r.strip_prefix(b" ")).ok_or(ProtoError::Invalid)?;
    let (negative, digits) = match rest.strip_prefix(b"-") {
        Some(d) if signed => (true, d),
        Some(_) => return Err(ProtoError::Invalid),
        None => (false, rest),
    };
    let ok = !digits.is_empty()
        && digits.len() <= 12
        && digits.iter().all(u8::is_ascii_digit)
        && (digits.len() == 1 || digits[0] != b'0');
    if !ok {
        return Err(ProtoError::Invalid);
    }
    let v = digits.iter().fold(0i64, |v, d| v * 10 + i64::from(d - b'0'));
    Ok(if negative { -v } else { v })
}

fn expect_magic(r: &mut impl Read) -> Result<(), ProtoError> {
    let mut magic = [0u8; MAGIC.len()];
    r.read_exact(&mut magic)?;
    if magic != MAGIC { Err(ProtoError::Invalid) } else { Ok(()) }
}

/// Exactly `len` bytes into one buffer allocated at its final size (never grown, so never copied unzeroed).
fn read_exact_zeroizing(r: &mut impl Read, len: usize) -> Result<Zeroizing<Vec<u8>>, ProtoError> {
    let mut buf = Zeroizing::new(vec![0u8; len]);
    r.read_exact(&mut buf)?;
    Ok(buf)
}

pub fn read_request(r: &mut impl Read) -> Result<Request, ProtoError> {
    expect_magic(r)?;
    let n = number_line(&read_line(r, 16)?, "args", false)?;
    if n as usize > MAX_ARGS {
        return Err(ProtoError::Invalid);
    }
    let mut args = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let line = read_line(r, ARG_MAX)?;
        let arg = String::from_utf8(line).map_err(|_| ProtoError::Invalid)?;
        if !is_valid_arg(&arg) {
            return Err(ProtoError::Invalid);
        }
        args.push(arg);
    }
    let len = number_line(&read_line(r, 24)?, "body", false)?;
    if len as u64 > BODY_MAX {
        return Err(ProtoError::TooLarge);
    }
    let body = read_exact_zeroizing(r, len as usize)?;
    Ok(Request { args, body })
}

pub fn read_response(r: &mut impl Read) -> Result<Response, ProtoError> {
    expect_magic(r)?;
    let code = number_line(&read_line(r, 24)?, "exit", true)?;
    let code = i32::try_from(code).map_err(|_| ProtoError::Invalid)?;
    let mut part = |word: &str| -> Result<Vec<u8>, ProtoError> {
        let len = number_line(&read_line(r, 24)?, word, false)?;
        if len as u64 > OUTPUT_MAX {
            return Err(ProtoError::TooLarge);
        }
        let mut buf = vec![0u8; len as usize];
        r.read_exact(&mut buf)?;
        Ok(buf)
    };
    let stdout = part("stdout")?;
    let stderr = part("stderr")?;
    Ok(Response { code, stdout, stderr })
}

// MARK: - `engine`

/// What the service knows about its engines (System Status; the `engine` command's stdout, JSON).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EngineFacts {
    pub service_version: u32,
    /// The service cannot connect anything (its data directory is unsafe): the localized reason.
    pub problem: Option<String>,
    pub openvpn: OpenVpnFacts,
    pub wireguard: WireGuardFacts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct OpenVpnFacts {
    /// `major.minor.patch` of `openvpn.exe`; `None`: not installed.
    pub version: Option<String>,
    pub path: Option<String>,
    /// The version of each data-channel driver; `None`: not installed (decision 4: all three are installed).
    pub dco: Option<String>,
    pub wintun: Option<String>,
    pub tap_windows6: Option<String>,
    /// Why OpenVPN cannot be used (localized); `None`: usable.
    pub problem: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WireGuardFacts {
    /// The bundled `wireguard.dll`'s version once loaded and verified.
    pub dll_version: Option<String>,
    pub problem: Option<String>,
}

impl EngineFacts {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("plain data serializes")
    }

    /// At most [`FACTS_MAX`] bytes of exactly this shape.
    pub fn parse(data: &[u8]) -> Option<EngineFacts> {
        if data.len() > FACTS_MAX {
            return None;
        }
        serde_json::from_slice(data).ok()
    }
}

// MARK: - `log`

/// A slice of a connection's log (`log <id> <offset>`): `generation` changes when the log file is replaced (the
/// counterpart of the inode check), `size` is the file's size, `data` the bytes from `start` (at most 1 MiB).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogSlice {
    pub generation: u64,
    pub size: u64,
    pub start: u64,
    pub data: Vec<u8>,
}

impl LogSlice {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = format!("{} {} {}\n", self.generation, self.size, self.start).into_bytes();
        out.extend_from_slice(&self.data);
        out
    }

    /// `start + data.len() <= size`, numbers without leading zeros.
    pub fn parse(bytes: &[u8]) -> Option<LogSlice> {
        let nl = bytes.iter().position(|&b| b == b'\n')?;
        let head = std::str::from_utf8(&bytes[..nl]).ok()?;
        let mut parts = head.split(' ');
        let mut num = || -> Option<u64> {
            let p = parts.next()?;
            let ok = !p.is_empty() && p.len() <= 20 && p.bytes().all(|b| b.is_ascii_digit());
            (ok && (p.len() == 1 || !p.starts_with('0'))).then(|| p.parse().ok()).flatten()
        };
        let (generation, size, start) = (num()?, num()?, num()?);
        if parts.next().is_some() {
            return None;
        }
        let data = bytes[nl + 1..].to_vec();
        (start.checked_add(data.len() as u64)? <= size).then_some(LogSlice { generation, size, start, data })
    }
}
```

- [x] **Step 4: Run the tests to verify they pass**

Run: `cargo test --locked -p macvpn-core --test service_proto && scripts/check-windows.sh`
Expected: PASS (8 tests); the Windows check OK.

- [x] **Step 5: Commit**

```bash
git add crates/core/src/service_proto.rs crates/core/src/lib.rs crates/core/tests/service_proto.rs
git commit -m "feat(core): the WinVPN Service's pipe protocol" -m "A strict, length-delimited envelope around the root layer 8 frame (a pipe has no half-close), the engine facts and log slices of the Windows-only commands, SERVICE_VERSION 1." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

## Task 2: the Windows tiers of the OpenVPN and WireGuard validators

**Goal:** the validators the service runs as SYSTEM refuse everything that would let a configuration act with SYSTEM's rights; macOS and Linux tables stay byte for byte.

**Files:**
- Modify: `crates/core/src/validators/openvpn.rs` (`PLATFORM_WINDOWS`, a new `FORBIDDEN_WINDOWS`, `tier_for`, `WINDOWS_ARGUMENT_SPECS` emptied, `allowed()`), `crates/core/src/validators/wireguard.rs` (a `validate_for(os, text)` with the Windows key rules), `crates/core/src/validators/mod.rs` (the WireGuard validator's `validate` uses the host OS)
- Modify: `crates/core/tests/openvpn_tiers.rs` (`windows_platform_tier` rewritten; the draft it pinned is replaced on purpose), `crates/core/tests/validators.rs` (WireGuard on Windows)
- Modify: `docs/openvpn-directives.md` (the Windows section), `crates/core/l10n/strings.json` (two texts)

- [x] **Step 1: Write the failing tests**

Replace `windows_platform_tier` in `crates/core/tests/openvpn_tiers.rs` with:

```rust
#[test]
fn windows_platform_tier() {
    en();
    let w = TargetOs::Windows;
    // As SYSTEM these would run programs from a chosen folder or hand OpenVPN a control channel: never allowed.
    for d in ["win-sys", "service", "msg-channel", "allow-nonadmin", "rdns-internal", "dhcp-internal", "windows-driver", "cryptoapicert"] {
        assert_eq!(OpenVPNValidator::tier_for(w, d), OpenVPNTier::Forbidden, "{d}");
        let r = check_for(w, &format!("{d} x"), &[d]);
        assert_eq!(r.issues.len(), 1, "{d}");
        assert!(r.issues[0].message.starts_with(&format!("Forbidden directive: {d}")), "{d}");
        assert_eq!(r.risky, [], "{d}");
    }
    // Acknowledging does not help, inside a <connection> block neither, nor through setenv opt.
    assert_eq!(check_for(w, "setenv opt win-sys env", &["win-sys"]).issues.len(), 1);
    // TAP-Windows6 and Wintun are installed (decision 4): what DCO cannot run is SAFE on Windows as on macOS; the
    // service picks the driver (Task 10).
    for good in ["dev tap", "dev-type tap", "comp-lzo yes", "compress lz4-v2", "cipher AES-256-CBC", "fragment 1300", "disable-dco"] {
        assert_eq!(check_for(w, good, &[]).all_issues(), [], "{good}");
    }
    // dev-node stays forbidden everywhere (an adapter chosen by name).
    assert_eq!(OpenVPNValidator::tier_for(w, "dev-node"), OpenVPNTier::Forbidden);
    // setcon stays refused with its reason (Linux only), as before.
    let r = check_for(w, "setcon x", &[]);
    assert_eq!(r.risky[0].reason_key, REASON_PLATFORM_WINDOWS);
    assert_eq!(platform_reasons(w).keys().copied().collect::<Vec<_>>(), ["setcon"]);
    // The Windows-only SAFE options keep working.
    for good in ["block-outside-dns", "register-dns", "route-method ipapi", "ip-win32 dynamic", "dhcp-renew"] {
        assert_eq!(check_for(w, good, &[]).all_issues(), [], "{good}");
    }
    assert!(check_for(w, "cryptoapicert \"THUMB:aa bb\"", &[]).issues[0].message.starts_with("Forbidden directive: cryptoapicert"));
}

#[test]
fn the_macos_and_linux_tiers_are_unchanged_by_the_windows_one() {
    en();
    for os in [TargetOs::MacOs, TargetOs::Linux] {
        for d in ["win-sys", "service", "msg-channel", "allow-nonadmin", "rdns-internal", "dhcp-internal"] {
            assert_eq!(OpenVPNValidator::tier_for(os, d), OpenVPNTier::Risky, "{os:?} {d}");
        }
        assert_eq!(OpenVPNValidator::tier_for(os, "windows-driver"), OpenVPNTier::Safe, "{os:?}");
    }
    assert_eq!(OpenVPNValidator::tier_for(TargetOs::MacOs, "cryptoapicert"), OpenVPNTier::Risky);
}
```

In `crates/core/tests/validators.rs` add:

```rust
#[test]
fn wireguard_on_windows() {
    use macvpn_core::target_os::TargetOs;
    use macvpn_core::validators::WireGuardValidator;
    lang(AppLanguage::En);
    let base = "[Interface]\nPrivateKey = bWFjdnBuLXRlc3QtcHJpdmF0ZS1rZXktMzJieXRlcyE=\nAddress = 10.0.0.2/32\n";
    let peer = "[Peer]\nPublicKey = bWFjdnBuLXRlc3QtcHVibGljLS1rZXktMzJieXRlcyE=\nAllowedIPs = 0.0.0.0/0\n";
    let w = |extra: &str| WireGuardValidator.validate_for(TargetOs::Windows, &format!("{base}{extra}{peer}"));
    let m = |extra: &str| WireGuardValidator.validate_for(TargetOs::MacOs, &format!("{base}{extra}{peer}"));
    assert_eq!(w(""), []);
    assert_eq!(w("FwMark = 51820\n")[0].message, "Not supported on Windows: fwmark");
    assert_eq!(w("Table = off\n"), []);
    assert_eq!(w("Table = auto\n"), []);
    assert_eq!(w("Table = 1234\n")[0].message, "Not supported on Windows: table");
    // macOS keeps every value it accepted.
    assert_eq!(m("FwMark = 51820\n"), []);
    assert_eq!(m("Table = 1234\n"), []);
}
```

(`lang` comes from `common`; if `validators.rs` does not `mod common;` yet, use `macvpn_core::l10n::AppLanguage::set_thread_override(Some(AppLanguage::En))`.)

- [x] **Step 2: Run them to verify they fail**

Run: `cargo test --locked -p macvpn-core --test openvpn_tiers windows && cargo test --locked -p macvpn-core --test validators wireguard_on_windows`
Expected: FAIL (`win-sys` is Risky on Windows; `validate_for` does not exist).

- [x] **Step 3: Implement**

In `openvpn.rs`, replace the `PLATFORM_WINDOWS` table and the Windows argument specs:

```rust
/// Windows: the WinVPN Service runs `openvpn.exe` as SYSTEM and sets these itself. `win-sys` would make OpenVPN run
/// `route.exe` / `netsh.exe` from a folder of the config's choosing, `service` / `msg-channel` hand it an event or a
/// pipe, `allow-nonadmin` changes a TAP adapter's permissions (TAP-Windows6 is installed), `rdns-internal` /
/// `dhcp-internal` are internal, `windows-driver` is chosen by the service per connection (DCO, Wintun or
/// TAP-Windows6), `cryptoapicert` would read the computer's certificate store as SYSTEM (decision 3 of the 2b plan).
/// FORBIDDEN, never acknowledgeable.
pub static FORBIDDEN_WINDOWS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "win-sys",
        "service",
        "msg-channel",
        "allow-nonadmin",
        "rdns-internal",
        "dhcp-internal",
        "windows-driver",
        "cryptoapicert",
    ]
    .into()
});

/// Windows: `setcon` is SELinux (Linux only).
static PLATFORM_WINDOWS: LazyLock<HashMap<&'static str, &'static str>> =
    LazyLock::new(|| [("setcon", REASON_PLATFORM_WINDOWS)].into());
```

Delete `WINDOWS_ARGUMENT_SPECS` (its only entry, `cryptoapicert`, is forbidden on Windows now) and make `argument_spec_for(_os: TargetOs, directive)` return `map_get(&ARGUMENT_SPECS, directive)` (the parameter stays for the callers). `allowed()` returns `ARGUMENT_SPECS`' keys, minus the `FORBIDDEN_WINDOWS` names on a Windows host (`windows-driver` is in the shared table). In `tier_for`, after the `FORBIDDEN` check:

```rust
        if os == TargetOs::Windows && set_contains(&FORBIDDEN_WINDOWS, directive) {
            return OpenVPNTier::Forbidden;
        }
```

`REASON_SERVICE_OWNED` stays defined (its text is in the l10n baseline) but no table uses it any more; add a doc line saying so.

In `wireguard.rs`, add (and make `ConfigValidator::validate` call `self.validate_for(TargetOs::host(), text)`; on macOS that is exactly today's code path):

```rust
impl WireGuardValidator {
    /// The checks of [`ConfigValidator::validate`] for `os`. Windows (wireguard-nt): `FwMark` has no equivalent,
    /// `Table` only `auto` or `off`.
    pub fn validate_for(&self, os: TargetOs, text: &str) -> Vec<ValidationIssue> {
        let mut issues = self.validate_common(text);
        if os == TargetOs::Windows {
            for (line_no, key, value) in key_values(text) {
                let unsupported = match key.as_str() {
                    "fwmark" => true,
                    "table" => !(swift_str::eq(&ascii_lowercased(value), "auto") || swift_str::eq(&ascii_lowercased(value), "off")),
                    _ => false,
                };
                if unsupported {
                    issues.push(ValidationIssue::new(line_no, l10n::tr("Not supported on Windows: %@", &[Arg::Str(&key)])));
                }
            }
            issues.sort_by_key(|i| i.line);
        }
        issues
    }
}
```

where `validate_common` is today's `validate` body moved unchanged, and `key_values(text)` is a small iterator over `(line_no, lower-cased key, trimmed value)` of the valid `key = value` lines (reuse the parsing steps already in the body: comment cut, `trim_space_tab`, `first_index(line, "=")`). Check the issue struct's line field name (`line`) in `models.rs` before writing the sort.

`strings.json` (scope `core`, `"only": ["windows"]`):
- `"Not supported on Windows: %@"` → hu `"Windowson nem támogatott: %@"`.

`docs/openvpn-directives.md`: in the Windows section, replace the draft table with the FORBIDDEN list above and its reasons (one row per directive), `setcon` refused (Linux only), the note "No acknowledgement unlocks these: the service runs OpenVPN as SYSTEM.", and a table "Which driver a configuration gets" (DCO by default; Wintun for compression, non-AEAD ciphers, `fragment`, `secret`, `disable-dco`; TAP-Windows6 for `dev tap`), the same rules as `ovpn_args::choose_driver`.

- [x] **Step 4: Run the tests to verify they pass**

Run: `cargo test --locked -p macvpn-core && node scripts/l10n-baseline.mjs --check && scripts/check-windows.sh`
Expected: PASS; the docs test in `openvpn_tiers.rs` (it reads `docs/openvpn-directives.md`) passes; the l10n baseline reports 1 new key and no changed macOS text.

- [x] **Step 5: Commit**

```bash
git add crates/core/src/validators crates/core/tests/openvpn_tiers.rs crates/core/tests/validators.rs crates/core/l10n/strings.json docs/openvpn-directives.md
git commit -m "feat(core): the Windows tiers of the OpenVPN and WireGuard validators" -m "The WinVPN Service runs OpenVPN as SYSTEM: win-sys, service, msg-channel, allow-nonadmin, rdns-internal, dhcp-internal, windows-driver and cryptoapicert are forbidden on Windows (the phase 1 draft made them acknowledgeable). WireGuard on Windows refuses FwMark and a Table other than auto/off. macOS and Linux unchanged (windows_platform_tier replaced on purpose; the_macos_and_linux_tiers_are_unchanged_by_the_windows_one)." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

## Task 3: `winsys::pipe`: the service endpoint

**Goal:** a pipe server the service binds as SYSTEM with the DACL of spec 4.1 (interactive users may connect, nobody but SYSTEM may create instances or change the DACL, network logons denied), and a client that refuses a server whose pipe is not owned by SYSTEM. The same code, with the current user as owner, serves the test-mode service.

**Files:**
- Modify: `crates/winsys/src/pipe.rs`, `crates/winsys/src/sid.rs` (`Sid::interactive`, `Sid::builtin_administrators`), `crates/winsys/src/file.rs` (`kernel_object_owner` becomes `pub`)
- Create: `crates/winsys/tests/service_pipe.rs`

- [x] **Step 1: Write the failing tests** (`crates/winsys/tests/service_pipe.rs`; Windows only, run over SSH as `winvpn-dev`)

```rust
//! The service endpoint's DACL and the client's trust (run as a standard user: the server is owned by this user,
//! the production shape is checked by the admin test at the end).
#![cfg(windows)]

use macvpn_winsys::pipe::{self, Endpoint, ServerTrust};
use macvpn_winsys::sid::Sid;
use std::io::{Read, Write};
use std::time::Duration;

fn name() -> String {
    format!(r"\\.\pipe\WinVPN-test-{}", uuid::Uuid::new_v4())
}

#[test]
fn the_test_endpoint_grants_clients_no_create_instance_right() {
    let n = name();
    let l = pipe::Listener::bind_endpoint(&n, Endpoint::ServiceForTests).unwrap();
    let dacl = l.dacl_masks().unwrap();
    let interactive = Sid::interactive().to_string();
    let entry = dacl.iter().find(|e| e.sid == interactive).expect("INTERACTIVE is granted");
    assert!(entry.allow);
    assert_eq!(entry.mask & pipe::FILE_CREATE_PIPE_INSTANCE, 0, "{:#x}", entry.mask);
    assert_eq!(entry.mask & (pipe::WRITE_DAC | pipe::WRITE_OWNER), 0);
    assert_eq!(entry.mask, pipe::SERVICE_CLIENT_ACCESS);
}

#[test]
fn a_client_trusting_local_system_refuses_a_user_owned_pipe() {
    let n = name();
    let _l = pipe::Listener::bind_endpoint(&n, Endpoint::ServiceForTests).unwrap();
    let e = pipe::connect_with(&n, Duration::from_secs(2), ServerTrust::LocalSystem).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(e.to_string(), pipe::NOT_THE_SERVICE);
}

#[test]
fn a_same_user_client_talks_to_the_test_endpoint() {
    let n = name();
    let l = pipe::Listener::bind_endpoint(&n, Endpoint::ServiceForTests).unwrap();
    let server = std::thread::spawn(move || {
        let (s, peer) = loop {
            if let Some(c) = l.accept(Duration::from_millis(100)).unwrap() {
                break c;
            }
        };
        assert_eq!(peer.unwrap().sid, Sid::current_user().unwrap());
        let mut buf = [0u8; 4];
        let mut s2 = s.clone();
        s2.read_exact(&mut buf).unwrap();
        s2.write_all(&buf).unwrap();
    });
    let mut c = pipe::connect_with(&n, Duration::from_secs(2), ServerTrust::SameUser).unwrap();
    c.write_all(b"ping").unwrap();
    let mut back = [0u8; 4];
    c.read_exact(&mut back).unwrap();
    assert_eq!(&back, b"ping");
    server.join().unwrap();
}

#[test]
fn the_production_endpoint_needs_local_system() {
    // As a standard user the owner cannot be SYSTEM: binding the production shape fails closed.
    let e = pipe::Listener::bind_endpoint(&name(), Endpoint::Service).unwrap_err();
    assert_eq!(e.kind(), std::io::ErrorKind::PermissionDenied);
}

#[test]
#[ignore = "admin: needs the installed WinVPN Service (CI windows-admin job, or the maintainer in an elevated Git Bash)"]
fn admin_the_installed_service_pipe_is_owned_by_system() {
    let c = pipe::connect_with(r"\\.\pipe\WinVPN", Duration::from_secs(5), ServerTrust::LocalSystem).unwrap();
    drop(c);
    let dacl = pipe::dacl_of_name(r"\\.\pipe\WinVPN").unwrap();
    let interactive = Sid::interactive().to_string();
    let network = Sid::network().to_string();
    assert!(dacl.iter().any(|e| !e.allow && e.sid == network));
    assert!(dacl.iter().any(|e| e.allow && e.sid == interactive && e.mask == pipe::SERVICE_CLIENT_ACCESS));
    assert!(dacl.iter().all(|e| !e.allow || e.sid == interactive || e.sid == Sid::local_system().to_string()));
}
```

Add `admin_the_installed_service_pipe_is_owned_by_system` to `scripts/ignored-everywhere.txt`. `uuid` is already a dev-dependency of winsys? If not, add `uuid = { version = "1.26.1", features = ["v4"] }` under `[dev-dependencies]` (in `Cargo.lock` already).

- [x] **Step 2: Run them to verify they fail**

Run: `scripts/win-remote.sh run 'cargo test --locked -p macvpn-winsys --test service_pipe'`
Expected: FAIL to compile (`Endpoint`, `connect_with`, `ServerTrust`, `dacl_masks` do not exist).

- [x] **Step 3: Implement** (in `crates/winsys/src/pipe.rs`)

```rust
/// What a client of the service endpoint may do: read, write data, read the security descriptor (to check the
/// owner), synchronize. Not `FILE_APPEND_DATA` (= `FILE_CREATE_PIPE_INSTANCE`: a rogue instance of the service's
/// name), not `WRITE_DAC` / `WRITE_OWNER`.
pub const SERVICE_CLIENT_ACCESS: u32 = FILE_GENERIC_READ | FILE_WRITE_DATA;
pub const FILE_CREATE_PIPE_INSTANCE: u32 = 0x0004;
pub const WRITE_DAC: u32 = 0x0004_0000;
pub const WRITE_OWNER: u32 = 0x0008_0000;
/// The message of the `PermissionDenied` error for a service pipe not owned by SYSTEM.
pub const NOT_THE_SERVICE: &str = "the pipe is not served by the WinVPN Service";

/// Which descriptor a listener's instances get.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endpoint {
    /// A per-user pipe (the control API, single instance): [`Listener::bind_with`]'s descriptor.
    User(NetworkLogons),
    /// The WinVPN Service: owner SYSTEM (the process must run as LocalSystem, else `PermissionDenied`); deny
    /// NETWORK; allow SYSTEM all; allow INTERACTIVE [`SERVICE_CLIENT_ACCESS`].
    Service,
    /// The test-mode service: owner = this user, who also gets all access (to create instances); INTERACTIVE as
    /// above; network logons allowed (the tests run over SSH).
    ServiceForTests,
}

/// Whom a client trusts to serve the pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerTrust {
    /// The server process runs as this user ([`connect`]'s rule).
    SameUser,
    /// The pipe object is owned by `NT AUTHORITY\SYSTEM`; opened with [`SERVICE_CLIENT_ACCESS`].
    LocalSystem,
}

/// One ACE as the tests and the review see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AceSummary {
    pub allow: bool,
    pub sid: String,
    pub mask: u32,
}

fn endpoint_descriptor(endpoint: Endpoint) -> io::Result<Box<Descriptor>> {
    match endpoint {
        Endpoint::User(network) => descriptor(network),
        Endpoint::Service => {
            let (system, interactive, network) = (Sid::local_system(), Sid::interactive(), Sid::network());
            if Sid::current_user()? != system {
                return Err(io::Error::new(ErrorKind::PermissionDenied, "the service endpoint needs LocalSystem"));
            }
            let acl = Acl::new(
                &[
                    Ace::Deny(&network, FILE_ALL_ACCESS),
                    Ace::Allow(&system, FILE_ALL_ACCESS),
                    Ace::Allow(&interactive, SERVICE_CLIENT_ACCESS),
                ],
                0,
            )?;
            Descriptor::new(system, acl)
        }
        Endpoint::ServiceForTests => {
            let (user, system, interactive) = (Sid::current_user()?, Sid::local_system(), Sid::interactive());
            let acl = Acl::new(
                &[
                    Ace::Allow(&user, FILE_ALL_ACCESS),
                    Ace::Allow(&system, FILE_ALL_ACCESS),
                    Ace::Allow(&interactive, SERVICE_CLIENT_ACCESS),
                ],
                0,
            )?;
            Descriptor::new(user, acl)
        }
    }
}
```

`Listener::bind_with(name, network)` becomes `Listener::bind_endpoint(name, Endpoint::User(network))`; add `pub fn bind_endpoint(name: &str, endpoint: Endpoint) -> io::Result<Listener>` with the body of today's `bind_with` using `endpoint_descriptor(endpoint)?` (keep `bind` and `bind_with` as thin wrappers so 2a's callers do not change). Add `pub fn dacl_masks(&self) -> io::Result<Vec<AceSummary>>` (like `dacl_summary`, with masks) and `pub fn dacl_of_name(name) -> io::Result<Vec<AceSummary>>` (opens the name with `READ_CONTROL` only and reads the DACL; for the admin test). Extend `file::dacl_entries` into `file::dacl_aces(h, kernel_object) -> io::Result<Vec<AceSummary>>` (reading `ACCESS_ALLOWED_ACE.Mask` too) and keep `dacl_entries` as a map over it.

The client:

```rust
/// [`connect`] with the choice of [`ServerTrust`].
pub fn connect_with(name: &str, timeout: Duration, trust: ServerTrust) -> io::Result<PipeStream> {
    match trust {
        ServerTrust::SameUser => connect(name, timeout),
        ServerTrust::LocalSystem => connect_service(name, timeout),
    }
}

fn connect_service(name: &str, timeout: Duration) -> io::Result<PipeStream> {
    let wide_name = local_name(name)?;
    let deadline = Instant::now() + timeout;
    loop {
        // SAFETY: `wide_name` is NUL-terminated; no security attributes, no template.
        let h = unsafe {
            CreateFileW(
                wide_name.as_ptr(),
                SERVICE_CLIENT_ACCESS,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                std::ptr::null_mut(),
            )
        };
        if h != INVALID_HANDLE_VALUE {
            let pipe = owned(h)?;
            let not_the_service = || io::Error::new(ErrorKind::PermissionDenied, NOT_THE_SERVICE);
            // The pipe object's owner: only SYSTEM (with SeRestorePrivilege) can make SYSTEM an object's owner.
            let owner = crate::file::kernel_object_owner(pipe.as_raw_handle()).map_err(|_| not_the_service())?;
            if owner != Sid::local_system() {
                return Err(not_the_service());
            }
            return Ok(PipeStream::new(pipe));
        }
        // SAFETY: no preconditions.
        let error = unsafe { GetLastError() };
        if error != ERROR_PIPE_BUSY {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::from(ErrorKind::TimedOut));
        }
        // SAFETY: `wide_name` is NUL-terminated.
        unsafe { WaitNamedPipeW(wide_name.as_ptr(), millis(left)) };
    }
}
```

`Sid::interactive()` = `well_known(WinInteractiveSid)` (S-1-5-4); `Sid::builtin_administrators()` = `well_known(WinBuiltinAdministratorsSid)` (S-1-5-32-544, used by Task 4). Add the features `Win32_Security` items already enabled; `FILE_GENERIC_READ` and `FILE_WRITE_DATA` are in `Win32_Storage_FileSystem`.

- [x] **Step 4: Run the tests to verify they pass**

Run: `scripts/check-windows.sh && scripts/win-remote.sh run 'cargo test --locked -p macvpn-winsys' && scripts/win-remote.sh test`
Expected: PASS; `service_pipe` 4 passed, 1 ignored; 2a's pipe tests unchanged.

- [x] **Step 5: Commit**

```bash
git add crates/winsys scripts/ignored-everywhere.txt
git commit -m "feat(winsys): the WinVPN Service's pipe endpoint and its client trust" -m "Endpoint::Service: owner SYSTEM, deny NETWORK, INTERACTIVE may read and write data but never create an instance or change the DACL. Clients of the service open with FILE_GENERIC_READ | FILE_WRITE_DATA and refuse a pipe not owned by SYSTEM before sending anything. ServiceForTests serves the debug console service over SSH." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**As built (Task 3):** `pipe::{Endpoint, ServerTrust, SERVICE_CLIENT_ACCESS, FILE_CREATE_PIPE_INSTANCE, WRITE_DAC, WRITE_OWNER, NOT_THE_SERVICE, connect_with, dacl_of_name, Listener::{bind_endpoint, dacl_masks}}` as planned (the three rights constants re-export `windows-sys`' values). `AceSummary` lives in `file` (re-exported as `pipe::AceSummary`) and already has `flags: u8` (Task 4's `acl_check`); `file::dacl_aces(h, kernel_object)` is `pub(crate)`, `dacl_entries` maps over it. `file::kernel_object_owner` is `pub` and takes a `BorrowedHandle` (not a raw `HANDLE`). `Listener` implements `Debug` (the plan's `unwrap_err` on `bind_endpoint` needs it). `Endpoint::ServiceForTests` is refused in a LocalSystem process (a SYSTEM-owned pipe always has the production DACL). The SYSTEM-owner path is testable as a standard user: the private `service_descriptor(owner)` (the production DACL with any owner) and `connect_owned_by(name, timeout, expected_owner)` (the service client with any expected owner) are what `Endpoint::Service` and `ServerTrust::LocalSystem` call with SYSTEM; the unit tests in `pipe.rs` run them with this user (the shape on a real pipe; the network deny; a holder of the client grant can open, talk and be identified but cannot create an instance or open with `GENERIC_WRITE`; another owner is refused before a byte is sent; `check_owner` fails closed). `dacl_of_name` waits at most 5 s for a free instance and opens with `READ_CONTROL` and identification level only.

## Task 4: `winsys`: Authenticode, file versions, admin-only paths, safe DLL loading

**Goal:** the four read-only checks the service makes before it trusts a binary, and the hardened DLL loader. Each runs as a standard user, so the tests run over SSH.

**Files:**
- Create: `crates/winsys/src/{trust,version,acl_check,dll}.rs`, `crates/winsys/tests/trust.rs`
- Modify: `crates/winsys/src/lib.rs` (the four `pub mod` lines), `crates/winsys/Cargo.toml` (features `Win32_Security_WinTrust`, `Win32_Security_Cryptography` (already), `Win32_System_LibraryLoader`, `Win32_Storage_FileSystem` (already); shared with Task 3: union)

- [x] **Step 1: Write the failing tests** (`crates/winsys/tests/trust.rs`)

```rust
//! Authenticode, file versions, admin-only paths and DLL loading, on files every Windows machine (and Git for
//! Windows, which the test machine and CI have) carries.
#![cfg(windows)]

use macvpn_winsys::{acl_check, dll, trust, version};
use std::path::{Path, PathBuf};

fn git_exe() -> PathBuf {
    // Embedded Authenticode signature (Git for Windows' binaries are signed by their maintainer).
    PathBuf::from(r"C:\Program Files\Git\cmd\git.exe")
}

fn temp_copy(src: &Path) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("winsys-trust-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    let to = dir.join(src.file_name().unwrap());
    std::fs::copy(src, &to).unwrap();
    to
}

#[test]
fn a_signed_binary_names_its_signer() {
    let s = trust::verify_signature(&git_exe()).unwrap();
    assert!(!s.subject.is_empty());
}

#[test]
fn a_modified_copy_is_not_trusted() {
    let copy = temp_copy(&git_exe());
    let mut bytes = std::fs::read(&copy).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF;
    std::fs::write(&copy, &bytes).unwrap();
    assert!(trust::verify_signature(&copy).is_err());
    let _ = std::fs::remove_dir_all(copy.parent().unwrap());
}

#[test]
fn an_unsigned_file_is_not_trusted() {
    let dir = std::env::temp_dir().join(format!("winsys-trust-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    let f = dir.join("plain.exe");
    std::fs::write(&f, b"MZ not really").unwrap();
    assert!(trust::verify_signature(&f).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn file_versions_are_read() {
    let v = version::file_version(Path::new(r"C:\Windows\System32\kernel32.dll")).unwrap();
    assert!(v.0 >= 10, "{v:?}");
    assert!(version::file_version(Path::new(r"C:\does-not-exist.exe")).is_err());
}

#[test]
fn system32_is_admin_only_and_a_temp_dir_is_not() {
    assert!(acl_check::is_admin_only(Path::new(r"C:\Windows\System32\kernel32.dll")).unwrap());
    let copy = temp_copy(&git_exe());
    assert!(!acl_check::is_admin_only(&copy).unwrap());
    let _ = std::fs::remove_dir_all(copy.parent().unwrap());
    assert!(acl_check::is_admin_only(Path::new("relative.exe")).is_err());
}

#[test]
fn dlls_load_only_by_absolute_path() {
    dll::harden_process_search();
    let lib = dll::Library::load(Path::new(r"C:\Windows\System32\version.dll")).unwrap();
    assert!(lib.symbol(c"GetFileVersionInfoSizeW").is_ok());
    assert!(lib.symbol(c"NoSuchExport").is_err());
    assert!(dll::Library::load(Path::new("version.dll")).is_err());
}
```

- [x] **Step 2: Run them to verify they fail**

Run: `scripts/win-remote.sh run 'cargo test --locked -p macvpn-winsys --test trust'`
Expected: FAIL to compile (modules missing).

- [x] **Step 3: Implement**

`trust.rs`:

```rust
//! Authenticode: `WinVerifyTrust` with the generic verify action on a file with an embedded signature (no
//! catalog), revocation not checked online (`WTD_REVOKE_NONE`, `WTD_CACHE_ONLY_URL_RETRIEVAL`: the service must not
//! wait for the network), then the signer certificate's simple display name. A file that is not signed, whose hash
//! does not match, or whose chain does not reach a trusted root is an error (fail closed).

use crate::util::wide_path;
use std::io;
use std::path::Path;
use windows_sys::Win32::Security::Cryptography::{CERT_NAME_SIMPLE_DISPLAY_TYPE, CertGetNameStringW};
use windows_sys::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL,
    WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signer {
    /// The signer certificate's simple display name (its CN), e.g. `OpenVPN Inc.`.
    pub subject: String,
}

pub fn verify_signature(path: &Path) -> io::Result<Signer> {
    if !path.is_absolute() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "an absolute path is required"));
    }
    let wpath = wide_path(path)?;
    // SAFETY: plain data; every pointer field is set below or null.
    let mut file: WINTRUST_FILE_INFO = unsafe { std::mem::zeroed() };
    file.cbStruct = size_of::<WINTRUST_FILE_INFO>() as u32;
    file.pcwszFilePath = wpath.as_ptr();
    // SAFETY: as above.
    let mut data: WINTRUST_DATA = unsafe { std::mem::zeroed() };
    data.cbStruct = size_of::<WINTRUST_DATA>() as u32;
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.Anonymous = WINTRUST_DATA_0 { pFile: &mut file };
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: `data` and `file` (and the path they point to) live across both calls; the state is closed below.
    let status = unsafe { WinVerifyTrust(std::ptr::null_mut(), &mut action, (&mut data as *mut WINTRUST_DATA).cast()) };
    let subject = if status == 0 { signer_name(&data) } else { Err(io::Error::from_raw_os_error(status)) };
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: closes the state the verify call opened (also after a failure, as the documentation requires).
    unsafe { WinVerifyTrust(std::ptr::null_mut(), &mut action, (&mut data as *mut WINTRUST_DATA).cast()) };
    Ok(Signer { subject: subject? })
}

fn signer_name(data: &WINTRUST_DATA) -> io::Result<String> {
    let fail = || io::Error::new(io::ErrorKind::InvalidData, "no signer certificate");
    // SAFETY: `hWVTStateData` is the open state of a successful verify; the provider data and the signer it returns
    // are owned by that state and stay valid until it is closed (after this function).
    unsafe {
        let prov = WTHelperProvDataFromStateData(data.hWVTStateData);
        if prov.is_null() {
            return Err(fail());
        }
        let signer = WTHelperGetProvSignerFromChain(prov, 0, 0, 0);
        if signer.is_null() || (*signer).csCertChain == 0 || (*signer).pasCertChain.is_null() {
            return Err(fail());
        }
        let cert = (*(*signer).pasCertChain).pCert;
        let mut buf = [0u16; 256];
        let n = CertGetNameStringW(cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, std::ptr::null(), buf.as_mut_ptr(), buf.len() as u32);
        if n <= 1 {
            return Err(fail());
        }
        Ok(String::from_utf16_lossy(&buf[..(n as usize - 1)]))
    }
}
```

`version.rs`: `pub fn file_version(path: &Path) -> io::Result<(u16, u16, u16, u16)>` with `GetFileVersionInfoSizeW` / `GetFileVersionInfoW` into a `Vec<u8>` / `VerQueryValueW(buf, "\\")` → `VS_FIXEDFILEINFO` (check `dwSignature == 0xFEEF04BD`), returning `(HIWORD(dwFileVersionMS), LOWORD(…MS), HIWORD(…LS), LOWORD(…LS))`.

`acl_check.rs`:

```rust
//! "Only administrators can change this file": the file and every ancestor directory up to the volume root are
//! owned by SYSTEM, Administrators or TrustedInstaller, and their DACLs grant no write, append, delete, WRITE_DAC,
//! WRITE_OWNER, GENERIC_WRITE or GENERIC_ALL to anyone else (an inherit-only ACE for CREATOR OWNER is allowed: it
//! applies to objects an administrator creates). Reparse points are not followed: a link in the chain is refused.

pub fn is_admin_only(path: &Path) -> io::Result<bool>
```

Implementation: refuse a relative path (`InvalidInput`); for `path` and each `ancestor()` (stopping at the root), open with `file::open_metadata(p, false)` (no reparse following; a name-surrogate reparse tag → `Ok(false)`), read the owner (`file::info(&f)?.owner`) and the ACEs (`file::dacl_aces(handle, false)`), and apply the rule with the trusted SIDs `S-1-5-18`, `S-1-5-32-544`, `S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464` (TrustedInstaller); the "write-ish" mask is `0x0002 | 0x0004 | 0x0040 | 0x00010000 | 0x00040000 | 0x00080000 | 0x40000000 | 0x10000000` (FILE_WRITE_DATA/ADD_FILE, FILE_APPEND_DATA/ADD_SUBDIRECTORY, FILE_DELETE_CHILD, DELETE, WRITE_DAC, WRITE_OWNER, GENERIC_WRITE, GENERIC_ALL); `CREATOR OWNER` (`S-1-3-0`) ACEs with `INHERIT_ONLY_ACE` are skipped (extend `AceSummary` with `flags` for this). Any read failure is an error (the caller treats it as "not admin-only").

`dll.rs`:

```rust
//! DLLs only from System32 and from where the caller says: `harden_process_search` removes the current directory
//! and PATH from the process' DLL search (`SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)`,
//! `SetDllDirectoryW("")`); `Library::load` takes an absolute path only and resolves the DLL's own imports from its
//! folder and System32 (`LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32`).

pub fn harden_process_search();
pub struct Library(HMODULE);           // FreeLibrary on drop; Send + Sync (a module handle is process-wide)
impl Library {
    pub fn load(path: &Path) -> io::Result<Library>;
    /// The export's address; calling it is the caller's `unsafe`.
    pub fn symbol(&self, name: &CStr) -> io::Result<*const core::ffi::c_void>;
}
```

`harden_process_search` asserts both calls succeeded (they cannot fail on Windows 10+; if they do, abort: the process must not run with an unsafe DLL search).

- [x] **Step 4: Run the tests to verify they pass**

Run: `scripts/check-windows.sh && scripts/win-remote.sh run 'cargo test --locked -p macvpn-winsys --test trust' && scripts/win-remote.sh test`
Expected: PASS (6 tests). Also print the signer of git.exe once (`cargo test … -- --nocapture` with a temporary `eprintln!`, removed before the commit) and note it in the commit body.

- [x] **Step 5: Commit**

```bash
git add crates/winsys
git commit -m "feat(winsys): Authenticode signer, file versions, admin-only paths, hardened DLL loading" -m "What the WinVPN Service checks before it runs openvpn.exe or loads wireguard.dll. All read-only and usable by a standard user; tested over SSH." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

*As built (2026-10-22):* the API is as above (`trust::{verify_signature, Signer { subject }}`, `version::file_version`, `acl_check::is_admin_only`, `dll::{harden_process_search, Library::{load, symbol}}`); the caller compares `Signer::subject` with its pin. All four take only a plain absolute drive path (`X:\a\b`, backslashes, no `.`/`..`, no ADS, no UNC or `\\?\`; `util::plain_absolute`), else `InvalidInput`. Changes from the listing: `WTHelperProvDataFromStateData` / `WTHelperGetProvSignerFromChain` need the windows-sys features `Win32_Security_Cryptography_Catalog` and `Win32_Security_Cryptography_Sip` as well; the signer name is read with a size query (no fixed buffer, a truncated name is refused) and a signer with `dwError ≠ 0` is refused; versions use `GetFileVersionInfo{Size,}ExW(FILE_VER_GET_NEUTRAL)` (the file's own resource, not a MUI satellite's) and Windows' own files report 6.2 to a process without a Windows 10 manifest (a compatibility shim; the build number is real), so the test checks the build. The admin-only rule as built skips **every** inherit-only ACE (not only CREATOR OWNER's: `C:\` carries `Authenticated Users:(OI)(CI)(IO)(M)`) and allows add-subdirectory (`FILE_APPEND_DATA`) on directories above the file's own (`C:\` grants `Authenticated Users:(AD)`); the file and its directory get the full mask; deny ACEs are skipped; an ACE of another type that grants a write right refuses; app execution aliases are refused like name surrogates. No `AceSummary`/`dacl_aces`: `file::AceEntry` became `pub(crate)` with `file::owner_and_aces`. The tests use the 2a `Scratch` directory (no `uuid` dev-dependency). Signatures on the test machine (Windows 11 26300): embedded in `git.exe` ("Johannes Schindelin"), `System32\{kernel32,version,wintrust}.dll`, `curl.exe`, `explorer.exe` ("Microsoft Windows" / "Microsoft 3rd Party Application Component"); catalog only in `System32\{cmd,notepad,msiexec}.exe` — refused, as a test pins.

## Task 5: the portable curl layer

**Goal:** the update check, the download and the HTTPS catalog fetch run the same code on macOS (`/usr/bin/curl`) and Windows (System32's `curl.exe`); macOS' argv, environment and behaviour stay byte for byte.

**Files:**
- Create: `crates/platform-api/src/curl/mod.rs` (`CommandRunner`, `CommandResult`, `CommandError`, `Curl` – the flavour), `crates/platform-api/src/curl/http.rs` (from `platform-mac/src/http.rs`), `crates/platform-api/src/curl/catalog.rs` (from `platform-mac/src/catalog_http.rs`), `crates/platform-mac/tests/curl_argv.rs`
- Modify: `crates/platform-api/src/lib.rs` (`pub mod curl;`), `crates/platform-api/Cargo.toml` (`uuid` with `v4`, already in the lock; `zeroize`), `crates/platform-mac/src/{http,catalog_http,command}.rs` (re-exports and the macOS flavour), `crates/platform-mac/src/api/*.rs` (imports only)

- [x] **Step 1: Pin macOS' argv and environment before the move** (`crates/platform-mac/tests/curl_argv.rs`)

```rust
//! Golden argv of every curl call MacVPN makes (written before the curl layer moved to platform-api; it must stay
//! green unchanged after the move).
#![cfg(target_os = "macos")]

use macvpn_platform_mac::command::{CommandError, CommandResult, CommandRunner};
use macvpn_platform_mac::http::{CurlHttpClient, HttpClient};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Recorder(Mutex<Vec<(String, Vec<String>, Option<String>)>>);

impl CommandRunner for Arc<Recorder> {
    fn run(&self, exe: &str, args: &[String], stdin: Option<&str>) -> Result<CommandResult, CommandError> {
        self.0.lock().unwrap().push((exe.to_string(), args.to_vec(), stdin.map(String::from)));
        Ok(CommandResult::stdout("200 "))
    }
}

/// The `--output` path is a fresh private directory each time: compare it by shape only.
fn normalize(args: &[String]) -> Vec<String> {
    let mut out = args.to_vec();
    if let Some(i) = out.iter().position(|a| a == "--output") {
        out[i + 1] = "<OUT>".into();
    }
    out
}

#[test]
fn the_release_query_argv_is_pinned() {
    let rec = Arc::new(Recorder::default());
    let client = CurlHttpClient::new(Box::new(rec.clone()));
    let _ = client.get("https://api.github.com/repositories/1/releases/latest");
    let seen = rec.0.lock().unwrap();
    assert_eq!(seen[0].0, "/usr/bin/curl");
    assert_eq!(
        normalize(&seen[0].1),
        [
            "-q", "--globoff", "--silent", "--show-error", "--proto", "=https", "--max-redirs", "0", "--globoff",
            "--connect-timeout", "30", "--max-time", "30", "--user-agent", "MacVPN-Updater", "--header",
            "Accept: application/vnd.github+json", "--write-out", "%{http_code} %{redirect_url}", "--output", "<OUT>",
            "--", "https://api.github.com/repositories/1/releases/latest",
        ]
    );
    assert_eq!(seen[0].2, None);
}

#[test]
fn the_environment_is_pinned() {
    let env = CurlHttpClient::environment();
    assert_eq!(env.keys().cloned().collect::<Vec<_>>(), ["HOME", "LANG", "PATH"]);
    assert_eq!(env["PATH"], "/usr/bin:/bin");
    assert_eq!(env["LANG"], "C");
}
```

Run it first: `cargo test --locked -p macvpn-platform-mac --test curl_argv` → PASS on today's code (if an expected value differs, the test is wrong: copy today's argv, not the plan's guess, and say so in the commit). Then also note the existing `crates/platform-mac/tests/catalog_http.rs` (its `FakeCurl` records every hop's argv and stdin) and `tests/update_installer.rs`: they are the catalog's and the download's golden tests and must pass unchanged after the move.

- [x] **Step 2: Commit the pin** (`test(platform-mac): pin curl's argv and environment before the move`).

- [x] **Step 3: Move** (a mechanical move; the code is today's, only these changes):
  - `macvpn_platform_api::curl::{CommandRunner, CommandResult, CommandError}`: moved verbatim from `platform-mac/src/command.rs` (the trait with `run` and `run_bytes`, the two types with their `Display` texts). `platform-mac/src/command.rs` keeps `ProcessCommandRunner`, `RunnerTimeouts`, `CancelToken` and adds `pub use macvpn_platform_api::curl::{CommandError, CommandResult, CommandRunner};`.
  - `curl/mod.rs` adds the flavour:

```rust
/// Where curl is and how it runs on this OS.
#[derive(Debug, Clone)]
pub struct Curl {
    /// Absolute (`/usr/bin/curl`; `C:\Windows\System32\curl.exe`).
    pub executable: String,
    /// Arguments after the shared base arguments (`--ssl-revoke-best-effort` on Windows; none on macOS).
    pub extra_args: Vec<&'static str>,
    /// Makes a fresh private (owner-only) directory `<temp>/<prefix>.<random>` and returns it; the caller removes it.
    pub private_dir: fn(prefix: &str) -> Result<std::path::PathBuf, String>,
    /// The directory where a finished download is moved (`<user temp>`).
    pub temp_base: fn() -> Result<std::path::PathBuf, String>,
}
```

  - `curl/http.rs`: `HttpClient`, `HttpResponse`, `HttpError`, `CurlHttpClient { runner, curl: Curl, max_redirects }` with `CurlHttpClient::with_curl(runner, curl)` (the flavour-taking constructor; macOS' `new(runner)` = `with_curl(runner, mac_curl())`), `base_arguments(accept, max_time, user_agent, extra)` (the `extra` args go right after `--max-time <n>`, so macOS' list, with `extra` empty, is unchanged), `parse_trailer`, `canonical_redirect_url`, `remove_output`, `with_private_directory(curl, prefix, body)`. `CURL` and `environment()` are no longer constants here: they are the flavour's.
  - `curl/catalog.rs`: `CurlCatalogFetcher { runner, curl, user_agent, test_ca }` and its helpers, verbatim but for `self.curl.executable` instead of `CURL` and `CurlHttpClient::base_arguments(…, &self.curl.extra_args)`. Its `with_test_ca` stays behind the platform-mac `test-support` feature: move the feature to platform-api (`[features] test-support = []`) and have platform-mac's `test-support` enable `macvpn-platform-api/test-support`.
  - `platform-mac/src/http.rs` becomes the macOS flavour and re-exports: `pub use macvpn_platform_api::curl::http::*;`, `pub fn mac_curl() -> Curl` (`/usr/bin/curl`, no extra args, `temp_dir::make_private_temp_directory` + `temporary_directory`), `CurlHttpClient::environment()` and `runner()` as today (they are macOS'; keep their bodies and doc comments), and `impl Default for CurlHttpClient` constructing with `mac_curl()`. The same for `catalog_http.rs`.
  - Nothing in `app/` or `app-core` changes (they reach the curl layer only through `ReleaseSource`, `Updater` and `CatalogFetcher`).

- [x] **Step 4: Run every pin**

Run: `cargo test --locked -p macvpn-platform-mac --test curl_argv --test catalog_http --test update_installer && CI=1 cargo test --workspace --locked && cargo clippy --workspace --all-targets --locked -- -D warnings && scripts/check-windows.sh`
Expected: PASS, the three test files unchanged since Step 2 (`git diff HEAD~1 -- crates/platform-mac/tests` is empty).

- [x] **Step 5: Commit**

```bash
git add crates/platform-api crates/platform-mac
git commit -m "refactor: the curl layer moves to platform-api for both OSes" -m "The redirect policy, canonical URLs, size caps, conditional GET and the bearer token's origin rule exist once; a Curl flavour names the executable, extra arguments and private directories. macOS' argv and environment are pinned by curl_argv.rs (written before the move) and the catalog_http and update_installer tests, all unchanged." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**As built (Task 5):** platform-mac's `CurlHttpClient` and `CurlCatalogFetcher` are thin newtypes over platform-api's (a re-export cannot take `impl Default` or the macOS-only `environment()` / `runner()`: the orphan rule), delegating `HttpClient` / `CatalogFetcher`; the macOS 3-argument `base_arguments` stays (the unchanged `catalog_http.rs` test calls it) over platform-api's 4-argument one. `curl_argv.rs` pins more than Step 1's sketch: the redirected download, the two-origin catalog fetch (token on stdin and validators only to the subscription origin) and the runner's 630 s limit; its recorder is a local `Runner` newtype (`impl CommandRunner for Arc<_>` breaks the orphan rule). `crates/platform-api/tests/curl_layer.rs` checks a Windows-like flavour (executable, `--ssl-revoke-best-effort` after `--max-time <n>`, temp base). The updater's and catalog's user agents (`MacVPN-Updater`, `MacVPN-Catalog/<v>`) moved verbatim; Tasks 18 and 19 decide WinVPN's.

## Task 6: `LogSource`: the log tail over any source

**Goal:** the Log tab reads a connection's log through a source: on macOS the root layer's file exactly as before, on Windows the service (Task 16). The tail's rules (the 256 KiB first window, the reset on a new file or a shorter file, partial lines, the UTF-8-safe flush) stay in one place.

**Files:**
- Modify: `crates/core/src/log.rs` (`LogSource`, `LogRead`, `LogIdentity`, `FileLogSource`, `LogTailer::{new, with_source, read_new}`), `crates/core/tests/log_status.rs` (one new test)
- Modify: `crates/platform-api/src/helper.rs` (`HelperClient::log_source`), `crates/app-core/src/logs.rs` (`LogFeed::new` takes the source), `app/src-tauri/src/manage.rs` (`log_subscribe`), the app-core tests that build a `LogFeed` (`crates/app-core/tests/log_view.rs`)

- [x] **Step 1: Write the failing test** (append to `crates/core/tests/log_status.rs`)

```rust
use macvpn_core::log::{LogIdentity, LogRead, LogSource, LogTailer};

/// A log kept in memory, as the WinVPN Service serves it: (generation, bytes).
struct Memory(std::sync::Arc<std::sync::Mutex<(u64, Vec<u8>)>>);

impl LogSource for Memory {
    fn read(&mut self, offset: u64, max: usize) -> Option<LogRead> {
        let g = self.0.lock().unwrap();
        let size = g.1.len() as u64;
        let from = offset.min(size) as usize;
        let to = (from + max).min(g.1.len());
        Some(LogRead { identity: Some(LogIdentity::Generation(g.0)), size, start: from as u64, data: g.1[from..to].to_vec() })
    }
}

#[test]
fn a_tailer_over_another_source_follows_the_same_rules() {
    let shared = std::sync::Arc::new(std::sync::Mutex::new((1u64, b"one\ntwo\npart".to_vec())));
    let mut t = LogTailer::with_source(Box::new(Memory(shared.clone())));
    assert_eq!(t.read_new(), ["one", "two"]);
    shared.lock().unwrap().1.extend_from_slice(b"ial\n");
    assert_eq!(t.read_new(), ["partial"]);
    assert_eq!(t.read_new(), Vec::<String>::new());
    // A new generation (the service started a new log for a new connect): from the start again.
    *shared.lock().unwrap() = (2, b"fresh\n".to_vec());
    assert_eq!(t.read_new(), ["fresh"]);
    // A large first read keeps only the last 256 KiB, without its first (cut) line.
    let mut big = vec![b'x'; 300 * 1024];
    big.extend_from_slice(b"\nlast\n");
    *shared.lock().unwrap() = (3, big);
    assert_eq!(t.read_new().last().map(String::as_str), Some("last"));
}
```

Run: `cargo test --locked -p macvpn-core --test log_status` → FAIL to compile (no `LogSource`).

- [x] **Step 2: Implement** (`crates/core/src/log.rs`)

```rust
/// What identifies one log file: the file id on macOS (the inode check), the service's generation on Windows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogIdentity {
    File(fsx::FileId),
    Generation(u64),
}

/// One read of a log: its identity, its size, and the bytes from `start` (at most what was asked).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogRead {
    pub identity: Option<LogIdentity>,
    pub size: u64,
    pub start: u64,
    pub data: Vec<u8>,
}

/// Where a [`LogTailer`] reads from.
pub trait LogSource: Send {
    /// The bytes from `offset` (at most `max`; none when `offset >= size`). `None`: there is no log (yet).
    fn read(&mut self, offset: u64, max: usize) -> Option<LogRead>;
}

/// The file at `path` (macOS: `/var/log/macvpn/<id>.log`), opened for each read, as the tailer always did.
pub struct FileLogSource {
    pub path: PathBuf,
}

impl LogSource for FileLogSource {
    fn read(&mut self, offset: u64, max: usize) -> Option<LogRead> {
        let mut file = File::open(&self.path).ok()?;
        let identity = fsx::stat(&file).ok().and_then(|s| fsx::file_id(&s)).map(LogIdentity::File);
        let size = file.seek(SeekFrom::End(0)).unwrap_or(0);
        let mut data = Vec::new();
        if offset < size && file.seek(SeekFrom::Start(offset)).is_ok() {
            let _ = (&mut file).take(max as u64).read_to_end(&mut data);
        }
        Some(LogRead { identity, size, start: offset, data })
    }
}
```

`LogTailer` keeps `pub path` (set by `new`, empty for `with_source`), gets `source: Box<dyn LogSource>` and `identity: Option<LogIdentity>` instead of `inode`, and `read_new` becomes:

```rust
    pub fn read_new(&mut self) -> Vec<String> {
        let Some(mut r) = self.source.read(self.offset, MAX_READ_BYTES) else { return Vec::new() };
        if let (Some(old), Some(new)) = (&self.identity, &r.identity)
            && old != new
        {
            self.offset = 0;
            self.partial.clear();
            self.discard_leading = false;
            self.started = false; // the 256 KB window applies to the new file too
        }
        self.identity = r.identity.clone();
        let size = r.size;
        if !self.started {
            self.started = true;
            if size > INITIAL_WINDOW {
                self.offset = size - INITIAL_WINDOW;
                self.discard_leading = true;
            }
        }
        if size < self.offset {
            self.offset = 0;
            self.partial.clear();
            self.discard_leading = false;
        }
        if size <= self.offset {
            return Vec::new();
        }
        // The window or a reset moved the offset after the read: read again from there (same log only).
        if r.start != self.offset {
            match self.source.read(self.offset, MAX_READ_BYTES) {
                Some(again) if again.identity == self.identity && again.start == self.offset => r = again,
                _ => return Vec::new(),
            }
        }
        let mut data = r.data;
        self.offset += data.len() as u64;
        // … unchanged from here: discard_leading, partial, lines, the MAX_PARTIAL_BYTES flush …
    }
```

`LogTailer::new(path)` = `with_source(Box::new(FileLogSource { path: path.clone() }))` with `path` kept in the field. The existing `log_status.rs` tests (`tailer_returns_only_complete_new_lines`, `first_read_is_bounded_to_last_256kb`, `inode_replacement_resets`, `overlong_line_without_newline_is_flushed`, `partial_flush_never_splits_multibyte_character`, `inode_replacement_reapplies_window`) are the macOS pin: unchanged and green.

`platform-api/src/helper.rs`:

```rust
    /// The connection's log as the Log tab reads it. Default: the file at [`Self::log_path`] (macOS); `None`: no
    /// log.
    fn log_source(&self, id: &Uuid) -> Option<Box<dyn macvpn_core::log::LogSource>> {
        self.log_path(id).map(|path| Box::new(macvpn_core::log::FileLogSource { path }) as Box<dyn macvpn_core::log::LogSource>)
    }
```

`LogFeed::new(c, source: Option<Box<dyn LogSource>>, native_logs)`: `Source::Tail(LogTailer::with_source(source.unwrap_or_else(|| Box::new(FileLogSource { path: PathBuf::new() }))))` for a non-native kind (an empty path opens nothing, as today's `unwrap_or_default()`). `manage.rs::log_subscribe`: `let source = crate::platform::get().helper_client().log_source(&c.id);` and `LogFeed::new(&c, source, …)`. Update `crates/app-core/tests/log_view.rs` call sites to pass `Some(Box::new(FileLogSource { path }))`.

- [x] **Step 3: Run the tests**

Run: `CI=1 cargo test --workspace --locked && cargo clippy --workspace --all-targets --locked -- -D warnings && cargo test --locked -p macvpn-app-core --test compat_1_4 && scripts/check-windows.sh`
Expected: PASS; no existing log test changed.

- [x] **Step 4: Commit**

```bash
git add crates/core/src/log.rs crates/core/tests/log_status.rs crates/platform-api/src/helper.rs crates/app-core app/src-tauri/src/manage.rs
git commit -m "refactor: the log tail reads through a LogSource" -m "macOS keeps reading /var/log/macvpn/<id>.log (FileLogSource, the default of HelperClient::log_source); the WinVPN Service will serve the log over its pipe. The tail's rules stay in LogTailer; the existing tailer tests are unchanged." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

## Task 7: helper shared moves (the OpenVPN log predicates, the in-process bridge)

**Goal:** what the Windows backend needs from the macOS backend is in `shared`, unchanged in behaviour: the OpenVPN log predicates and a `BridgeArgs` for a bridge that runs inside the service.

**Files:**
- Create: `crates/helper/src/shared/ovpn_log.rs`
- Modify: `crates/helper/src/shared/mod.rs`, `crates/helper/src/shared/bridge.rs`, `crates/helper/src/macos/log.rs`

- [x] **Step 1: The failing test** (in `crates/helper/src/shared/bridge.rs`'s test module)

```rust
    #[test]
    fn in_process_arguments_carry_only_what_the_bridge_uses() {
        let a = BridgeArgs::in_process("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", 420.0).unwrap();
        assert_eq!(a.id, "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0");
        assert_eq!(a.max_wait, 420.0);
        assert!(a.run.is_empty() && a.ui.is_empty());
        assert!(BridgeArgs::in_process("../x", 420.0).is_none());
        assert_eq!(BridgeArgs::in_process("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", 99999.0).unwrap().max_wait, 3600.0);
    }
```

Run: `cargo test --locked -p macvpn-helper in_process` → FAIL (no `in_process`).

- [x] **Step 2: Implement**

```rust
impl BridgeArgs {
    /// A bridge inside the WinVPN Service: no run or state directory, no user ids (the service keeps the state in
    /// memory and answers for the user over its pipe). `max_wait` clamped as `--max-wait` is.
    pub fn in_process(id: &str, max_wait: f64) -> Option<BridgeArgs> {
        let id = uuid_string(&parse_uuid(id)?);
        Some(BridgeArgs { id, run: String::new(), ui: String::new(), uid: 0, gid: 0, max_wait: max_wait.clamp(1.0, 3600.0) })
    }
}
```

Move `log_safe`, `ovpn_real_lines`, `ovpn_done`, `ovpn_auth_failed`, `ovpn_last_line`, `mentions_secret`, `is_blank` and the regexes they use (`DONE`, `ECHO`, `AUTH_NOT_FINAL`, and whatever `log_safe` needs) from `macos/log.rs` into `shared/ovpn_log.rs` verbatim (drop the `#[cfg(test)]` on `ovpn_auth_failed` and `ovpn_last_line`: the Windows engine uses them); `macos/log.rs` keeps its file functions (`flush_root_log`, `scan_root_log`, `ovpn_done_file`, …) and imports the predicates with `use crate::shared::ovpn_log::{…};` plus `pub use` for the names other macOS modules import from `log`. Move their unit tests along. `shared/mod.rs`: `pub mod ovpn_log;`. Also move `valid_status` (the strict `^(wait [0-9]{1,12}|ok|failed|cancelled|timeout)$` check of the bridge's `mgmt-status`) from `macos/openvpn.rs` to `shared::bridge::valid_status` (`pub`), with its test; `macos/openvpn.rs` calls it from there.

- [x] **Step 3: Run**

Run: `cargo test --locked -p macvpn-helper && MVPN_IMPL=rust scripts/test-root.sh && scripts/check-windows.sh`
Expected: PASS; `test-root.sh` 412 pass as before.

- [x] **Step 4: Commit**

```bash
git add crates/helper/src
git commit -m "refactor(helper): the OpenVPN log predicates and an in-process bridge in shared" -m "Moved verbatim from the macOS backend (its tests with them); macOS unchanged (test-root.sh)." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**As built:** `BridgeArgs::in_process` refuses a NaN `max_wait` (`f64::clamp` keeps NaN; fail closed), tested. The regexes `ECHO`, `DONE`, `AUTH_NOT_FINAL` are `pub(crate)` in `shared::ovpn_log` (macOS' file scanners use them); `mentions_secret` and `is_blank` are `pub`. `macos/log.rs` re-exports only `ovpn_done` (the one name another macOS module imports from `log`). The release `mvpn` of both macOS targets has the same string literals as before except the panic location `crates/helper/src/macos/log.rs` → `crates/helper/src/shared/ovpn_log.rs` (the regexes' `expect`).

## Task 8: the service core (pure request handling)

**Goal:** everything the WinVPN Service decides for a request, without Win32: parsing, the per-request language, ownership by SID, limits, validation with the shared validators, the masked per-connection log, status JSON, MFA answers and log slices. Compiled and tested on every OS with fake engines.

**Files:**
- Create: `crates/helper/src/windows/service.rs`, `crates/helper/src/windows/logs.rs`, `crates/helper/tests/service_core.rs`
- Modify: `crates/helper/src/windows/mod.rs` (module list; `main` unchanged in this task), `crates/helper/src/shared/limits.rs` (a const assertion), `crates/core/l10n/strings.json` (scope `mvpn`)

- [x] **Step 1: Write the failing tests** (`crates/helper/tests/service_core.rs`, every OS)

```rust
//! The WinVPN Service's request handling over fake engines (crates/helper/src/windows/service.rs).

use macvpn_core::l10n::{AppLanguage, with_language};
use macvpn_core::models::VPNKind;
use macvpn_core::service_proto::{EngineFacts, LogSlice, OpenVpnFacts, Request, SERVICE_VERSION, WireGuardFacts};
use macvpn_helper::windows::logs::FileLogStore;
use macvpn_helper::windows::service::{Caller, Engine, EngineState, Host, LogStore, Service, UpRequest};
use std::sync::Mutex;
use zeroize::Zeroizing;

const ID: &str = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";
const WG: &str = "[Interface]\nPrivateKey = bWFjdnBuLXRlc3QtcHJpdmF0ZS1rZXktMzJieXRlcyE=\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = bWFjdnBuLXRlc3QtcHVibGljLS1rZXktMzJieXRlcyE=\nAllowedIPs = 0.0.0.0/0\nEndpoint = vpn.example.com:51820\n";

#[derive(Default)]
struct Fake {
    up: Mutex<Vec<String>>,
    down: Mutex<Vec<String>>,
    fail_up: Option<String>,
}

impl Engine for Fake {
    fn up(&self, req: &UpRequest<'_>) -> Result<(), String> {
        req.log.line("starting");
        req.log.line(&format!("password is {}", String::from_utf8_lossy(&req.secrets.pass)));
        self.up.lock().unwrap().push(req.id.to_string());
        match &self.fail_up {
            Some(m) => Err(m.clone()),
            None => Ok(()),
        }
    }
    fn down(&self, id: &str) -> Result<(), String> {
        self.down.lock().unwrap().push(id.to_string());
        Ok(())
    }
    fn state(&self, id: &str) -> Option<EngineState> {
        self.up.lock().unwrap().iter().any(|u| u == id).then(|| EngineState {
            state: "connected",
            iface: "WinVPN0f1e2d3c".into(),
            ip: "10.0.0.2".into(),
            since: Some(1_700_000_000),
        })
    }
}

struct TestHost {
    wg: Fake,
    logs: FileLogStore,
    problem: Option<String>,
}

impl Host for TestHost {
    fn engine(&self, kind: VPNKind) -> Option<&dyn Engine> {
        (kind == VPNKind::Wireguard).then_some(&self.wg as &dyn Engine)
    }
    fn facts(&self) -> EngineFacts {
        EngineFacts {
            service_version: SERVICE_VERSION,
            problem: None,
            openvpn: OpenVpnFacts { version: None, path: None, dco: None, wintun: None, tap_windows6: None, problem: None },
            wireguard: WireGuardFacts { dll_version: Some("0.10.1".into()), problem: None },
        }
    }
    fn logs(&self) -> &dyn LogStore {
        &self.logs
    }
    fn problem(&self) -> Option<String> {
        self.problem.clone()
    }
}

fn service() -> (Service<TestHost>, tempdir::Dir) {
    let dir = tempdir::Dir::new();
    let host = TestHost { wg: Fake::default(), logs: FileLogStore::new(dir.path().to_path_buf()), problem: None };
    (Service::new(host), dir)
}

fn req(args: &[&str], body: &[u8]) -> Request {
    Request { args: args.iter().map(|s| s.to_string()).collect(), body: Zeroizing::new(body.to_vec()) }
}

fn framed(config: &str, secrets: &str) -> Vec<u8> {
    let mut v = format!("config {}\n{config}", config.len()).into_bytes();
    v.extend_from_slice(secrets.as_bytes());
    v
}

fn alice() -> Caller {
    Caller { sid: "S-1-5-21-1-2-3-1001".into() }
}

fn bob() -> Caller {
    Caller { sid: "S-1-5-21-1-2-3-1002".into() }
}

fn err(r: &macvpn_core::service_proto::Response) -> String {
    String::from_utf8_lossy(&r.stderr).trim_end().to_string()
}

mod tempdir {
    pub struct Dir(std::path::PathBuf);
    impl Dir {
        pub fn new() -> Dir {
            let p = std::env::temp_dir().join(format!("winvpn-service-core-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&p).unwrap();
            Dir(p)
        }
        pub fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[test]
fn version_and_engine_answer_anyone() {
    let (s, _d) = service();
    let r = s.handle(&alice(), &req(&["version"], b""));
    assert_eq!((r.code, r.stdout.as_slice()), (0, &b"1\n"[..]));
    let r = s.handle(&bob(), &req(&["engine"], b""));
    assert_eq!(EngineFacts::parse(&r.stdout).unwrap().wireguard.dll_version.as_deref(), Some("0.10.1"));
}

#[test]
fn up_validates_owns_and_status_shows_only_the_owner() {
    with_language(AppLanguage::En, || {
        let (s, _d) = service();
        let r = s.handle(&alice(), &req(&["up", "wireguard", ID], &framed(WG, "")));
        assert_eq!(r.code, 0, "{}", err(&r));
        let mine = String::from_utf8(s.handle(&alice(), &req(&["status"], b"")).stdout).unwrap();
        assert!(mine.contains(ID) && mine.contains("\"connected\""), "{mine}");
        let theirs = s.handle(&bob(), &req(&["status"], b""));
        assert_eq!(theirs.stdout, b"[]\n");
        // Bob can neither take it down, nor bring it up, nor read its log: the same answer as an unknown ID.
        for r in [
            s.handle(&bob(), &req(&["down", "wireguard", ID], b"")),
            s.handle(&bob(), &req(&["up", "wireguard", ID], &framed(WG, ""))),
            s.handle(&bob(), &req(&["log", ID, "0"], b"")),
            s.handle(&bob(), &req(&["auth-state", ID], b"")),
        ] {
            assert_eq!((r.code, err(&r).as_str()), (1, "Invalid ID"));
        }
        let r = s.handle(&alice(), &req(&["down", "wireguard", ID], b""));
        assert_eq!(r.code, 0);
        assert_eq!(s.handle(&alice(), &req(&["status"], b"")).stdout, b"[]\n");
    });
}

#[test]
fn an_invalid_config_is_refused_before_the_engine_runs() {
    with_language(AppLanguage::En, || {
        let (s, _d) = service();
        let bad = WG.replace("Address", "PostUp = calc.exe\nAddress");
        let r = s.handle(&alice(), &req(&["up", "wireguard", ID], &framed(&bad, "")));
        assert_eq!(r.code, 1);
        assert!(err(&r).starts_with("Invalid config:"), "{}", err(&r));
        assert!(s.host().wg.up.lock().unwrap().is_empty());
    });
}

#[test]
fn malformed_input_is_refused() {
    with_language(AppLanguage::En, || {
        let (s, _d) = service();
        assert_eq!(err(&s.handle(&alice(), &req(&["up", "wireguard", "../x"], &framed(WG, "")))), "Invalid ID");
        assert_eq!(err(&s.handle(&alice(), &req(&["up", "wireguard", ID], b"garbage"))), "Config not provided");
        assert_eq!(s.handle(&alice(), &req(&["up", "pptp", ID], b"")).code, 2);
        assert_eq!(err(&s.handle(&alice(), &req(&["up", "sstp", ID], b""))), "Not available on this system yet");
        assert_eq!(s.handle(&alice(), &req(&["frobnicate"], b"")).code, 2);
        assert_eq!(s.handle(&alice(), &req(&["up", "wireguard", ID, "--accept-risky", "A"], &framed(WG, ""))).code, 2);
    });
}

#[test]
fn the_log_is_masked_and_served_in_slices() {
    with_language(AppLanguage::En, || {
        let (s, _d) = service();
        let r = s.handle(&alice(), &req(&["up", "wireguard", ID], &framed(WG, "password=hunter22\n")));
        assert_eq!(r.code, 0);
        let slice = LogSlice::parse(&s.handle(&alice(), &req(&["log", ID, "0"], b"")).stdout).unwrap();
        let text = String::from_utf8(slice.data).unwrap();
        assert!(text.contains("starting"));
        assert!(text.contains("password is ***") && !text.contains("hunter22"), "{text}");
        assert_eq!(slice.start, 0);
        let past = LogSlice::parse(&s.handle(&alice(), &req(&["log", ID, &slice.size.to_string()], b"")).stdout).unwrap();
        assert!(past.data.is_empty());
        // Still readable after down (the Log tab shows why a connection ended).
        s.handle(&alice(), &req(&["down", "wireguard", ID], b""));
        assert!(s.handle(&alice(), &req(&["log", ID, "0"], b"")).code == 0);
    });
}

#[test]
fn a_failed_up_releases_the_id_and_reports_the_engines_message() {
    with_language(AppLanguage::En, || {
        let dir = tempdir::Dir::new();
        let host = TestHost {
            wg: Fake { fail_up: Some("wireguard.dll is not usable".into()), ..Fake::default() },
            logs: FileLogStore::new(dir.path().to_path_buf()),
            problem: None,
        };
        let s = Service::new(host);
        let r = s.handle(&alice(), &req(&["up", "wireguard", ID], &framed(WG, "")));
        assert_eq!((r.code, err(&r).as_str()), (1, "wireguard.dll is not usable"));
        assert_eq!(s.handle(&alice(), &req(&["status"], b"")).stdout, b"[]\n");
        // Bob may use the ID now (nobody owns it).
        assert_ne!(err(&s.handle(&bob(), &req(&["up", "wireguard", ID], &framed(WG, "")))), "Invalid ID");
    });
}

#[test]
fn limits_per_user_and_degraded_mode() {
    with_language(AppLanguage::En, || {
        let (s, _d) = service();
        for i in 0..macvpn_helper::windows::service::MAX_PER_USER {
            let id = format!("0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1{i:02X}");
            assert_eq!(s.handle(&alice(), &req(&["up", "wireguard", &id], &framed(WG, ""))).code, 0);
        }
        let r = s.handle(&alice(), &req(&["up", "wireguard", "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1FF"], &framed(WG, "")));
        assert_eq!(err(&r), "Too many connections");
        s.drop_user(&alice().sid);
        assert_eq!(s.handle(&alice(), &req(&["status"], b"")).stdout, b"[]\n");

        let dir = tempdir::Dir::new();
        let degraded = Service::new(TestHost {
            wg: Fake::default(),
            logs: FileLogStore::new(dir.path().to_path_buf()),
            problem: Some("unsafe folder".into()),
        });
        assert_eq!(err(&degraded.handle(&alice(), &req(&["up", "wireguard", ID], &framed(WG, "")))), "unsafe folder");
        assert_eq!(EngineFacts::parse(&degraded.handle(&alice(), &req(&["engine"], b"")).stdout).unwrap().problem.as_deref(), Some("unsafe folder"));
    });
}

#[test]
fn hungarian_requests_get_hungarian_answers() {
    let (s, _d) = service();
    let r = s.handle(&alice(), &req(&["down", "wireguard", "../x", "--lang", "hu"], b""));
    assert_eq!(err(&r), "Érvénytelen azonosító");
}
```

(`uuid` is a helper dependency with `v4` already; `zeroize` too. Check the Hungarian of "Invalid ID" in `strings.json` and use it.)

- [x] **Step 2: Run them to verify they fail**

Run: `cargo test --locked -p macvpn-helper --test service_core`
Expected: FAIL to compile (`macvpn_helper::windows::service` does not exist).

- [x] **Step 3: Implement**

`crates/helper/src/windows/mod.rs`:

```rust
//! The Windows backend: the WinVPN Service (spec 4.1). The request handling ([`service`], [`logs`]), the WireGuard
//! and OpenVPN pure parts compile and are tested on every OS; `sys` (Windows only) holds the service host, the pipe
//! server and the engines.

pub mod logs;
pub mod service;

use crate::shared::l10n::tr;
use std::io::Write as _;

/// The Windows helper's entry point; returns the exit code. Until the service host exists (Task 12) it refuses.
pub fn main() -> i32 {
    let _ = writeln!(std::io::stderr(), "{}", tr("Not available on this system yet", &[]));
    1
}
```

`crates/helper/src/windows/service.rs`:

```rust
//! What the WinVPN Service decides for one request (see the module docs of `macvpn_core::service_proto` for the
//! wire format). The caller's SID comes from the pipe (the host reads it from the client's token); everything else
//! from the request is untrusted. The rules of the macOS root layer apply: the shared CLI and framing, the shared
//! validators, masked logs, the status JSON; plus ownership: a connection belongs to the SID that brought it up.

use crate::shared::framing::{self, Secrets};
use crate::shared::l10n::tr;
use crate::shared::mask::Masker;
use crate::shared::status_json::{self, StatusLine};
use crate::shared::{cli, respond, validate};
use macvpn_core::l10n::with_language;
use macvpn_core::models::VPNKind;
use macvpn_core::service_proto::{EngineFacts, LogSlice, Request, Response, SERVICE_VERSION};
use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, PoisonError};

/// Connections one user may have at a time.
pub const MAX_PER_USER: usize = 8;
/// Connections the service runs at a time.
pub const MAX_TOTAL: usize = 32;
/// The longest log slice one `log` request returns.
pub const LOG_SLICE_MAX: usize = 1024 * 1024;

const USAGE: &str = "Usage: up|down <openvpn|wireguard> <id> [--debug] [--accept-risky a,b] [--lang en|hu] | respond openvpn <id> | status | version | engine | auth-state <id> | log <id> <offset>";

/// Who sent the request: the SID from the client's token (string form).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub sid: String,
}

/// One line sink of a connection's log; every line is masked by the sink.
pub trait LogSink: Send + Sync {
    fn line(&self, text: &str);
}

/// The connection logs (`C:\ProgramData\WinVPN\logs`).
pub trait LogStore: Send + Sync {
    /// Starts a new log for `id` (a new generation), masking with `masker`.
    fn open(&self, id: &str, masker: Masker) -> Box<dyn LogSink>;
    /// The bytes from `offset` (at most `max`) of the current log; `None`: no log.
    fn read(&self, id: &str, offset: u64, max: usize) -> Option<LogSlice>;
}

/// What an engine gets for an `up`: the validated config and the secrets (both zeroed on drop by their owner).
pub struct UpRequest<'a> {
    /// The canonical (upper-case) UUID.
    pub id: &'a str,
    pub config: &'a [u8],
    pub secrets: &'a Secrets,
    pub debug: bool,
    pub log: &'a dyn LogSink,
}

/// A connection's state as `status` reports it (the values are checked by the engine: `iface` letters, digits and
/// `-`, `ip` hex digits, `:` and `.`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineState {
    pub state: &'static str,
    pub iface: String,
    pub ip: String,
    pub since: Option<u64>,
}

/// One VPN engine of the service (OpenVPN, WireGuard).
pub trait Engine: Send + Sync {
    /// Blocks until the connection is up or has failed (the localized message).
    fn up(&self, req: &UpRequest<'_>) -> Result<(), String>;
    fn down(&self, id: &str) -> Result<(), String>;
    /// `None`: not running.
    fn state(&self, id: &str) -> Option<EngineState>;
    /// The MFA answer (`respond`'s body, already checked by `respond::parse`).
    fn respond(&self, _id: &str, _body: &[u8]) -> Result<(), String> {
        Err(tr("Not available on this system yet", &[]))
    }
    /// The bridge's `AuthUIState` JSON for the app.
    fn auth_state(&self, _id: &str) -> Option<Vec<u8>> {
        None
    }
}

/// The service's environment: the engines, the facts, the logs, and whether it may connect at all.
pub trait Host: Send + Sync {
    fn engine(&self, kind: VPNKind) -> Option<&dyn Engine>;
    fn facts(&self) -> EngineFacts;
    fn logs(&self) -> &dyn LogStore;
    /// Degraded (the data directory is unsafe): the localized reason; `up` is refused with it.
    fn problem(&self) -> Option<String>;
}

struct Owned {
    sid: String,
    kind: VPNKind,
}

pub struct Service<H: Host> {
    host: H,
    owned: Mutex<HashMap<String, Owned>>,
    /// The last owner of each log (logs stay readable by their owner after `down`).
    log_owner: Mutex<HashMap<String, String>>,
    busy: Mutex<HashSet<String>>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn invalid_id() -> Response {
    Response::fail(1, &tr("Invalid ID", &[]))
}

impl<H: Host> Service<H> {
    pub fn new(host: H) -> Service<H> {
        Service { host, owned: Mutex::default(), log_owner: Mutex::default(), busy: Mutex::default() }
    }

    pub fn host(&self) -> &H {
        &self.host
    }

    /// One request, answered in the language it asks for (`--lang hu`), on this thread only.
    pub fn handle(&self, caller: &Caller, req: &Request) -> Response {
        let args = cli::Args::parse(&req.args);
        with_language(args.language(), || self.dispatch(caller, &args, &req.body))
    }

    fn dispatch(&self, caller: &Caller, a: &cli::Args, body: &[u8]) -> Response {
        match a.cmd.as_str() {
            "version" => Response::ok(format!("{SERVICE_VERSION}\n")),
            "engine" => {
                let mut facts = self.host.facts();
                if let Some(p) = self.host.problem() {
                    facts.problem = Some(p);
                }
                Response::ok(facts.to_json())
            }
            "status" => Response::ok(self.status(caller)),
            "up" => self.up(caller, a, body),
            "down" => self.down(caller, a),
            "respond" => self.respond(caller, a, body),
            // `auth-state <id>` and `log <id> <offset>`: the id is the CLI's second positional ("kind").
            "auth-state" => self.auth_state(caller, &a.kind),
            "log" => self.log(caller, &a.kind, &a.id),
            _ => Response::fail(2, &tr(USAGE, &[])),
        }
    }

    /// The canonical ID if `raw` is a UUID owned by `caller` (`log`: also a past owner).
    fn owned_id(&self, caller: &Caller, raw: &str, past_too: bool) -> Option<String> {
        if !cli::is_uuid(raw) {
            return None;
        }
        let id = raw.to_ascii_uppercase();
        let now = lock(&self.owned).get(&id).is_some_and(|o| o.sid == caller.sid);
        let past = past_too && lock(&self.log_owner).get(&id).is_some_and(|s| *s == caller.sid);
        (now || past).then_some(id)
    }

    fn engine_for(&self, kind: &str) -> Result<(VPNKind, &dyn Engine), Response> {
        let Some(k) = VPNKind::from_raw_value(kind).filter(|_| cli::is_kind(kind)) else {
            return Err(Response::fail(2, &tr(USAGE, &[])));
        };
        self.host.engine(k).map(|e| (k, e)).ok_or_else(|| Response::fail(1, &tr("Not available on this system yet", &[])))
    }

    fn status(&self, caller: &Caller) -> String {
        let owned = lock(&self.owned);
        let mut mine: Vec<(&String, &Owned)> = owned.iter().filter(|(_, o)| o.sid == caller.sid).collect();
        mine.sort_by(|a, b| a.0.cmp(b.0));
        let lines: Vec<StatusLine> = mine
            .into_iter()
            .map(|(id, o)| {
                let st = self.host.engine(o.kind).and_then(|e| e.state(id));
                StatusLine {
                    id: id.clone(),
                    kind: o.kind.raw_value().to_string(),
                    state: st.as_ref().map_or("failed", |s| s.state),
                    iface: st.as_ref().map(|s| s.iface.clone()).unwrap_or_default(),
                    ip: st.as_ref().map(|s| s.ip.clone()).unwrap_or_default(),
                    since: st.and_then(|s| s.since).map(|n| n.to_string()),
                }
            })
            .collect();
        status_json::render(&lines)
    }

    fn up(&self, caller: &Caller, a: &cli::Args, body: &[u8]) -> Response {
        if let Some(problem) = self.host.problem() {
            return Response::fail(1, &problem);
        }
        let (kind, engine) = match self.engine_for(&a.kind) {
            Ok(x) => x,
            Err(r) => return r,
        };
        if !cli::is_uuid(&a.id) {
            return invalid_id();
        }
        if !a.accept_risky_valid() {
            return Response::fail(2, &tr("Invalid --accept-risky value", &[]));
        }
        let id = a.id.to_ascii_uppercase();
        let (config, secrets) = match framing::parse_framed(body, true) {
            Ok(x) => x,
            Err(e) => return Response::fail(1, &e.message()),
        };
        // The framing checked UTF-8.
        let text = std::str::from_utf8(&config).unwrap_or_default();
        let issues = validate::issues(kind, text, &validate::risky_set(&a.accept_risky)).unwrap_or_default();
        if !issues.is_empty() {
            return Response::fail(1, &format!("{}\n{}", tr("Invalid config:", &[]), issues.join("\n")));
        }
        {
            let mut owned = lock(&self.owned);
            match owned.get(&id) {
                Some(o) if o.sid != caller.sid => return invalid_id(),
                Some(_) => {}
                None => {
                    let mine = owned.values().filter(|o| o.sid == caller.sid).count();
                    if mine >= MAX_PER_USER || owned.len() >= MAX_TOTAL {
                        return Response::fail(1, &tr("Too many connections", &[]));
                    }
                }
            }
            if !lock(&self.busy).insert(id.clone()) {
                return Response::fail(1, &tr("Another operation on this connection is in progress", &[]));
            }
            owned.insert(id.clone(), Owned { sid: caller.sid.clone(), kind });
            lock(&self.log_owner).insert(id.clone(), caller.sid.clone());
        }
        let sink = self.host.logs().open(&id, secrets.masker());
        let result = engine.up(&UpRequest { id: &id, config: &config, secrets: &secrets, debug: a.debug, log: &*sink });
        lock(&self.busy).remove(&id);
        match result {
            Ok(()) => Response::ok(Vec::new()),
            Err(message) => {
                lock(&self.owned).remove(&id);
                Response::fail(1, &message)
            }
        }
    }

    fn down(&self, caller: &Caller, a: &cli::Args) -> Response {
        let (_, engine) = match self.engine_for(&a.kind) {
            Ok(x) => x,
            Err(r) => return r,
        };
        let Some(id) = self.owned_id(caller, &a.id, false) else { return invalid_id() };
        let result = engine.down(&id);
        lock(&self.owned).remove(&id);
        match result {
            Ok(()) => Response::ok(Vec::new()),
            Err(m) => Response::fail(1, &m),
        }
    }

    fn respond(&self, caller: &Caller, a: &cli::Args, body: &[u8]) -> Response {
        if a.kind != "openvpn" {
            return Response::fail(2, &tr(USAGE, &[]));
        }
        let Some(id) = self.owned_id(caller, &a.id, false) else { return invalid_id() };
        if let Err(key) = respond::parse(body) {
            return Response::fail(1, &tr(key, &[]));
        }
        match self.host.engine(VPNKind::Openvpn).map(|e| e.respond(&id, body)) {
            Some(Ok(())) => Response::ok(Vec::new()),
            Some(Err(m)) => Response::fail(1, &m),
            None => Response::fail(1, &tr("Not available on this system yet", &[])),
        }
    }

    fn auth_state(&self, caller: &Caller, raw: &str) -> Response {
        let Some(id) = self.owned_id(caller, raw, false) else { return invalid_id() };
        let kind = lock(&self.owned).get(&id).map(|o| o.kind);
        let state = kind.and_then(|k| self.host.engine(k)).and_then(|e| e.auth_state(&id));
        Response::ok(state.unwrap_or_default())
    }

    fn log(&self, caller: &Caller, raw: &str, offset: &str) -> Response {
        let Some(id) = self.owned_id(caller, raw, true) else { return invalid_id() };
        let Some(offset) = offset.parse::<u64>().ok().filter(|_| offset.bytes().all(|b| b.is_ascii_digit())) else {
            return Response::fail(2, &tr(USAGE, &[]));
        };
        match self.host.logs().read(&id, offset, LOG_SLICE_MAX) {
            Some(slice) => Response::ok(slice.encode()),
            None => Response::ok(LogSlice { generation: 0, size: 0, start: 0, data: Vec::new() }.encode()),
        }
    }

    /// The user's session ended (logoff, decision 2): every connection of `sid` goes down.
    pub fn drop_user(&self, sid: &str) {
        let ids: Vec<(String, VPNKind)> =
            lock(&self.owned).iter().filter(|(_, o)| o.sid == sid).map(|(id, o)| (id.clone(), o.kind)).collect();
        for (id, kind) in ids {
            if let Some(e) = self.host.engine(kind) {
                let _ = e.down(&id);
            }
            lock(&self.owned).remove(&id);
        }
    }

    /// The service stops: every connection goes down.
    pub fn shutdown(&self) {
        let sids: HashSet<String> = lock(&self.owned).values().map(|o| o.sid.clone()).collect();
        for sid in sids {
            self.drop_user(&sid);
        }
    }

    /// The SIDs that own a connection (the host's logoff check).
    pub fn owners(&self) -> HashSet<String> {
        lock(&self.owned).values().map(|o| o.sid.clone()).collect()
    }
}
```

`crates/helper/src/windows/logs.rs`:

```rust
//! The connection logs of the service: `<dir>\<ID>.log`, one per connection, replaced at each `up` (a new
//! generation), masked line by line, at most 8 MiB each (then one "log truncated" line). The directory is the
//! service's private `logs` folder (Task 12 creates it SYSTEM-only); names come only from canonical UUIDs.

use crate::shared::mask::Masker;
use crate::windows::service::{LogSink, LogStore};
use macvpn_core::service_proto::LogSlice;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

pub const LOG_MAX: u64 = 8 * 1024 * 1024;

pub struct FileLogStore {
    dir: PathBuf,
    next_generation: AtomicU64,
    generations: Mutex<HashMap<String, u64>>,
}

impl FileLogStore {
    pub fn new(dir: PathBuf) -> FileLogStore {
        // Generations only need to differ within one service run and from 0 (no log).
        let seed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(1, |d| d.as_secs() << 16);
        FileLogStore { dir, next_generation: AtomicU64::new(seed.max(1)), generations: Mutex::default() }
    }

    fn path(&self, id: &str) -> Option<PathBuf> {
        crate::shared::cli::is_uuid(id).then(|| self.dir.join(format!("{}.log", id.to_ascii_uppercase())))
    }
}

struct FileSink {
    file: Mutex<Option<File>>,
    written: AtomicU64,
    masker: Masker,
}

impl LogSink for FileSink {
    fn line(&self, text: &str) {
        let mut slot = self.file.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(file) = slot.as_mut() else { return };
        let mut line = self.masker.line(text.as_bytes());
        line.truncate(crate::shared::mask::MAX_LINE);
        line.push(b'\n');
        let total = self.written.fetch_add(line.len() as u64, Ordering::SeqCst) + line.len() as u64;
        if total > LOG_MAX {
            let _ = file.write_all(b"[WinVPN] log truncated\n");
            *slot = None;
            return;
        }
        let _ = file.write_all(&line);
    }
}

impl LogStore for FileLogStore {
    fn open(&self, id: &str, masker: Masker) -> Box<dyn LogSink> {
        let file = self.path(id).and_then(|p| {
            OpenOptions::new().write(true).create(true).truncate(true).open(p).ok()
        });
        let generation = self.next_generation.fetch_add(1, Ordering::SeqCst);
        self.generations.lock().unwrap_or_else(PoisonError::into_inner).insert(id.to_ascii_uppercase(), generation);
        Box::new(FileSink { file: Mutex::new(file), written: AtomicU64::new(0), masker })
    }

    fn read(&self, id: &str, offset: u64, max: usize) -> Option<LogSlice> {
        let generation = *self.generations.lock().unwrap_or_else(PoisonError::into_inner).get(&id.to_ascii_uppercase())?;
        let mut f = File::open(self.path(id)?).ok()?;
        let size = f.seek(SeekFrom::End(0)).ok()?;
        let start = offset.min(size);
        f.seek(SeekFrom::Start(start)).ok()?;
        let mut data = Vec::new();
        f.take(max as u64).read_to_end(&mut data).ok()?;
        Some(LogSlice { generation, size, start, data })
    }
}
```

On Windows the production store creates files through Task 12's private-file helper (owner SYSTEM, protected DACL, no reparse points): `FileLogStore` gets a `create: fn(&Path) -> io::Result<File>` field in Task 12; here it uses `OpenOptions` (portable, the tests' temp dir).

`shared/limits.rs`: `const _: () = assert!(STDIN_MAX == macvpn_core::service_proto::BODY_MAX);`.

`strings.json` (scope `mvpn`; the first is Windows-only):
- `"Usage: up|down <openvpn|wireguard> <id> [--debug] [--accept-risky a,b] [--lang en|hu] | respond openvpn <id> | status | version | engine | auth-state <id> | log <id> <offset>"` → hu `"Használat: up|down <openvpn|wireguard> <azonosító> [--debug] [--accept-risky a,b] [--lang en|hu] | respond openvpn <azonosító> | status | version | engine | auth-state <azonosító> | log <azonosító> <eltolás>"`, `"only": ["windows"]`
- `"Too many connections"` → `"Túl sok kapcsolat"`
- `"Another operation on this connection is in progress"` → `"Ezen a kapcsolaton már folyik egy művelet"`

- [x] **Step 4: Run the tests to verify they pass**

Run: `cargo test --locked -p macvpn-helper && scripts/check-windows.sh && MVPN_IMPL=rust scripts/test-root.sh && scripts/win-remote.sh test`
Expected: PASS (`service_core` 9 tests on the Mac and on Windows); `every_call_site_has_a_translation` passes with the new keys.

- [x] **Step 5: Commit**

```bash
git add crates/helper crates/core/l10n/strings.json
git commit -m "feat(helper): the WinVPN Service's request handling" -m "Pure and tested on every OS: the shared CLI, framing and validators, per-request language, ownership by the caller's SID (another user's ID answers like an unknown one), limits, masked per-connection logs served in slices, status, MFA answers, a degraded mode." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**As built (Task 8):** as planned, with these hardenings (each tested in `service_core.rs`, 15 tests): `--dry-run` is refused (usage, exit 2) instead of being ignored (the service has no dry run). `down` checks the request's kind for its form only and takes the connection down with the engine *recorded* at `up` (a wrong kind cannot orphan it). A failed `down` (and a failed one in `drop_user`) keeps the connection owned (it may still run: macOS keeps its run directory too). A second `up` of an ID the caller owns first takes the previous run down with its recorded engine ("Cannot close the previous connection" otherwise, the old record kept), as macOS' "closing the previous run". The busy marker records the SID: another user's `up` of a connecting ID answers "Invalid ID" (no oracle), the owner's "Another operation on this connection is in progress". Each owned record carries an epoch: a `down` or logoff during a blocking `up` (cancel; the `Engine::up` doc says it must return) wins: when that `up` returns `Ok`, the service calls `down` again and answers "The connection was taken down while connecting" (new string; if that `down` fails the connection is owned again). `status` reports a busy ID with no engine state as `connecting`, accepts only `connected`/`connecting` from an engine (else `failed`), and renders `iface`/`ip` only when they are `[A-Za-z0-9-]` / `[0-9A-Fa-f:.]` (≤ 64 bytes; `status_json` does not escape), and asks the engines without the service's locks held. `respond` needs an owned OpenVPN connection. `auth-state` answers above 8 KiB (`AuthUIState::parse`'s limit) are dropped. Past logs are bounded: `MAX_LOGS_PER_USER` 32 and `MAX_LOGS_TOTAL` 256, the oldest log of a connection that is not owned is deleted (`LogStore::remove`, new) when a new one starts. `FileLogStore::read` never returns more than `size - start` bytes. A config that is not UTF-8 after framing is refused (never validated as empty). `service_core` has 15 tests (the plan's 8, which the plan counted as 9, plus 7). app-core's `l10n_coverage` test allows no `tr(<variable>)` without a `VARIABLE_KEYS` entry, so the usage text is a literal in `usage()` (no `USAGE` const) and `respond`'s rejection goes through the new `shared::respond::message(key)` (its keys are `respond.rs`' constants, already covered). The Windows run passes `service_core` (15/15); two Task 2 tests (`openvpn_tiers::macos_tiers_equal_the_1_4_golden`, `validator_arguments::wireguard_valid_values`) already fail on Windows on the wave's base, independent of this task.

## Task 9: WireGuard on Windows, the pure parts

**Goal:** from a validated WireGuard config to (a) the exact bytes `WireGuardSetConfiguration` takes and (b) the list of addresses, routes, DNS settings and MTU the service applies with IP Helper. No Win32; tested on every OS.

**Files:**
- Create: `crates/helper/src/windows/wg_plan.rs`, `crates/helper/src/windows/wg_nt.rs`, `crates/helper/tests/wg_windows.rs`
- Modify: `crates/helper/src/windows/mod.rs` (`pub mod wg_nt; pub mod wg_plan;`), `crates/helper/Cargo.toml` (`base64 = "0.23.1"`, the version core uses: already in `Cargo.lock`)

- [x] **Step 1: Write the failing tests** (`crates/helper/tests/wg_windows.rs`)

```rust
use macvpn_helper::windows::wg_nt::{self, ALLOWED_IP_SIZE, INTERFACE_SIZE, PEER_SIZE};
use macvpn_helper::windows::wg_plan::{self, Endpoint, Prefix};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

const KEY_A: &str = "bWFjdnBuLXRlc3QtcHJpdmF0ZS1rZXktMzJieXRlcyE=";
const KEY_B: &str = "bWFjdnBuLXRlc3QtcHVibGljLS1rZXktMzJieXRlcyE=";

fn conf(extra_iface: &str, extra_peer: &str) -> String {
    format!(
        "[Interface]\nPrivateKey = {KEY_A}\nAddress = 10.0.0.2/32, fd00::2/128\nDNS = 10.0.0.1, corp.example\n{extra_iface}\n[Peer]\nPublicKey = {KEY_B}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 192.0.2.10:51820\nPersistentKeepalive = 25\n{extra_peer}"
    )
}

#[test]
fn the_plan_reads_every_supported_key() {
    let p = wg_plan::parse(&conf("MTU = 1380\nListenPort = 51000\n", "PresharedKey = bWFjdnBuLXRlc3QtcHJpdmF0ZS1rZXktMzJieXRlcyE=\n")).unwrap();
    assert_eq!(p.addresses, [Prefix::parse("10.0.0.2/32").unwrap(), Prefix::parse("fd00::2/128").unwrap()]);
    assert_eq!(p.dns_servers, [IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]);
    assert_eq!(p.dns_search, ["corp.example"]);
    assert_eq!((p.mtu, p.listen_port, p.routes_enabled), (Some(1380), Some(51000), true));
    assert_eq!(p.peers.len(), 1);
    assert_eq!(p.peers[0].endpoint, Some(Endpoint::Addr(SocketAddr::from(([192, 0, 2, 10], 51820)))));
    assert_eq!(p.peers[0].keepalive, Some(25));
    assert!(p.peers[0].preshared_key.is_some());
    assert_eq!(p.routes(), [Prefix::parse("0.0.0.0/0").unwrap(), Prefix::parse("::/0").unwrap()]);
    let off = wg_plan::parse(&conf("Table = off\n", "")).unwrap();
    assert!(off.routes().is_empty());
}

#[test]
fn host_endpoints_are_kept_for_resolution() {
    let p = wg_plan::parse(&conf("", "").replace("192.0.2.10:51820", "vpn.example.com:51820")).unwrap();
    assert_eq!(p.peers[0].endpoint, Some(Endpoint::Host("vpn.example.com".into(), 51820)));
    let p = wg_plan::parse(&conf("", "").replace("192.0.2.10:51820", "[2001:db8::1]:51820")).unwrap();
    assert!(matches!(p.peers[0].endpoint, Some(Endpoint::Addr(SocketAddr::V6(_)))));
}

#[test]
fn bad_keys_and_prefixes_are_refused() {
    assert!(wg_plan::parse(&conf("", "").replace(KEY_A, "c2hvcnQ=")).is_err());
    assert!(wg_plan::parse(&conf("", "").replace("10.0.0.2/32", "10.0.0.2/33")).is_err());
    assert!(Prefix::parse("10.0.0.1/24").unwrap().is_canonical() == false);
}

#[test]
fn the_layout_matches_wireguard_h() {
    // Checked against wireguard-nt 0.10.1's wireguard.h with MSVC (Task 14, Step 1): ALIGNED(8) structs.
    assert_eq!((INTERFACE_SIZE, PEER_SIZE, ALLOWED_IP_SIZE), (80, 136, 24));
}

#[test]
fn the_configuration_bytes_are_exact() {
    let p = wg_plan::parse(&conf("ListenPort = 51000\n", "")).unwrap();
    let resolved = vec![Some(SocketAddr::from(([192, 0, 2, 10], 51820)))];
    let bytes = wg_nt::encode(&p, &resolved);
    assert_eq!(bytes.len(), INTERFACE_SIZE + PEER_SIZE + 2 * ALLOWED_IP_SIZE);
    // Interface: flags HAS_PRIVATE_KEY | HAS_LISTEN_PORT | REPLACE_PEERS, the port, the key, one peer.
    assert_eq!(u32::from_le_bytes(bytes[0..4].try_into().unwrap()), 0b1110);
    assert_eq!(u16::from_le_bytes(bytes[4..6].try_into().unwrap()), 51000);
    assert_eq!(&bytes[6..38], wg_plan::decode_key(KEY_A).unwrap().as_slice());
    assert_eq!(u32::from_le_bytes(bytes[72..76].try_into().unwrap()), 1);
    // Peer: flags HAS_PUBLIC_KEY | HAS_PERSISTENT_KEEPALIVE | HAS_ENDPOINT | REPLACE_ALLOWED_IPS.
    let peer = &bytes[INTERFACE_SIZE..INTERFACE_SIZE + PEER_SIZE];
    assert_eq!(u32::from_le_bytes(peer[0..4].try_into().unwrap()), 0b10_1101);
    assert_eq!(&peer[8..40], wg_plan::decode_key(KEY_B).unwrap().as_slice());
    assert_eq!(u16::from_le_bytes(peer[72..74].try_into().unwrap()), 25);
    // SOCKADDR_INET for 192.0.2.10:51820: AF_INET (2), the port big-endian, the address.
    assert_eq!(&peer[76..84], &[2, 0, 0xCA, 0x6C, 192, 0, 2, 10]);
    assert_eq!(u32::from_le_bytes(peer[128..132].try_into().unwrap()), 2);
    // The first allowed IP: 0.0.0.0/0, AF_INET.
    let ip = &bytes[INTERFACE_SIZE + PEER_SIZE..];
    assert_eq!(&ip[0..4], &[0, 0, 0, 0]);
    assert_eq!(u16::from_le_bytes(ip[16..18].try_into().unwrap()), 2);
    assert_eq!(ip[18], 0);
    // The second: ::/0, AF_INET6 (23).
    assert_eq!(u16::from_le_bytes(ip[ALLOWED_IP_SIZE + 16..ALLOWED_IP_SIZE + 18].try_into().unwrap()), 23);
}
```

- [x] **Step 2: Run them to verify they fail**

Run: `cargo test --locked -p macvpn-helper --test wg_windows`
Expected: FAIL to compile.

- [x] **Step 3: Implement**

`wg_plan.rs`: `Prefix { addr: IpAddr, len: u8 }` with `parse` (refuses a length above 32 / 128) and `is_canonical` (no host bits); `Endpoint::{Addr(SocketAddr), Host(String, u16)}`; `Peer { public_key: Zeroizing<[u8; 32]>? (public keys are not secret: `[u8; 32]`), preshared_key: Option<Zeroizing<[u8; 32]>>, endpoint, keepalive: Option<u16>, allowed: Vec<Prefix> }`; `Plan { private_key: Zeroizing<[u8; 32]>, listen_port, addresses, dns_servers, dns_search, mtu: Option<u32>, routes_enabled: bool, peers }`; `pub fn parse(text) -> Result<Plan, String>` (the config is already validated by the shared validator; this parser is still strict and refuses what it cannot represent: a key that does not decode to 32 bytes, a bad prefix, an endpoint without a port, a port 0); `Plan::routes()` = the union of every peer's AllowedIPs when `routes_enabled`, in order, duplicates removed; `pub fn decode_key(b64) -> Result<Zeroizing<[u8; 32]>, String>` (standard base64 with padding, exactly 32 bytes). Comments and keys are matched as the validator does (case-insensitive keys, `#` comments, values trimmed). DNS entries that parse as IP addresses are servers, the rest search domains (`wg-quick`'s rule).

`wg_nt.rs`:

```rust
//! The configuration block `WireGuardSetConfiguration` takes (wireguard-nt's `wireguard.h`, 0.10.1): a
//! `WIREGUARD_INTERFACE`, then each `WIREGUARD_PEER` followed by its `WIREGUARD_ALLOWED_IP`s. All three structs are
//! `ALIGNED(8)`; little-endian; `SOCKADDR_INET` holds the port in network order. The private and preshared keys are
//! in the buffer: it is `Zeroizing`.

use crate::windows::wg_plan::{Plan, Prefix};
use std::net::{IpAddr, SocketAddr};
use zeroize::Zeroizing;

pub const INTERFACE_SIZE: usize = 80;
pub const PEER_SIZE: usize = 136;
pub const ALLOWED_IP_SIZE: usize = 24;
const AF_INET: u16 = 2;
const AF_INET6: u16 = 23;

pub const IF_HAS_PUBLIC_KEY: u32 = 1 << 0;
pub const IF_HAS_PRIVATE_KEY: u32 = 1 << 1;
pub const IF_HAS_LISTEN_PORT: u32 = 1 << 2;
pub const IF_REPLACE_PEERS: u32 = 1 << 3;
pub const PEER_HAS_PUBLIC_KEY: u32 = 1 << 0;
pub const PEER_HAS_PRESHARED_KEY: u32 = 1 << 1;
pub const PEER_HAS_PERSISTENT_KEEPALIVE: u32 = 1 << 2;
pub const PEER_HAS_ENDPOINT: u32 = 1 << 3;
pub const PEER_REPLACE_ALLOWED_IPS: u32 = 1 << 5;

fn put(buf: &mut [u8], at: usize, bytes: &[u8]) {
    buf[at..at + bytes.len()].copy_from_slice(bytes);
}

fn sockaddr_inet(addr: &SocketAddr) -> [u8; 28] {
    let mut s = [0u8; 28];
    match addr {
        SocketAddr::V4(a) => {
            put(&mut s, 0, &AF_INET.to_le_bytes());
            put(&mut s, 2, &a.port().to_be_bytes());
            put(&mut s, 4, &a.ip().octets());
        }
        SocketAddr::V6(a) => {
            put(&mut s, 0, &AF_INET6.to_le_bytes());
            put(&mut s, 2, &a.port().to_be_bytes());
            put(&mut s, 4, &a.flowinfo().to_be_bytes());
            put(&mut s, 8, &a.ip().octets());
            put(&mut s, 24, &a.scope_id().to_le_bytes());
        }
    }
    s
}

fn allowed_ip(p: &Prefix) -> [u8; ALLOWED_IP_SIZE] {
    let mut b = [0u8; ALLOWED_IP_SIZE];
    match p.addr {
        IpAddr::V4(a) => {
            put(&mut b, 0, &a.octets());
            put(&mut b, 16, &AF_INET.to_le_bytes());
        }
        IpAddr::V6(a) => {
            put(&mut b, 0, &a.octets());
            put(&mut b, 16, &AF_INET6.to_le_bytes());
        }
    }
    b[18] = p.len;
    b
}

/// `resolved[i]`: peer `i`'s endpoint as resolved by the service (`None`: no endpoint).
pub fn encode(plan: &Plan, resolved: &[Option<SocketAddr>]) -> Zeroizing<Vec<u8>> {
    let total = INTERFACE_SIZE + plan.peers.iter().map(|p| PEER_SIZE + p.allowed.len() * ALLOWED_IP_SIZE).sum::<usize>();
    let mut buf = Zeroizing::new(vec![0u8; total]);
    let mut flags = IF_HAS_PRIVATE_KEY | IF_REPLACE_PEERS;
    if let Some(port) = plan.listen_port {
        flags |= IF_HAS_LISTEN_PORT;
        put(&mut buf, 4, &port.to_le_bytes());
    }
    put(&mut buf, 0, &flags.to_le_bytes());
    put(&mut buf, 6, plan.private_key.as_slice());
    put(&mut buf, 72, &(plan.peers.len() as u32).to_le_bytes());
    let mut at = INTERFACE_SIZE;
    for (i, peer) in plan.peers.iter().enumerate() {
        let mut flags = PEER_HAS_PUBLIC_KEY | PEER_REPLACE_ALLOWED_IPS;
        put(&mut buf, at + 8, &peer.public_key);
        if let Some(psk) = &peer.preshared_key {
            flags |= PEER_HAS_PRESHARED_KEY;
            put(&mut buf, at + 40, psk.as_slice());
        }
        if let Some(k) = peer.keepalive {
            flags |= PEER_HAS_PERSISTENT_KEEPALIVE;
            put(&mut buf, at + 72, &k.to_le_bytes());
        }
        if let Some(Some(addr)) = resolved.get(i) {
            flags |= PEER_HAS_ENDPOINT;
            put(&mut buf, at + 76, &sockaddr_inet(addr));
        }
        put(&mut buf, at, &flags.to_le_bytes());
        put(&mut buf, at + 128, &(peer.allowed.len() as u32).to_le_bytes());
        at += PEER_SIZE;
        for p in &peer.allowed {
            put(&mut buf, at, &allowed_ip(p));
            at += ALLOWED_IP_SIZE;
        }
    }
    buf
}
```

(The test above expects the interface flags `0b1110` = HAS_PRIVATE_KEY | HAS_LISTEN_PORT | REPLACE_PEERS and the peer flags `0b10_1101` = PUBLIC_KEY | KEEPALIVE | ENDPOINT | REPLACE_ALLOWED_IPS; adjust the test, not the flags, if Step 1 of Task 14 shows other values in the header.)

- [x] **Step 4: Run**

Run: `cargo test --locked -p macvpn-helper --test wg_windows && scripts/check-windows.sh`
Expected: PASS (5 tests).

- [x] **Step 5: Commit**

```bash
git add crates/helper
git commit -m "feat(helper): WireGuard on Windows – the plan and wireguard-nt's configuration bytes" -m "Pure, tested on every OS: addresses, DNS servers and search domains, MTU, routes (Table = off: none), host endpoints kept for the service to resolve, and the exact WIREGUARD_INTERFACE / PEER / ALLOWED_IP layout (keys in a zeroized buffer)." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**As built (Task 9):** the API is as planned with these changes. `wg_nt::encode` returns `Result<Zeroizing<Vec<u8>>, String>` (fail closed): `resolved` must have one entry per peer, `Some` exactly where the config has an `Endpoint`, equal to an address endpoint and with the same port as a host endpoint; the block is at most `wg_nt::MAX_BYTES` (8 MiB, checked arithmetic; a 1 MB config stays far below); the counts go through `u32::try_from`. Task 14 calls it with `?`. `Prefix`'s fields are private (`addr()`, `prefix_len()`; a `Prefix` only comes from `parse`), plus `masked()`; `Plan::routes()` and the encoded allowed IPs are masked (wg/wg-quick behaviour; IP Helper refuses a route destination with host bits), `Plan::addresses` keep their host bits; duplicates are removed from the routes after masking, not from the allowed IPs (wireguard-nt merges them). `parse` first refuses a text above `SRC_MAX` and any issue of `WireGuardValidator::validate_for(TargetOs::Windows, …)` (so the bytes come only from validated values even if the caller skipped it), then also refuses: a repeated single-valued key (`Duplicate key: %@`; `Address`, `DNS`, `AllowedIPs` accumulate), a peer without `PublicKey` (the validator only requires one peer with a key), an address `std` cannot read (`010.0.0.2`), a DNS entry or endpoint host whose last label is a number (`1.2.3`, `3221225994`, `vpn.0x7f`: `getaddrinfo` would read it as IPv4). `ListenPort = 0` and `PersistentKeepalive = 0`/`off` are `None`. Errors reuse existing core strings (no new `strings.json` entry). `Plan` and `Peer` have a hand-written `Debug` that redacts the private and preshared keys. Step 1's `is_canonical() == false` is `!…is_canonical()` (clippy `bool_comparison`); 6 more tests (11 in all): the PSK and an IPv6 `SOCKADDR_IN6`, the endpoint fit, what Windows refuses, canonical routes, strict prefixes and keys, redacted `Debug`. The struct sizes and offsets are the header's as read from `wireguard.h` 0.10.1 (documented in `wg_nt.rs`); the MSVC check stays Task 14 Step 1's. `Cargo.lock` gains only the `base64 0.23.1` dependency line of `macvpn-helper`.

## Task 10: OpenVPN on Windows, the pure parts (argv, versions, pins)

**Goal:** the exact `openvpn.exe` command line, the driver choice per connection (decision 4), the version policy and the pinned installer, as data and pure functions the service and the app share by value.

**Files:**
- Create: `crates/helper/src/windows/ovpn_args.rs`, `crates/helper/src/windows/ovpn_pins.rs`, `scripts/pins/openvpn.txt`, `crates/helper/tests/ovpn_windows.rs`
- Modify: `crates/core/src/service_proto.rs` (`Version`: the `impl` blocks below go there, `ovpn_args` re-exports it)
- Create: `crates/platform-win/src/pure/openvpn_pins.rs` (the same pins for the app: generated from `scripts/pins/openvpn.txt` by the test below, never edited by hand)
- Modify: `crates/helper/src/windows/mod.rs`, `crates/platform-win/src/pure/mod.rs`

- [x] **Step 1: Pin OpenVPN Community** (once, on the Mac; record the evidence in the commit body)

Pick the newest OpenVPN Community 2.6.x release published at least 14 days before this task (the 2a rule for pinned versions), from `https://openvpn.net/community-downloads/`. Download its two MSIs (`OpenVPN-<v>-I<nnn>-amd64.msi`, `-arm64.msi`) from `https://swupdate.openvpn.org/community/releases/` into a new empty directory, and verify each against the release's GnuPG signature (`.asc`, the OpenVPN security mailing list key fingerprint published on the downloads page): `gpg --verify <msi>.asc <msi>`. Then on the Windows machine: `scripts/win-remote.sh run "powershell -NoProfile -Command \"Get-AuthenticodeSignature '<path to the copied msi>' | Format-List Status,SignerCertificate\""` → `Valid`, and the signer's CN. Record in `scripts/pins/openvpn.txt`:

```text
# OpenVPN Community, pinned for WinVPN (docs/superpowers/plans/2026-10-22-winvpn-2b-service-openvpn-wireguard.md, Task 10).
# Fields: key<TAB>value. Changing a pin: new MSIs verified with GnuPG and Authenticode, then this file, then
# `cargo test -p macvpn-helper --test ovpn_windows` regenerates crates/platform-win/src/pure/openvpn_pins.rs.
version	2.6.<n>
min_version	2.6.0
signer	<the CN Get-AuthenticodeSignature showed, e.g. OpenVPN Inc.>
msi_x64_url	https://swupdate.openvpn.org/community/releases/OpenVPN-2.6.<n>-I<nnn>-amd64.msi
msi_x64_sha256	<64 hex>
msi_arm64_url	https://swupdate.openvpn.org/community/releases/OpenVPN-2.6.<n>-I<nnn>-arm64.msi
msi_arm64_sha256	<64 hex>
features	<the ADDLOCAL list, from Step 2>
```

- [x] **Step 2: Find the MSI's feature names** (on the Windows machine, read-only; `scripts/msi-query.ps1` reads tables without installing)

Run: `scripts/win-remote.sh run "powershell -NoProfile -File scripts/msi-query.ps1 '<copied msi>' 'SELECT Feature, Feature_Parent, Title, Level FROM Feature'"`
Expected: the feature table. Choose the set for decision 4: the feature that installs `openvpn.exe` and its DLLs, the DCO, TAP-Windows6 and Wintun driver features, and their parents (the names are the MSI's own; typical names are `OpenVPN`, `Drivers`, `Drivers.OvpnDco`, `Drivers.TAPWindows6`, `Drivers.Wintun`; leave out `OpenVPN.GUI`, `OpenVPN.Service` / the Interactive Service, documentation, samples and EasyRSA). Write it as a comma list into `features`. Also list the driver files and their versions (`SELECT FileName, Version FROM File` filtered to `*.sys`) and record them in the commit body: System Status shows the installed versions, and the CI job (Task 21) compares them with these.

- [x] **Step 3: Write the failing tests** (`crates/helper/tests/ovpn_windows.rs`)

```rust
use macvpn_helper::windows::ovpn_args::{self, Driver, Version};
use macvpn_helper::windows::ovpn_pins::PINS;
use std::path::Path;

#[test]
fn the_argv_is_fixed_and_contains_nothing_from_the_request() {
    let run = Path::new(r"C:\ProgramData\WinVPN\run\0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0");
    let argv = ovpn_args::argv(run, 51234, Driver::Dco, false, true, false);
    let s: Vec<String> = argv.iter().map(|a| a.to_string_lossy().into_owned()).collect();
    assert_eq!(
        s,
        [
            "--config", r"C:\ProgramData\WinVPN\run\0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0\config.ovpn",
            "--script-security", "1",
            "--windows-driver", "ovpn-dco",
            "--verb", "3",
            "--management", "127.0.0.1", "51234", r"C:\ProgramData\WinVPN\run\0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0\mgmt.pw",
            "--management-hold",
            "--management-query-passwords",
            "--auth-retry", "interact",
            "--setenv", "IV_SSO", "openurl,webauth,crtext",
            "--auth-user-pass",
        ]
    );
    let debug_keypass = ovpn_args::argv(run, 51234, Driver::Wintun, true, false, true);
    let s: Vec<String> = debug_keypass.iter().map(|a| a.to_string_lossy().into_owned()).collect();
    assert!(s.windows(2).any(|w| w == ["--verb", "5"]));
    assert!(s.windows(2).any(|w| w[0] == "--askpass" && w[1].ends_with(r"\askpass")));
    assert!(!s.contains(&"--auth-user-pass".to_string()));
    assert!(s.windows(2).any(|w| w == ["--windows-driver", "wintun"]));
}

#[test]
fn the_driver_follows_the_validated_config() {
    let base = "client\ndev tun\nremote vpn.example.com 1194\n";
    let d = |extra: &str| ovpn_args::choose_driver(&format!("{base}{extra}"));
    assert_eq!(d(""), Driver::Dco);
    assert_eq!(d("data-ciphers AES-256-GCM:CHACHA20-POLY1305\n"), Driver::Dco);
    assert_eq!(d("compress stub-v2\n"), Driver::Dco, "framing only, no compression");
    for wintun in ["comp-lzo\n", "comp-lzo no\n", "compress lz4-v2\n", "cipher AES-256-CBC\ndata-ciphers AES-256-CBC\n", "fragment 1300\n", "secret [inline]\n", "disable-dco\n"] {
        assert_eq!(d(wintun), Driver::Wintun, "{wintun}");
    }
    for tap in ["dev tap\n", "dev tap0\n", "dev-type tap\n"] {
        assert_eq!(ovpn_args::choose_driver(&format!("client\n{tap}remote vpn.example.com 1194\n")), Driver::TapWindows6, "{tap}");
    }
    // Inside a <connection> block and through `setenv opt` too; comments and inline blocks are ignored.
    assert_eq!(d("<connection>\nremote b 1\nfragment 1300\n</connection>\n"), Driver::Wintun);
    assert_eq!(d("# comp-lzo\n<key>\ncomp-lzo\n</key>\n"), Driver::Dco);
    assert_eq!(Driver::Dco.arg(), "ovpn-dco");
    assert_eq!(Driver::TapWindows6.arg(), "tap-windows6");
}

#[test]
fn the_dco_incompatibility_line_is_recognized() {
    use macvpn_helper::shared::ovpn_log::dco_incompatible;
    // Record OpenVPN's exact wording from the pinned version's source (`dco.c` / `options.c`) when writing this test.
    assert!(dco_incompatible(b"2026-10-22 10:00:00 Note: --compress is not supported by DCO, disabling data channel offload."));
    assert!(!dco_incompatible(b"2026-10-22 10:00:00 Initialization Sequence Completed"));
}

#[test]
fn versions_compare_and_parse() {
    assert_eq!(Version::parse("2.6.14"), Some(Version(2, 6, 14)));
    assert_eq!(Version::from_file_version((2, 6, 14, 0)), Version(2, 6, 14));
    assert!(Version(2, 6, 0) <= Version(2, 6, 14) && Version(2, 5, 9) < Version(2, 6, 0));
    assert_eq!(Version::parse("2.6"), None);
    assert_eq!(Version::parse("2.6.x"), None);
}

#[test]
fn the_pins_are_complete_and_the_app_copy_is_current() {
    let text = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/pins/openvpn.txt")).unwrap();
    let pins = ovpn_pins::parse(&text).unwrap();
    assert_eq!(pins, *PINS);
    assert!(Version::parse(&pins.version).unwrap() >= Version::parse(&pins.min_version).unwrap());
    for (url, sha) in [(&pins.msi_x64_url, &pins.msi_x64_sha256), (&pins.msi_arm64_url, &pins.msi_arm64_sha256)] {
        assert!(url.starts_with("https://swupdate.openvpn.org/community/releases/OpenVPN-"), "{url}");
        assert!(sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()), "{sha}");
    }
    assert!(!pins.signer.is_empty() && !pins.features.is_empty());
    // The app's copy (platform-win/src/pure/openvpn_pins.rs) is generated from the same file.
    let generated = ovpn_pins::render_rust(&pins);
    let app = Path::new(env!("CARGO_MANIFEST_DIR")).join("../platform-win/src/pure/openvpn_pins.rs");
    if std::env::var_os("WINVPN_WRITE_PINS").is_some() {
        std::fs::write(&app, &generated).unwrap();
    }
    assert_eq!(std::fs::read_to_string(&app).unwrap(), generated, "run with WINVPN_WRITE_PINS=1");
}
```

(`use macvpn_helper::windows::ovpn_pins;` too.) `cipher` alone in a 2.6 client is only the fallback for old servers, but the conservative rule (no AEAD in the list → Wintun) costs only speed, never a connection. Add `pub fn dco_incompatible(line: &[u8]) -> bool` to `shared/ovpn_log.rs` (portable, next to `ovpn_done`), matching the pinned OpenVPN's message(s) that DCO was disabled or cannot be used for an option (copy them from its source; the test pins one).

- [x] **Step 4: Implement**

`ovpn_args.rs`:

```rust
//! The command line of `openvpn.exe` in the WinVPN Service: only the run directory (a UUID below the service's
//! data directory), a port number and fixed words. The management options come after the config, so they override
//! the same directives of the config (which the Windows tier forbids anyway). No `--log`: stdout and stderr go to
//! the service, which masks them into the connection log.

use std::ffi::OsString;
use std::path::Path;

/// The data-channel driver of one connection (decision 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Driver {
    Dco,
    Wintun,
    TapWindows6,
}

impl Driver {
    pub fn arg(self) -> &'static str {
        match self {
            Driver::Dco => "ovpn-dco",
            Driver::Wintun => "wintun",
            Driver::TapWindows6 => "tap-windows6",
        }
    }

    /// The driver's name in messages and System Status.
    pub fn name(self) -> &'static str {
        match self {
            Driver::Dco => "OpenVPN DCO",
            Driver::Wintun => "Wintun",
            Driver::TapWindows6 => "TAP-Windows6",
        }
    }
}

const AEAD: [&str; 4] = ["AES-128-GCM", "AES-192-GCM", "AES-256-GCM", "CHACHA20-POLY1305"];

/// The driver for a validated config: TAP-Windows6 for a layer-2 device (`dev tap…`, `dev-type tap`); Wintun for
/// what DCO cannot run (compression other than `compress stub-v2`, `fragment`, a static `secret`, `disable-dco`,
/// a `cipher` / `data-ciphers` / `data-ciphers-fallback` list without an AEAD cipher); DCO otherwise. Reads the
/// directives the validator accepted: top level and `<connection>` blocks, skipping comments and inline blocks,
/// `setenv opt <d>` counted as `<d>`. Never reads `windows-driver` (forbidden on Windows).
pub fn choose_driver(config: &str) -> Driver {
    let mut wintun = false;
    let mut in_block: Option<String> = None;
    for raw in config.lines() {
        let line = raw.trim();
        if let Some(tag) = &in_block {
            if line.eq_ignore_ascii_case(&format!("</{tag}>")) {
                in_block = None;
            }
            continue;
        }
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(tag) = line.strip_prefix('<').and_then(|t| t.strip_suffix('>')) {
            if !tag.starts_with('/') && !tag.eq_ignore_ascii_case("connection") {
                in_block = Some(tag.to_ascii_lowercase());
            }
            continue;
        }
        let mut words = line.split_whitespace().map(|w| w.trim_matches(|c| c == '"' || c == '\''));
        let mut d = words.next().unwrap_or_default().trim_start_matches("--").to_ascii_lowercase();
        if d == "setenv" && words.next().is_some_and(|w| w.eq_ignore_ascii_case("opt")) {
            d = words.next().unwrap_or_default().to_ascii_lowercase();
        }
        let args: Vec<&str> = words.collect();
        match d.as_str() {
            "dev" if args.first().is_some_and(|a| a.to_ascii_lowercase().starts_with("tap")) => return Driver::TapWindows6,
            "dev-type" if args.first().is_some_and(|a| a.eq_ignore_ascii_case("tap")) => return Driver::TapWindows6,
            "comp-lzo" | "fragment" | "secret" | "disable-dco" => wintun = true,
            "compress" if args.first().is_none_or(|a| !a.eq_ignore_ascii_case("stub-v2")) => wintun = true,
            "cipher" | "data-ciphers" | "data-ciphers-fallback" | "ncp-ciphers" => {
                let list = args.first().copied().unwrap_or_default().to_ascii_uppercase();
                if !list.split(':').any(|c| AEAD.contains(&c)) {
                    wintun = true;
                }
            }
            _ => {}
        }
    }
    if wintun { Driver::Wintun } else { Driver::Dco }
}

/// `user_pass`: credentials go through the management bridge; `keypass`: the private key's password file.
pub fn argv(run: &Path, port: u16, driver: Driver, debug: bool, user_pass: bool, keypass: bool) -> Vec<OsString> {
    let word = |s: &str| OsString::from(s);
    let mut a = vec![word("--config"), run.join("config.ovpn").into_os_string()];
    a.extend(["--script-security", "1", "--windows-driver", driver.arg(), "--verb", if debug { "5" } else { "3" }].map(word));
    a.extend([word("--management"), word("127.0.0.1"), OsString::from(port.to_string()), run.join("mgmt.pw").into_os_string()]);
    a.extend(
        [
            "--management-hold",
            "--management-query-passwords",
            "--auth-retry",
            "interact",
            "--setenv",
            "IV_SSO",
            "openurl,webauth,crtext",
        ]
        .map(word),
    );
    if user_pass {
        a.push(word("--auth-user-pass"));
    }
    if keypass {
        a.extend([word("--askpass"), run.join("askpass").into_os_string()]);
    }
    a
}

pub use macvpn_core::service_proto::Version;

// In crates/core/src/service_proto.rs (added by this task; the app compares versions with the same type):
/// `major.minor.patch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version(pub u16, pub u16, pub u16);

impl Version {
    /// Exactly three dot-separated decimal parts, each 1–5 digits.
    pub fn parse(s: &str) -> Option<Version> {
        let parts: Vec<u16> = s
            .split('.')
            .map(|p| if !p.is_empty() && p.len() <= 5 && p.bytes().all(|b| b.is_ascii_digit()) { p.parse().ok() } else { None })
            .collect::<Option<Vec<u16>>>()?;
        match parts.as_slice() {
            [a, b, c] => Some(Version(*a, *b, *c)),
            _ => None,
        }
    }

    pub fn from_file_version(v: (u16, u16, u16, u16)) -> Version {
        Version(v.0, v.1, v.2)
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.0, self.1, self.2)
    }
}
```


`ovpn_pins.rs`: `pub struct OpenVpnPins { pub version, min_version, signer, msi_x64_url, msi_x64_sha256, msi_arm64_url, msi_arm64_sha256, features: String }` (all `String`), `pub fn parse(text) -> Result<OpenVpnPins, String>` (every key exactly once, tab-separated, `#` comments; unknown keys refused), `pub static PINS: LazyLock<OpenVpnPins> = LazyLock::new(|| parse(include_str!("../../../../scripts/pins/openvpn.txt")).expect("valid pins"));` and `pub fn render_rust(p) -> String` writing a file with a `//! Generated from scripts/pins/openvpn.txt by crates/helper/tests/ovpn_windows.rs (WINVPN_WRITE_PINS=1); do not edit.` header and one `pub const` per field (`OPENVPN_VERSION`, `OPENVPN_MIN`, `OPENVPN_SIGNER`, `OPENVPN_MSI_X64_URL`, `OPENVPN_MSI_X64_SHA256`, `OPENVPN_MSI_ARM64_URL`, `OPENVPN_MSI_ARM64_SHA256`, `OPENVPN_FEATURES`). `include_str!` is not an OS `cfg` (the cfg rule bans `include!` only). Generate the app's copy: `WINVPN_WRITE_PINS=1 cargo test --locked -p macvpn-helper --test ovpn_windows`, then run without the variable.

- [x] **Step 5: Run and commit**

Run: `cargo test --locked -p macvpn-helper --test ovpn_windows && cargo test --locked -p macvpn-platform-win && scripts/check-windows.sh`
Expected: PASS.

```bash
git add crates/helper crates/platform-win/src/pure scripts/pins/openvpn.txt
git commit -m "feat: OpenVPN on Windows – the fixed argv, the version policy, the pinned installer" -m "OpenVPN <version> (min 2.6.0 for DCO): both MSIs verified with GnuPG (<key fingerprint>) and Authenticode (signer <CN>); features <list>: openvpn.exe, DCO, TAP-Windows6, Wintun (decision 4); driver files and versions <list>. The service picks DCO, Wintun or TAP-Windows6 per connection from the validated config. The app's copy of the pins is generated from scripts/pins/openvpn.txt." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**As built (Task 10, 2026-10-22):**
- **Pinned: OpenVPN 2.6.23, installer I002** (`scripts/pins/openvpn.txt`). Sources: `https://openvpn.net/community-downloads/` lists only 2.7.8 now; the 2.6 tags and dates come from `github.com/OpenVPN/openvpn` (v2.6.23: 2026-09-23) and `github.com/OpenVPN/openvpn-build`; the MSIs `https://swupdate.openvpn.org/community/releases/OpenVPN-2.6.23-I002-{amd64,arm64}.msi` (Last-Modified 2026-10-07, 15 days before this task; there is no I001 MSI on the server; the host redirects to `swupdate.openvpn.net`, which Task 17's download must allow). SHA-256 amd64 `31809e97debe44c12be06ed892c2a43e55b67b31cb852827b7ec8f2d6c0b8dc6`, arm64 `1c5e21a537fb920f251de9f842f2582d744901d45a1cc5f1e911eade87b2d63f` (computed on the Mac and again on the Windows machine). GnuPG: both `.asc` good, signing subkey `33DA8C9EAE0EAE8C73172C10822F6DF096D04874` of the security mailing list key `F554A3687412CFFEBDEFE0A312F5F7B42F2B01E7` (the downloads page no longer prints a fingerprint; the key came from `https://swupdate.openvpn.net/community/keys/security.key.asc` and matches keys.openpgp.org). Authenticode (`Get-AuthenticodeSignature` on the VM): both MSIs and the `openvpn.exe` extracted from each (7-Zip on the Mac, never run) `Valid`, signer simple name **`OpenVPN Inc.`** (issuer DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1, thumbprint `32BF9F103192726DAA416FEF348066E5F2D831CF`).
- **2.7 is not pinned and breaks decision 4:** OpenVPN 2.7 removed the Wintun driver (`Changes.rst` of v2.7.8: "Support for wintun Windows driver has been removed … fall back automatically to tap-windows6"). winget's `OpenVPNTechnologies.OpenVPN` and an existing installation will be 2.7.x: Task 13 must not pass `--windows-driver wintun` to a 2.7 `openvpn.exe` (use TAP-Windows6 there), and Task 17's winget path installs 2.7 (no Wintun feature). The same holds on **ARM64: its 2.6.23 MSI has no `Drivers.Wintun` feature** — so the pins carry one feature list per MSI (`msi_x64_features` / `msi_arm64_features`, constants `OPENVPN_MSI_X64_FEATURES` / `OPENVPN_MSI_ARM64_FEATURES`, instead of one `features`): x64 `OpenVPN,Drivers,Drivers.OvpnDco,Drivers.TAPWindows6,Drivers.Wintun`, ARM64 the same without `Drivers.Wintun` (an unknown feature in `ADDLOCAL` fails the install). Task 13 must map a Wintun choice to TAP-Windows6 where Wintun is not installed or `openvpn.exe` is 2.7+ (TAP-Windows6 runs layer 3 too).
- **The MSI (Feature table, both arches):** `OpenVPN` (level 2; `openvpn.exe` 2.6.23.0, its DLLs, `tapctl.exe`, **and `openvpnserv.exe` with the `OpenVPNServiceInteractive` service, start type automatic** — the Interactive Service cannot be left out by feature: it is a component of `OpenVPN` itself, so decision 4's "no Interactive Service" holds only for `OpenVPN.Service` / `openvpnserv2.exe`; the maintainer decides whether Task 17 disables it — decided 2026-10-22: it does, see decision 4), `Drivers` (1), `Drivers.OvpnDco` (0, raised to 1 by the condition `WIN102004`), `Drivers.TAPWindows6` (1), `Drivers.Wintun` (1, x64 only); left out: `OpenVPN.GUI`, `OpenVPN.GUI.OnLogon`, `OpenVPN.Service`, `OpenVPN.PLAP.Register`, `OpenVPN.Documentation`, `OpenVPN.SampleCfg`, `OpenSSL`, `EasyRSA`. `INSTALLLEVEL` 2, `ProductVersion` 2.6.2302. Driver versions: `ovpn-dco.sys` 1.3.4.0 (File table, two builds: nx20 and nx21); TAP-Windows6 and Wintun come as merge modules whose drivers are not in the File table (installed by a custom action): `tap0901` module 9.27.0, `wintun` module 0.8 (ModuleSignature). The CI job of Task 21 compares installed driver versions with these.
- **`choose_driver` follows the pinned source (2.6.23 `dco.c`), not Step 3's sketch:** `compress stub-v2` disables DCO too (`dco_check_option` refuses any `comp.alg` but `UNDEF`; only a *pushed* stub-v2 is accepted), so every `compress` but `compress migrate` → Wintun; also `allow-compression` other than `no`, `http-proxy`, `socks-proxy` → Wintun; a cipher list is DCO only when **every** entry (an optional `?` marker ignored, any case) is `AES-128/192/256-GCM` or `CHACHA20-POLY1305` (`dco_check_option` checks each token, not "at least one AEAD"). The test pins these cases, `setenv opt`, comments, `windows-driver` never read. A wrong guess towards DCO is not fatal: OpenVPN 2.6 then ignores `--windows-driver ovpn-dco` and uses TAP-Windows6 itself (`options.c`). `docs/openvpn-directives.md`'s table (Task 2) was updated to the same rules.
- **`dco_incompatible`** (`shared/ovpn_log.rs`) matches OpenVPN 2.6.23's own lines for a pushed option DCO cannot run: "Compression or compression stub framing is not allowed since data-channel offloading is enabled" (`comp.c`), "OPTIONS ERROR: pushed options are incompatible with data channel offload" (`init.c`, after "Server did not request DATA_V2 packet format"), "FATAL: DCO does not support" (`ssl.c`); never an `ECHO:` line; startup notes ("… disables data channel offload") do not count (OpenVPN falls back by itself). Step 3's sample line was not OpenVPN's wording.
- `argv` joins the run directory's file names with `\` whatever the host (`in_run`), so the test's Windows paths hold on the Mac; `Version` (in `service_proto`, re-exported by `ovpn_args`) also derives `Hash`; `parse` of the pins refuses a missing, repeated or unknown key, a line without a tab and an empty or padded value (tested). `render_rust` writes each `pub const` on one line when it fits 120 columns, else as `rustfmt` breaks it, so the generated file passes `cargo fmt --check`.
- On the Windows machine `ovpn_windows` passes (6/6) and workspace clippy is clean; the run also showed two failures outside this task, in Task 2's host-OS-dependent core tests (`openvpn_tiers::macos_tiers_equal_the_1_4_golden`, `validator_arguments::wireguard_valid_values`: on Windows the host tier is Windows), left for the wave merge.

**Re-pinned (2026-10-22, decision 4 amended): OpenVPN 2.7.8, DCO and TAP-Windows6, no Wintun.** Supersedes the 2.6.23 pins, the Wintun rows and the `--windows-driver` argv above.
- **Pins** (`scripts/pins/openvpn.txt`): `OpenVPN-2.7.8-I001-{amd64,arm64}.msi` from `https://swupdate.openvpn.org/community/releases/` (listed on `https://openvpn.net/community-downloads/`; 301 to `swupdate.openvpn.net`; Last-Modified 2026-10-07). SHA-256 amd64 `1ea61a3056905b90607d4b0f084c04e5cf3043e07cf192d9cd44b0474f29cc49`, arm64 `6fc0e8899cc5275ee297fb837bc84aa2bc49f8ef96d7ad93ee3fee1e7163a25c` (on the Mac and again on the Windows machine). GnuPG: both `.asc` and `openvpn-2.7.8.tar.gz.asc` good, subkey `33DA8C9EAE0EAE8C73172C10822F6DF096D04874` of `F554A3687412CFFEBDEFE0A312F5F7B42F2B01E7`. Authenticode (`Get-AuthenticodeSignature` on the VM; the binaries extracted with 7-Zip on the Mac, never run): both MSIs, `openvpn.exe` and `openvpnserv.exe` (2.7.8.0) of each `Valid`, signer `OpenVPN Inc.` (the same DigiCert CA and thumbprint as 2.6.23). `min_version` stays 2.6.0: the argv uses only options 2.6.0 has, and both lines pick the same driver from it.
- **The MSI** (Feature table, identical on x64 and ARM64; `ProductVersion` 2.7.801, `INSTALLLEVEL` 2): `OpenVPN` (2; `openvpn.exe`, DLLs, `tapctl.exe`, `openvpnserv.exe` = `OpenVPNServiceInteractive`, start type 2 = automatic), `Drivers` (1), `Drivers.OvpnDco` (0, raised to 1 by `WIN102004`), `Drivers.TAPWindows6` (1); **no `Drivers.Wintun` on either architecture**, so both feature lists are `OpenVPN,Drivers,Drivers.OvpnDco,Drivers.TAPWindows6` (the two pin keys stay: a later version may differ again). Left out as before: `OpenVPN.GUI`, `OpenVPN.GUI.OnLogon`, `OpenVPN.Service` (`OpenVPNService`, `openvpnserv2.exe`), `OpenVPN.PLAP.Register`, `OpenVPN.Documentation`, `OpenVPN.SampleCfg`, `OpenSSL`, `EasyRSA`. Drivers: `ovpn-dco.sys` 2.8.13.0 (nx20 and nx21 builds, signed by Microsoft Windows Hardware Compatibility Publisher), TAP-Windows6 merge module `tap0901` 9.27.0 (ModuleSignature).
- **Driver selection in 2.7** (`options.c` of 2.7.8): `--windows-driver` only prints "DEPRECATED OPTION … Wintun support has been removed" and changes nothing; the driver is DCO unless DCO is disabled (by `--disable-dco` or by OpenVPN's own checks), else TAP-Windows6. So `Driver::args()` is empty for DCO and `--disable-dco` for TAP-Windows6 (2.6.23 `options.c` picks the same: no `windows_driver` set → DCO if enabled, else TAP-Windows6). `choose_driver` returns TAP-Windows6 for every case it returned Wintun for: 2.7.8's `dco_check_option` / `_ce` / `_startup_option` keep the 2.6.23 client rules (compression contexts, `allow-compression` but `no` — 2.7 maps `yes` to `asym` —, non-DCO ciphers, `fragment`, proxies, static keys; the changes are server-mode and FreeBSD only). `dco_incompatible`'s three lines have the same wording in 2.7.8 (`comp.c`, `init.c`, `ssl.c`). `OpenVpnFacts::wintun` is removed (the protocol is unreleased; `SERVICE_VERSION` stays 1).

## Task 11: System Status' engine rows

**Goal:** System Status on Windows shows three rows (WinVPN Service, OpenVPN Community, WireGuard) with their details and the OpenVPN "Install"/"Update" action, plus a note that native Windows VPNs come later, instead of 2a's single engine note. macOS' view model and window are unchanged.

**Files:**
- Modify: `crates/platform-api/src/setup.rs` (`EngineReport`, `EngineRow`, `SetupReport::{engine, later_kinds}`, `is_complete`, `is_available`), `crates/platform-api/tests/setup_report.rs`
- Modify: `crates/app-core/src/setup.rs` (`EngineRowsView`, `SetupView::with_engine`), `crates/app-core/tests/setup.rs` (or the module's tests), `app/src-tauri/src/state.rs`, the view model's `unavailableReason` mapping (`ViewModel::set_engine_missing`'s sibling for `later_kinds`)
- Modify: `app/ui/src/lib/api.ts`, `app/ui/src/lib/Setup.svelte`, `app/ui/src/lib/setup.test.ts` (new), `crates/core/l10n/strings.json`

- [x] **Step 1: Write the failing tests**

`crates/platform-api/tests/setup_report.rs`:

```rust
use macvpn_core::models::VPNKind;
use macvpn_platform_api::setup::{EngineReport, EngineRow, SetupReport};

fn row(ok: bool) -> EngineRow {
    EngineRow { ok, usable: ok, detail: String::new(), action: None }
}

#[test]
fn an_engine_report_decides_availability_per_kind() {
    let r = SetupReport {
        engine: Some(EngineReport { service: row(true), openvpn: row(false), wireguard: row(true) }),
        later_kinds: vec![(VPNKind::L2tp, "later".into()), (VPNKind::Cisco, "later".into()), (VPNKind::Strongswan, "later".into()), (VPNKind::Sstp, "later".into())],
        ..SetupReport::unknown()
    };
    assert!(r.is_available(VPNKind::Wireguard));
    assert!(!r.is_available(VPNKind::Openvpn));
    assert!(!r.is_available(VPNKind::L2tp) && !r.is_available(VPNKind::Sstp));
    assert_eq!(r.later_reason(VPNKind::Cisco), Some("later"));
    // OpenVPN missing is something the user can install: not complete.
    assert!(!r.is_complete());
    let all = SetupReport { engine: Some(EngineReport { service: row(true), openvpn: row(true), wireguard: row(true) }), ..r.clone() };
    assert!(all.is_complete());
    // A missing driver: red with "repair", but OpenVPN still usable.
    let repair = EngineRow { ok: false, usable: true, detail: String::new(), action: Some("repair") };
    let r2 = SetupReport { engine: Some(EngineReport { service: row(true), openvpn: repair, wireguard: row(true) }), ..r };
    assert!(r2.is_available(VPNKind::Openvpn) && !r2.is_complete());
}

#[test]
fn macos_reports_are_unchanged() {
    let r = SetupReport::unknown();
    assert_eq!(r.engine, None);
    assert!(r.later_kinds.is_empty());
}
```

UI (`app/ui/src/lib/setup.test.ts`, vitest, as the other `*.test.ts`): a pure helper `engineRows(setup)` returning `[]` without `engine` and the three rows in order with their titles' l10n keys (`'WinVPN Service'`, `'OpenVPN Community'`, `'WireGuard'`) when present.

- [x] **Step 2: Run them to verify they fail**

Run: `cargo test --locked -p macvpn-platform-api --test setup_report && (cd app/ui && npm test)`
Expected: FAIL (no `EngineReport`; no `engineRows`).

- [x] **Step 3: Implement**

`platform-api/src/setup.rs`:

```rust
/// One row of the engine (Windows): green or red, its detail, and the action the row offers when it is red or an
/// update exists (`"install"` / `"update"`; only OpenVPN has one).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EngineRow {
    /// Green: nothing to install or repair.
    pub ok: bool,
    /// Connections can start (OpenVPN: `openvpn.exe` passed its checks and at least one driver exists; a missing
    /// driver refuses only the connections that need it, with its own message).
    pub usable: bool,
    pub detail: String,
    pub action: Option<&'static str>,
}

/// The WinVPN Service's engine as System Status shows it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EngineReport {
    pub service: EngineRow,
    pub openvpn: EngineRow,
    pub wireguard: EngineRow,
}
```

`SetupReport` gets `pub engine: Option<EngineReport>` and `pub later_kinds: Vec<(VPNKind, String)>` (both default-empty; macOS never sets them) and:

```rust
    /// The reason a kind is not offered on this platform yet (WinVPN: the native VPNs, 2c).
    pub fn later_reason(&self, kind: VPNKind) -> Option<&str> {
        self.later_kinds.iter().find(|(k, _)| *k == kind).map(|(_, r)| r.as_str())
    }
```

`is_available`: after the `engine_missing` check, `if self.later_reason(kind).is_some() { return false; }`, then `if let Some(e) = &self.engine { return match kind { VPNKind::Openvpn => e.service.usable && e.openvpn.usable, VPNKind::Wireguard => e.service.usable && e.wireguard.usable, _ => false }; }`, then the macOS rules unchanged. `is_complete`: after the `engine_missing` check, `if let Some(e) = &self.engine { return e.service.ok && e.openvpn.ok && e.wireguard.ok; }`.

`app-core/src/setup.rs`:

```rust
/// System Status' engine rows (WinVPN); absent from the JSON on macOS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineRowsView {
    pub service: CheckRow,
    pub openvpn: CheckRow,
    pub wireguard: CheckRow,
    /// "install" / "repair" / "update" / none: the OpenVPN row's button.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub openvpn_action: Option<&'static str>,
    /// The note under the rows: native Windows VPNs come later.
    pub later_note: String,
}
```

`SetupView` gets `#[serde(skip_serializing_if = "Option::is_none")] pub engine: Option<EngineRowsView>` and `pub fn with_engine(mut self, report: Option<&EngineReport>, later_note: Option<String>) -> SetupView` that, for `Some`, sets `engine`, clears `homebrew`, `tools`, `root`, `upgrade_notice` and leaves `brew_output` / `brew_running` (the OpenVPN installer's output uses them) and `can_install_tools = report.openvpn.action.is_some() && !brew_running`. `state.rs` (the view-model build): after `.with_engine_note(…)`, add `.with_engine(setup.engine.as_ref(), crate::platform::get().setup().later_note())` (`setup` is the stored `SetupReport` there), and after `vm.set_engine_missing(…)` add `vm.set_later_kinds(&setup.later_kinds)`; add `SystemSetup::later_note(&self) -> Option<String> { None }` to the trait (macOS unchanged). `ViewModel::set_later_kinds` (in `crates/app-core/src/view_model.rs`, next to `set_engine_missing`) marks each row whose kind is listed unavailable with that reason (the same `unavailable_reason` field, absent on macOS). The `connect` command and the control API's `up` refuse such a kind with its reason the way 2a made them refuse with `engine_missing` (`ControlHost::engine_missing`): extend both to look at `later_reason(kind)` too, with a test next to 2a's.

`Setup.svelte`: when `setup.engine` is present, render three `CheckRow`s titled `tr('WinVPN Service')`, `tr('OpenVPN Community')`, `tr('WireGuard')`, the OpenVPN row's button (`tr('Install')`, `tr('Repair')` or `tr('Update')`) calling the existing `api.setupInstallTools()` (the "install the missing tools" command, which on Windows installs OpenVPN: Task 17), the installer output box (the existing `brewOutput` block), and `setup.engine.laterNote` as a secondary line; the hero text uses a Windows variant (`variants.windows` of the existing "MacVPN uses the VPN tools from Homebrew…" key: "WinVPN connects OpenVPN and WireGuard through the WinVPN Service. OpenVPN Community is installed here when you need it."). 2a's `engineNote` block stays for the engine-missing state. `api.ts`: `engine?: { service: CheckRow; openvpn: CheckRow; wireguard: CheckRow; openvpnAction?: 'install' | 'repair' | 'update'; laterNote: string }`.

`strings.json` (scope `ui` unless noted; `"only": ["windows"]`):
- `"WinVPN Service"` → `"WinVPN szolgáltatás"`
- `"OpenVPN Community"` → `"OpenVPN Community"`
- `"Update"` (if not present) → `"Frissítés"`
- `"Repair"` → `"Javítás"`
- `"Native Windows VPNs (L2TP, IKEv2, SSTP, Cisco IPsec) come in a later version of WinVPN."` → `"A Windows saját VPN-jei (L2TP, IKEv2, SSTP, Cisco IPsec) a WinVPN egy későbbi verziójában érkeznek."` (scope `core`)
- the Windows variant of the hero text, en and hu: `"A WinVPN a WinVPN szolgáltatáson keresztül kapcsolja az OpenVPN- és a WireGuard-kapcsolatokat. Az OpenVPN Communityt itt telepítheted, ha szükséged van rá."`

- [x] **Step 4: Run**

Run: `CI=1 cargo test --workspace --locked && cargo test --locked -p macvpn-app-core --test compat_1_4 && node scripts/l10n-baseline.mjs --check && (cd app/ui && npm test && npm run build)`
Expected: PASS; compat fixtures unchanged (the new fields are absent on macOS); the l10n baseline: only new keys.

- [x] **Step 5: Commit**

```bash
git add crates/platform-api crates/app-core app/src-tauri/src/state.rs app/ui/src crates/core/l10n/strings.json
git commit -m "feat: System Status shows the WinVPN Service, OpenVPN and WireGuard" -m "SetupReport::engine and later_kinds (absent on macOS) decide availability per kind; the view model's engine rows replace the Homebrew, tools and root rows on Windows; native VPNs carry 'later' as their unavailable reason." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**As built (Task 11):** as planned (`EngineRow`, `EngineReport` also re-exported at the crate root; `SetupReport::{engine, later_kinds, later_reason}`; `SystemSetup::later_note` defaults to `None`; `EngineRowsView`, `SetupView::{engine, with_engine}`; `ViewModel::set_later_kinds`). Adaptations: the control API's check is a new `ControlHost::later_reason(key) -> Option<String>` (default `None`; the app's host maps the key to its managed connection's kind), asked right after `engine_missing` in `up` (test `a_later_kind_fails_with_its_reason`); `connect_key` and the `connect` command refuse a later kind with `failed` / its reason (test in `app/src-tauri/src/control.rs`). The UI test is `node --test` (the repo has no vitest): `setup.ts::engineRows(setup, tr)` takes the lookup so its titles stay literal `tr('…')` keys (the l10n rules); `CheckRow.svelte` got `showAction` (the OpenVPN row's "Update" shows while the row is green); System Status hides "L2TP and Cisco IPsec work without these." when the engine rows are shown. `strings.json`: the plan's entries plus `"WireGuard"` (the row's title, `only: windows`); the hero key lost `only: ["macos"]` and got `variants.windows` (macOS text unchanged, the baseline is identical), so `l10n.test.ts`' macOS-only sample moved to another macOS-only key. Hungarian hero: "A WinVPN az OpenVPN- és a WireGuard-kapcsolatokat a WinVPN szolgáltatáson keresztül építi fel. Az OpenVPN Communityt itt telepítheted, ha szükséged van rá."

## Task 12: the service host (SCM, the pipe server, the data directory, the test console)

**Goal:** `WinVPNService.exe service` runs as a Windows service: it hardens its DLL search, puts itself in a kill-on-close job, checks or creates `C:\ProgramData\WinVPN`, serves `\\.\pipe\WinVPN` with one thread per client (identity from the token, 5 s to send a request, 8 in flight per SID), takes a user's connections down at logoff, and everything down at stop. The debug-only `console` mode runs the same server as the standard user for the tests.

**Files:**
- Create: `crates/helper/src/windows/sys/{mod,host,server,data_dir,session,console,service_log,job}.rs`
- Modify: `crates/helper/src/windows/mod.rs` (`#[cfg(windows)] #[allow(unsafe_code)] mod sys;`, `main` dispatches to `sys::main` on Windows; elsewhere it still refuses), `crates/helper/Cargo.toml`, `crates/winsys/src/file.rs` (`Protection::Admins`, `protection_of`), `crates/winsys/src/sid.rs` (`builtin_administrators` from Task 4 if not there)
- Create: `crates/helper/tests/service_pipe.rs` (Windows), `crates/helper/tests/service_admin.rs` (Windows, admin, ignored)

`crates/helper/Cargo.toml` (shared with Tasks 13, 14: union of features, sorted):

```toml
[target.'cfg(windows)'.dependencies]
macvpn-winsys = { path = "../winsys" }
windows-sys = { version = "=0.61.2", features = [
    "Win32_Foundation",
    "Win32_Security",
    "Win32_Storage_FileSystem",
    "Win32_System_JobObjects",
    "Win32_System_RemoteDesktop",
    "Win32_System_Services",
    "Win32_System_Threading",
    "Win32_UI_Shell",
] }
```

- [x] **Step 1: Write the failing tests** (`crates/helper/tests/service_pipe.rs`; runs over SSH as the standard user)

```rust
//! The WinVPN Service's server in its debug console mode, over a real pipe, as a standard user.
#![cfg(windows)]

use macvpn_core::service_proto::{self as proto, Response};
use macvpn_winsys::pipe::{self, ServerTrust};
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

const ID: &str = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";
const WG: &str = "[Interface]\nPrivateKey = bWFjdnBuLXRlc3QtcHJpdmF0ZS1rZXktMzJieXRlcyE=\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = bWFjdnBuLXRlc3QtcHVibGljLS1rZXktMzJieXRlcyE=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.1:51820\n";

struct Console {
    child: Child,
    pipe: String,
    data: std::path::PathBuf,
}

impl Console {
    fn start(fake: bool) -> Console {
        let pipe = format!(r"\\.\pipe\WinVPN-test-{}", uuid::Uuid::new_v4());
        let data = std::env::temp_dir().join(format!("winvpn-console-{}", uuid::Uuid::new_v4()));
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_mvpn"));
        cmd.args(["console", "--pipe", &pipe, "--data", data.to_str().unwrap()]);
        if fake {
            cmd.arg("--fake-engine");
        }
        let mut child = cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        let mut first = String::new();
        BufReader::new(child.stdout.as_mut().unwrap()).read_line(&mut first).unwrap();
        assert_eq!(first.trim(), "ready");
        Console { child, pipe, data }
    }

    fn call(&self, args: &[&str], body: &[u8]) -> Response {
        let mut s = pipe::connect_with(&self.pipe, Duration::from_secs(5), ServerTrust::SameUser).unwrap();
        proto::write_request(&mut s, args, body).unwrap();
        proto::read_response(&mut s).unwrap()
    }
}

impl Drop for Console {
    fn drop(&mut self) {
        drop(self.child.stdin.take()); // closing stdin stops the console
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.data);
    }
}

fn framed(config: &str) -> Vec<u8> {
    format!("config {}\n{config}", config.len()).into_bytes()
}

#[test]
fn the_console_answers_the_protocol() {
    let c = Console::start(true);
    let v = c.call(&["version"], b"");
    assert_eq!((v.code, v.stdout.as_slice()), (0, &b"1\n"[..]));
    assert_eq!(c.call(&["up", "wireguard", ID, "--lang", "en"], &framed(WG)).code, 0);
    let st = String::from_utf8(c.call(&["status"], b"").stdout).unwrap();
    assert!(st.contains(ID), "{st}");
    assert_eq!(c.call(&["down", "wireguard", ID], b"").code, 0);
}

#[test]
fn a_malformed_or_slow_request_gets_no_service() {
    let c = Console::start(true);
    let mut s = pipe::connect_with(&c.pipe, Duration::from_secs(5), ServerTrust::SameUser).unwrap();
    s.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
    let r = proto::read_response(&mut s).unwrap();
    assert_eq!(r.code, 2);
    // Silent client: closed after the 5 s request timeout, with an answer of code 2.
    let mut s = pipe::connect_with(&c.pipe, Duration::from_secs(5), ServerTrust::SameUser).unwrap();
    let started = std::time::Instant::now();
    let r = proto::read_response(&mut s);
    assert!(started.elapsed() >= Duration::from_secs(5) && started.elapsed() < Duration::from_secs(9));
    assert!(r.map(|r| r.code == 2).unwrap_or(true));
}

#[test]
fn the_real_engines_fail_cleanly_without_admin_rights() {
    let c = Console::start(false);
    let r = c.call(&["up", "wireguard", ID, "--lang", "en"], &framed(WG));
    assert_eq!(r.code, 1);
    assert!(!String::from_utf8_lossy(&r.stderr).trim().is_empty());
    let r = c.call(&["engine"], b"");
    assert!(macvpn_core::service_proto::EngineFacts::parse(&r.stdout).is_some());
}

#[test]
fn the_console_refuses_an_unsafe_data_directory() {
    // A data directory that inherits the temp folder's permissions is not private: the console runs degraded.
    let data = std::env::temp_dir().join(format!("winvpn-open-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&data).unwrap();
    let pipe = format!(r"\\.\pipe\WinVPN-test-{}", uuid::Uuid::new_v4());
    let mut child = Command::new(env!("CARGO_BIN_EXE_mvpn"))
        .args(["console", "--pipe", &pipe, "--data", data.to_str().unwrap(), "--fake-engine", "--existing-data"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut first = String::new();
    BufReader::new(child.stdout.as_mut().unwrap()).read_line(&mut first).unwrap();
    assert_eq!(first.trim(), "ready");
    let mut s = pipe::connect_with(&pipe, Duration::from_secs(5), ServerTrust::SameUser).unwrap();
    proto::write_request(&mut s, &["up", "wireguard", ID, "--lang", "en"], &framed(WG)).unwrap();
    let r = proto::read_response(&mut s).unwrap();
    assert_eq!(r.code, 1);
    assert!(String::from_utf8_lossy(&r.stderr).contains("unsafe permissions"));
    drop(child.stdin.take());
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&data);
}
```

`crates/helper/tests/service_admin.rs` (ignored everywhere; listed in `scripts/ignored-everywhere.txt`):

```rust
//! Checks of the installed WinVPN Service (CI's windows-admin job after installing the MSI; the maintainer in an
//! elevated Git Bash on the VM).
#![cfg(windows)]

use macvpn_core::service_proto::{self as proto, EngineFacts, PIPE_NAME, SERVICE_VERSION};
use macvpn_winsys::pipe::{self, ServerTrust};
use std::time::Duration;

fn call(args: &[&str]) -> proto::Response {
    let mut s = pipe::connect_with(PIPE_NAME, Duration::from_secs(5), ServerTrust::LocalSystem).unwrap();
    proto::write_request(&mut s, args, b"").unwrap();
    proto::read_response(&mut s).unwrap()
}

#[test]
#[ignore = "admin: needs the installed WinVPN Service"]
fn admin_the_installed_service_answers() {
    assert_eq!(call(&["version"]).stdout, format!("{SERVICE_VERSION}\n").into_bytes());
    let facts = EngineFacts::parse(&call(&["engine"]).stdout).unwrap();
    assert_eq!(facts.problem, None, "the data directory must be in order");
}

#[test]
#[ignore = "admin: needs the installed WinVPN Service"]
fn admin_the_data_directory_is_system_and_administrators_only() {
    let out = std::process::Command::new(r"C:\Windows\System32\icacls.exe").arg(r"C:\ProgramData\WinVPN").output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("NT AUTHORITY\\SYSTEM:(OI)(CI)(F)") || text.contains("NT AUTHORITY\\SYSTEM:(OI)(CI)F"), "{text}");
    assert!(!text.contains("BUILTIN\\Users") && !text.contains("Everyone") && !text.contains("Authenticated Users"), "{text}");
}
```

(`icacls` prints localized group names on a non-English Windows; the CI runner and the VM are English. If the VM is not, compare SIDs with `icacls … /save` instead and say so in the checklist.)

- [x] **Step 2: Run them to verify they fail**

Run: `scripts/win-remote.sh run 'cargo test --locked -p macvpn-helper --test service_pipe'`
Expected: FAIL (`mvpn console` prints "Not available on this system yet" and exits 1: the test's `ready` assertion fails).

- [x] **Step 3: Implement**

`windows/mod.rs` `main`:

```rust
/// The Windows helper's entry point: `service` (started by the SCM), `console` (debug builds: the tests).
#[cfg(windows)]
pub fn main() -> i32 {
    sys::main(&std::env::args_os().map(|a| a.to_string_lossy().into_owned()).collect::<Vec<_>>())
}

/// Linux (phase 4) and any other target: no backend.
#[cfg(not(windows))]
pub fn main() -> i32 {
    let _ = writeln!(std::io::stderr(), "{}", tr("Not available on this system yet", &[]));
    1
}
```

`sys/mod.rs`:

```rust
//! The WinVPN Service on Windows: `WinVPNService.exe service` under the SCM; in debug builds also
//! `mvpn.exe console …` for the tests. Everything that calls Win32 for the service lives below this module.

mod console;
mod data_dir;
mod host;
mod job;
mod server;
mod service_log;
mod session;

use crate::windows::logs::FileLogStore;
use crate::windows::service::{Engine, EngineState, Host, LogStore, UpRequest};
use macvpn_core::models::VPNKind;
use macvpn_core::service_proto::{EngineFacts, OpenVpnFacts, SERVICE_VERSION, WireGuardFacts};

pub fn main(argv: &[String]) -> i32 {
    // Before anything loads a DLL: no current directory, no PATH in the DLL search.
    macvpn_winsys::dll::harden_process_search();
    match argv.get(1).map(String::as_str) {
        Some("service") => host::run(),
        #[cfg(debug_assertions)]
        Some("console") => console::main(&argv[2..]),
        _ => 2,
    }
}

/// An engine that cannot run (OpenVPN missing, wireguard.dll refused): every `up` answers its reason.
pub(crate) struct Unavailable(pub String);

impl Engine for Unavailable {
    fn up(&self, _req: &UpRequest<'_>) -> Result<(), String> {
        Err(self.0.clone())
    }
    fn down(&self, _id: &str) -> Result<(), String> {
        Ok(())
    }
    fn state(&self, _id: &str) -> Option<EngineState> {
        None
    }
}

/// The real environment of the service (and of the console without `--fake-engine`).
pub(crate) struct RealHost {
    pub openvpn: Box<dyn Engine>,
    pub wireguard: Box<dyn Engine>,
    pub logs: FileLogStore,
    pub problem: Option<String>,
    pub facts: Box<dyn Fn() -> (OpenVpnFacts, WireGuardFacts) + Send + Sync>,
}

impl Host for RealHost {
    fn engine(&self, kind: VPNKind) -> Option<&dyn Engine> {
        match kind {
            VPNKind::Openvpn => Some(&*self.openvpn),
            VPNKind::Wireguard => Some(&*self.wireguard),
            _ => None,
        }
    }
    fn facts(&self) -> EngineFacts {
        let (openvpn, wireguard) = (self.facts)();
        EngineFacts { service_version: SERVICE_VERSION, problem: self.problem.clone(), openvpn, wireguard }
    }
    fn logs(&self) -> &dyn LogStore {
        &self.logs
    }
    fn problem(&self) -> Option<String> {
        self.problem.clone()
    }
}

/// The two engines over a ready data directory (Tasks 13 and 14 each replace their `Unavailable` line).
pub(crate) fn engines(data: &std::sync::Arc<data_dir::DataDir>, log: &service_log::ServiceLog) -> (Box<dyn Engine>, Box<dyn Engine>) {
    let _ = (data, log);
    let later = crate::shared::l10n::tr("Not available on this system yet", &[]);
    (Box::new(Unavailable(later.clone())), Box::new(Unavailable(later)))
}
```

(The `let _ = (data, log);` disappears when Tasks 13 and 14 use them.)

`sys/job.rs`: `pub fn contain_self()`: `CreateJobObjectW(null, null)`, `SetInformationJobObject(JobObjectExtendedLimitInformation, LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)`, `AssignProcessToJobObject(job, GetCurrentProcess())`; the handle is leaked on purpose (it lives as long as the process; when the process ends, the last handle closes and every child – `openvpn.exe` – is killed). Failure is logged and fatal for `service` (fail closed: a VPN process must not outlive its service), ignored for `console`.

`sys/data_dir.rs`:

```rust
//! `C:\ProgramData\WinVPN` (spec 4.1): `run\<ID>\` and `logs\`. Any user may create folders in ProgramData, so an
//! existing `WinVPN` is used only if it is a real directory owned by SYSTEM or Administrators whose protected DACL
//! grants exactly SYSTEM and Administrators full access; anything else is not repaired (it may hold planted links):
//! the service runs degraded with the localized reason.

use macvpn_winsys::file::{self, Protection};
use macvpn_winsys::sid::Sid;
use std::io;
use std::path::{Path, PathBuf};

pub struct DataDir {
    pub root: PathBuf,
    pub run: PathBuf,
    pub logs: PathBuf,
    /// The protection of every directory and file the service creates here.
    pub protection: Protection,
}

pub fn unsafe_message(root: &Path) -> String {
    crate::shared::l10n::tr(
        "The folder %@ has unsafe permissions. An administrator must delete it, then restart the WinVPN Service.",
        &[&root.display().to_string()],
    )
}

/// The production directory, as SYSTEM.
pub fn open_service() -> Result<DataDir, String> {
    let program_data = macvpn_winsys::known::program_data().map_err(|_| unsafe_message(Path::new(r"C:\ProgramData\WinVPN")))?;
    open_at(&program_data.join("WinVPN"), Protection::Admins, &[Sid::local_system(), Sid::builtin_administrators()])
}

/// `root` with `protection`, created when missing; every level checked (no reparse point, the owner one of
/// `owners`, exactly `protection`'s DACL).
pub fn open_at(root: &Path, protection: Protection, owners: &[Sid]) -> Result<DataDir, String> {
    let fail = || unsafe_message(root);
    for dir in [root.to_path_buf(), root.join("run"), root.join("logs")] {
        ensure_dir(&dir, protection, owners).map_err(|_| fail())?;
    }
    let d = DataDir { root: root.to_path_buf(), run: root.join("run"), logs: root.join("logs"), protection };
    d.sweep_runs();
    Ok(d)
}

fn ensure_dir(dir: &Path, protection: Protection, owners: &[Sid]) -> io::Result<()> {
    match file::open_dir(dir, false) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            file::create_dir(dir, Some(protection))?;
        }
        Err(e) => return Err(e),
        Ok(_) => {}
    }
    let f = file::open_dir(dir, false)?;
    let info = file::info(&f)?;
    let ok = info.reparse_tag.is_none()
        && owners.contains(&info.owner)
        && file::protection_of(&f, true)? == Some(protection);
    if ok { Ok(()) } else { Err(io::Error::new(io::ErrorKind::PermissionDenied, "unsafe data directory")) }
}
```

Plus `DataDir::{make_run_dir(id) -> io::Result<PathBuf>, write_private(path, bytes) -> io::Result<()> (create-new, `protection`, no reparse following), remove_run_dir(id), sweep_runs()}` (sweep: every entry of `run\` whose name is a UUID and is a real directory: its files deleted by name, then the directory; anything else in `run\` is left and logged). Names come only from `cli::is_uuid` IDs. Check the actual field names of `file::Info` (owner, reparse tag) in `crates/winsys/src/file.rs` before writing; `macvpn_winsys::known::program_data()` is a new 15-line function (`SHGetKnownFolderPath(FOLDERID_ProgramData)`, freed with `CoTaskMemFree`; add `known.rs` to winsys with feature `Win32_UI_Shell`, `Win32_System_Com`). `Protection::Admins` in winsys: a protected DACL with `FILE_ALL_ACCESS` for SYSTEM and `BUILTIN\Administrators` (inheritable on directories), owner = the current user (SYSTEM in the service); `protection_of(file, dir)` returns which of the three shapes a handle has (extend 2a's `shape()`; its unit tests get one case for `Admins`).

`sys/server.rs`:

```rust
//! The accept loop of `\\.\pipe\WinVPN`: one thread per client. A client whose identity cannot be read is closed
//! unanswered (fail closed). Each client sends one request within 5 s and gets one answer.

use crate::shared::l10n::tr;
use crate::windows::service::{Caller, Host, Service};
use macvpn_core::service_proto::{self as proto, ProtoError, Response};
use macvpn_winsys::pipe::{Listener, PipeStream};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_IN_FLIGHT_PER_SID: usize = 8;

pub fn serve<H: Host + 'static>(listener: Listener, service: Arc<Service<H>>, stop: Arc<AtomicBool>, log: impl Fn(&str) + Send + Sync + 'static) {
    let in_flight: Arc<Mutex<HashMap<String, usize>>> = Arc::default();
    let log = Arc::new(log);
    while !stop.load(Ordering::SeqCst) {
        match listener.accept(Duration::from_millis(250)) {
            Ok(None) => {}
            Ok(Some((stream, Ok(peer)))) => {
                let sid = peer.sid.to_string();
                let (service, in_flight, log) = (service.clone(), in_flight.clone(), log.clone());
                let _ = std::thread::Builder::new()
                    .name("winvpn-request".into())
                    .spawn(move || handle(stream, sid, &service, &in_flight, &*log));
            }
            // Not identifiable (anonymous impersonation only, or gone): closed unanswered.
            Ok(Some((stream, Err(_)))) => drop(stream),
            Err(e) => {
                log(&format!("accept failed: {e}"));
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

fn handle<H: Host>(mut stream: PipeStream, sid: String, service: &Service<H>, in_flight: &Mutex<HashMap<String, usize>>, log: &dyn Fn(&str)) {
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    {
        let mut m = in_flight.lock().unwrap_or_else(PoisonError::into_inner);
        let n = m.entry(sid.clone()).or_default();
        if *n >= MAX_IN_FLIGHT_PER_SID {
            let _ = proto::write_response(&mut stream, &Response::fail(1, &tr("Too many requests", &[])));
            return;
        }
        *n += 1;
    }
    let _ = stream.set_read_timeout(Some(REQUEST_TIMEOUT));
    let answer = match proto::read_request(&mut stream) {
        Ok(req) => {
            let _ = stream.set_read_timeout(None);
            service.handle(&Caller { sid: sid.clone() }, &req)
        }
        Err(ProtoError::TooLarge) => Response::fail(2, &tr("The config is too large (1 MB at most)", &[])),
        Err(_) => Response::fail(2, &tr("Invalid input", &[])),
    };
    if let Err(e) = proto::write_response(&mut stream, &answer) {
        log(&format!("answer not delivered: {}", e.kind()));
    }
    let mut m = in_flight.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(n) = m.get_mut(&sid) {
        *n -= 1;
        if *n == 0 {
            m.remove(&sid);
        }
    }
}
```

(The request, with its secrets, is dropped (zeroized) at the end of the `Ok` arm, before the answer is written. Log lines name kinds and error kinds only: never request bytes.)

`sys/host.rs`: the SCM side (`windows-sys` `Win32_System_Services`):

```rust
//! `WinVPNService.exe service` under the SCM: service name `WinVPN` (the MSI's ServiceInstall), own process,
//! accepts STOP, SHUTDOWN and SESSIONCHANGE.

use super::data_dir::{self, DataDir};
use super::service_log::ServiceLog;
use super::{RealHost, Unavailable, engines, job, server, session};
use crate::windows::logs::FileLogStore;
use crate::windows::service::Service;
use macvpn_core::service_proto::PIPE_NAME;
use macvpn_winsys::pipe::{Endpoint, Listener};
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use windows_sys::Win32::Foundation::{ERROR_CALL_NOT_IMPLEMENTED, NO_ERROR};
use windows_sys::Win32::System::RemoteDesktop::WTS_SESSION_LOGOFF;
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_SESSIONCHANGE, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
    SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SESSIONCHANGE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP,
    SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STOP_PENDING, SERVICE_STOPPED,
    SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus, StartServiceCtrlDispatcherW,
};
use windows_sys::core::PWSTR;

static STOP: AtomicBool = AtomicBool::new(false);
/// The SERVICE_STATUS_HANDLE (an opaque pointer-sized value; 0 until registered).
static STATUS: AtomicIsize = AtomicIsize::new(0);
static SERVICE: OnceLock<Arc<Service<RealHost>>> = OnceLock::new();

pub fn run() -> i32 {
    let mut name: Vec<u16> = "WinVPN\0".encode_utf16().collect();
    let table = [
        SERVICE_TABLE_ENTRYW { lpServiceName: name.as_mut_ptr(), lpServiceProc: Some(service_main) },
        SERVICE_TABLE_ENTRYW { lpServiceName: std::ptr::null_mut(), lpServiceProc: None },
    ];
    // SAFETY: the table and the name live until the dispatcher returns (after the service has stopped).
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 { 1 } else { 0 }
}

fn set_status(state: u32, exit_code: u32) {
    let handle = STATUS.load(Ordering::SeqCst);
    if handle == 0 {
        return;
    }
    let pending = matches!(state, SERVICE_START_PENDING | SERVICE_STOP_PENDING);
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_SESSIONCHANGE
        } else {
            0
        },
        dwWin32ExitCode: exit_code,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: if pending { 10_000 } else { 0 },
    };
    // SAFETY: a handle RegisterServiceCtrlHandlerExW returned (never closed); `status` lives across the call.
    unsafe { SetServiceStatus(handle as _, &status) };
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
    let name: Vec<u16> = "WinVPN\0".encode_utf16().collect();
    // SAFETY: a NUL-terminated name; the handler is a 'static function; no context.
    let handle = unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(handler), std::ptr::null()) };
    if handle.is_null() {
        return;
    }
    STATUS.store(handle as isize, Ordering::SeqCst);
    set_status(SERVICE_START_PENDING, 0);
    // A VPN process must never outlive its service: no job, no service.
    if job::contain_self().is_err() {
        set_status(SERVICE_STOPPED, 1);
        return;
    }
    let (data, problem): (Option<Arc<DataDir>>, Option<String>) = match data_dir::open_service() {
        Ok(d) => (Some(Arc::new(d)), None),
        Err(p) => (None, Some(p)),
    };
    let log = match &data {
        Some(d) => ServiceLog::open(&d.root.join("service.log"), d.protection),
        None => ServiceLog::none(),
    };
    log.line("starting");
    let (openvpn, wireguard) = match (&data, &problem) {
        (Some(d), _) => engines(d, &log),
        (None, p) => {
            let reason = p.clone().unwrap_or_default();
            (Box::new(Unavailable(reason.clone())) as _, Box::new(Unavailable(reason)) as _)
        }
    };
    let logs_dir = data.as_ref().map(|d| d.logs.clone()).unwrap_or_default();
    let facts = super::facts_fn(data.clone());
    let host = RealHost { openvpn, wireguard, logs: FileLogStore::new(logs_dir), problem, facts };
    let service = Arc::new(Service::new(host));
    let _ = SERVICE.set(service.clone());
    let listener = loop {
        match Listener::bind_endpoint(PIPE_NAME, Endpoint::Service) {
            Ok(l) => break l,
            Err(e) => {
                log.line(&format!("cannot serve the pipe ({:?}); retrying in 5 s", e.kind()));
                if STOP.load(Ordering::SeqCst) {
                    set_status(SERVICE_STOPPED, 0);
                    return;
                }
                std::thread::sleep(Duration::from_secs(5));
            }
        }
    };
    set_status(SERVICE_RUNNING, 0);
    let stop = Arc::new(AtomicBool::new(false));
    let watch = stop.clone();
    std::thread::spawn(move || {
        while !STOP.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(200));
        }
        watch.store(true, Ordering::SeqCst);
    });
    let server_log = log.clone();
    server::serve(listener, service.clone(), stop, move |l| server_log.line(l));
    service.shutdown();
    log.line("stopped");
    set_status(SERVICE_STOPPED, 0);
}

unsafe extern "system" fn handler(control: u32, event: u32, _data: *mut c_void, _ctx: *mut c_void) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            STOP.store(true, Ordering::SeqCst);
            set_status(SERVICE_STOP_PENDING, 0);
            NO_ERROR
        }
        SERVICE_CONTROL_SESSIONCHANGE => {
            if event == WTS_SESSION_LOGOFF
                && let Some(s) = SERVICE.get().cloned()
            {
                std::thread::spawn(move || session::after_logoff(&s));
            }
            NO_ERROR
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR,
        _ => ERROR_CALL_NOT_IMPLEMENTED,
    }
}
```

`super::facts_fn(data)` (in `sys/mod.rs`) returns the `facts` closure: in this task `Box::new(|| (OpenVpnFacts { version: None, path: None, dco: false, problem: Some(later.clone()) }, WireGuardFacts { dll_version: None, problem: Some(later.clone()) }))`; Tasks 13 and 14 replace each half with their engine's facts. Check the exact `windows-sys` 0.61 type of `SERVICE_STATUS_HANDLE` (a pointer) and of `RegisterServiceCtrlHandlerExW`'s context parameter before compiling; `ServiceLog` is `Clone` (an `Arc` inside).

`sys/session.rs`:

```rust
/// After a logoff (decision 2 of the 2b plan): every owner SID without an interactive session left loses its
/// connections. Waits 2 s first, so the ending session is gone from the list.
pub fn after_logoff<H: Host>(service: &Service<H>) {
    std::thread::sleep(Duration::from_secs(2));
    let Ok(active) = interactive_sids() else { return }; // unreadable: keep the connections (never drop by mistake)
    for sid in service.owners() {
        if !active.contains(&sid) {
            service.drop_user(&sid);
        }
    }
}

/// The users of the sessions in state active or disconnected (`WTSEnumerateSessionsW` on
/// `WTS_CURRENT_SERVER_HANDLE`, then `WTSQueryUserToken` per session: SYSTEM holds `SeTcbPrivilege`), as SID strings.
fn interactive_sids() -> io::Result<HashSet<String>>
```

(Fail direction: if the sessions cannot be read, nothing is dropped — dropping is the convenience, keeping is not a security problem: the connection still belongs to its owner.)

`sys/service_log.rs`: `ServiceLog::open(path)` appends lines `<RFC 3339 UTC> <text>\n` to `service.log` (created with the data directory's protection), rotates to `service.log.1` above 1 MiB; `ServiceLog::none()` drops lines. Only fixed texts, error kinds, IDs and SIDs are ever logged.

`sys/console.rs` (debug builds only; `#![cfg(debug_assertions)]`):

```rust
//! `mvpn console --pipe \\.\pipe\WinVPN-test-<uuid> --data <dir> [--fake-engine] [--existing-data]
//! [--wireguard-dll <path>]`: the service's server as the current (non-SYSTEM) user, for the tests. The pipe is
//! `Endpoint::ServiceForTests`; the data directory must be new (created private) unless `--existing-data`, which
//! checks an existing one like the service does (a directory with inherited permissions is degraded). Prints
//! `ready` once listening; stops when stdin closes.
pub fn main(args: &[String]) -> i32
```

It refuses to run as LocalSystem (`Sid::current_user() == Sid::local_system()` → exit 2) and accepts only pipe names `\\.\pipe\WinVPN-test-<…>`. `data_dir::open_at(dir, Protection::Private, &[Sid::current_user()])` (create when missing). `--fake-engine`: a `FakeEngine` in this file (up: logs two lines and the masked password, records the ID; state: connected with iface `WinVPN0f1e2d3c` and ip `10.0.0.2`; down: forgets) for both kinds; otherwise `engines(...)`. A thread reads stdin to EOF, then sets the stop flag.

`strings.json` (scope `mvpn`, `"only": ["windows"]`):
- `"The folder %@ has unsafe permissions. An administrator must delete it, then restart the WinVPN Service."` → `"A(z) %@ mappa jogosultságai nem biztonságosak. Egy rendszergazdának törölnie kell, majd újra kell indítania a WinVPN szolgáltatást."`
- `"Too many requests"` → `"Túl sok kérés"`

- [x] **Step 4: Run the tests to verify they pass**

Run: `scripts/check-windows.sh && cargo test --locked -p macvpn-helper && scripts/win-remote.sh run 'cargo test --locked -p macvpn-helper --test service_pipe' && scripts/win-remote.sh test && MVPN_IMPL=rust scripts/test-root.sh`
Expected: PASS (`service_pipe` 4 passed); `service_admin` 2 ignored; macOS root layer unchanged.

- [x] **Step 5: Commit**

```bash
git add crates/helper crates/winsys crates/core/l10n/strings.json scripts/ignored-everywhere.txt
git commit -m "feat(helper): the WinVPN Service host" -m "SCM service 'WinVPN' (own process, STOP/SHUTDOWN/SESSIONCHANGE), a kill-on-close job for its children, C:\\ProgramData\\WinVPN checked or created SYSTEM+Administrators-only (an existing folder of another shape: degraded, never repaired), the pipe server with per-client identity, a 5 s request timeout and 8 requests in flight per SID, logoff drops the user's connections. The debug-only console mode serves the tests over SSH." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**As built (Task 12):** `sys/{mod,host,server,data_dir,session,console,service_log,job}.rs` as planned (`console` is `#[cfg(debug_assertions)] mod console;` in `sys/mod.rs`; `sys::main` takes `service` only without further arguments). Changes and hardenings: **winsys:** `Protection::Admins` (protected, SYSTEM + `BUILTIN\Administrators` `FILE_ALL_ACCESS`, any owner) and, instead of `protection_of`, `file::has_protection(file, protection, dir) -> io::Result<bool>`: it tests the named shape (a DACL owned by Administrators fits both Private and Admins, so "which shape" would be ambiguous) and the ACE flags (exactly `OI|CI` on a directory, none on a file); `info().protection` reports Admins only when neither Private nor Shared fits. `known::program_data()` (`SHGetKnownFolderPath(FOLDERID_ProgramData)`, freed with `CoTaskMemFree`; winsys features `Win32_System_Com`, `Win32_UI_Shell`). `Sid::builtin_administrators` already existed (Task 4). **Win32 names (windows-sys 0.61.2):** `WTS_SESSION_LOGOFF` lives only in `Win32_UI_WindowsAndMessaging`, so `host.rs` defines it (6, winuser.h); `SERVICE_STATUS_HANDLE` is `*mut c_void` (kept in an `AtomicPtr`, not an `AtomicIsize`); `OpenVpnFacts` has `dco`/`wintun`/`tap_windows6: Option<String>` since Task 10 (the plan's `dco: false`). The helper's features are the plan's list without `Win32_UI_Shell` (not used by the helper). **Host:** refuses to run unless the process is LocalSystem (stopped with exit code 1, so `Endpoint::Service` never loops on `PermissionDenied`); reports `SERVICE_RUNNING` (STOP accepted) *before* binding the pipe, so a squatted name (retried every 5 s, logged) never keeps the SCM in START_PENDING; wait hint 30 s; at stop `shutdown()` then `sweep_runs()`. **Degraded:** `real_host(data, log, fake)` builds the host from the data directory's outcome: no safe directory → both engines `Unavailable(reason)` and `NoLogs` (never a `FileLogStore` over an empty path, which would write relative to the working directory); `RealHost::logs` is a `Box<dyn LogStore>`. **Data directory:** opened with `open_metadata` (no `WRITE_DAC`), must be a directory (`FILE_ATTRIBUTE_DIRECTORY`) and no reparse point, owner in the list, `has_protection(…, true)`; a create that loses the race (`AlreadyExists`) is checked like any existing folder; the first failing level stops (nothing is created inside a refused folder). `make_run_dir(id)` (UUID only, a leftover removed first), `write_private(path, bytes)` (only `run\<ID>\<plain name>`, create-new, the protection, no reparse following), `remove_run_dir(id)` and `sweep_runs() -> usize` (UUID-named real directories; std's `remove_dir_all` removes links, never follows them; the rest is left and counted) – the first three are `allow(dead_code)` until Task 13. **Server:** the 5 s is a deadline for the whole request (a `Read` adapter sets each read's timeout to the time left: a client trickling a byte per second is cut at 5 s too, tested); the per-SID slot is an RAII guard (given back on panic). `serve` takes `&AtomicBool` (the host passes its `static STOP`, no watcher thread). Log lines carry error kinds only. **Session:** `user_sids()` asks `WTSQueryUserToken` for every listed session whatever its state (a locked, disconnected or shadowed session keeps its user); `ERROR_NO_TOKEN`, `ERROR_CTX_WINSTATION_NOT_FOUND`, `ERROR_FILE_NOT_FOUND` mean "no user", anything else fails (nothing dropped). `after_logoff` looks after 2, 5 and 10 s (a session that is still ending at the first look is caught later). **Service log:** `ServiceLog::open(PathBuf, Protection)`; lines are cut at 512 bytes, control characters become spaces (no forged lines); an existing `service.log` is written only if it is a plain file with one link and exactly the protection. **Console:** options parsed strictly (unknown option, a repeated one, a pipe name without the `WinVPN-test-` prefix or a relative `--data` → exit 2), refuses LocalSystem, a data directory that exists needs `--existing-data`; `contain_self` failure ignored. **Tests:** `service_pipe.rs` is `#![cfg(all(windows, debug_assertions))]` (the console does not exist in release builds) and has 6 tests (the plan's 4, with the trickling client, the private data directory and `engine`'s problem added, plus a junction at the data directory and the console's argument checks); unit tests in `data_dir` (5), `service_log` (2), `session` (2: only owners without a session are dropped, unreadable sessions drop nothing; a standard user cannot read the sessions' users), winsys `file` (Admins shape) and `tests/winsys.rs` (`has_protection`, `known`). Step 2's separate failing run was not made (the tests were written first; the first Windows run was after the implementation). Windows (standard user): helper + winsys all green, `service_pipe` 6/6, `service_admin` 2 ignored. Needs the maintainer (CP1, elevated): install (`sc create WinVPN binPath= "\"…\WinVPNService.exe\" service" obj= LocalSystem start= auto` or Task 15's MSI), `sc qc WinVPN` / `sc query WinVPN`, `icacls C:\ProgramData\WinVPN`, `cargo test -p macvpn-helper --test service_admin -- --ignored` and `cargo test -p macvpn-winsys --test service_pipe -- --ignored admin_the_installed_service_pipe_is_owned_by_system`, `sc stop WinVPN` (stops within the wait hint), a pre-created `C:\ProgramData\WinVPN` by a standard user → degraded `engine` answer, and logoff (connections of the user who logs off go down; lock and switch user keep them; checked once the engines exist).

## Task 13: the OpenVPN engine

**Goal:** `up openvpn` in the service: OpenVPN's trust checks, the driver choice (DCO or TAP-Windows6; one TAP-Windows6 retry after a DCO incompatibility), the run directory, `openvpn.exe` as SYSTEM, its output masked into the log, the management interface over loopback with password and owner-PID check, the shared bridge in process (MFA: CRV1, static challenge, web auth), the same wait rules as macOS, `down`, `state`, `respond`, `auth-state`.

**Files:**
- Create: `crates/helper/src/windows/bridge_state.rs` (portable), `crates/helper/tests/bridge_state.rs` (every OS)
- Create: `crates/helper/src/windows/sys/{openvpn,detect,mgmt,tcp_owner,adapters}.rs`
- Modify: `crates/helper/src/windows/{mod,sys/mod}.rs` (shared with Task 14: one `mod` line each and the OpenVPN line of `engines()`), `crates/helper/Cargo.toml` (features `Win32_NetworkManagement_IpHelper`, `Win32_NetworkManagement_Ndis`, `Win32_Networking_WinSock`, `Win32_System_Registry`), `crates/core/l10n/strings.json`
- Create: `crates/helper/tests/openvpn_installed.rs` (Windows, ignored: needs OpenVPN Community installed)

- [x] **Step 1: Write the failing portable test** (`crates/helper/tests/bridge_state.rs`)

```rust
//! The management bridge running inside the service: its state in memory instead of files (every OS).

use macvpn_helper::shared::bridge::{Bridge, BridgeArgs};
use macvpn_helper::windows::bridge_state::{BridgeState, InProcessFiles};
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};

/// A management stream: scripted input chunks (`None` = a read timeout), the bridge's writes recorded.
struct Script {
    input: VecDeque<Option<Vec<u8>>>,
    written: Arc<Mutex<Vec<u8>>>,
}

impl Read for Script {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.input.pop_front() {
            Some(Some(chunk)) => {
                buf[..chunk.len()].copy_from_slice(&chunk);
                Ok(chunk.len())
            }
            Some(None) => Err(io::ErrorKind::WouldBlock.into()),
            None => Ok(0),
        }
    }
}

impl Write for Script {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.written.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_crv1_challenge_reaches_the_app_and_the_answer_reaches_openvpn() {
    let state = Arc::new(BridgeState::new(Box::new(|_| {}), Box::new(|| {})));
    let written = Arc::new(Mutex::new(Vec::new()));
    let challenge = b">PASSWORD:Verification Failed: 'Auth' ['CRV1:R,E:Om01u7Fh4LrGBS7uh0SWmzwabUiGiW6l:Ym9i:Enter the code']\n".to_vec();
    let mut input: VecDeque<Option<Vec<u8>>> = VecDeque::from([Some(challenge), None]);
    // The app answers while the bridge polls.
    let answer_state = state.clone();
    input.push_back(None);
    let stream = Script { input, written: written.clone() };
    let args = BridgeArgs::in_process("0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", 420.0).unwrap();
    let mut bridge = Bridge::new(args, stream, InProcessFiles::new(state.clone()), None);
    std::thread::scope(|s| {
        s.spawn(|| {
            // Wait for the challenge to be published, then answer as `respond` does.
            for _ in 0..200 {
                if answer_state.ui().is_some() {
                    answer_state.set_response(b"kind=crv1\nresponse=123456\n");
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
        });
        bridge.run();
    });
    let ui = macvpn_core::mfa::AuthUIState::parse(&state.ui().unwrap_or_default());
    assert!(ui.is_some(), "the state the app reads is a valid AuthUIState");
    let sent = String::from_utf8(written.lock().unwrap().clone()).unwrap();
    assert!(sent.starts_with("state on\n"), "{sent}");
    assert!(sent.contains("CRV1::Om01u7Fh4LrGBS7uh0SWmzwabUiGiW6l::123456"), "{sent}");
}

#[test]
fn the_bridge_status_is_strict() {
    let state = BridgeState::new(Box::new(|_| {}), Box::new(|| {}));
    let mut files = InProcessFiles::new(Arc::new(state));
    use macvpn_helper::shared::bridge::BridgeFiles;
    assert!(files.write_run("mgmt-status", b"wait 1700000000\n"));
    assert_eq!(files.state().mgmt_status().as_deref(), Some("wait 1700000000"));
    assert!(files.write_run("mgmt-status", b"rm -rf\n"));
    assert_eq!(files.state().mgmt_status(), None);
    assert!(!files.write_run("../x", b"ok"), "only the bridge's own names");
}
```

(Before writing the expected CRV1 line, read how `Bridge` answers a CRV1 challenge in `shared/bridge.rs` and `core::management` (the exact `password "Auth" "CRV1::<state>::<response>"` form) and assert on that exact command; the poll timing is driven by the scripted `None`s: add as many as the bridge needs to see the answer.)

Run: `cargo test --locked -p macvpn-helper --test bridge_state` → FAIL to compile.

- [x] **Step 2: Implement `bridge_state.rs`** (portable)

```rust
//! The management bridge's files, in memory: the service runs the shared `Bridge` on a thread of its own, so the
//! user's `AuthUIState` (macOS: `/var/run/macvpn-ui/<id>.json`) is served by `auth-state`, the app's answer
//! (macOS: `<run>/mgmt-resp`) comes from `respond`, and `mgmt-status` is read by the engine's wait loop.

use crate::shared::bridge::{BridgeFiles, valid_status};
use std::sync::{Arc, Mutex, PoisonError};
use zeroize::Zeroizing;

pub struct BridgeState {
    ui: Mutex<Option<Vec<u8>>>,
    status: Mutex<Option<String>>,
    response: Mutex<Option<Zeroizing<Vec<u8>>>>,
    log: Box<dyn Fn(&str) + Send + Sync>,
    stop: Box<dyn Fn() + Send + Sync>,
}

impl BridgeState {
    /// `log`: the connection log's line sink; `stop`: kills this connection's `openvpn.exe`.
    pub fn new(log: Box<dyn Fn(&str) + Send + Sync>, stop: Box<dyn Fn() + Send + Sync>) -> BridgeState {
        BridgeState { ui: Mutex::default(), status: Mutex::default(), response: Mutex::default(), log, stop }
    }
    pub fn ui(&self) -> Option<Vec<u8>> {
        self.ui.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }
    /// The strict `mgmt-status` (`valid_status`), `None` otherwise.
    pub fn mgmt_status(&self) -> Option<String> {
        self.status.lock().unwrap_or_else(PoisonError::into_inner).clone()
    }
    /// `respond`'s body, for the bridge's next poll (a newer answer replaces an unread one).
    pub fn set_response(&self, body: &[u8]) {
        *self.response.lock().unwrap_or_else(PoisonError::into_inner) = Some(Zeroizing::new(body.to_vec()));
    }
}

pub struct InProcessFiles(Arc<BridgeState>);

impl InProcessFiles {
    pub fn new(state: Arc<BridgeState>) -> InProcessFiles {
        InProcessFiles(state)
    }
    pub fn state(&self) -> &BridgeState {
        &self.0
    }
}

impl BridgeFiles for InProcessFiles {
    fn log(&mut self, line: &str) {
        (self.0.log)(line);
    }
    fn run_trusted(&self) -> bool {
        true
    }
    fn ui_trusted(&self) -> bool {
        true
    }
    fn write_ui(&mut self, name: &str, data: &[u8]) -> bool {
        if !name.ends_with(".json") || name.contains(['/', '\\']) || data.len() > 8192 {
            return false;
        }
        *self.0.ui.lock().unwrap_or_else(PoisonError::into_inner) = Some(data.to_vec());
        true
    }
    fn write_run(&mut self, name: &str, data: &[u8]) -> bool {
        if name != "mgmt-status" {
            return false;
        }
        let first = data.split(|&b| b == b'\n').next().unwrap_or_default();
        let parsed = std::str::from_utf8(first).ok().filter(|s| valid_status(s)).map(String::from);
        *self.0.status.lock().unwrap_or_else(PoisonError::into_inner) = parsed;
        true
    }
    fn remove_ui(&mut self, _name: &str) {
        *self.0.ui.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }
    fn take_response(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        self.0.response.lock().unwrap_or_else(PoisonError::into_inner).take()
    }
    fn stop_openvpn(&mut self) {
        (self.0.stop)();
    }
}
```

(Check which names the bridge passes to `write_run` / `write_ui` in `shared/bridge.rs`: if it writes other run files than `mgmt-status`, accept exactly those names.)

Run: `cargo test --locked -p macvpn-helper --test bridge_state` → PASS.

- [x] **Step 3: Write the OpenVPN-installed test** (`crates/helper/tests/openvpn_installed.rs`; ignored everywhere, listed in `scripts/ignored-everywhere.txt`; the maintainer installs OpenVPN Community on the VM at checkpoint CP1, then `scripts/win-remote.sh run 'cargo test --locked -p macvpn-helper --test openvpn_installed -- --ignored'` runs it as the standard user: detection is read-only)

```rust
#![cfg(windows)]

#[test]
#[ignore = "needs OpenVPN Community installed (CP1; CI windows-admin installs it)"]
fn the_installed_openvpn_passes_every_trust_check() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_mvpn")).args(["console-detect"]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let facts: macvpn_core::service_proto::OpenVpnFacts = serde_json::from_str(&text).unwrap();
    assert_eq!(facts.problem, None, "{text}");
    assert!(facts.dco.is_some() && facts.tap_windows6.is_some(), "{text}");
    assert!(facts.version.is_some());
}
```

(`console-detect` is a debug-only subcommand in `sys/mod.rs` that prints `detect::facts()` as JSON. The helper has no `serde_json`: use `EngineFacts`-style parsing from core instead — add `OpenVpnFacts::parse(&[u8])` to core in this task, mirroring `EngineFacts::parse`.)

- [x] **Step 4: Implement the engine** (Windows only; compile-check on the Mac with `scripts/check-windows.sh` after each file)

`sys/detect.rs`:

```rust
//! Whether OpenVPN Community may be run as SYSTEM (the 2b plan's "OpenVPN's trust before every start"): the path
//! from HKLM (64-bit view), admin-only writable, the pinned Authenticode signer, at least the minimum version, the
//! data-channel drivers (DCO, TAP-Windows6) with their versions. Read again before every `up` (an update or a
//! tampering in between counts).

pub struct OpenVpnExe {
    pub path: PathBuf,
    pub version: Version,
}

/// The facts for `engine`, and the executable when every check passed.
pub fn detect() -> (OpenVpnFacts, Option<OpenVpnExe>)
```

Steps inside `detect`, each failing step setting `problem` (localized) and returning without the executable:
1. `RegGetValueW(HKEY_LOCAL_MACHINE, "SOFTWARE\\OpenVPN", "exe_path", RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY, …)` → missing: "OpenVPN Community is not installed."
2. The path must be absolute, a regular file (`file::open_metadata(p, false)`, no reparse point) → otherwise the same "not installed".
3. `version::file_version` → `Version::from_file_version`; below `PINS.min_version` → "OpenVPN Community %@ is too old (%@ or newer is needed)."
4. `acl_check::is_admin_only(path)` → false or error: "openvpn.exe is in a folder other users can change: %@"
5. `trust::verify_signature(path)` → error or `subject != PINS.signer`: "openvpn.exe is not signed by %@."
6. The drivers, each independently (a missing one is not a `problem`: only the connections that need it are refused): for `ovpn-dco` → `dco`, `tap0901` → `tap_windows6` (a `wintun` key is ignored): `RegOpenKeyExW(HKLM, "SYSTEM\\CurrentControlSet\\Services\\<name>")` exists, its `Start` DWORD is not 4 (disabled), and its `ImagePath` names a file below `%SystemRoot%\System32\drivers` (or `System32\DriverStore\FileRepository`) whose `version::file_version` gives the version string; anything unreadable counts as not installed. `detect` also returns `drivers: [bool; 2]` for the engine.

`sys/tcp_owner.rs`:

```rust
/// The PID owning the IPv4 TCP socket in state LISTEN on 127.0.0.1:`port` (`GetExtendedTcpTable(AF_INET,
/// TCP_TABLE_OWNER_PID_LISTENER)`; ports in the table are in network byte order in the low 16 bits). `None`: no
/// such listener, or the table could not be read.
pub fn listener_pid(port: u16) -> Option<u32>
```

`sys/mgmt.rs`:

```rust
//! The management connection over loopback TCP. Only after the listener on the port is shown to belong to the
//! openvpn.exe this run started is the password sent; then the stream goes to the shared bridge with a 250 ms read
//! timeout (the bridge's poll).

/// Connects within `deadline`, checks the listener's owner, logs in with `password` (OpenVPN prompts `ENTER
/// PASSWORD:` and answers `SUCCESS: password is correct`).
pub fn connect(port: u16, openvpn_pid: u32, password: &[u8], deadline: Instant) -> io::Result<TcpStream> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let stream = loop {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(500)) {
            Ok(s) => break s,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(200)),
            Err(e) => return Err(e),
        }
    };
    // The listener we reached must be our child's: a process that bound the port first never gets the password.
    if crate::windows::sys::tcp_owner::listener_pid(port) != Some(openvpn_pid) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "the management port is not openvpn's"));
    }
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut prompt = [0u8; 15];
    (&stream).read_exact(&mut prompt)?;
    if &prompt != b"ENTER PASSWORD:" {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "no management password prompt"));
    }
    let mut line = Zeroizing::new(password.to_vec());
    line.push(b'\n');
    (&stream).write_all(&line)?;
    let mut answer = Vec::new();
    let mut byte = [0u8; 1];
    while answer.len() < 256 && (&stream).read(&mut byte)? == 1 && byte[0] != b'\n' {
        answer.push(byte[0]);
    }
    if !answer.starts_with(b"SUCCESS: password is correct") {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "the management password was refused"));
    }
    stream.set_read_timeout(Some(Duration::from_millis(250)))?;
    Ok(stream)
}
```

(Check OpenVPN 2.6's exact management login texts against its `manage.c` / the management documentation shipped in the pinned MSI's `doc\management-notes.txt` before finalizing the two byte strings; adjust and note in the commit if they differ.)

`sys/adapters.rs`: `first_address(alias_prefix: &str) -> Option<IpAddr>` over `GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER)`: the first unicast IPv4 (else IPv6) address of the adapter whose `FriendlyName` equals the name OpenVPN logged (`ovpn-dco device [<name>] opened`); the name is only compared, never used as a path or command.

`sys/openvpn.rs`, the engine (the macOS `openvpn::up` + `wait_connected` + `down`, in process):

```rust
pub struct OpenVpnEngine {
    data: Arc<DataDir>,
    log: ServiceLog,
    runs: Mutex<HashMap<String, Arc<Run>>>,
}

struct Run {
    child: Mutex<Child>,
    pid: u32,
    bridge: Arc<BridgeState>,
    done: Arc<AtomicBool>,
    auth_failed: Arc<AtomicBool>,
    last_line: Arc<Mutex<Vec<u8>>>,
    adapter: Arc<Mutex<Option<String>>>,
    since: u64,
}

/// The macOS root layer's limits: 30 s to connect, at most 420 s more while waiting for authentication.
pub const UP_TIMEOUT: Duration = Duration::from_secs(30);
pub const MFA_MAX: Duration = Duration::from_secs(420);
```

`up(req)`:
1. `detect()` → no executable: `Err(problem)`. `let driver = ovpn_args::choose_driver(config_text)`; if that driver is not installed: `Err(tr("This connection needs the %@ driver. Repair OpenVPN Community in System Status.", driver.name()))`. TAP-Windows6 uses an adapter OpenVPN's installer created; when all are in use OpenVPN fails with its own message ("All TAP-Windows adapters on this system are currently in use"), which reaches the user as `openvpn exited: …`.
2. An existing run of this ID: `down` it first (macOS' `up` does the same).
3. `data.make_run_dir(id)`; write `config.ovpn` (the validated config), `mgmt.pw` (64 hex digits from `macvpn_winsys::random::fill` of 32 bytes; `Zeroizing`), and `askpass` when `secrets.keypass` is set (`keypass` + `\n`); all with `data.write_private` (SYSTEM + Administrators only, create-new, no reparse following).
4. Pick a port: up to 3 tries of a random port in 49152–65535 that a `TcpListener::bind(127.0.0.1:port)` accepts (then dropped).
5. Start: `Command::new(&exe.path).args(ovpn_args::argv(run, port, driver, req.debug, has_user_pass, has_keypass)).current_dir(run).env_clear().env("SystemRoot", sysroot).env("SystemDrive", …).env("windir", sysroot).env("TEMP", run).env("TMP", run).env("PATH", sysroot\System32).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).creation_flags(CREATE_NO_WINDOW)`; the child inherits the service's kill-on-close job. `sysroot` from `GetSystemWindowsDirectoryW`, never from the environment.
6. Two reader threads (stdout, stderr): `mask::lines` over the bytes, for each line: if `ovpn_log::log_safe(line)` write `masker.line(line)` to `req.log`; set `done` on `ovpn_done`, `auth_failed` on `ovpn_auth_failed`, keep the last non-blank masked line, capture the adapter's name from OpenVPN's "device opened" line for the chosen driver (DCO: `ovpn-dco device [<name>] opened`; TAP: the corresponding line of the pinned version, copied from its source; regex, letters, digits, space, `-`, `_` only), and set `dco_incompatible` on `ovpn_log::dco_incompatible`.
7. `mgmt::connect(port, pid, password, now + 10 s)`; on failure: kill the child, remove the run directory, `Err(tr("The management connection to OpenVPN failed"))`.
8. The bridge thread: `Bridge::new(BridgeArgs::in_process(id, MFA_MAX.as_secs_f64())?, stream, InProcessFiles::new(state.clone()), creds).run()` where `creds` = `ManagementCredentials { username, password, packed }` from `req.secrets` when a user name or password is set (built in `Zeroizing` buffers; the struct is zeroized by the bridge's `Drop`), and `state`'s `stop` kills this run's child.
9. The wait (macOS' `wait_connected`, the same messages): every second until done: `done` → `Ok`; `bridge.mgmt_status()` = `failed` / `cancelled` / `timeout` → the matching message (`Authentication failed`, `Authentication cancelled`, `Timed out waiting for authentication`); `wait <t>` moves the deadline to `max(deadline, t + 15 s)`, at most `UP_TIMEOUT + MFA_MAX` after the start; `auth_failed` → `Authentication failed (AUTH_FAILED)`; the child exited → `openvpn exited: <last masked line>`; the deadline passed → the macOS timeout messages. Every failure kills the child and removes the run directory before returning. **The one retry:** when the driver was DCO, the attempt failed before `done`, and `dco_incompatible` was seen (a server pushed an option DCO cannot run), log `[WinVPN] DCO cannot run this connection (pushed options); retrying with TAP-Windows6` to `req.log` and run steps 3–9 once more with `Driver::TapWindows6` (if TAP-Windows6 is installed; otherwise the "needs the TAP-Windows6 driver" message).

`down(id)`: kill the child (`Child::kill`, then `wait` at most 5 s), join nothing (the reader and bridge threads end with the pipes and the socket), remove the run directory, forget the run. `state(id)`: `connected` when `done` and the child runs (`try_wait` is `Ok(None)`), `connecting` while not done and running, `failed` otherwise; `iface` empty, `ip` = `adapters::first_address(adapter name)` once connected; `since` = the start time. `respond(id, body)`: `bridge.set_response(body)`. `auth_state(id)`: `bridge.ui()`.

In `sys/mod.rs::engines`, replace OpenVPN's `Unavailable` with `Box::new(openvpn::OpenVpnEngine::new(data.clone(), log.clone()))`, and the `facts` closure calls `detect::detect().0`.

`strings.json` (scope `mvpn`, `"only": ["windows"]`): "OpenVPN Community is not installed." → "Az OpenVPN Community nincs telepítve."; "OpenVPN Community %@ is too old (%@ or newer is needed)." → "Az OpenVPN Community %@ túl régi (%@ vagy újabb kell)."; "openvpn.exe is in a folder other users can change: %@" → "Az openvpn.exe olyan mappában van, amelyet más felhasználók is módosíthatnak: %@"; "openvpn.exe is not signed by %@." → "Az openvpn.exe-t nem a(z) %@ írta alá."; "The OpenVPN DCO driver is not installed. Repair or update OpenVPN Community in System Status." → "Az OpenVPN DCO-illesztőprogram nincs telepítve. Javítsd vagy frissítsd az OpenVPN Communityt a Rendszerállapotban."; "The management connection to OpenVPN failed" → "Nem sikerült a kapcsolat az OpenVPN kezelőfelületével".

`strings.json` also: "This connection needs the %@ driver. Repair OpenVPN Community in System Status." → "Ehhez a kapcsolathoz a(z) %@ illesztőprogram kell. Javítsd az OpenVPN Communityt a Rendszerállapotban." (scope `mvpn`, Windows only).

- [x] **Step 5: Run**

Run: `cargo test --locked -p macvpn-helper && scripts/check-windows.sh && scripts/win-remote.sh run 'cargo test --locked -p macvpn-helper --test service_pipe --test bridge_state' && scripts/win-remote.sh test && MVPN_IMPL=rust scripts/test-root.sh`
Expected: PASS. `the_real_engines_fail_cleanly_without_admin_rights` now gets "OpenVPN Community is not installed." for an OpenVPN `up` on a VM without OpenVPN (add that assertion to the test).

- [x] **Step 6: Commit**

```bash
git add crates/helper crates/core scripts/ignored-everywhere.txt
git commit -m "feat(helper): the OpenVPN engine of the WinVPN Service" -m "Before every start: path from HKLM, admin-only folder chain, pinned Authenticode signer, minimum version; the driver (DCO, TAP-Windows6) chosen from the validated config, one TAP-Windows6 retry after a DCO incompatibility. openvpn.exe runs as SYSTEM with a fixed argv and a cleared environment, its output masked into the log; the loopback management port is used only after its listener is shown to be our child's, with a random password; the shared bridge runs in process (MFA via auth-state/respond); the macOS wait rules and messages." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**As built (Task 13):** `windows/{bridge_state,ovpn_run}.rs` (portable) and `windows/sys/{detect,mgmt,tcp_owner,openvpn}.rs`, plus the debug-only `sys/fake_openvpn.rs`; **no `adapters.rs`** (see below). Changes from the plan, each tested: **Address:** OpenVPN 2.7.8 on Windows logs no adapter name at verb 3 (`tun.c`: "DCO device … opened" / "TUN/TAP device … opened" are non-Windows paths), so `status`' `ip` comes from the management stream instead: `bridge_state::StateWatch` passes the stream through to the bridge unchanged and takes the local address of a `>STATE:…,CONNECTED,…` line (field 4, else the IPv6 field 9; only what parses as `IpAddr`; any other state clears it); `iface` stays empty; no `Win32_NetworkManagement_Ndis`. **Owner check:** as "Resolved points" says, not Step 4's listener table: `tcp_owner::peer_pid(stream)` reads `GetExtendedTcpTable(AF_INET, TCP_TABLE_OWNER_PID_ALL)` and takes the ESTABLISHED row whose local end is our peer and whose remote end is our local address (the socket that accepted *this* connection; a second listener bound with `SO_REUSEADDR` cannot pass), refusing none or several owners; the password is sent only when it equals the child's PID. **Connect:** a plain blocking `TcpStream::connect` per try (a refused loopback connect takes ~2 s on Windows; `connect_timeout(500 ms)` abandoned tries whose SYN Windows kept retrying, and OpenVPN — one client at a time — then accepted the orphan: flaky in the fake run, fixed); a try stops early when the child has exited. Login texts checked against 2.7.8 `manage.c` (`ENTER PASSWORD:` without line end, `SUCCESS: password is correct`, `ERROR: bad password`). **Logs:** `UpRequest::log` is now `&Arc<dyn LogSink>` (the service wraps the store's `Box` with `Arc::from`), so OpenVPN keeps writing the connection log after `up` returns; readers stop writing once `down` took the run. Lines are split with `Masker::default().stream_lines` (64 KiB cap) and judged raw by `ovpn_run::Output` (`log_safe`, `ovpn_done`, `ovpn_auth_failed`, `dco_incompatible`, the masked last line; a trailing `\r` dropped — `DONE` is anchored); the sink masks. The bridge logs as `[mgmt] …` (macOS' prefix). **Wait:** `ovpn_run::Wait` is macOS' `wait_connected` (same order and messages, the `wait <t>` + 15 s rule up to 30 + 420 s), looking every 200 ms, plus: a DCO incompatibility ends a DCO attempt at once (OpenVPN 2.7 restarts after "OPTIONS ERROR: pushed options are incompatible…" instead of exiting), then the one TAP-Windows6 retry; an exit counts after the readers drained the output (≤ 1 s); `openvpn.exe` ending before its management interface answers is "openvpn exited: <last line>" (as macOS), not the management message. **Stop:** `signal SIGTERM` over a second handle of the management socket (OpenVPN takes its routes and DNS back), up to 5 s, then `TerminateProcess` (`Child::kill`) and 5 s more; a `down` whose process does not end answers "openvpn.exe did not stop" and keeps the run. **Detection:** `RegGetValueW` alone (no `RegOpenKeyExW`); driver `ImagePath` read unexpanded (`RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND`) and accepted only as a plain `.sys` path below `<windows>\System32\drivers\` or `…\DriverStore\FileRepository\` (`\SystemRoot\`, `%SystemRoot%\`, `System32\`, `\??\X:\`, `X:\` forms), the Windows folder from `GetSystemWindowsDirectoryW` (`Win32_System_SystemInformation`, new feature); driver versions are four-part (`2.8.13.0`); the facts carry the driver versions even when `openvpn.exe` fails. `openvpn.exe` must be a plain absolute path to a regular file (no reparse point) before its version, admin-only chain and signer are read. Features added: `Win32_NetworkManagement_IpHelper`, `Win32_Networking_WinSock`, `Win32_System_Registry`, `Win32_System_SystemInformation`. **Strings:** the plan's except the unused "The OpenVPN DCO driver is not installed…" (the "needs the %@ driver" text covers it), plus "openvpn.exe could not be started" and "openvpn.exe did not stop". **Tests:** `bridge_state` 5 (deterministic: a scripted step calls `set_response` instead of the sketch's racing thread; CRV1, cancel, stored credentials, strict files, `StateWatch`), `ovpn_run` 3 unit tests, core `openvpn_facts_round_trip_as_json` (`OpenVpnFacts::{to_json, parse}`; `{}` parses — every field is optional — so the test refuses `[]`). Windows unit tests: `detect` 4 (driver paths; the Windows folder; `curl.exe` refused for its signer, a copy in a user folder refused for its folder; the machine without OpenVPN → "OpenVPN Community is not installed."), `mgmt` 2 (the password reaches only the expected PID: a "squatter" gets zero bytes; an unknown owner and a refused password fail), `tcp_owner` 2, `openvpn` 2 (random hex password, port range). **End to end as a standard user** (`tests/openvpn_fake.rs`, 5): `mvpn console --fake-openvpn` runs the real engine with `mvpn.exe` itself as `openvpn.exe` (debug builds only: `sys::main` sends an argv starting with `--config` to `fake_openvpn`, which speaks the management protocol with the password from `mgmt.pw`; scenario from a `# winvpn-fake:` comment of the config): the private run files and their removal at `down`, the child's environment exactly `PATH,SystemDrive,SystemRoot,TEMP,TMP,windir`, the stored password masked in the log and the management password never in it, `status` connected with `10.8.0.2`, CRV1 through `auth-state`/`respond`, a wrong code and a cancel, AUTH_FAILED, an early exit, the DCO→TAP-Windows6 retry and a `dev tap` config on TAP-Windows6 at once, a `down` while connecting. `service_pipe::the_real_engines_fail_cleanly_without_admin_rights` asserts "OpenVPN Community is not installed." on a machine without it. `openvpn_installed.rs` is `cfg(all(windows, debug_assertions))` (`console-detect` is debug-only). **Needs the maintainer (CP1, OpenVPN 2.7.8 installed with DCO and TAP-Windows6):** `cargo test --locked -p macvpn-helper --test openvpn_installed -- --ignored`; through the installed service: a DCO connection (status `connected` with the tunnel address, the log masked), a TAP-Windows6 connection (e.g. `cipher AES-256-CBC` / `dev tap`), a server that pushes compression (the logged retry), user name and password, a static challenge, CRV1, web sign-in (`auth-state` URL, `webauth-ack`), cancel, `down` (routes and DNS restored after `signal SIGTERM`), `sc stop WinVPN` with a connection up (nothing left running), logoff takes the user's connections down (lock and switch user keep them), `engine` facts (path, version, DCO and TAP-Windows6 versions), and a squatted management port cannot be tested by hand (the unit test covers it).

## Task 14: the WireGuard engine (wireguard-nt)

**Goal:** `up wireguard` in the service: the bundled `wireguard.dll`, hash-checked and loaded only from the install directory, one adapter per connection with its addresses, routes, DNS, metric and MTU; `down` deletes the adapter.

**Files:**
- Create: `scripts/pins/wireguard-nt.txt`, `scripts/fetch-wireguard-nt.sh`, `scripts/wg-nt-layout.c`
- Create: `crates/helper/src/windows/wg_pins.rs` (portable), `crates/helper/src/windows/sys/{wireguard,wgdll,iphlp}.rs`, `crates/helper/tests/wireguard_admin.rs` (Windows, admin, ignored)
- Modify: `crates/helper/src/windows/{mod,sys/mod}.rs` (shared with Task 13), `crates/helper/Cargo.toml` (features `Win32_NetworkManagement_IpHelper`, `Win32_NetworkManagement_Ndis`, `Win32_Networking_WinSock`, `Win32_System_LibraryLoader`), `.gitignore` (`/target` already covers `target/wireguard-nt`)

- [x] **Step 1: Pin wireguard-nt and check the struct layout**

On the Mac, into a new empty directory: `curl -fsSLO https://download.wireguard.com/wireguard-nt/wireguard-nt-0.10.1.zip`, `shasum -a 256 wireguard-nt-0.10.1.zip`, `unzip -q wireguard-nt-0.10.1.zip`, `shasum -a 256 wireguard-nt/bin/amd64/wireguard.dll wireguard-nt/bin/arm64/wireguard.dll`. Compare the zip's hash with the one the official WireGuard for Windows build pins for the same version (`wireguard-windows`' `embeddable-dll-service` / `build.bat` lists the `wireguard-nt` zip hash) and record both the source and the hashes:

```text
# wireguard-nt, the prebuilt signed DLL WinVPN bundles (2b plan, Task 14). key<TAB>value.
version	0.10.1
zip_url	https://download.wireguard.com/wireguard-nt/wireguard-nt-0.10.1.zip
zip_sha256	<64 hex>
dll_amd64_sha256	<64 hex>
dll_arm64_sha256	<64 hex>
signer	WireGuard LLC
```

`scripts/wg-nt-layout.c` prints `sizeof` and `offsetof` of `WIREGUARD_INTERFACE`, `WIREGUARD_PEER` (every field), `WIREGUARD_ALLOWED_IP` from the zip's `include/wireguard.h`. Run it on the Windows machine with MSVC: `scripts/win-remote.sh run 'scripts/fetch-wireguard-nt.sh && cmd //c "\"C:\\Program Files\\Microsoft Visual Studio\\18\\BuildTools\\VC\\Auxiliary\\Build\\vcvars64.bat\" && cl /nologo /I target\\wireguard-nt\\include scripts\\wg-nt-layout.c /Fe:target\\wg-nt-layout.exe" && target/wg-nt-layout.exe'` (find the exact `vcvars64.bat` path with `ls "/c/Program Files/Microsoft Visual Studio"` first). Expected: 80 / 136 / 24 and the offsets Task 9 uses; any difference is fixed in `wg_nt.rs` and its test now, in this task.

`scripts/fetch-wireguard-nt.sh` (bash, runs on Windows and in CI; used by `build-msi.sh` and the tests): downloads the zip into `target/wireguard-nt.zip` unless present, refuses any SHA-256 but the pin, unzips into `target/wireguard-nt/`, refuses DLLs whose SHA-256 differ from the pins, and on Windows checks each DLL's Authenticode signer (`powershell -NoProfile -Command "(Get-AuthenticodeSignature '<dll>').Status, (Get-AuthenticodeSignature '<dll>').SignerCertificate.GetNameInfo('SimpleName', $false)"` → `Valid` and the pinned signer). Exit 1 with the reason on any mismatch.

- [x] **Step 2: The failing admin test** (`crates/helper/tests/wireguard_admin.rs`, ignored everywhere, in `scripts/ignored-everywhere.txt`)

```rust
//! An adapter up and down through the console service, with real wireguard-nt (an administrator, not SYSTEM: the
//! console refuses SYSTEM). CI's windows-admin job and the maintainer (elevated Git Bash) run it.
#![cfg(windows)]

mod common;

use common::console::Console;

const ID: &str = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F0";
const IFACE: &str = "WinVPN0f1e2d3c";
const CONF: &str = "[Interface]\nPrivateKey = bWFjdnBuLXRlc3QtcHJpdmF0ZS1rZXktMzJieXRlcyE=\nAddress = 10.199.0.2/32\nDNS = 10.199.0.1\n\n[Peer]\nPublicKey = bWFjdnBuLXRlc3QtcHVibGljLS1rZXktMzJieXRlcyE=\nAllowedIPs = 10.199.0.0/24\nEndpoint = 127.0.0.1:51820\n";

fn netsh(args: &[&str]) -> (bool, String) {
    let out = std::process::Command::new(r"C:\Windows\System32\netsh.exe").args(args).output().unwrap();
    (out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
#[ignore = "admin: creates a WireGuard adapter"]
fn admin_a_wireguard_adapter_comes_up_with_its_address_and_goes_away() {
    let dll = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/wireguard-nt/bin/amd64/wireguard.dll");
    let c = Console::start_with(&["--wireguard-dll", dll.to_str().unwrap()]);
    let r = c.call(&["up", "wireguard", ID, "--lang", "en"], &common::console::framed(CONF));
    assert_eq!(r.code, 0, "{}", String::from_utf8_lossy(&r.stderr));
    let st = String::from_utf8(c.call(&["status"], b"").stdout).unwrap();
    assert!(st.contains(IFACE) && st.contains("10.199.0.2") && st.contains("\"connected\""), "{st}");
    let name = format!("name={IFACE}");
    assert!(netsh(&["interface", "ipv4", "show", "addresses", &name]).1.contains("10.199.0.2"));
    assert!(netsh(&["interface", "ipv4", "show", "dnsservers", &name]).1.contains("10.199.0.1"));
    let routes = std::process::Command::new(r"C:\Windows\System32\route.exe").args(["print", "-4", "10.199.0.0"]).output().unwrap();
    assert!(String::from_utf8_lossy(&routes.stdout).contains("10.199.0.0"));
    assert_eq!(c.call(&["down", "wireguard", ID], b"").code, 0);
    assert!(!netsh(&["interface", "show", "interface", &name]).0, "the adapter is gone");
}
```

Move the `Console` helper of `service_pipe.rs` into `crates/helper/tests/common/console.rs` (with `start(fake)`, `start_with(extra_args)`, `call`, `framed`), used by both files. It fails now: `up wireguard` answers "Not available on this system yet".

- [x] **Step 3: Implement**

`wg_pins.rs`: the same parser pattern as `ovpn_pins.rs` over `include_str!("../../../../scripts/pins/wireguard-nt.txt")`, with `pub fn dll_sha256(arch: &str) -> Option<&'static str>` (`x86_64` → amd64, `aarch64` → arm64).

`sys/wgdll.rs`:

```rust
//! wireguard.dll (wireguard-nt 0.10.1): loaded once, from the service's own folder only, after its SHA-256 matched
//! the pin compiled into the service. The function pointers' types follow wireguard.h.

pub type AdapterHandle = *mut core::ffi::c_void;
type CreateAdapter = unsafe extern "system" fn(name: *const u16, tunnel_type: *const u16, guid: *const GUID) -> AdapterHandle;
type CloseAdapter = unsafe extern "system" fn(adapter: AdapterHandle);
type GetAdapterLuid = unsafe extern "system" fn(adapter: AdapterHandle, luid: *mut NET_LUID_LH);
type GetRunningDriverVersion = unsafe extern "system" fn() -> u32;
type SetConfiguration = unsafe extern "system" fn(adapter: AdapterHandle, config: *const u8, bytes: u32) -> BOOL;
type SetAdapterState = unsafe extern "system" fn(adapter: AdapterHandle, state: i32) -> BOOL;
type SetLogger = unsafe extern "system" fn(cb: Option<unsafe extern "system" fn(level: i32, timestamp: u64, message: *const u16)>);

pub struct WgDll {
    _lib: Library,
    pub create: CreateAdapter,
    pub close: CloseAdapter,
    pub luid: GetAdapterLuid,
    pub driver_version: GetRunningDriverVersion,
    pub set_config: SetConfiguration,
    pub set_state: SetAdapterState,
    pub set_logger: SetLogger,
}

/// `path`: `<folder of the service's exe>\wireguard.dll` (or the console's `--wireguard-dll`).
pub fn load(path: &Path) -> Result<WgDll, String>
```

`load`: read the file (at most 4 MiB) and compare `sha256_hex` with `wg_pins::dll_sha256(std::env::consts::ARCH)` → mismatch: `tr("wireguard.dll does not match its pinned version. Repair WinVPN.")`; `Library::load(path)`; resolve `WireGuardCreateAdapter`, `WireGuardCloseAdapter`, `WireGuardGetAdapterLUID`, `WireGuardGetRunningDriverVersion`, `WireGuardSetConfiguration`, `WireGuardSetAdapterState`, `WireGuardSetLogger` (`std::mem::transmute` of each non-null pointer to its type, each with a `// SAFETY:` naming the header's prototype). The hash check and the load open the file separately: the install folder is admin-only (checked with `acl_check::is_admin_only` before both; the console's test path skips that check).

`sys/iphlp.rs` (each function returns the Win32 error as `io::Error`):
- `add_address(luid, prefix)`: `InitializeUnicastIpAddressEntry`, `InterfaceLuid`, `Address` (`SOCKADDR_INET`), `OnLinkPrefixLength`, `DadState = IpDadStatePreferred`, `CreateUnicastIpAddressEntry`.
- `add_route(luid, prefix)`: `InitializeIpForwardEntry`, `InterfaceLuid`, `DestinationPrefix`, `NextHop` = the unspecified address of the family (on-link), `Metric = 0`, `CreateIpForwardEntry2`.
- `set_interface(luid, family, metric, mtu: Option<u32>)`: `InitializeIpInterfaceEntry` + `GetIpInterfaceEntry`, `UseAutomaticMetric = false`, `Metric = metric`, `NlMtu` when given, `SitePrefixLength = 0` (IPv4 requirement), `SetIpInterfaceEntry`.
- `set_dns(guid, servers, search)`: `SetInterfaceDnsSettings(guid, &DNS_INTERFACE_SETTINGS { Version: DNS_INTERFACE_SETTINGS_VERSION1, Flags: DNS_SETTING_NAMESERVER | DNS_SETTING_SEARCHLIST, NameServer: "a,b", SearchList: "x,y", .. })` for the IPv4 servers, and once more with `DNS_SETTING_IPV6` for the IPv6 ones (the strings are UTF-16, comma-separated, built only from parsed `IpAddr`s and validated domain names).

`sys/wireguard.rs`: `WireGuardEngine { dll: Result<WgDll, String>, runs: Mutex<HashMap<String, Run>>, log }`, `Run { adapter: AdapterHandle (Send wrapper), name: String, since: u64, address: Option<IpAddr> }`. `up(req)`:
1. `dll` is `Err(reason)` → `Err(reason)`.
2. `wg_plan::parse(config)` → `Err(message)`.
3. Resolve every `Endpoint::Host` (`(host, port).to_socket_addrs()` on a helper thread, at most 10 s; the first address); failure → `tr("Cannot resolve %@", host)`.
4. An existing run of this ID: `down` it first.
5. `create(name = "WinVPN<8 hex>", tunnel type "WinVPN", guid = the connection's UUID bytes as a GUID)`; null → `tr("Cannot create the WireGuard adapter (%@)", last error)`.
6. `set_config(adapter, wg_nt::encode(&plan, &resolved))`; `luid`; for each address `add_address`; for each `plan.routes()` `add_route`; `set_interface` for IPv4 and IPv6 with metric 5 and the MTU; `set_dns` when `plan.dns_servers` is not empty; `set_state(UP)`. Any failure: `close(adapter)` (which deletes the adapter and with it the addresses, routes and DNS) and `Err(message with the step's name)`.
7. Log each step to `req.log` (`adapter WinVPN0f1e2d3c created`, `addresses set`, `routes set (2)`, `DNS set`, `up`): never a key.

`down(id)`: `set_state(DOWN)`, `close(adapter)`. `state(id)`: `connected` with `iface` = the name (letters and digits), `ip` = the first address, `since`. The logger (`set_logger` once at load) writes wireguard-nt's messages (they never carry keys) to the service log with the level.

`sys/mod.rs::engines`: `Box::new(wireguard::WireGuardEngine::new(dll_path, log.clone()))` with `dll_path` = `std::env::current_exe()?.with_file_name("wireguard.dll")` (the console: `--wireguard-dll`); the `facts` closure reports `dll_version` from `driver_version()` (formatted `major.minor` from the DWORD: high word, low word) or the load error as `problem`.

`strings.json` (scope `mvpn`, `"only": ["windows"]`): "wireguard.dll does not match its pinned version. Repair WinVPN." → "A wireguard.dll nem egyezik a rögzített verzióval. Javítsd a WinVPN-t."; "Cannot resolve %@" → "Nem oldható fel: %@"; "Cannot create the WireGuard adapter (%@)" → "Nem hozható létre a WireGuard-adapter (%@)".

- [x] **Step 4: Run**

Run: `scripts/check-windows.sh && cargo test --locked -p macvpn-helper && scripts/win-remote.sh run 'scripts/fetch-wireguard-nt.sh && cargo test --locked -p macvpn-helper --test service_pipe' && scripts/win-remote.sh test`
Expected: PASS; as the standard user, `up wireguard` in the console now fails at the adapter step ("Cannot create the WireGuard adapter (…)": creating an adapter needs administrator rights) — extend `the_real_engines_fail_cleanly_without_admin_rights` to pass `--wireguard-dll target/wireguard-nt/bin/amd64/wireguard.dll` and assert that message. The admin test is run by the maintainer at CP1 and by CI (Task 21).

- [x] **Step 5: Commit**

```bash
git add scripts/pins/wireguard-nt.txt scripts/fetch-wireguard-nt.sh scripts/wg-nt-layout.c crates/helper crates/core/l10n/strings.json scripts/ignored-everywhere.txt
git commit -m "feat(helper): the WireGuard engine over wireguard-nt" -m "wireguard-nt 0.10.1 pinned (zip and both DLLs by SHA-256, signer WireGuard LLC), the struct layout checked against wireguard.h with MSVC (80/136/24). The DLL is loaded only by absolute path from the service's folder after its hash matched; one adapter per connection with addresses, routes, metric 5, MTU and DNS through IP Helper; closing the adapter removes everything." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**As built (Task 14):** **Pin** (`scripts/pins/wireguard-nt.txt`, recorded 2026-10-22 from https://download.wireguard.com/wireguard-nt/; decision 6: **1.1**, first committed as 0.10.1 and re-pinned the same day): 1.1, zip `dceb30a9bc4be48cce0f74160fc88a585a2c2627366e8f846fc6658f9038dace` (downloaded twice, equal to the pin of the official WireGuard for Windows `build.bat`, wireguard-windows commit 305e40248e54 "build: bump wireguard-nt to 1.1", 2026-05-07), `bin/amd64/wireguard.dll` `b1b85e072c45d81358be29d94c599dc76652f912be8c0f0a41e2d5d89a6461d3`, `bin/arm64/wireguard.dll` `75bcdc025d6c00e8315af5d62b869d760ca6a253fc82d70f146e789f059a3e0c`, both Authenticode `Valid`, signer "WireGuard LLC" (checked by `fetch-wireguard-nt.sh` on the VM); file version 1.1.0 (`engine` reports `1.1.0`). (0.10.1's values, for the record: zip `772c0b14…41b81605`, amd64 `d2ad6ce2…4d0e9cbb`, arm64 `19126ecd…cbb8ca57f42`.) 1.1's header against 0.10.1's: `WIREGUARD_ALLOWED_IP.Flags` (offset 20, former padding; `wg_nt` writes `ALLOWED_IP_ADD` = 0, test `allowed_ips_are_added_never_removed`), `WIREGUARD_PEER_UPDATE` → `WIREGUARD_PEER_UPDATE_ONLY` (`wg_nt::PEER_UPDATE_ONLY`, never set), prototypes unchanged. **Layout:** `scripts/wg-nt-layout.c` compiled with MSVC 18 (`vcvars64.bat`, `/W4`, no warning) on the VM, against 0.10.1's and again against 1.1's `wireguard.h`: `WIREGUARD_INTERFACE` 80 (Flags 0, ListenPort 4, PrivateKey 6, PublicKey 38, PeersCount 72), `WIREGUARD_PEER` 136 (Flags 0, Reserved 4, PublicKey 8, PresharedKey 40, PersistentKeepalive 72, Endpoint 76, TxBytes 104, RxBytes 112, LastHandshake 120, AllowedIPsCount 128), `WIREGUARD_ALLOWED_IP` 24 (Address 0, AddressFamily 16, Cidr 18, and in 1.1 Flags 20), `SOCKADDR_INET` 28: Task 9's offsets; `wg_nt.rs` only gained the 1.1 `Flags` (0). x64 only: the VM's Visual Studio has no ARM64 compiler (`vcvarsamd64_arm64.bat` missing). **`fetch-wireguard-nt.sh`** reuses `target/wireguard-nt.zip` only when its hash is the pin, unzips with `unzip` (Git Bash has it; `Expand-Archive` otherwise), leaves nothing in `target/wireguard-nt/` on any mismatch. **Changes from the listing** (security, each tested): the adapter name and GUID are **not** the ID's first 8 hex digits / bytes but come from SHA-256 of a fixed label and the canonical ID (`wg_nt::adapter_name` = `WinVPN` + 8 hex, `wg_nt::adapter_guid` with version-4/variant bits): deterministic, but a caller cannot request the GUID of an existing adapter or pick a name; the admin test asks `adapter_name(ID)` for its interface name; two connections whose names collide are refused (`ERROR_ALREADY_EXISTS`). DNS goes to the GUID `ConvertInterfaceLuidToGuid` gives for the adapter's own LUID, never to the requested GUID. `up` asks for an elevated token (or LocalSystem) **before** `WireGuardCreateAdapter`, so a standard user's console never makes wireguard-nt try to install its driver; the answer is still "Cannot create the WireGuard adapter (Access is denied. (os error 5))". `wgdll::load` holds the file open with share mode `FILE_SHARE_READ` and `FILE_FLAG_OPEN_REPARSE_POINT` from before the hash until `LoadLibraryExW` mapped it (the bytes hashed are the bytes loaded; a file open for writing elsewhere is refused), refuses a reparse point, a non-file and more than 4 MiB; every refusal is one localized message ("wireguard.dll does not match its pinned version. Repair WinVPN.") with the detail in the service log. The DLL is loaded once per process (`OnceLock`), shared by the engine and `engine`'s facts; the console's `--wireguard-dll <absolute path>` (debug only) replaces the path and skips only the admin-only check. The adapter is an RAII `Adapter` (close on drop): every failure after creation, `down` and the run's removal delete it. A failed step is "Cannot configure the WireGuard adapter: %@ (%@)" (new string, the step's name and the Win32 error) and is logged to the connection log. **Win32 fixes:** `BOOL` and `GUID` are `windows_sys::core::{BOOL, GUID}` in 0.61.2; `WireGuardSetConfiguration` takes a `const WIREGUARD_INTERFACE*` (`ALIGNED(8)`): the `Vec<u8>` block is copied into a zeroized `Vec<u64>` first; `DNS_INTERFACE_SETTINGS.Flags` is `u64` (the `DNS_SETTING_*` constants `u32`), `NameServer`/`SearchList` are `PWSTR`, `SetInterfaceDnsSettings` takes the `GUID` by value; `set_interface` runs only for a family the adapter has an address of (no IPv6 row is needed otherwise); the search list goes with the first family's DNS call, and nothing is set without a server (`wg_nt::dns_lists`). `WireGuardGetRunningDriverVersion` answers 0 until an adapter exists (the driver is not loaded before), so `engine`'s `dll_version` is the verified DLL's file version (`winsys::version::file_version`, `0.10.1`; `wg_nt::version_string`) and that export is not resolved; `WireGuardSetLogger` is set once at load (messages capped at 512 UTF-16 units, into the service log with their level). Features: the plan's list without `Win32_System_LibraryLoader` (the helper loads through `winsys::dll`). **Tests:** `wg_windows.rs` +5 (pins parse strictly, allowed IPs added never removed, adapter identity, DNS lists, versions); `wgdll` unit tests (3: the pinned DLL loads and reports 1.1.0; the pinned bytes outside an admin-only folder are refused for the service, one appended byte or System32's `version.dll` are refused by hash and stay unmapped, a file open for writing is refused; a loaded copy cannot be opened for writing); `service_pipe.rs` +1 (`a_wireguard_dll_that_is_not_the_pinned_one_is_never_loaded`) and `the_real_engines_fail_cleanly_without_admin_rights` extended (no DLL → "Repair WinVPN" in `up` and `engine`; the pinned DLL → `engine` reports 1.1.0, `up` fails with "Cannot create the WireGuard adapter (", nothing in `status`, the log names the step and no key); the `Console` helper moved to `tests/common/console.rs` (`start`, `start_with`, `call`, `framed`, `spawn`, `test_pipe`, `wireguard_dll`). Tests that load the DLL need `scripts/fetch-wireguard-nt.sh` first (they say so when it is missing): **Task 21's windows job must run it before `cargo test`.** Windows (standard user, after `fetch-wireguard-nt.sh`): with 0.10.1 the full `win-remote.sh test` set passed (one unrelated `app-core` `control_server` timing flake that passed in 3 of 3 reruns), and again after merging Task 13 (1703 passed, 0 failed); after the 1.1 re-pin the helper and winsys test binaries 197 passed, 0 failed (by the maintainer's rule only the touched crates; the wave merge runs the full gate); Windows clippy `-D warnings` and the ARM64 check clean. **Needs the maintainer (CP1, elevated):** `scripts/fetch-wireguard-nt.sh && cargo test -p macvpn-helper --test wireguard_admin -- --ignored` (an adapter up with address, DNS and route, gone after `down`); with the MSI (Task 15) a real full-tunnel WireGuard connection (`AllowedIPs = 0.0.0.0/0, ::/0`): traffic through the tunnel, the endpoint's own UDP not looping, `Get-DnsClientServerAddress` shows the tunnel's DNS on `WinVPN<8 hex>` only, `Get-NetIPInterface` metric 5 and the MTU, `route print` shows the routes on the adapter only, and a DNS leak check (no kill switch: Windows may still ask other interfaces' servers); a host-name endpoint; `down` removes the adapter (`Get-NetAdapter` no longer lists it) and its routes/DNS; logoff takes the user's WireGuard connections down while lock/switch user keep them; `sc stop WinVPN` removes the adapters; the installed DLL's folder passes the admin-only check (`engine` reports `dllVersion` 1.1.0); ARM64 not tested (no hardware).

## Task 15: the MSI with the service

**Goal:** both MSIs install `WinVPNService.exe` and `wireguard.dll` next to `WinVPN.exe`, register and start the `WinVPN` service (LocalSystem, automatic, restart on failure), stop it on upgrade and uninstall and remove it on uninstall; `build-msi.sh` gates the service binary and the DLL like the app.

**Files:**
- Create: `app/src-tauri/wix/service.wxs.in`, `scripts/notices/wireguard-nt-LICENSE.txt`
- Modify: `scripts/build-msi.sh`, `scripts/test-build-msi.sh`, `scripts/bundle-baseline/winvpn-msi-files.txt`, `scripts/third-party-notices.mjs` (`--os windows` appends the wireguard-nt license), `THIRD-PARTY-NOTICES.windows.txt` (regenerated), `.gitignore` (`/target` covers the generated fragment)

- [x] **Step 1: The fragment template** (`app/src-tauri/wix/service.wxs.in`; `@SERVICE_EXE@` and `@WIREGUARD_DLL@` are replaced by `build-msi.sh` with absolute Windows paths; the GUIDs are fixed once, generate them with `uuidgen` when writing the file and never change them)

```xml
<?xml version="1.0" encoding="utf-8"?>
<!-- The WinVPN Service (2b plan, Task 15). Generated per architecture into target/winvpn-wix/<arch>/service.wxs by
     scripts/build-msi.sh. Core WiX only (no util extension). -->
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Fragment>
    <DirectoryRef Id="INSTALLDIR">
      <Component Id="WinVPNServiceExe" Guid="{GENERATE-ONCE-1}">
        <File Id="WinVPNServiceExe" Name="WinVPNService.exe" Source="@SERVICE_EXE@" KeyPath="yes" />
        <ServiceInstall Id="WinVPNServiceInstall" Name="WinVPN" DisplayName="WinVPN Service"
                        Description="Connects WinVPN's OpenVPN and WireGuard connections."
                        Type="ownProcess" Start="auto" Account="LocalSystem" ErrorControl="normal"
                        Arguments="service" Vital="yes">
          <ServiceConfigFailureActions OnInstall="yes" OnReinstall="yes" ResetPeriod="86400">
            <Failure Action="restartService" Delay="5000" />
            <Failure Action="restartService" Delay="30000" />
            <Failure Action="none" Delay="0" />
          </ServiceConfigFailureActions>
        </ServiceInstall>
        <ServiceControl Id="WinVPNServiceControl" Name="WinVPN" Start="install" Stop="both" Remove="uninstall" Wait="yes" />
      </Component>
      <Component Id="WireGuardDll" Guid="{GENERATE-ONCE-2}">
        <File Id="WireGuardDll" Name="wireguard.dll" Source="@WIREGUARD_DLL@" KeyPath="yes" />
      </Component>
    </DirectoryRef>
    <ComponentGroup Id="WinVPNServiceComponents">
      <ComponentRef Id="WinVPNServiceExe" />
      <ComponentRef Id="WireGuardDll" />
    </ComponentGroup>
  </Fragment>
</Wix>
```

Replace `{GENERATE-ONCE-n}` with real GUIDs (upper case, braces) in this step. Check the install directory's `Id` in Tauri 2.12's `main.wxs` template (the one the 2a build uses: `INSTALLDIR`); if it differs, use Tauri's.

`C:\ProgramData\WinVPN` is not touched by the MSI: Windows Installer, running as SYSTEM, would follow a junction a user planted there and delete elsewhere. The service removes its run directories at every stop; the masked logs stay, and the guide says how an administrator deletes the folder (resolved points).

- [x] **Step 2: The build** (in `scripts/build-msi.sh`, per architecture, before `tauri build`)

```bash
  step "the WinVPN Service ($arch)"
  cargo build --release --locked -p macvpn-helper --target "$triple"
  SERVICE_EXE="target/$triple/release/mvpn.exe"
  scripts/fetch-wireguard-nt.sh || die "wireguard-nt does not match its pins"
  WG_DLL="target/wireguard-nt/bin/$([ "$arch" = x64 ] && echo amd64 || echo arm64)/wireguard.dll"
  FRAG_DIR="target/winvpn-wix/$arch"
  mkdir -p "$FRAG_DIR"
  sed -e "s|@SERVICE_EXE@|$(cygpath -w "$PWD/$SERVICE_EXE" | sed 's/\\/\\\\/g')|" \
      -e "s|@WIREGUARD_DLL@|$(cygpath -w "$PWD/$WG_DLL" | sed 's/\\/\\\\/g')|" \
      app/src-tauri/wix/service.wxs.in > "$FRAG_DIR/service.wxs"
  grep -q '@' "$FRAG_DIR/service.wxs" && die "service.wxs: a placeholder is left"
  WIX_CONFIG=$(printf '{"bundle":{"windows":{"wix":{"fragmentPaths":["wix/file-associations.wxs","%s"],"componentRefs":["WinVPNConfOpenWith"],"componentGroupRefs":["WinVPNServiceComponents"]}}}}' \
    "$(cygpath -w "$PWD/$FRAG_DIR/service.wxs" | sed 's/\\/\\\\/g')")
```

and pass `--config "$WIX_CONFIG"` to the existing `tauri build` call (next to the other `--config`s; JSON merge patch replaces arrays whole, so both fragment paths and the existing `componentRefs` are repeated here). Run the gates of Step 3 on the service exe and the DLL **before** `tauri build` (the built files) and again on the files unpacked from the MSI (what ships), as 2a does for `WinVPN.exe`.

- [x] **Step 3: The gates** (add to `build-msi.sh`, each with `step` and `die` like the existing ones)

1. The service exe: PE machine per architecture (`scripts/pe-imports.mjs --machine`), PE subsystem 3 (console: a service has no window), no `MACVPN_SANDBOX_HOME`, `MACVPN_SMOKE`, `--fake-engine`, `console-detect` strings (the debug-only console is not in a release build), no SQLite (`SQLite format 3` absent) and no crypto or SQLite DLL among its imports (`pe-imports.mjs`), and it imports no DLL outside the allow-list `KERNEL32.dll ADVAPI32.dll WS2_32.dll IPHLPAPI.DLL SHELL32.dll ole32.dll WTSAPI32.dll WINTRUST.dll CRYPT32.dll VERSION.dll bcrypt.dll ntdll.dll USERENV.dll api-ms-win-*` (print the list once with `pe-imports.mjs` and pin exactly what it shows; a new import later is a review question, not a silent change).
2. `wireguard.dll`: SHA-256 equals `dll_<arch>_sha256` of `scripts/pins/wireguard-nt.txt`; `Get-AuthenticodeSignature` `Valid` with the pinned signer.
3. The MSI's tables (`scripts/msi-query.ps1`): `SELECT Name, ServiceType, StartType, ErrorControl, StartName, Arguments FROM ServiceInstall` → exactly `WinVPN 16 2 1 LocalSystem service`; `SELECT Name, Event FROM ServiceControl` → `WinVPN 163` (start on install 1 + stop on install 2 + stop on uninstall 32 + delete on uninstall 128); `SELECT FileName FROM File` contains `WinVPNService.exe` (as `<short>|WinVPNService.exe`) and `wireguard.dll`.
4. The contents baseline (`scripts/bundle-baseline/winvpn-msi-files.txt`), regenerated with `--write-baseline` and reviewed: exactly `PFiles/WinVPN/THIRD-PARTY-NOTICES.txt`, `PFiles/WinVPN/WinVPN.exe`, `PFiles/WinVPN/WinVPNService.exe`, `PFiles/WinVPN/wireguard.dll` (the ARM64 MSI's root as 2a's baseline shows it).
5. The unpacked `WinVPNService.exe` equals `target/<triple>/release/mvpn.exe` byte for byte (Tauri does not patch it), and the unpacked `wireguard.dll` equals the pinned one.

`scripts/test-build-msi.sh` gets cases for the new pure parts (the fragment's placeholder check refuses a template with a placeholder left; the config JSON is valid: `node -e 'JSON.parse(process.argv[1])' "$WIX_CONFIG"`).

- [x] **Step 4: The notices**

Copy the wireguard-nt zip's license file (the one in the zip's root: its name is in the zip listing from Task 14) to `scripts/notices/wireguard-nt-LICENSE.txt` (record its SHA-256 in the commit body); `third-party-notices.mjs --os windows` appends a section "wireguard-nt 0.10.1 (wireguard.dll)" with it; regenerate `THIRD-PARTY-NOTICES.windows.txt` (`node scripts/third-party-notices.mjs --os windows`) and check the macOS file is unchanged (`node scripts/third-party-notices.mjs --check`). If the license does not permit redistributing the unmodified DLL inside an MSI, stop and ask the maintainer (it is the official "embed the DLL in your app" path, so this is not expected).

- [x] **Step 5: Build and gate on the Windows machine**

Run: `bash -n scripts/build-msi.sh && scripts/test-build-msi.sh && scripts/win-remote.sh msi --arch x64 && scripts/win-remote.sh msi --arch arm64 && scripts/win-remote.sh fetch dist/windows ./dist`
Expected: every gate passes for both architectures; `dist/windows/WinVPN-1.5.0-x64.msi` and `-arm64.msi` with `.sha256`.

- [x] **Step 6: Commit**

```bash
git add app/src-tauri/wix/service.wxs.in scripts/build-msi.sh scripts/test-build-msi.sh scripts/bundle-baseline/winvpn-msi-files.txt scripts/third-party-notices.mjs scripts/notices THIRD-PARTY-NOTICES.windows.txt
git commit -m "build: the WinVPN Service and wireguard.dll in the MSIs" -m "ServiceInstall WinVPN (own process, auto, LocalSystem, 'service', restart on failure), ServiceControl start/stop/remove; the service exe gated (PE machine and subsystem, no debug-only console, no SQLite, pinned imports), wireguard.dll by its pinned SHA-256 and signer; the MSI tables and contents checked; ProgramData is never touched by the installer." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**As built (Task 15):** `app/src-tauri/wix/service.wxs.in` as planned (GUIDs `{5501A1E0-1338-473A-B37C-B12D2B68F7FF}` service exe, `{1DA04AE6-3D84-4E07-A513-AAEADE8CD5FA}` DLL; `Interactive="no"` added; Tauri 2.12's install directory is `INSTALLDIR`). The built x64 MSI's tables: **ServiceInstall** `WinVPN, "WinVPN Service", 16, 2, 32769, LocalSystem, (no password), service, WinVPNServiceExe, (no dependencies)` — `ErrorControl` is **32769**, not the plan's 1: WiX adds `msidbServiceInstallErrorControlVital` (0x8000) for `Vital="yes"` (a service that cannot be installed fails the install); **ServiceControl** `WinVPN, 163, (no arguments), Wait 1`; **MsiServiceConfigFailureActions** `Event 5` (install 1 + reinstall 4; the plan's guess 3 is WiX's other bit order), `ResetPeriod 86400`, reboot message and command `[~]` (empty), `Actions 1[~]1[~]0`, `DelayActions 5000[~]30000[~]0`; both components in `INSTALLDIR`, each file its key path; sequence `RemoveExistingProducts` 1501 (after `InstallInitialize`: an upgrade removes the old product, stopping and deleting its service, before the new one is installed and started), `StopServices` 1900, `DeleteServices` 2000, `InstallServices` 5800, `MsiConfigureServices` 5850, `StartServices` 5900. **Build** (`build-msi.sh`): `fetch-wireguard-nt.sh` once before the architectures; per architecture `cargo build --release --locked -p macvpn-helper --bin mvpn`, then the service exe and the DLL are **copied** to `target/winvpn-wix/<arch>/files/` and gated there, and the fragment points at those copies (what the MSI packs is what passed); the fragment is rendered by `render_service_wxs` (both paths must be absolute Windows paths of `[A-Za-z0-9 ._\\-]`, so nothing XML, sed or JSON would read; no `@NAME@` left; each `Source` exactly once) and the `--config` JSON by node from `tauri.windows.conf.json`'s own `fragmentPaths` plus the generated one, with `componentGroupRefs` only (a JSON merge patch keeps `componentRefs`; the plan's `printf` JSON repeated it). `--service-fragment TEMPLATE EXE DLL OUT` runs only these two (any OS; `test-build-msi.sh`). The `WINVPN_WIX_NO_ICE` relink adds `service.wixobj`. **Gates:** `gate_service_exe` (before `tauri build` and on the unpacked file): PE machine (`pe-imports.mjs --machine`, new, also used by the app's gate now), subsystem 3, none of `MACVPN_SANDBOX_HOME MACVPN_SMOKE --fake-engine --fake-openvpn --existing-data --wireguard-dll WinVPN-test- console-detect winvpn-fake` (Task 12's note: no bare "console"), no `SQLite format`, and the imports **exactly** `advapi32 api-ms-win-core-synch-l1-2-0 api-ms-win-crt-{heap,locale,math,runtime,stdio,string}-l1-1-0 bcrypt bcryptprimitives combase crypt32 iphlpapi kernel32 ntdll shell32 version wintrust ws2_32 wtsapi32` (`.dll`; beyond the plan's list: std's `bcryptprimitives.dll`, `combase.dll` for `CoTaskMemFree`, the UCRT; the plan's `ole32`/`USERENV` are not imported); `gate_wireguard_dll` (before and after): the pinned SHA-256 of the architecture, `Get-AuthenticodeSignature` `Valid`, signer `WireGuard LLC` from the pin file; after unpacking: both next to `WinVPN.exe`, the service byte for byte `target/<triple>/release/mvpn.exe` and the gated copy, the DLL byte for byte the pinned one; the MSI's `ServiceInstall`, `ServiceControl`, failure actions, the two components and the **CustomAction table** (exactly Tauri's six: `LaunchApplication` 210 on the installed `WinVPN.exe`, `WixUIValidatePath`/`WixUIPrintEula` 65 from the Binary table, two setters 51, `DownloadAndInvokeBootstrapper` 1058) row for row; the baseline is the four files. **Adaptation (found by the import gate):** the release `mvpn.exe` imported `vcruntime140.dll`, which Windows does not ship (WinVPN.exe does not: tauri-build links the VC runtime statically), so on a machine without the Visual C++ Redistributable the service would not start and `ServiceControl` would fail the install; new `crates/helper/build.rs` gives the `mvpn` binary only (msvc targets only; no effect on macOS) the `static_vcruntime` 3.0.0 linker arguments (static VC runtime and C startup, dynamic UCRT); the pinned imports have no `vcruntime140.dll`. **Notices:** `scripts/notices/wireguard-nt-LICENSE.txt` is the zip's `LICENSE.txt` byte for byte (CRLF, SHA-256 `899d95154986f755d02fea5da6781c6054c83f8b1d32bf28eadeb9fbce0e9003`, "Prebuilt Binaries License": redistribution allowed alongside software that uses the DLL only through `wireguard.h`'s API, as the service does); `third-party-notices.mjs --os windows` appends "wireguard-nt 1.1 (wireguard.dll, …)" (the version from the pin file) and now walks `macvpn-helper` too (the service ships; it adds no crate the app does not already list), section title "Rust crates (the WinVPN app and the WinVPN Service)"; the macOS file is unchanged. **Risk left for CI/CP1:** ICE validation cannot run over SSH (`WINVPN_WIX_NO_ICE`), so the `MsiServiceConfigFailureActions` table under Tauri's `InstallerVersion` 450 is validated first by CI's `msi` job. **Pre-existing, for the review (Task 24), not changed here:** `DownloadAndInvokeBootstrapper` (Tauri's `webviewInstallMode: downloadBootstrapper`, 2a) is deferred and impersonated, runs only when no WebView2 is installed, and runs `MicrosoftEdgeWebview2Setup.exe` from the installing user's `%TEMP%` (a user-writable file run by an elevated install); `embedBootstrapper` or `skip` would avoid it. **Results:** `test-build-msi.sh` 48/48 (shellcheck clean), Windows: `service_pipe` 5/5 and `openvpn_fake` 7/7 with the new link, helper clippy (Windows target) clean, macOS helper tests green; `scripts/win-remote.sh msi --arch x64` passed every gate: `WinVPN-1.5.0-x64.msi` SHA-256 `e8355bc4c12af298b37a5c6d448f37c18cbb8325733cb471a2c83b4fda263fbf` (unsigned, no ICE). The ARM64 MSI was not built in this task (the coordinator's wave build). **Needs the maintainer (CP1, elevated):** install the MSI; `sc qc WinVPN` (`BINARY_PATH_NAME` exactly `"C:\Program Files\WinVPN\WinVPNService.exe" service`, quoted; `START_TYPE AUTO_START`; `SERVICE_START_NAME LocalSystem`), `sc qfailure WinVPN` (restart 5000/30000, reset 86400), `sc query WinVPN` running, `icacls "C:\Program Files\WinVPN"` (admin-only), `Get-AuthenticodeSignature` of the installed `wireguard.dll`; repair and an upgrade stop and restart the service; uninstall removes the service and the files and leaves `C:\ProgramData\WinVPN`.

**As built (fix2, CP1):** the first elevated install of the x64 MSI rolled back at `InstallFinalize` with **error 1939** ("Service 'WinVPN Service' (WinVPN) could not be configured") on `ServiceConfigureFailureAction(…, Actions=1[~]1[~]0, …)`: Windows Installer's built-in `MsiServiceConfigFailureActions` opens the service without `SERVICE_START`, which `ChangeServiceConfig2` requires for an `SC_ACTION_RESTART`, so it fails with access denied (5). Fixed without a custom action (the CustomAction gate stays Tauri's six): `service.wxs.in` has no `ServiceConfigFailureActions` any more (`ServiceInstall`/`ServiceControl` unchanged), and `build-msi.sh` now **requires** `MsiServiceConfigFailureActions` to be absent from `_Tables` or empty (a row fails the build, the message names error 1939); `test-build-msi.sh` checks the template has no failure actions and the gate is there. The service sets its own recovery instead: new `macvpn_winsys::scm::set_recovery(name, &Recovery { reset_period_secs, actions: &[FailureAction], on_non_crash_failures })` (winsys feature `Win32_System_Services`): `OpenSCManagerW(SC_MANAGER_CONNECT)`, `OpenServiceW(SERVICE_CHANGE_CONFIG | SERVICE_START)`, `ChangeServiceConfig2W(SERVICE_CONFIG_FAILURE_ACTIONS)` (empty reboot message and command) and `SERVICE_CONFIG_FAILURE_ACTIONS_FLAG`. The values live in `crates/helper/src/windows/recovery.rs` (pure, unit-tested on every OS): `WinVPN`, reset 86400 s, restart after 5000 ms, restart after 30000 ms, then none, and `fFailureActionsOnNonCrashFailures` TRUE (the service's own failed starts, exit code 1, count too). `sys::host::service_main` calls it once per start, right after the service log opens (only in `service_main`: the console and the tests never touch the SCM); a failure is only logged (`cannot set the recovery actions (kind, os error)`), the service runs on; the same values each start are idempotent. New ignored admin test `admin_the_installed_service_restarts_after_a_failure` (`service_admin.rs`, `sc qfailure` / `sc qfailureflag`; listed in `scripts/ignored-everywhere.txt`). **Needs the maintainer (CP1):** after the install has started the service once, `sc qfailure WinVPN` shows `RESET_PERIOD 86400` and `RESTART -- Delay = 5000` / `30000`, `sc qfailureflag WinVPN` TRUE, and `C:\ProgramData\WinVPN\service.log` has no "cannot set the recovery actions" line.

## Task 16: the app's service client

**Goal:** on Windows, connecting, disconnecting, MFA answers, the MFA state, the live log, status polling and System Status all go to the WinVPN Service over `\\.\pipe\WinVPN`, trusting only a SYSTEM-owned pipe; the engine-missing state appears only when the service is absent, unreachable, from another version or degraded.

**Files:**
- Create: `crates/core/src/helper_args.rs` (the root layer's `up` arguments and frame, moved from platform-mac's `MvpnClient`), `crates/platform-win/src/pure/engine.rs`, `crates/platform-win/src/win/service_client.rs`, `crates/platform-win/tests/service_client.rs` (Windows; uses the helper's console)
- Modify: `crates/platform-mac/src/mvpn_client.rs` (`up_arguments` / `up_stdin` call core), `crates/platform-win/src/win/{platform,not_yet,mod}.rs`, `crates/platform-win/src/pure/{mod,texts}.rs`, `crates/platform-win/Cargo.toml` (`[target.'cfg(windows)'.dev-dependencies] macvpn-helper = { path = "../helper" }` for the console binary), `crates/core/l10n/strings.json`

- [x] **Step 1: Move the `up` arguments to core** (a pure refactor; the pin is `crates/platform-mac/tests/mvpn_client.rs`, unchanged)

`crates/core/src/helper_args.rs`:

```rust
//! The command line and the framed stdin of the helper's `up` (root layer 8), shared by MacVPN's `sudo mvpn` client
//! and WinVPN's service client: the config goes in the frame, never in an argument; the secrets follow it.

use crate::models::{Secrets, VPNKind, uuid_string};
use std::collections::BTreeSet;
use uuid::Uuid;
use zeroize::Zeroizing;

/// `up <kind> <ID> [--debug] [--accept-risky a,b]` (the acknowledged names sorted, `^[a-z0-9-]+$` only, OpenVPN only).
pub fn up_arguments(kind: VPNKind, id: &Uuid, debug: bool, accept_risky: &[String]) -> Vec<String> {
    let mut args = vec!["up".to_string(), kind.raw_value().to_string(), uuid_string(id)];
    if debug {
        args.push("--debug".into());
    }
    let names: BTreeSet<&str> = accept_risky
        .iter()
        .map(String::as_str)
        .filter(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
        .collect();
    if kind == VPNKind::Openvpn && !names.is_empty() {
        args.push("--accept-risky".into());
        args.push(names.into_iter().collect::<Vec<_>>().join(","));
    }
    args
}

/// `config <len>\n<config><secret lines>`, in one zeroized buffer.
pub fn up_stdin(config: &[u8], secrets: &Secrets) -> Zeroizing<Vec<u8>> {
    let lines = secrets.stdin_payload();
    let header = format!("config {}\n", config.len());
    let mut payload = Zeroizing::new(Vec::with_capacity(header.len() + config.len() + lines.len()));
    payload.extend_from_slice(header.as_bytes());
    payload.extend_from_slice(config);
    payload.extend_from_slice(lines.as_bytes());
    payload
}
```

`MvpnClient::up_arguments` and `up_stdin` become one-line calls to these (kept as associated functions: their callers and tests do not change). Check that `Secrets` and `uuid_string` live at those core paths (`MvpnClient` imports them; copy its imports). Run `cargo test --locked -p macvpn-platform-mac --test mvpn_client` → PASS unchanged; commit (`refactor: the helper's up arguments and frame in core`).

- [x] **Step 2: Write the failing tests**

`crates/platform-win/src/pure/engine.rs` is pure (every OS) and maps the service's facts to a `SetupReport`; its tests in `crates/platform-win/tests/pure.rs`:

```rust
use macvpn_core::models::VPNKind;
use macvpn_core::service_proto::{EngineFacts, OpenVpnFacts, SERVICE_VERSION, WireGuardFacts};
use macvpn_platform_win::pure::engine::{Reach, report};

fn facts(openvpn_problem: Option<&str>, wg_problem: Option<&str>) -> EngineFacts {
    EngineFacts {
        service_version: SERVICE_VERSION,
        problem: None,
        openvpn: OpenVpnFacts {
            version: openvpn_problem.is_none().then(|| "2.6.14".into()),
            path: None,
            dco: openvpn_problem.is_none().then(|| "2.6.1".into()),
            tap_windows6: openvpn_problem.is_none().then(|| "9.27.0".into()),
            problem: openvpn_problem.map(String::from),
        },
        wireguard: WireGuardFacts { dll_version: Some("0.10".into()), problem: wg_problem.map(String::from) },
    }
}

#[test]
fn a_reachable_service_gives_three_rows() {
    let r = report(Reach::Facts(facts(None, None)), "2.6.14");
    let e = r.engine.as_ref().unwrap();
    assert!(e.service.ok && e.openvpn.ok && e.wireguard.ok);
    assert_eq!(r.engine_missing, None);
    assert!(r.is_available(VPNKind::Openvpn) && r.is_available(VPNKind::Wireguard));
    assert!(!r.is_available(VPNKind::L2tp) && r.later_reason(VPNKind::Sstp).is_some());
}

#[test]
fn missing_openvpn_offers_install_and_an_old_one_update() {
    let r = report(Reach::Facts(facts(Some("OpenVPN Community is not installed."), None)), "2.6.14");
    assert_eq!(r.engine.as_ref().unwrap().openvpn.action, Some("install"));
    let mut old = facts(None, None);
    old.openvpn.version = Some("2.6.3".into());
    assert_eq!(report(Reach::Facts(old), "2.6.14").engine.unwrap().openvpn.action, Some("update"));
    // A missing driver: "repair", still usable for the other drivers' connections.
    let mut no_tap = facts(None, None);
    no_tap.openvpn.tap_windows6 = None;
    let row = report(Reach::Facts(no_tap), "2.6.14").engine.unwrap().openvpn;
    assert_eq!((row.ok, row.usable, row.action), (false, true, Some("repair")));
}

#[test]
fn no_service_or_another_version_is_engine_missing() {
    for reach in [Reach::Absent, Reach::Unreachable("x".into())] {
        let r = report(reach, "2.6.14");
        assert!(r.engine_missing.is_some() && r.engine.is_none());
    }
    let mut other = facts(None, None);
    other.service_version = SERVICE_VERSION + 1;
    assert!(report(Reach::Facts(other), "2.6.14").engine_missing.is_some());
    let mut degraded = facts(None, None);
    degraded.problem = Some("unsafe folder".into());
    assert_eq!(report(Reach::Facts(degraded), "2.6.14").engine_missing.as_deref(), Some("unsafe folder"));
}
```

`crates/platform-win/tests/service_client.rs` (Windows; the client against the helper's debug console with the fake engine, over SSH):

```rust
#![cfg(windows)]

use macvpn_core::models::{Secrets, VPNKind};
use macvpn_platform_api::HelperClient;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

#[test]
fn the_client_connects_reads_status_and_the_log_through_the_service() {
    let pipe = format!(r"\\.\pipe\WinVPN-test-{}", uuid::Uuid::new_v4());
    let data = std::env::temp_dir().join(format!("winvpn-client-{}", uuid::Uuid::new_v4()));
    let exe = macvpn_platform_win::helper_console_for_tests();
    let mut child = Command::new(&exe)
        .args(["console", "--pipe", &pipe, "--data", data.to_str().unwrap(), "--fake-engine"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.as_mut().unwrap()).read_line(&mut line).unwrap();
    let client = macvpn_platform_win::service_client_for_tests(&pipe);
    let id = uuid::Uuid::new_v4();
    let wg = b"[Interface]\nPrivateKey = bWFjdnBuLXRlc3QtcHJpdmF0ZS1rZXktMzJieXRlcyE=\nAddress = 10.0.0.2/32\n\n[Peer]\nPublicKey = bWFjdnBuLXRlc3QtcHVibGljLS1rZXktMzJieXRlcyE=\nAllowedIPs = 0.0.0.0/0\n";
    client.up(VPNKind::Wireguard, &id, wg, &Secrets::default(), false, &[]).unwrap();
    let st = client.status().unwrap();
    assert_eq!(st.len(), 1);
    assert_eq!(st[0].id, id);
    let mut src = client.log_source(&id).unwrap();
    let read = src.read(0, 1 << 20).unwrap();
    assert!(!read.data.is_empty());
    client.down(VPNKind::Wireguard, &id).unwrap();
    assert!(client.status().unwrap().is_empty());
    drop(child.stdin.take());
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&data);
}

#[test]
fn a_user_owned_pipe_named_like_the_service_is_refused() {
    // The production client trusts only SYSTEM: a pipe of this user is "not the service", nothing is sent.
    let pipe = format!(r"\\.\pipe\WinVPN-test-{}", uuid::Uuid::new_v4());
    let _l = macvpn_winsys::pipe::Listener::bind_endpoint(&pipe, macvpn_winsys::pipe::Endpoint::ServiceForTests).unwrap();
    let client = macvpn_platform_win::service_client_trusting_system_for_tests(&pipe);
    let e = client.status().unwrap_err();
    assert_eq!(e, macvpn_platform_win::pure::texts::service_unreachable());
}
```

(`helper_console_for_tests()` returns the path of the helper's debug `mvpn.exe`: `target/<triple>/debug/mvpn.exe` next to the test binary's directory; build it first with `cargo build -p macvpn-helper`, which `scripts/win-remote.sh test` does when the workspace builds. The three `*_for_tests` functions are `#[doc(hidden)]` in `lib.rs` like 2a's.)

- [x] **Step 3: Run them to verify they fail**

Run: `cargo test --locked -p macvpn-platform-win --test pure && scripts/win-remote.sh run 'cargo build --locked -p macvpn-helper && cargo test --locked -p macvpn-platform-win --test service_client'`
Expected: FAIL to compile.

- [x] **Step 4: Implement**

`pure/engine.rs`:

```rust
//! System Status and availability on Windows from the WinVPN Service's `engine` answer (pure).

use crate::pure::texts;
use macvpn_core::models::VPNKind;
use macvpn_core::service_proto::{EngineFacts, SERVICE_VERSION, Version};
use macvpn_platform_api::setup::{EngineReport, EngineRow, SetupReport};

/// What the app learned about the service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reach {
    /// No service is installed (the pipe does not exist).
    Absent,
    /// The pipe exists but no trusted answer came (the localized reason).
    Unreachable(String),
    Facts(EngineFacts),
}

fn later() -> Vec<(VPNKind, String)> {
    [VPNKind::L2tp, VPNKind::Cisco, VPNKind::Strongswan, VPNKind::Sstp].map(|k| (k, texts::native_later())).to_vec()
}

/// `recommended_openvpn`: the pinned OpenVPN version (an older installed one offers "Update").
pub fn report(reach: Reach, recommended_openvpn: &str) -> SetupReport {
    let missing = |reason: String| SetupReport { engine_missing: Some(reason), later_kinds: later(), ..SetupReport::unknown() };
    let f = match reach {
        Reach::Absent => return missing(texts::service_missing()),
        Reach::Unreachable(_) => return missing(texts::service_unreachable()),
        Reach::Facts(f) => f,
    };
    if f.service_version != SERVICE_VERSION {
        return missing(texts::service_missing());
    }
    if let Some(p) = f.problem {
        return missing(p);
    }
    let recommended = Version::parse(recommended_openvpn);
    let installed = f.openvpn.version.as_deref().and_then(Version::parse);
    let o = &f.openvpn;
    let drivers = [("OpenVPN DCO", &o.dco), ("TAP-Windows6", &o.tap_windows6)];
    let missing: Vec<&str> = drivers.iter().filter(|(_, v)| v.is_none()).map(|(n, _)| *n).collect();
    let openvpn = match (&o.problem, installed) {
        (None, Some(v)) => {
            let detail = texts::openvpn_ok(&v.to_string(), &drivers.map(|(n, ver)| (n, ver.clone())));
            if missing.is_empty() {
                EngineRow { ok: true, usable: true, detail, action: recommended.is_some_and(|r| v < r).then_some("update") }
            } else {
                let usable = missing.len() < drivers.len();
                EngineRow { ok: false, usable, detail: format!("{detail} {}", texts::drivers_missing(&missing.join(", "))), action: Some("repair") }
            }
        }
        (Some(p), None) => EngineRow { ok: false, usable: false, detail: p.clone(), action: Some("install") },
        (Some(p), Some(_)) => EngineRow { ok: false, usable: false, detail: p.clone(), action: Some("update") },
        (None, None) => EngineRow { ok: false, usable: false, detail: texts::service_unreachable(), action: Some("install") },
    };
    let wireguard = match (&f.wireguard.problem, &f.wireguard.dll_version) {
        (None, Some(v)) => EngineRow { ok: true, usable: true, detail: format!("wireguard-nt {v}"), action: None },
        (Some(p), _) => EngineRow { ok: false, usable: false, detail: p.clone(), action: None },
        (None, None) => EngineRow { ok: false, usable: false, detail: texts::service_unreachable(), action: None },
    };
    SetupReport {
        engine: Some(EngineReport {
            service: EngineRow { ok: true, usable: true, detail: texts::service_running(&SERVICE_VERSION.to_string()), action: None },
            openvpn,
            wireguard,
        }),
        later_kinds: later(),
        ..SetupReport::unknown()
    }
}
```

`Version` lives in core (`macvpn_core::service_proto::Version`, added by Task 10), so the app and the service compare versions with one implementation.

`win/service_client.rs`:

```rust
//! The WinVPN Service over `\\.\pipe\WinVPN` (`macvpn_core::service_proto`): HelperClient, AuthStateReader, the log
//! source, the engine facts. Each call is one connection; the client trusts only a pipe owned by SYSTEM (in tests:
//! by this user). The language of the answer is the app's (`--lang`).

pub(crate) struct ServiceClient {
    pipe: String,
    trust: ServerTrust,
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// `up` may wait for an MFA answer (the service's limit is 30 s + 420 s).
const UP_TIMEOUT: Duration = Duration::from_secs(480);
const QUICK_TIMEOUT: Duration = Duration::from_secs(20);

impl ServiceClient {
    pub(crate) fn production() -> ServiceClient {
        ServiceClient { pipe: PIPE_NAME.to_string(), trust: ServerTrust::LocalSystem }
    }

    fn call(&self, args: &[&str], body: &[u8], timeout: Duration) -> Result<Response, String> {
        let mut s = pipe::connect_with(&self.pipe, CONNECT_TIMEOUT, self.trust).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => texts::service_missing(),
            _ => texts::service_unreachable(),
        })?;
        let lang = AppLanguage::current().raw_value();
        let mut all: Vec<&str> = args.to_vec();
        all.extend(["--lang", lang]);
        s.set_write_timeout(Some(QUICK_TIMEOUT)).map_err(|_| texts::service_unreachable())?;
        s.set_read_timeout(Some(timeout)).map_err(|_| texts::service_unreachable())?;
        proto::write_request(&mut s, &all, body).map_err(|_| texts::service_unreachable())?;
        proto::read_response(&mut s).map_err(|_| texts::service_unreachable())
    }

    /// The service's answer as a result: exit 0 = `Ok`; otherwise its message (or the exit code), as `MvpnClient`'s
    /// `check` does on macOS.
    fn check(r: Response) -> Result<Vec<u8>, String> {
        if r.code == 0 {
            return Ok(r.stdout);
        }
        let message = String::from_utf8_lossy(&r.stderr).trim().to_string();
        Err(if message.is_empty() { l10n::tr("mvpn error (exit code: %d)", &[Arg::Int(i64::from(r.code))]) } else { message })
    }

    /// The service's `engine` answer: no pipe = `Absent`; no trusted answer = `Unreachable`.
    pub(crate) fn reach(&self) -> Reach {
        let r = match pipe::connect_with(&self.pipe, CONNECT_TIMEOUT, self.trust) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Reach::Absent,
            Err(_) => return Reach::Unreachable(texts::service_unreachable()),
            Ok(_) => self.call(&["engine"], b"", QUICK_TIMEOUT),
        };
        match r.ok().and_then(|r| Self::check(r).ok()).and_then(|out| EngineFacts::parse(&out)) {
            Some(f) => Reach::Facts(f),
            None => Reach::Unreachable(texts::service_unreachable()),
        }
    }
}

impl HelperClient for ServiceClient {
    fn status(&self) -> Result<Vec<RootStatus>, String> {
        let out = Self::check(self.call(&["status"], b"", QUICK_TIMEOUT)?)?;
        parse_status(&String::from_utf8_lossy(&out)).map_err(|e| e.to_string())
    }
    fn up(&self, kind: VPNKind, id: &Uuid, config: &[u8], secrets: &Secrets, debug: bool, accept_risky: &[String]) -> Result<(), String> {
        let args = helper_args::up_arguments(kind, id, debug, accept_risky);
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let body = helper_args::up_stdin(config, secrets);
        Self::check(self.call(&refs, &body, UP_TIMEOUT)?).map(|_| ())
    }
    fn down(&self, kind: VPNKind, id: &Uuid) -> Result<(), String> {
        let id = uuid_string(id);
        Self::check(self.call(&["down", kind.raw_value(), &id], b"", QUICK_TIMEOUT)?).map(|_| ())
    }
    fn respond(&self, id: &Uuid, kind: AuthResponseKind, response: &str) -> Result<(), String> {
        let body = Zeroizing::new(kind.stdin_payload(response).ok_or_else(|| l10n::tr("Invalid response", &[]))?);
        let id = uuid_string(id);
        Self::check(self.call(&["respond", "openvpn", &id], body.as_bytes(), QUICK_TIMEOUT)?).map(|_| ())
    }
    fn log_source(&self, id: &Uuid) -> Option<Box<dyn LogSource>> {
        Some(Box::new(PipeLogSource { client: self.clone(), id: uuid_string(id) }))
    }
}

/// The MFA state the bridge publishes for this user's connection, with the same parser and limit as the file on
/// macOS.
impl AuthStateReader for ServiceClient {
    fn read(&self, id: &Uuid) -> Option<AuthUIState> {
        let id = uuid_string(id);
        let out = Self::check(self.call(&["auth-state", &id], b"", QUICK_TIMEOUT).ok()?).ok()?;
        if out.is_empty() { None } else { AuthUIState::parse(&out) }
    }
}

struct PipeLogSource {
    client: ServiceClient,
    id: String,
}

impl LogSource for PipeLogSource {
    fn read(&mut self, offset: u64, max: usize) -> Option<LogRead> {
        let off = offset.to_string();
        let out = ServiceClient::check(self.client.call(&["log", &self.id, &off], b"", QUICK_TIMEOUT).ok()?).ok()?;
        let s = LogSlice::parse(&out)?;
        if s.generation == 0 {
            return None;
        }
        let mut data = s.data;
        data.truncate(max);
        Some(LogRead { identity: Some(LogIdentity::Generation(s.generation)), size: s.size, start: s.start, data })
    }
}
```

(`ServiceClient` derives `Clone`; `kind.stdin_payload` returns the respond body as `String` on macOS: wrap it in `Zeroizing` as shown.)

`win/platform.rs`: `helper_client()` → `Arc::new(ServiceClient::production())`; `auth_state()` → the same; `SystemSetup::check` → `pure::engine::report(ServiceClient::production().reach(), OPENVPN_VERSION)`; `engine_note()` → `None` (the rows replace it; 2a's note stays only through `engine_missing`); `later_note()` → `Some(texts::native_later())`; `helper_upgrade_notice()` → "Updating WinVPN disconnects active VPN connections." `NativeController` and `NativeProfiles` stay `NoEngine` with the native text (`not_yet.rs`: `engine_later()` → `native_later()` for those two). `bundled_helper_dir` stays `None` (the MSI installs the service; there is no in-app installer).

`pure/texts.rs` (+ `strings.json`, scope `core`, `"only": ["windows"]`):
- `service_missing()`: "The WinVPN Service is missing or from another WinVPN version. Repair WinVPN: Settings → Apps → Installed apps → WinVPN → Modify → Repair." → "A WinVPN szolgáltatás hiányzik, vagy egy másik WinVPN-verzióhoz tartozik. Javítsd a WinVPN-t: Gépház → Alkalmazások → Telepített alkalmazások → WinVPN → Módosítás → Javítás."
- `service_unreachable()`: "The WinVPN Service is not reachable." → "A WinVPN szolgáltatás nem érhető el."
- `service_running(v)`: "Running (version %@)" → "Fut (%@. verzió)"
- `native_later()`: the text added in Task 11.
- `openvpn_ok(v, drivers)`, the OpenVPN row: "Version %@ · drivers: %@" → "%@. verzió · illesztőprogramok: %@" (the second argument lists each installed driver with its version, e.g. `OpenVPN DCO 2.8.13, TAP-Windows6 9.27.0`)
- `drivers_missing(list)`: "Missing: %@. Repair adds them." → "Hiányzik: %@. A Javítás telepíti őket."; WireGuard row: "wireguard-nt %@" (no translation needed: hu the same).
- "Updating WinVPN disconnects active VPN connections." → "A WinVPN frissítése bontja az aktív VPN-kapcsolatokat."

- [x] **Step 5: Run**

Run: `CI=1 cargo test --workspace --locked && scripts/check-windows.sh && scripts/win-remote.sh run 'cargo build --locked -p macvpn-helper && cargo test --locked -p macvpn-platform-win' && scripts/win-remote.sh test && node scripts/l10n-baseline.mjs --check`
Expected: PASS.

- [x] **Step 6: Commit**

```bash
git add crates/core crates/platform-mac/src/mvpn_client.rs crates/platform-win crates/core/l10n/strings.json
git commit -m "feat(platform-win): the app talks to the WinVPN Service" -m "HelperClient, AuthStateReader and the log source over \\\\.\\pipe\\WinVPN, trusting only a SYSTEM-owned pipe; System Status from the service's engine facts; engine-missing only when the service is absent, unreachable, of another version or degraded. The helper's up arguments and frame moved to core (macOS unchanged: mvpn_client tests)." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**As built (Task 16):** `core::helper_args::{up_arguments, up_stdin}` (`MvpnClient`'s two associated functions call them; `mvpn_client` tests unchanged, commit "refactor: the helper's up arguments and frame in core"), `platform-win::pure::engine::{Reach, report}`, `win::service_client::ServiceClient` as planned, with these changes. **Client:** one private `exchange` does connect (the SYSTEM-owner check passes before `write_request`; nothing is sent otherwise) → `args … --lang <app>` → answer; `reach` makes **one** connection (not the sketch's connect-then-call). Failures: no pipe = `Absent` / "The WinVPN Service is missing or from another WinVPN version. …"; another owner, busy, a timeout or a broken exchange = "The WinVPN Service is not reachable."; an answer that is not this protocol (`ProtoError::Invalid`), an `engine` that fails or facts that do not parse = another version ("missing or from another version"): `Reach::Unreachable(reason)` carries that reason (the sketch always used the unreachable text). `down` waits 30 s (OpenVPN's stop takes up to 5 + 5 s), the rest 20 s, `up` 480 s. `respond`'s invalid code is `MFAError::InvalidCode.message()` (macOS' text) and never reaches the pipe. **Report:** fail closed: the OpenVPN row is green only with no problem, a parseable version and both drivers; installed but refused by the service → "update" when older than the pin, else "repair" (e.g. a wrong signer; the sketch always said "update"); no driver → red, not usable, "repair"; the detail lists the installed drivers (`OpenVPN DCO 2.8.13.0, TAP-Windows6 9.27.0.0`; no Wintun) and "Version %@" alone when there is none. Service version 0 or any other than `SERVICE_VERSION` = missing. **Platform:** `helper_client` / `auth_state` = `ServiceClient::production()`; `check` = `report(reach(), OPENVPN_VERSION)`; `engine_note` `None`, `later_note` the native text, `helper_upgrade_notice` "Updating WinVPN disconnects active VPN connections."; `NoEngine` keeps only `NativeController` / `NativeProfiles` (native text), its `HelperClient` impl is gone. **App (one line, `state.rs`):** with `engine_note` `None`, System Status would have shown macOS' Homebrew/tools/helper rows when the service is missing, so the view takes `engine_note().or_else(|| setup.engine_missing.clone())` (macOS: both `None`, unchanged). **Strings** (core, `only: windows`): the plan's plus "Version %@" ("%@. verzió"); "wireguard-nt %@" is not translated (plain `format!`). **Tests:** `tests/pure.rs` `engine_report` (5: three rows, install/update/repair incl. refused-at-pin and no driver, fail-closed facts, missing/unreachable/other version/degraded, the texts in HU); `tests/service_client.rs` (`cfg(all(windows, debug_assertions))`, 5, against `mvpn console --fake-engine` as the standard user): up/status/live log (password masked, generation identity, `max` honoured)/auth-state/refused `respond`/down/unknown ID; messages in the app's language; `engine` facts → rows (no OpenVPN on the VM → "install"); no pipe → `Absent` and every call "missing"; a user-owned pipe with the production trust → "not reachable" for `status`, `up` (with a password) and `reach`, and the squatter received **zero bytes**. 2a's `tests/windows.rs::the_vpn_parts_say_later_and_list_nothing` became `without_the_service_the_vpn_parts_say_so`. No `macvpn-helper` dev-dependency (it would not build the binary): `helper_console_for_tests()` finds `target/<triple>/debug/mvpn.exe` and says to build it first (`cargo build -p macvpn-helper`; the full `win-remote.sh test` builds it with the helper's tests). The `*_for_tests` hooks assert a `WinVPN-test-` pipe; the same-user trust exists only in debug builds. Windows (standard user): platform-win lib + tests all green (`service_client` 5/5, `pure` 21/21, `windows` 19/19), clippy `-D warnings` clean for platform-win, core, app. **CP1 GUI checks:** System Status with the installed service shows the three rows (OpenVPN: version and both drivers; WireGuard row), the note about native VPNs, no Homebrew rows; with the service stopped (`sc stop WinVPN`): every row says "The WinVPN Service is not reachable." or "…missing…", System Status shows that text, connect refused with it; connect/disconnect OpenVPN and WireGuard; MFA prompt (CRV1/static) answered from the app; the Log tab shows masked lines live; the update notice text in System Status.

### Checkpoint CP1 (the maintainer, after Wave 3 is merged)

Build the MSI on the merged tip (`scripts/win-remote.sh msi --arch x64 && scripts/win-remote.sh fetch dist/windows ./dist`) and hand it with the "WinVPN 2b – CP1" items of the checklist (Task 22 writes the final section; until then this list is the checklist, in Hungarian in the hand-off message):
1. As administrator: install the MSI over the 2a WinVPN → `sc qc WinVPN` (LocalSystem, AUTO_START, `"…\WinVPNService.exe" service`), `sc query WinVPN` RUNNING; `icacls C:\ProgramData\WinVPN` → SYSTEM and Administrators only.
2. Install the pinned OpenVPN Community MSI by hand with the plan's `ADDLOCAL` (as administrator: `msiexec /i OpenVPN-….msi ADDLOCAL=<features> /qb`): `openvpn.exe`, DCO, TAP-Windows6 (OpenVPN 2.7.8: no Wintun); no GUI. The Interactive Service comes with the core feature and runs: a hand install is not WinVPN's, so WinVPN leaves it alone (Task 17 disables it only after its own installs).
3. In an elevated Git Bash: `cargo test --locked -p macvpn-helper --test service_admin --test wireguard_admin --test openvpn_installed -- --ignored` and `cargo test --locked -p macvpn-winsys --test service_pipe -- --ignored` → all pass.
4. As the standard user at the desktop: System Status shows the three rows green; connect an OpenVPN connection with a password (a test server the maintainer has), one with an MFA code (CRV1 or static challenge) and one with web sign-in if available; connect OpenVPN configs that select each driver — a plain one (DCO), one with `comp-lzo` or `cipher AES-256-CBC` (TAP-Windows6, layer 3) and one with `dev tap` against a TAP server (TAP-Windows6, layer 2): the Log tab names the driver; connect a WireGuard connection, full tunnel (`AllowedIPs = 0.0.0.0/0`): browsing works, `nslookup` uses the tunnel's DNS; the Log tab shows masked lines live; disconnect; quit with a connection up → the quit question.
5. A second standard user logged on (fast user switching): cannot see or disconnect the first user's connection; the first user logs off → the service takes that user's connections down (decision 2).
6. `sc stop WinVPN` with a connection up → the tunnel goes away and `openvpn.exe` is gone (Task Manager); `sc start WinVPN` → the app shows the connection as dropped.
Every unchecked item is a finding with its fix task before Wave 4 starts.

**CP1 result (2026-10-22, maintainer, Windows 11 x64 VM):** two findings, both fixed before Wave 4. (a) The first MSI failed with error 1939: Windows Installer's MsiServiceConfigFailureActions cannot set restart actions; fix2 (3fc41eb) moved the recovery settings into the service (`winsys::scm::set_recovery` at every start), the MSI gate refuses the table. (b) WireGuard failed with "route (os error 5010)": Windows creates the Address subnet's on-link route itself, so an AllowedIPs entry equal to it already existed; 35a7114 counts ERROR_OBJECT_ALREADY_EXISTS on the adapter's own LUID as added. Passed: install (also over the same version 1.5.0), `sc qc`/`query`/`qfailure`/`qfailureflag`, both ACLs, `service.log` (wireguard.dll 1.1.0 loaded), wireguard.dll Authenticode, the OpenVPN 2.7.8 hand install (default features, incl. GUI and Interactive Service) detected with DCO 2.8.13 and TAP-Windows6 9.27, an OpenVPN connection, a WireGuard full tunnel with traffic, `sc stop`/`sc start`. Not run at CP1, carried to the "WinVPN 2b" checklist (Task 22): the elevated `cargo test … -- --ignored` set (item 3), MFA/web sign-in and the per-driver configs (item 4), the second user and logoff (item 5).

## Task 17: OpenVPN Community install and update from System Status

**Goal:** the OpenVPN row's "Install" / "Repair" / "Update" installs OpenVPN Community with `openvpn.exe`, DCO and TAP-Windows6 (decision 4): through winget when it exists (the same features through `--override`), else — or when a driver is still missing afterwards — the pinned MSI after its SHA-256 and Authenticode signer matched; elevated by a UAC prompt; after an install WinVPN made, OpenVPN's Interactive Service is disabled, stopped and checked (decision 4); the output streams into System Status; afterwards the rows are checked again.

**Files:**
- Create: `crates/platform-win/src/pure/openvpn_install.rs` (argv builders, exit codes, texts), `crates/platform-win/src/win/{elevate,openvpn_install,curl_runner}.rs`, `crates/platform-win/tests/openvpn_install.rs` (Windows)
- Modify: `crates/platform-api/src/curl/http.rs` (`download_pinned`), `crates/platform-api/tests/curl_pinned.rs` (new), `crates/platform-win/src/win/platform.rs` (`install_tools`), `crates/platform-win/src/pure/mod.rs`, `crates/platform-win/tests/pure.rs`, `crates/platform-win/Cargo.toml` (feature `Win32_UI_Shell` already; `Win32_System_Threading` already), `crates/core/l10n/strings.json`

- [x] **Step 1: Write the failing tests**

Pure (`crates/platform-win/tests/pure.rs`):

```rust
use macvpn_platform_win::pure::openvpn_install::{self as oi, Outcome};

#[test]
fn the_winget_command_line_is_fixed() {
    assert_eq!(
        oi::winget_args(false, "OpenVPN,Drivers,Drivers.OvpnDco,Drivers.TAPWindows6"),
        [
            "install", "--id", "OpenVPNTechnologies.OpenVPN", "--exact", "--source", "winget", "--scope", "machine",
            "--silent", "--accept-package-agreements", "--accept-source-agreements", "--disable-interactivity",
            "--override", "/qn /norestart ADDLOCAL=OpenVPN,Drivers,Drivers.OvpnDco,Drivers.TAPWindows6",
        ]
    );
    assert_eq!(oi::winget_args(true, "OpenVPN")[0], "upgrade");
}

#[test]
fn the_msiexec_parameters_quote_only_a_checked_path() {
    let p = std::path::Path::new(r"C:\Users\bob\AppData\Local\WinVPN\downloads\OpenVPN-2.6.14-I001-amd64.msi");
    // `C:\…` is absolute only on Windows (the macOS CI runs the refusals below).
    if cfg!(windows) {
        assert_eq!(
            oi::msiexec_parameters(p, "OpenVPN,Drivers.OvpnDco,Drivers.TAPWindows6").unwrap(),
            r#"/i "C:\Users\bob\AppData\Local\WinVPN\downloads\OpenVPN-2.7.8-I001-amd64.msi" /qb! /norestart ADDLOCAL=OpenVPN,Drivers.OvpnDco,Drivers.TAPWindows6"#
        );
    }
    assert!(oi::msiexec_parameters(std::path::Path::new(r#"C:\x" /qn TRANSFORMS="evil.mst"#), "OpenVPN").is_none());
    assert!(oi::msiexec_parameters(p, "OpenVPN TRANSFORMS=x").is_none());
}

#[test]
fn exit_codes_map_to_outcomes() {
    assert_eq!(oi::outcome(0), Outcome::Done);
    assert_eq!(oi::outcome(3010), Outcome::DoneRestartNeeded);
    assert_eq!(oi::outcome(1602), Outcome::Cancelled);
    assert_eq!(oi::outcome(1223), Outcome::Cancelled);
    assert_eq!(oi::outcome(1603), Outcome::Failed(1603));
}
```

The pinned download (`crates/platform-api/tests/curl_pinned.rs`, every OS):

```rust
use macvpn_core::update::sha256_hex;
use macvpn_platform_api::curl::http::{CurlHttpClient, HttpError};
use macvpn_platform_api::curl::{CommandError, CommandResult, CommandRunner, Curl};
use std::sync::{Arc, Mutex};

/// Writes `payload` to the `--output` path and answers HTTP 200, recording each argv.
struct Server {
    payload: Vec<u8>,
    calls: Mutex<Vec<Vec<String>>>,
}

impl CommandRunner for Arc<Server> {
    fn run(&self, _exe: &str, args: &[String], _stdin: Option<&str>) -> Result<CommandResult, CommandError> {
        self.calls.lock().unwrap().push(args.to_vec());
        let out = args.iter().position(|a| a == "--output").map(|i| args[i + 1].clone()).unwrap();
        std::fs::write(out, &self.payload).unwrap();
        Ok(CommandResult::stdout("200 "))
    }
}

fn temp_dir(prefix: &str) -> Result<std::path::PathBuf, String> {
    let d = std::env::temp_dir().join(format!("{prefix}.{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&d).map_err(|e| e.to_string())?;
    Ok(d)
}

fn client(server: &Arc<Server>) -> CurlHttpClient {
    let curl = Curl { executable: "curl".into(), extra_args: vec![], private_dir: temp_dir, temp_base: || Ok(std::env::temp_dir()) };
    CurlHttpClient::with_curl(Box::new(server.clone()), curl)
}

const URL: &str = "https://swupdate.openvpn.org/community/releases/OpenVPN-2.6.14-I001-amd64.msi";

#[test]
fn a_pinned_download_is_kept_only_with_the_right_hash() {
    let server = Arc::new(Server { payload: b"payload".to_vec(), calls: Mutex::default() });
    let path = client(&server).download_pinned(URL, &sha256_hex(b"payload"), 1024).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"payload");
    std::fs::remove_file(&path).unwrap();
    let args = &server.calls.lock().unwrap()[0];
    assert!(args.windows(2).any(|w| w == ["--max-filesize", "1024"]));
    let wrong = client(&server).download_pinned(URL, &"0".repeat(64), 1024);
    assert!(matches!(wrong, Err(HttpError::Update(_))));
}

#[test]
fn only_https_is_downloaded() {
    let server = Arc::new(Server { payload: vec![], calls: Mutex::default() });
    let r = client(&server).download_pinned("http://swupdate.openvpn.org/x.msi", &"0".repeat(64), 1024);
    assert!(matches!(r, Err(HttpError::Update(_))));
    assert!(server.calls.lock().unwrap().is_empty());
}
```

(`CurlHttpClient::with_curl(runner, curl)` is the flavour-taking constructor of Task 5; if Task 5 named it differently, use that name. The wrong-hash case must also leave no file behind: the client deletes it before returning.)

Windows (`crates/platform-win/tests/openvpn_install.rs`, over SSH; no UAC there, so only the verification half):

```rust
#![cfg(windows)]

#[test]
fn a_file_with_the_wrong_signer_is_never_run() {
    // git.exe is validly signed, but not by the pinned OpenVPN signer: refused before any elevation.
    let r = macvpn_platform_win::verify_openvpn_msi_for_tests(std::path::Path::new(r"C:\Program Files\Git\cmd\git.exe"));
    assert!(r.unwrap_err().contains("not signed by"));
}
```

- [x] **Step 2: Run them to verify they fail**

Run: `cargo test --locked -p macvpn-platform-win --test pure && cargo test --locked -p macvpn-platform-api --test curl_pinned`
Expected: FAIL to compile.

- [x] **Step 3: Implement**

`pure/openvpn_install.rs`:

```rust
//! Installing OpenVPN Community for WinVPN (2b plan, decision 4: openvpn.exe, DCO, TAP-Windows6): the fixed command lines and the outcome of an
//! exit code. Nothing here runs anything.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Done,
    DoneRestartNeeded,
    Cancelled,
    Failed(u32),
}

pub fn winget_args(update: bool, features: &str) -> Vec<String> {
    let mut a: Vec<String> = [if update { "upgrade" } else { "install" }, "--id", "OpenVPNTechnologies.OpenVPN", "--exact", "--source", "winget", "--scope", "machine", "--silent", "--accept-package-agreements", "--accept-source-agreements", "--disable-interactivity", "--override"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    a.push(format!("/qn /norestart ADDLOCAL={features}"));
    a
}

/// A feature list is `[A-Za-z0-9._,]` only (the pins file; never user input).
fn valid_features(f: &str) -> bool {
    !f.is_empty() && f.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b','))
}

/// `msiexec`'s parameters for `ShellExecuteExW` (one string, which msiexec parses itself): the path must be
/// absolute and free of `"`, so it cannot end the quoting.
pub fn msiexec_parameters(msi: &std::path::Path, features: &str) -> Option<String> {
    let p = msi.to_str()?;
    if !msi.is_absolute() || p.contains('"') || !valid_features(features) {
        return None;
    }
    Some(format!(r#"/i "{p}" /qb! /norestart ADDLOCAL={features}"#))
}

/// msiexec and winget exit codes; 1223 is `ERROR_CANCELLED` (UAC declined).
pub fn outcome(code: u32) -> Outcome {
    match code {
        0 => Outcome::Done,
        3010 => Outcome::DoneRestartNeeded,
        1602 | 1223 => Outcome::Cancelled,
        c => Outcome::Failed(c),
    }
}
```

(The second path is refused because it contains `"`; a relative path is refused too. `cfg!` in a test file is outside the cfg rule.)

`win/elevate.rs`:

```rust
//! Running a System32 program elevated: `ShellExecuteExW` with the `runas` verb (UAC), waiting for it. Only
//! `%SystemRoot%\System32\msiexec.exe` is ever run this way (the updater and the OpenVPN install); the file it
//! reads is held open by the caller with share mode `FILE_SHARE_READ` only.

/// The exit code; `Err(1223)` when UAC was declined.
pub fn run_elevated_system32(program: &str, parameters: &str) -> Result<u32, u32>
```

Implementation: refuse any `program` other than `msiexec.exe`; the path is `GetSystemDirectoryW` + `\msiexec.exe`; `SHELLEXECUTEINFOW { fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI | SEE_MASK_NOASYNC, lpVerb: "runas", lpFile, lpParameters, nShow: SW_SHOWNORMAL }`; `ShellExecuteExW` failing with `ERROR_CANCELLED` → `Err(1223)`; else `WaitForSingleObject(hProcess, INFINITE)`, `GetExitCodeProcess`, `CloseHandle`.

`win/curl_runner.rs`: the Windows `CommandRunner` for the curl layer (also Tasks 18, 19): `std::process::Command::new(exe)` with `.env_clear().env("SystemRoot", sysroot).env("PATH", sysroot\System32)`, `creation_flags(CREATE_NO_WINDOW)`, stdin bytes written on a thread, stdout and stderr read on threads, a timeout (the curl layer's `max_time` + 30 s) after which the child is killed and `CommandError::TimedOut(exe)` returned. `pub fn windows_curl() -> Curl` = `<System32>\curl.exe`, `extra_args: vec!["--ssl-revoke-best-effort"]`, private directories made with `fsx::create_private_dir_all` under `std::env::temp_dir()` + a random suffix from `macvpn_winsys::random::fill`.

`curl/http.rs` (platform-api): `download_pinned(&self, url: &str, sha256: &str, max_bytes: u64) -> Result<PathBuf, HttpError>`: `HttpsUrl::parse(url)` (core's catalog URL type: https only, canonical); follows up to 5 redirects to https targets (`HttpsUrl::redirect_target`); `--max-filesize <max_bytes>`; after the download `sha256_of_file` must equal `sha256` (lower-case hex) — otherwise the file is deleted and `HttpError::Update(UpdateError::ChecksumMismatch)` (use the existing variant name in `UpdateError`); the caller owns the returned file.

`win/openvpn_install.rs` (`SystemSetup::install_tools(report, output)` on Windows calls `install(action, output)` with the OpenVPN row's action: `install`, `repair` or `update`):
1. `output(&tr("Installing OpenVPN Community %@…", OPENVPN_VERSION))`.
2. winget: if `%LOCALAPPDATA%\Microsoft\WindowsApps\winget.exe` exists (`SHGetKnownFolderPath(FOLDERID_LocalAppData)`, never `PATH`), run it with `winget_args(update, OPENVPN_FEATURES)` as the user (`CREATE_NO_WINDOW`, output lines streamed to `output`); `outcome(code)` Done / DoneRestartNeeded → step 4; Cancelled → `Err(tr("Cancelled"))`; Failed → `output(tr("winget could not install OpenVPN (%@); trying the official installer.", code))`, go on. After a winget success, ask the service again (`ServiceClient::reach`): if DCO or TAP-Windows6 is still missing, `output(tr("winget did not install every OpenVPN driver; adding them with the official installer."))` and go on with step 3. For `repair`, winget is used only when the installed version differs from the pinned one (`upgrade`); with the same version step 3 adds the features directly (a maintenance install); with another version and no winget: `Err(tr("Add the DCO and TAP-Windows6 drivers in Settings → Apps → Installed apps → OpenVPN → Modify."))`.
3. The pinned MSI: `download_pinned(OPENVPN_MSI_<ARCH>_URL, OPENVPN_MSI_<ARCH>_SHA256, 64 MiB)` into `%LOCALAPPDATA%\WinVPN\downloads\` (private); `trust::verify_signature` → signer must equal `OPENVPN_SIGNER` (else delete and `Err(tr("The OpenVPN installer is not signed by %@.", signer))`); open it with share mode `FILE_SHARE_READ` only and keep the handle until msiexec ends; `run_elevated_system32("msiexec.exe", &msiexec_parameters(path, OPENVPN_FEATURES)?)`; map the outcome; delete the MSI.
4. The Interactive Service (decision 4, amended 2026-10-22), only when OpenVPN was absent before this install or `HKLM\SOFTWARE\WinVPN\OpenVpnInstalledByWinVpn` is 1: in the elevated step (one UAC confirmation where the path allows it; never a shell, the service opened by its pinned name `OPENVPN_INTERACTIVE_SERVICE`) `ChangeServiceConfigW(SERVICE_DISABLED)`, `ControlService(SERVICE_CONTROL_STOP)` and wait for `SERVICE_STOPPED` (at most 30 s), write the marker value, then check with `QueryServiceConfigW` / `QueryServiceStatus`; a failed check → `output(tr("OpenVPN's Interactive Service could not be disabled."))` (EN+HU) and the install still counts as done (WinVPN works with it running). On an installation WinVPN did not make, nothing is touched (a unit test pins the decision: `disable_interactive(absent_before, marker)`). Then `output(tr("OpenVPN Community is installed."))` (+ "Restart Windows to finish." for 3010); the app checks the system again (the existing "check after install" flow of `install_tools`).

`#[doc(hidden)] pub fn verify_openvpn_msi_for_tests(path) -> Result<(), String>` runs only step 3's signer check.

`strings.json` (scope `core`, `"only": ["windows"]`): "winget did not install every OpenVPN driver; adding them with the official installer." → "A winget nem telepítette az összes OpenVPN-illesztőprogramot; a hivatalos telepítővel pótolom."; "Add the DCO and TAP-Windows6 drivers in Settings → Apps → Installed apps → OpenVPN → Modify." → "Add hozzá a DCO és a TAP-Windows6 illesztőprogramot: Gépház → Alkalmazások → Telepített alkalmazások → OpenVPN → Módosítás."; "Installing OpenVPN Community %@…" → "Az OpenVPN Community %@ telepítése…"; "winget could not install OpenVPN (%@); trying the official installer." → "A winget nem tudta telepíteni az OpenVPN-t (%@); a hivatalos telepítővel próbálom."; "The OpenVPN installer is not signed by %@." → "Az OpenVPN telepítőjét nem a(z) %@ írta alá."; "OpenVPN Community is installed." → "Az OpenVPN Community telepítve."; "Restart Windows to finish." → "A befejezéshez indítsd újra a Windowst."; "Cancelled" (if absent) → "Megszakítva".

- [x] **Step 4: Run**

Run: `CI=1 cargo test --workspace --locked && scripts/check-windows.sh && scripts/win-remote.sh run 'cargo test --locked -p macvpn-platform-win --test openvpn_install --test pure' && scripts/win-remote.sh test`
Expected: PASS. The elevated half is CP2's item.

- [x] **Step 5: Commit**

```bash
git add crates/platform-api crates/platform-win crates/core/l10n/strings.json
git commit -m "feat(platform-win): install and update OpenVPN Community from System Status" -m "winget first (machine scope, openvpn.exe + DCO + TAP-Windows6 through --override, checked afterwards), else the pinned MSI after its SHA-256 and Authenticode signer matched, run by msiexec elevated through UAC with the file held deny-write; exit codes mapped; output streamed into System Status. The service's own trust check of openvpn.exe stays the gate for using it." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**As built (Task 17):** the plan's API with these changes. **One elevated step, not msiexec elevated directly.** Decision 4 wants the Interactive Service disabled "in the same elevated step as the install where possible (one UAC confirmation)", which msiexec alone cannot do. So the elevated program is the installed `WinVPN.exe` itself: `WinVPN.exe --winvpn-openvpn-step msi "<msi>" absent|present` (or `interactive absent|present` after winget), dispatched first thing in `main` (`platform::helper_mode()` → `macvpn_platform_win::openvpn_elevated_step`, before the instance check or any window; macOS returns `None`). The app starts it with `ShellExecuteExW(runas)` (`win/elevate.rs::run_elevated`, COM initialised on the worker thread, `SEE_MASK_NOCLOSEPROCESS | FLAG_NO_UI | NOASYNC`) **only when `acl_check::is_admin_only(current_exe)`** (an installed WinVPN in Program Files; else "Only a WinVPN installed in Program Files can install OpenVPN Community.": a development build cannot elevate itself). The elevated process trusts nothing from the app: it re-opens the MSI deny-write (`FILE_SHARE_READ` only), re-checks its SHA-256 (read through that handle) and signer against the compiled pins, builds `msiexec_parameters` from the pinned features, runs `<System32>\msiexec.exe` (`FOLDERID_System`, `raw_arg`), then — when `disable_interactive(absent_before || no exe_path before msiexec, marker)` — `scm::disable_and_stop(OPENVPN_INTERACTIVE_SERVICE, 30 s)` (`ChangeServiceConfigW(SERVICE_DISABLED)`, `ControlService(STOP)`, polling `QueryServiceStatus`), `scm::query` (`QueryServiceConfigW` + `QueryServiceStatus`: disabled and stopped) and writes `HKLM\SOFTWARE\WinVPN` `OpenVpnInstalledByWinVpn` = 1 (REG_DWORD). Its result is the exit code (`pure::openvpn_install::StepResult::{code, from_code}`: bit 29 = the application bit, so a step code is never a system or msiexec code; msiexec's code in bits 0–15 + bit 16, the Interactive Service in 17–18 — untouched / disabled / not disabled / marker not written —, the step's own error in 20–21 — arguments / not verified / no msiexec). The winget path needs a second UAC prompt for the `interactive` step (winget elevates only its own installer), and only on an installation WinVPN made; a declined prompt there is the "could not be disabled" line, the install still counts. `absent_before` = no `HKLM\SOFTWARE\OpenVPN` `exe_path` before anything ran (passed to the step, because winget may have installed OpenVPN before the MSI fallback). The plan's `run_elevated_system32` does not exist (unused here; Task 18 adds its msiexec call itself). **Pure** (`pure/openvpn_install.rs`): also `Action::parse`, `first_step(action, installed, pinned, has_winget) -> First { Winget{update}, Msi, Refuse(text) }` (repair of the pinned version = maintenance install of the pinned MSI even with winget; repair of another version = winget `upgrade`, else the Settings text), `drivers_complete`, `pinned_msi(ARCH)` (one feature list per architecture, Task 10), `msi_file_name`, `code_text` (winget's HRESULTs in hex), `winget_line` (spinner/progress dropped), `after_step` (texts), `step_parameters`/`parse_step`. `msiexec_parameters` also refuses a path ending in `\` (it would escape the closing quote) and control characters. **Download** (`CurlHttpClient::download_pinned`): the pin must be 64 lower-case hex before any request; redirects through `HttpsUrl::redirect_target` (any `https` host: the content is pinned; `swupdate.openvpn.org` → `.net`), at most 5 (`PINNED_MAX_REDIRECTS`), a non-https target ends the chain with its 3xx = `UpdateError::Http(3xx)`; non-200 = `Http(status)`; mismatch = `ChecksumMismatch` with the file deleted (it never leaves the private directory); `request` got a `limits` argument (`--max-filesize`, only for this call: the macOS argv golden test is unchanged). The MSI lands in `%LOCALAPPDATA%\WinVPN\downloads\OpenVPN-2.7.8-I001-<arch>.msi` (`fsx::ensure_private_dir`) and is deleted after the step. **curl runner** (`win/curl_runner.rs`): as planned; the time limit is the argv's `--max-time` + 30 s (60 s without one); `SystemRoot` = `FOLDERID_Windows`, `PATH` = `FOLDERID_System` (new `system::{system32, windows_dir}`); private directories with `winsys::file::create_dir(…, Private)` (new only). **App:** `setup_install_tools` (`system.rs`) required Homebrew; it now accepts the OpenVPN row's action instead when the engine rows exist (macOS unchanged); `install_tools` writes the failure as the last output line too (the app ignores the `Err`), and the sandbox runs nothing. **winsys:** `scm::{query, disable_and_stop, ServiceState, START_DISABLED, STATE_STOPPED}`; platform-win `registry::{read_machine_string, read_machine_dword, write_machine_dword}` (64-bit view). **Strings** (core, `only: windows`, one block): the plan's eight plus "OpenVPN's Interactive Service could not be disabled.", "The OpenVPN installer could not be downloaded: %@", "The OpenVPN installer failed (%@).", "The OpenVPN installer could not be started.", "Only a WinVPN installed in Program Files can install OpenVPN Community.", "WinVPN could not record that it installed OpenVPN Community.". **Tests:** `curl_pinned.rs` 5 (Mac), `pure.rs` +12 (Mac and Windows), `openvpn_install.rs` 3 (Windows, standard user: wrong signer / unsigned / missing refused; no step argument = normal start; the elevated step refuses bad arguments, a signed non-OpenVPN file and a missing file before msiexec), curl runner unit tests 2, `winsys.rs` +1 (`scm::query` of EventLog; a nonexistent `WinVPN-test-…` service for the errors — never a real service, as CI runs as administrator). No ignored test: the elevated half changes the machine's OpenVPN and is CP2's. **Results:** Mac: `cargo fmt --check`, clippy `-D warnings` (platform-api, platform-win, winsys, app), platform-api and platform-win tests, app tests, `l10n_coverage`, core `l10n`, `cfg_rule`, `l10n-baseline --check`, the UI `l10n.test.ts` green; Windows (standard user, slot1): clippy `-D warnings` for winsys, platform-win, platform-api and the app; platform-win lib 6/6, `openvpn_install` 3/3, `pure` 33/33, winsys `winsys` 19/19.
**Needs the maintainer (CP2, Windows 11 VM, WinVPN MSI of this wave installed):** (1) Without OpenVPN (uninstall CP1's hand install first): System Status → OpenVPN "Install" → winget path (winget present): its own UAC prompt, output lines stream, then a second UAC prompt for "WinVPN" (the Interactive Service step); afterwards `sc qc OpenVPNServiceInteractive` START_TYPE 4 DISABLED, `sc query` STOPPED, `reg query HKLM\SOFTWARE\WinVPN /v OpenVpnInstalledByWinVpn` 0x1, the row green with DCO and TAP-Windows6, no OpenVPN GUI installed (`ADDLOCAL`). (2) The MSI path: uninstall OpenVPN, temporarily make winget unavailable for the user (or test on a machine without App Installer), "Install" → **one** UAC prompt (WinVPN), msiexec's progress window, the same checks as (1). (3) Decline the UAC prompt → "Cancelled", nothing installed. (4) Repair: remove the TAP-Windows6 feature (Settings → Apps → OpenVPN → Modify) → row "Repair" → the pinned MSI adds it; the Interactive Service is disabled again (marker set). (5) A hand-installed OpenVPN (marker deleted: `reg delete HKLM\SOFTWARE\WinVPN /v OpenVpnInstalledByWinVpn`, OpenVPN installed by hand with the GUI): "Repair"/"Update" never touches `OpenVPNServiceInteractive` (stays AUTO_START, RUNNING). (6) Development build (not in Program Files) → "Only a WinVPN installed in Program Files…" and no prompt.

**As built (fix3, 2026-10-24; decision 4 as amended 2026-10-24):** **Update check.** `WinPlatform::check` asks `engine::update_check_for(&reach)` for the installed version, which is `Some` only when the OpenVPN row would be green (service of this version and not degraded, no OpenVPN problem, both drivers): a "Repair" row and a refused installation never get a check, so "Repair" (and the service's own "Update" for a version below `min_version`) take precedence. Then `win::openvpn_install::upgrade(installed, ask_winget)`: with winget (`%LOCALAPPDATA%\Microsoft\WindowsApps\winget.exe`) it runs `winget list --id OpenVPNTechnologies.OpenVPN --exact --source winget --upgrade-available --disable-interactivity --accept-source-agreements` (read-only; no window, stdin null, stderr discarded, at most 64 KiB of stdout, killed after 30 s → `Unknown`), parsed by `pure::openvpn_install::parse_winget_check(code, output, installed) -> Upgrade { Unknown, None, Available { shown, version, via: Via::Winget } }` (without winget: `None`; not asked: `Unknown`). **The newest of winget and the pin** (`choose_update(&winget, installed, OPENVPN_VERSION)`): the pin (`via: Via::Msi`) when it is newer than the installed version and winget offers nothing at least as new (nothing, no answer, an older offer or a rebuilt installer of the installed version); winget's offer when it is at least the pin's version (a tie goes to winget); with the installed version at or above the pin, winget's answer stands (the pin is never offered as a downgrade). On the CP2 machine (winget's newest 2.7.7 installed, pin 2.7.8) the row offers "2.7.7 → 2.7.8" through the pinned MSI. **The pinned MSI upgrades winget's installation:** winget installs the same official MSI; read on the VM (`scripts/msi-query.ps1` on the pinned 2.7.8-I001 amd64 MSI, SHA-256 checked, deleted afterwards; installed products through `WindowsInstaller.Installer.RelatedProducts`): `UpgradeCode` `{461BDF86-D389-4471-BF36-99806B64C127}`, `ProductVersion` 2.7.801; Upgrade table `(that code, VersionMin –, VersionMax 2.7.801, Attributes 1 = migrate features, WIX_UPGRADE_DETECTED)` and `(that code, VersionMin 2.7.801, –, Attributes 2 = only detect, WIX_DOWNGRADE_DETECTED)`; `FindRelatedProducts` 25, `RemoveExistingProducts` 6501 (WiX `MajorUpgrade`); the installed winget OpenVPN 2.7.7 is product `{94991384-92E2-41D4-B467-B45C47C31CD3}`, version 2.7.701, per-machine, related to that `UpgradeCode`: so the pinned MSI major-upgrades it, and refuses to downgrade a newer one. `ask_winget` is false for the first check of the process (the launch's: `LaunchStep::CheckSetup` runs before polling starts and must not wait for winget) and in the sandbox; System Status' appearance, "Check Again" and the check after an install ask. `Unknown` is never an error row: the row stays green without an action. **What winget prints** (captured on the VM, winget 1.29.380, OpenVPN 2.7.7 installed by winget; the machine's UI culture is hu-HU but winget prints English): no upgrade = exit 0 and the single line "No installed package found matching input criteria." (`winget list --id <unknown> --exact` without `--upgrade-available` exits `0x8A150014`, accepted the same way); an upgrade = a header line, a line of dashes and one row per package, `Name Id Version Available` (a `Source` column only without `--source`); `winget upgrade --id … --exact` with nothing newer exits `0x8A15002B` (not used: `upgrade` without a check would install). The header words, messages and package names are localized and the columns aligned by width, so the parser reads only the exit code (0 or `0x8A150014`, anything else `Unknown`) and the row whose whitespace tokens contain `OpenVPNTechnologies.OpenVPN` exactly: the token two after the ID is the available version; no such row and no table → `None`; a table without the row (truncated, another package's) or a row without a readable version → `Unknown`. **Versions:** winget lists OpenVPN's MSI `ProductVersion`, `major.minor.(patch·100 + installer build)` (`winget show --versions`: `2.7.701`, `2.7.017`, `2.6.2302`), so `openvpn_version_of_winget` divides a three-or-more-digit third part by 100 (`2.7.801` → 2.7.8); when that is not newer than the installed version (a rebuilt installer) winget's own version is shown. **The row:** green, usable, detail + " Update available: <installed> → <new>" (`texts::update_available`), action `update`; `report(reach, recommended_openvpn, &upgrade)` no longer offers "Update" on a green row from the pin alone. **Update** asks the same question again when it runs (`upgrade(installed, true)`: the row may be older than winget's answer) and starts with `update_first(&choice, has_winget)`: an offer `via: Msi` → Task 17's MSI path (one UAC prompt; the elevated step re-checks the MSI, runs msiexec and, with the marker set, disables the Interactive Service again); else winget's `upgrade` with the same `--override` ADDLOCAL, then the `interactive` elevated step only on WinVPN's installation (marker or absent before); without winget the pinned MSI. Install and Repair keep `first_step`. The app checks again afterwards (`setup_install_tools`). **Changes on that path:** the winget path's first line is "Installing the newest OpenVPN Community with winget…" (the pinned version is named only when the MSI runs); the MSI fallback after a failed winget or missing drivers runs only when `msi_fallback_allowed(installed, pin)` (not installed, or not newer than the pin: the pinned MSI never downgrades winget's newer OpenVPN), else the failure ("The OpenVPN installer failed (code)") or the Settings text for the drivers. **Strings** (core, `only: windows`): "Update available: %@ → %@" (Frissítés elérhető: %@ → %@), "Installing the newest OpenVPN Community with winget…". **Tests** (`tests/pure.rs`, every OS): the check's argv (read-only, no version on the install argv), the winget→OpenVPN version mapping, the parser on the captured outputs (no upgrade; the captured multi-package table with OpenVPN's row added; a `Source` column; a German table, constructed; a rebuilt installer; truncated and garbled rows, other exit codes → `Unknown`), `choose_update` (winget none/unknown + newer pin → pin; winget = pin → winget; winget newer than the pin → winget; winget older → pin; installed ≥ pin and winget none → none), `update_first`, `msi_fallback_allowed`, the row (green + update, `None`/`Unknown`, repair precedence, refused, no check without a green row); `service_client.rs` passes `Upgrade::Unknown`.

**As built (fix4, 2026-10-24; decisions 4 and 6 as amended 2026-10-24): engine updates at runtime, without a WinVPN release.**

*Upstream sources (researched 2026-10-24).* **wireguard-nt:** `https://download.wireguard.com/wireguard-nt/` is an HTML page linking only the newest SDK zip (`<a href="wireguard-nt-1.1.zip">`; older zips stay downloadable by name, e.g. `wireguard-nt-0.10.1.zip`; the tags are listed at `https://git.zx2c4.com/wireguard-nt/refs/`). There is no `LATEST` file, no manifest and no signature for the zips: `wireguard-nt-1.1.zip.{sig,asc,minisig}`, `SHA256SUMS`, `sha256sums.txt`, `latest.sig`, `list.sig` all 404. The only signify-signed file of the site is `https://download.wireguard.com/windows-client/latest.sig` ("verify with wireguard-windows-release.pub"), which lists the WireGuard for Windows **MSIs** only (1.1.1 on that day), not the SDK. So the newest version is the highest `href="wireguard-nt-<v>.zip"` on the listing, and the trust is the DLL's Authenticode signature. **OpenVPN Community:** GitHub `OpenVPN/openvpn` releases carry only the source tarball (`v2.7.8`: `openvpn-2.7.8.tar.gz` + `.asc`), `OpenVPN/openvpn-build` has no GitHub releases (404), `swupdate.openvpn.org/community/releases/` has no listing (301 behind Cloudflare). The official page `https://openvpn.net/community-downloads/` (301 → `https://openvpn.net/community/`, fetched fine with curl and WinVPN's user agent) links the newest MSIs, `https://swupdate.openvpn.org/community/releases/OpenVPN-2.7.8-I002-{amd64,arm64,x86}.msi` + `.asc` on that day (the pin is I001; `swupdate.openvpn.org` redirects to `.net`). The `.asc` files are RSA-4096/SHA-256 signatures by subkey `822F6DF096D04874` of the security key `F554A3687412CFFEBDEFE0A312F5F7B42F2B01E7` (the pins file's key). **GnuPG is not checked at runtime:** the workspace has no OpenPGP or RSA code (Cargo.lock: ed25519 only) and writing RSA/OpenPGP verification by hand was judged worse than none; the runtime MSI is trusted on HTTPS from OpenVPN's hosts and its Authenticode signer `OpenVPN Inc.` (Authenticode-only, as the task allowed). Captured samples: `crates/helper/tests/fixtures/wireguard-nt-listing-2026-10-24.html` (the listing as it is), `crates/platform-win/tests/fixtures/openvpn-community-2026-10-24-excerpt.html` (the page's parts around its MSI links, as they are).

*wireguard-nt: who, where, how.* **The service** (SYSTEM) does everything; the app only sends `wireguard-check` or `wireguard-update` (no argument, no body is used; another argument is the usage error). `crates/helper/src/windows/wg_update.rs` (pure, every OS): `NtVersion` (1–4 numeric parts, missing = 0, so `1.1` = the DLL's 1.1.0.0), `parse_listing` (only `href="wireguard-nt-<digits and dots>.zip"`; the highest), `zip_url` (built from the parsed version only), `dll_member` (`wireguard-nt/bin/amd64/wireguard.dll` / `arm64`), `pe_dll_machine` (MZ → PE, `IMAGE_FILE_DLL`, machine), `matches_listed`, `use_downloaded`, `is_newer`, the curl argv (`-q --globoff --silent --show-error --proto =https --tlsv1.2 --max-redirs 0 --ssl-revoke-best-effort --connect-timeout 30 --max-time --max-filesize --user-agent WinVPN-Service/<v> --write-out %{http_code} --output <file> -- <url>`), the check cache (60 s), and the **zip reader**: the end-of-central-directory record, the central directory, one member by its exact name (never a path: no traversal possible), refusing a multi-disk/ZIP64 archive, a duplicate name, encryption, a method other than stored/deflate, a local header that names another file or other sizes, a member above 8 MiB, data that overlaps the central directory, and a CRC-32 or size mismatch after inflating (raw deflate by `miniz_oxide` 0.9.1, already in Cargo.lock through flate2/png and `#![forbid(unsafe_code)]`: a Windows dependency of the helper plus a dev-dependency for the zip tests; no new crate). `sys/fetch.rs`: the service's own curl runner (the helper cannot use platform-api's curl layer: that crate brings core's `vault`, which the service must not link): `<FOLDERID_System>\curl.exe`, environment `SystemRoot` + `PATH=<System32>` only, `CREATE_NO_WINDOW`, stdin null, the argv's `--max-time` + 30 s then killed, exit 0 and HTTP 200 required; it runs in the service's job object. Only the service's fixed URLs are fetched. `winsys::known::{system32, windows_dir}` (new; `known` generalised). `sys/data_dir.rs`: `DataDir::{engine_dir, is_own_file, write_engine_file}` (`engines\wireguard-nt`, created and checked at **every** call like the data directory: a real directory, owner SYSTEM/Administrators (the console: its user), exactly the protected admin-only DACL, no reparse point; a file of the service's own: no reparse point, owner, exactly that DACL — curl's output, which inherits, is never loaded). **An update** (`WireGuardEngine::update`): one at a time (a second is "busy"); refused "busy" (exit 3) while the service records any WireGuard connection (any user's) and again under the engine; the listing → `listing.html` (≤ 256 KiB, 30 s), read deny-write without following a reparse point, deleted; nothing above every version the service has (bundled pin, download, loaded) → "No newer wireguard-nt is available."; the zip → `download.zip` (≤ 32 MiB, 120 s), read, deleted; the member → `wireguard.new` (`create_new` with the admin-only DACL); `wgdll::inspect(Trust::Downloaded { above: the highest version it has })` and the file version must match the listed one, else deleted ("did not pass its checks"); then the **swap**: `GATE.try_write()` (every `up` holds `GATE` for reading from before it takes the DLL until its adapter is recorded) and no run → the DLL state cleared (no adapter exists, so the last `Arc<WgDll>` unloads it), `wireguard.new` renamed over `wireguard.dll`, `load_best` again; the loaded version must be the new one, else "The new wireguard-nt could not be loaded; WinVPN keeps using wireguard-nt <v>." (what was loaded before, or the bundled DLL, is loaded again). Every temporary file is deleted on every path; leftovers of an interrupted update and a download that is not above the bundled DLL (after a WinVPN update brought a newer one) are deleted at engine start. **Loading** (`load_best`, at engine start and after an update; `wgdll::load(path, Trust)`): the download only when its file version is above the bundled pin's, and then with `Trust::Downloaded`; a refused download is logged and the bundled DLL loaded (`Trust::Bundled`: admin-only install folder + the pinned SHA-256, as before). **Both** now also need: a plain file ≤ 8 MiB held open deny-write (`FILE_SHARE_READ`, `FILE_FLAG_OPEN_REPARSE_POINT`) from before it is read until it is mapped; a PE DLL for this machine; `trust::verify_signature` Valid with signer `WireGuard LLC` (the pin file's `signer`) — **at every load**. The DLL state is `Mutex<Option<Result<Arc<WgDll>, String>>>` (was a `OnceLock`); an `Adapter` holds its `Arc<WgDll>`. `engine` still reports `dllVersion` (the loaded DLL's file version).

*Protocol.* `service_proto::{WIREGUARD_CHECK = "wireguard-check", WIREGUARD_UPDATE = "wireguard-update", UPDATE_BUSY = 3, EngineUpdate { installed, available }}` (JSON, `deny_unknown_fields`, versions only digits and dots, ≤ 32 bytes). Check: exit 0 + `EngineUpdate` (answers reused 60 s), exit 1 + the reason. Update: exit 0 + `EngineUpdate { installed: <now loaded>, available: null }`, exit 3 + the reason when busy, exit 1 + the reason. `Engine::{update_check, update}` (defaults: "Not available on this system yet"), `service::UpdateRefusal::{Busy, Failed}`, `service::wireguard_busy()`. **`SERVICE_VERSION` stays 1:** `EngineFacts` is unchanged, the commands are new and an older service answers them with the usage error (exit 2), which the app reads as "unknown"; app and service still come from one MSI.

*OpenVPN.* `pure::openvpn_install`: `OFFICIAL_PAGE`, `OFFICIAL_PAGE_HOSTS` (`openvpn.net`), `OFFICIAL_MSI_HOSTS` (`swupdate.openvpn.org`, `swupdate.openvpn.net`), `parse_msi_name` (`OpenVPN-<x.y.z>-I<1–4 digits>-<amd64|arm64>.msi` exactly), `parse_official_page` (only `https://swupdate.openvpn.org/community/releases/<that name>` ended by a non-name character, so `.msi.asc` does not count; the highest version, then build), `pinned_official`, `pick_msi` (the official MSI only for a newer OpenVPN than the pin; the pin's own version keeps the hash-pinned MSI), `official_msi_name_ok`, `Step::OfficialMsi` (`--winvpn-openvpn-step msi-official "<path>" absent|present`). `curl::http::CurlHttpClient::{download_from, get_from}` (platform-api, new; `download_pinned` shares the hop loop `https_chain`): HTTPS only, at most 5 redirects, every hop on the given hosts at port 443, `--max-filesize`, status 200, else the file is deleted (the macOS argv golden test is unchanged). `win::openvpn_install`: `upgrade` asks winget and the page side by side (30 s each; no page = the pin), `choose_update` gets the newest official MSI's version instead of the pin's; "Install"/"Update"/"Repair" pick the MSI with `pick_msi` (a repair of the pin's version: the pinned MSI); the official MSI is downloaded from OpenVPN's hosts, opened deny-write, its name and signer checked, and the elevated step checks name and signer again before msiexec (`open_official`). Discovery failure = the pin, never an error row; never a downgrade (`msi_fallback_allowed` and `choose_update` against the newest official version).

*System Status.* `pure::wireguard_update::{Offer, check_for, offer_from, update_outcome, CHECK_SECS 45, UPDATE_SECS 240}`; `ServiceClient::{wireguard_check, wireguard_update}`; `engine::report(…, &Offer)`: a green WireGuard row with an offer reads "wireguard-nt 1.1.0 Update available: 1.1.0 → 1.2.0" (the existing "Update available: %@ → %@") with action `update`. `WinPlatform::check` asks the service (only a green row; not at launch, not in the sandbox, as fix3's winget question) next to the OpenVPN question; "Update" on the WireGuard row: `setup_install_tools` takes `engine: "wireguard"` (the app clears the OpenVPN action of its copy of the report), `install_tools` writes "Updating wireguard-nt…" and the service's answer ("wireguard-nt %@ is installed." or its reason, e.g. busy) into the output box under that row; the rows are checked again afterwards. View model: `EngineRowsView.wireguardAction` (absent when none; macOS JSON unchanged), `canInstallTools` also for it; UI: the WireGuard row's "Update" button, the output box under the row whose button ran (`Setup.svelte`, `api.setupInstallTools(engine?)`). **Strings** (EN + HU, `only: windows`): `mvpn`: the busy text, "wireguard-nt could not be checked for updates.", "The newest wireguard-nt could not be downloaded.", "The downloaded wireguard-nt did not pass its checks (signer WireGuard LLC, version, processor); nothing was changed.", "An update of wireguard-nt is already running.", "No newer wireguard-nt is available.", "The new wireguard-nt could not be loaded; WinVPN keeps using wireguard-nt %@."; `core`: "Updating wireguard-nt…", "wireguard-nt %@ is installed.". `build-msi.sh`'s release gate also refuses `--wireguard-updates` and `--wireguard-floor` (debug-console options) in the service exe.

*Threat notes for Task 24.* (1) **Trust of a downloaded `wireguard.dll`** rests on Authenticode only (Valid chain to a root in the machine's store, signer simple name `WireGuard LLC`, revocation not checked online as for every WinVPN signature check): a CA mis-issuing a code-signing certificate named "WireGuard LLC", or a stolen WireGuard LLC key, would let a DLL through that a release pin would have stopped; the maintainer accepted this (decision 6 as amended). The DLL loads into the SYSTEM service and installs/loads the wireguard-nt kernel driver (which Windows itself requires to be Microsoft-signed for the kernel). (2) **No path from user input:** the app can only say "check"/"update"; URLs are constants plus a version parsed to digits and dots; the zip member is a constant name; files are fixed names in a directory created and checked (owner, exact protected admin-only DACL, no reparse point) at every call; temporary files are created new, read deny-write without following reparse points, deleted on every path; curl runs from System32 with a bare environment, HTTPS-only, no redirects, size and time caps, inside the service's job. (3) **Downgrade/rollback:** only a version above every version the service has is downloaded, kept and loaded (a listing that names an older or equal version updates nothing; a zip whose DLL is not the listed version is refused); an attacker on the network cannot downgrade (TLS + signer + version); a local administrator can (out of scope: admins can replace Program Files too). (4) **Swap race:** the DLL is replaced only under `GATE`'s write lock with no run recorded; `up` holds the read lock from before it takes the DLL until its adapter is recorded, and every adapter holds its DLL, so a mapped DLL is never replaced (a failed rename keeps the old file and is reported). (5) **TOCTOU:** the file is held deny-write from before its bytes are checked until `LoadLibraryExW` mapped it (the signer check reads the same, unchangeable file). (6) **Denial of service:** any interactive user can make the service fetch (one update at a time; checks cached 60 s; 30 s/120 s caps; ≤ 32 MiB); an update cannot run while another user's WireGuard connection is up (busy), so no user can pull the driver from under another's tunnel. (7) **Parsing:** the listing and the zip are parsed by bounded pure code (tested with refusal cases); `miniz_oxide` inflates with an output limit. (8) **OpenVPN's runtime MSI** is trusted on HTTPS from OpenVPN's hosts and the Authenticode signer `OpenVPN Inc.`, checked by the app and again by the elevated step (with the official name and "not older than the pin"); the GnuPG `.asc` is not checked; msiexec's own Upgrade table refuses a downgrade of an installed OpenVPN Community; the service's own trust check of `openvpn.exe` (signer, admin-only path, `min_version`) is still the gate for using it. Same-user malware could already ask for UAC elevation of anything; the elevated step adds no new elevation path.

*Tests.* Every OS: `crates/helper/tests/wg_update.rs` 9 (the captured listing; numeric versions; refusal of odd links; downloaded vs bundled; stored and deflated members; missing, duplicate, traversal-named, oversized, encrypted, unsupported-method, inconsistent-local-header, corrupt, truncated, multi-disk and out-of-bounds zips; CRC-32; PE machine; the curl argv; the cache), `service_core.rs` +2 (check/update dispatch, extra arguments refused, busy while any user's WireGuard connection is recorded and the engine not asked, the engine's busy/failed exits, a degraded service updates nothing), core `service_proto.rs` +1, platform-win `pure.rs` +5 (the WireGuard row and its check gate, the service's answers, the captured OpenVPN page per architecture and refusal of other hosts/`.asc`/odd names, `pick_msi`, the official step's name rule and arguments), platform-api `curl_pinned.rs` unchanged and green, app-core `system_status.rs` (the WireGuard action and its JSON key). Windows (standard user, VM): helper lib (`wgdll`: a real 1.1 DLL as a download above 1.0 loads, not above 1.1; a tampered copy fails Authenticode; Microsoft's `version.dll` fails the signer; WireGuard LLC's arm64 and x86 DLLs fail the machine check; the pinned SDK zip yields the pinned DLL; `data_dir`: engine directories, own files, a junction refused), `wireguard_update.rs` 4 (through the console, offline with `--wireguard-updates <fixtures>`: the console never goes online; the bundled version is the newest; a zip whose DLL is not the listed version, a non-zip and a missing zip are refused and leave nothing; with `--wireguard-floor 1.0` and no bundled DLL the real signed 1.1 DLL is downloaded, checked, kept alone in `engines\wireguard-nt`, loaded, and loaded again by a new console over the same data directory), `service_pipe.rs` unchanged and green, winsys `winsys.rs` (System32/Windows known folders), platform-win lib, `pure`, `service_client` +1 (unknown/failed answers of a service without updates, no service), `openvpn_install` +1 (the elevated step refuses a signed non-OpenVPN file under an official name, another name and a missing file in `msi-official` mode). Mac: fmt, clippy `-D warnings` (helper, core, platform-api, platform-win, app-core, app), the touched crates' tests, `MVPN_IMPL=rust scripts/test-root.sh` 412/412, `check-l10n.sh`, `cfg_rule`, `check-ignored.sh`, notices (macOS and Windows), the two macOS `cargo tree` checks (no `miniz_oxide`/`windows*` in the macOS helper), UI `npm test` and `npm run build`; Windows: `clippy --all-targets -D warnings` for helper, winsys, platform-win, platform-api, app-core, core (the app crate's Windows clippy is left to the wave gate: the VM's disk was too full; its only change compiles and passes clippy on macOS).

*Needs the maintainer (MSI of the merged tip installed, Windows 11 VM):* (1) System Status opens → after a few seconds the WireGuard row stays "wireguard-nt 1.1.0" (1.1 is the newest on 2026-10-24) and the OpenVPN row shows winget's or the official page's offer as before (2.7.8-I002 is not offered: same OpenVPN version). (2) Simulate a newer wireguard-nt is not possible with real files; check instead, elevated: `C:\ProgramData\WinVPN\engines\wireguard-nt` exists after System Status opened, owner SYSTEM, `icacls` shows only SYSTEM and Administrators (protected), and it is empty (the check deleted its listing); `service.log` has no "wireguard-nt check:" line (a line means the check failed: no network?). (3) With network off: System Status shows no error row and no "Update"; the service log has one "wireguard-nt check: the listing: …" line. (4) When wireguard-nt publishes a newer SDK (or by hand: none needed now): "Update" on the WireGuard row with a WireGuard connection up → the output says it can be updated only while no WireGuard connection is up; disconnected → "wireguard-nt <v> is installed.", the row shows `<v>`, `engines\wireguard-nt\wireguard.dll` is signed by WireGuard LLC (`Get-AuthenticodeSignature`), a WireGuard connection works, `sc stop WinVPN` + `sc start WinVPN` → the row still shows `<v>` and `service.log` says "wireguard.dll <v> loaded (downloaded)". (5) OpenVPN, without winget (or with winget's offer older): when OpenVPN publishes a version above the pin, "Update" downloads `OpenVPN-<new>-I<nnn>-amd64.msi` into `%LOCALAPPDATA%\WinVPN\downloads`, one UAC prompt, msiexec installs it, the row is green with the new version afterwards.

## Task 18: the Windows updater

**Goal:** WinVPN offers, downloads, verifies (`.sha256`, then `verify_trusted_for(WinVpnV1, asset, …)`) and installs a newer WinVPN MSI with an elevated `msiexec`, quits, and comes back after the upgrade; launch housekeeping reports the result and cleans up.

**Files:**
- Create: `crates/platform-win/src/pure/update.rs` (asset selection, the update source constants, the relaunch arguments, the notice file format), `crates/platform-win/src/win/updater.rs`, `crates/platform-win/tests/update.rs` (every OS: the pure parts with throwaway keys)
- Modify: `scripts/build-msi.sh` (one more forbidden string), `crates/platform-win/src/win/platform.rs` (`updater()`, `release_source()`, `update_info`, `cache_directory`), `app/src-tauri/src/main.rs` (the `--relaunch-after` mode before anything else), `app/src-tauri/src/platform/windows.rs` (`relaunch_mode()`), `crates/core/l10n/strings.json`

- [x] **Step 1: Write the failing tests** (`crates/platform-win/tests/update.rs`)

```rust
use macvpn_core::update::{Release, ReleaseAsset, UpdateSignature};
use macvpn_platform_win::pure::update::{self as up, Verified};

fn asset(name: &str) -> ReleaseAsset {
    ReleaseAsset { name: name.into(), url: format!("https://github.com/SepsiG/MacVPN/releases/download/v1.6.0/{name}") }
}

#[test]
fn the_assets_of_this_architecture_are_chosen() {
    let release = Release {
        version: "1.6.0".into(),
        assets: vec![
            asset("MacVPN-1.6.0.dmg"),
            asset("WinVPN-1.6.0-x64.msi"),
            asset("WinVPN-1.6.0-x64.msi.sha256"),
            asset("WinVPN-1.6.0-x64.msi.sig"),
            asset("WinVPN-1.6.0-arm64.msi"),
        ],
        ..Release::default()
    };
    let x64 = up::assets(&release, "x86_64").unwrap();
    assert_eq!((x64.msi.name.as_str(), x64.sha256.name.as_str(), x64.sig.name.as_str()), ("WinVPN-1.6.0-x64.msi", "WinVPN-1.6.0-x64.msi.sha256", "WinVPN-1.6.0-x64.msi.sig"));
    assert!(up::assets(&release, "aarch64").is_none(), "arm64 has no .sha256/.sig in this release");
}

#[test]
fn the_signature_is_checked_with_the_winvpn_domain_and_the_asset_name() {
    // A throwaway key pair stands in for the release keys (`verify_for` with explicit keys).
    let (key, public) = test_keys();
    let sha = "a".repeat(64);
    let msg = UpdateSignature::message_for(macvpn_core::update::SignatureDomain::WinVpnV1, "WinVPN-1.6.0-x64.msi", "1.6.0", &sha).unwrap();
    let sig = sign(&key, &msg);
    assert_eq!(up::verify("WinVPN-1.6.0-x64.msi", "1.6.0", &sha, &sig, &[public]), Verified::Yes);
    // The same signature for the arm64 asset, or under MacVPN's domain, is refused.
    assert_eq!(up::verify("WinVPN-1.6.0-arm64.msi", "1.6.0", &sha, &sig, &[public]), Verified::No);
    let mac_msg = UpdateSignature::message("1.6.0", &sha).unwrap();
    assert_eq!(up::verify("WinVPN-1.6.0-x64.msi", "1.6.0", &sha, &sign(&key, &mac_msg), &[public]), Verified::No);
}

#[test]
fn the_relaunch_arguments_and_the_notice_round_trip() {
    let args = up::relaunch_args(4242, std::path::Path::new(r"C:\Program Files\WinVPN\WinVPN.exe"));
    assert_eq!(up::parse_relaunch(&args), Some((4242, std::path::PathBuf::from(r"C:\Program Files\WinVPN\WinVPN.exe"))));
    assert_eq!(up::parse_relaunch(&["--relaunch-after".into(), "x".into()]), None);
    let n = up::Notice { run: "r1".into(), ok: false, message: "msiexec 1603".into() };
    assert_eq!(up::Notice::parse(&n.encode()), Some(n));
}

#[test]
fn the_update_source_matches_the_info_plist() {
    let plist = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../app/src-tauri/Info.plist")).unwrap();
    assert!(plist.contains(&format!("<string>{}</string>", up::UPDATE_REPO)));
    assert!(plist.contains(&format!("<string>{}</string>", up::UPDATE_REPO_ID)));
}
```

`test_keys()` / `sign()`: an Ed25519 key from a fixed 32-byte seed with `ed25519-dalek` (already a core dependency: add it as a dev-dependency of platform-win at the same version, in the lock already) and base64 of the signature, as `crates/core/tests/update.rs` does — copy its helper. `up::verify` calls `UpdateSignature::verify_for(SignatureDomain::WinVpnV1, asset, version, sha, sig, keys)`; production calls `verify_trusted_for` (the same function with the embedded keys). Check the exact `ReleaseAsset` fields and `Release`'s constructor in `crates/core/src/update.rs` and adapt the test's literals.

- [x] **Step 2: Run them to verify they fail**

Run: `cargo test --locked -p macvpn-platform-win --test update`
Expected: FAIL to compile.

- [x] **Step 3: Implement**

`pure/update.rs`:
- `pub const UPDATE_REPO: &str = "SepsiG/MacVPN"; pub const UPDATE_REPO_ID: &str = "<the numeric id in Info.plist>";` (copy from `app/src-tauri/Info.plist`; the test pins them).
- `pub struct Assets<'a> { msi, sha256, sig: &'a ReleaseAsset }`, `pub fn assets(release, arch) -> Option<Assets>` via `WINVPN.update_asset(&release.version, arch)` and the two side files by exact name.
- `pub enum Verified { Yes, No }`, `pub fn verify(asset, version, sha256, sig, keys) -> Verified`.
- `relaunch_args(pid, target) -> Vec<String>` = `["--relaunch-after", "<pid>", "--target", "<absolute path>"]`, `parse_relaunch(args) -> Option<(u32, PathBuf)>` (exact shape, absolute target named `WinVPN.exe`).
- `Notice { run, ok, message }` with `encode` / `parse` (three lines: `run=…`, `ok=0|1`, `message=…`; at most 4 KiB; the message is a localized text or an msiexec code and a log path, never a secret).

`win/updater.rs`, `impl Updater for WinUpdater` (the `stage` texts are the macOS ones where they apply: "Downloading…", "Verifying…", "Installing…"):
1. `assets(release, ARCH)` → none: the localized "This release has no installer for this computer."
2. Download the `.sha256` and `.sig` (`HttpClient::get`, sizes capped as on macOS), then the MSI (`download`, GitHub canonical URLs only: the existing `UpdateURLPolicy`).
3. `parse_checksum(sha_text, msi_name)` must equal `sha256_of_file(msi)`; then `verify_trusted_for(SignatureDomain::WinVpnV1, msi_name, release.version, sha, sig)`; either failing deletes the file and returns the macOS texts for a checksum / signature failure.
4. Move the MSI into `%LOCALAPPDATA%\WinVPN\updates\` (private, created with `fsx::create_private_dir_all`), open it with share mode `FILE_SHARE_READ` only (`macvpn_winsys::file::open` with a new `share_read_only: true` field of `Open`, or `std::os::windows::fs::OpenOptionsExt::share_mode(FILE_SHARE_READ)` from platform-win) and keep the handle.
5. `confirm_quit()` → `false`: remove the file, `Ok(UpdateOutcome::Cancelled)`.
6. `ShellExecuteExW(runas, msiexec.exe, /i "<msi>" /qb! /norestart /l*v "<updates>\msiexec-<version>.log")` through `elevate.rs`, without waiting (`SEE_MASK_NOCLOSEPROCESS`, keep the process handle): UAC declined → the macOS "cancelled" path. Then copy the running `WinVPN.exe` to `<updates>\WinVPN-relaunch.exe` and start it (not elevated, `CREATE_NO_WINDOW`, `DETACHED_PROCESS`) with `relaunch_args(msiexec's PID, <app>\WinVPN.exe)`; return `Ok(UpdateOutcome::HelperLaunched)` — the app quits now (as on macOS), which frees `WinVPN.exe` for the installer. The deny-write handle is passed to nobody: it closes when WinVPN exits, after msiexec has opened the file (msiexec opens it before the UAC prompt returns control; the relauncher waits for msiexec, so the window in which the file is not held is after msiexec read it).
7. `launch_housekeeping`: read and delete `<updates>\last-update.txt` (`Notice`) unless `noticed` is its run, return it as `(run, message)`; delete `<updates>\*.msi`, `WinVPN-relaunch.exe` and logs older than 7 days.

`app/src-tauri/src/main.rs`: first thing in `main`, `if let Some((pid, target)) = platform::relaunch_mode() { platform::relaunch_after(pid, &target); return; }` — on Windows `relaunch_after` (in `platform/windows.rs`, over platform-win) opens the PID with `SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION`, waits at most 30 minutes, reads the exit code, writes the `Notice` (ok for 0 / 3010, else "The update failed (msiexec %@). Details: %@" with the log path), and starts `target` (`CreateProcessW` via `std::process::Command`, detached); on macOS `relaunch_mode()` is always `None`. No Tauri, no window, no single-instance claim in this mode.

A debug-only test hook for CP2: `WinVPN.exe --test-install-msi <absolute path>` (in `app/src-tauri/src/platform/windows.rs` behind `cfg(debug_assertions)`) runs steps 4–6 on a local MSI (no download, no signature: debug builds only); this task adds `--test-install-msi` to `scripts/build-msi.sh`'s list of strings that must not be in the release `WinVPN.exe` (next to `MACVPN_SMOKE`).

`release_source()` → a `ReleaseSource` over `CurlHttpClient` with `windows_curl()` (the macOS adapter's body: `UpdateChecker::latest_release_url(repo_id)`, `release_from_response`, the asset name `WINVPN.update_asset(version, ARCH)`); `update_info(app)` → the `Info` map with `UpdateChecker::INFO_PLIST_KEY` = `UPDATE_REPO` and `REPO_ID_INFO_PLIST_KEY` = `UPDATE_REPO_ID` (as strings, as in the plist) for an installed `WinVPN.exe` (`app_location` is `Some`), else `None`; `cache_directory(home)` → `%LOCALAPPDATA%\WinVPN\updates`.

`strings.json` (scope `core`, `"only": ["windows"]`): "This release has no installer for this computer." → "Ehhez a kiadáshoz nincs telepítő erre a számítógépre."; "The update failed (msiexec %@). Details: %@" → "A frissítés nem sikerült (msiexec %@). Részletek: %@".

- [x] **Step 4: Run**

Run: `CI=1 cargo test --workspace --locked && scripts/check-windows.sh && scripts/win-remote.sh test && cargo test --locked -p macvpn-app-core --test compat_1_4`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add crates/platform-win app/src-tauri/src crates/core/l10n/strings.json
git commit -m "feat(platform-win): the WinVPN updater" -m "The asset for this architecture, its .sha256, then verify_trusted_for(WinVpnV1, asset, …) (never MacVPN's domain); msiexec elevated through UAC on a deny-write copy in the private updates folder; a relauncher copy waits for msiexec, records the outcome for the next launch and starts the new WinVPN; housekeeping cleans up." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**As built (Task 18):** `pure/update.rs` (portable), `win/updater.rs` (Windows), `tests/update.rs` (every OS, 11) and `tests/update_windows.rs` (Windows, standard user, 4), with these differences from the sketch. **The release model:** core's `Release` already holds the one package of this machine (`package`, `checksum`, `signature`, chosen by `parse_release` with `WINVPN.update_asset(version, ARCH)`), not a list of assets: `up::assets(release, arch)` checks that the package is `WINVPN.update_asset(version, arch)` and that the `.sha256` / `.sig` are named after it (an unsigned release has no assets: nothing to install); the test builds `Release` literals. **Verification** is one portable function, `up::download_verified(http, release, arch, dir, hold, verify)` (tested with a scripted `HttpClient`): canonical github.com URLs only; the `.sha256` (≤ 4 KiB, names the package) and the `.sig` (404 → unsigned) first; then the MSI, moved into `<dir>\<asset>`, **opened with `hold` and hashed through that handle** (so the hash is of the file as held, not of a path checked earlier), `== .sha256`, then `verify(asset, version, hash, sig)`; any failure deletes the file and returns macOS' texts (checksum / "not signed by the WinVPN maintainer"). Production passes `up::verify_trusted` = `UpdateSignature::verify_trusted_for(WINVPN.signature_domain, …)`; never `verify_trusted`; tests use `up::verify` (= `verify_for` with throwaway keys) and show that a MacVPN-domain signature, the arm64 asset's signature, another key and a missing `.sig` all fail. `hold` (Windows) = `OpenOptions` read + `share_mode(FILE_SHARE_READ)` + `FILE_FLAG_OPEN_REPARSE_POINT`, regular file only (no new `winsys` field). **Relaunch arguments** carry the log too: `--relaunch-after <pid> --target <WinVPN.exe> --log <updates>\msiexec-<version>.log` (the relauncher must name the log in the notice and cannot derive the version); `parse_relaunch` is string-based (it runs on macOS in the tests): exactly six arguments, a PID without leading zeros, drive-absolute paths without `..`, `/`, `"` or control characters, target named `WinVPN.exe`, log named `msiexec-<[A-Za-z0-9.]>.log`. **Notice:** `Notice { run, exit_code, log }` (`run=`, `exit=`, `log=`, ≤ 4 KiB) instead of `{ run, ok, message }`: the relauncher runs without the app's language, so the text is made at the next launch (`message()` = "The update failed (msiexec %@). Details: %@" for anything but 0 / 3010). **A success shows no notice** (the app's notice is titled "The previous update did not complete"; CP2 item 4's "update notice" is the failure notice). **Stages:** macOS' existing "Downloading…", "Preparing the installation…", "Quitting and restarting…" (no new stage strings). **Install:** `confirm_quit` false → the MSI is removed, `Cancelled`; msiexec through `ShellExecuteExW(runas, <FOLDERID_System>\msiexec.exe, /i "<msi>" /qb! /norestart /l*v "<log>")` with `SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI | SEE_MASK_NOASYNC` (COM initialised on the worker thread), not waiting; `ERROR_CANCELLED` (UAC declined) → MSI removed, `Cancelled`; other failures → "Cannot start the installer helper script: …" (macOS' `HelperFailed`). The relaunch command line is validated **before** the UAC prompt. Then the MSI's deny-write handle and msiexec's process handle are kept in a static until WinVPN exits (msiexec's PID cannot be reused while the handle is open), `WinVPN.exe` is copied to `<updates>\WinVPN-relaunch.exe` (or `WinVPN-relaunch-<hex>.exe` when the old copy is still in use) and started with `DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP`; if that start fails, `HelperLaunched` is still returned (msiexec runs: the app must quit; WinVPN is then started by hand). **The relauncher** (`platform::relaunch_mode()` first thing in `main`; macOS: always `None`): `OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION)`, the image must be named `msiexec.exe` (`QueryFullProcessImageNameW`), waits ≤ 30 min; exited → the notice in its own folder (= the updates folder; `fsx::atomic_write`, private), then starts `target` detached; gone (also: msiexec already exited, since an exited process' image name can no longer be read) or another program → no notice, `target` started; still running after 30 min → nothing started. **Housekeeping:** the notice is read and deleted (a failure not yet `noticed` is returned); every `*.msi`, every `WinVPN-relaunch*.exe` and `msiexec-*.log` older than 7 days are removed (regular files only); `cache_directory` = `<app data root>\WinVPN\updates` (sandbox-aware, as `app_data_root`), created with `fsx::ensure_private_dir`. **Release source and update info:** `up::GitHubReleases(CurlHttpClient)` (portable, tested) over a local Windows flavour in `win/updater.rs` (`windows_curl()`: `<FOLDERID_System>\curl.exe`, `--ssl-revoke-best-effort`, fresh private temp directories via `winsys::file::create_dir(Private)`; `CurlRunner`: environment only `SystemRoot` and `PATH=<System32>`, `CREATE_NO_WINDOW`, stdin on a thread, 630 s limit). **Task 17 builds the same pieces in parallel** (`win/curl_runner.rs`, `win/elevate.rs`, which waits for msiexec): at merge, `updater.rs`'s `windows_curl` / `CurlRunner` should become Task 17's, and `run_elevated` may move next to `run_elevated_system32` (it must not wait). The user agent stays `MacVPN-Updater` (Task 5's text; changing it means editing `curl/http.rs`, which Task 17 also edits). `update_info(app)` = the repo and its ID (`UPDATE_REPO`, `UPDATE_REPO_ID`, pinned to Info.plist by a test) only when `app` is the running `WinVPN.exe`'s folder. Removed: `impl Updater for Inert`; `impl ReleaseSource for Inert` is left for Task 19 to delete with the catalog fetcher's (no shared hunk). **The debug hook** `WinVPN.exe --test-install-msi <absolute .msi>` (`app/src-tauri/src/platform/windows.rs`, `cfg(debug_assertions)`; the literal exists only there): copies the MSI into the updates folder, holds it, then the same `install_held` as an update; target `<FOLDERID_ProgramFiles>\WinVPN\WinVPN.exe`, log `msiexec-test.log`; **no quit question** (it runs before Tauri): quit WinVPN first. `build-msi.sh`'s app gate now loops over `APP_DEBUG_MARKERS=(MACVPN_SANDBOX_HOME MACVPN_SMOKE --test-install-msi)` with `grep -e` (a marker starting with `--` would otherwise be read as an option); `test-build-msi.sh` checks the list and that a binary with the hook is caught (56/56). **Strings** (core, `only: windows`): the plan's two. **Risks for CP2:** (1) msiexec may report WinVPN.exe in use if the app is still quitting when InstallValidate runs (basic UI's Restart Manager); (2) the UAC prompt has no owner window (it may open behind the Update window); (3) msiexec must open the MSI with read sharing compatible with the held handle (Task 17 relies on the same). **Results:** macOS: `cargo fmt --check`, clippy `-D warnings` (platform-win, app), `tests/update.rs` 11/11, the platform-win and app test sets, `l10n_coverage`, core `l10n`, `l10n-baseline --check` (1114 identical), `cfg_rule`, `test-build-msi.sh` 56/56 (shellcheck clean). Windows (standard user): clippy `-D warnings` for platform-win and the app (x64), `update` 11/11, `update_windows` 4/4, platform-win lib and `windows` green; `scripts/win-remote.sh msi --arch x64` passed every gate including the new marker (`WinVPN-1.5.0-x64.msi`, SHA-256 `deac4a52443f438b2b1d5387ed68c245214195f92494897f4065bae7e760b0d4`, unsigned, no ICE). **Needs the maintainer (CP2, elevated):** item 4 with `--test-install-msi` (quit WinVPN first): UAC once, the upgrade, `sc query WinVPN` running again, WinVPN starts by itself; a truncated MSI → after the next launch the notice "The update failed (msiexec 1620 or another code). Details: …\msiexec-test.log"; UAC declined → nothing installed, the MSI gone from `%LOCALAPPDATA%\WinVPN\updates`.

## Task 19: HTTPS team catalogs and the update check on Windows

**Goal:** an HTTPS catalog source works on Windows exactly as on macOS (conditional GET, the bearer token on stdin and only to its origin, the size cap, redirects), through System32's `curl.exe`; the update check is on (Task 18's release source and update info); 2a's "Not available on this system yet" for HTTPS sources goes.

**Files:**
- Modify: `crates/platform-win/src/win/platform.rs` (`https_catalog_fetcher()`), `crates/platform-win/tests/windows.rs` (or a new `tests/curl.rs`)
- Modify: `docs/` nothing here (Task 22)

- [x] **Step 1: Write the failing tests** (Windows, over SSH)

```rust
#![cfg(windows)]

#[test]
fn windows_curl_supports_every_flag_the_curl_layer_uses() {
    let curl = macvpn_platform_win::windows_curl_for_tests();
    let out = std::process::Command::new(&curl.executable).args(["--help", "all"]).output().unwrap();
    let help = String::from_utf8_lossy(&out.stdout);
    for flag in [
        "--globoff", "--proto", "--max-redirs", "--connect-timeout", "--max-time", "--user-agent", "--header",
        "--write-out", "--output", "--dump-header", "--max-filesize", "--config", "--cacert", "--ssl-revoke-best-effort",
    ] {
        assert!(help.contains(flag), "{} lacks {flag}", curl.executable);
    }
    assert!(curl.executable.to_ascii_lowercase().ends_with(r"\system32\curl.exe"));
}

#[test]
fn the_catalog_fetcher_runs_windows_curl_with_the_shared_arguments() {
    // A recording runner: the argv is the shared one (Task 5) plus --ssl-revoke-best-effort, and the token is on
    // stdin only (`--config -`), never in the argv.
    let (fetcher, seen) = macvpn_platform_win::catalog_fetcher_recording_for_tests();
    let _ = macvpn_core::catalog::fetch::CatalogFetcher::fetch(&*fetcher, &macvpn_platform_win::https_request_for_tests("https://catalog.example.com/team.macvpncatalog", Some("abc.DEF-123")));
    let calls = seen.lock().unwrap();
    let (exe, args, stdin) = &calls[0];
    assert!(exe.to_ascii_lowercase().ends_with(r"\system32\curl.exe"));
    assert!(args.iter().any(|a| a == "--ssl-revoke-best-effort"));
    assert!(!args.iter().any(|a| a.contains("abc.DEF-123")));
    assert!(stdin.as_deref().is_some_and(|s| s.contains("Authorization: Bearer abc.DEF-123")));
}
```

(The three `*_for_tests` helpers are `#[doc(hidden)]` in `lib.rs`; `https_request_for_tests` builds a `FetchRequest` the way `crates/platform-mac/tests/catalog_http.rs` does — copy its construction.)

- [x] **Step 2: Run them to verify they fail**

Run: `scripts/win-remote.sh run 'cargo test --locked -p macvpn-platform-win --test curl'`
Expected: FAIL to compile.

- [x] **Step 3: Implement**

`https_catalog_fetcher()` → `Arc::new(CurlCatalogFetcher::new_with(Box::new(WinCurlRunner::new(CATALOG_MAX_TIME + 30.0)), windows_curl(), format!("WinVPN-Catalog/{}", env!("CARGO_PKG_VERSION"))))` (add `new_with(runner, curl, user_agent)` to the moved fetcher; macOS' `new` stays and passes `MacVPN-Catalog/…`). Remove the `Inert` impls of `ReleaseSource` and `CatalogFetcher` from `platform.rs` (Task 18 replaced the release source). The view model's "Not available on this system yet" for HTTPS sources disappears by itself (it came from `CatalogError::Unavailable`).

- [x] **Step 4: Run**

Run: `CI=1 cargo test --workspace --locked && scripts/win-remote.sh run 'cargo test --locked -p macvpn-platform-win --test curl' && scripts/win-remote.sh test`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add crates/platform-win crates/platform-api
git commit -m "feat(platform-win): HTTPS team catalogs and the update check through System32's curl.exe" -m "The shared curl layer with Windows' curl (--ssl-revoke-best-effort, a minimal environment); the bearer token stays on stdin; every flag the layer uses is checked against the installed curl." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**As built (Task 19):**
- **Who owns what** (the coordinator's split for Wave 4): Task 19 turns the update *check* on (`release_source()`, `update_info`), Task 18 keeps the download, verification and install (`updater()`, `cache_directory`). The check lives in `crates/platform-win/src/pure/update_check.rs` (portable: `UPDATE_REPO_ID` = 1422472799, the same value as `MacVPNUpdateRepoID` in MacVPN's Info.plist; `update_info()` with `UpdateChecker`'s two keys and `WINVPN.repo`; `latest_release(http, repo_id, repo, arch)` with `WINVPN.update_asset`), tested on every OS by `crates/platform-win/tests/update_source.rs`. If Task 18's `pure/update.rs` defines the same constants, keep one of them at merge. `update_info` returns the info for any `app` (the app calls it only when `app_location` is `Some`, i.e. an installed `WinVPN.exe`).
- **The curl runner** is `crates/platform-win/src/win/curl_runner.rs` (`WinCurlRunner`, `windows_curl()`), as Task 17's text describes it; Tasks 17 and 18 may have written the same file in parallel: keep one at merge. System32 and `SystemRoot` come from `FOLDERID_System` / `FOLDERID_Windows` (`SHGetKnownFolderPath`, already used by `win/system.rs`) instead of `GetSystemDirectoryW`, so platform-win needs no new `windows-sys` feature; the runner refuses a relative executable (an unreadable System32 leaves the flavour's executable empty: fail closed). Without stdin the child gets `NUL`; stdout/stderr are kept up to 1 MiB each (the rest drained). Private directories: `<user temp>\<prefix>.<32 hex from BCryptGenRandom>` made with `create_dir` (never an existing one) then `fsx::ensure_private_dir` (protected owner-only DACL, no reparse point).
- `win/https.rs`: `catalog_fetcher()` = `CurlCatalogFetcher::new_with(WinCurlRunner::new(CATALOG_MAX_TIME + 30), windows_curl(), "WinVPN-Catalog/<v>")` (`new_with` added in platform-api; `with_curl` keeps `MacVPN-Catalog/<v>` for macOS), `WinReleases` (runner limit 30 + 30 s) and, as on macOS, `SandboxHttps` in debug builds with `MACVPN_SANDBOX_HOME` (the existing string "HTTPS sources are not available in the sandbox"). The release query's user agent stays the shared `MacVPN-Updater` (a constant in `curl/http.rs`; GitHub needs any agent). No new user-visible strings.
- The `Inert` impls of `ReleaseSource` and `CatalogFetcher` are gone from `platform.rs`.
- **Tests** (`crates/platform-win/tests/curl.rs`, Windows): the plan's two, with the fetch request built in the test (as `catalog_http.rs` does) instead of an `https_request_for_tests` helper (a `FetchRequest` borrows), plus: the runner hands curl its `--config -` on stdin (a loopback plain-HTTP server sees the `Authorization` header) and the child's environment is only `SystemRoot` and `PATH=<System32>` (`cmd.exe /d /c set`); the runner kills curl at its limit (`TimedOut`); a relative executable is refused; the real fetcher reports a closed loopback port as `Unavailable`. Test helpers in `lib.rs`: `windows_curl_for_tests`, `curl_runner_for_tests`, `catalog_fetcher_for_tests`, `catalog_fetcher_recording_for_tests`.
- Step 4 ran targeted (the maintainer's test strategy): on the Mac fmt, clippy and the tests of platform-api, platform-win and platform-mac's `curl_argv`, `catalog_http`, `update_installer`; on Windows `--test curl --test update_source` and clippy of platform-win and platform-api.

**As built (wave 4 merge):** Tasks 17, 18 and 19 merged into one branch; the duplicates were removed. **curl runner:** one `win/curl_runner.rs` — Task 19's `WinCurlRunner` / `windows_curl()` (absolute executable only, `SystemRoot` + `PATH=<System32>` only, `CREATE_NO_WINDOW`, stdin from memory or `NUL`, 1 MiB output caps) with Task 17's per-run limit (the argv's `--max-time` + 30 s, 60 s without one; `time_limit`) as well, capped by the runner's own limit; private directories `<temp>\<prefix>.<32 hex>` created owner-only by `winsys::file::create_dir(Private)` (Tasks 17/18) and then checked by `fsx::ensure_private_dir` (Task 19). `curl_runner::http_client(curl, cap)` is the one HTTP client of the update check, the updater (cap 630 s) and the OpenVPN download (cap 630 s, its own `temp_base`); Task 17's `CurlRunner` and Task 18's `windows_curl` / `CurlRunner` / `system32()` fallback (`C:\Windows\System32` when the known folder failed: now fail closed) are gone, and `updater_curl_for_tests` became `windows_curl_for_tests` + `curl_runner_for_tests`. **Elevation:** `win/elevate.rs` has `start_elevated` (Task 18's non-waiting `runas`, returns the owned process handle; the updater's msiexec) and `run_elevated` (Task 17's, now `start_elevated` + wait); one `ShellExecuteExW` wrapper. **Update check:** Task 19's `pure/update_check.rs` (`UPDATE_REPO_ID: i64`, `update_info()` with `WINVPN.repo`, `latest_release`) and `win/https.rs::WinReleases` won; Task 18's `UPDATE_REPO`, `UPDATE_REPO_ID`, `update_info()` and `GitHubReleases` (`pure/update.rs`) and `updater::release_source()` are gone; their tests moved to `tests/update_source.rs` (the Info.plist pin, now on `WINVPN.repo`; an unsigned release has no signature). `WinPlatform::update_info` keeps Task 18's gate (only for the running `WinVPN.exe`'s folder). The updater still verifies with `up::verify_trusted` = `verify_trusted_for(WINVPN.signature_domain, …)` only. **User agent:** `CurlHttpClient::new_with(runner, curl, user_agent)` (platform-api; `with_curl` keeps `MacVPN-Updater` for macOS, test in `curl_layer.rs`); WinVPN's release query, update download and OpenVPN download send `WinVPN-Updater/<version>`. **App entry:** `main` runs `platform::relaunch_mode()` first, then `helper_mode()` (the OpenVPN step, now reading its arguments through the Unicode-safe `text_args()`), then the debug-only `test_install_mode()`; macOS returns `None` for all three. `build-msi.sh` forbids `--test-install-msi` only (`--winvpn-openvpn-step` is a release feature).

### Checkpoint CP2 (the maintainer, after Wave 4 is merged)

A fresh x64 MSI (`scripts/win-remote.sh msi --arch x64`) and a debug build of the app; for the updater's install half a second MSI of a higher version (on a throwaway local branch with the workspace version `1.5.1`, never merged: `scripts/win-remote.sh msi --arch x64`). A release build accepts only maintainer-signed updates, so the download-and-verify half is covered by Task 18's tests and the install half by the debug-only `--test-install-msi`:
1. Uninstall OpenVPN Community; System Status → OpenVPN row red, "Install" → (winget present on Windows 11) winget runs, UAC prompt once, the output streams; the row turns green and lists the two drivers with their versions; `pnputil /enum-drivers` shows ovpn-dco and tap0901; `C:\Program Files\OpenVPN` has no GUI; `sc qc OpenVPNServiceInteractive` shows `START_TYPE 4 DISABLED` and `sc query OpenVPNServiceInteractive` `STOPPED`; connect works. Then remove the TAP-Windows6 feature (Installed apps → OpenVPN → Modify) → the row shows "Repair" and the TAP config is refused with the driver message, the DCO one still connects; "Repair" → the driver is back.
2. The pinned-MSI path: on a machine without winget (a Windows 10 VM without App Installer) the same "Install" downloads the pinned MSI, checks it and runs it after one UAC prompt; without such a machine mark it "nem tesztelt" (Task 17's tests cover the download, hash and signer checks).
3. UAC declined → "Cancelled", nothing installed.
4. Debug build: `WinVPN.exe --test-install-msi C:\…\WinVPN-1.5.1-x64.msi` → quit questions, UAC, the upgrade runs, the service restarts (`sc query WinVPN`), WinVPN comes back by itself, and the next launch shows the update notice; a failing MSI (a truncated copy) → the failure notice with the log path.
5. An HTTPS catalog subscription (a local HTTPS server or a test URL the maintainer controls) with a bearer token: subscribes, refreshes, a 304 keeps it; the token never appears in `service.log`, the app log or Task Manager's command line column of `curl.exe`.
6. The update check: Help → Check for updates → "up to date" (or the current release offered) with the network on; off → a clean error.

**CP2 result (2026-10-23/24, maintainer, Windows 11 x64 VM):** all items passed on the wave-4 tip (89af879): OpenVPN install from System Status via winget (two UAC prompts, Interactive Service disabled and stopped, marker set, no GUI, both drivers), Repair after removing TAP-Windows6, UAC declined → cancelled, the debug `--test-install-msi` upgrade 1.5.0 → 1.5.1 (throwaway branch, deleted) with the service restarted and WinVPN relaunched, the truncated MSI → the failure notice, the update check, then a downgrade back to the 1.5.0 build. No findings.

**As built (fix5, macOS, 2026-10-24):** the maintainer's "the VPNs should always be the newest": MacVPN's System Status offers Homebrew updates of its formulae. **Detection** (`platform-mac/src/brew.rs` `BrewOutdated`): `<prefix>/bin/brew outdated --json=v2 --formula openvpn wireguard-tools strongswan sstp-client bash` (`SetupChecker::BREW_PACKAGES`, the prefix from the existing `BREW_PREFIXES` discovery, never PATH), in `BrewEnvironment` plus `HOMEBREW_NO_AUTO_UPDATE=1` (Homebrew 4 auto-updates its taps even for `outdated`: measured ~10 s with network; the check uses the local tap state only), a 20 s `ProcessCommandRunner`. Run by `MacSetup::check` after the system check (`SetupChecker::check_outdated`), only when Homebrew is there and no tool is missing, never in the sandbox. The exit status is ignored (brew exits 1 when a named formula is outdated); the JSON is parsed with `serde_json::Value` (new platform-mac dependency), text before the first `{` skipped; only our formulae, not pinned, with an installed (the last of `installed_versions`) and a different `current_version`, in `BREW_PACKAGES` order. Any failure, timeout or unexpected JSON = unknown = no offer, never an error row. **Report:** platform-api `SetupReport::outdated_packages: Vec<OutdatedPackage { name, installed, available }>` (empty on Windows; `is_complete` / `is_available` ignore it: the row stays green and usable). **View** (app-core): `SetupFacts::outdated`; the green tools row's detail lists each one ("openvpn: Update available: 2.6.8 → 2.6.9", joined with "; "), and `SetupView::tools_action = Some("update")` (absent from the JSON otherwise, so the 1.4 view model is unchanged; cleared by the engine rows / engine note). **Update:** the same `setup_install_tools` command and live output as "Install": `MacSetup::install_tools` runs `brew upgrade <outdated formulae>` when nothing is missing (only names of `BREW_PACKAGES`; a list without one is refused, never a bare `brew upgrade`), then the app checks again. `brew upgrade` keeps Homebrew's own auto-update (user-initiated), so it installs the newest version. The sandbox prints `$ brew upgrade …` and runs nothing. **UI:** `Setup.svelte` shows "Update" on the green tools row (`CheckRow showAction`), `api.ts` `toolsAction?: 'update'`. **String:** "Update available: %@ → %@" / "Frissítés elérhető: %@ → %@" (`app`, no `only`): the parallel Windows change adds the same key with `only: windows`; the merge must keep it for both OSes. **Not done:** no periodic `brew update` (the offer appears once the user's own brew use, or an "Install"/"Update" here, has refreshed the taps). **Tests:** platform-mac `brew.rs` +3 (arguments/environment, JSON parsing incl. pinned/foreign/incomplete/garbage, `brew upgrade` streaming with a stand-in script and the bare-upgrade refusal), `setup_checker.rs` +3 (mock runner: green → one call and the parse, missing tool / no Homebrew → no call, unreadable answers and a timeout → nothing), `api.rs` (sandbox upgrade header); app-core `system_status.rs` +1 (EN/HU detail, `toolsAction`, JSON absence, missing tool wins). Not covered by the macOS smoke (its mock report has a missing tool). **As built (daily brew update, 2026-10-24):** the maintainer runs `brew update` by hand only now and then, so MacVPN does it once a day (this replaces the "Not done" above): platform-api `SystemSetup::update_package_index() -> PackageIndexUpdate { Unavailable, Busy, Updated, Failed(msg) }` (default `Unavailable`: Windows does nothing); `MacSetup` runs `<prefix>/bin/brew update` (prefix from `SetupChecker::installed_brew_prefix` = the `BREW_PREFIXES` discovery, never PATH) as the user with `ProcessCommandRunner` (120 s, `BrewUpdate::environment` = `BrewEnvironment`), `Unavailable` in the sandbox or without Homebrew; platform-mac `BrewGuard` (`BREW_GUARD`, an in-process mutex): the update `try_lock`s it and returns `Busy` while an install/upgrade runs, `install_tools` `lock`s it (waits for a running update). Scheduling (app-core `package_index`): `package_index_update_due(last, now)` (never run, ≥ 24 h, or the clock went back), `PackageIndexSchedule::run` waits 60 s after launch, then wakes hourly and runs when due; only `Updated` stores the time (preference `lastBrewUpdate`, the app's `PreferenceStore`: UserDefaults `local.macvpn`, in memory in the sandbox), so a failure/busy round is retried at the next hourly wake. The app starts the thread (`macvpn-package-index`) at the `StartUpdateScheduler` launch step, never in the sandbox; a failure is only logged (`MacVPN: brew update failed (…); retrying later`), after a success it runs the system check again (`system::check`, so System Status and its "Update" offer get the fresh `brew outdated` answer whether or not the window is open). No setting, no new strings. User guide (EN/HU) §2 item 2 mentions the update offer and the daily refresh. Tests: platform-mac `brew.rs` +3 (exact `/opt/homebrew/bin/brew update` with the minimal env via `MockCommandRunner`, failure messages incl. timeout, the guard: `Busy` without running, `lock` waits for a running update), `setup_checker.rs` +1 (prefix discovery), `api.rs` +1 (sandbox → `Unavailable`); app-core `package_index.rs` +5 (24 h decision, only success stored, recent run honoured at launch, scheduler rounds and retry, stop).

**As built (DNS fix, macOS, 2026-10-24):** the maintainer reported that after disconnecting an OpenVPN or WireGuard connection that set DNS the internet often stayed broken (DNS not back to the local network's), with long-lived connections. Root causes, confirmed in the code: (1) `hook_dns.rs` set the VPN DNS on every service with `networksetup -setdnsservers`, a **persistent** change, but kept the originals in `<run>/dns-backup` under `/var/run/macvpn` (wiped at boot): a reboot, shutdown or crash while connected left the VPN DNS for good, and the next connection backed it up as the "original" and restored it at every later down; (2) **stacking**: each connection captured the current DNS, so with two DNS-setting connections (A up, B up) B saved A's VPN DNS as original and A-then-B down left A's DNS; (3) **WireGuard** left DNS to Homebrew `wg-quick`, which keeps the originals only in the memory of its disowned route monitor and restores them asynchronously in that process's EXIT trap (output to `/dev/null`; a dead or disturbed monitor never restores; it also re-applies the VPN DNS on every route event); (4) an engine that **died without a down** (crash, kill, OpenVPN exiting when its hook could not run) kept its DNS until a later up/down of the same id (`ctx.dns_restore` ran only then; `status` did nothing). The logged 29-hour OpenVPN session restored correctly at its down, so the straight path was fine. **Fix:** one helper-owned DNS manager, `crates/helper/src/macos/dns.rs`, for every kind that sets DNS: OpenVPN and SSTP through the `ovpn-dns` hook (as root only; the hook still reads no environment beyond its allowlist), WireGuard in-process. A persistent, root-only **ledger** `/var/db/macvpn/dns/ledger` (`paths::DNS_BASE`; directory 0700 and ours, file 0600 written via a temp file + rename, never through a symlink, strict line format; one `flock` on `lock` serializes the hook processes and `mvpn`) holds the **true originals** per service (captured only when there is no ledger, i.e. by the first owner) and the **owners** (connection id + its servers/domains, newest last). The newest owner's DNS is in effect (an owner without search domains keeps each service's original ones); an owner leaving while others remain re-applies the newest remaining owner's DNS; the last owner's leaving restores the originals and deletes the ledger. Every set and restore is logged (`$ networksetup …` lines), read back with `-getdnsservers/-getsearchdomains` (addresses compared parsed, domains case- and dot-insensitive), set once more if it did not take, and the result logged ("DNS set and verified on N network service(s)", "original DNS restored and verified …", or "DNS check failed on <service> after a retry: expected …, found …") in the connection log, WireGuard included. **Reconcile** (owners whose run directory is gone or whose engine `status::one` reports `failed` are dropped; restore or re-apply as above) runs at every `up` (before anything is set), every `down` (after the teardown), every `mvpn status` (non-blocking: skipped if the ledger is busy; without a ledger only a `stat`), and the new `mvpn dns-reconcile`. The app needs no change: it already runs `mvpn status` as root through `sudo -n` at start (also after a reboot) and on every refresh, and the sudoers rule allows any `mvpn` argument. **WireGuard:** `wireguard::strip_dns` takes the `DNS =` lines out of the `[Interface]` of the conf `wg-quick` gets (addresses are servers, the rest search domains, as wg-quick splits them; the values were validated before), and the manager sets them after `wg-quick up` and gives them up after a successful `wg-quick down`. wg-quick's re-apply on network changes is gone; that is acceptable because a `networksetup` DNS setting is a persistent service preference that a network change or DHCP does not overwrite (the OpenVPN path never re-applied and was not affected), and the re-apply's other effect, putting the VPN DNS on services that appear mid-session, is exactly what the manager does not do. Services added during a session are not touched; services removed in the meantime are skipped at restore; a service whose DNS cannot be read is left alone (logged). A `<run>/dns-backup` of the previous root layer is still restored at down (through the hook as before, verified). **strongSwan and native:** the helper does not touch DNS for strongSwan (charon applies IKE-assigned DNS itself, in the volatile dynamic store, not in the persistent preferences), and native (system) VPNs are handled by macOS. **Test mode** never runs the real `networksetup`: `Settings::networksetup` is `None` unless `MVPN_NETWORKSETUP` names a fake (`MVPN_DNS_BASE` moves the ledger). **Tests:** `dns::tests` (19: first-owner capture and restore with modes 0700/0600, stacking both orders, reconnect, crash reconcile, reboot with a ledger and no run directory, a set that does not take retried and verified, one that never takes logged, removed/added/unreadable services, symlinked ledger directory refused, corrupt ledger set aside, legacy backup, strict format, `networksetup` output parsing), `hook_dns::tests::up_and_down_go_through_the_dns_manager`, `wireguard::tests::dns_lines_are_taken_out_of_the_conf_for_wg_quick`, `paths` (test mode never gets the real tool), and `scripts/test-root.sh` (status/dns-reconcile restore a dead owner's DNS with a fake `networksetup`, keep a live one's, touch nothing without the fake). Not changed: the uninstaller (all connections are taken down first, which removes the ledger; an empty `/var/db/macvpn/dns` stays). The root layer changed: at the next release `crates/helper/VERSION` goes to 9 (RELEASING step 2), otherwise the app does not offer the reinstall. A DNS left wrong by the old root layer before this fix is not in any ledger and must be reset once by hand (System Settings → Network → the service → DNS).

**As built (log caps and Windows DNS audit, 2026-10-24):** the maintainer's Mac had a 30.5 GB `/var/log/macvpn/<id>.log.1`: a 29-hour OpenVPN session across sleep/wake wrote `write UDPv4: Network is unreachable (fd=5,code=51)` 36.5 million times, and nothing bounded a log during a session (rotation only at `up`). Now every log that grows during a session has a hard cap, enforced while it runs. macOS (`crates/helper/src/macos/log.rs`): the user's connection log is at most 5 MiB (`LOG_MAX`) plus one generation `<id>.log.1` of at most 5 MiB; a full log is rolled in place (its newest whole lines become `.1`, the live file is truncated, so every `O_APPEND` writer – the bridge, sstpc through `mask-stream`, charon, wireguard-go with `--debug` – continues in the live file). The cap is checked on every `mvpn` write (`Log::bytes`), on every line of `mask-stream` (SSTP), by `status` (the app's poll; under the connection's lock taken without waiting) and by the management bridge every 30 s (`BridgeFiles::housekeeping`: the bridge runs as long as openvpn, so the cap holds also after "Quit, keep connections"). The engines' own logs in the run directory (`openvpn.log`, `pppd.log`) are cut to their newest 1 MiB above 5 MiB (`trim_root_log`), keeping the newest 16 decision lines (completion, final `AUTH_FAILED`, pppd's interface/address/DNS lines) so `status` and `up` decide as before, and moving the copy offset with them; one flush copies at most 1 MiB (an older backlog is skipped with a localized note), and an offset beyond the file restarts instead of stopping the copy for good. An oversized live log or `.1` left by an older version is cut to the cap at the next `up`/`down`/`respond` (the existing 30 GB file is the maintainer's to delete or keep; it is cut at the next connect). OpenVPN gets `--mute 20` on both OSes, after `--config` (later options win), so a config's `verb`/`mute` cannot raise the volume (the validator's 0–11 `verb` stays: it is overridden); `--mute-replay-warnings` is not added (`--mute` already rate-limits replay warnings and they stay visible). WireGuard (`wireguard-go` is silent unless `--debug`) and strongSwan (charon's own lines, IKE events) write little; their output is bounded by the same in-place roll from `status` and the next `mvpn` run (not by the bridge, which only exists for OpenVPN). Windows: `FileLogStore` rolled to "log truncated" and then dropped every newer line; it now rolls at 8 MiB to `<ID>.log.1` with a new generation (the app's tail starts over) and a localized first line naming it, a sink replaced by a newer `up` stops writing, `.1` goes with a new `up` and with `remove`; `service.log` (1 MiB + `.1`, also wireguard-nt's logger) was already bounded; OpenVPN's output reaches the connection log only through the service's pipes (no file). The app writes no log file during a session except the control API's `audit.log` (256 KiB + `.1`); `update.log` / `msiexec-<version>.log` are written once per update. Windows DNS audit: WireGuard sets DNS only on its own adapter (`SetInterfaceDnsSettings`, `sys/iphlp.rs`), which wireguard-nt deletes when its handle closes (also on a crash or kill; nothing survives a reboot); but the adapter GUID is stable per connection (`wg_nt::adapter_guid`) and Windows keeps an interface's DNS under its GUID in the registry, so a server, an IPv6 server or a search domain an earlier session set came back when the config no longer had it: every `up` now sets or clears both families and the search list (`wg_nt::dns_calls`). OpenVPN 2.7 without the Interactive Service: pushed `dhcp-option DNS/DOMAIN` goes to TAP-Windows6 through its DHCP (nothing persistent) and on DCO through `netsh … set dns … static` (persistent, removed on a graceful exit, left on a kill, but only on the DCO adapter, which is disconnected then, so the resolver ignores it, and OpenVPN deletes it at the next connect); `--dns` (NRPT) needs the Interactive Service, so no NRPT rule is ever written (and a `--dns`-only server gets no DNS on DCO: a known gap, not a leftover); `block-outside-dns` uses dynamic WFP filters that vanish with the process. The service stops OpenVPN with `signal SIGTERM` on the management connection, 5 s grace, then terminates it (`sys/openvpn.rs` `Proc::stop`), on `down`, logoff, service stop and shutdown; a second concurrent stop (a `down` while the bridge stops it) used to terminate at once and now waits out the same grace. Not changed: the service accepts SHUTDOWN, not PRESHUTDOWN, so at system shutdown a slow graceful stop may be cut short (the leftovers are then the harmless ones above); there is no start-time cleanup, as WinVPN creates no NRPT rule and its WireGuard DNS is now overwritten at every `up`.

## Task 20: the Windows smoke run

**Goal:** `scripts/smoke-manage.sh` runs on the Windows machine in `winvpn-dev`'s desktop session (started from the Mac by `scripts/win-smoke.sh` through a one-shot scheduled task), with every section that is not AppKit-specific; the macOS smoke run is unchanged.

**Files:**
- Create: `app/src-tauri/src/platform/smoke/mod.rs` (the portable driver), `app/src-tauri/src/platform/smoke/macos.rs` (window numbers, `screencapture`, the Dock, the activation policy, the window shapes), `scripts/win-smoke.sh`, `scripts/test-win-smoke.sh`
- Delete: `app/src-tauri/src/platform/smoke.rs` (split into the two files above)
- Modify: `app/src-tauri/src/platform/{mod,windows}.rs` (the `smoke_*` facades call the driver on Windows debug builds too), `scripts/smoke-manage.sh` (an OS switch), `scripts/smoke/*.js` (only where a script names macOS-only UI: guarded by the `platform` the page reports), `docs/architecture.md` is Task 22's

- [x] **Step 1: Split the driver (a pure move; the pin is the macOS smoke run itself)**

Move everything from `smoke.rs` that has no AppKit call into `smoke/mod.rs` unchanged: `seed_*`, `remember_recovery_key`, `smoke_dir*`, `fake_helper` / `FakeHelper` (with `framed_secret_names`), `fake_native`, `setup_report`, `mock_release`, the update installer fake, `start`, `renamed`, `wait_for`, `eval`, `run_script`, `prompts`. Move `menu_shape`, `manage_shot`, `popover_shots`, `shots_dir`, `with_shot`, `window_number`, `shoot`, `regular`, `dock` into `smoke/macos.rs` behind `#[cfg(target_os = "macos")]`; `start` calls them through `#[cfg(target_os = "macos")]` lines (the module is under `app/src-tauri/src/platform/`, where OS `cfg` is allowed). On Windows those steps print `MacVPN smoke: <step>: skipped on Windows` instead. The log prefix stays `MacVPN smoke:` on both OSes (the scripts grep it). `setup_report` on Windows returns a mock with `engine` rows (green service, red OpenVPN with "install", green WireGuard) so `setup.js` exercises the Windows rows; `setup.js` checks the rows the page shows by the `platform` (`get_platform`).

Run on the Mac: `SMOKE_LANG=en scripts/smoke-manage.sh && SMOKE_LANG=hu scripts/smoke-manage.sh` (the display must be unlocked: 2a's lesson) → both pass exactly as before the split.

- [x] **Step 2: The OS switch in `scripts/smoke-manage.sh`**

```bash
case "$(uname -s)" in
  MINGW*|MSYS*) SMOKE_OS=windows; APP=${APP:-target/debug/macvpn-app.exe}; NODE=$(command -v node) ;;
  *) SMOKE_OS=macos ;;
esac
```

and every macOS-only check (`dock`, the popover shape, `SMOKE_SHOTS`, the `screencapture` files, `open -a`) inside `if [ "$SMOKE_OS" = macos ]; then … fi`, with `grep -q "^MacVPN smoke: dock: skipped on Windows$"` as the Windows expectation. The sandbox home on Windows is a fresh directory under `$TEMP` (as on macOS under `$TMPDIR`); the control client test (`control-client.mjs`) connects to `\\.\pipe\WinVPN-control-<SID>` on Windows (Node's `net.connect` takes a pipe path; the SID from `whoami /user /fo csv /nh`).

- [x] **Step 3: `scripts/win-smoke.sh`** (run on the Mac)

```bash
#!/bin/bash
# The Windows smoke run in winvpn-dev's desktop session (2b plan, Task 20): builds the debug app on the Windows
# machine, then runs scripts/smoke-manage.sh through a one-shot scheduled task that runs only in the logged-on
# desktop session (/IT: no password is stored; a standard user may create it for itself). winvpn-dev must be
# logged on at the VM's console (the session may be locked or disconnected).
#
#   scripts/win-smoke.sh [en|hu]
set -euo pipefail
cd "$(dirname "$0")/.."
LANG_ARG="${1:-en}"
[[ "$LANG_ARG" =~ ^(en|hu)$ ]] || { echo "usage: scripts/win-smoke.sh [en|hu]"; exit 1; }
REMOTE_DIR="${WINVPN_REMOTE_DIR:-winvpn-work}"
TASK="WinVPN-smoke-$$"

scripts/win-remote.sh run '(cd app/ui && npm ci && npm run build) && cargo build --locked -p macvpn-app --features custom-protocol'
scripts/win-remote.sh run "query user winvpn-dev >/dev/null 2>&1 || { echo 'no interactive session of winvpn-dev: log on at the VM console'; exit 1; }"
RUNNER="\"C:\\Program Files\\Git\\bin\\bash.exe\" -lc \"cd ~/$REMOTE_DIR && SMOKE_LANG=$LANG_ARG scripts/smoke-manage.sh > target/smoke.log 2>&1; echo \\\$? > target/smoke.result\""
scripts/win-remote.sh run "rm -f target/smoke.result target/smoke.log && MSYS_NO_PATHCONV=1 schtasks /Create /F /SC ONCE /ST 00:00 /IT /RU winvpn-dev /TN $TASK /TR '$RUNNER' && MSYS_NO_PATHCONV=1 schtasks /Run /TN $TASK"
for _ in $(seq 1 180); do
  if scripts/win-remote.sh run 'test -f target/smoke.result' >/dev/null 2>&1; then break; fi
  sleep 5
done
scripts/win-remote.sh run "cat target/smoke.log; MSYS_NO_PATHCONV=1 schtasks /Delete /F /TN $TASK >/dev/null; exit \$(cat target/smoke.result 2>/dev/null || echo 1)"
```

(Each `win-remote.sh run` syncs first; pass the polling commands through a `run-nosync` subcommand instead — add it to `win-remote.sh` (`remote` + `in_checkout` without `sync`) with a case in `scripts/test-win-remote.sh`. Foreground `sleep` in the script is fine: it runs on the Mac in a terminal, not in the agent harness. `scripts/test-win-smoke.sh` checks the usage line and the argument validation in print mode.)

- [x] **Step 4: Run it**

Run (the maintainer logs `winvpn-dev` on at the VM's console first): `scripts/win-smoke.sh en && scripts/win-smoke.sh hu`
Expected: every non-macOS section passes, `dock`, shapes and shots print "skipped on Windows". A failure that only the desktop shows (blank window, a window that does not fit) is a finding with its own fix commit, as in 2a.

- [x] **Step 5: Commit**

```bash
git add app/src-tauri/src/platform scripts/smoke-manage.sh scripts/smoke scripts/win-smoke.sh scripts/test-win-smoke.sh scripts/win-remote.sh scripts/test-win-remote.sh
git commit -m "test: the smoke run on Windows" -m "The driver's portable part runs on Windows debug builds; the AppKit-only steps stay macOS-only. scripts/win-smoke.sh runs smoke-manage.sh in winvpn-dev's desktop session through a one-shot interactive scheduled task. macOS smoke EN/HU unchanged." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**As built (Task 20):** `platform/smoke.rs` became `platform/smoke/mod.rs` (portable driver, `#[cfg(debug_assertions)]` on both OSes) and `platform/smoke/macos.rs` (`#[cfg(target_os = "macos")]`: `menu_shape`, `manage_shot`, `popover_shots`, `shots_dir`, `with_shot`, `window_number`, `shoot`, `regular`, `dock`, plus what needs platform-mac: the old Keychain seed, `appearance` (dark/light), the mock Homebrew report, `SandboxUpdate` / `update_install` (it implements platform-mac's `UpdateSteps`, so it is not portable as the sketch assumed), `private_temp_dir` (`make_private_temp_directory`) and `mode` (Unix bits)). The move is mechanical; the only changes on macOS: `MvpnClient::up_stdin` → `core::helper_args::up_stdin` (Task 16's), the smoke catalog's entropy is `platform::get().entropy()` (the same `SystemEntropy` on macOS), `ready_report()` for the control step. Windows equivalents in `mod.rs` under `#[cfg(windows)]`: `skipped(step)` (`MacVPN smoke: dock|menu|shots|appearance: skipped on Windows`), `close_windows` in place of the Dock step (`MacVPN smoke: windows: closed=…`), no-op `shoot` / plain `with_shot`, `private_temp_dir` (random name, `fsx::ensure_private_dir`), `mode` from the DACL (`fsx::has_access` → `600` / `644` / `other`), `windows_report(openvpn)` (System Status' mock = `engine::report` over `EngineFacts`: service ok, OpenVPN "not installed" → Install, WireGuard 1.1.0; the control step's "ready" report has OpenVPN 2.7.8 with both drivers), the update fake (the stages "Downloading…", "Preparing the installation…", "Quitting and restarting…", then the quit questions; no MSI, no msiexec), the control endpoint from the running server (`AppState.control.endpoint()`, debug only, new in `control.rs`; a pipe has no file to look at). The facades in `platform/mod.rs` now call the driver on both OSes (the non-macOS stub module is gone). **Language on Windows:** `MACVPN_SMOKE_LANG=en|hu` sets the preferred languages in `seed_legacy_keychain` (the step after `install_core_hooks`, before any window). **`smoke-manage.sh`:** `SMOKE_OS` from `uname`; Windows: `APP=target/x86_64-pc-windows-msvc/debug/macvpn-app.exe` (the remote checkout's warm CI-target directory, not `target/debug`), `grep -a` instead of `strings`, sandbox `$TEMP/winvpn-smoke.XXXXXX` handed to the app as a long Windows path (`cygpath -l -w`), `SUPPORT=<home>/AppData/Local/WinVPN`, no `ioreg`, no screenshots, run limit 1200 s (480 on macOS), the app stopped with `taskkill` of its `winpid` and waited for before the sandbox is removed; expectations: no old Keychain item (`keychain_items=0`, `secret=no`, `0 secrets`), no Unix modes and no staged native profile, `dock: skipped`, `windows: closed=true`, `menu: skipped`, no control socket file, the audit file present; the system quit request (logout's `WM_QUERYENDSESSION` from outside) is not sent: the app is stopped and the line says so. The control client takes the pipe name from the `listening` line (no `whoami` SID needed). **Scripts:** `setup.js` (Windows: the three engine rows, OpenVPN's Install with the sandbox output, the native-VPN note, no uninstaller), `live.js` (the "removed from Windows" banner), `live-menu.js` and `vault-unlock.js` (the product name from `get_platform`, "WinVPN …"), `manage.js` (Ctrl+F; on Windows the native L2TP form is not edited – native VPNs come later, nothing can be saved there – and the search expects "Seeded L"), `pairing.js` / `control.js` (a Windows absolute path `C:\…` is accepted), `catalog.js` (a failed preview puts the sheet's error into the result). **`scripts/win-smoke.sh`:** the session check comes first (no build without a session) and reads `query.exe user`'s lines (`{ query.exe user || true; }`: it exits 1 even when it lists sessions, and the remote shell has `pipefail`; `.exe` explicitly: the VM has a stray 8-byte file `C:\Windows\System32\query` that Git Bash runs first); the task's user is `WINVPN_SSH`'s; the build is `--target x86_64-pc-windows-msvc`; the runner's `$?` is unescaped; waiting through `run-nosync` (new in `win-remote.sh`, tested in `test-win-remote.sh`), at most `WINVPN_SMOKE_WAIT` (1500 s), then the task's state; print mode does not wait. `scripts/test-win-smoke.sh` (36 checks: arguments, order, the task's flags, no `/RP`, no release build, no `sc`). **Findings of the first Windows runs, each with its own fix commit:** (1) `winsys::pipe`: a client that opens the pipe without `SECURITY_SQOS_PRESENT` (Node's `net.connect`; std's default) cannot be impersonated before the server has read from the pipe (`ERROR_CANNOT_IMPERSONATE`), so the control API closed the Node test client as unidentified; `accept` now gives such a client 2 s to write, reads what it wrote into the stream's `unread` buffer (returned first by the next reads), and identifies it then (tests `a_client_without_sqos_is_identified_once_it_writes`, `a_silent_client_without_sqos_is_not_identified`); (2) `core::catalog::source::parse_file_source` required a leading `/`, so every file source of a team catalog (chosen or opened from Explorer) was refused on Windows with "The file path contains an invalid character."; it now takes the OS's absolute paths (`Path::is_absolute`: drive and UNC paths on Windows, unchanged on macOS) and refuses device and verbatim prefixes (`\\.\`, `\\?\`). **Results:** macOS smoke EN and HU passed on the final tree (the maintainer approved the runs); Windows smoke EN and HU passed in `winvpn-dev`'s RDP session (VM, `winvpn-work-slot1`). Mac: `cargo fmt --check`, clippy `-D warnings` (app, core with vault), app tests, core `catalog_source`, `cfg_rule`, `check-windows.sh`, `test-win-smoke.sh` 36/36, `test-win-remote.sh`, UI tests 169/169. Windows: clippy `-D warnings` (app, winsys, core, platform-win), winsys `pipe` 27/27 (+ the rest of winsys), core `catalog_source`, platform-win green except `service_client::system_status_reads_the_services_facts`, which fails because the VM now has OpenVPN 2.7.7 (row "update"; the test expects 2.7.8 or none): an environment fact, not this task's.

## Task 21: CI, the admin job and the release workflow

**Goal:** CI tests the service like the app (the console tests in `windows`, the gates in `msi`), and a new `windows-admin` job installs OpenVPN and the fresh MSI on the administrator runner and runs the admin test set, including an OpenVPN connection end to end through the installed service; the release workflow's notes describe the service.

**Files:**
- Modify: `.github/workflows/ci.yml`, `.github/workflows/release.yml`, `docs/RELEASING.md`
- Create: `crates/helper/tests/openvpn_e2e.rs` (Windows, admin, ignored), `scripts/ci-install-openvpn.sh`

- [x] **Step 1: `windows` job** — before the test step add `scripts/fetch-wireguard-nt.sh` and `cargo build --locked --target x86_64-pc-windows-msvc -p macvpn-helper` (the platform-win tests start the helper's debug console). The test step's package list is unchanged (it already has `-p macvpn-helper -p macvpn-winsys`).

- [x] **Step 2: `windows-admin` job**

```yaml
  windows-admin:
    needs: msi
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
      - uses: actions/download-artifact@<the SHA the release workflow pins> # <its version>
        with:
          name: winvpn-msi
          path: dist/windows
      - name: Rust toolchain (x64)
        run: |
          RUST_VERSION=$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml)
          rustup toolchain install "$RUST_VERSION" --profile minimal -t x86_64-pc-windows-msvc
      - name: OpenVPN Community (the pinned MSI with the plan's features, decision 4)
        run: scripts/ci-install-openvpn.sh
      - name: Install WinVPN
        run: |
          (cd dist/windows && sha256sum -c WinVPN-*-x64.msi.sha256)
          MSYS_NO_PATHCONV=1 msiexec /i "$(cygpath -w dist/windows/WinVPN-*-x64.msi)" /qn /norestart /l*v "$(cygpath -w "$RUNNER_TEMP/winvpn-install.log")"
          sc query WinVPN | grep -q RUNNING
      - name: wireguard-nt for the console test
        run: scripts/fetch-wireguard-nt.sh
      - name: The admin test set
        run: |
          cargo test --locked --target x86_64-pc-windows-msvc -p macvpn-helper --test service_admin --test wireguard_admin --test openvpn_installed --test openvpn_e2e -- --ignored
          cargo test --locked --target x86_64-pc-windows-msvc -p macvpn-winsys --test service_pipe -- --ignored
      - name: Logs on failure
        if: failure()
        run: |
          cat "$RUNNER_TEMP/winvpn-install.log" | iconv -f UTF-16LE -t UTF-8 | tail -200 || true
          cat 'C:\ProgramData\WinVPN\service.log' || true
```

Look up the `actions/download-artifact` pin used in `release.yml` and use the same SHA. `scripts/ci-install-openvpn.sh`: reads `scripts/pins/openvpn.txt`, downloads the x64 MSI with `curl -fsSL`, refuses any SHA-256 but the pin, checks `Get-AuthenticodeSignature` (Valid, the pinned signer), runs `msiexec /i … /qn ADDLOCAL=<features>`, then checks that `ovpn-dco` and `tap0901` are installed driver services (it leaves the Interactive Service as the MSI set it: the CI install is not WinVPN's; Task 17's unit test and the "WinVPN 2b" checklist cover the disabling) and that the `.sys` versions equal those recorded in Task 10's commit; refuses to run unless `CI` is set (it changes the machine).

`crates/helper/tests/openvpn_e2e.rs` (ignored, in `scripts/ignored-everywhere.txt`):

```rust
//! OpenVPN through the installed WinVPN Service to a local OpenVPN server on loopback (CI's windows-admin job).
#![cfg(windows)]

use macvpn_core::service_proto::{self as proto, LogSlice, PIPE_NAME};
use macvpn_winsys::pipe::{self, ServerTrust};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const OPENSSL: &str = r"C:\Program Files\Git\usr\bin\openssl.exe";
const ID: &str = "0F1E2D3C-4B5A-6978-8796-A5B4C3D2E1F1";

fn openssl(dir: &Path, args: &[&str]) {
    let st = Command::new(OPENSSL).current_dir(dir).args(args).status().unwrap();
    assert!(st.success(), "openssl {args:?}");
}

/// A throwaway CA, server and client (prime256v1, valid 1 day), nothing committed.
fn pki(dir: &Path) {
    for name in ["ca", "server", "client"] {
        openssl(dir, &["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", &format!("{name}.key")]);
    }
    openssl(dir, &["req", "-new", "-x509", "-days", "1", "-key", "ca.key", "-subj", "/CN=WinVPN test CA", "-out", "ca.crt"]);
    for name in ["server", "client"] {
        openssl(dir, &["req", "-new", "-key", &format!("{name}.key"), "-subj", &format!("/CN={name}"), "-out", &format!("{name}.csr")]);
        openssl(dir, &["x509", "-req", "-days", "1", "-in", &format!("{name}.csr"), "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial", "-out", &format!("{name}.crt")]);
    }
}

fn openvpn_exe() -> PathBuf {
    let out = Command::new(r"C:\Windows\System32\reg.exe").args(["query", r"HKLM\SOFTWARE\OpenVPN", "/v", "exe_path", "/reg:64"]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let line = text.lines().find(|l| l.contains("exe_path")).expect("OpenVPN Community is installed");
    PathBuf::from(line.split("REG_SZ").nth(1).unwrap().trim())
}

fn server(dir: &Path) -> Child {
    let mut child = Command::new(openvpn_exe())
        .current_dir(dir)
        .args([
            "--dev", "tun", "--windows-driver", "tap-windows6", "--proto", "udp4", "--port", "11940", "--server",
            "10.201.0.0", "255.255.255.0", "--topology", "subnet", "--ca", "ca.crt", "--cert", "server.crt", "--key",
            "server.key", "--dh", "none", "--data-ciphers", "AES-256-GCM", "--verb", "3",
        ])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        match lines.next() {
            Some(Ok(l)) if l.contains("Initialization Sequence Completed") => break,
            Some(Ok(_)) => {}
            _ => panic!("the test server did not start"),
        }
    }
    std::thread::spawn(move || for _ in lines {}); // keep draining its output
    child
}

fn call(args: &[&str], body: &[u8], timeout: Duration) -> proto::Response {
    let mut s = pipe::connect_with(PIPE_NAME, Duration::from_secs(5), ServerTrust::LocalSystem).unwrap();
    s.set_read_timeout(Some(timeout)).unwrap();
    proto::write_request(&mut s, args, body).unwrap();
    proto::read_response(&mut s).unwrap()
}

#[test]
#[ignore = "admin: needs the installed WinVPN Service and OpenVPN Community (CI windows-admin)"]
fn admin_an_openvpn_connection_comes_up_through_the_service() {
    let dir = std::env::temp_dir().join(format!("winvpn-e2e-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    pki(&dir);
    let mut srv = server(&dir);
    let read = |n: &str| std::fs::read_to_string(dir.join(n)).unwrap();
    let config = format!(
        "client\ndev tun\nproto udp4\nremote 127.0.0.1 11940\nnobind\ndata-ciphers AES-256-GCM\nverb 3\n<ca>\n{}</ca>\n<cert>\n{}</cert>\n<key>\n{}</key>\n",
        read("ca.crt"),
        read("client.crt"),
        read("client.key")
    );
    let body = format!("config {}\n{config}", config.len());
    let r = call(&["up", "openvpn", ID, "--lang", "en"], body.as_bytes(), Duration::from_secs(90));
    assert_eq!(r.code, 0, "{}", String::from_utf8_lossy(&r.stderr));
    let st = String::from_utf8(call(&["status"], b"", Duration::from_secs(20)).stdout).unwrap();
    assert!(st.contains(ID) && st.contains("\"connected\"") && st.contains("10.201.0."), "{st}");
    let log = LogSlice::parse(&call(&["log", ID, "0"], b"", Duration::from_secs(20)).stdout).unwrap();
    let text = String::from_utf8_lossy(&log.data);
    assert!(text.contains("Initialization Sequence Completed"));
    assert!(!text.contains("BEGIN EC PRIVATE KEY") && !text.contains("BEGIN PRIVATE KEY"));
    assert_eq!(call(&["down", "openvpn", ID], b"", Duration::from_secs(30)).code, 0);
    assert_eq!(call(&["status"], b"", Duration::from_secs(20)).stdout, b"[]\n");
    let _ = srv.kill();
    let _ = std::fs::remove_dir_all(&dir);
}
```

The client config has no `auth-user-pass`, so the frame carries no secret lines. Add a second test in the same file, `admin_a_tap_windows6_connection_comes_up_through_the_service`, with the same server and a client config that adds `cipher AES-256-CBC` and `data-ciphers AES-256-CBC` (server: `--data-ciphers AES-256-GCM:AES-256-CBC`) → `choose_driver` picks TAP-Windows6 (`--disable-dco`); the log names the TAP-Windows6 adapter; `status` connected. (A `dev tap` client needs a TAP server on another adapter: the maintainer's checklist covers it.) If the runner cannot bring up DCO against a TAP server on loopback (record the job's log), keep the test ignored everywhere, note it in RELEASING.md and move this check to the maintainer's checklist with a real server; never weaken the service to make it pass.

- [x] **Step 3: Release workflow and RELEASING.md**

`release.yml`: `build-windows` runs `scripts/fetch-wireguard-nt.sh` before `scripts/build-msi.sh` (the script also runs it); the WinVPN notes paragraph (only when the MSIs are attached) adds: "WinVPN installs the WinVPN Service (connects OpenVPN and WireGuard) and the signed wireguard.dll from WireGuard; OpenVPN Community is installed from System Status when needed. / A WinVPN telepíti a WinVPN szolgáltatást (OpenVPN- és WireGuard-kapcsolatok) és a WireGuard aláírt wireguard.dll-jét; az OpenVPN Community-t szükség esetén a Rendszerállapotban telepítheted." `docs/RELEASING.md`, section "WinVPN": how to change the OpenVPN pin (Task 10's procedure), the wireguard-nt pin (Task 14's), and that the CI `windows-admin` job must be green on the temporary branch before a release with MSIs.

- [x] **Step 4: Check and commit**

Run: `ruby -ryaml -e 'YAML.load_file(".github/workflows/ci.yml"); YAML.load_file(".github/workflows/release.yml")' && bash -n scripts/ci-install-openvpn.sh && scripts/check-windows.sh`
Expected: no error. The workflows run only when the maintainer pushes the temporary squashed branch (never from this plan); record the result in Task 23.

```bash
git add .github/workflows docs/RELEASING.md crates/helper/tests/openvpn_e2e.rs scripts/ci-install-openvpn.sh scripts/ignored-everywhere.txt
git commit -m "ci: the WinVPN Service in CI, and an administrator job that installs and tests it" -m "windows builds the helper's console for the client tests; windows-admin installs the pinned OpenVPN (DCO, TAP-Windows6) and the fresh MSI, then runs the admin set (service, pipe DACL, data directory, WireGuard adapter, OpenVPN end to end on loopback with DCO and with TAP-Windows6)." -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**As built (Task 21):** as planned, with these differences. **`windows` job:** one step "wireguard-nt (the pinned SDK) and the helper's debug console" (`scripts/fetch-wireguard-nt.sh`, then `cargo build --locked --target x86_64-pc-windows-msvc -p macvpn-helper`) before the unchanged test step. **`rust` job:** also `scripts/ci-install-openvpn.sh --dry-run` (the pins parse; no network). **`windows-admin`:** the plan's job with the existing toolchain step (exact-version checks), its own build cache (`Swatinem/rust-cache`, the pinned SHA, `shared-key: windows-x64-admin`, saved only on main/develop pushes), `actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2` (release.yml's pin; no new action); the WinVPN install checks the `.sha256`, waits up to 30 s for `RUNNING` and prints `sc qc WinVPN`; the test command adds `--test-threads=1` (the WireGuard and OpenVPN tests create adapters); on failure it prints both install logs with NUL bytes removed (`tr -d '\000'`: works for ANSI and UTF-16 logs, unlike the sketch's `iconv`), `service.log` and the masked connection logs. **`scripts/ci-install-openvpn.sh`:** x64 only (the runner); validates the pin values (URL on `swupdate.openvpn.org`, 64 hex, feature list), `--dry-run` prints the plan and exits; otherwise refuses without `CI` and outside Git Bash, downloads with `--proto =https --proto-redir =https`, checks SHA-256 and `Get-AuthenticodeSignature` (Valid, `OpenVPN Inc.`), runs `msiexec /qn /norestart ADDLOCAL=<features> /l*v` (0 or 3010), then checks `exe_path`'s file version starts with the pinned version and that `ovpn-dco` / `tap0901` exist, are not disabled (`Start` ≠ 4) and have the `.sys` `FileVersionRaw` **2.8.13.0** / **9.27.0.0** — constants in the script (`DRIVERS`), not pin keys, because `ovpn_pins::parse` refuses unknown keys; RELEASING.md says to change them with the pin. The PowerShell part was run read-only on the Windows machine as the standard user (OpenVPN there is 2.7.7 from CP2's winget install: drivers 2.8.13.0 / 9.27.0.0 as recorded; a missing driver service exits 1). **`openvpn_e2e.rs`:** the server runs with `--disable-dco` instead of the sketch's `--windows-driver tap-windows6` (2.7 ignores that option, Task 10); the test makes its own TAP-Windows6 adapters with OpenVPN's `tapctl.exe create --hwid root\tap0901` (one for the DCO test's server, two for the TAP-Windows6 test) and deletes them; the two tests are serialized (a mutex) and use their own IDs and ports (11940, 11941); the server's output is read by a thread with a 60 s deadline (the sketch's loop could block forever) and is part of every failure message together with the connection log; after `down` `status` must not list the ID (not exactly `[]`, so it holds with other connections of the same user); the DCO test asserts no TAP-Windows6 retry, the TAP-Windows6 test that the connection log mentions `tap-windows` (case-insensitive: OpenVPN's own adapter/driver lines — **unverified wording**, check the first CI log). Both tests are in `scripts/ignored-everywhere.txt`. **release.yml:** `build-windows` runs `scripts/fetch-wireguard-nt.sh` as its own step before `build-msi.sh`; the WinVPN notes paragraph (only when `WINVPN_MSI_IN_RELEASE` is `true`) has the plan's sentence; the asset list is unchanged (MSIs reach a release only from 2.0.0). `ci-green` needs no change: it requires every CI job, `windows-admin` included. **RELEASING.md:** the job list, the admin job, the wireguard-nt and OpenVPN pin procedures, and that `windows-admin` must be green on the temporary branch before a release with MSIs. **Checks:** Mac: `cargo fmt --check`, helper clippy `-D warnings --all-targets`, `scripts/check-ignored.sh`, `scripts/check-windows.sh`, both workflows parse (`ruby -ryaml`), shellcheck of the new script and of every `run` block of `windows` and `windows-admin`, the script's dry run and refusals (no `CI`; not Windows; bad arguments). Windows (standard user, slot2): `openvpn_e2e` compiles and lists its two tests as ignored, helper clippy `-D warnings --all-targets` clean. Not run: the job itself (only on the maintainer's temporary branch).

## Task 22: documentation and the "WinVPN 2b" checklist

**Goal:** users know how WinVPN connects, installs OpenVPN and updates itself; developers have the map of the service; the maintainer has a Hungarian checklist for everything only a desktop or an administrator can check.

**Files:**
- Modify: `docs/architecture.md`, `docs/winvpn-user-guide.en.md`, `docs/winvpn-user-guide.hu.md`, `docs/manual-test-checklist.md`, `README.md`, `docs/superpowers/specs/2026-10-20-cross-platform-winvpn-design.md` (notes only)

- [x] **Step 1: `docs/architecture.md`**
- The intro and "The crates": WinVPN connects OpenVPN and WireGuard through the WinVPN Service; native VPNs in 2c. `helper/`: "`windows` (the WinVPN Service)".
- A section "The WinVPN Service" after "helper": the binary and its install name; `service` / `console` (debug); the pipe protocol (`service_proto`, the commands, `SERVICE_VERSION`); the pipe's DACL and the client's owner check; identity and ownership; limits; the data directory and its degraded mode; the job; logoff; the OpenVPN engine (trust checks, argv, the management port's owner check, the in-process bridge); the WireGuard engine (the pin, the loader, IP Helper, the adapter's life); the logs and `auth-state`; what is tested where (pure on every OS, the console over SSH, the admin set in CI's `windows-admin` and on the VM).
- `winsys`: the new modules (`trust`, `version`, `acl_check`, `dll`, `known`, `Endpoint`, `ServerTrust`, `Protection::Admins`).
- platform-api: the curl layer (`curl::{Curl, http, catalog}`), `HelperClient::log_source`, `SetupReport::{engine, later_kinds}`, `SystemSetup::later_note`.
- platform-win: the service client, System Status' rows, the OpenVPN installer, the updater and its relauncher, System32's curl.
- "Checking Windows": `scripts/win-smoke.sh`, the admin test set and `windows-admin`, `scripts/fetch-wireguard-nt.sh`; "The WinVPN MSIs": the service, the DLL and their gates.
- "Adding a platform": step 5 (the helper) and step 9 (the OpenVPN tier) done for Windows in 2b.

- [x] **Step 2: the user guides** (EN and HU, the same structure; the 2a glossary)
- Replace "This version (preview)" with what works: OpenVPN and WireGuard connections, MFA, the live log; native Windows VPNs (L2TP, IKEv2, SSTP, Cisco IPsec) later.
- "The WinVPN Service": installed with WinVPN, runs in the background as the system; each user's connections are their own (another user of the PC cannot see or end them, but while a VPN is up it carries the whole PC's traffic, as on any Windows VPN); connections end at logoff (decision 2).
- "OpenVPN Community": System Status installs it (winget, else the official installer), one administrator confirmation; what is installed (decision 4: OpenVPN 2.7, `openvpn.exe`, the DCO and TAP-Windows6 drivers; no OpenVPN GUI; OpenVPN's Interactive Service disabled when WinVPN installed OpenVPN, untouched on an existing installation); which driver a connection gets (DCO by default; TAP-Windows6 for compression, older ciphers, `fragment`, proxies, static keys and `dev tap`) and that the Log tab names it; "Repair" when a driver is missing; compression is allowed because servers still use it, but it weakens the encryption of compressible traffic (VORACLE): ask the server's administrator to turn it off; TAP adapters stay in Network Connections after uninstalling (they belong to OpenVPN).
- "WireGuard": bundled, nothing to install; `FwMark` and `Table` values other than `auto` / `off` are not supported.
- "Updates": WinVPN checks for updates; installing one asks for an administrator's confirmation (decision 1), WinVPN restarts itself.
- "Uninstalling": the service and `wireguard.dll` go with WinVPN; OpenVPN Community, its two drivers and its TAP adapters stay (remove OpenVPN in Installed apps); `C:\ProgramData\WinVPN` keeps the masked connection logs: an administrator may delete it.
- "Certificates from the Windows certificate store (`cryptoapicert`) are not supported" (decision 3).

- [x] **Step 3: the checklist** — a section `## WinVPN 2b: a szolgáltatás, OpenVPN, WireGuard (1.5.0-s build)` at the top of `docs/manual-test-checklist.md`, in the 2a section's style (prerequisites, `Windows build száma: ___`, a checkbox per check, the expected result after "→"). Subsections and items (write each as a full Hungarian sentence):
  - **Telepítés és szolgáltatás (rendszergazda):** a 2a-s WinVPN fölé telepítve → frissít, nem második példány; `sc qc WinVPN` → `LocalSystem`, `AUTO_START`, `"C:\Program Files\WinVPN\WinVPNService.exe" service`; `sc query WinVPN` → `RUNNING`; `icacls C:\ProgramData\WinVPN` → csak SYSTEM és Administrators; a `C:\Program Files\WinVPN` tartalma: `WinVPN.exe`, `WinVPNService.exe`, `wireguard.dll`, `THIRD-PARTY-NOTICES.txt`; a szolgáltatás leállítása (`sc stop WinVPN`) kapcsolattal → az alagút és az `openvpn.exe` eltűnik; újraindítás → az app „megszakadt” állapotot mutat; egy normál felhasználó által előre létrehozott `C:\ProgramData\WinVPN` (a telepítés előtt, saját jogosultságokkal) → a szolgáltatás nem javítja, a Rendszerállapot a „nem biztonságos jogosultságok” szöveget mutatja, minden kapcsolódás ezzel tér vissza; a rendszergazda törli a mappát és újraindítja a szolgáltatást → rendben.
  - **Az admin teszthalmaz:** emelt Git Bashben `cargo test --locked -p macvpn-helper --test service_admin --test wireguard_admin --test openvpn_installed -- --ignored` és `cargo test --locked -p macvpn-winsys --test service_pipe -- --ignored` → mind zöld.
  - **Rendszerállapot:** a három sor (WinVPN szolgáltatás, OpenVPN Community, WireGuard) és a natív VPN-ekről szóló megjegyzés; OpenVPN nélkül piros sor „Telepítés” gombbal; a régi OpenVPN „Frissítés”; a szolgáltatás leállítva → „A WinVPN szolgáltatás nem érhető el.” és minden kapcsolat ezt mutatja.
  - **OpenVPN telepítése:** wingettel (Windows 11) egy UAC-kérdés, a kimenet élőben; telepítve az OpenVPN 2.7.8 (`openvpn.exe`) és a DCO és a TAP-Windows6 illesztőprogram (`pnputil /enum-drivers`: ovpn-dco, tap0901; Wintun nincs), nincs OpenVPN GUI; a sor a két illesztőprogramot (DCO, TAP-Windows6) verzióval mutatja; UAC elutasítva → „Megszakítva”; winget nélkül (ha van ilyen gép) a hivatalos MSI; a hálózat nélkül → hibaüzenet, semmi nem települ; a TAP-Windows6 eltávolítva (Telepített alkalmazások → OpenVPN → Módosítás) → „Javítás” gomb, a TAP-os kapcsolat érthető hibát ad, a többi működik; „Javítás” → visszakerül.
  - **OpenVPN Interactive Service:** a WinVPN által telepített OpenVPN után `sc qc OpenVPNServiceInteractive` → `START_TYPE: 4 DISABLED`, `sc query OpenVPNServiceInteractive` → `STATE: 1 STOPPED`; egy WinVPN-es frissítés vagy „Javítás” után is így marad; ha az OpenVPN-t előtte kézzel telepítették (a WinVPN csak használja), a WinVPN nem nyúl hozzá: `AUTO_START` és `RUNNING` marad; a kapcsolatok mindkét esetben működnek.
  - **Illesztőprogram kapcsolatonként:** egy egyszerű konfiguráció → DCO (a Napló fül „ovpn-dco” eszközt mutat); `comp-lzo` vagy `cipher AES-256-CBC` + `data-ciphers AES-256-CBC` → TAP-Windows6; `dev tap` egy TAP-szerverhez → TAP-Windows6; egy szerver, amely tömörítést küld (push) → az első DCO-s kísérlet után egyszer TAP-Windows6-tal újrapróbálja, a naplóban az ok; `windows-driver` sor importáláskor → „Forbidden directive”; két TAP-os kapcsolat egyszerre → a második érthető hibát ad (egy TAP-adapter van).
  - **OpenVPN-kapcsolatok:** jelszavas; MFA-kód (CRV1 és statikus kihívás) a kódkérő ablakban; webes bejelentkezés a böngészőben; rossz jelszó → „Authentication failed”;  `win-sys` vagy `cryptoapicert` sor importáláskor → „Forbidden directive”, nyugtázással sem engedi; a Napló fül élőben, jelszó és kód sehol (a `C:\ProgramData\WinVPN\logs` fájljaiban sem); hibakereső kapcsolódás → bővebb napló.
  - **WireGuard:** csatlakozás; teljes alagút (`AllowedIPs = 0.0.0.0/0, ::/0`) → böngészés megy, `nslookup` az alagút DNS-ét használja, `route print` mutatja az útvonalat; `Table = off` → nincs útvonal; bontás → az adapter eltűnik (`Get-NetAdapter`); host nevű végpont feloldódik.
  - **Több felhasználó:** egy második normál fiók (gyors felhasználóváltás) nem látja és nem bontja az első kapcsolatát; az első kijelentkezik → a kapcsolatai bomlanak (2. kérdés); zárolás és felhasználóváltás → maradnak.
  - **Frissítés:** a hibakereső build `--test-install-msi` kapcsolójával egy 1.5.1-es MSI → kilépési kérdések, UAC, a szolgáltatás újraindul, a WinVPN magától visszajön, a következő indításkor értesítés; csonka MSI → hibaüzenet a napló útvonalával.
  - **Csapatkatalógus HTTPS-en:** feliratkozás tokennel, frissítés, 304; a token nem látszik a Feladatkezelő parancssor oszlopában a `curl.exe`-nél.
  - **Eltávolítás:** a szolgáltatás és a `wireguard.dll` eltűnik (`sc query WinVPN` → nincs ilyen); az OpenVPN Community a két illesztőprogrammal és a TAP-adapterekkel, valamint a `C:\ProgramData\WinVPN` marad.
  - **Smoke:** `scripts/win-smoke.sh en` és `hu` → zöld (a `winvpn-dev` be van jelentkezve a VM konzolján).
  - **ARM64:** az arm64 MSI egy ARM64 gépen (ha nincs: **nem tesztelt**, 5. kérdés).

- [x] **Step 4: README and the spec** — README's "WinVPN (preview)" says what 2b adds. The spec gets notes (not rewrites) under 4.1 ("As planned in 2b:" the pipe's create-instance right and the owner check, the envelope, the console test mode, the data directory's squatting rule, logoff), under 4.4 (the OpenVPN features of decision 4 and the per-connection driver choice, winget's trust and the fallback to the pinned MSI), and in section 9 phase 2 ("2b: service, OpenVPN, WireGuard; 2c: native RAS").

- [x] **Step 5: Check and commit**

Run: `grep -rniE 'alpha.?vet' docs README.md` → no output; `grep -rnE '([0-9]{1,3}\.){3}[0-9]{1,3}' docs/manual-test-checklist.md docs/winvpn-user-guide.*.md` → only documentation addresses (`10.x`, `192.0.2.x`, `127.0.0.1`), never the VM's; `node scripts/l10n-baseline.mjs --check` → PASS.

```bash
git add docs README.md
git commit -m "docs: WinVPN 2b – the service, OpenVPN, WireGuard, updates; the Windows checklist" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

**As built (Task 22, 2026-10-25; done together with 2c's Task 16 and G-10 on the branch `docs20`, after 2c and the features plan were merged).** Docs only. Differences from the steps above:
- **One pass for 2b and 2c.** The guides, the architecture map and the checklist describe the 2.0.0 state (service, OpenVPN, WireGuard, the native VPNs, system VPNs), not a 2b-only intermediate; the "native Windows VPNs later" text of Step 2 is gone.
- **User guides** (`docs/winvpn-user-guide.{en,hu}.md`, same heading structure, 98 headings each): restructured to MacVPN's numbering 1–16 (new 1.3 The WinVPN Service, 1.4 OpenVPN Community, 1.5 WireGuard and the Windows VPN client, 5.2 MFA, 5.3 Credentials, 5.6 DNS, 5.7 Quitting, 6 Debug mode and the log, 7 Troubleshooting, 8 Updates, 9 Uninstalling incl. G-9; the vault, folders, credentials, backup, FAQ and catalog chapters moved from 9–14 to 11–16, their text kept, HTTPS catalogs added). The 2.0 features of the features plan's Task 16 are kept, not repeated; its "This version (preview)" section and the 1.5.0 texts are replaced.
- **Checklist:** `## WinVPN 2b: a szolgáltatás, OpenVPN, WireGuard, frissítés (2.0.0-s build)` (49 items) below the "WinVPN 2c" section, written as post-release checks (the maintainer tests after the release); the CP1 carry-overs (elevated admin set, MFA/web sign-in, the per-driver configs, the second user and logoff) are marked "(CP1-ből)" and use the VPN lab's OpenVPN/WireGuard profiles; CP2's items that passed are kept as regression checks. Every PowerShell command names the `.exe` (`sc.exe`, `reg.exe`, `icacls.exe`, `pnputil.exe`).
- **architecture.md:** "The WinVPN Service" is a subsection of "helper" (not a top-level section); winsys lists every module (2b and 2c); platform-api lists the 2b and 2c additions; platform-win the OpenVPN installer, the updater, System32's curl, the RAS engine, G-1/G-7/G-9; "Checking Windows" (smoke on both OSes, `windows-admin`), "The WinVPN MSIs" (service exe and DLL gates) and "Adding a platform" (steps 5, 9 done, a new step 13) updated.
- **README and spec:** README's "WinVPN (preview)" became "WinVPN" with the 2.0 state (EN and HU); the spec got notes under 2 (Cisco), 4.1, 4.2, 4.4, 5 and 9.
- **Checks:** `grep -rniE 'alpha.?vet' docs README.md` → nothing; the only IPv4 literals in the guides and the checklist are documentation ones (`10.20.30.x`, the lab's `10.99.x`, `0.0.0.0`, driver versions); `node scripts/l10n-baseline.mjs --check` → 1114 identical; every relative link and anchor of `docs/*.md`, the release notes and README resolves (a GitHub-slug script).

## Task 23: verification

**Goal:** proof that MacVPN is unchanged and that the 2b MSI does what the goal says, on the Mac, on the Windows machine, in CI and at the maintainer's desktop.


  *Watch item (2026-10-22, Task 3):* one `win-remote.sh test` run on the VM ended with "error: 1 target failed" without the failing target being visible (filtered output, a run moved to the background after a timeout); two later full runs were clean. If it recurs, capture the full log and name the test.

  *Watch item (2026-10-22, Task 6):* macOS smoke EN failed twice in different steps (`manage: ERROR no result`; folders drag and drop) and passed the third time, while four other agents were building on the Mac; HU passed first time. Most likely the maintainer was using the Mac at the time. Rule from 2026-10-22: run the smoke only when a change to the macOS app really needs it, and ask the maintainer first (they work on the same Mac).

- [ ] **Step 1: MacVPN** (on the Mac; record each result in the commit body) — exactly 2a's Task 19 Step 1 list (fmt, clippy, tests debug and release, `compat_1_4`, the l10n baseline, the notices, `test-root.sh`, `test-sign-release.sh`, `check-windows.sh`, `check-ignored.sh`, the four `cargo tree` lines, the UI tests and build, `build-dmg.sh` + `bundle-baseline.sh dist/MacVPN.app`), plus `SMOKE_LANG=en scripts/smoke-manage.sh` and `SMOKE_LANG=hu scripts/smoke-manage.sh` with the display unlocked. Expected: all green; the bundle baseline reports no difference beyond what 2a's normalizes; `mvpn`'s string literals per architecture differ from 1.5.0 only by new `strings.json` entries (2a's method).

- [ ] **Step 2: Windows, automated** (the test machine, standard user)

Run: `scripts/win-remote.sh test && scripts/win-remote.sh run 'scripts/check-ignored.sh --target x86_64-pc-windows-msvc && cargo clippy --workspace --all-targets --locked --target x86_64-pc-windows-msvc -- -D warnings && cargo check --workspace --all-targets --locked --target aarch64-pc-windows-msvc' && scripts/win-remote.sh msi --arch both && scripts/win-remote.sh fetch dist/windows ./dist && scripts/win-smoke.sh en && scripts/win-smoke.sh hu`
Expected: all green; two MSIs with `.sha256` (record their hashes).

- [ ] **Step 3: GitHub CI** — ask the maintainer to push the temporary squashed branch and approve the run; record each job's result and duration (`rust`, `node`, `dmg`, `windows`, `windows-node`, `msi`, `windows-admin`); delete the branch and the runs afterwards (2a's procedure). A failure only CI shows is a finding with its fix commit.

- [ ] **Step 4: CP3 — the maintainer's desktop run** of the whole "WinVPN 2b" checklist section on the final x64 MSI; every unchecked item is a finding with its fix task.

- [ ] **Step 5: Record** — tick the plan's boxes; commit `docs(plan): 2b verified` with the results (which checks, which machine, the Windows build number, the CI run, the checklist outcome).

## Task 24: independent security review

**Goal:** a reviewer who did not write the code checks the privileged surface before 2b is done (spec 9: an independent security review before 2.0.0; this is the 2b part of it).

- [ ] **Step 1: Request it** (superpowers:requesting-code-review), with this focus list:
  - The service pipe: the DACL (no `FILE_CREATE_PIPE_INSTANCE`, no `WRITE_DAC` for INTERACTIVE, NETWORK denied), `FILE_FLAG_FIRST_PIPE_INSTANCE`, the squatter case (the service waits; the client refuses a non-SYSTEM owner before sending), identification-level identity per connection, `RevertToSelf` or abort.
  - The request handler: every field of a request is untrusted; ownership by SID (no oracle between "not yours" and "unknown"), limits, the per-thread language, zeroization of the body, nothing secret in `service.log` or the connection logs (grep every log call), the degraded mode.
  - The data directory: the squatting rule, creation with the protected DACL, reparse points refused below it, names only from UUIDs, the sweep; the MSI never touching it.
  - OpenVPN: the trust checks (registry view, admin-only chain, signer, version, the two drivers), the driver choice (`choose_driver` reads only validated directives, never `windows-driver`; `--disable-dco` the only driver option; the one TAP-Windows6 retry), the Interactive Service disabled only on WinVPN's own installs, TAP-Windows6's extra surface (an adapter any user's OpenVPN could open; `allow-nonadmin` and `dev-node` forbidden), the argv (nothing from the request), the cleared environment, the job, the management port's owner check before the password, the password file, the in-process bridge (only `ManagementCommand`s), the Windows validator tier (every directive that could run code or open a file as SYSTEM).
  - WireGuard: the DLL hash at load time vs the build pin, `SetDefaultDllDirectories`, `LoadLibraryExW` flags, the struct encoding (keys zeroized), DNS and routes only on the service's adapters, the adapter's cleanup on every failure path.
  - The app: the client's owner check, `log_source` and `auth-state` limits, the OpenVPN installer (winget path from the known folder, the pinned MSI's hash and signer, the deny-write handle, `msiexec` parameters), the updater (`verify_trusted_for(WinVpnV1, asset, …)` with this architecture's asset, never `verify_trusted`; the relauncher; the debug-only flags absent from release builds).
  - The curl layer move: macOS' argv byte for byte; Windows' curl from System32 only; the token never in argv.
  - MacVPN unchanged: Task 23 Step 1's evidence.
- [ ] **Step 2:** fix each finding in its own commit (`fix: review findings – …`, with a test where it is code), rerun Task 23 Steps 1–2, give the maintainer a fresh MSI for the items the fixes touch, and record the review and the fixes in `docs(plan): 2b review`.

---

## Spec coverage (self-review)

| Spec / brief | Requirement | Task |
|---|---|---|
| 4.1 | a Windows service as LocalSystem, installed by the MSI | 12, 15 |
| 4.1 | `\\.\pipe\WinVPN`, DACL for interactive users and SYSTEM | 3, 12 |
| 4.1 | each request bound to the caller's token SID; the SID owns its connections | 3, 8, 12 |
| 4.1 | the root layer 8 protocol (config + secrets), the same validators, zeroized, never logged | 1, 7, 8 |
| 4.1 | only its own operations: OpenVPN (DCO, management bridge), WireGuard (wireguard-nt), DNS on its adapters, status; never arbitrary commands | 8, 10, 13, 14 |
| 4.1 | state and logs in `C:\ProgramData\WinVPN` (SYSTEM + Administrators); the user's log lines relayed | 6, 8, 12, 16 |
| 4.1 | a service VERSION the app checks and the MSI updates | 1, 15, 16 |
| Brief 1 | reuse `crates/helper` shared logic; service install/start/stop/upgrade by WiX; uninstall cleanup | 7, 8, 15 (ProgramData deliberately kept: resolved points) |
| 4.4, brief 2 | OpenVPN detection (version, registry path, DCO, TAP-Windows6), winget first, pinned MSI by SHA-256, updates and repair, UAC elevation, what is verified; the driver per connection (decision 4) | 10, 13, 16, 17 |
| 5, brief 2 | the Windows OpenVPN tier confirmed | 2 |
| 4.4, brief 3 | the signed `wireguard.dll` in the MSI, pinned and hash-checked at build time, loaded only by the service; adapter, DNS, routes; the WireGuard validator on Windows | 2, 9, 14, 15 |
| Spec 7 | the `wireguard.dll` gate (deferred from 2a) | 14, 15 |
| Brief 4 | `HelperClient` / `NativeController` on Windows; System Status rows; engine-missing only when the service is absent or too old; MFA through the bridge; the live log | 6, 11, 16 |
| 4.3, brief 5 | the Windows updater with `verify_trusted_for(WinVpnV1, asset, …)` (2a review I7), `msiexec` with elevation, restart | 18 |
| Brief 5 (2a decision 4) | HTTPS team catalogs and the update check on Windows; the HTTP client decided | 5, 18, 19 |
| Spec 8, brief 5 | the Windows smoke run | 20 |
| Spec 8 | helper protocol tests on Windows, a service harness | 8, 12 (console), 21 (admin) |
| Brief 6 | native RAS VPNs stay "later" (2c) | 11, 16 |
| Testing reality | standard-user SSH; admin and desktop steps as ignored tests + CI admin job + Hungarian checklist; checkpoints after user-visible waves | Rules, CP1–CP3, 21, 22 |
| Security bar | fail closed, per-request identity, no injection, no traversal, secrets in memory only, DLL search, pins for every binary, independent review | Rules, 3, 4, 8, 12–15, 17, 18, 24 |
| Constraints | MacVPN unchanged; cfg/unsafe rule; no new crate in the lock; nothing pushed; no forbidden name; no VM address | Rules, 5, 6, 7, 23 |

**Placeholder scan:** values that can only be known when the task runs (the pinned OpenVPN version, its hashes, signer and feature names; wireguard-nt's hashes; the WiX component GUIDs; the update repository ID) are produced by an explicit step with its command and recorded in a pin file or the commit, and the tests check their shape. Where the plan names an API detail it could not verify from here (OpenVPN's management login strings, `windows-sys` 0.61 type names, Tauri's WiX directory id, `icacls` output), the step says what to check and where.

**Type consistency:** `service_proto::{Request, Response, EngineFacts, OpenVpnFacts, WireGuardFacts, LogSlice, Version, SERVICE_VERSION, PIPE_NAME, BODY_MAX}` (Tasks 1, 8, 10, 12, 16); `service::{Service, Caller, Engine, EngineState, Host, LogStore, LogSink, UpRequest, MAX_PER_USER}` (8, 12–14); `log::{LogSource, LogRead, LogIdentity, FileLogSource}` (6, 16); `pipe::{Endpoint, ServerTrust, connect_with, SERVICE_CLIENT_ACCESS, NOT_THE_SERVICE}` (3, 12, 16); `setup::{EngineReport, EngineRow, SetupReport::{engine, later_kinds, later_reason}}` (11, 16); `curl::{Curl, CommandRunner, http::CurlHttpClient::{with_curl, download_pinned}}` (5, 17–19).
